#!/usr/bin/env python3
"""
install-security-audit 配套：注册表与持久化基线对比工具 (v2.1.1)

用途：安装前拍「持久化基线」，安装后重新拍，对比出任何新增/修改的
     自启动项、计划任务、启动文件夹、服务 —— 即「后门持久化」的藏身处。

为什么需要它：
   文件系统快照（fs_snapshot.py）只看得到「文件」，
   但攻击者常把持久化写进【注册表 Run 键 / 计划任务 / 服务】——
   这些不产生新文件，文件快照完全看不见。

用法：
    1) 安装前：python registry_snapshot.py snapshot_before.json
    2) 执行安装
    3) 安装后：python registry_snapshot.py snapshot_after.json
    4) 对比  ：python registry_snapshot.py --diff snapshot_before.json snapshot_after.json
    5) 只看第三方：加 --exclude-system（diff 时过滤系统内建计划任务）

覆盖范围与能力（本机 2026-09-20 实测）：
    ✅ 注册表自启动键  —— 用 Python 标准库 winreg 直接读取（不依赖 reg.exe）
    ✅ 启动文件夹      —— 直接读目录
    ✅ 自启动服务      —— 读 HKLM\\SYSTEM\\CurrentControlSet\\Services 注册表
    ✅ 计划任务        —— 提权后递归遍历 TaskCache\\Tree，采集任务名 + 动作；
                          普通权限下【无法读取】，本工具会如实标注为未覆盖。
                          建议：以管理员身份运行本脚本可获得该层覆盖。

计划任务过滤：
   系统内建任务（\\Microsoft\\Windows\\...）通常 200+ 个，会淹没第三方任务。
   加 --exclude-system 可在对比时只看第三方/自定义任务，异常项一眼可见。
   （基线文件始终保存完整清单，过滤只作用于对比展示。）

安全设计：只读，绝不写注册表、绝不改任何配置。
"""
import sys
import os
import json
import pathlib
from datetime import datetime

try:
    import winreg
except ImportError:
    winreg = None

# ---------- 注册表自启动键 ----------
REG_AUTORUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (32位)"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce (32位)"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "HKLM Policy Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "HKCU Policy Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunServices", "HKCU RunServices"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunServices", "HKLM RunServices"),
]

# 单个值（Winlogon 等关键劫持点）
REG_SINGLE_VALUES = [
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit", "Winlogon Userinit"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell", "Winlogon Shell"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "Load", "HKCU Windows Load"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "Run", "HKCU Windows Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs", "AppInit_DLLs"),
]

STARTUP_DIRS = [
    os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
    os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                 r"Microsoft\Windows\Start Menu\Programs\Startup"),
]

SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"


def read_key_values(hive, subkey):
    """读取一个注册表键下的所有 值(名称/数据)。返回 list，键不存在返回 []。"""
    vals = []
    try:
        k = winreg.OpenKey(hive, subkey)
    except OSError:
        return vals
    try:
        i = 0
        while True:
            try:
                name, data, _typ = winreg.EnumValue(k, i)
                vals.append({"name": name, "value": str(data)})
                i += 1
            except OSError:
                break
    finally:
        winreg.CloseKey(k)
    return vals


def read_single_value(hive, subkey, name):
    """读取单个值。返回 list（统一结构，便于 diff）。"""
    try:
        k = winreg.OpenKey(hive, subkey)
    except OSError:
        return []
    try:
        data, _typ = winreg.QueryValueEx(k, name)
        return [{"name": name, "value": str(data)}]
    except OSError:
        return []
    finally:
        winreg.CloseKey(k)


def collect_registry():
    result = {}
    for hive, subkey, label in REG_AUTORUN_KEYS:
        result[label] = read_key_values(hive, subkey)
    for hive, subkey, name, label in REG_SINGLE_VALUES:
        result[label] = read_single_value(hive, subkey, name)
    return result


def collect_startup_folders():
    result = {}
    for d in STARTUP_DIRS:
        if not d or not os.path.isdir(d):
            result[d] = {"_missing": True}
            continue
        files = []
        try:
            for n in os.listdir(d):
                if n.lower() == "desktop.ini":
                    continue  # 系统自带，忽略
                fp = os.path.join(d, n)
                try:
                    files.append({"name": n, "size": os.path.getsize(fp)})
                except Exception:
                    files.append({"name": n, "size": None})
        except Exception as e:
            result[d] = {"_error": str(e)}
            continue
        result[d] = files
    return result


def collect_services():
    """读取所有服务，记录启动类型。Start: 0=Boot 1=System 2=Auto 3=Manual 4=Disabled"""
    services = []
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVICES_KEY)
    except OSError as e:
        return {"_error": str(e), "_coverage": False}
    try:
        n_sub, _, _ = winreg.QueryInfoKey(k)
        for i in range(n_sub):
            try:
                sname = winreg.EnumKey(k, i)
            except OSError:
                continue
            try:
                sk = winreg.OpenKey(k, sname)
                try:
                    start, _ = winreg.QueryValueEx(sk, "Start")
                except OSError:
                    start = None
                try:
                    img, _ = winreg.QueryValueEx(sk, "ImagePath")
                except OSError:
                    img = ""
                winreg.CloseKey(sk)
                if start in (0, 1, 2):  # 只关心会自动启动的
                    services.append({
                        "name": sname,
                        "start": start,
                        "image": str(img),
                    })
            except OSError:
                continue
    finally:
        winreg.CloseKey(k)
    return services


def _read_task_actions(task_id):
    """从 Actions 键读取某任务的动作（要执行的程序/命令）。"""
    acts = []
    if not task_id:
        return acts
    try:
        k = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            rf"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Actions\{task_id}",
            0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        )
    except OSError:
        return acts
    try:
        i = 0
        while True:
            try:
                name, data, _t = winreg.EnumValue(k, i)
                if name == "Path":
                    acts.append(str(data))
                elif name == "Arguments":
                    acts.append(str(data))
                i += 1
            except OSError:
                break
    finally:
        winreg.CloseKey(k)
    return acts


def _walk_task_tree(key, path=""):
    """递归遍历计划任务树，返回 [(任务全路径, task_id)]。"""
    out = []
    try:
        n_sub, _n_val, _ = winreg.QueryInfoKey(key)
    except OSError:
        return out
    for i in range(n_sub):
        try:
            sub = winreg.EnumKey(key, i)
        except OSError:
            continue
        full = f"{path}\\{sub}" if path else sub
        try:
            sk = winreg.OpenKey(key, sub)
        except OSError:
            continue
        try:
            # 若该节点有 Id 值，说明它本身是一个任务
            try:
                tid, _t = winreg.QueryValueEx(sk, "Id")
                out.append((full, str(tid)))
            except OSError:
                pass
            # 递归子目录
            out.extend(_walk_task_tree(sk, full))
        finally:
            winreg.CloseKey(sk)
    return out


# 判定为「系统内建任务」的路径前缀（大小写不敏感）
SYSTEM_TASK_PREFIXES = (
    "microsoft\\windows\\",
    "microsoft\\windows",
)


def is_system_task(taskname):
    r"""判断计划任务是否属于 Windows 系统内建（\Microsoft\Windows\... 等）。

    系统任务数量庞大（通常 200+），会淹没第三方/自定义任务；
    标记出来便于用 --exclude-system 过滤。
    """
    low = taskname.lower().lstrip("\\")
    return low.startswith(SYSTEM_TASK_PREFIXES)


def collect_scheduled_tasks():
    """采集计划任务。需管理员权限；普通权限返回未覆盖结构。

    返回 list（成功）或 dict（未覆盖，含 _coverage=False）。
    """
    root_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
    try:
        root = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, root_path,
            0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        )
    except OSError as e:
        return {
            "_coverage": False,
            "_reason": f"需管理员权限（WinError {getattr(e,'winerror',e)}）",
            "_fallback": "以管理员身份重跑本脚本即可覆盖此层（见 ADMIN_RUN.md）",
        }
    tasks = []
    try:
        pairs = _walk_task_tree(root, "")
    finally:
        winreg.CloseKey(root)

    for full, tid in pairs:
        # 采集完整清单（不跳过任何任务——完整基线更安全），
        # 但标记是否为系统内建任务，便于人工辨别与过滤。
        entry = {
            "taskname": full,
            "id": tid,
            "actions": _read_task_actions(tid),
            "system": is_system_task(full),
        }
        tasks.append(entry)
    return tasks


def take_snapshot():
    tasks = collect_scheduled_tasks()
    cov_tasks = not (isinstance(tasks, dict) and tasks.get("_coverage") is False)
    return {
        "time": datetime.now().isoformat(),
        "hostname": os.environ.get("COMPUTERNAME", ""),
        "user": os.environ.get("USERNAME", ""),
        "registry": collect_registry(),
        "startup_folders": collect_startup_folders(),
        "services": collect_services(),
        "scheduled_tasks": tasks,
        "coverage": {
            "registry_autorun": True,
            "startup_folders": True,
            "services": True,
            "scheduled_tasks": cov_tasks,
        },
    }


def diff_list(before, after, keyfn):
    bmap = {keyfn(x): x for x in before}
    amap = {keyfn(x): x for x in after}
    added = [amap[k] for k in amap if k not in bmap]
    removed = [bmap[k] for k in bmap if k not in amap]
    changed = []
    for k in set(bmap) & set(amap):
        if json.dumps(bmap[k], sort_keys=True, ensure_ascii=False) != \
           json.dumps(amap[k], sort_keys=True, ensure_ascii=False):
            changed.append({"before": bmap[k], "after": amap[k]})
    return added, removed, changed


def do_diff(bf, af, exclude_system=False):
    before = json.loads(pathlib.Path(bf).read_text(encoding="utf-8"))
    after = json.loads(pathlib.Path(af).read_text(encoding="utf-8"))

    print("=" * 72)
    print(" 注册表与持久化 变化对比报告")
    print("=" * 72)
    if exclude_system:
        print(" [过滤] 已排除系统内建计划任务（\\Microsoft\\Windows\\...）")
    print(f"基线时间: {before.get('time')}")
    print(f"对比时间: {after.get('time')}")
    print()

    suspicious = []
    changes = 0

    # 1. 注册表自启动
    for label in before.get("registry", {}):
        b = before["registry"][label]
        a = after.get("registry", {}).get(label, [])
        added, removed, changed = diff_list(b, a, lambda x: x.get("name", ""))
        if added or removed or changed:
            changes += len(added) + len(removed) + len(changed)
            print(f"[注册表] {label}")
            for x in added:
                print(f"   新增: {x.get('name')} = {x.get('value')}")
                suspicious.append(f"注册表新增自启: {label} / {x.get('name')}")
            for x in removed:
                print(f"   移除: {x.get('name')}")
            for c in changed:
                print(f"   修改: {c['before'].get('name')}")
                print(f"        旧: {c['before'].get('value')}")
                print(f"        新: {c['after'].get('value')}")
                suspicious.append(f"注册表自启被改: {label} / {c['before'].get('name')}")
            print()

    # 2. 启动文件夹
    for d, b in before.get("startup_folders", {}).items():
        a = after.get("startup_folders", {}).get(d, [])
        if not isinstance(b, list) or not isinstance(a, list):
            continue
        added, removed, changed = diff_list(b, a, lambda x: x.get("name", ""))
        if added or removed or changed:
            changes += len(added) + len(removed) + len(changed)
            print(f"[启动文件夹] {d}")
            for x in added:
                print(f"   新增: {x.get('name')} ({x.get('size')}B)")
                suspicious.append(f"启动文件夹新增: {x.get('name')}")
            for x in removed:
                print(f"   移除: {x.get('name')}")
            for c in changed:
                print(f"   修改: {c['after'].get('name')}")
            print()

    # 3. 服务
    b = before.get("services", [])
    a = after.get("services", [])
    if isinstance(b, list) and isinstance(a, list):
        added, removed, changed = diff_list(b, a, lambda x: x.get("name", ""))
        if added or removed or changed:
            changes += len(added) + len(removed) + len(changed)
            print("[自启动服务]")
            for x in added:
                print(f"   新增: {x.get('name')}  启动类型={x.get('start')}")
                print(f"        映像: {x.get('image')}")
                suspicious.append(f"新增自启动服务: {x.get('name')} -> {x.get('image')}")
            for x in removed:
                print(f"   移除: {x.get('name')}")
            for c in changed:
                print(f"   修改: {c['after'].get('name')}  启动类型 {c['before'].get('start')} -> {c['after'].get('start')}")
                suspicious.append(f"服务启动类型被改: {c['after'].get('name')}")
            print()

    # 4. 计划任务
    st = after.get("scheduled_tasks", {})
    st_ok = isinstance(st, list)
    if st_ok:
        b = before.get("scheduled_tasks", [])
        if not isinstance(b, list):
            b = []
        if exclude_system:
            st = [t for t in st if not t.get("system")]
            b = [t for t in b if not t.get("system")]
        n_hidden = 0
        if exclude_system and isinstance(after.get("scheduled_tasks"), list):
            n_hidden = sum(1 for t in after["scheduled_tasks"] if t.get("system"))
        added, removed, changed = diff_list(b, st, lambda x: x.get("taskname", ""))
        if added or removed or changed:
            changes += len(added) + len(removed) + len(changed)
            print("[计划任务]")
            for x in added:
                print(f"   新增: {x.get('taskname')}")
                for act in (x.get("actions") or []):
                    print(f"        动作: {act}")
                suspicious.append(
                    f"新增计划任务: {x.get('taskname')} -> {' '.join(x.get('actions') or [])}"
                )
            for x in removed:
                print(f"   移除: {x.get('taskname')}")
            for c in changed:
                print(f"   修改: {c['after'].get('taskname')}")
                print(f"        旧动作: {' '.join(c['before'].get('actions') or [])}")
                print(f"        新动作: {' '.join(c['after'].get('actions') or [])}")
                suspicious.append(f"计划任务被改: {c['after'].get('taskname')}")
            print()
        else:
            extra = f"，已过滤 {n_hidden} 个系统任务" if exclude_system and n_hidden else ""
            print(f"[计划任务] 已覆盖（{len(st)} 个任务{extra}），无变化")
            print()
    elif isinstance(st, dict) and not st.get("_coverage", False):
        print("[计划任务] ⚠️ 本层未覆盖")
        print(f"   原因: {st.get('_reason')}")
        print(f"   补救: {st.get('_fallback')}")
        print()

    print("=" * 72)
    if changes == 0:
        print("未发现任何持久化项（注册表自启/启动文件夹/服务/计划任务）变化")
    else:
        print(f"共发现 {changes} 处持久化变化")
        if suspicious:
            print()
            print("需要重点核查的条目：")
            for s in suspicious:
                print(f"   !! {s}")
    # 覆盖范围披露
    st_is_covered = isinstance(st, list)
    print()
    print("本次对比覆盖范围：")
    print("   [已覆盖] 注册表自启动键 / 启动文件夹 / 自启动服务")
    print(f"   [{'已覆盖' if st_is_covered else '未覆盖'}] 计划任务"
          f"{'' if st_is_covered else '  <- 需管理员权限，未验证（见 ADMIN_RUN.md）'}")
    print("=" * 72)


def main():
    if winreg is None:
        print("错误：本脚本仅支持 Windows（需要 winreg 模块）")
        sys.exit(1)

    args = sys.argv[1:]

    if "--diff" in args:
        i = args.index("--diff")
        if i + 2 >= len(args):
            print("用法: python registry_snapshot.py --diff before.json after.json [--exclude-system]")
            sys.exit(1)
        do_diff(args[i + 1], args[i + 2], exclude_system=("--exclude-system" in args))
        return

    # 过滤开关：非 diff 位置参数视为输出文件名
    out = "registry_snapshot.json"
    for a in args:
        if not a.startswith("--"):
            out = a
            break

    data = take_snapshot()
    st = data["scheduled_tasks"]
    n_tasks = len(st) if isinstance(st, list) else 0

    pathlib.Path(out).write_text(
        json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    n_reg = sum(len(v) if isinstance(v, list) else 0 for v in data["registry"].values())
    n_start = sum(len(v) if isinstance(v, list) else 0 for v in data["startup_folders"].values())
    n_svc = len(data["services"]) if isinstance(data["services"], list) else 0
    print(f"持久化基线已保存: {out}")
    print(f"  主机: {data['hostname']}   用户: {data['user']}")
    print(f"  注册表自启动值: {n_reg} 条（{len(data['registry'])} 个键）")
    print(f"  启动文件夹项: {n_start} 个")
    print(f"  自启动服务: {n_svc} 个")
    if isinstance(st, list):
        n_sys = sum(1 for t in st if t.get("system"))
        n_custom = n_tasks - n_sys
        print(f"  计划任务: 已覆盖（{n_tasks} 个 = 系统 {n_sys} + 第三方/自定义 {n_custom}）")
        # --list-custom：立即列出第三方任务，便于快速审查
        if "--list-custom" in args:
            custom = [t for t in st if not t.get("system")]
            print()
            print(f"--- 第三方/自定义计划任务（{len(custom)} 个）---")
            if not custom:
                print("   （无）")
            for t in custom:
                acts = " ".join(t.get("actions") or [])
                print(f"   {t.get('taskname')}")
                if acts:
                    print(f"       动作: {acts}")
    else:
        print(f"  计划任务: 未覆盖（需管理员权限，见 ADMIN_RUN.md）")


if __name__ == "__main__":
    main()
