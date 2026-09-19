#!/usr/bin/env python3
"""
install-security-audit companion: registry & persistence baseline diff tool (v2.2)

Purpose: capture a "persistence baseline" before install, re-capture after install,
         and diff out any added/modified autorun entries, scheduled tasks, startup
         folder items, or services -- the hiding places of persistence backdoors.

Why it is needed:
    A filesystem snapshot (fs_snapshot.py) only sees "files",
    but attackers commonly write persistence into [registry Run keys / scheduled
    tasks / services] -- none of which create a new file, so a file snapshot
    cannot see them at all.

Usage:
    1) Before install: python registry_snapshot.py before.json
    2) Run the install
    3) After install : python registry_snapshot.py after.json
    4) Diff          : python registry_snapshot.py --diff before.json after.json
    5) Third-party only: add --exclude-system (filters built-in tasks during diff)

Coverage (verified on Windows):
    [x] Registry autorun keys  -- read via Python's standard `winreg` (no reg.exe)
    [x] Startup folders        -- direct directory read
    [x] Auto-start services    -- read HKLM\\SYSTEM\\CurrentControlSet\\Services
    [x] Scheduled tasks        -- when elevated, recursively walks TaskCache\\Tree
                                  and collects task name + actions; under normal
                                  privileges it CANNOT be read and the tool will
                                  honestly report it as not covered.
                                  Tip: run this script as administrator for coverage.

Scheduled-task filtering:
   Windows ships 200+ built-in tasks (\\Microsoft\\Windows\\...) that drown out
   third-party ones. Add --exclude-system during diff to see only third-party /
   custom tasks, so anomalies stand out.
   (The baseline file always stores the complete list; filtering only affects display.)

Safety design: read-only. Never writes the registry, never modifies any configuration.
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

# ---------- Registry autorun keys ----------
REG_AUTORUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (32-bit)"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce (32-bit)"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "HKLM Policy Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "HKCU Policy Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunServices", "HKCU RunServices"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunServices", "HKLM RunServices"),
]

# Single values (key hijack points such as Winlogon)
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
    """Read all values (name/data) under a registry key. Returns a list; [] if absent."""
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
    """Read a single value. Returns a list (uniform structure for diffing)."""
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
                    continue  # shipped by Windows, ignore
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
    """Read all services and record their start type. Start: 0=Boot 1=System 2=Auto 3=Manual 4=Disabled"""
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
                if start in (0, 1, 2):  # only care about auto-starting ones
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
    """Read a task's actions (the program/command to execute) from its Actions key."""
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
    """Recursively walk the scheduled-task tree, returning [(full task path, task_id)]."""
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
            # If this node has an Id value, it is itself a task
            try:
                tid, _t = winreg.QueryValueEx(sk, "Id")
                out.append((full, str(tid)))
            except OSError:
                pass
            # Recurse into subfolders
            out.extend(_walk_task_tree(sk, full))
        finally:
            winreg.CloseKey(sk)
    return out


# Path prefixes considered "built-in system tasks" (case-insensitive)
SYSTEM_TASK_PREFIXES = (
    "microsoft\\windows\\",
    "microsoft\\windows",
)


def is_system_task(taskname):
    r"""Determine whether a scheduled task is Windows built-in (\Microsoft\Windows\... etc.).

    System tasks are numerous (usually 200+) and drown out third-party/custom ones;
    flagging them makes --exclude-system filtering possible.
    """
    low = taskname.lower().lstrip("\\")
    return low.startswith(SYSTEM_TASK_PREFIXES)


def collect_scheduled_tasks():
    """Collect scheduled tasks. Requires administrator privileges; returns an
    uncovered structure under normal privileges.

    Returns a list (success) or a dict (not covered, with _coverage=False).
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
            "_reason": f"administrator privileges required (WinError {getattr(e,'winerror',e)})",
            "_fallback": "re-run this script as administrator to cover this layer (see ADMIN_RUN.md)",
        }
    tasks = []
    try:
        pairs = _walk_task_tree(root, "")
    finally:
        winreg.CloseKey(root)

    for full, tid in pairs:
        # Collect the complete list (skip nothing -- a complete baseline is safer),
        # but flag whether each is a built-in system task, for human review and filtering.
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
    print(" Registry & Persistence Change Diff Report")
    print("=" * 72)
    if exclude_system:
        print(" [filter] built-in scheduled tasks excluded (\\Microsoft\\Windows\\...)")
    print(f"Baseline time : {before.get('time')}")
    print(f"Compare time  : {after.get('time')}")
    print()

    suspicious = []
    changes = 0

    # 1. Registry autoruns
    for label in before.get("registry", {}):
        b = before["registry"][label]
        a = after.get("registry", {}).get(label, [])
        added, removed, changed = diff_list(b, a, lambda x: x.get("name", ""))
        if added or removed or changed:
            changes += len(added) + len(removed) + len(changed)
            print(f"[registry] {label}")
            for x in added:
                print(f"   added: {x.get('name')} = {x.get('value')}")
                suspicious.append(f"registry autorun added: {label} / {x.get('name')}")
            for x in removed:
                print(f"   removed: {x.get('name')}")
            for c in changed:
                print(f"   modified: {c['before'].get('name')}")
                print(f"        old: {c['before'].get('value')}")
                print(f"        new: {c['after'].get('value')}")
                suspicious.append(f"registry autorun modified: {label} / {c['before'].get('name')}")
            print()

    # 2. Startup folders
    for d, b in before.get("startup_folders", {}).items():
        a = after.get("startup_folders", {}).get(d, [])
        if not isinstance(b, list) or not isinstance(a, list):
            continue
        added, removed, changed = diff_list(b, a, lambda x: x.get("name", ""))
        if added or removed or changed:
            changes += len(added) + len(removed) + len(changed)
            print(f"[startup folder] {d}")
            for x in added:
                print(f"   added: {x.get('name')} ({x.get('size')}B)")
                suspicious.append(f"startup folder item added: {x.get('name')}")
            for x in removed:
                print(f"   removed: {x.get('name')}")
            for c in changed:
                print(f"   modified: {c['after'].get('name')}")
            print()

    # 3. Services
    b = before.get("services", [])
    a = after.get("services", [])
    if isinstance(b, list) and isinstance(a, list):
        added, removed, changed = diff_list(b, a, lambda x: x.get("name", ""))
        if added or removed or changed:
            changes += len(added) + len(removed) + len(changed)
            print("[auto-start services]")
            for x in added:
                print(f"   added: {x.get('name')}  start={x.get('start')}")
                print(f"        image: {x.get('image')}")
                suspicious.append(f"auto-start service added: {x.get('name')} -> {x.get('image')}")
            for x in removed:
                print(f"   removed: {x.get('name')}")
            for c in changed:
                print(f"   modified: {c['after'].get('name')}  start {c['before'].get('start')} -> {c['after'].get('start')}")
                suspicious.append(f"service start type modified: {c['after'].get('name')}")
            print()

    # 4. Scheduled tasks
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
            print("[scheduled tasks]")
            for x in added:
                print(f"   added: {x.get('taskname')}")
                for act in (x.get("actions") or []):
                    print(f"        action: {act}")
                suspicious.append(
                    f"scheduled task added: {x.get('taskname')} -> {' '.join(x.get('actions') or [])}"
                )
            for x in removed:
                print(f"   removed: {x.get('taskname')}")
            for c in changed:
                print(f"   modified: {c['after'].get('taskname')}")
                print(f"        old actions: {' '.join(c['before'].get('actions') or [])}")
                print(f"        new actions: {' '.join(c['after'].get('actions') or [])}")
                suspicious.append(f"scheduled task modified: {c['after'].get('taskname')}")
            print()
        else:
            extra = f", {n_hidden} system task(s) filtered" if exclude_system and n_hidden else ""
            print(f"[scheduled tasks] covered ({len(st)} task(s){extra}), no changes")
            print()
    elif isinstance(st, dict) and not st.get("_coverage", False):
        print("[scheduled tasks] [!] this layer is NOT covered")
        print(f"   reason: {st.get('_reason')}")
        print(f"   remedy: {st.get('_fallback')}")
        print()

    print("=" * 72)
    if changes == 0:
        print("No persistence item (registry autorun / startup folder / service / scheduled task) changed")
    else:
        print(f"{changes} persistence change(s) found")
        if suspicious:
            print()
            print("Items requiring priority review:")
            for s in suspicious:
                print(f"   !! {s}")
    # Coverage disclosure
    st_is_covered = isinstance(st, list)
    print()
    print("Coverage for this comparison:")
    print("   [covered] registry autoruns / startup folders / auto-start services")
    print(f"   [{'covered' if st_is_covered else 'NOT covered'}] scheduled tasks"
          f"{'' if st_is_covered else '  <- administrator privileges required, unverified (see ADMIN_RUN.md)'}")
    print("=" * 72)


def main():
    if winreg is None:
        print("Error: this script supports Windows only (requires the winreg module)")
        sys.exit(1)

    args = sys.argv[1:]

    if "--diff" in args:
        i = args.index("--diff")
        if i + 2 >= len(args):
            print("Usage: python registry_snapshot.py --diff before.json after.json [--exclude-system]")
            sys.exit(1)
        do_diff(args[i + 1], args[i + 2], exclude_system=("--exclude-system" in args))
        return

    # Non-flag positional argument is treated as the output filename
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
    print(f"Persistence baseline saved: {out}")
    print(f"  Host: {data['hostname']}   User: {data['user']}")
    print(f"  Registry autorun values: {n_reg} ({len(data['registry'])} keys)")
    print(f"  Startup folder items: {n_start}")
    print(f"  Auto-start services: {n_svc}")
    if isinstance(st, list):
        n_sys = sum(1 for t in st if t.get("system"))
        n_custom = n_tasks - n_sys
        print(f"  Scheduled tasks: covered ({n_tasks} total = {n_sys} system + {n_custom} third-party/custom)")
        # --list-custom: list third-party tasks immediately for quick review
        if "--list-custom" in args:
            custom = [t for t in st if not t.get("system")]
            print()
            print(f"--- Third-party / custom scheduled tasks ({len(custom)}) ---")
            if not custom:
                print("   (none)")
            for t in custom:
                acts = " ".join(t.get("actions") or [])
                print(f"   {t.get('taskname')}")
                if acts:
                    print(f"       action: {acts}")
    else:
        print(f"  Scheduled tasks: NOT covered (administrator privileges required, see ADMIN_RUN.md)")


if __name__ == "__main__":
    main()
