#!/usr/bin/env python3
"""
install-security-audit 配套：文件系统快照对比工具
用途：安装前拍快照，安装后对比，发现任何意外的文件增删改。

用法：
    1) 安装前：python fs_snapshot.py <目标路径> snapshot_before.json
    2) 执行安装
    3) 安装后：python fs_snapshot.py <目标路径> snapshot_after.json
    4) 对比  ：python fs_snapshot.py --diff snapshot_before.json snapshot_after.json

默认同时监控一组敏感位置（可用 --敏感 关闭）。
"""
import sys
import os
import json
import hashlib
import pathlib
from datetime import datetime

# 敏感监控位置（除目标目录外，额外监控）
SENSITIVE = [
    os.path.expanduser("~/.ssh"),
    os.path.expanduser("~/.aws"),
    os.path.expanduser("~/.git-credentials"),
    os.path.expanduser("~/.netrc"),
    os.path.expanduser("~/.bashrc"),
    os.path.expanduser("~/.bash_profile"),
    os.path.expanduser("~/.zshrc"),
]


def sha256(p):
    h = hashlib.sha256()
    try:
        with open(p, "rb") as f:
            for b in iter(lambda: f.read(65536), b""):
                h.update(b)
        return h.hexdigest()
    except Exception:
        return None


def snapshot(paths, max_files=20000):
    result = {}
    count = 0
    for base in paths:
        b = pathlib.Path(base)
        if not b.exists():
            result[str(b)] = {"_missing": True}
            continue
        if b.is_file():
            result[str(b)] = {"size": b.stat().st_size, "sha256": sha256(b)}
            continue
        for p in b.rglob("*"):
            if count >= max_files:
                result["_truncated"] = f"超过 {max_files} 文件，已截断"
                return result
            try:
                if p.is_file():
                    rel = str(p)
                    result[rel] = {"size": p.stat().st_size, "sha256": sha256(p)}
                    count += 1
            except Exception:
                pass
    return result


def diff(before, after):
    bk, ak = set(before), set(after)
    added = ak - bk
    removed = bk - ak
    changed = []
    for k in bk & ak:
        bv, av = before[k], after[k]
        if isinstance(bv, dict) and isinstance(av, dict):
            if bv.get("sha256") != av.get("sha256"):
                changed.append(k)
    return added, removed, changed


def main():
    args = [a for a in sys.argv[1:]]

    if "--diff" in args:
        i = args.index("--diff")
        bf, af = args[i + 1], args[i + 2]
        before = json.loads(pathlib.Path(bf).read_text(encoding="utf-8"))
        after = json.loads(pathlib.Path(af).read_text(encoding="utf-8"))
        added, removed, changed = diff(before.get("files", {}), after.get("files", {}))
        print("=" * 72)
        print(" 文件系统变化对比报告")
        print("=" * 72)
        print(f"快照前时间: {before.get('time')}")
        print(f"快照后时间: {after.get('time')}")
        print()
        print(f"🟢 新增文件 ({len(added)}):")
        for f in sorted(added)[:200]:
            print(f"    + {f}")
        if len(added) > 200:
            print(f"    ... 还有 {len(added) - 200} 个")
        print()
        print(f"🔴 删除文件 ({len(removed)}):")
        for f in sorted(removed)[:200]:
            print(f"    - {f}")
        print()
        print(f"🟡 修改文件 ({len(changed)}):")
        for f in sorted(changed)[:200]:
            print(f"    ~ {f}")
        print()
        # 敏感位置检查
        sens_hits = [f for f in list(added) + list(changed)
                     if any(s.replace("\\", "/") in f.replace("\\", "/") for s in SENSITIVE)]
        if sens_hits:
            print("⚠️⚠️⚠️ 警告：敏感位置被改动！")
            for f in sens_hits:
                print(f"    !! {f}")
        else:
            print("✅ 未发现敏感位置（SSH/云凭据/shell配置）被改动")
        return

    # 拍摄快照
    if len(args) < 2:
        print(__doc__)
        sys.exit(1)
    target = args[0]
    out = args[1]
    paths = [target]
    if "--敏感" not in args and "--no-sensitive" not in args:
        paths += SENSITIVE
    data = {
        "time": datetime.now().isoformat(),
        "target": target,
        "monitored": paths,
        "files": snapshot(paths),
    }
    pathlib.Path(out).write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"快照已保存: {out}")
    print(f"  监控路径数: {len(paths)}")
    print(f"  记录文件数: {len(data['files'])}")


if __name__ == "__main__":
    main()
