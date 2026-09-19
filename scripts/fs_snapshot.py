#!/usr/bin/env python3
"""
install-security-audit companion: filesystem snapshot diff tool v2.1
Purpose: snapshot before install, diff after install, surface any unexpected file changes.

Usage:
    1) Before install: python fs_snapshot.py snapshot before.json <target-dir> [more dirs...]
    2) Run the install
    3) After install : python fs_snapshot.py snapshot after.json <target-dir> [more dirs...]
    4) Diff          : python fs_snapshot.py diff before.json after.json

A set of sensitive locations is monitored by default (disable with --no-sensitive).
"""
import sys
import os
import json
import hashlib
import pathlib
from datetime import datetime

# Sensitive locations monitored in addition to the target directory
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
                result["_truncated"] = f"exceeded {max_files} files; truncated"
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


def cmd_snapshot(args):
    positional = [a for a in args if not a.startswith("--")]
    if len(positional) < 2:
        print(__doc__)
        sys.exit(1)
    out = positional[0]
    targets = positional[1:]
    paths = list(targets)
    if "--no-sensitive" not in args:
        paths += SENSITIVE
    data = {
        "time": datetime.now().isoformat(),
        "target": targets[0] if len(targets) == 1 else targets,
        "monitored": paths,
        "files": snapshot(paths),
    }
    pathlib.Path(out).write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"Snapshot saved: {out}")
    print(f"  Monitored paths : {len(paths)}")
    print(f"  Recorded files  : {len(data['files'])}")


def cmd_diff(args):
    positional = [a for a in args if not a.startswith("--")]
    if len(positional) < 2:
        print("Usage: python fs_snapshot.py diff <before.json> <after.json>")
        sys.exit(1)
    bf, af = positional[0], positional[1]
    before = json.loads(pathlib.Path(bf).read_text(encoding="utf-8"))
    after = json.loads(pathlib.Path(af).read_text(encoding="utf-8"))
    added, removed, changed = diff(before.get("files", {}), after.get("files", {}))
    print("=" * 72)
    print(" Filesystem Change Diff Report")
    print("=" * 72)
    print(f"Before snapshot : {before.get('time')}")
    print(f"After snapshot  : {after.get('time')}")
    print()
    print(f"[+] Added files ({len(added)}):")
    for f in sorted(added)[:200]:
        print(f"    + {f}")
    if len(added) > 200:
        print(f"    ... {len(added) - 200} more")
    print()
    print(f"[-] Removed files ({len(removed)}):")
    for f in sorted(removed)[:200]:
        print(f"    - {f}")
    print()
    print(f"[~] Modified files ({len(changed)}):")
    for f in sorted(changed)[:200]:
        print(f"    ~ {f}")
    print()
    # Sensitive-location check
    norm = lambda s: s.replace("\\", "/").lower()
    sens_hits = [f for f in list(added) + list(changed)
                 if any(norm(s) in norm(f) for s in SENSITIVE)]
    if sens_hits:
        print("[!] WARNING: sensitive locations were modified!")
        for f in sens_hits:
            print(f"    !! {f}")
    else:
        print("[ok] No sensitive location (SSH / cloud credentials / shell config) was modified")


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0 if args else 1)

    cmd = args[0]
    rest = args[1:]
    if cmd == "snapshot":
        cmd_snapshot(rest)
    elif cmd == "diff":
        cmd_diff(rest)
    else:
        print(f"Unknown subcommand: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
