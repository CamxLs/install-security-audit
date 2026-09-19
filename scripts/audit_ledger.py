#!/usr/bin/env python3
"""
install-security-audit companion: audit ledger tool (audit_ledger.py) v1.1

Purpose: persist the result of every security audit, forming a cross-run
         traceable ledger. A single audit is isolated; the ledger reveals
         cross-run patterns.

Why it exists:
   - "This publisher was audited before" -> see that publisher's history at a glance
   - "This package keeps showing residual risk" -> cumulative risk becomes visible
   - "How was it judged last time?" -> decisions become traceable, not memory-based

Ledger format: JSON Lines (one JSON object per line), append-friendly.

Usage:
    # 1) Append an audit record
    python audit_ledger.py add --name agent-browser --source SkillHub \
        --publisher "Vercel Labs" --level low --verdict install \
        --notes "npm package maintained by Vercel; postinstall only selects a platform binary" \
        --risks "Downloaded exe has no local checksum (relies on TLS)"

    # 2) Query history for a project/publisher
    python audit_ledger.py query --name agent-browser
    python audit_ledger.py query --publisher "Vercel Labs"

    # 3) List all records (summary table)
    python audit_ledger.py list

    # 4) Statistics overview
    python audit_ledger.py stats

Default ledger location: ~/.install-security-audit/ledger.jsonl
Use --ledger <path> to specify another location.
"""
import sys
import os
import json
import pathlib
import argparse
from datetime import datetime

DEFAULT_LEDGER = os.path.join(os.path.expanduser("~"), ".install-security-audit", "ledger.jsonl")

# Canonical values for risk level and verdict
LEVELS = {"low", "medium", "high", "P0", "P1", "P2", "低", "中", "高"}
VERDICTS = {
    "install": "Install as-is",
    "conditional": "Install with conditions",
    "isolated": "Install isolated",
    "reject": "Do not install",
    "uninstalled": "Uninstalled",
}
# Accept legacy Chinese verdict keys for backward compatibility
LEGACY_VERDICTS = {
    "可直接安装": "Install as-is",
    "有条件安装": "Install with conditions",
    "隔离安装": "Install isolated",
    "不建议安装": "Do not install",
    "已卸载": "Uninstalled",
}


def load(ledger_path):
    """Read all ledger records."""
    p = pathlib.Path(ledger_path)
    if not p.exists():
        return []
    records = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            # Skip corrupt lines instead of aborting
            continue
    return records


def append(ledger_path, record):
    """Append one record (JSONL)."""
    p = pathlib.Path(ledger_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def verdict_label(value):
    """Resolve a verdict key or legacy label to a display label."""
    if not value:
        return ""
    if value in VERDICTS:
        return VERDICTS[value]
    if value in LEGACY_VERDICTS:
        return LEGACY_VERDICTS[value]
    return value


def cmd_add(args):
    if not args.name:
        print("Error: --name (project name) is required")
        sys.exit(1)
    record = {
        "time": datetime.now().isoformat(timespec="seconds"),
        "name": args.name,
        "source": args.source or "",
        "publisher": args.publisher or "",
        "level": args.level or "",
        "verdict": args.verdict or "",
        "verdict_label": verdict_label(args.verdict),
        "notes": args.notes or "",
        "risks": args.risks or "",
        "unverified": args.unverified or "",
        "version": args.version or "",
    }
    append(args.ledger, record)
    print("Audit record written to ledger:")
    print(f"  Time        : {record['time']}")
    print(f"  Project     : {record['name']}")
    print(f"  Source      : {record['source']}")
    print(f"  Publisher   : {record['publisher']}")
    print(f"  Risk level  : {record['level']}")
    print(f"  Verdict     : {record['verdict_label']}")
    if record["risks"]:
        print(f"  Residual    : {record['risks']}")
    if record["unverified"]:
        print(f"  Unverified  : {record['unverified']}")
    print(f"  Ledger      : {args.ledger}")


def cmd_query(args):
    records = load(args.ledger)
    hits = []
    for r in records:
        if args.name and args.name.lower() not in r.get("name", "").lower():
            continue
        if args.publisher and args.publisher.lower() not in r.get("publisher", "").lower():
            continue
        hits.append(r)

    if not hits:
        print("No matching records found.")
        return

    print("=" * 72)
    print(f" Audit ledger query results ({len(hits)} record(s))")
    print("=" * 72)
    for r in hits:
        print()
        print(f"  [{r.get('time')}] {r.get('name')}  v{r.get('version','')}")
        print(f"    Source: {r.get('source')}   Publisher: {r.get('publisher')}")
        print(f"    Level: {r.get('level')}   Verdict: {r.get('verdict_label')}")
        if r.get("notes"):
            print(f"    Notes: {r.get('notes')}")
        if r.get("risks"):
            print(f"    Residual risk: {r.get('risks')}")
        if r.get("unverified"):
            print(f"    Unverified: {r.get('unverified')}")
    print()
    print("=" * 72)

    # Flag projects audited more than once
    names = {}
    for r in hits:
        names[r.get("name")] = names.get(r.get("name"), 0) + 1
    repeated = {k: v for k, v in names.items() if v > 1}
    if repeated:
        print("Note: the following projects have multiple audit records:")
        for k, v in repeated.items():
            print(f"   {k}: {v} time(s)")


def cmd_list(args):
    records = load(args.ledger)
    if not records:
        print("Ledger is empty.")
        return
    print("=" * 72)
    print(f" Audit ledger overview ({len(records)} record(s))")
    print("=" * 72)
    print(f"{'Time':<20} {'Project':<22} {'Level':<7} {'Verdict':<26}")
    print("-" * 72)
    for r in records:
        t = (r.get("time") or "")[:19]
        print(f"{t:<20} {r.get('name','')[:21]:<22} {r.get('level','')[:6]:<7} {r.get('verdict_label','')[:25]:<26}")
    print("=" * 72)


def _meaningful(value):
    """Treat common 'empty' placeholders as no-value, so stats aren't inflated."""
    if not value:
        return False
    return str(value).strip().lower() not in {"none", "n/a", "na", "nil", "null", "-", "无"}


def cmd_stats(args):
    records = load(args.ledger)
    if not records:
        print("Ledger is empty.")
        return
    from collections import Counter
    total = len(records)
    by_level = Counter(r.get("level", "?") for r in records)
    by_verdict = Counter(r.get("verdict_label", "?") for r in records)
    by_publisher = Counter(r.get("publisher", "?") for r in records if r.get("publisher"))
    n_risk = sum(1 for r in records if _meaningful(r.get("risks")))
    n_unverified = sum(1 for r in records if _meaningful(r.get("unverified")))

    print("=" * 72)
    print(f" Audit ledger statistics ({total} record(s) total)")
    print("=" * 72)
    print("By risk level:")
    for k, v in by_level.most_common():
        print(f"   {k or 'unspecified'}: {v}")
    print()
    print("By verdict:")
    for k, v in by_verdict.most_common():
        print(f"   {k or 'unspecified'}: {v}")
    print()
    print(f"Records with residual risk : {n_risk}")
    print(f"Records with unverified    : {n_unverified}")
    if by_publisher:
        print()
        print("Audited publishers (by count):")
        for k, v in by_publisher.most_common(10):
            print(f"   {k}: {v}")
    print("=" * 72)


def main():
    ap = argparse.ArgumentParser(
        description="Pre-install security audit ledger tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--ledger", default=DEFAULT_LEDGER, help=f"Ledger file path (default {DEFAULT_LEDGER})")
    sub = ap.add_subparsers(dest="cmd")

    p_add = sub.add_parser("add", help="Append one audit record")
    p_add.add_argument("--name", required=True, help="Project name")
    p_add.add_argument("--source", help="Source (e.g. SkillHub / npm / GitHub)")
    p_add.add_argument("--publisher", help="Publisher / organization")
    p_add.add_argument("--version", help="Version")
    p_add.add_argument("--level", help="Risk level: low/medium/high/P0/P1/P2")
    p_add.add_argument("--verdict", help="Verdict: install/conditional/isolated/reject/uninstalled")
    p_add.add_argument("--notes", help="Notes")
    p_add.add_argument("--risks", help="Residual risk")
    p_add.add_argument("--unverified", help="Unverified items (e.g. sandbox could not run)")

    p_q = sub.add_parser("query", help="Query by project/publisher")
    p_q.add_argument("--name", help="Project name (substring match)")
    p_q.add_argument("--publisher", help="Publisher (substring match)")

    sub.add_parser("list", help="List all records")
    sub.add_parser("stats", help="Statistics overview")

    args = ap.parse_args()

    if args.cmd == "add":
        cmd_add(args)
    elif args.cmd == "query":
        cmd_query(args)
    elif args.cmd == "list":
        cmd_list(args)
    elif args.cmd == "stats":
        cmd_stats(args)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
