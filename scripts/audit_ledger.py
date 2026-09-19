#!/usr/bin/env python3
"""
install-security-audit 配套：审计台账工具 (audit_ledger.py) v1.0

用途：把每一次安全审计的结果**持久记录**下来，形成跨次可追溯的审计账本。
     单次审计是孤立的；有了台账，才能看出跨次规律。

为什么需要它：
   - 「这个发布者上次也审过」→ 一眼看到该发布者的历史记录与结论
   - 「这个包反复出现残留风险」→ 累积风险看得见
   - 「上次是怎么判的」→ 决策依据可回溯，不靠记忆

台账格式：JSON Lines（每行一条 JSON），便于追加、追加不会破坏已有记录。

用法：
    # 1) 追加一条审计记录（交互式或参数式）
    python audit_ledger.py add --name agent-browser --source SkillHub ^
        --publisher "Vercel Labs" --level 低 --verdict install ^
        --notes "npm 包由 Vercel 官方维护，postinstall 仅做平台二进制选择" ^
        --risks "下载的 exe 无本地校验和（依赖 TLS）"

    # 2) 查询某项目/发布者的历史
    python audit_ledger.py query --name agent-browser
    python audit_ledger.py query --publisher "Vercel Labs"

    # 3) 列出全部记录（简表）
    python audit_ledger.py list

    # 4) 统计概览
    python audit_ledger.py stats

台账默认位置：~/.install-security-audit/ledger.jsonl
可用 --ledger <path> 指定其它位置。
"""
import sys
import os
import json
import pathlib
import argparse
from datetime import datetime

DEFAULT_LEDGER = os.path.join(os.path.expanduser("~"), ".install-security-audit", "ledger.jsonl")

# 风险等级与结论的规范化取值
LEVELS = {"低", "中", "高", "P0", "P1", "P2"}
VERDICTS = {
    "install": "可直接安装",
    "conditional": "有条件安装",
    "isolated": "隔离安装",
    "reject": "不建议安装",
    "uninstalled": "已卸载",
}


def load(ledger_path):
    """读取台账全部记录。"""
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
            # 跳过损坏行，不中断
            continue
    return records


def append(ledger_path, record):
    """追加一条记录（JSONL）。"""
    p = pathlib.Path(ledger_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def cmd_add(args):
    if not args.name:
        print("错误：必须提供 --name（项目名）")
        sys.exit(1)
    record = {
        "time": datetime.now().isoformat(timespec="seconds"),
        "name": args.name,
        "source": args.source or "",
        "publisher": args.publisher or "",
        "level": args.level or "",
        "verdict": args.verdict or "",
        "verdict_label": VERDICTS.get(args.verdict or "", args.verdict or ""),
        "notes": args.notes or "",
        "risks": args.risks or "",
        "unverified": args.unverified or "",
        "version": args.version or "",
    }
    append(args.ledger, record)
    print("已记录审计台账：")
    print(f"  时间     : {record['time']}")
    print(f"  项目     : {record['name']}")
    print(f"  来源     : {record['source']}")
    print(f"  发布者   : {record['publisher']}")
    print(f"  风险等级 : {record['level']}")
    print(f"  结论     : {record['verdict_label']}")
    if record["risks"]:
        print(f"  残留风险 : {record['risks']}")
    if record["unverified"]:
        print(f"  未验证项 : {record['unverified']}")
    print(f"  台账位置 : {args.ledger}")


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
        print("未找到匹配记录。")
        return

    print("=" * 72)
    print(f" 审计台账查询结果（{len(hits)} 条）")
    print("=" * 72)
    for r in hits:
        print()
        print(f"  [{r.get('time')}] {r.get('name')}  v{r.get('version','')}")
        print(f"    来源: {r.get('source')}   发布者: {r.get('publisher')}")
        print(f"    等级: {r.get('level')}   结论: {r.get('verdict_label')}")
        if r.get("notes"):
            print(f"    说明: {r.get('notes')}")
        if r.get("risks"):
            print(f"    残留风险: {r.get('risks')}")
        if r.get("unverified"):
            print(f"    未验证项: {r.get('unverified')}")
    print()
    print("=" * 72)

    # 同一项目多次记录时给出提示
    names = {}
    for r in hits:
        names[r.get("name")] = names.get(r.get("name"), 0) + 1
    repeated = {k: v for k, v in names.items() if v > 1}
    if repeated:
        print("注意：以下项目有多次审计记录：")
        for k, v in repeated.items():
            print(f"   {k}: {v} 次")


def cmd_list(args):
    records = load(args.ledger)
    if not records:
        print("台账为空。")
        return
    print("=" * 72)
    print(f" 审计台账总览（{len(records)} 条）")
    print("=" * 72)
    print(f"{'时间':<20} {'项目':<22} {'等级':<5} {'结论':<12}")
    print("-" * 72)
    for r in records:
        t = (r.get("time") or "")[:19]
        print(f"{t:<20} {r.get('name','')[:21]:<22} {r.get('level',''):<5} {r.get('verdict_label',''):<12}")
    print("=" * 72)


def cmd_stats(args):
    records = load(args.ledger)
    if not records:
        print("台账为空。")
        return
    from collections import Counter
    total = len(records)
    by_level = Counter(r.get("level", "?") for r in records)
    by_verdict = Counter(r.get("verdict_label", "?") for r in records)
    by_publisher = Counter(r.get("publisher", "?") for r in records if r.get("publisher"))
    n_risk = sum(1 for r in records if r.get("risks"))
    n_unverified = sum(1 for r in records if r.get("unverified"))

    print("=" * 72)
    print(f" 审计台账统计（共 {total} 条）")
    print("=" * 72)
    print("按风险等级：")
    for k, v in by_level.most_common():
        print(f"   {k or '未填'}: {v}")
    print()
    print("按结论：")
    for k, v in by_verdict.most_common():
        print(f"   {k or '未填'}: {v}")
    print()
    print(f"含残留风险记录: {n_risk} 条")
    print(f"含未验证项记录: {n_unverified} 条")
    if by_publisher:
        print()
        print("审计过的发布者（按次数）：")
        for k, v in by_publisher.most_common(10):
            print(f"   {k}: {v} 次")
    print("=" * 72)


def main():
    ap = argparse.ArgumentParser(
        description="安装前安全审计台账工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--ledger", default=DEFAULT_LEDGER, help=f"台账文件路径（默认 {DEFAULT_LEDGER}）")
    sub = ap.add_subparsers(dest="cmd")

    p_add = sub.add_parser("add", help="追加一条审计记录")
    p_add.add_argument("--name", required=True, help="项目名")
    p_add.add_argument("--source", help="来源（如 SkillHub / npm / GitHub）")
    p_add.add_argument("--publisher", help="发布者/组织")
    p_add.add_argument("--version", help="版本")
    p_add.add_argument("--level", help="风险等级：低/中/高/P0/P1/P2")
    p_add.add_argument("--verdict", help="结论：install/conditional/isolated/reject/uninstalled")
    p_add.add_argument("--notes", help="说明")
    p_add.add_argument("--risks", help="残留风险")
    p_add.add_argument("--unverified", help="未验证项（如沙箱未能试跑）")

    p_q = sub.add_parser("query", help="按项目/发布者查询")
    p_q.add_argument("--name", help="项目名（子串匹配）")
    p_q.add_argument("--publisher", help="发布者（子串匹配）")

    sub.add_parser("list", help="列出全部记录")
    sub.add_parser("stats", help="统计概览")

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
