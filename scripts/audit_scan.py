#!/usr/bin/env python3
"""
install-security-audit 配套审计脚本 v2.0
用途：对任意目录/包做自动化静态安全扫描，输出结构化报告。

用法：
    python audit_scan.py <目标目录>
    python audit_scan.py <目标目录> --json
"""
import sys
import os
import re
import json
import hashlib
import pathlib
from collections import defaultdict

# ============ A 类：经典攻击特征 ============
PATTERNS_A = {
    "管道执行(远程代码)": r"(curl|wget|invoke-webrequest)[^\n|]{0,200}\|\s*(ba|z|k)?sh",
    "eval/exec 动态执行": r"\b(eval|exec)\s*\(",
    "base64 解码执行": r"base64\s+(-d|--decode)|atob\s*\(|FromBase64String",
    "命令替换$()": r"\$\([^)]{1,200}\)",
    "反引号命令替换": r"`[^`\n]{1,200}`",
    "硬编码IP": r"\b(?!127\.0\.0\.1|0\.0\.0\.0|255\.255)(\d{1,3}\.){3}\d{1,3}\b",
    "网络外传": r"(curl|wget|Invoke-RestMethod|fetch|requests\.post|http\.request)[^\n]{0,150}(-d\s|--data|--upload|-F\s|POST|body)",
    "敏感环境变量": r"\$\{?(AWS_|GITHUB_TOKEN|GH_TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL|ACCESS_TOKEN)",
    "SSH/云凭据文件": r"(\.ssh[/\\]|id_rsa|id_ed25519|\.aws[/\\]|\.netrc|\.git-credentials)",
    "反弹Shell": r"\b(nc|netcat|ncat)\b[^\n]{0,60}(-e|--exec|-c\s)|bash\s+-i\s+>&",
    "编码混淆(超长串)": r"[A-Za-z0-9+/]{200,}={0,2}|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){20,}",
    "持久化/自启": r"(crontab\s+-|/etc/cron|systemd[/\\]|LaunchAgents|schtasks|reg\s+add[^\n]*Run|CurrentVersion\\Run)",
    "浏览器凭据": r"(Login Data|Local State|keychain|gnome-keyring|Credential Manager|Cookies\b)",
    "可疑端口": r":(4444|5555|6666|8888|1337|31337)\b",
    "chmod提权执行": r"chmod\s+(\+x|777|4755)",
    "sudo/提权": r"\bsudo\s+",
}

# ============ B 类：现代供应链手法 ============
PATTERNS_B = {
    "供应链投毒(node_modules改写)": r"node_modules[/\\][^\s\"']{0,80}[/\\]|writeFile[^\n]{0,80}node_modules",
    "依赖混淆/typosquat线索": r"(npm\s+install\s+|require\s*\(\s*[\"'])[a-z0-9]{3,20}[\"']",
    "反沙箱/环境探测": r"(/proc/1/cgroup|hypervisor|VBOX|VMware|qemu|SUDO_USER|SANDBOX|is_debugger|debugger\s*;)",
    "时间炸弹/延迟": r"(setTimeout|sleep\s*\(|Start-Sleep)[^\n]{0,60}\d{5,}|Date\.now\(\)\s*[<>]\s*\d{10}",
    "远程动态加载": r"(import\s*\(\s*[\"']https?://|require\s*\(\s*[\"']https?://|loadstring|eval\s*\(\s*await\s+fetch)",
    "隐写/加密载荷": r"(decrypt|AES|XOR|fromhex|unhexlify)[^\n]{0,80}(exec|eval|run|popen)",
    "字符串拆分混淆": r"[\"'][a-z]{2,4}[\"']\s*\+\s*[\"'][a-z]{2,4}[\"']\s*\+\s*[\"'][a-z]{2,4}[\"']",
    "进程注入/内存执行": r"(VirtualAlloc|CreateRemoteThread|WriteProcessMemory|ptrace|mmap\s*\([^)]*PROT_EXEC)",
    "凭据收集批量": r"(getpass|input\s*\(\s*[\"'][Pp]assword|keyring\.get|win32cred|CredRead)",
    "隐藏文件写入": r"[^\n]{0,40}\.(bashrc|zshrc|profile|bash_profile|gitconfig)",
}

# 要特殊标记的文件类型（文档示例无害）
DOC_EXT = {".md", ".txt", ".rst", ".html", ".json"}
CODE_EXT = {".sh", ".bash", ".py", ".js", ".mjs", ".cjs", ".ts", ".bat", ".cmd", ".ps1",
            ".rb", ".pl", ".php", ".go", ".rs", ".java"}


def sha256_file(p, limit=50 * 1024 * 1024):
    h = hashlib.sha256()
    try:
        with open(p, "rb") as f:
            while True:
                b = f.read(65536)
                if not b:
                    break
                h.update(b)
        return h.hexdigest()
    except Exception:
        return None


def scan_file(path: pathlib.Path, rel: str):
    hits = []
    try:
        raw = path.read_bytes()
    except Exception as e:
        return [("READ_ERROR", str(e), True)]
    if b"\x00" in raw[:4096]:
        return [("BINARY", f"二进制文件 {len(raw)}B", True)]
    try:
        txt = raw.decode("utf-8", errors="ignore")
    except Exception:
        return []

    ext = path.suffix.lower()
    is_doc = ext in DOC_EXT

    for group, pats in (("A", PATTERNS_A), ("B", PATTERNS_B)):
        for name, pat in pats.items():
            m = re.search(pat, txt, re.IGNORECASE | re.MULTILINE)
            if m:
                s = max(0, m.start() - 50)
                e = min(len(txt), m.end() + 50)
                ctx = txt[s:e].replace("\n", " \u23ce ").strip()
                hits.append((f"{group}·{name}", ctx, is_doc))
    return hits


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    target = pathlib.Path(sys.argv[1]).resolve()
    as_json = "--json" in sys.argv

    if not target.exists():
        print(f"路径不存在: {target}")
        sys.exit(1)

    files = [p for p in target.rglob("*") if p.is_file()]
    report = {
        "target": str(target),
        "file_count": len(files),
        "files": [],
        "hits": [],
        "binaries": [],
        "code_files": [],
    }

    for p in files:
        rel = str(p.relative_to(target))
        st = p.stat()
        report["files"].append({"path": rel, "size": st.st_size})
        if p.suffix.lower() in CODE_EXT:
            report["code_files"].append(rel)
        hits = scan_file(p, rel)
        for name, ctx, is_doc in hits:
            if name == "BINARY":
                report["binaries"].append({"path": rel, "size": st.st_size, "sha256": sha256_file(p)})
            else:
                report["hits"].append({
                    "file": rel, "pattern": name, "context": ctx,
                    "in_documentation": is_doc,
                })

    if as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return

    # 人读报告
    print("=" * 72)
    print(f" 安全审计静态扫描报告")
    print("=" * 72)
    print(f"目标目录 : {report['target']}")
    print(f"文件总数 : {report['file_count']}")
    print(f"可执行代码文件 : {len(report['code_files'])}")
    print(f"二进制文件 : {len(report['binaries'])}")
    print()

    code_hits = [h for h in report["hits"] if not h["in_documentation"]]
    doc_hits = [h for h in report["hits"] if h["in_documentation"]]

    print(f"--- 真实代码命中: {len(code_hits)} 处 {'⚠️ 需人工复核' if code_hits else '✅'} ---")
    by_file = defaultdict(list)
    for h in code_hits:
        by_file[h["file"]].append(h)
    for f, hs in sorted(by_file.items()):
        print(f"\n  [{f}]")
        for h in hs:
            print(f"    · {h['pattern']}")
            print(f"      {h['context'][:160]}")

    print(f"\n--- 文档/数据文件命中: {len(doc_hits)} 处（通常为示例代码，参考）---")
    doc_by = defaultdict(int)
    for h in doc_hits:
        doc_by[h["pattern"]] += 1
    for k, v in sorted(doc_by.items()):
        print(f"    {k}: {v}")

    if report["binaries"]:
        print(f"\n--- 二进制文件（需哈希/签名/杀毒校验）---")
        for b in report["binaries"]:
            print(f"    {b['path']}  {b['size']}B")
            print(f"      sha256={b['sha256']}")

    if report["code_files"]:
        print(f"\n--- 需逐行审阅的代码文件 ---")
        for c in report["code_files"]:
            print(f"    {c}")

    print()
    print("=" * 72)
    print("下一步：人工逐行审阅上述代码文件 + 供应链核查 + 行为验证")
    print("=" * 72)


if __name__ == "__main__":
    main()
