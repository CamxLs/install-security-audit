#!/usr/bin/env python3
"""
install-security-audit companion audit script v2.1
Purpose: automated static security scan of any directory/package, with structured output.

Usage:
    python audit_scan.py <target-dir>
    python audit_scan.py <target-dir> --json
"""
import sys
import os
import re
import json
import hashlib
import pathlib
from collections import defaultdict

# ============ Class A: classic attack signatures ============
PATTERNS_A = {
    "pipe-to-shell (remote code)": r"(curl|wget|invoke-webrequest)[^\n|]{0,200}\|\s*(ba|z|k)?sh",
    "eval/exec dynamic execution": r"\b(eval|exec)\s*\(",
    "base64 decode-and-execute": r"base64\s+(-d|--decode)|atob\s*\(|FromBase64String",
    "command substitution $()": r"\$\([^)]{1,200}\)",
    "backtick command substitution": r"`[^`\n]{1,200}`",
    "hardcoded IP address": r"\b(?!127\.0\.0\.1|0\.0\.0\.0|255\.255)(\d{1,3}\.){3}\d{1,3}\b",
    "data exfiltration": r"(curl|wget|Invoke-RestMethod|fetch|requests\.post|http\.request)[^\n]{0,150}(-d\s|--data|--upload|-F\s|POST|body)",
    "sensitive env vars": r"\$\{?(AWS_|GITHUB_TOKEN|GH_TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL|ACCESS_TOKEN)",
    "SSH/cloud credential files": r"(\.ssh[/\\]|id_rsa|id_ed25519|\.aws[/\\]|\.netrc|\.git-credentials)",
    "reverse shell": r"\b(nc|netcat|ncat)\b[^\n]{0,60}(-e|--exec|-c\s)|bash\s+-i\s+>&",
    "encoding obfuscation (long blob)": r"[A-Za-z0-9+/]{200,}={0,2}|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){20,}",
    "persistence/autorun": r"(crontab\s+-|/etc/cron|systemd[/\\]|LaunchAgents|schtasks|reg\s+add[^\n]*Run|CurrentVersion\\Run)",
    "browser credentials": r"(Login Data|Local State|keychain|gnome-keyring|Credential Manager|Cookies\b)",
    "suspicious port": r":(4444|5555|6666|8888|1337|31337)\b",
    "chmod privilege escalation": r"chmod\s+(\+x|777|4755)",
    "sudo/elevation": r"\bsudo\s+",
}

# ============ Class B: modern supply-chain techniques ============
PATTERNS_B = {
    "supply-chain poisoning (node_modules write)": r"node_modules[/\\][^\s\"']{0,80}[/\\]|writeFile[^\n]{0,80}node_modules",
    "dependency confusion/typosquat clue": r"(npm\s+install\s+|require\s*\(\s*[\"'])[a-z0-9]{3,20}[\"']",
    "anti-sandbox/environment probing": r"(/proc/1/cgroup|hypervisor|VBOX|VMware|qemu|SUDO_USER|SANDBOX|is_debugger|debugger\s*;)",
    "time bomb/delayed trigger": r"(setTimeout|sleep\s*\(|Start-Sleep)[^\n]{0,60}\d{5,}|Date\.now\(\)\s*[<>]\s*\d{10}",
    "remote dynamic loading": r"(import\s*\(\s*[\"']https?://|require\s*\(\s*[\"']https?://|loadstring|eval\s*\(\s*await\s+fetch)",
    "steganography/encrypted payload": r"(decrypt|AES|XOR|fromhex|unhexlify)[^\n]{0,80}(exec|eval|run|popen)",
    "string-splitting obfuscation": r"[\"'][a-z]{2,4}[\"']\s*\+\s*[\"'][a-z]{2,4}[\"']\s*\+\s*[\"'][a-z]{2,4}[\"']",
    "process injection/memory execution": r"(VirtualAlloc|CreateRemoteThread|WriteProcessMemory|ptrace|mmap\s*\([^)]*PROT_EXEC)",
    "bulk credential collection": r"(getpass|input\s*\(\s*[\"'][Pp]assword|keyring\.get|win32cred|CredRead)",
    "hidden file write": r"[^\n]{0,40}\.(bashrc|zshrc|profile|bash_profile|gitconfig)",
}

# File types to treat specially (documentation examples are harmless)
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
        return [("BINARY", f"binary file {len(raw)}B", True)]
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
        print(f"Path does not exist: {target}")
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

    # Human-readable report
    print("=" * 72)
    print(f" Security Audit Static Scan Report")
    print("=" * 72)
    print(f"Target directory : {report['target']}")
    print(f"Total files      : {report['file_count']}")
    print(f"Executable code  : {len(report['code_files'])}")
    print(f"Binary files     : {len(report['binaries'])}")
    print()

    code_hits = [h for h in report["hits"] if not h["in_documentation"]]
    doc_hits = [h for h in report["hits"] if h["in_documentation"]]

    print(f"--- Real-code hits: {len(code_hits)} {'[!] needs manual review' if code_hits else '[ok]'} ---")
    by_file = defaultdict(list)
    for h in code_hits:
        by_file[h["file"]].append(h)
    for f, hs in sorted(by_file.items()):
        print(f"\n  [{f}]")
        for h in hs:
            print(f"    - {h['pattern']}")
            print(f"      {h['context'][:160]}")

    print(f"\n--- Documentation/data hits: {len(doc_hits)} (usually example code; for reference) ---")
    doc_by = defaultdict(int)
    for h in doc_hits:
        doc_by[h["pattern"]] += 1
    for k, v in sorted(doc_by.items()):
        print(f"    {k}: {v}")

    if report["binaries"]:
        print(f"\n--- Binary files (need hash/signature/AV verification) ---")
        for b in report["binaries"]:
            print(f"    {b['path']}  {b['size']}B")
            print(f"      sha256={b['sha256']}")

    if report["code_files"]:
        print(f"\n--- Code files requiring line-by-line review ---")
        for c in report["code_files"]:
            print(f"    {c}")

    print()
    print("=" * 72)
    print("Next: manually review the code files above + supply-chain verification + behavioral validation")
    print("=" * 72)


if __name__ == "__main__":
    main()
