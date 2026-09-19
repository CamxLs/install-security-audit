# install-security-audit

**A pre-install security audit workflow — mandatory supply-chain due diligence for AI agents and humans.**

Look a third-party project over thoroughly *before* it lands on your machine.

[![Release](https://img.shields.io/github/v/release/CamxLs/install-security-audit?label=release&color=red)](https://github.com/CamxLs/install-security-audit/releases)
[![License](https://img.shields.io/github/license/CamxLs/install-security-audit?color=blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-yellow)](#quick-start)
[![Zero Deps](https://img.shields.io/badge/dependencies-none-brightgreen)](#scripts)

[中文文档](README.zh-CN.md)

---

## Why

Most installs happen in seconds: `npm install`, `pip install`, a `git clone`, a new MCP server or agent skill.
Malicious code, supply-chain poisoning, and persistence backdoors hide precisely inside those seconds.

This project gives you a **structured, reproducible, mandatory audit process**:

- **9 audit stages** + **1 cross-run ledger**
- 4 zero-dependency Python scripts that turn "what to check" into "how to check it"
- A complete, reproducible report (every conclusion backed by a command and its output)
- **Report → user decides → then install.** The agent never decides on your behalf.

It works both as an operational spec for AI agents (`SKILL.md`) and as a methodology for humans.

---

## Core Principles

| Principle | Meaning |
|---|---|
| **Say nothing you can't see** | When a detection method is unavailable, mark it **"unverified"** — never guess a conclusion |
| **Never fake data** | Can't read the scheduled-tasks list? Show **"not covered"** — never imply "no scheduled tasks exist" |
| **Never silently downgrade** | If the sandbox won't run, do **not** quietly fall back to the real host. Escalate and hand over the decision |
| **Never silently skip** | The process is a fixed 9+1 stages — size or deadline is not a reason to trim it |
| **Always traceable** | Every audit is written to a ledger, so cross-run patterns (publisher reputation, recurring risks) surface |

---

## The Ten Stages

```
 1. Metadata verification      Publisher identity, reputation profile, version recency
 2. Static content audit       Full-file scan (Class A classic attacks + Class B modern supply chain)
 3. Line-by-line code review   Every executed artifact: reads / writes / network
 4. Supply-chain verification  Full dependency tree, typosquatting, CVEs, checksums
 5. Permissions & data flow    What data is read, where it is sent, least-privilege options
 6. Behavioral validation      Isolated run (fs/net/process/persistence) or mandatory escalation
 7. Binary trustworthiness     Hash / origin / signature / VirusTotal / local scan
 8. Registry & persistence     Run keys / startup folders / services / scheduled tasks diff
 9. Risk assessment            Low / Medium (P1) / High (P0) + one of four verdicts
10. Audit ledger               Append to JSONL; query and aggregate across runs
```

**Four verdicts**: ✅ Install ｜ ⚠️ Install with conditions ｜ 🧪 Install isolated ｜ ❌ Do not install

---

## Quick Start

No dependencies beyond Python 3.8+.

```bash
# 1) Static dangerous-pattern scan (16 Class A + 10 Class B checks)
python scripts/audit_scan.py <target-dir>

# 2) Snapshot the filesystem baseline (before install)
python scripts/fs_snapshot.py snapshot before.json <watched-dirs>

# 3) Snapshot the persistence baseline (registry / startup / services / scheduled tasks)
python scripts/registry_snapshot.py before.json

# 4) —— run the install ——

# 5) Re-snapshot and diff
python scripts/fs_snapshot.py snapshot after.json <watched-dirs>
python scripts/fs_snapshot.py diff before.json after.json

python scripts/registry_snapshot.py after.json
python scripts/registry_snapshot.py --diff before.json after.json --exclude-system

# 6) Record the audit in the ledger
python scripts/audit_ledger.py add \
  --name "some-package" --source "npm" --publisher "some-org" --version "1.2.3" \
  --level "low" --verdict "install" --notes "Conventional utility package, nothing anomalous" \
  --risks "none" --unverified "none"
```

---

## Scripts

| Script | Purpose | Deps |
|---|---|---|
| `audit_scan.py` | Static dangerous-pattern scan + SHA256 | none |
| `fs_snapshot.py` | Filesystem snapshot & diff (including sensitive-dir monitoring) | none |
| `registry_snapshot.py` | Registry autorun / startup folder / services / scheduled tasks baseline diff | none |
| `audit_ledger.py` | Audit ledger: `add` / `query` / `list` / `stats` | none |

### Handy options for `registry_snapshot.py`

```bash
--list-custom      List all third-party / custom scheduled tasks immediately when snapshotting
--exclude-system   Filter out built-in Windows tasks (200+) during diff so anomalies stand out
```

> The scheduled-tasks layer requires administrator privileges to read its protected locations.
> Under normal privileges the tool honestly reports **"not covered"** — that is correct behavior, not a bug.
> See [`ADMIN_RUN.md`](ADMIN_RUN.md) for the elevation procedure.

---

## Key Design: When the Sandbox Won't Run

Some projects **cannot** be exercised in a sandbox — they need real credentials, admin privileges,
specific hardware, a GUI, or the host simply offers no viable isolation mechanism.

In that situation, this project **forbids** silently running the project on the real host. Instead it requires:

1. **Stop.** Do not proceed, and do not act before reporting.
2. Add a **prominent standalone section** to the report covering:
   - **Why** the sandbox cannot run (the specific disqualifying condition)
   - The **risk exposure** of the unverified stage — which malicious behaviors could slip through
   - **Options and their trade-offs**:
     - **A** — Abandon dynamic validation; decide from static + supply-chain findings alone
     - **B** — Let the user decide whether to run it on the real host (explicit consent required, plus consequences and rollback)
     - **C** — Find an alternative isolation mechanism (VM / separate machine)
3. **Hand the decision to the user** and wait for explicit instruction.

> The principle: **an AI can advise, but it cannot absorb risk on the user's behalf.**

---

## Using It as an AI Agent Skill

`SKILL.md` is a ready-to-load skill definition (YAML frontmatter, trigger conditions, process, output template).
Drop the directory into your agent's skill folder:

```
~/.config/agent-skills/install-security-audit/
```

Once loaded, the agent walks all ten stages and produces a report before any install action.

---

## Platform Notes

The **methodology is platform-agnostic**; the scripts in this repository currently implement the
Windows-specific layers (registry autorun keys, Windows services, Task Scheduler).

On macOS/Linux the same stages apply — substitute the equivalents:

| Stage | Windows | macOS / Linux |
|---|---|---|
| 8 — Persistence | Registry `Run` keys, Startup folder, Services, Task Scheduler | `launchd`/`LaunchAgents`, systemd units, `crontab`, `~/.bashrc`/`~/.profile` |
| 7 — Signatures | `certutil -verify`, Authenticode | `codesign`, `gpg --verify` |
| 6 — Sandbox | Windows Sandbox, isolated dir + snapshot diff | `firejail`, containers, `strace`/`dtruss` |

Contributions extending the scripts to other platforms are welcome.

---

## Disclaimer

This tool provides **audit assistance**, not a security guarantee.

- Static scanning produces false positives and false negatives; it does **not** replace dynamic validation or human judgment
- Uncovered stages are explicitly labeled — do not read them as "checked"
- The final install decision, and its consequences, rest with the user

---

## Version

Current release: **v2.2.0** (first public release).

See [Releases](https://github.com/CamxLs/install-security-audit/releases) for the changelog.

## License

[Apache License 2.0](LICENSE)
