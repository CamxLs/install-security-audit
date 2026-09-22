# install-security-audit

**Check a package, repo, or agent skill before it touches your machine.**

Ten stages: static scanning, dependency verification, permission and data-flow review, persistence
diffs. Four Python scripts, no dependencies, one written report at the end.

You make the install call. The agent doesn't make it for you.

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
 7. Binary trustworthiness     Hash / origin / Authenticode / prebuilt-artifact cross-check
 8. Registry & persistence     Run keys / startup folders / services / scheduled tasks diff
 9. Risk assessment            Low / Medium (P1) / High (P0) + one of four verdicts
10. Audit ledger               Append to JSONL; query and aggregate across runs
```

Two sub-stages sit inside stage 7, because release artifacts and mirrors are where source-level
cleanliness stops meaning anything:

- **7.1 Prebuilt-binary audit** — signature status, version metadata, embedded domain and IP
  cross-check, and (for PyInstaller bundles) unpacking the archive to compare internal identifiers
  against the audited source
- **7.2 Mirror and distribution-channel check** — official domain vs re-upload, look-alike
  organizations, verification status

**Four verdicts**: ✅ Install ｜ ⚠️ Install with conditions ｜ 🧪 Install isolated ｜ ❌ Do not install

---

## What's New in v2.4

One audit drove most of this release: a documentation-only repository whose real payload turned out to
be an unsigned prebuilt binary in a sibling repo, and whose "runs locally, data never leaves your
device" headline didn't hold on anything except Apple Silicon. Every addition below comes from a gap
that audit walked into.

| Addition | Why it exists now |
|---|---|
| **Stage 7.1** prebuilt-binary audit | A clean source tree tells you nothing about the `.zip` users actually download. Covers signature status, version metadata, and unpacking a PyInstaller bundle to cross-check its internal identifiers against the source |
| **Stage 7.2** mirror and channel check | Re-uploads and look-alike organizations defeat "it's from the official repo" |
| **Documentation-only repositories** | A repo with 42 files and zero lines of code still ships a payload — it is in whatever the README tells you to install. The real audit target is somewhere else |
| **"Local privacy" that cannot be delivered** | When the source confines local inference to one platform, the promise dies on every other platform. Report this as a top-level conclusion, not a footnote |
| **The README as an attack surface** | Zero-width characters, bidirectional overrides, HTML comments, and prompt-injection strings — invisible to a human, visible to the model reading it |
| **Image trailing-payload detection** | In a docs repo, images are the only place a payload can hide. Bytes after a PNG's `IEND` chunk or a JPEG's EOI marker don't belong there |
| **Environment notes** | Working shell, PowerShell, and platform caveats, so a failed check isn't mistaken for a clean one |

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

**Shell note.** Some Windows environments ship a bash shim without the usual coreutils. If `ls`,
`head`, `mkdir`, `wc` or `find` report `command not found`, prepend the Git for Windows utilities
directory to `PATH`. Invoke `find` by absolute path — otherwise it resolves to the Windows
`FIND.EXE`, which has different semantics and will error out.

**PowerShell note.** In restricted environments `Add-Type` may be blocked, since it compiles and loads
.NET code at runtime; use `Expand-Archive` and other built-in cmdlets instead. If stdout is empty
despite an exit code of 0, write results with `Out-File` and read the file back.

---

## Disclaimer

This tool provides **audit assistance**, not a security guarantee.

- Static scanning produces false positives and false negatives; it does **not** replace dynamic validation or human judgment
- Uncovered stages are explicitly labeled — do not read them as "checked"
- The final install decision, and its consequences, rest with the user

---

## Version

Current release: **v2.4.0**. See [Releases](https://github.com/CamxLs/install-security-audit/releases)
for the changelog.

## License

[Apache License 2.0](LICENSE)
