---
name: install-security-audit
slug: install-security-audit
displayName: "Install Security Audit (Pre-Install Security Audit)"
version: 2.2.0
description: "Pre-install security audit. Before installing, updating, or introducing any third-party project, run this skill first and only then make an install decision — covering installing/updating agent skills, MCP servers, plugins, and tools; running npm install / pip install / cargo install / brew install; cloning or pulling external repositories; downloading and executing scripts; or introducing any third-party component that executes code or accesses the network on the host. Trigger words: install, add package, update, npm install, pip install, clone repo, download and run. Process: 9-stage full-spectrum audit -> complete reproducible report -> user decides -> only then install -> record in the audit ledger. Run the full process every time; never skip, never conceal. When the sandbox cannot run the target, escalate explicitly and let the user decide whether to run it on the real host."
license: Apache-2.0
agent_created: true
---

# Pre-Install Security Audit v2.2

> **MANDATORY process. Not bypassable.**
> Before any install action, run this process to completion → report the results to the user → let the user decide whether to install.
> Never decide on the user's behalf, never skip, never conceal risk.
> **Run the full process every time (9 stages + ledger). Never cherry-pick stages.**

## Trigger Conditions

**Any** action that introduces third-party code onto the host:

- Installing / updating an agent skill
- Installing / updating an MCP server, plugin, or tool
- `npm install` / `pip install` / `cargo install` / `brew install`, or any other package install
- Cloning or pulling an external repository; downloading and executing a script
- Introducing any third-party project that **executes code** or **accesses the network** on the host

## Recommended Configuration

| Item | Setting |
|---|---|
| Online detection services (VirusTotal, etc.) | Allowed (query by hash; do not upload samples) |
| Sandbox execution | Yes — perform the run |
| Report detail | Complete and reproducible (each conclusion with command + output) |

---

## Nine Audit Stages + Ledger (all required)

### Stage 1: Metadata Verification
- Publisher identity, source repository, license
- Download counts / stars / install counts
- Official security reports
- **Publisher reputation profile**:
  - What else has this publisher released? Is it bulk-published filler on the same theme?
  - Any versions withdrawn or yanked?
  - Any public security incidents or complaints?
- Version recency: is it current? Long-unmaintained (possibly abandoned)?

### Stage 2: Static Content Audit (all files)
List **every file** (nothing omitted) and scan with regexes in bulk.

**Class A — classic attack signatures**
- Pipe-to-shell: `curl|wget ... | bash`
- `eval` / `exec`
- base64 decode-and-execute
- Command substitution: `` `...` `` / `$(...)`
- Hardcoded IP addresses
- Data exfiltration (curl -d / --data / --upload-file / POST / webhook)
- Reading sensitive environment variables (AWS/TOKEN/SECRET/PASSWORD/API_KEY/PRIVATE/CREDENTIAL)
- Reading SSH keys / cloud credentials (.ssh / id_rsa / .aws / .env)
- Reverse shell (nc/netcat/ncat/bash -i)
- Encoding obfuscation (long base64 / hex blobs)
- Persistence (crontab / systemd / LaunchAgents / schtasks / registry Run)
- Reading browser credentials / key stores

**Class B — modern supply-chain techniques**
- **Supply-chain poisoning**: install scripts writing into other packages' directories, mutating `node_modules`, tampering with already-installed packages
- **Dependency confusion / typosquatting**: package names close to well-known ones (`lodas` vs `lodash`)
- **Environment probing / anti-sandbox**: detecting VM / CI / sandbox environments (`/proc/1/cgroup`, `hypervisor`, `SUDO_USER`) to evade analysis
- **Time bombs**: delayed triggers, date-activated behavior, random sleep before acting
- **Credential proxying**: not reading credentials directly, but exfiltrating them via legitimate-looking API calls
- **Dynamic code loading**: fetching and executing code from a remote URL at runtime (`import()`, `require()` of a remote URL)
- **Steganography / encrypted payloads**: ciphertext blob + runtime decryption
- **Obfuscation evasion**: string splitting and concatenation to defeat regex (`"cu"+"rl"`)

**Judgment rule**: example commands inside documentation (.md) code blocks are harmless. Always distinguish **"example"** from **"actually executable code"**.

### Stage 3: Line-by-Line Code Review
Read and explain the true behavior of **every executed artifact**:
- Install scripts (postinstall / preinstall / prepare / setup.py / build.rs)
- shell / python / js / ts scripts
- Executable wrappers (`.js` / `.cmd` / `.ps1` shims under `bin`)
- Build scripts

**Each must answer**: what data does it read? What files does it write? What network does it contact? Any covert behavior?

### Stage 4: Supply-Chain Verification (critical)
If external packages / binaries are involved:
- **Expand the full dependency tree** (including transitive dependencies), not just direct ones
- Verify identity:
  - npm: `https://registry.npmjs.org/<pkg>`
  - PyPI: `https://pypi.org/pypi/<pkg>/json`
  - GitHub: `https://api.github.com/repos/<owner>/<repo>`
- Cross-check: maintainer, organization, repository URL, license, publish date, whether official
- **Typosquat detection**: edit-distance comparison against well-known package names
- **Security history**: has this package/organization had CVEs or poisoning incidents?

### Stage 5: Permissions and Data Flow
- What data is read (files / environment / browser / credentials)?
- Where is data sent (domains / IPs / uploads)?
- Are credentials / API keys required?
- Are there default restrictions? Do safe options need to be explicitly enabled?
- **Least-privilege plan**: can it be installed isolated? Can network be restricted? Can it be limited to only the directories it needs?

### Stage 6: Behavioral Validation (sandbox run + escalation when unavailable)
> Static review cannot see dynamically generated malicious behavior; you must observe it.
> **But a sandbox is not omnipotent** — some projects cannot run in one (see the criteria below). In that case, **never quietly fall back to the real host.**

#### 6.1 Preferred: isolated-environment run
- Execute the install / run inside an **isolated directory or sandbox** (without contaminating the system)
- Monitor four behavior classes:
  - **Filesystem**: which paths were written/modified (especially system dirs, other packages' dirs, startup locations)
  - **Network**: which domains/IPs were contacted (especially unofficial ones, suspicious ports)
  - **Processes**: which child processes were spawned, what commands were executed
  - **Persistence**: were registry autoruns, scheduled tasks, or services created (see Stage 8)

**Practical methods**:

1. **Filesystem snapshot diff** (`scripts/fs_snapshot.py` — preferred)
   - **Before** install, record the scope list + hashes: target directory + sensitive locations (`~/.ssh`, `~/.aws`, startup items, `hosts`, installed `node_modules`)
   - **After** install, record again and diff → added / modified / deleted list
   - Any unexpected write to a **sensitive location** → flag as high risk immediately

2. **Persistence baseline diff** (`scripts/registry_snapshot.py`)
   - Diff registry autoruns / startup folders / auto-start services / scheduled tasks before and after install
   - See Stage 8

3. **Network behavior observation**
   - Diff `netstat -ano` snapshots before and after install
   - Statically extract domains/IPs from the scripts and compare against official claims
   - Determine whether there is **unofficial, suspicious-port, or cleartext exfiltration**

4. **Process behavior observation**
   - Wrap execution with Python `subprocess` and capture child-process invocations
   - Watch for: spawning a shell, calling `curl`/`wget`, executing a downloaded file

#### 6.2 Criteria for "cannot be safely sandboxed" (check each explicitly)
If **any** of these applies, it is **"cannot be safely sandboxed"**:
- Requires **real credentials / accounts** to start (login state, API key, OAuth)
- Requires **privileges** (administrator/root, service registration, driver loading)
- Requires **real hardware / devices / network resources** (printer, serial port, specific intranet)
- Requires **GUI desktop interaction** and the sandbox has no display
- The host **lacks sandbox capability** (e.g. Windows Sandbox not enabled, no alternative isolation)
- The run itself **could damage the system** or cause irreversible side effects

#### 6.3 [MANDATORY] Escalation and handover when the sandbox is unavailable
> **A hard requirement. Never bypassed.**

When "cannot be safely sandboxed" is determined, you **must**:

1. **Stop** any thought of running it anyway — **never run it on the real host on your own initiative**
2. Add a **prominent standalone section** to the report, containing:
   - **Why** the sandbox cannot run (the specific 6.2 condition)
   - The **risk exposure** of this unverified stage (which malicious behaviors might be missed)
   - **Options and their trade-offs**, at minimum:
     - **Option A**: **Abandon dynamic validation** — decide from static + supply-chain findings alone
     - **Option B**: **Let the user decide** whether to run it on the real host (requires explicit consent; state possible consequences and rollback)
     - **Option C**: **Wait for / find an alternative isolation mechanism** (e.g. the user runs it in a VM or separate machine)
3. **Hand the decision to the user** and act only after explicit instruction

**Forbidden wording and behavior**:
- ❌ "The sandbox won't run it, so I'll just run it locally" (unauthorized downgrade)
- ❌ "To save time, skipping behavioral validation" (silent omission)
- ❌ Using a "low risk" conclusion to **conceal** the fact that dynamic validation was not done
- ✅ "The sandbox cannot run this, reason X; should I run it on the real host? Your call."

- **If it truly cannot be run**: **state plainly that behavioral validation was not performed**, flag it as unverified risk, and call it out separately in the report.

### Stage 7: Binary Trustworthiness
For downloaded compiled artifacts (.exe / .dll / .so / binaries):
- **Hash verification**: `scripts/audit_scan.py` computes SHA256 automatically; compare against the official published checksum (if any)
- **Official origin**: does the download URL point to the official repository release / official CDN?
- **Digital signature**: verify the signer with `certutil -verify <file>` or PowerShell `Get-AuthenticodeSignature`
- **Online detection**: submit the file hash to VirusTotal (query by hash to avoid uploading samples)
- **Local scan**: Windows Defender `MpCmdRun.exe -Scan -ScanType 3 -File <path>`
- With no checksum / no signature, **flag it as residual supply-chain risk**

#### Detection capability reference (observed on Windows)
| Capability | Status | Notes |
|---|---|---|
| SHA256 computation | ✅ Available | Handled automatically by the bundled script |
| `curl` / `certutil` / `git` / `npm` / `node` | ✅ Available | Standard system paths |
| `signtool` / `7z` / `strings` / `objdump` / `wmic` | ❌ Often missing | Use `certutil -verify` for signature checks |
| Windows Defender `MpCmdRun.exe` | ⚠️ Environment-dependent | May return `0x80004005` in restricted environments. Fallback: VirusTotal |
| Windows Sandbox (WSB) | ❌ Disabled by default | Use "isolated directory + filesystem snapshot diff" instead |
| PowerShell `Add-Type` / COM instantiation | ⚠️ May be blocked by policy | If unavailable, use the external `certutil` command |
| `reg.exe` / `schtasks.exe` / `sc.exe` | ⚠️ May be blocked by policy | If blocked, read the registry via Python's native `winreg` module |
| Reading `C:\Windows\System32\Tasks` | ⚠️ Access denied (WinError 5) | The scheduled-tasks directory requires administrator privileges |

> The table above is a common reference; defer to actual results on the host.
> **Principle**: when a detection method is unavailable, **state plainly "method unavailable, unverified"** — never speculate a conclusion.

### Stage 8: Registry and Persistence Baseline Diff
> **Filesystem snapshots (Stage 6) only see "files" — they cannot see "registry / scheduled tasks / services" persistence backdoors.**
> Attackers often write autoruns into registry Run keys without dropping any new file — this layer must be covered explicitly.

**Bundled tool**: `scripts/registry_snapshot.py` (snapshot a baseline before install, diff after)

> **Third-party task filtering**
> Windows ships 200+ built-in scheduled tasks, which drown out third-party ones. The tool supports:
> - `--list-custom`: **list** all third-party/custom tasks immediately at snapshot time
> - `--exclude-system`: **filter** system tasks during diff so anomalies stand out
> The baseline file always stores the complete list; filtering only affects display, never detection completeness.

**Coverage**:
| Layer | Covered | Method |
|---|---|---|
| Registry autorun keys (HKCU/HKLM Run, RunOnce, Wow6432Node, Policies\Explorer\Run, RunServices) | ✅ | Python `winreg` native read |
| Key single-value hijack points (Winlogon Userinit/Shell, HKCU Windows Load/Run, AppInit_DLLs) | ✅ | Same as above |
| Startup folders (user + all-users) | ✅ | Direct directory read |
| Auto-start services (Start=0/1/2) | ✅ | Read `HKLM\SYSTEM\CurrentControlSet\Services` |
| Scheduled tasks | ⚠️ **Not covered under normal privileges** | TaskCache registry and the Tasks directory both require administrator privileges; **the report must state this explicitly**, and recommend re-running elevated (see `ADMIN_RUN.md`) |

> **Implementation note**: when elevated, the tool recursively walks `TaskCache\Tree` and reads each task's `Actions`
> (the program and arguments to execute), so "added/modified scheduled task" can be detected by the diff.
> When comparing against a baseline generated by an older version, the scheduled-tasks layer will show
> "not covered" because that baseline contains no task list — this is correct behavior (no data means no pretending).

**Judgment rules**:
- Any **added/modified** registry autorun value, startup-folder item, or auto-start service → **flag as high risk immediately** and put it on the priority review list
- A new service whose image path points to a temp directory / user directory / suspicious path → high risk
- **When the scheduled-tasks layer is not covered, state it separately in the report** — never default to "no scheduled tasks"

### Stage 9: Risk Assessment and Conclusion
Output:
- **Risk level**: Low / Medium (P1) / High (P0)
- **Evidence**: specific findings (reproducible)
- **Residual risk**: risks that cannot be eliminated
- **Recommendation (four tiers)**:
  - ✅ **Install as-is** (low risk)
  - ⚠️ **Install with conditions** (requires explicit user confirmation)
  - 🧪 **Install isolated** (sandbox / restricted directory, without full privileges)
  - ❌ **Do not install** (high risk)

---

## Reporting and Decision (strict order)

1. **Report first**: tell the user completely and honestly (with evidence)
2. **Then decide**: the user decides whether to install
3. **P0 high risk** → strong warning + recommend against installing; proceed only if the user insists
4. **P1 medium risk** → warn and require explicit user confirmation
5. Install only after the user **explicitly agrees**
6. **Write the ledger** (not optional): regardless of the verdict, **always** record this audit in the ledger

## Stage 10: Audit Ledger (every time)

> A single audit is isolated; the ledger makes cross-run patterns visible: whether a publisher
> has been audited repeatedly, whether a package keeps showing residual risk, how it was judged last time.

**Tool**: `scripts/audit_ledger.py`
**Ledger location**: `~/.install-security-audit/ledger.jsonl` (JSONL, append-only)

**At the end of every audit, run**:
```bash
python scripts/audit_ledger.py add \
  --name "<project>" --source "<source>" --publisher "<publisher>" --version "<version>" \
  --level "<low/medium/high>" --verdict "<install/conditional/isolated/reject/uninstalled>" \
  --notes "<key findings>" --risks "<residual risk>" --unverified "<unverified items>"
```

**Before an audit begins, query the history**:
```bash
python scripts/audit_ledger.py query --publisher "<publisher>"   # what has this publisher been audited for?
python scripts/audit_ledger.py query --name "<project>"          # how many times has this project been audited?
```
If history is found, **you must cite it in the report** (e.g. "this publisher has been audited N times before, with verdicts ...").

**Why the ledger matters**:
- The **source of truth** for the publisher reputation profile (usable in Stage 1)
- A **cumulative view** of residual risk (`stats` shows how many records carry residual risk)
- A **traceable basis** for decisions (not memory)

## Absolute Prohibitions

- Skipping checks because it "looks official", "has high download counts", "the user is in a hurry", or "I checked something similar last time"
- Simplifying the process because the task is small / time is short / the user is pushing
- Concealing risk or softening the warning
- **Running on the real host on your own initiative when the sandbox is unavailable** (must escalate and hand the decision to the user)
- **Silently omitting a stage** (e.g. skipping behavioral validation or the persistence baseline), or using a "low risk" conclusion to conceal the fact that something was not verified
- **Skipping the ledger** (every audit must be recorded, regardless of the verdict)
- When a full check is impossible, failing to state plainly that "the check is incomplete" and to mark the unverified parts

**This process outranks any efficiency consideration.**

## [MANDATORY] Always Run the Full Process

- **Never** run only a few stages because "this project is small", "it looks safe", or "we're in a hurry"
- **All ten stages must be executed.** If any stage cannot be completed, **list the incomplete items and the reason explicitly in the "Audit Completeness" section** of the report, and hand the decision to the user
- The process is **fixed**, not a menu — nine audit stages plus the ledger entry, every single time
- If a stage genuinely cannot be completed due to objective limits (privileges, environment), **label it plainly as unverified** — never pretend it was covered

---

## Output Template (complete and reproducible)

```
## Security Audit Report: <project>

**Audit time**: <time>
**Risk level**: Low / Medium (P1) / High (P0)
**Audit completeness**: Complete / Partial (list unverified items)
**Ledger history**: <previous audit records for this publisher/project, if any>

### 1. Metadata
- Source / publisher / license / version:
- Downloads / stars / official security reports:
- Publisher reputation: <past projects, incidents; ledger query results>

### 2. File and Content Scan
- Total file count and listing:
- Class A hits: <whether each is an example or real code>
- Class B hits: <supply-chain poisoning / obfuscation / anti-sandbox, etc.>

### 3. Code Review
| Script | Behavior | Reads | Writes | Network |
|---|---|---|---|---|

### 4. Supply Chain
- Dependency tree:
- Identity cross-check:
- Typosquat detection:
- Security history:
- Checksum: present / absent (flag the risk)

### 5. Data Flow
- Reads / sends / credentials / default restrictions / least-privilege plan:

### 6. Behavioral Validation (sandbox run)
- Method:
- Filesystem changes:
- Network connections:
- Process behavior:
- Or: <not performed — reason + unverified risk flagged>

**If the sandbox cannot run (6.3 mandatory escalation)**:
- Why the sandbox cannot run: <the specific 6.2 condition>
- Risk exposure of this unverified stage: <which malicious behaviors might be missed>
- Options: A abandon dynamic validation (decide from static + supply-chain only) / B run on the real host (your confirmation required) / C find alternative isolation
- **Please decide how to proceed; I will not run it on the real host until you explicitly instruct me**

### 7. Binary Trustworthiness
- Hash verification / official origin / signature / VirusTotal / local scan:

### 8. Registry and Persistence Baseline
- Registry autorun changes: none / <list added or modified entries>
- Startup folder changes: none / <list>
- Auto-start service changes: none / <list>
- Scheduled tasks: covered / **not covered (administrator privileges required — unverified)**
- Tool: `registry_snapshot.py --diff`

### 9. Residual Risk and Recommendation
- Residual risk:
- Recommendation: ✅ Install / ⚠️ Install with conditions / 🧪 Install isolated / ❌ Do not install
- **Please confirm whether to install**

### 10. Audit Ledger (required)
- Written to ledger: yes / no
- Record contents: <project/source/publisher/level/verdict/residual risk/unverified items>
- Ledger location: `~/.install-security-audit/ledger.jsonl`

### Evidence Appendix (reproducible)
<key commands and output excerpts>
```
