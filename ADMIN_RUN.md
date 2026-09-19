# Running with Administrator Privileges (covering the scheduled-tasks layer)

The **scheduled-tasks** layer of `registry_snapshot.py` requires administrator privileges to read.
Under normal privileges the tool honestly reports "not covered" — which is itself consistent with
the audit's principle of honesty. But if you want the **complete persistence picture** (including
scheduled tasks), follow the steps below.

---

## Why administrator privileges are needed

Scheduled-task metadata lives in two protected locations:

| Location | Normal privileges | Administrator |
|---|---|---|
| Registry `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree` | ❌ WinError 5 access denied | ✅ Readable |
| Directory `C:\Windows\System32\Tasks` | ❌ WinError 5 access denied | ✅ Readable |

The other layers (registry autorun keys, startup folders, auto-start services) are **readable under
normal privileges** and need no elevation.

---

## Procedure

### Option 1: Open a terminal as administrator (recommended)

1. Press `Win` and type `PowerShell`
2. **Right-click → Run as administrator** on "Windows PowerShell"
3. Click "Yes" in the UAC prompt
4. Run the following commands in order (replace the paths with your actual local paths)

```powershell
# Define the Python and script paths (replace with your actual paths)
$py     = "python"                                        # or the full path to your Python executable
$script = ".\scripts\registry_snapshot.py"                # path to this repository's script

# 1) Before install: capture an administrator-level baseline
& $py $script ".\audit_baseline_before.json"

# 2) (Perform your install here)

# 3) After install: capture again
& $py $script ".\audit_baseline_after.json"

# 4) Diff
& $py $script --diff ".\audit_baseline_before.json" ".\audit_baseline_after.json"

# 4b) Third-party tasks only (filter built-in noise — recommended)
& $py $script --diff ".\audit_baseline_before.json" ".\audit_baseline_after.json" --exclude-system
```

> **Tip**: Windows ships 200+ built-in scheduled tasks (`\Microsoft\Windows\...`).
> Adding `--exclude-system` shows only third-party/custom tasks, so anomalies stand out.
> You can also add `--list-custom` at snapshot time to **list** all current third-party tasks:
>
> ```powershell
> & $py $script ".\audit_baseline.json" --list-custom
> ```

### Option 2: A shortcut with "Run as administrator"

If you prefer a graphical approach, create a desktop shortcut:
- Target: your Python executable (e.g. `python.exe`)
- Arguments: `".\scripts\registry_snapshot.py" ".\audit_baseline.json"`
- Then right-click the shortcut → **Run as administrator**

---

## Confirming the scheduled-tasks layer is covered

After running the snapshot command, check the end of the output:

```
  Scheduled tasks: covered
```

The diff report will show at the end:

```
Coverage for this comparison:
   [covered] registry autoruns / startup folders / auto-start services
   [covered] scheduled tasks
```

If it still shows "not covered", you are not truly elevated — check that you are running in an
administrator terminal.

---

## Notes

- **Read-only**: this tool writes to and modifies no registry keys or scheduled tasks. Elevation is used only to **read protected locations**.
- **Recommendation**: keep baseline files inside your working directory for easy tracking.
- **Combine freely**: an administrator baseline and a normal-privilege baseline can coexist; both use the same format and the same diff logic.
- **Safety**: only elevate for scripts you trust; this script's source can be reviewed at any time (`scripts/registry_snapshot.py`).
