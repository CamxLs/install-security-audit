# 如何以管理员身份运行（覆盖「计划任务」层）

`registry_snapshot.py` 的**计划任务**层需要管理员权限才能读取。
普通权限下工具会如实标注「未覆盖」，这本身符合审计的诚实原则，
但如果你希望拿到**完整的持久化画像**（含计划任务），请按下面操作。

---

## 为什么需要管理员权限

计划任务的元数据存放在两个受保护位置：

| 位置 | 普通权限 | 管理员 |
|---|---|---|
| 注册表 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree` | ❌ WinError 5 拒绝访问 | ✅ 可读 |
| 目录 `C:\Windows\System32\Tasks` | ❌ WinError 5 拒绝访问 | ✅ 可读 |

其余层（注册表自启键、启动文件夹、自启动服务）**普通权限即可读取**，无需提权。

---

## 操作步骤

### 方式一：以管理员身份打开终端（推荐）

1. 按 `Win`，输入 `PowerShell`
2. 在「Windows PowerShell」上**右键 → 以管理员身份运行**
3. 在弹出的 UAC 窗口点「是」
4. 依次执行下面的命令（把路径替换为你本机的实际路径）

```powershell
# 定义 Python 与脚本路径（按本机实际路径替换）
$py     = "python"                                        # 或 Python 可执行文件的完整路径
$script = ".\scripts\registry_snapshot.py"                # 本仓库脚本路径

# 1) 安装前：拍管理员级基线
& $py $script ".\audit_baseline_before.json"

# 2) （此时执行你的安装操作）

# 3) 安装后：重新拍
& $py $script ".\audit_baseline_after.json"

# 4) 对比
& $py $script --diff ".\audit_baseline_before.json" ".\audit_baseline_after.json"

# 4b) 只看第三方任务（过滤系统内建噪声，推荐）
& $py $script --diff ".\audit_baseline_before.json" ".\audit_baseline_after.json" --exclude-system
```

> **提示**：系统内建计划任务通常有 200+ 个（`\Microsoft\Windows\...`），
> 加 `--exclude-system` 可只看第三方/自定义任务，异常项一眼可见。
> 也可以在拍基线时加 `--list-custom` **立即列出**当前所有第三方任务：
>
> ```powershell
> & $py $script ".\audit_baseline.json" --list-custom
> ```

### 方式二：右键「以管理员身份运行」快捷方式

若你更习惯图形操作，可在桌面创建快捷方式：
- 目标：你的 Python 可执行文件（如 `python.exe`）
- 参数：`".\scripts\registry_snapshot.py" ".\audit_baseline.json"`
- 然后右键快捷方式 → **以管理员身份运行**

---

## 如何确认「计划任务」层已覆盖

运行快照命令后，看输出末尾：

```
  计划任务: 已覆盖
```

对比报告末尾会显示：

```
本次对比覆盖范围：
   [已覆盖] 注册表自启动键 / 启动文件夹 / 自启动服务
   [已覆盖] 计划任务
```

如果仍显示「未覆盖」，说明未真正提权，请检查是否在管理员终端中运行。

---

## 注意事项

- **只读**：本工具不写入、不修改任何注册表或计划任务，提权仅用于「读取受保护位置」。
- **建议**：基线文件存放在你的工作区，便于追踪。
- **配合使用**：管理员基线可与普通权限基线并存，二者格式一致，diff 逻辑相同。
- **安全**：仅在你信任的脚本上提权；本脚本源码可随时审阅（`scripts/registry_snapshot.py`）。
