# install-security-audit

**装之前先看清：第三方的包、仓库、Skill，落地前先审一遍。**

十个环节：静态扫描、依赖核查、权限与数据流向、持久化对比。四个无依赖 Python 脚本，
最后出一份报告。

装不装由你决定，Agent 不替你决定。

[![Release](https://img.shields.io/github/v/release/CamxLs/install-security-audit?label=release&color=red)](https://github.com/CamxLs/install-security-audit/releases)
[![License](https://img.shields.io/github/license/CamxLs/install-security-audit?color=blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-yellow)](#快速开始)
[![Zero Deps](https://img.shields.io/badge/dependencies-none-brightgreen)](#脚本)

[English](README.md) ｜ [管理员运行说明](ADMIN_RUN.zh-CN.md)

---

## 这是什么

大多数"安装"动作发生在几秒钟内：`npm install`、`pip install`、克隆一个仓库、装一个 Skill 或 MCP Server。
而恶意代码、供应链投毒、注册表后门，恰恰藏在这几秒钟里。

本项目提供一套**结构化、可复现、强制的审计流程**：

- **9 个审计环节** + **1 个跨次审计台账**
- 配 4 个零依赖 Python 脚本，把「审什么」变成「怎么审」
- 输出完整可复现报告（每条结论附命令与输出）
- **报告 → 用户决策 → 才可安装**，绝不代为决定

它既是给 AI Agent 的操作规范（`SKILL.zh-CN.md`），也是给人看的方法论。

---

## 核心理念

| 原则 | 含义 |
|---|---|
| **不全则不言** | 某项检测手段不可用时，明确标注「不可用，未验证」，绝不臆测结论 |
| **不假有数据** | 拿不到计划任务清单，就显示「未覆盖」，不假装「无计划任务」 |
| **不擅自降级** | 沙箱跑不起来时，绝不偷偷改在本机真实环境跑，而是上报并交出决策权 |
| **不静默省略** | 流程是固定的 9+1 环节，不因「项目小」「赶时间」而只跑几个 |
| **可回溯** | 每次审计落台账，跨次规律（发布者信誉、反复出现的风险）可见 |

---

## 十个环节

```
1. 元信息核查          发布者身份 / 信誉档案 / 版本时效
2. 静态内容审计        全量文件扫描（A 类经典攻击 + B 类现代供应链）
3. 代码逐行审阅        所有会被执行的代码：读什么/写什么/连什么
4. 供应链核查          依赖树全展开 / typosquat / 历史 CVE / 校验和
5. 权限与数据流向      读哪些数据、发往哪里、最小权限方案
6. 行为验证            沙箱试跑（文件/网络/进程/持久化）或强制上报
7. 二进制可信度        哈希 / 来源 / Authenticode / 预编译产物交叉验证
8. 注册表与持久化基线  Run 键 / 启动文件夹 / 服务 / 计划任务 diff
9. 风险评估与结论      低 / 中(P1) / 高(P0) + 四档建议
10. 审计台账           写入 JSONL，跨次可查、可统计
```

环节 7 下面挂了两个子环节。原因很简单：到了发布产物和镜像这一层，「源码干净」就不说明任何问题了。

- **7.1 预编译二进制审计** —— 签名状态、版本元数据、内嵌域名与 IP 交叉比对；若是 PyInstaller 打包，
  还要解包归档，把内部标识串与已审计源码对一遍
- **7.2 镜像与分发渠道核查** —— 官方域 vs 转存、仿冒组织、验证状态

**四档结论**：✅ 可直接安装 ｜ ⚠️ 有条件安装 ｜ 🧪 隔离安装 ｜ ❌ 不建议安装

---

## v2.4 新增了什么

这一版的内容基本来自同一次审计：一个纯文档仓，真正的载荷是兄弟仓库里一个未签名的预编译二进制；
而它「本地运行、数据不出设备」的招牌，只在 Apple Silicon 上成立。下面每一条，都是那次审计踩出来的缺口。

| 新增 | 为什么现在有 |
|---|---|
| **环节 7.1** 预编译二进制审计 | 源码干净，跟用户实际下载的那个 zip 有没有问题，是两回事。覆盖签名状态、版本元数据，以及解包 PyInstaller 归档、比对其内部标识串与源码 |
| **环节 7.2** 镜像与渠道核查 | 转存包和仿冒组织，让「这是从官方仓库下的」这句话失效 |
| **纯文档仓** | 一个 42 文件、0 行代码的仓库照样有载荷 —— 在 README 指引你安装的东西里。真正的审计目标在别处 |
| **「本地隐私」兑现不了** | 源码把本地推理限定为单一平台时，这个承诺在其他平台上是死的。要当一级结论写，不是脚注 |
| **README 作为攻击面** | 零宽字符、双向覆盖、HTML 注释、提示词注入串 —— 人看不见，读它的模型看得见 |
| **图片尾部追加载荷检测** | 文档仓里，图片是唯一能藏载荷的地方。PNG 的 `IEND` 之后、JPEG 的 EOI 之后，不该有任何字节 |
| **环境说明** | shell、PowerShell 与平台注意事项，避免「检测没跑成」被当成「检测通过」 |

---

## 快速开始

无需安装任何依赖，只要 Python 3.8+。

```bash
# 1) 静态危险模式扫描（A 类 16 项 + B 类 10 项）
python scripts/audit_scan.py <目标目录>

# 2) 安装前：拍文件系统基线
python scripts/fs_snapshot.py snapshot before.json <监控目录>

# 3) 安装前：拍持久化基线（注册表/启动项/服务/计划任务）
python scripts/registry_snapshot.py before.json

# 4) ——执行安装——

# 5) 安装后：重新拍 + 对比
python scripts/fs_snapshot.py snapshot after.json <监控目录>
python scripts/fs_snapshot.py diff before.json after.json

python scripts/registry_snapshot.py after.json
python scripts/registry_snapshot.py --diff before.json after.json --exclude-system

# 6) 写入审计台账
python scripts/audit_ledger.py add \
  --name "some-package" --source "npm" --publisher "some-org" --version "1.2.3" \
  --level "低" --verdict "install" --notes "常规工具包，无异常" \
  --risks "无" --unverified "无"
```

---

## 脚本

| 脚本 | 作用 | 零依赖 |
|---|---|---|
| `audit_scan.py` | 静态危险模式扫描 + SHA256 | ✅ |
| `fs_snapshot.py` | 文件系统快照与 diff（含敏感目录监控） | ✅ |
| `registry_snapshot.py` | 注册表自启 / 启动文件夹 / 服务 / 计划任务 基线对比 | ✅ |
| `audit_ledger.py` | 审计台账：add / query / list / stats | ✅ |

### registry_snapshot.py 的实用选项

```bash
--list-custom      拍基线时立即列出所有第三方/自定义计划任务
--exclude-system   对比时过滤系统内建任务（200+ 个噪声），异常一眼可见
```

> 计划任务层需要管理员权限才能读取受保护位置。
> 普通权限下工具会如实显示「未覆盖」——这是正确行为，不是 bug。
> 提权操作见 [`ADMIN_RUN.zh-CN.md`](ADMIN_RUN.zh-CN.md)。

---

## 关键设计：沙箱跑不起来时怎么办

有些项目**无法在沙箱中试跑**——需要真实凭据、管理员特权、硬件、GUI，或本机根本没有可用的隔离手段。

这种情况下，本项目**明令禁止**擅自改到本机真实环境运行，而是要求：

1. **停止**试跑的念头，不上报不行动
2. 在报告中**单列醒目段落**，写明：
   - 为何无法沙箱试跑（对应具体判定条件）
   - 未验证环节的**风险敞口**（哪些恶意行为可能漏检）
   - 可选方案与代价：
     - A 放弃动态验证，仅凭静态 + 供应链结论决策
     - B 由用户决定是否在本地真实环境试跑（需明确同意，并说明后果与回滚方式）
     - C 另寻隔离手段（虚拟机 / 独立机器）
3. **把决策权交给用户**，等待明确指示

> 原则：**AI 可以建议，不可以替用户承担风险。**

---

## 作为 AI Agent 技能使用

`SKILL.zh-CN.md` 是一份可直接加载的技能定义（含 YAML frontmatter、触发条件、流程、输出模板）。
把整个目录放进 Agent 的技能目录即可生效，例如：

```
~/.config/agent-skills/install-security-audit/
```

触发后 Agent 会在任何安装动作前，自动完整走完 10 个环节并出具报告。

---

## 平台说明

**方法论与平台无关**；仓库里的脚本目前实现的是 Windows 相关的层（注册表自启键、Windows 服务、计划任务）。

macOS / Linux 上同样适用，替换成对应物即可：

| 环节 | Windows | macOS / Linux |
|---|---|---|
| 8 — 持久化 | 注册表 `Run` 键、启动文件夹、服务、计划任务 | `launchd`/LaunchAgents、systemd units、`crontab`、`~/.bashrc` |
| 7 — 签名 | `certutil -verify`、Authenticode | `codesign -dv --verbose=4`、`gpg --verify` |
| 6 — 沙箱 | Windows Sandbox、隔离目录 + 快照 diff | `firejail`、容器、`strace`/`dtruss` |

**Shell 提示**：部分 Windows 环境提供的 bash 不带 coreutils。`ls`、`head`、`mkdir`、`wc`、`find`
报 `command not found` 时，把 Git for Windows 的 utilities 目录前置到 `PATH`；`find` 务必用绝对路径调用，
否则会命中 Windows 的 `FIND.EXE`，语义不同，必然报错。

**PowerShell 提示**：受限环境里 `Add-Type` 可能被拦截（运行时编译加载 .NET 代码），改用 `Expand-Archive`
等内建 cmdlet；退出码为 0 但 stdout 为空时，用 `Out-File` 落盘后再读回。

欢迎把脚本扩展到其他平台。

---

## 免责声明

本工具提供**审计辅助**，不构成安全保证。

- 静态扫描有误报与漏报，**不能替代**动态验证与人工判断
- 未覆盖的环节（如无管理员权限时的计划任务）已明确标注，请勿视作"已检查"
- 最终安装决策与后果由使用者承担

---

## 许可

[Apache License 2.0](LICENSE)

---

## 版本

当前版本 **v2.4.0**。变更记录见 [Releases](https://github.com/CamxLs/install-security-audit/releases)。
