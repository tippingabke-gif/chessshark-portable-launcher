# 鲨鱼象棋 ChessShark 破解器

Windows x64 上的 ChessShark 便携启动与运行时修复助手，支持已适配的 V2.4.8、V2.5.3 主程序。助手在选定进程中完成启动状态处理，并在首次棋盘扫描前设置识别参数 `[100, 2]`，解决已定位的扫描除零和越界写入问题。

本仓库包含启动工具的完整源码与构建配置。单独使用助手时，需要完整 ChessShark 软件目录、引擎和资源；也可下载下方的 V2.5.3 整合包。该项目是独立工具，MIT 许可只覆盖本项目自行编写的代码和文档；原软件、商标和第三方依赖各自保留原有权利与许可。

## 下载

预编译版本见 [GitHub Releases](https://github.com/tippingabke-gif/chessshark-portable-launcher/releases)。

- **解压即用版**：`ChessShark-V2.5.3-Ready-to-Use-Windows-x64.zip`，包含 V2.5.3 主程序、启动助手、资源、官方 Pikafish 通用引擎与 NNUE，路径已配置为相对路径。
- **已有原软件**：`ChessShark-Portable-Launcher-v1.3.0-Windows-x64.zip`，仅提供助手及对应源码、许可证材料。

解压完整文件夹后，双击 `ChessShark_便携启动修复.exe`。校验值见同一发布页的 `SHA256SUMS.txt`。原软件与第三方组件不适用本项目 MIT 许可；整合包详情及验证范围见发布说明。

## 功能与适用范围

- 同目录发现、文件选择、拖入目标 EXE，以及记住上次选择。
- 按文件指纹或兼容的代码布局选择 V2.4.8 / V2.5.3 配置；兼容资源文字、图标、时间戳等变化，未知代码和关键布局会停止。
- 启动前备份已有的四份软件配置；完整启动记录匹配时复用已有正常窗口。
- 在目标进程内处理启动分支、主指针和初始化消息，并补齐识别参数。目标 EXE 文件不作永久补丁修改。
- 提供本机诊断记录和经过字段筛选的公开状态报告。

环境为 Windows 10/11 x64。目标程序本身为 x86；助手和 Python 构建环境使用 x64。同目录备用 EXE 使用不同外壳，目前不在适配范围。不要通过关闭版本检查来运行未知构建。

## 构建

使用 Python 3.10 x64，在仓库根目录打开 PowerShell：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
.\build.ps1 -Python .\.venv\Scripts\python.exe
```

如果本机 PowerShell 策略限制运行脚本，可以直接执行等价的 Python 命令：

```powershell
.\.venv\Scripts\python.exe build_bundle.py
.\.venv\Scripts\python.exe -m unittest test_portable test_presentation
.\.venv\Scripts\python.exe -m PyInstaller --noconfirm --distpath dist --workpath build portable_launcher.spec
.\dist\ChessShark_便携启动修复.exe --diagnose --no-dialog
```

结果为 `dist/ChessShark_便携启动修复.exe`，最终用户使用这个文件时无需安装 Python。构建、单元检查及 `--diagnose` 不启动 ChessShark，也不读写其进程内存。

如需直接从源码运行，先安装依赖并执行 `python build_bundle.py`，再运行：

```powershell
python portable_launcher.py --select
```

## 使用

1. 将构建出的助手放到完整 ChessShark 软件目录，双击助手；也可将 `ChessShark.exe` 拖到助手上。
2. 原软件需要管理员权限时，Windows 会显示 UAC 提示。
3. 等待助手报告“已就绪”，再选择引擎或开始连线。
4. 如果已有窗口缺少完整启动记录，助手会保留该窗口并提示。先自行保存棋局和方案，再决定是否关闭它。

常用命令：

```powershell
# 重新选择目标
.\ChessShark_便携启动修复.exe --select

# 只检查目标文件；先把示例路径换成自己的软件目录
.\ChessShark_便携启动修复.exe --check --target 'E:\ChessShark\ChessShark.exe'

# 只检查内嵌依赖和工作入口
.\ChessShark_便携启动修复.exe --diagnose --no-dialog

# 导出可分享的简要状态
.\ChessShark_便携启动修复.exe --check --target 'E:\ChessShark\ChessShark.exe' --export-report .\status.json
```

配置备份和完整日志默认写入助手旁的 `ChessShark助手数据`；不可写时使用当前用户的本地应用数据目录。完整日志含软件路径和运行信息，提交 Issue 时使用 `--export-report` 的简要报告。`--out` 属于完整本机诊断，不作为公开报告。

## 源码结构

| 文件或目录 | 用途 |
| --- | --- |
| `portable_launcher.py` | 用户入口、目标选择、启动顺序、实例复用 |
| `portable_support.py` | 文件身份、权限、路径、互斥锁和配置保护 |
| `version_profiles.py` | 两个版本的独立地址映射 |
| `pe_compatibility.py` | PE 代码与布局兼容检查 |
| `release_presentation.py` | 固定提示与公开字段白名单 |
| `scripts/` | 12 份运行辅助脚本及其依赖 |
| `build_bundle.py` | 将上述脚本和 3 份共享模块组装为 15 份内嵌脚本 |
| `portable_launcher.spec` | PyInstaller 单文件打包配置 |
| `test_portable.py`、`test_presentation.py` | 23 项无目标进程的逻辑与展示层检查 |

`scripts/` 中部分模块保留历史诊断入口，作为启动链依赖公开；它们的独立命令并非全部适用于 V2.5.3。日常使用从 `portable_launcher.py` 或最终 EXE 进入，避免直接运行底层诊断脚本。

`portable_support.py` 中的 `LEGACY_PROFILE` 是已观察到的 QQChess 配置副作用保护位置：文件不存在时跳过，仅在变化限于既定 `Version` / `VersionB` 字段时还原。它不要求安装 QQChess，也不影响本项目源码路径的可搬迁性。

## 已知验证范围

既有 V2.5.3 最终助手曾完成六步冷启动，使用者确认引擎和连线正常。冷启动验证使用仅修改 manifest 权限声明的普通权限副本；原版文件检查通过，原版 UAC 冷启动及另一台电脑尚未实测。V2.4.8 沿用既有确认。

本次公开源码整理沿用这些功能结果，检查范围为源码一致性、独立构建和运行时自检。没有把本机界面可用表述为服务器账号认证或全部功能已经通过验证。版本更新后应重新适配代码布局和地址映射。

## 许可与发布

自行编写的代码和文档采用 [MIT](LICENSE)。第三方许可详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)，其中 Keystone 原生引擎采用 GPLv2 及 FOSS 客户端例外，Python 绑定另有 BSD 许可。

GitHub 发布步骤见 [docs/PUBLISHING.md](docs/PUBLISHING.md)。源码仓库不包含原软件、引擎资源、用户方案、研究日志或代理配置。
