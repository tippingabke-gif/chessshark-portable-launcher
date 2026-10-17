# 第三方组件

本仓库自己的代码与文档采用 MIT。本项目的 MIT 许可不会替换第三方许可；`licenses/` 保存原有许可与署名。预编译发布包包含助手源码及第三方对应版本的源码归档，来源与 SHA-256 见 `docs/THIRD_PARTY_SOURCES.json`。

| 组件 | 使用版本 | 许可与来源 |
| --- | --- | --- |
| Python | 3.10.11 x64 | [PSF 与附属许可](licenses/Python-3.10.11-LICENSE.txt) |
| PyInstaller | 6.22.2 | [GPLv2-or-later，含引导程序/打包分发特别例外](https://github.com/pyinstaller/pyinstaller) |
| pywin32 | 312 | [PSF](https://github.com/mhammond/pywin32) |
| psutil | 7.2.2 | [BSD-3-Clause](https://github.com/giampaolo/psutil) |
| pefile | 2024.8.26 | [MIT](https://github.com/erocarrera/pefile) |
| keystone-engine 原生库 | 0.9.2 | [GPLv2 与 FOSS 客户端例外](https://github.com/keystone-engine/keystone/tree/0.9.2) |
| Keystone Python 绑定 | 0.9.2 | BSD-3-Clause，见 `licenses/keystone-python-LICENSE.txt` |
| setuptools / pkg_resources | 65.5.0 | MIT 及内部第三方组件各自许可；源码归档保留其原始声明 |

Python 的许可文件同时包含其随包组件的说明，包括 OpenSSL、libffi、bzip2 和 Microsoft 运行库。该产品包含 OpenSSL Project 为 OpenSSL Toolkit 开发的软件。Microsoft 运行库依照其自身分发条件，仅用于 Windows；本项目的 MIT 许可不覆盖这些运行库。

`licenses/` 还保留打包环境中 packaging、altgraph、pywin32-ctypes 等组件的原始许可。是否作为运行依赖，以 EXE 的实际归档为准，保存这些声明不表示它们的全部代码均已嵌入。

Keystone 的 [EXCEPTIONS-CLIENT](licenses/keystone-EXCEPTIONS-CLIENT.txt) 将 MIT 列入可适用的 FOSS 许可。例外仍附带条件，包括对 Keystone 本身遵守 GPL，以及分发独立部分的可执行文件时同时提供对应源码等；它不是将 Keystone 改成 MIT。GPL 正文见 [COPYING](licenses/keystone-COPYING.txt)。

预编译 ZIP 在同一包中提供 `source/launcher-source.zip`、`source/third-party/` 和 `licenses/`。Keystone 0.9.2 源码归档包含原生引擎、Python 绑定及 `CMakeLists.txt`、`nmake-lib.bat`、`make-lib.sh` 等构建材料；本项目未修改其代码。其他源归档包括 Python、pywin32、psutil、pefile、setuptools 和 PyInstaller。重建助手的入口为本仓库的 `build.ps1`。上游预编译依赖的编译器、时间戳等可能影响重建字节，不承诺逐字节可复现。

公开源码 ZIP 本身不附带 EXE。GitHub Actions 仅构建和自检，不自动创建 Release 或上传二进制附件。再次分发 EXE 时保留同包的源码、说明及许可证。

ChessShark 主程序、附带资源和棋类引擎属于其各自权利人，未包含在本仓库中。本项目不代表或隶属于原软件作者。
