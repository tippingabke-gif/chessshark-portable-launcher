# 发布到 GitHub

建议仓库名称：`chessshark-portable-launcher`。

建议简介：`Windows x64 portable launcher and runtime fixes for supported ChessShark builds.`

仓库代码和文档采用 MIT，根目录已经有 `LICENSE`。首次创建空仓库时，不再自动生成 README、.gitignore 或许可证，以免产生重复的初始内容。

## 网页上传

1. 登录你准备使用的 GitHub 账号，创建 Public 仓库。
2. 打开新仓库的上传入口，上传本源码目录里的文件和子目录。不要只上传外层 ZIP；GitHub 需要看到根目录的 `README.md`、`LICENSE` 和源码。
3. 核对 `.github/`、`.gitignore`、`.gitattributes` 也已加入；部分文件选择器会隐藏点开头的名称。
4. 提交后查看 README 展示和 Actions 的 Windows 构建结果。

仅上传 `ChessShark-Portable-Launcher` 目录里的公开源码。本机的总结、交接档案、证据包、配置备份及其他工作目录不属于公开仓库。

## Git 推送

如果使用 Git，在源码目录运行以下命令。先把尖括号占位符替换为自己的 GitHub 信息，提交邮箱可从 GitHub 的 Email 设置中复制 noreply 地址。

```powershell
git init -b main
git config --local user.name '<GitHub显示名>'
git config --local user.email '<GitHub提供的noreply邮箱>'
git add .
git diff --cached --stat
git commit -m 'Initial open source release'
git remote add origin 'https://github.com/<账号>/chessshark-portable-launcher.git'
git push -u origin main
```

这些身份配置只作用于当前仓库。本源码包没有附带本机 Git 历史、作者邮箱或访问令牌；发布仍会公开所用 GitHub 账号及提交身份，源码整理并不保证匿名。

## 后续发布

首次公开发布使用标签 `v1.3.0`。EXE 内部版本为 1.3.0，运行修复逻辑与既有功能确认版一致。

提交源码后，GitHub 自动生成的源码归档即可供他人下载。预编译下载包同时包含对应助手源码、第三方源码和依赖许可；其内容见 `THIRD_PARTY_NOTICES.md` 与 `THIRD_PARTY_SOURCES.json`。不要将本机接续资料、日志、代理配置或用户方案作为 Release 附件。
