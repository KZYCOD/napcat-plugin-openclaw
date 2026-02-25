# NapCat Plugin: OpenClaw AI Channel

通过 OpenClaw Gateway 的 WebSocket RPC 协议将 QQ 变为 AI 助手通道。

## 功能特性

- 🤖 **AI 集成**: 通过 OpenClaw Gateway 连接 AI 助手
- 💬 **私聊支持**: 支持 QQ 私聊消息透传
- 👥 **群聊支持**: 支持群聊@触发
- 📸 **图片发送**: 支持接收和发送图片（Markdown 格式 `![alt](url)` 或 `MEDIA: url`）
- 📎 **文件发送**: 支持接收和发送文件（`FILE: url` 格式）
- ⚡ **命令透传**: 所有 OpenClaw 命令可直接使用
- 🎯 **防抖处理**: 消息合并优化

## 安装

### 前置要求

- NapCat QQ 机器人 (v4.14.0+)
- OpenClaw Gateway 运行中
- Node.js 环境

### 安装步骤

1. 克隆或下载本仓库到 NapCat 插件目录：
```bash
git clone https://github.com/YOUR_USERNAME/napcat-plugin-openclaw.git
```

2. 安装依赖：
```bash
cd napcat-plugin-openclaw
npm install
```

3. 在 NapCat 中启用插件

## 配置

在 NapCat 插件配置中设置以下参数：

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| `token` | OpenClaw Gateway 认证令牌 | `""` |
| `gatewayUrl` | Gateway WebSocket 地址 | `ws://127.0.0.1:18789` |
| `cliPath` | OpenClaw CLI 路径（备用） | `/root/.nvm/versions/node/v22.22.0/bin/openclaw` |
| `privateChat` | 启用私聊 | `true` |
| `groupAtOnly` | 群聊仅@触发 | `true` |
| `userWhitelist` | 用户白名单（逗号分隔） | `""` |
| `groupWhitelist` | 群白名单（逗号分隔） | `""` |
| `debounceMs` | 防抖间隔 (ms) | `2000` |
| `groupSessionMode` | 群会话模式 (`user`/`shared`) | `user` |

## 使用方法

### 基本命令

- `/new` - 新建会话
- `/clear` - 清空会话
- `/stop` - 停止当前运行
- `/help` - 显示帮助
- `/whoami` - 显示当前用户信息

### 发送图片

AI 回复中使用以下格式可发送图片到 QQ：

```markdown
![描述](https://example.com/image.png)
```

或

```
MEDIA: https://example.com/image.png
```

### 发送文件

AI 回复中使用以下格式可发送文件到 QQ：

```
FILE: https://example.com/document.pdf
```

支持的文件类型：pdf, doc, docx, xls, xlsx, ppt, pptx, txt, zip, rar, 7z, mp3, mp4, avi, mkv 等

### 接收文件

用户发送的文件会自动保存到：
```
C:\Users\20576\.openclaw\workspace\received_files\
```

## 技术细节

### 会话管理

- 私聊会话：`qq-{userId}`
- 群聊会话（user 模式）：`qq-g{groupId}-{userId}`
- 群聊会话（shared 模式）：`qq-g{groupId}`

### 消息处理流程

1. 接收 QQ 消息（文本、图片、文件）
2. 保存媒体文件到 OpenClaw 工作区
3. 通过 `chat.send` 发送到 OpenClaw Gateway
4. 监听 `chat` 事件获取 AI 回复
5. 解析回复中的图片和文件链接
6. 发送回 QQ

### 防重复推送

使用 `sentRunIds` Set 跟踪已发送的 runId，避免 `setupAgentPushListener` 重复处理自己发送的消息。

## 开发

### 目录结构

```
napcat-plugin-openclaw/
├── index.mjs              # 主插件文件
├── package.json           # 项目配置
├── package-lock.json      # 依赖锁定
└── README.md              # 说明文档
```

### 调试

插件日志会输出到 NapCat 日志系统，搜索 `[OpenClaw]` 标签查看相关日志。

## 许可证

MIT License

## 致谢

- [NapCat](https://github.com/NapCatQQ/NapCat.QQ) - QQ 机器人框架
- [OpenClaw](https://github.com/openclaw-ai/openclaw) - AI 助手框架
