import { randomUUID, generateKeyPairSync, createPrivateKey, sign, createHash, createPublicKey } from 'crypto';
import { execFile } from 'child_process';
import { promisify } from 'util';
import dns from 'dns/promises';
import fs from 'fs';
import http from 'http';
import https from 'https';
import net from 'net';
import path from 'path';
import WebSocket from 'ws';
import { fileURLToPath } from 'url';

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
function ensureDir(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}
function base64UrlEncode(buf) {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function derivePublicKeyRaw(publicKeyPem) {
  const key = createPublicKey(publicKeyPem);
  const spki = key.export({ type: "spki", format: "der" });
  if (spki.length === ED25519_SPKI_PREFIX.length + 32 && spki.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)) {
    return spki.subarray(ED25519_SPKI_PREFIX.length);
  }
  return spki;
}
function fingerprintPublicKey(publicKeyPem) {
  return createHash("sha256").update(derivePublicKeyRaw(publicKeyPem)).digest("hex");
}
function publicKeyRawBase64UrlFromPem(publicKeyPem) {
  return base64UrlEncode(derivePublicKeyRaw(publicKeyPem));
}
function buildDeviceAuthPayload(params) {
  const version = params.nonce ? "v2" : "v1";
  const scopes = params.scopes.join(",");
  const token = params.token ?? "";
  const base = [
    version,
    params.deviceId,
    params.clientId,
    params.clientMode,
    params.role,
    scopes,
    String(params.signedAtMs),
    token
  ];
  if (version === "v2") {
    base.push(params.nonce ?? "");
  }
  return base.join("|");
}
function signDevicePayload(privateKeyPem, payload) {
  const key = createPrivateKey(privateKeyPem);
  const signature = sign(null, Buffer.from(payload, "utf8"), key);
  return base64UrlEncode(signature);
}
function resolveDeviceIdentityPath() {
  const envPath = process.env.OPENCLAW_DEVICE_IDENTITY_PATH?.trim();
  if (envPath) return envPath;
  const moduleDir = path.dirname(fileURLToPath(import.meta.url));
  return path.join(moduleDir, ".openclaw-device.json");
}
function loadOrCreateDeviceIdentity(filePath) {
  try {
    if (fs.existsSync(filePath)) {
      const raw = fs.readFileSync(filePath, "utf8");
      const parsed = JSON.parse(raw);
      if (parsed?.version === 1 && typeof parsed.deviceId === "string" && typeof parsed.publicKeyPem === "string" && typeof parsed.privateKeyPem === "string") {
        const derivedId = fingerprintPublicKey(parsed.publicKeyPem);
        if (derivedId !== parsed.deviceId) {
          const updated = { ...parsed, deviceId: derivedId };
          fs.writeFileSync(filePath, `${JSON.stringify(updated, null, 2)}
`, { mode: 384 });
          try {
            fs.chmodSync(filePath, 384);
          } catch {
          }
          return {
            deviceId: derivedId,
            publicKeyPem: parsed.publicKeyPem,
            privateKeyPem: parsed.privateKeyPem
          };
        }
        return {
          deviceId: parsed.deviceId,
          publicKeyPem: parsed.publicKeyPem,
          privateKeyPem: parsed.privateKeyPem
        };
      }
    }
  } catch {
  }
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const identity = {
    deviceId: fingerprintPublicKey(publicKeyPem),
    publicKeyPem,
    privateKeyPem
  };
  ensureDir(filePath);
  const stored = {
    version: 1,
    deviceId: identity.deviceId,
    publicKeyPem: identity.publicKeyPem,
    privateKeyPem: identity.privateKeyPem,
    createdAtMs: Date.now()
  };
  fs.writeFileSync(filePath, `${JSON.stringify(stored, null, 2)}
`, { mode: 384 });
  try {
    fs.chmodSync(filePath, 384);
  } catch {
  }
  return identity;
}
class GatewayClient {
  url;
  token;
  deviceIdentityPath;
  deviceIdentity = null;
  ws = null;
  pending = /* @__PURE__ */ new Map();
  eventHandlers = /* @__PURE__ */ new Map();
  chatWaiters = /* @__PURE__ */ new Map();
  _connected = false;
  connectPromise = null;
  connectNonce = null;
  logger;
  heartbeatTimer = null;
  reconnectTimer = null;
  lastPong = 0;
  _destroyed = false;
  constructor(url, token, logger) {
    this.url = url;
    this.token = token;
    this.logger = logger;
    this.deviceIdentityPath = resolveDeviceIdentityPath();
    try {
      this.deviceIdentity = loadOrCreateDeviceIdentity(this.deviceIdentityPath);
      this.logger?.info(
        `[OpenClaw] 设备身份已就绪: ${this.deviceIdentity.deviceId.slice(0, 8)}... (${this.deviceIdentityPath})`
      );
    } catch (e) {
      this.deviceIdentity = null;
      this.logger?.warn(`[OpenClaw] 设备身份初始化失败，将退化为无 device 握手: ${e?.message || e}`);
    }
  }
  get connected() {
    return this._connected;
  }
  async connect() {
    if (this._connected && this.ws?.readyState === WebSocket.OPEN) return;
    if (this.connectPromise) return this.connectPromise;
    this.connectPromise = new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        if (this.ws && this.ws.readyState !== WebSocket.CLOSED) {
          try {
            this.ws.close(4001, "connect timeout");
          } catch {
          }
        }
        reject(new Error("connect timeout"));
        this.connectPromise = null;
      }, 15e3);
      try {
        this.ws = new WebSocket(this.url);
      } catch (e) {
        clearTimeout(timeout);
        this.connectPromise = null;
        reject(e);
        return;
      }
      this.ws.on("open", () => {
        this.logger?.info("[OpenClaw] WS 已连接，等待 challenge...");
      });
      this.ws.on("message", (data) => {
        try {
          const frame = JSON.parse(data.toString());
          this.handleFrame(frame, resolve, reject, timeout);
        } catch (e) {
          this.logger?.error(`[OpenClaw] 解析帧失败: ${e.message}`);
        }
      });
      this.ws.on("close", (code, reason) => {
        this.logger?.info(`[OpenClaw] WS 关闭: ${code} ${reason}`);
        this._connected = false;
        this.connectPromise = null;
        this.stopHeartbeat();
        for (const [, p] of this.pending) {
          p.reject(new Error(`ws closed: ${code}`));
        }
        this.pending.clear();
        this.scheduleReconnect();
      });
      this.ws.on("error", (err) => {
        this.logger?.error(`[OpenClaw] WS 错误: ${err.message}`);
        clearTimeout(timeout);
        this._connected = false;
        this.connectPromise = null;
        this.stopHeartbeat();
        reject(err);
        this.scheduleReconnect();
      });
    });
    return this.connectPromise;
  }
  handleFrame(frame, connectResolve, connectReject, connectTimeout) {
    this.lastPong = Date.now();
    if (frame.type === "event" && frame.event === "connect.challenge") {
      this.connectNonce = frame.payload?.nonce;
      this.logger?.info(`[OpenClaw] 收到 challenge, nonce=${this.connectNonce?.slice(0, 8)}...`);
      this.sendConnect(connectResolve, connectReject, connectTimeout);
      return;
    }
    if (frame.type === "res" && frame.id) {
      const pending = this.pending.get(frame.id);
      if (pending) {
        this.pending.delete(frame.id);
        if (frame.ok !== false) {
          pending.resolve(frame.payload);
        } else {
          pending.reject(
            new Error(frame.error?.message || `request failed: ${JSON.stringify(frame.error)}`)
          );
        }
      }
      return;
    }
    if (frame.type === "event" && frame.event) {
      if (frame.event === "tick") return;
      if (frame.event === "chat" && frame.payload?.runId) {
        const waiter = this.chatWaiters.get(frame.payload.runId);
        if (waiter) {
          waiter.handler(frame.payload);
          return;
        }
      }
      const handler = this.eventHandlers.get(frame.event);
      if (handler) handler(frame.payload);
    }
  }
  sendConnect(resolve, reject, timeout) {
    const id = randomUUID();
    const role = "operator";
    const scopes = ["operator.admin", "operator.write"];
    const signedAtMs = Date.now();
    const nonce = this.connectNonce ?? void 0;
    const device = this.deviceIdentity ? (() => {
      const payload = buildDeviceAuthPayload({
        deviceId: this.deviceIdentity.deviceId,
        clientId: "gateway-client",
        clientMode: "backend",
        role,
        scopes,
        signedAtMs,
        token: this.token || null,
        nonce
      });
      return {
        id: this.deviceIdentity.deviceId,
        publicKey: publicKeyRawBase64UrlFromPem(this.deviceIdentity.publicKeyPem),
        signature: signDevicePayload(this.deviceIdentity.privateKeyPem, payload),
        signedAt: signedAtMs,
        nonce
      };
    })() : void 0;
    const params = {
      minProtocol: 1,
      maxProtocol: 3,
      client: {
        id: "gateway-client",
        displayName: "QQ Channel",
        version: "1.3.0",
        platform: "linux",
        mode: "backend"
      },
      caps: [],
      auth: { token: this.token },
      role,
      // chat.send 需要 operator.write，仅申请 admin 会在网关侧被拒绝
      scopes,
      device
    };
    const frame = { type: "req", id, method: "connect", params };
    this.pending.set(id, {
      resolve: () => {
        clearTimeout(timeout);
        this._connected = true;
        this.connectPromise = null;
        this.logger?.info("[OpenClaw] Gateway 认证成功");
        this.startHeartbeat();
        resolve();
      },
      reject: (err) => {
        clearTimeout(timeout);
        this._connected = false;
        this.connectPromise = null;
        this.logger?.error(`[OpenClaw] Gateway 认证失败: ${err.message}`);
        reject(err);
      }
    });
    this.ws.send(JSON.stringify(frame));
    this.logger?.info("[OpenClaw] 已发送 connect 请求");
  }
  startHeartbeat() {
    this.stopHeartbeat();
    this.lastPong = Date.now();
    this.heartbeatTimer = setInterval(() => {
      if (!this._connected || this.ws?.readyState !== WebSocket.OPEN) {
        this.stopHeartbeat();
        return;
      }
      if (Date.now() - this.lastPong > 3e4) {
        this.logger?.warn("[OpenClaw] 心跳超时，关闭连接");
        this.ws?.close(4e3, "heartbeat timeout");
        return;
      }
      try {
        this.ws.ping();
      } catch {
      }
    }, 15e3);
    this.ws?.on("pong", () => {
      this.lastPong = Date.now();
    });
  }
  stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }
  scheduleReconnect() {
    if (this._destroyed) return;
    if (this.reconnectTimer) return;
    this.logger?.info("[OpenClaw] 5 秒后自动重连...");
    this.reconnectTimer = setTimeout(async () => {
      this.reconnectTimer = null;
      try {
        await this.connect();
        this.logger?.info("[OpenClaw] 自动重连成功");
      } catch (e) {
        this.logger?.warn(`[OpenClaw] 自动重连失败: ${e.message}`);
        this.scheduleReconnect();
      }
    }, 5e3);
  }
  async request(method, params) {
    if (!this._connected || this.ws?.readyState !== WebSocket.OPEN) {
      await this.connect();
    }
    const id = randomUUID();
    const frame = { type: "req", id, method, params };
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`request timeout: ${method}`));
      }, 18e4);
      this.pending.set(id, {
        resolve: (payload) => {
          clearTimeout(timeout);
          resolve(payload);
        },
        reject: (err) => {
          clearTimeout(timeout);
          reject(err);
        }
      });
      this.ws.send(JSON.stringify(frame));
    });
  }
  disconnect() {
    this._destroyed = true;
    this.stopHeartbeat();
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      try {
        this.ws.close(1e3, "plugin cleanup");
      } catch {
      }
      this.ws = null;
    }
    this._connected = false;
    this.connectPromise = null;
  }
}

const DEFAULT_CONFIG = {
  openclaw: {
    token: "",
    gatewayUrl: "ws://127.0.0.1:18789",
    cliPath: "/root/.nvm/versions/node/v22.22.0/bin/openclaw"
  },
  behavior: {
    privateChat: true,
    groupAtOnly: true,
    userWhitelist: [],
    groupWhitelist: [],
    debounceMs: 2e3,
    groupSessionMode: "user"
  }
};
function buildConfigSchema() {
  return [
    {
      key: "token",
      label: "OpenClaw Token",
      type: "string",
      default: "",
      placeholder: "填入 OpenClaw Gateway Token",
      description: "用于连接 OpenClaw Gateway 的认证令牌"
    },
    {
      key: "gatewayUrl",
      label: "Gateway WebSocket 地址",
      type: "string",
      default: "ws://127.0.0.1:18789",
      placeholder: "ws://host:port",
      description: "OpenClaw Gateway 的 WebSocket 连接地址"
    },
    {
      key: "cliPath",
      label: "CLI 路径（备用）",
      type: "string",
      default: "/root/.nvm/versions/node/v22.22.0/bin/openclaw",
      description: "WebSocket 不可用时降级使用的 openclaw CLI 路径"
    },
    {
      key: "privateChat",
      label: "启用私聊",
      type: "boolean",
      default: true,
      description: "是否响应私聊消息"
    },
    {
      key: "groupAtOnly",
      label: "群聊仅@触发",
      type: "boolean",
      default: true,
      description: "群聊中是否仅在被@时响应"
    },
    {
      key: "userWhitelist",
      label: "用户白名单",
      type: "string",
      default: "",
      placeholder: "多个 QQ 号用英文逗号分隔，留空不限制",
      description: "允许使用的 QQ 号列表（逗号分隔），留空表示所有人"
    },
    {
      key: "groupWhitelist",
      label: "群白名单",
      type: "string",
      default: "",
      placeholder: "多个群号用英文逗号分隔，留空不限制",
      description: "允许使用的群号列表（逗号分隔），留空表示所有群"
    },
    {
      key: "debounceMs",
      label: "防抖间隔 (ms)",
      type: "number",
      default: 2e3,
      description: "同一用户连续消息的合并等待时间"
    },
    {
      key: "groupSessionMode",
      label: "群会话模式",
      type: "select",
      default: "user",
      options: [
        { label: "每人独立会话", value: "user" },
        { label: "群共享会话", value: "shared" }
      ],
      description: "群聊中是否每个成员独立会话"
    }
  ];
}

/**
 * NapCat Plugin: OpenClaw AI Channel
 *
 * 通过 OpenClaw Gateway 的 WebSocket RPC 协议（chat.send）将 QQ 变为 AI 助手通道。
 * 所有斜杠命令由 Gateway 统一处理，与 TUI/Telegram 体验一致。
 *
 * @author CharTyr
 * @license MIT
 */
const execFileAsync = promisify(execFile);
let logger = null;
let configPath = null;
let botUserId = null;
let gatewayClient = null;
let currentConfig = { ...DEFAULT_CONFIG };
let lastCtx = null;
let pluginDir = "/tmp";
let pushListenerAttached = false;
const sessionMap = /* @__PURE__ */ new Map(); // 会话映射表: sessionKey -> { type, id }
const debounceBuffers = /* @__PURE__ */ new Map();

// 跟踪所有通过 plugin_onmessage 发送的 runId，避免 setupAgentPushListener 重复处理
const sentRunIds = /* @__PURE__ */ new Set();

// OpenClaw 工作区接收文件目录
const OPENCLAW_RECEIVED_FILES_DIR = "C:\\Users\\20576\\.openclaw\\workspace\\received_files";

// 保存媒体文件到 OpenClaw 工作区
async function saveMediaToOpenClawWorkspace(mediaList, ctx) {
  logger?.info(`[OpenClaw] saveMediaToOpenClawWorkspace 被调用, mediaList长度: ${mediaList?.length}`);
  const saved = [];
  try {
    await fs.promises.mkdir(OPENCLAW_RECEIVED_FILES_DIR, { recursive: true });
    for (const m of mediaList) {
      try {
        let buf = null;
        if (m.url) {
          buf = await downloadToBuffer(m.url, 100 * 1024 * 1024); // 100MB max
        } else if (m.file_id && ctx) {
          // 从 NapCat 获取文件 (使用 ctx)
          try {
            const fileInfo = await ctx.actions.call(
              "get_file",
              { file_id: m.file_id },
              ctx.adapterName,
              ctx.pluginManager?.config
            );
            if (fileInfo?.file) {
              try {
                await fs.promises.access(fileInfo.file);
                buf = await fs.promises.readFile(fileInfo.file);
              } catch {
                if (fileInfo.url) buf = await downloadToBuffer(fileInfo.url, 100 * 1024 * 1024);
                else if (fileInfo.base64) buf = Buffer.from(fileInfo.base64, "base64");
              }
            }
          } catch (e) {
            logger?.warn(`[OpenClaw] OpenClaw工作区 get_file 失败: ${e.message}`);
          }
        }
        
        if (!buf) continue;
        
        const ext = (m.url || m.name || "bin").split("?").pop().split(".").pop() || "bin";
        const filename = `${Date.now()}-${Math.random().toString(36).slice(2, 10)}.${ext}`;
        const filePath = path.join(OPENCLAW_RECEIVED_FILES_DIR, filename);
        await fs.promises.writeFile(filePath, buf);
        saved.push({ type: m.type, path: filePath, name: m.name || filename, size: buf.length });
        logger?.info(`[OpenClaw] 保存文件到工作区: ${filePath}`);
      } catch (e) {
        logger?.warn(`[OpenClaw] 保存文件失败: ${e.message}`);
      }
    }
  } catch (e) {
    logger?.warn(`[OpenClaw] 创建接收目录失败: ${e.message}`);
  }
  return saved;
}
function cmdHelp() {
  return [
    "ℹ️ Help",
    "",
    "Session",
    "  /new  |  /clear  |  /stop",
    "",
    "Options",
    "  /think <level>  |  /model <id>  |  /verbose on|off",
    "",
    "Status",
    "  /status  |  /whoami  |  /context",
    "",
    "所有 OpenClaw 命令均可直接使用",
    "更多: /commands"
  ].join("\n");
}
function cmdWhoami(sessionBase, userId, nickname, messageType, groupId) {
  const epoch = sessionEpochs.get(sessionBase) || 0;
  const sessionKey = epoch > 0 ? `${sessionBase}-${epoch}` : sessionBase;
  return [
    `👤 ${nickname}`,
    `QQ: ${userId}`,
    `类型: ${messageType === "private" ? "私聊" : `群聊 (${groupId})`}`,
    `Session: ${sessionKey}`
  ].join("\n");
}
const LOCAL_COMMANDS = {
  "/help": cmdHelp,
  "/whoami": cmdWhoami
};
const sessionEpochs = /* @__PURE__ */ new Map();
function getSessionBase(messageType, userId, groupId) {
  if (messageType === "private") return `qq-${userId}`;
  if (currentConfig.behavior.groupSessionMode === "shared") return `qq-g${groupId}`;
  return `qq-g${groupId}-${userId}`;
}
function getSessionKey(sessionBase) {
  const epoch = sessionEpochs.get(sessionBase) || 0;
  return epoch > 0 ? `${sessionBase}-${epoch}` : sessionBase;
}

// 注册会话到映射表
function registerSession(sessionBase, messageType, userId, groupId) {
  const sessionKey = getSessionKey(sessionBase);
  sessionMap.set(sessionKey, {
    type: messageType, // "private" 或 "group"
    id: groupId || userId, // 群号或QQ号
    userId: userId,
    groupId: groupId,
    timestamp: Date.now()
  });
  
  // 同时注册带 agent 前缀的版本 (兼容 agent:main:qq-xxx 格式)
  const agentSessionKey = `agent:main:${sessionKey}`;
  sessionMap.set(agentSessionKey, {
    type: messageType,
    id: groupId || userId,
    userId: userId,
    groupId: groupId,
    timestamp: Date.now()
  });
  
  logger?.info(`[OpenClaw] 注册会话映射: ${sessionKey} 和 ${agentSessionKey} -> ${messageType}:${groupId || userId}`);
}

// 从映射表查询会话信息
function lookupSession(sessionKey) {
  return sessionMap.get(sessionKey) || null;
}

// 清理过期的会话映射 (超过10分钟)
function cleanupSessionMap() {
  const now = Date.now();
  const maxAge = 10 * 60 * 1000; // 10分钟
  for (const [key, value] of sessionMap) {
    if (now - value.timestamp > maxAge) {
      sessionMap.delete(key);
      logger?.info(`[OpenClaw] 清理过期会话映射: ${key}`);
    }
  }
}

// 定期清理 (每5分钟)
setInterval(cleanupSessionMap, 5 * 60 * 1000);
async function getGateway() {
  if (!gatewayClient) {
    gatewayClient = new GatewayClient(
      currentConfig.openclaw.gatewayUrl,
      currentConfig.openclaw.token,
      logger
    );
  }
  if (!gatewayClient.connected) {
    await gatewayClient.connect();
    if (!pushListenerAttached) {
      setupAgentPushListener(gatewayClient);
      pushListenerAttached = true;
    }
  }
  return gatewayClient;
}
function debounceMessage(sessionBase, text, media, debounceMs) {
  return new Promise((resolve) => {
    let buf = debounceBuffers.get(sessionBase);
    if (buf) {
      if (text) buf.messages.push(text);
      if (media.length > 0) buf.media.push(...media);
      clearTimeout(buf.timer);
      const prevResolve = buf.resolve;
      buf.resolve = resolve;
      prevResolve(null);
    } else {
      buf = {
        messages: text ? [text] : [],
        media: [...media],
        resolve,
        timer: setTimeout(() => void 0, 0)
      };
      debounceBuffers.set(sessionBase, buf);
    }
    buf.timer = setTimeout(() => {
      debounceBuffers.delete(sessionBase);
      buf.resolve({
        text: buf.messages.join("\n"),
        media: buf.media
      });
    }, debounceMs);
  });
}
function extractMessage(segments) {
  const textParts = [];
  const media = [];
  logger?.info(`[OpenClaw] extractMessage 原始segments: ${JSON.stringify(segments).slice(0, 500)}`);
  for (const seg of segments) {
    switch (seg.type) {
      case "text": {
        const t = seg.data?.text?.trim();
        if (t) textParts.push(t);
        break;
      }
      case "image":
        if (seg.data?.url) media.push({ type: "image", url: seg.data.url });
        break;
      case "at":
        if (String(seg.data?.qq) !== String(botUserId)) {
          textParts.push(`@${seg.data?.name || seg.data?.qq}`);
        }
        break;
      case "file":
        // 有 URL 或者有 file_id 都处理
        if (seg.data?.url) {
          media.push({ type: "file", url: seg.data.url, name: seg.data?.name });
        } else if (seg.data?.file_id) {
          // 只有 file_id，没有 URL，需要通过 ctx 获取文件
          media.push({ type: "file", file_id: seg.data.file_id, name: seg.data?.file || seg.data?.name });
        }
        break;
      case "record":
        if (seg.data?.url) media.push({ type: "voice", url: seg.data.url });
        break;
      case "video":
        if (seg.data?.url) media.push({ type: "video", url: seg.data.url });
        break;
    }
  }
  return { extractedText: textParts.join(" "), extractedMedia: media };
}
function extractTextFromContent(content) {
  if (typeof content === "string") return content;
  if (!content) return "";
  if (Array.isArray(content)) {
    return content.map((item) => extractTextFromContent(item)).filter(Boolean).join("\n");
  }
  if (typeof content !== "object") return "";
  if (typeof content.text === "string") return content.text;
  if (typeof content.output_text === "string") return content.output_text;
  if (typeof content.input_text === "string") return content.input_text;
  if (content.content) return extractTextFromContent(content.content);
  return "";
}
function extractTextFromPayload(message) {
  if (typeof message === "string") return message;
  if (!message) return "";
  const contentText = extractTextFromContent(message.content);
  if (contentText.trim()) return contentText;
  if (typeof message.text === "string") return message.text;
  return "";
}
function extractContentText(message) {
  return extractTextFromPayload(message);
}
async function setTypingStatus(ctx, userId, typing) {
  try {
    await ctx.actions.call(
      "set_input_status",
      { user_id: String(userId), event_type: typing ? 1 : 0 },
      ctx.adapterName,
      ctx.pluginManager?.config
    );
  } catch (e) {
    logger?.warn(`[OpenClaw] 设置输入状态失败: ${e.message}`);
  }
}
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
function normalizeMessageTimestampMs(message) {
  if (!message) return null;
  if (typeof message.timestamp === "number" && Number.isFinite(message.timestamp)) {
    return message.timestamp;
  }
  if (typeof message.timestamp === "string") {
    const parsed = Date.parse(message.timestamp);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}
function pickLatestAssistantText(messages, minTimestampMs) {
  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i];
    if (!msg || typeof msg !== "object") continue;
    const role = typeof msg.role === "string" ? msg.role.toLowerCase() : "";
    if (role !== "assistant") continue;
    const text = extractContentText(msg).trim();
    if (!text) continue;
    const ts = normalizeMessageTimestampMs(msg);
    if (ts !== null && ts + 1e3 < minTimestampMs) continue;
    return text;
  }
  return null;
}
async function resolveReplyFromHistory(gw, sessionKey, minTimestampMs, options) {
  const maxAttempts = Math.max(1, options?.maxAttempts ?? 6);
  const intervalMs = Math.max(100, options?.intervalMs ?? 350);
  for (let i = 0; i < maxAttempts; i++) {
    if (options?.shouldStop?.()) return null;
    try {
      const history = await gw.request("chat.history", { sessionKey, limit: 100 });
      const messages = Array.isArray(history?.messages) ? history.messages : [];
      const text = pickLatestAssistantText(messages, minTimestampMs);
      if (text) return text;
    } catch (e) {
      logger?.warn(`[OpenClaw] 回查 chat.history 失败: ${e.message}`);
      return null;
    }
    if (i + 1 < maxAttempts) {
      await sleep(intervalMs);
    }
  }
  return null;
}
function isRecoverableGatewayError(errorMessage) {
  const normalized = errorMessage.trim().toLowerCase();
  if (!normalized) return false;
  return /(terminated|abort|cancel|killed|interrupt|retry|timeout|in[_ -]?flight)/i.test(normalized);
}
async function sendReply(ctx, messageType, groupId, userId, text) {
  const action = messageType === "group" ? "send_group_msg" : "send_private_msg";
  const idKey = messageType === "group" ? "group_id" : "user_id";
  const idVal = String(messageType === "group" ? groupId : userId);
  const maxLen = 3e3;
  if (text.length <= maxLen) {
    await ctx.actions.call(action, { [idKey]: idVal, message: text }, ctx.adapterName, ctx.pluginManager?.config);
  } else {
    const total = Math.ceil(text.length / maxLen);
    for (let i = 0; i < text.length; i += maxLen) {
      const idx = Math.floor(i / maxLen) + 1;
      const prefix = total > 1 ? `[${idx}/${total}]
` : "";
      await ctx.actions.call(
        action,
        { [idKey]: idVal, message: prefix + text.slice(i, i + maxLen) },
        ctx.adapterName,
        ctx.pluginManager?.config
      );
      if (i + maxLen < text.length) await sleep(1e3);
    }
  }
}
async function sendImageMsg(ctx, messageType, groupId, userId, imageUrl) {
  const message = [{ type: "image", data: { url: imageUrl } }];
  if (messageType === "group") {
    await ctx.actions.call(
      "send_group_msg",
      { group_id: String(groupId), message },
      ctx.adapterName,
      ctx.pluginManager?.config
    );
    return;
  }
  await ctx.actions.call(
    "send_private_msg",
    { user_id: String(userId), message },
    ctx.adapterName,
    ctx.pluginManager?.config
  );
}

// 发送文件消息（支持私聊和群聊）
async function sendFileMsg(ctx, messageType, groupId, userId, fileUrl, fileName) {
  const message = [{ type: "file", data: { url: fileUrl, name: fileName || "file" } }];
  if (messageType === "group") {
    await ctx.actions.call(
      "send_group_msg",
      { group_id: String(groupId), message },
      ctx.adapterName,
      ctx.pluginManager?.config
    );
    return;
  }
  await ctx.actions.call(
    "send_private_msg",
    { user_id: String(userId), message },
    ctx.adapterName,
    ctx.pluginManager?.config
  );
}

async function sendGroupMsg(ctx, groupId, text) {
  await ctx.actions.call(
    "send_group_msg",
    { group_id: String(groupId), message: text },
    ctx.adapterName,
    ctx.pluginManager?.config
  );
}
async function sendPrivateMsg(ctx, userId, text) {
  await ctx.actions.call(
    "send_private_msg",
    { user_id: String(userId), message: text },
    ctx.adapterName,
    ctx.pluginManager?.config
  );
}
function isPrivateIp(host) {
  if (!host) return true;
  const normalized = host.trim().toLowerCase();
  if (normalized === "localhost" || normalized === "ip6-localhost") return true;
  const ipVersion = net.isIP(normalized);
  if (ipVersion === 4) {
    if (normalized.startsWith("127.")) return true;
    if (normalized.startsWith("10.")) return true;
    if (normalized.startsWith("192.168.")) return true;
    if (normalized.startsWith("169.254.")) return true;
    const parts = normalized.split(".").map(Number);
    if (parts.length === 4 && parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    return false;
  }
  if (ipVersion === 6) {
    if (normalized === "::1") return true;
    return normalized.startsWith("fc") || normalized.startsWith("fd");
  }
  return false;
}
async function assertSafeRemoteUrl(rawUrl) {
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`unsupported protocol: ${parsed.protocol}`);
  }
  if (!parsed.hostname) {
    throw new Error("invalid hostname");
  }
  if (isPrivateIp(parsed.hostname)) {
    throw new Error("private network address is not allowed");
  }
  const records = await dns.lookup(parsed.hostname, { all: true });
  if (!records.length) {
    throw new Error("hostname resolution failed");
  }
  for (const record of records) {
    if (isPrivateIp(record.address)) {
      throw new Error("resolved private network address is not allowed");
    }
  }
  return parsed;
}
async function downloadToBuffer(url, maxBytes = 5 * 1024 * 1024, redirectCount = 0) {
  if (redirectCount > 5) {
    throw new Error("too many redirects");
  }
  const parsed = await assertSafeRemoteUrl(url);
  return new Promise((resolve, reject) => {
    const mod = parsed.protocol === "https:" ? https : http;
    const req = mod.get(parsed.toString(), { timeout: 1e4 }, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        const nextUrl = new URL(res.headers.location, parsed).toString();
        res.resume();
        void downloadToBuffer(nextUrl, maxBytes, redirectCount + 1).then(resolve).catch(reject);
        return;
      }
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`HTTP ${res.statusCode}`));
        return;
      }
      const chunks = [];
      let total = 0;
      res.on("data", (chunk) => {
        total += chunk.length;
        if (total > maxBytes) {
          res.destroy();
          reject(new Error(`exceeds ${maxBytes} bytes`));
          return;
        }
        chunks.push(chunk);
      });
      res.on("end", () => resolve(Buffer.concat(chunks)));
      res.on("error", reject);
    });
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("timeout"));
    });
    req.on("error", reject);
  });
}
function guessMimeFromUrl(url) {
  const ext = (url || "").split("?")[0].split(".").pop()?.toLowerCase();
  const mimeMap = {
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
    png: "image/png",
    gif: "image/gif",
    webp: "image/webp",
    bmp: "image/bmp"
  };
  return mimeMap[ext || ""] || "image/png";
}
async function saveMediaToCache(mediaList, ctx) {
  const cacheDir = path.join(pluginDir || "/tmp", "cache", "media");
  await fs.promises.mkdir(cacheDir, { recursive: true });
  const saved = [];
  for (const m of mediaList) {
    try {
      let buf = null;
      if (m.url) {
        buf = await downloadToBuffer(m.url, 100 * 1024 * 1024);
      } else if (m.file_id && ctx) {
        try {
          const fileInfo = await ctx.actions.call(
            "get_file",
            { file_id: m.file_id },
            ctx.adapterName,
            ctx.pluginManager?.config
          );
          if (fileInfo?.file) {
            try {
              await fs.promises.access(fileInfo.file);
              buf = await fs.promises.readFile(fileInfo.file);
            } catch {
              if (fileInfo.url) buf = await downloadToBuffer(fileInfo.url, 100 * 1024 * 1024);
              else if (fileInfo.base64) buf = Buffer.from(fileInfo.base64, "base64");
            }
          }
        } catch (e) {
          logger?.warn(`[OpenClaw] get_file 失败: ${e.message}`);
        }
      }
      if (!buf) {
        saved.push({ type: m.type, path: null, url: m.url, name: m.name });
        continue;
      }
      let ext = "bin";
      if (m.type === "image") ext = guessMimeFromUrl(m.url).split("/")[1] || "png";
      else if (m.name) ext = m.name.split(".").pop() || "bin";
      else if (m.type === "voice") ext = "silk";
      else if (m.type === "video") ext = "mp4";
      const filename = `${Date.now()}-${randomUUID().slice(0, 8)}.${ext}`;
      const filePath = path.join(cacheDir, filename);
      await fs.promises.writeFile(filePath, buf);
      saved.push({ type: m.type, path: filePath, name: m.name || filename, size: buf.length });
    } catch (e) {
      logger?.warn(`[OpenClaw] 下载文件失败: ${e.message}`);
      saved.push({ type: m.type, path: null, url: m.url, name: m.name });
    }
  }
  try {
    const cutoff = Date.now() - 36e5;
    const files = await fs.promises.readdir(cacheDir);
    for (const name of files) {
      const fullPath = path.join(cacheDir, name);
      const stat = await fs.promises.stat(fullPath);
      if (stat.mtimeMs < cutoff) await fs.promises.unlink(fullPath);
    }
  } catch {
  }
  return saved;
}
function extractImagesFromReply(text) {
  const images = [];
  const mediaRegex = /^MEDIA:\s*(.+)$/gm;
  let match;
  while ((match = mediaRegex.exec(text)) !== null) {
    const url = match[1].trim();
    if (url.startsWith("http") || url.startsWith("file://") || url.startsWith("data:")) images.push(url);
  }
  const mdRegex = /!\[[^\]]*\]\(([^)]+)\)/g;
  while ((match = mdRegex.exec(text)) !== null) {
    const url = match[1].trim();
    if (url.startsWith("http") || url.startsWith("file://") || url.startsWith("data:")) images.push(url);
  }
  const cleanText = text.replace(/^MEDIA:\s*.+$/gm, "").replace(/!\[[^\]]*\]\([^)]+\)/g, "").trim();
  return { images: Array.from(new Set(images)), cleanText };
}

// 提取文件链接
function extractFilesFromReply(text) {
  const files = [];
  // 匹配 FILE: URL 格式
  const fileRegex = /^FILE:\s*(.+)$/gm;
  let match;
  while ((match = fileRegex.exec(text)) !== null) {
    const url = match[1].trim();
    if (url.startsWith("http") || url.startsWith("file://") || url.startsWith("data:")) {
      // 尝试从URL中提取文件名
      let fileName = null;
      try {
        const urlObj = new URL(url);
        const pathParts = urlObj.pathname.split("/");
        fileName = decodeURIComponent(pathParts[pathParts.length - 1]) || null;
      } catch (e) {
        // URL解析失败，使用默认文件名
      }
      files.push({ url, fileName });
    }
  }
  // 匹配常见文件扩展名的链接
  const extRegex = /(?:^|\s)(https?:\/\/[^\s]+\.(?:pdf|doc|docx|xls|xlsx|ppt|pptx|txt|zip|rar|7z|mp3|mp4|avi|mkv|png|jpg|jpeg|gif|bmp|webp)(?:\?[^\s]*)?)/gi;
  while ((match = extRegex.exec(text)) !== null) {
    const url = match[1].trim();
    // 排除已经是图片的链接（图片链接已经在 images 中处理）
    const imageExts = ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'];
    const isImage = imageExts.some(ext => url.toLowerCase().endsWith(ext));
    if (!isImage) {
      let fileName = null;
      try {
        const urlObj = new URL(url);
        const pathParts = urlObj.pathname.split("/");
        fileName = decodeURIComponent(pathParts[pathParts.length - 1]) || null;
      } catch (e) {}
      files.push({ url, fileName });
    }
  }
  const cleanText = text.replace(/^FILE:\s*.+$/gm, "").trim();
  return { files: Array.from(new Set(files.map(f => JSON.stringify(f)))).map(f => JSON.parse(f)), cleanText };
}

function setupAgentPushListener(gw) {
  gw.eventHandlers.set("chat", (payload) => {
    if (!payload || payload.state !== "final" || !payload.sessionKey) return;
    
    // 🔥 关键修复：跳过所有通过 plugin_onmessage 发送的消息
    if (payload.runId && sentRunIds.has(payload.runId)) {
      logger?.info(`[OpenClaw] 跳过自己发送的消息: runId=${payload.runId.slice(0, 8)}`);
      return;
    }
    
    // 优先使用会话映射表查询 (方案B)
    const sessionInfo = lookupSession(payload.sessionKey);
    
    if (!sessionInfo) {
      // 映射表中没有，尝试从 sessionKey 解析 (兼容旧方式)
      const isQQSession = payload.sessionKey.startsWith("qq-") || payload.sessionKey.includes(":qq-");
      if (!isQQSession) return;
    }
    
    if (payload.runId && gw.chatWaiters.has(payload.runId)) return;
    if (!lastCtx) return;
    const text = extractContentText(payload.message).trim();
    if (!text) return;
    logger?.info(`[OpenClaw] Agent 主动推送: ${payload.sessionKey} -> ${text.slice(0, 50)}`);
    
    // 使用映射表中的信息，或fallback到旧方式解析
    let targetId, isGroup;
    if (sessionInfo) {
      targetId = sessionInfo.id;
      isGroup = sessionInfo.type === 'group';
      logger?.info(`[OpenClaw] 使用映射表发送: ${isGroup ? 'group' : 'private'} ${targetId}`);
    } else {
      // 兼容旧方式
      const privateMatch = payload.sessionKey.match(/(?:agent:main:)?qq-(\d+)(?:-\d+)?$/);
      const groupMatch = payload.sessionKey.includes(":qq-g") ? payload.sessionKey.match(/:qq-g(\d+)/) : payload.sessionKey.match(/^qq-g(\d+)/);
      isGroup = payload.sessionKey.includes("-g") || payload.sessionKey.includes(":qq-g");
      if (privateMatch && !isGroup) {
        targetId = privateMatch[1];
      } else if (groupMatch) {
        targetId = groupMatch[1];
      } else {
        return;
      }
      logger?.info(`[OpenClaw] 使用旧方式解析发送: ${isGroup ? 'group' : 'private'} ${targetId}`);
    }
    
    // 发送消息
    if (!isGroup) {
      // 私聊
      const { images, cleanText } = extractImagesFromReply(text);
      const { files, cleanText: cleanText2 } = extractFilesFromReply(cleanText || text);
      if (cleanText2) void sendPrivateMsg(lastCtx, targetId, cleanText2);
      for (const img of images) void sendImageMsg(lastCtx, "private", null, targetId, img);
      for (const file of files) void sendFileMsg(lastCtx, "private", null, targetId, file.url, file.fileName);
    } else {
      // 群聊
      const { images, cleanText } = extractImagesFromReply(text);
      const { files, cleanText: cleanText2 } = extractFilesFromReply(cleanText || text);
      if (cleanText2) void sendGroupMsg(lastCtx, targetId, cleanText2);
      for (const img of images) void sendImageMsg(lastCtx, "group", targetId, null, img);
      for (const file of files) void sendFileMsg(lastCtx, "group", targetId, null, file.url, file.fileName);
    }
  });
}
let plugin_config_ui = [];
const plugin_init = async (ctx) => {
  logger = ctx.logger;
  lastCtx = ctx;
  configPath = ctx.configPath;
  pluginDir = new URL("data:video/mp2t;base64,LyoqCiAqIE5hcENhdCBQbHVnaW46IE9wZW5DbGF3IEFJIENoYW5uZWwKICoKICog6YCa6L+HIE9wZW5DbGF3IEdhdGV3YXkg55qEIFdlYlNvY2tldCBSUEMg5Y2P6K6u77yIY2hhdC5zZW5k77yJ5bCGIFFRIOWPmOS4uiBBSSDliqnmiYvpgJrpgZPjgIIKICog5omA5pyJ5pac5p2g5ZG95Luk55SxIEdhdGV3YXkg57uf5LiA5aSE55CG77yM5LiOIFRVSS9UZWxlZ3JhbSDkvZPpqozkuIDoh7TjgIIKICoKICogQGF1dGhvciBDaGFyVHlyCiAqIEBsaWNlbnNlIE1JVAogKi8KCmltcG9ydCB7IHJhbmRvbVVVSUQgfSBmcm9tICdjcnlwdG8nOwppbXBvcnQgeyBleGVjRmlsZSB9IGZyb20gJ2NoaWxkX3Byb2Nlc3MnOwppbXBvcnQgeyBwcm9taXNpZnkgfSBmcm9tICd1dGlsJzsKaW1wb3J0IGRucyBmcm9tICdkbnMvcHJvbWlzZXMnOwppbXBvcnQgZnMgZnJvbSAnZnMnOwppbXBvcnQgaHR0cCBmcm9tICdodHRwJzsKaW1wb3J0IGh0dHBzIGZyb20gJ2h0dHBzJzsKaW1wb3J0IG5ldCBmcm9tICduZXQnOwppbXBvcnQgcGF0aCBmcm9tICdwYXRoJzsKaW1wb3J0IHsgR2F0ZXdheUNsaWVudCB9IGZyb20gJy4vZ2F0ZXdheS1jbGllbnQnOwppbXBvcnQgeyBERUZBVUxUX0NPTkZJRywgYnVpbGRDb25maWdTY2hlbWEgfSBmcm9tICcuL2NvbmZpZyc7CmltcG9ydCB0eXBlIHsgUGx1Z2luQ29uZmlnLCBFeHRyYWN0ZWRNZWRpYSwgQ2hhdEV2ZW50UGF5bG9hZCwgQ29udGVudEJsb2NrLCBTYXZlZE1lZGlhLCBEZWJvdW5jZVJlc3VsdCB9IGZyb20gJy4vdHlwZXMnOwoKY29uc3QgZXhlY0ZpbGVBc3luYyA9IHByb21pc2lmeShleGVjRmlsZSk7CgovLyA9PT09PT09PT09IFN0YXRlID09PT09PT09PT0KbGV0IGxvZ2dlcjogYW55ID0gbnVsbDsKbGV0IGNvbmZpZ1BhdGg6IHN0cmluZyB8IG51bGwgPSBudWxsOwpsZXQgYm90VXNlcklkOiBzdHJpbmcgfCBudW1iZXIgfCBudWxsID0gbnVsbDsKbGV0IGdhdGV3YXlDbGllbnQ6IEdhdGV3YXlDbGllbnQgfCBudWxsID0gbnVsbDsKbGV0IGN1cnJlbnRDb25maWc6IFBsdWdpbkNvbmZpZyA9IHsgLi4uREVGQVVMVF9DT05GSUcgfTsKbGV0IGxhc3RDdHg6IGFueSA9IG51bGw7CmxldCBwbHVnaW5EaXIgPSAnL3RtcCc7CmxldCBwdXNoTGlzdGVuZXJBdHRhY2hlZCA9IGZhbHNlOwoKY29uc3QgZGVib3VuY2VCdWZmZXJzID0gbmV3IE1hcDwKICBzdHJpbmcsCiAgewogICAgbWVzc2FnZXM6IHN0cmluZ1tdOwogICAgbWVkaWE6IEV4dHJhY3RlZE1lZGlhW107CiAgICB0aW1lcjogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0VGltZW91dD47CiAgICByZXNvbHZlOiAodmFsdWU6IERlYm91bmNlUmVzdWx0IHwgbnVsbCkgPT4gdm9pZDsKICB9Cj4oKTsKCi8vID09PT09PT09PT0gTG9jYWwgQ29tbWFuZHMgPT09PT09PT09PQoKZnVuY3Rpb24gY21kSGVscCgpOiBzdHJpbmcgewogIHJldHVybiBbCiAgICAn4oS577iPIEhlbHAnLAogICAgJycsCiAgICAnU2Vzc2lvbicsCiAgICAnICAvbmV3ICB8ICAvY2xlYXIgIHwgIC9zdG9wJywKICAgICcnLAogICAgJ09wdGlvbnMnLAogICAgJyAgL3RoaW5rIDxsZXZlbD4gIHwgIC9tb2RlbCA8aWQ+ICB8ICAvdmVyYm9zZSBvbnxvZmYnLAogICAgJycsCiAgICAnU3RhdHVzJywKICAgICcgIC9zdGF0dXMgIHwgIC93aG9hbWkgIHwgIC9jb250ZXh0JywKICAgICcnLAogICAgJ+aJgOaciSBPcGVuQ2xhdyDlkb3ku6TlnYflj6/nm7TmjqXkvb/nlKgnLAogICAgJ+abtOWkmjogL2NvbW1hbmRzJywKICBdLmpvaW4oJ1xuJyk7Cn0KCmZ1bmN0aW9uIGNtZFdob2FtaSgKICBzZXNzaW9uQmFzZTogc3RyaW5nLAogIHVzZXJJZDogbnVtYmVyIHwgc3RyaW5nLAogIG5pY2tuYW1lOiBzdHJpbmcsCiAgbWVzc2FnZVR5cGU6IHN0cmluZywKICBncm91cElkPzogbnVtYmVyIHwgc3RyaW5nCik6IHN0cmluZyB7CiAgY29uc3QgZXBvY2ggPSBzZXNzaW9uRXBvY2hzLmdldChzZXNzaW9uQmFzZSkgfHwgMDsKICBjb25zdCBzZXNzaW9uS2V5ID0gZXBvY2ggPiAwID8gYCR7c2Vzc2lvbkJhc2V9LSR7ZXBvY2h9YCA6IHNlc3Npb25CYXNlOwogIHJldHVybiBbCiAgICBg8J+RpCAke25pY2tuYW1lfWAsCiAgICBgUVE6ICR7dXNlcklkfWAsCiAgICBg57G75Z6LOiAke21lc3NhZ2VUeXBlID09PSAncHJpdmF0ZScgPyAn56eB6IGKJyA6IGDnvqTogYogKCR7Z3JvdXBJZH0pYH1gLAogICAgYFNlc3Npb246ICR7c2Vzc2lvbktleX1gLAogIF0uam9pbignXG4nKTsKfQoKY29uc3QgTE9DQUxfQ09NTUFORFM6IFJlY29yZDxzdHJpbmcsICguLi5hcmdzOiBhbnlbXSkgPT4gc3RyaW5nPiA9IHsKICAnL2hlbHAnOiBjbWRIZWxwLAogICcvd2hvYW1pJzogY21kV2hvYW1pLAp9OwoKLy8gPT09PT09PT09PSBTZXNzaW9uIE1hbmFnZW1lbnQgPT09PT09PT09PQpjb25zdCBzZXNzaW9uRXBvY2hzID0gbmV3IE1hcDxzdHJpbmcsIG51bWJlcj4oKTsKCmZ1bmN0aW9uIGdldFNlc3Npb25CYXNlKG1lc3NhZ2VUeXBlOiBzdHJpbmcsIHVzZXJJZDogbnVtYmVyIHwgc3RyaW5nLCBncm91cElkPzogbnVtYmVyIHwgc3RyaW5nKTogc3RyaW5nIHsKICBpZiAobWVzc2FnZVR5cGUgPT09ICdwcml2YXRlJykgcmV0dXJuIGBxcS0ke3VzZXJJZH1gOwogIGlmIChjdXJyZW50Q29uZmlnLmJlaGF2aW9yLmdyb3VwU2Vzc2lvbk1vZGUgPT09ICdzaGFyZWQnKSByZXR1cm4gYHFxLWcke2dyb3VwSWR9YDsKICByZXR1cm4gYHFxLWcke2dyb3VwSWR9LSR7dXNlcklkfWA7Cn0KCmZ1bmN0aW9uIGdldFNlc3Npb25LZXkoc2Vzc2lvbkJhc2U6IHN0cmluZyk6IHN0cmluZyB7CiAgY29uc3QgZXBvY2ggPSBzZXNzaW9uRXBvY2hzLmdldChzZXNzaW9uQmFzZSkgfHwgMDsKICByZXR1cm4gZXBvY2ggPiAwID8gYCR7c2Vzc2lvbkJhc2V9LSR7ZXBvY2h9YCA6IHNlc3Npb25CYXNlOwp9CgovLyA9PT09PT09PT09IEdhdGV3YXkgPT09PT09PT09PQoKYXN5bmMgZnVuY3Rpb24gZ2V0R2F0ZXdheSgpOiBQcm9taXNlPEdhdGV3YXlDbGllbnQ+IHsKICBpZiAoIWdhdGV3YXlDbGllbnQpIHsKICAgIGdhdGV3YXlDbGllbnQgPSBuZXcgR2F0ZXdheUNsaWVudCgKICAgICAgY3VycmVudENvbmZpZy5vcGVuY2xhdy5nYXRld2F5VXJsLAogICAgICBjdXJyZW50Q29uZmlnLm9wZW5jbGF3LnRva2VuLAogICAgICBsb2dnZXIKICAgICk7CiAgfQogIGlmICghZ2F0ZXdheUNsaWVudC5jb25uZWN0ZWQpIHsKICAgIGF3YWl0IGdhdGV3YXlDbGllbnQuY29ubmVjdCgpOwogICAgaWYgKCFwdXNoTGlzdGVuZXJBdHRhY2hlZCkgewogICAgICBzZXR1cEFnZW50UHVzaExpc3RlbmVyKGdhdGV3YXlDbGllbnQpOwogICAgICBwdXNoTGlzdGVuZXJBdHRhY2hlZCA9IHRydWU7CiAgICB9CiAgfQogIHJldHVybiBnYXRld2F5Q2xpZW50Owp9CgpmdW5jdGlvbiBkZWJvdW5jZU1lc3NhZ2UoCiAgc2Vzc2lvbkJhc2U6IHN0cmluZywKICB0ZXh0OiBzdHJpbmcsCiAgbWVkaWE6IEV4dHJhY3RlZE1lZGlhW10sCiAgZGVib3VuY2VNczogbnVtYmVyCik6IFByb21pc2U8RGVib3VuY2VSZXN1bHQgfCBudWxsPiB7CiAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlKSA9PiB7CiAgICBsZXQgYnVmID0gZGVib3VuY2VCdWZmZXJzLmdldChzZXNzaW9uQmFzZSk7CiAgICBpZiAoYnVmKSB7CiAgICAgIGlmICh0ZXh0KSBidWYubWVzc2FnZXMucHVzaCh0ZXh0KTsKICAgICAgaWYgKG1lZGlhLmxlbmd0aCA+IDApIGJ1Zi5tZWRpYS5wdXNoKC4uLm1lZGlhKTsKICAgICAgY2xlYXJUaW1lb3V0KGJ1Zi50aW1lcik7CiAgICAgIGNvbnN0IHByZXZSZXNvbHZlID0gYnVmLnJlc29sdmU7CiAgICAgIGJ1Zi5yZXNvbHZlID0gcmVzb2x2ZTsKICAgICAgcHJldlJlc29sdmUobnVsbCk7CiAgICB9IGVsc2UgewogICAgICBidWYgPSB7CiAgICAgICAgbWVzc2FnZXM6IHRleHQgPyBbdGV4dF0gOiBbXSwKICAgICAgICBtZWRpYTogWy4uLm1lZGlhXSwKICAgICAgICByZXNvbHZlLAogICAgICAgIHRpbWVyOiBzZXRUaW1lb3V0KCgpID0+IHVuZGVmaW5lZCwgMCksCiAgICAgIH07CiAgICAgIGRlYm91bmNlQnVmZmVycy5zZXQoc2Vzc2lvbkJhc2UsIGJ1Zik7CiAgICB9CgogICAgYnVmLnRpbWVyID0gc2V0VGltZW91dCgoKSA9PiB7CiAgICAgIGRlYm91bmNlQnVmZmVycy5kZWxldGUoc2Vzc2lvbkJhc2UpOwogICAgICBidWYhLnJlc29sdmUoewogICAgICAgIHRleHQ6IGJ1ZiEubWVzc2FnZXMuam9pbignXG4nKSwKICAgICAgICBtZWRpYTogYnVmIS5tZWRpYSwKICAgICAgfSk7CiAgICB9LCBkZWJvdW5jZU1zKTsKICB9KTsKfQoKLy8gPT09PT09PT09PSBNZXNzYWdlIEV4dHJhY3Rpb24gPT09PT09PT09PQoKZnVuY3Rpb24gZXh0cmFjdE1lc3NhZ2Uoc2VnbWVudHM6IGFueVtdKTogeyBleHRyYWN0ZWRUZXh0OiBzdHJpbmc7IGV4dHJhY3RlZE1lZGlhOiBFeHRyYWN0ZWRNZWRpYVtdIH0gewogIGNvbnN0IHRleHRQYXJ0czogc3RyaW5nW10gPSBbXTsKICBjb25zdCBtZWRpYTogRXh0cmFjdGVkTWVkaWFbXSA9IFtdOwoKICBmb3IgKGNvbnN0IHNlZyBvZiBzZWdtZW50cykgewogICAgc3dpdGNoIChzZWcudHlwZSkgewogICAgICBjYXNlICd0ZXh0JzogewogICAgICAgIGNvbnN0IHQgPSBzZWcuZGF0YT8udGV4dD8udHJpbSgpOwogICAgICAgIGlmICh0KSB0ZXh0UGFydHMucHVzaCh0KTsKICAgICAgICBicmVhazsKICAgICAgfQogICAgICBjYXNlICdpbWFnZSc6CiAgICAgICAgaWYgKHNlZy5kYXRhPy51cmwpIG1lZGlhLnB1c2goeyB0eXBlOiAnaW1hZ2UnLCB1cmw6IHNlZy5kYXRhLnVybCB9KTsKICAgICAgICBicmVhazsKICAgICAgY2FzZSAnYXQnOgogICAgICAgIGlmIChTdHJpbmcoc2VnLmRhdGE/LnFxKSAhPT0gU3RyaW5nKGJvdFVzZXJJZCkpIHsKICAgICAgICAgIHRleHRQYXJ0cy5wdXNoKGBAJHtzZWcuZGF0YT8ubmFtZSB8fCBzZWcuZGF0YT8ucXF9YCk7CiAgICAgICAgfQogICAgICAgIGJyZWFrOwogICAgICBjYXNlICdmaWxlJzoKICAgICAgICBpZiAoc2VnLmRhdGE/LnVybCkgbWVkaWEucHVzaCh7IHR5cGU6ICdmaWxlJywgdXJsOiBzZWcuZGF0YS51cmwsIG5hbWU6IHNlZy5kYXRhPy5uYW1lIH0pOwogICAgICAgIGJyZWFrOwogICAgICBjYXNlICdyZWNvcmQnOgogICAgICAgIGlmIChzZWcuZGF0YT8udXJsKSBtZWRpYS5wdXNoKHsgdHlwZTogJ3ZvaWNlJywgdXJsOiBzZWcuZGF0YS51cmwgfSk7CiAgICAgICAgYnJlYWs7CiAgICAgIGNhc2UgJ3ZpZGVvJzoKICAgICAgICBpZiAoc2VnLmRhdGE/LnVybCkgbWVkaWEucHVzaCh7IHR5cGU6ICd2aWRlbycsIHVybDogc2VnLmRhdGEudXJsIH0pOwogICAgICAgIGJyZWFrOwogICAgfQogIH0KCiAgcmV0dXJuIHsgZXh0cmFjdGVkVGV4dDogdGV4dFBhcnRzLmpvaW4oJyAnKSwgZXh0cmFjdGVkTWVkaWE6IG1lZGlhIH07Cn0KCi8vID09PT09PT09PT0gVGV4dCBFeHRyYWN0aW9uIGZyb20gQ2hhdCBFdmVudCA9PT09PT09PT09CgpmdW5jdGlvbiBleHRyYWN0VGV4dEZyb21Db250ZW50KGNvbnRlbnQ6IGFueSk6IHN0cmluZyB7CiAgaWYgKHR5cGVvZiBjb250ZW50ID09PSAnc3RyaW5nJykgcmV0dXJuIGNvbnRlbnQ7CiAgaWYgKCFjb250ZW50KSByZXR1cm4gJyc7CgogIGlmIChBcnJheS5pc0FycmF5KGNvbnRlbnQpKSB7CiAgICByZXR1cm4gY29udGVudAogICAgICAubWFwKChpdGVtKSA9PiBleHRyYWN0VGV4dEZyb21Db250ZW50KGl0ZW0pKQogICAgICAuZmlsdGVyKEJvb2xlYW4pCiAgICAgIC5qb2luKCdcbicpOwogIH0KCiAgaWYgKHR5cGVvZiBjb250ZW50ICE9PSAnb2JqZWN0JykgcmV0dXJuICcnOwoKICBpZiAodHlwZW9mIGNvbnRlbnQudGV4dCA9PT0gJ3N0cmluZycpIHJldHVybiBjb250ZW50LnRleHQ7CiAgaWYgKHR5cGVvZiBjb250ZW50Lm91dHB1dF90ZXh0ID09PSAnc3RyaW5nJykgcmV0dXJuIGNvbnRlbnQub3V0cHV0X3RleHQ7CiAgaWYgKHR5cGVvZiBjb250ZW50LmlucHV0X3RleHQgPT09ICdzdHJpbmcnKSByZXR1cm4gY29udGVudC5pbnB1dF90ZXh0OwogIGlmIChjb250ZW50LmNvbnRlbnQpIHJldHVybiBleHRyYWN0VGV4dEZyb21Db250ZW50KGNvbnRlbnQuY29udGVudCk7CiAgcmV0dXJuICcnOwp9CgpmdW5jdGlvbiBleHRyYWN0VGV4dEZyb21QYXlsb2FkKG1lc3NhZ2U6IGFueSk6IHN0cmluZyB7CiAgaWYgKHR5cGVvZiBtZXNzYWdlID09PSAnc3RyaW5nJykgcmV0dXJuIG1lc3NhZ2U7CiAgaWYgKCFtZXNzYWdlKSByZXR1cm4gJyc7CgogIGNvbnN0IGNvbnRlbnRUZXh0ID0gZXh0cmFjdFRleHRGcm9tQ29udGVudChtZXNzYWdlLmNvbnRlbnQpOwogIGlmIChjb250ZW50VGV4dC50cmltKCkpIHJldHVybiBjb250ZW50VGV4dDsKICBpZiAodHlwZW9mIG1lc3NhZ2UudGV4dCA9PT0gJ3N0cmluZycpIHJldHVybiBtZXNzYWdlLnRleHQ7CiAgcmV0dXJuICcnOwp9CgpmdW5jdGlvbiBleHRyYWN0Q29udGVudFRleHQobWVzc2FnZTogYW55KTogc3RyaW5nIHsKICByZXR1cm4gZXh0cmFjdFRleHRGcm9tUGF5bG9hZChtZXNzYWdlKTsKfQoKLy8gPT09PT09PT09PSBUeXBpbmcgU3RhdHVzID09PT09PT09PT0KCmFzeW5jIGZ1bmN0aW9uIHNldFR5cGluZ1N0YXR1cyhjdHg6IGFueSwgdXNlcklkOiBudW1iZXIgfCBzdHJpbmcsIHR5cGluZzogYm9vbGVhbik6IFByb21pc2U8dm9pZD4gewogIHRyeSB7CiAgICBhd2FpdCBjdHguYWN0aW9ucy5jYWxsKAogICAgICAnc2V0X2lucHV0X3N0YXR1cycsCiAgICAgIHsgdXNlcl9pZDogU3RyaW5nKHVzZXJJZCksIGV2ZW50X3R5cGU6IHR5cGluZyA/IDEgOiAwIH0sCiAgICAgIGN0eC5hZGFwdGVyTmFtZSwKICAgICAgY3R4LnBsdWdpbk1hbmFnZXI/LmNvbmZpZwogICAgKTsKICB9IGNhdGNoIChlOiBhbnkpIHsKICAgIGxvZ2dlcj8ud2FybihgW09wZW5DbGF3XSDorr7nva7ovpPlhaXnirbmgIHlpLHotKU6ICR7ZS5tZXNzYWdlfWApOwogIH0KfQoKLy8gPT09PT09PT09PSBNZXNzYWdlIFNlbmRpbmcgPT09PT09PT09PQoKZnVuY3Rpb24gc2xlZXAobXM6IG51bWJlcik6IFByb21pc2U8dm9pZD4gewogIHJldHVybiBuZXcgUHJvbWlzZSgocikgPT4gc2V0VGltZW91dChyLCBtcykpOwp9CgpmdW5jdGlvbiBub3JtYWxpemVNZXNzYWdlVGltZXN0YW1wTXMobWVzc2FnZTogYW55KTogbnVtYmVyIHwgbnVsbCB7CiAgaWYgKCFtZXNzYWdlKSByZXR1cm4gbnVsbDsKICBpZiAodHlwZW9mIG1lc3NhZ2UudGltZXN0YW1wID09PSAnbnVtYmVyJyAmJiBOdW1iZXIuaXNGaW5pdGUobWVzc2FnZS50aW1lc3RhbXApKSB7CiAgICByZXR1cm4gbWVzc2FnZS50aW1lc3RhbXA7CiAgfQogIGlmICh0eXBlb2YgbWVzc2FnZS50aW1lc3RhbXAgPT09ICdzdHJpbmcnKSB7CiAgICBjb25zdCBwYXJzZWQgPSBEYXRlLnBhcnNlKG1lc3NhZ2UudGltZXN0YW1wKTsKICAgIGlmIChOdW1iZXIuaXNGaW5pdGUocGFyc2VkKSkgcmV0dXJuIHBhcnNlZDsKICB9CiAgcmV0dXJuIG51bGw7Cn0KCmZ1bmN0aW9uIHBpY2tMYXRlc3RBc3Npc3RhbnRUZXh0KG1lc3NhZ2VzOiBhbnlbXSwgbWluVGltZXN0YW1wTXM6IG51bWJlcik6IHN0cmluZyB8IG51bGwgewogIGZvciAobGV0IGkgPSBtZXNzYWdlcy5sZW5ndGggLSAxOyBpID49IDA7IGktLSkgewogICAgY29uc3QgbXNnID0gbWVzc2FnZXNbaV07CiAgICBpZiAoIW1zZyB8fCB0eXBlb2YgbXNnICE9PSAnb2JqZWN0JykgY29udGludWU7CgogICAgY29uc3Qgcm9sZSA9IHR5cGVvZiBtc2cucm9sZSA9PT0gJ3N0cmluZycgPyBtc2cucm9sZS50b0xvd2VyQ2FzZSgpIDogJyc7CiAgICBpZiAocm9sZSAhPT0gJ2Fzc2lzdGFudCcpIGNvbnRpbnVlOwoKICAgIGNvbnN0IHRleHQgPSBleHRyYWN0Q29udGVudFRleHQobXNnKS50cmltKCk7CiAgICBpZiAoIXRleHQpIGNvbnRpbnVlOwoKICAgIGNvbnN0IHRzID0gbm9ybWFsaXplTWVzc2FnZVRpbWVzdGFtcE1zKG1zZyk7CiAgICBpZiAodHMgIT09IG51bGwgJiYgdHMgKyAxMDAwIDwgbWluVGltZXN0YW1wTXMpIGNvbnRpbnVlOwoKICAgIHJldHVybiB0ZXh0OwogIH0KICByZXR1cm4gbnVsbDsKfQoKYXN5bmMgZnVuY3Rpb24gcmVzb2x2ZVJlcGx5RnJvbUhpc3RvcnkoCiAgZ3c6IEdhdGV3YXlDbGllbnQsCiAgc2Vzc2lvbktleTogc3RyaW5nLAogIG1pblRpbWVzdGFtcE1zOiBudW1iZXIsCiAgb3B0aW9ucz86IHsKICAgIG1heEF0dGVtcHRzPzogbnVtYmVyOwogICAgaW50ZXJ2YWxNcz86IG51bWJlcjsKICAgIHNob3VsZFN0b3A/OiAoKSA9PiBib29sZWFuOwogIH0KKTogUHJvbWlzZTxzdHJpbmcgfCBudWxsPiB7CiAgY29uc3QgbWF4QXR0ZW1wdHMgPSBNYXRoLm1heCgxLCBvcHRpb25zPy5tYXhBdHRlbXB0cyA/PyA2KTsKICBjb25zdCBpbnRlcnZhbE1zID0gTWF0aC5tYXgoMTAwLCBvcHRpb25zPy5pbnRlcnZhbE1zID8/IDM1MCk7CiAgZm9yIChsZXQgaSA9IDA7IGkgPCBtYXhBdHRlbXB0czsgaSsrKSB7CiAgICBpZiAob3B0aW9ucz8uc2hvdWxkU3RvcD8uKCkpIHJldHVybiBudWxsOwogICAgdHJ5IHsKICAgICAgY29uc3QgaGlzdG9yeSA9IGF3YWl0IGd3LnJlcXVlc3QoJ2NoYXQuaGlzdG9yeScsIHsgc2Vzc2lvbktleSwgbGltaXQ6IDEwMCB9KTsKICAgICAgY29uc3QgbWVzc2FnZXMgPSBBcnJheS5pc0FycmF5KGhpc3Rvcnk/Lm1lc3NhZ2VzKSA/IGhpc3RvcnkubWVzc2FnZXMgOiBbXTsKICAgICAgY29uc3QgdGV4dCA9IHBpY2tMYXRlc3RBc3Npc3RhbnRUZXh0KG1lc3NhZ2VzLCBtaW5UaW1lc3RhbXBNcyk7CiAgICAgIGlmICh0ZXh0KSByZXR1cm4gdGV4dDsKICAgIH0gY2F0Y2ggKGU6IGFueSkgewogICAgICBsb2dnZXI/Lndhcm4oYFtPcGVuQ2xhd10g5Zue5p+lIGNoYXQuaGlzdG9yeSDlpLHotKU6ICR7ZS5tZXNzYWdlfWApOwogICAgICByZXR1cm4gbnVsbDsKICAgIH0KCiAgICBpZiAoaSArIDEgPCBtYXhBdHRlbXB0cykgewogICAgICBhd2FpdCBzbGVlcChpbnRlcnZhbE1zKTsKICAgIH0KICB9CiAgcmV0dXJuIG51bGw7Cn0KCmZ1bmN0aW9uIGlzUmVjb3ZlcmFibGVHYXRld2F5RXJyb3IoZXJyb3JNZXNzYWdlOiBzdHJpbmcpOiBib29sZWFuIHsKICBjb25zdCBub3JtYWxpemVkID0gZXJyb3JNZXNzYWdlLnRyaW0oKS50b0xvd2VyQ2FzZSgpOwogIGlmICghbm9ybWFsaXplZCkgcmV0dXJuIGZhbHNlOwogIHJldHVybiAvKHRlcm1pbmF0ZWR8YWJvcnR8Y2FuY2VsfGtpbGxlZHxpbnRlcnJ1cHR8cmV0cnl8dGltZW91dHxpbltfIC1dP2ZsaWdodCkvaS50ZXN0KG5vcm1hbGl6ZWQpOwp9Cgphc3luYyBmdW5jdGlvbiBzZW5kUmVwbHkoY3R4OiBhbnksIG1lc3NhZ2VUeXBlOiBzdHJpbmcsIGdyb3VwSWQ6IGFueSwgdXNlcklkOiBhbnksIHRleHQ6IHN0cmluZyk6IFByb21pc2U8dm9pZD4gewogIGNvbnN0IGFjdGlvbiA9IG1lc3NhZ2VUeXBlID09PSAnZ3JvdXAnID8gJ3NlbmRfZ3JvdXBfbXNnJyA6ICdzZW5kX3ByaXZhdGVfbXNnJzsKICBjb25zdCBpZEtleSA9IG1lc3NhZ2VUeXBlID09PSAnZ3JvdXAnID8gJ2dyb3VwX2lkJyA6ICd1c2VyX2lkJzsKICBjb25zdCBpZFZhbCA9IFN0cmluZyhtZXNzYWdlVHlwZSA9PT0gJ2dyb3VwJyA/IGdyb3VwSWQgOiB1c2VySWQpOwoKICBjb25zdCBtYXhMZW4gPSAzMDAwOwogIGlmICh0ZXh0Lmxlbmd0aCA8PSBtYXhMZW4pIHsKICAgIGF3YWl0IGN0eC5hY3Rpb25zLmNhbGwoYWN0aW9uLCB7IFtpZEtleV06IGlkVmFsLCBtZXNzYWdlOiB0ZXh0IH0sIGN0eC5hZGFwdGVyTmFtZSwgY3R4LnBsdWdpbk1hbmFnZXI/LmNvbmZpZyk7CiAgfSBlbHNlIHsKICAgIGNvbnN0IHRvdGFsID0gTWF0aC5jZWlsKHRleHQubGVuZ3RoIC8gbWF4TGVuKTsKICAgIGZvciAobGV0IGkgPSAwOyBpIDwgdGV4dC5sZW5ndGg7IGkgKz0gbWF4TGVuKSB7CiAgICAgIGNvbnN0IGlkeCA9IE1hdGguZmxvb3IoaSAvIG1heExlbikgKyAxOwogICAgICBjb25zdCBwcmVmaXggPSB0b3RhbCA+IDEgPyBgWyR7aWR4fS8ke3RvdGFsfV1cbmAgOiAnJzsKICAgICAgYXdhaXQgY3R4LmFjdGlvbnMuY2FsbCgKICAgICAgICBhY3Rpb24sCiAgICAgICAgeyBbaWRLZXldOiBpZFZhbCwgbWVzc2FnZTogcHJlZml4ICsgdGV4dC5zbGljZShpLCBpICsgbWF4TGVuKSB9LAogICAgICAgIGN0eC5hZGFwdGVyTmFtZSwKICAgICAgICBjdHgucGx1Z2luTWFuYWdlcj8uY29uZmlnCiAgICAgICk7CiAgICAgIGlmIChpICsgbWF4TGVuIDwgdGV4dC5sZW5ndGgpIGF3YWl0IHNsZWVwKDEwMDApOwogICAgfQogIH0KfQoKYXN5bmMgZnVuY3Rpb24gc2VuZEltYWdlTXNnKAogIGN0eDogYW55LAogIG1lc3NhZ2VUeXBlOiBzdHJpbmcsCiAgZ3JvdXBJZDogbnVtYmVyIHwgc3RyaW5nIHwgbnVsbCwKICB1c2VySWQ6IG51bWJlciB8IHN0cmluZyB8IG51bGwsCiAgaW1hZ2VVcmw6IHN0cmluZwopOiBQcm9taXNlPHZvaWQ+IHsKICBjb25zdCBtZXNzYWdlID0gW3sgdHlwZTogJ2ltYWdlJywgZGF0YTogeyB1cmw6IGltYWdlVXJsIH0gfV07CiAgaWYgKG1lc3NhZ2VUeXBlID09PSAnZ3JvdXAnKSB7CiAgICBhd2FpdCBjdHguYWN0aW9ucy5jYWxsKAogICAgICAnc2VuZF9ncm91cF9tc2cnLAogICAgICB7IGdyb3VwX2lkOiBTdHJpbmcoZ3JvdXBJZCksIG1lc3NhZ2UgfSwKICAgICAgY3R4LmFkYXB0ZXJOYW1lLAogICAgICBjdHgucGx1Z2luTWFuYWdlcj8uY29uZmlnCiAgICApOwogICAgcmV0dXJuOwogIH0KICBhd2FpdCBjdHguYWN0aW9ucy5jYWxsKAogICAgJ3NlbmRfcHJpdmF0ZV9tc2cnLAogICAgeyB1c2VyX2lkOiBTdHJpbmcodXNlcklkKSwgbWVzc2FnZSB9LAogICAgY3R4LmFkYXB0ZXJOYW1lLAogICAgY3R4LnBsdWdpbk1hbmFnZXI/LmNvbmZpZwogICk7Cn0KCmFzeW5jIGZ1bmN0aW9uIHNlbmRHcm91cE1zZyhjdHg6IGFueSwgZ3JvdXBJZDogc3RyaW5nIHwgbnVtYmVyLCB0ZXh0OiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHsKICBhd2FpdCBjdHguYWN0aW9ucy5jYWxsKAogICAgJ3NlbmRfZ3JvdXBfbXNnJywKICAgIHsgZ3JvdXBfaWQ6IFN0cmluZyhncm91cElkKSwgbWVzc2FnZTogdGV4dCB9LAogICAgY3R4LmFkYXB0ZXJOYW1lLAogICAgY3R4LnBsdWdpbk1hbmFnZXI/LmNvbmZpZwogICk7Cn0KCmFzeW5jIGZ1bmN0aW9uIHNlbmRQcml2YXRlTXNnKGN0eDogYW55LCB1c2VySWQ6IHN0cmluZyB8IG51bWJlciwgdGV4dDogc3RyaW5nKTogUHJvbWlzZTx2b2lkPiB7CiAgYXdhaXQgY3R4LmFjdGlvbnMuY2FsbCgKICAgICdzZW5kX3ByaXZhdGVfbXNnJywKICAgIHsgdXNlcl9pZDogU3RyaW5nKHVzZXJJZCksIG1lc3NhZ2U6IHRleHQgfSwKICAgIGN0eC5hZGFwdGVyTmFtZSwKICAgIGN0eC5wbHVnaW5NYW5hZ2VyPy5jb25maWcKICApOwp9CgpmdW5jdGlvbiBpc1ByaXZhdGVJcChob3N0OiBzdHJpbmcpOiBib29sZWFuIHsKICBpZiAoIWhvc3QpIHJldHVybiB0cnVlOwogIGNvbnN0IG5vcm1hbGl6ZWQgPSBob3N0LnRyaW0oKS50b0xvd2VyQ2FzZSgpOwogIGlmIChub3JtYWxpemVkID09PSAnbG9jYWxob3N0JyB8fCBub3JtYWxpemVkID09PSAnaXA2LWxvY2FsaG9zdCcpIHJldHVybiB0cnVlOwoKICBjb25zdCBpcFZlcnNpb24gPSBuZXQuaXNJUChub3JtYWxpemVkKTsKICBpZiAoaXBWZXJzaW9uID09PSA0KSB7CiAgICBpZiAobm9ybWFsaXplZC5zdGFydHNXaXRoKCcxMjcuJykpIHJldHVybiB0cnVlOwogICAgaWYgKG5vcm1hbGl6ZWQuc3RhcnRzV2l0aCgnMTAuJykpIHJldHVybiB0cnVlOwogICAgaWYgKG5vcm1hbGl6ZWQuc3RhcnRzV2l0aCgnMTkyLjE2OC4nKSkgcmV0dXJuIHRydWU7CiAgICBpZiAobm9ybWFsaXplZC5zdGFydHNXaXRoKCcxNjkuMjU0LicpKSByZXR1cm4gdHJ1ZTsKICAgIGNvbnN0IHBhcnRzID0gbm9ybWFsaXplZC5zcGxpdCgnLicpLm1hcChOdW1iZXIpOwogICAgaWYgKHBhcnRzLmxlbmd0aCA9PT0gNCAmJiBwYXJ0c1swXSA9PT0gMTcyICYmIHBhcnRzWzFdID49IDE2ICYmIHBhcnRzWzFdIDw9IDMxKSByZXR1cm4gdHJ1ZTsKICAgIHJldHVybiBmYWxzZTsKICB9CiAgaWYgKGlwVmVyc2lvbiA9PT0gNikgewogICAgaWYgKG5vcm1hbGl6ZWQgPT09ICc6OjEnKSByZXR1cm4gdHJ1ZTsKICAgIHJldHVybiBub3JtYWxpemVkLnN0YXJ0c1dpdGgoJ2ZjJykgfHwgbm9ybWFsaXplZC5zdGFydHNXaXRoKCdmZCcpOwogIH0KICByZXR1cm4gZmFsc2U7Cn0KCmFzeW5jIGZ1bmN0aW9uIGFzc2VydFNhZmVSZW1vdGVVcmwocmF3VXJsOiBzdHJpbmcpOiBQcm9taXNlPFVSTD4gewogIGNvbnN0IHBhcnNlZCA9IG5ldyBVUkwocmF3VXJsKTsKICBpZiAocGFyc2VkLnByb3RvY29sICE9PSAnaHR0cDonICYmIHBhcnNlZC5wcm90b2NvbCAhPT0gJ2h0dHBzOicpIHsKICAgIHRocm93IG5ldyBFcnJvcihgdW5zdXBwb3J0ZWQgcHJvdG9jb2w6ICR7cGFyc2VkLnByb3RvY29sfWApOwogIH0KICBpZiAoIXBhcnNlZC5ob3N0bmFtZSkgewogICAgdGhyb3cgbmV3IEVycm9yKCdpbnZhbGlkIGhvc3RuYW1lJyk7CiAgfQogIGlmIChpc1ByaXZhdGVJcChwYXJzZWQuaG9zdG5hbWUpKSB7CiAgICB0aHJvdyBuZXcgRXJyb3IoJ3ByaXZhdGUgbmV0d29yayBhZGRyZXNzIGlzIG5vdCBhbGxvd2VkJyk7CiAgfQogIGNvbnN0IHJlY29yZHMgPSBhd2FpdCBkbnMubG9va3VwKHBhcnNlZC5ob3N0bmFtZSwgeyBhbGw6IHRydWUgfSk7CiAgaWYgKCFyZWNvcmRzLmxlbmd0aCkgewogICAgdGhyb3cgbmV3IEVycm9yKCdob3N0bmFtZSByZXNvbHV0aW9uIGZhaWxlZCcpOwogIH0KICBmb3IgKGNvbnN0IHJlY29yZCBvZiByZWNvcmRzKSB7CiAgICBpZiAoaXNQcml2YXRlSXAocmVjb3JkLmFkZHJlc3MpKSB7CiAgICAgIHRocm93IG5ldyBFcnJvcigncmVzb2x2ZWQgcHJpdmF0ZSBuZXR3b3JrIGFkZHJlc3MgaXMgbm90IGFsbG93ZWQnKTsKICAgIH0KICB9CiAgcmV0dXJuIHBhcnNlZDsKfQoKYXN5bmMgZnVuY3Rpb24gZG93bmxvYWRUb0J1ZmZlcih1cmw6IHN0cmluZywgbWF4Qnl0ZXMgPSA1ICogMTAyNCAqIDEwMjQsIHJlZGlyZWN0Q291bnQgPSAwKTogUHJvbWlzZTxCdWZmZXI+IHsKICBpZiAocmVkaXJlY3RDb3VudCA+IDUpIHsKICAgIHRocm93IG5ldyBFcnJvcigndG9vIG1hbnkgcmVkaXJlY3RzJyk7CiAgfQogIGNvbnN0IHBhcnNlZCA9IGF3YWl0IGFzc2VydFNhZmVSZW1vdGVVcmwodXJsKTsKICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4gewogICAgY29uc3QgbW9kID0gcGFyc2VkLnByb3RvY29sID09PSAnaHR0cHM6JyA/IGh0dHBzIDogaHR0cDsKICAgIGNvbnN0IHJlcSA9IG1vZC5nZXQocGFyc2VkLnRvU3RyaW5nKCksIHsgdGltZW91dDogMTAwMDAgfSwgKHJlcykgPT4gewogICAgICBpZiAocmVzLnN0YXR1c0NvZGUgJiYgcmVzLnN0YXR1c0NvZGUgPj0gMzAwICYmIHJlcy5zdGF0dXNDb2RlIDwgNDAwICYmIHJlcy5oZWFkZXJzLmxvY2F0aW9uKSB7CiAgICAgICAgY29uc3QgbmV4dFVybCA9IG5ldyBVUkwocmVzLmhlYWRlcnMubG9jYXRpb24sIHBhcnNlZCkudG9TdHJpbmcoKTsKICAgICAgICByZXMucmVzdW1lKCk7CiAgICAgICAgdm9pZCBkb3dubG9hZFRvQnVmZmVyKG5leHRVcmwsIG1heEJ5dGVzLCByZWRpcmVjdENvdW50ICsgMSkudGhlbihyZXNvbHZlKS5jYXRjaChyZWplY3QpOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBpZiAocmVzLnN0YXR1c0NvZGUgIT09IDIwMCkgewogICAgICAgIHJlcy5yZXN1bWUoKTsKICAgICAgICByZWplY3QobmV3IEVycm9yKGBIVFRQICR7cmVzLnN0YXR1c0NvZGV9YCkpOwogICAgICAgIHJldHVybjsKICAgICAgfQogICAgICBjb25zdCBjaHVua3M6IEJ1ZmZlcltdID0gW107CiAgICAgIGxldCB0b3RhbCA9IDA7CiAgICAgIHJlcy5vbignZGF0YScsIChjaHVuazogQnVmZmVyKSA9PiB7CiAgICAgICAgdG90YWwgKz0gY2h1bmsubGVuZ3RoOwogICAgICAgIGlmICh0b3RhbCA+IG1heEJ5dGVzKSB7CiAgICAgICAgICByZXMuZGVzdHJveSgpOwogICAgICAgICAgcmVqZWN0KG5ldyBFcnJvcihgZXhjZWVkcyAke21heEJ5dGVzfSBieXRlc2ApKTsKICAgICAgICAgIHJldHVybjsKICAgICAgICB9CiAgICAgICAgY2h1bmtzLnB1c2goY2h1bmspOwogICAgICB9KTsKICAgICAgcmVzLm9uKCdlbmQnLCAoKSA9PiByZXNvbHZlKEJ1ZmZlci5jb25jYXQoY2h1bmtzKSkpOwogICAgICByZXMub24oJ2Vycm9yJywgcmVqZWN0KTsKICAgIH0pOwogICAgcmVxLm9uKCd0aW1lb3V0JywgKCkgPT4gewogICAgICByZXEuZGVzdHJveSgpOwogICAgICByZWplY3QobmV3IEVycm9yKCd0aW1lb3V0JykpOwogICAgfSk7CiAgICByZXEub24oJ2Vycm9yJywgcmVqZWN0KTsKICB9KTsKfQoKZnVuY3Rpb24gZ3Vlc3NNaW1lRnJvbVVybCh1cmw/OiBzdHJpbmcpOiBzdHJpbmcgewogIGNvbnN0IGV4dCA9ICh1cmwgfHwgJycpLnNwbGl0KCc/JylbMF0uc3BsaXQoJy4nKS5wb3AoKT8udG9Mb3dlckNhc2UoKTsKICBjb25zdCBtaW1lTWFwOiBSZWNvcmQ8c3RyaW5nLCBzdHJpbmc+ID0gewogICAganBnOiAnaW1hZ2UvanBlZycsCiAgICBqcGVnOiAnaW1hZ2UvanBlZycsCiAgICBwbmc6ICdpbWFnZS9wbmcnLAogICAgZ2lmOiAnaW1hZ2UvZ2lmJywKICAgIHdlYnA6ICdpbWFnZS93ZWJwJywKICAgIGJtcDogJ2ltYWdlL2JtcCcsCiAgfTsKICByZXR1cm4gbWltZU1hcFtleHQgfHwgJyddIHx8ICdpbWFnZS9wbmcnOwp9Cgphc3luYyBmdW5jdGlvbiBzYXZlTWVkaWFUb0NhY2hlKG1lZGlhTGlzdDogRXh0cmFjdGVkTWVkaWFbXSwgY3R4OiBhbnkpOiBQcm9taXNlPFNhdmVkTWVkaWFbXT4gewogIGNvbnN0IGNhY2hlRGlyID0gcGF0aC5qb2luKHBsdWdpbkRpciB8fCAnL3RtcCcsICdjYWNoZScsICdtZWRpYScpOwogIGF3YWl0IGZzLnByb21pc2VzLm1rZGlyKGNhY2hlRGlyLCB7IHJlY3Vyc2l2ZTogdHJ1ZSB9KTsKCiAgY29uc3Qgc2F2ZWQ6IFNhdmVkTWVkaWFbXSA9IFtdOwogIGZvciAoY29uc3QgbSBvZiBtZWRpYUxpc3QpIHsKICAgIHRyeSB7CiAgICAgIGxldCBidWY6IEJ1ZmZlciB8IG51bGwgPSBudWxsOwogICAgICBpZiAobS51cmwpIHsKICAgICAgICBidWYgPSBhd2FpdCBkb3dubG9hZFRvQnVmZmVyKG0udXJsLCAxMCAqIDEwMjQgKiAxMDI0KTsKICAgICAgfSBlbHNlIGlmIChtLmZpbGVfaWQgJiYgY3R4KSB7CiAgICAgICAgdHJ5IHsKICAgICAgICAgIGNvbnN0IGZpbGVJbmZvID0gYXdhaXQgY3R4LmFjdGlvbnMuY2FsbCgKICAgICAgICAgICAgJ2dldF9maWxlJywKICAgICAgICAgICAgeyBmaWxlX2lkOiBtLmZpbGVfaWQgfSwKICAgICAgICAgICAgY3R4LmFkYXB0ZXJOYW1lLAogICAgICAgICAgICBjdHgucGx1Z2luTWFuYWdlcj8uY29uZmlnCiAgICAgICAgICApOwogICAgICAgICAgaWYgKGZpbGVJbmZvPy5maWxlKSB7CiAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgYXdhaXQgZnMucHJvbWlzZXMuYWNjZXNzKGZpbGVJbmZvLmZpbGUpOwogICAgICAgICAgICAgIGJ1ZiA9IGF3YWl0IGZzLnByb21pc2VzLnJlYWRGaWxlKGZpbGVJbmZvLmZpbGUpOwogICAgICAgICAgICB9IGNhdGNoIHsKICAgICAgICAgICAgICBpZiAoZmlsZUluZm8udXJsKSBidWYgPSBhd2FpdCBkb3dubG9hZFRvQnVmZmVyKGZpbGVJbmZvLnVybCwgMTAgKiAxMDI0ICogMTAyNCk7CiAgICAgICAgICAgICAgZWxzZSBpZiAoZmlsZUluZm8uYmFzZTY0KSBidWYgPSBCdWZmZXIuZnJvbShmaWxlSW5mby5iYXNlNjQsICdiYXNlNjQnKTsKICAgICAgICAgICAgfQogICAgICAgICAgfQogICAgICAgIH0gY2F0Y2ggKGU6IGFueSkgewogICAgICAgICAgbG9nZ2VyPy53YXJuKGBbT3BlbkNsYXddIGdldF9maWxlIOWksei0pTogJHtlLm1lc3NhZ2V9YCk7CiAgICAgICAgfQogICAgICB9CgogICAgICBpZiAoIWJ1ZikgewogICAgICAgIHNhdmVkLnB1c2goeyB0eXBlOiBtLnR5cGUsIHBhdGg6IG51bGwsIHVybDogbS51cmwsIG5hbWU6IG0ubmFtZSB9KTsKICAgICAgICBjb250aW51ZTsKICAgICAgfQogICAgICBsZXQgZXh0ID0gJ2Jpbic7CiAgICAgIGlmIChtLnR5cGUgPT09ICdpbWFnZScpIGV4dCA9IGd1ZXNzTWltZUZyb21VcmwobS51cmwpLnNwbGl0KCcvJylbMV0gfHwgJ3BuZyc7CiAgICAgIGVsc2UgaWYgKG0ubmFtZSkgZXh0ID0gbS5uYW1lLnNwbGl0KCcuJykucG9wKCkgfHwgJ2Jpbic7CiAgICAgIGVsc2UgaWYgKG0udHlwZSA9PT0gJ3ZvaWNlJykgZXh0ID0gJ3NpbGsnOwogICAgICBlbHNlIGlmIChtLnR5cGUgPT09ICd2aWRlbycpIGV4dCA9ICdtcDQnOwoKICAgICAgY29uc3QgZmlsZW5hbWUgPSBgJHtEYXRlLm5vdygpfS0ke3JhbmRvbVVVSUQoKS5zbGljZSgwLCA4KX0uJHtleHR9YDsKICAgICAgY29uc3QgZmlsZVBhdGggPSBwYXRoLmpvaW4oY2FjaGVEaXIsIGZpbGVuYW1lKTsKICAgICAgYXdhaXQgZnMucHJvbWlzZXMud3JpdGVGaWxlKGZpbGVQYXRoLCBidWYpOwogICAgICBzYXZlZC5wdXNoKHsgdHlwZTogbS50eXBlLCBwYXRoOiBmaWxlUGF0aCwgbmFtZTogbS5uYW1lIHx8IGZpbGVuYW1lLCBzaXplOiBidWYubGVuZ3RoIH0pOwogICAgfSBjYXRjaCAoZTogYW55KSB7CiAgICAgIGxvZ2dlcj8ud2FybihgW09wZW5DbGF3XSDkuIvovb3mlofku7blpLHotKU6ICR7ZS5tZXNzYWdlfWApOwogICAgICBzYXZlZC5wdXNoKHsgdHlwZTogbS50eXBlLCBwYXRoOiBudWxsLCB1cmw6IG0udXJsLCBuYW1lOiBtLm5hbWUgfSk7CiAgICB9CiAgfQoKICB0cnkgewogICAgY29uc3QgY3V0b2ZmID0gRGF0ZS5ub3coKSAtIDM2MDAwMDA7CiAgICBjb25zdCBmaWxlcyA9IGF3YWl0IGZzLnByb21pc2VzLnJlYWRkaXIoY2FjaGVEaXIpOwogICAgZm9yIChjb25zdCBuYW1lIG9mIGZpbGVzKSB7CiAgICAgIGNvbnN0IGZ1bGxQYXRoID0gcGF0aC5qb2luKGNhY2hlRGlyLCBuYW1lKTsKICAgICAgY29uc3Qgc3RhdCA9IGF3YWl0IGZzLnByb21pc2VzLnN0YXQoZnVsbFBhdGgpOwogICAgICBpZiAoc3RhdC5tdGltZU1zIDwgY3V0b2ZmKSBhd2FpdCBmcy5wcm9taXNlcy51bmxpbmsoZnVsbFBhdGgpOwogICAgfQogIH0gY2F0Y2ggewogICAgLy8gaWdub3JlIGNsZWFudXAgZXJyb3JzCiAgfQoKICByZXR1cm4gc2F2ZWQ7Cn0KCmZ1bmN0aW9uIGV4dHJhY3RJbWFnZXNGcm9tUmVwbHkodGV4dDogc3RyaW5nKTogeyBpbWFnZXM6IHN0cmluZ1tdOyBjbGVhblRleHQ6IHN0cmluZyB9IHsKICBjb25zdCBpbWFnZXM6IHN0cmluZ1tdID0gW107CiAgY29uc3QgbWVkaWFSZWdleCA9IC9eTUVESUE6XHMqKC4rKSQvZ207CiAgbGV0IG1hdGNoOiBSZWdFeHBFeGVjQXJyYXkgfCBudWxsOwogIHdoaWxlICgobWF0Y2ggPSBtZWRpYVJlZ2V4LmV4ZWModGV4dCkpICE9PSBudWxsKSB7CiAgICBjb25zdCB1cmwgPSBtYXRjaFsxXS50cmltKCk7CiAgICBpZiAodXJsLnN0YXJ0c1dpdGgoJ2h0dHAnKSkgaW1hZ2VzLnB1c2godXJsKTsKICB9CiAgY29uc3QgbWRSZWdleCA9IC8hXFtbXlxdXSpcXVwoKFteKV0rKVwpL2c7CiAgd2hpbGUgKChtYXRjaCA9IG1kUmVnZXguZXhlYyh0ZXh0KSkgIT09IG51bGwpIHsKICAgIGNvbnN0IHVybCA9IG1hdGNoWzFdLnRyaW0oKTsKICAgIGlmICh1cmwuc3RhcnRzV2l0aCgnaHR0cCcpKSBpbWFnZXMucHVzaCh1cmwpOwogIH0KICBjb25zdCBjbGVhblRleHQgPSB0ZXh0CiAgICAucmVwbGFjZSgvXk1FRElBOlxzKi4rJC9nbSwgJycpCiAgICAucmVwbGFjZSgvIVxbW15cXV0qXF1cKFteKV0rXCkvZywgJycpCiAgICAudHJpbSgpOwogIHJldHVybiB7IGltYWdlczogQXJyYXkuZnJvbShuZXcgU2V0KGltYWdlcykpLCBjbGVhblRleHQgfTsKfQoKZnVuY3Rpb24gc2V0dXBBZ2VudFB1c2hMaXN0ZW5lcihndzogR2F0ZXdheUNsaWVudCk6IHZvaWQgewogIGd3LmV2ZW50SGFuZGxlcnMuc2V0KCdjaGF0JywgKHBheWxvYWQ6IENoYXRFdmVudFBheWxvYWQpID0+IHsKICAgIGlmICghcGF5bG9hZCB8fCBwYXlsb2FkLnN0YXRlICE9PSAnZmluYWwnIHx8ICFwYXlsb2FkLnNlc3Npb25LZXkpIHJldHVybjsKICAgIGlmICghcGF5bG9hZC5zZXNzaW9uS2V5LnN0YXJ0c1dpdGgoJ3FxLScpKSByZXR1cm47CiAgICBpZiAocGF5bG9hZC5ydW5JZCAmJiBndy5jaGF0V2FpdGVycy5oYXMocGF5bG9hZC5ydW5JZCkpIHJldHVybjsKICAgIGlmICghbGFzdEN0eCkgcmV0dXJuOwoKICAgIGNvbnN0IHRleHQgPSBleHRyYWN0Q29udGVudFRleHQocGF5bG9hZC5tZXNzYWdlKS50cmltKCk7CiAgICBpZiAoIXRleHQpIHJldHVybjsKICAgIGxvZ2dlcj8uaW5mbyhgW09wZW5DbGF3XSBBZ2VudCDkuLvliqjmjqjpgIE6ICR7cGF5bG9hZC5zZXNzaW9uS2V5fSAtPiAke3RleHQuc2xpY2UoMCwgNTApfWApOwoKICAgIGNvbnN0IHByaXZhdGVNYXRjaCA9IHBheWxvYWQuc2Vzc2lvbktleS5tYXRjaCgvXnFxLShcZCspKD86LVxkKyk/JC8pOwogICAgaWYgKHByaXZhdGVNYXRjaCAmJiAhcGF5bG9hZC5zZXNzaW9uS2V5LmluY2x1ZGVzKCctZycpKSB7CiAgICAgIGNvbnN0IHsgaW1hZ2VzLCBjbGVhblRleHQgfSA9IGV4dHJhY3RJbWFnZXNGcm9tUmVwbHkodGV4dCk7CiAgICAgIGlmIChjbGVhblRleHQpIHZvaWQgc2VuZFByaXZhdGVNc2cobGFzdEN0eCwgcHJpdmF0ZU1hdGNoWzFdLCBjbGVhblRleHQpOwogICAgICBmb3IgKGNvbnN0IGltZyBvZiBpbWFnZXMpIHZvaWQgc2VuZEltYWdlTXNnKGxhc3RDdHgsICdwcml2YXRlJywgbnVsbCwgcHJpdmF0ZU1hdGNoWzFdLCBpbWcpOwogICAgICByZXR1cm47CiAgICB9CgogICAgY29uc3QgZ3JvdXBNYXRjaCA9IHBheWxvYWQuc2Vzc2lvbktleS5tYXRjaCgvXnFxLWcoXGQrKS8pOwogICAgaWYgKGdyb3VwTWF0Y2gpIHsKICAgICAgY29uc3QgeyBpbWFnZXMsIGNsZWFuVGV4dCB9ID0gZXh0cmFjdEltYWdlc0Zyb21SZXBseSh0ZXh0KTsKICAgICAgaWYgKGNsZWFuVGV4dCkgdm9pZCBzZW5kR3JvdXBNc2cobGFzdEN0eCwgZ3JvdXBNYXRjaFsxXSwgY2xlYW5UZXh0KTsKICAgICAgZm9yIChjb25zdCBpbWcgb2YgaW1hZ2VzKSB2b2lkIHNlbmRJbWFnZU1zZyhsYXN0Q3R4LCAnZ3JvdXAnLCBncm91cE1hdGNoWzFdLCBudWxsLCBpbWcpOwogICAgfQogIH0pOwp9CgovLyA9PT09PT09PT09IExpZmVjeWNsZSA9PT09PT09PT09CgpleHBvcnQgbGV0IHBsdWdpbl9jb25maWdfdWk6IGFueVtdID0gW107CgpleHBvcnQgY29uc3QgcGx1Z2luX2luaXQgPSBhc3luYyAoY3R4OiBhbnkpOiBQcm9taXNlPHZvaWQ+ID0+IHsKICBsb2dnZXIgPSBjdHgubG9nZ2VyOwogIGxhc3RDdHggPSBjdHg7CiAgY29uZmlnUGF0aCA9IGN0eC5jb25maWdQYXRoOwogIHBsdWdpbkRpciA9IG5ldyBVUkwoJy4nLCBpbXBvcnQubWV0YS51cmwpLnBhdGhuYW1lOwogIGxvZ2dlci5pbmZvKCdbT3BlbkNsYXddIFFRIENoYW5uZWwg5o+S5Lu25Yid5aeL5YyW5LitLi4uJyk7CgogIC8vIExvYWQgc2F2ZWQgY29uZmlnCiAgdHJ5IHsKICAgIGlmIChjb25maWdQYXRoICYmIGZzLmV4aXN0c1N5bmMoY29uZmlnUGF0aCkpIHsKICAgICAgY29uc3Qgc2F2ZWQgPSBKU09OLnBhcnNlKGZzLnJlYWRGaWxlU3luYyhjb25maWdQYXRoLCAndXRmLTgnKSk7CiAgICAgIGN1cnJlbnRDb25maWcgPSBkZWVwTWVyZ2UoY3VycmVudENvbmZpZywgc2F2ZWQpOwogICAgICBsb2dnZXIuaW5mbygnW09wZW5DbGF3XSDlt7LliqDovb3kv53lrZjnmoTphY3nva4nKTsKICAgIH0KICB9IGNhdGNoIChlOiBhbnkpIHsKICAgIGxvZ2dlci53YXJuKCdbT3BlbkNsYXddIOWKoOi9vemFjee9ruWksei0pTogJyArIGUubWVzc2FnZSk7CiAgfQoKICBwbHVnaW5fY29uZmlnX3VpID0gYnVpbGRDb25maWdTY2hlbWEoKTsKCiAgLy8gUHJlLWNvbm5lY3QgZ2F0ZXdheQogIHRyeSB7CiAgICBhd2FpdCBnZXRHYXRld2F5KCk7CiAgICBsb2dnZXIuaW5mbygnW09wZW5DbGF3XSBHYXRld2F5IOi/nuaOpeWwsee7qicpOwogIH0gY2F0Y2ggKGU6IGFueSkgewogICAgbG9nZ2VyLmVycm9yKGBbT3BlbkNsYXddIEdhdGV3YXkg6aKE6L+e5o6l5aSx6LSlOiAke2UubWVzc2FnZX3vvIjlsIblnKjpppbmrKHmtojmga/ml7bph43or5XvvIlgKTsKICB9CgogIGxvZ2dlci5pbmZvKGBbT3BlbkNsYXddIOe9keWFszogJHtjdXJyZW50Q29uZmlnLm9wZW5jbGF3LmdhdGV3YXlVcmx9YCk7CiAgbG9nZ2VyLmluZm8oJ1tPcGVuQ2xhd10g5qih5byPOiDnp4HogYrlhajpgI/kvKAgKyDnvqTogYpA6Kem5Y+RICsg5ZG95Luk6YCP5LygJyk7CiAgbG9nZ2VyLmluZm8oJ1tPcGVuQ2xhd10gUVEgQ2hhbm5lbCDmj5Lku7bliJ3lp4vljJblrozmiJAnKTsKfTsKCmV4cG9ydCBjb25zdCBwbHVnaW5fb25tZXNzYWdlID0gYXN5bmMgKGN0eDogYW55LCBldmVudDogYW55KTogUHJvbWlzZTx2b2lkPiA9PiB7CiAgbGV0IHR5cGluZ1N0YXR1c09uID0gZmFsc2U7CiAgdHJ5IHsKICAgIGlmICghbG9nZ2VyKSByZXR1cm47CiAgICBpZiAoZXZlbnQucG9zdF90eXBlICE9PSAnbWVzc2FnZScpIHJldHVybjsKCiAgICBjb25zdCB1c2VySWQgPSBldmVudC51c2VyX2lkOwogICAgY29uc3Qgbmlja25hbWUgPSBldmVudC5zZW5kZXI/Lm5pY2tuYW1lIHx8ICfmnKrnn6UnOwogICAgY29uc3QgbWVzc2FnZVR5cGUgPSBldmVudC5tZXNzYWdlX3R5cGU7CiAgICBjb25zdCBncm91cElkID0gZXZlbnQuZ3JvdXBfaWQ7CgogICAgaWYgKCFib3RVc2VySWQgJiYgZXZlbnQuc2VsZl9pZCkgewogICAgICBib3RVc2VySWQgPSBldmVudC5zZWxmX2lkOwogICAgICBsb2dnZXIuaW5mbyhgW09wZW5DbGF3XSBCb3QgUVE6ICR7Ym90VXNlcklkfWApOwogICAgfQoKICAgIC8vIFVzZXIgd2hpdGVsaXN0CiAgICBjb25zdCBiZWhhdmlvciA9IGN1cnJlbnRDb25maWcuYmVoYXZpb3IgfHwge307CiAgICBjb25zdCB1c2VyV2hpdGVsaXN0ID0gYmVoYXZpb3IudXNlcldoaXRlbGlzdCB8fCBbXTsKICAgIGlmICh1c2VyV2hpdGVsaXN0Lmxlbmd0aCA+IDApIHsKICAgICAgaWYgKCF1c2VyV2hpdGVsaXN0LnNvbWUoKGlkKSA9PiBOdW1iZXIoaWQpID09PSBOdW1iZXIodXNlcklkKSkpIHJldHVybjsKICAgIH0KCiAgICBsZXQgc2hvdWxkSGFuZGxlID0gZmFsc2U7CgogICAgaWYgKG1lc3NhZ2VUeXBlID09PSAncHJpdmF0ZScpIHsKICAgICAgaWYgKGJlaGF2aW9yLnByaXZhdGVDaGF0ID09PSBmYWxzZSkgcmV0dXJuOwogICAgICBzaG91bGRIYW5kbGUgPSB0cnVlOwogICAgfSBlbHNlIGlmIChtZXNzYWdlVHlwZSA9PT0gJ2dyb3VwJykgewogICAgICBpZiAoIWdyb3VwSWQpIHJldHVybjsKICAgICAgY29uc3QgZ1doaXRlbGlzdCA9IGJlaGF2aW9yLmdyb3VwV2hpdGVsaXN0IHx8IFtdOwogICAgICBpZiAoZ1doaXRlbGlzdC5sZW5ndGggPiAwICYmICFnV2hpdGVsaXN0LnNvbWUoKGlkKSA9PiBOdW1iZXIoaWQpID09PSBOdW1iZXIoZ3JvdXBJZCkpKSByZXR1cm47CiAgICAgIGlmIChiZWhhdmlvci5ncm91cEF0T25seSAhPT0gZmFsc2UpIHsKICAgICAgICBjb25zdCBpc0F0Qm90ID0gZXZlbnQubWVzc2FnZT8uc29tZSgKICAgICAgICAgIChzZWc6IGFueSkgPT4gc2VnLnR5cGUgPT09ICdhdCcgJiYgU3RyaW5nKHNlZy5kYXRhPy5xcSkgPT09IFN0cmluZyhib3RVc2VySWQgfHwgZXZlbnQuc2VsZl9pZCkKICAgICAgICApOwogICAgICAgIGlmICghaXNBdEJvdCkgcmV0dXJuOwogICAgICB9CiAgICAgIHNob3VsZEhhbmRsZSA9IHRydWU7CiAgICB9CgogICAgaWYgKCFzaG91bGRIYW5kbGUpIHJldHVybjsKCiAgICBsYXN0Q3R4ID0gY3R4OwogICAgbGV0IHsgZXh0cmFjdGVkVGV4dCwgZXh0cmFjdGVkTWVkaWEgfSA9IGV4dHJhY3RNZXNzYWdlKGV2ZW50Lm1lc3NhZ2UgfHwgW10pOwogICAgbGV0IHRleHQgPSBleHRyYWN0ZWRUZXh0OwogICAgaWYgKCF0ZXh0ICYmIGV4dHJhY3RlZE1lZGlhLmxlbmd0aCA9PT0gMCkgcmV0dXJuOwoKICAgIGNvbnN0IHNlc3Npb25CYXNlID0gZ2V0U2Vzc2lvbkJhc2UobWVzc2FnZVR5cGUsIHVzZXJJZCwgZ3JvdXBJZCk7CgogICAgLy8gTG9jYWwgY29tbWFuZHMKICAgIGlmICh0ZXh0Py5zdGFydHNXaXRoKCcvJykpIHsKICAgICAgY29uc3Qgc3BhY2VJZHggPSB0ZXh0LmluZGV4T2YoJyAnKTsKICAgICAgY29uc3QgY21kID0gKHNwYWNlSWR4ID4gMCA/IHRleHQuc2xpY2UoMCwgc3BhY2VJZHgpIDogdGV4dCkudG9Mb3dlckNhc2UoKTsKICAgICAgY29uc3QgYXJncyA9IHNwYWNlSWR4ID4gMCA/IHRleHQuc2xpY2Uoc3BhY2VJZHggKyAxKS50cmltKCkgOiAnJzsKCiAgICAgIGlmIChMT0NBTF9DT01NQU5EU1tjbWRdKSB7CiAgICAgICAgbG9nZ2VyLmluZm8oYFtPcGVuQ2xhd10g5pys5Zyw5ZG95LukOiAke2NtZH0gZnJvbSAke25pY2tuYW1lfSgke3VzZXJJZH0pYCk7CiAgICAgICAgY29uc3QgcmVzdWx0ID0gTE9DQUxfQ09NTUFORFNbY21kXShzZXNzaW9uQmFzZSwgdXNlcklkLCBuaWNrbmFtZSwgbWVzc2FnZVR5cGUsIGdyb3VwSWQsIGFyZ3MpOwogICAgICAgIGlmIChyZXN1bHQpIHsKICAgICAgICAgIGF3YWl0IHNlbmRSZXBseShjdHgsIG1lc3NhZ2VUeXBlLCBncm91cElkLCB1c2VySWQsIHJlc3VsdCk7CiAgICAgICAgICByZXR1cm47CiAgICAgICAgfQogICAgICB9CiAgICB9CgogICAgY29uc3QgZGVib3VuY2VNc1JhdyA9IGN1cnJlbnRDb25maWcuYmVoYXZpb3IuZGVib3VuY2VNczsKICAgIGNvbnN0IGRlYm91bmNlTXMgPSBOdW1iZXIuaXNGaW5pdGUoZGVib3VuY2VNc1JhdykgPyBkZWJvdW5jZU1zUmF3IDogMjAwMDsKICAgIGlmIChkZWJvdW5jZU1zID4gMCAmJiAhKHRleHQgJiYgdGV4dC5zdGFydHNXaXRoKCcvJykpKSB7CiAgICAgIGNvbnN0IG1lcmdlZCA9IGF3YWl0IGRlYm91bmNlTWVzc2FnZShzZXNzaW9uQmFzZSwgdGV4dCB8fCAnJywgZXh0cmFjdGVkTWVkaWEsIGRlYm91bmNlTXMpOwogICAgICBpZiAoIW1lcmdlZCkgcmV0dXJuOwogICAgICBleHRyYWN0ZWRUZXh0ID0gbWVyZ2VkLnRleHQ7CiAgICAgIGV4dHJhY3RlZE1lZGlhID0gbWVyZ2VkLm1lZGlhOwogICAgICB0ZXh0ID0gZXh0cmFjdGVkVGV4dDsKICAgICAgaWYgKCF0ZXh0ICYmIGV4dHJhY3RlZE1lZGlhLmxlbmd0aCA9PT0gMCkgcmV0dXJuOwogICAgfQoKICAgIC8vIEJ1aWxkIG1lc3NhZ2UKICAgIGxldCBvcGVuY2xhd01lc3NhZ2UgPSB0ZXh0IHx8ICcnOwogICAgaWYgKGV4dHJhY3RlZE1lZGlhLmxlbmd0aCA+IDApIHsKICAgICAgY29uc3Qgc2F2ZWRNZWRpYSA9IGF3YWl0IHNhdmVNZWRpYVRvQ2FjaGUoZXh0cmFjdGVkTWVkaWEsIGN0eCk7CiAgICAgIGlmIChzYXZlZE1lZGlhLmxlbmd0aCA+IDApIHsKICAgICAgICBjb25zdCBtZWRpYUluZm8gPSBzYXZlZE1lZGlhLm1hcCgobSkgPT4gewogICAgICAgICAgaWYgKG0ucGF0aCkgewogICAgICAgICAgICBpZiAobS50eXBlID09PSAnaW1hZ2UnKSByZXR1cm4gYFvnlKjmiLflj5HpgIHkuoblm77niYc6ICR7bS5wYXRofV1gOwogICAgICAgICAgICBpZiAobS50eXBlID09PSAnZmlsZScpIHJldHVybiBgW+eUqOaIt+WPkemAgeS6huaWh+S7tuOAjCR7bS5uYW1lfeOAjTogJHttLnBhdGh9XWA7CiAgICAgICAgICAgIGlmIChtLnR5cGUgPT09ICd2b2ljZScpIHJldHVybiBgW+eUqOaIt+WPkemAgeS6huivremfszogJHttLnBhdGh9XWA7CiAgICAgICAgICAgIGlmIChtLnR5cGUgPT09ICd2aWRlbycpIHJldHVybiBgW+eUqOaIt+WPkemAgeS6huinhumikTogJHttLnBhdGh9XWA7CiAgICAgICAgICAgIHJldHVybiBgW+eUqOaIt+WPkemAgeS6hiR7bS50eXBlfTogJHttLnBhdGh9XWA7CiAgICAgICAgICB9CiAgICAgICAgICByZXR1cm4gYFvnlKjmiLflj5HpgIHkuoYke20udHlwZX06ICR7bS51cmx9XWA7CiAgICAgICAgfSkuam9pbignXG4nKTsKICAgICAgICBvcGVuY2xhd01lc3NhZ2UgPSBvcGVuY2xhd01lc3NhZ2UgPyBgJHtvcGVuY2xhd01lc3NhZ2V9XG5cbiR7bWVkaWFJbmZvfWAgOiBtZWRpYUluZm87CiAgICAgIH0KICAgIH0KCiAgICBsb2dnZXIuaW5mbygKICAgICAgYFtPcGVuQ2xhd10gJHttZXNzYWdlVHlwZSA9PT0gJ3ByaXZhdGUnID8gJ+engeiBiicgOiBg576kJHtncm91cElkfWB9ICR7bmlja25hbWV9KCR7dXNlcklkfSk6ICR7b3BlbmNsYXdNZXNzYWdlLnNsaWNlKDAsIDUwKX1gCiAgICApOwoKICAgIGlmIChtZXNzYWdlVHlwZSA9PT0gJ3ByaXZhdGUnKSB7CiAgICAgIHR5cGluZ1N0YXR1c09uID0gdHJ1ZTsKICAgICAgYXdhaXQgc2V0VHlwaW5nU3RhdHVzKGN0eCwgdXNlcklkLCB0cnVlKTsKICAgIH0KCiAgICAvLyBTZW5kIHZpYSBHYXRld2F5IFJQQyArIGV2ZW50IGxpc3RlbmVyIChub24tc3RyZWFtaW5nKQogICAgY29uc3Qgc2Vzc2lvbktleSA9IGdldFNlc3Npb25LZXkoc2Vzc2lvbkJhc2UpOwogICAgY29uc3QgcnVuSWQgPSByYW5kb21VVUlEKCk7CiAgICBjb25zdCBydW5TdGFydGVkQXRNcyA9IERhdGUubm93KCk7CgogICAgbGV0IGd3OiBHYXRld2F5Q2xpZW50IHwgbnVsbCA9IG51bGw7CiAgICBsZXQgd2FpdFJ1bklkID0gcnVuSWQ7CiAgICB0cnkgewogICAgICBndyA9IGF3YWl0IGdldEdhdGV3YXkoKTsKICAgICAgY29uc3QgZ3dDbGllbnQgPSBndzsKCiAgICAgIC8vIOaMiSBydW5JZCDnm5HlkKwgY2hhdCDkuovku7bvvIzpgb/lhY3lpJrkuKrkvJror53lubblj5Hml7blhajlsYAgaGFuZGxlciDooqvopobnm5YKICAgICAgY29uc3QgcmVwbHlQcm9taXNlID0gbmV3IFByb21pc2U8c3RyaW5nIHwgbnVsbD4oKHJlc29sdmUpID0+IHsKICAgICAgICBsZXQgc2V0dGxlZCA9IGZhbHNlOwogICAgICAgIGxldCByZWNvdmVyaW5nID0gZmFsc2U7CiAgICAgICAgbGV0IGxhdGVzdFNlc3Npb25LZXkgPSBzZXNzaW9uS2V5OwoKICAgICAgICBjb25zdCBzYWZlUmVzb2x2ZSA9ICh2YWx1ZTogc3RyaW5nIHwgbnVsbCkgPT4gewogICAgICAgICAgaWYgKHNldHRsZWQpIHJldHVybjsKICAgICAgICAgIHNldHRsZWQgPSB0cnVlOwogICAgICAgICAgY2xlYW51cCgpOwogICAgICAgICAgcmVzb2x2ZSh2YWx1ZSk7CiAgICAgICAgfTsKCiAgICAgICAgY29uc3QgcmVjb3ZlckZyb21IaXN0b3J5ID0gYXN5bmMgKAogICAgICAgICAgcmVhc29uOiBzdHJpbmcsCiAgICAgICAgICBmYWxsYmFjazogc3RyaW5nIHwgbnVsbCwKICAgICAgICAgIG1heEF0dGVtcHRzID0gNDAsCiAgICAgICAgICBpbnRlcnZhbE1zID0gNTAwCiAgICAgICAgKSA9PiB7CiAgICAgICAgICBpZiAoc2V0dGxlZCB8fCByZWNvdmVyaW5nKSByZXR1cm47CiAgICAgICAgICByZWNvdmVyaW5nID0gdHJ1ZTsKICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgIGNvbnN0IGhpc3RvcnlUZXh0ID0gYXdhaXQgcmVzb2x2ZVJlcGx5RnJvbUhpc3RvcnkoZ3dDbGllbnQsIGxhdGVzdFNlc3Npb25LZXksIHJ1blN0YXJ0ZWRBdE1zLCB7CiAgICAgICAgICAgICAgbWF4QXR0ZW1wdHMsCiAgICAgICAgICAgICAgaW50ZXJ2YWxNcywKICAgICAgICAgICAgICBzaG91bGRTdG9wOiAoKSA9PiBzZXR0bGVkLAogICAgICAgICAgICB9KTsKICAgICAgICAgICAgaWYgKHNldHRsZWQpIHJldHVybjsKICAgICAgICAgICAgaWYgKGhpc3RvcnlUZXh0KSB7CiAgICAgICAgICAgICAgbG9nZ2VyLmluZm8oYFtPcGVuQ2xhd10gJHtyZWFzb25977yM5bey6YCa6L+HIGNoYXQuaGlzdG9yeSDlm57loavlm57lpI1gKTsKICAgICAgICAgICAgICBzYWZlUmVzb2x2ZShoaXN0b3J5VGV4dCk7CiAgICAgICAgICAgICAgcmV0dXJuOwogICAgICAgICAgICB9CiAgICAgICAgICAgIHNhZmVSZXNvbHZlKGZhbGxiYWNrKTsKICAgICAgICAgIH0gZmluYWxseSB7CiAgICAgICAgICAgIHJlY292ZXJpbmcgPSBmYWxzZTsKICAgICAgICAgIH0KICAgICAgICB9OwoKICAgICAgICBjb25zdCB0aW1lb3V0ID0gc2V0VGltZW91dCgoKSA9PiB7CiAgICAgICAgICBsb2dnZXIud2FybignW09wZW5DbGF3XSDnrYnlvoUgZmluYWwg6LaF5pe277yM5bCd6K+V6YCa6L+HIGNoYXQuaGlzdG9yeSDooaXmi4nlm57lpI0nKTsKICAgICAgICAgIHZvaWQgcmVjb3ZlckZyb21IaXN0b3J5KCfnrYnlvoUgZmluYWwg6LaF5pe2JywgbnVsbCwgMTIsIDUwMCk7CiAgICAgICAgfSwgMTgwMDAwKTsKCiAgICAgICAgY29uc3QgY2xlYW51cCA9ICgpID0+IHsKICAgICAgICAgIGNsZWFyVGltZW91dCh0aW1lb3V0KTsKICAgICAgICAgIGd3Q2xpZW50LmNoYXRXYWl0ZXJzLmRlbGV0ZSh3YWl0UnVuSWQpOwogICAgICAgIH07CgogICAgICAgIGd3Q2xpZW50LmNoYXRXYWl0ZXJzLnNldCh3YWl0UnVuSWQsIHsgaGFuZGxlcjogKHBheWxvYWQ6IGFueSkgPT4gewogICAgICAgICAgaWYgKHNldHRsZWQpIHJldHVybjsKICAgICAgICAgIGlmICghcGF5bG9hZCkgcmV0dXJuOwogICAgICAgICAgaWYgKHR5cGVvZiBwYXlsb2FkLnNlc3Npb25LZXkgPT09ICdzdHJpbmcnICYmIHBheWxvYWQuc2Vzc2lvbktleS50cmltKCkpIHsKICAgICAgICAgICAgbGF0ZXN0U2Vzc2lvbktleSA9IHBheWxvYWQuc2Vzc2lvbktleS50cmltKCk7CiAgICAgICAgICB9CiAgICAgICAgICBsb2dnZXIuaW5mbyhgW09wZW5DbGF3XSBjaGF0IGV2ZW50OiBzdGF0ZT0ke3BheWxvYWQuc3RhdGV9IHNlc3Npb249JHtwYXlsb2FkLnNlc3Npb25LZXl9IHJ1bj0ke3BheWxvYWQucnVuSWQ/LnNsaWNlKDAsIDgpfWApOwoKICAgICAgICAgIGlmIChwYXlsb2FkLnN0YXRlID09PSAnZmluYWwnKSB7CiAgICAgICAgICAgIGNvbnN0IGRpcmVjdFRleHQgPSBleHRyYWN0Q29udGVudFRleHQocGF5bG9hZC5tZXNzYWdlKS50cmltKCk7CiAgICAgICAgICAgIGlmIChkaXJlY3RUZXh0KSB7CiAgICAgICAgICAgICAgc2FmZVJlc29sdmUoZGlyZWN0VGV4dCk7CiAgICAgICAgICAgICAgcmV0dXJuOwogICAgICAgICAgICB9CiAgICAgICAgICAgIHZvaWQgcmVjb3ZlckZyb21IaXN0b3J5KCdmaW5hbCDluKfml6DmlofmnKwnLCBudWxsLCAyMCwgNDAwKTsKICAgICAgICAgICAgcmV0dXJuOwogICAgICAgICAgfQoKICAgICAgICAgIGlmIChwYXlsb2FkLnN0YXRlID09PSAnYWJvcnRlZCcpIHsKICAgICAgICAgICAgbG9nZ2VyLndhcm4oJ1tPcGVuQ2xhd10g5pS25YiwIGFib3J0ZWQg5LqL5Lu277yM562J5b6F5ZCO57ut6YeN6K+V57uT5p6cJyk7CiAgICAgICAgICAgIHZvaWQgcmVjb3ZlckZyb21IaXN0b3J5KAogICAgICAgICAgICAgICfmlLbliLAgYWJvcnRlZCDkuovku7YnLAogICAgICAgICAgICAgICfimqDvuI8g5pys5qyh6L+Q6KGM6KKr5Lit5pat77yM5pyq5ou/5Yiw5pyA57uI5Zue5aSN77yM6K+356iN5ZCO6YeN6K+V44CCJywKICAgICAgICAgICAgICA0NSwKICAgICAgICAgICAgICA1MDAKICAgICAgICAgICAgKTsKICAgICAgICAgICAgcmV0dXJuOwogICAgICAgICAgfQoKICAgICAgICAgIGlmIChwYXlsb2FkLnN0YXRlID09PSAnZXJyb3InKSB7CiAgICAgICAgICAgIGNvbnN0IGVycm9yTWVzc2FnZSA9IFN0cmluZyhwYXlsb2FkLmVycm9yTWVzc2FnZSB8fCAn5aSE55CG5Ye66ZSZJyk7CiAgICAgICAgICAgIGlmIChpc1JlY292ZXJhYmxlR2F0ZXdheUVycm9yKGVycm9yTWVzc2FnZSkpIHsKICAgICAgICAgICAgICBsb2dnZXIud2FybihgW09wZW5DbGF3XSDmlLbliLDlj6/mgaLlpI3plJnor686ICR7ZXJyb3JNZXNzYWdlfe+8jOetieW+heWQjue7remHjeivlee7k+aenGApOwogICAgICAgICAgICAgIHZvaWQgcmVjb3ZlckZyb21IaXN0b3J5KAogICAgICAgICAgICAgICAgYOaUtuWIsCBlcnJvcigke2Vycm9yTWVzc2FnZX0pYCwKICAgICAgICAgICAgICAgICfimqDvuI8g5pys5qyh6L+Q6KGM6KKr5Lit5pat77yM5pyq5ou/5Yiw5pyA57uI5Zue5aSN77yM6K+356iN5ZCO6YeN6K+V44CCJywKICAgICAgICAgICAgICAgIDQ1LAogICAgICAgICAgICAgICAgNTAwCiAgICAgICAgICAgICAgKTsKICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICBzYWZlUmVzb2x2ZShg4p2MICR7ZXJyb3JNZXNzYWdlfWApOwogICAgICAgICAgICB9CiAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgIH0KICAgICAgICB9fSk7CiAgICAgIH0pOwoKICAgICAgLy8gU2VuZCBtZXNzYWdlCiAgICAgIGNvbnN0IHNlbmRSZXN1bHQgPSBhd2FpdCBnd0NsaWVudC5yZXF1ZXN0KCdjaGF0LnNlbmQnLCB7CiAgICAgICAgc2Vzc2lvbktleSwKICAgICAgICBtZXNzYWdlOiBvcGVuY2xhd01lc3NhZ2UsCiAgICAgICAgaWRlbXBvdGVuY3lLZXk6IHJ1bklkLAogICAgICB9KTsKCiAgICAgIGxvZ2dlci5pbmZvKGBbT3BlbkNsYXddIGNoYXQuc2VuZCDlt7LmjqXlj5c6IHJ1bklkPSR7c2VuZFJlc3VsdD8ucnVuSWR9YCk7CiAgICAgIGNvbnN0IGFjdHVhbFJ1bklkID0gdHlwZW9mIHNlbmRSZXN1bHQ/LnJ1bklkID09PSAnc3RyaW5nJyAmJiBzZW5kUmVzdWx0LnJ1bklkID8gc2VuZFJlc3VsdC5ydW5JZCA6IHJ1bklkOwogICAgICBpZiAoYWN0dWFsUnVuSWQgIT09IHdhaXRSdW5JZCkgewogICAgICAgIGNvbnN0IHdhaXRlciA9IGd3Q2xpZW50LmNoYXRXYWl0ZXJzLmdldCh3YWl0UnVuSWQpOwogICAgICAgIGlmICh3YWl0ZXIpIHsKICAgICAgICAgIGd3Q2xpZW50LmNoYXRXYWl0ZXJzLmRlbGV0ZSh3YWl0UnVuSWQpOwogICAgICAgICAgd2FpdFJ1bklkID0gYWN0dWFsUnVuSWQ7CiAgICAgICAgICBnd0NsaWVudC5jaGF0V2FpdGVycy5zZXQod2FpdFJ1bklkLCB3YWl0ZXIpOwogICAgICAgIH0KICAgICAgICBsb2dnZXIud2FybigKICAgICAgICAgIGBbT3BlbkNsYXddIHJ1bklkIOmHjeaYoOWwhDogbG9jYWw9JHtydW5JZC5zbGljZSgwLCA4KX0gc2VydmVyPSR7YWN0dWFsUnVuSWQuc2xpY2UoMCwgOCl9YAogICAgICAgICk7CiAgICAgIH0KCiAgICAgIC8vIFdhaXQgZm9yIGZpbmFsIGV2ZW50CiAgICAgIGNvbnN0IHJlcGx5ID0gYXdhaXQgcmVwbHlQcm9taXNlOwoKICAgICAgaWYgKHJlcGx5KSB7CiAgICAgICAgY29uc3QgeyBpbWFnZXMsIGNsZWFuVGV4dCB9ID0gZXh0cmFjdEltYWdlc0Zyb21SZXBseShyZXBseSk7CiAgICAgICAgaWYgKGNsZWFuVGV4dCkgewogICAgICAgICAgYXdhaXQgc2VuZFJlcGx5KGN0eCwgbWVzc2FnZVR5cGUsIGdyb3VwSWQsIHVzZXJJZCwgY2xlYW5UZXh0KTsKICAgICAgICB9CiAgICAgICAgZm9yIChjb25zdCBpbWFnZVVybCBvZiBpbWFnZXMpIHsKICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgIGF3YWl0IHNlbmRJbWFnZU1zZyhjdHgsIG1lc3NhZ2VUeXBlLCBncm91cElkID8/IG51bGwsIHVzZXJJZCA/PyBudWxsLCBpbWFnZVVybCk7CiAgICAgICAgICB9IGNhdGNoIChlOiBhbnkpIHsKICAgICAgICAgICAgbG9nZ2VyPy53YXJuKGBbT3BlbkNsYXddIOWPkemAgeWbvueJh+Wksei0pTogJHtlLm1lc3NhZ2V9YCk7CiAgICAgICAgICB9CiAgICAgICAgfQogICAgICB9IGVsc2UgewogICAgICAgIGxvZ2dlci53YXJuKCdbT3BlbkNsYXddIOaXoOWbnuWkjeWGheWuue+8jOi/lOWbnuWFnOW6leaPkOekuicpOwogICAgICAgIGF3YWl0IHNlbmRSZXBseShjdHgsIG1lc3NhZ2VUeXBlLCBncm91cElkLCB1c2VySWQsICfimqDvuI8g5qih5Z6L5pyq6L+U5Zue5YaF5a6577yM6K+356iN5ZCO6YeN6K+V44CCJyk7CiAgICAgIH0KICAgIH0gY2F0Y2ggKGU6IGFueSkgewogICAgICBpZiAoZ3cgJiYgd2FpdFJ1bklkKSB7CiAgICAgICAgZ3cuY2hhdFdhaXRlcnMuZGVsZXRlKHdhaXRSdW5JZCk7CiAgICAgIH0KICAgICAgbG9nZ2VyLmVycm9yKGBbT3BlbkNsYXddIOWPkemAgeWksei0pTogJHtlLm1lc3NhZ2V9YCk7CiAgICAgIGlmIChnYXRld2F5Q2xpZW50KSB7CiAgICAgICAgZ2F0ZXdheUNsaWVudC5kaXNjb25uZWN0KCk7CiAgICAgICAgZ2F0ZXdheUNsaWVudCA9IG51bGw7CiAgICAgICAgcHVzaExpc3RlbmVyQXR0YWNoZWQgPSBmYWxzZTsKICAgICAgfQogICAgICB0cnkgewogICAgICAgIGNvbnN0IGNsaVBhdGggPSBjdXJyZW50Q29uZmlnLm9wZW5jbGF3LmNsaVBhdGggfHwgJy9yb290Ly5udm0vdmVyc2lvbnMvbm9kZS92MjIuMjIuMC9iaW4vb3BlbmNsYXcnOwogICAgICAgIGNvbnN0IHsgc3Rkb3V0LCBzdGRlcnIgfSA9IGF3YWl0IGV4ZWNGaWxlQXN5bmMoCiAgICAgICAgICBjbGlQYXRoLAogICAgICAgICAgWydhZ2VudCcsICctLXNlc3Npb24taWQnLCBzZXNzaW9uS2V5LCAnLS1tZXNzYWdlJywgb3BlbmNsYXdNZXNzYWdlXSwKICAgICAgICAgIHsKICAgICAgICAgICAgZW52OiB7IC4uLnByb2Nlc3MuZW52LCBPUEVOQ0xBV19UT0tFTjogY3VycmVudENvbmZpZy5vcGVuY2xhdy50b2tlbiB8fCAnJyB9LAogICAgICAgICAgICB0aW1lb3V0OiAxODAwMDAsCiAgICAgICAgICAgIG1heEJ1ZmZlcjogMTAyNCAqIDEwMjQsCiAgICAgICAgICB9CiAgICAgICAgKTsKICAgICAgICBjb25zdCBmYWxsYmFja091dHB1dCA9IFtzdGRvdXQsIHN0ZGVycl0uZmlsdGVyKEJvb2xlYW4pLmpvaW4oJ1xuJykudHJpbSgpOwogICAgICAgIGlmIChmYWxsYmFja091dHB1dCkgewogICAgICAgICAgYXdhaXQgc2VuZFJlcGx5KGN0eCwgbWVzc2FnZVR5cGUsIGdyb3VwSWQsIHVzZXJJZCwgZmFsbGJhY2tPdXRwdXQpOwogICAgICAgIH0KICAgICAgfSBjYXRjaCAoZTI6IGFueSkgewogICAgICAgIGF3YWl0IHNlbmRSZXBseShjdHgsIG1lc3NhZ2VUeXBlLCBncm91cElkLCB1c2VySWQsIGDlpITnkIblh7rplJk6ICR7KGUgYXMgRXJyb3IpLm1lc3NhZ2U/LnNsaWNlKDAsIDEwMCl9YCk7CiAgICAgIH0KICAgIH0KICB9IGNhdGNoIChvdXRlckVycjogYW55KSB7CiAgICBsb2dnZXI/LmVycm9yKGBbT3BlbkNsYXddIOacquaNleiOt+W8guW4uDogJHtvdXRlckVyci5tZXNzYWdlfVxuJHtvdXRlckVyci5zdGFja31gKTsKICB9IGZpbmFsbHkgewogICAgaWYgKHR5cGluZ1N0YXR1c09uKSB7CiAgICAgIGF3YWl0IHNldFR5cGluZ1N0YXR1cyhjdHgsIGV2ZW50Py51c2VyX2lkLCBmYWxzZSk7CiAgICB9CiAgfQp9OwoKZXhwb3J0IGNvbnN0IHBsdWdpbl9jbGVhbnVwID0gYXN5bmMgKCk6IFByb21pc2U8dm9pZD4gPT4gewogIGZvciAoY29uc3QgWywgZW50cnldIG9mIGRlYm91bmNlQnVmZmVycykgewogICAgY2xlYXJUaW1lb3V0KGVudHJ5LnRpbWVyKTsKICB9CiAgZGVib3VuY2VCdWZmZXJzLmNsZWFyKCk7CiAgaWYgKGdhdGV3YXlDbGllbnQpIHsKICAgIGdhdGV3YXlDbGllbnQuZGlzY29ubmVjdCgpOwogICAgZ2F0ZXdheUNsaWVudCA9IG51bGw7CiAgICBwdXNoTGlzdGVuZXJBdHRhY2hlZCA9IGZhbHNlOwogIH0KICBwdXNoTGlzdGVuZXJBdHRhY2hlZCA9IGZhbHNlOwogIGxvZ2dlcj8uaW5mbygnW09wZW5DbGF3XSBRUSBDaGFubmVsIOaPkuS7tua4heeQhuWujOaIkCcpOwp9OwoKLy8gPT09PT09PT09PSBDb25maWcgSG9va3MgPT09PT09PT09PQoKLy8gRmxhdHRlbiBuZXN0ZWQgY29uZmlnIHRvIGZsYXQga2V5cyBmb3IgV2ViVUkKZnVuY3Rpb24gZmxhdHRlbkNvbmZpZyhjZmc6IFBsdWdpbkNvbmZpZyk6IFJlY29yZDxzdHJpbmcsIGFueT4gewogIGNvbnN0IGJlaGF2aW9yID0gY2ZnLmJlaGF2aW9yIHx8IHt9OwogIHJldHVybiB7CiAgICB0b2tlbjogY2ZnLm9wZW5jbGF3Py50b2tlbiA/PyAnJywKICAgIGdhdGV3YXlVcmw6IGNmZy5vcGVuY2xhdz8uZ2F0ZXdheVVybCA/PyAnd3M6Ly8xMjcuMC4wLjE6MTg3ODknLAogICAgY2xpUGF0aDogY2ZnLm9wZW5jbGF3Py5jbGlQYXRoID8/ICcnLAogICAgcHJpdmF0ZUNoYXQ6IGJlaGF2aW9yLnByaXZhdGVDaGF0ID8/IHRydWUsCiAgICBncm91cEF0T25seTogYmVoYXZpb3IuZ3JvdXBBdE9ubHkgPz8gdHJ1ZSwKICAgIHVzZXJXaGl0ZWxpc3Q6IChiZWhhdmlvci51c2VyV2hpdGVsaXN0IHx8IFtdKS5qb2luKCcsJyksCiAgICBncm91cFdoaXRlbGlzdDogKGJlaGF2aW9yLmdyb3VwV2hpdGVsaXN0IHx8IFtdKS5qb2luKCcsJyksCiAgICBkZWJvdW5jZU1zOiBiZWhhdmlvci5kZWJvdW5jZU1zID8/IDIwMDAsCiAgICBncm91cFNlc3Npb25Nb2RlOiBiZWhhdmlvci5ncm91cFNlc3Npb25Nb2RlID8/ICd1c2VyJywKICB9Owp9CgovLyBVbmZsYXR0ZW4gZmxhdCBXZWJVSSBjb25maWcgYmFjayB0byBuZXN0ZWQgc3RydWN0dXJlCmZ1bmN0aW9uIHVuZmxhdHRlbkNvbmZpZyhmbGF0OiBSZWNvcmQ8c3RyaW5nLCBhbnk+KTogUGx1Z2luQ29uZmlnIHsKICBjb25zdCBwYXJzZURlYm91bmNlTXMgPSAodmFsdWU6IGFueSk6IG51bWJlciA9PiB7CiAgICBjb25zdCBwYXJzZWQgPSBOdW1iZXIodmFsdWUpOwogICAgaWYgKE51bWJlci5pc0Zpbml0ZShwYXJzZWQpICYmIHBhcnNlZCA+PSAwKSByZXR1cm4gcGFyc2VkOwogICAgcmV0dXJuIDIwMDA7CiAgfTsKICBjb25zdCBwYXJzZU51bUxpc3QgPSAoczogYW55KTogbnVtYmVyW10gPT4gewogICAgaWYgKEFycmF5LmlzQXJyYXkocykpIHJldHVybiBzLm1hcChOdW1iZXIpLmZpbHRlcihCb29sZWFuKTsKICAgIGlmICh0eXBlb2YgcyA9PT0gJ3N0cmluZycgJiYgcy50cmltKCkpIHJldHVybiBzLnNwbGl0KCcsJykubWFwKCh4OiBzdHJpbmcpID0+IE51bWJlcih4LnRyaW0oKSkpLmZpbHRlcihCb29sZWFuKTsKICAgIHJldHVybiBbXTsKICB9OwogIHJldHVybiB7CiAgICBvcGVuY2xhdzogewogICAgICB0b2tlbjogZmxhdC50b2tlbiA/PyAnJywKICAgICAgZ2F0ZXdheVVybDogZmxhdC5nYXRld2F5VXJsID8/ICd3czovLzEyNy4wLjAuMToxODc4OScsCiAgICAgIGNsaVBhdGg6IGZsYXQuY2xpUGF0aCA/PyAnL3Jvb3QvLm52bS92ZXJzaW9ucy9ub2RlL3YyMi4yMi4wL2Jpbi9vcGVuY2xhdycsCiAgICB9LAogICAgYmVoYXZpb3I6IHsKICAgICAgcHJpdmF0ZUNoYXQ6IGZsYXQucHJpdmF0ZUNoYXQgIT09IGZhbHNlLAogICAgICBncm91cEF0T25seTogZmxhdC5ncm91cEF0T25seSAhPT0gZmFsc2UsCiAgICAgIHVzZXJXaGl0ZWxpc3Q6IHBhcnNlTnVtTGlzdChmbGF0LnVzZXJXaGl0ZWxpc3QpLAogICAgICBncm91cFdoaXRlbGlzdDogcGFyc2VOdW1MaXN0KGZsYXQuZ3JvdXBXaGl0ZWxpc3QpLAogICAgICBkZWJvdW5jZU1zOiBwYXJzZURlYm91bmNlTXMoZmxhdC5kZWJvdW5jZU1zKSwKICAgICAgZ3JvdXBTZXNzaW9uTW9kZTogZmxhdC5ncm91cFNlc3Npb25Nb2RlID09PSAnc2hhcmVkJyA/ICdzaGFyZWQnIDogJ3VzZXInLAogICAgfSwKICB9Owp9CgpleHBvcnQgY29uc3QgcGx1Z2luX2dldF9jb25maWcgPSBhc3luYyAoKSA9PiB7CiAgY29uc3QgZmxhdCA9IGZsYXR0ZW5Db25maWcoY3VycmVudENvbmZpZyk7CiAgaWYgKGZsYXQudG9rZW4pIHsKICAgIGNvbnN0IHQgPSBTdHJpbmcoZmxhdC50b2tlbik7CiAgICBmbGF0LnRva2VuID0gdC5sZW5ndGggPiA4ID8gYCR7dC5zbGljZSgwLCA0KX0qKioqJHt0LnNsaWNlKC00KX1gIDogJyoqKionOwogIH0KICByZXR1cm4gZmxhdDsKfTsKCmV4cG9ydCBjb25zdCBwbHVnaW5fc2V0X2NvbmZpZyA9IGFzeW5jIChjdHg6IGFueSwgY29uZmlnOiBhbnkpOiBQcm9taXNlPHZvaWQ+ID0+IHsKICBjb25zdCBnZXQgPSAocGxhaW5LZXk6IHN0cmluZywgZG90dGVkS2V5OiBzdHJpbmcpOiBhbnkgPT4gewogICAgaWYgKGNvbmZpZz8uW3BsYWluS2V5XSAhPT0gdW5kZWZpbmVkKSByZXR1cm4gY29uZmlnW3BsYWluS2V5XTsKICAgIHJldHVybiBjb25maWc/Lltkb3R0ZWRLZXldOwogIH07CgogIGNvbnN0IG1heWJlVG9rZW4gPSBnZXQoJ3Rva2VuJywgJ29wZW5jbGF3LnRva2VuJyk7CiAgY29uc3QgbWF5YmVHYXRld2F5VXJsID0gZ2V0KCdnYXRld2F5VXJsJywgJ29wZW5jbGF3LmdhdGV3YXlVcmwnKTsKICBjb25zdCBtYXliZUNsaVBhdGggPSBnZXQoJ2NsaVBhdGgnLCAnb3BlbmNsYXcuY2xpUGF0aCcpOwogIGNvbnN0IG1heWJlUHJpdmF0ZUNoYXQgPSBnZXQoJ3ByaXZhdGVDaGF0JywgJ2JlaGF2aW9yLnByaXZhdGVDaGF0Jyk7CiAgY29uc3QgbWF5YmVHcm91cEF0T25seSA9IGdldCgnZ3JvdXBBdE9ubHknLCAnYmVoYXZpb3IuZ3JvdXBBdE9ubHknKTsKICBjb25zdCBtYXliZVVzZXJXaGl0ZWxpc3QgPSBnZXQoJ3VzZXJXaGl0ZWxpc3QnLCAnYmVoYXZpb3IudXNlcldoaXRlbGlzdCcpOwogIGNvbnN0IG1heWJlR3JvdXBXaGl0ZWxpc3QgPSBnZXQoJ2dyb3VwV2hpdGVsaXN0JywgJ2JlaGF2aW9yLmdyb3VwV2hpdGVsaXN0Jyk7CiAgY29uc3QgbWF5YmVEZWJvdW5jZU1zID0gZ2V0KCdkZWJvdW5jZU1zJywgJ2JlaGF2aW9yLmRlYm91bmNlTXMnKTsKICBjb25zdCBtYXliZUdyb3VwU2Vzc2lvbk1vZGUgPSBnZXQoJ2dyb3VwU2Vzc2lvbk1vZGUnLCAnYmVoYXZpb3IuZ3JvdXBTZXNzaW9uTW9kZScpOwoKICBpZiAoCiAgICBtYXliZVRva2VuICE9PSB1bmRlZmluZWQgfHwKICAgIG1heWJlR2F0ZXdheVVybCAhPT0gdW5kZWZpbmVkIHx8CiAgICBtYXliZUNsaVBhdGggIT09IHVuZGVmaW5lZCB8fAogICAgbWF5YmVQcml2YXRlQ2hhdCAhPT0gdW5kZWZpbmVkIHx8CiAgICBtYXliZUdyb3VwQXRPbmx5ICE9PSB1bmRlZmluZWQgfHwKICAgIG1heWJlVXNlcldoaXRlbGlzdCAhPT0gdW5kZWZpbmVkIHx8CiAgICBtYXliZUdyb3VwV2hpdGVsaXN0ICE9PSB1bmRlZmluZWQgfHwKICAgIG1heWJlRGVib3VuY2VNcyAhPT0gdW5kZWZpbmVkIHx8CiAgICBtYXliZUdyb3VwU2Vzc2lvbk1vZGUgIT09IHVuZGVmaW5lZAogICkgewogICAgY29uc3QgZmxhdENvbmZpZyA9IHsKICAgICAgdG9rZW46IHR5cGVvZiBtYXliZVRva2VuID09PSAnc3RyaW5nJyAmJiBtYXliZVRva2VuLmluY2x1ZGVzKCcqKioqJykKICAgICAgICA/IGN1cnJlbnRDb25maWcub3BlbmNsYXcudG9rZW4KICAgICAgICA6IChtYXliZVRva2VuID8/IGN1cnJlbnRDb25maWcub3BlbmNsYXcudG9rZW4pLAogICAgICBnYXRld2F5VXJsOiBtYXliZUdhdGV3YXlVcmwgPz8gY3VycmVudENvbmZpZy5vcGVuY2xhdy5nYXRld2F5VXJsLAogICAgICBjbGlQYXRoOiBtYXliZUNsaVBhdGggPz8gY3VycmVudENvbmZpZy5vcGVuY2xhdy5jbGlQYXRoLAogICAgICBwcml2YXRlQ2hhdDogbWF5YmVQcml2YXRlQ2hhdCA/PyBjdXJyZW50Q29uZmlnLmJlaGF2aW9yLnByaXZhdGVDaGF0LAogICAgICBncm91cEF0T25seTogbWF5YmVHcm91cEF0T25seSA/PyBjdXJyZW50Q29uZmlnLmJlaGF2aW9yLmdyb3VwQXRPbmx5LAogICAgICB1c2VyV2hpdGVsaXN0OiBtYXliZVVzZXJXaGl0ZWxpc3QgPz8gY3VycmVudENvbmZpZy5iZWhhdmlvci51c2VyV2hpdGVsaXN0LmpvaW4oJywnKSwKICAgICAgZ3JvdXBXaGl0ZWxpc3Q6IG1heWJlR3JvdXBXaGl0ZWxpc3QgPz8gY3VycmVudENvbmZpZy5iZWhhdmlvci5ncm91cFdoaXRlbGlzdC5qb2luKCcsJyksCiAgICAgIGRlYm91bmNlTXM6IG1heWJlRGVib3VuY2VNcyA/PyBjdXJyZW50Q29uZmlnLmJlaGF2aW9yLmRlYm91bmNlTXMsCiAgICAgIGdyb3VwU2Vzc2lvbk1vZGU6IG1heWJlR3JvdXBTZXNzaW9uTW9kZSA/PyBjdXJyZW50Q29uZmlnLmJlaGF2aW9yLmdyb3VwU2Vzc2lvbk1vZGUsCiAgICB9OwogICAgY3VycmVudENvbmZpZyA9IHVuZmxhdHRlbkNvbmZpZyhmbGF0Q29uZmlnKTsKICB9IGVsc2UgewogICAgY3VycmVudENvbmZpZyA9IGRlZXBNZXJnZShjdXJyZW50Q29uZmlnLCBjb25maWcpOwogIH0KICBpZiAoZ2F0ZXdheUNsaWVudCkgewogICAgZ2F0ZXdheUNsaWVudC5kaXNjb25uZWN0KCk7CiAgICBnYXRld2F5Q2xpZW50ID0gbnVsbDsKICB9CiAgaWYgKGN0eD8uY29uZmlnUGF0aCkgewogICAgdHJ5IHsKICAgICAgY29uc3QgZGlyID0gcGF0aC5kaXJuYW1lKGN0eC5jb25maWdQYXRoKTsKICAgICAgaWYgKCFmcy5leGlzdHNTeW5jKGRpcikpIGZzLm1rZGlyU3luYyhkaXIsIHsgcmVjdXJzaXZlOiB0cnVlIH0pOwogICAgICBmcy53cml0ZUZpbGVTeW5jKGN0eC5jb25maWdQYXRoLCBKU09OLnN0cmluZ2lmeShjdXJyZW50Q29uZmlnLCBudWxsLCAyKSwgJ3V0Zi04Jyk7CiAgICB9IGNhdGNoIChlOiBhbnkpIHsKICAgICAgbG9nZ2VyPy5lcnJvcignW09wZW5DbGF3XSDkv53lrZjphY3nva7lpLHotKU6ICcgKyBlLm1lc3NhZ2UpOwogICAgfQogIH0KfTsKCi8vID09PT09PT09PT0gVXRpbHMgPT09PT09PT09PQoKZnVuY3Rpb24gZGVlcE1lcmdlKHRhcmdldDogYW55LCBzb3VyY2U6IGFueSk6IGFueSB7CiAgY29uc3QgcmVzdWx0ID0geyAuLi50YXJnZXQgfTsKICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3Qua2V5cyhzb3VyY2UpKSB7CiAgICBpZiAoc291cmNlW2tleV0gJiYgdHlwZW9mIHNvdXJjZVtrZXldID09PSAnb2JqZWN0JyAmJiAhQXJyYXkuaXNBcnJheShzb3VyY2Vba2V5XSkpIHsKICAgICAgcmVzdWx0W2tleV0gPSBkZWVwTWVyZ2UodGFyZ2V0W2tleV0gfHwge30sIHNvdXJjZVtrZXldKTsKICAgIH0gZWxzZSB7CiAgICAgIHJlc3VsdFtrZXldID0gc291cmNlW2tleV07CiAgICB9CiAgfQogIHJldHVybiByZXN1bHQ7Cn0K", import.meta.url).pathname;
  logger.info("[OpenClaw] QQ Channel 插件初始化中...");
  try {
    if (configPath && fs.existsSync(configPath)) {
      const saved = JSON.parse(fs.readFileSync(configPath, "utf-8"));
      currentConfig = deepMerge(currentConfig, saved);
      logger.info("[OpenClaw] 已加载保存的配置");
    }
  } catch (e) {
    logger.warn("[OpenClaw] 加载配置失败: " + e.message);
  }
  plugin_config_ui = buildConfigSchema();
  try {
    await getGateway();
    logger.info("[OpenClaw] Gateway 连接就绪");
  } catch (e) {
    logger.error(`[OpenClaw] Gateway 预连接失败: ${e.message}（将在首次消息时重试）`);
  }
  logger.info(`[OpenClaw] 网关: ${currentConfig.openclaw.gatewayUrl}`);
  logger.info("[OpenClaw] 模式: 私聊全透传 + 群聊@触发 + 命令透传");
  logger.info("[OpenClaw] QQ Channel 插件初始化完成");
};
const plugin_onmessage = async (ctx, event) => {
  let typingStatusOn = false;
  try {
    if (!logger) return;
    if (event.post_type !== "message") return;
    const userId = event.user_id;
    const nickname = event.sender?.nickname || "未知";
    const messageType = event.message_type;
    const groupId = event.group_id;
    if (!botUserId && event.self_id) {
      botUserId = event.self_id;
      logger.info(`[OpenClaw] Bot QQ: ${botUserId}`);
    }
    const behavior = currentConfig.behavior || {};
    const userWhitelist = behavior.userWhitelist || [];
    if (userWhitelist.length > 0) {
      if (!userWhitelist.some((id) => Number(id) === Number(userId))) return;
    }
    let shouldHandle = false;
    if (messageType === "private") {
      if (behavior.privateChat === false) return;
      shouldHandle = true;
    } else if (messageType === "group") {
      if (!groupId) return;
      const gWhitelist = behavior.groupWhitelist || [];
      if (gWhitelist.length > 0 && !gWhitelist.some((id) => Number(id) === Number(groupId))) return;
      if (behavior.groupAtOnly !== false) {
        const isAtBot = event.message?.some(
          (seg) => seg.type === "at" && String(seg.data?.qq) === String(botUserId || event.self_id)
        );
        if (!isAtBot) return;
      }
      shouldHandle = true;
    }
    if (!shouldHandle) return;
    lastCtx = ctx;
    let { extractedText, extractedMedia } = extractMessage(event.message || []);
    let text = extractedText;
    if (!text && extractedMedia.length === 0) return;
    const sessionBase = getSessionBase(messageType, userId, groupId);
    // 注册会话到映射表
    registerSession(sessionBase, messageType, userId, groupId);
    if (text?.startsWith("/")) {
      const spaceIdx = text.indexOf(" ");
      const cmd = (spaceIdx > 0 ? text.slice(0, spaceIdx) : text).toLowerCase();
      const args = spaceIdx > 0 ? text.slice(spaceIdx + 1).trim() : "";
      if (LOCAL_COMMANDS[cmd]) {
        logger.info(`[OpenClaw] 本地命令: ${cmd} from ${nickname}(${userId})`);
        const result = LOCAL_COMMANDS[cmd](sessionBase, userId, nickname, messageType, groupId, args);
        if (result) {
          await sendReply(ctx, messageType, groupId, userId, result);
          return;
        }
      }
    }
    const debounceMsRaw = currentConfig.behavior.debounceMs;
    const debounceMs = Number.isFinite(debounceMsRaw) ? debounceMsRaw : 2e3;
    if (debounceMs > 0 && !(text && text.startsWith("/"))) {
      const merged = await debounceMessage(sessionBase, text || "", extractedMedia, debounceMs);
      if (!merged) return;
      extractedText = merged.text;
      extractedMedia = merged.media;
      text = extractedText;
      if (!text && extractedMedia.length === 0) return;
    }
    let openclawMessage = text || "";
    if (extractedMedia.length > 0) {
      logger?.info(`[OpenClaw] 开始处理媒体文件, 数量: ${extractedMedia.length}`);
      for (const m of extractedMedia) {
        try {
          let filePath = null;
          let fileName = m.name || m.file || "unknown";
          
          if (m.url) {
            // 有URL的情况，直接下载
            logger?.info(`[OpenClaw] 媒体有URL: ${m.url}`);
            // 保留原有逻辑
          } else if (m.file_id) {
            // 没有URL，只有file_id - 通过NapCat API获取
            logger?.info(`[OpenClaw] 媒体只有file_id: ${m.file_id}, 尝试通过API获取`);
            try {
              // 直接调用NapCat HTTP API获取文件
              const apiUrl = `http://127.0.0.1:3000/get_file?file_id=${encodeURIComponent(m.file_id)}&access_token=fb0ff3c363e9a8b1e467ee121c69b146`;
              const response = await fetch(apiUrl);
              const data = await response.json();
              logger?.info(`[OpenClaw] API响应: ${JSON.stringify(data).slice(0, 200)}`);
              
              if (data.data && (data.data.file || data.data.url || data.data.base64)) {
                // 保存文件
                await fs.promises.mkdir(OPENCLAW_RECEIVED_FILES_DIR, { recursive: true });
                const ext = fileName.split(".").pop() || "bin";
                const newFileName = `${Date.now()}-${Math.random().toString(36).slice(2, 10)}.${ext}`;
                filePath = path.join(OPENCLAW_RECEIVED_FILES_DIR, newFileName);
                
                if (data.data.file) {
                  // 文件已在本地
                  try {
                    await fs.promises.copyFile(data.data.file, filePath);
                    logger?.info(`[OpenClaw] 文件复制成功: ${filePath}`);
                  } catch (e) {
                    logger?.warn(`[OpenClaw] 文件复制失败: ${e.message}`);
                  }
                } else if (data.data.url) {
                  // 需要从URL下载
                  const buf = await downloadToBuffer(data.data.url, 100 * 1024 * 1024);
                  if (buf) {
                    await fs.promises.writeFile(filePath, buf);
                    logger?.info(`[OpenClaw] 文件下载保存成功: ${filePath}`);
                  }
                } else if (data.data.base64) {
                  // Base64编码
                  const buf = Buffer.from(data.data.base64, "base64");
                  await fs.promises.writeFile(filePath, buf);
                  logger?.info(`[OpenClaw] Base64文件保存成功: ${filePath}`);
                }
              } else {
                logger?.warn(`[OpenClaw] API返回没有文件数据: ${JSON.stringify(data).slice(0, 100)}`);
              }
            } catch (e) {
              logger?.warn(`[OpenClaw] 通过API获取文件失败: ${e.message}`);
            }
          }
          
          // 添加到消息中
          if (filePath) {
            openclawMessage += `\n\n[用户发送了文件「${fileName}」: ${filePath}]`;
          } else {
            openclawMessage += `\n\n[用户发送了文件「${fileName}」file_id: ${m.file_id || 'unknown'}]`;
          }
        } catch (e) {
          logger?.warn(`[OpenClaw] 处理媒体文件失败: ${e.message}`);
          openclawMessage += `\n\n[用户发送了文件处理失败: ${e.message}]`;
        }
      }
    }
    logger.info(
      `[OpenClaw] ${messageType === "private" ? "私聊" : `群${groupId}`} ${nickname}(${userId}): ${openclawMessage.slice(0, 50)}`
    );
    if (messageType === "private") {
      typingStatusOn = true;
      await setTypingStatus(ctx, userId, true);
    }
    const sessionKey = getSessionKey(sessionBase);
    const runId = randomUUID();
    const runStartedAtMs = Date.now();
    let gw = null;
    let waitRunId = runId;
    try {
      gw = await getGateway();
      const gwClient = gw;
      const replyPromise = new Promise((resolve) => {
        let settled = false;
        let recovering = false;
        let latestSessionKey = sessionKey;
        const safeResolve = (value) => {
          if (settled) return;
          settled = true;
          cleanup();
          resolve(value);
        };
        const recoverFromHistory = async (reason, fallback, maxAttempts = 40, intervalMs = 500) => {
          if (settled || recovering) return;
          recovering = true;
          try {
            const historyText = await resolveReplyFromHistory(gwClient, latestSessionKey, runStartedAtMs, {
              maxAttempts,
              intervalMs,
              shouldStop: () => settled
            });
            if (settled) return;
            if (historyText) {
              logger.info(`[OpenClaw] ${reason}，已通过 chat.history 回填回复`);
              safeResolve(historyText);
              return;
            }
            safeResolve(fallback);
          } finally {
            recovering = false;
          }
        };
        const timeout = setTimeout(() => {
          logger.warn("[OpenClaw] 等待 final 超时，尝试通过 chat.history 补拉回复");
          void recoverFromHistory("等待 final 超时", null, 12, 500);
        }, 18e4);
        const cleanup = () => {
          clearTimeout(timeout);
          gwClient.chatWaiters.delete(waitRunId);
        };
        gwClient.chatWaiters.set(waitRunId, { handler: (payload) => {
          if (settled) return;
          if (!payload) return;
          if (typeof payload.sessionKey === "string" && payload.sessionKey.trim()) {
            latestSessionKey = payload.sessionKey.trim();
          }
          logger.info(`[OpenClaw] chat event: state=${payload.state} session=${payload.sessionKey} run=${payload.runId?.slice(0, 8)}`);
          if (payload.state === "final") {
            const directText = extractContentText(payload.message).trim();
            if (directText) {
              safeResolve(directText);
              return;
            }
            void recoverFromHistory("final 帧无文本", null, 20, 400);
            return;
          }
          if (payload.state === "aborted") {
            logger.warn("[OpenClaw] 收到 aborted 事件，等待后续重试结果");
            void recoverFromHistory(
              "收到 aborted 事件",
              "⚠️ 本次运行被中断，未拿到最终回复，请稍后重试。",
              45,
              500
            );
            return;
          }
          if (payload.state === "error") {
            const errorMessage = String(payload.errorMessage || "处理出错");
            if (isRecoverableGatewayError(errorMessage)) {
              logger.warn(`[OpenClaw] 收到可恢复错误: ${errorMessage}，等待后续重试结果`);
              void recoverFromHistory(
                `收到 error(${errorMessage})`,
                "⚠️ 本次运行被中断，未拿到最终回复，请稍后重试。",
                45,
                500
              );
            } else {
              safeResolve(`❌ ${errorMessage}`);
            }
            return;
          }
        } });
      });
      
      const sendResult = await gwClient.request("chat.send", {
        sessionKey,
        message: openclawMessage,
        idempotencyKey: runId
      });
      logger.info(`[OpenClaw] chat.send 已接受: runId=${sendResult?.runId}`);
      const actualRunId = typeof sendResult?.runId === "string" && sendResult.runId ? sendResult.runId : runId;
      
      // 🔥 记录这个 runId，避免 setupAgentPushListener 重复处理
      sentRunIds.add(runId);
      sentRunIds.add(actualRunId);
      if (actualRunId !== waitRunId) {
        const waiter = gwClient.chatWaiters.get(waitRunId);
        if (waiter) {
          gwClient.chatWaiters.delete(waitRunId);
          waitRunId = actualRunId;
          gwClient.chatWaiters.set(waitRunId, waiter);
        }
        logger.warn(
          `[OpenClaw] runId 重映射: local=${runId.slice(0, 8)} server=${actualRunId.slice(0, 8)}`
        );
      }
      const reply = await replyPromise;
      if (reply) {
        const { images, cleanText } = extractImagesFromReply(reply);
        const { files, cleanText: cleanText2 } = extractFilesFromReply(cleanText || reply);
        if (cleanText2) {
          await sendReply(ctx, messageType, groupId, userId, cleanText2);
        }
        for (const imageUrl of images) {
          try {
            await sendImageMsg(ctx, messageType, groupId ?? null, userId ?? null, imageUrl);
          } catch (e) {
            logger?.warn(`[OpenClaw] 发送图片失败: ${e.message}`);
          }
        }
        // 发送文件
        for (const file of files) {
          try {
            await sendFileMsg(ctx, messageType, groupId ?? null, userId ?? null, file.url, file.fileName);
          } catch (e) {
            logger?.warn(`[OpenClaw] 发送文件失败: ${e.message}`);
          }
        }
      } else {
        logger.warn("[OpenClaw] 无回复内容，返回兜底提示");
        await sendReply(ctx, messageType, groupId, userId, "⚠️ 模型未返回内容，请稍后重试。");
      }
    } catch (e) {
      if (gw && waitRunId) {
        gw.chatWaiters.delete(waitRunId);
      }
      logger.error(`[OpenClaw] 发送失败: ${e.message}`);
      if (gatewayClient) {
        gatewayClient.disconnect();
        gatewayClient = null;
        pushListenerAttached = false;
      }
      try {
        const cliPath = currentConfig.openclaw.cliPath || "/root/.nvm/versions/node/v22.22.0/bin/openclaw";
        const { stdout, stderr } = await execFileAsync(
          cliPath,
          ["agent", "--session-id", sessionKey, "--message", openclawMessage],
          {
            env: { ...process.env, OPENCLAW_TOKEN: currentConfig.openclaw.token || "" },
            timeout: 18e4,
            maxBuffer: 1024 * 1024
          }
        );
        const fallbackOutput = [stdout, stderr].filter(Boolean).join("\n").trim();
        if (fallbackOutput) {
          await sendReply(ctx, messageType, groupId, userId, fallbackOutput);
        }
      } catch (e2) {
        await sendReply(ctx, messageType, groupId, userId, `处理出错: ${e.message?.slice(0, 100)}`);
      }
    } finally {
      // 🔥 清理 runId，避免 Set 无限增长（保留最近 100 个）
      if (sentRunIds.size > 100) {
        const toDelete = Array.from(sentRunIds).slice(0, sentRunIds.size - 100);
        toDelete.forEach(id => sentRunIds.delete(id));
      }
    }
  } catch (outerErr) {
    logger?.error(`[OpenClaw] 未捕获异常: ${outerErr.message}
${outerErr.stack}`);
  } finally {
    if (typingStatusOn) {
      await setTypingStatus(ctx, event?.user_id, false);
    }
  }
};
const plugin_cleanup = async () => {
  for (const [, entry] of debounceBuffers) {
    clearTimeout(entry.timer);
  }
  debounceBuffers.clear();
  if (gatewayClient) {
    gatewayClient.disconnect();
    gatewayClient = null;
    pushListenerAttached = false;
  }
  pushListenerAttached = false;
  logger?.info("[OpenClaw] QQ Channel 插件清理完成");
};
function flattenConfig(cfg) {
  const behavior = cfg.behavior || {};
  return {
    token: cfg.openclaw?.token ?? "",
    gatewayUrl: cfg.openclaw?.gatewayUrl ?? "ws://127.0.0.1:18789",
    cliPath: cfg.openclaw?.cliPath ?? "",
    privateChat: behavior.privateChat ?? true,
    groupAtOnly: behavior.groupAtOnly ?? true,
    userWhitelist: (behavior.userWhitelist || []).join(","),
    groupWhitelist: (behavior.groupWhitelist || []).join(","),
    debounceMs: behavior.debounceMs ?? 2e3,
    groupSessionMode: behavior.groupSessionMode ?? "user"
  };
}
function unflattenConfig(flat) {
  const parseDebounceMs = (value) => {
    const parsed = Number(value);
    if (Number.isFinite(parsed) && parsed >= 0) return parsed;
    return 2e3;
  };
  const parseNumList = (s) => {
    if (Array.isArray(s)) return s.map(Number).filter(Boolean);
    if (typeof s === "string" && s.trim()) return s.split(",").map((x) => Number(x.trim())).filter(Boolean);
    return [];
  };
  return {
    openclaw: {
      token: flat.token ?? "",
      gatewayUrl: flat.gatewayUrl ?? "ws://127.0.0.1:18789",
      cliPath: flat.cliPath ?? "/root/.nvm/versions/node/v22.22.0/bin/openclaw"
    },
    behavior: {
      privateChat: flat.privateChat !== false,
      groupAtOnly: flat.groupAtOnly !== false,
      userWhitelist: parseNumList(flat.userWhitelist),
      groupWhitelist: parseNumList(flat.groupWhitelist),
      debounceMs: parseDebounceMs(flat.debounceMs),
      groupSessionMode: flat.groupSessionMode === "shared" ? "shared" : "user"
    }
  };
}
const plugin_get_config = async () => {
  const flat = flattenConfig(currentConfig);
  if (flat.token) {
    const t = String(flat.token);
    flat.token = t.length > 8 ? `${t.slice(0, 4)}****${t.slice(-4)}` : "****";
  }
  return flat;
};
const plugin_set_config = async (ctx, config) => {
  const get = (plainKey, dottedKey) => {
    if (config?.[plainKey] !== void 0) return config[plainKey];
    return config?.[dottedKey];
  };
  const maybeToken = get("token", "openclaw.token");
  const maybeGatewayUrl = get("gatewayUrl", "openclaw.gatewayUrl");
  const maybeCliPath = get("cliPath", "openclaw.cliPath");
  const maybePrivateChat = get("privateChat", "behavior.privateChat");
  const maybeGroupAtOnly = get("groupAtOnly", "behavior.groupAtOnly");
  const maybeUserWhitelist = get("userWhitelist", "behavior.userWhitelist");
  const maybeGroupWhitelist = get("groupWhitelist", "behavior.groupWhitelist");
  const maybeDebounceMs = get("debounceMs", "behavior.debounceMs");
  const maybeGroupSessionMode = get("groupSessionMode", "behavior.groupSessionMode");
  if (maybeToken !== void 0 || maybeGatewayUrl !== void 0 || maybeCliPath !== void 0 || maybePrivateChat !== void 0 || maybeGroupAtOnly !== void 0 || maybeUserWhitelist !== void 0 || maybeGroupWhitelist !== void 0 || maybeDebounceMs !== void 0 || maybeGroupSessionMode !== void 0) {
    const flatConfig = {
      token: typeof maybeToken === "string" && maybeToken.includes("****") ? currentConfig.openclaw.token : maybeToken ?? currentConfig.openclaw.token,
      gatewayUrl: maybeGatewayUrl ?? currentConfig.openclaw.gatewayUrl,
      cliPath: maybeCliPath ?? currentConfig.openclaw.cliPath,
      privateChat: maybePrivateChat ?? currentConfig.behavior.privateChat,
      groupAtOnly: maybeGroupAtOnly ?? currentConfig.behavior.groupAtOnly,
      userWhitelist: maybeUserWhitelist ?? currentConfig.behavior.userWhitelist.join(","),
      groupWhitelist: maybeGroupWhitelist ?? currentConfig.behavior.groupWhitelist.join(","),
      debounceMs: maybeDebounceMs ?? currentConfig.behavior.debounceMs,
      groupSessionMode: maybeGroupSessionMode ?? currentConfig.behavior.groupSessionMode
    };
    currentConfig = unflattenConfig(flatConfig);
  } else {
    currentConfig = deepMerge(currentConfig, config);
  }
  if (gatewayClient) {
    gatewayClient.disconnect();
    gatewayClient = null;
  }
  if (ctx?.configPath) {
    try {
      const dir = path.dirname(ctx.configPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(ctx.configPath, JSON.stringify(currentConfig, null, 2), "utf-8");
    } catch (e) {
      logger?.error("[OpenClaw] 保存配置失败: " + e.message);
    }
  }
};
function deepMerge(target, source) {
  const result = { ...target };
  for (const key of Object.keys(source)) {
    if (source[key] && typeof source[key] === "object" && !Array.isArray(source[key])) {
      result[key] = deepMerge(target[key] || {}, source[key]);
    } else {
      result[key] = source[key];
    }
  }
  return result;
}

export { plugin_cleanup, plugin_config_ui, plugin_get_config, plugin_init, plugin_onmessage, plugin_set_config };
