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
const debounceBuffers = /* @__PURE__ */ new Map();
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
  for (const seg of segments) {
    switch (seg.type) {
      case "text": {
        const t = seg.data?.text?.trim();
        if (t) textParts.push(t);
        break;
      }
      case "image":
        if (seg.data?.url) {
          const imgData = { type: "image", url: seg.data.url };
          // 从 URL 中提取 fileid 参数
          try {
            const urlObj = new URL(seg.data.url);
            const fileId = urlObj.searchParams.get('fileid');
            if (fileId) imgData.file_id = fileId;
          } catch (e) {}
          media.push(imgData);
        }
        break;
      case "at":
        if (String(seg.data?.qq) !== String(botUserId)) {
          textParts.push(`@${seg.data?.name || seg.data?.qq}`);
        }
        break;
      case "file":
        if (seg.data?.url) media.push({ type: "file", url: seg.data.url, name: seg.data?.name });
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
        buf = await downloadToBuffer(m.url, 10 * 1024 * 1024);
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
              if (fileInfo.url) buf = await downloadToBuffer(fileInfo.url, 10 * 1024 * 1024);
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
  const localImages = [];
  const mediaRegex = /^MEDIA:\s*(.+)$/gm;
  let match;
  while ((match = mediaRegex.exec(text)) !== null) {
    const url = match[1].trim();
    if (url.startsWith("http")) images.push(url);
  }
  const mdRegex = /!\[[^\]]*\]\(([^)]+)\)/g;
  while ((match = mdRegex.exec(text)) !== null) {
    const url = match[1].trim();
    if (url.startsWith("http")) images.push(url);
  }
  // 提取本地图片路径
  const localRegex = /\[LOCAL_IMAGE_PATH\](.+)/g;
  while ((match = localRegex.exec(text)) !== null) {
    const path = match[1].trim();
    if (path) localImages.push(path);
  }
  const cleanText = text.replace(/^MEDIA:\s*.+$/gm, "").replace(/!\[[^\]]*\]\([^)]+\)/g, "").replace(/\[LOCAL_IMAGE_PATH\].+/g, "").trim();
  return { images: Array.from(new Set(images)), localImages, cleanText };
}
function setupAgentPushListener(gw) {
  gw.eventHandlers.set("chat", (payload) => {
    if (!payload || payload.state !== "final" || !payload.sessionKey) return;
    if (!payload.sessionKey.startsWith("qq-")) return;
    if (payload.runId && gw.chatWaiters.has(payload.runId)) return;
    if (!lastCtx) return;
    const text = extractContentText(payload.message).trim();
    if (!text) return;
    logger?.info(`[OpenClaw] Agent 主动推送: ${payload.sessionKey} -> ${text.slice(0, 50)}`);
    const privateMatch = payload.sessionKey.match(/^qq-(\d+)(?:-\d+)?$/);
    if (privateMatch && !payload.sessionKey.includes("-g")) {
      const { images, cleanText } = extractImagesFromReply(text);
      if (cleanText) void sendPrivateMsg(lastCtx, privateMatch[1], cleanText);
      for (const img of images) void sendImageMsg(lastCtx, "private", null, privateMatch[1], img);
      return;
    }
    const groupMatch = payload.sessionKey.match(/^qq-g(\d+)/);
    if (groupMatch) {
      const { images, cleanText } = extractImagesFromReply(text);
      if (cleanText) void sendGroupMsg(lastCtx, groupMatch[1], cleanText);
      for (const img of images) void sendImageMsg(lastCtx, "group", groupMatch[1], null, img);
    }
  });
}
let plugin_config_ui = [];
const plugin_init = async (ctx) => {
  logger = ctx.logger;
  lastCtx = ctx;
  configPath = ctx.configPath;
  pluginDir = new URL(".", import.meta.url).pathname.replace(/^\/[A-Z]:/, (m) => m.slice(1));
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
      const savedMedia = await saveMediaToCache(extractedMedia, ctx);
      if (savedMedia.length > 0) {
        const mediaInfo = savedMedia.map((m) => {
          if (m.path) {
            if (m.type === "image") return `[用户发送了图片: ${m.path}]`;
            if (m.type === "file") return `[用户发送了文件「${m.name}」: ${m.path}]`;
            if (m.type === "voice") return `[用户发送了语音: ${m.path}]`;
            if (m.type === "video") return `[用户发送了视频: ${m.path}]`;
            return `[用户发送了${m.type}: ${m.path}]`;
          }
          return `[用户发送了${m.type}: ${m.url}]`;
        }).join("\n");
        openclawMessage = openclawMessage ? `${openclawMessage}

${mediaInfo}` : mediaInfo;
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
            // 直接 resolve，即使为空也没关系（后续 extractImagesFromReply 会处理图片）
            // 不要调用 recoverFromHistory，避免重复发送
            safeResolve(directText || "");
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
        const { images, localImages, cleanText } = extractImagesFromReply(reply);
        if (cleanText) {
          await sendReply(ctx, messageType, groupId, userId, cleanText);
        }
        // 发送本地图片
        for (const localPath of localImages || []) {
          try {
            const normalizedPath = localPath.replace(/\\/g, '/');
            const fileUrl = `file:///${normalizedPath}`;
            await sendImageMsg(ctx, messageType, groupId ?? null, userId ?? null, fileUrl);
            logger?.info(`[OpenClaw] 发送本地图片：${localPath}`);
          } catch (e) {
            logger?.warn(`[OpenClaw] 发送本地图片失败：${e.message}`);
          }
        }
        // 发送网络图片
        for (const imageUrl of images) {
          try {
            await sendImageMsg(ctx, messageType, groupId ?? null, userId ?? null, imageUrl);
          } catch (e) {
            logger?.warn(`[OpenClaw] 发送图片失败: ${e.message}`);
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
