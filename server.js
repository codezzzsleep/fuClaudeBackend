const http = require("http");
const https = require("https");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const configPath = path.join(__dirname, "config.json");
const dataPath = path.join(__dirname, "data.json");
const templatePath = path.join(__dirname, "templates", "login.html");
const choosePath = path.join(__dirname, "templates", "choose.html");
const adminPath = path.join(__dirname, "templates", "admin.html");

const RAW_CONFIG = JSON.parse(fs.readFileSync(configPath, "utf8"));

function normalizeSessionKeys(raw) {
  const keys = [];
  if (Array.isArray(raw.SESSION_KEYS) && raw.SESSION_KEYS.length > 0) {
    let index = 1;
    for (const entry of raw.SESSION_KEYS) {
      if (typeof entry === "string") {
        keys.push({
          id: `key${index}`,
          label: `Key ${index}`,
          value: entry,
          expiresAt: ""
        });
        index += 1;
        continue;
      }
      if (entry && typeof entry === "object") {
        const value = entry.value || entry.key || entry.session_key;
        if (typeof value !== "string" || value.trim() === "") {
          index += 1;
          continue;
        }
        const id = typeof entry.id === "string" && entry.id.trim() !== "" ? entry.id : `key${index}`;
        const label = typeof entry.label === "string" && entry.label.trim() !== "" ? entry.label : id;
        const expiresAt =
          typeof entry.expiresAt === "string" && entry.expiresAt.trim() !== ""
            ? entry.expiresAt.trim()
            : typeof entry.expires_at === "string" && entry.expires_at.trim() !== ""
              ? entry.expires_at.trim()
              : "";
        keys.push({ id, label, value, expiresAt });
        index += 1;
      }
    }
  } else if (typeof raw.SESSION_KEY === "string" && raw.SESSION_KEY.trim() !== "") {
    keys.push({ id: "default", label: "Default", value: raw.SESSION_KEY, expiresAt: "" });
  }
  const defaultId = typeof raw.DEFAULT_KEY_ID === "string" ? raw.DEFAULT_KEY_ID : keys[0]?.id;
  return { ...raw, SESSION_KEYS: keys, DEFAULT_KEY_ID: defaultId };
}

const CONFIG = normalizeSessionKeys(RAW_CONFIG);
const KEY_EXPIRE_DAYS = 27;

function addDays(date, days) {
  const next = new Date(date.getTime());
  next.setDate(next.getDate() + days);
  return next;
}

function getDefaultKeyExpiresAt() {
  return addDays(new Date(), KEY_EXPIRE_DAYS).toISOString();
}

function normalizeKeys(rawKeys, rawDefaultId) {
  const normalized = normalizeSessionKeys({
    SESSION_KEYS: rawKeys,
    DEFAULT_KEY_ID: rawDefaultId,
    SESSION_KEY: ""
  });
  return { keys: normalized.SESSION_KEYS, defaultKeyId: normalized.DEFAULT_KEY_ID };
}

function normalizeUser(user, availableKeyIds) {
  if (!user || typeof user.username !== "string" || user.username.trim() === "") {
    return null;
  }
  const username = user.username.trim();
  const keys = Array.isArray(user.keys) ? user.keys.filter((id) => availableKeyIds.includes(id)) : [];
  return {
    username,
    active: user.active !== false,
    isolated: user.isolated !== false,
    keys,
    createdAt: user.createdAt || new Date().toISOString(),
    lastLoginAt: user.lastLoginAt || "",
    expiresAt: user.expiresAt || ""
  };
}

function loadData() {
  if (!fs.existsSync(dataPath)) {
    const normalized = normalizeKeys(CONFIG.SESSION_KEYS, CONFIG.DEFAULT_KEY_ID);
    return {
      keys: normalized.keys,
      defaultKeyId: normalized.defaultKeyId,
      users: []
    };
  }
  const raw = JSON.parse(fs.readFileSync(dataPath, "utf8"));
  const normalized = normalizeKeys(raw.keys || raw.SESSION_KEYS, raw.defaultKeyId || raw.DEFAULT_KEY_ID);
  const availableIds = normalized.keys.map((item) => item.id);
  const users = Array.isArray(raw.users)
    ? raw.users.map((entry) => normalizeUser(entry, availableIds)).filter(Boolean)
    : [];
  return {
    keys: normalized.keys,
    defaultKeyId: normalized.defaultKeyId,
    users
  };
}

let DATA = loadData();

function saveData() {
  fs.writeFileSync(dataPath, JSON.stringify(DATA, null, 2), "utf8");
}

function getDefaultKeyId() {
  if (DATA.defaultKeyId && DATA.keys.some((item) => item.id === DATA.defaultKeyId)) {
    return DATA.defaultKeyId;
  }
  return DATA.keys[0]?.id || "";
}

function getUsableDefaultKeyId() {
  const activeKeys = getActiveKeys();
  if (DATA.defaultKeyId && activeKeys.some((item) => item.id === DATA.defaultKeyId)) {
    return DATA.defaultKeyId;
  }
  return activeKeys[0]?.id || "";
}

function getUser(username) {
  if (!username) {
    return null;
  }
  return DATA.users.find((user) => user.username === username) || null;
}

function isUserExpired(user) {
  if (!user || !user.expiresAt) {
    return false;
  }
  const time = Date.parse(user.expiresAt);
  if (Number.isNaN(time)) {
    return false;
  }
  return Date.now() > time;
}

function isKeyExpired(key) {
  if (!key || !key.expiresAt) {
    return false;
  }
  const time = Date.parse(key.expiresAt);
  if (Number.isNaN(time)) {
    return false;
  }
  return Date.now() > time;
}

function getActiveKeys() {
  return DATA.keys.filter((item) => !isKeyExpired(item));
}

function getUserKeys(username) {
  const user = getUser(username);
  const activeKeys = getActiveKeys();
  if (!user) {
    return activeKeys;
  }
  const allowed = new Set(Array.isArray(user.keys) ? user.keys : []);
  return activeKeys.filter((item) => allowed.has(item.id));
}

function ensureUser(username) {
  if (!username) {
    return null;
  }
  let user = getUser(username);
  if (user) {
    return user;
  }
  user = {
    username,
    active: true,
    isolated: true,
    keys: DATA.keys.map((item) => item.id),
    createdAt: new Date().toISOString(),
    lastLoginAt: "",
    expiresAt: ""
  };
  DATA.users.push(user);
  saveData();
  return user;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function buildKeyCards(keys) {
  if (!keys || keys.length === 0) {
    return '<div class="empty">未配置可用账号</div>';
  }
  return keys.map((item, index) => {
    const fill = 28 + ((index * 17) % 60);
    const badge = item.label || item.id;
    return `
      <button class="key-card" type="submit" name="key_id" value="${escapeHtml(item.id)}" style="--fill:${fill}%" data-key-id="${escapeHtml(item.id)}">
        <div class="key-top">
          <span class="badge">${escapeHtml(badge)}</span>
          <span class="key-id">${escapeHtml(item.id)}</span>
        </div>
        <div class="key-row">
          <span class="key-label">实时状态</span>
          <span class="key-state">空闲</span>
        </div>
        <div class="key-bar"><span></span></div>
      </button>
    `;
  }).join("");
}

const FORM_HTML = fs.readFileSync(templatePath, "utf8");
const CHOOSE_TEMPLATE = fs.readFileSync(choosePath, "utf8");
const ADMIN_TEMPLATE = fs.readFileSync(adminPath, "utf8");

function renderChooseHtml(keys) {
  return CHOOSE_TEMPLATE.split("{{KEY_CARDS}}").join(buildKeyCards(keys));
}

function maskKey(value) {
  if (!value) {
    return "";
  }
  const str = String(value);
  if (str.length <= 8) {
    return `${str.slice(0, 2)}••••`;
  }
  return `${str.slice(0, 6)}••••${str.slice(-4)}`;
}

function formatKeyExpiry(key) {
  if (!key || !key.expiresAt) {
    return "--";
  }
  if (isKeyExpired(key)) {
    return `${key.expiresAt} (已过期)`;
  }
  return key.expiresAt;
}

function buildKeyOptions(selectedIds = []) {
  const selected = new Set(selectedIds);
  return DATA.keys.map((item) => {
    const isSelected = selected.has(item.id) ? " checked" : "";
    return `<label class="chip"><input type="checkbox" name="keys" value="${escapeHtml(item.id)}"${isSelected}>${escapeHtml(item.label || item.id)}</label>`;
  }).join("");
}

function buildDefaultKeyOptions() {
  const defaultId = getDefaultKeyId();
  return DATA.keys.map((item) => {
    const selected = item.id === defaultId ? " selected" : "";
    return `<option value="${escapeHtml(item.id)}"${selected}>${escapeHtml(item.label || item.id)}</option>`;
  }).join("");
}

function renderUsersRows() {
  if (!DATA.users.length) {
    return `<div class="table-empty">暂无用户数据</div>`;
  }
  return DATA.users.map((user) => {
    const keyCount = Array.isArray(user.keys) ? user.keys.length : 0;
    const lastLogin = user.lastLoginAt ? new Date(user.lastLoginAt).toLocaleString() : "--";
    const expiresAt = user.expiresAt || "--";
    const statusLabel = user.active ? "启用" : "禁用";
    const isoLabel = user.isolated ? "是" : "否";
    const keyChips = `<label class="chip select-all"><input type="checkbox" data-select-all> 全选</label>` + buildKeyOptions(user.keys);
    return `
      <div class="row">
        <div class="cell status">${statusLabel}</div>
        <div class="cell username">${escapeHtml(user.username)}</div>
        <div class="cell">${isoLabel}</div>
        <div class="cell"><span class="link">已绑定: ${keyCount} 个</span></div>
        <div class="cell">${lastLogin}</div>
        <div class="cell">${escapeHtml(expiresAt)}</div>
        <div class="cell">
          <form method="POST" action="/admin/users/update" class="inline-form">
            <input type="hidden" name="username" value="${escapeHtml(user.username)}">
            <input type="hidden" name="active" value="${user.active ? "1" : "0"}">
            <input type="hidden" name="isolated" value="${user.isolated ? "1" : "0"}">
            <button type="button" class="ghost" data-toggle="active">切换状态</button>
            <button type="button" class="ghost" data-toggle="isolated">切换隔离</button>
          </form>
          <form method="POST" action="/admin/users/delete" class="inline-form">
            <input type="hidden" name="username" value="${escapeHtml(user.username)}">
            <button class="danger" type="submit">删除</button>
          </form>
        </div>
        <div class="cell full">
          <form method="POST" action="/admin/users/keys" class="keys-form">
            <input type="hidden" name="username" value="${escapeHtml(user.username)}">
            <div class="chips">${keyChips}</div>
            <button type="submit" class="primary">保存绑定</button>
          </form>
        </div>
      </div>
    `;
  }).join("");
}

function renderKeyRows() {
  if (!DATA.keys.length) {
    return `<div class="table-empty">暂无 Key</div>`;
  }
  return DATA.keys.map((item) => {
    const expired = isKeyExpired(item);
    const expiryLabel = formatKeyExpiry(item);
    return `
      <div class="row key-row">
        <div class="cell key-id">${escapeHtml(item.id)}</div>
        <div class="cell">${escapeHtml(item.label || "--")}</div>
        <div class="cell mono">${escapeHtml(maskKey(item.value))}</div>
        <div class="cell${expired ? " expired" : ""}">${escapeHtml(expiryLabel)}</div>
        <div class="cell">
          <form method="POST" action="/admin/keys/delete" class="inline-form">
            <input type="hidden" name="key_id" value="${escapeHtml(item.id)}">
            <button class="danger" type="submit">删除</button>
          </form>
        </div>
      </div>
    `;
  }).join("");
}

function renderAdminHtml() {
  return ADMIN_TEMPLATE
    .split("{{USER_ROWS}}").join(renderUsersRows())
    .split("{{KEY_ROWS}}").join(renderKeyRows())
    .split("{{KEY_CHECKBOXES}}").join(buildKeyOptions(DATA.keys.map((item) => item.id)))
    .split("{{DEFAULT_KEY_OPTIONS}}").join(buildDefaultKeyOptions());
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8", ...headers });
  res.end(body);
}

function redirect(res, location, headers = {}) {
  res.writeHead(302, { Location: location, ...headers });
  res.end();
}

const LOGIN_STASH = new Map();
const LOGIN_TTL_MS = 5 * 60 * 1000;
const USER_COOKIE_MAX_AGE = 7 * 24 * 60 * 60;
const ADMIN_SESSIONS = new Map();
const ADMIN_TTL_MS = 12 * 60 * 60 * 1000;
const KEY_STATS = new Map();

function parseCookies(req) {
  const header = req.headers.cookie;
  if (!header) {
    return {};
  }
  const entries = header.split(";").map((part) => part.trim()).filter(Boolean);
  const cookies = {};
  for (const entry of entries) {
    const separatorIndex = entry.indexOf("=");
    if (separatorIndex === -1) {
      continue;
    }
    const name = entry.slice(0, separatorIndex).trim();
    const value = entry.slice(separatorIndex + 1);
    if (!name) {
      continue;
    }
    try {
      cookies[name] = decodeURIComponent(value);
    } catch (error) {
      cookies[name] = value;
    }
  }
  return cookies;
}

function hasCookie(cookies, name) {
  return Object.prototype.hasOwnProperty.call(cookies, name);
}

function buildCookie(name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value || "")}`];
  const path = options.path || "/";
  parts.push(`Path=${path}`);
  if (typeof options.maxAge === "number") {
    parts.push(`Max-Age=${options.maxAge}`);
  }
  if (options.expires instanceof Date) {
    parts.push(`Expires=${options.expires.toUTCString()}`);
  }
  if (options.sameSite) {
    parts.push(`SameSite=${options.sameSite}`);
  }
  if (options.httpOnly) {
    parts.push("HttpOnly");
  }
  if (options.secure) {
    parts.push("Secure");
  }
  return parts.join("; ");
}

function buildExpiredCookie(name, isSecure) {
  return buildCookie(name, "", {
    path: "/",
    expires: new Date(0),
    sameSite: "Lax",
    httpOnly: true,
    secure: isSecure
  });
}

function getKeyStat(keyId) {
  if (!keyId) {
    return null;
  }
  let stat = KEY_STATS.get(keyId);
  if (!stat) {
    stat = {
      keyId,
      total: 0,
      error: 0,
      inFlight: 0,
      lastAt: 0,
      lastStatus: 0,
      rateLimitedUntil: 0,
      avgLatencyMs: 0,
      latencySamples: 0
    };
    KEY_STATS.set(keyId, stat);
  }
  return stat;
}

function updateLatency(stat, latencyMs) {
  if (!stat || !Number.isFinite(latencyMs)) {
    return;
  }
  stat.latencySamples += 1;
  const n = stat.latencySamples;
  stat.avgLatencyMs = stat.avgLatencyMs + (latencyMs - stat.avgLatencyMs) / n;
}

function markRateLimited(stat, resetsAtSeconds) {
  if (!stat || !resetsAtSeconds) {
    return;
  }
  const untilMs = Number(resetsAtSeconds) * 1000;
  if (Number.isFinite(untilMs)) {
    stat.rateLimitedUntil = Math.max(stat.rateLimitedUntil, untilMs);
  }
}

function extractResetsAt(text) {
  if (!text) {
    return null;
  }
  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed.resetsAt === "number") {
      return parsed.resetsAt;
    }
    if (parsed && parsed.error && typeof parsed.error.message === "string") {
      const inner = JSON.parse(parsed.error.message);
      if (inner && typeof inner.resetsAt === "number") {
        return inner.resetsAt;
      }
    }
  } catch (error) {
    // ignore
  }
  const match = String(text).match(/\"resetsAt\"\s*:\s*(\d{9,})/);
  return match ? Number(match[1]) : null;
}

function createAdminSession() {
  const token = crypto.randomBytes(16).toString("hex");
  ADMIN_SESSIONS.set(token, { expiresAt: Date.now() + ADMIN_TTL_MS });
  return token;
}

function isAdmin(req) {
  const cookies = parseCookies(req);
  const token = cookies.fuclaude_admin;
  if (!token) {
    return false;
  }
  const entry = ADMIN_SESSIONS.get(token);
  if (!entry) {
    return false;
  }
  if (Date.now() > entry.expiresAt) {
    ADMIN_SESSIONS.delete(token);
    return false;
  }
  return true;
}

function stashLogin(uniqueName) {
  const token = crypto.randomBytes(16).toString("hex");
  LOGIN_STASH.set(token, {
    uniqueName,
    expiresAt: Date.now() + LOGIN_TTL_MS
  });
  return token;
}

function peekLogin(token) {
  if (!token) {
    return null;
  }
  const entry = LOGIN_STASH.get(token);
  if (!entry) {
    return null;
  }
  if (Date.now() > entry.expiresAt) {
    LOGIN_STASH.delete(token);
    return null;
  }
  return entry;
}

function consumeLogin(token) {
  const entry = peekLogin(token);
  if (entry) {
    LOGIN_STASH.delete(token);
  }
  return entry;
}

function hasSessionCookie(req) {
  const cookie = req.headers.cookie || "";
  return cookie.includes("_Secure-next-auth.session-data");
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function requestBuffer(url, options = {}, body) {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const client = target.protocol === "https:" ? https : http;
    const req = client.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || (target.protocol === "https:" ? 443 : 80),
        path: target.pathname + target.search,
        method: options.method || "GET",
        headers: options.headers || {}
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          resolve({
            statusCode: res.statusCode || 0,
            headers: res.headers || {},
            body: Buffer.concat(chunks)
          });
        });
      }
    );
    req.on("error", reject);
    if (body) {
      req.write(body);
    }
    req.end();
  });
}

async function handleLogin(req, res, baseUrl) {
  try {
    const raw = await readBody(req);
    const form = new URLSearchParams(raw);
    const loginType = form.get("login_type");
    let uniqueName = "";

    if (loginType === "site") {
      const sitePassword = form.get("site_password");
      if (sitePassword !== CONFIG.SITE_PASSWORD) {
        return send(res, 403, "Site password incorrect", {
          "Content-Type": "text/plain; charset=utf-8"
        });
      }
      const adminToken = createAdminSession();
      const secure = isSecureRequest(req);
      const adminCookie = buildCookie("fuclaude_admin", adminToken, {
        httpOnly: true,
        sameSite: "Lax",
        secure,
        maxAge: Math.floor(ADMIN_TTL_MS / 1000)
      });
      return redirect(res, "/admin", { "Set-Cookie": adminCookie });
    } else if (loginType === "guest") {
      const username = form.get("username");
      const guestPassword = form.get("guest_password");
      if (!username || username.trim() === "") {
        return send(res, 400, "Guest login requires a username", {
          "Content-Type": "text/plain; charset=utf-8"
        });
      }
      if (guestPassword !== CONFIG.GUEST_PASSWORD) {
        return send(res, 403, "Guest password incorrect", {
          "Content-Type": "text/plain; charset=utf-8"
        });
      }
      uniqueName = username.trim();
    } else {
      return send(res, 400, "Invalid login type", {
        "Content-Type": "text/plain; charset=utf-8"
      });
    }

    const existingUser = getUser(uniqueName);
    if (
      DATA.users.length > 0 &&
      (!existingUser || existingUser.active === false || isUserExpired(existingUser))
    ) {
      return send(res, 403, "User not allowed", {
        "Content-Type": "text/plain; charset=utf-8"
      });
    }
    const user = existingUser || ensureUser(uniqueName);
    if (user) {
      user.lastLoginAt = new Date().toISOString();
      saveData();
    }

    const secure = isSecureRequest(req);
    const loginToken = stashLogin(uniqueName);
    const cookies = [
      buildCookie("fuclaude_login", loginToken, {
        httpOnly: true,
        sameSite: "Lax",
        secure,
        maxAge: Math.floor(LOGIN_TTL_MS / 1000)
      }),
      buildCookie("fuclaude_user", uniqueName, {
        httpOnly: true,
        sameSite: "Lax",
        secure,
        maxAge: USER_COOKIE_MAX_AGE
      })
    ];
    return redirect(res, "/choose", { "Set-Cookie": cookies });
  } catch (error) {
    console.error("Login error:", error);
    return send(res, 500, "Login failed", {
      "Content-Type": "text/plain; charset=utf-8"
    });
  }
}

function buildRedirectTarget(loginUrl, req, baseUrl) {
  const forwardProto = req.headers["x-forwarded-proto"];
  const protocol = (Array.isArray(forwardProto) ? forwardProto[0] : forwardProto) || baseUrl.protocol;
  const safeProtocol = protocol && protocol.endsWith(":") ? protocol : `${protocol || "http"}:`;
  return loginUrl.startsWith("http") ? loginUrl : `${safeProtocol}//${baseUrl.host}${loginUrl}`;
}

async function handleChoose(req, res, baseUrl) {
  try {
    const raw = await readBody(req);
    const form = new URLSearchParams(raw);
    const cookies = parseCookies(req);
    const loginToken = cookies.fuclaude_login;
    const loginEntry = loginToken ? consumeLogin(loginToken) : null;
    const hasUser = hasCookie(cookies, "fuclaude_user");
    const uniqueName =
      (loginEntry && typeof loginEntry.uniqueName === "string" ? loginEntry.uniqueName : null) ??
      (hasUser ? cookies.fuclaude_user : null);

    if (!loginEntry && !hasUser) {
      return redirect(res, "/");
    }

    const availableKeys = getUserKeys(uniqueName);
    const selectedKeyId = form.get("key_id") || getUsableDefaultKeyId();
    const keyEntry =
      availableKeys.find((item) => item.id === selectedKeyId) ||
      availableKeys.find((item) => item.id === getUsableDefaultKeyId()) ||
      availableKeys[0];

    if (!keyEntry) {
      return send(res, 500, "No session keys configured", {
        "Content-Type": "text/plain; charset=utf-8"
      });
    }

    const body = { session_key: keyEntry.value };
    const user = uniqueName ? getUser(uniqueName) : null;
    if (user && (user.active === false || isUserExpired(user))) {
      return redirect(res, "/");
    }
    if (uniqueName && uniqueName.trim() !== "" && (!user || user.isolated !== false)) {
      body.unique_name = uniqueName.trim();
    }

    const authUrl = `${CONFIG.ORIGINAL_WEBSITE}/manage-api/auth/oauth_token`;
    const payload = JSON.stringify(body);
    const apiResponse = await requestBuffer(
      authUrl,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload)
        }
      },
      payload
    );

    if (apiResponse.statusCode < 200 || apiResponse.statusCode >= 300) {
      throw new Error(`API request failed with status ${apiResponse.statusCode}`);
    }

    const respJson = JSON.parse(apiResponse.body.toString("utf8") || "{}");
    const loginUrl = respJson.login_url || "/";
    const redirectTarget = buildRedirectTarget(loginUrl, req, baseUrl);
    const secure = isSecureRequest(req);
    const clearLogin = buildExpiredCookie("fuclaude_login", secure);
    const keyCookie = buildCookie("fuclaude_key", keyEntry.id, {
      httpOnly: true,
      sameSite: "Lax",
      secure,
      maxAge: USER_COOKIE_MAX_AGE
    });
    return redirect(res, redirectTarget, { "Set-Cookie": [clearLogin, keyCookie] });
  } catch (error) {
    console.error("Choose error:", error);
    return send(res, 500, "Choose failed", {
      "Content-Type": "text/plain; charset=utf-8"
    });
  }
}

function copyResponseHeaders(headers, res) {
  for (const [key, value] of Object.entries(headers || {})) {
    const lowerKey = key.toLowerCase();
    if (
      lowerKey === "content-encoding" ||
      lowerKey === "content-length" ||
      lowerKey === "content-security-policy" ||
      lowerKey === "content-security-policy-report-only"
    ) {
      continue;
    }
    if (typeof value !== "undefined") {
      res.setHeader(key, value);
    }
  }
}

function isHtmlResponse(headers) {
  const contentType = headers && headers["content-type"];
  if (!contentType) {
    return false;
  }
  return contentType.toLowerCase().includes("text/html");
}

function isEventStream(headers) {
  const contentType = headers && headers["content-type"];
  if (!contentType) {
    return false;
  }
  return contentType.toLowerCase().includes("text/event-stream");
}

function parseSseErrors(text, stat) {
  if (!text) {
    return;
  }
  const chunks = text.split("\n\n");
  for (const chunk of chunks) {
    if (!chunk.includes("data:")) {
      continue;
    }
    const dataLines = chunk
      .split("\n")
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trim());
    for (const data of dataLines) {
      try {
        const payload = JSON.parse(data);
        if (payload && payload.type === "error" && payload.error && payload.error.type === "rate_limit_error") {
          const resetsAt = extractResetsAt(payload.error.message);
          markRateLimited(stat, resetsAt);
        }
      } catch (error) {
        // ignore
      }
    }
  }
}

function injectSwitchButton(html) {
  const marker = "<!-- fuclaude-switch -->";
  if (html.includes(marker)) {
    return html;
  }
  const script = `${marker}<script>
  (function () {
    function ensureSwitch() {
      if (document.getElementById("fuclaude-switch")) return;
      var a = document.createElement("a");
      a.id = "fuclaude-switch";
      a.href = "/choose";
      a.textContent = "换号";
      a.style.cssText =
        "position:fixed;right:18px;top:18px;z-index:99999;" +
        "padding:8px 14px;background:#ffffff;color:#111827;" +
        "border-radius:999px;text-decoration:none;font-size:13px;" +
        "font-weight:600;box-shadow:0 10px 24px rgba(0,0,0,0.12);" +
        "border:1px solid rgba(15,23,42,0.12);";
      document.body.appendChild(a);
    }
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", ensureSwitch);
    } else {
      ensureSwitch();
    }
    var pushState = history.pushState;
    history.pushState = function () {
      pushState.apply(this, arguments);
      setTimeout(ensureSwitch, 0);
    };
    var replaceState = history.replaceState;
    history.replaceState = function () {
      replaceState.apply(this, arguments);
      setTimeout(ensureSwitch, 0);
    };
    window.addEventListener("popstate", function () {
      setTimeout(ensureSwitch, 0);
    });
    setInterval(ensureSwitch, 2000);
  })();
  </script>`;
  if (html.includes("</body>")) {
    return html.replace("</body>", `${script}</body>`);
  }
  return `${html}${script}`;
}

function isSecureRequest(req) {
  const forwardProto = req.headers["x-forwarded-proto"];
  const proto = Array.isArray(forwardProto) ? forwardProto[0] : forwardProto;
  if (proto) {
    return proto.toLowerCase() === "https";
  }
  return Boolean(req.socket && req.socket.encrypted);
}

function buildClearCookiesHeaders(isSecure) {
  const expires = new Date(0).toUTCString();
  const attrs = [`Path=/`, `Expires=${expires}`, `SameSite=Lax`];
  if (isSecure) {
    attrs.push("Secure");
  }
  const base = attrs.join("; ");
  const cookieNames = [
    "_Secure-next-auth.session-data",
    "__Secure-next-auth.session-token",
    "next-auth.session-token",
    "next-auth.csrf-token",
    "__Host-next-auth.csrf-token",
    "fuclaude_login",
    "fuclaude_user",
    "fuclaude_admin",
    "fuclaude_key"
  ];
  return cookieNames.map((name) => `${name}=; ${base}`);
}

function buildSwitchPageHtml() {
  return `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta http-equiv="Cache-Control" content="no-store" />
    <meta http-equiv="Pragma" content="no-cache" />
    <meta http-equiv="Expires" content="0" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>正在切换...</title>
    <style>
      body {
        margin: 0;
        font-family: "Sora", "Noto Sans SC", "PingFang SC", "Microsoft YaHei", sans-serif;
        background: radial-gradient(circle at top, #ffffff 0%, #f1f5f9 70%);
        color: #111827;
        display: grid;
        place-items: center;
        height: 100vh;
      }
      .card {
        background: #ffffff;
        border: 1px solid rgba(148, 163, 184, 0.4);
        border-radius: 20px;
        padding: 26px 32px;
        box-shadow: 0 20px 50px rgba(15, 23, 42, 0.12);
        text-align: center;
      }
      .title {
        font-size: 18px;
        margin-bottom: 6px;
      }
      .subtitle {
        font-size: 13px;
        color: #64748b;
      }
    </style>
  </head>
  <body>
    <div class="card">
      <div class="title">正在切换账号…</div>
      <div class="subtitle">正在清理会话数据</div>
    </div>
    <script>
      try { localStorage.clear(); } catch (e) {}
      try { sessionStorage.clear(); } catch (e) {}
      window.location.replace("/choose");
    </script>
  </body>
</html>`;
}

function requireAdmin(req, res) {
  if (!isAdmin(req)) {
    redirect(res, "/");
    return false;
  }
  return true;
}

function parseBool(value) {
  return value === "1" || value === "true" || value === "on";
}

function sanitizeKeyId(id) {
  if (!id) {
    return "";
  }
  return id.trim().replace(/\s+/g, "_");
}

function generateKeyId(label) {
  const base = sanitizeKeyId(label || "key").toLowerCase();
  const prefix = base || "key";
  const stamp = Date.now().toString(36);
  const rand = crypto.randomBytes(3).toString("hex");
  return `${prefix}_${stamp}_${rand}`;
}

function ensureDataKeys() {
  if (!Array.isArray(DATA.keys)) {
    DATA.keys = [];
  }
  if (!DATA.defaultKeyId || !DATA.keys.some((item) => item.id === DATA.defaultKeyId)) {
    DATA.defaultKeyId = DATA.keys[0]?.id || "";
  }
}

function updateUserKeys(username, keyIds) {
  const user = getUser(username);
  if (!user) {
    return false;
  }
  const validIds = new Set(DATA.keys.map((item) => item.id));
  user.keys = keyIds.filter((id) => validIds.has(id));
  saveData();
  return true;
}

async function proxyRequest(req, res, url) {
  const targetUrl = new URL(url.pathname + url.search, CONFIG.ORIGINAL_WEBSITE);
  const headers = { ...req.headers };
  headers.host = targetUrl.host;
  delete headers["accept-encoding"];
  const cookies = parseCookies(req);
  const keyId = cookies.fuclaude_key || "";
  const stat = getKeyStat(keyId);
  const startTime = Date.now();
  if (stat) {
    stat.inFlight += 1;
    stat.lastAt = startTime;
    stat.total += 1;
  }

  const client = targetUrl.protocol === "https:" ? https : http;
  const upstreamReq = client.request(
    {
      protocol: targetUrl.protocol,
      hostname: targetUrl.hostname,
      port: targetUrl.port || (targetUrl.protocol === "https:" ? 443 : 80),
      path: targetUrl.pathname + targetUrl.search,
      method: req.method,
      headers
    },
    (upstreamRes) => {
      res.statusCode = upstreamRes.statusCode || 502;
      if (stat) {
        stat.lastStatus = res.statusCode;
        if (res.statusCode >= 400) {
          stat.error += 1;
        }
      }
      const isHtml = req.method === "GET" && isHtmlResponse(upstreamRes.headers);
      const isStream = isEventStream(upstreamRes.headers);
      const needsBodyCapture = isHtml || (res.statusCode === 429 && !isStream);
      if (isStream && stat) {
        let buffer = "";
        upstreamRes.setEncoding("utf8");
        upstreamRes.on("data", (chunk) => {
          buffer += chunk;
          parseSseErrors(buffer, stat);
          if (buffer.length > 6000) {
            buffer = buffer.slice(-2000);
          }
        });
      }
      if (needsBodyCapture) {
        let body = "";
        upstreamRes.setEncoding("utf8");
        upstreamRes.on("data", (chunk) => {
          body += chunk;
        });
        upstreamRes.on("end", () => {
          const latency = Date.now() - startTime;
          if (stat) {
            stat.inFlight = Math.max(0, stat.inFlight - 1);
            updateLatency(stat, latency);
          }
          if (res.statusCode === 429 && stat) {
            const resetsAt = extractResetsAt(body);
            markRateLimited(stat, resetsAt);
          }
          copyResponseHeaders(upstreamRes.headers, res);
          if (isHtml) {
            res.end(injectSwitchButton(body));
            return;
          }
          res.end(body);
        });
        return;
      }
      upstreamRes.on("end", () => {
        const latency = Date.now() - startTime;
        if (stat) {
          stat.inFlight = Math.max(0, stat.inFlight - 1);
          updateLatency(stat, latency);
        }
      });
      copyResponseHeaders(upstreamRes.headers, res);
      upstreamRes.pipe(res);
    }
  );

  upstreamReq.on("error", (error) => {
    console.error("Proxy error:", error);
    if (stat) {
      stat.inFlight = Math.max(0, stat.inFlight - 1);
      stat.error += 1;
      stat.lastStatus = 502;
    }
    if (!res.headersSent) {
      send(res, 502, "Bad gateway", { "Content-Type": "text/plain; charset=utf-8" });
      return;
    }
    res.end();
  });

  req.pipe(upstreamReq);
}

const server = http.createServer(async (req, res) => {
  const baseUrl = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

  if (baseUrl.pathname === "/login") {
    return redirect(res, "/");
  }

  if (baseUrl.pathname === "/__switch") {
    const cookies = buildClearCookiesHeaders(isSecureRequest(req));
    return send(res, 200, buildSwitchPageHtml(), {
      "Set-Cookie": cookies,
      "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
      Pragma: "no-cache",
      Expires: "0"
    });
  }

  if (baseUrl.pathname === "/admin") {
    if (!requireAdmin(req, res)) {
      return;
    }
    return send(res, 200, renderAdminHtml());
  }

  if (baseUrl.pathname === "/status") {
    const now = Date.now();
    const status = DATA.keys.map((item) => {
      const stat = getKeyStat(item.id);
      const limited = stat && stat.rateLimitedUntil > now;
      const busy = stat && (stat.inFlight > 0 || (stat.lastAt > 0 && now - stat.lastAt <= 30000));
      const state = limited ? "limited" : busy ? "busy" : "idle";
      return {
        key_id: item.id,
        label: item.label || item.id,
        state,
        in_flight: stat ? stat.inFlight : 0,
        last_at: stat ? stat.lastAt : 0,
        last_status: stat ? stat.lastStatus : 0,
        rate_limited_until: stat ? stat.rateLimitedUntil : 0,
        avg_latency_ms: stat ? Math.round(stat.avgLatencyMs) : 0
      };
    });
    res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
    res.end(JSON.stringify({ status }));
    return;
  }

  if (baseUrl.pathname === "/admin/logout") {
    if (!requireAdmin(req, res)) {
      return;
    }
    const secure = isSecureRequest(req);
    const expired = buildExpiredCookie("fuclaude_admin", secure);
    return redirect(res, "/", { "Set-Cookie": expired });
  }

  if (baseUrl.pathname === "/admin/users/create" && req.method === "POST") {
    if (!requireAdmin(req, res)) {
      return;
    }
    const raw = await readBody(req);
    const form = new URLSearchParams(raw);
    const username = (form.get("username") || "").trim();
    if (!username) {
      return send(res, 400, "Username required", { "Content-Type": "text/plain; charset=utf-8" });
    }
    if (getUser(username)) {
      return send(res, 400, "User already exists", { "Content-Type": "text/plain; charset=utf-8" });
    }
    const keys = form.getAll("keys");
    const active = parseBool(form.get("active"));
    const isolated = parseBool(form.get("isolated"));
    const expiresAt = (form.get("expires_at") || "").trim();
    const validKeyIds = new Set(DATA.keys.map((item) => item.id));
    const selectedKeys = keys.filter((id) => validKeyIds.has(id));
    const user = {
      username,
      active,
      isolated,
      keys: selectedKeys.length ? selectedKeys : DATA.keys.map((item) => item.id),
      createdAt: new Date().toISOString(),
      lastLoginAt: "",
      expiresAt
    };
    DATA.users.push(user);
    saveData();
    return redirect(res, "/admin");
  }

  if (baseUrl.pathname === "/admin/users/update" && req.method === "POST") {
    if (!requireAdmin(req, res)) {
      return;
    }
    const raw = await readBody(req);
    const form = new URLSearchParams(raw);
    const username = (form.get("username") || "").trim();
    const user = getUser(username);
    if (!user) {
      return send(res, 404, "User not found", { "Content-Type": "text/plain; charset=utf-8" });
    }
    user.active = parseBool(form.get("active"));
    user.isolated = parseBool(form.get("isolated"));
    saveData();
    return redirect(res, "/admin");
  }

  if (baseUrl.pathname === "/admin/users/keys" && req.method === "POST") {
    if (!requireAdmin(req, res)) {
      return;
    }
    const raw = await readBody(req);
    const form = new URLSearchParams(raw);
    const username = (form.get("username") || "").trim();
    const keyIds = form.getAll("keys");
    if (!updateUserKeys(username, keyIds)) {
      return send(res, 404, "User not found", { "Content-Type": "text/plain; charset=utf-8" });
    }
    return redirect(res, "/admin");
  }

  if (baseUrl.pathname === "/admin/users/delete" && req.method === "POST") {
    if (!requireAdmin(req, res)) {
      return;
    }
    const raw = await readBody(req);
    const form = new URLSearchParams(raw);
    const username = (form.get("username") || "").trim();
    DATA.users = DATA.users.filter((user) => user.username !== username);
    saveData();
    return redirect(res, "/admin");
  }

  if (baseUrl.pathname === "/admin/users/grant_all" && req.method === "POST") {
    if (!requireAdmin(req, res)) {
      return;
    }
    const allKeys = DATA.keys.map((item) => item.id);
    DATA.users = DATA.users.map((user) => ({
      ...user,
      keys: allKeys
    }));
    saveData();
    return redirect(res, "/admin");
  }

  if (baseUrl.pathname === "/admin/keys/create" && req.method === "POST") {
    if (!requireAdmin(req, res)) {
      return;
    }
    const raw = await readBody(req);
    const form = new URLSearchParams(raw);
    const label = (form.get("label") || "").trim();
    const value = (form.get("value") || "").trim();
    const expiresAtInput = (form.get("expires_at") || "").trim();
    let expiresAt = expiresAtInput;
    if (expiresAtInput) {
      const parsed = Date.parse(expiresAtInput);
      if (Number.isNaN(parsed)) {
        return send(res, 400, "Invalid expires_at", { "Content-Type": "text/plain; charset=utf-8" });
      }
    } else {
      expiresAt = getDefaultKeyExpiresAt();
    }
    if (!value) {
      return send(res, 400, "Session key required", { "Content-Type": "text/plain; charset=utf-8" });
    }
    let keyId = generateKeyId(label);
    let attempts = 0;
    while (DATA.keys.some((item) => item.id === keyId) && attempts < 5) {
      keyId = generateKeyId(label);
      attempts += 1;
    }
    if (DATA.keys.some((item) => item.id === keyId)) {
      return send(res, 500, "Failed to generate key id", { "Content-Type": "text/plain; charset=utf-8" });
    }
    DATA.keys.push({ id: keyId, label: label || keyId, value, expiresAt });
    ensureDataKeys();
    saveData();
    return redirect(res, "/admin");
  }

  if (baseUrl.pathname === "/admin/keys/delete" && req.method === "POST") {
    if (!requireAdmin(req, res)) {
      return;
    }
    const raw = await readBody(req);
    const form = new URLSearchParams(raw);
    const keyId = (form.get("key_id") || "").trim();
    DATA.keys = DATA.keys.filter((item) => item.id !== keyId);
    DATA.users = DATA.users.map((user) => ({
      ...user,
      keys: Array.isArray(user.keys) ? user.keys.filter((id) => id !== keyId) : []
    }));
    ensureDataKeys();
    saveData();
    return redirect(res, "/admin");
  }

  if (baseUrl.pathname === "/admin/keys/default" && req.method === "POST") {
    if (!requireAdmin(req, res)) {
      return;
    }
    const raw = await readBody(req);
    const form = new URLSearchParams(raw);
    const keyId = (form.get("default_key_id") || "").trim();
    if (DATA.keys.some((item) => item.id === keyId)) {
      DATA.defaultKeyId = keyId;
      saveData();
    }
    return redirect(res, "/admin");
  }

  if (baseUrl.pathname === "/choose") {
    if (req.method === "POST") {
      return handleChoose(req, res, baseUrl);
    }
    const cookies = parseCookies(req);
    const loginToken = cookies.fuclaude_login;
    const loginEntry = loginToken ? peekLogin(loginToken) : null;
    const hasUser = hasCookie(cookies, "fuclaude_user");
    if (!loginEntry && !hasUser) {
      return redirect(res, "/");
    }
    const uniqueName =
      (loginEntry && typeof loginEntry.uniqueName === "string" ? loginEntry.uniqueName : null) ??
      (hasUser ? cookies.fuclaude_user : null);
    if (uniqueName) {
      const user = getUser(uniqueName);
      if (user && (user.active === false || isUserExpired(user))) {
        return redirect(res, "/");
      }
    }
    const keys = getUserKeys(uniqueName);
    return send(res, 200, renderChooseHtml(keys));
  }

  if (baseUrl.pathname === "/") {
    if (hasSessionCookie(req)) {
      return redirect(res, "/new");
    }
    if (req.method === "POST") {
      return handleLogin(req, res, baseUrl);
    }
    return send(res, 200, FORM_HTML);
  }

  return proxyRequest(req, res, baseUrl);
});

const port = Number(CONFIG.PORT || 3000);
server.listen(port, () => {
  console.log(`Server listening on :${port}`);
});
