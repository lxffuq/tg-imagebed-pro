const json = (data, status = 200, extra = {}) => new Response(JSON.stringify(data), {
  status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extra }
});
const err = (message, status = 400) => json({ error: message }, status);
const cleanName = (s) => (s || "image").replace(/[\\/:*?"<>|\x00-\x1f]/g, "_").slice(0, 180);
const isImage = (mime) => /^image\/(jpeg|png|gif|webp|avif|bmp|svg\+xml)$/i.test(mime || "");
const hex = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
const unhex = (s) => new Uint8Array((s.match(/../g) || []).map(h => parseInt(h, 16)));
const sha256hex = async (text) => hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
// D1 batch 单次最多 100 条，分块写更稳妥
async function batchChunked(env, stmts, size = 50) {
  for (let i = 0; i < stmts.length; i += size) await env.DB.batch(stmts.slice(i, i + size));
}
// 管理密码：PBKDF2-SHA256 10 万次迭代，盐 16 字节，存 D1 settings 表
async function hashPassword(password, saltHex) {
  const salt = saltHex ? unhex(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, key, 256);
  return hex(salt) + ":" + hex(bits);
}
let tablesReady = false;
async function ensureTables(env) {
  if (tablesReady) return;
  await env.DB.batch([
    env.DB.prepare("CREATE TABLE IF NOT EXISTS images (id TEXT PRIMARY KEY, original_name TEXT NOT NULL, mime_type TEXT NOT NULL, size_bytes INTEGER NOT NULL, telegram_chat_id TEXT NOT NULL, telegram_message_id INTEGER NOT NULL, telegram_file_id TEXT NOT NULL, telegram_file_unique_id TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')), status TEXT NOT NULL DEFAULT 'active', delete_error TEXT, delete_attempts INTEGER NOT NULL DEFAULT 0)"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_images_created ON images(created_at DESC)"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_images_name ON images(original_name)"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_images_status ON images(status)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS login_attempts (ip TEXT PRIMARY KEY, fails INTEGER NOT NULL DEFAULT 0, last_at INTEGER NOT NULL)"),
  ]);
  // 旧库补列：新库建表时已包含 delete_attempts，老库第一次跑到这里会加上（已存在会报错，已吞掉）
  try { await env.DB.prepare("ALTER TABLE images ADD COLUMN delete_attempts INTEGER NOT NULL DEFAULT 0").run(); } catch {}
  tablesReady = true;
}
async function getPasswordHash(env) {
  try { const row = await env.DB.prepare("SELECT value FROM settings WHERE key='admin_password_hash'").first(); return row?.value || null; }
  catch { return null; }
}
async function checkPassword(env, password) {
  if (!password) return false;
  if (env.ADMIN_TOKEN && safeEqual(password, env.ADMIN_TOKEN)) return true;
  const stored = await getPasswordHash(env);
  if (!stored) return false;
  const [salt, hash] = stored.split(":");
  if (!salt || !hash) return false;
  const computed = await hashPassword(password, salt);
  return safeEqual(computed.split(":")[1], hash);
}
async function newSession(env) {
  const token = hex(crypto.getRandomValues(new Uint8Array(32)));
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare("INSERT INTO sessions (token_hash, created_at, expires_at) VALUES (?, ?, ?)").bind(await sha256hex(token), now, now + 7 * 86400).run();
  return token;
}
async function verifySession(env, token) {
  if (!token) return false;
  try {
    const row = await env.DB.prepare("SELECT expires_at FROM sessions WHERE token_hash=?").bind(await sha256hex(token)).first();
    return !!row && row.expires_at > Math.floor(Date.now() / 1000);
  } catch { return false; }
}
// 鉴权：部署时设了 ADMIN_TOKEN 变量/密钥可直接当口令；否则认 D1 会话
async function auth(request, env) {
  const bearer = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  if (!bearer) return false;
  if (env.ADMIN_TOKEN && safeEqual(bearer, env.ADMIN_TOKEN)) return true;
  return verifySession(env, bearer);
}
const telegram = (botToken, method) => `https://api.telegram.org/bot${botToken}/${method}`;
// 机器人配置：优先用部署变量/密钥，其次用设置页绑定后存在 D1 里的值
async function getTelegramConfig(env) {
  let botToken = env.TG_BOT_TOKEN || "";
  let chatId = env.TG_CHAT_ID || "";
  if (!botToken || !chatId) {
    try {
      const { results = [] } = await env.DB.prepare("SELECT key, value FROM settings WHERE key IN ('tg_bot_token','tg_chat_id')").all();
      for (const r of results) {
        if (r.key === "tg_bot_token" && !botToken) botToken = r.value;
        if (r.key === "tg_chat_id" && !chatId) chatId = r.value;
      }
    } catch {}
  }
  return { botToken, chatId };
}

async function api(request, env, ctx) {
  const url = new URL(request.url);
  if (url.pathname === "/api/health") return json({ ok: true, service: "TG ImageBed Pro" });

  // 首次设置密码：部署成功后第一次打开站点时调用，之后不再开放
  if (url.pathname === "/api/auth/status") {
    await ensureTables(env);
    return json({ setupRequired: !env.ADMIN_TOKEN && !(await getPasswordHash(env)) });
  }
  if (url.pathname === "/api/auth/setup" && request.method === "POST") {
    await ensureTables(env);
    if (env.ADMIN_TOKEN || (await getPasswordHash(env))) return err("管理密码已设置", 409);
    const body = await request.json().catch(() => ({}));
    const password = String(body.password || "");
    if (password.length < 6) return err("密码至少 6 位", 400);
    await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('admin_password_hash', ?)").bind(await hashPassword(password)).run();
    return json({ token: await newSession(env) });
  }
  if (url.pathname === "/api/auth/login" && request.method === "POST") {
    await ensureTables(env);
    const body = await request.json().catch(() => ({}));
    // 限流：同一 IP 5 分钟内错 5 次，锁 15 分钟（防暴力猜密码和 CPU 打满）
    const ip = request.headers.get("cf-connecting-ip") || "unknown";
    const nowSec = Math.floor(Date.now() / 1000);
    let att = null;
    try { att = await env.DB.prepare("SELECT fails, last_at FROM login_attempts WHERE ip=?").bind(ip).first(); } catch {}
    if (att && att.fails >= 5 && nowSec - att.last_at < 900) return err("登录尝试过多，请 15 分钟后再试", 429);
    if (!(await checkPassword(env, String(body.password || "")))) {
      try { await env.DB.prepare("INSERT INTO login_attempts (ip, fails, last_at) VALUES (?, 1, ?) ON CONFLICT(ip) DO UPDATE SET fails = CASE WHEN login_attempts.last_at < ? THEN 1 ELSE login_attempts.fails + 1 END, last_at = excluded.last_at").bind(ip, nowSec, nowSec - 900).run(); } catch {}
      return err("密码不正确", 401);
    }
    try { await env.DB.prepare("DELETE FROM login_attempts WHERE ip=?").bind(ip).run(); } catch {}
    return json({ token: await newSession(env) });
  }
  if (url.pathname === "/api/auth/change" && request.method === "POST") {
    if (!(await auth(request, env))) return err("Unauthorized", 401);
    await ensureTables(env);
    const body = await request.json().catch(() => ({}));
    if (!(await checkPassword(env, String(body.oldPassword || "")))) return err("当前密码不正确", 401);
    const np = String(body.newPassword || "");
    if (np.length < 6) return err("新密码至少 6 位", 400);
    await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('admin_password_hash', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(await hashPassword(np)).run();
    // 先建新会话、再清旧会话：建会话万一失败，当前设备也不会没 token
    const tok = await newSession(env);
    try { await env.DB.prepare("DELETE FROM sessions WHERE token_hash != ?").bind(await sha256hex(tok)).run(); } catch {}
    return json({ token: tok });
  }
  if (url.pathname === "/api/auth/logout" && request.method === "POST") {
    const bearer = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
    if (bearer) { try { await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha256hex(bearer)).run(); } catch {} }
    return json({ ok: true });
  }

  // 绑定 Telegram 机器人：保存前先调 getMe 校验 Token，再调 getChatMember 确认机器人是该频道管理员
  if (url.pathname === "/api/settings/telegram" && request.method === "GET") {
    if (!(await auth(request, env))) return err("Unauthorized", 401);
    const cfg = await getTelegramConfig(env);
    let username = null;
    try { const row = await env.DB.prepare("SELECT value FROM settings WHERE key='tg_bot_username'").first(); username = row?.value || null; } catch {}
    return json({ configured: !!(cfg.botToken && cfg.chatId), hasBotToken: !!cfg.botToken, chatId: cfg.chatId || null, botUsername: username, fromEnv: !!(env.TG_BOT_TOKEN && env.TG_CHAT_ID) });
  }
  if (url.pathname === "/api/settings/telegram" && request.method === "POST") {
    if (!(await auth(request, env))) return err("Unauthorized", 401);
    await ensureTables(env);
    const body = await request.json().catch(() => ({}));
    const botToken = String(body.botToken || "").trim();
    const chatId = String(body.chatId || "").trim();
    if (!botToken && !chatId) {
      // 配置来自部署变量时，页面解绑不生效（前端已禁用按钮，接口也挡一下）
      if (env.TG_BOT_TOKEN || env.TG_CHAT_ID) return err("当前由部署变量提供，页面修改不生效", 400);
      await env.DB.batch([
        env.DB.prepare("DELETE FROM settings WHERE key='tg_bot_token'"),
        env.DB.prepare("DELETE FROM settings WHERE key='tg_chat_id'"),
        env.DB.prepare("DELETE FROM settings WHERE key='tg_bot_username'"),
      ]);
      return json({ configured: false });
    }
    // Token 留空时沿用已保存的 Token（已绑定后只换频道不用重填）
    let tokenToUse = botToken;
    if (!tokenToUse) { const cfg = await getTelegramConfig(env); tokenToUse = cfg.botToken || ""; }
    if (!tokenToUse) return err("请填写机器人 Token", 400);
    if (!/^\d+:[A-Za-z0-9_-]{35}$/.test(tokenToUse)) return err("机器人 Token 格式不对（应为 数字:35位字符）", 400);
    if (!/^-100\d+$/.test(chatId)) return err("频道 ID 格式不对（应为 -100 开头的数字）", 400);
    let me;
    try { me = await (await fetch(`https://api.telegram.org/bot${tokenToUse}/getMe`)).json(); }
    catch { return err("连接 Telegram 失败，请稍后重试", 502); }
    if (!me.ok) return err("机器人 Token 无效（Telegram 返回：" + (me.description || "Unauthorized") + "）", 400);
    let member;
    try {
      member = await (await fetch(`https://api.telegram.org/bot${tokenToUse}/getChatMember`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ chat_id: chatId, user_id: me.result.id }) })).json();
    } catch { return err("连接 Telegram 失败，请稍后重试", 502); }
    if (!member.ok) return err("频道 ID 无效或机器人不在该频道（" + (member.description || "") + "）", 400);
    if (member.result.status !== "administrator" && member.result.status !== "creator") return err("机器人不是该频道管理员，请先把机器人加为频道管理员", 400);
    const username = "@" + (me.result.username || "");
    await env.DB.batch([
      env.DB.prepare("INSERT INTO settings (key, value) VALUES ('tg_bot_token', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(tokenToUse),
      env.DB.prepare("INSERT INTO settings (key, value) VALUES ('tg_chat_id', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(chatId),
      env.DB.prepare("INSERT INTO settings (key, value) VALUES ('tg_bot_username', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(username),
    ]);
    return json({ configured: true, chatId, botUsername: username });
  }

  if (!(await auth(request, env))) return err("Unauthorized", 401);

  if (url.pathname === "/api/stats" && request.method === "GET") {
    const total = await env.DB.prepare("SELECT COUNT(*) AS c FROM images WHERE status='active'").first();
    const bytes = await env.DB.prepare("SELECT COALESCE(SUM(size_bytes),0) AS s FROM images WHERE status='active'").first();
    const today = await env.DB.prepare("SELECT COUNT(*) AS c FROM images WHERE status='active' AND date(created_at,'+8 hours') = date('now','+8 hours')").first();
    const deleting = await env.DB.prepare("SELECT COUNT(*) AS c FROM images WHERE status='deleting'").first();
    const n = total?.c || 0;
    return json({ total: n, totalBytes: bytes?.s || 0, today: today?.c || 0, success: n, deleting: deleting?.c || 0 });
  }

  if (url.pathname === "/api/images" && request.method === "GET") {
    const page = Math.max(1, Number(url.searchParams.get("page") || 1));
    const limit = Math.min(60, Math.max(1, Number(url.searchParams.get("limit") || 24)));
    const q = (url.searchParams.get("q") || "").trim().slice(0, 120);
    const filter = url.searchParams.get("filter") || "";
    const where = filter === "today"
      ? "status = 'active' AND date(created_at,'+8 hours') = date('now','+8 hours')"
      : "status = 'active'";
    // 服务端排序（白名单拼 ORDER BY，全库排，不再只排当前页）；LIKE 里的 % _ \ 先转义
    const orderBy = { new: "created_at DESC", old: "created_at ASC", big: "size_bytes DESC", small: "size_bytes ASC" }[url.searchParams.get("sort") || "new"] || "created_at DESC";
    const likeQ = "%" + q.replace(/[%_\\]/g, (m) => "\\" + m) + "%";
    const count = q
      ? await env.DB.prepare(`SELECT COUNT(*) AS total FROM images WHERE ${where} AND original_name LIKE ? ESCAPE '\\'`).bind(likeQ).first()
      : await env.DB.prepare(`SELECT COUNT(*) AS total FROM images WHERE ${where}`).first();
    const stmt = q
      ? env.DB.prepare(`SELECT id, original_name, mime_type, size_bytes, created_at FROM images WHERE ${where} AND original_name LIKE ? ESCAPE '\\' ORDER BY ${orderBy} LIMIT ? OFFSET ?`).bind(likeQ, limit, (page - 1) * limit)
      : env.DB.prepare(`SELECT id, original_name, mime_type, size_bytes, created_at FROM images WHERE ${where} ORDER BY ${orderBy} LIMIT ? OFFSET ?`).bind(limit, (page - 1) * limit);
    const { results = [] } = await stmt.all();
    return json({ items: results, total: count?.total || 0, page, limit, pages: Math.max(1, Math.ceil((count?.total || 0) / limit)) });
  }

  if (url.pathname === "/api/upload" && request.method === "POST") {
    const cfg = await getTelegramConfig(env);
    if (!cfg.botToken || !cfg.chatId) return err("未绑定 Telegram 机器人，请先在设置里绑定", 400);
    const form = await request.formData();
    const files = form.getAll("files").filter(x => x instanceof File);
    if (!files.length) return err("请先选择图片");
    if (files.length > 20) return err("单次最多上传20张图片");
    // 单张上传：并行发 Telegram（并发 4），不再一张一张等
    async function uploadOne(file) {
      if (!isImage(file.type)) return { name: file.name, ok: false, error: "仅支持图片格式" };
      if (file.size > 20 * 1024 * 1024) return { name: file.name, ok: false, error: "单张图片最大20MB" };
      try {
        const fd = new FormData();
        fd.set("chat_id", cfg.chatId);
        fd.set("document", file, cleanName(file.name));
        const tgRes = await fetch(telegram(cfg.botToken, "sendDocument"), { method: "POST", body: fd });
        const tg = await tgRes.json();
        if (!tg.ok) throw new Error(tg.description || "Telegram上传失败");
        const doc = tg.result.document;
        const id = crypto.randomUUID();
        await env.DB.prepare(`INSERT INTO images (id, original_name, mime_type, size_bytes, telegram_chat_id, telegram_message_id, telegram_file_id, telegram_file_unique_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
          .bind(id, cleanName(file.name), file.type || "application/octet-stream", file.size, cfg.chatId, tg.result.message_id, doc.file_id, doc.file_unique_id || null).run();
        return { name: file.name, ok: true, id, url: `${url.origin}/i/${id}` };
      } catch (e) { return { name: file.name, ok: false, error: e.message || "上传失败" }; }
    }
    const out = new Array(files.length);
    let next = 0;
    await Promise.all(Array.from({ length: Math.min(4, files.length) }, async () => {
      while (next < files.length) { const i = next++; out[i] = await uploadOne(files[i]); }
    }));
    return json({ results: out });
  }

  if (url.pathname === "/api/delete" && request.method === "POST") {
    const cfg = await getTelegramConfig(env);
    const body = await request.json().catch(() => ({}));
    const ids = [...new Set((Array.isArray(body.ids) ? body.ids : []).filter(x => typeof x === "string"))].slice(0, 100);
    if (!ids.length) return err("没有选择图片");
    // 一次查出全部行、一次批量标为 deleting（列表只显示 active，立即隐藏）
    const placeholders = ids.map(() => "?").join(",");
    const { results: rows = [] } = await env.DB.prepare(`SELECT * FROM images WHERE id IN (${placeholders}) AND status='active'`).bind(...ids).all();
    if (rows.length) {
      await batchChunked(env, rows.map(r => env.DB.prepare("UPDATE images SET status='deleting' WHERE id=?").bind(r.id)));
      // 清缓存：serveImage 用的是 ?v=2 的键，旧键也一起清
      ctx.waitUntil(Promise.all(rows.flatMap(r => [
        caches.default.delete(new Request(`${url.origin}/i/${r.id}?v=2`)),
        caches.default.delete(new Request(`${url.origin}/i/${r.id}`)),
      ])));
    }
    if (!cfg.botToken) {
      if (rows.length) await batchChunked(env, rows.map(r => env.DB.prepare("UPDATE images SET delete_error=? WHERE id=?").bind("未绑定 Telegram 机器人，请先在设置里绑定", r.id)));
      return json({ deleted: 0, queued: rows.length, hidden: rows.length });
    }
    // Telegram 删除并行发，不再一张一张等
    const settled = await Promise.allSettled(rows.map(async (row) => {
      const r = await fetch(telegram(cfg.botToken, "deleteMessage"), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ chat_id: row.telegram_chat_id, message_id: row.telegram_message_id }) });
      const j = await r.json();
      if (!j.ok && !/message to delete not found/i.test(j.description || "")) throw new Error(j.description || "Telegram删除失败");
      return row.id;
    }));
    const okIds = [], failList = [];
    settled.forEach((s, i) => { if (s.status === "fulfilled") okIds.push(rows[i].id); else failList.push({ id: rows[i].id, error: String(s.reason?.message || s.reason || "Telegram删除失败").slice(0, 500) }); });
    const stmts = [
      ...okIds.map(id => env.DB.prepare("DELETE FROM images WHERE id=?").bind(id)),
      ...failList.map(f => env.DB.prepare("UPDATE images SET delete_error=? WHERE id=?").bind(f.error, f.id)),
    ];
    if (stmts.length) await batchChunked(env, stmts);
    return json({ deleted: okIds.length, queued: failList.length, hidden: rows.length });
  }
  return err("Not found", 404);
}

async function serveImage(request, env, ctx) {
  const url = new URL(request.url);
  const id = url.pathname.split("/").pop();
  const cache = caches.default;
  // v2 缓存键：旧缓存里存的是 attachment（强制下载），换键后不再命中旧缓存
  const cacheKey = new Request(`${url.origin}/i/${id}?v=2`);
  const cached = await cache.match(cacheKey);
  if (cached) return cached;
  const row = await env.DB.prepare("SELECT * FROM images WHERE id=? AND status='active'").bind(id).first();
  if (!row) return new Response("Not found", { status: 404 });
  const cfg = await getTelegramConfig(env);
  if (!cfg.botToken) return new Response("未绑定 Telegram 机器人，请先在设置里绑定", { status: 503 });
  const gf = await fetch(telegram(cfg.botToken, "getFile"), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ file_id: row.telegram_file_id }) });
  const gj = await gf.json();
  if (!gj.ok || !gj.result?.file_path) return new Response("Telegram file unavailable", { status: 502 });
  const fileUrl = `https://api.telegram.org/file/bot${cfg.botToken}/${gj.result.file_path}`;
  const upstream = await fetch(fileUrl);
  if (!upstream.ok) return new Response("Image fetch failed", { status: 502 });
  const headers = new Headers(upstream.headers);
  const ext = (row.original_name || "").split(".").pop().toLowerCase();
  const extCt = { png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", webp: "image/webp", gif: "image/gif", avif: "image/avif", bmp: "image/bmp", svg: "image/svg+xml" }[ext];
  headers.set("content-type", (row.mime_type && row.mime_type.startsWith("image/")) ? row.mime_type : (extCt || headers.get("content-type") || "application/octet-stream"));
  // 浏览器内直接预览而不是下载：Telegram 上游返回的是 attachment，这里改成 inline
  headers.set("content-disposition", "inline; filename*=UTF-8''" + encodeURIComponent(row.original_name || "image"));
  headers.set("cache-control", "public, max-age=86400, s-maxage=604800");
  headers.set("access-control-allow-origin", "*");
  headers.set("x-content-type-options", "nosniff");
  // SVG 里内嵌的脚本跑不起来：沙箱后直接打开直链也不会执行（<img> 引用不受影响）
  headers.set("content-security-policy", "sandbox");
  const response = new Response(upstream.body, { status: 200, headers });
  ctx.waitUntil(cache.put(cacheKey, response.clone()));
  return response;
}

async function retryDeletes(env) {
  const cfg = await getTelegramConfig(env);
  if (!cfg.botToken) return;
  // 每 15 分钟一轮，最多重试 96 轮（约 24 小时）就停手，不再无限重试
  const { results = [] } = await env.DB.prepare("SELECT id, telegram_chat_id, telegram_message_id FROM images WHERE status='deleting' AND delete_attempts < 96 LIMIT 50").all();
  for (const row of results) {
    try {
      const r = await fetch(telegram(cfg.botToken, "deleteMessage"), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ chat_id: row.telegram_chat_id, message_id: row.telegram_message_id }) });
      const j = await r.json();
      if (j.ok || /message to delete not found/i.test(j.description || "")) await env.DB.prepare("DELETE FROM images WHERE id=?").bind(row.id).run();
      else await env.DB.prepare("UPDATE images SET delete_error=?, delete_attempts=delete_attempts+1 WHERE id=?").bind(j.description || "Telegram删除失败", row.id).run();
    } catch (e) { await env.DB.prepare("UPDATE images SET delete_error=?, delete_attempts=delete_attempts+1 WHERE id=?").bind(String(e.message).slice(0, 500), row.id).run(); }
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    try { await ensureTables(env); } catch {}
    if (url.pathname.startsWith("/api/")) return api(request, env, ctx);
    if (url.pathname.startsWith("/i/")) return serveImage(request, env, ctx);
    return env.ASSETS.fetch(request);
  },
  async scheduled(event, env, ctx) {
    await ensureTables(env);
    // 顺带清过期会话和过期的登录失败记录
    const nowSec = Math.floor(Date.now() / 1000);
    try { await env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(nowSec).run(); } catch {}
    try { await env.DB.prepare("DELETE FROM login_attempts WHERE last_at < ?").bind(nowSec - 3600).run(); } catch {}
    ctx.waitUntil(retryDeletes(env));
  }
};
