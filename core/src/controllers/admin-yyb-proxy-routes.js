const YYB_REQUEST_TIMEOUT_MS = 65000;

function normalizeYybApiBase(raw) {
  const base = String(raw || "").trim().replace(/\/+$/, "");
  if (!base) return null;
  return base;
}

function yybHeaders(apiKey) {
  const headers = {
    Accept: "application/json",
  };
  const key = String(apiKey || "").trim();
  if (key) headers.Authorization = `Bearer ${key}`;
  return headers;
}

async function yybFetch(url, { method = "GET", body, apiKey } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), YYB_REQUEST_TIMEOUT_MS);
  try {
    const options = {
      method,
      headers: yybHeaders(apiKey),
      signal: controller.signal,
    };
    if (body !== undefined) {
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(body);
    }
    const response = await fetch(url, options);
    const text = await response.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      throw new Error(`应用宝服务返回了无效响应（HTTP ${response.status}）`);
    }
    if (!response.ok) {
      const msg = data?.msg || data?.error || `应用宝服务请求失败（HTTP ${response.status}）`;
      const err = new Error(msg);
      err.yybCode = data?.code;
      err.status = response.status;
      throw err;
    }
    return data?.data !== undefined ? data.data : data;
  } catch (error) {
    if (error && error.name === "AbortError") throw new Error("应用宝服务请求超时");
    if (error && error.yybCode) throw error;
    throw new Error(`无法连接应用宝服务：${error && error.message ? error.message : "网络错误"}`);
  } finally {
    clearTimeout(timer);
  }
}

function registerAdminYybProxyRoutes({ app, store }) {
  const resolveTarget = (req) => {
    const { apiBase, apiKey } = req.body || {};
    const cfg = store.getGlobalWxConfig() || {};
    const target = normalizeYybApiBase(apiBase || cfg.apiBase);
    if (!target) {
      const err = new Error("请先配置应用宝接口地址");
      err.yybCode = 400;
      throw err;
    }
    const key = String(apiKey || cfg.apiKey || "").trim();
    return { target, key };
  };

  const sendError = (res, error) => {
    const status = error && error.status && Number(error.status) >= 400 ? Number(error.status) : 500;
    res.status(status).json({
      ok: false,
      error: error && error.message ? error.message : "应用宝服务请求失败",
      yybCode: error && error.yybCode ? error.yybCode : undefined,
    });
  };

  app.post("/api/yyb/qr/create", async (req, res) => {
    try {
      const { target, key } = resolveTarget(req);
      const data = await yybFetch(`${target}/qr?as_base64=true`, {
        method: "POST",
        apiKey: key,
      });
      res.json({ ok: true, data });
    } catch (error) {
      sendError(res, error);
    }
  });

  app.post("/api/yyb/qr/poll", async (req, res) => {
    try {
      const { sessionId } = req.body || {};
      if (!sessionId) return res.status(400).json({ ok: false, error: "缺少 sessionId", yybCode: 400 });
      const { target, key } = resolveTarget(req);
      const data = await yybFetch(`${target}/qr/${encodeURIComponent(sessionId)}/poll`, {
        apiKey: key,
      });
      res.json({ ok: true, data });
    } catch (error) {
      sendError(res, error);
    }
  });

  app.post("/api/yyb/qr/confirm", async (req, res) => {
    try {
      const { sessionId } = req.body || {};
      if (!sessionId) return res.status(400).json({ ok: false, error: "缺少 sessionId", yybCode: 400 });
      const { target, key } = resolveTarget(req);
      const data = await yybFetch(`${target}/qr/${encodeURIComponent(sessionId)}/confirm`, {
        method: "POST",
        apiKey: key,
      });
      res.json({ ok: true, data });
    } catch (error) {
      sendError(res, error);
    }
  });

  app.post("/api/yyb/getcode", async (req, res) => {
    try {
      const { openid } = req.body || {};
      if (!openid) return res.status(400).json({ ok: false, error: "缺少 openid", yybCode: 400 });
      const { target, key } = resolveTarget(req);
      const data = await yybFetch(`${target}/wxapp/getCode`, {
        method: "POST",
        body: { openid, forceRefresh: true },
        apiKey: key,
      });
      res.json({ ok: true, data });
    } catch (error) {
      sendError(res, error);
    }
  });
}

module.exports = { registerAdminYybProxyRoutes };
