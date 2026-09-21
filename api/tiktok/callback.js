import crypto from "node:crypto";

const ACCOUNT_LABELS = {
  m40: "Modalidad 40 / Pensiones",
  ppr: "PPR / Pediatras",
};

function parseCookies(header = "") {
  return Object.fromEntries(
    header.split(";").map(v => v.trim()).filter(Boolean).map(pair => {
      const i = pair.indexOf("=");
      return i >= 0 ? [pair.slice(0, i), pair.slice(i + 1)] : [pair, ""];
    })
  );
}

function sign(value, secret) {
  return crypto.createHmac("sha256", secret).update(value).digest("base64url");
}

function safeEqual(a, b) {
  try {
    const aa = Buffer.from(a);
    const bb = Buffer.from(b);
    return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
  } catch {
    return false;
  }
}

function page(title, body, status = 200) {
  return {
    status,
    html: `<!doctype html>
<html lang="es">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>KYPH | TikTok</title></head>
<body style="font-family:system-ui,sans-serif;max-width:760px;margin:72px auto;padding:0 24px;color:#152033">
<div style="font-weight:800;letter-spacing:.08em;color:#0b2342">KYPH</div>
<h1 style="color:#0b2342">${title}</h1>
${body}
</body></html>`
  };
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", "text/html; charset=utf-8");

  const clientKey = process.env.TIKTOK_CLIENT_KEY;
  const clientSecret = process.env.TIKTOK_CLIENT_SECRET;
  const redirectUri = process.env.TIKTOK_REDIRECT_URI;
  const webhookUrl = process.env.TIKTOK_TOKEN_WEBHOOK_URL;
  const webhookSecret = process.env.TIKTOK_TOKEN_WEBHOOK_SECRET;

  if (!clientKey || !clientSecret || !redirectUri) {
    const p = page("Configuración incompleta", "<p>Faltan credenciales del servidor.</p>", 500);
    return res.status(p.status).send(p.html);
  }

  const { code, state, error, error_description, scopes } = req.query || {};

  if (error) {
    const p = page(
      "No se completó la autorización",
      `<p>TikTok canceló o rechazó la autorización.</p><p><strong>Detalle:</strong> ${String(error_description || error)}</p>`,
      400
    );
    return res.status(p.status).send(p.html);
  }

  const cookies = parseCookies(req.headers.cookie || "");
  const raw = cookies.kyph_tiktok_oauth ? decodeURIComponent(cookies.kyph_tiktok_oauth) : "";
  const dot = raw.lastIndexOf(".");
  if (dot < 1) {
    const p = page("Sesión de autorización inválida", "<p>No se encontró el estado de seguridad de la sesión. Inicia la conexión nuevamente desde KYPH.</p>", 400);
    return res.status(p.status).send(p.html);
  }

  const payload = raw.slice(0, dot);
  const signature = raw.slice(dot + 1);
  if (!safeEqual(signature, sign(payload, clientSecret))) {
    const p = page("Sesión de autorización inválida", "<p>La verificación de seguridad falló.</p>", 400);
    return res.status(p.status).send(p.html);
  }

  let session;
  try {
    session = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    const p = page("Sesión de autorización inválida", "<p>No se pudo leer el estado de seguridad.</p>", 400);
    return res.status(p.status).send(p.html);
  }

  if (!state || state !== session.state || Date.now() - Number(session.ts || 0) > 10 * 60 * 1000) {
    const p = page("Sesión expirada o inválida", "<p>El estado OAuth no coincide o ya expiró. Inicia la conexión nuevamente.</p>", 400);
    return res.status(p.status).send(p.html);
  }

  if (!code) {
    const p = page("Falta el código de autorización", "<p>TikTok no devolvió un código utilizable.</p>", 400);
    return res.status(p.status).send(p.html);
  }

  if (!webhookUrl) {
    const p = page(
      "Almacenamiento seguro pendiente",
      "<p>La autorización llegó correctamente, pero KYPH todavía no tiene configurado el destino privado donde guardar los tokens. No se intercambió el código y no se expuso ningún token.</p><p>Configura el webhook privado y vuelve a iniciar la autorización.</p>",
      503
    );
    return res.status(p.status).send(p.html);
  }

  try {
    const tokenBody = new URLSearchParams({
      client_key: clientKey,
      client_secret: clientSecret,
      code: String(code),
      grant_type: "authorization_code",
      redirect_uri: redirectUri,
    });

    const tokenResp = await fetch("https://open.tiktokapis.com/v2/oauth/token/", {
      method: "POST",
      headers: {"Content-Type": "application/x-www-form-urlencoded"},
      body: tokenBody.toString(),
    });

    const tokenData = await tokenResp.json();
    if (!tokenResp.ok || !tokenData?.access_token || !tokenData?.refresh_token) {
      const p = page("TikTok no entregó los tokens", "<p>El intercambio del código falló. No se guardó ninguna credencial.</p>", 502);
      return res.status(p.status).send(p.html);
    }

    let user = null;
    try {
      const userResp = await fetch(
        "https://open.tiktokapis.com/v2/user/info/?fields=open_id,union_id,display_name,avatar_url",
        { headers: { Authorization: `Bearer ${tokenData.access_token}` } }
      );
      const userData = await userResp.json();
      user = userData?.data?.user || null;
    } catch {}

    const securePayload = {
      source: "kyph-vercel-oauth",
      account: session.account,
      account_label: ACCOUNT_LABELS[session.account] || session.account,
      received_at: new Date().toISOString(),
      granted_scopes: String(scopes || tokenData.scope || ""),
      user,
      token: {
        access_token: tokenData.access_token,
        refresh_token: tokenData.refresh_token,
        expires_in: tokenData.expires_in,
        refresh_expires_in: tokenData.refresh_expires_in,
        open_id: tokenData.open_id,
        scope: tokenData.scope,
        token_type: tokenData.token_type,
      },
    };

    const headers = {"Content-Type": "application/json"};
    if (webhookSecret) headers["x-make-apikey"] = webhookSecret;

    const hookResp = await fetch(webhookUrl, {
      method: "POST",
      headers,
      body: JSON.stringify(securePayload),
    });

    if (!hookResp.ok) {
      const p = page("No se pudieron guardar los tokens", "<p>TikTok autorizó correctamente, pero el almacenamiento privado respondió con error. Los tokens no se mostraron en el navegador.</p>", 502);
      return res.status(p.status).send(p.html);
    }

    res.setHeader("Set-Cookie", "kyph_tiktok_oauth=; Max-Age=0; Path=/api/tiktok; HttpOnly; Secure; SameSite=Lax");

    const displayName = user?.display_name ? `<p><strong>Cuenta:</strong> ${String(user.display_name)}</p>` : "";
    const p = page(
      "TikTok conectado",
      `<p>La autorización de <strong>${ACCOUNT_LABELS[session.account] || session.account}</strong> quedó completada.</p>${displayName}<p>Los tokens fueron enviados al almacenamiento privado de KYPH y no se mostraron en el navegador.</p><p>Puedes cerrar esta ventana.</p>`
    );
    return res.status(p.status).send(p.html);
  } catch {
    const p = page("Error al completar OAuth", "<p>Ocurrió un error del servidor durante la autorización. Intenta nuevamente.</p>", 500);
    return res.status(p.status).send(p.html);
  }
}
