import crypto from "node:crypto";

const ACCOUNT_LABELS = {
  m40: "Modalidad 40 / Pensiones",
  ppr: "PPR / Pediatras",
};

function sign(value, secret) {
  return crypto.createHmac("sha256", secret).update(value).digest("base64url");
}

export default function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).send("Method Not Allowed");
  }

  const clientKey = process.env.TIKTOK_CLIENT_KEY;
  const clientSecret = process.env.TIKTOK_CLIENT_SECRET;
  const redirectUri = process.env.TIKTOK_REDIRECT_URI;

  if (!clientKey || !clientSecret || !redirectUri) {
    return res.status(500).send("TikTok OAuth is not configured.");
  }

  const account = String(req.query?.account || "").toLowerCase();
  if (!ACCOUNT_LABELS[account]) {
    return res.status(400).send("Unknown TikTok account route.");
  }

  const state = crypto.randomBytes(32).toString("base64url");
  const payload = Buffer.from(
    JSON.stringify({ state, account, ts: Date.now() }),
    "utf8"
  ).toString("base64url");
  const signature = sign(payload, clientSecret);
  const cookieValue = encodeURIComponent(`${payload}.${signature}`);

  res.setHeader(
    "Set-Cookie",
    `kyph_tiktok_oauth=${cookieValue}; Max-Age=600; Path=/api/tiktok; HttpOnly; Secure; SameSite=Lax`
  );

  const params = new URLSearchParams({
    client_key: clientKey,
    response_type: "code",
    scope: "user.info.basic,video.publish,video.upload",
    redirect_uri: redirectUri,
    state,
    disable_auto_auth: "1",
  });

  return res.redirect(302, `https://www.tiktok.com/v2/auth/authorize/?${params.toString()}`);
}
