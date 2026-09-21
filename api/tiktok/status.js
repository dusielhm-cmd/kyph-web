export default function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  return res.status(200).json({
    clientConfigured: Boolean(
      process.env.TIKTOK_CLIENT_KEY &&
      process.env.TIKTOK_CLIENT_SECRET &&
      process.env.TIKTOK_REDIRECT_URI
    ),
    tokenWebhookConfigured: Boolean(process.env.TIKTOK_TOKEN_WEBHOOK_URL),
  });
}
