export default function handler(req, res) {
  const { code, state, error, error_description } = req.query || {};

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");

  if (error) {
    return res.status(400).send(`<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>KYPH | TikTok</title></head>
<body style="font-family:system-ui,sans-serif;max-width:720px;margin:80px auto;padding:0 24px">
<h1>No se completó la autorización</h1>
<p>TikTok devolvió un error durante el proceso de autorización.</p>
<p>Puedes cerrar esta ventana y volver a KYPH.</p>
</body></html>`);
  }

  if (!code) {
    return res.status(200).send(`<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>KYPH | TikTok OAuth</title></head>
<body style="font-family:system-ui,sans-serif;max-width:720px;margin:80px auto;padding:0 24px">
<h1>KYPH · TikTok OAuth</h1>
<p>El endpoint de retorno para la autorización de TikTok está activo.</p>
</body></html>`);
  }

  return res.status(200).send(`<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>KYPH | TikTok</title></head>
<body style="font-family:system-ui,sans-serif;max-width:720px;margin:80px auto;padding:0 24px">
<h1>Autorización recibida</h1>
<p>KYPH recibió la respuesta de TikTok. Puedes cerrar esta ventana.</p>
</body></html>`);
}
