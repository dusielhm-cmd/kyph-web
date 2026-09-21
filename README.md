# KYPH Web

Sitio institucional de KYPH y punto de retorno OAuth para integraciones autorizadas.

## Producción
- Sitio: https://www.kyphseguros.com/
- Privacidad: https://www.kyphseguros.com/aviso-de-privacidad.html
- Términos: https://www.kyphseguros.com/terminos-de-servicio.html
- TikTok OAuth callback: https://www.kyphseguros.com/api/tiktok/callback
- Página privada de conexión: https://www.kyphseguros.com/tiktok-connect.html

## TikTok OAuth
Una sola app KYPH / sandbox KYPH TEST autoriza por separado:
- M40 / Pensiones
- PPR / Pediatras

Scopes:
- user.info.basic
- video.publish
- video.upload

Variables de entorno de Vercel:
- TIKTOK_CLIENT_KEY
- TIKTOK_CLIENT_SECRET
- TIKTOK_REDIRECT_URI
- TIKTOK_TOKEN_WEBHOOK_URL (pendiente)
- TIKTOK_TOKEN_WEBHOOK_SECRET (recomendado)

El flujo usa state firmado y cookie HttpOnly/Secure para prevenir CSRF. El callback intercambia el authorization code del lado servidor y nunca muestra tokens en el navegador. Para activar las autorizaciones finales se requiere un webhook privado donde persistir los tokens.

## Seguridad
- Nunca exponer Client Secret, access_token o refresh_token en frontend, Git o capturas.
- La página de conexión mantiene los botones deshabilitados mientras no exista TIKTOK_TOKEN_WEBHOOK_URL.
- Los tokens deben persistirse en un almacén privado y manejar renovación antes de su vencimiento.
