# P-0048 · módulo de servidor para el panel existente

Continúa `feature/p0048-contentops-prototype`. No sustituye `main`, el sitio público, n8n o Mis pendientes. El HTML de `contentops-demo/index.html` se conserva como referencia UX; el módulo real usa formularios de servidor.

## Estado comprobado

Ocho pruebas HTTP locales cubren login real con contraseñas aleatorias, aislamiento entre dos agentes ficticios, V1 → solicitud → V2 → aprobación ligada al hash, persistencia en disco y reapertura de la aplicación, rechazo de versión obsoleta, idempotencia, CSRF, escape HTML, baja y revocación, carga en cuarentena y consumos por job sin doble cargo. También se conservan las 13 pruebas del panel anterior. No equivale a prueba en navegador o en el servidor desplegado.

## Integración sin duplicar infraestructura

- Misma aplicación Flask, dependencias existentes, cookie Secure/HttpOnly/SameSite y clave de sesión del panel.
- Misma base `auth.sqlite` y volumen `/data` del panel. Tablas `co_*` nuevas para datos de ContentOps. No se usa la base de n8n ni se copian pendientes de Google Sheets.
- El titular conserva su login original. Las sesiones de agentes se resuelven contra otra tabla en la misma base y **no** satisfacen el acceso del titular. No existe selector de rol cliente ni registro público.
- `KYPH_CONTENTOPS=1` habilita el módulo y su migración aditiva. Por defecto queda cerrado. `KYPH_CONTENTOPS_UPLOADS=1` se permite solo tras comprobar capacidad, respaldo y almacenamiento privado. No configurar otros servicios.
- Los archivos se guardan con nombre opaco y permisos0600, sin ruta pública o reproducción. Se vinculan a un guion/versión aprobados. Máximo100MiB por archivo y500MiB por agente; esto no acredita capacidad disponible del servidor. Permanecen en CUARENTENA: validar contenedor y seguridad antes de procesar. No hay envío a Descript, edición, recargas o publicaciones.
- El consumo admite un registro manual por job verificado por el titular. No verifica la API de Descript ni inventa saldo400. El saldo muestra NO CONCILIADO. No prometer integración de consumo automático.

## Preparar una actualización revisable

Recuperar PRIVADAMENTE el `app.py` y Dockerfile actuales de `kyph/kyph-panel-test`. El paquete anterior de Implementación03 se encontró en los archivos del titular, pero la versión1.2.0 en healthz no demuestra igualdad de código. Comparar la fuente viva antes de desplegar.

Ejecutar `python integrate.py --app /ruta/privada/app.py --docker /ruta/privada/Dockerfile --output /ruta/privada/revision_nueva`.

El integrador comprueba que ambas fuentes coinciden, prepara otra copia y se detiene si los puntos de integración difieren. No modifica el servicio. **No subir a GitHub el app.py original, Dockerfile generado, volumen, base de autenticación, claves o credencial Google del panel personal.** El repositorio es público; sus ramas también lo son. Solo este módulo genérico, el integrador y pruebas ficticias se guardan ahí.

En una copia privada junto al app.py preparado, ejecutar las pruebas existentes y `python -m unittest test_contentops -v`. Se necesita Flask3.1.3, ya usado por el panel. No se requiere otra licencia.

## Prueba real pendiente

1. Acceder a Easypanel y comparar la fuente actual. Respaldar el volumen propio con restauración comprobable. Conservar secretos, montaje, límites, TLS y servicios vecinos.
2. Actualizar exclusivamente el mismo servicio con código revisado y habilitar ContentOps. No invitar personas reales.
3. David entra por `/login` y abre `/contentops/admin`. Crear dos identidades de prueba autorizadas. Nunca publicar contraseñas en el reporte.
4. Asignar V1 al primero. En otra sesión/navegador entra por `/contentops/login`, pide cambios. David preparaV2. El agente apruebaV2, sale y vuelve. Verificar versión, hash, solicitud resuelta, aprobación y bitácora en el volumen.
5. Probar acceso denegado al guion del otro agente, a Mis pendientes y API del titular. Verificar sesión revocada al salir o dar baja.
6. Habilitar carga solo después de comprobar el almacenamiento. Probar archivo sintético y rechazo de formato. El piloto de video real y edición siguen bloqueados por créditos/licencia de Descript.

## Reversión

Deshabilitar `KYPH_CONTENTOPS` y desplegar solo el mismo servicio para cerrar las rutas. Conservar tablas/archivos y su respaldo para evitar pérdida. No borrar datos con una reversión automática. El código anterior del panel y sus sesiones siguen siendo la base. No restaurar todo el volumen sobre cambios recientes de Mis pendientes o autenticación sin reconciliarlo.

## Kypi

Trabajo independiente sobre Core y receptor existentes. No se modifica desde este módulo. El objetivo autorizado es respuesta automática privada en Instagram, no aprobación mensaje a mensaje. Antes de habilitar: identidad Kypi, firma, deduplicación y reserva de envío, opt-out, pausa humana y prueba controlada. Una visita a wa.me no acredita llegada al WhatsApp laboral. Falta recepción auténtica del mensaje de WhatsApp y asociación verificada de identidad/contexto antes de marcar la transferencia.
