# ContentOps · Acceso y administración del piloto privado

## Estado al 4 de noviembre de 2026

PARCIAL. Este manual describe el flujo implementado y el procedimiento pendiente. No certifica que el módulo esté accesible en producción. La ruta de destino es `/contentops/login` en el mismo panel privado; el acceso real no está demostrado.

Bloqueos observados: navegador conectado sin contexto de origen; navegador disponible al abrir Easypanel devuelve ERR_CERT_COMMON_NAME_INVALID y la política de seguridad impide continuar. No eludir advertencias, cambiar configuraciones o introducir credenciales a través de una conexión no validada. Se necesita un acceso autorizado al administrador por HTTPS válido.

## Antes de habilitar

1. Identificar `kyph/kyph-panel-test`, adquirir de forma privada su app.py y Dockerfile actuales y registrar configuración/volumen sin revelar secretos. El código recuperado no sustituye esta comprobación.
2. Comprobar respaldo recuperable y restauración de ese volumen. `RECUPERACION.md` detalla el procedimiento; las pruebas locales de copia no prueban el respaldo real.
3. Ejecutar `integrate.py` sobre la copia revisada. Rechaza incoherencias entre app.py/Dockerfile, guardas diferentes, duplicación de bloques, usuario de contenedor inesperado y salida existente. La preparación es atómica y privada. `integration_report.json` conserva hashes y marca explícitamente fuente viva/respaldo como no verificados.
4. Revisar la salida y la reversión antes de actualizar exclusivamente el mismo servicio. No usar main ni el sitio público. Conservar autenticación, volumen, TLS y credenciales actuales. Habilitar ContentOps; mantener cargas reales deshabilitadas.

## Cómo entra el titular

Usar `/login` del panel original y después `/contentops/admin`. Solo el administrador crea los accesos y asigna V1. No hay registro público ni envío automático de invitaciones. Nunca guardar contraseñas en el reporte.

## Cómo entra un usuario ficticio

Usar `/contentops/login` con su cuenta individual. En “Mis guiones” abre V1, pide un cambio y revisa V2 cuando KYPH la entrega. Marca la aprobación expresa de V2. El sistema guarda usuario, versión, fecha UTC y huella; esta aprobación no publica el material. Puede cerrar sesión desde la cabecera y volver para consultar el historial.

## Prueba pendiente en URL real

Comenzar con dos cuentas ficticias sin contacto con personas reales. Luego asignar los briefs TEST-KYPH-01, TEST-CARMEN-01 y TEST-SFS-01 a tres identidades ficticias separadas, conforme al brief privado existente. Los nombres de los proyectos no implican invitación, autorización de marca ni aprobación por Carmen o Juanma.

En cada recorrido registrar evidencias: URL, login/logout, V1, solicitud, V2, aprobación, reingreso e historial. Desde otro usuario intentar leer/modificar el ID ajeno: debe ser denegado. Probar también administrador, API de pendientes y rutas de archivos privadas. Un clic o captura de maqueta no acredita una sesión real. Registrar PASS solo tras verificar en el servicio vivo, con prueba móvil.

## Créditos y archivos

Sin consumo verificado, mostrar NO CONCILIADO. No asignar una bolsa ficticia. Carga de videos/portadas permanece cerrada; no usar originales privados como fixtures. Los archivos en cuarentena no están aprobados para procesamiento ni publicación.

## Preparación comercial: posterior al PASS de acceso

Hoy existen administrador y usuario agente, con aislamiento por agent_id. **No existe todavía un tipo comercial KYPH/externo ni un espacio compartido de despacho probado.** No presentar esa segmentación como implementada.

Diseño pendiente, sin migración aplicada: clasificar cliente KYPH o externo mediante un atributo administrado por el titular, separado del rol técnico. Un agente externo conserva únicamente permisos de agente y sus materiales; nunca hereda administración, cartera, CRM o archivos centrales. Si un despacho requiere varios colaboradores, resolver primero membresía y alcance explícitos: compartir correo/contraseña o dar rol administrador no es una solución.

Después de acceso real: aplicar identidad/recursos autorizados, biblioteca maestra privada y copias individuales, paquete acordado, renovación manual y consumo por trabajo verificado. No activar cobros automáticos, registro abierto, invitaciones, edición IA ni programación. No inventar paletas/logotipos para Carmen o SFS; Fianzas solo corresponde al brief SFS. Mantener las tres identidades y sus aprobaciones separadas.

## Si falla

No reintentar despliegue sobre diferencias desconocidas. Conservar datos y cerrar el módulo mediante la reversión previamente comprobada del mismo servicio. No restaurar una base vieja sobre cambios recientes sin conciliación. Este documento no autoriza cambios en n8n, Kypi, CRM, cobranza, redes o la web pública.
