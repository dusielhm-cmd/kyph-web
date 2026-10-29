# ContentOps · respaldo y restauración antes del despliegue

PASS local: 4 pruebas de recuperación con datos ficticios. No hay respaldo de producción verificado. No se contactó Easypanel, no se desplegó código, no se modificó un servicio ni se generaron datos reales.

## Qué hace

`panel_backup.py` respalda PRIVADAMENTE el volumen completo del panel: SQLite, clave de sesión, archivos de conexión existentes y archivos privados. Los respaldos **contienen secretos** y deben permanecer bajo control del titular, fuera de GitHub, chats y enlaces públicos. No son cifrados; los permisos locales 0700/0600 no sustituyen cifrado ni control del almacenamiento remoto.

Utiliza SQLite Backup API, valida integridad y tablas necesarias, calcula hashes SHA256 y detecta archivos extra, faltantes o alterados. La copia de base se normaliza a journal DELETE; incluye cambios confirmados que estaban en WAL. No copia el índice volátil SHM ni deja archivos WAL como sustituto del respaldo consistente. Compara la fuente antes/después y cancela si detecta cambios relevantes.

**Solo uso offline:** detener externamente las escrituras del mismo servicio y confirmar la parada. El flag `--offline-confirmed` es una declaración del operador, NO comprueba ni detiene procesos. No utilizar mientras esté sirviendo solicitudes. No introducir tareas automáticas de copia todavía.

Restaurar únicamente a una carpeta NUEVA y privada. Nunca sobreescribir el volumen vivo. El script valida antes de copiar y no conecta la restauración al servicio. Las carpetas vacías no contienen datos del panel; la restauración se limita a archivos y crea los directorios necesarios.

Los hashes detectan corrupción accidental; no prueban autenticidad frente a alguien que pudiera cambiar los archivos y el manifiesto. Guardar una copia separada del manifiesto en un destino confiable cuando se opere en el servidor.

## Procedimiento pendiente en la instalación real

1. Con acceso autorizado, revisar fuente viva y configuración del servicio existente. Registrar código y variables necesarias sin exponer valores.
2. Confirmar dónde está el volumen y elegir un destino privado fuera de él, con capacidad suficiente. No inferir que `/data` en el contenedor equivale a una ruta del host.
3. Acordar una ventana breve para detener escrituras SOLO del panel, sin cambiar n8n u otros servicios. Confirmar la parada.
4. Ejecutar backup; validar en destino. Un resultado VERIFIED_BACKUP no basta para aprobar el despliegue.
5. Restaurar en carpeta nueva y comprobar ahí guiones/versiones, solicitudes, aprobaciones y archivos; verificar acceso con la app existente en entorno aislado antes de declarar recuperación integral.
6. Guardar fuente anterior, configuración y respaldo. Comparar fuente actual con integración preparada. Solo entonces aplicar actualización al mismo servicio.
7. Si falla la actualización, volver al código/configuración anterior y conservar los datos nuevos. Restaurar un volumen antiguo sobre cambios recientes requiere conciliación; nunca hacerlo de forma ciega.

Ejemplos genéricos, NO ejecutados sobre producción:

```sh
python panel_backup.py backup /ruta/privada/volumen --destination /ruta/privada/respaldo_nuevo --offline-confirmed
python panel_backup.py verify /ruta/privada/respaldo_nuevo
python panel_backup.py restore /ruta/privada/respaldo_nuevo --destination /ruta/privada/restauracion_nueva
```

## Pruebas ejecutadas

- PASS: ida/vuelta conserva V1/V2, solicitud y aprobación, clave de sesión y archivos; permisos privados.
- PASS: cambios, faltantes, extras y sobrescritura rechazados; restauración inválida no se habilita.
- PASS: requiere confirmación offline; rechaza enlaces simbólicos y destino dentro de la fuente.
- PASS: fila confirmada aún en WAL queda incluida y restaurada.

Para repetir contra una COPIA PRIVADA de la integración existente:

```sh
KYPH_PANEL_SOURCE=/ruta/privada/integracion python -m unittest test_panel_backup -v
```

El test importa `app.py` de esa copia, pero fija DATA_DIR temporal, usa identidades ficticias y elimina los datos al terminar. No usar como directorio de código un volumen de datos. No se guarda ni publica ninguna base, contraseña, clave o credencial. Requiere las dependencias ya utilizadas por el panel; el script de respaldo solo usa biblioteca estándar Python.

## Estado

PARCIAL general. Preparación de recuperación probada localmente; respaldo recuperable y despliegue real siguen pendientes del acceso a Easypanel. El trabajo de este bloque no necesita el ordenador de David encendido ni acceso a su navegador. Ninguna compra, crédito generativo o cambio de ContentOps en vivo.
