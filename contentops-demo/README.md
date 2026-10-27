# P-0048 · KYPH ContentOps

La rama existente conserva `contentops-demo/index.html` como referencia visual v0.1 y añade `contentops-demo/panel/` con integración al panel Flask privado existente.

**Estado actual: módulo de servidor probado localmente, NO desplegado.** 21 pruebas: 8 nuevas de ContentOps y 13 regresiones del panel. No equivalen a acceso real de agente en producción.

## Avance
- Login de agentes separado del titular dentro del mismo servicio, cookie y volumen SQLite del panel.
- V1 → solicitud de cambios → V2 → aprobación ligada a versión y hash, con bitácora transaccional y persistencia tras reapertura.
- Restricciones por agente, CSRF, rechazo de versiones obsoletas, baja y revocación.
- Carga privada en cuarentena vinculada a guion aprobado; apagada por defecto hasta revisar capacidad y respaldo.
- Registro manual de consumo verificado por job sin duplicación. Saldo NO CONCILIADO; sin llamada a Descript.

No se habilitó ningún agente real, no se consumieron créditos y no se publicó contenido. El prototipo HTML con selector de roles sigue siendo solo una demo y nunca autentica usuarios.

## Antes de desplegar
Leer `panel/README.md`. Se recuperó el paquete privado de Implementación03, pero falta comparar el código vivo en Easypanel. `integrate.py` prepara una copia revisable y se detiene si la fuente difiere. Mantener `main`, la web pública, n8n y otros servicios intactos.

**Este repositorio y sus ramas son públicos.** No guardar aquí el app.py personal recuperado, Dockerfile generado con esa fuente, bases, claves, sesiones, archivos de agentes ni credenciales de Google.

Las portadas y los guiones editoriales reales permanecen privados en P-0048. Las pruebas del módulo usan identidades ficticias. Kypi se trabaja por separado en sus workflows existentes; no se activa desde esta aplicación.
