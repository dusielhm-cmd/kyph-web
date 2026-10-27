# P-0048 · KYPH ContentOps (prototipo aislado)

Esta rama abre la construcción de ContentOps sin modificar el sitio institucional ni sus callbacks OAuth.

**Estado: prototipo local v0.1, no desplegado ni habilitado para agentes.** El código HTML funcional fue generado como paquete entregable `kyph-contentops-prototipo-v01.zip` durante la sesión de preparación. Aún debe incorporarse a esta rama tras revisar que no contiene datos personales y terminar pruebas visuales.

## Funciones ya maquetadas
- Resumen por cuenta demo.
- Guiones V1 → comentarios → V2 preparada por KYPH → aprobación del agente.
- Solicitudes y estados de videos.
- Saldo de referencia 400 créditos; no se descuentan créditos simulando consumo real.
- Portadas de colores vivos y QA audiovisual V4 de los frentes 01 M40, 02 Seguros y PPR, 03 Reclutamiento.
- Alternancia de rol para **demo solamente**, sin acceso real.

## Gates antes de habilitar usuarios
1. Autenticación y permisos del lado servidor por agente, pruebas de aislamiento y privacidad.
2. Backend persistente y versionado de guiones, aprobaciones y bitácora.
3. Carga privada de archivos y QA, AV y URLs firmadas, control de cuota.
4. Licencia comercial, API y créditos disponibles de Descript.
5. Conciliación exacta de consumo por job y por agente.
6. Seguridad, consentimiento, aprobación/publicación y despliegue protegido.

**Reglas:** no compartir datos reales, no tocar `main`, no comprar ni publicar, no modificar el logotipo oficial azul marino KYPH. WildMoney no pertenece a este proyecto.
