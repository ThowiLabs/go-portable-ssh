# Registro de versiones

## v0.1.0

Primera versión independiente del módulo Go.

- Cliente SSH con autenticación configurable, sesiones y ejecución de comandos.
- Verificación por huella digital SHA-256 y descubrimiento seguro de claves desconocidas.
- Contextos cancelables, timeout de negociación, salida acotada y código de salida.
- Pruebas con servidor SSH local, documentación y flujo de integración continua.

El paquete es una extracción independiente de los componentes de conexión SSH de ThowiLabs MCP.

## [0.2.0] - 2026-10-19

- Subida de archivos sobre SSH existente mediante `Upload`, sin SFTP.
- Elevación `sudo -n` automática por defecto cuando el destino requiere privilegios.
- Verificación SHA-256 antes de instalar, temporales restringidos y reemplazo atómico.
- Preservación de UID, GID y permisos en sobrescrituras; pruebas de protección de destinos.
