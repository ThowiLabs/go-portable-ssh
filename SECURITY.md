# Seguridad

La identidad del servidor debe comprobarse antes de proporcionar credenciales.

- Para una clave ya aprobada, utiliza `sshtrust.Pinned` o un callback estricto de `knownhosts`.
- `sshtrust.Discover` muestra la huella presentada y detiene la conexión. La primera huella debe contrastarse por un canal independiente.
- El callback `ssh.InsecureIgnoreHostKey` desactiva deliberadamente esa comprobación. Evítalo para servidores de producción.
- No almacenes contraseñas, claves privadas ni tokens en el repositorio.
- Valida cualquier entrada externa antes de enviarla como comando al servidor remoto.
- `Client.Raw()` expone el cliente SSH subyacente. Los consumidores son responsables de gestionar sus propias sesiones.

Las incidencias de seguridad deben notificarse de forma privada al propietario del repositorio mediante las opciones de seguridad de GitHub; no publiques credenciales ni vulnerabilidades explotables en issues abiertos.

### Subidas privilegiadas

La elevación automática de `Upload` solo es viable si el usuario SSH ya tiene autorización para `sudo -n`. Controla dicha autorización en el servidor: una cuenta con `sudo` irrestricto ya puede modificar archivos de sistema. Usa `PrivilegeNever` cuando una aplicación no deba realizar operaciones privilegiadas. La transferencia rechaza rutas destino relativas, simbólicas y archivos especiales; la verificación del host SSH sigue siendo obligatoria. Para datos con ACL, xattrs o etiquetas SELinux, se recomienda un mecanismo de despliegue especializado.
