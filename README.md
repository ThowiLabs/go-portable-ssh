# go-portable-ssh

Biblioteca Go para conectar por SSH, ejecutar comandos remotos y comprobar la identidad del servidor sin administrar obligatoriamente `known_hosts`.

El módulo utiliza `golang.org/x/crypto/ssh`. **No implementa un protocolo SSH propio.**

## Funciones de la versión 0.1.0

- Conexiones SSH con autenticación por contraseña, llave privada u otros métodos de `ssh.AuthMethod`.
- Verificación de huella SHA-256 previamente aprobada (`sshtrust.Pinned`).
- Descubrimiento de huella con rechazo del handshake (`sshtrust.Discover`).
- Ejecución de comandos con salida, error estándar, estado de salida y límite de 4 MiB por flujo.
- Cancelación con `context.Context` y timeout de conexión/handshake.
- Acceso al cliente subyacente mediante `Client.Raw()` cuando se requieren canales SSH o PTY.

La biblioteca **no** incluye API propia para SFTP, túneles, reconexión automática ni sincronización de archivos en esta versión. Estas funciones pueden añadirse en versiones futuras según los casos de uso.

## Requisitos

Go 1.25 o superior.

Instalación desde la etiqueta `v0.1.0`:

```bash
go get github.com/ThowiLabs/go-portable-ssh@v0.1.0
```

## Ejemplo de ejecución

La huella SSH debe verificarse por un canal independiente antes de aprobarse. Por ejemplo, quien administra el servidor puede consultarla directamente desde su consola con `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256`.

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "time"

    portablessh "github.com/ThowiLabs/go-portable-ssh"
    "github.com/ThowiLabs/go-portable-ssh/sshtrust"
    "golang.org/x/crypto/ssh"
)

func main() {
    pin, err := sshtrust.Pinned(os.Getenv("SSH_HOST_FINGERPRINT"))
    if err != nil {
        log.Fatal(err)
    }
    password, ok := os.LookupEnv("SSH_PASSWORD")
    if !ok {
        log.Fatal("SSH_PASSWORD no está configurada")
    }

    ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
    defer cancel()

    client, err := portablessh.Dial(ctx, portablessh.Config{
        Address:         "servidor.example:22",
        User:            "deploy",
        Auth:            []ssh.AuthMethod{ssh.Password(password)},
        HostKeyCallback: pin,
        Timeout:         10 * time.Second,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    result, err := client.Run(ctx, "uname -a")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(result.Stdout)
    fmt.Println("Código:", result.ExitCode)
}
```

Puedes utilizar `ssh.PublicKeys(signer)` en `Auth` para autenticarte con llave privada, sin alterar la API del cliente.

## Servidor nuevo: conocer la huella

`sshtrust.Discover()` **no confía en ninguna clave**. Devuelve la huella ofrecida en un error y aborta el handshake antes de autenticar.

```go
cfg.HostKeyCallback = sshtrust.Discover()
client, err := portablessh.Dial(ctx, cfg)
var unknown *sshtrust.UnknownHostKeyError
if errors.As(err, &unknown) {
    fmt.Println("Verificar externamente:", unknown.Fingerprint)
}
// No conectar de nuevo hasta verificar la huella por otro canal.
```

Tras comprobar la huella, se puede crear el callback `sshtrust.Pinned(unknown.Fingerprint)` y guardar esa identidad asociada al perfil. Si cambia la clave del servidor, `sshtrust.Pinned` rechaza la conexión.

Para comprobar identidades a través de OpenSSH, también es posible pasar un callback creado con `golang.org/x/crypto/ssh/knownhosts` en `Config.HostKeyCallback`.

## Semántica de errores

- Error de conexión, handshake, autenticación o ejecución: `error` no nulo.
- Comando remoto que terminó con estado no cero: `Result.ExitCode` distinto de cero, normalmente sin error de transporte.
- Salida que supera 4 MiB en `stdout` o `stderr`: `Result.Truncated = true`.
- Cancelación: `context.Canceled` o `context.DeadlineExceeded`.

Los comandos se envían al intérprete remoto según la configuración del servidor. **No ejecutes entradas de usuarios sin validarlas.** Esta biblioteca no es un sandbox.

## Desarrollo

```bash
go test ./...
go test -race ./...
go vet ./...
```

La suite utiliza servidores SSH efímeros locales, sin acceder a servidores ajenos.

**Licencia:** 0BSD. Consulta `LICENSE`.

## Subir archivos con preservación de permisos

`Upload` transfiere un archivo regular desde el equipo local usando la conexión SSH existente. Calcula SHA-256 antes del envío y lo verifica antes de instalarlo en el destino. Utiliza un temporal de acceso restringido y reemplazo atómico.

```go
result, err := client.Upload(ctx, portablessh.UploadOptions{
    LocalPath: "./config.conf",
    RemotePath: "/root/mi-aplicacion/config.conf",
    Overwrite: true,
})
```

El modo de privilegio es **`auto` por defecto**: usa el usuario SSH cuando tiene permisos y recurre a `sudo -n` cuando el destino lo requiere. No habilita ni utiliza el inicio de sesión SSH como `root`. Se puede deshabilitar la elevación con `Privilege: portablessh.PrivilegeNever` o exigirla con `PrivilegeSudo`.

En sobrescrituras conserva propietario, grupo y permisos Unix del archivo destino; para archivos nuevos usa `Mode` (por defecto `0644`) y toma propietario/grupo del directorio cuando requiere elevación. Rechaza destinos simbólicos o no regulares y no sobrescribe por defecto. Requiere un host GNU/Linux con `sh`, `mktemp`, `install`, `stat` y `sha256sum`, además de `sudo` sin contraseña cuando se requiera elevación. No garantiza preservar ACL, etiquetas SELinux, atributos extendidos o permisos especiales fuera de los bits Unix; estos casos deben gestionarse mediante el despliegue del sistema.
