# I4 Froez

Navegador web de escritorio para Linux enfocado en privacidad, construido con GTK4 y WebKitGTK. Soporta tres modos de red completamente aislados — Clearnet, Tor e I2P — cada uno con su propio perfil cifrado, historial y marcadores independientes.

> Version actual: **Beta 0.8**

---

## Caracteristicas

### Perfiles de red aislados

Cada modo de red es un perfil completamente independiente con almacenamiento separado:

- **Clearnet** — navegacion normal
- **Tor** — trafico enrutado a traves de la red Tor via `torsocks`
- **I2P** — soporte para la red anonima I2P via `i2pd`

Al cambiar de perfil, la clave maestra en RAM se limpia de forma segura. Al salir de Tor o I2P se realiza un wipe agresivo de sesion.

### Cifrado de datos locales

- Historial y marcadores cifrados con **AES-256-GCM**
- Clave derivada con **PBKDF2-HMAC-SHA256** (200 000 iteraciones)
- Salt unico de 32 bytes por perfil, generado con `RAND_bytes`
- Verificacion de contrasena mediante **HMAC-SHA256** sin almacenar la contrasena
- Migracion automatica desde el formato legacy XOR de versiones anteriores

### Interfaz

- Multiples pestañas
- Barra de navegacion con soporte para URLs y busqueda integrada
- Barra de busqueda en pagina (Ctrl+F)
- Terminal interno con comandos propios (`help` para ver la lista)
- Consola JavaScript integrada (Ctrl+L para limpiar)
- Barra de estado con progreso de descargas
- Marcadores e historial cifrados por perfil
- Limpieza de datos del sitio web (cookies, cache, localStorage, IndexedDB, etc.)

---

## Requisitos

### Dependencias en tiempo de compilacion

| Paquete | Descripcion |
|---|---|
| `gtk4` | Toolkit grafico |
| `webkitgtk-6.0` | Motor de renderizado web |
| `openssl` | Cifrado AES-GCM y PBKDF2 |
| `nlohmann-json` | Serializacion JSON (header-only) |
| `glib2` | Utilidades de GLib |
| `base-devel` / `build-essential` | Herramientas de compilacion |
| `pkgconf` | Gestion de flags de compilacion |

### Dependencias en tiempo de ejecucion (opcionales segun el perfil)

| Paquete | Descripcion |
|---|---|
| `tor` | Necesario para el perfil Tor |
| `torsocks` | Proxy para enrutar trafico por Tor |
| `i2pd` | Necesario para el perfil I2P |

### Instalacion de dependencias

**Arch Linux / Manjaro**
```bash
sudo pacman -S gtk4 webkitgtk-6.0 openssl nlohmann-json glib2 base-devel pkgconf tor torsocks i2pd
```

**Debian / Ubuntu**
```bash
sudo apt install libgtk-4-dev libwebkitgtk-6.0-dev libssl-dev nlohmann-json3-dev libglib2.0-dev build-essential pkg-config tor torsocks i2pd
```

---

## Compilacion

```bash
g++ -std=c++20 main.cpp -o i4froez \
    $(pkg-config --cflags --libs gtk4 webkitgtk-6.0 glib-2.0 gio-2.0) \
    -lcrypto
```

---

## Uso

```bash
./i4froez
```

Al iniciar, se mostrara un dialogo para seleccionar el perfil de red. Si es la primera vez que usas ese perfil, se te pedira crear una contrasena maestra. Esta contrasena se solicitara cada vez que abras el navegador.

---

## Estructura de datos

Los datos de cada perfil se almacenan en:

```
~/.local/share/i4froez/profiles/
├── clearnet/
│   ├── history.json      # Historial cifrado
│   ├── bookmarks.json    # Marcadores cifrados
│   ├── settings.json     # Configuracion del perfil
│   ├── .salt             # Salt criptografico (32 bytes)
│   └── .verifier         # HMAC para verificar la contrasena
├── tor/
│   └── ...
└── i2p/
    └── ...
```

---

## Notas de seguridad

- La contraseña maestra **nunca se almacena en disco**. Solo se guarda un HMAC para verificarla.
- Al cerrar el navegador en modo Tor o I2P, se hace un wipe de memoria de sesion.
- Cada perfil tiene su propio salt, por lo que las claves derivadas son independientes entre perfiles aunque la contrasena sea la misma.

---

## Creditos

Desarrollado por [freetazapablo](https://www.youtube.com/@freetazapablo).
