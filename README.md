# Rootkit Userland Multiplataforma — Windows + Linux

Proyecto académico de Trabajo de Fin de Grado (TFG) para el Grado en Ingeniería de la Ciberseguridad (URJC).

Implementación de un rootkit userland que oculta procesos, ficheros, claves de registro, servicios y conexiones de red con el prefijo `secreto_`. Incluye bind shell en puerto TCP 8080 y un único punto de despliegue multiplataforma.

---

## Estructura del repositorio

```
rootkit_clean/
├── Rootkit_TFG.sln            # Solución Visual Studio (PayloadDLL + Stager)
├── build_dropper.py           # Builder: compila y empaqueta todos los payloads
├── secreto_dropper.py         # Dropper universal (plantilla; rellenada por el builder)
│
├── Linux/
│   ├── secreto_linux.c        # Módulo LD_PRELOAD — 23 hooks de libc
│   ├── secreto_backdoor.c     # Bind shell TCP 8080 para Linux
│   └── Makefile               # Build standalone Linux
│
├── PayloadDLL/
│   ├── hooks.cpp              # 10 hooks con Microsoft Detours (ntdll/advapi32/sechost)
│   ├── injector_logic.cpp     # Lógica de Reflective DLL Injection
│   ├── shellcode.cpp          # Shellcode x86 para inyección en procesos WOW64
│   ├── ReflectiveLoader.c/.h  # ReflectiveLoader de S. Fewer
│   ├── detours.h              # Cabecera Microsoft Detours
│   ├── detours.lib            # Detours precompilada para x64
│   ├── detours_src/           # Fuentes Detours compiladas para Win32
│   └── PayloadDLL.vcxproj
│
└── Stager/
    ├── Program.cs             # Inyector fileless + bind shell Windows
    └── Stager.csproj
```

---

## Requisitos previos

### Windows

| Herramienta | Versión mínima | Notas |
|---|---|---|
| Visual Studio | 2022 | Cargas de trabajo: *Desarrollo para el escritorio con C++* y *Desarrollo de escritorio de .NET* |
| SDK Windows | 10.0 | Incluido con VS |
| Python | 3.8+ | Para `build_dropper.py` y `secreto_dropper.py` |
| WSL2 + gcc | Opcional | Solo si se quiere empaquetar el payload Linux desde Windows |

### Linux

| Herramienta | Notas |
|---|---|
| gcc | Para compilar el módulo `.so` y el backdoor |
| make | Para usar el Makefile |
| Python 3 | Para ejecutar el dropper |

---

## Cómo compilar

### 1. Payloads Windows (Visual Studio)

Abre `Rootkit_TFG.sln` en Visual Studio y compila las siguientes configuraciones:

```
PayloadDLL  →  Release | x64
PayloadDLL  →  Release | Win32
Stager      →  Release | Any CPU
```

Esto genera:
- `x64/Release/PayloadDLL.dll`
- `Release/PayloadDLL.dll`
- `Stager/bin/Release/Stager.exe`

### 2. Empaquetar todo con el builder

Desde la raíz de `rootkit_clean/`, ejecuta el builder. Detecta el sistema operativo automáticamente.

**En Windows** (compila el `.so` Linux vía WSL si está disponible):
```
python build_dropper.py
```

**En Linux** (compila el `.so` de forma nativa):
```
python3 build_dropper.py
```

**Opciones del builder:**

| Flag | Efecto |
|---|---|
| *(ninguno)* | Empaqueta Windows + Linux x86_64 |
| `--skip-wsl` | Solo payloads Windows, sin intentar compilar Linux |
| `--status` | Muestra qué payloads están embebidos en el dropper |

Al terminar, `secreto_dropper.py` contiene todos los binarios embebidos como base64 y está listo para desplegarse.

### 3. Build standalone Linux (sin Python)

Si solo se quiere compilar el módulo Linux de forma independiente:

```bash
cd Linux/
make              # compila secreto_rootkit.so y secreto_bd
sudo make install # instala, activa LD_PRELOAD y persistencia
sudo make remove  # desinstala todo
make clean        # borra binarios generados
```

---

## Despliegue

El dropper detecta el SO en tiempo de ejecución y ejecuta la rama correspondiente.

**Windows (requiere privilegios de Administrador):**
```
python secreto_dropper.py
```

**Linux (requiere root):**
```
python3 secreto_dropper.py
```

### Qué hace en Windows

1. Descifra los payloads (XOR 0x26) y los escribe como `REG_BINARY` en `HKLM\SOFTWARE` (`secreto_stager`, `secreto_payload`, `secreto_payload_x86`).
2. Crea el servicio `secreto_svc` (DisplayName: *Windows Security Health*).
3. PowerShell carga el Stager directamente desde el registro con `[Reflection.Assembly]::Load` — **sin escribir ningún ejecutable en disco**.
4. El Stager inyecta `PayloadDLL.dll` en todos los procesos activos mediante Reflective DLL Injection (x64 nativo / x86 WOW64).
5. `DllMain` activa 10 hooks de Detours en cada proceso inyectado.
6. El hook `NtResumeThread` garantiza que los procesos nuevos también sean inyectados antes de ejecutar su primera instrucción.

### Qué hace en Linux

1. Copia `secreto_rootkit.so` a `/usr/local/lib/` y `secreto_bd` (bind shell) a `/usr/local/lib/`.
2. Registra la ruta en `/etc/ld.so.preload`.
3. Instala 4 mecanismos de persistencia: servicio systemd de recarga del módulo, servicio systemd para el backdoor, y entrada `crontab @reboot`.
4. En cada `execve` posterior, el linker carga el `.so` antes de `libc`; el constructor `init_secreto()` resuelve los 23 punteros mediante `dlsym(RTLD_NEXT, ...)`.

---

## Funcionalidades

| Capacidad | Windows | Linux |
|---|:---:|:---:|
| Ocultar procesos (`secreto_*`) | ✓ | ✓ |
| Ocultar ficheros (`secreto_*`) | ✓ | ✓ |
| Ocultar claves de registro | ✓ | — |
| Ocultar servicios | ✓ | — |
| Ocultar conexiones de red (puerto 8080) | ✓ | ✓ |
| Bind shell TCP 8080 | ✓ | ✓ |
| Anti-debug (bloquea ptrace) | — | ✓ |
| Toggle on/off (`kill -64 31337`) | — | ✓ |
| Propagación automática a procesos nuevos | ✓ (activa) | ✓ (pasiva) |
| Persistencia tras reinicio | ✓ (servicio fileless) | ✓ (4 mecanismos) |
| Evasión Windows Defender | ✓ (0 detecciones) | — |

---

## Limitaciones conocidas

**Windows**
- `NtOpenKey` (acceso por ruta directa) no está interceptado; las claves son visibles si se conoce la ruta completa.
- Las herramientas que usan *direct syscalls* (sin pasar por `ntdll.dll`) no son interceptadas.
- Existe una ventana de visibilidad entre el arranque del sistema y el inicio del servicio Stager.

**Linux**
- El acceso directo a `/proc/<PID>/` sin pasar por `readdir` no es interceptado si se conoce el PID.
- Herramientas con enlazado estático (`busybox`) no cargan `libc` dinámica y no son interceptadas.
- `ss` obtiene las conexiones vía `NETLINK_SOCK_DIAG` (sin pasar por `/proc/net`), por lo que el puerto 8080 sigue siendo visible con `ss`.

---

## Acceso al bind shell

Una vez desplegado, el bind shell escucha en el puerto TCP 8080 en todas las interfaces:

```bash
nc <IP_objetivo> 8080
```

El puerto no aparece en `netstat` ni `TCPView`(limitación: `ss` en Linux sí lo muestra).
