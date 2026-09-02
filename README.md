# DiffDylib

**Differential Dylib Protection** — módulo de [Dyld87](../prompts-proyectos-dylibs.txt).

Herramienta defensiva para macOS 14+ (Apple Silicon; Intel si el código sale portable). Construye, para cada aplicación observada, un *baseline* equivalente a una **protección diferencial**: lista de dylibs esperadas, hashes SHA-256, Team IDs, rutas resueltas y permisos POSIX. En cada corrida posterior compara el estado esperado con el estado real. Si un host suele cargar *N* bibliotecas y aparece la *N+1* desde `~/Library`, `/tmp`, `/var/tmp` o cualquier ruta escribible por el usuario, se emite una **condición diferencial**.

Eso **no es un veredicto de malware**. Es una anomalía con buena relación señal/ruido: el relé vio `ΣI ≠ 0`.

Prompt **01.2**: enumeración **estática** de dependencias Mach-O. Sigue sin haber `libproc`, firmas (más que el path), comparador ni Endpoint Security.

## Analogía eléctrica

| Software | Potencia |
| --- | --- |
| Proceso anfitrión | Barra / alimentador |
| Dylib | Carga conectada |
| Firma / Team ID | Placa de características |
| Baseline | Diagrama unifilar y estado operativo esperado |
| Compare (esperado vs real) | Relé diferencial 87 |
| Dylib extra en ruta escribible | Carga no autorizada en un circuito legítimo |
| Finding | Condición diferencial, no “el ataque” |

Principio rector (protecciones de potencia): una protección no tiene que reconocer *MalwareXYZ.dylib*. Basta demostrar que la aplicación está ejecutando código que **no pertenece a su estado legítimo esperado**.

## Esto NO es un antivirus

- No clasifica familias de malware ni tiene firmas de amenazas.
- `unsigned` no significa malicioso; `writableByUser` no significa compromiso.
- No inyecta, no hijackea aplicaciones reales, no usa `DYLD_INSERT_LIBRARIES` contra procesos ajenos.
- Los fixtures futuros serán un host de laboratorio y dylibs que solo registran “fixture loaded”.
- Un finding es una **incompatibilidad con el baseline**, igual que un diferencial no diagnostica si el conductor fue cortado o mordido: observa que la suma no cierra.

Si quieres un detector de *MalwareXYZ*, este repo no es ese producto.

## Limitaciones (Wardle) que el código debe documentar, no “resolver”

Patrick Wardle, *Detecting (Evil) Dylibs* (Objective-See, agosto 2026) y DEF CON 34 *Dylib Hijacking on macOS: Dead or Alive?*:

1. **`proc_pidinfo` + `PROC_PIDREGIONPATHINFO`** no enumera bien las dylibs del *dyld shared cache*.
2. **TOCTOU disco vs memoria:** el archivo en la ruta reportada puede ya no coincidir con las páginas ejecutables mapeadas.
3. **`AUTH_MMAP` tiene deadline;** fallarlo puede matar el cliente de Endpoint Security. *Este repo todavía no se suscribe.*
4. **Denegar un mapping requerido puede tumbar la app.** DiffDylib compara; no dispara trip (eso es otro proyecto).
5. **`MMAP` no cubre carga puramente in-memory ni `mprotect` exótico.**

Las APIs de seguridad de macOS (Network Extension, Endpoint Security, firewalls como LuLu) atribuyen eventos al **proceso**, no a la dylib que inició la acción. DiffDylib aumenta la granularidad de la instrumentación; no reescribe el kernel.

## Estado (01.6)

Implementado:

- Paquete Swift: `DiffDylibCore` + CLI `diffdylib` + tests.
- Modelo: `DylibIdentity`, `AppBaseline`, `DiffFinding` (incluye `rpathAmbiguous`), `DiffReport`.
- Parser Mach-O thin y fat/universal: `LC_LOAD_DYLIB`, `LC_LOAD_WEAK_DYLIB`, `LC_RPATH`, `LC_ID_DYLIB`.
- Resolución conservadora de `@executable_path`, `@loader_path`, `@rpath`.
- `StaticEnumerator.enumerate(appURL:depth:skipSystem:) -> [DylibIdentity]`
- Heurística tipo Dylib Hijack Scanner: la misma dependencia `@rpath` en más de un directorio de búsqueda → finding `rpathAmbiguous` (anomalía, no malware).
- `--skip-system` (default true): omite `/usr/lib`, `/System`, `/Library/Apple`, `/usr/lib/system`.
- `--depth` 1 (default) … 3. El primer nivel siempre; la recursión es opcional.
- Errores tipados: `notMachO`, `truncated`, `permissionDenied`.
- Fixtures de laboratorio en `Fixtures/src` (host propio, no `/Applications`).
- `FileIdentityInspector` (Security.framework + CryptoKit + `lstat`):
  - SHA-256 del archivo en disco
  - Team ID, signing ID, authority (certificado hoja)
  - `notarized` solo con evidencia *offline* (`notarization-date`); `null` = no determinado, **sin red**
  - `signingState`: `unsigned` | `valid` | `invalid` | `error(message)` — un fallo de codesign **no aborta**
  - `uid` / `gid` / `posix_permissions` (mode) / `owner` (`user:group`)
  - `writableByUser`: el uid efectivo puede escribir el archivo **o** su directorio padre (`access(W_OK)`)
  - `sip`: `protected` | `unprotected` | `unknown` aproximado con `st_flags` (`UF_RESTRICTED` / `SF_RESTRICTED`). Sin API privada de rootless. Los stubs del dyld shared cache pueden no llevar el flag aunque el sistema esté protegido por SIP.

- `diffdylib capture`: enumeración estática + JSON `baseline.v1`.
- SQLite opcional (`--store ~/.diffdylib/baselines.sqlite`).
- Clave natural: `(process_signing_id, app_path, content_hash_of_main_binary)`.
- Misma clave → nueva **revisión**. `--replace` sobreescribe la revisión más reciente.
- `diffdylib show --baseline <file>`: volcado humano y JSON (`--json` solo JSON).

- Comparador diferencial: baseline vs **otra enumeración estática** del mismo binario.
- Findings, en orden: `added`, `removed`, `hashChanged`, `teamChanged`, `writableUnexpected`, `rpathAmbiguous`.
- Scoring (hint, no veredicto): `writableUnexpected+teamChanged` = high; `writableUnexpected` = medium; added de sistema = low; `removed` = info.
- `diffdylib compare --baseline <file> --app <path> [--json]`
  - exit 0 = sin medium/high
  - exit 1 = medium/high
  - exit 2 = error de uso
- Runtime: `RuntimeEnumerator.listExecutableMappings(pid:)` via `proc_pidinfo` + `PROC_PIDREGIONPATHINFO` (solo `VM_PROT_EXECUTE` con path). **No** `task_for_pid`, **no** lectura de memoria ajena.
- `diffdylib ps --pid <pid>` y `compare --pid <pid>`.
- Δ runtime = mappings − baseline estático. Mismo basename, distinto path → `pathChanged` (dos `libtbb.12.6.dylib`).

No implementado (a propósito):

- Endpoint Security.

`unsigned` no es malware. `writableByUser` no es compromiso.

## Uso

```text
diffdylib enumerate --app <path> [--depth 1] [--skip-system|--no-skip-system]
diffdylib capture --app <path> --out <file> [--store [file]] [--replace]
                 [--depth 1] [--skip-system|--no-skip-system]
diffdylib show --baseline <file> [--json]
diffdylib compare --baseline <file> --app <path> [--json]
                 [--depth 1] [--skip-system|--no-skip-system]
diffdylib compare --baseline <file> --pid <pid> [--json]
diffdylib ps --pid <pid> [--json]
```

`enumerate` imprime JSON (`dyld87.static-enum.v1`). `capture` escribe el baseline. `compare --app` usa otra pasada estática; `compare --pid` usa mappings runtime. `ps` lista mappings ejecutables con path. `show` imprime texto humano y JSON.

`writableUnexpected` se dispara si hay `added` o `hashChanged`, el archivo es escribible por el usuario, y la ruta cae en `~/Library`, `/tmp` (`/private/tmp`), `/var/tmp`, `/Users`, o el directorio del propio host.

`--store` sin ruta usa `~/.diffdylib/baselines.sqlite`.

```sh
make fixtures
make build
make test
make run
```

Requisitos: Xcode / Swift 5.9+, `clang`, macOS 14+.

Los tests **no** abren apps de `/Applications`. Compilan hosts en `Fixtures/build`.

## Intercambio JSON

Los documentos usan snake_case y fechas RFC 3339 con fracción, alineados al contrato `dyld87.event.v1` del suite (este módulo todavía no emite eventos).

- Baseline: `"schema": "dyld87.baseline.v1"`
- Informe: `"schema": "dyld87.diff-report.v1"`

SQLite es opcional y solo guarda revisiones de baselines. No hay protobuf.

## SIP (`unknown` a propósito)

No hay API pública de “¿este path está cubierto por SIP?”. DiffDylib no llama interfaces privadas. Si `lstat` funciona y el bit restricted no está, el valor es `unprotected` aunque el path viva bajo `/usr/lib`. Eso es una limitación documentada, no un bug a “resolver con magia”.

## Límites del runtime (`proc_pidinfo`)

- **dyld shared cache:** las dylibs de plataforma suelen no aparecer como mappings con path propio. `ps` no es un inventario completo de `libSystem`.
- **TOCTOU disco vs memoria:** el SHA-256 y la firma se leen del archivo *actual* en esa ruta. Si el fichero se sustituyó después del `mmap`, el nameplate no describe las páginas residentes.
- No se usa `task_for_pid` ni `mach_vm_read`. Si hace falta ver JIT / mappings anónimos, eso es otro producto (y otro prompt).

## Siguiente prompt (01.7)

Reporte Markdown + JSON, `make demo` (captura, planta dylib extra en el fixture, compara), sección de falsos positivos (plugins, JIT). Sin Endpoint Security ni unifilares.

## Licencia

MIT. Ver [LICENSE](LICENSE).
