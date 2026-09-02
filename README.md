# DiffDylib

**Differential Dylib Protection** — módulo de Dyld87.

Herramienta defensiva para macOS 14+ (Apple Silicon; Intel si el código sale portable). Construye, para cada aplicación observada, un *baseline* equivalente a una **protección diferencial**: lista de dylibs esperadas, hashes SHA-256, Team IDs, rutas resueltas y permisos POSIX. En cada corrida posterior compara el estado esperado con el estado real (otra pasada estática o mappings runtime). Si un host suele cargar *N* bibliotecas y aparece la *N+1* desde `~/Library`, `/tmp` o cualquier ruta escribible por el usuario, se emite una **condición diferencial**.

Eso **no es un veredicto de malware**. Es una anomalía con buena relación señal/ruido: el relé vio `ΣI ≠ 0`.

## Analogía eléctrica

| Software | Potencia |
| --- | --- |
| Proceso anfitrión | Barra / alimentador |
| Dylib | Carga conectada |
| Firma / Team ID | Placa de características |
| Baseline | Estado operativo esperado |
| Compare (esperado vs real) | Relé diferencial 87 |
| Dylib extra en ruta escribible | Carga no autorizada en un circuito legítimo |
| Finding | Condición diferencial, no “el ataque” |
| Endpoint Security (no está aquí) | Relé de disparo — proyecto 09 |

Principio rector: una protección no tiene que reconocer *MalwareXYZ.dylib*. Basta demostrar que una aplicación está ejecutando código que **no pertenece a su estado legítimo esperado**.

## Esto NO es un antivirus

- No clasifica familias de malware ni tiene firmas de amenazas.
- `unsigned` no significa malicioso; `writableByUser` no significa compromiso.
- No inyecta, no hijackea aplicaciones reales, no usa `DYLD_INSERT_LIBRARIES` contra procesos ajenos.
- Los fixtures son un host de laboratorio y dylibs que solo registran `fixture loaded`.
- Un finding es una **incompatibilidad con el baseline**, igual que un diferencial no diagnostica si el conductor fue cortado o mordido: observa que la suma no cierra.

## Qué cubre este repo

- Parser Mach-O thin y fat: `LC_LOAD_DYLIB`, `LC_LOAD_WEAK_DYLIB`, `LC_RPATH`, `LC_ID_DYLIB`.
- Resolución conservadora de `@executable_path` / `@loader_path` / `@rpath`.
- Identidad de disco: SHA-256, Team ID, signing ID, POSIX, `writableByUser`, aproximación SIP por `st_flags`.
- `capture` / `show` con JSON `baseline.v1` y SQLite opcional de revisiones.
- Comparador: `added`, `removed`, `hashChanged`, `teamChanged`, `writableUnexpected`, `rpathAmbiguous`, `pathChanged`.
- Runtime: `proc_pidinfo` + `PROC_PIDREGIONPATHINFO` (solo mappings ejecutables **con path**). Sin `task_for_pid`.
- Informe de compare: **Markdown + JSON**, con tabla expected / observed / Δ added / Δ removed.

## Qué no cubre este repo

DiffDylib es el módulo 01. El resto de Dyld87 vive en otros proyectos a propósito:

| Hueco | Dónde va |
| --- | --- |
| `AUTH_MMAP` / `NOTIFY_MMAP` (bloquear o ver la energización) | Proyecto 09 (Alarm / Trip / Lockout) y 02 (selectividad) |
| Sequence-of-Events (`launch → mmap → file → net`) | Proyecto 05 |
| Digital twin / historial de planta tras updates | Proyecto 08 |
| Zonas de criticidad (`Risk = dylib × host`) | Proyecto 07 |
| Impedancia de confianza / estimación de estado | Proyectos 06 y 04 |
| Relé 87 puro `L_runtime − L_static` como producto | Proyecto 03 |
| Unifilar (barra + derivaciones coloreadas) | Proyecto 10 |
| System extension, notarización del cliente ES | Fuera de 01 |

Tampoco cubre: carga puramente in-memory, `mprotect` exótico, atribución “esta dylib abrió el socket” (las APIs de Apple siguen siendo de proceso), ni denegar un mapping (un falso positivo tumbaría la app).

## Falsos positivos

El relé dispara por **incompatibilidad con el baseline**, no por intención. Casos normales que producen Δ:

- **Plugins y extensiones** (Adobe, IDEs, browsers): `dlopen` de una dylib que no estaba en el Mach-O estático. Es `added`. Recalibrar el baseline después de instalar el plugin, o no tratar `added` de un directorio de plugins como trip.
- **JIT / mappings ejecutables sin path** (`proc_pidinfo` los ve como región `VM_PROT_EXECUTE` vacía). DiffDylib **no** los lista. Un comparador runtime no debe inventarlos.
- **Actualizaciones**: cambia el SHA-256 del binario principal y de sus dylibs. La clave natural incluye el hash del ejecutable; un update es otro baseline, no un hijack. El twin (proyecto 08) distingue update vs drift.
- **App Translocation / Gatekeeper**: rutas bajo `/private/var/folders/.../AppTranslocation/`. Pueden parecer “writable unexpected” si se comparan contra un baseline de `/Applications`.
- **Dos copias legítimas del mismo basename** (helpers, fat slices extraídas, frameworks duplicados): `pathChanged` / `rpathAmbiguous`. No es malware por sí solo.
- **`--depth` distinto** entre capture y compare: dependencias de segundo nivel aparecen como `added` o `removed` (score `info`/`medium`). Usar el mismo depth.
- **`--skip-system` vs no**: `libz` / `libSystem` salen como `added` low. No es un trip.

DiffDylib elige reportar falsos positivos antes que falsos negativos, igual que DHS.

## Limitaciones (Wardle)

Patrick Wardle, *Detecting (Evil) Dylibs* (Objective-See, agosto 2026) y DEF CON 34 *Dylib Hijacking on macOS: Dead or Alive?*:

1. **`proc_pidinfo`** no enumera bien las dylibs del *dyld shared cache*.
2. **TOCTOU disco vs memoria:** el archivo en la ruta reportada puede ya no coincidir con las páginas mapeadas.
3. **`AUTH_MMAP` tiene deadline** y denegar un mapping requerido tumba la app. Este repo no se suscribe.
4. **`MMAP` no cubre carga in-memory.**
5. Las APIs de red y ES atribuyen al **proceso**, no a la dylib.

SIP se aproxima con `UF_RESTRICTED` / `SF_RESTRICTED`. Si el bit no está, el valor es `unprotected` aunque el path viva bajo `/usr/lib`. Eso no se “arregla” con APIs privadas.

## Uso

```text
diffdylib enumerate --app <path> [--depth 1] [--skip-system|--no-skip-system]
diffdylib capture --app <path> --out <file> [--store [file]] [--replace]
diffdylib show --baseline <file> [--json]
diffdylib compare --baseline <file> --app <path> [--json|--markdown] [--out <report>]
diffdylib compare --baseline <file> --pid <pid> [--out <report>]
diffdylib ps --pid <pid> [--json]
```

`--out report` escribe `report.json` y `report.md`.

Códigos de `compare`: **0** sin medium/high, **1** medium/high, **2** uso.

```sh
make fixtures
make build
make test
make demo
```

Requisitos: Xcode / Swift 5.9+, `clang`, macOS 14+. Los tests y el demo **no** tocan `/Applications`.

## Ejemplos contra el fixture

Host de laboratorio: `Fixtures/build/rpath/host` con `@rpath/libcollide.dylib` y dos `LC_RPATH` (`r1`, `r2`).

```sh
# 1. Inventario estático
.build/debug/diffdylib enumerate --app Fixtures/build/thin/hello_host

# 2. Baseline + show
.build/debug/diffdylib capture --app Fixtures/build/thin/hello_host --out /tmp/hello.json
.build/debug/diffdylib show --baseline /tmp/hello.json

# 3. Compare limpio (exit 0)
.build/debug/diffdylib compare --baseline /tmp/hello.json --app Fixtures/build/thin/hello_host --json

# 4. Hijack sintético en el fixture (no en Photoshop)
make demo
# → demo-out/report.md  tabla Δ added ≥ 1, rpathAmbiguous, writableUnexpected
```

Runtime (el host tiene que seguir vivo; el demo estático no lo necesita):

```sh
./Fixtures/build/thin/linger_host &
pid=$!
.build/debug/diffdylib ps --pid "$pid"
.build/debug/diffdylib compare --baseline /tmp/hello.json --pid "$pid" --markdown
kill "$pid"
```

`make demo` copia el fixture a `/tmp`, vacía `r1`, captura, planta `libcollide.dylib` en `r1`, compara y deja Markdown+JSON en `demo-out/`.

## Intercambio JSON

Snake_case, RFC 3339 con fracción.

- Baseline: `"schema": "dyld87.baseline.v1"`
- Informe: `"schema": "dyld87.diff-report.v1"`
- Enumeración estática: `"schema": "dyld87.static-enum.v1"`
- `ps`: `"schema": "dyld87.runtime-ps.v1"`

SQLite opcional solo para revisiones de baseline. No hay protobuf.

## Licencia

MIT. Ver [LICENSE](LICENSE).
