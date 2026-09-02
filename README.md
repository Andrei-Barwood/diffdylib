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

## Estado (01.2)

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

No implementado (a propósito):

- Hash SHA-256, Team ID, permisos POSIX completos (prompt 01.3).
- Persistencia SQLite / `capture` de verdad.
- Comparador diferencial (`compare`).
- Enumeración runtime (`proc_pidinfo`).
- Endpoint Security.

## Uso

```text
diffdylib enumerate --app <path> [--depth 1] [--skip-system|--no-skip-system]
diffdylib capture --app <path> --out <file>
diffdylib compare --baseline <file> --app <path>
diffdylib show --baseline <file>
```

`enumerate` imprime JSON (`dyld87.static-enum.v1`) con `dylibs` y `findings`. `capture` / `compare` / `show` siguen saliendo 2 (`not implemented`).

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

SQLite queda reservado para un prompt posterior. No hay protobuf.

## Siguiente prompt (01.3)

Identidad criptográfica y POSIX de cada `DylibIdentity`: SHA-256, Team ID, signing ID, `uid/gid`/`mode`, `writableByUser` de verdad, y una aproximación a SIP. Sin `compare` todavía. `unsigned` no es malware.

## Licencia

MIT. Ver [LICENSE](LICENSE).
