#!/bin/sh
# Compile laboratory Mach-O fixtures. Never touches /Applications.
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
SRC="$ROOT/src"
OUT="$ROOT/build"
CLANG="${CLANG:-clang}"

rm -rf "$OUT"
mkdir -p "$OUT/thin" "$OUT/fat" "$OUT/rpath/r1" "$OUT/rpath/r2"

compile_dylib() {
  arch_flags=$1
  src=$2
  dest=$3
  install_name=$4
  shift 4
  # shellcheck disable=SC2086
  $CLANG $arch_flags -dynamiclib "$src" -o "$dest" -install_name "$install_name" "$@"
}

compile_exe() {
  arch_flags=$1
  src=$2
  dest=$3
  shift 3
  # shellcheck disable=SC2086
  $CLANG $arch_flags "$src" -o "$dest" "$@"
}

# --- thin (host architecture) ---
compile_dylib "" "$SRC/libleaf.c" "$OUT/thin/libleaf.dylib" "@rpath/libleaf.dylib"
compile_dylib "" "$SRC/libmid.c" "$OUT/thin/libmid.dylib" "@rpath/libmid.dylib" \
  -L "$OUT/thin" -lleaf -Wl,-rpath,@loader_path
compile_exe "" "$SRC/hello_host.c" "$OUT/thin/hello_host" \
  -L "$OUT/thin" -lmid -Wl,-rpath,@executable_path

# --- fat (arm64 + x86_64), if the toolchain can emit both ---
FAT="-arch arm64 -arch x86_64"
set +e
compile_dylib "$FAT" "$SRC/libleaf.c" "$OUT/fat/libleaf.dylib" "@rpath/libleaf.dylib"
fat_status=$?
set -e
if [ "$fat_status" -eq 0 ]; then
  compile_dylib "$FAT" "$SRC/libmid.c" "$OUT/fat/libmid.dylib" "@rpath/libmid.dylib" \
    -L "$OUT/fat" -lleaf -Wl,-rpath,@loader_path
  compile_exe "$FAT" "$SRC/hello_host.c" "$OUT/fat/hello_host" \
    -L "$OUT/fat" -lmid -Wl,-rpath,@executable_path
  file "$OUT/fat/hello_host" > "$OUT/fat/hello_host.file"
else
  echo "warning: toolchain cannot build a fat Mach-O; fat fixture omitted" >&2
  rm -f "$OUT/fat/libleaf.dylib"
fi

# --- synthetic @rpath ambiguity (two on-disk hits) ---
compile_dylib "" "$SRC/libcollide.c" "$OUT/rpath/r1/libcollide.dylib" "@rpath/libcollide.dylib"
compile_dylib "" "$SRC/libcollide.c" "$OUT/rpath/r2/libcollide.dylib" "@rpath/libcollide.dylib"
compile_exe "" "$SRC/rpath_host.c" "$OUT/rpath/host" \
  -L "$OUT/rpath/r1" -lcollide \
  -Wl,-rpath,@executable_path/r1 \
  -Wl,-rpath,@executable_path/r2

# --- system dylib only (libz) ---
compile_exe "" "$SRC/libz_host.c" "$OUT/libz_host" -lz

echo "fixtures ready under $OUT"
