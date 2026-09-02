#!/bin/sh
# Laboratory demo: capture a clean rpath host, plant a second @rpath hit
# in the fixture copy (never in /Applications), compare, print the report.
# A finding is success. Exit 1 from `compare` is expected.
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

SWIFT="${SWIFT:-swift}"
BIN="${BIN:-.build/debug/diffdylib}"
OUT_DIR="${OUT_DIR:-$ROOT/demo-out}"
WORK="$(mktemp -d /tmp/diffdylib-demo-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

echo "==> fixtures"
bash Fixtures/build-fixtures.sh

echo "==> build"
$SWIFT build
if [ ! -x "$BIN" ]; then
  BIN="$($SWIFT build --show-bin-path)/diffdylib"
fi

SRC="$ROOT/Fixtures/build/rpath"
if [ ! -x "$SRC/host" ]; then
  echo "error: missing $SRC/host" >&2
  exit 1
fi

cp -R "$SRC" "$WORK/rpath"
HOST="$WORK/rpath/host"
PLANTED="$WORK/rpath/r1/libcollide.dylib"

# Clean first rpath so the baseline has a single on-disk hit.
rm -f "$PLANTED"

mkdir -p "$OUT_DIR"
echo "==> capture baseline (r1 empty)"
"$BIN" capture --app "$HOST" --out "$OUT_DIR/baseline.json" >/dev/null

echo "==> plant extra dylib in fixture r1/"
cp "$WORK/rpath/r2/libcollide.dylib" "$PLANTED"

echo "==> compare"
set +e
"$BIN" compare --baseline "$OUT_DIR/baseline.json" --app "$HOST" \
  --markdown --out "$OUT_DIR/report"
status=$?
set -e
if [ "$status" -ne 1 ]; then
  echo "error: expected compare exit 1 (medium/high finding), got $status" >&2
  exit 1
fi

echo
echo "==> Markdown report ($OUT_DIR/report.md)"
cat "$OUT_DIR/report.md"
echo
echo "JSON: $OUT_DIR/report.json"
echo "demo planted: $PLANTED"
echo "done (finding is a differential condition, not malware)."
