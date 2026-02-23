#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_dir}"

make plugin >/dev/null
make >/dev/null

src="plugins/echo-plugin/dist/steel-echo-plugin.component.wasm"
tmp="$(mktemp -d)"
cleanup() { rm -rf "${tmp}"; }
trap cleanup EXIT

bad="${tmp}/tampered.component.wasm"
cp "${src}" "${bad}"

# Flip the last byte (inside manifest signature payload), preserving wasm structure.
python3 - "$bad" <<'PY'
import pathlib
import sys
p = pathlib.Path(sys.argv[1])
b = bytearray(p.read_bytes())
b[-1] ^= 0x01
p.write_bytes(bytes(b))
PY

set +e
out="$(./build/steel_host "${bad}" 2>&1)"
rc=$?
set -e
printf '%s\n' "$out"

if [[ $rc -eq 0 ]]; then
  echo "expected host load failure for tampered signature" >&2
  exit 1
fi

printf '%s\n' "$out" | rg -q "manifest signature verification failed"
