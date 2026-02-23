#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_dir}"

make plugin >/dev/null
make clean >/dev/null
make >/dev/null

out="$(./build/steel_host plugins/echo-plugin/dist/steel-echo-plugin.component.wasm)"
printf '%s\n' "${out}"

printf '%s\n' "${out}" | rg -q '^plugin output bytes: 15$'
printf '%s\n' "${out}" | rg -q '^hello from host$'
