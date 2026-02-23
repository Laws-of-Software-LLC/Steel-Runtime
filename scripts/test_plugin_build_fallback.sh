#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
plugin_dir="${repo_dir}/plugins/echo-plugin"

real_cargo="$(command -v cargo)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

cat > "${tmp_dir}/cargo" <<'WRAP'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -ge 2 && "$1" == "component" && "$2" == "build" ]]; then
  echo "error: no such command: component" >&2
  exit 101
fi
exec "$REAL_CARGO" "$@"
WRAP
chmod +x "${tmp_dir}/cargo"

rm -f "${plugin_dir}/dist/steel-echo-plugin.component.wasm"

(
  cd "${plugin_dir}"
  REAL_CARGO="${real_cargo}" PATH="${tmp_dir}:$PATH" ./scripts/build_component.sh >/dev/null
)

[[ -f "${plugin_dir}/dist/steel-echo-plugin.component.wasm" ]]

"${repo_dir}/build/steel_host" "${plugin_dir}/dist/steel-echo-plugin.component.wasm" >/dev/null

echo "plugin build fallback path works without cargo component"
