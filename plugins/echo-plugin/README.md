# Steel Echo Plugin (WASM Component)

This is a minimal WebAssembly component plugin for the Steel runtime. It implements the `steel:plugin/entry#invoke` export from `wit/steel-plugin.wit` and returns payloads for the two built-in facets:

- `log.info`: returns an empty payload.
- `document.append`: echoes the input payload, capped at 1024 bytes.

## Build

You need:

- `cargo component` (https://github.com/bytecodealliance/cargo-component)
- `rustup target add wasm32-wasip1` (or `wasm32-wasi` on older toolchains)
- Python 3
- OpenSSL (for manifest signing)

From `plugins/echo-plugin`:

```bash
./scripts/build_component.sh
```

This script handles both `wasm32-wasip1` and `wasm32-wasi` output layouts.
It also signs and attests the manifest with `keys/demo_private.pem`.
The host trusts `keys/demo_public.pem` and signer id `demo-dev` in this repo's demo policy.

## Test

```bash
cargo test
```

## Run

```bash
./build/steel_host plugins/echo-plugin/dist/steel-echo-plugin.component.wasm
```

The default host build can load and invoke this plugin.
