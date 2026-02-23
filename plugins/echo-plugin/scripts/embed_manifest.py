#!/usr/bin/env python3
import argparse
import hashlib
import os
import pathlib
import struct
import subprocess
import sys
import tempfile

STEEL_MANIFEST_SECTION_NAME = b"steel.manifest.v1"
STEEL_MANIFEST_MAGIC = 0x4D504653
STEEL_HOST_ABI_MAJOR = 1
STEEL_ABI_MINOR = 0

FACET_LOGGER = bytes([
    0x2a, 0xa2, 0xe8, 0x95, 0x90, 0xbb, 0x47, 0x95, 0x98, 0x42, 0x06, 0x6f, 0x17, 0x4e, 0x7f, 0x20,
])
FACET_DOCUMENT = bytes([
    0x94, 0x65, 0xfa, 0x66, 0xde, 0xe4, 0x49, 0x42, 0xab, 0x33, 0xa0, 0xf5, 0x95, 0x99, 0x4f, 0xf0,
])

STEEL_SIG_TYPE_VOID = 0
STEEL_SIG_TYPE_BYTES = 100
STEEL_SIG_TYPE_U32 = 101

METHOD_LOG_INFO_SIG = {
    "name": "log.info",
    "params": [STEEL_SIG_TYPE_BYTES],
    "result": STEEL_SIG_TYPE_VOID,
}
METHOD_DOC_APPEND_SIG = {
    "name": "document.append",
    "params": [STEEL_SIG_TYPE_U32, STEEL_SIG_TYPE_BYTES],
    "result": STEEL_SIG_TYPE_BYTES,
}


def load_generated_hashes() -> tuple[int, int]:
    script_dir = pathlib.Path(__file__).resolve().parent
    repo_root = script_dir.parent.parent.parent
    generator = repo_root / "scripts" / "generate_abi_hashes.py"
    subprocess.run(
        [
            "python3",
            str(generator),
            "--facet-header",
            str(repo_root / "include" / "steel" / "facet.h"),
            "--c-out",
            str(repo_root / "include" / "steel" / "abi_hashes.h"),
            "--py-out",
            str(script_dir / "abi_hashes_generated.py"),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        from abi_hashes_generated import HOST_LAYOUT_HASH, TYPE_TABLE_HASH  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(f"failed to load generated ABI hashes: {exc}") from exc
    return HOST_LAYOUT_HASH, TYPE_TABLE_HASH


def fnv1a64(data: bytes) -> int:
    h = 0x14650FB0739D0383
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def hash_typed_signature(param_types: list[int], result_type: int) -> int:
    payload = bytearray()
    for t in param_types:
        payload += struct.pack("<H", t)
    payload += struct.pack("<H", result_type)
    return fnv1a64(bytes(payload))


def hash_method_id(facet_id: bytes, method_name: str, param_types: list[int], result_type: int) -> int:
    payload = bytearray()
    payload += b"steel.method.v1\x00"
    payload += facet_id
    payload += b"\x00"
    payload += method_name.encode("utf-8")
    payload += b"\x00"
    for t in param_types:
        payload += struct.pack("<H", t)
    payload += struct.pack("<H", result_type)
    h = 0x811C9DC5
    for b in payload:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h if h != 0 else 1


def uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)


def sign_payload(payload: bytes, signing_key: str) -> bytes:
    with tempfile.NamedTemporaryFile(delete=False) as payload_file:
        payload_file.write(payload)
        payload_path = payload_file.name
    with tempfile.NamedTemporaryFile(delete=False) as sig_file:
        sig_path = sig_file.name
    try:
        subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", signing_key, "-out", sig_path, payload_path],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        with open(sig_path, "rb") as f:
            return f.read()
    finally:
        try:
            os.remove(payload_path)
        except FileNotFoundError:
            pass
        try:
            os.remove(sig_path)
        except FileNotFoundError:
            pass


def build_manifest_payload(
    component_bytes: bytes,
    requested_permissions: int,
    requested_region_bytes: int,
    signer_id: str,
    signing_key: str,
    object_types: list[tuple[str, list[int]]],
) -> bytes:
    host_layout_hash, type_table_hash = load_generated_hashes()
    memory_min_pages = 1
    memory_max_pages = 4
    facet_count = 2
    method_count = 2
    object_type_count = len(object_types)

    payload = bytearray()
    payload += struct.pack("<I", STEEL_MANIFEST_MAGIC)
    payload += struct.pack("<H", STEEL_HOST_ABI_MAJOR)
    payload += struct.pack("<H", STEEL_ABI_MINOR)
    payload += struct.pack("<Q", host_layout_hash)
    payload += struct.pack("<Q", type_table_hash)
    payload += struct.pack("<I", memory_min_pages)
    payload += struct.pack("<I", memory_max_pages)
    payload += struct.pack("<I", requested_permissions)
    payload += struct.pack("<I", requested_region_bytes)
    payload += struct.pack("<I", facet_count)
    payload += struct.pack("<I", method_count)
    payload += struct.pack("<I", object_type_count)

    # Facets
    facet_logger_requested_permissions = 0
    facet_document_requested_permissions = requested_permissions
    payload += FACET_LOGGER
    payload += struct.pack("<I", 0)  # method_start
    payload += struct.pack("<I", 1)  # method_count
    payload += struct.pack("<I", facet_logger_requested_permissions)

    payload += FACET_DOCUMENT
    payload += struct.pack("<I", 1)
    payload += struct.pack("<I", 1)
    payload += struct.pack("<I", facet_document_requested_permissions)

    # Methods
    payload += struct.pack("<I", 0)  # facet_index
    payload += struct.pack(
        "<I",
        hash_method_id(
            FACET_LOGGER,
            METHOD_LOG_INFO_SIG["name"],
            METHOD_LOG_INFO_SIG["params"],
            METHOD_LOG_INFO_SIG["result"],
        ),
    )
    payload += struct.pack("<H", len(METHOD_LOG_INFO_SIG["params"]))  # param_count
    payload += struct.pack("<H", 0)  # reserved
    payload += struct.pack(
        "<Q",
        hash_typed_signature(METHOD_LOG_INFO_SIG["params"], METHOD_LOG_INFO_SIG["result"]),
    )
    for t in METHOD_LOG_INFO_SIG["params"]:
        payload += struct.pack("<H", t)
    payload += struct.pack("<H", METHOD_LOG_INFO_SIG["result"])

    payload += struct.pack("<I", 1)  # facet_index
    payload += struct.pack(
        "<I",
        hash_method_id(
            FACET_DOCUMENT,
            METHOD_DOC_APPEND_SIG["name"],
            METHOD_DOC_APPEND_SIG["params"],
            METHOD_DOC_APPEND_SIG["result"],
        ),
    )
    payload += struct.pack("<H", len(METHOD_DOC_APPEND_SIG["params"]))
    payload += struct.pack("<H", 0)
    payload += struct.pack(
        "<Q",
        hash_typed_signature(METHOD_DOC_APPEND_SIG["params"], METHOD_DOC_APPEND_SIG["result"]),
    )
    for t in METHOD_DOC_APPEND_SIG["params"]:
        payload += struct.pack("<H", t)
    payload += struct.pack("<H", METHOD_DOC_APPEND_SIG["result"])

    for object_type_name, object_facet_indices in object_types:
        name = object_type_name.encode("utf-8")
        if len(name) == 0 or len(name) > 0xFFFF:
            raise ValueError("object type name must be between 1 and 65535 bytes")
        payload += struct.pack("<H", len(name))
        payload += name
        if len(object_facet_indices) > 0xFFFF:
            raise ValueError("object type facet list too large")
        payload += struct.pack("<H", len(object_facet_indices))
        for facet_index in object_facet_indices:
            payload += struct.pack("<I", facet_index)

    component_sha256 = hashlib.sha256(component_bytes).digest()
    signer_id_bytes = signer_id.encode("utf-8")
    payload += component_sha256
    payload += struct.pack("<H", len(signer_id_bytes))
    payload += signer_id_bytes

    signature = sign_payload(bytes(payload), signing_key)
    payload += struct.pack("<H", len(signature))
    payload += signature

    return bytes(payload)


def embed_manifest(wasm_bytes: bytes, manifest_payload: bytes) -> bytes:
    if len(wasm_bytes) < 8 or wasm_bytes[:4] != b"\x00asm":
        raise ValueError("input is not a wasm binary")

    name_len = uleb128(len(STEEL_MANIFEST_SECTION_NAME))
    section_payload = name_len + STEEL_MANIFEST_SECTION_NAME + manifest_payload
    section_size = uleb128(len(section_payload))
    section = b"\x00" + section_size + section_payload
    return wasm_bytes + section


def main() -> int:
    parser = argparse.ArgumentParser(description="Embed steel.manifest.v1 into a component WASM")
    parser.add_argument("input", help="path to input component wasm")
    parser.add_argument("output", help="path to output component wasm")
    parser.add_argument(
        "--requested-permissions",
        type=lambda x: int(x, 0),
        default=0,
        help="bitmask of requested plugin permissions (default: 0)",
    )
    parser.add_argument(
        "--signing-key",
        default="keys/demo_private.pem",
        help="path to PEM private key used for manifest signature",
    )
    parser.add_argument(
        "--requested-region-bytes",
        type=lambda x: int(x, 0),
        default=4096,
        help="plugin requested per-invocation region allotment in bytes (default: 4096)",
    )
    parser.add_argument(
        "--signer-id",
        default="demo-dev",
        help="attested signer id",
    )
    parser.add_argument(
        "--object-type-spec",
        action="append",
        default=None,
        help="object type spec as name=facets where facets are logger,document (example: document=document,logger)",
    )
    args = parser.parse_args()

    with open(args.input, "rb") as f:
        wasm_bytes = f.read()

    facet_index_by_name = {"logger": 0, "document": 1}
    object_types: list[tuple[str, list[int]]] = []
    specs = args.object_type_spec if args.object_type_spec else ["document=document,logger"]
    for spec in specs:
        if "=" not in spec:
            raise ValueError(f"invalid --object-type-spec '{spec}' (expected name=facet,facet)")
        name, facet_csv = spec.split("=", 1)
        name = name.strip()
        facet_names = [x.strip() for x in facet_csv.split(",") if x.strip()]
        if not name:
            raise ValueError("object type name cannot be empty")
        if not facet_names:
            raise ValueError(f"object type '{name}' must declare at least one facet")
        facet_indices: list[int] = []
        for facet_name in facet_names:
            if facet_name not in facet_index_by_name:
                raise ValueError(f"unknown facet '{facet_name}' in object type '{name}'")
            facet_indices.append(facet_index_by_name[facet_name])
        object_types.append((name, facet_indices))
    manifest_payload = build_manifest_payload(
        wasm_bytes,
        args.requested_permissions,
        args.requested_region_bytes,
        args.signer_id,
        args.signing_key,
        object_types,
    )
    out_bytes = embed_manifest(wasm_bytes, manifest_payload)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "wb") as f:
        f.write(out_bytes)

    return 0


if __name__ == "__main__":
    sys.exit(main())
