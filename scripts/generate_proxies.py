#!/usr/bin/env python3
import argparse
import pathlib
import re
from typing import Dict, List, Tuple


def sanitize_ident(s: str) -> str:
    s = s.lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    if not s:
        return "x"
    if s[0].isdigit():
        s = "_" + s
    return s


def find_brace_block(text: str, start_idx: int) -> Tuple[str, int]:
    i = text.find("{", start_idx)
    if i < 0:
        raise ValueError("missing opening brace")
    depth = 0
    j = i
    while j < len(text):
        c = text[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[i + 1 : j], j + 1
        j += 1
    raise ValueError("unterminated brace block")


def parse_contracts(src: str):
    method_consts: Dict[str, str] = {}
    facets: Dict[str, List[str]] = {}
    vtables: Dict[str, List[dict]] = {}
    contracts: List[Tuple[str, str]] = []

    for m in re.finditer(r"static\s+const\s+uint32_t\s+(\w+)\s*=\s*([^;]+);", src):
        method_consts[m.group(1)] = m.group(2).strip()

    for m in re.finditer(r"static\s+const\s+steel_facet_id_t\s+(\w+)\s*=\s*STEEL_FACET_ID_INIT\((.*?)\);", src, re.S):
        sym = m.group(1)
        vals = [v.strip() for v in m.group(2).split(",")]
        if len(vals) != 16:
            raise ValueError(f"facet {sym} does not have 16 bytes")
        facets[sym] = vals

    vtable_start_re = re.compile(r"static\s+const\s+steel_vtable_entry_t\s+(\w+)\s*\[\]\s*=", re.M)
    for m in vtable_start_re.finditer(src):
        name = m.group(1)
        body, _end = find_brace_block(src, m.end())
        entry_re = re.compile(
            r"\{\s*"
            r"\.method_id\s*=\s*(?P<method_id>[^,]+),\s*"
            r"\.method_name\s*=\s*\"(?P<method_name>[^\"]+)\",\s*"
            r"\.steel_fun_signature\s*=\s*\{\s*"
            r"\.param_count\s*=\s*(?P<param_count>\d+)\s*,\s*"
            r"(?:\.param_types\s*=\s*STEEL_SIG_TYPES\((?P<param_types>[^)]*)\)\s*,\s*)?"
            r"\.result_type\s*=\s*(?P<result_type>[A-Z0-9_]+)\s*,\s*"
            r"\}\s*,\s*"
            r"\}\s*,",
            re.S,
        )
        entries = []
        for em in entry_re.finditer(body):
            param_count = int(em.group("param_count"))
            ptypes_raw = em.group("param_types")
            if ptypes_raw is None or ptypes_raw.strip() == "":
                param_types: List[str] = []
            else:
                param_types = [p.strip() for p in ptypes_raw.split(",") if p.strip()]
            if len(param_types) != param_count:
                # Allow zero-param without param_types; otherwise strict.
                if not (param_count == 0 and len(param_types) == 0):
                    raise ValueError(
                        f"vtable {name} method {em.group('method_name')} param_count mismatch: {param_count} vs {len(param_types)}"
                    )
            entries.append(
                {
                    "method_id": em.group("method_id").strip(),
                    "method_name": em.group("method_name"),
                    "param_types": param_types,
                    "result_type": em.group("result_type").strip(),
                }
            )
        vtables[name] = entries

    for m in re.finditer(
        r"static\s+const\s+steel_facet_contract_t\s+\w+\s*=\s*\{\s*(\w+)\s*,\s*(\w+)\s*,\s*\d+\s*,?\s*\};",
        src,
        re.S,
    ):
        contracts.append((m.group(1), m.group(2)))

    return method_consts, facets, vtables, contracts


def resolve_method_id(expr: str, method_consts: Dict[str, str]) -> str:
    expr = expr.strip()
    if expr in method_consts:
        return method_consts[expr]
    return expr


def c_param_for_type(t: str, idx: int) -> List[str]:
    name = f"arg{idx}"
    if t == "STEEL_SIG_TYPE_BOOL":
        return [f"uint8_t {name}"]
    if t == "STEEL_SIG_TYPE_CHAR":
        return [f"char {name}"]
    if t == "STEEL_SIG_TYPE_SCHAR":
        return [f"signed char {name}"]
    if t == "STEEL_SIG_TYPE_UCHAR":
        return [f"unsigned char {name}"]
    if t == "STEEL_SIG_TYPE_SHORT":
        return [f"short {name}"]
    if t == "STEEL_SIG_TYPE_USHORT":
        return [f"unsigned short {name}"]
    if t == "STEEL_SIG_TYPE_INT":
        return [f"int {name}"]
    if t == "STEEL_SIG_TYPE_UINT":
        return [f"unsigned int {name}"]
    if t == "STEEL_SIG_TYPE_LONG":
        return [f"long {name}"]
    if t == "STEEL_SIG_TYPE_ULONG":
        return [f"unsigned long {name}"]
    if t == "STEEL_SIG_TYPE_LLONG":
        return [f"long long {name}"]
    if t == "STEEL_SIG_TYPE_ULLONG":
        return [f"unsigned long long {name}"]
    if t == "STEEL_SIG_TYPE_FLOAT":
        return [f"float {name}"]
    if t == "STEEL_SIG_TYPE_DOUBLE":
        return [f"double {name}"]
    if t == "STEEL_SIG_TYPE_LDOUBLE":
        return [f"long double {name}"]
    if t in ("STEEL_SIG_TYPE_VOID_PTR", "STEEL_SIG_TYPE_OBJ_PTR"):
        return [f"uintptr_t {name}"]
    if t == "STEEL_SIG_TYPE_U32":
        return [f"uint32_t {name}"]
    if t == "STEEL_SIG_TYPE_BYTES":
        return [f"steel_bytes_view_t {name}"]
    raise ValueError(f"unsupported param type {t}")


def c_out_param_for_type(t: str) -> List[str]:
    result_map = {
        "STEEL_SIG_TYPE_BOOL": "uint8_t",
        "STEEL_SIG_TYPE_CHAR": "char",
        "STEEL_SIG_TYPE_SCHAR": "signed char",
        "STEEL_SIG_TYPE_UCHAR": "unsigned char",
        "STEEL_SIG_TYPE_SHORT": "short",
        "STEEL_SIG_TYPE_USHORT": "unsigned short",
        "STEEL_SIG_TYPE_INT": "int",
        "STEEL_SIG_TYPE_UINT": "unsigned int",
        "STEEL_SIG_TYPE_LONG": "long",
        "STEEL_SIG_TYPE_ULONG": "unsigned long",
        "STEEL_SIG_TYPE_LLONG": "long long",
        "STEEL_SIG_TYPE_ULLONG": "unsigned long long",
        "STEEL_SIG_TYPE_FLOAT": "float",
        "STEEL_SIG_TYPE_DOUBLE": "double",
        "STEEL_SIG_TYPE_LDOUBLE": "long double",
        "STEEL_SIG_TYPE_VOID_PTR": "uintptr_t",
        "STEEL_SIG_TYPE_OBJ_PTR": "uintptr_t",
        "STEEL_SIG_TYPE_U32": "uint32_t",
        "STEEL_SIG_TYPE_BYTES": "steel_proxy_bytes_t",
    }
    if t == "STEEL_SIG_TYPE_VOID":
        return []
    if t in result_map:
        return [f"{result_map[t]} *out_result"]
    raise ValueError(f"unsupported result type {t}")


def emit_assign_for_type(t: str, idx: int) -> str:
    n = f"arg{idx}"
    if t == "STEEL_SIG_TYPE_BYTES":
        return f"  args[{idx}].as.bytes.ptr = {n}.ptr;\n  args[{idx}].as.bytes.len = {n}.len;"
    field_map = {
        "STEEL_SIG_TYPE_BOOL": "boolean",
        "STEEL_SIG_TYPE_CHAR": "c",
        "STEEL_SIG_TYPE_SCHAR": "sc",
        "STEEL_SIG_TYPE_UCHAR": "uc",
        "STEEL_SIG_TYPE_SHORT": "s",
        "STEEL_SIG_TYPE_USHORT": "us",
        "STEEL_SIG_TYPE_INT": "i",
        "STEEL_SIG_TYPE_UINT": "ui",
        "STEEL_SIG_TYPE_LONG": "l",
        "STEEL_SIG_TYPE_ULONG": "ul",
        "STEEL_SIG_TYPE_LLONG": "ll",
        "STEEL_SIG_TYPE_ULLONG": "ull",
        "STEEL_SIG_TYPE_FLOAT": "f",
        "STEEL_SIG_TYPE_DOUBLE": "d",
        "STEEL_SIG_TYPE_LDOUBLE": "ld",
        "STEEL_SIG_TYPE_VOID_PTR": "ptr",
        "STEEL_SIG_TYPE_OBJ_PTR": "ptr",
        "STEEL_SIG_TYPE_U32": "u32",
    }
    return f"  args[{idx}].as.{field_map[t]} = {n};"


def emit_store_result_for_type(t: str) -> str:
    if t == "STEEL_SIG_TYPE_VOID":
        return ""
    if t == "STEEL_SIG_TYPE_BYTES":
        return "\n".join(
            [
                "  out_result->ptr = NULL;",
                "  out_result->len = 0;",
                "  if (typed_result.value.as.bytes.len > 0) {",
                "    out_result->ptr = (uint8_t *)malloc(typed_result.value.as.bytes.len);",
                "    if (out_result->ptr == NULL) {",
                "      steel_typed_result_free(&typed_result);",
                "      return -1;",
                "    }",
                "    memcpy(out_result->ptr, typed_result.value.as.bytes.ptr, typed_result.value.as.bytes.len);",
                "    out_result->len = typed_result.value.as.bytes.len;",
                "  }",
            ]
        )
    field_map = {
        "STEEL_SIG_TYPE_BOOL": "boolean",
        "STEEL_SIG_TYPE_CHAR": "c",
        "STEEL_SIG_TYPE_SCHAR": "sc",
        "STEEL_SIG_TYPE_UCHAR": "uc",
        "STEEL_SIG_TYPE_SHORT": "s",
        "STEEL_SIG_TYPE_USHORT": "us",
        "STEEL_SIG_TYPE_INT": "i",
        "STEEL_SIG_TYPE_UINT": "ui",
        "STEEL_SIG_TYPE_LONG": "l",
        "STEEL_SIG_TYPE_ULONG": "ul",
        "STEEL_SIG_TYPE_LLONG": "ll",
        "STEEL_SIG_TYPE_ULLONG": "ull",
        "STEEL_SIG_TYPE_FLOAT": "f",
        "STEEL_SIG_TYPE_DOUBLE": "d",
        "STEEL_SIG_TYPE_LDOUBLE": "ld",
        "STEEL_SIG_TYPE_VOID_PTR": "ptr",
        "STEEL_SIG_TYPE_OBJ_PTR": "ptr",
        "STEEL_SIG_TYPE_U32": "u32",
    }
    if t not in field_map:
        raise ValueError(f"unsupported result type {t}")
    return f"  *out_result = typed_result.value.as.{field_map[t]};"


def generate(input_path: pathlib.Path, out_header: pathlib.Path, out_source: pathlib.Path) -> None:
    src = input_path.read_text(encoding="utf-8")
    method_consts, facets, vtables, contracts = parse_contracts(src)

    methods = []
    for facet_sym, vtable_sym in contracts:
        if facet_sym not in facets:
            continue
        for e in vtables.get(vtable_sym, []):
            method_id_expr = resolve_method_id(e["method_id"], method_consts)
            facet_slug = sanitize_ident(re.sub(r"^FACET_", "", facet_sym, flags=re.I))
            method_slug = sanitize_ident(e["method_name"])
            fn_name = f"steel_proxy_gen_{facet_slug}_{method_slug}"
            methods.append(
                {
                    "fn_name": fn_name,
                    "facet_sym": facet_sym,
                    "facet_bytes": facets[facet_sym],
                    "method_id_expr": method_id_expr,
                    "method_name": e["method_name"],
                    "param_types": e["param_types"],
                    "result_type": e["result_type"],
                }
            )

    out_header.parent.mkdir(parents=True, exist_ok=True)
    out_source.parent.mkdir(parents=True, exist_ok=True)

    hdr = []
    hdr.append("/* Auto-generated by scripts/generate_proxies.py. Do not edit manually. */")
    hdr.append("#ifndef STEEL_PROXY_GENERATED_H")
    hdr.append("#define STEEL_PROXY_GENERATED_H")
    hdr.append("\n#include <stddef.h>\n#include <stdint.h>\n")
    hdr.append('#include "steel/proxy.h"\n')
    hdr.append("#ifdef __cplusplus\nextern \"C\" {\n#endif\n")

    src_out = []
    src_out.append("/* Auto-generated by scripts/generate_proxies.py. Do not edit manually. */")
    src_out.append('#include "steel/proxy_generated.h"')
    src_out.append("\n#include <stdlib.h>\n#include <string.h>\n")

    facet_done = set()
    for m in methods:
        fs = m["facet_sym"]
        if fs in facet_done:
            continue
        facet_done.add(fs)
        vals = ", ".join(m["facet_bytes"])
        src_out.append(f"static const steel_facet_id_t {fs} = STEEL_FACET_ID_INIT({vals});")

    src_out.append("")

    for m in methods:
        params = [
            "steel_plugin_t *plugin",
            "uint32_t receiver_handle",
            "uint32_t permissions",
        ]
        for i, t in enumerate(m["param_types"]):
            params.extend(c_param_for_type(t, i))
        params.extend(c_out_param_for_type(m["result_type"]))
        params.extend(["char *err", "size_t err_len"])
        proto = f"int {m['fn_name']}({', '.join(params)});"
        hdr.append(proto)

        obj_param_types = m["param_types"]
        obj_skip_receiver = len(obj_param_types) > 0 and obj_param_types[0] == "STEEL_SIG_TYPE_U32"
        obj_fn_name = f"steel_object_proxy_gen_{sanitize_ident(re.sub(r'^FACET_', '', m['facet_sym'], flags=re.I))}_{sanitize_ident(m['method_name'])}"
        obj_params = [
            "const steel_object_t *object",
        ]
        for i, t in enumerate(obj_param_types[1:] if obj_skip_receiver else obj_param_types):
            obj_params.extend(c_param_for_type(t, i))
        obj_params.extend(c_out_param_for_type(m["result_type"]))
        obj_params.extend(["char *err", "size_t err_len"])
        obj_proto = f"int {obj_fn_name}({', '.join(obj_params)});"
        hdr.append(obj_proto)

        src_out.append(proto[:-1] + " {")
        arg_count = len(m["param_types"])
        src_out.append(f"  steel_typed_value_t args[{arg_count if arg_count > 0 else 1}];")
        src_out.append("  steel_typed_result_t typed_result;")
        src_out.append("  int rc;")
        if m["result_type"] != "STEEL_SIG_TYPE_VOID":
            src_out.append("  if (out_result == NULL) {")
            src_out.append("    return -1;")
            src_out.append("  }")
        src_out.append("  memset(args, 0, sizeof(args));")
        src_out.append("  memset(&typed_result, 0, sizeof(typed_result));")

        for i, t in enumerate(m["param_types"]):
            src_out.append(f"  args[{i}].type = {t};")
            src_out.append(emit_assign_for_type(t, i))

        src_out.append(
            f"  rc = steel_plugin_invoke_typed(plugin, &{m['facet_sym']}, {m['method_id_expr']}, receiver_handle, permissions, "
            f"{('args' if arg_count > 0 else 'NULL')}, {arg_count}, &typed_result, err, err_len);"
        )
        src_out.append("  if (rc != 0) {")
        src_out.append("    return rc;")
        src_out.append("  }")
        src_out.append(f"  if (typed_result.value.type != {m['result_type']}) {{")
        src_out.append("    steel_typed_result_free(&typed_result);")
        src_out.append("    return -1;")
        src_out.append("  }")
        store_lines = emit_store_result_for_type(m["result_type"])
        if store_lines:
            src_out.append(store_lines)
        src_out.append("  steel_typed_result_free(&typed_result);")
        src_out.append("  return 0;")
        src_out.append("}")
        src_out.append("")

        src_out.append(obj_proto[:-1] + " {")
        obj_arg_types = obj_param_types[1:] if obj_skip_receiver else obj_param_types
        obj_arg_count = len(obj_arg_types)
        src_out.append(f"  steel_typed_value_t args[{obj_arg_count if obj_arg_count > 0 else 1}];")
        src_out.append("  steel_typed_result_t typed_result;")
        src_out.append("  int rc;")
        src_out.append("  if (object == NULL) {")
        src_out.append("    return -1;")
        src_out.append("  }")
        if m["result_type"] != "STEEL_SIG_TYPE_VOID":
            src_out.append("  if (out_result == NULL) {")
            src_out.append("    return -1;")
            src_out.append("  }")
            if m["result_type"] == "STEEL_SIG_TYPE_BYTES":
                src_out.append("  out_result->ptr = NULL;")
                src_out.append("  out_result->len = 0;")
        src_out.append("  memset(args, 0, sizeof(args));")
        src_out.append("  memset(&typed_result, 0, sizeof(typed_result));")
        for i, t in enumerate(obj_arg_types):
            src_out.append(f"  args[{i}].type = {t};")
            src_out.append(emit_assign_for_type(t, i))
        src_out.append(
            f"  rc = steel_object_invoke_typed(object, &{m['facet_sym']}, {m['method_id_expr']}, object->default_permissions, "
            f"{('args' if obj_arg_count > 0 else 'NULL')}, {obj_arg_count}, &typed_result, err, err_len);"
        )
        src_out.append("  if (rc != 0) {")
        src_out.append("    return rc;")
        src_out.append("  }")
        src_out.append(f"  if (typed_result.value.type != {m['result_type']}) {{")
        src_out.append("    steel_typed_result_free(&typed_result);")
        src_out.append("    return -1;")
        src_out.append("  }")
        store_lines = emit_store_result_for_type(m["result_type"])
        if store_lines:
            src_out.append(store_lines)
        src_out.append("  steel_typed_result_free(&typed_result);")
        src_out.append("  return 0;")
        src_out.append("}")
        src_out.append("")

    hdr.append("\n#ifdef __cplusplus\n}\n#endif")
    hdr.append("\n#endif")

    out_header.write_text("\n".join(hdr) + "\n", encoding="utf-8")
    out_source.write_text("\n".join(src_out) + "\n", encoding="utf-8")


def main() -> int:
    p = argparse.ArgumentParser(description="Generate Steel proxy wrappers from contracts source")
    p.add_argument("--input", default="src/contracts_builtin.c")
    p.add_argument("--header", default="build/generated/include/steel/proxy_generated.h")
    p.add_argument("--source", default="build/generated/src/proxy_generated.c")
    args = p.parse_args()
    generate(pathlib.Path(args.input), pathlib.Path(args.header), pathlib.Path(args.source))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
