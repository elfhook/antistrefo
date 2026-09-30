# util-catalog.md - the lookup to read before writing a function. Rule 0 depends on it.
# Module: docs (Markdown).
# Owns: one row per utility, kept in sync with src/utils by scripts/check.py.
# Depends: none. If a header is missing from this table the build fails.

## How to use this

Before writing any function past 60 lines or 4 nesting levels, grep `src/utils/`
or scan the table below. If something here already does the job, use it. If not,
and the helper will be needed twice or loops over bytes, add it here first.

## Memory and strings

| Util | Gives you | Header |
|---|---|---|
| `re_arena_*` | bump allocation, one malloc and one free per command | `re_arena.h` |
| `re_buf_*` | bounds checked reads over an mmap'd file, the safety boundary | `re_buf.h` |
| `re_json_*` | the streaming JSON writer, the only sanctioned stdout writer | `re_json.h` |
| `re_strbuf_*` | growable buffer, `put_u64`, `put_hex64`, `appendf` | `re_strbuf.h` |
| `re_str_*` | `eq`, `icmp`, `find`, `rfind`, `trim`, `split`, `join` | `re_str.h` |
| `re_fmt_*` | signed ints, arbitrary base, column padding, byte sizes | `re_fmt.h` |
| `re_hex_*` | encode, decode with separators, nibble table | `re_hex.h` |
| `re_entropy_*` | Shannon entropy over a span, for packer detection | `re_entropy.h` |
| `re_time_*` | Unix timestamp to ISO date and build year | `re_time.h` |

## Containers

| Util | Gives you | Header |
|---|---|---|
| `re_vec_*` | typed growable array, one implementation for every element | `re_vec.h` |
| `re_map_*` | string keyed open addressing map, arena backed | `re_map.h` |
| `re_set_*` | a set, which is a map that ignores its values | `re_set.h` |
| `re_sort_*` | introsort over raw bytes, shared by every container | `re_sort.h` |

## Bit and byte level

| Util | Gives you | Header |
|---|---|---|
| `re_bits_*` | popcount, ctz, clz, rotate, `align_up`, min and max | `re_bits.h` |
| `re_bswap*` | byte swap for the big endian ELF and Mach-O readers | `re_bits.h` |
| `re_crc_*` | CRC-16/X-25 and CRC-32/IEEE, call `re_crc_init` once | `re_crc.h` |
| `re_hash_*` | MD5 and SHA-256, one shot or streaming | `re_hash.h` |

## Search, paths and diagnostics

| Util | Gives you | Header |
|---|---|---|
| `re_rx_*` | backtracking regex, with a literal fast path and step caps | `re_regex.h` |
| `re_path_*` | absolute test, extension, dirname, join, normalize | `re_path.h` |
| `re_err_*` | error codes, the error record, exit code mapping | `re_err.h` |
| `re_log_*` | the only stderr writer, silent when muted or in mcp mode | `re_log.h` |
| `re_text_*` | fixed width table rendering for `--format text` | `re_text.h` |

## Aggregator

| Util | Gives you | Header |
|---|---|---|
| `re_util_*` | every header above in one include, for cli and mcp only | `re_util.h` |

## Private to the regex engine

`re_regex_priv.h` holds the instruction and node layouts. It is shared only by
`re_regex.c` and `re_regex_vm.c` and is never included by feature code.

## Not yet built

These are named in `.rules/rules.md` but do not exist yet. Do not add a second
implementation when you need one; build these first instead.

| Missing | Needed by | Replace with |
|---|---|---|
| `re_table.h` command table | the CLI and MCP tool list | duplicated argument parsing |

Built in task 1: `re_buf`, `re_json`, `re_entropy`, `re_text`, `re_pe`, `re_format`,
`re_strings`, `re_triage`, and the IR seam in `re_ir.h` plus `re_disasm.h`.
Built in task 2: `re_time`, plus the features `re_search`, `re_rules`, `re_demangle`
in `re_demangle.c` and `re_demangle_msvc.c`.
Built in task 3 so far: `re_ir` storage, `re_code` (the address and coverage map),
`re_func` (recursive descent), and the x86-64 backend under `src/features/disasm/`.
Nothing is still missing.

## Disassembly, and the Capstone question

Rules 8.1 planned a Capstone backend behind the `re_disasm` vtable. The backend in
`src/features/disasm/` is a self contained x86-64 decoder instead, for three
reasons, and the seam is unchanged either way:

- There is no vcpkg and no pkg-config here, so Capstone would mean vendoring or
  `FetchContent`, which costs minutes on every clean build.
- Task 3 needs instruction *lengths*, control flow classification and frame sizes,
  not full semantics. A length decoder is enough, and it is what makes the tree
  dependency free.
- The vtable is the contract, so a Capstone backend drops in later behind the same
  `re_disasm_find` lookup without touching a single caller.

What this means in practice, stated plainly rather than buried:

- The decoder covers the integer and SSE subset: prefixes, REX, VEX2, VEX3, EVEX,
  ModRM, SIB, displacements, and the immediate width rules. Unknown opcodes are
  refused, which stops a walk rather than letting it desynchronise.
- Text rendering is mnemonic only. Operand text, and the data flow half of the IR,
  arrive with the emitter in task 4.
- `re_x64_lower` models control flow only. A data flow instruction emits nothing,
  which the seam defines as not modelled, and is deliberate: a wrong LOAD is worse
  than no LOAD.

Scope note: the Itanium demangler handles nested names, template arguments,
substitutions and the common builtin types, and renders unknown template
parameters as `auto` rather than guessing. It refuses anything it cannot parse
confidently, so an unsupported symbol keeps its raw name instead of getting a
plausible wrong one.
