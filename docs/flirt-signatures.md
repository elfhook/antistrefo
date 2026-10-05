# flirt-signatures.md - the pattern language, the built in database and its provenance.
# Module: docs (Markdown).
# Owns: what a signature means, what was verified, and what is deliberately not claimed.
# Depends: src/features/lib/re_flirt.h, src/features/lib/re_sigfile.h, .rules/rules.md.

## What a signature is

A signature is a byte pattern, a name, and a module. It is compared against the first
bytes of a function that recursive descent already recovered. A match on the opening
bytes is evidence about what a function is, and a function that matches nothing is left
unnamed; it is never given a name that a pattern did not earn.

## The pattern language

Tokens, separated by optional spaces:

| Token | Meaning |
|---|---|
| `hh` | exactly this byte |
| `??` | any byte |
| `h?` | high nibble fixed, low nibble any |
| `?h` | low nibble any, high nibble fixed |
| `!hh` | any byte except this one |
| `@` | four bytes of a relative displacement |

A pattern that is malformed, longer than 256 bytes, or whose slack covers every byte it
claims is refused at compile time rather than loaded. That matters more than it looks:
a signature that cannot match anything still counts as a loaded signature, so a file
that does nothing reads exactly like a database that found nothing.

An optional trailing slack field says how many bytes at the end of the pattern the
signature makes no claim about. It is how one pattern covers a prologue whose final
stack adjustment is not known in advance.

Wildcarded bytes are worth thinking about before they are written. A pattern wildcarded
down to something generic earns a confident wrong name, which is worse than no name at
all, so the built in entries below keep their claim as wide as the verification allowed.

## Signature files

The native format, one signature per line, `#` starting a comment:

    memcpy : vcruntime : 488bc14c8d15@4983f80f0f87@
    memset : vcruntime : 488bc14c8bc94c8d15@ : 4

The IDA `.pat` dialect is read as well, chosen by the file's suffix. The subset supported
is: entries separated by a line of eight or more dashes, a header line of
`<crc16> <length> <name>`, the pattern in hex with `.` or `?` for a wildcard half byte
and two of them for a whole one, then a line of three dashes, then tail bytes.

Two limits in that reader are deliberate and stated rather than hidden:

- The **crc16 is read and not enforced.** The polynomial behind it is not reproducible
  from the format's documentation, and checking against a guessed one would reject valid
  signatures while looking like a real check.
- The **length field is checked for shape only**, for the same reason.
- **Tail bytes are read past, not applied.** They are for matching functions whose
  pattern does not start at the entry, which this matcher does not do, so an entry that
  needs them contributes its pattern and not its tail.
- Binary `.sig` files are **not** read. The format is not documented reliably enough to
  implement without guessing, and shipping vendor signature files is not an option.

The reader was built from the format's description and is covered by hand written
fixtures. It has **not** been run against a vendor produced `.pat` file, because none was
available. A file outside the subset is counted as refused, so the failure mode is a
refusal count rather than a wrong match.

## How the built in database was built

Nothing in the table was written from memory. The procedure was:

1. Compile a small program with `/MT /O2` so the static runtime is linked in, and with
   `/MAP` so the linker states the address of every public symbol.
2. Read the map to get the true address of each function to be covered.
3. Read the bytes at those addresses out of the built image.
4. Write a pattern from those bytes, with `@` over the displacements that a link decides.
5. Verify by running the tool over that image and checking that each signature named the
   function **at exactly the address the map states**, and that no other function was
   named.

Step 5 is the part that makes the rest more than an assertion. The run reported 9 named
functions out of 349 recovered: the 9 expected ones, at the 9 expected addresses, and
nothing else. Each one was also confirmed by hand from its disassembly; the security
cookie check, for example, disassembles to compare, rotate, test, return, and then a jump
to the failure report, which is what that function is.

A second check was run on unrelated binaries. On a 12.8 KB x64 driver the only built in
signature that fires is `__security_check_cookie`, which is correct: that driver links
the static runtime's `/GS` check and nothing else from the CRT. A signature that had fired
on unrelated code would have been deleted before it was committed.

### Provenance

| Entry | Source | Verified against |
|---|---|---|
| `gs_cookie_init`, `gs_cookie_read`, `guard_dispatch_icall` | compiler idioms | their own shape; they are named for what they are |
| `__security_check_cookie` | MSVC x64 static runtime | linker map address, plus hand reading of the disassembly |
| `__chkstk` | MSVC x64 static runtime | linker map address |
| `memcpy`, `memset`, `memcmp`, `strlen`, `strcat`, `strcpy`, `strcmp` | MSVC 14.51 x64 `libvcruntime` and `libucrt` | linker map address |
| `__security_check_cookie` (also) | as above | fires on two independent real drivers at a plausible address |

`memcpy` and `memmove` share one implementation in this runtime, so the address resolves
to whichever name the linker chose; only `memcpy` is listed, and a reader whose runtime
differs can load that runtime's patterns as a file.

## What is not claimed

- **The CRT entries are version specific on purpose.** They were verified against the
  runtime of the toolchain that built this project, and a different runtime version may
  use different bytes. That is what per version signature files exist for, and why a file
  can be loaded over the built in set.
- **A match is evidence, not a fact.** A pattern is compared against the opening bytes of
  a function, which is what FLIRT has always done and why a match carries its module and
  its signature text in the report rather than just a name.
- **Coverage is measured, not promised.** The honest summary is the one produced by
  running the tool over a binary: `funcs` reports `named`, and `analyze` reports the
  signature pass count, so a claim about coverage can be checked rather than believed.
