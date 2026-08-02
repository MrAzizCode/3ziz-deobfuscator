# Test and Acceptance Plan

Tests are static unless a synthetic test explicitly exercises the TypeScript
engine itself. No supplied Lua/Luau fixture is executed.

## Semantic micro-tests

- table constructor identity and aliases;
- impure call count and evaluation order;
- anonymous/named closure capture followed by rebinding;
- self-recursive closures and nested shadowing;
- full `{...}` capture and `callback(...)` forwarding;
- scalarization differences between `local x = f(); return x` and `return f()`;
- last-argument multiple-result expansion;
- simultaneous assignment and nil holes;
- `__index`, `__add`, and `__len` sensitive expressions;
- receiver evaluation in dot-call versus colon-call;
- duplicate table keys and impure key/value order;
- tail-call and error-timing barriers;
- invalid, colliding, and reserved-word rename proposals.

The initial authoritative cleanup pass must skip any case it cannot prove.

## Detector tests

- plain Lua, Luau extensions, Lua 5.1 bytecode, text, and VM audit IR;
- MoonSec V3 marker plus structural-density evidence;
- Luraph marker, VM factory/dispatcher signals, and audit-output signals;
- ambiguous and weak evidence;
- deterministic tie handling;
- misleading markers inside comments/strings are low-weight evidence.

## Bytecode tests

- valid minimal Lua 5.1 chunk;
- bad signature/version/format;
- unsupported endianness and scalar sizes;
- truncated strings/instructions/constants/prototypes/debug tables;
- out-of-range counts and integer overflow;
- excessive nesting/prototype/instruction/constant counts;
- valid constant tags and unknown tag rejection;
- stable disassembly and branch-target diagnostics.

## Path and resource tests

- extension allowlist and 10 MiB limit;
- filenames with quotes, spaces, Unicode, and traversal-looking segments;
- immutable input and non-overwriting exports;
- unique random job IDs;
- worker timeout, cancellation, output caps, and malformed messages;
- renderer IPC sender and request-shape validation.

## Regression fixtures

Regression suites run against privately supplied obfuscated samples. Neither
the samples nor anything derived from them is part of this repository: they
carry no redistribution license. Each suite pins its input by SHA-256 and skips
itself when that input is absent, so a clean clone is green without them.

Assertions are structural rather than textual — counts, ratios, classification,
and status — so they verify behavior without embedding recovered content.

Categories covered:

- a source-level wrapper family: detected with explainable high-confidence
  evidence, never executed, and reported `partial` while no reviewed extractor
  is installed;
- a decompiler-polished script: parses as Lua 5.1, retains vararg forwarding,
  closure bindings, and multiple-return positions, and has its dynamic-loading
  and hook APIs inventoried without being invoked;
- a VM audit reconstruction: classified as non-executable audit IR, with label
  and goto references validated per function, unresolved fragments retained,
  and the dump never presented as readable source;
- a compact audit report: classified as audit pseudocode rather than drop-in
  executable source, with its uncertainty statements preserved;
- a VM-protected payload: streams located and decoded, records read end to end,
  and the target section devirtualized into Lua that re-parses, with coverage
  and unresolved counts asserted.

## Release gate

- unit and regression tests pass;
- typecheck and production build pass;
- packaged renderer contains no Node integration or remote assets;
- a static scan finds no code path that evaluates submitted Lua/Luau;
- smoke analysis succeeds for generic Lua, MoonSec wrapper detection, UtopiaSpy,
  Luraph VM audit, malformed input, and minimal Lua 5.1 bytecode;
- exported manifests verify every artifact hash;
- unsupported stages are visible in both UI and `warnings.md`.

