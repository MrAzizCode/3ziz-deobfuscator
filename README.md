# 3ziz Deobfuscator

A Windows desktop application for reading obfuscated Lua and Luau, built on one
rule: **submitted code is never executed.** Everything is static — parsing,
decoding, and reconstruction. There is no "run script" button, and there is no
code path that evaluates what you give it.

## What it does

**Reads modern Lua and Luau.** An in-tree lexer and parser cover Lua 5.1
through Luau: bitwise operators, floor division, hex-float and binary literals,
digit separators, string interpolation, compound assignment, `continue`, type
annotations, and `goto`/labels. Sources that off-the-shelf Lua 5.1 parsers
reject still reach analysis.

**Identifies what it is looking at.** Scored detectors classify plain Lua,
Luau, Lua 5.1 bytecode, VM audit IR, and known obfuscator families, with the
evidence — including negative evidence — recorded in the report. A family
plugin is only selected above a confidence threshold and margin; otherwise the
generic static route runs and the ambiguity is stated.

**Unpacks protected scripts.** Luraph-family payload streams are located in any
Lua string form, decoded in either 32-bit byte order, and decompressed or read
directly. Container count biases are inferred from the bytes by requiring a
candidate to decode the whole stream with every reference resolving, so a build
that ships different constants is still readable.

**Devirtualizes VM bytecode back to Lua.** Decoded instruction records are
lifted through a typed opcode-effect model into real, re-parseable Lua:
recovered global names, string and numeric literals, method calls, and folded
chained lookups. Basic blocks are re-ordered so control falls through rather
than jumping, and conditionals become `if` statements where a region is proven
to have a single entry and exit.

**Disassembles Lua 5.1 bytecode.** A bounded structural validator and
disassembler with depth, prototype, instruction, constant, and debug-table
limits checked before allocation.

**Reports capabilities, not guesses.** A reachability-neutral inventory lists
APIs, URLs, and suspicious capabilities found statically, with explicit limits
on what that implies.

**Exports a verifiable bundle.** Every job writes a new directory: a
byte-exact copy of the input, the readable output, an evidence-first exact
audit, behavior and validation reports, machine-readable JSON, a warnings file,
and a manifest with a SHA-256 for every artifact.

## What it does not claim

Compilation destroys local variable names, comments, and source layout. Those
are **not** recovered — synthesized names are emitted and labelled as such in
the output header. Opcodes that a build never proved keep their operands and
byte ranges as inline comments rather than being guessed at. Regions that
cannot be proven structurable keep `goto` and labels rather than being forced
into a shape they do not have. Coverage is reported as a number, and unresolved
work is reported instead of being hidden.

Statuses are honest: `verified`, `recovered-with-warnings`, `partial`,
`unsupported`, `failed-validation`, `cancelled`.

## Safety design

- Submitted Lua/Luau is never executed. No `load`, `loadstring`, `dofile`,
  executor, native library load, or generated shell command.
- Inputs are hashed before decoding and copied unchanged; originals are never
  overwritten and exports always go to a newly created directory.
- Analysis runs in a separate worker process with a minimal environment and
  wall-clock and memory ceilings, terminated on timeout or cancel.
- The renderer runs with `nodeIntegration: false`, `contextIsolation: true`,
  `sandbox: true`, a restrictive CSP, no remote content, blocked navigation,
  and a small validated IPC surface.
- Recovered source is rendered as text, never injected as HTML.
- Accepted extensions and a 10 MiB input ceiling are enforced; paths are
  normalized and resolved before policy checks.

A worker process is a fault and resource boundary, not a full OS sandbox. That
is acceptable precisely because nothing submitted is ever evaluated; any future
dynamic capture would need an additional sandbox and its own review.

## Requirements

Windows 10/11, Node.js 22+, npm.

```bash
npm ci
```

```bash
npm test
```

```bash
npm start
```

Build the portable app and installer:

```bash
npm run package:win
```

Locally produced executables are unsigned unless a code-signing certificate is
configured, so Windows may show a SmartScreen warning. Verify the release hash
before running an unsigned build.

There is also a shell-independent CLI:

```bash
npx tsx src/cli/index.ts analyze <input> --out <jobs-directory>
```

## Samples

No obfuscated samples or artifacts derived from them are included. They carry
no redistribution license and are not ours to publish. Suites that need a
private sample skip themselves when it is absent; point
`THREEZIZ_JNKIE_FIXTURE` at your own copy to run them.

## Authorized use only

Analyze only code you own or are explicitly authorized to inspect.

## Documentation

[Architecture](docs/ARCHITECTURE.md) · [Threat model](docs/THREAT_MODEL.md) ·
[Test plan](docs/TEST_PLAN.md) · [Dependency notes](docs/SECURITY_AUDIT.md)

## License

UNLICENSED. No ownership is claimed over analyzed or derivative code.
