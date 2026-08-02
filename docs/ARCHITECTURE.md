# 3ziz Deobfuscator Architecture

Status: implementation baseline, 2026-07-29

## Product boundary

“Autonomous” means that the application automatically imports, fingerprints,
plans, analyzes, validates, and exports a job. It does not mean executing
unknown code, guessing an obfuscator from weak evidence, or letting a language
model rewrite authoritative output.

The application does not promise universal deobfuscation. Its statuses are:

- `verified`
- `recovered-with-warnings`
- `partial`
- `unsupported`
- `failed-validation`
- `cancelled`

The first build is an Electron + React Windows application around an
independent TypeScript core and CLI. Electron was selected for this executable
milestone because the supplied prototype and the available toolchain are
Node-based. The renderer has no Node integration, runs with context isolation
and Chromium sandboxing, loads packaged local content only, and receives a
small validated IPC surface. A later Tauri broker can replace Electron without
changing core job or plugin contracts.

## Trust boundaries

```text
Untrusted input bytes
        |
        v
Desktop broker (path validation, limits, new non-overwriting job directory)
        |
        v
Static worker process (minimal environment, no shell, timeout)
        |
        +--> detectors and source/IR analyzers
        +--> Lua 5.1 bytecode validator/disassembler
        +--> proof-gated source passes
        |
        v
Artifact store (new files only, SHA-256 manifest)
        |
        v
Sandboxed renderer (read-only job/result presentation)
```

The static worker never evaluates Lua/Luau and does not receive Electron,
browser, credential, network, or shell APIs. The worker is not a complete OS
sandbox; therefore all implemented stages are static parsers and scanners.

## Packages

```text
src/
  core/
    artifacts/       immutable artifacts and manifests
    bytecode/        bounded Lua 5.1 chunk parser/disassembler
    detectors/       dialect/format/obfuscator evidence
    passes/          deterministic source transformations
    plugins/         generic, JNKIE/Luraph 14.7, MoonSec V3, Luraph audit
    validation/      invariants and before/after facts
    behavior/        reachability-neutral capability inventory
    jobs/            state machine, limits, cancellation
  cli/               shell-independent command line
  desktop/           Electron broker and narrow preload bridge
  renderer/          React user interface
tests/
  synthetic/         semantic and adversarial micro-fixtures
  regression/        supplied-fixture structural assertions
```

## Stable data contracts

```ts
interface DeobfuscatorPlugin {
  readonly manifest: PluginManifest;
  detect(context: DetectionContext): Promise<DetectionResult>;
  plan(context: AnalysisContext): Promise<StagePlan>;
  analyze(context: AnalysisContext): Promise<PluginAnalysis>;
  validate(context: ValidationContext): Promise<ValidationReport>;
}

interface Diagnostic {
  code: string;
  severity: "info" | "warning" | "error";
  stage: string;
  message: string;
  evidence?: string[];
  suggestedAction?: string;
}
```

Plugins may not spawn tools directly. Future sidecars are requested through one
broker with an allowlisted executable identity, argument arrays, a fresh job
directory, time/output limits, and process-tree cancellation.

## Automatic selection

1. Hash and classify the exact input bytes.
2. Run all cheap detectors.
3. Sort by confidence, then deterministic plugin ID.
4. Select a family plugin only at or above `0.70` confidence and with at least
   `0.15` margin over the next family plugin.
5. Otherwise use the generic static plugin and emit ambiguity diagnostics.
6. Freeze the stage plan before analysis.

Detection evidence, including negative evidence, is recorded in `report.json`.

## Plugin routes

```text
Lua source / register decompile
  -> parse -> binding facts -> proof-gated cleanup -> reparse -> readable output

Lua 5.1 bytecode
  -> bounded structural validation -> prototype tree -> exact disassembly
  -> optional reviewed decompiler ensemble in a future sidecar stage

MoonSec V3 wrapper
  -> scored static detection
  -> reviewed static extractor sidecar (not bundled in the foundation release)
  -> bytecode route

Luraph audit reconstruction
  -> detect non-executable VM IR -> labels/gotos/metadata validation
  -> audit and behavior report

Luraph protected loader
  -> scored static detection
  -> unsupported in static-only release
  -> future explicit opt-in capture route in a restricted Luau runtime
```

MoonSec and Luraph assumptions never enter generic source passes.
JNKIE/Luraph 14.7 wrapper
: The built-in static route recognizes the paired `LPH@V`/`LPH!` streams,
  reverses the wrapper's Ascii85 transform, and uses a bounded pure-JavaScript
  raw LZMA decoder. Recovered loader code remains inert data.


## Pass rules

Each source pass records:

- ID and version;
- preconditions;
- edits with source ranges;
- facts before and after;
- validation result;
- confidence and diagnostics.

Authoritative passes must preserve lexical binding, table identity, evaluation
count/order, closure rebinding, varargs, multiple-return position, and
metamethod-sensitive operations. An uncertain rewrite is skipped.

The supplied `beautify_decompiled_lua.mjs` is treated as research evidence, not
copied wholesale. In particular, name-based substitution, broad purity
classification, call inlining, dot-to-colon conversion, and cross-scope rename
profiles are not accepted without stronger binding/proof infrastructure.

## Output layers

| Layer | Contract |
|---|---|
| Exact audit | Preserves submitted source, bytecode disassembly, or recovered VM IR and all unknowns. |
| Readable | Only mechanically justified formatting, alpha-renaming, and constant reconstruction. |
| Behavior report | Static capability inventory with evidence and explicit reachability limits. |
| Machine JSON | Complete job, detection, stage, pass, diagnostic, validation, and artifact data. |

“Exact” means traceable to supplied/recovered evidence. It does not mean
restoration of lost names, comments, or original high-level control flow.

## Sidecar readiness

The interfaces reserve adapters for a MoonSec V3 static extractor, unluac, and
LuaDec. A sidecar is not shipped until its provenance, license, Windows build,
hash, input/output contract, and malformed-input behavior have been reviewed.
The unrelated supplied Linux CPython extension is never a candidate sidecar.

