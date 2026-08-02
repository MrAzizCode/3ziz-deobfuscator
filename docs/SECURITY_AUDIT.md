# Dependency and Release Security Notes

Last checked: 2026-08-01

## Dependency audit

- `npm audit --omit=dev`: **0 vulnerabilities** in the production npm
  dependency graph. This does not audit Electron's embedded Chromium/Node
  binary, which is installed as a packaging dependency.
- Full `npm audit`: **0 vulnerabilities** in the complete npm dependency graph
  at the time of this check.
- Electron is pinned to `43.2.0`; its security advisories and supported release
  line must be reviewed before each published build.

Registry audit results can change as advisories are published. Builds must run
only against this trusted repository, trusted local paths, and the pinned
lockfile; do not point the packaging process at attacker-controlled project
trees, templates, or filenames.

## Supplied inputs

All supplied Lua/Luau examples are regression fixtures read as bytes or text.
They are never executed. The supplied encrypted Linux CPython extension is not
imported, bundled, or placed on a sidecar allowlist.

## Release checks

Before publishing a build:

1. Run the typecheck, deterministic test suite, production build, and both npm
   audits.
2. Confirm the packaged renderer has Node integration disabled, context
   isolation and Chromium sandboxing enabled, no remote assets, and a narrow
   preload bridge.
3. Verify the installer and portable executable hashes after packaging.
4. Build from a clean checkout using the committed lockfile.

