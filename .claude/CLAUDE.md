# lean-archive

Tar and ZIP archives in Lean 4, on top of lean-zip (verified DEFLATE) and
lean-zlib (zlib FFI). Extracted from kim-em/lean-zip.

## Build and Test

    lake build
    lake exe test

Run from the project root. Tests require `testdata/`. Needs system zlib +
pkg-config; on NixOS use `nix-shell`. Lake caches `run_io` link flags in
`.lake/`; after environment changes use `lake -R build` or `rm -rf .lake`.

## Standards

- This code parses hostile bytes. Any new parser, extraction path, or
  streaming API must update `SECURITY.md` in the same change set (trust
  status, guardrails, missing work), per its *Required maintenance rule*.
- Every guard needs a minimized malformed fixture in `testdata/` plus a
  corpus row in `SECURITY.md`; build fixtures byte-deterministically via a
  `scripts/build-*` generator.
- Bounded reads only: attacker-controlled sizes go through the
  `readBounded*` helpers, never straight to `Handle.read`/`Stream.read`.
- Keep error-message substrings stable — tests match on them.
- Commits: conventional prefixes (`feat:`, `fix:`, `test:`, ...), one
  logical change each, must compile and pass tests.
