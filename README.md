# lean-archive

**Tar and ZIP archives in Lean 4.**

Pure-Lean archive parsing and construction, with compression provided by
[lean-zlib](https://github.com/kim-em/lean-zlib) (system zlib via FFI) and
decompression selectable between zlib and the formally verified pure-Lean
DEFLATE decoder from [lean-zip](https://github.com/kim-em/lean-zip).

The parsers and extractors are hardened against malformed and hostile
input — path traversal, symlink escapes, decompression bombs, oversized
metadata — with an 87-fixture malformed-input regression corpus and a
per-callsite audit of every read driven by untrusted bytes. See
[SECURITY.md](SECURITY.md).

Extracted from [lean-zip](https://github.com/kim-em/lean-zip)
(`pre-split` tag).

## Using it

Add to your `lakefile.lean`:

```lean
require "kim-em" / "lean-archive"
```

### Tar archives

```lean
import Archive

-- Create .tar.gz from a directory (streaming, bounded memory)
Tar.createTarGz "/tmp/archive.tar.gz" "/path/to/dir"

-- Extract .tar.gz
Tar.extractTarGz "/tmp/archive.tar.gz" "/tmp/output"

-- Extract .tar.gz using the verified pure-Lean gzip/DEFLATE decoder
Tar.extractTarGzNative "/tmp/archive.tar.gz" "/tmp/output"

-- Create/extract raw .tar via IO.FS.Stream
Tar.createFromDir stream dir
Tar.extract stream outDir

-- List entries without extracting
let entries ← Tar.list stream
```

Tar supports UStar, PAX extended headers (for long paths, large files, UTF-8),
and GNU long name/link extensions. Paths exceeding UStar limits are
automatically encoded with PAX headers on creation.

### ZIP archives

```lean
-- Create from explicit file list
Archive.create "/tmp/archive.zip" #[
  ("name-in-zip.txt", "/path/on/disk.txt"),
  ("subdir/file.bin", "/other/file.bin")
]

-- Create from directory
Archive.createFromDir "/tmp/archive.zip" "/path/to/dir"

-- Extract all files
Archive.extract "/tmp/archive.zip" "/tmp/output"

-- Extract using the verified pure-Lean DEFLATE decoder
Archive.extract "/tmp/archive.zip" "/tmp/output" (useNative := true)

-- Extract a single file by name
let data ← Archive.extractFile "/tmp/archive.zip" "name-in-zip.txt"

-- List entries
let entries ← Archive.list "/tmp/archive.zip"
```

ZIP supports stored (method 0) and deflated (method 8) entries with automatic
method selection, CRC32 verification, and ZIP64 extensions for archives
exceeding 4GB or 65535 entries.

Extraction limits: per-entry decompressed size defaults to a 1 GiB cap, and
`maxTotalSize` can bound the whole archive; the full knob inventory is in
[SECURITY.md](SECURITY.md) *Decompression and extraction limits*.

For Zstandard (zstd) support, see
[lean-zstd](https://github.com/kim-em/lean-zstd).

## Requirements

- Lean toolchain per [`lean-toolchain`](lean-toolchain) (via
  [elan](https://github.com/leanprover/elan))
- system zlib and `pkg-config` (Ubuntu: `apt install libz-dev pkg-config`;
  NixOS: `nix-shell` uses the provided [`shell.nix`](shell.nix)), or set
  `ZLIB_CFLAGS` / `ZLIB_LDFLAGS`

## Building and testing

```
lake build
lake exe test               # requires testdata/
scripts/fuzz-handle-read.sh # budgeted randomized Handle.read fuzz run
```

The `scripts/build-*` generators rebuild the malformed-archive fixtures
under `testdata/` byte-deterministically.

## Known limitations

- **TOCTOU in extraction**: see [SECURITY.md](SECURITY.md) *Known TOCTOU
  limitation* — if you extract untrusted archives into a location other
  processes can write to, stage extraction in a private directory.
- ZIP compression always uses zlib; there is no pure-Lean compression
  path yet (decompression has one via `useNative`).

## License

Apache 2.0. Test fixtures from other projects are used under their own
licenses; see [testdata/LICENSES.md](testdata/LICENSES.md).
