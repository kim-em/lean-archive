# Security

lean-archive parses attacker-controlled bytes: tar headers, PAX and GNU
extension records, ZIP central directories, ZIP64 metadata, and entry
payloads. This document records the trust boundaries, the guardrails,
the per-callsite read audit, and the malformed-input regression corpus.

Status vocabulary: `guarded-locally` (protected by explicit checks and
limits), `tested-only` (covered by tests but no stronger assurance).

## Required maintenance rule

Whenever a new parser, extraction path, or streaming API is added, this
file must be updated in the same change set with: trust status,
guardrails, known missing work, and regression references if a bug
prompted the change. Cite by stable identifier (function name, fixture
filename, section header), not line number. Every fixture named here
must exist under `testdata/`.

## ZIP archive reader/extractor

- Components: [`Archive/Zip.lean`](Archive/Zip.lean)
- Status: `guarded-locally`
- Trust boundary: parses EOCD, central directory, ZIP64 metadata, local
  headers, names, offsets, compressed sizes, and extraction paths from
  untrusted files.
- Current guardrails:
  - central directory must fit within file size; configurable
    `maxCentralDirSize`
  - `assertSpanInFile` validates local-header, name+extra, and
    compressed-data spans against actual file size before each
    attacker-controlled `Handle.read` in `readEntryData`; local
    `readExact` checks the `Nat → USize` roundtrip
  - CD-vs-LH consistency checks (method, sizes, bit-3-masked flags) and
    CD-vs-EOCD consistency checks (`totalEntries`,
    `numEntriesThisDisk`, disk numbers, per-entry `diskNumberStart`) —
    lean-archive supports single-disk archives only
  - path traversal blocked via `Binary.isPathSafe`; CRC and final size
    checked after extraction
- Missing work:
  - the trailing EOCD comment-length field is silently accepted, and
    trailing bytes past `EOCD.commentLen` are not cross-checked against
    the file tail — one of the classic ZIP-smuggling vectors.

## Tar parser/extractor

- Components: [`Archive/Tar.lean`](Archive/Tar.lean)
- Status: `guarded-locally`
- Trust boundary: parses tar headers, GNU long-name records, PAX
  metadata, symlinks, and streamed entry contents.
- Current guardrails:
  - explicit `maxEntrySize` in extraction paths; path safety checks for
    extracted files; short-read detection in entry and padding reads
  - invalid PAX UTF-8 is skipped instead of panicking in
    `parsePaxRecords`; raw-byte truncation goes through
    `Tar.truncateUTF8` (no reachable panicking `String.fromUTF8!`)
  - interior-NUL rejection in the five UStar string slots (`name`,
    `linkname`, `prefix`, `uname`, `gname`)
- Missing work: none open at this layer.

### Symlink/hardlink extraction policy

`Tar.extract` applies a fixed per-typeflag policy:

- `typeRegular` ('0') and `typeDirectory` ('5') — written under
  `outDir/path` after `Binary.isPathSafe` rejects unsafe paths
  (absolute, `..`, `.`, empty components, backslash, Windows drive
  letters).
- `typeSymlink` ('2') — `linkname` is rejected before any
  `Handle.createSymlink` call if it starts with `/`, contains `\`, or
  has any `..` component (path-component split). The payload is always
  discarded.
- `typeHardlink` ('1') — silently skipped. No filesystem entry is
  created, the payload is consumed and discarded, and no
  `Handle.createHardlink` call exists in the extractor. A crafted
  `linkname` therefore cannot escape `outDir`.
- All other typeflags (devices, FIFO, GNU sparse, etc.) — same silent
  skip as `typeHardlink`.

Regression fixtures live under `testdata/tar/security/` and are pinned
by rows in the reproducer corpus below.

### Known TOCTOU limitation

Extraction validates every archived path, but it creates parent
directories and writes files in separate steps. A local attacker with
concurrent write access to the output tree could replace a
freshly-created directory with a symlink in that window and redirect a
write outside it. The threat model is narrow — it requires an attacker
who can already write into the destination during extraction — but if
you extract untrusted archives into a location other processes can
write to, stage extraction in a private directory you control. Closing
it fully would need an `openat()`/`O_NOFOLLOW` component walk in C
(not implemented).

## Decompression and extraction limits

Every public API that accepts untrusted archive bytes and drives
decompression or extraction. This is the reference the bomb-limit
regression tests work against — it is intentionally concrete
(parameter, default, and semantics of `0`) so callers and tests can
reason about behaviour without re-reading the source. The FFI and
native codec entry points these forward to carry their own caps,
documented in lean-zlib's `SECURITY.md` and lean-zip's decoder docstrings.

| Entry point | Parameter | Default | Semantics of 0 | Notes |
|---|---|---|---|---|
| [Archive.list](Archive/Zip.lean) | `maxCentralDirSize : Nat` | `67108864` (64 MiB) | no limit | metadata-only; caps CD allocation, not decompressed payload. |
| [Archive.extract](Archive/Zip.lean) | `maxCentralDirSize : Nat` | `67108864` (64 MiB) | no limit | CD allocation cap. |
| [Archive.extract](Archive/Zip.lean) | `maxEntrySize : UInt64` | `1 * 1024^3` (1 GiB) | pass `0` for unlimited (FFI backend only; native inflate rejects `0`) | per-entry cap on the decompressed payload. |
| [Archive.extract](Archive/Zip.lean) | `maxTotalSize : UInt64` | `0` | no whole-archive cap | running sum across all entries; intended as a second line of defence against many-small-entries bombs. |
| [Archive.extractFile](Archive/Zip.lean) | `maxCentralDirSize : Nat` | `67108864` (64 MiB) | no limit | CD allocation cap. |
| [Archive.extractFile](Archive/Zip.lean) | `maxEntrySize : UInt64` | `1 * 1024^3` (1 GiB) | pass `0` for unlimited (FFI backend only; native inflate rejects `0`) | per-entry cap. |
| [Tar.extract](Archive/Tar.lean) | `maxEntrySize : UInt64` | `1 * 1024^3` (1 GiB) | pass `0` for unlimited | per-entry byte cap, applied via header `e.size` before any I/O (see `Archive/Tar.lean`). |
| [Tar.extract](Archive/Tar.lean) | `maxTotalSize : UInt64` | `0` | no whole-archive cap | running sum across all regular-file entries; directories and symlinks contribute zero. |
| [Tar.extractTarGz](Archive/Tar.lean) | `maxEntrySize : UInt64` | `1 * 1024^3` (1 GiB) | pass `0` for unlimited | per-entry cap. Outer gzip decode is streaming via `Gzip.InflateState`; no per-stream output cap. |
| [Tar.extractTarGz](Archive/Tar.lean) | `maxTotalSize : UInt64` | `0` | no whole-archive cap | forwarded to inner `Tar.extract`. |
| [Tar.extractTarGzNative](Archive/Tar.lean) | `maxEntrySize : UInt64` | `1 * 1024^3` (1 GiB) | pass `0` for unlimited | per-entry cap. |
| [Tar.extractTarGzNative](Archive/Tar.lean) | `maxTotalSize : UInt64` | `0` | no whole-archive cap | forwarded to inner `Tar.extract`. |
| [Tar.extractTarGzNative](Archive/Tar.lean) | `maxOutputSize : Nat` | `256 * 1024^2` (256 MiB) | hard cap at 0 bytes (explicit) | whole-archive tar-buffer cap for the outer native gzip decode. |
Whole-archive bomb regression tests (three entries individually under
`maxEntrySize` whose running sum must still be rejected) live in
[`ArchiveTest/Tar.lean`](ArchiveTest/Tar.lean) and
[`ArchiveTest/Zip.lean`](ArchiveTest/Zip.lean).

### Local guard inventory for `Handle.read` and `Stream.read`

Per-callsite audit of every `Handle.read`, `Stream.read`, and
`inStream.read` invocation reachable from untrusted archive bytes in
`Archive/Zip.lean` and `Archive/Tar.lean`. This documents which guards
**already run before** each read, so a reader does not have to trace
back through the source to confirm that every metadata-driven read is
protected. The *"Failure mode"* column states the behaviour that would
surface if the caller bypassed the guard. Since v4.30.0-rc2 the
runtime's own `lean_io_prim_handle_read` does checked arithmetic on
allocation paths and raises OOM on overflow rather than corrupting the
heap, so the local guards primarily exist to surface a clean,
catchable error before allocation rather than to prevent memory
corruption.

The creator-side `h.read` in `Archive/Tar.lean` `create` at
`Archive/Tar.lean` is **not**
listed: it reads local files chosen by the caller (the archive author),
not untrusted archive bytes, so it falls outside this inventory's
scope.

Trust-boundary callers reach the actual `.read` primitive via
`readExact` (`Archive/Zip.lean`,
`Archive/Tar.lean`),
`readExactStream` (`Archive/Zip.lean`),
`readEntryData` (`Archive/Tar.lean`),
`skipEntryData` (`Archive/Tar.lean`),
or open-coded read loops. Each row below names the call site that
drives an `n`-byte read; the `readExact`-family helpers themselves
perform a `Nat → USize` roundtrip check before every `Handle.read`.

| Callsite (file:line) | Reads driven by | Local guard | Failure mode if guard absent |
|---|---|---|---|
| `Archive/Zip.lean` `readExactStream` helper (inner `s.read`) | caller-provided `n : Nat` | `Nat → USize` roundtrip at `Archive/Zip.lean` | no production parser reaches this helper today — only `ArchiveTest/Zip.lean` exercises it. Any future stream-fed parser that wires into `readExactStream` must apply its own `n`-bound before calling; otherwise this row downgrades to caller-bounded |
| `Archive/Zip.lean` `readExact h tailSize "EOCD tail"` | `tailSize = min fileSize 65558` at `Archive/Zip.lean` | `min` clamp (≤ 65 558 bytes regardless of input); `Nat → USize` roundtrip in `readExact` | N/A — the read is structurally bounded to ≤ 65 558 bytes |
| `Archive/Zip.lean` `readExact h cdSize "central directory"` | `cdSize` parsed from EOCD (attacker-controlled) | `cdOffset + cdSize ≤ fileSize` check at `Archive/Zip.lean`; `maxCentralDirSize` cap (default 64 MiB) at `Archive/Zip.lean`; `Nat → USize` roundtrip in `readExact` | would request a crafted multi-GB allocation; depends on runtime to reject or OOM |
| `Archive/Zip.lean` `readBoundedSpanFromHandle h fileSize entry.localOffset 30 "local header for {label}"` | fixed `30` bytes | `assertSpanInFile fileSize entry.localOffset 30` internal to `readBoundedSpanFromHandle` at `Archive/Zip.lean` | N/A — fixed 30-byte read |
| `Archive/Zip.lean` `readBoundedSpanFromHandle h fileSize (entry.localOffset + 30) (nameLen + extraLen) "local name+extra for {label}"` | `nameLen + extraLen`, both `UInt16` read from the local header (≤ 2·`UInt16.max` ≈ 128 KiB) | `assertSpanInFile` at `Archive/Zip.lean`; `UInt16` type bound on each addend | N/A — `UInt16` type bounds each addend, total ≤ 128 KiB regardless of input |
| `Archive/Zip.lean` `readExact h entry.compressedSize.toNat "compressed data for {label}"` | `entry.compressedSize` from CD / ZIP64 local extra (attacker-controlled `UInt64`) | `assertSpanInFile fileSize (entry.localOffset + headerAndNames) entry.compressedSize` at `Archive/Zip.lean`; CD-vs-LH `compressedSize` consistency check at `Archive/Zip.lean` (only skipped when the LH data-descriptor flag bit 3 is set); CD-vs-LH flags-consistency check (bit-3-masked) at `Archive/Zip.lean` — *"flags mismatch between CD and local header"* — rejects mismatched general-purpose flag words before the payload read; CD-vs-LH `versionNeededToExtract` one-sided downgrade check at `Archive/Zip.lean` — *"LH versionNeededToExtract (…) exceeds CD versionNeededToExtract (…)"* — rejects LH claiming a higher version than CD (a capability-smuggle vector) before the payload read; `Nat → USize` roundtrip in `readExact`. Regression fixtures: `testdata/zip/malformed/oversized-compressed-size.zip`, `oversized-zip64-compressed-size.zip`, `cd-lh-flags-mismatch.zip`, `cd-lh-uncompsize-mismatch.zip`, `cd-lh-crc-mismatch.zip`, `cd-lh-version-mismatch.zip` | would request petabyte allocation on a crafted oversized `compressedSize`; relies on `assertSpanInFile` + CD/LH consistency to reject before `Handle.read` |
| `Archive/Tar.lean` `readExact input 512` in `forEntries` | fixed `512` (one tar header block) | fixed constant | N/A — fixed 512-byte read |
| `Archive/Tar.lean` `readBoundedEntryData input entry.size.toNat maxHeaderSize` (GNU long-name, GNU long-link, PAX extended header, PAX global header) | `entry.size` from tar header (attacker-controlled `UInt64`) | `maxHeaderSize` cap inside `readEntryData` at `Archive/Tar.lean` (default `defaultMaxHeaderSize = 8 MiB` at `Archive/Tar.lean`) — rejects `entry.size > maxHeaderSize` before any allocation with `IO.userError` containing `"exceeds maximum header size"`. Per-chunk reads are also capped at 64 KiB (`Archive/Tar.lean`) and padding at 512 bytes per chunk (`Archive/Tar.lean`). The cap is independent of the caller's `maxEntrySize`, which only bounds payload-bearing entries. Regression fixtures: `testdata/tar/malformed/gnu-longname-oversized-size.tar`, `pax-extended-oversized-size.tar` | with the cap raised, `readEntryData` would accumulate `entry.size` bytes into memory on a crafted GNU long-name or PAX header claiming multi-GB size — depends on runtime allocation to reject |
| `Archive/Tar.lean` `skipEntryData input e.size` (directory-entry payload skip, symlink-entry payload skip, unsupported-typeflag payload skip, `Tar.list`) | `e.size + paddingFor e.size` (attacker-controlled `UInt64`) | 64 KiB per-chunk cap at `Archive/Tar.lean`; discarded bytes are not buffered (peak allocation = 64 KiB per iteration) | no memory amplification, but a malicious stream can force an unbounded number of 64 KiB reads. `Tar.extract` applies `maxEntrySize` at `Archive/Tar.lean` for payload-bearing entries before the skip; `Tar.list` applies no cap |
| `Archive/Tar.lean` `input.read toRead.toUSize` in `Tar.extract` regular-file loop | `min remaining 65536` where `remaining ≤ e.size.toNat` (attacker-controlled `UInt64` from tar header) | `maxEntrySize` check at `Archive/Tar.lean` (effective only when `maxEntrySize > 0`); 64 KiB per-chunk cap; data is written through to disk, not buffered | with the default 1 GiB cap, `Tar.extract` writes up to 1 GiB to disk per regular-file entry; with `maxEntrySize = 0` (opt-in unlimited), the read is bounded only by `e.size` (attacker-controlled `UInt64`). The per-read allocation is bounded at 64 KiB regardless. Documented as the "per-entry cap" row in *Decompression Limit Inventory* |
| `Archive/Tar.lean` `input.read (min padRemaining 512).toUSize` in `Tar.extract` padding loop | `min padRemaining 512`; `padRemaining ≤ 511` by tar framing (`paddingFor size < 512`) | fixed 512-byte per-chunk cap; `pad < 512` by tar block alignment | N/A — ≤ 512 bytes per read, bounded by tar block alignment |
| `Archive/Tar.lean` `inStream.read 65536` in `extractTarGz` tarStream wrapper | fixed `65536` | fixed chunk constant regardless of input | N/A — fixed 64 KiB read |

Summary — what the inventory catches and what it does not:

- **Catches**: every metadata-driven read in ZIP extraction
  (`Archive.readEntryData`) is span-checked against the actual file
  size before `Handle.read` runs, and the CD-vs-LH consistency check
  rejects crafted size mismatches before the compressed-payload read.
  Padding and skip reads in `Tar.lean` are bounded per chunk (64 KiB
  or 512 bytes) and discarded, so they cannot amplify memory.
- **Does NOT catch** — one residual gap that would benefit from a
  follow-up issue:
  1. `Tar.extract` row 10 relies on a per-entry `maxEntrySize` cap
     of 1 GiB by default; an attacker who crafts many entries can
     still drive disk usage past this cap because the
     whole-archive `maxTotalSize` parameter on `Tar.extract` /
     `Tar.extractTarGz` / `Tar.extractTarGzNative` defaults to
     `0` (no limit) per Recommended Policy item 4. Callers
     concerned about multi-entry exhaustion must opt into a
     finite `maxTotalSize`.

  The previously-listed `Tar.readEntryData` gap at the four GNU
  long-name / long-link / PAX callsites is now closed by the
  `maxHeaderSize` cap (default `defaultMaxHeaderSize = 8 MiB`) that
  fires in `readEntryData` before any allocation; see row 8 above and
  the `gnu-longname-oversized-size.tar` /
  `pax-extended-oversized-size.tar` regression fixtures.

## Minimized reproducer corpus

Each row is a minimised input that trips a specific defensive guard in
the parsers or extractors. Regression of a listed guard surfaces as a
test failure in [`ArchiveTest/ZipFixtures.lean`](ArchiveTest/ZipFixtures.lean),
[`ArchiveTest/TarFixtures.lean`](ArchiveTest/TarFixtures.lean), or (for
the UTF-8 entry-name check)
[`ArchiveTest/Utf8Fixtures.lean`](ArchiveTest/Utf8Fixtures.lean).
The related class is one of {*oversized allocation*, *partial-decoder
panic*, *archive-slip*, *decompression bomb*, *other*} so an auditor
tracking regressions of a single class can filter. Fixtures are
byte-deterministic; the `scripts/build-*` generators rebuild them.

| Fixture (testdata/…) | Size | Defence exercised | Related class |
|---|---|---|---|
| [tar/malformed/bad-checksum.tar](testdata/tar/malformed/bad-checksum.tar) | 2048 B | Tar header checksum verification at `Archive/Tar.lean` — *"header checksum mismatch"* | other (integrity check) |
| [tar/malformed/gnu-longlink-nul-in-link.tar](testdata/tar/malformed/gnu-longlink-nul-in-link.tar) | 1536 B | GNU long-link NUL-byte rejection at `Archive/Tar.lean` — *"GNU long-link contains NUL byte"* | archive-slip |
| [tar/malformed/gnu-longlink-truncated.tar](testdata/tar/malformed/gnu-longlink-truncated.tar) | 612 B | `readEntryData` short-read at `Archive/Tar.lean` — *"unexpected end of archive reading entry data"* | partial-decoder panic |
| [tar/malformed/gnu-longname-invalid-utf8.tar](testdata/tar/malformed/gnu-longname-invalid-utf8.tar) | 1536 B | `String.fromUTF8?` → `Binary.fromLatin1` fallback at `Archive/Tar.lean` (no panicking `fromUTF8!` path) | partial-decoder panic |
| [tar/malformed/gnu-longname-no-terminator.tar](testdata/tar/malformed/gnu-longname-no-terminator.tar) | 1536 B | `stripTrailingNuls` is a no-op when the payload has no trailing NUL (`Archive/Tar.lean`); full payload becomes the name without a panic | partial-decoder panic |
| [tar/malformed/gnu-longname-nul-in-name.tar](testdata/tar/malformed/gnu-longname-nul-in-name.tar) | 1536 B | GNU long-name NUL-byte rejection at `Archive/Tar.lean` — *"GNU long-name contains NUL byte"* | archive-slip |
| [tar/malformed/gnu-longname-oversized-size.tar](testdata/tar/malformed/gnu-longname-oversized-size.tar) | 512 B | `readEntryData` `maxHeaderSize` cap at `Archive/Tar.lean` — *"exceeds maximum header size"* | oversized allocation |
| [tar/malformed/gnu-longname-truncated.tar](testdata/tar/malformed/gnu-longname-truncated.tar) | 612 B | `readEntryData` short-read at `Archive/Tar.lean` — *"unexpected end of archive reading entry data"* | partial-decoder panic |
| [tar/malformed/no-magic.tar](testdata/tar/malformed/no-magic.tar) | 2048 B | Tar magic check at `Archive/Tar.lean` — *"unsupported format"* | other (header validation) |
| [tar/malformed/pax-duplicate-path.tar](testdata/tar/malformed/pax-duplicate-path.tar) | 2048 B | `parsePaxRecords` duplicate-key guard at `Archive/Tar.lean` — *"tar: PAX extended header has duplicate {key.quote} record"* | archive-slip |
| [tar/malformed/pax-extended-oversized-size.tar](testdata/tar/malformed/pax-extended-oversized-size.tar) | 512 B | `readEntryData` `maxHeaderSize` cap at `Archive/Tar.lean` — *"exceeds maximum header size"* | oversized allocation |
| [tar/malformed/pax-inconsistent-length.tar](testdata/tar/malformed/pax-inconsistent-length.tar) | 2048 B | `parsePaxRecords` silent-skip when no `=` is found before the declared record end (scan at `Archive/Tar.lean`; record dropped at `Archive/Tar.lean`) | partial-decoder panic |
| [tar/malformed/pax-invalid-utf8-key.tar](testdata/tar/malformed/pax-invalid-utf8-key.tar) | 2048 B | `parsePaxRecords` `String.fromUTF8?` guard on key/value at `Archive/Tar.lean` (record dropped, no panic) | partial-decoder panic |
| [tar/malformed/pax-invalid-utf8-value.tar](testdata/tar/malformed/pax-invalid-utf8-value.tar) | 2048 B | Same `String.fromUTF8?` guard at `Archive/Tar.lean` | partial-decoder panic |
| [tar/malformed/pax-linkpath-nul-in-value.tar](testdata/tar/malformed/pax-linkpath-nul-in-value.tar) | 2048 B | `parsePaxRecords` NUL-byte guard on `valueBytes` at `Archive/Tar.lean` (record dropped silently, matching the invalid-UTF-8 precedent on the same loop). | archive-slip |
| [tar/malformed/pax-nul-in-key.tar](testdata/tar/malformed/pax-nul-in-key.tar) | 2048 B | `parsePaxRecords` NUL-byte guard on `keyBytes` at `Archive/Tar.lean` (record dropped silently, matching the invalid-UTF-8 precedent on the same loop). | archive-slip |
| [tar/malformed/pax-oversized-length.tar](testdata/tar/malformed/pax-oversized-length.tar) | 2048 B | `parsePaxRecords` `digitCount > 20` guard at `Archive/Tar.lean` (length-parse aborted before multiplying) | oversized allocation |
| [tar/malformed/pax-path-nul-in-value.tar](testdata/tar/malformed/pax-path-nul-in-value.tar) | 2048 B | `parsePaxRecords` NUL-byte guard on `keyBytes` / `valueBytes` at `Archive/Tar.lean` (record dropped silently, matching the invalid-UTF-8 precedent one line above). | archive-slip |
| [tar/malformed/pax-truncated-record.tar](testdata/tar/malformed/pax-truncated-record.tar) | 2048 B | `parsePaxRecords` `recordEnd > data.size` guard at `Archive/Tar.lean` (iteration breaks, remaining bytes ignored) | partial-decoder panic |
| [tar/malformed/truncated.tar](testdata/tar/malformed/truncated.tar) | 522 B | `Tar.extract` regular-file loop short-read at `Archive/Tar.lean` — *"unexpected end of archive reading {e.path} ({remaining} bytes remaining)"* | other (framing) |
| [tar/malformed/ustar-gname-nul-in-gname.tar](testdata/tar/malformed/ustar-gname-nul-in-gname.tar) | 1536 B | UStar `gname` field interior-NUL rejection at `Archive/Tar.lean` — *"UStar gname contains NUL byte"* | archive-slip |
| [tar/malformed/ustar-linkname-nul-in-name.tar](testdata/tar/malformed/ustar-linkname-nul-in-name.tar) | 1536 B | UStar `linkname` field interior-NUL rejection at `Archive/Tar.lean` — *"UStar linkname contains NUL byte"* | archive-slip |
| [tar/malformed/ustar-name-nul-in-name.tar](testdata/tar/malformed/ustar-name-nul-in-name.tar) | 1536 B | UStar `name` field interior-NUL rejection at `Archive/Tar.lean` — *"UStar name contains NUL byte"* | archive-slip |
| [tar/malformed/ustar-prefix-nul-in-name.tar](testdata/tar/malformed/ustar-prefix-nul-in-name.tar) | 1536 B | UStar `prefix` field interior-NUL rejection at `Archive/Tar.lean` — *"UStar prefix contains NUL byte"* | archive-slip |
| [tar/malformed/ustar-uname-nul-in-uname.tar](testdata/tar/malformed/ustar-uname-nul-in-uname.tar) | 1536 B | UStar `uname` field interior-NUL rejection at `Archive/Tar.lean` — *"UStar uname contains NUL byte"* | archive-slip |
| [tar/security/backslash-slip.tar](testdata/tar/security/backslash-slip.tar) | 2048 B | `Binary.isPathSafe` rejects backslashes before component-level `..` check at `Archive/Tar.lean` — *"unsafe path"* | archive-slip |
| [tar/security/hardlink-outside.tar](testdata/tar/security/hardlink-outside.tar) | 512 B | `typeHardlink` silent-skip else-branch at `Archive/Tar.lean`; payload discarded, no `createHardlink` call, extract directory remains empty | archive-slip |
| [tar/security/symlink-absolute.tar](testdata/tar/security/symlink-absolute.tar) | 512 B | Symlink linkname absolute/backslash check at `Archive/Tar.lean` — *"unsafe symlink target"* | archive-slip |
| [tar/security/symlink-slip.tar](testdata/tar/security/symlink-slip.tar) | 10240 B | Symlink linkname component `..` check at `Archive/Tar.lean` — *"unsafe symlink target"* | archive-slip |
| [tar/security/tar-absolute.tar](testdata/tar/security/tar-absolute.tar) | 2048 B | `Binary.isPathSafe` rejects absolute paths at `Archive/Tar.lean` — *"unsafe path"* | archive-slip |
| [tar/security/tar-fifo-skipped.tar](testdata/tar/security/tar-fifo-skipped.tar) | 512 B | `Tar.extract` silent-skip `else` fallback at `Archive/Tar.lean` for unsupported typeflag `'6'` (POSIX UStar FIFO, `0x36`) — 512-byte single-block UStar header for a zero-byte entry with `path = "fifo-entry"`, empty `linkname`, `typeflag = 0x36`, checksum recomputed to match. | other (typeflag-policy regression) |
| [tar/security/tar-chardev-skipped.tar](testdata/tar/security/tar-chardev-skipped.tar) | 512 B | `Tar.extract` silent-skip `else` fallback at `Archive/Tar.lean` for unsupported typeflag `'3'` (POSIX UStar character device, `0x33`) — 512-byte single-block UStar header for a zero-byte entry with `path = "chardev-entry"`, empty `linkname`, `typeflag = 0x33`, checksum recomputed to match. | other (typeflag-policy regression) |
| [tar/security/tar-blockdev-skipped.tar](testdata/tar/security/tar-blockdev-skipped.tar) | 512 B | `Tar.extract` silent-skip `else` fallback at `Archive/Tar.lean` for unsupported typeflag `'4'` (POSIX UStar block device, `0x34`) — 512-byte single-block UStar header for a zero-byte entry with `path = "blockdev-entry"`, empty `linkname`, `typeflag = 0x34`, checksum recomputed to match. | other (typeflag-policy regression) |
| [tar/security/tar-contiguous-skipped.tar](testdata/tar/security/tar-contiguous-skipped.tar) | 512 B | `Tar.extract` silent-skip `else` fallback at `Archive/Tar.lean` for unsupported typeflag `'7'` (POSIX UStar contiguous file, `0x37`) — 512-byte single-block UStar header for a zero-byte entry with `path = "contiguous-entry"`, empty `linkname`, `typeflag = 0x37`, checksum recomputed to match. | other (typeflag-policy regression) |
| [tar/security/tar-volumeheader-skipped.tar](testdata/tar/security/tar-volumeheader-skipped.tar) | 512 B | `Tar.extract` silent-skip `else` fallback at `Archive/Tar.lean` for unsupported GNU typeflag `'V'` (multi-volume archive label marker, `0x56`) — 512-byte single-block UStar header for a zero-byte entry with `path = "volume-label-entry"`, empty `linkname`, `typeflag = 0x56`, checksum recomputed to match. | other (typeflag-policy regression) |
| [tar/security/tar-multivol-skipped.tar](testdata/tar/security/tar-multivol-skipped.tar) | 512 B | `Tar.extract` silent-skip `else` fallback at `Archive/Tar.lean` for unsupported GNU typeflag `'M'` (multi-volume continuation marker, `0x4D`) — 512-byte single-block UStar header for a zero-byte entry with `path = "multivol-entry"`, empty `linkname`, `typeflag = 0x4D`, checksum recomputed to match. | other (typeflag-policy regression) |
| [tar/security/tar-sparse-skipped.tar](testdata/tar/security/tar-sparse-skipped.tar) | 512 B | `Tar.extract` silent-skip `else` fallback at `Archive/Tar.lean` for unsupported GNU typeflag `'S'` (sparse file, `0x53`) — 512-byte single-block UStar header for a zero-byte entry with `path = "sparse-entry"`, empty `linkname`, `typeflag = 0x53`, checksum recomputed to match. | other (typeflag-policy regression) |
| [tar/security/tar-incremental-skipped.tar](testdata/tar/security/tar-incremental-skipped.tar) | 512 B | `Tar.extract` silent-skip `else` fallback at `Archive/Tar.lean` for unsupported GNU typeflag `'D'` (directory-dump for incremental backups, `0x44`) — 512-byte single-block UStar header for a zero-byte entry with `path = "incremental-entry"`, empty `linkname`, `typeflag = 0x44`, checksum recomputed to match. | other (typeflag-policy regression) |
| [tar/security/tar-longnames-skipped.tar](testdata/tar/security/tar-longnames-skipped.tar) | 512 B | `Tar.extract` silent-skip `else` fallback at `Archive/Tar.lean` for unsupported GNU typeflag `'N'` (LF_NAMES old-long-name extension, `0x4E`) — 512-byte single-block UStar header for a zero-byte entry with `path = "longnames-entry"`, empty `linkname`, `typeflag = 0x4E`, checksum recomputed to match. | other (typeflag-policy regression) |
| [tar/security/tar-mixed-skipped.tar](testdata/tar/security/tar-mixed-skipped.tar) | 2560 B | `Tar.extract` *extract-continuation* invariant across the silent-skip `else` fallback at `Archive/Tar.lean` — three-entry archive interleaving a silently-skipped middle entry between two regular files: `before.txt` (typeflag `'0'`, payload `"BEFORE\n"`, size 7) → `fifo-entry` (typeflag `'6'` = `0x36`, POSIX UStar FIFO, empty linkname, size 0, silent-skipped) → `after.txt` (typeflag `'0'`, payload `"AFTER\n"`, size 6); checksum recomputed for each header. | other (extract-continuation regression) |
| [tar/security/tar-slip.tar](testdata/tar/security/tar-slip.tar) | 10240 B | `Binary.isPathSafe` rejects `..` component traversal at `Archive/Tar.lean` — *"unsafe path"* | archive-slip |
| [zip/malformed/bad-crc.zip](testdata/zip/malformed/bad-crc.zip) | 140 B | Post-extraction CRC32 verification at `Archive/Zip.lean` — *"CRC32 mismatch"* | other (integrity check) |
| [zip/malformed/bad-method.zip](testdata/zip/malformed/bad-method.zip) | 140 B | CD-entry compression-method allowlist check at `Archive/Zip.lean` — *"unsupported compression method"* | other (method validation) |
| [zip/malformed/cd-bad-lh-signature.zip](testdata/zip/malformed/cd-bad-lh-signature.zip) | 122 B | Late LH-signature guard regression coverage at `Archive/Zip.lean` — *"bad local header signature for {label}"* | other (LH signature regression) |
| [zip/malformed/cd-bad-method-early.zip](testdata/zip/malformed/cd-bad-method-early.zip) | 122 B | CD-entry compression-method allowlist check at `Archive/Zip.lean` — *"unsupported compression method"* | other (method validation) |
| [zip/malformed/cd-deflate-zero-compsize.zip](testdata/zip/malformed/cd-deflate-zero-compsize.zip) | 116 B | CD-entry `uncompSize > 0 → compSize > 0` math-invariant check at `Archive/Zip.lean` — *"CD entry has zero compressedSize with nonzero uncompressedSize"* | other (math invariant / method-agnostic) |
| [zip/malformed/cd-empty-entry-crc-nonzero.zip](testdata/zip/malformed/cd-empty-entry-crc-nonzero.zip) | 116 B | CD-entry empty-entry CRC invariant check at `Archive/Zip.lean` — *"CD entry CRC must be zero when uncompressedSize is zero"* | other (CRC/empty-file invariant) |
| [zip/malformed/cd-empty-name.zip](testdata/zip/malformed/cd-empty-name.zip) | 104 B | CD-entry empty-filename rejection at `Archive/Zip.lean` — *"CD entry has empty filename"* | other (filename validation) |
| [zip/malformed/cd-entry-disknum-mismatch.zip](testdata/zip/malformed/cd-entry-disknum-mismatch.zip) | 122 B | CD per-entry `diskNumberStart` consistency check at `Archive/Zip.lean` — *"CD entry diskNumberStart mismatch"* | other (CD/EOCD consistency) |
| [zip/malformed/cd-entry-internal-attrs-reserved.zip](testdata/zip/malformed/cd-entry-internal-attrs-reserved.zip) | 122 B | CD per-entry `internalFileAttributes` reserved-bits check at `Archive/Zip.lean` — *"internalAttrs reserved bits set"* | other (CD writer-invariant) |
| [zip/malformed/cd-entry-localoffset-past-cdstart.zip](testdata/zip/malformed/cd-entry-localoffset-past-cdstart.zip) | 122 B | CD-entry `localOffset + 30 ≤ cdOffset` archive-layout invariant check at `Archive/Zip.lean` — *"entry local offset overlaps central directory"* | other (archive-layout invariant) |
| [zip/malformed/cd-entry-past-cdend.zip](testdata/zip/malformed/cd-entry-past-cdend.zip) | 122 B | Per-entry `entryEnd > cdEnd` footprint guard regression coverage at `Archive/Zip.lean` — *"central directory entry extends past end of central directory"* | other (CD-region overrun regression) |
| [zip/malformed/cd-extra-overrun-datasize.zip](testdata/zip/malformed/cd-extra-overrun-datasize.zip) | 138 B | CD/LH extra-data sub-field structural check at `Archive/Zip.lean` — *"malformed extra field"* | other (ZIP64 consistency) |
| [zip/malformed/cd-flags-reserved-bits.zip](testdata/zip/malformed/cd-flags-reserved-bits.zip) | 122 B | CD-entry general-purpose flag reserved/unused-bits rejection at `Archive/Zip.lean` — *"flags reserved bits set"* | other (flag-bit validation) |
| [zip/malformed/cd-lh-crc-mismatch.zip](testdata/zip/malformed/cd-lh-crc-mismatch.zip) | 122 B | CD/LH `crc32` consistency check at `Archive/Zip.lean` — *"crc32 mismatch between CD and local header"* | other (CD/LH consistency) |
| [zip/malformed/cd-lh-flags-mismatch.zip](testdata/zip/malformed/cd-lh-flags-mismatch.zip) | 122 B | CD/LH flags-consistency check (bit-3-masked) at `Archive/Zip.lean` — *"flags mismatch between CD and local header"* | other (CD/LH consistency) |
| [zip/malformed/cd-lh-method-mismatch.zip](testdata/zip/malformed/cd-lh-method-mismatch.zip) | 122 B | CD/LH method-consistency check at `Archive/Zip.lean` — *"method mismatch between CD and local header"* | other (CD/LH consistency) |
| [zip/malformed/cd-lh-modtime-mismatch.zip](testdata/zip/malformed/cd-lh-modtime-mismatch.zip) | 122 B | CD/LH `lastModTime`/`lastModDate` consistency check at `Archive/Zip.lean` — *"lastModTime/Date mismatch between CD and local header"* | other (CD/LH consistency) |
| [zip/malformed/cd-lh-size-mismatch.zip](testdata/zip/malformed/cd-lh-size-mismatch.zip) | 122 B | CD/LH `compressedSize` consistency check at `Archive/Zip.lean` — *"compressedSize mismatch between CD and local header"* | other (CD/LH consistency) |
| [zip/malformed/cd-lh-uncompsize-mismatch.zip](testdata/zip/malformed/cd-lh-uncompsize-mismatch.zip) | 122 B | CD/LH `uncompressedSize` consistency check at `Archive/Zip.lean` — *"uncompressedSize mismatch between CD and local header"* | other (CD/LH consistency) |
| [zip/malformed/cd-lh-version-mismatch.zip](testdata/zip/malformed/cd-lh-version-mismatch.zip) | 122 B | CD/LH `versionNeededToExtract` downgrade check at `Archive/Zip.lean` — *"LH versionNeededToExtract (…) exceeds CD versionNeededToExtract (…)"* | other (CD/LH consistency) |
| [zip/malformed/cd-nul-in-name.zip](testdata/zip/malformed/cd-nul-in-name.zip) | 118 B | CD-entry name NUL-byte rejection at `Archive/Zip.lean` — *"CD entry name contains NUL byte"* | other (filename validation) |
| [zip/malformed/cd-path-unsafe.zip](testdata/zip/malformed/cd-path-unsafe.zip) | 126 B | CD-entry path-safety rejection at `Archive/Zip.lean` — *"CD entry has unsafe path"* | archive-slip |
| [zip/malformed/cd-past-eof.zip](testdata/zip/malformed/cd-past-eof.zip) | 22 B | `cdOffset + cdSize ≤ fileSize` check at `Archive/Zip.lean` — *"central directory extends beyond file"* | oversized allocation |
| [zip/malformed/cd-patched-data-flag.zip](testdata/zip/malformed/cd-patched-data-flag.zip) | 122 B | CD-entry general-purpose flag bit-5 (compressed patched data) rejection at `Archive/Zip.lean` — *"patched-data flag bit 5 set"* | other (flag-bit validation) |
| [zip/malformed/cd-stored-size-mismatch.zip](testdata/zip/malformed/cd-stored-size-mismatch.zip) | 122 B | CD-entry stored-method size-invariant check at `Archive/Zip.lean` — *"stored-method size mismatch"* | other (CD/LH consistency) |
| [zip/malformed/cd-zip64-extra-duplicate.zip](testdata/zip/malformed/cd-zip64-extra-duplicate.zip) | 158 B | CD-side duplicate ZIP64 extra-block guard at `Archive/Zip.lean` — *"duplicate ZIP64 extra field"* | other (ZIP64 consistency) |
| [zip/malformed/eocd-disknum-mismatch.zip](testdata/zip/malformed/eocd-disknum-mismatch.zip) | 122 B | CD-vs-EOCD disk-number consistency check at `Archive/Zip.lean` — *"EOCD disk-number mismatch"* | other (CD/EOCD consistency) |
| [zip/malformed/eocd-numentries-mismatch.zip](testdata/zip/malformed/eocd-numentries-mismatch.zip) | 122 B | CD-vs-EOCD `totalEntries` consistency check at `Archive/Zip.lean` — *"EOCD totalEntries mismatch"* | other (CD/EOCD consistency) |
| [zip/malformed/eocd-numentries-thisdisk-mismatch.zip](testdata/zip/malformed/eocd-numentries-thisdisk-mismatch.zip) | 122 B | EOCD-internal `numEntriesThisDisk` vs. `totalEntries` consistency check at `Archive/Zip.lean` — *"EOCD numEntriesThisDisk mismatch"* | other (CD/EOCD consistency) |
| [zip/malformed/eocd-zip64-override-cdsize-mismatch.zip](testdata/zip/malformed/eocd-zip64-override-cdsize-mismatch.zip) | 198 B | ZIP64/standard-EOCD override sentinel check — `cdSize` slot at `Archive/Zip.lean` — *"EOCD ZIP64-override mismatch"* | other (ZIP64 consistency) |
| [zip/malformed/eocd-zip64-override-diskcd-mismatch.zip](testdata/zip/malformed/eocd-zip64-override-diskcd-mismatch.zip) | 198 B | ZIP64/standard-EOCD override sentinel check — `diskWhereCDStarts` slot at `Archive/Zip.lean` — *"EOCD ZIP64-override mismatch"* | other (ZIP64 consistency) |
| [zip/malformed/eocd-zip64-override-entriesthisdisk-mismatch.zip](testdata/zip/malformed/eocd-zip64-override-entriesthisdisk-mismatch.zip) | 198 B | ZIP64/standard-EOCD override sentinel check — `numEntriesThisDisk` slot at `Archive/Zip.lean` — *"EOCD ZIP64-override mismatch"* | other (ZIP64 consistency) |
| [zip/malformed/eocd-zip64-override-totalentries-mismatch.zip](testdata/zip/malformed/eocd-zip64-override-totalentries-mismatch.zip) | 198 B | ZIP64/standard-EOCD override sentinel check — `totalEntries` slot at `Archive/Zip.lean` — *"EOCD ZIP64-override mismatch"* | other (ZIP64 consistency) |
| [zip/malformed/eocd-zip64-override-nosentinel.zip](testdata/zip/malformed/eocd-zip64-override-nosentinel.zip) | 198 B | ZIP64/standard-EOCD override sentinel check at `Archive/Zip.lean` — *"EOCD ZIP64-override mismatch"* | other (ZIP64 consistency) |
| [zip/malformed/invalid-utf8-with-flag.zip](testdata/zip/malformed/invalid-utf8-with-flag.zip) | 120 B | UTF-8-flagged entry name strict parse at `Archive/Zip.lean` — *"invalid UTF-8 in entry name (UTF-8 flag set)"* | partial-decoder panic |
| [zip/malformed/lh-zip64-extra-duplicate.zip](testdata/zip/malformed/lh-zip64-extra-duplicate.zip) | 158 B | LH-side duplicate ZIP64 extra-block guard at `Archive/Zip.lean` — *"duplicate ZIP64 local extra field"* | other (ZIP64 consistency) |
| [zip/malformed/no-eocd.zip](testdata/zip/malformed/no-eocd.zip) | 44 B | EOCD-scan failure at `Archive/Zip.lean` — *"cannot find end of central directory"* | other (framing) |
| [zip/malformed/oversized-compressed-size.zip](testdata/zip/malformed/oversized-compressed-size.zip) | 122 B | CD-entry stored-method size-invariant check at `Archive/Zip.lean` — *"stored-method size mismatch"* | oversized allocation |
| [zip/malformed/oversized-zip64-compressed-size.zip](testdata/zip/malformed/oversized-zip64-compressed-size.zip) | 134 B | CD-entry stored-method size-invariant check at `Archive/Zip.lean` — *"stored-method size mismatch"* | oversized allocation |
| [zip/malformed/oversized-zip64-uncompressed-size.zip](testdata/zip/malformed/oversized-zip64-uncompressed-size.zip) | 134 B | CD-entry stored-method size-invariant check at `Archive/Zip.lean` — *"stored-method size mismatch"* | oversized allocation |
| [zip/malformed/too-short.zip](testdata/zip/malformed/too-short.zip) | 10 B | EOCD-scan failure at `Archive/Zip.lean` — *"cannot find end of central directory"* | other (framing) |
| [zip/malformed/zip64-eocd64-bad-recsize.zip](testdata/zip/malformed/zip64-eocd64-bad-recsize.zip) | 198 B | ZIP64 EOCD64 self-declared record-size check at `Archive/Zip.lean` — *"ZIP64 EOCD64 record-size mismatch"* | other (ZIP64 consistency) |
| [zip/malformed/zip64-eocd64-v2-record.zip](testdata/zip/malformed/zip64-eocd64-v2-record.zip) | 214 B | ZIP64 EOCD64 self-declared record-size check at `Archive/Zip.lean` — *"ZIP64 EOCD64 record-size mismatch"* | other (ZIP64 consistency) |
| [zip/malformed/zip64-eocd64-versionmadeby-too-high.zip](testdata/zip/malformed/zip64-eocd64-versionmadeby-too-high.zip) | 198 B | ZIP64 EOCD64 `versionMadeBy` lower-byte upper-bound check at `Archive/Zip.lean` — *"ZIP64 EOCD64 versionMadeBy spec-version byte too high"* | other (ZIP64 consistency) |
| [zip/malformed/zip64-eocd64-versionneeded-too-high.zip](testdata/zip/malformed/zip64-eocd64-versionneeded-too-high.zip) | 198 B | ZIP64 EOCD64 `versionNeededToExtract` upper-bound check at `Archive/Zip.lean` — *"ZIP64 EOCD64 versionNeededToExtract too high"* | other (ZIP64 consistency) |
| [zip/malformed/zip64-extra-oversized-datasize.zip](testdata/zip/malformed/zip64-extra-oversized-datasize.zip) | 162 B | ZIP64 extra-field `dataSize` exactness check at `Archive/Zip.lean` — *"malformed ZIP64 extra field"* | other (ZIP64 consistency) |