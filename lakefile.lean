import Lake
open System Lake DSL

/-! # lean-archive

Tar and ZIP archives in Lean 4, built on the verified
[lean-zip](https://github.com/kim-em/lean-zip) DEFLATE codec and the
[lean-zlib](https://github.com/kim-em/lean-zlib) FFI bindings.
Archive compression uses zlib; decompression is selectable between zlib
and the verified native decoder. Building needs system zlib +
pkg-config (or `ZLIB_CFLAGS`/`ZLIB_LDFLAGS`). -/

/-- Split a shell-style flag string on spaces and drop empties. -/
def splitFlags (s : String) : Array String :=
  s.splitOn " " |>.filter (· ≠ "") |>.toArray

/-- Look `cmd` up on `PATH`, the way a shell would (keep in sync with
    lean-zlib's lakefile). -/
def onPath (cmd : String) : IO Bool := do
  let some path ← IO.getEnv "PATH" | return false
  let sep := if Platform.isWindows then ";" else ":"
  let exts := if Platform.isWindows then #["", ".exe", ".cmd", ".bat"] else #[""]
  for dir in path.splitOn sep do
    if dir.isEmpty then continue
    for ext in exts do
      let candidate : FilePath := dir / (cmd ++ ext)
      if (← candidate.pathExists) && !(← candidate.isDir) then return true
  return false

/-- Run a probe command, reporting `none` if the tool is not installed (keep in
    sync with lean-zlib's lakefile, which explains why a missing executable must
    never reach `IO.Process.output` on the pinned toolchain). -/
def tryOutput (cmd : String) (args : Array String) : IO (Option IO.Process.Output) := do
  unless (← onPath cmd) do return none
  match ← (IO.Process.output { cmd, args }).toBaseIO with
  | .ok out => return some out
  | .error e =>
    IO.eprintln s!"warning: could not run the probe '{cmd}': {e}"
    return none

/-- Run `pkg-config` and split the output into flags. Returns `#[]` on failure. -/
def pkgConfig (pkg : String) (flag : String) : IO (Array String) := do
  let some out ← tryOutput "pkg-config" #[flag, pkg] | return #[]
  if out.exitCode != 0 then return #[]
  return splitFlags out.stdout.trimAscii.toString

/-- Run `xcrun --show-sdk-path` and return the SDK path on Apple platforms. -/
def macSdkPath : IO (Option FilePath) := do
  if !Platform.isOSX then return none
  let some out ← tryOutput "xcrun" #["--show-sdk-path"] | return none
  if out.exitCode != 0 then
    return none
  else
    return some out.stdout.trimAscii.toString

/-- Prefer an explicit linker override when supplied by the environment. -/
def zlibLdFlagsOverride : IO (Option (Array String)) := do
  return (← IO.getEnv "ZLIB_LDFLAGS") |>.map (splitFlags ·.trimAscii.toString)

/-- Extract `-L` library paths from `NIX_LDFLAGS` (set by nix-shell). -/
def nixLdLibPaths : IO (Array String) := do
  let some val := (← IO.getEnv "NIX_LDFLAGS") | return #[]
  return val.splitOn " " |>.filter (·.startsWith "-L") |>.toArray

/-- Get link flags for zlib (keep in sync with lean-zlib's lakefile).
    The `lean-zlib` dependency's own `moreLinkArgs` do not propagate to this
    package's executables, so the link flags are re-supplied here. -/
def zlibLinkFlags : IO (Array String) := do
  if let some flags := (← zlibLdFlagsOverride) then
    return flags
  let libPaths ← nixLdLibPaths
  let zlibFlags ← pkgConfig "zlib" "--libs"
  if !zlibFlags.isEmpty && zlibFlags.any (·.startsWith "-L") then
    return zlibFlags
  if let some sdk := (← macSdkPath) then
    return #["-L", (sdk / "usr/lib").toString, "-lz"]
  if !zlibFlags.isEmpty then
    return libPaths ++ zlibFlags
  -- pkg-config unavailable — try NIX_LDFLAGS for -L paths
  return libPaths ++ #["-lz"]

/-- LTO link flags mirroring lean-zip's `ltoLinkFlags` (its issue #2806,
    keep in sync): on Linux the lean-zip dependency's objects are LLVM
    bitcode, so this package's executable links run the same LTO codegen
    at `-O3`. `LEAN_ZIP_LTO=0` opts out. -/
def ltoLinkFlags : IO (Array String) := do
  if Platform.isWindows || Platform.isOSX then return #[]
  if (← IO.getEnv "LEAN_ZIP_LTO") == some "0" then return #[]
  return #["-flto", "-fno-semantic-interposition", "-O3"]

package «lean-archive» where
  moreLinkArgs := run_io do return (← zlibLinkFlags) ++ (← ltoLinkFlags)
  testDriver := "test"

require «lean-zip» from git "https://github.com/kim-em/lean-zip" @ "ac1b7c51ff91b1d015a2f1dc616df19bde5e8865"

require «lean-zlib» from git "https://github.com/kim-em/lean-zlib" @ "a606785a8685df084356e075996c9b161e937626"

require zipCommon from git "https://github.com/kim-em/lean-zip-common" @ "086d1983eab397105c2340cae80e325fd2d40231"

lean_lib Archive

lean_lib ArchiveTest where
  globs := #[.submodules `ArchiveTest]

@[default_target]
lean_exe test where
  root := `ArchiveTest

lean_exe fuzz_handle_read where
  root := `FuzzHandleReadMain
