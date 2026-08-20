import ArchiveTest.Tar
import ArchiveTest.Zip
import ArchiveTest.ZipFixtures
import ArchiveTest.TarFixtures
import ArchiveTest.TarPathTruncation
import ArchiveTest.Utf8Fixtures
import ArchiveTest.NativeIntegration
import ArchiveTest.BoundedReadTest
import ArchiveTest.FuzzHandleRead

def main : IO Unit := do
  unless ← System.FilePath.pathExists "testdata" do
    throw (IO.userError "testdata/ not found — run tests via 'lake test' from the project root")
  ArchiveTest.Tar.tests
  ArchiveTest.Zip.tests
  ArchiveTest.ZipFixtures.tests
  ArchiveTest.TarFixtures.tests
  ArchiveTest.TarPathTruncation.tests
  ArchiveTest.Utf8Fixtures.tests
  ArchiveTest.NativeIntegration.tests
  ArchiveTest.BoundedRead.tests
  ArchiveTest.FuzzHandleRead.tests
  IO.println "\nAll tests passed!"
