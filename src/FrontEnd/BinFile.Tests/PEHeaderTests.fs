(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*)

namespace B2R2.FrontEnd.BinFile.Tests

open System.IO
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.PE
open Microsoft.VisualStudio.TestTools.UnitTesting
open type FileFormat

/// Names the types of the BCL's own PE reader apart from B2R2's, the two
/// having every name worth having in common.
module private Bcl =
  type Coff = System.Reflection.PortableExecutable.CoffHeader
  type Optional = System.Reflection.PortableExecutable.PEHeader
  type Section = System.Reflection.PortableExecutable.SectionHeader
  type Cor = System.Reflection.PortableExecutable.CorHeader
  type Directory = System.Reflection.PortableExecutable.DirectoryEntry

/// <summary>
/// Checks the headers B2R2 reads out of a PE file against the ones the BCL
/// reader reads out of the same bytes. Reading them was that reader's work
/// until B2R2 took it over, so field for field it records what this parser
/// has to go on reading, and every fixture there is goes through it.
/// </summary>
[<TestClass>]
type PEHeaderTests() =
  /// Every PE fixture, named by the archive holding it and the entry inside.
  static let fixtures =
    [| "pe_x64", "pe_x64.exe"
       "pe_x86", "pe_x86.exe"
       "pe_x64_dll", "pe_x64_dll.dll"
       "pe_x64_obj", "pe_x64_obj.obj"
       "pe_x64_pdb", "pe_x64_pdb.exe"
       "pe_x64_tls", "pe_x64_tls.exe"
       "pe_x64_guardcf", "pe_x64_guardcf.exe"
       "pe_x64_exc", "pe_x64_exc.exe"
       "pe_x64_exc_fh3", "pe_x64_exc_fh3.exe"
       "pe_x64_signed", "pe_x64_signed.exe" |]

  /// This test assembly is itself a managed PE, which is the one shape the
  /// fixtures leave out: it alone carries a CLI header.
  static let managedBytes =
    System.Reflection.Assembly.GetExecutingAssembly().Location
    |> File.ReadAllBytes

  /// Reads the headers the BCL reader makes of the given bytes. They outlive
  /// the reader that made them, holding what it read rather than the stream
  /// it read from.
  static let bclHeaders (bytes: byte[]) =
    use stream = new MemoryStream(bytes)
    use reader =
      new System.Reflection.PortableExecutable.PEReader(stream)
    reader.PEHeaders

  /// Asserts the two values are one and the same, whatever their type.
  static let same (expected: 'T) actual =
    Assert.AreEqual<'T>(expected, actual)

  static let checkDir (expected: Bcl.Directory) (actual: DataDirectory) =
    same expected.RelativeVirtualAddress actual.RVA
    same expected.Size actual.Size

  static let checkCoff (expected: Bcl.Coff) (actual: CoffHeader) =
    same (uint16 expected.Machine) (uint16 actual.Machine)
    same expected.NumberOfSections actual.NumberOfSections
    same expected.TimeDateStamp actual.TimeDateStamp
    same expected.PointerToSymbolTable actual.PointerToSymbolTable
    same expected.NumberOfSymbols actual.NumberOfSymbols
    same expected.SizeOfOptionalHeader actual.SizeOfOptionalHeader
    same (uint16 expected.Characteristics) (uint16 actual.Characteristics)

  /// The standard fields, which are those a COFF image of any system has.
  static let checkStandard (expected: Bcl.Optional) (actual: OptionalHeader) =
    same (uint16 expected.Magic) (uint16 actual.Magic)
    same expected.MajorLinkerVersion actual.MajorLinkerVersion
    same expected.MinorLinkerVersion actual.MinorLinkerVersion
    same expected.SizeOfCode actual.SizeOfCode
    same expected.SizeOfInitializedData actual.SizeOfInitializedData
    same expected.SizeOfUninitializedData actual.SizeOfUninitializedData
    same expected.AddressOfEntryPoint actual.AddressOfEntryPoint
    same expected.BaseOfCode actual.BaseOfCode
    same expected.BaseOfData actual.BaseOfData
    same expected.ImageBase actual.ImageBase

  /// The Windows-specific fields that follow them.
  static let checkWindows (expected: Bcl.Optional) (actual: OptionalHeader) =
    same expected.SectionAlignment actual.SectionAlignment
    same expected.FileAlignment actual.FileAlignment
    let majorOS = actual.MajorOperatingSystemVersion
    let minorOS = actual.MinorOperatingSystemVersion
    same expected.MajorOperatingSystemVersion majorOS
    same expected.MinorOperatingSystemVersion minorOS
    same expected.MajorImageVersion actual.MajorImageVersion
    same expected.MinorImageVersion actual.MinorImageVersion
    same expected.MajorSubsystemVersion actual.MajorSubsystemVersion
    same expected.MinorSubsystemVersion actual.MinorSubsystemVersion
    same expected.SizeOfImage actual.SizeOfImage
    same expected.SizeOfHeaders actual.SizeOfHeaders
    same expected.CheckSum actual.CheckSum
    same (uint16 expected.Subsystem) (uint16 actual.Subsystem)
    let dllChars = uint16 actual.DllCharacteristics
    same (uint16 expected.DllCharacteristics) dllChars
    same expected.SizeOfStackReserve actual.SizeOfStackReserve
    same expected.SizeOfStackCommit actual.SizeOfStackCommit
    same expected.SizeOfHeapReserve actual.SizeOfHeapReserve
    same expected.SizeOfHeapCommit actual.SizeOfHeapCommit
    same expected.NumberOfRvaAndSizes actual.NumberOfRvaAndSizes

  /// The fifteen data directories the BCL reader names one by one, in the
  /// order the header holds them, which is the order B2R2 indexes them by.
  static let bclDirectories (hdr: Bcl.Optional) =
    [| hdr.ExportTableDirectory
       hdr.ImportTableDirectory
       hdr.ResourceTableDirectory
       hdr.ExceptionTableDirectory
       hdr.CertificateTableDirectory
       hdr.BaseRelocationTableDirectory
       hdr.DebugTableDirectory
       hdr.CopyrightTableDirectory
       hdr.GlobalPointerTableDirectory
       hdr.ThreadLocalStorageTableDirectory
       hdr.LoadConfigTableDirectory
       hdr.BoundImportTableDirectory
       hdr.ImportAddressTableDirectory
       hdr.DelayImportTableDirectory
       hdr.CorHeaderTableDirectory |]

  static let checkDirectories expected (actual: OptionalHeader) =
    let dirs = bclDirectories expected
    for i = 0 to dirs.Length - 1 do
      checkDir dirs[i] actual.Directories[i]

  static let checkOptional (expected: Bcl.Optional) actual =
    match actual with
    | None ->
      Assert.IsNull expected
    | Some hdr ->
      Assert.IsNotNull expected
      checkStandard expected hdr
      checkWindows expected hdr
      checkDirectories expected hdr

  static let checkSection (expected: Bcl.Section) (actual: SectionHeader) =
    same expected.Name actual.Name
    same expected.VirtualSize actual.VirtualSize
    same expected.VirtualAddress actual.VirtualAddress
    same expected.SizeOfRawData actual.SizeOfRawData
    same expected.PointerToRawData actual.PointerToRawData
    same expected.PointerToRelocations actual.PointerToRelocations
    same expected.PointerToLineNumbers actual.PointerToLineNumbers
    same expected.NumberOfRelocations actual.NumberOfRelocations
    same expected.NumberOfLineNumbers actual.NumberOfLineNumbers
    let chars = uint32 actual.SectionCharacteristics
    same (uint32 expected.SectionCharacteristics) chars

  static let checkSections (expected: Bcl.Section[]) (actual: SectionHeader[]) =
    same expected.Length actual.Length
    for i = 0 to expected.Length - 1 do
      checkSection expected[i] actual[i]

  /// The directories a CLI header names, in the order it holds them.
  static let bclCorDirectories (hdr: Bcl.Cor) =
    [| hdr.MetadataDirectory
       hdr.ResourcesDirectory
       hdr.StrongNameSignatureDirectory
       hdr.CodeManagerTableDirectory
       hdr.VtableFixupsDirectory
       hdr.ExportAddressTableJumpsDirectory
       hdr.ManagedNativeHeaderDirectory |]

  static let corDirectories (hdr: CorHeader) =
    [| hdr.MetadataDirectory
       hdr.ResourcesDirectory
       hdr.StrongNameSignatureDirectory
       hdr.CodeManagerTableDirectory
       hdr.VtableFixupsDirectory
       hdr.ExportAddressTableJumpsDirectory
       hdr.ManagedNativeHeaderDirectory |]

  static let checkCor (expected: Bcl.Cor) actual =
    match actual with
    | None ->
      Assert.IsNull expected
    | Some hdr ->
      Assert.IsNotNull expected
      same expected.MajorRuntimeVersion hdr.MajorRuntimeVersion
      same expected.MinorRuntimeVersion hdr.MinorRuntimeVersion
      same (int expected.Flags) (int hdr.Flags)
      let token = hdr.EntryPointTokenOrRelativeVirtualAddress
      same expected.EntryPointTokenOrRelativeVirtualAddress token
      let dirs = bclCorDirectories expected
      Array.iter2 checkDir dirs (corDirectories hdr)

  /// Checks every header of one file, which is the whole of what this tests.
  static let checkFile (bytes: byte[]) =
    let expected = bclHeaders bytes
    let actual = Header.parse bytes (BinReader.Init Endian.Little)
    same expected.IsCoffOnly actual.IsCoffOnly
    same expected.CoffHeaderStartOffset actual.CoffHeaderOffset
    same expected.PEHeaderStartOffset actual.OptionalHeaderOffset
    same expected.CorHeaderStartOffset actual.CorHeaderOffset
    checkCoff expected.CoffHeader actual.CoffHeader
    checkOptional expected.PEHeader actual.OptionalHeader
    checkSections (Seq.toArray expected.SectionHeaders) actual.SectionHeaders
    checkCor expected.CorHeader actual.CorHeader

  [<TestMethod>]
  member _.``[PE] every fixture reads as the BCL reader reads it``() =
    for archive, entry in fixtures do
      ZIPReader.readBytes PEBinary (archive + ".zip") entry |> checkFile

  [<TestMethod>]
  member _.``[PE] a managed image reads as the BCL reader reads it``() =
    checkFile managedBytes
