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

open B2R2
open B2R2.Collections
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.Mach
open Microsoft.VisualStudio.TestTools.UnitTesting
open type B2R2.FrontEnd.BinFile.FileFormat

[<TestClass>]
type MachEmitterTests() =
  static let bytesOf fileName =
    ZIPReader.readBytes MachBinary (fileName + ".zip") fileName

  /// Returns the ISA of every image the given file holds, which is one per
  /// slice for a universal binary and any of them for a file holding one
  /// image, whose bytes are picked out by no ISA at all.
  static let isasOf (bytes: byte[]) =
    if Header.IsFat bytes then
      Fat.parseArchs bytes
      |> Array.map (fun fatArch ->
        let arch, wordSize =
          CPUType.toArchWordSizeTuple fatArch.CPUType fatArch.CPUSubType
        ISA(arch, Endian.Little, wordSize))
    else
      [| ISA(Architecture.Intel, Endian.Little, WordSize.Bit64) |]

  /// Returns the bytes of the image itself, which for a universal binary are
  /// the slice matching the given ISA rather than the whole of the file.
  static let imageOf name bytes isa =
    MachBinFile(name, bytes, isa, None, None).Bytes

  /// The ISA every fixture below is built for, none of them being universal.
  static let x64 = ISA(Architecture.Intel, Endian.Little, WordSize.Bit64)

  static let imageFor name = Image.ofBytes (bytesOf name) x64 None

  static let fileOf (bytes: byte[]) =
    MachBinFile("f", bytes, x64, None, None) :> IBinFile

  /// Returns what the given image holds for the named section, which takes
  /// both names, a section name being unique within its segment alone.
  static let sectionOf (img: Image) segName secName =
    let isNamed (entry: SectionEntry) =
      entry.Section.SegName = segName && entry.Section.SecName = secName
    (img.Sections |> Array.find isNamed).Section

  /// Returns a section the tests ask an image to add, holding the given
  /// bytes under names of its own.
  static let specOf secName content =
    { SpecSegName = "__B2R2"
      SpecSecName = secName
      SpecType = SectionType.S_REGULAR
      SpecAttrib = LanguagePrimitives.EnumOfValue 0
      SpecAlignment = 0u
      SpecPermission = Permission.Readable
      SpecContent = content }

  /// Returns the number of the section the given image holds under the
  /// given names, counted from one as a Mach-O counts its sections.
  static let secNumOf (img: Image) segName secName =
    let isNamed (entry: SectionEntry) =
      entry.Section.SegName = segName && entry.Section.SecName = secName
    (img.Sections |> Array.findIndex isNamed) + 1

  /// Every Mach-O fixture, one per row, so that whatever one is added next is
  /// round-tripped without anything here naming it.
  static member Fixtures =
    ZIPReader.listFixtureNames MachBinary
    |> Array.map (fun name -> [| box name |])

  [<TestMethod>]
  [<DynamicData(nameof MachEmitterTests.Fixtures)>]
  member _.``[Mach] untouched round trip test``(name: string) =
    let bytes = bytesOf name
    for isa in isasOf bytes do
      let emitted = Image.ofBytes bytes isa None |> Emitter.emit
      CollectionAssert.AreEqual(imageOf name bytes isa, emitted)

  [<TestMethod>]
  member _.``[Mach] rebased round trip test``() =
    let bytes = bytesOf "mach_x64"
    let isa = ISA(Architecture.Intel, Endian.Little, WordSize.Bit64)
    let emitted = Image.ofBytes bytes isa (Some 0x400000UL) |> Emitter.emit
    CollectionAssert.AreEqual(imageOf "mach_x64" bytes isa, emitted)

  /// What keeps the round trip above from passing on an emitter that writes
  /// nothing at all: a field the image alone was told about has to come back
  /// out of the file the emitter builds.
  [<TestMethod>]
  member _.``[Mach] emitted entry point test``() =
    let bytes = bytesOf "mach_x64"
    let entry = (fileOf bytes).EntryPoint.Value
    let img = Image.ofBytes bytes x64 None
    let emitted = Image.setEntryPoint (entry + 4UL) img |> Emitter.emit
    let after = (fileOf emitted).EntryPoint
    Assert.AreEqual<uint64 option>(Some(entry + 4UL), after)

  /// A file older than LC_MAIN names its entry point as the program counter
  /// of its initial thread, which sits inside a state this writer has to walk
  /// to again rather than at a field of its own.
  [<TestMethod>]
  member _.``[Mach] emitted entry point through a thread state test``() =
    let bytes = bytesOf "mach_x64_unixthread"
    let entry = (fileOf bytes).EntryPoint.Value
    let img = Image.ofBytes bytes x64 None
    let emitted = Image.setEntryPoint (entry + 4UL) img |> Emitter.emit
    let after = (fileOf emitted).EntryPoint
    Assert.AreEqual<uint64 option>(Some(entry + 4UL), after)

  [<TestMethod>]
  member _.``[Mach] emitted section attributes test``() =
    let img = imageFor "mach_x64"
    let attrib = SectionAttribute.S_ATTR_NO_DEAD_STRIP
    let regular = SectionType.S_REGULAR
    let edit = Image.setSectionAttributes "__TEXT" "__text" regular attrib
    let emitted = edit img |> Emitter.emit
    let text = sectionOf (Image.ofBytes emitted x64 None) "__TEXT" "__text"
    Assert.AreEqual<SectionAttribute>(attrib, text.SecAttrib)
    Assert.AreEqual<SectionType>(SectionType.S_REGULAR, text.SecType)

  /// A section of a segment the image does not hold is no section to edit.
  [<TestMethod>]
  member _.``[Mach] section named by the wrong segment test``() =
    let img = imageFor "mach_x64"
    let noAttr: SectionAttribute = LanguagePrimitives.EnumOfValue 0
    let regular = SectionType.S_REGULAR
    let edit = Image.setSectionAttributes "__DATA" "__text" regular noAttr
    Assert.ThrowsExactly<SectionNotFoundException>(fun () -> edit img |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``[Mach] patch at address test``() =
    let bytes = bytesOf "mach_x64"
    let addr = (fileOf bytes).EntryPoint.Value
    let img = Image.ofBytes bytes x64 None
    let nops = [| 0x90uy; 0x90uy |]
    let emitted = Image.patchByAddr addr nops img |> Emitter.emit
    let read = (fileOf emitted).Slice(addr, 2).ToArray()
    CollectionAssert.AreEqual(nops, read)

  /// An image never writes through to what it was parsed from, so the bytes
  /// handed to it are as good after a patch as they were before.
  [<TestMethod>]
  member _.``[Mach] patch leaves the original alone test``() =
    let bytes = bytesOf "mach_x64"
    let img = Image.ofBytes bytes x64 None
    let addr = (fileOf bytes).EntryPoint.Value
    Image.patchByAddr addr [| 0x90uy |] img |> Emitter.emit |> ignore
    CollectionAssert.AreEqual(bytesOf "mach_x64", bytes)

  [<TestMethod>]
  member _.``[Mach] patch beyond the file test``() =
    let img = imageFor "mach_x64"
    Assert.ThrowsExactly<InvalidAddrWriteException>(fun () ->
      let past = img.Original.Length - 1
      Image.patchByOffset past [| 0uy; 0uy |] img |> ignore)
    |> ignore

  /// An address no segment maps holds no bytes of the file to put anything
  /// at.
  [<TestMethod>]
  member _.``[Mach] patch at an unmapped address test``() =
    let img = imageFor "mach_x64"
    Assert.ThrowsExactly<InvalidAddrWriteException>(fun () ->
      Image.patchByAddr 0xdeadbeefUL [| 0uy |] img |> ignore)
    |> ignore

  /// Content of the size that was already there goes where the section
  /// already is, and the file stays as long as it was.
  [<TestMethod>]
  member _.``[Mach] same-size section content test``() =
    let img = imageFor "mach_x64"
    let size = int (sectionOf img "__TEXT" "__text").SecSize
    let content = Array.create size 0x90uy
    let emitted = Image.setSectionContent "__TEXT" "__text" content img
                  |> Emitter.emit
    Assert.AreEqual<int>(img.Original.Length, emitted.Length)
    let text = sectionOf (Image.ofBytes emitted x64 None) "__TEXT" "__text"
    let read = (fileOf emitted).Slice(text.SecAddr, size).ToArray()
    CollectionAssert.AreEqual(content, read)

  /// Every section sits inside a segment the file maps whole, so giving one
  /// content of another size would move whatever follows it out from under
  /// the segment describing it.
  [<TestMethod>]
  member _.``[Mach] resizing a section test``() =
    let img = imageFor "mach_x64"
    let edit = Image.setSectionContent "__TEXT" "__text" [| 0uy |]
    Assert.ThrowsExactly<UnsupportedEditException>(fun () ->
      edit img |> ignore)
    |> ignore

  /// A section holding nothing but zeros keeps no bytes in the file for
  /// anything to be put in.
  [<TestMethod>]
  member _.``[Mach] content of a zero-filled section test``() =
    let img = imageFor "mach_x64_reloc"
    let common = sectionOf img "__DATA" "__common"
    let content = Array.zeroCreate (int common.SecSize)
    let edit = Image.setSectionContent "__DATA" "__common" content
    Assert.ThrowsExactly<UnsupportedEditException>(fun () ->
      edit img |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``[Mach] added section test``() =
    let content = [| 1uy; 2uy; 3uy; 4uy; 5uy |]
    let img = imageFor "mach_x64_dyldinfo"
    let emitted = Image.addSection (specOf "__b2r2" content) img
                  |> Emitter.emit
    let sec = sectionOf (Image.ofBytes emitted x64 None) "__B2R2" "__b2r2"
    let file = fileOf emitted
    Assert.AreEqual<bool>(true, file.IsValidAddr sec.SecAddr)
    let read = file.Slice(sec.SecAddr, content.Length).ToArray()
    CollectionAssert.AreEqual(content, read)

  /// A section goes after the ones the file has, where it leaves every
  /// section number and every symbol the file already uses as they were.
  [<TestMethod>]
  member _.``[Mach] added section keeps the rest test``() =
    let bytes = bytesOf "mach_x64_dyldinfo"
    let img = Image.ofBytes bytes x64 None
    let emitted = Image.addSection (specOf "__b2r2" [| 7uy |]) img
                  |> Emitter.emit
    let before, after = fileOf bytes, fileOf emitted
    Assert.AreEqual<uint64 option>(before.EntryPoint, after.EntryPoint)
    let symbolCount (f: IBinFile) = f.SymbolTable.Value.Symbols.Length
    Assert.AreEqual<int>(symbolCount before, symbolCount after)
    let sectionCount (f: IBinFile) = f.Structure.Value.Sections.Length
    Assert.AreEqual<int>(sectionCount before + 1, sectionCount after)

  /// The address a segment is mapped at has to agree with the offset it is
  /// mapped from, down to the page the two sit in.
  [<TestMethod>]
  member _.``[Mach] added segment congruence test``() =
    let img = imageFor "mach_x64_dyldinfo"
    let emitted = Image.addSection (specOf "__b2r2" (Array.create 64 0uy)) img
                  |> Emitter.emit
    let after = Image.ofBytes emitted x64 None
    let isAdded (seg: SegCmd) = seg.SegCmdName = "__B2R2"
    let seg = Image.segmentsOf after |> Array.find isAdded
    let page = 0x1000UL
    Assert.AreEqual<uint64>(seg.VMAddr % page, seg.FileOff % page)
    Assert.AreEqual<uint64>(0UL, seg.FileOff % page)
    let sec = sectionOf after "__B2R2" "__b2r2"
    Assert.AreEqual<uint64>(seg.FileOff, uint64 sec.SecOffset)

  /// The commands of a Mach-O cannot grow past whatever the file keeps after
  /// them, so a section is refused once that room has gone rather than
  /// written over what follows.
  [<TestMethod>]
  member _.``[Mach] adding sections until the room runs out test``() =
    let img = imageFor "mach_x64_dyldinfo"
    let rec fill n img =
      if n = 0 then img
      else fill (n - 1) (Image.addSection (specOf ("__s" + string n) [| 1uy |])
                                          img)
    let filled = fill (Image.commandBudget img / (72 + 80)) img
    Assert.ThrowsExactly<UnsupportedEditException>(fun () ->
      Image.addSection (specOf "__over" [| 1uy |]) filled |> ignore)
    |> ignore

  /// An executable is linked with barely any room after its commands, so a
  /// section it has no place for is refused outright.
  [<TestMethod>]
  member _.``[Mach] adding a section without the room test``() =
    let img = imageFor "mach_x64"
    Assert.ThrowsExactly<UnsupportedEditException>(fun () ->
      Image.addSection (specOf "__b2r2" [| 1uy |]) img |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``[Mach] added symbol test``() =
    let bytes = bytesOf "mach_x64"
    let img = Image.ofBytes bytes x64 None
    let addr = (fileOf bytes).EntryPoint.Value + 8UL
    let spec =
      { SymSpecName = "_b2r2_fn"
        SymSpecAddr = addr
        SymSpecSecNum = secNumOf img "__TEXT" "__text" }
    let emitted = Image.addSymbol spec img |> Emitter.emit
    let resolved = (fileOf emitted).NameResolver.Value.TryResolveName addr
    Assert.AreEqual<Result<string, ErrorCase>>(Ok "_b2r2_fn", resolved)

  /// A symbol going into the middle of the table moves every index that
  /// named one after it, which is what the indirect symbol table and the
  /// imports read through it are built out of.
  [<TestMethod>]
  member _.``[Mach] added symbol keeps the rest test``() =
    let bytes = bytesOf "mach_x64"
    let img = Image.ofBytes bytes x64 None
    let spec =
      { SymSpecName = "_b2r2_fn"
        SymSpecAddr = (fileOf bytes).EntryPoint.Value + 8UL
        SymSpecSecNum = secNumOf img "__TEXT" "__text" }
    let emitted = Image.addSymbol spec img |> Emitter.emit
    let before, after = fileOf bytes, fileOf emitted
    let symbolCount (f: IBinFile) = f.SymbolTable.Value.Symbols.Length
    Assert.AreEqual<int>(symbolCount before + 1, symbolCount after)
    let importNames (f: IBinFile) =
      f.ImportTable.Value.Imports |> ImmutableArray.map (fun i -> i.Name)
    CollectionAssert.AreEqual(importNames before, importNames after)
    Assert.AreEqual<uint64 option>(before.EntryPoint, after.EntryPoint)

  /// The runs of __LINKEDIT after the ones that grew move along by as much,
  /// and the segment holding them all grows to cover them.
  [<TestMethod>]
  member _.``[Mach] added symbol moves the runs that follow test``() =
    let bytes = bytesOf "mach_x64"
    let img = Image.ofBytes bytes x64 None
    let spec =
      { SymSpecName = "_b2r2_fn"
        SymSpecAddr = (fileOf bytes).EntryPoint.Value + 8UL
        SymSpecSecNum = secNumOf img "__TEXT" "__text" }
    let emitted = Image.addSymbol spec img |> Emitter.emit
    Assert.AreEqual<bool>(true, emitted.Length > bytes.Length)
    let isLinkEdit (seg: SegCmd) = seg.SegCmdName = "__LINKEDIT"
    let segOf b = Image.segmentsOf (Image.ofBytes b x64 None)
                  |> Array.find isLinkEdit
    let before, after = segOf bytes, segOf emitted
    let grown = uint64 (emitted.Length - bytes.Length)
    Assert.AreEqual<uint64>(before.FileSize + grown, after.FileSize)
    Assert.AreEqual<bool>(true, after.VMSize >= after.FileSize)

  /// An object file names the symbol of every relocation by index, and its
  /// relocations sit outside __LINKEDIT, where nothing here moves them.
  [<TestMethod>]
  member _.``[Mach] adding a symbol to an object file test``() =
    let img = imageFor "mach_x64_reloc"
    let spec =
      { SymSpecName = "_b2r2_fn"; SymSpecAddr = 0x10UL; SymSpecSecNum = 1 }
    Assert.ThrowsExactly<UnsupportedEditException>(fun () ->
      Image.addSymbol spec img |> ignore)
    |> ignore

  /// A file whose symbols were stripped still names the three groups, so a
  /// symbol can be put back into one of them.
  [<TestMethod>]
  member _.``[Mach] added symbol to a stripped file test``() =
    let img = imageFor "mach_x64_stripped"
    let spec =
      { SymSpecName = "_b2r2_fn"
        SymSpecAddr = 0x100000f00UL
        SymSpecSecNum = secNumOf img "__TEXT" "__text" }
    let symbols = (fileOf (bytesOf "mach_x64_stripped")).SymbolTable.Value
    Assert.AreEqual<bool>(true, symbols.IsStripped)
    let emitted = Image.addSymbol spec img |> Emitter.emit
    let resolved = (fileOf emitted).NameResolver.Value.TryResolveName
                     0x100000f00UL
    Assert.AreEqual<Result<string, ErrorCase>>(Ok "_b2r2_fn", resolved)

  /// A signature covers the bytes as they were, so a writer that has changed
  /// any of them can take it off, which leaves the file the shorter for it.
  [<TestMethod>]
  member _.``[Mach] removed code signature test``() =
    let bytes = bytesOf "mach_x64_codesign"
    let img = Image.ofBytes bytes x64 None
    let emitted = Image.removeCodeSignature img |> Emitter.emit
    Assert.AreEqual<bool>(true, emitted.Length < bytes.Length)
    let after = Image.ofBytes emitted x64 None
    let isCodeSign entry =
      match entry.Command with
      | CodeSign _ -> true
      | _ -> false
    Assert.AreEqual<bool>(false, after.Commands |> Array.exists isCodeSign)
    let symbolCount (f: IBinFile) = f.SymbolTable.Value.Symbols.Length
    Assert.AreEqual<int>(symbolCount (fileOf bytes),
                         symbolCount (fileOf emitted))

  /// A file carrying no signature has none to take off.
  [<TestMethod>]
  member _.``[Mach] removing a signature that is not there test``() =
    let img = imageFor "mach_x64"
    Assert.ThrowsExactly<UnsupportedEditException>(fun () ->
      Image.removeCodeSignature img |> ignore)
    |> ignore

  /// The writer is what a Mach-O file is edited through from outside this
  /// assembly, so what it needs has to be public. Nothing else here can say
  /// so: the test assembly sees what is internal as well.
  [<TestMethod>]
  member _.``[Mach] public writing surface test``() =
    let isPublic (t: System.Type) = t.IsPublic
    Assert.AreEqual<bool>(true, isPublic typeof<MachWriter>)
    Assert.AreEqual<bool>(true, isPublic typeof<SectionType>)
    Assert.AreEqual<bool>(true, isPublic typeof<SectionAttribute>)
    Assert.AreEqual<bool>(true, isPublic typeof<SectionSpec>)
    Assert.AreEqual<bool>(true, isPublic typeof<SymbolSpec>)
    let members = typeof<MachWriter>.GetMethods() |> Array.filter _.IsPublic
    let named n = members |> Array.exists (fun m -> m.Name = n)
    let expected =
      [ "Emit"
        "PatchByAddr"
        "PatchByOffset"
        "SetEntryPoint"
        "SetSectionAttributes"
        "SetSectionContent"
        "AddSection"
        "AddSymbol"
        "RemoveCodeSignature" ]
    for name in expected do
      Assert.AreEqual<bool>(true, named name, name)

  /// The writer starts as the file it is given, so one nothing has been asked
  /// of emits that file back.
  [<TestMethod>]
  member _.``[Mach] writer round trip test``() =
    let bytes = bytesOf "mach_x64"
    let writer = MachWriter(MachBinFile("f", bytes, x64, None, None))
    CollectionAssert.AreEqual(bytes, writer.Emit())

  /// The same trip for one slice of a universal binary, which is the image
  /// the writer was handed rather than the whole of the file.
  [<TestMethod>]
  member _.``[Mach] writer round trip for one slice test``() =
    let bytes = bytesOf "mach_fat_x64_arm64"
    let file = MachBinFile("f", bytes, x64, None, None)
    CollectionAssert.AreEqual(file.Bytes, MachWriter(file).Emit())

  /// What the writer is for: an edit asked of it through the public surface
  /// reaches the bytes it emits.
  [<TestMethod>]
  member _.``[Mach] writer edits test``() =
    let bytes = bytesOf "mach_x64"
    let file = MachBinFile("f", bytes, x64, None, None)
    let writer = MachWriter(file)
    let entry = (file :> IBinFile).EntryPoint.Value
    writer.SetEntryPoint(entry + 4UL)
    let attrib = SectionAttribute.S_ATTR_NO_DEAD_STRIP
    let regular = SectionType.S_REGULAR
    writer.SetSectionAttributes("__TEXT", "__text", regular, attrib)
    let emitted = writer.Emit()
    let after = (fileOf emitted).EntryPoint
    Assert.AreEqual<uint64 option>(Some(entry + 4UL), after)
    let text = sectionOf (Image.ofBytes emitted x64 None) "__TEXT" "__text"
    Assert.AreEqual<SectionAttribute>(attrib, text.SecAttrib)

  /// What any format can be asked for reaches the bytes through the interface
  /// alone, so that a tool patching a binary need not know which format it is.
  [<TestMethod>]
  member _.``[Mach] writer through the interface test``() =
    let bytes = bytesOf "mach_x64"
    let file = MachBinFile("f", bytes, x64, None, None)
    let writer = MachWriter file :> IBinWriter
    let addr = (file :> IBinFile).EntryPoint.Value
    writer.PatchByAddr(addr, [| 0x90uy; 0x90uy |])
    writer.PatchByOffset(0x18, [| 0uy |])
    let emitted = writer.Emit()
    let read = (fileOf emitted).Slice(addr, 2).ToArray()
    CollectionAssert.AreEqual([| 0x90uy; 0x90uy |], read)
    Assert.AreEqual<byte>(0uy, emitted[0x18])

  /// Emitting a file, reading it back and emitting it again hands back the
  /// same bytes: everything the first pass moved is where the second pass
  /// reads it from, so nothing drifts.
  [<TestMethod>]
  member _.``[Mach] emitting twice test``() =
    let bytes = bytesOf "mach_x64"
    let img = Image.ofBytes bytes x64 None
    let spec =
      { SymSpecName = "_b2r2_fn"
        SymSpecAddr = (fileOf bytes).EntryPoint.Value + 8UL
        SymSpecSecNum = secNumOf img "__TEXT" "__text" }
    let once = Image.addSymbol spec img |> Emitter.emit
    let twice = Image.ofBytes once x64 None |> Emitter.emit
    CollectionAssert.AreEqual(once, twice)

  /// The two edits that add something meet where a symbol names the section
  /// that was added with it.
  [<TestMethod>]
  member _.``[Mach] writer adds a section and a symbol for it test``() =
    let bytes = bytesOf "mach_x64_dyldinfo"
    let file = MachBinFile("f", bytes, x64, None, None)
    let writer = MachWriter file
    let content = Array.create 16 0xccuy
    writer.AddSection(specOf "__b2r2" content)
    let emitted = writer.Emit()
    let img = Image.ofBytes emitted x64 None
    let sec = sectionOf img "__B2R2" "__b2r2"
    let writer = MachWriter(MachBinFile("f", emitted, x64, None, None))
    writer.AddSymbol { SymSpecName = "_b2r2_fn"
                       SymSpecAddr = sec.SecAddr
                       SymSpecSecNum = secNumOf img "__B2R2" "__b2r2" }
    let final = fileOf (writer.Emit())
    let resolved = final.NameResolver.Value.TryResolveName sec.SecAddr
    Assert.AreEqual<Result<string, ErrorCase>>(Ok "_b2r2_fn", resolved)
    CollectionAssert.AreEqual(content,
                              final.Slice(sec.SecAddr, 16).ToArray())
