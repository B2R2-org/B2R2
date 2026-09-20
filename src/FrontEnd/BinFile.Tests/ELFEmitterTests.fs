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
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.ELF
open Microsoft.VisualStudio.TestTools.UnitTesting
open type B2R2.FrontEnd.BinFile.FileFormat

[<TestClass>]
type ELFEmitterTests() =
  static let bytesOf fileName =
    ZIPReader.readBytes ELFBinary (fileName + ".zip") fileName

  static let noFlags: SectionFlags = LanguagePrimitives.EnumOfValue 0UL

  static let specOf name content =
    { SpecName = name
      SpecType = SectionType.SHT_PROGBITS
      SpecFlags = noFlags
      SpecAlignment = 1UL
      SpecContent = content }

  static let symbolSpecOf name addr =
    { SymSpecName = name
      SymSpecAddr = addr
      SymSpecSize = 8UL
      SymSpecType = SymbolType.STT_FUNC
      SymSpecBind = SymbolBind.STB_GLOBAL
      SymSpecSecIdx = 15 }

  static let sectionOf (img: Image) name =
    let isNamed (s: SectionEntry) = s.SecHeader.SecName = name
    (img.Sections |> Array.find isNamed).SecHeader

  /// Returns what the emitted file holds for the section of the given name,
  /// found by parsing that file rather than by trusting where it was put.
  static let sectionBytesOf (bytes: byte[]) name =
    let sec = sectionOf (Image.ofBytes bytes None) name
    let offset = int sec.SecOffset
    bytes[offset..offset + int sec.SecSize - 1]

  static let sectionNamesOf (bytes: byte[]) =
    (Image.ofBytes bytes None).Sections
    |> Array.map (fun s -> s.SecHeader.SecName)

  /// Every ELF fixture, one per row, so that whatever one is added next is
  /// round-tripped without anything here naming it.
  static member Fixtures =
    ZIPReader.listFixtureNames ELFBinary
    |> Array.map (fun name -> [| box name |])

  [<TestMethod>]
  [<DynamicData(nameof ELFEmitterTests.Fixtures)>]
  member _.``[ELF] untouched round trip test``(name: string) =
    let bytes = bytesOf name
    let emitted = Image.ofBytes bytes None |> Emitter.emit
    CollectionAssert.AreEqual(bytes, emitted)

  [<TestMethod>]
  member _.``[ELF] rebased round trip test``() =
    let bytes = bytesOf "elf_x64_pie"
    let emitted = Image.ofBytes bytes (Some 0x400000UL) |> Emitter.emit
    CollectionAssert.AreEqual(bytes, emitted)

  /// What keeps the round trip above from passing on an emitter that writes
  /// nothing at all: a field the image alone was told about has to come back
  /// out of the file the emitter builds.
  [<TestMethod>]
  member _.``[ELF] emitted entry point test``() =
    let img = Image.ofBytes (bytesOf "elf_x64_exec") None
    let emitted = Image.setEntryPoint 0x401234UL img |> Emitter.emit
    let reparsed = Image.ofBytes emitted None
    Assert.AreEqual<uint64>(0x401234UL, reparsed.Header.EntryPoint)

  [<TestMethod>]
  member _.``[ELF] emitted section flags test``() =
    let img = Image.ofBytes (bytesOf "elf_x64_exec") None
    let flags = SectionFlags.SHF_ALLOC ||| SectionFlags.SHF_WRITE
    let emitted = Image.setSectionFlags ".text" flags img |> Emitter.emit
    let reparsed = Image.ofBytes emitted None
    let isText (s: SectionEntry) = s.SecHeader.SecName = ".text"
    let text = reparsed.Sections |> Array.find isText
    Assert.AreEqual<SectionFlags>(flags, text.SecHeader.SecFlags)

  [<TestMethod>]
  member _.``[ELF] patch at address test``() =
    let img = Image.ofBytes (bytesOf "elf_x64_exec") None
    let addr = img.Header.EntryPoint
    let nops = [| 0x90uy; 0x90uy |]
    let emitted = Image.patchByAddr addr nops img |> Emitter.emit
    let file = ELFBinFile("patched", emitted, None, None) :> IBinFile
    let read = file.Slice(addr, 2).ToArray()
    CollectionAssert.AreEqual([| 0x90uy; 0x90uy |], read)

  /// An image never writes through to what it was parsed from, so the bytes
  /// handed to it are as good after a patch as they were before.
  [<TestMethod>]
  member _.``[ELF] patch leaves the original alone test``() =
    let bytes = bytesOf "elf_x64_exec"
    let img = Image.ofBytes bytes None
    let addr = img.Header.EntryPoint
    Image.patchByAddr addr [| 0x90uy |] img |> Emitter.emit |> ignore
    CollectionAssert.AreEqual(bytesOf "elf_x64_exec", bytes)

  [<TestMethod>]
  member _.``[ELF] patch beyond the file test``() =
    let img = Image.ofBytes (bytesOf "elf_x64_exec") None
    Assert.ThrowsExactly<InvalidAddrWriteException>(fun () ->
      let past = img.Original.Length - 1
      Image.patchByOffset past [| 0uy; 0uy |] img |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``[ELF] added section test``() =
    let content = [| 1uy; 2uy; 3uy; 4uy; 5uy |]
    let img = Image.ofBytes (bytesOf "elf_x64_exec") None
    let emitted = Image.addSection (specOf ".b2r2" content) img |> Emitter.emit
    CollectionAssert.AreEqual(content, sectionBytesOf emitted ".b2r2")

  /// A section goes on the end of the table, where it leaves every index the
  /// file already used pointing where it did.
  [<TestMethod>]
  member _.``[ELF] added section keeps the rest test``() =
    let bytes = bytesOf "elf_x64_exec"
    let img = Image.ofBytes bytes None
    let spec = specOf ".b2r2" [| 7uy |]
    let emitted = Image.addSection spec img |> Emitter.emit
    let expected = Array.append (sectionNamesOf bytes) [| ".b2r2" |]
    CollectionAssert.AreEqual(expected, sectionNamesOf emitted)
    let before = ELFBinFile("before", bytes, None, None) :> IBinFile
    let after = ELFBinFile("after", emitted, None, None) :> IBinFile
    Assert.AreEqual<uint64 option>(before.EntryPoint, after.EntryPoint)
    let symbolCount (f: IBinFile) = f.SymbolTable.Value.Symbols.Length
    Assert.AreEqual<int>(symbolCount before, symbolCount after)

  [<TestMethod>]
  member _.``[ELF] grown section test``() =
    let img = Image.ofBytes (bytesOf "elf_x64_exec") None
    let grown = Array.create 256 0x41uy
    let emitted = Image.setSectionContent ".comment" grown img |> Emitter.emit
    CollectionAssert.AreEqual(grown, sectionBytesOf emitted ".comment")

  /// Content of the size that was already there needs no room of its own, so
  /// it goes where the section already is and the file stays as long.
  [<TestMethod>]
  member _.``[ELF] same-size section test``() =
    let bytes = bytesOf "elf_x64_exec"
    let img = Image.ofBytes bytes None
    let size = int (sectionOf img ".comment").SecSize
    let content = Array.create size 0x42uy
    let emitted = Image.setSectionContent ".comment" content img |> Emitter.emit
    Assert.AreEqual<int>(bytes.Length, emitted.Length)
    CollectionAssert.AreEqual(content, sectionBytesOf emitted ".comment")

  /// Moving a section a segment maps would break the mapping, so a section
  /// the file loads cannot be given content of another size.
  [<TestMethod>]
  member _.``[ELF] resizing a loaded section test``() =
    let img = Image.ofBytes (bytesOf "elf_x64_exec") None
    Assert.ThrowsExactly<UnsupportedEditException>(fun () ->
      Image.setSectionContent ".text" [| 0uy |] img |> ignore)
    |> ignore

  /// A section the file loads needs a segment, and the one the image takes
  /// for it is an entry of the program header table that was going spare.
  [<TestMethod>]
  member _.``[ELF] added loaded section test``() =
    let content = Array.create 64 0x5auy
    let img = Image.ofBytes (bytesOf "elf_x64_exec") None
    let alloc = SectionFlags.SHF_ALLOC
    let spec = { specOf ".b2r2" content with SpecFlags = alloc }
    let emitted = Image.addSection spec img |> Emitter.emit
    let file = ELFBinFile("loaded", emitted, None, None) :> IBinFile
    let addr = (sectionOf (Image.ofBytes emitted None) ".b2r2").SecAddr
    Assert.AreEqual<bool>(true, file.IsValidAddr addr)
    CollectionAssert.AreEqual(content, file.Slice(addr, 64).ToArray())

  /// The address a segment is mapped at has to agree with the offset it is
  /// mapped from, down to the page the two sit in.
  [<TestMethod>]
  member _.``[ELF] added segment congruence test``() =
    let img = Image.ofBytes (bytesOf "elf_x64_exec") None
    let alloc = SectionFlags.SHF_ALLOC
    let spec = { specOf ".b2r2" (Array.create 64 0uy) with SpecFlags = alloc }
    let emitted = Image.addSection spec img |> Emitter.emit
    let sec = sectionOf (Image.ofBytes emitted None) ".b2r2"
    let phdrs = (Image.ofBytes emitted None).ProgramHeaders
    let covers ph =
      ph.PHType = ProgramHeaderType.PT_LOAD && ph.PHAddr = sec.SecAddr
    let ph = phdrs |> Array.find covers
    Assert.AreEqual<uint64>(ph.PHOffset, sec.SecOffset)
    let page = ph.PHAlignment
    Assert.AreEqual<uint64>(ph.PHAddr % page, ph.PHOffset % page)

  /// An object file has no program header table, so there is no entry in it
  /// to give a segment, and a section it would load cannot be added.
  [<TestMethod>]
  member _.``[ELF] adding a loaded section without a slot test``() =
    let img = Image.ofBytes (bytesOf "elf_x64_obj") None
    let alloc = SectionFlags.SHF_ALLOC
    let spec = { specOf ".b2r2" [| 0uy |] with SpecFlags = alloc }
    Assert.ThrowsExactly<UnsupportedEditException>(fun () ->
      Image.addSection spec img |> ignore)
    |> ignore

  /// Loadable segments go in ascending address order, and what the image adds
  /// is mapped above everything else, so its entry goes after the rest.
  [<TestMethod>]
  member _.``[ELF] added segment comes last test``() =
    let img = Image.ofBytes (bytesOf "elf_x64_exec") None
    let alloc = SectionFlags.SHF_ALLOC
    let spec = { specOf ".b2r2" (Array.create 64 0uy) with SpecFlags = alloc }
    let emitted = Image.addSection spec img |> Emitter.emit
    let phdrs = (Image.ofBytes emitted None).ProgramHeaders
    let isLoad ph = ph.PHType = ProgramHeaderType.PT_LOAD
    let addrs = phdrs |> Array.filter isLoad |> Array.map (fun ph -> ph.PHAddr)
    CollectionAssert.AreEqual(Array.sort addrs, addrs)

  /// Taking the note segment is what a file with nothing else to spare pays,
  /// and the notes it named are still described by their own sections.
  [<TestMethod>]
  member _.``[ELF] added loaded section keeps the build id test``() =
    let bytes = bytesOf "elf_x64_exec"
    let img = Image.ofBytes bytes None
    let alloc = SectionFlags.SHF_ALLOC
    let spec = { specOf ".b2r2" [| 0uy |] with SpecFlags = alloc }
    let emitted = Image.addSection spec img |> Emitter.emit
    let before = ELFBinFile("before", bytes, None, None) :> IBinFile
    let after = ELFBinFile("after", emitted, None, None) :> IBinFile
    Assert.AreNotEqual<int>(0, before.BuildId.Length)
    CollectionAssert.AreEqual(before.BuildId, after.BuildId)

  /// A symbol goes on the end of the table, where it leaves every index a
  /// relocation already uses naming what it named. Only one the linker calls
  /// global can go there, the local ones all coming first.
  [<TestMethod>]
  member _.``[ELF] added symbol test``() =
    let bytes = bytesOf "elf_x64_exec"
    let img = Image.ofBytes bytes None
    let addr = img.Header.EntryPoint
    let emitted = Image.addSymbol (symbolSpecOf "b2r2_fn" addr) img
                  |> Emitter.emit
    let file = ELFBinFile("named", emitted, None, None) :> IBinFile
    let resolved = file.NameResolver.Value.TryResolveName addr
    Assert.AreEqual<Result<string, ErrorCase>>(Ok "b2r2_fn", resolved)

  [<TestMethod>]
  member _.``[ELF] added symbol keeps the rest test``() =
    let bytes = bytesOf "elf_x64_exec"
    let img = Image.ofBytes bytes None
    let spec = symbolSpecOf "b2r2_fn" img.Header.EntryPoint
    let emitted = Image.addSymbol spec img |> Emitter.emit
    let before = ELFBinFile("before", bytes, None, None) :> IBinFile
    let after = ELFBinFile("after", emitted, None, None) :> IBinFile
    let symbolCount (f: IBinFile) = f.SymbolTable.Value.Symbols.Length
    Assert.AreEqual<int>(symbolCount before + 1, symbolCount after)

  [<TestMethod>]
  member _.``[ELF] adding a local symbol test``() =
    let img = Image.ofBytes (bytesOf "elf_x64_exec") None
    let spec =
      { symbolSpecOf "b2r2_fn" 0x401050UL with
          SymSpecBind = SymbolBind.STB_LOCAL }
    Assert.ThrowsExactly<UnsupportedEditException>(fun () ->
      Image.addSymbol spec img |> ignore)
    |> ignore

  /// A file whose symbol table was stripped has nowhere to put a symbol.
  [<TestMethod>]
  member _.``[ELF] adding a symbol without a table test``() =
    let img = Image.ofBytes (bytesOf "elf_x64_stripped") None
    let spec = symbolSpecOf "b2r2_fn" 0x401050UL
    Assert.ThrowsExactly<UnsupportedEditException>(fun () ->
      Image.addSymbol spec img |> ignore)
    |> ignore

  /// One table of extended section indices has an entry per symbol, so a
  /// symbol cannot be added to a file carrying one until that grows too.
  [<TestMethod>]
  member _.``[ELF] adding a symbol beside an index table test``() =
    let img = Image.ofBytes (bytesOf "elf_x64_shndx") None
    let spec = symbolSpecOf "b2r2_fn" 0UL
    Assert.ThrowsExactly<UnsupportedEditException>(fun () ->
      Image.addSymbol spec img |> ignore)
    |> ignore

  /// A section put in the middle moves every index that named a section past
  /// it, so what the section headers link to has to be unchanged by name.
  [<TestMethod>]
  member _.``[ELF] inserted section links test``() =
    let img = Image.ofBytes (bytesOf "elf_x64_exec") None
    let emitted = Image.insertSection (specOf ".b2r2" [| 9uy |]) 2 img
                  |> Emitter.emit
    let after = Image.ofBytes emitted None
    let nameAt i = after.Sections[i].SecHeader.SecName
    let linked name = nameAt (int (sectionOf after name).SecLink)
    Assert.AreEqual<string>(".b2r2", nameAt 2)
    Assert.AreEqual<string>(".strtab", linked ".symtab")
    Assert.AreEqual<string>(".dynstr", linked ".dynsym")
    Assert.AreEqual<string>(".dynsym", linked ".rela.plt")

  /// sh_info names a section only where the section says it does. A
  /// relocation section names what it relocates; a symbol table keeps the
  /// first non-local symbol there, which no renumbering may touch.
  [<TestMethod>]
  member _.``[ELF] inserted section info test``() =
    let bytes = bytesOf "elf_x64_exec"
    let img = Image.ofBytes bytes None
    let before = Image.ofBytes bytes None
    let emitted = Image.insertSection (specOf ".b2r2" [| 9uy |]) 2 img
                  |> Emitter.emit
    let after = Image.ofBytes emitted None
    let nameAt i = after.Sections[i].SecHeader.SecName
    let relocated = nameAt (int (sectionOf after ".rela.plt").SecInfo)
    Assert.AreEqual<string>(".got.plt", relocated)
    let symtabInfo img = (sectionOf img ".symtab").SecInfo
    Assert.AreEqual<uint32>(symtabInfo before, symtabInfo after)

  /// Every symbol keeps the section that defines it, which is what its
  /// st_shndx has to be moved along to go on naming.
  [<TestMethod>]
  member _.``[ELF] inserted section symbols test``() =
    let bytes = bytesOf "elf_x64_exec"
    let img = Image.ofBytes bytes None
    let emitted = Image.insertSection (specOf ".b2r2" [| 9uy |]) 2 img
                  |> Emitter.emit
    let parentsOf b =
      ELFBinFile("f", b, None, None).Symbols.StaticSymbols
      |> Array.map (fun s -> s.SymName, s.ParentSection |> Option.map _.SecName)
    CollectionAssert.AreEqual(parentsOf bytes, parentsOf emitted)

  /// The initial section is what a file using the extended numbering keeps
  /// its counts in, so nothing can go before it.
  [<TestMethod>]
  member _.``[ELF] inserting before the initial section test``() =
    let img = Image.ofBytes (bytesOf "elf_x64_exec") None
    Assert.ThrowsExactly<UnsupportedEditException>(fun () ->
      Image.insertSection (specOf ".b2r2" [| 9uy |]) 0 img |> ignore)
    |> ignore

  /// A symbol too far up the table to say so in st_shndx says it through a
  /// table of extended indices instead, and that is one more place a section
  /// index has to be moved along.
  [<TestMethod>]
  member _.``[ELF] inserted section extended index test``() =
    let bytes = bytesOf "elf_x64_shndx"
    let img = Image.ofBytes bytes None
    let emitted = Image.insertSection (specOf ".b2r2" [| 9uy |]) 1 img
                  |> Emitter.emit
    let parentsOf b =
      ELFBinFile("f", b, None, None).Symbols.StaticSymbols
      |> Array.map (fun s -> s.SymName, s.ParentSection |> Option.map _.SecName)
    CollectionAssert.AreEqual(parentsOf bytes, parentsOf emitted)
    let after = Image.ofBytes emitted None
    Assert.AreEqual<int>(img.Header.SHdrNum + 1, after.Header.SHdrNum)

  /// The writer is what an ELF file is edited through from outside this
  /// assembly, so what it needs has to be public. Nothing else here can say
  /// so: the test assembly sees what is internal as well.
  [<TestMethod>]
  member _.``[ELF] public writing surface test``() =
    let isPublic (t: System.Type) = t.IsPublic
    Assert.AreEqual<bool>(true, isPublic typeof<IBinWriter>)
    Assert.AreEqual<bool>(true, isPublic typeof<ELFWriter>)
    Assert.AreEqual<bool>(true, isPublic typeof<SectionSpec>)
    Assert.AreEqual<bool>(true, isPublic typeof<SymbolSpec>)
    Assert.AreEqual<bool>(true, isPublic typeof<SectionType>)
    Assert.AreEqual<bool>(true, isPublic typeof<SectionFlags>)
    Assert.AreEqual<bool>(true, isPublic typeof<SymbolType>)
    Assert.AreEqual<bool>(true, isPublic typeof<SymbolBind>)
    let members = typeof<ELFWriter>.GetMethods() |> Array.filter _.IsPublic
    let named n = members |> Array.exists (fun m -> m.Name = n)
    let expected =
      [ "Emit"
        "PatchByAddr"
        "PatchByOffset"
        "SetEntryPoint"
        "SetSectionFlags"
        "SetSectionContent"
        "AddSection"
        "InsertSection"
        "AddSymbol" ]
    for name in expected do
      Assert.AreEqual<bool>(true, named name, name)

  /// The writer starts as the file it is given, so one nothing has been asked
  /// of emits that file back.
  [<TestMethod>]
  member _.``[ELF] writer round trip test``() =
    let bytes = bytesOf "elf_x64_exec"
    let writer = ELFWriter(ELFBinFile("f", bytes, None, None))
    CollectionAssert.AreEqual(bytes, writer.Emit())

  /// The same trip for a file loaded at a base of its own, whose addresses
  /// the writer has to take that base back off before writing them down.
  [<TestMethod>]
  member _.``[ELF] writer round trip when rebased test``() =
    let bytes = bytesOf "elf_x64_pie"
    let file = ELFBinFile("f", bytes, Some 0x400000UL, None)
    CollectionAssert.AreEqual(bytes, ELFWriter(file).Emit())

  /// What the writer is for: an edit asked of it through the public surface
  /// reaches the bytes it emits.
  [<TestMethod>]
  member _.``[ELF] writer edits test``() =
    let bytes = bytesOf "elf_x64_exec"
    let file = ELFBinFile("f", bytes, None, None)
    let writer = ELFWriter(file)
    let content = [| 1uy; 2uy; 3uy |]
    writer.AddSection(specOf ".b2r2" content)
    writer.SetEntryPoint 0x401234UL
    let emitted = writer.Emit()
    CollectionAssert.AreEqual(content, sectionBytesOf emitted ".b2r2")
    let reparsed = ELFBinFile("f", emitted, None, None) :> IBinFile
    Assert.AreEqual<uint64 option>(Some 0x401234UL, reparsed.EntryPoint)

  /// What any format can be asked for reaches the bytes through the interface
  /// alone, so that a tool patching a binary need not know which format it is.
  [<TestMethod>]
  member _.``[ELF] writer through the interface test``() =
    let bytes = bytesOf "elf_x64_exec"
    let file = ELFBinFile("f", bytes, None, None)
    let writer = ELFWriter file :> IBinWriter
    let addr = (file :> IBinFile).EntryPoint.Value
    writer.PatchByAddr(addr, [| 0x90uy; 0x90uy |])
    writer.PatchByOffset(0x18, [| 0uy |])
    let emitted = writer.Emit()
    let reparsed = ELFBinFile("f", emitted, None, None) :> IBinFile
    let read = reparsed.Slice(addr, 2).ToArray()
    CollectionAssert.AreEqual([| 0x90uy; 0x90uy |], read)
    Assert.AreEqual<byte>(0uy, emitted[0x18])

  /// A writer nothing has been asked of hands back the file it started from,
  /// which is the contract the interface states.
  [<TestMethod>]
  member _.``[ELF] writer through the interface round trip test``() =
    let bytes = bytesOf "elf_x64_exec"
    let writer = ELFWriter(ELFBinFile("f", bytes, None, None)) :> IBinWriter
    CollectionAssert.AreEqual(bytes, writer.Emit())
