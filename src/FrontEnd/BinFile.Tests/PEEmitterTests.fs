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
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.PE
open Microsoft.VisualStudio.TestTools.UnitTesting
open type FileFormat

[<TestClass>]
type PEEmitterTests() =
  static let reader = BinReader.Init Endian.Little

  static let bytesOf name = ZIPReader.readPEFixture name

  static let imageOf name = Image.ofBytes (bytesOf name) None

  static let fileOf (bytes: byte[]) =
    PEBinFile("f", bytes, None, [||]) :> IBinFile

  static let named name (entry: SectionEntry) = entry.SecHeader.Name = name

  static let sectionOf (img: Image) name =
    (img.Sections |> Array.find (named name)).SecHeader

  /// Returns the bytes the emitted file holds for the named section, found
  /// by parsing that file rather than by trusting where it was put.
  static let sectionBytesOf (bytes: byte[]) name =
    let sec = sectionOf (Image.ofBytes bytes None) name
    let start = sec.PointerToRawData
    bytes[start..start + sec.SizeOfRawData - 1]

  static let sectionNamesOf (bytes: byte[]) =
    (Image.ofBytes bytes None).Sections
    |> Array.map (fun entry -> entry.SecHeader.Name)

  /// Returns a section the tests ask an image to add, holding the given
  /// bytes under a name of its own.
  static let specOf name content =
    { SpecName = name
      SpecCharacteristics =
        SectionCharacteristics.ContainsInitializedData
        ||| SectionCharacteristics.MemRead
      SpecContent = content }

  /// Appends bytes no structure of the file names, which is what an overlay
  /// is. An installer keeps its payload there and a signature sits there
  /// too, and neither is anything the emitter models: what reproduces them
  /// is the original it builds on. The pattern is one it could not hit by
  /// accident.
  static let withOverlay size (bytes: byte[]) =
    Array.append bytes (Array.init size (fun i -> byte (i * 7 + 1)))

  /// Returns the bytes with the checksum field blanked, so that two files
  /// can be compared over everything but the field one of them had worked
  /// out and the other never did.
  static let withoutChecksum (bytes: byte[]) =
    let copy = Array.copy bytes
    Array.fill copy ((Image.ofBytes bytes None).OptionalHeaderOffset + 64) 4 0uy
    copy

  /// Every PE fixture that is an image, one per row, so that whatever one is
  /// added next is round-tripped without anything here naming it. An object
  /// file is not one: it carries no optional header, and so names neither a
  /// base to place anything against nor an alignment to place it on.
  static member Fixtures =
    ZIPReader.listFixtureNames PEBinary
    |> Array.filter (fun name ->
      (Header.parse (ZIPReader.readPEFixture name) reader).IsCoffOnly |> not)
    |> Array.map (fun name -> [| box name |])

  [<TestMethod>]
  [<DynamicData(nameof PEEmitterTests.Fixtures)>]
  member _.``[PE] untouched round trip test``(name: string) =
    let bytes = bytesOf name
    CollectionAssert.AreEqual(bytes, Image.ofBytes bytes None |> Emitter.emit)

  /// The same trip for a file read at a base of its own. Every address a PE
  /// holds is relative to the image base it names, so the base a reader was
  /// given moves none of them.
  [<TestMethod>]
  member _.``[PE] rebased round trip test``() =
    let bytes = bytesOf "pe_x64"
    let emitted = Image.ofBytes bytes (Some 0x400000UL) |> Emitter.emit
    CollectionAssert.AreEqual(bytes, emitted)

  /// An object file names no base and no alignment, so there is no laying
  /// one out and no writing one back.
  [<TestMethod>]
  member _.``[PE] an object file cannot be written test``() =
    let bytes = bytesOf "pe_x64_obj"
    Assert.ThrowsExactly<UnsupportedEditException>(fun () ->
      Image.ofBytes bytes None |> ignore)
    |> ignore

  /// What keeps the round trip above from passing on an emitter that writes
  /// nothing at all: a field the image alone was told about has to come back
  /// out of the file the emitter builds.
  [<TestMethod>]
  member _.``[PE] emitted entry point test``() =
    let emitted =
      imageOf "pe_x64" |> Image.setEntryPoint 0x140001300UL |> Emitter.emit
    let entry = (fileOf emitted).EntryPoint
    Assert.AreEqual<uint64 option>(Some 0x140001300UL, entry)

  [<TestMethod>]
  member _.``[PE] emitted section characteristics test``() =
    let chars =
      SectionCharacteristics.MemRead ||| SectionCharacteristics.MemWrite
    let emitted =
      imageOf "pe_x64"
      |> Image.setSectionCharacteristics ".text" chars
      |> Emitter.emit
    let sec = sectionOf (Image.ofBytes emitted None) ".text"
    Assert.AreEqual<SectionCharacteristics>(chars, sec.SectionCharacteristics)

  [<TestMethod>]
  member _.``[PE] naming a section the file has not test``() =
    Assert.ThrowsExactly<SectionNotFoundException>(fun () ->
      imageOf "pe_x64" |> Image.setSectionContent ".nope" [||] |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``[PE] patch at address test``() =
    let bytes = bytesOf "pe_x64"
    let addr = (fileOf bytes).EntryPoint.Value
    let nops = [| 0x90uy; 0x90uy |]
    let emitted =
      Image.ofBytes bytes None |> Image.patchByAddr addr nops |> Emitter.emit
    CollectionAssert.AreEqual(nops, (fileOf emitted).Slice(addr, 2).ToArray())

  [<TestMethod>]
  member _.``[PE] patch leaves the original alone test``() =
    let bytes = bytesOf "pe_x64"
    let addr = (fileOf bytes).EntryPoint.Value
    Image.ofBytes bytes None
    |> Image.patchByAddr addr [| 0x90uy |]
    |> Emitter.emit
    |> ignore
    CollectionAssert.AreEqual(bytesOf "pe_x64", bytes)

  [<TestMethod>]
  member _.``[PE] patch beyond the file test``() =
    let img = imageOf "pe_x64"
    Assert.ThrowsExactly<InvalidAddrWriteException>(fun () ->
      Image.patchByOffset (img.KeptLength - 1) [| 0uy; 0uy |] img |> ignore)
    |> ignore

  /// An address the image does not load is no address to write to, and one
  /// below the base it was read at is not even an address of this image.
  [<TestMethod>]
  member _.``[PE] patch at an unmapped address test``() =
    let img = imageOf "pe_x64"
    Assert.ThrowsExactly<InvalidAddrWriteException>(fun () ->
      Image.patchByAddr 0UL [| 0uy |] img |> ignore)
    |> ignore

  /// A run reaching past the bytes a section holds would land in the next
  /// section, so it is no run this file has room for.
  [<TestMethod>]
  member _.``[PE] patch past the end of a section test``() =
    let img = imageOf "pe_x64"
    let sec = sectionOf img ".text"
    let rva = sec.VirtualAddress + sec.SizeOfRawData - 1
    let last = img.BaseAddress + uint64 rva
    Assert.ThrowsExactly<InvalidAddrWriteException>(fun () ->
      Image.patchByAddr last [| 0uy; 0uy |] img |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``[PE] same-size section content test``() =
    let img = imageOf "pe_x64"
    let content = Array.create (sectionOf img ".text").SizeOfRawData 0x90uy
    let emitted = Image.setSectionContent ".text" content img |> Emitter.emit
    CollectionAssert.AreEqual(content, sectionBytesOf emitted ".text")

  /// Every section sits at an address the section alignment fixes, so one
  /// cannot grow without moving every section above it.
  [<TestMethod>]
  member _.``[PE] resizing a section test``() =
    Assert.ThrowsExactly<UnsupportedEditException>(fun () ->
      imageOf "pe_x64" |> Image.setSectionContent ".text" [| 0uy |] |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``[PE] added section test``() =
    let content = [| 1uy; 2uy; 3uy; 4uy; 5uy |]
    let emitted =
      imageOf "pe_x64" |> Image.addSection (specOf ".b2r2" content)
      |> Emitter.emit
    let held = sectionBytesOf emitted ".b2r2"
    CollectionAssert.AreEqual(content, held[..content.Length - 1])

  /// A section goes after the ones the file has, where it leaves every index
  /// the file already used naming what it named.
  [<TestMethod>]
  member _.``[PE] added section keeps the rest test``() =
    let emitted =
      imageOf "pe_x64" |> Image.addSection (specOf ".b2r2" [| 1uy |])
      |> Emitter.emit
    let before = sectionNamesOf (bytesOf "pe_x64")
    CollectionAssert.AreEqual(Array.append before [| ".b2r2" |],
                              sectionNamesOf emitted)

  /// A section the image adds is loaded above everything the file loads, so
  /// the image reaches further than it did and is readable that far.
  [<TestMethod>]
  member _.``[PE] added section is loaded test``() =
    let content = Array.create 64 0x5auy
    let before = imageOf "pe_x64"
    let emitted =
      Image.addSection (specOf ".b2r2" content) before |> Emitter.emit
    let after = Image.ofBytes emitted None
    let reach (img: Image) = img.OptionalHeader.SizeOfImage
    Assert.AreEqual<bool>(true, reach after > reach before)
    let file = fileOf emitted
    let rva = (sectionOf after ".b2r2").VirtualAddress
    let addr = file.BaseAddress + uint64 rva
    CollectionAssert.AreEqual(content, file.Slice(addr, 64).ToArray())

  /// The headers of a file leave room for only so many section headers, and
  /// one more than that has nowhere to go.
  [<TestMethod>]
  member _.``[PE] adding sections until the room runs out test``() =
    let img = imageOf "pe_x64"
    let spare = Image.headerSlots img - img.Sections.Length
    Assert.AreEqual<bool>(true, spare > 0)
    let rec fill n img =
      if n = 0 then img
      else fill (n - 1) (Image.addSection (specOf $".s{n}" [| 1uy |]) img)
    let filled = fill spare img
    Assert.ThrowsExactly<UnsupportedEditException>(fun () ->
      Image.addSection (specOf ".over" [| 1uy |]) filled |> ignore)
    |> ignore

  /// A section header gives a name eight bytes, and an image has no string
  /// table to keep the rest of a longer one in.
  [<TestMethod>]
  member _.``[PE] a section name too long test``() =
    Assert.ThrowsExactly<UnsupportedEditException>(fun () ->
      imageOf "pe_x64"
      |> Image.addSection (specOf ".toolongname" [| 1uy |])
      |> ignore)
    |> ignore

  /// Bytes the file ends with that no section holds are nothing the emitter
  /// models, so what reproduces them is the original it builds on.
  [<TestMethod>]
  member _.``[PE] round trip with an overlay test``() =
    let bytes = bytesOf "pe_x64" |> withOverlay 1024
    CollectionAssert.AreEqual(bytes, Image.ofBytes bytes None |> Emitter.emit)

  /// A section the image adds takes room at the end of the file, and an
  /// overlay is what is already there.
  [<TestMethod>]
  member _.``[PE] added section keeps the overlay test``() =
    let original = bytesOf "pe_x64"
    let bytes = withOverlay 1024 original
    let emitted =
      Image.ofBytes bytes None |> Image.addSection (specOf ".b2r2" [| 1uy |])
      |> Emitter.emit
    let kept = emitted[original.Length..bytes.Length - 1]
    CollectionAssert.AreEqual(bytes[original.Length..], kept)

  /// Taking the certificate off leaves the file it was made of: the bytes it
  /// named go and the directory naming them is emptied.
  [<TestMethod>]
  member _.``[PE] removed certificate test``() =
    let emitted =
      imageOf "pe_x64_signed" |> Image.removeCertificate |> Emitter.emit
    let dir =
      (Image.ofBytes emitted None).OptionalHeader.Directory
        DirectoryKind.CertificateTable
    Assert.AreEqual<int>(0, dir.RVA)
    Assert.AreEqual<int>(0, dir.Size)
    CollectionAssert.AreEqual(withoutChecksum (bytesOf "pe_x64"),
                              withoutChecksum emitted)

  [<TestMethod>]
  member _.``[PE] removing a certificate that is not there test``() =
    Assert.ThrowsExactly<UnsupportedEditException>(fun () ->
      imageOf "pe_x64" |> Image.removeCertificate |> ignore)
    |> ignore

  /// The checksum the emitter works out is the one a reader checking the
  /// file works out. Signing is what last put a right one in a fixture here,
  /// so the signed one is what says whether this is right.
  [<TestMethod>]
  member _.``[PE] updated checksum test``() =
    let bytes = bytesOf "pe_x64_signed"
    let emitted =
      Image.ofBytes bytes None |> Image.updateChecksum |> Emitter.emit
    CollectionAssert.AreEqual(bytes, emitted)

  /// A file whose checksum was never right keeps it, which is the only way
  /// an image nothing has touched can emit such a file back.
  [<TestMethod>]
  member _.``[PE] checksum left alone test``() =
    let bytes = bytesOf "pe_x64"
    let updated =
      Image.ofBytes bytes None |> Image.updateChecksum |> Emitter.emit
    CollectionAssert.AreNotEqual(bytes, updated)

  /// What the emitter lays down is a PE that the BCL reader reads as well,
  /// which is a check on it owing nothing to the parser it was written
  /// against.
  [<TestMethod>]
  member _.``[PE] an emitted file reads as a PE elsewhere test``() =
    let content = [| 1uy; 2uy |]
    let emitted =
      imageOf "pe_x64" |> Image.addSection (specOf ".b2r2" content)
      |> Emitter.emit
    use stream = new System.IO.MemoryStream(emitted)
    use reader = new System.Reflection.PortableExecutable.PEReader(stream)
    let secs = reader.PEHeaders.SectionHeaders
    Assert.AreEqual<int>(6, secs.Length)
    let added = secs |> Seq.find (fun sec -> sec.Name = ".b2r2")
    Assert.AreEqual<int>(content.Length, added.VirtualSize)
    let top = added.VirtualAddress + added.VirtualSize
    Assert.AreEqual<bool>(true, reader.PEHeaders.PEHeader.SizeOfImage >= top)

  /// The writer is what a PE file is edited through from outside this
  /// assembly, so what it needs has to be public. Nothing else here can say
  /// so: the test assembly sees what is internal as well.
  [<TestMethod>]
  member _.``[PE] public writing surface test``() =
    let isPublic (t: System.Type) = t.IsPublic
    Assert.AreEqual<bool>(true, isPublic typeof<IBinWriter>)
    Assert.AreEqual<bool>(true, isPublic typeof<PEWriter>)
    Assert.AreEqual<bool>(true, isPublic typeof<SectionSpec>)
    Assert.AreEqual<bool>(true, isPublic typeof<SectionCharacteristics>)
    let members = typeof<PEWriter>.GetMethods() |> Array.filter _.IsPublic
    let named n = members |> Array.exists (fun m -> m.Name = n)
    let expected =
      [ "Emit"
        "PatchByAddr"
        "PatchByOffset"
        "SetEntryPoint"
        "SetSectionCharacteristics"
        "SetSectionContent"
        "AddSection"
        "RemoveCertificate"
        "UpdateChecksum" ]
    for name in expected do
      Assert.AreEqual<bool>(true, named name, name)

  /// The writer starts as the file it is given, so one nothing has been
  /// asked of emits that file back.
  [<TestMethod>]
  member _.``[PE] writer round trip test``() =
    let bytes = bytesOf "pe_x64"
    let writer = PEWriter(PEBinFile("f", bytes, None, [||]))
    CollectionAssert.AreEqual(bytes, writer.Emit())

  [<TestMethod>]
  member _.``[PE] writer rejects an object file test``() =
    let file = PEBinFile("f", bytesOf "pe_x64_obj", None, [||])
    Assert.ThrowsExactly<UnsupportedEditException>(fun () ->
      PEWriter file |> ignore)
    |> ignore

  /// What the writer is for: an edit asked of it through the public surface
  /// reaches the bytes it emits.
  [<TestMethod>]
  member _.``[PE] writer edits test``() =
    let writer = PEWriter(PEBinFile("f", bytesOf "pe_x64", None, [||]))
    let content = [| 1uy; 2uy; 3uy |]
    writer.AddSection(specOf ".b2r2" content)
    writer.SetEntryPoint 0x140001300UL
    let emitted = writer.Emit()
    let held = sectionBytesOf emitted ".b2r2"
    CollectionAssert.AreEqual(content, held[..content.Length - 1])
    let entry = (fileOf emitted).EntryPoint
    Assert.AreEqual<uint64 option>(Some 0x140001300UL, entry)

  /// Emitting changes nothing of the image, so a writer hands back the same
  /// bytes however often it is asked.
  [<TestMethod>]
  member _.``[PE] emitting twice test``() =
    let writer = PEWriter(PEBinFile("f", bytesOf "pe_x64", None, [||]))
    writer.SetEntryPoint 0x140001300UL
    CollectionAssert.AreEqual(writer.Emit(), writer.Emit())

  /// Taking the signature off a signed file and working the checksum out
  /// again is the whole of what editing one soundly takes.
  [<TestMethod>]
  member _.``[PE] writer unsigns a file test``() =
    let writer = PEWriter(PEBinFile("f", bytesOf "pe_x64_signed", None, [||]))
    writer.RemoveCertificate()
    writer.UpdateChecksum()
    let emitted = writer.Emit()
    Assert.AreEqual<int>((bytesOf "pe_x64").Length, emitted.Length)
    let again =
      Image.ofBytes emitted None |> Image.updateChecksum |> Emitter.emit
    CollectionAssert.AreEqual(emitted, again)

  /// What any format can be asked for reaches the bytes through the
  /// interface alone, so that a tool patching a binary need not know which
  /// format it is.
  [<TestMethod>]
  member _.``[PE] writer through the interface test``() =
    let bytes = bytesOf "pe_x64"
    let file = PEBinFile("f", bytes, None, [||])
    let writer = PEWriter file :> IBinWriter
    let addr = (file :> IBinFile).EntryPoint.Value
    writer.PatchByAddr(addr, [| 0x90uy; 0x90uy |])
    writer.PatchByOffset(0x400, [| 0uy |])
    let emitted = writer.Emit()
    let read = (fileOf emitted).Slice(addr, 2).ToArray()
    CollectionAssert.AreEqual([| 0x90uy; 0x90uy |], read)
    Assert.AreEqual<byte>(0uy, emitted[0x400])
