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

namespace B2R2.FrontEnd.BinFile.Mach

open System
open B2R2.FrontEnd.BinFile.FileHelper
open B2R2.FrontEnd.BinFile.ByteWriter

/// Writes an editable image back out as the bytes of a Mach-O file. Every
/// field goes back where the parser read it from, so that emitting an image
/// nothing has touched hands back the file it came from, byte for byte.
[<RequireQualifiedAccess>]
module internal Emitter =
  /// Writes every header field the image models. The magic and the CPU it
  /// names are not among them: they say which file this is rather than
  /// anything an edit can reach, so they are left as the original has them.
  let private writeHeader (span: Span<byte>) (img: Image) layout =
    let endian, at = img.Endian, int img.ToolBox.HeaderOffset
    writeUInt32 span endian (at + 12) (uint32 (int img.Header.FileType))
    writeUInt32 span endian (at + 16) layout.NumCmds
    writeUInt32 span endian (at + 20) layout.SizeOfCmds
    writeUInt32 span endian (at + 24) (uint32 (int img.Header.Flags))

  /// Writes the numbers of a segment command. Its name is left alone, the
  /// sixteen bytes holding it being the file's own to pad as it likes.
  let private writeSegCmd (img: Image) (dst: Span<byte>) seg =
    let endian, cls = img.Endian, img.Class
    writeUIntByWordSize dst endian cls 24 (seg.VMAddr - img.BaseAddress)
    writeUIntByWordSizeAndOffset dst endian cls 28 32 seg.VMSize
    writeUIntByWordSizeAndOffset dst endian cls 32 40 seg.FileOff
    writeUIntByWordSizeAndOffset dst endian cls 36 48 seg.FileSize
    writeUInt32 dst endian (selectByWordSize cls 40 56) (uint32 seg.MaxProt)
    writeUInt32 dst endian (selectByWordSize cls 44 60) (uint32 seg.InitProt)
    writeUInt32 dst endian (selectByWordSize cls 48 64) seg.NumSecs
    writeUInt32 dst endian (selectByWordSize cls 52 68) seg.SegFlag

  /// Writes the four fields of a symbol table command, which name where the
  /// symbols and the strings they go under sit.
  let private writeSymTabCmd (img: Image) (dst: Span<byte>) cmd =
    let endian = img.Endian
    writeUInt32 dst endian 8 (uint32 cmd.SymOff)
    writeUInt32 dst endian 12 cmd.NumOfSym
    writeUInt32 dst endian 16 (uint32 cmd.StrOff)
    writeUInt32 dst endian 20 cmd.StrSize

  /// Writes the eighteen fields of a dynamic symbol table command, which cut
  /// the symbol table into its three groups and name the tables the dynamic
  /// linker reads beside it.
  let private writeDySymTabCmd (img: Image) (dst: Span<byte>) cmd =
    let endian = img.Endian
    writeUInt32 dst endian 8 cmd.IdxLocalSym
    writeUInt32 dst endian 12 cmd.NumLocalSym
    writeUInt32 dst endian 16 cmd.IdxExtSym
    writeUInt32 dst endian 20 cmd.NumExtSym
    writeUInt32 dst endian 24 cmd.IdxUndefSym
    writeUInt32 dst endian 28 cmd.NumUndefSym
    writeUInt32 dst endian 32 cmd.TOCOffset
    writeUInt32 dst endian 36 cmd.NumTOCContents
    writeUInt32 dst endian 40 cmd.ModTabOff
    writeUInt32 dst endian 44 cmd.NumModTab
    writeUInt32 dst endian 48 cmd.ExtRefSymOff
    writeUInt32 dst endian 52 cmd.NumExtRefSym
    writeUInt32 dst endian 56 cmd.IndirectSymOff
    writeUInt32 dst endian 60 cmd.NumIndirectSym
    writeUInt32 dst endian 64 cmd.ExtRelOff
    writeUInt32 dst endian 68 cmd.NumExtRel
    writeUInt32 dst endian 72 cmd.LocalRelOff
    writeUInt32 dst endian 76 cmd.NumLocalRel

  /// Writes the five offset and size pairs of a dyld information command.
  let private writeDyLdInfoCmd (img: Image) (dst: Span<byte>) cmd =
    let endian = img.Endian
    writeUInt32 dst endian 8 (uint32 cmd.RebaseOff)
    writeUInt32 dst endian 12 cmd.RebaseSize
    writeUInt32 dst endian 16 (uint32 cmd.BindOff)
    writeUInt32 dst endian 20 cmd.BindSize
    writeUInt32 dst endian 24 (uint32 cmd.WeakBindOff)
    writeUInt32 dst endian 28 cmd.WeakBindSize
    writeUInt32 dst endian 32 (uint32 cmd.LazyBindOff)
    writeUInt32 dst endian 36 cmd.LazyBindSize
    writeUInt32 dst endian 40 (uint32 cmd.ExportOff)
    writeUInt32 dst endian 44 cmd.ExportSize

  /// Writes the offset and the size of the run of __LINKEDIT a command names,
  /// the pair of which every such command keeps in the same two fields.
  let private writeBlobCmd (img: Image) (dst: Span<byte>) offset size =
    writeUInt32 dst img.Endian 8 (uint32 (offset: int))
    writeUInt32 dst img.Endian 12 (size: uint32)

  /// Writes the two fields of a main command, both of which are as wide as a
  /// 64-bit word whatever the file is.
  let private writeMainCmd (img: Image) (dst: Span<byte>) cmd =
    writeUInt64 dst img.Endian 8 cmd.EntryOff
    writeUInt64 dst img.Endian 16 cmd.StackSize

  /// Writes the program counter of a thread state back where the parser read
  /// it from, which takes walking the states again to find. It is an unslid
  /// address, as the parser leaves it.
  let private writeThreadCmd (img: Image) (dst: Span<byte>) src size pc =
    match LoadCommands.tryFindThreadPCOffset img.ToolBox src size with
    | Some at ->
      writeUIntByWordSize dst img.Endian img.Class at pc
    | None ->
      ()

  /// Writes the address of the initialization routine a library names.
  let private writeRoutinesCmd (img: Image) (dst: Span<byte>) addr =
    let unslid = addr - img.BaseAddress
    writeUIntByWordSize dst img.Endian img.Class 8 unslid

  /// Writes the three fields of an encryption information command, which sit
  /// at the same offsets in both of its forms.
  let private writeEncryptionCmd (img: Image) (dst: Span<byte>) cmd =
    let endian = img.Endian
    writeUInt32 dst endian 8 (uint32 cmd.CryptOffset)
    writeUInt32 dst endian 12 cmd.CryptSize
    writeUInt32 dst endian 16 cmd.CryptId

  /// Writes one load command into the span covering its own entry. Only the
  /// numbers a command carries go back; the strings and the raw states it
  /// holds are left as the original file has them, nothing here being able to
  /// give them another length.
  let private writeCommand img dst src cmd =
    match cmd with
    | Segment(_, _, seg) ->
      writeSegCmd img dst seg
    | SymTab(_, _, c) ->
      writeSymTabCmd img dst c
    | DySymTab(_, _, c) ->
      writeDySymTabCmd img dst c
    | DyLdInfo(_, _, c) ->
      writeDyLdInfoCmd img dst c
    | FuncStarts(_, _, c) ->
      writeBlobCmd img dst c.DataOffset c.DataSize
    | DataInCode(_, _, c) ->
      writeBlobCmd img dst c.TableOffset c.TableSize
    | ChainedFixups(_, _, c) ->
      writeBlobCmd img dst c.FixupsDataOffset c.FixupsDataSize
    | ExportsTrie(_, _, c) ->
      writeBlobCmd img dst c.TrieOffset c.TrieSize
    | CodeSign(_, _, c) ->
      writeBlobCmd img dst c.BlobOffset c.BlobSize
    | Main(_, _, c) ->
      writeMainCmd img dst c
    | Thread(_, size, Some pc) ->
      writeThreadCmd img dst src (int size) pc
    | Routines(_, _, Some addr) ->
      writeRoutinesCmd img dst addr
    | EncryptionInfo(_, _, c) ->
      writeEncryptionCmd img dst c
    | _ ->
      ()

  /// Writes a name into the sixteen bytes a segment or a section keeps it
  /// in, which is as much of it as fits and nothing after it. The room it
  /// goes in has been cleared, so a name short of sixteen bytes ends where
  /// it ends.
  let private writeName (dst: Span<byte>) offset (name: string) =
    let bytes = Text.Encoding.Latin1.GetBytes name
    for i = 0 to min bytes.Length 16 - 1 do
      dst[offset + i] <- bytes[i]

  /// Writes all of a command the image added, which the original file has no
  /// bytes for: what it is, how long it is, and the name it goes under. The
  /// numbers it carries are written after, as any command's are.
  let private writeAddedCmd (img: Image) (dst: Span<byte>) cmd =
    dst.Clear()
    match cmd with
    | Segment(cmdType, size, seg) ->
      writeUInt32 dst img.Endian 0 (uint32 (int cmdType))
      writeUInt32 dst img.Endian 4 size
      writeName dst 8 seg.SegCmdName
    | _ ->
      ()

  /// Returns the __LINKEDIT segment as long as the runs it holds have made
  /// it, rounded up in memory to the page the loader maps.
  let private grownLinkEdit (layout: Layout) seg =
    if layout.LinkEditGrowth = 0L then
      seg
    else
      let fileSize = uint64 (int64 seg.FileSize + layout.LinkEditGrowth)
      let page = layout.PageSize
      { seg with
          FileSize = fileSize
          VMSize = (fileSize + page - 1UL) / page * page }

  /// Returns the command as it goes on disk: every run of __LINKEDIT it
  /// names at the offset the layout gave that run, and the segment holding
  /// those runs as long as they have made it.
  let private effectiveCommand (layout: Layout) cmd =
    match cmd with
    | Segment(cmdType, size, seg) when seg.SegCmdName = Segment.LinkEdit ->
      Segment(cmdType, size, grownLinkEdit layout seg)
    | _ ->
      LinkEdit.relocate layout.LinkEditPlaces cmd

  /// Writes every load command back into the table the header points at.
  let private writeCommands (out: byte[]) (img: Image) (layout: Layout) =
    for i = 0 to img.Commands.Length - 1 do
      let entry = img.Commands[i]
      let at = layout.CommandOffsets[i]
      let size = int entry.Command.CmdSize
      let dst = Span(out, at, size)
      let src = ReadOnlySpan(out, at, size)
      if entry.IsAdded then writeAddedCmd img dst entry.Command else ()
      writeCommand img dst src (effectiveCommand layout entry.Command)

  /// Clears whatever the load commands no longer reach. One the image took
  /// out leaves the bytes of the table it was in behind, and a reader that
  /// went by those rather than by the count would read a command that is no
  /// longer there.
  let private clearCommandTail (out: byte[]) (img: Image) (layout: Layout) =
    let at = int img.ToolBox.HeaderOffset + selectByWordSize img.Class 28 32
    let wasEnd = at + int img.Header.SizeOfCmds
    let isEnd = at + int layout.SizeOfCmds
    if isEnd < wasEnd then Array.fill out isEnd (wasEnd - isEnd) 0uy else ()

  /// Returns the section as it goes on disk, which is where the layout put
  /// its bytes rather than where the file had them.
  let private effectiveSection (img: Image) (layout: Layout) idx =
    { img.Sections[idx].Section with SecOffset = layout.SectionOffsets[idx] }

  /// Writes one section description into the span covering it. Its two names
  /// are left alone, as a segment's own name is.
  let private writeSectionStruct (img: Image) (dst: Span<byte>) sec =
    let endian, cls = img.Endian, img.Class
    writeUIntByWordSize dst endian cls 32 (sec.SecAddr - img.BaseAddress)
    writeUIntByWordSizeAndOffset dst endian cls 36 40 sec.SecSize
    writeUInt32 dst endian (selectByWordSize cls 40 48) sec.SecOffset
    writeUInt32 dst endian (selectByWordSize cls 44 52) sec.SecAlignment
    writeUInt32 dst endian (selectByWordSize cls 48 56) sec.SecRelOff
    let nreloc = uint32 sec.SecNumOfReloc
    let flags = uint32 (int sec.SecType ||| int sec.SecAttrib)
    let res1, res2 = uint32 sec.SecReserved1, uint32 sec.SecReserved2
    writeUInt32 dst endian (selectByWordSize cls 52 60) nreloc
    writeUInt32 dst endian (selectByWordSize cls 56 64) flags
    writeUInt32 dst endian (selectByWordSize cls 60 68) res1
    writeUInt32 dst endian (selectByWordSize cls 64 72) res2

  /// Writes the two names of a section the image added, which the original
  /// file has no bytes for.
  let private writeAddedSection (dst: Span<byte>) (sec: Section) =
    dst.Clear()
    writeName dst 0 sec.SecName
    writeName dst 16 sec.SegName

  /// Writes every section description back into the segment command holding
  /// it, which is where a Mach-O keeps them instead of in a table of its own.
  let private writeSections (out: byte[]) (img: Image) layout =
    let entSize = selectByWordSize img.Class 68 80
    for i = 0 to img.Sections.Length - 1 do
      let entry = img.Sections[i]
      let dst = Span(out, layout.StructOffsets[i], entSize)
      if entry.Origin.IsNone then writeAddedSection dst entry.Section else ()
      writeSectionStruct img dst (effectiveSection img layout i)

  /// Puts the bytes of every section the image was given where the layout
  /// says they go, which is where the file already kept them, a section
  /// being no freer to move than the segment mapping it is.
  let private writeContents (out: byte[]) (img: Image) (layout: Layout) =
    for i = 0 to img.Sections.Length - 1 do
      match img.Sections[i].Content with
      | InFile ->
        ()
      | Given bytes ->
        Array.blit bytes 0 out (int layout.SectionOffsets[i]) bytes.Length

  /// Puts every run of __LINKEDIT where the layout says it goes, which is
  /// where the file already kept it for as long as nothing before it has
  /// grown. A run the image was given none of holds what the original file
  /// has, moved along to its new place.
  let private writeLinkEdit (out: byte[]) (img: Image) (layout: Layout) =
    for i = 0 to img.LinkEdit.Length - 1 do
      let run = img.LinkEdit[i]
      let at = int layout.LinkEditOffsets[i]
      match run.RunContent with
      | InFile ->
        let from = int run.RunOrigin
        let size = int run.RunOriginSize
        if at <> from then Array.blit img.Original from out at size else ()
      | Given bytes ->
        Array.blit bytes 0 out at bytes.Length

  /// Lays the byte edits over what the structures have written. They come
  /// last so that one of them can reach whatever no structure here models,
  /// and oldest first so that a later edit of the same bytes is the one that
  /// stands.
  let private applyPatches (out: byte[]) (img: Image) =
    for patch in List.rev img.Patches do
      let bytes = patch.PatchBytes
      Array.blit bytes 0 out patch.PatchOffset bytes.Length

  /// Returns the bytes of the Mach-O file the given image describes.
  let emit (img: Image) =
    let layout = Layout.compute img
    let out = Array.zeroCreate layout.Size
    Array.blit img.Original 0 out 0 (min layout.Size img.Original.Length)
    writeLinkEdit out img layout
    writeContents out img layout
    writeHeader (Span out) img layout
    writeCommands out img layout
    clearCommandTail out img layout
    writeSections out img layout
    applyPatches out img
    out
