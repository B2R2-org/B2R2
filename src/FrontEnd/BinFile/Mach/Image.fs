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
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper
open B2R2.FrontEnd.BinFile.ByteWriter

/// Represents a Mach-O file that can be edited and written back out. It keeps
/// the bytes it was parsed from, because a parsed view is not all of a file:
/// whatever no structure here models is emitted by copying it from the
/// original, which is what lets an untouched image reproduce its file.
type internal Image =
  { /// The toolbox the image was parsed with, which holds the bytes it came
    /// from along with everything needed to read them again.
    ToolBox: Toolbox
    /// The byte order every field of the file goes back in.
    Endian: Endian
    /// The load command table, in the order the file names the commands.
    Commands: CommandEntry[]
    /// Every section of the image, in the order the segments name them,
    /// which is the order their numbers run in.
    Sections: SectionEntry[]
    /// The runs of __LINKEDIT the file keeps, in the order it keeps them.
    LinkEdit: LinkEditRun[]
    /// The byte edits laid over the original, newest first. They are the last
    /// word on what the emitted file holds, going on after every structure
    /// here has been written, so that one of them can reach what nothing here
    /// models.
    Patches: BytePatch list }
with
  /// The bytes the image was parsed from.
  member this.Original with get() = this.ToolBox.Bytes

  /// The Mach-O header.
  member this.Header with get() = this.ToolBox.Header

  /// The load base every address here has added to it, and must have taken
  /// back off to go on disk.
  member this.BaseAddress with get() = this.ToolBox.BaseAddress

  /// The word size the file writes its addresses and sizes in.
  member this.Class with get() = this.ToolBox.Header.Class

/// Represents one load command of an editable image.
and internal CommandEntry =
  { /// The parsed load command.
    Command: LoadCommand
    /// Whether the image added the command. The original file has no bytes
    /// for one it did, so all of such a command is written rather than the
    /// numbers alone.
    IsAdded: bool }

/// Represents one section of an editable image. A section is described by a
/// structure inside the segment command naming it, rather than by a table of
/// its own, so an entry says which command owns it and which of that
/// command's sections it is.
and internal SectionEntry =
  { /// The parsed section.
    Section: Section
    /// The index, in the command table, of the segment command naming it.
    OwnerIdx: int
    /// Which of that command's sections it is, counted from zero.
    SecIndexInSeg: int
    /// Where the bytes of the section come from.
    Content: SectionContent
    /// The room the original file gave the section; None for a section the
    /// image made, which the file never gave a place to.
    Origin: SectionOrigin option }

/// Represents the room the original file gave a section.
and internal SectionOrigin =
  { /// The file offset the section was at.
    OriginOffset: uint32
    /// How many bytes of the file it took up there, which is none for a
    /// section that occupies memory alone.
    OriginSize: uint64 }

/// Represents where a run of bytes comes from.
and internal SectionContent =
  /// From the original file, at the offset the description names, which is
  /// where they stay.
  | InFile
  /// From the image, which needs room of its own wherever what was there is
  /// no longer the size of what goes there now.
  | Given of byte[]

/// Represents one of the runs of bytes that __LINKEDIT holds, which is where
/// a Mach-O keeps everything the linker and the dynamic linker read.
and internal LinkEditRun =
  { /// Which run of __LINKEDIT it is.
    RunKind: LinkEditKind
    /// Where the original file keeps it.
    RunOrigin: uint32
    /// How many bytes the original file gives it.
    RunOriginSize: uint32
    /// The bytes that go there, which are the original ones until the image
    /// is given others.
    RunContent: SectionContent }

/// Represents a run of bytes put at one file offset of an image.
and internal BytePatch =
  { /// The file offset the run starts at.
    PatchOffset: int
    /// The bytes that go there.
    PatchBytes: byte[] }

/// Represents a section an image is asked to add, along with the segment
/// made to hold it. A Mach-O describes a section inside the command naming
/// its segment, and every segment a file already has is mapped as tightly as
/// the loader allows, so a section the image adds is given a segment of its
/// own past everything the file already holds.
and SectionSpec =
  { /// The name the segment goes under.
    SpecSegName: string
    /// The name the section goes under.
    SpecSecName: string
    /// What the section holds, in the terms a section description has for it.
    SpecType: SectionType
    /// The attributes of the section.
    SpecAttrib: SectionAttribute
    /// The power of two the address of the section is a multiple of, which
    /// is how a Mach-O spells an alignment out.
    SpecAlignment: uint32
    /// The rights the segment holding the section is mapped with.
    SpecPermission: Permission
    /// The bytes the section holds.
    SpecContent: byte[] }

/// Represents a symbol an image is asked to add. It goes in as a defined
/// external one, which is the only kind that can be added without moving a
/// symbol the file already has: those sit in three groups the dynamic symbol
/// table names by index, and a defined external symbol goes at the end of the
/// middle one.
and SymbolSpec =
  { /// The name the symbol goes under.
    SymSpecName: string
    /// The address the symbol is at.
    SymSpecAddr: Addr
    /// The number of the section defining it, counted from one as a Mach-O
    /// counts its sections.
    SymSpecSecNum: int }

[<RequireQualifiedAccess>]
module internal Image =
  /// Returns the load command table of the image, none of the entries having
  /// been added to what the file already carried.
  let private toCommandEntries (cmds: LoadCommand[]) =
    cmds |> Array.map (fun cmd -> { Command = cmd; IsAdded = false })

  /// Returns the segment commands among the given entries, in the order the
  /// file names them.
  let private segmentsIn (entries: CommandEntry[]) =
    entries
    |> Array.choose (fun entry ->
      match entry.Command with
      | Segment(_, _, seg) -> Some seg
      | _ -> None)

  /// Returns the segment commands of the image, in the order the file names
  /// them.
  let segmentsOf (img: Image) = segmentsIn img.Commands

  /// Returns which command owns each section and which of that command's
  /// sections it is, in the order the sections are numbered.
  let private sectionPlaces (entries: CommandEntry[]) =
    let places = ResizeArray()
    for i = 0 to entries.Length - 1 do
      match entries[i].Command with
      | Segment(_, _, seg) ->
        for j = 0 to int seg.NumSecs - 1 do
          places.Add(struct (i, j))
      | _ ->
        ()
    places.ToArray()

  /// Returns whether the section keeps no bytes in the file at all, which is
  /// what a section holding nothing but zeros is spared.
  let isZeroFill (sec: Section) =
    sec.SecType = SectionType.S_ZEROFILL
    || sec.SecType = SectionType.S_GB_ZEROFILL
    || sec.SecType = SectionType.S_THREAD_LOCAL_ZEROFILL

  /// Returns the section entries of the image, each knowing the room the file
  /// gave it so that the layout can tell what may stay where it is.
  let private toSectionEntries toolBox entries =
    let secs = Section.parse toolBox (segmentsIn entries)
    Array.map2 (fun sec (struct (owner, at)) ->
      let fileSize = if isZeroFill sec then 0UL else sec.SecSize
      let origin = { OriginOffset = sec.SecOffset; OriginSize = fileSize }
      { Section = sec
        OwnerIdx = owner
        SecIndexInSeg = at
        Content = InFile
        Origin = Some origin }) secs (sectionPlaces entries)

  /// Returns the runs of __LINKEDIT the file keeps, in the order it keeps
  /// them, which is the order they have to be laid back down in.
  let private toLinkEditRuns (toolBox: Toolbox) (entries: CommandEntry[]) =
    entries
    |> Array.map (fun entry -> entry.Command)
    |> LinkEdit.regionsIn toolBox.Header.Class
    |> Array.sortBy (fun region -> region.RegionOffset)
    |> Array.map (fun region ->
      { RunKind = region.RegionKind
        RunOrigin = region.RegionOffset
        RunOriginSize = region.RegionSize
        RunContent = InFile })

  /// Creates an editable image out of the given Mach-O file contents. A
  /// universal binary is narrowed to the slice matching the given ISA, which
  /// is the image everything here is offset from.
  let ofBytes bytes isa baseAddrOpt =
    let toolBox = Toolbox.Init(bytes, Header.parse bytes baseAddrOpt isa)
    let entries = toCommandEntries (LoadCommands.parse toolBox)
    { ToolBox = toolBox
      Endian = Header.magicToEndian toolBox.Header.Magic
      Commands = entries
      Sections = toSectionEntries toolBox entries
      LinkEdit = toLinkEditRuns toolBox entries
      Patches = [] }

  /// Returns the image with the given bytes put at the given file offset.
  let patchByOffset offset (bytes: byte[]) (img: Image) =
    if offset < 0 || offset + bytes.Length > img.Original.Length then
      raise InvalidAddrWriteException
    else
      let patch = { PatchOffset = offset; PatchBytes = Array.copy bytes }
      { img with Patches = patch :: img.Patches }

  /// Returns the image with the given bytes put where the file keeps the
  /// given address. Raises InvalidAddrWriteException when the address is not
  /// one the file holds bytes for, which is what an address in the
  /// zero-filled tail of a segment is.
  let patchByAddr addr bytes img =
    let ptr = Helper.boundedPointerOf (segmentsOf img) addr
    if ptr.CanReadFileBytes && Array.length bytes <= ptr.ReadableAmount then
      patchByOffset ptr.Offset bytes img
    else
      raise InvalidAddrWriteException

  /// Returns the image with the command at the given index replaced.
  let private replaceCommand idx cmd (img: Image) =
    let cmds = Array.copy img.Commands
    cmds[idx] <- { cmds[idx] with Command = cmd }
    { img with Commands = cmds }

  /// Returns the index of the first command the given test holds for.
  let private tryFindCmdIndex test (img: Image) =
    img.Commands |> Array.tryFindIndex (fun entry -> test entry.Command)

  /// Returns the address the image is loaded at, which is the vmaddr of its
  /// __TEXT segment, and zero for a file carrying no such segment.
  let private imageBaseOf img =
    segmentsOf img |> Segment.tryGetImageBase |> Option.defaultValue 0UL

  /// Returns the image whose thread state names the given address. Such a
  /// state spells the entry point out as an unslid address, which is what the
  /// load base moves.
  let private setThreadEntry idx addr (img: Image) =
    match img.Commands[idx].Command with
    | Thread(cmdType, size, _) ->
      let pc = addr - img.BaseAddress
      replaceCommand idx (Thread(cmdType, size, Some pc)) img
    | _ ->
      img

  /// Returns the image whose main command names the given address, which it
  /// keeps as an offset from the start of the image rather than as an address.
  let private setMainEntry idx addr img =
    match img.Commands[idx].Command with
    | Main(cmdType, size, cmd) ->
      let main = { cmd with EntryOff = addr - imageBaseOf img }
      replaceCommand idx (Main(cmdType, size, main)) img
    | _ ->
      img

  /// Returns the image whose entry point is the given address. A file names
  /// it through a thread state or through LC_MAIN, and one naming it through
  /// neither cannot be given one, there being no command to put it in.
  let setEntryPoint addr (img: Image) =
    let isThread = function Thread(_, _, Some _) -> true | _ -> false
    let isMain = function Main _ -> true | _ -> false
    match tryFindCmdIndex isThread img, tryFindCmdIndex isMain img with
    | Some idx, _ ->
      setThreadEntry idx addr img
    | None, Some idx ->
      setMainEntry idx addr img
    | None, None ->
      raise (UnsupportedEditException "The file names no entry point.")

  /// Returns the index of the section the given segment holds under the given
  /// name. A Mach-O section name is unique within its segment alone, so it
  /// takes both names to say which section is meant.
  let private findSectionIndex segName secName (img: Image) =
    let isNamed entry =
      entry.Section.SegName = segName && entry.Section.SecName = secName
    match Array.tryFindIndex isNamed img.Sections with
    | Some idx -> idx
    | None -> raise SectionNotFoundException

  /// Returns the image with the section at the given index replaced.
  let private replaceSection idx sec (img: Image) =
    let secs = Array.copy img.Sections
    secs[idx] <- { secs[idx] with Section = sec }
    { img with Sections = secs }

  /// Returns the image whose named section holds the given type and carries
  /// the given attributes, the two of which share one field of a section
  /// description and so are given together.
  let setSectionAttributes segName secName secType attrib img =
    let idx = findSectionIndex segName secName img
    let sec =
      { img.Sections[idx].Section with
          SecType = secType
          SecAttrib = attrib }
    replaceSection idx sec img

  /// Returns the bytes a section holds, whether they are ones the image was
  /// given or ones the original file still has.
  let contentOf (img: Image) entry =
    match entry.Content with
    | Given bytes ->
      bytes
    | InFile ->
      match entry.Origin with
      | Some origin when origin.OriginSize > 0UL ->
        let at = int origin.OriginOffset
        img.Original[at..at + int origin.OriginSize - 1]
      | _ ->
        [||]

  /// Returns the image whose named section holds the given bytes. Every
  /// section of a Mach-O sits inside a segment the file maps whole, so none
  /// of them can be given content of another size: whatever followed it
  /// would have to move, and the segment mapping it would no longer say
  /// where it is.
  let setSectionContent segName secName (bytes: byte[]) img =
    let idx = findSectionIndex segName secName img
    let entry = img.Sections[idx]
    if isZeroFill entry.Section then
      raise (UnsupportedEditException "A zero-filled section holds no bytes.")
    elif uint64 bytes.Length <> entry.Section.SecSize then
      raise (UnsupportedEditException "A section cannot be given a new size.")
    else
      let secs = Array.copy img.Sections
      secs[idx] <- { entry with Content = Given(Array.copy bytes) }
      { img with Sections = secs }

  /// Returns how many bytes a run of __LINKEDIT takes up, which is as many
  /// as the image was given wherever it was given any.
  let sizeOfRun run =
    match run.RunContent with
    | InFile -> int run.RunOriginSize
    | Given bytes -> bytes.Length

  /// Returns how many bytes longer the runs of __LINKEDIT have made that
  /// segment, which is negative where one of them has gone.
  let linkEditGrowth (img: Image) =
    img.LinkEdit
    |> Array.sumBy (fun run -> int64 (sizeOfRun run) - int64 run.RunOriginSize)

  /// Returns how many bytes the load commands of the image take up.
  let sizeOfCmds (img: Image) =
    img.Commands |> Array.sumBy (fun entry -> int entry.Command.CmdSize)

  /// Returns where the first thing the file keeps after its load commands
  /// begins, which is the nearest of every run of bytes anything points at.
  let private firstContentOffset (img: Image) =
    let secOffsets =
      img.Sections
      |> Array.choose (fun entry ->
        let sec = entry.Section
        if sec.SecSize > 0UL && not (isZeroFill sec) then Some sec.SecOffset
        else None)
    let runs = img.LinkEdit |> Array.map (fun run -> run.RunOrigin)
    let offsets = Array.append secOffsets runs
    if Array.isEmpty offsets then uint32 img.Original.Length
    else Array.min offsets

  /// Returns how many bytes are left between the end of the load commands
  /// and the first thing the file keeps after them. A Mach-O describes its
  /// segments and its sections in those commands rather than in a table of
  /// its own, and the table cannot grow past what follows it, so this is all
  /// the room a command the image adds has to go in.
  let commandBudget (img: Image) =
    let tableEnd = selectByWordSize img.Class 28 32 + sizeOfCmds img
    max 0 (int (firstContentOffset img) - tableEnd)

  /// Returns the value rounded up to the next multiple of the alignment.
  let align (value: uint64) alignment =
    if alignment <= 1UL then value
    else (value + alignment - 1UL) / alignment * alignment

  /// Returns the page size the image is mapped in, which is what both the
  /// address and the offset of a segment are a multiple of.
  let pageSizeOf (img: Image) =
    if img.Header.CPUType = CPUType.ARM64 then 0x4000UL else 0x1000UL

  /// Returns where the emitted file has reached, which is past everything
  /// any segment of the image keeps in it, __LINKEDIT counting for as much
  /// as the runs it holds have made it.
  let fileEndOf (img: Image) =
    let growth = linkEditGrowth img
    let endOf (seg: SegCmd) =
      if seg.SegCmdName = Segment.LinkEdit then
        uint64 (int64 (seg.FileOff + seg.FileSize) + growth)
      else
        seg.FileOff + seg.FileSize
    let ends = segmentsOf img |> Array.map endOf
    let top = if Array.isEmpty ends then 0UL else Array.max ends
    (* A file nothing has shortened keeps whatever sits past its segments,
       which for a slice of a universal binary is the padding it was given. *)
    if growth < 0L then top
    else max top (uint64 img.Original.Length + uint64 growth)

  /// Returns the address past everything the image maps, which is where a
  /// segment it adds can go without meeting one that is already there.
  let private freeAddrOf (img: Image) pageSize =
    let mapped = segmentsOf img |> Array.filter (fun s -> s.VMSize > 0UL)
    let ends = mapped |> Array.map (fun s -> s.VMAddr + s.VMSize)
    let top = if Array.isEmpty ends then img.BaseAddress else Array.max ends
    align top pageSize + pageSize

  /// Returns where a segment the image adds goes: the offset its bytes are
  /// kept at, the address it is mapped at, and the page size the two are
  /// each a multiple of.
  let private placeAdded img =
    let pageSize = pageSizeOf img
    struct (align (fileEndOf img) pageSize, freeAddrOf img pageSize, pageSize)

  /// Returns the segment command made to hold a section the image adds.
  let private newSegment spec at addr pageSize =
    let prot = Helper.permissionToMachVMProt spec.SpecPermission
    let size = uint64 (Array.length spec.SpecContent)
    { SecOff = 0
      SegCmdName = spec.SpecSegName
      VMAddr = addr
      VMSize = align size pageSize
      FileOff = at
      FileSize = size
      MaxProt = prot
      InitProt = prot
      NumSecs = 1u
      SegFlag = 0u }

  /// Returns the description of a section the image adds.
  let private newSection spec (at: uint64) addr =
    { SecName = spec.SpecSecName
      SegName = spec.SpecSegName
      SecAddr = addr
      SecSize = uint64 (Array.length spec.SpecContent)
      SecOffset = uint32 at
      SecAlignment = spec.SpecAlignment
      SecRelOff = 0u
      SecNumOfReloc = 0
      SecType = spec.SpecType
      SecAttrib = spec.SpecAttrib
      SecReserved1 = 0
      SecReserved2 = 0 }

  /// Returns the image with the given section added, inside a segment made
  /// to hold it. The command describing the two of them goes after the ones
  /// the file already carries, where it leaves every section number the file
  /// already uses naming what it named, and its bytes go past everything the
  /// file already keeps, where they meet nothing that is there.
  let addSection spec (img: Image) =
    let cls = img.Class
    let needed = selectByWordSize cls (56 + 68) (72 + 80)
    if commandBudget img < needed then
      raise (UnsupportedEditException "No room is left for another command.")
    else
      let struct (at, addr, pageSize) = placeAdded img
      let kind = selectByWordSize cls CmdType.LC_SEGMENT CmdType.LC_SEGMENT64
      let seg = newSegment spec at addr pageSize
      let entry = { Command = Segment(kind, uint32 needed, seg)
                    IsAdded = true }
      let secEntry =
        { Section = newSection spec at addr
          OwnerIdx = img.Commands.Length
          SecIndexInSeg = 0
          Content = Given(Array.copy spec.SpecContent)
          Origin = None }
      { img with
          Commands = Array.append img.Commands [| entry |]
          Sections = Array.append img.Sections [| secEntry |] }

  /// Returns the bytes a run of __LINKEDIT holds.
  let runContentOf (img: Image) run =
    match run.RunContent with
    | Given bytes ->
      bytes
    | InFile ->
      let at = int run.RunOrigin
      img.Original[at..at + int run.RunOriginSize - 1]

  /// Returns the bytes the run of the given kind holds, or None where the
  /// file keeps no such run.
  let private tryRunOf kind (img: Image) =
    img.LinkEdit
    |> Array.tryFind (fun run -> run.RunKind = kind)
    |> Option.map (runContentOf img)

  /// Returns the image with the run of the given kind holding the given
  /// bytes.
  let private replaceRun kind (bytes: byte[]) (img: Image) =
    let runs = Array.copy img.LinkEdit
    let idx = runs |> Array.findIndex (fun run -> run.RunKind = kind)
    runs[idx] <- { runs[idx] with RunContent = Given bytes }
    { img with LinkEdit = runs }

  /// Returns where the given name already sits in the given string table, if
  /// it sits there at all. An entry of such a table is any of its suffixes,
  /// so a name is there wherever a terminator follows it.
  let private findInStrTable (table: byte[]) (name: string) =
    let needle = Text.Encoding.Latin1.GetBytes(name + "\000")
    let idx = ReadOnlySpan(table).IndexOf(ReadOnlySpan needle)
    if idx < 0 then None else Some(uint32 idx)

  /// Returns the image with the given name in its string table, along with
  /// the offset the name sits at. A name the table already holds is used
  /// where it is rather than put there a second time.
  let private internName name (img: Image) =
    match tryRunOf StringTable img with
    | None ->
      raise (UnsupportedEditException "The file has no string table.")
    | Some table ->
      match findInStrTable table name with
      | Some offset ->
        img, offset
      | None ->
        let addition = Text.Encoding.Latin1.GetBytes(name + "\000")
        let grown = Array.append table addition
        replaceRun StringTable grown img, uint32 table.Length

  /// Returns the symbol table entry of a symbol the image adds, which names
  /// a section of this file and is seen from outside it.
  let private encodeSymbol (img: Image) nameOffset spec =
    let cls = img.Class
    let entry: byte[] = Array.zeroCreate (LinkEdit.entrySizeOfSymbol cls)
    let span = Span entry
    let nType = int SymbolType.N_SECT ||| 0x1
    writeUInt32 span img.Endian 0 nameOffset
    writeUInt8 span 4 (byte nType)
    writeUInt8 span 5 (byte spec.SymSpecSecNum)
    let value = spec.SymSpecAddr - img.BaseAddress
    writeUIntByWordSize span img.Endian cls 8 value
    entry

  /// Returns the table with the given entry put at the given index of it.
  let private insertEntry (table: byte[]) at (entry: byte[]) =
    let cut = at * entry.Length
    Array.concat [ table[0..cut - 1]; entry; table[cut..] ]

  /// Returns the indirect symbol table with every index from the given one
  /// on moved up by one. An entry naming no symbol of the table stands for a
  /// local or an absolute slot, and stands.
  let private bumpIndirect (img: Image) at (table: byte[]) =
    let out = Array.copy table
    let span = Span out
    for i = 0 to out.Length / 4 - 1 do
      let value = img.ToolBox.Reader.ReadUInt32(out, i * 4)
      if value < 0x40000000u && value >= uint32 (at: int) then
        writeUInt32 span img.Endian (i * 4) (value + 1u)
      else
        ()
    out

  /// Returns a relocation table with every symbol index from the given one
  /// on moved up by one. Only an external entry names a symbol; a local one
  /// names a section, and a scattered one an address, neither of which any
  /// symbol index moves.
  let private bumpRelocs (img: Image) at (table: byte[]) =
    let reader = img.ToolBox.Reader
    let out = Array.copy table
    let span = Span out
    for i = 0 to out.Length / 8 - 1 do
      let scattered = reader.ReadUInt32(out, i * 8) >>> 31 = 1u
      let word = int (reader.ReadUInt32(out, i * 8 + 4))
      let idx = word &&& 0xffffff
      if not scattered && (word >>> 27) &&& 1 = 1 && idx >= at then
        let bumped = (word &&& ~~~0xffffff) ||| (idx + 1)
        writeUInt32 span img.Endian (i * 8 + 4) (uint32 bumped)
      else
        ()
    out

  /// Returns the image with every index naming a symbol from the given one
  /// on moved up by one, which is what makes room for a symbol going in
  /// there: the indirect symbol table names one per slot of a stub or a
  /// pointer table, and an external relocation names the symbol it binds.
  let private remapSymbolIndices at (img: Image) =
    let remap img kind bump =
      match tryRunOf kind img with
      | Some table -> replaceRun kind (bump img at table) img
      | None -> img
    let img = remap img IndirectSymbolTable bumpIndirect
    let img = remap img ExtRelocTable bumpRelocs
    remap img LocalRelocTable bumpRelocs

  /// Returns where a defined external symbol goes in the symbol table, which
  /// is the end of the group of those, the undefined ones following them.
  /// Raises where the file keeps no symbol table of the kind that says where
  /// the groups are, or one whose groups leave symbols unaccounted for.
  let private insertionPointOf (img: Image) =
    let pick chooser =
      img.Commands |> Array.tryPick (fun entry -> chooser entry.Command)
    let symTab = pick (function SymTab(_, _, c) -> Some c | _ -> None)
    let dySymTab = pick (function DySymTab(_, _, c) -> Some c | _ -> None)
    match symTab, dySymTab with
    | None, _ ->
      raise (UnsupportedEditException "The file has no symbol table.")
    | Some _, None ->
      raise (UnsupportedEditException "The file has no dynamic symbols.")
    | Some s, Some d ->
      let counted = d.NumLocalSym + d.NumExtSym + d.NumUndefSym
      if counted <> s.NumOfSym then
        raise (UnsupportedEditException "The symbol groups do not add up.")
      else
        int (d.IdxExtSym + d.NumExtSym)

  /// Returns the command with the counts it keeps for the symbol table
  /// brought up to the one symbol and the bytes of name that have gone in.
  let private countedIn added cmd =
    match cmd with
    | SymTab(cmdType, size, c) ->
      let c =
        { c with
            NumOfSym = c.NumOfSym + 1u
            StrSize = c.StrSize + added }
      SymTab(cmdType, size, c)
    | DySymTab(cmdType, size, c) ->
      let c =
        { c with
            NumExtSym = c.NumExtSym + 1u
            IdxUndefSym = c.IdxUndefSym + 1u }
      DySymTab(cmdType, size, c)
    | _ ->
      cmd

  /// Returns the image with the given symbol added to its symbol table. It
  /// goes in as a defined external symbol, at the end of the group of those,
  /// so that the three groups the dynamic symbol table names go on naming
  /// what they named; every index from there on moves up by one to follow.
  /// Returns how many bytes longer the string table of the second image is
  /// than that of the first, which is what putting a name in it has added
  /// and is nothing at all where the name was already there.
  let private nameGrowth before after =
    let sizeOf img = tryRunOf StringTable img |> Option.map Array.length
    uint32 (defaultArg (sizeOf after) 0 - defaultArg (sizeOf before) 0)

  let addSymbol spec (img: Image) =
    if img.Header.FileType = FileType.MH_OBJECT then
      raise (UnsupportedEditException "An object file relocates by index.")
    else
      let at = insertionPointOf img
      let named, nameOffset = internName spec.SymSpecName img
      match tryRunOf SymbolTable named with
      | None ->
        raise (UnsupportedEditException "The file has no symbol table.")
      | Some table ->
        let entry = encodeSymbol named nameOffset spec
        let grown = replaceRun SymbolTable (insertEntry table at entry) named
        let remapped = remapSymbolIndices at grown
        let counted = countedIn (nameGrowth img named)
        let recount entry = { entry with Command = counted entry.Command }
        { remapped with Commands = Array.map recount remapped.Commands }

  /// Returns the image with its code signature taken off: the command naming
  /// it goes, and the run of __LINKEDIT holding it is emptied, which is what
  /// shortens the file. A signature covers the bytes as they were, so it is
  /// no use to a file anything has changed.
  let removeCodeSignature (img: Image) =
    let isCodeSign entry =
      match entry.Command with
      | CodeSign _ -> true
      | _ -> false
    if img.Commands |> Array.exists isCodeSign |> not then
      raise (UnsupportedEditException "The file carries no code signature.")
    else
      let empty run =
        if run.RunKind = CodeSignatureBlob then
          { run with RunContent = Given [||] }
        else
          run
      { img with
          Commands = img.Commands |> Array.filter (isCodeSign >> not)
          LinkEdit = Array.map empty img.LinkEdit }
