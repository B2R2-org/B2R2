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

namespace B2R2.FrontEnd.BinFile

open System.Collections.Generic
open B2R2
open B2R2.Collections
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile.FileHelper
open B2R2.FrontEnd.BinFile.DWARF
open B2R2.FrontEnd.BinFile.Mach
open B2R2.FrontEnd.BinFile.Mach.Helper

/// Represents a Mach-O binary file.
type MachBinFile private(path, bytes: byte[], toolBox, regFactoryOpt) =
  (* Every file offset a Mach-O records is relative to its own header, which in
     a universal binary is not where the file begins, so the image bytes are
     the slice the toolbox narrowed down to, not the bytes handed in. *)
  let image = toolBox.Bytes

  let rawBytes = System.ReadOnlyMemory image

  let fatArchs =
    lazy (if Header.IsFat bytes then Fat.parseArchs bytes else [||])

  let cmds = lazy LoadCommands.parse toolBox

  let segCmds = lazy Segment.extract cmds.Value

  let segMap = lazy Segment.buildMap segCmds.Value

  let secs = lazy Section.parse toolBox segCmds.Value

  let secText = lazy (Section.getTextSectionIndex secs.Value)

  let imageBase =
    lazy (Segment.tryGetImageBase segCmds.Value |> Option.defaultValue 0UL)

  let syms = lazy SymbolStore.parse toolBox cmds.Value secs.Value

  let exports =
    lazy ExportedSymbols.parse toolBox cmds.Value segCmds.Value

  let relocs =
    lazy Reloc.parse toolBox segCmds.Value secs.Value cmds.Value

  let relocMap = lazy Reloc.buildMap relocs.Value

  let fixups =
    lazy
      Array.append
        (ChainedFixup.parse toolBox cmds.Value segCmds.Value)
        (DyldInfo.parse toolBox cmds.Value segCmds.Value)

  let fixupMap = lazy Fixup.buildMap fixups.Value

  let notInMemRanges = lazy invalidRangesByVM toolBox segCmds.Value

  let notInFileRanges = lazy invalidRangesByFileBounds toolBox segCmds.Value

  let executableRanges = lazy executableRanges segCmds.Value

  let filesetEntries = lazy filesetEntries cmds.Value

  let encryptedRanges = lazy encryptedRanges segCmds.Value cmds.Value

  let codeSignature = lazy CodeSignature.parse toolBox cmds.Value

  let enumSymbols =
    lazy (syms.Value.SymbolArray
          |> Array.filter (fun s -> s.SymType <> SymbolType.N_OPT))

  let staticSymbols = lazy (enumSymbols.Value |> Array.filter Symbol.IsStatic)

  let dynamicSymbols =
    lazy (enumSymbols.Value |> Array.filter (Symbol.IsStatic >> not))

  let stripped =
    lazy (staticSymbols.Value
          |> Array.exists (fun s -> Symbol.IsFunc(secText.Value, s))
          |> not)

  let entryPoint =
    lazy computeEntryPoint toolBox segCmds.Value cmds.Value

  let interpreterPath =
    lazy (cmds.Value
          |> Array.tryPick (function
            | DyLinker(_, _, path) -> Some path
            | _ -> None))

  let rpaths =
    lazy (cmds.Value
          |> Array.choose (function
            | Rpath(_, _, path) -> Some path
            | _ -> None))

  let linkerOptions = lazy linkerOptions cmds.Value

  (* An object file carries no LC_LOAD_DYLIB: what it needs linked sits in its
     LC_LINKER_OPTION commands instead, named as a linker flag names it rather
     than by an install path. Only an object file is read that way, so the two
     forms never land in one array. *)
  let dependencies =
    lazy
      if toolBox.Header.FileType = FileType.MH_OBJECT then
        autolinkedLibraries cmds.Value
      else
        cmds.Value
        |> Array.choose (function
          | DyLib(_, _, c) -> Some c.DyLibName
          | _ -> None)

  let installName =
    lazy (cmds.Value
          |> Array.tryPick (function
            | DyLibId(_, _, c) -> Some c.DyLibName
            | _ -> None))

  let buildVersion =
    lazy (cmds.Value
          |> Array.tryPick (function
            | BuildVersion(_, _, c) -> Some c
            | _ -> None))

  (* Being a Mach-O is itself what names macOS, so an image carrying no
     version command is built for it all the same. *)
  let os =
    lazy (match buildVersion.Value with
          | Some cmd -> Platform.toOS cmd.Platform
          | None -> OS.MacOSX)

  let buildId =
    lazy (cmds.Value
          |> Array.tryPick (function
            | Uuid(_, _, uuid) -> Some uuid
            | _ -> None)
          |> Option.defaultValue [||])

  let machSymKind secText (s: Symbol) =
    if Symbol.IsFunc(secText, s) then FunctionSymbol
    elif Symbol.IsSection s then DataSymbol
    else OtherSymbol

  let machBinding (s: Symbol) =
    if s.SymDesc &&& 0xC0s <> 0s then WeakBinding (* N_WEAK_REF|N_WEAK_DEF *)
    elif s.IsExternal then GlobalBinding
    else LocalBinding

  let toBinSymbol secText (s: Symbol) =
    { Name = s.SymName
      Address = s.SymAddr
      Kind = machSymKind secText s
      Binding = machBinding s
      IsDefined = Symbol.IsDefined s
      Size = None
      LibraryName = s.VerInfo |> Option.map (fun d -> d.DyLibName) }

  let binSymbols =
    lazy (syms.Value.SymbolArray |> Array.map (toBinSymbol secText.Value))

  let codeModeMarkers =
    lazy
      let symbols = syms.Value.SymbolArray
      CodeMode.compute toolBox cmds.Value imageBase.Value secText.Value symbols

  let symbolTableObj =
    { new ISymbolTable with
        member _.IsStripped with get() = stripped.Value

        member _.Symbols with get() = binSymbols.Value

        member _.TryFindSymbolByAddr addr =
          match syms.Value.SymbolMap.TryGetValue addr with
          | true, s -> Ok(toBinSymbol secText.Value s)
          | false, _ -> Error ErrorCase.SymbolNotFound

        member _.CodeModeMarkers = codeModeMarkers.Value }

  let symbolTable = Some symbolTableObj

  let nameResolver = Some(NameResolver.ofSymbolTable symbolTableObj)

  (* An initializer pointer is written by dyld rather than by the linker: a
     chained image leaves a chain entry in the slot and a dyld info one a
     rebase opcode, so the fixup names the function where the bytes on disk
     do not. A slot nothing fixes up holds the address itself. *)
  let resolveFuncPointer addr =
    match fixupMap.Value.TryGetValue addr with
    | true, { FixupTarget = Rebase target } -> Some target
    | _ -> None

  let symbolFuncAddrs =
    lazy
      [| for s in syms.Value.SymbolArray do
           if Symbol.IsFunc(secText.Value, s) && s.SymAddr > 0UL then s.SymAddr
           else () |]

  let functionAddrs =
    lazy
      [| symbolFuncAddrs.Value
         funcPointerAddrs toolBox secs.Value resolveFuncPointer
         initRoutines cmds.Value |]
      |> Array.concat
      |> Array.distinct
      |> Array.sort

  let isZeroFillSection (sec: Section) =
    sec.SecType = SectionType.S_ZEROFILL
    || sec.SecType = SectionType.S_GB_ZEROFILL
    || sec.SecType = SectionType.S_THREAD_LOCAL_ZEROFILL

  let isTLSSection (sec: Section) =
    sec.SecType = SectionType.S_THREAD_LOCAL_REGULAR
    || sec.SecType = SectionType.S_THREAD_LOCAL_ZEROFILL
    || sec.SecType = SectionType.S_THREAD_LOCAL_VARIABLES
    || sec.SecType = SectionType.S_THREAD_LOCAL_VARIABLE_POINTERS
    || sec.SecType = SectionType.S_THREAD_LOCAL_INIT_FUNCTION_POINTERS

  let isDynamicLinkageSection (sec: Section) =
    sec.SecType = SectionType.S_NON_LAZY_SYMBOL_POINTERS
    || sec.SecType = SectionType.S_LAZY_SYMBOL_POINTERS
    || sec.SecType = SectionType.S_SYMBOL_STUBS

  let isMetadataSection (sec: Section) =
    sec.SecType = SectionType.S_MOD_INIT_FUNC_POINTERS
    || sec.SecType = SectionType.S_MOD_TERM_FUNC_POINTERS
    || sec.SecType = SectionType.S_INTERPOSING
    || sec.SecType = SectionType.S_LAZY_DYLIB_SYMBOL_POINTERS

  let secPermission (sec: Section) =
    match NoOverlapIntervalMap.tryFindByAddr sec.SecAddr segMap.Value with
    | Some seg -> machVMProtToPermission seg.InitProt
    | None -> enum 0

  let secKind (sec: Section) =
    if sec.SecAttrib.HasFlag SectionAttribute.S_ATTR_DEBUG then
      DebugSection
    elif isTLSSection sec then
      ThreadLocalStorageSection
    elif isZeroFillSection sec then
      UninitializedDataSection
    elif isDynamicLinkageSection sec then
      DynamicLinkageSection
    elif sec.SecAttrib.HasFlag SectionAttribute.S_ATTR_PURE_INSTRUCTIONS then
      CodeSection
    elif sec.SecName = Section.Text then
      CodeSection
    elif isMetadataSection sec then
      MetadataSection
    elif sec.SecType = SectionType.S_REGULAR then
      DataSection
    else
      UnknownSection

  let secFileSize (sec: Section) =
    if isZeroFillSection sec then 0UL else sec.SecSize

  let toBinSection (sec: Section) =
    { Name = sec.SecName
      Address = sec.SecAddr
      Size = sec.SecSize
      Offset =
        if isZeroFillSection sec then None else Some(uint64 sec.SecOffset)
      FileSize = secFileSize sec
      Permission = secPermission sec
      Kind = secKind sec }

  let tryFindSectionByAddr addr =
    secs.Value
    |> Array.tryFind (fun sec ->
      addr >= sec.SecAddr && addr < sec.SecAddr + sec.SecSize)

  let tryFindSectionByOffset (offset: uint32) =
    secs.Value
    |> Array.tryFind (fun sec ->
      let fileSize = secFileSize sec
      let secOffset = uint64 sec.SecOffset
      fileSize > 0UL
      && uint64 offset >= secOffset
      && uint64 offset < secOffset + fileSize)

  let binSections = lazy (secs.Value |> Array.map toBinSection)

  /// Returns a pointer to the file bytes of the given section, or a null
  /// pointer when the section has none to point at. A zero-fill section keeps
  /// a section offset of zero, which names the Mach header rather than bytes
  /// of its own.
  let toSectionPointer (sec: Section) =
    let size = secFileSize sec
    if size = 0UL then
      BinFilePointer.Null
    else
      BinFilePointer.CreateFileBacked(
        sec.SecAddr,
        sec.SecAddr + size - 1UL,
        int sec.SecOffset,
        int sec.SecOffset + int size - 1
      )

  let structure =
    Some { new IBinStructure with
      (* The cached array is never handed out as is, so a caller cannot make
         its edits visible to the next reader. *)
      member _.Sections with get() = Array.copy binSections.Value

      member _.CodeSectionPointer =
        if secText.Value < 0 then BinFilePointer.Null
        else toSectionPointer secs.Value[secText.Value]

      member _.GetSectionPointer name =
        secs.Value
        |> Array.tryFind (fun sec -> sec.SecName = name)
        |> function
          | Some sec -> toSectionPointer sec
          | None -> BinFilePointer.Null

      member _.TryFindSectionByName name =
        secs.Value
        |> Array.tryFind (fun sec -> sec.SecName = name)
        |> function
          | Some sec -> Ok(toBinSection sec)
          | None -> Error ErrorCase.ItemNotFound

      member _.TryFindSectionByAddr addr =
        match tryFindSectionByAddr addr with
        | Some sec -> Ok(toBinSection sec)
        | None -> Error ErrorCase.ItemNotFound

      member _.TryFindSectionByOffset offset =
        match tryFindSectionByOffset offset with
        | Some sec -> Ok(toBinSection sec)
        | None -> Error ErrorCase.ItemNotFound

      member _.TryFindSectionNameByAddr(addr: Addr) =
        tryFindSectionByAddr addr
        |> function
          | Some sec -> Ok sec.SecName
          | None -> Error ErrorCase.ItemNotFound

      member _.TryFindSectionNameByOffset offset =
        tryFindSectionByOffset offset
        |> function
          | Some sec -> Ok sec.SecName
          | None -> Error ErrorCase.ItemNotFound

      member _.FunctionAddresses = functionAddrs.Value
    }

  (* A classic entry is read back out of the file for its addend, so the whole
     table is built once and kept rather than on every reader's behalf. *)
  let binRelocations =
    lazy
      let classic =
        relocMap.Value.Values
        |> Seq.sortBy (fun reloc -> reloc.RelocAddr)
        |> Seq.map (Reloc.toBinRelocation toolBox syms.Value.SymbolArray)
        |> Seq.toArray
      let fixupRelocs =
        fixupMap.Value.Values
        |> Seq.sortBy (fun fixup -> fixup.FixupAddr)
        |> Seq.map (fun fixup ->
          let addr = fixup.FixupAddr
          match fixup.FixupTarget with
          | Rebase _ ->
            { Address = addr; SymbolName = None; Addend = None }
          | Bind(sym, _, addend) ->
            { Address = addr; SymbolName = Some sym; Addend = Some addend })
        |> Seq.toArray
      Array.append classic fixupRelocs

  let relocations =
    Some { new IRelocationTable with
      (* The cached array is never handed out as is, so a caller cannot make
         its edits visible to the next lookup. *)
      member _.Relocations = Array.copy binRelocations.Value

      member _.IsRelocationAddr addr =
        relocMap.Value.ContainsKey addr || fixupMap.Value.ContainsKey addr

      member _.TryGetRelocatedAddr relocAddr =
        match fixupMap.Value.TryGetValue relocAddr with
        | true, fixup ->
          match fixup.FixupTarget with
          | Rebase target -> Ok target
          | Bind _ -> Error ErrorCase.ItemNotFound
        | false, _ ->
          Reloc.getRelocatedAddr toolBox relocMap.Value syms.Value relocAddr

      member _.TryGetInternalFunctionAddr _relocAddr =
        Error ErrorCase.SymbolNotFound
    }

  let fixupImports =
    lazy
      fixups.Value
      |> Array.choose (fun fixup ->
        match fixup.FixupTarget with
        | Bind(name, library, _) ->
          Some { Name = name
                 LibraryName = library
                 TrampolineAddress = None
                 TableAddress = fixup.FixupAddr }
        | Rebase _ ->
          None)

  (* Stub-based binaries already describe imports via the symbol store; only
     fall back to dyld fixup binds when there is no classic import table (e.g.
     chained-fixups or dyld-info dylibs without __stubs). *)
  let importEntries =
    lazy
      let classic = getPLT syms.Value
      if Array.isEmpty classic then fixupImports.Value else classic

  (* Only the stub addresses are ever asked for by address, so they are kept
     on their own rather than looked for among the entries each time. *)
  let trampolineAddrs =
    lazy
      let addrs = HashSet<Addr>()
      for entry in syms.Value.Imports do
        match entry.TrampolineAddress with
        | Some addr -> addrs.Add addr |> ignore
        | None -> ()
      addrs

  let importTable =
    Some { new IImportTable with
      member _.Imports = importEntries.Value

      member _.IsInImportTable addr =
        trampolineAddrs.Value.Contains addr
        || (Array.isEmpty syms.Value.Imports
            && Fixup.isBindAt fixupMap.Value addr)
    }

  let segments =
    lazy
      segCmds.Value
      |> Array.filter (fun seg -> seg.VMSize > 0UL)
      |> Array.map (fun seg ->
        { Name = Some seg.SegCmdName
          Address = seg.VMAddr
          PhysAddr = seg.VMAddr
          Size = seg.VMSize
          Offset = seg.FileOff
          FileSize = seg.FileSize
          Permission = machVMProtToPermission seg.InitProt })

  let memoryLayout =
    Some { new IMemoryLayout with
      member _.Segments = segments.Value }

  let exn =
    lazy ExceptionData.parse toolBox segCmds.Value secs.Value regFactoryOpt

  let toExceptionHandlers (frame: FrameInfo) =
    match frame.LSDAPointer with
    | None ->
      [||]
    | Some p ->
      match Map.tryFind p exn.Value.LSDATable with
      | None ->
        [||]
      | Some lsda ->
        lsda.CallSiteTable
        |> List.map (fun cs ->
          { BlockStart = frame.FuncStart + cs.Position
            BlockEnd = frame.FuncStart + cs.Position + cs.Length - 1UL
            Handler =
              if cs.LandingPad = 0UL then None
              else Some(frame.FuncStart + cs.LandingPad) })
        |> List.toArray

  let exceptionFrames =
    lazy
      [| for frame in exn.Value.Frames do
           { FunctionStart = frame.FuncStart
             FunctionEnd = frame.FuncEnd - 1UL
             PersonalityRoutine = frame.PersonalityRoutine
             Handlers = toExceptionHandlers frame } |]

  let exceptionTable =
    Some { new IExceptionTable with
      member _.Frames = exceptionFrames.Value
    }

  /// Initializes a Mach-O binary file. A universal binary is narrowed to the
  /// slice matching the given ISA.
  new(path, bytes: byte[], isa, baseAddrOpt, regFactoryOpt) =
    let toolBox = Toolbox.Init(bytes, Header.parse bytes baseAddrOpt isa)
    MachBinFile(path, bytes, toolBox, regFactoryOpt)

  member internal _.Header with get() = toolBox.Header

  /// The bytes of the image itself, which for a universal binary are the
  /// slice that was picked rather than the whole of the file handed in.
  member internal _.Bytes with get() = image

  /// Where the header of this image sits within the bytes it was parsed
  /// against. Only an image opened out of a fileset container, whose load
  /// commands point into that container, has one that is not zero.
  member internal _.HeaderOffset with get() = toolBox.HeaderOffset

  /// The architectures a universal binary offers, or an empty array when the
  /// file is not one. They are read from the whole file rather than from the
  /// slice this instance was narrowed to.
  member internal _.FatArchs with get() = fatArchs.Value

  member internal _.Commands with get() = cmds.Value

  /// The images this file holds when it is a fileset container, such as the
  /// kernel and the kexts of a kernel collection, or an empty array when it
  /// holds none.
  member internal _.FilesetEntries with get() = filesetEntries.Value

  /// The options each LC_LINKER_OPTION command of this file carries, in the
  /// order the file names them, or an empty array when it carries none. Only
  /// an object file does.
  member internal _.LinkerOptions with get() = linkerOptions.Value

  /// The platform this file is built to run on, the oldest version of it the
  /// file runs on and the SDK it was built against, as its LC_BUILD_VERSION
  /// names them or as the LC_VERSION_MIN_* command that preceded it does.
  /// None when the file carries neither command.
  member internal _.BuildVersion with get() = buildVersion.Value

  /// The code signature this file carries, or None when it carries none.
  /// An unsigned file, and one signed by a scheme this parser does not read,
  /// both name none.
  member internal _.CodeSignature with get() = codeSignature.Value

  member internal _.Sections with get() = secs.Value

  member internal _.Symbols with get() = syms.Value

  member internal _.StaticSymbols with get() = staticSymbols.Value

  member internal _.DynamicSymbols with get() = dynamicSymbols.Value

  member internal _.ExportedSymbols with get() = exports.Value

  member internal _.Relocations with get() = relocs.Value

  /// Opens the image a fileset container holds under the given name, reading
  /// it in place: its load commands point into the container, so it is read
  /// against the same bytes rather than against a copy cut out of them.
  member _.TryOpenFilesetEntry(name) =
    filesetEntries.Value
    |> Array.tryFind (fun entry -> entry.EntryName = name)
    |> Option.map (fun entry ->
      let toolBox = Toolbox.InitFilesetEntry(toolBox, entry.EntryFileOffset)
      MachBinFile(path, bytes, toolBox, regFactoryOpt))

  interface IBinFile with
    member _.Reader with get() = toolBox.Reader

    member _.RawBytes with get() = rawBytes

    member _.Length with get() = image.Length

    member _.Path with get() = path

    member _.Format with get() = FileFormat.MachBinary

    member _.Kind with get() =
      match toolBox.Header.FileType with
      | FileType.MH_OBJECT -> BinFileKind.Object
      | FileType.MH_EXECUTE | FileType.MH_PRELOAD -> BinFileKind.Executable
      | FileType.MH_DYLIB | FileType.MH_FVMLIB
      | FileType.MH_BUNDLE | FileType.MH_DYLIB_STUB
      | FileType.MH_KEXT_BUNDLE -> BinFileKind.SharedLibrary
      | FileType.MH_CORE -> BinFileKind.Core
      | FileType.MH_FILESET -> BinFileKind.Executable
      | _ -> BinFileKind.Unknown

    member _.ISA with get() = toolBox.ISA

    member _.OS with get() = os.Value

    member _.EntryPoint with get() = entryPoint.Value

    member _.BaseAddress with get() = toolBox.BaseAddress

    member _.InterpreterPath with get() = interpreterPath.Value

    member _.RPath with get() = [||]

    member _.RunPath with get() = rpaths.Value

    member _.DependencyNames with get() = Array.copy dependencies.Value

    member _.SharedObjectName with get() = installName.Value

    member _.BuildId with get() = Array.copy buildId.Value

    member _.ProgramHeaderTable with get() = None

    member _.IsNXEnabled with get() = isNXEnabled toolBox.Header

    member _.IsPIE with get() = toolBox.Header.Flags.HasFlag MachFlag.MH_PIE

    member _.IsBaseRelative with get() =
      let hdr = toolBox.Header
      hdr.Flags.HasFlag MachFlag.MH_PIE
      || hdr.FileType <> FileType.MH_EXECUTE

    member _.Relro with get() = None

    member _.EncryptedRanges with get() = encryptedRanges.Value

    member _.NameResolver with get() = nameResolver

    member _.SymbolTable with get() = symbolTable

    member _.Structure with get() = structure

    member _.Relocations with get() = relocations

    member _.ExceptionTable with get() = exceptionTable

    member _.ImportTable with get() = importTable

    member _.MemoryLayout with get() = memoryLayout

    member this.Slice(addr, len) =
      let ptr = (this :> IAddressSpace).GetBoundedPointer addr
      sliceByPointer image ptr len

    member _.IsValidAddr addr =
      IntervalSet.containsAddr addr notInMemRanges.Value |> not

    member _.IsValidRange range =
      IntervalSet.findAll range notInMemRanges.Value |> List.isEmpty

    member _.IsAddrMappedToFile addr =
      IntervalSet.containsAddr addr notInFileRanges.Value |> not

    member _.IsRangeMappedToFile range =
      IntervalSet.findAll range notInFileRanges.Value |> List.isEmpty

    member _.IsExecutableAddr addr =
      IntervalSet.containsAddr addr executableRanges.Value

    member _.GetBoundedPointer addr = boundedPointerOf segCmds.Value addr
