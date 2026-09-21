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

open B2R2.FrontEnd.BinFile.FileHelper

/// Represents one of the runs of bytes that __LINKEDIT holds. A Mach-O keeps
/// all of what the linker and the dynamic linker read in that one segment,
/// each run named by a load command that says where it is and how long it is,
/// so a run is known by which command field pair names it.
type internal LinkEditKind =
  /// The rebase opcodes of a dyld information command.
  | RebaseInfo
  /// The binding opcodes of a dyld information command.
  | BindInfo
  /// The weak binding opcodes of a dyld information command.
  | WeakBindInfo
  /// The lazy binding opcodes of a dyld information command.
  | LazyBindInfo
  /// The export trie of a dyld information command.
  | ExportInfo
  /// The table of function starts.
  | FuncStartsData
  /// The table of the ranges of code that hold data.
  | DataInCodeTable
  /// The chained fixups, header and all.
  | ChainedFixupsData
  /// The export trie a command of its own names.
  | ExportsTrieData
  /// The code signature superblob.
  | CodeSignatureBlob
  /// The symbol table.
  | SymbolTable
  /// The string table the symbol names are kept in.
  | StringTable
  /// The table of indices naming the symbol each slot of a stub or a pointer
  /// table stands for.
  | IndirectSymbolTable
  /// The table of contents of a dynamic library.
  | TOCTable
  /// The module table of a dynamic library.
  | ModuleTable
  /// The table of the symbols other modules refer to.
  | ExtRefTable
  /// The external relocation table.
  | ExtRelocTable
  /// The local relocation table.
  | LocalRelocTable

/// Represents where the file keeps one run of __LINKEDIT.
and internal LinkEditRegion =
  { /// Which run it is.
    RegionKind: LinkEditKind
    /// Where the file keeps it.
    RegionOffset: uint32
    /// How many bytes it takes up.
    RegionSize: uint32 }

[<RequireQualifiedAccess>]
module internal LinkEdit =
  /// The size of one symbol table entry, which is a word wider on a 64-bit
  /// file than on a 32-bit one.
  let entrySizeOfSymbol cls = selectByWordSize cls 12 16

  /// The size of one entry of a module table.
  let private entrySizeOfModule cls = selectByWordSize cls 52 56

  /// The size of one relocation entry, which is the same either way.
  let [<Literal>] private RelocSize = 8u

  /// Returns the run of the given kind, or None where the file carries none
  /// of it, which is what an empty run and one named by no offset both are.
  let private region kind offset size =
    if offset = 0 || size = 0u then
      None
    else
      Some { RegionKind = kind
             RegionOffset = uint32 offset
             RegionSize = size }

  /// Returns the two runs a symbol table command names.
  let private symTabRegions cls (cmd: SymTabCmd) =
    let symSize = cmd.NumOfSym * uint32 (entrySizeOfSymbol cls)
    [| region SymbolTable cmd.SymOff symSize
       region StringTable cmd.StrOff cmd.StrSize |]

  /// Returns the six runs a dynamic symbol table command names.
  let private dySymTabRegions cls (cmd: DySymTabCmd) =
    let modSize = cmd.NumModTab * uint32 (entrySizeOfModule cls)
    let indSize = cmd.NumIndirectSym * 4u
    let extRelSize = cmd.NumExtRel * RelocSize
    let locRelSize = cmd.NumLocalRel * RelocSize
    [| region TOCTable (int cmd.TOCOffset) (cmd.NumTOCContents * 8u)
       region ModuleTable (int cmd.ModTabOff) modSize
       region ExtRefTable (int cmd.ExtRefSymOff) (cmd.NumExtRefSym * 4u)
       region IndirectSymbolTable (int cmd.IndirectSymOff) indSize
       region ExtRelocTable (int cmd.ExtRelOff) extRelSize
       region LocalRelocTable (int cmd.LocalRelOff) locRelSize |]

  /// Returns the five runs a dyld information command names.
  let private dyLdInfoRegions (cmd: DyLdInfoCmd) =
    [| region RebaseInfo cmd.RebaseOff cmd.RebaseSize
       region BindInfo cmd.BindOff cmd.BindSize
       region WeakBindInfo cmd.WeakBindOff cmd.WeakBindSize
       region LazyBindInfo cmd.LazyBindOff cmd.LazyBindSize
       region ExportInfo cmd.ExportOff cmd.ExportSize |]

  /// Returns every run of __LINKEDIT the given command names.
  let private regionsOf cls cmd =
    match cmd with
    | SymTab(_, _, c) ->
      symTabRegions cls c
    | DySymTab(_, _, c) ->
      dySymTabRegions cls c
    | DyLdInfo(_, _, c) ->
      dyLdInfoRegions c
    | FuncStarts(_, _, c) ->
      [| region FuncStartsData c.DataOffset c.DataSize |]
    | DataInCode(_, _, c) ->
      [| region DataInCodeTable c.TableOffset c.TableSize |]
    | ChainedFixups(_, _, c) ->
      [| region ChainedFixupsData c.FixupsDataOffset c.FixupsDataSize |]
    | ExportsTrie(_, _, c) ->
      [| region ExportsTrieData c.TrieOffset c.TrieSize |]
    | CodeSign(_, _, c) ->
      [| region CodeSignatureBlob c.BlobOffset c.BlobSize |]
    | _ ->
      [||]

  /// Returns every run of __LINKEDIT the given commands name, in no order of
  /// its own: where each of them sits is what the file says, not what the
  /// commands naming them are ordered by.
  let regionsIn cls cmds =
    cmds |> Array.collect (regionsOf cls) |> Array.choose id

  /// Returns the offset the layout gave the run of the given kind, or the
  /// one the command already holds where the layout gave it none.
  let private placed (places: Map<LinkEditKind, uint32>) kind fallback =
    match Map.tryFind kind places with
    | Some offset -> int offset
    | None -> fallback

  /// Returns that same offset as the unsigned number a command holds it as.
  let private placedU places kind (fallback: uint32) =
    uint32 (placed places kind (int fallback))

  /// Returns the symbol table command naming its two runs where they went.
  let private relocateSymTab places (cmd: SymTabCmd) =
    { cmd with
        SymOff = placed places SymbolTable cmd.SymOff
        StrOff = placed places StringTable cmd.StrOff }

  /// Returns the dynamic symbol table command naming its six runs where they
  /// went.
  let private relocateDySymTab places (cmd: DySymTabCmd) =
    { cmd with
        TOCOffset = placedU places TOCTable cmd.TOCOffset
        ModTabOff = placedU places ModuleTable cmd.ModTabOff
        ExtRefSymOff = placedU places ExtRefTable cmd.ExtRefSymOff
        IndirectSymOff = placedU places IndirectSymbolTable cmd.IndirectSymOff
        ExtRelOff = placedU places ExtRelocTable cmd.ExtRelOff
        LocalRelOff = placedU places LocalRelocTable cmd.LocalRelOff }

  /// Returns the dyld information command naming its five runs where they
  /// went.
  let private relocateDyLdInfo places (cmd: DyLdInfoCmd) =
    { cmd with
        RebaseOff = placed places RebaseInfo cmd.RebaseOff
        BindOff = placed places BindInfo cmd.BindOff
        WeakBindOff = placed places WeakBindInfo cmd.WeakBindOff
        LazyBindOff = placed places LazyBindInfo cmd.LazyBindOff
        ExportOff = placed places ExportInfo cmd.ExportOff }

  /// Returns the command with every run of __LINKEDIT it names at the offset
  /// the layout gave that run. Nothing else of the command changes: what a
  /// run holds and how long it is are the image's to say, and only where it
  /// sits is settled this late.
  let relocate places cmd =
    match cmd with
    | SymTab(t, s, c) ->
      SymTab(t, s, relocateSymTab places c)
    | DySymTab(t, s, c) ->
      DySymTab(t, s, relocateDySymTab places c)
    | DyLdInfo(t, s, c) ->
      DyLdInfo(t, s, relocateDyLdInfo places c)
    | FuncStarts(t, s, c) ->
      let at = placed places FuncStartsData c.DataOffset
      FuncStarts(t, s, { c with DataOffset = at })
    | DataInCode(t, s, c) ->
      let at = placed places DataInCodeTable c.TableOffset
      DataInCode(t, s, { c with TableOffset = at })
    | ChainedFixups(t, s, c) ->
      let at = placed places ChainedFixupsData c.FixupsDataOffset
      ChainedFixups(t, s, { c with FixupsDataOffset = at })
    | ExportsTrie(t, s, c) ->
      let at = placed places ExportsTrieData c.TrieOffset
      ExportsTrie(t, s, { c with TrieOffset = at })
    | CodeSign(t, s, c) ->
      let at = placed places CodeSignatureBlob c.BlobOffset
      CodeSign(t, s, { c with BlobOffset = at })
    | _ ->
      cmd
