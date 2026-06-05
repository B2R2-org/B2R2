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

namespace B2R2.RearEnd.BinExplore

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile
open B2R2.MiddleEnd
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.DataFlow
open B2R2.RearEnd.Visualization

/// Represents the kind of control flow graph (CFG) to be displayed.
type CFGKind =
  /// Disassembly CFG.
  | Disasm = 0
  /// LowUIR CFG.
  | LowUIR = 1
  /// SSA form of the IR CFG.
  | SSA = 2
  /// Call graph.
  | Call = 3

[<RequireQualifiedAccess>]
module API =

  let inline private (>>=) opt ([<InlineIfLambda>] f) =
    match opt with
    | Ok x -> f x
    | Error e -> Error e

  /// Returns the current binary file path.
  let getFilePath (arbiter: Arbiter<_, _>) =
    arbiter.GetBinaryBrew()
    >>= fun brew -> Ok brew.BinHandle.File.Path

  let private getCFG fnAddr cw ch cfgType (brew: BinaryBrew<_, _>) =
    try
      let func = brew.Functions.Find(addr = fnAddr)
      let g = func.CFG
      match cfgType with
      | CFGKind.LowUIR ->
        let roots = g.Roots |> Seq.toList
        Visualizer.toVisGraph g roots cw ch
        |> Ok
      | CFGKind.Disasm ->
        let file = brew.BinHandle.File
        let disasmBuilder = AsmWordDisasmBuilder(true, file, file.ISA.WordSize)
        let g = DisasmCFG(disasmBuilder, g)
        let roots = g.Roots |> Seq.toList
        Visualizer.toVisGraph g roots cw ch
        |> Ok
      | CFGKind.SSA ->
        let factory = SSA.SSALifterFactory.Create brew.BinHandle
        let ssaCFG = factory.Lift g
        let roots = ssaCFG.Roots |> List.ofArray
        Visualizer.toVisGraph ssaCFG roots cw ch
        |> Ok
      | _ ->
        Error $"Bad CFG type given: {cfgType}"
    with e ->
  #if DEBUG
      eprintfn "%A" e
      Error e.Message
  #else
      Error e.Message
  #endif

  /// Returns the disassembly CFG of the given function address.
  let getDisasmCFG (arbiter: Arbiter<_, _>) fnAddr cw ch =
    arbiter.GetBinaryBrew()
    >>= getCFG fnAddr cw ch CFGKind.Disasm

  /// Returns the LowUIR CFG of the given function address.
  let getLowUIRCFG (arbiter: Arbiter<_, _>) fnAddr cw ch =
    arbiter.GetBinaryBrew()
    >>= getCFG fnAddr cw ch CFGKind.LowUIR

  /// Returns the SSA CFG of the given function address.
  let getSSACFG (arbiter: Arbiter<_, _>) fnAddr cw ch =
    arbiter.GetBinaryBrew()
    >>= getCFG fnAddr cw ch CFGKind.SSA

  let private getCallGraph (brew: BinaryBrew<_, _>) =
    try
      let g, roots = CallGraph.create BinGraph.Imperative brew
      let cw, ch = Visualizer.CharWidth, Visualizer.CharHeight
      Visualizer.toVisGraph g roots cw ch
      |> Ok
    with e ->
  #if DEBUG
      eprintfn "%A" e
      failwith "[FATAL]: Failed to generate CG"
  #else
      Error e.Message
  #endif

  /// Returns the call graph of the binary.
  let getCallCFG (arbiter: Arbiter<_, _>) =
    arbiter.GetBinaryBrew()
    >>= getCallGraph

  let private getInternalFunctions (brew: BinaryBrew<_, _>) =
    brew.Functions.Sequence
    |> Seq.filter (fun fn -> not fn.IsExternal)
    |> Seq.sortBy (fun fn -> fn.EntryPoint)
    |> Seq.toArray
    |> Ok

  let private getExternalFunctions (brew: BinaryBrew<_, _>) =
    brew.Functions.Sequence
    |> Seq.filter (fun fn -> fn.IsExternal)
    |> Seq.sortBy (fun fn -> fn.EntryPoint)
    |> Seq.toArray
    |> Ok

  /// Returns the list of functions in the binary, sorted by their entry points.
  /// If `isInternal` is true, only internal functions are returned; otherwise,
  /// only external functions are returned.
  let getFunctions (arbiter: Arbiter<_, _>) isInternal =
    if isInternal then arbiter.GetBinaryBrew() >>= getInternalFunctions
    else arbiter.GetBinaryBrew() >>= getExternalFunctions

  /// Returns the loaded binary (IBinFile instance).
  let getFile (arbiter: Arbiter<_, _>) =
    arbiter.GetBinaryBrew()
    >>= fun brew -> Ok brew.BinHandle.File

  /// Returns the file format of the loaded binary.
  let getFileFormat (arbiter: Arbiter<_, _>) =
    arbiter.GetBinaryBrew()
    >>= fun brew -> Ok brew.BinHandle.File.Format

  /// Returns the raw bytes at the given address and the size.
  let getBytes (arbiter: Arbiter<_, _>) addr size =
    arbiter.GetBinaryBrew()
    >>= fun brew ->
      let ptr = brew.BinHandle.File.GetBoundedPointer(addr)
      brew.BinHandle.TryReadBytes(ptr, size)
      |> Result.mapError ErrorCase.toMessage

  let private computeConnectedVars chain v =
    match Map.tryFind v chain.UseDefChain with
    | None ->
      match Map.tryFind v chain.DefUseChain with
      | None -> Set.singleton v
      | Some us -> us
    | Some ds ->
      ds
      |> Set.fold (fun s d ->
        match Map.tryFind d chain.DefUseChain with
        | None -> s
        | Some us -> Set.union us s) ds

  let private getEncodedDataflow fnAddr insAddr reg (brew: BinaryBrew<_, _>) =
    try
      let cfg = brew.Functions[fnAddr].CFG
      let chain = DataFlowChain.compute cfg true
      let rid = brew.BinHandle.RegisterFactory.GetRegisterID(name = reg)
      let v = { ProgramPoint = ProgramPoint(insAddr, 0); VarKind = Regular rid }
      computeConnectedVars chain v
      |> Set.toArray
      |> Ok
    with e ->
  #if DEBUG
      eprintfn "%A" e
      failwith "[FATAL]: Failed to obtain dataflow info"
  #else
      Error e.Message
  #endif

  /// Returns the immediate dataflow chain of the given register at the given
  /// instruction address in the given function.
  let getImmediateDataflowChain (arbiter: Arbiter<_, _>) fnAddr insAddr reg =
    arbiter.GetBinaryBrew()
    >>= getEncodedDataflow fnAddr insAddr reg

  /// Returns an array of section infos in the binary.
  let getSections (arbiter: Arbiter<_, _>) =
    arbiter.GetBinaryBrew()
    >>= fun brew ->
      match brew.BinHandle.File.Format with
      | FileFormat.ELFBinary ->
        let elf = brew.BinHandle.File :?> ELFBinFile
        elf.SectionHeaders
        |> Array.map (fun sh ->
          {| Addr = sh.SecAddr
             Name = sh.SecName
             IsLinkage = elf.IsPLT sh
             ELFSectionHeader = Some sh
             PESectionHeader = None
             MachSectionHeader = None |})
        |> Ok
      | FileFormat.PEBinary ->
        let pe = brew.BinHandle.File :?> PEBinFile
        pe.SectionHeaders
        |> Array.map (fun sh ->
          {| Addr = uint64 sh.VirtualAddress
             Name = sh.Name
             IsLinkage = false
             ELFSectionHeader = None
             PESectionHeader = Some sh
             MachSectionHeader = None |})
        |> Ok
      | FileFormat.MachBinary ->
        let macho = brew.BinHandle.File :?> MachBinFile
        macho.Sections
        |> Array.map (fun sh ->
          {| Addr = sh.SecAddr
             Name = sh.SecName
             IsLinkage = false
             ELFSectionHeader = None
             PESectionHeader = None
             MachSectionHeader = Some sh |})
        |> Ok
      | _ ->
        Ok [||]
