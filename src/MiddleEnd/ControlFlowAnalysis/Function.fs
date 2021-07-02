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

namespace B2R2.MiddleEnd.ControlFlowAnalysis

open System.Collections.Generic
open System.Runtime.InteropServices
open B2R2
open B2R2.FrontEnd.BinInterface
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

/// Function can be either external or regualr.
type FunctionKind =
  /// Regular function.
  | Regular = 0
  /// External function.
  | External = 1

/// Callee's kind.
type CalleeKind =
  /// Callee is a regular function.
  | RegularCallee of Addr
  /// Callee is a set of indirect call targets. This means potential callees
  /// have been analyzed already.
  | IndirectCallees of Set<Addr>
  /// Callee (call target) is unresolved yet. This eventually will become
  /// IndirectCallees after indirect call analyses.
  | UnresolvedIndirectCallees
  | NullCallee

/// NoReturnProperty of a function specifies whether the function will
/// eventually return or not. Some functions, e.g., exit, will never return in
/// any cases, and compilers often remove fall-through edges of callers of such
/// functions.
type NoReturnProperty =
  /// This function will never return. For example, the "exit" function should
  /// have this property.
  | NoRet
  /// Conditionally no-return; function does not return only if the n-th
  /// argument (starting from one) specified is non-zero.
  | ConditionalNoRet of int
  /// Regular case: this is *not* no-return, and we have already performed
  /// parameter analysis to examine the possibility of being conditional no-ret.
  | NotNoRetConfirmed
  /// Regular case: *not* no-return.
  | NotNoRet
  /// When we are not certain: we need further analyses.
  | UnknownNoRet

/// Indirect jump's kind.
type IndirectJumpKind =
  /// We found a corresponding jump table at Addr.
  | JmpTbl of tAddr: Addr
  /// We analyzed this indirect jump, and we found no jump table.
  | NotJmpTbl
  /// We did not analyzed this indirect jump yet.
  | YetAnalyzed

/// Function is a non-overlapping chunk of code in a binary. We do not allow
/// function overlaps. When there exist two functions sharing common basic
/// blocks, B2R2 will create a new function to represent the common blocks.
/// Function can also represent a function defined outside of the current
/// binary. Such functions are called ExternalFunction.
[<AbstractClass>]
type Function (entry, name) =
  let fid = Addr.toFuncName entry
  let callers = SortedSet<Addr> ()
  let mutable noRetProp = UnknownNoRet

  /// Starting address of the function.
  member __.Entry with get(): Addr = entry

  /// Function's unique ID. This field is used to distinguish between functions.
  member __.FunctionID with get(): string = fid

  /// Function's symbolic name.
  member __.FunctionName with get(): string = name

  /// Function's kind. Is this external or regular?
  abstract FunctionKind: FunctionKind

  /// A set of functions which call this function.
  member __.Callers with get() = callers

  /// Register a set of callers to this function.
  member __.RegisterCallers (newCallers: Set<Addr>) =
    callers.UnionWith newCallers

  /// No-return property of this function.
  member __.NoReturnProperty
    with get() = noRetProp and set(b) = noRetProp <- b

/// FakeEdge is a tuple of (Callsite address, Call target address). This is to
/// uniquely identify edges from a call instruction to a fake block. Note that
/// even though there are multiple calls to the same outer function, each of the
/// callsites should be connected to an independent fake block. That's the
/// reason why we use FakeEdge to distinguish them.
type FakeEdge = Addr * Addr

module private RegularFunction =
  /// This is a heuristic to discover __x86.get_pc_thunk- family functions.
  /// We directly compare first 4 bytes of byte code. Because
  /// __x86.get_pc_thunk- family only has 4 bytes for its function body and
  /// their values are fixed.
  let obtainGetPCThunkReg hdl (entry: Addr) =
    match hdl.ISA.Arch with
    | Arch.IntelX86 ->
      match BinHandle.ReadUInt (hdl, entry, 4) with
      | 0xc324048bUL -> YesGetPCThunk <| hdl.RegisterBay.RegIDFromString "EAX"
      | 0xc3241c8bUL -> YesGetPCThunk <| hdl.RegisterBay.RegIDFromString "EBX"
      | 0xc3240c8bUL -> YesGetPCThunk <| hdl.RegisterBay.RegIDFromString "ECX"
      | 0xc324148bUL -> YesGetPCThunk <| hdl.RegisterBay.RegIDFromString "EDX"
      | 0xc324348bUL -> YesGetPCThunk <| hdl.RegisterBay.RegIDFromString "ESI"
      | 0xc3243c8bUL -> YesGetPCThunk <| hdl.RegisterBay.RegIDFromString "EDI"
      | 0xc3242c8bUL -> YesGetPCThunk <| hdl.RegisterBay.RegIDFromString "EBP"
      | _ -> NoGetPCThunk
    | _ -> NoGetPCThunk

/// Regular function is a function that has its own body in the target binary.
/// Therefore, regular functions have their own IR-level CFG.
type RegularFunction private (histMgr: HistoryManager, entry, name, thunkInfo) =
  inherit Function (entry, name)

  let callEdges = SortedList<Addr, CalleeKind> ()
  let syscallSites = SortedSet<Addr> ()
  let indirectJumps = SortedList<Addr, IndirectJumpKind> ()
  let regularVertices = Dictionary<ProgramPoint, Vertex<IRBasicBlock>> ()
  let fakeVertices = Dictionary<FakeEdge, Vertex<IRBasicBlock>> ()
  let coverage = CoverageMaintainer ()
  let mutable callEdgeChanged = false
  let mutable needRecalcSSA = true
  let mutable ircfg = IRCFG.init PersistentGraph
  let mutable ssacfg = SSACFG.init PersistentGraph
  let mutable amountUnwinding = 0UL
  let mutable getPCThunkInfo = thunkInfo
  let mutable minAddr = entry
  let mutable maxAddr = entry

  /// Create a new RegularFunction.
  new (histMgr, hdl, entry) =
    let name =
      match hdl.FileInfo.TryFindFunctionSymbolName entry with
      | Error _ -> Addr.toFuncName entry
      | Ok name -> name
    let thunkInfo = RegularFunction.obtainGetPCThunkReg hdl entry
    RegularFunction (histMgr, entry, name, thunkInfo)

  override __.FunctionKind with get() = FunctionKind.Regular

  /// A sequence of call edges (call site address, callee). That is, a CallEdge
  /// represents a function call edge from the caller bbl to its callee(s).
  member __.CallEdges with get() =
    callEdges
    |> Seq.map (fun (KeyValue (pp, callee)) -> pp, callee)
    |> Seq.toArray

  /// Is the given indirect call unresolved?
  member __.IsUnresolvedIndirectCall callSiteAddr =
    match callEdges.TryGetValue callSiteAddr with
    | true, UnresolvedIndirectCallees -> true
    | _ -> false

  /// Returns the set of call target addresses. This function returns the
  /// correct set regardless of their callee types; for indirect calls, it
  /// returns a set of resolved target addresses, and for direct calls, it
  /// returns a singleton target address set.
  member __.CallTargets callSiteAddr =
    match callEdges.TryGetValue callSiteAddr with
    | true, IndirectCallees targets -> targets
    | true, RegularCallee addr -> Set.singleton addr
    | _ -> Set.empty

  /// Remove call edge information from this function.
  member __.ClearCallEdges () = callEdges.Clear ()

  /// Return only a sequence of unresolved indirect call edge info: a tuple of
  /// (call site addr, fall-through addr).
  member __.UnresolvedIndirectCallEdges with get() =
    __.CallEdges
    |> Array.choose (fun (callSiteAddr, callee) ->
      match callee with
      | UnresolvedIndirectCallees -> Some callSiteAddr
      | _ -> None)

  /// A set of bbl entry points which have syscall at the end of each.
  member __.SyscallSites with get() = syscallSites

  /// Add a syscall callsite.
  member __.AddSysCallSite callSiteAddr =
    syscallSites.Add callSiteAddr |> ignore

  /// Remove the syscall callsite.
  member __.RemoveSysCallSite callSiteAddr =
    syscallSites.Remove callSiteAddr |> ignore

  /// IR-level CFG of this function.
  member __.IRCFG
    with get() = ircfg
    and private set(cfg) = ircfg <- cfg; needRecalcSSA <- true

  /// Check if the given vertex exists in this function.
  member __.HasVertex (v) = regularVertices.ContainsKey v

  /// Find an IRCFG vertex at the given program point.
  member __.FindVertex (pp) = regularVertices.[pp]

  /// Try to find an IRCFG vertex at the given program point.
  member __.TryFindVertex (pp) =
    regularVertices.TryGetValue pp |> Utils.tupleToOpt

  /// Return the current number of regular vertices in this function's IRCFG.
  member __.CountRegularVertices with get() = regularVertices.Count

  /// Fold each regular vertex in this function.
  member __.FoldRegularVertices fn acc = regularVertices |> Seq.fold fn acc

  /// Iterate each regular vertex's program points.
  member __.IterRegularVertexPps fn =
    regularVertices.Keys |> Seq.iter fn

  /// Add a vertex of a parsed regular basic block to this function.
  member __.AddVertex (blk: IRBasicBlock) =
    let v, g = DiGraph.addVertex __.IRCFG blk
    __.IRCFG <- g
    regularVertices.[blk.PPoint] <- v
    coverage.AddCoverage blk.Range
    v

  /// Add a parsed regular basic block (given as an array of instructions along
  /// with its leader address) to this function.
  member __.AddVertex (instrs, leader) =
    let blk = IRBasicBlock.initRegular instrs leader
    let v, g = DiGraph.addVertex __.IRCFG blk
    __.IRCFG <- g
    regularVertices.[leader] <- v
    coverage.AddCoverage blk.Range

  /// Add/replace a regular edge to this function.
  member __.AddEdge (srcPp, dstPp, edge) =
    let src = regularVertices.[srcPp]
    let dst = regularVertices.[dstPp]
    __.IRCFG <- DiGraph.addEdge __.IRCFG src dst edge

  /// Find a call fake block from callSite to callee. The third arg (isTailCall)
  /// indicates whether this is a tail call.
  member private __.GetOrAddFakeVertex (callSite, callee, isTailCall) =
    let edgeKey = callSite, callee
    match fakeVertices.TryGetValue (edgeKey) with
    | true, v -> v
    | _ ->
      let bbl = (* When callee = 0UL, then it means an indirect call. *)
        if callee = 0UL then IRBasicBlock.initIndirectCallBlock callSite
        else IRBasicBlock.initCallBlock callee callSite isTailCall
      let v, g = DiGraph.addVertex __.IRCFG bbl
      __.IRCFG <- g
      fakeVertices.[edgeKey] <- v
      v

  /// Add/replace a direct call edge to this function.
  member __.AddEdge (callerBlk, callSite, callee, isTailCall) =
    let src = regularVertices.[callerBlk]
    let dst = __.GetOrAddFakeVertex (callSite, callee, isTailCall)
    callEdges.[callSite] <-
      if callee = 0UL then NullCallee else RegularCallee callee
    callEdgeChanged <- true
    __.IRCFG <- DiGraph.addEdge __.IRCFG src dst CallEdge

  /// Add/replace an indirect call edge to this function.
  member __.AddEdge (callerBlk, callSite) =
    let src = regularVertices.[callerBlk]
    let dst = __.GetOrAddFakeVertex (callSite, 0UL, false)
    callEdges.[callSite] <- UnresolvedIndirectCallees
    callEdgeChanged <- true
    __.IRCFG <- DiGraph.addEdge __.IRCFG src dst IndirectCallEdge

  /// Add/replace a ret edge to this function.
  member __.AddEdge (callSite, callee, ftAddr) =
    let src = __.GetOrAddFakeVertex (callSite, callee, false)
    let dst = regularVertices.[(ProgramPoint (ftAddr, 0))]
    __.IRCFG <- DiGraph.addEdge __.IRCFG src dst RetEdge

  /// Update the call edge info.
  member __.UpdateCallEdgeInfo (callSiteAddr, callee) =
    callEdges.[callSiteAddr] <- callee
    callEdgeChanged <- true

  /// Remove the basic block at the given program point from this function.
  member private __.RemoveVertex (v: Vertex<IRBasicBlock>) =
    __.IRCFG <- DiGraph.removeVertex __.IRCFG v
    if v.VData.IsFakeBlock () then
      let callSite = v.VData.FakeBlockInfo.CallSite
      let edgeKey = callSite, v.VData.PPoint.Address
      fakeVertices.Remove (edgeKey) |> ignore
      callEdges.Remove callSite |> ignore
    else
      regularVertices.Remove v.VData.PPoint |> ignore
      coverage.RemoveCoverage v.VData.Range

  /// Remove the regular basic block at the given program point from this
  /// function.
  member __.RemoveVertex (pp: ProgramPoint) =
    regularVertices.[pp] |> __.RemoveVertex

  /// Remove the fake block from this function.
  member __.RemoveFakeVertex ((callSite, _) as fakeEdgeKey) =
    let v = fakeVertices.[fakeEdgeKey]
    __.IRCFG <- DiGraph.removeVertex __.IRCFG v
    fakeVertices.Remove (fakeEdgeKey) |> ignore
    callEdges.Remove callSite |> ignore

  /// Remove the given edge.
  member __.RemoveEdge (src, dst) =
    __.IRCFG <- DiGraph.removeEdge __.IRCFG src dst

  /// Remove the given edge.
  member __.RemoveEdge (src, dst, _kind) =
    __.IRCFG <- DiGraph.removeEdge __.IRCFG src dst

  static member AddEdgeByType (fn: RegularFunction)
                              (src: Vertex<IRBasicBlock>)
                              (dst: Vertex<IRBasicBlock>) e =
    match e with
    | CallEdge ->
      let callSite = dst.VData.FakeBlockInfo.CallSite
      let callee = dst.VData.PPoint.Address
      let isTailCall = dst.VData.FakeBlockInfo.IsTailCall
      fn.AddEdge (src.VData.PPoint, callSite, callee, isTailCall)
    | IndirectCallEdge ->
      fn.AddEdge (src.VData.PPoint, dst.VData.FakeBlockInfo.CallSite)
    | RetEdge ->
      let callSite = src.VData.FakeBlockInfo.CallSite
      let ftAddr = dst.VData.PPoint.Address
      fn.AddEdge (callSite, src.VData.PPoint.Address, ftAddr)
    | _ -> (* regular edges *)
      fn.AddEdge (src.VData.PPoint, dst.VData.PPoint, e)

  /// Split the given IR-level vertex (v) at the given point (splitPoint), and
  /// add the resulting vertices to the graph.
  member private __.AddByDividingVertex v (splitPoint: ProgramPoint) =
    let insInfos = (v: Vertex<IRBasicBlock>).VData.InsInfos
    let srcInfos, dstInfos =
      insInfos
      |> Array.partition (fun insInfo ->
        insInfo.Instruction.Address < splitPoint.Address)
    let srcBlk = IRBasicBlock.initRegular srcInfos v.VData.PPoint
    let dstBlk = IRBasicBlock.initRegular dstInfos splitPoint
    let src = __.AddVertex srcBlk
    let dst = __.AddVertex dstBlk
    __.AddEdge (src.VData.PPoint, dst.VData.PPoint, FallThroughEdge)
    struct (src, dst)

  /// Split the BBL at bblPoint into two at the splitPoint. This function
  /// returns the second block located at the splitPoint.
  member __.SplitBBL (bblPoint: ProgramPoint, splitPoint: ProgramPoint) =
    assert (bblPoint < splitPoint)
    let v = regularVertices.[bblPoint]
    let ins, outs, cycle = categorizeNeighboringEdges __.IRCFG v
    ins |> List.iter (fun (p, kind) -> __.RemoveEdge (p, v, kind))
    outs |> List.iter (fun (s, kind) -> __.RemoveEdge (v, s, kind))
    cycle |> Option.iter (fun kind -> __.RemoveEdge (v, v, kind))
    __.RemoveVertex v
    let struct (src, dst) = __.AddByDividingVertex v splitPoint
    ins |> List.iter (fun (p, e) -> RegularFunction.AddEdgeByType __ p src e)
    outs |> List.iter (fun (s, e) -> RegularFunction.AddEdgeByType __ dst s e)
    cycle |> Option.iter (fun e -> RegularFunction.AddEdgeByType __ dst src e)
    regularVertices.[bblPoint] <- src
    regularVertices.[splitPoint] <- dst
    dst

  /// Split the BBL at bblPoint into two at the splitPoint, and make the
  /// splitPoint be a new function's entry block. This function returns the
  /// newly created function, along with a test function that can check perform
  /// a membership test of a program point in the newly constructed graph.
  member __.SplitFunc (hdl, bblPoint, splitPoint) =
    let newBlk = __.SplitBBL (bblPoint, splitPoint)
    let newFn = RegularFunction (histMgr, hdl, splitPoint.Address)
    let reachableNodes, reachableEdges = getReachables __.IRCFG newBlk
    reachableNodes |> Set.iter (fun v ->
      if v.VData.IsFakeBlock () then () (* Fake blocks will be added below. *)
      else
        let lastAddr = v.VData.LastInstruction.Address
        if syscallSites.Contains lastAddr then
          __.RemoveSysCallSite lastAddr
          newFn.AddSysCallSite lastAddr
        else ()
        __.RemoveVertex v
        newFn.AddVertex (v.VData) |> ignore)
    reachableEdges |> Set.iter (fun (src, dst, e) ->
      RegularFunction.AddEdgeByType newFn src dst e)
    newFn

  member private __.RemoveUnreachableInfo acc (v: Vertex<IRBasicBlock>) =
    v.VData.Instructions
    |> Array.fold (fun acc i ->
      let insAddr = i.Address
      if syscallSites.Contains insAddr then
        syscallSites.Remove insAddr |> ignore
      else ()
      if indirectJumps.ContainsKey insAddr then
        let kv = insAddr, indirectJumps.[insAddr]
        indirectJumps.Remove insAddr |> ignore
        kv :: acc
      else acc
    ) acc

  /// Make the BBL (located at bblAddr) as a new function's entry. This function
  /// returns a set of nodes that became unreachable as we perform the
  /// transformation.
  member __.BBLToFunc bblAddr =
    let g = __.IRCFG
    let root = DiGraph.findVertexBy g (fun v -> v.VData.PPoint.Address = entry)
    let v = DiGraph.findVertexBy g (fun v -> v.VData.PPoint.Address = bblAddr)
    let srcs = DiGraph.getPreds g v
    let filteredSrcs = srcs |> List.filter (fun s ->
      DiGraph.findEdgeData g s v <> CallFallThroughEdge)
    let g = srcs |> List.fold (fun g pred -> DiGraph.removeEdge g pred v) g
    let reachables = Traversal.foldPostorder g [root] (fun acc v -> v :: acc) []
    let allVertices = DiGraph.getVertices g
    let unreachables = Set.difference allVertices (Set.ofList reachables)
    __.IRCFG <- g
    let removedIndJmps =
      unreachables |> Set.fold (fun acc v ->
        let acc = __.RemoveUnreachableInfo acc v
        __.RemoveVertex v
        acc) []
    filteredSrcs
    |> List.filter (fun s -> not (Set.contains s unreachables))
    |> List.iter (fun srcV ->
      if srcV.VData.IsFakeBlock () then () (* No-return case. *)
      else
        let callerBlk = srcV.VData.PPoint
        let callSite = srcV.VData.LastInstruction.Address
        __.AddEdge (callerBlk, callSite, bblAddr, true))
    unreachables, removedIndJmps

  /// This field indicates the amount of stack unwinding happening at the return
  /// of this function. This value is 0 if caller cleans the stack (e.g.,
  /// cdecl). That is, this value is only meaning for calling conventions where
  /// callee cleans up the stack, such as stdcall.
  member __.AmountUnwinding
    with get() = amountUnwinding and set(n) = amountUnwinding <- n

  /// This field is to remember a register ID that holds a PC value. When this
  /// function is deemed as a special thunk (e.g., *_get_pc_thunk), the register
  /// will hold a PC value after this function returns.
  member __.GetPCThunkInfo
    with get() = getPCThunkInfo and set(i) = getPCThunkInfo <- i

  /// Return a Dictionary that maps an indirect jump address to its jump kinds.
  member __.IndirectJumps with get() = indirectJumps

  /// Return an array of yet-analyzed indirect jump addresses.
  member __.YetAnalyzedIndirectJumpAddrs
    with get() =
      indirectJumps
      |> Seq.choose (fun (KeyValue (indJumpAddr, kind)) ->
        match kind with
        | YetAnalyzed -> Some indJumpAddr
        | _ -> None)
      |> Seq.toList

  /// Retrieve the currently known jump table addresses.
  member __.JumpTableAddrs
    with get() =
      indirectJumps
      |> Seq.choose (fun (KeyValue (indJumpAddr, kind)) ->
        match kind with
        | JmpTbl (tAddr) -> Some tAddr
        | _ -> None)
      |> Seq.toList

  /// Retrieve the jump table address of a given indirect jump address.
  member __.FindJumpTableAddr indJumpAddr =
    match indirectJumps.TryGetValue indJumpAddr with
    | true, JmpTbl addr -> addr
    | _ -> Utils.impossible ()

  /// Register a new indirect jump as YetAnalyzed.
  member __.RegisterNewIndJump indJumpAddr =
    indirectJumps.[indJumpAddr] <- YetAnalyzed

  /// Mark the given indirect jump as unknown.
  member __.MarkIndJumpAsUnknown indJumpAddr =
    indirectJumps.[indJumpAddr] <- NotJmpTbl

  /// Mark the given indirect jump as analyzed; we know the table address of it.
  member __.MarkIndJumpAsAnalyzed indJumpAddr tAddr =
    indirectJumps.[indJumpAddr] <- JmpTbl tAddr

  /// The minimum address of this function's range.
  member __.MinAddr with get() = minAddr and set(a) = minAddr <- a

  /// The maximum address of this function's range.
  member __.MaxAddr with get() = maxAddr and set(a) = maxAddr <- a

  /// Set the boundary of this function; set both MinAddr and MaxAddr.
  member __.SetBoundary minAddr maxAddr =
    __.MinAddr <- minAddr
    __.MaxAddr <- maxAddr

  /// Retrieve the SSA CFG of this function.
  member __.GetSSACFG hdl =
    if needRecalcSSA then
      let root =
        DiGraph.getUnreachables __.IRCFG
        |> List.find (fun v -> v.VData.PPoint.Address = __.Entry)
      let struct (ssa, root) = SSACFG.ofIRCFG hdl __.IRCFG root
      let struct (ssa, root) = SSAPromotion.promote hdl ssa root
      ssacfg <- ssa
      needRecalcSSA <- false
      ssa, root
    else
      let root =
        DiGraph.getUnreachables ssacfg
        |> List.find (fun v -> v.VData.PPoint.Address = __.Entry)
      ssacfg, root

  member private __.AddXRef entry xrefs callee =
    match Map.tryFind callee xrefs with
    | Some callers -> Map.add callee (Set.add entry callers) xrefs
    | None -> Map.add callee (Set.singleton entry) xrefs

  /// Accumulate cross references only if there is a change in the call edges.
  member __.AccumulateXRefs xrefs =
    if callEdgeChanged then
      callEdgeChanged <- false
      let entry = __.Entry
      callEdges
      |> Seq.fold (fun xrefs (KeyValue (_, callee)) ->
        match callee with
        | RegularCallee callee -> __.AddXRef entry xrefs callee
        | IndirectCallees callees -> Set.fold (__.AddXRef entry) xrefs callees
        | UnresolvedIndirectCallees -> xrefs
        | NullCallee -> xrefs) xrefs
    else xrefs

  /// Return the sorted gaps' ranges. Each range is a mapping from a start
  /// address to an end address (exclusive).
  member __.GapAddresses
    with get() = coverage.ComputeGapAddrs __.Entry __.MaxAddr

  /// Check if the function regards the given address as a valid instruction
  /// address.
  member __.IsAddressCovered addr =
    coverage.IsAddressCovered addr

/// External function is a function that is defined in another binary. Functions
/// in PLT is also considered as an external function, and we always link a PLT
/// entry with its corresponding GOT entry to consider such a pair as an
/// external function, where its entry is located at the GOT and its trampoline
/// is at the PLT.
type ExternalFunction private (entry, name, trampoline) =
  inherit Function (entry, name)

  /// Known list of no-return function names.
  static let knownNoReturnFuncs =
    [| "__assert_fail"
       "__stack_chk_fail"
       "abort"
       "_abort"
       "exit"
       "_exit"
       "__longjmp_chk"
       "__cxa_throw"
       "_Unwind_Resume"
       "_ZSt20__throw_length_errorPKc"
       "_gfortran_stop_numeric"
       "__libc_start_main"
       "longjmp" |]

  override __.FunctionKind with get() = FunctionKind.External

  /// If there is a trampoline (e.g., PLT) for the external function, this
  /// function returns the address of it.
  member __.TrampolineAddr ([<Out>] addr: byref<Addr>) =
    match trampoline with
    | 0UL -> false
    | _ -> addr <- trampoline; true

  /// Create a new ExternalFunction.
  static member Init entry name trampoline =
    let noretProp =
      if Array.contains name knownNoReturnFuncs then NoRet
      elif name = "error" || name = "error_at_line" then ConditionalNoRet 1
      else NotNoRet
    ExternalFunction (entry, name, trampoline, NoReturnProperty = noretProp)
