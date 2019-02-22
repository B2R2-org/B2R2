(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Soomin Kim <soomink@kaist.ac.kr>
          Sang Kil Cha <sangkilc@kaist.ac.kr>

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

/// This module finds (disassembly-level) basic block leader and function starts
/// as many as possible
module B2R2.BinGraph.Boundary

open B2R2
open B2R2.BinFile
open B2R2.FrontEnd
open B2R2.BinIR.LowUIR

let initFunction hdl (funcs: Funcs) entry =
  let found, _ = funcs.TryGetValue entry
  if found then ()
  else
    let found, name = hdl.FileInfo.TryFindFunctionSymbolName entry
    if found then funcs.[entry] <- Function (entry, name)
    else funcs.[entry] <- Function (entry, "func_" + entry.ToString("X"))

/// Entry point is meant to be starting addresses of functions. Since this is
/// not enough to grep all entry points, we'll collect more entry points by
/// investigating call instructions.
let getInitialEntries hdl (builder: CFGBuilder) funcs =
  let fi = hdl.FileInfo
  fi.GetFunctionAddresses () |> Seq.iter (initFunction hdl funcs)
  initFunction hdl funcs fi.EntryPoint
  if fi.TextStartAddr = fi.EntryPoint then ()
  else initFunction hdl funcs fi.TextStartAddr
  builder, funcs

/// TODO: This will be a heuristic to find function entries by prologue idioms
let findEntriesByPattern hdl builder funcs =
  builder, funcs

let inline private getBranchTarget (instr: Instruction) =
  instr.DirectBranchTarget () |> Utils.tupleToOpt

let inline isExitCall hdl (instr: Instruction) =
  if instr.IsCall () then
    match getBranchTarget instr with
    | Some addr ->
      let found, name = hdl.FileInfo.TryFindFunctionSymbolName addr
      if found then
        name = "__assert_fail" || name = "_abort" || name = "_exit"
      else false
    | _ -> false
  else false

/// Remove possibilities call instructions are considered as jump
let inline isExit hdl (instr: Instruction) = // FIXME: Cleanup needed
  instr.IsExit () && (not <| instr.IsCall ()) || isExitCall hdl instr

/// XXX: move this to BinHandler
/// This is a slightly different version of that of
/// FrontEnd/FrontEnd.Utils/Parser.fs. We don't separate basic blocks with
/// call instructions.
let parseBlk hdl (builder: CFGBuilder) addr =
  let rec parseLoop acc addr =
    if not <| builder.IsInteresting hdl addr then
      Error <| List.rev acc
    else
      match BinHandler.TryParseInstr hdl addr with
      | None -> Error <| List.rev acc
      | Some instr ->
        let acc = instr :: acc
        if isExit hdl instr then Ok <| List.rev acc
        else parseLoop acc (addr + uint64 instr.Length)
  parseLoop [] addr

(*
let isNop (instr: Instruction) =
  instr.IsNop ()

let isNullPadding hdl addr =
  let bytes =
    BinHandler.ReadBytes (hdl, addr, int <| 0x10UL - (addr &&& 0xFUL))
  Array.forall (fun b -> b = 0uy) bytes

/// Heuristic
let isDummyLeader hdl addr instrs =
  isNop (List.head instrs) || isNullPadding hdl addr
*)
/// TODO: Fill here
let checkDummyLeader () = false

let addBranchTarget hdl (builder: CFGBuilder) funcs leaders instr isCall =
  match getBranchTarget instr with
  /// TODO: Need to identify whether call target is really a function start
  | Some addr when builder.IsInteresting hdl addr ->
    if isCall then initFunction hdl funcs addr
    builder, funcs, addr :: leaders
  | Some addr ->
    let found, name = hdl.FileInfo.TryFindFunctionSymbolName addr
    /// TODO: Insert here libc_start_main heuristic to find main function
    if found && name = "__libc_start_main" then builder, funcs, leaders
    else builder, funcs, leaders
  | None -> builder, funcs, leaders

let collectEntry hdl builder funcs leaders (instr: Instruction) =
  if instr.IsCall () then addBranchTarget hdl builder funcs leaders instr true
  else builder, funcs, leaders

let rec scanInstrs hdl (builder: CFGBuilder) funcs leaders = function
  | instr :: instrs ->
    builder.AddInstr instr
    let builder, funcs, leaders = collectEntry hdl builder funcs leaders instr
    scanInstrs hdl builder funcs leaders instrs
  | [] -> builder, funcs, leaders

let rec parseDisasmBlk hdl (builder: CFGBuilder) funcs addr leaders =
  match parseBlk hdl builder addr with
  | Error instrs ->
    if List.length instrs <> 0 then
      let builder, funcs, leaders = scanInstrs hdl builder funcs leaders instrs
      let last = List.last instrs
      let nextAddr = last.Address + uint64 last.Length
      let newAddr = (nextAddr &&& 0xFFFFFFFFFFFFFFF0UL) + 0x10UL
      builder.AddDisasmLeader addr
      builder.UpdateParsableOfDisasmLeader addr
      if builder.DisasmEnd < nextAddr then builder.DisasmEnd <- nextAddr
      let leaders = nextAddr :: leaders
      let leaders = if checkDummyLeader () then newAddr :: leaders else leaders
      addBranchTarget hdl builder funcs leaders last false
    else
      builder.AddDisasmLeader addr
      builder, funcs, leaders
  | Ok instrs ->
    let builder, funcs, leaders = scanInstrs hdl builder funcs leaders instrs
    let last = List.last instrs
    let nextAddr = last.Address + uint64 last.Length
    let newAddr = (nextAddr &&& 0xFFFFFFFFFFFFFFF0UL) + 0x10UL
    builder.AddDisasmLeader addr
    builder.UpdateParsableOfDisasmLeader addr
    if builder.DisasmEnd < nextAddr then builder.DisasmEnd <- nextAddr
    let leaders = nextAddr :: leaders
    let leaders = if checkDummyLeader () then newAddr :: leaders else leaders
    addBranchTarget hdl builder funcs leaders last false

/// Scan disassembly-level basic block leaders.
let rec scanDisasmLeaders hdl (builder: CFGBuilder) funcs = function
  | leader :: leaders when builder.ExistDisasmLeader leader ->
    scanDisasmLeaders hdl builder funcs leaders
  | leader :: leaders when not <| builder.IsInteresting hdl leader ->
    builder.AddDisasmLeader leader
    scanDisasmLeaders hdl builder funcs leaders
  | leader :: leaders ->
    let builder, funcs, leaders =
      parseDisasmBlk hdl builder funcs leader leaders
    scanDisasmLeaders hdl builder funcs leaders
  | [] -> builder, funcs

/// Find leaders at disassembly level. Because the concept of leader totally
/// includes entry, we can find undiscovered entries while scanning
/// instructions.
let rec findDisasmLeaders hdl builder funcs = function
  | entry :: entries ->
    let builder, funcs = scanDisasmLeaders hdl builder funcs [entry]
    findDisasmLeaders hdl builder funcs entries
  | [] -> builder, funcs

let rec identifyDisasmBoundary hdl (builder: CFGBuilder) (funcs: Funcs) =
  let entries = funcs.Keys |> Set.ofSeq
  let disasmLeaders = builder.GetDisasmLeaders () |> Set.ofList
  let diff = Set.difference entries disasmLeaders
  if Set.isEmpty diff then builder, funcs
  else
    Set.iter (initFunction hdl funcs) diff
    findDisasmLeaders hdl builder funcs <| Set.toList diff
    ||> identifyDisasmBoundary hdl

let givePPointToStmtFold (addr, idx, stmts) = function
  | ISMark (addr, _) as stmt -> addr, 1, ((addr, 0), stmt) :: stmts
  | stmt -> addr, idx + 1, ((addr, idx), stmt) :: stmts

let givePPointToStmt stmts =
  let _, _, stmts = List.fold givePPointToStmtFold (0UL, 0, []) stmts
  List.rev stmts

let inline isInnerLeader (sPpoint, ePpoint) ppoint =
  ppoint >= sPpoint && ppoint < ePpoint

/// We only consider spliting disassembly level basic blocks into ir level
/// basic blocks. To find new disassembly level basic block leader is out of
/// scope.
let rec scanIRLeaders hdl (builder: CFGBuilder) boundary = function
  | (ppoint, (LMark symb as stmt)) :: stmts ->
    builder.AddStmt ppoint stmt
    builder.AddLabel ppoint symb
    builder.AddIRLeader ppoint
    builder.UpdateLiftableOfIRLeader ppoint
    scanIRLeaders hdl builder boundary stmts
  | (((addr, idx) as ppoint), (InterJmp (_, Num bv) as stmt)) :: stmts ->
    builder.AddStmt ppoint stmt
    let newPpoint = BitVector.toUInt64 bv, 0
    if isInnerLeader boundary newPpoint then
      builder.AddIRLeader newPpoint
      builder.UpdateLiftableOfIRLeader newPpoint
    let instr = builder.GetInstr addr
    if not <| instr.IsCall () then
      builder.AddIRLeader (addr, idx + 1)
      builder.UpdateLiftableOfIRLeader (addr, idx + 1)
    elif isExitCall hdl instr then
      builder.AddIRLeader (addr, idx + 1)
      builder.UpdateLiftableOfIRLeader (addr, idx + 1)
    scanIRLeaders hdl builder boundary stmts
  | (ppoint, (InterCJmp (_, _, Num tBv, Num fBv) as stmt)) :: stmts ->
    let addr, idx = ppoint
    builder.AddStmt ppoint stmt
    let tPpoint = BitVector.toUInt64 tBv, 0
    let fPpoint = BitVector.toUInt64 fBv, 0
    if isInnerLeader boundary tPpoint then
      builder.AddIRLeader tPpoint
      builder.UpdateLiftableOfIRLeader tPpoint
    if isInnerLeader boundary fPpoint then
      builder.AddIRLeader fPpoint
      builder.UpdateLiftableOfIRLeader fPpoint
    builder.AddIRLeader (addr, idx + 1)
    builder.UpdateLiftableOfIRLeader (addr, idx + 1)
    scanIRLeaders hdl builder boundary stmts
  | (((addr, idx) as ppoint), (Jmp _ as stmt)) :: stmts
  | (((addr, idx) as ppoint), (CJmp _ as stmt)) :: stmts
  | (((addr, idx) as ppoint), (InterJmp _ as stmt)) :: stmts
  | (((addr, idx) as ppoint), (InterCJmp _ as stmt)) :: stmts
  | (((addr, idx) as ppoint), ((SideEffect Halt) as stmt)) :: stmts ->
    builder.AddStmt ppoint stmt
    if not <| (builder.GetInstr addr).IsCall () then
      builder.AddIRLeader (addr, idx + 1)
      builder.UpdateLiftableOfIRLeader (addr, idx + 1)
    scanIRLeaders hdl builder boundary stmts
  | (ppoint, stmt) :: stmts ->
    builder.AddStmt ppoint stmt
    scanIRLeaders hdl builder boundary stmts
  | [] -> builder

/// This is also different version of that of
/// FrontEnd/FrontEnd.Utils/Lifter.fs because our basic block is more
/// fine-grainded, so we don't want to lift instructions more than our basic
/// block range.
let liftIRBlk hdl (builder: CFGBuilder) sAddr addrs =
  let rec liftLoop acc addr addrs =
    if addr = List.head addrs then acc, addr
    elif addr > List.head addrs then liftLoop acc addr <| List.tail addrs
    elif not <| builder.IsInteresting hdl addr then acc, addr
    else
      let instr = builder.GetInstr addr
      let stmts =
        BinHandler.LiftInstr hdl instr
        |> LocalOptimizer.Optimize |> Array.toList
      let acc = List.append acc stmts
      let nextAddr = addr + uint64 instr.Length
      liftLoop acc nextAddr addrs
  let stmts, eAddr = liftLoop [] sAddr addrs
  givePPointToStmt stmts, eAddr

let rec findIRLeaders hdl (builder: CFGBuilder) = function
  | sAddr :: ((_ :: _) as leaders) ->
    if builder.GetParsableByDisasmLeader sAddr then
      let stmts, eAddr = liftIRBlk hdl builder sAddr leaders
      let sPpoint = sAddr, 0
      let ePpoint = eAddr, 0
      builder.AddIRLeader sPpoint
      builder.UpdateLiftableOfIRLeader sPpoint
      let builder = scanIRLeaders hdl builder (sPpoint, ePpoint) stmts
      findIRLeaders hdl builder leaders
    else
      builder.AddIRLeader (sAddr, 0)
      findIRLeaders hdl builder leaders
  | [ addr ] ->
    if builder.GetParsableByDisasmLeader addr then
      let stmts, eAddr = liftIRBlk hdl builder addr [ builder.DisasmEnd ]
      let sPpoint = addr, 0
      let ePpoint = eAddr, 0
      builder.AddIRLeader sPpoint
      builder.UpdateLiftableOfIRLeader sPpoint
      scanIRLeaders hdl builder (sPpoint, ePpoint) stmts
    else builder
  | [] -> builder

let identifyIRBoundary hdl (builder: CFGBuilder) funcs =
  let builder = findIRLeaders hdl builder <| builder.GetDisasmLeaders ()
  builder, funcs

let identifyBoundaries hdl boundary builder funcs =
  match boundary with
  /// We already have basic boundary info -> we need another analyses
  | Some _ -> failwith "Not Implemented"
  | None ->
    (builder, funcs)
    ||> getInitialEntries hdl
    ||> findEntriesByPattern hdl
    ||> identifyDisasmBoundary hdl
    ||> identifyIRBoundary hdl
