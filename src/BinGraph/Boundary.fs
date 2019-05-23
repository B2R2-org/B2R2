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
open B2R2.FrontEnd
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinGraph.DisasHeuristic

let initFunction hdl (builder: CFGBuilder) (funcs: Funcs) entry =
  let found, _ = funcs.TryGetValue entry
  if found then ()
  else
    builder.UnanalyzedFuncs.Add entry |> ignore
    let found, name = hdl.FileInfo.TryFindFunctionSymbolName entry
    if found then funcs.[entry] <- Function (entry, name, hdl)
    else
      funcs.[entry] <- Function (entry, "func_" + entry.ToString("X"), hdl)

/// Entry point is meant to be starting addresses of functions. Since this is
/// not enough to grep all entry points, we'll collect more entry points by
/// investigating call instructions.
let getInitialEntries hdl (builder: CFGBuilder) funcs =
  let fi = hdl.FileInfo
  fi.GetFunctionAddresses () |> Seq.iter (initFunction hdl builder funcs)
  if fi.EntryPoint <> 0UL then initFunction hdl builder funcs fi.EntryPoint
  builder, funcs

/// TODO: This will be a heuristic to find function entries by prologue idioms
let findEntriesByPattern hdl builder funcs =
  builder, funcs

let inline private getBranchTarget (instr: Instruction) =
  instr.DirectBranchTarget () |> Utils.tupleToOpt

let noReturnFuncs = [ "abort" ; "__assert_fail" ; "_abort" ; "_exit" ; "_err" ]

let inline isExitCall hdl (instr: Instruction) =
  if instr.IsCall () then
    match getBranchTarget instr with
    | Some addr ->
      let found, name = hdl.FileInfo.TryFindFunctionSymbolName addr
      if found then List.contains name noReturnFuncs else false
    | _ -> false
  else false

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
        if instr.IsExit () then Ok <| List.rev acc
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

let rec scanInstrs hdl sAddr (builder: CFGBuilder) funcs leaders = function
  | instr :: instrs ->
    builder.AddInstr instr
    scanInstrs hdl sAddr builder funcs leaders instrs
  | [] -> builder, funcs, leaders

let addBranchTarget hdl sAddr (builder: CFGBuilder) funcs leaders (instr: Instruction) =
  let next = instr.Address + uint64 instr.Length
  if instr.IsExit () then
    if instr.IsCall () then
      match getBranchTarget instr with
      | Some addr when builder.IsInteresting hdl addr ->
        initFunction hdl builder funcs addr
        builder, funcs, next :: addr :: leaders
      | Some addr when isLibcStartMain hdl addr ->
        let ptrs = recoverLibcPointers hdl sAddr instr builder
        List.iter (initFunction hdl builder funcs) ptrs
        builder, funcs, next :: ptrs @ leaders
      | Some addr when isExitCall hdl instr -> builder, funcs, leaders
      | Some addr -> builder, funcs, next :: leaders
      | None -> builder, funcs, next :: leaders
    elif instr.IsDirectBranch () then
      match getBranchTarget instr with
      | Some addr when not <| builder.IsInteresting hdl addr ->
        builder, funcs, leaders
      | Some addr ->
        if instr.IsCondBranch () then builder, funcs, addr :: next :: leaders
        else builder, funcs, addr :: leaders
      | None -> builder, funcs, leaders
    elif instr.IsIndirectBranch () then
      if instr.IsCondBranch () then builder, funcs, next :: leaders
      else builder, funcs, leaders
    elif instr.IsInterrupt () then
      let b, num = instr.InterruptNum ()
      if b && num = 0x29L then builder, funcs, leaders
      else builder, funcs, next ::leaders
    else builder, funcs, leaders
  else builder, funcs, next :: leaders

let rec parseDisasmBlk hdl (builder: CFGBuilder) funcs addr leaders =
  match parseBlk hdl builder addr with
  | Error instrs ->
    if List.length instrs <> 0 then
      let builder, funcs, leaders =
        scanInstrs hdl addr builder funcs leaders instrs
      let last = List.last instrs
      let nextAddr = last.Address + uint64 last.Length
      builder.AddDisasmBoundary addr nextAddr
      builder, funcs, leaders
      //addBranchTarget hdl addr builder funcs leaders last
    else builder, funcs, leaders
  | Ok instrs ->
    let builder, funcs, leaders =
      scanInstrs hdl addr builder funcs leaders instrs
    let last = List.last instrs
    let nextAddr = last.Address + uint64 last.Length
    builder.AddDisasmBoundary addr nextAddr
    addBranchTarget hdl addr builder funcs leaders last

/// Scan disassembly-level basic block leaders.
let rec scanDisasmBoundaries hdl (builder: CFGBuilder) funcs = function
  | leader :: leaders when builder.ExistDisasmBoundary leader ->
    scanDisasmBoundaries hdl builder funcs leaders
  | leader :: leaders when not <| builder.IsInteresting hdl leader ->
    scanDisasmBoundaries hdl builder funcs leaders
  | leader :: leaders ->
    let builder, funcs, leaders =
      parseDisasmBlk hdl builder funcs leader leaders
    scanDisasmBoundaries hdl builder funcs leaders
  | [] -> builder, funcs

let rec checkRange (builder: CFGBuilder) addr eAddr =
  match builder.TryGetInstr addr with
  | Some instr ->
    let next = instr.Address + uint64 instr.Length
    if next > eAddr then false
    elif next = eAddr then true
    else checkRange builder next eAddr
  | None -> false

let includesDisasmBoundary builder (sAddr0, eAddr0) (sAddr1, eAddr1) =
  if eAddr0 = eAddr1 then
    if sAddr0 < sAddr1 then checkRange builder sAddr0 sAddr1
    else false
  else false

let rec refineDisasmBoundariesAux (builder: CFGBuilder) = function
  | boundary1 :: ((boundary2 :: _) as boundaries) ->
    if includesDisasmBoundary builder boundary1 boundary2 then
      let sAddr0, _ = boundary1
      let sAddr1, _ = boundary2
      builder.RemoveDisasmBoundary sAddr0
      builder.AddDisasmBoundary sAddr0 sAddr1
      refineDisasmBoundariesAux builder boundaries
    else refineDisasmBoundariesAux builder boundaries
  | [ _ ] | [] -> builder

let refineDisasmBoundaries (builder: CFGBuilder) =
  refineDisasmBoundariesAux builder <| builder.GetDisasmBoundaries ()

/// Find leaders at disassembly level. Because the concept of leader totally
/// includes entry, we can find undiscovered entries while scanning
/// instructions.
let rec findDisasmBoundaries hdl builder funcs = function
  | entry :: entries ->
    let builder, funcs = scanDisasmBoundaries hdl builder funcs [entry]
    findDisasmBoundaries hdl builder funcs entries
  | [] -> refineDisasmBoundaries builder, funcs

let rec identifyDisasmBoundary hdl (builder: CFGBuilder) (funcs: Funcs) =
  let entries = Seq.toList builder.UnanalyzedFuncs
  if List.length entries = 0 then builder, funcs
  else
    List.iter (fun a -> builder.UnanalyzedFuncs.Remove a |> ignore) entries
    findDisasmBoundaries hdl builder funcs entries
    ||> identifyDisasmBoundary hdl

let givePPointToStmtFold (addr, idx, stmts) = function
  | ISMark (addr, _) as stmt -> addr, 1, ((addr, 0), stmt) :: stmts
  | stmt -> addr, idx + 1, ((addr, idx), stmt) :: stmts

let givePPointToStmt stmts =
  let _, _, stmts = List.fold givePPointToStmtFold (0UL, 0, []) stmts
  List.rev stmts

let isInnerLeader (sPpoint, ePpoint) ppoint =
  ppoint >= sPpoint && ppoint < ePpoint

let rec getNextAddr (builder: CFGBuilder) ppoint =
  let addr = fst ppoint
  let instr = builder.GetInstr addr
  instr.Address + uint64 instr.Length

/// We only consider spliting disassembly level basic blocks into ir level
/// basic blocks. To find new disassembly level basic block leader is out of
/// scope.
let rec scanIRLeaders hdl (builder: CFGBuilder) boundary = function
  | (ppoint, (LMark symb as stmt)) :: stmts ->
    builder.AddStmt ppoint stmt
    builder.AddLabel ppoint symb
    builder.AddIRLeader ppoint
    scanIRLeaders hdl builder boundary stmts
  | (ppoint, (InterJmp (_, Num bv, _) as stmt)) :: stmts ->
    builder.AddStmt ppoint stmt
    let newPpoint = BitVector.toUInt64 bv, 0
    if isInnerLeader boundary newPpoint then builder.AddIRLeader newPpoint
    scanIRLeaders hdl builder boundary stmts
  | (ppoint, (InterCJmp (_, _, Num tBv, Num fBv) as stmt)) :: stmts ->
    builder.AddStmt ppoint stmt
    let tPpoint = BitVector.toUInt64 tBv, 0
    let fPpoint = BitVector.toUInt64 fBv, 0
    if isInnerLeader boundary tPpoint then builder.AddIRLeader tPpoint
    if isInnerLeader boundary fPpoint then builder.AddIRLeader fPpoint
    scanIRLeaders hdl builder boundary stmts
  | (ppoint, (SideEffect Halt as stmt)) :: stmts ->
    builder.AddStmt ppoint stmt
    scanIRLeaders hdl builder boundary stmts
  | (ppoint, (SideEffect (Interrupt 0x29) as stmt)) :: stmts ->
    builder.AddStmt ppoint stmt
    scanIRLeaders hdl builder boundary stmts
  | (ppoint, (SideEffect UndefinedInstr as stmt)) :: stmts ->
    builder.AddStmt ppoint stmt
    scanIRLeaders hdl builder boundary stmts
  | (ppoint, (SideEffect _ as stmt)) :: stmts ->
    builder.AddStmt ppoint stmt
    let addr = getNextAddr builder ppoint
    builder.AddIRLeader (addr, 0)
    scanIRLeaders hdl builder boundary stmts
  | (ppoint, stmt) :: stmts ->
    builder.AddStmt ppoint stmt
    scanIRLeaders hdl builder boundary stmts
  | [] -> builder

let rec getIRBBLEnd hdl (builder: CFGBuilder) prev ppoint ePpoint =
  match builder.TryGetStmt ppoint with
  | None -> prev
  | Some (InterJmp _) | Some (InterCJmp _) | Some (Jmp _) | Some (CJmp _)
  | Some (SideEffect _) -> ppoint
  | Some (IEMark addr) ->
    if (addr, 0) = ePpoint then ppoint
    else getIRBBLEnd hdl builder ppoint (addr, 0) ePpoint
  | _ ->
    let addr, cnt = ppoint
    getIRBBLEnd hdl builder ppoint (addr, cnt + 1) ePpoint

let rec scanIRBoundaries hdl builder last = function
  | leader :: ((nextLeader :: _) as leaders) ->
    let ePpoint = getIRBBLEnd hdl builder leader leader nextLeader
    builder.AddIRBoundary leader ePpoint
    scanIRBoundaries hdl builder last leaders
  | [ leader ] ->
    let ePpoint = getIRBBLEnd hdl builder leader leader last
    builder.AddIRBoundary leader ePpoint
    builder
  | [] -> builder

/// This is also different version of that of
/// FrontEnd/FrontEnd.Utils/Lifter.fs because our basic block is more
/// fine-grainded, so we don't want to lift instructions more than our basic
/// block range.
let liftIRBlk hdl (builder: CFGBuilder) sAddr eAddr =
  let rec liftLoop acc addr =
    if addr = eAddr then acc
    else
      let instr = builder.GetInstr addr
      let stmts =
        BinHandler.LiftInstr hdl instr
        |> LocalOptimizer.Optimize |> Array.toList
      let acc = List.append acc stmts
      let nextAddr = addr + uint64 instr.Length
      liftLoop acc nextAddr
  liftLoop [] sAddr |> givePPointToStmt

let includesIRBoundary builder (sPpoint0, ePpoint0) (sPpoint1, ePpoint1) =
  if ePpoint0 = ePpoint1 then
    let sAddr0, sCnt0 = sPpoint0
    let sAddr1, sCnt1 = sPpoint1
    if sAddr0 < sAddr1 || sAddr0 = sAddr1 && sCnt0 < sCnt1 then
      checkRange builder sAddr0 sAddr1
    else false
  else false

let rec refineIRBoundariesAux hdl (builder: CFGBuilder) = function
  | boundary1 :: ((boundary2 :: _) as boundaries) ->
    if includesIRBoundary builder boundary1 boundary2 then
      let sPpoint0, _ = boundary1
      let sPpoint1, _ = boundary2
      let ePpoint0 = getIRBBLEnd hdl builder sPpoint0 sPpoint0 sPpoint1
      builder.RemoveIRBoundary sPpoint0
      builder.AddIRBoundary sPpoint0 ePpoint0
      refineIRBoundariesAux hdl builder boundaries
    else refineIRBoundariesAux hdl builder boundaries
  | [ _ ] | [] -> builder

let refineIRBoundaries hdl (builder: CFGBuilder) =
  refineIRBoundariesAux hdl builder <| builder.GetIRBoundaries ()

let rec findIRBoundaries hdl (builder: CFGBuilder) ePpoint = function
  | (sAddr, eAddr) :: boundaries ->
    let stmts = liftIRBlk hdl builder sAddr eAddr
    let sPpoint = sAddr, 0
    let ePpoint = eAddr, 0
    builder.AddIRLeader sPpoint
    let builder =
      scanIRLeaders hdl builder (sPpoint, ePpoint) stmts
    findIRBoundaries hdl builder ePpoint boundaries
  | [] ->
    let builder =
      scanIRBoundaries hdl builder ePpoint <| builder.GetIRLeaders ()
    refineIRBoundaries hdl builder

let identifyIRBoundary hdl (builder: CFGBuilder) funcs =
  let builder =
    findIRBoundaries hdl builder (0UL, 0) <| builder.GetDisasmBoundaries ()
  builder, funcs

let identify hdl builder funcs =
  (builder, funcs)
  ||> getInitialEntries hdl
  ||> findEntriesByPattern hdl
  ||> identifyDisasmBoundary hdl
  ||> identifyIRBoundary hdl

let identifyWithEntries hdl entries builder funcs =
  List.iter (initFunction hdl builder funcs) entries
  (builder, funcs)
  ||> identifyDisasmBoundary hdl
  ||> identifyIRBoundary hdl
