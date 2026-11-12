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

module B2R2.MiddleEnd.ControlFlowAnalysis.CFGEvaluator

open System
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.Collections
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ConcEval
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.DataFlow.Constants

/// Checks if only the loader writes to the given address, so that the code
/// reads there what the binary holds. A variable in .data, for instance, may
/// hold anything by the time the code reads it.
let private isLoaderOnly (file: IBinFile) addr =
  match file with
  | :? ELFBinFile as elf -> elf.IsReadOnlyAfterLoading addr
  | _ -> file.IsExecutableAddr addr

let private isReadable (file: IBinFile) addr =
  addr < UInt64.MaxValue && file.IsValidAddr addr && isLoaderOnly file addr

let private memoryReader (hdl: BinHandle) _pc addr typ _e =
  let len = RegType.toByteWidth typ
  let file = hdl.File
  if isReadable file addr then
    let ptr = hdl.File.GetBoundedPointer addr
    match hdl.TryReadBytes(ptr, len) with
    | Ok v -> Ok(BitVector v)
    | Error e -> Error e
  else
    Error ErrorCase.InvalidMemoryRead

let private stackAddr t = BitVector(InitialStackPointer, t)

let private obtainStackDef (hdl: BinHandle) =
  match hdl.RegisterFactory.StackPointer with
  | Some r -> [| r, hdl.ISA.WordSize |> WordSize.toRegType |> stackAddr |]
  | None -> [||]

let private obtainFramePointerDef (hdl: BinHandle) =
  match hdl.RegisterFactory.FramePointer with
  | Some r -> [| r, hdl.ISA.WordSize |> WordSize.toRegType |> BitVector.Zero |]
  | None -> [||]

/// Gets the expressions that the given statement reads.
let private exprsReadBy stmt =
  match stmt with
  | Put(Src = e) | CJmp(Cond = e) | InterJmp(Target = e) -> [| e |]
  | Store(Addr = addr; Value = value) -> [| addr; value |]
  | InterCJmp(Cond = c; TrueTarget = t; FalseTarget = f) -> [| c; t; f |]
  | _ -> [||]

/// Gives each register that the given blocks read the value that the binary
/// fixes it to, if the data flow knows one, as the zero register of MIPS holds
/// zero, which the lifter reads like any other register.
let private obtainFixedDefs hdl (blks: IVertex<LowUIRBasicBlock>[]) =
  let provider = RegisterInitialValueProvider.create hdl
  let rset = RegisterSet()
  for blk in blks do
    for ins in blk.VData.Internals.LiftedInstructions do
      for e in Array.collect exprsReadBy ins.Stmts do
        AST.updateRegsUses rset e
  let defs = ResizeArray<RegisterID * BitVector>()
  rset.Iterate(fun idx ->
    let rid = RegisterID.create idx
    provider.TryGetInitialValue rid |> Option.iter (fun v -> defs.Add(rid, v)))
  defs.ToArray()

/// Creates the state to evaluate the given blocks from, in which the given
/// registers and those that the binary fixes hold their values.
let private initState hdl (blks: IVertex<LowUIRBasicBlock>[]) regs =
  let pc = blks[0].VData.Internals.PPoint.Address
  let st = ConcState()
  st.IgnoreUndef <- true
  st.LoadFailureEventHandler <- memoryReader hdl
  st.InitializeContext(pc, Array.append (obtainFixedDefs hdl blks) regs)
  st

let rec private evalBlockLoop idx (blk: Stmt[][]) result =
  match result with
  | Ok(st: ConcState) ->
    if idx < blk.Length then
      SafeEvaluator.evalInstr st blk[idx]
      |> Result.map (fun () -> st)
      |> evalBlockLoop (idx + 1) blk
    else
      result
  | Error e ->
    Error e

/// Evaluates a series of statement arrays, assuming that each array is obtained
/// from a single machine instruction.
let private evalBlock (st: ConcState) pc blk =
  st.PC <- pc
  evalBlockLoop 0 blk (Ok st)

/// Concretely evaluates the given basic blocks in turn, as the control runs
/// through them, from the given state.
let private evalBlocks (st: ConcState) (blks: IVertex<LowUIRBasicBlock>[]) =
  st.SideEffectEventHandler <- fun _ st -> st.AbortInstr()
  for blk in blks do
    let pc = blk.VData.Internals.PPoint.Address
    let stmts =
      blk.VData.Internals.LiftedInstructions |> Array.map (fun arr -> arr.Stmts)
    match evalBlock st pc stmts with
    | Ok _ -> ()
    | Error _ -> Terminator.impossible ()
  st

/// Concretely evaluates the given basic blocks in turn, as the control runs
/// through them, from an arbitrarily generated state.
let evalBlocksFromScratch hdl (blks: IVertex<LowUIRBasicBlock>[]) =
  let regs = Array.append (obtainStackDef hdl) (obtainFramePointerDef hdl)
  let st = initState hdl blks regs
  evalBlocks st blks

/// Concretely evaluates a basic block from an arbitrarily generated state.
let evalBlockFromScratch hdl blk = evalBlocksFromScratch hdl [| blk |]

/// Concretely evaluates a basic block from a state that knows nothing but the
/// stack pointer, the given registers, and those that the binary fixes, not
/// even the frame pointer, which a state from scratch takes for zero.
let evalBlockWith hdl regs (blk: IVertex<LowUIRBasicBlock>) =
  let regs = Array.append (obtainStackDef hdl) regs
  let st = initState hdl [| blk |] regs
  evalBlocks st [| blk |]
