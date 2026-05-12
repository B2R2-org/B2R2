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

namespace B2R2.MiddleEnd.SymEval

open System.Runtime.InteropServices
open B2R2
open B2R2.MiddleEnd.Executor

/// Represents the main symbolic evaluation state.
type SymState(regs, temps, lbls, mem: ISymMemory, pathCond) =

  let mutable pc = 0UL
  let mutable stmtIdx = 0
  let mutable currentInsLen = 0u
  let mutable isInstrTerminated = false
  let mutable needToEvaluateIEMark = false
  let mutable regs = regs
  let mutable temps = temps
  let mutable lbls = lbls
  let mutable mem = mem
  let mutable pathCond = pathCond

  new() =
    SymState(SymVariables(),
             SymVariables(),
             Labels(),
             SymMemory() :> ISymMemory,
             [])

  new(mem) =
    SymState(SymVariables(), SymVariables(), Labels(), mem, [])

  member _.PC with get() = pc and set(addr) = pc <- addr

  member _.StmtIdx with get() = stmtIdx and set(i) = stmtIdx <- i

  member _.CurrentInsLen
    with get() = currentInsLen and set(l) = currentInsLen <- l

  member _.Registers with get() = regs

  member _.Temporaries with get() = temps

  member _.Labels with get() = lbls

  member _.Memory with get() = mem and set v = mem <- v

  member _.PathCondition with get() = pathCond

  member _.IsInstrTerminated
    with get() = isInstrTerminated and set(f) = isInstrTerminated <- f

  member _.NeedToEvaluateIEMark
    with get() = needToEvaluateIEMark and set(f) = needToEvaluateIEMark <- f

  member inline this.NextStmt() = this.StmtIdx <- this.StmtIdx + 1

  member this.AbortInstr([<Optional; DefaultParameterValue(false)>]
                         needToUpdatePC: bool) =
    isInstrTerminated <- true
    needToEvaluateIEMark <- needToUpdatePC
    this.NextStmt()

  member _.SetReg(rid: RegisterID, value) = regs.Set(int rid, value)

  member _.TryGetReg(rid: RegisterID) = regs.TryGet(int rid)

  member _.GetReg(rid: RegisterID) = regs.Get(int rid)

  member _.SetTmp(idx, value) = temps.Set(idx, value)

  member _.TryGetTmp idx = temps.TryGet idx

  member _.UnsetTmp idx = temps.Unset idx

  /// Adds a 1-bit bit-vector condition that must evaluate to true.
  member _.AddPathCondition cond = pathCond <- cond :: pathCond

  member inline this.AdvancePC(amount: uint32) =
    this.PC <- this.PC + uint64 amount

  member inline this.GoToLabel lbl = this.StmtIdx <- this.Labels.Index lbl

  member inline this.PrepareInstrEval stmts =
    this.IsInstrTerminated <- false
    this.NeedToEvaluateIEMark <- false
    this.Labels.Update stmts
    this.StmtIdx <- 0

  member _.Clone() =
    SymState(regs.Clone(),
             temps.Clone(),
             lbls.Clone(),
             mem.Clone(),
             pathCond,
             PC = pc,
             StmtIdx = stmtIdx,
             CurrentInsLen = currentInsLen,
             IsInstrTerminated = isInstrTerminated,
             NeedToEvaluateIEMark = needToEvaluateIEMark)

  member this.InitializeContext(pc, registers: (RegisterID * SymExpr)[]) =
    this.PC <- pc
    registers |> Array.iter (fun (rid, value) -> this.SetReg(rid, value))
