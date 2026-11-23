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


namespace B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

[<AutoOpen>]
module private SPARCCFGRecoveryRules =
  /// Reads the instruction at the given address.
  let tryPeek (ctx: CFGBuildingContext<_, _>) addr =
    match ctx.BBLFactory.PeekInstruction addr with
    | Ok ins -> Some(ins :?> SPARC.Instruction)
    | Error _ -> None

  /// Checks if the instruction branches, linking nothing, with a nop in its
  /// delay slot, which leaves %o7 alone.
  let isBranchOverNop (ins: SPARC.Instruction) =
    let transfer = ins :> IInstruction
    let isNop (slot: SPARC.Instruction) = slot.Opcode = SPARC.Opcode.NOP
    transfer.IsDirectBranch
    && not transfer.IsCondBranch
    && not transfer.IsCall
    && Option.exists isNop ins.DelaySlot

  /// Checks if the transfer at the given address hands the code it goes to
  /// the return address of the caller of the function: it does so itself, or
  /// it branches over a nop right past a copy of %o7, into which the linker
  /// relaxes a call of a leaf that moves the copy back into %o7 in its delay
  /// slot, as both leave %o7 as it was.
  let passesReturnAddress ctx addr =
    match tryPeek ctx addr with
    | Some ins when ins.PassesReturnAddress ->
      true
    | Some ins when isBranchOverNop ins && addr >= 4UL ->
      tryPeek ctx (addr - 4UL) |> Option.exists _.CopiesReturnAddress
    | _ ->
      false

  /// Checks if the call that ends the given vertex returns onto code that
  /// turns the window, past what fills space between functions, as a
  /// function starts there. Code that a call returns to runs in the window
  /// that its function has turned to already, if it turns one at all.
  let callsBeforeSave (ctx: CFGBuildingContext<_, _>) v =
    let ins = (v: IVertex<LowUIRBasicBlock>).VData.Internals.LastInstruction
    if ins.IsCall then
      let lu = ctx.ScanningUnit
      let past = ins.Address + uint64 ins.Extent
      SPARCCode.skipFiller lu past System.UInt64.MaxValue
      |> SPARCCode.turnsWindowAt lu
    else
      false

/// Represents the rules of the CFG recovery for SPARC: the rules of every
/// architecture, except that a jump table ends where the range check right
/// before its indirect branch says, or where a mask on its index does. GCC
/// lays the tables of a translation unit next to each other in .text, apart
/// from the code, and reaches each through a register, which PIC code builds
/// from the GOT, so neither the entries nor the code end a table before the
/// next one, whose entries read as ones of the first, counted from its base.
/// A jump that restores the window in its delay slot, or a call that moves the
/// return address of its caller into %o7 there, calls the code it goes to as
/// its tail, whether a function is known to start there yet or not, as the
/// code there returns where the caller would have, and so does a branch over
/// a nop right past a copy of %o7, which GNU ld relaxes such a call of a leaf
/// into. A call forgets the stack slots that its callee may write, so that a
/// slot of the frame of the function holds nothing on entry: GCC keeps the
/// base of a table in a slot that the code writes before a loop, which code
/// that GCC shares reaches along a way that skips the write, but that never
/// reaches the read. A call right before code that turns the window never
/// returns there, whatever its callee does, as clang lays a function right
/// past a call to error with a status that it knows is not zero, where the
/// recovery may not tell, and GCC one past a call through a pointer to a
/// function that never returns.
type internal SPARCCFGRecoveryRules<'FnCtx, 'GlCtx>() =
  inherit CFGRecoveryRules<'FnCtx, 'GlCtx>()

  override _.EndsJumpTableBefore(_, jmptbl, idx) =
    let isPast = Option.exists (fun n -> idx >= n)
    isPast jmptbl.OwnRangeEntries || isPast jmptbl.MaskedEntries

  override _.ForgetsWrittenSlots _ = true

  override _.JudgeTailCall(ctx, jmpAddr, target) =
    if target <> ctx.FunctionAddress && passesReturnAddress ctx jmpAddr then
      TailCall
    else
      base.JudgeTailCall(ctx, jmpAddr, target)

  override _.TryJudgeIndirectReturn(ctx, caller) =
    if callsBeforeSave ctx caller then Some(NoRet, 0)
    else base.TryJudgeIndirectReturn(ctx, caller)

  override _.RefutesReturn(ctx, v) = callsBeforeSave ctx v
