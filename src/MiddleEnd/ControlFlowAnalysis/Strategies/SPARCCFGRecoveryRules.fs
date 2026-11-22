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
open B2R2.MiddleEnd.ControlFlowAnalysis

[<AutoOpen>]
module private SPARCCFGRecoveryRules =
  /// Checks if the transfer at the given address hands the code it goes to
  /// the return address of the caller of the function.
  let passesReturnAddress (ctx: CFGBuildingContext<_, _>) addr =
    match ctx.BBLFactory.PeekInstruction addr with
    | Ok ins -> (ins :?> SPARC.Instruction).PassesReturnAddress
    | Error _ -> false

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
/// code there returns where the caller would have.
type internal SPARCCFGRecoveryRules<'FnCtx, 'GlCtx>() =
  inherit CFGRecoveryRules<'FnCtx, 'GlCtx>()

  override _.EndsJumpTableBefore(_, jmptbl, idx) =
    let isPast = Option.exists (fun n -> idx >= n)
    isPast jmptbl.OwnRangeEntries || isPast jmptbl.MaskedEntries

  override _.JudgeTailCall(ctx, jmpAddr, target) =
    if target <> ctx.FunctionAddress && passesReturnAddress ctx jmpAddr then
      TailCall
    else
      base.JudgeTailCall(ctx, jmpAddr, target)
