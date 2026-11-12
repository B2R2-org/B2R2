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

open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowAnalysis.Strategies.CFGRecoveryCommon

[<AutoOpen>]
module private MIPSCFGRecoveryRules =
  /// Judges an indirect call that returns to the entry of another function
  /// never to return, as no code runs into a function from the code before
  /// it. Returns None when the call returns elsewhere.
  let tryJudgeReturnByNextEntry (ctx: CFGBuildingContext<_, _>) caller =
    let blk = (caller: IVertex<LowUIRBasicBlock>).VData.Internals
    let retAddr = ReturnAddress.ofCall blk.LastInstruction
    if retAddr <> ctx.FunctionAddress && isFuncEntryPoint ctx retAddr then
      Some(NoRet, 0)
    else
      None

/// Represents the rules of the CFG recovery for MIPS: the rules of every
/// architecture, except that a jump table ends where the range check right
/// before its indirect branch says, or where a mask on its index does. PIC
/// code builds the address of a table from a page that it loads from the GOT
/// far from the table, often once for several tables of a function, so
/// neither the entries nor the data the code addresses end a table before
/// the next one, whose offsets from gp read as entries too. A call through t9
/// reaches what the GOT entry that the code loads into t9 holds, and any
/// other indirect call right before another function never returns.
type internal MIPSCFGRecoveryRules<'FnCtx, 'GlCtx>() =
  inherit CFGRecoveryRules<'FnCtx, 'GlCtx>()

  override _.TryResolveIndirectCallee(ctx, caller) =
    MIPSCode.tryFindGOTCallee ctx.BinHandle caller.VData.Internals.Instructions

  override _.TryJudgeIndirectReturn(ctx, caller) =
    base.TryJudgeIndirectReturn(ctx, caller)
    |> Option.orElseWith (fun () -> tryJudgeReturnByNextEntry ctx caller)

  override _.EndsJumpTableBefore(_, jmptbl, idx) =
    let isPast = Option.exists (fun n -> idx >= n)
    isPast jmptbl.OwnRangeEntries || isPast jmptbl.MaskedEntries
