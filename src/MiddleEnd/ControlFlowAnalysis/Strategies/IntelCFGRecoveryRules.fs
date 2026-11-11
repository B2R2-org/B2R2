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

open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

[<AutoOpen>]
module private IntelCFGRecoveryRules =
  /// Checks if the call that ends the given block reads the PC, as 32-bit x86
  /// code does by calling the instruction right after the call, which pops the
  /// address that the call pushes.
  let isGetPCThunk (ctx: CFGBuildingContext<_, _>) srcBBL calleeAddr =
    if ctx.BinHandle.ISA.IsX86 then
      let ins = (srcBBL: ILowUIRBasicBlock).LastInstruction
      let nextAddr = ins.Address + uint64 ins.Length
      if calleeAddr = nextAddr then
        match ctx.BBLFactory.PeekBBL calleeAddr with
        | Ok bbl -> bbl[0].IsPop (* Call to pop *)
        | Error _ -> false
      else
        false
    else
      false

/// Represents the rules of the CFG recovery for Intel: the rules of every
/// architecture, except that a call that 32-bit code makes only to read the PC
/// calls no function.
type internal IntelCFGRecoveryRules<'FnCtx, 'GlCtx>() =
  inherit CFGRecoveryRules<'FnCtx, 'GlCtx>()

  override _.IsGetPCThunk(ctx, bbl, callee) = isGetPCThunk ctx bbl callee
