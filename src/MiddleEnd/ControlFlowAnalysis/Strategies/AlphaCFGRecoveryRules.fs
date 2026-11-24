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

open B2R2.MiddleEnd.ControlFlowAnalysis

[<AutoOpen>]
module private AlphaCFGRecoveryRules =
  /// The word of ldah gp, n(t12), with the displacement n masked off.
  [<Literal>]
  let LdahGPFromT12 = 0x27bb0000UL

  /// The word of lda gp, n(gp), with the displacement n masked off.
  [<Literal>]
  let LdaGPFromGP = 0x23bd0000UL

  /// Checks if the word at the given address is the given one, with its
  /// displacement of 16 bits masked off.
  let isWordAt (ctx: CFGBuildingContext<_, _>) addr word =
    match ctx.BinHandle.TryReadUInt((addr: uint64), 4) with
    | Ok v -> v &&& 0xffff0000UL = word
    | Error _ -> false

  /// Checks if the two words before the given target compute gp from t12, as
  /// the prologue of a function does with the address of itself that its
  /// caller puts in t12.
  let followsGPPrologue ctx target =
    target >= 8UL
    && isWordAt ctx (target - 8UL) LdahGPFromT12
    && isWordAt ctx (target - 4UL) LdaGPFromGP

/// Represents the rules of the CFG recovery for Alpha: the rules of every
/// architecture, except that a call or a jump past the prologue that computes
/// gp enters the function of the prologue. A caller that shares gp with its
/// callee skips the prologue, as the linker relaxes the call through the GOT
/// to a BSR past it, but the function starts at the prologue, where its FDE
/// starts too.
type internal AlphaCFGRecoveryRules<'FnCtx, 'GlCtx>() =
  inherit CFGRecoveryRules<'FnCtx, 'GlCtx>()

  override _.ToCalleeAddr(ctx, target) =
    if followsGPPrologue ctx target then target - 8UL else target
