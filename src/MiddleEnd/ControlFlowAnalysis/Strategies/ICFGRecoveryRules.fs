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

open B2R2
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Represents the rules that the CFG recovery follows where architectures
/// differ: where a call enters its callee, whether a jump calls a function as
/// its tail, whether a call calls a function at all, whether an indirect call
/// returns, and whether a function needs building again. Workers share the
/// rules, so the rules keep no state; what a function has to remember lives in
/// its context.
type internal ICFGRecoveryRules<'FnCtx, 'GlCtx> =
  /// Returns the address of the function that a call or a jump to the given
  /// target enters.
  abstract ToCalleeAddr:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    * target: Addr
    -> Addr

  /// Checks if the jump at jmpAddr calls the function at target as its tail.
  abstract IsTailCall:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    * jmpAddr: Addr
    * target: Addr
    -> bool

  /// Checks if the conditional jump at jmpAddr calls the function at target as
  /// its tail.
  abstract IsCondTailCall:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    * jmpAddr: Addr
    * target: Addr
    -> bool

  /// Checks if the call that ends the given block reads the PC rather than
  /// calls a function: the code at callee pops the address that the call
  /// pushes.
  abstract IsGetPCThunk:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    * ILowUIRBasicBlock
    * callee: Addr
    -> bool

  /// Judges whether the indirect call that ends the given vertex returns, along
  /// with how many bytes its callee pops when it does. Returns None when the
  /// rules do not tell.
  abstract TryJudgeIndirectReturn:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    * IVertex<LowUIRBasicBlock>
    -> (NonReturningStatus * int) option

  /// Checks if the function that the given context has built needs building
  /// again, as its code refutes what the building took for granted. Before it
  /// tells so, it notes in the context what the next building is to take
  /// instead.
  abstract RequiresRebuild: CFGBuildingContext<'FnCtx, 'GlCtx> -> bool

  /// Finds the functions to build again among the given builders, once all of
  /// them are done building, as what the recovery has found since tells their
  /// CFGs otherwise.
  abstract FindFunctionsToRebuild: IFunctionBuilder[] -> Addr[]
