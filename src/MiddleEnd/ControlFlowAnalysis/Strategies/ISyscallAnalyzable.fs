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

open B2R2.BinIR
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

/// The interface for syscall stub analysis. This is to know whether the given
/// syscall instruction is an exit syscall or not. Since this analysis runs in
/// the middle of the CFG building, it should be solely based on the LowUIRCFG,
/// not the SSACFG.
type ISyscallAnalyzable =
  /// Is the given syscall instruction located at the target vertex an exit
  /// syscall?
  abstract IsExit:
       ctx: CFGBuildingContext<'FnCtx, 'GlCtx>
     * TargetVertex: IVertex<LowUIRBasicBlock>
    -> bool

  abstract MakeAbstract:
       ctx: CFGBuildingContext<'FnCtx, 'GlCtx>
     * TargetVertex: IVertex<LowUIRBasicBlock>
     * IsExit: bool
    -> FunctionAbstraction<LowUIR.Stmt>
