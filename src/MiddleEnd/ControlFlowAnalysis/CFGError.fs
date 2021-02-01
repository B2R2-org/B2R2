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

namespace B2R2.MiddleEnd.ControlFlowAnalysis

open B2R2

/// Error occured from a CFG analysis.
type CFGError =
  /// This error occurs while resolving an indirect branch.
  | ErrorBranchRecovery of fnAddr: Addr
                         * brAddr: Addr
                         * rollbackFuncs: Set<Addr>
  /// Nested switch is found and we found the existence of a jump-table overlap
  /// late. So we rollback.
  | ErrorLateDetection
  /// This error occurs while parsing an invalid basic block.
  | ErrorParsing
  /// This error occurs while connecting an invalid edge; src/dst node is
  /// invalid, e.g., when an edge is intruding an instruction boundary.
  | ErrorConnectingEdge

[<RequireQualifiedAccess>]
module CFGError =
  let toString = function
    | ErrorBranchRecovery (fnAddr, brAddr, _) ->
      (nameof ErrorBranchRecovery)
      + "(" + fnAddr.ToString("x") + "," + brAddr.ToString("x") + ")"
    | ErrorLateDetection -> nameof ErrorLateDetection
    | ErrorParsing -> nameof ErrorParsing
    | ErrorConnectingEdge -> nameof ErrorConnectingEdge
