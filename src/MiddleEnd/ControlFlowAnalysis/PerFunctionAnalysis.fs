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

open B2R2.FrontEnd
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.ControlFlowAnalysis

/// PerFunctionAnalysis implements a core CFG-recovery algorithm, which modifies
/// a function-level CFG by analyzing the function. Though it works per
/// function, It can modify other functions (thus, the entire CFGInfo). An
/// analysis appends CFGEvents to modify function, but it can also modify the
/// function directly.
[<AbstractClass>]
type PerFunctionAnalysis () =

  /// Name of the analysis. This is for debugging.
  abstract Name: string

  /// Run the analysis.
  abstract Run:
       BinHandle
    -> CodeManager
    -> DataManager
    -> RegularFunction
    -> CFGEvents
    -> Result<CFGEvents, CFGError>

/// Helper module for per-function analyses.
[<RequireQualifiedAccess>]
module PerFunctionAnalysis =

  /// Run constant propagation on the function.
  let runCP hdl (func: RegularFunction) reader =
    let ssaCFG, ssaRoot = func.GetSSACFG hdl
    let cp =
      match reader with
      | Some reader -> SparseConstantPropagation (hdl, ssaCFG, reader)
      | None -> SparseConstantPropagation (hdl, ssaCFG)
    let cpState = cp.Compute ssaRoot
    struct (cpState, ssaCFG)
