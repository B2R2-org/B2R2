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
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Return types of pluggable analysis interface.
type PluggableAnalysisReturnType =
  /// Analysis done ok.
  | PluggableAnalysisOk
  /// Analysis done with error.
  | PluggableAnalysisError
  /// Analysis done and a new BinHandle has been created.
  | PluggableAnalysisNewBinary of BinHandle

/// Pluggable analysis interface. Any CFG-related analysis implementing this
/// interface can be plugged in or unplugged from the BinEssence.
type IPluggableAnalysis =

  /// The name of the analysis (for debugging purpose).
  abstract Name: string

  /// Run the analysis, which will return whether it needs further iteration.
  abstract Run:
       CFGBuilder
    -> BinHandle
    -> CodeManager
    -> DataManager
    -> PluggableAnalysisReturnType
