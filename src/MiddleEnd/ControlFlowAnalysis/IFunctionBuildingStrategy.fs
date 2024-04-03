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

/// A strategy that defines how CFGActions are handled to build a function.
type IFunctionBuildingStrategy<'Act,
                               'State,
                               'Req,
                               'Res when 'Act :> ICFGAction
                                     and 'State :> IResettable> =
  /// This is a callback that is called for every CFGAction generated for a
  /// function. Each action may discover a new basic block, add a new edge, etc.
  /// This function returns a CFGResult that indicates whether the function
  /// building should continue, postpone, or exit with an error.
  abstract OnAction:
      CFGBuildingContext<'State, 'Req, 'Res>
    * CFGActionQueue<'Act>
    * 'Act
    -> CFGResult

  /// This is a callback that is called when all CFGActions are processed, i.e.,
  /// when CFGActionQueue is empty.
  abstract OnFinish:
      CFGBuildingContext<'State, 'Req, 'Res>
    * INoReturnIdentifiable
    -> CFGResult

  /// This is a callback that is called when a query is made to the
  /// CFGTaskManager.
  abstract OnQuery: CFGTaskMessage<'Req, 'Res> * IValidityCheck -> unit
