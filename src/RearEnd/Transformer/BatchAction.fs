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

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*)

namespace B2R2.RearEnd.Transformer

open System.Threading

/// The `batch` action is evaluated by the REPL evaluator.
type BatchAction() =
  let notDirectlyInvoked () =
    invalidOp "batch is handled by the Transformer REPL evaluator."

  interface IAction with
    member _.ActionID with get() = "batch"
    member _.Signature with get() =
      "'a collection -> batch action=<action> params=<fun> -> 'b collection"

    member _.Description with get() =
      """
    Apply an action to each item in a collection. The params argument is a
    function of the form `fun item index -> ...`; use `_` when the index is not
    needed.
"""

    member _.Transform(_, _) = notDirectlyInvoked ()

  interface ICancellableAction with
    member _.Transform(_, _, _: CancellationToken) = notDirectlyInvoked ()
