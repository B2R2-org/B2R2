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

namespace B2R2.RearEnd.Transformer

open System
open System.Threading

/// The `pick` action.
type PickAction() =
  let transform cancellationToken (args: string list) collection =
    let cancellationToken: CancellationToken = cancellationToken
    cancellationToken.ThrowIfCancellationRequested()
    match args with
    | [ indexText ] ->
      match Int32.TryParse indexText with
      | true, index when index >= 0 && index < collection.Values.Length ->
        { Values = [| collection.Values[index] |] }
      | _ ->
        invalidArg (nameof args) "Index must select an existing value."
    | _ ->
      invalidArg (nameof args) "Expected: pick index=<n>."

  interface IAction with
    member _.ActionID with get() = "pick"
    member _.Signature with get() = "'a collection -> pick index=<n> -> 'a"
    member _.Description with get() =
      """
    Select one value from the current collection using a 0-based index.
"""
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection
