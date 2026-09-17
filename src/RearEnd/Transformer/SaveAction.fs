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

open System.Threading

/// The `save` action.
type SaveAction() =
  let save cancellationToken fname (input: obj) =
    let cancellationToken: CancellationToken = cancellationToken
    cancellationToken.ThrowIfCancellationRequested()
    match input with
    | :? Binary as bin -> ReplArtifactWriter.writeBinary fname bin
    | _ -> invalidArg (nameof input) "save only supports Binary values."

  let transform cancellationToken (args: string list) collection =
    match args, collection.Values with
    | [ fname ], [| value |] ->
      save cancellationToken fname value
      { Values = [||] }
    | [ _ ], _ ->
      invalidArg (nameof collection)
        "save expects one Binary; use batch to save collection items."
    | _ ->
      invalidArg (nameof args) "Expected: save path=<path>."

  interface IAction with
    member _.ActionID with get() = "save"
    member _.Signature with get() = "Binary -> save path=<path> -> Unit"
    member _.Description with get() =
      """
    Take in a Binary value and save its raw bytes to the <file>.
"""
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection
