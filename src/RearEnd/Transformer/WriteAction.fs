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

open System.IO
open System.Threading

/// The `write` action.
type WriteAction() =
  let rec write cancellationToken fname (o: obj) =
    let cancellationToken: CancellationToken = cancellationToken
    cancellationToken.ThrowIfCancellationRequested()
    match o with
    | :? (Instruction[]) as instructions ->
      let lines = instructions |> Array.map string
      File.WriteAllLines(fname, lines)
    | _ ->
      ReplArtifactWriter.writeText fname o

  let transform cancellationToken (args: string list) collection =
    if args.Length = collection.Values.Length then
      let args = List.toArray args
      Array.iter2 (write cancellationToken) args collection.Values
      { Values = [||] }
    elif args.Length = 1 then
      let fname = List.head args
      let fnames = collection.Values |> Array.mapi (fun i _ -> $"{fname}.{i}")
      Array.iter2 (write cancellationToken) fnames collection.Values
      { Values = [||] }
    else
      invalidArg (nameof args) "Input lengths mismatch."

  interface IAction with
    member _.ActionID with get() = "write"
    member _.Signature with get() =
      "Text|InstructionArray * path=<path> -> Unit"
    member _.Description with get() =
      """
    Take in a text value and write out its content to the <file>.
"""
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection
