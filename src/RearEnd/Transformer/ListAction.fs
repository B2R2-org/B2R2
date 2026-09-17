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
open B2R2
open B2R2.FrontEnd.BinFile

/// The `list` action.
type ListAction() =
  let sectionInfo bin section =
    let section: BinSection = section
    { Source = bin
      Name = section.Name
      Address = section.Address
      Size = section.Size
      FileSize = section.FileSize
      Kind = section.Kind.ToString() }

  let listSections (input: obj) =
    let bin = unbox<Binary> input
    let hdl = Binary.Handle bin
    BinFileOps.getSections hdl.File
    |> Array.map (sectionInfo bin >> box)

  let listFunctions (input: obj) =
    let bin = unbox<Binary> input
    let hdl = Binary.Handle bin
    let symbolName addr =
      match BinFileOps.tryFindSymbolByAddr hdl.File addr with
      | Ok symbol when not (System.String.IsNullOrWhiteSpace symbol.Name) ->
        Some symbol.Name
      | _ -> None
    BinFileOps.getFunctionAddresses hdl.File
    |> Array.sort
    |> Array.map (fun addr ->
      { Source = bin
        Entry = addr
        Symbol = symbolName addr }
      |> box)

  let transform cancellationToken args collection =
    let cancellationToken: CancellationToken = cancellationToken
    let collect operation =
      collection.Values
      |> Array.collect (fun value ->
        cancellationToken.ThrowIfCancellationRequested()
        operation value)
    match args with
    | [ "sections" ] -> { Values = collect listSections }
    | [ "functions" ] -> { Values = collect listFunctions }
    | _ -> invalidArg (nameof args) "Invalid argument."

  interface IAction with
    member _.ActionID with get() = "list"
    member _.Signature with get() =
      "Binary * <sections|functions> -> typed collection"
    member _.Description with get() =
      """
    Take in a parsed binary and return a list of elements such as functions,
    sections, etc. The output type is determined by the extra [cmd] argument.
    Currently, we support the following [cmd]:

      - `sections`: returns a list of sections.
      - `functions`: returns known function entry addresses.
"""
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection
