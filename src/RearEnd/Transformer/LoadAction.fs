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
open B2R2
open B2R2.FrontEnd

/// The `load` action.
type LoadAction() =
  let loadFile isa path =
    BinHandle.LoadFile(path, isa, None)

  let loadPath cancellationToken isa path =
    let cancellationToken: CancellationToken = cancellationToken
    cancellationToken.ThrowIfCancellationRequested()
    if File.Exists(path = path) then
      lazy loadFile isa path
      |> Binary.PlainInit
      |> box
      |> Array.singleton
    elif Directory.Exists(path = path) then
      Directory.GetFiles path
      |> Array.sortWith (fun left right ->
        System.StringComparer.OrdinalIgnoreCase.Compare(left, right))
      |> Array.map (fun f ->
        cancellationToken.ThrowIfCancellationRequested()
        lazy loadFile isa f
        |> Binary.PlainInit |> box)
    else
      invalidArg (nameof path) $"File or directory not found: {path}"

  let loadHex isa hex =
    lazy BinHandle.LoadRawImage(ByteArray.ofHexString hex, isa)
    |> Binary.PlainInit
    |> box
    |> Array.singleton

  let loadBytes cancellationToken input =
    let cancellationToken: CancellationToken = cancellationToken
    cancellationToken.ThrowIfCancellationRequested()
    match (input: obj) with
    | :? BinaryBytes as bytes ->
      let hdl =
        lazy (
          BinHandle.LoadRawImage(
            bytes.Bytes, bytes.ISA, bytes.BaseAddress, bytes.OS
          )
        )
      Binary.Init(bytes.Annotation, hdl) |> box
    | _ ->
      invalidArg (nameof input) "load expects ByteArray input."

  let transform cancellationToken (args: string list) collection =
    if collection.Values |> Array.forall isNull then
      match args with
      | [ value; isaName ] when File.Exists value || Directory.Exists value ->
        let isa = ISA isaName
        { Values = loadPath cancellationToken isa value }
      | [ hex; isaName ] ->
        let isa = ISA isaName
        { Values = loadHex isa hex }
      | [ value ] ->
        let isa = ISA Architecture.Intel
        { Values = loadPath cancellationToken isa value }
      | _ ->
        invalidArg (nameof args) "Invalid arguments given."
    elif List.isEmpty args then
      { Values = collection.Values |> Array.map (loadBytes cancellationToken) }
    else
      invalidArg (nameof args) "ByteArray input takes no load parameters."

  let transformNamed cancellationToken args collection =
    let options = Map.ofList args
    if collection.Values |> Array.forall isNull then
      let isa =
        options
        |> Map.tryFind "isa"
        |> Option.map (fun (name: string) -> ISA name)
        |> Option.defaultWith (fun () -> ISA Architecture.Intel)
      match Map.tryFind "path" options, Map.tryFind "hex" options with
      | Some path, None ->
        { Values = loadPath cancellationToken isa path }
      | None, Some hex ->
        { Values = loadHex isa hex }
      | _ ->
        invalidArg (nameof args) "Invalid load source."
    elif Map.isEmpty options then
      { Values = collection.Values |> Array.map (loadBytes cancellationToken) }
    else
      invalidArg (nameof args) "ByteArray input takes no load parameters."

  interface IAction with
    member _.ActionID with get() = "load"
    member _.Signature with get() =
      "Unit -> load path=<path> [isa=<isa>] | hex=<hex> isa=<isa> "
      + "| ByteArray -> load -> Binary"
    member _.Description with get() =
      """
    Take in a file path and return a binary object. If the given string is a
    valid directory path, then every file in the directory will be loaded in
    bulk. Use `hex=<hex> isa=<isa>` to load hexadecimal bytes as a raw image.
    With ByteArray input, reconstruct a binary retaining its metadata.

      - [isa] : parse the binary for the given ISA.
"""
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection

  interface ICancellableNamedArgumentsAction with
    member _.TransformNamed(args, collection, cancellationToken) =
      transformNamed cancellationToken args collection
