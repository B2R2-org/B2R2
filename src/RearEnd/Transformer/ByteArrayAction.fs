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
open B2R2.FrontEnd

/// The `bytes` action.
type BytesAction() =
  let convert cancellationToken (input: obj) =
    let cancellationToken: CancellationToken = cancellationToken
    cancellationToken.ThrowIfCancellationRequested()
    let binary =
      match input with
      | :? Binary as binary ->
        binary
      | :? BinarySlice as slice ->
        slice.ToBinary()
      | _ ->
        invalidArg (nameof input) "Invalid input type."
    let hdl = Binary.Handle binary
    { Bytes = hdl.File.RawBytes.ToArray()
      BaseAddress = hdl.File.BaseAddress
      ISA = hdl.ISA
      OS = hdl.OS
      Annotation = Binary.Annotation binary }
    |> box

  let transform cancellationToken collection =
    { Values = collection.Values |> Array.map (convert cancellationToken) }

  interface IAction with
    member _.ActionID with get() = "bytes"
    member _.Signature with get() = "Binary | BinarySlice -> ByteArray"
    member _.Description with get() =
      "Extract raw bytes while retaining address and ISA information."
    member _.Transform(args, collection) =
      match args with
      | [] ->
        transform CancellationToken.None collection
      | _ ->
        invalidArg (nameof args) "Invalid argument."

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      match args with
      | [] ->
        transform cancellationToken collection
      | _ ->
        invalidArg (nameof args) "Invalid argument."

/// The `as-binary` action.
type AsBinaryAction() =
  let convert cancellationToken input =
    let cancellationToken: CancellationToken = cancellationToken
    cancellationToken.ThrowIfCancellationRequested()
    let bytes = unbox<BinaryBytes> input
    let hdl =
      lazy (
        BinHandle.LoadRawImage(
          bytes.Bytes, bytes.ISA, bytes.BaseAddress, bytes.OS
        )
      )
    Binary.Init(bytes.Annotation, hdl) |> box

  let transform cancellationToken collection =
    { Values = collection.Values |> Array.map (convert cancellationToken) }

  interface IAction with
    member _.ActionID with get() = "as-binary"
    member _.Signature with get() = "ByteArray -> Binary"
    member _.Description with get() =
      "Reconstruct an analyzable raw Binary from retained bytes."
    member _.Transform(args, collection) =
      match args with
      | [] ->
        transform CancellationToken.None collection
      | _ ->
        invalidArg (nameof args) "Invalid argument."

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      match args with
      | [] ->
        transform cancellationToken collection
      | _ ->
        invalidArg (nameof args) "Invalid argument."
