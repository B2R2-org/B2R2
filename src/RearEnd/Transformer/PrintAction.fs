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
open FSharp.Reflection
open B2R2

/// The `print` action.
type PrintAction() =
  let rec print cancellationToken (o: obj) =
    let cancellationToken: CancellationToken = cancellationToken
    cancellationToken.ThrowIfCancellationRequested()
    let typ = o.GetType()
    if typ = typeof<ObjCollection> then
      printObjCollection cancellationToken o
    elif typ = typeof<ClusterResult> then
      printClusterResult cancellationToken o
    elif typ.IsArray then
      printArray cancellationToken o
    elif FSharpType.IsUnion typ
      && typ.BaseType = typeof<OutString> then
      printOutString o
    else
      printsn (o.ToString())

  and printObjCollection cancellationToken (o: obj) =
    let res = o :?> ObjCollection
    res.Values
    |> Array.iteri (fun idx v ->
      (cancellationToken: CancellationToken).ThrowIfCancellationRequested()
      printsn $"[*] result({idx})"
      print cancellationToken v)

  and printClusterResult cancellationToken (o: obj) =
    let res = o :?> ClusterResult
    res.Clusters
    |> Array.iteri (fun idx cluster ->
      cluster
      |> Array.iter (fun elem ->
        (cancellationToken: CancellationToken).ThrowIfCancellationRequested()
        printsn $"  - Cluster({idx}): {elem}"))

  and printArray cancellationToken (o: obj) =
    let arr = o :?> _[]
    arr |> Array.iter (print cancellationToken)

  and printOutString (o: obj) =
    let os = o :?> OutString
    printon os

  let transform cancellationToken args collection =
    match args with
    | [] ->
      print cancellationToken (box collection)
      { Values = [||] }
    | _ ->
      invalidArg (nameof args) "Invalid argument."

  interface IAction with
    member _.ActionID with get() = "print"
    member _.Signature with get() = "'a -> unit"
    member _.Description with get() =
      """
    Take in an input object and print out its value.
"""
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection
