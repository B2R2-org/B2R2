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

/// The `find` action.
type FindAction() =
  let parseArgument (args: string list) =
    match args with
    | [ argument ] ->
      let index = argument.IndexOf '='
      if index <= 0 || index = argument.Length - 1 then
        invalidArg (nameof argument) "Expected a property=value argument."
      else
        argument[..index - 1], argument[index + 1..]
    | _ ->
      invalidArg "args" "Expected exactly one property=value argument."

  let filter cancellationToken property expected (collection: ObjCollection) =
    let cancellationToken: CancellationToken = cancellationToken
    cancellationToken.ThrowIfCancellationRequested()
    ReplQueryCapabilities.tryFilterValues property expected collection.Values
    |> Result.map (fun values -> { Values = values })
    |> Result.defaultWith invalidOp

  let transform
    cancellationToken
    (args: string list)
    (collection: ObjCollection) =
    let property, expected = parseArgument args
    filter cancellationToken property expected collection

  let transformNamed cancellationToken arguments collection =
    match arguments with
    | [ property, expected ] ->
      filter cancellationToken property expected collection
    | _ ->
      invalidArg "arguments" "Expected exactly one named query argument."

  interface IAction with
    member _.ActionID with get() = "find"
    member _.Signature with get() =
      "FunctionInfo collection -> find symbol=<name>|entry=<addr> -> collection"
    member _.Description with get() =
      """
    Filter functions by one searchable property.
"""
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection

  interface INamedArgumentsAction with
    member _.TransformNamed(arguments, collection) =
      transformNamed CancellationToken.None arguments collection

  interface ICancellableNamedArgumentsAction with
    member _.TransformNamed(arguments, collection, cancellationToken) =
      transformNamed cancellationToken arguments collection
