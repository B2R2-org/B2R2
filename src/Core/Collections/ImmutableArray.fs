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

/// <summary>
/// Provides the way out of an <see
/// cref='T:System.Collections.Immutable.ImmutableArray`1'/> and into the
/// ordinary <c>Array</c> and <c>List</c> modules. The <c>Seq</c> module would
/// answer for all of this, but every one of its traversals boxes the struct
/// enumerator the immutable array hands it; each function here walks by index
/// instead, so a traversal allocates nothing but the result it returns. Each
/// one returns an ordinary value, which is what makes it a boundary rather
/// than a second collection library: one hop and the call site is back in the
/// modules it would have used anyway.
/// </summary>
[<RequireQualifiedAccess>]
module B2R2.Collections.ImmutableArray

open System.Collections.Immutable
open System.Runtime.InteropServices

/// <summary>
/// Returns the given array as an immutable one, sharing its storage rather
/// than copying it. The array must be one nothing writes to afterwards: what
/// is written through it is seen through the immutable one too.
/// </summary>
let ofArray (arr: 'T[]) = ImmutableCollectionsMarshal.AsImmutableArray arr

/// Returns the elements of the given immutable array as an array of their
/// own, which is a copy: the caller is free to write into what it gets back.
let toArray (arr: ImmutableArray<'T>) =
  let res = Array.zeroCreate arr.Length
  for i = 0 to arr.Length - 1 do res[i] <- arr[i]
  res

/// Returns the elements of the given immutable array as a list, in order.
let toList (arr: ImmutableArray<'T>) =
  let mutable acc = []
  for i = arr.Length - 1 downto 0 do acc <- arr[i] :: acc
  acc

/// Returns an array holding the results of applying the given function to
/// each element of the given immutable array.
let inline map ([<InlineIfLambda>] mapping) (arr: ImmutableArray<'T>) =
  let res = Array.zeroCreate arr.Length
  for i = 0 to arr.Length - 1 do res[i] <- mapping arr[i]
  res

/// Returns an array holding the results of applying the given function to
/// each element of the given immutable array along with its index.
let inline mapi ([<InlineIfLambda>] mapping) (arr: ImmutableArray<'T>) =
  let res = Array.zeroCreate arr.Length
  for i = 0 to arr.Length - 1 do res[i] <- mapping i arr[i]
  res

/// Returns an array holding the elements the given predicate holds for.
let inline filter ([<InlineIfLambda>] predicate) (arr: ImmutableArray<'T>) =
  let res = ResizeArray arr.Length
  for i = 0 to arr.Length - 1 do
    if predicate arr[i] then res.Add arr[i] else ()
  res.ToArray()

/// Returns an array holding the results the given function answers with, for
/// the elements it answers for at all.
let inline choose ([<InlineIfLambda>] chooser) (arr: ImmutableArray<'T>) =
  let res = ResizeArray arr.Length
  for i = 0 to arr.Length - 1 do
    match chooser arr[i] with
    | Some v -> res.Add v
    | None -> ()
  res.ToArray()

/// Applies the given function to each element in turn, threading the
/// accumulator through, and returns what it ends up as.
let inline fold ([<InlineIfLambda>] folder) state (arr: ImmutableArray<'T>) =
  let mutable acc = state
  for i = 0 to arr.Length - 1 do acc <- folder acc arr[i]
  acc

/// Returns the first element the given predicate holds for, or None where it
/// holds for none of them.
let inline tryFind ([<InlineIfLambda>] predicate) (arr: ImmutableArray<'T>) =
  let mutable found = None
  let mutable i = 0
  while found.IsNone && i < arr.Length do
    if predicate arr[i] then found <- Some arr[i] else i <- i + 1
  found

/// Returns the index of the first element the given predicate holds for, or
/// None where it holds for none of them.
let inline tryFindIndex
  ([<InlineIfLambda>] predicate) (arr: ImmutableArray<'T>) =
  let mutable found = None
  let mutable i = 0
  while found.IsNone && i < arr.Length do
    if predicate arr[i] then found <- Some i else i <- i + 1
  found

/// Checks whether the given predicate holds for any element.
let inline exists ([<InlineIfLambda>] predicate) (arr: ImmutableArray<'T>) =
  let mutable found = false
  let mutable i = 0
  while not found && i < arr.Length do
    if predicate arr[i] then found <- true else i <- i + 1
  found

/// Checks whether the given predicate holds for every element.
let inline forall ([<InlineIfLambda>] predicate) (arr: ImmutableArray<'T>) =
  let mutable holds = true
  let mutable i = 0
  while holds && i < arr.Length do
    if predicate arr[i] then i <- i + 1 else holds <- false
  holds
