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

/// Extended `SortedList`.
[<RequireQualifiedAccess>]
module B2R2.Collections.SortedList

open System.Collections.Generic

let rec private binSearch value lo hi (keys: IList<_>) (comp: Comparer<_>) =
  if lo < hi then
    let mid = (lo + hi) / 2
    match comp.Compare (keys[mid], value) with
    | 0 -> mid
    | n ->
      if n < 0 then binSearch value (mid + 1) hi keys comp
      else binSearch value lo (mid - 1) keys comp
  else lo

/// Find the greatest key that is less than the given key from the SortedList.
/// If there's no such key, this function returns None.
let findGreatestLowerBoundKey (key: 'T) (list: SortedList<'T, _>) =
  let comp = Comparer<'T>.Default
  let keys = list.Keys
  if keys.Count = 0 || comp.Compare (key, keys[0]) <= 0 then None
  else
    let idx = binSearch key 0 (list.Count - 1) keys comp
    if comp.Compare (keys[idx], key) < 0 then keys[idx] else keys[idx - 1]
    |> Some

/// Find the least key that is greater than the given key from the SortedList.
/// If there's no such key, this function returns None.
let findLeastUpperBoundKey (key: 'T) (list: SortedList<'T, _>) =
  let comp = Comparer<'T>.Default
  let keys = list.Keys
  let lastIdx = list.Count - 1
  if keys.Count = 0 || comp.Compare (keys[lastIdx], key) <= 0 then None
  else
    let idx = binSearch key 0 lastIdx keys comp
    if comp.Compare (keys[idx], key) <= 0 then keys[idx + 1] else keys[idx]
    |> Some
