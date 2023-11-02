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

namespace B2R2

open System.Collections.Generic

/// Extended Array.
[<RequireQualifiedAccess>]
module Array =
  /// Applies a function to each element of the array with its index.
  let inline foldi ([<InlineIfLambda>] folder) acc arr =
    Array.fold (fun (acc, idx) elt ->
      (folder acc idx elt, idx + 1)) (acc, 0) arr

/// Extended String.
[<RequireQualifiedAccess>]
module String =
  let explode (str: string) = [for ch in str do yield ch done]

  let inline fold ([<InlineIfLambda>] folder) acc str =
    explode str |> List.fold folder acc

  /// Convert a string to a byte array.
  [<CompiledName "ToBytes">]
  let toBytes (str: string) = str.ToCharArray () |> Array.map byte

  /// Convert a byte array to a string.
  [<CompiledName "FromBytes">]
  let fromBytes (bs: byte []) = Array.map char bs |> System.String

  /// Wrap a string with a pair of parentheses.
  [<CompiledName "WrapParen">]
  let wrapParen s =
    "(" + s + ")"

  /// Wrap a string with a pair of square brackets.
  [<CompiledName "WrapSqrdBracket">]
  let wrapSqrdBracket s =
    "[" + s + "]"

  /// Wrap a string with a pair of curly brackets.
  [<CompiledName "WrapCurlyBracket">]
  let wrapAngleBracket s =
    "<" + s + ">"

/// Extended BigInteger.
[<RequireQualifiedAccess>]
module BigInteger =
  /// Bitmask of size 128 bits.
  let mask128 = bigint.Subtract (bigint.Pow (2I, 128), bigint.One)

  /// Bitmask of size 256 bits.
  let mask256 = bigint.Subtract (bigint.Pow (2I, 256), bigint.One)

  /// Bitmask of size 512 bits.
  let mask512 = bigint.Subtract (bigint.Pow (2I, 512), bigint.One)

  /// Get a bitmask of size n.
  let getMask n = bigint.Pow (2I, n) - 1I

[<RequireQualifiedAccess>]
module Byte =
  /// Check if a byte is null.
  [<CompiledName "IsNull">]
  let isNull b = b = 0uy

  /// Check if a byte is printable.
  [<CompiledName "IsPrintable">]
  let isPrintable b = b >= 33uy && b <= 126uy

  /// Check if a byte is a whitespace.
  [<CompiledName "IsWhitespace">]
  let isWhitespace b = b = 32uy || (b >= 9uy && b <= 13uy)

  /// Check if a byte is a control character.
  [<CompiledName "IsControl">]
  let isControl b =
    b = 127uy || (b >= 1uy && b <= 8uy) || (b >= 14uy && b <= 31uy)

  /// Get a string representation of a byte used in B2R2. A null byte is
  /// represented as a dot, a printable byte is represented as an ASCII
  /// character, a whitespace is represented as an underscore, and a control
  /// character is represented as an asterisk.
  [<CompiledName "GetRepresentation">]
  let getRepresentation (b: byte) =
    if isNull b then "."
    elif isPrintable b then (char b).ToString ()
    elif isWhitespace b then "_"
    elif isControl b then "*"
    else "."

/// Extended Int64.
[<RequireQualifiedAccess>]
module Int64 =
  /// Get a power from a 64-bit integer.
  let pow value power =
    let rec loop result cnt =
      if result = 0L then raise <| System.OverflowException ()
      else if cnt = 0L then result
      else loop (result * value) (cnt - 1L)
    if (power = 0L) then 1L
    else loop value (power - 1L)

/// Extended Result.
[<RequireQualifiedAccess>]
module Result =
  /// Get the result assuming that there is no error.
  let inline get res =
    match res with
    | Ok (r) -> r
    | Error _ -> invalidOp "The Result type had an Error, but not handled."

[<RequireQualifiedAccess>]
module SortedList =
  let rec private binSearch value lo hi (keys: IList<_>) (comp: Comparer<_>) =
    if lo < hi then
      let mid = (lo + hi) / 2
      if comp.Compare (keys[mid], value) < 0 then
        binSearch value (mid + 1) hi keys comp
      else
        binSearch value lo (mid - 1) keys comp
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
      if comp.Compare (keys[idx], key) < 0 then keys[idx + 1] else keys[idx]
      |> Some

// vim: set tw=80 sts=2 sw=2:
