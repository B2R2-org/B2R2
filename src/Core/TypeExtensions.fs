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

/// Extended Array.
module Array =
  let foldi folder acc arr =
    Array.fold (fun (acc, idx) elt -> (folder acc idx elt, idx + 1)) (acc, 0) arr

/// Extended String.
module String =
  let explode (str: string) = [for ch in str do yield ch done]

  let fold folder acc str =
    explode str |> List.fold folder acc

  /// Convert a string to a byte array.
  let toBytes (str: string) = str.ToCharArray () |> Array.map byte

  /// Convert a byte array to a string.
  let fromBytes (bs: byte []) = Array.map char bs |> System.String

/// Extended BigInteger.
module BigInteger =
  /// Bitmask of size 128 bits.
  let mask128 = bigint.Subtract (bigint.Pow (2I, 128), bigint.One)

  /// Bitmask of size 256 bits.
  let mask256 = bigint.Subtract (bigint.Pow (2I, 256), bigint.One)

  /// Bitmask of size 512 bits.
  let mask512 = bigint.Subtract (bigint.Pow (2I, 512), bigint.One)

  /// Get a bitmask of size n.
  let getMask n = bigint.Pow (2I, n) - 1I

/// Extended Int64.
module Int64 =
  /// Get a power from a 64-bit integer.
  let pow value power =
    let rec loop result cnt =
      if result = 0L then raise <| System.OverflowException ()
      else if cnt = 0L then result
      else loop (result * value) (cnt - 1L)
    if (power = 0L) then 1L
    else loop value (power - 1L)

/// Extended Option.
module Option =
  /// Unwrap an option type. If the value is None, throw the exception (exn).
  let getWithExn (value: 'a option) exn =
    match value with
    | Some v -> v
    | None -> raise exn

// vim: set tw=80 sts=2 sw=2:
