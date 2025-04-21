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

namespace B2R2.BinIR

/// Represents the hash consing information of an object, which includes a
/// unique ID (tag) and a hash value.
[<AllowNullLiteral>]
type HashConsingInfo (id, hash) =
  let mutable id = id
  let mutable hash = hash

  /// <summary>
  /// Creates a new instance of HashConsingInfo with default values.
  /// </summary>
  new () = HashConsingInfo (0u, 0)

  /// Unique ID of the hash consed object.
  member _.ID with get(): uint32 = id and set(v) = id <- v
  /// Hash value of the hash consed object.
  member _.Hash with get(): int = hash and set(v) = hash <- v

[<AutoOpen>]
module internal HashConsingInfo =
  let inline (===) a b = LanguagePrimitives.PhysicalEquality a b
