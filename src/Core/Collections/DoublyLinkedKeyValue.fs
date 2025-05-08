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

namespace B2R2.Collections

/// <summary>
/// Represents a doubly-linked key-value node that is used in the
/// <see cref='T:B2R2.Collections.LRUCache`2'/>.
/// </summary>
[<AllowNullLiteral>]
type DoublyLinkedKeyValue<'K, 'V when 'K: equality and 'V: equality>
  (prev, next, key, value) =
  let mutable prev = prev
  let mutable next = next
  let mutable refCount = 0

  member _.Prev
    with get(): DoublyLinkedKeyValue<'K, 'V> = prev and set(n) = prev <- n

  member _.Next
    with get(): DoublyLinkedKeyValue<'K, 'V> = next and set(n) = next <- n

  member _.Key with get(): 'K = key

  member _.Value with get(): 'V = value

  member _.RefCount with get() = refCount and set(n) = refCount <- n

  override _.GetHashCode () = value.GetHashCode ()

  override this.Equals rhs =
    match rhs with
    | :? DoublyLinkedKeyValue<'K, 'V> as rhs -> this.Value = rhs.Value
    | _ -> false
