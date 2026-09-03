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

namespace B2R2.MiddleEnd.Executor

open System.Collections.Generic
open B2R2

/// Represents a memory that holds its values in a plain dictionary. An
/// evaluation that shares its memory across threads uses a sharable memory
/// instead.
type DictionaryMemory<'V>(mem: IDictionary<Addr, 'V>) =
  let mem = Dictionary<Addr, 'V>(mem)

  /// Instantiates an empty memory.
  new() = DictionaryMemory(Dictionary())

  interface IMemory<'V> with

    member _.ByteRead addr =
      match mem.TryGetValue addr with
      | true, v -> ValueSome v
      | false, _ -> ValueNone

    member _.ByteWrite(addr, v) = mem[addr] <- v

    member _.Clone() = DictionaryMemory(mem) :> IMemory<'V>

    member _.Clear() = mem.Clear()
