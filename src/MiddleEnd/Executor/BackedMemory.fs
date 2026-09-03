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

open B2R2
open B2R2.FrontEnd

/// Represents a memory that falls back to a read-only backing when an address
/// holds no written value. Whether a backing stands behind this memory is
/// fixed at construction: Clear() discards the values written to this memory,
/// but leaves the backing readable.
type BackedMemory<'V>(backing: Addr -> 'V voption, mem: IMemory<'V>) =

  /// Instantiates a memory backed by the sections of the given binary, with
  /// each backing byte lifted by the given function.
  new(hdl: BinHandle, lift, mem) =
    let readSection addr =
      if hdl.File.IsValidAddr addr then
        match hdl.TryReadBytes(addr, 1) with
        | Ok bs -> ValueSome(lift bs[0])
        | Error _ -> ValueNone
      else
        ValueNone
    BackedMemory(readSection, mem)

  interface IMemory<'V> with

    member _.ByteRead addr =
      match mem.ByteRead addr with
      | ValueSome v -> ValueSome v
      | ValueNone -> backing addr

    member _.ByteWrite(addr, v) = mem.ByteWrite(addr, v)

    member _.Clone() = BackedMemory(backing, mem.Clone()) :> IMemory<'V>

    member _.Clear() = mem.Clear()
