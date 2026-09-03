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

namespace B2R2.MiddleEnd.ConcEval

open B2R2
open B2R2.MiddleEnd.Executor

/// Provides the multi-byte accesses that every memory derives from its
/// single-byte primitives.
[<RequireQualifiedAccess>]
module Memory =
  let rec private readLE acc addr i (mem: IMemory<byte>) =
    if i <= 0UL then
      Ok acc
    else
      match mem.ByteRead(addr + i - 1UL) with
      | ValueSome b -> readLE (b :: acc) addr (i - 1UL) mem
      | ValueNone -> Error ErrorCase.InvalidMemoryRead

  let rec private readBE acc len addr i (mem: IMemory<byte>) =
    if i >= len then
      Ok acc
    else
      match mem.ByteRead(addr + i) with
      | ValueSome b -> readBE (b :: acc) len addr (i + 1UL) mem
      | ValueNone -> Error ErrorCase.InvalidMemoryRead

  /// Reads a bitvector value from the memory.
  [<CompiledName "Read">]
  let read addr endian typ mem =
    let len = RegType.toByteWidth typ |> uint64
    match endian with
    | Endian.Little -> readLE [] addr len mem
    | _ -> readBE [] len addr 0UL mem
    |> function
      | Ok lst -> Array.ofList lst |> BitVector |> Ok
      | Error e -> Error e

  /// Writes a bitvector value to the memory.
  [<CompiledName "Write">]
  let write addr (v: BitVector) endian (mem: IMemory<byte>) =
    let len = v.Length |> RegType.toByteWidth |> int
    let v = v.ToBigInt()
    if endian = Endian.Big then
      for i = 1 to len do
        let offset = i - 1
        let b = (v >>> (offset * 8)) &&& 255I |> byte
        mem.ByteWrite(addr + uint64 (len - i), b)
    else
      for i = 1 to len do
        let offset = i - 1
        let b = (v >>> (offset * 8)) &&& 255I |> byte
        mem.ByteWrite(addr + uint64 offset, b)
