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

open System.Collections.Generic
open System.Collections.Concurrent
open B2R2

[<AbstractClass>]
type Memory () =

  /// Read a byte from the memory.
  abstract member ByteRead: Addr -> Result<byte, ErrorCase>

  /// Write a byte from the memory.
  abstract member ByteWrite: Addr * byte -> unit

  /// Clear up the memory contents; make the whole memory empty.
  abstract member Clear: unit -> unit

  member private __.ReadLE acc addr i =
    if i <= 0UL then Ok acc
    else
      match __.ByteRead (addr + i - 1UL) with
      | Ok b -> __.ReadLE (b :: acc) addr (i - 1UL)
      | Error e -> Error e

  member private __.ReadBE acc len addr i =
    if i >= len then Ok acc
    else
      match __.ByteRead (addr + i) with
      | Ok b -> __.ReadBE (b :: acc) len addr (i + 1UL)
      | Error e -> Error e

  /// Read a bitvector value from the memory.
  member __.Read addr endian typ =
    let len = RegType.toByteWidth typ |> uint64
    match endian with
    | Endian.Little -> __.ReadLE [] addr len
    | _ -> __.ReadBE [] len addr 0UL
    |> function
      | Ok lst -> Array.ofList lst |> BitVector.OfArr |> Ok
      | Error e -> Error e

  /// Write a bitvector value to the memory.
  member __.Write addr v endian =
    let len = BitVector.GetType v |> RegType.toByteWidth |> int
    let v = BitVector.GetValue v
    if endian = Endian.Big then
      for i = 1 to len do
        let offset = i - 1
        let b = (v >>> (offset * 8)) &&& 255I |> byte
        __.ByteWrite (addr + uint64 (len - i), b)
    else
      for i = 1 to len do
        let offset = i - 1
        let b = (v >>> (offset * 8)) &&& 255I |> byte
        __.ByteWrite (addr + uint64 offset, b)

/// Non-sharable memory.
type NonsharableMemory () =
  inherit Memory ()

  let mem = Dictionary<Addr, byte> ()

  override __.ByteRead (addr) =
    if mem.ContainsKey addr then Ok mem[addr]
    else Error ErrorCase.InvalidMemoryRead

  override __.ByteWrite (addr, b) = mem[addr] <- b

  override __.Clear () = mem.Clear ()

/// Thread-safe (sharable) memory.
type SharableMemory () =
  inherit Memory ()

  let mem = ConcurrentDictionary<Addr, byte> ()

  override __.ByteRead (addr) =
    if mem.ContainsKey addr then Ok mem[addr]
    else Error ErrorCase.InvalidMemoryRead

  override __.ByteWrite (addr, b) = mem[addr] <- b

  override __.Clear () = mem.Clear ()
