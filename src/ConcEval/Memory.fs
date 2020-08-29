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

namespace B2R2.ConcEval

open B2R2
open System.Collections.Generic

type Memory (reader: Addr -> Addr -> Result<byte, ErrorCase>) =
  /// Store memory contents (byte-level).
  let mem = Dictionary<Addr, byte> ()

  let mutable reader = reader

  member __.Reader with get() = reader and set(f) = reader <- f

  member private __.Load (pc: Addr) addr =
    if mem.ContainsKey (addr) then Ok mem.[addr]
    else __.Reader pc addr

  member private __.ReadLE acc pc addr i =
    if i <= 0UL then Ok acc
    else
      match __.Load pc (addr + i - 1UL) with
      | Ok b -> __.ReadLE (b :: acc) pc addr (i - 1UL)
      | Error e -> Error e

  member private __.ReadBE acc pc len addr i =
    if i >= len then Ok acc
    else
      match __.Load pc (addr + i) with
      | Ok b -> __.ReadBE (b :: acc) pc len addr (i + 1UL)
      | Error e -> Error e

  member __.Read pc addr endian typ =
    let len = RegType.toByteWidth typ |> uint64
    match endian with
    | Endian.Little -> __.ReadLE [] pc addr len
    | _ -> __.ReadBE [] pc len addr 0UL
    |> function
      | Ok lst -> Array.ofList lst |> BitVector.ofArr |> Ok
      | Error e -> Error e

  member __.Write addr v endian =
    let len = BitVector.getType v |> RegType.toByteWidth |> int
    let v = BitVector.getValue v
    if endian = Endian.Big then
      for i = 1 to len do
        let offset = i - 1
        let b = (v >>> (offset * 8)) &&& 255I |> byte
        mem.[addr + uint64 (len - i)] <- b
    else
      for i = 1 to len do
        let offset = i - 1
        let b = (v >>> (offset * 8)) &&& 255I |> byte
        mem.[addr + uint64 offset] <- b

  member __.Clear () = mem.Clear ()
