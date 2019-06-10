(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

type Memory () =
  /// Store memory contents (byte-level).
  let mem = Dictionary<Addr, byte> ()

  member val Reader: Addr -> Addr -> byte option = fun _ _ -> None with get, set

  member private __.Load (pc: Addr) addr =
    if mem.ContainsKey (addr) then mem.[addr]
    else
      match __.Reader pc addr with
      | None -> raise InvalidMemException
      | Some b -> b

  member __.Read pc addr endian typ =
    let len = RegType.toByteWidth typ
    let v = [ for i = 0 to len - 1 do yield __.Load pc (addr + uint64 i) ]
    Array.ofList (if endian = Endian.Little then v else List.rev v)
    |> BitVector.ofArr

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
