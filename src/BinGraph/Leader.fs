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

namespace B2R2.BinGraph

open B2R2
open B2R2.FrontEnd

/// Leader information at a ProrgramPoint. Each leader holds information about
/// the corresponding basic block, such as ArchOperationMode and its address
/// offset. The offset is a virtual offset that can be used to readjust the
/// address of the basic block when necessary (it is mostly set to 0 though).
[<CustomEquality; CustomComparison>]
type LeaderInfo = {
  Point: ProgramPoint
  Mode: ArchOperationMode
  Offset: Addr
}
with
  override __.Equals (obj) =
    match obj with
    | :? LeaderInfo as y -> __.Point = y.Point
    | _ -> false

  override __.GetHashCode () = hash __.Point

  interface System.IComparable with
    member __.CompareTo obj =
      match obj with
      | :? LeaderInfo as y -> compare __.Point y.Point
      | _ -> -1

  static member Init (hdl: BinHandler, addr, mode, offset) =
    match hdl.ISA.Arch with
    | Arch.ARMv7 ->
      if addr &&& 1UL = 0UL then
        { Point = ProgramPoint (addr, 0)
          Mode = mode
          Offset = offset }
      else
        { Point = ProgramPoint (addr - 1UL, 0)
          Mode = ArchOperationMode.ThumbMode
          Offset = offset }
    | _ ->
      { Point = ProgramPoint (addr, 0)
        Mode = ArchOperationMode.NoMode
        Offset = offset }

  static member Init (hdl: BinHandler, addr, offset) =
    LeaderInfo.Init (hdl, addr, ArchOperationMode.ARMMode, offset)

  static member Init (hdl: BinHandler, addr) =
    LeaderInfo.Init (hdl, addr, ArchOperationMode.ARMMode, 0UL)

  static member Init (ppoint, mode, offset) =
    { Point = ppoint; Mode = mode; Offset = offset }
