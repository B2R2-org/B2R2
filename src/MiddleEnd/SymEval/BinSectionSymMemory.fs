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

namespace B2R2.MiddleEnd.SymEval

open B2R2
open B2R2.FrontEnd

/// Represents symbolic memory backed by binary file sections.
type BinSectionSymMemory(hdl: BinHandle, mem: ISymMemory, isBacked: bool) =
  let mutable isBacked = isBacked

  new(hdl) = BinSectionSymMemory(hdl, SymMemory() :> ISymMemory, true)

  new(hdl, mem) = BinSectionSymMemory(hdl, mem, true)

  new(hdl, isBacked) =
    BinSectionSymMemory(hdl, SymMemory() :> ISymMemory, isBacked)

  interface ISymMemory with

    member _.ByteRead addr =
      match mem.ByteRead addr with
      | Ok value -> Ok value
      | Error _ when isBacked && hdl.File.IsValidAddr addr ->
        match hdl.TryReadBytes(addr, 1) with
        | Ok bs -> Ok(SymExpr.Const(BitVector(uint32 bs[0], 8<rt>)))
        | Error _ -> Error(InvalidMemoryRead addr)
      | Error e -> Error e

    member _.ByteWrite(addr, value) = mem.ByteWrite(addr, value)

    member this.Load(addr, endian, typ) =
      SymMemoryOperation.load addr endian typ this

    member this.Store(addr, value, endian) =
      SymMemoryOperation.store addr value endian this

    member _.Clone() =
      BinSectionSymMemory(hdl, mem.Clone(), isBacked) :> ISymMemory

    member _.Clear() =
      isBacked <- false
      mem.Clear()
