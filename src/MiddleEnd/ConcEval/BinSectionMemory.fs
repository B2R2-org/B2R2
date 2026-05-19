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
open B2R2.FrontEnd

/// Represents a memory backed by binary file sections.
type BinSectionMemory(hdl: BinHandle) =
  let mem = NonsharableMemory() :> IMemory
  let mutable isBacked = true

  interface IMemory with

    member _.ByteRead(addr) =
      match mem.ByteRead addr with
      | Ok b -> Ok b
      | Error _ when isBacked && hdl.File.IsValidAddr addr ->
        match hdl.TryReadBytes(addr, 1) with
        | Ok bs -> Ok bs[0]
        | Error e -> Error e
      | Error e -> Error e

    member _.ByteWrite(addr, b) = mem.ByteWrite(addr, b)

    member this.Read(addr, endian, typ) = Memory.read addr endian typ this

    member this.Write(addr, v, endian) = Memory.write addr v endian this

    member _.Clear() =
      isBacked <- false
      mem.Clear()
