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

open System.Collections.Generic
open B2R2

/// Represents symbolic memory indexed by concrete addresses.
type SymMemory(?mem: IDictionary<Addr, SymExpr>) =
  let mem =
    match mem with
    | Some mem -> Dictionary<Addr, SymExpr>(mem)
    | None -> Dictionary<Addr, SymExpr>()

  interface ISymMemory with

    member _.ByteRead addr =
      match mem.TryGetValue addr with
      | true, value -> Ok value
      | false, _ -> Error(InvalidMemoryRead addr)

    member _.ByteWrite(addr, value) = mem[addr] <- value

    member this.Load(addr, endian, typ) =
      SymMemoryOperation.load addr endian typ this

    member this.Store(addr, value, endian) =
      SymMemoryOperation.store addr value endian this

    member _.Clone() = SymMemory(Dictionary<Addr, SymExpr>(mem)) :> ISymMemory

    member _.Clear() = mem.Clear()
