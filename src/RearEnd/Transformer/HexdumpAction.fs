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

namespace B2R2.RearEnd.Transformer

open B2R2.Logging

/// The `hexdump` action.
type HexdumpAction() =
  let rec hexdump (o: obj) =
    let typ = o.GetType()
    if typ = typeof<Binary> then hexdumpBinary o
    else invalidArg (nameof o) "Invalid input type."

  and hexdumpBinary o =
    let bin = unbox<Binary> o
    let hdl = Binary.Handle bin
    let bs = hdl.File.RawBytes
    let baseAddr = hdl.File.BaseAddress
    HexDump.makeLines 16 hdl.File.ISA.WordSize true baseAddr bs
    |> box

  interface IAction with
    member _.ActionID with get() = "hexdump"
    member _.Signature with get() = "Binary -> string"
    member _.Description with get() =
      """
    Take in a binary and convert it to a hexdump string.
"""
    member _.Transform(args, collection) =
      match args with
      | [] -> { Values = collection.Values |> Array.map hexdump }
      | _ -> invalidArg (nameof args) "Invalid argument given."
