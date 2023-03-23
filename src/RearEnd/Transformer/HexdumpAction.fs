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

open B2R2
open B2R2.RearEnd

/// The `hexdump` action.
type HexdumpAction () =
  let rec hexdump (o: obj) =
    let typ = o.GetType ()
    if typ = typeof<Binary> then hexdumpBinary o
    else invalidArg (nameof HexdumpAction) "Invalid input type."

  and hexdumpBinary o =
    let bin = unbox<Binary> o
    let hdl = Binary.Handle bin
    let bs = hdl.BinFile.Span.ToArray ()
    HexDumper.dump 16 hdl.BinFile.WordSize true hdl.BinFile.BaseAddress bs
    |> box

  interface IAction with
    member __.ActionID with get() = "hexdump"
    member __.Signature with get() = "Binary -> string"
    member __.Description with get() = """
    Takes in a binary and converts it to a hexdump string.
"""
    member __.Transform args collection =
      match args with
      | [] ->
        { Values = collection.Values |> Array.map hexdump }
      | _ -> invalidArg (nameof HexdumpAction) "Invalid argument given."
