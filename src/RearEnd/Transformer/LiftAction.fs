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

open System.Text
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinInterface

/// The `lift` action.
type LiftAction () =
  let rec lift (sb: StringBuilder) hdl ptr =
    if BinFilePointer.IsValid ptr then
      match BinHandle.TryParseInstr (hdl, ptr) with
      | Ok instr ->
        let s = instr.Translate hdl.TranslationContext |> Pp.stmtsToString
        let ptr = BinFilePointer.Advance ptr (int instr.Length)
        lift (sb.Append s) hdl ptr
      | Error _ -> "Bad instruction found"
    else
      sb.ToString ()

  let liftByteArray (o: obj) =
    let bin = unbox<Binary> o
    let hdl = Binary.Handle bin
    let baddr = hdl.BinFile.BaseAddress
    let ptr = BinFilePointer (baddr, 0, hdl.BinFile.Length - 1)
    let sb = StringBuilder ()
    lift sb hdl ptr
    |> box

  interface IAction with
    member __.ActionID with get() = "lift"
    member __.Signature with get() = "Binary -> string"
    member __.Description with get() = """
    Take in a binary and linearly disassemble the binary and lift it to a
    sequence of LowUIR statements, and dump the result to a string.
"""
    member __.Transform args collection =
      { Values = collection.Values |> Array.map liftByteArray }
