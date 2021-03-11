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

namespace B2R2.Peripheral.Assembly

open B2R2.FrontEnd.BinInterface

/// Assembly code parser interface.
[<AbstractClass>]
type AsmParser () =
  /// Run parsing from a given assembly string, and assemble binary code.
  abstract Assemble: string -> Result<byte [] list, string>

  /// Run parsing from a given assembly string, and lift it to LowUIR code.
  member __.Lift hdl asm addr =
    __.Assemble asm
    |> Result.bind (fun bins ->
      bins
      |> List.fold (fun acc bs ->
        let hdl = BinHandle.UpdateCode hdl addr bs
        let ins = BinHandle.ParseInstr (hdl, addr)
        BinHandle.LiftInstr hdl ins :: acc
      ) []
      |> List.rev
      |> Array.concat
      |> Ok)
