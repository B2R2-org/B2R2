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

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinHandleNS

type Assembler (isa: ISA, startAddress) =
  let hdl = BinHandle.Init (isa)

  /// Parse the given string input, and assemble a list of byte arrays, where
  /// each array corresponds to a binary instruction.
  member __.AssembleBin asm =
    match isa.Arch with
    | Architecture.IntelX64
    | Architecture.IntelX86 -> Intel.AsmParser(isa, startAddress).Run asm
    | Architecture.MIPS1
    | Architecture.MIPS2
    | Architecture.MIPS3
    | Architecture.MIPS32
    | Architecture.MIPS32R2
    | Architecture.MIPS32R6
    | Architecture.MIPS4
    | Architecture.MIPS5
    | Architecture.MIPS64
    | _ -> raise InvalidISAException

  /// Parse the given string input, and assemble an array of IR statements.
  member __.AssembleLowUIR isFromLowUIR asm =
    if isFromLowUIR then
      LowUIR.LowUIRParser(isa, hdl.RegisterBay).Run asm
    else
      let bs = __.AssembleBin asm |> Array.concat
      let hdl = BinHandle.UpdateCode hdl startAddress bs
      let rec loop ctxt addr acc =
        match BinHandle.TryParseInstr hdl ctxt addr with
        | Ok ins ->
          let stmts = BinHandle.LiftInstr hdl ins
          let ctxt = ins.NextParsingContext
          loop ctxt (addr + uint64 ins.Length) (stmts :: acc)
        | Error _ -> List.rev acc
      loop hdl.DefaultParsingContext 0UL []
      |> Array.concat
