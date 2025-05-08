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
open B2R2.FrontEnd

type AsmInterface (isa: ISA, startAddress) =
  let asmParser =
    match isa with
    | Intel -> Intel.IntelAsmParser (isa, startAddress) :> AsmParser
    | _ -> raise InvalidISAException
  let regFactory = GroundWork.CreateRegisterFactory isa
  let uirParser = LowUIR.LowUIRParser (isa, regFactory)

  /// Parse the given assembly input, and assemble a list of byte arrays, where
  /// each array corresponds to a binary instruction.
  member _.AssembleBin asm = asmParser.Assemble asm

  member _.Parser with get() = asmParser.Parser

  /// Parse the given string input, and lift it to an array of LowUIR
  /// statements. If the given string represents LowUIR instructions, then we
  /// simply parse the assembly instructions and return the corresponding AST.
  member _.LiftLowUIR isFromLowUIR asm =
    if isFromLowUIR then uirParser.Parse asm
    else asmParser.Lift asm startAddress
