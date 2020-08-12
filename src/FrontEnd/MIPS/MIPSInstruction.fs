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

namespace B2R2.FrontEnd.MIPS

open B2R2
open B2R2.FrontEnd
open System.Text

/// The internal representation for a MIPS instruction used by our
/// disassembler and lifter.
type MIPSInstruction (addr, numBytes, insInfo, wordSize) =
  inherit Instruction (addr, numBytes, wordSize)

  let defaultCtxt = ParsingContext.Init ()

  /// Basic instruction information.
  member val Info: InsInfo = insInfo

  override __.NextParsingContext with get() = defaultCtxt

  override __.AuxParsingContext with get() = None

  override __.IsBranch () =
    match __.Info.Opcode with
    | Opcode.B | Opcode.BAL | Opcode.BEQ | Opcode.BGEZ | Opcode.BGEZAL
    | Opcode.BGTZ | Opcode.BLEZ | Opcode.BLTZ | Opcode.BNE
    | Opcode.JALR | Opcode.JALRHB | Opcode.JR | Opcode.JRHB -> true
    | _ -> false

  member __.HasConcJmpTarget () =
    match __.Info.Operands with
    | OneOperand (OpAddr _) -> true
    | _ -> false

  override __.IsDirectBranch () =
    __.IsBranch () && __.HasConcJmpTarget ()

  override __.IsIndirectBranch () =
    __.IsBranch () && (not <| __.HasConcJmpTarget ())

  override __.IsCondBranch () =
    match __.Info.Opcode with
    | Opcode.BEQ | Opcode.BLTZ | Opcode.BLEZ | Opcode.BGTZ | Opcode.BGEZ
    | Opcode.BGEZAL | Opcode.BNE -> true
    | _ -> false

  override __.IsCJmpOnTrue () =
    match __.Info.Opcode with
    | Opcode.BEQ | Opcode.BLTZ | Opcode.BLEZ | Opcode.BGTZ | Opcode.BGEZ
    | Opcode.BGEZAL -> true
    | _ -> false

  override __.IsCall () =
    match __.Info.Opcode with
    | Opcode.JR | Opcode.JALR | Opcode.JALRHB -> true
    | _ -> false

  override __.IsRET () = false // XXX

  override __.IsInterrupt () = Utils.futureFeature ()

  override __.IsExit () = // FIXME
    __.IsDirectBranch () ||
    __.IsIndirectBranch ()

  override __.DirectBranchTarget (addr: byref<Addr>) =
    if __.IsBranch () then
      match __.Info.Operands with
      | OneOperand (OpAddr (Relative offset)) ->
        addr <- (int64 __.Address + offset) |> uint64
        true
      | _ -> false
    else false

  override __.IndirectTrampolineAddr (addr: byref<Addr>) =
    if __.IsBranch () then Utils.futureFeature ()
    else false

  override __.GetNextInstrAddrs () = Utils.futureFeature ()

  override __.InterruptNum (num: byref<int64>) = Utils.futureFeature ()

  override __.IsNop () =
    __.Info.Opcode = Opcode.NOP

  override __.Translate ctxt =
    Lifter.translate __.Info ctxt

  member private __.StrBuilder _ (str: string) (acc: StringBuilder) =
    acc.Append (str)

  override __.Disasm (showAddr, _resolveSymbol, _fileInfo) =
    let acc = StringBuilder ()
    let acc = Disasm.disasm showAddr wordSize __.Info __.StrBuilder acc
    acc.ToString ()

  override __.Disasm () =
    let acc = StringBuilder ()
    let acc = Disasm.disasm false wordSize __.Info __.StrBuilder acc
    acc.ToString ()

  member private __.WordBuilder kind str (acc: AsmWordBuilder) =
    acc.Append ({ AsmWordKind = kind; AsmWordValue = str })

  override __.Decompose () =
    AsmWordBuilder (8)
    |> Disasm.disasm true wordSize __.Info __.WordBuilder
    |> fun b -> b.Finish ()

// vim: set tw=80 sts=2 sw=2:
