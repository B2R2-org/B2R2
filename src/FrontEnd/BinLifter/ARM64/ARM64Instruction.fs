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

namespace B2R2.FrontEnd.BinLifter.ARM64

open B2R2
open B2R2.FrontEnd.BinLifter
open System.Text

/// The internal representation for an ARM64 instruction used by our
/// disassembler and lifter.
type ARM64Instruction (addr, numBytes, insInfo, wordSize) =
  inherit Instruction (addr, numBytes, wordSize)

  let defaultCtxt = ParsingContext.Init ()

  /// Basic instruction information.
  member val Info: InsInfo = insInfo

  override __.NextParsingContext with get() = defaultCtxt

  override __.AuxParsingContext with get() = None

  override __.IsBranch () =
    match __.Info.Opcode with
    (* Conditional branch *)
    | Opcode.BEQ | Opcode.BCS | Opcode.BMI | Opcode.BVS | Opcode.BHI
    | Opcode.BGE | Opcode.BGT | Opcode.BNE | Opcode.BCC | Opcode.BPL
    | Opcode.BVC | Opcode.BLS | Opcode.BLT | Opcode.BLE
    | Opcode.CBNZ | Opcode.CBZ | Opcode.TBNZ | Opcode.TBZ
    (* Unconditional branch (immediate) *)
    | Opcode.B | Opcode.BL
    (* Unconditional branch (register) *)
    | Opcode.BLR | Opcode.BR | Opcode.RET
      -> true
    | _ -> false

  member __.HasConcJmpTarget () =
    match __.Info.Operands with
    | OneOperand (Memory (LiteralMode _)) -> true
    | _ -> false

  override __.IsDirectBranch () =
    __.IsBranch () && __.HasConcJmpTarget ()

  override __.IsIndirectBranch () =
    __.IsBranch () && (not <| __.HasConcJmpTarget ())

  override __.IsCondBranch () =
    match __.Info.Opcode with
    | Opcode.BEQ | Opcode.BCS | Opcode.BMI | Opcode.BVS | Opcode.BHI
    | Opcode.BGE | Opcode.BGT | Opcode.BNE | Opcode.BCC | Opcode.BPL
    | Opcode.BVC | Opcode.BLS | Opcode.BLT | Opcode.BLE
    | Opcode.CBNZ | Opcode.CBZ | Opcode.TBNZ | Opcode.TBZ -> true
    | _ -> false

  override __.IsCJmpOnTrue () =
    match __.Info.Opcode with
    | Opcode.BEQ | Opcode.BCS | Opcode.BMI | Opcode.BVS | Opcode.BHI
    | Opcode.BGE | Opcode.BGT | Opcode.BCC | Opcode.BPL | Opcode.BVC
    | Opcode.BLS | Opcode.BLT | Opcode.BLE | Opcode.CBZ | Opcode.TBZ -> true
    | _ -> false

  override __.IsCall () =
    match __.Info.Opcode with
    | Opcode.BL | Opcode.BLR -> true
    | _ -> false

  override __.IsRET () =
    __.Info.Opcode = Opcode.RET

  override __.IsInterrupt () = Utils.futureFeature ()

  override __.IsExit () = // FIXME
    __.IsDirectBranch () ||
    __.IsIndirectBranch ()

  override __.DirectBranchTarget (addr: byref<Addr>) =
    if __.IsBranch () then
      match __.Info.Operands with
      | OneOperand (Memory (LiteralMode (ImmOffset (Lbl offset)))) ->
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
    let acc = Disasm.disasm showAddr __.Info __.StrBuilder acc
    acc.ToString ()

  override __.Disasm () =
    let acc = StringBuilder ()
    let acc = Disasm.disasm false __.Info __.StrBuilder acc
    acc.ToString ()

  member private __.WordBuilder kind str (acc: AsmWordBuilder) =
    acc.Append ({ AsmWordKind = kind; AsmWordValue = str })

  override __.Decompose () =
    AsmWordBuilder (8)
    |> Disasm.disasm true __.Info __.WordBuilder
    |> fun b -> b.Finish ()

// vim: set tw=80 sts=2 sw=2:
