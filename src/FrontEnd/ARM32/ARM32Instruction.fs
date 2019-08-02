(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Seung Il Jung <sijung@kaist.ac.kr>

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

namespace B2R2.FrontEnd.ARM32

open B2R2

/// The internal representation for an ARM32 instruction used by our
/// disassembler and lifter.
type ARM32Instruction (addr, numBytes, insInfo) =
  inherit FrontEnd.Instruction (addr, numBytes, WordSize.Bit32)

  member val Info: InsInfo = insInfo

  override __.IsBranch () =
    match __.Info.Opcode with
    | Op.B | Op.CBNZ | Op.CBZ | Op.BL | Op.BLX | Op.BX | Op.BXJ | Op.TBB
    | Op.TBH -> true
    | _ -> false

  member __.HasConcJmpTarget () =
    match __.Info.Operands with
    | OneOperand (OprMemory (LiteralMode _)) -> true
    | _ -> false

  override __.IsDirectBranch () =
    __.IsBranch () && __.HasConcJmpTarget ()

  override __.IsIndirectBranch () =
    __.IsBranch () && (not <| __.HasConcJmpTarget ())

  override __.IsCondBranch () =
    match __.Info.Opcode, __.Info.Condition with
    | Op.B, Some Condition.AL -> false
    | Op.B, Some Condition.NV -> false
    | Op.B, Some Condition.UN -> false
    | Op.B, Some _ -> true
    // XXX: Need to add more conditions for BX
    | Op.BX, Some Condition.EQ -> true
    | _ -> false

  override __.IsCJmpOnTrue () =
    match __.Info.Opcode, __.Info.Condition with
    | Op.B, Some Condition.CS | Op.B, Some Condition.CC
    | Op.B, Some Condition.MI | Op.B, Some Condition.PL
    | Op.B, Some Condition.VS | Op.B, Some Condition.VC
    | Op.B, Some Condition.HI | Op.B, Some Condition.LS
    | Op.B, Some Condition.GE | Op.B, Some Condition.LT
    | Op.B, Some Condition.GT | Op.B, Some Condition.LE
    | Op.B, Some Condition.EQ -> true
    | _ -> false

  override __.IsCall () =
    match __.Info.Opcode with
    | Opcode.BL | Opcode.BLX -> true
    | _ -> false

  override __.IsRET () = // This is wrong
    match __.Info.Opcode, __.Info.Operands with
    | Opcode.POP, OneOperand (OprReg R.PC) -> true
    | _ -> false

  override __.IsInterrupt () = Utils.futureFeature ()

  override __.IsExit () = // FIXME
    __.IsDirectBranch () ||
    __.IsIndirectBranch ()

  override __.DirectBranchTarget (addr: byref<Addr>) =
    if __.IsBranch () then
      match __.Info.Operands with
      | OneOperand (OprMemory (LiteralMode offset)) ->
        addr <- ((int64 __.Address + offset + 8L) &&& 0xFFFFFFFFL) |> uint64
        true
      | _ -> false
    else false

  override __.IndirectTrampolineAddr (addr: byref<Addr>) =
    if __.IsBranch () then Utils.futureFeature ()
    else false

  override __.GetNextInstrAddrs () =
    // FIXME this is wrong.
    let acc = Seq.singleton (__.Address + uint64 __.Length)
    match __.DirectBranchTarget () |> Utils.tupleToOpt with
    | None -> acc
    | Some target -> Seq.singleton target |> Seq.append acc

  override __.InterruptNum (num: byref<int64>) = Utils.futureFeature ()

  override __.IsNop () =
    __.Info.Opcode = Op.NOP

  override __.Translate ctxt =
    Lifter.translate __.Info ctxt

  override __.Disasm (showAddr, _resolveSymbol, _fileInfo) =
    Disasm.disasm showAddr __.Info

  override __.Disasm () =
    Disasm.disasm false __.Info

// vim: set tw=80 sts=2 sw=2:
