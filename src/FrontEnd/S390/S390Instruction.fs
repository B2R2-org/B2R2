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

namespace B2R2.FrontEnd.S390

open B2R2
open B2R2.FrontEnd.S390
open B2R2.FrontEnd.S390.Helper
open B2R2.FrontEnd.BinLifter

/// The internal representation for a S390 instruction used by our
/// disassembler and lifter.
type S390Instruction (addr, numBytes, insInfo, wordSize) =
  inherit Instruction (addr, numBytes, WordSize.Bit32)

  /// Basic instruction information.
  member val Info: InsInfo = insInfo

  override __.IsBranch () =
    match __.Info.Opcode with
    | Opcode.BALR | Opcode.BAL | Opcode.BASR | Opcode.BAS
    | Opcode.BASSM | Opcode.BSM | Opcode.BIC | Opcode.BCR
    | Opcode.BC | Opcode.BCTR | Opcode.BCTGR | Opcode.BCT
    | Opcode.BCTG | Opcode.BXH | Opcode.BXHG | Opcode.BXLE
    | Opcode.BXLEG | Opcode.BPP | Opcode.BPRP | Opcode.BRAS
    | Opcode.BRASL | Opcode.BRC | Opcode.BRCL | Opcode.BRCT
    | Opcode.BRCTG | Opcode.BRCTH | Opcode.BRXH | Opcode.BRXHG
    | Opcode.BRXLE | Opcode.BRXLG -> true
    | Opcode.CRB | Opcode.CGRB | Opcode.CRJ | Opcode.CGRJ
    | Opcode.CIB | Opcode.CGIB | Opcode.CIJ | Opcode.CGIJ
    | Opcode.CLRB | Opcode.CLGRB | Opcode.CLRJ | Opcode.CLGRJ
      when not (__.IsNop()) -> true
    | _ -> false

  override __.IsModeChanging () = false

  member __.HasConcJmpTarget () = Terminator.futureFeature ()

  override __.IsDirectBranch () =
    __.IsBranch () && __.HasConcJmpTarget ()

  override __.IsIndirectBranch () =
    __.IsBranch () && (not <| __.HasConcJmpTarget ())

  override __.IsCondBranch () =
    match __.Info.Opcode with
    | Opcode.BC | Opcode.BCR | Opcode.BIC -> true
    | Opcode.CRB | Opcode.CGRB | Opcode.CRJ | Opcode.CGRJ
    | Opcode.CIB | Opcode.CGIB | Opcode.CIJ | Opcode.CGIJ
    | Opcode.CLRB | Opcode.CLGRB | Opcode.CLRJ | Opcode.CLGRJ
      when not (__.IsNop()) -> true
    | _ -> false

  override __.IsCJmpOnTrue () = Terminator.futureFeature ()

  override __.IsCall () =
    match __.Info.Opcode with
    | Opcode.BAL | Opcode.BALR | Opcode.BAS | Opcode.BASR
    | Opcode.BASSM | Opcode.BSM -> true
    | Opcode.BC | Opcode.BCR when getMaskVal __.Info.Operands = Some(15us) ->
      true
    | _ -> false

  override __.IsRET () =
    match __.Info.Opcode with
    | Opcode.BCR | Opcode.BASR | Opcode.BCTR ->
      match __.Info.Operands with
      | TwoOperands (_, OpReg Register.R14) -> true
      | _ -> false
    | _ -> false

  override __.IsInterrupt () = Terminator.futureFeature ()

  override __.IsExit () = Terminator.futureFeature ()

  override __.IsTerminator () =
    __.IsDirectBranch () ||
    __.IsIndirectBranch ()

  override __.DirectBranchTarget (_addr: byref<Addr>) = Terminator.futureFeature ()

  override __.IndirectTrampolineAddr (_addr: byref<Addr>) =
    Terminator.futureFeature ()

  override __.Immediate (_v: byref<int64>) = Terminator.futureFeature ()

  override __.GetNextInstrAddrs () = Terminator.futureFeature ()

  override __.InterruptNum (_num: byref<int64>) = Terminator.futureFeature ()

  override __.IsNop () =
    let opr = __.Info.Operands
    match __.Info.Opcode with
    | Opcode.CRB | Opcode.CGRB | Opcode.CRJ | Opcode.CGRJ
    | Opcode.CIB | Opcode.CGIB | Opcode.CIJ | Opcode.CGIJ
    | Opcode.CLRB | Opcode.CLGRB | Opcode.CLRJ | Opcode.CLGRJ
    | Opcode.CRT | Opcode.CGRT | Opcode.CIT | Opcode.CGIT
    | Opcode.CLRT | Opcode.CLGRT | Opcode.CLFIT | Opcode.CLGIT ->
      match getMaskVal opr with
      | Some (value) -> (uint16 value &&& 0b1110us) = 0us
      | None -> false
    | Opcode.LOCR | Opcode.LOCGR | Opcode.LOC | Opcode.LOCG
    | Opcode.LOCFHR | Opcode.LOCFH | Opcode.STOC | Opcode.STOCG
    | Opcode.STOCFH ->
      match getMaskVal opr with
      | Some (value) -> (uint16 value &&& 0b1111us) = 0us
      | None -> false
    | _ -> false

  override __.Translate ctxt =
    Terminator.futureFeature ()

  override __.TranslateToList ctxt =
    Terminator.futureFeature ()

  override __.Disasm (showAddr: bool, nameReader: INameReadable) =
    let resolveSymb = not (isNull nameReader)
    let builder =
      DisasmStringBuilder (showAddr, resolveSymb, wordSize, addr, numBytes)
    Disasm.disasm nameReader wordSize __.Info builder
    builder.ToString ()

  override __.Disasm () =
    let builder =
      DisasmStringBuilder (false, false, wordSize, addr, numBytes)
    Disasm.disasm null wordSize __.Info builder
    builder.ToString ()

  override __.Decompose (showAddr) =
    let builder =
      DisasmWordBuilder (showAddr, false, wordSize, addr, numBytes, 8)
    Disasm.disasm null wordSize __.Info builder
    builder.ToArray ()

  override __.IsInlinedAssembly () = false

  override __.Equals (_) = Terminator.futureFeature ()
  override __.GetHashCode () = Terminator.futureFeature ()

// vim: set tw=80 sts=2 sw=2: