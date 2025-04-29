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
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.S390.Helper

/// The internal representation for a S390 instruction used by our
/// disassembler and lifter.
type S390Instruction (addr, numBytes, insInfo, wordSize) =
  inherit Instruction (addr, numBytes, WordSize.Bit32)

  /// Basic instruction information.
  member val Info: InsInfo = insInfo

  override this.IsBranch () =
    match this.Info.Opcode with
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
      when not (this.IsNop()) -> true
    | _ -> false

  override _.IsModeChanging () = false

  member _.HasConcJmpTarget () = Terminator.futureFeature ()

  override this.IsDirectBranch () =
    this.IsBranch () && this.HasConcJmpTarget ()

  override this.IsIndirectBranch () =
    this.IsBranch () && not <| this.HasConcJmpTarget ()

  override this.IsCondBranch () =
    match this.Info.Opcode with
    | Opcode.BC | Opcode.BCR | Opcode.BIC -> true
    | Opcode.CRB | Opcode.CGRB | Opcode.CRJ | Opcode.CGRJ
    | Opcode.CIB | Opcode.CGIB | Opcode.CIJ | Opcode.CGIJ
    | Opcode.CLRB | Opcode.CLGRB | Opcode.CLRJ | Opcode.CLGRJ
      when not (this.IsNop()) -> true
    | _ -> false

  override _.IsCJmpOnTrue () = Terminator.futureFeature ()

  override this.IsCall () =
    match this.Info.Opcode with
    | Opcode.BAL | Opcode.BALR | Opcode.BAS | Opcode.BASR
    | Opcode.BASSM | Opcode.BSM -> true
    | Opcode.BC | Opcode.BCR when getMaskVal this.Info.Operands = Some(15us) ->
      true
    | _ -> false

  override this.IsRET () =
    match this.Info.Opcode with
    | Opcode.BCR | Opcode.BASR | Opcode.BCTR ->
      match this.Info.Operands with
      | TwoOperands (_, OpReg Register.R14) -> true
      | _ -> false
    | _ -> false

  override _.IsInterrupt () = Terminator.futureFeature ()

  override _.IsExit () = Terminator.futureFeature ()

  override this.IsTerminator () =
    this.IsDirectBranch () || this.IsIndirectBranch ()

  override _.DirectBranchTarget (_addr: byref<Addr>) =
    Terminator.futureFeature ()

  override _.IndirectTrampolineAddr (_addr: byref<Addr>) =
    Terminator.futureFeature ()

  override _.Immediate (_v: byref<int64>) = Terminator.futureFeature ()

  override _.GetNextInstrAddrs () = Terminator.futureFeature ()

  override _.InterruptNum (_num: byref<int64>) = Terminator.futureFeature ()

  override this.IsNop () =
    let opr = this.Info.Operands
    match this.Info.Opcode with
    | Opcode.CRB | Opcode.CGRB | Opcode.CRJ | Opcode.CGRJ
    | Opcode.CIB | Opcode.CGIB | Opcode.CIJ | Opcode.CGIJ
    | Opcode.CLRB | Opcode.CLGRB | Opcode.CLRJ | Opcode.CLGRJ
    | Opcode.CRT | Opcode.CGRT | Opcode.CIT | Opcode.CGIT
    | Opcode.CLRT | Opcode.CLGRT | Opcode.CLFIT | Opcode.CLGIT ->
      match getMaskVal opr with
      | Some value -> uint16 value &&& 0b1110us = 0us
      | None -> false
    | Opcode.LOCR | Opcode.LOCGR | Opcode.LOC | Opcode.LOCG
    | Opcode.LOCFHR | Opcode.LOCFH | Opcode.STOC | Opcode.STOCG
    | Opcode.STOCFH ->
      match getMaskVal opr with
      | Some value -> uint16 value &&& 0b1111us = 0us
      | None -> false
    | _ -> false

  override _.Translate _ =
    Terminator.futureFeature ()

  override _.TranslateToList _ =
    Terminator.futureFeature ()

  override this.Disasm (showAddr: bool, nameReader: INameReadable) =
    let resolveSymb = not (isNull nameReader)
    let builder =
      DisasmStringBuilder (showAddr, resolveSymb, wordSize, addr, numBytes)
    Disasm.disasm nameReader this.Info builder
    builder.ToString ()

  override this.Disasm () =
    let builder =
      DisasmStringBuilder (false, false, wordSize, addr, numBytes)
    Disasm.disasm null this.Info builder
    builder.ToString ()

  override this.Decompose showAddr =
    let builder =
      DisasmWordBuilder (showAddr, false, wordSize, addr, numBytes, 8)
    Disasm.disasm null this.Info builder
    builder.ToArray ()

  override _.IsInlinedAssembly () = false

  override _.Equals _ = Terminator.futureFeature ()

  override _.GetHashCode () = Terminator.futureFeature ()

// vim: set tw=80 sts=2 sw=2:
