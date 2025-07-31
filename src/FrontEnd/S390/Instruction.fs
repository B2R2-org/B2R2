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

/// Represents an instruction for S390.
type Instruction
  internal (addr, numBytes, fmt, op, opr, wordSize, lifter: ILiftable) =

  let extractMask = function
    | OpMask op -> Some op
    | _ -> None

  let getMaskVal (opr: Operands) =
    match opr with
    | NoOperand -> None
    | OneOperand op1 -> extractMask op1
    | TwoOperands (op1, op2) -> [| op1; op2 |] |> Array.tryPick extractMask
    | ThreeOperands (op1, op2, op3) ->
      [| op1; op2; op3 |] |> Array.tryPick extractMask
    |  FourOperands (op1, op2, op3, op4) ->
      [| op1; op2; op3; op4 |] |> Array.tryPick extractMask
    | FiveOperands (op1, op2, op3, op4, op5) ->
      [| op1; op2; op3; op4; op5 |] |> Array.tryPick extractMask
    | SixOperands (op1, op2, op3, op4, op5, op6) ->
      [| op1; op2; op3; op4; op5; op6 |] |> Array.tryPick extractMask

  /// Address of this instruction.
  member _.Address with get (): Addr = addr

  /// Length of this instruction in bytes.
  member _.Length with get (): uint32 = numBytes

  /// Instruction format.
  member _.Fmt with get (): Fmt = fmt

  /// Opcode.
  member _.Opcode with get (): Opcode = op

  /// Operands.
  member _.Operands with get (): Operands = opr

  interface IInstruction with

    member _.Address with get() = addr

    member _.Length with get() = numBytes

    member this.IsBranch =
      match op with
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
        when not (this :> IInstruction).IsNop -> true
      | _ -> false

    member _.IsModeChanging = false

    member _.IsDirectBranch = Terminator.futureFeature ()

    member _.IsIndirectBranch = Terminator.futureFeature ()

    member this.IsCondBranch =
      match op with
      | Opcode.BC | Opcode.BCR | Opcode.BIC -> true
      | Opcode.CRB | Opcode.CGRB | Opcode.CRJ | Opcode.CGRJ
      | Opcode.CIB | Opcode.CGIB | Opcode.CIJ | Opcode.CGIJ
      | Opcode.CLRB | Opcode.CLGRB | Opcode.CLRJ | Opcode.CLGRJ
        when not (this :> IInstruction).IsNop -> true
      | _ -> false

    member _.IsCJmpOnTrue = Terminator.futureFeature ()

    member _.IsCall =
      match op with
      | Opcode.BAL | Opcode.BALR | Opcode.BAS | Opcode.BASR
      | Opcode.BASSM | Opcode.BSM -> true
      | Opcode.BC | Opcode.BCR when getMaskVal opr = Some (15us) -> true
      | _ -> false

    member _.IsRET =
      match op with
      | Opcode.BCR | Opcode.BASR | Opcode.BCTR ->
        match opr with
        | TwoOperands (_, OpReg Register.R14) -> true
        | _ -> false
      | _ -> false

    member _.IsPush = Terminator.futureFeature ()

    member _.IsPop = Terminator.futureFeature ()

    member _.IsInterrupt = Terminator.futureFeature ()

    member _.IsExit = Terminator.futureFeature ()

    member this.IsNop =
      match op with
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

    member _.IsInlinedAssembly = false

    member this.IsTerminator _ =
      let ins = this :> IInstruction
      ins.IsBranch || ins.IsInterrupt || ins.IsExit

    member _.DirectBranchTarget (_addr: byref<Addr>) =
      Terminator.futureFeature ()

    member _.IndirectTrampolineAddr (_addr: byref<Addr>) =
      Terminator.futureFeature ()

    member _.MemoryDereferences (_: byref<Addr[]>) =
      Terminator.futureFeature ()

    member _.Immediate (_v: byref<int64>) = Terminator.futureFeature ()

    member _.GetNextInstrAddrs () = Terminator.futureFeature ()

    member _.InterruptNum (_num: byref<int64>) = Terminator.futureFeature ()

    member this.Translate builder =
      (lifter.Lift this builder).Stream.ToStmts ()

    member this.TranslateToList builder =
      (lifter.Lift this builder).Stream

    member this.Disasm builder =
      (lifter.Disasm this builder).ToString ()

    member this.Disasm () =
      let builder = StringDisasmBuilder (false, null, wordSize)
      (lifter.Disasm this builder).ToString ()

    member this.Decompose builder =
      (lifter.Disasm this builder).ToAsmWords ()

and internal ILiftable =
  abstract Lift: Instruction -> ILowUIRBuilder -> ILowUIRBuilder
  abstract Disasm: Instruction -> IDisasmBuilder -> IDisasmBuilder
