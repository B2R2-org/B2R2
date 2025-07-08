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

namespace B2R2.FrontEnd.ARM64

open B2R2
open B2R2.FrontEnd.BinLifter

/// Instruction for ARM64.
type Instruction
  internal (addr, nb, cond, op, opr, oprSize, lifter: ILiftable) =

  let hasConcJmpTarget () =
    match opr with
    (* All other instructions *)
    | OneOperand (OprMemory (LiteralMode _)) -> true
    (* CBNZ and CBZ *)
    | TwoOperands (_, OprMemory (LiteralMode _)) -> true
    (* TBNZ and TBZ *)
    | ThreeOperands (_, _, OprMemory (LiteralMode _)) -> true
    | _ -> false

  /// Address of this instruction.
  member _.Address with get (): Addr = addr

  /// Length of this instruction in bytes.
  member _.Length with get (): uint32 = nb

  /// Condition.
  member _.Condition with get (): Condition option = cond

  /// Opcode.
  member _.Opcode with get (): Opcode = op

  /// Operands.
  member _.Operands with get (): Operands = opr

  /// Operation size.
  member _.OprSize with get (): RegType = oprSize

  interface IInstruction with

    member _.Address with get () = addr

    member _.Length with get () = nb

    member this.IsBranch () =
      match this.Opcode with
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

    member _.IsModeChanging () = false

    member this.IsDirectBranch () =
      (this :> IInstruction).IsBranch () && hasConcJmpTarget ()

    member this.IsIndirectBranch () =
      (this :> IInstruction).IsBranch () && (not <| hasConcJmpTarget ())

    member _.IsCondBranch () =
      match op with
      | Opcode.BEQ | Opcode.BCS | Opcode.BMI | Opcode.BVS | Opcode.BHI
      | Opcode.BGE | Opcode.BGT | Opcode.BNE | Opcode.BCC | Opcode.BPL
      | Opcode.BVC | Opcode.BLS | Opcode.BLT | Opcode.BLE
      | Opcode.CBNZ | Opcode.CBZ | Opcode.TBNZ | Opcode.TBZ -> true
      | _ -> false

    member _.IsCJmpOnTrue () =
      match op with
      | Opcode.BEQ | Opcode.BCS | Opcode.BMI | Opcode.BVS | Opcode.BHI
      | Opcode.BGE | Opcode.BGT | Opcode.BCC | Opcode.BPL | Opcode.BVC
      | Opcode.BLS | Opcode.BLT | Opcode.BLE | Opcode.CBZ | Opcode.TBZ -> true
      | _ -> false

    member _.IsCall () =
      match op with
      | Opcode.BL | Opcode.BLR -> true
      | _ -> false

    member _.IsRET () =
      op = Opcode.RET

    member _.IsPush () =
      Terminator.futureFeature ()

    member _.IsPop () =
      Terminator.futureFeature ()

    member _.IsInterrupt () =
      match op with
      | Opcode.SVC | Opcode.HVC | Opcode.SMC -> true
      | _ -> false

    member _.IsExit () =
      match op with
      | Opcode.HLT
      | Opcode.ERET -> true
      | _ -> false

    member this.IsTerminator () =
      let ins = this :> IInstruction
      ins.IsBranch () || ins.IsInterrupt () || ins.IsExit ()

    member _.IsNop () =
      op = Opcode.NOP

    member _.IsInlinedAssembly () = false

    member this.DirectBranchTarget (addr: byref<Addr>) =
      if (this :> IInstruction).IsBranch () then
        match opr with
        | OneOperand (OprMemory (LiteralMode (ImmOffset (Lbl offset)))) ->
          addr <- (this.Address + uint64 offset)
          true
        | TwoOperands (_, OprMemory (LiteralMode (ImmOffset (Lbl offset)))) ->
          addr <- (this.Address + uint64 offset)
          true
        | ThreeOperands (_, _,
                         OprMemory (LiteralMode (ImmOffset (Lbl offs)))) ->
          addr <- (this.Address + uint64 offs)
          true
        | _ -> false
      else false

    member this.IndirectTrampolineAddr (_addr: byref<Addr>) =
      if (this :> IInstruction).IsIndirectBranch () then
        Terminator.futureFeature ()
      else false

    member _.MemoryDereferences (_: byref<Addr[]>) =
      Terminator.futureFeature ()

    member _.Immediate (v: byref<int64>) =
      match opr with
      | OneOperand (OprImm c)
      | TwoOperands (OprImm c, _)
      | TwoOperands (_, OprImm c)
      | ThreeOperands (OprImm c, _, _)
      | ThreeOperands (_, OprImm c, _)
      | ThreeOperands (_, _, OprImm c)
      | FourOperands (OprImm c, _, _, _)
      | FourOperands (_, OprImm c, _, _)
      | FourOperands (_, _, OprImm c, _)
      | FourOperands (_, _, _, OprImm c)
      | FiveOperands (OprImm c, _, _, _, _)
      | FiveOperands (_, OprImm c, _, _, _)
      | FiveOperands (_, _, OprImm c, _, _)
      | FiveOperands (_, _, _, OprImm c, _)
      | FiveOperands (_, _, _, _, OprImm c) -> v <- c; true
      | _ -> false

    member _.GetNextInstrAddrs () = Terminator.futureFeature ()

    member _.InterruptNum (_num: byref<int64>) = Terminator.futureFeature ()

    member this.Translate builder =
      (lifter.Lift this builder).Stream.ToStmts ()

    member this.TranslateToList builder =
      (lifter.Lift this builder).Stream

    member this.Disasm builder =
      (lifter.Disasm this builder).ToString ()

    member this.Disasm () =
      let builder = StringDisasmBuilder (false, null, WordSize.Bit64)
      (lifter.Disasm this builder).ToString ()

    member this.Decompose builder =
      (lifter.Disasm this builder).ToAsmWords ()

and internal ILiftable =
  abstract Lift: Instruction -> ILowUIRBuilder -> ILowUIRBuilder
  abstract Disasm: Instruction -> IDisasmBuilder -> IDisasmBuilder
