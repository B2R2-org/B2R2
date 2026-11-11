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

namespace B2R2.FrontEnd.ARM32

open B2R2
open B2R2.FrontEnd.BinLifter

/// Represents an ARM32 instruction.
type Instruction
  internal(addr,
           nb,
           cond,
           op,
           opr,
           its,
           wb,
           caret,
           q,
           s,
           isThumb,
           inIT,
           cf,
           oSz,
           isAdd,
           lifter: ILiftable) =

  /// Tells whether this names where it branches to as a label, as B does, and
  /// as CBZ and CBNZ do besides the register that they test.
  let hasConcJmpTarget () =
    match op, opr with
    | _, OneOperand(OprMemory(LiteralMode _))
    | Op.CBZ, TwoOperands(_, OprMemory(LiteralMode _))
    | Op.CBNZ, TwoOperands(_, OprMemory(LiteralMode _)) -> true
    | _ -> false

  /// Tells whether this computes the PC as its destination, which ALUWritePC
  /// turns into a branch.
  let isALUWriteToPC () =
    match op with
    | Op.ADC | Op.ADD | Op.ADDW | Op.ADR | Op.AND | Op.ASR | Op.BIC | Op.EOR
    | Op.LSL | Op.LSR | Op.MOV | Op.MVN | Op.ORN | Op.ORR | Op.ROR | Op.RRX
    | Op.RSB | Op.RSC | Op.SBC | Op.SUB | Op.SUBW ->
      match opr with
      | TwoOperands(OprReg R.PC, _)
      | ThreeOperands(OprReg R.PC, _, _)
      | FourOperands(OprReg R.PC, _, _, _) -> true
      | _ -> false
    | _ ->
      false

  /// Returns the address at the given offset from the PC aligned to a word,
  /// which is where a load relative to the PC reads.
  let fromAlignedPC (offset: int64) =
    let pc = (int64 addr + (if isThumb then 4L else 8L)) / 4L * 4L
    (pc + offset) &&& 0xFFFFFFFFL |> uint64

  /// Address of this instruction.
  member _.Address with get(): Addr = addr

  /// Length of this instruction in bytes.
  member _.Length with get(): uint32 = nb

  /// Condition.
  member _.Condition with get(): Condition = cond

  /// Opcode.
  member _.Opcode with get(): Opcode = op

  /// Operands.
  member _.Operands with get(): Operands = opr

  /// IT state for this instruction (used only for IT instructions).
  member _.ITState with get(): byte = its

  /// Write back.
  member _.WriteBack with get(): bool = wb

  /// Whether this block transfer names the registers of another mode, or
  /// returns from an exception, which the manual writes with a trailing caret.
  member _.Caret with get(): bool = caret

  /// Qualifier.
  member _.Qualifier with get(): Qualifier = q

  /// SIMD data type.
  member _.SIMDTyp with get(): SIMDDataTypes option = s

  /// Is a Thumb mode instruction?
  member _.IsThumb with get(): bool = isThumb

  /// Whether this instruction sits in an IT block: it takes its condition
  /// from ITSTATE rather than from its encoding, and advances ITSTATE as it
  /// leaves. A conditional branch that carries its own condition never does.
  member _.IsInITBlock with get(): bool = inIT

  /// Carry Flag from decoding instruction.
  member _.Cflag with get(): bool option = cf

  /// Operation size.
  member _.OprSize with get(): RegType = oSz

  /// Add or subtract offsets.
  member _.IsAdd with get(): bool = isAdd

  member private this.AddBranchTargetIfExist addrs =
    match (this :> IInstruction).DirectBranchTarget() with
    | false, _ -> addrs
    | true, target -> [| target |] |> Array.append addrs

  interface IInstruction with

    member _.Address with get() = addr

    member _.Length with get() = nb

    member this.IsBranch =
      match this.Opcode with
      | Op.B | Op.BL | Op.BLX | Op.BX | Op.BXJ
      | Op.CBNZ | Op.CBZ
      | Op.TBB | Op.TBH ->
        true
      | Op.LDR ->
        match this.Operands with
        | TwoOperands(OprReg R.PC, _) -> true
        | _ -> false
      | Op.POP ->
        match this.Operands with
        | OneOperand(OprRegList regs) -> List.contains R.PC regs
        | _ -> false
      | Op.LDM | Op.LDMDA | Op.LDMDB | Op.LDMIA | Op.LDMIB ->
        match this.Operands with
        | TwoOperands(_, OprRegList regs) -> List.contains R.PC regs
        | _ -> false
      | _ ->
        isALUWriteToPC ()

    member this.IsModeChanging =
      match this.Opcode with
      | Op.BLX -> true
      | _ -> false

    member this.IsDirectBranch =
      (this :> IInstruction).IsBranch && hasConcJmpTarget ()

    member this.IsIndirectBranch =
      (this :> IInstruction).IsBranch && (not <| hasConcJmpTarget ())

    member this.IsCondBranch =
      match this.Opcode, this.Condition, this.Operands with
      | Op.B, Condition.AL, _ -> false
      | Op.B, Condition.NV, _ -> false
      | Op.B, Condition.UN, _ -> false
      | Op.B, _, _ -> true
      | Op.BX, Condition.AL, _ -> false
      | Op.BX, Condition.NV, _ -> false
      | Op.BX, Condition.UN, _ -> false
      | Op.BX, _, _ -> true
      | Op.CBZ, _, _
      | Op.CBNZ, _, _ -> true
      | Op.LDR, Condition.AL, TwoOperands(OprReg R.PC, _)
      | Op.LDR, Condition.NV, TwoOperands(OprReg R.PC, _)
      | Op.LDR, Condition.UN, TwoOperands(OprReg R.PC, _) -> false
      | Op.LDR, _, TwoOperands(OprReg R.PC, _) -> true
      | Op.POP, Condition.AL, OneOperand(OprRegList regs)
      | Op.POP, Condition.NV, OneOperand(OprRegList regs)
      | Op.POP, Condition.UN, OneOperand(OprRegList regs)
        when List.contains R.PC regs -> false
      | Op.POP, _, OneOperand(OprRegList regs)
        when List.contains R.PC regs -> true
      | Op.ADD, Condition.AL, FourOperands(OprReg R.PC, _, _, _)
      | Op.ADD, Condition.NV, FourOperands(OprReg R.PC, _, _, _)
      | Op.ADD, Condition.UN, FourOperands(OprReg R.PC, _, _, _) -> false
      | Op.ADD, _, FourOperands(OprReg R.PC, OprReg R.PC, _, _) -> true
      | _ -> false

    member this.IsCJmpOnTrue =
      match this.Opcode, this.Condition with
      | Op.B, Condition.CS | Op.B, Condition.CC
      | Op.B, Condition.MI | Op.B, Condition.PL
      | Op.B, Condition.VS | Op.B, Condition.VC
      | Op.B, Condition.HI | Op.B, Condition.LS
      | Op.B, Condition.GE | Op.B, Condition.LT
      | Op.B, Condition.GT | Op.B, Condition.LE
      | Op.B, Condition.EQ -> true
      | _ -> false

    member this.IsCall =
      match this.Opcode with
      | Opcode.BL | Opcode.BLX -> true
      | _ -> false

    member this.IsRET =
      match this.Opcode, this.Operands with
      | Op.POP, OneOperand(OprRegList regs) when List.contains R.PC regs -> true
      | Op.BX, OneOperand(OprReg R.LR) -> true
      | _ -> false

    member _.IsPush = Terminator.futureFeature ()

    member _.IsPop = Terminator.futureFeature ()

    member this.IsInterrupt =
      match this.Opcode with
      | Op.SVC | Op.HVC | Op.SMC -> true
      | _ -> false

    member this.IsExit =
      match this.Opcode with
      | Opcode.HLT
      | Opcode.UDF
      | Opcode.ERET -> true
      | _ -> false

    member this.IsNop = this.Opcode = Op.NOP

    member _.IsInlinedAssembly = false

    member this.DirectBranchTarget(addr: byref<Addr>) =
      if (this :> IInstruction).IsBranch then
        match op, opr with
        | _, OneOperand(OprMemory(LiteralMode target))
        | Op.CBZ, TwoOperands(_, OprMemory(LiteralMode target))
        | Op.CBNZ, TwoOperands(_, OprMemory(LiteralMode target)) ->
          (* The PC value of an instruction is its address plus 4 for a Thumb
             instruction, or plus 8 for an ARM instruction. *)
          let offset = if not this.IsThumb then 8L else 4L
          (* Align(PC,4) only when the TARGET instruction set is ARM,
             which from Thumb means BLX immediate:

               if targetInstrSet == InstrSet_ARM then
                    targetAddress = Align(PC,4) + imm32;
               else targetAddress = PC + imm32;

             and a plain B is `BranchWritePC(PC + imm32)` with no
             alignment at all. Aligning unconditionally put every Thumb
             branch sitting at an address congruent to 2 mod 4 -- about
             half of them -- two bytes low. In ARM state the alignment is
             a no-op, since A32 instructions are word-aligned already. *)
          let basePC = int64 this.Address + offset
          let pc =
            if this.IsThumb && op <> Op.BLX then basePC
            else basePC / 4L * 4L
          addr <- ((pc + target) &&& 0xFFFFFFFFL) |> uint64
          true
        | _ ->
          false
      else
        false

    member _.IndirectTrampolineAddr(_: byref<Addr>) = false

    member this.IsTerminator _ =
      let ins = this :> IInstruction
      ins.IsBranch || ins.IsInterrupt || ins.IsExit

    member _.MemoryDereferences(addrs: byref<Addr[]>) =
      match opr with
      | TwoOperands(_, OprMemory(LiteralMode target))
        when op <> Op.CBZ && op <> Op.CBNZ ->
        addrs <- [| fromAlignedPC target |]
        true
      | TwoOperands(_, OprMemory(OffsetMode(ImmOffset(R.PC, sign, imm)))) ->
        let imm = Option.defaultValue 0L imm
        addrs <- [| fromAlignedPC (if sign = Some Minus then -imm else imm) |]
        true
      | _ ->
        false

    member _.Immediate(v: byref<int64>) =
      match opr with
      | OneOperand(OprImm c)
      | TwoOperands(OprImm c, _)
      | TwoOperands(_, OprImm c)
      | ThreeOperands(OprImm c, _, _)
      | ThreeOperands(_, OprImm c, _)
      | ThreeOperands(_, _, OprImm c)
      | FourOperands(OprImm c, _, _, _)
      | FourOperands(_, OprImm c, _, _)
      | FourOperands(_, _, OprImm c, _)
      | FourOperands(_, _, _, OprImm c)
      | FiveOperands(OprImm c, _, _, _, _)
      | FiveOperands(_, OprImm c, _, _, _)
      | FiveOperands(_, _, OprImm c, _, _)
      | FiveOperands(_, _, _, OprImm c, _)
      | FiveOperands(_, _, _, _, OprImm c)
      | SixOperands(OprImm c, _, _, _, _, _)
      | SixOperands(_, OprImm c, _, _, _, _)
      | SixOperands(_, _, OprImm c, _, _, _)
      | SixOperands(_, _, _, OprImm c, _, _)
      | SixOperands(_, _, _, _, OprImm c, _)
      | SixOperands(_, _, _, _, _, OprImm c) -> v <- c; true
      | _ -> false

    member this.GetNextInstrAddrs() =
      let acc = [| this.Address + uint64 this.Length |]
      let ins = this :> IInstruction
      if ins.IsCall then
        acc |> this.AddBranchTargetIfExist
      elif ins.IsBranch then
        if ins.IsCondBranch then acc |> this.AddBranchTargetIfExist
        else this.AddBranchTargetIfExist [||]
      elif this.Opcode = Opcode.HLT || this.Opcode = Opcode.UDF then
        [||]
      else
        acc

    member _.InterruptNum(_num: byref<int64>) = Terminator.futureFeature ()

    member this.Translate builder = lifter.Lift(this, builder).Stream.ToStmts()

    member this.TranslateToList builder = lifter.Lift(this, builder).Stream

    member this.Disasm builder = lifter.Disasm(this, builder).ToString()

    member this.Disasm() =
      let builder = StringDisasmBuilder(false, null, WordSize.Bit32)
      lifter.Disasm(this, builder).ToString()

    member this.Decompose builder = lifter.Disasm(this, builder).ToAsmWords()

and internal ILiftable =
  abstract Lift: Instruction * ILowUIRBuilder -> ILowUIRBuilder
  abstract Disasm: Instruction * IDisasmBuilder -> IDisasmBuilder
