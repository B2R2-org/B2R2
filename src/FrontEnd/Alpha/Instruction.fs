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

namespace B2R2.FrontEnd.Alpha

open B2R2
open B2R2.FrontEnd.BinLifter

/// Represents an instruction for Alpha.
type Instruction internal(addr, numBytes, op, qual, opr, lifter: ILiftable) =

  /// The length of this instruction as an address, which is what the addresses
  /// counted from the instruction after this one are computed with.
  let numBytes64 = uint64 (numBytes: uint32)

  /// Address of this instruction.
  member _.Address with get(): Addr = addr

  /// Length of this instruction in bytes.
  member _.Length with get(): uint32 = numBytes

  /// Opcode.
  member _.Opcode with get(): Opcode = op

  /// The qualifier this instruction carries, which says how it rounds and what
  /// it traps on. Only a floating-point instruction carries one; everything
  /// else carries none.
  member _.Qualifier with get(): Qualifier = qual

  /// Operands.
  member _.Operands with get(): Operands = opr

  /// <summary>
  /// Returns the address a branch displacement reaches. The machine counts it
  /// from the instruction after the branch, and the sum wraps within the
  /// sixty-four bits of an address, so a branch backwards from near zero comes
  /// around at the top of the space rather than running past it.
  /// </summary>
  member _.TargetOf(disp: Disp): Addr = addr + numBytes64 + uint64 (int64 disp)

  interface IInstruction with

    member _.Address with get() = addr

    member _.Length with get() = numBytes

    member this.IsBranch =
      let ins = this :> IInstruction
      match op with
      | Op.BR | Op.JMP -> true
      | _ -> ins.IsCondBranch || ins.IsCall || ins.IsRET

    member _.IsModeChanging = false

    (* A branch names where it goes by a displacement, which is written in the
       word itself; a jump names it by a register, which is not. *)
    member _.IsDirectBranch =
      match opr with
      | TwoOperands(_, OprAddr _) -> true
      | _ -> false

    member _.IsIndirectBranch =
      match op with
      | Op.JMP | Op.JSR | Op.RET | Op.JSR_COROUTINE -> true
      | _ -> false

    member _.IsCondBranch =
      match op with
      | Op.BEQ | Op.BNE | Op.BLT | Op.BLE | Op.BGT | Op.BGE
      | Op.BLBC | Op.BLBS
      | Op.FBEQ | Op.FBNE | Op.FBLT | Op.FBLE | Op.FBGT | Op.FBGE -> true
      | _ -> false

    (* Every conditional branch Alpha has goes where the condition its name
       states holds, there being no form that goes where one does not. *)
    member this.IsCJmpOnTrue = (this :> IInstruction).IsCondBranch

    member _.IsCall =
      match op with
      | Op.BSR | Op.JSR | Op.JSR_COROUTINE -> true
      | _ -> false

    member _.IsRET = op = Op.RET

    (* Alpha keeps no stack of its own: what a stack is, is a register the
       calling convention names and the ordinary loads and stores that reach
       through it, so no instruction is a push or a pop. *)
    member _.IsPush = false

    member _.IsPop = false

    member _.IsInterrupt =
      (* Every trap an Alpha program takes deliberately is a call to PALcode,
         of which the two reading and writing the process unique value are the
         exception: those compute rather than trap. *)
      match op, opr with
      | Op.CALL_PAL, OneOperand(OprImm(0x9EUL | 0x9FUL)) -> false
      | Op.CALL_PAL, _ -> true
      | _ -> false

    member _.IsExit =
      match op, opr with
      | Op.CALL_PAL, OneOperand(OprImm 0x00UL) -> true
      | _ -> false

    (* Alpha spends no opcode on a no-op: what a program writes instead is an
       instruction whose result goes to the register that discards it, of which
       the three below are the ones an assembler emits. *)
    member _.IsNop =
      match op, opr with
      | Op.BIS, ThreeOperands(OprReg Register.R31,
                              OprReg Register.R31,
                              OprReg Register.R31) -> true
      | Op.LDQ_U, TwoOperands(OprReg Register.R31, _) -> true
      | Op.CPYS, ThreeOperands(OprReg Register.F31,
                               OprReg Register.F31,
                               OprReg Register.F31) -> true
      | _ -> false

    member _.IsInlinedAssembly = false

    member this.IsTerminator _ =
      let ins = this :> IInstruction
      ins.IsBranch || ins.IsInterrupt || ins.IsExit

    member this.DirectBranchTarget(target: byref<Addr>) =
      match opr with
      | TwoOperands(_, OprAddr disp) ->
        target <- this.TargetOf disp
        true
      | _ ->
        false

    member _.IndirectTrampolineAddr(_addr: byref<Addr>) =
      Terminator.futureFeature ()

    member _.MemoryDereferences(_: byref<Addr[]>) = Terminator.futureFeature ()

    member _.Immediate(v: byref<int64>) =
      match opr with
      | OneOperand(OprImm imm)
      | TwoOperands(OprImm imm, _)
      | ThreeOperands(_, OprImm imm, _) ->
        v <- int64 imm
        true
      | TwoOperands(_, OprMem(_, disp)) ->
        v <- int64 disp
        true
      | _ ->
        false

    member this.GetNextInstrAddrs() =
      let ins = this :> IInstruction
      let next = addr + numBytes64
      let mutable target = 0UL
      if ins.IsCondBranch && ins.DirectBranchTarget &target then
        [| next; target |]
      elif op = Op.BR && ins.DirectBranchTarget &target then
        [| target |]
      elif ins.IsIndirectBranch || ins.IsExit then
        [||]
      else
        [| next |]

    (* The routine a trap to PALcode names is the number the word carries, and
       the vector it enters is that number as well. *)
    member _.InterruptNum(num: byref<int64>) =
      match op, opr with
      | Op.CALL_PAL, OneOperand(OprImm imm) ->
        num <- int64 imm
        true
      | _ ->
        false

    member this.Translate builder = lifter.Lift(this, builder).Stream.ToStmts()

    member this.TranslateToList builder = lifter.Lift(this, builder).Stream

    member this.Disasm builder = lifter.Disasm(this, builder).ToString()

    member this.Disasm() =
      let builder = StringDisasmBuilder(false, null, WordSize.Bit64)
      lifter.Disasm(this, builder).ToString()

    member this.Decompose builder = lifter.Disasm(this, builder).ToAsmWords()

and internal ILiftable =
  abstract Lift: Instruction * ILowUIRBuilder -> ILowUIRBuilder
  abstract Disasm: Instruction * IDisasmBuilder -> IDisasmBuilder

// vim: set tw=80 sts=2 sw=2:
