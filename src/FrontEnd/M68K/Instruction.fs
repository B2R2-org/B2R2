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

namespace B2R2.FrontEnd.M68K

open B2R2
open B2R2.FrontEnd.M68K
open B2R2.FrontEnd.BinLifter

/// Represents an instruction for m68k.
type Instruction
  internal(addr, numBytes, op, sz, opr, lifter: ILiftable) =

  /// Address of this instruction.
  member _.Address with get(): Addr = addr

  /// Length of this instruction in bytes.
  member _.Length with get(): uint32 = numBytes

  /// Opcode.
  member _.Opcode with get(): Opcode = op

  /// Size of the operation, which the mnemonic carries as a suffix.
  member _.Size with get(): OperandSize = sz

  /// Operands.
  member _.Operands with get(): Operands = opr

  /// <summary>
  /// Returns the address that the given program counter relative displacement
  /// reaches. It is counted from where the extension word holding it sits
  /// rather than from the start of the instruction, and the sum wraps within
  /// the 32 bits of an m68k address, so a branch backwards from near zero comes
  /// around at the top of the space instead of running past it.
  /// </summary>
  member _.TargetOf(disp: int32): Addr = uint64 (uint32 addr + 2u + uint32 disp)

  interface IInstruction with

    member _.Address with get() = addr

    member _.Length with get() = numBytes

    member this.IsBranch =
      let ins = this :> IInstruction
      match op with
      | Op.BRA | Op.JMP | Op.JSR -> true
      | _ -> ins.IsCondBranch || ins.IsCall || ins.IsRET

    member _.IsModeChanging = false

    member _.IsDirectBranch =
      match opr with
      | OneOperand(OpRelAddr _) | TwoOperands(_, OpRelAddr _) -> true
      | OneOperand(OpAddr _) -> op = Op.JMP || op = Op.JSR
      | _ -> false

    member _.IsIndirectBranch =
      match op, opr with
      | (Op.JMP | Op.JSR), OneOperand(OpAddr _) -> false
      | (Op.JMP | Op.JSR), _ -> true
      | _ -> false

    member _.IsCondBranch =
      (* A Bcc of the always condition is a BRA and one of the never condition a
         BSR, so every Bcc that is still a Bcc is conditional. A DBcc is too:
         whether it branches turns on the counter as well as the condition. *)
      match op with
      | Op.BHI | Op.BLS | Op.BCC | Op.BCS | Op.BNE | Op.BEQ | Op.BVC | Op.BVS
      | Op.BPL | Op.BMI | Op.BGE | Op.BLT | Op.BGT | Op.BLE
      | Op.DBT | Op.DBF | Op.DBHI | Op.DBLS | Op.DBCC | Op.DBCS | Op.DBNE
      | Op.DBEQ | Op.DBVC | Op.DBVS | Op.DBPL | Op.DBMI | Op.DBGE | Op.DBLT
      | Op.DBGT | Op.DBLE -> true
      | _ -> false

    member _.IsCJmpOnTrue = Terminator.futureFeature ()

    member _.IsCall =
      match op with
      | Op.BSR | Op.JSR | Op.CALLM -> true
      | _ -> false

    member _.IsRET =
      match op with
      | Op.RTS | Op.RTR | Op.RTD | Op.RTM -> true
      | _ -> false

    member _.IsPush = Terminator.futureFeature ()

    member _.IsPop = Terminator.futureFeature ()

    member _.IsInterrupt =
      (* Each of these enters an exception vector: TRAP and BKPT
         unconditionally, TRAPV and the TRAPcc family on a condition, CHK and
         CHK2 on a bound, and ILLEGAL by being the encoding that is defined to
         be undefined. *)
      match op with
      | Op.TRAP | Op.TRAPV | Op.ILLEGAL | Op.BKPT | Op.CHK | Op.CHK2
      | Op.TRAPT | Op.TRAPF | Op.TRAPHI | Op.TRAPLS | Op.TRAPCC | Op.TRAPCS
      | Op.TRAPNE | Op.TRAPEQ | Op.TRAPVC | Op.TRAPVS | Op.TRAPPL | Op.TRAPMI
      | Op.TRAPGE | Op.TRAPLT | Op.TRAPGT | Op.TRAPLE -> true
      | _ -> false

    member _.IsExit =
      (* RTE leaves the exception handler the vector entered, and neither STOP
         nor RESET carries on with the next instruction in any ordinary way. *)
      match op with
      | Op.RTE | Op.STOP | Op.RESET -> true
      | _ -> false

    member _.IsNop = op = Op.NOP

    member _.IsInlinedAssembly = false

    member this.IsTerminator _ =
      let ins = this :> IInstruction
      ins.IsBranch || ins.IsInterrupt || ins.IsExit

    member this.DirectBranchTarget(target: byref<Addr>) =
      match opr with
      | OneOperand(OpRelAddr disp)
      | TwoOperands(_, OpRelAddr disp) ->
        target <- this.TargetOf disp
        true
      | OneOperand(OpAddr dst) when op = Op.JMP || op = Op.JSR ->
        target <- dst
        true
      | _ ->
        false

    member _.IndirectTrampolineAddr(_addr: byref<Addr>) =
      Terminator.futureFeature ()

    member _.MemoryDereferences(_: byref<Addr[]>) = Terminator.futureFeature ()

    member _.Immediate(_v: byref<int64>) = Terminator.futureFeature ()

    member _.GetNextInstrAddrs() = Terminator.futureFeature ()

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
