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

namespace B2R2.FrontEnd.BPF

open B2R2
open B2R2.FrontEnd.BinLifter

/// Represents an instruction for eBPF.
type Instruction internal(addr, numBytes, op, opr, lifter: ILiftable) =

  /// The length of this instruction as an address, which is what the addresses
  /// counted from the instruction after this one are computed with.
  let numBytes64 = uint64 (numBytes: uint32)

  /// Address of this instruction.
  member _.Address with get(): Addr = addr

  /// Length of this instruction in bytes, which is eight for every instruction
  /// but the one carrying a whole quadword, that one being sixteen.
  member _.Length with get(): uint32 = numBytes

  /// Opcode.
  member _.Opcode with get(): Opcode = op

  /// Operands.
  member _.Operands with get(): Operands = opr

  /// <summary>
  /// Returns the address a jump reaches. The machine counts the distance from
  /// the instruction after the jump, and the sum wraps within the sixty-four
  /// bits of an address, so a jump backwards from near zero comes around at the
  /// top of the space rather than running past it.
  /// </summary>
  member _.TargetOf(disp: Rel): Addr = addr + numBytes64 + uint64 disp

  interface IInstruction with

    member _.Address with get() = addr

    member _.Length with get() = numBytes

    member this.IsBranch =
      let ins = this :> IInstruction
      match op with
      | Opcode.JA | Opcode.GOTOL -> true
      | _ -> ins.IsCondBranch || ins.IsCall || ins.IsRET

    member _.IsModeChanging = false

    (* Every jump this machine has names where it goes by a distance written in
       the instruction itself, and a call to a helper names no address at all,
       so what tells the two apart is whether an operand stands for a place. *)
    member _.IsDirectBranch =
      match opr with
      | OneOperand(OprAddr _)
      | ThreeOperands(_, _, OprAddr _) -> true
      | _ -> false

    (* Nothing here goes where a register says: the verifier has to see every
       place a program may reach, and a register does not say. *)
    member _.IsIndirectBranch = false

    member _.IsCondBranch =
      match op with
      | Opcode.JEQ | Opcode.JGT | Opcode.JGE | Opcode.JSET | Opcode.JNE
      | Opcode.JSGT | Opcode.JSGE | Opcode.JLT | Opcode.JLE | Opcode.JSLT
      | Opcode.JSLE
      | Opcode.JEQ32 | Opcode.JGT32 | Opcode.JGE32 | Opcode.JSET32
      | Opcode.JNE32 | Opcode.JSGT32 | Opcode.JSGE32 | Opcode.JLT32
      | Opcode.JLE32 | Opcode.JSLT32 | Opcode.JSLE32 -> true
      | _ -> false

    (* Every conditional jump this machine has goes where the condition its name
       states holds, there being no form that goes where one does not. *)
    member this.IsCJmpOnTrue = (this :> IInstruction).IsCondBranch

    member _.IsCall =
      match op with
      | Opcode.CALL | Opcode.CALL_LOCAL | Opcode.CALL_KFUNC -> true
      | _ -> false

    member _.IsRET = op = Opcode.EXIT

    (* This machine keeps no stack of its own: what a stack is, is the frame a
       register points at and the ordinary loads and stores reaching through it,
       so no instruction is a push or a pop. *)
    member _.IsPush = false

    member _.IsPop = false

    (* A program leaves the machine only by returning, so nothing here traps. *)
    member _.IsInterrupt = false

    member _.IsExit = false

    (* This machine spends no encoding on doing nothing, and nothing an
       assembler emits stands in for one. *)
    member _.IsNop = false

    member _.IsInlinedAssembly = false

    member this.IsTerminator _ =
      let ins = this :> IInstruction
      ins.IsBranch || ins.IsInterrupt || ins.IsExit

    member this.DirectBranchTarget(target: byref<Addr>) =
      match opr with
      | OneOperand(OprAddr disp)
      | ThreeOperands(_, _, OprAddr disp) ->
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
      | TwoOperands(_, OprImm imm)
      | ThreeOperands(_, OprImm imm, _) ->
        v <- int64 imm
        true
      | TwoOperands(OprMem(_, disp), _)
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
      elif (op = Opcode.JA || op = Opcode.GOTOL)
           && ins.DirectBranchTarget &target then
        [| target |]
      elif ins.IsRET then
        [||]
      else
        [| next |]

    member _.InterruptNum(_num: byref<int64>) = false

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
