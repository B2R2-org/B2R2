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

  (* A Bcc of the always condition is a BRA and one of the never condition a
     BSR, so every Bcc that is still a Bcc is conditional. *)
  let isBcc () =
    match op with
    | Op.BHI | Op.BLS | Op.BCC | Op.BCS | Op.BNE | Op.BEQ | Op.BVC | Op.BVS
    | Op.BPL | Op.BMI | Op.BGE | Op.BLT | Op.BGT | Op.BLE -> true
    | _ -> false

  (* The floating-point unit names its always and never conditions as any
     other, and the lifter branches on them as on any other, so every FBcc is
     conditional. *)
  let isFBcc () =
    match op with
    | Op.FBF | Op.FBEQ | Op.FBOGT | Op.FBOGE | Op.FBOLT | Op.FBOLE | Op.FBOGL
    | Op.FBOR | Op.FBUN | Op.FBUEQ | Op.FBUGT | Op.FBUGE | Op.FBULT | Op.FBULE
    | Op.FBNE | Op.FBT | Op.FBSF | Op.FBSEQ | Op.FBGT | Op.FBGE | Op.FBLT
    | Op.FBLE | Op.FBGL | Op.FBGLE | Op.FBNGLE | Op.FBNGL | Op.FBNLE
    | Op.FBNLT | Op.FBNGE | Op.FBNGT | Op.FBSNE | Op.FBST -> true
    | _ -> false

  (* A DBcc or an FDBcc branches where its condition fails and the counter it
     decrements has not yet run past zero, so whether it branches turns on the
     counter as well as the condition. *)
  let isDBcc () =
    match op with
    | Op.DBT | Op.DBF | Op.DBHI | Op.DBLS | Op.DBCC | Op.DBCS | Op.DBNE
    | Op.DBEQ | Op.DBVC | Op.DBVS | Op.DBPL | Op.DBMI | Op.DBGE | Op.DBLT
    | Op.DBGT | Op.DBLE
    | Op.FDBF | Op.FDBEQ | Op.FDBOGT | Op.FDBOGE | Op.FDBOLT | Op.FDBOLE
    | Op.FDBOGL | Op.FDBOR | Op.FDBUN | Op.FDBUEQ | Op.FDBUGT | Op.FDBUGE
    | Op.FDBULT | Op.FDBULE | Op.FDBNE | Op.FDBT | Op.FDBSF | Op.FDBSEQ
    | Op.FDBGT | Op.FDBGE | Op.FDBLT | Op.FDBLE | Op.FDBGL | Op.FDBGLE
    | Op.FDBNGLE | Op.FDBNGL | Op.FDBNLE | Op.FDBNLT | Op.FDBNGE | Op.FDBNGT
    | Op.FDBSNE | Op.FDBST -> true
    | _ -> false

  let isCall () =
    match op with
    | Op.BSR | Op.JSR | Op.CALLM -> true
    | _ -> false

  let isRet () =
    match op with
    | Op.RTS | Op.RTR | Op.RTD | Op.RTM -> true
    | _ -> false

  (* Each of these enters an exception vector: TRAP and BKPT unconditionally,
     TRAPV and the TRAPcc family on a condition, CHK and CHK2 on a bound, and
     ILLEGAL by being the encoding that is defined to be undefined. *)
  let isInterrupt () =
    match op with
    | Op.TRAP | Op.TRAPV | Op.ILLEGAL | Op.BKPT | Op.CHK | Op.CHK2
    | Op.TRAPT | Op.TRAPF | Op.TRAPHI | Op.TRAPLS | Op.TRAPCC | Op.TRAPCS
    | Op.TRAPNE | Op.TRAPEQ | Op.TRAPVC | Op.TRAPVS | Op.TRAPPL | Op.TRAPMI
    | Op.TRAPGE | Op.TRAPLT | Op.TRAPGT | Op.TRAPLE -> true
    | _ -> false

  (* RTE leaves the exception handler the vector entered, and neither STOP nor
     RESET carries on with the next instruction in any ordinary way. ILLEGAL
     and BKPT come back, if at all, to themselves. Linux takes TRAP #0 as a
     system call and sends a signal for any other vector, which is why GCC puts
     TRAP #7 where __builtin_trap is, with the next function right after. *)
  let isExit () =
    match op, opr with
    | (Op.RTE | Op.STOP | Op.RESET | Op.ILLEGAL | Op.BKPT), _ -> true
    | Op.TRAP, OneOperand(OpImm vector) -> vector <> 0L
    | _ -> false

  let isBranch () =
    match op with
    | Op.BRA | Op.JMP -> true
    | _ -> isBcc () || isFBcc () || isDBcc () || isCall () || isRet ()

  (* A displacement from the program counter counts from where the extension
     word holding it sits rather than from the start of the instruction, and
     the sum wraps within the 32 bits of an m68k address, so a branch backwards
     from near zero comes around at the top of the space instead of running
     past it. *)
  let targetOf (disp: int32) = uint64 (uint32 addr + 2u + uint32 disp)

  (* A JMP or a JSR goes to the effective address it names rather than to what
     lies there, so one that names an absolute address or a displacement from
     the program counter goes where the instruction alone says. *)
  let tryJumpTarget () =
    match opr with
    | OneOperand(OpAddr dst) ->
      ValueSome dst
    | OneOperand(OpMem(Disp(disp, R.PC))) ->
      ValueSome(targetOf (int32 disp))
    | OneOperand(OpMem(Indexed { Base = Some R.PC
                                 Index = None
                                 BaseDisp = disp
                                 OuterDisp = None })) ->
      ValueSome(targetOf disp)
    | _ ->
      ValueNone

  let tryGetTarget () =
    match op, opr with
    | _, OneOperand(OpRelAddr disp)
    | _, TwoOperands(_, OpRelAddr disp) -> ValueSome(targetOf disp)
    | (Op.JMP | Op.JSR), _ -> tryJumpTarget ()
    | _ -> ValueNone

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
  member _.TargetOf(disp: int32): Addr = targetOf disp

  member private this.AddBranchTargetIfExist addrs =
    match (this :> IInstruction).DirectBranchTarget() with
    | false, _ -> addrs
    | true, target -> Array.append addrs [| target |]

  interface IInstruction with

    member _.Address with get() = addr

    member _.Length with get() = numBytes

    member _.Extent with get() = numBytes

    member _.IsBranch = isBranch ()

    member _.IsModeChanging = false

    member _.IsDirectBranch = tryGetTarget () |> ValueOption.isSome

    member _.IsIndirectBranch =
      match op with
      | Op.JMP | Op.JSR -> tryJumpTarget () |> ValueOption.isNone
      | _ -> false

    member _.IsCondBranch = isBcc () || isFBcc () || isDBcc ()

    (* A DBcc branches where its condition fails, which is when it does not
       fall through to the next instruction. *)
    member _.IsCJmpOnTrue = isBcc () || isFBcc ()

    member _.IsCall = isCall ()

    member _.IsRET = isRet ()

    member _.IsPush = Terminator.futureFeature ()

    member _.IsPop = Terminator.futureFeature ()

    member _.IsInterrupt = isInterrupt ()

    member _.IsExit = isExit ()

    member _.IsNop = op = Op.NOP

    member _.IsInlinedAssembly = false

    member _.IsTerminator _ = isBranch () || isInterrupt () || isExit ()

    member _.DirectBranchTarget(target: byref<Addr>) =
      match tryGetTarget () with
      | ValueSome t ->
        target <- t
        true
      | ValueNone ->
        false

    member _.IndirectTrampolineAddr(_addr: byref<Addr>) =
      Terminator.futureFeature ()

    member _.MemoryDereferences(_: byref<Addr[]>) = Terminator.futureFeature ()

    (* What an RTD drops off the stack is its immediate. *)
    member _.Immediate(v: byref<int64>) =
      match opr with
      | OneOperand(OpImm c)
      | TwoOperands(OpImm c, _) ->
        v <- c
        true
      | _ ->
        false

    member this.GetNextInstrAddrs() =
      let fallThrough = [| addr + uint64 numBytes |]
      if isCall () || isBcc () || isFBcc () || isDBcc () then
        this.AddBranchTargetIfExist fallThrough
      elif isBranch () || isExit () then
        this.AddBranchTargetIfExist [||]
      else
        fallThrough

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
