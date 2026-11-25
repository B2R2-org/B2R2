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

namespace B2R2.FrontEnd.PARISC

open B2R2
open B2R2.FrontEnd.BinLifter

/// Represents an instruction for PARISC.
type Instruction
  internal(addr,
           numBytes,
           completer,
           cond,
           id,
           op,
           opr,
           oprSize,
           wordSize,
           lifter: ILiftable) =
  let mutable delaySlot: Instruction option = None

  let isTransfer () =
    match op with
    | Opcode.B | Opcode.BLR | Opcode.BV | Opcode.BE | Opcode.BVE
    | Opcode.ADDB | Opcode.ADDIB | Opcode.BB | Opcode.CMPB | Opcode.CMPIB
    | Opcode.MOVB | Opcode.MOVIB -> true
    | _ -> false

  let isUnconditional () =
    match op with
    | Opcode.B | Opcode.BLR | Opcode.BV | Opcode.BE | Opcode.BVE -> true
    | _ -> false

  /// An unconditional transfer that nullifies never runs the instruction
  /// after it, so that instruction is none of its business: a jump table or
  /// a literal pool sits there as often as not.
  let hasDelaySlot () =
    isTransfer () && not (isUnconditional () && cond = Some Completer.N)

  let isCondTransfer () = isTransfer () && not (isUnconditional ())

  let isNever c = c = Completer.NEVER || c = Completer.DNEVER

  (* The condition on which an instruction nullifies the one after it, the way
     the lifter has it do: CMPICLR keeps it with its completers, the others in
     the condition slot. *)
  let tryGetNullifyingCond () =
    match op with
    | Opcode.CMPICLR ->
      match (completer: Completer array option) with
      | Some cs when cs.Length > 0 && not (isNever cs[0]) -> ValueSome cs[0]
      | _ -> ValueNone
    | Opcode.ADD | Opcode.ADDI | Opcode.SHLADD | Opcode.SUB | Opcode.SUBI
    | Opcode.CMPCLR | Opcode.DS | Opcode.AND | Opcode.ANDCM | Opcode.OR
    | Opcode.XOR | Opcode.UXOR | Opcode.UADDCM | Opcode.SHRPW | Opcode.SHRPD
    | Opcode.EXTRW | Opcode.EXTRD | Opcode.DEPW | Opcode.DEPWI | Opcode.DEPD
    | Opcode.DEPDI ->
      match cond with
      | Some c when not (isNever c) -> ValueSome c
      | _ -> ValueNone
    | _ ->
      ValueNone

  (* FTEST nullifies the next instruction where the last comparison set the
     compare bit. *)
  let nullifiesNext () =
    op = Opcode.FTEST || ValueOption.isSome (tryGetNullifyingCond ())

  let alwaysNullifies () =
    match tryGetNullifyingCond () with
    | ValueSome c -> c = Completer.TR || c = Completer.DTR
    | ValueNone -> false

  (* The lifter has an instruction that nullifies the next one branch past
     that one, which is a branch like any other to a client. *)
  let isCondBranch () =
    isCondTransfer () || (nullifiesNext () && not (alwaysNullifies ()))

  (* The decoder has already counted the displacement of a branch from eight
     past the branch, where PA-RISC counts it from. *)
  let tryGetDisplacement () =
    match op, opr with
    | Opcode.B, TwoOperands(OpImm imm, _) -> ValueSome imm
    | _, ThreeOperands(_, _, OpImm imm) when isCondTransfer () -> ValueSome imm
    | _ when nullifiesNext () -> ValueSome 8UL
    | _ -> ValueNone

  let tryGetTarget () =
    let mask =
      if wordSize = WordSize.Bit32 then 0xFFFFFFFFUL else System.UInt64.MaxValue
    tryGetDisplacement ()
    |> ValueOption.map (fun imm -> (addr + imm) &&& mask)

  let hasCompleter c =
    match completer with
    | Some cs -> Array.contains c cs
    | None -> false

  (* The register a transfer leaves the address past its delay slot in, which
     GR0 discards: B and BLR name it, BE,L links GR31 and BVE,L GR2. *)
  let linkRegister () =
    match op, opr with
    | Opcode.B, TwoOperands(_, OpReg r)
    | Opcode.BLR, TwoOperands(_, OpReg r) -> r
    | Opcode.BE, _ when hasCompleter Completer.L -> Register.GR31
    | Opcode.BVE, _ when hasCompleter Completer.L -> Register.GR2
    | _ -> Register.GR0

  (* BE to one of the three services of the gateway page of Linux, which
     return past the delay slot, as a system call does. *)
  let isService () =
    let isGateway d = d = 0xb0L || d = 0xe0L || d = 0x100L
    match op, opr with
    | Opcode.BE, OneOperand(OpMem(Register.GR0, _, Some(Imm d), _)) ->
      isGateway d
    | Opcode.BE, ThreeOperands(OpMem(Register.GR0, _, Some(Imm d), _), _, _) ->
      isGateway d
    | _ ->
      false

  (* B that links and goes right past its delay slot, where a callee would
     return to, reads the address it runs at, as PIC code does to find a jump
     table, rather than calls. *)
  let readsPC () = op = Opcode.B && tryGetDisplacement () = ValueSome 8UL

  let isCall () =
    linkRegister () <> Register.GR0 && not (isService () || readsPC ())

  (* The privileged instructions that user code reaches only to raise the
     illegal-instruction trap, which GCC plants for __builtin_trap. *)
  let isExit () =
    match op with
    | Opcode.IITLBA | Opcode.IITLBP | Opcode.IDTLBA | Opcode.IDTLBP
    | Opcode.LCI | Opcode.LPA -> true
    | _ -> false

  (* Where a conditional branch goes on when it is not taken: past its delay
     slot, unless the slot holds another transfer, which then runs on its own
     at its own address, as the lifter has it. An untaken backward branch that
     nullifies skips such a slot all the same. *)
  let fallThrough () =
    match delaySlot with
    | Some slot when slot.IsTransfer ->
      let backward =
        match tryGetDisplacement () with
        | ValueSome imm -> int64 (imm - 8UL) < 0L
        | ValueNone -> false
      if cond = Some Completer.N && backward then addr + 8UL else addr + 4UL
    | _ ->
      addr + 8UL

  let withTarget nexts =
    match tryGetTarget () with
    | ValueSome target -> Array.append nexts [| target |]
    | ValueNone -> nexts

  (* A delay slot that nullifies the next instruction passes over the one the
     transfer goes on to, wherever that is, and a call returns past its slot
     all the same. *)
  let skippedBySlot (nexts: Addr[]) =
    match delaySlot with
    | Some slot when slot.NullifiesNext ->
      nexts |> Array.collect (fun next -> [| next; next + 4UL |])
    | _ ->
      nexts

  let transferNexts () =
    if isCall () then
      Array.append [| addr + 8UL |] (skippedBySlot (withTarget [||]))
    elif isCondTransfer () then
      skippedBySlot (withTarget [| fallThrough () |])
    else
      skippedBySlot (withTarget [||])

  let isNop () =
    let r0 = OpReg Register.GR0
    op = Opcode.OR
    && opr = ThreeOperands(r0, r0, r0)
    && (Option.isNone cond || cond = Some Completer.NEVER)

  let tryImmediate () =
    match opr with
    | OneOperand(OpImm v)
    | TwoOperands(OpImm v, _)
    | ThreeOperands(OpImm v, _, _) -> Some(int64 v)
    | _ -> None

  /// Address of this instruction.
  member _.Address with get(): Addr = addr

  /// Length of this instruction in bytes.
  member _.Length with get(): uint32 = numBytes

  /// Completer.
  member _.Completer with get(): Completer array option = completer

  /// Completer condition or fmt.
  member _.Condition with get(): Completer option = cond

  /// Completer swap and uid.
  member _.ID with get(): uint64[] option = id

  /// Opcode.
  member _.Opcode with get(): Opcode = op

  /// Operands.
  member _.Operands with get(): Operands = opr

  /// Operation Size.
  member _.OperationSize with get(): RegType = oprSize

  /// Word size.
  member _.WordSize with get(): WordSize = wordSize

  /// Whether this instruction transfers control, which every one does after
  /// the instruction that follows it, its delay slot.
  member _.IsTransfer with get(): bool = isTransfer ()

  /// Whether this instruction is a transfer whose delay slot may run, and so
  /// must be lifted with it.
  member _.HasDelaySlot with get(): bool = hasDelaySlot ()

  /// The instruction in this transfer's delay slot, which the transfer lifts
  /// itself, or None where the instruction is no such transfer or the bytes
  /// ended before its slot (see MissingDelaySlotException). Only the parser
  /// sets it.
  member _.DelaySlot
    with get(): Instruction option = delaySlot
     and internal set v = delaySlot <- v

  /// Whether this instruction nullifies the next one where its condition
  /// holds, which the lifter has it do by a branch past that one.
  member internal _.NullifiesNext with get(): bool = nullifiesNext ()

  /// Lifts this instruction into the given builder, as a transfer does the
  /// instruction in its delay slot.
  member internal this.LiftInto(builder: LowUIRBuilder) =
    lifter.Lift(this, builder) |> ignore

  interface IInstruction with

    member this.Address with get() = this.Address

    member this.Length with get() = this.Length

    member _.Extent with get() =
      match delaySlot with
      | Some slot -> numBytes + slot.Length
      | None -> numBytes

    (* A service of the gateway page returns past its delay slot, as a system
       call does, rather than branches, and an instruction that nullifies the
       next one branches past it. *)
    member _.IsBranch =
      (isTransfer () && not (isService ())) || nullifiesNext ()

    member _.IsModeChanging = false

    member _.IsDirectBranch = tryGetTarget () |> ValueOption.isSome

    member _.IsIndirectBranch =
      isTransfer () && not (isService ())
      && (tryGetTarget () |> ValueOption.isNone)

    member _.IsCondBranch = isCondBranch ()

    (* The lifter puts the target of every conditional branch on the side
       that its condition holds. *)
    member _.IsCJmpOnTrue = isCondBranch ()

    member _.IsCall = isCall ()

    (* PA-RISC has no return instruction: a procedure returns by BV through
       GR2, where a call leaves the address to return to, but GCC jumps
       through a table by way of GR2 as well, so only what GR2 holds tells. *)
    member _.IsRET = false

    member _.IsPush = false

    member _.IsPop = false

    member _.IsInterrupt = isService ()

    member _.IsExit = isExit ()

    member _.IsNop = isNop ()

    member _.IsInlinedAssembly = false

    (* A transfer carries its delay slot, so it ends the block itself, and an
       instruction that nullifies the next one branches past it. *)
    member _.IsTerminator _ = isTransfer () || isExit () || nullifiesNext ()

    member _.DirectBranchTarget(target: byref<Addr>) =
      match tryGetTarget () with
      | ValueSome t ->
        target <- t
        true
      | ValueNone ->
        false

    member _.IndirectTrampolineAddr(_addr: byref<Addr>) = false

    member _.MemoryDereferences(_: byref<Addr[]>) = Terminator.futureFeature ()

    (* The immediate of an instruction, which no transfer has: a branch holds
       a displacement, and a return pops nothing off the stack. *)
    member _.Immediate(v: byref<int64>) =
      let imm = if isTransfer () then None else tryImmediate ()
      match imm with
      | Some c ->
        v <- c
        true
      | None ->
        false

    member _.GetNextInstrAddrs() =
      if isExit () then [||]
      elif isService () then [| addr + 8UL |]
      elif isTransfer () then transferNexts ()
      elif alwaysNullifies () then [| addr + 8UL |]
      elif nullifiesNext () then [| addr + 4UL; addr + 8UL |]
      else [| addr + 4UL |]

    member _.InterruptNum(_num: byref<int64>) = Terminator.futureFeature ()

    member this.Translate builder = lifter.Lift(this, builder).Stream.ToStmts()

    member this.TranslateToList builder = lifter.Lift(this, builder).Stream

    member this.Disasm builder = lifter.Disasm(this, builder).ToString()

    member this.Disasm() =
      let builder = StringDisasmBuilder(false, null, wordSize)
      lifter.Disasm(this, builder).ToString()

    member this.Decompose builder = lifter.Disasm(this, builder).ToAsmWords()

and internal ILiftable =
  abstract Lift: Instruction * ILowUIRBuilder -> ILowUIRBuilder
  abstract Disasm: Instruction * IDisasmBuilder -> IDisasmBuilder
