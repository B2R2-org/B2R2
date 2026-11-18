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
  internal(addr, numBytes, fmt, op, opr, wordSize, lifter: ILiftable) =

  let operands () =
    match opr with
    | NoOperand -> [||]
    | OneOperand o1 -> [| o1 |]
    | TwoOperands(o1, o2) -> [| o1; o2 |]
    | ThreeOperands(o1, o2, o3) -> [| o1; o2; o3 |]
    | FourOperands(o1, o2, o3, o4) -> [| o1; o2; o3; o4 |]
    | FiveOperands(o1, o2, o3, o4, o5) -> [| o1; o2; o3; o4; o5 |]
    | SixOperands(o1, o2, o3, o4, o5, o6) -> [| o1; o2; o3; o4; o5; o6 |]

  let getMaskVal () =
    operands ()
    |> Array.tryPick (function
      | OpMask m -> Some m
      | _ -> None)

  let immValue = function
    | ImmU4 bv | ImmU12 bv -> bv.ToInt64()
    | ImmS12 bv | ImmS24 bv -> BitVector.SExt(bv, 64<rt>).ToInt64()
    | ImmU8 v -> int64 v
    | ImmS8 v -> int64 v
    | ImmU16 v -> int64 v
    | ImmS16 v -> int64 v
    | ImmU32 v -> int64 v
    | ImmS32 v -> int64 v

  let tryImmediate () =
    operands ()
    |> Array.tryPick (function
      | OpImm i -> Some(immValue i)
      | _ -> None)

  (* A compare and branch takes its mask bits as equal, low and high, and
     leaves the last one unused. *)
  let isCompareAndBranch () =
    match op with
    | Opcode.CRJ | Opcode.CGRJ | Opcode.CLRJ | Opcode.CLGRJ | Opcode.CIJ
    | Opcode.CGIJ | Opcode.CLIJ | Opcode.CLGIJ | Opcode.CRB | Opcode.CGRB
    | Opcode.CLRB | Opcode.CLGRB | Opcode.CIB | Opcode.CGIB | Opcode.CLIB
    | Opcode.CLGIB -> true
    | _ -> false

  (* The bits of the mask that pick the outcomes the branch is taken on, along
     with the bits that pick them all: the four condition codes for a branch
     on condition, and equal, low and high for a compare and branch. *)
  let takenMask () =
    let m = getMaskVal () |> Option.defaultValue 0us
    if isCompareAndBranch () then struct (m &&& 0xeus, 0xeus)
    else struct (m &&& 0xfus, 0xfus)

  let takesNone () =
    let struct (m, _) = takenMask ()
    m = 0us

  let takesAll () =
    let struct (m, all) = takenMask ()
    m = all

  (* A relative branch counts its halfwords from the instruction itself, and
     the sum is an address of the addressing mode, which wraps within 31 bits
     under ESA/390 and keeps all 64 on z/Architecture. *)
  let relTarget (halfwords: int64) =
    let target = addr + uint64 (2L * halfwords)
    if wordSize = WordSize.Bit32 then target &&& 0x7FFFFFFFUL else target

  let extractRelImm = function
    | OpRImm(ImmS16 v) -> Some(int64 v)
    | OpRImm(ImmS32 v) -> Some(int64 v)
    | _ -> None

  let tryRelTarget () =
    match opr with
    | TwoOperands(_, o) | ThreeOperands(_, o, _) -> extractRelImm o
    | FourOperands(_, _, _, o) -> extractRelImm o
    | _ -> None
    |> Option.map relTarget

  (* GCC plants j .+2 where __builtin_trap is: the branch goes into its own
     second halfword, which holds no valid opcode, so the program interruption
     that the halfword raises ends the program rather than the branch going on
     anywhere. *)
  let isTrap () =
    (op = Opcode.BRC || op = Opcode.BRCL)
    && takesAll ()
    && tryRelTarget () = Some(addr + 2UL)

  (* An RR branch to the register R0 names no register, and so branches
     nowhere: BCR does nothing then, BASR only saves the address that follows,
     and BCTR only counts down. *)
  let r2 () =
    match opr with
    | TwoOperands(_, OpReg r) -> r
    | _ -> Register.R0

  let isMaskedBranch () =
    match op with
    | Opcode.BRC | Opcode.BRCL | Opcode.BC | Opcode.BIC -> true
    | Opcode.BCR -> r2 () <> Register.R0
    | _ -> isCompareAndBranch ()

  (* The branches that count down or step an index decide on the count or the
     index, whatever the condition code says. *)
  let isCountingBranch () =
    match op with
    | Opcode.BCT | Opcode.BCTG | Opcode.BRCT | Opcode.BRCTG | Opcode.BRCTH
    | Opcode.BXH | Opcode.BXHG | Opcode.BXLE | Opcode.BXLEG | Opcode.BRXH
    | Opcode.BRXHG | Opcode.BRXLE | Opcode.BRXLG -> true
    | Opcode.BCTR | Opcode.BCTGR -> r2 () <> Register.R0
    | _ -> false

  let isCall () =
    match op with
    | Opcode.BRAS | Opcode.BRASL | Opcode.BAL | Opcode.BAS -> true
    | Opcode.BALR | Opcode.BASR | Opcode.BASSM -> r2 () <> Register.R0
    | _ -> false

  let isBranch () =
    if isMaskedBranch () then
      not (takesNone () || isTrap ())
    else
      isCountingBranch () || isCall ()
      || (op = Opcode.BSM && r2 () <> Register.R0)

  let isCondBranch () =
    if isMaskedBranch () then not (takesNone () || takesAll ())
    else isCountingBranch ()

  let tryGetTarget () =
    match tryRelTarget () with
    | Some target when isBranch () -> ValueSome target
    | _ -> ValueNone

  let isInterrupt () =
    match op with
    (* SVC asks the supervisor, MC raises a monitor-event interruption, and
       TRAP2 and TRAP4 a special-operation one. PC enters a service routine
       the way SYSENTER does on Intel. *)
    | Opcode.SVC | Opcode.MC | Opcode.TRAP2 | Opcode.TRAP4
    | Opcode.PC -> true
    | _ -> false

  let isExit () =
    match op with
    (* PR leaves the routine a PC entered, and loading the PSW replaces the
       whole program state, which is how S390 returns from an interruption. *)
    | Opcode.PR | Opcode.LPSW | Opcode.LPSWE -> true
    | _ -> isTrap ()

  /// Address of this instruction.
  member _.Address with get(): Addr = addr

  /// Length of this instruction in bytes.
  member _.Length with get(): uint32 = numBytes

  /// Instruction format.
  member _.Fmt with get(): Fmt = fmt

  /// Opcode.
  member _.Opcode with get(): Opcode = op

  /// Operands.
  member _.Operands with get(): Operands = opr

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
      isBranch () && (tryGetTarget () |> ValueOption.isNone)

    member _.IsCondBranch = isCondBranch ()

    (* The lifter puts the target of every conditional branch on the side
       that its condition holds. *)
    member _.IsCJmpOnTrue = isCondBranch ()

    member _.IsCall = isCall ()

    (* S390 has no return instruction. A function returns by branching to the
       address that its caller left in R14, wherever it has moved it by then,
       and code branches through R14 for other ends as well, such as a jump
       through a table, so only the data flow tells a return. *)
    member _.IsRET = false

    member _.IsPush = false

    member _.IsPop = false

    member _.IsInterrupt = isInterrupt ()

    member _.IsExit = isExit ()

    member _.IsNop =
      match op with
      | Opcode.BRC | Opcode.BRCL | Opcode.BC ->
        takesNone ()
      | Opcode.BCR ->
        takesNone () || r2 () = Register.R0
      | Opcode.CRB | Opcode.CGRB | Opcode.CRJ | Opcode.CGRJ
      | Opcode.CIB | Opcode.CGIB | Opcode.CIJ | Opcode.CGIJ
      | Opcode.CLRB | Opcode.CLGRB | Opcode.CLRJ | Opcode.CLGRJ
      | Opcode.CLIB | Opcode.CLGIB | Opcode.CLIJ | Opcode.CLGIJ
      | Opcode.CRT | Opcode.CGRT | Opcode.CIT | Opcode.CGIT
      | Opcode.CLRT | Opcode.CLGRT | Opcode.CLFIT | Opcode.CLGIT ->
        match getMaskVal () with
        | Some value -> uint16 value &&& 0b1110us = 0us
        | None -> false
      | Opcode.LOCR | Opcode.LOCGR | Opcode.LOC | Opcode.LOCG
      | Opcode.LOCFHR | Opcode.LOCFH | Opcode.STOC | Opcode.STOCG
      | Opcode.STOCFH ->
        match getMaskVal () with
        | Some value -> uint16 value &&& 0b1111us = 0us
        | None -> false
      | _ ->
        false

    member _.IsInlinedAssembly = false

    member _.IsTerminator _ = isBranch () || isInterrupt () || isExit ()

    member _.DirectBranchTarget(target: byref<Addr>) =
      match tryGetTarget () with
      | ValueSome t ->
        target <- t
        true
      | ValueNone ->
        false

    (* BIC reads its target from storage, but from an address that registers
       form, which the instruction alone does not fix. *)
    member _.IndirectTrampolineAddr(_addr: byref<Addr>) = false

    member _.MemoryDereferences(_: byref<Addr[]>) = Terminator.futureFeature ()

    (* The immediate of an instruction, which no branch has: a relative one
       holds an offset, and a return pops nothing off the stack. *)
    member _.Immediate(v: byref<int64>) =
      match tryImmediate () with
      | Some c ->
        v <- c
        true
      | None ->
        false

    member this.GetNextInstrAddrs() =
      let fallThrough = [| addr + uint64 numBytes |]
      if isCall () || isCondBranch () then
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
      let builder = StringDisasmBuilder(false, null, wordSize)
      lifter.Disasm(this, builder).ToString()

    member this.Decompose builder = lifter.Disasm(this, builder).ToAsmWords()

and internal ILiftable =
  abstract Lift: Instruction * ILowUIRBuilder -> ILowUIRBuilder
  abstract Disasm: Instruction * IDisasmBuilder -> IDisasmBuilder
