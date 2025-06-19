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

namespace B2R2.FrontEnd.MIPS

open B2R2
open B2R2.FrontEnd.BinLifter

/// Instruction for MIPS.
type Instruction
  internal (addr, numBytes, condition, fmt, op, opr, oprSize, wordSize,
            lifter: ILiftable) =

  let hasConcJmpTarget () =
    match opr with
    | OneOperand (OpAddr _)
    | TwoOperands (_, OpAddr _)
    | ThreeOperands (_, _, OpAddr _)
    | OneOperand (OpImm _) -> true
    | _ -> false

  /// Address of this instruction.
  member _.Address with get (): Addr = addr

  /// Length of this instruction in bytes.
  member _.Length with get (): uint32 = numBytes

  /// Condition.
  member _.Condition with get (): Condition option = condition

  /// Floating Point Format.
  member _.Fmt with get (): Fmt option = fmt

  /// Opcode.
  member _.Opcode with get (): Opcode = op

  /// Operands.
  member _.Operands with get (): Operands = opr

  /// Operation Size.
  member _.OperationSize with get (): RegType = oprSize

  /// Word Size.
  member _.WordSize with get () = wordSize

  interface IInstruction with

    member _.Address with get() = addr

    member _.Length with get() = numBytes

    member _.IsBranch () =
      match op with
      | Opcode.B | Opcode.BAL | Opcode.BEQ | Opcode.BGEZ | Opcode.BGEZAL
      | Opcode.BGTZ | Opcode.BLEZ | Opcode.BLTZ | Opcode.BNE
      | Opcode.JALR | Opcode.JALRHB | Opcode.JR | Opcode.JRHB
      | Opcode.J | Opcode.JAL | Opcode.BC1F | Opcode.BC1T -> true
      | _ -> false

    member _.IsModeChanging () = false

    member this.IsDirectBranch () =
      (this :> IInstruction).IsBranch () && hasConcJmpTarget ()

    member this.IsIndirectBranch () =
      (this :> IInstruction).IsBranch () && (not <| hasConcJmpTarget ())

    member _.IsCondBranch () =
      match op with
      | Opcode.BEQ | Opcode.BLTZ | Opcode.BLEZ | Opcode.BGTZ | Opcode.BGEZ
      | Opcode.BGEZAL | Opcode.BNE | Opcode.BC1F | Opcode.BC1T -> true
      | _ -> false

    member _.IsCJmpOnTrue () =
      match op with
      | Opcode.BEQ | Opcode.BLTZ | Opcode.BLEZ | Opcode.BGTZ | Opcode.BGEZ
      | Opcode.BGEZAL | Opcode.BC1T -> true
      | _ -> false

    member _.IsCall () =
      match op with
      | Opcode.BAL | Opcode.BGEZAL | Opcode.JALR | Opcode.JALRHB | Opcode.JAL ->
        true
      | _ -> false

    member _.IsRET () =
      match op with
      | Opcode.JR ->
        match opr with
        | OneOperand (OpReg Register.R31) -> true
        | _ -> false
      | _ -> false

    member _.IsPush () = Terminator.futureFeature ()

    member _.IsPop () = Terminator.futureFeature ()

    member _.IsInterrupt () =
      match op with
      | Opcode.SYSCALL | Opcode.WAIT -> true
      | _ -> false

    member _.IsExit () =
      match op with
      | Opcode.DERET | Opcode.ERET | Opcode.ERETNC -> true
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
        | OneOperand (OpAddr (Relative offset)) ->
          addr <- (int64 this.Address + offset) |> uint64
          true
        | TwoOperands (_, OpAddr (Relative offset)) ->
          addr <- (int64 this.Address + offset) |> uint64
          true
        | ThreeOperands (_, _,OpAddr (Relative offset)) ->
          addr <- (int64 this.Address + offset) |> uint64
          true
        | OneOperand (OpImm (imm)) ->
          addr <- imm
          true
        | _ -> false
      else false

    member this.IndirectTrampolineAddr (_addr: byref<Addr>) =
      if (this :> IInstruction).IsIndirectBranch () then
        Terminator.futureFeature ()
      else false

    member _.Immediate (v: byref<int64>) =
      match opr with
      | OneOperand (OpImm (c))
      | TwoOperands (OpImm (c), _)
      | TwoOperands (_, OpImm (c))
      | ThreeOperands (OpImm (c), _, _)
      | ThreeOperands (_, OpImm (c), _)
      | ThreeOperands (_, _, OpImm (c))
      | FourOperands (OpImm (c), _, _, _)
      | FourOperands (_, OpImm (c), _, _)
      | FourOperands (_, _, OpImm (c), _)
      | FourOperands (_, _, _, OpImm (c)) -> v <- int64 c; true
      | _ -> false

    member _.GetNextInstrAddrs () = Terminator.futureFeature ()

    member _.InterruptNum (_num: byref<int64>) = Terminator.futureFeature ()

    member this.Translate builder =
      let builder = builder :?> LowUIRBuilder
      (lifter.Lift this builder).Stream.ToStmts ()

    member this.TranslateToList builder =
      let builder = builder :?> LowUIRBuilder
      (lifter.Lift this builder).Stream

    member this.Disasm builder =
      (lifter.Disasm this builder).ToString ()

    member this.Disasm () =
      let builder = StringDisasmBuilder (false, null, wordSize)
      (lifter.Disasm this builder).ToString ()

    member this.Decompose builder =
      (lifter.Disasm this builder).ToAsmWords ()

and internal ILiftable =
  abstract Lift: Instruction -> LowUIRBuilder -> ILowUIRBuilder
  abstract Disasm: Instruction -> IDisasmBuilder -> IDisasmBuilder
