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

namespace B2R2.FrontEnd.Python

open B2R2
open B2R2.FrontEnd.BinLifter

/// Represents an instruction for Python.
type Instruction
  internal(addr, numBytes, op, opr, oprSize, version, lifter: ILiftable) =

  let computeBranchTargetAddr ftAddr n =
    let minor = PythonVersion.minor version
    let n = uint64 n
    if minor <= 10 then (* Byte-offset, mostly absolute *)
      match op with
      | Op.JUMP_FORWARD | Op.FOR_ITER -> ftAddr + n
      | Op.JUMP_ABSOLUTE | Op.POP_JUMP_IF_TRUE | Op.POP_JUMP_IF_FALSE
      | Op.JUMP_IF_TRUE_OR_POP | Op.JUMP_IF_FALSE_OR_POP -> n
      | _ -> failwith "Invalid opcode for branch target computation"
    elif minor = 11 then (* Word-offset, relative *)
      match op with
      | Op.JUMP_FORWARD | Op.FOR_ITER | Op.SEND
      | Op.POP_JUMP_IF_TRUE | Op.POP_JUMP_IF_FALSE
      | Op.POP_JUMP_FORWARD_IF_NONE | Op.POP_JUMP_FORWARD_IF_NOT_NONE ->
        ftAddr + 2UL * n
      | Op.POP_JUMP_BACKWARD_IF_TRUE | Op.POP_JUMP_BACKWARD_IF_FALSE
      | Op.POP_JUMP_BACKWARD_IF_NONE | Op.POP_JUMP_BACKWARD_IF_NOT_NONE ->
        ftAddr - 2UL * n
      | Op.JUMP_ABSOLUTE
      | Op.JUMP_IF_TRUE_OR_POP | Op.JUMP_IF_FALSE_OR_POP -> 2UL * n
      | _ -> failwith "Invalid opcode for branch target computation"
    elif minor >= 12 then (* Word-offset, relative *)
      match op with
      | Op.JUMP_FORWARD
      | Op.POP_JUMP_IF_TRUE | Op.POP_JUMP_IF_FALSE
      | Op.POP_JUMP_IF_NONE | Op.POP_JUMP_IF_NOT_NONE
      | Op.FOR_ITER | Op.SEND
      | Op.INSTRUMENTED_JUMP_FORWARD | Op.INSTRUMENTED_FOR_ITER
      | Op.INSTRUMENTED_POP_JUMP_IF_TRUE | Op.INSTRUMENTED_POP_JUMP_IF_FALSE
      | Op.INSTRUMENTED_POP_JUMP_IF_NONE | Op.INSTRUMENTED_POP_JUMP_IF_NOT_NONE
        -> ftAddr + 2UL * n
      | Op.JUMP_BACKWARD | Op.JUMP_BACKWARD_NO_INTERRUPT
      | Op.INSTRUMENTED_JUMP_BACKWARD -> ftAddr - 2UL * n
      | _ -> failwith "Invalid opcode for branch target computation"
    else
      Terminator.futureFeature ()

  /// Address of this instruction.
  member _.Address with get(): Addr = addr

  /// Length of this instruction in bytes.
  member _.Length with get(): uint32 = numBytes

  /// Opcode.
  member _.Opcode with get(): Opcode = op

  /// Operands.
  member _.Operands with get(): Operands = opr

  /// Operation Size.
  member _.OperationSize with get(): RegType = oprSize

  /// Indicates whether this instruction has an additional flag enabled.
  member _.Flag with get() =
    match op with
    | Op.LOAD_GLOBAL
    | Op.LOAD_ATTR
    | Op.LOAD_SUPER_ATTR
    | Op.INSTRUMENTED_LOAD_SUPER_ATTR when PythonVersion.minor version >= 11 ->
      match opr with
      | OneOperand(idx, _) -> (idx &&& 1) = 1
      | _ -> false
    | _ -> false

  interface IInstruction with

    member this.Address with get() = this.Address

    member this.Length with get() = this.Length

    member _.IsBranch =
      match op with
      | Op.JUMP_FORWARD | Op.JUMP_BACKWARD
      | Op.JUMP_BACKWARD_NO_INTERRUPT
      | Op.JUMP | Op.JUMP_NO_INTERRUPT
      | Op.POP_JUMP_IF_FALSE | Op.POP_JUMP_IF_TRUE
      | Op.POP_JUMP_IF_NONE | Op.POP_JUMP_IF_NOT_NONE
      | Op.FOR_ITER | Op.SEND
      | Op.INSTRUMENTED_JUMP_FORWARD | Op.INSTRUMENTED_JUMP_BACKWARD
      | Op.INSTRUMENTED_FOR_ITER
      | Op.INSTRUMENTED_POP_JUMP_IF_FALSE
      | Op.INSTRUMENTED_POP_JUMP_IF_TRUE
      | Op.INSTRUMENTED_POP_JUMP_IF_NONE
      | Op.INSTRUMENTED_POP_JUMP_IF_NOT_NONE -> true
      | _ -> false

    member _.IsModeChanging = false

    member this.IsDirectBranch = (this :> IInstruction).IsBranch

    member _.IsIndirectBranch = false

    member _.IsCondBranch =
      match op with
      | Op.POP_JUMP_IF_FALSE | Op.POP_JUMP_IF_TRUE
      | Op.POP_JUMP_IF_NONE | Op.POP_JUMP_IF_NOT_NONE
      | Op.FOR_ITER | Op.SEND
      | Op.INSTRUMENTED_FOR_ITER
      | Op.INSTRUMENTED_POP_JUMP_IF_FALSE
      | Op.INSTRUMENTED_POP_JUMP_IF_TRUE
      | Op.INSTRUMENTED_POP_JUMP_IF_NONE
      | Op.INSTRUMENTED_POP_JUMP_IF_NOT_NONE -> true
      | _ -> false

    member _.IsCJmpOnTrue =
      match op with
      | Op.POP_JUMP_IF_TRUE
      | Op.INSTRUMENTED_POP_JUMP_IF_TRUE -> true
      | _ -> false

    member _.IsCall = Terminator.futureFeature ()

    member _.IsRET = Terminator.futureFeature ()

    member _.IsPush = Terminator.futureFeature ()

    member _.IsPop = Terminator.futureFeature ()

    member _.IsInterrupt = false

    member _.IsExit =
      match op with
      | Op.RETURN_VALUE | Op.RETURN_CONST
      | Op.RAISE_VARARGS | Op.RERAISE
      | Op.INTERPRETER_EXIT
      | Op.INSTRUMENTED_RETURN_VALUE
      | Op.INSTRUMENTED_RETURN_CONST -> true
      | _ -> false

    member _.IsNop = op = Op.NOP

    member _.IsInlinedAssembly = false

    member this.IsTerminator _ =
      let ins = this :> IInstruction
      ins.IsBranch || ins.IsExit

    member _.DirectBranchTarget(_addr: byref<Addr>) =
      Terminator.futureFeature ()

    member _.IndirectTrampolineAddr(_addr: byref<Addr>) =
      Terminator.futureFeature ()

    member _.MemoryDereferences(_: byref<Addr[]>) = Terminator.futureFeature ()

    member _.Immediate(_v: byref<int64>) = Terminator.futureFeature ()

    member this.GetNextInstrAddrs() =
      let ft = this.Address + uint64 this.Length
      if (this :> IInstruction).IsExit || (this :> IInstruction).IsRET then
        [||]
      elif (this :> IInstruction).IsBranch then
        let target =
          this.Operands
          |> function
            | OneOperand(n, _) -> n
            | _ -> failwith "Python instruction can have at most one operand."
          |> computeBranchTargetAddr ft
        if (this :> IInstruction).IsCondBranch then
          [| target; ft |]
        else
          [| target |]
      else
        [| ft |]

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
