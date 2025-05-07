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

namespace B2R2.FrontEnd.EVM

open B2R2
open B2R2.FrontEnd.BinLifter

/// Instruction for EVM.
type Instruction

  internal (addr, numBytes, offset, opcode, gas, lifter: ILiftable) =

  /// Address.
  member _.Address with get (): Addr = addr

  /// Instruction length.
  member _.NumBytes with get (): uint32 = numBytes

  /// Offset of the instruction. When codecopy (or similar) is used, we should
  /// adjust the address of the copied instructions using this offset.
  member _.Offset with get (): Addr = offset

  /// Opcode.
  member _.Opcode with get (): Opcode = opcode

  /// Gas.
  member _.GAS with get (): int = gas

  interface IInstruction with

    member _.Address with get () = addr

    member _.Length with get () = numBytes

    member _.IsBranch () =
      match opcode with
      | JUMP
      | JUMPI -> true
      | _ -> false

    member _.IsModeChanging () = false

    member _.IsDirectBranch () = false

    member this.IsIndirectBranch () =
      (this :> IInstruction).IsBranch ()

    member _.IsCondBranch () =
      match opcode with
      | JUMPI -> true
      | _ -> false

    member _.IsCJmpOnTrue () =
      match opcode with
      | JUMPI -> true
      | _ -> false

    member _.IsCall () = false

    member _.IsRET () =
      match opcode with
      | RETURN -> true
      | _ -> false

    member _.IsInterrupt () = Terminator.futureFeature ()

    member _.IsExit () =
      match opcode with
      | REVERT | RETURN | SELFDESTRUCT | INVALID | STOP -> true
      | _ -> false

    member this.IsTerminator () =
      let ins = this :> IInstruction
      ins.IsIndirectBranch () || ins.IsExit ()

    member _.IsNop () = false

    member _.IsInlinedAssembly () = false

    member _.DirectBranchTarget (_addr: byref<Addr>) = false

    member _.IndirectTrampolineAddr (_addr: byref<Addr>) = false

    member _.Immediate _ = false

    member this.GetNextInstrAddrs () =
      let fallthrough = this.Address + uint64 numBytes
      let acc = [| fallthrough |]
      if (this :> IInstruction).IsExit () then [||]
      else acc

    member _.InterruptNum (_num: byref<int64>) = Terminator.futureFeature ()

    member this.Translate builder =
      (lifter.Lift this builder).Stream.ToStmts ()

    member this.TranslateToList builder =
      (lifter.Lift this builder).Stream

    member this.Disasm builder =
      (lifter.Disasm this builder).ToString ()

    member this.Disasm () =
      let builder = StringDisasmBuilder (false, null, WordSize.Bit256)
      (lifter.Disasm this builder).ToString ()

    member this.Decompose builder =
      (lifter.Disasm this builder).ToAsmWords ()

and internal ILiftable =
  abstract Lift: Instruction -> ILowUIRBuilder -> ILowUIRBuilder
  abstract Disasm: Instruction -> IDisasmBuilder -> IDisasmBuilder
