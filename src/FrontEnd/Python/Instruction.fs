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
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter

/// Represents an instruction for Python.
///
/// The opcode is held as its raw numeric value in the *containing version's*
/// numbering, because every version has an Opcode enum of its own (whose
/// values are CPython's own opcode numbers) and no single type could hold
/// all of them. Everything that depends on what an opcode *means* therefore
/// comes from `semantics`, which each version's own module implements.
type Instruction
  internal(addr,
           numBytes,
           opcode: int,
           opr,
           oprSize,
           version,
           binFile: PythonBinFile,
           semantics: IInstructionSemantics) =

  /// Address of this instruction.
  member _.Address with get(): Addr = addr

  /// Length of this instruction in bytes.
  member _.Length with get(): uint32 = numBytes

  /// Opcode, as its raw value in this instruction's own Python version.
  /// Cast it to that version's Opcode enum to match on it.
  member _.Opcode with get(): int = opcode

  /// Operands.
  member _.Operands with get(): Operands = opr

  /// Operation Size.
  member _.OperationSize with get(): RegType = oprSize

  /// The Python version this instruction was decoded as.
  member _.Version with get(): PythonVersion = version

  /// The file this instruction was decoded from.
  member _.BinFile with get(): PythonBinFile = binFile

  /// Indicates whether this instruction has an additional flag enabled.
  member this.Flag with get() = semantics.HasFlag this

  /// For LOAD_SUPER_ATTR: whether the super() call had explicit (class,
  /// obj) arguments (namei bit 1), as opposed to the implicit zero-arg
  /// `super()` form that the compiler fills in via __class__/self.
  member this.SuperHasExplicitArgs with get() =
    semantics.SuperHasExplicitArgs this

  interface IInstruction with

    member this.Address with get() = this.Address

    member this.Length with get() = this.Length

    member this.IsBranch = semantics.IsBranch this

    member _.IsModeChanging = false

    member this.IsDirectBranch = semantics.IsBranch this

    member _.IsIndirectBranch = false

    member this.IsCondBranch = semantics.IsCondBranch this

    member this.IsCJmpOnTrue = semantics.IsCJmpOnTrue this

    member this.IsCall = semantics.IsCall this

    member this.IsRET = semantics.IsRET this

    member _.IsPush = Terminator.futureFeature ()

    member _.IsPop = Terminator.futureFeature ()

    member _.IsInterrupt = false

    member this.IsExit = semantics.IsExit this

    member this.IsNop = semantics.IsNop this

    member _.IsInlinedAssembly = false

    member this.IsTerminator _ =
      semantics.IsBranch this || semantics.IsExit this

    member _.DirectBranchTarget(_addr: byref<Addr>) =
      Terminator.futureFeature ()

    member _.IndirectTrampolineAddr(_addr: byref<Addr>) =
      Terminator.futureFeature ()

    member _.MemoryDereferences(_: byref<Addr[]>) = Terminator.futureFeature ()

    member _.Immediate _ = false

    member this.GetNextInstrAddrs() =
      let ft = this.Address + uint64 this.Length
      if semantics.IsExit this || semantics.IsRET this then
        [||]
      elif semantics.IsBranch this then
        let n =
          match this.Operands with
          | OneOperand(n, _) -> n
          | _ -> failwith "Python instruction can have at most one operand."
        let target = semantics.BranchTarget(this, ft, n)
        if semantics.IsCondBranch this then [| target; ft |] else [| target |]
      else
        [| ft |]

    member _.InterruptNum(_num: byref<int64>) = Terminator.futureFeature ()

    member this.Translate builder =
      semantics.Lift(this, builder).Stream.ToStmts()

    member this.TranslateToList builder = semantics.Lift(this, builder).Stream

    member this.Disasm builder = semantics.Disasm(this, builder).ToString()

    member this.Disasm() =
      let builder = StringDisasmBuilder(false, null, WordSize.Bit32)
      semantics.Disasm(this, builder).ToString()

    member this.Decompose builder = semantics.Disasm(this, builder).ToAsmWords()

/// Supplies everything about an instruction that depends on which Python
/// version it was decoded as. Each version implements this over its own
/// Opcode enum, which is why none of it can live on Instruction itself.
and internal IInstructionSemantics =
  abstract Lift: Instruction * ILowUIRBuilder -> ILowUIRBuilder
  abstract Disasm: Instruction * IDisasmBuilder -> IDisasmBuilder
  abstract IsBranch: Instruction -> bool
  abstract IsCondBranch: Instruction -> bool
  abstract IsCJmpOnTrue: Instruction -> bool
  abstract IsCall: Instruction -> bool
  abstract IsRET: Instruction -> bool
  abstract IsExit: Instruction -> bool
  abstract IsNop: Instruction -> bool
  abstract HasFlag: Instruction -> bool
  abstract SuperHasExplicitArgs: Instruction -> bool

  /// Branch target, given the fall-through address and the raw oparg.
  abstract BranchTarget: Instruction * Addr * int -> Addr
