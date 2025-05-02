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

namespace B2R2.FrontEnd.BinLifter

open System.Collections.Generic
open System.Runtime.InteropServices
open B2R2
open B2R2.BinIR.LowUIR

/// <summary>
///   A high-level class representing a single machine instruction in a
///   platform-independent manner. It provides useful methods for accessing
///   useful information about the instruction.
/// </summary>
[<AbstractClass>]
type Instruction (addr, len, wordSize) =
  /// <summary>
  ///   The address of this instruction.
  /// </summary>
  member _.Address with get(): Addr = addr

  /// <summary>
  ///   The length of this instruction in bytes.
  /// </summary>
  member _.Length with get(): uint32 = len

  /// <summary>
  ///   The word size used for translating this instruction. Some architectures
  ///   have several representations of their instruction sets depending on the
  ///   word size. For example, Intel can be represented as either x86 or x86-64
  ///   depending on the word size used. We store this information per
  ///   instruction to distinguish specific instruction sets used.
  /// </summary>
  member _.WordSize with get(): WordSize = wordSize

  /// <summary>
  ///   Is this a branch instruction? A branch instruction includes any kinds of
  ///   jump instructions, such as CALL/RET instructions, indirect/direct jump
  ///   instructions, and conditional jump instructions.
  /// </summary>
  /// <returns>
  ///   Returns true if this is a branch instruction.
  /// </returns>
  abstract IsBranch: unit -> bool

  /// <summary>
  ///   Is this a mode-changing instruction? In ARMv7, BLX is such an
  ///   instruction.
  /// </summary>
  /// <returns>
  ///   Returns true if this is a mode-changing instruction.
  /// </returns>
  abstract IsModeChanging: unit -> bool

  /// <summary>
  ///   Is this a direct branch instruction? A direct branch instruction is a
  ///   branch instruction with a concrete jump target, which is inscribed in
  ///   its operand. For example, <c>CALL ECX</c> is not a direct branch
  ///   instruction, but <c>JMP +10</c> is.
  /// </summary>
  /// <returns>
  ///   Returns true if this is a direct branch instruction.
  /// </returns>
  abstract IsDirectBranch: unit -> bool

  /// <summary>
  ///   Is this an indirect branch instruction? An indirect branch instruction
  ///   is a branch instruction with a symbolic jump target. Thus, the jump
  ///   target is only computed at runtime.
  /// </summary>
  /// <returns>
  ///   Returns true if this is an indirect branch instruction.
  /// </returns>
  abstract IsIndirectBranch: unit -> bool

  /// <summary>
  ///   Is this a conditional branch instruction?
  /// </summary>
  /// <returns>
  ///   Returns true if this is a conditional branch instruction.
  /// </returns>
  abstract IsCondBranch: unit -> bool

  /// <summary>
  ///   Is this a conditional branch instruction, and it jumps to the branch
  ///   target when the predicate is true? For example, this method returns true
  ///   for <c>JE</c> instructions of Intel, but false for <c>JNE</c>
  ///   instructions.
  /// </summary>
  /// <returns>
  ///   Returns true if this is a conditional branch instruction, and jumps to
  ///   the target when the predicate is true.
  /// </returns>
  abstract IsCJmpOnTrue: unit -> bool

  /// <summary>
  ///   Is this a call instruction?
  /// </summary>
  /// <returns>
  ///   Returns true if this is a call instruction.
  /// </returns>
  abstract IsCall: unit -> bool

  /// <summary>
  ///   Is this a return instruction?
  /// </summary>
  /// <returns>
  ///   Returns true if this is a return instruction.
  /// </returns>
  abstract IsRET: unit -> bool

  /// <summary>
  ///   Does this instruction involve an interrupt?
  /// </summary>
  /// <returns>
  ///   Returns true if this is an interrupt instruction
  /// </returns>
  abstract IsInterrupt: unit -> bool

  /// <summary>
  ///   Does this instruction exits the program execution? For example, this
  ///   function returns true for the <c>HLT</c> instruction of Intel. We also
  ///   consider returning from kernel mode to user mode (e.g. <c>SYSEXIT</c>
  ///   instruction of Intel) as an exit.
  /// </summary>
  /// <returns>
  ///   Returns true if this instruction should be at the end of the
  ///   corresponding basic block.
  /// </returns>
  abstract IsExit: unit -> bool

  /// <summary>
  ///   Does this instruction end a basic block? For example, this function
  ///   returns true for branch instructions and exit instructions. We also
  ///   consider system call instructions as a terminator.
  /// </summary>
  /// <returns>
  ///   Returns true if this instruction should be at the end of the
  ///   corresponding basic block.
  /// </returns>
  abstract IsTerminator: unit -> bool

  /// <summary>
  ///   Is this a NO-OP instruction?
  /// </summary>
  /// <returns>
  ///   Returns true if this instruction is a NO-OP.
  /// </returns>
  abstract IsNop: unit -> bool

  /// <summary>
  ///   Return a branch target address if we can directly compute it, i.e., for
  ///   direct branches.
  /// </summary>
  /// <returns>
  ///   Returns true if a target address exists. Otherwise, returns false.
  /// </returns>
  abstract DirectBranchTarget: [<Out>] addr: byref<Addr> -> bool

  /// <summary>
  ///   Return a trampoline address of an indirect branch instruction if we can
  ///   directly compute the address. For example, `JMP [RIP + 0x42]` is an
  ///   indirect branch instruction, but we can compute the trampoline address
  ///   as RIP is statically known anyways when PIC is off.
  /// </summary>
  /// <returns>
  ///   Returns true if a trampoline address exists. Otherwise, returns false.
  /// </returns>
  abstract IndirectTrampolineAddr: [<Out>] addr: byref<Addr> -> bool

  /// <summary>
  ///   Return an integer immediate value of the instruction if there is one.
  ///   This function will ignore floating-point immediate values.
  /// </summary>
  /// <returns>
  ///   Returns true if an immediate exists. Otherwise, returns false.
  /// </returns>
  abstract Immediate: [<Out>] v: byref<int64> -> bool

  /// <summary>
  ///   Return an array of possible next instruction addresses along with
  ///   their ArchOperationMode. For branch instructions, the returned sequence
  ///   includes jump target(s). For regular instructions, the sequence is a
  ///   singleton of the fall-through address. This function does not resolve
  ///   indirect branch targets.
  /// </summary>
  abstract GetNextInstrAddrs: unit -> (Addr * ArchOperationMode) array

  /// <summary>
  ///   Return the interrupt number if this is an interrupt instruction.
  /// </summary>
  abstract InterruptNum: [<Out>] num: byref<int64> -> bool

  /// <summary>
  ///   Lift this instruction into a LowUIR statement array given a translation
  ///   context.
  /// </summary>
  /// <returns>
  ///   Returns an array of LowUIR statements.
  /// </returns>
  abstract Translate: ILowUIRBuilder -> Stmt[]

  /// <summary>
  ///   Lift this instruction into a LowUIR statement list given a translation
  ///   context.
  /// </summary>
  /// <returns>
  ///   Returns a list of LowUIR statements.
  /// </returns>
  abstract TranslateToList: ILowUIRBuilder -> List<Stmt>

  /// <summary>
  ///   Disassemble this instruction.
  /// </summary>
  /// <param name="builder">
  ///   When this parameter is given, we disassemble the instruction with the
  ///   given name builder to disassemble the instruction. It can resolve
  ///   symbols depending on the implementation of the builder.
  /// </param>
  /// <returns>
  ///   Returns a disassembled string.
  /// </returns>
  abstract Disasm: builder: IDisasmBuilder -> string

  /// <summary>
  ///   Disassemble this instruction. This function is a convenience method,
  ///   which internally creates a default disassembly builder and uses it to
  ///   disassemble the instruction. Hence, this is not as efficient as the
  ///   previous method and should be avoided if disassembly performance is a
  ///   concern.
  /// </summary>
  /// <returns>
  ///   Returns a disassembled string.
  /// </returns>
  abstract Disasm: unit -> string

  /// <summary>
  ///   Decompose this instruction into AsmWords.
  /// </summary>
  /// <returns>
  ///   Returns an array of AsmWords.
  /// </returns>
  abstract Decompose: builder: IDisasmBuilder -> AsmWord []

  /// <summary>
  ///   Is this a virtual instruction that represents an inlined assembly code?
  /// </summary>
  abstract IsInlinedAssembly: unit -> bool

// vim: set tw=80 sts=2 sw=2:
