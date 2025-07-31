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
/// Represents a single machine instruction in a platform-independent manner.
/// It provides useful methods for accessing useful information about the
/// instruction.
/// </summary>
[<AllowNullLiteral>]
type IInstruction =
  /// <summary>
  /// The address of this instruction.
  /// </summary>
  abstract Address: Addr

  /// <summary>
  /// The length of this instruction in bytes.
  /// </summary>
  abstract Length: uint32

  /// <summary>
  /// Is this a branch instruction? A branch instruction includes any kinds of
  /// jump instructions, such as CALL/RET instructions, indirect/direct jump
  /// instructions, and conditional jump instructions.
  /// </summary>
  /// <returns>
  /// Returns true if this is a branch instruction.
  /// </returns>
  abstract IsBranch: bool

  /// <summary>
  /// Is this a mode-changing instruction? In ARMv7, BLX is such an
  /// instruction.
  /// </summary>
  /// <returns>
  /// Returns true if this is a mode-changing instruction.
  /// </returns>
  abstract IsModeChanging: bool

  /// <summary>
  /// Is this a direct branch instruction? A direct branch instruction is a
  /// branch instruction with a concrete jump target, which is inscribed in its
  /// operand. For example, <c>CALL ECX</c> is not a direct branch instruction,
  /// but <c>JMP +10</c> is.
  /// </summary>
  /// <returns>
  ///   Returns true if this is a direct branch instruction.
  /// </returns>
  abstract IsDirectBranch: bool

  /// <summary>
  /// Is this an indirect branch instruction? An indirect branch instruction
  /// is a branch instruction with a symbolic jump target. Thus, the jump
  /// target is only computed at runtime.
  /// </summary>
  /// <returns>
  /// Returns true if this is an indirect branch instruction.
  /// </returns>
  abstract IsIndirectBranch: bool

  /// <summary>
  /// Is this a conditional branch instruction?
  /// </summary>
  /// <returns>
  /// Returns true if this is a conditional branch instruction.
  /// </returns>
  abstract IsCondBranch: bool

  /// <summary>
  /// Is this a conditional branch instruction, and it jumps to the branch
  /// target when the predicate is true? For example, this method returns true
  /// for <c>JE</c> instructions of Intel, but false for <c>JNE</c>
  /// instructions.
  /// </summary>
  /// <returns>
  /// Returns true if this is a conditional branch instruction, and jumps to
  /// the target when the predicate is true.
  /// </returns>
  abstract IsCJmpOnTrue: bool

  /// <summary>
  /// Is this a call instruction?
  /// </summary>
  /// <returns>
  /// Returns true if this is a call instruction.
  /// </returns>
  abstract IsCall: bool

  /// <summary>
  /// Is this a return instruction?
  /// </summary>
  /// <returns>
  /// Returns true if this is a return instruction.
  /// </returns>
  abstract IsRET: bool

  /// <summary>
  /// Is this a push instruction? A push instruction is an instruction that
  /// pushes a value onto the stack. For example, <c>PUSH EAX</c> is a push
  /// instruction in Intel.
  /// </summary>
  /// <returns>
  /// Returns true if this is a push instruction.
  /// </returns>
  abstract IsPush: bool

  /// <summary>
  /// Is this a pop instruction? A pop instruction is an instruction that pops
  /// a value from the stack. For example, <c>POP EAX</c> is a pop instruction
  /// in Intel.
  /// </summary>
  /// <returns>
  /// Returns true if this is a pop instruction.
  /// </returns>
  abstract IsPop: bool

  /// <summary>
  /// Does this instruction involve an interrupt?
  /// </summary>
  /// <returns>
  /// Returns true if this is an interrupt instruction
  /// </returns>
  abstract IsInterrupt: bool

  /// <summary>
  /// Does this instruction exits the program execution? For example, this
  /// function returns true for the <c>HLT</c> instruction of Intel. We also
  /// consider returning from kernel mode to user mode (e.g. <c>SYSEXIT</c>
  /// instruction of Intel) as an exit.
  /// </summary>
  /// <returns>
  /// Returns true if this instruction should be at the end of the
  /// corresponding basic block.
  /// </returns>
  abstract IsExit: bool

  /// <summary>
  /// Is this a NO-OP instruction? We say an instruction is a NO-OP if it
  /// does not change the CPU state except for the program counter.
  /// </summary>
  /// <returns>
  /// Returns true if this instruction is a NO-OP.
  /// </returns>
  abstract IsNop: bool

  /// <summary>
  /// Is this a virtual instruction that represents an inlined assembly code?
  /// </summary>
  abstract IsInlinedAssembly: bool

  /// <summary>
  /// Does this instruction end a basic block? For example, this function
  /// returns true for branch instructions and exit instructions. We also
  /// consider system call instructions as a terminator. Note that this method
  /// takes the previous instruction as an argument, because instructions
  /// that are in a delay slot of a branch instruction should be considered
  /// as terminators in some architectures (e.g., MIPS).
  /// </summary>
  /// <returns>
  /// Returns true if this instruction should be at the end of the corresponding
  /// basic block.
  /// </returns>
  abstract IsTerminator: IInstruction -> bool

  /// <summary>
  /// Returns a branch target address if we can directly compute it, i.e., for
  /// direct branches.
  /// </summary>
  /// <returns>
  /// Returns true if a target address exists. Otherwise, returns false.
  /// </returns>
  abstract DirectBranchTarget: [<Out>] addr: byref<Addr> -> bool

  /// <summary>
  /// Returns a trampoline address of an indirect branch instruction if we can
  /// directly compute the address. For example, `JMP [RIP + 0x42]` is an
  /// indirect branch instruction, but we can compute the trampoline address as
  /// RIP is statically known anyways when PIC is off.
  /// </summary>
  /// <returns>
  /// Returns true if a trampoline address exists. Otherwise, returns false.
  /// </returns>
  abstract IndirectTrampolineAddr: [<Out>] addr: byref<Addr> -> bool

  /// <summary>
  /// Returns an array of addresses that this instruction directly dereferences
  /// from memory. This includes PC-relative memory accesses, such as <c>MOV
  /// [RIP + 0x42], EAX</c> in Intel. It does NOT include memory accesses
  /// through general-purpose registers (e.g., <c>MOV [RAX], EAX</c>), nor does
  /// it include instructions that only compute a memory address without
  /// dereferencing it (e.g., <c>LEA RAX, [RIP + 0x42]</c>).
  /// </summary>
  /// <returns>
  /// Returns if there exists any direct memory accesses. If there are
  /// direct memory accesses, the `addrs` parameter will be filled with the
  /// addresses of the direct memory accesses.
  /// </returns>
  abstract MemoryDereferences: [<Out>] addrs: byref<Addr[]> -> bool

  /// <summary>
  /// Return an integer immediate value of the instruction if there is one.
  /// This function will ignore floating-point immediate values.
  /// </summary>
  /// <returns>
  /// Returns true if an immediate exists. Otherwise, returns false.
  /// </returns>
  abstract Immediate: [<Out>] v: byref<int64> -> bool

  /// <summary>
  /// Returns an array of possible next instruction addresses. For branch
  /// instructions, the returned sequence includes jump target(s). For call
  /// instructions, the sequence does not include the return address (i.e., the
  /// address of the instruction following the call instruction). For regular
  /// instructions, the sequence is a singleton of the fall-through address.
  /// This function does not resolve indirect branch targets.
  /// </summary>
  abstract GetNextInstrAddrs: unit -> Addr[]

  /// <summary>
  /// Returns the interrupt number if this is an interrupt instruction.
  /// </summary>
  abstract InterruptNum: [<Out>] num: byref<int64> -> bool

  /// <summary>
  /// Lifts this instruction into a LowUIR statement array given a translation
  /// context.
  /// </summary>
  /// <returns>
  /// Returns an array of LowUIR statements.
  /// </returns>
  abstract Translate: ILowUIRBuilder -> Stmt[]

  /// <summary>
  /// Lifts this instruction into a LowUIR statement list given a translation
  /// context.
  /// </summary>
  /// <returns>
  /// Returns a list of LowUIR statements.
  /// </returns>
  abstract TranslateToList: ILowUIRBuilder -> List<Stmt>

  /// <summary>
  /// Disassembles this instruction.
  /// </summary>
  /// <param name="builder">
  /// When this parameter is given, we disassemble the instruction with the
  /// given name builder to disassemble the instruction. It can resolve symbols
  /// depending on the implementation of the builder.
  /// </param>
  /// <returns>
  /// Returns a disassembled string.
  /// </returns>
  abstract Disasm: builder: IDisasmBuilder -> string

  /// <summary>
  /// Disassembles this instruction. This function is a convenience method,
  /// which internally creates a default disassembly builder and uses it to
  /// disassemble the instruction. Hence, this is not as efficient as the
  /// previous method and should be avoided if disassembly performance is a
  /// concern.
  /// </summary>
  /// <returns>
  /// Returns a disassembled string.
  /// </returns>
  abstract Disasm: unit -> string

  /// <summary>
  /// Decomposes this instruction into AsmWords.
  /// </summary>
  /// <returns>
  /// Returns an array of AsmWords.
  /// </returns>
  abstract Decompose: builder: IDisasmBuilder -> AsmWord[]
