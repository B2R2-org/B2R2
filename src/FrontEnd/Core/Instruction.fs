(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

namespace B2R2.FrontEnd

open B2R2
open B2R2.BinIR.LowUIR
open System.Runtime.InteropServices

/// <summary>
///   A high-level class representing a single machine instruction in a
///   platform-independent manner. It provides useful methods for accessing
///   useful information about the instruction.
/// </summary>
[<AbstractClass>]
type Instruction (addr, numBytes, wordSize) =
  /// <summary>
  ///   The address of this instruction.
  /// </summary>
  member val Address: Addr = addr

  /// <summary>
  ///   The length of this instruction in bytes.
  /// </summary>
  member val Length: uint32 = numBytes

  /// <summary>
  ///   The word size used for translating this instruction. Some architectures
  ///   have several representations of their instruction sets depending on the
  ///   word size. For example, Intel can be represented as either x86 or x86-64
  ///   depending on the word size used. We store this information per
  ///   instruction to distinguish specific instruction sets used.
  /// </summary>
  member val WordSize: WordSize = wordSize

  /// <summary>
  ///   Is this a branch instruction? A branch instruction includes any kinds of
  ///   jump instructions, such as CALL/RET instructions, indirect/direct jump
  ///   instructions, and conditional jump instructions.
  /// </summary>
  /// <returns>
  ///   Returns true if this is a branch instruction.
  /// </returns>
  abstract member IsBranch: unit -> bool

  /// <summary>
  ///   Is this a direct branch instruction? A direct branch instruction is a
  ///   branch instruction with a concrete jump target, which is inscribed in
  ///   its operand. For example, <c>CALL ECX</c> is not a direct branch
  ///   instruction, but <c>JMP +10</c> is.
  /// </summary>
  /// <returns>
  ///   Returns true if this is a direct branch instruction.
  /// </returns>
  abstract member IsDirectBranch: unit -> bool

  /// <summary>
  ///   Is this an indirect branch instruction? An indirect branch instruction
  ///   is a branch instruction with a symbolic jump target. Thus, the jump
  ///   target is only computed at runtime.
  /// </summary>
  /// <returns>
  ///   Returns true if this is an indirect branch instruction.
  /// </returns>
  abstract member IsIndirectBranch: unit -> bool

  /// <summary>
  ///   Is this a conditional branch instruction?
  /// </summary>
  /// <returns>
  ///   Returns true if this is a conditional branch instruction.
  /// </returns>
  abstract member IsCondBranch: unit -> bool

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
  abstract member IsCJmpOnTrue: unit -> bool

  /// <summary>
  ///   Is this a call instruction?
  /// </summary>
  /// <returns>
  ///   Returns true if this is a call instruction.
  /// </returns>
  abstract member IsCall: unit -> bool

  /// <summary>
  ///   Is this a return instruction?
  /// </summary>
  /// <returns>
  ///   Returns true if this is a return instruction.
  /// </returns>
  abstract member IsRET: unit -> bool

  /// <summary>
  ///   Does this instruction involve an interrupt?
  /// </summary>
  /// <returns>
  ///   Returns true if this is an interrupt instruction
  /// </returns>
  abstract member IsInterrupt: unit -> bool

  /// <summary>
  ///   Does this instruction exit a basic block? For example, this function
  ///   returns true for the <c>HLT</c> instruction of Intel. We also consider
  ///   system call instructions as an exit instruction.
  /// </summary>
  /// <returns>
  ///   Returns true if this instruction is at the end of the corresponding
  ///   basic block.
  /// </returns>
  abstract member IsExit: unit -> bool

  /// <summary>
  ///   Is this a NO-OP instruction?
  /// </summary>
  /// <returns>
  ///   Returns true if this instruction is a NO-OP.
  /// </returns>
  abstract member IsNop: unit -> bool

  /// <summary>
  ///   Return a branch target address if we can directly compute it, i.e., for
  ///   direct branches.
  /// </summary>
  /// <returns>
  ///   Returns true if a target address exists. Otherwise, returns false.
  /// </returns>
  abstract member DirectBranchTarget: [<Out>] addr: byref<Addr> -> bool

  abstract member InterruptNum: [<Out>] num: byref<int64> -> bool

  /// <summary>
  ///   Lift this instruction into a LowUIR given a translation context.
  /// </summary>
  /// <param name="ctxt">Translation context.</param>
  /// <returns>
  ///   Returns an array of LowUIR statements.
  /// </returns>
  abstract member Translate: ctxt: TranslationContext -> Stmt []

  /// <summary>
  ///   Disassemble this instruction.
  /// </summary>
  /// <param name="showAddr">
  ///   Whether to show the instruction address in the resulting disassembly.
  /// </param>
  /// <param name="resolveSymbol">
  ///   Whether to resolve symbols while disassembling the instruction. For
  ///   example, when there is a call target, we the disassembled string will
  ///   show the target function name if this parameter is true, and the symbol
  ///   information exists.
  /// </param>
  /// <param name="fileInfo">
  ///   File information that this instruction resides in.
  /// </param>
  /// <returns>
  ///   Returns a disassembled string.
  /// </returns>
  abstract member Disasm:
    showAddr: bool
    * resolveSymbol: bool
    * fileInfo: BinFile.FileInfo
    -> string

  /// <summary>
  ///   Disassemble this instruction without resolving symbols.
  /// </summary>
  /// <returns>
  ///   Returns a disassembled string.
  /// </returns>
  abstract member Disasm: unit -> string

// vim: set tw=80 sts=2 sw=2:
