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

/// What an opcode means to control flow. An opcode name almost always means
/// the same thing in every version that has it, so this is shared and the few
/// places a version genuinely differs turn on its minor number.
module internal B2R2.FrontEnd.Python.Semantics

open B2R2

let isBranch (ins: Instruction) =
  match ins.Opcode with
  | Opcode.CALL_FINALLY
  | Opcode.CONTINUE_LOOP
  | Opcode.FOR_ITER
  | Opcode.INSTRUMENTED_FOR_ITER
  | Opcode.INSTRUMENTED_JUMP_BACKWARD
  | Opcode.INSTRUMENTED_JUMP_FORWARD
  | Opcode.INSTRUMENTED_POP_JUMP_IF_FALSE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_NONE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_NOT_NONE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_TRUE
  | Opcode.JUMP
  | Opcode.JUMP_ABSOLUTE
  | Opcode.JUMP_BACKWARD
  | Opcode.JUMP_BACKWARD_NO_INTERRUPT
  | Opcode.JUMP_FORWARD
  | Opcode.JUMP_IF_FALSE
  | Opcode.JUMP_IF_FALSE_OR_POP
  | Opcode.JUMP_IF_NOT_EXC_MATCH
  | Opcode.JUMP_IF_TRUE
  | Opcode.JUMP_IF_TRUE_OR_POP
  | Opcode.JUMP_NO_INTERRUPT
  | Opcode.POP_JUMP_BACKWARD_IF_FALSE
  | Opcode.POP_JUMP_BACKWARD_IF_NONE
  | Opcode.POP_JUMP_BACKWARD_IF_NOT_NONE
  | Opcode.POP_JUMP_BACKWARD_IF_TRUE
  | Opcode.POP_JUMP_FORWARD_IF_FALSE
  | Opcode.POP_JUMP_FORWARD_IF_NONE
  | Opcode.POP_JUMP_FORWARD_IF_NOT_NONE
  | Opcode.POP_JUMP_FORWARD_IF_TRUE
  | Opcode.POP_JUMP_IF_FALSE
  | Opcode.POP_JUMP_IF_NONE
  | Opcode.POP_JUMP_IF_NOT_NONE
  | Opcode.POP_JUMP_IF_TRUE
  | Opcode.SEND -> true
  | _ -> false

/// JUMP_IF_FALSE/JUMP_IF_TRUE are 3.0's own conditional jumps, which 3.1
/// replaced with the POP_JUMP_IF_* and *_OR_POP pairs. Unlike both of those
/// they leave the value they tested on the stack, which is a difference in
/// what the branch consumes rather than in where it lands.
let isCondBranch (ins: Instruction) =
  match ins.Opcode with
  | Opcode.FOR_ITER
  | Opcode.INSTRUMENTED_FOR_ITER
  | Opcode.INSTRUMENTED_POP_JUMP_IF_FALSE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_NONE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_NOT_NONE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_TRUE
  | Opcode.JUMP_IF_FALSE
  | Opcode.JUMP_IF_FALSE_OR_POP
  | Opcode.JUMP_IF_NOT_EXC_MATCH
  | Opcode.JUMP_IF_TRUE
  | Opcode.JUMP_IF_TRUE_OR_POP
  | Opcode.POP_JUMP_BACKWARD_IF_FALSE
  | Opcode.POP_JUMP_BACKWARD_IF_NONE
  | Opcode.POP_JUMP_BACKWARD_IF_NOT_NONE
  | Opcode.POP_JUMP_BACKWARD_IF_TRUE
  | Opcode.POP_JUMP_FORWARD_IF_FALSE
  | Opcode.POP_JUMP_FORWARD_IF_NONE
  | Opcode.POP_JUMP_FORWARD_IF_NOT_NONE
  | Opcode.POP_JUMP_FORWARD_IF_TRUE
  | Opcode.POP_JUMP_IF_FALSE
  | Opcode.POP_JUMP_IF_NONE
  | Opcode.POP_JUMP_IF_NOT_NONE
  | Opcode.POP_JUMP_IF_TRUE
  | Opcode.SEND -> true
  | _ -> false

let isCJmpOnTrue (ins: Instruction) =
  match ins.Opcode with
  | Opcode.INSTRUMENTED_POP_JUMP_IF_TRUE
  | Opcode.JUMP_IF_TRUE
  | Opcode.JUMP_IF_TRUE_OR_POP
  | Opcode.POP_JUMP_BACKWARD_IF_TRUE
  | Opcode.POP_JUMP_FORWARD_IF_TRUE
  | Opcode.POP_JUMP_IF_TRUE -> true
  | _ -> false

let isCall (ins: Instruction) =
  match ins.Opcode with
  | Opcode.CALL
  | Opcode.CALL_FUNCTION
  | Opcode.CALL_FUNCTION_EX
  | Opcode.CALL_FUNCTION_KW
  | Opcode.CALL_FUNCTION_VAR
  | Opcode.CALL_FUNCTION_VAR_KW
  | Opcode.CALL_KW
  | Opcode.CALL_METHOD
  | Opcode.INSTRUMENTED_CALL
  | Opcode.INSTRUMENTED_CALL_FUNCTION_EX
  | Opcode.INSTRUMENTED_CALL_KW -> true
  | _ -> false

let isRET (ins: Instruction) =
  match ins.Opcode with
  | Opcode.INSTRUMENTED_RETURN_CONST
  | Opcode.INSTRUMENTED_RETURN_VALUE
  | Opcode.RETURN_CONST
  | Opcode.RETURN_VALUE -> true
  | _ -> false

/// RERAISE counts from 3.10 on, where it is the opcode a re-raise ends at.
/// Before that a re-raise goes through END_FINALLY, whose effect follows from
/// the block stack rather than from the opcode, so it is not a static exit.
let isExit (ins: Instruction) =
  match ins.Opcode with
  | Opcode.INSTRUMENTED_RETURN_CONST
  | Opcode.INSTRUMENTED_RETURN_VALUE
  | Opcode.INTERPRETER_EXIT
  | Opcode.RAISE_VARARGS
  | Opcode.RERAISE
  | Opcode.RETURN_CONST
  | Opcode.RETURN_VALUE -> true
  | _ -> false

let isNop (ins: Instruction) = ins.Opcode = Opcode.NOP

/// Whether the given bits of the argument are set, which is how an opcode
/// carries a flag alongside the index it names.
let private argBits mask (ins: Instruction) =
  match ins.Operands with
  | OneOperand(idx, _) -> (idx &&& mask) <> 0
  | _ -> false

/// Whether namei's low bit is set, which is the push-NULL / is-method flag.
/// LOAD_GLOBAL gains it in 3.11, the attribute lookups in 3.12, and
/// IMPORT_NAME its own two-bit field in 3.15; before that no opcode has one.
let hasFlag (ins: Instruction) =
  match ins.Opcode with
  | Opcode.LOAD_GLOBAL -> ins.Minor >= 11 && argBits 1 ins
  | Opcode.LOAD_ATTR
  | Opcode.LOAD_SUPER_ATTR
  | Opcode.INSTRUMENTED_LOAD_SUPER_ATTR -> ins.Minor >= 12 && argBits 1 ins
  | Opcode.IMPORT_NAME -> ins.Minor >= 15 && argBits 3 ins
  | _ -> false

/// Whether a super() lookup carried explicit (class, obj) arguments, which
/// namei's second bit says. Only 3.12 and later have an opcode for it.
let superHasExplicitArgs (ins: Instruction) =
  match ins.Opcode with
  | Opcode.LOAD_SUPER_ATTR
  | Opcode.INSTRUMENTED_LOAD_SUPER_ATTR -> argBits 2 ins
  | _ -> false

/// Which end a jump measures its argument from.
type private TargetKind =
  /// The instruction after this one, forwards.
  | Forward
  /// The instruction after this one, backwards.
  | Backward
  /// The start of the code object this instruction sits in.
  | FromCodeObject
  /// Nothing at all, which is what 3.11 alone does for JUMP_IF_*_OR_POP.
  /// Its own lifting measures from the code object like every other version,
  /// so the two disagree; left as it stands rather than changed here.
  | FromZero

let private targetKind (ins: Instruction) =
  match ins.Opcode with
  | Opcode.JUMP_FORWARD
  | Opcode.FOR_ITER
  | Opcode.SEND
  | Opcode.POP_JUMP_FORWARD_IF_FALSE
  | Opcode.POP_JUMP_FORWARD_IF_NONE
  | Opcode.POP_JUMP_FORWARD_IF_NOT_NONE
  | Opcode.POP_JUMP_FORWARD_IF_TRUE
  | Opcode.POP_JUMP_IF_NONE
  | Opcode.POP_JUMP_IF_NOT_NONE
  | Opcode.CALL_FINALLY
  | Opcode.JUMP_IF_FALSE
  | Opcode.JUMP_IF_TRUE
  | Opcode.INSTRUMENTED_FOR_ITER
  | Opcode.INSTRUMENTED_JUMP_FORWARD
  | Opcode.INSTRUMENTED_POP_JUMP_IF_FALSE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_NONE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_NOT_NONE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_TRUE ->
    Forward
  | Opcode.JUMP_BACKWARD
  | Opcode.JUMP_BACKWARD_NO_INTERRUPT
  | Opcode.POP_JUMP_BACKWARD_IF_FALSE
  | Opcode.POP_JUMP_BACKWARD_IF_NONE
  | Opcode.POP_JUMP_BACKWARD_IF_NOT_NONE
  | Opcode.POP_JUMP_BACKWARD_IF_TRUE
  | Opcode.INSTRUMENTED_JUMP_BACKWARD ->
    Backward
  | Opcode.JUMP_ABSOLUTE
  | Opcode.CONTINUE_LOOP
  | Opcode.JUMP_IF_NOT_EXC_MATCH ->
    FromCodeObject
  (* 3.12 gave these two a forward-relative target, where every version up to
     3.10 measured them from the code object's own start. *)
  | Opcode.POP_JUMP_IF_FALSE
  | Opcode.POP_JUMP_IF_TRUE ->
    if ins.Minor >= 12 then Forward else FromCodeObject
  | Opcode.JUMP_IF_FALSE_OR_POP
  | Opcode.JUMP_IF_TRUE_OR_POP ->
    if ins.Minor = 11 then FromZero else FromCodeObject
  | op ->
    failwithf "Invalid opcode for branch target: %A" op

/// Where a branch lands, given the fall-through address and the raw argument.
/// Up to 3.9 the argument counts bytes; 3.10 made it count instructions, so
/// the same number means twice the distance from there on.
let branchTarget (ins: Instruction) (ftAddr: Addr) (n: int) =
  let n = uint64 n * (if ins.Minor >= 10 then 2UL else 1UL)
  match targetKind ins with
  | Forward -> ftAddr + n
  | Backward -> ftAddr - n
  | FromCodeObject -> LifterHelpers.codeObjectBase ins.BinFile ins.Address + n
  | FromZero -> n
