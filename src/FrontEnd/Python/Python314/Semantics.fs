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

module internal B2R2.FrontEnd.Python.Python314.Semantics

open B2R2
open B2R2.FrontEnd.Python

let inline private opcodeOf (ins: Instruction): Opcode =
  LanguagePrimitives.EnumOfValue ins.Opcode

let isBranch (ins: Instruction) =
  match opcodeOf ins with
  | Opcode.JUMP_FORWARD
  | Opcode.JUMP_BACKWARD
  | Opcode.JUMP_BACKWARD_NO_INTERRUPT
  | Opcode.JUMP
  | Opcode.JUMP_NO_INTERRUPT
  | Opcode.POP_JUMP_IF_TRUE
  | Opcode.POP_JUMP_IF_FALSE
  | Opcode.POP_JUMP_IF_NONE
  | Opcode.POP_JUMP_IF_NOT_NONE
  | Opcode.FOR_ITER
  | Opcode.SEND
  | Opcode.INSTRUMENTED_JUMP_FORWARD
  | Opcode.INSTRUMENTED_JUMP_BACKWARD
  | Opcode.INSTRUMENTED_FOR_ITER
  | Opcode.INSTRUMENTED_POP_JUMP_IF_FALSE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_TRUE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_NONE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_NOT_NONE -> true
  | _ -> false

let isCondBranch (ins: Instruction) =
  match opcodeOf ins with
  | Opcode.POP_JUMP_IF_FALSE
  | Opcode.POP_JUMP_IF_TRUE
  | Opcode.POP_JUMP_IF_NONE
  | Opcode.POP_JUMP_IF_NOT_NONE
  | Opcode.FOR_ITER
  | Opcode.SEND
  | Opcode.INSTRUMENTED_FOR_ITER
  | Opcode.INSTRUMENTED_POP_JUMP_IF_FALSE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_TRUE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_NONE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_NOT_NONE -> true
  | _ -> false

let isCJmpOnTrue (ins: Instruction) =
  match opcodeOf ins with
  | Opcode.POP_JUMP_IF_TRUE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_TRUE -> true
  | _ -> false

let isCall (ins: Instruction) =
  match opcodeOf ins with
  | Opcode.CALL
  | Opcode.INSTRUMENTED_CALL -> true
  | _ -> false

let isRET (ins: Instruction) =
  match opcodeOf ins with
  | Opcode.RETURN_VALUE
  | Opcode.INSTRUMENTED_RETURN_VALUE
  | _ -> false

let isExit (ins: Instruction) =
  match opcodeOf ins with
  | Opcode.RETURN_VALUE
  | Opcode.RAISE_VARARGS
  | Opcode.RERAISE
  | Opcode.INTERPRETER_EXIT
  | Opcode.INSTRUMENTED_RETURN_VALUE
  | _ -> false

(* namei's low bit is a push-NULL / is-method flag from 3.11 on. *)
let hasFlag (ins: Instruction) =
  match opcodeOf ins with
  | Opcode.LOAD_GLOBAL
  | Opcode.LOAD_ATTR
  | Opcode.LOAD_SUPER_ATTR
  | Opcode.INSTRUMENTED_LOAD_SUPER_ATTR ->
    match ins.Operands with
    | OneOperand(idx, _) -> (idx &&& 1) = 1
    | _ -> false
  | _ ->
    false

let superHasExplicitArgs (ins: Instruction) =
  match opcodeOf ins with
  | Opcode.LOAD_SUPER_ATTR
  | Opcode.INSTRUMENTED_LOAD_SUPER_ATTR ->
    match ins.Operands with
    | OneOperand(idx, _) -> (idx &&& 2) = 2
    | _ -> false
  | _ ->
    false

(* Jump opcodes encode their target as a WORD offset (oparg * 2). *)
let branchTarget (ins: Instruction) (ftAddr: Addr) (n: int) =
  let n = uint64 n
  match opcodeOf ins with
  | Opcode.JUMP_FORWARD
  | Opcode.POP_JUMP_IF_TRUE
  | Opcode.POP_JUMP_IF_FALSE
  | Opcode.POP_JUMP_IF_NONE
  | Opcode.POP_JUMP_IF_NOT_NONE
  | Opcode.FOR_ITER
  | Opcode.SEND
  | Opcode.INSTRUMENTED_JUMP_FORWARD
  | Opcode.INSTRUMENTED_FOR_ITER
  | Opcode.INSTRUMENTED_POP_JUMP_IF_TRUE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_FALSE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_NONE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_NOT_NONE -> ftAddr + 2UL * n
  | Opcode.JUMP_BACKWARD
  | Opcode.JUMP_BACKWARD_NO_INTERRUPT
  | Opcode.INSTRUMENTED_JUMP_BACKWARD -> ftAddr - 2UL * n
  | op -> failwithf "Invalid opcode for branch target: %A" op
