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

module internal B2R2.FrontEnd.Python.Python310.Semantics

open B2R2
open B2R2.FrontEnd.Python

let inline private opcodeOf (ins: Instruction): Opcode =
  LanguagePrimitives.EnumOfValue ins.Opcode

let isBranch (ins: Instruction) =
  match opcodeOf ins with
  | Opcode.JUMP_FORWARD
  | Opcode.JUMP_ABSOLUTE
  | Opcode.POP_JUMP_IF_TRUE
  | Opcode.POP_JUMP_IF_FALSE
  | Opcode.FOR_ITER
  | Opcode.JUMP_IF_TRUE_OR_POP
  | Opcode.JUMP_IF_FALSE_OR_POP
  | Opcode.JUMP_IF_NOT_EXC_MATCH -> true
  | _ -> false

let isCondBranch (ins: Instruction) =
  match opcodeOf ins with
  | Opcode.POP_JUMP_IF_FALSE
  | Opcode.POP_JUMP_IF_TRUE
  | Opcode.FOR_ITER
  | Opcode.JUMP_IF_TRUE_OR_POP
  | Opcode.JUMP_IF_FALSE_OR_POP
  | Opcode.JUMP_IF_NOT_EXC_MATCH -> true
  | _ -> false

let isCJmpOnTrue (ins: Instruction) =
  match opcodeOf ins with
  | Opcode.POP_JUMP_IF_TRUE
  | Opcode.JUMP_IF_TRUE_OR_POP -> true
  | _ -> false

let isCall (ins: Instruction) =
  match opcodeOf ins with
  | Opcode.CALL_FUNCTION
  | Opcode.CALL_FUNCTION_KW
  | Opcode.CALL_METHOD -> true
  | _ -> false

let isRET (ins: Instruction) =
  match opcodeOf ins with
  | Opcode.RETURN_VALUE -> true
  | _ -> false

let isExit (ins: Instruction) =
  match opcodeOf ins with
  | Opcode.RETURN_VALUE
  | Opcode.RAISE_VARARGS
  | Opcode.RERAISE -> true
  | _ -> false

(* namei's low bit is a push-NULL / is-method flag from 3.11 on. *)
let hasFlag (ins: Instruction) =
  false

let superHasExplicitArgs (ins: Instruction) =
  false

(* Jump opcodes encode their target as a WORD offset (oparg * 2). *)
let branchTarget (ins: Instruction) (ftAddr: Addr) (n: int) =
  let codeObjectBase (addr: Addr) =
    ins.BinFile.Consts
    |> Array.tryFind (fun (ar, _) -> ar.Min <= addr && ar.Max >= addr)
    |> function
      | Some(ar, _) -> ar.Min
      | None -> failwithf "Cannot find the code object containing 0x%x" addr
  let n = uint64 n
  match opcodeOf ins with
  | Opcode.JUMP_FORWARD
  | Opcode.FOR_ITER -> ftAddr + 2UL * n
  | Opcode.JUMP_ABSOLUTE
  | Opcode.POP_JUMP_IF_TRUE
  | Opcode.POP_JUMP_IF_FALSE
  | Opcode.JUMP_IF_TRUE_OR_POP
  | Opcode.JUMP_IF_FALSE_OR_POP
  | Opcode.JUMP_IF_NOT_EXC_MATCH -> codeObjectBase ins.Address + 2UL * n
  | op -> failwithf "Invalid opcode for branch target: %A" op
