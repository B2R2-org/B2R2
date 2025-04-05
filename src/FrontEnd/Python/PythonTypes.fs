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

open System.Runtime.CompilerServices
open B2R2

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.Python.Tests")>]
do ()

/// <summary>
///   Python opcodes.
/// </summary>
type Opcode =
  | CACHE
  | POP_TOP
  | PUSH_NULL
  | NOP
  | UNARY_POSITIVE
  | UNARY_NEGATIVE
  | UNARY_NOT
  | UNARY_INVERT
  | BINARY_SUBSCR
  | GET_LEN
  | MATCH_MAPPING
  | MATCH_SEQUENCE
  | MATCH_KEYS
  | PUSH_EXC_INFO
  | CHECK_EXC_MATCH
  | CHECK_EG_MATCH
  | WITH_EXCEPT_START
  | GET_AITER
  | GET_ANEXT
  | BEFORE_ASYNC_WITH
  | BEFORE_WITH
  | END_ASYNC_FOR
  | STORE_SUBSCR
  | DELETE_SUBSCR
  | GET_ITER
  | GET_YIELD_FROM_ITER
  | PRINT_EXPR
  | LOAD_BUILD_CLASS
  | LOAD_ASSERTION_ERROR
  | RETURN_GENERATOR
  | LIST_TO_TUPLE
  | RETURN_VALUE
  | IMPORT_STAR
  | SETUP_ANNOTATIONS
  | YIELD_VALUE
  | ASYNC_GEN_WRAP
  | PREP_RERAISE_STAR
  | POP_EXCEPT
  | STORE_NAME
  | DELETE_NAME
  | UNPACK_SEQUENCE
  | FOR_ITER
  | UNPACK_EX
  | STORE_ATTR
  | DELETE_ATTR
  | STORE_GLOBAL
  | DELETE_GLOBAL
  | SWAP
  | LOAD_CONST
  | LOAD_NAME
  | BUILD_TUPLE
  | BUILD_LIST
  | BUILD_SET
  | BUILD_MAP
  | LOAD_ATTR
  | COMPARE_OP
  | IMPORT_NAME
  | IMPORT_FROM
  | JUMP_FORWARD
  | JUMP_IF_FALSE_OR_POP
  | JUMP_IF_TRUE_OR_POP
  | POP_JUMP_FORWARD_IF_FALSE
  | POP_JUMP_FORWARD_IF_TRUE
  | LOAD_GLOBAL
  | IS_OP
  | CONTAINS_OP
  | RERAISE
  | COPY
  | BINARY_OP
  | SEND
  | LOAD_FAST
  | STORE_FAST
  | DELETE_FAST
  | POP_JUMP_FORWARD_IF_NOT_NONE
  | POP_JUMP_FORWARD_IF_NONE
  | RAISE_VARARGS
  | GET_AWAITABLE
  | MAKE_FUNCTION
  | BUILD_SLICE
  | JUMP_BACKWARD_NO_INTERRUPT
  | MAKE_CELL
  | LOAD_CLOSURE
  | LOAD_DEREF
  | STORE_DEREF
  | DELETE_DEREF
  | JUMP_BACKWARD
  | CALL_FUNCTION_EX
  | EXTENDED_ARG
  | LIST_APPEND
  | SET_ADD
  | MAP_ADD
  | LOAD_CLASSDEREF
  | COPY_FREE_VARS
  | RESUME
  | MATCH_CLASS
  | FORMAT_VALUE
  | BUILD_CONST_KEY_MAP
  | BUILD_STRING
  | LOAD_METHOD
  | LIST_EXTEND
  | SET_UPDATE
  | DICT_MERGE
  | DICT_UPDATE
  | PRECALL
  | CALL
  | KW_NAMES
  | POP_JUMP_BACKWARD_IF_NOT_NONE
  | POP_JUMP_BACKWARD_IF_NONE
  | POP_JUMP_BACKWARD_IF_FALSE
  | POP_JUMP_BACKWARD_IF_TRUE

type internal Op = Opcode

type Operand =
  | MyOpr // FIXME

type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand

/// Basic information obtained by parsing a Python instruction.
[<NoComparison; CustomEquality>]
type InsInfo = {
  /// Address.
  Address: Addr
  /// Instruction length.
  NumBytes: uint32
  /// Opcode.
  Opcode: Opcode
  /// Operands.
  Operands: Operands
  /// Operation Size.
  OperationSize: RegType
}
with
  override this.GetHashCode () =
    hash (this.Address,
          this.NumBytes,
          this.Opcode,
          this.Operands,
          this.OperationSize)

  override this.Equals (i) =
    match i with
    | :? InsInfo as i ->
      i.Address = this.Address
      && i.NumBytes = this.NumBytes
      && i.Opcode = this.Opcode
      && i.Operands = this.Operands
      && i.OperationSize = this.OperationSize
    | _ -> false
