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

module internal B2R2.FrontEnd.Python.ParsingMain

open System
open B2R2
open B2R2.FrontEnd.BinLifter

let private parseOpcode (span: ReadOnlySpan<byte>) (reader: IBinReader) =
  let bin = reader.ReadUInt8 (span, 0)
  (* Opcode of Python 3.11 *)
  match bin with
  | 0x0uy -> CACHE
  | 0x1uy -> POP_TOP
  | 0x2uy -> PUSH_NULL
  | 0x9uy -> NOP
  | 0xauy -> UNARY_POSITIVE
  | 0xbuy -> UNARY_NEGATIVE
  | 0xcuy -> UNARY_NOT
  | 0xfuy -> UNARY_INVERT
  | 0x19uy -> BINARY_SUBSCR
  | 0x1euy -> GET_LEN
  | 0x1fuy -> MATCH_MAPPING
  | 0x20uy -> MATCH_SEQUENCE
  | 0x21uy -> MATCH_KEYS
  | 0x23uy -> PUSH_EXC_INFO
  | 0x24uy -> CHECK_EXC_MATCH
  | 0x25uy -> CHECK_EG_MATCH
  | 0x31uy -> WITH_EXCEPT_START
  | 0x32uy -> GET_AITER
  | 0x33uy -> GET_ANEXT
  | 0x34uy -> BEFORE_ASYNC_WITH
  | 0x35uy -> BEFORE_WITH
  | 0x36uy -> END_ASYNC_FOR
  | 0x3cuy -> STORE_SUBSCR
  | 0x3duy -> DELETE_SUBSCR
  | 0x44uy -> GET_ITER
  | 0x45uy -> GET_YIELD_FROM_ITER
  | 0x46uy -> PRINT_EXPR
  | 0x47uy -> LOAD_BUILD_CLASS
  | 0x4auy -> LOAD_ASSERTION_ERROR
  | 0x4buy -> RETURN_GENERATOR
  | 0x52uy -> LIST_TO_TUPLE
  | 0x53uy -> RETURN_VALUE
  | 0x54uy -> IMPORT_STAR
  | 0x55uy -> SETUP_ANNOTATIONS
  | 0x56uy -> YIELD_VALUE
  | 0x57uy -> ASYNC_GEN_WRAP
  | 0x58uy -> PREP_RERAISE_STAR
  | 0x59uy -> POP_EXCEPT
  | 0x5auy -> STORE_NAME
  | 0x5buy -> DELETE_NAME
  | 0x5cuy -> UNPACK_SEQUENCE
  | 0x5duy -> FOR_ITER
  | 0x5euy -> UNPACK_EX
  | 0x5fuy -> STORE_ATTR
  | 0x60uy -> DELETE_ATTR
  | 0x61uy -> STORE_GLOBAL
  | 0x62uy -> DELETE_GLOBAL
  | 0x63uy -> SWAP
  | 0x64uy -> LOAD_CONST
  | 0x65uy -> LOAD_NAME
  | 0x66uy -> BUILD_TUPLE
  | 0x67uy -> BUILD_LIST
  | 0x68uy -> BUILD_SET
  | 0x69uy -> BUILD_MAP
  | 0x6auy -> LOAD_ATTR
  | 0x6buy -> COMPARE_OP
  | 0x6cuy -> IMPORT_NAME
  | 0x6duy -> IMPORT_FROM
  | 0x6euy -> JUMP_FORWARD
  | 0x6fuy -> JUMP_IF_FALSE_OR_POP
  | 0x70uy -> JUMP_IF_TRUE_OR_POP
  | 0x72uy -> POP_JUMP_FORWARD_IF_FALSE
  | 0x73uy -> POP_JUMP_FORWARD_IF_TRUE
  | 0x74uy -> LOAD_GLOBAL
  | 0x75uy -> IS_OP
  | 0x76uy -> CONTAINS_OP
  | 0x77uy -> RERAISE
  | 0x78uy -> COPY
  | 0x7auy -> BINARY_OP
  | 0x7buy -> SEND
  | 0x7cuy -> LOAD_FAST
  | 0x7duy -> STORE_FAST
  | 0x7euy -> DELETE_FAST
  | 0x80uy -> POP_JUMP_FORWARD_IF_NOT_NONE
  | 0x81uy -> POP_JUMP_FORWARD_IF_NONE
  | 0x82uy -> RAISE_VARARGS
  | 0x83uy -> GET_AWAITABLE
  | 0x84uy -> MAKE_FUNCTION
  | 0x85uy -> BUILD_SLICE
  | 0x86uy -> JUMP_BACKWARD_NO_INTERRUPT
  | 0x87uy -> MAKE_CELL
  | 0x88uy -> LOAD_CLOSURE
  | 0x89uy -> LOAD_DEREF
  | 0x8auy -> STORE_DEREF
  | 0x8buy -> DELETE_DEREF
  | 0x8cuy -> JUMP_BACKWARD
  | 0x8euy -> CALL_FUNCTION_EX
  | 0x90uy -> EXTENDED_ARG
  | 0x91uy -> LIST_APPEND
  | 0x92uy -> SET_ADD
  | 0x93uy -> MAP_ADD
  | 0x94uy -> LOAD_CLASSDEREF
  | 0x95uy -> COPY_FREE_VARS
  | 0x97uy -> RESUME
  | 0x98uy -> MATCH_CLASS
  | 0x9buy -> FORMAT_VALUE
  | 0x9cuy -> BUILD_CONST_KEY_MAP
  | 0x9duy -> BUILD_STRING
  | 0xa0uy -> LOAD_METHOD
  | 0xa2uy -> LIST_EXTEND
  | 0xa3uy -> SET_UPDATE
  | 0xa4uy -> DICT_MERGE
  | 0xa5uy -> DICT_UPDATE
  | 0xa6uy -> PRECALL
  | 0xabuy -> CALL
  | 0xacuy -> KW_NAMES
  | 0xaduy -> POP_JUMP_BACKWARD_IF_NOT_NONE
  | 0xaeuy -> POP_JUMP_BACKWARD_IF_NONE
  | 0xafuy -> POP_JUMP_BACKWARD_IF_FALSE
  | 0xb0uy -> POP_JUMP_BACKWARD_IF_TRUE
  | _ -> raise ParsingFailureException

let parse (span: ByteSpan) (reader: IBinReader) wordSize addr =
  Utils.futureFeature ()
