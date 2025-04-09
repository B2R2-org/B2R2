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

type Op = Opcode

let private parseOperands (span: ReadOnlySpan<byte>) (reader: IBinReader) =
  OneOperand (int (reader.ReadUInt8 (span, 1)))

let private parseInstruction (span: ReadOnlySpan<byte>) (reader: IBinReader) =
  let bin = reader.ReadUInt8 (span, 0)
  (* Opcode of Python 3.12 *)
  match bin with
  | 0x0uy -> struct (Op.CACHE, NoOperand, 2u)
  | 0x1uy -> struct (Op.POP_TOP, NoOperand, 2u)
  | 0x2uy -> struct (Op.PUSH_NULL, NoOperand, 2u)
  | 0x3uy -> struct (Op.INTERPRETER_EXIT, NoOperand, 2u)
  | 0x4uy -> struct (Op.END_FOR, NoOperand, 2u)
  | 0x5uy -> struct (Op.END_SEND, NoOperand, 2u)
  | 0x9uy -> struct (Op.NOP, NoOperand, 2u)
  | 0xBuy -> struct (Op.UNARY_NEGATIVE, NoOperand, 2u)
  | 0xCuy -> struct (Op.UNARY_NOT, NoOperand, 2u)
  | 0xFuy -> struct (Op.UNARY_INVERT, NoOperand, 2u)
  | 0x11uy -> struct (Op.RESERVED, NoOperand, 2u)
  | 0x19uy -> struct (Op.BINARY_SUBSCR, NoOperand, 2u)
  | 0x1Auy -> struct (Op.BINARY_SLICE, NoOperand, 2u)
  | 0x1Buy -> struct (Op.STORE_SLICE, NoOperand, 2u)
  | 0x1Euy -> struct (Op.GET_LEN, NoOperand, 2u)
  | 0x1Fuy -> struct (Op.MATCH_MAPPING, NoOperand, 2u)
  | 0x20uy -> struct (Op.MATCH_SEQUENCE, NoOperand, 2u)
  | 0x21uy -> struct (Op.MATCH_KEYS, NoOperand, 2u)
  | 0x23uy -> struct (Op.PUSH_EXC_INFO, NoOperand, 2u)
  | 0x24uy -> struct (Op.CHECK_EXC_MATCH, NoOperand, 2u)
  | 0x25uy -> struct (Op.CHECK_EG_MATCH, NoOperand, 2u)
  | 0x31uy -> struct (Op.WITH_EXCEPT_START, NoOperand, 2u)
  | 0x32uy -> struct (Op.GET_AITER, NoOperand, 2u)
  | 0x33uy -> struct (Op.GET_ANEXT, NoOperand, 2u)
  | 0x34uy -> struct (Op.BEFORE_ASYNC_WITH, NoOperand, 2u)
  | 0x35uy -> struct (Op.BEFORE_WITH, NoOperand, 2u)
  | 0x36uy -> struct (Op.END_ASYNC_FOR, NoOperand, 2u)
  | 0x37uy -> struct (Op.CLEANUP_THROW, NoOperand, 2u)
  | 0x3Cuy -> struct (Op.STORE_SUBSCR, NoOperand, 2u)
  | 0x3Duy -> struct (Op.DELETE_SUBSCR, NoOperand, 2u)
  | 0x44uy -> struct (Op.GET_ITER, NoOperand, 2u)
  | 0x45uy -> struct (Op.GET_YIELD_FROM_ITER, NoOperand, 2u)
  | 0x47uy -> struct (Op.LOAD_BUILD_CLASS, NoOperand, 2u)
  | 0x4Auy -> struct (Op.LOAD_ASSERTION_ERROR, NoOperand, 2u)
  | 0x4Buy -> struct (Op.RETURN_GENERATOR, NoOperand, 2u)
  | 0x53uy -> struct (Op.RETURN_VALUE, NoOperand, 2u)
  | 0x55uy -> struct (Op.SETUP_ANNOTATIONS, NoOperand, 2u)
  | 0x57uy -> struct (Op.LOAD_LOCALS, NoOperand, 2u)
  | 0x59uy -> struct (Op.POP_EXCEPT, NoOperand, 2u)
  | 0x5Auy -> struct (Op.STORE_NAME, parseOperands span reader, 2u)
  | 0x5Buy -> struct (Op.DELETE_NAME, parseOperands span reader, 2u)
  | 0x5Cuy -> struct (Op.UNPACK_SEQUENCE, parseOperands span reader, 2u)
  | 0x5Duy -> struct (Op.FOR_ITER, parseOperands span reader, 2u)
  | 0x5Euy -> struct (Op.UNPACK_EX, parseOperands span reader, 2u)
  | 0x5Fuy -> struct (Op.STORE_ATTR, parseOperands span reader, 2u)
  | 0x60uy -> struct (Op.DELETE_ATTR, parseOperands span reader, 2u)
  | 0x61uy -> struct (Op.STORE_GLOBAL, parseOperands span reader, 2u)
  | 0x62uy -> struct (Op.DELETE_GLOBAL, parseOperands span reader, 2u)
  | 0x63uy -> struct (Op.SWAP, parseOperands span reader, 2u)
  | 0x64uy -> struct (Op.LOAD_CONST, parseOperands span reader, 2u)
  | 0x65uy -> struct (Op.LOAD_NAME, parseOperands span reader, 2u)
  | 0x66uy -> struct (Op.BUILD_TUPLE, parseOperands span reader, 2u)
  | 0x67uy -> struct (Op.BUILD_LIST, parseOperands span reader, 2u)
  | 0x68uy -> struct (Op.BUILD_SET, parseOperands span reader, 2u)
  | 0x69uy -> struct (Op.BUILD_MAP, parseOperands span reader, 2u)
  | 0x6Auy -> struct (Op.LOAD_ATTR, parseOperands span reader, 2u)
  | 0x6Buy -> struct (Op.COMPARE_OP, parseOperands span reader, 2u)
  | 0x6Cuy -> struct (Op.IMPORT_NAME, parseOperands span reader, 2u)
  | 0x6Duy -> struct (Op.IMPORT_FROM, parseOperands span reader, 2u)
  | 0x6Euy -> struct (Op.JUMP_FORWARD, parseOperands span reader, 2u)
  | 0x72uy -> struct (Op.POP_JUMP_IF_FALSE, parseOperands span reader, 2u)
  | 0x73uy -> struct (Op.POP_JUMP_IF_TRUE, parseOperands span reader, 2u)
  | 0x74uy -> struct (Op.LOAD_GLOBAL, parseOperands span reader, 10u)
  | 0x75uy -> struct (Op.IS_OP, parseOperands span reader, 2u)
  | 0x76uy -> struct (Op.CONTAINS_OP, parseOperands span reader, 2u)
  | 0x77uy -> struct (Op.RERAISE, parseOperands span reader, 2u)
  | 0x78uy -> struct (Op.COPY, parseOperands span reader, 2u)
  | 0x79uy -> struct (Op.RETURN_CONST, parseOperands span reader, 2u)
  | 0x7Auy -> struct (Op.BINARY_OP, parseOperands span reader, 4u)
  | 0x7Buy -> struct (Op.SEND, parseOperands span reader, 2u)
  | 0x7Cuy -> struct (Op.LOAD_FAST, parseOperands span reader, 2u)
  | 0x7Duy -> struct (Op.STORE_FAST, parseOperands span reader, 2u)
  | 0x7Euy -> struct (Op.DELETE_FAST, parseOperands span reader, 2u)
  | 0x7Fuy -> struct (Op.LOAD_FAST_CHECK, parseOperands span reader, 2u)
  | 0x80uy -> struct (Op.POP_JUMP_IF_NOT_NONE, parseOperands span reader, 2u)
  | 0x81uy -> struct (Op.POP_JUMP_IF_NONE, parseOperands span reader, 2u)
  | 0x82uy -> struct (Op.RAISE_VARARGS, parseOperands span reader, 2u)
  | 0x83uy -> struct (Op.GET_AWAITABLE, parseOperands span reader, 2u)
  | 0x84uy -> struct (Op.MAKE_FUNCTION, parseOperands span reader, 2u)
  | 0x85uy -> struct (Op.BUILD_SLICE, parseOperands span reader, 2u)
  | 0x86uy ->
    struct (Op.JUMP_BACKWARD_NO_INTERRUPT, parseOperands span reader, 2u)
  | 0x87uy -> struct (Op.MAKE_CELL, parseOperands span reader, 2u)
  | 0x88uy -> struct (Op.LOAD_CLOSURE, parseOperands span reader, 2u)
  | 0x89uy -> struct (Op.LOAD_DEREF, parseOperands span reader, 2u)
  | 0x8Auy -> struct (Op.STORE_DEREF, parseOperands span reader, 2u)
  | 0x8Buy -> struct (Op.DELETE_DEREF, parseOperands span reader, 2u)
  | 0x8Cuy -> struct (Op.JUMP_BACKWARD, parseOperands span reader, 2u)
  | 0x8Duy -> struct (Op.LOAD_SUPER_ATTR, parseOperands span reader, 2u)
  | 0x8Euy -> struct (Op.CALL_FUNCTION_EX, parseOperands span reader, 2u)
  | 0x8Fuy -> struct (Op.LOAD_FAST_AND_CLEAR, parseOperands span reader, 2u)
  | 0x90uy -> struct (Op.EXTENDED_ARG, parseOperands span reader, 2u)
  | 0x91uy -> struct (Op.LIST_APPEND, parseOperands span reader, 2u)
  | 0x92uy -> struct (Op.SET_ADD, parseOperands span reader, 2u)
  | 0x93uy -> struct (Op.MAP_ADD, parseOperands span reader, 2u)
  | 0x95uy -> struct (Op.COPY_FREE_VARS, parseOperands span reader, 2u)
  | 0x96uy -> struct (Op.YIELD_VALUE, parseOperands span reader, 2u)
  | 0x97uy -> struct (Op.RESUME, parseOperands span reader, 2u)
  | 0x98uy -> struct (Op.MATCH_CLASS, parseOperands span reader, 2u)
  | 0x9Buy -> struct (Op.FORMAT_VALUE, parseOperands span reader, 2u)
  | 0x9Cuy -> struct (Op.BUILD_CONST_KEY_MAP, parseOperands span reader, 2u)
  | 0x9Duy -> struct (Op.BUILD_STRING, parseOperands span reader, 2u)
  | 0xA2uy -> struct (Op.LIST_EXTEND, parseOperands span reader, 2u)
  | 0xA3uy -> struct (Op.SET_UPDATE, parseOperands span reader, 2u)
  | 0xA4uy -> struct (Op.DICT_MERGE, parseOperands span reader, 2u)
  | 0xA5uy -> struct (Op.DICT_UPDATE, parseOperands span reader, 2u)
  | 0xABuy -> struct (Op.CALL, parseOperands span reader, 8u)
  | 0xACuy -> struct (Op.KW_NAMES, parseOperands span reader, 2u)
  | 0xADuy -> struct (Op.CALL_INTRINSIC_1, parseOperands span reader, 2u)
  | 0xAEuy -> struct (Op.CALL_INTRINSIC_2, parseOperands span reader, 2u)
  | 0xAFuy ->
    struct (Op.LOAD_FROM_DICT_OR_GLOBALS, parseOperands span reader, 2u)
  | 0xB0uy -> struct (Op.LOAD_FROM_DICT_OR_DEREF, parseOperands span reader, 2u)
  | 0xEDuy ->
    struct (Op.INSTRUMENTED_LOAD_SUPER_ATTR, parseOperands span reader, 2u)
  | 0xEEuy ->
    struct (Op.INSTRUMENTED_POP_JUMP_IF_NONE, parseOperands span reader, 2u)
  | 0xEFuy ->
    struct (Op.INSTRUMENTED_POP_JUMP_IF_NOT_NONE, parseOperands span reader, 2u)
  | 0xF0uy -> struct (Op.INSTRUMENTED_RESUME, parseOperands span reader, 2u)
  | 0xF1uy -> struct (Op.INSTRUMENTED_CALL, parseOperands span reader, 2u)
  | 0xF2uy -> (Op.INSTRUMENTED_RETURN_VALUE, parseOperands span reader, 2u)
  | 0xF3uy ->
    struct (Op.INSTRUMENTED_YIELD_VALUE, parseOperands span reader, 2u)
  | 0xF4uy ->
    struct (Op.INSTRUMENTED_CALL_FUNCTION_EX, parseOperands span reader, 2u)
  | 0xF5uy ->
    struct (Op.INSTRUMENTED_JUMP_FORWARD, parseOperands span reader, 2u)
  | 0xF6uy ->
    struct (Op.INSTRUMENTED_JUMP_BACKWARD, parseOperands span reader, 2u)
  | 0xF7uy ->
    struct (Op.INSTRUMENTED_RETURN_CONST, parseOperands span reader, 2u)
  | 0xF8uy -> struct (Op.INSTRUMENTED_FOR_ITER, parseOperands span reader, 2u)
  | 0xF9uy -> (Op.INSTRUMENTED_POP_JUMP_IF_FALSE, parseOperands span reader, 2u)
  | 0xFAuy ->
    struct (Op.INSTRUMENTED_POP_JUMP_IF_TRUE, parseOperands span reader, 2u)
  | 0xFBuy -> struct (Op.INSTRUMENTED_END_FOR, parseOperands span reader, 2u)
  | 0xFCuy -> struct (Op.INSTRUMENTED_END_SEND, parseOperands span reader, 2u)
  | 0xFDuy ->
    struct (Op.INSTRUMENTED_INSTRUCTION, parseOperands span reader, 2u)
  | 0xFEuy -> struct (Op.INSTRUMENTED_LINE, parseOperands span reader, 2u)
  (*
  | 0x100uy -> struct (Op.SETUP_FINALLY, NoOperand, 2u)
  | 0x101uy -> struct (Op.SETUP_CLEANUP, NoOperand, 2u)
  | 0x102uy -> struct (Op.SETUP_WITH, NoOperand, 2u)
  | 0x103uy -> struct (Op.POP_BLOCK, NoOperand, 2u)
  | 0x104uy -> struct (Op.JUMP, NoOperand, 2u)
  | 0x105uy -> struct (Op.JUMP_NO_INTERRUPT, NoOperand, 2u)
  | 0x106uy -> struct (Op.LOAD_METHOD, NoOperand, 2u)
  | 0x107uy -> struct (Op.LOAD_SUPER_METHOD, NoOperand, 2u)
  | 0x108uy -> struct (Op.LOAD_ZERO_SUPER_METHOD, NoOperand, 2u)
  | 0x109uy -> struct (Op.LOAD_ZERO_SUPER_ATTR, NoOperand, 2u)
  | 0x10Auy -> struct (Op.STORE_FAST_MAYBE_NULL, NoOperand, 2u)
  *)
  | _ -> raise ParsingFailureException

let parse lifter (span: ByteSpan) (reader: IBinReader) addr =
  let struct (opcode, operands, instrLen) = parseInstruction span reader
  Instruction (addr, instrLen, opcode, operands, 32<rt>, lifter)
