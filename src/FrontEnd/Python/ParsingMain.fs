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
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Python

let private getTable (binFile: PythonBinFile) = function
  | Op.LOAD_CONST | Op.RETURN_CONST -> binFile.Consts
  | Op.STORE_NAME | Op.IMPORT_NAME -> binFile.Names
  | Op.STORE_FAST | Op.LOAD_FAST -> binFile.Varnames
  | o -> printfn "Unsupported Opcode %A" o; [||]

let private parseOperand opcode (span: ReadOnlySpan<byte>) (reader: IBinReader)
  (binFile: PythonBinFile) addr instrLen =
  let tbl = getTable binFile opcode
  let idx = reader.ReadUInt8 (span, 1) |> int
  let cons =
    Array.tryFind (fun (ar, _) ->
      AddrRange.GetMin ar <= addr && AddrRange.GetMax ar >= addr) tbl
  let opr =
    match cons with
    | Some (_, c) -> OneOperand (idx, Some <| c[idx])
    | None -> OneOperand (idx, None)
  struct (opcode, opr, instrLen)

let private parseInstruction (span: ReadOnlySpan<byte>) (reader: IBinReader)
  (bFile: PythonBinFile) addr =
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
  | 0x5Auy -> parseOperand Op.STORE_NAME span reader bFile addr 2u
  | 0x5Buy -> parseOperand Op.DELETE_NAME span reader bFile addr 2u
  | 0x5Cuy -> parseOperand Op.UNPACK_SEQUENCE span reader bFile addr 2u
  | 0x5Duy -> parseOperand Op.FOR_ITER span reader bFile addr 2u
  | 0x5Euy -> parseOperand Op.UNPACK_EX span reader bFile addr 2u
  | 0x5Fuy -> parseOperand Op.STORE_ATTR span reader bFile addr 10u
  | 0x60uy -> parseOperand Op.DELETE_ATTR span reader bFile addr 2u
  | 0x61uy -> parseOperand Op.STORE_GLOBAL span reader bFile addr 2u
  | 0x62uy -> parseOperand Op.DELETE_GLOBAL span reader bFile addr 2u
  | 0x63uy -> parseOperand Op.SWAP span reader bFile addr 2u
  | 0x64uy -> parseOperand Op.LOAD_CONST span reader bFile addr 2u
  | 0x65uy -> parseOperand Op.LOAD_NAME span reader bFile addr 2u
  | 0x66uy -> parseOperand Op.BUILD_TUPLE span reader bFile addr 2u
  | 0x67uy -> parseOperand Op.BUILD_LIST span reader bFile addr 2u
  | 0x68uy -> parseOperand Op.BUILD_SET span reader bFile addr 2u
  | 0x69uy -> parseOperand Op.BUILD_MAP span reader bFile addr 2u
  | 0x6Auy -> parseOperand Op.LOAD_ATTR span reader bFile addr 20u
  | 0x6Buy -> parseOperand Op.COMPARE_OP span reader bFile addr 2u
  | 0x6Cuy -> parseOperand Op.IMPORT_NAME span reader bFile addr 2u
  | 0x6Duy -> parseOperand Op.IMPORT_FROM span reader bFile addr 2u
  | 0x6Euy -> parseOperand Op.JUMP_FORWARD span reader bFile addr 2u
  | 0x72uy -> parseOperand Op.POP_JUMP_IF_FALSE span reader bFile addr 2u
  | 0x73uy -> parseOperand Op.POP_JUMP_IF_TRUE span reader bFile addr 2u
  | 0x74uy -> parseOperand Op.LOAD_GLOBAL span reader bFile addr 10u
  | 0x75uy -> parseOperand Op.IS_OP span reader bFile addr 2u
  | 0x76uy -> parseOperand Op.CONTAINS_OP span reader bFile addr 2u
  | 0x77uy -> parseOperand Op.RERAISE span reader bFile addr 2u
  | 0x78uy -> parseOperand Op.COPY span reader bFile addr 2u
  | 0x79uy -> parseOperand Op.RETURN_CONST span reader bFile addr 2u
  | 0x7Auy -> parseOperand Op.BINARY_OP span reader bFile addr 4u
  | 0x7Buy -> parseOperand Op.SEND span reader bFile addr 2u
  | 0x7Cuy -> parseOperand Op.LOAD_FAST span reader bFile addr 2u
  | 0x7Duy -> parseOperand Op.STORE_FAST span reader bFile addr 2u
  | 0x7Euy -> parseOperand Op.DELETE_FAST span reader bFile addr 2u
  | 0x7Fuy -> parseOperand Op.LOAD_FAST_CHECK span reader bFile addr 2u
  | 0x80uy -> parseOperand Op.POP_JUMP_IF_NOT_NONE span reader bFile addr 2u
  | 0x81uy -> parseOperand Op.POP_JUMP_IF_NONE span reader bFile addr 2u
  | 0x82uy -> parseOperand Op.RAISE_VARARGS span reader bFile addr 2u
  | 0x83uy -> parseOperand Op.GET_AWAITABLE span reader bFile addr 2u
  | 0x84uy -> parseOperand Op.MAKE_FUNCTION span reader bFile addr 2u
  | 0x85uy -> parseOperand Op.BUILD_SLICE span reader bFile addr 2u
  | 0x86uy ->
    parseOperand Op.JUMP_BACKWARD_NO_INTERRUPT span reader bFile addr 2u
  | 0x87uy -> parseOperand Op.MAKE_CELL span reader bFile addr 2u
  | 0x88uy -> parseOperand Op.LOAD_CLOSURE span reader bFile addr 2u
  | 0x89uy -> parseOperand Op.LOAD_DEREF span reader bFile addr 2u
  | 0x8Auy -> parseOperand Op.STORE_DEREF span reader bFile addr 2u
  | 0x8Buy -> parseOperand Op.DELETE_DEREF span reader bFile addr 2u
  | 0x8Cuy -> parseOperand Op.JUMP_BACKWARD span reader bFile addr 2u
  | 0x8Duy -> parseOperand Op.LOAD_SUPER_ATTR span reader bFile addr 2u
  | 0x8Euy -> parseOperand Op.CALL_FUNCTION_EX span reader bFile addr 2u
  | 0x8Fuy -> parseOperand Op.LOAD_FAST_AND_CLEAR span reader bFile addr 2u
  | 0x90uy -> parseOperand Op.EXTENDED_ARG span reader bFile addr 2u
  | 0x91uy -> parseOperand Op.LIST_APPEND span reader bFile addr 2u
  | 0x92uy -> parseOperand Op.SET_ADD span reader bFile addr 2u
  | 0x93uy -> parseOperand Op.MAP_ADD span reader bFile addr 2u
  | 0x95uy -> parseOperand Op.COPY_FREE_VARS span reader bFile addr 2u
  | 0x96uy -> parseOperand Op.YIELD_VALUE span reader bFile addr 2u
  | 0x97uy -> parseOperand Op.RESUME span reader bFile addr 2u
  | 0x98uy -> parseOperand Op.MATCH_CLASS span reader bFile addr 2u
  | 0x9Buy -> parseOperand Op.FORMAT_VALUE span reader bFile addr 2u
  | 0x9Cuy -> parseOperand Op.BUILD_CONST_KEY_MAP span reader bFile addr 2u
  | 0x9Duy -> parseOperand Op.BUILD_STRING span reader bFile addr 2u
  | 0xA2uy -> parseOperand Op.LIST_EXTEND span reader bFile addr 2u
  | 0xA3uy -> parseOperand Op.SET_UPDATE span reader bFile addr 2u
  | 0xA4uy -> parseOperand Op.DICT_MERGE span reader bFile addr 2u
  | 0xA5uy -> parseOperand Op.DICT_UPDATE span reader bFile addr 2u
  | 0xABuy -> parseOperand Op.CALL span reader bFile addr 8u
  | 0xACuy -> parseOperand Op.KW_NAMES span reader bFile addr 2u
  | 0xADuy -> parseOperand Op.CALL_INTRINSIC_1 span reader bFile addr 2u
  | 0xAEuy -> parseOperand Op.CALL_INTRINSIC_2 span reader bFile addr 2u
  | 0xAFuy ->
    parseOperand Op.LOAD_FROM_DICT_OR_GLOBALS span reader bFile addr 2u
  | 0xB0uy -> parseOperand Op.LOAD_FROM_DICT_OR_DEREF span reader bFile addr 2u
  | 0xEDuy ->
    parseOperand Op.INSTRUMENTED_LOAD_SUPER_ATTR span reader bFile addr 2u
  | 0xEEuy ->
    parseOperand Op.INSTRUMENTED_POP_JUMP_IF_NONE span reader bFile addr 2u
  | 0xEFuy ->
    parseOperand Op.INSTRUMENTED_POP_JUMP_IF_NOT_NONE span reader bFile addr 2u
  | 0xF0uy -> parseOperand Op.INSTRUMENTED_RESUME span reader bFile addr 2u
  | 0xF1uy -> parseOperand Op.INSTRUMENTED_CALL span reader bFile addr 2u
  | 0xF2uy ->
    parseOperand Op.INSTRUMENTED_RETURN_VALUE span reader bFile addr 2u
  | 0xF3uy -> parseOperand Op.INSTRUMENTED_YIELD_VALUE span reader bFile addr 2u
  | 0xF4uy ->
    parseOperand Op.INSTRUMENTED_CALL_FUNCTION_EX span reader bFile addr 2u
  | 0xF5uy ->
    parseOperand Op.INSTRUMENTED_JUMP_FORWARD span reader bFile addr 2u
  | 0xF6uy ->
    parseOperand Op.INSTRUMENTED_JUMP_BACKWARD span reader bFile addr 2u
  | 0xF7uy ->
    parseOperand Op.INSTRUMENTED_RETURN_CONST span reader bFile addr 2u
  | 0xF8uy -> parseOperand Op.INSTRUMENTED_FOR_ITER span reader bFile addr 2u
  | 0xF9uy ->
    parseOperand Op.INSTRUMENTED_POP_JUMP_IF_FALSE span reader bFile addr 2u
  | 0xFAuy ->
    parseOperand Op.INSTRUMENTED_POP_JUMP_IF_TRUE span reader bFile addr 2u
  | 0xFBuy -> parseOperand Op.INSTRUMENTED_END_FOR span reader bFile addr 2u
  | 0xFCuy -> parseOperand Op.INSTRUMENTED_END_SEND span reader bFile addr 2u
  | 0xFDuy -> parseOperand Op.INSTRUMENTED_INSTRUCTION span reader bFile addr 2u
  | 0xFEuy -> parseOperand Op.INSTRUMENTED_LINE span reader bFile addr 2u
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

let parse lifter (span: ByteSpan) (reader: IBinReader) binFile addr =
  let struct (opcode, operands, instrLen) =
    parseInstruction span reader binFile addr
  Instruction (addr, instrLen, opcode, operands, 32<rt>, lifter)
