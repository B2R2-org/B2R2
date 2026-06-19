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

/// Implements parsing logic for Python 3.12.
module internal B2R2.FrontEnd.Python.Parsing.Parsing312

open System
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Python

(* LOAD_GLOBAL, LOAD_ATTR, and LOAD_SUPER_ATTR encode a flag in the low bit
   of arg; the actual name index is arg >> 1. *)
let private getIndex opcode (rawArg: int) =
  match opcode with
  | Op.LOAD_GLOBAL
  | Op.LOAD_ATTR
  | Op.LOAD_SUPER_ATTR
  | Op.INSTRUMENTED_LOAD_SUPER_ATTR -> rawArg >>> 1
  | _ -> rawArg

let private getTable (binFile: PythonBinFile) = function
  | Op.LOAD_CONST
  | Op.RETURN_CONST
  | Op.KW_NAMES
  | Op.INSTRUMENTED_RETURN_CONST -> binFile.Consts
  | Op.LOAD_NAME
  | Op.STORE_NAME
  | Op.DELETE_NAME
  | Op.STORE_ATTR
  | Op.DELETE_ATTR
  | Op.STORE_GLOBAL
  | Op.DELETE_GLOBAL
  | Op.LOAD_ATTR
  | Op.IMPORT_NAME
  | Op.IMPORT_FROM
  | Op.LOAD_GLOBAL
  | Op.LOAD_SUPER_ATTR
  | Op.LOAD_FROM_DICT_OR_GLOBALS
  | Op.INSTRUMENTED_LOAD_SUPER_ATTR -> binFile.Names
  | Op.LOAD_FAST
  | Op.STORE_FAST
  | Op.DELETE_FAST
  | Op.LOAD_FAST_CHECK
  | Op.LOAD_FAST_AND_CLEAR
  | Op.MAKE_CELL
  | Op.LOAD_CLOSURE
  | Op.LOAD_DEREF
  | Op.STORE_DEREF
  | Op.DELETE_DEREF
  | Op.LOAD_FROM_DICT_OR_DEREF -> binFile.Varnames
  | _ -> [||]

let private parseOperand opcode (span: ReadOnlySpan<byte>) (reader: IBinReader)
                         binFile addr instrLen extArg =
  let tbl = getTable binFile opcode
  let rawArg = (reader.ReadUInt8(span, 1) |> int) ||| extArg
  let idx = getIndex opcode rawArg
  let cons =
    tbl
    |> Array.tryFind (fun (ar, _) -> ar.Min <= addr && ar.Max >= addr)
  let opr =
    match cons with
    | Some(_, c) -> OneOperand(idx, Some <| c[idx])
    | None -> OneOperand(idx, None)
  struct (opcode, opr, instrLen)

let private parseInstruction (span: ReadOnlySpan<byte>) reader bf addr extArg =
  let bin = (reader: IBinReader).ReadUInt8(span, 0)
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
  | 0x5Auy -> parseOperand Op.STORE_NAME span reader bf addr 2u extArg
  | 0x5Buy -> parseOperand Op.DELETE_NAME span reader bf addr 2u extArg
  | 0x5Cuy -> parseOperand Op.UNPACK_SEQUENCE span reader bf addr 2u extArg
  | 0x5Duy -> parseOperand Op.FOR_ITER span reader bf addr 2u extArg
  | 0x5Euy -> parseOperand Op.UNPACK_EX span reader bf addr 2u extArg
  | 0x5Fuy -> parseOperand Op.STORE_ATTR span reader bf addr 10u extArg
  | 0x60uy -> parseOperand Op.DELETE_ATTR span reader bf addr 2u extArg
  | 0x61uy -> parseOperand Op.STORE_GLOBAL span reader bf addr 2u extArg
  | 0x62uy -> parseOperand Op.DELETE_GLOBAL span reader bf addr 2u extArg
  | 0x63uy -> parseOperand Op.SWAP span reader bf addr 2u extArg
  | 0x64uy -> parseOperand Op.LOAD_CONST span reader bf addr 2u extArg
  | 0x65uy -> parseOperand Op.LOAD_NAME span reader bf addr 2u extArg
  | 0x66uy -> parseOperand Op.BUILD_TUPLE span reader bf addr 2u extArg
  | 0x67uy -> parseOperand Op.BUILD_LIST span reader bf addr 2u extArg
  | 0x68uy -> parseOperand Op.BUILD_SET span reader bf addr 2u extArg
  | 0x69uy -> parseOperand Op.BUILD_MAP span reader bf addr 2u extArg
  | 0x6Auy -> parseOperand Op.LOAD_ATTR span reader bf addr 20u extArg
  | 0x6Buy -> parseOperand Op.COMPARE_OP span reader bf addr 2u extArg
  | 0x6Cuy -> parseOperand Op.IMPORT_NAME span reader bf addr 2u extArg
  | 0x6Duy -> parseOperand Op.IMPORT_FROM span reader bf addr 2u extArg
  | 0x6Euy -> parseOperand Op.JUMP_FORWARD span reader bf addr 2u extArg
  | 0x72uy -> parseOperand Op.POP_JUMP_IF_FALSE span reader bf addr 2u extArg
  | 0x73uy -> parseOperand Op.POP_JUMP_IF_TRUE span reader bf addr 2u extArg
  | 0x74uy -> parseOperand Op.LOAD_GLOBAL span reader bf addr 10u extArg
  | 0x75uy -> parseOperand Op.IS_OP span reader bf addr 2u extArg
  | 0x76uy -> parseOperand Op.CONTAINS_OP span reader bf addr 2u extArg
  | 0x77uy -> parseOperand Op.RERAISE span reader bf addr 2u extArg
  | 0x78uy -> parseOperand Op.COPY span reader bf addr 2u extArg
  | 0x79uy -> parseOperand Op.RETURN_CONST span reader bf addr 2u extArg
  | 0x7Auy -> parseOperand Op.BINARY_OP span reader bf addr 4u extArg
  | 0x7Buy -> parseOperand Op.SEND span reader bf addr 2u extArg
  | 0x7Cuy -> parseOperand Op.LOAD_FAST span reader bf addr 2u extArg
  | 0x7Duy -> parseOperand Op.STORE_FAST span reader bf addr 2u extArg
  | 0x7Euy -> parseOperand Op.DELETE_FAST span reader bf addr 2u extArg
  | 0x7Fuy -> parseOperand Op.LOAD_FAST_CHECK span reader bf addr 2u extArg
  | 0x80uy ->
    parseOperand Op.POP_JUMP_IF_NOT_NONE span reader bf addr 2u extArg
  | 0x81uy -> parseOperand Op.POP_JUMP_IF_NONE span reader bf addr 2u extArg
  | 0x82uy -> parseOperand Op.RAISE_VARARGS span reader bf addr 2u extArg
  | 0x83uy -> parseOperand Op.GET_AWAITABLE span reader bf addr 2u extArg
  | 0x84uy -> parseOperand Op.MAKE_FUNCTION span reader bf addr 2u extArg
  | 0x85uy -> parseOperand Op.BUILD_SLICE span reader bf addr 2u extArg
  | 0x86uy ->
    parseOperand Op.JUMP_BACKWARD_NO_INTERRUPT span reader bf addr 2u extArg
  | 0x87uy -> parseOperand Op.MAKE_CELL span reader bf addr 2u extArg
  | 0x88uy -> parseOperand Op.LOAD_CLOSURE span reader bf addr 2u extArg
  | 0x89uy -> parseOperand Op.LOAD_DEREF span reader bf addr 2u extArg
  | 0x8Auy -> parseOperand Op.STORE_DEREF span reader bf addr 2u extArg
  | 0x8Buy -> parseOperand Op.DELETE_DEREF span reader bf addr 2u extArg
  | 0x8Cuy -> parseOperand Op.JUMP_BACKWARD span reader bf addr 2u extArg
  | 0x8Duy -> parseOperand Op.LOAD_SUPER_ATTR span reader bf addr 2u extArg
  | 0x8Euy -> parseOperand Op.CALL_FUNCTION_EX span reader bf addr 2u extArg
  | 0x8Fuy ->
    parseOperand Op.LOAD_FAST_AND_CLEAR span reader bf addr 2u extArg
  | 0x91uy -> parseOperand Op.LIST_APPEND span reader bf addr 2u extArg
  | 0x92uy -> parseOperand Op.SET_ADD span reader bf addr 2u extArg
  | 0x93uy -> parseOperand Op.MAP_ADD span reader bf addr 2u extArg
  | 0x95uy -> parseOperand Op.COPY_FREE_VARS span reader bf addr 2u extArg
  | 0x96uy -> parseOperand Op.YIELD_VALUE span reader bf addr 2u extArg
  | 0x97uy -> parseOperand Op.RESUME span reader bf addr 2u extArg
  | 0x98uy -> parseOperand Op.MATCH_CLASS span reader bf addr 2u extArg
  | 0x9Buy -> parseOperand Op.FORMAT_VALUE span reader bf addr 2u extArg
  | 0x9Cuy ->
    parseOperand Op.BUILD_CONST_KEY_MAP span reader bf addr 2u extArg
  | 0x9Duy -> parseOperand Op.BUILD_STRING span reader bf addr 2u extArg
  | 0xA2uy -> parseOperand Op.LIST_EXTEND span reader bf addr 2u extArg
  | 0xA3uy -> parseOperand Op.SET_UPDATE span reader bf addr 2u extArg
  | 0xA4uy -> parseOperand Op.DICT_MERGE span reader bf addr 2u extArg
  | 0xA5uy -> parseOperand Op.DICT_UPDATE span reader bf addr 2u extArg
  | 0xABuy -> parseOperand Op.CALL span reader bf addr 8u extArg
  | 0xACuy -> parseOperand Op.KW_NAMES span reader bf addr 2u extArg
  | 0xADuy -> parseOperand Op.CALL_INTRINSIC_1 span reader bf addr 2u extArg
  | 0xAEuy -> parseOperand Op.CALL_INTRINSIC_2 span reader bf addr 2u extArg
  | 0xAFuy ->
    parseOperand Op.LOAD_FROM_DICT_OR_GLOBALS span reader bf addr 2u extArg
  | 0xB0uy ->
    parseOperand Op.LOAD_FROM_DICT_OR_DEREF span reader bf addr 2u extArg
  | 0xEDuy ->
    parseOperand Op.INSTRUMENTED_LOAD_SUPER_ATTR span reader bf addr 2u extArg
  | 0xEEuy ->
    parseOperand Op.INSTRUMENTED_POP_JUMP_IF_NONE span reader bf addr 2u extArg
  | 0xEFuy ->
    parseOperand
      Op.INSTRUMENTED_POP_JUMP_IF_NOT_NONE span reader bf addr 2u extArg
  | 0xF0uy -> parseOperand Op.INSTRUMENTED_RESUME span reader bf addr 2u extArg
  | 0xF1uy -> parseOperand Op.INSTRUMENTED_CALL span reader bf addr 2u extArg
  | 0xF2uy ->
    parseOperand Op.INSTRUMENTED_RETURN_VALUE span reader bf addr 2u extArg
  | 0xF3uy ->
    parseOperand Op.INSTRUMENTED_YIELD_VALUE span reader bf addr 2u extArg
  | 0xF4uy ->
    parseOperand
      Op.INSTRUMENTED_CALL_FUNCTION_EX span reader bf addr 2u extArg
  | 0xF5uy ->
    parseOperand Op.INSTRUMENTED_JUMP_FORWARD span reader bf addr 2u extArg
  | 0xF6uy ->
    parseOperand Op.INSTRUMENTED_JUMP_BACKWARD span reader bf addr 2u extArg
  | 0xF7uy ->
    parseOperand Op.INSTRUMENTED_RETURN_CONST span reader bf addr 2u extArg
  | 0xF8uy ->
    parseOperand Op.INSTRUMENTED_FOR_ITER span reader bf addr 2u extArg
  | 0xF9uy ->
    parseOperand
      Op.INSTRUMENTED_POP_JUMP_IF_FALSE span reader bf addr 2u extArg
  | 0xFAuy ->
    parseOperand
      Op.INSTRUMENTED_POP_JUMP_IF_TRUE span reader bf addr 2u extArg
  | 0xFBuy ->
    parseOperand Op.INSTRUMENTED_END_FOR span reader bf addr 2u extArg
  | 0xFCuy ->
    parseOperand Op.INSTRUMENTED_END_SEND span reader bf addr 2u extArg
  | 0xFDuy ->
    parseOperand Op.INSTRUMENTED_INSTRUCTION span reader bf addr 2u extArg
  | 0xFEuy -> parseOperand Op.INSTRUMENTED_LINE span reader bf addr 2u extArg
  | _ -> raise ParsingFailureException

(* Accumulate EXTENDED_ARG prefixes, then parse the real instruction.
   extArg is already shifted: each EXTENDED_ARG step does (acc ||| n) <<< 8,
   so the final opcode just ORs its own arg byte into extArg. *)
let rec private doParse lifter (span: ReadOnlySpan<byte>) (reader: IBinReader)
                        bf s c e =
  let op = reader.ReadUInt8(span, 0)
  let a = reader.ReadUInt8(span, 1) |> int
  if int op = int Op.EXTENDED_ARG then
    doParse lifter (span.Slice 2) reader bf s (c + 2UL) ((e ||| a) <<< 8)
  else
    let struct (opc, opr, len) = parseInstruction span reader bf c e
    let total = uint32 (c - s) + len
    Instruction(s, total, opc, opr, 32<rt>, lifter)

let parse lifter (span: ByteSpan) (reader: IBinReader) binFile addr =
  doParse lifter span reader binFile addr addr 0
