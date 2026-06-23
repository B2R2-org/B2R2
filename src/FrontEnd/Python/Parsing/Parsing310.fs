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

/// Implements parsing logic for Python 3.10.
module internal B2R2.FrontEnd.Python.Parsing.Parsing310

open System
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Python

let private getTable (binFile: PythonBinFile) = function
  | Op.LOAD_CONST -> binFile.Consts
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
  | Op.LOAD_METHOD -> binFile.Names
  | Op.LOAD_FAST
  | Op.STORE_FAST
  | Op.DELETE_FAST -> binFile.Varnames
  (* LOAD_CLOSURE/LOAD_DEREF/STORE_DEREF/DELETE_DEREF/LOAD_CLASSDEREF index
     into `co_cellvars ++ co_freevars`, a completely separate 0-based space
     from co_varnames -- see FreeVars' own doc comment on PyCodeObject. *)
  | Op.LOAD_CLOSURE
  | Op.LOAD_DEREF
  | Op.STORE_DEREF
  | Op.DELETE_DEREF
  | Op.LOAD_CLASSDEREF -> binFile.FreeVars
  | _ -> [||]

(* Every 3.10 instruction is a fixed 2 bytes (opcode + one oparg byte) --
   unlike 3.12+, which pads several hot opcodes with extra CACHE slots for
   adaptive specialization, 3.10 predates that entirely. *)
let private parseOperand opcode (span: ReadOnlySpan<byte>) (reader: IBinReader)
                         binFile addr extArg =
  let tbl = getTable binFile opcode
  let idx = (reader.ReadUInt8(span, 1) |> int) ||| extArg
  let cons =
    tbl |> Array.tryFind (fun (ar, _) -> ar.Min <= addr && ar.Max >= addr)
  let opr =
    match cons with
    | Some(_, c) ->
      if idx >= c.Length then failwith "Invalid instruction operand"
      else OneOperand(idx, Some c[idx])
    (* This can happen when performing linear sweep on a non-code region,
       or the opcode's arg is just a plain integer (e.g. UNPACK_SEQUENCE,
       COMPARE_OP), which getTable already reports via an empty table. *)
    | None -> OneOperand(idx, None)
  struct (opcode, opr, 2u)

let private parseInstruction (span: ReadOnlySpan<byte>) reader bf addr extArg =
  let bin = (reader: IBinReader).ReadUInt8(span, 0)
  (* Opcode of Python 3.10 *)
  match bin with
  | 0x1uy -> struct (Op.POP_TOP, NoOperand, 2u)
  | 0x2uy -> struct (Op.ROT_TWO, NoOperand, 2u)
  | 0x3uy -> struct (Op.ROT_THREE, NoOperand, 2u)
  | 0x4uy -> struct (Op.DUP_TOP, NoOperand, 2u)
  | 0x5uy -> struct (Op.DUP_TOP_TWO, NoOperand, 2u)
  | 0x6uy -> struct (Op.ROT_FOUR, NoOperand, 2u)
  | 0x9uy -> struct (Op.NOP, NoOperand, 2u)
  | 0xAuy -> struct (Op.UNARY_POSITIVE, NoOperand, 2u)
  | 0xBuy -> struct (Op.UNARY_NEGATIVE, NoOperand, 2u)
  | 0xCuy -> struct (Op.UNARY_NOT, NoOperand, 2u)
  | 0xFuy -> struct (Op.UNARY_INVERT, NoOperand, 2u)
  | 0x10uy -> struct (Op.BINARY_MATRIX_MULTIPLY, NoOperand, 2u)
  | 0x11uy -> struct (Op.INPLACE_MATRIX_MULTIPLY, NoOperand, 2u)
  | 0x13uy -> struct (Op.BINARY_POWER, NoOperand, 2u)
  | 0x14uy -> struct (Op.BINARY_MULTIPLY, NoOperand, 2u)
  | 0x16uy -> struct (Op.BINARY_MODULO, NoOperand, 2u)
  | 0x17uy -> struct (Op.BINARY_ADD, NoOperand, 2u)
  | 0x18uy -> struct (Op.BINARY_SUBTRACT, NoOperand, 2u)
  | 0x19uy -> struct (Op.BINARY_SUBSCR, NoOperand, 2u)
  | 0x1Auy -> struct (Op.BINARY_FLOOR_DIVIDE, NoOperand, 2u)
  | 0x1Buy -> struct (Op.BINARY_TRUE_DIVIDE, NoOperand, 2u)
  | 0x1Cuy -> struct (Op.INPLACE_FLOOR_DIVIDE, NoOperand, 2u)
  | 0x1Duy -> struct (Op.INPLACE_TRUE_DIVIDE, NoOperand, 2u)
  | 0x1Euy -> struct (Op.GET_LEN, NoOperand, 2u)
  | 0x1Fuy -> struct (Op.MATCH_MAPPING, NoOperand, 2u)
  | 0x20uy -> struct (Op.MATCH_SEQUENCE, NoOperand, 2u)
  | 0x21uy -> struct (Op.MATCH_KEYS, NoOperand, 2u)
  | 0x22uy -> struct (Op.COPY_DICT_WITHOUT_KEYS, NoOperand, 2u)
  | 0x31uy -> struct (Op.WITH_EXCEPT_START, NoOperand, 2u)
  | 0x32uy -> struct (Op.GET_AITER, NoOperand, 2u)
  | 0x33uy -> struct (Op.GET_ANEXT, NoOperand, 2u)
  | 0x34uy -> struct (Op.BEFORE_ASYNC_WITH, NoOperand, 2u)
  | 0x36uy -> struct (Op.END_ASYNC_FOR, NoOperand, 2u)
  | 0x37uy -> struct (Op.INPLACE_ADD, NoOperand, 2u)
  | 0x38uy -> struct (Op.INPLACE_SUBTRACT, NoOperand, 2u)
  | 0x39uy -> struct (Op.INPLACE_MULTIPLY, NoOperand, 2u)
  | 0x3Buy -> struct (Op.INPLACE_MODULO, NoOperand, 2u)
  | 0x3Cuy -> struct (Op.STORE_SUBSCR, NoOperand, 2u)
  | 0x3Duy -> struct (Op.DELETE_SUBSCR, NoOperand, 2u)
  | 0x3Euy -> struct (Op.BINARY_LSHIFT, NoOperand, 2u)
  | 0x3Fuy -> struct (Op.BINARY_RSHIFT, NoOperand, 2u)
  | 0x40uy -> struct (Op.BINARY_AND, NoOperand, 2u)
  | 0x41uy -> struct (Op.BINARY_XOR, NoOperand, 2u)
  | 0x42uy -> struct (Op.BINARY_OR, NoOperand, 2u)
  | 0x43uy -> struct (Op.INPLACE_POWER, NoOperand, 2u)
  | 0x44uy -> struct (Op.GET_ITER, NoOperand, 2u)
  | 0x45uy -> struct (Op.GET_YIELD_FROM_ITER, NoOperand, 2u)
  | 0x46uy -> struct (Op.PRINT_EXPR, NoOperand, 2u)
  | 0x47uy -> struct (Op.LOAD_BUILD_CLASS, NoOperand, 2u)
  | 0x48uy -> struct (Op.YIELD_FROM, NoOperand, 2u)
  | 0x49uy -> struct (Op.GET_AWAITABLE, NoOperand, 2u)
  | 0x4Auy -> struct (Op.LOAD_ASSERTION_ERROR, NoOperand, 2u)
  | 0x4Buy -> struct (Op.INPLACE_LSHIFT, NoOperand, 2u)
  | 0x4Cuy -> struct (Op.INPLACE_RSHIFT, NoOperand, 2u)
  | 0x4Duy -> struct (Op.INPLACE_AND, NoOperand, 2u)
  | 0x4Euy -> struct (Op.INPLACE_XOR, NoOperand, 2u)
  | 0x4Fuy -> struct (Op.INPLACE_OR, NoOperand, 2u)
  | 0x52uy -> struct (Op.LIST_TO_TUPLE, NoOperand, 2u)
  | 0x53uy -> struct (Op.RETURN_VALUE, NoOperand, 2u)
  | 0x54uy -> struct (Op.IMPORT_STAR, NoOperand, 2u)
  | 0x55uy -> struct (Op.SETUP_ANNOTATIONS, NoOperand, 2u)
  | 0x56uy -> struct (Op.YIELD_VALUE, NoOperand, 2u)
  | 0x57uy -> struct (Op.POP_BLOCK, NoOperand, 2u)
  | 0x59uy -> struct (Op.POP_EXCEPT, NoOperand, 2u)
  | 0x5Auy -> parseOperand Op.STORE_NAME span reader bf addr extArg
  | 0x5Buy -> parseOperand Op.DELETE_NAME span reader bf addr extArg
  | 0x5Cuy -> parseOperand Op.UNPACK_SEQUENCE span reader bf addr extArg
  | 0x5Duy -> parseOperand Op.FOR_ITER span reader bf addr extArg
  | 0x5Euy -> parseOperand Op.UNPACK_EX span reader bf addr extArg
  | 0x5Fuy -> parseOperand Op.STORE_ATTR span reader bf addr extArg
  | 0x60uy -> parseOperand Op.DELETE_ATTR span reader bf addr extArg
  | 0x61uy -> parseOperand Op.STORE_GLOBAL span reader bf addr extArg
  | 0x62uy -> parseOperand Op.DELETE_GLOBAL span reader bf addr extArg
  | 0x63uy -> parseOperand Op.ROT_N span reader bf addr extArg
  | 0x64uy -> parseOperand Op.LOAD_CONST span reader bf addr extArg
  | 0x65uy -> parseOperand Op.LOAD_NAME span reader bf addr extArg
  | 0x66uy -> parseOperand Op.BUILD_TUPLE span reader bf addr extArg
  | 0x67uy -> parseOperand Op.BUILD_LIST span reader bf addr extArg
  | 0x68uy -> parseOperand Op.BUILD_SET span reader bf addr extArg
  | 0x69uy -> parseOperand Op.BUILD_MAP span reader bf addr extArg
  | 0x6Auy -> parseOperand Op.LOAD_ATTR span reader bf addr extArg
  | 0x6Buy -> parseOperand Op.COMPARE_OP span reader bf addr extArg
  | 0x6Cuy -> parseOperand Op.IMPORT_NAME span reader bf addr extArg
  | 0x6Duy -> parseOperand Op.IMPORT_FROM span reader bf addr extArg
  | 0x6Euy -> parseOperand Op.JUMP_FORWARD span reader bf addr extArg
  | 0x6Fuy -> parseOperand Op.JUMP_IF_FALSE_OR_POP span reader bf addr extArg
  | 0x70uy -> parseOperand Op.JUMP_IF_TRUE_OR_POP span reader bf addr extArg
  | 0x71uy -> parseOperand Op.JUMP_ABSOLUTE span reader bf addr extArg
  | 0x72uy -> parseOperand Op.POP_JUMP_IF_FALSE span reader bf addr extArg
  | 0x73uy -> parseOperand Op.POP_JUMP_IF_TRUE span reader bf addr extArg
  | 0x74uy -> parseOperand Op.LOAD_GLOBAL span reader bf addr extArg
  | 0x75uy -> parseOperand Op.IS_OP span reader bf addr extArg
  | 0x76uy -> parseOperand Op.CONTAINS_OP span reader bf addr extArg
  | 0x77uy -> parseOperand Op.RERAISE span reader bf addr extArg
  | 0x79uy -> parseOperand Op.JUMP_IF_NOT_EXC_MATCH span reader bf addr extArg
  | 0x7Auy -> parseOperand Op.SETUP_FINALLY span reader bf addr extArg
  | 0x7Cuy -> parseOperand Op.LOAD_FAST span reader bf addr extArg
  | 0x7Duy -> parseOperand Op.STORE_FAST span reader bf addr extArg
  | 0x7Euy -> parseOperand Op.DELETE_FAST span reader bf addr extArg
  | 0x81uy -> parseOperand Op.GEN_START span reader bf addr extArg
  | 0x82uy -> parseOperand Op.RAISE_VARARGS span reader bf addr extArg
  | 0x83uy -> parseOperand Op.CALL_FUNCTION span reader bf addr extArg
  | 0x84uy -> parseOperand Op.MAKE_FUNCTION span reader bf addr extArg
  | 0x85uy -> parseOperand Op.BUILD_SLICE span reader bf addr extArg
  | 0x87uy -> parseOperand Op.LOAD_CLOSURE span reader bf addr extArg
  | 0x88uy -> parseOperand Op.LOAD_DEREF span reader bf addr extArg
  | 0x89uy -> parseOperand Op.STORE_DEREF span reader bf addr extArg
  | 0x8Auy -> parseOperand Op.DELETE_DEREF span reader bf addr extArg
  | 0x8Duy -> parseOperand Op.CALL_FUNCTION_KW span reader bf addr extArg
  | 0x8Euy -> parseOperand Op.CALL_FUNCTION_EX span reader bf addr extArg
  | 0x8Fuy -> parseOperand Op.SETUP_WITH span reader bf addr extArg
  | 0x91uy -> parseOperand Op.LIST_APPEND span reader bf addr extArg
  | 0x92uy -> parseOperand Op.SET_ADD span reader bf addr extArg
  | 0x93uy -> parseOperand Op.MAP_ADD span reader bf addr extArg
  | 0x94uy -> parseOperand Op.LOAD_CLASSDEREF span reader bf addr extArg
  | 0x98uy -> parseOperand Op.MATCH_CLASS span reader bf addr extArg
  | 0x9Auy -> parseOperand Op.SETUP_ASYNC_WITH span reader bf addr extArg
  | 0x9Buy -> parseOperand Op.FORMAT_VALUE span reader bf addr extArg
  | 0x9Cuy -> parseOperand Op.BUILD_CONST_KEY_MAP span reader bf addr extArg
  | 0x9Duy -> parseOperand Op.BUILD_STRING span reader bf addr extArg
  | 0xA0uy -> parseOperand Op.LOAD_METHOD span reader bf addr extArg
  | 0xA1uy -> parseOperand Op.CALL_METHOD span reader bf addr extArg
  | 0xA2uy -> parseOperand Op.LIST_EXTEND span reader bf addr extArg
  | 0xA3uy -> parseOperand Op.SET_UPDATE span reader bf addr extArg
  | 0xA4uy -> parseOperand Op.DICT_MERGE span reader bf addr extArg
  | 0xA5uy -> parseOperand Op.DICT_UPDATE span reader bf addr extArg
  | _ -> raise ParsingFailureException

(* Accumulate EXTENDED_ARG prefixes, then parse the real instruction.
   extArg is already shifted: each EXTENDED_ARG step does (acc ||| n) <<< 8,
   so the final opcode just ORs its own arg byte into extArg. *)
let rec private doParse lifter (span: ReadOnlySpan<byte>) (reader: IBinReader)
                        bf s c e =
  let op = reader.ReadUInt8(span, 0)
  let a = reader.ReadUInt8(span, 1) |> int
  if int op = 0x90 (* EXTENDED_ARG *) then
    doParse lifter (span.Slice 2) reader bf s (c + 2UL) ((e ||| a) <<< 8)
  else
    let struct (opc, opr, len) = parseInstruction span reader bf c e
    let total = uint32 (c - s) + len
    Instruction(s, total, opc, opr, OperationSize.regType, bf.Version, bf,
                lifter)

let parse lifter (span: ByteSpan) (reader: IBinReader) binFile addr =
  doParse lifter span reader binFile addr addr 0
