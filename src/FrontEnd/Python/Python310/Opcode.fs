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

namespace B2R2.FrontEnd.Python.Python310

/// <summary>
/// Represents a Python 3.10 opcode. Values are CPython 3.10's own
/// opcode numbers, so a byte decodes to a case by a plain cast and
/// this table is checkable directly against CPython's opcode module.
/// </summary>
type Opcode =
  | POP_TOP = 0x1
  | ROT_TWO = 0x2
  | ROT_THREE = 0x3
  | DUP_TOP = 0x4
  | DUP_TOP_TWO = 0x5
  | ROT_FOUR = 0x6
  | NOP = 0x9
  | UNARY_POSITIVE = 0xA
  | UNARY_NEGATIVE = 0xB
  | UNARY_NOT = 0xC
  | UNARY_INVERT = 0xF
  | BINARY_MATRIX_MULTIPLY = 0x10
  | INPLACE_MATRIX_MULTIPLY = 0x11
  | BINARY_POWER = 0x13
  | BINARY_MULTIPLY = 0x14
  | BINARY_MODULO = 0x16
  | BINARY_ADD = 0x17
  | BINARY_SUBTRACT = 0x18
  | BINARY_SUBSCR = 0x19
  | BINARY_FLOOR_DIVIDE = 0x1A
  | BINARY_TRUE_DIVIDE = 0x1B
  | INPLACE_FLOOR_DIVIDE = 0x1C
  | INPLACE_TRUE_DIVIDE = 0x1D
  | GET_LEN = 0x1E
  | MATCH_MAPPING = 0x1F
  | MATCH_SEQUENCE = 0x20
  | MATCH_KEYS = 0x21
  | COPY_DICT_WITHOUT_KEYS = 0x22
  | WITH_EXCEPT_START = 0x31
  | GET_AITER = 0x32
  | GET_ANEXT = 0x33
  | BEFORE_ASYNC_WITH = 0x34
  | END_ASYNC_FOR = 0x36
  | INPLACE_ADD = 0x37
  | INPLACE_SUBTRACT = 0x38
  | INPLACE_MULTIPLY = 0x39
  | INPLACE_MODULO = 0x3B
  | STORE_SUBSCR = 0x3C
  | DELETE_SUBSCR = 0x3D
  | BINARY_LSHIFT = 0x3E
  | BINARY_RSHIFT = 0x3F
  | BINARY_AND = 0x40
  | BINARY_XOR = 0x41
  | BINARY_OR = 0x42
  | INPLACE_POWER = 0x43
  | GET_ITER = 0x44
  | GET_YIELD_FROM_ITER = 0x45
  | PRINT_EXPR = 0x46
  | LOAD_BUILD_CLASS = 0x47
  | YIELD_FROM = 0x48
  | GET_AWAITABLE = 0x49
  | LOAD_ASSERTION_ERROR = 0x4A
  | INPLACE_LSHIFT = 0x4B
  | INPLACE_RSHIFT = 0x4C
  | INPLACE_AND = 0x4D
  | INPLACE_XOR = 0x4E
  | INPLACE_OR = 0x4F
  | LIST_TO_TUPLE = 0x52
  | RETURN_VALUE = 0x53
  | IMPORT_STAR = 0x54
  | SETUP_ANNOTATIONS = 0x55
  | YIELD_VALUE = 0x56
  | POP_BLOCK = 0x57
  | POP_EXCEPT = 0x59
  | STORE_NAME = 0x5A
  | DELETE_NAME = 0x5B
  | UNPACK_SEQUENCE = 0x5C
  | FOR_ITER = 0x5D
  | UNPACK_EX = 0x5E
  | STORE_ATTR = 0x5F
  | DELETE_ATTR = 0x60
  | STORE_GLOBAL = 0x61
  | DELETE_GLOBAL = 0x62
  | ROT_N = 0x63
  | LOAD_CONST = 0x64
  | LOAD_NAME = 0x65
  | BUILD_TUPLE = 0x66
  | BUILD_LIST = 0x67
  | BUILD_SET = 0x68
  | BUILD_MAP = 0x69
  | LOAD_ATTR = 0x6A
  | COMPARE_OP = 0x6B
  | IMPORT_NAME = 0x6C
  | IMPORT_FROM = 0x6D
  | JUMP_FORWARD = 0x6E
  | JUMP_IF_FALSE_OR_POP = 0x6F
  | JUMP_IF_TRUE_OR_POP = 0x70
  | JUMP_ABSOLUTE = 0x71
  | POP_JUMP_IF_FALSE = 0x72
  | POP_JUMP_IF_TRUE = 0x73
  | LOAD_GLOBAL = 0x74
  | IS_OP = 0x75
  | CONTAINS_OP = 0x76
  | RERAISE = 0x77
  | JUMP_IF_NOT_EXC_MATCH = 0x79
  | SETUP_FINALLY = 0x7A
  | LOAD_FAST = 0x7C
  | STORE_FAST = 0x7D
  | DELETE_FAST = 0x7E
  | GEN_START = 0x81
  | RAISE_VARARGS = 0x82
  | CALL_FUNCTION = 0x83
  | MAKE_FUNCTION = 0x84
  | BUILD_SLICE = 0x85
  | LOAD_CLOSURE = 0x87
  | LOAD_DEREF = 0x88
  | STORE_DEREF = 0x89
  | DELETE_DEREF = 0x8A
  | CALL_FUNCTION_KW = 0x8D
  | CALL_FUNCTION_EX = 0x8E
  | SETUP_WITH = 0x8F
  | EXTENDED_ARG = 0x90
  | LIST_APPEND = 0x91
  | SET_ADD = 0x92
  | MAP_ADD = 0x93
  | LOAD_CLASSDEREF = 0x94
  | MATCH_CLASS = 0x98
  | SETUP_ASYNC_WITH = 0x9A
  | FORMAT_VALUE = 0x9B
  | BUILD_CONST_KEY_MAP = 0x9C
  | BUILD_STRING = 0x9D
  | LOAD_METHOD = 0xA0
  | CALL_METHOD = 0xA1
  | LIST_EXTEND = 0xA2
  | SET_UPDATE = 0xA3
  | DICT_MERGE = 0xA4
  | DICT_UPDATE = 0xA5

/// Provides per-opcode facts that come straight from CPython's own
/// tables for 3.10.
module Opcode =
  /// Number of inline cache entries following the opcode. Each one
  /// occupies two bytes, so an instruction is 2 + 2 * this.
  let inlineCacheCount = function
    | _ -> 0

  /// Total encoded size of the opcode in bytes, inline caches
  /// included. EXTENDED_ARG prefixes are counted by the caller.
  let length opcode = 2u + 2u * uint32 (inlineCacheCount opcode)

  /// Whether the opcode takes an operand.
  let hasOperand = function
    | Opcode.BUILD_CONST_KEY_MAP
    | Opcode.BUILD_LIST
    | Opcode.BUILD_MAP
    | Opcode.BUILD_SET
    | Opcode.BUILD_SLICE
    | Opcode.BUILD_STRING
    | Opcode.BUILD_TUPLE
    | Opcode.CALL_FUNCTION
    | Opcode.CALL_FUNCTION_EX
    | Opcode.CALL_FUNCTION_KW
    | Opcode.CALL_METHOD
    | Opcode.COMPARE_OP
    | Opcode.CONTAINS_OP
    | Opcode.DELETE_ATTR
    | Opcode.DELETE_DEREF
    | Opcode.DELETE_FAST
    | Opcode.DELETE_GLOBAL
    | Opcode.DELETE_NAME
    | Opcode.DICT_MERGE
    | Opcode.DICT_UPDATE
    | Opcode.EXTENDED_ARG
    | Opcode.FORMAT_VALUE
    | Opcode.FOR_ITER
    | Opcode.GEN_START
    | Opcode.IMPORT_FROM
    | Opcode.IMPORT_NAME
    | Opcode.IS_OP
    | Opcode.JUMP_ABSOLUTE
    | Opcode.JUMP_FORWARD
    | Opcode.JUMP_IF_FALSE_OR_POP
    | Opcode.JUMP_IF_NOT_EXC_MATCH
    | Opcode.JUMP_IF_TRUE_OR_POP
    | Opcode.LIST_APPEND
    | Opcode.LIST_EXTEND
    | Opcode.LOAD_ATTR
    | Opcode.LOAD_CLASSDEREF
    | Opcode.LOAD_CLOSURE
    | Opcode.LOAD_CONST
    | Opcode.LOAD_DEREF
    | Opcode.LOAD_FAST
    | Opcode.LOAD_GLOBAL
    | Opcode.LOAD_METHOD
    | Opcode.LOAD_NAME
    | Opcode.MAKE_FUNCTION
    | Opcode.MAP_ADD
    | Opcode.MATCH_CLASS
    | Opcode.POP_JUMP_IF_FALSE
    | Opcode.POP_JUMP_IF_TRUE
    | Opcode.RAISE_VARARGS
    | Opcode.RERAISE
    | Opcode.ROT_N
    | Opcode.SETUP_ASYNC_WITH
    | Opcode.SETUP_FINALLY
    | Opcode.SETUP_WITH
    | Opcode.SET_ADD
    | Opcode.SET_UPDATE
    | Opcode.STORE_ATTR
    | Opcode.STORE_DEREF
    | Opcode.STORE_FAST
    | Opcode.STORE_GLOBAL
    | Opcode.STORE_NAME
    | Opcode.UNPACK_EX
    | Opcode.UNPACK_SEQUENCE
      -> true
    | _ -> false
