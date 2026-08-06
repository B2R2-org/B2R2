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

namespace B2R2.FrontEnd.Python.Python311

/// <summary>
/// Represents a Python 3.11 opcode. Values are CPython 3.11's own
/// opcode numbers, so a byte decodes to a case by a plain cast and
/// this table is checkable directly against CPython's opcode module.
/// </summary>
type Opcode =
  | CACHE = 0x0
  | POP_TOP = 0x1
  | PUSH_NULL = 0x2
  | NOP = 0x9
  | UNARY_POSITIVE = 0xA
  | UNARY_NEGATIVE = 0xB
  | UNARY_NOT = 0xC
  | UNARY_INVERT = 0xF
  | BINARY_SUBSCR = 0x19
  | GET_LEN = 0x1E
  | MATCH_MAPPING = 0x1F
  | MATCH_SEQUENCE = 0x20
  | MATCH_KEYS = 0x21
  | PUSH_EXC_INFO = 0x23
  | CHECK_EXC_MATCH = 0x24
  | CHECK_EG_MATCH = 0x25
  | WITH_EXCEPT_START = 0x31
  | GET_AITER = 0x32
  | GET_ANEXT = 0x33
  | BEFORE_ASYNC_WITH = 0x34
  | BEFORE_WITH = 0x35
  | END_ASYNC_FOR = 0x36
  | STORE_SUBSCR = 0x3C
  | DELETE_SUBSCR = 0x3D
  | GET_ITER = 0x44
  | GET_YIELD_FROM_ITER = 0x45
  | PRINT_EXPR = 0x46
  | LOAD_BUILD_CLASS = 0x47
  | LOAD_ASSERTION_ERROR = 0x4A
  | RETURN_GENERATOR = 0x4B
  | LIST_TO_TUPLE = 0x52
  | RETURN_VALUE = 0x53
  | IMPORT_STAR = 0x54
  | SETUP_ANNOTATIONS = 0x55
  | YIELD_VALUE = 0x56
  | ASYNC_GEN_WRAP = 0x57
  | PREP_RERAISE_STAR = 0x58
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
  | SWAP = 0x63
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
  | POP_JUMP_FORWARD_IF_FALSE = 0x72
  | POP_JUMP_FORWARD_IF_TRUE = 0x73
  | LOAD_GLOBAL = 0x74
  | IS_OP = 0x75
  | CONTAINS_OP = 0x76
  | RERAISE = 0x77
  | COPY = 0x78
  | BINARY_OP = 0x7A
  | SEND = 0x7B
  | LOAD_FAST = 0x7C
  | STORE_FAST = 0x7D
  | DELETE_FAST = 0x7E
  | POP_JUMP_FORWARD_IF_NOT_NONE = 0x80
  | POP_JUMP_FORWARD_IF_NONE = 0x81
  | RAISE_VARARGS = 0x82
  | GET_AWAITABLE = 0x83
  | MAKE_FUNCTION = 0x84
  | BUILD_SLICE = 0x85
  | JUMP_BACKWARD_NO_INTERRUPT = 0x86
  | MAKE_CELL = 0x87
  | LOAD_CLOSURE = 0x88
  | LOAD_DEREF = 0x89
  | STORE_DEREF = 0x8A
  | DELETE_DEREF = 0x8B
  | JUMP_BACKWARD = 0x8C
  | CALL_FUNCTION_EX = 0x8E
  | EXTENDED_ARG = 0x90
  | LIST_APPEND = 0x91
  | SET_ADD = 0x92
  | MAP_ADD = 0x93
  | LOAD_CLASSDEREF = 0x94
  | COPY_FREE_VARS = 0x95
  | RESUME = 0x97
  | MATCH_CLASS = 0x98
  | FORMAT_VALUE = 0x9B
  | BUILD_CONST_KEY_MAP = 0x9C
  | BUILD_STRING = 0x9D
  | LOAD_METHOD = 0xA0
  | LIST_EXTEND = 0xA2
  | SET_UPDATE = 0xA3
  | DICT_MERGE = 0xA4
  | DICT_UPDATE = 0xA5
  | PRECALL = 0xA6
  | CALL = 0xAB
  | KW_NAMES = 0xAC
  | POP_JUMP_BACKWARD_IF_NOT_NONE = 0xAD
  | POP_JUMP_BACKWARD_IF_NONE = 0xAE
  | POP_JUMP_BACKWARD_IF_FALSE = 0xAF
  | POP_JUMP_BACKWARD_IF_TRUE = 0xB0

/// Provides per-opcode facts that come straight from CPython's own
/// tables for 3.11.
module Opcode =
  /// Number of inline cache entries following the opcode. Each one
  /// occupies two bytes, so an instruction is 2 + 2 * this.
  let inlineCacheCount = function
    | Opcode.BINARY_OP -> 1
    | Opcode.BINARY_SUBSCR -> 4
    | Opcode.CALL -> 4
    | Opcode.COMPARE_OP -> 2
    | Opcode.LOAD_ATTR -> 4
    | Opcode.LOAD_GLOBAL -> 5
    | Opcode.LOAD_METHOD -> 10
    | Opcode.PRECALL -> 1
    | Opcode.STORE_ATTR -> 4
    | Opcode.STORE_SUBSCR -> 1
    | Opcode.UNPACK_SEQUENCE -> 1
    | _ -> 0

  /// Total encoded size of the opcode in bytes, inline caches
  /// included. EXTENDED_ARG prefixes are counted by the caller.
  let length opcode = 2u + 2u * uint32 (inlineCacheCount opcode)

  /// Whether the opcode takes an operand.
  let hasOperand = function
    | Opcode.BINARY_OP
    | Opcode.BUILD_CONST_KEY_MAP
    | Opcode.BUILD_LIST
    | Opcode.BUILD_MAP
    | Opcode.BUILD_SET
    | Opcode.BUILD_SLICE
    | Opcode.BUILD_STRING
    | Opcode.BUILD_TUPLE
    | Opcode.CALL
    | Opcode.CALL_FUNCTION_EX
    | Opcode.COMPARE_OP
    | Opcode.CONTAINS_OP
    | Opcode.COPY
    | Opcode.COPY_FREE_VARS
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
    | Opcode.GET_AWAITABLE
    | Opcode.IMPORT_FROM
    | Opcode.IMPORT_NAME
    | Opcode.IS_OP
    | Opcode.JUMP_BACKWARD
    | Opcode.JUMP_BACKWARD_NO_INTERRUPT
    | Opcode.JUMP_FORWARD
    | Opcode.JUMP_IF_FALSE_OR_POP
    | Opcode.JUMP_IF_TRUE_OR_POP
    | Opcode.KW_NAMES
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
    | Opcode.MAKE_CELL
    | Opcode.MAKE_FUNCTION
    | Opcode.MAP_ADD
    | Opcode.MATCH_CLASS
    | Opcode.POP_JUMP_BACKWARD_IF_FALSE
    | Opcode.POP_JUMP_BACKWARD_IF_NONE
    | Opcode.POP_JUMP_BACKWARD_IF_NOT_NONE
    | Opcode.POP_JUMP_BACKWARD_IF_TRUE
    | Opcode.POP_JUMP_FORWARD_IF_FALSE
    | Opcode.POP_JUMP_FORWARD_IF_NONE
    | Opcode.POP_JUMP_FORWARD_IF_NOT_NONE
    | Opcode.POP_JUMP_FORWARD_IF_TRUE
    | Opcode.PRECALL
    | Opcode.RAISE_VARARGS
    | Opcode.RERAISE
    | Opcode.RESUME
    | Opcode.SEND
    | Opcode.SET_ADD
    | Opcode.SET_UPDATE
    | Opcode.STORE_ATTR
    | Opcode.STORE_DEREF
    | Opcode.STORE_FAST
    | Opcode.STORE_GLOBAL
    | Opcode.STORE_NAME
    | Opcode.SWAP
    | Opcode.UNPACK_EX
    | Opcode.UNPACK_SEQUENCE
      -> true
    | _ -> false
