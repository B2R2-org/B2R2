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

namespace B2R2.FrontEnd.Python.Python313

/// <summary>
/// Represents a Python 3.13 opcode. Values are CPython 3.13's own
/// opcode numbers, so a byte decodes to a case by a plain cast and
/// this table is checkable directly against CPython's opcode module.
/// </summary>
type Opcode =
  | CACHE = 0x0
  | BEFORE_ASYNC_WITH = 0x1
  | BEFORE_WITH = 0x2
  | BINARY_SLICE = 0x4
  | BINARY_SUBSCR = 0x5
  | CHECK_EG_MATCH = 0x6
  | CHECK_EXC_MATCH = 0x7
  | CLEANUP_THROW = 0x8
  | DELETE_SUBSCR = 0x9
  | END_ASYNC_FOR = 0xA
  | END_FOR = 0xB
  | END_SEND = 0xC
  | EXIT_INIT_CHECK = 0xD
  | FORMAT_SIMPLE = 0xE
  | FORMAT_WITH_SPEC = 0xF
  | GET_AITER = 0x10
  | RESERVED = 0x11
  | GET_ANEXT = 0x12
  | GET_ITER = 0x13
  | GET_LEN = 0x14
  | GET_YIELD_FROM_ITER = 0x15
  | INTERPRETER_EXIT = 0x16
  | LOAD_ASSERTION_ERROR = 0x17
  | LOAD_BUILD_CLASS = 0x18
  | LOAD_LOCALS = 0x19
  | MAKE_FUNCTION = 0x1A
  | MATCH_KEYS = 0x1B
  | MATCH_MAPPING = 0x1C
  | MATCH_SEQUENCE = 0x1D
  | NOP = 0x1E
  | POP_EXCEPT = 0x1F
  | POP_TOP = 0x20
  | PUSH_EXC_INFO = 0x21
  | PUSH_NULL = 0x22
  | RETURN_GENERATOR = 0x23
  | RETURN_VALUE = 0x24
  | SETUP_ANNOTATIONS = 0x25
  | STORE_SLICE = 0x26
  | STORE_SUBSCR = 0x27
  | TO_BOOL = 0x28
  | UNARY_INVERT = 0x29
  | UNARY_NEGATIVE = 0x2A
  | UNARY_NOT = 0x2B
  | WITH_EXCEPT_START = 0x2C
  | BINARY_OP = 0x2D
  | BUILD_CONST_KEY_MAP = 0x2E
  | BUILD_LIST = 0x2F
  | BUILD_MAP = 0x30
  | BUILD_SET = 0x31
  | BUILD_SLICE = 0x32
  | BUILD_STRING = 0x33
  | BUILD_TUPLE = 0x34
  | CALL = 0x35
  | CALL_FUNCTION_EX = 0x36
  | CALL_INTRINSIC_1 = 0x37
  | CALL_INTRINSIC_2 = 0x38
  | CALL_KW = 0x39
  | COMPARE_OP = 0x3A
  | CONTAINS_OP = 0x3B
  | CONVERT_VALUE = 0x3C
  | COPY = 0x3D
  | COPY_FREE_VARS = 0x3E
  | DELETE_ATTR = 0x3F
  | DELETE_DEREF = 0x40
  | DELETE_FAST = 0x41
  | DELETE_GLOBAL = 0x42
  | DELETE_NAME = 0x43
  | DICT_MERGE = 0x44
  | DICT_UPDATE = 0x45
  | ENTER_EXECUTOR = 0x46
  | EXTENDED_ARG = 0x47
  | FOR_ITER = 0x48
  | GET_AWAITABLE = 0x49
  | IMPORT_FROM = 0x4A
  | IMPORT_NAME = 0x4B
  | IS_OP = 0x4C
  | JUMP_BACKWARD = 0x4D
  | JUMP_BACKWARD_NO_INTERRUPT = 0x4E
  | JUMP_FORWARD = 0x4F
  | LIST_APPEND = 0x50
  | LIST_EXTEND = 0x51
  | LOAD_ATTR = 0x52
  | LOAD_CONST = 0x53
  | LOAD_DEREF = 0x54
  | LOAD_FAST = 0x55
  | LOAD_FAST_AND_CLEAR = 0x56
  | LOAD_FAST_CHECK = 0x57
  | LOAD_FAST_LOAD_FAST = 0x58
  | LOAD_FROM_DICT_OR_DEREF = 0x59
  | LOAD_FROM_DICT_OR_GLOBALS = 0x5A
  | LOAD_GLOBAL = 0x5B
  | LOAD_NAME = 0x5C
  | LOAD_SUPER_ATTR = 0x5D
  | MAKE_CELL = 0x5E
  | MAP_ADD = 0x5F
  | MATCH_CLASS = 0x60
  | POP_JUMP_IF_FALSE = 0x61
  | POP_JUMP_IF_NONE = 0x62
  | POP_JUMP_IF_NOT_NONE = 0x63
  | POP_JUMP_IF_TRUE = 0x64
  | RAISE_VARARGS = 0x65
  | RERAISE = 0x66
  | RETURN_CONST = 0x67
  | SEND = 0x68
  | SET_ADD = 0x69
  | SET_FUNCTION_ATTRIBUTE = 0x6A
  | SET_UPDATE = 0x6B
  | STORE_ATTR = 0x6C
  | STORE_DEREF = 0x6D
  | STORE_FAST = 0x6E
  | STORE_FAST_LOAD_FAST = 0x6F
  | STORE_FAST_STORE_FAST = 0x70
  | STORE_GLOBAL = 0x71
  | STORE_NAME = 0x72
  | SWAP = 0x73
  | UNPACK_EX = 0x74
  | UNPACK_SEQUENCE = 0x75
  | YIELD_VALUE = 0x76
  | RESUME = 0x95
  | INSTRUMENTED_RESUME = 0xEC
  | INSTRUMENTED_END_FOR = 0xED
  | INSTRUMENTED_END_SEND = 0xEE
  | INSTRUMENTED_RETURN_VALUE = 0xEF
  | INSTRUMENTED_RETURN_CONST = 0xF0
  | INSTRUMENTED_YIELD_VALUE = 0xF1
  | INSTRUMENTED_LOAD_SUPER_ATTR = 0xF2
  | INSTRUMENTED_FOR_ITER = 0xF3
  | INSTRUMENTED_CALL = 0xF4
  | INSTRUMENTED_CALL_KW = 0xF5
  | INSTRUMENTED_CALL_FUNCTION_EX = 0xF6
  | INSTRUMENTED_INSTRUCTION = 0xF7
  | INSTRUMENTED_JUMP_FORWARD = 0xF8
  | INSTRUMENTED_JUMP_BACKWARD = 0xF9
  | INSTRUMENTED_POP_JUMP_IF_TRUE = 0xFA
  | INSTRUMENTED_POP_JUMP_IF_FALSE = 0xFB
  | INSTRUMENTED_POP_JUMP_IF_NONE = 0xFC
  | INSTRUMENTED_POP_JUMP_IF_NOT_NONE = 0xFD
  | INSTRUMENTED_LINE = 0xFE
  | JUMP = 0x100
  | JUMP_NO_INTERRUPT = 0x101
  | LOAD_CLOSURE = 0x102
  | LOAD_METHOD = 0x103
  | LOAD_SUPER_METHOD = 0x104
  | LOAD_ZERO_SUPER_ATTR = 0x105
  | LOAD_ZERO_SUPER_METHOD = 0x106
  | POP_BLOCK = 0x107
  | SETUP_CLEANUP = 0x108
  | SETUP_FINALLY = 0x109
  | SETUP_WITH = 0x10A
  | STORE_FAST_MAYBE_NULL = 0x10B

/// Provides per-opcode facts that come straight from CPython's own
/// tables for 3.13.
module Opcode =
  /// Number of inline cache entries following the opcode. Each one
  /// occupies two bytes, so an instruction is 2 + 2 * this.
  let inlineCacheCount = function
    | Opcode.BINARY_OP -> 1
    | Opcode.BINARY_SUBSCR -> 1
    | Opcode.CALL -> 3
    | Opcode.COMPARE_OP -> 1
    | Opcode.CONTAINS_OP -> 1
    | Opcode.FOR_ITER -> 1
    | Opcode.JUMP_BACKWARD -> 1
    | Opcode.LOAD_ATTR -> 9
    | Opcode.LOAD_GLOBAL -> 4
    | Opcode.LOAD_SUPER_ATTR -> 1
    | Opcode.POP_JUMP_IF_FALSE -> 1
    | Opcode.POP_JUMP_IF_NONE -> 1
    | Opcode.POP_JUMP_IF_NOT_NONE -> 1
    | Opcode.POP_JUMP_IF_TRUE -> 1
    | Opcode.SEND -> 1
    | Opcode.STORE_ATTR -> 4
    | Opcode.STORE_SUBSCR -> 1
    | Opcode.TO_BOOL -> 3
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
    | Opcode.CALL_INTRINSIC_1
    | Opcode.CALL_INTRINSIC_2
    | Opcode.CALL_KW
    | Opcode.COMPARE_OP
    | Opcode.CONTAINS_OP
    | Opcode.CONVERT_VALUE
    | Opcode.COPY
    | Opcode.COPY_FREE_VARS
    | Opcode.DELETE_ATTR
    | Opcode.DELETE_DEREF
    | Opcode.DELETE_FAST
    | Opcode.DELETE_GLOBAL
    | Opcode.DELETE_NAME
    | Opcode.DICT_MERGE
    | Opcode.DICT_UPDATE
    | Opcode.ENTER_EXECUTOR
    | Opcode.EXTENDED_ARG
    | Opcode.FOR_ITER
    | Opcode.GET_AWAITABLE
    | Opcode.IMPORT_FROM
    | Opcode.IMPORT_NAME
    | Opcode.INSTRUMENTED_CALL
    | Opcode.INSTRUMENTED_CALL_KW
    | Opcode.INSTRUMENTED_FOR_ITER
    | Opcode.INSTRUMENTED_JUMP_BACKWARD
    | Opcode.INSTRUMENTED_JUMP_FORWARD
    | Opcode.INSTRUMENTED_LOAD_SUPER_ATTR
    | Opcode.INSTRUMENTED_POP_JUMP_IF_FALSE
    | Opcode.INSTRUMENTED_POP_JUMP_IF_NONE
    | Opcode.INSTRUMENTED_POP_JUMP_IF_NOT_NONE
    | Opcode.INSTRUMENTED_POP_JUMP_IF_TRUE
    | Opcode.INSTRUMENTED_RESUME
    | Opcode.INSTRUMENTED_RETURN_CONST
    | Opcode.INSTRUMENTED_YIELD_VALUE
    | Opcode.IS_OP
    | Opcode.JUMP
    | Opcode.JUMP_BACKWARD
    | Opcode.JUMP_BACKWARD_NO_INTERRUPT
    | Opcode.JUMP_FORWARD
    | Opcode.JUMP_NO_INTERRUPT
    | Opcode.LIST_APPEND
    | Opcode.LIST_EXTEND
    | Opcode.LOAD_ATTR
    | Opcode.LOAD_CLOSURE
    | Opcode.LOAD_CONST
    | Opcode.LOAD_DEREF
    | Opcode.LOAD_FAST
    | Opcode.LOAD_FAST_AND_CLEAR
    | Opcode.LOAD_FAST_CHECK
    | Opcode.LOAD_FAST_LOAD_FAST
    | Opcode.LOAD_FROM_DICT_OR_DEREF
    | Opcode.LOAD_FROM_DICT_OR_GLOBALS
    | Opcode.LOAD_GLOBAL
    | Opcode.LOAD_METHOD
    | Opcode.LOAD_NAME
    | Opcode.LOAD_SUPER_ATTR
    | Opcode.LOAD_SUPER_METHOD
    | Opcode.LOAD_ZERO_SUPER_ATTR
    | Opcode.LOAD_ZERO_SUPER_METHOD
    | Opcode.MAKE_CELL
    | Opcode.MAP_ADD
    | Opcode.MATCH_CLASS
    | Opcode.POP_JUMP_IF_FALSE
    | Opcode.POP_JUMP_IF_NONE
    | Opcode.POP_JUMP_IF_NOT_NONE
    | Opcode.POP_JUMP_IF_TRUE
    | Opcode.RAISE_VARARGS
    | Opcode.RERAISE
    | Opcode.RESUME
    | Opcode.RETURN_CONST
    | Opcode.SEND
    | Opcode.SETUP_CLEANUP
    | Opcode.SETUP_FINALLY
    | Opcode.SETUP_WITH
    | Opcode.SET_ADD
    | Opcode.SET_FUNCTION_ATTRIBUTE
    | Opcode.SET_UPDATE
    | Opcode.STORE_ATTR
    | Opcode.STORE_DEREF
    | Opcode.STORE_FAST
    | Opcode.STORE_FAST_LOAD_FAST
    | Opcode.STORE_FAST_MAYBE_NULL
    | Opcode.STORE_FAST_STORE_FAST
    | Opcode.STORE_GLOBAL
    | Opcode.STORE_NAME
    | Opcode.SWAP
    | Opcode.UNPACK_EX
    | Opcode.UNPACK_SEQUENCE
    | Opcode.YIELD_VALUE
      -> true
    | _ -> false
