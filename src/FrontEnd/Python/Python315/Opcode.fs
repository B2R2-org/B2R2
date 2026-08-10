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

namespace B2R2.FrontEnd.Python.Python315

/// <summary>
/// Represents a Python 3.15 opcode. Values are CPython 3.15's own
/// opcode numbers, so a byte decodes to a case by a plain cast and
/// this table is checkable directly against CPython's opcode module.
/// </summary>
type Opcode =
  | CACHE = 0x0
  | BINARY_SLICE = 0x1
  | BUILD_TEMPLATE = 0x2
  | CALL_FUNCTION_EX = 0x4
  | CHECK_EG_MATCH = 0x5
  | CHECK_EXC_MATCH = 0x6
  | CLEANUP_THROW = 0x7
  | DELETE_SUBSCR = 0x8
  | END_FOR = 0x9
  | END_SEND = 0xA
  | EXIT_INIT_CHECK = 0xB
  | FORMAT_SIMPLE = 0xC
  | FORMAT_WITH_SPEC = 0xD
  | GET_AITER = 0xE
  | GET_ANEXT = 0xF
  | GET_LEN = 0x10
  | RESERVED = 0x11
  | INTERPRETER_EXIT = 0x12
  | LOAD_BUILD_CLASS = 0x13
  | LOAD_LOCALS = 0x14
  | MAKE_FUNCTION = 0x15
  | MATCH_KEYS = 0x16
  | MATCH_MAPPING = 0x17
  | MATCH_SEQUENCE = 0x18
  | NOP = 0x19
  | NOT_TAKEN = 0x1A
  | POP_EXCEPT = 0x1B
  | POP_ITER = 0x1C
  | POP_TOP = 0x1D
  | PUSH_EXC_INFO = 0x1E
  | PUSH_NULL = 0x1F
  | RETURN_GENERATOR = 0x20
  | RETURN_VALUE = 0x21
  | SETUP_ANNOTATIONS = 0x22
  | STORE_SLICE = 0x23
  | STORE_SUBSCR = 0x24
  | TO_BOOL = 0x25
  | UNARY_INVERT = 0x26
  | UNARY_NEGATIVE = 0x27
  | UNARY_NOT = 0x28
  | WITH_EXCEPT_START = 0x29
  | BINARY_OP = 0x2A
  | BUILD_INTERPOLATION = 0x2B
  | BUILD_LIST = 0x2C
  | BUILD_MAP = 0x2D
  | BUILD_SET = 0x2E
  | BUILD_SLICE = 0x2F
  | BUILD_STRING = 0x30
  | BUILD_TUPLE = 0x31
  | CALL = 0x32
  | CALL_INTRINSIC_1 = 0x33
  | CALL_INTRINSIC_2 = 0x34
  | CALL_KW = 0x35
  | COMPARE_OP = 0x36
  | CONTAINS_OP = 0x37
  | CONVERT_VALUE = 0x38
  | COPY = 0x39
  | COPY_FREE_VARS = 0x3A
  | DELETE_ATTR = 0x3B
  | DELETE_DEREF = 0x3C
  | DELETE_FAST = 0x3D
  | DELETE_GLOBAL = 0x3E
  | DELETE_NAME = 0x3F
  | DICT_MERGE = 0x40
  | DICT_UPDATE = 0x41
  | END_ASYNC_FOR = 0x42
  | EXTENDED_ARG = 0x43
  | FOR_ITER = 0x44
  | GET_AWAITABLE = 0x45
  | GET_ITER = 0x46
  | IMPORT_FROM = 0x47
  | IMPORT_NAME = 0x48
  | IS_OP = 0x49
  | JUMP_BACKWARD = 0x4A
  | JUMP_BACKWARD_NO_INTERRUPT = 0x4B
  | JUMP_FORWARD = 0x4C
  | LIST_APPEND = 0x4D
  | LIST_EXTEND = 0x4E
  | LOAD_ATTR = 0x4F
  | LOAD_COMMON_CONSTANT = 0x50
  | LOAD_CONST = 0x51
  | LOAD_DEREF = 0x52
  | LOAD_FAST = 0x53
  | LOAD_FAST_AND_CLEAR = 0x54
  | LOAD_FAST_BORROW = 0x55
  | LOAD_FAST_BORROW_LOAD_FAST_BORROW = 0x56
  | LOAD_FAST_CHECK = 0x57
  | LOAD_FAST_LOAD_FAST = 0x58
  | LOAD_FROM_DICT_OR_DEREF = 0x59
  | LOAD_FROM_DICT_OR_GLOBALS = 0x5A
  | LOAD_GLOBAL = 0x5B
  | LOAD_NAME = 0x5C
  | LOAD_SMALL_INT = 0x5D
  | LOAD_SPECIAL = 0x5E
  | LOAD_SUPER_ATTR = 0x5F
  | MAKE_CELL = 0x60
  | MAP_ADD = 0x61
  | MATCH_CLASS = 0x62
  | POP_JUMP_IF_FALSE = 0x63
  | POP_JUMP_IF_NONE = 0x64
  | POP_JUMP_IF_NOT_NONE = 0x65
  | POP_JUMP_IF_TRUE = 0x66
  | RAISE_VARARGS = 0x67
  | RERAISE = 0x68
  | SEND = 0x69
  | SET_ADD = 0x6A
  | SET_FUNCTION_ATTRIBUTE = 0x6B
  | SET_UPDATE = 0x6C
  | STORE_ATTR = 0x6D
  | STORE_DEREF = 0x6E
  | STORE_FAST = 0x6F
  | STORE_FAST_LOAD_FAST = 0x70
  | STORE_FAST_STORE_FAST = 0x71
  | STORE_GLOBAL = 0x72
  | STORE_NAME = 0x73
  | SWAP = 0x74
  | UNPACK_EX = 0x75
  | UNPACK_SEQUENCE = 0x76
  | YIELD_VALUE = 0x77
  | RESUME = 0x80
  | INSTRUMENTED_END_FOR = 0xE9
  | INSTRUMENTED_POP_ITER = 0xEA
  | INSTRUMENTED_END_SEND = 0xEB
  | INSTRUMENTED_FOR_ITER = 0xEC
  | INSTRUMENTED_INSTRUCTION = 0xED
  | INSTRUMENTED_JUMP_FORWARD = 0xEE
  | INSTRUMENTED_NOT_TAKEN = 0xEF
  | INSTRUMENTED_POP_JUMP_IF_TRUE = 0xF0
  | INSTRUMENTED_POP_JUMP_IF_FALSE = 0xF1
  | INSTRUMENTED_POP_JUMP_IF_NONE = 0xF2
  | INSTRUMENTED_POP_JUMP_IF_NOT_NONE = 0xF3
  | INSTRUMENTED_RESUME = 0xF4
  | INSTRUMENTED_RETURN_VALUE = 0xF5
  | INSTRUMENTED_YIELD_VALUE = 0xF6
  | INSTRUMENTED_END_ASYNC_FOR = 0xF7
  | INSTRUMENTED_LOAD_SUPER_ATTR = 0xF8
  | INSTRUMENTED_CALL = 0xF9
  | INSTRUMENTED_CALL_KW = 0xFA
  | INSTRUMENTED_CALL_FUNCTION_EX = 0xFB
  | INSTRUMENTED_JUMP_BACKWARD = 0xFC
  | INSTRUMENTED_LINE = 0xFD
  | ENTER_EXECUTOR = 0xFE
  | TRACE_RECORD = 0xFF
  | ANNOTATIONS_PLACEHOLDER = 0x100
  | JUMP = 0x101
  | JUMP_IF_FALSE = 0x102
  | JUMP_IF_TRUE = 0x103
  | JUMP_NO_INTERRUPT = 0x104
  | LOAD_CLOSURE = 0x105
  | POP_BLOCK = 0x106
  | SETUP_CLEANUP = 0x107
  | SETUP_FINALLY = 0x108
  | SETUP_WITH = 0x109
  | STORE_FAST_MAYBE_NULL = 0x10A

/// Provides per-opcode facts that come straight from CPython's own
/// tables for 3.15.
module Opcode =
  /// Number of inline cache entries following the opcode. Each one
  /// occupies two bytes, so an instruction is 2 + 2 * this.
  let inlineCacheCount = function
    | Opcode.BINARY_OP -> 5
    | Opcode.CALL -> 3
    | Opcode.CALL_FUNCTION_EX -> 1
    | Opcode.CALL_KW -> 3
    | Opcode.COMPARE_OP -> 1
    | Opcode.CONTAINS_OP -> 1
    | Opcode.FOR_ITER -> 1
    | Opcode.GET_ITER -> 1
    | Opcode.JUMP_BACKWARD -> 1
    | Opcode.LOAD_ATTR -> 9
    | Opcode.LOAD_GLOBAL -> 4
    | Opcode.LOAD_SUPER_ATTR -> 1
    | Opcode.POP_JUMP_IF_FALSE -> 1
    | Opcode.POP_JUMP_IF_NONE -> 1
    | Opcode.POP_JUMP_IF_NOT_NONE -> 1
    | Opcode.POP_JUMP_IF_TRUE -> 1
    | Opcode.RESUME -> 1
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
    | Opcode.BUILD_INTERPOLATION
    | Opcode.BUILD_LIST
    | Opcode.BUILD_MAP
    | Opcode.BUILD_SET
    | Opcode.BUILD_SLICE
    | Opcode.BUILD_STRING
    | Opcode.BUILD_TUPLE
    | Opcode.CALL
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
    | Opcode.END_ASYNC_FOR
    | Opcode.ENTER_EXECUTOR
    | Opcode.EXTENDED_ARG
    | Opcode.FOR_ITER
    | Opcode.GET_AWAITABLE
    | Opcode.GET_ITER
    | Opcode.IMPORT_FROM
    | Opcode.IMPORT_NAME
    | Opcode.INSTRUMENTED_CALL
    | Opcode.INSTRUMENTED_CALL_KW
    | Opcode.INSTRUMENTED_END_ASYNC_FOR
    | Opcode.INSTRUMENTED_FOR_ITER
    | Opcode.INSTRUMENTED_JUMP_BACKWARD
    | Opcode.INSTRUMENTED_JUMP_FORWARD
    | Opcode.INSTRUMENTED_LOAD_SUPER_ATTR
    | Opcode.INSTRUMENTED_POP_JUMP_IF_FALSE
    | Opcode.INSTRUMENTED_POP_JUMP_IF_NONE
    | Opcode.INSTRUMENTED_POP_JUMP_IF_NOT_NONE
    | Opcode.INSTRUMENTED_POP_JUMP_IF_TRUE
    | Opcode.INSTRUMENTED_RESUME
    | Opcode.INSTRUMENTED_YIELD_VALUE
    | Opcode.IS_OP
    | Opcode.JUMP
    | Opcode.JUMP_BACKWARD
    | Opcode.JUMP_BACKWARD_NO_INTERRUPT
    | Opcode.JUMP_FORWARD
    | Opcode.JUMP_IF_FALSE
    | Opcode.JUMP_IF_TRUE
    | Opcode.JUMP_NO_INTERRUPT
    | Opcode.LIST_APPEND
    | Opcode.LIST_EXTEND
    | Opcode.LOAD_ATTR
    | Opcode.LOAD_CLOSURE
    | Opcode.LOAD_COMMON_CONSTANT
    | Opcode.LOAD_CONST
    | Opcode.LOAD_DEREF
    | Opcode.LOAD_FAST
    | Opcode.LOAD_FAST_AND_CLEAR
    | Opcode.LOAD_FAST_BORROW
    | Opcode.LOAD_FAST_BORROW_LOAD_FAST_BORROW
    | Opcode.LOAD_FAST_CHECK
    | Opcode.LOAD_FAST_LOAD_FAST
    | Opcode.LOAD_FROM_DICT_OR_DEREF
    | Opcode.LOAD_FROM_DICT_OR_GLOBALS
    | Opcode.LOAD_GLOBAL
    | Opcode.LOAD_NAME
    | Opcode.LOAD_SMALL_INT
    | Opcode.LOAD_SPECIAL
    | Opcode.LOAD_SUPER_ATTR
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
    | Opcode.TRACE_RECORD
    | Opcode.UNPACK_EX
    | Opcode.UNPACK_SEQUENCE
    | Opcode.YIELD_VALUE
      -> true
    | _ -> false
