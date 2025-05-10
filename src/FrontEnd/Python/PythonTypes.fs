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
open B2R2.FrontEnd.BinFile.Python

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.Python.Tests")>]
do ()

/// <summary>
///   Python opcodes(Python 3.12).
/// </summary>
type Opcode =
  | CACHE = 0x0
  | POP_TOP = 0x1
  | PUSH_NULL = 0x2
  | INTERPRETER_EXIT = 0x3
  | END_FOR = 0x4
  | END_SEND = 0x5
  | NOP = 0x9
  | UNARY_NEGATIVE = 0xB
  | UNARY_NOT = 0xC
  | UNARY_INVERT = 0xF
  | RESERVED = 0x11
  | BINARY_SUBSCR = 0x19
  | BINARY_SLICE = 0x1A
  | STORE_SLICE = 0x1B
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
  | CLEANUP_THROW = 0x37
  | STORE_SUBSCR = 0x3C
  | DELETE_SUBSCR = 0x3D
  | GET_ITER = 0x44
  | GET_YIELD_FROM_ITER = 0x45
  | LOAD_BUILD_CLASS = 0x47
  | LOAD_ASSERTION_ERROR = 0x4A
  | RETURN_GENERATOR = 0x4B
  | RETURN_VALUE = 0x53
  | SETUP_ANNOTATIONS = 0x55
  | LOAD_LOCALS = 0x57
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
  | POP_JUMP_IF_FALSE = 0x72
  | POP_JUMP_IF_TRUE = 0x73
  | LOAD_GLOBAL = 0x74
  | IS_OP = 0x75
  | CONTAINS_OP = 0x76
  | RERAISE = 0x77
  | COPY = 0x78
  | RETURN_CONST = 0x79
  | BINARY_OP = 0x7A
  | SEND = 0x7B
  | LOAD_FAST = 0x7C
  | STORE_FAST = 0x7D
  | DELETE_FAST = 0x7E
  | LOAD_FAST_CHECK = 0x7F
  | POP_JUMP_IF_NOT_NONE = 0x80
  | POP_JUMP_IF_NONE = 0x81
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
  | LOAD_SUPER_ATTR = 0x8D
  | CALL_FUNCTION_EX = 0x8E
  | LOAD_FAST_AND_CLEAR = 0x8F
  | EXTENDED_ARG = 0x90
  | LIST_APPEND = 0x91
  | SET_ADD = 0x92
  | MAP_ADD = 0x93
  | COPY_FREE_VARS = 0x95
  | YIELD_VALUE = 0x96
  | RESUME = 0x97
  | MATCH_CLASS = 0x98
  | FORMAT_VALUE = 0x9B
  | BUILD_CONST_KEY_MAP = 0x9C
  | BUILD_STRING = 0x9D
  | LIST_EXTEND = 0xA2
  | SET_UPDATE = 0xA3
  | DICT_MERGE = 0xA4
  | DICT_UPDATE = 0xA5
  | CALL = 0xAB
  | KW_NAMES = 0xAC
  | CALL_INTRINSIC_1 = 0xAD
  | CALL_INTRINSIC_2 = 0xAE
  | LOAD_FROM_DICT_OR_GLOBALS = 0xAF
  | LOAD_FROM_DICT_OR_DEREF = 0xB0
  | INSTRUMENTED_LOAD_SUPER_ATTR = 0xED
  | INSTRUMENTED_POP_JUMP_IF_NONE = 0xEE
  | INSTRUMENTED_POP_JUMP_IF_NOT_NONE = 0xEF
  | INSTRUMENTED_RESUME = 0xF0
  | INSTRUMENTED_CALL = 0xF1
  | INSTRUMENTED_RETURN_VALUE = 0xF2
  | INSTRUMENTED_YIELD_VALUE = 0xF3
  | INSTRUMENTED_CALL_FUNCTION_EX = 0xF4
  | INSTRUMENTED_JUMP_FORWARD = 0xF5
  | INSTRUMENTED_JUMP_BACKWARD = 0xF6
  | INSTRUMENTED_RETURN_CONST = 0xF7
  | INSTRUMENTED_FOR_ITER = 0xF8
  | INSTRUMENTED_POP_JUMP_IF_FALSE = 0xF9
  | INSTRUMENTED_POP_JUMP_IF_TRUE = 0xFA
  | INSTRUMENTED_END_FOR = 0xFB
  | INSTRUMENTED_END_SEND = 0xFC
  | INSTRUMENTED_INSTRUCTION = 0xFD
  | INSTRUMENTED_LINE = 0xFE
  | SETUP_FINALLY = 0x100
  | SETUP_CLEANUP = 0x101
  | SETUP_WITH = 0x102
  | POP_BLOCK = 0x103
  | JUMP = 0x104
  | JUMP_NO_INTERRUPT = 0x105
  | LOAD_METHOD = 0x106
  | LOAD_SUPER_METHOD = 0x107
  | LOAD_ZERO_SUPER_METHOD = 0x108
  | LOAD_ZERO_SUPER_ATTR = 0x109
  | STORE_FAST_MAYBE_NULL = 0x10A

type internal Op = Opcode

type Operand = int * PyObject option

type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
