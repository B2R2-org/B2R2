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

module B2R2.FrontEnd.Python.Tables

open B2R2

/// CPython 3.0.
let private d300 = function
  | 0x00 -> Opcode.STOP_CODE
  | 0x01 -> Opcode.POP_TOP
  | 0x02 -> Opcode.ROT_TWO
  | 0x03 -> Opcode.ROT_THREE
  | 0x04 -> Opcode.DUP_TOP
  | 0x05 -> Opcode.ROT_FOUR
  | 0x09 -> Opcode.NOP
  | 0x0A -> Opcode.UNARY_POSITIVE
  | 0x0B -> Opcode.UNARY_NEGATIVE
  | 0x0C -> Opcode.UNARY_NOT
  | 0x0F -> Opcode.UNARY_INVERT
  | 0x11 -> Opcode.SET_ADD
  | 0x12 -> Opcode.LIST_APPEND
  | 0x13 -> Opcode.BINARY_POWER
  | 0x14 -> Opcode.BINARY_MULTIPLY
  | 0x16 -> Opcode.BINARY_MODULO
  | 0x17 -> Opcode.BINARY_ADD
  | 0x18 -> Opcode.BINARY_SUBTRACT
  | 0x19 -> Opcode.BINARY_SUBSCR
  | 0x1A -> Opcode.BINARY_FLOOR_DIVIDE
  | 0x1B -> Opcode.BINARY_TRUE_DIVIDE
  | 0x1C -> Opcode.INPLACE_FLOOR_DIVIDE
  | 0x1D -> Opcode.INPLACE_TRUE_DIVIDE
  | 0x36 -> Opcode.STORE_MAP
  | 0x37 -> Opcode.INPLACE_ADD
  | 0x38 -> Opcode.INPLACE_SUBTRACT
  | 0x39 -> Opcode.INPLACE_MULTIPLY
  | 0x3B -> Opcode.INPLACE_MODULO
  | 0x3C -> Opcode.STORE_SUBSCR
  | 0x3D -> Opcode.DELETE_SUBSCR
  | 0x3E -> Opcode.BINARY_LSHIFT
  | 0x3F -> Opcode.BINARY_RSHIFT
  | 0x40 -> Opcode.BINARY_AND
  | 0x41 -> Opcode.BINARY_XOR
  | 0x42 -> Opcode.BINARY_OR
  | 0x43 -> Opcode.INPLACE_POWER
  | 0x44 -> Opcode.GET_ITER
  | 0x45 -> Opcode.STORE_LOCALS
  | 0x46 -> Opcode.PRINT_EXPR
  | 0x47 -> Opcode.LOAD_BUILD_CLASS
  | 0x4B -> Opcode.INPLACE_LSHIFT
  | 0x4C -> Opcode.INPLACE_RSHIFT
  | 0x4D -> Opcode.INPLACE_AND
  | 0x4E -> Opcode.INPLACE_XOR
  | 0x4F -> Opcode.INPLACE_OR
  | 0x50 -> Opcode.BREAK_LOOP
  | 0x51 -> Opcode.WITH_CLEANUP
  | 0x53 -> Opcode.RETURN_VALUE
  | 0x54 -> Opcode.IMPORT_STAR
  | 0x56 -> Opcode.YIELD_VALUE
  | 0x57 -> Opcode.POP_BLOCK
  | 0x58 -> Opcode.END_FINALLY
  | 0x59 -> Opcode.POP_EXCEPT
  | 0x5A -> Opcode.STORE_NAME
  | 0x5B -> Opcode.DELETE_NAME
  | 0x5C -> Opcode.UNPACK_SEQUENCE
  | 0x5D -> Opcode.FOR_ITER
  | 0x5E -> Opcode.UNPACK_EX
  | 0x5F -> Opcode.STORE_ATTR
  | 0x60 -> Opcode.DELETE_ATTR
  | 0x61 -> Opcode.STORE_GLOBAL
  | 0x62 -> Opcode.DELETE_GLOBAL
  | 0x63 -> Opcode.DUP_TOPX
  | 0x64 -> Opcode.LOAD_CONST
  | 0x65 -> Opcode.LOAD_NAME
  | 0x66 -> Opcode.BUILD_TUPLE
  | 0x67 -> Opcode.BUILD_LIST
  | 0x68 -> Opcode.BUILD_SET
  | 0x69 -> Opcode.BUILD_MAP
  | 0x6A -> Opcode.LOAD_ATTR
  | 0x6B -> Opcode.COMPARE_OP
  | 0x6C -> Opcode.IMPORT_NAME
  | 0x6D -> Opcode.IMPORT_FROM
  | 0x6E -> Opcode.JUMP_FORWARD
  | 0x6F -> Opcode.JUMP_IF_FALSE
  | 0x70 -> Opcode.JUMP_IF_TRUE
  | 0x71 -> Opcode.JUMP_ABSOLUTE
  | 0x74 -> Opcode.LOAD_GLOBAL
  | 0x77 -> Opcode.CONTINUE_LOOP
  | 0x78 -> Opcode.SETUP_LOOP
  | 0x79 -> Opcode.SETUP_EXCEPT
  | 0x7A -> Opcode.SETUP_FINALLY
  | 0x7C -> Opcode.LOAD_FAST
  | 0x7D -> Opcode.STORE_FAST
  | 0x7E -> Opcode.DELETE_FAST
  | 0x82 -> Opcode.RAISE_VARARGS
  | 0x83 -> Opcode.CALL_FUNCTION
  | 0x84 -> Opcode.MAKE_FUNCTION
  | 0x85 -> Opcode.BUILD_SLICE
  | 0x86 -> Opcode.MAKE_CLOSURE
  | 0x87 -> Opcode.LOAD_CLOSURE
  | 0x88 -> Opcode.LOAD_DEREF
  | 0x89 -> Opcode.STORE_DEREF
  | 0x8C -> Opcode.CALL_FUNCTION_VAR
  | 0x8D -> Opcode.CALL_FUNCTION_KW
  | 0x8E -> Opcode.CALL_FUNCTION_VAR_KW
  | 0x8F -> Opcode.EXTENDED_ARG
  | _ -> Opcode.InvalidOp

/// CPython 3.1.
let private d301 = function
  | 0x00 -> Opcode.STOP_CODE
  | 0x01 -> Opcode.POP_TOP
  | 0x02 -> Opcode.ROT_TWO
  | 0x03 -> Opcode.ROT_THREE
  | 0x04 -> Opcode.DUP_TOP
  | 0x05 -> Opcode.ROT_FOUR
  | 0x09 -> Opcode.NOP
  | 0x0A -> Opcode.UNARY_POSITIVE
  | 0x0B -> Opcode.UNARY_NEGATIVE
  | 0x0C -> Opcode.UNARY_NOT
  | 0x0F -> Opcode.UNARY_INVERT
  | 0x13 -> Opcode.BINARY_POWER
  | 0x14 -> Opcode.BINARY_MULTIPLY
  | 0x16 -> Opcode.BINARY_MODULO
  | 0x17 -> Opcode.BINARY_ADD
  | 0x18 -> Opcode.BINARY_SUBTRACT
  | 0x19 -> Opcode.BINARY_SUBSCR
  | 0x1A -> Opcode.BINARY_FLOOR_DIVIDE
  | 0x1B -> Opcode.BINARY_TRUE_DIVIDE
  | 0x1C -> Opcode.INPLACE_FLOOR_DIVIDE
  | 0x1D -> Opcode.INPLACE_TRUE_DIVIDE
  | 0x36 -> Opcode.STORE_MAP
  | 0x37 -> Opcode.INPLACE_ADD
  | 0x38 -> Opcode.INPLACE_SUBTRACT
  | 0x39 -> Opcode.INPLACE_MULTIPLY
  | 0x3B -> Opcode.INPLACE_MODULO
  | 0x3C -> Opcode.STORE_SUBSCR
  | 0x3D -> Opcode.DELETE_SUBSCR
  | 0x3E -> Opcode.BINARY_LSHIFT
  | 0x3F -> Opcode.BINARY_RSHIFT
  | 0x40 -> Opcode.BINARY_AND
  | 0x41 -> Opcode.BINARY_XOR
  | 0x42 -> Opcode.BINARY_OR
  | 0x43 -> Opcode.INPLACE_POWER
  | 0x44 -> Opcode.GET_ITER
  | 0x45 -> Opcode.STORE_LOCALS
  | 0x46 -> Opcode.PRINT_EXPR
  | 0x47 -> Opcode.LOAD_BUILD_CLASS
  | 0x4B -> Opcode.INPLACE_LSHIFT
  | 0x4C -> Opcode.INPLACE_RSHIFT
  | 0x4D -> Opcode.INPLACE_AND
  | 0x4E -> Opcode.INPLACE_XOR
  | 0x4F -> Opcode.INPLACE_OR
  | 0x50 -> Opcode.BREAK_LOOP
  | 0x51 -> Opcode.WITH_CLEANUP
  | 0x53 -> Opcode.RETURN_VALUE
  | 0x54 -> Opcode.IMPORT_STAR
  | 0x56 -> Opcode.YIELD_VALUE
  | 0x57 -> Opcode.POP_BLOCK
  | 0x58 -> Opcode.END_FINALLY
  | 0x59 -> Opcode.POP_EXCEPT
  | 0x5A -> Opcode.STORE_NAME
  | 0x5B -> Opcode.DELETE_NAME
  | 0x5C -> Opcode.UNPACK_SEQUENCE
  | 0x5D -> Opcode.FOR_ITER
  | 0x5E -> Opcode.UNPACK_EX
  | 0x5F -> Opcode.STORE_ATTR
  | 0x60 -> Opcode.DELETE_ATTR
  | 0x61 -> Opcode.STORE_GLOBAL
  | 0x62 -> Opcode.DELETE_GLOBAL
  | 0x63 -> Opcode.DUP_TOPX
  | 0x64 -> Opcode.LOAD_CONST
  | 0x65 -> Opcode.LOAD_NAME
  | 0x66 -> Opcode.BUILD_TUPLE
  | 0x67 -> Opcode.BUILD_LIST
  | 0x68 -> Opcode.BUILD_SET
  | 0x69 -> Opcode.BUILD_MAP
  | 0x6A -> Opcode.LOAD_ATTR
  | 0x6B -> Opcode.COMPARE_OP
  | 0x6C -> Opcode.IMPORT_NAME
  | 0x6D -> Opcode.IMPORT_FROM
  | 0x6E -> Opcode.JUMP_FORWARD
  | 0x6F -> Opcode.JUMP_IF_FALSE_OR_POP
  | 0x70 -> Opcode.JUMP_IF_TRUE_OR_POP
  | 0x71 -> Opcode.JUMP_ABSOLUTE
  | 0x72 -> Opcode.POP_JUMP_IF_FALSE
  | 0x73 -> Opcode.POP_JUMP_IF_TRUE
  | 0x74 -> Opcode.LOAD_GLOBAL
  | 0x77 -> Opcode.CONTINUE_LOOP
  | 0x78 -> Opcode.SETUP_LOOP
  | 0x79 -> Opcode.SETUP_EXCEPT
  | 0x7A -> Opcode.SETUP_FINALLY
  | 0x7C -> Opcode.LOAD_FAST
  | 0x7D -> Opcode.STORE_FAST
  | 0x7E -> Opcode.DELETE_FAST
  | 0x82 -> Opcode.RAISE_VARARGS
  | 0x83 -> Opcode.CALL_FUNCTION
  | 0x84 -> Opcode.MAKE_FUNCTION
  | 0x85 -> Opcode.BUILD_SLICE
  | 0x86 -> Opcode.MAKE_CLOSURE
  | 0x87 -> Opcode.LOAD_CLOSURE
  | 0x88 -> Opcode.LOAD_DEREF
  | 0x89 -> Opcode.STORE_DEREF
  | 0x8C -> Opcode.CALL_FUNCTION_VAR
  | 0x8D -> Opcode.CALL_FUNCTION_KW
  | 0x8E -> Opcode.CALL_FUNCTION_VAR_KW
  | 0x8F -> Opcode.EXTENDED_ARG
  | 0x91 -> Opcode.LIST_APPEND
  | 0x92 -> Opcode.SET_ADD
  | 0x93 -> Opcode.MAP_ADD
  | _ -> Opcode.InvalidOp

/// CPython 3.2.
let private d302 = function
  | 0x00 -> Opcode.STOP_CODE
  | 0x01 -> Opcode.POP_TOP
  | 0x02 -> Opcode.ROT_TWO
  | 0x03 -> Opcode.ROT_THREE
  | 0x04 -> Opcode.DUP_TOP
  | 0x05 -> Opcode.DUP_TOP_TWO
  | 0x09 -> Opcode.NOP
  | 0x0A -> Opcode.UNARY_POSITIVE
  | 0x0B -> Opcode.UNARY_NEGATIVE
  | 0x0C -> Opcode.UNARY_NOT
  | 0x0F -> Opcode.UNARY_INVERT
  | 0x13 -> Opcode.BINARY_POWER
  | 0x14 -> Opcode.BINARY_MULTIPLY
  | 0x16 -> Opcode.BINARY_MODULO
  | 0x17 -> Opcode.BINARY_ADD
  | 0x18 -> Opcode.BINARY_SUBTRACT
  | 0x19 -> Opcode.BINARY_SUBSCR
  | 0x1A -> Opcode.BINARY_FLOOR_DIVIDE
  | 0x1B -> Opcode.BINARY_TRUE_DIVIDE
  | 0x1C -> Opcode.INPLACE_FLOOR_DIVIDE
  | 0x1D -> Opcode.INPLACE_TRUE_DIVIDE
  | 0x36 -> Opcode.STORE_MAP
  | 0x37 -> Opcode.INPLACE_ADD
  | 0x38 -> Opcode.INPLACE_SUBTRACT
  | 0x39 -> Opcode.INPLACE_MULTIPLY
  | 0x3B -> Opcode.INPLACE_MODULO
  | 0x3C -> Opcode.STORE_SUBSCR
  | 0x3D -> Opcode.DELETE_SUBSCR
  | 0x3E -> Opcode.BINARY_LSHIFT
  | 0x3F -> Opcode.BINARY_RSHIFT
  | 0x40 -> Opcode.BINARY_AND
  | 0x41 -> Opcode.BINARY_XOR
  | 0x42 -> Opcode.BINARY_OR
  | 0x43 -> Opcode.INPLACE_POWER
  | 0x44 -> Opcode.GET_ITER
  | 0x45 -> Opcode.STORE_LOCALS
  | 0x46 -> Opcode.PRINT_EXPR
  | 0x47 -> Opcode.LOAD_BUILD_CLASS
  | 0x4B -> Opcode.INPLACE_LSHIFT
  | 0x4C -> Opcode.INPLACE_RSHIFT
  | 0x4D -> Opcode.INPLACE_AND
  | 0x4E -> Opcode.INPLACE_XOR
  | 0x4F -> Opcode.INPLACE_OR
  | 0x50 -> Opcode.BREAK_LOOP
  | 0x51 -> Opcode.WITH_CLEANUP
  | 0x53 -> Opcode.RETURN_VALUE
  | 0x54 -> Opcode.IMPORT_STAR
  | 0x56 -> Opcode.YIELD_VALUE
  | 0x57 -> Opcode.POP_BLOCK
  | 0x58 -> Opcode.END_FINALLY
  | 0x59 -> Opcode.POP_EXCEPT
  | 0x5A -> Opcode.STORE_NAME
  | 0x5B -> Opcode.DELETE_NAME
  | 0x5C -> Opcode.UNPACK_SEQUENCE
  | 0x5D -> Opcode.FOR_ITER
  | 0x5E -> Opcode.UNPACK_EX
  | 0x5F -> Opcode.STORE_ATTR
  | 0x60 -> Opcode.DELETE_ATTR
  | 0x61 -> Opcode.STORE_GLOBAL
  | 0x62 -> Opcode.DELETE_GLOBAL
  | 0x64 -> Opcode.LOAD_CONST
  | 0x65 -> Opcode.LOAD_NAME
  | 0x66 -> Opcode.BUILD_TUPLE
  | 0x67 -> Opcode.BUILD_LIST
  | 0x68 -> Opcode.BUILD_SET
  | 0x69 -> Opcode.BUILD_MAP
  | 0x6A -> Opcode.LOAD_ATTR
  | 0x6B -> Opcode.COMPARE_OP
  | 0x6C -> Opcode.IMPORT_NAME
  | 0x6D -> Opcode.IMPORT_FROM
  | 0x6E -> Opcode.JUMP_FORWARD
  | 0x6F -> Opcode.JUMP_IF_FALSE_OR_POP
  | 0x70 -> Opcode.JUMP_IF_TRUE_OR_POP
  | 0x71 -> Opcode.JUMP_ABSOLUTE
  | 0x72 -> Opcode.POP_JUMP_IF_FALSE
  | 0x73 -> Opcode.POP_JUMP_IF_TRUE
  | 0x74 -> Opcode.LOAD_GLOBAL
  | 0x77 -> Opcode.CONTINUE_LOOP
  | 0x78 -> Opcode.SETUP_LOOP
  | 0x79 -> Opcode.SETUP_EXCEPT
  | 0x7A -> Opcode.SETUP_FINALLY
  | 0x7C -> Opcode.LOAD_FAST
  | 0x7D -> Opcode.STORE_FAST
  | 0x7E -> Opcode.DELETE_FAST
  | 0x82 -> Opcode.RAISE_VARARGS
  | 0x83 -> Opcode.CALL_FUNCTION
  | 0x84 -> Opcode.MAKE_FUNCTION
  | 0x85 -> Opcode.BUILD_SLICE
  | 0x86 -> Opcode.MAKE_CLOSURE
  | 0x87 -> Opcode.LOAD_CLOSURE
  | 0x88 -> Opcode.LOAD_DEREF
  | 0x89 -> Opcode.STORE_DEREF
  | 0x8A -> Opcode.DELETE_DEREF
  | 0x8C -> Opcode.CALL_FUNCTION_VAR
  | 0x8D -> Opcode.CALL_FUNCTION_KW
  | 0x8E -> Opcode.CALL_FUNCTION_VAR_KW
  | 0x8F -> Opcode.SETUP_WITH
  | 0x90 -> Opcode.EXTENDED_ARG
  | 0x91 -> Opcode.LIST_APPEND
  | 0x92 -> Opcode.SET_ADD
  | 0x93 -> Opcode.MAP_ADD
  | _ -> Opcode.InvalidOp

/// CPython 3.3.
let private d303 = function
  | 0x01 -> Opcode.POP_TOP
  | 0x02 -> Opcode.ROT_TWO
  | 0x03 -> Opcode.ROT_THREE
  | 0x04 -> Opcode.DUP_TOP
  | 0x05 -> Opcode.DUP_TOP_TWO
  | 0x09 -> Opcode.NOP
  | 0x0A -> Opcode.UNARY_POSITIVE
  | 0x0B -> Opcode.UNARY_NEGATIVE
  | 0x0C -> Opcode.UNARY_NOT
  | 0x0F -> Opcode.UNARY_INVERT
  | 0x13 -> Opcode.BINARY_POWER
  | 0x14 -> Opcode.BINARY_MULTIPLY
  | 0x16 -> Opcode.BINARY_MODULO
  | 0x17 -> Opcode.BINARY_ADD
  | 0x18 -> Opcode.BINARY_SUBTRACT
  | 0x19 -> Opcode.BINARY_SUBSCR
  | 0x1A -> Opcode.BINARY_FLOOR_DIVIDE
  | 0x1B -> Opcode.BINARY_TRUE_DIVIDE
  | 0x1C -> Opcode.INPLACE_FLOOR_DIVIDE
  | 0x1D -> Opcode.INPLACE_TRUE_DIVIDE
  | 0x36 -> Opcode.STORE_MAP
  | 0x37 -> Opcode.INPLACE_ADD
  | 0x38 -> Opcode.INPLACE_SUBTRACT
  | 0x39 -> Opcode.INPLACE_MULTIPLY
  | 0x3B -> Opcode.INPLACE_MODULO
  | 0x3C -> Opcode.STORE_SUBSCR
  | 0x3D -> Opcode.DELETE_SUBSCR
  | 0x3E -> Opcode.BINARY_LSHIFT
  | 0x3F -> Opcode.BINARY_RSHIFT
  | 0x40 -> Opcode.BINARY_AND
  | 0x41 -> Opcode.BINARY_XOR
  | 0x42 -> Opcode.BINARY_OR
  | 0x43 -> Opcode.INPLACE_POWER
  | 0x44 -> Opcode.GET_ITER
  | 0x45 -> Opcode.STORE_LOCALS
  | 0x46 -> Opcode.PRINT_EXPR
  | 0x47 -> Opcode.LOAD_BUILD_CLASS
  | 0x48 -> Opcode.YIELD_FROM
  | 0x4B -> Opcode.INPLACE_LSHIFT
  | 0x4C -> Opcode.INPLACE_RSHIFT
  | 0x4D -> Opcode.INPLACE_AND
  | 0x4E -> Opcode.INPLACE_XOR
  | 0x4F -> Opcode.INPLACE_OR
  | 0x50 -> Opcode.BREAK_LOOP
  | 0x51 -> Opcode.WITH_CLEANUP
  | 0x53 -> Opcode.RETURN_VALUE
  | 0x54 -> Opcode.IMPORT_STAR
  | 0x56 -> Opcode.YIELD_VALUE
  | 0x57 -> Opcode.POP_BLOCK
  | 0x58 -> Opcode.END_FINALLY
  | 0x59 -> Opcode.POP_EXCEPT
  | 0x5A -> Opcode.STORE_NAME
  | 0x5B -> Opcode.DELETE_NAME
  | 0x5C -> Opcode.UNPACK_SEQUENCE
  | 0x5D -> Opcode.FOR_ITER
  | 0x5E -> Opcode.UNPACK_EX
  | 0x5F -> Opcode.STORE_ATTR
  | 0x60 -> Opcode.DELETE_ATTR
  | 0x61 -> Opcode.STORE_GLOBAL
  | 0x62 -> Opcode.DELETE_GLOBAL
  | 0x64 -> Opcode.LOAD_CONST
  | 0x65 -> Opcode.LOAD_NAME
  | 0x66 -> Opcode.BUILD_TUPLE
  | 0x67 -> Opcode.BUILD_LIST
  | 0x68 -> Opcode.BUILD_SET
  | 0x69 -> Opcode.BUILD_MAP
  | 0x6A -> Opcode.LOAD_ATTR
  | 0x6B -> Opcode.COMPARE_OP
  | 0x6C -> Opcode.IMPORT_NAME
  | 0x6D -> Opcode.IMPORT_FROM
  | 0x6E -> Opcode.JUMP_FORWARD
  | 0x6F -> Opcode.JUMP_IF_FALSE_OR_POP
  | 0x70 -> Opcode.JUMP_IF_TRUE_OR_POP
  | 0x71 -> Opcode.JUMP_ABSOLUTE
  | 0x72 -> Opcode.POP_JUMP_IF_FALSE
  | 0x73 -> Opcode.POP_JUMP_IF_TRUE
  | 0x74 -> Opcode.LOAD_GLOBAL
  | 0x77 -> Opcode.CONTINUE_LOOP
  | 0x78 -> Opcode.SETUP_LOOP
  | 0x79 -> Opcode.SETUP_EXCEPT
  | 0x7A -> Opcode.SETUP_FINALLY
  | 0x7C -> Opcode.LOAD_FAST
  | 0x7D -> Opcode.STORE_FAST
  | 0x7E -> Opcode.DELETE_FAST
  | 0x82 -> Opcode.RAISE_VARARGS
  | 0x83 -> Opcode.CALL_FUNCTION
  | 0x84 -> Opcode.MAKE_FUNCTION
  | 0x85 -> Opcode.BUILD_SLICE
  | 0x86 -> Opcode.MAKE_CLOSURE
  | 0x87 -> Opcode.LOAD_CLOSURE
  | 0x88 -> Opcode.LOAD_DEREF
  | 0x89 -> Opcode.STORE_DEREF
  | 0x8A -> Opcode.DELETE_DEREF
  | 0x8C -> Opcode.CALL_FUNCTION_VAR
  | 0x8D -> Opcode.CALL_FUNCTION_KW
  | 0x8E -> Opcode.CALL_FUNCTION_VAR_KW
  | 0x8F -> Opcode.SETUP_WITH
  | 0x90 -> Opcode.EXTENDED_ARG
  | 0x91 -> Opcode.LIST_APPEND
  | 0x92 -> Opcode.SET_ADD
  | 0x93 -> Opcode.MAP_ADD
  | _ -> Opcode.InvalidOp

/// CPython 3.4.
let private d304 = function
  | 0x01 -> Opcode.POP_TOP
  | 0x02 -> Opcode.ROT_TWO
  | 0x03 -> Opcode.ROT_THREE
  | 0x04 -> Opcode.DUP_TOP
  | 0x05 -> Opcode.DUP_TOP_TWO
  | 0x09 -> Opcode.NOP
  | 0x0A -> Opcode.UNARY_POSITIVE
  | 0x0B -> Opcode.UNARY_NEGATIVE
  | 0x0C -> Opcode.UNARY_NOT
  | 0x0F -> Opcode.UNARY_INVERT
  | 0x13 -> Opcode.BINARY_POWER
  | 0x14 -> Opcode.BINARY_MULTIPLY
  | 0x16 -> Opcode.BINARY_MODULO
  | 0x17 -> Opcode.BINARY_ADD
  | 0x18 -> Opcode.BINARY_SUBTRACT
  | 0x19 -> Opcode.BINARY_SUBSCR
  | 0x1A -> Opcode.BINARY_FLOOR_DIVIDE
  | 0x1B -> Opcode.BINARY_TRUE_DIVIDE
  | 0x1C -> Opcode.INPLACE_FLOOR_DIVIDE
  | 0x1D -> Opcode.INPLACE_TRUE_DIVIDE
  | 0x36 -> Opcode.STORE_MAP
  | 0x37 -> Opcode.INPLACE_ADD
  | 0x38 -> Opcode.INPLACE_SUBTRACT
  | 0x39 -> Opcode.INPLACE_MULTIPLY
  | 0x3B -> Opcode.INPLACE_MODULO
  | 0x3C -> Opcode.STORE_SUBSCR
  | 0x3D -> Opcode.DELETE_SUBSCR
  | 0x3E -> Opcode.BINARY_LSHIFT
  | 0x3F -> Opcode.BINARY_RSHIFT
  | 0x40 -> Opcode.BINARY_AND
  | 0x41 -> Opcode.BINARY_XOR
  | 0x42 -> Opcode.BINARY_OR
  | 0x43 -> Opcode.INPLACE_POWER
  | 0x44 -> Opcode.GET_ITER
  | 0x46 -> Opcode.PRINT_EXPR
  | 0x47 -> Opcode.LOAD_BUILD_CLASS
  | 0x48 -> Opcode.YIELD_FROM
  | 0x4B -> Opcode.INPLACE_LSHIFT
  | 0x4C -> Opcode.INPLACE_RSHIFT
  | 0x4D -> Opcode.INPLACE_AND
  | 0x4E -> Opcode.INPLACE_XOR
  | 0x4F -> Opcode.INPLACE_OR
  | 0x50 -> Opcode.BREAK_LOOP
  | 0x51 -> Opcode.WITH_CLEANUP
  | 0x53 -> Opcode.RETURN_VALUE
  | 0x54 -> Opcode.IMPORT_STAR
  | 0x56 -> Opcode.YIELD_VALUE
  | 0x57 -> Opcode.POP_BLOCK
  | 0x58 -> Opcode.END_FINALLY
  | 0x59 -> Opcode.POP_EXCEPT
  | 0x5A -> Opcode.STORE_NAME
  | 0x5B -> Opcode.DELETE_NAME
  | 0x5C -> Opcode.UNPACK_SEQUENCE
  | 0x5D -> Opcode.FOR_ITER
  | 0x5E -> Opcode.UNPACK_EX
  | 0x5F -> Opcode.STORE_ATTR
  | 0x60 -> Opcode.DELETE_ATTR
  | 0x61 -> Opcode.STORE_GLOBAL
  | 0x62 -> Opcode.DELETE_GLOBAL
  | 0x64 -> Opcode.LOAD_CONST
  | 0x65 -> Opcode.LOAD_NAME
  | 0x66 -> Opcode.BUILD_TUPLE
  | 0x67 -> Opcode.BUILD_LIST
  | 0x68 -> Opcode.BUILD_SET
  | 0x69 -> Opcode.BUILD_MAP
  | 0x6A -> Opcode.LOAD_ATTR
  | 0x6B -> Opcode.COMPARE_OP
  | 0x6C -> Opcode.IMPORT_NAME
  | 0x6D -> Opcode.IMPORT_FROM
  | 0x6E -> Opcode.JUMP_FORWARD
  | 0x6F -> Opcode.JUMP_IF_FALSE_OR_POP
  | 0x70 -> Opcode.JUMP_IF_TRUE_OR_POP
  | 0x71 -> Opcode.JUMP_ABSOLUTE
  | 0x72 -> Opcode.POP_JUMP_IF_FALSE
  | 0x73 -> Opcode.POP_JUMP_IF_TRUE
  | 0x74 -> Opcode.LOAD_GLOBAL
  | 0x77 -> Opcode.CONTINUE_LOOP
  | 0x78 -> Opcode.SETUP_LOOP
  | 0x79 -> Opcode.SETUP_EXCEPT
  | 0x7A -> Opcode.SETUP_FINALLY
  | 0x7C -> Opcode.LOAD_FAST
  | 0x7D -> Opcode.STORE_FAST
  | 0x7E -> Opcode.DELETE_FAST
  | 0x82 -> Opcode.RAISE_VARARGS
  | 0x83 -> Opcode.CALL_FUNCTION
  | 0x84 -> Opcode.MAKE_FUNCTION
  | 0x85 -> Opcode.BUILD_SLICE
  | 0x86 -> Opcode.MAKE_CLOSURE
  | 0x87 -> Opcode.LOAD_CLOSURE
  | 0x88 -> Opcode.LOAD_DEREF
  | 0x89 -> Opcode.STORE_DEREF
  | 0x8A -> Opcode.DELETE_DEREF
  | 0x8C -> Opcode.CALL_FUNCTION_VAR
  | 0x8D -> Opcode.CALL_FUNCTION_KW
  | 0x8E -> Opcode.CALL_FUNCTION_VAR_KW
  | 0x8F -> Opcode.SETUP_WITH
  | 0x90 -> Opcode.EXTENDED_ARG
  | 0x91 -> Opcode.LIST_APPEND
  | 0x92 -> Opcode.SET_ADD
  | 0x93 -> Opcode.MAP_ADD
  | 0x94 -> Opcode.LOAD_CLASSDEREF
  | _ -> Opcode.InvalidOp

/// CPython 3.5.
let private d305 = function
  | 0x01 -> Opcode.POP_TOP
  | 0x02 -> Opcode.ROT_TWO
  | 0x03 -> Opcode.ROT_THREE
  | 0x04 -> Opcode.DUP_TOP
  | 0x05 -> Opcode.DUP_TOP_TWO
  | 0x09 -> Opcode.NOP
  | 0x0A -> Opcode.UNARY_POSITIVE
  | 0x0B -> Opcode.UNARY_NEGATIVE
  | 0x0C -> Opcode.UNARY_NOT
  | 0x0F -> Opcode.UNARY_INVERT
  | 0x10 -> Opcode.BINARY_MATRIX_MULTIPLY
  | 0x11 -> Opcode.INPLACE_MATRIX_MULTIPLY
  | 0x13 -> Opcode.BINARY_POWER
  | 0x14 -> Opcode.BINARY_MULTIPLY
  | 0x16 -> Opcode.BINARY_MODULO
  | 0x17 -> Opcode.BINARY_ADD
  | 0x18 -> Opcode.BINARY_SUBTRACT
  | 0x19 -> Opcode.BINARY_SUBSCR
  | 0x1A -> Opcode.BINARY_FLOOR_DIVIDE
  | 0x1B -> Opcode.BINARY_TRUE_DIVIDE
  | 0x1C -> Opcode.INPLACE_FLOOR_DIVIDE
  | 0x1D -> Opcode.INPLACE_TRUE_DIVIDE
  | 0x32 -> Opcode.GET_AITER
  | 0x33 -> Opcode.GET_ANEXT
  | 0x34 -> Opcode.BEFORE_ASYNC_WITH
  | 0x37 -> Opcode.INPLACE_ADD
  | 0x38 -> Opcode.INPLACE_SUBTRACT
  | 0x39 -> Opcode.INPLACE_MULTIPLY
  | 0x3B -> Opcode.INPLACE_MODULO
  | 0x3C -> Opcode.STORE_SUBSCR
  | 0x3D -> Opcode.DELETE_SUBSCR
  | 0x3E -> Opcode.BINARY_LSHIFT
  | 0x3F -> Opcode.BINARY_RSHIFT
  | 0x40 -> Opcode.BINARY_AND
  | 0x41 -> Opcode.BINARY_XOR
  | 0x42 -> Opcode.BINARY_OR
  | 0x43 -> Opcode.INPLACE_POWER
  | 0x44 -> Opcode.GET_ITER
  | 0x45 -> Opcode.GET_YIELD_FROM_ITER
  | 0x46 -> Opcode.PRINT_EXPR
  | 0x47 -> Opcode.LOAD_BUILD_CLASS
  | 0x48 -> Opcode.YIELD_FROM
  | 0x49 -> Opcode.GET_AWAITABLE
  | 0x4B -> Opcode.INPLACE_LSHIFT
  | 0x4C -> Opcode.INPLACE_RSHIFT
  | 0x4D -> Opcode.INPLACE_AND
  | 0x4E -> Opcode.INPLACE_XOR
  | 0x4F -> Opcode.INPLACE_OR
  | 0x50 -> Opcode.BREAK_LOOP
  | 0x51 -> Opcode.WITH_CLEANUP_START
  | 0x52 -> Opcode.WITH_CLEANUP_FINISH
  | 0x53 -> Opcode.RETURN_VALUE
  | 0x54 -> Opcode.IMPORT_STAR
  | 0x56 -> Opcode.YIELD_VALUE
  | 0x57 -> Opcode.POP_BLOCK
  | 0x58 -> Opcode.END_FINALLY
  | 0x59 -> Opcode.POP_EXCEPT
  | 0x5A -> Opcode.STORE_NAME
  | 0x5B -> Opcode.DELETE_NAME
  | 0x5C -> Opcode.UNPACK_SEQUENCE
  | 0x5D -> Opcode.FOR_ITER
  | 0x5E -> Opcode.UNPACK_EX
  | 0x5F -> Opcode.STORE_ATTR
  | 0x60 -> Opcode.DELETE_ATTR
  | 0x61 -> Opcode.STORE_GLOBAL
  | 0x62 -> Opcode.DELETE_GLOBAL
  | 0x64 -> Opcode.LOAD_CONST
  | 0x65 -> Opcode.LOAD_NAME
  | 0x66 -> Opcode.BUILD_TUPLE
  | 0x67 -> Opcode.BUILD_LIST
  | 0x68 -> Opcode.BUILD_SET
  | 0x69 -> Opcode.BUILD_MAP
  | 0x6A -> Opcode.LOAD_ATTR
  | 0x6B -> Opcode.COMPARE_OP
  | 0x6C -> Opcode.IMPORT_NAME
  | 0x6D -> Opcode.IMPORT_FROM
  | 0x6E -> Opcode.JUMP_FORWARD
  | 0x6F -> Opcode.JUMP_IF_FALSE_OR_POP
  | 0x70 -> Opcode.JUMP_IF_TRUE_OR_POP
  | 0x71 -> Opcode.JUMP_ABSOLUTE
  | 0x72 -> Opcode.POP_JUMP_IF_FALSE
  | 0x73 -> Opcode.POP_JUMP_IF_TRUE
  | 0x74 -> Opcode.LOAD_GLOBAL
  | 0x77 -> Opcode.CONTINUE_LOOP
  | 0x78 -> Opcode.SETUP_LOOP
  | 0x79 -> Opcode.SETUP_EXCEPT
  | 0x7A -> Opcode.SETUP_FINALLY
  | 0x7C -> Opcode.LOAD_FAST
  | 0x7D -> Opcode.STORE_FAST
  | 0x7E -> Opcode.DELETE_FAST
  | 0x82 -> Opcode.RAISE_VARARGS
  | 0x83 -> Opcode.CALL_FUNCTION
  | 0x84 -> Opcode.MAKE_FUNCTION
  | 0x85 -> Opcode.BUILD_SLICE
  | 0x86 -> Opcode.MAKE_CLOSURE
  | 0x87 -> Opcode.LOAD_CLOSURE
  | 0x88 -> Opcode.LOAD_DEREF
  | 0x89 -> Opcode.STORE_DEREF
  | 0x8A -> Opcode.DELETE_DEREF
  | 0x8C -> Opcode.CALL_FUNCTION_VAR
  | 0x8D -> Opcode.CALL_FUNCTION_KW
  | 0x8E -> Opcode.CALL_FUNCTION_VAR_KW
  | 0x8F -> Opcode.SETUP_WITH
  | 0x90 -> Opcode.EXTENDED_ARG
  | 0x91 -> Opcode.LIST_APPEND
  | 0x92 -> Opcode.SET_ADD
  | 0x93 -> Opcode.MAP_ADD
  | 0x94 -> Opcode.LOAD_CLASSDEREF
  | 0x95 -> Opcode.BUILD_LIST_UNPACK
  | 0x96 -> Opcode.BUILD_MAP_UNPACK
  | 0x97 -> Opcode.BUILD_MAP_UNPACK_WITH_CALL
  | 0x98 -> Opcode.BUILD_TUPLE_UNPACK
  | 0x99 -> Opcode.BUILD_SET_UNPACK
  | 0x9A -> Opcode.SETUP_ASYNC_WITH
  | _ -> Opcode.InvalidOp

/// CPython 3.6.
let private d306 = function
  | 0x01 -> Opcode.POP_TOP
  | 0x02 -> Opcode.ROT_TWO
  | 0x03 -> Opcode.ROT_THREE
  | 0x04 -> Opcode.DUP_TOP
  | 0x05 -> Opcode.DUP_TOP_TWO
  | 0x09 -> Opcode.NOP
  | 0x0A -> Opcode.UNARY_POSITIVE
  | 0x0B -> Opcode.UNARY_NEGATIVE
  | 0x0C -> Opcode.UNARY_NOT
  | 0x0F -> Opcode.UNARY_INVERT
  | 0x10 -> Opcode.BINARY_MATRIX_MULTIPLY
  | 0x11 -> Opcode.INPLACE_MATRIX_MULTIPLY
  | 0x13 -> Opcode.BINARY_POWER
  | 0x14 -> Opcode.BINARY_MULTIPLY
  | 0x16 -> Opcode.BINARY_MODULO
  | 0x17 -> Opcode.BINARY_ADD
  | 0x18 -> Opcode.BINARY_SUBTRACT
  | 0x19 -> Opcode.BINARY_SUBSCR
  | 0x1A -> Opcode.BINARY_FLOOR_DIVIDE
  | 0x1B -> Opcode.BINARY_TRUE_DIVIDE
  | 0x1C -> Opcode.INPLACE_FLOOR_DIVIDE
  | 0x1D -> Opcode.INPLACE_TRUE_DIVIDE
  | 0x32 -> Opcode.GET_AITER
  | 0x33 -> Opcode.GET_ANEXT
  | 0x34 -> Opcode.BEFORE_ASYNC_WITH
  | 0x37 -> Opcode.INPLACE_ADD
  | 0x38 -> Opcode.INPLACE_SUBTRACT
  | 0x39 -> Opcode.INPLACE_MULTIPLY
  | 0x3B -> Opcode.INPLACE_MODULO
  | 0x3C -> Opcode.STORE_SUBSCR
  | 0x3D -> Opcode.DELETE_SUBSCR
  | 0x3E -> Opcode.BINARY_LSHIFT
  | 0x3F -> Opcode.BINARY_RSHIFT
  | 0x40 -> Opcode.BINARY_AND
  | 0x41 -> Opcode.BINARY_XOR
  | 0x42 -> Opcode.BINARY_OR
  | 0x43 -> Opcode.INPLACE_POWER
  | 0x44 -> Opcode.GET_ITER
  | 0x45 -> Opcode.GET_YIELD_FROM_ITER
  | 0x46 -> Opcode.PRINT_EXPR
  | 0x47 -> Opcode.LOAD_BUILD_CLASS
  | 0x48 -> Opcode.YIELD_FROM
  | 0x49 -> Opcode.GET_AWAITABLE
  | 0x4B -> Opcode.INPLACE_LSHIFT
  | 0x4C -> Opcode.INPLACE_RSHIFT
  | 0x4D -> Opcode.INPLACE_AND
  | 0x4E -> Opcode.INPLACE_XOR
  | 0x4F -> Opcode.INPLACE_OR
  | 0x50 -> Opcode.BREAK_LOOP
  | 0x51 -> Opcode.WITH_CLEANUP_START
  | 0x52 -> Opcode.WITH_CLEANUP_FINISH
  | 0x53 -> Opcode.RETURN_VALUE
  | 0x54 -> Opcode.IMPORT_STAR
  | 0x55 -> Opcode.SETUP_ANNOTATIONS
  | 0x56 -> Opcode.YIELD_VALUE
  | 0x57 -> Opcode.POP_BLOCK
  | 0x58 -> Opcode.END_FINALLY
  | 0x59 -> Opcode.POP_EXCEPT
  | 0x5A -> Opcode.STORE_NAME
  | 0x5B -> Opcode.DELETE_NAME
  | 0x5C -> Opcode.UNPACK_SEQUENCE
  | 0x5D -> Opcode.FOR_ITER
  | 0x5E -> Opcode.UNPACK_EX
  | 0x5F -> Opcode.STORE_ATTR
  | 0x60 -> Opcode.DELETE_ATTR
  | 0x61 -> Opcode.STORE_GLOBAL
  | 0x62 -> Opcode.DELETE_GLOBAL
  | 0x64 -> Opcode.LOAD_CONST
  | 0x65 -> Opcode.LOAD_NAME
  | 0x66 -> Opcode.BUILD_TUPLE
  | 0x67 -> Opcode.BUILD_LIST
  | 0x68 -> Opcode.BUILD_SET
  | 0x69 -> Opcode.BUILD_MAP
  | 0x6A -> Opcode.LOAD_ATTR
  | 0x6B -> Opcode.COMPARE_OP
  | 0x6C -> Opcode.IMPORT_NAME
  | 0x6D -> Opcode.IMPORT_FROM
  | 0x6E -> Opcode.JUMP_FORWARD
  | 0x6F -> Opcode.JUMP_IF_FALSE_OR_POP
  | 0x70 -> Opcode.JUMP_IF_TRUE_OR_POP
  | 0x71 -> Opcode.JUMP_ABSOLUTE
  | 0x72 -> Opcode.POP_JUMP_IF_FALSE
  | 0x73 -> Opcode.POP_JUMP_IF_TRUE
  | 0x74 -> Opcode.LOAD_GLOBAL
  | 0x77 -> Opcode.CONTINUE_LOOP
  | 0x78 -> Opcode.SETUP_LOOP
  | 0x79 -> Opcode.SETUP_EXCEPT
  | 0x7A -> Opcode.SETUP_FINALLY
  | 0x7C -> Opcode.LOAD_FAST
  | 0x7D -> Opcode.STORE_FAST
  | 0x7E -> Opcode.DELETE_FAST
  | 0x7F -> Opcode.STORE_ANNOTATION
  | 0x82 -> Opcode.RAISE_VARARGS
  | 0x83 -> Opcode.CALL_FUNCTION
  | 0x84 -> Opcode.MAKE_FUNCTION
  | 0x85 -> Opcode.BUILD_SLICE
  | 0x87 -> Opcode.LOAD_CLOSURE
  | 0x88 -> Opcode.LOAD_DEREF
  | 0x89 -> Opcode.STORE_DEREF
  | 0x8A -> Opcode.DELETE_DEREF
  | 0x8D -> Opcode.CALL_FUNCTION_KW
  | 0x8E -> Opcode.CALL_FUNCTION_EX
  | 0x8F -> Opcode.SETUP_WITH
  | 0x90 -> Opcode.EXTENDED_ARG
  | 0x91 -> Opcode.LIST_APPEND
  | 0x92 -> Opcode.SET_ADD
  | 0x93 -> Opcode.MAP_ADD
  | 0x94 -> Opcode.LOAD_CLASSDEREF
  | 0x95 -> Opcode.BUILD_LIST_UNPACK
  | 0x96 -> Opcode.BUILD_MAP_UNPACK
  | 0x97 -> Opcode.BUILD_MAP_UNPACK_WITH_CALL
  | 0x98 -> Opcode.BUILD_TUPLE_UNPACK
  | 0x99 -> Opcode.BUILD_SET_UNPACK
  | 0x9A -> Opcode.SETUP_ASYNC_WITH
  | 0x9B -> Opcode.FORMAT_VALUE
  | 0x9C -> Opcode.BUILD_CONST_KEY_MAP
  | 0x9D -> Opcode.BUILD_STRING
  | 0x9E -> Opcode.BUILD_TUPLE_UNPACK_WITH_CALL
  | _ -> Opcode.InvalidOp

/// CPython 3.7.
let private d307 = function
  | 0x01 -> Opcode.POP_TOP
  | 0x02 -> Opcode.ROT_TWO
  | 0x03 -> Opcode.ROT_THREE
  | 0x04 -> Opcode.DUP_TOP
  | 0x05 -> Opcode.DUP_TOP_TWO
  | 0x09 -> Opcode.NOP
  | 0x0A -> Opcode.UNARY_POSITIVE
  | 0x0B -> Opcode.UNARY_NEGATIVE
  | 0x0C -> Opcode.UNARY_NOT
  | 0x0F -> Opcode.UNARY_INVERT
  | 0x10 -> Opcode.BINARY_MATRIX_MULTIPLY
  | 0x11 -> Opcode.INPLACE_MATRIX_MULTIPLY
  | 0x13 -> Opcode.BINARY_POWER
  | 0x14 -> Opcode.BINARY_MULTIPLY
  | 0x16 -> Opcode.BINARY_MODULO
  | 0x17 -> Opcode.BINARY_ADD
  | 0x18 -> Opcode.BINARY_SUBTRACT
  | 0x19 -> Opcode.BINARY_SUBSCR
  | 0x1A -> Opcode.BINARY_FLOOR_DIVIDE
  | 0x1B -> Opcode.BINARY_TRUE_DIVIDE
  | 0x1C -> Opcode.INPLACE_FLOOR_DIVIDE
  | 0x1D -> Opcode.INPLACE_TRUE_DIVIDE
  | 0x32 -> Opcode.GET_AITER
  | 0x33 -> Opcode.GET_ANEXT
  | 0x34 -> Opcode.BEFORE_ASYNC_WITH
  | 0x37 -> Opcode.INPLACE_ADD
  | 0x38 -> Opcode.INPLACE_SUBTRACT
  | 0x39 -> Opcode.INPLACE_MULTIPLY
  | 0x3B -> Opcode.INPLACE_MODULO
  | 0x3C -> Opcode.STORE_SUBSCR
  | 0x3D -> Opcode.DELETE_SUBSCR
  | 0x3E -> Opcode.BINARY_LSHIFT
  | 0x3F -> Opcode.BINARY_RSHIFT
  | 0x40 -> Opcode.BINARY_AND
  | 0x41 -> Opcode.BINARY_XOR
  | 0x42 -> Opcode.BINARY_OR
  | 0x43 -> Opcode.INPLACE_POWER
  | 0x44 -> Opcode.GET_ITER
  | 0x45 -> Opcode.GET_YIELD_FROM_ITER
  | 0x46 -> Opcode.PRINT_EXPR
  | 0x47 -> Opcode.LOAD_BUILD_CLASS
  | 0x48 -> Opcode.YIELD_FROM
  | 0x49 -> Opcode.GET_AWAITABLE
  | 0x4B -> Opcode.INPLACE_LSHIFT
  | 0x4C -> Opcode.INPLACE_RSHIFT
  | 0x4D -> Opcode.INPLACE_AND
  | 0x4E -> Opcode.INPLACE_XOR
  | 0x4F -> Opcode.INPLACE_OR
  | 0x50 -> Opcode.BREAK_LOOP
  | 0x51 -> Opcode.WITH_CLEANUP_START
  | 0x52 -> Opcode.WITH_CLEANUP_FINISH
  | 0x53 -> Opcode.RETURN_VALUE
  | 0x54 -> Opcode.IMPORT_STAR
  | 0x55 -> Opcode.SETUP_ANNOTATIONS
  | 0x56 -> Opcode.YIELD_VALUE
  | 0x57 -> Opcode.POP_BLOCK
  | 0x58 -> Opcode.END_FINALLY
  | 0x59 -> Opcode.POP_EXCEPT
  | 0x5A -> Opcode.STORE_NAME
  | 0x5B -> Opcode.DELETE_NAME
  | 0x5C -> Opcode.UNPACK_SEQUENCE
  | 0x5D -> Opcode.FOR_ITER
  | 0x5E -> Opcode.UNPACK_EX
  | 0x5F -> Opcode.STORE_ATTR
  | 0x60 -> Opcode.DELETE_ATTR
  | 0x61 -> Opcode.STORE_GLOBAL
  | 0x62 -> Opcode.DELETE_GLOBAL
  | 0x64 -> Opcode.LOAD_CONST
  | 0x65 -> Opcode.LOAD_NAME
  | 0x66 -> Opcode.BUILD_TUPLE
  | 0x67 -> Opcode.BUILD_LIST
  | 0x68 -> Opcode.BUILD_SET
  | 0x69 -> Opcode.BUILD_MAP
  | 0x6A -> Opcode.LOAD_ATTR
  | 0x6B -> Opcode.COMPARE_OP
  | 0x6C -> Opcode.IMPORT_NAME
  | 0x6D -> Opcode.IMPORT_FROM
  | 0x6E -> Opcode.JUMP_FORWARD
  | 0x6F -> Opcode.JUMP_IF_FALSE_OR_POP
  | 0x70 -> Opcode.JUMP_IF_TRUE_OR_POP
  | 0x71 -> Opcode.JUMP_ABSOLUTE
  | 0x72 -> Opcode.POP_JUMP_IF_FALSE
  | 0x73 -> Opcode.POP_JUMP_IF_TRUE
  | 0x74 -> Opcode.LOAD_GLOBAL
  | 0x77 -> Opcode.CONTINUE_LOOP
  | 0x78 -> Opcode.SETUP_LOOP
  | 0x79 -> Opcode.SETUP_EXCEPT
  | 0x7A -> Opcode.SETUP_FINALLY
  | 0x7C -> Opcode.LOAD_FAST
  | 0x7D -> Opcode.STORE_FAST
  | 0x7E -> Opcode.DELETE_FAST
  | 0x82 -> Opcode.RAISE_VARARGS
  | 0x83 -> Opcode.CALL_FUNCTION
  | 0x84 -> Opcode.MAKE_FUNCTION
  | 0x85 -> Opcode.BUILD_SLICE
  | 0x87 -> Opcode.LOAD_CLOSURE
  | 0x88 -> Opcode.LOAD_DEREF
  | 0x89 -> Opcode.STORE_DEREF
  | 0x8A -> Opcode.DELETE_DEREF
  | 0x8D -> Opcode.CALL_FUNCTION_KW
  | 0x8E -> Opcode.CALL_FUNCTION_EX
  | 0x8F -> Opcode.SETUP_WITH
  | 0x90 -> Opcode.EXTENDED_ARG
  | 0x91 -> Opcode.LIST_APPEND
  | 0x92 -> Opcode.SET_ADD
  | 0x93 -> Opcode.MAP_ADD
  | 0x94 -> Opcode.LOAD_CLASSDEREF
  | 0x95 -> Opcode.BUILD_LIST_UNPACK
  | 0x96 -> Opcode.BUILD_MAP_UNPACK
  | 0x97 -> Opcode.BUILD_MAP_UNPACK_WITH_CALL
  | 0x98 -> Opcode.BUILD_TUPLE_UNPACK
  | 0x99 -> Opcode.BUILD_SET_UNPACK
  | 0x9A -> Opcode.SETUP_ASYNC_WITH
  | 0x9B -> Opcode.FORMAT_VALUE
  | 0x9C -> Opcode.BUILD_CONST_KEY_MAP
  | 0x9D -> Opcode.BUILD_STRING
  | 0x9E -> Opcode.BUILD_TUPLE_UNPACK_WITH_CALL
  | 0xA0 -> Opcode.LOAD_METHOD
  | 0xA1 -> Opcode.CALL_METHOD
  | _ -> Opcode.InvalidOp

/// CPython 3.8.
let private d308 = function
  | 0x01 -> Opcode.POP_TOP
  | 0x02 -> Opcode.ROT_TWO
  | 0x03 -> Opcode.ROT_THREE
  | 0x04 -> Opcode.DUP_TOP
  | 0x05 -> Opcode.DUP_TOP_TWO
  | 0x06 -> Opcode.ROT_FOUR
  | 0x09 -> Opcode.NOP
  | 0x0A -> Opcode.UNARY_POSITIVE
  | 0x0B -> Opcode.UNARY_NEGATIVE
  | 0x0C -> Opcode.UNARY_NOT
  | 0x0F -> Opcode.UNARY_INVERT
  | 0x10 -> Opcode.BINARY_MATRIX_MULTIPLY
  | 0x11 -> Opcode.INPLACE_MATRIX_MULTIPLY
  | 0x13 -> Opcode.BINARY_POWER
  | 0x14 -> Opcode.BINARY_MULTIPLY
  | 0x16 -> Opcode.BINARY_MODULO
  | 0x17 -> Opcode.BINARY_ADD
  | 0x18 -> Opcode.BINARY_SUBTRACT
  | 0x19 -> Opcode.BINARY_SUBSCR
  | 0x1A -> Opcode.BINARY_FLOOR_DIVIDE
  | 0x1B -> Opcode.BINARY_TRUE_DIVIDE
  | 0x1C -> Opcode.INPLACE_FLOOR_DIVIDE
  | 0x1D -> Opcode.INPLACE_TRUE_DIVIDE
  | 0x32 -> Opcode.GET_AITER
  | 0x33 -> Opcode.GET_ANEXT
  | 0x34 -> Opcode.BEFORE_ASYNC_WITH
  | 0x35 -> Opcode.BEGIN_FINALLY
  | 0x36 -> Opcode.END_ASYNC_FOR
  | 0x37 -> Opcode.INPLACE_ADD
  | 0x38 -> Opcode.INPLACE_SUBTRACT
  | 0x39 -> Opcode.INPLACE_MULTIPLY
  | 0x3B -> Opcode.INPLACE_MODULO
  | 0x3C -> Opcode.STORE_SUBSCR
  | 0x3D -> Opcode.DELETE_SUBSCR
  | 0x3E -> Opcode.BINARY_LSHIFT
  | 0x3F -> Opcode.BINARY_RSHIFT
  | 0x40 -> Opcode.BINARY_AND
  | 0x41 -> Opcode.BINARY_XOR
  | 0x42 -> Opcode.BINARY_OR
  | 0x43 -> Opcode.INPLACE_POWER
  | 0x44 -> Opcode.GET_ITER
  | 0x45 -> Opcode.GET_YIELD_FROM_ITER
  | 0x46 -> Opcode.PRINT_EXPR
  | 0x47 -> Opcode.LOAD_BUILD_CLASS
  | 0x48 -> Opcode.YIELD_FROM
  | 0x49 -> Opcode.GET_AWAITABLE
  | 0x4B -> Opcode.INPLACE_LSHIFT
  | 0x4C -> Opcode.INPLACE_RSHIFT
  | 0x4D -> Opcode.INPLACE_AND
  | 0x4E -> Opcode.INPLACE_XOR
  | 0x4F -> Opcode.INPLACE_OR
  | 0x51 -> Opcode.WITH_CLEANUP_START
  | 0x52 -> Opcode.WITH_CLEANUP_FINISH
  | 0x53 -> Opcode.RETURN_VALUE
  | 0x54 -> Opcode.IMPORT_STAR
  | 0x55 -> Opcode.SETUP_ANNOTATIONS
  | 0x56 -> Opcode.YIELD_VALUE
  | 0x57 -> Opcode.POP_BLOCK
  | 0x58 -> Opcode.END_FINALLY
  | 0x59 -> Opcode.POP_EXCEPT
  | 0x5A -> Opcode.STORE_NAME
  | 0x5B -> Opcode.DELETE_NAME
  | 0x5C -> Opcode.UNPACK_SEQUENCE
  | 0x5D -> Opcode.FOR_ITER
  | 0x5E -> Opcode.UNPACK_EX
  | 0x5F -> Opcode.STORE_ATTR
  | 0x60 -> Opcode.DELETE_ATTR
  | 0x61 -> Opcode.STORE_GLOBAL
  | 0x62 -> Opcode.DELETE_GLOBAL
  | 0x64 -> Opcode.LOAD_CONST
  | 0x65 -> Opcode.LOAD_NAME
  | 0x66 -> Opcode.BUILD_TUPLE
  | 0x67 -> Opcode.BUILD_LIST
  | 0x68 -> Opcode.BUILD_SET
  | 0x69 -> Opcode.BUILD_MAP
  | 0x6A -> Opcode.LOAD_ATTR
  | 0x6B -> Opcode.COMPARE_OP
  | 0x6C -> Opcode.IMPORT_NAME
  | 0x6D -> Opcode.IMPORT_FROM
  | 0x6E -> Opcode.JUMP_FORWARD
  | 0x6F -> Opcode.JUMP_IF_FALSE_OR_POP
  | 0x70 -> Opcode.JUMP_IF_TRUE_OR_POP
  | 0x71 -> Opcode.JUMP_ABSOLUTE
  | 0x72 -> Opcode.POP_JUMP_IF_FALSE
  | 0x73 -> Opcode.POP_JUMP_IF_TRUE
  | 0x74 -> Opcode.LOAD_GLOBAL
  | 0x7A -> Opcode.SETUP_FINALLY
  | 0x7C -> Opcode.LOAD_FAST
  | 0x7D -> Opcode.STORE_FAST
  | 0x7E -> Opcode.DELETE_FAST
  | 0x82 -> Opcode.RAISE_VARARGS
  | 0x83 -> Opcode.CALL_FUNCTION
  | 0x84 -> Opcode.MAKE_FUNCTION
  | 0x85 -> Opcode.BUILD_SLICE
  | 0x87 -> Opcode.LOAD_CLOSURE
  | 0x88 -> Opcode.LOAD_DEREF
  | 0x89 -> Opcode.STORE_DEREF
  | 0x8A -> Opcode.DELETE_DEREF
  | 0x8D -> Opcode.CALL_FUNCTION_KW
  | 0x8E -> Opcode.CALL_FUNCTION_EX
  | 0x8F -> Opcode.SETUP_WITH
  | 0x90 -> Opcode.EXTENDED_ARG
  | 0x91 -> Opcode.LIST_APPEND
  | 0x92 -> Opcode.SET_ADD
  | 0x93 -> Opcode.MAP_ADD
  | 0x94 -> Opcode.LOAD_CLASSDEREF
  | 0x95 -> Opcode.BUILD_LIST_UNPACK
  | 0x96 -> Opcode.BUILD_MAP_UNPACK
  | 0x97 -> Opcode.BUILD_MAP_UNPACK_WITH_CALL
  | 0x98 -> Opcode.BUILD_TUPLE_UNPACK
  | 0x99 -> Opcode.BUILD_SET_UNPACK
  | 0x9A -> Opcode.SETUP_ASYNC_WITH
  | 0x9B -> Opcode.FORMAT_VALUE
  | 0x9C -> Opcode.BUILD_CONST_KEY_MAP
  | 0x9D -> Opcode.BUILD_STRING
  | 0x9E -> Opcode.BUILD_TUPLE_UNPACK_WITH_CALL
  | 0xA0 -> Opcode.LOAD_METHOD
  | 0xA1 -> Opcode.CALL_METHOD
  | 0xA2 -> Opcode.CALL_FINALLY
  | 0xA3 -> Opcode.POP_FINALLY
  | _ -> Opcode.InvalidOp

/// CPython 3.9.
let private d309 = function
  | 0x01 -> Opcode.POP_TOP
  | 0x02 -> Opcode.ROT_TWO
  | 0x03 -> Opcode.ROT_THREE
  | 0x04 -> Opcode.DUP_TOP
  | 0x05 -> Opcode.DUP_TOP_TWO
  | 0x06 -> Opcode.ROT_FOUR
  | 0x09 -> Opcode.NOP
  | 0x0A -> Opcode.UNARY_POSITIVE
  | 0x0B -> Opcode.UNARY_NEGATIVE
  | 0x0C -> Opcode.UNARY_NOT
  | 0x0F -> Opcode.UNARY_INVERT
  | 0x10 -> Opcode.BINARY_MATRIX_MULTIPLY
  | 0x11 -> Opcode.INPLACE_MATRIX_MULTIPLY
  | 0x13 -> Opcode.BINARY_POWER
  | 0x14 -> Opcode.BINARY_MULTIPLY
  | 0x16 -> Opcode.BINARY_MODULO
  | 0x17 -> Opcode.BINARY_ADD
  | 0x18 -> Opcode.BINARY_SUBTRACT
  | 0x19 -> Opcode.BINARY_SUBSCR
  | 0x1A -> Opcode.BINARY_FLOOR_DIVIDE
  | 0x1B -> Opcode.BINARY_TRUE_DIVIDE
  | 0x1C -> Opcode.INPLACE_FLOOR_DIVIDE
  | 0x1D -> Opcode.INPLACE_TRUE_DIVIDE
  | 0x30 -> Opcode.RERAISE
  | 0x31 -> Opcode.WITH_EXCEPT_START
  | 0x32 -> Opcode.GET_AITER
  | 0x33 -> Opcode.GET_ANEXT
  | 0x34 -> Opcode.BEFORE_ASYNC_WITH
  | 0x36 -> Opcode.END_ASYNC_FOR
  | 0x37 -> Opcode.INPLACE_ADD
  | 0x38 -> Opcode.INPLACE_SUBTRACT
  | 0x39 -> Opcode.INPLACE_MULTIPLY
  | 0x3B -> Opcode.INPLACE_MODULO
  | 0x3C -> Opcode.STORE_SUBSCR
  | 0x3D -> Opcode.DELETE_SUBSCR
  | 0x3E -> Opcode.BINARY_LSHIFT
  | 0x3F -> Opcode.BINARY_RSHIFT
  | 0x40 -> Opcode.BINARY_AND
  | 0x41 -> Opcode.BINARY_XOR
  | 0x42 -> Opcode.BINARY_OR
  | 0x43 -> Opcode.INPLACE_POWER
  | 0x44 -> Opcode.GET_ITER
  | 0x45 -> Opcode.GET_YIELD_FROM_ITER
  | 0x46 -> Opcode.PRINT_EXPR
  | 0x47 -> Opcode.LOAD_BUILD_CLASS
  | 0x48 -> Opcode.YIELD_FROM
  | 0x49 -> Opcode.GET_AWAITABLE
  | 0x4A -> Opcode.LOAD_ASSERTION_ERROR
  | 0x4B -> Opcode.INPLACE_LSHIFT
  | 0x4C -> Opcode.INPLACE_RSHIFT
  | 0x4D -> Opcode.INPLACE_AND
  | 0x4E -> Opcode.INPLACE_XOR
  | 0x4F -> Opcode.INPLACE_OR
  | 0x52 -> Opcode.LIST_TO_TUPLE
  | 0x53 -> Opcode.RETURN_VALUE
  | 0x54 -> Opcode.IMPORT_STAR
  | 0x55 -> Opcode.SETUP_ANNOTATIONS
  | 0x56 -> Opcode.YIELD_VALUE
  | 0x57 -> Opcode.POP_BLOCK
  | 0x59 -> Opcode.POP_EXCEPT
  | 0x5A -> Opcode.STORE_NAME
  | 0x5B -> Opcode.DELETE_NAME
  | 0x5C -> Opcode.UNPACK_SEQUENCE
  | 0x5D -> Opcode.FOR_ITER
  | 0x5E -> Opcode.UNPACK_EX
  | 0x5F -> Opcode.STORE_ATTR
  | 0x60 -> Opcode.DELETE_ATTR
  | 0x61 -> Opcode.STORE_GLOBAL
  | 0x62 -> Opcode.DELETE_GLOBAL
  | 0x64 -> Opcode.LOAD_CONST
  | 0x65 -> Opcode.LOAD_NAME
  | 0x66 -> Opcode.BUILD_TUPLE
  | 0x67 -> Opcode.BUILD_LIST
  | 0x68 -> Opcode.BUILD_SET
  | 0x69 -> Opcode.BUILD_MAP
  | 0x6A -> Opcode.LOAD_ATTR
  | 0x6B -> Opcode.COMPARE_OP
  | 0x6C -> Opcode.IMPORT_NAME
  | 0x6D -> Opcode.IMPORT_FROM
  | 0x6E -> Opcode.JUMP_FORWARD
  | 0x6F -> Opcode.JUMP_IF_FALSE_OR_POP
  | 0x70 -> Opcode.JUMP_IF_TRUE_OR_POP
  | 0x71 -> Opcode.JUMP_ABSOLUTE
  | 0x72 -> Opcode.POP_JUMP_IF_FALSE
  | 0x73 -> Opcode.POP_JUMP_IF_TRUE
  | 0x74 -> Opcode.LOAD_GLOBAL
  | 0x75 -> Opcode.IS_OP
  | 0x76 -> Opcode.CONTAINS_OP
  | 0x79 -> Opcode.JUMP_IF_NOT_EXC_MATCH
  | 0x7A -> Opcode.SETUP_FINALLY
  | 0x7C -> Opcode.LOAD_FAST
  | 0x7D -> Opcode.STORE_FAST
  | 0x7E -> Opcode.DELETE_FAST
  | 0x82 -> Opcode.RAISE_VARARGS
  | 0x83 -> Opcode.CALL_FUNCTION
  | 0x84 -> Opcode.MAKE_FUNCTION
  | 0x85 -> Opcode.BUILD_SLICE
  | 0x87 -> Opcode.LOAD_CLOSURE
  | 0x88 -> Opcode.LOAD_DEREF
  | 0x89 -> Opcode.STORE_DEREF
  | 0x8A -> Opcode.DELETE_DEREF
  | 0x8D -> Opcode.CALL_FUNCTION_KW
  | 0x8E -> Opcode.CALL_FUNCTION_EX
  | 0x8F -> Opcode.SETUP_WITH
  | 0x90 -> Opcode.EXTENDED_ARG
  | 0x91 -> Opcode.LIST_APPEND
  | 0x92 -> Opcode.SET_ADD
  | 0x93 -> Opcode.MAP_ADD
  | 0x94 -> Opcode.LOAD_CLASSDEREF
  | 0x9A -> Opcode.SETUP_ASYNC_WITH
  | 0x9B -> Opcode.FORMAT_VALUE
  | 0x9C -> Opcode.BUILD_CONST_KEY_MAP
  | 0x9D -> Opcode.BUILD_STRING
  | 0xA0 -> Opcode.LOAD_METHOD
  | 0xA1 -> Opcode.CALL_METHOD
  | 0xA2 -> Opcode.LIST_EXTEND
  | 0xA3 -> Opcode.SET_UPDATE
  | 0xA4 -> Opcode.DICT_MERGE
  | 0xA5 -> Opcode.DICT_UPDATE
  | _ -> Opcode.InvalidOp

/// CPython 3.10.
let private d310 = function
  | 0x01 -> Opcode.POP_TOP
  | 0x02 -> Opcode.ROT_TWO
  | 0x03 -> Opcode.ROT_THREE
  | 0x04 -> Opcode.DUP_TOP
  | 0x05 -> Opcode.DUP_TOP_TWO
  | 0x06 -> Opcode.ROT_FOUR
  | 0x09 -> Opcode.NOP
  | 0x0A -> Opcode.UNARY_POSITIVE
  | 0x0B -> Opcode.UNARY_NEGATIVE
  | 0x0C -> Opcode.UNARY_NOT
  | 0x0F -> Opcode.UNARY_INVERT
  | 0x10 -> Opcode.BINARY_MATRIX_MULTIPLY
  | 0x11 -> Opcode.INPLACE_MATRIX_MULTIPLY
  | 0x13 -> Opcode.BINARY_POWER
  | 0x14 -> Opcode.BINARY_MULTIPLY
  | 0x16 -> Opcode.BINARY_MODULO
  | 0x17 -> Opcode.BINARY_ADD
  | 0x18 -> Opcode.BINARY_SUBTRACT
  | 0x19 -> Opcode.BINARY_SUBSCR
  | 0x1A -> Opcode.BINARY_FLOOR_DIVIDE
  | 0x1B -> Opcode.BINARY_TRUE_DIVIDE
  | 0x1C -> Opcode.INPLACE_FLOOR_DIVIDE
  | 0x1D -> Opcode.INPLACE_TRUE_DIVIDE
  | 0x1E -> Opcode.GET_LEN
  | 0x1F -> Opcode.MATCH_MAPPING
  | 0x20 -> Opcode.MATCH_SEQUENCE
  | 0x21 -> Opcode.MATCH_KEYS
  | 0x22 -> Opcode.COPY_DICT_WITHOUT_KEYS
  | 0x31 -> Opcode.WITH_EXCEPT_START
  | 0x32 -> Opcode.GET_AITER
  | 0x33 -> Opcode.GET_ANEXT
  | 0x34 -> Opcode.BEFORE_ASYNC_WITH
  | 0x36 -> Opcode.END_ASYNC_FOR
  | 0x37 -> Opcode.INPLACE_ADD
  | 0x38 -> Opcode.INPLACE_SUBTRACT
  | 0x39 -> Opcode.INPLACE_MULTIPLY
  | 0x3B -> Opcode.INPLACE_MODULO
  | 0x3C -> Opcode.STORE_SUBSCR
  | 0x3D -> Opcode.DELETE_SUBSCR
  | 0x3E -> Opcode.BINARY_LSHIFT
  | 0x3F -> Opcode.BINARY_RSHIFT
  | 0x40 -> Opcode.BINARY_AND
  | 0x41 -> Opcode.BINARY_XOR
  | 0x42 -> Opcode.BINARY_OR
  | 0x43 -> Opcode.INPLACE_POWER
  | 0x44 -> Opcode.GET_ITER
  | 0x45 -> Opcode.GET_YIELD_FROM_ITER
  | 0x46 -> Opcode.PRINT_EXPR
  | 0x47 -> Opcode.LOAD_BUILD_CLASS
  | 0x48 -> Opcode.YIELD_FROM
  | 0x49 -> Opcode.GET_AWAITABLE
  | 0x4A -> Opcode.LOAD_ASSERTION_ERROR
  | 0x4B -> Opcode.INPLACE_LSHIFT
  | 0x4C -> Opcode.INPLACE_RSHIFT
  | 0x4D -> Opcode.INPLACE_AND
  | 0x4E -> Opcode.INPLACE_XOR
  | 0x4F -> Opcode.INPLACE_OR
  | 0x52 -> Opcode.LIST_TO_TUPLE
  | 0x53 -> Opcode.RETURN_VALUE
  | 0x54 -> Opcode.IMPORT_STAR
  | 0x55 -> Opcode.SETUP_ANNOTATIONS
  | 0x56 -> Opcode.YIELD_VALUE
  | 0x57 -> Opcode.POP_BLOCK
  | 0x59 -> Opcode.POP_EXCEPT
  | 0x5A -> Opcode.STORE_NAME
  | 0x5B -> Opcode.DELETE_NAME
  | 0x5C -> Opcode.UNPACK_SEQUENCE
  | 0x5D -> Opcode.FOR_ITER
  | 0x5E -> Opcode.UNPACK_EX
  | 0x5F -> Opcode.STORE_ATTR
  | 0x60 -> Opcode.DELETE_ATTR
  | 0x61 -> Opcode.STORE_GLOBAL
  | 0x62 -> Opcode.DELETE_GLOBAL
  | 0x63 -> Opcode.ROT_N
  | 0x64 -> Opcode.LOAD_CONST
  | 0x65 -> Opcode.LOAD_NAME
  | 0x66 -> Opcode.BUILD_TUPLE
  | 0x67 -> Opcode.BUILD_LIST
  | 0x68 -> Opcode.BUILD_SET
  | 0x69 -> Opcode.BUILD_MAP
  | 0x6A -> Opcode.LOAD_ATTR
  | 0x6B -> Opcode.COMPARE_OP
  | 0x6C -> Opcode.IMPORT_NAME
  | 0x6D -> Opcode.IMPORT_FROM
  | 0x6E -> Opcode.JUMP_FORWARD
  | 0x6F -> Opcode.JUMP_IF_FALSE_OR_POP
  | 0x70 -> Opcode.JUMP_IF_TRUE_OR_POP
  | 0x71 -> Opcode.JUMP_ABSOLUTE
  | 0x72 -> Opcode.POP_JUMP_IF_FALSE
  | 0x73 -> Opcode.POP_JUMP_IF_TRUE
  | 0x74 -> Opcode.LOAD_GLOBAL
  | 0x75 -> Opcode.IS_OP
  | 0x76 -> Opcode.CONTAINS_OP
  | 0x77 -> Opcode.RERAISE
  | 0x79 -> Opcode.JUMP_IF_NOT_EXC_MATCH
  | 0x7A -> Opcode.SETUP_FINALLY
  | 0x7C -> Opcode.LOAD_FAST
  | 0x7D -> Opcode.STORE_FAST
  | 0x7E -> Opcode.DELETE_FAST
  | 0x81 -> Opcode.GEN_START
  | 0x82 -> Opcode.RAISE_VARARGS
  | 0x83 -> Opcode.CALL_FUNCTION
  | 0x84 -> Opcode.MAKE_FUNCTION
  | 0x85 -> Opcode.BUILD_SLICE
  | 0x87 -> Opcode.LOAD_CLOSURE
  | 0x88 -> Opcode.LOAD_DEREF
  | 0x89 -> Opcode.STORE_DEREF
  | 0x8A -> Opcode.DELETE_DEREF
  | 0x8D -> Opcode.CALL_FUNCTION_KW
  | 0x8E -> Opcode.CALL_FUNCTION_EX
  | 0x8F -> Opcode.SETUP_WITH
  | 0x90 -> Opcode.EXTENDED_ARG
  | 0x91 -> Opcode.LIST_APPEND
  | 0x92 -> Opcode.SET_ADD
  | 0x93 -> Opcode.MAP_ADD
  | 0x94 -> Opcode.LOAD_CLASSDEREF
  | 0x98 -> Opcode.MATCH_CLASS
  | 0x9A -> Opcode.SETUP_ASYNC_WITH
  | 0x9B -> Opcode.FORMAT_VALUE
  | 0x9C -> Opcode.BUILD_CONST_KEY_MAP
  | 0x9D -> Opcode.BUILD_STRING
  | 0xA0 -> Opcode.LOAD_METHOD
  | 0xA1 -> Opcode.CALL_METHOD
  | 0xA2 -> Opcode.LIST_EXTEND
  | 0xA3 -> Opcode.SET_UPDATE
  | 0xA4 -> Opcode.DICT_MERGE
  | 0xA5 -> Opcode.DICT_UPDATE
  | _ -> Opcode.InvalidOp

/// CPython 3.11.
let private d311 = function
  | 0x00 -> Opcode.CACHE
  | 0x01 -> Opcode.POP_TOP
  | 0x02 -> Opcode.PUSH_NULL
  | 0x09 -> Opcode.NOP
  | 0x0A -> Opcode.UNARY_POSITIVE
  | 0x0B -> Opcode.UNARY_NEGATIVE
  | 0x0C -> Opcode.UNARY_NOT
  | 0x0F -> Opcode.UNARY_INVERT
  | 0x19 -> Opcode.BINARY_SUBSCR
  | 0x1E -> Opcode.GET_LEN
  | 0x1F -> Opcode.MATCH_MAPPING
  | 0x20 -> Opcode.MATCH_SEQUENCE
  | 0x21 -> Opcode.MATCH_KEYS
  | 0x23 -> Opcode.PUSH_EXC_INFO
  | 0x24 -> Opcode.CHECK_EXC_MATCH
  | 0x25 -> Opcode.CHECK_EG_MATCH
  | 0x31 -> Opcode.WITH_EXCEPT_START
  | 0x32 -> Opcode.GET_AITER
  | 0x33 -> Opcode.GET_ANEXT
  | 0x34 -> Opcode.BEFORE_ASYNC_WITH
  | 0x35 -> Opcode.BEFORE_WITH
  | 0x36 -> Opcode.END_ASYNC_FOR
  | 0x3C -> Opcode.STORE_SUBSCR
  | 0x3D -> Opcode.DELETE_SUBSCR
  | 0x44 -> Opcode.GET_ITER
  | 0x45 -> Opcode.GET_YIELD_FROM_ITER
  | 0x46 -> Opcode.PRINT_EXPR
  | 0x47 -> Opcode.LOAD_BUILD_CLASS
  | 0x4A -> Opcode.LOAD_ASSERTION_ERROR
  | 0x4B -> Opcode.RETURN_GENERATOR
  | 0x52 -> Opcode.LIST_TO_TUPLE
  | 0x53 -> Opcode.RETURN_VALUE
  | 0x54 -> Opcode.IMPORT_STAR
  | 0x55 -> Opcode.SETUP_ANNOTATIONS
  | 0x56 -> Opcode.YIELD_VALUE
  | 0x57 -> Opcode.ASYNC_GEN_WRAP
  | 0x58 -> Opcode.PREP_RERAISE_STAR
  | 0x59 -> Opcode.POP_EXCEPT
  | 0x5A -> Opcode.STORE_NAME
  | 0x5B -> Opcode.DELETE_NAME
  | 0x5C -> Opcode.UNPACK_SEQUENCE
  | 0x5D -> Opcode.FOR_ITER
  | 0x5E -> Opcode.UNPACK_EX
  | 0x5F -> Opcode.STORE_ATTR
  | 0x60 -> Opcode.DELETE_ATTR
  | 0x61 -> Opcode.STORE_GLOBAL
  | 0x62 -> Opcode.DELETE_GLOBAL
  | 0x63 -> Opcode.SWAP
  | 0x64 -> Opcode.LOAD_CONST
  | 0x65 -> Opcode.LOAD_NAME
  | 0x66 -> Opcode.BUILD_TUPLE
  | 0x67 -> Opcode.BUILD_LIST
  | 0x68 -> Opcode.BUILD_SET
  | 0x69 -> Opcode.BUILD_MAP
  | 0x6A -> Opcode.LOAD_ATTR
  | 0x6B -> Opcode.COMPARE_OP
  | 0x6C -> Opcode.IMPORT_NAME
  | 0x6D -> Opcode.IMPORT_FROM
  | 0x6E -> Opcode.JUMP_FORWARD
  | 0x6F -> Opcode.JUMP_IF_FALSE_OR_POP
  | 0x70 -> Opcode.JUMP_IF_TRUE_OR_POP
  | 0x72 -> Opcode.POP_JUMP_FORWARD_IF_FALSE
  | 0x73 -> Opcode.POP_JUMP_FORWARD_IF_TRUE
  | 0x74 -> Opcode.LOAD_GLOBAL
  | 0x75 -> Opcode.IS_OP
  | 0x76 -> Opcode.CONTAINS_OP
  | 0x77 -> Opcode.RERAISE
  | 0x78 -> Opcode.COPY
  | 0x7A -> Opcode.BINARY_OP
  | 0x7B -> Opcode.SEND
  | 0x7C -> Opcode.LOAD_FAST
  | 0x7D -> Opcode.STORE_FAST
  | 0x7E -> Opcode.DELETE_FAST
  | 0x80 -> Opcode.POP_JUMP_FORWARD_IF_NOT_NONE
  | 0x81 -> Opcode.POP_JUMP_FORWARD_IF_NONE
  | 0x82 -> Opcode.RAISE_VARARGS
  | 0x83 -> Opcode.GET_AWAITABLE
  | 0x84 -> Opcode.MAKE_FUNCTION
  | 0x85 -> Opcode.BUILD_SLICE
  | 0x86 -> Opcode.JUMP_BACKWARD_NO_INTERRUPT
  | 0x87 -> Opcode.MAKE_CELL
  | 0x88 -> Opcode.LOAD_CLOSURE
  | 0x89 -> Opcode.LOAD_DEREF
  | 0x8A -> Opcode.STORE_DEREF
  | 0x8B -> Opcode.DELETE_DEREF
  | 0x8C -> Opcode.JUMP_BACKWARD
  | 0x8E -> Opcode.CALL_FUNCTION_EX
  | 0x90 -> Opcode.EXTENDED_ARG
  | 0x91 -> Opcode.LIST_APPEND
  | 0x92 -> Opcode.SET_ADD
  | 0x93 -> Opcode.MAP_ADD
  | 0x94 -> Opcode.LOAD_CLASSDEREF
  | 0x95 -> Opcode.COPY_FREE_VARS
  | 0x97 -> Opcode.RESUME
  | 0x98 -> Opcode.MATCH_CLASS
  | 0x9B -> Opcode.FORMAT_VALUE
  | 0x9C -> Opcode.BUILD_CONST_KEY_MAP
  | 0x9D -> Opcode.BUILD_STRING
  | 0xA0 -> Opcode.LOAD_METHOD
  | 0xA2 -> Opcode.LIST_EXTEND
  | 0xA3 -> Opcode.SET_UPDATE
  | 0xA4 -> Opcode.DICT_MERGE
  | 0xA5 -> Opcode.DICT_UPDATE
  | 0xA6 -> Opcode.PRECALL
  | 0xAB -> Opcode.CALL
  | 0xAC -> Opcode.KW_NAMES
  | 0xAD -> Opcode.POP_JUMP_BACKWARD_IF_NOT_NONE
  | 0xAE -> Opcode.POP_JUMP_BACKWARD_IF_NONE
  | 0xAF -> Opcode.POP_JUMP_BACKWARD_IF_FALSE
  | 0xB0 -> Opcode.POP_JUMP_BACKWARD_IF_TRUE
  | _ -> Opcode.InvalidOp

/// CPython 3.12.
let private d312 = function
  | 0x00 -> Opcode.CACHE
  | 0x01 -> Opcode.POP_TOP
  | 0x02 -> Opcode.PUSH_NULL
  | 0x03 -> Opcode.INTERPRETER_EXIT
  | 0x04 -> Opcode.END_FOR
  | 0x05 -> Opcode.END_SEND
  | 0x09 -> Opcode.NOP
  | 0x0B -> Opcode.UNARY_NEGATIVE
  | 0x0C -> Opcode.UNARY_NOT
  | 0x0F -> Opcode.UNARY_INVERT
  | 0x11 -> Opcode.RESERVED
  | 0x19 -> Opcode.BINARY_SUBSCR
  | 0x1A -> Opcode.BINARY_SLICE
  | 0x1B -> Opcode.STORE_SLICE
  | 0x1E -> Opcode.GET_LEN
  | 0x1F -> Opcode.MATCH_MAPPING
  | 0x20 -> Opcode.MATCH_SEQUENCE
  | 0x21 -> Opcode.MATCH_KEYS
  | 0x23 -> Opcode.PUSH_EXC_INFO
  | 0x24 -> Opcode.CHECK_EXC_MATCH
  | 0x25 -> Opcode.CHECK_EG_MATCH
  | 0x31 -> Opcode.WITH_EXCEPT_START
  | 0x32 -> Opcode.GET_AITER
  | 0x33 -> Opcode.GET_ANEXT
  | 0x34 -> Opcode.BEFORE_ASYNC_WITH
  | 0x35 -> Opcode.BEFORE_WITH
  | 0x36 -> Opcode.END_ASYNC_FOR
  | 0x37 -> Opcode.CLEANUP_THROW
  | 0x3C -> Opcode.STORE_SUBSCR
  | 0x3D -> Opcode.DELETE_SUBSCR
  | 0x44 -> Opcode.GET_ITER
  | 0x45 -> Opcode.GET_YIELD_FROM_ITER
  | 0x47 -> Opcode.LOAD_BUILD_CLASS
  | 0x4A -> Opcode.LOAD_ASSERTION_ERROR
  | 0x4B -> Opcode.RETURN_GENERATOR
  | 0x53 -> Opcode.RETURN_VALUE
  | 0x55 -> Opcode.SETUP_ANNOTATIONS
  | 0x57 -> Opcode.LOAD_LOCALS
  | 0x59 -> Opcode.POP_EXCEPT
  | 0x5A -> Opcode.STORE_NAME
  | 0x5B -> Opcode.DELETE_NAME
  | 0x5C -> Opcode.UNPACK_SEQUENCE
  | 0x5D -> Opcode.FOR_ITER
  | 0x5E -> Opcode.UNPACK_EX
  | 0x5F -> Opcode.STORE_ATTR
  | 0x60 -> Opcode.DELETE_ATTR
  | 0x61 -> Opcode.STORE_GLOBAL
  | 0x62 -> Opcode.DELETE_GLOBAL
  | 0x63 -> Opcode.SWAP
  | 0x64 -> Opcode.LOAD_CONST
  | 0x65 -> Opcode.LOAD_NAME
  | 0x66 -> Opcode.BUILD_TUPLE
  | 0x67 -> Opcode.BUILD_LIST
  | 0x68 -> Opcode.BUILD_SET
  | 0x69 -> Opcode.BUILD_MAP
  | 0x6A -> Opcode.LOAD_ATTR
  | 0x6B -> Opcode.COMPARE_OP
  | 0x6C -> Opcode.IMPORT_NAME
  | 0x6D -> Opcode.IMPORT_FROM
  | 0x6E -> Opcode.JUMP_FORWARD
  | 0x72 -> Opcode.POP_JUMP_IF_FALSE
  | 0x73 -> Opcode.POP_JUMP_IF_TRUE
  | 0x74 -> Opcode.LOAD_GLOBAL
  | 0x75 -> Opcode.IS_OP
  | 0x76 -> Opcode.CONTAINS_OP
  | 0x77 -> Opcode.RERAISE
  | 0x78 -> Opcode.COPY
  | 0x79 -> Opcode.RETURN_CONST
  | 0x7A -> Opcode.BINARY_OP
  | 0x7B -> Opcode.SEND
  | 0x7C -> Opcode.LOAD_FAST
  | 0x7D -> Opcode.STORE_FAST
  | 0x7E -> Opcode.DELETE_FAST
  | 0x7F -> Opcode.LOAD_FAST_CHECK
  | 0x80 -> Opcode.POP_JUMP_IF_NOT_NONE
  | 0x81 -> Opcode.POP_JUMP_IF_NONE
  | 0x82 -> Opcode.RAISE_VARARGS
  | 0x83 -> Opcode.GET_AWAITABLE
  | 0x84 -> Opcode.MAKE_FUNCTION
  | 0x85 -> Opcode.BUILD_SLICE
  | 0x86 -> Opcode.JUMP_BACKWARD_NO_INTERRUPT
  | 0x87 -> Opcode.MAKE_CELL
  | 0x88 -> Opcode.LOAD_CLOSURE
  | 0x89 -> Opcode.LOAD_DEREF
  | 0x8A -> Opcode.STORE_DEREF
  | 0x8B -> Opcode.DELETE_DEREF
  | 0x8C -> Opcode.JUMP_BACKWARD
  | 0x8D -> Opcode.LOAD_SUPER_ATTR
  | 0x8E -> Opcode.CALL_FUNCTION_EX
  | 0x8F -> Opcode.LOAD_FAST_AND_CLEAR
  | 0x90 -> Opcode.EXTENDED_ARG
  | 0x91 -> Opcode.LIST_APPEND
  | 0x92 -> Opcode.SET_ADD
  | 0x93 -> Opcode.MAP_ADD
  | 0x95 -> Opcode.COPY_FREE_VARS
  | 0x96 -> Opcode.YIELD_VALUE
  | 0x97 -> Opcode.RESUME
  | 0x98 -> Opcode.MATCH_CLASS
  | 0x9B -> Opcode.FORMAT_VALUE
  | 0x9C -> Opcode.BUILD_CONST_KEY_MAP
  | 0x9D -> Opcode.BUILD_STRING
  | 0xA2 -> Opcode.LIST_EXTEND
  | 0xA3 -> Opcode.SET_UPDATE
  | 0xA4 -> Opcode.DICT_MERGE
  | 0xA5 -> Opcode.DICT_UPDATE
  | 0xAB -> Opcode.CALL
  | 0xAC -> Opcode.KW_NAMES
  | 0xAD -> Opcode.CALL_INTRINSIC_1
  | 0xAE -> Opcode.CALL_INTRINSIC_2
  | 0xAF -> Opcode.LOAD_FROM_DICT_OR_GLOBALS
  | 0xB0 -> Opcode.LOAD_FROM_DICT_OR_DEREF
  | 0xED -> Opcode.INSTRUMENTED_LOAD_SUPER_ATTR
  | 0xEE -> Opcode.INSTRUMENTED_POP_JUMP_IF_NONE
  | 0xEF -> Opcode.INSTRUMENTED_POP_JUMP_IF_NOT_NONE
  | 0xF0 -> Opcode.INSTRUMENTED_RESUME
  | 0xF1 -> Opcode.INSTRUMENTED_CALL
  | 0xF2 -> Opcode.INSTRUMENTED_RETURN_VALUE
  | 0xF3 -> Opcode.INSTRUMENTED_YIELD_VALUE
  | 0xF4 -> Opcode.INSTRUMENTED_CALL_FUNCTION_EX
  | 0xF5 -> Opcode.INSTRUMENTED_JUMP_FORWARD
  | 0xF6 -> Opcode.INSTRUMENTED_JUMP_BACKWARD
  | 0xF7 -> Opcode.INSTRUMENTED_RETURN_CONST
  | 0xF8 -> Opcode.INSTRUMENTED_FOR_ITER
  | 0xF9 -> Opcode.INSTRUMENTED_POP_JUMP_IF_FALSE
  | 0xFA -> Opcode.INSTRUMENTED_POP_JUMP_IF_TRUE
  | 0xFB -> Opcode.INSTRUMENTED_END_FOR
  | 0xFC -> Opcode.INSTRUMENTED_END_SEND
  | 0xFD -> Opcode.INSTRUMENTED_INSTRUCTION
  | 0xFE -> Opcode.INSTRUMENTED_LINE
  | _ -> Opcode.InvalidOp

/// CPython 3.13.
let private d313 = function
  | 0x00 -> Opcode.CACHE
  | 0x01 -> Opcode.BEFORE_ASYNC_WITH
  | 0x02 -> Opcode.BEFORE_WITH
  | 0x04 -> Opcode.BINARY_SLICE
  | 0x05 -> Opcode.BINARY_SUBSCR
  | 0x06 -> Opcode.CHECK_EG_MATCH
  | 0x07 -> Opcode.CHECK_EXC_MATCH
  | 0x08 -> Opcode.CLEANUP_THROW
  | 0x09 -> Opcode.DELETE_SUBSCR
  | 0x0A -> Opcode.END_ASYNC_FOR
  | 0x0B -> Opcode.END_FOR
  | 0x0C -> Opcode.END_SEND
  | 0x0D -> Opcode.EXIT_INIT_CHECK
  | 0x0E -> Opcode.FORMAT_SIMPLE
  | 0x0F -> Opcode.FORMAT_WITH_SPEC
  | 0x10 -> Opcode.GET_AITER
  | 0x11 -> Opcode.RESERVED
  | 0x12 -> Opcode.GET_ANEXT
  | 0x13 -> Opcode.GET_ITER
  | 0x14 -> Opcode.GET_LEN
  | 0x15 -> Opcode.GET_YIELD_FROM_ITER
  | 0x16 -> Opcode.INTERPRETER_EXIT
  | 0x17 -> Opcode.LOAD_ASSERTION_ERROR
  | 0x18 -> Opcode.LOAD_BUILD_CLASS
  | 0x19 -> Opcode.LOAD_LOCALS
  | 0x1A -> Opcode.MAKE_FUNCTION
  | 0x1B -> Opcode.MATCH_KEYS
  | 0x1C -> Opcode.MATCH_MAPPING
  | 0x1D -> Opcode.MATCH_SEQUENCE
  | 0x1E -> Opcode.NOP
  | 0x1F -> Opcode.POP_EXCEPT
  | 0x20 -> Opcode.POP_TOP
  | 0x21 -> Opcode.PUSH_EXC_INFO
  | 0x22 -> Opcode.PUSH_NULL
  | 0x23 -> Opcode.RETURN_GENERATOR
  | 0x24 -> Opcode.RETURN_VALUE
  | 0x25 -> Opcode.SETUP_ANNOTATIONS
  | 0x26 -> Opcode.STORE_SLICE
  | 0x27 -> Opcode.STORE_SUBSCR
  | 0x28 -> Opcode.TO_BOOL
  | 0x29 -> Opcode.UNARY_INVERT
  | 0x2A -> Opcode.UNARY_NEGATIVE
  | 0x2B -> Opcode.UNARY_NOT
  | 0x2C -> Opcode.WITH_EXCEPT_START
  | 0x2D -> Opcode.BINARY_OP
  | 0x2E -> Opcode.BUILD_CONST_KEY_MAP
  | 0x2F -> Opcode.BUILD_LIST
  | 0x30 -> Opcode.BUILD_MAP
  | 0x31 -> Opcode.BUILD_SET
  | 0x32 -> Opcode.BUILD_SLICE
  | 0x33 -> Opcode.BUILD_STRING
  | 0x34 -> Opcode.BUILD_TUPLE
  | 0x35 -> Opcode.CALL
  | 0x36 -> Opcode.CALL_FUNCTION_EX
  | 0x37 -> Opcode.CALL_INTRINSIC_1
  | 0x38 -> Opcode.CALL_INTRINSIC_2
  | 0x39 -> Opcode.CALL_KW
  | 0x3A -> Opcode.COMPARE_OP
  | 0x3B -> Opcode.CONTAINS_OP
  | 0x3C -> Opcode.CONVERT_VALUE
  | 0x3D -> Opcode.COPY
  | 0x3E -> Opcode.COPY_FREE_VARS
  | 0x3F -> Opcode.DELETE_ATTR
  | 0x40 -> Opcode.DELETE_DEREF
  | 0x41 -> Opcode.DELETE_FAST
  | 0x42 -> Opcode.DELETE_GLOBAL
  | 0x43 -> Opcode.DELETE_NAME
  | 0x44 -> Opcode.DICT_MERGE
  | 0x45 -> Opcode.DICT_UPDATE
  | 0x46 -> Opcode.ENTER_EXECUTOR
  | 0x47 -> Opcode.EXTENDED_ARG
  | 0x48 -> Opcode.FOR_ITER
  | 0x49 -> Opcode.GET_AWAITABLE
  | 0x4A -> Opcode.IMPORT_FROM
  | 0x4B -> Opcode.IMPORT_NAME
  | 0x4C -> Opcode.IS_OP
  | 0x4D -> Opcode.JUMP_BACKWARD
  | 0x4E -> Opcode.JUMP_BACKWARD_NO_INTERRUPT
  | 0x4F -> Opcode.JUMP_FORWARD
  | 0x50 -> Opcode.LIST_APPEND
  | 0x51 -> Opcode.LIST_EXTEND
  | 0x52 -> Opcode.LOAD_ATTR
  | 0x53 -> Opcode.LOAD_CONST
  | 0x54 -> Opcode.LOAD_DEREF
  | 0x55 -> Opcode.LOAD_FAST
  | 0x56 -> Opcode.LOAD_FAST_AND_CLEAR
  | 0x57 -> Opcode.LOAD_FAST_CHECK
  | 0x58 -> Opcode.LOAD_FAST_LOAD_FAST
  | 0x59 -> Opcode.LOAD_FROM_DICT_OR_DEREF
  | 0x5A -> Opcode.LOAD_FROM_DICT_OR_GLOBALS
  | 0x5B -> Opcode.LOAD_GLOBAL
  | 0x5C -> Opcode.LOAD_NAME
  | 0x5D -> Opcode.LOAD_SUPER_ATTR
  | 0x5E -> Opcode.MAKE_CELL
  | 0x5F -> Opcode.MAP_ADD
  | 0x60 -> Opcode.MATCH_CLASS
  | 0x61 -> Opcode.POP_JUMP_IF_FALSE
  | 0x62 -> Opcode.POP_JUMP_IF_NONE
  | 0x63 -> Opcode.POP_JUMP_IF_NOT_NONE
  | 0x64 -> Opcode.POP_JUMP_IF_TRUE
  | 0x65 -> Opcode.RAISE_VARARGS
  | 0x66 -> Opcode.RERAISE
  | 0x67 -> Opcode.RETURN_CONST
  | 0x68 -> Opcode.SEND
  | 0x69 -> Opcode.SET_ADD
  | 0x6A -> Opcode.SET_FUNCTION_ATTRIBUTE
  | 0x6B -> Opcode.SET_UPDATE
  | 0x6C -> Opcode.STORE_ATTR
  | 0x6D -> Opcode.STORE_DEREF
  | 0x6E -> Opcode.STORE_FAST
  | 0x6F -> Opcode.STORE_FAST_LOAD_FAST
  | 0x70 -> Opcode.STORE_FAST_STORE_FAST
  | 0x71 -> Opcode.STORE_GLOBAL
  | 0x72 -> Opcode.STORE_NAME
  | 0x73 -> Opcode.SWAP
  | 0x74 -> Opcode.UNPACK_EX
  | 0x75 -> Opcode.UNPACK_SEQUENCE
  | 0x76 -> Opcode.YIELD_VALUE
  | 0x95 -> Opcode.RESUME
  | 0xEC -> Opcode.INSTRUMENTED_RESUME
  | 0xED -> Opcode.INSTRUMENTED_END_FOR
  | 0xEE -> Opcode.INSTRUMENTED_END_SEND
  | 0xEF -> Opcode.INSTRUMENTED_RETURN_VALUE
  | 0xF0 -> Opcode.INSTRUMENTED_RETURN_CONST
  | 0xF1 -> Opcode.INSTRUMENTED_YIELD_VALUE
  | 0xF2 -> Opcode.INSTRUMENTED_LOAD_SUPER_ATTR
  | 0xF3 -> Opcode.INSTRUMENTED_FOR_ITER
  | 0xF4 -> Opcode.INSTRUMENTED_CALL
  | 0xF5 -> Opcode.INSTRUMENTED_CALL_KW
  | 0xF6 -> Opcode.INSTRUMENTED_CALL_FUNCTION_EX
  | 0xF7 -> Opcode.INSTRUMENTED_INSTRUCTION
  | 0xF8 -> Opcode.INSTRUMENTED_JUMP_FORWARD
  | 0xF9 -> Opcode.INSTRUMENTED_JUMP_BACKWARD
  | 0xFA -> Opcode.INSTRUMENTED_POP_JUMP_IF_TRUE
  | 0xFB -> Opcode.INSTRUMENTED_POP_JUMP_IF_FALSE
  | 0xFC -> Opcode.INSTRUMENTED_POP_JUMP_IF_NONE
  | 0xFD -> Opcode.INSTRUMENTED_POP_JUMP_IF_NOT_NONE
  | 0xFE -> Opcode.INSTRUMENTED_LINE
  | _ -> Opcode.InvalidOp

/// CPython 3.14.
let private d314 = function
  | 0x00 -> Opcode.CACHE
  | 0x01 -> Opcode.BINARY_SLICE
  | 0x02 -> Opcode.BUILD_TEMPLATE
  | 0x04 -> Opcode.CALL_FUNCTION_EX
  | 0x05 -> Opcode.CHECK_EG_MATCH
  | 0x06 -> Opcode.CHECK_EXC_MATCH
  | 0x07 -> Opcode.CLEANUP_THROW
  | 0x08 -> Opcode.DELETE_SUBSCR
  | 0x09 -> Opcode.END_FOR
  | 0x0A -> Opcode.END_SEND
  | 0x0B -> Opcode.EXIT_INIT_CHECK
  | 0x0C -> Opcode.FORMAT_SIMPLE
  | 0x0D -> Opcode.FORMAT_WITH_SPEC
  | 0x0E -> Opcode.GET_AITER
  | 0x0F -> Opcode.GET_ANEXT
  | 0x10 -> Opcode.GET_ITER
  | 0x11 -> Opcode.RESERVED
  | 0x12 -> Opcode.GET_LEN
  | 0x13 -> Opcode.GET_YIELD_FROM_ITER
  | 0x14 -> Opcode.INTERPRETER_EXIT
  | 0x15 -> Opcode.LOAD_BUILD_CLASS
  | 0x16 -> Opcode.LOAD_LOCALS
  | 0x17 -> Opcode.MAKE_FUNCTION
  | 0x18 -> Opcode.MATCH_KEYS
  | 0x19 -> Opcode.MATCH_MAPPING
  | 0x1A -> Opcode.MATCH_SEQUENCE
  | 0x1B -> Opcode.NOP
  | 0x1C -> Opcode.NOT_TAKEN
  | 0x1D -> Opcode.POP_EXCEPT
  | 0x1E -> Opcode.POP_ITER
  | 0x1F -> Opcode.POP_TOP
  | 0x20 -> Opcode.PUSH_EXC_INFO
  | 0x21 -> Opcode.PUSH_NULL
  | 0x22 -> Opcode.RETURN_GENERATOR
  | 0x23 -> Opcode.RETURN_VALUE
  | 0x24 -> Opcode.SETUP_ANNOTATIONS
  | 0x25 -> Opcode.STORE_SLICE
  | 0x26 -> Opcode.STORE_SUBSCR
  | 0x27 -> Opcode.TO_BOOL
  | 0x28 -> Opcode.UNARY_INVERT
  | 0x29 -> Opcode.UNARY_NEGATIVE
  | 0x2A -> Opcode.UNARY_NOT
  | 0x2B -> Opcode.WITH_EXCEPT_START
  | 0x2C -> Opcode.BINARY_OP
  | 0x2D -> Opcode.BUILD_INTERPOLATION
  | 0x2E -> Opcode.BUILD_LIST
  | 0x2F -> Opcode.BUILD_MAP
  | 0x30 -> Opcode.BUILD_SET
  | 0x31 -> Opcode.BUILD_SLICE
  | 0x32 -> Opcode.BUILD_STRING
  | 0x33 -> Opcode.BUILD_TUPLE
  | 0x34 -> Opcode.CALL
  | 0x35 -> Opcode.CALL_INTRINSIC_1
  | 0x36 -> Opcode.CALL_INTRINSIC_2
  | 0x37 -> Opcode.CALL_KW
  | 0x38 -> Opcode.COMPARE_OP
  | 0x39 -> Opcode.CONTAINS_OP
  | 0x3A -> Opcode.CONVERT_VALUE
  | 0x3B -> Opcode.COPY
  | 0x3C -> Opcode.COPY_FREE_VARS
  | 0x3D -> Opcode.DELETE_ATTR
  | 0x3E -> Opcode.DELETE_DEREF
  | 0x3F -> Opcode.DELETE_FAST
  | 0x40 -> Opcode.DELETE_GLOBAL
  | 0x41 -> Opcode.DELETE_NAME
  | 0x42 -> Opcode.DICT_MERGE
  | 0x43 -> Opcode.DICT_UPDATE
  | 0x44 -> Opcode.END_ASYNC_FOR
  | 0x45 -> Opcode.EXTENDED_ARG
  | 0x46 -> Opcode.FOR_ITER
  | 0x47 -> Opcode.GET_AWAITABLE
  | 0x48 -> Opcode.IMPORT_FROM
  | 0x49 -> Opcode.IMPORT_NAME
  | 0x4A -> Opcode.IS_OP
  | 0x4B -> Opcode.JUMP_BACKWARD
  | 0x4C -> Opcode.JUMP_BACKWARD_NO_INTERRUPT
  | 0x4D -> Opcode.JUMP_FORWARD
  | 0x4E -> Opcode.LIST_APPEND
  | 0x4F -> Opcode.LIST_EXTEND
  | 0x50 -> Opcode.LOAD_ATTR
  | 0x51 -> Opcode.LOAD_COMMON_CONSTANT
  | 0x52 -> Opcode.LOAD_CONST
  | 0x53 -> Opcode.LOAD_DEREF
  | 0x54 -> Opcode.LOAD_FAST
  | 0x55 -> Opcode.LOAD_FAST_AND_CLEAR
  | 0x56 -> Opcode.LOAD_FAST_BORROW
  | 0x57 -> Opcode.LOAD_FAST_BORROW_LOAD_FAST_BORROW
  | 0x58 -> Opcode.LOAD_FAST_CHECK
  | 0x59 -> Opcode.LOAD_FAST_LOAD_FAST
  | 0x5A -> Opcode.LOAD_FROM_DICT_OR_DEREF
  | 0x5B -> Opcode.LOAD_FROM_DICT_OR_GLOBALS
  | 0x5C -> Opcode.LOAD_GLOBAL
  | 0x5D -> Opcode.LOAD_NAME
  | 0x5E -> Opcode.LOAD_SMALL_INT
  | 0x5F -> Opcode.LOAD_SPECIAL
  | 0x60 -> Opcode.LOAD_SUPER_ATTR
  | 0x61 -> Opcode.MAKE_CELL
  | 0x62 -> Opcode.MAP_ADD
  | 0x63 -> Opcode.MATCH_CLASS
  | 0x64 -> Opcode.POP_JUMP_IF_FALSE
  | 0x65 -> Opcode.POP_JUMP_IF_NONE
  | 0x66 -> Opcode.POP_JUMP_IF_NOT_NONE
  | 0x67 -> Opcode.POP_JUMP_IF_TRUE
  | 0x68 -> Opcode.RAISE_VARARGS
  | 0x69 -> Opcode.RERAISE
  | 0x6A -> Opcode.SEND
  | 0x6B -> Opcode.SET_ADD
  | 0x6C -> Opcode.SET_FUNCTION_ATTRIBUTE
  | 0x6D -> Opcode.SET_UPDATE
  | 0x6E -> Opcode.STORE_ATTR
  | 0x6F -> Opcode.STORE_DEREF
  | 0x70 -> Opcode.STORE_FAST
  | 0x71 -> Opcode.STORE_FAST_LOAD_FAST
  | 0x72 -> Opcode.STORE_FAST_STORE_FAST
  | 0x73 -> Opcode.STORE_GLOBAL
  | 0x74 -> Opcode.STORE_NAME
  | 0x75 -> Opcode.SWAP
  | 0x76 -> Opcode.UNPACK_EX
  | 0x77 -> Opcode.UNPACK_SEQUENCE
  | 0x78 -> Opcode.YIELD_VALUE
  | 0x80 -> Opcode.RESUME
  | 0xEA -> Opcode.INSTRUMENTED_END_FOR
  | 0xEB -> Opcode.INSTRUMENTED_POP_ITER
  | 0xEC -> Opcode.INSTRUMENTED_END_SEND
  | 0xED -> Opcode.INSTRUMENTED_FOR_ITER
  | 0xEE -> Opcode.INSTRUMENTED_INSTRUCTION
  | 0xEF -> Opcode.INSTRUMENTED_JUMP_FORWARD
  | 0xF0 -> Opcode.INSTRUMENTED_NOT_TAKEN
  | 0xF1 -> Opcode.INSTRUMENTED_POP_JUMP_IF_TRUE
  | 0xF2 -> Opcode.INSTRUMENTED_POP_JUMP_IF_FALSE
  | 0xF3 -> Opcode.INSTRUMENTED_POP_JUMP_IF_NONE
  | 0xF4 -> Opcode.INSTRUMENTED_POP_JUMP_IF_NOT_NONE
  | 0xF5 -> Opcode.INSTRUMENTED_RESUME
  | 0xF6 -> Opcode.INSTRUMENTED_RETURN_VALUE
  | 0xF7 -> Opcode.INSTRUMENTED_YIELD_VALUE
  | 0xF8 -> Opcode.INSTRUMENTED_END_ASYNC_FOR
  | 0xF9 -> Opcode.INSTRUMENTED_LOAD_SUPER_ATTR
  | 0xFA -> Opcode.INSTRUMENTED_CALL
  | 0xFB -> Opcode.INSTRUMENTED_CALL_KW
  | 0xFC -> Opcode.INSTRUMENTED_CALL_FUNCTION_EX
  | 0xFD -> Opcode.INSTRUMENTED_JUMP_BACKWARD
  | 0xFE -> Opcode.INSTRUMENTED_LINE
  | 0xFF -> Opcode.ENTER_EXECUTOR
  | _ -> Opcode.InvalidOp

/// CPython 3.15.
let private d315 = function
  | 0x00 -> Opcode.CACHE
  | 0x01 -> Opcode.BINARY_SLICE
  | 0x02 -> Opcode.BUILD_TEMPLATE
  | 0x04 -> Opcode.CALL_FUNCTION_EX
  | 0x05 -> Opcode.CHECK_EG_MATCH
  | 0x06 -> Opcode.CHECK_EXC_MATCH
  | 0x07 -> Opcode.CLEANUP_THROW
  | 0x08 -> Opcode.DELETE_SUBSCR
  | 0x09 -> Opcode.END_FOR
  | 0x0A -> Opcode.END_SEND
  | 0x0B -> Opcode.EXIT_INIT_CHECK
  | 0x0C -> Opcode.FORMAT_SIMPLE
  | 0x0D -> Opcode.FORMAT_WITH_SPEC
  | 0x0E -> Opcode.GET_AITER
  | 0x0F -> Opcode.GET_ANEXT
  | 0x10 -> Opcode.GET_LEN
  | 0x11 -> Opcode.RESERVED
  | 0x12 -> Opcode.INTERPRETER_EXIT
  | 0x13 -> Opcode.LOAD_BUILD_CLASS
  | 0x14 -> Opcode.LOAD_LOCALS
  | 0x15 -> Opcode.MAKE_FUNCTION
  | 0x16 -> Opcode.MATCH_KEYS
  | 0x17 -> Opcode.MATCH_MAPPING
  | 0x18 -> Opcode.MATCH_SEQUENCE
  | 0x19 -> Opcode.NOP
  | 0x1A -> Opcode.NOT_TAKEN
  | 0x1B -> Opcode.POP_EXCEPT
  | 0x1C -> Opcode.POP_ITER
  | 0x1D -> Opcode.POP_TOP
  | 0x1E -> Opcode.PUSH_EXC_INFO
  | 0x1F -> Opcode.PUSH_NULL
  | 0x20 -> Opcode.RETURN_GENERATOR
  | 0x21 -> Opcode.RETURN_VALUE
  | 0x22 -> Opcode.SETUP_ANNOTATIONS
  | 0x23 -> Opcode.STORE_SLICE
  | 0x24 -> Opcode.STORE_SUBSCR
  | 0x25 -> Opcode.TO_BOOL
  | 0x26 -> Opcode.UNARY_INVERT
  | 0x27 -> Opcode.UNARY_NEGATIVE
  | 0x28 -> Opcode.UNARY_NOT
  | 0x29 -> Opcode.WITH_EXCEPT_START
  | 0x2A -> Opcode.BINARY_OP
  | 0x2B -> Opcode.BUILD_INTERPOLATION
  | 0x2C -> Opcode.BUILD_LIST
  | 0x2D -> Opcode.BUILD_MAP
  | 0x2E -> Opcode.BUILD_SET
  | 0x2F -> Opcode.BUILD_SLICE
  | 0x30 -> Opcode.BUILD_STRING
  | 0x31 -> Opcode.BUILD_TUPLE
  | 0x32 -> Opcode.CALL
  | 0x33 -> Opcode.CALL_INTRINSIC_1
  | 0x34 -> Opcode.CALL_INTRINSIC_2
  | 0x35 -> Opcode.CALL_KW
  | 0x36 -> Opcode.COMPARE_OP
  | 0x37 -> Opcode.CONTAINS_OP
  | 0x38 -> Opcode.CONVERT_VALUE
  | 0x39 -> Opcode.COPY
  | 0x3A -> Opcode.COPY_FREE_VARS
  | 0x3B -> Opcode.DELETE_ATTR
  | 0x3C -> Opcode.DELETE_DEREF
  | 0x3D -> Opcode.DELETE_FAST
  | 0x3E -> Opcode.DELETE_GLOBAL
  | 0x3F -> Opcode.DELETE_NAME
  | 0x40 -> Opcode.DICT_MERGE
  | 0x41 -> Opcode.DICT_UPDATE
  | 0x42 -> Opcode.END_ASYNC_FOR
  | 0x43 -> Opcode.EXTENDED_ARG
  | 0x44 -> Opcode.FOR_ITER
  | 0x45 -> Opcode.GET_AWAITABLE
  | 0x46 -> Opcode.GET_ITER
  | 0x47 -> Opcode.IMPORT_FROM
  | 0x48 -> Opcode.IMPORT_NAME
  | 0x49 -> Opcode.IS_OP
  | 0x4A -> Opcode.JUMP_BACKWARD
  | 0x4B -> Opcode.JUMP_BACKWARD_NO_INTERRUPT
  | 0x4C -> Opcode.JUMP_FORWARD
  | 0x4D -> Opcode.LIST_APPEND
  | 0x4E -> Opcode.LIST_EXTEND
  | 0x4F -> Opcode.LOAD_ATTR
  | 0x50 -> Opcode.LOAD_COMMON_CONSTANT
  | 0x51 -> Opcode.LOAD_CONST
  | 0x52 -> Opcode.LOAD_DEREF
  | 0x53 -> Opcode.LOAD_FAST
  | 0x54 -> Opcode.LOAD_FAST_AND_CLEAR
  | 0x55 -> Opcode.LOAD_FAST_BORROW
  | 0x56 -> Opcode.LOAD_FAST_BORROW_LOAD_FAST_BORROW
  | 0x57 -> Opcode.LOAD_FAST_CHECK
  | 0x58 -> Opcode.LOAD_FAST_LOAD_FAST
  | 0x59 -> Opcode.LOAD_FROM_DICT_OR_DEREF
  | 0x5A -> Opcode.LOAD_FROM_DICT_OR_GLOBALS
  | 0x5B -> Opcode.LOAD_GLOBAL
  | 0x5C -> Opcode.LOAD_NAME
  | 0x5D -> Opcode.LOAD_SMALL_INT
  | 0x5E -> Opcode.LOAD_SPECIAL
  | 0x5F -> Opcode.LOAD_SUPER_ATTR
  | 0x60 -> Opcode.MAKE_CELL
  | 0x61 -> Opcode.MAP_ADD
  | 0x62 -> Opcode.MATCH_CLASS
  | 0x63 -> Opcode.POP_JUMP_IF_FALSE
  | 0x64 -> Opcode.POP_JUMP_IF_NONE
  | 0x65 -> Opcode.POP_JUMP_IF_NOT_NONE
  | 0x66 -> Opcode.POP_JUMP_IF_TRUE
  | 0x67 -> Opcode.RAISE_VARARGS
  | 0x68 -> Opcode.RERAISE
  | 0x69 -> Opcode.SEND
  | 0x6A -> Opcode.SET_ADD
  | 0x6B -> Opcode.SET_FUNCTION_ATTRIBUTE
  | 0x6C -> Opcode.SET_UPDATE
  | 0x6D -> Opcode.STORE_ATTR
  | 0x6E -> Opcode.STORE_DEREF
  | 0x6F -> Opcode.STORE_FAST
  | 0x70 -> Opcode.STORE_FAST_LOAD_FAST
  | 0x71 -> Opcode.STORE_FAST_STORE_FAST
  | 0x72 -> Opcode.STORE_GLOBAL
  | 0x73 -> Opcode.STORE_NAME
  | 0x74 -> Opcode.SWAP
  | 0x75 -> Opcode.UNPACK_EX
  | 0x76 -> Opcode.UNPACK_SEQUENCE
  | 0x77 -> Opcode.YIELD_VALUE
  | 0x80 -> Opcode.RESUME
  | 0xE9 -> Opcode.INSTRUMENTED_END_FOR
  | 0xEA -> Opcode.INSTRUMENTED_POP_ITER
  | 0xEB -> Opcode.INSTRUMENTED_END_SEND
  | 0xEC -> Opcode.INSTRUMENTED_FOR_ITER
  | 0xED -> Opcode.INSTRUMENTED_INSTRUCTION
  | 0xEE -> Opcode.INSTRUMENTED_JUMP_FORWARD
  | 0xEF -> Opcode.INSTRUMENTED_NOT_TAKEN
  | 0xF0 -> Opcode.INSTRUMENTED_POP_JUMP_IF_TRUE
  | 0xF1 -> Opcode.INSTRUMENTED_POP_JUMP_IF_FALSE
  | 0xF2 -> Opcode.INSTRUMENTED_POP_JUMP_IF_NONE
  | 0xF3 -> Opcode.INSTRUMENTED_POP_JUMP_IF_NOT_NONE
  | 0xF4 -> Opcode.INSTRUMENTED_RESUME
  | 0xF5 -> Opcode.INSTRUMENTED_RETURN_VALUE
  | 0xF6 -> Opcode.INSTRUMENTED_YIELD_VALUE
  | 0xF7 -> Opcode.INSTRUMENTED_END_ASYNC_FOR
  | 0xF8 -> Opcode.INSTRUMENTED_LOAD_SUPER_ATTR
  | 0xF9 -> Opcode.INSTRUMENTED_CALL
  | 0xFA -> Opcode.INSTRUMENTED_CALL_KW
  | 0xFB -> Opcode.INSTRUMENTED_CALL_FUNCTION_EX
  | 0xFC -> Opcode.INSTRUMENTED_JUMP_BACKWARD
  | 0xFD -> Opcode.INSTRUMENTED_LINE
  | 0xFE -> Opcode.ENTER_EXECUTOR
  | 0xFF -> Opcode.TRACE_RECORD
  | _ -> Opcode.InvalidOp

/// The decode table of the given version.
/// The opcode a byte names in the given version, or InvalidOp when that
/// version defines no instruction with that number.
let decode version b =
  match version with
  | PythonVersion.Python300 -> d300 b
  | PythonVersion.Python301 -> d301 b
  | PythonVersion.Python302 -> d302 b
  | PythonVersion.Python303 -> d303 b
  | PythonVersion.Python304 -> d304 b
  | PythonVersion.Python305 -> d305 b
  | PythonVersion.Python306 -> d306 b
  | PythonVersion.Python307 -> d307 b
  | PythonVersion.Python308 -> d308 b
  | PythonVersion.Python309 -> d309 b
  | PythonVersion.Python310 -> d310 b
  | PythonVersion.Python311 -> d311 b
  | PythonVersion.Python312 -> d312 b
  | PythonVersion.Python313 -> d313 b
  | PythonVersion.Python314 -> d314 b
  | PythonVersion.Python315 -> d315 b
  | v -> failwithf "Unsupported Python version: %A" v

/// The byte that names the given opcode in the given version, or None when
/// that version has no such instruction.
let encode version opcode =
  let rec search b =
    if b > 0xFF then None
    elif decode version b = opcode then Some b
    else search (b + 1)
  search 0

/// Whether the opcode a byte names takes an argument. Up to 3.11 this is
/// CPython's own HAVE_ARGUMENT rule -- everything numbered 90 or above takes
/// one -- and 3.12 is where CPython replaced the rule with a table, so from
/// there on it is written out.
let private hasArg312 = function
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
  | Opcode.INSTRUMENTED_CALL
  | Opcode.INSTRUMENTED_CALL_FUNCTION_EX
  | Opcode.INSTRUMENTED_END_FOR
  | Opcode.INSTRUMENTED_END_SEND
  | Opcode.INSTRUMENTED_FOR_ITER
  | Opcode.INSTRUMENTED_INSTRUCTION
  | Opcode.INSTRUMENTED_JUMP_BACKWARD
  | Opcode.INSTRUMENTED_JUMP_FORWARD
  | Opcode.INSTRUMENTED_LINE
  | Opcode.INSTRUMENTED_LOAD_SUPER_ATTR
  | Opcode.INSTRUMENTED_POP_JUMP_IF_FALSE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_NONE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_NOT_NONE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_TRUE
  | Opcode.INSTRUMENTED_RESUME
  | Opcode.INSTRUMENTED_RETURN_CONST
  | Opcode.INSTRUMENTED_RETURN_VALUE
  | Opcode.INSTRUMENTED_YIELD_VALUE
  | Opcode.IS_OP
  | Opcode.JUMP
  | Opcode.JUMP_BACKWARD
  | Opcode.JUMP_BACKWARD_NO_INTERRUPT
  | Opcode.JUMP_FORWARD
  | Opcode.JUMP_NO_INTERRUPT
  | Opcode.KW_NAMES
  | Opcode.LIST_APPEND
  | Opcode.LIST_EXTEND
  | Opcode.LOAD_ATTR
  | Opcode.LOAD_CLOSURE
  | Opcode.LOAD_CONST
  | Opcode.LOAD_DEREF
  | Opcode.LOAD_FAST
  | Opcode.LOAD_FAST_AND_CLEAR
  | Opcode.LOAD_FAST_CHECK
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
  | Opcode.MAKE_FUNCTION
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
  | Opcode.SET_ADD
  | Opcode.SET_UPDATE
  | Opcode.STORE_ATTR
  | Opcode.STORE_DEREF
  | Opcode.STORE_FAST
  | Opcode.STORE_FAST_MAYBE_NULL
  | Opcode.STORE_GLOBAL
  | Opcode.STORE_NAME
  | Opcode.SWAP
  | Opcode.UNPACK_EX
  | Opcode.UNPACK_SEQUENCE
  | Opcode.YIELD_VALUE
    -> true
  | _ -> false

let private hasArg313 = function
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

let private hasArg314 = function
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
  | Opcode.UNPACK_EX
  | Opcode.UNPACK_SEQUENCE
  | Opcode.YIELD_VALUE
    -> true
  | _ -> false

let private hasArg315 = function
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

let hasOperand version b =
  match version with
  | PythonVersion.Python312 -> hasArg312 (decode version b)
  | PythonVersion.Python313 -> hasArg313 (decode version b)
  | PythonVersion.Python314 -> hasArg314 (decode version b)
  | PythonVersion.Python315 -> hasArg315 (decode version b)
  | _ -> b >= 90

/// How many inline cache entries follow the opcode, which is what makes an
/// instruction longer than the two bytes wordcode gives it. 3.11 is where
/// CPython began emitting them.
let private caches311 = function
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

let private caches312 = function
  | Opcode.BINARY_OP -> 1
  | Opcode.BINARY_SUBSCR -> 1
  | Opcode.CALL -> 3
  | Opcode.COMPARE_OP -> 1
  | Opcode.FOR_ITER -> 1
  | Opcode.LOAD_ATTR -> 9
  | Opcode.LOAD_GLOBAL -> 4
  | Opcode.LOAD_SUPER_ATTR -> 1
  | Opcode.SEND -> 1
  | Opcode.STORE_ATTR -> 4
  | Opcode.STORE_SUBSCR -> 1
  | Opcode.UNPACK_SEQUENCE -> 1
  | _ -> 0

let private caches313 = function
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

let private caches314 = function
  | Opcode.BINARY_OP -> 5
  | Opcode.CALL -> 3
  | Opcode.CALL_KW -> 3
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

let private caches315 = function
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

let private cachesOf version =
  match version with
  | PythonVersion.Python311 -> caches311
  | PythonVersion.Python312 -> caches312
  | PythonVersion.Python313 -> caches313
  | PythonVersion.Python314 -> caches314
  | PythonVersion.Python315 -> caches315
  | _ -> fun _ -> 0

/// How many inline cache entries follow the opcode, which is what makes an
/// instruction longer than the two bytes wordcode gives it. 3.11 is where
/// CPython began emitting them.
let cacheCount version b = cachesOf version (decode version b)

/// Whether an instruction is two bytes wide. 3.6 replaced the older encoding,
/// where an instruction with an argument was three bytes and a prefix carried
/// two of them, with wordcode.
let isWordcode version = PythonVersion.minor version >= 6

/// The encoded size of the instruction a byte names, inline caches included.
/// EXTENDED_ARG prefixes are counted by the caller.
let length version b =
  if isWordcode version then 2u + 2u * uint32 (cacheCount version b)
  elif b >= 90 then 3u
  else 1u

/// EXTENDED_ARG's own number, which prefixes a wide argument.
let extendedArg version =
  match encode version Opcode.EXTENDED_ARG with
  | Some b -> b
  | None -> failwithf "No EXTENDED_ARG in %A" version

// vim: set tw=80 sts=2 sw=2:
