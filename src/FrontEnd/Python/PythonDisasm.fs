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

module B2R2.FrontEnd.Python.Disasm

open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Python
open B2R2.FrontEnd.BinFile.Python

let opcodeToStrings = function
  | Op.CACHE -> "cache"
  | Op.POP_TOP -> "pop_top"
  | Op.PUSH_NULL -> "push_null"
  | Op.INTERPRETER_EXIT -> "interpreter_exit"
  | Op.END_FOR -> "end_for"
  | Op.END_SEND -> "end_send"
  | Op.NOP -> "nop"
  | Op.UNARY_NEGATIVE -> "unary_negative"
  | Op.UNARY_NOT -> "unary_not"
  | Op.UNARY_INVERT -> "unary_invert"
  | Op.RESERVED -> "reserved"
  | Op.BINARY_SUBSCR -> "binary_subscr"
  | Op.BINARY_SLICE -> "binary_slice"
  | Op.STORE_SLICE -> "store_slice"
  | Op.GET_LEN -> "get_len"
  | Op.MATCH_MAPPING -> "match_mapping"
  | Op.MATCH_SEQUENCE -> "match_sequence"
  | Op.MATCH_KEYS -> "match_keys"
  | Op.PUSH_EXC_INFO -> "push_exc_info"
  | Op.CHECK_EXC_MATCH -> "check_exc_match"
  | Op.CHECK_EG_MATCH -> "check_eg_match"
  | Op.WITH_EXCEPT_START -> "with_except_start"
  | Op.GET_AITER -> "get_aiter"
  | Op.GET_ANEXT -> "get_anext"
  | Op.BEFORE_ASYNC_WITH -> "before_async_with"
  | Op.BEFORE_WITH -> "before_with"
  | Op.END_ASYNC_FOR -> "end_async_for"
  | Op.CLEANUP_THROW -> "cleanup_throw"
  | Op.STORE_SUBSCR -> "store_subscr"
  | Op.DELETE_SUBSCR -> "delete_subscr"
  | Op.GET_ITER -> "get_iter"
  | Op.GET_YIELD_FROM_ITER -> "get_yield_from_iter"
  | Op.LOAD_BUILD_CLASS -> "load_build_class"
  | Op.LOAD_ASSERTION_ERROR -> "load_assertion_error"
  | Op.RETURN_GENERATOR -> "return_generator"
  | Op.RETURN_VALUE -> "return_value"
  | Op.SETUP_ANNOTATIONS -> "setup_annotations"
  | Op.LOAD_LOCALS -> "load_locals"
  | Op.POP_EXCEPT -> "pop_except"
  | Op.STORE_NAME -> "store_name"
  | Op.DELETE_NAME -> "delete_name"
  | Op.UNPACK_SEQUENCE -> "unpack_sequence"
  | Op.FOR_ITER -> "for_iter"
  | Op.UNPACK_EX -> "unpack_ex"
  | Op.STORE_ATTR -> "store_attr"
  | Op.DELETE_ATTR -> "delete_attr"
  | Op.STORE_GLOBAL -> "store_global"
  | Op.DELETE_GLOBAL -> "delete_global"
  | Op.SWAP -> "swap"
  | Op.LOAD_CONST -> "load_const"
  | Op.LOAD_NAME -> "load_name"
  | Op.BUILD_TUPLE -> "build_tuple"
  | Op.BUILD_LIST -> "build_list"
  | Op.BUILD_SET -> "build_set"
  | Op.BUILD_MAP -> "build_map"
  | Op.LOAD_ATTR -> "load_attr"
  | Op.COMPARE_OP -> "compare_op"
  | Op.IMPORT_NAME -> "import_name"
  | Op.IMPORT_FROM -> "import_from"
  | Op.JUMP_FORWARD -> "jump_forward"
  | Op.POP_JUMP_IF_FALSE -> "pop_jump_if_false"
  | Op.POP_JUMP_IF_TRUE -> "pop_jump_if_true"
  | Op.LOAD_GLOBAL -> "load_global"
  | Op.IS_OP -> "is_op"
  | Op.CONTAINS_OP -> "contains_op"
  | Op.RERAISE -> "reraise"
  | Op.COPY -> "copy"
  | Op.RETURN_CONST -> "return_const"
  | Op.BINARY_OP -> "binary_op"
  | Op.SEND -> "send"
  | Op.LOAD_FAST -> "load_fast"
  | Op.STORE_FAST -> "store_fast"
  | Op.DELETE_FAST -> "delete_fast"
  | Op.LOAD_FAST_CHECK -> "load_fast_check"
  | Op.POP_JUMP_IF_NOT_NONE -> "pop_jump_if_not_none"
  | Op.POP_JUMP_IF_NONE -> "pop_jump_if_none"
  | Op.RAISE_VARARGS -> "raise_varargs"
  | Op.GET_AWAITABLE -> "get_awaitable"
  | Op.MAKE_FUNCTION -> "make_function"
  | Op.BUILD_SLICE -> "build_slice"
  | Op.JUMP_BACKWARD_NO_INTERRUPT -> "jump_backward_no_interrupt"
  | Op.MAKE_CELL -> "make_cell"
  | Op.LOAD_CLOSURE -> "load_closure"
  | Op.LOAD_DEREF -> "load_deref"
  | Op.STORE_DEREF -> "store_deref"
  | Op.DELETE_DEREF -> "delete_deref"
  | Op.JUMP_BACKWARD -> "jump_backward"
  | Op.LOAD_SUPER_ATTR -> "load_super_attr"
  | Op.CALL_FUNCTION_EX -> "call_function_ex"
  | Op.LOAD_FAST_AND_CLEAR -> "load_fast_and_clear"
  | Op.EXTENDED_ARG -> "extended_arg"
  | Op.LIST_APPEND -> "list_append"
  | Op.SET_ADD -> "set_add"
  | Op.MAP_ADD -> "map_add"
  | Op.COPY_FREE_VARS -> "copy_free_vars"
  | Op.YIELD_VALUE -> "yield_value"
  | Op.RESUME -> "resume"
  | Op.MATCH_CLASS -> "match_class"
  | Op.FORMAT_VALUE -> "format_value"
  | Op.BUILD_CONST_KEY_MAP -> "build_const_key_map"
  | Op.BUILD_STRING -> "build_string"
  | Op.LIST_EXTEND -> "list_extend"
  | Op.SET_UPDATE -> "set_update"
  | Op.DICT_MERGE -> "dict_merge"
  | Op.DICT_UPDATE -> "dict_update"
  | Op.CALL -> "call"
  | Op.KW_NAMES -> "kw_names"
  | Op.CALL_INTRINSIC_1 -> "call_intrinsic_1"
  | Op.CALL_INTRINSIC_2 -> "call_intrinsic_2"
  | Op.LOAD_FROM_DICT_OR_GLOBALS -> "load_from_dict_or_globals"
  | Op.LOAD_FROM_DICT_OR_DEREF -> "load_from_dict_or_deref"
  | Op.INSTRUMENTED_LOAD_SUPER_ATTR -> "instrumented_load_super_attr"
  | Op.INSTRUMENTED_POP_JUMP_IF_NONE -> "instrumented_pop_jump_if_none"
  | Op.INSTRUMENTED_POP_JUMP_IF_NOT_NONE -> "instrumented_pop_jump_if_not_none"
  | Op.INSTRUMENTED_RESUME -> "instrumented_resume"
  | Op.INSTRUMENTED_CALL -> "instrumented_call"
  | Op.INSTRUMENTED_RETURN_VALUE -> "instrumented_return_value"
  | Op.INSTRUMENTED_YIELD_VALUE -> "instrumented_yield_value"
  | Op.INSTRUMENTED_CALL_FUNCTION_EX -> "instrumented_call_function_ex"
  | Op.INSTRUMENTED_JUMP_FORWARD -> "instrumented_jump_forward"
  | Op.INSTRUMENTED_JUMP_BACKWARD -> "instrumented_jump_backward"
  | Op.INSTRUMENTED_RETURN_CONST -> "instrumented_return_const"
  | Op.INSTRUMENTED_FOR_ITER -> "instrumented_for_iter"
  | Op.INSTRUMENTED_POP_JUMP_IF_FALSE -> "instrumented_pop_jump_if_false"
  | Op.INSTRUMENTED_POP_JUMP_IF_TRUE -> "instrumented_pop_jump_if_true"
  | Op.INSTRUMENTED_END_FOR -> "instrumented_end_for"
  | Op.INSTRUMENTED_END_SEND -> "instrumented_end_send"
  | Op.INSTRUMENTED_INSTRUCTION -> "instrumented_instruction"
  | Op.INSTRUMENTED_LINE -> "instrumented_line"
  | Op.SETUP_FINALLY -> "setup_finally"
  | Op.SETUP_CLEANUP -> "setup_cleanup"
  | Op.SETUP_WITH -> "setup_with"
  | Op.POP_BLOCK -> "pop_block"
  | Op.JUMP -> "jump"
  | Op.JUMP_NO_INTERRUPT -> "jump_no_interrupt"
  | Op.LOAD_METHOD -> "load_method"
  | Op.LOAD_SUPER_METHOD -> "load_super_method"
  | Op.LOAD_ZERO_SUPER_METHOD -> "load_zero_super_method"
  | Op.LOAD_ZERO_SUPER_ATTR -> "load_zero_super_attr"
  | Op.STORE_FAST_MAYBE_NULL -> "store_fast_maybe_null"
  | _ -> raise InvalidOpcodeException

let inline buildOpcode (ins: Instruction) (builder: IDisasmBuilder) =
  let opcode = opcodeToStrings ins.Opcode
  builder.Accumulate AsmWordKind.Mnemonic opcode

let toStringPyCodeObj = function
  | PyNone -> ""
  | PyInt i -> i.ToString()
  | o -> failwithf "Invalid PyCodeObj %A" o

let buildOprs (ins: Instruction) (builder: IDisasmBuilder) =
  match ins.Operands with
  | NoOperand -> ()
  | OneOperand (idx, None) | OneOperand (idx, Some PyNone) ->
    builder.Accumulate AsmWordKind.String "\t\t"
    builder.Accumulate AsmWordKind.Value (string idx)
  | OneOperand (idx, Some cons) ->
    builder.Accumulate AsmWordKind.String "\t\t"
    builder.Accumulate AsmWordKind.Value (string idx)
    builder.Accumulate AsmWordKind.String " ("
    builder.Accumulate AsmWordKind.Value (toStringPyCodeObj cons)
    builder.Accumulate AsmWordKind.String ")"
  | TwoOperands _ -> ()

let disasm (ins: Instruction) (builder: IDisasmBuilder) =
  builder.AccumulateAddrMarker ins.Address
  buildOpcode ins builder
  buildOprs ins builder
