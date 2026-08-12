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

module internal B2R2.FrontEnd.Python.Python308.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.Python
open B2R2.FrontEnd.Python.LifterHelpers

(* Every arm dispatches to a helper shared with the other
   versions; only which opcodes exist, and what they mean,
   is specific to 3.8. *)
let private minor = 8

(* SETUP_FINALLY pushes a block whose handler is a relative target. 3.8
   folded 3.7's SETUP_EXCEPT into it and dropped SETUP_LOOP outright, so
   this is the only block setup left that carries one. *)
let private setupBlock name (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let n = getIntArg ins * jumpArgScale ins
  let target = ins.Address + uint64 ins.Length + uint64 n
  bld <+ AST.extCall (AST.app name [ AST.num (BitVector(target, rt)) ] rt)
  bld --!> ins.Length

(* COMPARE_OP still carries the identity, membership and exception-match
   comparisons that 3.9 split out into IS_OP, CONTAINS_OP and
   JUMP_IF_NOT_EXC_MATCH, so its argument indexes an 11-entry cmp_op table
   rather than the six relational operators the shared cmpOpName knows.
   Names match those later opcodes' own apps so HIR translation sees one
   shape across versions. *)
let private compareOp (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let idx = getIntArg ins
  let right = popFromStack bld
  let left = popFromStack bld
  let result =
    match idx with
    | 6 -> AST.app "CONTAINS_OP" [ right; left ] rt
    | 7 -> AST.app "NOT_CONTAINS_OP" [ right; left ] rt
    | 8 -> AST.app "IS_OP" [ left; right ] rt
    | 9 -> AST.app "NOT_IS_OP" [ left; right ] rt
    | 10 -> AST.app "CHECK_EXC_MATCH" [ left; right ] rt
    | _ -> opApp (cmpOpName idx) left right
  pushToStack bld result
  bld --!> ins.Length

let translate (binFile: PythonBinFile) (ins: Instruction) bld =
  let opcode = ins.Opcode
  match opcode with
  | Opcode.NOP ->
    namedEffect "NOP" ins bld
  (* Stack manipulation *)
  | Opcode.POP_TOP ->
    popTop ins bld
  | Opcode.ROT_TWO ->
    rotateTopToBottom 2 ins bld
  | Opcode.ROT_THREE ->
    rotateTopToBottom 3 ins bld
  | Opcode.ROT_FOUR ->
    rotateTopToBottom 4 ins bld
  | Opcode.DUP_TOP ->
    dupTop ins bld
  | Opcode.DUP_TOP_TWO ->
    dupTopTwo ins bld
  (* Load instructions *)
  | Opcode.LOAD_CONST ->
    translateLoad "LOAD_CONST" ins bld
  | Opcode.LOAD_FAST ->
    translateLoad "LOAD_FAST" ins bld
  | Opcode.LOAD_NAME ->
    translateLoad "LOAD_NAME" ins bld
  | Opcode.LOAD_ATTR ->
    loadAttr ins bld
  | Opcode.LOAD_GLOBAL ->
    translateLoadGlobal ins bld
  | Opcode.LOAD_DEREF ->
    translateLoad "LOAD_DEREF" ins bld
  | Opcode.LOAD_CLOSURE ->
    translateLoad "LOAD_CLOSURE" ins bld
  | Opcode.LOAD_CLASSDEREF ->
    translateLoad "LOAD_CLASSDEREF" ins bld
  | Opcode.LOAD_METHOD ->
    loadMethod ins bld
  | Opcode.LOAD_BUILD_CLASS ->
    loadBuildClass ins bld
  | Opcode.STORE_FAST ->
    storeNamed "STORE_FAST" ins bld
  | Opcode.STORE_NAME ->
    storeNamed "STORE_NAME" ins bld
  | Opcode.STORE_GLOBAL ->
    storeNamed "STORE_GLOBAL" ins bld
  | Opcode.STORE_ATTR ->
    storeAttr ins bld
  | Opcode.STORE_DEREF ->
    storeNamed "STORE_DEREF" ins bld
  | Opcode.STORE_SUBSCR ->
    storeSubscript ins bld
  | Opcode.DELETE_FAST ->
    translateDelete "DELETE_FAST" ins bld
  | Opcode.DELETE_NAME ->
    translateDelete "DELETE_NAME" ins bld
  | Opcode.DELETE_GLOBAL ->
    translateDelete "DELETE_GLOBAL" ins bld
  | Opcode.DELETE_ATTR ->
    deleteAttr ins bld
  | Opcode.DELETE_DEREF ->
    translateDelete "DELETE_DEREF" ins bld
  | Opcode.DELETE_SUBSCR ->
    deleteSubscript ins bld
  (* Unary operations *)
  | Opcode.UNARY_NEGATIVE ->
    unaryOp "UNARY_NEGATIVE" ins bld
  | Opcode.UNARY_NOT ->
    unaryOp "UNARY_NOT" ins bld
  | Opcode.UNARY_INVERT ->
    unaryOp "UNARY_INVERT" ins bld
  | Opcode.UNARY_POSITIVE ->
    unaryOp "UNARY_POSITIVE" ins bld
  (* Binary / slice operations *)
  | Opcode.BINARY_SUBSCR ->
    binarySubscr ins bld
  | Opcode.BINARY_ADD ->
    binaryOpDirect (opApp "+") ins bld
  | Opcode.BINARY_SUBTRACT ->
    binaryOpDirect (opApp "-") ins bld
  | Opcode.BINARY_MULTIPLY ->
    binaryOpDirect (opApp "*") ins bld
  | Opcode.BINARY_MODULO ->
    binaryOpDirect (opApp "%") ins bld
  | Opcode.BINARY_FLOOR_DIVIDE ->
    binaryOpDirect (opApp "//") ins bld
  | Opcode.BINARY_TRUE_DIVIDE ->
    binaryOpDirect (opApp "/") ins bld
  | Opcode.BINARY_POWER ->
    binaryOpDirect (opApp "**") ins bld
  | Opcode.BINARY_MATRIX_MULTIPLY ->
    binaryOpDirect (opApp "@") ins bld
  | Opcode.BINARY_LSHIFT ->
    binaryOpDirect (opApp "<<") ins bld
  | Opcode.BINARY_RSHIFT ->
    binaryOpDirect (opApp ">>") ins bld
  | Opcode.BINARY_AND ->
    binaryOpDirect (opApp "&") ins bld
  | Opcode.BINARY_OR ->
    binaryOpDirect (opApp "|") ins bld
  | Opcode.BINARY_XOR ->
    binaryOpDirect (opApp "^") ins bld
  | Opcode.INPLACE_ADD ->
    binaryOpDirect (opApp "IADD") ins bld
  | Opcode.INPLACE_SUBTRACT ->
    binaryOpDirect (opApp "ISUB") ins bld
  | Opcode.INPLACE_MULTIPLY ->
    binaryOpDirect (opApp "IMUL") ins bld
  | Opcode.INPLACE_MODULO ->
    binaryOpDirect (opApp "IMOD") ins bld
  | Opcode.INPLACE_FLOOR_DIVIDE ->
    binaryOpDirect (opApp "IFLOORDIV") ins bld
  | Opcode.INPLACE_TRUE_DIVIDE ->
    binaryOpDirect (opApp "IDIV") ins bld
  | Opcode.INPLACE_POWER ->
    binaryOpDirect (opApp "IPOW") ins bld
  | Opcode.INPLACE_MATRIX_MULTIPLY ->
    binaryOpDirect (opApp "IMATMUL") ins bld
  | Opcode.INPLACE_LSHIFT ->
    binaryOpDirect (opApp "ILSHIFT") ins bld
  | Opcode.INPLACE_RSHIFT ->
    binaryOpDirect (opApp "IRSHIFT") ins bld
  | Opcode.INPLACE_AND ->
    binaryOpDirect (opApp "IBITAND") ins bld
  | Opcode.INPLACE_OR ->
    binaryOpDirect (opApp "IBITOR") ins bld
  | Opcode.INPLACE_XOR ->
    binaryOpDirect (opApp "IBITXOR") ins bld
  (* Compare *)
  | Opcode.COMPARE_OP ->
    compareOp ins bld
  (* Build instructions *)
  | Opcode.BUILD_TUPLE ->
    buildCollection "BUILD_TUPLE" ins bld
  | Opcode.BUILD_LIST ->
    buildCollection "BUILD_LIST" ins bld
  | Opcode.BUILD_SET ->
    buildCollection "BUILD_SET" ins bld
  | Opcode.BUILD_MAP ->
    buildMap ins bld
  | Opcode.BUILD_STRING ->
    buildCollection "BUILD_STRING" ins bld
  | Opcode.BUILD_SLICE ->
    buildCollection "BUILD_SLICE" ins bld
  | Opcode.BUILD_CONST_KEY_MAP ->
    buildConstKeyMap ins bld
  (* Unpacking builders, which 3.9 replaced with LIST_EXTEND / DICT_MERGE
     and friends. *)
  | Opcode.BUILD_TUPLE_UNPACK ->
    buildCollection "BUILD_TUPLE_UNPACK" ins bld
  | Opcode.BUILD_TUPLE_UNPACK_WITH_CALL ->
    buildCollection "BUILD_TUPLE_UNPACK_WITH_CALL" ins bld
  | Opcode.BUILD_LIST_UNPACK ->
    buildCollection "BUILD_LIST_UNPACK" ins bld
  | Opcode.BUILD_SET_UNPACK ->
    buildCollection "BUILD_SET_UNPACK" ins bld
  | Opcode.BUILD_MAP_UNPACK ->
    buildCollection "BUILD_MAP_UNPACK" ins bld
  | Opcode.BUILD_MAP_UNPACK_WITH_CALL ->
    buildCollection "BUILD_MAP_UNPACK_WITH_CALL" ins bld
  (* Function call instructions *)
  | Opcode.CALL_FUNCTION ->
    callFunction ins bld
  | Opcode.CALL_FUNCTION_KW ->
    callFunctionKw ins bld
  | Opcode.CALL_METHOD ->
    callMethod ins bld
  | Opcode.CALL_FUNCTION_EX ->
    callFunctionEx minor ins bld
  | Opcode.RETURN_VALUE ->
    translateReturn ins bld
  | Opcode.RAISE_VARARGS ->
    translateRaiseVarargs ins bld
  | Opcode.POP_EXCEPT ->
    bld <!-- (ins.Address, ins.Length)
    let exc = popFromStack bld
    bld <+ AST.extCall (AST.app "POP_EXCEPT" [ exc ] rt)
    bld --!> ins.Length
  (* Jump instructions *)
  | Opcode.JUMP_FORWARD ->
    jumpByOffset ins bld true
  | Opcode.POP_JUMP_IF_FALSE ->
    condJumpAbsolute binFile ins bld false
  | Opcode.POP_JUMP_IF_TRUE ->
    condJumpAbsolute binFile ins bld true
  | Opcode.JUMP_ABSOLUTE ->
    jumpAbsolute binFile ins bld
  | Opcode.JUMP_IF_FALSE_OR_POP ->
    jumpOrPop binFile ins bld false
  | Opcode.JUMP_IF_TRUE_OR_POP ->
    jumpOrPop binFile ins bld true
  (* Iteration instructions *)
  | Opcode.FOR_ITER ->
    forIter minor ins bld
  | Opcode.GET_ITER ->
    getIter ins bld
  | Opcode.GET_YIELD_FROM_ITER ->
    getYieldFromIter ins bld
  (* Async instructions *)
  | Opcode.GET_AITER ->
    unaryOp "GET_AITER" ins bld
  | Opcode.GET_ANEXT ->
    bld <!-- (ins.Address, ins.Length)
    let aiter = popFromStack bld
    pushToStack bld aiter
    pushToStack bld (AST.app "GET_ANEXT" [ aiter ] rt)
    bld --!> ins.Length
  | Opcode.BEFORE_ASYNC_WITH ->
    namedEffect "BEFORE_ASYNC_WITH" ins bld
  | Opcode.END_ASYNC_FOR ->
    bld <!-- (ins.Address, ins.Length)
    let exc = popFromStack bld
    let aiter = popFromStack bld
    bld <+ AST.extCall (AST.app "END_ASYNC_FOR" [ aiter; exc ] rt)
    bld --!> ins.Length
  | Opcode.GET_AWAITABLE ->
    bld <!-- (ins.Address, ins.Length)
    let tos = popFromStack bld
    pushToStack bld (AST.app "GET_AWAITABLE" [ tos ] rt)
    bld --!> ins.Length
  (* Block instructions *)
  | Opcode.SETUP_FINALLY ->
    setupBlock "SETUP_FINALLY" ins bld
  | Opcode.SETUP_WITH ->
    bld <!-- (ins.Address, ins.Length)
    let mgr = popFromStack bld
    pushToStack bld (exitMethod mgr)
    pushToStack bld (AST.app "__enter__" [ mgr ] rt)
    bld --!> ins.Length
  | Opcode.SETUP_ASYNC_WITH ->
    (* The awaited `__aenter__()` result is already on the stack (from the
       preceding GET_AWAITABLE + yield-from-loop) when this runs -- pop
       and re-push it, since our model doesn't yet track the block-stack
       target this opcode also records. *)
    bld <!-- (ins.Address, ins.Length)
    let enterResult = popFromStack bld
    pushToStack bld enterResult
    bld --!> ins.Length
  | Opcode.POP_BLOCK ->
    namedEffect "POP_BLOCK" ins bld
  (* BEGIN_FINALLY pushes the NULL that marks "no exception" for the
     END_FINALLY / POP_FINALLY that consume it. *)
  | Opcode.BEGIN_FINALLY ->
    pushNull ins bld
  | Opcode.END_FINALLY ->
    namedEffect "END_FINALLY" ins bld
  | Opcode.POP_FINALLY ->
    namedEffect "POP_FINALLY" ins bld
  (* Pushes the address to resume at, then jumps into the finally
     block; END_FINALLY there pops that address and returns to it. *)
  | Opcode.CALL_FINALLY ->
    let ret = ins.Address + uint64 ins.Length
    pushToStack bld (AST.num (BitVector(ret, rt)))
    jumpByOffset ins bld true
  | Opcode.WITH_CLEANUP_START ->
    bld <!-- (ins.Address, ins.Length)
    let exitFunc = peekFromStack bld 0
    pushToStack bld (AST.app "WITH_CLEANUP_START" [ exitFunc ] rt)
    bld --!> ins.Length
  | Opcode.WITH_CLEANUP_FINISH ->
    bld <!-- (ins.Address, ins.Length)
    let res = popFromStack bld
    bld <+ AST.extCall (AST.app "WITH_CLEANUP_FINISH" [ res ] rt)
    bld --!> ins.Length
  (* Generator instructions *)
  | Opcode.YIELD_VALUE ->
    (* Pops the yielded value. On resume, the value pushed back is
       whatever the caller sends via `.send(x)` -- genuinely unknown at
       decompile time, not necessarily None -- so tag it with its own
       sentinel rather than a plain `None` placeholder. *)
    bld <!-- (ins.Address, ins.Length)
    let item = popFromStack bld
    bld <+ AST.extCall (AST.app "YIELD_VALUE" [ item ] rt)
    pushToStack bld yieldReceived
    bld --!> ins.Length
  | Opcode.YIELD_FROM ->
    yieldFrom ins bld
  | Opcode.PRINT_EXPR ->
    printExpr ins bld
  (* Import instructions *)
  | Opcode.IMPORT_NAME ->
    importName ins bld
  | Opcode.IMPORT_FROM ->
    importFrom ins bld
  | Opcode.IMPORT_STAR ->
    importStar ins bld
  (* Function / class definition *)
  | Opcode.MAKE_FUNCTION ->
    makeFunctionLegacy ins bld
  | Opcode.SETUP_ANNOTATIONS ->
    namedEffect "SETUP_ANNOTATIONS" ins bld
  | Opcode.FORMAT_VALUE ->
    formatValue ins bld
  (* Unpack instructions *)
  | Opcode.UNPACK_SEQUENCE ->
    unpackSequence ins bld
  | Opcode.UNPACK_EX ->
    unpackEx ins bld
  (* Collection update instructions *)
  | Opcode.LIST_APPEND ->
    listAppend ins bld
  | Opcode.SET_ADD ->
    setAdd ins bld
  | Opcode.MAP_ADD ->
    mapAdd ins bld
  | _ ->
    Terminator.futureFeature ()
