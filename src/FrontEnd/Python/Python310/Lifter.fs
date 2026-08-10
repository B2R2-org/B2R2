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

module internal B2R2.FrontEnd.Python.Python310.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.Python
open B2R2.FrontEnd.Python.LifterHelpers

(* Every arm dispatches to a helper shared with the other
   versions; only which opcodes exist, and what they mean,
   is specific to 3.10. *)
let private minor = 10

let translate (binFile: PythonBinFile) (ins: Instruction) bld =
  let opcode: Opcode = LanguagePrimitives.EnumOfValue ins.Opcode
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
  | Opcode.ROT_N ->
    rotateTopToBottom (getIntArg ins) ins bld
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
  | Opcode.LOAD_ASSERTION_ERROR ->
    loadAssertionError ins bld
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
    binaryOpDirect (AST.binop BinOpType.ADD) ins bld
  | Opcode.BINARY_SUBTRACT ->
    binaryOpDirect (AST.binop BinOpType.SUB) ins bld
  | Opcode.BINARY_MULTIPLY ->
    binaryOpDirect (AST.binop BinOpType.MUL) ins bld
  | Opcode.BINARY_MODULO ->
    binaryOpDirect (AST.binop BinOpType.MOD) ins bld
  | Opcode.BINARY_FLOOR_DIVIDE ->
    binaryOpDirect (fun l r -> AST.app "//" [ l; r ] rt) ins bld
  | Opcode.BINARY_TRUE_DIVIDE ->
    binaryOpDirect (AST.binop BinOpType.DIV) ins bld
  | Opcode.BINARY_POWER ->
    binaryOpDirect (fun l r -> AST.app "**" [ l; r ] rt) ins bld
  | Opcode.BINARY_MATRIX_MULTIPLY ->
    binaryOpDirect (fun l r -> AST.app "@" [ l; r ] rt) ins bld
  | Opcode.BINARY_LSHIFT ->
    binaryOpDirect (AST.binop BinOpType.SHL) ins bld
  | Opcode.BINARY_RSHIFT ->
    binaryOpDirect (AST.binop BinOpType.SAR) ins bld
  | Opcode.BINARY_AND ->
    binaryOpDirect (AST.binop BinOpType.AND) ins bld
  | Opcode.BINARY_OR ->
    binaryOpDirect (AST.binop BinOpType.OR) ins bld
  | Opcode.BINARY_XOR ->
    binaryOpDirect (AST.binop BinOpType.XOR) ins bld
  | Opcode.INPLACE_ADD ->
    binaryOpDirect (fun l r -> AST.app "IADD" [ l; r ] rt) ins bld
  | Opcode.INPLACE_SUBTRACT ->
    binaryOpDirect (fun l r -> AST.app "ISUB" [ l; r ] rt) ins bld
  | Opcode.INPLACE_MULTIPLY ->
    binaryOpDirect (fun l r -> AST.app "IMUL" [ l; r ] rt) ins bld
  | Opcode.INPLACE_MODULO ->
    binaryOpDirect (fun l r -> AST.app "IMOD" [ l; r ] rt) ins bld
  | Opcode.INPLACE_FLOOR_DIVIDE ->
    binaryOpDirect (fun l r -> AST.app "IFLOORDIV" [ l; r ] rt) ins bld
  | Opcode.INPLACE_TRUE_DIVIDE ->
    binaryOpDirect (fun l r -> AST.app "IDIV" [ l; r ] rt) ins bld
  | Opcode.INPLACE_POWER ->
    binaryOpDirect (fun l r -> AST.app "IPOW" [ l; r ] rt) ins bld
  | Opcode.INPLACE_MATRIX_MULTIPLY ->
    binaryOpDirect (fun l r -> AST.app "IMATMUL" [ l; r ] rt) ins bld
  | Opcode.INPLACE_LSHIFT ->
    binaryOpDirect (fun l r -> AST.app "ILSHIFT" [ l; r ] rt) ins bld
  | Opcode.INPLACE_RSHIFT ->
    binaryOpDirect (fun l r -> AST.app "IRSHIFT" [ l; r ] rt) ins bld
  | Opcode.INPLACE_AND ->
    binaryOpDirect (fun l r -> AST.app "IBITAND" [ l; r ] rt) ins bld
  | Opcode.INPLACE_OR ->
    binaryOpDirect (fun l r -> AST.app "IBITOR" [ l; r ] rt) ins bld
  | Opcode.INPLACE_XOR ->
    binaryOpDirect (fun l r -> AST.app "IBITXOR" [ l; r ] rt) ins bld
  (* Compare / identity / membership *)
  | Opcode.COMPARE_OP ->
    compareOP minor ins bld
  | Opcode.IS_OP ->
    isOp ins bld
  | Opcode.CONTAINS_OP ->
    containsOp ins bld
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
  | Opcode.RERAISE ->
    bld <!-- (ins.Address, ins.Length)
    let arg = getIntArg ins
    let exc = popFromStack bld
    if arg <> 0 then discardTOS bld else ()
    bld <+ AST.extCall (AST.app "RERAISE" [ exc ] rt)
    bld <+ AST.sideEffect SideEffect.Terminate
    bld --!> ins.Length
  | Opcode.POP_EXCEPT ->
    bld <!-- (ins.Address, ins.Length)
    let exc = popFromStack bld
    bld <+ AST.extCall (AST.app "POP_EXCEPT" [ exc ] rt)
    bld --!> ins.Length
  | Opcode.WITH_EXCEPT_START ->
    bld <!-- (ins.Address, ins.Length)
    let exc = peekFromStack bld 0
    let exitFunc = peekFromStack bld 3
    pushToStack bld (AST.app "WITH_EXCEPT_START" [ exitFunc; exc ] rt)
    bld --!> ins.Length
  | Opcode.END_ASYNC_FOR ->
    bld <!-- (ins.Address, ins.Length)
    let exc = popFromStack bld
    let aiter = popFromStack bld
    bld <+ AST.extCall (AST.app "END_ASYNC_FOR" [ aiter; exc ] rt)
    bld --!> ins.Length
  (* Jump instructions *)
  | Opcode.JUMP_FORWARD ->
    jumpByOffset ins bld true
  | Opcode.POP_JUMP_IF_FALSE ->
    if minor >= 11 then condJump ins bld false
    else condJumpAbsolute binFile ins bld false
  | Opcode.POP_JUMP_IF_TRUE ->
    if minor >= 11 then condJump ins bld true
    else condJumpAbsolute binFile ins bld true
  | Opcode.JUMP_ABSOLUTE ->
    jumpAbsolute binFile ins bld
  | Opcode.JUMP_IF_FALSE_OR_POP ->
    jumpOrPop binFile ins bld false
  | Opcode.JUMP_IF_TRUE_OR_POP ->
    jumpOrPop binFile ins bld true
  | Opcode.JUMP_IF_NOT_EXC_MATCH ->
    jumpIfNotExcMatch binFile ins bld
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
       target this opcode also records (see this case group's own doc
       comment above). *)
    bld <!-- (ins.Address, ins.Length)
    let enterResult = popFromStack bld
    pushToStack bld enterResult
    bld --!> ins.Length
  | Opcode.SETUP_FINALLY ->
    bld <!-- (ins.Address, ins.Length)
    let n = getIntArg ins
    let target = codeObjectBase binFile ins.Address + uint64 (n * 2)
    let targetExpr = AST.num (BitVector(target, rt))
    bld <+ AST.extCall (AST.app "SETUP_FINALLY" [ targetExpr ] rt)
    bld --!> ins.Length
  | Opcode.POP_BLOCK ->
    namedEffect "POP_BLOCK" ins bld
  | Opcode.GET_AWAITABLE ->
    (* Stack-neutral: pops the object to await, pushes its awaitable
       iterator (mirrors GET_ITER) -- previously a bare namedEffect with
       no pop/push, which desynced the simulated stack from here on. *)
    bld <!-- (ins.Address, ins.Length)
    let tos = popFromStack bld
    pushToStack bld (AST.app "GET_AWAITABLE" [ tos ] rt)
    bld --!> ins.Length
  | Opcode.YIELD_VALUE ->
    (* Pops the yielded value. On resume, the value pushed back is
       whatever the caller sends via `.send(x)` -- genuinely unknown at
       decompile time, not necessarily None -- so this must NOT be a
       plain `None` placeholder (that would be indistinguishable from a
       real `None` constant and silently turn `v = yield x` into
       `yield x; v = None`, discarding the received value entirely).
       Tag it with its own distinct sentinel name instead, mirroring the
       "NULL" self/callable-slot sentinel elsewhere, so
       TranslationHelper can recognize a STORE right after this as `v =
       yield x` rather than `v = None`. The following POP_TOP (if the
       yield result is unused) discards it either way. *)
    bld <!-- (ins.Address, ins.Length)
    let item = popFromStack bld
    bld <+ AST.extCall (AST.app "YIELD_VALUE" [ item ] rt)
    pushToStack bld yieldReceived
    bld --!> ins.Length
  | Opcode.YIELD_FROM ->
    yieldFrom ins bld
  (* GEN_START: pops and discards a debug-only marker distinguishing
     generator/coroutine/async-generator kind -- purely an internal
     assertion, no source-visible effect. *)
  | Opcode.GEN_START ->
    bld <!-- (ins.Address, ins.Length)
    discardTOS bld
    bld --!> ins.Length
  | Opcode.PRINT_EXPR ->
    printExpr ins bld
  | Opcode.LIST_TO_TUPLE ->
    consumeAndPush "LIST_TO_TUPLE" ins bld
  (* Import instructions *)
  | Opcode.IMPORT_NAME ->
    importName ins bld
  | Opcode.IMPORT_FROM ->
    importFrom ins bld
  | Opcode.IMPORT_STAR ->
    importStar ins bld
  (* Function / class definition *)
  | Opcode.MAKE_FUNCTION ->
    if minor >= 11 then makeFunction ins bld else makeFunctionLegacy ins bld
  | Opcode.SETUP_ANNOTATIONS ->
    namedEffect "SETUP_ANNOTATIONS" ins bld
  | Opcode.FORMAT_VALUE ->
    formatValue ins bld
  (* Unpack instructions *)
  | Opcode.UNPACK_SEQUENCE ->
    unpackSequence ins bld
  | Opcode.UNPACK_EX ->
    namedEffect "UNPACK_EX" ins bld
  (* Collection update instructions *)
  | Opcode.LIST_APPEND ->
    listAppend ins bld
  | Opcode.SET_ADD ->
    setAdd ins bld
  | Opcode.MAP_ADD ->
    mapAdd ins bld
  | Opcode.LIST_EXTEND ->
    listExtend ins bld
  | Opcode.SET_UPDATE ->
    namedEffect "SET_UPDATE" ins bld
  | Opcode.DICT_MERGE ->
    dictMerge "DICT_MERGE" ins bld
  | Opcode.DICT_UPDATE ->
    dictMerge "DICT_UPDATE" ins bld
  (* Pattern matching instructions *)
  | Opcode.COPY_DICT_WITHOUT_KEYS ->
    copyDictWithoutKeys ins bld
  | Opcode.GET_LEN ->
    bld <!-- (ins.Address, ins.Length)
    let obj = peekFromStack bld 0
    pushToStack bld (AST.app "GET_LEN" [ obj ] rt)
    bld --!> ins.Length
  | Opcode.MATCH_MAPPING ->
    bld <!-- (ins.Address, ins.Length)
    let subject = peekFromStack bld 0
    pushToStack bld (AST.app "MATCH_MAPPING" [ subject ] rt)
    bld --!> ins.Length
  | Opcode.MATCH_SEQUENCE ->
    bld <!-- (ins.Address, ins.Length)
    let subject = peekFromStack bld 0
    pushToStack bld (AST.app "MATCH_SEQUENCE" [ subject ] rt)
    bld --!> ins.Length
  | Opcode.MATCH_KEYS ->
    bld <!-- (ins.Address, ins.Length)
    let keys = peekFromStack bld 0
    let subject = peekFromStack bld 1
    pushToStack bld (AST.app "MATCH_KEYS_VALUES" [ subject; keys ] rt)
    pushToStack bld (AST.app "MATCH_KEYS" [ subject; keys ] rt)
    bld --!> ins.Length
  | Opcode.MATCH_CLASS ->
    bld <!-- (ins.Address, ins.Length)
    let names = popFromStack bld
    let cls = popFromStack bld
    let subject = peekFromStack bld 0
    pushToStack bld (AST.app "MATCH_CLASS_ATTRS" [ subject; cls; names ] rt)
    pushToStack bld (AST.app "MATCH_CLASS" [ subject; cls; names ] rt)
    bld --!> ins.Length
  | _ ->
    Terminator.futureFeature ()
