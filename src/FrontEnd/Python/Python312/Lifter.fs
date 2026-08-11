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

module internal B2R2.FrontEnd.Python.Python312.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.Python
open B2R2.FrontEnd.Python.LifterHelpers

(* Every arm dispatches to a helper shared with the other
   versions; only which opcodes exist, and what they mean,
   is specific to 3.12. *)
let private minor = 12

let translate (binFile: PythonBinFile) (ins: Instruction) bld =
  let opcode = ins.Opcode
  match opcode with
  | Opcode.RESUME
  | Opcode.CACHE ->
    nopInstr ins bld
  (* NOP is the only no-op that can carry a genuine source-level `pass`
     statement (see PruneEmptyIf.fs / Translator.fs for why this must stay
     distinguishable from RESUME/CACHE, which never do). *)
  | Opcode.NOP ->
    namedEffect "NOP" ins bld
  (* Stack manipulation *)
  | Opcode.POP_TOP ->
    popTop ins bld
  | Opcode.PUSH_NULL ->
    pushNull ins bld
  | Opcode.END_FOR ->
    endFor ins bld
  | Opcode.END_SEND ->
    endSend ins bld
  | Opcode.COPY ->
    copy ins bld
  | Opcode.SWAP ->
    swap ins bld
  | Opcode.LOAD_CONST ->
    translateLoad "LOAD_CONST" ins bld
  | Opcode.LOAD_FAST
  | Opcode.LOAD_FAST_CHECK
  | Opcode.LOAD_FAST_AND_CLEAR ->
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
  | Opcode.LOAD_METHOD ->
    loadMethod ins bld
  | Opcode.LOAD_SUPER_ATTR ->
    loadSuperAttr ins bld
  | Opcode.LOAD_FROM_DICT_OR_GLOBALS ->
    translateLoad "LOAD_FROM_DICT_OR_GLOBALS" ins bld
  | Opcode.LOAD_FROM_DICT_OR_DEREF ->
    translateLoad "LOAD_FROM_DICT_OR_DEREF" ins bld
  | Opcode.LOAD_BUILD_CLASS ->
    loadBuildClass ins bld
  | Opcode.LOAD_ASSERTION_ERROR ->
    loadAssertionError ins bld
  | Opcode.LOAD_LOCALS ->
    namedEffect "LOAD_LOCALS" ins bld
  (* Store instructions *)
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
  | Opcode.STORE_SLICE ->
    storeSlice ins bld
  (* Delete instructions *)
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
  | Opcode.BINARY_OP ->
    binaryOp ins bld
  | Opcode.BINARY_SUBSCR ->
    binarySubscr ins bld
  | Opcode.BINARY_SLICE ->
    binarySlice ins bld
  (* Pre-3.11: each binary/inplace operator is its own opcode (see
     binaryOpDirect's own doc comment) -- the named-app strings mirror
     binaryOp's arg-index table above exactly. *)
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
  | Opcode.CALL ->
    call ins bld
  | Opcode.CALL_FUNCTION_EX ->
    callFunctionEx minor ins bld
  | Opcode.CALL_INTRINSIC_1 ->
    callIntrinsic1 ins bld
  | Opcode.CALL_INTRINSIC_2 ->
    namedEffect "CALL_INTRINSIC_2" ins bld
  | Opcode.KW_NAMES ->
    kwNames ins bld
  (* Return instructions *)
  | Opcode.INTERPRETER_EXIT
  | Opcode.RETURN_VALUE ->
    translateReturn ins bld
  | Opcode.RETURN_GENERATOR ->
    bld <!-- (ins.Address, ins.Length)
    pushToStack bld noneValue
    bld --!> ins.Length
  | Opcode.RETURN_CONST ->
    translateReturnConst ins bld
  (* Exception instructions *)
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
  | Opcode.PUSH_EXC_INFO ->
    bld <!-- (ins.Address, ins.Length)
    let exc = popFromStack bld
    pushToStack bld (AST.app "PREV_EXC_INFO" [] rt)
    pushToStack bld exc
    bld --!> ins.Length
  | Opcode.POP_EXCEPT ->
    bld <!-- (ins.Address, ins.Length)
    let exc = popFromStack bld
    bld <+ AST.extCall (AST.app "POP_EXCEPT" [ exc ] rt)
    bld --!> ins.Length
  | Opcode.CHECK_EXC_MATCH ->
    bld <!-- (ins.Address, ins.Length)
    let excType = popFromStack bld
    let exc = peekFromStack bld 0
    pushToStack bld (AST.app "CHECK_EXC_MATCH" [ exc; excType ] rt)
    bld --!> ins.Length
  | Opcode.CHECK_EG_MATCH ->
    namedEffect "CHECK_EG_MATCH" ins bld
  | Opcode.WITH_EXCEPT_START ->
    bld <!-- (ins.Address, ins.Length)
    let exc = peekFromStack bld 0
    let exitFunc = peekFromStack bld 3
    pushToStack bld (AST.app "WITH_EXCEPT_START" [ exitFunc; exc ] rt)
    bld --!> ins.Length
  | Opcode.CLEANUP_THROW ->
    (* Per CPython's own bytecodes.c: (sub_iter, last_sent_val, exc_value
       -- none, value). If TOS is a StopIteration, pops those 3 values
       and pushes back TWO: a None placeholder, then the exception's
       `value` attribute on top -- pop 3, push 2, net -1. We model only
       this success path; the re-raise path doesn't change the value
       stack (it unwinds via the exception mechanism instead). *)
    bld <!-- (ins.Address, ins.Length)
    let excValue = popFromStack bld
    let sentVal = popFromStack bld
    let gen = popFromStack bld
    pushToStack bld noneValue
    pushToStack bld (AST.app "CLEANUP_THROW" [ gen; sentVal; excValue ] rt)
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
  | Opcode.JUMP_BACKWARD
  | Opcode.JUMP_BACKWARD_NO_INTERRUPT ->
    jumpByOffset ins bld false
  (* POP_JUMP_IF_FALSE/TRUE's enum cases are shared across versions (see
     Opcode.fs), but their target ENCODING isn't: 3.12+ uses a
     forward-relative offset (condJump), while pre-3.11 uses an absolute
     word offset from the code object's own start (condJumpAbsolute) --
     see codeObjectBase's own doc comment. *)
  | Opcode.POP_JUMP_IF_FALSE ->
    if minor >= 11 then condJump ins bld false
    else condJumpAbsolute binFile ins bld false
  | Opcode.POP_JUMP_IF_TRUE ->
    if minor >= 11 then condJump ins bld true
    else condJumpAbsolute binFile ins bld true
  | Opcode.POP_JUMP_IF_NONE ->
    condJumpNone ins bld true
  | Opcode.POP_JUMP_IF_NOT_NONE ->
    condJumpNone ins bld false
  (* Pre-3.11 only (both "removed in 3.12" per Opcode.fs -- absolute
     targets, same as POP_JUMP_IF_FALSE/TRUE's own pre-3.11 encoding). *)
  | Opcode.FOR_ITER ->
    forIter minor ins bld
  | Opcode.SEND ->
    send ins bld
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
  | Opcode.BEFORE_WITH ->
    bld <!-- (ins.Address, ins.Length)
    let mgr = popFromStack bld
    pushToStack bld (exitMethod mgr)
    (* Originally, `mgr.__enter__()`, but we simplify the expression here. *)
    pushToStack bld (AST.app "__enter__" [ mgr ] rt)
    bld --!> ins.Length
  (* Pre-3.11 SETUP_FINALLY/SETUP_WITH/SETUP_ASYNC_WITH/POP_BLOCK: these
     manage a runtime BLOCK STACK (a separate structure from the eval
     stack), not exception-table entries -- 3.10 predates zero-cost
     exceptions (introduced in 3.11) entirely, so there is no exception
     table to consult for it in the first place. `ExceptionHelper.fs` and
     `Translator.fs`'s try/except/with reconstruction are built entirely
     around exception-table queries (`ExceptionTable.getHandlerChainByAddr`
     etc.), which simply don't exist for 3.10 bytecode -- so even with
     these opcodes correctly lifted to IR, HIR-level try/except/with
     reconstruction for 3.10 does not work yet; that needs its own
     block-stack-based mechanism as a separate follow-up. This only
     lifts each opcode's own EVAL-STACK effect (SETUP_WITH mirrors
     BEFORE_WITH's own mgr->__exit__+__enter__() shape exactly, since
     3.10 folds what 3.12 splits into BEFORE_WITH+SETUP_WITH into one
     opcode) faithfully, without emitting the block-stack's own implicit
     exception-jump edge at all -- so CFG discovery will not see the
     handler block as reachable via this edge (it may still be reached by
     other means, e.g. a later fallthrough). *)
  | Opcode.SETUP_WITH ->
    bld <!-- (ins.Address, ins.Length)
    let mgr = popFromStack bld
    pushToStack bld (exitMethod mgr)
    pushToStack bld (AST.app "__enter__" [ mgr ] rt)
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
  | Opcode.IMPORT_NAME ->
    importName ins bld
  | Opcode.IMPORT_FROM ->
    importFrom ins bld
  | Opcode.MAKE_FUNCTION ->
    if minor >= 11 then makeFunction ins bld else makeFunctionLegacy ins bld
  | Opcode.MAKE_CELL ->
    namedEffectWithArgs "MAKE_CELL" [ operandIndex ins ] ins bld
  | Opcode.COPY_FREE_VARS ->
    namedEffectWithArgs "COPY_FREE_VARS" [ operandIndex ins ] ins bld
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
    setUpdate ins bld
  | Opcode.DICT_MERGE ->
    dictMerge "DICT_MERGE" ins bld
  | Opcode.DICT_UPDATE ->
    dictMerge "DICT_UPDATE" ins bld
  (* Pattern matching instructions *)
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
