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

/// Turns one decoded instruction into LowUIR. Which opcodes a version has is
/// Tables.fs's answer, not this file's -- a byte only ever decodes to an
/// opcode the version defines, so an arm here is reached only by the versions
/// that actually have it. What is left for this file is the handful of
/// opcodes whose *meaning* moved: those read the minor version below, and
/// everything else lifts the same way for all sixteen.
module internal B2R2.FrontEnd.Python.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.Python
open B2R2.FrontEnd.Python.LifterHelpers

/// DUP_TOPX: 3.2 replaced it with DUP_TOP_TWO, the only count CPython ever
/// emitted for it. The copies keep their relative order.
let private dupTopN (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let items = [| for i in 0 .. getIntArg ins - 1 -> peekFromStack bld i |]
  for v in Array.rev items do pushToStack bld v
  bld --!> ins.Length

/// The two co_varnames indices a paired local opcode packs into one oparg,
/// the high nibble first -- the same split Parsing.resolveOperand makes to
/// look the two names up.
let private pairedIndices (ins: Instruction) =
  let arg = getIntArg ins
  numI32 (arg >>> 4) rt, numI32 (arg &&& 0xF) rt

/// LOAD_FAST_LOAD_FAST, LOAD_FAST_BORROW_LOAD_FAST_BORROW: one oparg, two
/// locals pushed in order.
let private loadPair (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let a, b = pairedIndices ins
  pushToStack bld (AST.app "LOAD_FAST" [ a ] rt)
  pushToStack bld (AST.app "LOAD_FAST" [ b ] rt)
  bld --!> ins.Length

/// LOAD_SMALL_INT: the oparg IS the value, not an index into anything.
let private loadSmallInt (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  pushToStack bld (numI32 (getIntArg ins) rt)
  bld --!> ins.Length

/// LOAD_COMMON_CONSTANT and LOAD_SPECIAL index a table built into the
/// interpreter, not a co_* table, so the raw index is all there is.
let private loadIndexed name (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  pushToStack bld (AST.app name [ numI32 (getIntArg ins) rt ] rt)
  bld --!> ins.Length

/// STORE_FAST_LOAD_FAST: store into the first local, then load the second.
let private storeLoadPair (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let a, b = pairedIndices ins
  let v = popFromStack bld
  bld <+ AST.extCall (AST.app "STORE_FAST" [ a; v ] rt)
  pushToStack bld (AST.app "LOAD_FAST" [ b ] rt)
  bld --!> ins.Length

/// STORE_FAST_STORE_FAST: two stores, the first taking the top of stack.
let private storePair (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let a, b = pairedIndices ins
  let first = popFromStack bld
  let second = popFromStack bld
  bld <+ AST.extCall (AST.app "STORE_FAST" [ a; first ] rt)
  bld <+ AST.extCall (AST.app "STORE_FAST" [ b; second ] rt)
  bld --!> ins.Length

/// STORE_MAP: up to 3.4 a dict display is built by pushing the dict and then
/// one value/key pair per entry, which is what 3.5's BUILD_MAP takes all at
/// once. The dict stays on the stack for the entry after this one. Named as
/// MAP_ADD, the opcode that does the same job from 3.1 on, so that HIR
/// translation sees one shape across versions.
let private storeMap (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let key = popFromStack bld
  let value = popFromStack bld
  let mp = peekFromStack bld 0
  bld <+ AST.extCall (AST.app "MAP_ADD" [ mp; key; value ] rt)
  bld --!> ins.Length

/// STORE_LOCALS: 3.0-3.3 build a class body's namespace as an ordinary
/// mapping and install it as the frame's locals with this; 3.4 replaced it
/// with LOAD_BUILD_CLASS's own protocol.
let private storeLocals (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let mapping = popFromStack bld
  bld <+ AST.extCall (AST.app "STORE_LOCALS" [ mapping ] rt)
  bld --!> ins.Length

/// TO_BOOL: 3.13 gives the truthiness test its own instruction, where 3.12
/// left it implicit inside the conditional jump.
let private toBool (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let v = popFromStack bld
  pushToStack bld (AST.app "TO_BOOL" [ v ] rt)
  bld --!> ins.Length

/// BUILD_TEMPLATE and BUILD_INTERPOLATION build a t-string (PEP 750).
let private buildFromStack name count (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let items = List.init count (fun _ -> popFromStack bld) |> List.rev
  pushToStack bld (AST.app name items rt)
  bld --!> ins.Length

/// SET_FUNCTION_ATTRIBUTE pops the attribute value, sets it on the function
/// beneath it, and leaves that function on the stack.
let private setFunctionAttribute (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let attr = popFromStack bld
  let func = popFromStack bld
  let which = numI32 (getIntArg ins) rt
  pushToStack bld (AST.app "SET_FUNCTION_ATTRIBUTE" [ func; which; attr ] rt)
  bld --!> ins.Length

/// WITH_CLEANUP: 3.5 split this into WITH_CLEANUP_START, which calls
/// __exit__, and WITH_CLEANUP_FINISH, which consumes its result. Before that
/// one opcode did both, so the pair's two stack effects cancel down to
/// popping the exit function this calls.
let private withCleanup (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let exitFunc = popFromStack bld
  bld <+ AST.extCall (AST.app "WITH_CLEANUP" [ exitFunc ] rt)
  bld --!> ins.Length

/// 3.0's JUMP_IF_FALSE and JUMP_IF_TRUE, which 3.1 replaced with the
/// POP_JUMP_IF_* and *_OR_POP pairs: unlike every conditional jump after
/// them, these leave the value they tested on the stack.
let private condJumpNoPop (ins: Instruction) bld jumpIfTrue =
  bld <!-- (ins.Address, ins.Length)
  let cond = peekFromStack bld 0
  let n = getIntArg ins * jumpArgScale ins
  let jmpDst = ins.Address + uint64 ins.Length + uint64 n
  let fallDst = ins.Address + uint64 ins.Length
  let tLbl = AST.num (BitVector(jmpDst, rt))
  let fLbl = AST.num (BitVector(fallDst, rt))
  let tLbl, fLbl = if jumpIfTrue then tLbl, fLbl else fLbl, tLbl
  bld <+ AST.intercjmp (truthOf cond) tLbl fLbl
  bld

/// SETUP_LOOP, SETUP_EXCEPT and SETUP_FINALLY each push a block whose handler
/// sits at a forward-relative target -- all three are jump-relative in every
/// version that has them, so the scale is the only thing 3.10 changes here.
let private setupBlock name (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let n = getIntArg ins * jumpArgScale ins
  let target = ins.Address + uint64 ins.Length + uint64 n
  bld <+ AST.extCall (AST.app name [ AST.num (BitVector(target, rt)) ] rt)
  bld --!> ins.Length

/// CONVERT_VALUE, FORMAT_SIMPLE and FORMAT_WITH_SPEC are 3.12's FORMAT_VALUE
/// split into three, each doing one part of what formatValue did.
let private convertValue (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let conv = numI32 (getIntArg ins) rt
  let v = popFromStack bld
  pushToStack bld (AST.app "CONVERT_VALUE" [ v; conv ] rt)
  bld --!> ins.Length

let private formatSimple (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let v = popFromStack bld
  pushToStack bld (AST.app "FORMAT_SIMPLE" [ v ] rt)
  bld --!> ins.Length

let private formatWithSpec (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let spec = popFromStack bld
  let v = popFromStack bld
  pushToStack bld (AST.app "FORMAT_WITH_SPEC" [ v; spec ] rt)
  bld --!> ins.Length

let translate (binFile: PythonBinFile) (ins: Instruction) bld =
  let minor = PythonVersion.minor ins.Version
  match ins.Opcode with
  | Opcode.RESUME
  | Opcode.INSTRUMENTED_RESUME
  | Opcode.CACHE ->
    nopInstr ins bld
  (* NOP is the only no-op that can carry a genuine source-level `pass`
     statement (see PruneEmptyIf.fs / Translator.fs for why this must stay
     distinguishable from RESUME/CACHE, which never do). *)
  | Opcode.NOP ->
    namedEffect "NOP" ins bld
  (* A branch-prediction marker with no runtime effect. *)
  | Opcode.NOT_TAKEN
  | Opcode.INSTRUMENTED_NOT_TAKEN ->
    namedEffect "NOT_TAKEN" ins bld
  (* Interpreter bookkeeping that never reaches a .pyc: RESERVED is a hole
     kept in the numbering, and the other three are written over a live code
     object at run time -- by sys.monitoring, or by the tier-2 JIT. Each
     stands in front of the instruction it replaced, whose own effect the
     INSTRUMENTED_* arms below carry, so none of them has a stack effect of
     its own to model. *)
  | Opcode.RESERVED
  | Opcode.ENTER_EXECUTOR
  | Opcode.TRACE_RECORD
  | Opcode.INSTRUMENTED_LINE
  | Opcode.INSTRUMENTED_INSTRUCTION ->
    namedEffect "INSTRUMENTATION" ins bld
  (* 3.2 dropped this marker for the end of a code object; it names no
     instruction the interpreter ever executes. *)
  | Opcode.STOP_CODE ->
    namedEffect "STOP_CODE" ins bld
  (* Stack manipulation *)
  | Opcode.POP_TOP
  | Opcode.POP_ITER
  | Opcode.INSTRUMENTED_POP_ITER ->
    popTop ins bld
  | Opcode.PUSH_NULL ->
    pushNull ins bld
  | Opcode.END_FOR
  | Opcode.INSTRUMENTED_END_FOR ->
    endFor ins bld
  | Opcode.END_SEND
  | Opcode.INSTRUMENTED_END_SEND ->
    endSend ins bld
  | Opcode.COPY ->
    copy ins bld
  | Opcode.SWAP ->
    swap ins bld
  (* 3.11 replaced the fixed-depth rotations with COPY and SWAP. *)
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
  | Opcode.DUP_TOPX ->
    dupTopN ins bld
  (* Load instructions *)
  | Opcode.LOAD_CONST ->
    translateLoad "LOAD_CONST" ins bld
  | Opcode.LOAD_FAST
  | Opcode.LOAD_FAST_CHECK ->
    translateLoad "LOAD_FAST" ins bld
  (* A borrowed reference: same value, one fewer refcount bump. *)
  | Opcode.LOAD_FAST_BORROW ->
    translateLoad "LOAD_FAST" ins bld
  (* Its own name, not LOAD_FAST's: an inlined comprehension reads the slot it
     is about to borrow, and that slot is very often unset -- which for a plain
     LOAD_FAST is an unbound local and an error worth reporting. *)
  | Opcode.LOAD_FAST_AND_CLEAR ->
    translateLoad "LOAD_FAST_AND_CLEAR" ins bld
  | Opcode.LOAD_FAST_LOAD_FAST
  | Opcode.LOAD_FAST_BORROW_LOAD_FAST_BORROW ->
    loadPair ins bld
  | Opcode.LOAD_NAME ->
    translateLoad "LOAD_NAME" ins bld
  | Opcode.LOAD_ATTR ->
    loadAttr ins bld
  | Opcode.LOAD_METHOD ->
    loadMethod ins bld
  | Opcode.LOAD_GLOBAL ->
    translateLoadGlobal ins bld
  | Opcode.LOAD_DEREF ->
    translateLoad "LOAD_DEREF" ins bld
  | Opcode.LOAD_CLASSDEREF ->
    translateLoad "LOAD_CLASSDEREF" ins bld
  | Opcode.LOAD_CLOSURE ->
    translateLoad "LOAD_CLOSURE" ins bld
  | Opcode.LOAD_SUPER_ATTR
  | Opcode.INSTRUMENTED_LOAD_SUPER_ATTR ->
    loadSuperAttr ins bld
  | Opcode.LOAD_FROM_DICT_OR_GLOBALS ->
    loadFromDict "LOAD_FROM_DICT_OR_GLOBALS" ins bld
  | Opcode.LOAD_FROM_DICT_OR_DEREF ->
    loadFromDict "LOAD_FROM_DICT_OR_DEREF" ins bld
  | Opcode.LOAD_BUILD_CLASS ->
    loadBuildClass ins bld
  | Opcode.LOAD_LOCALS ->
    loadLocals ins bld
  | Opcode.LOAD_ASSERTION_ERROR ->
    loadAssertionError ins bld
  | Opcode.LOAD_SMALL_INT ->
    loadSmallInt ins bld
  | Opcode.LOAD_COMMON_CONSTANT ->
    loadIndexed "LOAD_COMMON_CONSTANT" ins bld
  | Opcode.LOAD_SPECIAL ->
    loadIndexed "LOAD_SPECIAL" ins bld
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
  (* 3.6 only: 3.7 dropped this in favour of storing into __annotations__
     through the ordinary subscript path. *)
  | Opcode.STORE_ANNOTATION ->
    storeNamed "STORE_ANNOTATION" ins bld
  | Opcode.STORE_SUBSCR ->
    storeSubscript ins bld
  | Opcode.STORE_SLICE ->
    storeSlice ins bld
  | Opcode.STORE_MAP ->
    storeMap ins bld
  | Opcode.STORE_LOCALS ->
    storeLocals ins bld
  | Opcode.STORE_FAST_LOAD_FAST ->
    storeLoadPair ins bld
  | Opcode.STORE_FAST_STORE_FAST ->
    storePair ins bld
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
  | Opcode.UNARY_POSITIVE ->
    unaryOp "UNARY_POSITIVE" ins bld
  | Opcode.UNARY_NEGATIVE ->
    unaryOp "UNARY_NEGATIVE" ins bld
  | Opcode.UNARY_NOT ->
    unaryOp "UNARY_NOT" ins bld
  | Opcode.UNARY_INVERT ->
    unaryOp "UNARY_INVERT" ins bld
  | Opcode.TO_BOOL ->
    toBool ins bld
  (* Binary operations *)
  | Opcode.BINARY_OP ->
    binaryOp ins bld
  | Opcode.BINARY_SUBSCR ->
    binarySubscr ins bld
  | Opcode.BINARY_SLICE ->
    binarySlice ins bld
  (* Pre-3.11: each binary/inplace operator is its own opcode (see
     binaryOpDirect's own doc comment) -- the named-app strings mirror
     binaryOp's arg-index table exactly. *)
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
  | Opcode.BUILD_CONST_KEY_MAP ->
    buildConstKeyMap ins bld
  | Opcode.BUILD_STRING ->
    buildCollection "BUILD_STRING" ins bld
  | Opcode.BUILD_SLICE ->
    buildCollection "BUILD_SLICE" ins bld
  (* Unpacking builders, which 3.9 replaced with LIST_EXTEND / DICT_MERGE and
     friends. *)
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
  | Opcode.BUILD_INTERPOLATION ->
    buildFromStack "BUILD_INTERPOLATION" (getIntArg ins) ins bld
  | Opcode.BUILD_TEMPLATE ->
    buildFromStack "BUILD_TEMPLATE" 2 ins bld
  (* Function call instructions *)
  | Opcode.CALL
  | Opcode.INSTRUMENTED_CALL ->
    call ins bld
  (* 3.13 folds 3.12's separate KW_NAMES into the call itself. *)
  | Opcode.CALL_KW
  | Opcode.INSTRUMENTED_CALL_KW ->
    call ins bld
  | Opcode.KW_NAMES ->
    kwNames ins bld
  | Opcode.CALL_FUNCTION_EX
  | Opcode.INSTRUMENTED_CALL_FUNCTION_EX ->
    callFunctionEx minor ins bld
  | Opcode.CALL_INTRINSIC_1 ->
    callIntrinsic1 ins bld
  | Opcode.CALL_INTRINSIC_2 ->
    namedEffect "CALL_INTRINSIC_2" ins bld
  (* Pre-3.11 call opcodes. The VAR forms differ only in how the interpreter
     spreads the arguments it has already been handed, which the stack effect
     callFunction models does not depend on. *)
  | Opcode.CALL_FUNCTION
  | Opcode.CALL_FUNCTION_VAR
  | Opcode.CALL_FUNCTION_VAR_KW ->
    callFunction ins bld
  | Opcode.CALL_FUNCTION_KW ->
    callFunctionKw ins bld
  | Opcode.CALL_METHOD ->
    callMethod ins bld
  (* 3.11 splits a call in two: PRECALL settles the callable and argument
     shape, CALL performs it. The stack effect belongs to CALL. *)
  | Opcode.PRECALL ->
    namedEffect "PRECALL" ins bld
  (* MAKE_FUNCTION's stack shape moved twice: 3.11 dropped the explicit
     qualname and reversed which side of the code object the flag-selected
     extras sit on, and 3.13 dropped the flags entirely in favour of the
     SET_FUNCTION_ATTRIBUTE instructions that follow it. *)
  | Opcode.MAKE_FUNCTION ->
    if minor >= 13 then makeFunctionSimple ins bld
    elif minor >= 11 then makeFunction ins bld
    else makeFunctionLegacy ins bld
  (* Dropped in 3.6, which gave MAKE_FUNCTION a closure flag instead. The
     stack shape is the legacy one either way. *)
  | Opcode.MAKE_CLOSURE ->
    makeFunctionLegacy ins bld
  | Opcode.SET_FUNCTION_ATTRIBUTE ->
    setFunctionAttribute ins bld
  (* Both carry a count that says how much of the locals array they cover, so
     it travels with them rather than being dropped. *)
  | Opcode.MAKE_CELL ->
    namedEffectWithArgs "MAKE_CELL" [ operandIndex ins ] ins bld
  | Opcode.COPY_FREE_VARS ->
    namedEffectWithArgs "COPY_FREE_VARS" [ operandIndex ins ] ins bld
  (* Return instructions *)
  | Opcode.INTERPRETER_EXIT
  | Opcode.RETURN_VALUE
  | Opcode.INSTRUMENTED_RETURN_VALUE ->
    translateReturn ins bld
  | Opcode.RETURN_CONST
  | Opcode.INSTRUMENTED_RETURN_CONST ->
    translateReturnConst ins bld
  | Opcode.RETURN_GENERATOR ->
    bld <!-- (ins.Address, ins.Length)
    pushToStack bld noneValue
    bld --!> ins.Length
  (* Exception instructions *)
  | Opcode.RAISE_VARARGS ->
    translateRaiseVarargs ins bld
  | Opcode.RERAISE ->
    bld <!-- (ins.Address, ins.Length)
    (* 3.10 gave RERAISE an oparg: a nonzero one says the original
       instruction offset sits beneath the exception, to be discarded. *)
    let arg = getIntArgOr 0 ins
    let exc = popFromStack bld
    if arg <> 0 then discardTOS bld else ()
    bld <+ AST.extCall (AST.app "RERAISE" [ exc ] rt)
    bld <+ AST.sideEffect SideEffect.Terminate
    bld --!> ins.Length
  | Opcode.PREP_RERAISE_STAR ->
    (* Builds the exception group to re-raise from an except* block: pops the
       original group and the list of unhandled excs, pushes the result. *)
    bld <!-- (ins.Address, ins.Length)
    let unhandled = popFromStack bld
    let orig = popFromStack bld
    pushToStack bld (AST.app "PREP_RERAISE_STAR" [ orig; unhandled ] rt)
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
  | Opcode.JUMP_IF_NOT_EXC_MATCH ->
    jumpIfNotExcMatch binFile ins bld
  | Opcode.WITH_EXCEPT_START ->
    bld <!-- (ins.Address, ins.Length)
    let exc = peekFromStack bld 0
    let exitFunc = peekFromStack bld 3
    pushToStack bld (AST.app "WITH_EXCEPT_START" [ exitFunc; exc ] rt)
    bld --!> ins.Length
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
  | Opcode.WITH_CLEANUP ->
    withCleanup ins bld
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
  | Opcode.END_ASYNC_FOR
  | Opcode.INSTRUMENTED_END_ASYNC_FOR ->
    bld <!-- (ins.Address, ins.Length)
    let exc = popFromStack bld
    let aiter = popFromStack bld
    bld <+ AST.extCall (AST.app "END_ASYNC_FOR" [ aiter; exc ] rt)
    bld --!> ins.Length
  (* BEGIN_FINALLY pushes the NULL that marks "no exception" for the
     END_FINALLY / POP_FINALLY that consume it. *)
  | Opcode.BEGIN_FINALLY ->
    pushNull ins bld
  | Opcode.END_FINALLY ->
    namedEffect "END_FINALLY" ins bld
  | Opcode.POP_FINALLY ->
    namedEffect "POP_FINALLY" ins bld
  (* Pushes the address to resume at, then jumps into the finally block;
     END_FINALLY there pops that address and returns to it. *)
  | Opcode.CALL_FINALLY ->
    let ret = ins.Address + uint64 ins.Length
    pushToStack bld (AST.num (BitVector(ret, rt)))
    jumpByOffset ins bld true
  (* Jump instructions *)
  | Opcode.JUMP_FORWARD
  | Opcode.INSTRUMENTED_JUMP_FORWARD ->
    jumpByOffset ins bld true
  | Opcode.JUMP_BACKWARD
  | Opcode.JUMP_BACKWARD_NO_INTERRUPT
  | Opcode.INSTRUMENTED_JUMP_BACKWARD ->
    jumpByOffset ins bld false
  | Opcode.JUMP_ABSOLUTE
  | Opcode.CONTINUE_LOOP ->
    jumpAbsolute binFile ins bld
  (* POP_JUMP_IF_FALSE/TRUE's enum cases are shared across versions (see
     Opcode.fs), but their target ENCODING isn't: 3.11+ uses a
     forward-relative offset (condJump), while pre-3.11 uses an absolute
     word offset from the code object's own start (condJumpAbsolute) --
     see codeObjectBase's own doc comment. *)
  | Opcode.POP_JUMP_IF_FALSE ->
    if minor >= 11 then condJump ins bld false
    else condJumpAbsolute binFile ins bld false
  | Opcode.POP_JUMP_IF_TRUE ->
    if minor >= 11 then condJump ins bld true
    else condJumpAbsolute binFile ins bld true
  (* 3.11 names the direction in the opcode; the target computation lives
     in Semantics.branchTarget, so both directions lift the same way. *)
  | Opcode.POP_JUMP_FORWARD_IF_FALSE
  | Opcode.POP_JUMP_BACKWARD_IF_FALSE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_FALSE ->
    condJump ins bld false
  | Opcode.POP_JUMP_FORWARD_IF_TRUE
  | Opcode.POP_JUMP_BACKWARD_IF_TRUE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_TRUE ->
    condJump ins bld true
  | Opcode.POP_JUMP_IF_NONE
  | Opcode.POP_JUMP_FORWARD_IF_NONE
  | Opcode.POP_JUMP_BACKWARD_IF_NONE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_NONE ->
    condJumpNone ins bld true
  | Opcode.POP_JUMP_IF_NOT_NONE
  | Opcode.POP_JUMP_FORWARD_IF_NOT_NONE
  | Opcode.POP_JUMP_BACKWARD_IF_NOT_NONE
  | Opcode.INSTRUMENTED_POP_JUMP_IF_NOT_NONE ->
    condJumpNone ins bld false
  | Opcode.JUMP_IF_TRUE_OR_POP ->
    jumpOrPop binFile ins bld true
  | Opcode.JUMP_IF_FALSE_OR_POP ->
    jumpOrPop binFile ins bld false
  | Opcode.JUMP_IF_TRUE ->
    condJumpNoPop ins bld true
  | Opcode.JUMP_IF_FALSE ->
    condJumpNoPop ins bld false
  (* BREAK_LOOP takes no argument: its destination is the loop block that
     SETUP_LOOP pushed, so there is nothing static to jump to here. *)
  | Opcode.BREAK_LOOP ->
    namedEffect "BREAK_LOOP" ins bld
  (* Iteration instructions *)
  | Opcode.FOR_ITER
  | Opcode.INSTRUMENTED_FOR_ITER ->
    forIter minor ins bld
  | Opcode.SEND ->
    send ins bld
  | Opcode.GET_ITER ->
    getIter ins bld
  | Opcode.GET_YIELD_FROM_ITER ->
    getYieldFromIter ins bld
  (* GEN_START: pops and discards a debug-only marker distinguishing
     generator/coroutine/async-generator kind -- purely an internal
     assertion, no source-visible effect. *)
  | Opcode.GEN_START ->
    bld <!-- (ins.Address, ins.Length)
    discardTOS bld
    bld --!> ins.Length
  (* Async instructions *)
  | Opcode.GET_AITER ->
    unaryOp "GET_AITER" ins bld
  | Opcode.GET_ANEXT ->
    bld <!-- (ins.Address, ins.Length)
    let aiter = popFromStack bld
    pushToStack bld aiter
    pushToStack bld (AST.app "GET_ANEXT" [ aiter ] rt)
    bld --!> ins.Length
  | Opcode.GET_AWAITABLE ->
    (* Stack-neutral: pops the object to await, pushes its awaitable
       iterator (mirrors GET_ITER) -- previously a bare namedEffect with
       no pop/push, which desynced the simulated stack from here on. *)
    bld <!-- (ins.Address, ins.Length)
    let tos = popFromStack bld
    pushToStack bld (AST.app "GET_AWAITABLE" [ tos ] rt)
    bld --!> ins.Length
  (* Wraps the yielded value of an async generator in place. *)
  | Opcode.ASYNC_GEN_WRAP ->
    consumeAndPush "ASYNC_GEN_WRAP" ins bld
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
  | Opcode.SETUP_ASYNC_WITH ->
    (* The awaited `__aenter__()` result is already on the stack (from the
       preceding GET_AWAITABLE + yield-from-loop) when this runs -- pop
       and re-push it, since our model doesn't yet track the block-stack
       target this opcode also records. *)
    bld <!-- (ins.Address, ins.Length)
    let enterResult = popFromStack bld
    pushToStack bld enterResult
    bld --!> ins.Length
  | Opcode.SETUP_FINALLY ->
    setupBlock "SETUP_FINALLY" ins bld
  | Opcode.SETUP_EXCEPT ->
    setupBlock "SETUP_EXCEPT" ins bld
  | Opcode.SETUP_LOOP ->
    setupBlock "SETUP_LOOP" ins bld
  | Opcode.POP_BLOCK ->
    namedEffect "POP_BLOCK" ins bld
  (* Generator instructions *)
  | Opcode.YIELD_VALUE
  | Opcode.INSTRUMENTED_YIELD_VALUE ->
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
  (* Import instructions *)
  | Opcode.IMPORT_NAME ->
    importName ins bld
  | Opcode.IMPORT_FROM ->
    importFrom ins bld
  | Opcode.IMPORT_STAR ->
    importStar ins bld
  (* Collection update instructions *)
  | Opcode.LIST_APPEND ->
    listAppend ins bld
  | Opcode.SET_ADD ->
    setAdd ins bld
  | Opcode.MAP_ADD ->
    mapAdd ins bld
  | Opcode.LIST_EXTEND ->
    listExtend ins bld
  | Opcode.LIST_TO_TUPLE ->
    consumeAndPush "LIST_TO_TUPLE" ins bld
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
  | Opcode.COPY_DICT_WITHOUT_KEYS ->
    copyDictWithoutKeys ins bld
  (* Formatting instructions *)
  | Opcode.FORMAT_VALUE ->
    formatValue ins bld
  | Opcode.CONVERT_VALUE ->
    convertValue ins bld
  | Opcode.FORMAT_SIMPLE ->
    formatSimple ins bld
  | Opcode.FORMAT_WITH_SPEC ->
    formatWithSpec ins bld
  (* Unpack instructions *)
  | Opcode.UNPACK_SEQUENCE ->
    unpackSequence ins bld
  | Opcode.UNPACK_EX ->
    unpackEx ins bld
  (* Miscellaneous *)
  | Opcode.SETUP_ANNOTATIONS ->
    namedEffect "SETUP_ANNOTATIONS" ins bld
  | Opcode.PRINT_EXPR ->
    printExpr ins bld
  | Opcode.EXIT_INIT_CHECK ->
    namedEffect "EXIT_INIT_CHECK" ins bld
  | _ ->
    Terminator.futureFeature ()
