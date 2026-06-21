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

module internal B2R2.FrontEnd.Python.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.Python
open B2R2.FrontEnd.BinLifter.LiftingUtils

let private rt = OperationSize.regType

let private extractMinorVersion = function
  | PythonVersion.Python306 -> 6
  | PythonVersion.Python307 -> 7
  | PythonVersion.Python308 -> 8
  | PythonVersion.Python309 -> 9
  | PythonVersion.Python310 -> 10
  | PythonVersion.Python311 -> 11
  | PythonVersion.Python312 -> 12
  | PythonVersion.Python313 -> 13
  | PythonVersion.Python314 -> 14
  | version -> failwithf "Unsupported Python version: %A" version

let private getIntArg (ins: Instruction) =
  match ins.Operands with
  | OneOperand(arg, _) -> arg
  | _ -> failwith "Expected one operand with an integer argument."

let private stackSlotSize = numI32 1 rt

/// Pushes an element onto the evaluation stack.
let private pushToStack bld expr =
  let spReg = regVar bld R.SP
  bld <+ (spReg := (spReg .- stackSlotSize))
  bld <+ (AST.store Endian.Little spReg expr)

/// Pops an element from the evaluation stack and returns it.
let private popFromStack bld =
  let spReg = regVar bld R.SP
  let tmp = tmpVar bld rt
  bld <+ (tmp := AST.loadLE rt spReg)
  bld <+ (spReg := (spReg .+ stackSlotSize))
  tmp

/// Pops an element from the evaluation stack but does not return it.
let private discardTOS bld =
  let spReg = regVar bld R.SP
  bld <+ (spReg := (spReg .+ stackSlotSize))

(* Returns the expression at stack[SP + offset] without modifying SP.
   offset=0 is TOS, offset=1 is TOS1, etc. *)
let private peekFromStack bld offset =
  let spReg = regVar bld R.SP
  let tmp = tmpVar bld rt
  bld <+ (tmp := AST.loadLE rt (spReg .+ (numI32 offset rt)))
  tmp

(* Emit ISMark + IEMark only; used for no-op instructions. *)
let private nopInstr (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  bld --!> ins.Length

let private effInstr eff (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  bld <+ AST.extCall eff
  bld --!> ins.Length

let private namedEffect name ins bld =
  effInstr (AST.app name [] rt) ins bld

let private namedEffectWithArgs name args ins bld =
  effInstr (AST.app name args rt) ins bld

let private resolveOperand isConst = function
  (* ASCII strings. *)
  | OneOperand(_, Some(PyAscii n))
  | OneOperand(_, Some(PyShortAscii n))
  | OneOperand(_, Some(PyShortAsciiInterned n)) ->
    if isConst then sprintf "\"%s\"" n
    else n
  (* Function reference. Used when calling a function. *)
  | OneOperand(_, Some(PyREF(_, n))) -> n
  (* Function name. Used when defining a function. *)
  | OneOperand(_, Some(PyCode(codeObj))) -> codeObj.Name
  (* None *)
  | OneOperand(_, Some(PyNone)) -> "None"
  (* PyFalse *)
  | OneOperand(_, Some(PyFalse)) -> "False"
  (* PyInt *)
  | OneOperand(_, Some(PyInt n)) -> sprintf "%d" n
  (* Otherwise *)
  | OneOperand(idx, _) -> sprintf "<%d>" idx
  | _ -> "?"

let private resolveName = resolveOperand false

let private resolveConst = resolveOperand true

let private translateLoad opname isConst (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let arg =
    if isConst then resolveConst ins.Operands
    else resolveName ins.Operands
  let e = AST.app opname [ AST.undef rt arg ] rt
  pushToStack bld e
  bld --!> ins.Length

let private translateLoadGlobal minor (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let name = resolveName ins.Operands
  let v = AST.app "LOAD_GLOBAL" [ AST.undef rt name ] rt
  if ins.Flag then
    let e = AST.undef rt "NULL"
    pushToStack bld e
  else
    ()
  pushToStack bld v
  bld --!> ins.Length

let private translateDelete opname (ins: Instruction) bld =
  let args = [ AST.undef rt (resolveName ins.Operands) ]
  namedEffectWithArgs opname args ins bld

let private popTop (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  discardTOS bld
  bld --!> ins.Length

/// NULL is a special value implemented in Python internally.
let private pushNull (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  pushToStack bld (AST.undef rt "NULL")
  bld --!> ins.Length

let private jumpByOffset (ins: Instruction) bld isForward =
  bld <!-- (ins.Address, ins.Length)
  let n = getIntArg ins
  let offset = n * 2 * (if isForward then 1 else -1)
  let dst = ins.Address + uint64 ins.Length + uint64 offset
  bld <+ AST.interjmp (AST.num (BitVector(dst, rt))) InterJmpKind.Base
  bld

let private endFor (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  discardTOS bld
  bld --!> ins.Length

let private copy (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let n = getIntArg ins
  pushToStack bld (peekFromStack bld (n - 1))
  bld --!> ins.Length

let private swap (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let n = getIntArg ins
  let top = peekFromStack bld 0
  let nth = peekFromStack bld (n - 1)
  let spReg = regVar bld R.SP
  let tmp = tmpVar bld rt
  bld <+ (tmp := top)
  bld <+ (AST.store Endian.Little spReg nth)
  bld <+ (AST.store Endian.Little (spReg .+ (numI32 (n - 1) rt)) tmp)
  bld --!> ins.Length

let private storeFast (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let name = resolveName ins.Operands
  let value = popFromStack bld
  let eff = AST.app "STORE_FAST" [ AST.undef rt name; value ] rt
  bld <+ AST.extCall eff
  bld --!> ins.Length

(* Generic store for STORE_NAME / STORE_GLOBAL / STORE_ATTR / STORE_DEREF:
   pop TOS and emit an external call recording the target name. *)
let private storeNamed opname (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let name = resolveName ins.Operands
  let value = popFromStack bld
  let eff = AST.app opname [ AST.undef rt name; value ] rt
  bld <+ AST.extCall eff
  bld --!> ins.Length

(* STORE_SUBSCR: TOS1[TOS] = TOS2 — pops three items. *)
let private storeSubscript (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let sub = popFromStack bld
  let obj = popFromStack bld
  let value = popFromStack bld
  let eff = AST.app "STORE_SUBSCR" [ obj; sub; value ] rt
  bld <+ AST.extCall eff
  bld --!> ins.Length

(* STORE_SLICE: TOS2[TOS1:TOS] = TOS3 — pops four items. *)
let private storeSlice (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let stop = popFromStack bld
  let start = popFromStack bld
  let obj = popFromStack bld
  let value = popFromStack bld
  let eff = AST.app "STORE_SLICE" [ obj; start; stop; value ] rt
  bld <+ AST.extCall eff
  bld --!> ins.Length

(* RETURN_VALUE / RETURN_GENERATOR: pop TOS and emit a RETURN call. *)
let private translateReturn (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let value = popFromStack bld
  let t = tmpVar bld rt
  bld <+ AST.extCall (AST.app "RETURN" [ value ] rt)
  bld <+ (AST.interjmp t InterJmpKind.IsRet)
  bld

(* RETURN_CONST: load constant directly without a stack round-trip. *)
let private translateReturnConst (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let name = resolveConst ins.Operands
  let value = AST.app "LOAD_CONST" [ AST.undef rt name ] rt
  let t = tmpVar bld rt
  bld <+ AST.extCall (AST.app "RETURN" [ value ] rt)
  bld <+ (AST.interjmp t InterJmpKind.IsRet)
  bld

(* RAISE_VARARGS arg: pop arg items (0–2) and raise. *)
let private translateRaise (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let n = getIntArg ins
  let args = List.init n (fun _ -> popFromStack bld)
  bld <+ AST.extCall (AST.app "RAISE_VARARGS" args rt)
  bld --!> ins.Length

(* Conditional jump shared by POP_JUMP_IF_FALSE and POP_JUMP_IF_TRUE.
   jumpIfTrue=true  → jump when TOS is truthy.
   jumpIfTrue=false → jump when TOS is falsy. *)
let private condJump (ins: Instruction) bld jumpIfTrue =
  bld <!-- (ins.Address, ins.Length)
  let cond = popFromStack bld
  let n = getIntArg ins
  let jmpDst = ins.Address + uint64 ins.Length + uint64 (n * 2)
  let fallDst = ins.Address + uint64 ins.Length
  let tLbl = AST.num (BitVector(jmpDst, rt))
  let fLbl = AST.num (BitVector(fallDst, rt))
  if jumpIfTrue then bld <+ AST.intercjmp cond tLbl fLbl
  else bld <+ AST.intercjmp cond fLbl tLbl
  bld

(* Conditional jump for POP_JUMP_IF_NONE / POP_JUMP_IF_NOT_NONE.
   jumpIfNone=true  → jump when TOS is None (modeled as IS_NONE(TOS) = 1).
   jumpIfNone=false → jump when TOS is not None. *)
let private condJumpNone (ins: Instruction) bld jumpIfNone =
  bld <!-- (ins.Address, ins.Length)
  let value = popFromStack bld
  let isNone = AST.app "IS_NONE" [ value ] rt
  let n = getIntArg ins
  let jmpDst = ins.Address + uint64 ins.Length + uint64 (n * 2)
  let fallDst = ins.Address + uint64 ins.Length
  let tLbl = AST.num (BitVector(jmpDst, rt))
  let fLbl = AST.num (BitVector(fallDst, rt))
  if jumpIfNone then bld <+ AST.intercjmp isNone tLbl fLbl
  else bld <+ AST.intercjmp isNone fLbl tLbl
  bld

let private forIter minor (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let tos = peekFromStack bld 0
  let n = getIntArg ins
  let jmpDst = ins.Address + uint64 ins.Length + uint64 (n * 2)
  let fallDst = ins.Address + uint64 ins.Length
  let tLbl = AST.num (BitVector(jmpDst, rt))
  let fLbl = AST.num (BitVector(fallDst, rt))
  let cond = AST.app "IS_EXHAUSTED" [ tos ] rt
  let lblLTrue = label bld "LTrue"
  let lblLFalse = label bld "LFalse"
  bld <+ AST.cjmp cond (AST.jmpDest lblLTrue) (AST.jmpDest lblLFalse)
  (* True branch: pop the exhausted iterator and jump to the loop exit. *)
  bld <+ AST.lmark lblLTrue
  if minor < 12 then
    discardTOS bld
  (* From 3.12, END_FOR is introduced and instead pops the iterator. *)
  else
    ()
  bld <+ AST.interjmp tLbl InterJmpKind.Base
  (* False branch: jump to the body and push the next value. *)
  bld <+ AST.lmark lblLFalse
  pushToStack bld (AST.app "NEXT" [ tos ] rt)
  bld <+ AST.interjmp fLbl InterJmpKind.Base
  bld

let private getIter (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let iter = popFromStack bld
  let iterNext = AST.app "GET_ITER" [ iter ] rt
  pushToStack bld iterNext
  bld --!> ins.Length

(* SEND: pop TOS (sent value), peek TOS1 (generator), call send(gen, val).
   Push result; jump on exhaustion, fall through otherwise. *)
let private send (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let sentVal = popFromStack bld
  let gen = peekFromStack bld 0
  let result = AST.app "SEND" [ gen; sentVal ] rt
  let n = getIntArg ins
  let jmpDst = ins.Address + uint64 ins.Length + uint64 (n * 2)
  let fallDst = ins.Address + uint64 ins.Length
  pushToStack bld result
  let isExhausted = AST.app "IS_EXHAUSTED" [ result ] rt
  bld <+ AST.intercjmp isExhausted
    (AST.num (BitVector(jmpDst, rt)))
    (AST.num (BitVector(fallDst, rt)))
  bld --!> ins.Length

let private getYieldFromIter (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let tos = popFromStack bld
  pushToStack bld (AST.app "GET_YIELD_FROM_ITER" [ tos ] rt)
  bld --!> ins.Length

let private call (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let argc = getIntArg ins
  let args = List.init argc (fun _ -> popFromStack bld)
  let func = popFromStack bld
  let maybeSelf = popFromStack bld
  let result = AST.app "CALL" (maybeSelf :: func :: args) rt
  pushToStack bld result
  bld --!> ins.Length

let private consumeAndPush name (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let v = popFromStack bld
  let result = AST.app name [ v ] rt
  pushToStack bld result
  bld --!> ins.Length

let private cmpOpType = function
  | 0 -> RelOpType.LT
  | 1 -> RelOpType.LE
  | 2 -> RelOpType.EQ
  | 3 -> RelOpType.NEQ
  | 4 -> RelOpType.GT
  | 5 -> RelOpType.GE
  | _ -> Terminator.futureFeature ()

(* COMPARE_OP: pop right (TOS) then left (TOS1), push bool result.
   In 3.12+ the operator index is arg >> 4; lower bits are cache flags. *)
let private compareOP minor (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let n = getIntArg ins
  let opIdx =
    if minor >= 12 then
      n >>> 4
    else
      n
  let right = popFromStack bld
  let left = popFromStack bld
  let b = AST.relop (cmpOpType opIdx) left right
  let b = AST.zext rt b
  pushToStack bld b
  bld --!> ins.Length

(* BINARY_OP: pop right (TOS) and left (TOS1), apply operator, push result.
   arg directly indexes the operation; inplace variants (arg >= 13) share
   the same index offset as their non-inplace counterparts. *)
let binaryOp (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let right = popFromStack bld
  let left = popFromStack bld
  let result =
    match getIntArg ins with
    | 0  | 13 -> AST.binop BinOpType.ADD left right
    | 1  | 14 -> AST.binop BinOpType.AND left right
    | 2  | 15 -> AST.app "//" [ left; right ] rt
    | 3  | 16 -> AST.binop BinOpType.SHL left right
    | 4  | 17 -> AST.app "@" [ left; right ] rt
    | 5  | 18 -> AST.binop BinOpType.MUL left right
    | 6  | 19 -> AST.binop BinOpType.MOD left right
    | 7  | 20 -> AST.binop BinOpType.OR left right
    | 8  | 21 -> AST.app "**" [ left; right ] rt
    | 9  | 22 -> AST.binop BinOpType.SAR left right
    | 10 | 23 -> AST.binop BinOpType.SUB left right
    | 11 | 24 -> AST.binop BinOpType.DIV left right
    | 12 | 25 -> AST.binop BinOpType.XOR left right
    | n -> failwithf "Invalid BINARY_OP arg %d at %A" n ins.Address
  pushToStack bld result
  bld --!> ins.Length

let unpackSequence (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let n = getIntArg ins
  let seq = popFromStack bld
  for i in 0 .. n - 1 do
    let elem = AST.app "UNPACK" [ seq; AST.num (BitVector(i, rt)) ] rt
    pushToStack bld elem
  bld --!> ins.Length

/// Translate IR.
let translate (binFile: PythonBinFile) (ins: Instruction) bld =
  let minor = extractMinorVersion binFile.Version
  match ins.Opcode with
  (* No-ops *)
  | Opcode.NOP | Opcode.RESUME | Opcode.CACHE ->
    nopInstr ins bld
  (* Stack manipulation *)
  | Opcode.POP_TOP ->
    popTop ins bld
  | Opcode.PUSH_NULL ->
    pushNull ins bld
  | Opcode.END_FOR ->
    endFor ins bld
  | Opcode.END_SEND ->
    namedEffect "END_SEND" ins bld
  | Opcode.COPY ->
    copy ins bld
  | Opcode.SWAP ->
    swap ins bld
  (* Load instructions *)
  | Opcode.LOAD_CONST ->
    translateLoad "LOAD_CONST" true ins bld
  | Opcode.LOAD_FAST | Opcode.LOAD_FAST_CHECK | Opcode.LOAD_FAST_AND_CLEAR ->
    translateLoad "LOAD_FAST" false ins bld
  | Opcode.LOAD_NAME ->
    translateLoad "LOAD_NAME" false ins bld
  | Opcode.LOAD_ATTR ->
    translateLoad "LOAD_ATTR" false ins bld
  | Opcode.LOAD_GLOBAL ->
    translateLoadGlobal minor ins bld
  | Opcode.LOAD_DEREF ->
    translateLoad "LOAD_DEREF" false ins bld
  | Opcode.LOAD_CLOSURE ->
    translateLoad "LOAD_CLOSURE" false ins bld
  | Opcode.LOAD_SUPER_ATTR ->
    translateLoad "LOAD_SUPER_ATTR" false ins bld
  | Opcode.LOAD_FROM_DICT_OR_GLOBALS ->
    translateLoad "LOAD_FROM_DICT_OR_GLOBALS" false ins bld
  | Opcode.LOAD_FROM_DICT_OR_DEREF ->
    translateLoad "LOAD_FROM_DICT_OR_DEREF" false ins bld
  | Opcode.LOAD_BUILD_CLASS ->
    namedEffect "LOAD_BUILD_CLASS" ins bld
  | Opcode.LOAD_ASSERTION_ERROR ->
    namedEffect "LOAD_ASSERTION_ERROR" ins bld
  | Opcode.LOAD_LOCALS ->
    namedEffect "LOAD_LOCALS" ins bld
  (* Store instructions *)
  | Opcode.STORE_FAST ->
    storeFast ins bld
  | Opcode.STORE_NAME ->
    storeNamed "STORE_NAME" ins bld
  | Opcode.STORE_GLOBAL ->
    storeNamed "STORE_GLOBAL" ins bld
  | Opcode.STORE_ATTR ->
    storeNamed "STORE_ATTR" ins bld
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
    translateDelete "DELETE_ATTR" ins bld
  | Opcode.DELETE_DEREF ->
    translateDelete "DELETE_DEREF" ins bld
  | Opcode.DELETE_SUBSCR ->
    namedEffect "DELETE_SUBSCR" ins bld
  (* Unary operations *)
  | Opcode.UNARY_NEGATIVE ->
    namedEffect "UNARY_NEGATIVE" ins bld
  | Opcode.UNARY_NOT ->
    namedEffect "UNARY_NOT" ins bld
  | Opcode.UNARY_INVERT ->
    namedEffect "UNARY_INVERT" ins bld
  (* Binary / slice operations *)
  | Opcode.BINARY_OP ->
    binaryOp ins bld
  | Opcode.BINARY_SUBSCR ->
    namedEffect "BINARY_SUBSCR" ins bld
  | Opcode.BINARY_SLICE ->
    namedEffect "BINARY_SLICE" ins bld
  (* Compare / identity / membership *)
  | Opcode.COMPARE_OP ->
    compareOP minor ins bld
  | Opcode.IS_OP ->
    namedEffect "IS_OP" ins bld
  | Opcode.CONTAINS_OP ->
    namedEffect "CONTAINS_OP" ins bld
  (* Build instructions *)
  | Opcode.BUILD_TUPLE ->
    namedEffect "BUILD_TUPLE" ins bld
  | Opcode.BUILD_LIST ->
    namedEffect "BUILD_LIST" ins bld
  | Opcode.BUILD_SET ->
    namedEffect "BUILD_SET" ins bld
  | Opcode.BUILD_MAP ->
    namedEffect "BUILD_MAP" ins bld
  | Opcode.BUILD_STRING ->
    namedEffect "BUILD_STRING" ins bld
  | Opcode.BUILD_SLICE ->
    namedEffect "BUILD_SLICE" ins bld
  | Opcode.BUILD_CONST_KEY_MAP ->
    namedEffect "BUILD_CONST_KEY_MAP" ins bld
  (* Function call instructions *)
  | Opcode.CALL ->
    call ins bld
  | Opcode.CALL_FUNCTION_EX ->
    namedEffect "CALL_FUNCTION_EX" ins bld
  | Opcode.CALL_INTRINSIC_1 ->
    namedEffect "CALL_INTRINSIC_1" ins bld
  | Opcode.CALL_INTRINSIC_2 ->
    namedEffect "CALL_INTRINSIC_2" ins bld
  | Opcode.KW_NAMES ->
    namedEffect "KW_NAMES" ins bld
  (* Return instructions *)
  | Opcode.RETURN_VALUE | Opcode.RETURN_GENERATOR ->
    translateReturn ins bld
  | Opcode.RETURN_CONST ->
    translateReturnConst ins bld
  (* Exception instructions *)
  | Opcode.RAISE_VARARGS ->
    translateRaise ins bld
  | Opcode.RERAISE ->
    namedEffect "RERAISE" ins bld
  | Opcode.PUSH_EXC_INFO ->
    namedEffect "PUSH_EXC_INFO" ins bld
  | Opcode.POP_EXCEPT ->
    namedEffect "POP_EXCEPT" ins bld
  | Opcode.CHECK_EXC_MATCH ->
    namedEffect "CHECK_EXC_MATCH" ins bld
  | Opcode.CHECK_EG_MATCH ->
    namedEffect "CHECK_EG_MATCH" ins bld
  | Opcode.WITH_EXCEPT_START ->
    namedEffect "WITH_EXCEPT_START" ins bld
  | Opcode.CLEANUP_THROW ->
    namedEffect "CLEANUP_THROW" ins bld
  | Opcode.END_ASYNC_FOR ->
    namedEffect "END_ASYNC_FOR" ins bld
  (* Jump instructions *)
  | Opcode.JUMP_FORWARD ->
    jumpByOffset ins bld true
  | Opcode.JUMP_BACKWARD | Opcode.JUMP_BACKWARD_NO_INTERRUPT ->
    jumpByOffset ins bld false
  | Opcode.POP_JUMP_IF_FALSE ->
    condJump ins bld false
  | Opcode.POP_JUMP_IF_TRUE ->
    condJump ins bld true
  | Opcode.POP_JUMP_IF_NONE ->
    condJumpNone ins bld true
  | Opcode.POP_JUMP_IF_NOT_NONE ->
    condJumpNone ins bld false
  (* Iteration instructions *)
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
    namedEffect "GET_AITER" ins bld
  | Opcode.GET_ANEXT ->
    namedEffect "GET_ANEXT" ins bld
  | Opcode.BEFORE_ASYNC_WITH ->
    namedEffect "BEFORE_ASYNC_WITH" ins bld
  | Opcode.BEFORE_WITH ->
    namedEffect "BEFORE_WITH" ins bld
  | Opcode.GET_AWAITABLE ->
    namedEffect "GET_AWAITABLE" ins bld
  | Opcode.YIELD_VALUE ->
    namedEffect "YIELD_VALUE" ins bld
  (* Import instructions *)
  | Opcode.IMPORT_NAME ->
    translateLoad "IMPORT_NAME" false ins bld
  | Opcode.IMPORT_FROM ->
    translateLoad "IMPORT_FROM" false ins bld
  (* Function / class definition *)
  | Opcode.MAKE_FUNCTION ->
    consumeAndPush "MAKE_FUNCTION" ins bld
  | Opcode.MAKE_CELL ->
    namedEffect "MAKE_CELL" ins bld
  | Opcode.COPY_FREE_VARS ->
    namedEffect "COPY_FREE_VARS" ins bld
  | Opcode.SETUP_ANNOTATIONS ->
    namedEffect "SETUP_ANNOTATIONS" ins bld
  | Opcode.FORMAT_VALUE ->
    namedEffect "FORMAT_VALUE" ins bld
  (* Unpack instructions *)
  | Opcode.UNPACK_SEQUENCE ->
    unpackSequence ins bld
  | Opcode.UNPACK_EX ->
    namedEffect "UNPACK_EX" ins bld
  (* Collection update instructions *)
  | Opcode.LIST_APPEND ->
    namedEffect "LIST_APPEND" ins bld
  | Opcode.SET_ADD ->
    namedEffect "SET_ADD" ins bld
  | Opcode.MAP_ADD ->
    namedEffect "MAP_ADD" ins bld
  | Opcode.LIST_EXTEND ->
    namedEffect "LIST_EXTEND" ins bld
  | Opcode.SET_UPDATE ->
    namedEffect "SET_UPDATE" ins bld
  | Opcode.DICT_MERGE ->
    namedEffect "DICT_MERGE" ins bld
  | Opcode.DICT_UPDATE ->
    namedEffect "DICT_UPDATE" ins bld
  (* Pattern matching instructions *)
  | Opcode.GET_LEN ->
    namedEffect "GET_LEN" ins bld
  | Opcode.MATCH_MAPPING ->
    namedEffect "MATCH_MAPPING" ins bld
  | Opcode.MATCH_SEQUENCE ->
    namedEffect "MATCH_SEQUENCE" ins bld
  | Opcode.MATCH_KEYS ->
    namedEffect "MATCH_KEYS" ins bld
  | Opcode.MATCH_CLASS ->
    namedEffect "MATCH_CLASS" ins bld
  | _ -> Terminator.futureFeature ()
