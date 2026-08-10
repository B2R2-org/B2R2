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

module internal B2R2.FrontEnd.Python.Python304.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.Python
open B2R2.FrontEnd.Python.LifterHelpers

(* Every arm dispatches to a helper shared with the other
   versions; only which opcodes exist, and what they mean,
   is specific to 3.4. *)
let private minor = 5

(* SETUP_LOOP/SETUP_EXCEPT/SETUP_FINALLY each push a block whose handler is a
   relative target. Those three are gone by 3.10, so unlike the jump helpers
   there is no shared version of this to reuse. *)
let private setupBlock name (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let n = getIntArg ins * jumpArgScale ins
  let target = ins.Address + uint64 ins.Length + uint64 n
  bld <+ AST.extCall (AST.app name [ AST.num (BitVector(target, rt)) ] rt)
  bld --!> ins.Length

(* COMPARE_OP still carries the identity, membership and exception-match
   comparisons that 3.9 split out into IS_OP, CONTAINS_OP and
   JUMP_IF_NOT_EXC_MATCH, so its argument indexes an 11-entry cmp_op table
   rather than the six relational operators the shared cmpOpType knows.
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
    | _ -> AST.zext rt (AST.relop (cmpOpType idx) left right)
  pushToStack bld result
  bld --!> ins.Length

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
  | Opcode.DUP_TOP ->
    dupTop ins bld
  | Opcode.DUP_TOP_TWO ->
    dupTopTwo ins bld
  (* Load instructions *)
  | Opcode.LOAD_CONST ->
    translateLoad "LOAD_CONST" true ins bld
  | Opcode.LOAD_FAST ->
    translateLoad "LOAD_FAST" false ins bld
  | Opcode.LOAD_NAME ->
    translateLoad "LOAD_NAME" false ins bld
  | Opcode.LOAD_ATTR ->
    loadAttr ins bld
  | Opcode.LOAD_GLOBAL ->
    translateLoadGlobal minor ins bld
  | Opcode.LOAD_DEREF ->
    translateLoad "LOAD_DEREF" false ins bld
  | Opcode.LOAD_CLOSURE ->
    translateLoad "LOAD_CLOSURE" false ins bld
  | Opcode.LOAD_CLASSDEREF ->
    translateLoad "LOAD_CLASSDEREF" false ins bld
  | Opcode.LOAD_BUILD_CLASS ->
    loadBuildClass ins bld
  | Opcode.STORE_FAST ->
    storeFast ins bld
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
  | Opcode.BUILD_SLICE ->
    buildCollection "BUILD_SLICE" ins bld
  (* Unpacking builders, which 3.9 replaced with LIST_EXTEND / DICT_MERGE
     and friends. *)
  (* Function call instructions *)
  | Opcode.CALL_FUNCTION ->
    callFunction ins bld
  | Opcode.CALL_FUNCTION_KW ->
    callFunctionKw ins bld
  (* 3.6 folded these two into CALL_FUNCTION_EX. Both take the
     same packed argument count, so they lift like the plain
     call with the extra iterable/mapping left on the stack. *)
  | Opcode.CALL_FUNCTION_VAR
  | Opcode.CALL_FUNCTION_VAR_KW ->
    callFunction ins bld
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
  | Opcode.JUMP_ABSOLUTE
  | Opcode.CONTINUE_LOOP ->
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
  (* Async instructions *)
  (* Block instructions. The loop and except blocks are 3.7-era only: 3.8
     dropped SETUP_LOOP/BREAK_LOOP/CONTINUE_LOOP and folded
     SETUP_EXCEPT into SETUP_FINALLY. *)
  | Opcode.SETUP_LOOP ->
    setupBlock "SETUP_LOOP" ins bld
  | Opcode.SETUP_EXCEPT ->
    setupBlock "SETUP_EXCEPT" ins bld
  | Opcode.SETUP_FINALLY ->
    setupBlock "SETUP_FINALLY" ins bld
  | Opcode.SETUP_WITH ->
    bld <!-- (ins.Address, ins.Length)
    let mgr = popFromStack bld
    pushToStack bld (AST.undef rt "__exit__")
    pushToStack bld (AST.app "__enter__" [ mgr ] rt)
    bld --!> ins.Length
  | Opcode.POP_BLOCK ->
    namedEffect "POP_BLOCK" ins bld
  (* BREAK_LOOP takes no argument: its destination is the loop block that
     SETUP_LOOP pushed, so there is nothing static to jump to here. *)
  | Opcode.BREAK_LOOP ->
    namedEffect "BREAK_LOOP" ins bld
  | Opcode.END_FINALLY ->
    namedEffect "END_FINALLY" ins bld
  (* Generator instructions *)
  | Opcode.YIELD_VALUE ->
    (* Pops the yielded value. On resume, the value pushed back is
       whatever the caller sends via `.send(x)` -- genuinely unknown at
       decompile time, not necessarily None -- so tag it with its own
       sentinel rather than a plain `None` placeholder. *)
    bld <!-- (ins.Address, ins.Length)
    let item = popFromStack bld
    bld <+ AST.extCall (AST.app "YIELD_VALUE" [ item ] rt)
    pushToStack bld (AST.undef rt "YIELD_RECEIVED")
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
  (* Dropped in 3.6, which gave MAKE_FUNCTION a closure flag
     instead. The stack shape is the legacy one either way. *)
  | Opcode.MAKE_CLOSURE ->
    makeFunctionLegacy ins bld
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
  | _ ->
    Terminator.futureFeature ()
