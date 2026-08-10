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

module internal B2R2.FrontEnd.Python.LifterHelpers

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.Python
open B2R2.FrontEnd.BinLifter.LiftingUtils

/// A shorthand for the one width every Python operand and register has. The
/// constant itself is OperationSize.RegType, a literal that folds into each
/// use of this alias.
let rt = OperationSize.RegType

let extractMinorVersion = function
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

let getIntArg (ins: Instruction) =
  match ins.Operands with
  | OneOperand(arg, _) -> arg
  | _ -> failwith "Expected one operand with an integer argument."

/// How far apart two evaluation-stack slots sit. A slot holds one rt-wide
/// value and LowUIR's stores are byte-addressed, so the distance is rt's
/// width in bytes -- exactly as a native architecture's push moves its stack
/// pointer by the width it stores. Spacing slots one apart (a slot *index*)
/// would leave the IR contradicting itself: consecutive rt-wide stores would
/// overlap by all but one byte, so every push would corrupt the slot beneath
/// it. Derived from the width rather than spelled out, so a change to it
/// carries here on its own; both are literals, so the division folds away at
/// compile time.
let [<Literal>] SlotSize = OperationSize.RegType / 8<rt>

/// SlotSize as an expression, built once. Unlike the literals it is a LowUIR
/// node -- a reference type -- so it cannot be one itself.
let stackSlotSize = numI32 SlotSize rt

/// The address of the slot n above the stack pointer; n = 0 is TOS.
let slotAddr spReg n = spReg .+ (numI32 (n * SlotSize) rt)

/// Pushes an element onto the evaluation stack.
let pushToStack bld expr =
  let spReg = regVar bld R.SP
  bld <+ (spReg := (spReg .- stackSlotSize))
  bld <+ (AST.store Endian.Little spReg expr)

/// Pops an element from the evaluation stack and returns it.
let popFromStack bld =
  let spReg = regVar bld R.SP
  let tmp = tmpVar bld rt
  bld <+ (tmp := AST.loadLE rt spReg)
  bld <+ (spReg := (spReg .+ stackSlotSize))
  tmp

/// Pops an element from the evaluation stack but does not return it.
let discardTOS bld =
  let spReg = regVar bld R.SP
  bld <+ (spReg := (spReg .+ stackSlotSize))

(* Returns the expression at stack[SP + offset] without modifying SP.
   offset=0 is TOS, offset=1 is TOS1, etc. *)
let peekFromStack bld offset =
  let spReg = regVar bld R.SP
  let tmp = tmpVar bld rt
  bld <+ (tmp := AST.loadLE rt (slotAddr spReg offset))
  tmp

(* Emit ISMark + IEMark only; used for no-op instructions. *)
let nopInstr (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  bld --!> ins.Length

let effInstr eff (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  bld <+ AST.extCall eff
  bld --!> ins.Length

let namedEffect name ins bld = effInstr (AST.app name [] rt) ins bld

let namedEffectWithArgs name args ins bld =
  effInstr (AST.app name args rt) ins bld

(* A unary operator (UNARY_NEGATIVE/INVERT/POSITIVE/NOT): pop the operand and
   push the operator applied to it. Modeled as a named app (like `**`/`//`)
   so the surface operator is preserved for decompilation, rather than as a
   stack-ignoring effect that would silently drop the operand's sign. *)
let unaryOp name (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let operand = popFromStack bld
  pushToStack bld (AST.app name [ operand ] rt)
  bld --!> ins.Length

/// The instruction's argument as an operand index -- the raw oparg, which
/// indexes the containing code object's own constant, name, or local table.
/// Which of the three it indexes is fixed by the opcode, so the named app the
/// index rides in already says which table to read (see each version's own
/// Parsing.getTable), and the code object is the one containing the
/// instruction's own address. Emitting the index rather than a rendering of
/// the object it selects keeps the lifted IR lossless -- the object's type,
/// its interned identity, and the int/long distinction all survive -- and
/// leaves the lookup to a consumer holding the PythonBinFile, exactly as a
/// native architecture's IR leaves a Load's target to whoever holds the
/// binary.
let operandIndex (ins: Instruction) = numI32 (getIntArg ins) rt

/// The interpreter's NULL: the empty self-or-kwnames slot a call's shape
/// reserves, and what a flag-carrying attribute load pushes ahead of the
/// attribute. It is a marker rather than a Python value, and the opcode
/// determines it completely, so it is a nullary named app -- not an
/// Undefined, which would claim the bytecode leaves it unspecified.
let nullSlot = AST.app "NULL" [] rt

/// The None singleton, for the opcodes that push it without naming a constant
/// (RETURN_GENERATOR, CLEANUP_THROW). A named app for the same reason
/// nullSlot is one.
let noneValue = AST.app "None" [] rt

/// The context manager's __exit__ bound method, which BEFORE_WITH and
/// SETUP_WITH push beneath the __enter__ result so both exit paths -- the
/// normal one and WITH_EXCEPT_START's -- can call it. It takes the manager
/// for the same reason __enter__ does: both are attribute lookups on that
/// one object, so dropping it would leave the IR unable to say whose
/// __exit__ this is.
let exitMethod mgr = AST.app "__exit__" [ mgr ] rt

/// The value a suspended yield receives when it is resumed. Unlike every
/// marker above, this one genuinely is not determined by the bytecode -- it
/// is whatever the caller later sends in -- so it is an Undefined, which is
/// precisely what that node means.
let yieldReceived = AST.undef rt "YIELD_RECEIVED"

/// Where a return lands. Python's return address lives in the interpreter's
/// own frame object, which the bytecode can neither name nor address -- so,
/// unlike a native architecture whose return address sits in a register or
/// on the stack, no expression here can name it. Undefined for the same
/// reason yieldReceived is; the two are the only ones this lifter emits. The
/// jump itself stays an InterJmp of kind IsRet, so CFG recovery still sees a
/// return edge -- only its target is unknown.
let returnTarget = AST.undef rt "RETURN_TARGET"

let translateLoad opname (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  pushToStack bld (AST.app opname [ operandIndex ins ] rt)
  bld --!> ins.Length

let translateLoadGlobal (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let v = AST.app "LOAD_GLOBAL" [ operandIndex ins ] rt
  if ins.Flag then pushToStack bld nullSlot else ()
  pushToStack bld v
  bld --!> ins.Length

let translateDelete opname (ins: Instruction) bld =
  namedEffectWithArgs opname [ operandIndex ins ] ins bld

(* DELETE_ATTR: pops the owner object and deletes the named attribute. *)
let deleteAttr (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let owner = popFromStack bld
  let args = [ owner; operandIndex ins ]
  bld <+ AST.extCall (AST.app "DELETE_ATTR" args rt)
  bld --!> ins.Length

(* IMPORT_NAME: pops fromlist (unused by our translation) and level (the
   number of leading dots for a relative import, e.g. `from ..pkg import x`),
   then pushes the imported module object. *)
let importName (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let name = operandIndex ins
  let fromList = popFromStack bld
  let level = popFromStack bld
  pushToStack bld (AST.app "IMPORT_NAME" [ name; level; fromList ] rt)
  bld --!> ins.Length

(* IMPORT_FROM: peeks (does not pop) the module object left by IMPORT_NAME so
   that later IMPORT_FROMs can reuse it, and pushes obj.name. *)
let importFrom (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let name = operandIndex ins
  let moduleObj = peekFromStack bld 0
  pushToStack bld (AST.app "IMPORT_FROM" [ moduleObj; name ] rt)
  bld --!> ins.Length

(* IMPORT_STAR: pops the module object and binds all its exported names. *)
let importStar (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let moduleObj = popFromStack bld
  bld <+ AST.extCall (AST.app "IMPORT_STAR" [ moduleObj ] rt)
  bld --!> ins.Length

let callIntrinsic1 (ins: Instruction) bld =
  match getIntArg ins with
  | 2 -> importStar ins bld (* INTRINSIC_IMPORT_STAR in Python 3.12. *)
  | _ -> namedEffect "CALL_INTRINSIC_1" ins bld

let popTop (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  discardTOS bld
  bld --!> ins.Length

/// PUSH_NULL: NULL is a special value implemented in Python internally.
let pushNull (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  pushToStack bld nullSlot
  bld --!> ins.Length

(* LOAD_ASSERTION_ERROR: pushes the AssertionError builtin a failing assert
   raises. The opcode names it outright -- it takes no argument -- so it is a
   nullary named app. *)
let loadAssertionError (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  pushToStack bld (AST.app "LOAD_ASSERTION_ERROR" [] rt)
  bld --!> ins.Length

(* LOAD_BUILD_CLASS: pushes the __build_class__ builtin used to construct a
   class from its body function, name, and bases. Nullary for the same reason
   loadAssertionError is. *)
let loadBuildClass (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  pushToStack bld (AST.app "LOAD_BUILD_CLASS" [] rt)
  bld --!> ins.Length

/// Bytes each unit of a jump's argument stands for. Jump arguments counted
/// bytes up to and including 3.9; 3.10 made them instruction offsets, so the
/// same argument denotes twice the distance from there on (bpo-27129).
/// Deriving it from the instruction keeps the arithmetic below shared: a
/// version supplies its number by being that version, not by passing a
/// scale down through every helper.
let jumpArgScale (ins: Instruction) = if int ins.Version >= 310 then 2 else 1

let jumpByOffset (ins: Instruction) bld isForward =
  bld <!-- (ins.Address, ins.Length)
  let n = getIntArg ins * jumpArgScale ins
  let offset = n * (if isForward then 1 else -1)
  let dst = ins.Address + uint64 ins.Length + uint64 offset
  bld <+ AST.interjmp (AST.num (BitVector(dst, rt))) InterJmpKind.Base
  bld

(* Pre-3.11 jump opcodes (JUMP_ABSOLUTE, POP_JUMP_IF_FALSE/TRUE,
   JUMP_IF_FALSE/TRUE_OR_POP, JUMP_IF_NOT_EXC_MATCH) encode their target as
   an ABSOLUTE word offset (`oparg * 2`) from the CONTAINING CODE OBJECT's
   own start -- unlike 3.12's forward/backward opcodes, which are always
   relative to the jump instruction itself. Since B2R2 assigns each code
   object a real, distinct base address (not always 0), the actual target
   is that base plus the absolute word offset. Reuses the same
   (addrRange, _) lookup `binFile.Consts`/`Names`/`Varnames` already carry
   per code object (confirmed identical range across all of them, since
   they're all keyed off the same `code.Code` address/length) rather than
   adding a new table just for this. *)
let codeObjectBase (binFile: PythonBinFile) (addr: Addr) =
  binFile.Consts
  |> Array.tryFind (fun (ar, _) -> ar.Min <= addr && ar.Max >= addr)
  |> function
    | Some(ar, _) ->
      ar.Min
    | None ->
      failwithf "Cannot find the code object containing address 0x%x" addr

let jumpAbsolute (binFile: PythonBinFile) (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let n = getIntArg ins
  let dst = codeObjectBase binFile ins.Address + uint64 (n * jumpArgScale ins)
  bld <+ AST.interjmp (AST.num (BitVector(dst, rt))) InterJmpKind.Base
  bld

(* Pre-3.11 counterpart to condJump: same "honest" jumpIfTrue-preserving
   semantics (see condJump's own doc comment for why), but with an absolute
   rather than relative target -- see codeObjectBase's doc comment. *)
let condJumpAbsolute (binFile: PythonBinFile)
                     (ins: Instruction)
                     bld
                     jumpIfTrue =
  bld <!-- (ins.Address, ins.Length)
  let cond = popFromStack bld
  let n = getIntArg ins
  let jmpDst =
    codeObjectBase binFile ins.Address + uint64 (n * jumpArgScale ins)
  let fallDst = ins.Address + uint64 ins.Length
  let tLbl = AST.num (BitVector(jmpDst, rt))
  let fLbl = AST.num (BitVector(fallDst, rt))
  let cond, tLbl, fLbl =
    if jumpIfTrue then cond, tLbl, fLbl else cond, fLbl, tLbl
  bld <+ AST.intercjmp cond tLbl fLbl
  bld

(* JUMP_IF_FALSE_OR_POP / JUMP_IF_TRUE_OR_POP: like POP_JUMP_IF_*, but only
   pop TOS on the FALL-THROUGH side (short-circuit `and`/`or`) -- the
   not-taken branch keeps TOS as the expression's own result. Modeled with
   two explicit labels so each side gets its own stack effect, mirroring
   forIter's own label-based branching just above.
   (NOTE: an attempt to unify this with 3.12's COPY+POP_JUMP_IF_FALSE+
   POP_TOP shape via a single Ite-computed SP write before one real
   InterCJmp was tried and reverted -- it makes SP's value conditional on
   a runtime cond instead of a per-edge CONSTANT, which breaks
   StackPointerPropagation's ConstSP tracking that the whole StackVar
   mechanism depends on (confirmed via a cascading crash in
   processSSAStmt once several chained JUMP_IF_FALSE_OR_POPs' Ite
   expressions failed to fold to a constant offset). SP must change by a
   statically-known amount per CFG edge, which the label-based two-branch
   split already provides -- the real bug is elsewhere, still open.) *)
let jumpOrPop (binFile: PythonBinFile) (ins: Instruction) bld jumpIfTrue =
  bld <!-- (ins.Address, ins.Length)
  let cond = peekFromStack bld 0
  let n = getIntArg ins
  let jmpDst =
    codeObjectBase binFile ins.Address + uint64 (n * jumpArgScale ins)
  let fallDst = ins.Address + uint64 ins.Length
  let tLbl = AST.num (BitVector(jmpDst, rt))
  let fLbl = AST.num (BitVector(fallDst, rt))
  let lblLTrue = label bld "LTrue"
  let lblLFalse = label bld "LFalse"
  let cond = if jumpIfTrue then cond else AST.not cond
  bld <+ AST.cjmp cond (AST.jmpDest lblLTrue) (AST.jmpDest lblLFalse)
  bld <+ AST.lmark lblLTrue
  bld <+ AST.interjmp tLbl InterJmpKind.Base
  bld <+ AST.lmark lblLFalse
  discardTOS bld
  bld <+ AST.interjmp fLbl InterJmpKind.Base
  bld

let jumpIfNotExcMatch (binFile: PythonBinFile) (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let excType = popFromStack bld
  let excValue = popFromStack bld
  let n = getIntArg ins
  let jmpDst =
    codeObjectBase binFile ins.Address + uint64 (n * jumpArgScale ins)
  let fallDst = ins.Address + uint64 ins.Length
  let tLbl = AST.num (BitVector(jmpDst, rt))
  let fLbl = AST.num (BitVector(fallDst, rt))
  let matches = AST.app "CHECK_EXC_MATCH" [ excValue; excType ] rt
  (* Jump (to the next handler) when it does NOT match. *)
  bld <+ AST.intercjmp matches fLbl tLbl
  bld

(* ROT_TWO/THREE/FOUR/N: rotate the top `n` stack items by one slot,
   moving TOS down to position `n` (the bottom of the rotated window) and
   shifting everything above it up by one. Reads TOS first into a temp
   (so it survives being overwritten), then shifts each of the remaining
   n-1 items down into the slot below it in a single forward pass -- safe
   because each slot is read before it is ever written (see this
   function's own construction: iteration i reads slot i+1 and writes
   slot i, so slot i+1 is never touched by an earlier iteration). *)
let rotateTopToBottom n (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let spReg = regVar bld R.SP
  let top = peekFromStack bld 0
  for i in 0 .. n - 2 do
    let v = peekFromStack bld (i + 1)
    bld <+ (AST.store Endian.Little (slotAddr spReg i) v)
  bld <+ (AST.store Endian.Little (slotAddr spReg (n - 1)) top)
  bld --!> ins.Length

let dupTop (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  pushToStack bld (peekFromStack bld 0)
  bld --!> ins.Length

(* DUP_TOP_TWO: duplicates the top two items, keeping their relative
   order (stack before, top-to-bottom: a, b -> after: a, b, a, b). *)
let dupTopTwo (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let a = peekFromStack bld 0
  let b = peekFromStack bld 1
  pushToStack bld b
  pushToStack bld a
  bld --!> ins.Length

(* A binary/inplace operator with no oparg of its own (3.10-and-earlier:
   each operator is its own opcode, unlike 3.12's single BINARY_OP with an
   operator-selecting oparg -- see binaryOp's own arg-index table just
   below, whose named-app strings this mirrors so downstream HIR
   translation (which pattern-matches on those exact names) recognizes
   both versions' encodings identically). *)
let binaryOpDirect opExpr (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let right = popFromStack bld
  let left = popFromStack bld
  pushToStack bld (opExpr left right)
  bld --!> ins.Length

let copyDictWithoutKeys (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let keys = popFromStack bld
  let subject = peekFromStack bld 0
  pushToStack bld (AST.app "COPY_DICT_WITHOUT_KEYS" [ subject; keys ] rt)
  bld --!> ins.Length

let printExpr (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let v = popFromStack bld
  bld <+ AST.extCall (AST.app "PRINT_EXPR" [ v ] rt)
  bld --!> ins.Length

(* YIELD_FROM (pre-3.11 `yield from`/`await`): unlike 3.12's explicit
   GET_AWAITABLE + SEND-loop decomposition (recognized and folded by
   AwaitFolding.fs), YIELD_FROM is a single opcode that internally loops
   in the interpreter itself -- it either completes (leaving the
   sub-generator's final return value on the stack) or suspends (yielding
   a value, then resuming with the very same PC on the next `.send()`).
   Modeled as a single external-call step mirroring YIELD_VALUE's own
   "unknown resumption value" sentinel below, since the actual multi-path
   control flow (yield-and-loop vs completed) isn't something a single
   linear IR sequence can express -- HIR-level reconstruction of the
   pre-3.11 yield-from/await shape (an AwaitFolding.fs counterpart for
   this encoding) is a separate, not-yet-attempted follow-up; this only
   ensures the opcode lifts to something well-typed instead of crashing. *)
let yieldFrom (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let sendVal = popFromStack bld
  let subIter = peekFromStack bld 0
  bld <+ AST.extCall (AST.app "YIELD_FROM" [ subIter; sendVal ] rt)
  pushToStack bld yieldReceived
  bld --!> ins.Length

let callFunction (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let argc = getIntArg ins
  let args = List.init argc (fun _ -> popFromStack bld) |> List.rev
  let func = popFromStack bld
  (* Reuses "CALL"'s own named-app shape (maybeSelf :: func :: args @
     [kwReg]), just with an explicit NULL self-slot and NULL kwnames in
     place of 3.12's separate PUSH_NULL/KW_NAMES steps -- so the existing
     HIR translation for "CALL" (TranslationHelper.fs) recognizes this
     identically without needing its own separate pattern. *)
  let result = AST.app "CALL" (nullSlot :: func :: args @ [ nullSlot ]) rt
  pushToStack bld result
  bld --!> ins.Length

let callFunctionKw (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let argc = getIntArg ins
  let kwNamesTuple = popFromStack bld
  let args = List.init argc (fun _ -> popFromStack bld) |> List.rev
  let func = popFromStack bld
  let result = AST.app "CALL" (nullSlot :: func :: args @ [ kwNamesTuple ]) rt
  pushToStack bld result
  bld --!> ins.Length

(* LOAD_METHOD: like 3.12's LOAD_ATTR with its method flag always set --
   pushes NULL then the attribute, so a following CALL_METHOD (or CALL,
   see callMethod below) sees (NULL, boundMethod, args...) and treats it
   uniformly with the plain-attribute-then-call shape. Reuses "LOAD_ATTR"
   as the named app (not a separate "LOAD_METHOD") so the existing
   NULL-before-CALL method-call recognition in TranslationHelper.fs (built
   for 3.12's LOAD_ATTR-with-flag) applies here for free. *)
let loadMethod (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let name = operandIndex ins
  let obj = popFromStack bld
  let attr = AST.app "LOAD_ATTR" [ obj; name ] rt
  pushToStack bld nullSlot
  pushToStack bld attr
  bld --!> ins.Length

(* CALL_METHOD: pops argc args, the method (or plain attr) below them, and
   the self-or-NULL slot LOAD_METHOD left under that -- same three-part
   shape CALL already expects, just without a KW_NAMES register (3.10's
   LOAD_METHOD/CALL_METHOD pair is positional-only; a call needing keyword
   arguments instead falls back to plain LOAD_ATTR + CALL_FUNCTION_KW), so
   NULL fills that last slot. Reuses "CALL" for the same reason
   callFunction above does. *)
let callMethod (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let argc = getIntArg ins
  let args = List.init argc (fun _ -> popFromStack bld) |> List.rev
  let methodOrFunc = popFromStack bld
  let selfOrNull = popFromStack bld
  let result =
    AST.app "CALL" (selfOrNull :: methodOrFunc :: args @ [ nullSlot ]) rt
  pushToStack bld result
  bld --!> ins.Length

let endFor (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  discardTOS bld
  bld --!> ins.Length

(* END_SEND: removes the second-from-top value (the exhausted generator
   left by SEND), keeping the top (the awaited result) in place. *)
let endSend (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let value = popFromStack bld
  discardTOS bld
  pushToStack bld value
  bld --!> ins.Length

let copy (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let n = getIntArg ins
  pushToStack bld (peekFromStack bld (n - 1))
  bld --!> ins.Length

let swap (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let n = getIntArg ins
  let top = peekFromStack bld 0
  let nth = peekFromStack bld (n - 1)
  let spReg = regVar bld R.SP
  let tmp = tmpVar bld rt
  bld <+ (tmp := top)
  bld <+ (AST.store Endian.Little spReg nth)
  bld <+ (AST.store Endian.Little (slotAddr spReg (n - 1)) tmp)
  bld --!> ins.Length

(* Generic store for STORE_FAST / STORE_NAME / STORE_GLOBAL / STORE_DEREF:
   pop TOS and emit an external call recording the target name. *)
let storeNamed opname (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let name = operandIndex ins
  let value = popFromStack bld
  let eff = AST.app opname [ name; value ] rt
  bld <+ AST.extCall eff
  bld --!> ins.Length

(* STORE_ATTR: TOS = value, TOS1 = obj => obj.attr = value *)
let storeAttr (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let name = operandIndex ins
  let obj = popFromStack bld
  let value = popFromStack bld
  let eff = AST.app "STORE_ATTR" [ name; obj; value ] rt
  bld <+ AST.extCall eff
  bld --!> ins.Length

(* LOAD_ATTR: pop TOS (obj), push obj.attr.
   In Python >= 3.11, ins.Flag = true means method mode: push NULL then the
   attr so that CALL sees (NULL, obj.attr, args) and treats obj as self. *)
let loadAttr (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let name = operandIndex ins
  let obj = popFromStack bld
  let attr = AST.app "LOAD_ATTR" [ obj; name ] rt
  if ins.Flag then pushToStack bld nullSlot else ()
  pushToStack bld attr
  bld --!> ins.Length

(* LOAD_SUPER_ATTR: pops self, __class__, and the global `super` reference
   (pushed by preceding LOAD_FAST self / LOAD_DEREF __class__ / LOAD_GLOBAL
   super), and computes getattr(super(__class__, self), name). For the
   common zero-arg `super()` form, __class__/self are compiler-generated,
   so the HIR reconstruction just emits the literal `super().name` form and
   the popped values only need to preserve stack balance. For an explicit
   `super(cls, obj).attr`, __class__/self are real user expressions, so we
   tag it differently to keep them. *)
let loadSuperAttr (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let name = operandIndex ins
  let self = popFromStack bld
  let cls = popFromStack bld
  let superGlobal = popFromStack bld
  let opname =
    if ins.SuperHasExplicitArgs then "LOAD_SUPER_ATTR_EXPLICIT"
    else "LOAD_SUPER_ATTR"
  let attr = AST.app opname [ superGlobal; cls; self; name ] rt
  if ins.Flag then pushToStack bld nullSlot else ()
  pushToStack bld attr
  bld --!> ins.Length

(* STORE_SUBSCR: TOS1[TOS] = TOS2 ??pops three items. *)
let storeSubscript (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let sub = popFromStack bld
  let obj = popFromStack bld
  let value = popFromStack bld
  let eff = AST.app "STORE_SUBSCR" [ obj; sub; value ] rt
  bld <+ AST.extCall eff
  bld --!> ins.Length

(* STORE_SLICE: TOS2[TOS1:TOS] = TOS3 ??pops four items. *)
let storeSlice (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let stop = popFromStack bld
  let start = popFromStack bld
  let obj = popFromStack bld
  let value = popFromStack bld
  let eff = AST.app "STORE_SLICE" [ obj; start; stop; value ] rt
  bld <+ AST.extCall eff
  bld --!> ins.Length

(* DELETE_SUBSCR: del TOS1[TOS] ??pops two items. *)
let deleteSubscript (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let sub = popFromStack bld
  let obj = popFromStack bld
  let eff = AST.app "DELETE_SUBSCR" [ obj; sub ] rt
  bld <+ AST.extCall eff
  bld --!> ins.Length

(* RETURN_VALUE: pop TOS and emit a RETURN call. *)
let translateReturn (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let value = popFromStack bld
  bld <+ AST.extCall (AST.app "RETURN" [ value ] rt)
  bld <+ (AST.interjmp returnTarget InterJmpKind.IsRet)
  bld

(* RETURN_CONST: load constant directly without a stack round-trip. *)
let translateReturnConst (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let name = operandIndex ins
  let value = AST.app "LOAD_CONST" [ name ] rt
  bld <+ AST.extCall (AST.app "RETURN" [ value ] rt)
  bld <+ (AST.interjmp returnTarget InterJmpKind.IsRet)
  bld

(* RAISE_VARARGS arg: pop arg items (0??) and raise. *)
let translateRaiseVarargs (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let n = getIntArg ins
  let args = List.init n (fun _ -> popFromStack bld)
  bld <+ AST.extCall (AST.app "RAISE_VARARGS" args rt)
  bld <+ AST.sideEffect SideEffect.Terminate
  bld --!> ins.Length

(* Conditional jump shared by POP_JUMP_IF_FALSE and POP_JUMP_IF_TRUE.
   jumpIfTrue=true  ??jump when TOS is truthy.
   jumpIfTrue=false ??jump when TOS is falsy. *)
let condJump (ins: Instruction) bld jumpIfTrue =
  bld <!-- (ins.Address, ins.Length)
  let cond = popFromStack bld
  let n = getIntArg ins
  let jmpDst = ins.Address + uint64 ins.Length + uint64 (n * jumpArgScale ins)
  let fallDst = ins.Address + uint64 ins.Length
  let tLbl = AST.num (BitVector(jmpDst, rt))
  let fLbl = AST.num (BitVector(fallDst, rt))
  (* EXPERIMENTAL (2026-07-27): previously, jumpIfTrue negated cond and
     swapped tLbl/fLbl, canonicalizing every conditional jump to "fallthrough
     = true edge" regardless of the original opcode. Execution-wise that is
     equivalent (De Morgan), but it discards which branch was the real
     jump-taken target -- e.g. `if x in y: body` (no else, body is the
     loop's last statement) compiles via POP_JUMP_IF_TRUE, and after the old
     swap, Translator.fs saw an artificially negated `not (x in y)` with the
     body/continue roles exchanged, printing `if not (x in y): continue`
     instead of the original `if x in y: body` -- same runtime behavior, but
     failing bytecode-identity (`x not in y` compiles to a genuinely
     different CONTAINS_OP arg + POP_JUMP_IF_FALSE, not just a `not` wrapper
     -- confirmed by direct comparison). This "honest" version keeps cond
     and the two labels exactly as they map onto POP_JUMP_IF_TRUE's real
     semantics (jump to jmpDst when truthy), matching the FALSE case's
     existing (unmodified) mapping in spirit -- to see, empirically, what in
     the CFG-recovery/dominance/loop-detection pipeline actually depends on
     the old canonicalization before deciding whether to keep this. *)
  let cond, tLbl, fLbl =
    if jumpIfTrue then cond, tLbl, fLbl else cond, fLbl, tLbl
  bld <+ AST.intercjmp cond tLbl fLbl
  bld

(* Conditional jump for POP_JUMP_IF_NONE / POP_JUMP_IF_NOT_NONE.
   jumpIfNone=true  ??jump when TOS is None (modeled as IS_NONE(TOS) = 1).
   jumpIfNone=false ??jump when TOS is not None. *)
let condJumpNone (ins: Instruction) bld jumpIfNone =
  bld <!-- (ins.Address, ins.Length)
  let value = popFromStack bld
  let n = getIntArg ins
  let jmpDst = ins.Address + uint64 ins.Length + uint64 (n * jumpArgScale ins)
  let fallDst = ins.Address + uint64 ins.Length
  let tLbl = AST.num (BitVector(jmpDst, rt))
  let fLbl = AST.num (BitVector(fallDst, rt))
  (* EXPERIMENTAL (2026-07-27): honest counterpart to condJump's fix above
     -- jump directly to jmpDst on the condition that actually matches the
     opcode's own real semantics (IS_NONE for POP_JUMP_IF_NONE, IS_NOT_NONE
     for POP_JUMP_IF_NOT_NONE), instead of negating to the contrapositive
     and swapping tLbl/fLbl to fit the old "fallthrough = true edge"
     canonicalization. *)
  if jumpIfNone then
    let isNone = AST.app "IS_NONE" [ value ] rt
    bld <+ AST.intercjmp isNone tLbl fLbl
  else
    let isNotNone = AST.app "IS_NOT_NONE" [ value ] rt
    bld <+ AST.intercjmp isNotNone tLbl fLbl
  bld

let forIter minor (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let tos = peekFromStack bld 0
  let n = getIntArg ins
  let jmpDst = ins.Address + uint64 ins.Length + uint64 (n * jumpArgScale ins)
  let fallDst = ins.Address + uint64 ins.Length
  let tLbl = AST.num (BitVector(jmpDst, rt))
  let fLbl = AST.num (BitVector(fallDst, rt))
  let cond = AST.app "IS_EXHAUSTED" [ tos ] rt
  let lblLTrue = label bld "LTrue"
  let lblLFalse = label bld "LFalse"
  bld <+ AST.cjmp cond (AST.jmpDest lblLTrue) (AST.jmpDest lblLFalse)
  (* True branch: pop the exhausted iterator and jump to the loop exit. *)
  bld <+ AST.lmark lblLTrue
  if minor < 12 then discardTOS bld
  (* From 3.12, END_FOR is introduced and instead pops the iterator. *)
  else ()
  bld <+ AST.interjmp tLbl InterJmpKind.Base
  (* False branch: jump to the body and push the next value. *)
  bld <+ AST.lmark lblLFalse
  let tos = peekFromStack bld 0
  pushToStack bld (AST.app "NEXT" [ tos ] rt)
  bld <+ AST.interjmp fLbl InterJmpKind.Base
  bld

let getIter (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let iter = popFromStack bld
  let iterNext = AST.app "GET_ITER" [ iter ] rt
  pushToStack bld iterNext
  bld --!> ins.Length

(* SEND: pop TOS (sent value), pop TOS1 (generator), call send(gen, val).
   Per CPython's own bytecodes.c, the stack effect is
   `(receiver, v -- receiver, retval)` on BOTH the exhausted and
   not-exhausted paths -- receiver stays regardless; only END_SEND (via
   the exhausted jump) later drops it. So push gen back unconditionally,
   then push the result, then jump on exhaustion or fall through. *)
let send (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let sentVal = popFromStack bld
  let gen = popFromStack bld
  let result = AST.app "SEND" [ gen; sentVal ] rt
  let n = getIntArg ins
  let jmpDst = ins.Address + uint64 ins.Length + uint64 (n * jumpArgScale ins)
  let fallDst = ins.Address + uint64 ins.Length
  let isExhausted = AST.app "IS_EXHAUSTED" [ result ] rt
  pushToStack bld gen
  pushToStack bld result
  bld <+ AST.intercjmp isExhausted
    (AST.num (BitVector(jmpDst, rt)))
    (AST.num (BitVector(fallDst, rt)))
  bld

let getYieldFromIter (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let tos = popFromStack bld
  pushToStack bld (AST.app "GET_YIELD_FROM_ITER" [ tos ] rt)
  bld --!> ins.Length

let kwNames (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let names = operandIndex ins
  let kwReg = regVar bld R.KW_NAMES
  bld <+ (kwReg := names)
  bld --!> ins.Length

let call (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let argc = getIntArg ins
  let args = List.init argc (fun _ -> popFromStack bld) |> List.rev
  let func = popFromStack bld
  let maybeSelf = popFromStack bld
  let kwReg = regVar bld R.KW_NAMES
  let result = AST.app "CALL" (maybeSelf :: func :: args @ [ kwReg ]) rt
  pushToStack bld result
  bld <+ (kwReg := nullSlot)
  bld --!> ins.Length

let consumeAndPush name (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let v = popFromStack bld
  let result = AST.app name [ v ] rt
  pushToStack bld result
  bld --!> ins.Length

let makeFunction (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let flags = getIntArg ins
  let codeObj = popFromStack bld
  if flags &&& 0x08 <> 0 then discardTOS bld else ()
  let annotations =
    if flags &&& 0x04 <> 0 then popFromStack bld else nullSlot
  let kwDefs =
    if flags &&& 0x02 <> 0 then popFromStack bld else nullSlot
  let posDefs =
    if flags &&& 0x01 <> 0 then popFromStack bld else nullSlot
  let result =
    AST.app "MAKE_FUNCTION" [ codeObj; posDefs; kwDefs; annotations ] rt
  pushToStack bld result
  bld --!> ins.Length

(* Pre-3.11: MAKE_FUNCTION's stack order is different in two ways --
   there's an explicit qualname STRING on top of the code object (3.11+
   bakes qualname into the code object's own metadata instead, so this
   slot doesn't exist there at all), and the flag-dependent extras
   (closure/annotations/kwdefaults/posdefaults) sit BELOW the code object
   rather than above it, popped in the OPPOSITE bit order (0x01 first,
   not 0x08 first) -- reusing the 3.12 version's `makeFunction` verbatim
   silently popped the qualname string as if it were the code object
   itself, corrupting every nested function's own CodeRef into its own
   qualname text instead of an address-based ref (confirmed via `10013`
   in the CSN 3.10 sweep: `fillIncompleteFuncSigs` crashed looking up
   codeRef `"get_bucket"` -- the qualname -- instead of `"<90>"`). *)
let makeFunctionLegacy (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let flags = getIntArg ins
  (* Neither popFromStack-and-ignore NOR discardTOS works here: either
     way, the qualname's own LOAD_CONST push ends up as a dead SSA value
     nothing ever reads, and a generic "unconsumed LOAD_CONST becomes its
     own standalone statement" rule elsewhere (TranslationHelper.fs,
     `processSSAStmt`'s `isDeadVar` LOAD_CONST case) then mistakes it for
     a genuine bare-expression statement, printing the qualname as a
     bogus leading module "docstring" (confirmed via a minimal `def
     foo(x): return x + 1` repro under 3.10). That rule only fires on a
     bare `Def`, not an external call -- wrapping the pop in one marks it
     as genuinely consumed (no longer "dead") without needing a
     recognized opcode name for `processSSAStmt`'s catch-all to actually
     act on (an unrecognized ExternalCall name is silently ignored, same
     as e.g. register-bookkeeping Defs are). *)
  let qualname = popFromStack bld
  bld <+ AST.extCall (AST.app "DISCARD" [ qualname ] rt)
  let codeObj = popFromStack bld
  let posDefs =
    if flags &&& 0x01 <> 0 then popFromStack bld else nullSlot
  let kwDefs =
    if flags &&& 0x02 <> 0 then popFromStack bld else nullSlot
  let annotations =
    if flags &&& 0x04 <> 0 then popFromStack bld else nullSlot
  if flags &&& 0x08 <> 0 then discardTOS bld else ()
  let result =
    AST.app "MAKE_FUNCTION" [ codeObj; posDefs; kwDefs; annotations ] rt
  pushToStack bld result
  bld --!> ins.Length

(* Pre-3.11, the callable sits directly on TOS with no NULL/self slot
   beneath it (that slot is a 3.11+ addition, matching CALL's own
   NULL-or-self convention elsewhere in this file) -- popping it
   unconditionally here consumed one stack slot too many under 3.10,
   silently desynchronizing SP from the CPython-defined stack effect
   (confirmed via `etc_4`/`async_callback` in datasets/examples/src/
   regression.py: a `functools.partial(callback, *args, **kwargs)` call
   whose two branches merge into a shared return, surfacing as an
   untranslatable raw `Load(MemVar, ...)` once SSAStackPointerPropagation
   lost ConstSP tracking after the phantom extra pop). *)
let callFunctionEx minor (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let flags = getIntArg ins
  let kwargs =
    if flags &&& 0x01 <> 0 then popFromStack bld else nullSlot
  let args = popFromStack bld
  let func = popFromStack bld
  let maybeSelf = if minor >= 11 then popFromStack bld else nullSlot
  let result = AST.app "CALL_FUNCTION_EX" [ maybeSelf; func; args; kwargs ] rt
  pushToStack bld result
  bld --!> ins.Length

let listAppend (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let i = getIntArg ins
  let item = popFromStack bld
  let lst = peekFromStack bld (i - 1)
  bld <+ AST.extCall (AST.app "LIST_APPEND" [ lst; item ] rt)
  bld --!> ins.Length

let setAdd (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let i = getIntArg ins
  let item = popFromStack bld
  let st = peekFromStack bld (i - 1)
  bld <+ AST.extCall (AST.app "SET_ADD" [ st; item ] rt)
  bld --!> ins.Length

let mapAdd (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let i = getIntArg ins
  let value = popFromStack bld
  let key = popFromStack bld
  let mp = peekFromStack bld (i - 1)
  bld <+ AST.extCall (AST.app "MAP_ADD" [ mp; key; value ] rt)
  bld --!> ins.Length

(* DICT_MERGE/DICT_UPDATE replace the dict `i-1` slots below TOS with a new
   merged value -- rather than popping it, updating in place, and leaving
   everything else on the stack untouched, the original lifting peeked at
   that slot and stored the merged result back via a raw memory write at a
   computed offset. That store bypasses pushToStack/popFromStack, the only
   stack effects SSAStackPointerPropagation's ConstSP tracking recognizes
   (see its own `Load _ -> NotConstSP` catch-all) -- so any LATER access
   built on an address derived from this slot no longer resolves to a
   clean StackVar reference, and surfaces instead as a raw, untranslatable
   `Load` (confirmed via real-world PyPI/CSN code using chained calls that
   unpack several iterables and mappings at once). Popping down to the
   dict (saving any
   intervening values), then pushing the merged result followed by the
   saved values back in their original order, keeps every stack slot's
   value flowing through the same recognized push/pop primitives as
   everywhere else. *)
let dictMerge name (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let i = getIntArg ins
  let update = popFromStack bld
  let saved = [| for _ in 1 .. i - 1 -> popFromStack bld |]
  let dict = popFromStack bld
  let merged = AST.app name [ dict; update ] rt
  pushToStack bld merged
  for v in Array.rev saved do pushToStack bld v
  bld --!> ins.Length

let cmpOpType = function
  | 0 -> RelOpType.LT
  | 1 -> RelOpType.LE
  | 2 -> RelOpType.EQ
  | 3 -> RelOpType.NEQ
  | 4 -> RelOpType.GT
  | 5 -> RelOpType.GE
  | _ -> Terminator.futureFeature ()

(* COMPARE_OP: pop right (TOS) then left (TOS1), push bool result.
   In 3.12+ the operator index is arg >> 4; lower bits are cache flags. *)
let compareOP minor (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let n = getIntArg ins
  let opIdx = if minor >= 12 then n >>> 4 else n
  let right = popFromStack bld
  let left = popFromStack bld
  let b = AST.relop (cmpOpType opIdx) left right
  let b = AST.zext rt b
  pushToStack bld b
  bld --!> ins.Length

(* IS_OP: pop TOS (right) and TOS1 (left), push identity test.
   operand=0 ??left is right; operand=1 ??left is not right. *)
let isOp (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let invert = getIntArg ins
  let right = popFromStack bld
  let left = popFromStack bld
  let fname = if invert = 0 then "IS_OP" else "NOT_IS_OP"
  pushToStack bld (AST.app fname [ left; right ] rt)
  bld --!> ins.Length

(* CONTAINS_OP: pop TOS (container) and TOS1 (item), push membership test.
   operand=0 ??item in container; operand=1 ??item not in container. *)
let containsOp (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let invert = getIntArg ins
  let container = popFromStack bld
  let item = popFromStack bld
  let fname = if invert = 0 then "CONTAINS_OP" else "NOT_CONTAINS_OP"
  let result = AST.app fname [ container; item ] rt
  pushToStack bld result
  bld --!> ins.Length

(* BINARY_OP: pop right (TOS) and left (TOS1), apply operator, push result.
   arg directly indexes the operation; inplace variants (arg >= 13) share
   the same index offset as their non-inplace counterparts. *)
let binaryOp (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let right = popFromStack bld
  let left = popFromStack bld
  let result =
    (* CPython BINARY_OP arg: 0-12 are the plain ops, 13-25 the matching
       in-place (`+=`, `-=`, ...) variants (regular + 13). The in-place ones
       dispatch to `__iadd__` etc. and can mutate in place, so -- unlike a
       generic binary lifter -- we must NOT fold them into the plain op; they
       are lifted to distinct named apps that a store recovers as AugAssign
       (see makeAssign). Matrix-multiply follows the same plain/in-place
       split as every other operator here (`@` at 4, `@=` at 17 = 4 + 13). *)
    match getIntArg ins with
    | 0 -> AST.binop BinOpType.ADD left right
    | 1 -> AST.binop BinOpType.AND left right
    | 2 -> AST.app "//" [ left; right ] rt
    | 3 -> AST.binop BinOpType.SHL left right
    | 4 -> AST.app "@" [ left; right ] rt
    | 5 -> AST.binop BinOpType.MUL left right
    | 6 -> AST.binop BinOpType.MOD left right
    | 7 -> AST.binop BinOpType.OR left right
    | 8 -> AST.app "**" [ left; right ] rt
    | 9 -> AST.binop BinOpType.SAR left right
    | 10 -> AST.binop BinOpType.SUB left right
    | 11 -> AST.binop BinOpType.DIV left right
    | 12 -> AST.binop BinOpType.XOR left right
    | 13 -> AST.app "IADD" [ left; right ] rt
    | 14 -> AST.app "IBITAND" [ left; right ] rt
    | 15 -> AST.app "IFLOORDIV" [ left; right ] rt
    | 16 -> AST.app "ILSHIFT" [ left; right ] rt
    | 17 -> AST.app "IMATMUL" [ left; right ] rt
    | 18 -> AST.app "IMUL" [ left; right ] rt
    | 19 -> AST.app "IMOD" [ left; right ] rt
    | 20 -> AST.app "IBITOR" [ left; right ] rt
    | 21 -> AST.app "IPOW" [ left; right ] rt
    | 22 -> AST.app "IRSHIFT" [ left; right ] rt
    | 23 -> AST.app "ISUB" [ left; right ] rt
    | 24 -> AST.app "IDIV" [ left; right ] rt
    | 25 -> AST.app "IBITXOR" [ left; right ] rt
    | n -> failwithf "Invalid BINARY_OP arg %d at %A" n ins.Address
  pushToStack bld result
  bld --!> ins.Length

let binarySubscr (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let idx = popFromStack bld
  let obj = popFromStack bld
  pushToStack bld (AST.app "BINARY_SUBSCR" [ obj; idx ] rt)
  bld --!> ins.Length

let binarySlice (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let stop = popFromStack bld
  let start = popFromStack bld
  let obj = popFromStack bld
  pushToStack bld (AST.app "BINARY_SLICE" [ obj; start; stop ] rt)
  bld --!> ins.Length

let unpackSequence (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let n = getIntArg ins
  let seq = popFromStack bld
  for i in 0 .. n - 1 do
    let elem = AST.app "UNPACK" [ seq; AST.num (BitVector(i, rt)) ] rt
    pushToStack bld elem
  bld --!> ins.Length

(* Same fix as dictMerge above, and for the same reason: pop down to the
   list (saving any intervening values), extend it, then push the result
   back followed by the saved values, instead of peeking and writing the
   new value back via a raw store SSAStackPointerPropagation's ConstSP
   tracking cannot see through. *)
let listExtend (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let n = getIntArg ins
  let tos = popFromStack bld
  let saved = [| for _ in 1 .. n - 1 -> popFromStack bld |]
  let lst = popFromStack bld
  let extended = AST.app "LIST_EXTEND" [ lst; tos ] rt
  pushToStack bld extended
  for v in Array.rev saved do pushToStack bld v
  bld --!> ins.Length

let buildCollection name (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let n = getIntArg ins
  let items =
    [| for _ in 0 .. n - 1 do yield popFromStack bld |]
    |> Array.rev
    |> Array.toList
  pushToStack bld (AST.app name items rt)
  bld --!> ins.Length

(* BUILD_MAP: pops n key-value pairs (key1 value1 ... keyN valueN from
   bottom to top) and pushes the resulting dict. *)
let buildMap (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let n = getIntArg ins
  let items =
    [| for _ in 0 .. (2 * n) - 1 do yield popFromStack bld |]
    |> Array.rev
    |> Array.toList
  pushToStack bld (AST.app "BUILD_MAP" items rt)
  bld --!> ins.Length

(* BUILD_CONST_KEY_MAP: TOS = keys tuple, TOS1..TOS(n) = values.
   Pops keys then n values; pushes the resulting dict. *)
let buildConstKeyMap (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let n = getIntArg ins
  let keys = popFromStack bld
  let values =
    [| for _ in 0 .. n - 1 do yield popFromStack bld |]
    |> Array.rev
    |> Array.toList
  pushToStack bld (AST.app "BUILD_CONST_KEY_MAP" (keys :: values) rt)
  bld --!> ins.Length

(* FORMAT_VALUE: flags & 0x3 = conversion (0=none,1=str,2=repr,3=ascii);
   flags & 0x4 = has_format_spec. Pops spec (if any) then value; pushes
   the formatted string. The conversion travels as the two-bit selector the
   oparg already holds rather than a rendering of it, so the operand stays a
   number the IR can actually reason about. *)
let formatValue (ins: Instruction) bld =
  bld <!-- (ins.Address, ins.Length)
  let flags = getIntArg ins
  let spec = if flags &&& 0x4 <> 0 then [ popFromStack bld ] else []
  let value = popFromStack bld
  let conv = numI32 (flags &&& 0x3) rt
  let result = AST.app "FORMAT_VALUE" (value :: conv :: spec) rt
  pushToStack bld result
  bld --!> ins.Length
