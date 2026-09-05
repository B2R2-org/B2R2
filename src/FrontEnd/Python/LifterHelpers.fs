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

let getIntArg (ins: Instruction) =
  match ins.Operands with
  | OneOperand(arg, _) -> arg
  | _ -> failwith "Expected one operand with an integer argument."

/// The instruction's argument, or the given value when this version's
/// encoding gives the opcode none. An opcode that gains or loses its oparg
/// across versions -- 3.1 gave LIST_APPEND and SET_ADD theirs, 3.13 took
/// MAKE_FUNCTION's away -- otherwise reaches getIntArg with NoOperand and
/// fails there, which is a lifting failure rather than the missing argument's
/// own well-defined meaning.
let getIntArgOr dflt (ins: Instruction) =
  match ins.Operands with
  | OneOperand(arg, _) -> arg
  | _ -> dflt

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
  append bld {
    let spReg = regVar bld R.SP
    spReg := (spReg .- stackSlotSize)
    AST.store Endian.Little spReg expr
  }

/// Pops an element from the evaluation stack and returns it.
let popFromStack bld =
  let spReg = regVar bld R.SP
  let tmp = tmpVar bld rt
  append bld {
    tmp := AST.loadLE rt spReg
    spReg := (spReg .+ stackSlotSize)
  }
  tmp

/// Pops an element from the evaluation stack but does not return it.
let discardTOS bld =
  let spReg = regVar bld R.SP
  append bld {
    spReg := (spReg .+ stackSlotSize)
  }

(* Returns the expression at stack[SP + offset] without modifying SP.
   offset=0 is TOS, offset=1 is TOS1, etc. *)
let peekFromStack bld offset =
  let spReg = regVar bld R.SP
  let tmp = tmpVar bld rt
  append bld {
    tmp := AST.loadLE rt (slotAddr spReg offset)
  }
  tmp

(* Emit ISMark + IEMark only; used for no-op instructions. *)
let nopInstr (ins: Instruction) bld =
  lift bld ins ins.Length {
  }

let effInstr eff (ins: Instruction) bld =
  lift bld ins ins.Length {
    AST.extCall eff
  }

let namedEffect name ins bld = effInstr (AST.app name [] rt) ins bld

let namedEffectWithArgs name args ins bld =
  effInstr (AST.app name args rt) ins bld

(* A unary operator (UNARY_NEGATIVE/INVERT/POSITIVE/NOT): pop the operand and
   push the operator applied to it. Modeled as a named app (like `**`/`//`)
   so the surface operator is preserved for decompilation, rather than as a
   stack-ignoring effect that would silently drop the operand's sign. *)
let unaryOp name (ins: Instruction) bld =
  lift bld ins ins.Length {
    let operand = popFromStack bld
    pushToStack bld (AST.app name [ operand ] rt)
  }

/// The truth of an object, which is what a conditional jump branches on.
/// Every type answers it and most of them say something the reference itself
/// cannot: zero, the empty string, the empty list and None are all false while
/// being perfectly good objects. So the question goes to whoever knows the
/// object model, exactly as 3.13's own TO_BOOL opcode hands it over -- testing
/// the lifted value's bits would instead ask whether the guest is holding
/// anything at all, which it always is.
let truthOf value = AST.app "IS_TRUTHY" [ value ] rt

/// A binary operator as a named call, which every one of them is: Python's
/// operators dispatch on their operands' types (`__add__` and friends), so
/// `+` may add, concatenate, or run a user's own method, and comparisons
/// answer with whatever `__lt__` returns rather than a bit. A lifted value is
/// also a reference to an object, not the object's own bits, so an IR
/// operator applied to two of them would compute on the references -- a
/// silently wrong result rather than a refused one. Naming the operator hands
/// both problems to a consumer that knows the object model, which is what //,
/// @ and ** have always done here.
let opApp name l r = AST.app name [ l; r ] rt

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

/// The same, with the flag bits some opcodes pack below the index removed:
/// LOAD_GLOBAL's push-NULL bit from 3.11, LOAD_ATTR's is-method bit from 3.12,
/// and LOAD_SUPER_ATTR's two bits from 3.12. What travels has to be the index
/// that actually selects the entry -- the flag is already available on its own
/// through ins.Flag, and nothing downstream could tell from the IR alone how
/// far to shift. The shifts mirror each version's own Parsing.resolveOperand,
/// which reads the same operand for the disassembler.
let private shiftedIndex bits (ins: Instruction) =
  numI32 (getIntArg ins >>> bits) rt

let globalIndex (ins: Instruction) =
  if int ins.Version >= 311 then shiftedIndex 1 ins else operandIndex ins

let attrIndex (ins: Instruction) =
  if int ins.Version >= 312 then shiftedIndex 1 ins else operandIndex ins

let superAttrIndex (ins: Instruction) =
  if int ins.Version >= 312 then shiftedIndex 2 ins else operandIndex ins

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
  lift bld ins ins.Length {
    pushToStack bld (AST.app opname [ operandIndex ins ] rt)
  }

(* LOAD_LOCALS: leaves the mapping the running activation binds into. A class
   body written with type parameters is what reaches for it -- the parameters
   are a scope of their own, and the body reads a name out of this before
   falling back to its own cells -- so it has to leave that mapping rather than
   nothing at all. *)
let loadLocals (ins: Instruction) bld =
  lift bld ins ins.Length {
    pushToStack bld (AST.app "LOAD_LOCALS" [] rt)
  }

(* LOAD_FROM_DICT_OR_DEREF and LOAD_FROM_DICT_OR_GLOBALS: the name is looked
   for in the mapping LOAD_LOCALS left, and only then in the cell or the
   module. The mapping is popped -- CPython's own stack effect consumes it --
   so it travels as an operand rather than being left behind. *)
let loadFromDict opname (ins: Instruction) bld =
  lift bld ins ins.Length {
    let mapping = popFromStack bld
    pushToStack bld (AST.app opname [ mapping; operandIndex ins ] rt)
  }

(* Which of the two slots a call sits on is the deeper. 3.11 gave every call a
   self-or-NULL beside its callable and put it underneath; 3.13 swapped the
   pair, so the callable is pushed first and the slot above it. Everything that
   leaves that pair -- a global or attribute load with its own flag set, and a
   super lookup with the same -- swapped with it. *)
let calleeFirst (ins: Instruction) = ins.Minor >= 13

(* The pair, taken off in whichever order this version put them on. *)
let popCallee (ins: Instruction) bld =
  if calleeFirst ins then
    let maybeSelf = popFromStack bld
    popFromStack bld, maybeSelf
  else
    let func = popFromStack bld
    func, popFromStack bld

(* And put on the same way: the callable, with the empty self-slot beside it
   where the instruction's flag asked for one. *)
let pushCallee (ins: Instruction) bld callee =
  if not ins.Flag then
    pushToStack bld callee
  elif calleeFirst ins then
    pushToStack bld callee
    pushToStack bld nullSlot
  else
    pushToStack bld nullSlot
    pushToStack bld callee

let translateLoadGlobal (ins: Instruction) bld =
  lift bld ins ins.Length {
    pushCallee ins bld (AST.app "LOAD_GLOBAL" [ globalIndex ins ] rt)
  }

let translateDelete opname (ins: Instruction) bld =
  namedEffectWithArgs opname [ operandIndex ins ] ins bld

(* DELETE_ATTR: pops the owner object and deletes the named attribute. *)
let deleteAttr (ins: Instruction) bld =
  lift bld ins ins.Length {
    let owner = popFromStack bld
    let args = [ owner; operandIndex ins ]
    AST.extCall (AST.app "DELETE_ATTR" args rt)
  }

(* IMPORT_NAME: pops fromlist (unused by our translation) and level (the
   number of leading dots for a relative import, e.g. `from ..pkg import x`),
   then pushes the imported module object. *)
let importName (ins: Instruction) bld =
  lift bld ins ins.Length {
    let name = operandIndex ins
    let fromList = popFromStack bld
    let level = popFromStack bld
    pushToStack bld (AST.app "IMPORT_NAME" [ name; level; fromList ] rt)
  }

(* IMPORT_FROM: peeks (does not pop) the module object left by IMPORT_NAME so
   that later IMPORT_FROMs can reuse it, and pushes obj.name. *)
let importFrom (ins: Instruction) bld =
  lift bld ins ins.Length {
    let name = operandIndex ins
    let moduleObj = peekFromStack bld 0
    pushToStack bld (AST.app "IMPORT_FROM" [ moduleObj; name ] rt)
  }

(* IMPORT_STAR: pops the module object and binds all its exported names. *)
let importStar (ins: Instruction) bld =
  lift bld ins ins.Length {
    let moduleObj = popFromStack bld
    AST.extCall (AST.app "IMPORT_STAR" [ moduleObj ] rt)
  }

(* Which intrinsic CALL_INTRINSIC_1's argument selects. They are not alike
   enough to share a name: the list-to-tuple one is what every call written
   with a `*` spread ends with, and lifting it under the same name as the rest
   leaves such a call no arguments to make. *)
let private intrinsic1Name arg =
  match arg with
  | 1 -> "INTRINSIC_PRINT"
  | 3 -> "INTRINSIC_STOPITERATION_ERROR"
  | 4 -> "INTRINSIC_ASYNC_GEN_WRAP"
  | 5 -> "UNARY_POSITIVE"
  | 6 -> "LIST_TO_TUPLE"
  | 7 -> "INTRINSIC_TYPEVAR"
  | 8 -> "INTRINSIC_PARAMSPEC"
  | 9 -> "INTRINSIC_TYPEVARTUPLE"
  | 10 -> "INTRINSIC_SUBSCRIPT_GENERIC"
  | 11 -> "INTRINSIC_TYPEALIAS"
  | _ -> "CALL_INTRINSIC_1"

(* CALL_INTRINSIC_1 took over several standalone opcodes in 3.12, import star
   among them, and folded them into one shape: an intrinsic takes a single
   operand and leaves a single result. Import star is the one whose result is
   worth nothing -- it binds names, and the compiler discards what it left with
   its own POP_TOP -- but the slot is still there, and consuming without
   leaving walks the stack pointer off its own region a few statements later.
   Every other one leaves the value the instruction is for. *)
let callIntrinsic1 (ins: Instruction) bld =
  lift bld ins ins.Length {
    let operand = popFromStack bld
    let arg = getIntArg ins
    if arg = 2 then
      AST.extCall (AST.app "IMPORT_STAR" [ operand ] rt)
      pushToStack bld noneValue
    else
      pushToStack bld (AST.app (intrinsic1Name arg) [ operand ] rt)
  }

let popTop (ins: Instruction) bld =
  lift bld ins ins.Length {
    discardTOS bld
  }

/// PUSH_NULL: NULL is a special value implemented in Python internally.
let pushNull (ins: Instruction) bld =
  lift bld ins ins.Length {
    pushToStack bld nullSlot
  }

(* LOAD_ASSERTION_ERROR: pushes the AssertionError builtin a failing assert
   raises. The opcode names it outright -- it takes no argument -- so it is a
   nullary named app. *)
let loadAssertionError (ins: Instruction) bld =
  lift bld ins ins.Length {
    pushToStack bld (AST.app "LOAD_ASSERTION_ERROR" [] rt)
  }

(* LOAD_BUILD_CLASS: pushes the __build_class__ builtin used to construct a
   class from its body function, name, and bases. Nullary for the same reason
   loadAssertionError is. *)
let loadBuildClass (ins: Instruction) bld =
  lift bld ins ins.Length {
    pushToStack bld (AST.app "LOAD_BUILD_CLASS" [] rt)
  }

/// Bytes each unit of a jump's argument stands for. Jump arguments counted
/// bytes up to and including 3.9; 3.10 made them instruction offsets, so the
/// same argument denotes twice the distance from there on (bpo-27129).
/// Deriving it from the instruction keeps the arithmetic below shared: a
/// version supplies its number by being that version, not by passing a
/// scale down through every helper.
let jumpArgScale (ins: Instruction) = if int ins.Version >= 310 then 2 else 1

let jumpByOffset (ins: Instruction) bld isForward =
  liftOpen bld ins ins.Length {
    let n = getIntArg ins * jumpArgScale ins
    let offset = n * (if isForward then 1 else -1)
    let dst = ins.Address + uint64 ins.Length + uint64 offset
    AST.interjmp (AST.num (BitVector(dst, rt))) InterJmpKind.Base
  }

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
  liftOpen bld ins ins.Length {
    let n = getIntArg ins
    let dst = codeObjectBase binFile ins.Address + uint64 (n * jumpArgScale ins)
    AST.interjmp (AST.num (BitVector(dst, rt))) InterJmpKind.Base
  }

(* Pre-3.11 counterpart to condJump: same "honest" jumpIfTrue-preserving
   semantics (see condJump's own doc comment for why), but with an absolute
   rather than relative target -- see codeObjectBase's doc comment. *)
let condJumpAbsolute (binFile: PythonBinFile)
                     (ins: Instruction)
                     bld
                     jumpIfTrue =
  liftOpen bld ins ins.Length {
    let cond = truthOf (popFromStack bld)
    let n = getIntArg ins
    let jmpDst =
      codeObjectBase binFile ins.Address + uint64 (n * jumpArgScale ins)
    let fallDst = ins.Address + uint64 ins.Length
    let tLbl = AST.num (BitVector(jmpDst, rt))
    let fLbl = AST.num (BitVector(fallDst, rt))
    let tLbl, fLbl = if jumpIfTrue then tLbl, fLbl else fLbl, tLbl
    AST.intercjmp cond tLbl fLbl
  }

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
  liftOpen bld ins ins.Length {
    let cond = peekFromStack bld 0
    let n = getIntArg ins
    let jmpDst =
      codeObjectBase binFile ins.Address + uint64 (n * jumpArgScale ins)
    let fallDst = ins.Address + uint64 ins.Length
    let tLbl = AST.num (BitVector(jmpDst, rt))
    let fLbl = AST.num (BitVector(fallDst, rt))
    let lblLTrue = label bld "LTrue"
    let lblLFalse = label bld "LFalse"
    (* The truth test cannot be negated for the FALSE variant -- an object's
       truth is not a bit to flip -- so the two destinations swap instead. *)
    let taken, notTaken =
      if jumpIfTrue then AST.jmpDest lblLTrue, AST.jmpDest lblLFalse
      else AST.jmpDest lblLFalse, AST.jmpDest lblLTrue
    AST.cjmp (truthOf cond) taken notTaken
    AST.lmark lblLTrue
    AST.interjmp tLbl InterJmpKind.Base
    AST.lmark lblLFalse
    discardTOS bld
    AST.interjmp fLbl InterJmpKind.Base
  }

let jumpIfNotExcMatch (binFile: PythonBinFile) (ins: Instruction) bld =
  liftOpen bld ins ins.Length {
    let excType = popFromStack bld
    let excValue = popFromStack bld
    let n = getIntArg ins
    let jmpDst =
      codeObjectBase binFile ins.Address + uint64 (n * jumpArgScale ins)
    let fallDst = ins.Address + uint64 ins.Length
    let tLbl = AST.num (BitVector(jmpDst, rt))
    let fLbl = AST.num (BitVector(fallDst, rt))
    (* Through truthOf rather than on the answer itself: CHECK_EXC_MATCH gives
       back a Python bool, and a lifted value is a reference to an object, so
       branching on it directly asks whether the runtime answered at all --
       which it always does, False included. That is how 3.11's own
       CHECK_EXC_MATCH reaches its jump too, by way of the POP_JUMP_IF_* that
       follows it. *)
    let matches = truthOf (AST.app "CHECK_EXC_MATCH" [ excValue; excType ] rt)
    (* Jump (to the next handler) when it does NOT match. *)
    AST.intercjmp matches fLbl tLbl
  }

(* ROT_TWO/THREE/FOUR/N: rotate the top `n` stack items by one slot,
   moving TOS down to position `n` (the bottom of the rotated window) and
   shifting everything above it up by one. Reads TOS first into a temp
   (so it survives being overwritten), then shifts each of the remaining
   n-1 items down into the slot below it in a single forward pass -- safe
   because each slot is read before it is ever written (see this
   function's own construction: iteration i reads slot i+1 and writes
   slot i, so slot i+1 is never touched by an earlier iteration). *)
let rotateTopToBottom n (ins: Instruction) bld =
  lift bld ins ins.Length {
    let spReg = regVar bld R.SP
    let top = peekFromStack bld 0
    for i in 0 .. n - 2 do
      let v = peekFromStack bld (i + 1)
      AST.store Endian.Little (slotAddr spReg i) v
    AST.store Endian.Little (slotAddr spReg (n - 1)) top
  }

let dupTop (ins: Instruction) bld =
  lift bld ins ins.Length {
    pushToStack bld (peekFromStack bld 0)
  }

(* DUP_TOP_TWO: duplicates the top two items, keeping their relative
   order (stack before, top-to-bottom: a, b -> after: a, b, a, b). *)
let dupTopTwo (ins: Instruction) bld =
  lift bld ins ins.Length {
    let a = peekFromStack bld 0
    let b = peekFromStack bld 1
    pushToStack bld b
    pushToStack bld a
  }

(* A binary/inplace operator with no oparg of its own (3.10-and-earlier:
   each operator is its own opcode, unlike 3.12's single BINARY_OP with an
   operator-selecting oparg -- see binaryOp's own arg-index table just
   below, whose named-app strings this mirrors so downstream HIR
   translation (which pattern-matches on those exact names) recognizes
   both versions' encodings identically). *)
let binaryOpDirect opExpr (ins: Instruction) bld =
  lift bld ins ins.Length {
    let right = popFromStack bld
    let left = popFromStack bld
    pushToStack bld (opExpr left right)
  }

let copyDictWithoutKeys (ins: Instruction) bld =
  lift bld ins ins.Length {
    let keys = popFromStack bld
    let subject = peekFromStack bld 0
    pushToStack bld (AST.app "COPY_DICT_WITHOUT_KEYS" [ subject; keys ] rt)
  }

let printExpr (ins: Instruction) bld =
  lift bld ins ins.Length {
    let v = popFromStack bld
    AST.extCall (AST.app "PRINT_EXPR" [ v ] rt)
  }

(* YIELD_FROM (pre-3.11 `yield from`/`await`): unlike 3.12's explicit
   GET_AWAITABLE + SEND-loop decomposition (recognized and folded by
   AwaitFolding.fs), YIELD_FROM is a single opcode that internally loops
   in the interpreter itself -- it either completes, or suspends, yielding a
   value and resuming at the very same PC on the next `.send()`.

   Both paths leave the stack the same shape, which is what lets one linear
   sequence say it: the sent value is popped, and the sub-iterator beneath it
   stays where it is. On completion CPython overwrites that slot with what the
   sub-iterator returned (SET_TOP in ceval.c); on suspension it leaves the
   sub-iterator there for the resumed instruction to find. So the effect is
   -1, and it is the external call rather than a push that settles what the
   remaining slot holds. Pushing a resumption sentinel here instead -- as
   YIELD_VALUE rightly does, that one really does receive what was sent --
   made the effect 0 and left every stack slot after a `yield from` off by
   one. *)
let yieldFrom (ins: Instruction) bld =
  lift bld ins ins.Length {
    let sendVal = popFromStack bld
    let subIter = peekFromStack bld 0
    AST.extCall (AST.app "YIELD_FROM" [ subIter; sendVal ] rt)
  }

let callFunction (ins: Instruction) bld =
  lift bld ins ins.Length {
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
  }

let callFunctionKw (ins: Instruction) bld =
  lift bld ins ins.Length {
    let argc = getIntArg ins
    let kwNamesTuple = popFromStack bld
    let args = List.init argc (fun _ -> popFromStack bld) |> List.rev
    let func = popFromStack bld
    let result = AST.app "CALL" (nullSlot :: func :: args @ [ kwNamesTuple ]) rt
    pushToStack bld result
  }

(* LOAD_METHOD: like 3.12's LOAD_ATTR with its method flag always set --
   pushes NULL then the attribute, so a following CALL_METHOD (or CALL,
   see callMethod below) sees (NULL, boundMethod, args...) and treats it
   uniformly with the plain-attribute-then-call shape. Reuses "LOAD_ATTR"
   as the named app (not a separate "LOAD_METHOD") so the existing
   NULL-before-CALL method-call recognition in TranslationHelper.fs (built
   for 3.12's LOAD_ATTR-with-flag) applies here for free. *)
let loadMethod (ins: Instruction) bld =
  lift bld ins ins.Length {
    let name = operandIndex ins
    let obj = popFromStack bld
    let attr = AST.app "LOAD_ATTR" [ obj; name ] rt
    pushToStack bld nullSlot
    pushToStack bld attr
  }

(* CALL_METHOD: pops argc args, the method (or plain attr) below them, and
   the self-or-NULL slot LOAD_METHOD left under that -- same three-part
   shape CALL already expects, just without a KW_NAMES register (3.10's
   LOAD_METHOD/CALL_METHOD pair is positional-only; a call needing keyword
   arguments instead falls back to plain LOAD_ATTR + CALL_FUNCTION_KW), so
   NULL fills that last slot. Reuses "CALL" for the same reason
   callFunction above does. *)
let callMethod (ins: Instruction) bld =
  lift bld ins ins.Length {
    let argc = getIntArg ins
    let args = List.init argc (fun _ -> popFromStack bld) |> List.rev
    let methodOrFunc = popFromStack bld
    let selfOrNull = popFromStack bld
    let result =
      AST.app "CALL" (selfOrNull :: methodOrFunc :: args @ [ nullSlot ]) rt
    pushToStack bld result
  }

(* END_FOR: what a for loop ends at. Up to 3.12 it is alone; 3.13 splits what
   it did between it and a POP_TOP after it. What is on the stack here is the
   iterator and nothing else -- the exhausted value CPython leaves beside it is
   not something this model puts there, see forIter -- so between them the pair
   takes one slot however it is spelled. END_FOR takes it where it is alone,
   and leaves it to the POP_TOP where it is not. *)
let endFor (ins: Instruction) bld =
  lift bld ins ins.Length {
    if ins.Minor < 13 then discardTOS bld else ()
  }

(* END_SEND: removes the second-from-top value (the exhausted generator
   left by SEND), keeping the top (the awaited result) in place. *)
let endSend (ins: Instruction) bld =
  lift bld ins ins.Length {
    let value = popFromStack bld
    discardTOS bld
    pushToStack bld value
  }

let copy (ins: Instruction) bld =
  lift bld ins ins.Length {
    let n = getIntArg ins
    pushToStack bld (peekFromStack bld (n - 1))
  }

let swap (ins: Instruction) bld =
  lift bld ins ins.Length {
    let n = getIntArg ins
    let top = peekFromStack bld 0
    let nth = peekFromStack bld (n - 1)
    let spReg = regVar bld R.SP
    let tmp = tmpVar bld rt
    append bld { tmp := top }
    append bld { AST.store Endian.Little spReg nth }
    append bld { AST.store Endian.Little (slotAddr spReg (n - 1)) tmp }
  }

(* Generic store for STORE_FAST / STORE_NAME / STORE_GLOBAL / STORE_DEREF:
   pop TOS and emit an external call recording the target name. *)
let storeNamed opname (ins: Instruction) bld =
  lift bld ins ins.Length {
    let name = operandIndex ins
    let value = popFromStack bld
    let eff = AST.app opname [ name; value ] rt
    AST.extCall eff
  }

(* STORE_ATTR: TOS = value, TOS1 = obj => obj.attr = value *)
let storeAttr (ins: Instruction) bld =
  lift bld ins ins.Length {
    let name = operandIndex ins
    let obj = popFromStack bld
    let value = popFromStack bld
    let eff = AST.app "STORE_ATTR" [ name; obj; value ] rt
    AST.extCall eff
  }

(* LOAD_ATTR: pop TOS (obj), push obj.attr.
   In Python >= 3.11, ins.Flag = true means method mode: push NULL then the
   attr so that CALL sees (NULL, obj.attr, args) and treats obj as self. *)
let loadAttr (ins: Instruction) bld =
  lift bld ins ins.Length {
    let name = attrIndex ins
    let obj = popFromStack bld
    pushCallee ins bld (AST.app "LOAD_ATTR" [ obj; name ] rt)
  }

(* LOAD_SUPER_ATTR: pops self, __class__, and the global `super` reference
   (pushed by preceding LOAD_FAST self / LOAD_DEREF __class__ / LOAD_GLOBAL
   super), and computes getattr(super(__class__, self), name). For the
   common zero-arg `super()` form, __class__/self are compiler-generated,
   so the HIR reconstruction just emits the literal `super().name` form and
   the popped values only need to preserve stack balance. For an explicit
   `super(cls, obj).attr`, __class__/self are real user expressions, so we
   tag it differently to keep them. *)
let loadSuperAttr (ins: Instruction) bld =
  lift bld ins ins.Length {
    let name = superAttrIndex ins
    let self = popFromStack bld
    let cls = popFromStack bld
    let superGlobal = popFromStack bld
    let opname =
      if ins.SuperHasExplicitArgs then "LOAD_SUPER_ATTR_EXPLICIT"
      else "LOAD_SUPER_ATTR"
    pushCallee ins bld (AST.app opname [ superGlobal; cls; self; name ] rt)
  }

(* STORE_SUBSCR: TOS1[TOS] = TOS2 ??pops three items. *)
let storeSubscript (ins: Instruction) bld =
  lift bld ins ins.Length {
    let sub = popFromStack bld
    let obj = popFromStack bld
    let value = popFromStack bld
    let eff = AST.app "STORE_SUBSCR" [ obj; sub; value ] rt
    AST.extCall eff
  }

(* STORE_SLICE: TOS2[TOS1:TOS] = TOS3 ??pops four items. *)
let storeSlice (ins: Instruction) bld =
  lift bld ins ins.Length {
    let stop = popFromStack bld
    let start = popFromStack bld
    let obj = popFromStack bld
    let value = popFromStack bld
    let eff = AST.app "STORE_SLICE" [ obj; start; stop; value ] rt
    AST.extCall eff
  }

(* DELETE_SUBSCR: del TOS1[TOS] ??pops two items. *)
let deleteSubscript (ins: Instruction) bld =
  lift bld ins ins.Length {
    let sub = popFromStack bld
    let obj = popFromStack bld
    let eff = AST.app "DELETE_SUBSCR" [ obj; sub ] rt
    AST.extCall eff
  }

(* RETURN_VALUE: pop TOS and emit a RETURN call. *)
let translateReturn (ins: Instruction) bld =
  liftOpen bld ins ins.Length {
    let value = popFromStack bld
    AST.extCall (AST.app "RETURN" [ value ] rt)
    append bld { AST.interjmp returnTarget InterJmpKind.IsRet }
  }

(* RETURN_CONST: load constant directly without a stack round-trip. *)
let translateReturnConst (ins: Instruction) bld =
  liftOpen bld ins ins.Length {
    let name = operandIndex ins
    let value = AST.app "LOAD_CONST" [ name ] rt
    AST.extCall (AST.app "RETURN" [ value ] rt)
    append bld { AST.interjmp returnTarget InterJmpKind.IsRet }
  }

(* RAISE_VARARGS arg: pop arg items (0??) and raise. *)
let translateRaiseVarargs (ins: Instruction) bld =
  lift bld ins ins.Length {
    let n = getIntArg ins
    let args = List.init n (fun _ -> popFromStack bld)
    AST.extCall (AST.app "RAISE_VARARGS" args rt)
    AST.sideEffect SideEffect.Terminate
  }

(* Conditional jump shared by POP_JUMP_IF_FALSE and POP_JUMP_IF_TRUE.
   jumpIfTrue=true  ??jump when TOS is truthy.
   jumpIfTrue=false ??jump when TOS is falsy. *)
let condJump (ins: Instruction) bld jumpIfTrue =
  liftOpen bld ins ins.Length {
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
    let tLbl, fLbl = if jumpIfTrue then tLbl, fLbl else fLbl, tLbl
    AST.intercjmp (truthOf cond) tLbl fLbl
  }

(* Conditional jump for POP_JUMP_IF_NONE / POP_JUMP_IF_NOT_NONE.
   jumpIfNone=true  ??jump when TOS is None (modeled as IS_NONE(TOS) = 1).
   jumpIfNone=false ??jump when TOS is not None. *)
let condJumpNone (ins: Instruction) bld jumpIfNone =
  liftOpen bld ins ins.Length {
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
      AST.intercjmp isNone tLbl fLbl
    else
      let isNotNone = AST.app "IS_NOT_NONE" [ value ] rt
      AST.intercjmp isNotNone tLbl fLbl
  }

let forIter minor (ins: Instruction) bld =
  liftOpen bld ins ins.Length {
    let tos = peekFromStack bld 0
    let n = getIntArg ins
    let jmpDst = ins.Address + uint64 ins.Length + uint64 (n * jumpArgScale ins)
    let fallDst = ins.Address + uint64 ins.Length
    let tLbl = AST.num (BitVector(jmpDst, rt))
    let fLbl = AST.num (BitVector(fallDst, rt))
    let cond = AST.app "IS_EXHAUSTED" [ tos ] rt
    let lblLTrue = label bld "LTrue"
    let lblLFalse = label bld "LFalse"
    AST.cjmp cond (AST.jmpDest lblLTrue) (AST.jmpDest lblLFalse)
    (* True branch: pop the exhausted iterator and jump to the loop exit. *)
    AST.lmark lblLTrue
    if minor < 12 then discardTOS bld
    (* From 3.12, END_FOR is introduced and instead pops the iterator. *)
    else ()
    AST.interjmp tLbl InterJmpKind.Base
    (* False branch: jump to the body and push the next value. *)
    AST.lmark lblLFalse
    let tos = peekFromStack bld 0
    pushToStack bld (AST.app "NEXT" [ tos ] rt)
    AST.interjmp fLbl InterJmpKind.Base
  }

let getIter (ins: Instruction) bld =
  lift bld ins ins.Length {
    let iter = popFromStack bld
    let iterNext = AST.app "GET_ITER" [ iter ] rt
    pushToStack bld iterNext
  }

(* SEND: pop TOS (sent value), send it into the receiver beneath. Per CPython's
   own bytecodes.c, the stack effect is `(receiver, v -- receiver, retval)` on
   BOTH the exhausted and not-exhausted paths -- the receiver stays regardless;
   only END_SEND (via the exhausted jump) later drops it. So the receiver is
   read where it lies rather than popped and pushed back: a send runs the
   sub-generator's own bytecode, which re-enters the interpreter and reuses
   every temporary this instruction holds, so a receiver popped into one and
   written back afterwards would be whatever that run left there. Leaving it in
   its slot also keeps it out of the way of the sub-generator's own stack,
   which is placed below the stack pointer -- and the stack pointer, with the
   sent value popped, is the receiver's own slot. *)
let send (ins: Instruction) bld =
  liftOpen bld ins ins.Length {
    let sentVal = popFromStack bld
    let gen = peekFromStack bld 0
    (* Bound before it is used, because it is used twice: once pushed onto the
       stack and once asked whether it means the sub-generator is done. Left as
       an expression it would be two sends rather than one, and the second would
       take a value out of the sub-generator that nothing ever yields. *)
    let result = tmpVar bld rt
    append bld { result := AST.app "SEND" [ gen; sentVal ] rt }
    let n = getIntArg ins
    let jmpDst = ins.Address + uint64 ins.Length + uint64 (n * jumpArgScale ins)
    let fallDst = ins.Address + uint64 ins.Length
    let isExhausted = AST.app "IS_EXHAUSTED" [ result ] rt
    pushToStack bld result
    AST.intercjmp isExhausted
      (AST.num (BitVector(jmpDst, rt)))
      (AST.num (BitVector(fallDst, rt)))
  }

let getYieldFromIter (ins: Instruction) bld =
  lift bld ins ins.Length {
    let tos = popFromStack bld
    pushToStack bld (AST.app "GET_YIELD_FROM_ITER" [ tos ] rt)
  }

(* KW_NAMES: the tuple of names the following call's last arguments were given
   by, which the call reads out of the register this leaves it in. What travels
   is the constant itself rather than the index selecting it -- the same
   LOAD_CONST every other constant reaches its consumer through. The index alone
   would be indistinguishable from the NULL a call with no keywords finds in the
   register, since a kwnames tuple can genuinely be a code object's constant
   zero (`g(a=x)` at module level compiles to exactly that). *)
let kwNames (ins: Instruction) bld =
  lift bld ins ins.Length {
    let names = AST.app "LOAD_CONST" [ operandIndex ins ] rt
    let kwReg = regVar bld R.KW_NAMES
    kwReg := names
  }

let call (ins: Instruction) bld =
  lift bld ins ins.Length {
    let argc = getIntArg ins
    (* 3.13 folded the keyword names into the call itself: they arrive as a
       tuple above the arguments, where 3.12 left them in a register a separate
       KW_NAMES had set. *)
    let named =
      match ins.Opcode with
      | Opcode.CALL_KW | Opcode.INSTRUMENTED_CALL_KW -> Some(popFromStack bld)
      | _ -> None
    let args = List.init argc (fun _ -> popFromStack bld) |> List.rev
    let func, maybeSelf = popCallee ins bld
    let kwReg = regVar bld R.KW_NAMES
    let names = defaultArg named kwReg
    let result = AST.app "CALL" (maybeSelf :: func :: args @ [ names ]) rt
    pushToStack bld result
    kwReg := nullSlot
  }

let consumeAndPush name (ins: Instruction) bld =
  lift bld ins ins.Length {
    let v = popFromStack bld
    let result = AST.app name [ v ] rt
    pushToStack bld result
  }

(* The closure travels with the other three rather than being discarded: it is
   the tuple of cells LOAD_CLOSURE built, and the function it is being attached
   to is the only thing that says which cells a nested body reads. Dropping it
   left every closure's free variables coming from nowhere. *)
let makeFunction (ins: Instruction) bld =
  lift bld ins ins.Length {
    let flags = getIntArg ins
    let codeObj = popFromStack bld
    let closure = if flags &&& 0x08 <> 0 then popFromStack bld else nullSlot
    let annotations = if flags &&& 0x04 <> 0 then popFromStack bld else nullSlot
    let kwDefs = if flags &&& 0x02 <> 0 then popFromStack bld else nullSlot
    let posDefs = if flags &&& 0x01 <> 0 then popFromStack bld else nullSlot
    let args = [ codeObj; posDefs; kwDefs; annotations; closure ]
    pushToStack bld (AST.app "MAKE_FUNCTION" args rt)
  }

(* 3.13 removed MAKE_FUNCTION's oparg along with everything it selected: the
   defaults, annotations and closure are attached one at a time by the
   SET_FUNCTION_ATTRIBUTE instructions that follow, so the code object is all
   this pops. The four slots stay NULL rather than vanishing, so the app keeps
   the arity the other two forms have and HIR translation reads one shape. *)
let makeFunctionSimple (ins: Instruction) bld =
  lift bld ins ins.Length {
    let codeObj = popFromStack bld
    let args = [ codeObj; nullSlot; nullSlot; nullSlot; nullSlot ]
    pushToStack bld (AST.app "MAKE_FUNCTION" args rt)
  }

(* Pre-3.11: MAKE_FUNCTION pops one thing more than the later form -- an
   explicit qualname STRING sitting on top of the code object, which 3.11
   bakes into the code object's own metadata instead, so that slot does not
   exist there at all. Reusing the 3.12 version's `makeFunction` verbatim
   silently popped the qualname string as if it were the code object
   itself, corrupting every nested function's own CodeRef into its own
   qualname text instead of an address-based ref (confirmed via `10013`
   in the CSN 3.10 sweep: `fillIncompleteFuncSigs` crashed looking up
   codeRef `"get_bucket"` -- the qualname -- instead of `"<90>"`).
   Everything below the code object is popped in the very order 3.11 uses:
   3.10's ceval.c takes the closure first and the positional defaults last,
   highest flag bit to lowest, exactly as its successor does. Reversing them
   here left `def f(a, b=2, *, c=3)` -- flags 0x03, the one shape where the
   order shows -- with the keyword defaults read as the positional tuple and
   the positional defaults as the keyword dictionary, so every parameter that
   had a default arrived with none. *)
let makeFunctionLegacy (ins: Instruction) bld =
  lift bld ins ins.Length {
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
    AST.extCall (AST.app "DISCARD" [ qualname ] rt)
    let codeObj = popFromStack bld
    let closure = if flags &&& 0x08 <> 0 then popFromStack bld else nullSlot
    let annotations = if flags &&& 0x04 <> 0 then popFromStack bld else nullSlot
    let kwDefs = if flags &&& 0x02 <> 0 then popFromStack bld else nullSlot
    let posDefs = if flags &&& 0x01 <> 0 then popFromStack bld else nullSlot
    let args = [ codeObj; posDefs; kwDefs; annotations; closure ]
    pushToStack bld (AST.app "MAKE_FUNCTION" args rt)
  }

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
  lift bld ins ins.Length {
    (* 3.14 dropped the oparg whose low bit used to say whether a keyword
       mapping was passed: the mapping became a stack slot that is always
       there, holding NULL for a call that passes none. 3.13's instrumented
       form has no oparg either, and nothing else says what it was, so the
       unflagged shape -- no mapping -- is what it reads as. *)
    let kwargs =
      if minor >= 14 then popFromStack bld
      elif getIntArgOr 0 ins &&& 0x01 <> 0 then popFromStack bld
      else nullSlot
    let args = popFromStack bld
    let func, maybeSelf =
      if minor >= 11 then popCallee ins bld else popFromStack bld, nullSlot
    let result = AST.app "CALL_FUNCTION_EX" [ maybeSelf; func; args; kwargs ] rt
    pushToStack bld result
  }

(* 3.0 gives neither this nor SET_ADD an oparg: the collection is always the
   slot directly beneath the item, which is what an oparg of 1 says. *)
let listAppend (ins: Instruction) bld =
  lift bld ins ins.Length {
    let i = getIntArgOr 1 ins
    let item = popFromStack bld
    let lst = peekFromStack bld (i - 1)
    AST.extCall (AST.app "LIST_APPEND" [ lst; item ] rt)
  }

let setAdd (ins: Instruction) bld =
  lift bld ins ins.Length {
    let i = getIntArgOr 1 ins
    let item = popFromStack bld
    let st = peekFromStack bld (i - 1)
    AST.extCall (AST.app "SET_ADD" [ st; item ] rt)
  }

let mapAdd (ins: Instruction) bld =
  lift bld ins ins.Length {
    let i = getIntArg ins
    let value = popFromStack bld
    let key = popFromStack bld
    let mp = peekFromStack bld (i - 1)
    AST.extCall (AST.app "MAP_ADD" [ mp; key; value ] rt)
  }

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
  lift bld ins ins.Length {
    let i = getIntArg ins
    let update = popFromStack bld
    let saved = [| for _ in 1 .. i - 1 -> popFromStack bld |]
    let dict = popFromStack bld
    let merged = AST.app name [ dict; update ] rt
    pushToStack bld merged
    for v in Array.rev saved do pushToStack bld v
  }

let cmpOpName = function
  | 0 -> "<"
  | 1 -> "<="
  | 2 -> "=="
  | 3 -> "!="
  | 4 -> ">"
  | 5 -> ">="
  | _ -> Terminator.futureFeature ()

(* Before 3.9, COMPARE_OP's argument indexes an eleven-entry cmp_op table
   that also holds the identity, membership and exception-match tests 3.9
   split out into IS_OP, CONTAINS_OP and JUMP_IF_NOT_EXC_MATCH. The names
   here are those later opcodes' own, so HIR translation sees one shape
   across versions. *)
let private legacyCmp idx left right =
  match idx with
  | 6 -> AST.app "CONTAINS_OP" [ right; left ] rt
  | 7 -> AST.app "NOT_CONTAINS_OP" [ right; left ] rt
  | 8 -> AST.app "IS_OP" [ left; right ] rt
  | 9 -> AST.app "NOT_IS_OP" [ left; right ] rt
  | 10 -> AST.app "CHECK_EXC_MATCH" [ left; right ] rt
  | _ -> opApp (cmpOpName idx) left right

(* COMPARE_OP: pop right (TOS) then left (TOS1), push bool result.
   The index sits above whatever flag bits the version put beneath it: none up
   to 3.11, four cache bits in 3.12, and five from 3.13, which added one saying
   the result is to be forced to a bool. Reading a 3.13 argument four bits down
   leaves that bit in the index, which names an operator there is none of. *)
let compareOP minor (ins: Instruction) bld =
  lift bld ins ins.Length {
    let n = getIntArg ins
    let opIdx = if minor >= 13 then n >>> 5 elif minor >= 12 then n >>> 4 else n
    let right = popFromStack bld
    let left = popFromStack bld
    if minor >= 9 then pushToStack bld (opApp (cmpOpName opIdx) left right)
    else pushToStack bld (legacyCmp opIdx left right)
  }

(* IS_OP: pop TOS (right) and TOS1 (left), push identity test.
   operand=0 ??left is right; operand=1 ??left is not right. *)
let isOp (ins: Instruction) bld =
  lift bld ins ins.Length {
    let invert = getIntArg ins
    let right = popFromStack bld
    let left = popFromStack bld
    let fname = if invert = 0 then "IS_OP" else "NOT_IS_OP"
    pushToStack bld (AST.app fname [ left; right ] rt)
  }

(* CONTAINS_OP: pop TOS (container) and TOS1 (item), push membership test.
   operand=0 ??item in container; operand=1 ??item not in container. *)
let containsOp (ins: Instruction) bld =
  lift bld ins ins.Length {
    let invert = getIntArg ins
    let container = popFromStack bld
    let item = popFromStack bld
    let fname = if invert = 0 then "CONTAINS_OP" else "NOT_CONTAINS_OP"
    let result = AST.app fname [ container; item ] rt
    pushToStack bld result
  }

/// The operator a BINARY_OP argument names. Zero to twelve are the plain
/// operators and thirteen to twenty-five their in-place forms (`+=`, `-=`,
/// ...), each thirteen past the plain one it matches. The in-place ones
/// dispatch to `__iadd__` and can mutate in place, so -- unlike a generic
/// binary lifter -- they must not be folded into the plain operator: they are
/// named apart so that a store recovers them as AugAssign (see makeAssign).
/// Matrix multiply splits the same way as everything else here (`@` at 4,
/// `@=` at 17 = 4 + 13).
///
/// 3.14 folded the subscript in as well: `a[b]` arrives as BINARY_OP one past
/// the in-place operators, where every version before it had a BINARY_SUBSCR
/// of its own. It keeps that opcode's name, so nothing downstream has to know
/// which spelling it came from.
let private binaryOpName addr = function
  | 0 -> "+"
  | 1 -> "&"
  | 2 -> "//"
  | 3 -> "<<"
  | 4 -> "@"
  | 5 -> "*"
  | 6 -> "%"
  | 7 -> "|"
  | 8 -> "**"
  | 9 -> ">>"
  | 10 -> "-"
  | 11 -> "/"
  | 12 -> "^"
  | 13 -> "IADD"
  | 14 -> "IBITAND"
  | 15 -> "IFLOORDIV"
  | 16 -> "ILSHIFT"
  | 17 -> "IMATMUL"
  | 18 -> "IMUL"
  | 19 -> "IMOD"
  | 20 -> "IBITOR"
  | 21 -> "IPOW"
  | 22 -> "IRSHIFT"
  | 23 -> "ISUB"
  | 24 -> "IDIV"
  | 25 -> "IBITXOR"
  | 26 -> "BINARY_SUBSCR"
  | n -> failwithf "Invalid BINARY_OP arg %d at %A" n addr

(* BINARY_OP: pop right (TOS) and left (TOS1), apply operator, push result.
   arg directly indexes the operation; inplace variants (arg >= 13) share
   the same index offset as their non-inplace counterparts. *)
let binaryOp (ins: Instruction) bld =
  lift bld ins ins.Length {
    let right = popFromStack bld
    let left = popFromStack bld
    let name = binaryOpName ins.Address (getIntArg ins)
    pushToStack bld (opApp name left right)
  }

let binarySubscr (ins: Instruction) bld =
  lift bld ins ins.Length {
    let idx = popFromStack bld
    let obj = popFromStack bld
    pushToStack bld (AST.app "BINARY_SUBSCR" [ obj; idx ] rt)
  }

let binarySlice (ins: Instruction) bld =
  lift bld ins ins.Length {
    let stop = popFromStack bld
    let start = popFromStack bld
    let obj = popFromStack bld
    pushToStack bld (AST.app "BINARY_SLICE" [ obj; start; stop ] rt)
  }

/// UNPACK_SEQUENCE: the elements go on the stack so that the *first* one ends
/// up on top, because the stores that follow take them off in the order the
/// target list writes them -- `a, b = pair` stores a first. Pushing them in
/// index order would put the last on top and hand every target the wrong
/// element, which is a swap rather than a failure and so shows up as a wrong
/// answer far from here.
(* UNPACK_EX: the starred form of an unpacking, `a, *rest, b = xs`. The
   argument packs how many targets precede the star in its low byte and how
   many follow it in the high one. What it leaves is one value per target --
   the star's own list among them -- deepest first, so the leftmost target ends
   on top, exactly as UNPACK_SEQUENCE leaves its own. Which element each target
   takes depends on how long the sequence turns out to be, which only the
   runtime knows, so each is asked for by position rather than sliced here. *)
let unpackEx (ins: Instruction) bld =
  lift bld ins ins.Length {
    let arg = getIntArg ins
    let before = arg &&& 0xFF
    let after = arg >>> 8
    let seq = popFromStack bld
    (* Walked once, for the same reason UNPACK_SEQUENCE walks once. *)
    let items = tmpVar bld rt
    items := AST.app "LIST_TO_TUPLE" [ seq ] rt
    for i in before + after .. -1 .. 0 do
      let taken =
        AST.app "UNPACK_EX"
          [ items
            AST.num (BitVector(before, rt))
            AST.num (BitVector(after, rt))
            AST.num (BitVector(i, rt)) ] rt
      pushToStack bld taken
  }

let unpackSequence (ins: Instruction) bld =
  lift bld ins ins.Length {
    let n = getIntArg ins
    let seq = popFromStack bld
    (* Walked once, into a tuple the elements are then taken from. Asking for
       each element against the sequence itself would walk it once per element,
       and walking a generator consumes it -- so `a, b = (x for x in xs)` would
       take the first element and then find nothing left, which is a wrong
       answer rather than a failure. *)
    let items = tmpVar bld rt
    append bld { items := AST.app "LIST_TO_TUPLE" [ seq ] rt }
    (* How many targets there are goes with each element, because the count is
       half of what makes an unpacking right: a sequence longer than the targets
       is as much an error as one shorter, and only the opcode's argument says
       how many were written. *)
    for i in n - 1 .. -1 .. 0 do
      let elem =
        AST.app "UNPACK"
          [ items; AST.num (BitVector(i, rt)); AST.num (BitVector(n, rt)) ] rt
      pushToStack bld elem
  }

(* Same fix as dictMerge above, and for the same reason: pop down to the
   list (saving any intervening values), extend it, then push the result
   back followed by the saved values, instead of peeking and writing the
   new value back via a raw store SSAStackPointerPropagation's ConstSP
   tracking cannot see through. *)
let listExtend (ins: Instruction) bld =
  lift bld ins ins.Length {
    let n = getIntArg ins
    let tos = popFromStack bld
    let saved = [| for _ in 1 .. n - 1 -> popFromStack bld |]
    let lst = popFromStack bld
    let extended = AST.app "LIST_EXTEND" [ lst; tos ] rt
    pushToStack bld extended
    for v in Array.rev saved do pushToStack bld v
  }

/// SET_UPDATE, which is LIST_EXTEND's counterpart for a set: the iterable on
/// top is folded into the set n slots below it. A set display whose elements
/// are all constants compiles to exactly this -- BUILD_SET 0, then the folded
/// frozen set, then SET_UPDATE -- so it stands between a program and every
/// `{1, 2, 3}` it writes, not just an unpacking one.
let setUpdate (ins: Instruction) bld =
  lift bld ins ins.Length {
    let n = getIntArg ins
    let tos = popFromStack bld
    let saved = [| for _ in 1 .. n - 1 -> popFromStack bld |]
    let st = popFromStack bld
    let updated = AST.app "SET_UPDATE" [ st; tos ] rt
    pushToStack bld updated
    for v in Array.rev saved do pushToStack bld v
  }

let buildCollection name (ins: Instruction) bld =
  lift bld ins ins.Length {
    let n = getIntArg ins
    let items =
      [| for _ in 0 .. n - 1 do yield popFromStack bld |]
      |> Array.rev
      |> Array.toList
    pushToStack bld (AST.app name items rt)
  }

(* BUILD_MAP: pops n key-value pairs (key1 value1 ... keyN valueN from
   bottom to top) and pushes the resulting dict. *)
let buildMap (ins: Instruction) bld =
  lift bld ins ins.Length {
    let n = getIntArg ins
    let items =
      [| for _ in 0 .. (2 * n) - 1 do yield popFromStack bld |]
      |> Array.rev
      |> Array.toList
    pushToStack bld (AST.app "BUILD_MAP" items rt)
  }

(* BUILD_CONST_KEY_MAP: TOS = keys tuple, TOS1..TOS(n) = values.
   Pops keys then n values; pushes the resulting dict. *)
let buildConstKeyMap (ins: Instruction) bld =
  lift bld ins ins.Length {
    let n = getIntArg ins
    let keys = popFromStack bld
    let values =
      [| for _ in 0 .. n - 1 do yield popFromStack bld |]
      |> Array.rev
      |> Array.toList
    pushToStack bld (AST.app "BUILD_CONST_KEY_MAP" (keys :: values) rt)
  }

(* FORMAT_VALUE: flags & 0x3 = conversion (0=none,1=str,2=repr,3=ascii);
   flags & 0x4 = has_format_spec. Pops spec (if any) then value; pushes
   the formatted string. The conversion travels as the two-bit selector the
   oparg already holds rather than a rendering of it, so the operand stays a
   number the IR can actually reason about. *)
let formatValue (ins: Instruction) bld =
  lift bld ins ins.Length {
    let flags = getIntArg ins
    let spec = if flags &&& 0x4 <> 0 then [ popFromStack bld ] else []
    let value = popFromStack bld
    let conv = numI32 (flags &&& 0x3) rt
    let result = AST.app "FORMAT_VALUE" (value :: conv :: spec) rt
    pushToStack bld result
  }
