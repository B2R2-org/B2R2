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

/// <summary>
/// Provides a set of functions for constructing LowUIR expressions and
/// statements.
/// <remarks>
/// Any LowUIR AST construction must be done through the functions in this
/// module.
/// </remarks>
/// </summary>
[<RequireQualifiedAccess>]
module B2R2.BinIR.LowUIR.AST

open System.Collections.Generic
open B2R2
open B2R2.Collections
open B2R2.BinIR

#if HASHCONS
let private eTagCnt = ref 0u
let private sTagCnt = ref 0u

let private newEID () = System.Threading.Interlocked.Increment eTagCnt
let private newSID () = System.Threading.Interlocked.Increment sTagCnt

/// The hash-consing information of a new expression kept under hash.
let private exprInfo hash = HashConsingInfo(newEID (), hash)

/// The hash-consing information of a new statement kept under hash.
let private stmtInfo hash = HashConsingInfo(newSID (), hash)

/// Checks whether two lists hold the same expressions.
let rec private sameExprs (lhs: Expr list) (rhs: Expr list) =
  match lhs, rhs with
  | [], [] -> true
  | e1 :: lhs, e2 :: rhs -> e1 === e2 && sameExprs lhs rhs
  | _ -> false

(* The keys a node is interned by, one per kind: the parts of the node, which
   match an existing one as Expr.Equals and Stmt.Equals would, and how to make
   the node when there is none. A lookup that finds its node allocates
   nothing. *)

[<Struct>]
type private NumKey(n: BitVector) =
  interface IInternKey<Expr> with
    member _.Matches x =
      match x with
      | Num(m, _) -> m = n
      | _ -> false

    member _.Create hash = Num(n, exprInfo hash)

[<Struct>]
type private VarKey(t: RegType, r: RegisterID, name: string) =
  interface IInternKey<Expr> with
    member _.Matches x =
      match x with
      | Var(t', r', _, _) -> t' = t && r' = r
      | _ -> false

    member _.Create hash = Var(t, r, name, exprInfo hash)

[<Struct>]
type private PCVarKey(t: RegType, name: string) =
  interface IInternKey<Expr> with
    member _.Matches x =
      match x with
      | PCVar(t', _, _) -> t' = t
      | _ -> false

    member _.Create hash = PCVar(t, name, exprInfo hash)

[<Struct>]
type private TempVarKey(t: RegType, n: int) =
  interface IInternKey<Expr> with
    member _.Matches x =
      match x with
      | TempVar(t', n', _) -> t' = t && n' = n
      | _ -> false

    member _.Create hash = TempVar(t, n, exprInfo hash)

[<Struct>]
type private ExprListKey(es: Expr list) =
  interface IInternKey<Expr> with
    member _.Matches x =
      match x with
      | ExprList(es', _) -> sameExprs es' es
      | _ -> false

    member _.Create hash = ExprList(es, exprInfo hash)

[<Struct>]
type private UnOpKey(op: UnOpType, e: Expr) =
  interface IInternKey<Expr> with
    member _.Matches x =
      match x with
      | UnOp(op', e', _) -> op' = op && e' === e
      | _ -> false

    member _.Create hash = UnOp(op, e, exprInfo hash)

[<Struct>]
type private JmpDestKey(l: Label) =
  interface IInternKey<Expr> with
    member _.Matches x =
      match x with
      | JmpDest(l', _) -> l' = l
      | _ -> false

    member _.Create hash = JmpDest(l, exprInfo hash)

[<Struct>]
type private FuncNameKey(name: string) =
  interface IInternKey<Expr> with
    member _.Matches x =
      match x with
      | FuncName(name', _) -> name' = name
      | _ -> false

    member _.Create hash = FuncName(name, exprInfo hash)

[<Struct>]
type private BinOpKey(op: BinOpType, t: RegType, e1: Expr, e2: Expr) =
  interface IInternKey<Expr> with
    member _.Matches x =
      match x with
      | BinOp(op', t', e1', e2', _) ->
        op' = op && t' = t && e1' === e1 && e2' === e2
      | _ ->
        false

    member _.Create hash = BinOp(op, t, e1, e2, exprInfo hash)

[<Struct>]
type private RelOpKey(op: RelOpType, e1: Expr, e2: Expr) =
  interface IInternKey<Expr> with
    member _.Matches x =
      match x with
      | RelOp(op', e1', e2', _) -> op' = op && e1' === e1 && e2' === e2
      | _ -> false

    member _.Create hash = RelOp(op, e1, e2, exprInfo hash)

[<Struct>]
type private LoadKey(en: Endian, t: RegType, a: Expr) =
  interface IInternKey<Expr> with
    member _.Matches x =
      match x with
      | Load(en', t', a', _) -> en' = en && t' = t && a' === a
      | _ -> false

    member _.Create hash = Load(en, t, a, exprInfo hash)

[<Struct>]
type private IteKey(c: Expr, e1: Expr, e2: Expr) =
  interface IInternKey<Expr> with
    member _.Matches x =
      match x with
      | Ite(c', e1', e2', _) -> c' === c && e1' === e1 && e2' === e2
      | _ -> false

    member _.Create hash = Ite(c, e1, e2, exprInfo hash)

[<Struct>]
type private CastKey(k: CastKind, t: RegType, e: Expr) =
  interface IInternKey<Expr> with
    member _.Matches x =
      match x with
      | Cast(k', t', e', _) -> k' = k && t' = t && e' === e
      | _ -> false

    member _.Create hash = Cast(k, t, e, exprInfo hash)

[<Struct>]
type private RoundCtrlKey(m: Expr, b: Expr) =
  interface IInternKey<Expr> with
    member _.Matches x =
      match x with
      | RoundCtrl(m', b', _) -> m' === m && b' === b
      | _ -> false

    member _.Create hash = RoundCtrl(m, b, exprInfo hash)

[<Struct>]
type private ExtractKey(e: Expr, t: RegType, p: int) =
  interface IInternKey<Expr> with
    member _.Matches x =
      match x with
      | Extract(e', t', p', _) -> e' === e && t' = t && p' = p
      | _ -> false

    member _.Create hash = Extract(e, t, p, exprInfo hash)

[<Struct>]
type private UndefinedKey(t: RegType, why: string) =
  interface IInternKey<Expr> with
    member _.Matches x =
      match x with
      | Undefined(t', why', _) -> t' = t && why' = why
      | _ -> false

    member _.Create hash = Undefined(t, why, exprInfo hash)

[<Struct>]
type private ISMarkKey(len: uint32) =
  interface IInternKey<Stmt> with
    member _.Matches x =
      match x with
      | ISMark(len', _) -> len' = len
      | _ -> false

    member _.Create hash = ISMark(len, stmtInfo hash)

[<Struct>]
type private IEMarkKey(len: uint32) =
  interface IInternKey<Stmt> with
    member _.Matches x =
      match x with
      | IEMark(len', _) -> len' = len
      | _ -> false

    member _.Create hash = IEMark(len, stmtInfo hash)

[<Struct>]
type private LMarkKey(l: Label) =
  interface IInternKey<Stmt> with
    member _.Matches x =
      match x with
      | LMark(l', _) -> l' = l
      | _ -> false

    member _.Create hash = LMark(l, stmtInfo hash)

[<Struct>]
type private PutKey(d: Expr, v: Expr) =
  interface IInternKey<Stmt> with
    member _.Matches x =
      match x with
      | Put(d', v', _) -> d' === d && v' === v
      | _ -> false

    member _.Create hash = Put(d, v, stmtInfo hash)

[<Struct>]
type private StoreKey(en: Endian, a: Expr, v: Expr) =
  interface IInternKey<Stmt> with
    member _.Matches x =
      match x with
      | Store(en', a', v', _) -> en' = en && a' === a && v' === v
      | _ -> false

    member _.Create hash = Store(en, a, v, stmtInfo hash)

[<Struct>]
type private JmpKey(t: Expr) =
  interface IInternKey<Stmt> with
    member _.Matches x =
      match x with
      | Jmp(t', _) -> t' === t
      | _ -> false

    member _.Create hash = Jmp(t, stmtInfo hash)

[<Struct>]
type private CJmpKey(c: Expr, t: Expr, f: Expr) =
  interface IInternKey<Stmt> with
    member _.Matches x =
      match x with
      | CJmp(c', t', f', _) -> c' === c && t' === t && f' === f
      | _ -> false

    member _.Create hash = CJmp(c, t, f, stmtInfo hash)

[<Struct>]
type private InterJmpKey(t: Expr, k: InterJmpKind) =
  interface IInternKey<Stmt> with
    member _.Matches x =
      match x with
      | InterJmp(t', k', _) -> t' === t && k' = k
      | _ -> false

    member _.Create hash = InterJmp(t, k, stmtInfo hash)

[<Struct>]
type private InterCJmpKey(c: Expr, t: Expr, f: Expr) =
  interface IInternKey<Stmt> with
    member _.Matches x =
      match x with
      | InterCJmp(c', t', f', _) -> c' === c && t' === t && f' === f
      | _ -> false

    member _.Create hash = InterCJmp(c, t, f, stmtInfo hash)

[<Struct>]
type private ExternalCallKey(e: Expr) =
  interface IInternKey<Stmt> with
    member _.Matches x =
      match x with
      | ExternalCall(e', _) -> e' === e
      | _ -> false

    member _.Create hash = ExternalCall(e, stmtInfo hash)

[<Struct>]
type private SideEffectKey(eff: SideEffect) =
  interface IInternKey<Stmt> with
    member _.Matches x =
      match x with
      | SideEffect(eff', _) -> eff' = eff
      | _ -> false

    member _.Create hash = SideEffect(eff, stmtInfo hash)

let private exprs = WeakInternTable<Expr>()

let private stmts = WeakInternTable<Stmt>()
#endif

/// <summary>
/// Provides the constructors of this module that simplify, in a form that
/// builds exactly the node asked for.
/// </summary>
/// <remarks>
/// <c>AST.binop</c> and its kin fold an operation on constants, drop a cast
/// that changes nothing, and take the arm of an if-then-else on a constant. A
/// pass that rebuilds a node around new operands means the node it names, and
/// these give it that node, interned as any other where HASHCONS is defined.
/// </remarks>
[<RequireQualifiedAccess>]
module Raw =
  /// Construct a unary operator (UnOp) as it is.
  [<CompiledName("UnOp")>]
  let unop op e =
#if ! HASHCONS
    UnOp(op, e)
#else
    let key = UnOpKey(op, e)
    exprs.Intern(&key, Expr.HashUnOp(op, e))
#endif

  /// Construct a binary operator (BinOp) of the given type as it is.
  [<CompiledName("BinOp")>]
  let binop op t e1 e2 =
#if ! HASHCONS
    BinOp(op, t, e1, e2)
#else
    let key = BinOpKey(op, t, e1, e2)
    exprs.Intern(&key, Expr.HashBinOp(op, t, e1, e2))
#endif

  /// Construct a relative operator (RelOp) as it is.
  [<CompiledName("RelOp")>]
  let relop op e1 e2 =
#if ! HASHCONS
    RelOp(op, e1, e2)
#else
    let key = RelOpKey(op, e1, e2)
    exprs.Intern(&key, Expr.HashRelOp(op, e1, e2))
#endif

  /// Construct an ITE (if-then-else) expression (Ite) as it is.
  [<CompiledName("Ite")>]
  let ite cond e1 e2 =
#if ! HASHCONS
    Ite(cond, e1, e2)
#else
    let key = IteKey(cond, e1, e2)
    exprs.Intern(&key, Expr.HashIte(cond, e1, e2))
#endif

  /// Construct a cast expression (Cast) as it is.
  [<CompiledName("Cast")>]
  let cast kind rt e =
#if ! HASHCONS
    Cast(kind, rt, e)
#else
    let key = CastKey(kind, rt, e)
    exprs.Intern(&key, Expr.HashCast(kind, rt, e))
#endif

  /// Construct a body evaluated in a rounding direction (RoundCtrl) as it is.
  [<CompiledName("RoundCtrl")>]
  let roundCtrl mode body =
#if ! HASHCONS
    RoundCtrl(mode, body)
#else
    let key = RoundCtrlKey(mode, body)
    exprs.Intern(&key, Expr.HashRoundCtrl(mode, body))
#endif

  /// Construct an extraction (Extract) as it is.
  [<CompiledName("Extract")>]
  let extract expr rt pos =
#if ! HASHCONS
    Extract(expr, rt, pos)
#else
    let key = ExtractKey(expr, rt, pos)
    exprs.Intern(&key, Expr.HashExtract(expr, rt, pos))
#endif

/// Construct a number (Num).
[<CompiledName("Num")>]
let num bv =
#if ! HASHCONS
  Num bv
#else
  let key = NumKey(bv)
  exprs.Intern(&key, bv.GetHashCode())
#endif

/// Construct a variable (Var).
[<CompiledName("Var")>]
let var t id name =
#if ! HASHCONS
  Var(t, id, name)
#else
  let key = VarKey(t, id, name)
  exprs.Intern(&key, Expr.HashVar(t, id))
#endif

/// Construct a pc variable (PCVar).
[<CompiledName("PCVar")>]
let pcvar t name =
#if ! HASHCONS
  PCVar(t, name)
#else
  let key = PCVarKey(t, name)
  exprs.Intern(&key, Expr.HashPCVar t)
#endif

/// Construct a temporary variable (TempVar) with the given ID.
[<CompiledName("TmpVar")>]
let tmpvar t id =
#if ! HASHCONS
  TempVar(t, id)
#else
  let key = TempVarKey(t, id)
  exprs.Intern(&key, Expr.HashTempVar(t, id))
#endif

/// Construct a symbol (for a label) from a string and a IDCounter.
[<CompiledName("Label")>]
let inline label name id addr = Label(name, id, addr)

/// Construct an unary operator (UnOp).
[<CompiledName("UnOp")>]
let unop op e =
  match e with
  (* A rounding-dependent operation is left standing: what it comes to is not
     settled until a direction is, and the folding here has none. *)
  | Num(Value = n) when not (UnOpType.isRoundingDependent op) ->
    ValueOptimizer.unop n op |> num
  | _ ->
    Raw.unop op e

/// Construct a jump target (JmpDest).
[<CompiledName("JmpDest")>]
let jmpDest symb =
#if ! HASHCONS
  JmpDest symb
#else
  let key = JmpDestKey(symb)
  exprs.Intern(&key, Expr.HashJmpDest symb)
#endif

let private binopWithType op t e1 e2 =
  match e1, e2 with
  | Num(Value = n1), Num(Value = n2)
    when not (BinOpType.isRoundingDependent op) ->
    ValueOptimizer.binop n1 n2 op |> num
  | _ ->
    Raw.binop op t e1 e2

/// Construct a binary operator (BinOp).
[<CompiledName("BinOp")>]
let binop op e1 e2 =
  let t =
    match op with
    | BinOpType.CONCAT ->
      TypeCheck.concat e1 e2
    | _ ->
#if DEBUG
      TypeCheck.binop e1 e2
#else
      Expr.typeOf e1
#endif
  binopWithType op t e1 e2

/// Expression list.
[<CompiledName("ExprList")>]
let exprList lst =
#if ! HASHCONS
  ExprList lst
#else
  let key = ExprListKey(lst)
  exprs.Intern(&key, Expr.HashExprList lst)
#endif

/// Function name.
[<CompiledName("FuncName")>]
let funcName name =
#if ! HASHCONS
  FuncName name
#else
  let key = FuncNameKey(name)
  exprs.Intern(&key, Expr.HashFuncName name)
#endif

/// Construct a function application.
[<CompiledName("App")>]
let app name args retType =
  Raw.binop BinOpType.APP retType (funcName name) (exprList args)

/// Construct a relative operator (RelOp).
[<CompiledName("RelOp")>]
let relop op e1 e2 =
#if DEBUG
  TypeCheck.binop e1 e2 |> ignore
#endif
  match e1, e2 with
  | Num(Value = n1), Num(Value = n2) ->
    ValueOptimizer.relop n1 n2 op |> num
  | _ ->
    Raw.relop op e1 e2

/// Construct a load expression (Load).
[<CompiledName("Load")>]
let load endian rt addr =
#if DEBUG
  match addr with
  | JmpDest _ ->
    raise InvalidExprException
  | _ ->
#endif
#if ! HASHCONS
    Load(endian, rt, addr)
#else
    let key = LoadKey(endian, rt, addr)
    exprs.Intern(&key, Expr.HashLoad(endian, rt, addr))
#endif

/// Construct a load expression in little-endian.
[<CompiledName("LoadLE")>]
let loadLE t expr = load Endian.Little t expr

/// Construct a load expression in big-endian.
[<CompiledName("LoadBE")>]
let loadBE t expr = load Endian.Big t expr

/// Construct an ITE (if-then-else) expression (Ite).
[<CompiledName("Ite")>]
let ite cond e1 e2 =
#if DEBUG
  TypeCheck.bool cond
  TypeCheck.checkEquivalence (Expr.typeOf e1) (Expr.typeOf e2)
#endif
  match cond with
  | Num(Value = n) ->
    if n.IsZero then e2 else e1
  | _ ->
    Raw.ite cond e1 e2

/// Construct a cast expression (Cast).
[<CompiledName("Cast")>]
let cast kind rt e =
  match e with
  | Num(Value = n) when not (CastKind.isRoundingDependent kind) ->
    ValueOptimizer.cast rt n kind |> num
  | _ ->
    if TypeCheck.canCast kind rt e then
      Raw.cast kind rt e
    else
      e (* Remove unnecessary casting . *)

/// <summary>
/// Construct the mode expression naming a rounding direction outright, for a
/// <c>RoundCtrl</c> whose direction is known when the instruction is lifted.
/// </summary>
[<CompiledName("RoundingMode")>]
let roundingMode (mode: RoundingMode) =
  num (BitVector(int mode, RoundingMode.modeType))

/// <summary>
/// Construct a rounding control (RoundCtrl), which evaluates the body with the
/// given rounding direction in force. The mode is an 8-bit expression in the
/// <see cref='T:B2R2.BinIR.RoundingMode'/> encoding. It names a direction
/// rather than rounding anything itself: what rounds is the body.
/// </summary>
[<CompiledName("RoundCtrl")>]
let roundCtrl mode body =
#if DEBUG
  TypeCheck.roundingMode mode
#endif
  match body with
  (* A constant carries its own value; there is nothing left to round. *)
  | Num _ ->
    body
  (* The inner direction covers the whole body, so the outer one reaches
     nothing. *)
  | RoundCtrl _ ->
    body
  | _ ->
    Raw.roundCtrl mode body

/// <summary>
/// Construct a float-to-signed-integer conversion in a direction the
/// instruction names outright.
/// </summary>
/// <remarks>
/// A conversion that takes whatever direction the target's control register
/// holds is a bare <c>Cast(FloatToSInt, ...)</c> with nothing around it, this
/// being the difference the two spellings are there to draw.
/// </remarks>
[<CompiledName("FloatToSInt")>]
let floatToSInt mode rt e =
  roundCtrl (roundingMode mode) (cast CastKind.FloatToSInt rt e)

/// <summary>
/// Construct a round-to-integral-value in a direction the instruction names
/// outright, the result staying in the floating format it came in.
/// </summary>
/// <remarks>
/// As with <c>floatToSInt</c>, one that follows the target's control register
/// is a bare <c>Cast(RoundToIntegral, ...)</c>.
/// </remarks>
[<CompiledName("RoundToIntegral")>]
let roundToIntegral mode rt e =
  roundCtrl (roundingMode mode) (cast CastKind.RoundToIntegral rt e)

/// <summary>
/// Extract bits of the given size (<see cref='T:B2R2.RegType'/>) at the given
/// position from the given expression.
/// </summary>
[<CompiledName("Extract")>]
let extract expr rt pos =
  TypeCheck.extract rt pos (Expr.typeOf expr)
  match expr with
  | Num(Value = n) ->
    ValueOptimizer.extract n rt pos |> num
  | Extract(Operand = e; StartPos = p) ->
    Raw.extract e rt (p + pos)
  | _ ->
    Raw.extract expr rt pos

/// Undefined expression.
[<CompiledName("Undef")>]
let undef rt s =
#if ! HASHCONS
  Undefined(rt, s)
#else
  let key = UndefinedKey(rt, s)
  exprs.Intern(&key, Expr.HashUndef(rt, s))
#endif

/// Num expression for a one-bit number zero.
[<CompiledName("B0")>]
let b0 = num (BitVector.Zero 1<rt>)

/// Num expression for a one-bit number one.
[<CompiledName("B1")>]
let b1 = num (BitVector.One 1<rt>)

(* The widths a lifter asks for over and over. A Num is immutable, so one
   node serves every use site, which is what b0 and b1 above already do for
   one bit; keeping the rest spares a BitVector and a Num on every constant a
   lifter writes. Wider ones go through BitVectorBig and are too rare to be
   worth holding. *)
let private zeros =
  [| b0
     num (BitVector.Zero 8<rt>)
     num (BitVector.Zero 16<rt>)
     num (BitVector.Zero 32<rt>)
     num (BitVector.Zero 64<rt>) |]

let private ones =
  [| b1
     num (BitVector.One 8<rt>)
     num (BitVector.One 16<rt>)
     num (BitVector.One 32<rt>)
     num (BitVector.One 64<rt>) |]

let private widthIndex rt =
  match rt with
  | 1<rt> -> 0
  | 8<rt> -> 1
  | 16<rt> -> 2
  | 32<rt> -> 3
  | 64<rt> -> 4
  | _ -> -1

/// Construct a (Num 0) of size t.
[<CompiledName("Num0")>]
let num0 rt =
  let i = widthIndex rt
  if i < 0 then num (BitVector.Zero rt) else zeros[i]

/// Construct a (Num 1) of size t.
[<CompiledName("Num1")>]
let num1 rt =
  let i = widthIndex rt
  if i < 0 then num (BitVector.One rt) else ones[i]

/// Concatenation.
[<CompiledName("Concat")>]
let concat e1 e2 =
  let t = TypeCheck.concat e1 e2
  binopWithType BinOpType.CONCAT t e1 e2

let rec private concatLoop (arr: Expr[]) sPos ePos =
  let diff = ePos - sPos
  if diff > 0 then concat (concatLoop arr (sPos + diff / 2 + 1) ePos)
                          (concatLoop arr sPos (sPos + diff / 2))
  elif diff = 0 then arr[sPos]
  else Terminator.impossible ()

/// <summary>
/// Concatenate the given arrays in reverse order. For example, if the input is
/// <c>[| Num 0; Num 1; Num 2; Num 3 |]</c> then the output is <c>Concat (Concat
/// (Num 3, Num 2), Concat (Num 1, Num 0))</c>.
/// </summary>
[<CompiledName("RevConcat")>]
let revConcat (arr: Expr[]) = concatLoop arr 0 (Array.length arr - 1)

/// <summary>
/// Concatenate a range of the given array in reverse order, as revConcat does
/// for the whole of it. A caller that concatenates one slice after another
/// takes this rather than copying each slice out first.
/// </summary>
[<CompiledName("RevConcatRange")>]
let revConcatRange (arr: Expr[]) start len =
  concatLoop arr start (start + len - 1)

/// Unwrap (casted) expression.
[<CompiledName("Unwrap")>]
let rec unwrap e =
  match e with
  | Cast(Operand = e)
  | Extract(Operand = e) -> unwrap e
  | _ -> e

/// Zero-extend an expression.
[<CompiledName("ZExt")>]
let zext addrSize expr = cast CastKind.ZeroExt addrSize expr

/// Sign-extend an expression.
[<CompiledName("SExt")>]
let sext addrSize expr = cast CastKind.SignExt addrSize expr

/// Take the low half bits of an expression.
[<CompiledName("XtLo")>]
let xtlo addrSize expr = extract expr addrSize 0

/// Take the high half bits of an expression.
[<CompiledName("XtHi")>]
let xthi addrSize expr =
  extract expr addrSize (int (Expr.typeOf expr - addrSize))

/// Add two expressions.
[<CompiledName("Add")>]
let add e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.typeOf e1
#endif
  binopWithType BinOpType.ADD t e1 e2

/// Subtract two expressions.
[<CompiledName("Sub")>]
let sub e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.typeOf e1
#endif
  binopWithType BinOpType.SUB t e1 e2

/// Multiply two expressions.
[<CompiledName("Mul")>]
let mul e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.typeOf e1
#endif
  binopWithType BinOpType.MUL t e1 e2

/// Unsigned division.
[<CompiledName("Div")>]
let div e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.typeOf e1
#endif
  binopWithType BinOpType.DIV t e1 e2

/// Signed division.
[<CompiledName("SDiv")>]
let sdiv e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.typeOf e1
#endif
  binopWithType BinOpType.SDIV t e1 e2

/// Unsigned modulus.
[<CompiledName("Mod")>]
let ``mod`` e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.typeOf e1
#endif
  binopWithType BinOpType.MOD t e1 e2

/// Signed modulus.
[<CompiledName("SMod")>]
let smod e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.typeOf e1
#endif
  binopWithType BinOpType.SMOD t e1 e2

/// Equal.
[<CompiledName("Eq")>]
let eq e1 e2 =
  relop RelOpType.EQ e1 e2

/// Not equal.
[<CompiledName("Neq")>]
let neq e1 e2 =
  relop RelOpType.NEQ e1 e2

/// Unsigned greater than.
[<CompiledName("Gt")>]
let gt e1 e2 = relop RelOpType.GT e1 e2

/// Unsigned greater than or equal.
[<CompiledName("Ge")>]
let ge e1 e2 = relop RelOpType.GE e1 e2

/// Signed greater than.
[<CompiledName("SGt")>]
let sgt e1 e2 = relop RelOpType.SGT e1 e2

/// Signed greater than or equal.
[<CompiledName("SGe")>]
let sge e1 e2 = relop RelOpType.SGE e1 e2

/// Unsigned less than.
[<CompiledName("Lt")>]
let lt e1 e2 = relop RelOpType.LT e1 e2

/// Unsigned less than or equal.
[<CompiledName("Le")>]
let le e1 e2 = relop RelOpType.LE e1 e2

/// Signed less than.
[<CompiledName("SLt")>]
let slt e1 e2 = relop RelOpType.SLT e1 e2

/// Signed less than or equal.
[<CompiledName("SLe")>]
let sle e1 e2 = relop RelOpType.SLE e1 e2

/// Bitwise AND.
[<CompiledName("And")>]
let ``and`` e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.typeOf e1
#endif
  binopWithType BinOpType.AND t e1 e2

/// Bitwise OR.
[<CompiledName("Or")>]
let ``or`` e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.typeOf e1
#endif
  binopWithType BinOpType.OR t e1 e2

/// Bitwise XOR.
[<CompiledName("Xor")>]
let xor e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.typeOf e1
#endif
  binopWithType BinOpType.XOR t e1 e2

/// Shift arithmetic right.
[<CompiledName("Sar")>]
let sar e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.typeOf e1
#endif
  binopWithType BinOpType.SAR t e1 e2

/// Shift logical right.
[<CompiledName("Shr")>]
let shr e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.typeOf e1
#endif
  binopWithType BinOpType.SHR t e1 e2

/// Shift logical left.
[<CompiledName("Shl")>]
let shl e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.typeOf e1
#endif
  binopWithType BinOpType.SHL t e1 e2

/// Negation (Two's complement).
[<CompiledName("Neg")>]
let neg e = unop UnOpType.NEG e

/// Logical not.
[<CompiledName("Not")>]
let not e = unop UnOpType.NOT e

/// Floating point add two expressions.
[<CompiledName("FAdd")>]
let fadd e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.typeOf e1
#endif
  binopWithType BinOpType.FADD t e1 e2

/// Floating point subtract two expressions.
[<CompiledName("FSub")>]
let fsub e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.typeOf e1
#endif
  binopWithType BinOpType.FSUB t e1 e2

/// Floating point multiplication.
[<CompiledName("FMul")>]
let fmul e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.typeOf e1
#endif
  binopWithType BinOpType.FMUL t e1 e2

/// Floating point division.
[<CompiledName("FDiv")>]
let fdiv e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.typeOf e1
#endif
  binopWithType BinOpType.FDIV t e1 e2

/// Floating point equal.
[<CompiledName("FEq")>]
let feq e1 e2 = relop RelOpType.FEQ e1 e2

/// Floating point greater than.
[<CompiledName("FGt")>]
let fgt e1 e2 = relop RelOpType.FGT e1 e2

/// Floating point greater than or equal.
[<CompiledName("FGe")>]
let fge e1 e2 = relop RelOpType.FGE e1 e2

/// Floating point less than.
[<CompiledName("FLt")>]
let flt e1 e2 = relop RelOpType.FLT e1 e2

/// Floating point less than or equal.
[<CompiledName("FLe")>]
let fle e1 e2 = relop RelOpType.FLE e1 e2

/// Floating point power.
[<CompiledName("FPow")>]
let fpow e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.typeOf e1
#endif
  binopWithType BinOpType.FPOW t e1 e2

/// Floating point logarithm.
[<CompiledName("FLog")>]
let flog e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.typeOf e1
#endif
  binopWithType BinOpType.FLOG t e1 e2

/// Floating point square root.
[<CompiledName("FSqrt")>]
let fsqrt e = unop UnOpType.FSQRT e

/// Floating point sine.
[<CompiledName("FSin")>]
let fsin e = unop UnOpType.FSIN e

/// Floating point cosine.
[<CompiledName("FCos")>]
let fcos e = unop UnOpType.FCOS e

/// Floating point tangent.
[<CompiledName("FTan")>]
let ftan e = unop UnOpType.FTAN e

/// Floating point arc tangent.
[<CompiledName("FATan")>]
let fatan e = unop UnOpType.FATAN e

/// Floating point arc sine.
[<CompiledName("FAsin")>]
let fasin e = unop UnOpType.FASIN e

/// Floating point arc cosine.
[<CompiledName("FAcos")>]
let facos e = unop UnOpType.FACOS e

/// Floating point hyperbolic sine.
[<CompiledName("FSinh")>]
let fsinh e = unop UnOpType.FSINH e

/// Floating point hyperbolic cosine.
[<CompiledName("FCosh")>]
let fcosh e = unop UnOpType.FCOSH e

/// Floating point hyperbolic tangent.
[<CompiledName("FTanh")>]
let ftanh e = unop UnOpType.FTANH e

/// Floating point inverse hyperbolic tangent.
[<CompiledName("FAtanh")>]
let fatanh e = unop UnOpType.FATANH e

/// An ISMark statement.
[<CompiledName("ISMark")>]
let ismark nBytes =
#if ! HASHCONS
  ISMark nBytes
#else
  let key = ISMarkKey(nBytes)
  stmts.Intern(&key, Stmt.HashISMark nBytes)
#endif

/// An IEMark statement.
[<CompiledName("IEMark")>]
let iemark nBytes =
#if ! HASHCONS
  IEMark nBytes
#else
  let key = IEMarkKey(nBytes)
  stmts.Intern(&key, Stmt.HashIEMark nBytes)
#endif

/// An LMark statement.
[<CompiledName("LMark")>]
let lmark label =
#if ! HASHCONS
  LMark label
#else
  let key = LMarkKey(label)
  stmts.Intern(&key, Stmt.HashLMark label)
#endif

/// A Put statement.
[<CompiledName("Put")>]
let put dst src =
#if ! HASHCONS
  Put(dst, src)
#else
  let key = PutKey(dst, src)
  stmts.Intern(&key, Stmt.HashPut(dst, src))
#endif

let private assignForExtractDst e1 e2 =
  match e1 with
  | Extract(Operand = Var(Type = t) as e1; Type = eTyp; StartPos = 0)
  | Extract(Operand = TempVar(Type = t) as e1; Type = eTyp; StartPos = 0) ->
    let nMask = RegType.makeMask t - RegType.makeMask eTyp
    let mask = BitVector(nMask, t) |> num
    let src = cast CastKind.ZeroExt t e2
    put e1 (binopWithType BinOpType.OR
                          t
                          (binopWithType BinOpType.AND t e1 mask)
                          src)
  | Extract(Operand = Var(Type = t) as e1; Type = eTyp; StartPos = pos)
  | Extract(Operand = TempVar(Type = t) as e1; Type = eTyp; StartPos = pos) ->
    let nMask = RegType.makeMask t - (RegType.makeMask eTyp <<< pos)
    let mask = BitVector(nMask, t) |> num
    let src = cast CastKind.ZeroExt t e2
    let shift = BitVector(pos, t) |> num
    let src = binopWithType BinOpType.SHL t src shift
    put e1 (binopWithType BinOpType.OR
                          t
                          (binopWithType BinOpType.AND t e1 mask)
                          src)
  | e ->
#if DEBUG
    eprintfn $"{e.ToString()}"
#endif
    raise InvalidAssignmentException

/// A Store statement.
[<CompiledName("Store")>]
let store endian addr v =
#if ! HASHCONS
  Store(endian, addr, v)
#else
  let key = StoreKey(endian, addr, v)
  stmts.Intern(&key, Stmt.HashStore(endian, addr, v))
#endif

/// An assignment statement.
[<CompiledName("Assign")>]
let assign dst src =
#if DEBUG
  TypeCheck.checkEquivalence (Expr.typeOf dst) (Expr.typeOf src)
#endif
  match dst with
  | Var _ | TempVar _ | PCVar _ -> put dst src
  | Load(Endian = endian; Addr = e) -> store endian e src
  | Extract _ -> assignForExtractDst dst src
  | _ -> raise InvalidAssignmentException

/// A Jmp statement.
[<CompiledName("Jmp")>]
let jmp target =
#if ! HASHCONS
  Jmp target
#else
  let key = JmpKey(target)
  stmts.Intern(&key, Stmt.HashJmp target)
#endif

/// A CJmp statement.
[<CompiledName("CJmp")>]
let cjmp cond dst1 dst2 =
#if ! HASHCONS
  CJmp(cond, dst1, dst2)
#else
  let key = CJmpKey(cond, dst1, dst2)
  stmts.Intern(&key, Stmt.HashCJmp(cond, dst1, dst2))
#endif

/// An InterJmp statement.
[<CompiledName("InterJmp")>]
let interjmp dst kind =
#if ! HASHCONS
  InterJmp(dst, kind)
#else
  let key = InterJmpKey(dst, kind)
  stmts.Intern(&key, Stmt.HashInterJmp(dst, kind))
#endif

/// A InterCJmp statement.
[<CompiledName("InterCJmp")>]
let intercjmp cond d1 d2 =
#if ! HASHCONS
  InterCJmp(cond, d1, d2)
#else
  let key = InterCJmpKey(cond, d1, d2)
  stmts.Intern(&key, Stmt.HashInterCJmp(cond, d1, d2))
#endif

/// External call.
[<CompiledName("ExtCall")>]
let extCall appExpr =
#if ! HASHCONS
  ExternalCall appExpr
#else
  let key = ExternalCallKey(appExpr)
  stmts.Intern(&key, Stmt.HashExtCall appExpr)
#endif

/// A SideEffect statement.
[<CompiledName("SideEffect")>]
let sideEffect eff =
#if ! HASHCONS
  SideEffect eff
#else
  let key = SideEffectKey(eff)
  stmts.Intern(&key, Stmt.HashSideEffect eff)
#endif

/// Record the use of vars and tempvars from the given expression.
let rec updateAllVarsUses (rset: RegisterSet) (tset: HashSet<int>) e =
  match e with
  | Num _ | PCVar _ | JmpDest _ | FuncName _ | Undefined _ ->
    ()
  | Var(RegisterID = rid) ->
    rset.Add(int rid)
  | TempVar(Index = n) ->
    tset.Add n |> ignore
  | ExprList(Elements = exprs) ->
    for e in exprs do updateAllVarsUses rset tset e done
  | UnOp(Operand = e) ->
    updateAllVarsUses rset tset e
  | BinOp(Left = lhs; Right = rhs) ->
    updateAllVarsUses rset tset lhs
    updateAllVarsUses rset tset rhs
  | RelOp(Left = lhs; Right = rhs) ->
    updateAllVarsUses rset tset lhs
    updateAllVarsUses rset tset rhs
  | Load(Addr = e) ->
    updateAllVarsUses rset tset e
  | Ite(Cond = cond; TrueExpr = e1; FalseExpr = e2) ->
    updateAllVarsUses rset tset cond
    updateAllVarsUses rset tset e1
    updateAllVarsUses rset tset e2
  | Cast(Operand = e) ->
    updateAllVarsUses rset tset e
  | RoundCtrl(Mode = mode; Body = body) ->
    updateAllVarsUses rset tset mode
    updateAllVarsUses rset tset body
  | Extract(Operand = e) ->
    updateAllVarsUses rset tset e

/// Record the use of vars (registers) from the given expression.
let rec updateRegsUses (rset: RegisterSet) e =
  match e with
  | Num _ | PCVar _ | JmpDest _ | FuncName _ | Undefined _ | TempVar _ ->
    ()
  | Var(RegisterID = rid) ->
    rset.Add(int rid)
  | ExprList(Elements = exprs) ->
    for e in exprs do updateRegsUses rset e done
  | UnOp(Operand = e) ->
    updateRegsUses rset e
  | BinOp(Left = lhs; Right = rhs) ->
    updateRegsUses rset lhs
    updateRegsUses rset rhs
  | RelOp(Left = lhs; Right = rhs) ->
    updateRegsUses rset lhs
    updateRegsUses rset rhs
  | Load(Addr = e) ->
    updateRegsUses rset e
  | Ite(Cond = cond; TrueExpr = e1; FalseExpr = e2) ->
    updateRegsUses rset cond
    updateRegsUses rset e1
    updateRegsUses rset e2
  | Cast(Operand = e) ->
    updateRegsUses rset e
  | RoundCtrl(Mode = mode; Body = body) ->
    updateRegsUses rset mode
    updateRegsUses rset body
  | Extract(Operand = e) ->
    updateRegsUses rset e

/// Record the use of tempvars from the given expression.
let rec updateTempsUses (tset: HashSet<int>) e =
  match e with
  | Num _ | PCVar _ | JmpDest _ | FuncName _ | Undefined _ | Var _ ->
    ()
  | TempVar(Index = n) ->
    tset.Add n |> ignore
  | ExprList(Elements = exprs) ->
    for e in exprs do updateTempsUses tset e done
  | UnOp(Operand = e) ->
    updateTempsUses tset e
  | BinOp(Left = lhs; Right = rhs) ->
    updateTempsUses tset lhs
    updateTempsUses tset rhs
  | RelOp(Left = lhs; Right = rhs) ->
    updateTempsUses tset lhs
    updateTempsUses tset rhs
  | Load(Addr = e) ->
    updateTempsUses tset e
  | Ite(Cond = cond; TrueExpr = e1; FalseExpr = e2) ->
    updateTempsUses tset cond
    updateTempsUses tset e1
    updateTempsUses tset e2
  | Cast(Operand = e) ->
    updateTempsUses tset e
  | RoundCtrl(Mode = mode; Body = body) ->
    updateTempsUses tset mode
    updateTempsUses tset body
  | Extract(Operand = e) ->
    updateTempsUses tset e

/// <summary>
/// Provides infix operators for LowUIR expressions. Each infix operator has a
/// corresponding function in the <see cref='T:B2R2.BinIR.LowUIR.AST'/> module.
/// </summary>
module InfixOp =
  /// Assignment.
  let inline (:=) e1 e2 = assign e1 e2

  /// Addition.
  let inline (.+) e1 e2 = add e1 e2

  /// Subtraction.
  let inline (.-) e1 e2 = sub e1 e2

  /// Multiplication.
  let inline (.*) e1 e2 = mul e1 e2

  /// Unsigned division.
  let inline (./) e1 e2 = div e1 e2

  /// Signed division.
  let inline (?/) e1 e2 = sdiv e1 e2

  /// Unsigned modulus.
  let inline (.%) e1 e2 = ``mod`` e1 e2

  /// Signed modulus.
  let inline (?%) e1 e2 = smod e1 e2

  /// Equal.
  let inline (==) e1 e2 = eq e1 e2

  /// Not equal.
  let inline (!=) e1 e2 = neq e1 e2

  /// Unsigned greater than.
  let inline (.>) e1 e2 = gt e1 e2

  /// Unsigned greater than or equal.
  let inline (.>=) e1 e2 = ge e1 e2

  /// Signed greater than.
  let inline (?>) e1 e2 = sgt e1 e2

  /// Signed greater than or equal.
  let inline (?>=) e1 e2 = sge e1 e2

  /// Unsigned less than.
  let inline (.<) e1 e2 = lt e1 e2

  /// Unsigned less than or equal.
  let inline (.<=) e1 e2 = le e1 e2

  /// Signed less than.
  let inline (?<) e1 e2 = slt e1 e2

  /// Signed less than or equal.
  let inline (?<=) e1 e2 = sle e1 e2

  /// Bitwise AND.
  let inline (.&) e1 e2 = ``and`` e1 e2

  /// Bitwise OR.
  let inline (.|) e1 e2 = ``or`` e1 e2

  /// Bitwise XOR.
  let inline (<+>) e1 e2 = xor e1 e2

  /// Shift arithmetic right.
  let inline (?>>) e1 e2 = sar e1 e2

  /// Shift logical right.
  let inline (>>) e1 e2 = shr e1 e2

  /// Shift logical left.
  let inline (<<) e1 e2 = shl e1 e2
