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
open System
open System.Collections.Concurrent

let private eTagCnt = ref 0u
let private sTagCnt = ref 0u

(* As we use a dictionary with WeakReference values, only the "values" will be
   collected in the end. This will produce some garbage entries (with a null
   value). We could use MemoryCache to handle the problem, but the memory leak
   is not severe enough to trade-off the performance. *)
let private exprs = ConcurrentDictionary<Expr, WeakReference<Expr>>()
let private stmts = ConcurrentDictionary<Stmt, WeakReference<Stmt>>()
let private newEID () = Threading.Interlocked.Increment eTagCnt
let private newSID () = Threading.Interlocked.Increment sTagCnt

let inline private tryGetExpr (k: Expr) =
  match exprs.TryGetValue k with
  | true, e ->
    match e.TryGetTarget() with
    | true, e -> Ok e
    | false, _ -> Error true
  | _ -> Error false

let inline private tryGetStmt (k: Stmt) =
  match stmts.TryGetValue k with
  | true, s ->
    match s.TryGetTarget() with
    | true, s -> Ok s
    | false, _ -> Error true
  | _ -> Error false
#endif

/// Construct a number (Num).
[<CompiledName("Num")>]
let num bv =
#if ! HASHCONS
  Num(bv, null)
#else
  let hc = HashConsingInfo()
  let e = Num(bv, hc)
  match tryGetExpr e with
  | Ok e -> e
  | Error isReclaimed ->
    hc.ID <- newEID ()
    hc.Hash <- bv.GetHashCode()
    if isReclaimed then exprs[e].SetTarget e
    else exprs[e] <- WeakReference<Expr> e
    e
#endif

/// Construct a variable (Var).
[<CompiledName("Var")>]
let var t id name =
#if ! HASHCONS
  Var(t, id, name, null)
#else
  let hc = HashConsingInfo()
  let e = Var(t, id, name, hc)
  match tryGetExpr e with
  | Ok e -> e
  | Error isReclaimed ->
    hc.ID <- newEID ()
    hc.Hash <- Expr.HashVar t id
    if isReclaimed then exprs[e].SetTarget e
    else exprs[e] <- WeakReference<Expr> e
    e
#endif

/// Construct a pc variable (PCVar).
[<CompiledName("PCVar")>]
let pcvar t name =
#if ! HASHCONS
  PCVar(t, name, null)
#else
  let hc = HashConsingInfo()
  let e = PCVar(t, name, hc)
  match tryGetExpr e with
  | Ok e -> e
  | Error isReclaimed ->
    hc.ID <- newEID ()
    hc.Hash <- Expr.HashPCVar t
    if isReclaimed then exprs[e].SetTarget e
    else exprs[e] <- WeakReference<Expr> e
    e
#endif

/// Construct a temporary variable (TempVar) with the given ID.
[<CompiledName("TmpVar")>]
let tmpvar t id =
#if ! HASHCONS
  TempVar(t, id, null)
#else
  let hc = HashConsingInfo()
  let e = TempVar(t, id, hc)
  match tryGetExpr e with
  | Ok e -> e
  | Error isReclaimed ->
    hc.ID <- newEID ()
    hc.Hash <- Expr.HashTempVar t id
    if isReclaimed then exprs[e].SetTarget e
    else exprs[e] <- WeakReference<Expr> e
    e
#endif

/// Construct a symbol (for a label) from a string and a IDCounter.
[<CompiledName("Label")>]
let inline label name id addr =
  Label(name, id, addr)

/// Construct an unary operator (UnOp).
[<CompiledName("UnOp")>]
let unop op e =
  match e with
  | Num(n, _) -> ValueOptimizer.unop n op |> num
#if ! HASHCONS
  | _ -> UnOp(op, e, null)
#else
  | _ ->
    let hc = HashConsingInfo()
    let e = UnOp(op, e, hc)
    match tryGetExpr e with
    | Ok e -> e
    | Error isReclaimed ->
      hc.ID <- newEID ()
      hc.Hash <- Expr.HashUnOp op e true
      if isReclaimed then exprs[e].SetTarget e
      else exprs[e] <- WeakReference<Expr> e
      e
#endif

/// Construct a jump target (JmpDest).
[<CompiledName("JmpDest")>]
let jmpDest symb =
#if ! HASHCONS
  JmpDest(symb, null)
#else
  let hc = HashConsingInfo()
  let e = JmpDest(symb, hc)
  match tryGetExpr e with
  | Ok e -> e
  | Error isReclaimed ->
    hc.ID <- newEID ()
    hc.Hash <- Expr.HashJmpDest symb
    if isReclaimed then exprs[e].SetTarget e
    else exprs[e] <- WeakReference<Expr> e
    e
#endif

let private binopWithType op t e1 e2 =
  match e1, e2 with
  | Num(n1, _), Num(n2, _) -> ValueOptimizer.binop n1 n2 op |> num
#if ! HASHCONS
  | _ ->
    BinOp(op, t, e1, e2, null)
#else
  | _ ->
    let hc = HashConsingInfo()
    let e = BinOp(op, t, e1, e2, hc)
    match tryGetExpr e with
    | Ok e -> e
    | Error isReclaimed ->
      hc.ID <- newEID ()
      hc.Hash <- Expr.HashBinOp op t e1 e2 true
      if isReclaimed then exprs[e].SetTarget e
      else exprs[e] <- WeakReference<Expr> e
      e
#endif

/// Construct a binary operator (BinOp).
[<CompiledName("BinOp")>]
let binop op e1 e2 =
  let t =
    match op with
    | BinOpType.CONCAT -> TypeCheck.concat e1 e2
    | _ ->
#if DEBUG
      TypeCheck.binop e1 e2
#else
      Expr.TypeOf e1
#endif
  binopWithType op t e1 e2

/// Expression list.
[<CompiledName("ExprList")>]
let exprList lst =
#if ! HASHCONS
  ExprList(lst, null)
#else
    let hc = HashConsingInfo()
    let e = ExprList(lst, hc)
    match tryGetExpr e with
    | Ok e -> e
    | Error isReclaimed ->
      hc.ID <- newEID ()
      hc.Hash <- Expr.HashExprList lst true
      if isReclaimed then exprs[e].SetTarget e
      else exprs[e] <- WeakReference<Expr> e
      e
#endif

/// Function name.
[<CompiledName("FuncName")>]
let funcName name =
#if ! HASHCONS
  FuncName(name, null)
#else
  let hc = HashConsingInfo()
  let e = FuncName(name, hc)
  match tryGetExpr e with
  | Ok e -> e
  | Error isReclaimed ->
    hc.ID <- newEID ()
    hc.Hash <- Expr.HashFuncName name
    if isReclaimed then exprs[e].SetTarget e
    else exprs[e] <- WeakReference<Expr> e
    e
#endif

/// Construct a function application.
[<CompiledName("App")>]
let app name args retType =
  let fnName = funcName name
  exprList args
#if ! HASHCONS
  |> fun cons ->
    BinOp(BinOpType.APP, retType, fnName, cons, null)
#else
  |> fun cons ->
    let hc = HashConsingInfo()
    let e = BinOp(BinOpType.APP, retType, fnName, cons, hc)
    match tryGetExpr e with
    | Ok e -> e
    | Error isReclaimed ->
      hc.ID <- newEID ()
      hc.Hash <- Expr.HashBinOp BinOpType.APP retType fnName cons true
      if isReclaimed then exprs[e].SetTarget e
      else exprs[e] <- WeakReference<Expr> e
      e
#endif

/// Construct a relative operator (RelOp).
[<CompiledName("RelOp")>]
let relop op e1 e2 =
#if DEBUG
  TypeCheck.binop e1 e2 |> ignore
#endif
  match e1, e2 with
  | Num(n1, _), Num(n2, _) -> ValueOptimizer.relop n1 n2 op |> num
#if ! HASHCONS
  | _ ->
    RelOp(op, e1, e2, null)
#else
  | _ ->
    let hc = HashConsingInfo()
    let e = RelOp(op, e1, e2, hc)
    match tryGetExpr e with
    | Ok e -> e
    | Error isReclaimed ->
      hc.ID <- newEID ()
      hc.Hash <- Expr.HashRelOp op e1 e2 true
      if isReclaimed then exprs[e].SetTarget e
      else exprs[e] <- WeakReference<Expr> e
      e
#endif

/// Construct a load expression (Load).
[<CompiledName("Load")>]
let load endian rt addr =
#if DEBUG
  match addr with
  | JmpDest _ -> raise InvalidExprException
  | _ ->
#endif
#if ! HASHCONS
    Load(endian, rt, addr, null)
#else
    let hc = HashConsingInfo()
    let e = Load(endian, rt, addr, hc)
    match tryGetExpr e with
    | Ok e -> e
    | Error isReclaimed ->
      hc.ID <- newEID ()
      hc.Hash <- Expr.HashLoad endian rt addr true
      if isReclaimed then exprs[e].SetTarget e
      else exprs[e] <- WeakReference<Expr> e
      e
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
  TypeCheck.checkEquivalence (Expr.TypeOf e1) (Expr.TypeOf e2)
#endif
  match cond with
  | Num(n, _) -> if BitVector.IsZero n then e2 else e1
  | _ ->
#if ! HASHCONS
    Ite(cond, e1, e2, null)
#else
    let hc = HashConsingInfo()
    let e = Ite(cond, e1, e2, hc)
    match tryGetExpr e with
    | Ok e -> e
    | Error isReclaimed ->
      hc.ID <- newEID ()
      hc.Hash <- Expr.HashIte cond e1 e2 true
      if isReclaimed then exprs[e].SetTarget e
      else exprs[e] <- WeakReference<Expr> e
      e
#endif

/// Construct a cast expression (Cast).
[<CompiledName("Cast")>]
let cast kind rt e =
  match e with
  | Num(n, _) -> ValueOptimizer.cast rt n kind |> num
  | _ ->
    if TypeCheck.canCast kind rt e then
#if ! HASHCONS
      Cast(kind, rt, e, null)
#else
      let hc = HashConsingInfo()
      let e = Cast(kind, rt, e, hc)
      match tryGetExpr e with
      | Ok e -> e
      | Error isReclaimed ->
        hc.ID <- newEID ()
        hc.Hash <- Expr.HashCast kind rt e true
        if isReclaimed then exprs[e].SetTarget e
        else exprs[e] <- WeakReference<Expr> e
        e
#endif
    else e (* Remove unnecessary casting . *)

/// <summary>
/// Extract bits of the given size (<see cref='T:B2R2.RegType'/>) at the given
/// position from the given expression.
/// </summary>
[<CompiledName("Extract")>]
let extract expr rt pos =
  TypeCheck.extract rt pos (Expr.TypeOf expr)
  match expr with
  | Num(n, _) -> ValueOptimizer.extract n rt pos |> num
  | Extract(e, _, p, _) ->
    let pos = p + pos
#if ! HASHCONS
    Extract(e, rt, pos, null)
#else
    let hc = HashConsingInfo()
    let e = Extract(e, rt, pos, hc)
    match tryGetExpr e with
    | Ok e -> e
    | Error isReclaimed ->
      hc.ID <- newEID ()
      hc.Hash <- Expr.HashExtract e rt pos true
      if isReclaimed then exprs[e].SetTarget e
      else exprs[e] <- WeakReference<Expr> e
      e
#endif
  | _ ->
#if ! HASHCONS
    Extract(expr, rt, pos, null)
#else
    let hc = HashConsingInfo()
    let e = Extract(expr, rt, pos, hc)
    match tryGetExpr e with
    | Ok e -> e
    | Error isReclaimed ->
      hc.ID <- newEID ()
      hc.Hash <- Expr.HashExtract expr rt pos true
      if isReclaimed then exprs[e].SetTarget e
      else exprs[e] <- WeakReference<Expr> e
      e
#endif

/// Undefined expression.
[<CompiledName("Undef")>]
let undef rt s =
#if ! HASHCONS
  Undefined(rt, s, null)
#else
  let hc = HashConsingInfo()
  let e = Undefined(rt, s, hc)
  match tryGetExpr e with
  | Ok e -> e
  | Error isReclaimed ->
    hc.ID <- newEID ()
    hc.Hash <- Expr.HashUndef rt s
    if isReclaimed then exprs[e].SetTarget e
    else exprs[e] <- WeakReference<Expr> e
    e
#endif

/// Construct a (Num 0) of size t.
[<CompiledName("Num0")>]
let num0 rt = num (BitVector.Zero rt)

/// Construct a (Num 1) of size t.
[<CompiledName("Num1")>]
let num1 rt = num (BitVector.One rt)

/// Num expression for a one-bit number zero.
[<CompiledName("B0")>]
let b0 = num (BitVector.Zero 1<rt>)

/// Num expression for a one-bit number one.
[<CompiledName("B1")>]
let b1 = num (BitVector.One 1<rt>)

/// Concatenation.
[<CompiledName("Concat")>]
let concat e1 e2 =
  let t = TypeCheck.concat e1 e2
  binopWithType BinOpType.CONCAT t e1 e2

let rec private concatLoop (arr: Expr []) sPos ePos =
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
let revConcat (arr: Expr[]) =
  concatLoop arr 0 (Array.length arr - 1)

/// Unwrap (casted) expression.
[<CompiledName("Unwrap")>]
let rec unwrap e =
  match e with
  | Cast(_, _, e, _)
  | Extract(e, _, _, _) -> unwrap e
  | _ -> e

/// Zero-extend an expression.
[<CompiledName("ZExt")>]
let zext addrSize expr = cast CastKind.ZeroExt addrSize expr

/// Sign-extend an expression.
[<CompiledName("SExt")>]
let sext addrSize expr = cast CastKind.SignExt addrSize expr

/// Take the low half bits of an expression.
[<CompiledName("XtLo")>]
let xtlo addrSize expr =
  extract expr addrSize 0

/// Take the high half bits of an expression.
[<CompiledName("XtHi")>]
let xthi addrSize expr =
  extract expr addrSize (int (Expr.TypeOf expr - addrSize))

/// Add two expressions.
[<CompiledName("Add")>]
let add e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.TypeOf e1
#endif
#if ! HASHCONS
  binopWithType BinOpType.ADD t e1 e2
#else
  if e1 < e2 then binopWithType BinOpType.ADD t e1 e2
  else binopWithType BinOpType.ADD t e2 e1
#endif

/// Subtract two expressions.
[<CompiledName("Sub")>]
let sub e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.TypeOf e1
#endif
  binopWithType BinOpType.SUB t e1 e2

/// Multiply two expressions.
[<CompiledName("Mul")>]
let mul e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.TypeOf e1
#endif
#if ! HASHCONS
  binopWithType BinOpType.MUL t e1 e2
#else
  if e1 < e2 then binopWithType BinOpType.MUL t e1 e2
  else binopWithType BinOpType.MUL t e2 e1
#endif

/// Unsigned division.
[<CompiledName("Div")>]
let div e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.TypeOf e1
#endif
  binopWithType BinOpType.DIV t e1 e2

/// Signed division.
[<CompiledName("SDiv")>]
let sdiv e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.TypeOf e1
#endif
  binopWithType BinOpType.SDIV t e1 e2

/// Unsigned modulus.
[<CompiledName("Mod")>]
let ``mod`` e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.TypeOf e1
#endif
  binopWithType BinOpType.MOD t e1 e2

/// Signed modulus.
[<CompiledName("SMod")>]
let smod e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.TypeOf e1
#endif
  binopWithType BinOpType.SMOD t e1 e2

/// Equal.
[<CompiledName("Eq")>]
let eq e1 e2 =
#if ! HASHCONS
  relop RelOpType.EQ e1 e2
#else
  if e1 < e2 then relop RelOpType.EQ e1 e2
  else relop RelOpType.EQ e2 e1
#endif

/// Not equal.
[<CompiledName("Neq")>]
let neq e1 e2 =
#if ! HASHCONS
  relop RelOpType.NEQ e2 e1
#else
  if e1 < e2 then relop RelOpType.NEQ e1 e2
  else relop RelOpType.NEQ e2 e1
#endif

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
    Expr.TypeOf e1
#endif
  binopWithType BinOpType.AND t e1 e2

/// Bitwise OR.
[<CompiledName("Or")>]
let ``or`` e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.TypeOf e1
#endif
#if ! HASHCONS
  binopWithType BinOpType.OR t e2 e1
#else
  if e1 < e2 then binopWithType BinOpType.OR t e1 e2
  else binopWithType BinOpType.OR t e2 e1
#endif

/// Bitwise XOR.
[<CompiledName("Xor")>]
let xor e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.TypeOf e1
#endif
#if ! HASHCONS
  binopWithType BinOpType.XOR t e2 e1
#else
  if e1 < e2 then binopWithType BinOpType.XOR t e1 e2
  else binopWithType BinOpType.XOR t e2 e1
#endif

/// Shift arithmetic right.
[<CompiledName("Sar")>]
let sar e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.TypeOf e1
#endif
  binopWithType BinOpType.SAR t e1 e2

/// Shift logical right.
[<CompiledName("Shr")>]
let shr e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.TypeOf e1
#endif
  binopWithType BinOpType.SHR t e1 e2

/// Shift logical left.
[<CompiledName("Shl")>]
let shl e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.TypeOf e1
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
    Expr.TypeOf e1
#endif
#if ! HASHCONS
  binopWithType BinOpType.FADD t e1 e2
#else
  if e1 < e2 then binopWithType BinOpType.FADD t e1 e2
  else binopWithType BinOpType.FADD t e2 e1
#endif

/// Floating point subtract two expressions.
[<CompiledName("FSub")>]
let fsub e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.TypeOf e1
#endif
  binopWithType BinOpType.FSUB t e1 e2

/// Floating point multiplication.
[<CompiledName("FMul")>]
let fmul e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.TypeOf e1
#endif
#if ! HASHCONS
  binopWithType BinOpType.FMUL t e1 e2
#else
  if e1 < e2 then binopWithType BinOpType.FMUL t e1 e2
  else binopWithType BinOpType.FMUL t e2 e1
#endif

/// Floating point division.
[<CompiledName("FDiv")>]
let fdiv e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.TypeOf e1
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
    Expr.TypeOf e1
#endif
  binopWithType BinOpType.FPOW t e1 e2

/// Floating point logarithm.
[<CompiledName("FLog")>]
let flog e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    Expr.TypeOf e1
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

/// An ISMark statement.
[<CompiledName("ISMark")>]
let ismark nBytes =
#if ! HASHCONS
  ISMark(nBytes, null)
#else
  let hc = HashConsingInfo()
  let s = ISMark(nBytes, hc)
  match tryGetStmt s with
  | Ok s -> s
  | Error isReclaimed ->
    hc.ID <- newSID ()
    hc.Hash <- Stmt.HashISMark nBytes
    if isReclaimed then stmts[s].SetTarget s
    else stmts[s] <- WeakReference<Stmt> s
    s
#endif

/// An IEMark statement.
[<CompiledName("IEMark")>]
let iemark nBytes =
#if ! HASHCONS
  IEMark(nBytes, null)
#else
  let hc = HashConsingInfo()
  let s = IEMark(nBytes, hc)
  match tryGetStmt s with
  | Ok s -> s
  | Error isReclaimed ->
    hc.ID <- newSID ()
    hc.Hash <- Stmt.HashIEMark nBytes
    if isReclaimed then stmts[s].SetTarget s
    else stmts[s] <- WeakReference<Stmt> s
    s
#endif

/// An LMark statement.
[<CompiledName("LMark")>]
let lmark label =
#if ! HASHCONS
  LMark(label, null)
#else
  let hc = HashConsingInfo()
  let s = LMark(label, hc)
  match tryGetStmt s with
  | Ok s -> s
  | Error isReclaimed ->
    hc.ID <- newSID ()
    hc.Hash <- Stmt.HashLMark label
    if isReclaimed then stmts[s].SetTarget s
    else stmts[s] <- WeakReference<Stmt> s
    s
#endif

/// A Put statement.
[<CompiledName("Put")>]
let put dst src =
#if ! HASHCONS
  Put(dst, src, null)
#else
  let hc = HashConsingInfo()
  let s = Put(dst, src, hc)
  match tryGetStmt s with
  | Ok s -> s
  | Error isReclaimed ->
    hc.ID <- newSID ()
    hc.Hash <- Stmt.HashPut dst src
    if isReclaimed then stmts[s].SetTarget s
    else stmts[s] <- WeakReference<Stmt> s
    s
#endif

let private assignForExtractDst e1 e2 =
  match e1 with
  | Extract(Var(t, _, _, _) as e1, eTyp, 0, _)
  | Extract(TempVar(t, _, _) as e1, eTyp, 0, _) ->
    let nMask = RegType.getMask t - RegType.getMask eTyp
    let mask = BitVector.OfBInt nMask t |> num
    let src = cast CastKind.ZeroExt t e2
    put e1 (binopWithType BinOpType.OR t
              (binopWithType BinOpType.AND t e1 mask) src)
  | Extract(Var(t, _, _, _) as e1, eTyp, pos, _)
  | Extract(TempVar(t, _, _) as e1, eTyp, pos, _) ->
    let nMask = RegType.getMask t - (RegType.getMask eTyp <<< pos)
    let mask = BitVector.OfBInt nMask t |> num
    let src = cast CastKind.ZeroExt t e2
    let shift = BitVector.OfInt32 pos t |> num
    let src = binopWithType BinOpType.SHL t src shift
    put e1 (binopWithType BinOpType.OR t
              (binopWithType BinOpType.AND t e1 mask) src)
  | e -> eprintfn "%A" e; raise InvalidAssignmentException

/// A Store statement.
[<CompiledName("Store")>]
let store endian addr v =
#if ! HASHCONS
  Store(endian, addr, v, null)
#else
  let hc = HashConsingInfo()
  let s = Store(endian, addr, v, hc)
  match tryGetStmt s with
  | Ok s -> s
  | Error isReclaimed ->
    hc.ID <- newSID ()
    hc.Hash <- Stmt.HashStore endian addr v
    if isReclaimed then stmts[s].SetTarget s
    else stmts[s] <- WeakReference<Stmt> s
    s
#endif

/// An assignment statement.
[<CompiledName("Assign")>]
let assign dst src =
#if DEBUG
  TypeCheck.checkEquivalence (Expr.TypeOf dst) (Expr.TypeOf src)
#endif
  match dst with
  | Var _ | TempVar _ | PCVar _ -> put dst src
  | Load(endian, _, e, _) -> store endian e src
  | Extract _ -> assignForExtractDst dst src
  | _ -> raise InvalidAssignmentException

/// A Jmp statement.
[<CompiledName("Jmp")>]
let jmp target =
#if ! HASHCONS
  Jmp(target, null)
#else
  let hc = HashConsingInfo()
  let s = Jmp(target, hc)
  match tryGetStmt s with
  | Ok s -> s
  | Error isReclaimed ->
    hc.ID <- newSID ()
    hc.Hash <- Stmt.HashJmp target
    if isReclaimed then stmts[s].SetTarget s
    else stmts[s] <- WeakReference<Stmt> s
    s
#endif

/// A CJmp statement.
[<CompiledName("CJmp")>]
let cjmp cond dst1 dst2 =
#if ! HASHCONS
  CJmp(cond, dst1, dst2, null)
#else
  let hc = HashConsingInfo()
  let s = CJmp(cond, dst1, dst2, hc)
  match tryGetStmt s with
  | Ok s -> s
  | Error isReclaimed ->
    hc.ID <- newSID ()
    hc.Hash <- Stmt.HashCJmp cond dst1 dst2
    if isReclaimed then stmts[s].SetTarget s
    else stmts[s] <- WeakReference<Stmt> s
    s
#endif

/// An InterJmp statement.
[<CompiledName("InterJmp")>]
let interjmp dst kind =
#if ! HASHCONS
  InterJmp(dst, kind, null)
#else
  let hc = HashConsingInfo()
  let s = InterJmp(dst, kind, hc)
  match tryGetStmt s with
  | Ok s -> s
  | Error isReclaimed ->
    hc.ID <- newSID ()
    hc.Hash <- Stmt.HashInterJmp dst kind
    if isReclaimed then stmts[s].SetTarget s
    else stmts[s] <- WeakReference<Stmt> s
    s
#endif

/// A InterCJmp statement.
[<CompiledName("InterCJmp")>]
let intercjmp cond d1 d2 =
#if ! HASHCONS
  InterCJmp(cond, d1, d2, null)
#else
  let hc = HashConsingInfo()
  let s = InterCJmp(cond, d1, d2, hc)
  match tryGetStmt s with
  | Ok s -> s
  | Error isReclaimed ->
    hc.ID <- newSID ()
    hc.Hash <- Stmt.HashInterCJmp cond d1 d2
    if isReclaimed then stmts[s].SetTarget s
    else stmts[s] <- WeakReference<Stmt> s
    s
#endif

/// External call.
[<CompiledName("ExtCall")>]
let extCall appExpr =
#if ! HASHCONS
  ExternalCall(appExpr, null)
#else
  let hc = HashConsingInfo()
  let s = ExternalCall(appExpr, hc)
  match tryGetStmt s with
  | Ok s -> s
  | Error isReclaimed ->
    hc.ID <- newSID ()
    hc.Hash <- Stmt.HashExtCall appExpr
    if isReclaimed then stmts[s].SetTarget s
    else stmts[s] <- WeakReference<Stmt> s
    s
#endif

/// A SideEffect statement.
[<CompiledName("SideEffect")>]
let sideEffect eff =
#if ! HASHCONS
  SideEffect(eff, null)
#else
  let hc = HashConsingInfo()
  let s = SideEffect(eff, hc)
  match tryGetStmt s with
  | Ok s -> s
  | Error isReclaimed ->
    hc.ID <- newSID ()
    hc.Hash <- Stmt.HashSideEffect eff
    if isReclaimed then stmts[s].SetTarget s
    else stmts[s] <- WeakReference<Stmt> s
    s
#endif

/// Record the use of vars and tempvars from the given expression.
let rec updateAllVarsUses (rset: RegisterSet) (tset: HashSet<int>) e =
  match e with
  | Num _ | PCVar _ | JmpDest _ | FuncName _ | Undefined _ ->
    ()
  | Var(_, rid, _, _) ->
    rset.Add(int rid)
  | TempVar(_, n, _) ->
    tset.Add n |> ignore
  | ExprList(exprs, _) ->
    for e in exprs do updateAllVarsUses rset tset e done
  | UnOp(_, e, _) ->
    updateAllVarsUses rset tset e
  | BinOp(_, _, lhs, rhs, _) ->
    updateAllVarsUses rset tset lhs
    updateAllVarsUses rset tset rhs
  | RelOp(_, lhs, rhs, _) ->
    updateAllVarsUses rset tset lhs
    updateAllVarsUses rset tset rhs
  | Load(_, _, e, _) ->
    updateAllVarsUses rset tset e
  | Ite(cond, e1, e2, _) ->
    updateAllVarsUses rset tset cond
    updateAllVarsUses rset tset e1
    updateAllVarsUses rset tset e2
  | Cast(_, _, e, _) ->
    updateAllVarsUses rset tset e
  | Extract(e, _, _, _) ->
    updateAllVarsUses rset tset e

/// Record the use of vars (registers) from the given expression.
let rec updateRegsUses (rset: RegisterSet) e =
  match e with
  | Num _ | PCVar _ | JmpDest _ | FuncName _ | Undefined _ | TempVar _ ->
    ()
  | Var(_, rid, _, _) ->
    rset.Add(int rid)
  | ExprList(exprs, _) ->
    for e in exprs do updateRegsUses rset e done
  | UnOp(_, e, _) ->
    updateRegsUses rset e
  | BinOp(_, _, lhs, rhs, _) ->
    updateRegsUses rset lhs
    updateRegsUses rset rhs
  | RelOp(_, lhs, rhs, _) ->
    updateRegsUses rset lhs
    updateRegsUses rset rhs
  | Load(_, _, e, _) ->
    updateRegsUses rset e
  | Ite(cond, e1, e2, _) ->
    updateRegsUses rset cond
    updateRegsUses rset e1
    updateRegsUses rset e2
  | Cast(_, _, e, _) ->
    updateRegsUses rset e
  | Extract(e, _, _, _) ->
    updateRegsUses rset e

/// Record the use of tempvars from the given expression.
let rec updateTempsUses (tset: HashSet<int>) e =
  match e with
  | Num _ | PCVar _ | JmpDest _ | FuncName _ | Undefined _ | Var _ ->
    ()
  | TempVar(_, n, _) ->
    tset.Add n |> ignore
  | ExprList(exprs, _) ->
    for e in exprs do updateTempsUses tset e done
  | UnOp(_, e, _) ->
    updateTempsUses tset e
  | BinOp(_, _, lhs, rhs, _) ->
    updateTempsUses tset lhs
    updateTempsUses tset rhs
  | RelOp(_, lhs, rhs, _) ->
    updateTempsUses tset lhs
    updateTempsUses tset rhs
  | Load(_, _, e, _) ->
    updateTempsUses tset e
  | Ite(cond, e1, e2, _) ->
    updateTempsUses tset cond
    updateTempsUses tset e1
    updateTempsUses tset e2
  | Cast(_, _, e, _) ->
    updateTempsUses tset e
  | Extract(e, _, _, _) ->
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
