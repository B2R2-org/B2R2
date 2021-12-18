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

/// LowUIR AST construction must be done through this module.
module B2R2.BinIR.LowUIR.AST

open B2R2
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
let private exprs = ConcurrentDictionary<E, WeakReference<Expr>> ()
let private stmts = ConcurrentDictionary<S, WeakReference<Stmt>> ()
let private newETag () = Threading.Interlocked.Increment eTagCnt
let private newSTag () = Threading.Interlocked.Increment sTagCnt

let inline private tryGetExpr (k: E) =
  match exprs.TryGetValue k with
  | true, e ->
    match e.TryGetTarget () with
    | true, e -> Ok e
    | false, _ -> Error true
  | _ -> Error false

let inline private tryGetStmt (k: S) =
  match stmts.TryGetValue k with
  | true, s ->
    match s.TryGetTarget () with
    | true, s -> Ok s
    | false, _ -> Error true
  | _ -> Error false
#endif

/// Get the expression info from the given expression (Expr).
[<CompiledName("GetExprInfo")>]
let getExprInfo e = ASTHelper.getExprInfo e

/// Construct a number (Num).
[<CompiledName("Num")>]
let num bv =
#if ! HASHCONS
  Num (bv) |> ASTHelper.buildExpr
#else
  let k = Num bv
  match tryGetExpr k with
  | Ok e -> e
  | Error isReclaimed ->
    let e' = { E = k; Tag = newETag (); HashKey = bv.GetHashCode () }
    if isReclaimed then exprs[k].SetTarget e'
    else exprs[k] <- WeakReference<Expr> e'
    e'
#endif

/// Construct a variable (Var).
[<CompiledName("Var")>]
let var t id name rs =
#if ! HASHCONS
  Var (t, id, name, rs) |> ASTHelper.buildExpr
#else
  let k = Var (t, id, name, rs)
  match tryGetExpr k with
  | Ok e -> e
  | Error isReclaimed ->
    let e' = { E = k; Tag = newETag (); HashKey = E.HashVar t id }
    if isReclaimed then exprs[k].SetTarget e'
    else exprs[k] <- WeakReference<Expr> e'
    e'
#endif

/// Construct a pc variable (PCVar).
[<CompiledName("PCVar")>]
let pcvar t name =
#if ! HASHCONS
  PCVar (t, name) |> ASTHelper.buildExpr
#else
  let k = PCVar (t, name)
  match tryGetExpr k with
  | Ok e -> e
  | Error isReclaimed ->
    let e' = { E = k; Tag = newETag (); HashKey = E.HashPCVar t }
    if isReclaimed then exprs[k].SetTarget e'
    else exprs[k] <- WeakReference<Expr> e'
    e'
#endif

/// Construct a temporary variable (TempVar) with the given ID.
[<CompiledName("TmpVar")>]
let tmpvar t id =
#if ! HASHCONS
  TempVar (t, id) |> ASTHelper.buildExpr
#else
  let k = TempVar (t, id)
  match tryGetExpr k with
  | Ok e -> e
  | Error isReclaimed ->
    let e' = { E = k; Tag = newETag (); HashKey = E.HashTempVar t id }
    if isReclaimed then exprs[k].SetTarget e'
    else exprs[k] <- WeakReference<Expr> e'
    e'
#endif

/// Construct a symbol (for a label) from a string and a IDCounter.
[<CompiledName("Symbol")>]
let inline symbol name id =
  Symbol (name, id)

/// Construct an unary operator (UnOp).
[<CompiledName("UnOp")>]
let unop op e =
  match e.E with
  | Num n -> ValueOptimizer.unop n op |> num
#if ! HASHCONS
  | _ -> UnOp (op, e, getExprInfo e) |> ASTHelper.buildExpr
#else
  | _ ->
    let k = UnOp (op, e, getExprInfo e)
    match tryGetExpr k with
    | Ok e -> e
    | Error isReclaimed ->
      let e' = { E = k; Tag = newETag (); HashKey = E.HashUnOp op e }
      if isReclaimed then exprs[k].SetTarget e'
      else exprs[k] <- WeakReference<Expr> e'
      e'
#endif

/// Construct a symbolic name (Name).
[<CompiledName("Name")>]
let name symb =
#if ! HASHCONS
  Name symb |> ASTHelper.buildExpr
#else
  let k = Name symb
  match tryGetExpr k with
  | Ok e -> e
  | Error isReclaimed ->
    let e' = { E = k; Tag = newETag (); HashKey = E.HashName symb }
    if isReclaimed then exprs[k].SetTarget e'
    else exprs[k] <- WeakReference<Expr> e'
    e'
#endif

let inline private (===) e1 e2 =
  LanguagePrimitives.PhysicalEquality e1.E e2.E

let binopWithType op t e1 e2 =
  match op, e1.E, e2.E with
  | _, Num n1, Num n2 -> ValueOptimizer.binop n1 n2 op |> num
  | BinOpType.XOR, _, _ when e1 === e2 -> BitVector.zero t |> num
#if ! HASHCONS
  | _ ->
    BinOp (op, t, e1, e2, ASTHelper.mergeTwoExprInfo e1 e2)
    |> ASTHelper.buildExpr
#else
  | _ ->
    let k = BinOp (op, t, e1, e2, ASTHelper.mergeTwoExprInfo e1 e2)
    match tryGetExpr k with
    | Ok e -> e
    | Error isReclaimed ->
      let e' = { E = k; Tag = newETag (); HashKey = E.HashBinOp op t e1 e2 }
      if isReclaimed then exprs[k].SetTarget e'
      else exprs[k] <- WeakReference<Expr> e'
      e'
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
      TypeCheck.typeOf e1
#endif
  binopWithType op t e1 e2

/// Consing two expr.
[<CompiledName("Cons")>]
let cons a b =
  match b.E with
  | Nil ->
    let t = TypeCheck.typeOf a
#if ! HASHCONS
    BinOp (BinOpType.CONS, t, a, b, ASTHelper.getExprInfo a)
    |> ASTHelper.buildExpr
#else
    let k = BinOp (BinOpType.CONS, t, a, b, ASTHelper.getExprInfo a)
    match tryGetExpr k with
    | Ok e -> e
    | Error isReclaimed ->
      let e' = { E = k; Tag = newETag ()
                 HashKey = E.HashBinOp BinOpType.CONS t a b }
      if isReclaimed then exprs[k].SetTarget e'
      else exprs[k] <- WeakReference<Expr> e'
      e'
#endif
  | _ -> binop BinOpType.CONS a b

/// Nil.
[<CompiledName("Nil")>]
let nil =
#if ! HASHCONS
  Nil |> ASTHelper.buildExpr
#else
  { E = Nil; Tag = newETag (); HashKey = 0 }
#endif

/// Function name.
[<CompiledName("FuncName")>]
let funcName name =
#if ! HASHCONS
  FuncName (name) |> ASTHelper.buildExpr
#else
  let k = FuncName (name)
  match tryGetExpr k with
  | Ok e -> e
  | Error isReclaimed ->
    let e' = { E = k; Tag = newETag (); HashKey = E.HashFuncName name }
    if isReclaimed then exprs[k].SetTarget e'
    else exprs[k] <- WeakReference<Expr> e'
    e'
#endif

/// Construct a function application.
[<CompiledName("App")>]
let app name args retType =
  let funName = funcName name
  List.reduceBack cons (args @ [ nil ])
#if ! HASHCONS
  |> fun cons ->
    BinOp (BinOpType.APP, retType, funName, cons, getExprInfo cons)
    |> ASTHelper.buildExpr
#else
  |> fun cons ->
    let k = BinOp (BinOpType.APP, retType, funName, cons, getExprInfo cons)
    match tryGetExpr k with
    | Ok e -> e
    | Error isReclaimed ->
      let e' = { E = k; Tag = newETag ()
                 HashKey = E.HashBinOp BinOpType.APP retType funName cons }
      if isReclaimed then exprs[k].SetTarget e'
      else exprs[k] <- WeakReference<Expr> e'
      e'
#endif

/// Construct a relative operator (RelOp).
[<CompiledName("RelOp")>]
let relop op e1 e2 =
#if DEBUG
  TypeCheck.binop e1 e2 |> ignore
#endif
  match e1.E, e2.E with
  | Num n1, Num n2 -> ValueOptimizer.relop n1 n2 op |> num
#if ! HASHCONS
  | _ ->
    RelOp (op, e1, e2, ASTHelper.mergeTwoExprInfo e1 e2)|> ASTHelper.buildExpr
#else
  | _ ->
    let k = RelOp (op, e1, e2, ASTHelper.mergeTwoExprInfo e1 e2)
    match tryGetExpr k with
    | Ok e -> e
    | Error isReclaimed ->
      let e' = { E = k; Tag = newETag (); HashKey = E.HashRelOp op e1 e2 }
      if isReclaimed then exprs[k].SetTarget e'
      else exprs[k] <- WeakReference<Expr> e'
      e'
#endif

/// Construct a load expression (Load).
[<CompiledName("Load")>]
let load endian rt addr =
#if DEBUG
  match addr.E with
  | Name _ -> raise InvalidExprException
  | _ ->
#endif
#if ! HASHCONS
    Load (endian, rt, addr, { getExprInfo addr with HasLoad = true })
    |> ASTHelper.buildExpr
#else
    let k = Load (endian, rt, addr, { getExprInfo addr with HasLoad = true })
    match tryGetExpr k with
    | Ok e -> e
    | Error isReclaimed ->
      let e' = { E = k; Tag = newETag (); HashKey = E.HashLoad endian rt addr }
      if isReclaimed then exprs[k].SetTarget e'
      else exprs[k] <- WeakReference<Expr> e'
      e'
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
  TypeCheck.checkEquivalence (TypeCheck.typeOf e1) (TypeCheck.typeOf e2)
#endif
  match cond.E with
  | Num (n) -> if BitVector.isOne n then e1 else e2 (* Assume valid cond *)
  | _ ->
#if ! HASHCONS
    Ite (cond, e1, e2, ASTHelper.mergeThreeExprInfo cond e1 e2)
    |> ASTHelper.buildExpr
#else
    let k = Ite (cond, e1, e2, ASTHelper.mergeThreeExprInfo cond e1 e2)
    match tryGetExpr k with
    | Ok e -> e
    | Error isReclaimed ->
      let e' = { E = k; Tag = newETag (); HashKey = E.HashIte cond e1 e2 }
      if isReclaimed then exprs[k].SetTarget e'
      else exprs[k] <- WeakReference<Expr> e'
      e'
#endif


/// Construct a cast expression (Cast).
[<CompiledName("Cast")>]
let cast kind rt e =
  match e.E with
  | Num n -> ValueOptimizer.cast rt n kind |> num
  | _ ->
    if TypeCheck.canCast kind rt e then
#if ! HASHCONS
      Cast (kind, rt, e, getExprInfo e) |> ASTHelper.buildExpr
#else
      let k = Cast (kind, rt, e, getExprInfo e)
      match tryGetExpr k with
      | Ok e -> e
      | Error isReclaimed ->
        let e' = { E = k; Tag = newETag (); HashKey = E.HashCast kind rt e }
        if isReclaimed then exprs[k].SetTarget e'
        else exprs[k] <- WeakReference<Expr> e'
        e'
#endif
    else e (* Remove unnecessary casting . *)

/// Construct a extract expression (Extract).
[<CompiledName("Extract")>]
let extract expr rt pos =
  TypeCheck.extract rt pos (TypeCheck.typeOf expr)
  match expr.E with
  | Num n -> ValueOptimizer.extract n rt pos |> num
  | Extract (e, _, p, ei) ->
    let pos = p + pos
#if ! HASHCONS
    Extract (e, rt, pos, ei) |> ASTHelper.buildExpr
#else
    let k = Extract (e, rt, pos, ei)
    match tryGetExpr k with
    | Ok e -> e
    | Error isReclaimed ->
      let e' = { E = k; Tag = newETag (); HashKey = E.HashExtract e rt pos }
      if isReclaimed then exprs[k].SetTarget e'
      else exprs[k] <- WeakReference<Expr> e'
      e'
#endif
  | _ ->
#if ! HASHCONS
    Extract (expr, rt, pos, getExprInfo expr) |> ASTHelper.buildExpr
#else
    let k = Extract (expr, rt, pos, getExprInfo expr)
    match tryGetExpr k with
    | Ok e -> e
    | Error isReclaimed ->
      let e' = { E = k; Tag = newETag (); HashKey = E.HashExtract expr rt pos }
      if isReclaimed then exprs[k].SetTarget e'
      else exprs[k] <- WeakReference<Expr> e'
      e'
#endif

/// Undefined expression.
[<CompiledName("Undef")>]
let undef rt s =
#if ! HASHCONS
  Undefined (rt, s) |> ASTHelper.buildExpr
#else
  let k = Undefined (rt, s)
  match tryGetExpr k with
  | Ok e -> e
  | Error isReclaimed ->
    let e' = { E = k; Tag = newETag (); HashKey = E.HashUndef rt s }
    if isReclaimed then exprs[k].SetTarget e'
    else exprs[k] <- WeakReference<Expr> e'
    e'
#endif

/// Construct a (Num 0) of size t.
[<CompiledName("Num0")>]
let num0 rt = num (BitVector.zero rt)

/// Construct a (Num 1) of size t.
[<CompiledName("Num1")>]
let num1 rt = num (BitVector.one rt)

/// Num expression for a one-bit number zero.
[<CompiledName("B0")>]
let b0 = num (BitVector.zero 1<rt>)

/// Num expression for a one-bit number one.
[<CompiledName("B1")>]
let b1 = num (BitVector.one 1<rt>)

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
  else Utils.impossible ()

/// Concatenate an array of expressions.
[<CompiledName("Concat")>]
let concatArr (arr: Expr[]) =
  concatLoop arr 0 (Array.length arr - 1)

/// Unwrap (casted) expression.
[<CompiledName("Unwrap")>]
let rec unwrap e =
  match e.E with
  | Cast (_, _, e, _)
  | Extract (e, _, _, _) -> unwrap e
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
  extract expr addrSize (int (TypeCheck.typeOf expr - addrSize))

/// Add two expressions.
[<CompiledName("Add")>]
let add e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
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
    TypeCheck.typeOf e1
#endif
  binopWithType BinOpType.SUB t e1 e2

/// Multiply two expressions.
[<CompiledName("Mul")>]
let mul e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
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
    TypeCheck.typeOf e1
#endif
  binopWithType BinOpType.DIV t e1 e2

/// Signed division.
[<CompiledName("SDiv")>]
let sdiv e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
#endif
  binopWithType BinOpType.SDIV t e1 e2

/// Unsigned modulus.
[<CompiledName("Mod")>]
let ``mod`` e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
#endif
  binopWithType BinOpType.MOD t e1 e2

/// Signed modulus.
[<CompiledName("SMod")>]
let smod e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
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
    TypeCheck.typeOf e1
#endif
  binopWithType BinOpType.AND t e1 e2

/// Bitwise OR.
[<CompiledName("Or")>]
let ``or`` e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
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
    TypeCheck.typeOf e1
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
    TypeCheck.typeOf e1
#endif
  binopWithType BinOpType.SAR t e1 e2

/// Shift logical right.
[<CompiledName("Shr")>]
let shr e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
#endif
  binopWithType BinOpType.SHR t e1 e2

/// Shift logical left.
[<CompiledName("Shl")>]
let shl e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
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
    TypeCheck.typeOf e1
#endif
#if ! HASHCONS
  binopWithType BinOpType.FADD t e2 e1
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
    TypeCheck.typeOf e1
#endif
  binopWithType BinOpType.FSUB t e1 e2

/// Floating point multiplication.
[<CompiledName("FMul")>]
let fmul e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
#endif
#if ! HASHCONS
  binopWithType BinOpType.FMUL t e2 e1
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
    TypeCheck.typeOf e1
#endif
  binopWithType BinOpType.FDIV t e1 e2

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
    TypeCheck.typeOf e1
#endif
  binopWithType BinOpType.FPOW t e1 e2

/// Floating point logarithm.
[<CompiledName("FLog")>]
let flog e1 e2 =
  let t =
#if DEBUG
    TypeCheck.binop e1 e2
#else
    TypeCheck.typeOf e1
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
  ISMark nBytes |> ASTHelper.buildStmt
#else
  let k = ISMark nBytes
  match tryGetStmt k with
  | Ok s -> s
  | Error isReclaimed ->
    let s' = { S = k; Tag = newSTag (); HashKey = S.HashISMark nBytes }
    if isReclaimed then stmts[k].SetTarget s'
    else stmts[k] <- WeakReference<Stmt> s'
    s'
#endif

/// An IEMark statement.
[<CompiledName("IEMark")>]
let iemark nBytes =
#if ! HASHCONS
  IEMark nBytes |> ASTHelper.buildStmt
#else
  let k = IEMark nBytes
  match tryGetStmt k with
  | Ok s -> s
  | Error isReclaimed ->
    let s' = { S = k; Tag = newSTag (); HashKey = S.HashIEMark nBytes }
    if isReclaimed then stmts[k].SetTarget s'
    else stmts[k] <- WeakReference<Stmt> s'
    s'
#endif

/// An LMark statement.
[<CompiledName("LMark")>]
let lmark s =
#if ! HASHCONS
  LMark s |> ASTHelper.buildStmt
#else
  let k = LMark s
  match tryGetStmt k with
  | Ok s -> s
  | Error isReclaimed ->
    let s' = { S = k; Tag = newSTag (); HashKey = S.HashLMark s }
    if isReclaimed then stmts[k].SetTarget s'
    else stmts[k] <- WeakReference<Stmt> s'
    s'
#endif

/// A Put statement.
[<CompiledName("Put")>]
let put dst src =
#if ! HASHCONS
  Put (dst, src) |> ASTHelper.buildStmt
#else
  let k = Put (dst, src)
  match tryGetStmt k with
  | Ok s -> s
  | Error isReclaimed ->
    let s' = { S = k; Tag = newSTag (); HashKey = S.HashPut dst src }
    if isReclaimed then stmts[k].SetTarget s'
    else stmts[k] <- WeakReference<Stmt> s'
    s'
#endif

let assignForExtractDst e1 e2 =
  match e1.E with
  | Extract ({ E = Var (t, _, _, _) } as e1, eTyp, 0, _)
  | Extract ({ E = TempVar (t, _) } as e1, eTyp, 0, _)->
    let nMask = RegType.getMask t - RegType.getMask eTyp
    let mask = BitVector.ofBInt nMask t |> num
    let src = cast CastKind.ZeroExt t e2
    put e1 (binopWithType BinOpType.OR t
              (binopWithType BinOpType.AND t e1 mask) src)
  | Extract ({ E = Var (t, _, _, _) } as e1, eTyp, pos, _)
  | Extract ({ E = TempVar (t, _) } as e1, eTyp, pos, _) ->
    let nMask = RegType.getMask t - (RegType.getMask eTyp <<< pos)
    let mask = BitVector.ofBInt nMask t |> num
    let src = cast CastKind.ZeroExt t e2
    let shift = BitVector.ofInt32 pos t |> num
    let src = binopWithType BinOpType.SHL t src shift
    put e1 (binopWithType BinOpType.OR t
              (binopWithType BinOpType.AND t e1 mask) src)
  | e -> printfn "%A" e; raise InvalidAssignmentException

/// A Store statement.
[<CompiledName("Store")>]
let store endian addr v =
#if ! HASHCONS
  Store (endian, addr, v) |> ASTHelper.buildStmt
#else
  let k = Store (endian, addr, v)
  match tryGetStmt k with
  | Ok s -> s
  | Error isReclaimed ->
    let s' = { S = k; Tag = newSTag (); HashKey = S.HashStore endian addr v }
    if isReclaimed then stmts[k].SetTarget s'
    else stmts[k] <- WeakReference<Stmt> s'
    s'
#endif

/// An assignment statement.
[<CompiledName("Assign")>]
let assign dst src =
#if DEBUG
  TypeCheck.checkEquivalence (TypeCheck.typeOf dst) (TypeCheck.typeOf src)
#endif
  match dst.E with
  | Var _ | TempVar _ | PCVar _ -> put dst src
  | Load (_, _, e, _) -> store Endian.Little e src
  | Extract (_) -> assignForExtractDst dst src
  | _ -> raise InvalidAssignmentException

/// A Jmp statement.
[<CompiledName("Jmp")>]
let jmp target =
#if ! HASHCONS
  Jmp (target) |> ASTHelper.buildStmt
#else
  let k = Jmp (target)
  match tryGetStmt k with
  | Ok s -> s
  | Error isReclaimed ->
    let s' = { S = k; Tag = newSTag (); HashKey = S.HashJmp target }
    if isReclaimed then stmts[k].SetTarget s'
    else stmts[k] <- WeakReference<Stmt> s'
    s'
#endif

/// A CJmp statement.
[<CompiledName("CJmp")>]
let cjmp cond dst1 dst2 =
#if ! HASHCONS
  CJmp (cond, dst1, dst2) |> ASTHelper.buildStmt
#else
  let k = CJmp (cond, dst1, dst2)
  match tryGetStmt k with
  | Ok s -> s
  | Error isReclaimed ->
    let s' = { S = k; Tag = newSTag (); HashKey = S.HashCJmp cond dst1 dst2 }
    if isReclaimed then stmts[k].SetTarget s'
    else stmts[k] <- WeakReference<Stmt> s'
    s'
#endif

/// An InterJmp statement.
[<CompiledName("InterJmp")>]
let interjmp dst kind =
#if ! HASHCONS
  InterJmp (dst, kind) |> ASTHelper.buildStmt
#else
  let k = InterJmp (dst, kind)
  match tryGetStmt k with
  | Ok s -> s
  | Error isReclaimed ->
    let s' = { S = k; Tag = newSTag (); HashKey = S.HashInterJmp dst kind }
    if isReclaimed then stmts[k].SetTarget s'
    else stmts[k] <- WeakReference<Stmt> s'
    s'
#endif

/// A InterCJmp statement.
[<CompiledName("InterCJmp")>]
let intercjmp cond d1 d2 =
#if ! HASHCONS
  InterCJmp (cond, d1, d2) |> ASTHelper.buildStmt
#else
  let k = InterCJmp (cond, d1, d2)
  match tryGetStmt k with
  | Ok s -> s
  | Error isReclaimed ->
    let s' = { S = k; Tag = newSTag (); HashKey = S.HashInterCJmp cond d1 d2 }
    if isReclaimed then stmts[k].SetTarget s'
    else stmts[k] <- WeakReference<Stmt> s'
    s'
#endif

/// A SideEffect statement.
[<CompiledName("SideEffect")>]
let sideEffect eff =
#if ! HASHCONS
  SideEffect eff |> ASTHelper.buildStmt
#else
  let k = SideEffect eff
  match tryGetStmt k with
  | Ok s -> s
  | Error isReclaimed ->
    let s' = { S = k; Tag = newSTag (); HashKey = S.HashSideEffect eff }
    if isReclaimed then stmts[k].SetTarget s'
    else stmts[k] <- WeakReference<Stmt> s'
    s'
#endif

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

  /// Signed less than.
  let inline (.<) e1 e2 = lt e1 e2

  /// Signed less than or equal.
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
