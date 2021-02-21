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

namespace B2R2.BinIR.LowUIR

open B2R2
open B2R2.BinIR

/// Concrete value optimization.
[<RequireQualifiedAccess>]
module private ValueOptimizer =
  let inline unop n = function
    | UnOpType.NEG -> BitVector.neg n |> Num
    | UnOpType.NOT -> BitVector.bnot n |> Num
    | UnOpType.FSQRT -> BitVector.fsqrt n |> Num
    | UnOpType.FCOS -> BitVector.fcos n |> Num
    | UnOpType.FSIN -> BitVector.fsin n |> Num
    | UnOpType.FTAN -> BitVector.ftan n |> Num
    | UnOpType.FATAN -> BitVector.fatan n |> Num
    | _ -> Utils.impossible ()

  let inline binop n1 n2 = function
    | BinOpType.ADD  -> BitVector.add n1 n2 |> Num
    | BinOpType.SUB  -> BitVector.sub n1 n2 |> Num
    | BinOpType.MUL  -> BitVector.mul n1 n2 |> Num
    | BinOpType.DIV  -> BitVector.div n1 n2 |> Num
    | BinOpType.SDIV -> BitVector.sdiv n1 n2 |> Num
    | BinOpType.MOD  -> BitVector.modulo n1 n2 |> Num
    | BinOpType.SMOD -> BitVector.smodulo n1 n2 |> Num
    | BinOpType.SHL  -> BitVector.shl n1 n2 |> Num
    | BinOpType.SAR  -> BitVector.sar n1 n2 |> Num
    | BinOpType.SHR  -> BitVector.shr n1 n2 |> Num
    | BinOpType.AND  -> BitVector.band n1 n2 |> Num
    | BinOpType.OR   -> BitVector.bor n1 n2 |> Num
    | BinOpType.XOR  -> BitVector.bxor n1 n2 |> Num
    | BinOpType.CONCAT -> BitVector.concat n1 n2 |> Num
    | BinOpType.FADD -> BitVector.fadd n1 n2 |> Num
    | BinOpType.FSUB -> BitVector.fsub n1 n2 |> Num
    | BinOpType.FMUL -> BitVector.fmul n1 n2 |> Num
    | BinOpType.FDIV -> BitVector.fdiv n1 n2 |> Num
    | BinOpType.FPOW -> BitVector.fpow n1 n2 |> Num
    | BinOpType.FLOG -> BitVector.flog n1 n2 |> Num
    | _ -> Utils.impossible ()

  let inline relop n1 n2 = function
    | RelOpType.EQ  -> BitVector.eq n1 n2 |> Num
    | RelOpType.NEQ -> BitVector.neq n1 n2 |> Num
    | RelOpType.GT  -> BitVector.gt n1 n2 |> Num
    | RelOpType.GE  -> BitVector.ge n1 n2 |> Num
    | RelOpType.SGT -> BitVector.sgt n1 n2 |> Num
    | RelOpType.SGE -> BitVector.sge n1 n2 |> Num
    | RelOpType.LT  -> BitVector.lt n1 n2 |> Num
    | RelOpType.LE  -> BitVector.le n1 n2 |> Num
    | RelOpType.SLT -> BitVector.slt n1 n2 |> Num
    | RelOpType.SLE -> BitVector.sle n1 n2 |> Num
    | RelOpType.FLT -> BitVector.flt n1 n2 |> Num
    | RelOpType.FLE -> BitVector.fle n1 n2 |> Num
    | RelOpType.FGT -> BitVector.fgt n1 n2 |> Num
    | RelOpType.FGE -> BitVector.fge n1 n2 |> Num
    | _ -> Utils.impossible ()

  let inline cast t n = function
    | CastKind.SignExt -> BitVector.sext n t |> Num
    | CastKind.ZeroExt -> BitVector.zext n t |> Num
    | CastKind.FloatCast -> BitVector.fcast n t |> Num
    | CastKind.IntToFloat -> BitVector.itof n t |> Num
    | CastKind.FtoICeil -> BitVector.ftoiceil n t |> Num
    | CastKind.FtoIFloor -> BitVector.ftoifloor n t |> Num
    | CastKind.FtoIRound -> BitVector.ftoiround n t |> Num
    | CastKind.FtoITrunc -> BitVector.ftoitrunc n t |> Num
    | _ -> Utils.impossible ()

  let inline extract e t pos = BitVector.extract e t pos |> Num

[<RequireQualifiedAccess>]
module internal ASTHelper =
  let emptyExprInfo =
    { HasLoad = false
      VarsUsed = RegisterSet.empty
      TempVarsUsed = Set.empty }

  let getExprInfo e =
    match e.E with
    | Num _ | PCVar _ | Nil | Name _ | FuncName _ | Undefined _ -> emptyExprInfo
    | Var (_, _, _, rset) ->
      { HasLoad = false; VarsUsed = rset; TempVarsUsed = Set.empty }
    | TempVar (_, name) ->
      { HasLoad = false
        VarsUsed = RegisterSet.empty
        TempVarsUsed = Set.singleton name }
    | UnOp (_, _, ei)
    | BinOp (_, _, _, _, ei)
    | RelOp (_, _, _, ei)
    | Load (_, _, _, ei)
    | Ite (_, _, _, ei)
    | Cast (_, _, _, ei)
    | Extract (_, _, _, ei) -> ei

  let private mergeTwoExprInfo e1 e2 =
    let ei1 = getExprInfo e1
    let ei2 = getExprInfo e2
    { HasLoad = ei1.HasLoad || ei2.HasLoad
      VarsUsed = RegisterSet.union ei1.VarsUsed ei2.VarsUsed
      TempVarsUsed = Set.union ei1.TempVarsUsed ei2.TempVarsUsed }

  let private mergeThreeExprInfo e1 e2 e3 =
    let ei1 = getExprInfo e1
    let ei2 = getExprInfo e2
    let ei3 = getExprInfo e3
    let vars =
      RegisterSet.union ei1.VarsUsed ei2.VarsUsed
      |> RegisterSet.union ei3.VarsUsed
    let tmps =
      Set.union ei1.TempVarsUsed ei2.TempVarsUsed
      |> Set.union ei3.TempVarsUsed
    { HasLoad = ei1.HasLoad || ei2.HasLoad || ei3.HasLoad
      VarsUsed = vars
      TempVarsUsed = tmps }

  let inline buildExpr e =
    { E = e }

  let inline buildStmt s =
    { S = s }

  let inline (===) e1 e2 =
    LanguagePrimitives.PhysicalEquality e1.E e2.E
    // LanguagePrimitives.PhysicalEquality<Expr> e1 e2

  let inline unop (t: UnOpType) e =
    match e.E with
    | Num n -> ValueOptimizer.unop n t
    | _ -> UnOp (t, e, getExprInfo e)
    |> buildExpr

  let inline binop op t e1 e2 =
    match op, e1.E, e2.E with
    | _, Num n1, Num n2 -> ValueOptimizer.binop n1 n2 op
    | BinOpType.XOR, _, _ when e1 === e2 -> BitVector.zero t |> Num
    (* TODO: add more cases for optimization *)
    | _ -> BinOp (op, t, e1, e2, mergeTwoExprInfo e1 e2)
    |> buildExpr

  let inline cons a b =
    match b.E with
    | Nil ->
      BinOp (BinOpType.CONS, TypeCheck.typeOf a, a, b, getExprInfo a)
      |> buildExpr
    | _ ->
      let t = TypeCheck.binop a b
      BinOp (BinOpType.CONS, t, a, b, mergeTwoExprInfo a b)
      |> buildExpr

  let inline app name args retType =
    let funName = { E = FuncName (name) }
    List.reduceBack cons (args @ [ { E = Nil } ])
    |> fun cons ->
      BinOp (BinOpType.APP, retType, funName, cons, getExprInfo cons)
      |> buildExpr

  let inline relop (op: RelOpType) e1 e2 =
#if DEBUG
    TypeCheck.binop e1 e2 |> ignore
#endif
    match e1.E, e2.E with
    | Num n1, Num n2 -> ValueOptimizer.relop n1 n2 op
    | _ -> RelOp (op, e1, e2, mergeTwoExprInfo e1 e2)
    |> buildExpr

  let inline load (e: Endian) (t: RegType) addr =
#if DEBUG
    match addr.E with
    | Name _ -> raise InvalidExprException
    | _ ->
      Load (e, t, addr, { getExprInfo addr with HasLoad = true })
      |> buildExpr
#else
    Load (e, t, addr, { getExprInfo addr with HasLoad = true })
    |> buildExpr
#endif

  let inline ite cond e1 e2 =
#if DEBUG
    TypeCheck.bool cond
    TypeCheck.checkEquivalence (TypeCheck.typeOf e1) (TypeCheck.typeOf e2)
#endif
    match cond.E with
    | Num (n) -> if BitVector.isOne n then e1 else e2 (* Assume valid cond *)
    | _ -> Ite (cond, e1, e2, mergeThreeExprInfo cond e1 e2) |> buildExpr

  let inline cast kind (t: RegType) (e: Expr) =
    match e.E with
    | Num n -> ValueOptimizer.cast t n kind |> buildExpr
    | _ ->
      if TypeCheck.canCast kind t e then
        Cast (kind, t, e, getExprInfo e) |> buildExpr
      else e (* Remove unnecessary casting . *)

  let inline extract (expr: Expr) (t: RegType) (pos: StartPos) =
    TypeCheck.extract t pos (TypeCheck.typeOf expr)
    match expr.E with
    | Num n -> ValueOptimizer.extract n t pos
    | Extract (e, _, p, ei) -> Extract (e, t, p + pos, ei)
    | _ -> Extract (expr, t, pos, getExprInfo expr)
    |> buildExpr

  let inline concat e1 e2 =
    let t = TypeCheck.concat e1 e2
    binop BinOpType.CONCAT t e1 e2

  let rec concatLoop (arr: Expr []) sPos ePos =
    let diff = ePos - sPos
    if diff > 0 then concat (concatLoop arr (sPos + diff / 2 + 1) ePos)
                            (concatLoop arr sPos (sPos + diff / 2))
    elif diff = 0 then arr.[sPos]
    else Utils.impossible ()

  let inline concatArr (arr: Expr []) =
    concatLoop arr 0 (Array.length arr - 1)

  let rec unwrap { E = node } =
    match node with
    | Cast (_, _, e, _)
    | Extract (e, _, _, _) -> unwrap e
    | e -> e |> buildExpr

  let assignForExtractDst e1 e2 =
    match e1.E with
    | Extract ({ E = Var (t, _, _, _) } as e1, eTyp, 0, _)
    | Extract ({ E = TempVar (t, _) } as e1, eTyp, 0, _)->
      let nMask = RegType.getMask t - RegType.getMask eTyp
      let mask = Num (BitVector.ofBInt nMask t) |> buildExpr
      let src = cast CastKind.ZeroExt t e2
      Put (e1, binop BinOpType.OR t (binop BinOpType.AND t e1 mask) src)
      |> buildStmt
    | Extract ({ E = Var (t, _, _, _) } as e1, eTyp, pos, _)
    | Extract ({ E = TempVar (t, _) } as e1, eTyp, pos, _) ->
      let nMask = RegType.getMask t - (RegType.getMask eTyp <<< pos)
      let mask = Num (BitVector.ofBInt nMask t) |> buildExpr
      let src = cast CastKind.ZeroExt t e2
      let shift = Num (BitVector.ofInt32 pos t) |> buildExpr
      let src = binop BinOpType.SHL t src shift
      Put (e1, binop BinOpType.OR t (binop BinOpType.AND t e1 mask) src)
      |> buildStmt
    | e -> printfn "%A" e; raise InvalidAssignmentException

  let inline assign e1 e2 =
#if DEBUG
    TypeCheck.checkEquivalence (TypeCheck.typeOf e1) (TypeCheck.typeOf e2)
#endif
    match e1.E with
    | Var _ | TempVar _ | PCVar _ -> Put (e1, e2) |> buildStmt
    | Load (_, _, e, _) -> Store (Endian.Little, e, e2) |> buildStmt
    | Extract (_) -> assignForExtractDst e1 e2
    | _ -> raise InvalidAssignmentException
