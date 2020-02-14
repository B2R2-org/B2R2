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

module TypeCheck =

  let rec typeOf = function
    | Num n -> BitVector.getType n
    | Var (t, _, _, _)
    | PCVar (t, _)
    | TempVar (t, _) -> t
    | UnOp (_, e, _, _) -> typeOf e
    | BinOp (_, t, _, _, _, _) -> t
    | RelOp (_) -> 1<rt>
    | Load (_, t, _, _, _) -> t
    | Ite (_, e1, _e2, _, _) -> typeOf e1
    | Cast (_, t, _, _, _) -> t
    | Extract (_, t, _, _, _) -> t
    | Undefined (t, _) -> t
    | FuncName (_) | Name (_) | Nil -> raise InvalidExprException

  let concatType e1 e2 =
    let t1 = typeOf e1
    let t2 = typeOf e2
    if t1 <> t2 then raise <| TypeCheckException "Invalid concatenation."
    else 2 * t1

  let checkTypeIsBool e =
    let t = typeOf e
    if t <> 1<rt> then
      raise <| TypeCheckException (Pp.expToString e + "must be boolean.")

  let checkTypeIsEquivalent t1 t2 =
    if t1 = t2 then ()
    else raise <| TypeCheckException "Inconsistent types."

  let getCommonType e1 e2 =
    let t1 = typeOf e1
    let t2 = typeOf e2
    checkTypeIsEquivalent t1 t2
    t1

  let castErr (newType: RegType) (oldType: RegType) =
    let errMsg =
      "Cannot cast from " + oldType.ToString () + " to " + newType.ToString ()
    raise <| TypeCheckException errMsg

  let isFloatValid = function
  | 32<rt> | 64<rt> | 80<rt> -> true
  | _ -> false

  let isCastingValid kind newType e =
    let oldType = typeOf e
    match kind with
    | CastKind.SignExt
    | CastKind.ZeroExt ->
      if oldType < newType then true
      else if oldType = newType then false
      else castErr newType oldType
    | CastKind.IntToFloat ->
      if isFloatValid newType then true else raise InvalidFloatTypeException
    | CastKind.FloatExt ->
      if isFloatValid oldType && isFloatValid newType then true
      else raise InvalidFloatTypeException
    | _ -> true

  let extractTypeCheck (t: RegType) pos (t2: RegType) =
    if (RegType.toBitWidth t + pos) <= RegType.toBitWidth t2 && pos >= 0 then ()
    else raise <| TypeCheckException "Inconsistent types."

module ConcreteEvaluator =
  let takeHigh n t =
    let vTyp = BitVector.getType n
    let shiftAmount = (RegType.toBitWidth vTyp) - (RegType.toBitWidth t)
    BitVector.cast (BitVector.shr n (BitVector.ofInt32 shiftAmount vTyp)) t

  let inline evalUnOp n = function
    | UnOpType.NEG -> BitVector.neg n |> Num
    | UnOpType.NOT -> BitVector.bnot n |> Num
    | _ -> failwith "Invalid"

  let inline evalBinOp n1 n2 = function
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
    | _ -> failwith "Invalid"

  let inline evalRelOp n1 n2 = function
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
    | _ -> failwith "Invalid"

  let inline evalCast t n = function
    | CastKind.SignExt -> BitVector.sext n t |> Num
    | CastKind.ZeroExt -> BitVector.zext n t |> Num
    | _ -> failwith "Invalid"

  let inline evalExtract e t pos = BitVector.extract e t pos |> Num

module AST =
  open TypeCheck
  open ConcreteEvaluator

  let private emptyInfo =
    { HasLoad = false; VarInfo = RegisterSet.empty; TempVarInfo = Set.empty }

  let getExprInfo = function
    | Num _ | PCVar _ | Nil | Name _ | FuncName _ | Undefined _ -> emptyInfo
    | Var (_, _, _, x) ->
      { HasLoad = false; VarInfo = x; TempVarInfo = Set.empty }
    | TempVar (_, name) -> { HasLoad = false
                             VarInfo = RegisterSet.empty
                             TempVarInfo = Set.singleton name }
    | UnOp (_, _, ei, _) | BinOp (_, _, _, _, ei, _) | RelOp (_, _, _, ei, _)
    | Load (_, _, _, ei, _) | Ite (_, _, _, ei, _) | Cast (_, _, _, ei, _)
    | Extract (_, _, _, ei, _) -> ei

  let mergeTwoInfo e1 e2 =
    let ei1 = getExprInfo e1
    let ei2 = getExprInfo e2
    { HasLoad = ei1.HasLoad || ei2.HasLoad
      VarInfo = RegisterSet.union ei1.VarInfo ei2.VarInfo
      TempVarInfo = Set.union ei1.TempVarInfo ei2.TempVarInfo }

  let mergeThreeInfo e1 e2 e3 =
    let ei1 = getExprInfo e1
    let ei2 = getExprInfo e2
    let ei3 = getExprInfo e3
    let vInfo = RegisterSet.union ei1.VarInfo ei2.VarInfo
                |> RegisterSet.union ei3.VarInfo
    let tvInfo = Set.union ei1.TempVarInfo ei2.TempVarInfo
                 |> Set.union ei3.TempVarInfo
    { HasLoad = ei1.HasLoad || ei2.HasLoad || ei3.HasLoad
      VarInfo = vInfo; TempVarInfo = tvInfo }

  let num (num: BitVector) = Num (num)

  let var (t: RegType) (id: RegisterID) (name: string) (rs: RegisterSet) =
    Var (t, id, name, rs)

  let pcVar (t: RegType) (name: string) = PCVar (t, name)

  let private varCnt = ref -1

  let tmpVar (t: RegType) =
    let i = System.Threading.Interlocked.Increment (varCnt)
    if i >= 0 then TempVar (t, i)
    else failwith "temporary variable counter wrapped around"

  let private lblCnt = ref -1

  let lblSymbol n : Symbol =
    let i = System.Threading.Interlocked.Increment (lblCnt)
    if i >= 0 then (n, i)
    else failwith "label counter wrapped around"

  let inline unopBuilder (t: UnOpType) e proc =
    match e with
    | Num n -> evalUnOp n t
    | _ -> UnOp (t, e, getExprInfo e, None) |> proc

  let unop (t: UnOpType) e = unopBuilder t e (fun x -> x)

  let binopErr () = failwith "BinOp typecheck failure"

  let inline (===) e1 e2 = LanguagePrimitives.PhysicalEquality e1 e2

  let inline binopBuilder (op: BinOpType) e1 e2 proc =
#if DEBUG
    let t =
      match op with
      | BinOpType.CONCAT -> concatType e1 e2
      | _ -> getCommonType e1 e2
#else
    let t =
      match op with
      | BinOpType.CONCAT -> concatType e1 e2
      | _ -> typeOf e1
#endif
    match op, e1, e2 with
    | _, Num n1, Num n2 -> evalBinOp n1 n2 op
    | BinOpType.XOR, _, _ when e1 === e2 -> BitVector.zero t |> Num
    (* TODO: add more cases for optimization *)
    | _ -> BinOp (op, t, e1, e2, mergeTwoInfo e1 e2, None) |> proc

  let binop op e1 e2 = binopBuilder op e1 e2 (fun x -> x)

  let cons a b =
    match b with
    | Nil ->
      BinOp (BinOpType.CONS, typeOf a, a, b, getExprInfo a, None)
    | _ ->
      let t = getCommonType a b
      BinOp (BinOpType.CONS, t, a, b, mergeTwoInfo a b, None)

  let app name args retType =
    let funName = FuncName (name)
    List.reduceBack cons (args @ [ Nil ])
    |> fun cons ->
      BinOp (BinOpType.APP, retType, funName, cons, getExprInfo cons, None)

  let inline relopBuilder (op: RelOpType) e1 e2 proc =
#if DEBUG
    getCommonType e1 e2 |> ignore
#endif
    match e1, e2 with
    | Num n1, Num n2 -> evalRelOp n1 n2 op
    | _ -> RelOp (op, e1, e2, mergeTwoInfo e1 e2, None) |> proc

  let relop (op: RelOpType) e1 e2 = relopBuilder op e1 e2 (fun x -> x)

  let inline loadBuilder (e: Endian) (t: RegType) addr (proc: Expr -> Expr) =
#if DEBUG
    match addr with
    | Name _ -> raise InvalidExprException
    | expr ->
      Load (e, t, expr, { getExprInfo expr with HasLoad = true }, None) |> proc
#else
    Load (e, t, addr, { getExprInfo addr with HasLoad = true }, None) |> proc
#endif

  let load (e: Endian) (t: RegType) addr = loadBuilder e t addr (fun x -> x)

  let inline iteBuilder cond e1 e2 proc =
#if DEBUG
    checkTypeIsBool cond
    checkTypeIsEquivalent (typeOf e1) (typeOf e2)
#endif
    match cond with
    | Num (n) -> if BitVector.isOne n then e1 else e2 (* Assume valid cond *)
    | _ -> Ite (cond, e1, e2, mergeThreeInfo cond e1 e2, None) |> proc

  let ite cond e1 e2 = iteBuilder cond e1 e2 (fun x -> x)

  let inline castBuilder kind (t: RegType) (e: Expr) proc =
    match e with
    | Num n -> evalCast t n kind
    | _ when isCastingValid kind t e ->
      Cast (kind, t, e, getExprInfo e, None) |> proc
    | _ -> e

  let cast kind (t: RegType) (e: Expr) = castBuilder kind t e (fun x -> x)

  let inline extractBuilder (expr: Expr) (t: RegType) (pos: StartPos) proc =
    extractTypeCheck t pos (typeOf expr)
    match expr with
    | Num n -> evalExtract n t pos
    | Extract (e, _, p, ei, _) -> Extract (e, t, p + pos, ei, None) |> proc
    | _ -> Extract (expr, t, pos, getExprInfo expr, None) |> proc

  let extract (expr: Expr) (t: RegType) (pos: StartPos) =
    extractBuilder expr t pos (fun x -> x)

  let unDef (t: RegType) (s: string) =
    Undefined (t, s)

  let num0 t = num <| BitVector.zero t
  let num1 t = num <| BitVector.one t

  let b0 = num0 1<rt>
  let b1 = num1 1<rt>

  let concat e1 e2 = binop BinOpType.CONCAT e1 e2

  /// Concatenate an array of expressions.
  let concatExprs (arr: Expr []) =
    let rec concatLoop sPos ePos =
      let diff = ePos - sPos
      if diff > 0 then concat (concatLoop (sPos + diff / 2 + 1) ePos)
                              (concatLoop sPos (sPos + diff / 2))
      elif diff = 0 then arr.[sPos]
      else failwith "Invalid positions."
    concatLoop 0 (Array.length arr - 1)

  let assignForExtractDst e1 e2 =
    match e1 with
    | Extract ((Var (t, _, _, _) as e1), eTyp, 0, _, _)
    | Extract ((TempVar (t, _) as e1), eTyp, 0, _, _)->
      let nMask = RegType.getMask t - RegType.getMask eTyp
      let mask = num <| BitVector.ofUBInt nMask t
      let src = cast CastKind.ZeroExt t e2
      Put (e1, binop BinOpType.OR (binop BinOpType.AND e1 mask) src)
    | Extract ((Var (t, _, _, _) as e1), eTyp, pos, _, _)
    | Extract ((TempVar (t, _) as e1), eTyp, pos, _, _) ->
      let nMask = RegType.getMask t - (RegType.getMask eTyp <<< pos)
      let mask = num <| BitVector.ofUBInt nMask t
      let src = cast CastKind.ZeroExt t e2
      let shift = (num <| BitVector.ofInt32 pos t)
      let src = binop BinOpType.SHL src shift
      Put (e1, binop BinOpType.OR (binop BinOpType.AND e1 mask) src)
    | _ -> raise InvalidAssignmentException

  let (:=) e1 e2 = (* Assignment *)
#if DEBUG
    checkTypeIsEquivalent (typeOf e1) (typeOf e2)
#endif
    match e1 with
    | Load (_, _, e, _, _) -> Store (Endian.Little, e, e2)
    | Var _ | PCVar _ | TempVar _ -> Put (e1, e2)
    | Extract (_) as e1 -> assignForExtractDst e1 e2
    | _ -> raise InvalidAssignmentException

  let (.+) e1 e2 = binop BinOpType.ADD e1 e2

  let (.-) e1 e2 = binop BinOpType.SUB e1 e2

  let (.*) e1 e2 = binop BinOpType.MUL e1 e2

  let (./) e1 e2 = binop BinOpType.DIV e1 e2

  let (?/) e1 e2 = binop BinOpType.SDIV e1 e2

  let (.%) e1 e2 = binop BinOpType.MOD e1 e2

  let (?%) e1 e2 = binop BinOpType.SMOD e1 e2

  let faddOp e1 e2 = binop BinOpType.FADD e1 e2

  let fsubOp e1 e2 = binop BinOpType.FSUB e1 e2

  let fmulOp e1 e2 = binop BinOpType.FMUL e1 e2

  let fdivOp e1 e2 = binop BinOpType.FDIV e1 e2

  let fpowOp e1 e2 = binop BinOpType.FPOW e1 e2

  let flog e1 e2 = binop BinOpType.FLOG e1 e2

  let (==) e1 e2 = relop RelOpType.EQ e1 e2

  let (!=) e1 e2 = relop RelOpType.NEQ e1 e2

  let gt e1 e2 = relop RelOpType.GT e1 e2

  let ge e1 e2 = relop RelOpType.GE e1 e2

  let sgt e1 e2 = relop RelOpType.SGT e1 e2

  let sge e1 e2 = relop RelOpType.SGE e1 e2

  let lt e1 e2 = relop RelOpType.LT e1 e2

  let le e1 e2 = relop RelOpType.LE e1 e2

  let slt e1 e2 = relop RelOpType.SLT e1 e2

  let sle e1 e2 = relop RelOpType.SLE e1 e2

  let fgt e1 e2 = relop RelOpType.FGT e1 e2

  let fge e1 e2 = relop RelOpType.FGE e1 e2

  let flt e1 e2 = relop RelOpType.FLT e1 e2

  let fle e1 e2 = relop RelOpType.FLE e1 e2

  let (.&) e1 e2 = binop BinOpType.AND e1 e2

  let (.|) e1 e2 = binop BinOpType.OR e1 e2

  let (<+>) e1 e2 = binop BinOpType.XOR e1 e2

  let (?>>) e1 e2 = binop BinOpType.SAR e1 e2

  let (>>) e1 e2 = binop BinOpType.SHR e1 e2

  let (<<) e1 e2 = binop BinOpType.SHL e1 e2

  let neg e = unop UnOpType.NEG e

  let not e = unop UnOpType.NOT e

  let fSqrt e = unop UnOpType.FSQRT e

  let fSin e = unop UnOpType.FSIN e

  let fCos e = unop UnOpType.FCOS e

  let fTan e = unop UnOpType.FTAN e

  let fAtan e = unop UnOpType.FATAN e

  let rec unwrapExpr = function
    | Cast (_, _, e, _, _)
    | Extract (e, _, _, _, _) -> unwrapExpr e
    | e -> e

  /// Zero padding (extension).
  let zExt addrSize expr = cast CastKind.ZeroExt addrSize expr

  /// Sign extension.
  let sExt addrSize expr = cast CastKind.SignExt addrSize expr

  /// Take low.
  let extractLow addrSize expr = extract expr addrSize 0

  /// Take high.
  let extractHigh addrSize expr =
    extract expr addrSize (int (typeOf expr - addrSize))

  /// Load expression in little-endian.
  let loadLE t expr = load Endian.Little t expr

  let typeOf e = TypeCheck.typeOf e

  let rec private typeCheckExpr = function
    | UnOp (_, e, _, _) -> typeCheckExpr e
    | BinOp (BinOpType.CONCAT, t, e1, e2, _, _) ->
      typeCheckExpr e1 && typeCheckExpr e2 && concatType e1 e2 = t
    | BinOp (_, t, e1, e2, _, _) ->
      typeCheckExpr e1 && typeCheckExpr e2 && getCommonType e1 e2 = t
    | RelOp (_, e1, e2, _, _) ->
      typeCheckExpr e1 && typeCheckExpr e2 && typeOf e1 = typeOf e2
    | Load (_, _, addr, _, _) -> typeCheckExpr addr
    | Ite (cond, e1, e2, _, _) ->
      typeOf cond = 1<rt>
      && typeCheckExpr e1 && typeCheckExpr e2 && typeOf e1 = typeOf e2
    | Cast (CastKind.SignExt, t, e, _, _)
    | Cast (CastKind.ZeroExt, t, e, _, _) -> typeCheckExpr e && t >= typeOf e
    | Extract (e, t, p, _, _) ->
      typeCheckExpr e && ((t + RegType.fromBitWidth p) <= typeOf e)
    | _ -> true

  let typeCheck = function
    | Put (v, e) -> (typeOf v) = (typeOf e)
    | Store (_, a, v) -> typeCheckExpr a && typeCheckExpr v
    | Jmp (a) -> typeCheckExpr a
    | CJmp (cond, e1, e2) ->
      typeCheckExpr cond && typeCheckExpr e1 && typeCheckExpr e2
    | InterJmp (pc, addr, _) -> typeCheckExpr pc && typeCheckExpr addr
    | InterCJmp (cond, pc, a1, a2) ->
      typeCheckExpr cond && typeCheckExpr pc
      && typeCheckExpr a1 && typeCheckExpr a2
    | _ -> true

module HashCons =
  exception ConsistencyFailException of string
  exception TagNotExistException

  let private tag = ref 0L

  let private wrt = new ConcurrentWeakReferenceTable<Expr> ()

  let inline private genMeta expr =
    { Tag = System.Threading.Interlocked.Increment (tag)
      Hash = expr.GetHashCode () } |> Some

  let private factory expr =
    match expr with
    | UnOp (op, e, ei, None) -> UnOp (op, e, ei, genMeta expr)
    | BinOp (op, typ, e1, e2, ei, None) ->
      BinOp (op, typ, e1, e2, ei, genMeta expr)
    | RelOp (op, e1, e2, ei, None) -> RelOp (op, e1, e2, ei, genMeta expr)
    | Load (edn, typ, e, ei, None) -> Load (edn, typ, e, ei, genMeta expr)
    | Ite (cond, e1, e2, ei, None) -> Ite (cond, e1, e2, ei, genMeta expr)
    | Cast (cast, typ, e, ei, None) -> Cast (cast, typ, e, ei, genMeta expr)
    | Extract (e, rt, st, ei, None) -> Extract (e, rt, st, ei, genMeta expr)
    | Num (_) | Var (_) | PCVar (_) | TempVar (_) | Name (_) | Undefined (_) ->
      raise <| ConsistencyFailException ("ConcurrentWeakReferenceTable:
                                          This expr cannot be hash-consed.")
    | _ -> raise <| ConsistencyFailException ("ConcurrentWeakReferenceTable:
                                               This expr already hash-consed.")

  let isHashConsable = function
    | Num _ | Var _ | PCVar _ | TempVar _ | Name _ | FuncName _ | Undefined _ ->
      false
    | _ -> true

  let isHashConsed = function
    | Num _ | Var _ | PCVar _ | TempVar _ | FuncName _ | Name _ | Undefined _
    | UnOp (_, _, _, Some _) | BinOp (_, _, _, _, _, Some _)
    | RelOp (_, _, _, _, Some _) | Load (_, _, _, _, Some _)
    | Ite (_, _, _, _, Some _) | Cast (_, _, _, _, Some _)
    | Extract (_, _, _, _, Some _) -> true
    | _ -> false

  let getTag = function
    | UnOp (_, _, _, Some x) | BinOp (_, _, _, _, _, Some x)
    | RelOp (_, _, _, _, Some x) | Load (_, _, _, _, Some x)
    | Ite (_, _, _, _, Some x) | Cast (_, _, _, _, Some x)
    | Extract (_, _, _, _, Some x) -> x.Tag
    | _ -> raise TagNotExistException

  let hashCons expr = wrt.GetOrApplyAndAdd expr factory

  let cons x y = AST.cons x y |> hashCons

  /// Hash-consed App constructor.
  let app name args retType =
    let funName = FuncName (name)
    if List.isEmpty args then [ Nil ] else args
    |> List.reduceBack cons
    |> fun cons ->
      BinOp (BinOpType.APP, retType, funName, cons, AST.getExprInfo cons, None)
      |> hashCons

  let unop t e = AST.unopBuilder t e hashCons

  let binop op e1 e2 = AST.binopBuilder op e1 e2 hashCons

  let relop op e1 e2 = AST.relopBuilder op e1 e2 hashCons

  let load endian t e = AST.loadBuilder endian t e hashCons

  let ite cond e1 e2 = AST.iteBuilder cond e1 e2 hashCons

  let cast kind t e = AST.castBuilder kind t e hashCons

  let extract e t pos = AST.extractBuilder e t pos hashCons

// vim: set tw=80 sts=2 sw=2:
