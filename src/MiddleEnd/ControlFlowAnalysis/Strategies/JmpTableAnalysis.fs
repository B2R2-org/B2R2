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

namespace B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

open B2R2
open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.FrontEnd.BinFile
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.DataFlow

type private L = ConstantDomain.Lattice

/// Represents how the index of a jump table selects its entries.
type private IndexOrigin =
  { /// The variable that the index derives from.
    Root: Variable
    /// The address of the entry that the index selects when Root is zero.
    ZeroAddr: int64
    /// The index itself, whose value is the number of the entry it selects.
    Index: Expr
    /// Tells whether the range check of the branch lets the index select the
    /// entry at the given address.
    Admits: int64 -> bool
    /// Tells whether the entry at the given address is the first that the
    /// conditional jumps on every path to the branch let the index select.
    StartsAt: int64 -> bool }

/// Represents a base class for analyzing jump tables.
type JmpTableAnalysis<'FnCtx, 'GlCtx>
  public(ssaLifter: ICFGAnalysis<unit -> SSACFG> option) =

  /// Gets the guard on the edge from pred to v: the condition of the
  /// conditional jump that ends pred, and whether the jump takes the edge
  /// when that holds.
  let tryGetGuard stmExtractor (g: IDiGraph<_, _>) pred v =
    match stmExtractor pred, g.FindEdge(pred, v).Label with
    | Some(Jmp(InterCJmp(cond, t, f))), InterCJmpTrueEdge when t <> f ->
      Some(cond, true)
    | Some(Jmp(InterCJmp(cond, t, f))), InterCJmpFalseEdge when t <> f ->
      Some(cond, false)
    | _ ->
      None

  /// Collects the guards on the edges into the given vertex, which is where an
  /// indirect branch checks its range.
  let collectGuards stmExtractor (g: IDiGraph<_, _>) v =
    g.GetPreds v
    |> Seq.choose (fun pred -> tryGetGuard stmExtractor g pred v)
    |> Seq.toList

  /// Collects the guards that every path to the given vertex passes: those on
  /// the edge into the vertex or into one of its dominators, from the only
  /// predecessor that it has.
  let collectDominatingGuards stmExtractor (g: IDiGraph<_, _>) v =
    let df = Dominance.CooperDominanceFrontier()
    let dom = Dominance.LengauerTarjanDominance.create g df
    let rec collect (v: IVertex<_>) acc =
      match dom.ImmediateDominator v with
      | null ->
        acc
      | idom ->
        match g.GetPreds v with
        | [| pred |] ->
          match tryGetGuard stmExtractor g pred v with
          | Some guard -> collect idom (guard :: acc)
          | None -> collect idom acc
        | _ ->
          collect idom acc
    collect v []

  let rec findJumpExpr stmExtractor (g: IDiGraph<_, _>) vFst =
    function
    | (v: IVertex<_>) :: vs ->
      match stmExtractor v with
      | Some(Jmp(InterJmp jmpExpr)) ->
        let guards = collectGuards stmExtractor g v
        Ok(jmpExpr, guards, lazy collectDominatingGuards stmExtractor g v)
      | _ ->
        let vs =
          g.GetSuccs v
          |> Seq.fold (fun acc succ ->
            if succ <> vFst then succ :: acc else acc) vs
        findJumpExpr stmExtractor g vFst vs
    | [] ->
      Error ErrorCase.ItemNotFound

  let findIndBranchExprFromIRCFG (g: LowUIRCFG) state addr =
    (* Since there could be multiple SSA vertices, search for the right one. *)
    let v = g.FindVertexBy(fun v -> v.VData.Internals.BlockAddress = addr)
    let stmExtractor (v: IVertex<LowUIRBasicBlock>) =
      if v.VData.Internals.IsAbstract then None
      else Some((state: LowUIRSparseDataFlow.State<_>).GetTerminatorInSSA v)
    findJumpExpr stmExtractor g v [ v ]

  let findIndBranchExprFromSSACFG (ssaCFG: SSACFG) addr =
    (* Since there could be multiple SSA vertices, search for the right one. *)
    let v = ssaCFG.FindVertexBy(fun v -> v.VData.Internals.BlockAddress = addr)
    let stmExtractor (v: IVertex<SSABasicBlock>) =
      if v.VData.Internals.IsAbstract then None
      else Some v.VData.Internals.LastStmt
    findJumpExpr stmExtractor ssaCFG v [ v ]

  let rec simplify e =
    match e with
    | Load(v, rt, e) ->
      Load(v, rt, simplify e)
    | Store(v, rt, e1, e2) ->
      Store(v, rt, simplify e1, simplify e2)
    | BinOp(BinOpType.ADD, _, e, Num v)
    | BinOp(BinOpType.ADD, _, Num v, e) when v.IsZero ->
      simplify e
    | BinOp(BinOpType.ADD, rt, BinOp(BinOpType.ADD, _, Num v1, e), Num v2)
    | BinOp(BinOpType.ADD, rt, BinOp(BinOpType.ADD, _, e, Num v1), Num v2)
    | BinOp(BinOpType.ADD, rt, Num v1, BinOp(BinOpType.ADD, _, e, Num v2))
    | BinOp(BinOpType.ADD, rt, Num v1, BinOp(BinOpType.ADD, _, Num v2, e)) ->
      BinOp(BinOpType.ADD, rt, e, Num(BitVector.Add(v1, v2)))
    | BinOp(BinOpType.ADD, _, Num v1, Num v2) ->
      Num(BitVector.Add(v1, v2))
    | BinOp(BinOpType.SUB, _, Num v1, Num v2) ->
      Num(BitVector.Sub(v1, v2))
    | BinOp(BinOpType.MUL, _, Num v1, Num v2) ->
      Num(BitVector.Mul(v1, v2))
    | BinOp(BinOpType.DIV, _, Num v1, Num v2) ->
      Num(BitVector.Div(v1, v2))
    | BinOp(BinOpType.AND, _, Num v1, Num v2) ->
      Num(BitVector.And(v1, v2))
    | BinOp(BinOpType.OR, _, Num v1, Num v2) ->
      Num(BitVector.Or(v1, v2))
    | BinOp(BinOpType.SHR, _, Num v1, Num v2) ->
      Num(BitVector.Shr(v1, v2))
    | BinOp(BinOpType.SHL, _, Num v1, Num v2) ->
      Num(BitVector.Shl(v1, v2))
    | BinOp(op, rt, e1, e2) ->
      BinOp(op, rt, simplify e1, simplify e2)
    | UnOp(op, rt, e) ->
      UnOp(op, rt, simplify e)
    | RelOp(op, rt, e1, e2) ->
      RelOp(op, rt, simplify e1, simplify e2)
    | Ite(c, rt, e1, e2) ->
      Ite(simplify c, rt, simplify e1, simplify e2)
    | Cast(k, rt, e) ->
      Cast(k, rt, simplify e)
    | RoundCtrl(mode, rt, body) ->
      RoundCtrl(simplify mode, rt, simplify body)
    | Extract(Cast(CastKind.ZeroExt, _, e), rt, 0) when Expr.typeOf e = rt ->
      e
    | Extract(Cast(CastKind.SignExt, _, e), rt, 0) when Expr.typeOf e = rt ->
      e
    | Extract(e, rt, pos) ->
      Extract(simplify e, rt, pos)
    | expr ->
      expr

  let rec constantFold findConst findDef e =
    match e with
    | Var v when v.Identifier <> 0 ->
      match findConst v with
      | ConstantDomain.Const bv ->
        Num bv
      | _ ->
        match findDef v with
        | Some(Def(_, e)) -> constantFold findConst findDef e
        | _ -> e
    | Load(m, rt, addr) ->
      Load(m, rt, constantFold findConst findDef addr)
    | UnOp(op, rt, e) ->
      UnOp(op, rt, constantFold findConst findDef e)
    | BinOp(op, rt, e1, e2) ->
      let e1 = constantFold findConst findDef e1
      let e2 = constantFold findConst findDef e2
      BinOp(op, rt, e1, e2) |> simplify
    | RelOp(op, rt, e1, e2) ->
      let e1 = constantFold findConst findDef e1
      let e2 = constantFold findConst findDef e2
      RelOp(op, rt, e1, e2)
    | Ite(e1, rt, e2, e3) ->
      let e1 = constantFold findConst findDef e1
      let e2 = constantFold findConst findDef e2
      let e3 = constantFold findConst findDef e3
      Ite(e1, rt, e2, e3)
    | Cast(op, rt, e) ->
      Cast(op, rt, constantFold findConst findDef e)
    | RoundCtrl(mode, rt, body) ->
      let mode = constantFold findConst findDef mode
      RoundCtrl(mode, rt, constantFold findConst findDef body)
    | Extract(e, rt, pos) ->
      Extract(constantFold findConst findDef e, rt, pos)
    | e ->
      e

  /// Expands the given expression by recursively substituting the
  /// subexpressions with their definitions. The recursion stops after following
  /// the next definitions.
  let rec symbExpand expandPhi findConst findDef doNext e =
    match e with
    | Num _ ->
      e
    | Var({ Kind = PCVar _ } as v) ->
      match findConst v with
      | ConstantDomain.Const bv -> Num bv
      | _ -> e
    | Var v when v.Identifier = 0 ->
      match findConst v with
      | ConstantDomain.Const bv -> Num bv
      | _ -> e
    | Var v when doNext ->
      match findDef v with
      | Some(Def(_, e)) -> symbExpand expandPhi findConst findDef false e
      | Some(Phi(_, ids)) -> expandPhi findConst v ids e
      | _ -> e
    | Var _ ->
      e
    | Load(m, rt, addr) ->
      let e = symbExpand expandPhi findConst findDef doNext addr
      Load(m, rt, e)
    | UnOp(op, rt, e) ->
      let e = symbExpand expandPhi findConst findDef doNext e
      UnOp(op, rt, e)
    | BinOp(op, rt, e1, e2) ->
      let e1 = symbExpand expandPhi findConst findDef doNext e1
      let e2 = symbExpand expandPhi findConst findDef doNext e2
      BinOp(op, rt, e1, e2)
    | RelOp(op, rt, e1, e2) ->
      let e1 = symbExpand expandPhi findConst findDef doNext e1
      let e2 = symbExpand expandPhi findConst findDef doNext e2
      RelOp(op, rt, e1, e2)
    | Ite(e1, rt, e2, e3) ->
      let e1 = symbExpand expandPhi findConst findDef doNext e1
      let e2 = symbExpand expandPhi findConst findDef doNext e2
      let e3 = symbExpand expandPhi findConst findDef doNext e3
      Ite(e1, rt, e2, e3)
    | Cast(op, rt, e) ->
      let e = symbExpand expandPhi findConst findDef doNext e
      Cast(op, rt, e)
    | RoundCtrl(mode, rt, body) ->
      let mode = symbExpand expandPhi findConst findDef doNext mode
      let body = symbExpand expandPhi findConst findDef doNext body
      RoundCtrl(mode, rt, body)
    | Extract(e, rt, pos) ->
      let e = symbExpand expandPhi findConst findDef doNext e
      Extract(e, rt, pos)
    | e ->
      e

  /// Expands the given expression exhaustively by recursively substituting the
  /// subexpressions with their definitions until no more expansion is possible.
  let rec symbExpandExhaustively expandPhi findConst findDef e =
    let e' = symbExpand expandPhi findConst findDef true e
    if e = e' then e else symbExpandExhaustively expandPhi findConst findDef e'

  let rec simplifyMultiplication = function
    | BinOp(BinOpType.ADD, rt, e1, e2) ->
      let e1 = simplifyMultiplication e1
      let e2 = simplifyMultiplication e2
      match e1, e2 with
      | e1, BinOp(BinOpType.SHL, _, e2, Num(n))
      | BinOp(BinOpType.SHL, _, e2, Num(n)), e1 when e1 = e2 ->
        let coeff = 1 + 1 <<< n.ToInt32()
        BinOp(BinOpType.MUL, rt, e1, Num(BitVector(coeff, rt)))
      | _ ->
        BinOp(BinOpType.ADD, rt, e1, e2)
    | BinOp(BinOpType.SHL, rt, e1, e2) ->
      let e1 = simplifyMultiplication e1
      let e2 = simplifyMultiplication e2
      BinOp(BinOpType.SHL, rt, e1, e2)
    | Cast(_, _, e) ->
      simplifyMultiplication e
    | Extract(e, _, 0) ->
      simplifyMultiplication e
    | e ->
      e

  /// Checks whether the given expression is a proper index expression, i.e., it
  /// does not contain multiplication or shift with a constant.
  let isProperIndex expandPhi findConst findDef e =
    e
    |> symbExpandExhaustively expandPhi findConst findDef
    |> simplifyMultiplication
    |> function
      | BinOp(BinOpType.MUL, _, _, Num(_))
      | BinOp(BinOpType.MUL, _, Num(_), _)
      | BinOp(BinOpType.SHL, _, _, Num(_)) -> false
      | _ -> true

  let rec isJmpTable expandPhi findConst findDef t = function
    | BinOp(BinOpType.MUL, _, idx, Num n)
    | BinOp(BinOpType.MUL, _, Num n, idx)
      when isProperIndex expandPhi findConst findDef idx ->
      RegType.toByteWidth t = n.ToInt32()
    | BinOp(BinOpType.SHL, _, idx, Num n)
      when isProperIndex expandPhi findConst findDef idx ->
      RegType.toByteWidth t = (1 <<< n.ToInt32())
    | BinOp(BinOpType.ADD, _, e1, e2) ->
      isJmpTable expandPhi findConst findDef t e1
      || isJmpTable expandPhi findConst findDef t e2
    | _ ->
      false

  let isSingleEntryJmpTable = function
    | Num(_) -> true
    | BinOp(BinOpType.ADD, _, Num(_), Num(_)) -> true
    | _ -> false

  let rec extractTableExpr = function
    | BinOp(BinOpType.ADD, _, BinOp(BinOpType.MUL, _, _, Num _), e)
    | BinOp(BinOpType.ADD, _, BinOp(BinOpType.MUL, _, Num _, _), e)
    | BinOp(BinOpType.ADD, _, BinOp(BinOpType.SHL, _, _, Num _), e)
    | BinOp(BinOpType.ADD, _, e, BinOp(BinOpType.MUL, _, _, Num _))
    | BinOp(BinOpType.ADD, _, e, BinOp(BinOpType.MUL, _, Num _, _))
    | BinOp(BinOpType.ADD, _, e, BinOp(BinOpType.SHL, _, _, Num _)) ->
      e
    | BinOp(op, rt, e1, e2) ->
      BinOp(op, rt, extractTableExpr e1, extractTableExpr e2)
    | e ->
      e

  let extractBaseAddr findConst findDef expr =
    constantFold findConst findDef expr
    |> simplify
    |> function
      | Num b -> Ok <| b.ToUInt64()
      | _ -> Error ErrorCase.ItemNotFound

  let extractTableAddr findConst findDef memExpr =
    memExpr
    |> extractTableExpr
    |> constantFold findConst findDef
    |> function
      | Num t -> Ok <| t.ToUInt64()
      | _ -> Error ErrorCase.ItemNotFound

  /// Finds the index in the given table expression, i.e., the operand of the
  /// scaled term that extractTableExpr strips.
  let rec tryExtractIndexExpr = function
    | BinOp(BinOpType.ADD, _, BinOp(BinOpType.MUL, _, idx, Num _), _)
    | BinOp(BinOpType.ADD, _, BinOp(BinOpType.MUL, _, Num _, idx), _)
    | BinOp(BinOpType.ADD, _, BinOp(BinOpType.SHL, _, idx, Num _), _)
    | BinOp(BinOpType.ADD, _, _, BinOp(BinOpType.MUL, _, idx, Num _))
    | BinOp(BinOpType.ADD, _, _, BinOp(BinOpType.MUL, _, Num _, idx))
    | BinOp(BinOpType.ADD, _, _, BinOp(BinOpType.SHL, _, idx, Num _)) ->
      Some idx
    | BinOp(_, _, e1, e2) ->
      match tryExtractIndexExpr e1 with
      | None -> tryExtractIndexExpr e2
      | idx -> idx
    | _ ->
      None

  /// Reads the given constant as a signed integer.
  let toSigned (n: BitVector) =
    BitVector.SExt(n, max n.Length 64<rt>).ToInt64()

  /// Decomposes an index into the variable it derives from and the constant
  /// added to that variable, looking through copies, extensions, and constant
  /// additions.
  let rec decomposeIndex findDef e =
    match e with
    | Var v ->
      match findDef v with
      | Some(Def(_, def)) ->
        decomposeIndex findDef def |> Option.orElse (Some(v, 0L))
      | _ ->
        Some(v, 0L)
    | BinOp(BinOpType.ADD, _, e, Num n)
    | BinOp(BinOpType.ADD, _, Num n, e) ->
      decomposeIndex findDef e
      |> Option.map (fun (v, offset) -> v, offset + toSigned n)
    | BinOp(BinOpType.SUB, _, e, Num n) ->
      decomposeIndex findDef e
      |> Option.map (fun (v, offset) -> v, offset - toSigned n)
    | Cast(CastKind.ZeroExt, _, e)
    | Cast(CastKind.SignExt, _, e)
    | Extract(e, _, 0) ->
      decomposeIndex findDef e
    | _ ->
      None

  /// Finds how the index of the given table selects its entries, leaving the
  /// range check of the indirect branch to be found later.
  let findIndexOrigin findDef (jmptbl: JmpTableInfo) tblExpr =
    match tryExtractIndexExpr tblExpr with
    | Some idx ->
      decomposeIndex findDef idx
      |> Option.map (fun (root, offset) ->
        let size = int64 jmptbl.EntrySize
        { Root = root
          ZeroAddr = int64 jmptbl.TableAddress + offset * size
          Index = idx
          Admits = fun _ -> false
          StartsAt = fun _ -> false })
    | None ->
      None

  let extractTblInfo findConst findDef insAddr baseExpr tblExpr rt singleEntry =
    let baseAddr = extractBaseAddr findConst findDef baseExpr
    let tblAddr = extractTableAddr findConst findDef tblExpr
    match baseAddr, tblAddr with
    | Ok baseAddr, Ok tblAddr ->
      let jmptbl =
        { InsAddr = insAddr
          JumpBase = baseAddr
          TableAddress = tblAddr
          EntrySize = RegType.toByteWidth rt
          NumEntries = 0
          WaitingInstructions = []
          IsSingleEntry = singleEntry
          OwnRangeEntries = None
          IsFunctionPointerTable = false }
      Ok(jmptbl, findIndexOrigin findDef jmptbl tblExpr)
    | _ ->
      Error ErrorCase.ItemNotFound

  let detect expandPhi findConst findDef iAddr = function
    | BinOp(BinOpType.ADD, _, Num b, Load(_, t, memExpr))
    | BinOp(BinOpType.ADD, _, Load(_, t, memExpr), Num b)
    | BinOp(BinOpType.ADD, _, Num b, Cast(_, _, Load(_, t, memExpr)))
    | BinOp(BinOpType.ADD, _, Cast(_, _, Load(_, t, memExpr)), Num b) ->
      if isJmpTable expandPhi findConst findDef t memExpr then
        extractTblInfo findConst findDef iAddr (Num b) memExpr t false
      elif isSingleEntryJmpTable memExpr then
        extractTblInfo findConst findDef iAddr (Num b) memExpr t true
      else
        Error ErrorCase.ItemNotFound
    | BinOp(BinOpType.ADD, _, (Load(_, _, e1) as m1), (Load(_, t, e2) as m2)) ->
      if isJmpTable expandPhi findConst findDef t e1 then
        extractTblInfo findConst findDef iAddr m2 e1 t false
      elif isJmpTable expandPhi findConst findDef t e2 then
        extractTblInfo findConst findDef iAddr m1 e2 t false
      elif isSingleEntryJmpTable e1 then
        extractTblInfo findConst findDef iAddr m2 e1 t true
      elif isSingleEntryJmpTable e2 then
        extractTblInfo findConst findDef iAddr m1 e2 t true
      else
        Error ErrorCase.ItemNotFound
    | BinOp(BinOpType.ADD, _, baseExpr, Load(_, t, tblExpr))
    | BinOp(BinOpType.ADD, _, Load(_, t, tblExpr), baseExpr) ->
      if isJmpTable expandPhi findConst findDef t tblExpr then
        extractTblInfo findConst findDef iAddr baseExpr tblExpr t false
      elif isSingleEntryJmpTable tblExpr then
        extractTblInfo findConst findDef iAddr baseExpr tblExpr t true
      else
        Error ErrorCase.ItemNotFound
    | Load(_, t, memExpr)
    | Cast(_, _, Load(_, t, memExpr)) ->
      if isJmpTable expandPhi findConst findDef t memExpr then
        let zero = BitVector.Zero t
        extractTblInfo findConst findDef iAddr (Num zero) memExpr t false
      elif isSingleEntryJmpTable memExpr then
        let zero = BitVector.Zero t
        extractTblInfo findConst findDef iAddr (Num zero) memExpr t true
      else
        Error ErrorCase.ItemNotFound
    | _ ->
      Error ErrorCase.ItemNotFound

  /// This is a practical limit for the depth of symbolic expansion.
  let [<Literal>] MaxDepth = 10

  let rec findSymbPattern expandPhi findConst findDef fnAddr insAddr depth exp =
#if CFGDEBUG
    dbglog ManagerTid "JumpTable"
    <| $"{insAddr:x} ({depth}): {PrettyPrinter.ToString(ssaExpr = exp)}"
#endif
    match detect expandPhi findConst findDef insAddr exp with
    | Ok(info, origin) ->
#if CFGDEBUG
      dbglog ManagerTid "JumpTable" $"detected @ {fnAddr:x}"
#endif
      Ok(info, origin)
    | Error _ ->
      if depth < MaxDepth then
        let e = symbExpand expandPhi findConst findDef true exp |> simplify
        findSymbPattern expandPhi findConst findDef fnAddr insAddr (depth + 1) e
      else
        Error ErrorCase.ItemNotFound

  let findConstFromIRCFG (state: LowUIRSparseDataFlow.State<_>) v =
    state.TryGetAbsValueOfSSAVar v
    |> Option.defaultValue ConstantDomain.NotAConst

  let findDefFromIRCFG (state: LowUIRSparseDataFlow.State<_>) v =
    state.TryGetSSADef v

  let expandPhiFromIRCFG findConst v _ e =
    match findConst v with
    | ConstantDomain.Const bv -> Num bv
    | _ -> e

  /// Checks if the index that the origin describes selects the given entry
  /// while its root holds the given value.
  let selects findDef origin value (entry: uint64) =
    let evaluate = SSAExprEvaluator.evaluate findDef origin.Root value MaxDepth
    match evaluate origin.Index with
    | ConstantDomain.Const n -> n.Length <= 64<rt> && n.ToUInt64() = entry
    | _ -> false

  /// Checks if the given guard, a condition paired with the outcome on which it
  /// branches toward the indirect jump, branches there while the root holds
  /// the given value. Returns None if the condition does not read the root,
  /// since then it bounds nothing.
  let tryTakeBranch findDef root value (cond, outcome) =
    let eval value = SSAExprEvaluator.evaluate findDef root value MaxDepth cond
    match eval None, eval value with
    | ConstantDomain.NotAConst, ConstantDomain.Const c ->
      Some(c.IsTrue = outcome)
    | _ ->
      None

  /// Computes the value that the root has to hold for the index of the given
  /// table to select the entry at addr, if the index can select it at all.
  let tryComputeRootValue findDef (jmptbl: JmpTableInfo) origin addr =
    let size = int64 jmptbl.EntrySize
    let offset = addr - int64 jmptbl.TableAddress
    if offset >= 0L && offset % size = 0L then
      let value = Some((addr - origin.ZeroAddr) / size)
      if selects findDef origin value (uint64 (offset / size)) then value
      else None
    else
      None

  /// Checks if one of the given guards lets the index of the given table select
  /// the entry at addr: the root has to hold the value with which the index
  /// selects that entry, and with that value the guard has to branch to the
  /// indirect jump.
  let admits findDef guards jmptbl origin addr =
    match tryComputeRootValue findDef jmptbl origin addr with
    | Some _ as value ->
      guards
      |> List.exists (fun guard ->
        tryTakeBranch findDef origin.Root value guard = Some true)
    | None ->
      false

  /// Checks if the entry at addr is the first that the given guards, which
  /// every path to the indirect jump passes, let the index of the given table
  /// select: none of them keeps the index from selecting that entry, while one
  /// of them keeps it from selecting the entry before.
  let startsAt findDef (guards: Lazy<_>) (jmptbl: JmpTableInfo) origin addr =
    let prevAddr = addr - int64 jmptbl.EntrySize
    let tryCompute = tryComputeRootValue findDef jmptbl origin
    match tryCompute addr, tryCompute prevAddr with
    | Some _ as value, (Some _ as prevValue) ->
      let branch value guard = tryTakeBranch findDef origin.Root value guard
      guards.Value |> List.forall (fun g -> branch value g <> Some false)
      && guards.Value |> List.exists (fun g -> branch prevValue g = Some false)
    | _ ->
      false

  /// Lets the origin of the index tell which entries the range check admits,
  /// which the given guards of the indirect branch decide, and which entry it
  /// selects first, which the given guards on every path to it decide.
  let guardOrigin findDef guards domGuards (jmptbl: JmpTableInfo, origin) =
    let guard o =
      { o with
          Admits = admits findDef guards jmptbl o
          StartsAt = startsAt findDef domGuards jmptbl o }
    jmptbl, Option.map guard origin

  let analyzeSymbolicallyWithIRCFG ctx state insAddr bblAddr =
    let cfg = (ctx: CFGBuildingContext<_, _>).CFG
    match findIndBranchExprFromIRCFG cfg state bblAddr with
    | Ok(exp, guards, domGuards) ->
      let findConst = findConstFromIRCFG state
      let findDef = findDefFromIRCFG state
      let fnAddr = ctx.FunctionAddress
      findSymbPattern expandPhiFromIRCFG findConst findDef fnAddr insAddr 0 exp
      |> Result.map (guardOrigin findDef guards domGuards)
    | Error e ->
      Error e

  let findConstFromSSACFG (state: SSASparseDataFlow.State<_>) v =
    state.GetRegValue v

  let findDefFromSSACFG (state: SSASparseDataFlow.State<_>) v =
    state.TryGetSSADef v

  let varToBV findConst var id =
    let v = { var with Identifier = id }
    match findConst v with
    | ConstantDomain.Const bv -> Some bv
    | _ -> None

  let expandPhiFromSSACFG findConst var ids e =
    let bvs = ids |> Array.map (fun id -> varToBV findConst var id)
    match bvs[0] with
    | Some hd ->
      if bvs |> Array.forall (fun bv -> bv = Some hd) then Num hd else e
    | None ->
      e

  let analyzeSymbolicallyWithSSACFG ctx ssaCFG state insAddr bblAddr =
    match findIndBranchExprFromSSACFG ssaCFG bblAddr with
    | Ok(exp, guards, domGuards) ->
      let findConst = findConstFromSSACFG state
      let findDef = findDefFromSSACFG state
      let fnAddr = (ctx: CFGBuildingContext<_, _>).FunctionAddress
      findSymbPattern expandPhiFromSSACFG findConst findDef fnAddr insAddr 0 exp
      |> Result.map (guardOrigin findDef guards domGuards)
    | Error e ->
      Error e

  /// Finds the vertex that ends with the indirect branch at insAddr.
  let tryFindIndBranchVertex (ctx: CFGBuildingContext<_, _>) insAddr =
    match ctx.CallerVertices.TryGetValue(LeafCallSite insAddr) with
    | true, v -> Some v
    | false, _ -> None

  /// Finds the jump table entry through which the indirect branch of the given
  /// table was first reached, if the entry belongs to another table. Returns
  /// that table along with the entry address.
  let tryFindEnclosingEntry ctx (jmptbl: JmpTableInfo) =
    tryFindIndBranchVertex ctx jmptbl.InsAddr
    |> Option.bind (fun v -> v.VData.DominatingJumpTableEntry)
    |> Option.bind (fun (tblAddr, idx) ->
      match ctx.JumpTables.TryGetValue tblAddr with
      | true, outer when outer.InsAddr <> jmptbl.InsAddr ->
        Some(outer, int64 outer.TableAddress + int64 (idx * outer.EntrySize))
      | _ ->
        None)

  /// Analyzes the indirect branch of the given table again, finding how its
  /// index selects its entries.
  let tryFindIndexOrigin ctx analyze (jmptbl: JmpTableInfo) =
    match tryFindIndBranchVertex ctx jmptbl.InsAddr with
    | Some v ->
      match analyze jmptbl.InsAddr v.VData.Internals.BlockAddress with
      | Ok(_, origin) -> origin
      | Error _ -> None
    | None ->
      None

  /// Computes the value that the variable indexing the given table holds when
  /// the entry at entryAddr is taken, along with the variable. The range check
  /// of the table must admit both that entry and the one at addr.
  let tryComputeIndexValue ctx analyze (jmptbl: JmpTableInfo) entryAddr addr =
    match tryFindIndexOrigin ctx analyze jmptbl with
    | Some o when o.Admits entryAddr && o.Admits addr ->
      Some(o.Root, (entryAddr - o.ZeroAddr) / int64 jmptbl.EntrySize)
    | _ ->
      None

  /// Rebases the jump table onto the entry that its index selects first, when
  /// the address its code computes lies within the enclosing table whose entry
  /// led to its indirect branch, and the same variable indexes both tables. No
  /// table starts within another, so the address is not where the table starts:
  /// knowing from the enclosing switch which values the variable holds there,
  /// the compiler has skipped the range check and folded the smallest value
  /// into the table address. The range check of the enclosing table bounds it,
  /// and must admit the entry that led to the branch too, since the table may
  /// have been read past its end before that end was known.
  let rebase ctx analyze (jmptbl: JmpTableInfo, origin) =
    match origin, tryFindEnclosingEntry ctx jmptbl with
    | Some o, Some(outer, entryAddr) ->
      let tblAddr = int64 jmptbl.TableAddress
      match tryComputeIndexValue ctx analyze outer entryAddr tblAddr with
      | Some(root, value) when root = o.Root ->
        let start = o.ZeroAddr + value * int64 jmptbl.EntrySize
        if start > tblAddr then
#if CFGDEBUG
          dbglog ctx.ThreadID "JumpTable"
          <| $"{jmptbl.InsAddr:x}: rebased to [{start:x}] by {outer.InsAddr:x}"
#endif
          { jmptbl with TableAddress = uint64 start }
        else
          jmptbl
      | _ ->
        jmptbl
    | _ ->
      jmptbl

  /// Returns the section names that may host a jump table per file format.
  let jumpTableSectionNames = function
    | FileFormat.ELFBinary -> [| ELF.Section.Text; ELF.Section.ROData |]
    | FileFormat.PEBinary -> [| PE.Section.Text; PE.Section.RData |]
    | FileFormat.MachBinary -> [| Mach.Section.Text; Mach.Section.Const |]
    | _ -> [||]

  /// Counts the entries that fit between the start of the given table and the
  /// end of its section, which has to be one that may host a jump table.
  let countFittingEntries (file: IBinFile) (jmptbl: JmpTableInfo) =
    match BinFileOps.tryFindSectionByAddr file jmptbl.TableAddress with
    | Ok sec when Array.contains sec.Name (jumpTableSectionNames file.Format) ->
      (sec.Address + sec.Size - jmptbl.TableAddress) / uint64 jmptbl.EntrySize
    | _ ->
      0UL

  /// Counts the entries of the given table, from the first, that the range
  /// check of its indirect branch lets the index select. Returns None if the
  /// check keeps the index from the first entry, since then the table may not
  /// start there, or lets it select the last entry that fits in the section,
  /// since then the check bounds nothing.
  let countAdmittedEntries file (jmptbl: JmpTableInfo) origin =
    let size = uint64 jmptbl.EntrySize
    let admitsEntry n = origin.Admits(int64 (jmptbl.TableAddress + n * size))
    let rec count n = if admitsEntry n then count (n + 1UL) else n
    match countFittingEntries file jmptbl with
    | fits when fits > 0UL && not (admitsEntry (fits - 1UL)) ->
      match count 0UL with
      | 0UL -> None
      | n -> Some(int n)
    | _ ->
      None

  /// Counts the entries of the given table, from the first, that its indirect
  /// branch can only reach as entries of this table. A table without an index
  /// has its one entry.
  let countOwnRange file (jmptbl: JmpTableInfo) origin =
    if jmptbl.IsSingleEntry then
      Some 1
    else
      match origin with
      | Some o -> countAdmittedEntries file jmptbl o
      | None -> None

  /// Identifies the jump table of the indirect branch at insAddr, using the
  /// given analysis of indirect branches for its enclosing branch as well.
  let identify ctx analyze insAddr bblAddr =
    analyze insAddr bblAddr
    |> Result.map (fun (jmptbl, origin) ->
      let jmptbl = rebase ctx analyze (jmptbl, origin)
      let file = (ctx: CFGBuildingContext<_, _>).BinHandle.File
      { jmptbl with OwnRangeEntries = countOwnRange file jmptbl origin })

  /// Checks if the address is in a section that may host a jump table,
  /// according to the file format's heuristic.
  let isInJumpTableSection (file: IBinFile) addr =
    match jumpTableSectionNames file.Format with
    | [||] ->
      false
    | sections ->
      match BinFileOps.tryFindSectionNameByAddr file addr with
      | Ok name -> Array.contains name sections
      | Error _ -> false

  let checkValidity (ctx: CFGBuildingContext<'FnCtx, 'GlCtx>) result =
    match result with
    | Ok info ->
      let file = ctx.BinHandle.File
      let tblAddr = info.TableAddress
      if isInJumpTableSection file tblAddr then result
      else Error ErrorCase.InvalidMemoryRead
    | Error e ->
      Error e

  /// Prepares the analysis of the indirect branches of the given function,
  /// computing the data flow that it reads.
  let prepareAnalysis (ctx: CFGBuildingContext<'FnCtx, 'GlCtx>) =
    match ssaLifter with
    | Some ssaLifter ->
      let ssaCFG = ssaLifter.Unwrap { Context = ctx } ()
      let cp = SSAConstantPropagation ctx.BinHandle
      let dfa = cp :> IDataFlowComputable<_, _, _>
      dfa.Compute ssaCFG |> ignore
      analyzeSymbolicallyWithSSACFG ctx ssaCFG cp.State
    | None ->
      let cp = ctx.CP
      let dfa = cp :> IDataFlowComputable<_, _, _>
      dfa.Compute ctx.CFG |> ignore
      analyzeSymbolicallyWithIRCFG ctx cp.State

  interface IJmpTableAnalyzable<'FnCtx, 'GlCtx> with
    member _.Identify(ctx, insAddr, bblAddr) =
      let analyze = prepareAnalysis ctx
      identify ctx analyze insAddr bblAddr
      |> checkValidity ctx

    member _.ConfirmStart(ctx, jmptbl, addr) =
      match tryFindIndexOrigin ctx (prepareAnalysis ctx) jmptbl with
      | Some o -> o.StartsAt(int64 addr)
      | None -> false
