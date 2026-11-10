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

open System.Collections.Generic
open B2R2
open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.FrontEnd
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

  /// Gets the condition of the conditional jump that ends the given vertex,
  /// whether it jumps out of its instruction or within it, as stmExtractor
  /// gives it in an SSA form.
  let tryGetCondition stmExtractor v =
    match stmExtractor v with
    | Some(Jmp(InterCJmp(cond, t, f))) when t <> f -> Some cond
    | Some(Jmp(IntraCJmp(cond, t, f))) when t <> f -> Some cond
    | _ -> None

  /// Collects the guards on the edges into the given vertex, one per edge, or
  /// None for an edge without one, each with a function that tells what a
  /// variable stands for along the edge: the operand from that edge, as
  /// tryGetPhiOperand finds it, if a phi of the vertex defines the variable,
  /// or else the variable itself.
  let collectGuards stmExtractor tryGetPhiOperand g v =
    Guard.collect (tryGetCondition stmExtractor) g v
    |> List.map (fun (pred, guard) ->
      let along var = tryGetPhiOperand var pred v |> Option.defaultValue var
      along, guard)

  /// Collects the guards that every path to the given vertex passes.
  let collectDominatingGuards stmExtractor g v =
    let df = Dominance.CooperDominanceFrontier()
    let dom = Dominance.LengauerTarjanDominance.create g df
    Guard.collectDominating (tryGetCondition stmExtractor) g dom v

  /// Finds the vertex where the instruction that ends the given vertex starts,
  /// following the edges within the instruction back from the vertex, as far
  /// as they are the only ones in. An ARM jump that may switch instruction
  /// sets ends in a way of its own for each of them.
  let rec findInstructionStart (g: IDiGraph<_, _>) v =
    match g.GetPreds v with
    | [| pred |] ->
      match g.FindEdge(pred, v).Label with
      | IntraJmpEdge | IntraCJmpTrueEdge | IntraCJmpFalseEdge ->
        findInstructionStart g pred
      | _ ->
        v
    | _ ->
      v

  let rec findJumpExpr stmExtractor tryGetPhiOperand (g: IDiGraph<_, _>) vFst =
    function
    | (v: IVertex<_>) :: vs ->
      match stmExtractor v with
      | Some(Jmp(InterJmp jmpExpr)) ->
        (* The guards on the edges into the instruction are where the branch
           checks its range. *)
        let start = findInstructionStart g v
        let guards = collectGuards stmExtractor tryGetPhiOperand g start
        Ok(jmpExpr, guards, lazy collectDominatingGuards stmExtractor g v)
      | _ ->
        let vs =
          g.GetSuccs v
          |> Seq.fold (fun acc succ ->
            if succ <> vFst then succ :: acc else acc) vs
        findJumpExpr stmExtractor tryGetPhiOperand g vFst vs
    | [] ->
      Error ErrorCase.ItemNotFound

  /// Finds the vertex that ends with the indirect branch at insAddr. The
  /// address of its block does not tell which vertex it is, since a branch
  /// that may switch instruction sets ends in a vertex for each of them.
  let tryFindIndBranchVertex (ctx: CFGBuildingContext<_, _>) insAddr =
    match ctx.CallerVertices.TryGetValue(LeafCallSite insAddr) with
    | true, vs -> Some vs[0]
    | false, _ -> None

  /// Finds the program point of the vertex that ends with the indirect branch
  /// at insAddr, which the recovery noted when it reached the branch.
  let findIndBranchPPoint ctx insAddr =
    match tryFindIndBranchVertex ctx insAddr with
    | Some v -> Ok v.VData.Internals.PPoint
    | None -> Error ErrorCase.ItemNotFound

  /// Gets the terminator of the given vertex of an IR CFG in an SSA form, as
  /// the data flow of the given state translates it, unless the vertex is
  /// abstract.
  let extractTerminatorFromIRCFG state (v: IVertex<LowUIRBasicBlock>) =
    if v.VData.Internals.IsAbstract then None
    else Some((state: LowUIRSparseDataFlow.State<_>).GetTerminatorInSSA v)

  /// Finds the expression that the indirect branch at pp jumps to, along with
  /// the vertex that the branch ends.
  let findIndBranchExprFromIRCFG (g: LowUIRCFG) state pp =
    (* Since there could be multiple SSA vertices, search for the right one. *)
    let v = g.FindVertexBy(fun v -> v.VData.Internals.PPoint = pp)
    let stmExtractor = extractTerminatorFromIRCFG state
    let tryGetPhiOperand var pred v = state.TryGetSSAPhiOperand(var, pred, v)
    findJumpExpr stmExtractor tryGetPhiOperand g v [ v ]
    |> Result.map (fun found -> v, found)

  /// Tries to get the operand that the phi of v defining the given variable
  /// takes from pred, which is the operand at the index of pred among the
  /// predecessors of v.
  let tryGetPhiOperandFromSSACFG g var pred (v: IVertex<SSABasicBlock>) =
    v.VData.Internals.Statements
    |> Array.tryPick (fun (_, stmt) ->
      match stmt with
      | Phi(def, ids) when def = var ->
        let idx = (g: SSACFG).GetPreds v |> Array.findIndex ((=) pred)
        Some { var with Identifier = ids[idx] }
      | _ ->
        None)

  let findIndBranchExprFromSSACFG (ssaCFG: SSACFG) pp =
    (* Since there could be multiple SSA vertices, search for the right one. *)
    let v = ssaCFG.FindVertexBy(fun v -> v.VData.Internals.PPoint = pp)
    let stmExtractor (v: IVertex<SSABasicBlock>) =
      if v.VData.Internals.IsAbstract then None
      else Some v.VData.Internals.LastStmt
    let tryGetPhiOperand = tryGetPhiOperandFromSSACFG ssaCFG
    findJumpExpr stmExtractor tryGetPhiOperand ssaCFG v [ v ]

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
    (* AArch64 zero-extends what it writes to a W register into X, so a byte
       that LDRB loads is extended twice. An extension by the sign of what the
       inner one zero-extended finds the sign bit clear. *)
    | Cast(CastKind.ZeroExt, rt, Cast(CastKind.ZeroExt, _, e)) ->
      Cast(CastKind.ZeroExt, rt, simplify e)
    | Cast(CastKind.SignExt, rt, Cast(CastKind.ZeroExt, mid, e))
      when Expr.typeOf e < mid ->
      Cast(CastKind.ZeroExt, rt, simplify e)
    | Cast(CastKind.SignExt, rt, Cast(CastKind.SignExt, _, e)) ->
      Cast(CastKind.SignExt, rt, simplify e)
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
    | Var v ->
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

  /// Checks if the given expression is a variable that carries no width and
  /// that no definition computes, as a stack slot that only a callee writes,
  /// or a copy of one, as a temporary that a load of AArch64 copies the slot
  /// into. The evaluator cannot give such a variable a value where a cast
  /// reads it, since nothing tells how wide the value is.
  let rec isWidthlessLeaf findDef e =
    match e with
    | Var v when Expr.typeOf e = 0<rt> ->
      match findDef v with
      | Some(Def(_, (Var _ as copied))) -> isWidthlessLeaf findDef copied
      | Some(Def _) -> false
      | _ -> true
    | _ ->
      false

  /// Decomposes an index into the variable it derives from and the constant
  /// added to that variable, looking through copies, extensions, and constant
  /// additions, but not through an extension of a variable that carries no
  /// width and that no definition computes, so that the variable holding the
  /// extension becomes the root instead.
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
    | Extract(e, _, 0) when not (isWidthlessLeaf findDef e) ->
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
          EntryShift = 0
          IsSignedEntry = true
          NumEntries = 0
          WaitingInstructions = []
          IsSingleEntry = singleEntry
          OwnRangeEntries = None
          IsFunctionPointerTable = false }
      Ok(jmptbl, findIndexOrigin findDef jmptbl tblExpr)
    | _ ->
      Error ErrorCase.ItemNotFound

  /// Reads the given factor as the shift to the left that multiplying by it
  /// amounts to, if it is a power of two.
  let tryGetShiftOfFactor (n: BitVector) =
    let v = n.ToUInt64()
    if v <> 0UL && v &&& (v - 1UL) = 0UL then
      Some(System.Numerics.BitOperations.Log2 v)
    else
      None

  /// Matches an entry that the code extends and then shifts to the left before
  /// adding it to the base, as GCC for ARM adds an entry to the PC, giving
  /// whether the extension is signed, the shift, and the load of the entry.
  /// TBB and TBH of Thumb double the entry by a multiplication instead.
  let (|ShiftedEntry|_|) = function
    | BinOp(BinOpType.SHL, _, Cast(kind, _, Load(_, t, memExpr)), Num n)
      when kind = CastKind.SignExt || kind = CastKind.ZeroExt ->
      let signed = kind = CastKind.SignExt
      Some(signed, n.ToInt32(), t, memExpr)
    | BinOp(BinOpType.MUL, _, Num n, Cast(kind, _, Load(_, t, memExpr)))
    | BinOp(BinOpType.MUL, _, Cast(kind, _, Load(_, t, memExpr)), Num n)
      when kind = CastKind.SignExt || kind = CastKind.ZeroExt ->
      let signed = kind = CastKind.SignExt
      tryGetShiftOfFactor n
      |> Option.map (fun shift -> signed, shift, t, memExpr)
    | _ ->
      None

  /// Matches the target of a jump that clears its lowest bit, as every branch
  /// of Thumb does, where the bit is clear anyway: an entry shifted to the left
  /// and added to an even base, as TBB and TBH jump. Gives the target without
  /// the mask.
  let (|EvenTarget|_|) = function
    | BinOp(BinOpType.AND, _, e, Num mask)
      when BitVector.Not mask = BitVector.One mask.Length ->
      match e with
      | BinOp(BinOpType.ADD, _, Num b, ShiftedEntry(_, shift, _, _))
      | BinOp(BinOpType.ADD, _, ShiftedEntry(_, shift, _, _), Num b)
        when shift > 0 && b.ToUInt64() % 2UL = 0UL ->
        Some e
      | _ ->
        None
    | _ ->
      None

  /// Finds the expression that computes the given one, following the copies
  /// through which ARM moves a value, which go via a temporary.
  let rec findComputation findDef e =
    match e with
    | Var v ->
      match findDef v with
      | Some(Def(_, d)) ->
        match simplify d with
        | Var _ as copied -> findComputation findDef copied
        | computed -> computed
      | _ ->
        e
    | _ ->
      e

  /// Rewrites the address of a byte or halfword entry, whose index ARM cannot
  /// scale within the load, so that the index is scaled as isJmpTable expects.
  /// For a byte, tbl + i becomes tbl + (i << 0), the table being the side that
  /// folds to a constant and the index the side that does not. For a halfword,
  /// whose index the code adds twice, tbl + (i + i) and (tbl + i) + i become
  /// tbl + (i << 1).
  let scaleNarrowIndex findConst findDef t memExpr =
    let isConst e =
      match constantFold findConst findDef e with
      | Num _ -> true
      | _ -> false
    (* The address has the width of the index, which a temporary or a stack
       slot of the data flow does not tell. *)
    let shl rt idx (n: uint64) =
      BinOp(BinOpType.SHL, rt, idx, Num(BitVector(n, rt)))
    let tryScaleHalf rt tbl idx =
      match findComputation findDef idx, findComputation findDef tbl with
      | BinOp(BinOpType.ADD, _, i1, i2), _ when i1 = i2 ->
        Some(tbl, shl rt i1 1UL)
      | _, BinOp(BinOpType.ADD, _, inner, i) when i = idx ->
        Some(inner, shl rt idx 1UL)
      | _, BinOp(BinOpType.ADD, _, i, inner) when i = idx ->
        Some(inner, shl rt idx 1UL)
      | _ ->
        None
    let tryScale rt tbl idx =
      if t = 8<rt> && isConst tbl && not (isConst idx) then
        Some(tbl, shl rt idx 0UL)
      elif t = 16<rt> then
        tryScaleHalf rt tbl idx
      else
        None
    match memExpr with
    | BinOp(BinOpType.ADD, rt, e1, e2) ->
      match tryScale rt e1 e2 |> Option.orElse (tryScale rt e2 e1) with
      | Some(tbl, idx) -> BinOp(BinOpType.ADD, rt, tbl, idx)
      | None -> memExpr
    | _ ->
      memExpr

  let rec detect expandPhi findConst findDef iAddr = function
    | EvenTarget e ->
      detect expandPhi findConst findDef iAddr e
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
    | BinOp(BinOpType.ADD, _, Num b, ShiftedEntry(signed, shift, t, memExpr))
    | BinOp(BinOpType.ADD, _, ShiftedEntry(signed, shift, t, memExpr), Num b) ->
      let memExpr = scaleNarrowIndex findConst findDef t memExpr
      if isJmpTable expandPhi findConst findDef t memExpr then
        extractTblInfo findConst findDef iAddr (Num b) memExpr t false
        |> Result.map (fun (jmptbl, origin) ->
          { jmptbl with EntryShift = shift; IsSignedEntry = signed }, origin)
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

  /// Expands the phi that defines the given variable into the constant that
  /// the data flow gives it, which holds wherever the phi goes. The phi stays
  /// otherwise, even where it folds along the branch toward the jump, so that
  /// an index that it defines stays one for the range check to bound.
  let expandPhiFromIRCFG fromCP _ v _ e =
    match fromCP v with
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

  /// Checks if the given guards, one per edge into the indirect jump or None
  /// for an edge without one, each paired with what the root stands for along
  /// its edge, let the index of the given table select the entry at addr: the
  /// root has to hold the value with which the index selects that entry, and
  /// with that value one of the guards has to branch to the indirect jump. An
  /// edge whose guard cannot tell lets the index in unchecked, and then there
  /// is no range check to admit the entry.
  let admits findDef guards jmptbl origin addr =
    match tryComputeRootValue findDef jmptbl origin addr with
    | Some _ as value ->
      let branches =
        guards
        |> List.map (fun (root, guard) ->
          guard |> Option.bind (tryTakeBranch findDef root value))
      List.forall Option.isSome branches && List.contains (Some true) branches
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
  /// selects first, which the given guards on every path to it decide. A guard
  /// of the branch reads the root as it flows in along its own edge, which is
  /// the operand from that edge if the root is a phi of the branch.
  let guardOrigin findDef guards domGuards (jmptbl: JmpTableInfo, origin) =
    let guard o =
      let guards = guards |> List.map (fun (along, g) -> along o.Root, g)
      { o with
          Admits = admits findDef guards jmptbl o
          StartsAt = startsAt findDef domGuards jmptbl o }
    jmptbl, Option.map guard origin

  /// Finds the constant that the given variable holds, as the given function
  /// finds it, or else as the binary holds it, if the variable is memory that
  /// only the loader writes. The data flow leaves unknown what a global
  /// variable holds before the function writes it.
  let findConstOrLoaded hdl findConst (v: Variable) =
    match findConst v, v.Kind with
    | ConstantDomain.Const _ as c, _ ->
      c
    | c, GlobalVar(_, addr) when v.Identifier = 0 ->
      let rt = WordSize.toRegType (hdl: BinHandle).File.ISA.WordSize
      LoaderOnlyMemory.tryRead hdl addr rt
      |> Option.map ConstantDomain.Const
      |> Option.defaultValue c
    | c, _ ->
      c

  /// Finds the vertex that starts with the phi defining the given variable,
  /// if a phi defines it.
  let tryFindPhiVertex (state: LowUIRSparseDataFlow.State<_>) var =
    match state.SSAVarToVp.TryGetValue var with
    | true, vp ->
      match state.StmtOfBBLs.TryGetValue vp.ProgramPoint with
      | true, (_, v) when v.VData.Internals.PPoint = vp.ProgramPoint -> Some v
      | _ -> None
    | false, _ ->
      None

  /// This is a practical limit for the number of vertices to walk from a phi
  /// to the branch that tells where its operands go.
  let [<Literal>] MaxWalk = 16

  /// Gets the vertices that the conditional jump ending v goes to when its
  /// condition holds and when it does not.
  let tryGetWays (g: IDiGraph<_, _>) v =
    let tryFindWay holds =
      g.GetSuccEdges v
      |> Array.tryPick (fun e ->
        match e.Label with
        | InterCJmpTrueEdge | IntraCJmpTrueEdge when holds ->
          Some e.Second
        | InterCJmpFalseEdge | IntraCJmpFalseEdge when not holds ->
          Some e.Second
        | _ ->
          None)
    match tryFindWay true, tryFindWay false with
    | Some t, Some f -> Some(t, f)
    | _ -> None

  /// Checks if the given way of a conditional jump only runs some code before
  /// it rejoins the other way, as an ARM instruction runs what it does on its
  /// condition.
  let rejoins (g: IDiGraph<_, _>) (way: IVertex<LowUIRBasicBlock>) other =
    match g.GetPreds way, g.GetSuccs way with
    | [| _ |], [| next |] -> not way.VData.Internals.IsAbstract && next = other
    | _ -> false

  /// Checks if the given kind of edge leads on to the code that runs next,
  /// rather than to a callee or through a table.
  let isFlowOn = function
    | FallThroughEdge | IntraJmpEdge | InterJmpEdge -> true
    | _ -> false

  /// Walks from v down the code that every path from v runs, up to the first
  /// conditional jump whose ways do not just rejoin after some code, as those
  /// of an ARM instruction do, and gets its condition and its ways. Adds every
  /// vertex it walks to the given set.
  let rec tryWalkToBranch condOf (g: IDiGraph<_, _>) (walked: HashSet<_>) v =
    let isAbstract = (v: IVertex<LowUIRBasicBlock>).VData.Internals.IsAbstract
    if isAbstract || walked.Count >= MaxWalk || not (walked.Add v) then
      None
    else
      match condOf v, tryGetWays g v with
      | Some _, Some(t, f) when rejoins g t f ->
        walked.Add t |> ignore
        tryWalkToBranch condOf g walked f
      | Some cond, Some(t, f) ->
        Some(cond, t, f)
      | Some _, None ->
        None
      | None, _ ->
        match g.GetSuccEdges v with
        | [| e |] when isFlowOn e.Label ->
          tryWalkToBranch condOf g walked e.Second
        | _ ->
          None

  /// Checks if the given kind of edge is one that a conditional jump takes.
  let isCondJmpEdge = function
    | InterCJmpTrueEdge | InterCJmpFalseEdge
    | IntraCJmpTrueEdge | IntraCJmpFalseEdge -> true
    | _ -> false

  /// Collects the variables that the given expression reads.
  let rec collectVars acc = function
    | Var v ->
      v :: acc
    | Load(_, _, e) | UnOp(_, _, e) | Cast(_, _, e) | Extract(e, _, _) ->
      collectVars acc e
    | BinOp(_, _, e1, e2) | RelOp(_, _, e1, e2) | RoundCtrl(e1, _, e2) ->
      collectVars (collectVars acc e1) e2
    | Ite(e1, _, e2, e3) ->
      collectVars (collectVars (collectVars acc e1) e2) e3
    | _ ->
      acc

  /// Checks if none of the given vertices defines a variable that the given
  /// expression reads.
  let definesNone (state: LowUIRSparseDataFlow.State<_>) (vs: HashSet<_>) e =
    collectVars [] e
    |> List.forall (fun var ->
      match state.SSAVarToVp.TryGetValue var with
      | true, vp ->
        match state.StmtOfBBLs.TryGetValue vp.ProgramPoint with
        | true, (_, v) -> not (vs.Contains v)
        | false, _ -> false
      | false, _ ->
        true)

  /// Checks if the branch on the given condition, which every path from p
  /// reaches through the walked vertices, sends the code on as the guards on
  /// the edges into p tell: the indirect jump ending jmpV comes after it, and
  /// no vertex from the conditional jumps of the guards to the branch defines
  /// what the condition reads, which would change it on the way. Those are
  /// the walked ones and the ways into p that do not end in such a jump.
  let branchDecides state (g: IDiGraph<_, _>) walked jmpV p cond =
    let between = HashSet(walked: HashSet<_>)
    g.GetPredEdges p
    |> Array.filter (fun e -> not (isCondJmpEdge e.Label))
    |> Array.iter (fun e -> between.Add e.First |> ignore)
    not (walked.Contains jmpV) && definesNone state between cond

  /// Collects the vertices from which the code can reach the given target
  /// without passing through the given vertex to avoid.
  let collectReaching (g: IDiGraph<_, _>) target avoid =
    let reached = HashSet<IVertex<LowUIRBasicBlock>>([ target ])
    let queue = Queue<IVertex<LowUIRBasicBlock>>([ target ])
    while queue.Count > 0 do
      for pred in g.GetPreds(queue.Dequeue()) do
        if pred <> avoid && reached.Add pred then queue.Enqueue pred else ()
    reached

  /// Tells which way of a branch on the given condition the given guard leads
  /// to, true for the one that the branch takes when its condition holds, if
  /// the guard decides it: its condition is that of the branch or the
  /// negation of it.
  let tryOrient cond (guardCond, holds) =
    match guardCond, cond with
    | _ when guardCond = cond -> Some holds
    | UnOp(UnOpType.NOT, _, c), _ when c = cond -> Some(not holds)
    | _, UnOp(UnOpType.NOT, _, c) when c = guardCond -> Some(not holds)
    | _ -> None

  /// Gets the guard on the edge from pred to v as Guard.tryGet does, or else,
  /// where pred falls through to v, the guard on the way into pred, as what an
  /// ARM instruction runs on its condition falls through to its end.
  let tryGetGuardInto condOf (g: IDiGraph<_, _>) pred v =
    match g.FindEdge(pred, v).Label with
    | FallThroughEdge -> Guard.tryGetOfWay condOf g pred
    | _ -> Guard.tryGet condOf g pred v

  /// Collects the vertices whose edges into p the code may take on its way to
  /// the indirect jump ending jmpV, without passing through p again, as the
  /// branch that every path from p reaches first tells: an edge whose guard
  /// leads to the way of the branch from which no path reaches the jump is
  /// not one. Returns None if the branch cannot tell.
  let tryCollectPredsToward state (g: IDiGraph<_, _>) jmpV p =
    let condOf = tryGetCondition (extractTerminatorFromIRCFG state)
    let walked = HashSet()
    match tryWalkToBranch condOf g walked p with
    | Some(cond, t, f) when branchDecides state g walked jmpV p cond ->
      let reaching = collectReaching g jmpV p
      let leadsToJump guard =
        match tryOrient cond guard with
        | Some holds -> reaching.Contains(if holds then t else f)
        | None -> true
      g.GetPreds p
      |> Array.filter (fun pred ->
        tryGetGuardInto condOf g pred p |> Option.forall leadsToJump)
      |> Some
    | _ ->
      None

  /// Folds what a phi takes along the edges from the given vertices, which
  /// operandOf gives for each, into the one constant that all of them hold.
  let tryFoldOperands findConst findDef operandOf preds =
    let fold o = constantFold findConst findDef (Var o)
    let folded = preds |> Array.map (operandOf >> Option.map fold)
    match Array.distinct folded with
    | [| Some(Num bv) |] -> Some bv
    | _ -> None

  /// Folds the phi that defines the given variable, if one does, into the one
  /// constant that its operands hold along the edges that the code may take
  /// on its way to the indirect jump ending jmpV.
  let tryFoldPhiAlongBranch g state jmpV findConst findDef var =
    match tryFindPhiVertex state var with
    | Some p ->
      let operandOf pred = state.TryGetSSAPhiOperand(var, pred, p)
      tryCollectPredsToward state g jmpV p
      |> Option.bind (tryFoldOperands findConst findDef operandOf)
    | None ->
      None

  /// Finds the constant that the given variable holds where the indirect jump
  /// ending jmpV reads it, as findConst finds it, or else as the phi defining
  /// it folds along the branch toward the jump, which it does once per phi.
  /// The data flow merges all that reaches a phi, while a branch on the
  /// condition on which an ARM instruction defines the variable sends some of
  /// that away from the jump, as GCC loads the address of a table there.
  let findConstAlongBranch g state jmpV findDef findConst =
    let folded = Dictionary<Variable, BitVector option>()
    let tryFold var =
      match folded.TryGetValue var with
      | true, bv ->
        bv
      | false, _ ->
        let bv = tryFoldPhiAlongBranch g state jmpV findConst findDef var
        folded[var] <- bv
        bv
    fun var ->
      match findConst var with
      | ConstantDomain.Const _ as c ->
        c
      | c ->
        match tryFold var with
        | Some bv -> ConstantDomain.Const bv
        | None -> c

  let analyzeSymbolicallyWithIRCFG ctx state insAddr =
    let cfg = (ctx: CFGBuildingContext<_, _>).CFG
    let found =
      findIndBranchPPoint ctx insAddr
      |> Result.bind (findIndBranchExprFromIRCFG cfg state)
    match found with
    | Ok(v, (exp, guards, domGuards)) ->
      let fromCP = findConstFromIRCFG state
      let findDef = findDefFromIRCFG state
      let expandPhi = expandPhiFromIRCFG fromCP
      let findConst =
        findConstOrLoaded ctx.BinHandle fromCP
        |> findConstAlongBranch cfg state v findDef
      let fnAddr = ctx.FunctionAddress
      findSymbPattern expandPhi findConst findDef fnAddr insAddr 0 exp
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

  let analyzeSymbolicallyWithSSACFG ctx ssaCFG state insAddr =
    let found =
      findIndBranchPPoint ctx insAddr
      |> Result.bind (findIndBranchExprFromSSACFG ssaCFG)
    match found with
    | Ok(exp, guards, domGuards) ->
      let findConst = findConstFromSSACFG state
      let findDef = findDefFromSSACFG state
      let fnAddr = (ctx: CFGBuildingContext<_, _>).FunctionAddress
      findSymbPattern expandPhiFromSSACFG findConst findDef fnAddr insAddr 0 exp
      |> Result.map (guardOrigin findDef guards domGuards)
    | Error e ->
      Error e

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
  let tryFindIndexOrigin analyze (jmptbl: JmpTableInfo) =
    match analyze jmptbl.InsAddr with
    | Ok(_, origin) -> origin
    | Error _ -> None

  /// Computes the value that the variable indexing the given table holds when
  /// the entry at entryAddr is taken, along with the variable. The range check
  /// of the table must admit both that entry and the one at addr.
  let tryComputeIndexValue analyze (jmptbl: JmpTableInfo) entryAddr addr =
    match tryFindIndexOrigin analyze jmptbl with
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
      match tryComputeIndexValue analyze outer entryAddr tblAddr with
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
  /// start there, or lets it select an entry that does not fit in the section,
  /// since then the check bounds nothing. A table may come last in its
  /// section, so the check may end it right where the section ends.
  let countAdmittedEntries file (jmptbl: JmpTableInfo) origin =
    let size = uint64 jmptbl.EntrySize
    let admitsEntry n = origin.Admits(int64 (jmptbl.TableAddress + n * size))
    let rec count n = if admitsEntry n then count (n + 1UL) else n
    match countFittingEntries file jmptbl with
    | fits when fits > 0UL && not (admitsEntry fits) ->
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
  let identify ctx analyze insAddr =
    analyze insAddr
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

  /// Checks if the given table has an index and lies where the loader keeps
  /// it read-only once it has relocated the binary, so that its entries stay
  /// what the binary holds. A single slot read through a constant address is
  /// a pointer rather than a table, e.g., one in .got, which the dynamic
  /// linker binds.
  let isReadOnlyTable (file: IBinFile) jmptbl =
    match file with
    | :? ELFBinFile as elf when not jmptbl.IsSingleEntry ->
      elf.IsReadOnlyAfterLoading jmptbl.TableAddress
    | _ ->
      false

  /// Checks if the given table holds the addresses of labels of the function
  /// under analysis, as GNU C builds one out of `&&label`: an indexed table
  /// whose first entry points into the function. Such a table may lie in any
  /// section, even one the program can write, since a label is good only
  /// within its function, so whatever the program writes there is one, too.
  let isLabelTable (ctx: CFGBuildingContext<'FnCtx, 'GlCtx>) jmptbl =
    let fnAddr = ctx.FunctionAddress
    match ctx.ManagerChannel.GetNextFunctionAddress fnAddr with
    | Some nextFnAddr when not jmptbl.IsSingleEntry ->
      match JmpTableInfo.tryReadTarget ctx.BinHandle jmptbl 0 with
      | Some target -> fnAddr < target && target < nextFnAddr
      | None -> false
    | _ ->
      false

  /// Checks if the found table can be one: it lies in a section that may host
  /// a jump table, it has an index and the loader keeps it read-only, or it
  /// holds the labels of the function under analysis.
  let checkValidity (ctx: CFGBuildingContext<'FnCtx, 'GlCtx>) result =
    match result with
    | Ok info ->
      let file = ctx.BinHandle.File
      let tblAddr = info.TableAddress
      if isInJumpTableSection file tblAddr then result
      elif isReadOnlyTable file info then result
      elif isLabelTable ctx info then result
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
    member _.Identify(ctx, insAddr) =
      let analyze = prepareAnalysis ctx
      identify ctx analyze insAddr
      |> checkValidity ctx

    member _.ConfirmStart(ctx, jmptbl, addr) =
      match tryFindIndexOrigin (prepareAnalysis ctx) jmptbl with
      | Some o -> o.StartsAt(int64 addr)
      | None -> false
