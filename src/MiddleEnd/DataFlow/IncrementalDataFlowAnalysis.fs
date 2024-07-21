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

namespace B2R2.MiddleEnd.DataFlow

open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.BinGraph
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open System.Collections.Generic

[<AbstractClass>]
type IncrementalDataFlowAnalysis<'Lattice, 'E when 'E: equality> (hdl) as this =
  let absValues = Dictionary<VarPoint, 'Lattice> ()
  let varDefs = Dictionary<ProgramPoint, VarDefDomain.Lattice> ()
  let constants = Dictionary<VarPoint, ConstantDomain.Lattice> ()

  let incomingPps = Dictionary<ProgramPoint, Set<ProgramPoint>> ()

  let workList = Queue ()
  let workSet = HashSet ()

  let isWorklistEmpty () = Seq.isEmpty workList

  let pushWork vid =
    if workSet.Contains vid then ()
    else
      workSet.Add vid |> ignore
      workList.Enqueue vid

  let popWork () =
    let vid = workList.Dequeue ()
    assert (workSet.Contains vid)
    workSet.Remove vid |> ignore
    vid

  let addIncomingPp pp incomingPp =
    match incomingPps.TryGetValue pp with
    | true, set -> incomingPps[pp] <- Set.add incomingPp set
    | false, _ -> incomingPps[pp] <- Set.singleton incomingPp

  let getIncomingPps pp =
    match incomingPps.TryGetValue pp with
    | true, set -> set
    | false, _ -> Set.empty

  let getAbsValue vp =
    match absValues.TryGetValue vp with
    | false, _ -> this.Bottom
    | true, v -> v

  let getInitialVarConstant varKind =
    Map.tryFind varKind this.InitialVarConstants
    |> Option.defaultValue ConstantDomain.Undef

  /////////
  // Etc //
  /////////

  /// TODO: isn't it slow due to creation of the upper bound?
  /// TODO: rename
  let intoUInt64 (bv: BitVector) =
    let rt = bv.Length
    let ub = BitVector.OfUInt64 0xFFFFFFFFFFFFFFFFUL rt
    bv.Le ub |> BitVector.IsTrue

  //////////////////////////////////
  // Var definition analysis //
  //////////////////////////////////

  /// Note that we record **outgoing** var definitions!
  /// To get an incoming var definitions, use calculateIncomingVarDef.
  let getVarDef (pp: ProgramPoint) =
    match varDefs.TryGetValue pp with
    | false, _ -> VarDefDomain.empty
    | true, rd -> rd

  /// TODO: do not forget to implement memoization of it
  let calculateIncomingVarDef pp =
    let incomingPps = getIncomingPps pp
    let incomingVarDefs = incomingPps |> Seq.map getVarDef
    Seq.fold VarDefDomain.join VarDefDomain.empty incomingVarDefs

  //////////////////////////
  // Constant propagation //
  //////////////////////////

  let getConstant vp =
    match constants.TryGetValue vp with
    | false, _ -> ConstantDomain.Undef
    | true, c -> c

  let getConstantFromVps vps =
    vps |> Set.fold (fun acc vp ->
      ConstantDomain.join acc (getConstant vp)) ConstantDomain.Undef

  let getConstantFromVarKindAt varKind pp =
    calculateIncomingVarDef pp
    |> VarDefDomain.get varKind
    |> getConstantFromVps

  let rec evaluateExprIntoConst pp (e: Expr) =
    match e.E with
    | Num bv -> ConstantDomain.Const bv
    | Var _ | TempVar _ ->
      let varKind = VarKind.ofIRExpr e
      match getConstantFromVarKindAt varKind pp with
      | ConstantDomain.Undef -> getInitialVarConstant varKind
      | c -> c
    | Load (_, _, addr) ->
      match evaluateExprIntoConst pp addr with
      | ConstantDomain.Const bv when intoUInt64 bv ->
        let addr = BitVector.ToUInt64 bv
        getConstantFromVarKindAt (Memory (Some addr)) pp
      | _ -> ConstantDomain.NotAConst
    | BinOp (binOpType, _, e1, e2) ->
      let v1 = evaluateExprIntoConst pp e1
      let v2 = evaluateExprIntoConst pp e2
      match binOpType with
      | BinOpType.ADD -> ConstantDomain.add v1 v2
      | BinOpType.SUB -> ConstantDomain.sub v1 v2
      | BinOpType.MUL -> ConstantDomain.mul v1 v2
      | BinOpType.DIV -> ConstantDomain.div v1 v2
      | BinOpType.SDIV -> ConstantDomain.div v1 v2
      | BinOpType.MOD -> ConstantDomain.``mod`` v1 v2
      | BinOpType.SMOD -> ConstantDomain.``mod`` v1 v2
      | BinOpType.SHL -> ConstantDomain.shl v1 v2
      | BinOpType.SHR -> ConstantDomain.shr v1 v2
      | BinOpType.SAR -> ConstantDomain.sar v1 v2
      | BinOpType.AND -> ConstantDomain.``and`` v1 v2
      | BinOpType.OR -> ConstantDomain.``or`` v1 v2
      | BinOpType.XOR -> ConstantDomain.xor v1 v2
      | BinOpType.CONCAT -> ConstantDomain.concat v1 v2
      | _ -> ConstantDomain.NotAConst
    | RelOp (relOpType, e1, e2) ->
      let v1 = evaluateExprIntoConst pp e1
      let v2 = evaluateExprIntoConst pp e2
      match relOpType with
      | RelOpType.EQ -> ConstantDomain.eq v1 v2
      | RelOpType.NEQ -> ConstantDomain.neq v1 v2
      | RelOpType.GT -> ConstantDomain.gt v1 v2
      | RelOpType.GE -> ConstantDomain.ge v1 v2
      | RelOpType.SGT -> ConstantDomain.sgt v1 v2
      | RelOpType.SGE -> ConstantDomain.sge v1 v2
      | RelOpType.LT -> ConstantDomain.lt v1 v2
      | RelOpType.LE -> ConstantDomain.le v1 v2
      | RelOpType.SLT -> ConstantDomain.slt v1 v2
      | RelOpType.SLE -> ConstantDomain.sle v1 v2
      | _ -> ConstantDomain.NotAConst
    | Extract (e, _, _) -> evaluateExprIntoConst pp e
    | UnOp (unOpType, e) ->
      let v = evaluateExprIntoConst pp e
      match unOpType with
      | UnOpType.NEG -> ConstantDomain.neg v
      | UnOpType.NOT -> ConstantDomain.not v
      | _ -> ConstantDomain.NotAConst
    | Cast (_, _, e) -> evaluateExprIntoConst pp e
    | _ -> failwith "TODO: FILLME"

  abstract Bottom: 'Lattice

  abstract Transfer:
       IGraph<IRBasicBlock, 'E>
     * IVertex<IRBasicBlock>
     * ProgramPoint
     * Stmt
    -> (VarPoint * 'Lattice) option

  abstract IsSubsumable:
       'Lattice
     * 'Lattice
    -> bool

  abstract Join:
       'Lattice
     * 'Lattice
    -> 'Lattice

  abstract GetNextVertices:
       IGraph<IRBasicBlock, 'E>
     * IVertex<IRBasicBlock>
    -> VertexID seq

  abstract InitialVarConstants: Map<VarKind, ConstantDomain.Lattice>

  /// Call this whenever a new vertex is added to the graph
  member __.PushWork (v: IVertex<IRBasicBlock>) = pushWork v.ID

  member __.GetVarDef (vp: VarPoint) = getVarDef vp.ProgramPoint

  member __.CalculateIncomingVarDef pp = calculateIncomingVarDef pp

  member __.GetConstant (vp: VarPoint) =
    getVarDef vp.ProgramPoint
    |> VarDefDomain.get vp.VarKind
    |> fun vps ->
      if Set.isEmpty vps then getInitialVarConstant vp.VarKind
      else getConstantFromVps vps

  member __.EvaluateExprIntoConst (pp, e) = evaluateExprIntoConst pp e

  default __.GetNextVertices (g, v) = g.GetSuccs v |> Seq.map (fun x -> x.ID)

  /// Has an initial constant value for a stack pointer.
  default __.InitialVarConstants =
    match (hdl: BinHandle).RegisterFactory.StackPointer with
    | None -> Map.empty
    | Some rid ->
      let rt = hdl.RegisterFactory.RegIDToRegType rid
      let varKind = Regular rid
      let bv = BitVector.OfUInt64 Constants.InitialStackPointer rt
      let c = ConstantDomain.Const bv
      [ (varKind, c) ]
      |> Map.ofList

  member private __.TransferConstant (pp, stmt) =
    let fnUpdate vp e =
      let prevConst = getConstant vp
      let currConst = evaluateExprIntoConst pp e
      if ConstantDomain.isSubsumable prevConst currConst then false
      else constants[vp] <- ConstantDomain.join prevConst currConst; true
    match stmt.S with
    | Put (dst, src) ->
      let varKind = VarKind.ofIRExpr dst
      let varPoint = { ProgramPoint = pp; VarKind = varKind }
      fnUpdate varPoint src
    | Store (_, addr, value) ->
      match evaluateExprIntoConst pp addr with
      | ConstantDomain.Const bv when intoUInt64 bv ->
        let loc = BitVector.ToUInt64 bv
        let varKind = Memory (Some loc)
        let varPoint = { ProgramPoint = pp; VarKind = varKind }
        fnUpdate varPoint value
      | _ -> false
    | _ -> false

  /// Transfer function for var definition analysis.
  /// Note that a source expression is not used here since var definition
  /// analysis does not need to evaluate expressions.
  member private __.TransferVarDef (pp: ProgramPoint, stmt) =
    let varDef = calculateIncomingVarDef pp
    let varDef =
      match stmt.S with
      | Put (dst, _src) ->
        let dstVarKind = VarKind.ofIRExpr dst
        let vp = { ProgramPoint = pp; VarKind = dstVarKind }
        let vps = Set.singleton vp
        let varDef = Map.add vp.VarKind vps varDef
        varDef
      | Store (_, addr, _value) ->
        match evaluateExprIntoConst pp addr with
        | ConstantDomain.Const bv when intoUInt64 bv ->
          let loc = BitVector.ToUInt64 bv
          let varKind = Memory (Some loc)
          let vp = { ProgramPoint = pp; VarKind = varKind }
          let vps = Set.singleton vp
          let varDef = Map.add vp.VarKind vps varDef
          varDef
        | _ -> varDef
      | _ -> varDef
    let prevVarDef = getVarDef pp
    if varDef = prevVarDef then false
    else varDefs[pp] <- VarDefDomain.join prevVarDef varDef; true

  member private __.TransferConstantAndVarDef (pp, stmt) =
    let constantChanged = __.TransferConstant (pp, stmt)
    let varDefChanged = __.TransferVarDef (pp, stmt)
    constantChanged || varDefChanged

  interface IDataFlowAnalysis<VarPoint, 'Lattice, IRBasicBlock, 'E> with
    /// Execute each vertex in the worklist until a fixed point is reached.
    member __.Compute g =
      while not <| isWorklistEmpty () do
        let vid = popWork ()
        let v = g.FindVertexByID vid
        let stmts =
          v.VData.LiftedInstructions
          |> Array.collect (fun x ->
            let addr = x.Original.Address
            x.Stmts |> Array.mapi (fun i stmt -> ProgramPoint (addr, i), stmt))
        (* TODO: what about abstract vertices? they do not have a unqiue
           identifier unlike normal vertices other than VertexID. *)
        let mutable dirty = false
        let mutable lastExecutedPp = None
        for pp, stmt in stmts do
          match lastExecutedPp with
          | None -> ()
          | Some lastPp -> addIncomingPp pp lastPp
          lastExecutedPp <- Some pp
          match __.Transfer (g, v, pp, stmt) with
          | None -> ()
          | Some (vp, value) when __.IsSubsumable (getAbsValue vp, value) -> ()
          | Some (vp, value) ->
            absValues[vp] <- value
            dirty <- true
          if __.TransferConstantAndVarDef (pp, stmt) then
            dirty <- true
        if dirty then
          for vid in __.GetNextVertices (g, v) do
            let lastPp = Option.get lastExecutedPp
            let nextV = g.FindVertexByID vid
            let pp = nextV.VData.PPoint
            addIncomingPp pp lastPp
            pushWork vid

    member __.GetAbsValue absLoc = getAbsValue absLoc

[<RequireQualifiedAccess>]
module IncrementalDataFlowAnalysis =
  type DummyLattice = DummyValue

  /// Dummy incremental data flow analysis only for using its internal lattices
  /// such as ConstantDomain and VarDefDomain. We fill the lattice and the
  /// methods with dummy values.
  let createDummy<'E when 'E: equality> (hdl) =
    { new IncrementalDataFlowAnalysis<DummyLattice, 'E> (hdl) with
      override __.Bottom = DummyValue
      override __.IsSubsumable (_a, _b) = true
      override __.Join (_a, _b) = __.Bottom
      override __.Transfer (_g, _v, _pp, _stmt) = None }
