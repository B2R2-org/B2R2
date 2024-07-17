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
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.BinGraph
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open System.Collections.Generic

type ReachingDefDomain = Map<VarKind, Set<VarPoint>>

module ReachingDefDomain =
  let empty = Map.empty

  let get varKind rd =
    match Map.tryFind varKind rd with
    | None -> Set.empty
    | Some pps -> pps

  let load addr rd = get (Memory addr) rd

  let store addr pp rd =
    let pps = load addr rd
    let pps = Set.add pp pps
    Map.add (Memory addr) pps rd

  let join rd1 rd2 =
    Map.keys rd2
    |> Seq.fold (fun acc k ->
      let pps1 = get k rd1
      let pps2 = get k rd2
      let pps = Set.union pps1 pps2
      Map.add k pps acc) rd1

[<AbstractClass>]
type IncrementalDataFlowAnalysis<'Lattice> () as this =
  let absValues = Dictionary<ProgramPoint, 'Lattice> ()
  let reachingDefs = Dictionary<ProgramPoint, ReachingDefDomain> ()
  let constants = Dictionary<VarPoint, ConstantDomain> ()

  let regInitialValues = Dictionary<RegisterID, BitVector> ()

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

  let getAbsValue pp =
    match absValues.TryGetValue pp with
    | false, _ -> this.Bottom
    | true, v -> v

  /////////
  // Etc //
  /////////

  /// Consider two cases:
  /// (1) the beginning of the vertex,
  /// (2) otherwise.
  /// TODO: we can even memoize it.
  let getIncomingProgramPoints g v pp =
    if (pp: ProgramPoint).Position = 0 then
      (g: IGraph<IRBasicBlock, _>).GetPreds v
      |> Seq.map (fun pred ->
        let liftedInss = pred.VData.LiftedInstructions
        let addr = pred.VData.PPoint.Address
        let lastIdx = liftedInss.Length - 1
        ProgramPoint (addr, lastIdx))
    else Seq.singleton <| ProgramPoint (pp.Address, pp.Position - 1)

  /// TODO: isn't it slow due to creation of the upper bound?
  /// TODO: rename
  let intoUInt64 (bv: BitVector) =
    let rt = bv.Length
    let ub = BitVector.OfUInt64 0xFFFFFFFFFFFFFFFFUL rt
    bv.Ge ub |> BitVector.IsTrue

  //////////////////////////////////
  // Reaching definition analysis //
  //////////////////////////////////

  /// Note that we record **outgoing** reaching definitions!
  /// To get an incoming reaching definitions, use calculateIncomingReachingDef.
  let getReachingDef (pp: ProgramPoint) =
    match reachingDefs.TryGetValue pp with
    | false, _ -> ReachingDefDomain.empty
    | true, rd -> rd

  /// TODO: do not forget to implement memoization of it
  let calculateIncomingReachingDef g v pp =
    let incomingPps = getIncomingProgramPoints g v pp
    let incomingReachingDefs = incomingPps |> Seq.map getReachingDef
    let firstIncomingRD = Seq.head incomingReachingDefs
    let otherIncomingRDs = Seq.tail incomingReachingDefs
    Seq.fold ReachingDefDomain.join firstIncomingRD otherIncomingRDs

  //////////////////////////
  // Constant propagation //
  //////////////////////////

  let getConstant pp =
    match constants.TryGetValue pp with
    | false, _ -> ConstantDomain.Undef
    | true, c -> c

  let getConstantFromPps pps =
    pps |> Set.fold (fun acc pp ->
      ConstantDomain.join acc (getConstant pp)) ConstantDomain.Undef

  let getConstantFromVarKindAt g v varKind pp =
    calculateIncomingReachingDef g v pp
    |> ReachingDefDomain.get varKind
    |> getConstantFromPps

  /// ProgramPoint -> Expr -> ConstantDomain
  /// Note that this does not return IRConstant.Domain.
  let rec evaluateExprIntoConst g v pp (e: Expr) =
    match e.E with
    | Num bv -> ConstantDomain.Const bv
    | Var _ | TempVar _ -> getConstantFromVarKindAt g v (VarKind.ofIRExpr e) pp
    | Load (_, _, addr) ->
      match evaluateExprIntoConst g v pp addr with
      | ConstantDomain.Const bv when intoUInt64 bv ->
        let addr = BitVector.ToUInt64 bv
        getConstantFromVarKindAt g v (Memory (Some addr)) pp
      | _ -> ConstantDomain.NotAConst
    | BinOp (binOpType, _, e1, e2) ->
      let v1 = evaluateExprIntoConst g v pp e1
      let v2 = evaluateExprIntoConst g v pp e2
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
    | _ -> failwith "TODO: FILLME"

  member private __.TransferConstant (g, v, pp, stmt) =
    match stmt.S with
    | Put (dst, src) ->
      let varKind = VarKind.ofIRExpr dst
      let vp = { ProgramPoint = pp; VarKind = varKind }
      let prevConst = getConstant vp
      let currConst = evaluateExprIntoConst g v pp src
      let joinConst = ConstantDomain.join prevConst currConst
      if ConstantDomain.isNonmonotonic prevConst joinConst then false
      else constants[vp] <- joinConst; true
    // Note that we do not maintain an abstracted value for each memory.
    | Store (_, _addr, _value) -> false
    | _ -> failwith "TODO: FILLME"

  /// Transfer function for reaching definition analysis.
  /// Note that a source expression is not used here since reaching definition
  /// analysis does not need to evaluate expressions.
  member private __.TransferReachingDef (g, v, pp: ProgramPoint, stmt) =
    let rd = calculateIncomingReachingDef g v pp
    let update vp rd =
      let prevVps = ReachingDefDomain.get vp.VarKind rd
      if Set.contains vp prevVps then false
      else
        let joinVps = Set.add vp prevVps
        let rd = Map.add vp.VarKind joinVps rd
        reachingDefs[vp.ProgramPoint] <- rd
        true
    match stmt.S with
    | Put (dst, _src) ->
      let dstVarKind = VarKind.ofIRExpr dst
      let dstVp = { ProgramPoint = pp; VarKind = dstVarKind }
      update dstVp rd
    | Store (_, addr, _value) ->
      match evaluateExprIntoConst g v pp addr with
      | ConstantDomain.Const bv when intoUInt64 bv ->
        let loc = BitVector.ToUInt64 bv
        let varKind = Memory (Some loc)
        let vp = { ProgramPoint = pp; VarKind = varKind }
        update vp rd
      | _ -> false
    | _ -> failwith "TODO"

  member private __.TransferConstantAndReachingDef (g, v, pp, stmt) =
    let constantChanged = __.TransferConstant (g, v, pp, stmt)
    let reachingDefChanged = __.TransferReachingDef (g, v, pp, stmt)
    constantChanged || reachingDefChanged

  abstract Bottom: 'Lattice

  interface IDataFlowAnalysis<ProgramPoint, 'Lattice, IRBasicBlock, CFGEdgeKind>
    with
    /// Execute each vertex in the worklist until a fixed point is reached.
    member __.Compute g =
      while not <| isWorklistEmpty () do
        let vid = popWork ()
        let v = g.FindVertexByID vid
        let stmts =
          v.VData.LiftedInstructions
          |> Array.map (fun x ->
            let addr = x.Original.Address
            x.Stmts |> Array.mapi (fun i stmt -> ProgramPoint (addr, i), stmt))
          |> Array.concat
        (* TODO: what about abstract vertices? they do not have a unqiue
           identifier unlike normal vertices other than VertexID. *)
        let mutable dirty = false
        for pp, stmt in stmts do
          let prevAbsValue = getAbsValue pp
          let currAbsValue = __.Transfer (g, v, pp, stmt)
          let joinAbsValue = __.Join (prevAbsValue, currAbsValue)
          if not <| __.Subsume (prevAbsValue, joinAbsValue) then
            dirty <- true
            absValues[pp] <- joinAbsValue
          if __.TransferConstantAndReachingDef (g, v, pp, stmt) then
            dirty <- true
        if not dirty then ()
        else for vid in __.GetNextVertices (g, v) do pushWork vid

    member __.GetAbsValue absLoc = getAbsValue absLoc

  abstract Transfer:
       IGraph<IRBasicBlock, CFGEdgeKind>
     * IVertex<IRBasicBlock>
     * ProgramPoint
     * Stmt
    -> 'Lattice

  abstract Join:
       'Lattice
     * 'Lattice
    -> 'Lattice

  abstract Subsume:
       'Lattice
     * 'Lattice
    -> bool

  abstract GetNextVertices:
       IGraph<IRBasicBlock, CFGEdgeKind>
     * IVertex<IRBasicBlock>
    -> VertexID seq

  /// Call this whenever a new vertex is added to the graph
  member __.PushWork (v: IVertex<IRBasicBlock>) = pushWork v.ID

  member __.GetReachingDef (vp: VarPoint) =
    getReachingDef vp.ProgramPoint
    |> ReachingDefDomain.get vp.VarKind

  member __.GetConstant (vp: VarPoint) =
    __.GetReachingDef vp
    |> getConstantFromPps

  member __.SetInitialRegisterValues (regs: Map<RegisterID, BitVector>) =
    regs |> Map.iter (fun regId bv ->
      (* 1. set a virtual reaching definition *)
      let pp = ProgramPoint (0UL, 0)
      let varKind = Regular regId
      let virtualPp = ProgramPoint (0UL, -1)
      let virtualVp = { ProgramPoint = virtualPp; VarKind = varKind }
      let rd = Map.add varKind (Set.singleton virtualVp) ReachingDefDomain.empty
      reachingDefs[pp] <- rd
      (* 2. set an initial value *)
      constants[virtualVp] <- ConstantDomain.Const bv)
