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

module IRConstant =
  /// For incremental constant propagation.
  type Domain =
    | Variable of ConstantDomain
    (* we use Addr here since BitVector does not have a comparison property *)
    | Memory of Map<Addr, ConstantDomain>
    (* we use a common Bot to support two different kind of abstract variables:
       Variable and Memory *)
    | Bot

module IRReachingDef =
  /// For incremental reaching definition analysis.
  type Domain = Map<VarKind, Value>
  and Value =
    | Memory of Map<Addr, Set<ProgramPoint>>
    | Variable of Set<ProgramPoint>

  let empty = Map.empty

  let join a b = failwith "TODO"

  let load addr rd =
    rd
    |> Map.tryFind (VarKind.Memory None)
    |> function
      | None -> empty
      | Some (Memory m) -> m
      | _ -> Utils.impossible ()
    |> Map.tryFind addr
    |> function
      | None -> Set.empty
      | Some s -> s

  let store addr pp rd =
    let m =
      match Map.tryFind (VarKind.Memory None) rd with
      | None -> Map.empty
      | Some (Memory m) -> m
      | _ -> Utils.impossible ()
    let pps =
      match Map.tryFind addr m with
      | None -> Set.empty
      | Some s -> s
    let pps = Set.add pp pps
    let v = Memory (Map.add addr pps m)
    Map.add (VarKind.Memory None) v rd

[<AbstractClass>]
type IncrementalDataFlowAnalysis<'Lattice> () as this =
  let absValues = Dictionary<ProgramPoint, 'Lattice> ()
  let reachingDefs = Dictionary<ProgramPoint, IRReachingDef.Domain> ()
  let constants = Dictionary<ProgramPoint, IRConstant.Domain> ()

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

  let getAbsValue (absLoc: ProgramPoint) =
    match absValues.TryGetValue absLoc with
    | false, _ -> this.Bottom
    | true, v -> v

  /////////
  // Etc //
  /////////

  /// TODO: consider two cases:
  /// (1) the beginning of the vertex,
  /// (2) otherwise.
  let getIncomingProgramPoints (pp: ProgramPoint) = failwith "TODO"

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
    | false, _ -> IRReachingDef.empty
    | true, rd -> rd

  /// TODO: memoization
  let calculateIncomingReachingDef pp =
    let incomingPps = getIncomingProgramPoints pp
    let incomingReachingDefs = incomingPps |> Set.map getReachingDef
    let firstIncomingRD = Seq.head incomingReachingDefs
    let otherIncomingRDs = Seq.tail incomingReachingDefs
    Seq.fold IRReachingDef.join firstIncomingRD otherIncomingRDs

  //////////////////////////
  // Constant propagation //
  //////////////////////////

  let getConstant pp =
    match constants.TryGetValue pp with
    | false, _ -> IRConstant.Bot
    | true, c -> c

  /// ProgramPoint -> Expr -> ConstantDomain
  /// Note that this does not return IRConstant.Domain.
  let rec evaluateExprIntoVarConst (pp: ProgramPoint) (e: Expr) =
    match e.E with
    | Num bv -> ConstantDomain.Const bv
    // Use the reaching definition to calculate the value of the variable.
    | Var _ | TempVar _ ->
      let rd = calculateIncomingReachingDef pp (* get the rd state *)
      let varKind = VarKind.ofIRExpr e
      let rdPps = (* fetch its reaching definitions *)
        match Map.tryFind varKind rd with
        | None -> Set.empty
        | Some (IRReachingDef.Variable s) -> s
        | _ -> Utils.impossible ()
      let joinedConst = (* join the values from its reaching definitions *)
        rdPps |> Set.fold (fun acc pp ->
          match getConstant pp with
          | IRConstant.Variable c -> c
          | _ -> Utils.impossible ()
          |> ConstantDomain.join acc) ConstantDomain.Undef
      joinedConst
    // Load the value from the memory.
    | Load (_, _, addr) ->
      let addrVarConst = evaluateExprIntoVarConst pp addr
      match addrVarConst with
      | ConstantDomain.Const bv when intoUInt64 bv ->
        let rd = calculateIncomingReachingDef pp
        let addr = BitVector.ToUInt64 bv
        let memRD = (* get the rd of memory *)
          match Map.tryFind (VarKind.Memory None) rd with (* TODO: make API *)
          | None -> Map.empty
          | Some (IRReachingDef.Memory m) -> m
          | _ -> Utils.impossible ()
        match Map.tryFind addr memRD with
        | None -> ConstantDomain.NotAConst (* TODO: should it be Top or Bot? *)
        | Some rdPps ->
          let joinedConst = (* join the values from its reaching definitions *)
            rdPps |> Set.fold (fun acc pp ->
              match getConstant pp with
              | IRConstant.Variable c -> c
              | _ -> Utils.impossible ()
              |> ConstantDomain.join acc) ConstantDomain.Undef
          joinedConst
      | _ -> ConstantDomain.NotAConst
    | BinOp (BinOpType.ADD, _, e1, e2) ->
      let v1 = evaluateExprIntoVarConst pp e1
      let v2 = evaluateExprIntoVarConst pp e2
      match v1, v2 with
      | ConstantDomain.Const bv1, ConstantDomain.Const bv2 ->
        let bv = bv1 + bv2
        ConstantDomain.Const bv
      | c1, c2 -> ConstantDomain.join c1 c2
    | _ -> failwith "TODO: FILLME"

  member private __.TransferConstant (pp, stmt) =
    match stmt.S with
    | Put (_dst, src) ->
      let srcVarConst = evaluateExprIntoVarConst pp src
      let srcConst = IRConstant.Variable srcVarConst
      constants[pp] <- srcConst
      true
    (* TODO: we do not need to execute the store semantics here, since our
       reaching definition has memory-cell-wise granularity. but still
       we need to check if this store **moves** the current fixpoint *)
    | Store (_, addr, value) ->
      let addrVarConst = evaluateExprIntoVarConst pp addr
      match addrVarConst with
      | ConstantDomain.Const bv when intoUInt64 bv ->
        let valueVarConst = evaluateExprIntoVarConst pp value
        let rd = calculateIncomingReachingDef pp
        let addrToPps =
          match Map.tryFind (VarKind.Memory None) rd with
          | None -> Map.empty
          | Some (IRReachingDef.Memory m) -> m
          | _ -> Utils.impossible ()
        let loc = BitVector.ToUInt64 bv
        match Map.tryFind loc addrToPps with
        | None -> true
        | Some pps ->
          let prevVarConst =
            pps |> Set.fold (fun acc pp ->
              match getConstant pp with
              | IRConstant.Variable c -> c
              | _ -> Utils.impossible ()
              |> ConstantDomain.join acc) ConstantDomain.Undef
          let joinedVarConst = ConstantDomain.join prevVarConst valueVarConst
          not <| ConstantDomain.isNonmonotonic prevVarConst joinedVarConst
      | _ -> false (* cannot determine the memory cell, so skip it *)
    | _ -> failwith "TODO: FILLME"

  /// Transfer function for reaching definition analysis.
  /// Note that a source expression is not used here since reaching definition
  /// analysis does not need to evaluate expressions.
  member private __.TransferReachingDef (pp: ProgramPoint, stmt) =
    let rd = calculateIncomingReachingDef pp
    match stmt.S with
    | Put (dst, _src) ->
      let varKind = VarKind.ofIRExpr dst
      let v = IRReachingDef.Variable (Set.singleton pp)
      let rd = Map.add varKind v rd
      reachingDefs[pp] <- rd
      true
    | Store (_, addr, _value) ->
      match evaluateExprIntoVarConst pp addr with
      | ConstantDomain.Const bv when intoUInt64 bv ->
        let loc = BitVector.ToUInt64 bv
        let rd = IRReachingDef.store loc pp rd
        reachingDefs[pp] <- rd
        true
      | _ -> false
    | _ -> failwith "TODO"

  /// TODO: is it efficient to transfer the two different domains w/ cross
  /// product?
  member private __.TransferConstantAndReachingDef (pp, stmt) =
    let constantChanged = __.TransferConstant (pp, stmt)
    let reachingDefChanged = __.TransferReachingDef (pp, stmt)
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
          if __.TransferConstantAndReachingDef (pp, stmt) then dirty <- true
          let absValue = __.Transfer (g, v, pp, stmt)
          if __.Subsume (getAbsValue pp, absValue) then ()
          else
            absValues[pp] <- absValue
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

  abstract Subsume: 'Lattice * 'Lattice -> bool

  abstract GetNextVertices:
       IGraph<IRBasicBlock, CFGEdgeKind>
     * IVertex<IRBasicBlock>
    -> VertexID seq

  /// Call this whenever a new vertex is added to the graph
  member __.PushWork (v: IVertex<IRBasicBlock>) = pushWork v.ID
