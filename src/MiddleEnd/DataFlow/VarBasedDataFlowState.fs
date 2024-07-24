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

type VarBasedDataFlowState<'Lattice, 'E when 'E: equality>
  public (hdl, analysis: IVarBasedDataFlowAnalysis<'Lattice, 'E>) =

  let absValues = Dictionary<VarPoint, 'Lattice> ()

  let varDefs = Dictionary<ProgramPoint, VarDefDomain.Lattice> ()

  let constants = Dictionary<VarPoint, ConstantDomain.Lattice> ()

  let incomingPps = Dictionary<ProgramPoint, Set<ProgramPoint>> ()

  let workList = Queue<VertexID> ()

  let workSet = HashSet ()

  let initialConstants = Dictionary<VarKind, ConstantDomain.Lattice> ()

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
    | false, _ -> analysis.Bottom
    | true, v -> v

  let getInitialConstant varKind =
    match initialConstants.TryGetValue varKind with
    | false, _ -> ConstantDomain.Undef
    | true, c -> c

  let initializeInitialConstants () =
    match (hdl: BinHandle).RegisterFactory.StackPointer with
    | None -> ()
    | Some rid ->
      let rt = hdl.RegisterFactory.RegIDToRegType rid
      let varKind = Regular rid
      let bv = BitVector.OfUInt64 Constants.InitialStackPointer rt
      let c = ConstantDomain.Const bv
      initialConstants[varKind] <- c

  let getVarDef (pp: ProgramPoint) =
    match varDefs.TryGetValue pp with
    | false, _ -> VarDefDomain.empty
    | true, rd -> rd

  let calculateIncomingVarDef pp =
    getIncomingPps pp
    |> Seq.map getVarDef
    |> Seq.fold VarDefDomain.join VarDefDomain.empty

  let getConstant vp =
    match constants.TryGetValue vp with
    | false, _ -> ConstantDomain.Undef
    | true, c -> c

  let getConstantFromVps vps =
    vps |> Set.fold (fun acc vp ->
      ConstantDomain.join acc (getConstant vp)) ConstantDomain.Undef

  let getIncomingConstant varKind pp =
    calculateIncomingVarDef pp
    |> VarDefDomain.get varKind
    |> getConstantFromVps

  let calculateConstant vp =
    getConstant vp
    |> function
      | ConstantDomain.Undef -> getInitialConstant vp.VarKind
      | c -> c
    |> function
      | ConstantDomain.Undef ->
        getVarDef vp.ProgramPoint
        |> VarDefDomain.get vp.VarKind
        |> getConstantFromVps
      | c -> c

  let rec evaluateExprIntoConst pp (e: Expr) =
    match e.E with
    | Num bv -> ConstantDomain.Const bv
    | Var _ | TempVar _ ->
      let varKind = VarKind.ofIRExpr e
      match getIncomingConstant varKind pp with
      | ConstantDomain.Undef -> getInitialConstant varKind
      | c -> c
    | Load (_, _, addr) ->
      match evaluateExprIntoConst pp addr with
      | ConstantDomain.Const bv ->
        let addr = BitVector.ToUInt64 bv
        getIncomingConstant (Memory (Some addr)) pp
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

  do initializeInitialConstants ()

  member __.IsWorklistEmpty with get () = isWorklistEmpty ()

  /// Push a work (vertex id) to the worklist in the data flow analysis. Call
  /// this whenever a new vertex is added to the graph.
  member __.PushWork vid = pushWork vid

  member __.PopWork () = popWork ()

  member __.GetVarDef pp = getVarDef pp

  member __.SetVarDef pp vd = varDefs[pp] <- vd

  /// Calculate the incoming var defs to the given program point. Note that we
  /// use outgoing var defs in our lattice.
  member __.CalculateIncomingVarDef pp = calculateIncomingVarDef pp

  /// Remember an incoming program point to the given program point.
  member __.AddIncomingProgramPoint pp incomingPp = addIncomingPp pp incomingPp

  member __.GetConstant vp = getConstant vp

  member __.SetConstant vp c = constants[vp] <- c

  /// Get the abstract value of a variable point, but calculate it if the given
  /// variable point is not defined in the existing statements. We can use this
  /// to calculate the abstract value of a variable after a certain statement.
  member __.CalculateConstant vp = calculateConstant vp

  member __.EvaluateExprIntoConst pp e = evaluateExprIntoConst pp e

  member __.SetAbsValue vp absVal = absValues[vp] <- absVal

  interface IDataFlowState<VarPoint, 'Lattice> with
    member __.GetAbsValue absLoc = getAbsValue absLoc

and IVarBasedDataFlowAnalysis<'Lattice, 'E when 'E: equality> =
  abstract OnInitialize:
       VarBasedDataFlowState<'Lattice, 'E>
    -> VarBasedDataFlowState<'Lattice, 'E>

  abstract Bottom: 'Lattice

  abstract Join:
       'Lattice
    -> 'Lattice
    -> 'Lattice

  abstract Subsume:
       'Lattice
    -> 'Lattice
    -> bool

  abstract Transfer:
       IGraph<IRBasicBlock, 'E>
    -> IVertex<IRBasicBlock>
    -> ProgramPoint
    -> Stmt
    -> VarBasedDataFlowState<'Lattice, 'E>
    -> (VarPoint * 'Lattice) option

  abstract EvalExpr:
       VarBasedDataFlowState<'Lattice, 'E>
    -> ProgramPoint
    -> Expr
    -> 'Lattice

  abstract GetNextVertices:
       IGraph<IRBasicBlock, 'E>
    -> IVertex<IRBasicBlock>
    -> VertexID seq
