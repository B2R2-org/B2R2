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
open B2R2.ABI
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Represents where a value comes from, as far as the pointers that a function
/// gets in its argument registers go.
type private Provenance =
  /// Nothing reaches here yet.
  | NoValue
  /// A value that comes from no argument, such as a constant or the address
  /// of a stack slot.
  | Unrelated
  /// What the argument register holds on entry plus the given offset.
  | ArgPlus of RegisterID * int64
  /// What the argument register holds on entry plus an offset that nothing
  /// tells, such as an index.
  | ArgAround of RegisterID
  /// A value that may come from any argument.
  | AnyArg

[<RequireQualifiedAccess>]
module private Provenance =
  /// Joins two values. A value that comes from an argument along one way and
  /// from no argument, or from the same argument at another offset, along
  /// another comes from it at an offset that nothing tells.
  let join a b =
    match a, b with
    | NoValue, x | x, NoValue ->
      x
    | _ when a = b ->
      a
    | AnyArg, _ | _, AnyArg ->
      AnyArg
    | (ArgPlus(r1, _) | ArgAround r1), (ArgPlus(r2, _) | ArgAround r2)
      when r1 <> r2 ->
      AnyArg
    | (ArgPlus(r, _) | ArgAround r), _ | _, (ArgPlus(r, _) | ArgAround r) ->
      ArgAround r
    | _ ->
      Unrelated

  /// Turns the given value into one at an offset that nothing tells from
  /// where it comes, if it comes from an argument.
  let loseOffset v =
    match v with
    | ArgPlus(r, _) -> ArgAround r
    | _ -> v

  /// Adds the given constant to the given value.
  let addConst v (bv: BitVector) =
    match v with
    | ArgPlus(r, k) when bv.Length < 64<rt> ->
      ArgPlus(r, k + BitVector.SExt(bv, 64<rt>).ToInt64())
    | ArgPlus(r, k) when bv.Length = 64<rt> ->
      ArgPlus(r, k + bv.ToInt64())
    | _ ->
      loseOffset v

  /// Combines the operands of an operation other than one that adds a
  /// constant, which leaves the offset of a pointer unknown.
  let combine a b = join (loseOffset a) (loseOffset b)

/// Traces where the values of a function come from, as far as the pointers
/// that it gets in its argument registers go, through the definitions that
/// the data flow of the function chains, on demand. A pointer that the
/// function loads from memory other than its stack, or that a callee returns,
/// comes from no argument as far as this goes.
type private ProvenanceTracer(state: LowUIRSparseDataFlow.State<_>, args) =
  let values = Dictionary<VarPoint, Provenance>()

  let readers = Dictionary<VarPoint, HashSet<VarPoint>>()

  let worklist = Queue<VarPoint>()

  let getBaseCase vk =
    match vk with
    | Regular rid when Array.contains rid args -> ArgPlus(rid, 0L)
    | _ -> Unrelated

  (* Reads the value of a definition for the given reader, which the solver
     reads again whenever the definition grows. *)
  let readDef reader (def: VarPoint) =
    if def.ProgramPoint.IsFake then
      getBaseCase def.VarKind
    else
      if not (values.ContainsKey def) then
        values[def] <- NoValue
        readers[def] <- HashSet()
        worklist.Enqueue def
      else
        ()
      if reader.ProgramPoint.IsFake then () (* a query, not a definition *)
      else readers[def].Add reader |> ignore
      values[def]

  let readUse reader pp vk =
    match state.UseDefMap.TryGetValue { ProgramPoint = pp; VarKind = vk } with
    | true, def -> readDef reader def
    | false, _ -> Unrelated

  (* The data flow knows a register that holds zero, such as the zero register
     of MIPS, with which MIPS copies a register. *)
  let isZero pp e =
    match state.EvaluateAddressExpr(pp, e) with
    | AddressDomain.Const bv -> bv.IsZero
    | _ -> false

  let rec evaluate reader pp e =
    match e with
    | Var _ | TempVar _ ->
      readUse reader pp (VarKind.ofIRExpr e)
    | Load(Addr = addr) ->
      match state.EvaluateAddressExpr(pp, addr) with
      | AddressDomain.StackAddr off ->
        readUse reader pp (StackLocal(LowUIRAddress.toFrameOffset off))
      | _ ->
        Unrelated
    | BinOp(Op = BinOpType.ADD; Left = Num(Value = bv); Right = e)
    | BinOp(Op = BinOpType.ADD; Left = e; Right = Num(Value = bv)) ->
      Provenance.addConst (evaluate reader pp e) bv
    | BinOp(Op = BinOpType.SUB; Left = e; Right = Num(Value = bv)) ->
      Provenance.addConst (evaluate reader pp e) (-bv)
    | BinOp(Op = BinOpType.ADD | BinOpType.OR | BinOpType.XOR
            Left = z
            Right = e) when isZero pp z ->
      evaluate reader pp e
    | BinOp(Op = BinOpType.ADD | BinOpType.OR | BinOpType.XOR | BinOpType.SUB
            Left = e
            Right = z) when isZero pp z ->
      evaluate reader pp e
    | BinOp(Left = e1; Right = e2) ->
      let v1 = evaluate reader pp e1
      Provenance.combine v1 (evaluate reader pp e2)
    | Extract(Operand = e) | Cast(Operand = e) ->
      evaluate reader pp e
    | Ite(TrueExpr = e1; FalseExpr = e2) ->
      let v1 = evaluate reader pp e1
      Provenance.join v1 (evaluate reader pp e2)
    | _ ->
      Unrelated

  (* A definition that is neither a phi nor a statement of the function, such
     as the one of a stack slot that a callee may write, comes from no
     argument. *)
  let evaluateDef (def: VarPoint) =
    match state.TryGetPhiOperands def with
    | Some operands ->
      operands
      |> Array.fold (fun acc op -> Provenance.join acc (readDef def op)) NoValue
    | None ->
      let pp = def.ProgramPoint
      match state.StmtOfBBLs.TryGetValue pp with
      | true, (Put(Src = src), _) -> evaluate def pp src
      | true, (Store(Value = value), _) -> evaluate def pp value
      | _ -> Unrelated

  let rec solve () =
    match worklist.TryDequeue() with
    | true, def ->
      let prev = values[def]
      let curr = Provenance.join prev (evaluateDef def)
      if curr <> prev then
        values[def] <- curr
        for reader in readers[def] do worklist.Enqueue reader
      else
        ()
      solve ()
    | false, _ ->
      ()

  /// Finds where the given expression, which the statement at pp reads, comes
  /// from.
  member _.Evaluate(pp, e) =
    let root = { ProgramPoint = ProgramPoint.Fake; VarKind = Memory }
    evaluate root pp e |> ignore
    solve ()
    evaluate root pp e

  /// Finds where the given register comes from as the given vertex starts.
  member _.EvaluateAtStart(v: IVertex<LowUIRBasicBlock>, rid) =
    let vk = Regular rid
    match state.PerVertexIncomingDefs.TryGetValue v with
    | true, defs when Map.containsKey vk defs ->
      let root = { ProgramPoint = ProgramPoint.Fake; VarKind = Memory }
      readDef root defs[vk] |> ignore
      solve ()
      readDef root defs[vk]
    | _ ->
      getBaseCase vk

[<RequireQualifiedAccess>]
module private PointerWriteHelper =
  /// Checks if the function ends where the recovery cannot follow it, such as
  /// an indirect jump to targets that it does not know, which may then write
  /// anything.
  let hasUnknownExit (ctx: CFGBuildingContext<_, _>) =
    ctx.CFG.Exits
    |> Array.exists (fun v ->
      let blk = v.VData.Internals
      not blk.IsAbstract
      && not (ctx.GapAnalysisVertices.Contains blk.PPoint)
      && blk.LastInstruction.IsIndirectBranch
      && not blk.LastInstruction.IsRET)

  /// Gets the registers in which the calling convention passes arguments.
  let getArgRegisters (hdl: BinHandle) =
    hdl.Conventions.Calling.IntArgs
    |> Array.choose (function
      | ArgLocation.Reg rid -> Some rid
      | _ -> None)

  /// Joins two extents of what the function writes through one pointer.
  let join e1 e2 =
    match e1, e2 with
    | WrittenBytes(lo1, hi1), WrittenBytes(lo2, hi2) ->
      WrittenBytes(min lo1 lo2, max hi1 hi2)
    | _ ->
      AnyBytes

  let add (acc: Dictionary<RegisterID, WriteExtent>) rid extent =
    match acc.TryGetValue rid with
    | true, prev -> acc[rid] <- join prev extent
    | false, _ -> acc[rid] <- extent

  /// Shifts the given extent of writes by the given offset, unless that moves
  /// it out of what an extent holds.
  let shift (k: int64) extent =
    match extent with
    | WrittenBytes(lo, hi) when abs k < 0x10000L ->
      WrittenBytes(lo + int k, hi + int k)
    | _ ->
      AnyBytes

  /// Notes that the function writes the given extent of bytes through a value
  /// that comes from where the given provenance tells.
  let noteWrite args acc provenance extent =
    match provenance with
    | ArgPlus(rid, k) -> add acc rid (shift k extent)
    | ArgAround rid -> add acc rid AnyBytes
    | AnyArg -> for rid in args do add acc rid AnyBytes
    | NoValue | Unrelated -> ()

  /// Notes what the call at the given vertex writes through the pointers that
  /// the function hands it.
  let noteCall (tracer: ProvenanceTracer) args acc v =
    let summary = (v: IVertex<LowUIRBasicBlock>).VData.Internals.AbstractContent
    for callArg in args do
      let extent =
        match summary.PointerWrites with
        | UnknownPointerWrites -> Some AnyBytes
        | PointerWritesOf extents -> Map.tryFind callArg extents
      match extent with
      | Some extent ->
        noteWrite args acc (tracer.EvaluateAtStart(v, callArg)) extent
      | None ->
        ()

  /// Checks if the data flow knows the address that the store at pp writes,
  /// a stack slot or a fixed one, which no argument points to.
  let isKnownAddress (state: LowUIRSparseDataFlow.State<_>) pp addr =
    match state.EvaluateAddressExpr(pp, addr) with
    | AddressDomain.StackAddr _ | AddressDomain.Const _ -> true
    | _ -> false

  /// Notes what the stores of the given vertex write through the pointers
  /// that the function gets.
  let noteStores state (tracer: ProvenanceTracer) args acc v =
    for stmt, pp in (state: LowUIRSparseDataFlow.State<_>).GetStmtInfos v do
      match stmt with
      | Store(Addr = addr; Value = v) when not (isKnownAddress state pp addr) ->
        let extent = WrittenBytes(0, RegType.toByteWidth (Expr.typeOf v))
        noteWrite args acc (tracer.Evaluate(pp, addr)) extent
      | _ ->
        ()

  /// Computes what the function writes through the pointers it gets, along
  /// the chains of its constant propagation.
  let compute (ctx: CFGBuildingContext<_, _>) =
    if hasUnknownExit ctx then
      UnknownPointerWrites
    else
      let args = getArgRegisters ctx.BinHandle
      let state = ctx.CP.State
      if Seq.isEmpty state.PendingVertices then ()
      else (ctx.CP :> IDataFlowComputable<_, _, _>).Compute ctx.CFG |> ignore
      let tracer = ProvenanceTracer(state, args)
      let acc = Dictionary()
      for v in ctx.CFG.Vertices do
        if v.VData.Internals.IsAbstract then noteCall tracer args acc v
        else noteStores state tracer args acc v
      acc |> Seq.map (fun (KeyValue(rid, e)) -> rid, e) |> Map.ofSeq
      |> PointerWritesOf

/// Finds what a function writes through the pointers that it gets in its
/// argument registers: the bytes that it stores at a constant offset from
/// where one points as it gets it, or any bytes when an index takes part, and
/// what the functions it hands one on to write through it. A caller then
/// forgets only those bytes of an object on its stack that it hands on. The
/// context keeps the safe default, which lets a function write anything,
/// when this analysis does not run or when the function ends where the
/// recovery cannot follow it. The analysis runs once the callers of the
/// function need it, rather than every time the function ends.
type PointerWriteAnalysis() =
  interface ICFGAnalysis<unit -> unit> with
    member _.Unwrap env =
      fun () ->
        let ctx = env.Context
        ctx.SetPointerWrites(lazy (PointerWriteHelper.compute ctx))
