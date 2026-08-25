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

namespace B2R2.MiddleEnd.SSA.Tests

open B2R2
open B2R2.BinIR.SSA
open B2R2.FrontEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Provides the sample binary every SSA test lifts, along with the readers a
/// test needs to state what it expects of the lifted graph.
[<AutoOpen>]
module Helper =
  /// A raw x86-64 snippet shaped as a diamond, which is the smallest shape a
  /// phi can be asked for. It stores to a stack slot on both arms and reads
  /// the slot back at the join, so the join is a dominance frontier of both
  /// arms and the lifter has to place a phi there.
  ///
  /// 00: 55                    push rbp
  /// 01: 48 89 e5              mov  rbp, rsp
  /// 04: 89 7d fc              mov  [rbp-4], edi
  /// 07: 83 7d fc 00           cmp  dword [rbp-4], 0
  /// 0b: 7e 09                 jle  0x16
  /// 0d: c7 45 f8 01 00 00 00  mov  dword [rbp-8], 1
  /// 14: eb 07                 jmp  0x1d
  /// 16: c7 45 f8 02 00 00 00  mov  dword [rbp-8], 2
  /// 1d: 8b 45 f8              mov  eax, [rbp-8]
  /// 20: 5d                    pop  rbp
  /// 21: c3                    ret
  let binary =
    ByteArray.ofHexString
      "554889e5897dfc837dfc007e09c745f801000000eb07c745f8020000008b45f85dc3"

  /// The address of the block the two arms of the diamond join into.
  let joinAddr = 0x1dUL

  let isa = ISA(Architecture.Intel, WordSize.Bit64)

  let hdl = BinHandle.LoadRawImage(binary, isa)

  let private instrs =
    InstructionCollection(LinearSweepInstructionCollector hdl)

  /// Builds the LowUIR CFG of the sample binary. The blocks are scanned from
  /// the entry point, so the diamond comes out of the scan whole, and the
  /// edges are then spelled out here rather than recovered, which keeps a test
  /// of the lifter from turning into a test of CFG recovery.
  let buildDiamondCFG t =
    let bblFactory = BBLFactory(hdl, instrs)
    bblFactory.ScanBBLs [| 0x00UL |]
    |> Async.AwaitTask
    |> Async.RunSynchronously
    |> ignore
    let cfg = LowUIRCFG.create t
    let entry = cfg.AddVertex(bblFactory.Find(ProgramPoint(0x00UL, 0)))
    let thenV = cfg.AddVertex(bblFactory.Find(ProgramPoint(0x0dUL, 0)))
    let elseV = cfg.AddVertex(bblFactory.Find(ProgramPoint(0x16UL, 0)))
    let joinV = cfg.AddVertex(bblFactory.Find(ProgramPoint(joinAddr, 0)))
    cfg.AddEdge(entry, thenV, InterCJmpFalseEdge)
    cfg.AddEdge(entry, elseV, InterCJmpTrueEdge)
    cfg.AddEdge(thenV, joinV, InterJmpEdge)
    cfg.AddEdge(elseV, joinV, FallThroughEdge)
    cfg.SetRoots [ entry ]
    cfg

  /// Returns every statement of the given SSA graph.
  let statementsOf (g: SSACFG) =
    g.Vertices
    |> Array.collect (fun v -> v.VData.Internals.Statements)
    |> Array.map snd

  /// Returns the address expression of every memory store of the given graph.
  let storeAddressesOf g =
    statementsOf g
    |> Array.choose (fun stmt ->
      match stmt with
      | Def(_, Store(_, _, addr, _)) -> Some addr
      | _ -> None)

  /// Returns how many phis the given vertex carries.
  let phiCountOf (v: IVertex<SSABasicBlock>) =
    v.VData.Internals.Statements
    |> Array.sumBy (fun (_, stmt) ->
      match stmt with
      | Phi _ -> 1
      | _ -> 0)

  let rec private variablesOfExpr expr =
    match expr with
    | Num _ | Undefined _ | FuncName _ ->
      []
    | Var v ->
      [ v ]
    | ExprList exprs ->
      exprs |> List.collect variablesOfExpr
    | Load(v, _, e) ->
      v :: variablesOfExpr e
    | Store(v, _, addr, e) ->
      v :: variablesOfExpr addr @ variablesOfExpr e
    | Cast(_, _, e)
    | UnOp(_, _, e)
    | Extract(e, _, _) ->
      variablesOfExpr e
    | BinOp(_, _, lhs, rhs)
    | RelOp(_, _, lhs, rhs) ->
      variablesOfExpr lhs @ variablesOfExpr rhs
    | Ite(cond, _, lhs, rhs) ->
      variablesOfExpr cond @ variablesOfExpr lhs @ variablesOfExpr rhs

  let private variablesOfJmp jmpTy =
    match jmpTy with
    | IntraJmp _ ->
      []
    | IntraCJmp(e, _, _)
    | InterJmp e ->
      variablesOfExpr e
    | InterCJmp(cond, t1, t2) ->
      variablesOfExpr cond @ variablesOfExpr t1 @ variablesOfExpr t2

  /// Returns every variable the given statement defines or uses.
  let variablesOf stmt =
    match stmt with
    | LMark _ | SideEffect _ ->
      []
    | ExternalCall(e, inVars, outVars) ->
      variablesOfExpr e @ inVars @ outVars
    | Jmp jmpTy ->
      variablesOfJmp jmpTy
    | Def(def, e) ->
      def :: variablesOfExpr e
    | Phi(def, _) ->
      [ def ]
