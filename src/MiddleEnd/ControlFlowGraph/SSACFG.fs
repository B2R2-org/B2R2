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

namespace B2R2.MiddleEnd.ControlFlowGraph

open B2R2.BinIR.SSA
open B2R2.MiddleEnd.BinGraph

/// SSA-based CFG, where each node contains disassembly code.
type SSACFG<'E when 'E: equality> =
  IGraph<SSABasicBlock, 'E>

[<RequireQualifiedAccess>]
module SSACFG =
  /// Constructor for SSACFG.
  type IConstructable<'E when 'E: equality> =
    /// Construct an SSACFG.
    abstract Construct: ImplementationType -> SSACFG<'E>

  /// Find SSAVertex that includes the given instruction address.
  [<CompiledName "FindVertexByAddr">]
  let findVertexByAddr (ssaCFG: IGraph<SSABasicBlock, _>) addr =
    ssaCFG.FindVertexBy (fun v ->
      if v.VData.IsAbstract then false
      else v.VData.Range.IsIncluding addr)

  /// Find the definition of the given variable kind (targetVarKind) at the
  /// given node v. We simply follow the dominator tree of the given SSACFG
  /// until we find a definition.
  [<CompiledName "FindDef">]
  let rec findDef (v: IVertex<SSABasicBlock>) targetVarKind =
    let stmtInfo =
      v.VData.LiftedSSAStmts
      |> Array.tryFindBack (fun (_, stmt) ->
        match stmt with
        | Def ({ Kind = k }, _) when k = targetVarKind -> true
        | _ -> false)
    match stmtInfo with
    | Some stmtInfo -> Some (snd stmtInfo)
    | None ->
      match v.VData.ImmDominator with
      | Some idom ->
        findDef idom targetVarKind
      | None -> None

  /// Find the reaching definition of the given variable kind (targetVarKind) at
  /// the entry of node v. We simply follow the dominator tree of the given
  /// SSACFG until we find a definition.
  [<CompiledName "FindReachingDef">]
  let findReachingDef (v: IVertex<SSABasicBlock>) targetVarKind =
    match v.VData.ImmDominator with
    | Some idom ->
      findDef idom targetVarKind
    | None -> None
