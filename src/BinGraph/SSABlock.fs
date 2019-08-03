(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

namespace B2R2.BinGraph

open B2R2
open B2R2.BinIR

module SSABlockHelper =
  let private updateDefinedVar set = function
    | LowUIR.Put (LowUIR.Var (_) as dst, _) ->
      Set.add (SSA.AST.translateDest dst) set
    | LowUIR.Store (_) ->
      Set.add ({ Kind = SSA.MemVar; Identifier = -1 }) set
    | _ -> set

  let private defVarFolder acc (v: Vertex<IRBasicBlock>) =
    v.VData.GetIRStatements ()
    |> Array.fold (fun acc stmts -> Array.fold updateDefinedVar acc stmts) acc

  /// This is currently intra-procedural.
  let computeDefinedVars (scfg: SCFG) addr =
    try
      let g, root = scfg.GetFunctionCFG addr
      g.FoldVertexDFS root defVarFolder Set.empty
      |> Set.toArray
    with _ -> [||]

/// Basic block type for an SSA-based CFG (SSACFG).
type SSABBlock (scfg, pp: ProgramPoint, pairs: InsIRPair []) =
  inherit BasicBlock ()
  let mutable stmts =
    if Array.isEmpty pairs then
      SSABlockHelper.computeDefinedVars scfg pp.Address
      |> Array.map (fun dst -> SSA.Def (dst, SSA.Return (pp.Address)))
    else
      pairs
      |> Array.map (fun (i, stmts) ->
        let wordSize = i.WordSize |> WordSize.toRegType
        stmts |> SSA.AST.translateStmts wordSize i.Address)
      |> Array.concat

  let mutable frontier: Vertex<SSABBlock> list = []

  override __.PPoint = pp

  override __.Range =
    let last = pairs.[pairs.Length - 1] |> fst
    AddrRange (last.Address, last.Address + uint64 last.Length)

  override __.IsDummyBlock () = Array.isEmpty pairs

  override __.ToVisualBlock (_) =
    __.Stmts
    |> Array.toList
    |> List.map (fun stmt -> [ SSA.Pp.stmtToString stmt |> String ])

  member __.Stmts with get () = stmts and set (v) = stmts <- v

  member __.Frontier with get () = frontier and set(v) = frontier <- v

  member __.InsertPhi varKind count =
    let var = { SSA.Kind = varKind; SSA.Identifier = -1 }
    stmts <- Array.append [| SSA.Phi (var, Array.zeroCreate count) |] stmts
