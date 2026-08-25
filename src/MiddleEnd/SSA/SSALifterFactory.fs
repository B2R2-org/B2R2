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

namespace B2R2.MiddleEnd.SSA

open System.Collections.Generic
open B2R2
open B2R2.BinIR.SSA
open B2R2.FrontEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

module private SSALifterFactory =
  /// Represents a mapping from a LowUIR CFG vertex to an SSACFG vertex.
  type SSAVMap = Dictionary<IVertex<LowUIRBasicBlock>, SSAVertex>

  /// Lifts the given LowUIR statements to SSA statements.
  let liftStmts (stmtProcessor: IStmtPostProcessor) liftedInstrs =
    let wordSize = stmtProcessor.WordSize |> WordSize.toRegType
    (liftedInstrs: LiftedInstruction[])
    |> Array.collect (fun liftedIns ->
      let stmts = liftedIns.Stmts
      let address = liftedIns.Original.Address
      AST.translateStmts wordSize address stmtProcessor stmts)
    |> Array.map (fun s -> ProgramPoint.Fake, s)

  let translateRegularBlock stmtProcessor (bbl: ILowUIRBasicBlock) =
    let stmts = liftStmts stmtProcessor bbl.LiftedInstructions
    let lastAddr = bbl.LastInstruction.Address
    let endPoint = lastAddr + uint64 bbl.LastInstruction.Length - 1UL
    let ppoint = bbl.PPoint
    SSABasicBlock.CreateRegular(stmts, ppoint, endPoint)

  let liftRundown stmtProcessor rundown =
    if Array.isEmpty rundown then
      [||]
    else
      let memVar = { Kind = MemVar; Identifier = -1 }
      [| (* Safe approximation: memory is always defined. *)
         Def(memVar, Var memVar)
         (* The word size and the address are read only where an ISMark is
            translated, and an ISMark exists only where a real instruction
            was lifted. A rundown is a summary this analysis synthesizes
            rather than lifted code, so neither argument is ever read. *)
         yield! AST.translateStmts 64<rt> 0UL stmtProcessor rundown |]

  let translateAbstractBlock stmtProcessor (bbl: ILowUIRBasicBlock) =
    let calleePpoint = bbl.PPoint
    let absContent = bbl.AbstractContent
    let rundown = absContent.Rundown |> liftRundown stmtProcessor
    let absContent = FunctionSummary<Stmt>(absContent.EntryPoint,
                                           absContent.UnwindingBytes,
                                           rundown,
                                           absContent.IsExternal,
                                           absContent.ReturningStatus)
    SSABasicBlock.CreateAbstract(calleePpoint, absContent)

  let translateBlock stmtProcessor irBlk =
    if (irBlk: ILowUIRBasicBlock).IsAbstract then
      translateAbstractBlock stmtProcessor irBlk
    else
      translateRegularBlock stmtProcessor irBlk

  let getVertex stmtProcessor vMap g (irV: IVertex<LowUIRBasicBlock>) =
    match (vMap: SSAVMap).TryGetValue irV with
    | true, v ->
      v
    | false, _ ->
      let blk = translateBlock stmtProcessor irV.VData
      let ssaV = (g: SSACFG).AddVertex(blk)
      vMap[irV] <- ssaV
      ssaV

  (* Every root of the given CFG becomes a root of the SSA CFG, for a CFG of
     more than one root is an ordinary outcome of a gap analysis, whose dead
     code blocks enter the graph as roots of their own. The roots are the first
     vertices to be translated, so that they keep their order in the SSA CFG. *)
  let convertToSSA stmtProcessor (cfg: LowUIRCFG) (ssaCFG: SSACFG) =
    let vMap = SSAVMap()
    let roots = cfg.Roots |> Array.map (getVertex stmtProcessor vMap ssaCFG)
    cfg |> DiGraph.iterEdge (fun e ->
      let src, dst = e.First, e.Second
      let srcV = getVertex stmtProcessor vMap ssaCFG src
      let dstV = getVertex stmtProcessor vMap ssaCFG dst
      ssaCFG.AddEdge(srcV, dstV, e.Label)
    )
    ssaCFG.SetRoots roots

  let createDominance (g: SSACFG) =
    Dominance.LengauerTarjanDominance.create g
    <| Dominance.CooperDominanceFrontier()

  let create stmtProcessor =
    { new ISSALiftable with
        member _.Lift cfg =
          let ssaCFG = SSACFG.create cfg.ImplementationType
          convertToSSA stmtProcessor cfg ssaCFG
          let dom = createDominance ssaCFG
          SSAForm.build ssaCFG dom
          SSACFGWithDominance(ssaCFG, dom) }

/// Provides ways to create an SSA lifter.
type SSALifterFactory =
  /// Creates an SSA lifter for the given binary.
  static member Create(hdl: BinHandle) =
    let wordSize = hdl.ISA.WordSize
    SSALifterFactory.create
      { new IStmtPostProcessor with
          member _.WordSize with get() = wordSize
          member _.PostProcess stmt = stmt }

  /// Creates an SSA lifter reading its word size off the given statement
  /// post-processor, which every lifted statement is passed through.
  static member Create(stmtProcessor: IStmtPostProcessor) =
    SSALifterFactory.create stmtProcessor
