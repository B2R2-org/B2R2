(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Soomin Kim <soomink@kaist.ac.kr>
          Sang Kil Cha <sangkilc@kaist.ac.kr>

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

module B2R2.BinGraph.CFGUtils

open B2R2
open B2R2.BinFile
open B2R2.FrontEnd
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open System.Text
open System.Collections.Generic

let isExecutable hdl addr =
  match hdl.FileInfo.GetSections addr |> Seq.tryHead with
  | Some s -> s.Kind = SectionKind.ExecutableSection
  | _ -> false

let accumulateBBLs (bbls: Dictionary<_, _>) addr = function
  | Error () -> bbls
  | Ok bbl ->
    bbls.[addr] <- bbl
    bbls

let rec buildDisasmBBLAux (builder: CFGBuilder) sAddr addr eAddr instrs =
  if addr = eAddr then
    if List.length instrs = 0 then Error ()
    else
      let addrRange = AddrRange (sAddr, eAddr)
      let last = List.head instrs
      let instrs = List.rev instrs
      Ok <| DisasmBBL (addrRange, instrs, last)
  else
    let instr = builder.GetInstr addr
    let nextAddr = addr + uint64 instr.Length
    let instrs = instr :: instrs
    buildDisasmBBLAux builder sAddr nextAddr eAddr instrs

let rec buildDisasmBBLs hdl (builder: CFGBuilder) bbls = function
  | (sAddr, eAddr) :: boundaries ->
    let bbls =
      buildDisasmBBLAux builder sAddr sAddr eAddr []
      |> accumulateBBLs bbls sAddr
    buildDisasmBBLs hdl builder bbls boundaries
  | [] -> bbls

let inline getNextPpoint (addr, cnt) = function
  | IEMark (addr) -> addr, 0
  | _ -> addr, cnt + 1

let rec buildIRBBLAux (builder: CFGBuilder) sPpoint ppoint ePpoint stmts =
  if ppoint = ePpoint then
    let last = builder.GetStmt ppoint
    let stmts = List.rev (last :: stmts)
    Ok <| IRBBL (sPpoint, ppoint, stmts, last)
  else
    let stmt = builder.GetStmt ppoint
    let nextPpoint = getNextPpoint ppoint stmt
    let stmts = stmt :: stmts
    buildIRBBLAux builder sPpoint nextPpoint ePpoint stmts

let rec buildIRBBLs hdl (builder: CFGBuilder) bbls = function
  | (sPpoint, ePpoint) :: boundaries ->
    let bbls =
      buildIRBBLAux builder sPpoint sPpoint ePpoint []
      |> accumulateBBLs bbls sPpoint
    buildIRBBLs hdl builder bbls boundaries
  | [] -> bbls

let inline private getBranchTarget (instr: Instruction) =
  instr.DirectBranchTarget () |> Utils.tupleToOpt

let getDisasmSuccessors hdl (builder: CFGBuilder) leader edges (bbl: DisasmBBL) =
  let last = bbl.LastInstr
  let next = last.Address + uint64 last.Length
  if last.IsExit () then
    if last.IsCall () then
      [next], (leader, Some (next, JmpEdge)) :: edges
    elif last.IsDirectBranch () then
      match getBranchTarget last with
      | Some addr when not <| builder.IsInteresting hdl addr -> [], edges
      | Some addr ->
        if last.IsCondBranch () then
          if last.IsCJmpOnTrue () then
            [addr ; next], (leader, Some (addr, CJmpFalseEdge)) ::
                              (leader, Some (next, CJmpTrueEdge)) :: edges
          else
            [addr ; next], (leader, Some (addr, CJmpTrueEdge)) ::
                              (leader, Some (next, CJmpFalseEdge)) :: edges
        else [addr], (leader, Some (addr, JmpEdge)) :: edges
      | None -> [], edges
    elif last.IsIndirectBranch () then [], (leader, None) :: edges
    elif last.IsInterrupt () then
      [next], (leader, Some (next, JmpEdge)) :: edges
    else [], edges
  else [next], (leader, Some (next, JmpEdge)) :: edges

let rec addDisasmVertex hdl (builder: CFGBuilder) funcset (bbls: Dictionary<Addr, DisasmBBL>) (g: DisasmCFG) entry edges leader =
  match builder.GetEntryByDisasmLeader leader with
  | None ->
    if leader <> entry && Set.contains leader funcset then edges
    else
      builder.UpdateEntryOfDisasmBoundary leader entry
      let bbl = bbls.[leader]
      let v = g.AddVertex bbl
      let targets, edges = getDisasmSuccessors hdl builder leader edges bbl
      List.fold (addDisasmVertex hdl builder funcset bbls g entry) edges targets
  | Some entry_ when entry = entry_ -> edges
  | Some entry -> edges /// XXX: Need to merge functions here

let belongSameDisasm (builder: CFGBuilder) sAddr dAddr =
  let sEntry = builder.GetEntryByDisasmLeader sAddr
  let dEntry = builder.GetEntryByDisasmLeader dAddr
  match sEntry, dEntry with
  | Some sEntry, Some dEntry when sEntry = dEntry -> true
  | _ -> false

let rec addDisasmEdges builder (bbls: Dictionary<Addr, DisasmBBL>) (g: DisasmCFG) = function
  | [] -> ()
  | (src, Some (dst, edgeType)) :: edges ->
    if belongSameDisasm builder src dst then
      let s = g.FindVertexByData bbls.[src]
      let d = g.FindVertexByData bbls.[dst]
      g.AddEdge s d edgeType
      addDisasmEdges builder bbls g edges
    else addDisasmEdges builder bbls g edges
  | (src, None) :: edges ->
    let s = g.FindVertexByData bbls.[src]
    s.VData.ToResolve <- true
    addDisasmEdges builder bbls g edges

let buildDisasmCFG hdl (builder: CFGBuilder) (cfg: DisasmCFG) funcset bbls entry =
  addDisasmVertex hdl builder funcset bbls cfg entry [] entry
  |> addDisasmEdges builder bbls cfg

let rec buildDisasmCFGs hdl builder (funcs: Funcs) funcset bbls = function
  | entry :: entries ->
    let cfg = funcs.[entry].DisasmCFG
    buildDisasmCFG hdl builder cfg funcset bbls entry
    let bbl = bbls.[entry]
    if cfg.Size () <> 0 then cfg.FindVertexByData bbl |> cfg.SetRoot else ()
    buildDisasmCFGs hdl builder funcs funcset bbls entries
  | [] -> builder

let rec getNextAddr (builder: CFGBuilder) ppoint =
  match builder.GetStmt ppoint with
  | IEMark addr -> addr
  | stmt -> getNextAddr builder <| getNextPpoint ppoint stmt

let getIRSuccessors hdl (builder: CFGBuilder) leader edges (bbl: IRBBL) =
  match bbl.LastStmt with
  | Jmp (Name symbol) ->
    let addr, _ = bbl.LastPpoint
    let ppoint = builder.FindPPointByLabel addr symbol
    [ppoint], (leader, Some (ppoint, JmpEdge)) :: edges
  | CJmp (_, Name tSymbol, Name fSymbol) ->
    let addr, _ = bbl.LastPpoint
    let tPpoint = builder.FindPPointByLabel addr tSymbol
    let fPpoint = builder.FindPPointByLabel addr fSymbol
    [tPpoint ; fPpoint], (leader, Some (tPpoint, CJmpTrueEdge)) ::
                            (leader, Some (fPpoint, CJmpFalseEdge)) :: edges
  | CJmp (_, Name tSymbol, _) ->
    let addr, _ = bbl.LastPpoint
    let tPpoint = builder.FindPPointByLabel addr tSymbol
    [tPpoint], (leader, Some (tPpoint, CJmpTrueEdge)) :: (leader, None) :: edges
  | CJmp (_, _, Name fSymbol) ->
    let addr, _ = bbl.LastPpoint
    let fPpoint = builder.FindPPointByLabel addr fSymbol
    [fPpoint], (leader, Some (fPpoint, CJmpFalseEdge)) :: (leader, None) :: edges
  | InterJmp (_, Num bv, InterJmpInfo.IsCall) ->
    let addr = getNextAddr builder bbl.LastPpoint
    [(addr, 0)], (leader, Some ((addr, 0), FallThroughEdge)) :: edges
  | InterJmp (_, Num bv, _) ->
    let addr = BitVector.toUInt64 bv
    if isExecutable hdl addr then
      [(addr, 0)], (leader, Some ((addr, 0), JmpEdge)) :: edges
    else [], edges
  | InterCJmp (_, _, Num tBv, Num fBv) ->
    let tAddr = BitVector.toUInt64 tBv
    let fAddr = BitVector.toUInt64 fBv
    [(tAddr, 0) ; (fAddr, 0)], (leader, Some ((tAddr, 0), CJmpTrueEdge)) ::
                                  (leader, Some ((fAddr, 0), CJmpFalseEdge)) :: edges
  | Jmp _ | CJmp _ | InterJmp _ | InterCJmp _ -> [], (leader, None) :: edges
  | SideEffect Halt -> [], edges
  | (SideEffect SysCall) as stmt ->
    let next = getNextPpoint bbl.LastPpoint stmt
    [next], (leader, Some (next, FallThroughEdge)) :: edges
  | stmt ->
    let next = getNextPpoint bbl.LastPpoint stmt
    [next], (leader, Some (next, JmpEdge)) :: edges

let rec addIRVertex hdl (builder: CFGBuilder) funcset (bbls: Dictionary<PPoint, IRBBL>) (g: IRCFG) entry edges leader =
  match builder.GetEntryByIRLeader leader with
  | None ->
    if leader <> (entry, 0) && Set.contains (fst leader) funcset then edges
    else
      builder.UpdateEntryOfIRBoundary leader entry
      let bbl = bbls.[leader]
      let v = g.AddVertex bbl
      let targets, edges = getIRSuccessors hdl builder leader edges bbl
      List.fold (addIRVertex hdl builder funcset bbls g entry) edges targets
  | Some entry_ when entry = entry_ -> edges
  | Some entry -> edges

let belongSameIR (builder: CFGBuilder) sAddr dAddr =
  let sEntry = builder.GetEntryByIRLeader sAddr
  let dEntry = builder.GetEntryByIRLeader dAddr
  match sEntry, dEntry with
  | Some sEntry, Some dEntry when sEntry = dEntry -> true
  | _ -> false

let rec addIREdges builder (bbls: Dictionary<PPoint, IRBBL>) (g: IRCFG) = function
  | [] -> ()
  | (src, Some (dst, edgeType)) :: edges ->
    if belongSameIR builder src dst then
      let s = g.FindVertexByData bbls.[src]
      let d = g.FindVertexByData bbls.[dst]
      g.AddEdge s d edgeType
      addIREdges builder bbls g edges
    else addIREdges builder bbls g edges
  | (src, None) :: edges ->
    let s = g.FindVertexByData bbls.[src]
    s.VData.SetToResolve true
    addIREdges builder bbls g edges

let buildIRCFG hdl (builder: CFGBuilder) (cfg: IRCFG) funcset bbls entry =
  addIRVertex hdl builder funcset bbls cfg entry [] (entry, 0)
  |> addIREdges builder bbls cfg

let rec buildIRCFGs hdl builder (funcs: Funcs) funcset bbls = function
  | entry :: entries ->
    let cfg = funcs.[entry].IRCFG
    buildIRCFG hdl builder cfg funcset bbls entry
    let bbl = bbls.[(entry, 0)]
    if cfg.Size () <> 0 then cfg.FindVertexByData bbl |> cfg.SetRoot else ()
    buildIRCFGs hdl builder funcs funcset bbls entries
  | [] -> builder

let buildCFGs hdl (builder: CFGBuilder) (funcs: Funcs) =
  let disasmBBLs = Dictionary<Addr, DisasmBBL> ()
  let disasmBBLs =
    buildDisasmBBLs hdl builder disasmBBLs <| builder.GetDisasmBoundaries ()
  let irBBLs = Dictionary<PPoint, IRBBL> ()
  let irBBLs = buildIRBBLs hdl builder irBBLs <| builder.GetIRBoundaries ()
  let entries = funcs.Keys |> Seq.toList
  let funcset = Set.ofList entries
  let builder = buildDisasmCFGs hdl builder funcs funcset disasmBBLs entries
  let builder = buildIRCFGs hdl builder funcs funcset irBBLs entries
  builder, funcs

/// This is our primary API
let construct hdl = function
  | Some entryAddrs ->
    let builder = CFGBuilder ()
    let funcs = Funcs ()
    (builder, funcs)
    ||> Boundary.identifyWithEntries hdl entryAddrs
    ||> buildCFGs hdl
  | None ->
    let builder = CFGBuilder ()
    let funcs = Funcs ()
    (builder, funcs)
    ||> Boundary.identify hdl
    ||> buildCFGs hdl

let hasCall (bbl: IRVertexData) =
  let b, stmt = bbl.GetLastStmt ()
  if b then
    match stmt with
    | InterJmp (_, _, InterJmpInfo.IsCall) -> true
    | _ -> false
  else false

let tryGetCallTarget (bbl: IRVertexData) =
  let b, stmt = bbl.GetLastStmt ()
  if b then
    match stmt with
    | InterJmp (_, Num bv, _) -> Some <| BitVector.toUInt64 bv
    | _ -> None
  else None

let callVertexFinder addr (v: IRVertex) =
  let vData = v.VData
  let b, target = vData.GetTarget ()
  if b then addr = target else false

let getCallVertex (irCFG: IRCFG) addr =
  match irCFG.TryFindVertexBy (callVertexFinder addr) with
  | Some v -> v
  | None ->
    let vData = IRCall (addr)
    irCFG.AddVertex vData

/// XXX: Need refactoring
let tryFindFallThrough (irCFG: IRCFG) (v: IRVertex) =
  List.fold (fun acc w ->
    match irCFG.FindEdge v w with
    | FallThroughEdge -> Some w
    | _ -> None) None v.Succs

let addIRCall irCFG v vData =
  if hasCall vData then
    match tryGetCallTarget vData, tryFindFallThrough irCFG v with
    | Some addr, Some fallThrough ->
      let callV = getCallVertex irCFG addr
      irCFG.AddEdge v callV CallEdge
      irCFG.AddEdge callV fallThrough RetEdge
    | _ -> ()

let analIRCallsAux irCFG (v: IRVertex) =
  let vData = v.VData
  if vData.IsBBL () then addIRCall irCFG v vData

let analIRCalls (func: Function) =
  let cfg = func.IRCFG
  cfg.IterVertex (analIRCallsAux cfg)

let analCalls funcs =
  Seq.iter (fun (KeyValue(_, func)) -> analIRCalls func) funcs
  funcs

let addCallGraphEdge hdl (funcs: Funcs) (callGraph: CallGraph) (func: Function) =
  func.IRCFG.IterVertex (fun (v: IRVertex) ->
    let vData = v.VData
    if not <| vData.IsBBL () then
      let _, target = vData.GetTarget ()
      if isExecutable hdl target then
        let target = funcs.[target]
        let src = callGraph.FindVertexByData func
        let dst = callGraph.FindVertexByData target
        callGraph.AddEdge src dst CGCallEdge
    else ())

let buildCallGraph (hdl: BinHandler) funcs (callGraph: CallGraph) =
  Seq.iter (fun (KeyValue(_, func)) -> callGraph.AddVertex func |> ignore) funcs
  Seq.iter (fun (KeyValue(_, func)) ->
    addCallGraphEdge hdl funcs callGraph func) funcs
  let fi = hdl.FileInfo
  if fi.EntryPoint <> 0UL then
    let v =
      callGraph.FindVertexBy (fun (v: Vertex<Function>) ->
        v.VData.Entry = fi.EntryPoint)
    callGraph.SetRoot v
  else () // XXX: Library cases. Fix this

/// Stringify functions
let bgToJson toResolve (sb: StringBuilder) =
  if toResolve then sb.Append("\"pink\"")
  else sb.Append("\"white\"")

let inline disasmVertexToString (v: DisasmVertex) =
  v.VData.AddrRange.Min.ToString ("X")

let private disasmToJson hdl (sb: StringBuilder) ins =
  let disasm = BinHandler.DisasmInstr hdl true true ins
  sb.Append("        {\"disasm\": \"").Append(disasm).Append("\"}")

let private instrsToJson hdl instrs sb =
  let rec disasmLoop sb = function
    | [] -> sb
    | [ins] -> disasmToJson hdl sb ins
    | ins :: instrs ->
      disasmLoop ((disasmToJson hdl sb ins).Append(",\n")) instrs
  disasmLoop sb instrs

let private disasmVertexToJson (sb: StringBuilder, hdl, cnt) (v: DisasmVertex) =
  let sb = if cnt = 0 then sb else sb.Append(",\n")
  let sb = sb.Append("    \"").Append(disasmVertexToString v)
  let sb = sb.Append("\": {\n")
  let sb = sb.Append("      \"background\": ")
  let sb = bgToJson v.VData.ToResolve sb
  let sb = sb.Append(",\n")
  let sb = sb.Append("      \"instrs\": [\n")
  let sb = instrsToJson hdl v.VData.Instrs sb
  let sb = sb.Append("\n      ]")
  sb.Append("\n    }"), hdl, cnt + 1

let inline irVertexToString (v: IRVertex) =
  let _, ppoint = v.VData.GetPpoint ()
  ppoint.ToString ()

let private irToJson hdl (sb: StringBuilder) stmt =
  let s = Pp.stmtToString stmt
  sb.Append("        {\"stmt\: \"").Append(s).Append("\"}")

let private stmtsToJson hdl stmts sb =
  let rec irLoop sb = function
    | [] -> sb
    | [stmt] -> irToJson hdl sb stmt
    | stmt :: stmts ->
      irLoop ((irToJson hdl sb stmt).Append(",\n")) stmts
  irLoop sb stmts

let private irVertexToJson (sb: StringBuilder, hdl, cnt) (v: IRVertex) =
  let vData = v.VData
  let sb = if cnt = 0 then sb else sb.Append(",\n")
  let sb = sb.Append("    \"").Append(irVertexToString v)
  let sb = sb.Append("\": {\n")
  let sb = sb.Append("      \"background\": ")
  let _, toResolve = vData.GetToResolve ()
  let sb = bgToJson toResolve sb
  let sb = sb.Append(",\n")
  let sb = sb.Append("      \"instrs\": [\n")
  let sb = stmtsToJson hdl (snd <| vData.GetStmts ()) sb
  let sb = sb.Append("\n      ]")
  sb.Append("\n    }"), hdl, cnt + 1

let private edgeTypeToString = function
  | JmpEdge -> "cfgJmpEdge"
  | CJmpTrueEdge -> "cfgCJmpTrueEdge"
  | CJmpFalseEdge -> "cfgCJmpFalseEdge"
  | CallEdge -> "cfgCallEdge"
  | RetEdge -> "cfgRetEdge"
  | FallThroughEdge -> "cfgFallThroughEdge"

let private edgeToJson vToStrFunc (sb: StringBuilder, g: CFG<_>, cnt) src dst =
  let srcID: string = vToStrFunc src
  let dstID: string = vToStrFunc dst
  let edge = g.FindEdge src dst |> edgeTypeToString
  let sb = if cnt = 0 then sb else sb.Append(",")
  let sb = sb.Append("    {\"from\": \"").Append(srcID)
  let sb = sb.Append("\", \"to\": \"").Append(dstID)
  let sb = sb.Append("\", \"type\": \"").Append(edge).Append("\"}")
  sb, g, cnt + 1

let toJson hdl (g: CFG<_>) (rootAddr: string) vertexToStrFunc vertexToJsonFunc =
  let sb = StringBuilder ()
  let sb = sb.Append("{\n  \"root\": \"").Append(rootAddr).Append("\",\n")
  let sb = sb.Append("  \"nodes\": {\n")
  let sb, _, _ = g.FoldVertex vertexToJsonFunc (sb, hdl, 0)
  let sb = sb.Append("  },\n")
  let sb = sb.Append("  \"edges\": [\n")
  let sb, _, _ = g.FoldEdge (edgeToJson vertexToStrFunc) (sb, g, 0)
  let sb = sb.Append("  ]")
  sb.Append("\n}").ToString()

let disasmCFGToJson hdl g (entry: Addr) =
  let root = entry.ToString ("X")
  toJson hdl g root disasmVertexToString disasmVertexToJson

let irCFGToJson hdl g entry =
  let root = (entry, 0).ToString ()
  toJson hdl g root irVertexToString irVertexToJson
