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
      Ok <| DisassemblyBBL (addrRange, instrs, last)
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
    if List.length stmts = 0 then Error ()
    else
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

let getDisasmSuccessors hdl (builder: CFGBuilder) (bbl: DisassemblyBBL) =
  let last = bbl.LastInstr
  let next = last.Address + uint64 last.Length
  if last.IsExit () then
    if last.IsCall () then [ Some (next, JmpEdge) ] // XXX: Will be modified
    elif last.IsDirectBranch () then
      match getBranchTarget last with
      | Some addr when not <| builder.IsInteresting hdl addr -> []
      | Some addr ->
        if last.IsCondBranch () then
          if last.IsCJmpOnTrue () then
            [ Some (addr, CJmpFalseEdge) ; Some (next, CJmpTrueEdge) ]
          else [ Some (addr, CJmpTrueEdge) ; Some (next, CJmpFalseEdge) ]
        else [ Some (addr, JmpEdge) ]
      | None -> []
    elif last.IsIndirectBranch () then [ None ]
    elif last.IsInterrupt () then [ Some (next, JmpEdge) ]
    else []
  else [ Some (next, JmpEdge) ]

let addDisasmLeader
    hdl (builder:CFGBuilder) funcset (bbls: Dictionary<Addr, DisassemblyBBL>) (g: DisasmCFG) entry leader = function
  | None ->
    if leader <> entry && Set.contains leader funcset then None
    else
      builder.UpdateEntryOfDisasmBoundary leader entry
      let bbl = bbls.[leader]
      let v = g.AddVertex bbl
      Some (v, getDisasmSuccessors hdl builder bbl)
  | Some entry_ when entry = entry_ ->
    let bbl = bbls.[leader]
    let v = g.FindVertexByData bbl
    Some (v, [])
  | Some entry_ ->
    /// XXX: Need to merge functions here
    None

let chkAndAddDisasmLeader
    hdl (builder:CFGBuilder) funcset bbls cfg entry leader =
  builder.TryGetEntryByDisasmLeader leader
  |> Option.bind (addDisasmLeader hdl builder funcset bbls cfg entry leader)

/// XXX: Cleanup needed
let buildDisasmCFG hdl (builder: CFGBuilder) cfg funcset bbls entry =
  let rec buildLoop parent = function
    | [] -> ()
    | Some (leader, edgeType) :: leaders ->
      match chkAndAddDisasmLeader hdl builder funcset bbls cfg entry leader with
      | Some (child, succs) ->
        cfg.AddEdge parent child edgeType
        buildLoop child succs
      | None -> ()
      buildLoop parent leaders
    | None :: leaders ->
      /// This is the case that needs branch target resolving.
      parent.VData.ToResolve <- true
      buildLoop parent leaders
  match chkAndAddDisasmLeader hdl builder funcset bbls cfg entry entry with
  | Some (v, succs) -> buildLoop v succs
  | None -> ()

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

let getIRSuccessors hdl (builder: CFGBuilder) (bbl: IRBBL) =
  match bbl.LastStmt with
  | Jmp (Name symbol) ->
    let addr, _ = bbl.LastPpoint
    let ppoint = builder.FindPPointByLabel addr symbol
    [ Some (ppoint, JmpEdge) ]
  | CJmp (_, Name tSymbol, Name fSymbol) ->
    let addr, _ = bbl.LastPpoint
    let tPpoint = builder.FindPPointByLabel addr tSymbol
    let fPpoint = builder.FindPPointByLabel addr fSymbol
    [ Some (tPpoint, CJmpTrueEdge) ; Some (fPpoint, CJmpFalseEdge) ]
  | CJmp (_, Name tSymbol, _) ->
    let addr, _ = bbl.LastPpoint
    let tPpoint = builder.FindPPointByLabel addr tSymbol
    [ Some (tPpoint, CJmpTrueEdge) ; None ]
  | CJmp (_, _, Name fSymbol) ->
    let addr, _ = bbl.LastPpoint
    let fPpoint = builder.FindPPointByLabel addr fSymbol
    [ Some (fPpoint, CJmpFalseEdge) ; None ]
  | InterJmp (_, Num bv, InterJmpInfo.IsCall) ->
    let addr = getNextAddr builder bbl.LastPpoint
    [ Some ((addr, 0), JmpEdge) ]
  | InterJmp (_, Num bv, _) ->
    let addr = BitVector.toUInt64 bv
    if isExecutable hdl addr then [ Some ((addr, 0), JmpEdge) ] else []
  | InterCJmp (_, _, Num tBv, Num fBv) ->
    let tAddr = BitVector.toUInt64 tBv
    let fAddr = BitVector.toUInt64 fBv
    [ Some ((tAddr, 0), CJmpTrueEdge) ; Some ((fAddr, 0), CJmpFalseEdge) ]
  | Jmp _ | CJmp _ | InterJmp _ | InterCJmp _ -> [ None ]
  | SideEffect Halt -> []
  | stmt -> [ Some (getNextPpoint bbl.LastPpoint stmt, JmpEdge) ]

let addIRLeader
    hdl (builder: CFGBuilder) funcset (bbls: Dictionary<PPoint, IRBBL>) (cfg: IRCFG) entry leader = function
  | None ->
    if leader <> (entry, 0) && Set.contains (fst leader) funcset then None
    else
      builder.UpdateEntryOfIRBoundary leader entry
      let bbl = bbls.[leader]
      let v = cfg.AddVertex bbl
      Some (v, getIRSuccessors hdl builder bbl)
  | Some entry_ when entry = entry_ ->
    let bbl = bbls.[leader]
    let v = cfg.FindVertexByData bbl
    Some (v, [])
  | Some entry_ ->
    /// XXX: Need to merge functions here
    None

let chkAndAddIRLeader hdl (builder:CFGBuilder) funcset bbls cfg entry leader =
  builder.TryGetEntryByIRLeader leader
  |> Option.bind (addIRLeader hdl builder funcset bbls cfg entry leader)

let buildIRCFG hdl (builder: CFGBuilder) cfg funcset bbls entry =
  let rec buildLoop (parent: Vertex<IRBBL>) = function
    | [] -> ()
    | Some (leader, edgeType) :: leaders ->
      match chkAndAddIRLeader hdl builder funcset bbls cfg entry leader with
      | Some (child, succs) ->
        cfg.AddEdge parent child edgeType
        buildLoop child succs
      | None -> ()
      buildLoop parent leaders
    | None :: leaders ->
      parent.VData.ToResolve <- true
      buildLoop parent leaders
  match chkAndAddIRLeader hdl builder funcset bbls cfg entry (entry, 0) with
  | Some (v, succs) -> buildLoop v succs
  | None -> ()

let rec buildIRCFGs hdl builder (funcs: Funcs) funcset bbls = function
  | entry :: entries ->
    let cfg = funcs.[entry].IRCFG
    buildIRCFG hdl builder cfg funcset bbls entry
    let bbl = bbls.[(entry, 0)]
    if cfg.Size () <> 0 then cfg.FindVertexByData bbl |> cfg.SetRoot else ()
    buildIRCFGs hdl builder funcs funcset bbls entries
  | [] -> builder

let buildCFGs hdl (builder: CFGBuilder) (funcs: Funcs) =
  let disasmBBLs = Dictionary<Addr, DisassemblyBBL> ()
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
  v.VData.Ppoint.ToString ()

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
  let sb = if cnt = 0 then sb else sb.Append(",\n")
  let sb = sb.Append("    \"").Append(irVertexToString v)
  let sb = sb.Append("\": {\n")
  let sb = sb.Append("      \"background\": ")
  let sb = bgToJson v.VData.ToResolve sb
  let sb = sb.Append(",\n")
  let sb = sb.Append("      \"instrs\": [\n")
  let sb = stmtsToJson hdl v.VData.Stmts sb
  let sb = sb.Append("\n      ]")
  sb.Append("\n    }"), hdl, cnt + 1

let private edgeTypeToString = function
  | JmpEdge -> "cfgJmpEdge"
  | CJmpTrueEdge -> "cfgCJmpTrueEdge"
  | CJmpFalseEdge -> "cfgCJmpFalseEdge"

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
