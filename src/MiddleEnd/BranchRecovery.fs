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

namespace B2R2.MiddleEnd

open B2R2
open B2R2.FrontEnd
open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.BinGraph
open B2R2.BinEssence
open B2R2.DataFlow
open B2R2.Lens

type BranchPattern =
  | FromTable of baseAddr: Addr * indexAddr: Addr * rt: RegType
  | FromConst of targetAddr: Addr
  | UnknownPattern

type ConstantBranchInfo = {
  CalleeEntry: Addr
  TargetAddr: Addr
}
with
  static member Init entry addr =
    { CalleeEntry = entry; TargetAddr = addr }

type TableBranchInfo = {
  CalleeStart: Addr
  CalleeEnd: Addr
  BlockAddr: Addr
  InsAddr: Addr
  JTBaseAddr: Addr
  JTRange: AddrRange
  JTEntrySize: RegType
  TargetAddresses: Set<Addr>
}
with
  static member Init fStart fEnd block ins bAddr sAddr rt =
    { CalleeStart = fStart
      CalleeEnd = fEnd
      BlockAddr = block
      InsAddr = ins
      JTBaseAddr = bAddr
      JTRange = AddrRange (sAddr, sAddr + 1UL)
      JTEntrySize = rt
      TargetAddresses = Set.empty }

type BranchRecoveryState = {
  ResolvedCallees: Set<Addr>
  ConstantBranches: Map<Addr, ConstantBranchInfo>
  TableBranches: Map<Addr, TableBranchInfo>
}
with
  static member Init () =
    { ResolvedCallees = Set.empty
      ConstantBranches = Map.empty;
      TableBranches = Map.empty }

  static member UpdateTableBranches st jmpInfoMap =
    let tableBranches =
      jmpInfoMap
      |> Map.fold (fun acc addr jmpInfo ->
        Map.add addr jmpInfo acc) st.TableBranches
    { st with TableBranches = tableBranches }

  static member UpdateConstantBranches st jmpInfoMap =
    let constBranches =
      jmpInfoMap
      |> Map.fold (fun acc addr jmpInfo ->
        Map.add addr jmpInfo acc) st.ConstantBranches
    { st with ConstantBranches = constBranches }

type TableRecoveryInfo =
  | Done of TableBranchInfo
  | Continue of TableBranchInfo * Addr

type TableBranchKnowledge = {
  Bases: Set<Addr>
  TableBoundaries: Map<Addr, AddrRange>
  TableInfos: Map<Addr, TableRecoveryInfo>
}
with
  static member ComputeBoundaries hint addrs =
    let rec loop acc = function
      | [] | [ _ ] -> acc
      | addr :: ((addr' :: _) as next) ->
        let acc =
          if Set.contains addr addrs then
            Map.add addr (AddrRange (addr, addr')) acc
          else acc
        loop acc next
    Set.map snd hint.TableHint
    |> Set.union addrs |> Set.toList |> loop Map.empty

  static member AddNewInformation hint knowledge jtInfo =
    let newBase = jtInfo.JTRange.Min
    let bases = Set.add newBase knowledge.Bases
    let boundaries = TableBranchKnowledge.ComputeBoundaries hint bases
    let info = Continue (jtInfo, newBase)
    let tableInfos = Map.add jtInfo.InsAddr info knowledge.TableInfos
    let hint =
      { hint with TableHint = Set.add (jtInfo.InsAddr, jtInfo.JTRange.Min) hint.TableHint}
    let knowledge =
      { Bases = bases; TableBoundaries = boundaries; TableInfos = tableInfos }
    hint, knowledge

  static member RemoveInformation hint knowledge jtInfo =
    let bAddr = jtInfo.JTRange.Min
    let bases = Set.remove bAddr knowledge.Bases
    let boundaries = TableBranchKnowledge.ComputeBoundaries hint bases
    let tableInfos = Map.remove jtInfo.InsAddr knowledge.TableInfos
    let hint =
      { hint with
          TableHint =
            hint.TableHint
            |> Set.filter (fun (ins, addr) ->
              ins <> jtInfo.InsAddr && addr <> jtInfo.JTRange.Min) }
    let knowledge =
      { Bases = bases; TableBoundaries = boundaries; TableInfos = tableInfos }
    hint, knowledge

  static member UpdateBoundary hint knowledge =
    let boundaries = TableBranchKnowledge.ComputeBoundaries hint knowledge.Bases
    { knowledge with TableBoundaries = boundaries }

  static member ResetTableRanges knowledge =
    let tableInfos =
      knowledge.TableInfos
      |> Map.map (fun _ info ->
        match info with
        | Done jtInfo | Continue (jtInfo, _) ->
          let range = jtInfo.JTRange
          let jtInfo =
            { jtInfo with
                JTRange = AddrRange (range.Min, range.Min + 1UL)
                TargetAddresses = Set.empty }
          Continue (jtInfo, range.Min))
    { knowledge with TableInfos = tableInfos }

module BranchRecoveryHelper =

  let filterOutLinkageTables hdl calleeAddrs =
    let tabAddrs =
      hdl.FileInfo.GetLinkageTableEntries ()
      |> Seq.map (fun ent -> ent.TrampolineAddress)
      |> Set.ofSeq
    calleeAddrs
    |> List.filter (fun addr -> not <| Set.contains addr tabAddrs)

  let computeCalleeAddrs ess =
    ess.CalleeMap.Callees
    |> Seq.choose (fun callee -> callee.Addr)
    |> Seq.toList
    |> filterOutLinkageTables ess.BinHandler
    |> List.sort

  let rec computeFunctionBoundaries acc = function
    | [] -> acc
    | [ addr ] -> Map.add addr (addr, 0UL) acc
    | addr :: ((next :: _) as addrs) ->
      let acc = Map.add addr (addr, next) acc
      computeFunctionBoundaries acc addrs

  let hasIndirectBranch (ess: BinEssence) entry =
    let cfg, _ = ess.GetFunctionCFG (entry, false)
    DiGraph.foldVertex cfg (fun acc (v: Vertex<IRBasicBlock>) ->
      (not <| v.VData.IsFakeBlock () && v.VData.HasIndirectBranch)
      || acc) false

  let computeConstantPropagation ess entry =
    let irCFG, irRoot = (ess: BinEssence).GetFunctionCFG (entry, false)
    let lens = SSALens.Init ess
    let ssaCFG, ssaRoots = lens.Filter (irCFG, [irRoot], ess)
    let cp = ConstantPropagation (ess.BinHandler, ssaCFG)
    let ssaRoot = List.head ssaRoots
    cp.Compute (ssaRoot), ssaCFG

  let extractBranches cfg =
    DiGraph.foldVertex cfg (fun acc (v: Vertex<SSABBlock>) ->
      let len = v.VData.InsInfos.Length
      if not <| v.VData.IsFakeBlock ()
        && v.VData.HasIndirectBranch
        && len > 0
      then
        let addr = v.VData.PPoint.Address
        let lastIns = v.VData.InsInfos.[len - 1].Instruction
        let isCall = lastIns.IsCall ()
        (addr, lastIns.Address, v.VData.GetLastStmt (), isCall) :: acc
      else acc) []

  let rec simplifyBinOp = function
    | BinOp (BinOpType.ADD, _, Num v1, Num v2) -> Num (BitVector.add v1 v2)
    | BinOp (BinOpType.SUB, _, Num v1, Num v2) -> Num (BitVector.sub v1 v2)
    | BinOp (BinOpType.MUL, _, Num v1, Num v2) ->
      let v1 =
        if BitVector.toUInt64 v2 = 4UL && not <| BitVector.isZero v1 then
          BitVector.zero <| BitVector.getType v1
        else v1
      Num (BitVector.mul v1 v2)
    | BinOp (BinOpType.ADD, rt, Num v1, BinOp (BinOpType.ADD, _, Num v2, e))
    | BinOp (BinOpType.ADD, rt, Num v1, BinOp (BinOpType.ADD, _, e, Num v2))
    | BinOp (BinOpType.ADD, rt, BinOp (BinOpType.ADD, _, Num v2, e), Num v1)
    | BinOp (BinOpType.ADD, rt, BinOp (BinOpType.ADD, _, e, Num v2), Num v1) ->
      simplifyBinOp (BinOp (BinOpType.ADD, rt, Num (BitVector.add v1 v2), e))
    | e -> e

  let simplifyExtract = function
    | Extract (Cast (CastKind.ZeroExt, _, e'), rt, 0) as e ->
      if AST.typeOf e' = rt then e' else e
    | e -> e

  let rec extractExp cpstate expr =
    match expr with
    | Num _ -> expr
    | Var v ->
      match CPState.findReg cpstate v with
      | Const bv -> Num bv
      | Pointer bv -> Num bv
      | _ ->
        match Map.tryFind v cpstate.SSAEdges.Defs with
        | Some (Def (_, e)) -> extractExp cpstate e
        | _ -> expr
    | Load (mem, rt, addr) ->
      match extractExp cpstate addr with
      | Num bv ->
        let addr = BitVector.toUInt64 bv
        match CPState.findMem cpstate mem rt addr with
        | Const bv -> Num bv
        | Pointer bv -> Num bv
        | _ -> Load (mem, rt, Num bv)
      | expr -> Load (mem, rt, expr)
    | UnOp (op, rt, e) ->
      let e = extractExp cpstate e
      UnOp (op, rt, e)
    | BinOp (op, rt, e1, e2) ->
      let e1 = extractExp cpstate e1
      let e2 = extractExp cpstate e2
      simplifyBinOp (BinOp (op, rt, e1, e2))
    | RelOp (op, rt, e1, e2) ->
      let e1 = extractExp cpstate e1
      let e2 = extractExp cpstate e2
      RelOp (op, rt, e1, e2)
    | Ite (e1, rt, e2, e3) ->
      let e1 = extractExp cpstate e1
      let e2 = extractExp cpstate e2
      let e3 = extractExp cpstate e3
      Ite (e1, rt, e2, e3)
    | Cast (op, rt, e) ->
      let e = extractExp cpstate e
      Cast (op, rt, e)
    | Extract (e, rt, pos) ->
      let e = extractExp cpstate e
      simplifyExtract (Extract (e, rt, pos))
    | _ -> expr

  let computeIndexAddr = function
    | BinOp (BinOpType.ADD, _, Num idx, _)
    | BinOp (BinOpType.ADD, _, _, Num idx)
    | Num idx -> Some (BitVector.toUInt64 idx)
    | _ -> None

  let computeBranchPattern isCall expr =
    match expr, isCall with
    | Num addr, _ -> FromConst (BitVector.toUInt64 addr)
    | _, true -> UnknownPattern
    | BinOp (BinOpType.ADD, _, Load (_, t, idx), Num tbase), _
    | BinOp (BinOpType.ADD, _, Num tbase, Load (_, t, idx)), _
    | BinOp (BinOpType.ADD, _, Cast (_, _, Load (_, t, idx)), Num tbase), _
    | BinOp (BinOpType.ADD, _, Num tbase, Cast (_, _, Load (_, t, idx))), _ ->
      match computeIndexAddr idx with
      | Some tindex -> FromTable (BitVector.toUInt64 tbase, tindex, t)
      | None -> UnknownPattern
    | _ -> UnknownPattern

  let classifyBranch cpState isCall = function
    | Jmp (InterJmp exp)
    | Jmp (InterCJmp (_, exp, Num _))
    | Jmp (InterCJmp (_, Num _, exp)) ->
      extractExp cpState exp |> computeBranchPattern isCall
    | _ -> UnknownPattern

  let findConstBranches ess entry =
    let cpState, ssaCFG = computeConstantPropagation ess entry
    extractBranches ssaCFG
    |> List.fold (fun acc (blockAddr, insAddr, stmt, isCall) ->
      match classifyBranch cpState isCall stmt with
      | FromConst target ->
        let constJmpInfo = ConstantBranchInfo.Init entry target
        (blockAddr, insAddr, constJmpInfo, isCall) :: acc
      | _ -> acc) []

  let addConstJmpEdge ess blockAddr jmpInfo isCall =
    let target = (jmpInfo: ConstantBranchInfo).TargetAddr
    if isCall then
      [ (target, (ess: BinEssence).BinHandler.DefaultParsingContext) ]
      |> BinEssence.addEntries ess
    else Ok ess
    |> Result.bind (fun ess ->
      if isCall then IndirectCallEdge else IndirectJmpEdge
      |> BinEssence.addEdge ess blockAddr target)
    |> (fun ess ->
      match ess with
      | Ok ess -> ess
      | _ -> Utils.impossible ())

  let recoverConstJmpsOfCallee noReturn (entry, _) ess hint st =
    match findConstBranches ess entry with
    | [] -> ess, hint, st
    | constBranches ->
      let ess, jmpAddrs =
        constBranches
        |> List.fold (fun (ess, jmpAddrs) (block, ins, jmpInfo, isCall) ->
          let ess = addConstJmpEdge ess block jmpInfo isCall
          ess, Map.add ins jmpInfo jmpAddrs) (ess, Map.empty)
      let ess, hint = (noReturn: IAnalysis).Run ess hint
      let st = BranchRecoveryState.UpdateConstantBranches st jmpAddrs
      ess, hint, st

  let findTableBranches (fStart, fEnd) (cpState, ssaCFG) =
    extractBranches ssaCFG
    |> List.fold (fun acc (block, ins, stmt, isCall) ->
      match classifyBranch cpState isCall stmt with
      | FromTable (bAddr, iAddr, rt) ->
        TableBranchInfo.Init fStart fEnd block ins bAddr iAddr rt :: acc
      | _ -> acc) []

  let withinCallee jmpInfo addr =
    jmpInfo.CalleeStart <= addr && addr < jmpInfo.CalleeEnd

  let readTarget ess jmpInfo sAddr =
    let hdl = (ess: BinEssence).BinHandler
    if hdl.FileInfo.IsValidAddr sAddr then
      let size = RegType.toByteWidth jmpInfo.JTEntrySize
      match BinHandler.TryReadInt (hdl, sAddr, size) with
      | Error _ -> Error ()
      | Ok offset ->
        let target = jmpInfo.JTBaseAddr + uint64 offset
        if withinCallee jmpInfo target then
          let block = jmpInfo.BlockAddr
          match BinEssence.addEdge ess block target IndirectJmpEdge with
          | Ok ess' ->
            let next = sAddr + uint64 size
            let jmpInfo =
              { jmpInfo with
                  JTRange = AddrRange (jmpInfo.JTRange.Min, next)
                  TargetAddresses = Set.add target jmpInfo.TargetAddresses }
            Ok (ess', jmpInfo)
          | Error _ -> Error ()
        else Error ()
    else Error ()

  let recoverInitialTables ((fStart, _) as fnBdry) ess acc =
    let cpInfo = computeConstantPropagation ess fStart
    match findTableBranches fnBdry cpInfo with
    | [] -> acc
    | tableBranches ->
      let minBase =
        List.map (fun jmpInfo -> jmpInfo.JTRange.Min) tableBranches |> List.min
      Map.add fStart (tableBranches, minBase, cpInfo) acc

  let rec computeTableBoundaries tableBdrys = function
    | [] -> Utils.impossible ()
    | [ _ ] -> tableBdrys
    | addr :: ((addr' :: _) as rest) ->
      let tableBdrys = Map.add addr (AddrRange (addr, addr')) tableBdrys
      computeTableBoundaries tableBdrys rest

  let initializeKnowledge hint knowledgeMap entry tableBranches max cpInfo =
    let tableHint =
      tableBranches
      |> List.fold (fun tableHint jtInfo ->
        Set.add (jtInfo.InsAddr, jtInfo.JTRange.Min) tableHint) hint.TableHint
    let hint = { hint with TableHint = tableHint }
    let bases =
      tableBranches
      |> List.fold (fun bases jmpInfo ->
        Set.add jmpInfo.JTRange.Min bases) Set.empty
      |> Set.add max
    let tableBdrys = computeTableBoundaries Map.empty <| Set.toList bases
    let tableInfos =
      tableBranches
      |> List.fold (fun tableInfos jtInfo ->
        let info = Continue (jtInfo, jtInfo.JTRange.Min)
        Map.add jtInfo.InsAddr info tableInfos) Map.empty
    let knowledge =
      { Bases = bases; TableBoundaries = tableBdrys; TableInfos = tableInfos }
    hint, Map.add entry (knowledge, cpInfo) knowledgeMap

  let rec initializeKnowledgeMap hint knowledgeMap = function
    | [] -> hint, Map.empty
    | [ (entry, (tableBranches, _, cpInfo)) ] ->
      let dummyMax = 0xFFFFFFFFFFFFFFFFUL
      initializeKnowledge hint knowledgeMap entry tableBranches dummyMax cpInfo
    | (entry, (tableBranches, _, cpInfo)) :: (((_, (_, minBase, _)) :: _) as rest) ->
      let hint, knowledgeMap =
        initializeKnowledge hint knowledgeMap entry tableBranches minBase cpInfo
      initializeKnowledgeMap hint knowledgeMap rest

  let prepareTableRecovery fnBdrys ess hint callees =
    callees
    |> List.fold (fun acc entry ->
      let fnBdry = Map.find entry fnBdrys
      recoverInitialTables fnBdry ess acc) Map.empty
    |> Map.toList
    |> List.sortBy (fun (_, (_, minBase, _)) -> minBase)
    |> initializeKnowledgeMap hint Map.empty

  let collectIndirectJumps (ess: BinEssence) entry =
    let cfg, root = ess.GetFunctionCFG (entry, false)
    Traversal.foldPostorder cfg root (fun acc (v: Vertex<IRBasicBlock>) ->
      if not <| v.VData.IsFakeBlock () && v.VData.HasIndirectBranch then
        let addr = v.VData.PPoint.Address
        if v.VData.LastInstruction.IsCall () then acc
        else Set.add addr acc
      else acc) Set.empty

  let rec readTargets ess jmpInfo sAddr max =
    if sAddr >= max then Error jmpInfo
    else
      let oldJmps = collectIndirectJumps ess jmpInfo.CalleeStart
      match readTarget ess jmpInfo sAddr with
      | Ok (ess, jmpInfo) ->
        let newJmps = collectIndirectJumps ess jmpInfo.CalleeStart
        let diff = Set.difference newJmps oldJmps
        if Set.isEmpty diff then
          let next = jmpInfo.JTRange.Max
          readTargets ess jmpInfo next max
        else Ok (ess, jmpInfo)
      | Error _ -> Error jmpInfo

  let rec readTargetsUntil ess jmpInfo sAddr max =
    if sAddr >= max then ess, jmpInfo
    else
      match readTarget ess jmpInfo sAddr with
      | Ok (ess', jmpInfo) ->
        let next = jmpInfo.JTRange.Max
        readTargetsUntil ess' jmpInfo next max
      | Error _ -> ess, jmpInfo

  let tryRecoverTable noReturn ess hint knowledge (discover, recover) jtInfo =
    let ins = jtInfo.InsAddr
    match Map.find ins knowledge.TableInfos with
    | Done _ -> discover, recover
    | Continue (jtInfo, minAddr) ->
      let tableBase = jtInfo.JTRange.Min
      let tableBdry = Map.find tableBase knowledge.TableBoundaries
      let ess, jtInfo = readTargetsUntil ess jtInfo tableBase minAddr
      match readTargets ess jtInfo minAddr tableBdry.Max with
      | Ok (ess, jtInfo) ->
        let ess, _ = (noReturn: IAnalysis).Run ess hint
        Map.add ins (ess, jtInfo) discover, recover
      | Error jtInfo -> discover, Map.add ins jtInfo recover

  let isAlreadyFound knowledge jtInfo =
    Map.containsKey jtInfo.InsAddr knowledge.TableInfos

  let hasDuplicatedBase knowledge jtInfo =
    Map.containsKey jtInfo.JTRange.Min knowledge.TableBoundaries

  let discoverNewBranches fnBdry hint knowledge jtInfo cpInfo =
    let newBranches, hasDuplicated =
      findTableBranches fnBdry cpInfo
      |> List.fold (fun (acc, hasDuplicated) jtInfo ->
        if isAlreadyFound knowledge jtInfo then (acc, hasDuplicated)
        elif hasDuplicatedBase knowledge jtInfo then (acc, true)
        else jtInfo :: acc, hasDuplicated) ([], false)
    if List.isEmpty newBranches then
      if hasDuplicated then Error knowledge
      else
        let ins = jtInfo.InsAddr
        let info = Continue (jtInfo, jtInfo.JTRange.Max)
        { knowledge with TableInfos = Map.add ins info knowledge.TableInfos }
        |> Error
    else
      newBranches
      |> List.fold (fun (hint, knowledge) jtInfo ->
        TableBranchKnowledge.AddNewInformation hint knowledge jtInfo
        ) (hint, knowledge)
      |> Ok

  let checkOverlap knowledge =
    knowledge.TableInfos
    |> Map.exists (fun _ jtInfo ->
      match jtInfo with
      | Done jtInfo | Continue (jtInfo, _) ->
        let range = jtInfo.JTRange
        let tableBoundary = Map.find range.Min knowledge.TableBoundaries
        range.Max > tableBoundary.Max)

  let recoverTableUntilNewBranch (ess, knowledge) ins (_, jtInfo) =
    let range = jtInfo.JTRange
    let tblBdry = Map.find range.Min knowledge.TableBoundaries
    let ess, jtInfo = readTargetsUntil ess jtInfo range.Min range.Max
    let info =
      if jtInfo.JTRange = tblBdry then Done jtInfo
      else Continue (jtInfo, jtInfo.JTRange.Max)
    let knowledge =
      { knowledge with TableInfos = Map.add ins info knowledge.TableInfos }
    ess, knowledge

  let recoverTableUntilBoundary (ess, knowledge) ins jtInfo =
    let range = jtInfo.JTRange
    let tblBdry = Map.find range.Min knowledge.TableBoundaries
    if range.Max > tblBdry.Max then ess, knowledge
    else
      let ess, jtInfo = readTargetsUntil ess jtInfo range.Min range.Max
      let info = Done jtInfo
      let knowledge =
        { knowledge with TableInfos = Map.add ins info knowledge.TableInfos }
      ess, knowledge

  let updateBinEssenceWithKnowledge ess knowledge discover recover =
    if not <| Map.isEmpty discover then
      discover |> Map.fold recoverTableUntilNewBranch (ess, knowledge)
    elif not <| Map.isEmpty recover then
      recover |> Map.fold recoverTableUntilBoundary (ess, knowledge)
    else ess, knowledge

  let updateKnowledgeWithNewBinEssence fnBdry knowledge cpInfo =
    findTableBranches fnBdry cpInfo
    |> List.fold (fun knowledge jtInfo ->
      let ins = jtInfo.InsAddr
      if not <| Map.containsKey ins knowledge.TableInfos then knowledge
      else
        match Map.find ins knowledge.TableInfos with
        | Done jtInfo' ->
          let jtInfo' = { jtInfo' with BlockAddr = jtInfo.BlockAddr }
          let info = Done jtInfo'
          { knowledge with TableInfos = Map.add ins info knowledge.TableInfos }
        | Continue (jtInfo', minAddr) ->
          let jtInfo' = { jtInfo' with BlockAddr = jtInfo.BlockAddr }
          let info = Continue (jtInfo', minAddr)
          { knowledge with TableInfos = Map.add ins info knowledge.TableInfos })
      knowledge

  let checkTableConflictAndUpdateKnowledge hint acc knowledge info jtInfo =
    match info with
    | Done jtInfo' | Continue (jtInfo', _) ->
      if jtInfo.JTRange.Min < jtInfo'.JTRange.Min then
        let hint, knowledge =
          TableBranchKnowledge.RemoveInformation hint knowledge jtInfo'
        TableBranchKnowledge.AddNewInformation hint knowledge jtInfo
        |> Error
      else
        match acc with
        | Ok _ -> Ok (hint, knowledge)
        | Error _ -> Error (hint, knowledge)

  let recoverNewBranches fnBdry hint knowledge cpInfo =
    findTableBranches fnBdry cpInfo
    |> List.fold (fun acc jtInfo ->
      let hint, knowledge =
        match acc with
        | Ok (hint, knowledge) | Error (hint, knowledge) -> (hint, knowledge)
      let ins = jtInfo.InsAddr
      match Map.tryFind ins knowledge.TableInfos with
      | None ->
        match discoverNewBranches fnBdry hint knowledge jtInfo cpInfo with
        | Ok (hint, knowledge) ->
          match acc with
          | Ok _ -> Ok (hint, knowledge)
          | Error _ -> Error (hint, knowledge)
        | Error knowledge ->
          match acc with
          | Ok _ -> Ok (hint, knowledge)
          | Error _ -> Error (hint, knowledge)
      | Some info ->
        checkTableConflictAndUpdateKnowledge hint acc knowledge info jtInfo
      ) (Ok (hint, knowledge))

  let checkAllDone knowledge =
    knowledge.TableInfos
    |> Map.forall (fun _ info ->
      match info with
      | Done _ -> true
      | _ -> false)

  let rec recoverTableBranchesLoop noReturn fnBdry oldEss ess hint knowledge cpInfo =
    let discover, recover =
      findTableBranches fnBdry cpInfo
      |> List.fold (tryRecoverTable noReturn ess hint knowledge) (Map.empty, Map.empty)
    let hint, knowledge, discover =
      discover
      |> Map.fold (fun (hint, knowledge, discover) ins (ess, jtInfo) ->
        let cpInfo = computeConstantPropagation ess <| fst fnBdry
        match discoverNewBranches fnBdry hint knowledge jtInfo cpInfo with
        | Ok (hint, knowledge) -> hint, knowledge, Map.add ins (ess, jtInfo) discover
        | Error knowledge -> hint, knowledge, discover) (hint, knowledge, Map.empty)
    if checkOverlap knowledge then
      rollBackWithKnowledge noReturn fnBdry oldEss hint knowledge
    else
      let ess, knowledge =
        updateBinEssenceWithKnowledge ess knowledge discover recover
      if checkOverlap knowledge then
        rollBackWithKnowledge noReturn fnBdry oldEss hint knowledge
      else
        let candidates =
          computeConstantPropagation ess <| fst fnBdry
          |> findTableBranches fnBdry
          |> List.fold (fun acc jtInfo ->
            if Map.containsKey jtInfo.InsAddr knowledge.TableInfos then acc
            else
              Set.add (jtInfo.InsAddr, jtInfo.JTRange.Min) acc) Set.empty
        let ess, hint = (noReturn: IAnalysis).Run ess hint
        let cpInfo = computeConstantPropagation ess <| fst fnBdry
        let knowledge = updateKnowledgeWithNewBinEssence fnBdry knowledge cpInfo
        match recoverNewBranches fnBdry hint knowledge cpInfo with
        | Ok (hint, knowledge) ->
          let tableHint = Set.union candidates hint.TableHint
          let tableHint =
            knowledge.TableInfos
            |> Map.fold (fun acc _ info ->
              match info with
              | Done jtInfo | Continue (jtInfo, _) ->
                acc
                |> Set.filter (fun (ins, addr) ->
                  ins <> jtInfo.InsAddr && addr <> jtInfo.JTRange.Min)) tableHint
          let hint = { hint with TableHint = tableHint }
          if checkAllDone knowledge then ess, hint, knowledge
          else
            let tableHint = Set.union candidates hint.TableHint
            let tableHint =
              knowledge.TableInfos
              |> Map.fold (fun acc _ info ->
                match info with
                | Done jtInfo | Continue (jtInfo, _) ->
                  acc
                  |> Set.filter (fun (ins, addr) ->
                    ins <> jtInfo.InsAddr && addr <> jtInfo.JTRange.Min)) tableHint
            let hint = { hint with TableHint = tableHint }
            let knowledge = TableBranchKnowledge.UpdateBoundary hint knowledge
            recoverTableBranchesLoop noReturn fnBdry oldEss ess hint knowledge cpInfo
        | Error (hint, knowledge) ->
          let tableHint = Set.union candidates hint.TableHint
          let tableHint =
            knowledge.TableInfos
            |> Map.fold (fun acc _ info ->
              match info with
              | Done jtInfo | Continue (jtInfo, _) ->
                acc
                |> Set.filter (fun (ins, addr) ->
                  ins <> jtInfo.InsAddr && addr <> jtInfo.JTRange.Min)) tableHint
          let hint = { hint with TableHint = tableHint }
          let knowledge = TableBranchKnowledge.UpdateBoundary hint knowledge
          rollBackWithKnowledge noReturn fnBdry oldEss hint knowledge

  and rollBackWithKnowledge noReturn fnBdry ess hint knowledge =
    let cpInfo = computeConstantPropagation ess <| fst fnBdry
    let knowledge = updateKnowledgeWithNewBinEssence fnBdry knowledge cpInfo
    let knowledge = TableBranchKnowledge.ResetTableRanges knowledge
    recoverTableBranchesLoop noReturn fnBdry ess ess hint knowledge cpInfo

  let recoverTableBranches noReturn fnBdrys (ess, hint, st) entry initInfo =
    let fnBdry = Map.find entry fnBdrys
    let knowledge, cpInfo = initInfo
    let ess, hint, knowledge =
      recoverTableBranchesLoop noReturn fnBdry ess ess hint knowledge cpInfo
    let tableInfos =
      knowledge.TableInfos
      |> Map.fold (fun acc ins info ->
        match info with
        | Done jtInfo -> Map.add ins jtInfo acc
        | _ -> acc) Map.empty
    let st = BranchRecoveryState.UpdateTableBranches st tableInfos
    ess, hint, st

  let toIndMap st =
    let acc =
      st.ConstantBranches
      |> Map.fold (fun acc insAddr info ->
        let info =
          { HostFunctionAddr = info.CalleeEntry
            TargetAddresses = Set.singleton info.TargetAddr
            JumpTableInfo = None }
        Map.add insAddr info acc) Map.empty
    let acc =
      st.TableBranches
      |> Map.fold (fun acc insAddr info ->
        if Set.isEmpty info.TargetAddresses then acc
        else
          let jtInfo =
            JumpTableInfo.Init info.JTBaseAddr info.JTRange info.JTEntrySize
          let info =
            { HostFunctionAddr = info.CalleeStart
              TargetAddresses = info.TargetAddresses
              JumpTableInfo = Some jtInfo }
          Map.add insAddr info acc) acc
    acc

  let filterCallees ess (hint, st, acc) entry =
    if Set.contains entry hint.BranchRecoveryPerformed then hint, st, acc
    elif hasIndirectBranch ess entry then hint, st, entry :: acc
    else
      let brPerformed = hint.BranchRecoveryPerformed
      let hint =
        { hint with BranchRecoveryPerformed = Set.add entry brPerformed }
      hint, st, acc

  let recoverTableJmps noReturn fnBdrys ess hint st callees =
    let hint, knowledge = prepareTableRecovery fnBdrys ess hint callees
    Map.fold (recoverTableBranches noReturn fnBdrys) (ess, hint, st) knowledge

  let recoverConstJmps noReturn boundaries (ess, hint, st) entry =
    let boundary = Map.find entry boundaries
    recoverConstJmpsOfCallee noReturn boundary ess hint st

  let rec recover noReturn ess hint st =
    let oldCJmps, oldTJmps = st.ConstantBranches, st.TableBranches
    let callees = computeCalleeAddrs ess
    let fnBdrys = computeFunctionBoundaries Map.empty callees
    let hint, st, callees = List.fold (filterCallees ess) (hint, st, []) callees
    let callees = List.rev callees
    let ess, hint, st = recoverTableJmps noReturn fnBdrys ess hint st callees
    let ess, hint, st =
      callees |> List.fold (recoverConstJmps noReturn fnBdrys) (ess, hint, st)
    let hint =
      callees
      |> List.fold (fun hint entry ->
        let brPerformed = hint.BranchRecoveryPerformed
        { hint with BranchRecoveryPerformed = Set.add entry brPerformed }) hint
    let newCJmps, newTJmps = st.ConstantBranches, st.TableBranches
    let indMap = toIndMap st
    let ess = BinEssence.addIndirectBranchMap ess indMap
    if oldCJmps = newCJmps && oldTJmps = newTJmps then ess, hint
    else
#if DEBUG
      printfn "[*] Go to next phase..."
#endif
      recover noReturn ess hint st

type BranchRecovery (enableNoReturn) =
  let noReturn =
    if enableNoReturn then NoReturnAnalysis () :> IAnalysis
    else NoAnalysis () :> IAnalysis

  member __.RunWith _ = Utils.futureFeature ()

  member __.CalculateTable _ = Utils.futureFeature ()

  interface IAnalysis with
    member __.Name = "Indirect Branch Recovery"

    member __.Run ess hint =
      let st = BranchRecoveryState.Init ()
      BranchRecoveryHelper.recover noReturn ess hint st
