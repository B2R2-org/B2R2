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
open B2R2.MiddleEnd.DataFlow

module private SSALifterFactory =
  /// Represents a mapping from a LowUIR CFG vertex to an SSACFG vertex.
  type SSAVMap = Dictionary<IVertex<LowUIRBasicBlock>, SSAVertex>

  /// Represents a mapping from a variable to the SSA basic blocks defining it.
  type DefSites = Dictionary<VariableKind, HashSet<SSAVertex>>

  /// Represents how many definitions each variable has been given so far.
  type VarCountMap = Dictionary<VariableKind, int>

  /// Represents the identifiers in scope for each variable, innermost first.
  type IDStack = Dictionary<VariableKind, int list>

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

  let inline updateGlobalName (globals: HashSet<_>) (varKill: HashSet<_>) v =
    if varKill.Contains v then () else globals.Add v |> ignore

  let rec updateGlobals (globals: HashSet<_>) (varKill: HashSet<_>) = function
    | Num _ | Undefined _ | FuncName _ ->
      ()
    | Var v ->
      updateGlobalName globals varKill v.Kind
    | ExprList exprs ->
      for e in exprs do
        updateGlobals globals varKill e
    | Load(v, _, e)
    | Store(v, _, _, e) ->
      updateGlobalName globals varKill v.Kind
      updateGlobals globals varKill e
    | Cast(_, _, e)
    | UnOp(_, _, e) ->
      updateGlobals globals varKill e
    | BinOp(_, _, lhs, rhs)
    | RelOp(_, _, lhs, rhs) ->
      updateGlobals globals varKill lhs
      updateGlobals globals varKill rhs
    | Ite(cond, _, lhs, rhs) ->
      updateGlobals globals varKill cond
      updateGlobals globals varKill lhs
      updateGlobals globals varKill rhs
    | Extract(e, _, _) ->
      updateGlobals globals varKill e

  let findDefVars ssaCFG (defSites: DefSites) =
    let ssaCFG = ssaCFG :> IDiGraph<SSABasicBlock, _>
    let globals = HashSet()
    let varKill = HashSet()
    for v in ssaCFG.Vertices do
      varKill.Clear()
      for _pp, stmt in v.VData.Internals.Statements do
        match stmt with
        | Def({ Kind = k }, srcExpr) ->
          updateGlobals globals varKill srcExpr
          varKill.Add k |> ignore
          match defSites.TryGetValue k with
          | true, sites -> sites.Add v |> ignore
          | false, _ -> defSites[k] <- HashSet [v]
        | _ ->
          ()
    globals

  let placePhis g (defSites: DefSites) globals (dom: IForwardDominance<_>) =
    let phiSites = HashSet()
    for variable in globals do
      let workList =
        match defSites.TryGetValue variable with
        | true, sites -> Queue sites
        | false, _ -> Queue()
      phiSites.Clear()
      while workList.Count <> 0 do
        let node = workList.Dequeue()
        for df in dom.DominanceFrontier node do
          if phiSites.Contains df then
            ()
          else
            match variable with
            (* Temporary vars are only meaningful in an instruction boundary.
               Thus, a PhiSite for a TempVar should be an intra-instruction bbl,
               but not the start of an instruction. *)
            | TempVar _ when df.VData.Internals.PPoint.Position = 0 ->
              ()
            | _ ->
              let preds = (g: IDiGraph<_, _>).GetPreds df
              df.VData.Internals.PrependPhi(variable, preds.Length)
              phiSites.Add df |> ignore
              workList.Enqueue df

  let renameVar (stack: IDStack) (v: Variable) =
    match stack.TryGetValue v.Kind with
    | false, _ -> v.Identifier <- 0
    | true, ids -> v.Identifier <- List.head ids

  let renameVarList stack vars = vars |> List.iter (renameVar stack)

  let rec renameExpr stack = function
    | Num _
    | Undefined _
    | FuncName _ ->
      ()
    | Var v ->
      renameVar stack v
    | ExprList exprs ->
      for expr in exprs do
        renameExpr stack expr
    | Load(v, _, expr) ->
      renameVar stack v
      renameExpr stack expr
    | Store(mem, _, addr, expr) ->
      renameVar stack mem
      renameExpr stack addr
      renameExpr stack expr
    | UnOp(_, _, expr) ->
      renameExpr stack expr
    | BinOp(_, _, expr1, expr2) ->
      renameExpr stack expr1
      renameExpr stack expr2
    | RelOp(_, _, expr1, expr2) ->
      renameExpr stack expr1
      renameExpr stack expr2
    | Ite(expr1, _, expr2, expr3) ->
      renameExpr stack expr1
      renameExpr stack expr2
      renameExpr stack expr3
    | Cast(_, _, expr) ->
      renameExpr stack expr
    | Extract(expr, _, _) ->
      renameExpr stack expr

  let renameJmp stack = function
    | IntraJmp _ ->
      ()
    | IntraCJmp(expr, _, _) ->
      renameExpr stack expr
    | InterJmp expr ->
      renameExpr stack expr
    | InterCJmp(cond, target1, target2) ->
      renameExpr stack cond
      renameExpr stack target1
      renameExpr stack target2

  let introduceDef (count: VarCountMap) (stack: IDStack) (v: Variable) =
    let i, ids =
      match count.TryGetValue v.Kind with
      | true, n -> n + 1, stack[v.Kind]
      | false, _ -> 1, [ 0 ] (* Lazy initialization *)
    count[v.Kind] <- i
    stack[v.Kind] <- i :: ids
    v.Identifier <- i

  let introduceDefList count stack vars =
    vars |> List.iter (introduceDef count stack)

  let renameStmt count stack stmt =
    match stmt with
    | LMark _ ->
      ()
    | ExternalCall(e, inVars, outVars) ->
      renameExpr stack e
      renameVarList stack inVars
      introduceDefList count stack outVars
    | SideEffect _ ->
      ()
    | Jmp jmpTy ->
      renameJmp stack jmpTy
    | Def(def, e) ->
      renameExpr stack e
      introduceDef count stack def
    | Phi(def, _) ->
      introduceDef count stack def

  let renamePhi g (stack: IDStack) (parent: SSAVertex) (succ: SSAVertex) =
    (* Which phi operand this parent fills in is its index among the
       predecessors of the successor, which is one and the same for every phi
       there, so the predecessors are worth reading only once, and only once a
       phi has asked for them. *)
    let mutable idx = -1
    for _, stmt in succ.VData.Internals.Statements do
      match stmt with
      | Phi(def, nums) ->
        if idx < 0 then
          let preds = (g: IDiGraph<_, _>).GetPreds succ
          idx <- preds |> Array.findIndex (fun v -> v.VData = parent.VData)
        else
          ()
        nums[idx] <- List.head stack[def.Kind]
      | _ ->
        ()

  let popStack (stack: IDStack) stmt =
    match stmt with
    | Def(def, _)
    | Phi(def, _) -> stack[def.Kind] <- List.tail stack[def.Kind]
    | _ -> ()

  let rec rename g domTree count stack (v: SSAVertex) =
    for _, stmt in v.VData.Internals.Statements do renameStmt count stack stmt
    for succ in (g: IDiGraph<_, _>).GetSuccs v do
      renamePhi g stack v succ
    for child in (domTree: DominatorTree<_>).GetChildren v do
      rename g domTree count stack child
    for _, stmt in v.VData.Internals.Statements do popStack stack stmt

  let renameVars g defSites (dom: IForwardDominance<_>) =
    let domTree = dom.DominatorTree
    let count = VarCountMap()
    let stack = IDStack()
    for variable in (defSites: DefSites).Keys do
      count[variable] <- 0
      stack[variable] <- [0]
    (* The dominator tree of a graph of more than one root is a forest, and so
       is that of a graph holding a vertex that no root reaches. Renaming starts
       from every tree of the forest, hence no vertex is left unrenamed. Each of
       them leaves the stack as it found it, so the order they come in does not
       matter. *)
    for root in domTree.Roots do
      rename g domTree count stack root

  /// Places the phis of the given SSACFG and renames every variable of it,
  /// then puts the program point of every statement back in step with the
  /// phis those two steps leave behind.
  let buildSSAForm ssaCFG dom =
    let defSites = DefSites()
    let globals = findDefVars ssaCFG defSites
    placePhis ssaCFG defSites globals dom
    renameVars ssaCFG defSites dom
    ssaCFG |> DiGraph.iterVertex (fun v -> v.VData.Internals.UpdatePPoints())

  let memStore pp rt addr src =
    match addr with
    | StackPointerDomain.ConstSP addr ->
      let addr = addr.ToUInt64()
      let offset = int (int64 Constants.InitialStackPointer - int64 addr)
      let v = { Kind = StackVar(rt, offset); Identifier = 0 }
      Some(pp, Def(v, src))
    | _ ->
      None

  let loadToVar rt addr =
    match addr with
    | StackPointerDomain.ConstSP addr ->
      let addr = addr.ToUInt64()
      let offset = int (int64 Constants.InitialStackPointer - int64 addr)
      let v = { Kind = StackVar(rt, offset); Identifier = 0 }
      Some(Var v)
    | _ ->
      None

  let rec replaceLoad (state: SSASparseDataFlow.State<_>) e =
    match e with
    | Load(memVar, rt, addr) ->
      let addrValue = state.EvalExpr addr
      match loadToVar rt addrValue with
      | Some e ->
        Some e
      | None ->
        match replaceLoad state addr with
        | Some addr -> Some(Load(memVar, rt, addr))
        | None -> None
    | ExprList exprs ->
      let exprs' = List.map (replaceLoad state) exprs
      if List.forall Option.isNone exprs' then
        None
      else
        exprs'
        |> List.map2 Option.defaultValue exprs
        |> ExprList
        |> Some
    | Store(memVar, rt, addr, src) ->
      let addr' = replaceLoad state addr |> Option.defaultValue addr
      let src' = replaceLoad state src |> Option.defaultValue src
      if addr' = addr && src' = src then None
      else Some(Store(memVar, rt, addr', src'))
    | UnOp(op, rt, e) ->
      replaceLoad state e
      |> Option.map (fun e -> UnOp(op, rt, e))
    | BinOp(op, rt, le, re) ->
      let le' = replaceLoad state le |> Option.defaultValue le
      let re' = replaceLoad state re |> Option.defaultValue re
      if le' = le && re' = re then None else Some(BinOp(op, rt, le', re'))
    | RelOp(op, rt, le, re) ->
      let le' = replaceLoad state le |> Option.defaultValue le
      let re' = replaceLoad state re |> Option.defaultValue re
      if le' = le && re' = re then None else Some(RelOp(op, rt, le', re'))
    | Ite(cond, rt, le, re) ->
      let cond' = replaceLoad state cond |> Option.defaultValue cond
      let le' = replaceLoad state le |> Option.defaultValue le
      let re' = replaceLoad state re |> Option.defaultValue re
      if cond' = cond && le' = le && re' = re then None
      else Some(Ite(cond', rt, le', re'))
    | Cast(ck, rt, e) ->
      replaceLoad state e
      |> Option.map (fun e -> Cast(ck, rt, e))
    | Extract(e, rt, sPos) ->
      replaceLoad state e
      |> Option.map (fun e -> Extract(e, rt, sPos))
    | _ ->
      None

  let stmtChooser state ((pp, stmt) as stmtInfo) =
    match stmt with
    | Phi _ ->
      None
    | Def({ Kind = MemVar } as dstMemVar, Store(memVar, rt, addrExpr, src)) ->
      let addr = (state: SSASparseDataFlow.State<_>).EvalExpr addrExpr
      let src = replaceLoad state src |> Option.defaultValue src
      match memStore pp rt addr src with
      | Some stmtInfo ->
        Some stmtInfo
      | None ->
        let addrExpr =
          replaceLoad state addrExpr |> Option.defaultValue addrExpr
        Some(pp, Def(dstMemVar, Store(memVar, rt, addrExpr, src)))
    | Def(dstVar, e) ->
      match replaceLoad state e with
      | Some e -> Some(pp, Def(dstVar, e))
      | None -> Some stmtInfo
    | _ ->
      Some stmtInfo

  /// Propagates the stack pointer through the given SSACFG.
  let propagateStackPointer hdl ssaCFG =
    let spp = SSAStackPointerPropagation hdl
    let dfa = spp :> IDataFlowComputable<_, _, _, _>
    dfa.Compute ssaCFG

  /// Rewrites every stack slot the given propagation knows the address of
  /// into a variable of its own.
  let promote state ssaCFG =
    for v in (ssaCFG: SSACFG).Vertices do
      v.VData.Internals.Statements
      |> Array.choose (stmtChooser state)
      |> v.VData.Internals.UpdateStatements

  let create hdl stmtProcessor (observer: ISSAStackPointerObserver) =
    { new ISSALiftable with
        member _.Lift cfg =
          let ssaCFG = SSACFG.create cfg.ImplementationType
          convertToSSA stmtProcessor cfg ssaCFG
          let dom = createDominance ssaCFG
          buildSSAForm ssaCFG dom
          let state = propagateStackPointer hdl ssaCFG
          (* The propagation is observed on the graph it read, and before the
             renaming below mutates the very variables it is keyed under.
             Later than here it is unreadable. *)
          observer.Observe(ssaCFG, dom, state)
          promote state ssaCFG
          (* Promotion turns stack slots into variables the round of phi
             placement above knew nothing about, and it drops every phi that
             round placed, so the form is built a second time over what
             promotion leaves behind. *)
          buildSSAForm ssaCFG dom
          SSACFGWithDominance(ssaCFG, dom) }

/// Provides ways to create an SSA lifter.
type SSALifterFactory =
  /// Creates an SSA lifter with a binary handle.
  static member Create(hdl: BinHandle) =
    let wordSize = hdl.ISA.WordSize
    SSALifterFactory.create hdl
      { new IStmtPostProcessor with
          member _.WordSize with get() = wordSize
          member _.PostProcess stmt = stmt }
      { new ISSAStackPointerObserver with
          member _.Observe(_, _, _) = () }

  /// Creates an SSA lifter with a binary handle and a statement processor.
  static member Create(hdl, stmtProcessor) =
    SSALifterFactory.create hdl
      stmtProcessor
      { new ISSAStackPointerObserver with
          member _.Observe(_, _, _) = () }

  /// Creates an SSA lifter with a binary handle and an observer of the stack
  /// pointer propagation.
  static member Create(hdl: BinHandle, observer) =
    let wordSize = hdl.ISA.WordSize
    SSALifterFactory.create hdl
      { new IStmtPostProcessor with
          member _.WordSize with get() = wordSize
          member _.PostProcess stmt = stmt }
      observer

  /// Creates an SSA lifter with a binary handle, a statement processor, and
  /// an observer of the stack pointer propagation.
  static member Create(hdl, stmtProcessor, observer) =
    SSALifterFactory.create hdl stmtProcessor observer
