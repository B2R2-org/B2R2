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
open B2R2.BinIR.SSA
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

/// Provides the one operation that puts a graph of SSA statements into SSA
/// form, which both lifting a graph and promoting the stack slots of one have
/// to do to what they leave behind.
module internal SSAForm =
  /// Represents a mapping from a variable to the SSA basic blocks defining it.
  type DefSites = Dictionary<VariableKind, HashSet<SSAVertex>>

  /// Represents how many definitions each variable has been given so far.
  type VarCountMap = Dictionary<VariableKind, int>

  /// Represents the identifiers in scope for each variable, innermost first.
  type IDStack = Dictionary<VariableKind, int list>

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
  let build ssaCFG dom =
    let defSites = DefSites()
    let globals = findDefVars ssaCFG defSites
    placePhis ssaCFG defSites globals dom
    renameVars ssaCFG defSites dom
    ssaCFG |> DiGraph.iterVertex (fun v -> v.VData.Internals.UpdatePPoints())
