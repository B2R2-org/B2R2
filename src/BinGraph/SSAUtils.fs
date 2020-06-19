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

module internal B2R2.BinGraph.SSAUtils

open B2R2
open B2R2.BinIR

let computeFrontiers (g: SSACFG) root =
  let domCtxt = Dominator.initDominatorContext g root
  g.IterVertex (fun v -> v.VData.Frontier <- Dominator.frontier domCtxt v)
  domCtxt

let collectDefVars defs = function
  | SSA.Def ({ Kind = k }, _) -> Set.add k defs
  | _ -> defs

let findPhiSites defsPerNode variable (phiSites, workList) v =
  if Set.contains v phiSites then phiSites, workList
  else
    (* Insert Phi for v *)
    (v: Vertex<SSABBlock>).VData.InsertPhi variable v.Preds.Length
    let phiSites = Set.add v phiSites
    let defs = (defsPerNode: DefsPerNode).[v]
    if not <| Set.contains variable defs then phiSites, v :: workList
    else phiSites, workList

let rec iterDefs phiSites defsPerNode variable = function
  | [] -> phiSites
  | (v: Vertex<SSABBlock>) :: workList ->
    let phiSites, workList =
      v.VData.Frontier
      |> List.fold (findPhiSites defsPerNode variable) (phiSites, workList)
    iterDefs phiSites defsPerNode variable workList

let placePhis (vMap: SSAVMap) (fMap: FakeVMap) (defSites: DefSites) domCtxt =
  let defsPerNode = DefsPerNode ()
  Seq.append vMap.Values fMap.Values
  |> Seq.iter (fun v ->
    let defs = v.VData.Stmts |> Array.fold collectDefVars Set.empty
    defsPerNode.[v] <- defs
    defs |> Set.iter (fun d ->
      if defSites.ContainsKey d then defSites.[d] <- Set.add v defSites.[d]
      else defSites.[d] <- Set.singleton v))
  for KeyValue (variable, defs) in defSites do
    match variable with
    | SSA.TempVar (_) when defs.Count = 1 ->
      (* We can safely ignore TempVars here because they are used only within a
         single basic block. *)
      ()
    | _ ->
      Set.toList defs
      |> iterDefs Set.empty defsPerNode variable
      |> ignore
  domCtxt

let renameDest (stack: IDStack) (dest: SSA.Variable) =
  match dest.Kind with
  | SSA.RegVar (_)
  | SSA.TempVar (_)
  | SSA.MemVar
  | SSA.PCVar (_) ->
    match stack.TryGetValue dest.Kind with
    | false, _ -> dest.Identifier <- 0
    | true, ids -> dest.Identifier <- List.head ids

let rec renameExpr stack = function
  | SSA.Num (_)
  | SSA.Undefined (_)
  | SSA.FuncName (_)
  | SSA.Nil -> ()
  | SSA.ReturnVal (_, _, v) -> renameDest stack v
  | SSA.Var v -> renameDest stack v
  | SSA.Load (v, _, expr) ->
    renameDest stack v
    renameExpr stack expr
  | SSA.Store (mem, _, addr, expr) ->
    renameDest stack mem
    renameExpr stack addr
    renameExpr stack expr
  | SSA.UnOp (_, _, expr) ->
    renameExpr stack expr
  | SSA.BinOp (_, _, expr1, expr2) ->
    renameExpr stack expr1
    renameExpr stack expr2
  | SSA.RelOp (_, _, expr1, expr2) ->
    renameExpr stack expr1
    renameExpr stack expr2
  | SSA.Ite (expr1, _, expr2, expr3) ->
    renameExpr stack expr1
    renameExpr stack expr2
    renameExpr stack expr3
  | SSA.Cast (_, _, expr) ->
    renameExpr stack expr
  | SSA.Extract (expr, _, _) ->
    renameExpr stack expr

let renameJmp stack = function
  | SSA.IntraJmp _ -> ()
  | SSA.IntraCJmp (expr, _, _) ->
    renameExpr stack expr
  | SSA.InterJmp (expr) ->
    renameExpr stack expr
  | SSA.InterCJmp (cond, target1, target2) ->
    renameExpr stack cond
    renameExpr stack target1
    renameExpr stack target2

let introduceDef (count: VarCountMap) (stack: IDStack) (v: SSA.Variable) =
  match v.Kind with
  | SSA.RegVar (_)
  | SSA.TempVar (_)
  | SSA.MemVar
  | SSA.PCVar (_) ->
    count.[v.Kind] <- count.[v.Kind] + 1
    let i = count.[v.Kind]
    stack.[v.Kind] <- i :: stack.[v.Kind]
    v.Identifier <- i

let renameStmt count stack = function
  | SSA.LMark _
  | SSA.SideEffect _ -> ()
  | SSA.Jmp jmpTy -> renameJmp stack jmpTy
  | SSA.Def (def, e) ->
    renameExpr stack e
    introduceDef count stack def
  | SSA.Phi (def, _) ->
    introduceDef count stack def

let renamePhiAux (stack: IDStack) preds (parent: Vertex<SSABBlock>) = function
  | SSA.Phi (def, nums) ->
    let idx =
      List.findIndex (fun (v: Vertex<SSABBlock>) ->
        v.VData = parent.VData) preds
    nums.[idx] <- List.head stack.[def.Kind]
  | _ -> ()

let renamePhi stack (parent: Vertex<SSABBlock>) (succ: Vertex<SSABBlock>) =
  succ.VData.Stmts |> Array.iter (renamePhiAux stack succ.Preds parent)

let popStack (stack: IDStack) = function
  | SSA.LMark _
  | SSA.SideEffect _
  | SSA.Jmp _ -> ()
  | SSA.Def (def, _)
  | SSA.Phi (def, _) -> stack.[def.Kind] <- List.tail stack.[def.Kind]

let rec rename domTree count stack (v: Vertex<SSABBlock>) =
  v.VData.Stmts |> Array.iter (renameStmt count stack)
  v.Succs |> List.iter (renamePhi stack v)
  traverseChildren domTree count stack (Map.find v domTree)
  v.VData.Stmts |> Array.iter (popStack stack)
and traverseChildren domTree count stack = function
  | child :: rest ->
    rename domTree count stack child
    traverseChildren domTree count stack rest
  | [] -> ()

let renameVars (defSites: DefSites) domCtxt =
  let domTree, root = Dominator.dominatorTree domCtxt
  let count = VarCountMap ()
  let stack = IDStack ()
  defSites.Keys |> Seq.iter (fun variable ->
    count.[variable] <- 0
    stack.[variable] <- [0])
  rename domTree count stack root |> ignore
