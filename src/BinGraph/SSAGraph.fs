(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Soomin Kim <soomink@kaist.ac.kr>

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

module B2R2.BinGraph.SSAGraph

open B2R2
open B2R2.FrontEnd
open B2R2.BinIR.SSA
open B2R2.BinGraph

type DefKind =
  | Reg of RegType * RegisterID * string
  | PC of RegType
  | Mem

let defKindToDest = function
  | Reg (ty, r, s) -> RegVar (ty, r, s, -1)
  | PC ty -> PCVar (ty, -1)
  | Mem -> MemVar -1

let destToDefKind = function
  | RegVar (ty, r, s, _) -> Reg (ty, r, s)
  | PCVar (ty, _) -> PC ty
  | MemVar _ -> Mem
  | _ -> failwith "Unexpected"

type SSAContext =
  {
    PredMap : Map<VertexID, VertexID []>
    SuccMap : Map<VertexID, (VertexID * CFGEdge) list>
    DFMap : Map<VertexID, VertexID list>
    SSAMap : Map<VertexID, Stmt list>
    DomTree : Map<VertexID, VertexID list> * int
  }

let getDomTree ctxt =
  let domTree, root = Dominator.dominatorTree ctxt
  let domTree =
    Map.fold (fun tree (v: Vertex<_>) vs ->
      let vs = List.map (fun (v: Vertex<_>) -> v.GetID ()) vs
      Map.add (v.GetID ()) vs tree) Map.empty domTree
  let root = root.GetID ()
  domTree, root

let getGraphInfo domCtxt (irCFG: IRCFG) ssaCtxt (v: Vertex<_>) =
  let id = v.VData.ID
  let preds =
    List.toArray v.Preds |> Array.map (fun (v: Vertex<_>) -> v.GetID ())
  let predMap = Map.add id preds ssaCtxt.PredMap
  let succs =
    List.map (fun (w: Vertex<_>) ->
      let edge = irCFG.FindEdge v w
      w.GetID (), edge) v.Succs
  let succMap = Map.add id succs ssaCtxt.SuccMap
  let frontiers =
    Dominator.frontier domCtxt v
    |> List.map (fun (v: Vertex<IRBBL>) -> v.GetID ())
  let dfMap = Map.add id frontiers ssaCtxt.DFMap
  { ssaCtxt with PredMap = predMap ; SuccMap = succMap ; DFMap = dfMap }

let translateIR regType ctxt (v: Vertex<IRBBL>) =
  let vData = v.VData
  let stmts = Translate.translateStmt regType (fst vData.Ppoint) [] vData.Stmts
  let ssaMap = Map.add vData.ID stmts ctxt.SSAMap
  { ctxt with SSAMap = ssaMap }

let initContext regType (irCFG: IRCFG) =
  let ctxt = Dominator.initDominatorContext irCFG
  let domTree = getDomTree ctxt
  { PredMap = Map.empty ; SuccMap = Map.empty ; DFMap = Map.empty ;
    SSAMap = Map.empty ; DomTree = domTree }
  |> irCFG.FoldVertex (getGraphInfo ctxt irCFG)
  |> irCFG.FoldVertex (translateIR regType)

let addDefFromDest defSet = function
  | RegVar (ty, r, s, _) -> Set.add (Reg (ty, r, s)) defSet
  | PCVar (ty, _) -> Set.add (PC ty) defSet
  | TempVar _ -> defSet
  | MemVar _ -> Set.add Mem defSet

let rec addDefFromExpr defSet = function
  | Num _ -> defSet
  | Var dest -> addDefFromDest defSet dest
  | Load (dest, _, expr) ->
    let defSet = addDefFromExpr defSet expr
    addDefFromDest defSet dest
  | Store (dest, expr1, expr2) ->
    let defSet = addDefFromExpr defSet expr1
    let defSet = addDefFromExpr defSet expr2
    addDefFromDest defSet dest
  | FuncName _ -> defSet
  | UnOp (_, expr) -> addDefFromExpr defSet expr
  | BinOp (_, _, expr1, expr2) ->
    let defSet = addDefFromExpr defSet expr1
    addDefFromExpr defSet expr2
  | RelOp (_, expr1, expr2) ->
    let defSet = addDefFromExpr defSet expr1
    addDefFromExpr defSet expr2
  | Ite (expr1, expr2, expr3) ->
    let defSet = addDefFromExpr defSet expr1
    let defSet = addDefFromExpr defSet expr2
    addDefFromExpr defSet expr3
  | Cast (_, _, expr) -> addDefFromExpr defSet expr
  | Extract (expr, _, _) -> addDefFromExpr defSet expr
  | Undefined _ -> defSet

let collectVars defSet = function
  | Def (dest, expr) ->
    let defSet = addDefFromExpr defSet expr
    addDefFromDest defSet dest
  | Phi (dest, _) -> addDefFromDest defSet dest
  | _ -> defSet

let collectDefs defSet = function
  | Def (dest, _)
  | Phi (dest, _) -> addDefFromDest defSet dest
  | _ -> defSet

let getDefSite def defSites =
  match Map.tryFind def defSites with
  | Some defSite -> defSite
  | None -> Set.empty

let collectDefSite id defSites def =
  let defSite = getDefSite def defSites
  Map.add def defSite defSites

let collectDefSites defSites id defSet =
  Set.fold (collectDefSite id) defSites defSet

let findPhiSiteAux defs def phiSite w id =
  if not <| Set.contains id phiSite then
    let phiSite = Set.add id phiSite
    if not <| Set.contains def (Map.find id defs) then phiSite, id :: w
    else phiSite, id :: w
  else phiSite, w

let rec findPhiSite dfMap defs def phiSite = function
  | [] -> phiSite
  | id :: w ->
    let frontiers = Map.find id dfMap
    let phiSite, w = findPhiSiteAux defs def phiSite w id
    findPhiSite dfMap defs def phiSite w

let findPhiSites dfMap defs def defSites =
  let w = Set.toList defSites
  findPhiSite dfMap defs def Set.empty w

let insertPhiAux predMap def ssaMap id =
  let numPreds = Map.find id predMap |> Array.length
  let stmts = Map.find id ssaMap
  let stmts =
    if numPreds > 1 then
      Phi (defKindToDest def, Array.zeroCreate numPreds) :: stmts
    else stmts
  Map.add id stmts ssaMap

let insertPhi predMap ssaMap def phiSites =
  Set.fold (insertPhiAux predMap def) ssaMap phiSites

let placePhis ctxt =
  let ssaMap = ctxt.SSAMap
  let defs =
    Map.map (fun _ stmts -> List.fold collectDefs Set.empty stmts) ssaMap
  let defSites = Map.fold collectDefSites Map.empty defs
  let phiSites = Map.map (findPhiSites ctxt.DFMap defs) defSites
  let ssaMap = Map.fold (insertPhi ctxt.PredMap) ssaMap phiSites
  { ctxt with SSAMap = ssaMap }

let initializeRenaming regType ssaMap =
  let defs =
    Map.fold (fun d _ stmts -> List.fold collectVars d stmts) Set.empty ssaMap
    |> Set.add Mem |> Set.add (PC regType)
  let counts = Set.fold (fun count def -> Map.add def 0 count) Map.empty defs
  let stacks = Set.fold (fun stack def -> Map.add def [0] stack) Map.empty defs
  counts, stacks

let renameDest stacks = function
  | RegVar (ty, r, s, _) ->
    let def = Reg (ty, r, s)
    let i = Map.find def stacks |> List.head
    RegVar (ty, r, s, i)
  | PCVar (ty, _) ->
    let def = PC ty
    let i = Map.find def stacks |> List.head
    PCVar (ty, i)
  | TempVar _ as def -> def
  | MemVar _ ->
    let def = Mem
    let i = Map.find def stacks |> List.head
    MemVar i

let rec renameExpr stacks = function
  | (Num _ as expr)
  | (Undefined _ as expr)
  | (FuncName _ as expr) -> expr
  | Var def -> Var <| renameDest stacks def
  | Load (def, ty, expr) ->
    let def = renameDest stacks def
    let expr = renameExpr stacks expr
    Load (def, ty, expr)
  | Store (def, addr, expr) ->
    let def = renameDest stacks def
    let addr = renameExpr stacks addr
    let expr = renameExpr stacks expr
    Store (def, addr, expr)
  | UnOp (op, expr) ->
    let expr = renameExpr stacks expr
    UnOp (op, expr)
  | BinOp (op, ty, expr1, expr2) ->
    let expr1 = renameExpr stacks expr1
    let expr2 = renameExpr stacks expr2
    BinOp (op, ty, expr1, expr2)
  | RelOp (op, expr1, expr2) ->
    let expr1 = renameExpr stacks expr1
    let expr2 = renameExpr stacks expr2
    RelOp (op, expr1, expr2)
  | Ite (expr1, expr2, expr3) ->
    let expr1 = renameExpr stacks expr1
    let expr2 = renameExpr stacks expr2
    let expr3 = renameExpr stacks expr3
    Ite (expr1, expr2, expr3)
  | Cast (op, ty, expr) ->
    let expr = renameExpr stacks expr
    Cast (op, ty, expr)
  | Extract (expr, ty, pos) ->
    let expr = renameExpr stacks expr
    Extract (expr, ty, pos)

let renameJmp stacks = function
  | IntraJmp _ as jmpTy -> jmpTy
  | IntraCJmp (expr, label1, label2) ->
    let expr = renameExpr stacks expr
    IntraCJmp (expr, label1, label2)
  | InterJmp (def, expr) ->
    let def = renameDest stacks def
    let expr = renameExpr stacks expr
    InterJmp (def, expr)
  | InterCJmp (expr1, def, expr2, expr3) ->
    let def = renameDest stacks def
    let expr1 = renameExpr stacks expr1
    let expr2 = renameExpr stacks expr2
    let expr3 = renameExpr stacks expr3
    InterCJmp (expr1, def, expr2, expr3)

let introduceDef counts stacks = function
  | RegVar (ty, r, s, _) ->
    let def = Reg (ty, r, s)
    let cnt = Map.find def counts + 1
    let counts = Map.add def cnt counts
    let stacks = Map.add def (cnt :: Map.find def stacks) stacks
    RegVar (ty, r, s, cnt), counts, stacks
  | PCVar (ty, _) ->
    let def = PC ty
    let cnt = Map.find def counts + 1
    let counts = Map.add def cnt counts
    let stacks = Map.add def (cnt :: Map.find def stacks) stacks
    PCVar (ty, cnt), counts, stacks
  | TempVar _ as def -> def, counts, stacks
  | MemVar _ ->
    let def = Mem
    let cnt = Map.find def counts + 1
    let counts = Map.add def cnt counts
    let stacks = Map.add def (cnt :: Map.find def stacks) stacks
    MemVar cnt, counts, stacks

let renameStmt (acc, counts, stacks) = function
  | (LMark _ as stmt)
  | (SideEffect _ as stmt) -> stmt :: acc, counts, stacks
  | Jmp jmpTy ->
    let jmpTy = renameJmp stacks jmpTy
    Jmp jmpTy :: acc, counts, stacks
  | Def (def, expr) ->
    let expr = renameExpr stacks expr
    let def, counts, stacks = introduceDef counts stacks def
    Def (def, expr) :: acc, counts, stacks
  | Phi (def, nums) ->
    let def, counts, stacks = introduceDef counts stacks def
    Phi (def, nums) :: acc, counts, stacks

let renamePhiAux stacks preds parent = function
  | Phi (def, nums) ->
    let p = Array.findIndex (fun i -> i = parent) preds
    let i = Map.find (destToDefKind def) stacks |> List.head
    nums.[p] <- i
  | _ -> ()

let renamePhi stacks predMap parent ssaMap n =
  let preds = Map.find n predMap
  let stmts = Map.find n ssaMap
  List.iter (renamePhiAux stacks preds parent) stmts
  Map.add n stmts ssaMap

let rec rename tree predMap succMap aOrig (ssaMap, counts, stacks) n =
  let stmts = Map.find n ssaMap
  let stmts, counts, stacks =
    List.fold renameStmt ([], counts, stacks) stmts
  let ssaMap = Map.add n (List.rev stmts) ssaMap
  let ssaMap =
    List.fold (renamePhi stacks predMap n) ssaMap (Map.find n succMap)
  let children = Map.find n tree
  let ssaMap, counts, stacks =
    List.fold (rename tree predMap succMap aOrig) (ssaMap, counts, stacks) children
  let defs = Map.find n aOrig
  let stacks = Set.fold (fun stacks def ->
    let stack = Map.find def stacks |> List.tail
    Map.add def stack stacks) stacks defs
  ssaMap, counts, stacks

let renameVars regType ctxt =
  let ssaMap = ctxt.SSAMap
  let counts, stacks = initializeRenaming regType ssaMap
  let defs =
    Map.map (fun _ stmts -> List.fold collectDefs Set.empty stmts) ssaMap
  let tree, root = ctxt.DomTree
  let ssaMap = ctxt.SSAMap
  let succMap = Map.map (fun _ succs -> List.map fst succs) ctxt.SuccMap
  let ssaMap, _, _ =
    rename tree ctxt.PredMap succMap defs (ssaMap, counts, stacks) root
  { ctxt with SSAMap = ssaMap }

let toResolve = function
  | Jmp (IntraJmp _)
  | Jmp (IntraCJmp _)
  | Jmp (InterJmp (_, Num _))
  | Jmp (InterCJmp (_, _, Num _, Num _)) -> false
  | Jmp (InterJmp _)
  | Jmp (InterCJmp _) -> true
  | _ -> false

let genVMap (g: SSACFG) n stmts =
  let ssaBBL = SSABBL (stmts, List.head <| List.rev stmts)
  if toResolve ssaBBL.LastStmt then ssaBBL.ToResolve <- true
  g.AddVertex ssaBBL

let addEdge (g: SSACFG) p (c, ty) =
  g.AddEdge p c ty

let addEdges vMap g p cs =
  let p = Map.find p vMap
  let cs = List.map (fun (c, ty) -> Map.find c vMap, ty) cs
  List.iter (addEdge g p) cs

let buildCFG g ctxt =
  let vMap = Map.map (genVMap g) ctxt.SSAMap
  Map.iter (addEdges vMap g) ctxt.SuccMap

let transform (hdl: BinHandler) irCFG ssaCFG =
  let regType =
    hdl.FileInfo.WordSize |> WordSize.toByteWidth |> RegType.fromByteWidth
  let ctxt = initContext regType irCFG
  let ctxt = placePhis ctxt
  let ctxt = renameVars regType ctxt
  buildCFG ssaCFG ctxt
