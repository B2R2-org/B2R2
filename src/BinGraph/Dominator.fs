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

module B2R2.BinGraph.Dominator

open B2R2.Utils
open System.Collections.Generic

type DominatorContext<'V when 'V :> VertexData> =
    {
        /// Vertex ID -> DFNum
        DFNumMap      : Dictionary<VertexID, int>
        /// DFNum -> Vertex
        Vertex        : Vertex<'V> []
        /// DFNum -> DFNum in the ancestor chain s.t. DFNum of its Semi is minimal.
        Label         : int []
        /// DFNum -> DFNum of the parent node (zero if not exists).
        Parent        : int []
        /// DFNum -> DFNum of the child node (zero if not exists).
        Child         : int []
        /// DFNum -> DFNum of an ancestor.
        Ancestor      : int []
        /// DFNum -> DFNum of a semidominator.
        Semi          : int []
        /// DFNum -> set of DFNums (vertices that share the same sdom).
        Bucket        : Set<int> []
        /// DFNum -> Size
        Size          : int []
        /// DFNum -> DFNum of an immediate dominator.
        IDom          : int []
        /// Length of the arrays.
        MaxLength     : int
    }

let initContext (g: DiGraph<_, _>) =
    let len = g.Size () + 2 (* To reserve a room for entry (dummy) node. *)
    {
        DFNumMap = Dictionary<VertexID, int>()
        Vertex = Array.zeroCreate len
        Label = Array.create len 0
        Parent = Array.create len 0
        Child = Array.create len 0
        Ancestor = Array.create len 0
        Semi = Array.create len 0
        Bucket = Array.create len Set.empty
        Size = Array.create len 1
        IDom = Array.create len 0
        MaxLength = len
    }

let inline dfnum ctxt (v: Vertex<_>) =
    ctxt.DFNumMap.[v.GetID ()]

let rec assignDFNum ctxt n = function
    | (p, v: Vertex<_>) :: stack
            when not <| ctxt.DFNumMap.ContainsKey (v.GetID ()) ->
        ctxt.DFNumMap.Add (v.GetID (), n)
        ctxt.Semi.[n] <- n
        ctxt.Vertex.[n] <- v
        ctxt.Label.[n] <- n
        ctxt.Parent.[n] <- p
        List.fold (fun acc s -> (n, s) :: acc) stack v.Succs
        |> assignDFNum ctxt (n+1)
    | _ :: stack -> assignDFNum ctxt n stack
    | [] -> n

let rec compress ctxt v =
    let a = ctxt.Ancestor.[v]
    if ctxt.Ancestor.[a] <> 0 then
        compress ctxt a
        if ctxt.Semi.[ctxt.Label.[a]] < ctxt.Semi.[ctxt.Label.[v]] then
            ctxt.Label.[v] <- ctxt.Label.[a]
        else ()
        ctxt.Ancestor.[v] <- ctxt.Ancestor.[a]

let eval ctxt v =
    let a = ctxt.Ancestor.[v]
    if a = 0 then ctxt.Label.[v]
    else
        compress ctxt v
        if ctxt.Semi.[ctxt.Label.[a]] >= ctxt.Semi.[ctxt.Label.[v]] then
            ctxt.Label.[v]
        else ctxt.Label.[a]

/// Compute semidominator of v.
let rec computeSemiDom ctxt v = function
    | pred :: preds ->
        let u = eval ctxt pred
        if ctxt.Semi.[u] < ctxt.Semi.[v] then ctxt.Semi.[v] <- ctxt.Semi.[u]
        computeSemiDom ctxt v preds
    | [] -> ()

let link ctxt v w =
    let mutable s = w
    while ctxt.Semi.[ctxt.Label.[w]] < ctxt.Semi.[ctxt.Label.[ctxt.Child.[s]]] do
        if ctxt.Size.[s] + ctxt.Size.[ctxt.Child.[ctxt.Child.[s]]]
              >= 2 * ctxt.Size.[ctxt.Child.[s]]
        then 
            ctxt.Ancestor.[ctxt.Child.[s]] <- s
            ctxt.Child.[s] <- ctxt.Child.[ctxt.Child.[s]]
        else 
            ctxt.Size.[ctxt.Child.[s]] <- ctxt.Size.[s]
            ctxt.Ancestor.[s] <- ctxt.Child.[s]
            s <- ctxt.Ancestor.[s]
    done
    ctxt.Label.[s] <- ctxt.Label.[w]
    ctxt.Size.[v] <- ctxt.Size.[v] + ctxt.Size.[w]
    if ctxt.Size.[v] < 2 * ctxt.Size.[w] then
        let t = s
        s <- ctxt.Child.[v]
        ctxt.Child.[v] <- t
    while s <> 0 do
        ctxt.Ancestor.[s] <- v
        s <- ctxt.Child.[s]
    done

let computeDom ctxt p =
    Set.iter (fun v ->
        let u = eval ctxt v
        if ctxt.Semi.[u] < ctxt.Semi.[v] then ctxt.IDom.[v] <- u
        else ctxt.IDom.[v] <- p) ctxt.Bucket.[p]
    ctxt.Bucket.[p] <- Set.empty

let rec computeDomOrDelay ctxt parent =
    if ctxt.Bucket.[parent].IsEmpty then ()
    else computeDom ctxt parent

/// Temporarily connect entry dummy node and real entry nodes.
let connect (g: DiGraph<_, _>) =
    let root = g.GetRoot ()
    if root.GetID () = 0 then root (* We already have added a dummy node. *)
    else
        let dummyEntry = Vertex<_> ()
        dummyEntry.Succs <- [root]
        root.Preds <- dummyEntry :: root.Preds
        dummyEntry

/// Disconnect the dummy node and the entry nodes.
let disconnect (g: DiGraph<_, _>) =
    let root = g.GetRoot ()
    root.Preds <- root.Preds |> List.filter (fun p -> p.GetID () <> root.GetID ())

let initDominator (g: DiGraph<_, _>) =
    let ctxt = initContext g
    let dummyEntry = connect g
    let n = assignDFNum ctxt 1 [(0, dummyEntry)]
    for i = n - 1 downto 2 do
        let v = ctxt.Vertex.[i]
        let p = ctxt.Parent.[i]
        List.map (dfnum ctxt) v.Preds |> computeSemiDom ctxt i
        ctxt.Bucket.[ctxt.Semi.[i]] <- Set.add i ctxt.Bucket.[ctxt.Semi.[i]]
        link ctxt p i (* Link the parent (p) to the forest. *)
        computeDomOrDelay ctxt p
    done
    disconnect g
    for i = 2 to n - 1 do
        if ctxt.IDom.[i] <> ctxt.Semi.[i] then
            ctxt.IDom.[i] <- ctxt.IDom.[ctxt.IDom.[i]]
        else ()
    done
    ctxt

let checkVertexInGraph (g: DiGraph<'V, 'E>) (v: Vertex<'V>) =
    let v' = g.FindVertex v
    if v === v' then ()
    else raise VertexNotFoundException

let private idomAux g v =
    let ctxt = initDominator g
    let id = ctxt.IDom.[dfnum ctxt v]
    if id > 1 then Some ctxt.Vertex.[id] else None

let idom g v =
    checkVertexInGraph g v
    idomAux g v

let preparePostDomAnalysis (g: DiGraph<'V, 'E>) =
    match g.Unreachables with
    | [] -> (* No exit nodes found: make an arbitrary node as a root. *)
        g.FoldVertex (fun _ v -> Some v) None |> Option.iter (fun v -> g.SetRoot v)
    | [v] -> g.SetRoot v
    | vertices ->
        let dummy = Vertex<'V> ()
        dummy.Succs <- vertices
        vertices |> List.iter (fun v -> v.Preds <- dummy :: v.Preds)
        g.SetRoot dummy
    g

let ipdom (g: DiGraph<'V, 'E>) (v: Vertex<'V>) =
    let g' = g.Reverse () |> preparePostDomAnalysis
    let v = g'.FindVertex v
    idomAux g' v

let rec domsAux acc v ctxt =
    let id = ctxt.IDom.[dfnum ctxt v]
    if id > 0 then domsAux (ctxt.Vertex.[id] :: acc) ctxt.Vertex.[id] ctxt
    else List.rev acc

let doms (g: DiGraph<'V, 'E>) (v: Vertex<'V>) =
    checkVertexInGraph g v
    initDominator g |> domsAux [] v

let pdoms (g: DiGraph<'V, 'E>) v =
    let g' = g.Reverse () |> preparePostDomAnalysis
    initDominator g' |> domsAux [] v

let computeDomTree (g: DiGraph<'V, 'E>) entry ctxt =
    let domTree = Array.create ctxt.MaxLength []
    g.IterVertexDFS (fun v ->
        let idom = ctxt.IDom.[dfnum ctxt v]
        domTree.[idom] <- v :: domTree.[idom])
    domTree

let rec computeFrontierLocal s ctxt (parent: Vertex<_>) = function
    | succ :: rest ->
        let succID = dfnum ctxt succ
        let d = ctxt.Vertex.[ctxt.IDom.[succID]]
        let s = if d.GetID () = parent.GetID () then s else Set.add succID s
        computeFrontierLocal s ctxt parent rest
    | [] -> s

let rec computeDF (frontiers: Vertex<_> list []) g ctxt (r: Vertex<'V>) =
    let mutable s = Set.empty
    for succ in r.Succs do
        let succID = dfnum ctxt succ
        let d = ctxt.Vertex.[ctxt.IDom.[succID]]
        if d.GetID () <> r.GetID () then s <- Set.add succID s
    done
    let domTree = computeDomTree g r ctxt
    for child in domTree.[dfnum ctxt r] do
        computeDF frontiers g ctxt child
        for node in frontiers.[dfnum ctxt child] do
            let doms = domsAux [] node ctxt
            let dominate = doms |> List.exists (fun d -> d.GetID () = r.GetID ())
            if not dominate then s <- Set.add (dfnum ctxt node) s
        done
    done
    frontiers.[dfnum ctxt r] <- Set.fold (fun df n -> ctxt.Vertex.[n] :: df) [] s

let frontier (g: DiGraph<'V, 'E>) v =
    checkVertexInGraph g v
    let root = g.GetRoot ()
    let ctxt = initDominator g
    let frontiers = Array.create ctxt.MaxLength []
    computeDF frontiers g ctxt root
    frontiers.[dfnum ctxt v]

// vim: set tw=80 sts=2 sw=2:
