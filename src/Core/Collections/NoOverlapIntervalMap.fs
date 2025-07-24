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

namespace B2R2.Collections

open B2R2

exception InvalidWhiteningException

exception KeyNotFoundException

type internal RBColor =
  /// Red
  | R
  /// Black
  | B
  /// Double Black
  | DB
  /// Negative Black
  | NB

type NoOverlapIntervalMap<'V> =
  | Leaf of RBColor
  | Node of RBColor
          * AddrRange
          * 'V
          * NoOverlapIntervalMap<'V>
          * NoOverlapIntervalMap<'V>

[<RequireQualifiedAccess>]
module NoOverlapIntervalMap =

  let (++) col1 col2 =
    match col1, col2 with
    | R, B
    | B, R -> B
    | B, B -> DB
    | _, _ -> R

  let whiten = function
    | DB -> B
    | B -> R
    | R -> NB
    | NB -> raise InvalidWhiteningException

  let toBlack = function
    | Node(R, k, v, l, r)
    | Node(DB, k, v, l, r) -> Node(B, k, v, l, r)
    | n -> n

  let rec private balance = function
    | ((DB|B) as l, zk, zv, Node(R, yk, yv, Node(R, xk, xv, a, b), c), d)
    | ((DB|B) as l, zk, zv, Node(R, xk, xv, a, Node(R, yk, yv, b, c)), d)
    | ((DB|B) as l, xk, xv, a, Node(R, zk, zv, Node(R, yk, yv, b, c), d))
    | ((DB|B) as l, xk, xv, a, Node(R, yk, yv, b, Node(R, zk, zv, c, d))) ->
      Node(whiten l, yk, yv, Node(B, xk, xv, a, b), Node(B, zk, zv, c, d))
    | (DB, zk, zv, Node(NB, xk, xv, Node(B, wk, wv, a, b),
                                     Node(B, yk, yv, c, d)), e) ->
      Node(B, yk, yv, balance (B, xk, xv, Node(R, wk, wv, a, b), c),
                       Node(B, zk, zv, d, e))
    | (DB, xk, xv, a,
                   Node(NB, zk, zv, Node(B, yk, yv, b, c),
                                     Node(B, wk, wv, d, e))) ->
      Node(B, yk, yv, Node(B, xk, xv, a, b),
                        balance (B, zk, zv, c, Node(R, wk, wv, d, e)))
    | node -> Node(node)

  let private fnAdd k v tree isReplace =
    let rec ins = function
      | Leaf _ -> Node(R, k, v, Leaf B, Leaf B)
      | Node(c, k', v', l, r) ->
        if k' = k then (if isReplace then Node(c, k', v, l, r)
                        else raise RangeOverlapException)
        elif k.Min < k'.Min && k.Max < k'.Min then
          balance (c, k', v', ins l, r)
        elif k.Min > k'.Max && k.Max > k'.Max then
          balance (c, k', v', l, ins r)
        else raise RangeOverlapException
    ins tree |> toBlack

  [<CompiledName("Add")>]
  let add k v tree = fnAdd k v tree false

  [<CompiledName("AddRange")>]
  let addRange min max v tree = add (AddrRange(min, max)) v tree

  [<CompiledName("Replace")>]
  let replace k v tree = fnAdd k v tree true

  let rec private findLoop isExact k = function
    | Leaf _ -> Error ErrorCase.ItemNotFound
    | Node(_, k', v', l, r) ->
      if k = k' then Ok(k', v')
      elif k.Min < k'.Min && k.Max < k'.Min then findLoop isExact k l
      elif k.Min > k'.Max && k.Max > k'.Max then findLoop isExact k r
      elif (not isExact) && k.Min >= k'.Min && k.Max <= k'.Max then Ok(k', v')
      else Error ErrorCase.ItemNotFound

  let rec private del isExact k = function
    | Leaf _ -> raise KeyNotFoundException
    | Node(c, k', v', l, r) ->
      if k = k' then delAndBalance isExact (c, l, r)
      elif k.Min < k'.Min && k.Max < k'.Min then
        bubble (c, k', v', del isExact k l, r)
      elif k.Min > k'.Max && k.Max > k'.Max then
        bubble (c, k', v', l, del isExact k r)
      elif not isExact && k.Min >= k'.Min && k.Max <= k'.Max then
        delAndBalance isExact (c, l, r)
      else raise RangeOverlapException

  and delAndBalance isExact = function
    | c, Leaf _, Leaf _ -> Leaf(B ++ c)
    | B, Leaf _, Node(_, nk, nv, nl, nr)
    | B, Node(_, nk, nv, nl, nr), Leaf _ -> Node(B, nk, nv, nl, nr)
    | c, l, r -> let k, v = findMax l in bubble (c, k, v, del isExact k l, r)

  and findMax = function
    | Leaf _ -> failwith "Max binding not found"
    | Node(_, k, v, _, Leaf _) -> k, v
    | Node(_, _, _, _, r) -> findMax r

  and bubble = function
    | (nc, nk, nv, Node(lc, lk, lv, a, b), Node(rc, rk, rv, c, d))
      when lc = DB || rc = DB ->
      balance (B ++ nc, nk, nv, Node(whiten lc, lk, lv, a, b),
                                Node(whiten rc, rk, rv, c, d))
    | (nc, nk, nv, Leaf DB, Node(rc, rk, rv, c, d)) ->
      balance (B ++ nc, nk, nv, Leaf B, Node(whiten rc, rk, rv, c, d))
    | (nc, nk, nv, Node(rc, rk, rv, c, d), Leaf DB) ->
      balance (B ++ nc, nk, nv, Node(whiten rc, rk, rv, c, d), Leaf B)
    | node -> Node node

  [<CompiledName("Remove")>]
  let remove k tree =
    del true k tree |> toBlack

  [<CompiledName("RemoveAddr")>]
  let removeAddr addr tree =
    del false (AddrRange addr) tree

  [<CompiledName("Empty")>]
  let empty = Leaf B

  [<CompiledName("IsEmpty")>]
  let isEmpty tree =
    match tree with
    | Leaf B -> true
    | _ -> false

  [<CompiledName("ContainsAddr")>]
  let containsAddr addr tree =
    findLoop false (AddrRange addr) tree |> Result.isOk

  [<CompiledName("ContainsRange")>]
  let containsRange range tree =
    findLoop true range tree |> Result.isOk

  [<CompiledName("Find")>]
  let find range tree =
    match findLoop true range tree with
    | Ok(_, v) -> v
    | _ -> raise KeyNotFoundException

  [<CompiledName("TryFindKey")>]
  let tryFindKey addr tree =
    match findLoop false (AddrRange addr) tree with
    | Ok(k, _) -> Some k
    | _ -> None

  [<CompiledName("TryFind")>]
  let tryFind range tree =
    match findLoop true range tree with
    | Ok(_, v) -> Some v
    | _ -> None

  [<CompiledName("TryFindByAddr")>]
  let tryFindByAddr addr tree =
    match findLoop false (AddrRange addr) tree with
    | Ok(_, v) -> Some v
    | _ -> None

  [<CompiledName("FindByAddr")>]
  let findByAddr addr tree =
    match findLoop false (AddrRange addr) tree with
    | Ok(_, v) -> v
    | _ -> raise KeyNotFoundException

  let rec private sizeAux acc tree =
    match tree with
    | Leaf _ -> acc
    | Node(_, _, _, l, r) -> sizeAux (sizeAux (acc + 1) l) r

  [<CompiledName("Count")>]
  let count tree = sizeAux 0 tree

  [<CompiledName("Iterate")>]
  let rec iter fn tree =
    match tree with
    | Leaf _ -> ()
    | Node(_, k, v, l, r) -> iter fn l; fn k v; iter fn r

  [<CompiledName("Fold")>]
  let rec fold fn acc tree =
    match tree with
    | Leaf _ -> acc
    | Node(_, k, v, l, r) ->
      let acc = fold fn acc l
      let acc = fn acc k v
      fold fn acc r

  [<CompiledName("GetOverlaps")>]
  let getOverlaps (k: AddrRange) tree =
    let rec loop acc = function
      | Leaf _ -> acc
      | Node(_, k', v', l, r) ->
        let acc = if k.Min < k'.Min then loop acc l else acc
        let acc =
          if k.Max < k'.Min || k.Min > k'.Max then acc
          else (k', v') :: acc
        let acc = if k.Max > k'.Max then loop acc r else acc
        acc
    loop [] tree
