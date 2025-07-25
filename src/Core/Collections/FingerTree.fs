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

/// FingerTree implementation.
module internal B2R2.Collections.FingerTree

exception EmptyTreeException
exception InvalidDigitException
exception InvalidNodeException

/// Monoid with an identity, and an associative operation.
type IMonoid<'A> =
  abstract member Zero: 'A
  abstract member Assoc: 'A -> 'A

/// A "typeclass" that has a measurement. The measurement should be a monoid.
type IMeasured<'V when 'V :> IMonoid<'V>> =
  abstract member Measurement: 'V

/// Returns the measurement.
let inline calib (m: IMeasured<_>) = m.Measurement

let inline combine<'V, 'A when 'V :> IMonoid<'V>
                           and 'A :> IMeasured<'V>
                  > (a: 'V) (b: 'V) = a.Assoc b
let inline (++) a b = combine a b

type Prio<'A when 'A : comparison> =
  | MInfty (* Minus infinity. *)
  | Prio of 'A

/// A monoid that represents a priority.
type Priority<'A when 'A : comparison> (p) =
  new () = Priority (MInfty)
  member inline _.Value: Prio<'A> = p
  override _.ToString () =
    match p with
    | MInfty -> ""
    | Prio p -> p.ToString ()
  interface IMonoid<Priority<'A>> with
    member _.Zero = Priority (MInfty)
    member this.Assoc (rhs: Priority<'A>) =
      match this.Value, rhs.Value with
      | Prio m, Prio n -> Priority (Prio (if m > n then m else n))
      | MInfty, p
      | p, MInfty -> Priority (p)

type Key<'A when 'A : comparison> =
  | NoKey
  | Key of 'A

/// A monoid that represents ordering.
type Ordered<'A when 'A : comparison> (k) =
  new () = Ordered (NoKey)
  member inline _.Key: Key<'A> = k
  override _.ToString () =
    match k with
    | NoKey -> ""
    | Key (k) -> k.ToString ()
  interface IMonoid<Ordered<'A>> with
    member _.Zero = Ordered (NoKey)
    member _.Assoc (rhs: Ordered<'A>) =
      match rhs.Key with
      | NoKey -> Ordered (k)
      | b -> Ordered (b)

/// A monoid that represents an interval (uint64 * uint64).
type InterMonoid<'A when 'A : comparison> (o, p) =
  let v = o, p
  new () = InterMonoid<'A> (Ordered<'A>(), Priority<'A>())
  member inline _.Value: Ordered<'A> * Priority<'A> = v
  member _.GetMin () = o.Key
  member _.GetMax () = p.Value
  override _.ToString () = "(" + o.ToString () + "," + p.ToString () + ")"
  interface IMonoid<InterMonoid<'A>> with
    member _.Zero =
      InterMonoid (Ordered<'A>(), Priority<'A>())
    member this.Assoc (rhs: InterMonoid<'A>) =
      let a1, b1 = this.Value
      let a2, b2 = rhs.Value
      InterMonoid (a1 ++ a2, b1 ++ b2)

/// A size monoid for random access.
type Size (s) =
  new () = Size (0u)
  member _.Value = s
  override _.ToString () = s.ToString ()
  interface IMonoid<Size> with
    member _.Zero = Size (0u)
    member _.Assoc (rhs: Size) = Size (s + rhs.Value)

/// 2-3 tree node.
type Node<'V, 'A when 'V :> IMonoid<'V>> =
  | Node2 of 'V * 'A * 'A
  | Node3 of 'V * 'A * 'A * 'A
with
  override this.ToString () =
    match this with
    | Node2 (m, a, b) -> "N(" + m.ToString () + "|"
                              + a.ToString () + ", "
                              + b.ToString () + ")"
    | Node3 (m, a, b, c) -> "N(" + m.ToString () + "|"
                                 + a.ToString () + ", "
                                 + b.ToString () + ", "
                                 + c.ToString () + ")"

  static member Foldr fn node acc =
    match node with
    | Node2 (_, a, b) -> fn a (fn b acc)
    | Node3 (_, a, b, c) -> fn a (fn b (fn c acc))

  static member Foldl fn acc node =
    match node with
    | Node2 (_, b, a) -> fn (fn acc b) a
    | Node3 (_, c, b, a) -> fn (fn (fn acc c) b) a

  interface IMeasured<'V> with
    member this.Measurement =
      match this with
      | Node2 (v, _, _)
      | Node3 (v, _, _, _) -> v

/// Digit nodes actually store values.
type Digit<'V, 'A when 'V :> IMonoid<'V>
                   and 'A :> IMeasured<'V>> =
  | One of 'A
  | Two of 'A * 'A
  | Three of 'A * 'A * 'A
  | Four of 'A * 'A * 'A * 'A
with
  override this.ToString () =
    match this with
    | One a -> "D(" + a.ToString () + ")"
    | Two (a, b) -> "D(" + a.ToString () + ", " + b.ToString () + ")"
    | Three (a, b, c) -> "D(" + a.ToString () + ", "
                              + b.ToString () + ", "
                              + c.ToString () + ")"
    | Four (a, b, c, d) -> "D(" + a.ToString () + ", "
                                + b.ToString () + ", "
                                + c.ToString () + ", "
                                + d.ToString () + ")"

  interface IMeasured<'V> with
    member this.Measurement: 'V =
      match this with
      | Three (a, b, c) -> calib a ++ calib b ++ calib c
      | Two (a, b) -> calib a ++ calib b
      | Four (a, b, c, d) -> calib a ++ calib b ++ calib c ++ calib d
      | One (a) -> calib a

  static member Foldr fn digit acc =
    match digit with
    | One (a) -> fn a acc
    | Two (a, b) -> fn a (fn b acc)
    | Three (a, b, c) -> fn a (fn b (fn c acc))
    | Four (a, b, c, d) -> fn a (fn b (fn c (fn d acc)))

  static member Foldl fn acc digit =
    match digit with
    | One (a) -> fn acc a
    | Two (b, a) -> fn (fn acc b) a
    | Three (c, b, a) -> fn (fn (fn acc c) b) a
    | Four (d, c, b, a) -> fn (fn (fn ((fn acc d)) c) b) a

/// FingerTree defined in [Hinze 2006]. N.B. non-regular type is used.
type FingerTree<'V, 'A when 'V :> IMonoid<'V>
                        and 'V : (new: unit -> 'V)
                        and 'A :> IMeasured<'V>> =
  | Empty
  | Single of 'A
  | Deep of 'V
          * Digit<'V, 'A>
          * FingerTree<'V, Node<'V, 'A>>
          * Digit<'V, 'A>
with
  override this.ToString () =
    match this with
    | Empty -> "Empty"
    | Single x -> "Single(" + x.ToString () + ")"
    | Deep (m, l, t, r) -> "Deep(" + m.ToString () + "|"
                                   + l.ToString () + ", "
                                   + t.ToString () + ", "
                                   + r.ToString () + ")"

  member _.Monoid: 'V = new 'V ()

  interface IMeasured<'V> with
    member this.Measurement: 'V =
      match this with
      | Empty -> this.Monoid.Zero
      | Single x -> calib x
      | Deep (v, _, _, _) -> v

/// View of a FingerMap.
type View<'A, 'B> =
  | Nil
  | Cons of 'A * rest: 'B

/// Split represents an element in a FingerTree with containers of elements to
/// its left and right.
type Split<'V, 'A> = 'V (* Left *)
                   * 'A
                   * 'V (* Right *)

let inline snocDigit lhs rhs =
  match lhs with
  | One (a) -> Two (a, rhs)
  | Two (a, b) -> Three (a, b, rhs)
  | Three (a, b, c) -> Four (a, b, c, rhs)
  | _ -> raise InvalidDigitException

let inline consDigit lhs rhs =
  match rhs with
  | One (a) -> Two (lhs, a)
  | Two (a, b) -> Three (lhs, a, b)
  | Three (a, b, c) -> Four (lhs, a, b, c)
  | _ -> raise InvalidDigitException

/// Reduce a FingerTree from the right.
let rec foldr<'V, 'A, 'B when 'V :> IMonoid<'V>
                          and 'V : (new: unit -> 'V)
                          and 'A :> IMeasured<'V>
             > (f: 'A -> 'B -> 'B) (t: FingerTree<'V, 'A>) (acc: 'B) : 'B =
  match t with
  | Empty -> acc
  | Single x -> f x acc
  | Deep (_, pr, m, sf) ->
    let acc = Digit<'V, 'A>.Foldr f sf acc
    let acc = foldr (fun node acc -> Node<'V, 'A>.Foldr f node acc) m acc
    Digit<'V, 'A>.Foldr f pr acc

/// Reduce a FingerTree from the left.
let rec foldl<'V, 'A, 'B when 'V :> IMonoid<'V>
                          and 'V : (new: unit -> 'V)
                          and 'A :> IMeasured<'V>
             > (fn: 'B -> 'A -> 'B) (acc: 'B) (t: FingerTree<'V, 'A>) : 'B =
  match t with
  | Empty -> acc
  | Single x -> fn acc x
  | Deep (_, pr, m, sf) ->
    let acc = Digit<'V, 'A>.Foldl fn acc pr
    let acc = foldl (fun acc node -> Node<'V, 'A>.Foldl fn acc node) acc m
    Digit<'V, 'A>.Foldl fn acc sf

/// This is a helper class that defines FingerTree operations. This class
/// contains only static members. We use this class to simplify type annotations
/// for polymorphic recursion.
type Op<'V, 'A when 'V :> IMonoid<'V>
                and 'V : (new: unit -> 'V)
                and 'A :> IMeasured<'V>> () =

  static member private Node2 a b : Node<'V, 'A> =
    Node2 (calib a ++ calib b, a, b)

  static member private Node3 a b c : Node<'V, 'A> =
    Node3 (calib a ++ calib b ++ calib c, a, b, c)

  static member private Deep (pr: Digit<'V, 'A>,
                              m: FingerTree<'V, Node<'V, 'A>>,
                              sf: Digit<'V, 'A>) : FingerTree<'V, 'A> =
    Deep (calib pr ++ calib m ++ calib sf, pr, m, sf)

  /// (infixr): Prepend an element to a FingerTree.
  static member Cons (a: 'A) (tree: FingerTree<'V, 'A>) : FingerTree<'V, 'A> =
    match tree with
    | Empty -> Single a
    | Single b -> Deep (calib a ++ calib b, One a, Empty, One b)
    | Deep (_, Four (b, c, d, e), m, suffix) ->
      Op.Deep (Two (a, b), Op.Cons (Op.Node3 c d e) m, suffix)
    | Deep (v, prefix, m, suffix) ->
      Deep (calib a ++ v, consDigit a prefix, m, suffix)

  /// (infixl): Append an element to a FingerTree.
  static member Snoc (tree: FingerTree<'V, 'A>) (a: 'A) : FingerTree<'V, 'A> =
    match tree with
    | Empty -> Single a
    | Single b -> Deep (calib b ++ calib a, One b, Empty, One a)
    | Deep (_, prefix, m, Four (e, d, c, b)) ->
      Op.Deep (prefix, Op.Snoc m (Op.Node3 e d c), Two (b, a))
    | Deep (v, prefix, m, suffix) ->
      Deep (v ++ calib a, prefix, m, snocDigit suffix a)

  static member private DigitToTree s : FingerTree<'V, 'A> =
    Digit<'V, 'A>.Foldr Op.Cons s Empty

  static member private NodeToDigit (node: Node<'V, 'A>) =
    match node with
    | Node2 (_, a, b) -> Two (a, b)
    | Node3 (_, a, b, c) -> Three (a, b, c)

  static member ViewL (tree: FingerTree<'V, 'A>)
                      : View<'A, FingerTree<'V, 'A>> =
    match tree with
    | Empty -> Nil
    | Single x -> Cons (x, Empty)
    | Deep (_, One a, m, sf) -> Cons (a, Op.DeepL m sf)
    | Deep (_, pr, m, sf) ->
      let hd, tl = match pr with
                    | Two (a, b) -> a, One b
                    | Three (a, b, c) -> a, Two (b, c)
                    | Four (a, b, c, d) -> a, Three (b, c, d)
                    | _ -> raise InvalidDigitException
      Cons (hd, Op.Deep (tl, m, sf))

  static member DeepL (m: FingerTree<'V, Node<'V, 'A>>)
                      (suffix: Digit<'V, 'A>) : FingerTree<'V, 'A> =
    match Op.ViewL m with
    | Nil -> Op.DigitToTree suffix
    | Cons (a, m') -> Op.Deep (Op.NodeToDigit a, m', suffix)

  static member ViewR (tree: FingerTree<'V, 'A>)
                      : View<'A, FingerTree<'V, 'A>> =
    match tree with
    | Empty -> Nil
    | Single x -> Cons (x, Empty)
    | Deep (_, pr, m, One a) -> Cons (a, Op.DeepR m pr)
    | Deep (_, pr, m, sf) ->
      let rest, l = match sf with
                    | Two (a, b) -> One a, b
                    | Three (a, b, c) -> Two (a, b), c
                    | Four (a, b, c, d) -> Three (a, b, c), d
                    | _ -> raise InvalidDigitException
      Cons (l, Op.Deep (pr, m, rest))

  static member DeepR (m: FingerTree<'V, Node<'V, 'A>>) (prefix: Digit<'V, 'A>)
                      : FingerTree<'V, 'A> =
    match Op.ViewR m with
    | Nil -> Op.DigitToTree prefix
    | Cons (a, m') -> Op.Deep (prefix, m', Op.NodeToDigit a)

  static member IsEmpty (tree: FingerTree<'V, 'A>) =
    match tree with
    | Empty -> true
    | _ -> false

  /// Return head of the left subtree.
  static member HeadL (tree: FingerTree<'V, 'A>) =
    match Op.ViewL tree with
    | Nil -> raise EmptyTreeException
    | Cons (a, _) -> a

  /// Return tail of the left subtree.
  static member TailL (tree: FingerTree<'V, 'A>) =
    match Op.ViewL tree with
    | Nil -> raise EmptyTreeException
    | Cons (_, m) -> m

  /// Return head of the right subtree.
  static member HeadR (tree: FingerTree<'V, 'A>) =
    match Op.ViewR tree with
    | Nil -> raise EmptyTreeException
    | Cons (a, _) -> a

  /// Return tail of the right subtree.
  static member TailR (tree: FingerTree<'V, 'A>) =
    match Op.ViewR tree with
    | Nil -> raise EmptyTreeException
    | Cons (_, m) -> m

  static member private AddToLst acc (digit: Digit<'V, 'A>) =
    match digit with
    | One a -> a :: acc
    | Two (a, b) -> a :: b :: acc
    | Three (a, b, c) -> a :: b :: c :: acc
    | Four (a, b, c, d) -> a :: b :: c :: d :: acc

  static member private NodeAcc : 'A list -> Node<'V, 'A> list = function
    | [ a; b ] -> [ Op.Node2 a b ]
    | [ a; b; c ] -> [ Op.Node3 a b c ]
    | [ a; b; c; d ] -> [ Op.Node2 a b; Op.Node2 c d ]
    | a :: b :: c :: xs -> Op.Node3 a b c :: Op.NodeAcc xs
    | _ -> raise InvalidNodeException

  static member private Nodes sf1 ts pr2 : Node<'V, 'A> list =
    Op.AddToLst ts sf1 @ Op.AddToLst [] pr2 |> Op.NodeAcc

  static member private App3 (t1: FingerTree<'V, 'A>)
                             (ts: 'A list)
                             (t2: FingerTree<'V, 'A>) : FingerTree<'V, 'A> =
    match t1, t2 with
    | Empty, xs -> List.foldBack Op.Cons ts xs
    | xs, Empty -> List.fold Op.Snoc xs ts
    | Single x, xs -> Op.Cons x (List.foldBack Op.Cons ts xs)
    | xs, Single x -> Op.Snoc (List.fold Op.Snoc xs ts) x
    | Deep (_, pr1, m1, sf1), Deep (_, pr2, m2, sf2) ->
      Op.Deep (pr1, Op.App3 m1 (Op.Nodes sf1 ts pr2) m2, sf2)

  static member private SplitDigit pred i (digit: Digit<'V, 'A>) =
    match digit with
    | One (a) -> [], a, []
    | Two (a, b) ->
      let i' = i ++ calib a
      if pred i' then [], a, [ b ] else [ a ], b, []
    | Three (a, b, c) ->
      let i' = i ++ calib a
      if pred i' then [], a, [ b; c ]
      else let i'' = i' ++ calib b
           if pred i'' then [ a ], b, [ c ]
           else [ a; b ], c, []
    | Four (a, b, c, d) ->
      let i' = i ++ calib a
      if pred i' then [], a, [ b; c; d ]
      else let i'' = i' ++ calib b
           if pred i'' then [ a ], b, [ c; d ]
           else let i''' = i'' ++ calib c
                if pred i''' then [ a; b ], c, [ d ]
                else [ a; b; c ], d, []

  static member private LstToDigit (lst: 'A list) =
    match lst with
    | [ a ] -> One (a)
    | [ a; b ] -> Two (a, b)
    | [ a; b; c ] -> Three (a, b, c)
    | [ a; b; c; d ] -> Four (a, b, c, d)
    | _ -> raise InvalidDigitException

  static member private ToTree (lst: 'A list) =
    match lst with
    | [] -> Empty
    | [ a ] -> Single a
    | [ a; b ] -> Op.Deep (One a, Empty, One b)
    | [ a; b; c ] -> Op.Deep (Two (a, b), Empty, One c)
    | [ a; b; c; d ] -> Op.Deep (Three (a, b, c), Empty, One d)
    | _ -> raise InvalidDigitException

  static member SplitTree (p: 'V -> bool)
                          (i: 'V)
                          (tree: FingerTree<'V, 'A>)
                          : Split<FingerTree<'V, 'A>, 'A> =
    match tree with
    | Empty -> raise EmptyTreeException
    | Single x -> Empty, x, Empty
    | Deep (_, pr, m, sf) ->
      let vpr = i ++ calib pr
      if p vpr then
        let l, x, r = Op.SplitDigit p i pr
        let r = if r.IsEmpty then Op.DeepL m sf
                else Op.Deep (Op.LstToDigit r, m, sf)
        Op.ToTree l, x, r
      else
        let vm = vpr ++ calib m
        if p vm then
          let ml, xs, mr = Op.SplitTree p vpr m
          let xs = Op.NodeToDigit xs
          let l, x, r = Op.SplitDigit p (vpr ++ calib ml) xs
          let l = if l.IsEmpty then Op.DeepR ml pr
                  else Op.Deep (pr, ml, Op.LstToDigit l)
          let r = if r.IsEmpty then Op.DeepL mr sf
                  else Op.Deep (Op.LstToDigit r, mr, sf)
          l, x, r
        else
          let l, x, r = Op.SplitDigit p vm sf
          let l = if l.IsEmpty then Op.DeepR m pr
                  else Op.Deep (pr, m, Op.LstToDigit l)
          l, x, Op.ToTree r

  /// Split a FingerTree into two based on a predicate (p).
  static member Split (p: 'V -> bool) (tree: FingerTree<'V, 'A>)
                      : FingerTree<'V, 'A> * FingerTree<'V, 'A> =
    match tree with
    | Empty -> (Empty, Empty)
    | xs when p (calib xs) ->
      let l, x, r = Op.SplitTree p tree.Monoid.Zero xs
      (l, Op.Cons x r)
    | xs -> (xs, Empty)

  /// Take a subset of a FingerTree that satisfies the predicate (p).
  static member TakeUntil p (tree: FingerTree<'V, 'A>) =
    Op.Split p tree |> fst

  /// Take a subset of a FingerTree that does not satisfies the predicate (p).
  static member DropUntil p (tree: FingerTree<'V, 'A>) =
    Op.Split p tree |> snd

  /// Concatenate two FingerTrees into one.
  static member Concat (xs: FingerTree<'V, 'A>) (ys: FingerTree<'V, 'A>) =
    Op.App3 xs [] ys

  /// TODO: (faster) lookup functions without building extra trees
  static member Lookup (p: 'V -> bool) i (tree: FingerTree<'V, 'A>) : 'V * 'A =
    let zero = tree.Monoid.Zero
    let l, x, _ = Op.SplitTree p zero tree
    (i ++ calib l, x)

(* Exposed APIs *)

// vim: set tw=80 sts=2 sw=2:
