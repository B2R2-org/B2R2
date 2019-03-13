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

namespace B2R2

open B2R2.FingerTree

/// An element for our interval map.
type IntervalMapElem<'a> (k, v) =
    member val Key: AddrRange = k
    member val Val: 'a = v
    member __.Min = __.Key.Min
    member __.Max = __.Key.Max
    override __.ToString () = __.Key.ToString ()
    interface IMeasured<InterMonoid<Addr>> with
        member __.Measurement =
            InterMonoid<Addr> (Ordered(Key(__.Key.Min)), Priority(Prio(__.Key.Max)))

/// Interval-tree-based map, which maps an interval of type (AddrRange) to an
/// IntervalMapElement ('a).
type IntervalMap<'a> =
    private
        IntervalMap of FingerTree<InterMonoid<Addr>, IntervalMapElem<'a>>

/// Helper module for IntervalMap.
module IntervalMap =

    /// Empty interval tree.
    let empty: IntervalMap<'a> = IntervalMap Empty

    let isEmpty (m: IntervalMap<'a>) = m = IntervalMap Empty

    /// Add an item to the interval tree.
    let add (i: AddrRange) v (IntervalMap m) =
        let l, r =
            Op.Split (fun (e: InterMonoid<Addr>) -> Key i.Min <= e.GetMin ()) m
        IntervalMap <| Op.Concat l (Op.Cons (IntervalMapElem (i, v)) r)

    /// Add an item to the interval tree.
    let addByTuple (il, ih) v m = add (AddrRange (il, ih)) v m

    /// Find all overlapping intervals.
    let findAll (range: AddrRange) (IntervalMap m) =
        let il = range.Min
        let ih = range.Max
        let dropMatcher (e: InterMonoid<Addr>) = Prio il < e.GetMax ()
        let rec matches xs =
            let v = Op.DropUntil dropMatcher xs
            match Op.ViewL v with
            | Nil -> []
            | Cons (x, xs) -> x :: matches xs
        Op.TakeUntil (fun (elt: InterMonoid<Addr>) -> Key ih < elt.GetMin ()) m
        |> matches

    /// Find exactly matching interval.
    let tryFind range (m: IntervalMap<'a>) =
        findAll range m
        |> List.tryFind (fun (elt: IntervalMapElem<'a>) -> elt.Key = range)
        |> Option.map (fun v -> v.Val)

    /// Find an interval that has the same low bound (Min) as the given address.
    let tryFindByMin (addr: Addr) (IntervalMap m) =
        let comp (elt: InterMonoid<Addr>) = Key addr <= elt.GetMin ()
        if Prio addr < ((m :> IMeasured<_>).Measurement).GetMax () then
            let z = (m.Monoid :> IMonoid<InterMonoid<Addr>>).Zero
            let _, x, _ = Op.SplitTree comp z m
            if x.Min = addr then Some (x.Val) else None
        else None

    /// Check whether the given address interval is included in any of the
    /// intervals in the interval map.
    let includeRange (range: AddrRange) (IntervalMap m) =
        let il = range.Min
        let ih = range.Max
        if Prio il < ((m :> IMeasured<_>).Measurement).GetMax () then
            let z = (m.Monoid :> IMonoid<InterMonoid<Addr>>).Zero
            let _, x, _ =
                Op.SplitTree (fun (e: InterMonoid<Addr>) -> Prio il < e.GetMax()) z m
            x.Min < ih
        else false

    /// Check whether the given address exists in the interval tree.
    let containsAddr addr m = includeRange (AddrRange (addr, addr)) m

    /// Check whether the exact range exists in the interval tree.
    let contains (range: AddrRange) (m: IntervalMap<'a>) =
        match tryFind range m with
        | None -> false
        | _ -> true

    /// Replace the exactly matched interval from the map to the given one.
    let replace (i: AddrRange) (v: 'a) (IntervalMap m) =
        let l, r =
            Op.Split (fun (e: InterMonoid<Addr>) -> Key i.Min <= e.GetMin ()) m
        let rec replaceLoop l r =
            match Op.ViewL r with
            | Nil -> raise InvalidAddrRangeException
            | Cons (x: IntervalMapElem<'a>, xs)
                when x.Min = i.Min && x.Max = i.Max ->
                Op.Concat l (Op.Cons (IntervalMapElem (i, v)) xs)
            | Cons (x, xs) ->
                if i.Min = x.Min then replaceLoop (Op.Snoc l x) xs
                else raise InvalidAddrRangeException
        IntervalMap <| replaceLoop l r

    /// Remove the exactly matched interval from the map.
    let remove (i: AddrRange) (IntervalMap m) =
        let l, r =
            Op.Split (fun (e: InterMonoid<Addr>) -> Key i.Min <= e.GetMin ()) m
        let rec rmLoop l r =
            match Op.ViewL r with
            | Nil -> raise InvalidAddrRangeException
            | Cons (x: IntervalMapElem<'a>, xs)
                when x.Min = i.Min && x.Max = i.Max ->
                Op.Concat l xs
            | Cons (x, xs) ->
                if i.Min = x.Min then rmLoop (Op.Snoc l x) xs
                else raise InvalidAddrRangeException
        IntervalMap <| rmLoop l r

    /// Fold the map.
    let fold fn acc (IntervalMap m) =
        foldl (fun acc (elt: IntervalMapElem<'a>) -> fn acc elt.Key elt.Val) acc m

// vim: set tw=80 sts=2 sw=2:
