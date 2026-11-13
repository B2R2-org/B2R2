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

namespace B2R2.RearEnd.BinExplore.GUI

open System.Collections.Generic
open Avalonia

/// An immutable bounding-volume tree over graph coordinates.
type CFGSpatialIndex =
  private
    | Empty
    | Leaf of Rect * (int * Rect)[]
    | Branch of Rect * CFGSpatialIndex * CFGSpatialIndex

[<RequireQualifiedAccess>]
module CFGSpatialIndex =
  let rec private build (items: (int * Rect)[]) =
    if items.Length = 0 then
      Empty
    else
      let bounds = items |> Array.map snd |> Array.reduce (fun a b -> a.Union b)
      if items.Length <= 8 then
        Leaf(bounds, items)
      else
        let ordered =
          items |> Array.sortBy (fun (_, r) ->
            if bounds.Width >= bounds.Height then r.Center.X else r.Center.Y)
        let middle = ordered.Length / 2
        Branch(bounds, build ordered[..middle - 1], build ordered[middle..])

  let create items = build (Array.ofSeq items)

  let rec private collect area (found: HashSet<int>) = function
    | Empty ->
      ()
    | Leaf(bounds, items) when bounds.Intersects area ->
      for id, bounds in items do
        if bounds.Intersects area then found.Add id |> ignore else ()
    | Branch(bounds, left, right) when bounds.Intersects area ->
      collect area found left
      collect area found right
    | _ ->
      ()

  /// Returns unique IDs in drawing order, including zero-width segments.
  let query area index =
    let found = HashSet<int>()
    collect area found index
    found |> Seq.sort |> Seq.toArray
