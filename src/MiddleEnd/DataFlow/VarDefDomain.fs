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

namespace B2R2.MiddleEnd.DataFlow

/// A domain for tracking variable definitions.
[<RequireQualifiedAccess>]
module VarDefDomain =
  type Lattice = Map<VarKind, Set<VarPoint>>

  let empty = Map.empty

  let get varKind rd =
    match Map.tryFind varKind rd with
    | None -> Set.empty
    | Some pps -> pps

  let load addr rd = get (Memory addr) rd

  let store addr pp rd =
    let pps = load addr rd
    let pps = Set.add pp pps
    Map.add (Memory addr) pps rd

  let join rd1 rd2 =
    Map.keys rd2
    |> Seq.fold (fun acc k ->
      let pps1 = get k rd1
      let pps2 = get k rd2
      let pps = Set.union pps1 pps2
      Map.add k pps acc) rd1
