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

namespace B2R2.MiddleEnd.BinGraph

type RangedDiGraph<'D, 'E
    when 'D :> RangedVertexData and 'D : equality> (core) =
  inherit DiGraph<'D, 'E> (core: GraphCore<'D, 'E, DiGraph<'D, 'E>>)

  member _.FindVertexByRange range =
    core.FindVertexBy (fun (v: Vertex<'D>) -> v.VData.AddrRange = range)

[<RequireQualifiedAccess>]
module RangedDiGraph =
  let private initializer core = RangedDiGraph<'D, 'E> (core) :> DiGraph<'D, 'E>

  let private initImperative edgeData =
    let core = ImperativeRangedCore<'D, 'E> (initializer, edgeData)
    RangedDiGraph<'D, 'E> (core) :> DiGraph<'D, 'E>

  let private initPersistent edgeData =
    let core = PersistentRangedCore<'D, 'E> (initializer, edgeData)
    RangedDiGraph<'D, 'E> (core) :> DiGraph<'D, 'E>

  /// Initialize RangedDiGraph based on the implementation type.
  let init edgeData = function
    | ImperativeGraph -> initImperative edgeData
    | PersistentGraph -> initPersistent edgeData
