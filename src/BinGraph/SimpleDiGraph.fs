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

namespace B2R2.BinGraph

type SimpleDiGraph<'D, 'E when 'D :> VertexData and 'D : equality> (core) =
  inherit DiGraph<'D, 'E> (core: GraphCore<'D, 'E, DiGraph<'D, 'E>>)

module SimpleDiGraph =
  let initImperative<'D, 'E when 'D :> VertexData and 'D : equality> edgeData =
    let initializer core =
      SimpleDiGraph<'D, 'E> (core) :> DiGraph<'D, 'E>
    let core = ImperativeCore<'D, 'E> (initializer, edgeData)
    SimpleDiGraph<'D, 'E> (core) :> DiGraph<'D, 'E>

  let initPersistent<'D, 'E when 'D :> VertexData and 'D : equality> edgeData =
    let initializer core =
      SimpleDiGraph<'D, 'E> (core) :> DiGraph<'D, 'E>
    let core = PersistentCore<'D, 'E> (initializer, edgeData)
    SimpleDiGraph<'D, 'E> (core) :> DiGraph<'D, 'E>
