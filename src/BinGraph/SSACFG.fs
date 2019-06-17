(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Soomin Kim <soomink@kaist.ac.kr>
          Sang Kil Cha <sangkilc@kaist.ac.kr>

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

open B2R2.BinIR

[<AbstractClass>]
type SSAVertexData (irVertexData) =
  inherit VertexData (VertexData.genID ())

  member __.IRVertexData : IRVertexData = irVertexData

  abstract member IsBBL : unit -> bool

  abstract GetStmts : unit -> SSA.Stmt list

type SSABBL (irVertexData, stmts, last) =
  inherit SSAVertexData (irVertexData)

  member __.LastStmt: SSA.Stmt = last

  member val IsIndirectCall = false with get, set

  member val IsIndirectJump = false with get, set

  override __.IsBBL () = true

  override __.GetStmts () = stmts

type SSACall (irVertexData, stmts) =
  inherit SSAVertexData (irVertexData)

  override __.IsBBL () = false

  override __.GetStmts () = stmts

type SSAVertex = Vertex<SSAVertexData>

type SSACFG = SimpleDiGraph<SSAVertexData, CFGEdge>
