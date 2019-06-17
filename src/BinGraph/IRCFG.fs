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

open B2R2
open B2R2.BinIR

[<AbstractClass>]
type IRVertexData () =
  inherit VertexData (VertexData.genID ())

  abstract member IsBBL: unit -> bool

  abstract member GetPpoint: outref<PPoint> -> bool

  abstract member GetLastPpoint: outref<PPoint> -> bool

  abstract member GetStmts: outref<LowUIR.Stmt list> -> bool

  abstract member GetLastStmt: outref<LowUIR.Stmt> -> bool

  abstract member SetIsIndirectCall: bool -> unit

  abstract member GetIsIndirectCall: outref<bool> -> bool

  abstract member SetIsIndirectJump: bool -> unit

  abstract member GetIsIndirectJump: outref<bool> -> bool

  abstract member GetTarget: outref<Addr> -> bool

  abstract member GetComments: string list with get

  abstract member SetComments: string list -> unit

type IRBBL (ppoint, lastPpoint, stmts, last, comments) =
  inherit IRVertexData ()

  let mutable isIndirectCall = false
  let mutable isIndirectJump = false
  let mutable comments = comments

  /// The last statement of this block (to access it efficiently).
  member __.LastStmt: LowUIR.Stmt = last

  /// Program point of the last statement.
  member __.LastPpoint: PPoint = lastPpoint

  override __.IsBBL () = true

  override __.GetPpoint (pp: outref<PPoint>) =
    pp <- ppoint
    true

  override __.GetLastPpoint (pp: outref<PPoint>) =
    pp <- lastPpoint
    true

  override __.GetStmts (s: outref<LowUIR.Stmt list>) =
    s <- stmts
    true

  override __.GetLastStmt (s: outref<LowUIR.Stmt>) =
    s <- last
    true

  override __.SetIsIndirectCall b = isIndirectCall <- b

  override __.GetIsIndirectCall (b: outref<bool>) =
    b <- isIndirectCall
    true

  override __.SetIsIndirectJump b = isIndirectJump <- b

  override __.GetIsIndirectJump (b: outref<bool>) =
    b <- isIndirectJump
    true

  override __.GetComments =
    comments

  override __.SetComments (_comments: string list) =
    comments <- _comments

  override __.GetTarget (target: outref<Addr>) = false

type IRCall (target) =
  inherit IRVertexData ()

  override __.IsBBL () = false

  override __.GetPpoint (pp: outref<PPoint>) = false

  override __.GetLastPpoint (pp: outref<PPoint>) = false

  override __.GetStmts (s: outref<LowUIR.Stmt list>) = false

  override __.GetLastStmt (s: outref<LowUIR.Stmt>) = false

  override __.SetIsIndirectCall b = ()

  override __.GetIsIndirectCall (b: outref<bool>) = false

  override __.SetIsIndirectJump b = ()

  override __.GetIsIndirectJump (b: outref<bool>) = false

  override __.GetTarget (t: outref<Addr>) =
    t <- target
    true

  override __.GetComments = []

  override __.SetComments (_comments: string list) = ()

type IRVertex = Vertex<IRVertexData>

type IRCFG = SimpleDiGraph<IRVertexData, CFGEdge>
