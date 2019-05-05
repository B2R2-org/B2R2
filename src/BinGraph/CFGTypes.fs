(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Soomin Kim <soomink@kaist.ac.kr>

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
open B2R2.FrontEnd
open B2R2.BinIR
open System.Collections.Generic

type PPoint = Addr * int

type DisasmBBL (range: AddrRange, instrs, last) =
  inherit RangedVertexData (range)

  /// List of all the instructions in this block.
  member __.Instrs: Instruction list = instrs

  /// The last instruction of this block (to access it efficiently).
  member __.LastInstr: Instruction = last

  /// Do we need to resolve the successor(s) of this basic block?
  member val ToResolve = false with get, set

[<AbstractClass>]
type IRVertexData () =
  inherit VertexData (VertexData.genID ())

  abstract member IsBBL: unit -> bool

  abstract member GetPpoint: outref<PPoint> -> bool

  abstract member GetStmts: outref<LowUIR.Stmt list> -> bool

  abstract member GetLastStmt: outref<LowUIR.Stmt> -> bool

  abstract member SetToResolve: bool -> unit

  abstract member GetToResolve: outref<bool> -> bool

  abstract member GetTarget: outref<Addr> -> bool

type IRBBL (ppoint, lastPpoint, stmts, last) =
  inherit IRVertexData ()

  let mutable toResolve = false

  /// The last statement of this block (to access it efficiently).
  member __.LastStmt: LowUIR.Stmt = last

  /// Program point of the last statement.
  member __.LastPpoint: PPoint = lastPpoint

  override __.IsBBL () = true

  override __.GetPpoint (pp: outref<PPoint>) =
    pp <- ppoint
    true

  override __.GetStmts (s: outref<LowUIR.Stmt list>) =
    s <- stmts
    true

  override __.GetLastStmt (s: outref<LowUIR.Stmt>) =
    s <- last
    true

  override __.SetToResolve b = toResolve <- b

  override __.GetToResolve (b: outref<bool>) =
    b <- toResolve
    true

  override __.GetTarget (target: outref<Addr>) = false

type IRCall (target) =
  inherit IRVertexData ()

  override __.IsBBL () = false

  override __.GetPpoint (pp: outref<PPoint>) = false

  override __.GetStmts (s: outref<LowUIR.Stmt list>) = false

  override __.GetLastStmt (s: outref<LowUIR.Stmt>) = false

  override __.SetToResolve b = ()

  override __.GetToResolve (b: outref<bool>) = false

  override __.GetTarget (t: outref<Addr>) =
    t <- target
    true

[<AbstractClass>]
type SSAVertexData (irVertexData) =
  inherit VertexData (VertexData.genID ())

  member __.IRVertexData : IRVertexData = irVertexData

  abstract member IsBBL : unit -> bool

  abstract GetStmts : unit -> SSA.Stmt list

type SSABBL (irVertexData, stmts, last) =
  inherit SSAVertexData (irVertexData)

  member __.LastStmt: SSA.Stmt = last

  member val ToResolve = false with get, set

  override __.IsBBL () = true

  override __.GetStmts () = stmts

type SSACall (irVertexData, stmts) =
  inherit SSAVertexData (irVertexData)

  override __.IsBBL () = false

  override __.GetStmts () = stmts

type CFGEdge =
  | JmpEdge
  | CJmpTrueEdge
  | CJmpFalseEdge
  | CallEdge
  | RetEdge
  | FallThroughEdge

type CFG<'a when 'a :> VertexData> = DiGraph<'a, CFGEdge>

type DisasmVertex = Vertex<DisasmBBL>

type DisasmCFG = RangedDiGraph<DisasmBBL, CFGEdge>

type IRVertex = Vertex<IRVertexData>

type IRCFG = SimpleDiGraph<IRVertexData, CFGEdge>

type SSAVertex = Vertex<SSAVertexData>

type SSACFG = SimpleDiGraph<SSAVertexData, CFGEdge>
