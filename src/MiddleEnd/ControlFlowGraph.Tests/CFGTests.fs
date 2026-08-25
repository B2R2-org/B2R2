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

namespace B2R2.MiddleEnd.ControlFlowGraph.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

[<TestClass>]
type CFGTests() =
  let lowUIRBlock addr =
    let rundown: LowUIR.Stmt[] = [||]
    let abs = FunctionAbstraction(addr, 0, rundown, false, UnknownNoRet)
    LowUIRBasicBlock.CreateAbstract(ProgramPoint(addr, 0), abs)

  let ssaBlock addr stmts =
    SSABasicBlock.CreateRegular(stmts, ProgramPoint(addr, 0), addr)

  let varKind = TempVar(32<rt>, 0)

  let def kind num =
    let v = { Kind = kind; Identifier = 0 }
    ProgramPoint.Fake, Def(v, Num(BitVector(uint64 num, 32<rt>)))

  (* A CFG is created by its own module, whichever the graph behind it is, and
     the kind asked for is the kind that comes back. *)
  [<TestMethod>]
  member _.``CFG Creation Test``() =
    for t in [ Mutable; Persistent ] do
      let ircfg = LowUIRCFG.create t
      Assert.AreEqual<ImplementationType>(t, ircfg.ImplementationType)
      Assert.AreEqual<bool>(true, ircfg.IsEmpty)
      let ssacfg = SSACFG.create t
      Assert.AreEqual<ImplementationType>(t, ssacfg.ImplementationType)
      Assert.AreEqual<bool>(true, ssacfg.IsEmpty)
      let callcfg = CallCFG.create t
      Assert.AreEqual<ImplementationType>(t, callcfg.ImplementationType)
      Assert.AreEqual<bool>(true, callcfg.IsEmpty)

  (* A CFG is the graph interface it names, hence every member of that
     interface is one a caller holding a CFG reaches, not the handful a
     wrapper happened to pass along. *)
  [<TestMethod>]
  member _.``CFG Graph Interface Test``() =
    let g = LowUIRCFG.create Mutable
    let b1, b2 = lowUIRBlock 0x100UL, lowUIRBlock 0x200UL
    let v1 = g.AddVertex b1
    let v2 = g.AddVertex b2
    g.AddEdge(v1, v2, FallThroughEdge)
    Assert.AreEqual<bool>(true, g.HasEdge(v1, v2))
    Assert.AreEqual<bool>(false, g.HasEdge(v2, v1))
    Assert.AreEqual<bool>(true, g.Contains v1)
    Assert.AreEqual<IVertex<_>>(v2, g.FindVertexByData b2)
    let addrIs addr (v: IVertex<LowUIRBasicBlock>) =
      v.VData.Internals.PPoint.Address = addr
    Assert.AreEqual<IVertex<_>>(v2, g.FindVertexBy(addrIs 0x200UL))
    let missing = g.TryFindVertexBy(addrIs 0x300UL)
    Assert.AreEqual<IVertex<_> option>(None, missing)
    let reversed = g.Reverse [ v2 ]
    let succ = reversed.GetSuccs v2 |> Array.exactlyOne
    Assert.AreEqual<IVertex<_>>(v1, succ)
    let g' = LowUIRCFG.create Mutable
    g'.AddVertexCopy v1 |> ignore
    Assert.AreEqual<int>(1, g'.VertexCount)

  (* The reaching definition of a variable is read off the dominator tree
     alone, so the function asking for it takes the vertex it starts from and
     nothing else. *)
  [<TestMethod>]
  member _.``SSA Reaching Definition Test``() =
    let g = SSACFG.create Mutable
    let defStmt = def varKind 42
    let v1 = g.AddVertex(ssaBlock 0x100UL [| defStmt |])
    let v2 = g.AddVertex(ssaBlock 0x200UL [| def (TempVar(32<rt>, 1)) 7 |])
    g.AddEdge(v1, v2, FallThroughEdge)
    v2.VData.ImmDominator <- Some v1
    let reaching = SSACFG.findReachingDef v2 varKind
    Assert.AreEqual<Stmt option>(Some(snd defStmt), reaching)
    Assert.AreEqual<Stmt option>(None, SSACFG.findReachingDef v1 varKind)
