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

open System.Collections.Generic
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.ControlFlowGraph

[<TestClass>]
type BasicBlockTests() =
  (* A basic block is the object it is, as the vertex holding it is, and every
     path that asks whether two of them are the same has to answer alike. A
     type defining one of those paths and leaving the rest alone is what
     breaks that, and a hash container is where it shows: it picks a bucket by
     a hash that the equality it then applies knows nothing of, so a set can
     come to hold two blocks it calls equal. *)
  let assertComparedByIdentity (a: 'T) (b: 'T) =
    Assert.AreEqual<bool>(true, (a = a))
    Assert.AreEqual<bool>(false, (a = b))
    Assert.AreEqual<bool>(false, (box a).Equals(box b))
    Assert.AreEqual<bool>(false, EqualityComparer<'T>.Default.Equals(a, b))
    let held = HashSet<'T>([ a; b ])
    Assert.AreEqual<int>(2, held.Count)
    Assert.AreEqual<bool>(true, held.Contains a)

  let lowUIRBlock addr =
    let rundown: LowUIR.Stmt[] = [||]
    let abs = FunctionSummary(addr, 0, rundown, false, UnknownNoRet)
    LowUIRBasicBlock.CreateAbstract(ProgramPoint(addr, 0), abs)

  let ssaBlock addr =
    let rundown: SSA.Stmt[] = [||]
    let abs = FunctionSummary(addr, 0, rundown, false, UnknownNoRet)
    SSABasicBlock.CreateAbstract(ProgramPoint(addr, 0), abs)

  let disasmBlock addr = DisasmBasicBlock(null, ProgramPoint(addr, 0), [||])

  let callBlock addr = CallBasicBlock(WordSize.Bit64, addr, "f", false)

  [<TestMethod>]
  member _.``LowUIR Basic Block Identity Test``() =
    assertComparedByIdentity (lowUIRBlock 0x100UL) (lowUIRBlock 0x100UL)

  [<TestMethod>]
  member _.``SSA Basic Block Identity Test``() =
    assertComparedByIdentity (ssaBlock 0x100UL) (ssaBlock 0x100UL)

  [<TestMethod>]
  member _.``Disasm Basic Block Identity Test``() =
    assertComparedByIdentity (disasmBlock 0x100UL) (disasmBlock 0x100UL)

  [<TestMethod>]
  member _.``Call Basic Block Identity Test``() =
    assertComparedByIdentity (callBlock 0x100UL) (callBlock 0x100UL)

  (* A call graph reads the addresses of one binary against one another, so
     the width every one of them takes is the width of that binary's word,
     whatever the address happens to fit in. *)
  [<TestMethod>]
  member _.``Call Basic Block Address Width Test``() =
    let words = (callBlock 0x555555554000UL).Internals.Visualize()
    Assert.AreEqual<int>(1, words.Length)
    let addrWord = words[0][0]
    Assert.AreEqual<AsmWordKind>(AsmWordKind.Address, addrWord.AsmWordKind)
    Assert.AreEqual<string>("0000555555554000", addrWord.AsmWordValue)
