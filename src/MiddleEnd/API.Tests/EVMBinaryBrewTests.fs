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

namespace B2R2.MiddleEnd.Tests

open System
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

[<TestClass>]
type EVMBinaryBrewTests() =
  /// A contract whose dispatcher calls the public function at 0x13, which
  /// passes one argument to the internal function at 0x1d. The internal
  /// function returns to 0x1b, whose address lies one slot below the top of
  /// the stack.
  static let contract =
    [ "60003560e01c" (* 0x00: selector *)
      "63aabbccdd14601357" (* 0x06: jump to 0x13 if it matches *)
      "600080fd" (* 0x0f: revert *)
      "5b601b602a601d56" (* 0x13: call 0x1d with 0x2a *)
      "5b00" (* 0x1b: return site *)
      "5b505600" ] (* 0x1d: drop the argument and return *)
    |> String.concat ""
    |> Convert.FromHexString

  static let brew =
    lazy
      let hdl = BinHandle.LoadRawImage(contract, ISA "evm")
      EVMBinaryBrew(hdl, EVMCFGRecovery())

  [<TestMethod>]
  member _.``EVMBinaryBrew recovers public and internal functions``() =
    let fns =
      brew.Value.Functions.Sequence
      |> Seq.sortBy (fun fn -> fn.EntryPoint)
      |> Seq.map (fun fn -> fn.EntryPoint, fn.NoRet)
      |> Seq.toList
    let expected = [ 0x0UL, NoRet; 0x13UL, NoRet; 0x1dUL, NotNoRet ]
    Assert.AreEqual<(Addr * NonReturningStatus) list>(expected, fns)

  [<TestMethod>]
  member _.``EVMBinaryBrew returns from a callee to its return site``() =
    let blocks =
      brew.Value.Functions[0x13UL].CFG.Vertices
      |> Array.filter (fun v -> not v.VData.Internals.IsAbstract)
      |> Array.map (fun v -> v.VData.Internals.PPoint.Address)
      |> Array.sort
      |> Array.toList
    Assert.AreEqual<Addr list>([ 0x13UL; 0x1bUL ], blocks)
