(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*)

namespace B2R2.FrontEnd.BinLifter.Tests

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.S390
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type InstructionTests() =
  static let parser =
    let isa = ISA(Architecture.S390, endian = Endian.Big)
    S390Parser(isa, BinReader.Init Endian.Big) :> IInstructionParsable

  static let parse hex =
    let head = ByteArray.ofHexString hex
    let bytes = Array.append head (Array.zeroCreate 8)
    parser.Parse(ReadOnlySpan bytes, 0x1000UL)

  (* IsTerminator reads IsInterrupt and IsExit, both of which used to be
     unimplemented, so asking whether any S390 instruction ended a block raised
     NotImplementedException and took every block-level API with it. *)
  [<TestMethod>]
  member _.``[S390] Supervisor Call Is An Interrupt Test``() =
    let svc = parse "0a00"
    Assert.AreEqual<bool>(true, svc.IsInterrupt)
    Assert.AreEqual<bool>(true, svc.IsTerminator null)

  [<TestMethod>]
  member _.``[S390] Monitor Call Is An Interrupt Test``() =
    Assert.AreEqual<bool>(true, (parse "af001000").IsInterrupt)

  (* Program Return leaves the service routine a Program Call entered, and
     Load PSW replaces the whole program status word, which is how S390 returns
     from an interruption. Both end execution of the current stream. *)
  [<TestMethod>]
  member _.``[S390] Program Return Is An Exit Test``() =
    let pr = parse "0101"
    Assert.AreEqual<bool>(true, pr.IsExit)
    Assert.AreEqual<bool>(true, pr.IsTerminator null)

  [<TestMethod>]
  member _.``[S390] Load PSW Is An Exit Test``() =
    Assert.AreEqual<bool>(true, (parse "82001000").IsExit)

  [<TestMethod>]
  member _.``[S390] A Plain Load Ends Nothing Test``() =
    let lr = parse "1812"
    Assert.AreEqual<bool>(false, lr.IsInterrupt)
    Assert.AreEqual<bool>(false, lr.IsExit)
    Assert.AreEqual<bool>(false, lr.IsTerminator null)

  (* A branch already ended a block, which must stay true now that the two
     other tests of IsTerminator answer instead of raising. *)
  [<TestMethod>]
  member _.``[S390] A Branch Ends A Block Test``() =
    Assert.AreEqual<bool>(true, (parse "07fe").IsTerminator null)

  (* Bytes with no opcode used to parse into an InvalOp instruction, so every
     address looked like code to a linear sweep and TryParseInstruction never
     reported a failure on this architecture. *)
  [<TestMethod>]
  member _.``[S390] Undecodable Bytes Do Not Parse Test``() =
    for hex in [| "ffff"; "ffffffff"; "ffffffffffff" |] do
      Assert.ThrowsExactly<ParsingFailureException>(fun () ->
        parse hex |> ignore) |> ignore
