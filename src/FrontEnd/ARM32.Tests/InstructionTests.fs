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

namespace B2R2.FrontEnd.ARM32.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.ARM32

[<TestClass>]
type InstructionTests() =
  static let parseAt isThumb hex addr =
    let reader = BinReader.Init Endian.Big
    let parser = Parser(ISA "armv7", isThumb, reader) :> IInstructionParsable
    parser.Parse(ByteArray.ofHexString hex, addr)

  static let parse isThumb hex = parseAt isThumb hex 0UL

  (* A function returns by branching to the link register as much as by popping
     the PC, and a BX to any other register is a jump that the CFG has to
     follow, not a return. *)
  [<TestMethod>]
  member _.``[ARMv7] returns test``() =
    let isRET isThumb hex = (parse isThumb hex).IsRET
    Assert.AreEqual<bool>(true, isRET false "e12fff1e") (* bx lr *)
    Assert.AreEqual<bool>(true, isRET true "4770") (* bx lr *)
    Assert.AreEqual<bool>(true, isRET false "e8bd8010") (* pop {r4, pc} *)
    Assert.AreEqual<bool>(true, isRET false "e49df004") (* pop {pc} *)
    Assert.AreEqual<bool>(false, isRET false "e12fff13") (* bx r3 *)

  (* An instruction that computes or loads the PC branches, whichever form it
     takes, and a block has to end with it; reading the PC does not branch, as
     add r1, pc, #4 does. *)
  [<TestMethod>]
  member _.``[ARMv7] writes to the PC are branches test``() =
    let branches =
      [ false, "e081f000" (* add pc, r1, r0 *)
        false, "e1a0f00e" (* mov pc, lr *)
        false, "e8918004" (* ldm r1, {r2, pc} *)
        true, "4487" (* add pc, r0 *)
        true, "46f7" (* mov pc, lr *) ]
    let missed =
      branches
      |> List.filter (fun (isThumb, hex) -> not (parse isThumb hex).IsBranch)
      |> List.map snd
    Assert.AreEqual<string>("", String.concat " " missed)
    Assert.AreEqual<bool>(false, (parse false "e28f1004").IsBranch)

  (* CBZ and CBNZ branch to the label that they name, as B does, besides the
     register that they test, so they branch directly. *)
  [<TestMethod>]
  member _.``[ARMv7] compares and branches on zero directly test``() =
    let kinds hex =
      let ins = parse true hex
      ins.IsDirectBranch, ins.IsIndirectBranch
    Assert.AreEqual<bool * bool>((true, false), kinds "b175") (* cbz r5 *)
    Assert.AreEqual<bool * bool>((true, false), kinds "b97b") (* cbnz r3 *)

  (* GCC puts a UDF where control never arrives, such as a case of a switch
     that cannot happen, and lays data right after it, so nothing after it is
     code to follow, just as nothing is after a UD2 of Intel. *)
  [<TestMethod>]
  member _.``[ARMv7] undefined instructions have no successors test``() =
    let successors isThumb hex = (parse isThumb hex).GetNextInstrAddrs()
    CollectionAssert.AreEqual(Array.empty<Addr>, successors false "e7f000f0")
    CollectionAssert.AreEqual(Array.empty<Addr>, successors true "de00")

  (* A VLDR reads its literal from the PC aligned to a word, just as an LDR
     does, though its operand names the PC as a base rather than a label. *)
  [<TestMethod>]
  member _.``[ARMv7] loads relative to the PC dereference memory test``() =
    let derefs isThumb hex addr =
      match (parseAt isThumb hex addr).MemoryDereferences() with
      | true, addrs -> addrs
      | false, _ -> [||]
    let actual =
      [| derefs false "e59f0010" 0x0UL (* ldr r0, [pc, #16] *)
         derefs false "ed9f0a02" 0x0UL (* vldr s0, [pc, #8] *)
         derefs false "ed1f1b01" 0x0UL (* vldr d1, [pc, #-4] *)
         derefs true "ed9f1a14" 0x2UL (* vldr s2, [pc, #80] *) |]
      |> Array.concat
    CollectionAssert.AreEqual([| 0x18UL; 0x10UL; 0x4UL; 0x54UL |], actual)
