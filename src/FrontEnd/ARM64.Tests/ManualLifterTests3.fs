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

namespace B2R2.FrontEnd.ARM64.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR.LowUIR

/// <summary>
/// One test for each instruction DDI0487F.c describes, LDUMINALB to STLURB in
/// the order of its sections. A value test runs the statements each word of
/// the instruction lifts to over the four register files A64Machine
/// describes, and checks the whole file and memory window they leave against
/// what QEMU's -cpu max computed over the same files: the places listed are
/// the ones that changed, and every other place must keep its input. A
/// structural test, for an instruction the oracle cannot run or whose value no
/// second implementation fixes, checks what the manual fixes about the
/// lifting, and says in its own comment what and why.
/// </summary>
[<TestClass>]
type ManualLifterTests3() =
  /// Checks a word over each input set against the places given as the
  /// ones it changes: what the oracle found for a value test, what the
  /// manual says for a structural one.
  let check hex inputs expected =
    let found = A64Machine.mismatches hex inputs expected
    Assert.AreEqual<string>("", String.concat "\n" found, hex)

  /// Checks that a word raises the given exception over every input set,
  /// as the oracle's process took the signal for it.
  let raises effect hex =
    for k in 0 .. A64Machine.sets - 1 do
      let found = A64Machine.effectsOver hex [] k
      Assert.AreEqual<BinIR.SideEffect list>([ effect ], found, hex)

  /// How a word's statements leave the instruction: the kind of a jump out
  /// of it, or a conditional one.
  let exitOf hex =
    A64Machine.lift hex
    |> Array.tryPick (function
      | InterJmp(Kind = k) -> Some(string k)
      | InterCJmp _ -> Some "InterCJmp"
      | _ -> None)

  /// The pointer the authentication tests sign: canonical and in the lower
  /// half, its field above bit 47 a copy of bit 55.
  let pointer = 0x0000123456789abcUL

  /// Checks what AddPAC and Auth() fix about a signer over each input set:
  /// it keeps bit 55 and the address below bit 48 and changes the pointer;
  /// the matching AUT gives it back; and the other key's AUT fails, leaving
  /// that key's error code in bits 62:61.
  let signs pac aut wrong reg (code: uint64) =
    for k in 0 .. A64Machine.sets - 1 do
      let after hexes = (A64Machine.after hexes [ X(reg, pointer) ] k).Xs
      let signed = (after [ pac ])[reg]
      Assert.AreEqual<uint64>(pointer, signed &&& 0x0080ffffffffffffUL, pac)
      Assert.AreNotEqual<uint64>(pointer, signed, pac)
      Assert.AreEqual<uint64>(pointer, (after [ pac; aut ])[reg], aut)
      let failed = (after [ pac; wrong ])[reg]
      Assert.AreEqual<uint64>(pointer ||| code, failed, wrong)

  /// Checks an authenticated branch over each input set: with its target
  /// signed by the given word it goes to the pointer, unsigned to the
  /// pointer with the key's error code in bits 62:61, and where it links,
  /// X30 is the address after it.
  let branchesSigned pac hex reg (code: uint64) links =
    for k in 0 .. A64Machine.sets - 1 do
      let inputs = [ X(reg, pointer) ]
      let signed = A64Machine.after [ pac; hex ] inputs k
      let unsigned = A64Machine.after [ hex ] inputs k
      Assert.AreEqual<uint64>(pointer, signed.Pc, hex)
      Assert.AreEqual<uint64>(pointer ||| code, unsigned.Pc, hex)
      if links then
        Assert.AreEqual<uint64>(A64Machine.code + 4UL, signed.Xs[30], hex)
      else
        ()

  /// C6.2.164 LDUMINB, LDUMINAB, LDUMINALB, LDUMINLB
  [<TestMethod>]
  member _.``C6.2.164 LDUMINALB``() =
    check "38e27020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4a5eUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe12fUL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.164 LDUMINB, LDUMINAB, LDUMINALB, LDUMINLB
  [<TestMethod>]
  member _.``C6.2.164 LDUMINB``() =
    check "38227020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4a5eUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe12fUL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.164 LDUMINB, LDUMINAB, LDUMINALB, LDUMINLB
  [<TestMethod>]
  member _.``C6.2.164 LDUMINLB``() =
    check "38627020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4a5eUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe12fUL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.165 LDUMINH, LDUMINAH, LDUMINALH, LDUMINLH
  [<TestMethod>]
  member _.``C6.2.165 LDUMINAH``() =
    check "78a27020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f532fUL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.165 LDUMINH, LDUMINAH, LDUMINALH, LDUMINLH
  [<TestMethod>]
  member _.``C6.2.165 LDUMINALH``() =
    check "78e27020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f532fUL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.165 LDUMINH, LDUMINAH, LDUMINALH, LDUMINLH
  [<TestMethod>]
  member _.``C6.2.165 LDUMINH``() =
    check "78227020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f532fUL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.165 LDUMINH, LDUMINAH, LDUMINALH, LDUMINLH
  [<TestMethod>]
  member _.``C6.2.165 LDUMINLH``() =
    check "78627020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f532fUL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.166 LDUMIN, LDUMINA, LDUMINAL, LDUMINL
  [<TestMethod>]
  member _.``C6.2.166 LDUMIN``() =
    check "f8227020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "b8227020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.166 LDUMIN, LDUMINA, LDUMINAL, LDUMINL
  [<TestMethod>]
  member _.``C6.2.166 LDUMINA``() =
    check "b8a27020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.166 LDUMIN, LDUMINA, LDUMINAL, LDUMINL
  [<TestMethod>]
  member _.``C6.2.166 LDUMINAL``() =
    check "b8e27020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.166 LDUMIN, LDUMINA, LDUMINAL, LDUMINL
  [<TestMethod>]
  member _.``C6.2.166 LDUMINL``() =
    check "b8627020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.167 LDUR
  [<TestMethod>]
  member _.``C6.2.167 LDUR``() =
    check "b8410020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "f8400020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "f8410020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "b8400020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.168 LDURB
  [<TestMethod>]
  member _.``C6.2.168 LDURB``() =
    check "38410020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38400020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.169 LDURH
  [<TestMethod>]
  member _.``C6.2.169 LDURH``() =
    check "78410020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "78400020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.170 LDURSB
  [<TestMethod>]
  member _.``C6.2.170 LDURSB``() =
    check "38c10020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xffffff81UL) ]
        [ X(0, 0xffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38800020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffffffffffff81UL) ]
        [ X(0, 0xffffffffffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38810020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xffffffffffffff81UL) ]
        [ X(0, 0xffffffffffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38c00020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffff81UL) ]
        [ X(0, 0xffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.171 LDURSH
  [<TestMethod>]
  member _.``C6.2.171 LDURSH``() =
    check "78c10020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "78800020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffffffffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "78810020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffffffffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "78c00020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.172 LDURSW
  [<TestMethod>]
  member _.``C6.2.172 LDURSW``() =
    check "b8810020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xffffffffc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "b8800020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffffffc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.173 LDXP
  [<TestMethod>]
  member _.``C6.2.173 LDXP``() =
    check "887f0022" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290aUL); X(2, 0xc13e4a81UL) ]
        [ X(0, 0x912f822bUL); X(2, 0x1e8fe1e4UL) ]
        [ X(2, 0x0UL) ]
        [ X(0, 0x55555555UL); X(2, 0x55555555UL) ] ]

  /// C6.2.174 LDXR
  [<TestMethod>]
  member _.``C6.2.174 LDXR``() =
    check "885f7c20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.175 LDXRB
  [<TestMethod>]
  member _.``C6.2.175 LDXRB``() =
    check "085f7c20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.176 LDXRH
  [<TestMethod>]
  member _.``C6.2.176 LDXRH``() =
    check "485f7c20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.177 LSL (register)
  [<TestMethod>]
  member _.``C6.2.177 LSL``() =
    check "1ac22020" []
      [ [ X(0, 0xc0000000UL) ]
        [ X(0, 0xf210000UL) ]
        [ X(0, 0x80000000UL) ]
        [ X(0, 0x0UL) ] ]
    check "531f7820" []
      [ [ X(0, 0xcb1dd8ceUL) ]
        [ X(0, 0x17f83c84UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0x0UL) ] ]
    check "d37ff820" []
      [ [ X(0, 0x7dd71b42cb1dd8ceUL) ]
        [ X(0, 0x7f908c2017f83c84UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0x200000000UL) ] ]
    check "9ac22020" []
      [ [ X(0, 0x5963bb19c0000000UL) ]
        [ X(0, 0xf21000000000000UL) ]
        [ X(0, 0x8000000000000000UL) ]
        [ X(0, 0x20000000000000UL) ] ]
    check "d3430820" []
      [ [ X(0, 0xe000000000000000UL) ]
        [ X(0, 0x4000000000000000UL) ]
        [ X(0, 0x2000000000000000UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.179 LSLV
  [<TestMethod>]
  member _.``C6.2.179 LSLV``() =
    check "1ac22020" []
      [ [ X(0, 0xc0000000UL) ]
        [ X(0, 0xf210000UL) ]
        [ X(0, 0x80000000UL) ]
        [ X(0, 0x0UL) ] ]
    check "9ac22020" []
      [ [ X(0, 0x5963bb19c0000000UL) ]
        [ X(0, 0xf21000000000000UL) ]
        [ X(0, 0x8000000000000000UL) ]
        [ X(0, 0x20000000000000UL) ] ]

  /// C6.2.180 LSR (register)
  [<TestMethod>]
  member _.``C6.2.180 LSR``() =
    check "1ac22420" []
      [ [ X(0, 0x1UL) ]
        [ X(0, 0x17f8UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "53017c20" []
      [ [ X(0, 0x32c77633UL) ]
        [ X(0, 0x5fe0f21UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "d341fc20" []
      [ [ X(0, 0x5f75c6d0b2c77633UL) ]
        [ X(0, 0x5fe4230805fe0f21UL) ]
        []
        [ X(0, 0x80000000UL) ] ]
    check "9ac22420" []
      [ [ X(0, 0x2fbae3685UL) ]
        [ X(0, 0x17f90UL) ]
        []
        [ X(0, 0x800UL) ] ]

  /// C6.2.182 LSRV
  [<TestMethod>]
  member _.``C6.2.182 LSRV``() =
    check "1ac22420" []
      [ [ X(0, 0x1UL) ]
        [ X(0, 0x17f8UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "9ac22420" []
      [ [ X(0, 0x2fbae3685UL) ]
        [ X(0, 0x17f90UL) ]
        []
        [ X(0, 0x800UL) ] ]

  /// C6.2.183 MADD
  [<TestMethod>]
  member _.``C6.2.183 MADD``() =
    check "1b020c20" []
      [ [ X(0, 0xd659c9ddUL) ]
        [ X(0, 0xcf7cea82UL) ]
        [ X(0, 0xffffffffUL) ]
        [ X(0, 0xaaaaaaaaUL) ] ]
    check "9b020c20" []
      [ [ X(0, 0xdfd0c01d659c9ddUL) ]
        [ X(0, 0xfb62ac3cf7cea82UL) ]
        [ X(0, 0x7fffffffffffffffUL) ]
        [ X(0, 0xffffffffaaaaaaaaUL) ] ]

  /// C6.2.184 MNEG
  [<TestMethod>]
  member _.``C6.2.184 MNEG``() =
    check "1b02fc20" []
      [ [ X(0, 0x17e8ff2eUL) ]
        [ X(0, 0x306b0be2UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "9b02fc20" []
      [ [ X(0, 0x63c47a8f17e8ff2eUL) ]
        [ X(0, 0xb43c57b7306b0be2UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaab00000000UL) ] ]

  /// C6.2.185 MOV (to/from SP)
  [<TestMethod>]
  member _.``C6.2.185 MOV``() =
    check "2a0103e0" []
      [ [ X(0, 0x658eec67UL) ]
        [ X(0, 0xbfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "52800200" []
      [ [ X(0, 0x10UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x10UL) ] ]
    check "d2800200" []
      [ [ X(0, 0x10UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x10UL) ] ]
    check "2a0203e0" []
      [ [ X(0, 0xfb32555eUL) ]
        [ X(0, 0xdd7e532fUL) ]
        [ X(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]
    check "aa0203e0" []
      [ [ X(0, 0xf893a2eefb32555eUL) ]
        [ X(0, 0x987bbcbfdd7e532fUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x5555555555555555UL) ] ]
    check "12800200" []
      [ [ X(0, 0xffffffefUL) ]
        [ X(0, 0xffffffefUL) ]
        [ X(0, 0xffffffefUL) ]
        [ X(0, 0xffffffefUL) ] ]
    check "92800200" []
      [ [ X(0, 0xffffffffffffffefUL) ]
        [ X(0, 0xffffffffffffffefUL) ]
        [ X(0, 0xffffffffffffffefUL) ]
        [ X(0, 0xffffffffffffffefUL) ] ]
    check "0ea11c20" []
      [ [ V(0, 0x70616f2f48dce01cUL, 0x0UL) ]
        [ V(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ V(0, 0x7f80000080000000UL, 0x0UL) ]
        [ V(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4ea11c20" []
      [ [ V(0, 0x70616f2f48dce01cUL, 0x40d6824e2ef3fc17UL) ]
        [ V(0, 0x57c883255f0f9e24UL, 0xe2311b535f1fb0a9UL) ]
        [ V(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ V(0, 0x4008000000000000UL, 0x3fb999999999999aUL) ] ]
    check "0e0c3c20" []
      [ [ X(0, 0x70616f2fUL) ]
        [ X(0, 0x57c88325UL) ]
        [ X(0, 0x7f800000UL) ]
        [ X(0, 0x40080000UL) ] ]
    check "4e183c20" []
      [ [ X(0, 0x40d6824e2ef3fc17UL) ]
        [ X(0, 0xe2311b535f1fb0a9UL) ]
        [ X(0, 0x7fa000007fc00000UL) ]
        [ X(0, 0x3fb999999999999aUL) ] ]
    check "4e081c20" []
      [ [ V(0, 0xbeeb8da1658eec67UL, 0x65ace2685a072c6dUL) ]
        [ V(0, 0xbfc846100bfc1e42UL, 0x444bcaba22bb690fUL) ]
        [ V(0, 0x1UL, 0x3dcccccd40400000UL) ]
        [ V(0, 0x100000000UL, 0xbff8000000000000UL) ] ]
    check "4e083c20" []
      [ [ X(0, 0x70616f2f48dce01cUL) ]
        [ X(0, 0x57c883255f0f9e24UL) ]
        [ X(0, 0x7f80000080000000UL) ]
        [ X(0, 0x4008000000000000UL) ] ]
    check "aa0203f0" []
      [ [ X(16, 0xf893a2eefb32555eUL) ]
        [ X(16, 0x987bbcbfdd7e532fUL) ]
        [ X(16, 0xffffffffffffffffUL) ]
        [ X(16, 0x5555555555555555UL) ] ]
    check "aa1103e0" []
      [ [ X(0, 0xd0bad0da572baaf1UL) ]
        [ X(0, 0x5d3e47ecad6ef3d4UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0x40UL) ] ]
    check "aa1e03e0" []
      [ [ X(0, 0x990cd70b12c5d084UL) ]
        [ X(0, 0xddfcd92ab490c639UL) ]
        [ X(0, 0x8000000080000000UL) ]
        [ X(0, 0x7fffffffUL) ] ]
    check "aa0003fe" []
      [ [ X(30, 0x910a2dec89025cc1UL) ]
        [ X(30, 0x975835de1c9756ceUL) ]
        [ X(30, 0x0UL) ]
        [ X(30, 0xffffffffUL) ] ]
    check "aa0103e0" []
      [ [ X(0, 0xbeeb8da1658eec67UL) ]
        [ X(0, 0xbfc846100bfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x100000000UL) ] ]
    check "92800000" []
      [ [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0xffffffffffffffffUL) ] ]
    check "d2800000" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "d2a24680" []
      [ [ X(0, 0x12340000UL) ]
        [ X(0, 0x12340000UL) ]
        [ X(0, 0x12340000UL) ]
        [ X(0, 0x12340000UL) ] ]
    check "52900000" []
      [ [ X(0, 0x8000UL) ]
        [ X(0, 0x8000UL) ]
        [ X(0, 0x8000UL) ]
        [ X(0, 0x8000UL) ] ]
    check "92c24680" []
      [ [ X(0, 0xffffedcbffffffffUL) ]
        [ X(0, 0xffffedcbffffffffUL) ]
        [ X(0, 0xffffedcbffffffffUL) ]
        [ X(0, 0xffffedcbffffffffUL) ] ]
    check "128000a0" []
      [ [ X(0, 0xfffffffaUL) ]
        [ X(0, 0xfffffffaUL) ]
        [ X(0, 0xfffffffaUL) ]
        [ X(0, 0xfffffffaUL) ] ]

  /// C6.2.190 MOVK
  [<TestMethod>]
  member _.``C6.2.190 MOVK``() =
    check "72800200" []
      [ [ X(0, 0x89020010UL) ]
        [ X(0, 0x1c970010UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0xffff0010UL) ] ]
    check "f2800200" []
      [ [ X(0, 0x910a2dec89020010UL) ]
        [ X(0, 0x975835de1c970010UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0xffff0010UL) ] ]
    check "f2800000" []
      [ [ X(0, 0x910a2dec89020000UL) ]
        [ X(0, 0x975835de1c970000UL) ]
        []
        [ X(0, 0xffff0000UL) ] ]

  /// C6.2.191 MOVN
  [<TestMethod>]
  member _.``C6.2.191 MOVN``() =
    check "12800200" []
      [ [ X(0, 0xffffffefUL) ]
        [ X(0, 0xffffffefUL) ]
        [ X(0, 0xffffffefUL) ]
        [ X(0, 0xffffffefUL) ] ]
    check "92800200" []
      [ [ X(0, 0xffffffffffffffefUL) ]
        [ X(0, 0xffffffffffffffefUL) ]
        [ X(0, 0xffffffffffffffefUL) ]
        [ X(0, 0xffffffffffffffefUL) ] ]
    check "92800000" []
      [ [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0xffffffffffffffffUL) ] ]
    check "92c24680" []
      [ [ X(0, 0xffffedcbffffffffUL) ]
        [ X(0, 0xffffedcbffffffffUL) ]
        [ X(0, 0xffffedcbffffffffUL) ]
        [ X(0, 0xffffedcbffffffffUL) ] ]
    check "128000a0" []
      [ [ X(0, 0xfffffffaUL) ]
        [ X(0, 0xfffffffaUL) ]
        [ X(0, 0xfffffffaUL) ]
        [ X(0, 0xfffffffaUL) ] ]

  /// C6.2.192 MOVZ
  [<TestMethod>]
  member _.``C6.2.192 MOVZ``() =
    check "52800200" []
      [ [ X(0, 0x10UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x10UL) ] ]
    check "d2800200" []
      [ [ X(0, 0x10UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x10UL) ] ]
    check "d2800000" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "d2a24680" []
      [ [ X(0, 0x12340000UL) ]
        [ X(0, 0x12340000UL) ]
        [ X(0, 0x12340000UL) ]
        [ X(0, 0x12340000UL) ] ]
    check "52900000" []
      [ [ X(0, 0x8000UL) ]
        [ X(0, 0x8000UL) ]
        [ X(0, 0x8000UL) ]
        [ X(0, 0x8000UL) ] ]

  /// C6.2.193 MRS
  [<TestMethod>]
  member _.``C6.2.193 MRS``() =
    check "d53b4200" []
      [ [ X(0, 0x10000000UL) ]
        [ X(0, 0x50000000UL) ]
        [ X(0, 0x60000000UL) ]
        [ X(0, 0x90000000UL) ] ]
    check "d53b4420" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]

  /// C6.2.194 MSR (immediate)
  [<TestMethod>]
  member _.``C6.2.194 MSR``() =
    check "d51b4200" []
      [ [ NZCV 0x80000000UL ]
        [ NZCV 0x10000000UL ]
        [ NZCV 0x0UL ]
        [ NZCV 0xf0000000UL ] ]
    check "d503415f" [] [ []; []; []; [] ]

  /// C6.2.196 MSUB
  [<TestMethod>]
  member _.``C6.2.196 MSUB``() =
    check "1b028c20" []
      [ [ X(0, 0x62bc839UL) ]
        [ X(0, 0x30530246UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaaaUL) ] ]
    check "9b028c20" []
      [ [ X(0, 0xd5860120062bc839UL) ]
        [ X(0, 0x782eda3230530246UL) ]
        [ X(0, 0x8000000000000001UL) ]
        [ X(0, 0x55555555aaaaaaaaUL) ] ]

  /// C6.2.197 MUL
  [<TestMethod>]
  member _.``C6.2.197 MUL``() =
    check "1b027c20" []
      [ [ X(0, 0xe81700d2UL) ]
        [ X(0, 0xcf94f41eUL) ]
        [ X(0, 0xffffffffUL) ]
        [ X(0, 0x0UL) ] ]
    check "0f528020" []
      [ [ V(0, 0x163e1aa23248c3c8UL, 0x0UL) ]
        [ V(0, 0x5a803b10e3304140UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ] ]
    check "4f528020" []
      [ [ V(0, 0x163e1aa23248c3c8UL, 0x38547d64371ad8d2UL) ]
        [ V(0, 0x5a803b10e3304140UL, 0x60d0be7080305a50UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ] ]
    check "0fa28020" []
      [ [ V(0, 0xd6ed363e72e2cbb8UL, 0x0UL) ]
        [ V(0, 0xce1948c4a627d850UL, 0x0UL) ]
        [ V(0, 0x8080000080000000UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ] ]
    check "4fa28020" []
      [ [ V(0, 0xd6ed363e72e2cbb8UL, 0xb60b525ccae59d0eUL) ]
        [ V(0, 0xce1948c4a627d850UL, 0x8f93259c48e29894UL) ]
        [ V(0, 0x8080000080000000UL, 0x8060000080400000UL) ]
        [ V(0, 0x0UL, 0x8000000000000000UL) ] ]
    check "0e229c20" []
      [ [ V(0, 0x10def23e30482050UL, 0x0UL) ]
        [ V(0, 0x3f2804c4773066acUL, 0x0UL) ]
        [ V(0, 0x8080000000000000UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ] ]
    check "4e229c20" []
      [ [ V(0, 0x10def23e30482050UL, 0xc07404b8e4318003UL) ]
        [ V(0, 0x3f2804c4773066acUL, 0xae606e0e2047409cUL) ]
        [ V(0, 0x8080000000000000UL, 0x1400000UL) ]
        [ V(0, 0x0UL, 0x4170000000000000UL) ] ]
    check "0e629c20" []
      [ [ V(0, 0x82de363e32486550UL, 0x0UL) ]
        [ V(0, 0xef2848c4e3306bacUL, 0x0UL) ]
        [ V(0, 0x4080000000000000UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ] ]
    check "4e629c20" []
      [ [ V(0, 0x82de363e32486550UL, 0xd87438b8fb316203UL) ]
        [ V(0, 0xef2848c4e3306bacUL, 0x69604d0ec147639cUL) ]
        [ V(0, 0x4080000000000000UL, 0xd0000000a0400000UL) ]
        [ V(0, 0x0UL, 0x8470000000000000UL) ] ]
    check "0ea29c20" []
      [ [ V(0, 0xd6ed363e315e6550UL, 0x0UL) ]
        [ V(0, 0xce1948c447926bacUL, 0x0UL) ]
        [ V(0, 0x8080000080000000UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ] ]
    check "4ea29c20" []
      [ [ V(0, 0xd6ed363e315e6550UL, 0xaa0338b8b8d16203UL) ]
        [ V(0, 0xce1948c447926bacUL, 0x36904d0e3a55639cUL) ]
        [ V(0, 0x8080000080000000UL, 0x80400000UL) ]
        [ V(0, 0x0UL, 0xe670000000000000UL) ] ]
    check "9b027c20" []
      [ [ X(0, 0x9c3b8570e81700d2UL) ]
        [ X(0, 0x4bc3a848cf94f41eUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x5555555500000000UL) ] ]

  /// C6.2.198 MVN
  [<TestMethod>]
  member _.``C6.2.198 MVN``() =
    check "6e205820" []
      [ [ V(0, 0x8f9e90d0b7231fe3UL, 0xbf297db1d10c03e8UL) ]
        [ V(0, 0xa8377cdaa0f061dbUL, 0x1dcee4aca0e04f56UL) ]
        [ V(0, 0x807fffff7fffffffUL, 0x805fffff803fffffUL) ]
        [ V(0, 0xbff7ffffffffffffUL, 0xc046666666666665UL) ] ]
    check "2a2203e0" []
      [ [ X(0, 0x4cdaaa1UL) ]
        [ X(0, 0x2281acd0UL) ]
        []
        [ X(0, 0xaaaaaaaaUL) ] ]
    check "2e205820" []
      [ [ V(0, 0x8f9e90d0b7231fe3UL, 0x0UL) ]
        [ V(0, 0xa8377cdaa0f061dbUL, 0x0UL) ]
        [ V(0, 0x807fffff7fffffffUL, 0x0UL) ]
        [ V(0, 0xbff7ffffffffffffUL, 0x0UL) ] ]
    check "aa2203e0" []
      [ [ X(0, 0x76c5d1104cdaaa1UL) ]
        [ X(0, 0x678443402281acd0UL) ]
        []
        [ X(0, 0xaaaaaaaaaaaaaaaaUL) ] ]

  /// C6.2.199 NEG (shifted register)
  [<TestMethod>]
  member _.``C6.2.199 NEG``() =
    check "4b0203e0" []
      [ [ X(0, 0x4cdaaa2UL) ]
        [ X(0, 0x2281acd1UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaabUL) ] ]
    check "2e20b820" []
      [ [ V(0, 0x909f91d1b82420e4UL, 0x0UL) ]
        [ V(0, 0xa9387ddba1f162dcUL, 0x0UL) ]
        [ V(0, 0x8180000080000000UL, 0x0UL) ]
        [ V(0, 0xc0f8000000000000UL, 0x0UL) ] ]
    check "6e20b820" []
      [ [ V(0, 0x909f91d1b82420e4UL, 0xc02a7eb2d20d04e9UL) ]
        [ V(0, 0xa9387ddba1f162dcUL, 0x1ecfe5ada1e15057UL) ]
        [ V(0, 0x8180000080000000UL, 0x8160000081400000UL) ]
        [ V(0, 0xc0f8000000000000UL, 0xc147676767676766UL) ] ]
    check "2e60b820" []
      [ [ V(0, 0x8f9f90d1b7241fe4UL, 0x0UL) ]
        [ V(0, 0xa8387cdba0f161dcUL, 0x0UL) ]
        [ V(0, 0x8080000080000000UL, 0x0UL) ]
        [ V(0, 0xbff8000000000000UL, 0x0UL) ] ]
    check "6e60b820" []
      [ [ V(0, 0x8f9f90d1b7241fe4UL, 0xbf2a7db2d10d03e9UL) ]
        [ V(0, 0xa8387cdba0f161dcUL, 0x1dcfe4ada0e14f57UL) ]
        [ V(0, 0x8080000080000000UL, 0x8060000080400000UL) ]
        [ V(0, 0xbff8000000000000UL, 0xc047666766676666UL) ] ]
    check "2ea0b820" []
      [ [ V(0, 0x8f9e90d1b7231fe4UL, 0x0UL) ]
        [ V(0, 0xa8377cdba0f061dcUL, 0x0UL) ]
        [ V(0, 0x8080000080000000UL, 0x0UL) ]
        [ V(0, 0xbff8000000000000UL, 0x0UL) ] ]
    check "6ea0b820" []
      [ [ V(0, 0x8f9e90d1b7231fe4UL, 0xbf297db2d10c03e9UL) ]
        [ V(0, 0xa8377cdba0f061dcUL, 0x1dcee4ada0e04f57UL) ]
        [ V(0, 0x8080000080000000UL, 0x8060000080400000UL) ]
        [ V(0, 0xbff8000000000000UL, 0xc046666766666666UL) ] ]
    check "6ee0b820" []
      [ [ V(0, 0x8f9e90d0b7231fe4UL, 0xbf297db1d10c03e9UL) ]
        [ V(0, 0xa8377cdaa0f061dcUL, 0x1dcee4aca0e04f57UL) ]
        [ V(0, 0x807fffff80000000UL, 0x805fffff80400000UL) ]
        [ V(0, 0xbff8000000000000UL, 0xc046666666666666UL) ] ]
    check "cb0203e0" []
      [ [ X(0, 0x76c5d1104cdaaa2UL) ]
        [ X(0, 0x678443402281acd1UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaaaaaaaaaabUL) ] ]

  /// C6.2.200 NEGS
  [<TestMethod>]
  member _.``C6.2.200 NEGS``() =
    check "6b0203e0" []
      [ [ X(0, 0x4cdaaa2UL); NZCV 0x0UL ]
        [ X(0, 0x2281acd1UL); NZCV 0x0UL ]
        [ X(0, 0x1UL); NZCV 0x0UL ]
        [ X(0, 0xaaaaaaabUL); NZCV 0x80000000UL ] ]
    check "eb0203e0" []
      [ [ X(0, 0x76c5d1104cdaaa2UL); NZCV 0x0UL ]
        [ X(0, 0x678443402281acd1UL); NZCV 0x0UL ]
        [ X(0, 0x1UL); NZCV 0x0UL ]
        [ X(0, 0xaaaaaaaaaaaaaaabUL); NZCV 0x80000000UL ] ]

  /// C6.2.201 NGC
  [<TestMethod>]
  member _.``C6.2.201 NGC``() =
    check "5a0203e0" []
      [ [ X(0, 0x4cdaaa1UL) ]
        [ X(0, 0x2281acd0UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaaaUL) ] ]
    check "da0203e0" []
      [ [ X(0, 0x76c5d1104cdaaa1UL) ]
        [ X(0, 0x678443402281acd0UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaaaaaaaaaaaUL) ] ]

  /// C6.2.202 NGCS
  [<TestMethod>]
  member _.``C6.2.202 NGCS``() =
    check "7a0203e0" []
      [ [ X(0, 0x4cdaaa1UL); NZCV 0x0UL ]
        [ X(0, 0x2281acd0UL); NZCV 0x0UL ]
        [ X(0, 0x1UL); NZCV 0x0UL ]
        [ X(0, 0xaaaaaaaaUL); NZCV 0x80000000UL ] ]
    check "fa0203e0" []
      [ [ X(0, 0x76c5d1104cdaaa1UL); NZCV 0x0UL ]
        [ X(0, 0x678443402281acd0UL); NZCV 0x0UL ]
        [ X(0, 0x1UL); NZCV 0x0UL ]
        [ X(0, 0xaaaaaaaaaaaaaaaaUL); NZCV 0x80000000UL ] ]

  /// C6.2.203 NOP
  [<TestMethod>]
  member _.``C6.2.203 NOP``() =
    check "d503201f" [] [ []; []; []; [] ]

  /// C6.2.204 ORN (shifted register)
  [<TestMethod>]
  member _.``C6.2.204 ORN``() =
    check "2a220020" []
      [ [ X(0, 0x65cfeee7UL) ]
        [ X(0, 0x2bfdbed2UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaaaUL) ] ]
    check "0ee21c20" []
      [ [ V(0, 0x7861ffffe9dde0ffUL, 0x0UL) ]
        [ V(0, 0xf7fad3af5f2fbe2cUL, 0x0UL) ]
        [ V(0, 0x7f800000fffffffeUL, 0x0UL) ]
        [ V(0, 0x7fffffffffffffffUL, 0x0UL) ] ]
    check "4ee21c20" []
      [ [ V(0, 0x7861ffffe9dde0ffUL, 0x74d7ffffaff7ff1fUL) ]
        [ V(0, 0xf7fad3af5f2fbe2cUL, 0xfabfdf575f3ff3ebUL) ]
        [ V(0, 0x7f800000fffffffeUL, 0xffffffffffc00000UL) ]
        [ V(0, 0x7fffffffffffffffUL, 0xbfbfffffffffffffUL) ] ]
    check "aa220020" []
      [ [ X(0, 0xbfefddb165cfeee7UL) ]
        [ X(0, 0xffcc47502bfdbed2UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaabaaaaaaaaUL) ] ]

  /// C6.2.205 ORR (immediate)
  [<TestMethod>]
  member _.``C6.2.205 ORR``() =
    check "b2410420" []
      [ [ X(0, 0xbeeb8da1658eec67UL) ]
        [ X(0, 0xbfc846100bfc1e43UL) ]
        [ X(0, 0x8000000000000001UL) ]
        [ X(0, 0x8000000100000001UL) ] ]
    check "321c0020" []
      [ [ X(0, 0x658eec77UL) ]
        [ X(0, 0xbfc1e52UL) ]
        [ X(0, 0x11UL) ]
        [ X(0, 0x10UL) ] ]
    check "b27c0020" []
      [ [ X(0, 0xbeeb8da1658eec77UL) ]
        [ X(0, 0xbfc846100bfc1e52UL) ]
        [ X(0, 0x11UL) ]
        [ X(0, 0x100000010UL) ] ]
    check "2a020020" []
      [ [ X(0, 0xffbefd7fUL) ]
        [ X(0, 0xdffe5f6fUL) ]
        [ X(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]
    check "aa020020" []
      [ [ X(0, 0xfefbafefffbefd7fUL) ]
        [ X(0, 0xbffbfebfdffe5f6fUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x5555555555555555UL) ] ]
    check "0f009460" []
      [ [ V(0, 0x962b1967c90789bbUL, 0x0UL) ]
        [ V(0, 0x9a7ba72730fbca57UL, 0x0UL) ]
        [ V(0, 0xbfc300033f830003UL, 0x0UL) ]
        [ V(0, 0x3ff3000300030003UL, 0x0UL) ] ]
    check "4f009460" []
      [ [ V(0, 0x962b1967c90789bbUL, 0x65afe26b5a072c6fUL) ]
        [ V(0, 0x9a7ba72730fbca57UL, 0x444bcabb22bb690fUL) ]
        [ V(0, 0xbfc300033f830003UL, 0x3dcfcccf40430003UL) ]
        [ V(0, 0x3ff3000300030003UL, 0xbffb000300030003UL) ] ]
    check "0f001460" []
      [ [ V(0, 0x962b1967c90789bbUL, 0x0UL) ]
        [ V(0, 0x9a7aa72730f9ca57UL, 0x0UL) ]
        [ V(0, 0xbfc000033f800003UL, 0x0UL) ]
        [ V(0, 0x3ff0000300000003UL, 0x0UL) ] ]
    check "4f001460" []
      [ [ V(0, 0x962b1967c90789bbUL, 0x65ace26b5a072c6fUL) ]
        [ V(0, 0x9a7aa72730f9ca57UL, 0x444bcabb22bb690fUL) ]
        [ V(0, 0xbfc000033f800003UL, 0x3dcccccf40400003UL) ]
        [ V(0, 0x3ff0000300000003UL, 0xbff8000300000003UL) ] ]
    check "0ea21c20" []
      [ [ V(0, 0xf7ff6f2f5efeff1cUL, 0x0UL) ]
        [ V(0, 0x5fcdaf75ffdfdff7UL, 0x0UL) ]
        [ V(0, 0xffffffff80000001UL, 0x0UL) ]
        [ V(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "4ea21c20" []
      [ [ V(0, 0xf7ff6f2f5efeff1cUL, 0xcbfe824e7efbfcf7UL) ]
        [ V(0, 0x5fcdaf75ffdfdff7UL, 0xe7713bfbffdfbcbdUL) ]
        [ V(0, 0xffffffff80000001UL, 0x7fa000007fffffffUL) ]
        [ V(0, 0xc008000000000000UL, 0x7ff999999999999aUL) ] ]

  /// <summary>
  /// The code PACDA computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.207, AddPAC, Auth()), over every input
  /// set with X0 a canonical pointer and X1 the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTDA
  /// gives it back; and the other key's AUT fails, leaving key B's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.207 PACDA``() =
    signs "dac10820" "dac11820" "dac11c20" 0 0x4000000000000000UL

  /// <summary>
  /// The code PACDZA computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.207, AddPAC, Auth()), over every input
  /// set with X0 a canonical pointer and zero the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTDZA
  /// gives it back; and the other key's AUT fails, leaving key B's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.207 PACDZA``() =
    signs "dac12be0" "dac13be0" "dac13fe0" 0 0x4000000000000000UL

  /// <summary>
  /// The code PACDB computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.208, AddPAC, Auth()), over every input
  /// set with X0 a canonical pointer and X1 the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTDB
  /// gives it back; and the other key's AUT fails, leaving key A's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.208 PACDB``() =
    signs "dac10c20" "dac11c20" "dac11820" 0 0x2000000000000000UL

  /// <summary>
  /// The code PACDZB computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.208, AddPAC, Auth()), over every input
  /// set with X0 a canonical pointer and zero the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTDZB
  /// gives it back; and the other key's AUT fails, leaving key A's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.208 PACDZB``() =
    signs "dac12fe0" "dac13fe0" "dac13be0" 0 0x2000000000000000UL

  /// <summary>
  /// The code PACGA computes comes from a key the oracle's process draws
  /// at random, so no value of it can be compared. What the manual fixes is
  /// checked instead (C6.2.209): the code goes to the top half of Xd and
  /// the bottom half is zero, over every input set, and it is a function
  /// of both operands, changing with each.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.209 PACGA``() =
    for k in 0 .. A64Machine.sets - 1 do
      let code inputs = (A64Machine.after [ "9ac23020" ] inputs k).Xs[0]
      let given = code []
      Assert.AreEqual<uint64>(0UL, given &&& 0xffffffffUL)
      Assert.AreNotEqual<uint64>(given, code [ X(1, pointer) ])
      Assert.AreNotEqual<uint64>(given, code [ X(2, pointer) ])

  /// <summary>
  /// The code PACIA computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.210, AddPAC, Auth()), over every input
  /// set with X0 a canonical pointer and X1 the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTIA
  /// gives it back; and the other key's AUT fails, leaving key B's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.210 PACIA``() =
    signs "dac10020" "dac11020" "dac11420" 0 0x4000000000000000UL

  /// <summary>
  /// The code PACIA1716 computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.210, AddPAC, Auth()), over every input
  /// set with X17 a canonical pointer and X16 the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTIA1716
  /// gives it back; and the other key's AUT fails, leaving key B's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.210 PACIA1716``() =
    signs "d503211f" "d503219f" "d50321df" 17 0x4000000000000000UL

  /// <summary>
  /// The code PACIASP computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.210, AddPAC, Auth()), over every input
  /// set with X30 a canonical pointer and SP the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTIASP
  /// gives it back; and the other key's AUT fails, leaving key B's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.210 PACIASP``() =
    signs "d503233f" "d50323bf" "d50323ff" 30 0x4000000000000000UL

  /// <summary>
  /// The code PACIAZ computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.210, AddPAC, Auth()), over every input
  /// set with X30 a canonical pointer and zero the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTIAZ
  /// gives it back; and the other key's AUT fails, leaving key B's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.210 PACIAZ``() =
    signs "d503231f" "d503239f" "d50323df" 30 0x4000000000000000UL

  /// <summary>
  /// The code PACIZA computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.210, AddPAC, Auth()), over every input
  /// set with X0 a canonical pointer and zero the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTIZA
  /// gives it back; and the other key's AUT fails, leaving key B's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.210 PACIZA``() =
    signs "dac123e0" "dac133e0" "dac137e0" 0 0x4000000000000000UL

  /// <summary>
  /// The code PACIB computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.211, AddPAC, Auth()), over every input
  /// set with X0 a canonical pointer and X1 the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTIB
  /// gives it back; and the other key's AUT fails, leaving key A's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.211 PACIB``() =
    signs "dac10420" "dac11420" "dac11020" 0 0x2000000000000000UL

  /// <summary>
  /// The code PACIB1716 computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.211, AddPAC, Auth()), over every input
  /// set with X17 a canonical pointer and X16 the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTIB1716
  /// gives it back; and the other key's AUT fails, leaving key A's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.211 PACIB1716``() =
    signs "d503215f" "d50321df" "d503219f" 17 0x2000000000000000UL

  /// <summary>
  /// The code PACIBSP computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.211, AddPAC, Auth()), over every input
  /// set with X30 a canonical pointer and SP the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTIBSP
  /// gives it back; and the other key's AUT fails, leaving key A's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.211 PACIBSP``() =
    signs "d503237f" "d50323ff" "d50323bf" 30 0x2000000000000000UL

  /// <summary>
  /// The code PACIBZ computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.211, AddPAC, Auth()), over every input
  /// set with X30 a canonical pointer and zero the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTIBZ
  /// gives it back; and the other key's AUT fails, leaving key A's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.211 PACIBZ``() =
    signs "d503235f" "d50323df" "d503239f" 30 0x2000000000000000UL

  /// <summary>
  /// The code PACIZB computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.211, AddPAC, Auth()), over every input
  /// set with X0 a canonical pointer and zero the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTIZB
  /// gives it back; and the other key's AUT fails, leaving key A's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.211 PACIZB``() =
    signs "dac127e0" "dac137e0" "dac133e0" 0 0x2000000000000000UL

  /// C6.2.212 PRFM (immediate)
  [<TestMethod>]
  member _.``C6.2.212 PRFM``() =
    check "f9800020" [ X(1, 0x2008000UL) ] [ []; []; []; [] ]

  /// C6.2.215 PRFUM
  [<TestMethod>]
  member _.``C6.2.215 PRFUM``() =
    check "f8800020" [ X(1, 0x2008000UL) ] [ []; []; []; [] ]

  /// C6.2.216 PSB CSYNC
  [<TestMethod>]
  member _.``C6.2.216 PSB``() =
    check "d503223f" [] [ []; []; []; [] ]

  /// C6.2.217 PSSBB
  [<TestMethod>]
  member _.``C6.2.217 PSSBB``() =
    check "d503349f" [] [ []; []; []; [] ]

  /// C6.2.218 RBIT
  [<TestMethod>]
  member _.``C6.2.218 RBIT``() =
    check "5ac00020" []
      [ [ X(0, 0xe63771a6UL) ]
        [ X(0, 0x42783fd0UL) ]
        [ X(0, 0x80000000UL) ]
        [ X(0, 0x0UL) ] ]
    check "2e605820" []
      [ [ V(0, 0xe86f6f4123b0738UL, 0x0UL) ]
        [ V(0, 0xea13c1a4faf07924UL, 0x0UL) ]
        [ V(0, 0xfe01000001000000UL, 0x0UL) ]
        [ V(0, 0x210000000000000UL, 0x0UL) ] ]
    check "6e605820" []
      [ [ V(0, 0xe86f6f4123b0738UL, 0x26b417274cf3fe8UL) ]
        [ V(0, 0xea13c1a4faf07924UL, 0x478cd8cafaf80d95UL) ]
        [ V(0, 0xfe01000001000000UL, 0xfe050000fe030000UL) ]
        [ V(0, 0x210000000000000UL, 0xfc9d999999999959UL) ] ]
    check "dac00020" []
      [ [ X(0, 0xe63771a685b1d77dUL) ]
        [ X(0, 0x42783fd0086213fdUL) ]
        [ X(0, 0x8000000000000000UL) ]
        [ X(0, 0x80000000UL) ] ]

  /// <summary>
  /// RET cannot run in the oracle, which has nowhere for it to go, so this
  /// checks the jump: a return out of the instruction to what X30 holds, or
  /// the register it names, over every input set (C6.2.219).
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.219 RET``() =
    Assert.AreEqual<string option>(Some "IsRet", exitOf "d65f03c0")
    check "d65f03c0" []
      [ [ PC 0x990cd70b12c5d084UL ]
        [ PC 0xddfcd92ab490c639UL ]
        [ PC 0x8000000080000000UL ]
        [ PC 0x7fffffffUL ] ]
    check "d65f0020" []
      [ [ PC 0xbeeb8da1658eec67UL ]
        [ PC 0xbfc846100bfc1e42UL ]
        [ PC 0x1UL ]
        [ PC 0x100000000UL ] ]

  /// <summary>
  /// RETAA cannot run in the oracle, which has nowhere for it to go, and
  /// its target is authenticated with a key the oracle's process draws
  /// at random. What the manual fixes is checked instead (C6.2.220): with X30
  /// a canonical pointer the matching PAC signed, the jump, a return,
  /// goes to the pointer; unsigned, to the pointer with the key's error
  /// code in bits 62:61, over every input set.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.220 RETAA``() =
    Assert.AreEqual<string option>(Some "IsRet", exitOf "d65f0bff")
    branchesSigned "d503233f" "d65f0bff" 30 0x2000000000000000UL false

  /// <summary>
  /// RETAB cannot run in the oracle, which has nowhere for it to go, and
  /// its target is authenticated with a key the oracle's process draws
  /// at random. What the manual fixes is checked instead (C6.2.220): with X30
  /// a canonical pointer the matching PAC signed, the jump, a return,
  /// goes to the pointer; unsigned, to the pointer with the key's error
  /// code in bits 62:61, over every input set.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.220 RETAB``() =
    Assert.AreEqual<string option>(Some "IsRet", exitOf "d65f0fff")
    branchesSigned "d503237f" "d65f0fff" 30 0x4000000000000000UL false

  /// C6.2.221 REV
  [<TestMethod>]
  member _.``C6.2.221 REV``() =
    check "5ac00820" []
      [ [ X(0, 0x67ec8e65UL) ]
        [ X(0, 0x421efc0bUL) ]
        [ X(0, 0x1000000UL) ]
        [ X(0, 0x0UL) ] ]
    check "dac00c20" []
      [ [ X(0, 0x67ec8e65a18debbeUL) ]
        [ X(0, 0x421efc0b1046c8bfUL) ]
        [ X(0, 0x100000000000000UL) ]
        [ X(0, 0x1000000UL) ] ]

  /// C6.2.222 REV16
  [<TestMethod>]
  member _.``C6.2.222 REV16``() =
    check "5ac00420" []
      [ [ X(0, 0x8e6567ecUL) ]
        [ X(0, 0xfc0b421eUL) ]
        [ X(0, 0x100UL) ]
        [ X(0, 0x0UL) ] ]
    check "0e201820" []
      [ [ V(0, 0x61702f6fdc481ce0UL, 0x0UL) ]
        [ V(0, 0xc85725830f5f249eUL, 0x0UL) ]
        [ V(0, 0x807f000000800000UL, 0x0UL) ]
        [ V(0, 0x840000000000000UL, 0x0UL) ] ]
    check "4e201820" []
      [ [ V(0, 0x61702f6fdc481ce0UL, 0xd6404e82f32e17fcUL) ]
        [ V(0, 0xc85725830f5f249eUL, 0x31e2531b1f5fa9b0UL) ]
        [ V(0, 0x807f000000800000UL, 0xa07f0000c07f0000UL) ]
        [ V(0, 0x840000000000000UL, 0xb93f999999999a99UL) ] ]
    check "dac00420" []
      [ [ X(0, 0xebbea18d8e6567ecUL) ]
        [ X(0, 0xc8bf1046fc0b421eUL) ]
        [ X(0, 0x100UL) ]
        [ X(0, 0x10000000000UL) ] ]

  /// C6.2.223 REV32
  [<TestMethod>]
  member _.``C6.2.223 REV32``() =
    check "2e200820" []
      [ [ V(0, 0x2f6f61701ce0dc48UL, 0x0UL) ]
        [ V(0, 0x2583c857249e0f5fUL, 0x0UL) ]
        [ V(0, 0x807f00000080UL, 0x0UL) ]
        [ V(0, 0x84000000000UL, 0x0UL) ] ]
    check "6e200820" []
      [ [ V(0, 0x2f6f61701ce0dc48UL, 0x4e82d64017fcf32eUL) ]
        [ V(0, 0x2583c857249e0f5fUL, 0x531b31e2a9b01f5fUL) ]
        [ V(0, 0x807f00000080UL, 0xa07f0000c07fUL) ]
        [ V(0, 0x84000000000UL, 0x9999b93f9a999999UL) ] ]
    check "2e600820" []
      [ [ V(0, 0x6f2f7061e01c48dcUL, 0x0UL) ]
        [ V(0, 0x832557c89e245f0fUL, 0x0UL) ]
        [ V(0, 0x7f8000008000UL, 0x0UL) ]
        [ V(0, 0x400800000000UL, 0x0UL) ] ]
    check "6e600820" []
      [ [ V(0, 0x6f2f7061e01c48dcUL, 0x824e40d6fc172ef3UL) ]
        [ V(0, 0x832557c89e245f0fUL, 0x1b53e231b0a95f1fUL) ]
        [ V(0, 0x7f8000008000UL, 0x7fa000007fc0UL) ]
        [ V(0, 0x400800000000UL, 0x99993fb9999a9999UL) ] ]
    check "dac00820" []
      [ [ X(0, 0xa18debbe67ec8e65UL) ]
        [ X(0, 0x1046c8bf421efc0bUL) ]
        [ X(0, 0x1000000UL) ]
        [ X(0, 0x100000000000000UL) ] ]

  /// C6.2.224 REV64
  [<TestMethod>]
  member _.``C6.2.224 REV64``() =
    check "0e200820" []
      [ [ V(0, 0x1ce0dc482f6f6170UL, 0x0UL) ]
        [ V(0, 0x249e0f5f2583c857UL, 0x0UL) ]
        [ V(0, 0x800000807fUL, 0x0UL) ]
        [ V(0, 0x840UL, 0x0UL) ] ]
    check "4e200820" []
      [ [ V(0, 0x1ce0dc482f6f6170UL, 0x17fcf32e4e82d640UL) ]
        [ V(0, 0x249e0f5f2583c857UL, 0xa9b01f5f531b31e2UL) ]
        [ V(0, 0x800000807fUL, 0xc07f0000a07fUL) ]
        [ V(0, 0x840UL, 0x9a9999999999b93fUL) ] ]
    check "0e600820" []
      [ [ V(0, 0xe01c48dc6f2f7061UL, 0x0UL) ]
        [ V(0, 0x9e245f0f832557c8UL, 0x0UL) ]
        [ V(0, 0x800000007f80UL, 0x0UL) ]
        [ V(0, 0x4008UL, 0x0UL) ] ]
    check "4e600820" []
      [ [ V(0, 0xe01c48dc6f2f7061UL, 0xfc172ef3824e40d6UL) ]
        [ V(0, 0x9e245f0f832557c8UL, 0xb0a95f1f1b53e231UL) ]
        [ V(0, 0x800000007f80UL, 0x7fc000007fa0UL) ]
        [ V(0, 0x4008UL, 0x999a999999993fb9UL) ] ]
    check "0ea00820" []
      [ [ V(0, 0x48dce01c70616f2fUL, 0x0UL) ]
        [ V(0, 0x5f0f9e2457c88325UL, 0x0UL) ]
        [ V(0, 0x800000007f800000UL, 0x0UL) ]
        [ V(0, 0x40080000UL, 0x0UL) ] ]
    check "4ea00820" []
      [ [ V(0, 0x48dce01c70616f2fUL, 0x2ef3fc1740d6824eUL) ]
        [ V(0, 0x5f0f9e2457c88325UL, 0x5f1fb0a9e2311b53UL) ]
        [ V(0, 0x800000007f800000UL, 0x7fc000007fa00000UL) ]
        [ V(0, 0x40080000UL, 0x9999999a3fb99999UL) ] ]

  /// C6.2.225 RMIF
  [<TestMethod>]
  member _.``C6.2.225 RMIF``() =
    check "ba03840f" []
      [ [ NZCV 0x90000000UL ]
        [ NZCV 0xd0000000UL ]
        [ NZCV 0x0UL ]
        [ NZCV 0xf0000000UL ] ]

  /// C6.2.226 ROR (immediate)
  [<TestMethod>]
  member _.``C6.2.226 ROR``() =
    check "13820440" []
      [ [ X(0, 0x7d992aafUL) ]
        [ X(0, 0xeebf2997UL) ]
        [ X(0, 0xffffffffUL) ]
        [ X(0, 0xaaaaaaaaUL) ] ]
    check "93c20440" []
      [ [ X(0, 0x7c49d1777d992aafUL) ]
        [ X(0, 0xcc3dde5feebf2997UL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0xaaaaaaaaaaaaaaaaUL) ] ]
    check "1ac22c20" []
      [ [ X(0, 0x963bb19dUL) ]
        [ X(0, 0x3c8417f8UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0x0UL) ] ]
    check "93c20040" []
      [ [ X(0, 0xf893a2eefb32555eUL) ]
        [ X(0, 0x987bbcbfdd7e532fUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x5555555555555555UL) ] ]
    check "9ac22c20" []
      [ [ X(0, 0x963bb19efbae3685UL) ]
        [ X(0, 0x8c2017f83c857f90UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0x800UL) ] ]

  /// C6.2.228 RORV
  [<TestMethod>]
  member _.``C6.2.228 RORV``() =
    check "1ac22c20" []
      [ [ X(0, 0x963bb19dUL) ]
        [ X(0, 0x3c8417f8UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0x0UL) ] ]
    check "9ac22c20" []
      [ [ X(0, 0x963bb19efbae3685UL) ]
        [ X(0, 0x8c2017f83c857f90UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0x800UL) ] ]

  /// C6.2.229 SB
  [<TestMethod>]
  member _.``C6.2.229 SB``() =
    check "d50330ff" [] [ []; []; []; [] ]

  /// C6.2.230 SBC
  [<TestMethod>]
  member _.``C6.2.230 SBC``() =
    check "5a020020" []
      [ [ X(0, 0x6a5c9708UL) ]
        [ X(0, 0x2e7dcb12UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0xaaaaaaaaUL) ] ]
    check "da020020" []
      [ [ X(0, 0xc657eab26a5c9708UL) ]
        [ X(0, 0x274c89502e7dcb12UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0xaaaaaaabaaaaaaaaUL) ] ]

  /// C6.2.231 SBCS
  [<TestMethod>]
  member _.``C6.2.231 SBCS``() =
    check "7a020020" []
      [ [ X(0, 0x6a5c9708UL); NZCV 0x0UL ]
        [ X(0, 0x2e7dcb12UL); NZCV 0x0UL ]
        [ X(0, 0x2UL); NZCV 0x0UL ]
        [ X(0, 0xaaaaaaaaUL); NZCV 0x80000000UL ] ]
    check "fa020020" []
      [ [ X(0, 0xc657eab26a5c9708UL); NZCV 0x80000000UL ]
        [ X(0, 0x274c89502e7dcb12UL); NZCV 0x20000000UL ]
        [ X(0, 0x2UL); NZCV 0x0UL ]
        [ X(0, 0xaaaaaaabaaaaaaaaUL); NZCV 0x80000000UL ] ]

  /// C6.2.232 SBFIZ
  [<TestMethod>]
  member _.``C6.2.232 SBFIZ``() =
    check "131d1020" []
      [ [ X(0, 0x38UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x8UL) ]
        [ X(0, 0x0UL) ] ]
    check "937d1020" []
      [ [ X(0, 0x38UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x8UL) ]
        [ X(0, 0x0UL) ] ]
    check "93430820" []
      [ [ X(0, 0xe000000000000000UL) ]
        [ X(0, 0x4000000000000000UL) ]
        [ X(0, 0x2000000000000000UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.233 SBFM
  [<TestMethod>]
  member _.``C6.2.233 SBFM``() =
    check "13017c20" []
      [ [ X(0, 0x32c77633UL) ]
        [ X(0, 0x5fe0f21UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "9341fc20" []
      [ [ X(0, 0xdf75c6d0b2c77633UL) ]
        [ X(0, 0xdfe4230805fe0f21UL) ]
        []
        [ X(0, 0x80000000UL) ] ]
    check "131d1020" []
      [ [ X(0, 0x38UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x8UL) ]
        [ X(0, 0x0UL) ] ]
    check "937d1020" []
      [ [ X(0, 0x38UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x8UL) ]
        [ X(0, 0x0UL) ] ]
    check "13031420" []
      [ [ X(0, 0xfffffffcUL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "93431420" []
      [ [ X(0, 0xfffffffffffffffcUL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "13031c20" []
      [ [ X(0, 0xcUL) ]
        [ X(0, 0x8UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "93431c20" []
      [ [ X(0, 0xcUL) ]
        [ X(0, 0x8UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "13001c20" []
      [ [ X(0, 0x67UL) ]
        [ X(0, 0x42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "13003c20" []
      [ [ X(0, 0xffffec67UL) ]
        [ X(0, 0x1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "93400020" []
      [ [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x0UL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x0UL) ] ]
    check "93401c20" []
      [ [ X(0, 0x67UL) ]
        [ X(0, 0x42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "93403c20" []
      [ [ X(0, 0xffffffffffffec67UL) ]
        [ X(0, 0x1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "93407c20" []
      [ [ X(0, 0x658eec67UL) ]
        [ X(0, 0xbfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "93430820" []
      [ [ X(0, 0xe000000000000000UL) ]
        [ X(0, 0x4000000000000000UL) ]
        [ X(0, 0x2000000000000000UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.234 SBFX
  [<TestMethod>]
  member _.``C6.2.234 SBFX``() =
    check "13031420" []
      [ [ X(0, 0xfffffffcUL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "93431420" []
      [ [ X(0, 0xfffffffffffffffcUL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "13031c20" []
      [ [ X(0, 0xcUL) ]
        [ X(0, 0x8UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "93431c20" []
      [ [ X(0, 0xcUL) ]
        [ X(0, 0x8UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "93400020" []
      [ [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x0UL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.235 SDIV
  [<TestMethod>]
  member _.``C6.2.235 SDIV``() =
    check "1ac20c20" []
      [ [ X(0, 0xffffffebUL) ]
        [ X(0, 0x0UL) ]
        [ X(0, 0xffffffffUL) ]
        [ X(0, 0x0UL) ] ]
    check "9ac20c20" []
      [ [ X(0, 0x8UL) ]
        [ X(0, 0x0UL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.236 SETF8, SETF16
  [<TestMethod>]
  member _.``C6.2.236 SETF16``() =
    check "3a00480d" []
      [ [ NZCV 0x0UL ]
        [ NZCV 0x10000000UL ]
        []
        [ NZCV 0x80000000UL ] ]
    check "3a00482d" []
      [ [ NZCV 0x90000000UL ]
        [ NZCV 0x0UL ]
        [ NZCV 0x20000000UL ]
        [ NZCV 0x40000000UL ] ]

  /// C6.2.236 SETF8, SETF16
  [<TestMethod>]
  member _.``C6.2.236 SETF8``() =
    check "3a00080d" []
      [ [ NZCV 0x90000000UL ]
        [ NZCV 0x90000000UL ]
        []
        [ NZCV 0x80000000UL ] ]
    check "3a00082d" []
      [ [ NZCV 0x0UL ]
        [ NZCV 0x0UL ]
        [ NZCV 0x20000000UL ]
        [ NZCV 0x40000000UL ] ]

  /// C6.2.237 SEV
  [<TestMethod>]
  member _.``C6.2.237 SEV``() =
    check "d503209f" [] [ []; []; []; [] ]

  /// C6.2.238 SEVL
  [<TestMethod>]
  member _.``C6.2.238 SEVL``() =
    check "d50320bf" [] [ []; []; []; [] ]

  /// C6.2.239 SMADDL
  [<TestMethod>]
  member _.``C6.2.239 SMADDL``() =
    check "9b220c20" []
      [ [ X(0, 0x6fd9b3bad659c9ddUL) ]
        [ X(0, 0xc254f453cf7cea82UL) ]
        [ X(0, 0x7fffffffffffffffUL) ]
        [ X(0, 0xaaaaaaaaaaaaaaaaUL) ] ]

  /// C6.2.240 SMC
  [<TestMethod>]
  member _.``C6.2.240 SMC``() =
    raises BinIR.SideEffect.UndefinedInstruction "d4000003"

  /// C6.2.241 SMNEGL
  [<TestMethod>]
  member _.``C6.2.241 SMNEGL``() =
    check "9b22fc20" []
      [ [ X(0, 0x1e7d2d617e8ff2eUL) ]
        [ X(0, 0x19d8e27306b0be2UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.242 SMSUBL
  [<TestMethod>]
  member _.``C6.2.242 SMSUBL``() =
    check "9b228c20" []
      [ [ X(0, 0x73a95967062bc839UL) ]
        [ X(0, 0xc59010a230530246UL) ]
        [ X(0, 0x8000000000000001UL) ]
        [ X(0, 0xaaaaaaaaaaaaaaaaUL) ] ]

  /// C6.2.243 SMULH
  [<TestMethod>]
  member _.``C6.2.243 SMULH``() =
    check "9b427c20" []
      [ [ X(0, 0x1e31b699742d02aUL) ]
        [ X(0, 0x19f7996a172798ceUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.244 SMULL
  [<TestMethod>]
  member _.``C6.2.244 SMULL``() =
    check "0f52a020" []
      [ [ V(0, 0x18c23248f529c3c8UL, 0x2630163e25c81aa2UL) ]
        [ V(0, 0xf7c2e330087b4140UL, 0xf8645a800ad23b10UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ] ]
    check "0fa2a020" []
      [ [ V(0, 0xddbc9f8672e2cbb8UL, 0xcb2762d5d6ed363eUL) ]
        [ V(0, 0x212945b6a627d850UL, 0x1e9f5809ce1948c4UL) ]
        [ V(0, 0x3fc0000080000000UL, 0xc07fbfff80800000UL) ]
        [ V(0, 0x0UL, 0xdffc000000000000UL) ] ]
    check "0e22c020" []
      [ [ V(0, 0x1830004800200150UL, 0xcb10dade13f2063eUL) ]
        [ V(0, 0xf777fd30dc66f9acUL, 0x1e3fef28290410c4UL) ]
        [ V(0, 0x0UL, 0xc080c08000000000UL) ]
        [ V(0, 0x0UL, 0xe000000000000000UL) ] ]
    check "0e62c020" []
      [ [ V(0, 0x18c23248001e6550UL, 0xcb2782de1409363eUL) ]
        [ V(0, 0xf7c2e330dc226bacUL, 0x1e9eef2828bf48c4UL) ]
        [ V(0, 0x0UL, 0xc07f408000000000UL) ]
        [ V(0, 0x0UL, 0xdffc000000000000UL) ] ]
    check "0ea2c020" []
      [ [ V(0, 0x18c2c707315e6550UL, 0xcb2762d5d6ed363eUL) ]
        [ V(0, 0xf7c2f85247926bacUL, 0x1e9f5809ce1948c4UL) ]
        [ V(0, 0xffffffff80000000UL, 0xc07fbfff80800000UL) ]
        [ V(0, 0x0UL, 0xdffc000000000000UL) ] ]
    check "9b227c20" []
      [ [ X(0, 0xfe182d29e81700d2UL) ]
        [ X(0, 0xfe6271d8cf94f41eUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.245 SSBB
  [<TestMethod>]
  member _.``C6.2.245 SSBB``() =
    check "d503309f" [] [ []; []; []; [] ]

  /// C6.2.246 ST2G
  [<TestMethod>]
  member _.``C6.2.246 ST2G``() =
    check "d9a00820" [ X(1, 0x2008000UL) ] [ []; []; []; [] ]
    check "d9a01420" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ] ]
    check "d9a01c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ] ]
    check "d9a01820" [ X(1, 0x2007ff0UL) ] [ []; []; []; [] ]
    check "d9a00420" [ X(1, 0x2008000UL) ] [ []; []; []; [] ]

  /// C6.2.247 STADDB, STADDLB
  [<TestMethod>]
  member _.``C6.2.247 STADDB``() =
    check "3822003f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4adfUL) ]
        [ M(0, 0x912f822b1e8fe113UL) ]
        [ M(0, 0xffUL) ]
        [ M(0, 0x55555555555555aaUL) ] ]

  /// C6.2.247 STADDB, STADDLB
  [<TestMethod>]
  member _.``C6.2.247 STADDLB``() =
    check "3862003f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4adfUL) ]
        [ M(0, 0x912f822b1e8fe113UL) ]
        [ M(0, 0xffUL) ]
        [ M(0, 0x55555555555555aaUL) ] ]

  /// C6.2.248 STADDH, STADDLH
  [<TestMethod>]
  member _.``C6.2.248 STADDH``() =
    check "7822003f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e9fdfUL) ]
        [ M(0, 0x912f822b1e8f3513UL) ]
        [ M(0, 0xffffUL) ]
        [ M(0, 0x555555555555aaaaUL) ] ]

  /// C6.2.248 STADDH, STADDLH
  [<TestMethod>]
  member _.``C6.2.248 STADDLH``() =
    check "7862003f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e9fdfUL) ]
        [ M(0, 0x912f822b1e8f3513UL) ]
        [ M(0, 0xffffUL) ]
        [ M(0, 0x555555555555aaaaUL) ] ]

  /// C6.2.249 STADD, STADDL
  [<TestMethod>]
  member _.``C6.2.249 STADD``() =
    check "f822003f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xd3b3cbf9bc709fdfUL) ]
        [ M(0, 0x29ab3eeafc0e3513UL) ]
        [ M(0, 0xffffffffffffffffUL) ]
        [ M(0, 0xaaaaaaaaaaaaaaaaUL) ] ]
    check "b822003f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290abc709fdfUL) ]
        [ M(0, 0x912f822bfc0e3513UL) ]
        [ M(0, 0xffffffffUL) ]
        [ M(0, 0x55555555aaaaaaaaUL) ] ]

  /// C6.2.249 STADD, STADDL
  [<TestMethod>]
  member _.``C6.2.249 STADDL``() =
    check "b862003f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290abc709fdfUL) ]
        [ M(0, 0x912f822bfc0e3513UL) ]
        [ M(0, 0xffffffffUL) ]
        [ M(0, 0x55555555aaaaaaaaUL) ] ]

  /// C6.2.250 STCLRB, STCLRLB
  [<TestMethod>]
  member _.``C6.2.250 STCLRB``() =
    check "3822103f" [ X(1, 0x2008000UL) ]
      [ []
        [ M(0, 0x912f822b1e8fe1c0UL) ]
        []
        [ M(0, 0x5555555555555500UL) ] ]

  /// C6.2.250 STCLRB, STCLRLB
  [<TestMethod>]
  member _.``C6.2.250 STCLRLB``() =
    check "3862103f" [ X(1, 0x2008000UL) ]
      [ []
        [ M(0, 0x912f822b1e8fe1c0UL) ]
        []
        [ M(0, 0x5555555555555500UL) ] ]

  /// C6.2.251 STCLRH, STCLRLH
  [<TestMethod>]
  member _.``C6.2.251 STCLRH``() =
    check "7822103f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e0a81UL) ]
        [ M(0, 0x912f822b1e8fa0c0UL) ]
        []
        [ M(0, 0x5555555555550000UL) ] ]

  /// C6.2.251 STCLRH, STCLRLH
  [<TestMethod>]
  member _.``C6.2.251 STCLRLH``() =
    check "7862103f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e0a81UL) ]
        [ M(0, 0x912f822b1e8fa0c0UL) ]
        []
        [ M(0, 0x5555555555550000UL) ] ]

  /// C6.2.252 STCLR, STCLRL
  [<TestMethod>]
  member _.``C6.2.252 STCLR``() =
    check "f822103f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x3200900000c0a81UL) ]
        [ M(0, 0x10402000281a0c0UL) ]
        []
        [ M(0, 0x0UL) ] ]
    check "b822103f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290a000c0a81UL) ]
        [ M(0, 0x912f822b0281a0c0UL) ]
        []
        [ M(0, 0x5555555500000000UL) ] ]

  /// C6.2.252 STCLR, STCLRL
  [<TestMethod>]
  member _.``C6.2.252 STCLRL``() =
    check "b862103f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290a000c0a81UL) ]
        [ M(0, 0x912f822b0281a0c0UL) ]
        []
        [ M(0, 0x5555555500000000UL) ] ]

  /// C6.2.253 STEORB, STEORLB
  [<TestMethod>]
  member _.``C6.2.253 STEORB``() =
    check "3822203f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4adfUL) ]
        [ M(0, 0x912f822b1e8fe1cbUL) ]
        [ M(0, 0xffUL) ]
        [ M(0, 0x5555555555555500UL) ] ]

  /// C6.2.253 STEORB, STEORLB
  [<TestMethod>]
  member _.``C6.2.253 STEORLB``() =
    check "3862203f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4adfUL) ]
        [ M(0, 0x912f822b1e8fe1cbUL) ]
        [ M(0, 0xffUL) ]
        [ M(0, 0x5555555555555500UL) ] ]

  /// C6.2.254 STEORH, STEORLH
  [<TestMethod>]
  member _.``C6.2.254 STEORH``() =
    check "7822203f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e1fdfUL) ]
        [ M(0, 0x912f822b1e8fb2cbUL) ]
        [ M(0, 0xffffUL) ]
        [ M(0, 0x5555555555550000UL) ] ]

  /// C6.2.254 STEORH, STEORLH
  [<TestMethod>]
  member _.``C6.2.254 STEORLH``() =
    check "7862203f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e1fdfUL) ]
        [ M(0, 0x912f822b1e8fb2cbUL) ]
        [ M(0, 0xffffUL) ]
        [ M(0, 0x5555555555550000UL) ] ]

  /// C6.2.255 STEOR, STEORL
  [<TestMethod>]
  member _.``C6.2.255 STEOR``() =
    check "f822203f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x23b38be43a0c1fdfUL) ]
        [ M(0, 0x9543e94c3f1b2cbUL) ]
        [ M(0, 0xffffffffffffffffUL) ]
        [ M(0, 0x0UL) ] ]
    check "b822203f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290a3a0c1fdfUL) ]
        [ M(0, 0x912f822bc3f1b2cbUL) ]
        [ M(0, 0xffffffffUL) ]
        [ M(0, 0x5555555500000000UL) ] ]

  /// C6.2.255 STEOR, STEORL
  [<TestMethod>]
  member _.``C6.2.255 STEORL``() =
    check "b862203f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290a3a0c1fdfUL) ]
        [ M(0, 0x912f822bc3f1b2cbUL) ]
        [ M(0, 0xffffffffUL) ]
        [ M(0, 0x5555555500000000UL) ] ]

  /// C6.2.256 STG
  [<TestMethod>]
  member _.``C6.2.256 STG``() =
    check "d9200820" [ X(1, 0x2008000UL) ] [ []; []; []; [] ]
    check "d9201420" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ] ]
    check "d9201c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ] ]
    check "d9201820" [ X(1, 0x2007ff0UL) ] [ []; []; []; [] ]
    check "d9200420" [ X(1, 0x2008000UL) ] [ []; []; []; [] ]

  /// C6.2.258 STGP
  [<TestMethod>]
  member _.``C6.2.258 STGP``() =
    check "69000820" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x910a2dec89025cc1UL); M(8, 0xf893a2eefb32555eUL) ]
        [ M(0, 0x975835de1c9756ceUL); M(8, 0x987bbcbfdd7e532fUL) ]
        [ M(8, 0xffffffffffffffffUL) ]
        [ M(0, 0xffffffffUL); M(8, 0x5555555555555555UL) ] ]
    check "68808c22" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL)
          M(0, 0xf893a2eefb32555eUL)
          M(8, 0x71c18690ee42c90bUL) ]
        [ X(1, 0x2008010UL)
          M(0, 0x987bbcbfdd7e532fUL)
          M(8, 0xc3f2827affe7f664UL) ]
        [ X(1, 0x2008010UL)
          M(0, 0xffffffffffffffffUL)
          M(8, 0x8000000000000000UL) ]
        [ X(1, 0x2008010UL) ] ]
    check "69808c22" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL)
          M(0, 0xf893a2eefb32555eUL)
          M(8, 0x71c18690ee42c90bUL) ]
        [ X(1, 0x2008000UL)
          M(0, 0x987bbcbfdd7e532fUL)
          M(8, 0xc3f2827affe7f664UL) ]
        [ X(1, 0x2008000UL)
          M(0, 0xffffffffffffffffUL)
          M(8, 0x8000000000000000UL) ]
        [ X(1, 0x2008000UL) ] ]
    check "69000c22" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xf893a2eefb32555eUL); M(8, 0x71c18690ee42c90bUL) ]
        [ M(0, 0x987bbcbfdd7e532fUL); M(8, 0xc3f2827affe7f664UL) ]
        [ M(0, 0xffffffffffffffffUL); M(8, 0x8000000000000000UL) ]
        [] ]
    check "69008c22" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xf893a2eefb32555eUL); M(8, 0x71c18690ee42c90bUL) ]
        [ M(0, 0x987bbcbfdd7e532fUL); M(8, 0xc3f2827affe7f664UL) ]
        [ M(0, 0xffffffffffffffffUL); M(8, 0x8000000000000000UL) ]
        [] ]
    check "68800420" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x910a2dec89025cc1UL); M(8, 0x2008000UL) ]
        [ M(0, 0x975835de1c9756ceUL); M(8, 0x2008000UL) ]
        [ M(8, 0x2008000UL) ]
        [ M(0, 0xffffffffUL); M(8, 0x2008000UL) ] ]

  /// C6.2.259 STLLRB
  [<TestMethod>]
  member _.``C6.2.259 STLLRB``() =
    check "089f7c20" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4ac1UL) ]
        [ M(0, 0x912f822b1e8fe1ceUL) ]
        []
        [ M(0, 0x55555555555555ffUL) ] ]

  /// C6.2.260 STLLRH
  [<TestMethod>]
  member _.``C6.2.260 STLLRH``() =
    check "489f7c20" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e5cc1UL) ]
        [ M(0, 0x912f822b1e8f56ceUL) ]
        []
        [ M(0, 0x555555555555ffffUL) ] ]

  /// C6.2.261 STLLR
  [<TestMethod>]
  member _.``C6.2.261 STLLR``() =
    check "c89f7c20" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x910a2dec89025cc1UL) ]
        [ M(0, 0x975835de1c9756ceUL) ]
        []
        [ M(0, 0xffffffffUL) ] ]
    check "889f7c20" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290a89025cc1UL) ]
        [ M(0, 0x912f822b1c9756ceUL) ]
        []
        [ M(0, 0x55555555ffffffffUL) ] ]

  /// C6.2.262 STLR
  [<TestMethod>]
  member _.``C6.2.262 STLR``() =
    check "c89ffc20" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x910a2dec89025cc1UL) ]
        [ M(0, 0x975835de1c9756ceUL) ]
        []
        [ M(0, 0xffffffffUL) ] ]
    check "889ffc20" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290a89025cc1UL) ]
        [ M(0, 0x912f822b1c9756ceUL) ]
        []
        [ M(0, 0x55555555ffffffffUL) ] ]

  /// C6.2.263 STLRB
  [<TestMethod>]
  member _.``C6.2.263 STLRB``() =
    check "089ffc20" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4ac1UL) ]
        [ M(0, 0x912f822b1e8fe1ceUL) ]
        []
        [ M(0, 0x55555555555555ffUL) ] ]

  /// C6.2.264 STLRH
  [<TestMethod>]
  member _.``C6.2.264 STLRH``() =
    check "489ffc20" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e5cc1UL) ]
        [ M(0, 0x912f822b1e8f56ceUL) ]
        []
        [ M(0, 0x555555555555ffffUL) ] ]

  /// C6.2.265 STLUR
  [<TestMethod>]
  member _.``C6.2.265 STLUR``() =
    check "d9000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x910a2dec89025cc1UL) ]
        [ M(0, 0x975835de1c9756ceUL) ]
        []
        [ M(0, 0xffffffffUL) ] ]
    check "99010020" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xdb20290a89025cc1UL) ]
        [ M(0, 0x912f822b1c9756ceUL) ]
        []
        [ M(0, 0x55555555ffffffffUL) ] ]
    check "d9010020" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0x910a2dec89025cc1UL) ]
        [ M(0, 0x975835de1c9756ceUL) ]
        []
        [ M(0, 0xffffffffUL) ] ]
    check "99000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290a89025cc1UL) ]
        [ M(0, 0x912f822b1c9756ceUL) ]
        []
        [ M(0, 0x55555555ffffffffUL) ] ]

  /// C6.2.266 STLURB
  [<TestMethod>]
  member _.``C6.2.266 STLURB``() =
    check "19000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4ac1UL) ]
        [ M(0, 0x912f822b1e8fe1ceUL) ]
        []
        [ M(0, 0x55555555555555ffUL) ] ]
    check "19010020" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xdb20290ac13e4ac1UL) ]
        [ M(0, 0x912f822b1e8fe1ceUL) ]
        []
        [ M(0, 0x55555555555555ffUL) ] ]
