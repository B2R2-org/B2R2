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
/// One test for each instruction DDI0487F.c describes, LDADDB to LDUMINAB in
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
type ManualLifterTests2() =
  /// Checks a word over each input set against the places given as the
  /// ones it changes: what the oracle found for a value test, what the
  /// manual says for a structural one.
  let check hex inputs expected =
    let found = A64Machine.mismatches hex inputs expected
    Assert.AreEqual<string>("", String.concat "\n" found, hex)

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

  /// Checks what Auth() fixes about an authenticator over each input set: a
  /// pointer the matching signer signed comes back, and one nothing signed,
  /// or the other key's signer did, fails, leaving the key's error code in
  /// bits 62:61.
  let authenticates aut pac other reg (code: uint64) =
    for k in 0 .. A64Machine.sets - 1 do
      let after hexes = (A64Machine.after hexes [ X(reg, pointer) ] k).Xs
      Assert.AreEqual<uint64>(pointer, (after [ pac; aut ])[reg], aut)
      Assert.AreEqual<uint64>(pointer ||| code, (after [ aut ])[reg], aut)
      Assert.AreEqual<uint64>(pointer ||| code, (after [ other; aut ])[reg])

  /// Checks an authenticated load over each input set: with the window
  /// signed by the given word, it reads the q-th doubleword of the window,
  /// and the base keeps the signed pointer.
  let loadsSigned pac hex (q: int) =
    for k in 0 .. A64Machine.sets - 1 do
      let inputs = [ X(1, A64Machine.window) ]
      let signed = A64Machine.after [ pac ] inputs k
      let loaded = A64Machine.after [ pac; hex ] inputs k
      let mem = (A64Machine.inputSet k).Mem
      Assert.AreEqual<uint64>(mem[q], loaded.Xs[0], hex)
      Assert.AreEqual<uint64>(signed.Xs[1], loaded.Xs[1], hex)

  /// C6.2.98 LDADDB, LDADDAB, LDADDALB, LDADDLB
  [<TestMethod>]
  member _.``C6.2.98 LDADDB``() =
    check "38220020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4adfUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe113UL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL); M(0, 0x55555555555555aaUL) ] ]

  /// C6.2.98 LDADDB, LDADDAB, LDADDALB, LDADDLB
  [<TestMethod>]
  member _.``C6.2.98 LDADDLB``() =
    check "38620020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4adfUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe113UL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL); M(0, 0x55555555555555aaUL) ] ]

  /// C6.2.99 LDADDH, LDADDAH, LDADDALH, LDADDLH
  [<TestMethod>]
  member _.``C6.2.99 LDADDAH``() =
    check "78a20020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e9fdfUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f3513UL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL); M(0, 0x555555555555aaaaUL) ] ]

  /// C6.2.99 LDADDH, LDADDAH, LDADDALH, LDADDLH
  [<TestMethod>]
  member _.``C6.2.99 LDADDALH``() =
    check "78e20020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e9fdfUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f3513UL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL); M(0, 0x555555555555aaaaUL) ] ]

  /// C6.2.99 LDADDH, LDADDAH, LDADDALH, LDADDLH
  [<TestMethod>]
  member _.``C6.2.99 LDADDH``() =
    check "78220020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e9fdfUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f3513UL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL); M(0, 0x555555555555aaaaUL) ] ]

  /// C6.2.99 LDADDH, LDADDAH, LDADDALH, LDADDLH
  [<TestMethod>]
  member _.``C6.2.99 LDADDLH``() =
    check "78620020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e9fdfUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f3513UL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL); M(0, 0x555555555555aaaaUL) ] ]

  /// C6.2.100 LDADD, LDADDA, LDADDAL, LDADDL
  [<TestMethod>]
  member _.``C6.2.100 LDADD``() =
    check "f8220020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL); M(0, 0xd3b3cbf9bc709fdfUL) ]
        [ X(0, 0x912f822b1e8fe1e4UL); M(0, 0x29ab3eeafc0e3513UL) ]
        [ M(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x5555555555555555UL); M(0, 0xaaaaaaaaaaaaaaaaUL) ] ]
    check "b8220020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290abc709fdfUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bfc0e3513UL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL); M(0, 0x55555555aaaaaaaaUL) ] ]

  /// C6.2.100 LDADD, LDADDA, LDADDAL, LDADDL
  [<TestMethod>]
  member _.``C6.2.100 LDADDA``() =
    check "b8a20020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290abc709fdfUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bfc0e3513UL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL); M(0, 0x55555555aaaaaaaaUL) ] ]

  /// C6.2.100 LDADD, LDADDA, LDADDAL, LDADDL
  [<TestMethod>]
  member _.``C6.2.100 LDADDAL``() =
    check "b8e20020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290abc709fdfUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bfc0e3513UL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL); M(0, 0x55555555aaaaaaaaUL) ] ]

  /// C6.2.100 LDADD, LDADDA, LDADDAL, LDADDL
  [<TestMethod>]
  member _.``C6.2.100 LDADDL``() =
    check "b8620020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290abc709fdfUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bfc0e3513UL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL); M(0, 0x55555555aaaaaaaaUL) ] ]

  /// C6.2.101 LDAPR
  [<TestMethod>]
  member _.``C6.2.101 LDAPR``() =
    check "f8bfc020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "b8bfc020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.102 LDAPRB
  [<TestMethod>]
  member _.``C6.2.102 LDAPRB``() =
    check "38bfc020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.103 LDAPRH
  [<TestMethod>]
  member _.``C6.2.103 LDAPRH``() =
    check "78bfc020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.104 LDAPUR
  [<TestMethod>]
  member _.``C6.2.104 LDAPUR``() =
    check "d9400020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "99410020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "d9410020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "99400020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.105 LDAPURB
  [<TestMethod>]
  member _.``C6.2.105 LDAPURB``() =
    check "19400020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "19410020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.106 LDAPURH
  [<TestMethod>]
  member _.``C6.2.106 LDAPURH``() =
    check "59400020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "59410020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.107 LDAPURSB
  [<TestMethod>]
  member _.``C6.2.107 LDAPURSB``() =
    check "19800020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffffffffffff81UL) ]
        [ X(0, 0xffffffffffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "19c10020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xffffff81UL) ]
        [ X(0, 0xffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "19810020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xffffffffffffff81UL) ]
        [ X(0, 0xffffffffffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "19c00020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffff81UL) ]
        [ X(0, 0xffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.108 LDAPURSH
  [<TestMethod>]
  member _.``C6.2.108 LDAPURSH``() =
    check "59800020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffffffffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "59c10020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "59810020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffffffffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "59c00020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.109 LDAPURSW
  [<TestMethod>]
  member _.``C6.2.109 LDAPURSW``() =
    check "99800020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffffffc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "99810020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xffffffffc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.110 LDAR
  [<TestMethod>]
  member _.``C6.2.110 LDAR``() =
    check "c8dffc20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "88dffc20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.111 LDARB
  [<TestMethod>]
  member _.``C6.2.111 LDARB``() =
    check "08dffc20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.112 LDARH
  [<TestMethod>]
  member _.``C6.2.112 LDARH``() =
    check "48dffc20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.113 LDAXP
  [<TestMethod>]
  member _.``C6.2.113 LDAXP``() =
    check "887f8022" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290aUL); X(2, 0xc13e4a81UL) ]
        [ X(0, 0x912f822bUL); X(2, 0x1e8fe1e4UL) ]
        [ X(2, 0x0UL) ]
        [ X(0, 0x55555555UL); X(2, 0x55555555UL) ] ]

  /// C6.2.114 LDAXR
  [<TestMethod>]
  member _.``C6.2.114 LDAXR``() =
    check "885ffc20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.115 LDAXRB
  [<TestMethod>]
  member _.``C6.2.115 LDAXRB``() =
    check "085ffc20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.116 LDAXRH
  [<TestMethod>]
  member _.``C6.2.116 LDAXRH``() =
    check "485ffc20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.117 LDCLRB, LDCLRAB, LDCLRALB, LDCLRLB
  [<TestMethod>]
  member _.``C6.2.117 LDCLRAB``() =
    check "38a21020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe1c0UL) ]
        []
        [ X(0, 0x55UL); M(0, 0x5555555555555500UL) ] ]

  /// C6.2.117 LDCLRB, LDCLRAB, LDCLRALB, LDCLRLB
  [<TestMethod>]
  member _.``C6.2.117 LDCLRALB``() =
    check "38e21020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe1c0UL) ]
        []
        [ X(0, 0x55UL); M(0, 0x5555555555555500UL) ] ]

  /// C6.2.117 LDCLRB, LDCLRAB, LDCLRALB, LDCLRLB
  [<TestMethod>]
  member _.``C6.2.117 LDCLRB``() =
    check "38221020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe1c0UL) ]
        []
        [ X(0, 0x55UL); M(0, 0x5555555555555500UL) ] ]

  /// C6.2.117 LDCLRB, LDCLRAB, LDCLRALB, LDCLRLB
  [<TestMethod>]
  member _.``C6.2.117 LDCLRLB``() =
    check "38621020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe1c0UL) ]
        []
        [ X(0, 0x55UL); M(0, 0x5555555555555500UL) ] ]

  /// C6.2.118 LDCLRH, LDCLRAH, LDCLRALH, LDCLRLH
  [<TestMethod>]
  member _.``C6.2.118 LDCLRAH``() =
    check "78a21020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e0a81UL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8fa0c0UL) ]
        []
        [ X(0, 0x5555UL); M(0, 0x5555555555550000UL) ] ]

  /// C6.2.118 LDCLRH, LDCLRAH, LDCLRALH, LDCLRLH
  [<TestMethod>]
  member _.``C6.2.118 LDCLRALH``() =
    check "78e21020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e0a81UL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8fa0c0UL) ]
        []
        [ X(0, 0x5555UL); M(0, 0x5555555555550000UL) ] ]

  /// C6.2.118 LDCLRH, LDCLRAH, LDCLRALH, LDCLRLH
  [<TestMethod>]
  member _.``C6.2.118 LDCLRH``() =
    check "78221020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e0a81UL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8fa0c0UL) ]
        []
        [ X(0, 0x5555UL); M(0, 0x5555555555550000UL) ] ]

  /// C6.2.118 LDCLRH, LDCLRAH, LDCLRALH, LDCLRLH
  [<TestMethod>]
  member _.``C6.2.118 LDCLRLH``() =
    check "78621020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e0a81UL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8fa0c0UL) ]
        []
        [ X(0, 0x5555UL); M(0, 0x5555555555550000UL) ] ]

  /// C6.2.119 LDCLR, LDCLRA, LDCLRAL, LDCLRL
  [<TestMethod>]
  member _.``C6.2.119 LDCLR``() =
    check "f8221020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL); M(0, 0x3200900000c0a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL); M(0, 0x10402000281a0c0UL) ]
        []
        [ X(0, 0x5555555555555555UL); M(0, 0x0UL) ] ]
    check "b8221020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290a000c0a81UL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822b0281a0c0UL) ]
        []
        [ X(0, 0x55555555UL); M(0, 0x5555555500000000UL) ] ]

  /// C6.2.119 LDCLR, LDCLRA, LDCLRAL, LDCLRL
  [<TestMethod>]
  member _.``C6.2.119 LDCLRA``() =
    check "b8a21020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290a000c0a81UL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822b0281a0c0UL) ]
        []
        [ X(0, 0x55555555UL); M(0, 0x5555555500000000UL) ] ]

  /// C6.2.119 LDCLR, LDCLRA, LDCLRAL, LDCLRL
  [<TestMethod>]
  member _.``C6.2.119 LDCLRAL``() =
    check "b8e21020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290a000c0a81UL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822b0281a0c0UL) ]
        []
        [ X(0, 0x55555555UL); M(0, 0x5555555500000000UL) ] ]

  /// C6.2.119 LDCLR, LDCLRA, LDCLRAL, LDCLRL
  [<TestMethod>]
  member _.``C6.2.119 LDCLRL``() =
    check "b8621020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290a000c0a81UL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822b0281a0c0UL) ]
        []
        [ X(0, 0x55555555UL); M(0, 0x5555555500000000UL) ] ]

  /// C6.2.120 LDEORB, LDEORAB, LDEORALB, LDEORLB
  [<TestMethod>]
  member _.``C6.2.120 LDEORAB``() =
    check "38a22020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4adfUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe1cbUL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL); M(0, 0x5555555555555500UL) ] ]

  /// C6.2.120 LDEORB, LDEORAB, LDEORALB, LDEORLB
  [<TestMethod>]
  member _.``C6.2.120 LDEORALB``() =
    check "38e22020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4adfUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe1cbUL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL); M(0, 0x5555555555555500UL) ] ]

  /// C6.2.120 LDEORB, LDEORAB, LDEORALB, LDEORLB
  [<TestMethod>]
  member _.``C6.2.120 LDEORB``() =
    check "38222020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4adfUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe1cbUL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL); M(0, 0x5555555555555500UL) ] ]

  /// C6.2.120 LDEORB, LDEORAB, LDEORALB, LDEORLB
  [<TestMethod>]
  member _.``C6.2.120 LDEORLB``() =
    check "38622020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4adfUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe1cbUL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL); M(0, 0x5555555555555500UL) ] ]

  /// C6.2.121 LDEORH, LDEORAH, LDEORALH, LDEORLH
  [<TestMethod>]
  member _.``C6.2.121 LDEORAH``() =
    check "78a22020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e1fdfUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8fb2cbUL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL); M(0, 0x5555555555550000UL) ] ]

  /// C6.2.121 LDEORH, LDEORAH, LDEORALH, LDEORLH
  [<TestMethod>]
  member _.``C6.2.121 LDEORALH``() =
    check "78e22020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e1fdfUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8fb2cbUL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL); M(0, 0x5555555555550000UL) ] ]

  /// C6.2.121 LDEORH, LDEORAH, LDEORALH, LDEORLH
  [<TestMethod>]
  member _.``C6.2.121 LDEORH``() =
    check "78222020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e1fdfUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8fb2cbUL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL); M(0, 0x5555555555550000UL) ] ]

  /// C6.2.121 LDEORH, LDEORAH, LDEORALH, LDEORLH
  [<TestMethod>]
  member _.``C6.2.121 LDEORLH``() =
    check "78622020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e1fdfUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8fb2cbUL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL); M(0, 0x5555555555550000UL) ] ]

  /// C6.2.122 LDEOR, LDEORA, LDEORAL, LDEORL
  [<TestMethod>]
  member _.``C6.2.122 LDEOR``() =
    check "f8222020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL); M(0, 0x23b38be43a0c1fdfUL) ]
        [ X(0, 0x912f822b1e8fe1e4UL); M(0, 0x9543e94c3f1b2cbUL) ]
        [ M(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x5555555555555555UL); M(0, 0x0UL) ] ]
    check "b8222020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290a3a0c1fdfUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bc3f1b2cbUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL); M(0, 0x5555555500000000UL) ] ]

  /// C6.2.122 LDEOR, LDEORA, LDEORAL, LDEORL
  [<TestMethod>]
  member _.``C6.2.122 LDEORA``() =
    check "b8a22020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290a3a0c1fdfUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bc3f1b2cbUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL); M(0, 0x5555555500000000UL) ] ]

  /// C6.2.122 LDEOR, LDEORA, LDEORAL, LDEORL
  [<TestMethod>]
  member _.``C6.2.122 LDEORAL``() =
    check "b8e22020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290a3a0c1fdfUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bc3f1b2cbUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL); M(0, 0x5555555500000000UL) ] ]

  /// C6.2.122 LDEOR, LDEORA, LDEORAL, LDEORL
  [<TestMethod>]
  member _.``C6.2.122 LDEORL``() =
    check "b8622020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290a3a0c1fdfUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bc3f1b2cbUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL); M(0, 0x5555555500000000UL) ] ]

  /// C6.2.123 LDG
  [<TestMethod>]
  member _.``C6.2.123 LDG``() =
    check "d9600020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x900a2dec89025cc1UL) ]
        [ X(0, 0x905835de1c9756ceUL) ]
        []
        [] ]
    check "d9601020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x900a2dec89025cc1UL) ]
        [ X(0, 0x905835de1c9756ceUL) ]
        []
        [] ]

  /// C6.2.125 LDLARB
  [<TestMethod>]
  member _.``C6.2.125 LDLARB``() =
    check "08df7c20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.126 LDLARH
  [<TestMethod>]
  member _.``C6.2.126 LDLARH``() =
    check "48df7c20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.127 LDLAR
  [<TestMethod>]
  member _.``C6.2.127 LDLAR``() =
    check "c8df7c20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "88df7c20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.128 LDNP
  [<TestMethod>]
  member _.``C6.2.128 LDNP``() =
    check "28400c22" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xc13e4a81UL); X(3, 0xdb20290aUL) ]
        [ X(2, 0x1e8fe1e4UL); X(3, 0x912f822bUL) ]
        [ X(2, 0x0UL); X(3, 0x0UL) ]
        [ X(2, 0x55555555UL); X(3, 0x55555555UL) ] ]
    check "28420c22" [ X(1, 0x2007ff0UL) ]
      [ [ X(2, 0xc13e4a81UL); X(3, 0xdb20290aUL) ]
        [ X(2, 0x1e8fe1e4UL); X(3, 0x912f822bUL) ]
        [ X(2, 0x0UL); X(3, 0x0UL) ]
        [ X(2, 0x55555555UL); X(3, 0x55555555UL) ] ]
    check "a8400c22" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL); X(3, 0xd80391ffb30d1390UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL); X(3, 0xf8606cc314fb6b96UL) ]
        [ X(2, 0x0UL); X(3, 0x1UL) ]
        [] ]
    check "a8410c22" [ X(1, 0x2007ff0UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL); X(3, 0xd80391ffb30d1390UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL); X(3, 0xf8606cc314fb6b96UL) ]
        [ X(2, 0x0UL); X(3, 0x1UL) ]
        [] ]
    check "28400420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); X(1, 0xdb20290aUL) ]
        [ X(0, 0x1e8fe1e4UL); X(1, 0x912f822bUL) ]
        [ X(1, 0x0UL) ]
        [ X(0, 0x55555555UL); X(1, 0x55555555UL) ] ]

  /// C6.2.129 LDP
  [<TestMethod>]
  member _.``C6.2.129 LDP``() =
    check "28c20c22" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL); X(2, 0xc13e4a81UL); X(3, 0xdb20290aUL) ]
        [ X(1, 0x2008010UL); X(2, 0x1e8fe1e4UL); X(3, 0x912f822bUL) ]
        [ X(1, 0x2008010UL); X(2, 0x0UL); X(3, 0x0UL) ]
        [ X(1, 0x2008010UL); X(2, 0x55555555UL); X(3, 0x55555555UL) ] ]
    check "a8c10c22" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL)
          X(2, 0xdb20290ac13e4a81UL)
          X(3, 0xd80391ffb30d1390UL) ]
        [ X(1, 0x2008010UL)
          X(2, 0x912f822b1e8fe1e4UL)
          X(3, 0xf8606cc314fb6b96UL) ]
        [ X(1, 0x2008010UL); X(2, 0x0UL); X(3, 0x1UL) ]
        [ X(1, 0x2008010UL) ] ]
    check "29c20c22" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL); X(2, 0xc13e4a81UL); X(3, 0xdb20290aUL) ]
        [ X(1, 0x2008000UL); X(2, 0x1e8fe1e4UL); X(3, 0x912f822bUL) ]
        [ X(1, 0x2008000UL); X(2, 0x0UL); X(3, 0x0UL) ]
        [ X(1, 0x2008000UL); X(2, 0x55555555UL); X(3, 0x55555555UL) ] ]
    check "a9c10c22" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL)
          X(2, 0xdb20290ac13e4a81UL)
          X(3, 0xd80391ffb30d1390UL) ]
        [ X(1, 0x2008000UL)
          X(2, 0x912f822b1e8fe1e4UL)
          X(3, 0xf8606cc314fb6b96UL) ]
        [ X(1, 0x2008000UL); X(2, 0x0UL); X(3, 0x1UL) ]
        [ X(1, 0x2008000UL) ] ]
    check "29400c22" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xc13e4a81UL); X(3, 0xdb20290aUL) ]
        [ X(2, 0x1e8fe1e4UL); X(3, 0x912f822bUL) ]
        [ X(2, 0x0UL); X(3, 0x0UL) ]
        [ X(2, 0x55555555UL); X(3, 0x55555555UL) ] ]
    check "29420c22" [ X(1, 0x2007ff0UL) ]
      [ [ X(2, 0xc13e4a81UL); X(3, 0xdb20290aUL) ]
        [ X(2, 0x1e8fe1e4UL); X(3, 0x912f822bUL) ]
        [ X(2, 0x0UL); X(3, 0x0UL) ]
        [ X(2, 0x55555555UL); X(3, 0x55555555UL) ] ]
    check "a9400c22" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL); X(3, 0xd80391ffb30d1390UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL); X(3, 0xf8606cc314fb6b96UL) ]
        [ X(2, 0x0UL); X(3, 0x1UL) ]
        [] ]
    check "a9410c22" [ X(1, 0x2007ff0UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL); X(3, 0xd80391ffb30d1390UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL); X(3, 0xf8606cc314fb6b96UL) ]
        [ X(2, 0x0UL); X(3, 0x1UL) ]
        [] ]
    check "28c00420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.130 LDPSW
  [<TestMethod>]
  member _.``C6.2.130 LDPSW``() =
    check "68c20c22" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL)
          X(2, 0xffffffffc13e4a81UL)
          X(3, 0xffffffffdb20290aUL) ]
        [ X(1, 0x2008010UL); X(2, 0x1e8fe1e4UL); X(3, 0xffffffff912f822bUL) ]
        [ X(1, 0x2008010UL); X(2, 0x0UL); X(3, 0x0UL) ]
        [ X(1, 0x2008010UL); X(2, 0x55555555UL); X(3, 0x55555555UL) ] ]
    check "69c20c22" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL)
          X(2, 0xffffffffc13e4a81UL)
          X(3, 0xffffffffdb20290aUL) ]
        [ X(1, 0x2008000UL); X(2, 0x1e8fe1e4UL); X(3, 0xffffffff912f822bUL) ]
        [ X(1, 0x2008000UL); X(2, 0x0UL); X(3, 0x0UL) ]
        [ X(1, 0x2008000UL); X(2, 0x55555555UL); X(3, 0x55555555UL) ] ]
    check "69400c22" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xffffffffc13e4a81UL); X(3, 0xffffffffdb20290aUL) ]
        [ X(2, 0x1e8fe1e4UL); X(3, 0xffffffff912f822bUL) ]
        [ X(2, 0x0UL); X(3, 0x0UL) ]
        [ X(2, 0x55555555UL); X(3, 0x55555555UL) ] ]
    check "69420c22" [ X(1, 0x2007ff0UL) ]
      [ [ X(2, 0xffffffffc13e4a81UL); X(3, 0xffffffffdb20290aUL) ]
        [ X(2, 0x1e8fe1e4UL); X(3, 0xffffffff912f822bUL) ]
        [ X(2, 0x0UL); X(3, 0x0UL) ]
        [ X(2, 0x55555555UL); X(3, 0x55555555UL) ] ]
    check "68c10c22" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008008UL)
          X(2, 0xffffffffc13e4a81UL)
          X(3, 0xffffffffdb20290aUL) ]
        [ X(1, 0x2008008UL); X(2, 0x1e8fe1e4UL); X(3, 0xffffffff912f822bUL) ]
        [ X(1, 0x2008008UL); X(2, 0x0UL); X(3, 0x0UL) ]
        [ X(1, 0x2008008UL); X(2, 0x55555555UL); X(3, 0x55555555UL) ] ]

  /// C6.2.131 LDR (immediate)
  [<TestMethod>]
  member _.``C6.2.131 LDR``() =
    check "b8410420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); X(1, 0x2008010UL) ]
        [ X(0, 0x1e8fe1e4UL); X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(0, 0x55555555UL); X(1, 0x2008010UL) ] ]
    check "f8410420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL); X(1, 0x2008010UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL); X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(0, 0x5555555555555555UL); X(1, 0x2008010UL) ] ]
    check "b8410c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xc13e4a81UL); X(1, 0x2008000UL) ]
        [ X(0, 0x1e8fe1e4UL); X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(0, 0x55555555UL); X(1, 0x2008000UL) ] ]
    check "f8410c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL); X(1, 0x2008000UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL); X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(0, 0x5555555555555555UL); X(1, 0x2008000UL) ] ]
    check "b9400020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "b9400820" [ X(1, 0x2007ff8UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "f9400020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "f9400420" [ X(1, 0x2007ff8UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "18000200" [ Window 0x1000040UL ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "58000200" [ Window 0x1000040UL ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "b8400420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// <summary>
  /// LDRAA authenticates its base with a key the oracle's process draws
  /// at random, so the base must be signed first, and a signed value
  /// cannot be compared. What the manual fixes is checked instead
  /// (C6.2.134): with the window signed as the matching PACDZA signs it,
  /// the load reads the doubleword at the window plus the offset, and the
  /// base keeps the signed pointer, over every input set. The oracle
  /// agrees with the value loaded. The pre-indexed forms, which write
  /// the authenticated address back, are left out: this front end does
  /// not write it back.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.134 LDRAA``() =
    loadsSigned "dac12be1" "f8200420" 0
    loadsSigned "dac12be1" "f8202420" 2

  /// <summary>
  /// LDRAB authenticates its base with a key the oracle's process draws
  /// at random, so the base must be signed first, and a signed value
  /// cannot be compared. What the manual fixes is checked instead
  /// (C6.2.134): with the window signed as the matching PACDZB signs it,
  /// the load reads the doubleword at the window plus the offset, and the
  /// base keeps the signed pointer, over every input set. The oracle
  /// agrees with the value loaded. The pre-indexed forms, which write
  /// the authenticated address back, are left out: this front end does
  /// not write it back.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.134 LDRAB``() =
    loadsSigned "dac12fe1" "f8a00420" 0

  /// C6.2.135 LDRB (immediate)
  [<TestMethod>]
  member _.``C6.2.135 LDRB``() =
    check "38410420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); X(1, 0x2008010UL) ]
        [ X(0, 0xe4UL); X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(0, 0x55UL); X(1, 0x2008010UL) ] ]
    check "38410c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x81UL); X(1, 0x2008000UL) ]
        [ X(0, 0xe4UL); X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(0, 0x55UL); X(1, 0x2008000UL) ] ]
    check "39400020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "39402020" [ X(1, 0x2007ff8UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38626820" [ X(1, 0x2008000UL); X(2, 0x1UL) ]
      [ [ X(0, 0x4aUL) ]
        [ X(0, 0xe1UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38400420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.137 LDRH (immediate)
  [<TestMethod>]
  member _.``C6.2.137 LDRH``() =
    check "78410420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); X(1, 0x2008010UL) ]
        [ X(0, 0xe1e4UL); X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(0, 0x5555UL); X(1, 0x2008010UL) ] ]
    check "78410c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x4a81UL); X(1, 0x2008000UL) ]
        [ X(0, 0xe1e4UL); X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(0, 0x5555UL); X(1, 0x2008000UL) ] ]
    check "79400020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "79401020" [ X(1, 0x2007ff8UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "78400420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.139 LDRSB (immediate)
  [<TestMethod>]
  member _.``C6.2.139 LDRSB``() =
    check "38c10420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffff81UL); X(1, 0x2008010UL) ]
        [ X(0, 0xffffffe4UL); X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(0, 0x55UL); X(1, 0x2008010UL) ] ]
    check "38810420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffffffffffff81UL); X(1, 0x2008010UL) ]
        [ X(0, 0xffffffffffffffe4UL); X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(0, 0x55UL); X(1, 0x2008010UL) ] ]
    check "38c10c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xffffff81UL); X(1, 0x2008000UL) ]
        [ X(0, 0xffffffe4UL); X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(0, 0x55UL); X(1, 0x2008000UL) ] ]
    check "38810c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xffffffffffffff81UL); X(1, 0x2008000UL) ]
        [ X(0, 0xffffffffffffffe4UL); X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(0, 0x55UL); X(1, 0x2008000UL) ] ]
    check "39c00020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffff81UL) ]
        [ X(0, 0xffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "39c02020" [ X(1, 0x2007ff8UL) ]
      [ [ X(0, 0xffffff81UL) ]
        [ X(0, 0xffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "39800020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffffffffffff81UL) ]
        [ X(0, 0xffffffffffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "39802020" [ X(1, 0x2007ff8UL) ]
      [ [ X(0, 0xffffffffffffff81UL) ]
        [ X(0, 0xffffffffffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38e26820" [ X(1, 0x2008000UL); X(2, 0x1UL) ]
      [ [ X(0, 0x4aUL) ]
        [ X(0, 0xffffffe1UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38a26820" [ X(1, 0x2008000UL); X(2, 0x1UL) ]
      [ [ X(0, 0x4aUL) ]
        [ X(0, 0xffffffffffffffe1UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38c00420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffff81UL) ]
        [ X(0, 0xffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.141 LDRSH (immediate)
  [<TestMethod>]
  member _.``C6.2.141 LDRSH``() =
    check "78c10420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); X(1, 0x2008010UL) ]
        [ X(0, 0xffffe1e4UL); X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(0, 0x5555UL); X(1, 0x2008010UL) ] ]
    check "78810420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); X(1, 0x2008010UL) ]
        [ X(0, 0xffffffffffffe1e4UL); X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(0, 0x5555UL); X(1, 0x2008010UL) ] ]
    check "78c10c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x4a81UL); X(1, 0x2008000UL) ]
        [ X(0, 0xffffe1e4UL); X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(0, 0x5555UL); X(1, 0x2008000UL) ] ]
    check "78810c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x4a81UL); X(1, 0x2008000UL) ]
        [ X(0, 0xffffffffffffe1e4UL); X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(0, 0x5555UL); X(1, 0x2008000UL) ] ]
    check "79c00020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "79c01020" [ X(1, 0x2007ff8UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "79800020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffffffffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "79801020" [ X(1, 0x2007ff8UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffffffffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "78c00420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.143 LDRSW (immediate)
  [<TestMethod>]
  member _.``C6.2.143 LDRSW``() =
    check "b8810420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffffffc13e4a81UL); X(1, 0x2008010UL) ]
        [ X(0, 0x1e8fe1e4UL); X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(0, 0x55555555UL); X(1, 0x2008010UL) ] ]
    check "b8810c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xffffffffc13e4a81UL); X(1, 0x2008000UL) ]
        [ X(0, 0x1e8fe1e4UL); X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(0, 0x55555555UL); X(1, 0x2008000UL) ] ]
    check "b9800020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffffffc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "b9800820" [ X(1, 0x2007ff8UL) ]
      [ [ X(0, 0xffffffffc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "98000200" [ Window 0x1000040UL ]
      [ [ X(0, 0xffffffffc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "b8800420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffffffc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.146 LDSETB, LDSETAB, LDSETALB, LDSETLB
  [<TestMethod>]
  member _.``C6.2.146 LDSETAB``() =
    check "38a23020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4adfUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe1efUL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.146 LDSETB, LDSETAB, LDSETALB, LDSETLB
  [<TestMethod>]
  member _.``C6.2.146 LDSETALB``() =
    check "38e23020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4adfUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe1efUL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.146 LDSETB, LDSETAB, LDSETALB, LDSETLB
  [<TestMethod>]
  member _.``C6.2.146 LDSETB``() =
    check "38223020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4adfUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe1efUL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.146 LDSETB, LDSETAB, LDSETALB, LDSETLB
  [<TestMethod>]
  member _.``C6.2.146 LDSETLB``() =
    check "38623020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4adfUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe1efUL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.147 LDSETH, LDSETAH, LDSETALH, LDSETLH
  [<TestMethod>]
  member _.``C6.2.147 LDSETAH``() =
    check "78a23020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e5fdfUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8ff3efUL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.147 LDSETH, LDSETAH, LDSETALH, LDSETLH
  [<TestMethod>]
  member _.``C6.2.147 LDSETALH``() =
    check "78e23020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e5fdfUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8ff3efUL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.147 LDSETH, LDSETAH, LDSETALH, LDSETLH
  [<TestMethod>]
  member _.``C6.2.147 LDSETH``() =
    check "78223020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e5fdfUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8ff3efUL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.147 LDSETH, LDSETAH, LDSETALH, LDSETLH
  [<TestMethod>]
  member _.``C6.2.147 LDSETLH``() =
    check "78623020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e5fdfUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8ff3efUL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.148 LDSET, LDSETA, LDSETAL, LDSETL
  [<TestMethod>]
  member _.``C6.2.148 LDSET``() =
    check "f8223020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL); M(0, 0xfbb3abeefb3e5fdfUL) ]
        [ X(0, 0x912f822b1e8fe1e4UL); M(0, 0x997fbebfdffff3efUL) ]
        [ M(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x5555555555555555UL) ] ]
    check "b8223020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb3e5fdfUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdffff3efUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.148 LDSET, LDSETA, LDSETAL, LDSETL
  [<TestMethod>]
  member _.``C6.2.148 LDSETA``() =
    check "b8a23020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb3e5fdfUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdffff3efUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.148 LDSET, LDSETA, LDSETAL, LDSETL
  [<TestMethod>]
  member _.``C6.2.148 LDSETAL``() =
    check "b8e23020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb3e5fdfUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdffff3efUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.148 LDSET, LDSETA, LDSETAL, LDSETL
  [<TestMethod>]
  member _.``C6.2.148 LDSETL``() =
    check "b8623020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb3e5fdfUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdffff3efUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.149 LDSMAXB, LDSMAXAB, LDSMAXALB, LDSMAXLB
  [<TestMethod>]
  member _.``C6.2.149 LDSMAXAB``() =
    check "38a24020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4a5eUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe12fUL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.149 LDSMAXB, LDSMAXAB, LDSMAXALB, LDSMAXLB
  [<TestMethod>]
  member _.``C6.2.149 LDSMAXALB``() =
    check "38e24020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4a5eUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe12fUL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.149 LDSMAXB, LDSMAXAB, LDSMAXALB, LDSMAXLB
  [<TestMethod>]
  member _.``C6.2.149 LDSMAXB``() =
    check "38224020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4a5eUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe12fUL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.149 LDSMAXB, LDSMAXAB, LDSMAXALB, LDSMAXLB
  [<TestMethod>]
  member _.``C6.2.149 LDSMAXLB``() =
    check "38624020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4a5eUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe12fUL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.150 LDSMAXH, LDSMAXAH, LDSMAXALH, LDSMAXLH
  [<TestMethod>]
  member _.``C6.2.150 LDSMAXAH``() =
    check "78a24020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e555eUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f532fUL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.150 LDSMAXH, LDSMAXAH, LDSMAXALH, LDSMAXLH
  [<TestMethod>]
  member _.``C6.2.150 LDSMAXALH``() =
    check "78e24020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e555eUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f532fUL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.150 LDSMAXH, LDSMAXAH, LDSMAXALH, LDSMAXLH
  [<TestMethod>]
  member _.``C6.2.150 LDSMAXH``() =
    check "78224020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e555eUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f532fUL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.150 LDSMAXH, LDSMAXAH, LDSMAXALH, LDSMAXLH
  [<TestMethod>]
  member _.``C6.2.150 LDSMAXLH``() =
    check "78624020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e555eUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f532fUL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.151 LDSMAX, LDSMAXA, LDSMAXAL, LDSMAXL
  [<TestMethod>]
  member _.``C6.2.151 LDSMAX``() =
    check "f8224020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL); M(0, 0xf893a2eefb32555eUL) ]
        [ X(0, 0x912f822b1e8fe1e4UL); M(0, 0x987bbcbfdd7e532fUL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "b8224020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb32555eUL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.151 LDSMAX, LDSMAXA, LDSMAXAL, LDSMAXL
  [<TestMethod>]
  member _.``C6.2.151 LDSMAXA``() =
    check "b8a24020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb32555eUL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.151 LDSMAX, LDSMAXA, LDSMAXAL, LDSMAXL
  [<TestMethod>]
  member _.``C6.2.151 LDSMAXAL``() =
    check "b8e24020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb32555eUL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.151 LDSMAX, LDSMAXA, LDSMAXAL, LDSMAXL
  [<TestMethod>]
  member _.``C6.2.151 LDSMAXL``() =
    check "b8624020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb32555eUL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.152 LDSMINB, LDSMINAB, LDSMINALB, LDSMINLB
  [<TestMethod>]
  member _.``C6.2.152 LDSMINAB``() =
    check "38a25020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.152 LDSMINB, LDSMINAB, LDSMINALB, LDSMINLB
  [<TestMethod>]
  member _.``C6.2.152 LDSMINALB``() =
    check "38e25020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.152 LDSMINB, LDSMINAB, LDSMINALB, LDSMINLB
  [<TestMethod>]
  member _.``C6.2.152 LDSMINB``() =
    check "38225020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.152 LDSMINB, LDSMINAB, LDSMINALB, LDSMINLB
  [<TestMethod>]
  member _.``C6.2.152 LDSMINLB``() =
    check "38625020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.153 LDSMINH, LDSMINAH, LDSMINALH, LDSMINLH
  [<TestMethod>]
  member _.``C6.2.153 LDSMINAH``() =
    check "78a25020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.153 LDSMINH, LDSMINAH, LDSMINALH, LDSMINLH
  [<TestMethod>]
  member _.``C6.2.153 LDSMINALH``() =
    check "78e25020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.153 LDSMINH, LDSMINAH, LDSMINALH, LDSMINLH
  [<TestMethod>]
  member _.``C6.2.153 LDSMINH``() =
    check "78225020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.153 LDSMINH, LDSMINAH, LDSMINALH, LDSMINLH
  [<TestMethod>]
  member _.``C6.2.153 LDSMINLH``() =
    check "78625020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.154 LDSMIN, LDSMINA, LDSMINAL, LDSMINL
  [<TestMethod>]
  member _.``C6.2.154 LDSMIN``() =
    check "f8225020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        [ M(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x5555555555555555UL) ] ]
    check "b8225020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.154 LDSMIN, LDSMINA, LDSMINAL, LDSMINL
  [<TestMethod>]
  member _.``C6.2.154 LDSMINA``() =
    check "b8a25020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.154 LDSMIN, LDSMINA, LDSMINAL, LDSMINL
  [<TestMethod>]
  member _.``C6.2.154 LDSMINAL``() =
    check "b8e25020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.154 LDSMIN, LDSMINA, LDSMINAL, LDSMINL
  [<TestMethod>]
  member _.``C6.2.154 LDSMINL``() =
    check "b8625020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.155 LDTR
  [<TestMethod>]
  member _.``C6.2.155 LDTR``() =
    check "b8410820" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "f8400820" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "f8410820" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "b8400820" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.156 LDTRB
  [<TestMethod>]
  member _.``C6.2.156 LDTRB``() =
    check "38410820" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38400820" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.157 LDTRH
  [<TestMethod>]
  member _.``C6.2.157 LDTRH``() =
    check "78410820" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "78400820" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.158 LDTRSB
  [<TestMethod>]
  member _.``C6.2.158 LDTRSB``() =
    check "38c10820" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xffffff81UL) ]
        [ X(0, 0xffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38800820" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffffffffffff81UL) ]
        [ X(0, 0xffffffffffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38810820" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xffffffffffffff81UL) ]
        [ X(0, 0xffffffffffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38c00820" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffff81UL) ]
        [ X(0, 0xffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.159 LDTRSH
  [<TestMethod>]
  member _.``C6.2.159 LDTRSH``() =
    check "78c10820" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "78800820" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffffffffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "78810820" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffffffffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "78c00820" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.160 LDTRSW
  [<TestMethod>]
  member _.``C6.2.160 LDTRSW``() =
    check "b8810820" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xffffffffc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "b8800820" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffffffc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.161 LDUMAXB, LDUMAXAB, LDUMAXALB, LDUMAXLB
  [<TestMethod>]
  member _.``C6.2.161 LDUMAXAB``() =
    check "38a26020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.161 LDUMAXB, LDUMAXAB, LDUMAXALB, LDUMAXLB
  [<TestMethod>]
  member _.``C6.2.161 LDUMAXALB``() =
    check "38e26020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.161 LDUMAXB, LDUMAXAB, LDUMAXALB, LDUMAXLB
  [<TestMethod>]
  member _.``C6.2.161 LDUMAXB``() =
    check "38226020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.161 LDUMAXB, LDUMAXAB, LDUMAXALB, LDUMAXLB
  [<TestMethod>]
  member _.``C6.2.161 LDUMAXLB``() =
    check "38626020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.162 LDUMAXH, LDUMAXAH, LDUMAXALH, LDUMAXLH
  [<TestMethod>]
  member _.``C6.2.162 LDUMAXAH``() =
    check "78a26020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e555eUL) ]
        [ X(0, 0xe1e4UL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.162 LDUMAXH, LDUMAXAH, LDUMAXALH, LDUMAXLH
  [<TestMethod>]
  member _.``C6.2.162 LDUMAXALH``() =
    check "78e26020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e555eUL) ]
        [ X(0, 0xe1e4UL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.162 LDUMAXH, LDUMAXAH, LDUMAXALH, LDUMAXLH
  [<TestMethod>]
  member _.``C6.2.162 LDUMAXH``() =
    check "78226020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e555eUL) ]
        [ X(0, 0xe1e4UL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.162 LDUMAXH, LDUMAXAH, LDUMAXALH, LDUMAXLH
  [<TestMethod>]
  member _.``C6.2.162 LDUMAXLH``() =
    check "78626020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e555eUL) ]
        [ X(0, 0xe1e4UL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.163 LDUMAX, LDUMAXA, LDUMAXAL, LDUMAXL
  [<TestMethod>]
  member _.``C6.2.163 LDUMAX``() =
    check "f8226020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL); M(0, 0xf893a2eefb32555eUL) ]
        [ X(0, 0x912f822b1e8fe1e4UL); M(0, 0x987bbcbfdd7e532fUL) ]
        [ M(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x5555555555555555UL) ] ]
    check "b8226020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb32555eUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.163 LDUMAX, LDUMAXA, LDUMAXAL, LDUMAXL
  [<TestMethod>]
  member _.``C6.2.163 LDUMAXA``() =
    check "b8a26020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb32555eUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.163 LDUMAX, LDUMAXA, LDUMAXAL, LDUMAXL
  [<TestMethod>]
  member _.``C6.2.163 LDUMAXAL``() =
    check "b8e26020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb32555eUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.163 LDUMAX, LDUMAXA, LDUMAXAL, LDUMAXL
  [<TestMethod>]
  member _.``C6.2.163 LDUMAXL``() =
    check "b8626020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb32555eUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.164 LDUMINB, LDUMINAB, LDUMINALB, LDUMINLB
  [<TestMethod>]
  member _.``C6.2.164 LDUMINAB``() =
    check "38a27020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4a5eUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe12fUL) ]
        []
        [ X(0, 0x55UL) ] ]
