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
/// One test for each instruction DDI0487F.c describes, ADC to LDADDALB in
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
type ManualLifterTests1() =
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

  /// Checks that a word goes to the given address over every input set,
  /// and changes nothing else.
  let goesTo hex inputs (target: uint64) =
    check hex inputs (List.replicate A64Machine.sets [ PC target ])

  /// Checks that a word goes to the given address over every input set,
  /// with X30 the address after it, and changes nothing else.
  let links hex inputs (target: uint64) =
    let back = X(30, A64Machine.code + 4UL)
    check hex inputs (List.replicate A64Machine.sets [ back; PC target ])

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

  /// C6.2.1 ADC
  [<TestMethod>]
  member _.``C6.2.1 ADC``() =
    check "1a020020" []
      [ [ X(0, 0x60c141c5UL) ]
        [ X(0, 0xe97a7171UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x55555555UL) ] ]
    check "9a020020" []
      [ [ X(0, 0xb77f309060c141c5UL) ]
        [ X(0, 0x584402cfe97a7171UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x5555555655555555UL) ] ]

  /// C6.2.2 ADCS
  [<TestMethod>]
  member _.``C6.2.2 ADCS``() =
    check "3a020020" []
      [ [ X(0, 0x60c141c5UL); NZCV 0x20000000UL ]
        [ X(0, 0xe97a7171UL); NZCV 0x80000000UL ]
        [ X(0, 0x1UL); NZCV 0x20000000UL ]
        [ X(0, 0x55555555UL); NZCV 0x0UL ] ]
    check "ba020020" []
      [ [ X(0, 0xb77f309060c141c5UL); NZCV 0xa0000000UL ]
        [ X(0, 0x584402cfe97a7171UL); NZCV 0x30000000UL ]
        [ X(0, 0x1UL); NZCV 0x20000000UL ]
        [ X(0, 0x5555555655555555UL); NZCV 0x0UL ] ]

  /// C6.2.3 ADD (extended register)
  [<TestMethod>]
  member _.``C6.2.3 ADD``() =
    check "0b020020" []
      [ [ X(0, 0x60c141c5UL) ]
        [ X(0, 0xe97a7171UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "11004020" []
      [ [ X(0, 0x658eec77UL) ]
        [ X(0, 0xbfc1e52UL) ]
        [ X(0, 0x11UL) ]
        [ X(0, 0x10UL) ] ]
    check "91004020" []
      [ [ X(0, 0xbeeb8da1658eec77UL) ]
        [ X(0, 0xbfc846100bfc1e52UL) ]
        [ X(0, 0x11UL) ]
        [ X(0, 0x100000010UL) ] ]
    check "8b020020" []
      [ [ X(0, 0xb77f309060c141c5UL) ]
        [ X(0, 0x584402cfe97a7171UL) ]
        []
        [ X(0, 0x5555555655555555UL) ] ]
    check "0e228420" []
      [ [ V(0, 0xf7ff9d519edadf28UL, 0x0UL) ]
        [ V(0, 0xb0152f9948dffbf7UL, 0x0UL) ]
        [ V(0, 0xffffffff80000001UL, 0x0UL) ]
        [ V(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "4e228420" []
      [ [ V(0, 0xf7ff9d519edadf28UL, 0xcb0484928c3edc0cUL) ]
        [ V(0, 0xb0152f9948dffbf7UL, 0x2991454d3ff84ce5UL) ]
        [ V(0, 0xffffffff80000001UL, 0x7f200000fe3fffffUL) ]
        [ V(0, 0xc008000000000000UL, 0xbea999999999999aUL) ] ]
    check "0e628420" []
      [ [ V(0, 0xf7ff9d519fdadf28UL, 0x0UL) ]
        [ V(0, 0xb1152f9948dffbf7UL, 0x0UL) ]
        [ V(0, 0xffffffff80000001UL, 0x0UL) ]
        [ V(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "4e628420" []
      [ [ V(0, 0xf7ff9d519fdadf28UL, 0xcc0484928d3edd0cUL) ]
        [ V(0, 0xb1152f9948dffbf7UL, 0x2991464d3ff84ce5UL) ]
        [ V(0, 0xffffffff80000001UL, 0x80200000ff3fffffUL) ]
        [ V(0, 0xc008000000000000UL, 0xbfa999999999999aUL) ] ]
    check "0ea28420" []
      [ [ V(0, 0xf7ff9d519fdbdf28UL, 0x0UL) ]
        [ V(0, 0xb1162f9948dffbf7UL, 0x0UL) ]
        [ V(0, 0xffffffff80000001UL, 0x0UL) ]
        [ V(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "4ee28420" []
      [ [ V(0, 0xf7ff9d519fdbdf28UL, 0xcc0484928d3fdd0cUL) ]
        [ V(0, 0xb1162f9a48dffbf7UL, 0x2991464e3ff94ce5UL) ]
        [ V(0, 0xffffffff80000001UL, 0x80200000ff3fffffUL) ]
        [ V(0, 0xc008000000000000UL, 0xbfa999999999999aUL) ] ]
    check "912af020" []
      [ [ X(0, 0xbeeb8da1658ef723UL) ]
        [ X(0, 0xbfc846100bfc28feUL) ]
        [ X(0, 0xabdUL) ]
        [ X(0, 0x100000abcUL) ] ]
    check "4ea28420" []
      [ [ V(0, 0xf7ff9d519fdbdf28UL, 0xcc0484928d3fdd0cUL) ]
        [ V(0, 0xb1162f9948dffbf7UL, 0x2991464d3ff94ce5UL) ]
        [ V(0, 0xffffffff80000001UL, 0x80200000ff3fffffUL) ]
        [ V(0, 0xc008000000000000UL, 0xbfa999999999999aUL) ] ]

  /// C6.2.6 ADDG
  [<TestMethod>]
  member _.``C6.2.6 ADDG``() =
    check "91800020" []
      [ [ X(0, 0xb0eb8da1658eec67UL) ]
        [ X(0, 0xb0c846100bfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x100000000UL) ] ]

  /// C6.2.7 ADDS (extended register)
  [<TestMethod>]
  member _.``C6.2.7 ADDS``() =
    check "2b020020" []
      [ [ X(0, 0x60c141c5UL); NZCV 0x20000000UL ]
        [ X(0, 0xe97a7171UL); NZCV 0x80000000UL ]
        []
        [ X(0, 0x55555555UL); NZCV 0x0UL ] ]
    check "31004020" []
      [ [ X(0, 0x658eec77UL); NZCV 0x0UL ]
        [ X(0, 0xbfc1e52UL); NZCV 0x0UL ]
        [ X(0, 0x11UL); NZCV 0x0UL ]
        [ X(0, 0x10UL); NZCV 0x0UL ] ]
    check "b1004020" []
      [ [ X(0, 0xbeeb8da1658eec77UL); NZCV 0x80000000UL ]
        [ X(0, 0xbfc846100bfc1e52UL); NZCV 0x80000000UL ]
        [ X(0, 0x11UL); NZCV 0x0UL ]
        [ X(0, 0x100000010UL); NZCV 0x0UL ] ]
    check "ab020020" []
      [ [ X(0, 0xb77f309060c141c5UL); NZCV 0xa0000000UL ]
        [ X(0, 0x584402cfe97a7171UL); NZCV 0x30000000UL ]
        []
        [ X(0, 0x5555555655555555UL); NZCV 0x0UL ] ]
    check "b1448c20" []
      [ [ X(0, 0xbeeb8da165a11c67UL); NZCV 0x80000000UL ]
        [ X(0, 0xbfc846100c0e4e42UL); NZCV 0x80000000UL ]
        [ X(0, 0x123001UL); NZCV 0x0UL ]
        [ X(0, 0x100123000UL); NZCV 0x0UL ] ]

  /// C6.2.10 ADR
  [<TestMethod>]
  member _.``C6.2.10 ADR``() =
    check "10000020" []
      [ [ X(0, 0x1000004UL) ]
        [ X(0, 0x1000004UL) ]
        [ X(0, 0x1000004UL) ]
        [ X(0, 0x1000004UL) ] ]

  /// C6.2.11 ADRP
  [<TestMethod>]
  member _.``C6.2.11 ADRP``() =
    check "90000000" []
      [ [ X(0, 0x1000000UL) ]
        [ X(0, 0x1000000UL) ]
        [ X(0, 0x1000000UL) ]
        [ X(0, 0x1000000UL) ] ]

  /// C6.2.12 AND (immediate)
  [<TestMethod>]
  member _.``C6.2.12 AND``() =
    check "9200f020" []
      [ [ X(0, 0x1441050145044445UL) ]
        [ X(0, 0x1540441001541440UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x100000000UL) ] ]
    check "121c0020" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "927c0020" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "0a020020" []
      [ [ X(0, 0x61024446UL) ]
        [ X(0, 0x97c1202UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "8a020020" []
      [ [ X(0, 0xb88380a061024446UL) ]
        [ X(0, 0x98480410097c1202UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x100000000UL) ] ]
    check "0e221c20" []
      [ [ V(0, 0x2e2240dce00cUL, 0x0UL) ]
        [ V(0, 0x5148802449001c00UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ] ]
    check "4e221c20" []
      [ [ V(0, 0x2e2240dce00cUL, 0x602440e43e015UL) ]
        [ V(0, 0x5148802449001c00UL, 0x42200a5240199028UL) ]
        [ V(0, 0x0UL, 0x8000007f400000UL) ]
        [ V(0, 0x0UL, 0x3fb0000000000000UL) ] ]
    check "9240bc00" []
      [ [ X(0, 0x2dec89025cc1UL) ]
        [ X(0, 0x35de1c9756ceUL) ]
        []
        [] ]
    check "9240bc11" []
      [ [ X(17, 0x2dec89025cc1UL) ]
        [ X(17, 0x35de1c9756ceUL) ]
        [ X(17, 0x0UL) ]
        [ X(17, 0xffffffffUL) ] ]
    check "9240bc1e" []
      [ [ X(30, 0x2dec89025cc1UL) ]
        [ X(30, 0x35de1c9756ceUL) ]
        [ X(30, 0x0UL) ]
        [ X(30, 0xffffffffUL) ] ]

  /// C6.2.14 ANDS (immediate)
  [<TestMethod>]
  member _.``C6.2.14 ANDS``() =
    check "f2089c20" []
      [ [ X(0, 0xbe008d006500ec00UL); NZCV 0x80000000UL ]
        [ X(0, 0xbf0046000b001e00UL); NZCV 0x80000000UL ]
        [ NZCV 0x40000000UL ]
        [ X(0, 0x0UL); NZCV 0x40000000UL ] ]
    check "721c0020" []
      [ [ X(0, 0x0UL); NZCV 0x40000000UL ]
        [ X(0, 0x0UL); NZCV 0x40000000UL ]
        [ NZCV 0x40000000UL ]
        [ X(0, 0x0UL); NZCV 0x40000000UL ] ]
    check "f27c0020" []
      [ [ X(0, 0x0UL); NZCV 0x40000000UL ]
        [ X(0, 0x0UL); NZCV 0x40000000UL ]
        [ NZCV 0x40000000UL ]
        [ X(0, 0x0UL); NZCV 0x40000000UL ] ]
    check "6a020020" []
      [ [ X(0, 0x61024446UL); NZCV 0x0UL ]
        [ X(0, 0x97c1202UL); NZCV 0x0UL ]
        [ X(0, 0x1UL); NZCV 0x0UL ]
        [ X(0, 0x0UL); NZCV 0x40000000UL ] ]
    check "ea020020" []
      [ [ X(0, 0xb88380a061024446UL); NZCV 0x80000000UL ]
        [ X(0, 0x98480410097c1202UL); NZCV 0x80000000UL ]
        [ X(0, 0x1UL); NZCV 0x0UL ]
        [ X(0, 0x100000000UL); NZCV 0x0UL ] ]

  /// C6.2.16 ASR (register)
  [<TestMethod>]
  member _.``C6.2.16 ASR``() =
    check "1ac22820" []
      [ [ X(0, 0x1UL) ]
        [ X(0, 0x17f8UL) ]
        []
        [ X(0, 0x0UL) ] ]
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
    check "9ac22820" []
      [ [ X(0, 0xfffffffefbae3685UL) ]
        [ X(0, 0xffffffffffff7f90UL) ]
        []
        [ X(0, 0x800UL) ] ]

  /// C6.2.18 ASRV
  [<TestMethod>]
  member _.``C6.2.18 ASRV``() =
    check "1ac22820" []
      [ [ X(0, 0x1UL) ]
        [ X(0, 0x17f8UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "9ac22820" []
      [ [ X(0, 0xfffffffefbae3685UL) ]
        [ X(0, 0xffffffffffff7f90UL) ]
        []
        [ X(0, 0x800UL) ] ]

  /// C6.2.19 AT
  [<TestMethod>]
  member _.``C6.2.19 AT``() =
    raises BinIR.SideEffect.UndefinedInstruction "d5087841"

  /// <summary>
  /// The code AUTDA checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.20, Auth()), over every input set with
  /// X0 a canonical pointer and X1 the modifier: a pointer PACDA signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key A's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.20 AUTDA``() =
    authenticates "dac11820" "dac10820" "dac10c20" 0 0x2000000000000000UL

  /// <summary>
  /// The code AUTDZA checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.20, Auth()), over every input set with
  /// X0 a canonical pointer and zero the modifier: a pointer PACDZA signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key A's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.20 AUTDZA``() =
    authenticates "dac13be0" "dac12be0" "dac12fe0" 0 0x2000000000000000UL

  /// <summary>
  /// The code AUTDB checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.21, Auth()), over every input set with
  /// X0 a canonical pointer and X1 the modifier: a pointer PACDB signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key B's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.21 AUTDB``() =
    authenticates "dac11c20" "dac10c20" "dac10820" 0 0x4000000000000000UL

  /// <summary>
  /// The code AUTDZB checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.21, Auth()), over every input set with
  /// X0 a canonical pointer and zero the modifier: a pointer PACDZB signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key B's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.21 AUTDZB``() =
    authenticates "dac13fe0" "dac12fe0" "dac12be0" 0 0x4000000000000000UL

  /// <summary>
  /// The code AUTIA checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.22, Auth()), over every input set with
  /// X0 a canonical pointer and X1 the modifier: a pointer PACIA signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key A's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.22 AUTIA``() =
    authenticates "dac11020" "dac10020" "dac10420" 0 0x2000000000000000UL

  /// <summary>
  /// The code AUTIA1716 checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.22, Auth()), over every input set with
  /// X17 a canonical pointer and X16 the modifier: a pointer PACIA1716 signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key A's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.22 AUTIA1716``() =
    authenticates "d503219f" "d503211f" "d503215f" 17 0x2000000000000000UL

  /// <summary>
  /// The code AUTIASP checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.22, Auth()), over every input set with
  /// X30 a canonical pointer and SP the modifier: a pointer PACIASP signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key A's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.22 AUTIASP``() =
    authenticates "d50323bf" "d503233f" "d503237f" 30 0x2000000000000000UL

  /// <summary>
  /// The code AUTIAZ checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.22, Auth()), over every input set with
  /// X30 a canonical pointer and zero the modifier: a pointer PACIAZ signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key A's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.22 AUTIAZ``() =
    authenticates "d503239f" "d503231f" "d503235f" 30 0x2000000000000000UL

  /// <summary>
  /// The code AUTIZA checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.22, Auth()), over every input set with
  /// X0 a canonical pointer and zero the modifier: a pointer PACIZA signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key A's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.22 AUTIZA``() =
    authenticates "dac133e0" "dac123e0" "dac127e0" 0 0x2000000000000000UL

  /// <summary>
  /// The code AUTIB checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.23, Auth()), over every input set with
  /// X0 a canonical pointer and X1 the modifier: a pointer PACIB signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key B's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.23 AUTIB``() =
    authenticates "dac11420" "dac10420" "dac10020" 0 0x4000000000000000UL

  /// <summary>
  /// The code AUTIB1716 checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.23, Auth()), over every input set with
  /// X17 a canonical pointer and X16 the modifier: a pointer PACIB1716 signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key B's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.23 AUTIB1716``() =
    authenticates "d50321df" "d503215f" "d503211f" 17 0x4000000000000000UL

  /// <summary>
  /// The code AUTIBSP checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.23, Auth()), over every input set with
  /// X30 a canonical pointer and SP the modifier: a pointer PACIBSP signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key B's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.23 AUTIBSP``() =
    authenticates "d50323ff" "d503237f" "d503233f" 30 0x4000000000000000UL

  /// <summary>
  /// The code AUTIBZ checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.23, Auth()), over every input set with
  /// X30 a canonical pointer and zero the modifier: a pointer PACIBZ signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key B's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.23 AUTIBZ``() =
    authenticates "d50323df" "d503235f" "d503231f" 30 0x4000000000000000UL

  /// <summary>
  /// The code AUTIZB checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.23, Auth()), over every input set with
  /// X0 a canonical pointer and zero the modifier: a pointer PACIZB signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key B's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.23 AUTIZB``() =
    authenticates "dac137e0" "dac127e0" "dac123e0" 0 0x4000000000000000UL

  /// C6.2.24 AXFLAG
  [<TestMethod>]
  member _.``C6.2.24 AXFLAG``() =
    check "d500405f" []
      [ [ NZCV 0x40000000UL ]
        [ NZCV 0x40000000UL ]
        []
        [ NZCV 0x40000000UL ] ]

  /// <summary>
  /// B.cond cannot run in the oracle, which has nowhere for it to go, so
  /// this checks the jump: a conditional one out of the instruction, to its
  /// own address plus imm19 times four where the condition holds and to the
  /// next instruction where it does not, for every condition under every
  /// NZCV (C6.2.25).
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.25 B.COND``() =
    (* Bit n of entry c says whether condition c holds for NZCV n, as
       ConditionHolds gives it. *)
    let holds =
      [| 0xf0f0
         0x0f0f
         0xcccc
         0x3333
         0xff00
         0x00ff
         0xaaaa
         0x5555
         0x0c0c
         0xf3f3
         0xaa55
         0x55aa
         0x0a05
         0xf5fa
         0xffff
         0xffff |]
    for c in 0 .. 15 do
      let hex = $"{0x54000200 ||| c:x8}"
      Assert.AreEqual<string option>(Some "InterCJmp", exitOf hex)
      for n in 0 .. 15 do
        let taken = (holds[c] >>> n) &&& 1 = 1
        let target = if taken then 0x40UL else 0x4UL
        let inputs = [ NZCV(uint64 n <<< 28) ]
        goesTo hex inputs (A64Machine.code + target)

  /// <summary>
  /// B cannot run in the oracle, which has nowhere for it to go, so this
  /// checks the jump: one out of the instruction, of the plain kind, to the
  /// address the encoding names -- its own plus imm26 times four (C6.2.26)
  /// -- whatever the registers hold, and nothing else changed.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.26 B``() =
    Assert.AreEqual<string option>(Some "Base", exitOf "14000001")
    goesTo "14000001" [] (A64Machine.code + 0x4UL)
    goesTo "14000040" [] (A64Machine.code + 0x100UL)
    goesTo "17ffffc0" [] (A64Machine.code - 0x100UL)

  /// C6.2.27 BFC
  [<TestMethod>]
  member _.``C6.2.27 BFC``() =
    check "331d13e0" []
      [ [ X(0, 0x89025c01UL) ]
        [ X(0, 0x1c975606UL) ]
        []
        [ X(0, 0xffffff07UL) ] ]
    check "b37d13e0" []
      [ [ X(0, 0x910a2dec89025c01UL) ]
        [ X(0, 0x975835de1c975606UL) ]
        []
        [ X(0, 0xffffff07UL) ] ]

  /// C6.2.28 BFI
  [<TestMethod>]
  member _.``C6.2.28 BFI``() =
    check "331d1020" []
      [ [ X(0, 0x89025c39UL) ]
        [ X(0, 0x1c975616UL) ]
        [ X(0, 0x8UL) ]
        [ X(0, 0xffffff07UL) ] ]
    check "b37d1020" []
      [ [ X(0, 0x910a2dec89025c39UL) ]
        [ X(0, 0x975835de1c975616UL) ]
        [ X(0, 0x8UL) ]
        [ X(0, 0xffffff07UL) ] ]
    check "b3430820" []
      [ [ X(0, 0xf10a2dec89025cc1UL) ]
        [ X(0, 0x575835de1c9756ceUL) ]
        [ X(0, 0x2000000000000000UL) ]
        [] ]

  /// C6.2.29 BFM
  [<TestMethod>]
  member _.``C6.2.29 BFM``() =
    check "331d13e0" []
      [ [ X(0, 0x89025c01UL) ]
        [ X(0, 0x1c975606UL) ]
        []
        [ X(0, 0xffffff07UL) ] ]
    check "b37d13e0" []
      [ [ X(0, 0x910a2dec89025c01UL) ]
        [ X(0, 0x975835de1c975606UL) ]
        []
        [ X(0, 0xffffff07UL) ] ]
    check "331d1020" []
      [ [ X(0, 0x89025c39UL) ]
        [ X(0, 0x1c975616UL) ]
        [ X(0, 0x8UL) ]
        [ X(0, 0xffffff07UL) ] ]
    check "b37d1020" []
      [ [ X(0, 0x910a2dec89025c39UL) ]
        [ X(0, 0x975835de1c975616UL) ]
        [ X(0, 0x8UL) ]
        [ X(0, 0xffffff07UL) ] ]
    check "33031420" []
      [ [ X(0, 0x89025cc4UL) ]
        [ X(0, 0x1c9756c8UL) ]
        []
        [ X(0, 0xfffffff8UL) ] ]
    check "b3431420" []
      [ [ X(0, 0x910a2dec89025cc4UL) ]
        [ X(0, 0x975835de1c9756c8UL) ]
        []
        [ X(0, 0xfffffff8UL) ] ]
    check "33031c20" []
      [ [ X(0, 0x89025cccUL) ]
        [ X(0, 0x1c9756c8UL) ]
        []
        [ X(0, 0xffffffe0UL) ] ]
    check "b3431c20" []
      [ [ X(0, 0x910a2dec89025cccUL) ]
        [ X(0, 0x975835de1c9756c8UL) ]
        []
        [ X(0, 0xffffffe0UL) ] ]
    check "b34003e0" []
      [ [ X(0, 0x910a2dec89025cc0UL) ]
        []
        []
        [ X(0, 0xfffffffeUL) ] ]
    check "b3400020" [] [ []; []; [ X(0, 0x1UL) ]; [ X(0, 0xfffffffeUL) ] ]
    check "b3430820" []
      [ [ X(0, 0xf10a2dec89025cc1UL) ]
        [ X(0, 0x575835de1c9756ceUL) ]
        [ X(0, 0x2000000000000000UL) ]
        [] ]

  /// C6.2.30 BFXIL
  [<TestMethod>]
  member _.``C6.2.30 BFXIL``() =
    check "33031420" []
      [ [ X(0, 0x89025cc4UL) ]
        [ X(0, 0x1c9756c8UL) ]
        []
        [ X(0, 0xfffffff8UL) ] ]
    check "b3431420" []
      [ [ X(0, 0x910a2dec89025cc4UL) ]
        [ X(0, 0x975835de1c9756c8UL) ]
        []
        [ X(0, 0xfffffff8UL) ] ]
    check "33031c20" []
      [ [ X(0, 0x89025cccUL) ]
        [ X(0, 0x1c9756c8UL) ]
        []
        [ X(0, 0xffffffe0UL) ] ]
    check "b3431c20" []
      [ [ X(0, 0x910a2dec89025cccUL) ]
        [ X(0, 0x975835de1c9756c8UL) ]
        []
        [ X(0, 0xffffffe0UL) ] ]
    check "b34003e0" []
      [ [ X(0, 0x910a2dec89025cc0UL) ]
        []
        []
        [ X(0, 0xfffffffeUL) ] ]
    check "b3400020" [] [ []; []; [ X(0, 0x1UL) ]; [ X(0, 0xfffffffeUL) ] ]

  /// C6.2.31 BIC (shifted register)
  [<TestMethod>]
  member _.``C6.2.31 BIC``() =
    check "0a220020" []
      [ [ X(0, 0x48ca821UL) ]
        [ X(0, 0x2800c40UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "2f009460" []
      [ [ V(0, 0x96281964c90489b8UL, 0x0UL) ]
        [ V(0, 0x9a78a72430f8ca54UL, 0x0UL) ]
        [ V(0, 0xbfc000003f800000UL, 0x0UL) ]
        [ V(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "6f009460" []
      [ [ V(0, 0x96281964c90489b8UL, 0x65ace2685a042c6cUL) ]
        [ V(0, 0x9a78a72430f8ca54UL, 0x4448cab822b8690cUL) ]
        [ V(0, 0xbfc000003f800000UL, 0x3dcccccc40400000UL) ]
        [] ]
    check "2f001460" []
      [ [ V(0, 0x962b1964c90789b8UL, 0x0UL) ]
        [ V(0, 0x9a7aa72430f9ca54UL, 0x0UL) ]
        [ V(0, 0xbfc000003f800000UL, 0x0UL) ]
        [ V(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "6f001460" []
      [ [ V(0, 0x962b1964c90789b8UL, 0x65ace2685a072c6cUL) ]
        [ V(0, 0x9a7aa72430f9ca54UL, 0x444bcab822bb690cUL) ]
        [ V(0, 0xbfc000003f800000UL, 0x3dcccccc40400000UL) ]
        [] ]
    check "0e621c20" []
      [ [ V(0, 0x7061410d08000010UL, 0x0UL) ]
        [ V(0, 0x6800301160f8224UL, 0x0UL) ]
        [ V(0, 0x7f80000080000000UL, 0x0UL) ]
        [ V(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4e621c20" []
      [ [ V(0, 0x7061410d08000010UL, 0x40d0800a20b01c02UL) ]
        [ V(0, 0x6800301160f8224UL, 0xa01111011f062081UL) ]
        [ V(0, 0x7f80000080000000UL, 0x7f20000000800000UL) ]
        [ V(0, 0x4008000000000000UL, 0x999999999999aUL) ] ]
    check "8a220020" []
      [ [ X(0, 0x6680d01048ca821UL) ]
        [ X(0, 0x2780420002800c40UL) ]
        []
        [ X(0, 0x0UL) ] ]

  /// C6.2.32 BICS (shifted register)
  [<TestMethod>]
  member _.``C6.2.32 BICS``() =
    check "6a220020" []
      [ [ X(0, 0x48ca821UL); NZCV 0x0UL ]
        [ X(0, 0x2800c40UL); NZCV 0x0UL ]
        [ NZCV 0x40000000UL ]
        [ X(0, 0x0UL); NZCV 0x40000000UL ] ]
    check "ea220020" []
      [ [ X(0, 0x6680d01048ca821UL); NZCV 0x0UL ]
        [ X(0, 0x2780420002800c40UL); NZCV 0x0UL ]
        [ NZCV 0x40000000UL ]
        [ X(0, 0x0UL); NZCV 0x40000000UL ] ]

  /// <summary>
  /// BL cannot run in the oracle, which has nowhere for it to go, so this
  /// checks the jump: a call out of the instruction to its own address
  /// plus imm26 times four, with X30 the address after it (C6.2.33).
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.33 BL``() =
    Assert.AreEqual<string option>(Some "IsCall", exitOf "94000001")
    links "94000001" [] (A64Machine.code + 0x4UL)
    links "94000040" [] (A64Machine.code + 0x100UL)

  /// <summary>
  /// BLR cannot run in the oracle, which has nowhere for it to go, so this
  /// checks the jump: a call out of the instruction to what Xn holds, with
  /// X30 the address after it, over every input set (C6.2.34).
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.34 BLR``() =
    Assert.AreEqual<string option>(Some "IsCall", exitOf "d63f0020")
    check "d63f0020" []
      [ [ X(30, 0x1000004UL); PC 0xbeeb8da1658eec67UL ]
        [ X(30, 0x1000004UL); PC 0xbfc846100bfc1e42UL ]
        [ X(30, 0x1000004UL); PC 0x1UL ]
        [ X(30, 0x1000004UL); PC 0x100000000UL ] ]

  /// <summary>
  /// BLRAA cannot run in the oracle, which has nowhere for it to go, and
  /// its target is authenticated with a key the oracle's process draws
  /// at random. What the manual fixes is checked instead (C6.2.35): with X1
  /// a canonical pointer the matching PAC signed, the jump, a call,
  /// goes to the pointer; unsigned, to the pointer with the key's error
  /// code in bits 62:61; and X30 is the address after it, over every input set.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.35 BLRAA``() =
    Assert.AreEqual<string option>(Some "IsCall", exitOf "d73f0822")
    branchesSigned "dac10041" "d73f0822" 1 0x2000000000000000UL true

  /// <summary>
  /// BLRAAZ cannot run in the oracle, which has nowhere for it to go, and
  /// its target is authenticated with a key the oracle's process draws
  /// at random. What the manual fixes is checked instead (C6.2.35): with X1
  /// a canonical pointer the matching PAC signed, the jump, a call,
  /// goes to the pointer; unsigned, to the pointer with the key's error
  /// code in bits 62:61; and X30 is the address after it, over every input set.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.35 BLRAAZ``() =
    Assert.AreEqual<string option>(Some "IsCall", exitOf "d63f083f")
    branchesSigned "dac123e1" "d63f083f" 1 0x2000000000000000UL true

  /// <summary>
  /// BLRAB cannot run in the oracle, which has nowhere for it to go, and
  /// its target is authenticated with a key the oracle's process draws
  /// at random. What the manual fixes is checked instead (C6.2.35): with X1
  /// a canonical pointer the matching PAC signed, the jump, a call,
  /// goes to the pointer; unsigned, to the pointer with the key's error
  /// code in bits 62:61; and X30 is the address after it, over every input set.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.35 BLRAB``() =
    Assert.AreEqual<string option>(Some "IsCall", exitOf "d73f0c22")
    branchesSigned "dac10441" "d73f0c22" 1 0x4000000000000000UL true

  /// <summary>
  /// BLRABZ cannot run in the oracle, which has nowhere for it to go, and
  /// its target is authenticated with a key the oracle's process draws
  /// at random. What the manual fixes is checked instead (C6.2.35): with X1
  /// a canonical pointer the matching PAC signed, the jump, a call,
  /// goes to the pointer; unsigned, to the pointer with the key's error
  /// code in bits 62:61; and X30 is the address after it, over every input set.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.35 BLRABZ``() =
    Assert.AreEqual<string option>(Some "IsCall", exitOf "d63f0c3f")
    branchesSigned "dac127e1" "d63f0c3f" 1 0x4000000000000000UL true

  /// <summary>
  /// BR cannot run in the oracle, which has nowhere for it to go, so this
  /// checks the jump: out of the instruction, of the plain kind, to what
  /// Xn holds, over every input set (C6.2.36).
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.36 BR``() =
    Assert.AreEqual<string option>(Some "Base", exitOf "d61f0020")
    check "d61f0020" []
      [ [ PC 0xbeeb8da1658eec67UL ]
        [ PC 0xbfc846100bfc1e42UL ]
        [ PC 0x1UL ]
        [ PC 0x100000000UL ] ]

  /// <summary>
  /// BRAA cannot run in the oracle, which has nowhere for it to go, and
  /// its target is authenticated with a key the oracle's process draws
  /// at random. What the manual fixes is checked instead (C6.2.37): with X1
  /// a canonical pointer the matching PAC signed, the jump, of the plain kind,
  /// goes to the pointer; unsigned, to the pointer with the key's error
  /// code in bits 62:61, over every input set.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.37 BRAA``() =
    Assert.AreEqual<string option>(Some "Base", exitOf "d71f0822")
    branchesSigned "dac10041" "d71f0822" 1 0x2000000000000000UL false

  /// <summary>
  /// BRAAZ cannot run in the oracle, which has nowhere for it to go, and
  /// its target is authenticated with a key the oracle's process draws
  /// at random. What the manual fixes is checked instead (C6.2.37): with X1
  /// a canonical pointer the matching PAC signed, the jump, of the plain kind,
  /// goes to the pointer; unsigned, to the pointer with the key's error
  /// code in bits 62:61, over every input set.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.37 BRAAZ``() =
    Assert.AreEqual<string option>(Some "Base", exitOf "d61f083f")
    branchesSigned "dac123e1" "d61f083f" 1 0x2000000000000000UL false

  /// <summary>
  /// BRAB cannot run in the oracle, which has nowhere for it to go, and
  /// its target is authenticated with a key the oracle's process draws
  /// at random. What the manual fixes is checked instead (C6.2.37): with X1
  /// a canonical pointer the matching PAC signed, the jump, of the plain kind,
  /// goes to the pointer; unsigned, to the pointer with the key's error
  /// code in bits 62:61, over every input set.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.37 BRAB``() =
    Assert.AreEqual<string option>(Some "Base", exitOf "d71f0c22")
    branchesSigned "dac10441" "d71f0c22" 1 0x4000000000000000UL false

  /// <summary>
  /// BRABZ cannot run in the oracle, which has nowhere for it to go, and
  /// its target is authenticated with a key the oracle's process draws
  /// at random. What the manual fixes is checked instead (C6.2.37): with X1
  /// a canonical pointer the matching PAC signed, the jump, of the plain kind,
  /// goes to the pointer; unsigned, to the pointer with the key's error
  /// code in bits 62:61, over every input set.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.37 BRABZ``() =
    Assert.AreEqual<string option>(Some "Base", exitOf "d61f0c3f")
    branchesSigned "dac127e1" "d61f0c3f" 1 0x4000000000000000UL false

  /// C6.2.38 BRK
  [<TestMethod>]
  member _.``C6.2.38 BRK``() =
    raises BinIR.SideEffect.Breakpoint "d4200000"

  /// C6.2.39 BTI
  [<TestMethod>]
  member _.``C6.2.39 BTI``() =
    check "d503241f" [] [ []; []; []; [] ]

  /// C6.2.40 CASB, CASAB, CASALB, CASLB
  [<TestMethod>]
  member _.``C6.2.40 CASAB``() =
    check "08e27c20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x81UL) ]
        [ X(2, 0xe4UL) ]
        [ X(2, 0x0UL) ]
        [ X(2, 0x55UL); M(0, 0x55555555555555ffUL) ] ]

  /// C6.2.40 CASB, CASAB, CASALB, CASLB
  [<TestMethod>]
  member _.``C6.2.40 CASALB``() =
    check "08e2fc20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x81UL) ]
        [ X(2, 0xe4UL) ]
        [ X(2, 0x0UL) ]
        [ X(2, 0x55UL); M(0, 0x55555555555555ffUL) ] ]

  /// C6.2.40 CASB, CASAB, CASALB, CASLB
  [<TestMethod>]
  member _.``C6.2.40 CASB``() =
    check "08a27c20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x81UL) ]
        [ X(2, 0xe4UL) ]
        [ X(2, 0x0UL) ]
        [ X(2, 0x55UL); M(0, 0x55555555555555ffUL) ] ]

  /// C6.2.40 CASB, CASAB, CASALB, CASLB
  [<TestMethod>]
  member _.``C6.2.40 CASLB``() =
    check "08a2fc20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x81UL) ]
        [ X(2, 0xe4UL) ]
        [ X(2, 0x0UL) ]
        [ X(2, 0x55UL); M(0, 0x55555555555555ffUL) ] ]

  /// C6.2.41 CASH, CASAH, CASALH, CASLH
  [<TestMethod>]
  member _.``C6.2.41 CASAH``() =
    check "48e27c20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x4a81UL) ]
        [ X(2, 0xe1e4UL) ]
        [ X(2, 0x0UL) ]
        [ X(2, 0x5555UL); M(0, 0x555555555555ffffUL) ] ]

  /// C6.2.41 CASH, CASAH, CASALH, CASLH
  [<TestMethod>]
  member _.``C6.2.41 CASALH``() =
    check "48e2fc20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x4a81UL) ]
        [ X(2, 0xe1e4UL) ]
        [ X(2, 0x0UL) ]
        [ X(2, 0x5555UL); M(0, 0x555555555555ffffUL) ] ]

  /// C6.2.41 CASH, CASAH, CASALH, CASLH
  [<TestMethod>]
  member _.``C6.2.41 CASH``() =
    check "48a27c20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x4a81UL) ]
        [ X(2, 0xe1e4UL) ]
        [ X(2, 0x0UL) ]
        [ X(2, 0x5555UL); M(0, 0x555555555555ffffUL) ] ]

  /// C6.2.41 CASH, CASAH, CASALH, CASLH
  [<TestMethod>]
  member _.``C6.2.41 CASLH``() =
    check "48a2fc20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x4a81UL) ]
        [ X(2, 0xe1e4UL) ]
        [ X(2, 0x0UL) ]
        [ X(2, 0x5555UL); M(0, 0x555555555555ffffUL) ] ]

  /// C6.2.42 CASP, CASPA, CASPAL, CASPL
  [<TestMethod>]
  member _.``C6.2.42 CASP``() =
    check "48227c80" [ X(4, 0x2008000UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL); X(3, 0xd80391ffb30d1390UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL); X(3, 0xf8606cc314fb6b96UL) ]
        [ X(2, 0x0UL); X(3, 0x1UL) ]
        [ M(0, 0xffffffffUL); M(8, 0x100000000UL) ] ]
    check "48227c20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL); X(3, 0xd80391ffb30d1390UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL); X(3, 0xf8606cc314fb6b96UL) ]
        [ X(2, 0x0UL); X(3, 0x1UL) ]
        [ M(0, 0xffffffffUL); M(8, 0x2008000UL) ] ]

  /// C6.2.42 CASP, CASPA, CASPAL, CASPL
  [<TestMethod>]
  member _.``C6.2.42 CASPA``() =
    check "48627c80" [ X(4, 0x2008000UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL); X(3, 0xd80391ffb30d1390UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL); X(3, 0xf8606cc314fb6b96UL) ]
        [ X(2, 0x0UL); X(3, 0x1UL) ]
        [ M(0, 0xffffffffUL); M(8, 0x100000000UL) ] ]
    check "48627c20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL); X(3, 0xd80391ffb30d1390UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL); X(3, 0xf8606cc314fb6b96UL) ]
        [ X(2, 0x0UL); X(3, 0x1UL) ]
        [ M(0, 0xffffffffUL); M(8, 0x2008000UL) ] ]

  /// C6.2.42 CASP, CASPA, CASPAL, CASPL
  [<TestMethod>]
  member _.``C6.2.42 CASPAL``() =
    check "4862fc80" [ X(4, 0x2008000UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL); X(3, 0xd80391ffb30d1390UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL); X(3, 0xf8606cc314fb6b96UL) ]
        [ X(2, 0x0UL); X(3, 0x1UL) ]
        [ M(0, 0xffffffffUL); M(8, 0x100000000UL) ] ]
    check "4862fc20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL); X(3, 0xd80391ffb30d1390UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL); X(3, 0xf8606cc314fb6b96UL) ]
        [ X(2, 0x0UL); X(3, 0x1UL) ]
        [ M(0, 0xffffffffUL); M(8, 0x2008000UL) ] ]

  /// C6.2.42 CASP, CASPA, CASPAL, CASPL
  [<TestMethod>]
  member _.``C6.2.42 CASPL``() =
    check "4822fc80" [ X(4, 0x2008000UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL); X(3, 0xd80391ffb30d1390UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL); X(3, 0xf8606cc314fb6b96UL) ]
        [ X(2, 0x0UL); X(3, 0x1UL) ]
        [ M(0, 0xffffffffUL); M(8, 0x100000000UL) ] ]
    check "4822fc20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL); X(3, 0xd80391ffb30d1390UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL); X(3, 0xf8606cc314fb6b96UL) ]
        [ X(2, 0x0UL); X(3, 0x1UL) ]
        [ M(0, 0xffffffffUL); M(8, 0x2008000UL) ] ]

  /// C6.2.43 CAS, CASA, CASAL, CASL
  [<TestMethod>]
  member _.``C6.2.43 CAS``() =
    check "c8a27c20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL) ]
        [ X(2, 0x0UL) ]
        [ M(0, 0xffffffffUL) ] ]
    check "88a27c20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xc13e4a81UL) ]
        [ X(2, 0x1e8fe1e4UL) ]
        [ X(2, 0x0UL) ]
        [ X(2, 0x55555555UL); M(0, 0x55555555ffffffffUL) ] ]

  /// C6.2.43 CAS, CASA, CASAL, CASL
  [<TestMethod>]
  member _.``C6.2.43 CASA``() =
    check "88e27c20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xc13e4a81UL) ]
        [ X(2, 0x1e8fe1e4UL) ]
        [ X(2, 0x0UL) ]
        [ X(2, 0x55555555UL); M(0, 0x55555555ffffffffUL) ] ]

  /// C6.2.43 CAS, CASA, CASAL, CASL
  [<TestMethod>]
  member _.``C6.2.43 CASAL``() =
    check "88e2fc20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xc13e4a81UL) ]
        [ X(2, 0x1e8fe1e4UL) ]
        [ X(2, 0x0UL) ]
        [ X(2, 0x55555555UL); M(0, 0x55555555ffffffffUL) ] ]

  /// C6.2.43 CAS, CASA, CASAL, CASL
  [<TestMethod>]
  member _.``C6.2.43 CASL``() =
    check "88a2fc20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xc13e4a81UL) ]
        [ X(2, 0x1e8fe1e4UL) ]
        [ X(2, 0x0UL) ]
        [ X(2, 0x55555555UL); M(0, 0x55555555ffffffffUL) ] ]

  /// <summary>
  /// CBNZ cannot run in the oracle, which has nowhere for it to go, so
  /// this checks the jump: a conditional one out of the instruction, to
  /// its own address plus imm19 times four where W0 or X0 is not zero and to
  /// the next instruction where it is, over 0, 2^32 and 1 (C6.2.44).
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.44 CBNZ``() =
    Assert.AreEqual<string option>(Some "InterCJmp", exitOf "35000200")
    goesTo "35000200" [ X(0, 0x0UL) ] (A64Machine.code + 0x4UL)
    goesTo "35000200" [ X(0, 0x100000000UL) ] (A64Machine.code + 0x4UL)
    goesTo "35000200" [ X(0, 0x1UL) ] (A64Machine.code + 0x40UL)
    Assert.AreEqual<string option>(Some "InterCJmp", exitOf "b5000200")
    goesTo "b5000200" [ X(0, 0x0UL) ] (A64Machine.code + 0x4UL)
    goesTo "b5000200" [ X(0, 0x100000000UL) ] (A64Machine.code + 0x40UL)
    goesTo "b5000200" [ X(0, 0x1UL) ] (A64Machine.code + 0x40UL)

  /// <summary>
  /// CBZ cannot run in the oracle, which has nowhere for it to go, so
  /// this checks the jump: a conditional one out of the instruction, to
  /// its own address plus imm19 times four where W0 or X0 is zero and to
  /// the next instruction where it is not, over 0, 2^32 and 1 (C6.2.45).
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.45 CBZ``() =
    Assert.AreEqual<string option>(Some "InterCJmp", exitOf "34000200")
    goesTo "34000200" [ X(0, 0x0UL) ] (A64Machine.code + 0x40UL)
    goesTo "34000200" [ X(0, 0x100000000UL) ] (A64Machine.code + 0x40UL)
    goesTo "34000200" [ X(0, 0x1UL) ] (A64Machine.code + 0x4UL)
    Assert.AreEqual<string option>(Some "InterCJmp", exitOf "b4000200")
    goesTo "b4000200" [ X(0, 0x0UL) ] (A64Machine.code + 0x40UL)
    goesTo "b4000200" [ X(0, 0x100000000UL) ] (A64Machine.code + 0x4UL)
    goesTo "b4000200" [ X(0, 0x1UL) ] (A64Machine.code + 0x4UL)

  /// C6.2.46 CCMN (immediate)
  [<TestMethod>]
  member _.``C6.2.46 CCMN``() =
    check "3a500829" []
      [ [ NZCV 0x90000000UL ]
        [ NZCV 0x0UL ]
        [ NZCV 0x0UL ]
        [] ]
    check "ba500829" []
      [ [ NZCV 0x90000000UL ]
        [ NZCV 0x80000000UL ]
        [ NZCV 0x0UL ]
        [] ]
    check "3a420029" [] [ [ NZCV 0x90000000UL ]; [ NZCV 0x80000000UL ]; []; [] ]
    check "ba420029" [] [ [ NZCV 0x90000000UL ]; [ NZCV 0x30000000UL ]; []; [] ]
    check "ba400820" []
      [ [ NZCV 0x0UL ]
        [ NZCV 0x80000000UL ]
        [ NZCV 0x0UL ]
        [ NZCV 0x0UL ] ]

  /// C6.2.48 CCMP (immediate)
  [<TestMethod>]
  member _.``C6.2.48 CCMP``() =
    check "7a500829" []
      [ [ NZCV 0x90000000UL ]
        [ NZCV 0x20000000UL ]
        [ NZCV 0x80000000UL ]
        [] ]
    check "fa500829" []
      [ [ NZCV 0x90000000UL ]
        [ NZCV 0xa0000000UL ]
        [ NZCV 0x80000000UL ]
        [] ]
    check "7a420029" []
      [ [ NZCV 0x90000000UL ]
        [ NZCV 0x0UL ]
        [ NZCV 0x0UL ]
        [] ]
    check "fa420029" []
      [ [ NZCV 0x90000000UL ]
        [ NZCV 0x20000000UL ]
        [ NZCV 0x0UL ]
        [] ]
    check "fa400820" []
      [ [ NZCV 0x0UL ]
        [ NZCV 0xa0000000UL ]
        [ NZCV 0x20000000UL ]
        [ NZCV 0x0UL ] ]

  /// C6.2.50 CFINV
  [<TestMethod>]
  member _.``C6.2.50 CFINV``() =
    check "d500401f" []
      [ [ NZCV 0x30000000UL ]
        [ NZCV 0x70000000UL ]
        [ NZCV 0x40000000UL ]
        [ NZCV 0xb0000000UL ] ]

  /// C6.2.51 CFP
  [<TestMethod>]
  member _.``C6.2.51 CFP``() =
    raises BinIR.SideEffect.UndefinedInstruction "d50b7380"

  /// C6.2.52 CINC
  [<TestMethod>]
  member _.``C6.2.52 CINC``() =
    check "1a811420" []
      [ [ X(0, 0x658eec67UL) ]
        [ X(0, 0xbfc1e43UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0x0UL) ] ]
    check "9a811420" []
      [ [ X(0, 0xbeeb8da1658eec67UL) ]
        [ X(0, 0xbfc846100bfc1e43UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0x100000000UL) ] ]

  /// C6.2.53 CINV
  [<TestMethod>]
  member _.``C6.2.53 CINV``() =
    check "5a811020" []
      [ [ X(0, 0x658eec67UL) ]
        [ X(0, 0xf403e1bdUL) ]
        [ X(0, 0xfffffffeUL) ]
        [ X(0, 0x0UL) ] ]
    check "da811020" []
      [ [ X(0, 0xbeeb8da1658eec67UL) ]
        [ X(0, 0x4037b9eff403e1bdUL) ]
        [ X(0, 0xfffffffffffffffeUL) ]
        [ X(0, 0x100000000UL) ] ]

  /// C6.2.54 CLREX
  [<TestMethod>]
  member _.``C6.2.54 CLREX``() =
    check "d5033f5f" [] [ []; []; []; [] ]

  /// C6.2.55 CLS
  [<TestMethod>]
  member _.``C6.2.55 CLS``() =
    check "5ac01420" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0x3UL) ]
        [ X(0, 0x1eUL) ]
        [ X(0, 0x1fUL) ] ]
    check "0e204820" []
      [ [ V(0, 0x100010202UL, 0x0UL) ]
        [ V(0, 0x1000100030001UL, 0x0UL) ]
        [ V(0, 0x70700070707UL, 0x0UL) ]
        [ V(0, 0x3070707070707UL, 0x0UL) ] ]
    check "4e204820" []
      [ [ V(0, 0x100010202UL, 0x1000001030502UL) ]
        [ V(0, 0x1000100030001UL, 0x201020000020000UL) ]
        [ V(0, 0x70700070707UL, 0x70700010707UL) ]
        [ V(0, 0x3070707070707UL, 0x100000000000000UL) ] ]
    check "0e604820" []
      [ [ V(0, 0x2UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0xf0000000fUL, 0x0UL) ]
        [ V(0, 0xf000f000fUL, 0x0UL) ] ]
    check "4e604820" []
      [ [ V(0, 0x2UL, 0x10005UL) ]
        [ V(0, 0x0UL, 0x2000200000000UL) ]
        [ V(0, 0xf0000000fUL, 0xf0000000fUL) ]
        [ V(0, 0xf000f000fUL, 0x1000000000000UL) ] ]
    check "0ea04820" []
      [ [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x1fUL, 0x0UL) ] ]
    check "4ea04820" []
      [ [ V(0, 0x0UL, 0x1UL) ]
        [ V(0, 0x0UL, 0x200000000UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x1fUL, 0x100000000UL) ] ]
    check "dac01420" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0x0UL) ]
        [ X(0, 0x3eUL) ]
        [ X(0, 0x1eUL) ] ]

  /// C6.2.56 CLZ
  [<TestMethod>]
  member _.``C6.2.56 CLZ``() =
    check "5ac01020" []
      [ [ X(0, 0x1UL) ]
        [ X(0, 0x4UL) ]
        [ X(0, 0x1fUL) ]
        [ X(0, 0x20UL) ] ]
    check "2e204820" []
      [ [ V(0, 0x101010201000003UL, 0x0UL) ]
        [ V(0, 0x100000201040002UL, 0x0UL) ]
        [ V(0, 0x100080800080808UL, 0x0UL) ]
        [ V(0, 0x104080808080808UL, 0x0UL) ] ]
    check "6e204820" []
      [ [ V(0, 0x101010201000003UL, 0x100000102000003UL) ]
        [ V(0, 0x100000201040002UL, 0x2030101030000UL) ]
        [ V(0, 0x100080800080808UL, 0x100080801000808UL) ]
        [ V(0, 0x104080808080808UL, 0x200000000000000UL) ] ]
    check "2e604820" []
      [ [ V(0, 0x1000100010000UL, 0x0UL) ]
        [ V(0, 0x1000000010000UL, 0x0UL) ]
        [ V(0, 0x1001000000010UL, 0x0UL) ]
        [ V(0, 0x1001000100010UL, 0x0UL) ] ]
    check "6e604820" []
      [ [ V(0, 0x1000100010000UL, 0x1000000020000UL) ]
        [ V(0, 0x1000000010000UL, 0x300010000UL) ]
        [ V(0, 0x1001000000010UL, 0x1001000010010UL) ]
        [ V(0, 0x1001000100010UL, 0x2000000000000UL) ] ]
    check "2ea04820" []
      [ [ V(0, 0x100000001UL, 0x0UL) ]
        [ V(0, 0x100000001UL, 0x0UL) ]
        [ V(0, 0x100000000UL, 0x0UL) ]
        [ V(0, 0x100000020UL, 0x0UL) ] ]
    check "6ea04820" []
      [ [ V(0, 0x100000001UL, 0x100000002UL) ]
        [ V(0, 0x100000001UL, 0x1UL) ]
        [ V(0, 0x100000000UL, 0x100000001UL) ]
        [ V(0, 0x100000020UL, 0x200000000UL) ] ]
    check "dac01020" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0x0UL) ]
        [ X(0, 0x3fUL) ]
        [ X(0, 0x1fUL) ] ]

  /// C6.2.57 CMN (extended register)
  [<TestMethod>]
  member _.``C6.2.57 CMN``() =
    check "2b02003f" []
      [ [ NZCV 0x20000000UL ]
        [ NZCV 0x80000000UL ]
        []
        [ NZCV 0x0UL ] ]
    check "3100403f" []
      [ [ NZCV 0x0UL ]
        [ NZCV 0x0UL ]
        [ NZCV 0x0UL ]
        [ NZCV 0x0UL ] ]
    check "b100403f" []
      [ [ NZCV 0x80000000UL ]
        [ NZCV 0x80000000UL ]
        [ NZCV 0x0UL ]
        [ NZCV 0x0UL ] ]
    check "ab02003f" []
      [ [ NZCV 0xa0000000UL ]
        [ NZCV 0x30000000UL ]
        []
        [ NZCV 0x0UL ] ]
    check "b140043f" []
      [ [ NZCV 0x80000000UL ]
        [ NZCV 0x80000000UL ]
        [ NZCV 0x0UL ]
        [ NZCV 0x0UL ] ]

  /// C6.2.60 CMP (extended register)
  [<TestMethod>]
  member _.``C6.2.60 CMP``() =
    check "6b02003f" []
      [ [ NZCV 0x0UL ]
        [ NZCV 0x0UL ]
        [ NZCV 0x0UL ]
        [ NZCV 0x80000000UL ] ]
    check "7100403f" []
      [ [ NZCV 0x20000000UL ]
        [ NZCV 0x20000000UL ]
        [ NZCV 0x80000000UL ]
        [ NZCV 0x80000000UL ] ]
    check "f100403f" []
      [ [ NZCV 0xa0000000UL ]
        [ NZCV 0xa0000000UL ]
        [ NZCV 0x80000000UL ]
        [ NZCV 0x20000000UL ] ]
    check "eb02003f" []
      [ [ NZCV 0x80000000UL ]
        [ NZCV 0x20000000UL ]
        [ NZCV 0x0UL ]
        [ NZCV 0x80000000UL ] ]
    check "f11ffc3f" []
      [ [ NZCV 0xa0000000UL ]
        [ NZCV 0xa0000000UL ]
        [ NZCV 0x80000000UL ]
        [ NZCV 0x20000000UL ] ]

  /// C6.2.63 CMPP
  [<TestMethod>]
  member _.``C6.2.63 CMPP``() =
    check "bac1001f" []
      [ [ NZCV 0x0UL ]
        [ NZCV 0x0UL ]
        [ NZCV 0x80000000UL ]
        [ NZCV 0x80000000UL ] ]

  /// C6.2.64 CNEG
  [<TestMethod>]
  member _.``C6.2.64 CNEG``() =
    check "5a811420" []
      [ [ X(0, 0x658eec67UL) ]
        [ X(0, 0xf403e1beUL) ]
        [ X(0, 0xffffffffUL) ]
        [ X(0, 0x0UL) ] ]
    check "da811420" []
      [ [ X(0, 0xbeeb8da1658eec67UL) ]
        [ X(0, 0x4037b9eff403e1beUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x100000000UL) ] ]

  /// C6.2.65 CPP
  [<TestMethod>]
  member _.``C6.2.65 CPP``() =
    raises BinIR.SideEffect.UndefinedInstruction "d50b73e0"

  /// C6.2.66 CRC32B, CRC32H, CRC32W, CRC32X
  [<TestMethod>]
  member _.``C6.2.66 CRC32B``() =
    check "1ac24020" []
      [ [ X(0, 0x5f6006e4UL) ]
        [ X(0, 0x3308e1fbUL) ]
        [ X(0, 0x5a05df1bUL) ]
        [ X(0, 0x1b01a57bUL) ] ]

  /// C6.2.66 CRC32B, CRC32H, CRC32W, CRC32X
  [<TestMethod>]
  member _.``C6.2.66 CRC32H``() =
    check "1ac24420" []
      [ [ X(0, 0xbc39e31cUL) ]
        [ X(0, 0xd83e233bUL) ]
        [ X(0, 0xa73d23beUL) ]
        [ X(0, 0xdccd0c6aUL) ] ]

  /// C6.2.66 CRC32B, CRC32H, CRC32W, CRC32X
  [<TestMethod>]
  member _.``C6.2.66 CRC32W``() =
    check "1ac24820" []
      [ [ X(0, 0x186b2d43UL) ]
        [ X(0, 0xd70bbc65UL) ]
        [ X(0, 0x66074786UL) ]
        [ X(0, 0x4a691fa1UL) ] ]

  /// C6.2.66 CRC32B, CRC32H, CRC32W, CRC32X
  [<TestMethod>]
  member _.``C6.2.66 CRC32X``() =
    check "9ac24c20" []
      [ [ X(0, 0x290714a8UL) ]
        [ X(0, 0x80b57c0aUL) ]
        [ X(0, 0x88cc00ebUL) ]
        [ X(0, 0x8af2fdecUL) ] ]

  /// C6.2.67 CRC32CB, CRC32CH, CRC32CW, CRC32CX
  [<TestMethod>]
  member _.``C6.2.67 CRC32CB``() =
    check "1ac25020" []
      [ [ X(0, 0x48341c91UL) ]
        [ X(0, 0xdee523afUL) ]
        [ X(0, 0x5f16d052UL) ]
        [ X(0, 0x64d4cecfUL) ] ]

  /// C6.2.67 CRC32CB, CRC32CH, CRC32CW, CRC32CX
  [<TestMethod>]
  member _.``C6.2.67 CRC32CH``() =
    check "1ac25420" []
      [ [ X(0, 0x45f85c7UL) ]
        [ X(0, 0xbef34586UL) ]
        [ X(0, 0x1d3cefa5UL) ]
        [ X(0, 0xf92e00e1UL) ] ]

  /// C6.2.67 CRC32CB, CRC32CH, CRC32CW, CRC32CX
  [<TestMethod>]
  member _.``C6.2.67 CRC32CW``() =
    check "1ac25820" []
      [ [ X(0, 0xc45238a0UL) ]
        [ X(0, 0xc1fff7edUL) ]
        [ X(0, 0x6add1e80UL) ]
        [ X(0, 0x91d3be47UL) ] ]

  /// C6.2.67 CRC32CB, CRC32CH, CRC32CW, CRC32CX
  [<TestMethod>]
  member _.``C6.2.67 CRC32CX``() =
    check "9ac25c20" []
      [ [ X(0, 0x7fca6a99UL) ]
        [ X(0, 0x7461290eUL) ]
        [ X(0, 0x8d73846aUL) ]
        [ X(0, 0xbf617a94UL) ] ]

  /// C6.2.68 CSDB
  [<TestMethod>]
  member _.``C6.2.68 CSDB``() =
    check "d503229f" [] [ []; []; []; [] ]

  /// C6.2.69 CSEL
  [<TestMethod>]
  member _.``C6.2.69 CSEL``() =
    check "1a820020" []
      [ [ X(0, 0xfb32555eUL) ]
        [ X(0, 0xbfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x55555555UL) ] ]
    check "9a820020" []
      [ [ X(0, 0xf893a2eefb32555eUL) ]
        [ X(0, 0xbfc846100bfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x5555555555555555UL) ] ]

  /// C6.2.70 CSET
  [<TestMethod>]
  member _.``C6.2.70 CSET``() =
    check "1a9f17e0" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "9a9f17e0" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.71 CSETM
  [<TestMethod>]
  member _.``C6.2.71 CSETM``() =
    check "5a9f13e0" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0xffffffffUL) ]
        [ X(0, 0xffffffffUL) ]
        [ X(0, 0x0UL) ] ]
    check "da9f13e0" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.72 CSINC
  [<TestMethod>]
  member _.``C6.2.72 CSINC``() =
    check "1a820420" []
      [ [ X(0, 0xfb32555fUL) ]
        [ X(0, 0xbfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x55555556UL) ] ]
    check "9a820420" []
      [ [ X(0, 0xf893a2eefb32555fUL) ]
        [ X(0, 0xbfc846100bfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x5555555555555556UL) ] ]

  /// C6.2.73 CSINV
  [<TestMethod>]
  member _.``C6.2.73 CSINV``() =
    check "5a820020" []
      [ [ X(0, 0x4cdaaa1UL) ]
        [ X(0, 0xbfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaaaUL) ] ]
    check "da820020" []
      [ [ X(0, 0x76c5d1104cdaaa1UL) ]
        [ X(0, 0xbfc846100bfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaaaaaaaaaaaUL) ] ]

  /// C6.2.74 CSNEG
  [<TestMethod>]
  member _.``C6.2.74 CSNEG``() =
    check "5a820420" []
      [ [ X(0, 0x4cdaaa2UL) ]
        [ X(0, 0xbfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaabUL) ] ]
    check "da820420" []
      [ [ X(0, 0x76c5d1104cdaaa2UL) ]
        [ X(0, 0xbfc846100bfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaaaaaaaaaabUL) ] ]

  /// C6.2.75 DC
  [<TestMethod>]
  member _.``C6.2.75 DC``() =
    check "d50b7b21" [] [ []; []; []; [] ]
    check "d50b7e21" [] [ []; []; []; [] ]

  /// C6.2.76 DCPS1
  [<TestMethod>]
  member _.``C6.2.76 DCPS1``() =
    raises BinIR.SideEffect.UndefinedInstruction "d4a00001"

  /// C6.2.77 DCPS2
  [<TestMethod>]
  member _.``C6.2.77 DCPS2``() =
    raises BinIR.SideEffect.UndefinedInstruction "d4a00002"

  /// C6.2.78 DCPS3
  [<TestMethod>]
  member _.``C6.2.78 DCPS3``() =
    raises BinIR.SideEffect.UndefinedInstruction "d4a00003"

  /// C6.2.79 DGH
  [<TestMethod>]
  member _.``C6.2.79 DGH``() =
    check "d50320df" [] [ []; []; []; [] ]

  /// C6.2.80 DMB
  [<TestMethod>]
  member _.``C6.2.80 DMB``() =
    check "d5033bbf" [] [ []; []; []; [] ]

  /// C6.2.81 DRPS
  [<TestMethod>]
  member _.``C6.2.81 DRPS``() =
    raises BinIR.SideEffect.UndefinedInstruction "d6bf03e0"

  /// C6.2.82 DSB
  [<TestMethod>]
  member _.``C6.2.82 DSB``() =
    check "d5033f9f" [] [ []; []; []; [] ]

  /// C6.2.83 DVP
  [<TestMethod>]
  member _.``C6.2.83 DVP``() =
    raises BinIR.SideEffect.UndefinedInstruction "d50b73a0"

  /// C6.2.84 EON (shifted register)
  [<TestMethod>]
  member _.``C6.2.84 EON``() =
    check "4a220020" []
      [ [ X(0, 0x614346c6UL) ]
        [ X(0, 0x297db292UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaaaUL) ] ]
    check "ca220020" []
      [ [ X(0, 0xb987d0b0614346c6UL) ]
        [ X(0, 0xd84c0550297db292UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaabaaaaaaaaUL) ] ]

  /// C6.2.85 EOR (immediate)
  [<TestMethod>]
  member _.``C6.2.85 EOR``() =
    check "d200cc20" []
      [ [ X(0, 0xb1e482ae6a81e368UL) ]
        [ X(0, 0xb0c7491f04f3114dUL) ]
        [ X(0, 0xf0f0f0f0f0f0f0eUL) ]
        [ X(0, 0xf0f0f0e0f0f0f0fUL) ] ]
    check "521c0020" []
      [ [ X(0, 0x658eec77UL) ]
        [ X(0, 0xbfc1e52UL) ]
        [ X(0, 0x11UL) ]
        [ X(0, 0x10UL) ] ]
    check "d27c0020" []
      [ [ X(0, 0xbeeb8da1658eec77UL) ]
        [ X(0, 0xbfc846100bfc1e52UL) ]
        [ X(0, 0x11UL) ]
        [ X(0, 0x100000010UL) ] ]
    check "4a020020" []
      [ [ X(0, 0x9ebcb939UL) ]
        [ X(0, 0xd6824d6dUL) ]
        [ X(0, 0xfffffffeUL) ]
        [ X(0, 0x55555555UL) ] ]
    check "ca020020" []
      [ [ X(0, 0x46782f4f9ebcb939UL) ]
        [ X(0, 0x27b3faafd6824d6dUL) ]
        [ X(0, 0xfffffffffffffffeUL) ]
        [ X(0, 0x5555555455555555UL) ] ]
    check "2e221c20" []
      [ [ V(0, 0xf7ff410d1e221f10UL, 0x0UL) ]
        [ V(0, 0xe852f51b6dfc3f7UL, 0x0UL) ]
        [ V(0, 0xffffffff80000001UL, 0x0UL) ]
        [ V(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "6e221c20" []
      [ [ V(0, 0xf7ff410d1e221f10UL, 0xcbf8800a70b81ce2UL) ]
        [ V(0, 0xe852f51b6dfc3f7UL, 0xa55131a9bfc62c95UL) ]
        [ V(0, 0xffffffff80000001UL, 0x7f20000000bfffffUL) ]
        [ V(0, 0xc008000000000000UL, 0x404999999999999aUL) ] ]

  /// C6.2.87 ERET
  [<TestMethod>]
  member _.``C6.2.87 ERET``() =
    raises BinIR.SideEffect.UndefinedInstruction "d69f03e0"

  /// C6.2.88 ERETAA, ERETAB
  [<TestMethod>]
  member _.``C6.2.88 ERETAA``() =
    raises BinIR.SideEffect.UndefinedInstruction "d69f0bff"

  /// C6.2.88 ERETAA, ERETAB
  [<TestMethod>]
  member _.``C6.2.88 ERETAB``() =
    raises BinIR.SideEffect.UndefinedInstruction "d69f0fff"

  /// C6.2.89 ESB
  [<TestMethod>]
  member _.``C6.2.89 ESB``() =
    check "d503221f" [] [ []; []; []; [] ]

  /// C6.2.90 EXTR
  [<TestMethod>]
  member _.``C6.2.90 EXTR``() =
    check "13820c20" []
      [ [ X(0, 0xff664aabUL) ]
        [ X(0, 0x5bafca65UL) ]
        [ X(0, 0x3fffffffUL) ]
        [ X(0, 0xaaaaaaaUL) ] ]
    check "93c20c20" []
      [ [ X(0, 0xff12745ddf664aabUL) ]
        [ X(0, 0x530f7797fbafca65UL) ]
        [ X(0, 0x3fffffffffffffffUL) ]
        [ X(0, 0xaaaaaaaaaaaaaaaUL) ] ]
    check "93c20020" []
      [ [ X(0, 0xf893a2eefb32555eUL) ]
        [ X(0, 0x987bbcbfdd7e532fUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x5555555555555555UL) ] ]

  /// C6.2.91 GMI
  [<TestMethod>]
  member _.``C6.2.91 GMI``() =
    check "9ac21420" []
      [ [ X(0, 0xf893a2eefb32555eUL) ]
        [ X(0, 0x987bbcbfdd7ed32fUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x5555555555555555UL) ] ]

  /// C6.2.92 HINT
  [<TestMethod>]
  member _.``C6.2.92 HINT``() =
    check "d50320df" [] [ []; []; []; [] ]

  /// C6.2.93 HLT
  [<TestMethod>]
  member _.``C6.2.93 HLT``() =
    raises BinIR.SideEffect.UndefinedInstruction "d4400000"

  /// C6.2.94 HVC
  [<TestMethod>]
  member _.``C6.2.94 HVC``() =
    raises BinIR.SideEffect.UndefinedInstruction "d4000002"

  /// C6.2.95 IC
  [<TestMethod>]
  member _.``C6.2.95 IC``() =
    check "d50b7521" [] [ []; []; []; [] ]

  /// C6.2.96 IRG
  [<TestMethod>]
  member _.``C6.2.96 IRG``() =
    check "9adf1020" []
      [ [ X(0, 0xb0eb8da1658eec67UL) ]
        [ X(0, 0xb0c846100bfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x100000000UL) ] ]
    check "9ac21020" []
      [ [ X(0, 0xb0eb8da1658eec67UL) ]
        [ X(0, 0xb0c846100bfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x100000000UL) ] ]

  /// C6.2.97 ISB
  [<TestMethod>]
  member _.``C6.2.97 ISB``() =
    check "d5033fdf" [] [ []; []; []; [] ]

  /// C6.2.98 LDADDB, LDADDAB, LDADDALB, LDADDLB
  [<TestMethod>]
  member _.``C6.2.98 LDADDAB``() =
    check "38a20020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4adfUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe113UL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL); M(0, 0x55555555555555aaUL) ] ]

  /// C6.2.98 LDADDB, LDADDAB, LDADDALB, LDADDLB
  [<TestMethod>]
  member _.``C6.2.98 LDADDALB``() =
    check "38e20020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4adfUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe113UL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL); M(0, 0x55555555555555aaUL) ] ]
