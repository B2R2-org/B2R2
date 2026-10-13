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
/// One test for each instruction DDI0487F.c describes, STLURH to CMEQ in
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
type ManualLifterTests4() =
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

  /// How a word's statements leave the instruction: the kind of a jump out
  /// of it, or a conditional one.
  let exitOf hex =
    A64Machine.lift hex
    |> Array.tryPick (function
      | InterJmp(Kind = k) -> Some(string k)
      | InterCJmp _ -> Some "InterCJmp"
      | _ -> None)

  /// The statements a word lifts to, as text, without the instruction's
  /// marks.
  let statementsOf hex =
    A64Machine.lift hex
    |> Array.filter (function
      | ISMark _ | IEMark _ -> false
      | _ -> true)
    |> Array.map string
    |> List.ofArray

  /// The pointer the authentication tests sign: canonical and in the lower
  /// half, its field above bit 47 a copy of bit 55.
  let pointer = 0x0000123456789abcUL

  /// C6.2.267 STLURH
  [<TestMethod>]
  member _.``C6.2.267 STLURH``() =
    check "59000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e5cc1UL) ]
        [ M(0, 0x912f822b1e8f56ceUL) ]
        []
        [ M(0, 0x555555555555ffffUL) ] ]
    check "59010020" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xdb20290ac13e5cc1UL) ]
        [ M(0, 0x912f822b1e8f56ceUL) ]
        []
        [ M(0, 0x555555555555ffffUL) ] ]

  /// C6.2.268 STLXP
  [<TestMethod>]
  member _.``C6.2.268 STLXP``() =
    check "88238820" [ X(1, 0x2008000UL) ]
      [ [ X(3, 0x1UL) ]
        [ X(3, 0x1UL) ]
        [ X(3, 0x1UL) ]
        [ X(3, 0x1UL) ] ]

  /// C6.2.269 STLXR
  [<TestMethod>]
  member _.``C6.2.269 STLXR``() =
    check "8802fc20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ] ]

  /// C6.2.270 STLXRB
  [<TestMethod>]
  member _.``C6.2.270 STLXRB``() =
    check "0802fc20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ] ]

  /// C6.2.271 STLXRH
  [<TestMethod>]
  member _.``C6.2.271 STLXRH``() =
    check "4802fc20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ] ]

  /// C6.2.272 STNP
  [<TestMethod>]
  member _.``C6.2.272 STNP``() =
    check "28000c22" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xee42c90bfb32555eUL) ]
        [ M(0, 0xffe7f664dd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ M(0, 0xaaaaaaaa55555555UL) ] ]
    check "28020c22" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xee42c90bfb32555eUL) ]
        [ M(0, 0xffe7f664dd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ M(0, 0xaaaaaaaa55555555UL) ] ]
    check "a8000c22" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xf893a2eefb32555eUL); M(8, 0x71c18690ee42c90bUL) ]
        [ M(0, 0x987bbcbfdd7e532fUL); M(8, 0xc3f2827affe7f664UL) ]
        [ M(0, 0xffffffffffffffffUL); M(8, 0x8000000000000000UL) ]
        [] ]
    check "a8010c22" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xf893a2eefb32555eUL); M(8, 0x71c18690ee42c90bUL) ]
        [ M(0, 0x987bbcbfdd7e532fUL); M(8, 0xc3f2827affe7f664UL) ]
        [ M(0, 0xffffffffffffffffUL); M(8, 0x8000000000000000UL) ]
        [] ]
    check "28000420" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x200800089025cc1UL) ]
        [ M(0, 0x20080001c9756ceUL) ]
        [ M(0, 0x200800000000000UL) ]
        [ M(0, 0x2008000ffffffffUL) ] ]

  /// C6.2.273 STP
  [<TestMethod>]
  member _.``C6.2.273 STP``() =
    check "28820c22" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL); M(0, 0xee42c90bfb32555eUL) ]
        [ X(1, 0x2008010UL); M(0, 0xffe7f664dd7e532fUL) ]
        [ X(1, 0x2008010UL); M(0, 0xffffffffUL) ]
        [ X(1, 0x2008010UL); M(0, 0xaaaaaaaa55555555UL) ] ]
    check "a8810c22" [ X(1, 0x2008000UL) ]
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
    check "29820c22" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL); M(0, 0xee42c90bfb32555eUL) ]
        [ X(1, 0x2008000UL); M(0, 0xffe7f664dd7e532fUL) ]
        [ X(1, 0x2008000UL); M(0, 0xffffffffUL) ]
        [ X(1, 0x2008000UL); M(0, 0xaaaaaaaa55555555UL) ] ]
    check "a9810c22" [ X(1, 0x2007ff0UL) ]
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
    check "29000c22" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xee42c90bfb32555eUL) ]
        [ M(0, 0xffe7f664dd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ M(0, 0xaaaaaaaa55555555UL) ] ]
    check "29020c22" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xee42c90bfb32555eUL) ]
        [ M(0, 0xffe7f664dd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ M(0, 0xaaaaaaaa55555555UL) ] ]
    check "a9000c22" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xf893a2eefb32555eUL); M(8, 0x71c18690ee42c90bUL) ]
        [ M(0, 0x987bbcbfdd7e532fUL); M(8, 0xc3f2827affe7f664UL) ]
        [ M(0, 0xffffffffffffffffUL); M(8, 0x8000000000000000UL) ]
        [] ]
    check "a9010c22" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xf893a2eefb32555eUL); M(8, 0x71c18690ee42c90bUL) ]
        [ M(0, 0x987bbcbfdd7e532fUL); M(8, 0xc3f2827affe7f664UL) ]
        [ M(0, 0xffffffffffffffffUL); M(8, 0x8000000000000000UL) ]
        [] ]
    check "28810c22" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008008UL); M(0, 0xee42c90bfb32555eUL) ]
        [ X(1, 0x2008008UL); M(0, 0xffe7f664dd7e532fUL) ]
        [ X(1, 0x2008008UL); M(0, 0xffffffffUL) ]
        [ X(1, 0x2008008UL); M(0, 0xaaaaaaaa55555555UL) ] ]

  /// C6.2.274 STR (immediate)
  [<TestMethod>]
  member _.``C6.2.274 STR``() =
    check "b8010420" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL); M(0, 0xdb20290a89025cc1UL) ]
        [ X(1, 0x2008010UL); M(0, 0x912f822b1c9756ceUL) ]
        [ X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL); M(0, 0x55555555ffffffffUL) ] ]
    check "f8010420" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL); M(0, 0x910a2dec89025cc1UL) ]
        [ X(1, 0x2008010UL); M(0, 0x975835de1c9756ceUL) ]
        [ X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL); M(0, 0xffffffffUL) ] ]
    check "b8010c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL); M(0, 0xdb20290a89025cc1UL) ]
        [ X(1, 0x2008000UL); M(0, 0x912f822b1c9756ceUL) ]
        [ X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL); M(0, 0x55555555ffffffffUL) ] ]
    check "f8010c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL); M(0, 0x910a2dec89025cc1UL) ]
        [ X(1, 0x2008000UL); M(0, 0x975835de1c9756ceUL) ]
        [ X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL); M(0, 0xffffffffUL) ] ]
    check "b9000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290a89025cc1UL) ]
        [ M(0, 0x912f822b1c9756ceUL) ]
        []
        [ M(0, 0x55555555ffffffffUL) ] ]
    check "b9000820" [ X(1, 0x2007ff8UL) ]
      [ [ M(0, 0xdb20290a89025cc1UL) ]
        [ M(0, 0x912f822b1c9756ceUL) ]
        []
        [ M(0, 0x55555555ffffffffUL) ] ]
    check "f9000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x910a2dec89025cc1UL) ]
        [ M(0, 0x975835de1c9756ceUL) ]
        []
        [ M(0, 0xffffffffUL) ] ]
    check "f9000420" [ X(1, 0x2007ff8UL) ]
      [ [ M(0, 0x910a2dec89025cc1UL) ]
        [ M(0, 0x975835de1c9756ceUL) ]
        []
        [ M(0, 0xffffffffUL) ] ]
    check "b8000420" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290a89025cc1UL) ]
        [ M(0, 0x912f822b1c9756ceUL) ]
        []
        [ M(0, 0x55555555ffffffffUL) ] ]

  /// C6.2.276 STRB (immediate)
  [<TestMethod>]
  member _.``C6.2.276 STRB``() =
    check "38010420" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL); M(0, 0xdb20290ac13e4ac1UL) ]
        [ X(1, 0x2008010UL); M(0, 0x912f822b1e8fe1ceUL) ]
        [ X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL); M(0, 0x55555555555555ffUL) ] ]
    check "38010c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL); M(0, 0xdb20290ac13e4ac1UL) ]
        [ X(1, 0x2008000UL); M(0, 0x912f822b1e8fe1ceUL) ]
        [ X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL); M(0, 0x55555555555555ffUL) ] ]
    check "39000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4ac1UL) ]
        [ M(0, 0x912f822b1e8fe1ceUL) ]
        []
        [ M(0, 0x55555555555555ffUL) ] ]
    check "39002020" [ X(1, 0x2007ff8UL) ]
      [ [ M(0, 0xdb20290ac13e4ac1UL) ]
        [ M(0, 0x912f822b1e8fe1ceUL) ]
        []
        [ M(0, 0x55555555555555ffUL) ] ]
    check "38226820" [ X(1, 0x2008000UL); X(2, 0x1UL) ]
      [ [ M(0, 0xdb20290ac13ec181UL) ]
        [ M(0, 0x912f822b1e8fcee4UL) ]
        []
        [ M(0, 0x555555555555ff55UL) ] ]
    check "38000420" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4ac1UL) ]
        [ M(0, 0x912f822b1e8fe1ceUL) ]
        []
        [ M(0, 0x55555555555555ffUL) ] ]

  /// C6.2.278 STRH (immediate)
  [<TestMethod>]
  member _.``C6.2.278 STRH``() =
    check "78010420" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL); M(0, 0xdb20290ac13e5cc1UL) ]
        [ X(1, 0x2008010UL); M(0, 0x912f822b1e8f56ceUL) ]
        [ X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL); M(0, 0x555555555555ffffUL) ] ]
    check "78010c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL); M(0, 0xdb20290ac13e5cc1UL) ]
        [ X(1, 0x2008000UL); M(0, 0x912f822b1e8f56ceUL) ]
        [ X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL); M(0, 0x555555555555ffffUL) ] ]
    check "79000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e5cc1UL) ]
        [ M(0, 0x912f822b1e8f56ceUL) ]
        []
        [ M(0, 0x555555555555ffffUL) ] ]
    check "79001020" [ X(1, 0x2007ff8UL) ]
      [ [ M(0, 0xdb20290ac13e5cc1UL) ]
        [ M(0, 0x912f822b1e8f56ceUL) ]
        []
        [ M(0, 0x555555555555ffffUL) ] ]
    check "78000420" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e5cc1UL) ]
        [ M(0, 0x912f822b1e8f56ceUL) ]
        []
        [ M(0, 0x555555555555ffffUL) ] ]

  /// C6.2.280 STSETB, STSETLB
  [<TestMethod>]
  member _.``C6.2.280 STSETB``() =
    check "3822303f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4adfUL) ]
        [ M(0, 0x912f822b1e8fe1efUL) ]
        [ M(0, 0xffUL) ]
        [] ]

  /// C6.2.280 STSETB, STSETLB
  [<TestMethod>]
  member _.``C6.2.280 STSETLB``() =
    check "3862303f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4adfUL) ]
        [ M(0, 0x912f822b1e8fe1efUL) ]
        [ M(0, 0xffUL) ]
        [] ]

  /// C6.2.281 STSETH, STSETLH
  [<TestMethod>]
  member _.``C6.2.281 STSETH``() =
    check "7822303f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e5fdfUL) ]
        [ M(0, 0x912f822b1e8ff3efUL) ]
        [ M(0, 0xffffUL) ]
        [] ]

  /// C6.2.281 STSETH, STSETLH
  [<TestMethod>]
  member _.``C6.2.281 STSETLH``() =
    check "7862303f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e5fdfUL) ]
        [ M(0, 0x912f822b1e8ff3efUL) ]
        [ M(0, 0xffffUL) ]
        [] ]

  /// C6.2.282 STSET, STSETL
  [<TestMethod>]
  member _.``C6.2.282 STSET``() =
    check "f822303f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xfbb3abeefb3e5fdfUL) ]
        [ M(0, 0x997fbebfdffff3efUL) ]
        [ M(0, 0xffffffffffffffffUL) ]
        [] ]
    check "b822303f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290afb3e5fdfUL) ]
        [ M(0, 0x912f822bdffff3efUL) ]
        [ M(0, 0xffffffffUL) ]
        [] ]

  /// C6.2.282 STSET, STSETL
  [<TestMethod>]
  member _.``C6.2.282 STSETL``() =
    check "b862303f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290afb3e5fdfUL) ]
        [ M(0, 0x912f822bdffff3efUL) ]
        [ M(0, 0xffffffffUL) ]
        [] ]

  /// C6.2.283 STSMAXB, STSMAXLB
  [<TestMethod>]
  member _.``C6.2.283 STSMAXB``() =
    check "3822403f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4a5eUL) ]
        [ M(0, 0x912f822b1e8fe12fUL) ]
        []
        [] ]

  /// C6.2.283 STSMAXB, STSMAXLB
  [<TestMethod>]
  member _.``C6.2.283 STSMAXLB``() =
    check "3862403f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4a5eUL) ]
        [ M(0, 0x912f822b1e8fe12fUL) ]
        []
        [] ]

  /// C6.2.284 STSMAXH, STSMAXLH
  [<TestMethod>]
  member _.``C6.2.284 STSMAXH``() =
    check "7822403f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e555eUL) ]
        [ M(0, 0x912f822b1e8f532fUL) ]
        []
        [] ]

  /// C6.2.284 STSMAXH, STSMAXLH
  [<TestMethod>]
  member _.``C6.2.284 STSMAXLH``() =
    check "7862403f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e555eUL) ]
        [ M(0, 0x912f822b1e8f532fUL) ]
        []
        [] ]

  /// C6.2.285 STSMAX, STSMAXL
  [<TestMethod>]
  member _.``C6.2.285 STSMAX``() =
    check "f822403f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xf893a2eefb32555eUL) ]
        [ M(0, 0x987bbcbfdd7e532fUL) ]
        []
        [] ]
    check "b822403f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290afb32555eUL) ]
        []
        []
        [] ]

  /// C6.2.285 STSMAX, STSMAXL
  [<TestMethod>]
  member _.``C6.2.285 STSMAXL``() =
    check "b862403f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290afb32555eUL) ]
        []
        []
        [] ]

  /// C6.2.286 STSMINB, STSMINLB
  [<TestMethod>]
  member _.``C6.2.286 STSMINB``() =
    check "3822503f" [ X(1, 0x2008000UL) ] [ []; []; [ M(0, 0xffUL) ]; [] ]

  /// C6.2.286 STSMINB, STSMINLB
  [<TestMethod>]
  member _.``C6.2.286 STSMINLB``() =
    check "3862503f" [ X(1, 0x2008000UL) ] [ []; []; [ M(0, 0xffUL) ]; [] ]

  /// C6.2.287 STSMINH, STSMINLH
  [<TestMethod>]
  member _.``C6.2.287 STSMINH``() =
    check "7822503f" [ X(1, 0x2008000UL) ] [ []; []; [ M(0, 0xffffUL) ]; [] ]

  /// C6.2.287 STSMINH, STSMINLH
  [<TestMethod>]
  member _.``C6.2.287 STSMINLH``() =
    check "7862503f" [ X(1, 0x2008000UL) ] [ []; []; [ M(0, 0xffffUL) ]; [] ]

  /// C6.2.288 STSMIN, STSMINL
  [<TestMethod>]
  member _.``C6.2.288 STSMIN``() =
    check "f822503f" [ X(1, 0x2008000UL) ]
      [ []
        []
        [ M(0, 0xffffffffffffffffUL) ]
        [] ]
    check "b822503f" [ X(1, 0x2008000UL) ]
      [ []
        [ M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [] ]

  /// C6.2.288 STSMIN, STSMINL
  [<TestMethod>]
  member _.``C6.2.288 STSMINL``() =
    check "b862503f" [ X(1, 0x2008000UL) ]
      [ []
        [ M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [] ]

  /// C6.2.289 STTR
  [<TestMethod>]
  member _.``C6.2.289 STTR``() =
    check "b8010820" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xdb20290a89025cc1UL) ]
        [ M(0, 0x912f822b1c9756ceUL) ]
        []
        [ M(0, 0x55555555ffffffffUL) ] ]
    check "f8000820" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x910a2dec89025cc1UL) ]
        [ M(0, 0x975835de1c9756ceUL) ]
        []
        [ M(0, 0xffffffffUL) ] ]
    check "f8010820" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0x910a2dec89025cc1UL) ]
        [ M(0, 0x975835de1c9756ceUL) ]
        []
        [ M(0, 0xffffffffUL) ] ]
    check "b8000820" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290a89025cc1UL) ]
        [ M(0, 0x912f822b1c9756ceUL) ]
        []
        [ M(0, 0x55555555ffffffffUL) ] ]

  /// C6.2.290 STTRB
  [<TestMethod>]
  member _.``C6.2.290 STTRB``() =
    check "38010820" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xdb20290ac13e4ac1UL) ]
        [ M(0, 0x912f822b1e8fe1ceUL) ]
        []
        [ M(0, 0x55555555555555ffUL) ] ]
    check "38000820" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4ac1UL) ]
        [ M(0, 0x912f822b1e8fe1ceUL) ]
        []
        [ M(0, 0x55555555555555ffUL) ] ]

  /// C6.2.291 STTRH
  [<TestMethod>]
  member _.``C6.2.291 STTRH``() =
    check "78010820" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xdb20290ac13e5cc1UL) ]
        [ M(0, 0x912f822b1e8f56ceUL) ]
        []
        [ M(0, 0x555555555555ffffUL) ] ]
    check "78000820" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e5cc1UL) ]
        [ M(0, 0x912f822b1e8f56ceUL) ]
        []
        [ M(0, 0x555555555555ffffUL) ] ]

  /// C6.2.292 STUMAXB, STUMAXLB
  [<TestMethod>]
  member _.``C6.2.292 STUMAXB``() =
    check "3822603f" [ X(1, 0x2008000UL) ] [ []; []; [ M(0, 0xffUL) ]; [] ]

  /// C6.2.292 STUMAXB, STUMAXLB
  [<TestMethod>]
  member _.``C6.2.292 STUMAXLB``() =
    check "3862603f" [ X(1, 0x2008000UL) ] [ []; []; [ M(0, 0xffUL) ]; [] ]

  /// C6.2.293 STUMAXH, STUMAXLH
  [<TestMethod>]
  member _.``C6.2.293 STUMAXH``() =
    check "7822603f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e555eUL) ]
        []
        [ M(0, 0xffffUL) ]
        [] ]

  /// C6.2.293 STUMAXH, STUMAXLH
  [<TestMethod>]
  member _.``C6.2.293 STUMAXLH``() =
    check "7862603f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e555eUL) ]
        []
        [ M(0, 0xffffUL) ]
        [] ]

  /// C6.2.294 STUMAX, STUMAXL
  [<TestMethod>]
  member _.``C6.2.294 STUMAX``() =
    check "f822603f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xf893a2eefb32555eUL) ]
        [ M(0, 0x987bbcbfdd7e532fUL) ]
        [ M(0, 0xffffffffffffffffUL) ]
        [] ]
    check "b822603f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290afb32555eUL) ]
        [ M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [] ]

  /// C6.2.294 STUMAX, STUMAXL
  [<TestMethod>]
  member _.``C6.2.294 STUMAXL``() =
    check "b862603f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290afb32555eUL) ]
        [ M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [] ]

  /// C6.2.295 STUMINB, STUMINLB
  [<TestMethod>]
  member _.``C6.2.295 STUMINB``() =
    check "3822703f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4a5eUL) ]
        [ M(0, 0x912f822b1e8fe12fUL) ]
        []
        [] ]

  /// C6.2.295 STUMINB, STUMINLB
  [<TestMethod>]
  member _.``C6.2.295 STUMINLB``() =
    check "3862703f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4a5eUL) ]
        [ M(0, 0x912f822b1e8fe12fUL) ]
        []
        [] ]

  /// C6.2.296 STUMINH, STUMINLH
  [<TestMethod>]
  member _.``C6.2.296 STUMINH``() =
    check "7822703f" [ X(1, 0x2008000UL) ]
      [ []
        [ M(0, 0x912f822b1e8f532fUL) ]
        []
        [] ]

  /// C6.2.296 STUMINH, STUMINLH
  [<TestMethod>]
  member _.``C6.2.296 STUMINLH``() =
    check "7862703f" [ X(1, 0x2008000UL) ]
      [ []
        [ M(0, 0x912f822b1e8f532fUL) ]
        []
        [] ]

  /// C6.2.297 STUMIN, STUMINL
  [<TestMethod>]
  member _.``C6.2.297 STUMIN``() =
    check "f822703f" [ X(1, 0x2008000UL) ] [ []; []; []; [] ]
    check "b822703f" [ X(1, 0x2008000UL) ] [ []; []; []; [] ]

  /// C6.2.297 STUMIN, STUMINL
  [<TestMethod>]
  member _.``C6.2.297 STUMINL``() =
    check "b862703f" [ X(1, 0x2008000UL) ] [ []; []; []; [] ]

  /// C6.2.298 STUR
  [<TestMethod>]
  member _.``C6.2.298 STUR``() =
    check "b8010020" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xdb20290a89025cc1UL) ]
        [ M(0, 0x912f822b1c9756ceUL) ]
        []
        [ M(0, 0x55555555ffffffffUL) ] ]
    check "f8000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x910a2dec89025cc1UL) ]
        [ M(0, 0x975835de1c9756ceUL) ]
        []
        [ M(0, 0xffffffffUL) ] ]
    check "f8010020" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0x910a2dec89025cc1UL) ]
        [ M(0, 0x975835de1c9756ceUL) ]
        []
        [ M(0, 0xffffffffUL) ] ]
    check "b8000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290a89025cc1UL) ]
        [ M(0, 0x912f822b1c9756ceUL) ]
        []
        [ M(0, 0x55555555ffffffffUL) ] ]

  /// C6.2.299 STURB
  [<TestMethod>]
  member _.``C6.2.299 STURB``() =
    check "38010020" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xdb20290ac13e4ac1UL) ]
        [ M(0, 0x912f822b1e8fe1ceUL) ]
        []
        [ M(0, 0x55555555555555ffUL) ] ]
    check "38000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4ac1UL) ]
        [ M(0, 0x912f822b1e8fe1ceUL) ]
        []
        [ M(0, 0x55555555555555ffUL) ] ]

  /// C6.2.300 STURH
  [<TestMethod>]
  member _.``C6.2.300 STURH``() =
    check "78010020" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xdb20290ac13e5cc1UL) ]
        [ M(0, 0x912f822b1e8f56ceUL) ]
        []
        [ M(0, 0x555555555555ffffUL) ] ]
    check "78000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e5cc1UL) ]
        [ M(0, 0x912f822b1e8f56ceUL) ]
        []
        [ M(0, 0x555555555555ffffUL) ] ]

  /// C6.2.301 STXP
  [<TestMethod>]
  member _.``C6.2.301 STXP``() =
    check "88230820" [ X(1, 0x2008000UL) ]
      [ [ X(3, 0x1UL) ]
        [ X(3, 0x1UL) ]
        [ X(3, 0x1UL) ]
        [ X(3, 0x1UL) ] ]

  /// C6.2.302 STXR
  [<TestMethod>]
  member _.``C6.2.302 STXR``() =
    check "88027c20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ] ]

  /// C6.2.303 STXRB
  [<TestMethod>]
  member _.``C6.2.303 STXRB``() =
    check "08027c20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ] ]

  /// C6.2.304 STXRH
  [<TestMethod>]
  member _.``C6.2.304 STXRH``() =
    check "48027c20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ] ]

  /// C6.2.305 STZ2G
  [<TestMethod>]
  member _.``C6.2.305 STZ2G``() =
    check "d9e00820" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x0UL); M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ]
        [ M(0, 0x0UL); M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ]
        [ M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ]
        [ M(0, 0x0UL); M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ] ]
    check "d9e01420" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL)
          M(0, 0x0UL)
          M(8, 0x0UL)
          M(16, 0x0UL)
          M(24, 0x0UL) ]
        [ X(1, 0x2008010UL)
          M(0, 0x0UL)
          M(8, 0x0UL)
          M(16, 0x0UL)
          M(24, 0x0UL) ]
        [ X(1, 0x2008010UL); M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ]
        [ X(1, 0x2008010UL)
          M(0, 0x0UL)
          M(8, 0x0UL)
          M(16, 0x0UL)
          M(24, 0x0UL) ] ]
    check "d9e01c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL)
          M(0, 0x0UL)
          M(8, 0x0UL)
          M(16, 0x0UL)
          M(24, 0x0UL) ]
        [ X(1, 0x2008000UL)
          M(0, 0x0UL)
          M(8, 0x0UL)
          M(16, 0x0UL)
          M(24, 0x0UL) ]
        [ X(1, 0x2008000UL); M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ]
        [ X(1, 0x2008000UL)
          M(0, 0x0UL)
          M(8, 0x0UL)
          M(16, 0x0UL)
          M(24, 0x0UL) ] ]
    check "d9e01820" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0x0UL); M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ]
        [ M(0, 0x0UL); M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ]
        [ M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ]
        [ M(0, 0x0UL); M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ] ]
    check "d9e00420" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x0UL); M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ]
        [ M(0, 0x0UL); M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ]
        [ M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ]
        [ M(0, 0x0UL); M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ] ]

  /// C6.2.306 STZG
  [<TestMethod>]
  member _.``C6.2.306 STZG``() =
    check "d9600820" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x0UL); M(8, 0x0UL) ]
        [ M(0, 0x0UL); M(8, 0x0UL) ]
        [ M(8, 0x0UL) ]
        [ M(0, 0x0UL); M(8, 0x0UL) ] ]
    check "d9601420" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL); M(0, 0x0UL); M(8, 0x0UL) ]
        [ X(1, 0x2008010UL); M(0, 0x0UL); M(8, 0x0UL) ]
        [ X(1, 0x2008010UL); M(8, 0x0UL) ]
        [ X(1, 0x2008010UL); M(0, 0x0UL); M(8, 0x0UL) ] ]
    check "d9601c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL); M(0, 0x0UL); M(8, 0x0UL) ]
        [ X(1, 0x2008000UL); M(0, 0x0UL); M(8, 0x0UL) ]
        [ X(1, 0x2008000UL); M(8, 0x0UL) ]
        [ X(1, 0x2008000UL); M(0, 0x0UL); M(8, 0x0UL) ] ]
    check "d9601820" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0x0UL); M(8, 0x0UL) ]
        [ M(0, 0x0UL); M(8, 0x0UL) ]
        [ M(8, 0x0UL) ]
        [ M(0, 0x0UL); M(8, 0x0UL) ] ]
    check "d9600420" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x0UL); M(8, 0x0UL) ]
        [ M(0, 0x0UL); M(8, 0x0UL) ]
        [ M(8, 0x0UL) ]
        [ M(0, 0x0UL); M(8, 0x0UL) ] ]

  /// C6.2.308 SUB (extended register)
  [<TestMethod>]
  member _.``C6.2.308 SUB``() =
    check "4b020020" []
      [ [ X(0, 0x6a5c9709UL) ]
        [ X(0, 0x2e7dcb13UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0xaaaaaaabUL) ] ]
    check "51004020" []
      [ [ X(0, 0x658eec57UL) ]
        [ X(0, 0xbfc1e32UL) ]
        [ X(0, 0xfffffff1UL) ]
        [ X(0, 0xfffffff0UL) ] ]
    check "d1004020" []
      [ [ X(0, 0xbeeb8da1658eec57UL) ]
        [ X(0, 0xbfc846100bfc1e32UL) ]
        [ X(0, 0xfffffffffffffff1UL) ]
        [ X(0, 0xfffffff0UL) ] ]
    check "cb020020" []
      [ [ X(0, 0xc657eab26a5c9709UL) ]
        [ X(0, 0x274c89502e7dcb13UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0xaaaaaaabaaaaaaabUL) ] ]
    check "2e228420" []
      [ [ V(0, 0xe9c3410df2dee110UL, 0x0UL) ]
        [ V(0, 0xfe7bd7b1763f4151UL, 0x0UL) ]
        [ V(0, 0xff010101800000ffUL, 0x0UL) ]
        [ V(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "6e228420" []
      [ [ V(0, 0xe9c3410df2dee110UL, 0xb5a8800ad0a81c22UL) ]
        [ V(0, 0xfe7bd7b1763f4151UL, 0x9bd1f1597f46146dUL) ]
        [ V(0, 0xff010101800000ffUL, 0x7f20000000410101UL) ]
        [ V(0, 0xc008000000000000UL, 0xc0c999999999999aUL) ] ]
    check "2e628420" []
      [ [ V(0, 0xe8c3410df1dee110UL, 0x0UL) ]
        [ V(0, 0xfe7bd6b1753f4051UL, 0x0UL) ]
        [ V(0, 0xff0100018000ffffUL, 0x0UL) ]
        [ V(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "6e628420" []
      [ [ V(0, 0xe8c3410df1dee110UL, 0xb5a8800ad0a81b22UL) ]
        [ V(0, 0xfe7bd6b1753f4051UL, 0x9ad1f0597e46146dUL) ]
        [ V(0, 0xff0100018000ffffUL, 0x7f20000000410001UL) ]
        [ V(0, 0xc008000000000000UL, 0xbfc999999999999aUL) ] ]
    check "2ea28420" []
      [ [ V(0, 0xe8c3410df1dde110UL, 0x0UL) ]
        [ V(0, 0xfe7ad6b1753f4051UL, 0x0UL) ]
        [ V(0, 0xff0000017fffffffUL, 0x0UL) ]
        [ V(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "6ea28420" []
      [ [ V(0, 0xe8c3410df1dde110UL, 0xb5a8800ad0a81b22UL) ]
        [ V(0, 0xfe7ad6b1753f4051UL, 0x9ad0f0597e46146dUL) ]
        [ V(0, 0xff0000017fffffffUL, 0x7f20000000400001UL) ]
        [ V(0, 0xc008000000000000UL, 0xbfc999999999999aUL) ] ]
    check "6ee28420" []
      [ [ V(0, 0xe8c3410cf1dde110UL, 0xb5a88009d0a81b22UL) ]
        [ V(0, 0xfe7ad6b0753f4051UL, 0x9ad0f0587e46146dUL) ]
        [ V(0, 0xff0000017fffffffUL, 0x7f20000000400001UL) ]
        [ V(0, 0xc008000000000000UL, 0xbfc999999999999aUL) ] ]
    check "d13ffc20" []
      [ [ X(0, 0xbeeb8da1658edc68UL) ]
        [ X(0, 0xbfc846100bfc0e43UL) ]
        [ X(0, 0xfffffffffffff002UL) ]
        [ X(0, 0xfffff001UL) ] ]

  /// C6.2.311 SUBG
  [<TestMethod>]
  member _.``C6.2.311 SUBG``() =
    check "d1800020" []
      [ [ X(0, 0xb0eb8da1658eec67UL) ]
        [ X(0, 0xb0c846100bfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x100000000UL) ] ]

  /// C6.2.312 SUBP
  [<TestMethod>]
  member _.``C6.2.312 SUBP``() =
    check "9ac20020" []
      [ [ X(0, 0x57eab26a5c9709UL) ]
        [ X(0, 0xff4c89502e7dcb13UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0xffaaaaabaaaaaaabUL) ] ]

  /// C6.2.313 SUBPS
  [<TestMethod>]
  member _.``C6.2.313 SUBPS``() =
    check "bac20020" []
      [ [ X(0, 0x57eab26a5c9709UL); NZCV 0x20000000UL ]
        [ X(0, 0xff4c89502e7dcb13UL); NZCV 0xa0000000UL ]
        [ X(0, 0x2UL); NZCV 0x0UL ]
        [ X(0, 0xffaaaaabaaaaaaabUL); NZCV 0x80000000UL ] ]

  /// C6.2.314 SUBS (extended register)
  [<TestMethod>]
  member _.``C6.2.314 SUBS``() =
    check "6b020020" []
      [ [ X(0, 0x6a5c9709UL); NZCV 0x0UL ]
        [ X(0, 0x2e7dcb13UL); NZCV 0x0UL ]
        [ X(0, 0x2UL); NZCV 0x0UL ]
        [ X(0, 0xaaaaaaabUL); NZCV 0x80000000UL ] ]
    check "71004020" []
      [ [ X(0, 0x658eec57UL); NZCV 0x20000000UL ]
        [ X(0, 0xbfc1e32UL); NZCV 0x20000000UL ]
        [ X(0, 0xfffffff1UL); NZCV 0x80000000UL ]
        [ X(0, 0xfffffff0UL); NZCV 0x80000000UL ] ]
    check "f1004020" []
      [ [ X(0, 0xbeeb8da1658eec57UL); NZCV 0xa0000000UL ]
        [ X(0, 0xbfc846100bfc1e32UL); NZCV 0xa0000000UL ]
        [ X(0, 0xfffffffffffffff1UL); NZCV 0x80000000UL ]
        [ X(0, 0xfffffff0UL); NZCV 0x20000000UL ] ]
    check "eb020020" []
      [ [ X(0, 0xc657eab26a5c9709UL); NZCV 0x80000000UL ]
        [ X(0, 0x274c89502e7dcb13UL); NZCV 0x20000000UL ]
        [ X(0, 0x2UL); NZCV 0x0UL ]
        [ X(0, 0xaaaaaaabaaaaaaabUL); NZCV 0x80000000UL ] ]
    check "f1600020" []
      [ [ X(0, 0xbeeb8da1650eec67UL); NZCV 0xa0000000UL ]
        [ X(0, 0xbfc846100b7c1e42UL); NZCV 0xa0000000UL ]
        [ X(0, 0xffffffffff800001UL); NZCV 0x80000000UL ]
        [ X(0, 0xff800000UL); NZCV 0x20000000UL ] ]

  /// <summary>
  /// SVC calls the kernel the oracle runs under, which would make a system
  /// call of whatever X8 holds, so it is not run. What the manual fixes is
  /// checked instead (C6.2.317): it ends the instruction in an exception
  /// that carries its 16-bit immediate, over every input set.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.317 SVC``() =
    for k in 0 .. A64Machine.sets - 1 do
      let found hex = A64Machine.effectsOver hex [] k
      let svc n = BinIR.SideEffect.Interrupt n
      Assert.AreEqual<BinIR.SideEffect list>([ svc 0 ], found "d4000001")
      Assert.AreEqual<BinIR.SideEffect list>([ svc 0x802 ], found "d4010041")

  /// C6.2.318 SWPB, SWPAB, SWPALB, SWPLB
  [<TestMethod>]
  member _.``C6.2.318 SWPAB``() =
    check "38a28020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4a5eUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe12fUL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.318 SWPB, SWPAB, SWPALB, SWPLB
  [<TestMethod>]
  member _.``C6.2.318 SWPALB``() =
    check "38e28020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4a5eUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe12fUL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.318 SWPB, SWPAB, SWPALB, SWPLB
  [<TestMethod>]
  member _.``C6.2.318 SWPB``() =
    check "38228020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4a5eUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe12fUL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.318 SWPB, SWPAB, SWPALB, SWPLB
  [<TestMethod>]
  member _.``C6.2.318 SWPLB``() =
    check "38628020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4a5eUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe12fUL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.319 SWPH, SWPAH, SWPALH, SWPLH
  [<TestMethod>]
  member _.``C6.2.319 SWPAH``() =
    check "78a28020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e555eUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f532fUL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.319 SWPH, SWPAH, SWPALH, SWPLH
  [<TestMethod>]
  member _.``C6.2.319 SWPALH``() =
    check "78e28020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e555eUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f532fUL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.319 SWPH, SWPAH, SWPALH, SWPLH
  [<TestMethod>]
  member _.``C6.2.319 SWPH``() =
    check "78228020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e555eUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f532fUL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.319 SWPH, SWPAH, SWPALH, SWPLH
  [<TestMethod>]
  member _.``C6.2.319 SWPLH``() =
    check "78628020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e555eUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f532fUL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.320 SWP, SWPA, SWPAL, SWPL
  [<TestMethod>]
  member _.``C6.2.320 SWP``() =
    check "f8228020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL); M(0, 0xf893a2eefb32555eUL) ]
        [ X(0, 0x912f822b1e8fe1e4UL); M(0, 0x987bbcbfdd7e532fUL) ]
        [ M(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x5555555555555555UL) ] ]
    check "b8228020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb32555eUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.320 SWP, SWPA, SWPAL, SWPL
  [<TestMethod>]
  member _.``C6.2.320 SWPA``() =
    check "b8a28020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb32555eUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.320 SWP, SWPA, SWPAL, SWPL
  [<TestMethod>]
  member _.``C6.2.320 SWPAL``() =
    check "b8e28020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb32555eUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.320 SWP, SWPA, SWPAL, SWPL
  [<TestMethod>]
  member _.``C6.2.320 SWPL``() =
    check "b8628020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb32555eUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.321 SXTB
  [<TestMethod>]
  member _.``C6.2.321 SXTB``() =
    check "13001c20" []
      [ [ X(0, 0x67UL) ]
        [ X(0, 0x42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "93401c20" []
      [ [ X(0, 0x67UL) ]
        [ X(0, 0x42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.322 SXTH
  [<TestMethod>]
  member _.``C6.2.322 SXTH``() =
    check "13003c20" []
      [ [ X(0, 0xffffec67UL) ]
        [ X(0, 0x1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "93403c20" []
      [ [ X(0, 0xffffffffffffec67UL) ]
        [ X(0, 0x1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.323 SXTW
  [<TestMethod>]
  member _.``C6.2.323 SXTW``() =
    check "93407c20" []
      [ [ X(0, 0x658eec67UL) ]
        [ X(0, 0xbfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.324 SYS
  [<TestMethod>]
  member _.``C6.2.324 SYS``() =
    raises BinIR.SideEffect.UndefinedInstruction "d50b7380"
    raises BinIR.SideEffect.UndefinedInstruction "d50b73e0"
    raises BinIR.SideEffect.UndefinedInstruction "d50b73a0"
    check "d50b7b21" [] [ []; []; []; [] ]
    raises BinIR.SideEffect.UndefinedInstruction "d5087841"
    check "d50b7e21" [] [ []; []; []; [] ]
    check "d50b7521" [] [ []; []; []; [] ]
    raises BinIR.SideEffect.UndefinedInstruction "d508871f"

  /// C6.2.325 SYSL
  [<TestMethod>]
  member _.``C6.2.325 SYSL``() =
    raises BinIR.SideEffect.UndefinedInstruction "d5290000"

  /// <summary>
  /// TBNZ cannot run in the oracle, which has nowhere for it to go, so
  /// this checks the jump: a conditional one out of the instruction, to
  /// its own address plus imm14 times four where the bit it names is 1
  /// and to the next instruction where it is not, with that bit alone
  /// set and alone clear, bit 3, 0 and 63 among them (C6.2.326).
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.326 TBNZ``() =
    Assert.AreEqual<string option>(Some "InterCJmp", exitOf "37000081")
    goesTo "37000081" [ X(1, 0x1UL) ] (A64Machine.code + 0x10UL)
    goesTo "37000081" [ X(1, 0xfffffffffffffffeUL) ] (A64Machine.code + 0x4UL)
    Assert.AreEqual<string option>(Some "InterCJmp", exitOf "b7f80201")
    goesTo "b7f80201" [ X(1, 0x8000000000000000UL) ] (A64Machine.code + 0x40UL)
    goesTo "b7f80201" [ X(1, 0x7fffffffffffffffUL) ] (A64Machine.code + 0x4UL)

  /// <summary>
  /// TBZ cannot run in the oracle, which has nowhere for it to go, so
  /// this checks the jump: a conditional one out of the instruction, to
  /// its own address plus imm14 times four where the bit it names is 0
  /// and to the next instruction where it is not, with that bit alone
  /// set and alone clear, bit 3, 0 and 63 among them (C6.2.327).
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.327 TBZ``() =
    Assert.AreEqual<string option>(Some "InterCJmp", exitOf "36180041")
    goesTo "36180041" [ X(1, 0x8UL) ] (A64Machine.code + 0x4UL)
    goesTo "36180041" [ X(1, 0xfffffffffffffff7UL) ] (A64Machine.code + 0x8UL)
    Assert.AreEqual<string option>(Some "InterCJmp", exitOf "b6f80201")
    goesTo "b6f80201" [ X(1, 0x8000000000000000UL) ] (A64Machine.code + 0x4UL)
    goesTo "b6f80201" [ X(1, 0x7fffffffffffffffUL) ] (A64Machine.code + 0x40UL)

  /// C6.2.328 TLBI
  [<TestMethod>]
  member _.``C6.2.328 TLBI``() =
    raises BinIR.SideEffect.UndefinedInstruction "d508871f"

  /// C6.2.329 TSB CSYNC
  [<TestMethod>]
  member _.``C6.2.329 TSB``() =
    check "d503225f" [] [ []; []; []; [] ]

  /// C6.2.330 TST (immediate)
  [<TestMethod>]
  member _.``C6.2.330 TST``() =
    check "f240783f" []
      [ [ NZCV 0x0UL ]
        [ NZCV 0x0UL ]
        [ NZCV 0x0UL ]
        [ NZCV 0x40000000UL ] ]
    check "721c003f" []
      [ [ NZCV 0x40000000UL ]
        [ NZCV 0x40000000UL ]
        [ NZCV 0x40000000UL ]
        [ NZCV 0x40000000UL ] ]
    check "f27c003f" []
      [ [ NZCV 0x40000000UL ]
        [ NZCV 0x40000000UL ]
        [ NZCV 0x40000000UL ]
        [ NZCV 0x40000000UL ] ]
    check "6a02003f" []
      [ [ NZCV 0x0UL ]
        [ NZCV 0x0UL ]
        [ NZCV 0x0UL ]
        [ NZCV 0x40000000UL ] ]
    check "ea02003f" []
      [ [ NZCV 0x80000000UL ]
        [ NZCV 0x80000000UL ]
        [ NZCV 0x0UL ]
        [ NZCV 0x0UL ] ]

  /// C6.2.332 UBFIZ
  [<TestMethod>]
  member _.``C6.2.332 UBFIZ``() =
    check "531d1020" []
      [ [ X(0, 0x38UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x8UL) ]
        [ X(0, 0x0UL) ] ]
    check "d37d1020" []
      [ [ X(0, 0x38UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x8UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.333 UBFM
  [<TestMethod>]
  member _.``C6.2.333 UBFM``() =
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
    check "531d1020" []
      [ [ X(0, 0x38UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x8UL) ]
        [ X(0, 0x0UL) ] ]
    check "d37d1020" []
      [ [ X(0, 0x38UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x8UL) ]
        [ X(0, 0x0UL) ] ]
    check "53031420" []
      [ [ X(0, 0x4UL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "d3431420" []
      [ [ X(0, 0x4UL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "53031c20" []
      [ [ X(0, 0xcUL) ]
        [ X(0, 0x8UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "d3431c20" []
      [ [ X(0, 0xcUL) ]
        [ X(0, 0x8UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "d3400020" []
      [ [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "53001c20" []
      [ [ X(0, 0x67UL) ]
        [ X(0, 0x42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "53003c20" []
      [ [ X(0, 0xec67UL) ]
        [ X(0, 0x1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "d3430820" []
      [ [ X(0, 0xe000000000000000UL) ]
        [ X(0, 0x4000000000000000UL) ]
        [ X(0, 0x2000000000000000UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.334 UBFX
  [<TestMethod>]
  member _.``C6.2.334 UBFX``() =
    check "53031420" []
      [ [ X(0, 0x4UL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "d3431420" []
      [ [ X(0, 0x4UL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "53031c20" []
      [ [ X(0, 0xcUL) ]
        [ X(0, 0x8UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "d3431c20" []
      [ [ X(0, 0xcUL) ]
        [ X(0, 0x8UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "d3400020" []
      [ [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.335 UDF
  [<TestMethod>]
  member _.``C6.2.335 UDF``() =
    raises BinIR.SideEffect.UndefinedInstruction "00000005"

  /// C6.2.336 UDIV
  [<TestMethod>]
  member _.``C6.2.336 UDIV``() =
    check "1ac20820" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "9ac20820" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0x1UL) ]
        []
        [ X(0, 0x0UL) ] ]

  /// C6.2.337 UMADDL
  [<TestMethod>]
  member _.``C6.2.337 UMADDL``() =
    check "9ba20c20" []
      [ [ X(0, 0xd568a021d659c9ddUL) ]
        [ X(0, 0xce511295cf7cea82UL) ]
        [ X(0, 0x80000000ffffffffUL) ]
        [ X(0, 0xaaaaaaaaaaaaaaaaUL) ] ]

  /// C6.2.338 UMNEGL
  [<TestMethod>]
  member _.``C6.2.338 UMNEGL``() =
    check "9ba2fc20" []
      [ [ X(0, 0x9c58e66f17e8ff2eUL) ]
        [ X(0, 0xf5a16fe5306b0be2UL) ]
        [ X(0, 0xffffffff00000001UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.339 UMSUBL
  [<TestMethod>]
  member _.``C6.2.339 UMSUBL``() =
    check "9ba28c20" []
      [ [ X(0, 0xe1a6d00062bc839UL) ]
        [ X(0, 0xb993f26030530246UL) ]
        [ X(0, 0x7fffffff00000001UL) ]
        [ X(0, 0xaaaaaaaaaaaaaaaaUL) ] ]

  /// C6.2.340 UMULH
  [<TestMethod>]
  member _.``C6.2.340 UMULH``() =
    check "9bc27c20" []
      [ [ X(0, 0xb9624bf9f80411efUL) ]
        [ X(0, 0x723b9c3a00a20a3fUL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.341 UMULL
  [<TestMethod>]
  member _.``C6.2.341 UMULL``() =
    check "2f52a020" []
      [ [ V(0, 0x18c232484c27c3c8UL, 0x2630163e25c81aa2UL) ]
        [ V(0, 0x56d1e330906f4140UL, 0x502c5a8077c73b10UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ] ]
    check "2fa2a020" []
      [ [ V(0, 0x26997fa272e2cbb8UL, 0x3b88d204d6ed363eUL) ]
        [ V(0, 0x212945b6a627d850UL, 0x1e9f5809ce1948c4UL) ]
        [ V(0, 0x403fffff80000000UL, 0x3fffbfff80800000UL) ]
        [ V(0, 0x0UL, 0x2004000000000000UL) ] ]
    check "2e22c020" []
      [ [ V(0, 0x1830da48df200150UL, 0x3b103bde13f2063eUL) ]
        [ V(0, 0x56770c3039661dacUL, 0x1e3f3c28580410c4UL) ]
        [ V(0, 0x0UL, 0x3f803f8000000000UL) ]
        [ V(0, 0x0UL, 0x2000000000000000UL) ] ]
    check "2e62c020" []
      [ [ V(0, 0x18c23248df466550UL, 0x3b8882de1409363eUL) ]
        [ V(0, 0x56d1e33039f56bacUL, 0x1e9eef28585848c4UL) ]
        [ V(0, 0x0UL, 0x3fff408000000000UL) ]
        [ V(0, 0x0UL, 0x2004000000000000UL) ] ]
    check "2ea2c020" []
      [ [ V(0, 0x18c2c707315e6550UL, 0x3b88d204d6ed363eUL) ]
        [ V(0, 0x56d2967647926bacUL, 0x1e9f5809ce1948c4UL) ]
        [ V(0, 0x80000000UL, 0x3fffbfff80800000UL) ]
        [ V(0, 0x0UL, 0x2004000000000000UL) ] ]
    check "9ba27c20" []
      [ [ X(0, 0x63a71990e81700d2UL) ]
        [ X(0, 0xa5e901acf94f41eUL) ]
        [ X(0, 0xffffffffUL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.342 UXTB
  [<TestMethod>]
  member _.``C6.2.342 UXTB``() =
    check "53001c20" []
      [ [ X(0, 0x67UL) ]
        [ X(0, 0x42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.343 UXTH
  [<TestMethod>]
  member _.``C6.2.343 UXTH``() =
    check "53003c20" []
      [ [ X(0, 0xec67UL) ]
        [ X(0, 0x1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]

  /// <summary>
  /// WFE waits for an event, which may never come, so the oracle does not
  /// run it. With one thread and nothing to wait for, the manual
  /// leaves it nothing a program can see (C6.2.344): it lifts to no
  /// statement.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.344 WFE``() =
    Assert.AreEqual<string list>([], statementsOf "d503205f")

  /// <summary>
  /// WFI waits for an interrupt, which may never come, so the oracle does not
  /// run it. With one thread and nothing to wait for, the manual
  /// leaves it nothing a program can see (C6.2.345): it lifts to no
  /// statement.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.345 WFI``() =
    Assert.AreEqual<string list>([], statementsOf "d503207f")

  /// C6.2.346 XAFLAG
  [<TestMethod>]
  member _.``C6.2.346 XAFLAG``() =
    check "d500403f" []
      [ [ NZCV 0x80000000UL ]
        [ NZCV 0x30000000UL ]
        []
        [ NZCV 0x80000000UL ] ]

  /// <summary>
  /// The oracle's process runs with TCR_EL1.TBI0 set, as Linux sets it,
  /// under which Strip() keeps the top byte; this front end models TBI
  /// off for pointer authentication, as stripPAC says, so the oracle's
  /// values are not this model's. What Strip() gives with TBI off is
  /// checked instead (C6.2.347): bit 55 copied over bits 63:48 of X0, over
  /// every input set; and a canonical pointer PAC signed comes back, as
  /// the oracle agrees.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.347 XPACD``() =
    check "dac147e0" []
      [ [ X(0, 0x2dec89025cc1UL) ]
        [ X(0, 0x35de1c9756ceUL) ]
        []
        [] ]
    let back = A64Machine.after [ "dac10820"; "dac147e0" ] [ X(0, pointer) ]
    for k in 0 .. A64Machine.sets - 1 do
      Assert.AreEqual<uint64>(pointer, (back k).Xs[0], "dac147e0")

  /// <summary>
  /// The oracle's process runs with TCR_EL1.TBI0 set, as Linux sets it,
  /// under which Strip() keeps the top byte; this front end models TBI
  /// off for pointer authentication, as stripPAC says, so the oracle's
  /// values are not this model's. What Strip() gives with TBI off is
  /// checked instead (C6.2.347): bit 55 copied over bits 63:48 of X0, over
  /// every input set; and a canonical pointer PAC signed comes back, as
  /// the oracle agrees.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.347 XPACI``() =
    check "dac143e0" []
      [ [ X(0, 0x2dec89025cc1UL) ]
        [ X(0, 0x35de1c9756ceUL) ]
        []
        [] ]
    let back = A64Machine.after [ "dac10020"; "dac143e0" ] [ X(0, pointer) ]
    for k in 0 .. A64Machine.sets - 1 do
      Assert.AreEqual<uint64>(pointer, (back k).Xs[0], "dac143e0")

  /// <summary>
  /// The oracle's process runs with TCR_EL1.TBI0 set, as Linux sets it,
  /// under which Strip() keeps the top byte; this front end models TBI
  /// off for pointer authentication, as stripPAC says, so the oracle's
  /// values are not this model's. What Strip() gives with TBI off is
  /// checked instead (C6.2.347): bit 55 copied over bits 63:48 of X30, over
  /// every input set; and a canonical pointer PAC signed comes back, as
  /// the oracle agrees.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.347 XPACLRI``() =
    check "d50320ff" []
      [ [ X(30, 0xd70b12c5d084UL) ]
        [ X(30, 0xffffd92ab490c639UL) ]
        [ X(30, 0x80000000UL) ]
        [] ]
    let back = A64Machine.after [ "d503233f"; "d50320ff" ] [ X(30, pointer) ]
    for k in 0 .. A64Machine.sets - 1 do
      Assert.AreEqual<uint64>(pointer, (back k).Xs[30], "d50320ff")

  /// C6.2.348 YIELD
  [<TestMethod>]
  member _.``C6.2.348 YIELD``() =
    check "d503203f" [] [ []; []; []; [] ]

  /// C7.2.1 ABS
  [<TestMethod>]
  member _.``C7.2.1 ABS``() =
    check "0e20b820" []
      [ [ V(0, 0x70616f2f4824201cUL, 0x0UL) ]
        [ V(0, 0x57387d255f0f6224UL, 0x0UL) ]
        [ V(0, 0x7f80000080000000UL, 0x0UL) ]
        [ V(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "0e60b820" []
      [ [ V(0, 0x70616f2f48dc1fe4UL, 0x0UL) ]
        [ V(0, 0x57c87cdb5f0f61dcUL, 0x0UL) ]
        [ V(0, 0x7f80000080000000UL, 0x0UL) ]
        [ V(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4e60b820" []
      [ [ V(0, 0x70616f2f48dc1fe4UL, 0x40d67db22ef303e9UL) ]
        [ V(0, 0x57c87cdb5f0f61dcUL, 0x1dcf1b535f1f4f57UL) ]
        [ V(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ V(0, 0x4008000000000000UL, 0x3fb9666766676666UL) ] ]
    check "0ea0b820" []
      [ [ V(0, 0x70616f2f48dce01cUL, 0x0UL) ]
        [ V(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ V(0, 0x7f80000080000000UL, 0x0UL) ]
        [ V(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4ea0b820" []
      [ [ V(0, 0x70616f2f48dce01cUL, 0x40d6824e2ef3fc17UL) ]
        [ V(0, 0x57c883255f0f9e24UL, 0x1dcee4ad5f1fb0a9UL) ]
        [ V(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ V(0, 0x4008000000000000UL, 0x3fb9999966666666UL) ] ]
    check "4ee0b820" []
      [ [ V(0, 0x70616f2f48dce01cUL, 0x40d6824e2ef3fc17UL) ]
        [ V(0, 0x57c883255f0f9e24UL, 0x1dcee4aca0e04f57UL) ]
        [ V(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ V(0, 0x4008000000000000UL, 0x3fb999999999999aUL) ] ]
    check "4e20b820" []
      [ [ V(0, 0x70616f2f4824201cUL, 0x402a7e4e2e0d0417UL) ]
        [ V(0, 0x57387d255f0f6224UL, 0x1e311b535f1f5057UL) ]
        [ V(0, 0x7f80000080000000UL, 0x7f6000007f400000UL) ]
        [ V(0, 0x4008000000000000UL, 0x3f47676767676766UL) ] ]

  /// C7.2.3 ADDHN, ADDHN2
  [<TestMethod>]
  member _.``C7.2.3 ADDHN``() =
    check "0e624020" []
      [ [ V(0, 0xcc048d3ff7ff9fdbUL, 0x0UL) ]
        [ V(0, 0x29913ff9b11648dfUL, 0x0UL) ]
        [ V(0, 0x8020ff3fffff8000UL, 0x0UL) ]
        [ V(0, 0xbfa99999c0080000UL, 0x0UL) ] ]
    check "0ea24020" []
      [ [ V(0, 0xcc048492f7ff9d51UL, 0x0UL) ]
        [ V(0, 0x2991464eb1162f9aUL, 0x0UL) ]
        [ V(0, 0x80200000ffffffffUL, 0x0UL) ]
        [ V(0, 0xbfa99999c0080000UL, 0x0UL) ] ]
    check "0e224020" []
      [ [ V(0, 0xcc848dddf79d9fdfUL, 0x0UL) ]
        [ V(0, 0x29463f4cb12f48fbUL, 0x0UL) ]
        [ V(0, 0x8000ffffffff8000UL, 0x0UL) ]
        [ V(0, 0xbf999999c0000000UL, 0x0UL) ] ]

  /// C7.2.3 ADDHN, ADDHN2
  [<TestMethod>]
  member _.``C7.2.3 ADDHN2``() =
    check "4e624020" []
      [ [ V(0, 0x962b1967c90789baUL, 0xcc048d3ff7ff9fdbUL) ]
        [ V(0, 0x9a7aa72430f9ca55UL, 0x29913ff9b11648dfUL) ]
        [ V(0, 0xbfc000003f800000UL, 0x8020ff3fffff8000UL) ]
        [ V(0, 0x3ff0000000000000UL, 0xbfa99999c0080000UL) ] ]
    check "4ea24020" []
      [ [ V(0, 0x962b1967c90789baUL, 0xcc048492f7ff9d51UL) ]
        [ V(0, 0x9a7aa72430f9ca55UL, 0x2991464eb1162f9aUL) ]
        [ V(0, 0xbfc000003f800000UL, 0x80200000ffffffffUL) ]
        [ V(0, 0x3ff0000000000000UL, 0xbfa99999c0080000UL) ] ]
    check "4e224020" []
      [ [ V(0, 0x962b1967c90789baUL, 0xcc848dddf79d9fdfUL) ]
        [ V(0, 0x9a7aa72430f9ca55UL, 0x29463f4cb12f48fbUL) ]
        [ V(0, 0xbfc000003f800000UL, 0x8000ffffffff8000UL) ]
        [ V(0, 0x3ff0000000000000UL, 0xbf999999c0000000UL) ] ]

  /// C7.2.4 ADDP (scalar)
  [<TestMethod>]
  member _.``C7.2.4 ADDP``() =
    check "0e22bc20" []
      [ [ V(0, 0x2550540bd19e24fcUL, 0x0UL) ]
        [ V(0, 0xa620b9301fa86ec2UL, 0x0UL) ]
        [ V(0, 0xfffe0001ff008000UL, 0x0UL) ]
        [ V(0, 0x8000000048000000UL, 0x0UL) ] ]
    check "4e22bc20" []
      [ [ V(0, 0x16d02113d19e24fcUL, 0xb946a9d52550540bUL) ]
        [ V(0, 0x136e7e591fa86ec2UL, 0xa724b9d8a620b930UL) ]
        [ V(0, 0x1f003f00ff008000UL, 0x8000fefefffe0001UL) ]
        [ V(0, 0xf832323348000000UL, 0x6f00000080000000UL) ] ]
    check "0e62bc20" []
      [ [ V(0, 0xb5c0560adf9028f8UL, 0x0UL) ]
        [ V(0, 0x5c147a3daedfd33UL, 0x0UL) ]
        [ V(0, 0x807e00017f808000UL, 0x0UL) ]
        [ V(0, 0x8000000040080000UL, 0x0UL) ] ]
    check "4e62bc20" []
      [ [ V(0, 0xc3242b0adf9028f8UL, 0x8d723f40b5c0560aUL) ]
        [ V(0, 0xfd840fc8daedfd33UL, 0x725a7d1505c147a3UL) ]
        [ V(0, 0x7fa07fc07f808000UL, 0x807f7e807e0001UL) ]
        [ V(0, 0xd952333340080000UL, 0x7ff0000080000000UL) ] ]
    check "0ea2bc20" []
      [ [ V(0, 0xde9d2d2eb93e4f4bUL, 0x0UL) ]
        [ V(0, 0x431e0a47b6d82149UL, 0x0UL) ]
        [ V(0, 0x80800000ff800000UL, 0x0UL) ]
        [ V(0, 0x8000000040080000UL, 0x0UL) ] ]
    check "4ee2bc20" []
      [ [ V(0, 0xb137f17d77d0dc33UL, 0x12cc3066b54ae001UL) ]
        [ V(0, 0x39f99e78be2f4ecdUL, 0xa0add76fcaa9fa0fUL) ]
        [ V(0, 0xff200000ffc00000UL, 0x80ffffff7f800000UL) ]
        [ V(0, 0x7fc199999999999aUL, 0xfff0000000000000UL) ] ]
    check "4ea2bc20" []
      [ [ V(0, 0x6fca7e65b93e4f4bUL, 0xe979e339de9d2d2eUL) ]
        [ V(0, 0x4150cbfcb6d82149UL, 0x2839c736431e0a47UL) ]
        [ V(0, 0xff600000ff800000UL, 0x7fffffff80800000UL) ]
        [ V(0, 0xd953333340080000UL, 0x7ff0000080000000UL) ] ]

  /// C7.2.6 ADDV
  [<TestMethod>]
  member _.``C7.2.6 ADDV``() =
    check "4eb1b820" []
      [ [ V(0, 0x2908cdb0UL, 0x0UL) ]
        [ V(0, 0xf828ed45UL, 0x0UL) ]
        [ V(0, 0xfee00000UL, 0x0UL) ]
        [ V(0, 0x195b3333UL, 0x0UL) ] ]

  /// <summary>
  /// AESD is InvSubBytes(InvShiftRows(Vd EOR Vn)) (C7.2.7); with no AES
  /// unit in IRRunner it is checked as the statements it lifts to: the EOR
  /// of the two registers handed to AESDECLAST with a zero round key,
  /// which is InvShiftRows then InvSubBytes then the EOR of that key.
  /// </summary>
  [<TestMethod>]
  member _.``C7.2.7 AESD``() =
    let expected =
      [ "T_1:I128 := AESDECLAST(((V0B ++ V0A) ^ (V1B ++ V1A)), 0x0:I128):I128"
        "V0A := (T_1:I128[63:0])"
        "V0B := (T_1:I128[127:64])" ]
    Assert.AreEqual<string list>(expected, statementsOf "4e285820")

  /// <summary>
  /// AESE is SubBytes(ShiftRows(Vd EOR Vn)) (C7.2.8); with no AES unit in
  /// IRRunner it is checked as the statements it lifts to: the EOR of the
  /// two registers handed to AESENCLAST with a zero round key, which is
  /// ShiftRows then SubBytes then the EOR of that zero key.
  /// </summary>
  [<TestMethod>]
  member _.``C7.2.8 AESE``() =
    let expected =
      [ "T_1:I128 := AESENCLAST(((V0B ++ V0A) ^ (V1B ++ V1A)), 0x0:I128):I128"
        "V0A := (T_1:I128[63:0])"
        "V0B := (T_1:I128[127:64])" ]
    Assert.AreEqual<string list>(expected, statementsOf "4e284820")

  /// <summary>
  /// AESIMC is InvMixColumns(Vn) (C7.2.9); with no AES unit in IRRunner
  /// it is checked as the statements it lifts to: Vn handed to AESIMC,
  /// which is InvMixColumns.
  /// </summary>
  [<TestMethod>]
  member _.``C7.2.9 AESIMC``() =
    let expected =
      [ "T_1:I128 := AESIMC((V1B ++ V1A)):I128"
        "V0A := (T_1:I128[63:0])"
        "V0B := (T_1:I128[127:64])" ]
    Assert.AreEqual<string list>(expected, statementsOf "4e287820")

  /// <summary>
  /// AESMC is MixColumns(Vn) (C7.2.10); with no AES unit in IRRunner it is
  /// checked as the statements it lifts to: AESDECLAST with a zero key
  /// undoes the ShiftRows and SubBytes AESENC with a zero key then does,
  /// which leaves AESENC's MixColumns alone.
  /// </summary>
  [<TestMethod>]
  member _.``C7.2.10 AESMC``() =
    let expected =
      [ "T_1:I128 := AESDECLAST((V1B ++ V1A), 0x0:I128):I128"
        "T_1:I128 := AESENC(T_1:I128, 0x0:I128):I128"
        "V0A := (T_1:I128[63:0])"
        "V0B := (T_1:I128[127:64])" ]
    Assert.AreEqual<string list>(expected, statementsOf "4e286820")

  /// C7.2.12 BCAX
  [<TestMethod>]
  member _.``C7.2.12 BCAX``() =
    check "ce220c20" []
      [ [ V(0, 0x7073492f1e164c10UL, 0x4ad2800a66f39cf2UL) ]
        [ V(0, 0xe88a34536cf9626UL, 0xe3311353bfdeac91UL) ]
        [ V(0, 0x7f97ffff80000000UL, 0x7fa000003fbfffffUL) ]
        [ V(0, 0xc008000000000000UL, 0x3fb999999999999aUL) ] ]

  /// C7.2.13 BFCVT
  [<TestMethod>]
  member _.``C7.2.13 BFCVT``() =
    check "1e634020" []
      [ [ V(0, 0x48ddUL, 0x0UL); FPSR 0x10UL ]
        [ V(0, 0x5f10UL, 0x0UL); FPSR 0x10UL ]
        [ V(0, 0x8000UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ] ]

  /// C7.2.14 BFCVTN, BFCVTN2
  [<TestMethod>]
  member _.``C7.2.14 BFCVTN``() =
    check "0ea16820" []
      [ [ V(0, 0x40d72ef4706148ddUL, 0x0UL); FPSR 0x10UL ]
        [ V(0, 0xe2315f2057c95f10UL, 0x0UL); FPSR 0x10UL ]
        [ V(0, 0x7fe07fc07f808000UL, 0x0UL); FPSR 0x1UL ]
        [ V(0, 0x3fba999a40080000UL, 0x0UL); FPSR 0x10UL ] ]

  /// C7.2.14 BFCVTN, BFCVTN2
  [<TestMethod>]
  member _.``C7.2.14 BFCVTN2``() =
    check "4ea16820" []
      [ [ V(0, 0x962b1967c90789baUL, 0x40d72ef4706148ddUL); FPSR 0x10UL ]
        [ V(0, 0x9a7aa72430f9ca55UL, 0xe2315f2057c95f10UL); FPSR 0x10UL ]
        [ V(0, 0xbfc000003f800000UL, 0x7fe07fc07f808000UL); FPSR 0x1UL ]
        [ V(0, 0x3ff0000000000000UL, 0x3fba999a40080000UL); FPSR 0x10UL ] ]

  /// C7.2.15 BFDOT (by element)
  [<TestMethod>]
  member _.``C7.2.15 BFDOT``() =
    check "2e42fc20" []
      [ [ V(0, 0x5ddd7bff7f800000UL, 0x0UL) ]
        [ V(0, 0x71a027ffff800000UL, 0x0UL) ]
        [ V(0, 0x7fc000003f800000UL, 0x0UL) ]
        [ V(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "0f62f020" []
      [ [ V(0, 0x5ddd7bffcec580f3UL, 0x0UL) ]
        [ V(0, 0x71a027ff78e50601UL, 0x0UL) ]
        [ V(0, 0x7fc000007fc00000UL, 0x0UL) ]
        [ V(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "4f62f020" []
      [ [ V(0, 0x5ddd7bffcec580f3UL, 0x65ace267eabf1bffUL) ]
        [ V(0, 0x71a027ff78e50601UL, 0xfc0dbd0178fea601UL) ]
        [ V(0, 0x7fc000007fc00000UL, 0x7fc000007fc00000UL) ]
        [] ]
    check "6e42fc20" []
      [ [ V(0, 0x5ddd7bff7f800000UL, 0x65ace2677f800000UL) ]
        [ V(0, 0x71a027ffff800000UL, 0xea1adfffff800000UL) ]
        [ V(0, 0x7fc000003f800000UL, 0x7fc000007fc00000UL) ]
        [ V(0, 0x3ff0000000000000UL, 0x7fc0000000000000UL) ] ]

  /// C7.2.17 BFMLALB, BFMLALT (by element)
  [<TestMethod>]
  member _.``C7.2.17 BFMLALB``() =
    check "2ec2fc20" []
      [ [ V(0, 0x5ddd7c007f800000UL, 0x65ace2687f800000UL); FPSR 0x14UL ]
        [ V(0, 0x9a7aa724bc872bffUL, 0x444bcaba22bb690fUL); FPSR 0x10UL ]
        [ V(0, 0xffff00003f800000UL, 0x3dcccccdffff0000UL) ]
        [] ]

  /// C7.2.17 BFMLALB, BFMLALT (by element)
  [<TestMethod>]
  member _.``C7.2.17 BFMLALT``() =
    check "6ec2fc20" []
      [ [ V(0, 0xb88ade00605a4800UL, 0x65ace2685a072c6dUL); FPSR 0x10UL ]
        [ V(0, 0x71a02800ff800000UL, 0xea1ae000ff800000UL); FPSR 0x14UL ]
        [ V(0, 0xff8000003f800000UL, 0x7fe000007fc00000UL); FPSR 0x1UL ]
        [ V(0, 0x3ff0000000000000UL, 0x7fc0000000000000UL) ] ]

  /// C7.2.19 BFMMLA
  [<TestMethod>]
  member _.``C7.2.19 BFMMLA``() =
    check "6e42ec20" []
      [ [ V(0, 0x7f8000007f800000UL, 0x7f8000007f800000UL) ]
        [ V(0, 0xff800000ff800000UL, 0xff800000ff800000UL) ]
        [ V(0, 0x7fc000007fc00000UL, 0x7fc000007fc00000UL) ]
        [ V(0, 0x7fc0000000000000UL, 0x7fc0000000000000UL) ] ]

  /// C7.2.22 BIF
  [<TestMethod>]
  member _.``C7.2.22 BIF``() =
    check "6ee21c20" []
      [ [ V(0, 0xf66b492f48068918UL, 0x41fc824a7ab33c67UL) ]
        [ V(0, 0x1ec8a72536dfca75UL, 0xe4511bbb3f9f288dUL) ]
        [ V(0, 0xffc0000080000000UL, 0x7fa0000040c00000UL) ]
        [ V(0, 0x4008000000000000UL, 0x3ff999999999999aUL) ] ]
    check "2ee21c20" []
      [ [ V(0, 0xf66b492f48068918UL, 0x0UL) ]
        [ V(0, 0x1ec8a72536dfca75UL, 0x0UL) ]
        [ V(0, 0xffc0000080000000UL, 0x0UL) ]
        [ V(0, 0x4008000000000000UL, 0x0UL) ] ]

  /// C7.2.23 BIT
  [<TestMethod>]
  member _.``C7.2.23 BIT``() =
    check "6ea21c20" []
      [ [ V(0, 0x10213f67c9dde0beUL, 0x6486e26c0e47ec1dUL) ]
        [ V(0, 0xd37a832459299e04UL, 0x422bca52423bf12bUL) ]
        [ V(0, 0x3f8000003f800000UL, 0x3dcccccd7f400000UL) ]
        [ V(0, 0x3ff0000000000000UL, 0xbfb8000000000000UL) ] ]
    check "2ea21c20" []
      [ [ V(0, 0x10213f67c9dde0beUL, 0x0UL) ]
        [ V(0, 0xd37a832459299e04UL, 0x0UL) ]
        [ V(0, 0x3f8000003f800000UL, 0x0UL) ]
        [ V(0, 0x3ff0000000000000UL, 0x0UL) ] ]

  /// C7.2.24 BSL
  [<TestMethod>]
  member _.``C7.2.24 BSL``() =
    check "6e621c20" []
      [ [ V(0, 0x11b52f275efcf61cUL, 0xca86824c0e4bec95UL) ]
        [ V(0, 0x534d8b74d9099f86UL, 0x43212a52c25bb439UL) ]
        [ V(0, 0x3fbfffff00000001UL, 0x3d8000007f7fffffUL) ]
        [ V(0, 0x8000000000000000UL, 0x7fb8000000000000UL) ] ]
    check "2e621c20" []
      [ [ V(0, 0x11b52f275efcf61cUL, 0x0UL) ]
        [ V(0, 0x534d8b74d9099f86UL, 0x0UL) ]
        [ V(0, 0x3fbfffff00000001UL, 0x0UL) ]
        [ V(0, 0x8000000000000000UL, 0x0UL) ] ]

  /// C7.2.27 CMEQ (register)
  [<TestMethod>]
  member _.``C7.2.27 CMEQ``() =
    check "2e228c20" []
      [ [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0xffff00UL, 0x0UL) ]
        [ V(0, 0xffffffffffffUL, 0x0UL) ] ]
    check "2e628c20" []
      [ [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0xffffffffffffUL, 0x0UL) ] ]
    check "6e628c20" []
      [ [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0xffff00000000UL) ]
        [ V(0, 0xffffffffffffUL, 0x0UL) ] ]
    check "2ea28c20" []
      [ [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0xffffffffUL, 0x0UL) ] ]
    check "6ea28c20" []
      [ [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0xffffffffUL, 0x0UL) ] ]
    check "6ee28c20" []
      [ [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ] ]
    check "0e209820" []
      [ [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0xffff00ffffffUL, 0x0UL) ]
        [ V(0, 0xffffffffffffUL, 0x0UL) ] ]
    check "4e209820" []
      [ [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0xffff00ffffffUL, 0xffff0000ffffUL) ]
        [ V(0, 0xffffffffffffUL, 0x0UL) ] ]
    check "0e609820" []
      [ [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0xffff0000ffffUL, 0x0UL) ]
        [ V(0, 0xffffffffffffUL, 0x0UL) ] ]
    check "4e609820" []
      [ [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0xffff0000ffffUL, 0xffff0000ffffUL) ]
        [ V(0, 0xffffffffffffUL, 0x0UL) ] ]
    check "0ea09820" []
      [ [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0xffffffffUL, 0x0UL) ] ]
    check "4ea09820" []
      [ [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0xffffffffUL, 0x0UL) ] ]
    check "4ee09820" []
      [ [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ] ]
    check "6e228c20" []
      [ [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0x0UL, 0x0UL) ]
        [ V(0, 0xffff00UL, 0xffffff000000UL) ]
        [ V(0, 0xffffffffffffUL, 0x0UL) ] ]
