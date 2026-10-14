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

namespace B2R2.FrontEnd.MIPS.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.MIPS
open type Register

/// <summary>
/// Release 6 microMIPS lifted, one manual page at a time, on the processor
/// MD00594 describes: microMIPS64, big-endian, with a 64-bit FPU.
///
/// Each method takes the word the parser tests built from the same page and
/// checks what the page's Operation computes from it. Where the statements
/// are only arithmetic on registers they are run (IRRunner), over values
/// chosen so that a wrong field, a missed sign extension or a missed carry
/// changes the answer; a branch or a jump is run to the jump it leaves by,
/// from 0x1000. Where they read or write memory, which nothing here
/// evaluates, the statements themselves are the claim. No reference runs
/// Release 6 microMIPS, so every expected value is the page's: the
/// encodings and their lifting match the manual.
/// </summary>
[<TestClass>]
type MicroMIPSR6LifterTests() =
  let isa =
    let flags = int MIPSISAMode.MicroMIPS ||| int MIPSRelease.R6
    ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64, flags)

  let regs = RegisterFactory isa :> IRegisterFactory

  let var r = Register.toRegID r |> regs.GetRegVar

  /// A coprocessor 0 register, which the register enumeration does not name.
  let cp0 (r: CP0Register) = regs.GetRegVar(RegisterID.create (int r))

  /// The statements one word lifts to at an address.
  let liftedAt addr (hex: string) =
    let bld = LowUIRBuilder(isa, RegisterFactory isa, LowUIRStream())
    let p = Parser(isa, BinReader.Init Endian.Big) :> IInstructionParsable
    (p.Parse(ByteArray.ofHexString hex, addr)).Translate bld

  /// The same at 0, where the parser tests read every word.
  let lifted hex = liftedAt 0UL hex

  let given (r, (v: uint64)) = var r, BitVector(v, Expr.typeOf (var r))

  /// What each register holds once a word read at an address ran over the
  /// given values, and zero everywhere else.
  let runAt addr hex inputs =
    let read = IRRunner.run (liftedAt addr hex) (List.map given inputs)
    fun r -> (read (var r)).ToUInt64()

  let run hex inputs = runAt 0UL hex inputs

  /// Where a word read at 0x1000 goes over the given values, as the address
  /// and the kind of the jump it leaves by, and what each register holds by
  /// then.
  let goes hex inputs =
    let pc = var PC, BitVector(0x1000UL, 64<rt>)
    let stmts = liftedAt 0x1000UL hex
    match IRRunner.leave stmts (pc :: List.map given inputs) with
    | Some(target, kind), read ->
      target, kind, fun r -> (read (var r)).ToUInt64()
    | None, _ ->
      failwith hex

  /// The address alone.
  let next hex inputs =
    let target, _, _ = goes hex inputs
    target

  /// What a floating-point word leaves in the registers, run from an FCSR and
  /// the given FPRs.
  let fpRun hex (fcsr: uint32) fprs =
    let inputs = (var FCSR, BitVector(fcsr, 32<rt>)) :: List.map given fprs
    let read = IRRunner.run (lifted hex) inputs
    fun r -> (read (var r)).ToUInt64()

  /// The side effects one word raises.
  let effects hex =
    lifted hex
    |> Array.choose (function
      | SideEffect(Effect = e) -> Some e
      | _ -> None)

  /// What a privileged word raises and leaves, run with a Status: zero is
  /// Kernel Mode and 0x10 User Mode.
  let privileged (status: uint64) hex inputs =
    let status = cp0 CP0Register.Status, BitVector(status, 64<rt>)
    let effects, read = IRRunner.follow (lifted hex) (status :: inputs)
    effects, fun r -> (read r).ToUInt64()

  /// The statements of one word, without its marks.
  let test hex (expected: Stmt[]) =
    let stmts = lifted hex
    CollectionAssert.AreEqual(expected, Array.sub stmts 1 (stmts.Length - 2))

  let micro = InterJmpKind.SwitchToMicroMIPS

  let wide = InterJmpKind.SwitchToMIPS

  let call = InterJmpKind.IsCall

  let plain = InterJmpKind.Base

  /// AND16 (MD00582 revision 6.04, p.72): "GPR[rt] &lt;- GPR[rs] and
  /// GPR[rt]", s1 and a2 here.
  [<TestMethod>]
  member _.``[microMIPS64R6] AND16 lifts (32r6 p.72)``() =
    let inputs = [ R17, 0x123456789abcdef0UL; R6, 0x0ff00ff00ff00ff0UL ]
    let read = run "44e1" inputs
    Assert.AreEqual<uint64>(0x023006700ab00ef0UL, read R17)
    Assert.AreEqual<uint64>(0x0ff00ff00ff00ff0UL, read R6)

  /// BC16 (MD00582 revision 6.04, p.74): "PC &lt;- PC + 2 + target_offset",
  /// -1012 from 0x1000.
  [<TestMethod>]
  member _.``[microMIPS64R6] BC16 lifts (32r6 p.74)``() =
    let target, kind, _ = goes "ce05" []
    Assert.AreEqual<uint64>(0xc0cUL, target)
    Assert.AreEqual<InterJmpKind>(plain, kind)

  /// BEQZC16 (MD00582 revision 6.04, p.75): "condition &lt;- (GPR[rs] ==
  /// 0)", to the place past the next instruction (see the parser test) and
  /// otherwise on to that instruction, two bytes along, with no delay slot.
  [<TestMethod>]
  member _.``[microMIPS64R6] BEQZC16 lifts (32r6 p.75)``() =
    Assert.AreEqual<uint64>(0xf88UL, next "8fc3" [ R7, 0UL ])
    Assert.AreEqual<uint64>(0x1002UL, next "8fc3" [ R7, 5UL ])

  /// BNEZC16 (MD00582 revision 6.04, p.76): "condition &lt;- (GPR[rs] !=
  /// 0)"; all sixty-four bits are compared.
  [<TestMethod>]
  member _.``[microMIPS64R6] BNEZC16 lifts (32r6 p.76)``() =
    Assert.AreEqual<uint64>(0x1002UL, next "acd5" [ R17, 0UL ])
    Assert.AreEqual<uint64>(0xfacUL, next "acd5" [ R17, 0xffffffff00000000UL ])

  /// BREAK16 (MD00582 revision 6.04, p.77): "SignalException(Breakpoint)",
  /// and nothing else.
  [<TestMethod>]
  member _.``[microMIPS64R6] BREAK16 lifts (32r6 p.77)``() =
    CollectionAssert.AreEqual([| Breakpoint |], effects "469b")

  /// <summary>
  /// JALRC16 (MD00582 revision 6.04, p.78): "GPR[31] &lt;- PC + 2", which
  /// section 2.4 (p.22) has carry the ISA mode in bit 0, and "PC &lt;-
  /// tempGPRLEN-1..1 || 0; ISAMode &lt;- temp0": to s1 with bit 0 cleared, in
  /// the encoding bit 0 names, as a call.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] JALRC16 lifts (32r6 p.78)``() =
    let target, kind, read = goes "462b" [ R17, 0x400021UL ]
    Assert.AreEqual<uint64>(0x400020UL, target)
    Assert.AreEqual<InterJmpKind>(call ||| micro, kind)
    Assert.AreEqual<uint64>(0x1003UL, read R31)
    let target, kind, _ = goes "462b" [ R17, 0x400020UL ]
    Assert.AreEqual<uint64>(0x400020UL, target)
    Assert.AreEqual<InterJmpKind>(call ||| wide, kind)

  /// JRCADDIUSP (MD00582 revision 6.04, p.80): "PC &lt;- GPR[31]GPRLEN-1..1 ||
  /// 0", the mode from bit 0, and "GPR[29] &lt;- GPR[29] +
  /// zero_extend(immediate || 02)": 0x58 onto sp.
  [<TestMethod>]
  member _.``[microMIPS64R6] JRCADDIUSP lifts (32r6 p.80)``() =
    let inputs = [ R31, 0x400031UL; R29, 0x7fff0000UL ]
    let target, kind, read = goes "46d3" inputs
    Assert.AreEqual<uint64>(0x400030UL, target)
    Assert.AreEqual<InterJmpKind>(plain ||| micro, kind)
    Assert.AreEqual<uint64>(0x7fff0058UL, read R29)

  /// JRC16 (MD00582 revision 6.04, p.82): "PC &lt;- tempGPRLEN-1..1 || 0;
  /// ISAMode &lt;- temp0", to t9.
  [<TestMethod>]
  member _.``[microMIPS64R6] JRC16 lifts (32r6 p.82)``() =
    let target, kind, _ = goes "4723" [ R25, 0x400011UL ]
    Assert.AreEqual<uint64>(0x400010UL, target)
    Assert.AreEqual<InterJmpKind>(plain ||| micro, kind)
    let _, kind, _ = goes "4723" [ R25, 0x400010UL ]
    Assert.AreEqual<InterJmpKind>(plain ||| wide, kind)

  /// LWM16 (MD00582 revision 6.04, p.91): one word for each listed register
  /// from "zero_extend(offset||02) + GPR[sp]" upwards, "sign-extended to the
  /// GPR register length", in the processor's byte order.
  [<TestMethod>]
  member _.``[microMIPS64R6] LWM16 lifts (32r6 p.91)``() =
    let bse = var R29 .+ numI64 44L 64<rt>
    let word i = AST.sext 64<rt> (AST.loadBE 32<rt> (bse .+ numI32 i 64<rt>))
    test "46b2"
      [| var R16 := word 0
         var R17 := word 4
         var R18 := word 8
         var R31 := word 12 |]

  /// MOVEP (MD00582 revision 6.04, p.96): "GPR[rd] &lt;- GPR[rs]; GPR[re]
  /// &lt;- GPR[rt]", a0 from s2 and s5 from s3.
  [<TestMethod>]
  member _.``[microMIPS64R6] MOVEP lifts (32r6 p.96)``() =
    let inputs = [ R18, 0x1111111111111111UL; R19, 0x2222222222222222UL ]
    let read = run "45ed" inputs
    Assert.AreEqual<uint64>(0x1111111111111111UL, read R4)
    Assert.AreEqual<uint64>(0x2222222222222222UL, read R21)

  /// NOT16 (MD00594 revision 6.01, p.102): "GPR[rt] &lt;- GPR[rs] xor
  /// 0xffffffffffffffff", where the microMIPS32 page (MD00582 revision 6.04,
  /// p.98) inverts the thirty-two bits it has.
  [<TestMethod>]
  member _.``[microMIPS64R6] NOT16 lifts (64r6 p.102)``() =
    let read = run "4710" [ R17, 0x00000000ffff0000UL ]
    Assert.AreEqual<uint64>(0xffffffff0000ffffUL, read R6)

  /// OR16 (MD00582 revision 6.04, p.99): "GPR[rt] &lt;- GPR[rs] or GPR[rt]".
  [<TestMethod>]
  member _.``[microMIPS64R6] OR16 lifts (32r6 p.99)``() =
    let inputs = [ R7, 0x00ff00ff00ff00ffUL; R16, 0x1200340056007800UL ]
    Assert.AreEqual<uint64>(0x12ff34ff56ff78ffUL, run "4789" inputs R7)

  /// SDBBP16 (MD00582 revision 6.04, p.101): a debug breakpoint, which is
  /// this front end's breakpoint, and nothing else.
  [<TestMethod>]
  member _.``[microMIPS64R6] SDBBP16 lifts (32r6 p.101)``() =
    CollectionAssert.AreEqual([| Breakpoint |], effects "457b")

  /// SWM16 (MD00582 revision 6.04, p.108): the low word of each listed
  /// register to "zero_extend(offset||02) + GPR[sp]" upwards, in the
  /// processor's byte order.
  [<TestMethod>]
  member _.``[microMIPS64R6] SWM16 lifts (32r6 p.108)``() =
    let bse = var R29 .+ numI64 24L 64<rt>
    let at i = AST.loadBE 32<rt> (bse .+ numI32 i 64<rt>)
    test "456a"
      [| at 0 := AST.xtlo 32<rt> (var R16)
         at 4 := AST.xtlo 32<rt> (var R17)
         at 8 := AST.xtlo 32<rt> (var R31) |]

  /// XOR16 (MD00582 revision 6.04, p.113): "GPR[rt] &lt;- GPR[rs] xor
  /// GPR[rt]".
  [<TestMethod>]
  member _.``[microMIPS64R6] XOR16 lifts (32r6 p.113)``() =
    let inputs = [ R3, 0xffff0000ffff0000UL; R5, 0x0f0f0f0f0f0f0f0fUL ]
    Assert.AreEqual<uint64>(0xf0f00f0ff0f00f0fUL, run "45d8" inputs R3)

  /// ADDIUPC (MD00582 revision 6.04, p.119): "GPR[rt] &lt;- ( PC &amp; ~0x3 +
  /// sign_extend( immediate &lt;&lt; 2 ) )". At 0x1002 that counts from
  /// 0x1000.
  [<TestMethod>]
  member _.``[microMIPS64R6] ADDIUPC lifts (32r6 p.119)``() =
    let read = runAt 0x1002UL "7ae40005" []
    Assert.AreEqual<uint64>(0xfffffffffff01014UL, read R23)

  /// <summary>
  /// ALIGN (MD00582 revision 6.04, p.121; MD00594 revision 6.01, p.130):
  /// "tmp_rt_hi &lt;- unsigned_word(GPR[rt]) &lt;&lt; (8*bp)", "tmp_rs_lo
  /// &lt;- unsigned_word(GPR[rs]) &gt;&gt; (8*(4-bp))", and on a 64-bit CPU
  /// "GPR[rd] &lt;- sign_extend.32(tmp)". bp 3 takes the low byte of s3 above
  /// the top three of a2.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] ALIGN lifts (32r6 p.121)``() =
    let inputs = [ R19, 0x123456abUL; R6, 0xffffffff89abcdefUL ]
    Assert.AreEqual<uint64>(0xffffffffab89abcdUL, run "02666e1f" inputs R13)

  /// DALIGN (MD00594 revision 6.01, p.130): the same on doublewords, "(8 *
  /// (8-bp))", with nothing to extend. bp 5 takes the low five bytes of s3
  /// above the top three of a2.
  [<TestMethod>]
  member _.``[microMIPS64R6] DALIGN lifts (64r6 p.129)``() =
    let inputs = [ R19, 0x0123456789abcdefUL; R6, 0xfedcba9876543210UL ]
    Assert.AreEqual<uint64>(0xabcdeffedcba9876UL, run "5a666d1c" inputs R13)

  /// ALUIPC (MD00582 revision 6.04, p.123): "GPR[rt] &lt;- ~0x0FFFF &amp; ( PC
  /// + sign_extend( immediate &lt;&lt; 16 ) )", at 0x1002.
  [<TestMethod>]
  member _.``[microMIPS64R6] ALUIPC lifts (32r6 p.123)``() =
    let read = runAt 0x1002UL "7adf8004" []
    Assert.AreEqual<uint64>(0xffffffff80040000UL, read R22)

  /// AUI (MD00594 revision 6.01, p.134; MD00582 revision 6.04, p.126): "AUI:
  /// GPR[rt] &lt;- sign_extend.32( GPR[rs] + sign_extend(immediate &lt;&lt;
  /// 16) )". 0x8001 is negative, and 0x7fff0000 plus 0x10000 carries into
  /// bit 31, which the sign extension of the word spreads upwards.
  [<TestMethod>]
  member _.``[microMIPS64R6] AUI lifts (32r6 p.126)``() =
    let sum = run "10f08001" [ R16, 0x12345678UL ] R7
    Assert.AreEqual<uint64>(0xffffffff92355678UL, sum)
    let carried = run "10f00001" [ R16, 0x7fff0000UL ] R7
    Assert.AreEqual<uint64>(0xffffffff80000000UL, carried)

  /// DAUI (MD00594 revision 6.01, p.134): "GPR[rt] &lt;- GPR[rs] +
  /// sign_extend(immediate &lt;&lt; 16)" on the whole doubleword.
  [<TestMethod>]
  member _.``[microMIPS64R6] DAUI lifts (64r6 p.134)``() =
    let read = run "f0cf8002" [ R15, 0x100000000UL ]
    Assert.AreEqual<uint64>(0x80020000UL, read R6)

  /// AUIPC (MD00582 revision 6.04, p.127): "GPR[rt] &lt;- ( PC + ( immediate
  /// &lt;&lt; 16 ) )", from the address as it is, 0x1002 here: revision 6.02
  /// "Corrected mistake in 6.01. AUIPC PC should not be qualified with 0x3"
  /// (p.391).
  [<TestMethod>]
  member _.``[microMIPS64R6] AUIPC lifts (32r6 p.127)``() =
    let read = runAt 0x1002UL "7abe8003" []
    Assert.AreEqual<uint64>(0xffffffff80031002UL, read R21)

  /// BALC (MD00582 revision 6.04, p.128): "GPR[31] &lt;- PC+4", carrying the
  /// ISA mode (Table 1.1, p.18), and "PC &lt;- PC+4 +
  /// sign_extend(target_offset)", as a call.
  [<TestMethod>]
  member _.``[microMIPS64R6] BALC lifts (32r6 p.128)``() =
    let target, kind, read = goes "b6000003" []
    Assert.AreEqual<uint64>(0xfffffffffc00100aUL, target)
    Assert.AreEqual<InterJmpKind>(call, kind)
    Assert.AreEqual<uint64>(0x1005UL, read R31)

  /// BC1EQZC and BC1NEZC (MD00582 revision 6.04, pp.129-130): "cond &lt;-
  /// tmp &amp; 1 = 0" and "tmp &amp; 1 != 0" on FPR ft, to "PC+4 +
  /// sign_extend( offset &lt;&lt; 1 )", and otherwise on.
  [<TestMethod>]
  member _.``[microMIPS64R6] BC1EQZC BC1NEZC lift (32r6 p.129)``() =
    Assert.AreEqual<uint64>(0xffffffffffff100eUL, next "41078005" [ F7, 2UL ])
    Assert.AreEqual<uint64>(0x1004UL, next "41078005" [ F7, 3UL ])
    Assert.AreEqual<uint64>(0x1024UL, next "412c0010" [ F12, 1UL ])
    Assert.AreEqual<uint64>(0x1004UL, next "412c0010" [ F12, 0x100UL ])

  /// BC2EQZC and BC2NEZC (MD00582 revision 6.04, p.131) list Coprocessor
  /// Unusable first among their exceptions, and the processor modelled here
  /// has no coprocessor 2 (Config1.C2 clear), so that is all they do.
  [<TestMethod>]
  member _.``[microMIPS64R6] BC2EQZC BC2NEZC lift (32r6 p.131)``() =
    for hex in [ "41498006"; "417e0021" ] do
      CollectionAssert.AreEqual([| UndefinedInstruction |], effects hex, hex)

  /// <summary>
  /// The compact zero-compare branch-and-links (MD00582 revision 6.04,
  /// p.134): "GPR[31] &lt;- PC+4" whether or not the branch is taken, with
  /// the ISA mode in bit 0 (Table 1.1, p.18), then "PC &lt;- ( PC+4+
  /// sign_extend( target_offset ) )" on the condition, signed.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] The ZALC branches lift (32r6 p.133)``() =
    let minus1 = 0xffffffffffffffffUL
    let cases =
      [ "c0c08007", R6, 0UL, 0xffffffffffff1012UL
        "c0c08007", R6, 1UL, 0x1004UL
        "c2520030", R18, 0UL, 0x1064UL
        "c2520030", R18, minus1, 0x1004UL
        "e180ffff", R12, 1UL, 0x1002UL
        "e180ffff", R12, 0UL, 0x1004UL
        "e3de0001", R30, minus1, 0x1006UL
        "e3de0001", R30, 0UL, 0x1004UL
        "75208000", R9, 0UL, 0xffffffffffff1004UL
        "75208000", R9, 0x100000000UL, 0x1004UL
        "7f801234", R28, 0x100000000UL, 0x346cUL
        "7f801234", R28, 0UL, 0x1004UL ]
    for hex, r, v, place in cases do
      let target, kind, read = goes hex [ r, v ]
      Assert.AreEqual<uint64>(place, target, hex)
      Assert.AreEqual<InterJmpKind>(plain, kind, hex)
      Assert.AreEqual<uint64>(0x1005UL, read R31, hex)

  /// <summary>
  /// The compact compare branches (MD00582 revision 6.04, p.137): signed
  /// comparisons for BLTC and BGEC and the compares with zero, unsigned ones
  /// for BLTUC and BGEUC, all sixty-four bits of each register, to "PC+4+
  /// sign_extend( offset )" when the condition holds and on to the next
  /// instruction when not.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] The compact branches lift (32r6 p.135)``() =
    let top, all = 0x8000000000000000UL, 0xffffffffffffffffUL
    let cases =
      [ "f4e08008", [ R7, 0xfffffffffffffffbUL ], 0xffffffffffff1014UL
        "f4e08008", [ R7, 5UL ], 0x1004UL
        "f6310002", [ R17, 0UL ], 0x1008UL
        "f6310002", [ R17, all ], 0x1004UL
        "f48d8009", [ R13, all; R4, 0xfffffffffffffffeUL ], 0xffffffffffff1016UL
        "f48d8009", [ R13, 0xfffffffffffffffeUL; R4, 1UL ], 0x1004UL
        "d4600003", [ R3, 1UL ], 0x100aUL
        "d4600003", [ R3, 0UL ], 0x1004UL
        "d6d6800a", [ R22, all ], 0xffffffffffff1018UL
        "d6d6800a", [ R22, 0UL ], 0x1004UL
        "d4570004", [ R23, top; R2, 0UL ], 0x100cUL
        "d4570004", [ R23, 1UL; R2, 0UL ], 0x1004UL
        "c0b8800b", [ R24, top; R5, 1UL ], 0xffffffffffff101aUL
        "c0b8800b", [ R24, 1UL; R5, all ], 0x1004UL
        "e2140005", [ R20, 1UL; R16, all ], 0x100eUL
        "e2140005", [ R20, all; R16, 1UL ], 0x1004UL
        "75c6800c", [ R6, 7UL; R14, 7UL ], 0xffffffffffff101cUL
        "75c6800c", [ R6, 7UL; R14, 0x100000007UL ], 0x1004UL
        "7feb0006", [ R11, 7UL; R31, 0x100000007UL ], 0x1010UL
        "7feb0006", [ R11, 7UL; R31, 7UL ], 0x1004UL
        "82700007", [ R19, 0UL ], 0xffffffffffe01012UL
        "82700007", [ R19, 1UL ], 0x1004UL
        "a1000040", [ R8, 1UL ], 0x1084UL
        "a1000040", [ R8, 0UL ], 0x1004UL ]
    for hex, inputs, place in cases do
      let target, kind, _ = goes hex inputs
      Assert.AreEqual<uint64>(place, target, hex)
      Assert.AreEqual<InterJmpKind>(plain, kind, hex)

  /// BC (MD00582 revision 6.04, p.138): "PC &lt;- ( PC+4 +
  /// sign_extend(target_offset) )", with no link.
  [<TestMethod>]
  member _.``[microMIPS64R6] BC lifts (32r6 p.138)``() =
    let target, kind, read = goes "96000101" []
    Assert.AreEqual<uint64>(0xfffffffffc001206UL, target)
    Assert.AreEqual<InterJmpKind>(plain, kind)
    Assert.AreEqual<uint64>(0UL, read R31)

  /// BREAK (MD00582 revision 6.04, p.139): "SignalException(Breakpoint)".
  [<TestMethod>]
  member _.``[microMIPS64R6] BREAK lifts (32r6 p.139)``() =
    CollectionAssert.AreEqual([| Breakpoint |], effects "026af347")

  /// BITSWAP (MD00594 revision 6.01, p.152): each of the four bytes of the
  /// word reversed in place, "GPR[rd] &lt;- sign_extend.32( tmp )": bytes 01
  /// 02 03 04 become 80 40 c0 20.
  [<TestMethod>]
  member _.``[microMIPS64R6] BITSWAP lifts (32r6 p.140)``() =
    let read = run "01f10b3c" [ R15, 0x01020304UL ]
    Assert.AreEqual<uint64>(0xffffffff8040c020UL, read R17)

  /// DBITSWAP (MD00594 revision 6.01, p.152): the same for all eight bytes,
  /// with nothing to extend.
  [<TestMethod>]
  member _.``[microMIPS64R6] DBITSWAP lifts (64r6 p.152)``() =
    let read = run "59560b3c" [ R10, 0x0102030405060708UL ]
    Assert.AreEqual<uint64>(0x8040c020a060e010UL, read R22)

  /// <summary>
  /// BOVC and BNVC (MD00594 revision 6.01, p.155; MD00582 revision 6.04,
  /// p.142): "sum_overflow &lt;- (tempd32 != tempd31)" for the sum of the
  /// two sign-extended words, and on a 64-bit processor "input_overflow
  /// &lt;- NotWordValue(GPR[rs]) or NotWordValue(GPR[rt])"; BOVC branches on
  /// either and BNVC on neither.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] BOVC BNVC lift (32r6 p.142)``() =
    let taken = 0xffffffffffff101eUL
    let bovc inputs = next "7489800d" inputs
    Assert.AreEqual<uint64>(taken, bovc [ R9, 0x7fffffffUL; R4, 1UL ])
    Assert.AreEqual<uint64>(taken, bovc [ R9, 0x100000000UL; R4, 0UL ])
    Assert.AreEqual<uint64>(0x1004UL, bovc [ R9, 1UL; R4, 2UL ])
    Assert.AreEqual<uint64>(0x1012UL, next "7c150007" [ R21, 0x7fffffffUL ])
    Assert.AreEqual<uint64>(0x1004UL, next "7c150007" [ R21, 0x100000000UL ])

  /// <summary>
  /// CACHE (MD00582 revision 6.04, pp.144-149): "If access to Coprocessor 0
  /// is not enabled, a Coprocessor Unusable Exception is signaled" (p.149),
  /// and the processor modelled here has no cache for the operation to
  /// reach -- which revision 6.03 makes a NOP for an operation that does not
  /// apply (p.392) -- so in Kernel Mode it does nothing at all.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] CACHE lifts (32r6 p.144)``() =
    let kernel, _ = privileged 0UL "22a561f0" []
    Assert.AreEqual<SideEffect list>([], kernel)
    let user, _ = privileged 0x10UL "22a561f0" []
    Assert.AreEqual<SideEffect list>([ UndefinedInstruction ], user)

  /// <summary>
  /// CLASS.fmt (MD00582 revision 6.04, p.161): the ten-bit mask, "signaling
  /// NaN (bit 0) and quiet NaN (bit 1)", the negative infinity, normal,
  /// subnormal and zero in bits 2 to 5 and the positive ones in 6 to 9:
  /// minus infinity is 0x4, minus zero 0x20, the least positive subnormal
  /// 0x100, and a NaN with its quiet bit clear 0x1.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] CLASS.fmt lifts (32r6 p.161)``() =
    let cases =
      [ 0xfff0000000000000UL, 0x4UL
        0x8000000000000000UL, 0x20UL
        0x0000000000000001UL, 0x100UL
        0x7ff0000000000001UL, 0x1UL ]
    for v, mask in cases do
      Assert.AreEqual<uint64>(mask, fpRun "553a0260" 0u [ F9, v ] F26)

  /// <summary>
  /// CMP.condn.fmt (MD00582 revision 6.04, pp.165-169): "condition &lt;-
  /// cond4 xor ((cond2 and less) or (cond1 and equal) or (cond0 and
  /// unordered))", stored as a mask of the format's width. SULT (01101) is
  /// true for 1 &lt; 2 and for a NaN, false for 2 &lt; 1, and as a
  /// signalling compare raises Invalid Operation for the quiet NaN, which
  /// FCSR records as both cause and flag (0x10040); NE (10011) is true for 1
  /// and 2, false for equal operands and, being quiet, for a NaN without a
  /// word to FCSR.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] CMP.condn.fmt lifts (32r6 p.165)``() =
    let one, two, qnan = 0x3f800000UL, 0x40000000UL, 0x7fc00000UL
    let sult a b = fpRun "55658b45" 0u [ F5, a; F11, b ]
    Assert.AreEqual<uint64>(0xffffffffUL, sult one two F17 &&& 0xffffffffUL)
    Assert.AreEqual<uint64>(0UL, sult two one F17 &&& 0xffffffffUL)
    let unordered = sult qnan one
    Assert.AreEqual<uint64>(0xffffffffUL, unordered F17 &&& 0xffffffffUL)
    Assert.AreEqual<uint64>(0x10040UL, unordered FCSR)
    let one, two = 0x3ff0000000000000UL, 0x4000000000000000UL
    let ne a b = fpRun "543e44d5" 0u [ F30, a; F1, b ]
    Assert.AreEqual<uint64>(0xffffffffffffffffUL, ne one two F8)
    Assert.AreEqual<uint64>(0UL, ne two two F8)
    let unordered = ne 0x7ff8000000000000UL two
    Assert.AreEqual<uint64>(0UL, unordered F8)
    Assert.AreEqual<uint64>(0UL, unordered FCSR)

  /// DVP (MD00582 revision 6.04, pp.185-186): "data &lt;- VPControl; GPR[rs]
  /// &lt;- data; VPControlDIS &lt;- 1" in Kernel Mode, and Coprocessor
  /// Unusable outside it, leaving both alone.
  [<TestMethod>]
  member _.``[microMIPS64R6] DVP lifts (32r6 p.185)``() =
    let control = cp0 CP0Register.VPControl
    let inputs = [ control, BitVector(0x10UL, 64<rt>) ]
    let kernel, read = privileged 0UL "000c197c" inputs
    Assert.AreEqual<SideEffect list>([], kernel)
    Assert.AreEqual<uint64>(0x10UL, read (var R12))
    Assert.AreEqual<uint64>(0x11UL, read control)
    let user, read = privileged 0x10UL "000c197c" inputs
    Assert.AreEqual<SideEffect list>([ UndefinedInstruction ], user)
    Assert.AreEqual<uint64>(0x10UL, read control)

  /// EVP (MD00582 revision 6.04, pp.196-197): "data &lt;- VPControl; GPR[rs]
  /// &lt;- data; VPControlDIS &lt;- 0".
  [<TestMethod>]
  member _.``[microMIPS64R6] EVP lifts (32r6 p.196)``() =
    let control = cp0 CP0Register.VPControl
    let inputs = [ control, BitVector(0x13UL, 64<rt>) ]
    let kernel, read = privileged 0UL "001a397c" inputs
    Assert.AreEqual<SideEffect list>([], kernel)
    Assert.AreEqual<uint64>(0x13UL, read (var R26))
    Assert.AreEqual<uint64>(0x12UL, read control)

  /// <summary>
  /// JIALC (MD00582 revision 6.04, pp.207-208): "temp &lt;- GPR[rt] +
  /// sign_extend(offset)", "GPR[31] &lt;- PC + 4" with the ISA mode in bit 0
  /// (section 2.4, p.22), and "PC &lt;- (tempGPRLEN-1..1 || 0); ISAMode
  /// &lt;- temp0", as a call. 0x408000 less 0x7fef is 0x400011.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] JIALC lifts (32r6 p.207)``() =
    let target, kind, read = goes "a0198011" [ R25, 0x408000UL ]
    Assert.AreEqual<uint64>(0x400010UL, target)
    Assert.AreEqual<InterJmpKind>(call ||| micro, kind)
    Assert.AreEqual<uint64>(0x1005UL, read R31)
    let target, kind, _ = goes "a0198011" [ R25, 0x407fffUL ]
    Assert.AreEqual<uint64>(0x400010UL, target)
    Assert.AreEqual<InterJmpKind>(call ||| wide, kind)

  /// JIC (MD00582 revision 6.04, pp.209-210): JIALC's target with no link.
  /// 0x400022 less 15 is 0x400013.
  [<TestMethod>]
  member _.``[microMIPS64R6] JIC lifts (32r6 p.209)``() =
    let target, kind, read = goes "8007fff1" [ R7, 0x400022UL ]
    Assert.AreEqual<uint64>(0x400012UL, target)
    Assert.AreEqual<InterJmpKind>(plain ||| micro, kind)
    Assert.AreEqual<uint64>(0UL, read R31)

  /// <summary>
  /// LL (MD00582 revision 6.04, p.221): "vAddr &lt;- sign_extend(offset) +
  /// GPR[base]", the word there in the processor's byte order into rt, sign
  /// extended, and "LLbit &lt;- 1", which this front end keeps as the address
  /// and the value it watches.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] LL lifts (32r6 p.221)``() =
    let addr = var R12 .+ numI64 -91L 64<rt>
    let t = AST.tmpvar 32<rt> 1
    test "624c31a5"
      [| t := AST.loadBE 32<rt> addr
         var ExMonAddr := addr
         var ExMonVal := AST.zext 64<rt> t
         var R18 := AST.sext 64<rt> t |]

  /// <summary>
  /// LLWP (MD00582 revision 6.04, pp.226-227): the doubleword at GPR[base],
  /// "GPR[rt] &lt;- memdoubleword31..0" and "GPR[rd] &lt;-
  /// memdoubleword63..32", each sign-extended on this 64-bit processor, the
  /// watch on the address.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] LLWP lifts (32r6 p.226)``() =
    let addr = var R16 .+ numI64 0L 64<rt>
    let t = AST.tmpvar 64<rt> 1
    test "607010e0"
      [| t := AST.loadBE 64<rt> addr
         var ExMonAddr := addr
         var ExMonVal := AST.zext 64<rt> (AST.xtlo 32<rt> t)
         var R14 := AST.sext 64<rt> (AST.xthi 32<rt> t)
         var R3 := AST.sext 64<rt> (AST.xtlo 32<rt> t) |]

  /// LLWPE (MD00582 revision 6.04, pp.228-229): LLWP in Kernel Mode, and
  /// Coprocessor Unusable outside it, among its exceptions.
  [<TestMethod>]
  member _.``[microMIPS64R6] LLWPE lifts (32r6 p.228)``() =
    let t = AST.tmpvar 64<rt> 1
    let stmts = lifted "630764d0"
    let addr = var R7 .+ numI64 0L 64<rt>
    let load = t := AST.loadBE 64<rt> addr
    CollectionAssert.Contains(stmts, load)
    let high = var R13 := AST.sext 64<rt> (AST.xthi 32<rt> t)
    CollectionAssert.Contains(stmts, high)
    let user, _ = privileged 0x10UL "630764d0" []
    Assert.AreEqual<SideEffect list>([ UndefinedInstruction ], user)

  /// LSA (MD00582 revision 6.04, p.230): "GPR[rd] &lt;- sign_extend.32(
  /// GPR[rs] &lt;&lt; (sa+1) + GPR[rt] )": a1 shifted by three plus s4,
  /// whose word carries into bit 31.
  [<TestMethod>]
  member _.``[microMIPS64R6] LSA lifts (32r6 p.230)``() =
    let read = run "02854c0f" [ R5, 0x0fffffffUL; R20, 9UL ]
    Assert.AreEqual<uint64>(0xffffffff80000001UL, read R9)

  /// LUI (MD00594 revision 6.01, p.285): "GPR[rs] &lt;- sign_extend(immediate
  /// || 016)", the microMIPS32 page's (MD00582 revision 6.04, p.231) word
  /// extended by its sign.
  [<TestMethod>]
  member _.``[microMIPS64R6] LUI lifts (32r6 p.231)``() =
    Assert.AreEqual<uint64>(0xffffffff87650000UL, run "13008765" [] R24)

  /// LWC2 and SWC2 (MD00582 revision 6.04, pp.234 and 332) list Coprocessor
  /// Unusable among their exceptions, and the processor modelled here has no
  /// coprocessor 2, so that is all they do.
  [<TestMethod>]
  member _.``[microMIPS64R6] LWC2 SWC2 lift (32r6 p.234 p.332)``() =
    for hex in [ "21a30404"; "236887ff" ] do
      CollectionAssert.AreEqual([| UndefinedInstruction |], effects hex, hex)

  /// LWPC (MD00582 revision 6.04, p.236): "vAddr &lt;- ( PC &amp; ~0x3 +
  /// sign_extend(offset)&lt;&lt;2)", the word there in the processor's byte
  /// order, sign-extended. At 0x1002 that counts from 0x1000.
  [<TestMethod>]
  member _.``[microMIPS64R6] LWPC lifts (32r6 p.236)``() =
    let at = numU64 0xfffffffffff0100cUL 64<rt>
    let load = var R5 := AST.sext 64<rt> (AST.loadBE 32<rt> at)
    CollectionAssert.Contains(liftedAt 0x1002UL "78ac0003", load)

  /// LDPC (MD00594 revision 6.01, p.262): "vAddr &lt;- ( (PC&amp;~0x7)+
  /// sign_extend(offset) )", the offset in doublewords. At 0x100e that
  /// counts from 0x1008.
  [<TestMethod>]
  member _.``[microMIPS64R6] LDPC lifts (64r6 p.262)``() =
    let at = numU64 0xfffffffffff01050UL 64<rt>
    let load = var R20 := AST.loadBE 64<rt> at
    CollectionAssert.Contains(liftedAt 0x100eUL "7a9a0009", load)

  /// LWUPC (MD00594 revision 6.01, p.291): "vAddr &lt;- ( PC +
  /// sign_extend(offset)&lt;&lt; 2)", from the address as it is, 0x1002
  /// here, and "GPR[rt] &lt;- zero_extend(memword)". The book's revision
  /// history lists the PC-relative instructions it aligns (p.454), and
  /// LWUPC is not among them.
  [<TestMethod>]
  member _.``[microMIPS64R6] LWUPC lifts (64r6 p.291)``() =
    let at = numU64 0xfffffffffff0101eUL 64<rt>
    let load = var R14 := AST.zext 64<rt> (AST.loadBE 32<rt> at)
    CollectionAssert.Contains(liftedAt 0x1002UL "79d40007", load)

  /// <summary>
  /// MADDF.fmt and MSUBF.fmt (MD00582 revision 6.04, pp.237-238): "vinf
  /// &lt;- vfd +inf (vfs *inf vft)" and "-inf", rounded once. (1 + 2^-23)
  /// times (1 - 2^-24) less 1 is 2^-24 - 2^-47 exactly, where the product
  /// rounded first would leave 0; 10 less 2 times 3 is 4.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] MADDF MSUBF lift (32r6 p.237)``() =
    let fprs = [ F6, 0xbf800000UL; F2, 0x3f800001UL; F4, 0x3f7fffffUL ]
    let fused = fpRun "548231b8" 0u fprs F6 &&& 0xffffffffUL
    Assert.AreEqual<uint64>(0x337ffffeUL, fused)
    let fprs =
      [ F18, 0x4024000000000000UL
        F14, 0x4000000000000000UL
        F10, 0x4008000000000000UL ]
    Assert.AreEqual<uint64>(0x4010000000000000UL, fpRun "554e93f8" 0u fprs F18)

  /// <summary>
  /// MAX.fmt, MAXA.fmt, MIN.fmt and MINA.fmt (MD00582 revision 6.04,
  /// pp.239-241): maxNum, maxNumMag, minNum and minNumMag, with Table 5.24's
  /// cases -- MAX of -0.0 and 0.0 is 0.0 and MIN -0.0, a number is preferred
  /// to a quiet NaN -- and "For equal absolute values, returns the largest
  /// argument" for MAXA and the smallest for MINA.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] MAX MAXA MIN MINA lift (32r6 p.239)``() =
    let lo32 v = v &&& 0xffffffffUL
    let max a b = fpRun "54670a0b" 0u [ F7, a; F3, b ] F1
    Assert.AreEqual<uint64>(0UL, max 0x8000000000000000UL 0UL)
    let three = 0x4008000000000000UL
    Assert.AreEqual<uint64>(three, max 0x7ff8000000000000UL three)
    let maxa a b = fpRun "55a9282b" 0u [ F9, a; F13, b ] F5 |> lo32
    Assert.AreEqual<uint64>(0xc0400000UL, maxa 0xc0400000UL 0x40000000UL)
    Assert.AreEqual<uint64>(0x40000000UL, maxa 0xc0000000UL 0x40000000UL)
    let min a b = fpRun "5690c003" 0u [ F16, a; F20, b ] F24 |> lo32
    Assert.AreEqual<uint64>(0x80000000UL, min 0UL 0x80000000UL)
    Assert.AreEqual<uint64>(0x3f800000UL, min 0x3f800000UL 0x7fc00000UL)
    let mina a b = fpRun "57fdda23" 0u [ F29, a; F31, b ] F27
    let minusOne, two = 0xbff0000000000000UL, 0x4000000000000000UL
    Assert.AreEqual<uint64>(minusOne, mina minusOne two)
    Assert.AreEqual<uint64>(0xc000000000000000UL, mina two 0xc000000000000000UL)

  /// PREF (MD00582 revision 6.04, p.266): "Any action, including doing
  /// nothing, is permitted as long as it does not change architecturally
  /// visible state"; this one does nothing.
  [<TestMethod>]
  member _.``[microMIPS64R6] PREF lifts (32r6 p.266)``() =
    test "63d121fc" [||]

  /// <summary>
  /// RDHWR (MD00582 revision 6.04, pp.274-275): register 29 is UserLocal,
  /// read with select 0, and "when the 3-bit sel is undefined for use with a
  /// specific register number, then a Reserved Instruction Exception is
  /// signaled", as select 5 is for it.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] RDHWR lifts (32r6 p.274)``() =
    let read = run "011d01c0" [ ULR, 0x7fff12345678UL ]
    Assert.AreEqual<uint64>(0x7fff12345678UL, read R8)
    CollectionAssert.AreEqual([| UndefinedInstruction |], effects "011d29c0")

  /// <summary>
  /// RINT.fmt (MD00582 revision 6.04, p.279): "Round to integer operation,
  /// using rounding mode FCSR.RM". The rounding is left to the evaluator,
  /// which takes the direction from FCSR, so the statements name none of
  /// their own; IRRunner rounds such a cast to nearest, which is RM 0: 2.5 is
  /// 2, 3.5 is 4 and -2.5 is -2. What it raises comes from the host's
  /// exception query, so FCSR is not the claim here.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] RINT.fmt lifts (32r6 p.279)``() =
    let named =
      lifted "55870220"
      |> Array.exists (function
        | Put(Src = RoundCtrl _) -> true
        | _ -> false)
    Assert.AreEqual<bool>(false, named)
    let rint v = fpRun "55870220" 0u [ F12, v ] F7
    Assert.AreEqual<uint64>(0x4000000000000000UL, rint 0x4004000000000000UL)
    Assert.AreEqual<uint64>(0x4010000000000000UL, rint 0x400c000000000000UL)
    Assert.AreEqual<uint64>(0xc000000000000000UL, rint 0xc004000000000000UL)

  /// <summary>
  /// SC (MD00582 revision 6.04, pp.288-290): "if LLbit then StoreMemory
  /// (CCA, WORD, dataword, ...)" and "GPR[rt] &lt;- 0 || LLbit", the LLbit
  /// being, here, that the address is the one LL watched and still holds
  /// the value it read.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] SC lifts (32r6 p.288)``() =
    let addr = var R21 .+ numI64 -255L 64<rt>
    let cur, matched = AST.tmpvar 32<rt> 1, AST.tmpvar 1<rt> 2
    let watched = AST.xtlo 32<rt> (var ExMonVal)
    let mem = AST.loadBE 32<rt> addr
    test "6155b101"
      [| cur := mem
         matched := (addr == var ExMonAddr) .& (cur == watched)
         mem := AST.ite matched (AST.xtlo 32<rt> (var R10)) cur
         var R10 := AST.zext 64<rt> matched |]

  /// <summary>
  /// SCWP (MD00582 revision 6.04, pp.294-295): "datadoubleword31..0 &lt;-
  /// GPR[rt]", "datadoubleword63..32 &lt;- GPR[rd]", stored in the
  /// processor's byte order if the watch holds, and "GPR[rt] &lt;- 0 ||
  /// 1'b1" or 0.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] SCWP lifts (32r6 p.294)``() =
    let addr = var R29 .+ numI64 0L 64<rt>
    let ok = var ExMonAddr == addr
    let pair = AST.concat (AST.xtlo 32<rt> (var R2)) (AST.xtlo 32<rt> (var R11))
    let one, zero = AST.num1 1<rt>, AST.num0 1<rt>
    test "617d9020"
      [| AST.loadBE 64<rt> addr := AST.ite ok pair (AST.loadBE 64<rt> addr)
         var R11 := AST.zext 64<rt> (AST.ite ok one zero) |]

  /// SCWPE (MD00582 revision 6.04, pp.298-299): SCWP in Kernel Mode, and
  /// Coprocessor Unusable outside it.
  [<TestMethod>]
  member _.``[microMIPS64R6] SCWPE lifts (32r6 p.298)``() =
    let addr = var R4 .+ numI64 0L 64<rt>
    let ok = var ExMonAddr == addr
    let lo32 r = AST.xtlo 32<rt> (var r)
    let mem = AST.loadBE 64<rt> addr
    let store = mem := AST.ite ok (AST.concat (lo32 R30) (lo32 R19)) mem
    CollectionAssert.Contains(lifted "6264a1e0", store)
    let user, _ = privileged 0x10UL "6264a1e0" []
    Assert.AreEqual<SideEffect list>([ UndefinedInstruction ], user)

  /// SDBBP (MD00582 revision 6.04, p.301): a debug breakpoint, which is this
  /// front end's breakpoint.
  [<TestMethod>]
  member _.``[microMIPS64R6] SDBBP lifts (32r6 p.301)``() =
    CollectionAssert.AreEqual([| Breakpoint |], effects "02c5db7c")

  /// SEL.fmt (MD00582 revision 6.04, p.306): "FPR[fd] &lt;- FPR[fd].bit0 ?
  /// FPR[ft] : FPR[fs]", f6 when bit 0 of f10 is set and f8 when not.
  [<TestMethod>]
  member _.``[microMIPS64R6] SEL.fmt lifts (32r6 p.306)``() =
    let three, minusTwo = 0x4008000000000000UL, 0xc000000000000000UL
    let sel cond = fpRun "54c852b8" 0u [ F10, cond; F6, three; F8, minusTwo ]
    Assert.AreEqual<uint64>(three, sel 1UL F10)
    Assert.AreEqual<uint64>(minusTwo, sel 2UL F10)

  /// SELEQZ and SELNEZ (MD00582 revision 6.04, p.307): "SELEQZ: GPR[rd] &lt;-
  /// GPR[rt] ? 0 : GPR[rs]" and SELNEZ the other way, all GPRLEN bits of rt
  /// tested.
  [<TestMethod>]
  member _.``[microMIPS64R6] SELEQZ SELNEZ lift (32r6 p.307)``() =
    let seleqz cond = run "02e44940" [ R23, cond; R4, 0x1234UL ] R9
    Assert.AreEqual<uint64>(0x1234UL, seleqz 0UL)
    Assert.AreEqual<uint64>(0UL, seleqz 0x100000000UL)
    let selnez cond = run "005f7980" [ R2, cond; R31, 0x5678UL ] R15
    Assert.AreEqual<uint64>(0x5678UL, selnez 0x100000000UL)
    Assert.AreEqual<uint64>(0UL, selnez 0UL)

  /// SELEQZ.fmt and SELNEQZ.fmt (MD00582 revision 6.04, pp.309-310): fs when
  /// bit 0 of ft is clear (SELEQZ) or set (SELNEQZ), and "the value that has
  /// all bits zero" otherwise.
  [<TestMethod>]
  member _.``[microMIPS64R6] SELEQZ.fmt SELNEQZ.fmt lift (32r6 p.309)``() =
    let seleqz cond = fpRun "55e3a838" 0u [ F15, cond; F3, 0x3f800000UL ] F21
    Assert.AreEqual<uint64>(0x3f800000UL, seleqz 2UL &&& 0xffffffffUL)
    Assert.AreEqual<uint64>(0UL, seleqz 1UL &&& 0xffffffffUL)
    let three = 0x4008000000000000UL
    let selneqz cond = fpRun "57335a78" 0u [ F25, cond; F19, three ] F11
    Assert.AreEqual<uint64>(three, selneqz 1UL)
    Assert.AreEqual<uint64>(0UL, selneqz 2UL)

  /// SIGRIE (MD00582 revision 6.04, p.313):
  /// "SignalException(ReservedInstruction)", and nothing else.
  [<TestMethod>]
  member _.``[microMIPS64R6] SIGRIE lifts (32r6 p.313)``() =
    CollectionAssert.AreEqual([| UndefinedInstruction |], effects "002fbbff")

  /// <summary>
  /// TLBINV (MD00582 revision 6.04, pp.346-347): every entry with "TLB[i]ASID
  /// = EntryHiASID &amp; TLB[i]G = 0" gets "TLB[i]VPN2_invalid &lt;- 1", which
  /// this front end keeps as EntryHi's EHINV bit (0x400) in the entry. Of
  /// three entries in address space 5, 5 and 6, the second global, only the
  /// first is marked; outside Kernel Mode it is Coprocessor Unusable.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] TLBINV lifts (32r6 p.346)``() =
    let entry i field = cp0 (CP0.tlbReg i field)
    let hi i = entry i CP0.TLBField.Hi
    let inputs =
      [ cp0 CP0Register.EntryHi, BitVector(0x5UL, 64<rt>)
        hi 0, BitVector(0x40000005UL, 64<rt>)
        hi 1, BitVector(0x80000005UL, 64<rt>)
        entry 1 CP0.TLBField.Lo0, BitVector(1UL, 64<rt>)
        entry 1 CP0.TLBField.Lo1, BitVector(1UL, 64<rt>)
        hi 2, BitVector(0xc0000006UL, 64<rt>) ]
    let kernel, read = privileged 0UL "0000437c" inputs
    Assert.AreEqual<SideEffect list>([], kernel)
    Assert.AreEqual<uint64>(0x40000405UL, read (hi 0))
    Assert.AreEqual<uint64>(0x80000005UL, read (hi 1))
    Assert.AreEqual<uint64>(0xc0000006UL, read (hi 2))
    let user, _ = privileged 0x10UL "0000437c" inputs
    Assert.AreEqual<SideEffect list>([ UndefinedInstruction ], user)

  /// TLBINVF (MD00582 revision 6.04, pp.349-350): "TLB[i]VPN2_invalid &lt;-
  /// 1" for every entry, global or not and whatever its address space.
  [<TestMethod>]
  member _.``[microMIPS64R6] TLBINVF lifts (32r6 p.349)``() =
    let entry i field = cp0 (CP0.tlbReg i field)
    let hi i = entry i CP0.TLBField.Hi
    let inputs =
      [ cp0 CP0Register.EntryHi, BitVector(0x5UL, 64<rt>)
        hi 0, BitVector(0x40000005UL, 64<rt>)
        hi 1, BitVector(0x80000005UL, 64<rt>)
        entry 1 CP0.TLBField.Lo0, BitVector(1UL, 64<rt>)
        entry 1 CP0.TLBField.Lo1, BitVector(1UL, 64<rt>)
        hi 2, BitVector(0xc0000006UL, 64<rt>) ]
    let kernel, read = privileged 0UL "0000537c" inputs
    Assert.AreEqual<SideEffect list>([], kernel)
    Assert.AreEqual<uint64>(0x40000405UL, read (hi 0))
    Assert.AreEqual<uint64>(0x80000405UL, read (hi 1))
    Assert.AreEqual<uint64>(0xc0000406UL, read (hi 2))
