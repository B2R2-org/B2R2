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
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.ARM64
open B2R2.BinIR.LowUIR.AST.InfixOp
open type Register

[<TestClass>]
type LifterTests() =
  let num (v: uint32) = BitVector(v, 32<rt>) |> AST.num

  let num64 (v: uint64) = BitVector(v, 64<rt>) |> AST.num

  let bv64 (v: uint64) = BitVector(v, 64<rt>)

  let unwrapStmts stmts = Array.sub stmts 1 (Array.length stmts - 2)

  let isa = ISA(Architecture.ARMv8, Endian.Big)

  let reader = BinReader.Init Endian.Big

  let regFactory = RegisterFactory isa :> IRegisterFactory

  let ( !. ) name = Register.toRegID name |> regFactory.GetRegVar

  (* The halves of a vector register are pseudo registers: V0A is Q0's
     first, V0B its second. *)
  let ( !@ ) (name, pos) =
    regFactory.GetPseudoRegVar(Register.toRegID name, pos)

  let ( ++ ) (byteStr: string) (givenStmts: Stmt[]) =
    ByteArray.ofHexString byteStr, givenStmts

  let unsupported = AST.sideEffect BinIR.SideEffect.UnsupportedInstruction

  /// The statements one encoding lifts to, for a test whose claim is that
  /// the encoding lifts at all rather than what it lifts to.
  let lifted (hex: string) =
    let parser = Parser reader :> IInstructionParsable
    let builder = ILowUIRBuilder.Default(isa, regFactory, LowUIRStream())
    let ins = parser.Parse(ByteArray.ofHexString hex, 0UL)
    ins.Translate builder

  let test (bytes: byte[], givenStmts) =
    let parser = Parser reader :> IInstructionParsable
    let builder = ILowUIRBuilder.Default(isa, regFactory, LowUIRStream())
    let ins = parser.Parse(bytes, 0UL)
    CollectionAssert.AreEqual(givenStmts, unwrapStmts <| ins.Translate builder)

  /// The statements one encoding lifts to, as the text they print as.
  let liftedText (hex: string) =
    lifted hex |> Array.map string |> String.concat "\n"

  /// How a failed authentication writes its error code over bits 62:61, as
  /// the lifted text spells it.
  let poison (code: uint64) =
    $"& 0x9fffffffffffffff:I64) | 0x{code:x16}:I64"

  /// Whether a statement jumps to the given expression.
  let jumpsTo target (stmt: Stmt) =
    match stmt with
    | InterJmp(Target = t) -> t = target
    | _ -> false

  /// What one encoding assigns to a register or a temporary, if anything.
  let assigned (hex: string) dst =
    lifted hex
    |> Array.tryPick (function
      | Put(Dst = d; Src = src) when d = dst -> Some src
      | _ -> None)

  /// QC after one encoding ran on both halves of V1 and V2 set to the given
  /// words.
  let qcAfter hex v1 v2 =
    let inputs =
      [ !@(Q1, 1), bv64 v1
        !@(Q1, 2), bv64 v1
        !@(Q2, 1), bv64 v2
        !@(Q2, 2), bv64 v2 ]
    let read = IRRunner.run (lifted hex) inputs
    (read !.FPSR).ToUInt64() >>> 27 &&& 1UL

  (* FPCR.FZ, FPCR.FZ16 and FPCR.AHP, as FPCR holds them *)
  let fz = 1UL <<< 24

  let fz16 = 1UL <<< 19

  let ahp = 1UL <<< 26

  /// What one encoding leaves in the low half of V0 and in FPSR, run with
  /// FPCR and the low half of V1 set to the given words.
  let fpAfter hex fpcr v1 =
    let inputs = [ !.FPCR, bv64 fpcr; !@(Q1, 1), bv64 v1 ]
    let read = IRRunner.run (lifted hex) inputs
    (read !@(Q0, 1)).ToUInt64(), (read !.FPSR).ToUInt64()

  (* NGC, NGCS and a BFC with a non-zero lsb all reached the raising
     fall-through in `translate`, so a block containing one did not lift at
     all. The claim these pin is exactly that -- each encoding produces
     statements instead of NotImplementedIRException. *)
  [<TestMethod>]
  member _.``[AArch64] NGC lifts``() =
    Assert.AreEqual<bool>(true, (lifted "da0103e0").Length > 0, "NGC")

  [<TestMethod>]
  member _.``[AArch64] NGCS lifts``() =
    Assert.AreEqual<bool>(true, (lifted "fa0103e0").Length > 0, "NGCS")

  [<TestMethod>]
  member _.``[AArch64] BFC with a non-zero lsb lifts``() =
    Assert.AreEqual<bool>(true, (lifted "b3781fe0").Length > 0, "BFC")

  /// BLR X30 goes where X30 pointed, not to the instruction after it: the
  /// target is taken before the link register is written, so the jump is to
  /// that copy and never to X30 itself.
  [<TestMethod>]
  member _.``[AArch64] BLR X30 branches to the old X30``() =
    let jumps = lifted "d63f03c0" |> Array.exists (jumpsTo !.X30)
    Assert.AreEqual<bool>(false, jumps)

  [<TestMethod>]
  member _.``[AArch64] ADD (immedate) lift test``() =
    "114dc4ba"
    ++ [| !.X26 := AST.zext 64<rt>
           ((AST.xtlo 32<rt> !.X5 .+ num 0x371000u .+ num 0x0u)) |]
    |> test

  [<TestMethod>]
  member _.``[AArch64] ADD (extended register) lift test``() =
    "0b3f43ff"
    ++ [| !.SP := AST.zext 64<rt>
           (AST.xtlo 32<rt> !.SP .+ AST.xtlo 32<rt> !.XZR .+ num 0x0u) |]
    |> test

  [<TestMethod>]
  member _.``[AArch64] ADD (shifted register) lift test``() =
    "0b8e5f9b"
    ++ [| !.X27 := AST.zext 64<rt>
           (AST.xtlo 32<rt> !.X28 .+ (AST.xtlo 32<rt> !.X14 ?>> num 0x17u)
             .+ num 0x0u) |]
    |> test

  [<TestMethod>]
  member _.``[AArch64] ADD (extended register, UXTX) lift test``() =
    "8b336280"
    ++ [| !.X0 := !.X20 .+ (!.X19 << num64 0x0UL) .+ num64 0x0UL |]
    |> test

  /// DC ZVA clears the block DCZID_EL0 names, so the register has to be one
  /// this front end models, with a value from reset on.
  [<TestMethod>]
  member _.``[AArch64] DCZID_EL0 is a modelled system register``() =
    Assert.AreEqual<bool>(true, List.contains DCZIDEL0 SysReg.modelled)

  /// What it holds is what the processor holds: a Cortex-A57 clears sixteen
  /// words, which DCZID_EL0.BS spells as four.
  [<TestMethod>]
  member _.``[AArch64] DCZID_EL0 holds a Cortex-A57's block size``() =
    Assert.AreEqual<uint64>(0x4UL, SysReg.resetValue DCZIDEL0)

  /// DAIFSet and DAIFClr set and clear the masks their immediate names, at the
  /// bits DAIF keeps them in, and leave the other masks as they were.
  [<TestMethod>]
  member _.``[AArch64] MSR DAIFSet ORs its masks into DAIF``() =
    "d50345df"
    ++ [| !.DAIF := !.DAIF .| num64 0x140UL |]
    |> test

  [<TestMethod>]
  member _.``[AArch64] MSR DAIFClr clears its masks from DAIF``() =
    "d50343ff"
    ++ [| !.DAIF := !.DAIF .& num64 0xffffffffffffff3fUL |]
    |> test

  /// Every other field takes the low bit of the immediate and nothing else.
  [<TestMethod>]
  member _.``[AArch64] MSR PAN takes the low bit of its immediate``() =
    "d5004f9f"
    ++ [| !.PAN := num64 0x400000UL |]
    |> test

  /// A register that is a window onto PSTATE keeps only its field's bits.
  [<TestMethod>]
  member _.``[AArch64] MSR DAIF keeps only the mask bits``() =
    "d51b4220"
    ++ [| !.DAIF := !.X0 .& num64 0x3c0UL |]
    |> test

  /// What a system register with no name holds is the processor's own, so a
  /// read or a write of one is left to the emulator to report rather than
  /// given a value nothing stands behind.
  [<TestMethod>]
  member _.``[AArch64] MRS of an unnamed system register is unsupported``() =
    "d538f200" ++ [| unsupported |] |> test

  [<TestMethod>]
  member _.``[AArch64] MSR to an unnamed system register is unsupported``() =
    "d51ff001" ++ [| unsupported |] |> test

  /// A failed authentication puts key_number:NOT(key_number) in bits 62:61 in
  /// place of what was there (Auth(), J1-7662): 01 under an A key, 10 under a
  /// B key. Setting one bit on top of the address would leave an address in
  /// the upper half, whose top bits are all ones, exactly as it was.
  [<TestMethod>]
  member _.``[AArch64] A failed AUTIA leaves 01 in bits 62:61``() =
    StringAssert.Contains(liftedText "dac11020", poison 0x2000000000000000UL)

  [<TestMethod>]
  member _.``[AArch64] A failed AUTIB leaves 10 in bits 62:61``() =
    StringAssert.Contains(liftedText "dac11420", poison 0x4000000000000000UL)

  [<TestMethod>]
  member _.``[AArch64] A failed AUTDA leaves 01 in bits 62:61``() =
    StringAssert.Contains(liftedText "dac11820", poison 0x2000000000000000UL)

  [<TestMethod>]
  member _.``[AArch64] A failed AUTDB leaves 10 in bits 62:61``() =
    StringAssert.Contains(liftedText "dac11c20", poison 0x4000000000000000UL)

  /// A hint changes nothing a program can see: with one thread and nothing
  /// to wait for, each of these lifts to no statement at all.
  [<TestMethod>]
  member _.``[AArch64] YIELD lifts to nothing``() =
    "d503203f" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] WFE lifts to nothing``() =
    "d503205f" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] WFI lifts to nothing``() =
    "d503207f" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] SEV lifts to nothing``() =
    "d503209f" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] SEVL lifts to nothing``() =
    "d50320bf" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] BTI lifts to nothing``() =
    "d503241f" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] ESB lifts to nothing``() =
    "d503221f" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] PSB CSYNC lifts to nothing``() =
    "d503223f" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] TSB CSYNC lifts to nothing``() =
    "d503225f" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] CSDB lifts to nothing``() =
    "d503229f" ++ [||] |> test

  /// The tag stores write the base back in their indexed forms, as any store
  /// does, and a post-index one accesses the base itself (DDI0487F.c C6.2.256
  /// STG, C6.2.306 STZG, C6.2.258 STGP).
  [<TestMethod>]
  member _.``[AArch64] STG (post-index) writes the base back``() =
    Assert.AreEqual<Expr option>(Some(!.X1 .+ num64 16UL),
                                 assigned "d9201420" !.X1)

  [<TestMethod>]
  member _.``[AArch64] STG (pre-index) writes the base back``() =
    Assert.AreEqual<Expr option>(Some(!.X1 .+ num64 16UL),
                                 assigned "d9201c20" !.X1)

  [<TestMethod>]
  member _.``[AArch64] STG (signed offset) leaves the base``() =
    Assert.AreEqual<Expr option>(None, assigned "d9201820" !.X1)

  [<TestMethod>]
  member _.``[AArch64] STZG (post-index) zeroes at the base``() =
    Assert.AreEqual<Expr option>(Some !.X1,
                                 assigned "d9601420" (AST.tmpvar 64<rt> 1))

  [<TestMethod>]
  member _.``[AArch64] STGP (post-index) stores at the base``() =
    Assert.AreEqual<Expr option>(Some !.X1,
                                 assigned "68808c22" (AST.tmpvar 64<rt> 1))

  /// CLREX clears the reservation, leaving it on the last byte of memory, so
  /// that a store-exclusive after it fails (DDI0487F.c C6.2.54).
  [<TestMethod>]
  member _.``[AArch64] CLREX clears the reservation``() =
    let cleared = Some(num64 0xffffffffffffffffUL)
    Assert.AreEqual<Expr option>(cleared, assigned "d5033f5f" !.ExMonAddr)
    Assert.AreEqual<Expr option>(cleared, assigned "d503355f" !.ExMonAddr)

  /// The rounding narrows add the rounding constant to the integer value of
  /// the element, which no width bounds (DDI0487F.c C7.2.300 SQRSHRN), so a
  /// lane at the top of its range rounds up and saturates instead of wrapping.
  [<TestMethod>]
  member _.``[AArch64] SQRSHRN rounds 0x7fff to the largest byte``() =
    let read = IRRunner.run (lifted "0f0f9c20") [ !@(Q1, 1), bv64 0x7fffUL ]
    Assert.AreEqual<uint64>(0x7fUL, (read !@(Q0, 1)).ToUInt64() &&& 0xffUL)

  [<TestMethod>]
  member _.``[AArch64] SQRSHRUN rounds 0x7fff to the largest byte``() =
    let read = IRRunner.run (lifted "2f0f8c20") [ !@(Q1, 1), bv64 0x7fffUL ]
    Assert.AreEqual<uint64>(0xffUL, (read !@(Q0, 1)).ToUInt64() &&& 0xffUL)

  [<TestMethod>]
  member _.``[AArch64] UQRSHRN rounds 0xffff to the largest byte``() =
    let read = IRRunner.run (lifted "2f0f9c20") [ !@(Q1, 1), bv64 0xffffUL ]
    Assert.AreEqual<uint64>(0xffUL, (read !@(Q0, 1)).ToUInt64() &&& 0xffUL)
    Assert.AreEqual<uint64>(1UL, (read !.FPSR).ToUInt64() >>> 27 &&& 1UL)

  /// A negative amount shifts right, which cannot saturate (C7.2.378 UQSHL,
  /// C7.2.375 UQRSHL), even when every set bit goes; nor can a zero element.
  [<TestMethod>]
  member _.``[AArch64] UQSHL by -1 leaves QC``() =
    Assert.AreEqual<uint64>(0UL, qcAfter "6e224c20" 0x0101010101010101UL
                                   0xffffffffffffffffUL)

  [<TestMethod>]
  member _.``[AArch64] UQSHL of zero leaves QC``() =
    Assert.AreEqual<uint64>(0UL, qcAfter "6e224c20" 0UL 0UL)

  [<TestMethod>]
  member _.``[AArch64] UQSHL of 0x80 by 1 sets QC``() =
    Assert.AreEqual<uint64>(1UL, qcAfter "6e224c20" 0x8080808080808080UL
                                   0x0101010101010101UL)

  [<TestMethod>]
  member _.``[AArch64] UQRSHL by -2 leaves QC``() =
    Assert.AreEqual<uint64>(0UL, qcAfter "6e225c20" 0x0101010101010101UL
                                   0xfefefefefefefefeUL)

  [<TestMethod>]
  member _.``[AArch64] UQRSHL of zero leaves QC``() =
    Assert.AreEqual<uint64>(0UL, qcAfter "6e225c20" 0UL 0UL)

  /// TBX keeps the destination's byte where the index is past the table, in
  /// the top eight lanes as in the bottom eight (DDI0487F.c C7.2.336).
  [<TestMethod>]
  member _.``[AArch64] TBX of sixteen bytes keeps the top lanes``() =
    let inputs =
      [ !@(Q0, 1), bv64 0xeeeeeeeeeeeeeeeeUL
        !@(Q0, 2), bv64 0xeeeeeeeeeeeeeeeeUL
        !@(Q1, 1), bv64 0x4746454443424140UL
        !@(Q1, 2), bv64 0x4f4e4d4c4b4a4948UL
        !@(Q2, 1), bv64 0x0a082005ff100f00UL
        !@(Q2, 2), bv64 0x40071003800e1101UL ]
    let read = IRRunner.run (lifted "4e021020") inputs
    Assert.AreEqual<uint64>(0x4a48ee45eeee4f40UL, (read !@(Q0, 1)).ToUInt64())
    Assert.AreEqual<uint64>(0xee47ee43ee4eee41UL, (read !@(Q0, 2)).ToUInt64())

  /// FPUnpackCV flushes a denormal single under FPCR.FZ and raises Input
  /// Denormal alone (DDI0487F.c J1.3): what is left converts exactly.
  [<TestMethod>]
  member _.``[AArch64] FCVT flushes a denormal single under FZ``() =
    Assert.AreEqual<uint64 * uint64>((0UL, 0x80UL), fpAfter "1e23c020" fz 1UL)

  /// The alternative half-precision format FPCR.AHP selects has no infinity
  /// and no NaN (J1.3 FPConvert): an infinity becomes the largest magnitude
  /// and a NaN a zero of its own sign, each raising Invalid.
  [<TestMethod>]
  member _.``[AArch64] FCVT under AHP saturates an infinity``() =
    Assert.AreEqual<uint64 * uint64>((0x7fffUL, 1UL),
                                     fpAfter "1e23c020" ahp 0x7f800000UL)

  [<TestMethod>]
  member _.``[AArch64] FCVT under AHP makes a NaN a zero``() =
    Assert.AreEqual<uint64 * uint64>((0x8000UL, 1UL),
                                     fpAfter "1e23c020" ahp 0xffc00000UL)

  /// Its top exponent is an ordinary one, so 131008 converts exactly, and
  /// anything past it saturates with Invalid and without Inexact (J1.3
  /// FPRoundBase).
  [<TestMethod>]
  member _.``[AArch64] FCVT under AHP reaches the top exponent``() =
    Assert.AreEqual<uint64 * uint64>((0x7fffUL, 0UL),
                                     fpAfter "1e23c020" ahp 0x47ffe000UL)

  [<TestMethod>]
  member _.``[AArch64] FCVT under AHP saturates past 2^17 as Invalid``() =
    Assert.AreEqual<uint64 * uint64>((0x7fffUL, 1UL),
                                     fpAfter "1e23c020" ahp 0x48000001UL)

  /// Read back, the top exponent is a number too: 7c01 is 65600, not a
  /// signalling NaN.
  [<TestMethod>]
  member _.``[AArch64] FCVT from a half under AHP reads 7c01 as 65600``() =
    Assert.AreEqual<uint64 * uint64>((0x47802000UL, 0UL),
                                     fpAfter "1ee24020" ahp 0x7c01UL)

  /// FPConvertBF unpacks its operand, so FZ flushes a denormal single that
  /// would otherwise round up to the smallest normal bfloat16.
  [<TestMethod>]
  member _.``[AArch64] BFCVT flushes a denormal single under FZ``() =
    Assert.AreEqual<uint64 * uint64>((0UL, 0x80UL),
                                     fpAfter "1e634020" fz 0x7fffffUL)

  /// FPToFixedJS clears Z for a denormal flushed to zero, though the zero
  /// it converts to is exact (J1.3: `!IsZero(op<51:0>)`).
  [<TestMethod>]
  member _.``[AArch64] FJCVTZS clears Z for a flushed denormal``() =
    let inputs =
      [ !.FPCR, bv64 fz
        !@(Q1, 1), bv64 1UL
        !.Z, BitVector.One 1<rt> ]
    let read = IRRunner.run (lifted "1e7e0020") inputs
    Assert.AreEqual<uint64>(0UL, (read !.Z).ToUInt64())
    Assert.AreEqual<uint64>(0x80UL, (read !.FPSR).ToUInt64())

  /// The flush keeps the operand's sign: a negative denormal is minus zero.
  [<TestMethod>]
  member _.``[AArch64] FCVT flushes a negative denormal to minus zero``() =
    Assert.AreEqual<uint64 * uint64>((0x8000UL, 0x80UL),
                                     fpAfter "1e23c020" fz 0x80000001UL)

  /// A negative half with the top exponent reads back as a negative number.
  [<TestMethod>]
  member _.``[AArch64] FCVT from a half under AHP reads fc01 as -65600``() =
    Assert.AreEqual<uint64 * uint64>((0xc7802000UL, 0UL),
                                     fpAfter "1ee24020" ahp 0xfc01UL)

  /// FixedToFP rounds by FPRound, so FZ16 flushes a half result that was
  /// tiny before rounding, raising Underflow alone, even an exact one: 1 with
  /// 20 fraction bits is 2^-20, a subnormal half (J1.3 FPRoundBase).
  [<TestMethod>]
  member _.``[AArch64] SCVTF to a half flushes 2^-20 under FZ16``() =
    let inputs = [ !.FPCR, bv64 fz16; !.X1, bv64 1UL ]
    let read = IRRunner.run (lifted "1ec2b020") inputs
    Assert.AreEqual<uint64>(0UL, (read !@(Q0, 1)).ToUInt64())
    Assert.AreEqual<uint64>(8UL, (read !.FPSR).ToUInt64())

  /// The flushed zero keeps the result's sign: -1 gives minus zero.
  [<TestMethod>]
  member _.``[AArch64] SCVTF to a half flushes -2^-20 to minus zero``() =
    let inputs = [ !.FPCR, bv64 fz16; !.X1, bv64 0xffffffffUL ]
    let read = IRRunner.run (lifted "1ec2b020") inputs
    Assert.AreEqual<uint64>(0x8000UL, (read !@(Q0, 1)).ToUInt64())
    Assert.AreEqual<uint64>(8UL, (read !.FPSR).ToUInt64())

  /// Without FZ16 the same subnormal half is written as it is.
  [<TestMethod>]
  member _.``[AArch64] SCVTF to a half keeps 2^-20 without FZ16``() =
    let read = IRRunner.run (lifted "1ec2b020") [ !.X1, bv64 1UL ]
    Assert.AreEqual<uint64>(0x10UL, (read !@(Q0, 1)).ToUInt64())
    Assert.AreEqual<uint64>(0UL, (read !.FPSR).ToUInt64())

  /// <summary>
  /// A 64-bit integer with 64 fraction bits is a half inside its range, and
  /// rounds to it once (DDI0487F.c C7.2.235, FixedToFP): (2^62 + 2^51 + 1) /
  /// 2^64 is just past the middle of two halves and rounds up to 0.25 +
  /// 2^-12, where a double of the integer, rounded first, lands on the middle
  /// and rounds to the even one; and (2^63 - 1) / 2^64 is inexact however
  /// close a double of it comes.
  /// </summary>
  [<TestMethod>]
  member _.``[AArch64] SCVTF of a 64-bit integer to a half rounds once``() =
    let run x = IRRunner.run (lifted "9ec20020") [ !.X1, bv64 x ]
    let up = run 0x4008000000000001UL
    Assert.AreEqual<uint64>(0x3401UL, (up !@(Q0, 1)).ToUInt64())
    Assert.AreEqual<uint64>(0x10UL, (up !.FPSR).ToUInt64())
    let near = run 0x7fffffffffffffffUL
    Assert.AreEqual<uint64>(0x3800UL, (near !@(Q0, 1)).ToUInt64())
    Assert.AreEqual<uint64>(0x10UL, (near !.FPSR).ToUInt64())

  /// The same for UCVTF (C7.2.354): (2^63 + 2^52 + 1) / 2^64 rounds up to
  /// 0.5 + 2^-11.
  [<TestMethod>]
  member _.``[AArch64] UCVTF of a 64-bit integer to a half rounds once``() =
    let inputs = [ !.X1, bv64 0x8010000000000001UL ]
    let read = IRRunner.run (lifted "9ec30020") inputs
    Assert.AreEqual<uint64>(0x3801UL, (read !@(Q0, 1)).ToUInt64())
    Assert.AreEqual<uint64>(0x10UL, (read !.FPSR).ToUInt64())

  /// FZ16 is a half's FZ: FRECPE of 2^14 is under the smallest normal half
  /// and gives a zero, raising Underflow alone.
  [<TestMethod>]
  member _.``[AArch64] FRECPE of the half 2^14 is zero under FZ16``() =
    Assert.AreEqual<uint64 * uint64>((0UL, 8UL),
                                     fpAfter "5ef9d820" fz16 0x7400UL)

  /// FPRecipEstimate gives a zero, raising Underflow alone, for a reciprocal
  /// FZ would flush: 2^127's is under the smallest normal.
  [<TestMethod>]
  member _.``[AArch64] FRECPE of 2^127 is zero under FZ``() =
    Assert.AreEqual<uint64 * uint64>((0UL, 8UL),
                                     fpAfter "5ea1d820" fz 0x7f000000UL)

  /// UDF raises an Undefined Instruction exception wherever it runs.
  [<TestMethod>]
  member _.``[AArch64] UDF lifts to an undefined instruction``() =
    let undefined = AST.sideEffect BinIR.SideEffect.UndefinedInstruction
    "0000abcd" ++ [| undefined |] |> test
