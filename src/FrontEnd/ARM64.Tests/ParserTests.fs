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

namespace B2R2.FrontEnd.ARM64.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.ARM64
open B2R2.FrontEnd.ARM64.OperandHelper
open type Opcode
open type Register

/// Shortcut for creating operands.
[<AutoOpen>]
module private Shortcut =
  type O =
    static member Reg(r) = OprRegister r

    static member RegOffset(r) = OprExtReg r

    static member MemBaseReg(baseReg, offsetReg, typ: ExtendType, imm) =
      memBaseReg (baseReg, offsetReg, Some <| ExtRegOffset(typ, imm))

    static member MemBaseReg(baseReg, offsetReg, typ: ShiftOp, imm) =
      memBaseReg (baseReg, offsetReg, Some <| ShiftOffset(typ, imm))

    static member MemBaseImm(register, imm) = memBaseImm (register, Some imm)

    static member MemBaseImm register = memBaseImm (register, None)

    static member MemPreIdxImm(register, imm) =
      memPreIdxImm (register, Some imm)

    static member MemPreIdxReg(baseReg, offsetReg, imm) =
      memPreIdxReg (baseReg, offsetReg, Some imm)

    static member MemPostIdxImm(register, imm) =
      memPostIdxImm (register, Some imm)

    static member MemPostIdxReg(baseReg, offsetReg, imm) =
      memPostIdxReg (baseReg, offsetReg, Some imm)

    static member MemPostIdxReg(baseReg, offsetReg) =
      memPostIdxReg (baseReg, offsetReg, None)

    static member MemLabel label = memLabel label

    static member Imm(v) = OprImm v

    static member Shift(srType, v: int64) = OprShift(srType, Imm v)

    static member LSB v = OprLSB v

    static member Pstate st = OprPstate st

    static member SIMDVecReg(reg, typ: SIMDVector) = VecReg(reg, typ) |> OprSIMD

    static member SIMDVecRegWithIdx(reg, typ: SIMDVector, idx) =
      (reg, typ, idx) |> VecRegWithIdx |> OprSIMD

    static member SIMDList(lst, typ: SIMDVector) =
      lst |> List.map (fun r -> VecReg(r, typ)) |> OprSIMDList

    static member SIMDList(lst, typ: SIMDVector, idx: Index) =
      OprSIMDList <| List.map (fun reg -> VecRegWithIdx(reg, typ, idx)) lst

    static member Prefetch v = OprPrfOp v

    static member ScalarReg r = scalReg r

/// - C4.2 Data processing - immediate
/// - C4.3 Branches, exception generating and system instructions
/// - C4.4 Loads and stores
/// - C4.5 Data processing - register
/// - C4.6 Data processing - SIMD and floating point
[<TestClass>]
type ParserTests() =
  let reader = BinReader.Init Endian.Big
  let parser = Parser(reader) :> IInstructionParsable

  let test (bytes: byte[]) (opcode, oprs: Operands) =
    let span = System.ReadOnlySpan bytes
    let ins = parser.Parse(span, 0UL) :?> Instruction
    let opcode' = ins.Opcode
    let oprs' = ins.Operands
    Assert.AreEqual<Opcode>(opcode, opcode')
    Assert.AreEqual<Operands>(oprs, oprs')

  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let ins = parser.Parse(System.ReadOnlySpan bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  /// A word the decoder must refuse, being no instruction at all.
  let testRefused (byteString: string) =
    let bytes = ByteArray.ofHexString byteString
    let parse () = parser.Parse(bytes, 0UL) |> ignore
    Assert.ThrowsExactly<ParsingFailureException>(fun () -> parse ()) |> ignore

  let operandsFromArray oprList =
    let oprs = Array.ofList oprList
    match oprs.Length with
    | 0 -> NoOperand
    | 1 -> OneOperand oprs[0]
    | 2 -> TwoOperands(oprs[0], oprs[1])
    | 3 -> ThreeOperands(oprs[0], oprs[1], oprs[2])
    | 4 -> FourOperands(oprs[0], oprs[1], oprs[2], oprs[3])
    | 5 -> FiveOperands(oprs[0], oprs[1], oprs[2], oprs[3], oprs[4])
    | _ -> Terminator.impossible ()

  let ( ** ) opcode oprList = opcode, operandsFromArray oprList

  let ( ++ ) byteString pair = ByteArray.ofHexString byteString, pair

  /// The disassembly of a word under the ISA a name gives, or nothing where
  /// that ISA leaves the word UNDEFINED.
  let under (isaName: string) (byteString: string) =
    let parser = Parser(ISA isaName, reader) :> IInstructionParsable
    let bytes = ByteArray.ofHexString byteString
    try Some((parser.Parse(System.ReadOnlySpan bytes, 0UL)).Disasm())
    with :? ParsingFailureException -> None

  /// Checks that a word reads under each ISA of one list and is refused under
  /// each of the other, which is what a version and its extensions decide.
  let readsOnlyUnder word (reads: string list) (refuses: string list) =
    for name in reads do
      Assert.AreEqual<bool>(true, (under name word).IsSome, $"{word} {name}")
    for name in refuses do
      Assert.AreEqual<string option>(None, under name word, $"{word} {name}")

  /// Checks the two readings of a hint-space word: what an ISA without its
  /// feature reads it as, and what one with the feature does.
  let readsAs word without (asHint: string) isaWith (asName: string) =
    Assert.AreEqual<string option>(Some asHint, under without word)
    Assert.AreEqual<string option>(Some asName, under isaWith word)

  /// C4.2.1 Add/subtract (immediate)
  [<TestMethod>]
  member _.``[AArch64] Add/subtract (immedate) Parse Test``() =
    "114dc4ba"
    ++ ADD
    ** [ O.Reg W26; O.Reg W5; O.Imm 0x371L; O.Shift(ShiftOp.LSL, 12L) ]
    ||> test

  [<TestMethod>]
  member _.``C4.2.2 Bit Field (1)``() =
    "13010401"
    ++ SBFX ** [ O.Reg W1; O.Reg W0; O.Imm 0x1L; O.Imm 0x1L ]
    ||> test

  [<TestMethod>]
  member _.``C4.2.3 ExtendType.ract (1)``() =
    "93c00422"
    ++ EXTR ** [ O.Reg X2; O.Reg X1; O.Reg X0; O.LSB 0x1uy ]
    ||> test

  [<TestMethod>]
  member _.``C4.2.4 Logical (immediate) (1)``() =
    "12010401"
    ++ AND ** [ O.Reg W1; O.Reg W0; O.Imm 0x80000001L ]
    ||> test

  [<TestMethod>]
  member _.``C4.2.4 Logical (immediate) (2)``() =
    "12030c01"
    ++ AND ** [ O.Reg W1; O.Reg W0; O.Imm 0xE0000001L ]
    ||> test

  [<TestMethod>]
  member _.``C4.2.4 Logical (immediate) (3)``() =
    "12200401"
    ++ AND ** [ O.Reg W1; O.Reg W0; O.Imm 0x3L ]
    ||> test

  [<TestMethod>]
  member _.``C4.2.4 Logical (immediate) (4)``() =
    "121a7821"
    ++ AND ** [ O.Reg W1; O.Reg W1; O.Imm 0xffffffdfL ]
    ||> test

  [<TestMethod>]
  member _.``C4.2.4 Logical (immediate) (5)``() =
    "92200401"
    ++ AND ** [ O.Reg X1; O.Reg X0; O.Imm 0x300000003L ]
    ||> test

  [<TestMethod>]
  member _.``C4.2.5 Move wide (immediate) (1)``() =
    "92a00015"
    ++ MOVN ** [ O.Reg X21; O.Imm 0x0L; O.Shift(ShiftOp.LSL, 0x10L) ]
    ||> test

  [<TestMethod>]
  member _.``C4.2.5 Move wide (immediate) (2)``() =
    "92e3ffbf"
    ++ MOV ** [ O.Reg XZR; O.Imm 0xE002FFFFFFFFFFFFL ]
    ||> test

  [<TestMethod>]
  member _.``C4.2.5 Move wide (immediate) (3)``() =
    "12b0001a"
    ++ MOV ** [ O.Reg W26; O.Imm 0x7FFFFFFFL ]
    ||> test

  [<TestMethod>]
  member _.``C4.2.6 PC-rel. addressing (1)``() =
    "707ff067"
    ++ ADR ** [ O.Reg X7; O.MemLabel 0xffe0fL ]
    ||> test

  [<TestMethod>]
  member _.``C4.3.1 Compare & branch (immediate) (1)``() =
    "b4041023"
    ++ CBZ ** [ O.Reg X3; O.MemLabel 0x8204L ]
    ||> test

  [<TestMethod>]
  member _.``C4.3.2 Conditional branch (immediate) (1)``() =
    "54000021"
    ++ BNE ** [ O.MemLabel 0x4L ]
    ||> test

  [<TestMethod>]
  member _.``C4.3.3 Exception generation (1)``() =
    "d4000061"
    ++ SVC ** [ O.Imm 0x3L ]
    ||> test

  [<TestMethod>]
  member _.``C4.3.4 System (1)``() =
    "d50042bf"
    ++ MSR ** [ O.Pstate Pstate.SPSEL; O.Imm 0x2L ]
    ||> test

  [<TestMethod>]
  member _.``C4.3.4 System (2)``() =
    "d50342df"
    ++ MSR ** [ O.Pstate DAIFSET; O.Imm 0x2L ]
    ||> test

  /// Hint 6 is DGH (C6.2.79), and DSB's word with CRm 0000 and 0100 is SSBB
  /// and PSSBB (C6.2.245, C6.2.217), not DSB with those options.
  [<TestMethod>]
  member _.``C4.3.4 System (3)``() =
    "d50320df" ++ DGH ** [] ||> test
    "d503309f" ++ SSBB ** [] ||> test
    "d503349f" ++ PSSBB ** [] ||> test
    testDisasm "d503309f" "ssbb"
    testDisasm "d503349f" "pssbb"
    testDisasm "d503389f" "dsb #0x8"

  [<TestMethod>]
  member _.``[AArch64] DGH reads as HINT before Armv8.6``() =
    readsAs "d50320df" "armv8.5-a" "hint #0x6" "armv8.6-a" "dgh"

  /// BFM from the zero register with imms below immr is BFC (C6.2.27), the
  /// one bitfield move that had kept its raw name; DCPS's immediate is
  /// optional and is not written when it is zero (C6.2.76).
  [<TestMethod>]
  member _.``[AArch64] BFC and DCPS print as the manual prefers``() =
    testDisasm "331d0fe0" "bfc w0, #0x3, #0x4"
    testDisasm "b37d0fe1" "bfc x1, #0x3, #0x4"
    testDisasm "331d0c20" "bfi w0, w1, #0x3, #0x4"
    testDisasm "d4a00001" "dcps1"
    testDisasm "d4a000a2" "dcps2 #0x5"

  [<TestMethod>]
  member _.``C4.3.4 System (4)``() =
    "d50320bf"
    ++ SEVL ** []
    ||> test

  [<TestMethod>]
  member _.``C4.3.4 System (5)``() =
    "d50b7423"
    ++ DCZVA ** [ O.Reg X3 ]
    ||> test

  /// DC CVAP and DC CVADP clean to the points of persistence and of deep
  /// persistence (DDI0487F.c C5.3.18 and C5.3.17).
  [<TestMethod>]
  member _.``[AArch64] DC CVAP and DC CVADP decode``() =
    testDisasm "d50b7c21" "dc cvap, x1"
    testDisasm "d50b7d22" "dc cvadp, x2"

  /// <summary>
  /// Every alias of SYS prints as the manual prefers it: DC, AT, IC, TLBI,
  /// CFP, DVP and CPP with the operation they name (C6.2.75, C6.2.19,
  /// C6.2.95, C6.2.328, C6.2.51, C6.2.83 and C6.2.65), where all but DC's
  /// had printed as SYS and DC's as one word, "dczva x1".
  ///
  /// IC's and TLBI's register is optional and defaults to 11111: an
  /// operation that reads none leaves it out there and writes it anywhere
  /// else, and one that reads it writes it always. FEAT_MTE's DC operations
  /// were refused. A SYS no alias names stays SYS, whose register is
  /// optional in the same way (C6.2.324).
  /// </summary>
  [<TestMethod>]
  member _.``[AArch64] The aliases of SYS print by name``() =
    testDisasm "d50b7421" "dc zva, x1"
    testDisasm "d50b7463" "dc gva, x3"
    testDisasm "d50b7484" "dc gzva, x4"
    testDisasm "d5087685" "dc igsw, x5"
    testDisasm "d50b7ea6" "dc cigdvac, x6"
    testDisasm "d5087802" "at s1e1r, x2"
    testDisasm "d5087921" "at s1e1wp, x1"
    testDisasm "d50c78c3" "at s12e0r, x3"
    testDisasm "d508751f" "ic iallu"
    testDisasm "d5087505" "ic iallu, x5"
    testDisasm "d50b7520" "ic ivau, x0"
    testDisasm "d50b753f" "ic ivau, xzr"
    testDisasm "d508871f" "tlbi vmalle1"
    testDisasm "d5088723" "tlbi vae1, x3"
    testDisasm "d508811f" "tlbi vmalle1os"
    testDisasm "d5088621" "tlbi rvae1, x1"
    testDisasm "d50b7384" "cfp rctx, x4"
    testDisasm "d50b73a4" "dvp rctx, x4"
    testDisasm "d50b73e4" "cpp rctx, x4"
    testDisasm "d5080005" "sys #0x0, c0, c0, #0x0, x5"
    testDisasm "d508701f" "sys #0x0, c7, c0, #0x0"

  /// An operation a version does not have is refused under it, as the
  /// processor refuses it: FEAT_TLBIOS's TLBI forms are Armv8.4's and
  /// FEAT_MTE's DC forms are had by naming the extension.
  [<TestMethod>]
  member _.``[AArch64] The aliases of SYS follow their versions``() =
    readsOnlyUnder "d508811f" [ "armv8.4-a" ] [ "armv8.3-a" ]
    readsOnlyUnder "d50b7463" [ "armv8.5-a+memtag" ] [ "armv8.5-a" ]

  [<TestMethod>]
  member _.``C4.3.4 System (6)``() =
    "d528f4d8"
    ++ SYSL ** [ O.Reg X24; O.Imm 0L; O.Reg C15; O.Reg C4; O.Imm 6L ]
    ||> test

  [<TestMethod>]
  member _.``C4.3.4 System (7)``() =
    "d51c6080"
    ++ MSR ** [ O.Reg HPFAREL2; O.Reg X0 ]
    ||> test

  [<TestMethod>]
  member _.``C4.3.4 System (8)``() =
    "d5181020"
    ++ MSR ** [ O.Reg ACTLREL1; O.Reg X0 ]
    ||> test

  [<TestMethod>]
  member _.``C4.3.4 System (9)``() =
    "d5381020"
    ++ MRS ** [ O.Reg X0; O.Reg ACTLREL1 ]
    ||> test

  [<TestMethod>]
  member _.``C4.3.4 System (10)``() =
    "d50330ff"
    ++ SB ** []
    ||> test

  [<TestMethod>]
  member _.``C4.3.4 System (11)``() =
    "d500419f"
    ++ MSR ** [ O.Pstate Pstate.PAN; O.Imm 0x1L ]
    ||> test

  [<TestMethod>]
  member _.``C4.3.4 System (12)``() =
    "d500417f"
    ++ MSR ** [ O.Pstate Pstate.UAO; O.Imm 0x1L ]
    ||> test

  [<TestMethod>]
  member _.``C4.3.4 System (13)``() =
    "d503415f"
    ++ MSR ** [ O.Pstate Pstate.DIT; O.Imm 0x1L ]
    ||> test

  [<TestMethod>]
  member _.``C4.3.4 System (14)``() =
    "d503413f"
    ++ MSR ** [ O.Pstate Pstate.SSBS; O.Imm 0x1L ]
    ||> test

  [<TestMethod>]
  member _.``C4.3.4 System (15)``() =
    "d503419f"
    ++ MSR ** [ O.Pstate Pstate.TCO; O.Imm 0x1L ]
    ||> test

  [<TestMethod>]
  member _.``C4.3.4 System (16)``() =
    "d5384260"
    ++ MRS ** [ O.Reg X0; O.Reg PAN ]
    ||> test

  [<TestMethod>]
  member _.``C4.3.4 System (17)``() =
    "d5184201"
    ++ MSR ** [ O.Reg SPSEL; O.Reg X1 ]
    ||> test

  /// A system register this front end has no name for is still a system
  /// register, written by its encoding the way the manual spells one that has
  /// no name -- S<op0>_<op1>_C<n>_C<m>_<op2> -- and not refused.
  [<TestMethod>]
  member _.``C4.3.4 System (18)``() =
    testDisasm "d538f200" "mrs x0, s3_0_c15_c2_0"

  [<TestMethod>]
  member _.``C4.3.4 System (19)``() =
    testDisasm "d51ff001" "msr s3_7_c15_c0_0, x1"

  [<TestMethod>]
  member _.``C4.3.4 System (20)``() =
    testDisasm "d53314e5" "mrs x5, s2_3_c1_c4_7"

  /// S3_7_C2_C2_7 is the register the table names; the word with op0 = 2 is
  /// another one, and has no name.
  [<TestMethod>]
  member _.``C4.3.4 System (21)``() =
    testDisasm "d53f22e0" "mrs x0, s3_7_c2_c2_7"

  [<TestMethod>]
  member _.``C4.3.4 System (22)``() =
    testDisasm "d53722e0" "mrs x0, s2_7_c2_c2_7"

  /// The hints the manual names are read by name: BTI with the branches it
  /// admits, and ESB, PSB CSYNC, TSB CSYNC and CSDB.
  [<TestMethod>]
  member _.``C4.3.4 System (23)``() =
    testDisasm "d503241f" "bti"

  [<TestMethod>]
  member _.``C4.3.4 System (24)``() =
    testDisasm "d503245f" "bti c"

  [<TestMethod>]
  member _.``C4.3.4 System (25)``() =
    testDisasm "d503249f" "bti j"

  [<TestMethod>]
  member _.``C4.3.4 System (26)``() =
    testDisasm "d50324df" "bti jc"

  [<TestMethod>]
  member _.``C4.3.4 System (27)``() =
    testDisasm "d503221f" "esb"

  [<TestMethod>]
  member _.``C4.3.4 System (28)``() =
    testDisasm "d503223f" "psb csync"

  [<TestMethod>]
  member _.``C4.3.4 System (29)``() =
    testDisasm "d503225f" "tsb csync"

  [<TestMethod>]
  member _.``C4.3.4 System (30)``() =
    testDisasm "d503229f" "csdb"

  /// PAR_EL1, where AT puts its result, is S3_0_C7_C4_0 and has its name.
  [<TestMethod>]
  member _.``C4.3.4 System (31)``() =
    testDisasm "d5387400" "mrs x0, par_el1"

  /// CNTFRQ_EL0 and TPIDRRO_EL0 have their names.
  [<TestMethod>]
  member _.``C4.3.4 System (32)``() =
    testDisasm "d53be000" "mrs x0, cntfrq_el0"
    testDisasm "d51bd061" "msr tpidrro_el0, x1"

  /// op1:op2 of 001:000 names no field of PSTATE, and the manual leaves the
  /// encoding UNDEFINED.
  [<TestMethod>]
  member _.``[AArch64] MSR (immediate) naming no field is refused``() =
    testRefused "d501401f"

  [<TestMethod>]
  member _.``C4.3.5 Test & branch (immediate) (1)``() =
    "b6080043"
    ++ TBZ ** [ O.Reg X3; O.Imm 0x21L; O.MemLabel 0x8L ]
    ||> test

  [<TestMethod>]
  member _.``C4.3.6 Unconditional branch (immediate) (1)``() =
    "14082a09"
    ++ B ** [ O.MemLabel 0x20a824L ]
    ||> test

  [<TestMethod>]
  member _.``C4.3.7 Unconditional branch (register) (1)``() =
    "d61f03e0"
    ++ BR ** [ O.Reg XZR ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.1 load/store multiple structures (1)``() =
    "0c0001c5"
    ++ ST4 ** [ O.SIMDList([ V5; V6; V7; V8 ], EightB); O.MemBaseImm X14 ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.1 load/store multiple structures (2)``() =
    "0c0081f8"
    ++ ST2 ** [ O.SIMDList([ V24; V25 ], EightB); O.MemBaseImm X15 ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.1 load/store multiple structures (3)``() =
    "0c402f3d"
    ++ LD1 ** [ O.SIMDList([ V29; V30; V31; V0 ], OneD); O.MemBaseImm X25 ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.2 load/store multiple structures (post-indexed) (1)``() =
    "0c800421"
    ++ ST4 ** [ O.SIMDList([ V1; V2; V3; V4 ], FourH); O.MemPostIdxReg(X1, X0) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.2 load/store multiple structures (post-indexed) (2)``() =
    "0c950539"
    ++ ST4 ** [ O.SIMDList([ V25; V26; V27; V28 ], FourH)
                O.MemPostIdxReg(X9, X21) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.2 load/store multiple structures (post-indexed) (3)``() =
    "4c9f0684"
    ++ ST4 ** [ O.SIMDList([ V4; V5; V6; V7 ], EightH)
                O.MemPostIdxImm(X20, 0x40L) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.2 load/store multiple structures (post-indexed) (4)``() =
    "4cca46be"
    ++ LD3 ** [ O.SIMDList([ V30; V31; V0 ], EightH)
                O.MemPostIdxReg(X21, X10) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.2 load/store multiple structures (post-indexed) (5)``() =
    "4cdf0684"
    ++ LD4 ** [ O.SIMDList([ V4; V5; V6; V7 ], EightH)
                O.MemPostIdxImm(X20, 0x40L) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.3 load/store single structure (1)``() =
    "0d00147e"
    ++ ST1 ** [ O.SIMDList([ V30 ], VecB, 5uy); O.MemBaseImm X3 ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.3 load/store single structure (2)``() =
    "0d0025c3"
    ++ ST3 ** [ O.SIMDList([ V3; V4; V5 ], VecB, 1uy); O.MemBaseImm X14 ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.3 load/store single structure (3)``() =
    "4d20b2bd"
    ++ ST4 ** [ O.SIMDList([ V29; V30; V31; V0 ], VecS, 3uy)
                O.MemBaseImm X21 ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.3 load/store single structure (4)``() =
    "4d601d4a"
    ++ LD2 ** [ O.SIMDList([ V10; V11 ], VecB, 0xfuy); O.MemBaseImm X10 ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.3 load/store single structure (5)``() =
    "4d40e6b5"
    ++ LD3R ** [ O.SIMDList([ V21; V22; V23 ], EightH); O.MemBaseImm X21 ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.4 load/store single structure (post-indexed) (1)``() =
    "0d8a06be"
    ++ ST1 ** [ O.SIMDList([ V30 ], VecB, 1uy); O.MemPostIdxReg(X21, X10) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.4 load/store single structure (post-indexed) (2)``() =
    "4d9f597e"
    ++ ST1 ** [ O.SIMDList([ V30 ], VecH, 7uy)
                O.MemPostIdxImm(X11, 0x2L) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.4 load/store single structure (post-indexed) (3)``() =
    "4db581bd"
    ++ ST2 ** [ O.SIMDList([ V29; V30 ], VecS, 2uy)
                O.MemPostIdxReg(X13, X21) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.4 load/store single structure (post-indexed) (4)``() =
    "0dca06be"
    ++ LD1 ** [ O.SIMDList([ V30 ], VecB, 1uy); O.MemPostIdxReg(X21, X10) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.4 load/store single structure (post-indexed) (5)``() =
    "4dff39fd"
    ++ LD4 ** [ O.SIMDList([ V29; V30; V31; V0 ], VecB, 0xeuy)
                O.MemPostIdxImm(X15, 0x4L) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.5 Load register (literal) (1)``() =
    "58531c49"
    ++ LDR ** [ O.Reg X9; O.MemLabel 0xa6388L ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.5 Load register (literal) (2)``() =
    "9880001e"
    ++ LDRSW ** [ O.Reg X30; O.MemLabel 0xfffffffffff00000L ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.5 Load register (literal) (3)``() =
    "d800802b"
    ++ PRFM ** [ O.Prefetch PLIL2STRM; O.MemLabel 0x1004L ]
    ||> test

  /// A post-indexed access keeps a zero offset, which the other addressing
  /// modes leave out: it is what closes the bracket and says that the base is
  /// written back.
  [<TestMethod>]
  member _.``C4.4.5 Load/store Disasm test (1)``() =
    testDisasm "f8400420" "ldr x0, [x1], #0x0"

  [<TestMethod>]
  member _.``C4.4.5 Load/store Disasm test (2)``() =
    testDisasm "f9400020" "ldr x0, [x1]"

  [<TestMethod>]
  member _.``C4.4.5 Load/store Disasm test (3)``() =
    testDisasm "f8408420" "ldr x0, [x1], #0x8"

  /// The pair transfers reach the same post-indexed zero offset.
  [<TestMethod>]
  member _.``C4.4.5 Load/store Disasm test (4)``() =
    testDisasm "a8c00440" "ldp x0, x1, [x2], #0x0"

  [<TestMethod>]
  member _.``C4.4.6 Load/store exclusive (1)``() =
    "08147cb5"
    ++ STXRB ** [ O.Reg W20; O.Reg W21; O.MemBaseImm X5 ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.6 Load/store exclusive (2)``() =
    "882b04c2"
    ++ STXP ** [ O.Reg W11; O.Reg W2; O.Reg W1; O.MemBaseImm X6 ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.6 Load/store exclusive (3)``() =
    "085f7d7a"
    ++ LDXRB ** [ O.Reg W26; O.MemBaseImm X11 ]
    ||> test

  /// FEAT_LSE's compare and swap of a pair takes an even register for
  /// each pair and encodes only it.
  [<TestMethod>]
  member _.``C4.4.6 Load/store exclusive (CASP) (1)``() =
    testDisasm "08207c82" "casp w0, w1, w2, w3, [x4]"

  [<TestMethod>]
  member _.``C4.4.6 Load/store exclusive (CASP) (2)``() =
    testDisasm "08607c82" "caspa w0, w1, w2, w3, [x4]"

  [<TestMethod>]
  member _.``C4.4.6 Load/store exclusive (CASP) (3)``() =
    testDisasm "0860fc82" "caspal w0, w1, w2, w3, [x4]"

  [<TestMethod>]
  member _.``C4.4.6 Load/store exclusive (CASP) (4)``() =
    testDisasm "0820fc82" "caspl w0, w1, w2, w3, [x4]"

  [<TestMethod>]
  member _.``C4.4.6 Load/store exclusive (CASP) (5)``() =
    testDisasm "48207c82" "casp x0, x1, x2, x3, [x4]"

  [<TestMethod>]
  member _.``C4.4.6 Load/store exclusive (CASP) (6)``() =
    testDisasm "48667fe8" "caspa x6, x7, x8, x9, [sp]"

  [<TestMethod>]
  member _.``C4.4.6 Load/store exclusive (CASP) (7)``() =
    testDisasm "487cfd8a" "caspal x28, x29, x10, x11, [x12]"

  [<TestMethod>]
  member _.``C4.4.6 Load/store exclusive (CASP) (8)``() =
    testDisasm "4822fcc4" "caspl x2, x3, x4, x5, [x6]"

  [<TestMethod>]
  member _.``C4.4.7 Load/store no-allocate pair (offset) (1)``() =
    "280c2aa3"
    ++ STNP ** [ O.Reg W3; O.Reg W10; O.MemBaseImm(X21, 0x60L) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.7 Load/store no-allocate pair (offset) (2)``() =
    "ac1505b5"
    ++ STNP ** [ O.ScalarReg Q21; O.ScalarReg Q1; O.MemBaseImm(X13, 0x2a0L) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.8 Load/store register (immediate post-indexed) (1)``() =
    "3810a423"
    ++ STRB ** [ O.Reg W3; O.MemPostIdxImm(X1, 0xffffffffffffff0aL) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.8 Load/store register (immediate post-indexed) (2)``() =
    "38cea4b2"
    ++ LDRSB ** [ O.Reg W18; O.MemPostIdxImm(X5, 0xeaL) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.8 Load/store register (immediate post-indexed) (3)``() =
    "7c0ca422"
    ++ STR ** [ O.ScalarReg H2; O.MemPostIdxImm(X1, 0xcaL) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.8 Load/store register (immediate post-indexed) (4)``() =
    "781004f5"
    ++ STRH ** [ O.Reg W21; O.MemPostIdxImm(X7, 0xffffffffffffff00L) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.8 Load/store register (immediate post-indexed) (5)``() =
    "b8803555"
    ++ LDRSW ** [ O.Reg X21; O.MemPostIdxImm(X10, 0x3L) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.9 Load/store register (immediate pre-indexed) (1)``() =
    "3800fcb1"
    ++ STRB ** [ O.Reg W17; O.MemPreIdxImm(X5, 0xfL) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.9 Load/store register (immediate pre-indexed) (2)``() =
    "7c00fc6a"
    ++ STR ** [ O.ScalarReg H10; O.MemPreIdxImm(X3, 0xfL) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.10 Load/store register (register offset) (1)``() =
    "38214867"
    ++ STRB ** [ O.Reg W7; O.MemBaseReg(X3, W1, ExtendType.UXTW, None) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.10 Load/store register (register offset) (2)``() =
    "38235867"
    ++ STRB ** [ O.Reg W7; O.MemBaseReg(X3, W3, ExtendType.UXTW, Some 0x0L) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.10 Load/store register (register offset) (3)``() =
    "3820782c"
    ++ STRB ** [ O.Reg W12; O.MemBaseReg(X1, X0, ShiftOp.LSL, Imm 0x0L) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.10 Load/store register (register offset) (4)``() =
    "7867cabf"
    ++ LDRH ** [ O.Reg WZR; O.MemBaseReg(X21, W7, ExtendType.SXTW, None) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.10 Load/store register (register offset) (5)``() =
    "78e37871"
    ++ LDRSH
    ** [ O.Reg W17; O.MemBaseReg(X3, X3, ShiftOp.LSL, Imm 0x1L) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.10 Load/store register (register offset) (6)``() =
    "f8a35867"
    ++ PRFM ** [ O.Imm 0x7L; O.MemBaseReg(X3, W3, ExtendType.UXTW, Some 0x3L) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.10 Load/store register (register offset) (7)``() =
    "f8a3586c"
    ++ PRFM ** [ O.Prefetch PLIL3KEEP
                 O.MemBaseReg(X3, W3, ExtendType.UXTW, Some 0x3L) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.11 Load/store register (unprivileged) (1)``() =
    "380198ee"
    ++ STTRB ** [ O.Reg W14; O.MemBaseImm(X7, 0x19L) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.11 Load/store register (unprivileged) (2)``() =
    "781188ba"
    ++ STTRH ** [ O.Reg W26; O.MemBaseImm(X5, 0xffffffffffffff18L) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.11 Load/store register (unprivileged) (3)``() =
    "b881f86a"
    ++ LDTRSW ** [ O.Reg X10; O.MemBaseImm(X3, 0x1fL) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.12 Load/store register (unscaled immediate) (1)``() =
    "3806a0f8"
    ++ STURB ** [ O.Reg W24; O.MemBaseImm(X7, 0x6aL) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.12 Load/store register (unscaled immediate) (2)``() =
    "3cce0283"
    ++ LDUR ** [ O.ScalarReg Q3; O.MemBaseImm(X20, 0xe0L) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.12 Load/store register (unscaled immediate) (3)``() =
    "f881f07c"
    ++ PRFUM ** [ O.Imm 0x1cL; O.MemBaseImm(X3, 0x1fL) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.13 Load/store register (unsigned immediate) (1)``() =
    "391557ff"
    ++ STRB ** [ O.Reg WZR; O.MemBaseImm(SP, 0x555L) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.13 Load/store register (unsigned immediate) (2)``() =
    "bd1fffff"
    ++ STR ** [ O.ScalarReg S31; O.MemBaseImm(SP, 0x1ffcL) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.13 Load/store register (unsigned immediate) (3)``() =
    "f9be01f2"
    ++ PRFM ** [ O.Prefetch PSTL2KEEP; O.MemBaseImm(X15, 0x7c00L) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.14 Load/store register pair (offset) (1)``() =
    "2961cbb9"
    ++ LDP ** [ O.Reg W25; O.Reg W18; O.MemBaseImm(X29, 0xffffffffffffff0cL) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.15 Load/store register pair (post-indexed) (1)``() =
    "a89fd7eb"
    ++ STP ** [ O.Reg X11; O.Reg X21; O.MemPostIdxImm(SP, 0x1f8L) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.15 Load/store register pair (post-indexed) (2)``() =
    "68cfdfdf"
    ++ LDPSW ** [ O.Reg XZR; O.Reg X23; O.MemPostIdxImm(X30, 0x7cL) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4.16 Load/store register pair (pre-indexed) (1)``() =
    "a99fffff"
    ++ STP ** [ O.Reg XZR; O.Reg XZR; O.MemPreIdxImm(SP, 0x1f8L) ]
    ||> test

  [<TestMethod>]
  member _.``4.5.1 Add/subtract (extended register) (1)``() =
    "0b3f43ff"
    ++ ADD ** [ O.Reg WSP; O.Reg WSP; O.Reg WZR; O.RegOffset None ]
    ||> test

  [<TestMethod>]
  member _.``4.5.1 Add/subtract (extended register) (2)``() =
    "0b3f4bff"
    ++ ADD ** [ O.Reg WSP
                O.Reg WSP
                O.Reg WZR
                O.RegOffset(Some(ShiftOffset(ShiftOp.LSL, Imm 2L))) ]
    ||> test

  [<TestMethod>]
  member _.``4.5.1 Add/subtract (extended register) (3)``() =
    "8b2a495f"
    ++ ADD ** [ O.Reg SP
                O.Reg X10
                O.Reg W10
                O.RegOffset(Some(ExtRegOffset(ExtendType.UXTW, Some 2L))) ]
    ||> test

  [<TestMethod>]
  member _.``4.5.1 Add/subtract (extended register) (4)``() =
    "ab2e67ff"
    ++ CMN ** [ O.Reg SP
                O.Reg X14
                O.RegOffset(Some(ShiftOffset(ShiftOp.LSL, Imm 1L))) ]
    ||> test

  [<TestMethod>]
  member _.``4.5.2 Add/subtract (shifted register) (1)``() =
    "0b8e5f9b"
    ++ ADD
    ** [ O.Reg W27; O.Reg W28; O.Reg W14; O.Shift(ShiftOp.ASR, 23L) ]
    ||> test

  [<TestMethod>]
  member _.``4.5.2 Add/subtract (shifted register) (2)``() =
    "6b4e1fab"
    ++ SUBS
    ** [ O.Reg W11; O.Reg W29; O.Reg W14; O.Shift(ShiftOp.LSR, 7L) ]
    ||> test

  [<TestMethod>]
  member _.``4.5.2 Add/subtract (shifted register) (3)``() =
    "ab8e1fb2"
    ++ ADDS
    ** [ O.Reg X18; O.Reg X29; O.Reg X14; O.Shift(ShiftOp.ASR, 7L) ]
    ||> test

  [<TestMethod>]
  member _.``4.5.3 Add/subtract (with carry) (1)``() =
    "ba0a02bf"
    ++ ADCS ** [ O.Reg XZR; O.Reg X21; O.Reg X10 ]
    ||> test

  [<TestMethod>]
  member _.``4.5.3 Add/subtract (with carry) (2)``() =
    "5a0b03fe"
    ++ NGC ** [ O.Reg W30; O.Reg W11 ]
    ||> test

  [<TestMethod>]
  member _.``4.5.4 Conditional compare (immediate) (1)``() =
    "ba55c868"
    ++ CCMN ** [ O.Reg X3; O.Imm 0x15L; OprNZCV 8uy; OprCond GT ]
    ||> test

  [<TestMethod>]
  member _.``4.5.5 Conditional compare (register) (1)``() =
    "ba5c51ef"
    ++ CCMN ** [ O.Reg X15; O.Reg X28; OprNZCV 0xfuy; OprCond PL ]
    ||> test

  [<TestMethod>]
  member _.``4.5.6 Conditional select (1)``() =
    "9a8692fc"
    ++ CSEL ** [ O.Reg X28; O.Reg X23; O.Reg X6; OprCond LS ]
    ||> test

  [<TestMethod>]
  member _.``4.5.6 Conditional select (2)``() =
    "1a902415"
    ++ CSINC ** [ O.Reg W21; O.Reg W0; O.Reg W16; OprCond CS ] // HS
    ||> test

  [<TestMethod>]
  member _.``4.5.6 Conditional select (3)``() =
    "1a902615"
    ++ CINC ** [ O.Reg W21; O.Reg W16; OprCond CC ] // LO
    ||> test

  [<TestMethod>]
  member _.``4.5.6 Conditional select (4)``() =
    "1a9fc7e7"
    ++ CSET ** [ O.Reg W7; OprCond LE ]
    ||> test

  [<TestMethod>]
  member _.``4.5.6 Conditional select (5)``() =
    "da87c0ea"
    ++ CINV ** [ O.Reg X10; O.Reg X7; OprCond LE ]
    ||> test

  [<TestMethod>]
  member _.``4.5.6 Conditional select (6)``() =
    "da9fc3ea"
    ++ CSETM ** [ O.Reg X10; OprCond LE ]
    ||> test

  [<TestMethod>]
  member _.``4.5.6 Conditional select (7)``() =
    "da9fc36a"
    ++ CSINV ** [ O.Reg X10; O.Reg X27; O.Reg XZR; OprCond GT ]
    ||> test

  [<TestMethod>]
  member _.``4.5.6 Conditional select (8)``() =
    "5a8ae6be"
    ++ CSNEG ** [ O.Reg W30; O.Reg W21; O.Reg W10; OprCond AL ]
    ||> test

  [<TestMethod>]
  member _.``4.5.6 Conditional select (9)``() =
    "5a95c6be"
    ++ CNEG ** [ O.Reg W30; O.Reg W21; OprCond LE ]
    ||> test

  [<TestMethod>]
  member _.``4.5.7 Data-processing (1 source) (1)``() =
    "5ac0017c"
    ++ RBIT ** [ O.Reg W28; O.Reg W11 ]
    ||> test

  [<TestMethod>]
  member _.``4.5.7 Data-processing (1 source) (2)``() =
    "dac0157f"
    ++ CLS ** [ O.Reg XZR; O.Reg X11 ]
    ||> test

  [<TestMethod>]
  member _.``4.5.7 Data-processing (1 source) (3)``() =
    "dac009fe"
    ++ REV32 ** [ O.Reg X30; O.Reg X15 ]
    ||> test

  [<TestMethod>]
  member _.``4.5.8 Data-processing (2 source) (1)``() =
    "1ac90afe"
    ++ UDIV ** [ O.Reg W30; O.Reg W23; O.Reg W9 ]
    ||> test

  [<TestMethod>]
  member _.``4.5.8 Data-processing (2 source) (2)``() =
    "9ada5c7d"
    ++ CRC32CX ** [ O.Reg W29; O.Reg W3; O.Reg X26 ]
    ||> test

  [<TestMethod>]
  member _.``4.5.9 Data-processing (3 source) (1)``() =
    "9b0a2f87"
    ++ MADD ** [ O.Reg X7; O.Reg X28; O.Reg X10; O.Reg X11 ]
    ||> test

  [<TestMethod>]
  member _.``4.5.9 Data-processing (3 source) (2)``() =
    "9b0a7f87"
    ++ MUL ** [ O.Reg X7; O.Reg X28; O.Reg X10 ]
    ||> test

  [<TestMethod>]
  member _.``4.5.9 Data-processing (3 source) (3)``() =
    "9b0aaf87"
    ++ MSUB ** [ O.Reg X7; O.Reg X28; O.Reg X10; O.Reg X11 ]
    ||> test

  [<TestMethod>]
  member _.``4.5.9 Data-processing (3 source) (4)``() =
    "9b2a2f87"
    ++ SMADDL ** [ O.Reg X7; O.Reg W28; O.Reg W10; O.Reg X11 ]
    ||> test

  [<TestMethod>]
  member _.``4.5.9 Data-processing (3 source) (5)``() =
    "9b2aaf87"
    ++ SMSUBL ** [ O.Reg X7; O.Reg W28; O.Reg W10; O.Reg X11 ]
    ||> test

  [<TestMethod>]
  member _.``4.5.9 Data-processing (3 source) (6)``() =
    "9b4a2f87"
    ++ SMULH ** [ O.Reg X7; O.Reg X28; O.Reg X10 ]
    ||> test

  [<TestMethod>]
  member _.``4.5.9 Data-processing (3 source) (7)``() =
    "9baa2f87"
    ++ UMADDL ** [ O.Reg X7; O.Reg W28; O.Reg W10; O.Reg X11 ]
    ||> test

  [<TestMethod>]
  member _.``4.5.9 Data-processing (3 source) (8)``() =
    "9baaaf87"
    ++ UMSUBL ** [ O.Reg X7; O.Reg W28; O.Reg W10; O.Reg X11 ]
    ||> test

  [<TestMethod>]
  member _.``4.5.9 Data-processing (3 source) (9)``() =
    "9bca2f87"
    ++ UMULH ** [ O.Reg X7; O.Reg X28; O.Reg X10 ]
    ||> test

  [<TestMethod>]
  member _.``4.5.9 Data-processing (3 source) (10)``() =
    "9b0aff87"
    ++ MNEG ** [ O.Reg X7; O.Reg X28; O.Reg X10 ]
    ||> test

  [<TestMethod>]
  member _.``4.5.9 Data-processing (3 source) (11)``() =
    "9b2a7f87"
    ++ SMULL ** [ O.Reg X7; O.Reg W28; O.Reg W10 ]
    ||> test

  [<TestMethod>]
  member _.``4.5.9 Data-processing (3 source) (12)``() =
    "9b2aff87"
    ++ SMNEGL ** [ O.Reg X7; O.Reg W28; O.Reg W10 ]
    ||> test

  [<TestMethod>]
  member _.``4.5.9 Data-processing (3 source) (13)``() =
    "9baa7f87"
    ++ UMULL ** [ O.Reg X7; O.Reg W28; O.Reg W10 ]
    ||> test

  [<TestMethod>]
  member _.``4.5.9 Data-processing (3 source) (14)``() =
    "9baaff87"
    ++ UMNEGL ** [ O.Reg X7; O.Reg W28; O.Reg W10 ]
    ||> test

  [<TestMethod>]
  member _.``4.5.10 Logical (shifted register) (1)``() =
    "8a583945"
    ++ AND
    ** [ O.Reg X5; O.Reg X10; O.Reg X24; O.Shift(ShiftOp.LSR, 14L) ]
    ||> test

  [<TestMethod>]
  member _.``4.5.10 Logical (shifted register) (2)``() =
    "2af61fba"
    ++ ORN
    ** [ O.Reg W26; O.Reg W29; O.Reg W22; O.Shift(ShiftOp.ROR, 7L) ]
    ||> test

  [<TestMethod>]
  member _.``4.5.10 Logical (shifted register) (3)``() =
    "2af61ffa"
    ++ MVN ** [ O.Reg W26; O.Reg W22; O.Shift(ShiftOp.ROR, 0x7L) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.1 Advanced SIMD across lanes (1)``() =
    "4eb03ac2"
    ++ SADDLV ** [ O.ScalarReg D2; O.SIMDVecReg(V22, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.1 Advanced SIMD across lanes (2)``() =
    "0e30a8d2"
    ++ SMAXV ** [ O.ScalarReg B18; O.SIMDVecReg(V6, EightB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.1 Advanced SIMD across lanes (3)``() =
    "0e71aa0a"
    ++ SMINV ** [ O.ScalarReg H10; O.SIMDVecReg(V16, FourH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.1 Advanced SIMD across lanes (4)``() =
    "4e71b89a"
    ++ ADDV ** [ O.ScalarReg H26; O.SIMDVecReg(V4, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.1 Advanced SIMD across lanes (5)``() =
    "6eb03931"
    ++ UADDLV ** [ O.ScalarReg D17; O.SIMDVecReg(V9, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.1 Advanced SIMD across lanes (6)``() =
    "2e70ab88"
    ++ UMAXV ** [ O.ScalarReg H8; O.SIMDVecReg(V28, FourH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.1 Advanced SIMD across lanes (7)``() =
    "6eb1aaea"
    ++ UMINV ** [ O.ScalarReg S10; O.SIMDVecReg(V23, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.1 Advanced SIMD across lanes (8)``() =
    "6e30ca4b"
    ++ FMAXNMV ** [ O.ScalarReg S11; O.SIMDVecReg(V18, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.1 Advanced SIMD across lanes (9)``() =
    "6e30f948"
    ++ FMAXV ** [ O.ScalarReg S8; O.SIMDVecReg(V10, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.1 Advanced SIMD across lanes (10)``() =
    "6eb0cacc"
    ++ FMINNMV ** [ O.ScalarReg S12; O.SIMDVecReg(V22, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.1 Advanced SIMD across lanes (11)``() =
    "6eb0fac2"
    ++ FMINV ** [ O.ScalarReg S2; O.SIMDVecReg(V22, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.2 Advanced SIMD copy (1)``() =
    "4e180486"
    ++ DUP ** [ O.SIMDVecReg(V6, TwoD); O.SIMDVecRegWithIdx(V4, VecD, 1uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.2 Advanced SIMD copy (2)``() =
    "4e080c61"
    ++ DUP ** [ O.SIMDVecReg(V1, TwoD); O.Reg X3 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.2 Advanced SIMD copy (3)``() =
    // Online HEX To ARM Conv error
    "0e1e0ffc"
    ++ DUP ** [ O.SIMDVecReg(V28, FourH); O.Reg WZR ]
    ||> test

  [<TestMethod>]
  member _.``4.6.2 Advanced SIMD copy (4)``() =
    "0e020ffc"
    ++ DUP ** [ O.SIMDVecReg(V28, FourH); O.Reg WZR ]
    ||> test

  [<TestMethod>]
  member _.``4.6.2 Advanced SIMD copy (5)``() =
    "0e022cfa"
    ++ SMOV ** [ O.Reg W26; O.SIMDVecRegWithIdx(V7, VecH, 0uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.2 Advanced SIMD copy (6)``() =
    "0e013dc3"
    ++ UMOV ** [ O.Reg W3; O.SIMDVecRegWithIdx(V14, VecB, 0uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.2 Advanced SIMD copy (7)``() =
    "0e043dc3"
    ++ MOV ** [ O.Reg W3; O.SIMDVecRegWithIdx(V14, VecS, 0uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.2 Advanced SIMD copy (8)``() =
    "4e083dc3"
    ++ MOV ** [ O.Reg X3; O.SIMDVecRegWithIdx(V14, VecD, 0uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.2 Advanced SIMD copy (9)``() =
    "4e041c29"
    ++ INS ** [ O.SIMDVecRegWithIdx(V9, VecS, 0uy); O.Reg W1 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.2 Advanced SIMD copy (10)``() =
    "6e0274c5"
    ++ INS ** [ O.SIMDVecRegWithIdx(V5, VecH, 0uy)
                O.SIMDVecRegWithIdx(V6, VecH, 7uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.3 Advanced SIMD extract (1)``() =
    "6e064983"
    ++ EXT ** [ O.SIMDVecReg(V3, SixteenB)
                O.SIMDVecReg(V12, SixteenB)
                O.SIMDVecReg(V6, SixteenB)
                O.Imm 9L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.3 Advanced SIMD extract (2)``() =
    "2e0738fc"
    ++ EXT ** [ O.SIMDVecReg(V28, EightB)
                O.SIMDVecReg(V7, EightB)
                O.SIMDVecReg(V7, EightB)
                O.Imm 7L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.4 Advanced SIMD modified immediate (1)``() =
    "4f056559"
    ++ MOVI ** [ O.SIMDVecReg(V25, FourS)
                 O.Imm 0xAAL
                 O.Shift(ShiftOp.LSL, 24L) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.4 Advanced SIMD modified immediate (2)``() =
    "4f050559"
    ++ MOVI ** [ O.SIMDVecReg(V25, FourS); O.Imm 0xAAL ]
    ||> test

  [<TestMethod>]
  member _.``4.6.4 Advanced SIMD modified immediate (3)``() =
    "4f0234c5"
    ++ ORR
    ** [ O.SIMDVecReg(V5, FourS); O.Imm 0x46L; O.Shift(ShiftOp.LSL, 8L) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.4 Advanced SIMD modified immediate (4)``() =
    "4f01e5d9"
    ++ MOVI ** [ O.SIMDVecReg(V25, SixteenB); O.Imm 0x2EL ]
    ||> test

  [<TestMethod>]
  member _.``4.6.4 Advanced SIMD modified immediate (5)``() =
    "0f06b4e5"
    ++ ORR
    ** [ O.SIMDVecReg(V5, FourH); O.Imm 0xC7L; O.Shift(ShiftOp.LSL, 8L) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.4 Advanced SIMD modified immediate (6)``() =
    "4f04a759"
    ++ MOVI ** [ O.SIMDVecReg(V25, EightH)
                 O.Imm 0x9AL
                 O.Shift(ShiftOp.LSL, 8L) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.4 Advanced SIMD modified immediate (7)``() =
    "4f05c655"
    ++ MOVI ** [ O.SIMDVecReg(V21, FourS)
                 O.Imm 0xB2L
                 O.Shift(ShiftOp.MSL, 8L) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.4 Advanced SIMD modified immediate (8)``() =
    "4f05f4e5"
    ++ FMOV ** [ O.SIMDVecReg(V5, FourS); OprFPImm -11.5 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.4 Advanced SIMD modified immediate (9)``() =
    "6f0724d5"
    ++ MVNI ** [ O.SIMDVecReg(V21, FourS)
                 O.Imm 0xE6L
                 O.Shift(ShiftOp.LSL, 8L) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.4 Advanced SIMD modified immediate (10)``() =
    "2f0536a7"
    ++ BIC
    ** [ O.SIMDVecReg(V7, TwoS); O.Imm 0xB5L; O.Shift(ShiftOp.LSL, 8L) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.4 Advanced SIMD modified immediate (11)``() =
    "6f07a4d5"
    ++ MVNI ** [ O.SIMDVecReg(V21, EightH)
                 O.Imm 0xE6L
                 O.Shift(ShiftOp.LSL, 8L) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.4 Advanced SIMD modified immediate (12)``() =
    "2f0596a7"
    ++ BIC ** [ O.SIMDVecReg(V7, FourH); O.Imm 0xB5L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.4 Advanced SIMD modified immediate (13)``() =
    "6f07c4d5"
    ++ MVNI ** [ O.SIMDVecReg(V21, FourS)
                 O.Imm 0xE6L
                 O.Shift(ShiftOp.MSL, 8L) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.4 Advanced SIMD modified immediate (14)``() =
    "2f05e75b"
    ++ MOVI ** [ O.ScalarReg D27; O.Imm 0xFF00FFFFFF00FF00L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.4 Advanced SIMD modified immediate (15)``() =
    "6f05e757"
    ++ MOVI ** [ O.SIMDVecReg(V23, TwoD); O.Imm 0xFF00FFFFFF00FF00L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.4 Advanced SIMD modified immediate (16)``() =
    "6f05f4e5"
    ++ FMOV ** [ O.SIMDVecReg(V5, TwoD); OprFPImm -11.5 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.5 Advanced SIMD permute (1)``() =
    "4e4e1983"
    ++ UZP1 ** [ O.SIMDVecReg(V3, EightH)
                 O.SIMDVecReg(V12, EightH)
                 O.SIMDVecReg(V14, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.5 Advanced SIMD permute (2)``() =
    "0e8728fe"
    ++ TRN1 ** [ O.SIMDVecReg(V30, TwoS)
                 O.SIMDVecReg(V7, TwoS)
                 O.SIMDVecReg(V7, TwoS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.5 Advanced SIMD permute (3)``() =
    "4e03383c"
    ++ ZIP1 ** [ O.SIMDVecReg(V28, SixteenB)
                 O.SIMDVecReg(V1, SixteenB)
                 O.SIMDVecReg(V3, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.5 Advanced SIMD permute (4)``() =
    "0e0738c1"
    ++ ZIP1 ** [ O.SIMDVecReg(V1, EightB)
                 O.SIMDVecReg(V6, EightB)
                 O.SIMDVecReg(V7, EightB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.5 Advanced SIMD permute (5)``() =
    "4ec158c6"
    ++ UZP2 ** [ O.SIMDVecReg(V6, TwoD)
                 O.SIMDVecReg(V6, TwoD)
                 O.SIMDVecReg(V1, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.5 Advanced SIMD permute (6)``() =
    "0e8768c3"
    ++ TRN2 ** [ O.SIMDVecReg(V3, TwoS)
                 O.SIMDVecReg(V6, TwoS)
                 O.SIMDVecReg(V7, TwoS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.5 Advanced SIMD permute (7)``() =
    "4e017885"
    ++ ZIP2 ** [ O.SIMDVecReg(V5, SixteenB)
                 O.SIMDVecReg(V4, SixteenB)
                 O.SIMDVecReg(V1, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.6 Advanced SIMD scalar copy (1)``() =
    "5e08054a"
    ++ MOV ** [ O.ScalarReg D10; O.SIMDVecRegWithIdx(V10, VecD, 0uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.6 Advanced SIMD scalar copy (2)``() =
    "5e070541"
    ++ MOV ** [ O.ScalarReg B1; O.SIMDVecRegWithIdx(V10, VecB, 3uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.7 Advanced SIMD scalar pairwise (1)``() =
    "5ef1b867"
    ++ ADDP ** [ O.ScalarReg D7; O.SIMDVecReg(V3, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.7 Advanced SIMD scalar pairwise (2)``() =
    "7e70c9cf"
    ++ FMAXNMP ** [ O.ScalarReg D15; O.SIMDVecReg(V14, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.7 Advanced SIMD scalar pairwise (3)``() =
    "7e30d9ff"
    ++ FADDP ** [ O.ScalarReg S31; O.SIMDVecReg(V15, TwoS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.7 Advanced SIMD scalar pairwise (4)``() =
    "7e70fa32"
    ++ FMAXP ** [ O.ScalarReg D18; O.SIMDVecReg(V17, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.7 Advanced SIMD scalar pairwise (5)``() =
    "7eb0c9c1"
    ++ FMINNMP ** [ O.ScalarReg S1; O.SIMDVecReg(V14, TwoS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.7 Advanced SIMD scalar pairwise (6)``() =
    "7ef0f827"
    ++ FMINP ** [ O.ScalarReg D7; O.SIMDVecReg(V1, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (1)``() =
    "5f420541"
    ++ SSHR ** [ O.ScalarReg D1; O.ScalarReg D10; O.Imm 0x3eL ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (2)``() =
    "5f64147c"
    ++ SSRA ** [ O.ScalarReg D28; O.ScalarReg D3; O.Imm 0x1cL ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (3)``() =
    "5f5924e1"
    ++ SRSHR ** [ O.ScalarReg D1; O.ScalarReg D7; O.Imm 0x27L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (4)``() =
    "5f7f34c3"
    ++ SRSRA ** [ O.ScalarReg D3; O.ScalarReg D6; O.Imm 1L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (5)``() =
    "5f4254ed"
    ++ SHL ** [ O.ScalarReg D13; O.ScalarReg D7; O.Imm 2L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (6)``() =
    "5f247619"
    ++ SQSHL ** [ O.ScalarReg S25; O.ScalarReg S16; O.Imm 4L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (7)``() =
    "5f647619"
    ++ SQSHL ** [ O.ScalarReg D25; O.ScalarReg D16; O.Imm 0x24L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (8)``() =
    "5f299587"
    ++ SQSHRN ** [ O.ScalarReg S7; O.ScalarReg D12; O.Imm 0x17L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (9)``() =
    "5f1f9cf9"
    ++ SQRSHRN ** [ O.ScalarReg H25; O.ScalarReg S7; O.Imm 1L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (10)``() =
    "5f61e4c1"
    ++ SCVTF ** [ O.ScalarReg D1; O.ScalarReg D6; OprFbits 0x1fuy ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (11)``() =
    "5f5bfd0b"
    ++ FCVTZS ** [ O.ScalarReg D11; O.ScalarReg D8; OprFbits 0x25uy ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (12)``() =
    "7f6905c7"
    ++ USHR ** [ O.ScalarReg D7; O.ScalarReg D14; O.Imm 0x17L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (13)``() =
    "7f4a1431"
    ++ USRA ** [ O.ScalarReg D17; O.ScalarReg D1; O.Imm 0x36L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (14)``() =
    "7f602449"
    ++ URSHR ** [ O.ScalarReg D9; O.ScalarReg D2; O.Imm 0x20L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (15)``() =
    "7f4434c9"
    ++ URSRA ** [ O.ScalarReg D9; O.ScalarReg D6; O.Imm 0x3cL ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (16)``() =
    "7f6145c3"
    ++ SRI ** [ O.ScalarReg D3; O.ScalarReg D14; O.Imm 0x1fL ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (17)``() =
    "7f4e54c3"
    ++ SLI ** [ O.ScalarReg D3; O.ScalarReg D6; O.Imm 0xeL ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (18)``() =
    "7f2b6687"
    ++ SQSHLU ** [ O.ScalarReg S7; O.ScalarReg S20; O.Imm 0xbL ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (19)``() =
    "7f0b74f8"
    ++ UQSHL ** [ O.ScalarReg B24; O.ScalarReg B7; O.Imm 3L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (20)``() =
    "7f2f858d"
    ++ SQSHRUN ** [ O.ScalarReg S13; O.ScalarReg D12; O.Imm 0x11L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (21)``() =
    "7f3a8c30"
    ++ SQRSHRUN ** [ O.ScalarReg S16; O.ScalarReg D1; O.Imm 6L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (22)``() =
    "7f1594cd"
    ++ UQSHRN ** [ O.ScalarReg H13; O.ScalarReg S6; O.Imm 0xbL ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (23)``() =
    "7f0c9c46"
    ++ UQRSHRN ** [ O.ScalarReg B6; O.ScalarReg H2; O.Imm 4L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (24)``() =
    "7f24e4c1"
    ++ UCVTF ** [ O.ScalarReg S1; O.ScalarReg S6; OprFbits 0x1cuy ]
    ||> test

  [<TestMethod>]
  member _.``4.6.8 Advanced SIMD scalar shift by imm (25)``() =
    "7f51fc83"
    ++ FCVTZU ** [ O.ScalarReg D3; O.ScalarReg D4; OprFbits 0x2fuy ]
    ||> test

  [<TestMethod>]
  member _.``4.6.9 Advanced SIMD scalar three different (1)``() =
    "5ea693c2"
    ++ SQDMLAL ** [ O.ScalarReg D2; O.ScalarReg S30; O.ScalarReg S6 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.9 Advanced SIMD scalar three different (2)``() =
    "5e61b006"
    ++ SQDMLSL ** [ O.ScalarReg S6; O.ScalarReg H0; O.ScalarReg H1 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.9 Advanced SIMD scalar three different (3)``() =
    "5ea2d242"
    ++ SQDMULL ** [ O.ScalarReg D2; O.ScalarReg S18; O.ScalarReg S2 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (1)``() =
    "5e210dfc"
    ++ SQADD ** [ O.ScalarReg B28; O.ScalarReg B15; O.ScalarReg B1 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (2)``() =
    "5e632fc5"
    ++ SQSUB ** [ O.ScalarReg H5; O.ScalarReg H30; O.ScalarReg H3 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (3)``() =
    "5ee134c5"
    ++ CMGT ** [ O.ScalarReg D5; O.ScalarReg D6; O.ScalarReg D1 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (4)``() =
    "5ee73cca"
    ++ CMGE ** [ O.ScalarReg D10; O.ScalarReg D6; O.ScalarReg D7 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (5)``() =
    "5eff441e"
    ++ SSHL ** [ O.ScalarReg D30; O.ScalarReg D0; O.ScalarReg D31 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (6)``() =
    "5e294f0e"
    ++ SQSHL ** [ O.ScalarReg B14; O.ScalarReg B24; O.ScalarReg B9 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (7)``() =
    "5efe5791"
    ++ SRSHL ** [ O.ScalarReg D17; O.ScalarReg D28; O.ScalarReg D30 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (8)``() =
    "5e6e5e2e"
    ++ SQRSHL ** [ O.ScalarReg H14; O.ScalarReg H17; O.ScalarReg H14 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (9)``() =
    "5ef88478"
    ++ ADD ** [ O.ScalarReg D24; O.ScalarReg D3; O.ScalarReg D24 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (10)``() =
    "5efc8d8a"
    ++ CMTST ** [ O.ScalarReg D10; O.ScalarReg D12; O.ScalarReg D28 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (11)``() =
    "5ea1b4f0"
    ++ SQDMULH ** [ O.ScalarReg S16; O.ScalarReg S7; O.ScalarReg S1 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (12)``() =
    "5e61df0c"
    ++ FMULX ** [ O.ScalarReg D12; O.ScalarReg D24; O.ScalarReg D1 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (13)``() =
    "5e38e4c1"
    ++ FCMEQ ** [ O.ScalarReg S1; O.ScalarReg S6; O.ScalarReg S24 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (14)``() =
    "5e61fc44"
    ++ FRECPS ** [ O.ScalarReg D4; O.ScalarReg D2; O.ScalarReg D1 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (15)``() =
    "5ee1fe18"
    ++ FRSQRTS ** [ O.ScalarReg D24; O.ScalarReg D16; O.ScalarReg D1 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (16)``() =
    "7e610d12"
    ++ UQADD ** [ O.ScalarReg H18; O.ScalarReg H8; O.ScalarReg H1 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (17)``() =
    "7e2c2d81"
    ++ UQSUB ** [ O.ScalarReg B1; O.ScalarReg B12; O.ScalarReg B12 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (18)``() =
    "7ee134be"
    ++ CMHI ** [ O.ScalarReg D30; O.ScalarReg D5; O.ScalarReg D1 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (19)``() =
    "7ee33f12"
    ++ CMHS ** [ O.ScalarReg D18; O.ScalarReg D24; O.ScalarReg D3 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (20)``() =
    "7ee34541"
    ++ USHL ** [ O.ScalarReg D1; O.ScalarReg D10; O.ScalarReg D3 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (21)``() =
    "7e274e11"
    ++ UQSHL ** [ O.ScalarReg B17; O.ScalarReg B16; O.ScalarReg B7 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (22)``() =
    "7ee15703"
    ++ URSHL ** [ O.ScalarReg D3; O.ScalarReg D24; O.ScalarReg D1 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (23)``() =
    "7e675e38"
    ++ UQRSHL ** [ O.ScalarReg H24; O.ScalarReg H17; O.ScalarReg H7 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (24)``() =
    "7eea84df"
    ++ SUB ** [ O.ScalarReg D31; O.ScalarReg D6; O.ScalarReg D10 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (25)``() =
    "7ee08e24"
    ++ CMEQ ** [ O.ScalarReg D4; O.ScalarReg D17; O.ScalarReg D0 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (26)``() =
    "7e61b4ca"
    ++ SQRDMULH ** [ O.ScalarReg H10; O.ScalarReg H6; O.ScalarReg H1 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (27)``() =
    "7ea7b501"
    ++ SQRDMULH ** [ O.ScalarReg S1; O.ScalarReg S8; O.ScalarReg S7 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (28)``() =
    "7e61e606"
    ++ FCMGE ** [ O.ScalarReg D6; O.ScalarReg D16; O.ScalarReg D1 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (29)``() =
    "7e21ec41"
    ++ FACGE ** [ O.ScalarReg S1; O.ScalarReg S2; O.ScalarReg S1 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (30)``() =
    "7ea1d626"
    ++ FABD ** [ O.ScalarReg S6; O.ScalarReg S17; O.ScalarReg S1 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (31)``() =
    "7ee4e687"
    ++ FCMGT ** [ O.ScalarReg D7; O.ScalarReg D20; O.ScalarReg D4 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.10 Advanced SIMD scalar three same (32)``() =
    "7ea5ec73"
    ++ FACGT ** [ O.ScalarReg S19; O.ScalarReg S3; O.ScalarReg S5 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (1)``() =
    "5ea03bb5"
    ++ SUQADD ** [ O.ScalarReg S21; O.ScalarReg S29 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (2)``() =
    "5e607bc1"
    ++ SQABS ** [ O.ScalarReg H1; O.ScalarReg H30 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (3)``() =
    "5ee089fe"
    ++ CMGT ** [ O.ScalarReg D30; O.ScalarReg D15; O.Imm 0L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (4)``() =
    "5ee09af4"
    ++ CMEQ ** [ O.ScalarReg D20; O.ScalarReg D23; O.Imm 0L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (5)``() =
    "5ee0abdc"
    ++ CMLT ** [ O.ScalarReg D28; O.ScalarReg D30; O.Imm 0L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (6)``() =
    "5ee0bb11"
    ++ ABS ** [ O.ScalarReg D17; O.ScalarReg D24 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (7)``() =
    "5e614b87"
    ++ SQXTN ** [ O.ScalarReg H7; O.ScalarReg S28 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (8)``() =
    "5e61ab01"
    ++ FCVTNS ** [ O.ScalarReg D1; O.ScalarReg D24 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (9)``() =
    "5e21bb36"
    ++ FCVTMS ** [ O.ScalarReg S22; O.ScalarReg S25 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (10)``() =
    "5e61caff"
    ++ FCVTAS ** [ O.ScalarReg D31; O.ScalarReg D23 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (11)``() =
    "5e21daaa"
    ++ SCVTF ** [ O.ScalarReg S10; O.ScalarReg S21 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (12)``() =
    "5ea0cabc"
    ++ FCMGT ** [ O.ScalarReg S28; O.ScalarReg S21; OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (13)``() =
    "5ee0da39"
    ++ FCMEQ ** [ O.ScalarReg D25; O.ScalarReg D17; OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (14)``() =
    "5ee0c9fe"
    ++ FCMGT ** [ O.ScalarReg D30; O.ScalarReg D15; OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (15)``() =
    "5ea1abfc"
    ++ FCVTPS ** [ O.ScalarReg S28; O.ScalarReg S31 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (16)``() =
    "5ee1b9fe"
    ++ FCVTZS ** [ O.ScalarReg D30; O.ScalarReg D15 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (17)``() =
    "5ea1daf6"
    ++ FRECPE ** [ O.ScalarReg S22; O.ScalarReg S23 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (18)``() =
    "5ee1f9ff"
    ++ FRECPX ** [ O.ScalarReg D31; O.ScalarReg D15 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (19)``() =
    "7ea03a7c"
    ++ USQADD ** [ O.ScalarReg S28; O.ScalarReg S19 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (20)``() =
    "7e60795b"
    ++ SQNEG ** [ O.ScalarReg H27; O.ScalarReg H10 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (21)``() =
    "7ee08a81"
    ++ CMGE ** [ O.ScalarReg D1; O.ScalarReg D20; O.Imm 0L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (22)``() =
    "7ee09a38"
    ++ CMLE ** [ O.ScalarReg D24; O.ScalarReg D17; O.Imm 0L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (23)``() =
    "7ee0b97f"
    ++ NEG ** [ O.ScalarReg D31; O.ScalarReg D11 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (24)``() =
    "7ea12a11"
    ++ SQXTUN ** [ O.ScalarReg S17; O.ScalarReg D16 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (25)``() =
    "7e214a81"
    ++ UQXTN ** [ O.ScalarReg B1; O.ScalarReg H20 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (26)``() =
    "7e616af8"
    ++ FCVTXN ** [ O.ScalarReg S24; O.ScalarReg D23 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (27)``() =
    "7e21aaf8"
    ++ FCVTNU ** [ O.ScalarReg S24; O.ScalarReg S23 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (28)``() =
    "7e61b807"
    ++ FCVTMU ** [ O.ScalarReg D7; O.ScalarReg D0 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (29)``() =
    "7e21ca11"
    ++ FCVTAU ** [ O.ScalarReg S17; O.ScalarReg S16 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (30)``() =
    "7e61d844"
    ++ UCVTF ** [ O.ScalarReg D4; O.ScalarReg D2 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (31)``() =
    "7ea0cafe"
    ++ FCMGE ** [ O.ScalarReg S30; O.ScalarReg S23; OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (32)``() =
    "7ee0d8c8"
    ++ FCMLE ** [ O.ScalarReg D8; O.ScalarReg D6; OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (33)``() =
    "7ea1aa21"
    ++ FCVTPU ** [ O.ScalarReg S1; O.ScalarReg S17 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (34)``() =
    "7ee1b823"
    ++ FCVTZU ** [ O.ScalarReg D3; O.ScalarReg D1 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (35)``() =
    "7ea1da35"
    ++ FRSQRTE ** [ O.ScalarReg S21; O.ScalarReg S17 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.11 Advanced SIMD scalar two-reg misc (36)``() =
    "7ee1dabd"
    ++ FRSQRTE ** [ O.ScalarReg D29; O.ScalarReg D21 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.12 Advanced SIMD scalar x indexed elem (1)``() =
    "5f883a21"
    ++ SQDMLAL ** [ O.ScalarReg D1
                    O.ScalarReg S17
                    O.SIMDVecRegWithIdx(V8, VecS, 2uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.12 Advanced SIMD scalar x indexed elem (2)``() =
    "5f767b1a"
    ++ SQDMLSL ** [ O.ScalarReg S26
                    O.ScalarReg H24
                    O.SIMDVecRegWithIdx(V6, VecH, 7uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.12 Advanced SIMD scalar x indexed elem (3)``() =
    "5facba67"
    ++ SQDMULL ** [ O.ScalarReg D7
                    O.ScalarReg S19
                    O.SIMDVecRegWithIdx(V12, VecS, 3uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.12 Advanced SIMD scalar x indexed elem (4)``() =
    "5f7ec203"
    ++ SQDMULH ** [ O.ScalarReg H3
                    O.ScalarReg H16
                    O.SIMDVecRegWithIdx(V14, VecH, 3uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.12 Advanced SIMD scalar x indexed elem (5)``() =
    "5fbfcb7b"
    ++ SQDMULH ** [ O.ScalarReg S27
                    O.ScalarReg S27
                    O.SIMDVecRegWithIdx(V31, VecS, 3uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.12 Advanced SIMD scalar x indexed elem (6)``() =
    "5f7fda7c"
    ++ SQRDMULH ** [ O.ScalarReg H28
                     O.ScalarReg H19
                     O.SIMDVecRegWithIdx(V15, VecH, 7uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.12 Advanced SIMD scalar x indexed elem (7)``() =
    "5fd318c3"
    ++ FMLA ** [ O.ScalarReg D3
                 O.ScalarReg D6
                 O.SIMDVecRegWithIdx(V19, VecD, 1uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.12 Advanced SIMD scalar x indexed elem (8)``() =
    "5fb05822"
    ++ FMLS ** [ O.ScalarReg S2
                 O.ScalarReg S1
                 O.SIMDVecRegWithIdx(V16, VecS, 3uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.12 Advanced SIMD scalar x indexed elem (9)``() =
    "5fd1987e"
    ++ FMUL ** [ O.ScalarReg D30
                 O.ScalarReg D3
                 O.SIMDVecRegWithIdx(V17, VecD, 1uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.12 Advanced SIMD scalar x indexed elem (10)``() =
    "7fbe90d9"
    ++ FMULX ** [ O.ScalarReg S25
                  O.ScalarReg S6
                  O.SIMDVecRegWithIdx(V30, VecS, 1uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (1)``() =
    "4f0d05c5"
    ++ SSHR ** [ O.SIMDVecReg(V5, SixteenB)
                 O.SIMDVecReg(V14, SixteenB)
                 O.Imm 3L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (2)``() =
    "4f1505c5"
    ++ SSHR ** [ O.SIMDVecReg(V5, EightH)
                 O.SIMDVecReg(V14, EightH)
                 O.Imm 0xBL ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (3)``() =
    "4f3505c5"
    ++ SSHR ** [ O.SIMDVecReg(V5, FourS)
                 O.SIMDVecReg(V14, FourS)
                 O.Imm 0xBL ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (4)``() =
    "4f5205c5"
    ++ SSHR ** [ O.SIMDVecReg(V5, TwoD)
                 O.SIMDVecReg(V14, TwoD)
                 O.Imm 0x2EL ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (5)``() =
    "4f0d15c5"
    ++ SSRA ** [ O.SIMDVecReg(V5, SixteenB)
                 O.SIMDVecReg(V14, SixteenB)
                 O.Imm 3L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (6)``() =
    "4f1525c5"
    ++ SRSHR ** [ O.SIMDVecReg(V5, EightH)
                  O.SIMDVecReg(V14, EightH)
                  O.Imm 0xBL ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (7)``() =
    "4f3535c5"
    ++ SRSRA ** [ O.SIMDVecReg(V5, FourS)
                  O.SIMDVecReg(V14, FourS)
                  O.Imm 0xBL ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (8)``() =
    "4f0d55c5"
    ++ SHL ** [ O.SIMDVecReg(V5, SixteenB)
                O.SIMDVecReg(V14, SixteenB)
                O.Imm 5L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (9)``() =
    "4f0d75c5"
    ++ SQSHL ** [ O.SIMDVecReg(V5, SixteenB)
                  O.SIMDVecReg(V14, SixteenB)
                  O.Imm 5L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (10)``() =
    "4f2e85c5"
    ++ SHRN2 ** [ O.SIMDVecReg(V5, FourS)
                  O.SIMDVecReg(V14, TwoD)
                  O.Imm 0x12L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (11)``() =
    "4f0d8dc5"
    ++ RSHRN2 ** [ O.SIMDVecReg(V5, SixteenB)
                   O.SIMDVecReg(V14, EightH)
                   O.Imm 3L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (12)``() =
    "4f0d95c5"
    ++ SQSHRN2 ** [ O.SIMDVecReg(V5, SixteenB)
                    O.SIMDVecReg(V14, EightH)
                    O.Imm 3L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (13)``() =
    "4f0d9dc5"
    ++ SQRSHRN2 ** [ O.SIMDVecReg(V5, SixteenB)
                     O.SIMDVecReg(V14, EightH)
                     O.Imm 3L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (14)``() =
    "4f0da5c5"
    ++ SSHLL2 ** [ O.SIMDVecReg(V5, EightH)
                   O.SIMDVecReg(V14, SixteenB)
                   O.Imm 5L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (15)``() =
    "4f4fe54d"
    ++ SCVTF ** [ O.SIMDVecReg(V13, TwoD)
                  O.SIMDVecReg(V10, TwoD)
                  OprFbits 0x31uy ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (16)``() =
    "4f4ffd4d"
    ++ FCVTZS ** [ O.SIMDVecReg(V13, TwoD)
                   O.SIMDVecReg(V10, TwoD)
                   OprFbits 0x31uy ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (17)``() =
    "6f0d05c5"
    ++ USHR ** [ O.SIMDVecReg(V5, SixteenB)
                 O.SIMDVecReg(V14, SixteenB)
                 O.Imm 3L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (18)``() =
    "6f0d15c5"
    ++ USRA ** [ O.SIMDVecReg(V5, SixteenB)
                 O.SIMDVecReg(V14, SixteenB)
                 O.Imm 3L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (19)``() =
    "6f0d25c5"
    ++ URSHR ** [ O.SIMDVecReg(V5, SixteenB)
                  O.SIMDVecReg(V14, SixteenB)
                  O.Imm 3L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (20)``() =
    "6f0d35c5"
    ++ URSRA ** [ O.SIMDVecReg(V5, SixteenB)
                  O.SIMDVecReg(V14, SixteenB)
                  O.Imm 3L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (21)``() =
    "6f0d45c5"
    ++ SRI ** [ O.SIMDVecReg(V5, SixteenB)
                O.SIMDVecReg(V14, SixteenB)
                O.Imm 3L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (22)``() =
    "6f0d55c5"
    ++ SLI ** [ O.SIMDVecReg(V5, SixteenB)
                O.SIMDVecReg(V14, SixteenB)
                O.Imm 5L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (23)``() =
    "6f0d65c5"
    ++ SQSHLU ** [ O.SIMDVecReg(V5, SixteenB)
                   O.SIMDVecReg(V14, SixteenB)
                   O.Imm 5L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (24)``() =
    "6f0d75c5"
    ++ UQSHL ** [ O.SIMDVecReg(V5, SixteenB)
                  O.SIMDVecReg(V14, SixteenB)
                  O.Imm 5L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (25)``() =
    "6f2985c5"
    ++ SQSHRUN2 ** [ O.SIMDVecReg(V5, FourS)
                     O.SIMDVecReg(V14, TwoD)
                     O.Imm 0x17L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (26)``() =
    "6f1b8dc5"
    ++ SQRSHRUN2 ** [ O.SIMDVecReg(V5, EightH)
                      O.SIMDVecReg(V14, FourS)
                      O.Imm 5L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (27)``() =
    "6f2695c5"
    ++ UQSHRN2 ** [ O.SIMDVecReg(V5, FourS)
                    O.SIMDVecReg(V14, TwoD)
                    O.Imm 0x1AL ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (28)``() =
    "6f1f9dc5"
    ++ UQRSHRN2 ** [ O.SIMDVecReg(V5, EightH)
                     O.SIMDVecReg(V14, FourS)
                     O.Imm 1L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (29)``() =
    "2f2da4bb"
    ++ USHLL ** [ O.SIMDVecReg(V27, TwoD)
                  O.SIMDVecReg(V5, TwoS)
                  O.Imm 0xDL ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (30)``() =
    "6f39e5c5"
    ++ UCVTF ** [ O.SIMDVecReg(V5, FourS)
                  O.SIMDVecReg(V14, FourS)
                  OprFbits 7uy ]
    ||> test

  [<TestMethod>]
  member _.``4.6.13 Advanced SIMD shift by immediate (31)``() =
    "6f26fdc5"
    ++ FCVTZU ** [ O.SIMDVecReg(V5, FourS)
                   O.SIMDVecReg(V14, FourS)
                   OprFbits 0x1Auy ]
    ||> test

  [<TestMethod>]
  member _.``4.6.14 Advanced SIMD table lookup (1)``() =
    "4e0320c1"
    ++ TBL ** [ O.SIMDVecReg(V1, SixteenB)
                O.SIMDList([ V6; V7 ], SixteenB)
                O.SIMDVecReg(V3, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.14 Advanced SIMD table lookup (2)``() =
    "0e0342c9"
    ++ TBL ** [ O.SIMDVecReg(V9, EightB)
                O.SIMDList([ V22; V23; V24 ], SixteenB)
                O.SIMDVecReg(V3, EightB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.14 Advanced SIMD table lookup (3)``() =
    "4e0363e5"
    ++ TBL ** [ O.SIMDVecReg(V5, SixteenB)
                O.SIMDList([ V31; V0; V1; V2 ], SixteenB)
                O.SIMDVecReg(V3, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.14 Advanced SIMD table lookup (4)``() =
    "0e030371"
    ++ TBL ** [ O.SIMDVecReg(V17, EightB)
                O.SIMDList([ V27 ], SixteenB)
                O.SIMDVecReg(V3, EightB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.14 Advanced SIMD table lookup (5)``() =
    "0e1930fc"
    ++ TBX ** [ O.SIMDVecReg(V28, EightB)
                O.SIMDList([ V7; V8 ], SixteenB)
                O.SIMDVecReg(V25, EightB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.14 Advanced SIMD table lookup (6)``() =
    "4e1950fc"
    ++ TBX ** [ O.SIMDVecReg(V28, SixteenB)
                O.SIMDList([ V7; V8; V9 ], SixteenB)
                O.SIMDVecReg(V25, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.14 Advanced SIMD table lookup (7)``() =
    "0e1970fc"
    ++ TBX ** [ O.SIMDVecReg(V28, EightB)
                O.SIMDList([ V7; V8; V9; V10 ], SixteenB)
                O.SIMDVecReg(V25, EightB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.14 Advanced SIMD table lookup (8)``() =
    "4e1910fc"
    ++ TBX ** [ O.SIMDVecReg(V28, SixteenB)
                O.SIMDList([ V7 ], SixteenB)
                O.SIMDVecReg(V25, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (1)``() =
    "0e6b039a"
    ++ SADDL ** [ O.SIMDVecReg(V26, FourS)
                  O.SIMDVecReg(V28, FourH)
                  O.SIMDVecReg(V11, FourH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (2)``() =
    "4ea50325"
    ++ SADDL2 ** [ O.SIMDVecReg(V5, TwoD)
                   O.SIMDVecReg(V25, FourS)
                   O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (3)``() =
    "0e2712ba"
    ++ SADDW ** [ O.SIMDVecReg(V26, EightH)
                  O.SIMDVecReg(V21, EightH)
                  O.SIMDVecReg(V7, EightB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (4)``() =
    "4e631079"
    ++ SADDW2 ** [ O.SIMDVecReg(V25, FourS)
                   O.SIMDVecReg(V3, FourS)
                   O.SIMDVecReg(V3, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (5)``() =
    "4e632079"
    ++ SSUBL2 ** [ O.SIMDVecReg(V25, FourS)
                   O.SIMDVecReg(V3, EightH)
                   O.SIMDVecReg(V3, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (6)``() =
    "4e633079"
    ++ SSUBW2 ** [ O.SIMDVecReg(V25, FourS)
                   O.SIMDVecReg(V3, FourS)
                   O.SIMDVecReg(V3, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (7)``() =
    "4e634079"
    ++ ADDHN2 ** [ O.SIMDVecReg(V25, EightH)
                   O.SIMDVecReg(V3, FourS)
                   O.SIMDVecReg(V3, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (8)``() =
    "4e635079"
    ++ SABAL2 ** [ O.SIMDVecReg(V25, FourS)
                   O.SIMDVecReg(V3, EightH)
                   O.SIMDVecReg(V3, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (9)``() =
    "4e636079"
    ++ SUBHN2 ** [ O.SIMDVecReg(V25, EightH)
                   O.SIMDVecReg(V3, FourS)
                   O.SIMDVecReg(V3, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (10)``() =
    "4e637079"
    ++ SABDL2 ** [ O.SIMDVecReg(V25, FourS)
                   O.SIMDVecReg(V3, EightH)
                   O.SIMDVecReg(V3, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (11)``() =
    "0ea68258"
    ++ SMLAL ** [ O.SIMDVecReg(V24, TwoD)
                  O.SIMDVecReg(V18, TwoS)
                  O.SIMDVecReg(V6, TwoS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (12)``() =
    "4ea692fa"
    ++ SQDMLAL2 ** [ O.SIMDVecReg(V26, TwoD)
                     O.SIMDVecReg(V23, FourS)
                     O.SIMDVecReg(V6, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (13)``() =
    "4e66a22c"
    ++ SMLSL2 ** [ O.SIMDVecReg(V12, FourS)
                   O.SIMDVecReg(V17, EightH)
                   O.SIMDVecReg(V6, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (14)``() =
    "4ea5b2c3"
    ++ SQDMLSL2 ** [ O.SIMDVecReg(V3, TwoD)
                     O.SIMDVecReg(V22, FourS)
                     O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (15)``() =
    "0e65c17c"
    ++ SMULL ** [ O.SIMDVecReg(V28, FourS)
                  O.SIMDVecReg(V11, FourH)
                  O.SIMDVecReg(V5, FourH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (16)``() =
    "0ea8d079"
    ++ SQDMULL ** [ O.SIMDVecReg(V25, TwoD)
                    O.SIMDVecReg(V3, TwoS)
                    O.SIMDVecReg(V8, TwoS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (17)``() =
    "4ee3e245"
    ++ PMULL2 ** [ O.SIMDVecReg(V5, OneQ)
                   O.SIMDVecReg(V18, TwoD)
                   O.SIMDVecReg(V3, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (18)``() =
    "2e2e026b"
    ++ UADDL ** [ O.SIMDVecReg(V11, EightH)
                  O.SIMDVecReg(V19, EightB)
                  O.SIMDVecReg(V14, EightB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (19)``() =
    "6eae1252"
    ++ UADDW2 ** [ O.SIMDVecReg(V18, TwoD)
                   O.SIMDVecReg(V18, TwoD)
                   O.SIMDVecReg(V14, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (20)``() =
    "2ea122bd"
    ++ USUBL ** [ O.SIMDVecReg(V29, TwoD)
                  O.SIMDVecReg(V21, TwoS)
                  O.SIMDVecReg(V1, TwoS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (21)``() =
    "6e27339b"
    ++ USUBW2 ** [ O.SIMDVecReg(V27, EightH)
                   O.SIMDVecReg(V28, EightH)
                   O.SIMDVecReg(V7, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (22)``() =
    "6e27439b"
    ++ RADDHN2 ** [ O.SIMDVecReg(V27, SixteenB)
                    O.SIMDVecReg(V28, EightH)
                    O.SIMDVecReg(V7, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (23)``() =
    "6e27539b"
    ++ UABAL2 ** [ O.SIMDVecReg(V27, EightH)
                   O.SIMDVecReg(V28, SixteenB)
                   O.SIMDVecReg(V7, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (24)``() =
    "6e27639b"
    ++ RSUBHN2 ** [ O.SIMDVecReg(V27, SixteenB)
                    O.SIMDVecReg(V28, EightH)
                    O.SIMDVecReg(V7, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (25)``() =
    "6e27739b"
    ++ UABDL2 ** [ O.SIMDVecReg(V27, EightH)
                   O.SIMDVecReg(V28, SixteenB)
                   O.SIMDVecReg(V7, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (26)``() =
    "6e27839b"
    ++ UMLAL2 ** [ O.SIMDVecReg(V27, EightH)
                   O.SIMDVecReg(V28, SixteenB)
                   O.SIMDVecReg(V7, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (27)``() =
    "6e27a39b"
    ++ UMLSL2 ** [ O.SIMDVecReg(V27, EightH)
                   O.SIMDVecReg(V28, SixteenB)
                   O.SIMDVecReg(V7, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.15 Advanced SIMD three different (28)``() =
    "6e27c39b"
    ++ UMULL2 ** [ O.SIMDVecReg(V27, EightH)
                   O.SIMDVecReg(V28, SixteenB)
                   O.SIMDVecReg(V7, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (1)``() =
    "4e2504b5"
    ++ SHADD ** [ O.SIMDVecReg(V21, SixteenB)
                  O.SIMDVecReg(V5, SixteenB)
                  O.SIMDVecReg(V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (2)``() =
    "4e650cb5"
    ++ SQADD ** [ O.SIMDVecReg(V21, EightH)
                  O.SIMDVecReg(V5, EightH)
                  O.SIMDVecReg(V5, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (3)``() =
    "4ea514b5"
    ++ SRHADD ** [ O.SIMDVecReg(V21, FourS)
                   O.SIMDVecReg(V5, FourS)
                   O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (4)``() =
    "4e2524b5"
    ++ SHSUB ** [ O.SIMDVecReg(V21, SixteenB)
                  O.SIMDVecReg(V5, SixteenB)
                  O.SIMDVecReg(V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (5)``() =
    "4e652cb5"
    ++ SQSUB ** [ O.SIMDVecReg(V21, EightH)
                  O.SIMDVecReg(V5, EightH)
                  O.SIMDVecReg(V5, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (6)``() =
    "4ea534b5"
    ++ CMGT ** [ O.SIMDVecReg(V21, FourS)
                 O.SIMDVecReg(V5, FourS)
                 O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (7)``() =
    "4e253cb5"
    ++ CMGE ** [ O.SIMDVecReg(V21, SixteenB)
                 O.SIMDVecReg(V5, SixteenB)
                 O.SIMDVecReg(V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (8)``() =
    "4e6544b5"
    ++ SSHL ** [ O.SIMDVecReg(V21, EightH)
                 O.SIMDVecReg(V5, EightH)
                 O.SIMDVecReg(V5, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (9)``() =
    "4ea54cb5"
    ++ SQSHL ** [ O.SIMDVecReg(V21, FourS)
                  O.SIMDVecReg(V5, FourS)
                  O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (10)``() =
    "4e2554b5"
    ++ SRSHL ** [ O.SIMDVecReg(V21, SixteenB)
                  O.SIMDVecReg(V5, SixteenB)
                  O.SIMDVecReg(V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (11)``() =
    "4e655cb5"
    ++ SQRSHL ** [ O.SIMDVecReg(V21, EightH)
                   O.SIMDVecReg(V5, EightH)
                   O.SIMDVecReg(V5, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (12)``() =
    "4ea564b5"
    ++ SMAX ** [ O.SIMDVecReg(V21, FourS)
                 O.SIMDVecReg(V5, FourS)
                 O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (13)``() =
    "4e256cb5"
    ++ SMIN ** [ O.SIMDVecReg(V21, SixteenB)
                 O.SIMDVecReg(V5, SixteenB)
                 O.SIMDVecReg(V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (14)``() =
    "4e6574b5"
    ++ SABD ** [ O.SIMDVecReg(V21, EightH)
                 O.SIMDVecReg(V5, EightH)
                 O.SIMDVecReg(V5, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (15)``() =
    "4ea57cb5"
    ++ SABA ** [ O.SIMDVecReg(V21, FourS)
                 O.SIMDVecReg(V5, FourS)
                 O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (16)``() =
    "4e2584b5"
    ++ ADD ** [ O.SIMDVecReg(V21, SixteenB)
                O.SIMDVecReg(V5, SixteenB)
                O.SIMDVecReg(V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (17)``() =
    "4e658cb5"
    ++ CMTST ** [ O.SIMDVecReg(V21, EightH)
                  O.SIMDVecReg(V5, EightH)
                  O.SIMDVecReg(V5, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (18)``() =
    "4ea594b5"
    ++ MLA ** [ O.SIMDVecReg(V21, FourS)
                O.SIMDVecReg(V5, FourS)
                O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (19)``() =
    "4e259cb5"
    ++ MUL ** [ O.SIMDVecReg(V21, SixteenB)
                O.SIMDVecReg(V5, SixteenB)
                O.SIMDVecReg(V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (20)``() =
    "4e65a4b5"
    ++ SMAXP ** [ O.SIMDVecReg(V21, EightH)
                  O.SIMDVecReg(V5, EightH)
                  O.SIMDVecReg(V5, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (21)``() =
    "4ea5acb5"
    ++ SMINP ** [ O.SIMDVecReg(V21, FourS)
                  O.SIMDVecReg(V5, FourS)
                  O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (22)``() =
    "4ea5b4b5"
    ++ SQDMULH ** [ O.SIMDVecReg(V21, FourS)
                    O.SIMDVecReg(V5, FourS)
                    O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (23)``() =
    "4e65bcb5"
    ++ ADDP ** [ O.SIMDVecReg(V21, EightH)
                 O.SIMDVecReg(V5, EightH)
                 O.SIMDVecReg(V5, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (24)``() =
    "4e25c6b5"
    ++ FMAXNM ** [ O.SIMDVecReg(V21, FourS)
                   O.SIMDVecReg(V21, FourS)
                   O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (25)``() =
    "4e65cdb5"
    ++ FMLA ** [ O.SIMDVecReg(V21, TwoD)
                 O.SIMDVecReg(V13, TwoD)
                 O.SIMDVecReg(V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (26)``() =
    "4e25d4b5"
    ++ FADD ** [ O.SIMDVecReg(V21, FourS)
                 O.SIMDVecReg(V5, FourS)
                 O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (27)``() =
    "4e65dcb1"
    ++ FMULX ** [ O.SIMDVecReg(V17, TwoD)
                  O.SIMDVecReg(V5, TwoD)
                  O.SIMDVecReg(V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (28)``() =
    "4e25e455"
    ++ FCMEQ ** [ O.SIMDVecReg(V21, FourS)
                  O.SIMDVecReg(V2, FourS)
                  O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (29)``() =
    "4e65f5b5"
    ++ FMAX ** [ O.SIMDVecReg(V21, TwoD)
                 O.SIMDVecReg(V13, TwoD)
                 O.SIMDVecReg(V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (30)``() =
    "4e25fdb5"
    ++ FRECPS ** [ O.SIMDVecReg(V21, FourS)
                   O.SIMDVecReg(V13, FourS)
                   O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (31)``() =
    "4e251cb1"
    ++ AND ** [ O.SIMDVecReg(V17, SixteenB)
                O.SIMDVecReg(V5, SixteenB)
                O.SIMDVecReg(V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (32)``() =
    "4e651eb9"
    ++ BIC ** [ O.SIMDVecReg(V25, SixteenB)
                O.SIMDVecReg(V21, SixteenB)
                O.SIMDVecReg(V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (33)``() =
    "4ea5c43d"
    ++ FMINNM ** [ O.SIMDVecReg(V29, FourS)
                   O.SIMDVecReg(V1, FourS)
                   O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (34)``() =
    "4ee5cfb4"
    ++ FMLS ** [ O.SIMDVecReg(V20, TwoD)
                 O.SIMDVecReg(V29, TwoD)
                 O.SIMDVecReg(V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (35)``() =
    "4ea5d4b5"
    ++ FSUB ** [ O.SIMDVecReg(V21, FourS)
                 O.SIMDVecReg(V5, FourS)
                 O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (36)``() =
    "4ee5f425"
    ++ FMIN ** [ O.SIMDVecReg(V5, TwoD)
                 O.SIMDVecReg(V1, TwoD)
                 O.SIMDVecReg(V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (37)``() =
    "4ea5fcbd"
    ++ FRSQRTS ** [ O.SIMDVecReg(V29, FourS)
                    O.SIMDVecReg(V5, FourS)
                    O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (38)``() =
    "4ea51cb5"
    ++ MOV ** [ O.SIMDVecReg(V21, SixteenB); O.SIMDVecReg(V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (39)``() =
    "4ee51da9"
    ++ ORN ** [ O.SIMDVecReg(V9, SixteenB)
                O.SIMDVecReg(V13, SixteenB)
                O.SIMDVecReg(V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (40)``() =
    "6e2504b5"
    ++ UHADD ** [ O.SIMDVecReg(V21, SixteenB)
                  O.SIMDVecReg(V5, SixteenB)
                  O.SIMDVecReg(V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (41)``() =
    "6e650cb5"
    ++ UQADD ** [ O.SIMDVecReg(V21, EightH)
                  O.SIMDVecReg(V5, EightH)
                  O.SIMDVecReg(V5, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (42)``() =
    "6ea514b5"
    ++ URHADD ** [ O.SIMDVecReg(V21, FourS)
                   O.SIMDVecReg(V5, FourS)
                   O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (43)``() =
    "6e2524b5"
    ++ UHSUB ** [ O.SIMDVecReg(V21, SixteenB)
                  O.SIMDVecReg(V5, SixteenB)
                  O.SIMDVecReg(V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (44)``() =
    "6e652cb5"
    ++ UQSUB ** [ O.SIMDVecReg(V21, EightH)
                  O.SIMDVecReg(V5, EightH)
                  O.SIMDVecReg(V5, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (45)``() =
    "6ea534b5"
    ++ CMHI ** [ O.SIMDVecReg(V21, FourS)
                 O.SIMDVecReg(V5, FourS)
                 O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (46)``() =
    "6e253cb5"
    ++ CMHS ** [ O.SIMDVecReg(V21, SixteenB)
                 O.SIMDVecReg(V5, SixteenB)
                 O.SIMDVecReg(V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (47)``() =
    "6e6544b5"
    ++ USHL ** [ O.SIMDVecReg(V21, EightH)
                 O.SIMDVecReg(V5, EightH)
                 O.SIMDVecReg(V5, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (48)``() =
    "6ea54cb5"
    ++ UQSHL ** [ O.SIMDVecReg(V21, FourS)
                  O.SIMDVecReg(V5, FourS)
                  O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (49)``() =
    "6e2554b5"
    ++ URSHL ** [ O.SIMDVecReg(V21, SixteenB)
                  O.SIMDVecReg(V5, SixteenB)
                  O.SIMDVecReg(V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (50)``() =
    "6e655cb5"
    ++ UQRSHL ** [ O.SIMDVecReg(V21, EightH)
                   O.SIMDVecReg(V5, EightH)
                   O.SIMDVecReg(V5, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (51)``() =
    "6ea564b5"
    ++ UMAX ** [ O.SIMDVecReg(V21, FourS)
                 O.SIMDVecReg(V5, FourS)
                 O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (52)``() =
    "6e256cb5"
    ++ UMIN ** [ O.SIMDVecReg(V21, SixteenB)
                 O.SIMDVecReg(V5, SixteenB)
                 O.SIMDVecReg(V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (53)``() =
    "6e6574b5"
    ++ UABD ** [ O.SIMDVecReg(V21, EightH)
                 O.SIMDVecReg(V5, EightH)
                 O.SIMDVecReg(V5, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (54)``() =
    "6ea57cb5"
    ++ UABA ** [ O.SIMDVecReg(V21, FourS)
                 O.SIMDVecReg(V5, FourS)
                 O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (55)``() =
    "6e2584b5"
    ++ SUB ** [ O.SIMDVecReg(V21, SixteenB)
                O.SIMDVecReg(V5, SixteenB)
                O.SIMDVecReg(V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (56)``() =
    "6e658cb5"
    ++ CMEQ ** [ O.SIMDVecReg(V21, EightH)
                 O.SIMDVecReg(V5, EightH)
                 O.SIMDVecReg(V5, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (57)``() =
    "6ea594b5"
    ++ MLS ** [ O.SIMDVecReg(V21, FourS)
                O.SIMDVecReg(V5, FourS)
                O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (58)``() =
    "6e259cb5"
    ++ PMUL ** [ O.SIMDVecReg(V21, SixteenB)
                 O.SIMDVecReg(V5, SixteenB)
                 O.SIMDVecReg(V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (59)``() =
    "6e65a4b5"
    ++ UMAXP ** [ O.SIMDVecReg(V21, EightH)
                  O.SIMDVecReg(V5, EightH)
                  O.SIMDVecReg(V5, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (60)``() =
    "6ea5acb5"
    ++ UMINP ** [ O.SIMDVecReg(V21, FourS)
                  O.SIMDVecReg(V5, FourS)
                  O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (61)``() =
    "6e65b4b5"
    ++ SQRDMULH ** [ O.SIMDVecReg(V21, EightH)
                     O.SIMDVecReg(V5, EightH)
                     O.SIMDVecReg(V5, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (62)``() =
    "6e25c4b5"
    ++ FMAXNMP ** [ O.SIMDVecReg(V21, FourS)
                    O.SIMDVecReg(V5, FourS)
                    O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (63)``() =
    "6e65d4b5"
    ++ FADDP ** [ O.SIMDVecReg(V21, TwoD)
                  O.SIMDVecReg(V5, TwoD)
                  O.SIMDVecReg(V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (64)``() =
    "6e25dcb5"
    ++ FMUL ** [ O.SIMDVecReg(V21, FourS)
                 O.SIMDVecReg(V5, FourS)
                 O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (65)``() =
    "6e65e4b5"
    ++ FCMGE ** [ O.SIMDVecReg(V21, TwoD)
                  O.SIMDVecReg(V5, TwoD)
                  O.SIMDVecReg(V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (66)``() =
    "6e25ecb5"
    ++ FACGE ** [ O.SIMDVecReg(V21, FourS)
                  O.SIMDVecReg(V5, FourS)
                  O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (67)``() =
    "6e65f4b5"
    ++ FMAXP ** [ O.SIMDVecReg(V21, TwoD)
                  O.SIMDVecReg(V5, TwoD)
                  O.SIMDVecReg(V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (68)``() =
    "6e25fcb5"
    ++ FDIV ** [ O.SIMDVecReg(V21, FourS)
                 O.SIMDVecReg(V5, FourS)
                 O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (69)``() =
    "6e251cb5"
    ++ EOR ** [ O.SIMDVecReg(V21, SixteenB)
                O.SIMDVecReg(V5, SixteenB)
                O.SIMDVecReg(V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (70)``() =
    "6e651cb5"
    ++ BSL ** [ O.SIMDVecReg(V21, SixteenB)
                O.SIMDVecReg(V5, SixteenB)
                O.SIMDVecReg(V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (71)``() =
    "6ea5c4b5"
    ++ FMINNMP ** [ O.SIMDVecReg(V21, FourS)
                    O.SIMDVecReg(V5, FourS)
                    O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (72)``() =
    "6ee5d4b5"
    ++ FABD ** [ O.SIMDVecReg(V21, TwoD)
                 O.SIMDVecReg(V5, TwoD)
                 O.SIMDVecReg(V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (73)``() =
    "6ea5e4b5"
    ++ FCMGT ** [ O.SIMDVecReg(V21, FourS)
                  O.SIMDVecReg(V5, FourS)
                  O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (74)``() =
    "6ee5ecb5"
    ++ FACGT ** [ O.SIMDVecReg(V21, TwoD)
                  O.SIMDVecReg(V5, TwoD)
                  O.SIMDVecReg(V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (75)``() =
    "6ea5f4b5"
    ++ FMINP ** [ O.SIMDVecReg(V21, FourS)
                  O.SIMDVecReg(V5, FourS)
                  O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (76)``() =
    "6ea51cb5"
    ++ BIT ** [ O.SIMDVecReg(V21, SixteenB)
                O.SIMDVecReg(V5, SixteenB)
                O.SIMDVecReg(V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.16 Advanced SIMD three same (77)``() =
    "6ee51cb5"
    ++ BIF ** [ O.SIMDVecReg(V21, SixteenB)
                O.SIMDVecReg(V5, SixteenB)
                O.SIMDVecReg(V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (1)``() =
    "4e600983"
    ++ REV64 ** [ O.SIMDVecReg(V3, EightH); O.SIMDVecReg(V12, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (2)``() =
    "4e2018b2"
    ++ REV16 ** [ O.SIMDVecReg(V18, SixteenB); O.SIMDVecReg(V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (3)``() =
    "4e602983"
    ++ SADDLP ** [ O.SIMDVecReg(V3, FourS); O.SIMDVecReg(V12, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (4)``() =
    "4e603a33"
    ++ SUQADD ** [ O.SIMDVecReg(V19, EightH); O.SIMDVecReg(V17, EightH) ]
    ||> test

  /// SUQADD reads doublewords where Q is set: only the single doubleword is
  /// reserved. REV64 is the other way round, since an element as wide as
  /// the container it is reversed within leaves nothing to reverse, so size
  /// 11 is reserved whatever Q says.
  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (SUQADD 2D)``() =
    "4ee03a33"
    ++ SUQADD ** [ O.SIMDVecReg(V19, TwoD); O.SIMDVecReg(V17, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (REV64 2D)``() =
    testRefused "4ee00983"

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (5)``() =
    "4ea0487c"
    ++ CLS ** [ O.SIMDVecReg(V28, FourS); O.SIMDVecReg(V3, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (6)``() =
    "0ea028cd"
    ++ SADDLP ** [ O.SIMDVecReg(V13, OneD); O.SIMDVecReg(V6, TwoS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (7)``() =
    "4ee07a46"
    ++ SQABS ** [ O.SIMDVecReg(V6, TwoD); O.SIMDVecReg(V18, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (8)``() =
    "4e208867"
    ++ CMGT ** [ O.SIMDVecReg(V7, SixteenB)
                 O.SIMDVecReg(V3, SixteenB)
                 O.Imm 0L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (9)``() =
    "0e609879"
    ++ CMEQ ** [ O.SIMDVecReg(V25, FourH)
                 O.SIMDVecReg(V3, FourH)
                 O.Imm 0L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (10)``() =
    "4ea0a841"
    ++ CMLT ** [ O.SIMDVecReg(V1, FourS)
                 O.SIMDVecReg(V2, FourS)
                 O.Imm 0L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (11)``() =
    "4e20bb7d"
    ++ ABS ** [ O.SIMDVecReg(V29, SixteenB); O.SIMDVecReg(V27, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (12)``() =
    "0ea128b9"
    ++ XTN ** [ O.SIMDVecReg(V25, TwoS); O.SIMDVecReg(V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (13)``() =
    "4ea128f8"
    ++ XTN2 ** [ O.SIMDVecReg(V24, FourS); O.SIMDVecReg(V7, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (14)``() =
    "0e2148c3"
    ++ SQXTN ** [ O.SIMDVecReg(V3, EightB); O.SIMDVecReg(V6, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (15)``() =
    "4e214945"
    ++ SQXTN2 ** [ O.SIMDVecReg(V5, SixteenB); O.SIMDVecReg(V10, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (16)``() =
    "0e616885"
    ++ FCVTN ** [ O.SIMDVecReg(V5, TwoS); O.SIMDVecReg(V4, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (17)``() =
    "4e2168f8"
    ++ FCVTN2 ** [ O.SIMDVecReg(V24, EightH); O.SIMDVecReg(V7, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (18)``() =
    "0e217a7c"
    ++ FCVTL ** [ O.SIMDVecReg(V28, FourS); O.SIMDVecReg(V19, FourH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (19)``() =
    "4e617b43"
    ++ FCVTL2 ** [ O.SIMDVecReg(V3, TwoD); O.SIMDVecReg(V26, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (20)``() =
    "4e6188b8"
    ++ FRINTN ** [ O.SIMDVecReg(V24, TwoD); O.SIMDVecReg(V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (21)``() =
    "0e219865"
    ++ FRINTM ** [ O.SIMDVecReg(V5, TwoS); O.SIMDVecReg(V3, TwoS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (22)``() =
    "4e21a86d"
    ++ FCVTNS ** [ O.SIMDVecReg(V13, FourS); O.SIMDVecReg(V3, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (23)``() =
    "0e21b87e"
    ++ FCVTMS ** [ O.SIMDVecReg(V30, TwoS); O.SIMDVecReg(V3, TwoS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (24)``() =
    "4e61c876"
    ++ FCVTAS ** [ O.SIMDVecReg(V22, TwoD); O.SIMDVecReg(V3, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (25)``() =
    "4e21d892"
    ++ SCVTF ** [ O.SIMDVecReg(V18, FourS); O.SIMDVecReg(V4, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (26)``() =
    "4ea0c8bd"
    ++ FCMGT ** [ O.SIMDVecReg(V29, FourS)
                  O.SIMDVecReg(V5, FourS)
                  OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (27)``() =
    "0ea0d83e"
    ++ FCMEQ ** [ O.SIMDVecReg(V30, TwoS)
                  O.SIMDVecReg(V1, TwoS)
                  OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (28)``() =
    "4ee0e939"
    ++ FCMLT ** [ O.SIMDVecReg(V25, TwoD)
                  O.SIMDVecReg(V9, TwoD)
                  OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (29)``() =
    "4ea0f88e"
    ++ FABS ** [ O.SIMDVecReg(V14, FourS); O.SIMDVecReg(V4, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (30)``() =
    "0ea18896"
    ++ FRINTP ** [ O.SIMDVecReg(V22, TwoS); O.SIMDVecReg(V4, TwoS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (31)``() =
    "4ee19849"
    ++ FRINTZ ** [ O.SIMDVecReg(V9, TwoD); O.SIMDVecReg(V2, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (32)``() =
    "4ea1aac3"
    ++ FCVTPS ** [ O.SIMDVecReg(V3, FourS); O.SIMDVecReg(V22, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (33)``() =
    "0ea1ba7a"
    ++ FCVTZS ** [ O.SIMDVecReg(V26, TwoS); O.SIMDVecReg(V19, TwoS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (34)``() =
    "0ea1c8c7"
    ++ URECPE ** [ O.SIMDVecReg(V7, TwoS); O.SIMDVecReg(V6, TwoS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (35)``() =
    "4ee1d883"
    ++ FRECPE ** [ O.SIMDVecReg(V3, TwoD); O.SIMDVecReg(V4, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (36)``() =
    "6e60083e"
    ++ REV32 ** [ O.SIMDVecReg(V30, EightH); O.SIMDVecReg(V1, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (37)``() =
    "6ea028fc"
    ++ UADDLP ** [ O.SIMDVecReg(V28, TwoD); O.SIMDVecReg(V7, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (38)``() =
    "6ee03883"
    ++ USQADD ** [ O.SIMDVecReg(V3, TwoD); O.SIMDVecReg(V4, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (39)``() =
    "6ea048c9"
    ++ CLZ ** [ O.SIMDVecReg(V9, FourS); O.SIMDVecReg(V6, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (40)``() =
    "6e60683e"
    ++ UADALP ** [ O.SIMDVecReg(V30, FourS); O.SIMDVecReg(V1, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (41)``() =
    "2ea078ef"
    ++ SQNEG ** [ O.SIMDVecReg(V15, TwoS); O.SIMDVecReg(V7, TwoS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (42)``() =
    "6e208874"
    ++ CMGE ** [ O.SIMDVecReg(V20, SixteenB)
                 O.SIMDVecReg(V3, SixteenB)
                 O.Imm 0L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (43)``() =
    "2e2098fd"
    ++ CMLE ** [ O.SIMDVecReg(V29, EightB)
                 O.SIMDVecReg(V7, EightB)
                 O.Imm 0L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (44)``() =
    "6e60b8ca"
    ++ NEG ** [ O.SIMDVecReg(V10, EightH); O.SIMDVecReg(V6, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (45)``() =
    "0ea14887"
    ++ SQXTN ** [ O.SIMDVecReg(V7, TwoS); O.SIMDVecReg(V4, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (46)``() =
    "4e6148b4"
    ++ SQXTN2 ** [ O.SIMDVecReg(V20, EightH); O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (47)``() =
    "2ea13a75"
    ++ SHLL ** [ O.SIMDVecReg(V21, TwoD); O.SIMDVecReg(V19, TwoS); O.Imm 32L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (48)``() =
    "6e613a7d"
    ++ SHLL2 ** [ O.SIMDVecReg(V29, FourS)
                  O.SIMDVecReg(V19, EightH)
                  O.Imm 16L ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (49)``() =
    "2ea148e9"
    ++ UQXTN ** [ O.SIMDVecReg(V9, TwoS); O.SIMDVecReg(V7, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (50)``() =
    "6e6148c2"
    ++ UQXTN2 ** [ O.SIMDVecReg(V2, EightH); O.SIMDVecReg(V6, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (51)``() =
    "2e6168ca"
    ++ FCVTXN ** [ O.SIMDVecReg(V10, TwoS); O.SIMDVecReg(V6, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (52)``() =
    "6e6169c5"
    ++ FCVTXN2 ** [ O.SIMDVecReg(V5, FourS); O.SIMDVecReg(V14, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (53)``() =
    "6e2188ba"
    ++ FRINTA ** [ O.SIMDVecReg(V26, FourS); O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (54)``() =
    "6e6198bc"
    ++ FRINTX ** [ O.SIMDVecReg(V28, TwoD); O.SIMDVecReg(V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (55)``() =
    "2e21a8c5"
    ++ FCVTNU ** [ O.SIMDVecReg(V5, TwoS); O.SIMDVecReg(V6, TwoS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (56)``() =
    "6e21bac6"
    ++ FCVTMU ** [ O.SIMDVecReg(V6, FourS); O.SIMDVecReg(V22, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (57)``() =
    "2e21cb65"
    ++ FCVTAU ** [ O.SIMDVecReg(V5, TwoS); O.SIMDVecReg(V27, TwoS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (58)``() =
    "6e21d896"
    ++ UCVTF ** [ O.SIMDVecReg(V22, FourS); O.SIMDVecReg(V4, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (59)``() =
    "6e20593a"
    ++ MVN ** [ O.SIMDVecReg(V26, SixteenB); O.SIMDVecReg(V9, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (60)``() =
    "2e6058f2"
    ++ RBIT ** [ O.SIMDVecReg(V18, EightB); O.SIMDVecReg(V7, EightB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (61)``() =
    "6ea0cae5"
    ++ FCMGE ** [ O.SIMDVecReg(V5, FourS)
                  O.SIMDVecReg(V23, FourS)
                  OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (62)``() =
    "2ea0da4e"
    ++ FCMLE ** [ O.SIMDVecReg(V14, TwoS)
                  O.SIMDVecReg(V18, TwoS)
                  OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (63)``() =
    "6ee0fa75"
    ++ FNEG ** [ O.SIMDVecReg(V21, TwoD); O.SIMDVecReg(V19, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (64)``() =
    "2ea19abe"
    ++ FRINTI ** [ O.SIMDVecReg(V30, TwoS); O.SIMDVecReg(V21, TwoS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (65)``() =
    "6ee1a889"
    ++ FCVTPU ** [ O.SIMDVecReg(V9, TwoD); O.SIMDVecReg(V4, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (66)``() =
    "2ea1b9fe"
    ++ FCVTZU ** [ O.SIMDVecReg(V30, TwoS); O.SIMDVecReg(V15, TwoS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (67)``() =
    "6ea1cba5"
    ++ URSQRTE ** [ O.SIMDVecReg(V5, FourS); O.SIMDVecReg(V29, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (68)``() =
    "2ea1db32"
    ++ FRSQRTE ** [ O.SIMDVecReg(V18, TwoS); O.SIMDVecReg(V25, TwoS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.17 Advanced SIMD two-reg miscellaneous (69)``() =
    "6ea1f8a6"
    ++ FSQRT ** [ O.SIMDVecReg(V6, FourS); O.SIMDVecReg(V5, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.18 Advanced SIMD vector x indexed elem (1)``() =
    "4f6228da"
    ++ SMLAL2 ** [ O.SIMDVecReg(V26, FourS)
                   O.SIMDVecReg(V6, EightH)
                   O.SIMDVecRegWithIdx(V2, VecH, 6uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.18 Advanced SIMD vector x indexed elem (2)``() =
    "4fb13b42"
    ++ SQDMLAL2 ** [ O.SIMDVecReg(V2, TwoD)
                     O.SIMDVecReg(V26, FourS)
                     O.SIMDVecRegWithIdx(V17, VecS, 3uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.18 Advanced SIMD vector x indexed elem (3)``() =
    "4f7961ca"
    ++ SMLSL2 ** [ O.SIMDVecReg(V10, FourS)
                   O.SIMDVecReg(V14, EightH)
                   O.SIMDVecRegWithIdx(V9, VecH, 3uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.18 Advanced SIMD vector x indexed elem (4)``() =
    "0f92702f"
    ++ SQDMLSL ** [ O.SIMDVecReg(V15, TwoD)
                    O.SIMDVecReg(V1, TwoS)
                    O.SIMDVecRegWithIdx(V18, VecS, 0uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.18 Advanced SIMD vector x indexed elem (5)``() =
    "0f738342"
    ++ MUL ** [ O.SIMDVecReg(V2, FourH)
                O.SIMDVecReg(V26, FourH)
                O.SIMDVecRegWithIdx(V3, VecH, 3uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.18 Advanced SIMD vector x indexed elem (6)``() =
    "0f6ca8c5"
    ++ SMULL ** [ O.SIMDVecReg(V5, FourS)
                  O.SIMDVecReg(V6, FourH)
                  O.SIMDVecRegWithIdx(V12, VecH, 6uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.18 Advanced SIMD vector x indexed elem (7)``() =
    "4fbdbb42"
    ++ SQDMULL2 ** [ O.SIMDVecReg(V2, TwoD)
                     O.SIMDVecReg(V26, FourS)
                     O.SIMDVecRegWithIdx(V29, VecS, 3uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.18 Advanced SIMD vector x indexed elem (8)``() =
    "4f9dcb5d"
    ++ SQDMULH ** [ O.SIMDVecReg(V29, FourS)
                    O.SIMDVecReg(V26, FourS)
                    O.SIMDVecRegWithIdx(V29, VecS, 2uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.18 Advanced SIMD vector x indexed elem (9)``() =
    "0f5dd3da"
    ++ SQRDMULH ** [ O.SIMDVecReg(V26, FourH)
                     O.SIMDVecReg(V30, FourH)
                     O.SIMDVecRegWithIdx(V13, VecH, 1uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.18 Advanced SIMD vector x indexed elem (10)``() =
    "4fa31b5b"
    ++ FMLA ** [ O.SIMDVecReg(V27, FourS)
                 O.SIMDVecReg(V26, FourS)
                 O.SIMDVecRegWithIdx(V3, VecS, 3uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.18 Advanced SIMD vector x indexed elem (11)``() =
    "4fd3535b"
    ++ FMLS ** [ O.SIMDVecReg(V27, TwoD)
                 O.SIMDVecReg(V26, TwoD)
                 O.SIMDVecRegWithIdx(V19, VecD, 0uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.18 Advanced SIMD vector x indexed elem (12)``() =
    "4f839b5b"
    ++ FMUL ** [ O.SIMDVecReg(V27, FourS)
                 O.SIMDVecReg(V26, FourS)
                 O.SIMDVecRegWithIdx(V3, VecS, 2uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.18 Advanced SIMD vector x indexed elem (13)``() =
    "6fad08be"
    ++ MLA ** [ O.SIMDVecReg(V30, FourS)
                O.SIMDVecReg(V5, FourS)
                O.SIMDVecRegWithIdx(V13, VecS, 3uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.18 Advanced SIMD vector x indexed elem (14)``() =
    "6f7f2b56"
    ++ UMLAL2 ** [ O.SIMDVecReg(V22, FourS)
                   O.SIMDVecReg(V26, EightH)
                   O.SIMDVecRegWithIdx(V15, VecH, 7uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.18 Advanced SIMD vector x indexed elem (15)``() =
    "6f97488a"
    ++ MLS ** [ O.SIMDVecReg(V10, FourS)
                O.SIMDVecReg(V4, FourS)
                O.SIMDVecRegWithIdx(V23, VecS, 2uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.18 Advanced SIMD vector x indexed elem (16)``() =
    "2f6e60de"
    ++ UMLSL ** [ O.SIMDVecReg(V30, FourS)
                  O.SIMDVecReg(V6, FourH)
                  O.SIMDVecRegWithIdx(V14, VecH, 2uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.18 Advanced SIMD vector x indexed elem (17)``() =
    "6fbfa8ea"
    ++ UMULL2 ** [ O.SIMDVecReg(V10, TwoD)
                   O.SIMDVecReg(V7, FourS)
                   O.SIMDVecRegWithIdx(V31, VecS, 3uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.18 Advanced SIMD vector x indexed elem (18)``() =
    "6fad92c5"
    ++ FMULX ** [ O.SIMDVecReg(V5, FourS)
                  O.SIMDVecReg(V22, FourS)
                  O.SIMDVecRegWithIdx(V13, VecS, 1uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.19 Cryptographic AES (1)``() =
    "4e284ab5"
    ++ AESE ** [ O.SIMDVecReg(V21, SixteenB); O.SIMDVecReg(V21, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.19 Cryptographic AES (2)``() =
    "4e285ab5"
    ++ AESD ** [ O.SIMDVecReg(V21, SixteenB); O.SIMDVecReg(V21, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.19 Cryptographic AES (3)``() =
    "4e286ab5"
    ++ AESMC ** [ O.SIMDVecReg(V21, SixteenB); O.SIMDVecReg(V21, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.19 Cryptographic AES (4)``() =
    "4e287ab5"
    ++ AESIMC ** [ O.SIMDVecReg(V21, SixteenB); O.SIMDVecReg(V21, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.20 Cryptographic three-register SHA (1)``() =
    "5e190378"
    ++ SHA1C ** [ O.ScalarReg Q24; O.ScalarReg S27; O.SIMDVecReg(V25, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.20 Cryptographic three-register SHA (2)``() =
    "5e1313ff"
    ++ SHA1P ** [ O.ScalarReg Q31; O.ScalarReg S31; O.SIMDVecReg(V19, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.20 Cryptographic three-register SHA (3)``() =
    "5e0e22bc"
    ++ SHA1M ** [ O.ScalarReg Q28; O.ScalarReg S21; O.SIMDVecReg(V14, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.20 Cryptographic three-register SHA (4)``() =
    "5e173207"
    ++ SHA1SU0 ** [ O.SIMDVecReg(V7, FourS)
                    O.SIMDVecReg(V16, FourS)
                    O.SIMDVecReg(V23, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.20 Cryptographic three-register SHA (5)``() =
    "5e1143de"
    ++ SHA256H ** [ O.ScalarReg Q30
                    O.ScalarReg Q30
                    O.SIMDVecReg(V17, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.20 Cryptographic three-register SHA (6)``() =
    "5e19531e"
    ++ SHA256H2 ** [ O.ScalarReg Q30
                     O.ScalarReg Q24
                     O.SIMDVecReg(V25, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.20 Cryptographic three-register SHA (7)``() =
    "5e1732bf"
    ++ SHA1SU0 ** [ O.SIMDVecReg(V31, FourS)
                    O.SIMDVecReg(V21, FourS)
                    O.SIMDVecReg(V23, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.21 Cryptographic two-register SHA (1)``() =
    "5e28095f"
    ++ SHA1H ** [ O.ScalarReg S31; O.ScalarReg S10 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.21 Cryptographic two-register SHA (2)``() =
    "5e281bd7"
    ++ SHA1SU1 ** [ O.SIMDVecReg(V23, FourS); O.SIMDVecReg(V30, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.21 Cryptographic two-register SHA (3)``() =
    "5e282955"
    ++ SHA256SU0 ** [ O.SIMDVecReg(V21, FourS); O.SIMDVecReg(V10, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.22 Floating-point compare (1)``() =
    "1e3520e0"
    ++ FCMP ** [ O.ScalarReg S7; O.ScalarReg S21 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.22 Floating-point compare (2)``() =
    "1e312388"
    ++ FCMP ** [ O.ScalarReg S28; OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.22 Floating-point compare (3)``() =
    "1e2b22d0"
    ++ FCMPE ** [ O.ScalarReg S22; O.ScalarReg S11 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.22 Floating-point compare (4)``() =
    "1e392238"
    ++ FCMPE ** [ O.ScalarReg S17; OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.22 Floating-point compare (5)``() =
    "1e6220c0"
    ++ FCMP ** [ O.ScalarReg D6; O.ScalarReg D2 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.22 Floating-point compare (6)``() =
    "1e7921c8"
    ++ FCMP ** [ O.ScalarReg D14; OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.22 Floating-point compare (7)``() =
    "1e742170"
    ++ FCMPE ** [ O.ScalarReg D11; O.ScalarReg D20 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.22 Floating-point compare (8)``() =
    "1e6323b8"
    ++ FCMPE ** [ O.ScalarReg D29; OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.23 Floating-point conditional compare (1)``() =
    "1e2d274d"
    ++ FCCMP ** [ O.ScalarReg S26; O.ScalarReg S13; OprNZCV 0xDuy; OprCond CS ]
    ||> test

  [<TestMethod>]
  member _.``4.6.23 Floating-point conditional compare (2)``() =
    "1e2ae756"
    ++ FCCMPE ** [ O.ScalarReg S26; O.ScalarReg S10; OprNZCV 6uy; OprCond AL ]
    ||> test

  [<TestMethod>]
  member _.``4.6.23 Floating-point conditional compare (3)``() =
    "1e693649"
    ++ FCCMP ** [ O.ScalarReg D18; O.ScalarReg D9; OprNZCV 9uy; OprCond CC ]
    ||> test

  [<TestMethod>]
  member _.``4.6.23 Floating-point conditional compare (4)``() =
    "1e6ee752"
    ++ FCCMPE ** [ O.ScalarReg D26; O.ScalarReg D14; OprNZCV 2uy; OprCond AL ]
    ||> test

  [<TestMethod>]
  member _.``4.6.24 Floating-point conditional select (1)``() =
    "1e292c5b"
    ++ FCSEL ** [ O.ScalarReg S27; O.ScalarReg S2; O.ScalarReg S9; OprCond CS ]
    ||> test

  [<TestMethod>]
  member _.``4.6.24 Floating-point conditional select (2)``() =
    "1e7ced53"
    ++ FCSEL ** [ O.ScalarReg D19
                  O.ScalarReg D10
                  O.ScalarReg D28
                  OprCond AL ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (1)``() =
    "1e20423a"
    ++ FMOV ** [ O.ScalarReg S26; O.ScalarReg S17 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (2)``() =
    "1e20c0ea"
    ++ FABS ** [ O.ScalarReg S10; O.ScalarReg S7 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (3)``() =
    "1e21410e"
    ++ FNEG ** [ O.ScalarReg S14; O.ScalarReg S8 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (4)``() =
    "1e21c178"
    ++ FSQRT ** [ O.ScalarReg S24; O.ScalarReg S11 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (5)``() =
    "1e22c2ca"
    ++ FCVT ** [ O.ScalarReg D10; O.ScalarReg S22 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (6)``() =
    "1e23c1f0"
    ++ FCVT ** [ O.ScalarReg H16; O.ScalarReg S15 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (7)``() =
    "1e244261"
    ++ FRINTN ** [ O.ScalarReg S1; O.ScalarReg S19 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (8)``() =
    "1e24c15c"
    ++ FRINTP ** [ O.ScalarReg S28; O.ScalarReg S10 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (9)``() =
    "1e2541d8"
    ++ FRINTM ** [ O.ScalarReg S24; O.ScalarReg S14 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (10)``() =
    "1e25c0ce"
    ++ FRINTZ ** [ O.ScalarReg S14; O.ScalarReg S6 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (11)``() =
    "1e26414c"
    ++ FRINTA ** [ O.ScalarReg S12; O.ScalarReg S10 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (12)``() =
    "1e274178"
    ++ FRINTX ** [ O.ScalarReg S24; O.ScalarReg S11 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (13)``() =
    "1e27c1e2"
    ++ FRINTI ** [ O.ScalarReg S2; O.ScalarReg S15 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (14)``() =
    "1e604234"
    ++ FMOV ** [ O.ScalarReg D20; O.ScalarReg D17 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (15)``() =
    "1e60c222"
    ++ FABS ** [ O.ScalarReg D2; O.ScalarReg D17 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (16)``() =
    "1e6142a2"
    ++ FNEG ** [ O.ScalarReg D2; O.ScalarReg D21 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (17)``() =
    "1e61c1a6"
    ++ FSQRT ** [ O.ScalarReg D6; O.ScalarReg D13 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (18)``() =
    "1e6241cd"
    ++ FCVT ** [ O.ScalarReg S13; O.ScalarReg D14 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (19)``() =
    "1e63c2aa"
    ++ FCVT ** [ O.ScalarReg H10; O.ScalarReg D21 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (20)``() =
    "1e6441e3"
    ++ FRINTN ** [ O.ScalarReg D3; O.ScalarReg D15 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (21)``() =
    "1e64c2b2"
    ++ FRINTP ** [ O.ScalarReg D18; O.ScalarReg D21 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (22)``() =
    "1e654374"
    ++ FRINTM ** [ O.ScalarReg D20; O.ScalarReg D27 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (23)``() =
    "1e65c2e2"
    ++ FRINTZ ** [ O.ScalarReg D2; O.ScalarReg D23 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (24)``() =
    "1e664351"
    ++ FRINTA ** [ O.ScalarReg D17; O.ScalarReg D26 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (25)``() =
    "1e6742b8"
    ++ FRINTX ** [ O.ScalarReg D24; O.ScalarReg D21 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (26)``() =
    "1e67c375"
    ++ FRINTI ** [ O.ScalarReg D21; O.ScalarReg D27 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (27)``() =
    "1ee241d4"
    ++ FCVT ** [ O.ScalarReg S20; O.ScalarReg H14 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.25 FP data-processing (1 source) (28)``() =
    "1ee2c388"
    ++ FCVT ** [ O.ScalarReg D8; O.ScalarReg H28 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.26 FP data-processing (2 source) (1)``() =
    "1e210822"
    ++ FMUL ** [ O.ScalarReg S2; O.ScalarReg S1; O.ScalarReg S1 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.26 FP data-processing (2 source) (2)``() =
    "1e221a88"
    ++ FDIV ** [ O.ScalarReg S8; O.ScalarReg S20; O.ScalarReg S2 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.26 FP data-processing (2 source) (3)``() =
    "1e2228ae"
    ++ FADD ** [ O.ScalarReg S14; O.ScalarReg S5; O.ScalarReg S2 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.26 FP data-processing (2 source) (4)``() =
    "1e233956"
    ++ FSUB ** [ O.ScalarReg S22; O.ScalarReg S10; O.ScalarReg S3 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.26 FP data-processing (2 source) (5)``() =
    "1e244af4"
    ++ FMAX ** [ O.ScalarReg S20; O.ScalarReg S23; O.ScalarReg S4 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.26 FP data-processing (2 source) (6)``() =
    "1e255915"
    ++ FMIN ** [ O.ScalarReg S21; O.ScalarReg S8; O.ScalarReg S5 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.26 FP data-processing (2 source) (7)``() =
    "1e266932"
    ++ FMAXNM ** [ O.ScalarReg S18; O.ScalarReg S9; O.ScalarReg S6 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.26 FP data-processing (2 source) (8)``() =
    "1e2778ba"
    ++ FMINNM ** [ O.ScalarReg S26; O.ScalarReg S5; O.ScalarReg S7 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.26 FP data-processing (2 source) (9)``() =
    "1e288aba"
    ++ FNMUL ** [ O.ScalarReg S26; O.ScalarReg S21; O.ScalarReg S8 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.26 FP data-processing (2 source) (10)``() =
    "1e690abb"
    ++ FMUL ** [ O.ScalarReg D27; O.ScalarReg D21; O.ScalarReg D9 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.26 FP data-processing (2 source) (11)``() =
    "1e6a18a2"
    ++ FDIV ** [ O.ScalarReg D2; O.ScalarReg D5; O.ScalarReg D10 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.26 FP data-processing (2 source) (12)``() =
    "1e6b2aba"
    ++ FADD ** [ O.ScalarReg D26; O.ScalarReg D21; O.ScalarReg D11 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.26 FP data-processing (2 source) (13)``() =
    "1e6c39be"
    ++ FSUB ** [ O.ScalarReg D30; O.ScalarReg D13; O.ScalarReg D12 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.26 FP data-processing (2 source) (14)``() =
    "1e6d48ba"
    ++ FMAX ** [ O.ScalarReg D26; O.ScalarReg D5; O.ScalarReg D13 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.26 FP data-processing (2 source) (15)``() =
    "1e6e5abb"
    ++ FMIN ** [ O.ScalarReg D27; O.ScalarReg D21; O.ScalarReg D14 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.26 FP data-processing (2 source) (16)``() =
    "1e726ae2"
    ++ FMAXNM ** [ O.ScalarReg D2; O.ScalarReg D23; O.ScalarReg D18 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.26 FP data-processing (2 source) (17)``() =
    "1e7f7882"
    ++ FMINNM ** [ O.ScalarReg D2; O.ScalarReg D4; O.ScalarReg D31 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.26 FP data-processing (2 source) (18)``() =
    "1e608bd4"
    ++ FNMUL ** [ O.ScalarReg D20; O.ScalarReg D30; O.ScalarReg D0 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.27 FP data-processing (3 source) (1)``() =
    "1f1f0759"
    ++ FMADD ** [ O.ScalarReg S25
                  O.ScalarReg S26
                  O.ScalarReg S31
                  O.ScalarReg S1 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.27 FP data-processing (3 source) (2)``() =
    "1f1e8b44"
    ++ FMSUB ** [ O.ScalarReg S4
                  O.ScalarReg S26
                  O.ScalarReg S30
                  O.ScalarReg S2 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.27 FP data-processing (3 source) (3)``() =
    "1f3c1116"
    ++ FNMADD ** [ O.ScalarReg S22
                   O.ScalarReg S8
                   O.ScalarReg S28
                   O.ScalarReg S4 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.27 FP data-processing (3 source) (4)``() =
    "1f38a1d5"
    ++ FNMSUB ** [ O.ScalarReg S21
                   O.ScalarReg S14
                   O.ScalarReg S24
                   O.ScalarReg S8 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.27 FP data-processing (3 source) (5)``() =
    "1f504159"
    ++ FMADD ** [ O.ScalarReg D25
                  O.ScalarReg D10
                  O.ScalarReg D16
                  O.ScalarReg D16 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.27 FP data-processing (3 source) (6)``() =
    "1f48e1dd"
    ++ FMSUB ** [ O.ScalarReg D29
                  O.ScalarReg D14
                  O.ScalarReg D8
                  O.ScalarReg D24 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.27 FP data-processing (3 source) (7)``() =
    "1f647171"
    ++ FNMADD ** [ O.ScalarReg D17
                   O.ScalarReg D11
                   O.ScalarReg D4
                   O.ScalarReg D28 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.27 FP data-processing (3 source) (8)``() =
    "1f62f871"
    ++ FNMSUB ** [ O.ScalarReg D17
                   O.ScalarReg D3
                   O.ScalarReg D2
                   O.ScalarReg D30 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.28 Floating-point immediate (1)``() =
    "1e201015"
    ++ FMOV ** [ O.ScalarReg S21; OprFPImm 2.0 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.28 Floating-point immediate (2)``() =
    "1e64b019"
    ++ FMOV ** [ O.ScalarReg D25; OprFPImm 10.5 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.29 Conversion between FP and fixed-pt (1)``() =
    "1e02a8bc"
    ++ SCVTF ** [ O.ScalarReg S28; O.Reg W5; OprFbits 0x16uy ]
    ||> test

  [<TestMethod>]
  member _.``4.6.29 Conversion between FP and fixed-pt (2)``() =
    "1e03f8a5"
    ++ UCVTF ** [ O.ScalarReg S5; O.Reg W5; OprFbits 2uy ]
    ||> test

  [<TestMethod>]
  member _.``4.6.29 Conversion between FP and fixed-pt (3)``() =
    "1e18fc91"
    ++ FCVTZS ** [ O.Reg W17; O.ScalarReg S4; OprFbits 1uy ]
    ||> test

  [<TestMethod>]
  member _.``4.6.29 Conversion between FP and fixed-pt (4)``() =
    "1e1985c5"
    ++ FCVTZU ** [ O.Reg W5; O.ScalarReg S14; OprFbits 0x1Fuy ]
    ||> test

  [<TestMethod>]
  member _.``4.6.29 Conversion between FP and fixed-pt (5)``() =
    "1e42c5c5"
    ++ SCVTF ** [ O.ScalarReg D5; O.Reg W14; OprFbits 0xFuy ]
    ||> test

  [<TestMethod>]
  member _.``4.6.29 Conversion between FP and fixed-pt (6)``() =
    "1e43a5c5"
    ++ UCVTF ** [ O.ScalarReg D5; O.Reg W14; OprFbits 0x17uy ]
    ||> test

  [<TestMethod>]
  member _.``4.6.29 Conversion between FP and fixed-pt (7)``() =
    "1e5895c5"
    ++ FCVTZS ** [ O.Reg W5; O.ScalarReg D14; OprFbits 0x1Buy ]
    ||> test

  [<TestMethod>]
  member _.``4.6.29 Conversion between FP and fixed-pt (8)``() =
    "1e59ab45"
    ++ FCVTZU ** [ O.Reg W5; O.ScalarReg D26; OprFbits 0x16uy ]
    ||> test

  [<TestMethod>]
  member _.``4.6.29 Conversion between FP and fixed-pt (9)``() =
    "9e02c4d1"
    ++ SCVTF ** [ O.ScalarReg S17; O.Reg X6; OprFbits 0xFuy ]
    ||> test

  [<TestMethod>]
  member _.``4.6.29 Conversion between FP and fixed-pt (10)``() =
    "9e03b5a5"
    ++ UCVTF ** [ O.ScalarReg S5; O.Reg X13; OprFbits 0x13uy ]
    ||> test

  [<TestMethod>]
  member _.``4.6.29 Conversion between FP and fixed-pt (11)``() =
    "9e18f0cd"
    ++ FCVTZS ** [ O.Reg X13; O.ScalarReg S6; OprFbits 4uy ]
    ||> test

  [<TestMethod>]
  member _.``4.6.29 Conversion between FP and fixed-pt (12)``() =
    "9e1995cd"
    ++ FCVTZU ** [ O.Reg X13; O.ScalarReg S14; OprFbits 0x1Buy ]
    ||> test

  [<TestMethod>]
  member _.``4.6.29 Conversion between FP and fixed-pt (13)``() =
    "9e428b85"
    ++ SCVTF ** [ O.ScalarReg D5; O.Reg X28; OprFbits 0x1Euy ]
    ||> test

  [<TestMethod>]
  member _.``4.6.29 Conversion between FP and fixed-pt (14)``() =
    "9e43c5c5"
    ++ UCVTF ** [ O.ScalarReg D5; O.Reg X14; OprFbits 0xFuy ]
    ||> test

  [<TestMethod>]
  member _.``4.6.29 Conversion between FP and fixed-pt (15)``() =
    "9e58e6d1"
    ++ FCVTZS ** [ O.Reg X17; O.ScalarReg D22; OprFbits 7uy ]
    ||> test

  [<TestMethod>]
  member _.``4.6.29 Conversion between FP and fixed-pt (16)``() =
    "9e59d1d2"
    ++ FCVTZU ** [ O.Reg X18; O.ScalarReg D14; OprFbits 0xCuy ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (1)``() =
    "1e200154"
    ++ FCVTNS ** [ O.Reg W20; O.ScalarReg S10 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (2)``() =
    "1e60034a"
    ++ FCVTNS ** [ O.Reg W10; O.ScalarReg D26 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (3)``() =
    "9e200162"
    ++ FCVTNS ** [ O.Reg X2; O.ScalarReg S11 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (4)``() =
    "9e600257"
    ++ FCVTNS ** [ O.Reg X23; O.ScalarReg D18 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (5)``() =
    "1e2100b8"
    ++ FCVTNU ** [ O.Reg W24; O.ScalarReg S5 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (6)``() =
    "1e6102b2"
    ++ FCVTNU ** [ O.Reg W18; O.ScalarReg D21 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (7)``() =
    "9e2100bb"
    ++ FCVTNU ** [ O.Reg X27; O.ScalarReg S5 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (8)``() =
    "9e6101bc"
    ++ FCVTNU ** [ O.Reg X28; O.ScalarReg D13 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (9)``() =
    "1e2200ba"
    ++ SCVTF ** [ O.ScalarReg S26; O.Reg W5 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (10)``() =
    "1e6201e8"
    ++ SCVTF ** [ O.ScalarReg D8; O.Reg W15 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (11)``() =
    "9e2201c2"
    ++ SCVTF ** [ O.ScalarReg S2; O.Reg X14 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (12)``() =
    "9e6201dd"
    ++ SCVTF ** [ O.ScalarReg D29; O.Reg X14 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (13)``() =
    "1e2302bd"
    ++ UCVTF ** [ O.ScalarReg S29; O.Reg W21 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (14)``() =
    "1e6301c7"
    ++ UCVTF ** [ O.ScalarReg D7; O.Reg W14 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (15)``() =
    "9e2301de"
    ++ UCVTF ** [ O.ScalarReg S30; O.Reg X14 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (16)``() =
    "9e6302b9"
    ++ UCVTF ** [ O.ScalarReg D25; O.Reg X21 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (17)``() =
    "1e24018a"
    ++ FCVTAS ** [ O.Reg W10; O.ScalarReg S12 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (18)``() =
    "1e640299"
    ++ FCVTAS ** [ O.Reg W25; O.ScalarReg D20 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (19)``() =
    "9e240255"
    ++ FCVTAS ** [ O.Reg X21; O.ScalarReg S18 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (20)``() =
    "9e640338"
    ++ FCVTAS ** [ O.Reg X24; O.ScalarReg D25 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (21)``() =
    "1e25035d"
    ++ FCVTAU ** [ O.Reg W29; O.ScalarReg S26 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (22)``() =
    "1e650345"
    ++ FCVTAU ** [ O.Reg W5; O.ScalarReg D26 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (23)``() =
    "9e250311"
    ++ FCVTAU ** [ O.Reg X17; O.ScalarReg S24 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (24)``() =
    "9e650374"
    ++ FCVTAU ** [ O.Reg X20; O.ScalarReg D27 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (25)``() =
    "1e26032e"
    ++ FMOV ** [ O.Reg W14; O.ScalarReg S25 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (26)``() =
    "1e2701c3"
    ++ FMOV ** [ O.ScalarReg S3; O.Reg W14 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (27)``() =
    "9e6602ab"
    ++ FMOV ** [ O.Reg X11; O.ScalarReg D21 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (28)``() =
    "9e6701e3"
    ++ FMOV ** [ O.ScalarReg D3; O.Reg X15 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (29)``() =
    "9eae021d"
    ++ FMOV ** [ O.Reg X29; O.SIMDVecRegWithIdx(V16, VecD, 1uy) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (30)``() =
    "9eaf02f8"
    ++ FMOV ** [ O.SIMDVecRegWithIdx(V24, VecD, 1uy); O.Reg X23 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (31)``() =
    "1e2800ce"
    ++ FCVTPS ** [ O.Reg W14; O.ScalarReg S6 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (32)``() =
    "1e680066"
    ++ FCVTPS ** [ O.Reg W6; O.ScalarReg D3 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (33)``() =
    "9e280223"
    ++ FCVTPS ** [ O.Reg X3; O.ScalarReg S17 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (34)``() =
    "9e68037a"
    ++ FCVTPS ** [ O.Reg X26; O.ScalarReg D27 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (35)``() =
    "1e29021c"
    ++ FCVTPU ** [ O.Reg W28; O.ScalarReg S16 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (36)``() =
    "1e690133"
    ++ FCVTPU ** [ O.Reg W19; O.ScalarReg D9 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (37)``() =
    "9e290069"
    ++ FCVTPU ** [ O.Reg X9; O.ScalarReg S3 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (38)``() =
    "9e690275"
    ++ FCVTPU ** [ O.Reg X21; O.ScalarReg D19 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (39)``() =
    "1e3001dd"
    ++ FCVTMS ** [ O.Reg W29; O.ScalarReg S14 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (40)``() =
    "1e700362"
    ++ FCVTMS ** [ O.Reg W2; O.ScalarReg D27 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (41)``() =
    "9e300079"
    ++ FCVTMS ** [ O.Reg X25; O.ScalarReg S3 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (42)``() =
    "9e700086"
    ++ FCVTMS ** [ O.Reg X6; O.ScalarReg D4 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (43)``() =
    "1e310185"
    ++ FCVTMU ** [ O.Reg W5; O.ScalarReg S12 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (44)``() =
    "1e71027d"
    ++ FCVTMU ** [ O.Reg W29; O.ScalarReg D19 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (45)``() =
    "9e3103ff"
    ++ FCVTMU ** [ O.Reg XZR; O.ScalarReg S31 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (46)``() =
    "9e710000"
    ++ FCVTMU ** [ O.Reg X0; O.ScalarReg D0 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (47)``() =
    "1e380343"
    ++ FCVTZS ** [ O.Reg W3; O.ScalarReg S26 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (48)``() =
    "1e7800cd"
    ++ FCVTZS ** [ O.Reg W13; O.ScalarReg D6 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (49)``() =
    "9e380279"
    ++ FCVTZS ** [ O.Reg X25; O.ScalarReg S19 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (50)``() =
    "9e780146"
    ++ FCVTZS ** [ O.Reg X6; O.ScalarReg D10 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (51)``() =
    "1e390261"
    ++ FCVTZU ** [ O.Reg W1; O.ScalarReg S19 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (52)``() =
    "1e79033b"
    ++ FCVTZU ** [ O.Reg W27; O.ScalarReg D25 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (53)``() =
    "9e390053"
    ++ FCVTZU ** [ O.Reg X19; O.ScalarReg S2 ]
    ||> test

  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and integer (54)``() =
    "9e790262"
    ++ FCVTZU ** [ O.Reg X2; O.ScalarReg D19 ]
    ||> test

  /// The moves and conversions between a half and a general register: a
  /// W or an X on the general side, type 11 on the other.
  [<TestMethod>]
  member _.``C4.6 Conversion between FP and integer (FP16) (1)``() =
    testDisasm "1ee70020" "fmov h0, w1"

  [<TestMethod>]
  member _.``C4.6 Conversion between FP and integer (FP16) (2)``() =
    testDisasm "1ee60020" "fmov w0, h1"

  [<TestMethod>]
  member _.``C4.6 Conversion between FP and integer (FP16) (3)``() =
    testDisasm "9ee70020" "fmov h0, x1"

  [<TestMethod>]
  member _.``C4.6 Conversion between FP and integer (FP16) (4)``() =
    testDisasm "9ee30020" "ucvtf h0, x1"

  [<TestMethod>]
  member _.``C4.6 Conversion between FP and integer (FP16) (5)``() =
    testDisasm "1ef80020" "fcvtzs w0, h1"

  [<TestMethod>]
  member _.``C4.6 Conversion between FP and integer (FP16) (6)``() =
    testDisasm "9ee50020" "fcvtau x0, h1"

  [<TestMethod>]
  member _.``C4.6 Conversion between FP and fixed-point (FP16) (1)``() =
    testDisasm "1ed8f420" "fcvtzs w0, h1, #3"

  [<TestMethod>]
  member _.``C4.6 Conversion between FP and fixed-point (FP16) (2)``() =
    testDisasm "1ec2f420" "scvtf h0, w1, #3"

  (* The instructions below had a lifter and no decoder arm, so the front end
     answered ParsingFailureException to every one of them and the lifter was
     unreachable. Each byte string is the assembler's own encoding of the text
     beside it. *)

  /// FEAT_FlagM and FEAT_FlagM2 write where a move to a PSTATE field would,
  /// with the immediate that field carries left at zero.
  [<TestMethod>]
  member _.``C4.2 Flag manipulation (1)``() =
    testDisasm "d500401f" "cfinv"

  [<TestMethod>]
  member _.``C4.2 Flag manipulation (2)``() =
    testDisasm "d500403f" "xaflag"

  [<TestMethod>]
  member _.``C4.2 Flag manipulation (3)``() =
    testDisasm "d500405f" "axflag"

  /// RMIF is the third of FEAT_FlagM and the only one that reads a register.
  /// Its immediate's low bit sits at 15, inside the field the class selects
  /// on, so an odd rotate reaches a different arm from an even one.
  [<TestMethod>]
  member _.``C4.2 Rotate right into flags (1)``() =
    "ba05040f" ++ RMIF ** [ O.Reg X0; O.Imm 0xaL; O.Imm 0xfL ] ||> test

  [<TestMethod>]
  member _.``C4.2 Rotate right into flags (2)``() =
    "ba1f87c9" ++ RMIF ** [ O.Reg X30; O.Imm 0x3fL; O.Imm 0x9L ] ||> test

  /// SETF8 and SETF16 share their class with the carrying add; the size sits
  /// in bit 14 of opcode2.
  [<TestMethod>]
  member _.``C4.2 Evaluate into flags (1)``() =
    "3a00086d" ++ SETF8 ** [ O.Reg W3 ] ||> test

  [<TestMethod>]
  member _.``C4.2 Evaluate into flags (2)``() =
    "3a0048ed" ++ SETF16 ** [ O.Reg W7 ] ||> test

  /// IRG writes its third operand only when it is named: register 31 there is
  /// the zero register and excludes no tag value.
  [<TestMethod>]
  member _.``C4.5 Data processing (2 source, tags) (1)``() =
    "9adf1020" ++ IRG ** [ O.Reg X0; O.Reg X1 ] ||> test

  [<TestMethod>]
  member _.``C4.5 Data processing (2 source, tags) (2)``() =
    "9ac21020" ++ IRG ** [ O.Reg X0; O.Reg X1; O.Reg X2 ] ||> test

  [<TestMethod>]
  member _.``C4.5 Data processing (2 source, tags) (3)``() =
    "9adf103f" ++ IRG ** [ O.Reg SP; O.Reg X1 ] ||> test

  [<TestMethod>]
  member _.``C4.5 Data processing (2 source, tags) (4)``() =
    "9ac21420" ++ GMI ** [ O.Reg X0; O.Reg X1; O.Reg X2 ] ||> test

  [<TestMethod>]
  member _.``C4.5 Data processing (2 source, tags) (5)``() =
    "9ac20020" ++ SUBP ** [ O.Reg X0; O.Reg X1; O.Reg X2 ] ||> test

  [<TestMethod>]
  member _.``C4.5 Data processing (2 source, tags) (6)``() =
    "bac50083" ++ SUBPS ** [ O.Reg X3; O.Reg X4; O.Reg X5 ] ||> test

  /// CMPP is the SUBPS whose destination is the zero register, so the
  /// destination field alone tells the two apart.
  [<TestMethod>]
  member _.``C4.5 Data processing (2 source, tags) (7)``() =
    "bac2003f" ++ CMPP ** [ O.Reg X1; O.Reg X2 ] ||> test

  /// ADDG and SUBG reach the immediate group by an op0 of 011 where the
  /// ordinary add and subtract take 010, and their first immediate counts
  /// granules of sixteen bytes rather than bytes. Both fields name the
  /// stack pointer at 31 rather than the zero register.
  [<TestMethod>]
  member _.``C4.2 Add/subtract (immediate, tags) (1)``() =
    "91810c20" ++ ADDG ** [ O.Reg X0; O.Reg X1; O.Imm 0x10L; O.Imm 3L ]
    ||> test

  [<TestMethod>]
  member _.``C4.2 Add/subtract (immediate, tags) (2)``() =
    "919f03ff" ++ ADDG ** [ O.Reg SP; O.Reg SP; O.Imm 0x1f0L; O.Imm 0L ]
    ||> test

  [<TestMethod>]
  member _.``C4.2 Add/subtract (immediate, tags) (3)``() =
    "d18214c5" ++ SUBG ** [ O.Reg X5; O.Reg X6; O.Imm 0x20L; O.Imm 5L ]
    ||> test

  /// FEAT_FP16 gave the halves two vector classes of their own, because the
  /// classes they would otherwise sit in spend on the element size the bits
  /// that would have named them. The three-same class is told apart by bit
  /// 21 being zero and the two-register one by bits 22:17, and in both the
  /// arrangement is named by Q alone.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-same (FP16) (1)``() =
    "4e423c20"
    ++ FRECPS
    ** [ O.SIMDVecReg(V0, EightH)
         O.SIMDVecReg(V1, EightH)
         O.SIMDVecReg(V2, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-same (FP16) (2)``() =
    "4ec23c20"
    ++ FRSQRTS
    ** [ O.SIMDVecReg(V0, EightH)
         O.SIMDVecReg(V1, EightH)
         O.SIMDVecReg(V2, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-same (FP16) (3)``() =
    "6ec21420"
    ++ FABD
    ** [ O.SIMDVecReg(V0, EightH)
         O.SIMDVecReg(V1, EightH)
         O.SIMDVecReg(V2, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-same (FP16) (4)``() =
    "0e421420"
    ++ FADD
    ** [ O.SIMDVecReg(V0, FourH)
         O.SIMDVecReg(V1, FourH)
         O.SIMDVecReg(V2, FourH) ]
    ||> test

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-same (FP16) (5)``() =
    "6ec22c20"
    ++ FACGT
    ** [ O.SIMDVecReg(V0, EightH)
         O.SIMDVecReg(V1, EightH)
         O.SIMDVecReg(V2, EightH) ]
    ||> test

  /// The scalar arithmetic takes type 11 for a half, which the class had no
  /// arm for at all.
  [<TestMethod>]
  member _.``C4.6 FP data-processing (2 source, FP16) (1)``() =
    testDisasm "1ee22820" "fadd h0, h1, h2"

  [<TestMethod>]
  member _.``C4.6 FP data-processing (2 source, FP16) (2)``() =
    testDisasm "1ee28820" "fnmul h0, h1, h2"

  [<TestMethod>]
  member _.``C4.6 FP data-processing (1 source, FP16) (1)``() =
    testDisasm "1ee1c020" "fsqrt h0, h1"

  [<TestMethod>]
  member _.``C4.6 FP data-processing (1 source, FP16) (2)``() =
    testDisasm "1ee74020" "frintx h0, h1"

  [<TestMethod>]
  member _.``C4.6 FP data-processing (1 source, FP16) (3)``() =
    testDisasm "1ee04020" "fmov h0, h1"

  [<TestMethod>]
  member _.``C4.6 FP data-processing (3 source, FP16) (1)``() =
    testDisasm "1fc20c20" "fmadd h0, h1, h2, h3"

  [<TestMethod>]
  member _.``C4.6 FP data-processing (3 source, FP16) (2)``() =
    testDisasm "1fe28c20" "fnmsub h0, h1, h2, h3"

  [<TestMethod>]
  member _.``C4.6 FP immediate (FP16)``() =
    testDisasm "1eee1000" "fmov h0, #1.00000000"

  [<TestMethod>]
  member _.``C4.6 FP compare (FP16) (1)``() =
    testDisasm "1ee12000" "fcmp h0, h1"

  [<TestMethod>]
  member _.``C4.6 FP compare (FP16) (2)``() =
    testDisasm "1ee02018" "fcmpe h0, #0.00000000"

  [<TestMethod>]
  member _.``C4.6 FP conditional compare (FP16)``() =
    testDisasm "1ee10400" "fccmp h0, h1, #0x0, eq"

  [<TestMethod>]
  member _.``C4.6 FP conditional select (FP16)``() =
    testDisasm "1ee21c20" "fcsel h0, h1, h2, ne"

  /// The scalar FP16 classes sit where the vector ones do in the scalar
  /// group, and nothing routed them before.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD scalar three-same (FP16) (1)``() =
    testDisasm "7ec21420" "fabd h0, h1, h2"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD scalar three-same (FP16) (2)``() =
    testDisasm "5ec23c20" "frsqrts h0, h1, h2"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD scalar two-register (FP16) (1)``() =
    testDisasm "5ef8d820" "fcmeq h0, h1, #0.00000000"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD scalar two-register (FP16) (2)``() =
    testDisasm "5ef9f820" "frecpx h0, h1"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD scalar two-register (FP16) (3)``() =
    testDisasm "7ef9b820" "fcvtzu h0, h1"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD scalar two-register (FP16) (4)``() =
    testDisasm "5e79d820" "scvtf h0, h1"

  /// A U of 0 is the half-precision pairwise form, whose source is two
  /// halves.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD scalar pairwise (FP16) (1)``() =
    testDisasm "5e30d820" "faddp h0, v1.2h"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD scalar pairwise (FP16) (2)``() =
    testDisasm "5eb0c820" "fminnmp h0, v1.2h"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD across lanes (FP16) (1)``() =
    testDisasm "4e30f820" "fmaxv h0, v1.8h"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD across lanes (FP16) (2)``() =
    testDisasm "0eb0c820" "fminnmv h0, v1.4h"

  /// FMOV of a half is the one modified-immediate form with o2 set.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD modified immediate (FP16) (1)``() =
    testDisasm "4f03fe00" "fmov v0.8h, #1.00000000"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD modified immediate (FP16) (2)``() =
    testDisasm "0f04fc00" "fmov v0.4h, #-2.00000000"

  /// An immh of 001x is FEAT_FP16's, which the class had as reserved.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD shift by immediate (FP16) (1)``() =
    testDisasm "4f1de420" "scvtf v0.8h, v1.8h, #3"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD shift by immediate (FP16) (2)``() =
    testDisasm "2f1efc20" "fcvtzu v0.4h, v1.4h, #2"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD shift by immediate (FP16) (3)``() =
    testDisasm "5f1de420" "scvtf h0, h1, #3"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD shift by immediate (FP16) (4)``() =
    testDisasm "5f1bfc20" "fcvtzs h0, h1, #5"

  /// A size of 00 is the half-precision form, whose element is laid out as
  /// an integer form of size 01 lays it out.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD by element (FP16) (1)``() =
    testDisasm "4f321020" "fmla v0.8h, v1.8h, v2.h[3]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD by element (FP16) (2)``() =
    testDisasm "0f125020" "fmls v0.4h, v1.4h, v2.h[1]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD by element (FP16) (3)``() =
    testDisasm "4f329020" "fmul v0.8h, v1.8h, v2.h[3]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD by element (FP16) (4)``() =
    testDisasm "6f229820" "fmulx v0.8h, v1.8h, v2.h[6]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD by element (FP16) (5)``() =
    testDisasm "5f129020" "fmul h0, h1, v2.h[1]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD by element (FP16) (6)``() =
    testDisasm "5f221020" "fmla h0, h1, v2.h[2]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD by element (FP16) (7)``() =
    testDisasm "7f329020" "fmulx h0, h1, v2.h[3]"

  /// FEAT_FCMA is the three-register extension class with U set: FCADD at
  /// opcode 11x0 with one bit of rotation, FCMLA at 10xx with two -- and by
  /// element, where its index names a pair and its register is M:Rm.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD complex (FCMA) (1)``() =
    testDisasm "2e42e420" "fcadd v0.4h, v1.4h, v2.4h, #0x5a"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD complex (FCMA) (2)``() =
    testDisasm "6e42f420" "fcadd v0.8h, v1.8h, v2.8h, #0x10e"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD complex (FCMA) (3)``() =
    testDisasm "2e82e420" "fcadd v0.2s, v1.2s, v2.2s, #0x5a"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD complex (FCMA) (4)``() =
    testDisasm "6e82f420" "fcadd v0.4s, v1.4s, v2.4s, #0x10e"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD complex (FCMA) (5)``() =
    testDisasm "6ec2e420" "fcadd v0.2d, v1.2d, v2.2d, #0x5a"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD complex (FCMA) (6)``() =
    testDisasm "2e42c420" "fcmla v0.4h, v1.4h, v2.4h, #0x0"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD complex (FCMA) (7)``() =
    testDisasm "6e42cc20" "fcmla v0.8h, v1.8h, v2.8h, #0x5a"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD complex (FCMA) (8)``() =
    testDisasm "2e82d420" "fcmla v0.2s, v1.2s, v2.2s, #0xb4"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD complex (FCMA) (9)``() =
    testDisasm "6e82dc20" "fcmla v0.4s, v1.4s, v2.4s, #0x10e"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD complex (FCMA) (10)``() =
    testDisasm "6ec2cc20" "fcmla v0.2d, v1.2d, v2.2d, #0x5a"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD complex (FCMA) (11)``() =
    testDisasm "2f621020" "fcmla v0.4h, v1.4h, v2.h[1], #0x0"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD complex (FCMA) (12)``() =
    testDisasm "6f623820" "fcmla v0.8h, v1.8h, v2.h[3], #0x5a"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD complex (FCMA) (13)``() =
    testDisasm "6f5f5820" "fcmla v0.8h, v1.8h, v31.h[2], #0xb4"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD complex (FCMA) (14)``() =
    testDisasm "6f827820" "fcmla v0.4s, v1.4s, v2.s[1], #0x10e"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD complex (FCMA) (15)``() =
    testDisasm "6f913020" "fcmla v0.4s, v1.4s, v17.s[0], #0x5a"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD two-register (FP16) (1)``() =
    "6ef8d820"
    ++ FCMLE
    ** [ O.SIMDVecReg(V0, EightH)
         O.SIMDVecReg(V1, EightH)
         OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD two-register (FP16) (2)``() =
    "4ef8e820"
    ++ FCMLT
    ** [ O.SIMDVecReg(V0, EightH)
         O.SIMDVecReg(V1, EightH)
         OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD two-register (FP16) (3)``() =
    "4e798820"
    ++ FRINTN
    ** [ O.SIMDVecReg(V0, EightH); O.SIMDVecReg(V1, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD two-register (FP16) (4)``() =
    "6ef9f820"
    ++ FSQRT
    ** [ O.SIMDVecReg(V0, EightH); O.SIMDVecReg(V1, EightH) ]
    ||> test

  /// FEAT_FHM's long multiply-accumulate, whose sources are halves and whose
  /// destination is words. Both forms spell the arrangement the same way, so
  /// the mnemonic is the only thing that says which half of the source
  /// register is read.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-same (FHM) (1)``() =
    "0e22ec20"
    ++ FMLAL
    ** [ O.SIMDVecReg(V0, TwoS)
         O.SIMDVecReg(V1, TwoH)
         O.SIMDVecReg(V2, TwoH) ]
    ||> test

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-same (FHM) (2)``() =
    "2e22cc20"
    ++ FMLAL2
    ** [ O.SIMDVecReg(V0, TwoS)
         O.SIMDVecReg(V1, TwoH)
         O.SIMDVecReg(V2, TwoH) ]
    ||> test

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-same (FHM) (3)``() =
    "4ea2ec20"
    ++ FMLSL
    ** [ O.SIMDVecReg(V0, FourS)
         O.SIMDVecReg(V1, FourH)
         O.SIMDVecReg(V2, FourH) ]
    ||> test

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-same (FHM) (4)``() =
    "6ea2cc20"
    ++ FMLSL2
    ** [ O.SIMDVecReg(V0, FourS)
         O.SIMDVecReg(V1, FourH)
         O.SIMDVecReg(V2, FourH) ]
    ||> test

  /// FEAT_RDM sits in the three-register extension class beside the dot
  /// products, and is the only thing there whose arrangement comes from the
  /// size field rather than from Q alone.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-register extension (RDM) (1)``() =
    "6e828420"
    ++ SQRDMLAH
    ** [ O.SIMDVecReg(V0, FourS)
         O.SIMDVecReg(V1, FourS)
         O.SIMDVecReg(V2, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-register extension (RDM) (2)``() =
    "6e828c20"
    ++ SQRDMLSH
    ** [ O.SIMDVecReg(V0, FourS)
         O.SIMDVecReg(V1, FourS)
         O.SIMDVecReg(V2, FourS) ]
    ||> test

  /// BFCVTN and BFCVTN2 are an ordinary two-register miscellaneous encoding
  /// whose two sides carry different arrangements: the source is four words
  /// whichever half of the destination the mnemonic names, so Q comes from
  /// the destination alone.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD two-register (BF16) (1)``() =
    "0ea16820"
    ++ BFCVTN
    ** [ O.SIMDVecReg(V0, FourH); O.SIMDVecReg(V1, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD two-register (BF16) (2)``() =
    "4ea16820"
    ++ BFCVTN2
    ** [ O.SIMDVecReg(V0, EightH); O.SIMDVecReg(V1, FourS) ]
    ||> test

  /// FEAT_I8MM's matrix multiplies are the one thing in this class whose
  /// arrangements are fixed rather than named by a size field: four words
  /// accumulated from sixteen bytes on each side, whatever Q says.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-register extension (I8MM) (1)``() =
    "4e82a420"
    ++ SMMLA
    ** [ O.SIMDVecReg(V0, FourS)
         O.SIMDVecReg(V1, SixteenB)
         O.SIMDVecReg(V2, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-register extension (I8MM) (2)``() =
    "6e82a420"
    ++ UMMLA
    ** [ O.SIMDVecReg(V0, FourS)
         O.SIMDVecReg(V1, SixteenB)
         O.SIMDVecReg(V2, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-register extension (I8MM) (3)``() =
    "4e82ac20"
    ++ USMMLA
    ** [ O.SIMDVecReg(V0, FourS)
         O.SIMDVecReg(V1, SixteenB)
         O.SIMDVecReg(V2, SixteenB) ]
    ||> test

  /// The dot products by element name a group of four bytes, whose register
  /// is M:Rm and whose index is H:L; they sit at an opcode the class had
  /// read as unallocated.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (DotProd) (1)``() =
    testDisasm "4fa2e020" "sdot v0.4s, v1.16b, v2.4b[1]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (DotProd) (2)``() =
    testDisasm "0fbfe820" "sdot v0.2s, v1.8b, v31.4b[3]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (DotProd) (3)``() =
    testDisasm "4f92e225" "sdot v5.4s, v17.16b, v18.4b[0]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (DotProd) (4)``() =
    testDisasm "6f82e820" "udot v0.4s, v1.16b, v2.4b[2]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (DotProd) (5)``() =
    testDisasm "2fb4e020" "udot v0.2s, v1.8b, v20.4b[1]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (I8MM) (1)``() =
    testDisasm "4f22f020" "sudot v0.4s, v1.16b, v2.4b[1]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (I8MM) (2)``() =
    testDisasm "0f1bf820" "sudot v0.2s, v1.8b, v27.4b[2]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (I8MM) (3)``() =
    testDisasm "0fa2f820" "usdot v0.2s, v1.8b, v2.4b[3]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (I8MM) (4)``() =
    testDisasm "4f93f020" "usdot v0.4s, v1.16b, v19.4b[0]"

  /// BFDOT by element names a pair of halves the same way; BFMLALB and
  /// BFMLALT name one half, with a register of four bits and H:L:M.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (BF16) (1)``() =
    testDisasm "4f62f020" "bfdot v0.4s, v1.8h, v2.2h[1]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (BF16) (2)``() =
    testDisasm "0f7ff820" "bfdot v0.2s, v1.4h, v31.2h[3]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (BF16) (3)``() =
    testDisasm "0ff2f820" "bfmlalb v0.4s, v1.8h, v2.h[7]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (BF16) (4)``() =
    testDisasm "0fc5f083" "bfmlalb v3.4s, v4.8h, v5.h[0]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (BF16) (5)``() =
    testDisasm "4feff020" "bfmlalt v0.4s, v1.8h, v15.h[2]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (FHM) (1)``() =
    testDisasm "4f920820" "fmlal v0.4s, v1.4h, v2.h[5]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (FHM) (2)``() =
    testDisasm "0f820020" "fmlal v0.2s, v1.2h, v2.h[0]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (FHM) (3)``() =
    testDisasm "2fbf8820" "fmlal2 v0.2s, v1.2h, v15.h[7]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (FHM) (4)``() =
    testDisasm "6fb38020" "fmlal2 v0.4s, v1.4h, v3.h[3]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (FHM) (5)``() =
    testDisasm "4f924020" "fmlsl v0.4s, v1.4h, v2.h[1]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (FHM) (6)``() =
    testDisasm "0fa94820" "fmlsl v0.2s, v1.2h, v9.h[6]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (FHM) (7)``() =
    testDisasm "6fa2c820" "fmlsl2 v0.4s, v1.4h, v2.h[6]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (FHM) (8)``() =
    testDisasm "2f8cc820" "fmlsl2 v0.2s, v1.2h, v12.h[4]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (RDM) (1)``() =
    testDisasm "6fa2d820" "sqrdmlah v0.4s, v1.4s, v2.s[3]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (RDM) (2)``() =
    testDisasm "2f9fd020" "sqrdmlah v0.2s, v1.2s, v31.s[0]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (RDM) (3)``() =
    testDisasm "6f72d820" "sqrdmlah v0.8h, v1.8h, v2.h[7]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (RDM) (4)``() =
    testDisasm "2f4fd820" "sqrdmlah v0.4h, v1.4h, v15.h[4]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (RDM) (5)``() =
    testDisasm "2f52f020" "sqrdmlsh v0.4h, v1.4h, v2.h[1]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (RDM) (6)``() =
    testDisasm "2fbff020" "sqrdmlsh v0.2s, v1.2s, v31.s[1]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (RDM) (7)``() =
    testDisasm "6f91f820" "sqrdmlsh v0.4s, v1.4s, v17.s[2]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD vector x indexed element (RDM) (8)``() =
    testDisasm "6f57f820" "sqrdmlsh v0.8h, v1.8h, v7.h[5]"

  /// BFDOT and BFMMLA are the three-register extension class at U = 1 and a
  /// size of 01, BFMMLA with Q set alone.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-register extension (BF16 dot) (1)``() =
    testDisasm "2e42fc20" "bfdot v0.2s, v1.4h, v2.4h"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-register extension (BF16 dot) (2)``() =
    testDisasm "6e42fc20" "bfdot v0.4s, v1.8h, v2.8h"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-register extension (BF16 dot) (3)``() =
    testDisasm "6e42ec20" "bfmmla v0.4s, v1.8h, v2.8h"

  /// SDOT with bit 10 clear: every word of the class holds it set.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-register extension (SDOT, bit 10)``() =
    testRefused "4e829020"

  /// SQRDMLAH with bit 10 clear.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-register extension (RDM, bit 10)``() =
    testRefused "6e828020"

  /// SMMLA with bit 10 clear.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-register extension (SMMLA, bit 10)``() =
    testRefused "4e82a020"

  /// BFDOT with bit 10 clear.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-register extension (BFDOT, bit 10)``() =
    testRefused "6e42f820"

  /// SMMLA with Q clear: the matrix multiplies are quadword-only, Q being
  /// part of their opcode rather than a choice of arrangement.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-register extension (SMMLA, Q clear)``() =
    testRefused "0e82a420"

  /// UMMLA with Q clear.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-register extension (UMMLA, Q clear)``() =
    testRefused "2e82a420"

  /// USMMLA with Q clear.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-register extension (USMMLA, Q clear)``() =
    testRefused "0e82ac20"

  /// BFMMLA with Q clear.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-register extension (BFMMLA, Q clear)``() =
    testRefused "2e42ec20"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD scalar x indexed element (RDM) (1)``() =
    testDisasm "7fa2d020" "sqrdmlah s0, s1, v2.s[1]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD scalar x indexed element (RDM) (2)``() =
    testDisasm "7f6fd820" "sqrdmlah h0, h1, v15.h[6]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD scalar x indexed element (RDM) (3)``() =
    testDisasm "7f72f020" "sqrdmlsh h0, h1, v2.h[3]"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD scalar x indexed element (RDM) (4)``() =
    testDisasm "7fbff820" "sqrdmlsh s0, s1, v31.s[3]"

  /// The scalar three same extra class holds the scalar SQRDMLAH and
  /// SQRDMLSH and nothing else, and nothing routed it.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD scalar three same extra (RDM) (1)``() =
    testDisasm "7e828420" "sqrdmlah s0, s1, s2"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD scalar three same extra (RDM) (2)``() =
    testDisasm "7e428420" "sqrdmlah h0, h1, h2"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD scalar three same extra (RDM) (3)``() =
    testDisasm "7e828c20" "sqrdmlsh s0, s1, s2"

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD scalar three same extra (RDM) (4)``() =
    testDisasm "7e458c83" "sqrdmlsh h3, h4, h5"

  /// BFMLALB and BFMLALT share one encoding and are told apart by Q, which
  /// here picks which bfloat16 of each word is read rather than how many
  /// lanes there are -- both write all four words.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-register extension (BF16) (1)``() =
    "2ec2fc20"
    ++ BFMLALB
    ** [ O.SIMDVecReg(V0, FourS)
         O.SIMDVecReg(V1, EightH)
         O.SIMDVecReg(V2, EightH) ]
    ||> test

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-register extension (BF16) (2)``() =
    "6ec2fc20"
    ++ BFMLALT
    ** [ O.SIMDVecReg(V0, FourS)
         O.SIMDVecReg(V1, EightH)
         O.SIMDVecReg(V2, EightH) ]
    ||> test

  /// FEAT_FRINTTS sits at the four opcodes above the ordinary roundings,
  /// which the one-source class had read as unallocated because the guard
  /// there tests the bit they all carry.
  [<TestMethod>]
  member _.``C4.6 Floating-point round to integer (1)``() =
    "1e684020" ++ FRINT32Z ** [ O.ScalarReg D0; O.ScalarReg D1 ] ||> test

  [<TestMethod>]
  member _.``C4.6 Floating-point round to integer (2)``() =
    "1e68c020" ++ FRINT32X ** [ O.ScalarReg D0; O.ScalarReg D1 ] ||> test

  [<TestMethod>]
  member _.``C4.6 Floating-point round to integer (3)``() =
    "1e694020" ++ FRINT64Z ** [ O.ScalarReg D0; O.ScalarReg D1 ] ||> test

  [<TestMethod>]
  member _.``C4.6 Floating-point round to integer (4)``() =
    "1e69c020" ++ FRINT64X ** [ O.ScalarReg D0; O.ScalarReg D1 ] ||> test

  /// The vector forms sit at the two-register opcodes 11110 and 11111 with a
  /// size of 0x, which the class had read as unallocated too.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD two-register (FRINTTS) (1)``() =
    "4e21e820"
    ++ FRINT32Z ** [ O.SIMDVecReg(V0, FourS); O.SIMDVecReg(V1, FourS) ]
    ||> test

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD two-register (FRINTTS) (2)``() =
    "6e61e820"
    ++ FRINT32X ** [ O.SIMDVecReg(V0, TwoD); O.SIMDVecReg(V1, TwoD) ]
    ||> test

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD two-register (FRINTTS) (3)``() =
    "0e21f820"
    ++ FRINT64Z ** [ O.SIMDVecReg(V0, TwoS); O.SIMDVecReg(V1, TwoS) ]
    ||> test

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD two-register (FRINTTS) (4)``() =
    "6e21f820"
    ++ FRINT64X ** [ O.SIMDVecReg(V0, FourS); O.SIMDVecReg(V1, FourS) ]
    ||> test

  /// FEAT_JSCVT takes the one combination of rmode and opcode the
  /// conversion class leaves free, and its source is a double and nothing
  /// else -- the type field is part of what names it.
  [<TestMethod>]
  member _.``C4.6 Floating-point convert (JavaScript)``() =
    "1e7e0020" ++ FJCVTZS ** [ O.Reg W0; O.ScalarReg D1 ] ||> test

  /// The memory-tag accesses count their offset in granules of sixteen bytes,
  /// where the unscaled accesses they sit beside count bytes.
  [<TestMethod>]
  member _.``C4.4 Load/store memory tags (1)``() =
    "d9600020" ++ LDG ** [ O.Reg X0; O.MemBaseImm(X1, 0L) ] ||> test

  [<TestMethod>]
  member _.``C4.4 Load/store memory tags (2)``() =
    "d97ff020" ++ LDG ** [ O.Reg X0; O.MemBaseImm(X1, -16L) ] ||> test

  [<TestMethod>]
  member _.``C4.4 Load/store memory tags (3)``() =
    "d9202820" ++ STG ** [ O.Reg X0; O.MemBaseImm(X1, 32L) ] ||> test

  [<TestMethod>]
  member _.``C4.4 Load/store memory tags (4)``() =
    "d9202420" ++ STG ** [ O.Reg X0; O.MemPostIdxImm(X1, 32L) ] ||> test

  [<TestMethod>]
  member _.``C4.4 Load/store memory tags (5)``() =
    "d9a01c20" ++ ST2G ** [ O.Reg X0; O.MemPreIdxImm(X1, 16L) ] ||> test

  [<TestMethod>]
  member _.``C4.4 Load/store memory tags (6)``() =
    "d9e01420" ++ STZ2G ** [ O.Reg X0; O.MemPostIdxImm(X1, 16L) ] ||> test

  /// LDGM, STGM and STZGM are op2 = 00 with no offset, which LDG leaves free
  /// at the other values of opc; with an offset they are no instruction.
  [<TestMethod>]
  member _.``C4.4 Load/store memory tags (LDGM)``() =
    "d9e003c0" ++ LDGM ** [ O.Reg X0; O.MemBaseImm X30 ] ||> test

  [<TestMethod>]
  member _.``C4.4 Load/store memory tags (STGM)``() =
    "d9a003e1" ++ STGM ** [ O.Reg X1; O.MemBaseImm SP ] ||> test

  [<TestMethod>]
  member _.``C4.4 Load/store memory tags (STZGM)``() =
    "d9200041" ++ STZGM ** [ O.Reg X1; O.MemBaseImm X2 ] ||> test

  /// LDGM with an offset: the block forms take none.
  [<TestMethod>]
  member _.``C4.4 Load/store memory tags (LDGM with an offset)``() =
    testRefused "d9e013c0"

  /// STGM with an offset.
  [<TestMethod>]
  member _.``C4.4 Load/store memory tags (STGM with an offset)``() =
    testRefused "d9a013e1"

  /// STZGM with an offset.
  [<TestMethod>]
  member _.``C4.4 Load/store memory tags (STZGM with an offset)``() =
    testRefused "d9201041"

  /// STGP is the one combination of opc and L the ordinary pairs leave free.
  [<TestMethod>]
  member _.``C4.4 Load/store register pair (tags) (1)``() =
    "69008440"
    ++ STGP ** [ O.Reg X0; O.Reg X1; O.MemBaseImm(X2, 16L) ]
    ||> test

  [<TestMethod>]
  member _.``C4.4 Load/store register pair (tags) (2)``() =
    "69808440"
    ++ STGP ** [ O.Reg X0; O.Reg X1; O.MemPreIdxImm(X2, 16L) ]
    ||> test

  /// The dot products read four bytes of each source for every word of the
  /// destination, so the two sides carry different arrangements.
  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-register extension (1)``() =
    "4e829420"
    ++ SDOT
    ** [ O.SIMDVecReg(V0, FourS)
         O.SIMDVecReg(V1, SixteenB)
         O.SIMDVecReg(V2, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-register extension (2)``() =
    "2e829420"
    ++ UDOT
    ** [ O.SIMDVecReg(V0, TwoS)
         O.SIMDVecReg(V1, EightB)
         O.SIMDVecReg(V2, EightB) ]
    ||> test

  [<TestMethod>]
  member _.``C4.6 Advanced SIMD three-register extension (3)``() =
    "4e829c20"
    ++ USDOT
    ** [ O.SIMDVecReg(V0, FourS)
         O.SIMDVecReg(V1, SixteenB)
         O.SIMDVecReg(V2, SixteenB) ]
    ||> test

  /// BFCVT sits in the slot beside the double-precision conversions, so its
  /// type field says 01 while its operands are a single and a half.
  [<TestMethod>]
  member _.``4.6.30 Conversion between FP and BFloat16``() =
    "1e634020" ++ BFCVT ** [ O.ScalarReg H0; O.ScalarReg S1 ] ||> test

  /// The four FEAT_SHA3 encodings share the 0xce opcode byte with the
  /// SHA-512, SM3 and SM4 families and are told from them by bits 23:21,
  /// which the group's own selector does not carry.
  [<TestMethod>]
  member _.``4.6.31 Cryptographic four-register (EOR3)``() =
    "ce020c20"
    ++ EOR3
    ** [ O.SIMDVecReg(V0, SixteenB)
         O.SIMDVecReg(V1, SixteenB)
         O.SIMDVecReg(V2, SixteenB)
         O.SIMDVecReg(V3, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.31 Cryptographic four-register (BCAX)``() =
    "ce220c20"
    ++ BCAX
    ** [ O.SIMDVecReg(V0, SixteenB)
         O.SIMDVecReg(V1, SixteenB)
         O.SIMDVecReg(V2, SixteenB)
         O.SIMDVecReg(V3, SixteenB) ]
    ||> test

  [<TestMethod>]
  member _.``4.6.31 Cryptographic three-register (RAX1)``() =
    "ce628c20"
    ++ RAX1
    ** [ O.SIMDVecReg(V0, TwoD)
         O.SIMDVecReg(V1, TwoD)
         O.SIMDVecReg(V2, TwoD) ]
    ||> test

  /// SHA-512, SM3 and SM4 fill the rest of the byte: the three-
  /// register SHA 512 class RAX1 belongs to, the two-register one,
  /// the imm2 one and the four-register one.
  [<TestMethod>]
  member _.``4.6.31 Cryptographic SHA512, SM3 and SM4 (1)``() =
    testDisasm "ce628020" "sha512h q0, q1, v2.2d"

  [<TestMethod>]
  member _.``4.6.31 Cryptographic SHA512, SM3 and SM4 (2)``() =
    testDisasm "ce628420" "sha512h2 q0, q1, v2.2d"

  [<TestMethod>]
  member _.``4.6.31 Cryptographic SHA512, SM3 and SM4 (3)``() =
    testDisasm "cec08020" "sha512su0 v0.2d, v1.2d"

  [<TestMethod>]
  member _.``4.6.31 Cryptographic SHA512, SM3 and SM4 (4)``() =
    testDisasm "ce628820" "sha512su1 v0.2d, v1.2d, v2.2d"

  [<TestMethod>]
  member _.``4.6.31 Cryptographic SHA512, SM3 and SM4 (5)``() =
    testDisasm "ce420c20" "sm3ss1 v0.4s, v1.4s, v2.4s, v3.4s"

  [<TestMethod>]
  member _.``4.6.31 Cryptographic SHA512, SM3 and SM4 (6)``() =
    testDisasm "ce42b020" "sm3tt1a v0.4s, v1.4s, v2.s[3]"

  [<TestMethod>]
  member _.``4.6.31 Cryptographic SHA512, SM3 and SM4 (7)``() =
    testDisasm "ce428420" "sm3tt1b v0.4s, v1.4s, v2.s[0]"

  [<TestMethod>]
  member _.``4.6.31 Cryptographic SHA512, SM3 and SM4 (8)``() =
    testDisasm "ce429820" "sm3tt2a v0.4s, v1.4s, v2.s[1]"

  [<TestMethod>]
  member _.``4.6.31 Cryptographic SHA512, SM3 and SM4 (9)``() =
    testDisasm "ce42ac20" "sm3tt2b v0.4s, v1.4s, v2.s[2]"

  [<TestMethod>]
  member _.``4.6.31 Cryptographic SHA512, SM3 and SM4 (10)``() =
    testDisasm "ce62c020" "sm3partw1 v0.4s, v1.4s, v2.4s"

  [<TestMethod>]
  member _.``4.6.31 Cryptographic SHA512, SM3 and SM4 (11)``() =
    testDisasm "ce62c420" "sm3partw2 v0.4s, v1.4s, v2.4s"

  [<TestMethod>]
  member _.``4.6.31 Cryptographic SHA512, SM3 and SM4 (12)``() =
    testDisasm "cec08420" "sm4e v0.4s, v1.4s"

  [<TestMethod>]
  member _.``4.6.31 Cryptographic SHA512, SM3 and SM4 (13)``() =
    testDisasm "ce62c820" "sm4ekey v0.4s, v1.4s, v2.4s"

  [<TestMethod>]
  member _.``4.6.31 XAR``() =
    "ce823420"
    ++ XAR
    ** [ O.SIMDVecReg(V0, TwoD)
         O.SIMDVecReg(V1, TwoD)
         O.SIMDVecReg(V2, TwoD)
         O.Imm 0xdL ]
    ||> test

  /// The pointer authentication family sits at opcode2 = 00001 of the
  /// one-source class, which every guard above it had marked unallocated.
  /// The Z forms fix the modifier's field to the zero register rather than
  /// leaving it out, so they are one operand where the others are two.
  [<TestMethod>]
  member _.``4.6.32 Pointer authentication (PACIA)``() =
    "dac10020" ++ PACIA ** [ O.Reg X0; O.Reg X1 ] ||> test

  [<TestMethod>]
  member _.``4.6.32 Pointer authentication (AUTDB)``() =
    "dac11c20" ++ AUTDB ** [ O.Reg X0; O.Reg X1 ] ||> test

  [<TestMethod>]
  member _.``4.6.32 Pointer authentication (PACIZA)``() =
    "dac123e0" ++ PACIZA ** [ O.Reg X0 ] ||> test

  [<TestMethod>]
  member _.``4.6.32 Pointer authentication (XPACD)``() =
    "dac147e0" ++ XPACD ** [ O.Reg X0 ] ||> test

  /// PACIZA with a register in Rn: the Z forms and XPACI and XPACD hold
  /// 11111 there as part of their opcode.
  [<TestMethod>]
  member _.``4.6.32 Pointer authentication (PACIZA, Rn not 11111)``() =
    testRefused "dac12043"

  /// AUTDZB with a register in Rn.
  [<TestMethod>]
  member _.``4.6.32 Pointer authentication (AUTDZB, Rn not 11111)``() =
    testRefused "dac13c43"

  /// XPACI with a register in Rn.
  [<TestMethod>]
  member _.``4.6.32 Pointer authentication (XPACI, Rn not 11111)``() =
    testRefused "dac14043"

  /// XPACD with a register in Rn.
  [<TestMethod>]
  member _.``4.6.32 Pointer authentication (XPACD, Rn not 11111)``() =
    testRefused "dac14443"

  [<TestMethod>]
  member _.``4.6.32 Pointer authentication (PACGA)``() =
    "9ac23020" ++ PACGA ** [ O.Reg X0; O.Reg X1; O.Reg X2 ] ||> test

  /// The implicit forms name no register and are encoded as hints, which is
  /// how a processor without the feature runs them and does nothing. They
  /// are told apart by CRm, which the system class's own selector does not
  /// carry.
  [<TestMethod>]
  member _.``4.6.32 Pointer authentication (PACIASP)``() =
    "d503233f" ++ PACIASP ** [] ||> test

  [<TestMethod>]
  member _.``4.6.32 Pointer authentication (AUTIB1716)``() =
    "d50321df" ++ AUTIB1716 ** [] ||> test

  [<TestMethod>]
  member _.``4.6.32 Pointer authentication (XPACLRI)``() =
    "d50320ff" ++ XPACLRI ** [] ||> test

  /// The branches authenticate their target first. BRAA and BLRAA name the
  /// modifier in the field the others hold 11111 in, where 11111 is the
  /// stack pointer; the Z forms fix that field, and RETAA and ERETAA fix Rn
  /// as well, so any other value in a fixed field is no instruction.
  [<TestMethod>]
  member _.``4.6.32 Pointer authentication (BRAA)``() =
    "d71f0843" ++ BRAA ** [ O.Reg X2; O.Reg X3 ] ||> test

  [<TestMethod>]
  member _.``4.6.32 Pointer authentication (BLRAB)``() =
    "d73f0c5f" ++ BLRAB ** [ O.Reg X2; O.Reg SP ] ||> test

  [<TestMethod>]
  member _.``4.6.32 Pointer authentication (BRABZ)``() =
    "d61f0c5f" ++ BRABZ ** [ O.Reg X2 ] ||> test

  [<TestMethod>]
  member _.``4.6.32 Pointer authentication (BLRAAZ)``() =
    "d63f081f" ++ BLRAAZ ** [ O.Reg X0 ] ||> test

  [<TestMethod>]
  member _.``4.6.32 Pointer authentication (RETAA)``() =
    "d65f0bff" ++ RETAA ** [] ||> test

  [<TestMethod>]
  member _.``4.6.32 Pointer authentication (ERETAB)``() =
    "d69f0fff" ++ ERETAB ** [] ||> test

  /// BRAAZ with a register in Rm, which the Z form holds at 11111.
  [<TestMethod>]
  member _.``4.6.32 Pointer authentication (BRAAZ, Rm not 11111)``() =
    testRefused "d61f0843"

  /// RETAA with registers in Rn and Rm, which it holds at 11111.
  [<TestMethod>]
  member _.``4.6.32 Pointer authentication (RETAA, Rn and Rm not 11111)``() =
    testRefused "d65f0843"

  /// ERETAA with a register in Rm.
  [<TestMethod>]
  member _.``4.6.32 Pointer authentication (ERETAA, Rm not 11111)``() =
    testRefused "d69f0bfe"

  /// DRPS with op3 set, which has no authenticated form.
  [<TestMethod>]
  member _.``4.6.32 Pointer authentication (DRPS, op3 not 000000)``() =
    testRefused "d6bf0bff"

  /// LDRAA and LDRAB authenticate the base before the offset is added, and
  /// the offset counts eight-byte words rather than bytes. Bit 10 is what
  /// tells the class from the atomics and the register offset beside it, and
  /// bit 11 above it is the writeback.
  [<TestMethod>]
  member _.``C4.4 Load/store register (pac) (1)``() =
    "f8201420" ++ LDRAA ** [ O.Reg X0; O.MemBaseImm(X1, 8L) ] ||> test

  [<TestMethod>]
  member _.``C4.4 Load/store register (pac) (2)``() =
    "f87ff420" ++ LDRAA ** [ O.Reg X0; O.MemBaseImm(X1, -8L) ] ||> test

  [<TestMethod>]
  member _.``C4.4 Load/store register (pac) (3)``() =
    "f83ffc62" ++ LDRAA ** [ O.Reg X2; O.MemPreIdxImm(X3, 4088L) ] ||> test

  [<TestMethod>]
  member _.``C4.4 Load/store register (pac) (4)``() =
    "f8e004a4" ++ LDRAB ** [ O.Reg X4; O.MemBaseImm(X5, -4096L) ] ||> test

  [<TestMethod>]
  member _.``C4.4 Load/store register (pac) (5)``() =
    "f8a007e6" ++ LDRAB ** [ O.Reg X6; O.MemBaseImm(SP, 0L) ] ||> test

  /// An ISA naming a version reads what DDI0487F.c A2 makes mandatory at that
  /// version and what its extensions name, and nothing else: FEAT_LSE is
  /// Armv8.1's and an Armv8.0 core has it only by naming it, FEAT_FP16 stays
  /// OPTIONAL at every version, and FEAT_FHM is mandatory from Armv8.4 only
  /// where FEAT_FP16 is had.

  [<TestMethod>]
  member _.``[AArch64] CASAL is FEAT_LSE's``() =
    readsOnlyUnder "88e0fc41" [ "armv8.1-a"; "armv8-a+lse" ] [ "armv8-a" ]

  [<TestMethod>]
  member _.``[AArch64] SQRDMLAH is FEAT_RDM's``() =
    readsOnlyUnder "6e828420" [ "armv8.1-a"; "armv8-a+rdma" ] [ "armv8-a" ]

  [<TestMethod>]
  member _.``[AArch64] FADD of halves is FEAT_FP16's``() =
    readsOnlyUnder "1ee22820" [ "armv8.2-a+fp16" ] [ "armv8.2-a"; "armv8.6-a" ]

  [<TestMethod>]
  member _.``[AArch64] FMLAL is FEAT_FHM's``() =
    readsOnlyUnder "0e22ec20" [ "armv8.2-a+fp16fml" ] [ "armv8.2-a+fp16" ]

  [<TestMethod>]
  member _.``[AArch64] FMLAL comes with FEAT_FP16 at Armv8.4``() =
    readsOnlyUnder "0e22ec20" [ "armv8.4-a+fp16" ] [ "armv8.4-a" ]

  [<TestMethod>]
  member _.``[AArch64] SDOT is FEAT_DotProd's``() =
    readsOnlyUnder "4e829420"
      [ "armv8.2-a+dotprod"; "armv8.4-a" ]
      [ "armv8.2-a" ]

  [<TestMethod>]
  member _.``[AArch64] PACIA is FEAT_PAuth's``() =
    readsOnlyUnder "dac10020" [ "armv8.3-a"; "armv8.2-a+pauth" ] [ "armv8.2-a" ]

  [<TestMethod>]
  member _.``[AArch64] FJCVTZS is Armv8.3's``() =
    readsOnlyUnder "1e7e0020" [ "armv8.3-a" ] [ "armv8.2-a" ]

  [<TestMethod>]
  member _.``[AArch64] LDAPUR is Armv8.4's``() =
    readsOnlyUnder "99400020" [ "armv8.4-a" ] [ "armv8.3-a" ]

  [<TestMethod>]
  member _.``[AArch64] FRINT32Z is Armv8.5's``() =
    readsOnlyUnder "1e284020" [ "armv8.5-a" ] [ "armv8.4-a" ]

  [<TestMethod>]
  member _.``[AArch64] IRG is FEAT_MTE's``() =
    readsOnlyUnder "9adf1020"
      [ "armv8.5-a+memtag" ]
      [ "armv8.5-a"; "armv8.6-a" ]

  [<TestMethod>]
  member _.``[AArch64] BFDOT is FEAT_BF16's``() =
    readsOnlyUnder "6e42fc20" [ "armv8.6-a"; "armv8.2-a+bf16" ] [ "armv8.5-a" ]

  [<TestMethod>]
  member _.``[AArch64] SMMLA is FEAT_I8MM's``() =
    readsOnlyUnder "4e82a420" [ "armv8.6-a"; "armv8.2-a+i8mm" ] [ "armv8.5-a" ]

  [<TestMethod>]
  member _.``[AArch64] CRC32B is FEAT_CRC32's``() =
    readsOnlyUnder "1ac24020" [ "armv8.1-a"; "armv8-a+crc" ] [ "armv8-a" ]

  [<TestMethod>]
  member _.``[AArch64] AESE is FEAT_AES's``() =
    readsOnlyUnder "4e284820"
      [ "armv8-a+aes"; "armv8-a+crypto" ]
      [ "armv8.6-a" ]

  [<TestMethod>]
  member _.``[AArch64] PMULL of bytes is every version's``() =
    readsOnlyUnder "0e22e020" [ "armv8-a" ] []

  [<TestMethod>]
  member _.``[AArch64] PMULL of doublewords is FEAT_PMULL's``() =
    readsOnlyUnder "0ee2e020" [ "armv8-a+aes" ] [ "armv8-a" ]

  [<TestMethod>]
  member _.``[AArch64] SHA512H is FEAT_SHA512's``() =
    readsOnlyUnder "ce628020"
      [ "armv8.2-a+sha3" ]
      [ "armv8.2-a"; "armv8.2-a+crypto" ]

  [<TestMethod>]
  member _.``[AArch64] SM4E is FEAT_SM4's``() =
    readsOnlyUnder "cec08420" [ "armv8.2-a+sm4" ] [ "armv8.2-a" ]

  [<TestMethod>]
  member _.``[AArch64] FCADD of singles is Armv8.3's``() =
    readsOnlyUnder "6e82e420" [ "armv8.3-a" ] [ "armv8.2-a" ]

  [<TestMethod>]
  member _.``[AArch64] FCADD of halves needs FEAT_FP16 as well``() =
    readsOnlyUnder "2e42e420"
      [ "armv8.3-a+fp16" ]
      [ "armv8.3-a"; "armv8.2-a+fp16" ]

  [<TestMethod>]
  member _.``[AArch64] ADD is every version's``() =
    readsOnlyUnder "8b020020" [ "armv8-a" ] []

  [<TestMethod>]
  member _.``[AArch64] LDLAR is Armv8.1's``() =
    readsOnlyUnder "88df7c20" [ "armv8.1-a" ] [ "armv8-a" ]

  [<TestMethod>]
  member _.``[AArch64] CFINV is FEAT_FlagM's``() =
    readsOnlyUnder "d500401f" [ "armv8.4-a"; "armv8.2-a+flagm" ] [ "armv8.3-a" ]

  [<TestMethod>]
  member _.``[AArch64] AXFLAG is Armv8.5's``() =
    readsOnlyUnder "d500405f" [ "armv8.5-a" ] [ "armv8.4-a" ]

  [<TestMethod>]
  member _.``[AArch64] SB is FEAT_SB's``() =
    readsOnlyUnder "d50330ff" [ "armv8.5-a"; "armv8-a+sb" ] [ "armv8.4-a" ]

  [<TestMethod>]
  member _.``[AArch64] MSR PAN is Armv8.1's``() =
    readsOnlyUnder "d500419f" [ "armv8.1-a" ] [ "armv8-a" ]

  [<TestMethod>]
  member _.``[AArch64] MRS PAN is Armv8.1's``() =
    readsOnlyUnder "d5384260" [ "armv8.1-a" ] [ "armv8-a" ]

  [<TestMethod>]
  member _.``[AArch64] MSR UAO is Armv8.2's``() =
    readsOnlyUnder "d500417f" [ "armv8.2-a" ] [ "armv8.1-a" ]

  [<TestMethod>]
  member _.``[AArch64] MSR DIT is Armv8.4's``() =
    readsOnlyUnder "d503415f" [ "armv8.4-a" ] [ "armv8.3-a" ]

  [<TestMethod>]
  member _.``[AArch64] MSR SSBS is FEAT_SSBS's``() =
    readsOnlyUnder "d503413f" [ "armv8.5-a"; "armv8-a+ssbs" ] [ "armv8.4-a" ]

  [<TestMethod>]
  member _.``[AArch64] MSR TCO is FEAT_MTE's``() =
    readsOnlyUnder "d503419f" [ "armv8.5-a+memtag" ] [ "armv8.5-a" ]

  [<TestMethod>]
  member _.``[AArch64] MSR SPSel is every version's``() =
    readsOnlyUnder "d50042bf" [ "armv8-a" ] []

  [<TestMethod>]
  member _.``[AArch64] LDAPR is FEAT_LRCPC's``() =
    readsOnlyUnder "b8bfc020" [ "armv8.3-a"; "armv8.2-a+rcpc" ] [ "armv8.2-a" ]

  [<TestMethod>]
  member _.``[AArch64] FMOV of a half is FEAT_FP16's``() =
    readsOnlyUnder "1ee70020" [ "armv8.2-a+fp16" ] [ "armv8.2-a" ]

  /// An ISA that names no version reads every word, which is what it has
  /// always done.
  [<TestMethod>]
  member _.``[AArch64] An ISA with no version reads CASAL``() =
    Assert.AreEqual<bool>(true, (under "aarch64" "88e0fc41").IsSome)

  [<TestMethod>]
  member _.``[AArch64] An ISA with no version reads FADD of halves``() =
    Assert.AreEqual<bool>(true, (under "aarch64" "1ee22820").IsSome)

  [<TestMethod>]
  member _.``[AArch64] An ISA with no version reads IRG``() =
    Assert.AreEqual<bool>(true, (under "aarch64" "9adf1020").IsSome)

  [<TestMethod>]
  member _.``[AArch64] An ISA with no version reads BFDOT``() =
    Assert.AreEqual<bool>(true, (under "aarch64" "6e42fc20").IsSome)

  /// A hint the version does not have is still a hint: the hint space is
  /// defined as a NOP wherever its instruction is not implemented, so the
  /// word reads as HINT rather than being refused.
  [<TestMethod>]
  member _.``[AArch64] PACIASP reads as HINT before Armv8.3``() =
    readsAs "d503233f" "armv8.2-a" "hint #0x19" "armv8.3-a" "paciasp"

  [<TestMethod>]
  member _.``[AArch64] XPACLRI reads as HINT before Armv8.3``() =
    readsAs "d50320ff" "armv8.2-a" "hint #0x7" "armv8.3-a" "xpaclri"

  /// The named hints follow the same rule. FEAT_BTI is Armv8.5's and
  /// FEAT_RAS Armv8.2's; FEAT_SPE and FEAT_TRF are never made mandatory and
  /// are had by naming them; CSDB is every version's.
  [<TestMethod>]
  member _.``[AArch64] BTI reads as HINT before Armv8.5``() =
    readsAs "d503241f" "armv8.4-a" "hint #0x20" "armv8.5-a" "bti"

  [<TestMethod>]
  member _.``[AArch64] ESB reads as HINT before Armv8.2``() =
    readsAs "d503221f" "armv8.1-a" "hint #0x10" "armv8.2-a" "esb"

  [<TestMethod>]
  member _.``[AArch64] ESB reads by name where FEAT_RAS is named``() =
    readsAs "d503221f" "armv8-a" "hint #0x10" "armv8-a+ras" "esb"

  [<TestMethod>]
  member _.``[AArch64] PSB CSYNC reads by name only with FEAT_SPE``() =
    readsAs "d503223f" "armv8.6-a" "hint #0x11" "armv8.2-a+profile" "psb csync"

  [<TestMethod>]
  member _.``[AArch64] TSB CSYNC reads by name only with FEAT_TRF``() =
    readsAs "d503225f" "armv8.6-a" "hint #0x12" "armv8.4-a+trf" "tsb csync"

  [<TestMethod>]
  member _.``[AArch64] CSDB reads by name at every version``() =
    Assert.AreEqual<string option>(Some "csdb", under "armv8-a" "d503229f")

  /// 0x0000_imm16 is UDF, permanently undefined (DDI0487F.c C6.2.335); the
  /// rest of the reserved space is unallocated.
  [<TestMethod>]
  member _.``[AArch64] UDF decodes``() =
    testDisasm "00000000" "udf #0x0"
    testDisasm "0000abcd" "udf #0xabcd"

  [<TestMethod>]
  member _.``[AArch64] The rest of the reserved space is refused``() =
    testRefused "00010000"

  /// A pre-indexed access writes its offset even when it is zero, since
  /// [<Xn|SP>, #<imm>]! has no form without one (DDI0487F.c C6.2.273, STP);
  /// only LDRAA and LDRAB make it optional there (C6.2.134).
  [<TestMethod>]
  member _.``[AArch64] A pre-indexed access writes a zero offset``() =
    testDisasm "298003c0" "stp w0, w0, [x30, #0x0]!"
    testDisasm "29c007c0" "ldp w0, w1, [x30, #0x0]!"
    testDisasm "3c400fc0" "ldr b0, [x30, #0x0]!"
    testDisasm "38c00fc0" "ldrsb w0, [x30, #0x0]!"
    testDisasm "78800fc0" "ldrsh x0, [x30, #0x0]!"
    testDisasm "698003c0" "stgp x0, x0, [x30, #0x0]!"
    testDisasm "d9200fc0" "stg x0, [x30, #0x0]!"
    testDisasm "f8200fc0" "ldraa x0, [x30]!"

  /// AL goes unwritten nowhere it is an operand: the instructions that take
  /// a condition write it as al like any other.
  [<TestMethod>]
  member _.``[AArch64] A condition operand writes AL``() =
    testDisasm "1a81e043" "csel w3, w2, w1, al"
    testDisasm "1a82e420" "csinc w0, w1, w2, al"
    testDisasm "5a82e020" "csinv w0, w1, w2, al"
    testDisasm "da82e420" "csneg x0, x1, x2, al"
    testDisasm "7a41e003" "ccmp w0, w1, #0x3, al"
    testDisasm "ba5fe800" "ccmn x0, #0x1f, #0x0, al"
    testDisasm "1e22ec20" "fcsel s0, s1, s2, al"
    testDisasm "1e61e403" "fccmp d0, d1, #0x3, al"
    testDisasm "1e21e41f" "fccmpe s0, s1, #0xf, al"

  /// A shifted register leaves out only LSL #0, which is what an absent
  /// shift means; any other shift by zero is a different encoding and is
  /// written.
  [<TestMethod>]
  member _.``[AArch64] A shift other than LSL keeps an amount of zero``() =
    testDisasm "2a5f03ff" "orr wzr, wzr, wzr, lsr #0x0"
    testDisasm "8a820020" "and x0, x1, x2, asr #0x0"
    testDisasm "0a620020" "bic w0, w1, w2, lsr #0x0"
    testDisasm "cae20020" "eon x0, x1, x2, ror #0x0"
    testDisasm "2ae103e0" "mvn w0, w1, ror #0x0"
    testDisasm "eac2003f" "tst x1, x2, ror #0x0"
    testDisasm "0b420020" "add w0, w1, w2, lsr #0x0"
    testDisasm "cb820020" "sub x0, x1, x2, asr #0x0"
    testDisasm "cb8103e0" "neg x0, x1, asr #0x0"
    testDisasm "6b42003f" "cmp w1, w2, lsr #0x0"
    testDisasm "8a020020" "and x0, x1, x2"

  /// SHLL's amount is an immediate, SHLL <Vd>.<Ta>, <Vn>.<Tb>, #<shift>
  /// (DDI0487F.c C7.2.255), not a shift.
  [<TestMethod>]
  member _.``[AArch64] SHLL writes its amount as an immediate``() =
    testDisasm "2e213843" "shll v3.8h, v2.8b, #0x8"
    testDisasm "6e613843" "shll2 v3.4s, v2.8h, #0x10"
    testDisasm "2ea13843" "shll v3.2d, v2.2s, #0x20"

  /// A byte access with a register offset has two encodings that scale by
  /// zero: S clear writes no amount, S set writes "#0" (DDI0487F.c C6.2,
  /// LDRB (register): "{, <extend> {<amount>}}", <amount> 0 when S is 1),
  /// and the two read differently or they would be one encoding.
  [<TestMethod>]
  member _.``[AArch64] A byte register offset keeps an amount of zero``() =
    testDisasm "38627820" "ldrb w0, [x1, x2, lsl #0x0]"
    testDisasm "38626820" "ldrb w0, [x1, x2]"
    testDisasm "38615843" "ldrb w3, [x2, w1, uxtw #0]"
    testDisasm "38614843" "ldrb w3, [x2, w1, uxtw]"
    testDisasm "38a15843" "ldrsb x3, [x2, w1, uxtw #0]"
    testDisasm "38215843" "strb w3, [x2, w1, uxtw #0]"
    testDisasm "3c627820" "ldr b0, [x1, x2, lsl #0x0]"
    testDisasm "b8627820" "ldr w0, [x1, x2, lsl #0x2]"

  (* One test for each A64 instruction DDI0487F.c's C6.2 and C7.2 describes, in
     the order of its sections. Each reads words of the instruction and checks
     the text, and each word is one binutils' objdump reads as the same
     instruction with the same operands, so what is asserted is a reading two
     decoders agree on. *)
  /// C6.2.1 ADC
  [<TestMethod>]
  member _.``C6.2.1 ADC``() =
    testDisasm "1a020020" "adc w0, w1, w2"
    testDisasm "9a020020" "adc x0, x1, x2"
    testDisasm "1a1f03ff" "adc wzr, wzr, wzr"
    testDisasm "1a0a03e9" "adc w9, wzr, w10"

  /// C6.2.10 ADR
  [<TestMethod>]
  member _.``C6.2.10 ADR``() =
    testDisasm "10000020" "adr x0, 0x4"
    testDisasm "101f03ff" "adr xzr, 0x3e07c"

  /// C6.2.100 LDADD, LDADDA, LDADDAL, LDADDL
  [<TestMethod>]
  member _.``C6.2.100 LDADD``() =
    testDisasm "f8220020" "ldadd x2, x0, [x1]"
    testDisasm "f822003f" "stadd x2, [x1]"
    testDisasm "b8220020" "ldadd w2, w0, [x1]"
    testDisasm "b822003f" "stadd w2, [x1]"

  /// C6.2.100 LDADD, LDADDA, LDADDAL, LDADDL
  [<TestMethod>]
  member _.``C6.2.100 LDADDA``() =
    testDisasm "b8a20020" "ldadda w2, w0, [x1]"
    testDisasm "b8bf03ff" "ldadda wzr, wzr, [sp]"
    testDisasm "b8aa03e9" "ldadda w10, w9, [sp]"
    testDisasm "b8bf03c0" "ldadda wzr, w0, [x30]"

  /// C6.2.100 LDADD, LDADDA, LDADDAL, LDADDL
  [<TestMethod>]
  member _.``C6.2.100 LDADDAL``() =
    testDisasm "b8e20020" "ldaddal w2, w0, [x1]"
    testDisasm "b8ff03ff" "ldaddal wzr, wzr, [sp]"
    testDisasm "b8ea03e9" "ldaddal w10, w9, [sp]"
    testDisasm "b8ff03c0" "ldaddal wzr, w0, [x30]"

  /// C6.2.100 LDADD, LDADDA, LDADDAL, LDADDL
  [<TestMethod>]
  member _.``C6.2.100 LDADDL``() =
    testDisasm "b8620020" "ldaddl w2, w0, [x1]"
    testDisasm "b862003f" "staddl w2, [x1]"
    testDisasm "b87f03ff" "staddl wzr, [sp]"
    testDisasm "b86a03e9" "ldaddl w10, w9, [sp]"

  /// C6.2.101 LDAPR
  [<TestMethod>]
  member _.``C6.2.101 LDAPR``() =
    testDisasm "f8bfc020" "ldapr x0, [x1]"
    testDisasm "b8bfc020" "ldapr w0, [x1]"
    testDisasm "b8bfc3ff" "ldapr wzr, [sp]"
    testDisasm "b8bfc3e0" "ldapr w0, [sp]"

  /// C6.2.102 LDAPRB
  [<TestMethod>]
  member _.``C6.2.102 LDAPRB``() =
    testDisasm "38bfc020" "ldaprb w0, [x1]"
    testDisasm "38bfc3ff" "ldaprb wzr, [sp]"
    testDisasm "38bfc3e0" "ldaprb w0, [sp]"

  /// C6.2.103 LDAPRH
  [<TestMethod>]
  member _.``C6.2.103 LDAPRH``() =
    testDisasm "78bfc020" "ldaprh w0, [x1]"
    testDisasm "78bfc3ff" "ldaprh wzr, [sp]"
    testDisasm "78bfc3e0" "ldaprh w0, [sp]"

  /// C6.2.104 LDAPUR
  [<TestMethod>]
  member _.``C6.2.104 LDAPUR``() =
    testDisasm "d9400020" "ldapur x0, [x1]"
    testDisasm "99410020" "ldapur w0, [x1, #0x10]"
    testDisasm "d9410020" "ldapur x0, [x1, #0x10]"
    testDisasm "99400020" "ldapur w0, [x1]"

  /// C6.2.105 LDAPURB
  [<TestMethod>]
  member _.``C6.2.105 LDAPURB``() =
    testDisasm "19400020" "ldapurb w0, [x1]"
    testDisasm "19410020" "ldapurb w0, [x1, #0x10]"
    testDisasm "195f03ff" "ldapurb wzr, [sp, #0xfffffffffffffff0]"
    testDisasm "194a03e9" "ldapurb w9, [sp, #0xa0]"

  /// C6.2.106 LDAPURH
  [<TestMethod>]
  member _.``C6.2.106 LDAPURH``() =
    testDisasm "59400020" "ldapurh w0, [x1]"
    testDisasm "59410020" "ldapurh w0, [x1, #0x10]"
    testDisasm "595f03ff" "ldapurh wzr, [sp, #0xfffffffffffffff0]"
    testDisasm "594a03e9" "ldapurh w9, [sp, #0xa0]"

  /// C6.2.107 LDAPURSB
  [<TestMethod>]
  member _.``C6.2.107 LDAPURSB``() =
    testDisasm "19800020" "ldapursb x0, [x1]"
    testDisasm "19c10020" "ldapursb w0, [x1, #0x10]"
    testDisasm "19810020" "ldapursb x0, [x1, #0x10]"
    testDisasm "19c00020" "ldapursb w0, [x1]"

  /// C6.2.108 LDAPURSH
  [<TestMethod>]
  member _.``C6.2.108 LDAPURSH``() =
    testDisasm "59800020" "ldapursh x0, [x1]"
    testDisasm "59c10020" "ldapursh w0, [x1, #0x10]"
    testDisasm "59810020" "ldapursh x0, [x1, #0x10]"
    testDisasm "59c00020" "ldapursh w0, [x1]"

  /// C6.2.109 LDAPURSW
  [<TestMethod>]
  member _.``C6.2.109 LDAPURSW``() =
    testDisasm "99800020" "ldapursw x0, [x1]"
    testDisasm "99810020" "ldapursw x0, [x1, #0x10]"
    testDisasm "999f03ff" "ldapursw xzr, [sp, #0xfffffffffffffff0]"
    testDisasm "998a03e9" "ldapursw x9, [sp, #0xa0]"

  /// C6.2.11 ADRP
  [<TestMethod>]
  member _.``C6.2.11 ADRP``() =
    testDisasm "90000000" "adrp x0, 0x0"
    testDisasm "901f03ff" "adrp xzr, 0x3e07c000"

  /// C6.2.110 LDAR
  [<TestMethod>]
  member _.``C6.2.110 LDAR``() =
    testDisasm "c8dffc20" "ldar x0, [x1]"
    testDisasm "88dffc20" "ldar w0, [x1]"

  /// C6.2.111 LDARB
  [<TestMethod>]
  member _.``C6.2.111 LDARB``() =
    testDisasm "08dffc20" "ldarb w0, [x1]"

  /// C6.2.112 LDARH
  [<TestMethod>]
  member _.``C6.2.112 LDARH``() =
    testDisasm "48dffc20" "ldarh w0, [x1]"

  /// C6.2.113 LDAXP
  [<TestMethod>]
  member _.``C6.2.113 LDAXP``() =
    testDisasm "887f8022" "ldaxp w2, w0, [x1]"
    testDisasm "887f83ff" "ldaxp wzr, w0, [sp]"
    testDisasm "886a83e9" "ldaxp w9, w0, [sp]"
    testDisasm "8861fc43" "ldaxp w3, wzr, [x2]"

  /// C6.2.114 LDAXR
  [<TestMethod>]
  member _.``C6.2.114 LDAXR``() =
    testDisasm "885ffc20" "ldaxr w0, [x1]"
    testDisasm "885f83ff" "ldaxr wzr, [sp]"
    testDisasm "884a83e9" "ldaxr w9, [sp]"
    testDisasm "c8418043" "ldaxr x3, [x2]"

  /// C6.2.115 LDAXRB
  [<TestMethod>]
  member _.``C6.2.115 LDAXRB``() =
    testDisasm "085ffc20" "ldaxrb w0, [x1]"
    testDisasm "085f83ff" "ldaxrb wzr, [sp]"
    testDisasm "084a83e9" "ldaxrb w9, [sp]"

  /// C6.2.116 LDAXRH
  [<TestMethod>]
  member _.``C6.2.116 LDAXRH``() =
    testDisasm "485ffc20" "ldaxrh w0, [x1]"
    testDisasm "485f83ff" "ldaxrh wzr, [sp]"
    testDisasm "484a83e9" "ldaxrh w9, [sp]"

  /// C6.2.117 LDCLRB, LDCLRAB, LDCLRALB, LDCLRLB
  [<TestMethod>]
  member _.``C6.2.117 LDCLRAB``() =
    testDisasm "38a21020" "ldclrab w2, w0, [x1]"
    testDisasm "38bf13ff" "ldclrab wzr, wzr, [sp]"
    testDisasm "38aa13e9" "ldclrab w10, w9, [sp]"
    testDisasm "38bf13c0" "ldclrab wzr, w0, [x30]"

  /// C6.2.117 LDCLRB, LDCLRAB, LDCLRALB, LDCLRLB
  [<TestMethod>]
  member _.``C6.2.117 LDCLRALB``() =
    testDisasm "38e21020" "ldclralb w2, w0, [x1]"
    testDisasm "38ff13ff" "ldclralb wzr, wzr, [sp]"
    testDisasm "38ea13e9" "ldclralb w10, w9, [sp]"
    testDisasm "38ff13c0" "ldclralb wzr, w0, [x30]"

  /// C6.2.117 LDCLRB, LDCLRAB, LDCLRALB, LDCLRLB
  [<TestMethod>]
  member _.``C6.2.117 LDCLRB``() =
    testDisasm "38221020" "ldclrb w2, w0, [x1]"
    testDisasm "3822103f" "stclrb w2, [x1]"
    testDisasm "383f13ff" "stclrb wzr, [sp]"
    testDisasm "382a13e9" "ldclrb w10, w9, [sp]"

  /// C6.2.117 LDCLRB, LDCLRAB, LDCLRALB, LDCLRLB
  [<TestMethod>]
  member _.``C6.2.117 LDCLRLB``() =
    testDisasm "38621020" "ldclrlb w2, w0, [x1]"
    testDisasm "3862103f" "stclrlb w2, [x1]"
    testDisasm "387f13ff" "stclrlb wzr, [sp]"
    testDisasm "386a13e9" "ldclrlb w10, w9, [sp]"

  /// C6.2.118 LDCLRH, LDCLRAH, LDCLRALH, LDCLRLH
  [<TestMethod>]
  member _.``C6.2.118 LDCLRAH``() =
    testDisasm "78a21020" "ldclrah w2, w0, [x1]"
    testDisasm "78bf13ff" "ldclrah wzr, wzr, [sp]"
    testDisasm "78aa13e9" "ldclrah w10, w9, [sp]"
    testDisasm "78bf13c0" "ldclrah wzr, w0, [x30]"

  /// C6.2.118 LDCLRH, LDCLRAH, LDCLRALH, LDCLRLH
  [<TestMethod>]
  member _.``C6.2.118 LDCLRALH``() =
    testDisasm "78e21020" "ldclralh w2, w0, [x1]"
    testDisasm "78ff13ff" "ldclralh wzr, wzr, [sp]"
    testDisasm "78ea13e9" "ldclralh w10, w9, [sp]"
    testDisasm "78ff13c0" "ldclralh wzr, w0, [x30]"

  /// C6.2.118 LDCLRH, LDCLRAH, LDCLRALH, LDCLRLH
  [<TestMethod>]
  member _.``C6.2.118 LDCLRH``() =
    testDisasm "78221020" "ldclrh w2, w0, [x1]"
    testDisasm "7822103f" "stclrh w2, [x1]"
    testDisasm "783f13ff" "stclrh wzr, [sp]"
    testDisasm "782a13e9" "ldclrh w10, w9, [sp]"

  /// C6.2.118 LDCLRH, LDCLRAH, LDCLRALH, LDCLRLH
  [<TestMethod>]
  member _.``C6.2.118 LDCLRLH``() =
    testDisasm "78621020" "ldclrlh w2, w0, [x1]"
    testDisasm "7862103f" "stclrlh w2, [x1]"
    testDisasm "787f13ff" "stclrlh wzr, [sp]"
    testDisasm "786a13e9" "ldclrlh w10, w9, [sp]"

  /// C6.2.119 LDCLR, LDCLRA, LDCLRAL, LDCLRL
  [<TestMethod>]
  member _.``C6.2.119 LDCLR``() =
    testDisasm "f8221020" "ldclr x2, x0, [x1]"
    testDisasm "f822103f" "stclr x2, [x1]"
    testDisasm "b8221020" "ldclr w2, w0, [x1]"
    testDisasm "b822103f" "stclr w2, [x1]"

  /// C6.2.119 LDCLR, LDCLRA, LDCLRAL, LDCLRL
  [<TestMethod>]
  member _.``C6.2.119 LDCLRA``() =
    testDisasm "b8a21020" "ldclra w2, w0, [x1]"
    testDisasm "b8bf13ff" "ldclra wzr, wzr, [sp]"
    testDisasm "b8aa13e9" "ldclra w10, w9, [sp]"
    testDisasm "b8bf13c0" "ldclra wzr, w0, [x30]"

  /// C6.2.119 LDCLR, LDCLRA, LDCLRAL, LDCLRL
  [<TestMethod>]
  member _.``C6.2.119 LDCLRAL``() =
    testDisasm "b8e21020" "ldclral w2, w0, [x1]"
    testDisasm "b8ff13ff" "ldclral wzr, wzr, [sp]"
    testDisasm "b8ea13e9" "ldclral w10, w9, [sp]"
    testDisasm "b8ff13c0" "ldclral wzr, w0, [x30]"

  /// C6.2.119 LDCLR, LDCLRA, LDCLRAL, LDCLRL
  [<TestMethod>]
  member _.``C6.2.119 LDCLRL``() =
    testDisasm "b8621020" "ldclrl w2, w0, [x1]"
    testDisasm "b862103f" "stclrl w2, [x1]"
    testDisasm "b87f13ff" "stclrl wzr, [sp]"
    testDisasm "b86a13e9" "ldclrl w10, w9, [sp]"

  /// C6.2.12 AND (immediate)
  [<TestMethod>]
  member _.``C6.2.12 AND``() =
    testDisasm "9200f020" "and x0, x1, #0x5555555555555555"
    testDisasm "121c0020" "and w0, w1, #0x10"
    testDisasm "0a020020" "and w0, w1, w2"
    testDisasm "8a020020" "and x0, x1, x2"

  /// C6.2.120 LDEORB, LDEORAB, LDEORALB, LDEORLB
  [<TestMethod>]
  member _.``C6.2.120 LDEORAB``() =
    testDisasm "38a22020" "ldeorab w2, w0, [x1]"
    testDisasm "38bf23ff" "ldeorab wzr, wzr, [sp]"
    testDisasm "38aa23e9" "ldeorab w10, w9, [sp]"
    testDisasm "38bf23c0" "ldeorab wzr, w0, [x30]"

  /// C6.2.120 LDEORB, LDEORAB, LDEORALB, LDEORLB
  [<TestMethod>]
  member _.``C6.2.120 LDEORALB``() =
    testDisasm "38e22020" "ldeoralb w2, w0, [x1]"
    testDisasm "38ff23ff" "ldeoralb wzr, wzr, [sp]"
    testDisasm "38ea23e9" "ldeoralb w10, w9, [sp]"
    testDisasm "38ff23c0" "ldeoralb wzr, w0, [x30]"

  /// C6.2.120 LDEORB, LDEORAB, LDEORALB, LDEORLB
  [<TestMethod>]
  member _.``C6.2.120 LDEORB``() =
    testDisasm "38222020" "ldeorb w2, w0, [x1]"
    testDisasm "3822203f" "steorb w2, [x1]"
    testDisasm "383f23ff" "steorb wzr, [sp]"
    testDisasm "382a23e9" "ldeorb w10, w9, [sp]"

  /// C6.2.120 LDEORB, LDEORAB, LDEORALB, LDEORLB
  [<TestMethod>]
  member _.``C6.2.120 LDEORLB``() =
    testDisasm "38622020" "ldeorlb w2, w0, [x1]"
    testDisasm "3862203f" "steorlb w2, [x1]"
    testDisasm "387f23ff" "steorlb wzr, [sp]"
    testDisasm "386a23e9" "ldeorlb w10, w9, [sp]"

  /// C6.2.121 LDEORH, LDEORAH, LDEORALH, LDEORLH
  [<TestMethod>]
  member _.``C6.2.121 LDEORAH``() =
    testDisasm "78a22020" "ldeorah w2, w0, [x1]"
    testDisasm "78bf23ff" "ldeorah wzr, wzr, [sp]"
    testDisasm "78aa23e9" "ldeorah w10, w9, [sp]"
    testDisasm "78bf23c0" "ldeorah wzr, w0, [x30]"

  /// C6.2.121 LDEORH, LDEORAH, LDEORALH, LDEORLH
  [<TestMethod>]
  member _.``C6.2.121 LDEORALH``() =
    testDisasm "78e22020" "ldeoralh w2, w0, [x1]"
    testDisasm "78ff23ff" "ldeoralh wzr, wzr, [sp]"
    testDisasm "78ea23e9" "ldeoralh w10, w9, [sp]"
    testDisasm "78ff23c0" "ldeoralh wzr, w0, [x30]"

  /// C6.2.121 LDEORH, LDEORAH, LDEORALH, LDEORLH
  [<TestMethod>]
  member _.``C6.2.121 LDEORH``() =
    testDisasm "78222020" "ldeorh w2, w0, [x1]"
    testDisasm "7822203f" "steorh w2, [x1]"
    testDisasm "783f23ff" "steorh wzr, [sp]"
    testDisasm "782a23e9" "ldeorh w10, w9, [sp]"

  /// C6.2.121 LDEORH, LDEORAH, LDEORALH, LDEORLH
  [<TestMethod>]
  member _.``C6.2.121 LDEORLH``() =
    testDisasm "78622020" "ldeorlh w2, w0, [x1]"
    testDisasm "7862203f" "steorlh w2, [x1]"
    testDisasm "787f23ff" "steorlh wzr, [sp]"
    testDisasm "786a23e9" "ldeorlh w10, w9, [sp]"

  /// C6.2.122 LDEOR, LDEORA, LDEORAL, LDEORL
  [<TestMethod>]
  member _.``C6.2.122 LDEOR``() =
    testDisasm "f8222020" "ldeor x2, x0, [x1]"
    testDisasm "f822203f" "steor x2, [x1]"
    testDisasm "b8222020" "ldeor w2, w0, [x1]"
    testDisasm "b822203f" "steor w2, [x1]"

  /// C6.2.122 LDEOR, LDEORA, LDEORAL, LDEORL
  [<TestMethod>]
  member _.``C6.2.122 LDEORA``() =
    testDisasm "b8a22020" "ldeora w2, w0, [x1]"
    testDisasm "b8bf23ff" "ldeora wzr, wzr, [sp]"
    testDisasm "b8aa23e9" "ldeora w10, w9, [sp]"
    testDisasm "b8bf23c0" "ldeora wzr, w0, [x30]"

  /// C6.2.122 LDEOR, LDEORA, LDEORAL, LDEORL
  [<TestMethod>]
  member _.``C6.2.122 LDEORAL``() =
    testDisasm "b8e22020" "ldeoral w2, w0, [x1]"
    testDisasm "b8ff23ff" "ldeoral wzr, wzr, [sp]"
    testDisasm "b8ea23e9" "ldeoral w10, w9, [sp]"
    testDisasm "b8ff23c0" "ldeoral wzr, w0, [x30]"

  /// C6.2.122 LDEOR, LDEORA, LDEORAL, LDEORL
  [<TestMethod>]
  member _.``C6.2.122 LDEORL``() =
    testDisasm "b8622020" "ldeorl w2, w0, [x1]"
    testDisasm "b862203f" "steorl w2, [x1]"
    testDisasm "b87f23ff" "steorl wzr, [sp]"
    testDisasm "b86a23e9" "ldeorl w10, w9, [sp]"

  /// C6.2.123 LDG
  [<TestMethod>]
  member _.``C6.2.123 LDG``() =
    testDisasm "d9600020" "ldg x0, [x1]"
    testDisasm "d9601020" "ldg x0, [x1, #0x10]"
    testDisasm "d97f03ff" "ldg xzr, [sp, #0xffffffffffffff00]"
    testDisasm "d96a03e9" "ldg x9, [sp, #0xa00]"

  /// C6.2.124 LDGM
  [<TestMethod>]
  member _.``C6.2.124 LDGM``() =
    testDisasm "d9e00020" "ldgm x0, [x1]"

  /// C6.2.125 LDLARB
  [<TestMethod>]
  member _.``C6.2.125 LDLARB``() =
    testDisasm "08df7c20" "ldlarb w0, [x1]"
    testDisasm "08df03ff" "ldlarb wzr, [sp]"
    testDisasm "08ca03e9" "ldlarb w9, [sp]"
    testDisasm "08c1005f" "ldlarb wzr, [x2]"

  /// C6.2.126 LDLARH
  [<TestMethod>]
  member _.``C6.2.126 LDLARH``() =
    testDisasm "48df7c20" "ldlarh w0, [x1]"
    testDisasm "48df03ff" "ldlarh wzr, [sp]"
    testDisasm "48ca03e9" "ldlarh w9, [sp]"
    testDisasm "48c1005f" "ldlarh wzr, [x2]"

  /// C6.2.127 LDLAR
  [<TestMethod>]
  member _.``C6.2.127 LDLAR``() =
    testDisasm "c8df7c20" "ldlar x0, [x1]"
    testDisasm "88df7c20" "ldlar w0, [x1]"
    testDisasm "88df03ff" "ldlar wzr, [sp]"
    testDisasm "88ca03e9" "ldlar w9, [sp]"

  /// C6.2.128 LDNP
  [<TestMethod>]
  member _.``C6.2.128 LDNP``() =
    testDisasm "28400c22" "ldnp w2, w3, [x1]"
    testDisasm "28420c22" "ldnp w2, w3, [x1, #0x10]"
    testDisasm "a8400c22" "ldnp x2, x3, [x1]"
    testDisasm "a8410c22" "ldnp x2, x3, [x1, #0x10]"

  /// C6.2.129 LDP
  [<TestMethod>]
  member _.``C6.2.129 LDP``() =
    testDisasm "28c20c22" "ldp w2, w3, [x1], #0x10"
    testDisasm "a8c10c22" "ldp x2, x3, [x1], #0x10"
    testDisasm "29c20c22" "ldp w2, w3, [x1, #0x10]!"
    testDisasm "a9c10c22" "ldp x2, x3, [x1, #0x10]!"

  /// C6.2.130 LDPSW
  [<TestMethod>]
  member _.``C6.2.130 LDPSW``() =
    testDisasm "68c20c22" "ldpsw x2, x3, [x1], #0x10"
    testDisasm "69c20c22" "ldpsw x2, x3, [x1, #0x10]!"
    testDisasm "69400c22" "ldpsw x2, x3, [x1]"
    testDisasm "69420c22" "ldpsw x2, x3, [x1, #0x10]"

  /// C6.2.131 LDR (immediate)
  [<TestMethod>]
  member _.``C6.2.131 LDR``() =
    testDisasm "b8410420" "ldr w0, [x1], #0x10"
    testDisasm "f8410420" "ldr x0, [x1], #0x10"
    testDisasm "b8410c20" "ldr w0, [x1, #0x10]!"
    testDisasm "f8410c20" "ldr x0, [x1, #0x10]!"

  /// C6.2.134 LDRAA, LDRAB
  [<TestMethod>]
  member _.``C6.2.134 LDRAA``() =
    testDisasm "f8200420" "ldraa x0, [x1]"
    testDisasm "f8202420" "ldraa x0, [x1, #0x10]"
    testDisasm "f8200c20" "ldraa x0, [x1]!"
    testDisasm "f8202c20" "ldraa x0, [x1, #0x10]!"

  /// C6.2.134 LDRAA, LDRAB
  [<TestMethod>]
  member _.``C6.2.134 LDRAB``() =
    testDisasm "f8a00420" "ldrab x0, [x1]"
    testDisasm "f8a10443" "ldrab x3, [x2, #0x80]"
    testDisasm "f8bf07ff" "ldrab xzr, [sp, #0xf80]"
    testDisasm "f8aa07e9" "ldrab x9, [sp, #0x500]"

  /// C6.2.135 LDRB (immediate)
  [<TestMethod>]
  member _.``C6.2.135 LDRB``() =
    testDisasm "38410420" "ldrb w0, [x1], #0x10"
    testDisasm "38410c20" "ldrb w0, [x1, #0x10]!"
    testDisasm "39400020" "ldrb w0, [x1]"
    testDisasm "39402020" "ldrb w0, [x1, #0x8]"

  /// C6.2.137 LDRH (immediate)
  [<TestMethod>]
  member _.``C6.2.137 LDRH``() =
    testDisasm "78410420" "ldrh w0, [x1], #0x10"
    testDisasm "78410c20" "ldrh w0, [x1, #0x10]!"
    testDisasm "79400020" "ldrh w0, [x1]"
    testDisasm "79401020" "ldrh w0, [x1, #0x8]"

  /// C6.2.139 LDRSB (immediate)
  [<TestMethod>]
  member _.``C6.2.139 LDRSB``() =
    testDisasm "38c10420" "ldrsb w0, [x1], #0x10"
    testDisasm "38810420" "ldrsb x0, [x1], #0x10"
    testDisasm "38c10c20" "ldrsb w0, [x1, #0x10]!"
    testDisasm "38810c20" "ldrsb x0, [x1, #0x10]!"

  /// C6.2.14 ANDS (immediate)
  [<TestMethod>]
  member _.``C6.2.14 ANDS``() =
    testDisasm "f2089c20" "ands x0, x1, #0xff00ff00ff00ff00"
    testDisasm "f240783f" "tst x1, #0x7fffffff"
    testDisasm "721c0020" "ands w0, w1, #0x10"
    testDisasm "6a020020" "ands w0, w1, w2"

  /// C6.2.141 LDRSH (immediate)
  [<TestMethod>]
  member _.``C6.2.141 LDRSH``() =
    testDisasm "78c10420" "ldrsh w0, [x1], #0x10"
    testDisasm "78810420" "ldrsh x0, [x1], #0x10"
    testDisasm "78c10c20" "ldrsh w0, [x1, #0x10]!"
    testDisasm "78810c20" "ldrsh x0, [x1, #0x10]!"

  /// C6.2.143 LDRSW (immediate)
  [<TestMethod>]
  member _.``C6.2.143 LDRSW``() =
    testDisasm "b8810420" "ldrsw x0, [x1], #0x10"
    testDisasm "b8810c20" "ldrsw x0, [x1, #0x10]!"
    testDisasm "b9800020" "ldrsw x0, [x1]"
    testDisasm "b9800820" "ldrsw x0, [x1, #0x8]"

  /// C6.2.146 LDSETB, LDSETAB, LDSETALB, LDSETLB
  [<TestMethod>]
  member _.``C6.2.146 LDSETAB``() =
    testDisasm "38a23020" "ldsetab w2, w0, [x1]"
    testDisasm "38bf33ff" "ldsetab wzr, wzr, [sp]"
    testDisasm "38aa33e9" "ldsetab w10, w9, [sp]"
    testDisasm "38bf33c0" "ldsetab wzr, w0, [x30]"

  /// C6.2.146 LDSETB, LDSETAB, LDSETALB, LDSETLB
  [<TestMethod>]
  member _.``C6.2.146 LDSETALB``() =
    testDisasm "38e23020" "ldsetalb w2, w0, [x1]"
    testDisasm "38ff33ff" "ldsetalb wzr, wzr, [sp]"
    testDisasm "38ea33e9" "ldsetalb w10, w9, [sp]"
    testDisasm "38ff33c0" "ldsetalb wzr, w0, [x30]"

  /// C6.2.146 LDSETB, LDSETAB, LDSETALB, LDSETLB
  [<TestMethod>]
  member _.``C6.2.146 LDSETB``() =
    testDisasm "38223020" "ldsetb w2, w0, [x1]"
    testDisasm "3822303f" "stsetb w2, [x1]"
    testDisasm "383f33ff" "stsetb wzr, [sp]"
    testDisasm "382a33e9" "ldsetb w10, w9, [sp]"

  /// C6.2.146 LDSETB, LDSETAB, LDSETALB, LDSETLB
  [<TestMethod>]
  member _.``C6.2.146 LDSETLB``() =
    testDisasm "38623020" "ldsetlb w2, w0, [x1]"
    testDisasm "3862303f" "stsetlb w2, [x1]"
    testDisasm "387f33ff" "stsetlb wzr, [sp]"
    testDisasm "386a33e9" "ldsetlb w10, w9, [sp]"

  /// C6.2.147 LDSETH, LDSETAH, LDSETALH, LDSETLH
  [<TestMethod>]
  member _.``C6.2.147 LDSETAH``() =
    testDisasm "78a23020" "ldsetah w2, w0, [x1]"
    testDisasm "78bf33ff" "ldsetah wzr, wzr, [sp]"
    testDisasm "78aa33e9" "ldsetah w10, w9, [sp]"
    testDisasm "78bf33c0" "ldsetah wzr, w0, [x30]"

  /// C6.2.147 LDSETH, LDSETAH, LDSETALH, LDSETLH
  [<TestMethod>]
  member _.``C6.2.147 LDSETALH``() =
    testDisasm "78e23020" "ldsetalh w2, w0, [x1]"
    testDisasm "78ff33ff" "ldsetalh wzr, wzr, [sp]"
    testDisasm "78ea33e9" "ldsetalh w10, w9, [sp]"
    testDisasm "78ff33c0" "ldsetalh wzr, w0, [x30]"

  /// C6.2.147 LDSETH, LDSETAH, LDSETALH, LDSETLH
  [<TestMethod>]
  member _.``C6.2.147 LDSETH``() =
    testDisasm "78223020" "ldseth w2, w0, [x1]"
    testDisasm "7822303f" "stseth w2, [x1]"
    testDisasm "783f33ff" "stseth wzr, [sp]"
    testDisasm "782a33e9" "ldseth w10, w9, [sp]"

  /// C6.2.147 LDSETH, LDSETAH, LDSETALH, LDSETLH
  [<TestMethod>]
  member _.``C6.2.147 LDSETLH``() =
    testDisasm "78623020" "ldsetlh w2, w0, [x1]"
    testDisasm "7862303f" "stsetlh w2, [x1]"
    testDisasm "787f33ff" "stsetlh wzr, [sp]"
    testDisasm "786a33e9" "ldsetlh w10, w9, [sp]"

  /// C6.2.148 LDSET, LDSETA, LDSETAL, LDSETL
  [<TestMethod>]
  member _.``C6.2.148 LDSET``() =
    testDisasm "f8223020" "ldset x2, x0, [x1]"
    testDisasm "f822303f" "stset x2, [x1]"
    testDisasm "b8223020" "ldset w2, w0, [x1]"
    testDisasm "b822303f" "stset w2, [x1]"

  /// C6.2.148 LDSET, LDSETA, LDSETAL, LDSETL
  [<TestMethod>]
  member _.``C6.2.148 LDSETA``() =
    testDisasm "b8a23020" "ldseta w2, w0, [x1]"
    testDisasm "b8bf33ff" "ldseta wzr, wzr, [sp]"
    testDisasm "b8aa33e9" "ldseta w10, w9, [sp]"
    testDisasm "b8bf33c0" "ldseta wzr, w0, [x30]"

  /// C6.2.148 LDSET, LDSETA, LDSETAL, LDSETL
  [<TestMethod>]
  member _.``C6.2.148 LDSETAL``() =
    testDisasm "b8e23020" "ldsetal w2, w0, [x1]"
    testDisasm "b8ff33ff" "ldsetal wzr, wzr, [sp]"
    testDisasm "b8ea33e9" "ldsetal w10, w9, [sp]"
    testDisasm "b8ff33c0" "ldsetal wzr, w0, [x30]"

  /// C6.2.148 LDSET, LDSETA, LDSETAL, LDSETL
  [<TestMethod>]
  member _.``C6.2.148 LDSETL``() =
    testDisasm "b8623020" "ldsetl w2, w0, [x1]"
    testDisasm "b862303f" "stsetl w2, [x1]"
    testDisasm "b87f33ff" "stsetl wzr, [sp]"
    testDisasm "b86a33e9" "ldsetl w10, w9, [sp]"

  /// C6.2.149 LDSMAXB, LDSMAXAB, LDSMAXALB, LDSMAXLB
  [<TestMethod>]
  member _.``C6.2.149 LDSMAXAB``() =
    testDisasm "38a24020" "ldsmaxab w2, w0, [x1]"
    testDisasm "38bf43ff" "ldsmaxab wzr, wzr, [sp]"
    testDisasm "38aa43e9" "ldsmaxab w10, w9, [sp]"
    testDisasm "38bf43c0" "ldsmaxab wzr, w0, [x30]"

  /// C6.2.149 LDSMAXB, LDSMAXAB, LDSMAXALB, LDSMAXLB
  [<TestMethod>]
  member _.``C6.2.149 LDSMAXALB``() =
    testDisasm "38e24020" "ldsmaxalb w2, w0, [x1]"
    testDisasm "38ff43ff" "ldsmaxalb wzr, wzr, [sp]"
    testDisasm "38ea43e9" "ldsmaxalb w10, w9, [sp]"
    testDisasm "38ff43c0" "ldsmaxalb wzr, w0, [x30]"

  /// C6.2.149 LDSMAXB, LDSMAXAB, LDSMAXALB, LDSMAXLB
  [<TestMethod>]
  member _.``C6.2.149 LDSMAXB``() =
    testDisasm "38224020" "ldsmaxb w2, w0, [x1]"
    testDisasm "3822403f" "stsmaxb w2, [x1]"
    testDisasm "383f43ff" "stsmaxb wzr, [sp]"
    testDisasm "382a43e9" "ldsmaxb w10, w9, [sp]"

  /// C6.2.149 LDSMAXB, LDSMAXAB, LDSMAXALB, LDSMAXLB
  [<TestMethod>]
  member _.``C6.2.149 LDSMAXLB``() =
    testDisasm "38624020" "ldsmaxlb w2, w0, [x1]"
    testDisasm "3862403f" "stsmaxlb w2, [x1]"
    testDisasm "387f43ff" "stsmaxlb wzr, [sp]"
    testDisasm "386a43e9" "ldsmaxlb w10, w9, [sp]"

  /// C6.2.150 LDSMAXH, LDSMAXAH, LDSMAXALH, LDSMAXLH
  [<TestMethod>]
  member _.``C6.2.150 LDSMAXAH``() =
    testDisasm "78a24020" "ldsmaxah w2, w0, [x1]"
    testDisasm "78bf43ff" "ldsmaxah wzr, wzr, [sp]"
    testDisasm "78aa43e9" "ldsmaxah w10, w9, [sp]"
    testDisasm "78bf43c0" "ldsmaxah wzr, w0, [x30]"

  /// C6.2.150 LDSMAXH, LDSMAXAH, LDSMAXALH, LDSMAXLH
  [<TestMethod>]
  member _.``C6.2.150 LDSMAXALH``() =
    testDisasm "78e24020" "ldsmaxalh w2, w0, [x1]"
    testDisasm "78ff43ff" "ldsmaxalh wzr, wzr, [sp]"
    testDisasm "78ea43e9" "ldsmaxalh w10, w9, [sp]"
    testDisasm "78ff43c0" "ldsmaxalh wzr, w0, [x30]"

  /// C6.2.150 LDSMAXH, LDSMAXAH, LDSMAXALH, LDSMAXLH
  [<TestMethod>]
  member _.``C6.2.150 LDSMAXH``() =
    testDisasm "78224020" "ldsmaxh w2, w0, [x1]"
    testDisasm "7822403f" "stsmaxh w2, [x1]"
    testDisasm "783f43ff" "stsmaxh wzr, [sp]"
    testDisasm "782a43e9" "ldsmaxh w10, w9, [sp]"

  /// C6.2.150 LDSMAXH, LDSMAXAH, LDSMAXALH, LDSMAXLH
  [<TestMethod>]
  member _.``C6.2.150 LDSMAXLH``() =
    testDisasm "78624020" "ldsmaxlh w2, w0, [x1]"
    testDisasm "7862403f" "stsmaxlh w2, [x1]"
    testDisasm "787f43ff" "stsmaxlh wzr, [sp]"
    testDisasm "786a43e9" "ldsmaxlh w10, w9, [sp]"

  /// C6.2.151 LDSMAX, LDSMAXA, LDSMAXAL, LDSMAXL
  [<TestMethod>]
  member _.``C6.2.151 LDSMAX``() =
    testDisasm "f8224020" "ldsmax x2, x0, [x1]"
    testDisasm "f822403f" "stsmax x2, [x1]"
    testDisasm "b8224020" "ldsmax w2, w0, [x1]"
    testDisasm "b822403f" "stsmax w2, [x1]"

  /// C6.2.151 LDSMAX, LDSMAXA, LDSMAXAL, LDSMAXL
  [<TestMethod>]
  member _.``C6.2.151 LDSMAXA``() =
    testDisasm "b8a24020" "ldsmaxa w2, w0, [x1]"
    testDisasm "b8bf43ff" "ldsmaxa wzr, wzr, [sp]"
    testDisasm "b8aa43e9" "ldsmaxa w10, w9, [sp]"
    testDisasm "b8bf43c0" "ldsmaxa wzr, w0, [x30]"

  /// C6.2.151 LDSMAX, LDSMAXA, LDSMAXAL, LDSMAXL
  [<TestMethod>]
  member _.``C6.2.151 LDSMAXAL``() =
    testDisasm "b8e24020" "ldsmaxal w2, w0, [x1]"
    testDisasm "b8ff43ff" "ldsmaxal wzr, wzr, [sp]"
    testDisasm "b8ea43e9" "ldsmaxal w10, w9, [sp]"
    testDisasm "b8ff43c0" "ldsmaxal wzr, w0, [x30]"

  /// C6.2.151 LDSMAX, LDSMAXA, LDSMAXAL, LDSMAXL
  [<TestMethod>]
  member _.``C6.2.151 LDSMAXL``() =
    testDisasm "b8624020" "ldsmaxl w2, w0, [x1]"
    testDisasm "b862403f" "stsmaxl w2, [x1]"
    testDisasm "b87f43ff" "stsmaxl wzr, [sp]"
    testDisasm "b86a43e9" "ldsmaxl w10, w9, [sp]"

  /// C6.2.152 LDSMINB, LDSMINAB, LDSMINALB, LDSMINLB
  [<TestMethod>]
  member _.``C6.2.152 LDSMINAB``() =
    testDisasm "38a25020" "ldsminab w2, w0, [x1]"
    testDisasm "38bf53ff" "ldsminab wzr, wzr, [sp]"
    testDisasm "38aa53e9" "ldsminab w10, w9, [sp]"
    testDisasm "38bf53c0" "ldsminab wzr, w0, [x30]"

  /// C6.2.152 LDSMINB, LDSMINAB, LDSMINALB, LDSMINLB
  [<TestMethod>]
  member _.``C6.2.152 LDSMINALB``() =
    testDisasm "38e25020" "ldsminalb w2, w0, [x1]"
    testDisasm "38ff53ff" "ldsminalb wzr, wzr, [sp]"
    testDisasm "38ea53e9" "ldsminalb w10, w9, [sp]"
    testDisasm "38ff53c0" "ldsminalb wzr, w0, [x30]"

  /// C6.2.152 LDSMINB, LDSMINAB, LDSMINALB, LDSMINLB
  [<TestMethod>]
  member _.``C6.2.152 LDSMINB``() =
    testDisasm "38225020" "ldsminb w2, w0, [x1]"
    testDisasm "3822503f" "stsminb w2, [x1]"
    testDisasm "383f53ff" "stsminb wzr, [sp]"
    testDisasm "382a53e9" "ldsminb w10, w9, [sp]"

  /// C6.2.152 LDSMINB, LDSMINAB, LDSMINALB, LDSMINLB
  [<TestMethod>]
  member _.``C6.2.152 LDSMINLB``() =
    testDisasm "38625020" "ldsminlb w2, w0, [x1]"
    testDisasm "3862503f" "stsminlb w2, [x1]"
    testDisasm "387f53ff" "stsminlb wzr, [sp]"
    testDisasm "386a53e9" "ldsminlb w10, w9, [sp]"

  /// C6.2.153 LDSMINH, LDSMINAH, LDSMINALH, LDSMINLH
  [<TestMethod>]
  member _.``C6.2.153 LDSMINAH``() =
    testDisasm "78a25020" "ldsminah w2, w0, [x1]"
    testDisasm "78bf53ff" "ldsminah wzr, wzr, [sp]"
    testDisasm "78aa53e9" "ldsminah w10, w9, [sp]"
    testDisasm "78bf53c0" "ldsminah wzr, w0, [x30]"

  /// C6.2.153 LDSMINH, LDSMINAH, LDSMINALH, LDSMINLH
  [<TestMethod>]
  member _.``C6.2.153 LDSMINALH``() =
    testDisasm "78e25020" "ldsminalh w2, w0, [x1]"
    testDisasm "78ff53ff" "ldsminalh wzr, wzr, [sp]"
    testDisasm "78ea53e9" "ldsminalh w10, w9, [sp]"
    testDisasm "78ff53c0" "ldsminalh wzr, w0, [x30]"

  /// C6.2.153 LDSMINH, LDSMINAH, LDSMINALH, LDSMINLH
  [<TestMethod>]
  member _.``C6.2.153 LDSMINH``() =
    testDisasm "78225020" "ldsminh w2, w0, [x1]"
    testDisasm "7822503f" "stsminh w2, [x1]"
    testDisasm "783f53ff" "stsminh wzr, [sp]"
    testDisasm "782a53e9" "ldsminh w10, w9, [sp]"

  /// C6.2.153 LDSMINH, LDSMINAH, LDSMINALH, LDSMINLH
  [<TestMethod>]
  member _.``C6.2.153 LDSMINLH``() =
    testDisasm "78625020" "ldsminlh w2, w0, [x1]"
    testDisasm "7862503f" "stsminlh w2, [x1]"
    testDisasm "787f53ff" "stsminlh wzr, [sp]"
    testDisasm "786a53e9" "ldsminlh w10, w9, [sp]"

  /// C6.2.154 LDSMIN, LDSMINA, LDSMINAL, LDSMINL
  [<TestMethod>]
  member _.``C6.2.154 LDSMIN``() =
    testDisasm "f8225020" "ldsmin x2, x0, [x1]"
    testDisasm "f822503f" "stsmin x2, [x1]"
    testDisasm "b8225020" "ldsmin w2, w0, [x1]"
    testDisasm "b822503f" "stsmin w2, [x1]"

  /// C6.2.154 LDSMIN, LDSMINA, LDSMINAL, LDSMINL
  [<TestMethod>]
  member _.``C6.2.154 LDSMINA``() =
    testDisasm "b8a25020" "ldsmina w2, w0, [x1]"
    testDisasm "b8bf53ff" "ldsmina wzr, wzr, [sp]"
    testDisasm "b8aa53e9" "ldsmina w10, w9, [sp]"
    testDisasm "b8bf53c0" "ldsmina wzr, w0, [x30]"

  /// C6.2.154 LDSMIN, LDSMINA, LDSMINAL, LDSMINL
  [<TestMethod>]
  member _.``C6.2.154 LDSMINAL``() =
    testDisasm "b8e25020" "ldsminal w2, w0, [x1]"
    testDisasm "b8ff53ff" "ldsminal wzr, wzr, [sp]"
    testDisasm "b8ea53e9" "ldsminal w10, w9, [sp]"
    testDisasm "b8ff53c0" "ldsminal wzr, w0, [x30]"

  /// C6.2.154 LDSMIN, LDSMINA, LDSMINAL, LDSMINL
  [<TestMethod>]
  member _.``C6.2.154 LDSMINL``() =
    testDisasm "b8625020" "ldsminl w2, w0, [x1]"
    testDisasm "b862503f" "stsminl w2, [x1]"
    testDisasm "b87f53ff" "stsminl wzr, [sp]"
    testDisasm "b86a53e9" "ldsminl w10, w9, [sp]"

  /// C6.2.155 LDTR
  [<TestMethod>]
  member _.``C6.2.155 LDTR``() =
    testDisasm "b8410820" "ldtr w0, [x1, #0x10]"
    testDisasm "f8400820" "ldtr x0, [x1]"
    testDisasm "f8410820" "ldtr x0, [x1, #0x10]"
    testDisasm "b8400820" "ldtr w0, [x1]"

  /// C6.2.156 LDTRB
  [<TestMethod>]
  member _.``C6.2.156 LDTRB``() =
    testDisasm "38410820" "ldtrb w0, [x1, #0x10]"
    testDisasm "38400820" "ldtrb w0, [x1]"
    testDisasm "385f0bff" "ldtrb wzr, [sp, #0xfffffffffffffff0]"
    testDisasm "384a0be9" "ldtrb w9, [sp, #0xa0]"

  /// C6.2.157 LDTRH
  [<TestMethod>]
  member _.``C6.2.157 LDTRH``() =
    testDisasm "78410820" "ldtrh w0, [x1, #0x10]"
    testDisasm "78400820" "ldtrh w0, [x1]"
    testDisasm "785f0bff" "ldtrh wzr, [sp, #0xfffffffffffffff0]"
    testDisasm "784a0be9" "ldtrh w9, [sp, #0xa0]"

  /// C6.2.158 LDTRSB
  [<TestMethod>]
  member _.``C6.2.158 LDTRSB``() =
    testDisasm "38c10820" "ldtrsb w0, [x1, #0x10]"
    testDisasm "38800820" "ldtrsb x0, [x1]"
    testDisasm "38810820" "ldtrsb x0, [x1, #0x10]"
    testDisasm "38c00820" "ldtrsb w0, [x1]"

  /// C6.2.159 LDTRSH
  [<TestMethod>]
  member _.``C6.2.159 LDTRSH``() =
    testDisasm "78c10820" "ldtrsh w0, [x1, #0x10]"
    testDisasm "78800820" "ldtrsh x0, [x1]"
    testDisasm "78810820" "ldtrsh x0, [x1, #0x10]"
    testDisasm "78c00820" "ldtrsh w0, [x1]"

  /// C6.2.16 ASR (register)
  [<TestMethod>]
  member _.``C6.2.16 ASR``() =
    testDisasm "1ac22820" "asr w0, w1, w2"
    testDisasm "13017c20" "asr w0, w1, #0x1"
    testDisasm "9341fc20" "asr x0, x1, #0x1"
    testDisasm "9ac22820" "asr x0, x1, x2"

  /// C6.2.160 LDTRSW
  [<TestMethod>]
  member _.``C6.2.160 LDTRSW``() =
    testDisasm "b8810820" "ldtrsw x0, [x1, #0x10]"
    testDisasm "b8800820" "ldtrsw x0, [x1]"
    testDisasm "b89f0bff" "ldtrsw xzr, [sp, #0xfffffffffffffff0]"
    testDisasm "b88a0be9" "ldtrsw x9, [sp, #0xa0]"

  /// C6.2.161 LDUMAXB, LDUMAXAB, LDUMAXALB, LDUMAXLB
  [<TestMethod>]
  member _.``C6.2.161 LDUMAXAB``() =
    testDisasm "38a26020" "ldumaxab w2, w0, [x1]"
    testDisasm "38bf63ff" "ldumaxab wzr, wzr, [sp]"
    testDisasm "38aa63e9" "ldumaxab w10, w9, [sp]"
    testDisasm "38bf63c0" "ldumaxab wzr, w0, [x30]"

  /// C6.2.161 LDUMAXB, LDUMAXAB, LDUMAXALB, LDUMAXLB
  [<TestMethod>]
  member _.``C6.2.161 LDUMAXALB``() =
    testDisasm "38e26020" "ldumaxalb w2, w0, [x1]"
    testDisasm "38ff63ff" "ldumaxalb wzr, wzr, [sp]"
    testDisasm "38ea63e9" "ldumaxalb w10, w9, [sp]"
    testDisasm "38ff63c0" "ldumaxalb wzr, w0, [x30]"

  /// C6.2.161 LDUMAXB, LDUMAXAB, LDUMAXALB, LDUMAXLB
  [<TestMethod>]
  member _.``C6.2.161 LDUMAXB``() =
    testDisasm "38226020" "ldumaxb w2, w0, [x1]"
    testDisasm "3822603f" "stumaxb w2, [x1]"
    testDisasm "383f63ff" "stumaxb wzr, [sp]"
    testDisasm "382a63e9" "ldumaxb w10, w9, [sp]"

  /// C6.2.161 LDUMAXB, LDUMAXAB, LDUMAXALB, LDUMAXLB
  [<TestMethod>]
  member _.``C6.2.161 LDUMAXLB``() =
    testDisasm "38626020" "ldumaxlb w2, w0, [x1]"
    testDisasm "3862603f" "stumaxlb w2, [x1]"
    testDisasm "387f63ff" "stumaxlb wzr, [sp]"
    testDisasm "386a63e9" "ldumaxlb w10, w9, [sp]"

  /// C6.2.162 LDUMAXH, LDUMAXAH, LDUMAXALH, LDUMAXLH
  [<TestMethod>]
  member _.``C6.2.162 LDUMAXAH``() =
    testDisasm "78a26020" "ldumaxah w2, w0, [x1]"
    testDisasm "78bf63ff" "ldumaxah wzr, wzr, [sp]"
    testDisasm "78aa63e9" "ldumaxah w10, w9, [sp]"
    testDisasm "78bf63c0" "ldumaxah wzr, w0, [x30]"

  /// C6.2.162 LDUMAXH, LDUMAXAH, LDUMAXALH, LDUMAXLH
  [<TestMethod>]
  member _.``C6.2.162 LDUMAXALH``() =
    testDisasm "78e26020" "ldumaxalh w2, w0, [x1]"
    testDisasm "78ff63ff" "ldumaxalh wzr, wzr, [sp]"
    testDisasm "78ea63e9" "ldumaxalh w10, w9, [sp]"
    testDisasm "78ff63c0" "ldumaxalh wzr, w0, [x30]"

  /// C6.2.162 LDUMAXH, LDUMAXAH, LDUMAXALH, LDUMAXLH
  [<TestMethod>]
  member _.``C6.2.162 LDUMAXH``() =
    testDisasm "78226020" "ldumaxh w2, w0, [x1]"
    testDisasm "7822603f" "stumaxh w2, [x1]"
    testDisasm "783f63ff" "stumaxh wzr, [sp]"
    testDisasm "782a63e9" "ldumaxh w10, w9, [sp]"

  /// C6.2.162 LDUMAXH, LDUMAXAH, LDUMAXALH, LDUMAXLH
  [<TestMethod>]
  member _.``C6.2.162 LDUMAXLH``() =
    testDisasm "78626020" "ldumaxlh w2, w0, [x1]"
    testDisasm "7862603f" "stumaxlh w2, [x1]"
    testDisasm "787f63ff" "stumaxlh wzr, [sp]"
    testDisasm "786a63e9" "ldumaxlh w10, w9, [sp]"

  /// C6.2.163 LDUMAX, LDUMAXA, LDUMAXAL, LDUMAXL
  [<TestMethod>]
  member _.``C6.2.163 LDUMAX``() =
    testDisasm "f8226020" "ldumax x2, x0, [x1]"
    testDisasm "f822603f" "stumax x2, [x1]"
    testDisasm "b8226020" "ldumax w2, w0, [x1]"
    testDisasm "b822603f" "stumax w2, [x1]"

  /// C6.2.163 LDUMAX, LDUMAXA, LDUMAXAL, LDUMAXL
  [<TestMethod>]
  member _.``C6.2.163 LDUMAXA``() =
    testDisasm "b8a26020" "ldumaxa w2, w0, [x1]"
    testDisasm "b8bf63ff" "ldumaxa wzr, wzr, [sp]"
    testDisasm "b8aa63e9" "ldumaxa w10, w9, [sp]"
    testDisasm "b8bf63c0" "ldumaxa wzr, w0, [x30]"

  /// C6.2.163 LDUMAX, LDUMAXA, LDUMAXAL, LDUMAXL
  [<TestMethod>]
  member _.``C6.2.163 LDUMAXAL``() =
    testDisasm "b8e26020" "ldumaxal w2, w0, [x1]"
    testDisasm "b8ff63ff" "ldumaxal wzr, wzr, [sp]"
    testDisasm "b8ea63e9" "ldumaxal w10, w9, [sp]"
    testDisasm "b8ff63c0" "ldumaxal wzr, w0, [x30]"

  /// C6.2.163 LDUMAX, LDUMAXA, LDUMAXAL, LDUMAXL
  [<TestMethod>]
  member _.``C6.2.163 LDUMAXL``() =
    testDisasm "b8626020" "ldumaxl w2, w0, [x1]"
    testDisasm "b862603f" "stumaxl w2, [x1]"
    testDisasm "b87f63ff" "stumaxl wzr, [sp]"
    testDisasm "b86a63e9" "ldumaxl w10, w9, [sp]"

  /// C6.2.164 LDUMINB, LDUMINAB, LDUMINALB, LDUMINLB
  [<TestMethod>]
  member _.``C6.2.164 LDUMINAB``() =
    testDisasm "38a27020" "lduminab w2, w0, [x1]"
    testDisasm "38bf73ff" "lduminab wzr, wzr, [sp]"
    testDisasm "38aa73e9" "lduminab w10, w9, [sp]"
    testDisasm "38bf73c0" "lduminab wzr, w0, [x30]"

  /// C6.2.164 LDUMINB, LDUMINAB, LDUMINALB, LDUMINLB
  [<TestMethod>]
  member _.``C6.2.164 LDUMINALB``() =
    testDisasm "38e27020" "lduminalb w2, w0, [x1]"
    testDisasm "38ff73ff" "lduminalb wzr, wzr, [sp]"
    testDisasm "38ea73e9" "lduminalb w10, w9, [sp]"
    testDisasm "38ff73c0" "lduminalb wzr, w0, [x30]"

  /// C6.2.164 LDUMINB, LDUMINAB, LDUMINALB, LDUMINLB
  [<TestMethod>]
  member _.``C6.2.164 LDUMINB``() =
    testDisasm "38227020" "lduminb w2, w0, [x1]"
    testDisasm "3822703f" "stuminb w2, [x1]"
    testDisasm "383f73ff" "stuminb wzr, [sp]"
    testDisasm "382a73e9" "lduminb w10, w9, [sp]"

  /// C6.2.164 LDUMINB, LDUMINAB, LDUMINALB, LDUMINLB
  [<TestMethod>]
  member _.``C6.2.164 LDUMINLB``() =
    testDisasm "38627020" "lduminlb w2, w0, [x1]"
    testDisasm "3862703f" "stuminlb w2, [x1]"
    testDisasm "387f73ff" "stuminlb wzr, [sp]"
    testDisasm "386a73e9" "lduminlb w10, w9, [sp]"

  /// C6.2.165 LDUMINH, LDUMINAH, LDUMINALH, LDUMINLH
  [<TestMethod>]
  member _.``C6.2.165 LDUMINAH``() =
    testDisasm "78a27020" "lduminah w2, w0, [x1]"
    testDisasm "78bf73ff" "lduminah wzr, wzr, [sp]"
    testDisasm "78aa73e9" "lduminah w10, w9, [sp]"
    testDisasm "78bf73c0" "lduminah wzr, w0, [x30]"

  /// C6.2.165 LDUMINH, LDUMINAH, LDUMINALH, LDUMINLH
  [<TestMethod>]
  member _.``C6.2.165 LDUMINALH``() =
    testDisasm "78e27020" "lduminalh w2, w0, [x1]"
    testDisasm "78ff73ff" "lduminalh wzr, wzr, [sp]"
    testDisasm "78ea73e9" "lduminalh w10, w9, [sp]"
    testDisasm "78ff73c0" "lduminalh wzr, w0, [x30]"

  /// C6.2.165 LDUMINH, LDUMINAH, LDUMINALH, LDUMINLH
  [<TestMethod>]
  member _.``C6.2.165 LDUMINH``() =
    testDisasm "78227020" "lduminh w2, w0, [x1]"
    testDisasm "7822703f" "stuminh w2, [x1]"
    testDisasm "783f73ff" "stuminh wzr, [sp]"
    testDisasm "782a73e9" "lduminh w10, w9, [sp]"

  /// C6.2.165 LDUMINH, LDUMINAH, LDUMINALH, LDUMINLH
  [<TestMethod>]
  member _.``C6.2.165 LDUMINLH``() =
    testDisasm "78627020" "lduminlh w2, w0, [x1]"
    testDisasm "7862703f" "stuminlh w2, [x1]"
    testDisasm "787f73ff" "stuminlh wzr, [sp]"
    testDisasm "786a73e9" "lduminlh w10, w9, [sp]"

  /// C6.2.166 LDUMIN, LDUMINA, LDUMINAL, LDUMINL
  [<TestMethod>]
  member _.``C6.2.166 LDUMIN``() =
    testDisasm "f8227020" "ldumin x2, x0, [x1]"
    testDisasm "f822703f" "stumin x2, [x1]"
    testDisasm "b8227020" "ldumin w2, w0, [x1]"
    testDisasm "b822703f" "stumin w2, [x1]"

  /// C6.2.166 LDUMIN, LDUMINA, LDUMINAL, LDUMINL
  [<TestMethod>]
  member _.``C6.2.166 LDUMINA``() =
    testDisasm "b8a27020" "ldumina w2, w0, [x1]"
    testDisasm "b8bf73ff" "ldumina wzr, wzr, [sp]"
    testDisasm "b8aa73e9" "ldumina w10, w9, [sp]"
    testDisasm "b8bf73c0" "ldumina wzr, w0, [x30]"

  /// C6.2.166 LDUMIN, LDUMINA, LDUMINAL, LDUMINL
  [<TestMethod>]
  member _.``C6.2.166 LDUMINAL``() =
    testDisasm "b8e27020" "lduminal w2, w0, [x1]"
    testDisasm "b8ff73ff" "lduminal wzr, wzr, [sp]"
    testDisasm "b8ea73e9" "lduminal w10, w9, [sp]"
    testDisasm "b8ff73c0" "lduminal wzr, w0, [x30]"

  /// C6.2.166 LDUMIN, LDUMINA, LDUMINAL, LDUMINL
  [<TestMethod>]
  member _.``C6.2.166 LDUMINL``() =
    testDisasm "b8627020" "lduminl w2, w0, [x1]"
    testDisasm "b862703f" "stuminl w2, [x1]"
    testDisasm "b87f73ff" "stuminl wzr, [sp]"
    testDisasm "b86a73e9" "lduminl w10, w9, [sp]"

  /// C6.2.167 LDUR
  [<TestMethod>]
  member _.``C6.2.167 LDUR``() =
    testDisasm "b8410020" "ldur w0, [x1, #0x10]"
    testDisasm "f8400020" "ldur x0, [x1]"
    testDisasm "f8410020" "ldur x0, [x1, #0x10]"
    testDisasm "b8400020" "ldur w0, [x1]"

  /// C6.2.168 LDURB
  [<TestMethod>]
  member _.``C6.2.168 LDURB``() =
    testDisasm "38410020" "ldurb w0, [x1, #0x10]"
    testDisasm "38400020" "ldurb w0, [x1]"
    testDisasm "385f03ff" "ldurb wzr, [sp, #0xfffffffffffffff0]"
    testDisasm "384a03e9" "ldurb w9, [sp, #0xa0]"

  /// C6.2.169 LDURH
  [<TestMethod>]
  member _.``C6.2.169 LDURH``() =
    testDisasm "78410020" "ldurh w0, [x1, #0x10]"
    testDisasm "78400020" "ldurh w0, [x1]"
    testDisasm "785f03ff" "ldurh wzr, [sp, #0xfffffffffffffff0]"
    testDisasm "784a03e9" "ldurh w9, [sp, #0xa0]"

  /// C6.2.170 LDURSB
  [<TestMethod>]
  member _.``C6.2.170 LDURSB``() =
    testDisasm "38c10020" "ldursb w0, [x1, #0x10]"
    testDisasm "38800020" "ldursb x0, [x1]"
    testDisasm "38810020" "ldursb x0, [x1, #0x10]"
    testDisasm "38c00020" "ldursb w0, [x1]"

  /// C6.2.171 LDURSH
  [<TestMethod>]
  member _.``C6.2.171 LDURSH``() =
    testDisasm "78c10020" "ldursh w0, [x1, #0x10]"
    testDisasm "78800020" "ldursh x0, [x1]"
    testDisasm "78810020" "ldursh x0, [x1, #0x10]"
    testDisasm "78c00020" "ldursh w0, [x1]"

  /// C6.2.172 LDURSW
  [<TestMethod>]
  member _.``C6.2.172 LDURSW``() =
    testDisasm "b8810020" "ldursw x0, [x1, #0x10]"
    testDisasm "b8800020" "ldursw x0, [x1]"
    testDisasm "b89f03ff" "ldursw xzr, [sp, #0xfffffffffffffff0]"
    testDisasm "b88a03e9" "ldursw x9, [sp, #0xa0]"

  /// C6.2.173 LDXP
  [<TestMethod>]
  member _.``C6.2.173 LDXP``() =
    testDisasm "887f0022" "ldxp w2, w0, [x1]"
    testDisasm "887f03ff" "ldxp wzr, w0, [sp]"
    testDisasm "886a03e9" "ldxp w9, w0, [sp]"
    testDisasm "88617c43" "ldxp w3, wzr, [x2]"

  /// C6.2.174 LDXR
  [<TestMethod>]
  member _.``C6.2.174 LDXR``() =
    testDisasm "885f7c20" "ldxr w0, [x1]"
    testDisasm "885f03ff" "ldxr wzr, [sp]"
    testDisasm "884a03e9" "ldxr w9, [sp]"
    testDisasm "c8410043" "ldxr x3, [x2]"

  /// C6.2.175 LDXRB
  [<TestMethod>]
  member _.``C6.2.175 LDXRB``() =
    testDisasm "085f7c20" "ldxrb w0, [x1]"
    testDisasm "085f03ff" "ldxrb wzr, [sp]"
    testDisasm "084a03e9" "ldxrb w9, [sp]"
    testDisasm "0841005f" "ldxrb wzr, [x2]"

  /// C6.2.176 LDXRH
  [<TestMethod>]
  member _.``C6.2.176 LDXRH``() =
    testDisasm "485f7c20" "ldxrh w0, [x1]"
    testDisasm "485f03ff" "ldxrh wzr, [sp]"
    testDisasm "484a03e9" "ldxrh w9, [sp]"
    testDisasm "4841005f" "ldxrh wzr, [x2]"

  /// C6.2.177 LSL (register)
  [<TestMethod>]
  member _.``C6.2.177 LSL``() =
    testDisasm "1ac22020" "lsl w0, w1, w2"
    testDisasm "531f7820" "lsl w0, w1, #0x1"
    testDisasm "d37ff820" "lsl x0, x1, #0x1"
    testDisasm "9ac22020" "lsl x0, x1, x2"

  /// C6.2.179 LSLV
  [<TestMethod>]
  member _.``C6.2.179 LSLV``() =
    testDisasm "1ac22020" "lsl w0, w1, w2"
    testDisasm "9ac22020" "lsl x0, x1, x2"
    testDisasm "1adf23ff" "lsl wzr, wzr, wzr"
    testDisasm "1aca23e9" "lsl w9, wzr, w10"

  /// C6.2.18 ASRV
  [<TestMethod>]
  member _.``C6.2.18 ASRV``() =
    testDisasm "1ac22820" "asr w0, w1, w2"
    testDisasm "9ac22820" "asr x0, x1, x2"
    testDisasm "1adf2bff" "asr wzr, wzr, wzr"
    testDisasm "1aca2be9" "asr w9, wzr, w10"

  /// C6.2.180 LSR (register)
  [<TestMethod>]
  member _.``C6.2.180 LSR``() =
    testDisasm "1ac22420" "lsr w0, w1, w2"
    testDisasm "53017c20" "lsr w0, w1, #0x1"
    testDisasm "d341fc20" "lsr x0, x1, #0x1"
    testDisasm "9ac22420" "lsr x0, x1, x2"

  /// C6.2.182 LSRV
  [<TestMethod>]
  member _.``C6.2.182 LSRV``() =
    testDisasm "1ac22420" "lsr w0, w1, w2"
    testDisasm "9ac22420" "lsr x0, x1, x2"
    testDisasm "1adf27ff" "lsr wzr, wzr, wzr"
    testDisasm "1aca27e9" "lsr w9, wzr, w10"

  /// C6.2.183 MADD
  [<TestMethod>]
  member _.``C6.2.183 MADD``() =
    testDisasm "1b020c20" "madd w0, w1, w2, w3"
    testDisasm "1b027c20" "mul w0, w1, w2"
    testDisasm "9b020c20" "madd x0, x1, x2, x3"
    testDisasm "9b027c20" "mul x0, x1, x2"

  /// C6.2.184 MNEG
  [<TestMethod>]
  member _.``C6.2.184 MNEG``() =
    testDisasm "1b02fc20" "mneg w0, w1, w2"
    testDisasm "9b02fc20" "mneg x0, x1, x2"
    testDisasm "1b1fffff" "mneg wzr, wzr, wzr"
    testDisasm "1b0affe9" "mneg w9, wzr, w10"

  /// C6.2.185 MOV (to/from SP)
  [<TestMethod>]
  member _.``C6.2.185 MOV``() =
    testDisasm "2a0103e0" "mov w0, w1"
    testDisasm "52800200" "mov w0, #0x10"
    testDisasm "d2800200" "mov x0, #0x10"
    testDisasm "aa0203e0" "mov x0, x2"

  /// C6.2.19 AT
  [<TestMethod>]
  member _.``C6.2.19 AT``() =
    testDisasm "d5087800" "at s1e1r, x0"
    testDisasm "d508781f" "at s1e1r, xzr"
    testDisasm "d5087820" "at s1e1w, x0"
    testDisasm "d508783f" "at s1e1w, xzr"

  /// C6.2.190 MOVK
  [<TestMethod>]
  member _.``C6.2.190 MOVK``() =
    testDisasm "72800200" "movk w0, #0x10"
    testDisasm "f2800200" "movk x0, #0x10"
    testDisasm "729f03ff" "movk wzr, #0xf81f"
    testDisasm "72a10043" "movk w3, #0x802, lsl #0x10"

  /// C6.2.191 MOVN
  [<TestMethod>]
  member _.``C6.2.191 MOVN``() =
    testDisasm "12800200" "mov w0, #0xffffffef"
    testDisasm "92800200" "mov x0, #0xffffffffffffffef"
    testDisasm "129f03ff" "mov wzr, #0xffff07e0"
    testDisasm "129fffff" "movn wzr, #0xffff"

  /// C6.2.192 MOVZ
  [<TestMethod>]
  member _.``C6.2.192 MOVZ``() =
    testDisasm "52800200" "mov w0, #0x10"
    testDisasm "d2800200" "mov x0, #0x10"
    testDisasm "52a00000" "movz w0, #0x0, lsl #0x10"
    testDisasm "d2a00000" "movz x0, #0x0, lsl #0x10"

  /// C6.2.193 MRS
  [<TestMethod>]
  member _.``C6.2.193 MRS``() =
    testDisasm "d53402b6" "mrs x22, s2_4_c0_c2_5"
    testDisasm "d53f03ff" "mrs xzr, s3_7_c0_c3_7"
    testDisasm "d5380000" "mrs x0, midr_el1"
    testDisasm "d538001f" "mrs xzr, midr_el1"

  /// C6.2.194 MSR (immediate)
  [<TestMethod>]
  member _.``C6.2.194 MSR``() =
    testDisasm "d51402b6" "msr s2_4_c0_c2_5, x22"
    testDisasm "d51f03ff" "msr s3_7_c0_c3_7, xzr"
    testDisasm "d500407f" "msr uao, #0x0"
    testDisasm "d500409f" "msr pan, #0x0"

  /// C6.2.196 MSUB
  [<TestMethod>]
  member _.``C6.2.196 MSUB``() =
    testDisasm "1b02fc20" "mneg w0, w1, w2"
    testDisasm "1b028c20" "msub w0, w1, w2, w3"
    testDisasm "9b02fc20" "mneg x0, x1, x2"
    testDisasm "9b028c20" "msub x0, x1, x2, x3"

  /// C6.2.197 MUL
  [<TestMethod>]
  member _.``C6.2.197 MUL``() =
    testDisasm "1b027c20" "mul w0, w1, w2"
    testDisasm "0f528020" "mul v0.4h, v1.4h, v2.h[1]"
    testDisasm "0fa28020" "mul v0.2s, v1.2s, v2.s[1]"
    testDisasm "0e229c20" "mul v0.8b, v1.8b, v2.8b"

  /// C6.2.198 MVN
  [<TestMethod>]
  member _.``C6.2.198 MVN``() =
    testDisasm "6e205820" "mvn v0.16b, v1.16b"
    testDisasm "2a2203e0" "mvn w0, w2"
    testDisasm "aa2203e0" "mvn x0, x2"
    testDisasm "2a3f03ff" "mvn wzr, wzr"

  /// C6.2.199 NEG (shifted register)
  [<TestMethod>]
  member _.``C6.2.199 NEG``() =
    testDisasm "4b0203e0" "neg w0, w2"
    testDisasm "2e20b820" "neg v0.8b, v1.8b"
    testDisasm "2e60b820" "neg v0.4h, v1.4h"
    testDisasm "2ea0b820" "neg v0.2s, v1.2s"

  /// C6.2.2 ADCS
  [<TestMethod>]
  member _.``C6.2.2 ADCS``() =
    testDisasm "3a020020" "adcs w0, w1, w2"
    testDisasm "ba020020" "adcs x0, x1, x2"
    testDisasm "3a1f03ff" "adcs wzr, wzr, wzr"
    testDisasm "3a0a03e9" "adcs w9, wzr, w10"

  /// C6.2.20 AUTDA, AUTDZA
  [<TestMethod>]
  member _.``C6.2.20 AUTDA``() =
    testDisasm "dac11820" "autda x0, x1"

  /// C6.2.20 AUTDA, AUTDZA
  [<TestMethod>]
  member _.``C6.2.20 AUTDZA``() =
    testDisasm "dac13be0" "autdza x0"

  /// C6.2.200 NEGS
  [<TestMethod>]
  member _.``C6.2.200 NEGS``() =
    testDisasm "6b0203e0" "negs w0, w2"
    testDisasm "eb0203e0" "negs x0, x2"
    testDisasm "6b1f03e0" "negs w0, wzr"
    testDisasm "6b0a07e9" "negs w9, w10, lsl #0x1"

  /// C6.2.201 NGC
  [<TestMethod>]
  member _.``C6.2.201 NGC``() =
    testDisasm "5a0203e0" "ngc w0, w2"
    testDisasm "da0203e0" "ngc x0, x2"
    testDisasm "5a1f03ff" "ngc wzr, wzr"
    testDisasm "5a1f03e0" "ngc w0, wzr"

  /// C6.2.202 NGCS
  [<TestMethod>]
  member _.``C6.2.202 NGCS``() =
    testDisasm "7a0203e0" "ngcs w0, w2"
    testDisasm "fa0203e0" "ngcs x0, x2"
    testDisasm "7a1f03ff" "ngcs wzr, wzr"
    testDisasm "7a1f03e0" "ngcs w0, wzr"

  /// C6.2.203 NOP
  [<TestMethod>]
  member _.``C6.2.203 NOP``() =
    testDisasm "d503201f" "nop"

  /// C6.2.204 ORN (shifted register)
  [<TestMethod>]
  member _.``C6.2.204 ORN``() =
    testDisasm "2a2203e0" "mvn w0, w2"
    testDisasm "2a220020" "orn w0, w1, w2"
    testDisasm "0ee21c20" "orn v0.8b, v1.8b, v2.8b"
    testDisasm "aa2203e0" "mvn x0, x2"

  /// C6.2.205 ORR (immediate)
  [<TestMethod>]
  member _.``C6.2.205 ORR``() =
    testDisasm "b2410420" "orr x0, x1, #0x8000000000000001"
    testDisasm "2a0103e0" "mov w0, w1"
    testDisasm "aa0203e0" "mov x0, x2"
    testDisasm "321c0020" "orr w0, w1, #0x10"

  /// C6.2.207 PACDA, PACDZA
  [<TestMethod>]
  member _.``C6.2.207 PACDA``() =
    testDisasm "dac10820" "pacda x0, x1"

  /// C6.2.207 PACDA, PACDZA
  [<TestMethod>]
  member _.``C6.2.207 PACDZA``() =
    testDisasm "dac12be0" "pacdza x0"

  /// C6.2.208 PACDB, PACDZB
  [<TestMethod>]
  member _.``C6.2.208 PACDB``() =
    testDisasm "dac10c20" "pacdb x0, x1"

  /// C6.2.208 PACDB, PACDZB
  [<TestMethod>]
  member _.``C6.2.208 PACDZB``() =
    testDisasm "dac12fe0" "pacdzb x0"

  /// C6.2.209 PACGA
  [<TestMethod>]
  member _.``C6.2.209 PACGA``() =
    testDisasm "9ac23020" "pacga x0, x1, x2"
    testDisasm "9adf33ff" "pacga xzr, xzr, sp"
    testDisasm "9aca33e9" "pacga x9, xzr, x10"
    testDisasm "9adf33c0" "pacga x0, x30, sp"

  /// C6.2.21 AUTDB, AUTDZB
  [<TestMethod>]
  member _.``C6.2.21 AUTDB``() =
    testDisasm "dac11c20" "autdb x0, x1"

  /// C6.2.21 AUTDB, AUTDZB
  [<TestMethod>]
  member _.``C6.2.21 AUTDZB``() =
    testDisasm "dac13fe0" "autdzb x0"

  /// C6.2.210 PACIA, PACIA1716, PACIASP, PACIAZ, PACIZA
  [<TestMethod>]
  member _.``C6.2.210 PACIA``() =
    testDisasm "dac10020" "pacia x0, x1"
    testDisasm "dac103e3" "pacia x3, sp"
    testDisasm "dac1005f" "pacia xzr, x2"

  /// C6.2.210 PACIA, PACIA1716, PACIASP, PACIAZ, PACIZA
  [<TestMethod>]
  member _.``C6.2.210 PACIA1716``() =
    testDisasm "d503211f" "pacia1716"

  /// C6.2.210 PACIA, PACIA1716, PACIASP, PACIAZ, PACIZA
  [<TestMethod>]
  member _.``C6.2.210 PACIASP``() =
    testDisasm "d503233f" "paciasp"

  /// C6.2.210 PACIA, PACIA1716, PACIASP, PACIAZ, PACIZA
  [<TestMethod>]
  member _.``C6.2.210 PACIAZ``() =
    testDisasm "d503231f" "paciaz"

  /// C6.2.210 PACIA, PACIA1716, PACIASP, PACIAZ, PACIZA
  [<TestMethod>]
  member _.``C6.2.210 PACIZA``() =
    testDisasm "dac123e0" "paciza x0"

  /// C6.2.211 PACIB, PACIB1716, PACIBSP, PACIBZ, PACIZB
  [<TestMethod>]
  member _.``C6.2.211 PACIB``() =
    testDisasm "dac10420" "pacib x0, x1"

  /// C6.2.211 PACIB, PACIB1716, PACIBSP, PACIBZ, PACIZB
  [<TestMethod>]
  member _.``C6.2.211 PACIB1716``() =
    testDisasm "d503215f" "pacib1716"

  /// C6.2.211 PACIB, PACIB1716, PACIBSP, PACIBZ, PACIZB
  [<TestMethod>]
  member _.``C6.2.211 PACIBSP``() =
    testDisasm "d503237f" "pacibsp"

  /// C6.2.211 PACIB, PACIB1716, PACIBSP, PACIBZ, PACIZB
  [<TestMethod>]
  member _.``C6.2.211 PACIBZ``() =
    testDisasm "d503235f" "pacibz"

  /// C6.2.211 PACIB, PACIB1716, PACIBSP, PACIBZ, PACIZB
  [<TestMethod>]
  member _.``C6.2.211 PACIZB``() =
    testDisasm "dac127e0" "pacizb x0"

  /// C6.2.212 PRFM (immediate)
  [<TestMethod>]
  member _.``C6.2.212 PRFM``() =
    testDisasm "f9800020" "prfm pldl1keep, [x1]"
    testDisasm "d8010043" "prfm pldl2strm, 0x2008"
    testDisasm "d81f03ff" "prfm #0x1f, 0x3e07c"
    testDisasm "d80003c0" "prfm pldl1keep, 0x78"

  /// C6.2.215 PRFUM
  [<TestMethod>]
  member _.``C6.2.215 PRFUM``() =
    testDisasm "f8800020" "prfum pldl1keep, [x1]"
    testDisasm "f8810043" "prfum pldl2strm, [x2, #0x10]"
    testDisasm "f89f03ff" "prfum #0x1f, [sp, #0xfffffffffffffff0]"
    testDisasm "f88a03e9" "prfum plil1strm, [sp, #0xa0]"

  /// C6.2.216 PSB CSYNC
  [<TestMethod>]
  member _.``C6.2.216 PSB``() =
    testDisasm "d503223f" "psb csync"

  /// C6.2.217 PSSBB
  [<TestMethod>]
  member _.``C6.2.217 PSSBB``() =
    testDisasm "d503349f" "pssbb"

  /// C6.2.218 RBIT
  [<TestMethod>]
  member _.``C6.2.218 RBIT``() =
    testDisasm "5ac00020" "rbit w0, w1"
    testDisasm "2e605820" "rbit v0.8b, v1.8b"
    testDisasm "dac00020" "rbit x0, x1"

  /// C6.2.219 RET
  [<TestMethod>]
  member _.``C6.2.219 RET``() =
    testDisasm "d65f03c0" "ret"
    testDisasm "d65f03e0" "ret xzr"

  /// C6.2.22 AUTIA, AUTIA1716, AUTIASP, AUTIAZ, AUTIZA
  [<TestMethod>]
  member _.``C6.2.22 AUTIA``() =
    testDisasm "dac11020" "autia x0, x1"

  /// C6.2.22 AUTIA, AUTIA1716, AUTIASP, AUTIAZ, AUTIZA
  [<TestMethod>]
  member _.``C6.2.22 AUTIA1716``() =
    testDisasm "d503219f" "autia1716"

  /// C6.2.22 AUTIA, AUTIA1716, AUTIASP, AUTIAZ, AUTIZA
  [<TestMethod>]
  member _.``C6.2.22 AUTIASP``() =
    testDisasm "d50323bf" "autiasp"

  /// C6.2.22 AUTIA, AUTIA1716, AUTIASP, AUTIAZ, AUTIZA
  [<TestMethod>]
  member _.``C6.2.22 AUTIAZ``() =
    testDisasm "d503239f" "autiaz"

  /// C6.2.22 AUTIA, AUTIA1716, AUTIASP, AUTIAZ, AUTIZA
  [<TestMethod>]
  member _.``C6.2.22 AUTIZA``() =
    testDisasm "dac133e0" "autiza x0"

  /// C6.2.220 RETAA, RETAB
  [<TestMethod>]
  member _.``C6.2.220 RETAA``() =
    testDisasm "d65f0bff" "retaa"

  /// C6.2.220 RETAA, RETAB
  [<TestMethod>]
  member _.``C6.2.220 RETAB``() =
    testDisasm "d65f0fff" "retab"

  /// C6.2.221 REV
  [<TestMethod>]
  member _.``C6.2.221 REV``() =
    testDisasm "5ac00820" "rev w0, w1"
    testDisasm "dac00c20" "rev x0, x1"

  /// C6.2.222 REV16
  [<TestMethod>]
  member _.``C6.2.222 REV16``() =
    testDisasm "5ac00420" "rev16 w0, w1"
    testDisasm "0e201820" "rev16 v0.8b, v1.8b"
    testDisasm "dac00420" "rev16 x0, x1"

  /// C6.2.223 REV32
  [<TestMethod>]
  member _.``C6.2.223 REV32``() =
    testDisasm "2e200820" "rev32 v0.8b, v1.8b"
    testDisasm "2e600820" "rev32 v0.4h, v1.4h"
    testDisasm "dac00820" "rev32 x0, x1"

  /// C6.2.224 REV64
  [<TestMethod>]
  member _.``C6.2.224 REV64``() =
    testDisasm "0e200820" "rev64 v0.8b, v1.8b"
    testDisasm "0e600820" "rev64 v0.4h, v1.4h"
    testDisasm "0ea00820" "rev64 v0.2s, v1.2s"

  /// C6.2.225 RMIF
  [<TestMethod>]
  member _.``C6.2.225 RMIF``() =
    testDisasm "ba03840f" "rmif x0, #0x7, #0xf"
    testDisasm "ba0a07e9" "rmif xzr, #0x14, #0x9"

  /// C6.2.226 ROR (immediate)
  [<TestMethod>]
  member _.``C6.2.226 ROR``() =
    testDisasm "13820440" "ror w0, w2, #1"
    testDisasm "93c20440" "ror x0, x2, #1"
    testDisasm "1ac22c20" "rorv w0, w1, w2"
    testDisasm "9ac22c20" "rorv x0, x1, x2"

  /// C6.2.228 RORV
  [<TestMethod>]
  member _.``C6.2.228 RORV``() =
    testDisasm "1ac22c20" "rorv w0, w1, w2"
    testDisasm "9ac22c20" "rorv x0, x1, x2"
    testDisasm "1adf2fff" "rorv wzr, wzr, wzr"
    testDisasm "1aca2fe9" "rorv w9, wzr, w10"

  /// C6.2.229 SB
  [<TestMethod>]
  member _.``C6.2.229 SB``() =
    testDisasm "d50330ff" "sb"

  /// C6.2.23 AUTIB, AUTIB1716, AUTIBSP, AUTIBZ, AUTIZB
  [<TestMethod>]
  member _.``C6.2.23 AUTIB``() =
    testDisasm "dac11420" "autib x0, x1"

  /// C6.2.23 AUTIB, AUTIB1716, AUTIBSP, AUTIBZ, AUTIZB
  [<TestMethod>]
  member _.``C6.2.23 AUTIB1716``() =
    testDisasm "d50321df" "autib1716"

  /// C6.2.23 AUTIB, AUTIB1716, AUTIBSP, AUTIBZ, AUTIZB
  [<TestMethod>]
  member _.``C6.2.23 AUTIBSP``() =
    testDisasm "d50323ff" "autibsp"

  /// C6.2.23 AUTIB, AUTIB1716, AUTIBSP, AUTIBZ, AUTIZB
  [<TestMethod>]
  member _.``C6.2.23 AUTIBZ``() =
    testDisasm "d50323df" "autibz"

  /// C6.2.23 AUTIB, AUTIB1716, AUTIBSP, AUTIBZ, AUTIZB
  [<TestMethod>]
  member _.``C6.2.23 AUTIZB``() =
    testDisasm "dac137e0" "autizb x0"

  /// C6.2.230 SBC
  [<TestMethod>]
  member _.``C6.2.230 SBC``() =
    testDisasm "5a0203e0" "ngc w0, w2"
    testDisasm "5a020020" "sbc w0, w1, w2"
    testDisasm "da0203e0" "ngc x0, x2"
    testDisasm "da020020" "sbc x0, x1, x2"

  /// C6.2.231 SBCS
  [<TestMethod>]
  member _.``C6.2.231 SBCS``() =
    testDisasm "7a0203e0" "ngcs w0, w2"
    testDisasm "7a020020" "sbcs w0, w1, w2"
    testDisasm "fa0203e0" "ngcs x0, x2"
    testDisasm "fa020020" "sbcs x0, x1, x2"

  /// C6.2.232 SBFIZ
  [<TestMethod>]
  member _.``C6.2.232 SBFIZ``() =
    testDisasm "131d1020" "sbfiz w0, w1, #0x3, #0x5"
    testDisasm "937d1020" "sbfiz x0, x1, #0x3, #0x5"
    testDisasm "131f03ff" "sbfiz wzr, wzr, #0x1, #0x1"
    testDisasm "130a03e9" "sbfiz w9, wzr, #0x16, #0x1"

  /// C6.2.233 SBFM
  [<TestMethod>]
  member _.``C6.2.233 SBFM``() =
    testDisasm "13017c20" "asr w0, w1, #0x1"
    testDisasm "9341fc20" "asr x0, x1, #0x1"
    testDisasm "131d1020" "sbfiz w0, w1, #0x3, #0x5"
    testDisasm "937d1020" "sbfiz x0, x1, #0x3, #0x5"

  /// C6.2.234 SBFX
  [<TestMethod>]
  member _.``C6.2.234 SBFX``() =
    testDisasm "13031420" "sbfx w0, w1, #0x3, #0x3"
    testDisasm "93431420" "sbfx x0, x1, #0x3, #0x3"
    testDisasm "130a2be9" "sbfx w9, wzr, #0xa, #0x1"
    testDisasm "934a2be9" "sbfx x9, xzr, #0xa, #0x1"

  /// C6.2.235 SDIV
  [<TestMethod>]
  member _.``C6.2.235 SDIV``() =
    testDisasm "1ac20c20" "sdiv w0, w1, w2"
    testDisasm "9ac20c20" "sdiv x0, x1, x2"
    testDisasm "1adf0fff" "sdiv wzr, wzr, wzr"
    testDisasm "1aca0fe9" "sdiv w9, wzr, w10"

  /// C6.2.236 SETF8, SETF16
  [<TestMethod>]
  member _.``C6.2.236 SETF16``() =
    testDisasm "3a00480d" "setf16 w0"

  /// C6.2.236 SETF8, SETF16
  [<TestMethod>]
  member _.``C6.2.236 SETF8``() =
    testDisasm "3a00080d" "setf8 w0"

  /// C6.2.237 SEV
  [<TestMethod>]
  member _.``C6.2.237 SEV``() =
    testDisasm "d503209f" "sev"

  /// C6.2.238 SEVL
  [<TestMethod>]
  member _.``C6.2.238 SEVL``() =
    testDisasm "d50320bf" "sevl"

  /// C6.2.239 SMADDL
  [<TestMethod>]
  member _.``C6.2.239 SMADDL``() =
    testDisasm "9b220c20" "smaddl x0, w1, w2, x3"
    testDisasm "9b227c20" "smull x0, w1, w2"
    testDisasm "9b3f03ff" "smaddl xzr, wzr, wzr, x0"
    testDisasm "9b2a03e9" "smaddl x9, wzr, w10, x0"

  /// C6.2.24 AXFLAG
  [<TestMethod>]
  member _.``C6.2.24 AXFLAG``() =
    testDisasm "d500405f" "axflag"

  /// C6.2.240 SMC
  [<TestMethod>]
  member _.``C6.2.240 SMC``() =
    testDisasm "d4010043" "smc #0x802"

  /// C6.2.241 SMNEGL
  [<TestMethod>]
  member _.``C6.2.241 SMNEGL``() =
    testDisasm "9b22fc20" "smnegl x0, w1, w2"
    testDisasm "9b3fffff" "smnegl xzr, wzr, wzr"
    testDisasm "9b2affe9" "smnegl x9, wzr, w10"
    testDisasm "9b3fffc0" "smnegl x0, w30, wzr"

  /// C6.2.242 SMSUBL
  [<TestMethod>]
  member _.``C6.2.242 SMSUBL``() =
    testDisasm "9b22fc20" "smnegl x0, w1, w2"
    testDisasm "9b228c20" "smsubl x0, w1, w2, x3"
    testDisasm "9b3f83ff" "smsubl xzr, wzr, wzr, x0"
    testDisasm "9b2a83e9" "smsubl x9, wzr, w10, x0"

  /// C6.2.243 SMULH
  [<TestMethod>]
  member _.``C6.2.243 SMULH``() =
    testDisasm "9b427c20" "smulh x0, x1, x2"
    testDisasm "9b5f03ff" "smulh xzr, xzr, xzr"
    testDisasm "9b4a03e9" "smulh x9, xzr, x10"
    testDisasm "9b5f03c0" "smulh x0, x30, xzr"

  /// C6.2.244 SMULL
  [<TestMethod>]
  member _.``C6.2.244 SMULL``() =
    testDisasm "0f52a020" "smull v0.4s, v1.4h, v2.h[1]"
    testDisasm "0fa2a020" "smull v0.2d, v1.2s, v2.s[1]"
    testDisasm "0e22c020" "smull v0.8h, v1.8b, v2.8b"
    testDisasm "0e62c020" "smull v0.4s, v1.4h, v2.4h"

  /// C6.2.245 SSBB
  [<TestMethod>]
  member _.``C6.2.245 SSBB``() =
    testDisasm "d503309f" "ssbb"

  /// C6.2.246 ST2G
  [<TestMethod>]
  member _.``C6.2.246 ST2G``() =
    testDisasm "d9a00820" "st2g x0, [x1]"
    testDisasm "d9a01420" "st2g x0, [x1], #0x10"
    testDisasm "d9a01c20" "st2g x0, [x1, #0x10]!"
    testDisasm "d9a01820" "st2g x0, [x1, #0x10]"

  /// C6.2.247 STADDB, STADDLB
  [<TestMethod>]
  member _.``C6.2.247 STADDB``() =
    testDisasm "3822003f" "staddb w2, [x1]"
    testDisasm "383f03ff" "staddb wzr, [sp]"

  /// C6.2.247 STADDB, STADDLB
  [<TestMethod>]
  member _.``C6.2.247 STADDLB``() =
    testDisasm "3862003f" "staddlb w2, [x1]"
    testDisasm "387f03ff" "staddlb wzr, [sp]"

  /// C6.2.248 STADDH, STADDLH
  [<TestMethod>]
  member _.``C6.2.248 STADDH``() =
    testDisasm "7822003f" "staddh w2, [x1]"
    testDisasm "783f03ff" "staddh wzr, [sp]"

  /// C6.2.248 STADDH, STADDLH
  [<TestMethod>]
  member _.``C6.2.248 STADDLH``() =
    testDisasm "7862003f" "staddlh w2, [x1]"
    testDisasm "787f03ff" "staddlh wzr, [sp]"

  /// C6.2.249 STADD, STADDL
  [<TestMethod>]
  member _.``C6.2.249 STADD``() =
    testDisasm "f822003f" "stadd x2, [x1]"
    testDisasm "b822003f" "stadd w2, [x1]"
    testDisasm "b83f03ff" "stadd wzr, [sp]"
    testDisasm "f83f03ff" "stadd xzr, [sp]"

  /// C6.2.249 STADD, STADDL
  [<TestMethod>]
  member _.``C6.2.249 STADDL``() =
    testDisasm "b862003f" "staddl w2, [x1]"
    testDisasm "b87f03ff" "staddl wzr, [sp]"
    testDisasm "f87f03ff" "staddl xzr, [sp]"
    testDisasm "f861005f" "staddl x1, [x2]"

  /// C6.2.25 B.cond
  [<TestMethod>]
  member _.``C6.2.25 B.COND``() =
    testDisasm "54000040" "beq 0x8"
    testDisasm "54010043" "bcc 0x2008"
    testDisasm "540a03e9" "bls 0x1407c"
    testDisasm "5403010d" "ble 0x6020"

  /// C6.2.250 STCLRB, STCLRLB
  [<TestMethod>]
  member _.``C6.2.250 STCLRB``() =
    testDisasm "3822103f" "stclrb w2, [x1]"
    testDisasm "383f13ff" "stclrb wzr, [sp]"

  /// C6.2.250 STCLRB, STCLRLB
  [<TestMethod>]
  member _.``C6.2.250 STCLRLB``() =
    testDisasm "3862103f" "stclrlb w2, [x1]"
    testDisasm "387f13ff" "stclrlb wzr, [sp]"

  /// C6.2.251 STCLRH, STCLRLH
  [<TestMethod>]
  member _.``C6.2.251 STCLRH``() =
    testDisasm "7822103f" "stclrh w2, [x1]"
    testDisasm "783f13ff" "stclrh wzr, [sp]"

  /// C6.2.251 STCLRH, STCLRLH
  [<TestMethod>]
  member _.``C6.2.251 STCLRLH``() =
    testDisasm "7862103f" "stclrlh w2, [x1]"
    testDisasm "787f13ff" "stclrlh wzr, [sp]"

  /// C6.2.252 STCLR, STCLRL
  [<TestMethod>]
  member _.``C6.2.252 STCLR``() =
    testDisasm "f822103f" "stclr x2, [x1]"
    testDisasm "b822103f" "stclr w2, [x1]"
    testDisasm "b83f13ff" "stclr wzr, [sp]"
    testDisasm "f83f13ff" "stclr xzr, [sp]"

  /// C6.2.252 STCLR, STCLRL
  [<TestMethod>]
  member _.``C6.2.252 STCLRL``() =
    testDisasm "b862103f" "stclrl w2, [x1]"
    testDisasm "b87f13ff" "stclrl wzr, [sp]"
    testDisasm "f87f13ff" "stclrl xzr, [sp]"

  /// C6.2.253 STEORB, STEORLB
  [<TestMethod>]
  member _.``C6.2.253 STEORB``() =
    testDisasm "3822203f" "steorb w2, [x1]"
    testDisasm "383f23ff" "steorb wzr, [sp]"

  /// C6.2.253 STEORB, STEORLB
  [<TestMethod>]
  member _.``C6.2.253 STEORLB``() =
    testDisasm "3862203f" "steorlb w2, [x1]"
    testDisasm "387f23ff" "steorlb wzr, [sp]"

  /// C6.2.254 STEORH, STEORLH
  [<TestMethod>]
  member _.``C6.2.254 STEORH``() =
    testDisasm "7822203f" "steorh w2, [x1]"
    testDisasm "783f23ff" "steorh wzr, [sp]"

  /// C6.2.254 STEORH, STEORLH
  [<TestMethod>]
  member _.``C6.2.254 STEORLH``() =
    testDisasm "7862203f" "steorlh w2, [x1]"
    testDisasm "787f23ff" "steorlh wzr, [sp]"

  /// C6.2.255 STEOR, STEORL
  [<TestMethod>]
  member _.``C6.2.255 STEOR``() =
    testDisasm "f822203f" "steor x2, [x1]"
    testDisasm "b822203f" "steor w2, [x1]"
    testDisasm "b83f23ff" "steor wzr, [sp]"
    testDisasm "f83f23ff" "steor xzr, [sp]"

  /// C6.2.255 STEOR, STEORL
  [<TestMethod>]
  member _.``C6.2.255 STEORL``() =
    testDisasm "b862203f" "steorl w2, [x1]"
    testDisasm "b87f23ff" "steorl wzr, [sp]"
    testDisasm "f87f23ff" "steorl xzr, [sp]"

  /// C6.2.256 STG
  [<TestMethod>]
  member _.``C6.2.256 STG``() =
    testDisasm "d9200820" "stg x0, [x1]"
    testDisasm "d9201420" "stg x0, [x1], #0x10"
    testDisasm "d9201c20" "stg x0, [x1, #0x10]!"
    testDisasm "d9201820" "stg x0, [x1, #0x10]"

  /// C6.2.257 STGM
  [<TestMethod>]
  member _.``C6.2.257 STGM``() =
    testDisasm "d9a00020" "stgm x0, [x1]"

  /// C6.2.258 STGP
  [<TestMethod>]
  member _.``C6.2.258 STGP``() =
    testDisasm "69000820" "stgp x0, x2, [x1]"
    testDisasm "68808c22" "stgp x2, x3, [x1], #0x10"
    testDisasm "69808c22" "stgp x2, x3, [x1, #0x10]!"
    testDisasm "69008c22" "stgp x2, x3, [x1, #0x10]"

  /// C6.2.259 STLLRB
  [<TestMethod>]
  member _.``C6.2.259 STLLRB``() =
    testDisasm "089f7c20" "stllrb w0, [x1]"
    testDisasm "089f03ff" "stllrb wzr, [sp]"
    testDisasm "088a03e9" "stllrb w9, [sp]"
    testDisasm "0881005f" "stllrb wzr, [x2]"

  /// C6.2.26 B
  [<TestMethod>]
  member _.``C6.2.26 B``() =
    testDisasm "14000001" "b 0x4"

  /// C6.2.260 STLLRH
  [<TestMethod>]
  member _.``C6.2.260 STLLRH``() =
    testDisasm "489f7c20" "stllrh w0, [x1]"
    testDisasm "489f03ff" "stllrh wzr, [sp]"
    testDisasm "488a03e9" "stllrh w9, [sp]"
    testDisasm "4881005f" "stllrh wzr, [x2]"

  /// C6.2.261 STLLR
  [<TestMethod>]
  member _.``C6.2.261 STLLR``() =
    testDisasm "c89f7c20" "stllr x0, [x1]"
    testDisasm "889f7c20" "stllr w0, [x1]"
    testDisasm "889f03ff" "stllr wzr, [sp]"
    testDisasm "888a03e9" "stllr w9, [sp]"

  /// C6.2.262 STLR
  [<TestMethod>]
  member _.``C6.2.262 STLR``() =
    testDisasm "c89ffc20" "stlr x0, [x1]"
    testDisasm "889ffc20" "stlr w0, [x1]"
    testDisasm "889f83ff" "stlr wzr, [sp]"
    testDisasm "888a83e9" "stlr w9, [sp]"

  /// C6.2.263 STLRB
  [<TestMethod>]
  member _.``C6.2.263 STLRB``() =
    testDisasm "089ffc20" "stlrb w0, [x1]"
    testDisasm "089f83ff" "stlrb wzr, [sp]"
    testDisasm "088a83e9" "stlrb w9, [sp]"

  /// C6.2.264 STLRH
  [<TestMethod>]
  member _.``C6.2.264 STLRH``() =
    testDisasm "489ffc20" "stlrh w0, [x1]"
    testDisasm "489f83ff" "stlrh wzr, [sp]"
    testDisasm "488a83e9" "stlrh w9, [sp]"

  /// C6.2.265 STLUR
  [<TestMethod>]
  member _.``C6.2.265 STLUR``() =
    testDisasm "d9000020" "stlur x0, [x1]"
    testDisasm "99010020" "stlur w0, [x1, #0x10]"
    testDisasm "d9010020" "stlur x0, [x1, #0x10]"
    testDisasm "99000020" "stlur w0, [x1]"

  /// C6.2.266 STLURB
  [<TestMethod>]
  member _.``C6.2.266 STLURB``() =
    testDisasm "19000020" "stlurb w0, [x1]"
    testDisasm "19010020" "stlurb w0, [x1, #0x10]"
    testDisasm "191f03ff" "stlurb wzr, [sp, #0xfffffffffffffff0]"
    testDisasm "190a03e9" "stlurb w9, [sp, #0xa0]"

  /// C6.2.267 STLURH
  [<TestMethod>]
  member _.``C6.2.267 STLURH``() =
    testDisasm "59000020" "stlurh w0, [x1]"
    testDisasm "59010020" "stlurh w0, [x1, #0x10]"
    testDisasm "591f03ff" "stlurh wzr, [sp, #0xfffffffffffffff0]"
    testDisasm "590a03e9" "stlurh w9, [sp, #0xa0]"

  /// C6.2.268 STLXP
  [<TestMethod>]
  member _.``C6.2.268 STLXP``() =
    testDisasm "88238820" "stlxp w3, w0, w2, [x1]"
    testDisasm "883f83ff" "stlxp wzr, wzr, w0, [sp]"
    testDisasm "882a83e9" "stlxp w10, w9, w0, [sp]"
    testDisasm "883f83c0" "stlxp wzr, w0, w0, [x30]"

  /// C6.2.269 STLXR
  [<TestMethod>]
  member _.``C6.2.269 STLXR``() =
    testDisasm "8802fc20" "stlxr w2, w0, [x1]"
    testDisasm "881f83ff" "stlxr wzr, wzr, [sp]"
    testDisasm "880a83e9" "stlxr w10, w9, [sp]"
    testDisasm "881f83c0" "stlxr wzr, w0, [x30]"

  /// C6.2.27 BFC
  [<TestMethod>]
  member _.``C6.2.27 BFC``() =
    testDisasm "331d13e0" "bfc w0, #0x3, #0x5"
    testDisasm "b37d13e0" "bfc x0, #0x3, #0x5"
    testDisasm "331f03ff" "bfc wzr, #0x1, #0x1"
    testDisasm "b35f03ff" "bfc xzr, #0x21, #0x1"

  /// C6.2.270 STLXRB
  [<TestMethod>]
  member _.``C6.2.270 STLXRB``() =
    testDisasm "0802fc20" "stlxrb w2, w0, [x1]"
    testDisasm "081f83ff" "stlxrb wzr, wzr, [sp]"
    testDisasm "080a83e9" "stlxrb w10, w9, [sp]"
    testDisasm "081f83c0" "stlxrb wzr, w0, [x30]"

  /// C6.2.271 STLXRH
  [<TestMethod>]
  member _.``C6.2.271 STLXRH``() =
    testDisasm "4802fc20" "stlxrh w2, w0, [x1]"
    testDisasm "481f83ff" "stlxrh wzr, wzr, [sp]"
    testDisasm "480a83e9" "stlxrh w10, w9, [sp]"
    testDisasm "481f83c0" "stlxrh wzr, w0, [x30]"

  /// C6.2.272 STNP
  [<TestMethod>]
  member _.``C6.2.272 STNP``() =
    testDisasm "28000c22" "stnp w2, w3, [x1]"
    testDisasm "28020c22" "stnp w2, w3, [x1, #0x10]"
    testDisasm "a8000c22" "stnp x2, x3, [x1]"
    testDisasm "a8010c22" "stnp x2, x3, [x1, #0x10]"

  /// C6.2.273 STP
  [<TestMethod>]
  member _.``C6.2.273 STP``() =
    testDisasm "28820c22" "stp w2, w3, [x1], #0x10"
    testDisasm "a8810c22" "stp x2, x3, [x1], #0x10"
    testDisasm "29820c22" "stp w2, w3, [x1, #0x10]!"
    testDisasm "a9810c22" "stp x2, x3, [x1, #0x10]!"

  /// C6.2.274 STR (immediate)
  [<TestMethod>]
  member _.``C6.2.274 STR``() =
    testDisasm "b8010420" "str w0, [x1], #0x10"
    testDisasm "f8010420" "str x0, [x1], #0x10"
    testDisasm "b8010c20" "str w0, [x1, #0x10]!"
    testDisasm "f8010c20" "str x0, [x1, #0x10]!"

  /// C6.2.276 STRB (immediate)
  [<TestMethod>]
  member _.``C6.2.276 STRB``() =
    testDisasm "38010420" "strb w0, [x1], #0x10"
    testDisasm "38010c20" "strb w0, [x1, #0x10]!"
    testDisasm "39000020" "strb w0, [x1]"
    testDisasm "39002020" "strb w0, [x1, #0x8]"

  /// C6.2.278 STRH (immediate)
  [<TestMethod>]
  member _.``C6.2.278 STRH``() =
    testDisasm "78010420" "strh w0, [x1], #0x10"
    testDisasm "78010c20" "strh w0, [x1, #0x10]!"
    testDisasm "79000020" "strh w0, [x1]"
    testDisasm "79001020" "strh w0, [x1, #0x8]"

  /// C6.2.28 BFI
  [<TestMethod>]
  member _.``C6.2.28 BFI``() =
    testDisasm "331d1020" "bfi w0, w1, #0x3, #0x5"
    testDisasm "b37d1020" "bfi x0, x1, #0x3, #0x5"
    testDisasm "3301005f" "bfi wzr, w2, #0x1f, #0x1"
    testDisasm "b341005f" "bfi xzr, x2, #0x3f, #0x1"

  /// C6.2.280 STSETB, STSETLB
  [<TestMethod>]
  member _.``C6.2.280 STSETB``() =
    testDisasm "3822303f" "stsetb w2, [x1]"
    testDisasm "383f33ff" "stsetb wzr, [sp]"

  /// C6.2.280 STSETB, STSETLB
  [<TestMethod>]
  member _.``C6.2.280 STSETLB``() =
    testDisasm "3862303f" "stsetlb w2, [x1]"
    testDisasm "387f33ff" "stsetlb wzr, [sp]"

  /// C6.2.281 STSETH, STSETLH
  [<TestMethod>]
  member _.``C6.2.281 STSETH``() =
    testDisasm "7822303f" "stseth w2, [x1]"
    testDisasm "783f33ff" "stseth wzr, [sp]"

  /// C6.2.281 STSETH, STSETLH
  [<TestMethod>]
  member _.``C6.2.281 STSETLH``() =
    testDisasm "7862303f" "stsetlh w2, [x1]"
    testDisasm "787f33ff" "stsetlh wzr, [sp]"

  /// C6.2.282 STSET, STSETL
  [<TestMethod>]
  member _.``C6.2.282 STSET``() =
    testDisasm "f822303f" "stset x2, [x1]"
    testDisasm "b822303f" "stset w2, [x1]"
    testDisasm "b83f33ff" "stset wzr, [sp]"
    testDisasm "f83f33ff" "stset xzr, [sp]"

  /// C6.2.282 STSET, STSETL
  [<TestMethod>]
  member _.``C6.2.282 STSETL``() =
    testDisasm "b862303f" "stsetl w2, [x1]"
    testDisasm "b87f33ff" "stsetl wzr, [sp]"
    testDisasm "f87f33ff" "stsetl xzr, [sp]"

  /// C6.2.283 STSMAXB, STSMAXLB
  [<TestMethod>]
  member _.``C6.2.283 STSMAXB``() =
    testDisasm "3822403f" "stsmaxb w2, [x1]"
    testDisasm "383f43ff" "stsmaxb wzr, [sp]"

  /// C6.2.283 STSMAXB, STSMAXLB
  [<TestMethod>]
  member _.``C6.2.283 STSMAXLB``() =
    testDisasm "3862403f" "stsmaxlb w2, [x1]"
    testDisasm "387f43ff" "stsmaxlb wzr, [sp]"

  /// C6.2.284 STSMAXH, STSMAXLH
  [<TestMethod>]
  member _.``C6.2.284 STSMAXH``() =
    testDisasm "7822403f" "stsmaxh w2, [x1]"
    testDisasm "783f43ff" "stsmaxh wzr, [sp]"

  /// C6.2.284 STSMAXH, STSMAXLH
  [<TestMethod>]
  member _.``C6.2.284 STSMAXLH``() =
    testDisasm "7862403f" "stsmaxlh w2, [x1]"
    testDisasm "787f43ff" "stsmaxlh wzr, [sp]"

  /// C6.2.285 STSMAX, STSMAXL
  [<TestMethod>]
  member _.``C6.2.285 STSMAX``() =
    testDisasm "f822403f" "stsmax x2, [x1]"
    testDisasm "b822403f" "stsmax w2, [x1]"
    testDisasm "b83f43ff" "stsmax wzr, [sp]"
    testDisasm "f83f43ff" "stsmax xzr, [sp]"

  /// C6.2.285 STSMAX, STSMAXL
  [<TestMethod>]
  member _.``C6.2.285 STSMAXL``() =
    testDisasm "b862403f" "stsmaxl w2, [x1]"
    testDisasm "b87f43ff" "stsmaxl wzr, [sp]"
    testDisasm "f87f43ff" "stsmaxl xzr, [sp]"

  /// C6.2.286 STSMINB, STSMINLB
  [<TestMethod>]
  member _.``C6.2.286 STSMINB``() =
    testDisasm "3822503f" "stsminb w2, [x1]"
    testDisasm "383f53ff" "stsminb wzr, [sp]"

  /// C6.2.286 STSMINB, STSMINLB
  [<TestMethod>]
  member _.``C6.2.286 STSMINLB``() =
    testDisasm "3862503f" "stsminlb w2, [x1]"
    testDisasm "387f53ff" "stsminlb wzr, [sp]"

  /// C6.2.287 STSMINH, STSMINLH
  [<TestMethod>]
  member _.``C6.2.287 STSMINH``() =
    testDisasm "7822503f" "stsminh w2, [x1]"
    testDisasm "783f53ff" "stsminh wzr, [sp]"

  /// C6.2.287 STSMINH, STSMINLH
  [<TestMethod>]
  member _.``C6.2.287 STSMINLH``() =
    testDisasm "7862503f" "stsminlh w2, [x1]"
    testDisasm "787f53ff" "stsminlh wzr, [sp]"

  /// C6.2.288 STSMIN, STSMINL
  [<TestMethod>]
  member _.``C6.2.288 STSMIN``() =
    testDisasm "f822503f" "stsmin x2, [x1]"
    testDisasm "b822503f" "stsmin w2, [x1]"
    testDisasm "b83f53ff" "stsmin wzr, [sp]"
    testDisasm "f83f53ff" "stsmin xzr, [sp]"

  /// C6.2.288 STSMIN, STSMINL
  [<TestMethod>]
  member _.``C6.2.288 STSMINL``() =
    testDisasm "b862503f" "stsminl w2, [x1]"
    testDisasm "b87f53ff" "stsminl wzr, [sp]"
    testDisasm "f87f53ff" "stsminl xzr, [sp]"

  /// C6.2.289 STTR
  [<TestMethod>]
  member _.``C6.2.289 STTR``() =
    testDisasm "b8010820" "sttr w0, [x1, #0x10]"
    testDisasm "f8000820" "sttr x0, [x1]"
    testDisasm "f8010820" "sttr x0, [x1, #0x10]"
    testDisasm "b8000820" "sttr w0, [x1]"

  /// C6.2.29 BFM
  [<TestMethod>]
  member _.``C6.2.29 BFM``() =
    testDisasm "331d13e0" "bfc w0, #0x3, #0x5"
    testDisasm "b37d13e0" "bfc x0, #0x3, #0x5"
    testDisasm "331d1020" "bfi w0, w1, #0x3, #0x5"
    testDisasm "b37d1020" "bfi x0, x1, #0x3, #0x5"

  /// C6.2.290 STTRB
  [<TestMethod>]
  member _.``C6.2.290 STTRB``() =
    testDisasm "38010820" "sttrb w0, [x1, #0x10]"
    testDisasm "38000820" "sttrb w0, [x1]"
    testDisasm "381f0bff" "sttrb wzr, [sp, #0xfffffffffffffff0]"
    testDisasm "380a0be9" "sttrb w9, [sp, #0xa0]"

  /// C6.2.291 STTRH
  [<TestMethod>]
  member _.``C6.2.291 STTRH``() =
    testDisasm "78010820" "sttrh w0, [x1, #0x10]"
    testDisasm "78000820" "sttrh w0, [x1]"
    testDisasm "781f0bff" "sttrh wzr, [sp, #0xfffffffffffffff0]"
    testDisasm "780a0be9" "sttrh w9, [sp, #0xa0]"

  /// C6.2.292 STUMAXB, STUMAXLB
  [<TestMethod>]
  member _.``C6.2.292 STUMAXB``() =
    testDisasm "3822603f" "stumaxb w2, [x1]"
    testDisasm "383f63ff" "stumaxb wzr, [sp]"

  /// C6.2.292 STUMAXB, STUMAXLB
  [<TestMethod>]
  member _.``C6.2.292 STUMAXLB``() =
    testDisasm "3862603f" "stumaxlb w2, [x1]"
    testDisasm "387f63ff" "stumaxlb wzr, [sp]"

  /// C6.2.293 STUMAXH, STUMAXLH
  [<TestMethod>]
  member _.``C6.2.293 STUMAXH``() =
    testDisasm "7822603f" "stumaxh w2, [x1]"
    testDisasm "783f63ff" "stumaxh wzr, [sp]"

  /// C6.2.293 STUMAXH, STUMAXLH
  [<TestMethod>]
  member _.``C6.2.293 STUMAXLH``() =
    testDisasm "7862603f" "stumaxlh w2, [x1]"
    testDisasm "787f63ff" "stumaxlh wzr, [sp]"

  /// C6.2.294 STUMAX, STUMAXL
  [<TestMethod>]
  member _.``C6.2.294 STUMAX``() =
    testDisasm "f822603f" "stumax x2, [x1]"
    testDisasm "b822603f" "stumax w2, [x1]"
    testDisasm "b83f63ff" "stumax wzr, [sp]"
    testDisasm "f83f63ff" "stumax xzr, [sp]"

  /// C6.2.294 STUMAX, STUMAXL
  [<TestMethod>]
  member _.``C6.2.294 STUMAXL``() =
    testDisasm "b862603f" "stumaxl w2, [x1]"
    testDisasm "b87f63ff" "stumaxl wzr, [sp]"
    testDisasm "f87f63ff" "stumaxl xzr, [sp]"

  /// C6.2.295 STUMINB, STUMINLB
  [<TestMethod>]
  member _.``C6.2.295 STUMINB``() =
    testDisasm "3822703f" "stuminb w2, [x1]"
    testDisasm "383f73ff" "stuminb wzr, [sp]"

  /// C6.2.295 STUMINB, STUMINLB
  [<TestMethod>]
  member _.``C6.2.295 STUMINLB``() =
    testDisasm "3862703f" "stuminlb w2, [x1]"
    testDisasm "387f73ff" "stuminlb wzr, [sp]"

  /// C6.2.296 STUMINH, STUMINLH
  [<TestMethod>]
  member _.``C6.2.296 STUMINH``() =
    testDisasm "7822703f" "stuminh w2, [x1]"
    testDisasm "783f73ff" "stuminh wzr, [sp]"

  /// C6.2.296 STUMINH, STUMINLH
  [<TestMethod>]
  member _.``C6.2.296 STUMINLH``() =
    testDisasm "7862703f" "stuminlh w2, [x1]"
    testDisasm "787f73ff" "stuminlh wzr, [sp]"

  /// C6.2.297 STUMIN, STUMINL
  [<TestMethod>]
  member _.``C6.2.297 STUMIN``() =
    testDisasm "f822703f" "stumin x2, [x1]"
    testDisasm "b822703f" "stumin w2, [x1]"
    testDisasm "b83f73ff" "stumin wzr, [sp]"
    testDisasm "f83f73ff" "stumin xzr, [sp]"

  /// C6.2.297 STUMIN, STUMINL
  [<TestMethod>]
  member _.``C6.2.297 STUMINL``() =
    testDisasm "b862703f" "stuminl w2, [x1]"
    testDisasm "b87f73ff" "stuminl wzr, [sp]"
    testDisasm "f87f73ff" "stuminl xzr, [sp]"

  /// C6.2.298 STUR
  [<TestMethod>]
  member _.``C6.2.298 STUR``() =
    testDisasm "b8010020" "stur w0, [x1, #0x10]"
    testDisasm "f8000020" "stur x0, [x1]"
    testDisasm "f8010020" "stur x0, [x1, #0x10]"
    testDisasm "b8000020" "stur w0, [x1]"

  /// C6.2.299 STURB
  [<TestMethod>]
  member _.``C6.2.299 STURB``() =
    testDisasm "38010020" "sturb w0, [x1, #0x10]"
    testDisasm "38000020" "sturb w0, [x1]"
    testDisasm "381f03ff" "sturb wzr, [sp, #0xfffffffffffffff0]"
    testDisasm "380a03e9" "sturb w9, [sp, #0xa0]"

  /// C6.2.3 ADD (extended register)
  [<TestMethod>]
  member _.``C6.2.3 ADD``() =
    testDisasm "0b020020" "add w0, w1, w2"
    testDisasm "11004020" "add w0, w1, #0x10"
    testDisasm "91004020" "add x0, x1, #0x10"
    testDisasm "8b020020" "add x0, x1, x2"

  /// C6.2.30 BFXIL
  [<TestMethod>]
  member _.``C6.2.30 BFXIL``() =
    testDisasm "33031420" "bfxil w0, w1, #0x3, #0x3"
    testDisasm "b3431420" "bfxil x0, x1, #0x3, #0x3"
    testDisasm "b34003e0" "bfxil x0, xzr, #0x0, #0x1"
    testDisasm "330a2be9" "bfxil w9, wzr, #0xa, #0x1"

  /// C6.2.300 STURH
  [<TestMethod>]
  member _.``C6.2.300 STURH``() =
    testDisasm "78010020" "sturh w0, [x1, #0x10]"
    testDisasm "78000020" "sturh w0, [x1]"
    testDisasm "781f03ff" "sturh wzr, [sp, #0xfffffffffffffff0]"
    testDisasm "780a03e9" "sturh w9, [sp, #0xa0]"

  /// C6.2.301 STXP
  [<TestMethod>]
  member _.``C6.2.301 STXP``() =
    testDisasm "88230820" "stxp w3, w0, w2, [x1]"
    testDisasm "883f03ff" "stxp wzr, wzr, w0, [sp]"
    testDisasm "882a03e9" "stxp w10, w9, w0, [sp]"
    testDisasm "883f03c0" "stxp wzr, w0, w0, [x30]"

  /// C6.2.302 STXR
  [<TestMethod>]
  member _.``C6.2.302 STXR``() =
    testDisasm "88027c20" "stxr w2, w0, [x1]"
    testDisasm "881f03ff" "stxr wzr, wzr, [sp]"
    testDisasm "880a03e9" "stxr w10, w9, [sp]"
    testDisasm "881f03c0" "stxr wzr, w0, [x30]"

  /// C6.2.303 STXRB
  [<TestMethod>]
  member _.``C6.2.303 STXRB``() =
    testDisasm "08027c20" "stxrb w2, w0, [x1]"
    testDisasm "081f03ff" "stxrb wzr, wzr, [sp]"
    testDisasm "080a03e9" "stxrb w10, w9, [sp]"
    testDisasm "081f03c0" "stxrb wzr, w0, [x30]"

  /// C6.2.304 STXRH
  [<TestMethod>]
  member _.``C6.2.304 STXRH``() =
    testDisasm "48027c20" "stxrh w2, w0, [x1]"
    testDisasm "481f03ff" "stxrh wzr, wzr, [sp]"
    testDisasm "480a03e9" "stxrh w10, w9, [sp]"
    testDisasm "481f03c0" "stxrh wzr, w0, [x30]"

  /// C6.2.305 STZ2G
  [<TestMethod>]
  member _.``C6.2.305 STZ2G``() =
    testDisasm "d9e00820" "stz2g x0, [x1]"
    testDisasm "d9e01420" "stz2g x0, [x1], #0x10"
    testDisasm "d9e01c20" "stz2g x0, [x1, #0x10]!"
    testDisasm "d9e01820" "stz2g x0, [x1, #0x10]"

  /// C6.2.306 STZG
  [<TestMethod>]
  member _.``C6.2.306 STZG``() =
    testDisasm "d9600820" "stzg x0, [x1]"
    testDisasm "d9601420" "stzg x0, [x1], #0x10"
    testDisasm "d9601c20" "stzg x0, [x1, #0x10]!"
    testDisasm "d9601820" "stzg x0, [x1, #0x10]"

  /// C6.2.307 STZGM
  [<TestMethod>]
  member _.``C6.2.307 STZGM``() =
    testDisasm "d9200020" "stzgm x0, [x1]"

  /// C6.2.308 SUB (extended register)
  [<TestMethod>]
  member _.``C6.2.308 SUB``() =
    testDisasm "4b0203e0" "neg w0, w2"
    testDisasm "4b020020" "sub w0, w1, w2"
    testDisasm "51004020" "sub w0, w1, #0x10"
    testDisasm "d1004020" "sub x0, x1, #0x10"

  /// C6.2.31 BIC (shifted register)
  [<TestMethod>]
  member _.``C6.2.31 BIC``() =
    testDisasm "0a220020" "bic w0, w1, w2"
    testDisasm "2f009460" "bic v0.4h, #0x3"
    testDisasm "2f001460" "bic v0.2s, #0x3"
    testDisasm "0e621c20" "bic v0.8b, v1.8b, v2.8b"

  /// C6.2.311 SUBG
  [<TestMethod>]
  member _.``C6.2.311 SUBG``() =
    testDisasm "d1800020" "subg x0, x1, #0x0, #0x0"
    testDisasm "d19f03ff" "subg sp, sp, #0x1f0, #0x0"
    testDisasm "d18a03e9" "subg x9, sp, #0xa0, #0x0"
    testDisasm "d181005f" "subg sp, x2, #0x10, #0x0"

  /// C6.2.312 SUBP
  [<TestMethod>]
  member _.``C6.2.312 SUBP``() =
    testDisasm "9ac20020" "subp x0, x1, x2"
    testDisasm "9adf03ff" "subp xzr, sp, sp"
    testDisasm "9aca03e9" "subp x9, sp, x10"
    testDisasm "9adf03c0" "subp x0, x30, sp"

  /// C6.2.313 SUBPS
  [<TestMethod>]
  member _.``C6.2.313 SUBPS``() =
    testDisasm "bac1001f" "cmpp x0, x1"
    testDisasm "bac20020" "subps x0, x1, x2"
    testDisasm "badf03ff" "cmpp sp, sp"
    testDisasm "baca03e9" "subps x9, sp, x10"

  /// C6.2.314 SUBS (extended register)
  [<TestMethod>]
  member _.``C6.2.314 SUBS``() =
    testDisasm "6b02003f" "cmp w1, w2"
    testDisasm "7100403f" "cmp w1, #0x10"
    testDisasm "f100403f" "cmp x1, #0x10"
    testDisasm "eb02003f" "cmp x1, x2"

  /// C6.2.317 SVC
  [<TestMethod>]
  member _.``C6.2.317 SVC``() =
    testDisasm "d4010041" "svc #0x802"

  /// C6.2.318 SWPB, SWPAB, SWPALB, SWPLB
  [<TestMethod>]
  member _.``C6.2.318 SWPAB``() =
    testDisasm "38a28020" "swpab w2, w0, [x1]"
    testDisasm "38bf83ff" "swpab wzr, wzr, [sp]"
    testDisasm "38aa83e9" "swpab w10, w9, [sp]"
    testDisasm "38bf83c0" "swpab wzr, w0, [x30]"

  /// C6.2.318 SWPB, SWPAB, SWPALB, SWPLB
  [<TestMethod>]
  member _.``C6.2.318 SWPALB``() =
    testDisasm "38e28020" "swpalb w2, w0, [x1]"
    testDisasm "38ff83ff" "swpalb wzr, wzr, [sp]"
    testDisasm "38ea83e9" "swpalb w10, w9, [sp]"
    testDisasm "38ff83c0" "swpalb wzr, w0, [x30]"

  /// C6.2.318 SWPB, SWPAB, SWPALB, SWPLB
  [<TestMethod>]
  member _.``C6.2.318 SWPB``() =
    testDisasm "38228020" "swpb w2, w0, [x1]"
    testDisasm "383f83ff" "swpb wzr, wzr, [sp]"
    testDisasm "382a83e9" "swpb w10, w9, [sp]"
    testDisasm "383f83c0" "swpb wzr, w0, [x30]"

  /// C6.2.318 SWPB, SWPAB, SWPALB, SWPLB
  [<TestMethod>]
  member _.``C6.2.318 SWPLB``() =
    testDisasm "38628020" "swplb w2, w0, [x1]"
    testDisasm "387f83ff" "swplb wzr, wzr, [sp]"
    testDisasm "386a83e9" "swplb w10, w9, [sp]"
    testDisasm "387f83c0" "swplb wzr, w0, [x30]"

  /// C6.2.319 SWPH, SWPAH, SWPALH, SWPLH
  [<TestMethod>]
  member _.``C6.2.319 SWPAH``() =
    testDisasm "78a28020" "swpah w2, w0, [x1]"
    testDisasm "78bf83ff" "swpah wzr, wzr, [sp]"
    testDisasm "78aa83e9" "swpah w10, w9, [sp]"
    testDisasm "78bf83c0" "swpah wzr, w0, [x30]"

  /// C6.2.319 SWPH, SWPAH, SWPALH, SWPLH
  [<TestMethod>]
  member _.``C6.2.319 SWPALH``() =
    testDisasm "78e28020" "swpalh w2, w0, [x1]"
    testDisasm "78ff83ff" "swpalh wzr, wzr, [sp]"
    testDisasm "78ea83e9" "swpalh w10, w9, [sp]"
    testDisasm "78ff83c0" "swpalh wzr, w0, [x30]"

  /// C6.2.319 SWPH, SWPAH, SWPALH, SWPLH
  [<TestMethod>]
  member _.``C6.2.319 SWPH``() =
    testDisasm "78228020" "swph w2, w0, [x1]"
    testDisasm "783f83ff" "swph wzr, wzr, [sp]"
    testDisasm "782a83e9" "swph w10, w9, [sp]"
    testDisasm "783f83c0" "swph wzr, w0, [x30]"

  /// C6.2.319 SWPH, SWPAH, SWPALH, SWPLH
  [<TestMethod>]
  member _.``C6.2.319 SWPLH``() =
    testDisasm "78628020" "swplh w2, w0, [x1]"
    testDisasm "787f83ff" "swplh wzr, wzr, [sp]"
    testDisasm "786a83e9" "swplh w10, w9, [sp]"
    testDisasm "787f83c0" "swplh wzr, w0, [x30]"

  /// C6.2.32 BICS (shifted register)
  [<TestMethod>]
  member _.``C6.2.32 BICS``() =
    testDisasm "6a220020" "bics w0, w1, w2"
    testDisasm "ea220020" "bics x0, x1, x2"
    testDisasm "6a3f03ff" "bics wzr, wzr, wzr"
    testDisasm "6a2a03e9" "bics w9, wzr, w10"

  /// C6.2.320 SWP, SWPA, SWPAL, SWPL
  [<TestMethod>]
  member _.``C6.2.320 SWP``() =
    testDisasm "f8228020" "swp x2, x0, [x1]"
    testDisasm "b8228020" "swp w2, w0, [x1]"
    testDisasm "b83f83ff" "swp wzr, wzr, [sp]"
    testDisasm "b82a83e9" "swp w10, w9, [sp]"

  /// C6.2.320 SWP, SWPA, SWPAL, SWPL
  [<TestMethod>]
  member _.``C6.2.320 SWPA``() =
    testDisasm "b8a28020" "swpa w2, w0, [x1]"
    testDisasm "b8bf83ff" "swpa wzr, wzr, [sp]"
    testDisasm "b8aa83e9" "swpa w10, w9, [sp]"
    testDisasm "b8bf83c0" "swpa wzr, w0, [x30]"

  /// C6.2.320 SWP, SWPA, SWPAL, SWPL
  [<TestMethod>]
  member _.``C6.2.320 SWPAL``() =
    testDisasm "b8e28020" "swpal w2, w0, [x1]"
    testDisasm "b8ff83ff" "swpal wzr, wzr, [sp]"
    testDisasm "b8ea83e9" "swpal w10, w9, [sp]"
    testDisasm "b8ff83c0" "swpal wzr, w0, [x30]"

  /// C6.2.320 SWP, SWPA, SWPAL, SWPL
  [<TestMethod>]
  member _.``C6.2.320 SWPL``() =
    testDisasm "b8628020" "swpl w2, w0, [x1]"
    testDisasm "b87f83ff" "swpl wzr, wzr, [sp]"
    testDisasm "b86a83e9" "swpl w10, w9, [sp]"
    testDisasm "b87f83c0" "swpl wzr, w0, [x30]"

  /// C6.2.321 SXTB
  [<TestMethod>]
  member _.``C6.2.321 SXTB``() =
    testDisasm "13001c20" "sxtb w0, w1"
    testDisasm "93401c20" "sxtb x0, w1"

  /// C6.2.322 SXTH
  [<TestMethod>]
  member _.``C6.2.322 SXTH``() =
    testDisasm "13003c20" "sxth w0, w1"
    testDisasm "93403c20" "sxth x0, w1"

  /// C6.2.323 SXTW
  [<TestMethod>]
  member _.``C6.2.323 SXTW``() =
    testDisasm "93407c20" "sxtw x0, w1"

  /// C6.2.324 SYS
  [<TestMethod>]
  member _.``C6.2.324 SYS``() =
    testDisasm "d50b7380" "cfp rctx, x0"
    testDisasm "d50b73e0" "cpp rctx, x0"
    testDisasm "d50b73a0" "dvp rctx, x0"
    testDisasm "d50a03e9" "sys #0x2, c0, c3, #0x7, x9"

  /// C6.2.325 SYSL
  [<TestMethod>]
  member _.``C6.2.325 SYSL``() =
    testDisasm "d52a03e9" "sysl x9, #0x2, c0, c3, #0x7"
    testDisasm "d528001f" "sysl xzr, #0x0, c0, c0, #0x0"

  /// C6.2.326 TBNZ
  [<TestMethod>]
  member _.``C6.2.326 TBNZ``() =
    testDisasm "37010043" "tbnz w3, #0x0, 0x2008"
    testDisasm "371f03ff" "tbnz wzr, #0x3, 0xffffffffffffe07c"
    testDisasm "b7010043" "tbnz x3, #0x20, 0x2008"
    testDisasm "b71f03ff" "tbnz xzr, #0x23, 0xffffffffffffe07c"

  /// C6.2.327 TBZ
  [<TestMethod>]
  member _.``C6.2.327 TBZ``() =
    testDisasm "36010043" "tbz w3, #0x0, 0x2008"
    testDisasm "361f03ff" "tbz wzr, #0x3, 0xffffffffffffe07c"
    testDisasm "b6010043" "tbz x3, #0x20, 0x2008"
    testDisasm "b61f03ff" "tbz xzr, #0x23, 0xffffffffffffe07c"

  /// C6.2.328 TLBI
  [<TestMethod>]
  member _.``C6.2.328 TLBI``() =
    testDisasm "d508811f" "tlbi vmalle1os"
    testDisasm "d5088120" "tlbi vae1os, x0"
    testDisasm "d508813f" "tlbi vae1os, xzr"
    testDisasm "d5088140" "tlbi aside1os, x0"

  /// C6.2.329 TSB CSYNC
  [<TestMethod>]
  member _.``C6.2.329 TSB``() =
    testDisasm "d503225f" "tsb csync"

  /// C6.2.33 BL
  [<TestMethod>]
  member _.``C6.2.33 BL``() =
    testDisasm "94000001" "bl 0x4"

  /// C6.2.330 TST (immediate)
  [<TestMethod>]
  member _.``C6.2.330 TST``() =
    testDisasm "f240783f" "tst x1, #0x7fffffff"
    testDisasm "721c003f" "tst w1, #0x10"
    testDisasm "6a02003f" "tst w1, w2"
    testDisasm "ea02003f" "tst x1, x2"

  /// C6.2.332 UBFIZ
  [<TestMethod>]
  member _.``C6.2.332 UBFIZ``() =
    testDisasm "531d1020" "ubfiz w0, w1, #0x3, #0x5"
    testDisasm "d37d1020" "ubfiz x0, x1, #0x3, #0x5"
    testDisasm "531f03ff" "ubfiz wzr, wzr, #0x1, #0x1"
    testDisasm "530a03e9" "ubfiz w9, wzr, #0x16, #0x1"

  /// C6.2.333 UBFM
  [<TestMethod>]
  member _.``C6.2.333 UBFM``() =
    testDisasm "531f7820" "lsl w0, w1, #0x1"
    testDisasm "d37ff820" "lsl x0, x1, #0x1"
    testDisasm "53017c20" "lsr w0, w1, #0x1"
    testDisasm "d341fc20" "lsr x0, x1, #0x1"

  /// C6.2.334 UBFX
  [<TestMethod>]
  member _.``C6.2.334 UBFX``() =
    testDisasm "53031420" "ubfx w0, w1, #0x3, #0x3"
    testDisasm "d3431420" "ubfx x0, x1, #0x3, #0x3"
    testDisasm "530a2be9" "ubfx w9, wzr, #0xa, #0x1"
    testDisasm "d34a2be9" "ubfx x9, xzr, #0xa, #0x1"

  /// C6.2.335 UDF
  [<TestMethod>]
  member _.``C6.2.335 UDF``() =
    testDisasm "00000005" "udf #0x5"

  /// C6.2.336 UDIV
  [<TestMethod>]
  member _.``C6.2.336 UDIV``() =
    testDisasm "1ac20820" "udiv w0, w1, w2"
    testDisasm "9ac20820" "udiv x0, x1, x2"
    testDisasm "1adf0bff" "udiv wzr, wzr, wzr"
    testDisasm "1aca0be9" "udiv w9, wzr, w10"

  /// C6.2.337 UMADDL
  [<TestMethod>]
  member _.``C6.2.337 UMADDL``() =
    testDisasm "9ba20c20" "umaddl x0, w1, w2, x3"
    testDisasm "9ba27c20" "umull x0, w1, w2"
    testDisasm "9bbf03ff" "umaddl xzr, wzr, wzr, x0"
    testDisasm "9baa03e9" "umaddl x9, wzr, w10, x0"

  /// C6.2.338 UMNEGL
  [<TestMethod>]
  member _.``C6.2.338 UMNEGL``() =
    testDisasm "9ba2fc20" "umnegl x0, w1, w2"
    testDisasm "9bbfffff" "umnegl xzr, wzr, wzr"
    testDisasm "9baaffe9" "umnegl x9, wzr, w10"
    testDisasm "9bbfffc0" "umnegl x0, w30, wzr"

  /// C6.2.339 UMSUBL
  [<TestMethod>]
  member _.``C6.2.339 UMSUBL``() =
    testDisasm "9ba2fc20" "umnegl x0, w1, w2"
    testDisasm "9ba28c20" "umsubl x0, w1, w2, x3"
    testDisasm "9bbf83ff" "umsubl xzr, wzr, wzr, x0"
    testDisasm "9baa83e9" "umsubl x9, wzr, w10, x0"

  /// C6.2.34 BLR
  [<TestMethod>]
  member _.``C6.2.34 BLR``() =
    testDisasm "d63f03c0" "blr x30"
    testDisasm "d63f03e0" "blr xzr"

  /// C6.2.340 UMULH
  [<TestMethod>]
  member _.``C6.2.340 UMULH``() =
    testDisasm "9bc27c20" "umulh x0, x1, x2"
    testDisasm "9bdf03ff" "umulh xzr, xzr, xzr"
    testDisasm "9bca03e9" "umulh x9, xzr, x10"
    testDisasm "9bdf03c0" "umulh x0, x30, xzr"

  /// C6.2.341 UMULL
  [<TestMethod>]
  member _.``C6.2.341 UMULL``() =
    testDisasm "2f52a020" "umull v0.4s, v1.4h, v2.h[1]"
    testDisasm "2fa2a020" "umull v0.2d, v1.2s, v2.s[1]"
    testDisasm "2e22c020" "umull v0.8h, v1.8b, v2.8b"
    testDisasm "2e62c020" "umull v0.4s, v1.4h, v2.4h"

  /// C6.2.342 UXTB
  [<TestMethod>]
  member _.``C6.2.342 UXTB``() =
    testDisasm "53001c20" "uxtb w0, w1"

  /// C6.2.343 UXTH
  [<TestMethod>]
  member _.``C6.2.343 UXTH``() =
    testDisasm "53003c20" "uxth w0, w1"

  /// C6.2.344 WFE
  [<TestMethod>]
  member _.``C6.2.344 WFE``() =
    testDisasm "d503205f" "wfe"

  /// C6.2.345 WFI
  [<TestMethod>]
  member _.``C6.2.345 WFI``() =
    testDisasm "d503207f" "wfi"

  /// C6.2.346 XAFLAG
  [<TestMethod>]
  member _.``C6.2.346 XAFLAG``() =
    testDisasm "d500403f" "xaflag"

  /// C6.2.347 XPACD, XPACI, XPACLRI
  [<TestMethod>]
  member _.``C6.2.347 XPACD``() =
    testDisasm "dac147e0" "xpacd x0"

  /// C6.2.347 XPACD, XPACI, XPACLRI
  [<TestMethod>]
  member _.``C6.2.347 XPACI``() =
    testDisasm "dac143e0" "xpaci x0"

  /// C6.2.347 XPACD, XPACI, XPACLRI
  [<TestMethod>]
  member _.``C6.2.347 XPACLRI``() =
    testDisasm "d50320ff" "xpaclri"

  /// C6.2.348 YIELD
  [<TestMethod>]
  member _.``C6.2.348 YIELD``() =
    testDisasm "d503203f" "yield"

  /// C6.2.35 BLRAA, BLRAAZ, BLRAB, BLRABZ
  [<TestMethod>]
  member _.``C6.2.35 BLRAA``() =
    testDisasm "d73f0bff" "blraa xzr, sp"
    testDisasm "d73f0bc0" "blraa x30, x0"
    testDisasm "d73f0be0" "blraa xzr, x0"

  /// C6.2.35 BLRAA, BLRAAZ, BLRAB, BLRABZ
  [<TestMethod>]
  member _.``C6.2.35 BLRAAZ``() =
    testDisasm "d63f0bff" "blraaz xzr"

  /// C6.2.35 BLRAA, BLRAAZ, BLRAB, BLRABZ
  [<TestMethod>]
  member _.``C6.2.35 BLRAB``() =
    testDisasm "d73f0fff" "blrab xzr, sp"
    testDisasm "d73f0fc0" "blrab x30, x0"
    testDisasm "d73f0fe0" "blrab xzr, x0"

  /// C6.2.35 BLRAA, BLRAAZ, BLRAB, BLRABZ
  [<TestMethod>]
  member _.``C6.2.35 BLRABZ``() =
    testDisasm "d63f0fff" "blrabz xzr"

  /// C6.2.36 BR
  [<TestMethod>]
  member _.``C6.2.36 BR``() =
    testDisasm "d61f03c0" "br x30"
    testDisasm "d61f03e0" "br xzr"

  /// C6.2.37 BRAA, BRAAZ, BRAB, BRABZ
  [<TestMethod>]
  member _.``C6.2.37 BRAA``() =
    testDisasm "d71f0bff" "braa xzr, sp"
    testDisasm "d71f0bc0" "braa x30, x0"
    testDisasm "d71f0be0" "braa xzr, x0"

  /// C6.2.37 BRAA, BRAAZ, BRAB, BRABZ
  [<TestMethod>]
  member _.``C6.2.37 BRAAZ``() =
    testDisasm "d61f0bff" "braaz xzr"

  /// C6.2.37 BRAA, BRAAZ, BRAB, BRABZ
  [<TestMethod>]
  member _.``C6.2.37 BRAB``() =
    testDisasm "d71f0fff" "brab xzr, sp"
    testDisasm "d71f0fc0" "brab x30, x0"
    testDisasm "d71f0fe0" "brab xzr, x0"

  /// C6.2.37 BRAA, BRAAZ, BRAB, BRABZ
  [<TestMethod>]
  member _.``C6.2.37 BRABZ``() =
    testDisasm "d61f0fff" "brabz xzr"

  /// C6.2.38 BRK
  [<TestMethod>]
  member _.``C6.2.38 BRK``() =
    testDisasm "d42003c0" "brk #0x1e"

  /// C6.2.39 BTI
  [<TestMethod>]
  member _.``C6.2.39 BTI``() =
    testDisasm "d503241f" "bti"
    testDisasm "d503245f" "bti c"
    testDisasm "d503249f" "bti j"
    testDisasm "d50324df" "bti jc"

  /// C6.2.40 CASB, CASAB, CASALB, CASLB
  [<TestMethod>]
  member _.``C6.2.40 CASAB``() =
    testDisasm "08e27c20" "casab w2, w0, [x1]"
    testDisasm "08ff7fff" "casab wzr, wzr, [sp]"
    testDisasm "08ea7fe9" "casab w10, w9, [sp]"
    testDisasm "08ff7fc0" "casab wzr, w0, [x30]"

  /// C6.2.40 CASB, CASAB, CASALB, CASLB
  [<TestMethod>]
  member _.``C6.2.40 CASALB``() =
    testDisasm "08e2fc20" "casalb w2, w0, [x1]"
    testDisasm "08ffffff" "casalb wzr, wzr, [sp]"
    testDisasm "08eaffe9" "casalb w10, w9, [sp]"
    testDisasm "08ffffc0" "casalb wzr, w0, [x30]"

  /// C6.2.40 CASB, CASAB, CASALB, CASLB
  [<TestMethod>]
  member _.``C6.2.40 CASB``() =
    testDisasm "08a27c20" "casb w2, w0, [x1]"
    testDisasm "08bf7fff" "casb wzr, wzr, [sp]"
    testDisasm "08aa7fe9" "casb w10, w9, [sp]"
    testDisasm "08bf7fc0" "casb wzr, w0, [x30]"

  /// C6.2.40 CASB, CASAB, CASALB, CASLB
  [<TestMethod>]
  member _.``C6.2.40 CASLB``() =
    testDisasm "08a2fc20" "caslb w2, w0, [x1]"
    testDisasm "08bfffff" "caslb wzr, wzr, [sp]"
    testDisasm "08aaffe9" "caslb w10, w9, [sp]"
    testDisasm "08bfffc0" "caslb wzr, w0, [x30]"

  /// C6.2.41 CASH, CASAH, CASALH, CASLH
  [<TestMethod>]
  member _.``C6.2.41 CASAH``() =
    testDisasm "48e27c20" "casah w2, w0, [x1]"
    testDisasm "48ff7fff" "casah wzr, wzr, [sp]"
    testDisasm "48ea7fe9" "casah w10, w9, [sp]"
    testDisasm "48ff7fc0" "casah wzr, w0, [x30]"

  /// C6.2.41 CASH, CASAH, CASALH, CASLH
  [<TestMethod>]
  member _.``C6.2.41 CASALH``() =
    testDisasm "48e2fc20" "casalh w2, w0, [x1]"
    testDisasm "48ffffff" "casalh wzr, wzr, [sp]"
    testDisasm "48eaffe9" "casalh w10, w9, [sp]"
    testDisasm "48ffffc0" "casalh wzr, w0, [x30]"

  /// C6.2.41 CASH, CASAH, CASALH, CASLH
  [<TestMethod>]
  member _.``C6.2.41 CASH``() =
    testDisasm "48a27c20" "cash w2, w0, [x1]"
    testDisasm "48bf7fff" "cash wzr, wzr, [sp]"
    testDisasm "48aa7fe9" "cash w10, w9, [sp]"
    testDisasm "48bf7fc0" "cash wzr, w0, [x30]"

  /// C6.2.41 CASH, CASAH, CASALH, CASLH
  [<TestMethod>]
  member _.``C6.2.41 CASLH``() =
    testDisasm "48a2fc20" "caslh w2, w0, [x1]"
    testDisasm "48bfffff" "caslh wzr, wzr, [sp]"
    testDisasm "48aaffe9" "caslh w10, w9, [sp]"
    testDisasm "48bfffc0" "caslh wzr, w0, [x30]"

  /// C6.2.42 CASP, CASPA, CASPAL, CASPL
  [<TestMethod>]
  member _.``C6.2.42 CASP``() =
    testDisasm "48227c80" "casp x2, x3, x0, x1, [x4]"
    testDisasm "08347eb6" "casp w20, w21, w22, w23, [x21]"

  /// C6.2.42 CASP, CASPA, CASPAL, CASPL
  [<TestMethod>]
  member _.``C6.2.42 CASPA``() =
    testDisasm "48627c80" "caspa x2, x3, x0, x1, [x4]"
    testDisasm "08747eb6" "caspa w20, w21, w22, w23, [x21]"

  /// C6.2.42 CASP, CASPA, CASPAL, CASPL
  [<TestMethod>]
  member _.``C6.2.42 CASPAL``() =
    testDisasm "4862fc80" "caspal x2, x3, x0, x1, [x4]"
    testDisasm "0874feb6" "caspal w20, w21, w22, w23, [x21]"

  /// C6.2.42 CASP, CASPA, CASPAL, CASPL
  [<TestMethod>]
  member _.``C6.2.42 CASPL``() =
    testDisasm "4822fc80" "caspl x2, x3, x0, x1, [x4]"
    testDisasm "0834feb6" "caspl w20, w21, w22, w23, [x21]"

  /// C6.2.43 CAS, CASA, CASAL, CASL
  [<TestMethod>]
  member _.``C6.2.43 CAS``() =
    testDisasm "c8a27c20" "cas x2, x0, [x1]"
    testDisasm "88a27c20" "cas w2, w0, [x1]"
    testDisasm "88bf7fff" "cas wzr, wzr, [sp]"
    testDisasm "88aa7fe9" "cas w10, w9, [sp]"

  /// C6.2.43 CAS, CASA, CASAL, CASL
  [<TestMethod>]
  member _.``C6.2.43 CASA``() =
    testDisasm "88e27c20" "casa w2, w0, [x1]"
    testDisasm "88ff7fff" "casa wzr, wzr, [sp]"
    testDisasm "88ea7fe9" "casa w10, w9, [sp]"
    testDisasm "88ff7fc0" "casa wzr, w0, [x30]"

  /// C6.2.43 CAS, CASA, CASAL, CASL
  [<TestMethod>]
  member _.``C6.2.43 CASAL``() =
    testDisasm "88e2fc20" "casal w2, w0, [x1]"
    testDisasm "88ffffff" "casal wzr, wzr, [sp]"
    testDisasm "88eaffe9" "casal w10, w9, [sp]"
    testDisasm "88ffffc0" "casal wzr, w0, [x30]"

  /// C6.2.43 CAS, CASA, CASAL, CASL
  [<TestMethod>]
  member _.``C6.2.43 CASL``() =
    testDisasm "88a2fc20" "casl w2, w0, [x1]"
    testDisasm "88bfffff" "casl wzr, wzr, [sp]"
    testDisasm "88aaffe9" "casl w10, w9, [sp]"
    testDisasm "88bfffc0" "casl wzr, w0, [x30]"

  /// C6.2.44 CBNZ
  [<TestMethod>]
  member _.``C6.2.44 CBNZ``() =
    testDisasm "35000020" "cbnz w0, 0x4"
    testDisasm "b5000020" "cbnz x0, 0x4"
    testDisasm "351f03ff" "cbnz wzr, 0x3e07c"
    testDisasm "b51f03ff" "cbnz xzr, 0x3e07c"

  /// C6.2.45 CBZ
  [<TestMethod>]
  member _.``C6.2.45 CBZ``() =
    testDisasm "34000020" "cbz w0, 0x4"
    testDisasm "b4000020" "cbz x0, 0x4"
    testDisasm "341f03ff" "cbz wzr, 0x3e07c"
    testDisasm "b41f03ff" "cbz xzr, 0x3e07c"

  /// C6.2.46 CCMN (immediate)
  [<TestMethod>]
  member _.``C6.2.46 CCMN``() =
    testDisasm "3a500829" "ccmn w1, #0x10, #0x9, eq"
    testDisasm "ba500829" "ccmn x1, #0x10, #0x9, eq"
    testDisasm "3a420029" "ccmn w1, w2, #0x9, eq"
    testDisasm "ba420029" "ccmn x1, x2, #0x9, eq"

  /// C6.2.48 CCMP (immediate)
  [<TestMethod>]
  member _.``C6.2.48 CCMP``() =
    testDisasm "7a500829" "ccmp w1, #0x10, #0x9, eq"
    testDisasm "fa500829" "ccmp x1, #0x10, #0x9, eq"
    testDisasm "7a420029" "ccmp w1, w2, #0x9, eq"
    testDisasm "fa420029" "ccmp x1, x2, #0x9, eq"

  /// C6.2.50 CFINV
  [<TestMethod>]
  member _.``C6.2.50 CFINV``() =
    testDisasm "d500401f" "cfinv"

  /// C6.2.51 CFP
  [<TestMethod>]
  member _.``C6.2.51 CFP``() =
    testDisasm "d50b7380" "cfp rctx, x0"
    testDisasm "d50b739f" "cfp rctx, xzr"

  /// C6.2.52 CINC
  [<TestMethod>]
  member _.``C6.2.52 CINC``() =
    testDisasm "1a811420" "cinc w0, w1, eq"
    testDisasm "9a811420" "cinc x0, x1, eq"
    testDisasm "1a800400" "cinc w0, w0, ne"
    testDisasm "1a802400" "cinc w0, w0, cc"

  /// C6.2.53 CINV
  [<TestMethod>]
  member _.``C6.2.53 CINV``() =
    testDisasm "5a811020" "cinv w0, w1, eq"
    testDisasm "da811020" "cinv x0, x1, eq"
    testDisasm "5a800000" "cinv w0, w0, ne"
    testDisasm "5a802000" "cinv w0, w0, cc"

  /// C6.2.54 CLREX
  [<TestMethod>]
  member _.``C6.2.54 CLREX``() =
    testDisasm "d503305f" "clrex #0x0"

  /// C6.2.55 CLS
  [<TestMethod>]
  member _.``C6.2.55 CLS``() =
    testDisasm "5ac01420" "cls w0, w1"
    testDisasm "0e204820" "cls v0.8b, v1.8b"
    testDisasm "0e604820" "cls v0.4h, v1.4h"
    testDisasm "0ea04820" "cls v0.2s, v1.2s"

  /// C6.2.56 CLZ
  [<TestMethod>]
  member _.``C6.2.56 CLZ``() =
    testDisasm "5ac01020" "clz w0, w1"
    testDisasm "2e204820" "clz v0.8b, v1.8b"
    testDisasm "2e604820" "clz v0.4h, v1.4h"
    testDisasm "2ea04820" "clz v0.2s, v1.2s"

  /// C6.2.57 CMN (extended register)
  [<TestMethod>]
  member _.``C6.2.57 CMN``() =
    testDisasm "2b02003f" "cmn w1, w2"
    testDisasm "3100403f" "cmn w1, #0x10"
    testDisasm "b100403f" "cmn x1, #0x10"
    testDisasm "ab02003f" "cmn x1, x2"

  /// C6.2.6 ADDG
  [<TestMethod>]
  member _.``C6.2.6 ADDG``() =
    testDisasm "91800020" "addg x0, x1, #0x0, #0x0"
    testDisasm "919f03ff" "addg sp, sp, #0x1f0, #0x0"
    testDisasm "918a03e9" "addg x9, sp, #0xa0, #0x0"
    testDisasm "9181005f" "addg sp, x2, #0x10, #0x0"

  /// C6.2.60 CMP (extended register)
  [<TestMethod>]
  member _.``C6.2.60 CMP``() =
    testDisasm "6b02003f" "cmp w1, w2"
    testDisasm "7100403f" "cmp w1, #0x10"
    testDisasm "f100403f" "cmp x1, #0x10"
    testDisasm "eb02003f" "cmp x1, x2"

  /// C6.2.63 CMPP
  [<TestMethod>]
  member _.``C6.2.63 CMPP``() =
    testDisasm "bac1001f" "cmpp x0, x1"
    testDisasm "badf03ff" "cmpp sp, sp"

  /// C6.2.64 CNEG
  [<TestMethod>]
  member _.``C6.2.64 CNEG``() =
    testDisasm "5a811420" "cneg w0, w1, eq"
    testDisasm "da811420" "cneg x0, x1, eq"
    testDisasm "5a9f07ff" "cneg wzr, wzr, ne"
    testDisasm "5a9f07e0" "cneg w0, wzr, ne"

  /// C6.2.65 CPP
  [<TestMethod>]
  member _.``C6.2.65 CPP``() =
    testDisasm "d50b73e0" "cpp rctx, x0"
    testDisasm "d50b73ff" "cpp rctx, xzr"

  /// C6.2.66 CRC32B, CRC32H, CRC32W, CRC32X
  [<TestMethod>]
  member _.``C6.2.66 CRC32B``() =
    testDisasm "1ac24020" "crc32b w0, w1, w2"
    testDisasm "1adf43ff" "crc32b wzr, wzr, wzr"
    testDisasm "1aca43e9" "crc32b w9, wzr, w10"
    testDisasm "1adf43c0" "crc32b w0, w30, wzr"

  /// C6.2.66 CRC32B, CRC32H, CRC32W, CRC32X
  [<TestMethod>]
  member _.``C6.2.66 CRC32H``() =
    testDisasm "1ac24420" "crc32h w0, w1, w2"
    testDisasm "1adf47ff" "crc32h wzr, wzr, wzr"
    testDisasm "1aca47e9" "crc32h w9, wzr, w10"
    testDisasm "1adf47c0" "crc32h w0, w30, wzr"

  /// C6.2.66 CRC32B, CRC32H, CRC32W, CRC32X
  [<TestMethod>]
  member _.``C6.2.66 CRC32W``() =
    testDisasm "1ac24820" "crc32w w0, w1, w2"
    testDisasm "1adf4bff" "crc32w wzr, wzr, wzr"
    testDisasm "1aca4be9" "crc32w w9, wzr, w10"
    testDisasm "1adf4bc0" "crc32w w0, w30, wzr"

  /// C6.2.66 CRC32B, CRC32H, CRC32W, CRC32X
  [<TestMethod>]
  member _.``C6.2.66 CRC32X``() =
    testDisasm "9ac24c20" "crc32x w0, w1, x2"
    testDisasm "9adf4fff" "crc32x wzr, wzr, xzr"
    testDisasm "9aca4fe9" "crc32x w9, wzr, x10"
    testDisasm "9adf4fc0" "crc32x w0, w30, xzr"

  /// C6.2.67 CRC32CB, CRC32CH, CRC32CW, CRC32CX
  [<TestMethod>]
  member _.``C6.2.67 CRC32CB``() =
    testDisasm "1ac25020" "crc32cb w0, w1, w2"
    testDisasm "1adf53ff" "crc32cb wzr, wzr, wzr"
    testDisasm "1aca53e9" "crc32cb w9, wzr, w10"
    testDisasm "1adf53c0" "crc32cb w0, w30, wzr"

  /// C6.2.67 CRC32CB, CRC32CH, CRC32CW, CRC32CX
  [<TestMethod>]
  member _.``C6.2.67 CRC32CH``() =
    testDisasm "1ac25420" "crc32ch w0, w1, w2"
    testDisasm "1adf57ff" "crc32ch wzr, wzr, wzr"
    testDisasm "1aca57e9" "crc32ch w9, wzr, w10"
    testDisasm "1adf57c0" "crc32ch w0, w30, wzr"

  /// C6.2.67 CRC32CB, CRC32CH, CRC32CW, CRC32CX
  [<TestMethod>]
  member _.``C6.2.67 CRC32CW``() =
    testDisasm "1ac25820" "crc32cw w0, w1, w2"
    testDisasm "1adf5bff" "crc32cw wzr, wzr, wzr"
    testDisasm "1aca5be9" "crc32cw w9, wzr, w10"
    testDisasm "1adf5bc0" "crc32cw w0, w30, wzr"

  /// C6.2.67 CRC32CB, CRC32CH, CRC32CW, CRC32CX
  [<TestMethod>]
  member _.``C6.2.67 CRC32CX``() =
    testDisasm "9ac25c20" "crc32cx w0, w1, x2"
    testDisasm "9adf5fff" "crc32cx wzr, wzr, xzr"
    testDisasm "9aca5fe9" "crc32cx w9, wzr, x10"
    testDisasm "9adf5fc0" "crc32cx w0, w30, xzr"

  /// C6.2.68 CSDB
  [<TestMethod>]
  member _.``C6.2.68 CSDB``() =
    testDisasm "d503229f" "csdb"

  /// C6.2.69 CSEL
  [<TestMethod>]
  member _.``C6.2.69 CSEL``() =
    testDisasm "1a820020" "csel w0, w1, w2, eq"
    testDisasm "9a820020" "csel x0, x1, x2, eq"
    testDisasm "1a9f03ff" "csel wzr, wzr, wzr, eq"
    testDisasm "1a8a03e9" "csel w9, wzr, w10, eq"

  /// C6.2.7 ADDS (extended register)
  [<TestMethod>]
  member _.``C6.2.7 ADDS``() =
    testDisasm "2b020020" "adds w0, w1, w2"
    testDisasm "31004020" "adds w0, w1, #0x10"
    testDisasm "b1004020" "adds x0, x1, #0x10"
    testDisasm "ab020020" "adds x0, x1, x2"

  /// C6.2.70 CSET
  [<TestMethod>]
  member _.``C6.2.70 CSET``() =
    testDisasm "1a9f17e0" "cset w0, eq"
    testDisasm "9a9f17e0" "cset x0, eq"
    testDisasm "1a9f07ff" "cset wzr, ne"
    testDisasm "1a9f07e0" "cset w0, ne"

  /// C6.2.71 CSETM
  [<TestMethod>]
  member _.``C6.2.71 CSETM``() =
    testDisasm "5a9f13e0" "csetm w0, eq"
    testDisasm "da9f13e0" "csetm x0, eq"
    testDisasm "5a9f03ff" "csetm wzr, ne"
    testDisasm "5a9f03e0" "csetm w0, ne"

  /// C6.2.72 CSINC
  [<TestMethod>]
  member _.``C6.2.72 CSINC``() =
    testDisasm "1a811420" "cinc w0, w1, eq"
    testDisasm "1a9f17e0" "cset w0, eq"
    testDisasm "1a820420" "csinc w0, w1, w2, eq"
    testDisasm "9a811420" "cinc x0, x1, eq"

  /// C6.2.73 CSINV
  [<TestMethod>]
  member _.``C6.2.73 CSINV``() =
    testDisasm "5a811020" "cinv w0, w1, eq"
    testDisasm "5a9f13e0" "csetm w0, eq"
    testDisasm "5a820020" "csinv w0, w1, w2, eq"
    testDisasm "da811020" "cinv x0, x1, eq"

  /// C6.2.74 CSNEG
  [<TestMethod>]
  member _.``C6.2.74 CSNEG``() =
    testDisasm "5a811420" "cneg w0, w1, eq"
    testDisasm "5a820420" "csneg w0, w1, w2, eq"
    testDisasm "da811420" "cneg x0, x1, eq"
    testDisasm "da820420" "csneg x0, x1, x2, eq"

  /// C6.2.75 DC
  [<TestMethod>]
  member _.``C6.2.75 DC``() =
    testDisasm "d5087620" "dc ivac, x0"
    testDisasm "d508763f" "dc ivac, xzr"
    testDisasm "d5087640" "dc isw, x0"
    testDisasm "d508765f" "dc isw, xzr"

  /// C6.2.76 DCPS1
  [<TestMethod>]
  member _.``C6.2.76 DCPS1``() =
    testDisasm "d4a10041" "dcps1 #0x802"

  /// C6.2.77 DCPS2
  [<TestMethod>]
  member _.``C6.2.77 DCPS2``() =
    testDisasm "d4a10042" "dcps2 #0x802"

  /// C6.2.78 DCPS3
  [<TestMethod>]
  member _.``C6.2.78 DCPS3``() =
    testDisasm "d4a10043" "dcps3 #0x802"

  /// C6.2.79 DGH
  [<TestMethod>]
  member _.``C6.2.79 DGH``() =
    testDisasm "d50320df" "dgh"

  /// C6.2.80 DMB
  [<TestMethod>]
  member _.``C6.2.80 DMB``() =
    testDisasm "d50330bf" "dmb #0x0"
    testDisasm "d50331bf" "dmb oshld"
    testDisasm "d50332bf" "dmb oshst"
    testDisasm "d50333bf" "dmb osh"

  /// C6.2.81 DRPS
  [<TestMethod>]
  member _.``C6.2.81 DRPS``() =
    testDisasm "d6bf03e0" "drps"

  /// C6.2.82 DSB
  [<TestMethod>]
  member _.``C6.2.82 DSB``() =
    testDisasm "d503349f" "pssbb"
    testDisasm "d503309f" "ssbb"
    testDisasm "d503319f" "dsb oshld"
    testDisasm "d503329f" "dsb oshst"

  /// C6.2.83 DVP
  [<TestMethod>]
  member _.``C6.2.83 DVP``() =
    testDisasm "d50b73a0" "dvp rctx, x0"
    testDisasm "d50b73bf" "dvp rctx, xzr"

  /// C6.2.84 EON (shifted register)
  [<TestMethod>]
  member _.``C6.2.84 EON``() =
    testDisasm "4a220020" "eon w0, w1, w2"
    testDisasm "ca220020" "eon x0, x1, x2"
    testDisasm "4a3f03ff" "eon wzr, wzr, wzr"
    testDisasm "4a2a03e9" "eon w9, wzr, w10"

  /// C6.2.85 EOR (immediate)
  [<TestMethod>]
  member _.``C6.2.85 EOR``() =
    testDisasm "d200cc20" "eor x0, x1, #0xf0f0f0f0f0f0f0f"
    testDisasm "521c0020" "eor w0, w1, #0x10"
    testDisasm "4a020020" "eor w0, w1, w2"
    testDisasm "ca020020" "eor x0, x1, x2"

  /// C6.2.87 ERET
  [<TestMethod>]
  member _.``C6.2.87 ERET``() =
    testDisasm "d69f03e0" "eret"

  /// C6.2.88 ERETAA, ERETAB
  [<TestMethod>]
  member _.``C6.2.88 ERETAA``() =
    testDisasm "d69f0bff" "eretaa"

  /// C6.2.88 ERETAA, ERETAB
  [<TestMethod>]
  member _.``C6.2.88 ERETAB``() =
    testDisasm "d69f0fff" "eretab"

  /// C6.2.89 ESB
  [<TestMethod>]
  member _.``C6.2.89 ESB``() =
    testDisasm "d503221f" "esb"

  /// C6.2.90 EXTR
  [<TestMethod>]
  member _.``C6.2.90 EXTR``() =
    testDisasm "13820c20" "extr w0, w1, w2, #3"
    testDisasm "93c20c20" "extr x0, x1, x2, #3"
    testDisasm "13820440" "ror w0, w2, #1"
    testDisasm "93c20440" "ror x0, x2, #1"

  /// C6.2.91 GMI
  [<TestMethod>]
  member _.``C6.2.91 GMI``() =
    testDisasm "9ac21420" "gmi x0, x1, x2"
    testDisasm "9adf17ff" "gmi xzr, sp, xzr"
    testDisasm "9aca17e9" "gmi x9, sp, x10"
    testDisasm "9adf17c0" "gmi x0, x30, xzr"

  /// C6.2.92 HINT
  [<TestMethod>]
  member _.``C6.2.92 HINT``() =
    testDisasm "d503219f" "autia1716"
    testDisasm "d50323bf" "autiasp"
    testDisasm "d503239f" "autiaz"
    testDisasm "d50321df" "autib1716"

  /// C6.2.93 HLT
  [<TestMethod>]
  member _.``C6.2.93 HLT``() =
    testDisasm "d44003c0" "hlt #0x1e"

  /// C6.2.94 HVC
  [<TestMethod>]
  member _.``C6.2.94 HVC``() =
    testDisasm "d4010042" "hvc #0x802"

  /// C6.2.95 IC
  [<TestMethod>]
  member _.``C6.2.95 IC``() =
    testDisasm "d508711f" "ic ialluis"
    testDisasm "d508751f" "ic iallu"
    testDisasm "d50b7520" "ic ivau, x0"
    testDisasm "d50b753f" "ic ivau, xzr"

  /// C6.2.96 IRG
  [<TestMethod>]
  member _.``C6.2.96 IRG``() =
    testDisasm "9adf1020" "irg x0, x1"
    testDisasm "9ac21020" "irg x0, x1, x2"
    testDisasm "9adf13ff" "irg sp, sp"
    testDisasm "9aca13e9" "irg x9, sp, x10"

  /// C6.2.97 ISB
  [<TestMethod>]
  member _.``C6.2.97 ISB``() =
    testDisasm "d50330df" "isb #0x0"

  /// C6.2.98 LDADDB, LDADDAB, LDADDALB, LDADDLB
  [<TestMethod>]
  member _.``C6.2.98 LDADDAB``() =
    testDisasm "38a20020" "ldaddab w2, w0, [x1]"
    testDisasm "38bf03ff" "ldaddab wzr, wzr, [sp]"
    testDisasm "38aa03e9" "ldaddab w10, w9, [sp]"
    testDisasm "38bf03c0" "ldaddab wzr, w0, [x30]"

  /// C6.2.98 LDADDB, LDADDAB, LDADDALB, LDADDLB
  [<TestMethod>]
  member _.``C6.2.98 LDADDALB``() =
    testDisasm "38e20020" "ldaddalb w2, w0, [x1]"
    testDisasm "38ff03ff" "ldaddalb wzr, wzr, [sp]"
    testDisasm "38ea03e9" "ldaddalb w10, w9, [sp]"
    testDisasm "38ff03c0" "ldaddalb wzr, w0, [x30]"

  /// C6.2.98 LDADDB, LDADDAB, LDADDALB, LDADDLB
  [<TestMethod>]
  member _.``C6.2.98 LDADDB``() =
    testDisasm "38220020" "ldaddb w2, w0, [x1]"
    testDisasm "3822003f" "staddb w2, [x1]"
    testDisasm "383f03ff" "staddb wzr, [sp]"
    testDisasm "382a03e9" "ldaddb w10, w9, [sp]"

  /// C6.2.98 LDADDB, LDADDAB, LDADDALB, LDADDLB
  [<TestMethod>]
  member _.``C6.2.98 LDADDLB``() =
    testDisasm "38620020" "ldaddlb w2, w0, [x1]"
    testDisasm "3862003f" "staddlb w2, [x1]"
    testDisasm "387f03ff" "staddlb wzr, [sp]"
    testDisasm "386a03e9" "ldaddlb w10, w9, [sp]"

  /// C6.2.99 LDADDH, LDADDAH, LDADDALH, LDADDLH
  [<TestMethod>]
  member _.``C6.2.99 LDADDAH``() =
    testDisasm "78a20020" "ldaddah w2, w0, [x1]"
    testDisasm "78bf03ff" "ldaddah wzr, wzr, [sp]"
    testDisasm "78aa03e9" "ldaddah w10, w9, [sp]"
    testDisasm "78bf03c0" "ldaddah wzr, w0, [x30]"

  /// C6.2.99 LDADDH, LDADDAH, LDADDALH, LDADDLH
  [<TestMethod>]
  member _.``C6.2.99 LDADDALH``() =
    testDisasm "78e20020" "ldaddalh w2, w0, [x1]"
    testDisasm "78ff03ff" "ldaddalh wzr, wzr, [sp]"
    testDisasm "78ea03e9" "ldaddalh w10, w9, [sp]"
    testDisasm "78ff03c0" "ldaddalh wzr, w0, [x30]"

  /// C6.2.99 LDADDH, LDADDAH, LDADDALH, LDADDLH
  [<TestMethod>]
  member _.``C6.2.99 LDADDH``() =
    testDisasm "78220020" "ldaddh w2, w0, [x1]"
    testDisasm "7822003f" "staddh w2, [x1]"
    testDisasm "783f03ff" "staddh wzr, [sp]"
    testDisasm "782a03e9" "ldaddh w10, w9, [sp]"

  /// C6.2.99 LDADDH, LDADDAH, LDADDALH, LDADDLH
  [<TestMethod>]
  member _.``C6.2.99 LDADDLH``() =
    testDisasm "78620020" "ldaddlh w2, w0, [x1]"
    testDisasm "7862003f" "staddlh w2, [x1]"
    testDisasm "787f03ff" "staddlh wzr, [sp]"
    testDisasm "786a03e9" "ldaddlh w10, w9, [sp]"

  /// C7.2.1 ABS
  [<TestMethod>]
  member _.``C7.2.1 ABS``() =
    testDisasm "0e20b820" "abs v0.8b, v1.8b"
    testDisasm "0e60b820" "abs v0.4h, v1.4h"
    testDisasm "0ea0b820" "abs v0.2s, v1.2s"
    testDisasm "4ee0b820" "abs v0.2d, v1.2d"

  /// C7.2.10 AESMC
  [<TestMethod>]
  member _.``C7.2.10 AESMC``() =
    testDisasm "4e286820" "aesmc v0.16b, v1.16b"

  /// C7.2.100 FMADD
  [<TestMethod>]
  member _.``C7.2.100 FMADD``() =
    testDisasm "1fc20c20" "fmadd h0, h1, h2, h3"
    testDisasm "1f020c20" "fmadd s0, s1, s2, s3"
    testDisasm "1f420c20" "fmadd d0, d1, d2, d3"

  /// C7.2.101 FMAX (vector)
  [<TestMethod>]
  member _.``C7.2.101 FMAX``() =
    testDisasm "0e423420" "fmax v0.4h, v1.4h, v2.4h"
    testDisasm "0e22f420" "fmax v0.2s, v1.2s, v2.2s"
    testDisasm "4e62f420" "fmax v0.2d, v1.2d, v2.2d"
    testDisasm "1ee24820" "fmax h0, h1, h2"

  /// C7.2.103 FMAXNM (vector)
  [<TestMethod>]
  member _.``C7.2.103 FMAXNM``() =
    testDisasm "0e420420" "fmaxnm v0.4h, v1.4h, v2.4h"
    testDisasm "0e22c420" "fmaxnm v0.2s, v1.2s, v2.2s"
    testDisasm "4e62c420" "fmaxnm v0.2d, v1.2d, v2.2d"
    testDisasm "1ee26820" "fmaxnm h0, h1, h2"

  /// C7.2.105 FMAXNMP (scalar)
  [<TestMethod>]
  member _.``C7.2.105 FMAXNMP``() =
    testDisasm "2e420420" "fmaxnmp v0.4h, v1.4h, v2.4h"
    testDisasm "2e22c420" "fmaxnmp v0.2s, v1.2s, v2.2s"
    testDisasm "6e62c420" "fmaxnmp v0.2d, v1.2d, v2.2d"
    testDisasm "5e30c843" "fmaxnmp h3, v2.2h"

  /// C7.2.107 FMAXNMV
  [<TestMethod>]
  member _.``C7.2.107 FMAXNMV``() =
    testDisasm "6e30c820" "fmaxnmv s0, v1.4s"
    testDisasm "0e30c843" "fmaxnmv h3, v2.4h"

  /// C7.2.108 FMAXP (scalar)
  [<TestMethod>]
  member _.``C7.2.108 FMAXP``() =
    testDisasm "2e423420" "fmaxp v0.4h, v1.4h, v2.4h"
    testDisasm "2e22f420" "fmaxp v0.2s, v1.2s, v2.2s"
    testDisasm "6e62f420" "fmaxp v0.2d, v1.2d, v2.2d"
    testDisasm "5e30f843" "fmaxp h3, v2.2h"

  /// C7.2.110 FMAXV
  [<TestMethod>]
  member _.``C7.2.110 FMAXV``() =
    testDisasm "6e30f820" "fmaxv s0, v1.4s"
    testDisasm "0e30f843" "fmaxv h3, v2.4h"

  /// C7.2.111 FMIN (vector)
  [<TestMethod>]
  member _.``C7.2.111 FMIN``() =
    testDisasm "0ec23420" "fmin v0.4h, v1.4h, v2.4h"
    testDisasm "0ea2f420" "fmin v0.2s, v1.2s, v2.2s"
    testDisasm "4ee2f420" "fmin v0.2d, v1.2d, v2.2d"
    testDisasm "1ee25820" "fmin h0, h1, h2"

  /// C7.2.113 FMINNM (vector)
  [<TestMethod>]
  member _.``C7.2.113 FMINNM``() =
    testDisasm "0ec20420" "fminnm v0.4h, v1.4h, v2.4h"
    testDisasm "0ea2c420" "fminnm v0.2s, v1.2s, v2.2s"
    testDisasm "4ee2c420" "fminnm v0.2d, v1.2d, v2.2d"
    testDisasm "1ee27820" "fminnm h0, h1, h2"

  /// C7.2.115 FMINNMP (scalar)
  [<TestMethod>]
  member _.``C7.2.115 FMINNMP``() =
    testDisasm "2ec20420" "fminnmp v0.4h, v1.4h, v2.4h"
    testDisasm "2ea2c420" "fminnmp v0.2s, v1.2s, v2.2s"
    testDisasm "6ee2c420" "fminnmp v0.2d, v1.2d, v2.2d"
    testDisasm "5eb0c843" "fminnmp h3, v2.2h"

  /// C7.2.117 FMINNMV
  [<TestMethod>]
  member _.``C7.2.117 FMINNMV``() =
    testDisasm "6eb0c820" "fminnmv s0, v1.4s"
    testDisasm "0eb0c843" "fminnmv h3, v2.4h"

  /// C7.2.118 FMINP (scalar)
  [<TestMethod>]
  member _.``C7.2.118 FMINP``() =
    testDisasm "2ec23420" "fminp v0.4h, v1.4h, v2.4h"
    testDisasm "2ea2f420" "fminp v0.2s, v1.2s, v2.2s"
    testDisasm "6ee2f420" "fminp v0.2d, v1.2d, v2.2d"
    testDisasm "5eb0f843" "fminp h3, v2.2h"

  /// C7.2.12 BCAX
  [<TestMethod>]
  member _.``C7.2.12 BCAX``() =
    testDisasm "ce220c20" "bcax v0.16b, v1.16b, v2.16b, v3.16b"

  /// C7.2.120 FMINV
  [<TestMethod>]
  member _.``C7.2.120 FMINV``() =
    testDisasm "6eb0f820" "fminv s0, v1.4s"
    testDisasm "0eb0f843" "fminv h3, v2.4h"

  /// C7.2.121 FMLA (by element)
  [<TestMethod>]
  member _.``C7.2.121 FMLA``() =
    testDisasm "5f121020" "fmla h0, h1, v2.h[1]"
    testDisasm "0f121020" "fmla v0.4h, v1.4h, v2.h[1]"
    testDisasm "0fa21020" "fmla v0.2s, v1.2s, v2.s[1]"
    testDisasm "4fc21820" "fmla v0.2d, v1.2d, v2.d[1]"

  /// C7.2.123 FMLAL, FMLAL2 (by element)
  [<TestMethod>]
  member _.``C7.2.123 FMLAL``() =
    testDisasm "0e22ec20" "fmlal v0.2s, v1.2h, v2.2h"
    testDisasm "4f920020" "fmlal v0.4s, v1.4h, v2.h[1]"

  /// C7.2.123 FMLAL, FMLAL2 (by element)
  [<TestMethod>]
  member _.``C7.2.123 FMLAL2``() =
    testDisasm "6e22cc20" "fmlal2 v0.4s, v1.4h, v2.4h"
    testDisasm "2f818043" "fmlal2 v3.2s, v2.2h, v1.h[0]"

  /// C7.2.125 FMLS (by element)
  [<TestMethod>]
  member _.``C7.2.125 FMLS``() =
    testDisasm "5f125020" "fmls h0, h1, v2.h[1]"
    testDisasm "0f125020" "fmls v0.4h, v1.4h, v2.h[1]"
    testDisasm "0fa25020" "fmls v0.2s, v1.2s, v2.s[1]"
    testDisasm "4fc25820" "fmls v0.2d, v1.2d, v2.d[1]"

  /// C7.2.127 FMLSL, FMLSL2 (by element)
  [<TestMethod>]
  member _.``C7.2.127 FMLSL``() =
    testDisasm "0ea2ec20" "fmlsl v0.2s, v1.2h, v2.2h"
    testDisasm "4f924020" "fmlsl v0.4s, v1.4h, v2.h[1]"

  /// C7.2.127 FMLSL, FMLSL2 (by element)
  [<TestMethod>]
  member _.``C7.2.127 FMLSL2``() =
    testDisasm "6ea2cc20" "fmlsl2 v0.4s, v1.4h, v2.4h"
    testDisasm "2f81c043" "fmlsl2 v3.2s, v2.2h, v1.h[0]"

  /// C7.2.129 FMOV (vector, immediate)
  [<TestMethod>]
  member _.``C7.2.129 FMOV``() =
    testDisasm "9e670020" "fmov d0, x1"
    testDisasm "0f01fe00" "fmov v0.4h, #16.00000000"
    testDisasm "0f01f600" "fmov v0.2s, #16.00000000"
    testDisasm "6f01f600" "fmov v0.2d, #16.00000000"

  /// C7.2.13 BFCVT
  [<TestMethod>]
  member _.``C7.2.13 BFCVT``() =
    testDisasm "1e634020" "bfcvt h0, s1"

  /// C7.2.133 FMSUB
  [<TestMethod>]
  member _.``C7.2.133 FMSUB``() =
    testDisasm "1fc28c20" "fmsub h0, h1, h2, h3"
    testDisasm "1f028c20" "fmsub s0, s1, s2, s3"
    testDisasm "1f428c20" "fmsub d0, d1, d2, d3"

  /// C7.2.134 FMUL (by element)
  [<TestMethod>]
  member _.``C7.2.134 FMUL``() =
    testDisasm "5f129020" "fmul h0, h1, v2.h[1]"
    testDisasm "0f129020" "fmul v0.4h, v1.4h, v2.h[1]"
    testDisasm "0fa29020" "fmul v0.2s, v1.2s, v2.s[1]"
    testDisasm "4fc29820" "fmul v0.2d, v1.2d, v2.d[1]"

  /// C7.2.137 FMULX (by element)
  [<TestMethod>]
  member _.``C7.2.137 FMULX``() =
    testDisasm "7f129020" "fmulx h0, h1, v2.h[1]"
    testDisasm "2f129020" "fmulx v0.4h, v1.4h, v2.h[1]"
    testDisasm "2fa29020" "fmulx v0.2s, v1.2s, v2.s[1]"
    testDisasm "6fc29820" "fmulx v0.2d, v1.2d, v2.d[1]"

  /// C7.2.139 FNEG (vector)
  [<TestMethod>]
  member _.``C7.2.139 FNEG``() =
    testDisasm "2ef8f820" "fneg v0.4h, v1.4h"
    testDisasm "2ea0f820" "fneg v0.2s, v1.2s"
    testDisasm "6ee0f820" "fneg v0.2d, v1.2d"
    testDisasm "1ee14020" "fneg h0, h1"

  /// C7.2.14 BFCVTN, BFCVTN2
  [<TestMethod>]
  member _.``C7.2.14 BFCVTN``() =
    testDisasm "0ea16820" "bfcvtn v0.4h, v1.4s"

  /// C7.2.14 BFCVTN, BFCVTN2
  [<TestMethod>]
  member _.``C7.2.14 BFCVTN2``() =
    testDisasm "4ea16820" "bfcvtn2 v0.8h, v1.4s"

  /// C7.2.141 FNMADD
  [<TestMethod>]
  member _.``C7.2.141 FNMADD``() =
    testDisasm "1fe20c20" "fnmadd h0, h1, h2, h3"
    testDisasm "1f620c20" "fnmadd d0, d1, d2, d3"
    testDisasm "1f220c20" "fnmadd s0, s1, s2, s3"

  /// C7.2.142 FNMSUB
  [<TestMethod>]
  member _.``C7.2.142 FNMSUB``() =
    testDisasm "1fe28c20" "fnmsub h0, h1, h2, h3"
    testDisasm "1f228c20" "fnmsub s0, s1, s2, s3"
    testDisasm "1f628c20" "fnmsub d0, d1, d2, d3"

  /// C7.2.143 FNMUL (scalar)
  [<TestMethod>]
  member _.``C7.2.143 FNMUL``() =
    testDisasm "1ee28820" "fnmul h0, h1, h2"
    testDisasm "1e228820" "fnmul s0, s1, s2"
    testDisasm "1e628820" "fnmul d0, d1, d2"

  /// C7.2.144 FRECPE
  [<TestMethod>]
  member _.``C7.2.144 FRECPE``() =
    testDisasm "5ef9d820" "frecpe h0, h1"
    testDisasm "0ef9d820" "frecpe v0.4h, v1.4h"
    testDisasm "0ea1d820" "frecpe v0.2s, v1.2s"
    testDisasm "4ee1d820" "frecpe v0.2d, v1.2d"

  /// C7.2.145 FRECPS
  [<TestMethod>]
  member _.``C7.2.145 FRECPS``() =
    testDisasm "5e423c20" "frecps h0, h1, h2"
    testDisasm "0e423c20" "frecps v0.4h, v1.4h, v2.4h"
    testDisasm "0e22fc20" "frecps v0.2s, v1.2s, v2.2s"
    testDisasm "4e62fc20" "frecps v0.2d, v1.2d, v2.2d"

  /// C7.2.146 FRECPX
  [<TestMethod>]
  member _.``C7.2.146 FRECPX``() =
    testDisasm "5ef9f820" "frecpx h0, h1"
    testDisasm "5ee1f820" "frecpx d0, d1"
    testDisasm "5ea1f843" "frecpx s3, s2"

  /// C7.2.147 FRINT32X (vector)
  [<TestMethod>]
  member _.``C7.2.147 FRINT32X``() =
    testDisasm "1e68c020" "frint32x d0, d1"
    testDisasm "2e21e820" "frint32x v0.2s, v1.2s"
    testDisasm "6e61e820" "frint32x v0.2d, v1.2d"
    testDisasm "1e28c020" "frint32x s0, s1"

  /// C7.2.149 FRINT32Z (vector)
  [<TestMethod>]
  member _.``C7.2.149 FRINT32Z``() =
    testDisasm "1e684020" "frint32z d0, d1"
    testDisasm "0e21e820" "frint32z v0.2s, v1.2s"
    testDisasm "4e61e820" "frint32z v0.2d, v1.2d"
    testDisasm "1e284020" "frint32z s0, s1"

  /// C7.2.15 BFDOT (by element)
  [<TestMethod>]
  member _.``C7.2.15 BFDOT``() =
    testDisasm "2e42fc20" "bfdot v0.2s, v1.4h, v2.4h"
    testDisasm "0f62f020" "bfdot v0.2s, v1.4h, v2.2h[1]"

  /// C7.2.151 FRINT64X (vector)
  [<TestMethod>]
  member _.``C7.2.151 FRINT64X``() =
    testDisasm "1e69c020" "frint64x d0, d1"
    testDisasm "2e21f820" "frint64x v0.2s, v1.2s"
    testDisasm "6e61f820" "frint64x v0.2d, v1.2d"
    testDisasm "1e29c020" "frint64x s0, s1"

  /// C7.2.153 FRINT64Z (vector)
  [<TestMethod>]
  member _.``C7.2.153 FRINT64Z``() =
    testDisasm "1e694020" "frint64z d0, d1"
    testDisasm "0e21f820" "frint64z v0.2s, v1.2s"
    testDisasm "4e61f820" "frint64z v0.2d, v1.2d"
    testDisasm "1e294020" "frint64z s0, s1"

  /// C7.2.155 FRINTA (vector)
  [<TestMethod>]
  member _.``C7.2.155 FRINTA``() =
    testDisasm "2e798820" "frinta v0.4h, v1.4h"
    testDisasm "2e218820" "frinta v0.2s, v1.2s"
    testDisasm "6e618820" "frinta v0.2d, v1.2d"
    testDisasm "1ee64020" "frinta h0, h1"

  /// C7.2.157 FRINTI (vector)
  [<TestMethod>]
  member _.``C7.2.157 FRINTI``() =
    testDisasm "2ef99820" "frinti v0.4h, v1.4h"
    testDisasm "2ea19820" "frinti v0.2s, v1.2s"
    testDisasm "6ee19820" "frinti v0.2d, v1.2d"
    testDisasm "1ee7c020" "frinti h0, h1"

  /// C7.2.159 FRINTM (vector)
  [<TestMethod>]
  member _.``C7.2.159 FRINTM``() =
    testDisasm "0e799820" "frintm v0.4h, v1.4h"
    testDisasm "0e219820" "frintm v0.2s, v1.2s"
    testDisasm "4e619820" "frintm v0.2d, v1.2d"
    testDisasm "1ee54020" "frintm h0, h1"

  /// C7.2.161 FRINTN (vector)
  [<TestMethod>]
  member _.``C7.2.161 FRINTN``() =
    testDisasm "0e798820" "frintn v0.4h, v1.4h"
    testDisasm "0e218820" "frintn v0.2s, v1.2s"
    testDisasm "4e618820" "frintn v0.2d, v1.2d"
    testDisasm "1ee44020" "frintn h0, h1"

  /// C7.2.163 FRINTP (vector)
  [<TestMethod>]
  member _.``C7.2.163 FRINTP``() =
    testDisasm "0ef98820" "frintp v0.4h, v1.4h"
    testDisasm "0ea18820" "frintp v0.2s, v1.2s"
    testDisasm "4ee18820" "frintp v0.2d, v1.2d"
    testDisasm "1ee4c020" "frintp h0, h1"

  /// C7.2.165 FRINTX (vector)
  [<TestMethod>]
  member _.``C7.2.165 FRINTX``() =
    testDisasm "2e799820" "frintx v0.4h, v1.4h"
    testDisasm "2e219820" "frintx v0.2s, v1.2s"
    testDisasm "6e619820" "frintx v0.2d, v1.2d"
    testDisasm "1ee74020" "frintx h0, h1"

  /// C7.2.167 FRINTZ (vector)
  [<TestMethod>]
  member _.``C7.2.167 FRINTZ``() =
    testDisasm "0ef99820" "frintz v0.4h, v1.4h"
    testDisasm "0ea19820" "frintz v0.2s, v1.2s"
    testDisasm "4ee19820" "frintz v0.2d, v1.2d"
    testDisasm "1ee5c020" "frintz h0, h1"

  /// C7.2.169 FRSQRTE
  [<TestMethod>]
  member _.``C7.2.169 FRSQRTE``() =
    testDisasm "7ef9d820" "frsqrte h0, h1"
    testDisasm "2ef9d820" "frsqrte v0.4h, v1.4h"
    testDisasm "2ea1d820" "frsqrte v0.2s, v1.2s"
    testDisasm "6ee1d820" "frsqrte v0.2d, v1.2d"

  /// C7.2.17 BFMLALB, BFMLALT (by element)
  [<TestMethod>]
  member _.``C7.2.17 BFMLALB``() =
    testDisasm "2ec2fc20" "bfmlalb v0.4s, v1.8h, v2.8h"
    testDisasm "0fc1f043" "bfmlalb v3.4s, v2.8h, v1.h[0]"

  /// C7.2.17 BFMLALB, BFMLALT (by element)
  [<TestMethod>]
  member _.``C7.2.17 BFMLALT``() =
    testDisasm "6ec2fc20" "bfmlalt v0.4s, v1.8h, v2.8h"
    testDisasm "4fc1f043" "bfmlalt v3.4s, v2.8h, v1.h[0]"

  /// C7.2.170 FRSQRTS
  [<TestMethod>]
  member _.``C7.2.170 FRSQRTS``() =
    testDisasm "5ec23c20" "frsqrts h0, h1, h2"
    testDisasm "0ec23c20" "frsqrts v0.4h, v1.4h, v2.4h"
    testDisasm "0ea2fc20" "frsqrts v0.2s, v1.2s, v2.2s"
    testDisasm "4ee2fc20" "frsqrts v0.2d, v1.2d, v2.2d"

  /// C7.2.171 FSQRT (vector)
  [<TestMethod>]
  member _.``C7.2.171 FSQRT``() =
    testDisasm "2ef9f820" "fsqrt v0.4h, v1.4h"
    testDisasm "2ea1f820" "fsqrt v0.2s, v1.2s"
    testDisasm "6ee1f820" "fsqrt v0.2d, v1.2d"
    testDisasm "1ee1c020" "fsqrt h0, h1"

  /// C7.2.173 FSUB (vector)
  [<TestMethod>]
  member _.``C7.2.173 FSUB``() =
    testDisasm "0ec21420" "fsub v0.4h, v1.4h, v2.4h"
    testDisasm "0ea2d420" "fsub v0.2s, v1.2s, v2.2s"
    testDisasm "4ee2d420" "fsub v0.2d, v1.2d, v2.2d"
    testDisasm "1ee23820" "fsub h0, h1, h2"

  /// C7.2.175 INS (element)
  [<TestMethod>]
  member _.``C7.2.175 INS``() =
    testDisasm "4e081c20" "ins v0.d[0], x1"
    testDisasm "4e011c43" "ins v3.b[0], w2"
    testDisasm "4e141eb6" "ins v22.s[2], w21"
    testDisasm "4e1f1fff" "ins v31.b[15], wzr"

  /// C7.2.177 LD1 (multiple structures)
  [<TestMethod>]
  member _.``C7.2.177 LD1``() =
    testDisasm "4c407020" "ld1 { v0.16b }, [x1]"
    testDisasm "0c4023c0" "ld1 { v0.8b - v3.8b }, [x30]"
    testDisasm "0c4027c0" "ld1 { v0.4h - v3.4h }, [x30]"
    testDisasm "0c402bc0" "ld1 { v0.2s - v3.2s }, [x30]"

  /// C7.2.179 LD1R
  [<TestMethod>]
  member _.``C7.2.179 LD1R``() =
    testDisasm "4d40c020" "ld1r { v0.16b }, [x1]"
    testDisasm "0d40c7c0" "ld1r { v0.4h }, [x30]"
    testDisasm "0d40cbc0" "ld1r { v0.2s }, [x30]"
    testDisasm "0d40cfc0" "ld1r { v0.1d }, [x30]"

  /// C7.2.180 LD2 (multiple structures)
  [<TestMethod>]
  member _.``C7.2.180 LD2``() =
    testDisasm "4c408020" "ld2 { v0.16b, v1.16b }, [x1]"
    testDisasm "0c4087c0" "ld2 { v0.4h, v1.4h }, [x30]"
    testDisasm "0c408bc0" "ld2 { v0.2s, v1.2s }, [x30]"
    testDisasm "0cc18043" "ld2 { v3.8b, v4.8b }, [x2], x1"

  /// C7.2.182 LD2R
  [<TestMethod>]
  member _.``C7.2.182 LD2R``() =
    testDisasm "4d60c020" "ld2r { v0.16b, v1.16b }, [x1]"
    testDisasm "0d60c7c0" "ld2r { v0.4h, v1.4h }, [x30]"
    testDisasm "0d60cbc0" "ld2r { v0.2s, v1.2s }, [x30]"
    testDisasm "0d60cfc0" "ld2r { v0.1d, v1.1d }, [x30]"

  /// C7.2.183 LD3 (multiple structures)
  [<TestMethod>]
  member _.``C7.2.183 LD3``() =
    testDisasm "4c404020" "ld3 { v0.16b, v1.16b, v2.16b }, [x1]"
    testDisasm "0c4047c0" "ld3 { v0.4h, v1.4h, v2.4h }, [x30]"
    testDisasm "0c404bc0" "ld3 { v0.2s, v1.2s, v2.2s }, [x30]"
    testDisasm "0cc14043" "ld3 { v3.8b, v4.8b, v5.8b }, [x2], x1"

  /// C7.2.185 LD3R
  [<TestMethod>]
  member _.``C7.2.185 LD3R``() =
    testDisasm "4d40e020" "ld3r { v0.16b, v1.16b, v2.16b }, [x1]"
    testDisasm "0d40e7c0" "ld3r { v0.4h, v1.4h, v2.4h }, [x30]"
    testDisasm "0d40ebc0" "ld3r { v0.2s, v1.2s, v2.2s }, [x30]"
    testDisasm "0d40efc0" "ld3r { v0.1d, v1.1d, v2.1d }, [x30]"

  /// C7.2.186 LD4 (multiple structures)
  [<TestMethod>]
  member _.``C7.2.186 LD4``() =
    testDisasm "4c400020" "ld4 { v0.16b - v3.16b }, [x1]"
    testDisasm "0c4007c0" "ld4 { v0.4h - v3.4h }, [x30]"
    testDisasm "0c400bc0" "ld4 { v0.2s - v3.2s }, [x30]"
    testDisasm "0cc10043" "ld4 { v3.8b - v6.8b }, [x2], x1"

  /// C7.2.188 LD4R
  [<TestMethod>]
  member _.``C7.2.188 LD4R``() =
    testDisasm "4d60e020" "ld4r { v0.16b - v3.16b }, [x1]"
    testDisasm "0d60e7c0" "ld4r { v0.4h - v3.4h }, [x30]"
    testDisasm "0d60ebc0" "ld4r { v0.2s - v3.2s }, [x30]"
    testDisasm "0d60efc0" "ld4r { v0.1d - v3.1d }, [x30]"

  /// C7.2.19 BFMMLA
  [<TestMethod>]
  member _.``C7.2.19 BFMMLA``() =
    testDisasm "6e42ec20" "bfmmla v0.4s, v1.8h, v2.8h"

  /// C7.2.195 MLA (by element)
  [<TestMethod>]
  member _.``C7.2.195 MLA``() =
    testDisasm "2f520020" "mla v0.4h, v1.4h, v2.h[1]"
    testDisasm "2fa20020" "mla v0.2s, v1.2s, v2.s[1]"
    testDisasm "0e229420" "mla v0.8b, v1.8b, v2.8b"
    testDisasm "0e629420" "mla v0.4h, v1.4h, v2.4h"

  /// C7.2.197 MLS (by element)
  [<TestMethod>]
  member _.``C7.2.197 MLS``() =
    testDisasm "2f524020" "mls v0.4h, v1.4h, v2.h[1]"
    testDisasm "2fa24020" "mls v0.2s, v1.2s, v2.s[1]"
    testDisasm "2e229420" "mls v0.8b, v1.8b, v2.8b"
    testDisasm "2e629420" "mls v0.4h, v1.4h, v2.4h"

  /// C7.2.204 MOVI
  [<TestMethod>]
  member _.``C7.2.204 MOVI``() =
    testDisasm "0f00e460" "movi v0.8b, #0x3"
    testDisasm "0f008460" "movi v0.4h, #0x3"
    testDisasm "0f000460" "movi v0.2s, #0x3"
    testDisasm "0f012443" "movi v3.2s, #0x22, lsl #0x8"

  /// C7.2.208 MVNI
  [<TestMethod>]
  member _.``C7.2.208 MVNI``() =
    testDisasm "2f008460" "mvni v0.4h, #0x3"
    testDisasm "2f000460" "mvni v0.2s, #0x3"
    testDisasm "2f012443" "mvni v3.2s, #0x22, lsl #0x8"
    testDisasm "2f01a443" "mvni v3.4h, #0x22, lsl #0x8"

  /// C7.2.210 NOT
  [<TestMethod>]
  member _.``C7.2.210 NOT``() =
    testDisasm "6e205820" "mvn v0.16b, v1.16b"

  /// C7.2.214 PMUL
  [<TestMethod>]
  member _.``C7.2.214 PMUL``() =
    testDisasm "2e229c20" "pmul v0.8b, v1.8b, v2.8b"

  /// C7.2.215 PMULL, PMULL2
  [<TestMethod>]
  member _.``C7.2.215 PMULL``() =
    testDisasm "0e22e020" "pmull v0.8h, v1.8b, v2.8b"
    testDisasm "0ee1e043" "pmull v3.1q, v2.1d, v1.1d"

  /// C7.2.215 PMULL, PMULL2
  [<TestMethod>]
  member _.``C7.2.215 PMULL2``() =
    testDisasm "4e22e020" "pmull2 v0.8h, v1.16b, v2.16b"
    testDisasm "4ee1e043" "pmull2 v3.1q, v2.2d, v1.2d"

  /// C7.2.216 RADDHN, RADDHN2
  [<TestMethod>]
  member _.``C7.2.216 RADDHN``() =
    testDisasm "2e224020" "raddhn v0.8b, v1.8h, v2.8h"
    testDisasm "2ea24020" "raddhn v0.2s, v1.2d, v2.2d"
    testDisasm "2e624020" "raddhn v0.4h, v1.4s, v2.4s"

  /// C7.2.216 RADDHN, RADDHN2
  [<TestMethod>]
  member _.``C7.2.216 RADDHN2``() =
    testDisasm "6e624020" "raddhn2 v0.8h, v1.4s, v2.4s"
    testDisasm "6ea24020" "raddhn2 v0.4s, v1.2d, v2.2d"
    testDisasm "6e224020" "raddhn2 v0.16b, v1.8h, v2.8h"

  /// C7.2.217 RAX1
  [<TestMethod>]
  member _.``C7.2.217 RAX1``() =
    testDisasm "ce628c20" "rax1 v0.2d, v1.2d, v2.2d"

  /// C7.2.22 BIF
  [<TestMethod>]
  member _.``C7.2.22 BIF``() =
    testDisasm "6ee21c20" "bif v0.16b, v1.16b, v2.16b"

  /// C7.2.222 RSHRN, RSHRN2
  [<TestMethod>]
  member _.``C7.2.222 RSHRN``() =
    testDisasm "0f1f8c20" "rshrn v0.4h, v1.4s, #0x1"
    testDisasm "0f0f8c20" "rshrn v0.8b, v1.8h, #0x1"
    testDisasm "0f3f8c20" "rshrn v0.2s, v1.2d, #0x1"

  /// C7.2.222 RSHRN, RSHRN2
  [<TestMethod>]
  member _.``C7.2.222 RSHRN2``() =
    testDisasm "4f1f8c20" "rshrn2 v0.8h, v1.4s, #0x1"
    testDisasm "4f3f8c20" "rshrn2 v0.4s, v1.2d, #0x1"
    testDisasm "4f0f8c20" "rshrn2 v0.16b, v1.8h, #0x1"

  /// C7.2.223 RSUBHN, RSUBHN2
  [<TestMethod>]
  member _.``C7.2.223 RSUBHN``() =
    testDisasm "2e226020" "rsubhn v0.8b, v1.8h, v2.8h"
    testDisasm "2ea26020" "rsubhn v0.2s, v1.2d, v2.2d"
    testDisasm "2e626020" "rsubhn v0.4h, v1.4s, v2.4s"

  /// C7.2.223 RSUBHN, RSUBHN2
  [<TestMethod>]
  member _.``C7.2.223 RSUBHN2``() =
    testDisasm "6e626020" "rsubhn2 v0.8h, v1.4s, v2.4s"
    testDisasm "6ea26020" "rsubhn2 v0.4s, v1.2d, v2.2d"
    testDisasm "6e226020" "rsubhn2 v0.16b, v1.8h, v2.8h"

  /// C7.2.224 SABA
  [<TestMethod>]
  member _.``C7.2.224 SABA``() =
    testDisasm "0e227c20" "saba v0.8b, v1.8b, v2.8b"
    testDisasm "0e627c20" "saba v0.4h, v1.4h, v2.4h"
    testDisasm "0ea27c20" "saba v0.2s, v1.2s, v2.2s"

  /// C7.2.225 SABAL, SABAL2
  [<TestMethod>]
  member _.``C7.2.225 SABAL``() =
    testDisasm "0e625020" "sabal v0.4s, v1.4h, v2.4h"
    testDisasm "0e225020" "sabal v0.8h, v1.8b, v2.8b"
    testDisasm "0ea25020" "sabal v0.2d, v1.2s, v2.2s"

  /// C7.2.225 SABAL, SABAL2
  [<TestMethod>]
  member _.``C7.2.225 SABAL2``() =
    testDisasm "4e225020" "sabal2 v0.8h, v1.16b, v2.16b"
    testDisasm "4ea25020" "sabal2 v0.2d, v1.4s, v2.4s"
    testDisasm "4e625020" "sabal2 v0.4s, v1.8h, v2.8h"

  /// C7.2.226 SABD
  [<TestMethod>]
  member _.``C7.2.226 SABD``() =
    testDisasm "0e227420" "sabd v0.8b, v1.8b, v2.8b"
    testDisasm "0e627420" "sabd v0.4h, v1.4h, v2.4h"
    testDisasm "0ea27420" "sabd v0.2s, v1.2s, v2.2s"

  /// C7.2.227 SABDL, SABDL2
  [<TestMethod>]
  member _.``C7.2.227 SABDL``() =
    testDisasm "0e627020" "sabdl v0.4s, v1.4h, v2.4h"
    testDisasm "0e227020" "sabdl v0.8h, v1.8b, v2.8b"
    testDisasm "0ea27020" "sabdl v0.2d, v1.2s, v2.2s"

  /// C7.2.227 SABDL, SABDL2
  [<TestMethod>]
  member _.``C7.2.227 SABDL2``() =
    testDisasm "4e227020" "sabdl2 v0.8h, v1.16b, v2.16b"
    testDisasm "4ea27020" "sabdl2 v0.2d, v1.4s, v2.4s"
    testDisasm "4e627020" "sabdl2 v0.4s, v1.8h, v2.8h"

  /// C7.2.228 SADALP
  [<TestMethod>]
  member _.``C7.2.228 SADALP``() =
    testDisasm "0e206820" "sadalp v0.4h, v1.8b"
    testDisasm "0e606820" "sadalp v0.2s, v1.4h"
    testDisasm "4ea06820" "sadalp v0.2d, v1.4s"

  /// C7.2.229 SADDL, SADDL2
  [<TestMethod>]
  member _.``C7.2.229 SADDL``() =
    testDisasm "0e620020" "saddl v0.4s, v1.4h, v2.4h"
    testDisasm "0e220020" "saddl v0.8h, v1.8b, v2.8b"
    testDisasm "0ea20020" "saddl v0.2d, v1.2s, v2.2s"

  /// C7.2.229 SADDL, SADDL2
  [<TestMethod>]
  member _.``C7.2.229 SADDL2``() =
    testDisasm "4e220020" "saddl2 v0.8h, v1.16b, v2.16b"
    testDisasm "4ea20020" "saddl2 v0.2d, v1.4s, v2.4s"
    testDisasm "4e620020" "saddl2 v0.4s, v1.8h, v2.8h"

  /// C7.2.23 BIT
  [<TestMethod>]
  member _.``C7.2.23 BIT``() =
    testDisasm "6ea21c20" "bit v0.16b, v1.16b, v2.16b"

  /// C7.2.230 SADDLP
  [<TestMethod>]
  member _.``C7.2.230 SADDLP``() =
    testDisasm "0e202820" "saddlp v0.4h, v1.8b"
    testDisasm "0e602820" "saddlp v0.2s, v1.4h"
    testDisasm "4ea02820" "saddlp v0.2d, v1.4s"

  /// C7.2.231 SADDLV
  [<TestMethod>]
  member _.``C7.2.231 SADDLV``() =
    testDisasm "0e303820" "saddlv h0, v1.8b"
    testDisasm "0e703843" "saddlv s3, v2.4h"
    testDisasm "4eb03843" "saddlv d3, v2.4s"

  /// C7.2.232 SADDW, SADDW2
  [<TestMethod>]
  member _.``C7.2.232 SADDW``() =
    testDisasm "0e621020" "saddw v0.4s, v1.4s, v2.4h"
    testDisasm "0e221020" "saddw v0.8h, v1.8h, v2.8b"
    testDisasm "0ea21020" "saddw v0.2d, v1.2d, v2.2s"

  /// C7.2.232 SADDW, SADDW2
  [<TestMethod>]
  member _.``C7.2.232 SADDW2``() =
    testDisasm "4e221020" "saddw2 v0.8h, v1.8h, v2.16b"
    testDisasm "4ea21020" "saddw2 v0.2d, v1.2d, v2.4s"
    testDisasm "4e621020" "saddw2 v0.4s, v1.4s, v2.8h"

  /// C7.2.233 SCVTF (vector, fixed-point)
  [<TestMethod>]
  member _.``C7.2.233 SCVTF``() =
    testDisasm "0f1be420" "scvtf v0.4h, v1.4h, #5"
    testDisasm "0f3be420" "scvtf v0.2s, v1.2s, #5"
    testDisasm "4f7be420" "scvtf v0.2d, v1.2d, #5"
    testDisasm "5e79d820" "scvtf h0, h1"

  /// C7.2.237 SDOT (by element)
  [<TestMethod>]
  member _.``C7.2.237 SDOT``() =
    testDisasm "0e829420" "sdot v0.2s, v1.8b, v2.8b"
    testDisasm "0f81e043" "sdot v3.2s, v2.8b, v1.4b[0]"

  /// C7.2.239 SHA1C
  [<TestMethod>]
  member _.``C7.2.239 SHA1C``() =
    testDisasm "5e020020" "sha1c q0, s1, v2.4s"

  /// C7.2.24 BSL
  [<TestMethod>]
  member _.``C7.2.24 BSL``() =
    testDisasm "6e621c20" "bsl v0.16b, v1.16b, v2.16b"

  /// C7.2.240 SHA1H
  [<TestMethod>]
  member _.``C7.2.240 SHA1H``() =
    testDisasm "5e280820" "sha1h s0, s1"

  /// C7.2.241 SHA1M
  [<TestMethod>]
  member _.``C7.2.241 SHA1M``() =
    testDisasm "5e022020" "sha1m q0, s1, v2.4s"

  /// C7.2.242 SHA1P
  [<TestMethod>]
  member _.``C7.2.242 SHA1P``() =
    testDisasm "5e021020" "sha1p q0, s1, v2.4s"

  /// C7.2.243 SHA1SU0
  [<TestMethod>]
  member _.``C7.2.243 SHA1SU0``() =
    testDisasm "5e023020" "sha1su0 v0.4s, v1.4s, v2.4s"

  /// C7.2.244 SHA1SU1
  [<TestMethod>]
  member _.``C7.2.244 SHA1SU1``() =
    testDisasm "5e281820" "sha1su1 v0.4s, v1.4s"

  /// C7.2.245 SHA256H2
  [<TestMethod>]
  member _.``C7.2.245 SHA256H2``() =
    testDisasm "5e025020" "sha256h2 q0, q1, v2.4s"

  /// C7.2.246 SHA256H
  [<TestMethod>]
  member _.``C7.2.246 SHA256H``() =
    testDisasm "5e024020" "sha256h q0, q1, v2.4s"

  /// C7.2.247 SHA256SU0
  [<TestMethod>]
  member _.``C7.2.247 SHA256SU0``() =
    testDisasm "5e282820" "sha256su0 v0.4s, v1.4s"

  /// C7.2.248 SHA256SU1
  [<TestMethod>]
  member _.``C7.2.248 SHA256SU1``() =
    testDisasm "5e026020" "sha256su1 v0.4s, v1.4s, v2.4s"

  /// C7.2.249 SHA512H
  [<TestMethod>]
  member _.``C7.2.249 SHA512H``() =
    testDisasm "ce628020" "sha512h q0, q1, v2.2d"

  /// C7.2.250 SHA512H2
  [<TestMethod>]
  member _.``C7.2.250 SHA512H2``() =
    testDisasm "ce628420" "sha512h2 q0, q1, v2.2d"

  /// C7.2.251 SHA512SU0
  [<TestMethod>]
  member _.``C7.2.251 SHA512SU0``() =
    testDisasm "cec08020" "sha512su0 v0.2d, v1.2d"

  /// C7.2.252 SHA512SU1
  [<TestMethod>]
  member _.``C7.2.252 SHA512SU1``() =
    testDisasm "ce628820" "sha512su1 v0.2d, v1.2d, v2.2d"

  /// C7.2.253 SHADD
  [<TestMethod>]
  member _.``C7.2.253 SHADD``() =
    testDisasm "0e220420" "shadd v0.8b, v1.8b, v2.8b"
    testDisasm "0e620420" "shadd v0.4h, v1.4h, v2.4h"
    testDisasm "0ea20420" "shadd v0.2s, v1.2s, v2.2s"

  /// C7.2.254 SHL
  [<TestMethod>]
  member _.``C7.2.254 SHL``() =
    testDisasm "0f095420" "shl v0.8b, v1.8b, #0x1"
    testDisasm "0f115420" "shl v0.4h, v1.4h, #0x1"
    testDisasm "0f215420" "shl v0.2s, v1.2s, #0x1"
    testDisasm "4f415420" "shl v0.2d, v1.2d, #0x1"

  /// C7.2.255 SHLL, SHLL2
  [<TestMethod>]
  member _.``C7.2.255 SHLL``() =
    testDisasm "2e613820" "shll v0.4s, v1.4h, #0x10"
    testDisasm "2e213843" "shll v3.8h, v2.8b, #0x8"
    testDisasm "2ea13843" "shll v3.2d, v2.2s, #0x20"

  /// C7.2.255 SHLL, SHLL2
  [<TestMethod>]
  member _.``C7.2.255 SHLL2``() =
    testDisasm "6e213820" "shll2 v0.8h, v1.16b, #0x8"
    testDisasm "6e613843" "shll2 v3.4s, v2.8h, #0x10"
    testDisasm "6ea13843" "shll2 v3.2d, v2.4s, #0x20"

  /// C7.2.256 SHRN, SHRN2
  [<TestMethod>]
  member _.``C7.2.256 SHRN``() =
    testDisasm "0f1f8420" "shrn v0.4h, v1.4s, #0x1"
    testDisasm "0f0f8420" "shrn v0.8b, v1.8h, #0x1"
    testDisasm "0f3f8420" "shrn v0.2s, v1.2d, #0x1"

  /// C7.2.256 SHRN, SHRN2
  [<TestMethod>]
  member _.``C7.2.256 SHRN2``() =
    testDisasm "4f1f8420" "shrn2 v0.8h, v1.4s, #0x1"
    testDisasm "4f3f8420" "shrn2 v0.4s, v1.2d, #0x1"
    testDisasm "4f0f8420" "shrn2 v0.16b, v1.8h, #0x1"

  /// C7.2.257 SHSUB
  [<TestMethod>]
  member _.``C7.2.257 SHSUB``() =
    testDisasm "0e222420" "shsub v0.8b, v1.8b, v2.8b"
    testDisasm "0e622420" "shsub v0.4h, v1.4h, v2.4h"
    testDisasm "0ea22420" "shsub v0.2s, v1.2s, v2.2s"

  /// C7.2.258 SLI
  [<TestMethod>]
  member _.``C7.2.258 SLI``() =
    testDisasm "2f095420" "sli v0.8b, v1.8b, #0x1"
    testDisasm "2f115420" "sli v0.4h, v1.4h, #0x1"
    testDisasm "2f215420" "sli v0.2s, v1.2s, #0x1"
    testDisasm "6f415420" "sli v0.2d, v1.2d, #0x1"

  /// C7.2.259 SM3PARTW1
  [<TestMethod>]
  member _.``C7.2.259 SM3PARTW1``() =
    testDisasm "ce62c020" "sm3partw1 v0.4s, v1.4s, v2.4s"

  /// C7.2.260 SM3PARTW2
  [<TestMethod>]
  member _.``C7.2.260 SM3PARTW2``() =
    testDisasm "ce62c420" "sm3partw2 v0.4s, v1.4s, v2.4s"

  /// C7.2.261 SM3SS1
  [<TestMethod>]
  member _.``C7.2.261 SM3SS1``() =
    testDisasm "ce420c20" "sm3ss1 v0.4s, v1.4s, v2.4s, v3.4s"

  /// C7.2.262 SM3TT1A
  [<TestMethod>]
  member _.``C7.2.262 SM3TT1A``() =
    testDisasm "ce428020" "sm3tt1a v0.4s, v1.4s, v2.s[0]"

  /// C7.2.263 SM3TT1B
  [<TestMethod>]
  member _.``C7.2.263 SM3TT1B``() =
    testDisasm "ce428420" "sm3tt1b v0.4s, v1.4s, v2.s[0]"

  /// C7.2.264 SM3TT2A
  [<TestMethod>]
  member _.``C7.2.264 SM3TT2A``() =
    testDisasm "ce428820" "sm3tt2a v0.4s, v1.4s, v2.s[0]"

  /// C7.2.265 SM3TT2B
  [<TestMethod>]
  member _.``C7.2.265 SM3TT2B``() =
    testDisasm "ce428c20" "sm3tt2b v0.4s, v1.4s, v2.s[0]"

  /// C7.2.266 SM4E
  [<TestMethod>]
  member _.``C7.2.266 SM4E``() =
    testDisasm "cec08420" "sm4e v0.4s, v1.4s"

  /// C7.2.267 SM4EKEY
  [<TestMethod>]
  member _.``C7.2.267 SM4EKEY``() =
    testDisasm "ce62c820" "sm4ekey v0.4s, v1.4s, v2.4s"

  /// C7.2.268 SMAX
  [<TestMethod>]
  member _.``C7.2.268 SMAX``() =
    testDisasm "0e226420" "smax v0.8b, v1.8b, v2.8b"
    testDisasm "0e626420" "smax v0.4h, v1.4h, v2.4h"
    testDisasm "0ea26420" "smax v0.2s, v1.2s, v2.2s"

  /// C7.2.269 SMAXP
  [<TestMethod>]
  member _.``C7.2.269 SMAXP``() =
    testDisasm "0e22a420" "smaxp v0.8b, v1.8b, v2.8b"
    testDisasm "0e62a420" "smaxp v0.4h, v1.4h, v2.4h"
    testDisasm "0ea2a420" "smaxp v0.2s, v1.2s, v2.2s"

  /// C7.2.27 CMEQ (register)
  [<TestMethod>]
  member _.``C7.2.27 CMEQ``() =
    testDisasm "2e228c20" "cmeq v0.8b, v1.8b, v2.8b"
    testDisasm "2e628c20" "cmeq v0.4h, v1.4h, v2.4h"
    testDisasm "2ea28c20" "cmeq v0.2s, v1.2s, v2.2s"
    testDisasm "6ee28c20" "cmeq v0.2d, v1.2d, v2.2d"

  /// C7.2.270 SMAXV
  [<TestMethod>]
  member _.``C7.2.270 SMAXV``() =
    testDisasm "4eb0a820" "smaxv s0, v1.4s"
    testDisasm "0e30a843" "smaxv b3, v2.8b"
    testDisasm "0e70a843" "smaxv h3, v2.4h"

  /// C7.2.271 SMIN
  [<TestMethod>]
  member _.``C7.2.271 SMIN``() =
    testDisasm "0e226c20" "smin v0.8b, v1.8b, v2.8b"
    testDisasm "0e626c20" "smin v0.4h, v1.4h, v2.4h"
    testDisasm "0ea26c20" "smin v0.2s, v1.2s, v2.2s"

  /// C7.2.272 SMINP
  [<TestMethod>]
  member _.``C7.2.272 SMINP``() =
    testDisasm "0e22ac20" "sminp v0.8b, v1.8b, v2.8b"
    testDisasm "0e62ac20" "sminp v0.4h, v1.4h, v2.4h"
    testDisasm "0ea2ac20" "sminp v0.2s, v1.2s, v2.2s"

  /// C7.2.273 SMINV
  [<TestMethod>]
  member _.``C7.2.273 SMINV``() =
    testDisasm "4eb1a820" "sminv s0, v1.4s"
    testDisasm "0e31a843" "sminv b3, v2.8b"
    testDisasm "0e71a843" "sminv h3, v2.4h"

  /// C7.2.274 SMLAL, SMLAL2 (by element)
  [<TestMethod>]
  member _.``C7.2.274 SMLAL``() =
    testDisasm "0e628020" "smlal v0.4s, v1.4h, v2.4h"
    testDisasm "0f522020" "smlal v0.4s, v1.4h, v2.h[1]"
    testDisasm "0fa22020" "smlal v0.2d, v1.2s, v2.s[1]"
    testDisasm "0e228020" "smlal v0.8h, v1.8b, v2.8b"

  /// C7.2.274 SMLAL, SMLAL2 (by element)
  [<TestMethod>]
  member _.``C7.2.274 SMLAL2``() =
    testDisasm "4f522020" "smlal2 v0.4s, v1.8h, v2.h[1]"
    testDisasm "4fa22020" "smlal2 v0.2d, v1.4s, v2.s[1]"
    testDisasm "4e228020" "smlal2 v0.8h, v1.16b, v2.16b"
    testDisasm "4ea28020" "smlal2 v0.2d, v1.4s, v2.4s"

  /// C7.2.276 SMLSL, SMLSL2 (by element)
  [<TestMethod>]
  member _.``C7.2.276 SMLSL``() =
    testDisasm "0e62a020" "smlsl v0.4s, v1.4h, v2.4h"
    testDisasm "0f526020" "smlsl v0.4s, v1.4h, v2.h[1]"
    testDisasm "0fa26020" "smlsl v0.2d, v1.2s, v2.s[1]"
    testDisasm "0e22a020" "smlsl v0.8h, v1.8b, v2.8b"

  /// C7.2.276 SMLSL, SMLSL2 (by element)
  [<TestMethod>]
  member _.``C7.2.276 SMLSL2``() =
    testDisasm "4f526020" "smlsl2 v0.4s, v1.8h, v2.h[1]"
    testDisasm "4fa26020" "smlsl2 v0.2d, v1.4s, v2.s[1]"
    testDisasm "4e22a020" "smlsl2 v0.8h, v1.16b, v2.16b"
    testDisasm "4ea2a020" "smlsl2 v0.2d, v1.4s, v2.4s"

  /// C7.2.278 SMMLA (vector)
  [<TestMethod>]
  member _.``C7.2.278 SMMLA``() =
    testDisasm "4e82a420" "smmla v0.4s, v1.16b, v2.16b"

  /// C7.2.279 SMOV
  [<TestMethod>]
  member _.``C7.2.279 SMOV``() =
    testDisasm "0e032c20" "smov w0, v1.b[1]"
    testDisasm "0e062c20" "smov w0, v1.h[1]"
    testDisasm "4e032c20" "smov x0, v1.b[1]"
    testDisasm "4e062c20" "smov x0, v1.h[1]"

  /// C7.2.280 SMULL, SMULL2 (by element)
  [<TestMethod>]
  member _.``C7.2.280 SMULL2``() =
    testDisasm "4f52a020" "smull2 v0.4s, v1.8h, v2.h[1]"
    testDisasm "4fa2a020" "smull2 v0.2d, v1.4s, v2.s[1]"
    testDisasm "4e62c020" "smull2 v0.4s, v1.8h, v2.8h"
    testDisasm "4ea2c020" "smull2 v0.2d, v1.4s, v2.4s"

  /// C7.2.282 SQABS
  [<TestMethod>]
  member _.``C7.2.282 SQABS``() =
    testDisasm "0e207820" "sqabs v0.8b, v1.8b"
    testDisasm "0e607820" "sqabs v0.4h, v1.4h"
    testDisasm "0ea07820" "sqabs v0.2s, v1.2s"
    testDisasm "4ee07820" "sqabs v0.2d, v1.2d"

  /// C7.2.283 SQADD
  [<TestMethod>]
  member _.``C7.2.283 SQADD``() =
    testDisasm "0e220c20" "sqadd v0.8b, v1.8b, v2.8b"
    testDisasm "0e620c20" "sqadd v0.4h, v1.4h, v2.4h"
    testDisasm "0ea20c20" "sqadd v0.2s, v1.2s, v2.2s"
    testDisasm "4ee20c20" "sqadd v0.2d, v1.2d, v2.2d"

  /// C7.2.284 SQDMLAL, SQDMLAL2 (by element)
  [<TestMethod>]
  member _.``C7.2.284 SQDMLAL``() =
    testDisasm "0f523020" "sqdmlal v0.4s, v1.4h, v2.h[1]"
    testDisasm "0fa23020" "sqdmlal v0.2d, v1.2s, v2.s[1]"
    testDisasm "0ea29020" "sqdmlal v0.2d, v1.2s, v2.2s"
    testDisasm "0e629020" "sqdmlal v0.4s, v1.4h, v2.4h"

  /// C7.2.284 SQDMLAL, SQDMLAL2 (by element)
  [<TestMethod>]
  member _.``C7.2.284 SQDMLAL2``() =
    testDisasm "4f523020" "sqdmlal2 v0.4s, v1.8h, v2.h[1]"
    testDisasm "4fa23020" "sqdmlal2 v0.2d, v1.4s, v2.s[1]"
    testDisasm "4ea29020" "sqdmlal2 v0.2d, v1.4s, v2.4s"
    testDisasm "4e629020" "sqdmlal2 v0.4s, v1.8h, v2.8h"

  /// C7.2.286 SQDMLSL, SQDMLSL2 (by element)
  [<TestMethod>]
  member _.``C7.2.286 SQDMLSL``() =
    testDisasm "0f527020" "sqdmlsl v0.4s, v1.4h, v2.h[1]"
    testDisasm "0fa27020" "sqdmlsl v0.2d, v1.2s, v2.s[1]"
    testDisasm "0ea2b020" "sqdmlsl v0.2d, v1.2s, v2.2s"
    testDisasm "0e62b020" "sqdmlsl v0.4s, v1.4h, v2.4h"

  /// C7.2.286 SQDMLSL, SQDMLSL2 (by element)
  [<TestMethod>]
  member _.``C7.2.286 SQDMLSL2``() =
    testDisasm "4f527020" "sqdmlsl2 v0.4s, v1.8h, v2.h[1]"
    testDisasm "4fa27020" "sqdmlsl2 v0.2d, v1.4s, v2.s[1]"
    testDisasm "4ea2b020" "sqdmlsl2 v0.2d, v1.4s, v2.4s"
    testDisasm "4e62b020" "sqdmlsl2 v0.4s, v1.8h, v2.8h"

  /// C7.2.288 SQDMULH (by element)
  [<TestMethod>]
  member _.``C7.2.288 SQDMULH``() =
    testDisasm "0f52c020" "sqdmulh v0.4h, v1.4h, v2.h[1]"
    testDisasm "0fa2c020" "sqdmulh v0.2s, v1.2s, v2.s[1]"
    testDisasm "0e62b420" "sqdmulh v0.4h, v1.4h, v2.4h"
    testDisasm "0ea2b420" "sqdmulh v0.2s, v1.2s, v2.2s"

  /// C7.2.29 CMGE (register)
  [<TestMethod>]
  member _.``C7.2.29 CMGE``() =
    testDisasm "0e223c20" "cmge v0.8b, v1.8b, v2.8b"
    testDisasm "0e623c20" "cmge v0.4h, v1.4h, v2.4h"
    testDisasm "0ea23c20" "cmge v0.2s, v1.2s, v2.2s"
    testDisasm "4ee23c20" "cmge v0.2d, v1.2d, v2.2d"

  /// C7.2.290 SQDMULL, SQDMULL2 (by element)
  [<TestMethod>]
  member _.``C7.2.290 SQDMULL``() =
    testDisasm "0f52b020" "sqdmull v0.4s, v1.4h, v2.h[1]"
    testDisasm "0fa2b020" "sqdmull v0.2d, v1.2s, v2.s[1]"
    testDisasm "0ea2d020" "sqdmull v0.2d, v1.2s, v2.2s"
    testDisasm "0e62d020" "sqdmull v0.4s, v1.4h, v2.4h"

  /// C7.2.290 SQDMULL, SQDMULL2 (by element)
  [<TestMethod>]
  member _.``C7.2.290 SQDMULL2``() =
    testDisasm "4f52b020" "sqdmull2 v0.4s, v1.8h, v2.h[1]"
    testDisasm "4fa2b020" "sqdmull2 v0.2d, v1.4s, v2.s[1]"
    testDisasm "4ea2d020" "sqdmull2 v0.2d, v1.4s, v2.4s"
    testDisasm "4e62d020" "sqdmull2 v0.4s, v1.8h, v2.8h"

  /// C7.2.292 SQNEG
  [<TestMethod>]
  member _.``C7.2.292 SQNEG``() =
    testDisasm "2e207820" "sqneg v0.8b, v1.8b"
    testDisasm "2e607820" "sqneg v0.4h, v1.4h"
    testDisasm "2ea07820" "sqneg v0.2s, v1.2s"
    testDisasm "6ee07820" "sqneg v0.2d, v1.2d"

  /// C7.2.293 SQRDMLAH (by element)
  [<TestMethod>]
  member _.``C7.2.293 SQRDMLAH``() =
    testDisasm "2f52d020" "sqrdmlah v0.4h, v1.4h, v2.h[1]"
    testDisasm "2fa2d020" "sqrdmlah v0.2s, v1.2s, v2.s[1]"
    testDisasm "2e428420" "sqrdmlah v0.4h, v1.4h, v2.4h"
    testDisasm "2e828420" "sqrdmlah v0.2s, v1.2s, v2.2s"

  /// C7.2.295 SQRDMLSH (by element)
  [<TestMethod>]
  member _.``C7.2.295 SQRDMLSH``() =
    testDisasm "2f52f020" "sqrdmlsh v0.4h, v1.4h, v2.h[1]"
    testDisasm "2fa2f020" "sqrdmlsh v0.2s, v1.2s, v2.s[1]"
    testDisasm "2e428c20" "sqrdmlsh v0.4h, v1.4h, v2.4h"
    testDisasm "2e828c20" "sqrdmlsh v0.2s, v1.2s, v2.2s"

  /// C7.2.297 SQRDMULH (by element)
  [<TestMethod>]
  member _.``C7.2.297 SQRDMULH``() =
    testDisasm "0f52d020" "sqrdmulh v0.4h, v1.4h, v2.h[1]"
    testDisasm "0fa2d020" "sqrdmulh v0.2s, v1.2s, v2.s[1]"
    testDisasm "2e62b420" "sqrdmulh v0.4h, v1.4h, v2.4h"
    testDisasm "2ea2b420" "sqrdmulh v0.2s, v1.2s, v2.2s"

  /// C7.2.299 SQRSHL
  [<TestMethod>]
  member _.``C7.2.299 SQRSHL``() =
    testDisasm "0e225c20" "sqrshl v0.8b, v1.8b, v2.8b"
    testDisasm "0e625c20" "sqrshl v0.4h, v1.4h, v2.4h"
    testDisasm "0ea25c20" "sqrshl v0.2s, v1.2s, v2.2s"
    testDisasm "4ee25c20" "sqrshl v0.2d, v1.2d, v2.2d"

  /// C7.2.3 ADDHN, ADDHN2
  [<TestMethod>]
  member _.``C7.2.3 ADDHN``() =
    testDisasm "0e624020" "addhn v0.4h, v1.4s, v2.4s"
    testDisasm "0ea24020" "addhn v0.2s, v1.2d, v2.2d"
    testDisasm "0e224020" "addhn v0.8b, v1.8h, v2.8h"

  /// C7.2.3 ADDHN, ADDHN2
  [<TestMethod>]
  member _.``C7.2.3 ADDHN2``() =
    testDisasm "4e624020" "addhn2 v0.8h, v1.4s, v2.4s"
    testDisasm "4ea24020" "addhn2 v0.4s, v1.2d, v2.2d"
    testDisasm "4e224020" "addhn2 v0.16b, v1.8h, v2.8h"

  /// C7.2.300 SQRSHRN, SQRSHRN2
  [<TestMethod>]
  member _.``C7.2.300 SQRSHRN``() =
    testDisasm "0f1f9c20" "sqrshrn v0.4h, v1.4s, #0x1"
    testDisasm "0f3f9c20" "sqrshrn v0.2s, v1.2d, #0x1"
    testDisasm "0f0f9c20" "sqrshrn v0.8b, v1.8h, #0x1"
    testDisasm "5f149eb6" "sqrshrn h22, s21, #0xc"

  /// C7.2.300 SQRSHRN, SQRSHRN2
  [<TestMethod>]
  member _.``C7.2.300 SQRSHRN2``() =
    testDisasm "4f1f9c20" "sqrshrn2 v0.8h, v1.4s, #0x1"
    testDisasm "4f3f9c20" "sqrshrn2 v0.4s, v1.2d, #0x1"
    testDisasm "4f0f9c20" "sqrshrn2 v0.16b, v1.8h, #0x1"

  /// C7.2.301 SQRSHRUN, SQRSHRUN2
  [<TestMethod>]
  member _.``C7.2.301 SQRSHRUN``() =
    testDisasm "2f1f8c20" "sqrshrun v0.4h, v1.4s, #0x1"
    testDisasm "2f3f8c20" "sqrshrun v0.2s, v1.2d, #0x1"
    testDisasm "2f0f8c20" "sqrshrun v0.8b, v1.8h, #0x1"
    testDisasm "7f148eb6" "sqrshrun h22, s21, #0xc"

  /// C7.2.301 SQRSHRUN, SQRSHRUN2
  [<TestMethod>]
  member _.``C7.2.301 SQRSHRUN2``() =
    testDisasm "6f1f8c20" "sqrshrun2 v0.8h, v1.4s, #0x1"
    testDisasm "6f3f8c20" "sqrshrun2 v0.4s, v1.2d, #0x1"
    testDisasm "6f0f8c20" "sqrshrun2 v0.16b, v1.8h, #0x1"

  /// C7.2.302 SQSHL (immediate)
  [<TestMethod>]
  member _.``C7.2.302 SQSHL``() =
    testDisasm "0f097420" "sqshl v0.8b, v1.8b, #0x1"
    testDisasm "0f117420" "sqshl v0.4h, v1.4h, #0x1"
    testDisasm "0f217420" "sqshl v0.2s, v1.2s, #0x1"
    testDisasm "4f417420" "sqshl v0.2d, v1.2d, #0x1"

  /// C7.2.304 SQSHLU
  [<TestMethod>]
  member _.``C7.2.304 SQSHLU``() =
    testDisasm "2f096420" "sqshlu v0.8b, v1.8b, #0x1"
    testDisasm "2f116420" "sqshlu v0.4h, v1.4h, #0x1"
    testDisasm "2f216420" "sqshlu v0.2s, v1.2s, #0x1"
    testDisasm "6f416420" "sqshlu v0.2d, v1.2d, #0x1"

  /// C7.2.305 SQSHRN, SQSHRN2
  [<TestMethod>]
  member _.``C7.2.305 SQSHRN``() =
    testDisasm "0f0f9420" "sqshrn v0.8b, v1.8h, #0x1"
    testDisasm "0f1f9420" "sqshrn v0.4h, v1.4s, #0x1"
    testDisasm "0f3f9420" "sqshrn v0.2s, v1.2d, #0x1"
    testDisasm "5f1496b6" "sqshrn h22, s21, #0xc"

  /// C7.2.305 SQSHRN, SQSHRN2
  [<TestMethod>]
  member _.``C7.2.305 SQSHRN2``() =
    testDisasm "4f1f9420" "sqshrn2 v0.8h, v1.4s, #0x1"
    testDisasm "4f3f9420" "sqshrn2 v0.4s, v1.2d, #0x1"
    testDisasm "4f0f9420" "sqshrn2 v0.16b, v1.8h, #0x1"

  /// C7.2.306 SQSHRUN, SQSHRUN2
  [<TestMethod>]
  member _.``C7.2.306 SQSHRUN``() =
    testDisasm "2f1f8420" "sqshrun v0.4h, v1.4s, #0x1"
    testDisasm "2f3f8420" "sqshrun v0.2s, v1.2d, #0x1"
    testDisasm "2f0f8420" "sqshrun v0.8b, v1.8h, #0x1"
    testDisasm "7f1486b6" "sqshrun h22, s21, #0xc"

  /// C7.2.306 SQSHRUN, SQSHRUN2
  [<TestMethod>]
  member _.``C7.2.306 SQSHRUN2``() =
    testDisasm "6f1f8420" "sqshrun2 v0.8h, v1.4s, #0x1"
    testDisasm "6f3f8420" "sqshrun2 v0.4s, v1.2d, #0x1"
    testDisasm "6f0f8420" "sqshrun2 v0.16b, v1.8h, #0x1"

  /// C7.2.307 SQSUB
  [<TestMethod>]
  member _.``C7.2.307 SQSUB``() =
    testDisasm "0e222c20" "sqsub v0.8b, v1.8b, v2.8b"
    testDisasm "0e622c20" "sqsub v0.4h, v1.4h, v2.4h"
    testDisasm "0ea22c20" "sqsub v0.2s, v1.2s, v2.2s"
    testDisasm "4ee22c20" "sqsub v0.2d, v1.2d, v2.2d"

  /// C7.2.308 SQXTN, SQXTN2
  [<TestMethod>]
  member _.``C7.2.308 SQXTN``() =
    testDisasm "0e214820" "sqxtn v0.8b, v1.8h"
    testDisasm "0ea14820" "sqxtn v0.2s, v1.2d"
    testDisasm "0e614820" "sqxtn v0.4h, v1.4s"
    testDisasm "5e214843" "sqxtn b3, h2"

  /// C7.2.308 SQXTN, SQXTN2
  [<TestMethod>]
  member _.``C7.2.308 SQXTN2``() =
    testDisasm "4e614820" "sqxtn2 v0.8h, v1.4s"
    testDisasm "4ea14820" "sqxtn2 v0.4s, v1.2d"
    testDisasm "4e214820" "sqxtn2 v0.16b, v1.8h"

  /// C7.2.309 SQXTUN, SQXTUN2
  [<TestMethod>]
  member _.``C7.2.309 SQXTUN``() =
    testDisasm "2e212820" "sqxtun v0.8b, v1.8h"
    testDisasm "2ea12820" "sqxtun v0.2s, v1.2d"
    testDisasm "2e612820" "sqxtun v0.4h, v1.4s"
    testDisasm "7e212843" "sqxtun b3, h2"

  /// C7.2.309 SQXTUN, SQXTUN2
  [<TestMethod>]
  member _.``C7.2.309 SQXTUN2``() =
    testDisasm "6e612820" "sqxtun2 v0.8h, v1.4s"
    testDisasm "6ea12820" "sqxtun2 v0.4s, v1.2d"
    testDisasm "6e212820" "sqxtun2 v0.16b, v1.8h"

  /// C7.2.31 CMGT (register)
  [<TestMethod>]
  member _.``C7.2.31 CMGT``() =
    testDisasm "0e223420" "cmgt v0.8b, v1.8b, v2.8b"
    testDisasm "0e623420" "cmgt v0.4h, v1.4h, v2.4h"
    testDisasm "0ea23420" "cmgt v0.2s, v1.2s, v2.2s"
    testDisasm "4ee23420" "cmgt v0.2d, v1.2d, v2.2d"

  /// C7.2.310 SRHADD
  [<TestMethod>]
  member _.``C7.2.310 SRHADD``() =
    testDisasm "0e221420" "srhadd v0.8b, v1.8b, v2.8b"
    testDisasm "0e621420" "srhadd v0.4h, v1.4h, v2.4h"
    testDisasm "0ea21420" "srhadd v0.2s, v1.2s, v2.2s"

  /// C7.2.311 SRI
  [<TestMethod>]
  member _.``C7.2.311 SRI``() =
    testDisasm "2f0f4420" "sri v0.8b, v1.8b, #0x1"
    testDisasm "2f1f4420" "sri v0.4h, v1.4h, #0x1"
    testDisasm "2f3f4420" "sri v0.2s, v1.2s, #0x1"
    testDisasm "6f7f4420" "sri v0.2d, v1.2d, #0x1"

  /// C7.2.312 SRSHL
  [<TestMethod>]
  member _.``C7.2.312 SRSHL``() =
    testDisasm "0e225420" "srshl v0.8b, v1.8b, v2.8b"
    testDisasm "0e625420" "srshl v0.4h, v1.4h, v2.4h"
    testDisasm "0ea25420" "srshl v0.2s, v1.2s, v2.2s"
    testDisasm "4ee25420" "srshl v0.2d, v1.2d, v2.2d"

  /// C7.2.313 SRSHR
  [<TestMethod>]
  member _.``C7.2.313 SRSHR``() =
    testDisasm "0f0f2420" "srshr v0.8b, v1.8b, #0x1"
    testDisasm "0f1f2420" "srshr v0.4h, v1.4h, #0x1"
    testDisasm "0f3f2420" "srshr v0.2s, v1.2s, #0x1"
    testDisasm "4f7f2420" "srshr v0.2d, v1.2d, #0x1"

  /// C7.2.314 SRSRA
  [<TestMethod>]
  member _.``C7.2.314 SRSRA``() =
    testDisasm "0f0f3420" "srsra v0.8b, v1.8b, #0x1"
    testDisasm "0f1f3420" "srsra v0.4h, v1.4h, #0x1"
    testDisasm "0f3f3420" "srsra v0.2s, v1.2s, #0x1"
    testDisasm "4f7f3420" "srsra v0.2d, v1.2d, #0x1"

  /// C7.2.315 SSHL
  [<TestMethod>]
  member _.``C7.2.315 SSHL``() =
    testDisasm "0e224420" "sshl v0.8b, v1.8b, v2.8b"
    testDisasm "0e624420" "sshl v0.4h, v1.4h, v2.4h"
    testDisasm "0ea24420" "sshl v0.2s, v1.2s, v2.2s"
    testDisasm "4ee24420" "sshl v0.2d, v1.2d, v2.2d"

  /// C7.2.316 SSHLL, SSHLL2
  [<TestMethod>]
  member _.``C7.2.316 SSHLL``() =
    testDisasm "0f11a420" "sshll v0.4s, v1.4h, #0x1"
    testDisasm "0f09a420" "sshll v0.8h, v1.8b, #0x1"
    testDisasm "0f21a420" "sshll v0.2d, v1.2s, #0x1"

  /// C7.2.316 SSHLL, SSHLL2
  [<TestMethod>]
  member _.``C7.2.316 SSHLL2``() =
    testDisasm "4f09a420" "sshll2 v0.8h, v1.16b, #0x1"
    testDisasm "4f11a420" "sshll2 v0.4s, v1.8h, #0x1"
    testDisasm "4f21a420" "sshll2 v0.2d, v1.4s, #0x1"

  /// C7.2.317 SSHR
  [<TestMethod>]
  member _.``C7.2.317 SSHR``() =
    testDisasm "0f0f0420" "sshr v0.8b, v1.8b, #0x1"
    testDisasm "0f1f0420" "sshr v0.4h, v1.4h, #0x1"
    testDisasm "0f3f0420" "sshr v0.2s, v1.2s, #0x1"
    testDisasm "4f7f0420" "sshr v0.2d, v1.2d, #0x1"

  /// C7.2.318 SSRA
  [<TestMethod>]
  member _.``C7.2.318 SSRA``() =
    testDisasm "0f0f1420" "ssra v0.8b, v1.8b, #0x1"
    testDisasm "0f1f1420" "ssra v0.4h, v1.4h, #0x1"
    testDisasm "0f3f1420" "ssra v0.2s, v1.2s, #0x1"
    testDisasm "4f7f1420" "ssra v0.2d, v1.2d, #0x1"

  /// C7.2.319 SSUBL, SSUBL2
  [<TestMethod>]
  member _.``C7.2.319 SSUBL``() =
    testDisasm "0e622020" "ssubl v0.4s, v1.4h, v2.4h"
    testDisasm "0e222020" "ssubl v0.8h, v1.8b, v2.8b"
    testDisasm "0ea22020" "ssubl v0.2d, v1.2s, v2.2s"

  /// C7.2.319 SSUBL, SSUBL2
  [<TestMethod>]
  member _.``C7.2.319 SSUBL2``() =
    testDisasm "4e222020" "ssubl2 v0.8h, v1.16b, v2.16b"
    testDisasm "4ea22020" "ssubl2 v0.2d, v1.4s, v2.4s"
    testDisasm "4e622020" "ssubl2 v0.4s, v1.8h, v2.8h"

  /// C7.2.320 SSUBW, SSUBW2
  [<TestMethod>]
  member _.``C7.2.320 SSUBW``() =
    testDisasm "0e623020" "ssubw v0.4s, v1.4s, v2.4h"
    testDisasm "0e223020" "ssubw v0.8h, v1.8h, v2.8b"
    testDisasm "0ea23020" "ssubw v0.2d, v1.2d, v2.2s"

  /// C7.2.320 SSUBW, SSUBW2
  [<TestMethod>]
  member _.``C7.2.320 SSUBW2``() =
    testDisasm "4e223020" "ssubw2 v0.8h, v1.8h, v2.16b"
    testDisasm "4ea23020" "ssubw2 v0.2d, v1.2d, v2.4s"
    testDisasm "4e623020" "ssubw2 v0.4s, v1.4s, v2.8h"

  /// C7.2.321 ST1 (multiple structures)
  [<TestMethod>]
  member _.``C7.2.321 ST1``() =
    testDisasm "4c007020" "st1 { v0.16b }, [x1]"
    testDisasm "0c0023c0" "st1 { v0.8b - v3.8b }, [x30]"
    testDisasm "0c0027c0" "st1 { v0.4h - v3.4h }, [x30]"
    testDisasm "0c002bc0" "st1 { v0.2s - v3.2s }, [x30]"

  /// C7.2.323 ST2 (multiple structures)
  [<TestMethod>]
  member _.``C7.2.323 ST2``() =
    testDisasm "4c008020" "st2 { v0.16b, v1.16b }, [x1]"
    testDisasm "0c0087c0" "st2 { v0.4h, v1.4h }, [x30]"
    testDisasm "0c008bc0" "st2 { v0.2s, v1.2s }, [x30]"
    testDisasm "0c818043" "st2 { v3.8b, v4.8b }, [x2], x1"

  /// C7.2.325 ST3 (multiple structures)
  [<TestMethod>]
  member _.``C7.2.325 ST3``() =
    testDisasm "4c004020" "st3 { v0.16b, v1.16b, v2.16b }, [x1]"
    testDisasm "0c0047c0" "st3 { v0.4h, v1.4h, v2.4h }, [x30]"
    testDisasm "0c004bc0" "st3 { v0.2s, v1.2s, v2.2s }, [x30]"
    testDisasm "0c814043" "st3 { v3.8b, v4.8b, v5.8b }, [x2], x1"

  /// C7.2.327 ST4 (multiple structures)
  [<TestMethod>]
  member _.``C7.2.327 ST4``() =
    testDisasm "4c000020" "st4 { v0.16b - v3.16b }, [x1]"
    testDisasm "0c0007c0" "st4 { v0.4h - v3.4h }, [x30]"
    testDisasm "0c000bc0" "st4 { v0.2s - v3.2s }, [x30]"
    testDisasm "0c810043" "st4 { v3.8b - v6.8b }, [x2], x1"

  /// C7.2.33 CMHI (register)
  [<TestMethod>]
  member _.``C7.2.33 CMHI``() =
    testDisasm "2e223420" "cmhi v0.8b, v1.8b, v2.8b"
    testDisasm "2e623420" "cmhi v0.4h, v1.4h, v2.4h"
    testDisasm "2ea23420" "cmhi v0.2s, v1.2s, v2.2s"
    testDisasm "6ee23420" "cmhi v0.2d, v1.2d, v2.2d"

  /// C7.2.335 SUBHN, SUBHN2
  [<TestMethod>]
  member _.``C7.2.335 SUBHN``() =
    testDisasm "0e626020" "subhn v0.4h, v1.4s, v2.4s"
    testDisasm "0ea26020" "subhn v0.2s, v1.2d, v2.2d"
    testDisasm "0e226020" "subhn v0.8b, v1.8h, v2.8h"

  /// C7.2.335 SUBHN, SUBHN2
  [<TestMethod>]
  member _.``C7.2.335 SUBHN2``() =
    testDisasm "4e626020" "subhn2 v0.8h, v1.4s, v2.4s"
    testDisasm "4ea26020" "subhn2 v0.4s, v1.2d, v2.2d"
    testDisasm "4e226020" "subhn2 v0.16b, v1.8h, v2.8h"

  /// C7.2.336 SUDOT (by element)
  [<TestMethod>]
  member _.``C7.2.336 SUDOT``() =
    testDisasm "4f02f020" "sudot v0.4s, v1.16b, v2.4b[0]"

  /// C7.2.337 SUQADD
  [<TestMethod>]
  member _.``C7.2.337 SUQADD``() =
    testDisasm "0e203820" "suqadd v0.8b, v1.8b"
    testDisasm "0e603820" "suqadd v0.4h, v1.4h"
    testDisasm "0ea03820" "suqadd v0.2s, v1.2s"
    testDisasm "4ee03820" "suqadd v0.2d, v1.2d"

  /// C7.2.338 SXTL, SXTL2
  [<TestMethod>]
  member _.``C7.2.338 SXTL``() =
    testDisasm "0f10a420" "sshll v0.4s, v1.4h, #0x0"
    testDisasm "0f08a420" "sshll v0.8h, v1.8b, #0x0"
    testDisasm "0f20a420" "sshll v0.2d, v1.2s, #0x0"

  /// C7.2.338 SXTL, SXTL2
  [<TestMethod>]
  member _.``C7.2.338 SXTL2``() =
    testDisasm "4f08a420" "sshll2 v0.8h, v1.16b, #0x0"
    testDisasm "4f20a420" "sshll2 v0.2d, v1.4s, #0x0"
    testDisasm "4f10a420" "sshll2 v0.4s, v1.8h, #0x0"

  /// C7.2.339 TBL
  [<TestMethod>]
  member _.``C7.2.339 TBL``() =
    testDisasm "0e020020" "tbl v0.8b, { v1.16b }, v2.8b"
    testDisasm "0e012043" "tbl v3.8b, { v2.16b, v3.16b }, v1.8b"
    testDisasm "0e014043" "tbl v3.8b, { v2.16b, v3.16b, v4.16b }, v1.8b"
    testDisasm "0e016043" "tbl v3.8b, { v2.16b - v5.16b }, v1.8b"

  /// C7.2.34 CMHS (register)
  [<TestMethod>]
  member _.``C7.2.34 CMHS``() =
    testDisasm "2e223c20" "cmhs v0.8b, v1.8b, v2.8b"
    testDisasm "2e623c20" "cmhs v0.4h, v1.4h, v2.4h"
    testDisasm "2ea23c20" "cmhs v0.2s, v1.2s, v2.2s"
    testDisasm "6ee23c20" "cmhs v0.2d, v1.2d, v2.2d"

  /// C7.2.340 TBX
  [<TestMethod>]
  member _.``C7.2.340 TBX``() =
    testDisasm "0e021020" "tbx v0.8b, { v1.16b }, v2.8b"
    testDisasm "0e013043" "tbx v3.8b, { v2.16b, v3.16b }, v1.8b"
    testDisasm "0e015043" "tbx v3.8b, { v2.16b, v3.16b, v4.16b }, v1.8b"
    testDisasm "0e017043" "tbx v3.8b, { v2.16b - v5.16b }, v1.8b"

  /// C7.2.341 TRN1
  [<TestMethod>]
  member _.``C7.2.341 TRN1``() =
    testDisasm "0e022820" "trn1 v0.8b, v1.8b, v2.8b"
    testDisasm "0e422820" "trn1 v0.4h, v1.4h, v2.4h"
    testDisasm "0e822820" "trn1 v0.2s, v1.2s, v2.2s"
    testDisasm "4ec22820" "trn1 v0.2d, v1.2d, v2.2d"

  /// C7.2.342 TRN2
  [<TestMethod>]
  member _.``C7.2.342 TRN2``() =
    testDisasm "0e026820" "trn2 v0.8b, v1.8b, v2.8b"
    testDisasm "0e426820" "trn2 v0.4h, v1.4h, v2.4h"
    testDisasm "0e826820" "trn2 v0.2s, v1.2s, v2.2s"
    testDisasm "4ec26820" "trn2 v0.2d, v1.2d, v2.2d"

  /// C7.2.343 UABA
  [<TestMethod>]
  member _.``C7.2.343 UABA``() =
    testDisasm "2e227c20" "uaba v0.8b, v1.8b, v2.8b"
    testDisasm "2e627c20" "uaba v0.4h, v1.4h, v2.4h"
    testDisasm "2ea27c20" "uaba v0.2s, v1.2s, v2.2s"

  /// C7.2.344 UABAL, UABAL2
  [<TestMethod>]
  member _.``C7.2.344 UABAL``() =
    testDisasm "2e625020" "uabal v0.4s, v1.4h, v2.4h"
    testDisasm "2e225020" "uabal v0.8h, v1.8b, v2.8b"
    testDisasm "2ea25020" "uabal v0.2d, v1.2s, v2.2s"

  /// C7.2.344 UABAL, UABAL2
  [<TestMethod>]
  member _.``C7.2.344 UABAL2``() =
    testDisasm "6e225020" "uabal2 v0.8h, v1.16b, v2.16b"
    testDisasm "6ea25020" "uabal2 v0.2d, v1.4s, v2.4s"
    testDisasm "6e625020" "uabal2 v0.4s, v1.8h, v2.8h"

  /// C7.2.345 UABD
  [<TestMethod>]
  member _.``C7.2.345 UABD``() =
    testDisasm "2e227420" "uabd v0.8b, v1.8b, v2.8b"
    testDisasm "2e627420" "uabd v0.4h, v1.4h, v2.4h"
    testDisasm "2ea27420" "uabd v0.2s, v1.2s, v2.2s"

  /// C7.2.346 UABDL, UABDL2
  [<TestMethod>]
  member _.``C7.2.346 UABDL``() =
    testDisasm "2e627020" "uabdl v0.4s, v1.4h, v2.4h"
    testDisasm "2e227020" "uabdl v0.8h, v1.8b, v2.8b"
    testDisasm "2ea27020" "uabdl v0.2d, v1.2s, v2.2s"

  /// C7.2.346 UABDL, UABDL2
  [<TestMethod>]
  member _.``C7.2.346 UABDL2``() =
    testDisasm "6e227020" "uabdl2 v0.8h, v1.16b, v2.16b"
    testDisasm "6ea27020" "uabdl2 v0.2d, v1.4s, v2.4s"
    testDisasm "6e627020" "uabdl2 v0.4s, v1.8h, v2.8h"

  /// C7.2.347 UADALP
  [<TestMethod>]
  member _.``C7.2.347 UADALP``() =
    testDisasm "2e206820" "uadalp v0.4h, v1.8b"
    testDisasm "2e606820" "uadalp v0.2s, v1.4h"
    testDisasm "6ea06820" "uadalp v0.2d, v1.4s"

  /// C7.2.348 UADDL, UADDL2
  [<TestMethod>]
  member _.``C7.2.348 UADDL``() =
    testDisasm "2e620020" "uaddl v0.4s, v1.4h, v2.4h"
    testDisasm "2e220020" "uaddl v0.8h, v1.8b, v2.8b"
    testDisasm "2ea20020" "uaddl v0.2d, v1.2s, v2.2s"

  /// C7.2.348 UADDL, UADDL2
  [<TestMethod>]
  member _.``C7.2.348 UADDL2``() =
    testDisasm "6e220020" "uaddl2 v0.8h, v1.16b, v2.16b"
    testDisasm "6ea20020" "uaddl2 v0.2d, v1.4s, v2.4s"
    testDisasm "6e620020" "uaddl2 v0.4s, v1.8h, v2.8h"

  /// C7.2.349 UADDLP
  [<TestMethod>]
  member _.``C7.2.349 UADDLP``() =
    testDisasm "2e202820" "uaddlp v0.4h, v1.8b"
    testDisasm "2e602820" "uaddlp v0.2s, v1.4h"
    testDisasm "6ea02820" "uaddlp v0.2d, v1.4s"

  /// C7.2.35 CMLE (zero)
  [<TestMethod>]
  member _.``C7.2.35 CMLE``() =
    testDisasm "2e209820" "cmle v0.8b, v1.8b, #0x0"
    testDisasm "2e609820" "cmle v0.4h, v1.4h, #0x0"
    testDisasm "2ea09820" "cmle v0.2s, v1.2s, #0x0"
    testDisasm "6ee09820" "cmle v0.2d, v1.2d, #0x0"

  /// C7.2.350 UADDLV
  [<TestMethod>]
  member _.``C7.2.350 UADDLV``() =
    testDisasm "2e303820" "uaddlv h0, v1.8b"
    testDisasm "2e703843" "uaddlv s3, v2.4h"
    testDisasm "6eb03843" "uaddlv d3, v2.4s"

  /// C7.2.351 UADDW, UADDW2
  [<TestMethod>]
  member _.``C7.2.351 UADDW``() =
    testDisasm "2e621020" "uaddw v0.4s, v1.4s, v2.4h"
    testDisasm "2e221020" "uaddw v0.8h, v1.8h, v2.8b"
    testDisasm "2ea21020" "uaddw v0.2d, v1.2d, v2.2s"

  /// C7.2.351 UADDW, UADDW2
  [<TestMethod>]
  member _.``C7.2.351 UADDW2``() =
    testDisasm "6e221020" "uaddw2 v0.8h, v1.8h, v2.16b"
    testDisasm "6ea21020" "uaddw2 v0.2d, v1.2d, v2.4s"
    testDisasm "6e621020" "uaddw2 v0.4s, v1.4s, v2.8h"

  /// C7.2.352 UCVTF (vector, fixed-point)
  [<TestMethod>]
  member _.``C7.2.352 UCVTF``() =
    testDisasm "2f1be420" "ucvtf v0.4h, v1.4h, #5"
    testDisasm "2f3be420" "ucvtf v0.2s, v1.2s, #5"
    testDisasm "6f7be420" "ucvtf v0.2d, v1.2d, #5"
    testDisasm "7e79d820" "ucvtf h0, h1"

  /// C7.2.356 UDOT (by element)
  [<TestMethod>]
  member _.``C7.2.356 UDOT``() =
    testDisasm "2e829420" "udot v0.2s, v1.8b, v2.8b"
    testDisasm "2f81e043" "udot v3.2s, v2.8b, v1.4b[0]"

  /// C7.2.358 UHADD
  [<TestMethod>]
  member _.``C7.2.358 UHADD``() =
    testDisasm "2e220420" "uhadd v0.8b, v1.8b, v2.8b"
    testDisasm "2e620420" "uhadd v0.4h, v1.4h, v2.4h"
    testDisasm "2ea20420" "uhadd v0.2s, v1.2s, v2.2s"

  /// C7.2.359 UHSUB
  [<TestMethod>]
  member _.``C7.2.359 UHSUB``() =
    testDisasm "2e222420" "uhsub v0.8b, v1.8b, v2.8b"
    testDisasm "2e622420" "uhsub v0.4h, v1.4h, v2.4h"
    testDisasm "2ea22420" "uhsub v0.2s, v1.2s, v2.2s"

  /// C7.2.36 CMLT (zero)
  [<TestMethod>]
  member _.``C7.2.36 CMLT``() =
    testDisasm "0e20a820" "cmlt v0.8b, v1.8b, #0x0"
    testDisasm "0e60a820" "cmlt v0.4h, v1.4h, #0x0"
    testDisasm "0ea0a820" "cmlt v0.2s, v1.2s, #0x0"
    testDisasm "4ee0a820" "cmlt v0.2d, v1.2d, #0x0"

  /// C7.2.360 UMAX
  [<TestMethod>]
  member _.``C7.2.360 UMAX``() =
    testDisasm "2e226420" "umax v0.8b, v1.8b, v2.8b"
    testDisasm "2e626420" "umax v0.4h, v1.4h, v2.4h"
    testDisasm "2ea26420" "umax v0.2s, v1.2s, v2.2s"

  /// C7.2.361 UMAXP
  [<TestMethod>]
  member _.``C7.2.361 UMAXP``() =
    testDisasm "2e22a420" "umaxp v0.8b, v1.8b, v2.8b"
    testDisasm "2e62a420" "umaxp v0.4h, v1.4h, v2.4h"
    testDisasm "2ea2a420" "umaxp v0.2s, v1.2s, v2.2s"

  /// C7.2.362 UMAXV
  [<TestMethod>]
  member _.``C7.2.362 UMAXV``() =
    testDisasm "6eb0a820" "umaxv s0, v1.4s"
    testDisasm "2e30a843" "umaxv b3, v2.8b"
    testDisasm "2e70a843" "umaxv h3, v2.4h"

  /// C7.2.363 UMIN
  [<TestMethod>]
  member _.``C7.2.363 UMIN``() =
    testDisasm "2e226c20" "umin v0.8b, v1.8b, v2.8b"
    testDisasm "2e626c20" "umin v0.4h, v1.4h, v2.4h"
    testDisasm "2ea26c20" "umin v0.2s, v1.2s, v2.2s"

  /// C7.2.364 UMINP
  [<TestMethod>]
  member _.``C7.2.364 UMINP``() =
    testDisasm "2e22ac20" "uminp v0.8b, v1.8b, v2.8b"
    testDisasm "2e62ac20" "uminp v0.4h, v1.4h, v2.4h"
    testDisasm "2ea2ac20" "uminp v0.2s, v1.2s, v2.2s"

  /// C7.2.365 UMINV
  [<TestMethod>]
  member _.``C7.2.365 UMINV``() =
    testDisasm "6eb1a820" "uminv s0, v1.4s"
    testDisasm "2e31a843" "uminv b3, v2.8b"
    testDisasm "2e71a843" "uminv h3, v2.4h"

  /// C7.2.366 UMLAL, UMLAL2 (by element)
  [<TestMethod>]
  member _.``C7.2.366 UMLAL``() =
    testDisasm "2e628020" "umlal v0.4s, v1.4h, v2.4h"
    testDisasm "2f522020" "umlal v0.4s, v1.4h, v2.h[1]"
    testDisasm "2fa22020" "umlal v0.2d, v1.2s, v2.s[1]"
    testDisasm "2e228020" "umlal v0.8h, v1.8b, v2.8b"

  /// C7.2.366 UMLAL, UMLAL2 (by element)
  [<TestMethod>]
  member _.``C7.2.366 UMLAL2``() =
    testDisasm "6f522020" "umlal2 v0.4s, v1.8h, v2.h[1]"
    testDisasm "6fa22020" "umlal2 v0.2d, v1.4s, v2.s[1]"
    testDisasm "6e228020" "umlal2 v0.8h, v1.16b, v2.16b"
    testDisasm "6ea28020" "umlal2 v0.2d, v1.4s, v2.4s"

  /// C7.2.368 UMLSL, UMLSL2 (by element)
  [<TestMethod>]
  member _.``C7.2.368 UMLSL``() =
    testDisasm "2e62a020" "umlsl v0.4s, v1.4h, v2.4h"
    testDisasm "2f526020" "umlsl v0.4s, v1.4h, v2.h[1]"
    testDisasm "2fa26020" "umlsl v0.2d, v1.2s, v2.s[1]"
    testDisasm "2e22a020" "umlsl v0.8h, v1.8b, v2.8b"

  /// C7.2.368 UMLSL, UMLSL2 (by element)
  [<TestMethod>]
  member _.``C7.2.368 UMLSL2``() =
    testDisasm "6f526020" "umlsl2 v0.4s, v1.8h, v2.h[1]"
    testDisasm "6fa26020" "umlsl2 v0.2d, v1.4s, v2.s[1]"
    testDisasm "6e22a020" "umlsl2 v0.8h, v1.16b, v2.16b"
    testDisasm "6ea2a020" "umlsl2 v0.2d, v1.4s, v2.4s"

  /// C7.2.37 CMTST
  [<TestMethod>]
  member _.``C7.2.37 CMTST``() =
    testDisasm "0e228c20" "cmtst v0.8b, v1.8b, v2.8b"
    testDisasm "0e628c20" "cmtst v0.4h, v1.4h, v2.4h"
    testDisasm "0ea28c20" "cmtst v0.2s, v1.2s, v2.2s"
    testDisasm "4ee28c20" "cmtst v0.2d, v1.2d, v2.2d"

  /// C7.2.370 UMMLA (vector)
  [<TestMethod>]
  member _.``C7.2.370 UMMLA``() =
    testDisasm "6e82a420" "ummla v0.4s, v1.16b, v2.16b"

  /// C7.2.371 UMOV
  [<TestMethod>]
  member _.``C7.2.371 UMOV``() =
    testDisasm "0e0c3c20" "mov w0, v1.s[1]"
    testDisasm "4e183c20" "mov x0, v1.d[1]"
    testDisasm "0e033c20" "umov w0, v1.b[1]"
    testDisasm "0e063c20" "umov w0, v1.h[1]"

  /// C7.2.372 UMULL, UMULL2 (by element)
  [<TestMethod>]
  member _.``C7.2.372 UMULL2``() =
    testDisasm "6f52a020" "umull2 v0.4s, v1.8h, v2.h[1]"
    testDisasm "6fa2a020" "umull2 v0.2d, v1.4s, v2.s[1]"
    testDisasm "6e62c020" "umull2 v0.4s, v1.8h, v2.8h"
    testDisasm "6ea2c020" "umull2 v0.2d, v1.4s, v2.4s"

  /// C7.2.374 UQADD
  [<TestMethod>]
  member _.``C7.2.374 UQADD``() =
    testDisasm "2e220c20" "uqadd v0.8b, v1.8b, v2.8b"
    testDisasm "2e620c20" "uqadd v0.4h, v1.4h, v2.4h"
    testDisasm "2ea20c20" "uqadd v0.2s, v1.2s, v2.2s"
    testDisasm "6ee20c20" "uqadd v0.2d, v1.2d, v2.2d"

  /// C7.2.375 UQRSHL
  [<TestMethod>]
  member _.``C7.2.375 UQRSHL``() =
    testDisasm "2e225c20" "uqrshl v0.8b, v1.8b, v2.8b"
    testDisasm "2e625c20" "uqrshl v0.4h, v1.4h, v2.4h"
    testDisasm "2ea25c20" "uqrshl v0.2s, v1.2s, v2.2s"
    testDisasm "6ee25c20" "uqrshl v0.2d, v1.2d, v2.2d"

  /// C7.2.376 UQRSHRN, UQRSHRN2
  [<TestMethod>]
  member _.``C7.2.376 UQRSHRN``() =
    testDisasm "2f1f9c20" "uqrshrn v0.4h, v1.4s, #0x1"
    testDisasm "2f3f9c20" "uqrshrn v0.2s, v1.2d, #0x1"
    testDisasm "2f0f9c20" "uqrshrn v0.8b, v1.8h, #0x1"
    testDisasm "7f149eb6" "uqrshrn h22, s21, #0xc"

  /// C7.2.376 UQRSHRN, UQRSHRN2
  [<TestMethod>]
  member _.``C7.2.376 UQRSHRN2``() =
    testDisasm "6f1f9c20" "uqrshrn2 v0.8h, v1.4s, #0x1"
    testDisasm "6f3f9c20" "uqrshrn2 v0.4s, v1.2d, #0x1"
    testDisasm "6f0f9c20" "uqrshrn2 v0.16b, v1.8h, #0x1"

  /// C7.2.377 UQSHL (immediate)
  [<TestMethod>]
  member _.``C7.2.377 UQSHL``() =
    testDisasm "2f097420" "uqshl v0.8b, v1.8b, #0x1"
    testDisasm "2f117420" "uqshl v0.4h, v1.4h, #0x1"
    testDisasm "2f217420" "uqshl v0.2s, v1.2s, #0x1"
    testDisasm "6f417420" "uqshl v0.2d, v1.2d, #0x1"

  /// C7.2.379 UQSHRN, UQSHRN2
  [<TestMethod>]
  member _.``C7.2.379 UQSHRN``() =
    testDisasm "2f1f9420" "uqshrn v0.4h, v1.4s, #0x1"
    testDisasm "2f3f9420" "uqshrn v0.2s, v1.2d, #0x1"
    testDisasm "2f0f9420" "uqshrn v0.8b, v1.8h, #0x1"
    testDisasm "7f1496b6" "uqshrn h22, s21, #0xc"

  /// C7.2.379 UQSHRN, UQSHRN2
  [<TestMethod>]
  member _.``C7.2.379 UQSHRN2``() =
    testDisasm "6f1f9420" "uqshrn2 v0.8h, v1.4s, #0x1"
    testDisasm "6f3f9420" "uqshrn2 v0.4s, v1.2d, #0x1"
    testDisasm "6f0f9420" "uqshrn2 v0.16b, v1.8h, #0x1"

  /// C7.2.38 CNT
  [<TestMethod>]
  member _.``C7.2.38 CNT``() =
    testDisasm "4e205820" "cnt v0.16b, v1.16b"

  /// C7.2.380 UQSUB
  [<TestMethod>]
  member _.``C7.2.380 UQSUB``() =
    testDisasm "2e222c20" "uqsub v0.8b, v1.8b, v2.8b"
    testDisasm "2e622c20" "uqsub v0.4h, v1.4h, v2.4h"
    testDisasm "2ea22c20" "uqsub v0.2s, v1.2s, v2.2s"
    testDisasm "6ee22c20" "uqsub v0.2d, v1.2d, v2.2d"

  /// C7.2.381 UQXTN, UQXTN2
  [<TestMethod>]
  member _.``C7.2.381 UQXTN``() =
    testDisasm "2e214820" "uqxtn v0.8b, v1.8h"
    testDisasm "2ea14820" "uqxtn v0.2s, v1.2d"
    testDisasm "2e614820" "uqxtn v0.4h, v1.4s"
    testDisasm "7e214843" "uqxtn b3, h2"

  /// C7.2.381 UQXTN, UQXTN2
  [<TestMethod>]
  member _.``C7.2.381 UQXTN2``() =
    testDisasm "6e614820" "uqxtn2 v0.8h, v1.4s"
    testDisasm "6ea14820" "uqxtn2 v0.4s, v1.2d"
    testDisasm "6e214820" "uqxtn2 v0.16b, v1.8h"

  /// C7.2.382 URECPE
  [<TestMethod>]
  member _.``C7.2.382 URECPE``() =
    testDisasm "0ea1c820" "urecpe v0.2s, v1.2s"

  /// C7.2.383 URHADD
  [<TestMethod>]
  member _.``C7.2.383 URHADD``() =
    testDisasm "2e221420" "urhadd v0.8b, v1.8b, v2.8b"
    testDisasm "2e621420" "urhadd v0.4h, v1.4h, v2.4h"
    testDisasm "2ea21420" "urhadd v0.2s, v1.2s, v2.2s"

  /// C7.2.384 URSHL
  [<TestMethod>]
  member _.``C7.2.384 URSHL``() =
    testDisasm "2e225420" "urshl v0.8b, v1.8b, v2.8b"
    testDisasm "2e625420" "urshl v0.4h, v1.4h, v2.4h"
    testDisasm "2ea25420" "urshl v0.2s, v1.2s, v2.2s"
    testDisasm "6ee25420" "urshl v0.2d, v1.2d, v2.2d"

  /// C7.2.385 URSHR
  [<TestMethod>]
  member _.``C7.2.385 URSHR``() =
    testDisasm "2f0f2420" "urshr v0.8b, v1.8b, #0x1"
    testDisasm "2f1f2420" "urshr v0.4h, v1.4h, #0x1"
    testDisasm "2f3f2420" "urshr v0.2s, v1.2s, #0x1"
    testDisasm "6f7f2420" "urshr v0.2d, v1.2d, #0x1"

  /// C7.2.386 URSQRTE
  [<TestMethod>]
  member _.``C7.2.386 URSQRTE``() =
    testDisasm "2ea1c820" "ursqrte v0.2s, v1.2s"

  /// C7.2.387 URSRA
  [<TestMethod>]
  member _.``C7.2.387 URSRA``() =
    testDisasm "2f0f3420" "ursra v0.8b, v1.8b, #0x1"
    testDisasm "2f1f3420" "ursra v0.4h, v1.4h, #0x1"
    testDisasm "2f3f3420" "ursra v0.2s, v1.2s, #0x1"
    testDisasm "6f7f3420" "ursra v0.2d, v1.2d, #0x1"

  /// C7.2.388 USDOT (vector)
  [<TestMethod>]
  member _.``C7.2.388 USDOT``() =
    testDisasm "0e829c20" "usdot v0.2s, v1.8b, v2.8b"
    testDisasm "0f81f043" "usdot v3.2s, v2.8b, v1.4b[0]"

  /// C7.2.39 DUP (element)
  [<TestMethod>]
  member _.``C7.2.39 DUP``() =
    testDisasm "0e030420" "dup v0.8b, v1.b[1]"
    testDisasm "0e060420" "dup v0.4h, v1.h[1]"
    testDisasm "0e0c0420" "dup v0.2s, v1.s[1]"
    testDisasm "4e180420" "dup v0.2d, v1.d[1]"

  /// C7.2.390 USHL
  [<TestMethod>]
  member _.``C7.2.390 USHL``() =
    testDisasm "2e224420" "ushl v0.8b, v1.8b, v2.8b"
    testDisasm "2e624420" "ushl v0.4h, v1.4h, v2.4h"
    testDisasm "2ea24420" "ushl v0.2s, v1.2s, v2.2s"
    testDisasm "6ee24420" "ushl v0.2d, v1.2d, v2.2d"

  /// C7.2.391 USHLL, USHLL2
  [<TestMethod>]
  member _.``C7.2.391 USHLL``() =
    testDisasm "2f11a420" "ushll v0.4s, v1.4h, #0x1"
    testDisasm "2f09a420" "ushll v0.8h, v1.8b, #0x1"
    testDisasm "2f21a420" "ushll v0.2d, v1.2s, #0x1"

  /// C7.2.391 USHLL, USHLL2
  [<TestMethod>]
  member _.``C7.2.391 USHLL2``() =
    testDisasm "6f09a420" "ushll2 v0.8h, v1.16b, #0x1"
    testDisasm "6f11a420" "ushll2 v0.4s, v1.8h, #0x1"
    testDisasm "6f21a420" "ushll2 v0.2d, v1.4s, #0x1"

  /// C7.2.392 USHR
  [<TestMethod>]
  member _.``C7.2.392 USHR``() =
    testDisasm "2f0f0420" "ushr v0.8b, v1.8b, #0x1"
    testDisasm "2f1f0420" "ushr v0.4h, v1.4h, #0x1"
    testDisasm "2f3f0420" "ushr v0.2s, v1.2s, #0x1"
    testDisasm "6f7f0420" "ushr v0.2d, v1.2d, #0x1"

  /// C7.2.393 USMMLA (vector)
  [<TestMethod>]
  member _.``C7.2.393 USMMLA``() =
    testDisasm "4e82ac20" "usmmla v0.4s, v1.16b, v2.16b"

  /// C7.2.394 USQADD
  [<TestMethod>]
  member _.``C7.2.394 USQADD``() =
    testDisasm "2e203820" "usqadd v0.8b, v1.8b"
    testDisasm "2e603820" "usqadd v0.4h, v1.4h"
    testDisasm "2ea03820" "usqadd v0.2s, v1.2s"
    testDisasm "6ee03820" "usqadd v0.2d, v1.2d"

  /// C7.2.395 USRA
  [<TestMethod>]
  member _.``C7.2.395 USRA``() =
    testDisasm "2f0f1420" "usra v0.8b, v1.8b, #0x1"
    testDisasm "2f1f1420" "usra v0.4h, v1.4h, #0x1"
    testDisasm "2f3f1420" "usra v0.2s, v1.2s, #0x1"
    testDisasm "6f7f1420" "usra v0.2d, v1.2d, #0x1"

  /// C7.2.396 USUBL, USUBL2
  [<TestMethod>]
  member _.``C7.2.396 USUBL``() =
    testDisasm "2e622020" "usubl v0.4s, v1.4h, v2.4h"
    testDisasm "2e222020" "usubl v0.8h, v1.8b, v2.8b"
    testDisasm "2ea22020" "usubl v0.2d, v1.2s, v2.2s"

  /// C7.2.396 USUBL, USUBL2
  [<TestMethod>]
  member _.``C7.2.396 USUBL2``() =
    testDisasm "6e222020" "usubl2 v0.8h, v1.16b, v2.16b"
    testDisasm "6ea22020" "usubl2 v0.2d, v1.4s, v2.4s"
    testDisasm "6e622020" "usubl2 v0.4s, v1.8h, v2.8h"

  /// C7.2.397 USUBW, USUBW2
  [<TestMethod>]
  member _.``C7.2.397 USUBW``() =
    testDisasm "2e623020" "usubw v0.4s, v1.4s, v2.4h"
    testDisasm "2e223020" "usubw v0.8h, v1.8h, v2.8b"
    testDisasm "2ea23020" "usubw v0.2d, v1.2d, v2.2s"

  /// C7.2.397 USUBW, USUBW2
  [<TestMethod>]
  member _.``C7.2.397 USUBW2``() =
    testDisasm "6e223020" "usubw2 v0.8h, v1.8h, v2.16b"
    testDisasm "6ea23020" "usubw2 v0.2d, v1.2d, v2.4s"
    testDisasm "6e623020" "usubw2 v0.4s, v1.4s, v2.8h"

  /// C7.2.398 UXTL, UXTL2
  [<TestMethod>]
  member _.``C7.2.398 UXTL``() =
    testDisasm "2f10a420" "ushll v0.4s, v1.4h, #0x0"
    testDisasm "2f08a420" "ushll v0.8h, v1.8b, #0x0"
    testDisasm "2f20a420" "ushll v0.2d, v1.2s, #0x0"

  /// C7.2.398 UXTL, UXTL2
  [<TestMethod>]
  member _.``C7.2.398 UXTL2``() =
    testDisasm "6f08a420" "ushll2 v0.8h, v1.16b, #0x0"
    testDisasm "6f20a420" "ushll2 v0.2d, v1.4s, #0x0"
    testDisasm "6f10a420" "ushll2 v0.4s, v1.8h, #0x0"

  /// C7.2.399 UZP1
  [<TestMethod>]
  member _.``C7.2.399 UZP1``() =
    testDisasm "0e021820" "uzp1 v0.8b, v1.8b, v2.8b"
    testDisasm "0e421820" "uzp1 v0.4h, v1.4h, v2.4h"
    testDisasm "0e821820" "uzp1 v0.2s, v1.2s, v2.2s"
    testDisasm "4ec21820" "uzp1 v0.2d, v1.2d, v2.2d"

  /// C7.2.4 ADDP (scalar)
  [<TestMethod>]
  member _.``C7.2.4 ADDP``() =
    testDisasm "0e22bc20" "addp v0.8b, v1.8b, v2.8b"
    testDisasm "0e62bc20" "addp v0.4h, v1.4h, v2.4h"
    testDisasm "0ea2bc20" "addp v0.2s, v1.2s, v2.2s"
    testDisasm "4ee2bc20" "addp v0.2d, v1.2d, v2.2d"

  /// C7.2.400 UZP2
  [<TestMethod>]
  member _.``C7.2.400 UZP2``() =
    testDisasm "0e025820" "uzp2 v0.8b, v1.8b, v2.8b"
    testDisasm "0e425820" "uzp2 v0.4h, v1.4h, v2.4h"
    testDisasm "0e825820" "uzp2 v0.2s, v1.2s, v2.2s"
    testDisasm "4ec25820" "uzp2 v0.2d, v1.2d, v2.2d"

  /// C7.2.401 XAR
  [<TestMethod>]
  member _.``C7.2.401 XAR``() =
    testDisasm "ce820c20" "xar v0.2d, v1.2d, v2.2d, #0x3"

  /// C7.2.402 XTN, XTN2
  [<TestMethod>]
  member _.``C7.2.402 XTN``() =
    testDisasm "0e612820" "xtn v0.4h, v1.4s"
    testDisasm "0e212820" "xtn v0.8b, v1.8h"
    testDisasm "0ea12820" "xtn v0.2s, v1.2d"

  /// C7.2.402 XTN, XTN2
  [<TestMethod>]
  member _.``C7.2.402 XTN2``() =
    testDisasm "4e212820" "xtn2 v0.16b, v1.8h"
    testDisasm "4ea12820" "xtn2 v0.4s, v1.2d"
    testDisasm "4e612820" "xtn2 v0.8h, v1.4s"

  /// C7.2.403 ZIP1
  [<TestMethod>]
  member _.``C7.2.403 ZIP1``() =
    testDisasm "0e023820" "zip1 v0.8b, v1.8b, v2.8b"
    testDisasm "0e423820" "zip1 v0.4h, v1.4h, v2.4h"
    testDisasm "0e823820" "zip1 v0.2s, v1.2s, v2.2s"
    testDisasm "4ec23820" "zip1 v0.2d, v1.2d, v2.2d"

  /// C7.2.404 ZIP2
  [<TestMethod>]
  member _.``C7.2.404 ZIP2``() =
    testDisasm "0e027820" "zip2 v0.8b, v1.8b, v2.8b"
    testDisasm "0e427820" "zip2 v0.4h, v1.4h, v2.4h"
    testDisasm "0e827820" "zip2 v0.2s, v1.2s, v2.2s"
    testDisasm "4ec27820" "zip2 v0.2d, v1.2d, v2.2d"

  /// C7.2.42 EOR3
  [<TestMethod>]
  member _.``C7.2.42 EOR3``() =
    testDisasm "ce020c20" "eor3 v0.16b, v1.16b, v2.16b, v3.16b"

  /// C7.2.43 EXT
  [<TestMethod>]
  member _.``C7.2.43 EXT``() =
    testDisasm "6e020820" "ext v0.16b, v1.16b, v2.16b, #0x1"

  /// C7.2.44 FABD
  [<TestMethod>]
  member _.``C7.2.44 FABD``() =
    testDisasm "7ec21420" "fabd h0, h1, h2"
    testDisasm "2ec21420" "fabd v0.4h, v1.4h, v2.4h"
    testDisasm "2ea2d420" "fabd v0.2s, v1.2s, v2.2s"
    testDisasm "6ee2d420" "fabd v0.2d, v1.2d, v2.2d"

  /// C7.2.45 FABS (vector)
  [<TestMethod>]
  member _.``C7.2.45 FABS``() =
    testDisasm "0ef8f820" "fabs v0.4h, v1.4h"
    testDisasm "0ea0f820" "fabs v0.2s, v1.2s"
    testDisasm "4ee0f820" "fabs v0.2d, v1.2d"
    testDisasm "1ee0c020" "fabs h0, h1"

  /// C7.2.47 FACGE
  [<TestMethod>]
  member _.``C7.2.47 FACGE``() =
    testDisasm "7e422c20" "facge h0, h1, h2"
    testDisasm "2e422c20" "facge v0.4h, v1.4h, v2.4h"
    testDisasm "2e22ec20" "facge v0.2s, v1.2s, v2.2s"
    testDisasm "6e62ec20" "facge v0.2d, v1.2d, v2.2d"

  /// C7.2.48 FACGT
  [<TestMethod>]
  member _.``C7.2.48 FACGT``() =
    testDisasm "7ec22c20" "facgt h0, h1, h2"
    testDisasm "2ec22c20" "facgt v0.4h, v1.4h, v2.4h"
    testDisasm "2ea2ec20" "facgt v0.2s, v1.2s, v2.2s"
    testDisasm "6ee2ec20" "facgt v0.2d, v1.2d, v2.2d"

  /// C7.2.49 FADD (vector)
  [<TestMethod>]
  member _.``C7.2.49 FADD``() =
    testDisasm "0e421420" "fadd v0.4h, v1.4h, v2.4h"
    testDisasm "0e22d420" "fadd v0.2s, v1.2s, v2.2s"
    testDisasm "4e62d420" "fadd v0.2d, v1.2d, v2.2d"
    testDisasm "1ee22820" "fadd h0, h1, h2"

  /// C7.2.51 FADDP (scalar)
  [<TestMethod>]
  member _.``C7.2.51 FADDP``() =
    testDisasm "2e421420" "faddp v0.4h, v1.4h, v2.4h"
    testDisasm "2e22d420" "faddp v0.2s, v1.2s, v2.2s"
    testDisasm "6e62d420" "faddp v0.2d, v1.2d, v2.2d"
    testDisasm "5e30d843" "faddp h3, v2.2h"

  /// C7.2.53 FCADD
  [<TestMethod>]
  member _.``C7.2.53 FCADD``() =
    testDisasm "6e82e420" "fcadd v0.4s, v1.4s, v2.4s, #0x5a"
    testDisasm "2e41e443" "fcadd v3.4h, v2.4h, v1.4h, #0x5a"
    testDisasm "6ec1e443" "fcadd v3.2d, v2.2d, v1.2d, #0x5a"

  /// C7.2.54 FCCMP
  [<TestMethod>]
  member _.``C7.2.54 FCCMP``() =
    testDisasm "1ee20429" "fccmp h1, h2, #0x9, eq"
    testDisasm "1e220429" "fccmp s1, s2, #0x9, eq"
    testDisasm "1e620429" "fccmp d1, d2, #0x9, eq"
    testDisasm "1e211443" "fccmp s2, s1, #0x3, ne"

  /// C7.2.55 FCCMPE
  [<TestMethod>]
  member _.``C7.2.55 FCCMPE``() =
    testDisasm "1ee20439" "fccmpe h1, h2, #0x9, eq"
    testDisasm "1e220439" "fccmpe s1, s2, #0x9, eq"
    testDisasm "1e620439" "fccmpe d1, d2, #0x9, eq"
    testDisasm "1e3416b6" "fccmpe s21, s20, #0x6, ne"

  /// C7.2.56 FCMEQ (register)
  [<TestMethod>]
  member _.``C7.2.56 FCMEQ``() =
    testDisasm "5e422420" "fcmeq h0, h1, h2"
    testDisasm "0e422420" "fcmeq v0.4h, v1.4h, v2.4h"
    testDisasm "0e22e420" "fcmeq v0.2s, v1.2s, v2.2s"
    testDisasm "4e62e420" "fcmeq v0.2d, v1.2d, v2.2d"

  /// C7.2.58 FCMGE (register)
  [<TestMethod>]
  member _.``C7.2.58 FCMGE``() =
    testDisasm "7e422420" "fcmge h0, h1, h2"
    testDisasm "2e422420" "fcmge v0.4h, v1.4h, v2.4h"
    testDisasm "2e22e420" "fcmge v0.2s, v1.2s, v2.2s"
    testDisasm "6e62e420" "fcmge v0.2d, v1.2d, v2.2d"

  /// C7.2.6 ADDV
  [<TestMethod>]
  member _.``C7.2.6 ADDV``() =
    testDisasm "4eb1b820" "addv s0, v1.4s"
    testDisasm "0e31b843" "addv b3, v2.8b"
    testDisasm "0e71b843" "addv h3, v2.4h"

  /// C7.2.60 FCMGT (register)
  [<TestMethod>]
  member _.``C7.2.60 FCMGT``() =
    testDisasm "7ec22420" "fcmgt h0, h1, h2"
    testDisasm "2ec22420" "fcmgt v0.4h, v1.4h, v2.4h"
    testDisasm "2ea2e420" "fcmgt v0.2s, v1.2s, v2.2s"
    testDisasm "6ee2e420" "fcmgt v0.2d, v1.2d, v2.2d"

  /// C7.2.62 FCMLA (by element)
  [<TestMethod>]
  member _.``C7.2.62 FCMLA``() =
    testDisasm "6e82cc20" "fcmla v0.4s, v1.4s, v2.4s, #0x5a"
    testDisasm "2e41c443" "fcmla v3.4h, v2.4h, v1.4h, #0x0"
    testDisasm "2f411043" "fcmla v3.4h, v2.4h, v1.h[0], #0x0"
    testDisasm "6ec1c443" "fcmla v3.2d, v2.2d, v1.2d, #0x0"

  /// C7.2.64 FCMLE (zero)
  [<TestMethod>]
  member _.``C7.2.64 FCMLE``() =
    testDisasm "7ef8d820" "fcmle h0, h1, #0.00000000"
    testDisasm "2ef8d820" "fcmle v0.4h, v1.4h, #0.00000000"
    testDisasm "2ea0d820" "fcmle v0.2s, v1.2s, #0.00000000"
    testDisasm "6ee0d820" "fcmle v0.2d, v1.2d, #0.00000000"

  /// C7.2.65 FCMLT (zero)
  [<TestMethod>]
  member _.``C7.2.65 FCMLT``() =
    testDisasm "5ef8e820" "fcmlt h0, h1, #0.00000000"
    testDisasm "0ef8e820" "fcmlt v0.4h, v1.4h, #0.00000000"
    testDisasm "0ea0e820" "fcmlt v0.2s, v1.2s, #0.00000000"
    testDisasm "4ee0e820" "fcmlt v0.2d, v1.2d, #0.00000000"

  /// C7.2.66 FCMP
  [<TestMethod>]
  member _.``C7.2.66 FCMP``() =
    testDisasm "1ee22020" "fcmp h1, h2"
    testDisasm "1ee02028" "fcmp h1, #0.00000000"
    testDisasm "1e222020" "fcmp s1, s2"
    testDisasm "1e202028" "fcmp s1, #0.00000000"

  /// C7.2.67 FCMPE
  [<TestMethod>]
  member _.``C7.2.67 FCMPE``() =
    testDisasm "1ee22030" "fcmpe h1, h2"
    testDisasm "1ee02038" "fcmpe h1, #0.00000000"
    testDisasm "1e222030" "fcmpe s1, s2"
    testDisasm "1e202038" "fcmpe s1, #0.00000000"

  /// C7.2.68 FCSEL
  [<TestMethod>]
  member _.``C7.2.68 FCSEL``() =
    testDisasm "1ee20c20" "fcsel h0, h1, h2, eq"
    testDisasm "1e220c20" "fcsel s0, s1, s2, eq"
    testDisasm "1e620c20" "fcsel d0, d1, d2, eq"
    testDisasm "1e211c43" "fcsel s3, s2, s1, ne"

  /// C7.2.69 FCVT
  [<TestMethod>]
  member _.``C7.2.69 FCVT``() =
    testDisasm "1e22c020" "fcvt d0, s1"
    testDisasm "1ee24020" "fcvt s0, h1"
    testDisasm "1e23c020" "fcvt h0, s1"
    testDisasm "1e63c020" "fcvt h0, d1"

  /// C7.2.7 AESD
  [<TestMethod>]
  member _.``C7.2.7 AESD``() =
    testDisasm "4e285820" "aesd v0.16b, v1.16b"

  /// C7.2.70 FCVTAS (vector)
  [<TestMethod>]
  member _.``C7.2.70 FCVTAS``() =
    testDisasm "9e640020" "fcvtas x0, d1"
    testDisasm "5e79c820" "fcvtas h0, h1"
    testDisasm "0e79c820" "fcvtas v0.4h, v1.4h"
    testDisasm "0e21c820" "fcvtas v0.2s, v1.2s"

  /// C7.2.72 FCVTAU (vector)
  [<TestMethod>]
  member _.``C7.2.72 FCVTAU``() =
    testDisasm "9e650020" "fcvtau x0, d1"
    testDisasm "7e79c820" "fcvtau h0, h1"
    testDisasm "2e79c820" "fcvtau v0.4h, v1.4h"
    testDisasm "2e21c820" "fcvtau v0.2s, v1.2s"

  /// C7.2.74 FCVTL, FCVTL2
  [<TestMethod>]
  member _.``C7.2.74 FCVTL``() =
    testDisasm "0e217820" "fcvtl v0.4s, v1.4h"
    testDisasm "0e617820" "fcvtl v0.2d, v1.2s"

  /// C7.2.74 FCVTL, FCVTL2
  [<TestMethod>]
  member _.``C7.2.74 FCVTL2``() =
    testDisasm "4e617820" "fcvtl2 v0.2d, v1.4s"
    testDisasm "4e217820" "fcvtl2 v0.4s, v1.8h"

  /// C7.2.75 FCVTMS (vector)
  [<TestMethod>]
  member _.``C7.2.75 FCVTMS``() =
    testDisasm "9e700020" "fcvtms x0, d1"
    testDisasm "5e79b820" "fcvtms h0, h1"
    testDisasm "0e79b820" "fcvtms v0.4h, v1.4h"
    testDisasm "0e21b820" "fcvtms v0.2s, v1.2s"

  /// C7.2.77 FCVTMU (vector)
  [<TestMethod>]
  member _.``C7.2.77 FCVTMU``() =
    testDisasm "9e710020" "fcvtmu x0, d1"
    testDisasm "7e79b820" "fcvtmu h0, h1"
    testDisasm "2e79b820" "fcvtmu v0.4h, v1.4h"
    testDisasm "2e21b820" "fcvtmu v0.2s, v1.2s"

  /// C7.2.79 FCVTN, FCVTN2
  [<TestMethod>]
  member _.``C7.2.79 FCVTN``() =
    testDisasm "0e216820" "fcvtn v0.4h, v1.4s"
    testDisasm "0e616820" "fcvtn v0.2s, v1.2d"

  /// C7.2.79 FCVTN, FCVTN2
  [<TestMethod>]
  member _.``C7.2.79 FCVTN2``() =
    testDisasm "4e616820" "fcvtn2 v0.4s, v1.2d"
    testDisasm "4e216820" "fcvtn2 v0.8h, v1.4s"

  /// C7.2.8 AESE
  [<TestMethod>]
  member _.``C7.2.8 AESE``() =
    testDisasm "4e284820" "aese v0.16b, v1.16b"

  /// C7.2.80 FCVTNS (vector)
  [<TestMethod>]
  member _.``C7.2.80 FCVTNS``() =
    testDisasm "9e600020" "fcvtns x0, d1"
    testDisasm "5e79a820" "fcvtns h0, h1"
    testDisasm "0e79a820" "fcvtns v0.4h, v1.4h"
    testDisasm "0e21a820" "fcvtns v0.2s, v1.2s"

  /// C7.2.82 FCVTNU (vector)
  [<TestMethod>]
  member _.``C7.2.82 FCVTNU``() =
    testDisasm "9e610020" "fcvtnu x0, d1"
    testDisasm "7e79a820" "fcvtnu h0, h1"
    testDisasm "2e79a820" "fcvtnu v0.4h, v1.4h"
    testDisasm "2e21a820" "fcvtnu v0.2s, v1.2s"

  /// C7.2.84 FCVTPS (vector)
  [<TestMethod>]
  member _.``C7.2.84 FCVTPS``() =
    testDisasm "9e680020" "fcvtps x0, d1"
    testDisasm "5ef9a820" "fcvtps h0, h1"
    testDisasm "0ef9a820" "fcvtps v0.4h, v1.4h"
    testDisasm "0ea1a820" "fcvtps v0.2s, v1.2s"

  /// C7.2.86 FCVTPU (vector)
  [<TestMethod>]
  member _.``C7.2.86 FCVTPU``() =
    testDisasm "9e690020" "fcvtpu x0, d1"
    testDisasm "7ef9a820" "fcvtpu h0, h1"
    testDisasm "2ef9a820" "fcvtpu v0.4h, v1.4h"
    testDisasm "2ea1a820" "fcvtpu v0.2s, v1.2s"

  /// C7.2.88 FCVTXN, FCVTXN2
  [<TestMethod>]
  member _.``C7.2.88 FCVTXN``() =
    testDisasm "2e616820" "fcvtxn v0.2s, v1.2d"
    testDisasm "7e616843" "fcvtxn s3, d2"

  /// C7.2.88 FCVTXN, FCVTXN2
  [<TestMethod>]
  member _.``C7.2.88 FCVTXN2``() =
    testDisasm "6e616820" "fcvtxn2 v0.4s, v1.2d"

  /// C7.2.89 FCVTZS (vector, fixed-point)
  [<TestMethod>]
  member _.``C7.2.89 FCVTZS``() =
    testDisasm "9e780020" "fcvtzs x0, d1"
    testDisasm "0f1bfc20" "fcvtzs v0.4h, v1.4h, #5"
    testDisasm "0f3bfc20" "fcvtzs v0.2s, v1.2s, #5"
    testDisasm "4f7bfc20" "fcvtzs v0.2d, v1.2d, #5"

  /// C7.2.9 AESIMC
  [<TestMethod>]
  member _.``C7.2.9 AESIMC``() =
    testDisasm "4e287820" "aesimc v0.16b, v1.16b"

  /// C7.2.93 FCVTZU (vector, fixed-point)
  [<TestMethod>]
  member _.``C7.2.93 FCVTZU``() =
    testDisasm "9e790020" "fcvtzu x0, d1"
    testDisasm "2f1bfc20" "fcvtzu v0.4h, v1.4h, #5"
    testDisasm "2f3bfc20" "fcvtzu v0.2s, v1.2s, #5"
    testDisasm "6f7bfc20" "fcvtzu v0.2d, v1.2d, #5"

  /// C7.2.97 FDIV (vector)
  [<TestMethod>]
  member _.``C7.2.97 FDIV``() =
    testDisasm "2e423c20" "fdiv v0.4h, v1.4h, v2.4h"
    testDisasm "2e22fc20" "fdiv v0.2s, v1.2s, v2.2s"
    testDisasm "6e62fc20" "fdiv v0.2d, v1.2d, v2.2d"
    testDisasm "1ee21820" "fdiv h0, h1, h2"

  /// C7.2.99 FJCVTZS
  [<TestMethod>]
  member _.``C7.2.99 FJCVTZS``() =
    testDisasm "1e7e0020" "fjcvtzs w0, d1"
    testDisasm "1e7e03ff" "fjcvtzs wzr, d31"
