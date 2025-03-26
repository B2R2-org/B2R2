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

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter.ARM64
open B2R2.FrontEnd.BinLifter.ARM64.OperandHelper
open type Opcode
open type Register

/// Shortcut for creating operands.
[<AutoOpen>]
module private ARM64Shortcut =
  type O =
    static member Reg (r) =
      OprRegister r

    static member RegOffset (r) =
      OprExtReg r

    static member MemBaseReg (baseReg, offsetReg, typ: ExtendType, imm) =
      memBaseReg (baseReg, offsetReg, Some <| ExtRegOffset (typ, imm))

    static member MemBaseReg (baseReg, offsetReg, typ: SRType, imm) =
      memBaseReg (baseReg, offsetReg, Some <| ShiftOffset (typ, imm))

    static member MemBaseImm (register, imm) =
      memBaseImm (register, Some imm)

    static member MemBaseImm register =
      memBaseImm (register, None)

    static member MemPreIdxImm (register, imm) =
      memPreIdxImm (register, Some imm)

    static member MemPreIdxReg (baseReg, offsetReg, imm) =
      memPreIdxReg (baseReg, offsetReg, Some imm)

    static member MemPostIdxImm (register, imm) =
      memPostIdxImm (register, Some imm)

    static member MemPostIdxReg (baseReg, offsetReg, imm) =
      memPostIdxReg (baseReg, offsetReg, Some imm)

    static member MemPostIdxReg (baseReg, offsetReg) =
      memPostIdxReg (baseReg, offsetReg, None)

    static member MemLabel label =
      memLabel label

    static member Imm (v) =
      OprImm v

    static member Shift (srType, v: int64) =
      OprShift (srType, Imm v)

    static member LSB v =
      OprLSB v

    static member Pstate st =
      OprPstate st

    static member SIMDVecReg (reg: Register, typ: SIMDVector) =
      SIMDVecReg (reg, typ) |> OprSIMD

    static member SIMDVecRegWithIdx (reg: Register, typ: SIMDVector, idx) =
      (reg, typ, idx) |> SIMDVecRegWithIdx |> OprSIMD

    static member SIMDList (lst: Register list, typ: SIMDVector) =
      lst |> List.map (fun r -> SIMDVecReg (r, typ)) |> OprSIMDList

    static member SIMDList (lst: Register list, typ: SIMDVector, idx: Index) =
      OprSIMDList <| List.map (fun reg -> SIMDVecRegWithIdx (reg, typ, idx)) lst

    static member Prefetch v =
      OprPrfOp v

    static member ScalarReg r =
      scalReg r

/// - C4.2 Data processing - immediate
/// - C4.3 Branches, exception generating and system instructions
/// - C4.4 Loads and stores
/// - C4.5 Data processing - register
/// - C4.6 Data processing - SIMD and floating point
[<TestClass>]
type ARM64ParserTests () =
  let test (bytes: byte[]) (opcode, oprs: Operands) =
    let reader = BinReader.Init Endian.Big
    let span = System.ReadOnlySpan bytes
    let ins = ParsingMain.parse span reader 0UL
    let opcode' = ins.Info.Opcode
    let oprs' = ins.Info.Operands
    Assert.AreEqual<Opcode> (opcode, opcode')
    Assert.AreEqual<Operands> (oprs, oprs')

  let operandsFromArray oprList =
    let oprs = Array.ofList oprList
    match oprs.Length with
    | 0 -> NoOperand
    | 1 -> OneOperand oprs[0]
    | 2 -> TwoOperands (oprs[0], oprs[1])
    | 3 -> ThreeOperands (oprs[0], oprs[1], oprs[2])
    | 4 -> FourOperands (oprs[0], oprs[1], oprs[2], oprs[3])
    | 5 -> FiveOperands (oprs[0], oprs[1], oprs[2], oprs[3], oprs[4])
    | _ -> Utils.impossible ()

  let ( ** ) opcode oprList = (opcode, operandsFromArray oprList)

  let ( ++ ) byteString pair = (ByteArray.ofHexString byteString, pair)

  /// C4.2.1 Add/subtract (immediate)
  [<TestMethod>]
  member __.``[AArch64] Add/subtract (immedate) Parse Test`` () =
    "114dc4ba"
    ++ ADD ** [ O.Reg W26; O.Reg W5; O.Imm 0x371L; O.Shift (SRTypeLSL, 12L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.2.2 Bit Field (1)`` () =
    "13010401"
    ++ SBFX ** [ O.Reg W1; O.Reg W0; O.Imm 0x1L; O.Imm 0x1L ]
    ||> test

  [<TestMethod>]
  member __.``C4.2.3 Extract (1)`` () =
    "93c00422"
    ++ EXTR ** [ O.Reg X2; O.Reg X1; O.Reg X0; O.LSB 0x1uy ]
    ||> test

  [<TestMethod>]
  member __.``C4.2.4 Logical (immediate) (1)`` () =
    "12010401"
    ++ AND ** [ O.Reg W1; O.Reg W0; O.Imm 0x80000001L ]
    ||> test

  [<TestMethod>]
  member __.``C4.2.4 Logical (immediate) (2)`` () =
    "12030c01"
    ++ AND ** [ O.Reg W1; O.Reg W0; O.Imm 0xE0000001L ]
    ||> test

  [<TestMethod>]
  member __.``C4.2.4 Logical (immediate) (3)`` () =
    "12200401"
    ++ AND ** [ O.Reg W1; O.Reg W0; O.Imm 0x3L ]
    ||> test

  [<TestMethod>]
  member __.``C4.2.4 Logical (immediate) (4)`` () =
    "121a7821"
    ++ AND ** [ O.Reg W1; O.Reg W1; O.Imm 0xffffffdfL ]
    ||> test

  [<TestMethod>]
  member __.``C4.2.4 Logical (immediate) (5)`` () =
    "92200401"
    ++ AND ** [ O.Reg X1; O.Reg X0; O.Imm 0x300000003L ]
    ||> test

  [<TestMethod>]
  member __.``C4.2.5 Move wide (immediate) (1)`` () =
    "92a00015"
    ++ MOVN ** [ O.Reg X21; O.Imm 0x0L; O.Shift (SRTypeLSL, 0x10L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.2.5 Move wide (immediate) (2)`` () =
    "92e3ffbf"
    ++ MOV ** [ O.Reg XZR; O.Imm 0xE002FFFFFFFFFFFFL ]
    ||> test

  [<TestMethod>]
  member __.``C4.2.5 Move wide (immediate) (3)`` () =
    "12b0001a"
    ++ MOV ** [ O.Reg W26; O.Imm 0x7FFFFFFFL ]
    ||> test

  [<TestMethod>]
  member __.``C4.2.6 PC-rel. addressing (1)`` () =
    "707ff067"
    ++ ADR ** [ O.Reg X7; O.MemLabel 0xffe0fL ]
    ||> test

  [<TestMethod>]
  member __.``C4.3.1 Compare & branch (immediate) (1)`` () =
    "b4041023"
    ++ CBZ ** [ O.Reg X3; O.MemLabel 0x8204L ]
    ||> test

  [<TestMethod>]
  member __.``C4.3.2 Conditional branch (immediate) (1)`` () =
    "54000021"
    ++ BNE ** [ O.MemLabel 0x4L ]
    ||> test

  [<TestMethod>]
  member __.``C4.3.3 Exception generation (1)`` () =
    "d4000061"
    ++ SVC ** [ O.Imm 0x3L ]
    ||> test

  [<TestMethod>]
  member __.``C4.3.4 System (1)`` () =
    "d50042bf"
    ++ MSR ** [ O.Pstate SPSEL; O.Imm 0x2L ]
    ||> test

  [<TestMethod>]
  member __.``C4.3.4 System (2)`` () =
    "d50342df"
    ++ MSR ** [ O.Pstate DAIFSET; O.Imm 0x2L ]
    ||> test

  [<TestMethod>]
  member __.``C4.3.4 System (3)`` () =
    "d50320df"
    ++ HINT ** [ O.Imm 0x6L ]
    ||> test

  [<TestMethod>]
  member __.``C4.3.4 System (4)`` () =
    "d50320bf"
    ++ SEVL ** []
    ||> test

  [<TestMethod>]
  member __.``C4.3.4 System (5)`` () =
    "d50b7423"
    ++ DCZVA ** [ O.Reg X3 ]
    ||> test

  [<TestMethod>]
  member __.``C4.3.4 System (6)`` () =
    "d528f4d8"
    ++ SYSL ** [ O.Reg X24; O.Imm 0L; O.Reg C15; O.Reg C4; O.Imm 6L ]
    ||> test

  [<TestMethod>]
  member __.``C4.3.4 System (7)`` () =
    "d51c6080"
    ++ MSR ** [ O.Reg HPFAREL2; O.Reg X0 ]
    ||> test

  [<TestMethod>]
  member __.``C4.3.4 System (8)`` () =
    "d5181020"
    ++ MSR ** [ O.Reg ACTLREL1; O.Reg X0 ]
    ||> test

  [<TestMethod>]
  member __.``C4.3.4 System (9)`` () =
    "d5381020"
    ++ MRS ** [ O.Reg X0; O.Reg ACTLREL1 ]
    ||> test

  [<TestMethod>]
  member __.``C4.3.5 Test & branch (immediate) (1)`` () =
    "b6080043"
    ++ TBZ ** [ O.Reg X3; O.Imm 0x21L; O.MemLabel 0x8L ]
    ||> test

  [<TestMethod>]
  member __.``C4.3.6 Unconditional branch (immediate) (1)`` () =
    "14082a09"
    ++ B ** [ O.MemLabel 0x20a824L ]
    ||> test

  [<TestMethod>]
  member __.``C4.3.7 Unconditional branch (register) (1)`` () =
    "d61f03e0"
    ++ BR ** [ O.Reg XZR ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.1 load/store multiple structures (1)`` () =
    "0c0001c5"
    ++ ST4 ** [ O.SIMDList ([ V5; V6; V7; V8 ], EightB); O.MemBaseImm X14 ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.1 load/store multiple structures (2)`` () =
    "0c0081f8"
    ++ ST2 ** [ O.SIMDList ([ V24; V25 ], EightB); O.MemBaseImm X15 ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.1 load/store multiple structures (3)`` () =
    "0c402f3d"
    ++ LD1 ** [ O.SIMDList ([ V29; V30; V31; V0 ], OneD); O.MemBaseImm X25 ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.2 load/store multiple structures (post-indexed) (1)`` () =
    "0c800421"
    ++ ST4 ** [ O.SIMDList ([ V1; V2; V3; V4 ], FourH)
                O.MemPostIdxReg (X1, X0) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.2 load/store multiple structures (post-indexed) (2)`` () =
    "0c950539"
    ++ ST4 ** [ O.SIMDList ([ V25; V26; V27; V28 ], FourH)
                O.MemPostIdxReg (X9, X21) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.2 load/store multiple structures (post-indexed) (3)`` () =
    "4c9f0684"
    ++ ST4 ** [ O.SIMDList ([ V4; V5; V6; V7 ], EightH)
                O.MemPostIdxImm (X20, 0x40L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.2 load/store multiple structures (post-indexed) (4)`` () =
    "4cca46be"
    ++ LD3 ** [ O.SIMDList ([ V30; V31; V0 ], EightH)
                O.MemPostIdxReg (X21, X10) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.2 load/store multiple structures (post-indexed) (5)`` () =
    "4cdf0684"
    ++ LD4 ** [ O.SIMDList ([ V4; V5; V6; V7 ], EightH)
                O.MemPostIdxImm (X20, 0x40L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.3 load/store single structure (1)`` () =
    "0d00147e"
    ++ ST1 ** [ O.SIMDList ([ V30 ], VecB, 5uy); O.MemBaseImm X3 ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.3 load/store single structure (2)`` () =
    "0d0025c3"
    ++ ST3 ** [ O.SIMDList ([ V3; V4; V5 ], VecB, 1uy); O.MemBaseImm X14 ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.3 load/store single structure (3)`` () =
    "4d20b2bd"
    ++ ST4 ** [ O.SIMDList ([ V29; V30; V31; V0 ], VecS, 3uy)
                O.MemBaseImm X21 ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.3 load/store single structure (4)`` () =
    "4d601d4a"
    ++ LD2 ** [ O.SIMDList ([ V10; V11 ], VecB, 0xfuy); O.MemBaseImm X10 ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.3 load/store single structure (5)`` () =
    "4d40e6b5"
    ++ LD3R ** [ O.SIMDList ([ V21; V22; V23 ], EightH); O.MemBaseImm X21 ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.4 load/store single structure (post-indexed) (1)`` () =
    "0d8a06be"
    ++ ST1 ** [ O.SIMDList ([ V30 ], VecB, 1uy); O.MemPostIdxReg (X21, X10) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.4 load/store single structure (post-indexed) (2)`` () =
    "4d9f597e"
    ++ ST1 ** [ O.SIMDList ([ V30 ], VecH, 7uy)
                O.MemPostIdxImm (X11, 0x2L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.4 load/store single structure (post-indexed) (3)`` () =
    "4db581bd"
    ++ ST2 ** [ O.SIMDList ([ V29; V30 ], VecS, 2uy)
                O.MemPostIdxReg (X13, X21) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.4 load/store single structure (post-indexed) (4)`` () =
    "0dca06be"
    ++ LD1 ** [ O.SIMDList ([ V30 ], VecB, 1uy); O.MemPostIdxReg (X21, X10) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.4 load/store single structure (post-indexed) (5)`` () =
    "4dff39fd"
    ++ LD4 ** [ O.SIMDList ([ V29; V30; V31; V0 ], VecB, 0xeuy)
                O.MemPostIdxImm (X15, 0x4L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.5 Load register (literal) (1)`` () =
    "58531c49"
    ++ LDR ** [ O.Reg X9; O.MemLabel 0xa6388L ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.5 Load register (literal) (2)`` () =
    "9880001e"
    ++ LDRSW ** [ O.Reg X30; O.MemLabel 0xfffffffffff00000L ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.5 Load register (literal) (3)`` () =
    "d800802b"
    ++ PRFM ** [ O.Prefetch PLIL2STRM; O.MemLabel 0x1004L ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.6 Load/store exclusive (1)`` () =
    "08147cb5"
    ++ STXRB ** [ O.Reg W20; O.Reg W21; O.MemBaseImm X5 ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.6 Load/store exclusive (2)`` () =
    "882b04c2"
    ++ STXP ** [ O.Reg W11; O.Reg W2; O.Reg W1; O.MemBaseImm X6 ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.6 Load/store exclusive (3)`` () =
    "085f7d7a"
    ++ LDXRB ** [ O.Reg W26; O.MemBaseImm X11 ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.7 Load/store no-allocate pair (offset) (1)`` () =
    "280c2aa3"
    ++ STNP ** [ O.Reg W3; O.Reg W10; O.MemBaseImm (X21, 0x60L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.7 Load/store no-allocate pair (offset) (2)`` () =
    "ac1505b5"
    ++ STNP ** [ O.ScalarReg Q21; O.ScalarReg Q1; O.MemBaseImm (X13, 0x2a0L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.8 Load/store register (immediate post-indexed) (1)`` () =
    "3810a423"
    ++ STRB ** [ O.Reg W3; O.MemPostIdxImm (X1, 0xffffffffffffff0aL) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.8 Load/store register (immediate post-indexed) (2)`` () =
    "38cea4b2"
    ++ LDRSB ** [ O.Reg W18; O.MemPostIdxImm (X5, 0xeaL) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.8 Load/store register (immediate post-indexed) (3)`` () =
    "7c0ca422"
    ++ STR ** [ O.ScalarReg H2; O.MemPostIdxImm (X1, 0xcaL) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.8 Load/store register (immediate post-indexed) (4)`` () =
    "781004f5"
    ++ STRH ** [ O.Reg W21; O.MemPostIdxImm (X7, 0xffffffffffffff00L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.8 Load/store register (immediate post-indexed) (5)`` () =
    "b8803555"
    ++ LDRSW ** [ O.Reg X21; O.MemPostIdxImm (X10, 0x3L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.9 Load/store register (immediate pre-indexed) (1)`` () =
    "3800fcb1"
    ++ STRB ** [ O.Reg W17; O.MemPreIdxImm (X5, 0xfL) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.9 Load/store register (immediate pre-indexed) (2)`` () =
    "7c00fc6a"
    ++ STR ** [ O.ScalarReg H10; O.MemPreIdxImm (X3, 0xfL) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.10 Load/store register (register offset) (1)`` () =
    "38214867"
    ++ STRB ** [ O.Reg W7; O.MemBaseReg (X3, W1, ExtUXTW, None) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.10 Load/store register (register offset) (2)`` () =
    "38235867"
    ++ STRB ** [ O.Reg W7; O.MemBaseReg (X3, W3, ExtUXTW, Some 0x0L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.10 Load/store register (register offset) (3)`` () =
    "3820782c"
    ++ STRB ** [ O.Reg W12; O.MemBaseReg (X1, X0, SRTypeLSL, Imm 0x0L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.10 Load/store register (register offset) (4)`` () =
    "7867cabf"
    ++ LDRH ** [ O.Reg WZR; O.MemBaseReg (X21, W7, ExtSXTW, None) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.10 Load/store register (register offset) (5)`` () =
    "78e37871"
    ++ LDRSH ** [ O.Reg W17; O.MemBaseReg (X3, X3, SRTypeLSL, Imm 0x1L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.10 Load/store register (register offset) (6)`` () =
    "f8a35867"
    ++ PRFM ** [ O.Imm 0x7L; O.MemBaseReg (X3, W3, ExtUXTW, Some 0x3L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.10 Load/store register (register offset) (7)`` () =
    "f8a3586c"
    ++ PRFM ** [ O.Prefetch PLIL3KEEP
                 O.MemBaseReg (X3, W3, ExtUXTW, Some 0x3L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.11 Load/store register (unprivileged) (1)`` () =
    "380198ee"
    ++ STTRB ** [ O.Reg W14; O.MemBaseImm (X7, 0x19L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.11 Load/store register (unprivileged) (2)`` () =
    "781188ba"
    ++ STTRH ** [ O.Reg W26; O.MemBaseImm (X5, 0xffffffffffffff18L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.11 Load/store register (unprivileged) (3)`` () =
    "b881f86a"
    ++ LDTRSW ** [ O.Reg X10; O.MemBaseImm (X3, 0x1fL) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.12 Load/store register (unscaled immediate) (1)`` () =
    "3806a0f8"
    ++ STURB ** [ O.Reg W24; O.MemBaseImm (X7, 0x6aL) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.12 Load/store register (unscaled immediate) (2)`` () =
    "3cce0283"
    ++ LDUR ** [ O.ScalarReg Q3; O.MemBaseImm (X20, 0xe0L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.12 Load/store register (unscaled immediate) (3)`` () =
    "f881f07c"
    ++ PRFUM ** [ O.Imm 0x1cL; O.MemBaseImm (X3, 0x1fL) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.13 Load/store register (unsigned immediate) (1)`` () =
    "391557ff"
    ++ STRB ** [ O.Reg WZR; O.MemBaseImm (SP, 0x555L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.13 Load/store register (unsigned immediate) (2)`` () =
    "bd1fffff"
    ++ STR ** [ O.ScalarReg S31; O.MemBaseImm (SP, 0x1ffcL) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.13 Load/store register (unsigned immediate) (3)`` () =
    "f9be01f2"
    ++ PRFM ** [ O.Prefetch PSTL2KEEP; O.MemBaseImm (X15, 0x7c00L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.14 Load/store register pair (offset) (1)`` () =
    "2961cbb9"
    ++ LDP ** [ O.Reg W25; O.Reg W18; O.MemBaseImm (X29, 0xffffffffffffff0cL) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.15 Load/store register pair (post-indexed) (1)`` () =
    "a89fd7eb"
    ++ STP ** [ O.Reg X11; O.Reg X21; O.MemPostIdxImm (SP, 0x1f8L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.15 Load/store register pair (post-indexed) (2)`` () =
    "68cfdfdf"
    ++ LDPSW ** [ O.Reg XZR; O.Reg X23; O.MemPostIdxImm (X30, 0x7cL) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.16 Load/store register pair (pre-indexed) (1)`` () =
    "a99fffff"
    ++ STP ** [ O.Reg XZR; O.Reg XZR; O.MemPreIdxImm (SP, 0x1f8L) ]
    ||> test

  [<TestMethod>]
  member __.``4.5.1 Add/subtract (extended register) (1)`` () =
    "0b3f43ff"
    ++ ADD ** [ O.Reg WSP; O.Reg WSP; O.Reg WZR; O.RegOffset None ]
    ||> test

  [<TestMethod>]
  member __.``4.5.1 Add/subtract (extended register) (2)`` () =
    "0b3f4bff"
    ++ ADD ** [ O.Reg WSP; O.Reg WSP; O.Reg WZR
                O.RegOffset (Some (ShiftOffset (SRTypeLSL, Imm 2L))) ]
    ||> test

  [<TestMethod>]
  member __.``4.5.1 Add/subtract (extended register) (3)`` () =
    "8b2a495f"
    ++ ADD ** [ O.Reg SP; O.Reg X10; O.Reg W10
                O.RegOffset (Some (ExtRegOffset (ExtUXTW, Some 2L))) ]
    ||> test

  [<TestMethod>]
  member __.``4.5.1 Add/subtract (extended register) (4)`` () =
    "ab2e67ff"
    ++ CMN ** [ O.Reg SP; O.Reg X14
                O.RegOffset (Some (ShiftOffset (SRTypeLSL, Imm 1L))) ]
    ||> test

  [<TestMethod>]
  member __.``4.5.2 Add/subtract (shifted register) (1)`` () =
    "0b8e5f9b"
    ++ ADD ** [ O.Reg W27; O.Reg W28; O.Reg W14; O.Shift (SRTypeASR, 23L) ]
    ||> test

  [<TestMethod>]
  member __.``4.5.2 Add/subtract (shifted register) (2)`` () =
    "6b4e1fab"
    ++ SUBS ** [ O.Reg W11; O.Reg W29; O.Reg W14; O.Shift (SRTypeLSR, 7L) ]
    ||> test

  [<TestMethod>]
  member __.``4.5.2 Add/subtract (shifted register) (3)`` () =
    "ab8e1fb2"
    ++ ADDS ** [ O.Reg X18; O.Reg X29; O.Reg X14; O.Shift (SRTypeASR, 7L) ]
    ||> test

  [<TestMethod>]
  member __.``4.5.3 Add/subtract (with carry) (1)`` () =
    "ba0a02bf"
    ++ ADCS ** [ O.Reg XZR; O.Reg X21; O.Reg X10 ]
    ||> test

  [<TestMethod>]
  member __.``4.5.3 Add/subtract (with carry) (2)`` () =
    "5a0b03fe"
    ++ NGC ** [ O.Reg W30; O.Reg W11 ]
    ||> test

  [<TestMethod>]
  member __.``4.5.4 Conditional compare (immediate) (1)`` () =
    "ba55c868"
    ++ CCMN ** [ O.Reg X3; O.Imm 0x15L; OprNZCV 8uy; OprCond GT ]
    ||> test

  [<TestMethod>]
  member __.``4.5.5 Conditional compare (register) (1)`` () =
    "ba5c51ef"
    ++ CCMN ** [ O.Reg X15; O.Reg X28; OprNZCV 0xfuy; OprCond PL ]
    ||> test

  [<TestMethod>]
  member __.``4.5.6 Conditional select (1)`` () =
    "9a8692fc"
    ++ CSEL ** [ O.Reg X28; O.Reg X23; O.Reg X6; OprCond LS ]
    ||> test

  [<TestMethod>]
  member __.``4.5.6 Conditional select (2)`` () =
    "1a902415"
    ++ CSINC ** [ O.Reg W21; O.Reg W0; O.Reg W16; OprCond CS ] // HS
    ||> test

  [<TestMethod>]
  member __.``4.5.6 Conditional select (3)`` () =
    "1a902615"
    ++ CINC ** [ O.Reg W21; O.Reg W16; OprCond CC ] // LO
    ||> test

  [<TestMethod>]
  member __.``4.5.6 Conditional select (4)`` () =
    "1a9fc7e7"
    ++ CSET ** [ O.Reg W7; OprCond LE ]
    ||> test

  [<TestMethod>]
  member __.``4.5.6 Conditional select (5)`` () =
    "da87c0ea"
    ++ CINV ** [ O.Reg X10; O.Reg X7; OprCond LE ]
    ||> test

  [<TestMethod>]
  member __.``4.5.6 Conditional select (6)`` () =
    "da9fc3ea"
    ++ CSETM ** [ O.Reg X10; OprCond LE ]
    ||> test

  [<TestMethod>]
  member __.``4.5.6 Conditional select (7)`` () =
    "da9fc36a"
    ++ CSINV ** [ O.Reg X10; O.Reg X27; O.Reg XZR; OprCond GT ]
    ||> test

  [<TestMethod>]
  member __.``4.5.6 Conditional select (8)`` () =
    "5a8ae6be"
    ++ CSNEG ** [ O.Reg W30; O.Reg W21; O.Reg W10; OprCond AL ]
    ||> test

  [<TestMethod>]
  member __.``4.5.6 Conditional select (9)`` () =
    "5a95c6be"
    ++ CNEG ** [ O.Reg W30; O.Reg W21; OprCond LE ]
    ||> test

  [<TestMethod>]
  member __.``4.5.7 Data-processing (1 source) (1)`` () =
    "5ac0017c"
    ++ RBIT ** [ O.Reg W28; O.Reg W11 ]
    ||> test

  [<TestMethod>]
  member __.``4.5.7 Data-processing (1 source) (2)`` () =
    "dac0157f"
    ++ CLS ** [ O.Reg XZR; O.Reg X11 ]
    ||> test

  [<TestMethod>]
  member __.``4.5.7 Data-processing (1 source) (3)`` () =
    "dac009fe"
    ++ REV32 ** [ O.Reg X30; O.Reg X15 ]
    ||> test

  [<TestMethod>]
  member __.``4.5.8 Data-processing (2 source) (1)`` () =
    "1ac90afe"
    ++ UDIV ** [ O.Reg W30; O.Reg W23; O.Reg W9 ]
    ||> test

  [<TestMethod>]
  member __.``4.5.8 Data-processing (2 source) (2)`` () =
    "9ada5c7d"
    ++ CRC32CX ** [ O.Reg W29; O.Reg W3; O.Reg X26 ]
    ||> test

  [<TestMethod>]
  member __.``4.5.9 Data-processing (3 source) (1)`` () =
    "9b0a2f87"
    ++ MADD ** [ O.Reg X7; O.Reg X28; O.Reg X10; O.Reg X11 ]
    ||> test

  [<TestMethod>]
  member __.``4.5.9 Data-processing (3 source) (2)`` () =
    "9b0a7f87"
    ++ MUL ** [ O.Reg X7; O.Reg X28; O.Reg X10 ]
    ||> test

  [<TestMethod>]
  member __.``4.5.9 Data-processing (3 source) (3)`` () =
    "9b0aaf87"
    ++ MSUB ** [ O.Reg X7; O.Reg X28; O.Reg X10; O.Reg X11 ]
    ||> test

  [<TestMethod>]
  member __.``4.5.9 Data-processing (3 source) (4)`` () =
    "9b2a2f87"
    ++ SMADDL ** [ O.Reg X7; O.Reg W28; O.Reg W10; O.Reg X11 ]
    ||> test

  [<TestMethod>]
  member __.``4.5.9 Data-processing (3 source) (5)`` () =
    "9b2aaf87"
    ++ SMSUBL ** [ O.Reg X7; O.Reg W28; O.Reg W10; O.Reg X11 ]
    ||> test

  [<TestMethod>]
  member __.``4.5.9 Data-processing (3 source) (6)`` () =
    "9b4a2f87"
    ++ SMULH ** [ O.Reg X7; O.Reg X28; O.Reg X10 ]
    ||> test

  [<TestMethod>]
  member __.``4.5.9 Data-processing (3 source) (7)`` () =
    "9baa2f87"
    ++ UMADDL ** [ O.Reg X7; O.Reg W28; O.Reg W10; O.Reg X11 ]
    ||> test

  [<TestMethod>]
  member __.``4.5.9 Data-processing (3 source) (8)`` () =
    "9baaaf87"
    ++ UMSUBL ** [ O.Reg X7; O.Reg W28; O.Reg W10; O.Reg X11 ]
    ||> test

  [<TestMethod>]
  member __.``4.5.9 Data-processing (3 source) (9)`` () =
    "9bca2f87"
    ++ UMULH ** [ O.Reg X7; O.Reg X28; O.Reg X10 ]
    ||> test

  [<TestMethod>]
  member __.``4.5.9 Data-processing (3 source) (10)`` () =
    "9b0aff87"
    ++ MNEG ** [ O.Reg X7; O.Reg X28; O.Reg X10 ]
    ||> test

  [<TestMethod>]
  member __.``4.5.9 Data-processing (3 source) (11)`` () =
    "9b2a7f87"
    ++ SMULL ** [ O.Reg X7; O.Reg W28; O.Reg W10 ]
    ||> test

  [<TestMethod>]
  member __.``4.5.9 Data-processing (3 source) (12)`` () =
    "9b2aff87"
    ++ SMNEGL ** [ O.Reg X7; O.Reg W28; O.Reg W10 ]
    ||> test

  [<TestMethod>]
  member __.``4.5.9 Data-processing (3 source) (13)`` () =
    "9baa7f87"
    ++ UMULL ** [ O.Reg X7; O.Reg W28; O.Reg W10 ]
    ||> test

  [<TestMethod>]
  member __.``4.5.9 Data-processing (3 source) (14)`` () =
    "9baaff87"
    ++ UMNEGL ** [ O.Reg X7; O.Reg W28; O.Reg W10 ]
    ||> test

  [<TestMethod>]
  member __.``4.5.10 Logical (shifted register) (1)`` () =
    "8a583945"
    ++ AND ** [ O.Reg X5; O.Reg X10; O.Reg X24; O.Shift (SRTypeLSR, 14L) ]
    ||> test

  [<TestMethod>]
  member __.``4.5.10 Logical (shifted register) (2)`` () =
    "2af61fba"
    ++ ORN ** [ O.Reg W26; O.Reg W29; O.Reg W22; O.Shift (SRTypeROR, 7L) ]
    ||> test

  [<TestMethod>]
  member __.``4.5.10 Logical (shifted register) (3)`` () =
    "2af61ffa"
    ++ MVN ** [ O.Reg W26; O.Reg W22; O.Shift (SRTypeROR, 0x7L) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.1 Advanced SIMD across lanes (1)`` () =
    "4eb03ac2"
    ++ SADDLV ** [ O.ScalarReg D2; O.SIMDVecReg (V22, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.1 Advanced SIMD across lanes (2)`` () =
    "0e30a8d2"
    ++ SMAXV ** [ O.ScalarReg B18; O.SIMDVecReg (V6, EightB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.1 Advanced SIMD across lanes (3)`` () =
    "0e71aa0a"
    ++ SMINV ** [ O.ScalarReg H10; O.SIMDVecReg (V16, FourH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.1 Advanced SIMD across lanes (4)`` () =
    "4e71b89a"
    ++ ADDV ** [ O.ScalarReg H26; O.SIMDVecReg (V4, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.1 Advanced SIMD across lanes (5)`` () =
    "6eb03931"
    ++ UADDLV ** [ O.ScalarReg D17; O.SIMDVecReg (V9, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.1 Advanced SIMD across lanes (6)`` () =
    "2e70ab88"
    ++ UMAXV ** [ O.ScalarReg H8; O.SIMDVecReg (V28, FourH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.1 Advanced SIMD across lanes (7)`` () =
    "6eb1aaea"
    ++ UMINV ** [ O.ScalarReg S10; O.SIMDVecReg (V23, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.1 Advanced SIMD across lanes (8)`` () =
    "6e30ca4b"
    ++ FMAXNMV ** [ O.ScalarReg S11; O.SIMDVecReg (V18, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.1 Advanced SIMD across lanes (9)`` () =
    "6e30f948"
    ++ FMAXV ** [ O.ScalarReg S8; O.SIMDVecReg (V10, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.1 Advanced SIMD across lanes (10)`` () =
    "6eb0cacc"
    ++ FMINNMV ** [ O.ScalarReg S12; O.SIMDVecReg (V22, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.1 Advanced SIMD across lanes (11)`` () =
    "6eb0fac2"
    ++ FMINV ** [ O.ScalarReg S2; O.SIMDVecReg (V22, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.2 Advanced SIMD copy (1)`` () =
    "4e180486"
    ++ DUP ** [ O.SIMDVecReg (V6, TwoD); O.SIMDVecRegWithIdx (V4, VecD, 1uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.2 Advanced SIMD copy (2)`` () =
    "4e080c61"
    ++ DUP ** [ O.SIMDVecReg (V1, TwoD); O.Reg X3 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.2 Advanced SIMD copy (3)`` () =
    // Online HEX To ARM Conv error
    "0e1e0ffc"
    ++ DUP ** [ O.SIMDVecReg (V28, FourH); O.Reg WZR ]
    ||> test

  [<TestMethod>]
  member __.``4.6.2 Advanced SIMD copy (4)`` () =
    "0e020ffc"
    ++ DUP ** [ O.SIMDVecReg (V28, FourH); O.Reg WZR ]
    ||> test

  [<TestMethod>]
  member __.``4.6.2 Advanced SIMD copy (5)`` () =
    "0e022cfa"
    ++ SMOV ** [ O.Reg W26; O.SIMDVecRegWithIdx (V7, VecH, 0uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.2 Advanced SIMD copy (6)`` () =
    "0e013dc3"
    ++ UMOV ** [ O.Reg W3; O.SIMDVecRegWithIdx (V14, VecB, 0uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.2 Advanced SIMD copy (7)`` () =
    "0e043dc3"
    ++ MOV ** [ O.Reg W3; O.SIMDVecRegWithIdx (V14, VecS, 0uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.2 Advanced SIMD copy (8)`` () =
    "4e083dc3"
    ++ MOV ** [ O.Reg X3; O.SIMDVecRegWithIdx (V14, VecD, 0uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.2 Advanced SIMD copy (9)`` () =
    "4e041c29"
    ++ INS ** [ O.SIMDVecRegWithIdx (V9, VecS, 0uy); O.Reg W1 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.2 Advanced SIMD copy (10)`` () =
    "6e0274c5"
    ++ INS ** [ O.SIMDVecRegWithIdx (V5, VecH, 0uy)
                O.SIMDVecRegWithIdx (V6, VecH, 7uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.3 Advanced SIMD extract (1)`` () =
    "6e064983"
    ++ EXT ** [ O.SIMDVecReg (V3, SixteenB); O.SIMDVecReg (V12, SixteenB)
                O.SIMDVecReg (V6, SixteenB); O.Imm 9L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.3 Advanced SIMD extract (2)`` () =
    "2e0738fc"
    ++ EXT ** [ O.SIMDVecReg (V28, EightB); O.SIMDVecReg (V7, EightB)
                O.SIMDVecReg (V7, EightB); O.Imm 7L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.4 Advanced SIMD modified immediate (1)`` () =
    "4f056559"
    ++ MOVI ** [ O.SIMDVecReg (V25, FourS); O.Imm 0xAAL
                 O.Shift (SRTypeLSL, 24L) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.4 Advanced SIMD modified immediate (2)`` () =
    "4f050559"
    ++ MOVI ** [ O.SIMDVecReg (V25, FourS); O.Imm 0xAAL ]
    ||> test

  [<TestMethod>]
  member __.``4.6.4 Advanced SIMD modified immediate (3)`` () =
    "4f0234c5"
    ++ ORR ** [ O.SIMDVecReg (V5, FourS); O.Imm 0x46L; O.Shift (SRTypeLSL, 8L) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.4 Advanced SIMD modified immediate (4)`` () =
    "4f01e5d9"
    ++ MOVI ** [ O.SIMDVecReg (V25, SixteenB); O.Imm 0x2EL ]
    ||> test

  [<TestMethod>]
  member __.``4.6.4 Advanced SIMD modified immediate (5)`` () =
    "0f06b4e5"
    ++ ORR ** [ O.SIMDVecReg (V5, FourH); O.Imm 0xC7L; O.Shift (SRTypeLSL, 8L) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.4 Advanced SIMD modified immediate (6)`` () =
    "4f04a759"
    ++ MOVI ** [ O.SIMDVecReg (V25, EightH); O.Imm 0x9AL
                 O.Shift (SRTypeLSL, 8L) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.4 Advanced SIMD modified immediate (7)`` () =
    "4f05c655"
    ++ MOVI ** [ O.SIMDVecReg (V21, FourS); O.Imm 0xB2L
                 O.Shift (SRTypeMSL, 8L) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.4 Advanced SIMD modified immediate (8)`` () =
    "4f05f4e5"
    ++ FMOV ** [ O.SIMDVecReg (V5, FourS); OprFPImm -11.5 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.4 Advanced SIMD modified immediate (9)`` () =
    "6f0724d5"
    ++ MVNI ** [ O.SIMDVecReg (V21, FourS); O.Imm 0xE6L
                 O.Shift (SRTypeLSL, 8L) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.4 Advanced SIMD modified immediate (10)`` () =
    "2f0536a7"
    ++ BIC ** [ O.SIMDVecReg (V7, TwoS); O.Imm 0xB5L; O.Shift (SRTypeLSL, 8L) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.4 Advanced SIMD modified immediate (11)`` () =
    "6f07a4d5"
    ++ MVNI ** [ O.SIMDVecReg (V21, EightH); O.Imm 0xE6L
                 O.Shift (SRTypeLSL, 8L) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.4 Advanced SIMD modified immediate (12)`` () =
    "2f0596a7"
    ++ BIC ** [ O.SIMDVecReg (V7, FourH); O.Imm 0xB5L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.4 Advanced SIMD modified immediate (13)`` () =
    "6f07c4d5"
    ++ MVNI ** [ O.SIMDVecReg (V21, FourS); O.Imm 0xE6L
                 O.Shift (SRTypeMSL, 8L) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.4 Advanced SIMD modified immediate (14)`` () =
    "2f05e75b"
    ++ MOVI ** [ O.ScalarReg D27; O.Imm 0xFF00FFFFFF00FF00L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.4 Advanced SIMD modified immediate (15)`` () =
    "6f05e757"
    ++ MOVI ** [ O.SIMDVecReg (V23, TwoD); O.Imm 0xFF00FFFFFF00FF00L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.4 Advanced SIMD modified immediate (16)`` () =
    "6f05f4e5"
    ++ FMOV ** [ O.SIMDVecReg (V5, TwoD); OprFPImm -11.5 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.5 Advanced SIMD permute (1)`` () =
    "4e4e1983"
    ++ UZP1 ** [ O.SIMDVecReg (V3, EightH); O.SIMDVecReg (V12, EightH)
                 O.SIMDVecReg (V14, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.5 Advanced SIMD permute (2)`` () =
    "0e8728fe"
    ++ TRN1 ** [ O.SIMDVecReg (V30, TwoS); O.SIMDVecReg (V7, TwoS)
                 O.SIMDVecReg (V7, TwoS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.5 Advanced SIMD permute (3)`` () =
    "4e03383c"
    ++ ZIP1 ** [ O.SIMDVecReg (V28, SixteenB); O.SIMDVecReg (V1, SixteenB)
                 O.SIMDVecReg (V3, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.5 Advanced SIMD permute (4)`` () =
    "0e0738c1"
    ++ ZIP1 ** [ O.SIMDVecReg (V1, EightB); O.SIMDVecReg (V6, EightB)
                 O.SIMDVecReg (V7, EightB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.5 Advanced SIMD permute (5)`` () =
    "4ec158c6"
    ++ UZP2 ** [ O.SIMDVecReg (V6, TwoD); O.SIMDVecReg (V6, TwoD)
                 O.SIMDVecReg (V1, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.5 Advanced SIMD permute (6)`` () =
    "0e8768c3"
    ++ TRN2 ** [ O.SIMDVecReg (V3, TwoS); O.SIMDVecReg (V6, TwoS)
                 O.SIMDVecReg (V7, TwoS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.5 Advanced SIMD permute (7)`` () =
    "4e017885"
    ++ ZIP2 ** [ O.SIMDVecReg (V5, SixteenB); O.SIMDVecReg (V4, SixteenB)
                 O.SIMDVecReg (V1, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.6 Advanced SIMD scalar copy (1)`` () =
    "5e08054a"
    ++ MOV ** [ O.ScalarReg D10; O.SIMDVecRegWithIdx (V10, VecD, 0uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.6 Advanced SIMD scalar copy (2)`` () =
    "5e070541"
    ++ MOV ** [ O.ScalarReg B1; O.SIMDVecRegWithIdx (V10, VecB, 3uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.7 Advanced SIMD scalar pairwise (1)`` () =
    "5ef1b867"
    ++ ADDP ** [ O.ScalarReg D7; O.SIMDVecReg (V3, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.7 Advanced SIMD scalar pairwise (2)`` () =
    "7e70c9cf"
    ++ FMAXNMP ** [ O.ScalarReg D15; O.SIMDVecReg (V14, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.7 Advanced SIMD scalar pairwise (3)`` () =
    "7e30d9ff"
    ++ FADDP ** [ O.ScalarReg S31; O.SIMDVecReg (V15, TwoS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.7 Advanced SIMD scalar pairwise (4)`` () =
    "7e70fa32"
    ++ FMAXP ** [ O.ScalarReg D18; O.SIMDVecReg (V17, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.7 Advanced SIMD scalar pairwise (5)`` () =
    "7eb0c9c1"
    ++ FMINNMP ** [ O.ScalarReg S1; O.SIMDVecReg (V14, TwoS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.7 Advanced SIMD scalar pairwise (6)`` () =
    "7ef0f827"
    ++ FMINP ** [ O.ScalarReg D7; O.SIMDVecReg (V1, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (1)`` () =
    "5f420541"
    ++ SSHR ** [ O.ScalarReg D1; O.ScalarReg D10; O.Imm 0x3eL ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (2)`` () =
    "5f64147c"
    ++ SSRA ** [ O.ScalarReg D28; O.ScalarReg D3; O.Imm 0x1cL ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (3)`` () =
    "5f5924e1"
    ++ SRSHR ** [ O.ScalarReg D1; O.ScalarReg D7; O.Imm 0x27L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (4)`` () =
    "5f7f34c3"
    ++ SRSRA ** [ O.ScalarReg D3; O.ScalarReg D6; O.Imm 1L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (5)`` () =
    "5f4254ed"
    ++ SHL ** [ O.ScalarReg D13; O.ScalarReg D7; O.Imm 2L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (6)`` () =
    "5f247619"
    ++ SQSHL ** [ O.ScalarReg S25; O.ScalarReg S16; O.Imm 4L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (7)`` () =
    "5f647619"
    ++ SQSHL ** [ O.ScalarReg D25; O.ScalarReg D16; O.Imm 0x24L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (8)`` () =
    "5f299587"
    ++ SQSHRN ** [ O.ScalarReg S7; O.ScalarReg D12; O.Imm 0x17L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (9)`` () =
    "5f1f9cf9"
    ++ SQRSHRN ** [ O.ScalarReg H25; O.ScalarReg S7; O.Imm 1L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (10)`` () =
    "5f61e4c1"
    ++ SCVTF ** [ O.ScalarReg D1; O.ScalarReg D6; OprFbits 0x1fuy ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (11)`` () =
    "5f5bfd0b"
    ++ FCVTZS ** [ O.ScalarReg D11; O.ScalarReg D8; OprFbits 0x25uy ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (12)`` () =
    "7f6905c7"
    ++ USHR ** [ O.ScalarReg D7; O.ScalarReg D14; O.Imm 0x17L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (13)`` () =
    "7f4a1431"
    ++ USRA ** [ O.ScalarReg D17; O.ScalarReg D1; O.Imm 0x36L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (14)`` () =
    "7f602449"
    ++ URSHR ** [ O.ScalarReg D9; O.ScalarReg D2; O.Imm 0x20L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (15)`` () =
    "7f4434c9"
    ++ URSRA ** [ O.ScalarReg D9; O.ScalarReg D6; O.Imm 0x3cL ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (16)`` () =
    "7f6145c3"
    ++ SRI ** [ O.ScalarReg D3; O.ScalarReg D14; O.Imm 0x1fL ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (17)`` () =
    "7f4e54c3"
    ++ SLI ** [ O.ScalarReg D3; O.ScalarReg D6; O.Imm 0xeL ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (18)`` () =
    "7f2b6687"
    ++ SQSHLU ** [ O.ScalarReg S7; O.ScalarReg S20; O.Imm 0xbL ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (19)`` () =
    "7f0b74f8"
    ++ UQSHL ** [ O.ScalarReg B24; O.ScalarReg B7; O.Imm 3L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (20)`` () =
    "7f2f858d"
    ++ SQSHRUN ** [ O.ScalarReg S13; O.ScalarReg D12; O.Imm 0x11L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (21)`` () =
    "7f3a8c30"
    ++ SQRSHRUN ** [ O.ScalarReg S16; O.ScalarReg D1; O.Imm 6L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (22)`` () =
    "7f1594cd"
    ++ UQSHRN ** [ O.ScalarReg H13; O.ScalarReg S6; O.Imm 0xbL ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (23)`` () =
    "7f0c9c46"
    ++ UQRSHRN ** [ O.ScalarReg B6; O.ScalarReg H2; O.Imm 4L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (24)`` () =
    "7f24e4c1"
    ++ UCVTF ** [ O.ScalarReg S1; O.ScalarReg S6; OprFbits 0x1cuy ]
    ||> test

  [<TestMethod>]
  member __.``4.6.8 Advanced SIMD scalar shift by imm (25)`` () =
    "7f51fc83"
    ++ FCVTZU ** [ O.ScalarReg D3; O.ScalarReg D4; OprFbits 0x2fuy ]
    ||> test

  [<TestMethod>]
  member __.``4.6.9 Advanced SIMD scalar three different (1)`` () =
    "5ea693c2"
    ++ SQDMLAL ** [ O.ScalarReg D2; O.ScalarReg S30; O.ScalarReg S6 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.9 Advanced SIMD scalar three different (2)`` () =
    "5e61b006"
    ++ SQDMLSL ** [ O.ScalarReg S6; O.ScalarReg H0; O.ScalarReg H1 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.9 Advanced SIMD scalar three different (3)`` () =
    "5ea2d242"
    ++ SQDMULL ** [ O.ScalarReg D2; O.ScalarReg S18; O.ScalarReg S2 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (1)`` () =
    "5e210dfc"
    ++ SQADD ** [ O.ScalarReg B28; O.ScalarReg B15; O.ScalarReg B1 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (2)`` () =
    "5e632fc5"
    ++ SQSUB ** [ O.ScalarReg H5; O.ScalarReg H30; O.ScalarReg H3 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (3)`` () =
    "5ee134c5"
    ++ CMGT ** [ O.ScalarReg D5; O.ScalarReg D6; O.ScalarReg D1 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (4)`` () =
    "5ee73cca"
    ++ CMGE ** [ O.ScalarReg D10; O.ScalarReg D6; O.ScalarReg D7 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (5)`` () =
    "5eff441e"
    ++ SSHL ** [ O.ScalarReg D30; O.ScalarReg D0; O.ScalarReg D31 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (6)`` () =
    "5e294f0e"
    ++ SQSHL ** [ O.ScalarReg B14; O.ScalarReg B24; O.ScalarReg B9 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (7)`` () =
    "5efe5791"
    ++ SRSHL ** [ O.ScalarReg D17; O.ScalarReg D28; O.ScalarReg D30 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (8)`` () =
    "5e6e5e2e"
    ++ SQRSHL ** [ O.ScalarReg H14; O.ScalarReg H17; O.ScalarReg H14 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (9)`` () =
    "5ef88478"
    ++ ADD ** [ O.ScalarReg D24; O.ScalarReg D3; O.ScalarReg D24 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (10)`` () =
    "5efc8d8a"
    ++ CMTST ** [ O.ScalarReg D10; O.ScalarReg D12; O.ScalarReg D28 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (11)`` () =
    "5ea1b4f0"
    ++ SQDMULH ** [ O.ScalarReg S16; O.ScalarReg S7; O.ScalarReg S1 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (12)`` () =
    "5e61df0c"
    ++ FMULX ** [ O.ScalarReg D12; O.ScalarReg D24; O.ScalarReg D1 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (13)`` () =
    "5e38e4c1"
    ++ FCMEQ ** [ O.ScalarReg S1; O.ScalarReg S6; O.ScalarReg S24 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (14)`` () =
    "5e61fc44"
    ++ FRECPS ** [ O.ScalarReg D4; O.ScalarReg D2; O.ScalarReg D1 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (15)`` () =
    "5ee1fe18"
    ++ FRSQRTS ** [ O.ScalarReg D24; O.ScalarReg D16; O.ScalarReg D1 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (16)`` () =
    "7e610d12"
    ++ UQADD ** [ O.ScalarReg H18; O.ScalarReg H8; O.ScalarReg H1 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (17)`` () =
    "7e2c2d81"
    ++ UQSUB ** [ O.ScalarReg B1; O.ScalarReg B12; O.ScalarReg B12 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (18)`` () =
    "7ee134be"
    ++ CMHI ** [ O.ScalarReg D30; O.ScalarReg D5; O.ScalarReg D1 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (19)`` () =
    "7ee33f12"
    ++ CMHS ** [ O.ScalarReg D18; O.ScalarReg D24; O.ScalarReg D3 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (20)`` () =
    "7ee34541"
    ++ USHL ** [ O.ScalarReg D1; O.ScalarReg D10; O.ScalarReg D3 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (21)`` () =
    "7e274e11"
    ++ UQSHL ** [ O.ScalarReg B17; O.ScalarReg B16; O.ScalarReg B7 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (22)`` () =
    "7ee15703"
    ++ URSHL ** [ O.ScalarReg D3; O.ScalarReg D24; O.ScalarReg D1 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (23)`` () =
    "7e675e38"
    ++ UQRSHL ** [ O.ScalarReg H24; O.ScalarReg H17; O.ScalarReg H7 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (24)`` () =
    "7eea84df"
    ++ SUB ** [ O.ScalarReg D31; O.ScalarReg D6; O.ScalarReg D10 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (25)`` () =
    "7ee08e24"
    ++ CMEQ ** [ O.ScalarReg D4; O.ScalarReg D17; O.ScalarReg D0 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (26)`` () =
    "7e61b4ca"
    ++ SQRDMULH ** [ O.ScalarReg H10; O.ScalarReg H6; O.ScalarReg H1 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (27)`` () =
    "7ea7b501"
    ++ SQRDMULH ** [ O.ScalarReg S1; O.ScalarReg S8; O.ScalarReg S7 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (28)`` () =
    "7e61e606"
    ++ FCMGE ** [ O.ScalarReg D6; O.ScalarReg D16; O.ScalarReg D1 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (29)`` () =
    "7e21ec41"
    ++ FACGE ** [ O.ScalarReg S1; O.ScalarReg S2; O.ScalarReg S1 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (30)`` () =
    "7ea1d626"
    ++ FABD ** [ O.ScalarReg S6; O.ScalarReg S17; O.ScalarReg S1 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (31)`` () =
    "7ee4e687"
    ++ FCMGT ** [ O.ScalarReg D7; O.ScalarReg D20; O.ScalarReg D4 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.10 Advanced SIMD scalar three same (32)`` () =
    "7ea5ec73"
    ++ FACGT ** [ O.ScalarReg S19; O.ScalarReg S3; O.ScalarReg S5 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (1)`` () =
    "5ea03bb5"
    ++ SUQADD ** [ O.ScalarReg S21; O.ScalarReg S29 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (2)`` () =
    "5e607bc1"
    ++ SQABS ** [ O.ScalarReg H1; O.ScalarReg H30 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (3)`` () =
    "5ee089fe"
    ++ CMGT ** [ O.ScalarReg D30; O.ScalarReg D15; O.Imm 0L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (4)`` () =
    "5ee09af4"
    ++ CMEQ ** [ O.ScalarReg D20; O.ScalarReg D23; O.Imm 0L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (5)`` () =
    "5ee0abdc"
    ++ CMLT ** [ O.ScalarReg D28; O.ScalarReg D30; O.Imm 0L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (6)`` () =
    "5ee0bb11"
    ++ ABS ** [ O.ScalarReg D17; O.ScalarReg D24 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (7)`` () =
    "5e614b87"
    ++ SQXTN ** [ O.ScalarReg H7; O.ScalarReg S28 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (8)`` () =
    "5e61ab01"
    ++ FCVTNS ** [ O.ScalarReg D1; O.ScalarReg D24 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (9)`` () =
    "5e21bb36"
    ++ FCVTMS ** [ O.ScalarReg S22; O.ScalarReg S25 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (10)`` () =
    "5e61caff"
    ++ FCVTAS ** [ O.ScalarReg D31; O.ScalarReg D23 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (11)`` () =
    "5e21daaa"
    ++ SCVTF ** [ O.ScalarReg S10; O.ScalarReg S21 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (12)`` () =
    "5ea0cabc"
    ++ FCMGT ** [ O.ScalarReg S28; O.ScalarReg S21; OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (13)`` () =
    "5ee0da39"
    ++ FCMEQ ** [ O.ScalarReg D25; O.ScalarReg D17; OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (14)`` () =
    "5ee0c9fe"
    ++ FCMGT ** [ O.ScalarReg D30; O.ScalarReg D15; OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (15)`` () =
    "5ea1abfc"
    ++ FCVTPS ** [ O.ScalarReg S28; O.ScalarReg S31 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (16)`` () =
    "5ee1b9fe"
    ++ FCVTZS ** [ O.ScalarReg D30; O.ScalarReg D15 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (17)`` () =
    "5ea1daf6"
    ++ FRECPE ** [ O.ScalarReg S22; O.ScalarReg S23 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (18)`` () =
    "5ee1f9ff"
    ++ FRECPX ** [ O.ScalarReg D31; O.ScalarReg D15 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (19)`` () =
    "7ea03a7c"
    ++ USQADD ** [ O.ScalarReg S28; O.ScalarReg S19 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (20)`` () =
    "7e60795b"
    ++ SQNEG ** [ O.ScalarReg H27; O.ScalarReg H10 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (21)`` () =
    "7ee08a81"
    ++ CMGE ** [ O.ScalarReg D1; O.ScalarReg D20; O.Imm 0L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (22)`` () =
    "7ee09a38"
    ++ CMLE ** [ O.ScalarReg D24; O.ScalarReg D17; O.Imm 0L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (23)`` () =
    "7ee0b97f"
    ++ NEG ** [ O.ScalarReg D31; O.ScalarReg D11 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (24)`` () =
    "7ea12a11"
    ++ SQXTUN ** [ O.ScalarReg S17; O.ScalarReg D16 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (25)`` () =
    "7e214a81"
    ++ UQXTN ** [ O.ScalarReg B1; O.ScalarReg H20 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (26)`` () =
    "7e616af8"
    ++ FCVTXN ** [ O.ScalarReg S24; O.ScalarReg D23 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (27)`` () =
    "7e21aaf8"
    ++ FCVTNU ** [ O.ScalarReg S24; O.ScalarReg S23 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (28)`` () =
    "7e61b807"
    ++ FCVTMU ** [ O.ScalarReg D7; O.ScalarReg D0 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (29)`` () =
    "7e21ca11"
    ++ FCVTAU ** [ O.ScalarReg S17; O.ScalarReg S16 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (30)`` () =
    "7e61d844"
    ++ UCVTF ** [ O.ScalarReg D4; O.ScalarReg D2 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (31)`` () =
    "7ea0cafe"
    ++ FCMGE ** [ O.ScalarReg S30; O.ScalarReg S23; OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (32)`` () =
    "7ee0d8c8"
    ++ FCMLE ** [ O.ScalarReg D8; O.ScalarReg D6; OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (33)`` () =
    "7ea1aa21"
    ++ FCVTPU ** [ O.ScalarReg S1; O.ScalarReg S17 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (34)`` () =
    "7ee1b823"
    ++ FCVTZU ** [ O.ScalarReg D3; O.ScalarReg D1 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (35)`` () =
    "7ea1da35"
    ++ FRSQRTE ** [ O.ScalarReg S21; O.ScalarReg S17 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.11 Advanced SIMD scalar two-reg misc (36)`` () =
    "7ee1dabd"
    ++ FRSQRTE ** [ O.ScalarReg D29; O.ScalarReg D21 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.12 Advanced SIMD scalar x indexed elem (1)`` () =
    "5f883a21"
    ++ SQDMLAL ** [ O.ScalarReg D1; O.ScalarReg S17
                    O.SIMDVecRegWithIdx (V8, VecS, 2uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.12 Advanced SIMD scalar x indexed elem (2)`` () =
    "5f767b1a"
    ++ SQDMLSL ** [ O.ScalarReg S26; O.ScalarReg H24
                    O.SIMDVecRegWithIdx (V6, VecH, 7uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.12 Advanced SIMD scalar x indexed elem (3)`` () =
    "5facba67"
    ++ SQDMULL ** [ O.ScalarReg D7; O.ScalarReg S19
                    O.SIMDVecRegWithIdx (V12, VecS, 3uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.12 Advanced SIMD scalar x indexed elem (4)`` () =
    "5f7ec203"
    ++ SQDMULH ** [ O.ScalarReg H3; O.ScalarReg H16
                    O.SIMDVecRegWithIdx (V14, VecH, 3uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.12 Advanced SIMD scalar x indexed elem (5)`` () =
    "5fbfcb7b"
    ++ SQDMULH ** [ O.ScalarReg S27; O.ScalarReg S27
                    O.SIMDVecRegWithIdx (V31, VecS, 3uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.12 Advanced SIMD scalar x indexed elem (6)`` () =
    "5f7fda7c"
    ++ SQRDMULH ** [ O.ScalarReg H28; O.ScalarReg H19
                     O.SIMDVecRegWithIdx (V15, VecH, 7uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.12 Advanced SIMD scalar x indexed elem (7)`` () =
    "5fd318c3"
    ++ FMLA ** [ O.ScalarReg D3; O.ScalarReg D6
                 O.SIMDVecRegWithIdx (V19, VecD, 1uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.12 Advanced SIMD scalar x indexed elem (8)`` () =
    "5fb05822"
    ++ FMLS ** [ O.ScalarReg S2; O.ScalarReg S1
                 O.SIMDVecRegWithIdx (V16, VecS, 3uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.12 Advanced SIMD scalar x indexed elem (9)`` () =
    "5fd1987e"
    ++ FMUL ** [ O.ScalarReg D30; O.ScalarReg D3
                 O.SIMDVecRegWithIdx (V17, VecD, 1uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.12 Advanced SIMD scalar x indexed elem (10)`` () =
    "7fbe90d9"
    ++ FMULX ** [ O.ScalarReg S25; O.ScalarReg S6
                  O.SIMDVecRegWithIdx (V30, VecS, 1uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (1)`` () =
    "4f0d05c5"
    ++ SSHR ** [ O.SIMDVecReg (V5, SixteenB); O.SIMDVecReg (V14, SixteenB)
                 O.Imm 3L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (2)`` () =
    "4f1505c5"
    ++ SSHR ** [ O.SIMDVecReg (V5, EightH); O.SIMDVecReg (V14, EightH)
                 O.Imm 0xBL ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (3)`` () =
    "4f3505c5"
    ++ SSHR ** [ O.SIMDVecReg (V5, FourS); O.SIMDVecReg (V14, FourS)
                 O.Imm 0xBL ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (4)`` () =
    "4f5205c5"
    ++ SSHR ** [ O.SIMDVecReg (V5, TwoD); O.SIMDVecReg (V14, TwoD)
                 O.Imm 0x2EL ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (5)`` () =
    "4f0d15c5"
    ++ SSRA ** [ O.SIMDVecReg (V5, SixteenB); O.SIMDVecReg (V14, SixteenB)
                 O.Imm 3L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (6)`` () =
    "4f1525c5"
    ++ SRSHR ** [ O.SIMDVecReg (V5, EightH); O.SIMDVecReg (V14, EightH)
                  O.Imm 0xBL ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (7)`` () =
    "4f3535c5"
    ++ SRSRA ** [ O.SIMDVecReg (V5, FourS); O.SIMDVecReg (V14, FourS)
                  O.Imm 0xBL ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (8)`` () =
    "4f0d55c5"
    ++ SHL ** [ O.SIMDVecReg (V5, SixteenB); O.SIMDVecReg (V14, SixteenB)
                O.Imm 5L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (9)`` () =
    "4f0d75c5"
    ++ SQSHL ** [ O.SIMDVecReg (V5, SixteenB); O.SIMDVecReg (V14, SixteenB)
                  O.Imm 5L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (10)`` () =
    "4f2e85c5"
    ++ SHRN2 ** [ O.SIMDVecReg (V5, FourS); O.SIMDVecReg (V14, TwoD)
                  O.Imm 0x12L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (11)`` () =
    "4f0d8dc5"
    ++ RSHRN2 ** [ O.SIMDVecReg (V5, SixteenB); O.SIMDVecReg (V14, EightH)
                   O.Imm 3L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (12)`` () =
    "4f0d95c5"
    ++ SQSHRN2 ** [ O.SIMDVecReg (V5, SixteenB); O.SIMDVecReg (V14, EightH)
                    O.Imm 3L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (13)`` () =
    "4f0d9dc5"
    ++ SQRSHRN2 ** [ O.SIMDVecReg (V5, SixteenB); O.SIMDVecReg (V14, EightH)
                     O.Imm 3L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (14)`` () =
    "4f0da5c5"
    ++ SSHLL2 ** [ O.SIMDVecReg (V5, EightH); O.SIMDVecReg (V14, SixteenB)
                   O.Imm 5L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (15)`` () =
    "4f4fe54d"
    ++ SCVTF ** [ O.SIMDVecReg (V13, TwoD); O.SIMDVecReg (V10, TwoD)
                  OprFbits 0x31uy ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (16)`` () =
    "4f4ffd4d"
    ++ FCVTZS ** [ O.SIMDVecReg (V13, TwoD); O.SIMDVecReg (V10, TwoD)
                   OprFbits 0x31uy ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (17)`` () =
    "6f0d05c5"
    ++ USHR ** [ O.SIMDVecReg (V5, SixteenB); O.SIMDVecReg (V14, SixteenB)
                 O.Imm 3L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (18)`` () =
    "6f0d15c5"
    ++ USRA ** [ O.SIMDVecReg (V5, SixteenB); O.SIMDVecReg (V14, SixteenB)
                 O.Imm 3L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (19)`` () =
    "6f0d25c5"
    ++ URSHR ** [ O.SIMDVecReg (V5, SixteenB); O.SIMDVecReg (V14, SixteenB)
                  O.Imm 3L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (20)`` () =
    "6f0d35c5"
    ++ URSRA ** [ O.SIMDVecReg (V5, SixteenB); O.SIMDVecReg (V14, SixteenB)
                  O.Imm 3L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (21)`` () =
    "6f0d45c5"
    ++ SRI ** [ O.SIMDVecReg (V5, SixteenB); O.SIMDVecReg (V14, SixteenB)
                O.Imm 3L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (22)`` () =
    "6f0d55c5"
    ++ SLI ** [ O.SIMDVecReg (V5, SixteenB); O.SIMDVecReg (V14, SixteenB)
                O.Imm 5L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (23)`` () =
    "6f0d65c5"
    ++ SQSHLU ** [ O.SIMDVecReg (V5, SixteenB); O.SIMDVecReg (V14, SixteenB)
                   O.Imm 5L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (24)`` () =
    "6f0d75c5"
    ++ UQSHL ** [ O.SIMDVecReg (V5, SixteenB); O.SIMDVecReg (V14, SixteenB)
                  O.Imm 5L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (25)`` () =
    "6f2985c5"
    ++ SQSHRUN2 ** [ O.SIMDVecReg (V5, FourS); O.SIMDVecReg (V14, TwoD)
                     O.Imm 0x17L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (26)`` () =
    "6f1b8dc5"
    ++ SQRSHRUN2 ** [ O.SIMDVecReg (V5, EightH); O.SIMDVecReg (V14, FourS)
                      O.Imm 5L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (27)`` () =
    "6f2695c5"
    ++ UQSHRN2 ** [ O.SIMDVecReg (V5, FourS); O.SIMDVecReg (V14, TwoD)
                    O.Imm 0x1AL ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (28)`` () =
    "6f1f9dc5"
    ++ UQRSHRN2 ** [ O.SIMDVecReg (V5, EightH); O.SIMDVecReg (V14, FourS)
                     O.Imm 1L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (29)`` () =
    "2f2da4bb"
    ++ USHLL ** [ O.SIMDVecReg (V27, TwoD); O.SIMDVecReg (V5, TwoS)
                  O.Imm 0xDL ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (30)`` () =
    "6f39e5c5"
    ++ UCVTF ** [ O.SIMDVecReg (V5, FourS); O.SIMDVecReg (V14, FourS)
                  OprFbits 7uy ]
    ||> test

  [<TestMethod>]
  member __.``4.6.13 Advanced SIMD shift by immediate (31)`` () =
    "6f26fdc5"
    ++ FCVTZU ** [ O.SIMDVecReg (V5, FourS); O.SIMDVecReg (V14, FourS)
                   OprFbits 0x1Auy ]
    ||> test

  [<TestMethod>]
  member __.``4.6.14 Advanced SIMD table lookup (1)`` () =
    "4e0320c1"
    ++ TBL ** [ O.SIMDVecReg (V1, SixteenB); O.SIMDList ([ V6; V7 ], SixteenB)
                O.SIMDVecReg (V3, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.14 Advanced SIMD table lookup (2)`` () =
    "0e0342c9"
    ++ TBL ** [ O.SIMDVecReg (V9, EightB)
                O.SIMDList ([ V22; V23; V24 ], SixteenB)
                O.SIMDVecReg (V3, EightB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.14 Advanced SIMD table lookup (3)`` () =
    "4e0363e5"
    ++ TBL ** [ O.SIMDVecReg (V5, SixteenB)
                O.SIMDList ([ V31; V0; V1; V2 ], SixteenB)
                O.SIMDVecReg (V3, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.14 Advanced SIMD table lookup (4)`` () =
    "0e030371"
    ++ TBL ** [ O.SIMDVecReg (V17, EightB); O.SIMDList ([ V27 ], SixteenB)
                O.SIMDVecReg (V3, EightB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.14 Advanced SIMD table lookup (5)`` () =
    "0e1930fc"
    ++ TBX ** [ O.SIMDVecReg (V28, EightB); O.SIMDList ([ V7; V8 ], SixteenB)
                O.SIMDVecReg (V25, EightB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.14 Advanced SIMD table lookup (6)`` () =
    "4e1950fc"
    ++ TBX ** [ O.SIMDVecReg (V28, SixteenB)
                O.SIMDList ([ V7; V8; V9], SixteenB)
                O.SIMDVecReg (V25, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.14 Advanced SIMD table lookup (7)`` () =
    "0e1970fc"
    ++ TBX ** [ O.SIMDVecReg (V28, EightB)
                O.SIMDList ([ V7; V8; V9; V10], SixteenB)
                O.SIMDVecReg (V25, EightB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.14 Advanced SIMD table lookup (8)`` () =
    "4e1910fc"
    ++ TBX ** [ O.SIMDVecReg (V28, SixteenB); O.SIMDList ([ V7 ], SixteenB)
                O.SIMDVecReg (V25, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (1)`` () =
    "0e6b039a"
    ++ SADDL ** [ O.SIMDVecReg (V26, FourS); O.SIMDVecReg (V28, FourH)
                  O.SIMDVecReg (V11, FourH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (2)`` () =
    "4ea50325"
    ++ SADDL2 ** [ O.SIMDVecReg (V5, TwoD); O.SIMDVecReg (V25, FourS)
                   O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (3)`` () =
    "0e2712ba"
    ++ SADDW ** [ O.SIMDVecReg (V26, EightH); O.SIMDVecReg (V21, EightH)
                  O.SIMDVecReg (V7, EightB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (4)`` () =
    "4e631079"
    ++ SADDW2 ** [ O.SIMDVecReg (V25, FourS); O.SIMDVecReg (V3, FourS)
                   O.SIMDVecReg (V3, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (5)`` () =
    "4e632079"
    ++ SSUBL2 ** [ O.SIMDVecReg (V25, FourS); O.SIMDVecReg (V3, EightH)
                   O.SIMDVecReg (V3, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (6)`` () =
    "4e633079"
    ++ SSUBW2 ** [ O.SIMDVecReg (V25, FourS); O.SIMDVecReg (V3, FourS)
                   O.SIMDVecReg (V3, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (7)`` () =
    "4e634079"
    ++ ADDHN2 ** [ O.SIMDVecReg (V25, EightH); O.SIMDVecReg (V3, FourS)
                   O.SIMDVecReg (V3, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (8)`` () =
    "4e635079"
    ++ SABAL2 ** [ O.SIMDVecReg (V25, FourS); O.SIMDVecReg (V3, EightH)
                   O.SIMDVecReg (V3, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (9)`` () =
    "4e636079"
    ++ SUBHN2 ** [ O.SIMDVecReg (V25, EightH); O.SIMDVecReg (V3, FourS)
                   O.SIMDVecReg (V3, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (10)`` () =
    "4e637079"
    ++ SABDL2 ** [ O.SIMDVecReg (V25, FourS); O.SIMDVecReg (V3, EightH)
                   O.SIMDVecReg (V3, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (11)`` () =
    "0ea68258"
    ++ SMLAL ** [ O.SIMDVecReg (V24, TwoD); O.SIMDVecReg (V18, TwoS)
                  O.SIMDVecReg (V6, TwoS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (12)`` () =
    "4ea692fa"
    ++ SQDMLAL2 ** [ O.SIMDVecReg (V26, TwoD); O.SIMDVecReg (V23, FourS)
                     O.SIMDVecReg (V6, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (13)`` () =
    "4e66a22c"
    ++ SMLSL2 ** [ O.SIMDVecReg (V12, FourS); O.SIMDVecReg (V17, EightH)
                   O.SIMDVecReg (V6, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (14)`` () =
    "4ea5b2c3"
    ++ SQDMLSL2 ** [ O.SIMDVecReg (V3, TwoD); O.SIMDVecReg (V22, FourS)
                     O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (15)`` () =
    "0e65c17c"
    ++ SMULL ** [ O.SIMDVecReg (V28, FourS); O.SIMDVecReg (V11, FourH)
                  O.SIMDVecReg (V5, FourH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (16)`` () =
    "0ea8d079"
    ++ SQDMULL ** [ O.SIMDVecReg (V25, TwoD); O.SIMDVecReg (V3, TwoS)
                    O.SIMDVecReg (V8, TwoS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (17)`` () =
    "4ee3e245"
    ++ PMULL2 ** [ O.SIMDVecReg (V5, OneQ); O.SIMDVecReg (V18, TwoD)
                   O.SIMDVecReg (V3, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (18)`` () =
    "2e2e026b"
    ++ UADDL ** [ O.SIMDVecReg (V11, EightH); O.SIMDVecReg (V19, EightB)
                  O.SIMDVecReg (V14, EightB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (19)`` () =
    "6eae1252"
    ++ UADDW2 ** [ O.SIMDVecReg (V18, TwoD); O.SIMDVecReg (V18, TwoD)
                   O.SIMDVecReg (V14, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (20)`` () =
    "2ea122bd"
    ++ USUBL ** [ O.SIMDVecReg (V29, TwoD); O.SIMDVecReg (V21, TwoS)
                  O.SIMDVecReg (V1, TwoS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (21)`` () =
    "6e27339b"
    ++ USUBW2 ** [ O.SIMDVecReg (V27, EightH); O.SIMDVecReg (V28, EightH)
                   O.SIMDVecReg (V7, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (22)`` () =
    "6e27439b"
    ++ RADDHN2 ** [ O.SIMDVecReg (V27, SixteenB); O.SIMDVecReg (V28, EightH)
                    O.SIMDVecReg (V7, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (23)`` () =
    "6e27539b"
    ++ UABAL2 ** [ O.SIMDVecReg (V27, EightH); O.SIMDVecReg (V28, SixteenB)
                   O.SIMDVecReg (V7, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (24)`` () =
    "6e27639b"
    ++ RSUBHN2 ** [ O.SIMDVecReg (V27, SixteenB); O.SIMDVecReg (V28, EightH)
                    O.SIMDVecReg (V7, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (25)`` () =
    "6e27739b"
    ++ UABDL2 ** [ O.SIMDVecReg (V27, EightH); O.SIMDVecReg (V28, SixteenB)
                   O.SIMDVecReg (V7, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (26)`` () =
    "6e27839b"
    ++ UMLAL2 ** [ O.SIMDVecReg (V27, EightH); O.SIMDVecReg (V28, SixteenB)
                   O.SIMDVecReg (V7, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (27)`` () =
    "6e27a39b"
    ++ UMLSL2 ** [ O.SIMDVecReg (V27, EightH); O.SIMDVecReg (V28, SixteenB)
                   O.SIMDVecReg (V7, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.15 Advanced SIMD three different (28)`` () =
    "6e27c39b"
    ++ UMULL2 ** [ O.SIMDVecReg (V27, EightH); O.SIMDVecReg (V28, SixteenB)
                   O.SIMDVecReg (V7, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (1)`` () =
    "4e2504b5"
    ++ SHADD ** [ O.SIMDVecReg (V21, SixteenB); O.SIMDVecReg (V5, SixteenB)
                  O.SIMDVecReg (V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (2)`` () =
    "4e650cb5"
    ++ SQADD ** [ O.SIMDVecReg (V21, EightH); O.SIMDVecReg (V5, EightH)
                  O.SIMDVecReg (V5, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (3)`` () =
    "4ea514b5"
    ++ SRHADD ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V5, FourS)
                   O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (4)`` () =
    "4e2524b5"
    ++ SHSUB ** [ O.SIMDVecReg (V21, SixteenB); O.SIMDVecReg (V5, SixteenB)
                  O.SIMDVecReg (V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (5)`` () =
    "4e652cb5"
    ++ SQSUB ** [ O.SIMDVecReg (V21, EightH); O.SIMDVecReg (V5, EightH)
                  O.SIMDVecReg (V5, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (6)`` () =
    "4ea534b5"
    ++ CMGT ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V5, FourS)
                 O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (7)`` () =
    "4e253cb5"
    ++ CMGE ** [ O.SIMDVecReg (V21, SixteenB); O.SIMDVecReg (V5, SixteenB)
                 O.SIMDVecReg (V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (8)`` () =
    "4e6544b5"
    ++ SSHL ** [ O.SIMDVecReg (V21, EightH); O.SIMDVecReg (V5, EightH)
                 O.SIMDVecReg (V5, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (9)`` () =
    "4ea54cb5"
    ++ SQSHL ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V5, FourS)
                  O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (10)`` () =
    "4e2554b5"
    ++ SRSHL ** [ O.SIMDVecReg (V21, SixteenB); O.SIMDVecReg (V5, SixteenB)
                  O.SIMDVecReg (V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (11)`` () =
    "4e655cb5"
    ++ SQRSHL ** [ O.SIMDVecReg (V21, EightH); O.SIMDVecReg (V5, EightH)
                   O.SIMDVecReg (V5, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (12)`` () =
    "4ea564b5"
    ++ SMAX ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V5, FourS)
                 O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (13)`` () =
    "4e256cb5"
    ++ SMIN ** [ O.SIMDVecReg (V21, SixteenB); O.SIMDVecReg (V5, SixteenB)
                 O.SIMDVecReg (V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (14)`` () =
    "4e6574b5"
    ++ SABD ** [ O.SIMDVecReg (V21, EightH); O.SIMDVecReg (V5, EightH)
                 O.SIMDVecReg (V5, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (15)`` () =
    "4ea57cb5"
    ++ SABA ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V5, FourS)
                 O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (16)`` () =
    "4e2584b5"
    ++ ADD ** [ O.SIMDVecReg (V21, SixteenB); O.SIMDVecReg (V5, SixteenB)
                O.SIMDVecReg (V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (17)`` () =
    "4e658cb5"
    ++ CMTST ** [ O.SIMDVecReg (V21, EightH); O.SIMDVecReg (V5, EightH)
                  O.SIMDVecReg (V5, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (18)`` () =
    "4ea594b5"
    ++ MLA ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V5, FourS)
                O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (19)`` () =
    "4e259cb5"
    ++ MUL ** [ O.SIMDVecReg (V21, SixteenB); O.SIMDVecReg (V5, SixteenB)
                O.SIMDVecReg (V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (20)`` () =
    "4e65a4b5"
    ++ SMAXP ** [ O.SIMDVecReg (V21, EightH); O.SIMDVecReg (V5, EightH)
                  O.SIMDVecReg (V5, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (21)`` () =
    "4ea5acb5"
    ++ SMINP ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V5, FourS)
                  O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (22)`` () =
    "4ea5b4b5"
    ++ SQDMULH ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V5, FourS)
                    O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (23)`` () =
    "4e65bcb5"
    ++ ADDP ** [ O.SIMDVecReg (V21, EightH); O.SIMDVecReg (V5, EightH)
                 O.SIMDVecReg (V5, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (24)`` () =
    "4e25c6b5"
    ++ FMAXNM ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V21, FourS)
                   O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (25)`` () =
    "4e65cdb5"
    ++ FMLA ** [ O.SIMDVecReg (V21, TwoD); O.SIMDVecReg (V13, TwoD)
                 O.SIMDVecReg (V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (26)`` () =
    "4e25d4b5"
    ++ FADD ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V5, FourS)
                 O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (27)`` () =
    "4e65dcb1"
    ++ FMULX ** [ O.SIMDVecReg (V17, TwoD); O.SIMDVecReg (V5, TwoD)
                  O.SIMDVecReg (V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (28)`` () =
    "4e25e455"
    ++ FCMEQ ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V2, FourS)
                  O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (29)`` () =
    "4e65f5b5"
    ++ FMAX ** [ O.SIMDVecReg (V21, TwoD); O.SIMDVecReg (V13, TwoD)
                 O.SIMDVecReg (V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (30)`` () =
    "4e25fdb5"
    ++ FRECPS ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V13, FourS)
                   O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (31)`` () =
    "4e251cb1"
    ++ AND ** [ O.SIMDVecReg (V17, SixteenB); O.SIMDVecReg (V5, SixteenB)
                O.SIMDVecReg (V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (32)`` () =
    "4e651eb9"
    ++ BIC ** [ O.SIMDVecReg (V25, SixteenB); O.SIMDVecReg (V21, SixteenB)
                O.SIMDVecReg (V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (33)`` () =
    "4ea5c43d"
    ++ FMINNM ** [ O.SIMDVecReg (V29, FourS); O.SIMDVecReg (V1, FourS)
                   O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (34)`` () =
    "4ee5cfb4"
    ++ FMLS ** [ O.SIMDVecReg (V20, TwoD); O.SIMDVecReg (V29, TwoD)
                 O.SIMDVecReg (V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (35)`` () =
    "4ea5d4b5"
    ++ FSUB ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V5, FourS)
                 O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (36)`` () =
    "4ee5f425"
    ++ FMIN ** [ O.SIMDVecReg (V5, TwoD); O.SIMDVecReg (V1, TwoD)
                 O.SIMDVecReg (V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (37)`` () =
    "4ea5fcbd"
    ++ FRSQRTS ** [ O.SIMDVecReg (V29, FourS); O.SIMDVecReg (V5, FourS)
                    O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (38)`` () =
    "4ea51cb5"
    ++ MOV ** [ O.SIMDVecReg (V21, SixteenB); O.SIMDVecReg (V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (39)`` () =
    "4ee51da9"
    ++ ORN ** [ O.SIMDVecReg (V9, SixteenB); O.SIMDVecReg (V13, SixteenB)
                O.SIMDVecReg (V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (40)`` () =
    "6e2504b5"
    ++ UHADD ** [ O.SIMDVecReg (V21, SixteenB); O.SIMDVecReg (V5, SixteenB)
                  O.SIMDVecReg (V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (41)`` () =
    "6e650cb5"
    ++ UQADD ** [ O.SIMDVecReg (V21, EightH); O.SIMDVecReg (V5, EightH)
                  O.SIMDVecReg (V5, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (42)`` () =
    "6ea514b5"
    ++ URHADD ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V5, FourS)
                   O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (43)`` () =
    "6e2524b5"
    ++ UHSUB ** [ O.SIMDVecReg (V21, SixteenB); O.SIMDVecReg (V5, SixteenB)
                  O.SIMDVecReg (V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (44)`` () =
    "6e652cb5"
    ++ UQSUB ** [ O.SIMDVecReg (V21, EightH); O.SIMDVecReg (V5, EightH)
                  O.SIMDVecReg (V5, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (45)`` () =
    "6ea534b5"
    ++ CMHI ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V5, FourS)
                 O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (46)`` () =
    "6e253cb5"
    ++ CMHS ** [ O.SIMDVecReg (V21, SixteenB); O.SIMDVecReg (V5, SixteenB)
                 O.SIMDVecReg (V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (47)`` () =
    "6e6544b5"
    ++ USHL ** [ O.SIMDVecReg (V21, EightH); O.SIMDVecReg (V5, EightH)
                 O.SIMDVecReg (V5, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (48)`` () =
    "6ea54cb5"
    ++ UQSHL ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V5, FourS)
                  O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (49)`` () =
    "6e2554b5"
    ++ URSHL ** [ O.SIMDVecReg (V21, SixteenB); O.SIMDVecReg (V5, SixteenB)
                  O.SIMDVecReg (V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (50)`` () =
    "6e655cb5"
    ++ UQRSHL ** [ O.SIMDVecReg (V21, EightH); O.SIMDVecReg (V5, EightH)
                   O.SIMDVecReg (V5, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (51)`` () =
    "6ea564b5"
    ++ UMAX ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V5, FourS)
                 O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (52)`` () =
    "6e256cb5"
    ++ UMIN ** [ O.SIMDVecReg (V21, SixteenB); O.SIMDVecReg (V5, SixteenB)
                 O.SIMDVecReg (V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (53)`` () =
    "6e6574b5"
    ++ UABD ** [ O.SIMDVecReg (V21, EightH); O.SIMDVecReg (V5, EightH)
                 O.SIMDVecReg (V5, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (54)`` () =
    "6ea57cb5"
    ++ UABA ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V5, FourS)
                 O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (55)`` () =
    "6e2584b5"
    ++ SUB ** [ O.SIMDVecReg (V21, SixteenB); O.SIMDVecReg (V5, SixteenB)
                O.SIMDVecReg (V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (56)`` () =
    "6e658cb5"
    ++ CMEQ ** [ O.SIMDVecReg (V21, EightH); O.SIMDVecReg (V5, EightH)
                 O.SIMDVecReg (V5, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (57)`` () =
    "6ea594b5"
    ++ MLS ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V5, FourS)
                O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (58)`` () =
    "6e259cb5"
    ++ PMUL ** [ O.SIMDVecReg (V21, SixteenB); O.SIMDVecReg (V5, SixteenB)
                 O.SIMDVecReg (V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (59)`` () =
    "6e65a4b5"
    ++ UMAXP ** [ O.SIMDVecReg (V21, EightH); O.SIMDVecReg (V5, EightH)
                  O.SIMDVecReg (V5, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (60)`` () =
    "6ea5acb5"
    ++ UMINP ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V5, FourS)
                  O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (61)`` () =
    "6e65b4b5"
    ++ SQRDMULH ** [ O.SIMDVecReg (V21, EightH); O.SIMDVecReg (V5, EightH)
                     O.SIMDVecReg (V5, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (62)`` () =
    "6e25c4b5"
    ++ FMAXNMP ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V5, FourS)
                    O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (63)`` () =
    "6e65d4b5"
    ++ FADDP ** [ O.SIMDVecReg (V21, TwoD); O.SIMDVecReg (V5, TwoD)
                  O.SIMDVecReg (V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (64)`` () =
    "6e25dcb5"
    ++ FMUL ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V5, FourS)
                 O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (65)`` () =
    "6e65e4b5"
    ++ FCMGE ** [ O.SIMDVecReg (V21, TwoD); O.SIMDVecReg (V5, TwoD)
                  O.SIMDVecReg (V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (66)`` () =
    "6e25ecb5"
    ++ FACGE ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V5, FourS)
                  O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (67)`` () =
    "6e65f4b5"
    ++ FMAXP ** [ O.SIMDVecReg (V21, TwoD); O.SIMDVecReg (V5, TwoD)
                  O.SIMDVecReg (V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (68)`` () =
    "6e25fcb5"
    ++ FDIV ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V5, FourS)
                 O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (69)`` () =
    "6e251cb5"
    ++ EOR ** [ O.SIMDVecReg (V21, SixteenB); O.SIMDVecReg (V5, SixteenB)
                O.SIMDVecReg (V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (70)`` () =
    "6e651cb5"
    ++ BSL ** [ O.SIMDVecReg (V21, SixteenB); O.SIMDVecReg (V5, SixteenB)
                O.SIMDVecReg (V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (71)`` () =
    "6ea5c4b5"
    ++ FMINNMP ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V5, FourS)
                    O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (72)`` () =
    "6ee5d4b5"
    ++ FABD ** [ O.SIMDVecReg (V21, TwoD); O.SIMDVecReg (V5, TwoD)
                 O.SIMDVecReg (V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (73)`` () =
    "6ea5e4b5"
    ++ FCMGT ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V5, FourS)
                  O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (74)`` () =
    "6ee5ecb5"
    ++ FACGT ** [ O.SIMDVecReg (V21, TwoD); O.SIMDVecReg (V5, TwoD)
                  O.SIMDVecReg (V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (75)`` () =
    "6ea5f4b5"
    ++ FMINP ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V5, FourS)
                  O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (76)`` () =
    "6ea51cb5"
    ++ BIT ** [ O.SIMDVecReg (V21, SixteenB); O.SIMDVecReg (V5, SixteenB)
                O.SIMDVecReg (V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.16 Advanced SIMD three same (77)`` () =
    "6ee51cb5"
    ++ BIF ** [ O.SIMDVecReg (V21, SixteenB); O.SIMDVecReg (V5, SixteenB)
                O.SIMDVecReg (V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (1)`` () =
    "4e600983"
    ++ REV64 ** [ O.SIMDVecReg (V3, EightH); O.SIMDVecReg (V12, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (2)`` () =
    "4e2018b2"
    ++ REV16 ** [ O.SIMDVecReg (V18, SixteenB); O.SIMDVecReg (V5, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (3)`` () =
    "4e602983"
    ++ SADDLP ** [ O.SIMDVecReg (V3, FourS); O.SIMDVecReg (V12, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (4)`` () =
    "4e603a33"
    ++ SUQADD ** [ O.SIMDVecReg (V19, EightH); O.SIMDVecReg (V17, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (5)`` () =
    "4ea0487c"
    ++ CLS ** [ O.SIMDVecReg (V28, FourS); O.SIMDVecReg (V3, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (6)`` () =
    "0ea028cd"
    ++ SADDLP ** [ O.SIMDVecReg (V13, OneD); O.SIMDVecReg (V6, TwoS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (7)`` () =
    "4ee07a46"
    ++ SQABS ** [ O.SIMDVecReg (V6, TwoD); O.SIMDVecReg (V18, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (8)`` () =
    "4e208867"
    ++ CMGT ** [ O.SIMDVecReg (V7, SixteenB); O.SIMDVecReg (V3, SixteenB)
                 O.Imm 0L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (9)`` () =
    "0e609879"
    ++ CMEQ ** [ O.SIMDVecReg (V25, FourH); O.SIMDVecReg (V3, FourH)
                 O.Imm 0L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (10)`` () =
    "4ea0a841"
    ++ CMLT ** [ O.SIMDVecReg (V1, FourS); O.SIMDVecReg (V2, FourS)
                 O.Imm 0L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (11)`` () =
    "4e20bb7d"
    ++ ABS ** [ O.SIMDVecReg (V29, SixteenB); O.SIMDVecReg (V27, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (12)`` () =
    "0ea128b9"
    ++ XTN ** [ O.SIMDVecReg (V25, TwoS); O.SIMDVecReg (V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (13)`` () =
    "4ea128f8"
    ++ XTN2 ** [ O.SIMDVecReg (V24, FourS); O.SIMDVecReg (V7, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (14)`` () =
    "0e2148c3"
    ++ SQXTN ** [ O.SIMDVecReg (V3, EightB); O.SIMDVecReg (V6, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (15)`` () =
    "4e214945"
    ++ SQXTN2 ** [ O.SIMDVecReg (V5, SixteenB); O.SIMDVecReg (V10, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (16)`` () =
    "0e616885"
    ++ FCVTN ** [ O.SIMDVecReg (V5, TwoS); O.SIMDVecReg (V4, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (17)`` () =
    "4e2168f8"
    ++ FCVTN2 ** [ O.SIMDVecReg (V24, EightH); O.SIMDVecReg (V7, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (18)`` () =
    "0e217a7c"
    ++ FCVTL ** [ O.SIMDVecReg (V28, FourS); O.SIMDVecReg (V19, FourH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (19)`` () =
    "4e617b43"
    ++ FCVTL2 ** [ O.SIMDVecReg (V3, TwoD); O.SIMDVecReg (V26, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (20)`` () =
    "4e6188b8"
    ++ FRINTN ** [ O.SIMDVecReg (V24, TwoD); O.SIMDVecReg (V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (21)`` () =
    "0e219865"
    ++ FRINTM ** [ O.SIMDVecReg (V5, TwoS); O.SIMDVecReg (V3, TwoS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (22)`` () =
    "4e21a86d"
    ++ FCVTNS ** [ O.SIMDVecReg (V13, FourS); O.SIMDVecReg (V3, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (23)`` () =
    "0e21b87e"
    ++ FCVTMS ** [ O.SIMDVecReg (V30, TwoS); O.SIMDVecReg (V3, TwoS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (24)`` () =
    "4e61c876"
    ++ FCVTAS ** [ O.SIMDVecReg (V22, TwoD); O.SIMDVecReg (V3, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (25)`` () =
    "4e21d892"
    ++ SCVTF ** [ O.SIMDVecReg (V18, FourS); O.SIMDVecReg (V4, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (26)`` () =
    "4ea0c8bd"
    ++ FCMGT ** [ O.SIMDVecReg (V29, FourS); O.SIMDVecReg (V5, FourS)
                  OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (27)`` () =
    "0ea0d83e"
    ++ FCMEQ ** [ O.SIMDVecReg (V30, TwoS); O.SIMDVecReg (V1, TwoS)
                  OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (28)`` () =
    "4ee0e939"
    ++ FCMLT ** [ O.SIMDVecReg (V25, TwoD); O.SIMDVecReg (V9, TwoD)
                  OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (29)`` () =
    "4ea0f88e"
    ++ FABS ** [ O.SIMDVecReg (V14, FourS); O.SIMDVecReg (V4, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (30)`` () =
    "0ea18896"
    ++ FRINTP ** [ O.SIMDVecReg (V22, TwoS); O.SIMDVecReg (V4, TwoS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (31)`` () =
    "4ee19849"
    ++ FRINTZ ** [ O.SIMDVecReg (V9, TwoD); O.SIMDVecReg (V2, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (32)`` () =
    "4ea1aac3"
    ++ FCVTPS ** [ O.SIMDVecReg (V3, FourS); O.SIMDVecReg (V22, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (33)`` () =
    "0ea1ba7a"
    ++ FCVTZS ** [ O.SIMDVecReg (V26, TwoS); O.SIMDVecReg (V19, TwoS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (34)`` () =
    "0ea1c8c7"
    ++ URECPE ** [ O.SIMDVecReg (V7, TwoS); O.SIMDVecReg (V6, TwoS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (35)`` () =
    "4ee1d883"
    ++ FRECPE ** [ O.SIMDVecReg (V3, TwoD); O.SIMDVecReg (V4, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (36)`` () =
    "6e60083e"
    ++ REV32 ** [ O.SIMDVecReg (V30, EightH); O.SIMDVecReg (V1, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (37)`` () =
    "6ea028fc"
    ++ UADDLP ** [ O.SIMDVecReg (V28, TwoD); O.SIMDVecReg (V7, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (38)`` () =
    "6ee03883"
    ++ USQADD ** [ O.SIMDVecReg (V3, TwoD); O.SIMDVecReg (V4, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (39)`` () =
    "6ea048c9"
    ++ CLZ ** [ O.SIMDVecReg (V9, FourS); O.SIMDVecReg (V6, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (40)`` () =
    "6e60683e"
    ++ UADALP ** [ O.SIMDVecReg (V30, FourS); O.SIMDVecReg (V1, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (41)`` () =
    "2ea078ef"
    ++ SQNEG ** [ O.SIMDVecReg (V15, TwoS); O.SIMDVecReg (V7, TwoS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (42)`` () =
    "6e208874"
    ++ CMGE ** [ O.SIMDVecReg (V20, SixteenB); O.SIMDVecReg (V3, SixteenB)
                 O.Imm 0L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (43)`` () =
    "2e2098fd"
    ++ CMLE ** [ O.SIMDVecReg (V29, EightB); O.SIMDVecReg (V7, EightB)
                 O.Imm 0L ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (44)`` () =
    "6e60b8ca"
    ++ NEG ** [ O.SIMDVecReg (V10, EightH); O.SIMDVecReg (V6, EightH) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (45)`` () =
    "0ea14887"
    ++ SQXTN ** [ O.SIMDVecReg (V7, TwoS); O.SIMDVecReg (V4, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (46)`` () =
    "4e6148b4"
    ++ SQXTN2 ** [ O.SIMDVecReg (V20, EightH); O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (47)`` () =
    "2ea13a75"
    ++ SHLL ** [ O.SIMDVecReg (V21, TwoD); O.SIMDVecReg (V19, TwoS)
                 O.Shift (SRTypeLSL, 32L) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (48)`` () =
    "6e613a7d"
    ++ SHLL2 ** [ O.SIMDVecReg (V29, FourS); O.SIMDVecReg (V19, EightH)
                  O.Shift (SRTypeLSL, 16L) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (49)`` () =
    "2ea148e9"
    ++ UQXTN ** [ O.SIMDVecReg (V9, TwoS); O.SIMDVecReg (V7, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (50)`` () =
    "6e6148c2"
    ++ UQXTN2 ** [ O.SIMDVecReg (V2, EightH); O.SIMDVecReg (V6, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (51)`` () =
    "2e6168ca"
    ++ FCVTXN ** [ O.SIMDVecReg (V10, TwoS); O.SIMDVecReg (V6, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (52)`` () =
    "6e6169c5"
    ++ FCVTXN2 ** [ O.SIMDVecReg (V5, FourS); O.SIMDVecReg (V14, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (53)`` () =
    "6e2188ba"
    ++ FRINTA ** [ O.SIMDVecReg (V26, FourS); O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (54)`` () =
    "6e6198bc"
    ++ FRINTX ** [ O.SIMDVecReg (V28, TwoD); O.SIMDVecReg (V5, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (55)`` () =
    "2e21a8c5"
    ++ FCVTNU ** [ O.SIMDVecReg (V5, TwoS); O.SIMDVecReg (V6, TwoS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (56)`` () =
    "6e21bac6"
    ++ FCVTMU ** [ O.SIMDVecReg (V6, FourS); O.SIMDVecReg (V22, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (57)`` () =
    "2e21cb65"
    ++ FCVTAU ** [ O.SIMDVecReg (V5, TwoS); O.SIMDVecReg (V27, TwoS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (58)`` () =
    "6e21d896"
    ++ UCVTF ** [ O.SIMDVecReg (V22, FourS); O.SIMDVecReg (V4, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (59)`` () =
    "6e20593a"
    ++ MVN ** [ O.SIMDVecReg (V26, SixteenB); O.SIMDVecReg (V9, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (60)`` () =
    "2e6058f2"
    ++ RBIT ** [ O.SIMDVecReg (V18, EightB); O.SIMDVecReg (V7, EightB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (61)`` () =
    "6ea0cae5"
    ++ FCMGE ** [ O.SIMDVecReg (V5, FourS); O.SIMDVecReg (V23, FourS)
                  OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (62)`` () =
    "2ea0da4e"
    ++ FCMLE ** [ O.SIMDVecReg (V14, TwoS); O.SIMDVecReg (V18, TwoS)
                  OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (63)`` () =
    "6ee0fa75"
    ++ FNEG ** [ O.SIMDVecReg (V21, TwoD); O.SIMDVecReg (V19, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (64)`` () =
    "2ea19abe"
    ++ FRINTI ** [ O.SIMDVecReg (V30, TwoS); O.SIMDVecReg (V21, TwoS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (65)`` () =
    "6ee1a889"
    ++ FCVTPU ** [ O.SIMDVecReg (V9, TwoD); O.SIMDVecReg (V4, TwoD) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (66)`` () =
    "2ea1b9fe"
    ++ FCVTZU ** [ O.SIMDVecReg (V30, TwoS); O.SIMDVecReg (V15, TwoS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (67)`` () =
    "6ea1cba5"
    ++ URSQRTE ** [ O.SIMDVecReg (V5, FourS); O.SIMDVecReg (V29, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (68)`` () =
    "2ea1db32"
    ++ FRSQRTE ** [ O.SIMDVecReg (V18, TwoS); O.SIMDVecReg (V25, TwoS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.17 Advanced SIMD two-reg miscellaneous (69)`` () =
    "6ea1f8a6"
    ++ FSQRT ** [ O.SIMDVecReg (V6, FourS); O.SIMDVecReg (V5, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.18 Advanced SIMD vector x indexed elem (1)`` () =
    "4f6228da"
    ++ SMLAL2 ** [ O.SIMDVecReg (V26, FourS); O.SIMDVecReg (V6, EightH)
                   O.SIMDVecRegWithIdx (V2, VecH, 6uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.18 Advanced SIMD vector x indexed elem (2)`` () =
    "4fb13b42"
    ++ SQDMLAL2 ** [ O.SIMDVecReg (V2, TwoD); O.SIMDVecReg (V26, FourS)
                     O.SIMDVecRegWithIdx (V17, VecS, 3uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.18 Advanced SIMD vector x indexed elem (3)`` () =
    "4f7961ca"
    ++ SMLSL2 ** [ O.SIMDVecReg (V10, FourS); O.SIMDVecReg (V14, EightH)
                   O.SIMDVecRegWithIdx (V9, VecH, 3uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.18 Advanced SIMD vector x indexed elem (4)`` () =
    "0f92702f"
    ++ SQDMLSL ** [ O.SIMDVecReg (V15, TwoD); O.SIMDVecReg (V1, TwoS)
                    O.SIMDVecRegWithIdx (V18, VecS, 0uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.18 Advanced SIMD vector x indexed elem (5)`` () =
    "0f738342"
    ++ MUL ** [ O.SIMDVecReg (V2, FourH); O.SIMDVecReg (V26, FourH)
                O.SIMDVecRegWithIdx (V3, VecH, 3uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.18 Advanced SIMD vector x indexed elem (6)`` () =
    "0f6ca8c5"
    ++ SMULL ** [ O.SIMDVecReg (V5, FourS); O.SIMDVecReg (V6, FourH)
                  O.SIMDVecRegWithIdx (V12, VecH, 6uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.18 Advanced SIMD vector x indexed elem (7)`` () =
    "4fbdbb42"
    ++ SQDMULL2 ** [ O.SIMDVecReg (V2, TwoD); O.SIMDVecReg (V26, FourS)
                     O.SIMDVecRegWithIdx (V29, VecS, 3uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.18 Advanced SIMD vector x indexed elem (8)`` () =
    "4f9dcb5d"
    ++ SQDMULH ** [ O.SIMDVecReg (V29, FourS); O.SIMDVecReg (V26, FourS)
                    O.SIMDVecRegWithIdx (V29, VecS, 2uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.18 Advanced SIMD vector x indexed elem (9)`` () =
    "0f5dd3da"
    ++ SQRDMULH ** [ O.SIMDVecReg (V26, FourH); O.SIMDVecReg (V30, FourH)
                     O.SIMDVecRegWithIdx (V13, VecH, 1uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.18 Advanced SIMD vector x indexed elem (10)`` () =
    "4fa31b5b"
    ++ FMLA ** [ O.SIMDVecReg (V27, FourS); O.SIMDVecReg (V26, FourS)
                 O.SIMDVecRegWithIdx (V3, VecS, 3uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.18 Advanced SIMD vector x indexed elem (11)`` () =
    "4fd3535b"
    ++ FMLS ** [ O.SIMDVecReg (V27, TwoD); O.SIMDVecReg (V26, TwoD)
                 O.SIMDVecRegWithIdx (V19, VecD, 0uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.18 Advanced SIMD vector x indexed elem (12)`` () =
    "4f839b5b"
    ++ FMUL ** [ O.SIMDVecReg (V27, FourS); O.SIMDVecReg (V26, FourS)
                 O.SIMDVecRegWithIdx (V3, VecS, 2uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.18 Advanced SIMD vector x indexed elem (13)`` () =
    "6fad08be"
    ++ MLA ** [ O.SIMDVecReg (V30, FourS); O.SIMDVecReg (V5, FourS)
                O.SIMDVecRegWithIdx (V13, VecS, 3uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.18 Advanced SIMD vector x indexed elem (14)`` () =
    "6f7f2b56"
    ++ UMLAL2 ** [ O.SIMDVecReg (V22, FourS); O.SIMDVecReg (V26, EightH)
                   O.SIMDVecRegWithIdx (V15, VecH, 7uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.18 Advanced SIMD vector x indexed elem (15)`` () =
    "6f97488a"
    ++ MLS ** [ O.SIMDVecReg (V10, FourS); O.SIMDVecReg (V4, FourS)
                O.SIMDVecRegWithIdx (V23, VecS, 2uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.18 Advanced SIMD vector x indexed elem (16)`` () =
    "2f6e60de"
    ++ UMLSL ** [ O.SIMDVecReg (V30, FourS); O.SIMDVecReg (V6, FourH)
                  O.SIMDVecRegWithIdx (V14, VecH, 2uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.18 Advanced SIMD vector x indexed elem (17)`` () =
    "6fbfa8ea"
    ++ UMULL2 ** [ O.SIMDVecReg (V10, TwoD); O.SIMDVecReg (V7, FourS)
                   O.SIMDVecRegWithIdx (V31, VecS, 3uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.18 Advanced SIMD vector x indexed elem (18)`` () =
    "6fad92c5"
    ++ FMULX ** [ O.SIMDVecReg (V5, FourS); O.SIMDVecReg (V22, FourS)
                  O.SIMDVecRegWithIdx (V13, VecS, 1uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.19 Cryptographic AES (1)`` () =
    "4e284ab5"
    ++ AESE ** [ O.SIMDVecReg (V21, SixteenB); O.SIMDVecReg (V21, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.19 Cryptographic AES (2)`` () =
    "4e285ab5"
    ++ AESD ** [ O.SIMDVecReg (V21, SixteenB); O.SIMDVecReg (V21, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.19 Cryptographic AES (3)`` () =
    "4e286ab5"
    ++ AESMC ** [ O.SIMDVecReg (V21, SixteenB); O.SIMDVecReg (V21, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.19 Cryptographic AES (4)`` () =
    "4e287ab5"
    ++ AESIMC ** [ O.SIMDVecReg (V21, SixteenB); O.SIMDVecReg (V21, SixteenB) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.20 Cryptographic three-register SHA (1)`` () =
    "5e190378"
    ++ SHA1C ** [ O.ScalarReg Q24; O.ScalarReg S27; O.SIMDVecReg (V25, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.20 Cryptographic three-register SHA (2)`` () =
    "5e1313ff"
    ++ SHA1P ** [ O.ScalarReg Q31; O.ScalarReg S31; O.SIMDVecReg (V19, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.20 Cryptographic three-register SHA (3)`` () =
    "5e0e22bc"
    ++ SHA1M ** [ O.ScalarReg Q28; O.ScalarReg S21; O.SIMDVecReg (V14, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.20 Cryptographic three-register SHA (4)`` () =
    "5e173207"
    ++ SHA1SU0 ** [ O.SIMDVecReg (V7, FourS); O.SIMDVecReg (V16, FourS)
                    O.SIMDVecReg (V23, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.20 Cryptographic three-register SHA (5)`` () =
    "5e1143de"
    ++ SHA256H ** [ O.ScalarReg Q30; O.ScalarReg Q30
                    O.SIMDVecReg (V17, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.20 Cryptographic three-register SHA (6)`` () =
    "5e19531e"
    ++ SHA256H2 ** [ O.ScalarReg Q30; O.ScalarReg Q24
                     O.SIMDVecReg (V25, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.20 Cryptographic three-register SHA (7)`` () =
    "5e1732bf"
    ++ SHA1SU0 ** [ O.SIMDVecReg (V31, FourS); O.SIMDVecReg (V21, FourS)
                    O.SIMDVecReg (V23, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.21 Cryptographic two-register SHA (1)`` () =
    "5e28095f"
    ++ SHA1H ** [ O.ScalarReg S31; O.ScalarReg S10 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.21 Cryptographic two-register SHA (2)`` () =
    "5e281bd7"
    ++ SHA1SU1 ** [ O.SIMDVecReg (V23, FourS); O.SIMDVecReg (V30, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.21 Cryptographic two-register SHA (3)`` () =
    "5e282955"
    ++ SHA256SU0 ** [ O.SIMDVecReg (V21, FourS); O.SIMDVecReg (V10, FourS) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.22 Floating-point compare (1)`` () =
    "1e3520e0"
    ++ FCMP ** [ O.ScalarReg S7; O.ScalarReg S21 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.22 Floating-point compare (2)`` () =
    "1e312388"
    ++ FCMP ** [ O.ScalarReg S28; OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.22 Floating-point compare (3)`` () =
    "1e2b22d0"
    ++ FCMPE ** [ O.ScalarReg S22; O.ScalarReg S11 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.22 Floating-point compare (4)`` () =
    "1e392238"
    ++ FCMPE ** [ O.ScalarReg S17; OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.22 Floating-point compare (5)`` () =
    "1e6220c0"
    ++ FCMP ** [ O.ScalarReg D6; O.ScalarReg D2 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.22 Floating-point compare (6)`` () =
    "1e7921c8"
    ++ FCMP ** [ O.ScalarReg D14; OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.22 Floating-point compare (7)`` () =
    "1e742170"
    ++ FCMPE ** [ O.ScalarReg D11; O.ScalarReg D20 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.22 Floating-point compare (8)`` () =
    "1e6323b8"
    ++ FCMPE ** [ O.ScalarReg D29; OprFPImm 0.0 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.23 Floating-point conditional compare (1)`` () =
    "1e2d274d"
    ++ FCCMP ** [ O.ScalarReg S26; O.ScalarReg S13; OprNZCV 0xDuy; OprCond CS ]
    ||> test

  [<TestMethod>]
  member __.``4.6.23 Floating-point conditional compare (2)`` () =
    "1e2ae756"
    ++ FCCMPE ** [ O.ScalarReg S26; O.ScalarReg S10; OprNZCV 6uy; OprCond AL ]
    ||> test

  [<TestMethod>]
  member __.``4.6.23 Floating-point conditional compare (3)`` () =
    "1e693649"
    ++ FCCMP ** [ O.ScalarReg D18; O.ScalarReg D9; OprNZCV 9uy; OprCond CC ]
    ||> test

  [<TestMethod>]
  member __.``4.6.23 Floating-point conditional compare (4)`` () =
    "1e6ee752"
    ++ FCCMPE ** [ O.ScalarReg D26; O.ScalarReg D14; OprNZCV 2uy; OprCond AL ]
    ||> test

  [<TestMethod>]
  member __.``4.6.24 Floating-point conditional select (1)`` () =
    "1e292c5b"
    ++ FCSEL ** [ O.ScalarReg S27; O.ScalarReg S2; O.ScalarReg S9; OprCond CS ]
    ||> test

  [<TestMethod>]
  member __.``4.6.24 Floating-point conditional select (2)`` () =
    "1e7ced53"
    ++ FCSEL ** [ O.ScalarReg D19; O.ScalarReg D10; O.ScalarReg D28
                  OprCond AL ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (1)`` () =
    "1e20423a"
    ++ FMOV ** [ O.ScalarReg S26; O.ScalarReg S17 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (2)`` () =
    "1e20c0ea"
    ++ FABS ** [ O.ScalarReg S10; O.ScalarReg S7 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (3)`` () =
    "1e21410e"
    ++ FNEG ** [ O.ScalarReg S14; O.ScalarReg S8 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (4)`` () =
    "1e21c178"
    ++ FSQRT ** [ O.ScalarReg S24; O.ScalarReg S11 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (5)`` () =
    "1e22c2ca"
    ++ FCVT ** [ O.ScalarReg D10; O.ScalarReg S22 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (6)`` () =
    "1e23c1f0"
    ++ FCVT ** [ O.ScalarReg H16; O.ScalarReg S15 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (7)`` () =
    "1e244261"
    ++ FRINTN ** [ O.ScalarReg S1; O.ScalarReg S19 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (8)`` () =
    "1e24c15c"
    ++ FRINTP ** [ O.ScalarReg S28; O.ScalarReg S10 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (9)`` () =
    "1e2541d8"
    ++ FRINTM ** [ O.ScalarReg S24; O.ScalarReg S14 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (10)`` () =
    "1e25c0ce"
    ++ FRINTZ ** [ O.ScalarReg S14; O.ScalarReg S6 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (11)`` () =
    "1e26414c"
    ++ FRINTA ** [ O.ScalarReg S12; O.ScalarReg S10 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (12)`` () =
    "1e274178"
    ++ FRINTX ** [ O.ScalarReg S24; O.ScalarReg S11 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (13)`` () =
    "1e27c1e2"
    ++ FRINTI ** [ O.ScalarReg S2; O.ScalarReg S15 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (14)`` () =
    "1e604234"
    ++ FMOV ** [ O.ScalarReg D20; O.ScalarReg D17 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (15)`` () =
    "1e60c222"
    ++ FABS ** [ O.ScalarReg D2; O.ScalarReg D17 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (16)`` () =
    "1e6142a2"
    ++ FNEG ** [ O.ScalarReg D2; O.ScalarReg D21 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (17)`` () =
    "1e61c1a6"
    ++ FSQRT ** [ O.ScalarReg D6; O.ScalarReg D13 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (18)`` () =
    "1e6241cd"
    ++ FCVT ** [ O.ScalarReg S13; O.ScalarReg D14 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (19)`` () =
    "1e63c2aa"
    ++ FCVT ** [ O.ScalarReg H10; O.ScalarReg D21 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (20)`` () =
    "1e6441e3"
    ++ FRINTN ** [ O.ScalarReg D3; O.ScalarReg D15 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (21)`` () =
    "1e64c2b2"
    ++ FRINTP ** [ O.ScalarReg D18; O.ScalarReg D21 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (22)`` () =
    "1e654374"
    ++ FRINTM ** [ O.ScalarReg D20; O.ScalarReg D27 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (23)`` () =
    "1e65c2e2"
    ++ FRINTZ ** [ O.ScalarReg D2; O.ScalarReg D23 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (24)`` () =
    "1e664351"
    ++ FRINTA ** [ O.ScalarReg D17; O.ScalarReg D26 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (25)`` () =
    "1e6742b8"
    ++ FRINTX ** [ O.ScalarReg D24; O.ScalarReg D21 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (26)`` () =
    "1e67c375"
    ++ FRINTI ** [ O.ScalarReg D21; O.ScalarReg D27 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (27)`` () =
    "1ee241d4"
    ++ FCVT ** [ O.ScalarReg S20; O.ScalarReg H14 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.25 FP data-processing (1 source) (28)`` () =
    "1ee2c388"
    ++ FCVT ** [ O.ScalarReg D8; O.ScalarReg H28 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.26 FP data-processing (2 source) (1)`` () =
    "1e210822"
    ++ FMUL ** [ O.ScalarReg S2; O.ScalarReg S1; O.ScalarReg S1 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.26 FP data-processing (2 source) (2)`` () =
    "1e221a88"
    ++ FDIV ** [ O.ScalarReg S8; O.ScalarReg S20; O.ScalarReg S2 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.26 FP data-processing (2 source) (3)`` () =
    "1e2228ae"
    ++ FADD ** [ O.ScalarReg S14; O.ScalarReg S5; O.ScalarReg S2 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.26 FP data-processing (2 source) (4)`` () =
    "1e233956"
    ++ FSUB ** [ O.ScalarReg S22; O.ScalarReg S10; O.ScalarReg S3 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.26 FP data-processing (2 source) (5)`` () =
    "1e244af4"
    ++ FMAX ** [ O.ScalarReg S20; O.ScalarReg S23; O.ScalarReg S4 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.26 FP data-processing (2 source) (6)`` () =
    "1e255915"
    ++ FMIN ** [ O.ScalarReg S21; O.ScalarReg S8; O.ScalarReg S5 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.26 FP data-processing (2 source) (7)`` () =
    "1e266932"
    ++ FMAXNM ** [ O.ScalarReg S18; O.ScalarReg S9; O.ScalarReg S6 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.26 FP data-processing (2 source) (8)`` () =
    "1e2778ba"
    ++ FMINNM ** [ O.ScalarReg S26; O.ScalarReg S5; O.ScalarReg S7 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.26 FP data-processing (2 source) (9)`` () =
    "1e288aba"
    ++ FNMUL ** [ O.ScalarReg S26; O.ScalarReg S21; O.ScalarReg S8 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.26 FP data-processing (2 source) (10)`` () =
    "1e690abb"
    ++ FMUL ** [ O.ScalarReg D27; O.ScalarReg D21; O.ScalarReg D9 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.26 FP data-processing (2 source) (11)`` () =
    "1e6a18a2"
    ++ FDIV ** [ O.ScalarReg D2; O.ScalarReg D5; O.ScalarReg D10 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.26 FP data-processing (2 source) (12)`` () =
    "1e6b2aba"
    ++ FADD ** [ O.ScalarReg D26; O.ScalarReg D21; O.ScalarReg D11 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.26 FP data-processing (2 source) (13)`` () =
    "1e6c39be"
    ++ FSUB ** [ O.ScalarReg D30; O.ScalarReg D13; O.ScalarReg D12 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.26 FP data-processing (2 source) (14)`` () =
    "1e6d48ba"
    ++ FMAX ** [ O.ScalarReg D26; O.ScalarReg D5; O.ScalarReg D13 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.26 FP data-processing (2 source) (15)`` () =
    "1e6e5abb"
    ++ FMIN ** [ O.ScalarReg D27; O.ScalarReg D21; O.ScalarReg D14 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.26 FP data-processing (2 source) (16)`` () =
    "1e726ae2"
    ++ FMAXNM ** [ O.ScalarReg D2; O.ScalarReg D23; O.ScalarReg D18 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.26 FP data-processing (2 source) (17)`` () =
    "1e7f7882"
    ++ FMINNM ** [ O.ScalarReg D2; O.ScalarReg D4; O.ScalarReg D31 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.26 FP data-processing (2 source) (18)`` () =
    "1e608bd4"
    ++ FNMUL ** [ O.ScalarReg D20; O.ScalarReg D30; O.ScalarReg D0 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.27 FP data-processing (3 source) (1)`` () =
    "1f1f0759"
    ++ FMADD ** [ O.ScalarReg S25; O.ScalarReg S26; O.ScalarReg S31
                  O.ScalarReg S1 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.27 FP data-processing (3 source) (2)`` () =
    "1f1e8b44"
    ++ FMSUB ** [ O.ScalarReg S4; O.ScalarReg S26; O.ScalarReg S30
                  O.ScalarReg S2 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.27 FP data-processing (3 source) (3)`` () =
    "1f3c1116"
    ++ FNMADD ** [ O.ScalarReg S22; O.ScalarReg S8; O.ScalarReg S28
                   O.ScalarReg S4 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.27 FP data-processing (3 source) (4)`` () =
    "1f38a1d5"
    ++ FNMSUB ** [ O.ScalarReg S21; O.ScalarReg S14; O.ScalarReg S24
                   O.ScalarReg S8 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.27 FP data-processing (3 source) (5)`` () =
    "1f504159"
    ++ FMADD ** [ O.ScalarReg D25; O.ScalarReg D10; O.ScalarReg D16
                  O.ScalarReg D16 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.27 FP data-processing (3 source) (6)`` () =
    "1f48e1dd"
    ++ FMSUB ** [ O.ScalarReg D29; O.ScalarReg D14; O.ScalarReg D8
                  O.ScalarReg D24 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.27 FP data-processing (3 source) (7)`` () =
    "1f647171"
    ++ FNMADD ** [ O.ScalarReg D17; O.ScalarReg D11; O.ScalarReg D4
                   O.ScalarReg D28 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.27 FP data-processing (3 source) (8)`` () =
    "1f62f871"
    ++ FNMSUB ** [ O.ScalarReg D17; O.ScalarReg D3; O.ScalarReg D2
                   O.ScalarReg D30 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.28 Floating-point immediate (1)`` () =
    "1e201015"
    ++ FMOV ** [ O.ScalarReg S21; OprFPImm 2.0 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.28 Floating-point immediate (2)`` () =
    "1e64b019"
    ++ FMOV ** [ O.ScalarReg D25; OprFPImm 10.5 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.29 Conversion between FP and fixed-pt (1)`` () =
    "1e02a8bc"
    ++ SCVTF ** [ O.ScalarReg S28; O.Reg W5; OprFbits 0x16uy ]
    ||> test

  [<TestMethod>]
  member __.``4.6.29 Conversion between FP and fixed-pt (2)`` () =
    "1e03f8a5"
    ++ UCVTF ** [ O.ScalarReg S5; O.Reg W5; OprFbits 2uy ]
    ||> test

  [<TestMethod>]
  member __.``4.6.29 Conversion between FP and fixed-pt (3)`` () =
    "1e18fc91"
    ++ FCVTZS ** [ O.Reg W17; O.ScalarReg S4; OprFbits 1uy ]
    ||> test

  [<TestMethod>]
  member __.``4.6.29 Conversion between FP and fixed-pt (4)`` () =
    "1e1985c5"
    ++ FCVTZU ** [ O.Reg W5; O.ScalarReg S14; OprFbits 0x1Fuy ]
    ||> test

  [<TestMethod>]
  member __.``4.6.29 Conversion between FP and fixed-pt (5)`` () =
    "1e42c5c5"
    ++ SCVTF ** [ O.ScalarReg D5; O.Reg W14; OprFbits 0xFuy ]
    ||> test

  [<TestMethod>]
  member __.``4.6.29 Conversion between FP and fixed-pt (6)`` () =
    "1e43a5c5"
    ++ UCVTF ** [ O.ScalarReg D5; O.Reg W14; OprFbits 0x17uy ]
    ||> test

  [<TestMethod>]
  member __.``4.6.29 Conversion between FP and fixed-pt (7)`` () =
    "1e5895c5"
    ++ FCVTZS ** [ O.Reg W5; O.ScalarReg D14; OprFbits 0x1Buy ]
    ||> test

  [<TestMethod>]
  member __.``4.6.29 Conversion between FP and fixed-pt (8)`` () =
    "1e59ab45"
    ++ FCVTZU ** [ O.Reg W5; O.ScalarReg D26; OprFbits 0x16uy ]
    ||> test

  [<TestMethod>]
  member __.``4.6.29 Conversion between FP and fixed-pt (9)`` () =
    "9e02c4d1"
    ++ SCVTF ** [ O.ScalarReg S17; O.Reg X6; OprFbits 0xFuy ]
    ||> test

  [<TestMethod>]
  member __.``4.6.29 Conversion between FP and fixed-pt (10)`` () =
    "9e03b5a5"
    ++ UCVTF ** [ O.ScalarReg S5; O.Reg X13; OprFbits 0x13uy ]
    ||> test

  [<TestMethod>]
  member __.``4.6.29 Conversion between FP and fixed-pt (11)`` () =
    "9e18f0cd"
    ++ FCVTZS ** [ O.Reg X13; O.ScalarReg S6; OprFbits 4uy ]
    ||> test

  [<TestMethod>]
  member __.``4.6.29 Conversion between FP and fixed-pt (12)`` () =
    "9e1995cd"
    ++ FCVTZU ** [ O.Reg X13; O.ScalarReg S14; OprFbits 0x1Buy ]
    ||> test

  [<TestMethod>]
  member __.``4.6.29 Conversion between FP and fixed-pt (13)`` () =
    "9e428b85"
    ++ SCVTF ** [ O.ScalarReg D5; O.Reg X28; OprFbits 0x1Euy ]
    ||> test

  [<TestMethod>]
  member __.``4.6.29 Conversion between FP and fixed-pt (14)`` () =
    "9e43c5c5"
    ++ UCVTF ** [ O.ScalarReg D5; O.Reg X14; OprFbits 0xFuy ]
    ||> test

  [<TestMethod>]
  member __.``4.6.29 Conversion between FP and fixed-pt (15)`` () =
    "9e58e6d1"
    ++ FCVTZS ** [ O.Reg X17; O.ScalarReg D22; OprFbits 7uy ]
    ||> test

  [<TestMethod>]
  member __.``4.6.29 Conversion between FP and fixed-pt (16)`` () =
    "9e59d1d2"
    ++ FCVTZU ** [ O.Reg X18; O.ScalarReg D14; OprFbits 0xCuy ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (1)`` () =
    "1e200154"
    ++ FCVTNS ** [ O.Reg W20; O.ScalarReg S10 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (2)`` () =
    "1e60034a"
    ++ FCVTNS ** [ O.Reg W10; O.ScalarReg D26 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (3)`` () =
    "9e200162"
    ++ FCVTNS ** [ O.Reg X2; O.ScalarReg S11 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (4)`` () =
    "9e600257"
    ++ FCVTNS ** [ O.Reg X23; O.ScalarReg D18 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (5)`` () =
    "1e2100b8"
    ++ FCVTNU ** [ O.Reg W24; O.ScalarReg S5 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (6)`` () =
    "1e6102b2"
    ++ FCVTNU ** [ O.Reg W18; O.ScalarReg D21 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (7)`` () =
    "9e2100bb"
    ++ FCVTNU ** [ O.Reg X27; O.ScalarReg S5 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (8)`` () =
    "9e6101bc"
    ++ FCVTNU ** [ O.Reg X28; O.ScalarReg D13 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (9)`` () =
    "1e2200ba"
    ++ SCVTF ** [ O.ScalarReg S26; O.Reg W5 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (10)`` () =
    "1e6201e8"
    ++ SCVTF ** [ O.ScalarReg D8; O.Reg W15 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (11)`` () =
    "9e2201c2"
    ++ SCVTF ** [ O.ScalarReg S2; O.Reg X14 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (12)`` () =
    "9e6201dd"
    ++ SCVTF ** [ O.ScalarReg D29; O.Reg X14 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (13)`` () =
    "1e2302bd"
    ++ UCVTF ** [ O.ScalarReg S29; O.Reg W21 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (14)`` () =
    "1e6301c7"
    ++ UCVTF ** [ O.ScalarReg D7; O.Reg W14 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (15)`` () =
    "9e2301de"
    ++ UCVTF ** [ O.ScalarReg S30; O.Reg X14 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (16)`` () =
    "9e6302b9"
    ++ UCVTF ** [ O.ScalarReg D25; O.Reg X21 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (17)`` () =
    "1e24018a"
    ++ FCVTAS ** [ O.Reg W10; O.ScalarReg S12 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (18)`` () =
    "1e640299"
    ++ FCVTAS ** [ O.Reg W25; O.ScalarReg D20 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (19)`` () =
    "9e240255"
    ++ FCVTAS ** [ O.Reg X21; O.ScalarReg S18 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (20)`` () =
    "9e640338"
    ++ FCVTAS ** [ O.Reg X24; O.ScalarReg D25 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (21)`` () =
    "1e25035d"
    ++ FCVTAU ** [ O.Reg W29; O.ScalarReg S26 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (22)`` () =
    "1e650345"
    ++ FCVTAU ** [ O.Reg W5; O.ScalarReg D26 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (23)`` () =
    "9e250311"
    ++ FCVTAU ** [ O.Reg X17; O.ScalarReg S24 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (24)`` () =
    "9e650374"
    ++ FCVTAU ** [ O.Reg X20; O.ScalarReg D27 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (25)`` () =
    "1e26032e"
    ++ FMOV ** [ O.Reg W14; O.ScalarReg S25 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (26)`` () =
    "1e2701c3"
    ++ FMOV ** [ O.ScalarReg S3; O.Reg W14 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (27)`` () =
    "9e6602ab"
    ++ FMOV ** [ O.Reg X11; O.ScalarReg D21 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (28)`` () =
    "9e6701e3"
    ++ FMOV ** [ O.ScalarReg D3; O.Reg X15 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (29)`` () =
    "9eae021d"
    ++ FMOV ** [ O.Reg X29; O.SIMDVecRegWithIdx (V16, VecD, 1uy) ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (30)`` () =
    "9eaf02f8"
    ++ FMOV ** [ O.SIMDVecRegWithIdx (V24, VecD, 1uy); O.Reg X23 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (31)`` () =
    "1e2800ce"
    ++ FCVTPS ** [ O.Reg W14; O.ScalarReg S6 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (32)`` () =
    "1e680066"
    ++ FCVTPS ** [ O.Reg W6; O.ScalarReg D3 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (33)`` () =
    "9e280223"
    ++ FCVTPS ** [ O.Reg X3; O.ScalarReg S17 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (34)`` () =
    "9e68037a"
    ++ FCVTPS ** [ O.Reg X26; O.ScalarReg D27 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (35)`` () =
    "1e29021c"
    ++ FCVTPU ** [ O.Reg W28; O.ScalarReg S16 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (36)`` () =
    "1e690133"
    ++ FCVTPU ** [ O.Reg W19; O.ScalarReg D9 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (37)`` () =
    "9e290069"
    ++ FCVTPU ** [ O.Reg X9; O.ScalarReg S3 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (38)`` () =
    "9e690275"
    ++ FCVTPU ** [ O.Reg X21; O.ScalarReg D19 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (39)`` () =
    "1e3001dd"
    ++ FCVTMS ** [ O.Reg W29; O.ScalarReg S14 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (40)`` () =
    "1e700362"
    ++ FCVTMS ** [ O.Reg W2; O.ScalarReg D27 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (41)`` () =
    "9e300079"
    ++ FCVTMS ** [ O.Reg X25; O.ScalarReg S3 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (42)`` () =
    "9e700086"
    ++ FCVTMS ** [ O.Reg X6; O.ScalarReg D4 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (43)`` () =
    "1e310185"
    ++ FCVTMU ** [ O.Reg W5; O.ScalarReg S12 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (44)`` () =
    "1e71027d"
    ++ FCVTMU ** [ O.Reg W29; O.ScalarReg D19 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (45)`` () =
    "9e3103ff"
    ++ FCVTMU ** [ O.Reg XZR; O.ScalarReg S31 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (46)`` () =
    "9e710000"
    ++ FCVTMU ** [ O.Reg X0; O.ScalarReg D0 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (47)`` () =
    "1e380343"
    ++ FCVTZS ** [ O.Reg W3; O.ScalarReg S26 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (48)`` () =
    "1e7800cd"
    ++ FCVTZS ** [ O.Reg W13; O.ScalarReg D6 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (49)`` () =
    "9e380279"
    ++ FCVTZS ** [ O.Reg X25; O.ScalarReg S19 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (50)`` () =
    "9e780146"
    ++ FCVTZS ** [ O.Reg X6; O.ScalarReg D10 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (51)`` () =
    "1e390261"
    ++ FCVTZU ** [ O.Reg W1; O.ScalarReg S19 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (52)`` () =
    "1e79033b"
    ++ FCVTZU ** [ O.Reg W27; O.ScalarReg D25 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (53)`` () =
    "9e390053"
    ++ FCVTZU ** [ O.Reg X19; O.ScalarReg S2 ]
    ||> test

  [<TestMethod>]
  member __.``4.6.30 Conversion between FP and integer (54)`` () =
    "9e790262"
    ++ FCVTZU ** [ O.Reg X2; O.ScalarReg D19 ]
    ||> test
