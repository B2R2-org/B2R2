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

module B2R2.FrontEnd.Tests.ARM64

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter.ARM64
open B2R2.FrontEnd.BinLifter.ARM64.OperandHelper
open type Opcode
open type Register

/// Shortcut for creating operands.
type O =
  static member Reg (r) =
    OprRegister r

  static member Imm (v) =
    OprImm v

  static member Shift (srType, v: int64) =
    OprShift (srType, Imm v)

  static member Shift (srType, r: Register) =
    OprShift (srType, Reg r)

  static member LSB v =
    OprLSB v

  static member Pstate st =
    OprPstate st

  static member SIMDList (lst: Register list, typ: SIMDVector) =
    lst |> List.map (fun r -> SIMDVecReg (r, typ)) |> OprSIMDList

  static member Prefetch v =
    OprPrfOp v

  static member ScalarReg r =
    scalReg r

(* FIXME: REMOVE THIS FUNCTION! *)
let private test' opcode oprs (bytes: byte[]) =
  let reader = BinReader.Init Endian.Big
  let span = System.ReadOnlySpan bytes
  let ins = ParsingMain.parse span reader 0UL
  let opcode' = ins.Info.Opcode
  let oprs' = ins.Info.Operands
  Assert.AreEqual (opcode', opcode)
  Assert.AreEqual (oprs', oprs)

let private test (bytes: byte[]) (opcode, oprs) =
  let reader = BinReader.Init Endian.Big
  let span = System.ReadOnlySpan bytes
  let ins = ParsingMain.parse span reader 0UL
  let opcode' = ins.Info.Opcode
  let oprs' = ins.Info.Operands
  Assert.AreEqual (opcode', opcode)
  Assert.AreEqual (oprs', oprs)

let private operandsFromArray oprList =
  let oprs = Array.ofList oprList
  match oprs.Length with
  | 0 -> NoOperand
  | 1 -> OneOperand oprs[0]
  | 2 -> TwoOperands (oprs[0], oprs[1])
  | 3 -> ThreeOperands (oprs[0], oprs[1], oprs[2])
  | 4 -> FourOperands (oprs[0], oprs[1], oprs[2], oprs[3])
  | 5 -> FiveOperands (oprs[0], oprs[1], oprs[2], oprs[3], oprs[4])
  | _ -> Utils.impossible ()

let private ( ** ) opcode oprList = (opcode, operandsFromArray oprList)

let private ( ++ ) byteString pair = (ByteArray.ofHexString byteString, pair)

/// C4.2 Data processing - immediate
[<TestClass>]
type DataProcessingImmClass () =
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
    ++ ADR ** [ O.Reg X7; memLabel 0xffe0fL ]
    ||> test

/// C4.3 Branches, exception generating and system instructions
[<TestClass>]
type BranchesAndExcepGenAndSystemClass () =
  [<TestMethod>]
  member __.``C4.3.1 Compare & branch (immediate) (1)`` () =
    "b4041023"
    ++ CBZ ** [ O.Reg X3; memLabel 0x8204L ]
    ||> test

  [<TestMethod>]
  member __.``C4.3.2 Conditional branch (immediate) (1)`` () =
    "54000021"
    ++ BNE ** [ memLabel 0x4L ]
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
    ++ TBZ ** [ O.Reg X3; O.Imm 0x21L; memLabel 0x8L ]
    ||> test

  [<TestMethod>]
  member __.``C4.3.6 Unconditional branch (immediate) (1)`` () =
    "14082a09"
    ++ B ** [ memLabel 0x20a824L ]
    ||> test

  [<TestMethod>]
  member __.``C4.3.7 Unconditional branch (register) (1)`` () =
    "d61f03e0"
    ++ BR ** [ O.Reg XZR ]
    ||> test

/// C4.4 Loads and stores
[<TestClass>]
type LoadAndStoreClass () =
  [<TestMethod>]
  member __.``C4.4.1 load/store multiple structures (1)`` () =
    "0c0001c5"
    ++ ST4 ** [ O.SIMDList ([ V5; V6; V7; V8 ], EightB)
                memBaseImm (X14, None) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.1 load/store multiple structures (2)`` () =
    "0c0081f8"
    ++ ST2 ** [ O.SIMDList ([ V24; V25 ], EightB); memBaseImm (X15, None) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.1 load/store multiple structures (3)`` () =
    "0c402f3d"
    ++ LD1 ** [ O.SIMDList ([ V29; V30; V31; V0 ], OneD)
                memBaseImm (X25, None) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.2 load/store multiple structures (post-indexed) (1)`` () =
    "0c800421"
    ++ ST4 ** [ O.SIMDList ([ V1; V2; V3; V4 ], FourH)
                memPostIdxReg (X1, X0, None) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.2 load/store multiple structures (post-indexed) (2)`` () =
    "0c950539"
    ++ ST4 ** [ O.SIMDList ([ V25; V26; V27; V28 ], FourH)
                memPostIdxReg (X9, X21, None) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.2 load/store multiple structures (post-indexed) (3)`` () =
    "4c9f0684"
    ++ ST4 ** [ O.SIMDList ([ V4; V5; V6; V7 ], EightH)
                memPostIdxImm (X20, Some 0x40L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.2 load/store multiple structures (post-indexed) (4)`` () =
    "4cca46be"
    ++ LD3 ** [ O.SIMDList ([ V30; V31; V0 ], EightH)
                memPostIdxReg (X21, X10, None) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.2 load/store multiple structures (post-indexed) (5)`` () =
    "4cdf0684"
    ++ LD4 ** [ O.SIMDList ([ V4; V5; V6; V7 ], EightH)
                memPostIdxImm (X20, Some 0x40L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.3 load/store single structure (1)`` () =
    "0d00147e"
    ++ ST1 ** [ OprSIMDList [ sVRegIdx V30 VecB 5uy ]; memBaseImm (X3, None) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.3 load/store single structure (2)`` () =
    "0d0025c3"
    ++ ST3 ** [ OprSIMDList [ sVRegIdx V3 VecB 1uy
                              sVRegIdx V4 VecB 1uy
                              sVRegIdx V5 VecB 1uy ]; memBaseImm (X14, None) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.3 load/store single structure (3)`` () =
    "4d20b2bd"
    ++ ST4 ** [ OprSIMDList [ sVRegIdx V29 VecS 3uy
                              sVRegIdx V30 VecS 3uy
                              sVRegIdx V31 VecS 3uy
                              sVRegIdx V0 VecS 3uy ]; memBaseImm (X21, None) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.3 load/store single structure (4)`` () =
    "4d601d4a"
    ++ LD2 ** [ OprSIMDList [ sVRegIdx V10 VecB 0xfuy; sVRegIdx V11 VecB 0xfuy ]
                memBaseImm (X10, None) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.3 load/store single structure (5)`` () =
    "4d40e6b5"
    ++ LD3R ** [ O.SIMDList ([ V21; V22; V23 ], EightH)
                 memBaseImm (X21, None) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.4 load/store single structure (post-indexed) (1)`` () =
    "0d8a06be"
    ++ ST1 ** [ OprSIMDList [ sVRegIdx V30 VecB 1uy ]
                memPostIdxReg (X21, X10, None) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.4 load/store single structure (post-indexed) (2)`` () =
    "4d9f597e"
    ++ ST1 ** [ OprSIMDList [ sVRegIdx V30 VecH 7uy ]
                memPostIdxImm (X11, Some 0x2L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.4 load/store single structure (post-indexed) (3)`` () =
    "4db581bd"
    ++ ST2 ** [ OprSIMDList [ sVRegIdx V29 VecS 2uy; sVRegIdx V30 VecS 2uy ]
                memPostIdxReg (X13, X21, None) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.4 load/store single structure (post-indexed) (4)`` () =
    "0dca06be"
    ++ LD1 ** [ OprSIMDList [ sVRegIdx V30 VecB 1uy ]
                memPostIdxReg (X21, X10, None) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.4 load/store single structure (post-indexed) (5)`` () =
    "4dff39fd"
    ++ LD4 ** [ OprSIMDList [ sVRegIdx V29 VecB 0xeuy
                              sVRegIdx V30 VecB 0xeuy
                              sVRegIdx V31 VecB 0xeuy
                              sVRegIdx V0 VecB 0xeuy ]
                memPostIdxImm (X15, Some 0x4L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.5 Load register (literal) (1)`` () =
    "58531c49"
    ++ LDR ** [ O.Reg X9; memLabel 0xa6388L ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.5 Load register (literal) (2)`` () =
    "9880001e"
    ++ LDRSW ** [ O.Reg X30; memLabel 0xfffffffffff00000L ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.5 Load register (literal) (3)`` () =
    "d800802b"
    ++ PRFM ** [ O.Prefetch PLIL2STRM; memLabel 0x1004L ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.6 Load/store exclusive (1)`` () =
    "08147cb5"
    ++ STXRB ** [ O.Reg W20; O.Reg W21; memBaseImm (X5, None) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.6 Load/store exclusive (2)`` () =
    "882b04c2"
    ++ STXP ** [ O.Reg W11; O.Reg W2; O.Reg W1; memBaseImm (X6, None) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.6 Load/store exclusive (3)`` () =
    "085f7d7a"
    ++ LDXRB ** [ O.Reg W26; memBaseImm (X11, None) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.7 Load/store no-allocate pair (offset) (1)`` () =
    "280c2aa3"
    ++ STNP ** [ O.Reg W3; O.Reg W10; memBaseImm (X21, Some 0x60L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.7 Load/store no-allocate pair (offset) (2)`` () =
    "ac1505b5"
    ++ STNP ** [ O.ScalarReg Q21; O.ScalarReg Q1
                 memBaseImm (X13, Some 0x2a0L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.8 Load/store register (immediate post-indexed) (1)`` () =
    "3810a423"
    ++ STRB ** [ O.Reg W3; memPostIdxImm (X1, Some 0xffffffffffffff0aL) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.8 Load/store register (immediate post-indexed) (2)`` () =
    "38cea4b2"
    ++ LDRSB ** [ O.Reg W18; memPostIdxImm (X5, Some 0xeaL) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.8 Load/store register (immediate post-indexed) (3)`` () =
    "7c0ca422"
    ++ STR ** [ O.ScalarReg H2; memPostIdxImm (X1, Some 0xcaL) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.8 Load/store register (immediate post-indexed) (4)`` () =
    "781004f5"
    ++ STRH ** [ O.Reg W21; memPostIdxImm (X7, Some 0xffffffffffffff00L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.8 Load/store register (immediate post-indexed) (5)`` () =
    "b8803555"
    ++ LDRSW ** [ O.Reg X21; memPostIdxImm (X10, Some 0x3L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.9 Load/store register (immediate pre-indexed) (1)`` () =
    "3800fcb1"
    ++ STRB ** [ O.Reg W17; memPreIdxImm (X5, Some 0xfL) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.9 Load/store register (immediate pre-indexed) (2)`` () =
    "7c00fc6a"
    ++ STR ** [ O.ScalarReg H10; memPreIdxImm (X3, Some 0xfL) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.10 Load/store register (register offset) (1)`` () =
    "38214867"
    ++ STRB ** [ O.Reg W7
                 memBaseReg (X3, W1, Some (ExtRegOffset (ExtUXTW, None))) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.10 Load/store register (register offset) (2)`` () =
    "38235867"
    ++ STRB ** [ O.Reg W7
                 memBaseReg (X3, W3, Some (ExtRegOffset (ExtUXTW, Some 0x0L))) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.10 Load/store register (register offset) (3)`` () =
    "3820782c"
    ++ STRB ** [ O.Reg W12
                 memBaseReg (X1, X0, Some (ShiftOffset (SRTypeLSL, Imm 0x0L))) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.10 Load/store register (register offset) (4)`` () =
    "7867cabf"
    ++ LDRH ** [ O.Reg WZR
                 memBaseReg (X21, W7, Some (ExtRegOffset (ExtSXTW, None))) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.10 Load/store register (register offset) (5)`` () =
    "78e37871"
    ++ LDRSH ** [ O.Reg W17
                  memBaseReg (X3, X3, Some (ShiftOffset (SRTypeLSL, Imm 0x1L)))
                ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.10 Load/store register (register offset) (6)`` () =
    "f8a35867"
    ++ PRFM ** [ O.Imm 0x7L
                 memBaseReg (X3, W3, Some (ExtRegOffset (ExtUXTW, Some 0x3L))) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.10 Load/store register (register offset) (7)`` () =
    "f8a3586c"
    ++ PRFM ** [ O.Prefetch PLIL3KEEP
                 memBaseReg (X3, W3, Some (ExtRegOffset (ExtUXTW, Some 0x3L))) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.11 Load/store register (unprivileged) (1)`` () =
    "380198ee"
    ++ STTRB ** [ O.Reg W14; memBaseImm (X7, Some 0x19L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.11 Load/store register (unprivileged) (2)`` () =
    "781188ba"
    ++ STTRH ** [ O.Reg W26; memBaseImm (X5, Some 0xffffffffffffff18L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.11 Load/store register (unprivileged) (3)`` () =
    "b881f86a"
    ++ LDTRSW ** [ O.Reg X10; memBaseImm (X3, Some 0x1fL) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.12 Load/store register (unscaled immediate) (1)`` () =
    "3806a0f8"
    ++ STURB ** [ O.Reg W24; memBaseImm (X7, Some 0x6aL) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.12 Load/store register (unscaled immediate) (2)`` () =
    "3cce0283"
    ++ LDUR ** [ O.ScalarReg Q3; memBaseImm (X20, Some 0xe0L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.12 Load/store register (unscaled immediate) (3)`` () =
    "f881f07c"
    ++ PRFUM ** [ O.Imm 0x1cL; memBaseImm (X3, Some 0x1fL) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.13 Load/store register (unsigned immediate) (1)`` () =
    "391557ff"
    ++ STRB ** [ O.Reg WZR; memBaseImm (SP, Some 0x555L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.13 Load/store register (unsigned immediate) (2)`` () =
    "bd1fffff"
    ++ STR ** [ O.ScalarReg S31; memBaseImm (SP, Some 0x1ffcL) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.13 Load/store register (unsigned immediate) (3)`` () =
    "f9be01f2"
    ++ PRFM ** [ O.Prefetch PSTL2KEEP; memBaseImm (X15, Some 0x7c00L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.14 Load/store register pair (offset) (1)`` () =
    "2961cbb9"
    ++ LDP ** [ O.Reg W25
                O.Reg W18
                memBaseImm (X29, Some 0xffffffffffffff0cL) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.15 Load/store register pair (post-indexed) (1)`` () =
    "a89fd7eb"
    ++ STP ** [ O.Reg X11; O.Reg X21; memPostIdxImm (SP, Some 0x1f8L) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.15 Load/store register pair (post-indexed) (2)`` () =
    "68cfdfdf"
    ++ LDPSW ** [ O.Reg XZR; O.Reg X23; memPostIdxImm (X30, Some 0x7cL) ]
    ||> test

  [<TestMethod>]
  member __.``C4.4.16 Load/store register pair (pre-indexed) (1)`` () =
    "a99fffff"
    ++ STP ** [ O.Reg XZR; O.Reg XZR; memPreIdxImm (SP, Some 0x1f8L) ]
    ||> test

/// C4.5 Data processing - register
[<TestClass>]
type DataPorcessingRegClass () =
  /// C4.5.1 Add/subtract (extended register)
  [<TestMethod>]
  member __.``[AArch64] Add/subtract (extended register) Parse Test`` () =
    test'
      ADD
      (FourOperands (
        OprRegister WSP,
        OprRegister WSP,
        OprRegister WZR,
        OprExtReg None
      ))
      [| 0x0buy; 0x3fuy; 0x43uy; 0xffuy |]

    test'
      ADD
      (FourOperands (
        OprRegister WSP,
        OprRegister WSP,
        OprRegister WZR,
        OprExtReg (Some (ShiftOffset (SRTypeLSL, Imm 2L)))
      ))
      [| 0x0buy; 0x3fuy; 0x4buy; 0xffuy |]

    test'
      ADD
      (FourOperands (
        OprRegister SP,
        OprRegister X10,
        OprRegister W10,
        OprExtReg (Some (ExtRegOffset (ExtUXTW, Some 2L)))
      ))
      [| 0x8buy; 0x2auy; 0x49uy; 0x5fuy |]

    test'
      CMN
      (ThreeOperands (
        OprRegister SP,
        OprRegister X14,
        OprExtReg (Some (ShiftOffset (SRTypeLSL, Imm 1L)))
      ))
      [| 0xabuy; 0x2euy; 0x67uy; 0xffuy |]

  /// C4.5.2 Add/subtract (shifted register)
  [<TestMethod>]
  member __.``[AArch64] Add/subtract (shifted register) Parse Test`` () =
    test'
      ADD
      (FourOperands (
        OprRegister W27,
        OprRegister W28,
        OprRegister W14,
        OprShift (SRTypeASR, Imm 23L)
      ))
      [| 0x0buy; 0x8euy; 0x5fuy; 0x9buy |]

    test'
      SUBS
      (FourOperands (
        OprRegister W11,
        OprRegister W29,
        OprRegister W14,
        OprShift (SRTypeLSR, Imm 7L)
      ))
      [| 0x6buy; 0x4euy; 0x1fuy; 0xabuy |]

    test'
      ADDS
      (FourOperands (
        OprRegister X18,
        OprRegister X29,
        OprRegister X14,
        OprShift (SRTypeASR, Imm 7L)
      ))
      [| 0xabuy; 0x8euy; 0x1fuy; 0xb2uy |]

  /// C4.5.3 Add/subtract (with carry)
  [<TestMethod>]
  member __.``[AArch64] Add/subtract (with carry) Parse Test`` () =
    test'
      ADCS
      (ThreeOperands (
        OprRegister XZR,
        OprRegister X21,
        OprRegister X10
      ))
      [| 0xbauy; 0x0auy; 0x02uy; 0xbfuy |]

    test'
      NGC
      (TwoOperands (OprRegister W30, OprRegister W11))
      [| 0x5auy; 0x0buy; 0x03uy; 0xfeuy |]

  /// C4.5.4 Conditional compare (immediate)
  [<TestMethod>]
  member __.``[AArch64] Conditional compare (immediate) Parse Test`` () =
    test'
      CCMN
      (FourOperands (OprRegister X3, OprImm 0x15L, OprNZCV 8uy, OprCond GT))
      [| 0xbauy; 0x55uy; 0xc8uy; 0x68uy |]

  /// C4.5.5 Conditional compare (register)
  [<TestMethod>]
  member __.``[AArch64] Conditional compare (register) Parse Test`` () =
    test'
      CCMN
      (FourOperands (
        OprRegister X15,
        OprRegister X28,
        OprNZCV 0xfuy,
        OprCond PL
      ))
      [| 0xbauy; 0x5cuy; 0x51uy; 0xefuy |]

  /// C4.5.6 Conditional select
  [<TestMethod>]
  member __.``[AArch64] Conditional select Parse Test`` () =
    test'
      CSEL
      (FourOperands (
        OprRegister X28,
        OprRegister X23,
        OprRegister X6,
        OprCond LS
      ))
      [| 0x9auy; 0x86uy; 0x92uy; 0xfcuy |]

    test'
      CSINC
      (FourOperands (
        OprRegister W21,
        OprRegister W0,
        OprRegister W16,
        OprCond CS
      )) // HS
      [| 0x1auy; 0x90uy; 0x24uy; 0x15uy |]

    test'
      CINC
      (ThreeOperands (OprRegister W21, OprRegister W16, OprCond CC)) // LO
      [| 0x1auy; 0x90uy; 0x26uy; 0x15uy |]

    test'
      CSET
      (TwoOperands (OprRegister W7, OprCond LE))
      [| 0x1auy; 0x9fuy; 0xc7uy; 0xe7uy |]

    test'
      CINV
      (ThreeOperands (OprRegister X10, OprRegister X7, OprCond LE))
      [| 0xdauy; 0x87uy; 0xc0uy; 0xeauy |]

    test'
      CSETM
      (TwoOperands (OprRegister X10, OprCond LE))
      [| 0xdauy; 0x9fuy; 0xc3uy; 0xeauy |]

    test'
      CSINV
      (FourOperands (
        OprRegister X10,
        OprRegister X27,
        OprRegister XZR,
        OprCond GT
      ))
      [| 0xdauy; 0x9fuy; 0xc3uy; 0x6auy |]

    test'
      CSNEG
      (FourOperands (
        OprRegister W30,
        OprRegister W21,
        OprRegister W10,
        OprCond AL
      ))
      [| 0x5auy; 0x8auy; 0xe6uy; 0xbeuy |]

    test'
      CNEG
      (ThreeOperands (OprRegister W30, OprRegister W21, OprCond LE))
      [| 0x5auy; 0x95uy; 0xc6uy; 0xbeuy |]

  /// C4.5.7 Data-processing (1 source)
  [<TestMethod>]
  member __.``[AArch64] Data-processing (1 source) Parse Test`` () =
    test'
      RBIT
      (TwoOperands (OprRegister W28, OprRegister W11))
      [| 0x5auy; 0xc0uy; 0x01uy; 0x7cuy |]

    test'
      CLS
      (TwoOperands (OprRegister XZR, OprRegister X11))
      [| 0xdauy; 0xc0uy; 0x15uy; 0x7fuy |]

    test'
      REV32
      (TwoOperands (OprRegister X30, OprRegister X15))
      [| 0xdauy; 0xc0uy; 0x09uy; 0xfeuy |]

  /// C4.5.8 Data-processing (2 source)
  [<TestMethod>]
  member __.``[AArch64] Data-processing (2 source) Parse Test`` () =
    test'
      UDIV
      (ThreeOperands (OprRegister W30, OprRegister W23, OprRegister W9))
      [| 0x1auy; 0xc9uy; 0x0auy; 0xfeuy |]

    test'
      CRC32CX
      (ThreeOperands (OprRegister W29, OprRegister W3, OprRegister X26))
      [| 0x9auy; 0xdauy; 0x5cuy; 0x7duy |]

  /// C4.5.9 Data-processing (3 source)
  [<TestMethod>]
  member __.``[AArch64] Data-processing (3 source) Parse Test`` () =
    test'
      MADD
      (FourOperands (
        OprRegister X7,
        OprRegister X28,
        OprRegister X10,
        OprRegister X11
      ))
      [| 0x9buy; 0x0auy; 0x2fuy; 0x87uy |]

    test'
      MUL
      (ThreeOperands (OprRegister X7, OprRegister X28, OprRegister X10))
      [| 0x9buy; 0x0auy; 0x7fuy; 0x87uy |] (* Alias of MADD *)

    test'
      MSUB
      (FourOperands (
        OprRegister X7,
        OprRegister X28,
        OprRegister X10,
        OprRegister X11
      ))
      [| 0x9buy; 0x0auy; 0xafuy; 0x87uy |]

    test'
      SMADDL
      (FourOperands (
        OprRegister X7,
        OprRegister W28,
        OprRegister W10,
        OprRegister X11
      ))
      [| 0x9buy; 0x2auy; 0x2fuy; 0x87uy |]

    test'
      SMSUBL
      (FourOperands (
        OprRegister X7,
        OprRegister W28,
        OprRegister W10,
        OprRegister X11
      ))
      [| 0x9buy; 0x2auy; 0xafuy; 0x87uy |]

    test'
      SMULH
      (ThreeOperands (OprRegister X7, OprRegister X28, OprRegister X10))
      [| 0x9buy; 0x4auy; 0x2fuy; 0x87uy |]

    test'
      UMADDL
      (FourOperands (
        OprRegister X7,
        OprRegister W28,
        OprRegister W10,
        OprRegister X11
      ))
      [| 0x9buy; 0xaauy; 0x2fuy; 0x87uy |]

    test'
      UMSUBL
      (FourOperands (
        OprRegister X7,
        OprRegister W28,
        OprRegister W10,
        OprRegister X11
      ))
      [| 0x9buy; 0xaauy; 0xafuy; 0x87uy |]

    test'
      UMULH
      (ThreeOperands (OprRegister X7, OprRegister X28, OprRegister X10))
      [| 0x9buy; 0xcauy; 0x2fuy; 0x87uy |]

    test'
      MNEG
      (ThreeOperands (OprRegister X7, OprRegister X28, OprRegister X10))
      [| 0x9buy; 0x0auy; 0xffuy; 0x87uy |] (* Alias of MSUB *)

    test'
      SMULL
      (ThreeOperands (OprRegister X7, OprRegister W28, OprRegister W10))
      [| 0x9buy; 0x2auy; 0x7fuy; 0x87uy |] (* Alias of SMADDL *)

    test'
      SMNEGL
      (ThreeOperands (OprRegister X7, OprRegister W28, OprRegister W10))
      [| 0x9buy; 0x2auy; 0xffuy; 0x87uy |] (* Alias of SMSUBL *)

    test'
      UMULL
      (ThreeOperands (OprRegister X7, OprRegister W28, OprRegister W10))
      [| 0x9buy; 0xaauy; 0x7fuy; 0x87uy |] (* Alias of UMADDL *)

    test'
      UMNEGL
      (ThreeOperands (OprRegister X7, OprRegister W28, OprRegister W10))
      [| 0x9buy; 0xaauy; 0xffuy; 0x87uy |] (* Alias of UMSUBL *)

  /// C4.5.10 Logical (shifted register)
  [<TestMethod>]
  member __.``[AArch64] Logical (shifted register) Parse Test`` () =
    test'
      AND
      (FourOperands (
        OprRegister X5,
        OprRegister X10,
        OprRegister X24,
        OprShift (SRTypeLSR, Imm 14L)
      ))
      [| 0x8auy; 0x58uy; 0x39uy; 0x45uy |]

    test'
      ORN
      (FourOperands (
        OprRegister W26,
        OprRegister W29,
        OprRegister W22,
        OprShift (SRTypeROR, Imm 7L)
      ))
      [| 0x2auy; 0xf6uy; 0x1fuy; 0xbauy |]

    test'
      MVN
      (ThreeOperands (
        OprRegister W26,
        OprRegister W22,
        OprShift (SRTypeROR, Imm 0x7L)
      ))
      [| 0x2auy; 0xf6uy; 0x1fuy; 0xfauy |]

/// C4.6 Data processing - SIMD and floating point
[<TestClass>]
type DataProcessingSIMDAndFPClass () =
  /// C4.6.1 Advanced SIMD across lanes
  [<TestMethod>]
  member __.``[AArch64] Advanced SIMD across lanes Parse Test`` () =
    test'
      SADDLV
      (TwoOperands (
        scalReg D2,
        OprSIMD (SIMDVecReg (V22, FourS))
      ))
      [| 0x4euy; 0xb0uy; 0x3auy; 0xc2uy |]

    test'
      SMAXV
      (TwoOperands (
        scalReg B18,
        OprSIMD (SIMDVecReg (V6, EightB))
      ))
      [| 0x0euy; 0x30uy; 0xa8uy; 0xd2uy |]

    test'
      SMINV
      (TwoOperands (
        scalReg H10,
        OprSIMD (SIMDVecReg (V16, FourH))
      ))
      [| 0x0euy; 0x71uy; 0xaauy; 0x0auy |]

    test'
      ADDV
      (TwoOperands (
        scalReg H26,
        OprSIMD (SIMDVecReg (V4, EightH))
      ))
      [| 0x4euy; 0x71uy; 0xb8uy; 0x9auy |]

    test'
      UADDLV
      (TwoOperands (
        scalReg D17,
        OprSIMD (SIMDVecReg (V9, FourS))
      ))
      [| 0x6euy; 0xb0uy; 0x39uy; 0x31uy |]

    test'
      UMAXV
      (TwoOperands (
        scalReg H8,
        OprSIMD (SIMDVecReg (V28, FourH))
      ))
      [| 0x2euy; 0x70uy; 0xabuy; 0x88uy |]

    test'
      UMINV
      (TwoOperands (
        scalReg S10,
        OprSIMD (SIMDVecReg (V23, FourS))
      ))
      [| 0x6euy; 0xb1uy; 0xaauy; 0xeauy |]

    test'
      FMAXNMV
      (TwoOperands (
        scalReg S11,
        OprSIMD (SIMDVecReg (V18, FourS))
      ))
      [| 0x6euy; 0x30uy; 0xcauy; 0x4buy |]

    test'
      FMAXV
      (TwoOperands (
        scalReg S8,
        OprSIMD (SIMDVecReg (V10, FourS))
      ))
      [| 0x6euy; 0x30uy; 0xf9uy; 0x48uy |]

    test'
      FMINNMV
      (TwoOperands (
        scalReg S12,
        OprSIMD (SIMDVecReg (V22, FourS))
      ))
      [| 0x6euy; 0xb0uy; 0xcauy; 0xccuy |]

    test'
      FMINV
      (TwoOperands (
        scalReg S2,
        OprSIMD (SIMDVecReg (V22, FourS))
      ))
      [| 0x6euy; 0xb0uy; 0xfauy; 0xc2uy |]

  /// C4.6.2 Advanced SIMD copy
  [<TestMethod>]
  member __.``[AArch64] Advanced SIMD copy Parse Test`` () =
    test'
      DUP
      (TwoOperands (
        OprSIMD (SIMDVecReg (V6, TwoD)),
        OprSIMD (sVRegIdx V4 VecD 1uy)
      ))
      [| 0x4euy; 0x18uy; 0x04uy; 0x86uy |]

    test'
      DUP
      (TwoOperands (
        OprSIMD (SIMDVecReg (V1, TwoD)),
        OprRegister X3
      ))
      [| 0x4euy; 0x08uy; 0x0cuy; 0x61uy |]

    test'
      DUP
      (TwoOperands (
        OprSIMD (SIMDVecReg (V28, FourH)),
        OprRegister WZR
      )) // Online HEX To ARM Conv error
      [| 0x0euy; 0x1euy; 0x0fuy; 0xfcuy |]

    test'
      DUP
      (TwoOperands (
        OprSIMD (SIMDVecReg (V28, FourH)),
        OprRegister WZR
      ))
      [| 0x0euy; 0x02uy; 0x0fuy; 0xfcuy |]

    test'
      SMOV
      (TwoOperands (
        OprRegister W26,
        OprSIMD (sVRegIdx V7 VecH 0uy)
      ))
      [| 0x0euy; 0x02uy; 0x2cuy; 0xfauy |]

    test'
      UMOV
      (TwoOperands (
        OprRegister W3,
        OprSIMD (sVRegIdx V14 VecB 0uy)
      ))
      [| 0x0euy; 0x01uy; 0x3duy; 0xc3uy |]

    test'
      MOV
      (TwoOperands (
        OprRegister W3,
        OprSIMD (sVRegIdx V14 VecS 0uy)
      ))
      [| 0x0euy; 0x04uy; 0x3duy; 0xc3uy |]

    test'
      MOV
      (TwoOperands (
        OprRegister X3,
        OprSIMD (sVRegIdx V14 VecD 0uy)
      ))
      [| 0x4euy; 0x08uy; 0x3duy; 0xc3uy |]

    test'
      INS
      (TwoOperands (
        OprSIMD (sVRegIdx V9 VecS 0uy),
        OprRegister W1
      ))
      [| 0x4euy; 0x04uy; 0x1cuy; 0x29uy |]

    test'
      INS
      (TwoOperands (
        OprSIMD (sVRegIdx V5 VecH 0uy),
        OprSIMD (sVRegIdx V6 VecH 7uy)
      ))
      [| 0x6euy; 0x02uy; 0x74uy; 0xc5uy |]

  /// C4.6.3 Advanced SIMD extract
  [<TestMethod>]
  member __.``[AArch64] Advanced SIMD extract Parse Test`` () =
    test'
      EXT
      (FourOperands (
        OprSIMD (SIMDVecReg (V3, SixteenB)),
        OprSIMD (SIMDVecReg (V12, SixteenB)),
        OprSIMD (SIMDVecReg (V6, SixteenB)),
        OprImm 9L
      ))
      [| 0x6euy; 0x06uy; 0x49uy; 0x83uy |]

    test'
      EXT
      (FourOperands (
        OprSIMD (SIMDVecReg (V28, EightB)),
        OprSIMD (SIMDVecReg (V7, EightB)),
        OprSIMD (SIMDVecReg (V7, EightB)),
        OprImm 7L
      ))
      [| 0x2euy; 0x07uy; 0x38uy; 0xfcuy |]

  /// C4.6.4 Advanced SIMD modified immediate
  [<TestMethod>]
  member __.``[AArch64] Advanced SIMD modified immediate Parse Test`` () =
    test'
      MOVI
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V25, FourS)),
        OprImm 0xAAL,
        OprShift (SRTypeLSL, Imm 24L)
      ))
      [| 0x4fuy; 0x05uy; 0x65uy; 0x59uy |]

    test'
      MOVI
      (TwoOperands (
        OprSIMD (SIMDVecReg (V25, FourS)),
        OprImm 0xAAL
      ))
      [| 0x4fuy; 0x05uy; 0x05uy; 0x59uy |]

    test'
      ORR
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprImm 0x46L,
        OprShift (SRTypeLSL, Imm 8L)
      ))
      [| 0x4fuy; 0x02uy; 0x34uy; 0xc5uy |]

    test'
      MOVI
      (TwoOperands (
        OprSIMD (SIMDVecReg (V25, SixteenB)),
        OprImm 0x2EL
      ))
      [| 0x4fuy; 0x01uy; 0xe5uy; 0xd9uy |]

    test'
      ORR
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, FourH)),
        OprImm 0xC7L,
        OprShift (SRTypeLSL, Imm 8L)
      ))
      [| 0x0fuy; 0x06uy; 0xb4uy; 0xe5uy |]

    test'
      MOVI
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V25, EightH)),
        OprImm 0x9AL,
        OprShift (SRTypeLSL, Imm 8L)
      ))
      [| 0x4fuy; 0x04uy; 0xa7uy; 0x59uy |]

    test'
      MOVI
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprImm 0xB2L,
        OprShift (SRTypeMSL, Imm 8L)
      ))
      [| 0x4fuy; 0x05uy; 0xc6uy; 0x55uy |]

    test'
      FMOV
      (TwoOperands (
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprFPImm -11.5
      ))
      [| 0x4fuy; 0x05uy; 0xf4uy; 0xe5uy |]

    test'
      MVNI
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprImm 0xE6L,
        OprShift (SRTypeLSL, Imm 8L)
      ))
      [| 0x6fuy; 0x07uy; 0x24uy; 0xd5uy |]

    test'
      BIC
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V7, TwoS)),
        OprImm 0xB5L,
        OprShift (SRTypeLSL, Imm 8L)
      ))
      [| 0x2fuy; 0x05uy; 0x36uy; 0xa7uy |]

    test'
      MVNI
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, EightH)),
        OprImm 0xE6L,
        OprShift (SRTypeLSL, Imm 8L)
      ))
      [| 0x6fuy; 0x07uy; 0xa4uy; 0xd5uy |]

    test'
      BIC
      (TwoOperands (
        OprSIMD (SIMDVecReg (V7, FourH)),
        OprImm 0xB5L
      ))
      [| 0x2fuy; 0x05uy; 0x96uy; 0xa7uy |]

    test'
      MVNI
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprImm 0xE6L,
        OprShift (SRTypeMSL, Imm 8L)
      ))
      [| 0x6fuy; 0x07uy; 0xc4uy; 0xd5uy |]

    test'
      MOVI
      (TwoOperands (scalReg D27, OprImm 0xFF00FFFFFF00FF00L))
      [| 0x2fuy; 0x05uy; 0xe7uy; 0x5buy |]

    test'
      MOVI
      (TwoOperands (
        OprSIMD (SIMDVecReg (V23, TwoD)),
        OprImm 0xFF00FFFFFF00FF00L
      ))
      [| 0x6fuy; 0x05uy; 0xe7uy; 0x57uy |]

    test'
      FMOV
      (TwoOperands (
        OprSIMD (SIMDVecReg (V5, TwoD)),
        OprFPImm -11.5
      ))
      [| 0x6fuy; 0x05uy; 0xf4uy; 0xe5uy |]

  /// C4.6.5 Advanced SIMD permute
  [<TestMethod>]
  member __.``[AArch64] Advanced SIMD permute Parse Test`` () =
    test'
      UZP1
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V3, EightH)),
        OprSIMD (SIMDVecReg (V12, EightH)),
        OprSIMD (SIMDVecReg (V14, EightH))
      ))
      [| 0x4euy; 0x4euy; 0x19uy; 0x83uy |]

    test'
      TRN1
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V30, TwoS)),
        OprSIMD (SIMDVecReg (V7, TwoS)),
        OprSIMD (SIMDVecReg (V7, TwoS))
      ))
      [| 0x0euy; 0x87uy; 0x28uy; 0xfeuy |]

    test'
      ZIP1
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V28, SixteenB)),
        OprSIMD (SIMDVecReg (V1, SixteenB)),
        OprSIMD (SIMDVecReg (V3, SixteenB))
      ))
      [| 0x4euy; 0x03uy; 0x38uy; 0x3cuy |]

    test'
      ZIP1
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V1, EightB)),
        OprSIMD (SIMDVecReg (V6, EightB)),
        OprSIMD (SIMDVecReg (V7, EightB))
      ))
      [| 0x0euy; 0x07uy; 0x38uy; 0xc1uy |]

    test'
      UZP2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V6, TwoD)),
        OprSIMD (SIMDVecReg (V6, TwoD)),
        OprSIMD (SIMDVecReg (V1, TwoD))
      ))
      [| 0x4euy; 0xc1uy; 0x58uy; 0xc6uy |]

    test'
      TRN2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V3, TwoS)),
        OprSIMD (SIMDVecReg (V6, TwoS)),
        OprSIMD (SIMDVecReg (V7, TwoS))
      ))
      [| 0x0euy; 0x87uy; 0x68uy; 0xc3uy |]

    test'
      ZIP2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V4, SixteenB)),
        OprSIMD (SIMDVecReg (V1, SixteenB))
      ))
      [| 0x4euy; 0x01uy; 0x78uy; 0x85uy |]

  /// C4.6.6 Advanced SIMD scalar copy
  [<TestMethod>]
  member __.``[AArch64] Advanced SIMD scalar copy Parse Test`` () =
    test'
      MOV
      (TwoOperands (scalReg D10, OprSIMD (sVRegIdx V10 VecD 0uy)))
      [| 0x5euy; 0x08uy; 0x05uy; 0x4auy |]

    test'
      MOV
      (TwoOperands (scalReg B1, OprSIMD (sVRegIdx V10 VecB 3uy)))
      [| 0x5euy; 0x07uy; 0x05uy; 0x41uy |]

  /// C4.6.7 Advanced SIMD scalar pairwise
  [<TestMethod>]
  member __.``[AArch64] Advanced SIMD scalar pairwise Parse Test`` () =
    test'
      ADDP
      (TwoOperands (scalReg D7, OprSIMD (SIMDVecReg (V3, TwoD))))
      [| 0x5euy; 0xf1uy; 0xb8uy; 0x67uy |]

    test'
      FMAXNMP
      (TwoOperands (
        scalReg D15,
        OprSIMD (SIMDVecReg (V14, TwoD))
      ))
      [| 0x7euy; 0x70uy; 0xc9uy; 0xcfuy |]

    test'
      FADDP
      (TwoOperands (
        scalReg S31,
        OprSIMD (SIMDVecReg (V15, TwoS))
      ))
      [| 0x7euy; 0x30uy; 0xd9uy; 0xffuy |]

    test'
      FMAXP
      (TwoOperands (
        scalReg D18,
        OprSIMD (SIMDVecReg (V17, TwoD))
      ))
      [| 0x7euy; 0x70uy; 0xfauy; 0x32uy |]

    test'
      FMINNMP
      (TwoOperands (scalReg S1, OprSIMD (SIMDVecReg (V14, TwoS))))
      [| 0x7euy; 0xb0uy; 0xc9uy; 0xc1uy |]

    test'
      FMINP
      (TwoOperands (scalReg D7, OprSIMD (SIMDVecReg (V1, TwoD))))
      [| 0x7euy; 0xf0uy; 0xf8uy; 0x27uy |]

  /// C4.6.8 Advanced SIMD scalar shift by immediate
  [<TestMethod>]
  member __.``[AArch64] Advanced SIMD scalar shift by imm Parse Test`` () =
    test'
      SSHR
      (ThreeOperands (scalReg D1, scalReg D10, OprImm 0x3eL))
      [| 0x5fuy; 0x42uy; 0x05uy; 0x41uy |]

    test'
      SSRA
      (ThreeOperands (scalReg D28, scalReg D3, OprImm 0x1cL))
      [| 0x5fuy; 0x64uy; 0x14uy; 0x7cuy |]

    test'
      SRSHR
      (ThreeOperands (scalReg D1, scalReg D7, OprImm 0x27L))
      [| 0x5fuy; 0x59uy; 0x24uy; 0xe1uy |]

    test'
      SRSRA
      (ThreeOperands (scalReg D3, scalReg D6, OprImm 1L))
      [| 0x5fuy; 0x7fuy; 0x34uy; 0xc3uy |]

    test'
      SHL
      (ThreeOperands (scalReg D13, scalReg D7, OprImm 2L))
      [| 0x5fuy; 0x42uy; 0x54uy; 0xeduy |]

    test'
      SQSHL
      (ThreeOperands (scalReg S25, scalReg S16, OprImm 4L))
      [| 0x5fuy; 0x24uy; 0x76uy; 0x19uy |]

    test'
      SQSHL
      (ThreeOperands (scalReg D25, scalReg D16, OprImm 0x24L))
      [| 0x5fuy; 0x64uy; 0x76uy; 0x19uy |]

    test'
      SQSHRN
      (ThreeOperands (scalReg S7, scalReg D12, OprImm 0x17L))
      [| 0x5fuy; 0x29uy; 0x95uy; 0x87uy |]

    test'
      SQRSHRN
      (ThreeOperands (scalReg H25, scalReg S7, OprImm 1L))
      [| 0x5fuy; 0x1fuy; 0x9cuy; 0xf9uy |]

    test'
      SCVTF
      (ThreeOperands (scalReg D1, scalReg D6, OprFbits 0x1fuy))
      [| 0x5fuy; 0x61uy; 0xe4uy; 0xc1uy |]

    test'
      FCVTZS
      (ThreeOperands (scalReg D11, scalReg D8, OprFbits 0x25uy))
      [| 0x5fuy; 0x5buy; 0xfduy; 0x0buy |]

    test'
      USHR
      (ThreeOperands (scalReg D7, scalReg D14, OprImm 0x17L))
      [| 0x7fuy; 0x69uy; 0x05uy; 0xc7uy |]

    test'
      USRA
      (ThreeOperands (scalReg D17, scalReg D1, OprImm 0x36L))
      [| 0x7fuy; 0x4auy; 0x14uy; 0x31uy |]

    test'
      URSHR
      (ThreeOperands (scalReg D9, scalReg D2, OprImm 0x20L))
      [| 0x7fuy; 0x60uy; 0x24uy; 0x49uy |]

    test'
      URSRA
      (ThreeOperands (scalReg D9, scalReg D6, OprImm 0x3cL))
      [| 0x7fuy; 0x44uy; 0x34uy; 0xc9uy |]

    test'
      SRI
      (ThreeOperands (scalReg D3, scalReg D14, OprImm 0x1fL))
      [| 0x7fuy; 0x61uy; 0x45uy; 0xc3uy |]

    test'
      SLI
      (ThreeOperands (scalReg D3, scalReg D6, OprImm 0xeL))
      [| 0x7fuy; 0x4euy; 0x54uy; 0xc3uy |]

    test'
      SQSHLU
      (ThreeOperands (scalReg S7, scalReg S20, OprImm 0xbL))
      [| 0x7fuy; 0x2buy; 0x66uy; 0x87uy |]

    test'
      UQSHL
      (ThreeOperands (scalReg B24, scalReg B7, OprImm 3L))
      [| 0x7fuy; 0x0buy; 0x74uy; 0xf8uy |]

    test'
      SQSHRUN
      (ThreeOperands (scalReg S13, scalReg D12, OprImm 0x11L))
      [| 0x7fuy; 0x2fuy; 0x85uy; 0x8duy |]

    test'
      SQRSHRUN
      (ThreeOperands (scalReg S16, scalReg D1, OprImm 6L))
      [| 0x7fuy; 0x3auy; 0x8cuy; 0x30uy |]

    test'
      UQSHRN
      (ThreeOperands (scalReg H13, scalReg S6, OprImm 0xbL))
      [| 0x7fuy; 0x15uy; 0x94uy; 0xcduy |]

    test'
      UQRSHRN
      (ThreeOperands (scalReg B6, scalReg H2, OprImm 4L))
      [| 0x7fuy; 0x0cuy; 0x9cuy; 0x46uy |]

    test'
      UCVTF
      (ThreeOperands (scalReg S1, scalReg S6, OprFbits 0x1cuy))
      [| 0x7fuy; 0x24uy; 0xe4uy; 0xc1uy |]

    test'
      FCVTZU
      (ThreeOperands (scalReg D3, scalReg D4, OprFbits 0x2fuy))
      [| 0x7fuy; 0x51uy; 0xfcuy; 0x83uy |]

  /// C4.6.9 Advanced SIMD scalar three different
  [<TestMethod>]
  member __.``[AArch64] Advanced SIMD scalar three different Parse Test``
    ()
    =
    test'
      SQDMLAL
      (ThreeOperands (scalReg D2, scalReg S30, scalReg S6))
      [| 0x5euy; 0xa6uy; 0x93uy; 0xc2uy |]

    test'
      SQDMLSL
      (ThreeOperands (scalReg S6, scalReg H0, scalReg H1))
      [| 0x5euy; 0x61uy; 0xb0uy; 0x06uy |]

    test'
      SQDMULL
      (ThreeOperands (scalReg D2, scalReg S18, scalReg S2))
      [| 0x5euy; 0xa2uy; 0xd2uy; 0x42uy |]

  /// C4.6.10 Advanced SIMD scalar three same
  [<TestMethod>]
  member __.``[AArch64] Advanced SIMD scalar three same Parse Test`` () =
    test'
      SQADD
      (ThreeOperands (scalReg B28, scalReg B15, scalReg B1))
      [| 0x5euy; 0x21uy; 0x0duy; 0xfcuy |]

    test'
      SQSUB
      (ThreeOperands (scalReg H5, scalReg H30, scalReg H3))
      [| 0x5euy; 0x63uy; 0x2fuy; 0xc5uy |]

    test'
      CMGT
      (ThreeOperands (scalReg D5, scalReg D6, scalReg D1))
      [| 0x5euy; 0xe1uy; 0x34uy; 0xc5uy |]

    test'
      CMGE
      (ThreeOperands (scalReg D10, scalReg D6, scalReg D7))
      [| 0x5euy; 0xe7uy; 0x3cuy; 0xcauy |]

    test'
      SSHL
      (ThreeOperands (scalReg D30, scalReg D0, scalReg D31))
      [| 0x5euy; 0xffuy; 0x44uy; 0x1euy |]

    test'
      SQSHL
      (ThreeOperands (scalReg B14, scalReg B24, scalReg B9))
      [| 0x5euy; 0x29uy; 0x4fuy; 0x0euy |]

    test'
      SRSHL
      (ThreeOperands (scalReg D17, scalReg D28, scalReg D30))
      [| 0x5euy; 0xfeuy; 0x57uy; 0x91uy |]

    test'
      SQRSHL
      (ThreeOperands (scalReg H14, scalReg H17, scalReg H14))
      [| 0x5euy; 0x6euy; 0x5euy; 0x2euy |]

    test'
      ADD
      (ThreeOperands (scalReg D24, scalReg D3, scalReg D24))
      [| 0x5euy; 0xf8uy; 0x84uy; 0x78uy |]

    test'
      CMTST
      (ThreeOperands (scalReg D10, scalReg D12, scalReg D28))
      [| 0x5euy; 0xfcuy; 0x8duy; 0x8auy |]

    test'
      SQDMULH
      (ThreeOperands (scalReg S16, scalReg S7, scalReg S1))
      [| 0x5euy; 0xa1uy; 0xb4uy; 0xf0uy |]

    test'
      FMULX
      (ThreeOperands (scalReg D12, scalReg D24, scalReg D1))
      [| 0x5euy; 0x61uy; 0xdfuy; 0x0cuy |]

    test'
      FCMEQ
      (ThreeOperands (scalReg S1, scalReg S6, scalReg S24))
      [| 0x5euy; 0x38uy; 0xe4uy; 0xc1uy |]

    test'
      FRECPS
      (ThreeOperands (scalReg D4, scalReg D2, scalReg D1))
      [| 0x5euy; 0x61uy; 0xfcuy; 0x44uy |]

    test'
      FRSQRTS
      (ThreeOperands (scalReg D24, scalReg D16, scalReg D1))
      [| 0x5euy; 0xe1uy; 0xfeuy; 0x18uy |]

    test'
      UQADD
      (ThreeOperands (scalReg H18, scalReg H8, scalReg H1))
      [| 0x7euy; 0x61uy; 0x0duy; 0x12uy |]

    test'
      UQSUB
      (ThreeOperands (scalReg B1, scalReg B12, scalReg B12))
      [| 0x7euy; 0x2cuy; 0x2duy; 0x81uy |]

    test'
      CMHI
      (ThreeOperands (scalReg D30, scalReg D5, scalReg D1))
      [| 0x7euy; 0xe1uy; 0x34uy; 0xbeuy |]

    test'
      CMHS
      (ThreeOperands (scalReg D18, scalReg D24, scalReg D3))
      [| 0x7euy; 0xe3uy; 0x3fuy; 0x12uy |]

    test'
      USHL
      (ThreeOperands (scalReg D1, scalReg D10, scalReg D3))
      [| 0x7euy; 0xe3uy; 0x45uy; 0x41uy |]

    test'
      UQSHL
      (ThreeOperands (scalReg B17, scalReg B16, scalReg B7))
      [| 0x7euy; 0x27uy; 0x4euy; 0x11uy |]

    test'
      URSHL
      (ThreeOperands (scalReg D3, scalReg D24, scalReg D1))
      [| 0x7euy; 0xe1uy; 0x57uy; 0x03uy |]

    test'
      UQRSHL
      (ThreeOperands (scalReg H24, scalReg H17, scalReg H7))
      [| 0x7euy; 0x67uy; 0x5euy; 0x38uy |]

    test'
      SUB
      (ThreeOperands (scalReg D31, scalReg D6, scalReg D10))
      [| 0x7euy; 0xeauy; 0x84uy; 0xdfuy |]

    test'
      CMEQ
      (ThreeOperands (scalReg D4, scalReg D17, scalReg D0))
      [| 0x7euy; 0xe0uy; 0x8euy; 0x24uy |]

    test'
      SQRDMULH
      (ThreeOperands (scalReg H10, scalReg H6, scalReg H1))
      [| 0x7euy; 0x61uy; 0xb4uy; 0xcauy |]

    test'
      SQRDMULH
      (ThreeOperands (scalReg S1, scalReg S8, scalReg S7))
      [| 0x7euy; 0xa7uy; 0xb5uy; 0x01uy |]

    test'
      FCMGE
      (ThreeOperands (scalReg D6, scalReg D16, scalReg D1))
      [| 0x7euy; 0x61uy; 0xe6uy; 0x06uy |]

    test'
      FACGE
      (ThreeOperands (scalReg S1, scalReg S2, scalReg S1))
      [| 0x7euy; 0x21uy; 0xecuy; 0x41uy |]

    test'
      FABD
      (ThreeOperands (scalReg S6, scalReg S17, scalReg S1))
      [| 0x7euy; 0xa1uy; 0xd6uy; 0x26uy |]

    test'
      FCMGT
      (ThreeOperands (scalReg D7, scalReg D20, scalReg D4))
      [| 0x7euy; 0xe4uy; 0xe6uy; 0x87uy |]

    test'
      FACGT
      (ThreeOperands (scalReg S19, scalReg S3, scalReg S5))
      [| 0x7euy; 0xa5uy; 0xecuy; 0x73uy |]

  /// C4.6.11 Advanced SIMD scalar two-scalReg miscellaneous
  [<TestMethod>]
  member __.``[AArch64] Advanced SIMD scalar two-reg misc Parse Test`` () =
    test'
      SUQADD
      (TwoOperands (scalReg S21, scalReg S29))
      [| 0x5euy; 0xa0uy; 0x3buy; 0xb5uy |]

    test'
      SQABS
      (TwoOperands (scalReg H1, scalReg H30))
      [| 0x5euy; 0x60uy; 0x7buy; 0xc1uy |]

    test'
      CMGT
      (ThreeOperands (scalReg D30, scalReg D15, OprImm 0L))
      [| 0x5euy; 0xe0uy; 0x89uy; 0xfeuy |]

    test'
      CMEQ
      (ThreeOperands (scalReg D20, scalReg D23, OprImm 0L))
      [| 0x5euy; 0xe0uy; 0x9auy; 0xf4uy |]

    test'
      CMLT
      (ThreeOperands (scalReg D28, scalReg D30, OprImm 0L))
      [| 0x5euy; 0xe0uy; 0xabuy; 0xdcuy |]

    test'
      ABS
      (TwoOperands (scalReg D17, scalReg D24))
      [| 0x5euy; 0xe0uy; 0xbbuy; 0x11uy |]

    test'
      SQXTN
      (TwoOperands (scalReg H7, scalReg S28))
      [| 0x5euy; 0x61uy; 0x4buy; 0x87uy |]

    test'
      FCVTNS
      (TwoOperands (scalReg D1, scalReg D24))
      [| 0x5euy; 0x61uy; 0xabuy; 0x01uy |]

    test'
      FCVTMS
      (TwoOperands (scalReg S22, scalReg S25))
      [| 0x5euy; 0x21uy; 0xbbuy; 0x36uy |]

    test'
      FCVTAS
      (TwoOperands (scalReg D31, scalReg D23))
      [| 0x5euy; 0x61uy; 0xcauy; 0xffuy |]

    test'
      SCVTF
      (TwoOperands (scalReg S10, scalReg S21))
      [| 0x5euy; 0x21uy; 0xdauy; 0xaauy |]

    test'
      FCMGT
      (ThreeOperands (scalReg S28, scalReg S21, OprFPImm 0.0))
      [| 0x5euy; 0xa0uy; 0xcauy; 0xbcuy |]

    test'
      FCMEQ
      (ThreeOperands (scalReg D25, scalReg D17, OprFPImm 0.0))
      [| 0x5euy; 0xe0uy; 0xdauy; 0x39uy |]

    test'
      FCMGT
      (ThreeOperands (scalReg D30, scalReg D15, OprFPImm 0.0))
      [| 0x5euy; 0xe0uy; 0xc9uy; 0xfeuy |]

    test'
      FCVTPS
      (TwoOperands (scalReg S28, scalReg S31))
      [| 0x5euy; 0xa1uy; 0xabuy; 0xfcuy |]

    test'
      FCVTZS
      (TwoOperands (scalReg D30, scalReg D15))
      [| 0x5euy; 0xe1uy; 0xb9uy; 0xfeuy |]

    test'
      FRECPE
      (TwoOperands (scalReg S22, scalReg S23))
      [| 0x5euy; 0xa1uy; 0xdauy; 0xf6uy |]

    test'
      FRECPX
      (TwoOperands (scalReg D31, scalReg D15))
      [| 0x5euy; 0xe1uy; 0xf9uy; 0xffuy |]

    test'
      USQADD
      (TwoOperands (scalReg S28, scalReg S19))
      [| 0x7euy; 0xa0uy; 0x3auy; 0x7cuy |]

    test'
      SQNEG
      (TwoOperands (scalReg H27, scalReg H10))
      [| 0x7euy; 0x60uy; 0x79uy; 0x5buy |]

    test'
      CMGE
      (ThreeOperands (scalReg D1, scalReg D20, OprImm 0L))
      [| 0x7euy; 0xe0uy; 0x8auy; 0x81uy |]

    test'
      CMLE
      (ThreeOperands (scalReg D24, scalReg D17, OprImm 0L))
      [| 0x7euy; 0xe0uy; 0x9auy; 0x38uy |]

    test'
      NEG
      (TwoOperands (scalReg D31, scalReg D11))
      [| 0x7euy; 0xe0uy; 0xb9uy; 0x7fuy |]

    test'
      SQXTUN
      (TwoOperands (scalReg S17, scalReg D16))
      [| 0x7euy; 0xa1uy; 0x2auy; 0x11uy |]

    test'
      UQXTN
      (TwoOperands (scalReg B1, scalReg H20))
      [| 0x7euy; 0x21uy; 0x4auy; 0x81uy |]

    test'
      FCVTXN
      (TwoOperands (scalReg S24, scalReg D23))
      [| 0x7euy; 0x61uy; 0x6auy; 0xf8uy |]

    test'
      FCVTNU
      (TwoOperands (scalReg S24, scalReg S23))
      [| 0x7euy; 0x21uy; 0xaauy; 0xf8uy |]

    test'
      FCVTMU
      (TwoOperands (scalReg D7, scalReg D0))
      [| 0x7euy; 0x61uy; 0xb8uy; 0x07uy |]

    test'
      FCVTAU
      (TwoOperands (scalReg S17, scalReg S16))
      [| 0x7euy; 0x21uy; 0xcauy; 0x11uy |]

    test'
      UCVTF
      (TwoOperands (scalReg D4, scalReg D2))
      [| 0x7euy; 0x61uy; 0xd8uy; 0x44uy |]

    test'
      FCMGE
      (ThreeOperands (scalReg S30, scalReg S23, OprFPImm 0.0))
      [| 0x7euy; 0xa0uy; 0xcauy; 0xfeuy |]

    test'
      FCMLE
      (ThreeOperands (scalReg D8, scalReg D6, OprFPImm 0.0))
      [| 0x7euy; 0xe0uy; 0xd8uy; 0xc8uy |]

    test'
      FCVTPU
      (TwoOperands (scalReg S1, scalReg S17))
      [| 0x7euy; 0xa1uy; 0xaauy; 0x21uy |]

    test'
      FCVTZU
      (TwoOperands (scalReg D3, scalReg D1))
      [| 0x7euy; 0xe1uy; 0xb8uy; 0x23uy |]

    test'
      FRSQRTE
      (TwoOperands (scalReg S21, scalReg S17))
      [| 0x7euy; 0xa1uy; 0xdauy; 0x35uy |]

    test'
      FRSQRTE
      (TwoOperands (scalReg D29, scalReg D21))
      [| 0x7euy; 0xe1uy; 0xdauy; 0xbduy |]

  /// C4.6.12 Advanced SIMD scalar x indexed element
  [<TestMethod>]
  member __.``[AArch64] Advanced SIMD scalar x indexed elem Parse Test`` () =
    test'
      SQDMLAL
      (ThreeOperands (
        scalReg D1,
        scalReg S17,
        OprSIMD (sVRegIdx V8 VecS 2uy)
      ))
      [| 0x5fuy; 0x88uy; 0x3auy; 0x21uy |]

    test'
      SQDMLSL
      (ThreeOperands (
        scalReg S26,
        scalReg H24,
        OprSIMD (sVRegIdx V6 VecH 7uy)
      ))
      [| 0x5fuy; 0x76uy; 0x7buy; 0x1auy |]

    test'
      SQDMULL
      (ThreeOperands (
        scalReg D7,
        scalReg S19,
        OprSIMD (sVRegIdx V12 VecS 3uy)
      ))
      [| 0x5fuy; 0xacuy; 0xbauy; 0x67uy |]

    test'
      SQDMULH
      (ThreeOperands (
        scalReg H3,
        scalReg H16,
        OprSIMD (sVRegIdx V14 VecH 3uy)
      ))
      [| 0x5fuy; 0x7euy; 0xc2uy; 0x03uy |]

    test'
      SQDMULH
      (ThreeOperands (
        scalReg S27,
        scalReg S27,
        OprSIMD (sVRegIdx V31 VecS 3uy)
      ))
      [| 0x5fuy; 0xbfuy; 0xcbuy; 0x7buy |]

    test'
      SQRDMULH
      (ThreeOperands (
        scalReg H28,
        scalReg H19,
        OprSIMD (sVRegIdx V15 VecH 7uy)
      ))
      [| 0x5fuy; 0x7fuy; 0xdauy; 0x7cuy |]

    test'
      FMLA
      (ThreeOperands (
        scalReg D3,
        scalReg D6,
        OprSIMD (sVRegIdx V19 VecD 1uy)
      ))
      [| 0x5fuy; 0xd3uy; 0x18uy; 0xc3uy |]

    test'
      FMLS
      (ThreeOperands (
        scalReg S2,
        scalReg S1,
        OprSIMD (sVRegIdx V16 VecS 3uy)
      ))
      [| 0x5fuy; 0xb0uy; 0x58uy; 0x22uy |]

    test'
      FMUL
      (ThreeOperands (
        scalReg D30,
        scalReg D3,
        OprSIMD (sVRegIdx V17 VecD 1uy)
      ))
      [| 0x5fuy; 0xd1uy; 0x98uy; 0x7euy |]

    test'
      FMULX
      (ThreeOperands (
        scalReg S25,
        scalReg S6,
        OprSIMD (sVRegIdx V30 VecS 1uy)
      ))
      [| 0x7fuy; 0xbeuy; 0x90uy; 0xd9uy |]

  /// C4.6.13 Advanced SIMD shift by immediate
  [<TestMethod>]
  member __.``[AArch64] Advanced SIMD shift by immediate Parse Test`` () =
    test'
      SSHR
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V14, SixteenB)),
        OprImm 3L
      ))
      [| 0x4fuy; 0x0duy; 0x05uy; 0xc5uy |]

    test'
      SSHR
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, EightH)),
        OprSIMD (SIMDVecReg (V14, EightH)),
        OprImm 0xBL
      ))
      [| 0x4fuy; 0x15uy; 0x05uy; 0xc5uy |]

    test'
      SSHR
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V14, FourS)),
        OprImm 0xBL
      ))
      [| 0x4fuy; 0x35uy; 0x05uy; 0xc5uy |]

    test'
      SSHR
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, TwoD)),
        OprSIMD (SIMDVecReg (V14, TwoD)),
        OprImm 0x2EL
      ))
      [| 0x4fuy; 0x52uy; 0x05uy; 0xc5uy |]

    test'
      SSRA
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V14, SixteenB)),
        OprImm 3L
      ))
      [| 0x4fuy; 0x0duy; 0x15uy; 0xc5uy |]

    test'
      SRSHR
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, EightH)),
        OprSIMD (SIMDVecReg (V14, EightH)),
        OprImm 0xBL
      ))
      [| 0x4fuy; 0x15uy; 0x25uy; 0xc5uy |]

    test'
      SRSRA
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V14, FourS)),
        OprImm 0xBL
      ))
      [| 0x4fuy; 0x35uy; 0x35uy; 0xc5uy |]

    test'
      SHL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V14, SixteenB)),
        OprImm 5L
      ))
      [| 0x4fuy; 0x0duy; 0x55uy; 0xc5uy |]

    test'
      SQSHL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V14, SixteenB)),
        OprImm 5L
      ))
      [| 0x4fuy; 0x0duy; 0x75uy; 0xc5uy |]

    test'
      SHRN2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V14, TwoD)),
        OprImm 0x12L
      ))
      [| 0x4fuy; 0x2euy; 0x85uy; 0xc5uy |]

    test'
      RSHRN2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V14, EightH)),
        OprImm 3L
      ))
      [| 0x4fuy; 0x0duy; 0x8duy; 0xc5uy |]

    test'
      SQSHRN2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V14, EightH)),
        OprImm 3L
      ))
      [| 0x4fuy; 0x0duy; 0x95uy; 0xc5uy |]

    test'
      SQRSHRN2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V14, EightH)),
        OprImm 3L
      ))
      [| 0x4fuy; 0x0duy; 0x9duy; 0xc5uy |]

    test'
      SSHLL2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, EightH)),
        OprSIMD (SIMDVecReg (V14, SixteenB)),
        OprImm 5L
      ))
      [| 0x4fuy; 0x0duy; 0xa5uy; 0xc5uy |]

    test'
      SCVTF
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V13, TwoD)),
        OprSIMD (SIMDVecReg (V10, TwoD)),
        OprFbits 0x31uy
      ))
      [| 0x4fuy; 0x4fuy; 0xe5uy; 0x4duy |]

    test'
      FCVTZS
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V13, TwoD)),
        OprSIMD (SIMDVecReg (V10, TwoD)),
        OprFbits 0x31uy
      ))
      [| 0x4fuy; 0x4fuy; 0xfduy; 0x4duy |]

    test'
      USHR
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V14, SixteenB)),
        OprImm 3L
      ))
      [| 0x6fuy; 0x0duy; 0x05uy; 0xc5uy |]

    test'
      USRA
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V14, SixteenB)),
        OprImm 3L
      ))
      [| 0x6fuy; 0x0duy; 0x15uy; 0xc5uy |]

    test'
      URSHR
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V14, SixteenB)),
        OprImm 3L
      ))
      [| 0x6fuy; 0x0duy; 0x25uy; 0xc5uy |]

    test'
      URSRA
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V14, SixteenB)),
        OprImm 3L
      ))
      [| 0x6fuy; 0x0duy; 0x35uy; 0xc5uy |]

    test'
      SRI
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V14, SixteenB)),
        OprImm 3L
      ))
      [| 0x6fuy; 0x0duy; 0x45uy; 0xc5uy |]

    test'
      SLI
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V14, SixteenB)),
        OprImm 5L
      ))
      [| 0x6fuy; 0x0duy; 0x55uy; 0xc5uy |]

    test'
      SQSHLU
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V14, SixteenB)),
        OprImm 5L
      ))
      [| 0x6fuy; 0x0duy; 0x65uy; 0xc5uy |]

    test'
      UQSHL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V14, SixteenB)),
        OprImm 5L
      ))
      [| 0x6fuy; 0x0duy; 0x75uy; 0xc5uy |]

    test'
      SQSHRUN2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V14, TwoD)),
        OprImm 0x17L
      ))
      [| 0x6fuy; 0x29uy; 0x85uy; 0xc5uy |]

    test'
      SQRSHRUN2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, EightH)),
        OprSIMD (SIMDVecReg (V14, FourS)),
        OprImm 5L
      ))
      [| 0x6fuy; 0x1buy; 0x8duy; 0xc5uy |]

    test'
      UQSHRN2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V14, TwoD)),
        OprImm 0x1AL
      ))
      [| 0x6fuy; 0x26uy; 0x95uy; 0xc5uy |]

    test'
      UQRSHRN2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, EightH)),
        OprSIMD (SIMDVecReg (V14, FourS)),
        OprImm 1L
      ))
      [| 0x6fuy; 0x1fuy; 0x9duy; 0xc5uy |]

    test'
      USHLL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V27, TwoD)),
        OprSIMD (SIMDVecReg (V5, TwoS)),
        OprImm 0xDL
      ))
      [| 0x2fuy; 0x2duy; 0xa4uy; 0xbbuy |]

    test'
      UCVTF
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V14, FourS)),
        OprFbits 7uy
      ))
      [| 0x6fuy; 0x39uy; 0xe5uy; 0xc5uy |]

    test'
      FCVTZU
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V14, FourS)),
        OprFbits 0x1Auy
      ))
      [| 0x6fuy; 0x26uy; 0xfduy; 0xc5uy |]

  /// C4.6.14 Advanced SIMD table lookup
  [<TestMethod>]
  member __.``[AArch64] Advanced SIMD table lookup Parse Test`` () =
    test'
      TBL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V1, SixteenB)),
        OprSIMDList [
          SIMDVecReg (V6, SixteenB); SIMDVecReg (V7, SixteenB) ],
        OprSIMD (SIMDVecReg (V3, SixteenB))
      ))
      [| 0x4euy; 0x03uy; 0x20uy; 0xc1uy |]

    test'
      TBL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V9, EightB)),
        OprSIMDList [
          SIMDVecReg (V22, SixteenB);
          SIMDVecReg (V23, SixteenB);
          SIMDVecReg (V24, SixteenB) ],
        OprSIMD (SIMDVecReg (V3, EightB))
      ))
      [| 0x0euy; 0x03uy; 0x42uy; 0xc9uy |]

    test'
      TBL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMDList [
          SIMDVecReg (V31, SixteenB);
          SIMDVecReg (V0, SixteenB);
          SIMDVecReg (V1, SixteenB);
          SIMDVecReg (V2, SixteenB) ],
        OprSIMD (SIMDVecReg (V3, SixteenB))
      ))
      [| 0x4euy; 0x03uy; 0x63uy; 0xe5uy |]

    test'
      TBL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V17, EightB)),
        OprSIMDList [ SIMDVecReg (V27, SixteenB) ],
        OprSIMD (SIMDVecReg (V3, EightB))
      ))
      [| 0x0euy; 0x03uy; 0x03uy; 0x71uy |]

    test'
      TBX
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V28, EightB)),
        OprSIMDList [
          SIMDVecReg (V7, SixteenB); SIMDVecReg (V8, SixteenB) ],
        OprSIMD (SIMDVecReg (V25, EightB))
      ))
      [| 0x0euy; 0x19uy; 0x30uy; 0xfcuy |]

    test'
      TBX
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V28, SixteenB)),
        OprSIMDList [
          SIMDVecReg (V7, SixteenB);
          SIMDVecReg (V8, SixteenB);
          SIMDVecReg (V9, SixteenB) ],
        OprSIMD (SIMDVecReg (V25, SixteenB))
      ))
      [| 0x4euy; 0x19uy; 0x50uy; 0xfcuy |]

    test'
      TBX
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V28, EightB)),
        OprSIMDList [
          SIMDVecReg (V7, SixteenB);
          SIMDVecReg (V8, SixteenB);
          SIMDVecReg (V9, SixteenB);
          SIMDVecReg (V10, SixteenB) ],
        OprSIMD (SIMDVecReg (V25, EightB))
      ))
      [| 0x0euy; 0x19uy; 0x70uy; 0xfcuy |]

    test'
      TBX
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V28, SixteenB)),
        OprSIMDList [ SIMDVecReg (V7, SixteenB) ],
        OprSIMD (SIMDVecReg (V25, SixteenB))
      ))
      [| 0x4euy; 0x19uy; 0x10uy; 0xfcuy |]

  /// C4.6.15 Advanced SIMD three different
  [<TestMethod>]
  member __.``[AArch64] Advanced SIMD three different Parse Test`` () =
    test'
      SADDL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V26, FourS)),
        OprSIMD (SIMDVecReg (V28, FourH)),
        OprSIMD (SIMDVecReg (V11, FourH))
      ))
      [| 0x0euy; 0x6buy; 0x03uy; 0x9auy |]

    test'
      SADDL2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, TwoD)),
        OprSIMD (SIMDVecReg (V25, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x4euy; 0xa5uy; 0x03uy; 0x25uy |]

    test'
      SADDW
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V26, EightH)),
        OprSIMD (SIMDVecReg (V21, EightH)),
        OprSIMD (SIMDVecReg (V7, EightB))
      ))
      [| 0x0euy; 0x27uy; 0x12uy; 0xbauy |]

    test'
      SADDW2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V25, FourS)),
        OprSIMD (SIMDVecReg (V3, FourS)),
        OprSIMD (SIMDVecReg (V3, EightH))
      ))
      [| 0x4euy; 0x63uy; 0x10uy; 0x79uy |]

    test'
      SSUBL2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V25, FourS)),
        OprSIMD (SIMDVecReg (V3, EightH)),
        OprSIMD (SIMDVecReg (V3, EightH))
      ))
      [| 0x4euy; 0x63uy; 0x20uy; 0x79uy |]

    test'
      SSUBW2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V25, FourS)),
        OprSIMD (SIMDVecReg (V3, FourS)),
        OprSIMD (SIMDVecReg (V3, EightH))
      ))
      [| 0x4euy; 0x63uy; 0x30uy; 0x79uy |]

    test'
      ADDHN2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V25, EightH)),
        OprSIMD (SIMDVecReg (V3, FourS)),
        OprSIMD (SIMDVecReg (V3, FourS))
      ))
      [| 0x4euy; 0x63uy; 0x40uy; 0x79uy |]

    test'
      SABAL2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V25, FourS)),
        OprSIMD (SIMDVecReg (V3, EightH)),
        OprSIMD (SIMDVecReg (V3, EightH))
      ))
      [| 0x4euy; 0x63uy; 0x50uy; 0x79uy |]

    test'
      SUBHN2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V25, EightH)),
        OprSIMD (SIMDVecReg (V3, FourS)),
        OprSIMD (SIMDVecReg (V3, FourS))
      ))
      [| 0x4euy; 0x63uy; 0x60uy; 0x79uy |]

    test'
      SABDL2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V25, FourS)),
        OprSIMD (SIMDVecReg (V3, EightH)),
        OprSIMD (SIMDVecReg (V3, EightH))
      ))
      [| 0x4euy; 0x63uy; 0x70uy; 0x79uy |]

    test'
      SMLAL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V24, TwoD)),
        OprSIMD (SIMDVecReg (V18, TwoS)),
        OprSIMD (SIMDVecReg (V6, TwoS))
      ))
      [| 0x0euy; 0xa6uy; 0x82uy; 0x58uy |]

    test'
      SQDMLAL2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V26, TwoD)),
        OprSIMD (SIMDVecReg (V23, FourS)),
        OprSIMD (SIMDVecReg (V6, FourS))
      ))
      [| 0x4euy; 0xa6uy; 0x92uy; 0xfauy |]

    test'
      SMLSL2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V12, FourS)),
        OprSIMD (SIMDVecReg (V17, EightH)),
        OprSIMD (SIMDVecReg (V6, EightH))
      ))
      [| 0x4euy; 0x66uy; 0xa2uy; 0x2cuy |]

    test'
      SQDMLSL2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V3, TwoD)),
        OprSIMD (SIMDVecReg (V22, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x4euy; 0xa5uy; 0xb2uy; 0xc3uy |]

    test'
      SMULL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V28, FourS)),
        OprSIMD (SIMDVecReg (V11, FourH)),
        OprSIMD (SIMDVecReg (V5, FourH))
      ))
      [| 0x0euy; 0x65uy; 0xc1uy; 0x7cuy |]

    test'
      SQDMULL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V25, TwoD)),
        OprSIMD (SIMDVecReg (V3, TwoS)),
        OprSIMD (SIMDVecReg (V8, TwoS))
      ))
      [| 0x0euy; 0xa8uy; 0xd0uy; 0x79uy |]

    test'
      PMULL2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, OneQ)),
        OprSIMD (SIMDVecReg (V18, TwoD)),
        OprSIMD (SIMDVecReg (V3, TwoD))
      ))
      [| 0x4euy; 0xe3uy; 0xe2uy; 0x45uy |]

    test'
      UADDL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V11, EightH)),
        OprSIMD (SIMDVecReg (V19, EightB)),
        OprSIMD (SIMDVecReg (V14, EightB))
      ))
      [| 0x2euy; 0x2euy; 0x02uy; 0x6buy |]

    test'
      UADDW2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V18, TwoD)),
        OprSIMD (SIMDVecReg (V18, TwoD)),
        OprSIMD (SIMDVecReg (V14, FourS))
      ))
      [| 0x6euy; 0xaeuy; 0x12uy; 0x52uy |]

    test'
      USUBL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V29, TwoD)),
        OprSIMD (SIMDVecReg (V21, TwoS)),
        OprSIMD (SIMDVecReg (V1, TwoS))
      ))
      [| 0x2euy; 0xa1uy; 0x22uy; 0xbduy |]

    test'
      USUBW2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V27, EightH)),
        OprSIMD (SIMDVecReg (V28, EightH)),
        OprSIMD (SIMDVecReg (V7, SixteenB))
      ))
      [| 0x6euy; 0x27uy; 0x33uy; 0x9buy |]

    test'
      RADDHN2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V27, SixteenB)),
        OprSIMD (SIMDVecReg (V28, EightH)),
        OprSIMD (SIMDVecReg (V7, EightH))
      ))
      [| 0x6euy; 0x27uy; 0x43uy; 0x9buy |]

    test'
      UABAL2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V27, EightH)),
        OprSIMD (SIMDVecReg (V28, SixteenB)),
        OprSIMD (SIMDVecReg (V7, SixteenB))
      ))
      [| 0x6euy; 0x27uy; 0x53uy; 0x9buy |]

    test'
      RSUBHN2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V27, SixteenB)),
        OprSIMD (SIMDVecReg (V28, EightH)),
        OprSIMD (SIMDVecReg (V7, EightH))
      ))
      [| 0x6euy; 0x27uy; 0x63uy; 0x9buy |]

    test'
      UABDL2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V27, EightH)),
        OprSIMD (SIMDVecReg (V28, SixteenB)),
        OprSIMD (SIMDVecReg (V7, SixteenB))
      ))
      [| 0x6euy; 0x27uy; 0x73uy; 0x9buy |]

    test'
      UMLAL2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V27, EightH)),
        OprSIMD (SIMDVecReg (V28, SixteenB)),
        OprSIMD (SIMDVecReg (V7, SixteenB))
      ))
      [| 0x6euy; 0x27uy; 0x83uy; 0x9buy |]

    test'
      UMLSL2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V27, EightH)),
        OprSIMD (SIMDVecReg (V28, SixteenB)),
        OprSIMD (SIMDVecReg (V7, SixteenB))
      ))
      [| 0x6euy; 0x27uy; 0xa3uy; 0x9buy |]

    test'
      UMULL2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V27, EightH)),
        OprSIMD (SIMDVecReg (V28, SixteenB)),
        OprSIMD (SIMDVecReg (V7, SixteenB))
      ))
      [| 0x6euy; 0x27uy; 0xc3uy; 0x9buy |]

  /// C4.6.16 Advanced SIMD three same
  [<TestMethod>]
  member __.``[AArch64] Advanced SIMD three same Parse Test`` () =
    test'
      SHADD
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB))
      ))
      [| 0x4euy; 0x25uy; 0x04uy; 0xb5uy |]

    test'
      SQADD
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH))
      ))
      [| 0x4euy; 0x65uy; 0x0cuy; 0xb5uy |]

    test'
      SRHADD
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x4euy; 0xa5uy; 0x14uy; 0xb5uy |]

    test'
      SHSUB
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB))
      ))
      [| 0x4euy; 0x25uy; 0x24uy; 0xb5uy |]

    test'
      SQSUB
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH))
      ))
      [| 0x4euy; 0x65uy; 0x2cuy; 0xb5uy |]

    test'
      CMGT
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x4euy; 0xa5uy; 0x34uy; 0xb5uy |]

    test'
      CMGE
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB))
      ))
      [| 0x4euy; 0x25uy; 0x3cuy; 0xb5uy |]

    test'
      SSHL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH))
      ))
      [| 0x4euy; 0x65uy; 0x44uy; 0xb5uy |]

    test'
      SQSHL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x4euy; 0xa5uy; 0x4cuy; 0xb5uy |]

    test'
      SRSHL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB))
      ))
      [| 0x4euy; 0x25uy; 0x54uy; 0xb5uy |]

    test'
      SQRSHL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH))
      ))
      [| 0x4euy; 0x65uy; 0x5cuy; 0xb5uy |]

    test'
      SMAX
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x4euy; 0xa5uy; 0x64uy; 0xb5uy |]

    test'
      SMIN
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB))
      ))
      [| 0x4euy; 0x25uy; 0x6cuy; 0xb5uy |]

    test'
      SABD
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH))
      ))
      [| 0x4euy; 0x65uy; 0x74uy; 0xb5uy |]

    test'
      SABA
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x4euy; 0xa5uy; 0x7cuy; 0xb5uy |]

    test'
      ADD
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB))
      ))
      [| 0x4euy; 0x25uy; 0x84uy; 0xb5uy |]

    test'
      CMTST
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH))
      ))
      [| 0x4euy; 0x65uy; 0x8cuy; 0xb5uy |]

    test'
      MLA
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x4euy; 0xa5uy; 0x94uy; 0xb5uy |]

    test'
      MUL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB))
      ))
      [| 0x4euy; 0x25uy; 0x9cuy; 0xb5uy |]

    test'
      SMAXP
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH))
      ))
      [| 0x4euy; 0x65uy; 0xa4uy; 0xb5uy |]

    test'
      SMINP
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x4euy; 0xa5uy; 0xacuy; 0xb5uy |]

    test'
      SQDMULH
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x4euy; 0xa5uy; 0xb4uy; 0xb5uy |]

    test'
      ADDP
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH))
      ))
      [| 0x4euy; 0x65uy; 0xbcuy; 0xb5uy |]

    test'
      FMAXNM
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x4euy; 0x25uy; 0xc6uy; 0xb5uy |]

    test'
      FMLA
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, TwoD)),
        OprSIMD (SIMDVecReg (V13, TwoD)),
        OprSIMD (SIMDVecReg (V5, TwoD))
      ))
      [| 0x4euy; 0x65uy; 0xcduy; 0xb5uy |]

    test'
      FADD
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x4euy; 0x25uy; 0xd4uy; 0xb5uy |]

    test'
      FMULX
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V17, TwoD)),
        OprSIMD (SIMDVecReg (V5, TwoD)),
        OprSIMD (SIMDVecReg (V5, TwoD))
      ))
      [| 0x4euy; 0x65uy; 0xdcuy; 0xb1uy |]

    test'
      FCMEQ
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V2, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x4euy; 0x25uy; 0xe4uy; 0x55uy |]

    test'
      FMAX
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, TwoD)),
        OprSIMD (SIMDVecReg (V13, TwoD)),
        OprSIMD (SIMDVecReg (V5, TwoD))
      ))
      [| 0x4euy; 0x65uy; 0xf5uy; 0xb5uy |]

    test'
      FRECPS
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V13, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x4euy; 0x25uy; 0xfduy; 0xb5uy |]

    test'
      AND
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V17, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB))
      ))
      [| 0x4euy; 0x25uy; 0x1cuy; 0xb1uy |]

    test'
      BIC
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V25, SixteenB)),
        OprSIMD (SIMDVecReg (V21, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB))
      ))
      [| 0x4euy; 0x65uy; 0x1euy; 0xb9uy |]

    test'
      FMINNM
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V29, FourS)),
        OprSIMD (SIMDVecReg (V1, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x4euy; 0xa5uy; 0xc4uy; 0x3duy |]

    test'
      FMLS
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V20, TwoD)),
        OprSIMD (SIMDVecReg (V29, TwoD)),
        OprSIMD (SIMDVecReg (V5, TwoD))
      ))
      [| 0x4euy; 0xe5uy; 0xcfuy; 0xb4uy |]

    test'
      FSUB
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x4euy; 0xa5uy; 0xd4uy; 0xb5uy |]

    test'
      FMIN
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, TwoD)),
        OprSIMD (SIMDVecReg (V1, TwoD)),
        OprSIMD (SIMDVecReg (V5, TwoD))
      ))
      [| 0x4euy; 0xe5uy; 0xf4uy; 0x25uy |]

    test'
      FRSQRTS
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V29, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x4euy; 0xa5uy; 0xfcuy; 0xbduy |]

    test'
      MOV
      (TwoOperands (
        OprSIMD (SIMDVecReg (V21, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB))
      ))
      [| 0x4euy; 0xa5uy; 0x1cuy; 0xb5uy |]

    test'
      ORN
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V9, SixteenB)),
        OprSIMD (SIMDVecReg (V13, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB))
      ))
      [| 0x4euy; 0xe5uy; 0x1duy; 0xa9uy |]

    test'
      UHADD
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB))
      ))
      [| 0x6euy; 0x25uy; 0x04uy; 0xb5uy |]

    test'
      UQADD
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH))
      ))
      [| 0x6euy; 0x65uy; 0x0cuy; 0xb5uy |]

    test'
      URHADD
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x6euy; 0xa5uy; 0x14uy; 0xb5uy |]

    test'
      UHSUB
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB))
      ))
      [| 0x6euy; 0x25uy; 0x24uy; 0xb5uy |]

    test'
      UQSUB
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH))
      ))
      [| 0x6euy; 0x65uy; 0x2cuy; 0xb5uy |]

    test'
      CMHI
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x6euy; 0xa5uy; 0x34uy; 0xb5uy |]

    test'
      CMHS
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB))
      ))
      [| 0x6euy; 0x25uy; 0x3cuy; 0xb5uy |]

    test'
      USHL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH))
      ))
      [| 0x6euy; 0x65uy; 0x44uy; 0xb5uy |]

    test'
      UQSHL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x6euy; 0xa5uy; 0x4cuy; 0xb5uy |]

    test'
      URSHL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB))
      ))
      [| 0x6euy; 0x25uy; 0x54uy; 0xb5uy |]

    test'
      UQRSHL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH))
      ))
      [| 0x6euy; 0x65uy; 0x5cuy; 0xb5uy |]

    test'
      UMAX
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x6euy; 0xa5uy; 0x64uy; 0xb5uy |]

    test'
      UMIN
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB))
      ))
      [| 0x6euy; 0x25uy; 0x6cuy; 0xb5uy |]

    test'
      UABD
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH))
      ))
      [| 0x6euy; 0x65uy; 0x74uy; 0xb5uy |]

    test'
      UABA
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x6euy; 0xa5uy; 0x7cuy; 0xb5uy |]

    test'
      SUB
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB))
      ))
      [| 0x6euy; 0x25uy; 0x84uy; 0xb5uy |]

    test'
      CMEQ
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH))
      ))
      [| 0x6euy; 0x65uy; 0x8cuy; 0xb5uy |]

    test'
      MLS
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x6euy; 0xa5uy; 0x94uy; 0xb5uy |]

    test'
      PMUL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB))
      ))
      [| 0x6euy; 0x25uy; 0x9cuy; 0xb5uy |]

    test'
      UMAXP
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH))
      ))
      [| 0x6euy; 0x65uy; 0xa4uy; 0xb5uy |]

    test'
      UMINP
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x6euy; 0xa5uy; 0xacuy; 0xb5uy |]

    test'
      SQRDMULH
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH)),
        OprSIMD (SIMDVecReg (V5, EightH))
      ))
      [| 0x6euy; 0x65uy; 0xb4uy; 0xb5uy |]

    test'
      FMAXNMP
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x6euy; 0x25uy; 0xc4uy; 0xb5uy |]

    test'
      FADDP
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, TwoD)),
        OprSIMD (SIMDVecReg (V5, TwoD)),
        OprSIMD (SIMDVecReg (V5, TwoD))
      ))
      [| 0x6euy; 0x65uy; 0xd4uy; 0xb5uy |]

    test'
      FMUL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x6euy; 0x25uy; 0xdcuy; 0xb5uy |]

    test'
      FCMGE
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, TwoD)),
        OprSIMD (SIMDVecReg (V5, TwoD)),
        OprSIMD (SIMDVecReg (V5, TwoD))
      ))
      [| 0x6euy; 0x65uy; 0xe4uy; 0xb5uy |]

    test'
      FACGE
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x6euy; 0x25uy; 0xecuy; 0xb5uy |]

    test'
      FMAXP
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, TwoD)),
        OprSIMD (SIMDVecReg (V5, TwoD)),
        OprSIMD (SIMDVecReg (V5, TwoD))
      ))
      [| 0x6euy; 0x65uy; 0xf4uy; 0xb5uy |]

    test'
      FDIV
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x6euy; 0x25uy; 0xfcuy; 0xb5uy |]

    test'
      EOR
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB))
      ))
      [| 0x6euy; 0x25uy; 0x1cuy; 0xb5uy |]

    test'
      BSL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB))
      ))
      [| 0x6euy; 0x65uy; 0x1cuy; 0xb5uy |]

    test'
      FMINNMP
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x6euy; 0xa5uy; 0xc4uy; 0xb5uy |]

    test'
      FABD
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, TwoD)),
        OprSIMD (SIMDVecReg (V5, TwoD)),
        OprSIMD (SIMDVecReg (V5, TwoD))
      ))
      [| 0x6euy; 0xe5uy; 0xd4uy; 0xb5uy |]

    test'
      FCMGT
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x6euy; 0xa5uy; 0xe4uy; 0xb5uy |]

    test'
      FACGT
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, TwoD)),
        OprSIMD (SIMDVecReg (V5, TwoD)),
        OprSIMD (SIMDVecReg (V5, TwoD))
      ))
      [| 0x6euy; 0xe5uy; 0xecuy; 0xb5uy |]

    test'
      FMINP
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x6euy; 0xa5uy; 0xf4uy; 0xb5uy |]

    test'
      BIT
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB))
      ))
      [| 0x6euy; 0xa5uy; 0x1cuy; 0xb5uy |]

    test'
      BIF
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB))
      ))
      [| 0x6euy; 0xe5uy; 0x1cuy; 0xb5uy |]

  /// C4.6.17 Advanced SIMD two-register miscellaneous
  [<TestMethod>]
  member __.``[AArch64] Advanced SIMD two-reg miscellaneous Parse Test`` () =
    test'
      REV64
      (TwoOperands (
        OprSIMD (SIMDVecReg (V3, EightH)),
        OprSIMD (SIMDVecReg (V12, EightH))
      ))
      [| 0x4euy; 0x60uy; 0x09uy; 0x83uy |]

    test'
      REV16
      (TwoOperands (
        OprSIMD (SIMDVecReg (V18, SixteenB)),
        OprSIMD (SIMDVecReg (V5, SixteenB))
      ))
      [| 0x4euy; 0x20uy; 0x18uy; 0xb2uy |]

    test'
      SADDLP
      (TwoOperands (
        OprSIMD (SIMDVecReg (V3, FourS)),
        OprSIMD (SIMDVecReg (V12, EightH))
      ))
      [| 0x4euy; 0x60uy; 0x29uy; 0x83uy |]

    test'
      SUQADD
      (TwoOperands (
        OprSIMD (SIMDVecReg (V19, EightH)),
        OprSIMD (SIMDVecReg (V17, EightH))
      ))
      [| 0x4euy; 0x60uy; 0x3auy; 0x33uy |]

    test'
      CLS
      (TwoOperands (
        OprSIMD (SIMDVecReg (V28, FourS)),
        OprSIMD (SIMDVecReg (V3, FourS))
      ))
      [| 0x4euy; 0xa0uy; 0x48uy; 0x7cuy |]

    test'
      SADDLP
      (TwoOperands (
        OprSIMD (SIMDVecReg (V13, OneD)),
        OprSIMD (SIMDVecReg (V6, TwoS))
      ))
      [| 0x0euy; 0xa0uy; 0x28uy; 0xcduy |]

    test'
      SQABS
      (TwoOperands (
        OprSIMD (SIMDVecReg (V6, TwoD)),
        OprSIMD (SIMDVecReg (V18, TwoD))
      ))
      [| 0x4euy; 0xe0uy; 0x7auy; 0x46uy |]

    test'
      CMGT
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V7, SixteenB)),
        OprSIMD (SIMDVecReg (V3, SixteenB)),
        OprImm 0L
      ))
      [| 0x4euy; 0x20uy; 0x88uy; 0x67uy |]

    test'
      CMEQ
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V25, FourH)),
        OprSIMD (SIMDVecReg (V3, FourH)),
        OprImm 0L
      ))
      [| 0x0euy; 0x60uy; 0x98uy; 0x79uy |]

    test'
      CMLT
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V1, FourS)),
        OprSIMD (SIMDVecReg (V2, FourS)),
        OprImm 0L
      ))
      [| 0x4euy; 0xa0uy; 0xa8uy; 0x41uy |]

    test'
      ABS
      (TwoOperands (
        OprSIMD (SIMDVecReg (V29, SixteenB)),
        OprSIMD (SIMDVecReg (V27, SixteenB))
      ))
      [| 0x4euy; 0x20uy; 0xbbuy; 0x7duy |]

    test'
      XTN
      (TwoOperands (
        OprSIMD (SIMDVecReg (V25, TwoS)),
        OprSIMD (SIMDVecReg (V5, TwoD))
      ))
      [| 0x0euy; 0xa1uy; 0x28uy; 0xb9uy |]

    test'
      XTN2
      (TwoOperands (
        OprSIMD (SIMDVecReg (V24, FourS)),
        OprSIMD (SIMDVecReg (V7, TwoD))
      ))
      [| 0x4euy; 0xa1uy; 0x28uy; 0xf8uy |]

    test'
      SQXTN
      (TwoOperands (
        OprSIMD (SIMDVecReg (V3, EightB)),
        OprSIMD (SIMDVecReg (V6, EightH))
      ))
      [| 0x0euy; 0x21uy; 0x48uy; 0xc3uy |]


    test'
      SQXTN2
      (TwoOperands (
        OprSIMD (SIMDVecReg (V5, SixteenB)),
        OprSIMD (SIMDVecReg (V10, EightH))
      ))
      [| 0x4euy; 0x21uy; 0x49uy; 0x45uy |]

    test'
      FCVTN
      (TwoOperands (
        OprSIMD (SIMDVecReg (V5, TwoS)),
        OprSIMD (SIMDVecReg (V4, TwoD))
      ))
      [| 0x0euy; 0x61uy; 0x68uy; 0x85uy |]

    test'
      FCVTN2
      (TwoOperands (
        OprSIMD (SIMDVecReg (V24, EightH)),
        OprSIMD (SIMDVecReg (V7, FourS))
      ))
      [| 0x4euy; 0x21uy; 0x68uy; 0xf8uy |]

    test'
      FCVTL
      (TwoOperands (
        OprSIMD (SIMDVecReg (V28, FourS)),
        OprSIMD (SIMDVecReg (V19, FourH))
      ))
      [| 0x0euy; 0x21uy; 0x7auy; 0x7cuy |]

    test'
      FCVTL2
      (TwoOperands (
        OprSIMD (SIMDVecReg (V3, TwoD)),
        OprSIMD (SIMDVecReg (V26, FourS))
      ))
      [| 0x4euy; 0x61uy; 0x7buy; 0x43uy |]

    test'
      FRINTN
      (TwoOperands (
        OprSIMD (SIMDVecReg (V24, TwoD)),
        OprSIMD (SIMDVecReg (V5, TwoD))
      ))
      [| 0x4euy; 0x61uy; 0x88uy; 0xb8uy |]

    test'
      FRINTM
      (TwoOperands (
        OprSIMD (SIMDVecReg (V5, TwoS)),
        OprSIMD (SIMDVecReg (V3, TwoS))
      ))
      [| 0x0euy; 0x21uy; 0x98uy; 0x65uy |]

    test'
      FCVTNS
      (TwoOperands (
        OprSIMD (SIMDVecReg (V13, FourS)),
        OprSIMD (SIMDVecReg (V3, FourS))
      ))
      [| 0x4euy; 0x21uy; 0xa8uy; 0x6duy |]

    test'
      FCVTMS
      (TwoOperands (
        OprSIMD (SIMDVecReg (V30, TwoS)),
        OprSIMD (SIMDVecReg (V3, TwoS))
      ))
      [| 0x0euy; 0x21uy; 0xb8uy; 0x7euy |]

    test'
      FCVTAS
      (TwoOperands (
        OprSIMD (SIMDVecReg (V22, TwoD)),
        OprSIMD (SIMDVecReg (V3, TwoD))
      ))
      [| 0x4euy; 0x61uy; 0xc8uy; 0x76uy |]

    test'
      SCVTF
      (TwoOperands (
        OprSIMD (SIMDVecReg (V18, FourS)),
        OprSIMD (SIMDVecReg (V4, FourS))
      ))
      [| 0x4euy; 0x21uy; 0xd8uy; 0x92uy |]

    test'
      FCMGT
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V29, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprFPImm 0.0
      ))
      [| 0x4euy; 0xa0uy; 0xc8uy; 0xbduy |]

    test'
      FCMEQ
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V30, TwoS)),
        OprSIMD (SIMDVecReg (V1, TwoS)),
        OprFPImm 0.0
      ))
      [| 0x0euy; 0xa0uy; 0xd8uy; 0x3euy |]

    test'
      FCMLT
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V25, TwoD)),
        OprSIMD (SIMDVecReg (V9, TwoD)),
        OprFPImm 0.0
      ))
      [| 0x4euy; 0xe0uy; 0xe9uy; 0x39uy |]

    test'
      FABS
      (TwoOperands (
        OprSIMD (SIMDVecReg (V14, FourS)),
        OprSIMD (SIMDVecReg (V4, FourS))
      ))
      [| 0x4euy; 0xa0uy; 0xf8uy; 0x8euy |]

    test'
      FRINTP
      (TwoOperands (
        OprSIMD (SIMDVecReg (V22, TwoS)),
        OprSIMD (SIMDVecReg (V4, TwoS))
      ))
      [| 0x0euy; 0xa1uy; 0x88uy; 0x96uy |]

    test'
      FRINTZ
      (TwoOperands (
        OprSIMD (SIMDVecReg (V9, TwoD)),
        OprSIMD (SIMDVecReg (V2, TwoD))
      ))
      [| 0x4euy; 0xe1uy; 0x98uy; 0x49uy |]

    test'
      FCVTPS
      (TwoOperands (
        OprSIMD (SIMDVecReg (V3, FourS)),
        OprSIMD (SIMDVecReg (V22, FourS))
      ))
      [| 0x4euy; 0xa1uy; 0xaauy; 0xc3uy |]

    test'
      FCVTZS
      (TwoOperands (
        OprSIMD (SIMDVecReg (V26, TwoS)),
        OprSIMD (SIMDVecReg (V19, TwoS))
      ))
      [| 0x0euy; 0xa1uy; 0xbauy; 0x7auy |]

    test'
      URECPE
      (TwoOperands (
        OprSIMD (SIMDVecReg (V7, TwoS)),
        OprSIMD (SIMDVecReg (V6, TwoS))
      ))
      [| 0x0euy; 0xa1uy; 0xc8uy; 0xc7uy |]

    test'
      FRECPE
      (TwoOperands (
        OprSIMD (SIMDVecReg (V3, TwoD)),
        OprSIMD (SIMDVecReg (V4, TwoD))
      ))
      [| 0x4euy; 0xe1uy; 0xd8uy; 0x83uy |]

    test'
      REV32
      (TwoOperands (
        OprSIMD (SIMDVecReg (V30, EightH)),
        OprSIMD (SIMDVecReg (V1, EightH))
      ))
      [| 0x6euy; 0x60uy; 0x08uy; 0x3euy |]

    test'
      UADDLP
      (TwoOperands (
        OprSIMD (SIMDVecReg (V28, TwoD)),
        OprSIMD (SIMDVecReg (V7, FourS))
      ))
      [| 0x6euy; 0xa0uy; 0x28uy; 0xfcuy |]

    test'
      USQADD
      (TwoOperands (
        OprSIMD (SIMDVecReg (V3, TwoD)),
        OprSIMD (SIMDVecReg (V4, TwoD))
      ))
      [| 0x6euy; 0xe0uy; 0x38uy; 0x83uy |]

    test'
      CLZ
      (TwoOperands (
        OprSIMD (SIMDVecReg (V9, FourS)),
        OprSIMD (SIMDVecReg (V6, FourS))
      ))
      [| 0x6euy; 0xa0uy; 0x48uy; 0xc9uy |]

    test'
      UADALP
      (TwoOperands (
        OprSIMD (SIMDVecReg (V30, FourS)),
        OprSIMD (SIMDVecReg (V1, EightH))
      ))
      [| 0x6euy; 0x60uy; 0x68uy; 0x3euy |]

    test'
      SQNEG
      (TwoOperands (
        OprSIMD (SIMDVecReg (V15, TwoS)),
        OprSIMD (SIMDVecReg (V7, TwoS))
      ))
      [| 0x2euy; 0xa0uy; 0x78uy; 0xefuy |]

    test'
      CMGE
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V20, SixteenB)),
        OprSIMD (SIMDVecReg (V3, SixteenB)),
        OprImm 0L
      ))
      [| 0x6euy; 0x20uy; 0x88uy; 0x74uy |]

    test'
      CMLE
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V29, EightB)),
        OprSIMD (SIMDVecReg (V7, EightB)),
        OprImm 0L
      ))
      [| 0x2euy; 0x20uy; 0x98uy; 0xfduy |]

    test'
      NEG
      (TwoOperands (
        OprSIMD (SIMDVecReg (V10, EightH)),
        OprSIMD (SIMDVecReg (V6, EightH))
      ))
      [| 0x6euy; 0x60uy; 0xb8uy; 0xcauy |]

    test'
      SQXTN
      (TwoOperands (
        OprSIMD (SIMDVecReg (V7, TwoS)),
        OprSIMD (SIMDVecReg (V4, TwoD))
      ))
      [| 0x0euy; 0xa1uy; 0x48uy; 0x87uy |]

    test'
      SQXTN2
      (TwoOperands (
        OprSIMD (SIMDVecReg (V20, EightH)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x4euy; 0x61uy; 0x48uy; 0xb4uy |]

    test'
      SHLL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V21, TwoD)),
        OprSIMD (SIMDVecReg (V19, TwoS)),
        OprShift (SRTypeLSL, Imm 32L)
      ))
      [| 0x2euy; 0xa1uy; 0x3auy; 0x75uy |]

    test'
      SHLL2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V29, FourS)),
        OprSIMD (SIMDVecReg (V19, EightH)),
        OprShift (SRTypeLSL, Imm 16L)
      ))
      [| 0x6euy; 0x61uy; 0x3auy; 0x7duy |]

    test'
      UQXTN
      (TwoOperands (
        OprSIMD (SIMDVecReg (V9, TwoS)),
        OprSIMD (SIMDVecReg (V7, TwoD))
      ))
      [| 0x2euy; 0xa1uy; 0x48uy; 0xe9uy |]

    test'
      UQXTN2
      (TwoOperands (
        OprSIMD (SIMDVecReg (V2, EightH)),
        OprSIMD (SIMDVecReg (V6, FourS))
      ))
      [| 0x6euy; 0x61uy; 0x48uy; 0xc2uy |]

    test'
      FCVTXN
      (TwoOperands (
        OprSIMD (SIMDVecReg (V10, TwoS)),
        OprSIMD (SIMDVecReg (V6, TwoD))
      ))
      [| 0x2euy; 0x61uy; 0x68uy; 0xcauy |]

    test'
      FCVTXN2
      (TwoOperands (
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V14, TwoD))
      ))
      [| 0x6euy; 0x61uy; 0x69uy; 0xc5uy |]

    test'
      FRINTA
      (TwoOperands (
        OprSIMD (SIMDVecReg (V26, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x6euy; 0x21uy; 0x88uy; 0xbauy |]

    test'
      FRINTX
      (TwoOperands (
        OprSIMD (SIMDVecReg (V28, TwoD)),
        OprSIMD (SIMDVecReg (V5, TwoD))
      ))
      [| 0x6euy; 0x61uy; 0x98uy; 0xbcuy |]

    test'
      FCVTNU
      (TwoOperands (
        OprSIMD (SIMDVecReg (V5, TwoS)),
        OprSIMD (SIMDVecReg (V6, TwoS))
      ))
      [| 0x2euy; 0x21uy; 0xa8uy; 0xc5uy |]

    test'
      FCVTMU
      (TwoOperands (
        OprSIMD (SIMDVecReg (V6, FourS)),
        OprSIMD (SIMDVecReg (V22, FourS))
      ))
      [| 0x6euy; 0x21uy; 0xbauy; 0xc6uy |]

    test'
      FCVTAU
      (TwoOperands (
        OprSIMD (SIMDVecReg (V5, TwoS)),
        OprSIMD (SIMDVecReg (V27, TwoS))
      ))
      [| 0x2euy; 0x21uy; 0xcbuy; 0x65uy |]

    test'
      UCVTF
      (TwoOperands (
        OprSIMD (SIMDVecReg (V22, FourS)),
        OprSIMD (SIMDVecReg (V4, FourS))
      ))
      [| 0x6euy; 0x21uy; 0xd8uy; 0x96uy |]

    test'
      MVN
      (TwoOperands (
        OprSIMD (SIMDVecReg (V26, SixteenB)),
        OprSIMD (SIMDVecReg (V9, SixteenB))
      ))
      [| 0x6euy; 0x20uy; 0x59uy; 0x3auy |]

    test'
      RBIT
      (TwoOperands (
        OprSIMD (SIMDVecReg (V18, EightB)),
        OprSIMD (SIMDVecReg (V7, EightB))
      ))
      [| 0x2euy; 0x60uy; 0x58uy; 0xf2uy |]

    test'
      FCMGE
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V23, FourS)),
        OprFPImm 0.0
      ))
      [| 0x6euy; 0xa0uy; 0xcauy; 0xe5uy |]

    test'
      FCMLE
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V14, TwoS)),
        OprSIMD (SIMDVecReg (V18, TwoS)),
        OprFPImm 0.0
      ))
      [| 0x2euy; 0xa0uy; 0xdauy; 0x4euy |]

    test'
      FNEG
      (TwoOperands (
        OprSIMD (SIMDVecReg (V21, TwoD)),
        OprSIMD (SIMDVecReg (V19, TwoD))
      ))
      [| 0x6euy; 0xe0uy; 0xfauy; 0x75uy |]

    test'
      FRINTI
      (TwoOperands (
        OprSIMD (SIMDVecReg (V30, TwoS)),
        OprSIMD (SIMDVecReg (V21, TwoS))
      ))
      [| 0x2euy; 0xa1uy; 0x9auy; 0xbeuy |]

    test'
      FCVTPU
      (TwoOperands (
        OprSIMD (SIMDVecReg (V9, TwoD)),
        OprSIMD (SIMDVecReg (V4, TwoD))
      ))
      [| 0x6euy; 0xe1uy; 0xa8uy; 0x89uy |]

    test'
      FCVTZU
      (TwoOperands (
        OprSIMD (SIMDVecReg (V30, TwoS)),
        OprSIMD (SIMDVecReg (V15, TwoS))
      ))
      [| 0x2euy; 0xa1uy; 0xb9uy; 0xfeuy |]

    test'
      URSQRTE
      (TwoOperands (
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V29, FourS))
      ))
      [| 0x6euy; 0xa1uy; 0xcbuy; 0xa5uy |]

    test'
      FRSQRTE
      (TwoOperands (
        OprSIMD (SIMDVecReg (V18, TwoS)),
        OprSIMD (SIMDVecReg (V25, TwoS))
      ))
      [| 0x2euy; 0xa1uy; 0xdbuy; 0x32uy |]

    test'
      FSQRT
      (TwoOperands (
        OprSIMD (SIMDVecReg (V6, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS))
      ))
      [| 0x6euy; 0xa1uy; 0xf8uy; 0xa6uy |]

  /// C4.6.18 Advanced SIMD vector x indexed element
  [<TestMethod>]
  member __.``[AArch64] Advanced SIMD vector x indexed elem Parse Test`` () =
    test'
      SMLAL2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V26, FourS)),
        OprSIMD (SIMDVecReg (V6, EightH)),
        OprSIMD (sVRegIdx V2 VecH 6uy)
      ))
      [| 0x4fuy; 0x62uy; 0x28uy; 0xdauy |]

    test'
      SQDMLAL2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V2, TwoD)),
        OprSIMD (SIMDVecReg (V26, FourS)),
        OprSIMD (sVRegIdx V17 VecS 3uy)
      ))
      [| 0x4fuy; 0xb1uy; 0x3buy; 0x42uy |]

    test'
      SMLSL2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V10, FourS)),
        OprSIMD (SIMDVecReg (V14, EightH)),
        OprSIMD (sVRegIdx V9 VecH 3uy)
      ))
      [| 0x4fuy; 0x79uy; 0x61uy; 0xcauy |]

    test'
      SQDMLSL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V15, TwoD)),
        OprSIMD (SIMDVecReg (V1, TwoS)),
        OprSIMD (sVRegIdx V18 VecS 0uy)
      ))
      [| 0x0fuy; 0x92uy; 0x70uy; 0x2fuy |]

    test'
      MUL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V2, FourH)),
        OprSIMD (SIMDVecReg (V26, FourH)),
        OprSIMD (sVRegIdx V3 VecH 3uy)
      ))
      [| 0x0fuy; 0x73uy; 0x83uy; 0x42uy |]

    test'
      SMULL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V6, FourH)),
        OprSIMD (sVRegIdx V12 VecH 6uy)
      ))
      [| 0x0fuy; 0x6cuy; 0xa8uy; 0xc5uy |]

    test'
      SQDMULL2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V2, TwoD)),
        OprSIMD (SIMDVecReg (V26, FourS)),
        OprSIMD (sVRegIdx V29 VecS 3uy)
      ))
      [| 0x4fuy; 0xbduy; 0xbbuy; 0x42uy |]

    test'
      SQDMULH
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V29, FourS)),
        OprSIMD (SIMDVecReg (V26, FourS)),
        OprSIMD (sVRegIdx V29 VecS 2uy)
      ))
      [| 0x4fuy; 0x9duy; 0xcbuy; 0x5duy |]

    test'
      SQRDMULH
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V26, FourH)),
        OprSIMD (SIMDVecReg (V30, FourH)),
        OprSIMD (sVRegIdx V13 VecH 1uy)
      ))
      [| 0x0fuy; 0x5duy; 0xd3uy; 0xdauy |]

    test'
      FMLA
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V27, FourS)),
        OprSIMD (SIMDVecReg (V26, FourS)),
        OprSIMD (sVRegIdx V3 VecS 3uy)
      ))
      [| 0x4fuy; 0xa3uy; 0x1buy; 0x5buy |]

    test'
      FMLS
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V27, TwoD)),
        OprSIMD (SIMDVecReg (V26, TwoD)),
        OprSIMD (sVRegIdx V19 VecD 0uy)
      ))
      [| 0x4fuy; 0xd3uy; 0x53uy; 0x5buy |]

    test'
      FMUL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V27, FourS)),
        OprSIMD (SIMDVecReg (V26, FourS)),
        OprSIMD (sVRegIdx V3 VecS 2uy)
      ))
      [| 0x4fuy; 0x83uy; 0x9buy; 0x5buy |]

    test'
      MLA
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V30, FourS)),
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (sVRegIdx V13 VecS 3uy)
      ))
      [| 0x6fuy; 0xaduy; 0x08uy; 0xbeuy |]

    test'
      UMLAL2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V22, FourS)),
        OprSIMD (SIMDVecReg (V26, EightH)),
        OprSIMD (sVRegIdx V15 VecH 7uy)
      ))
      [| 0x6fuy; 0x7fuy; 0x2buy; 0x56uy |]

    test'
      MLS
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V10, FourS)),
        OprSIMD (SIMDVecReg (V4, FourS)),
        OprSIMD (sVRegIdx V23 VecS 2uy)
      ))
      [| 0x6fuy; 0x97uy; 0x48uy; 0x8auy |]

    test'
      UMLSL
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V30, FourS)),
        OprSIMD (SIMDVecReg (V6, FourH)),
        OprSIMD (sVRegIdx V14 VecH 2uy)
      ))
      [| 0x2fuy; 0x6euy; 0x60uy; 0xdeuy |]

    test'
      UMULL2
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V10, TwoD)),
        OprSIMD (SIMDVecReg (V7, FourS)),
        OprSIMD (sVRegIdx V31 VecS 3uy)
      ))
      [| 0x6fuy; 0xbfuy; 0xa8uy; 0xeauy |]

    test'
      FMULX
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V5, FourS)),
        OprSIMD (SIMDVecReg (V22, FourS)),
        OprSIMD (sVRegIdx V13 VecS 1uy)
      ))
      [| 0x6fuy; 0xaduy; 0x92uy; 0xc5uy |]

  /// C4.6.19 Cryptographic AES
  [<TestMethod>]
  member __.``[AArch64] Cryptographic AES Parse Test`` () =
    test'
      AESE
      (TwoOperands (
        OprSIMD (SIMDVecReg (V21, SixteenB)),
        OprSIMD (SIMDVecReg (V21, SixteenB))
      ))
      [| 0x4euy; 0x28uy; 0x4auy; 0xb5uy |]

    test'
      AESD
      (TwoOperands (
        OprSIMD (SIMDVecReg (V21, SixteenB)),
        OprSIMD (SIMDVecReg (V21, SixteenB))
      ))
      [| 0x4euy; 0x28uy; 0x5auy; 0xb5uy |]

    test'
      AESMC
      (TwoOperands (
        OprSIMD (SIMDVecReg (V21, SixteenB)),
        OprSIMD (SIMDVecReg (V21, SixteenB))
      ))
      [| 0x4euy; 0x28uy; 0x6auy; 0xb5uy |]

    test'
      AESIMC
      (TwoOperands (
        OprSIMD (SIMDVecReg (V21, SixteenB)),
        OprSIMD (SIMDVecReg (V21, SixteenB))
      ))
      [| 0x4euy; 0x28uy; 0x7auy; 0xb5uy |]

  /// C4.6.20 Cryptographic three-register SHA
  [<TestMethod>]
  member __.``[AArch64] Cryptographic three-register SHA Parse Test`` () =
    test'
      SHA1C
      (ThreeOperands (
        scalReg Q24,
        scalReg S27,
        OprSIMD (SIMDVecReg (V25, FourS))
      ))
      [| 0x5euy; 0x19uy; 0x03uy; 0x78uy |]

    test'
      SHA1P
      (ThreeOperands (
        scalReg Q31,
        scalReg S31,
        OprSIMD (SIMDVecReg (V19, FourS))
      ))
      [| 0x5euy; 0x13uy; 0x13uy; 0xffuy |]

    test'
      SHA1M
      (ThreeOperands (
        scalReg Q28,
        scalReg S21,
        OprSIMD (SIMDVecReg (V14, FourS))
      ))
      [| 0x5euy; 0x0euy; 0x22uy; 0xbcuy |]

    test'
      SHA1SU0
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V7, FourS)),
        OprSIMD (SIMDVecReg (V16, FourS)),
        OprSIMD (SIMDVecReg (V23, FourS))
      ))
      [| 0x5euy; 0x17uy; 0x32uy; 0x07uy |]

    test'
      SHA256H
      (ThreeOperands (
        scalReg Q30,
        scalReg Q30,
        OprSIMD (SIMDVecReg (V17, FourS))
      ))
      [| 0x5euy; 0x11uy; 0x43uy; 0xdeuy |]

    test'
      SHA256H2
      (ThreeOperands (
        scalReg Q30,
        scalReg Q24,
        OprSIMD (SIMDVecReg (V25, FourS))
      ))
      [| 0x5euy; 0x19uy; 0x53uy; 0x1euy |]

    test'
      SHA1SU0
      (ThreeOperands (
        OprSIMD (SIMDVecReg (V31, FourS)),
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V23, FourS))
      ))
      [| 0x5euy; 0x17uy; 0x32uy; 0xbfuy |]

  /// C4.6.21 Cryptographic two-register SHA
  [<TestMethod>]
  member __.``[AArch64] Cryptographic two-register SHA Parse Test`` () =
    test'
      SHA1H
      (TwoOperands (scalReg S31, scalReg S10))
      [| 0x5euy; 0x28uy; 0x09uy; 0x5fuy |]

    test'
      SHA1SU1
      (TwoOperands (
        OprSIMD (SIMDVecReg (V23, FourS)),
        OprSIMD (SIMDVecReg (V30, FourS))
      ))
      [| 0x5euy; 0x28uy; 0x1buy; 0xd7uy |]

    test'
      SHA256SU0
      (TwoOperands (
        OprSIMD (SIMDVecReg (V21, FourS)),
        OprSIMD (SIMDVecReg (V10, FourS))
      ))
      [| 0x5euy; 0x28uy; 0x29uy; 0x55uy |]

  /// C4.6.22 Floating-point compare
  [<TestMethod>]
  member __.``[AArch64] Floating-point compare Parse Test`` () =
    test'
      FCMP
      (TwoOperands (scalReg S7, scalReg S21))
      [| 0x1euy; 0x35uy; 0x20uy; 0xe0uy |]

    test'
      FCMP
      (TwoOperands (scalReg S28, OprFPImm 0.0))
      [| 0x1euy; 0x31uy; 0x23uy; 0x88uy |]

    test'
      FCMPE
      (TwoOperands (scalReg S22, scalReg S11))
      [| 0x1euy; 0x2buy; 0x22uy; 0xd0uy |]

    test'
      FCMPE
      (TwoOperands (scalReg S17, OprFPImm 0.0))
      [| 0x1euy; 0x39uy; 0x22uy; 0x38uy |]

    test'
      FCMP
      (TwoOperands (scalReg D6, scalReg D2))
      [| 0x1euy; 0x62uy; 0x20uy; 0xc0uy |]

    test'
      FCMP
      (TwoOperands (scalReg D14, OprFPImm 0.0))
      [| 0x1euy; 0x79uy; 0x21uy; 0xc8uy |]

    test'
      FCMPE
      (TwoOperands (scalReg D11, scalReg D20))
      [| 0x1euy; 0x74uy; 0x21uy; 0x70uy |]

    test'
      FCMPE
      (TwoOperands (scalReg D29, OprFPImm 0.0))
      [| 0x1euy; 0x63uy; 0x23uy; 0xb8uy |]

  /// C4.6.23 Floating-point conditional compare
  [<TestMethod>]
  member __.``[AArch64] Floating-point conditional compare Parse Test`` () =
    test'
      FCCMP
      (FourOperands (scalReg S26, scalReg S13, OprNZCV 0xDuy, OprCond CS))
      [| 0x1euy; 0x2duy; 0x27uy; 0x4duy |]

    test'
      FCCMPE
      (FourOperands (scalReg S26, scalReg S10, OprNZCV 6uy, OprCond AL))
      [| 0x1euy; 0x2auy; 0xe7uy; 0x56uy |]

    test'
      FCCMP
      (FourOperands (scalReg D18, scalReg D9, OprNZCV 9uy, OprCond CC))
      [| 0x1euy; 0x69uy; 0x36uy; 0x49uy |]

    test'
      FCCMPE
      (FourOperands (scalReg D26, scalReg D14, OprNZCV 2uy, OprCond AL))
      [| 0x1euy; 0x6euy; 0xe7uy; 0x52uy |]

  /// C4.6.24 Floating-point conditional select
  [<TestMethod>]
  member __.``[AArch64] Floating-point conditional select Parse Test`` () =
    test'
      FCSEL
      (FourOperands (scalReg S27, scalReg S2, scalReg S9, OprCond CS))
      [| 0x1euy; 0x29uy; 0x2cuy; 0x5buy |]

    test'
      FCSEL
      (FourOperands (scalReg D19, scalReg D10, scalReg D28, OprCond AL))
      [| 0x1euy; 0x7cuy; 0xeduy; 0x53uy |]

  /// C4.6.25 Floating-point data-processing (1 source)
  [<TestMethod>]
  member __.``[AArch64] FP data-processing (1 source) Parse Test`` () =
    test'
      FMOV
      (TwoOperands (scalReg S26, scalReg S17))
      [| 0x1euy; 0x20uy; 0x42uy; 0x3auy |]

    test'
      FABS
      (TwoOperands (scalReg S10, scalReg S7))
      [| 0x1euy; 0x20uy; 0xc0uy; 0xeauy |]

    test'
      FNEG
      (TwoOperands (scalReg S14, scalReg S8))
      [| 0x1euy; 0x21uy; 0x41uy; 0x0euy |]

    test'
      FSQRT
      (TwoOperands (scalReg S24, scalReg S11))
      [| 0x1euy; 0x21uy; 0xc1uy; 0x78uy |]

    test'
      FCVT
      (TwoOperands (scalReg D10, scalReg S22))
      [| 0x1euy; 0x22uy; 0xc2uy; 0xcauy |]

    test'
      FCVT
      (TwoOperands (scalReg H16, scalReg S15))
      [| 0x1euy; 0x23uy; 0xc1uy; 0xf0uy |]

    test'
      FRINTN
      (TwoOperands (scalReg S1, scalReg S19))
      [| 0x1euy; 0x24uy; 0x42uy; 0x61uy |]

    test'
      FRINTP
      (TwoOperands (scalReg S28, scalReg S10))
      [| 0x1euy; 0x24uy; 0xc1uy; 0x5cuy |]

    test'
      FRINTM
      (TwoOperands (scalReg S24, scalReg S14))
      [| 0x1euy; 0x25uy; 0x41uy; 0xd8uy |]

    test'
      FRINTZ
      (TwoOperands (scalReg S14, scalReg S6))
      [| 0x1euy; 0x25uy; 0xc0uy; 0xceuy |]

    test'
      FRINTA
      (TwoOperands (scalReg S12, scalReg S10))
      [| 0x1euy; 0x26uy; 0x41uy; 0x4cuy |]

    test'
      FRINTX
      (TwoOperands (scalReg S24, scalReg S11))
      [| 0x1euy; 0x27uy; 0x41uy; 0x78uy |]

    test'
      FRINTI
      (TwoOperands (scalReg S2, scalReg S15))
      [| 0x1euy; 0x27uy; 0xc1uy; 0xe2uy |]

    test'
      FMOV
      (TwoOperands (scalReg D20, scalReg D17))
      [| 0x1euy; 0x60uy; 0x42uy; 0x34uy |]

    test'
      FABS
      (TwoOperands (scalReg D2, scalReg D17))
      [| 0x1euy; 0x60uy; 0xc2uy; 0x22uy |]

    test'
      FNEG
      (TwoOperands (scalReg D2, scalReg D21))
      [| 0x1euy; 0x61uy; 0x42uy; 0xa2uy |]

    test'
      FSQRT
      (TwoOperands (scalReg D6, scalReg D13))
      [| 0x1euy; 0x61uy; 0xc1uy; 0xa6uy |]

    test'
      FCVT
      (TwoOperands (scalReg S13, scalReg D14))
      [| 0x1euy; 0x62uy; 0x41uy; 0xcduy |]

    test'
      FCVT
      (TwoOperands (scalReg H10, scalReg D21))
      [| 0x1euy; 0x63uy; 0xc2uy; 0xaauy |]

    test'
      FRINTN
      (TwoOperands (scalReg D3, scalReg D15))
      [| 0x1euy; 0x64uy; 0x41uy; 0xe3uy |]

    test'
      FRINTP
      (TwoOperands (scalReg D18, scalReg D21))
      [| 0x1euy; 0x64uy; 0xc2uy; 0xb2uy |]

    test'
      FRINTM
      (TwoOperands (scalReg D20, scalReg D27))
      [| 0x1euy; 0x65uy; 0x43uy; 0x74uy |]

    test'
      FRINTZ
      (TwoOperands (scalReg D2, scalReg D23))
      [| 0x1euy; 0x65uy; 0xc2uy; 0xe2uy |]

    test'
      FRINTA
      (TwoOperands (scalReg D17, scalReg D26))
      [| 0x1euy; 0x66uy; 0x43uy; 0x51uy |]

    test'
      FRINTX
      (TwoOperands (scalReg D24, scalReg D21))
      [| 0x1euy; 0x67uy; 0x42uy; 0xb8uy |]

    test'
      FRINTI
      (TwoOperands (scalReg D21, scalReg D27))
      [| 0x1euy; 0x67uy; 0xc3uy; 0x75uy |]

    test'
      FCVT
      (TwoOperands (scalReg S20, scalReg H14))
      [| 0x1euy; 0xe2uy; 0x41uy; 0xd4uy |]

    test'
      FCVT
      (TwoOperands (scalReg D8, scalReg H28))
      [| 0x1euy; 0xe2uy; 0xc3uy; 0x88uy |]

  /// C4.6.26 Floating-point data-processing (2 source)
  [<TestMethod>]
  member __.``[AArch64] FP data-processing (2 source) Parse Test`` () =
    test'
      FMUL
      (ThreeOperands (scalReg S2, scalReg S1, scalReg S1))
      [| 0x1euy; 0x21uy; 0x08uy; 0x22uy |]

    test'
      FDIV
      (ThreeOperands (scalReg S8, scalReg S20, scalReg S2))
      [| 0x1euy; 0x22uy; 0x1auy; 0x88uy |]

    test'
      FADD
      (ThreeOperands (scalReg S14, scalReg S5, scalReg S2))
      [| 0x1euy; 0x22uy; 0x28uy; 0xaeuy |]

    test'
      FSUB
      (ThreeOperands (scalReg S22, scalReg S10, scalReg S3))
      [| 0x1euy; 0x23uy; 0x39uy; 0x56uy |]

    test'
      FMAX
      (ThreeOperands (scalReg S20, scalReg S23, scalReg S4))
      [| 0x1euy; 0x24uy; 0x4auy; 0xf4uy |]

    test'
      FMIN
      (ThreeOperands (scalReg S21, scalReg S8, scalReg S5))
      [| 0x1euy; 0x25uy; 0x59uy; 0x15uy |]

    test'
      FMAXNM
      (ThreeOperands (scalReg S18, scalReg S9, scalReg S6))
      [| 0x1euy; 0x26uy; 0x69uy; 0x32uy |]

    test'
      FMINNM
      (ThreeOperands (scalReg S26, scalReg S5, scalReg S7))
      [| 0x1euy; 0x27uy; 0x78uy; 0xbauy |]

    test'
      FNMUL
      (ThreeOperands (scalReg S26, scalReg S21, scalReg S8))
      [| 0x1euy; 0x28uy; 0x8auy; 0xbauy |]

    test'
      FMUL
      (ThreeOperands (scalReg D27, scalReg D21, scalReg D9))
      [| 0x1euy; 0x69uy; 0x0auy; 0xbbuy |]

    test'
      FDIV
      (ThreeOperands (scalReg D2, scalReg D5, scalReg D10))
      [| 0x1euy; 0x6auy; 0x18uy; 0xa2uy |]

    test'
      FADD
      (ThreeOperands (scalReg D26, scalReg D21, scalReg D11))
      [| 0x1euy; 0x6buy; 0x2auy; 0xbauy |]

    test'
      FSUB
      (ThreeOperands (scalReg D30, scalReg D13, scalReg D12))
      [| 0x1euy; 0x6cuy; 0x39uy; 0xbeuy |]

    test'
      FMAX
      (ThreeOperands (scalReg D26, scalReg D5, scalReg D13))
      [| 0x1euy; 0x6duy; 0x48uy; 0xbauy |]

    test'
      FMIN
      (ThreeOperands (scalReg D27, scalReg D21, scalReg D14))
      [| 0x1euy; 0x6euy; 0x5auy; 0xbbuy |]

    test'
      FMAXNM
      (ThreeOperands (scalReg D2, scalReg D23, scalReg D18))
      [| 0x1euy; 0x72uy; 0x6auy; 0xe2uy |]

    test'
      FMINNM
      (ThreeOperands (scalReg D2, scalReg D4, scalReg D31))
      [| 0x1euy; 0x7fuy; 0x78uy; 0x82uy |]

    test'
      FNMUL
      (ThreeOperands (scalReg D20, scalReg D30, scalReg D0))
      [| 0x1euy; 0x60uy; 0x8buy; 0xd4uy |]

  /// C4.6.27 Floating-point data-processing (3 source)
  [<TestMethod>]
  member __.``[AArch64] FP data-processing (3 source) Parse Test`` () =
    test'
      FMADD
      (FourOperands (
        scalReg S25,
        scalReg S26,
        scalReg S31,
        scalReg S1
      ))
      [| 0x1fuy; 0x1fuy; 0x07uy; 0x59uy |]

    test'
      FMSUB
      (FourOperands (
        scalReg S4,
        scalReg S26,
        scalReg S30,
        scalReg S2
      ))
      [| 0x1fuy; 0x1euy; 0x8buy; 0x44uy |]

    test'
      FNMADD
      (FourOperands (
        scalReg S22,
        scalReg S8,
        scalReg S28,
        scalReg S4
      ))
      [| 0x1fuy; 0x3cuy; 0x11uy; 0x16uy |]

    test'
      FNMSUB
      (FourOperands (
        scalReg S21,
        scalReg S14,
        scalReg S24,
        scalReg S8
      ))
      [| 0x1fuy; 0x38uy; 0xa1uy; 0xd5uy |]

    test'
      FMADD
      (FourOperands (
        scalReg D25,
        scalReg D10,
        scalReg D16,
        scalReg D16
      ))
      [| 0x1fuy; 0x50uy; 0x41uy; 0x59uy |]

    test'
      FMSUB
      (FourOperands (
        scalReg D29,
        scalReg D14,
        scalReg D8,
        scalReg D24
      ))
      [| 0x1fuy; 0x48uy; 0xe1uy; 0xdduy |]

    test'
      FNMADD
      (FourOperands (
        scalReg D17,
        scalReg D11,
        scalReg D4,
        scalReg D28
      ))
      [| 0x1fuy; 0x64uy; 0x71uy; 0x71uy |]

    test'
      FNMSUB
      (FourOperands (
        scalReg D17,
        scalReg D3,
        scalReg D2,
        scalReg D30
      ))
      [| 0x1fuy; 0x62uy; 0xf8uy; 0x71uy |]

  /// C4.6.28 Floating-point immediate
  [<TestMethod>]
  member __.``[AArch64] Floating-point immediate Parse Test`` () =
    test'
      FMOV
      (TwoOperands (scalReg S21, OprFPImm 2.0))
      [| 0x1euy; 0x20uy; 0x10uy; 0x15uy |]

    test'
      FMOV
      (TwoOperands (scalReg D25, OprFPImm 10.5))
      [| 0x1euy; 0x64uy; 0xb0uy; 0x19uy |]

  /// C4.6.29 Conversion between floating-point and fixed-point
  [<TestMethod>]
  member __.``[AArch64] Conversion between FP and fixed-pt Parse Test`` () =
    test'
      SCVTF
      (ThreeOperands (scalReg S28, OprRegister W5, OprFbits 0x16uy))
      [| 0x1euy; 0x02uy; 0xa8uy; 0xbcuy |]

    test'
      UCVTF
      (ThreeOperands (scalReg S5, OprRegister W5, OprFbits 2uy))
      [| 0x1euy; 0x03uy; 0xf8uy; 0xa5uy |]

    test'
      FCVTZS
      (ThreeOperands (OprRegister W17, scalReg S4, OprFbits 1uy))
      [| 0x1euy; 0x18uy; 0xfcuy; 0x91uy |]

    test'
      FCVTZU
      (ThreeOperands (OprRegister W5, scalReg S14, OprFbits 0x1Fuy))
      [| 0x1euy; 0x19uy; 0x85uy; 0xc5uy |]

    test'
      SCVTF
      (ThreeOperands (scalReg D5, OprRegister W14, OprFbits 0xFuy))
      [| 0x1euy; 0x42uy; 0xc5uy; 0xc5uy |]

    test'
      UCVTF
      (ThreeOperands (scalReg D5, OprRegister W14, OprFbits 0x17uy))
      [| 0x1euy; 0x43uy; 0xa5uy; 0xc5uy |]

    test'
      FCVTZS
      (ThreeOperands (OprRegister W5, scalReg D14, OprFbits 0x1Buy))
      [| 0x1euy; 0x58uy; 0x95uy; 0xc5uy |]

    test'
      FCVTZU
      (ThreeOperands (OprRegister W5, scalReg D26, OprFbits 0x16uy))
      [| 0x1euy; 0x59uy; 0xabuy; 0x45uy |]

    test'
      SCVTF
      (ThreeOperands (scalReg S17, OprRegister X6, OprFbits 0xFuy))
      [| 0x9euy; 0x02uy; 0xc4uy; 0xd1uy |]

    test'
      UCVTF
      (ThreeOperands (scalReg S5, OprRegister X13, OprFbits 0x13uy))
      [| 0x9euy; 0x03uy; 0xb5uy; 0xa5uy |]

    test'
      FCVTZS
      (ThreeOperands (OprRegister X13, scalReg S6, OprFbits 4uy))
      [| 0x9euy; 0x18uy; 0xf0uy; 0xcduy |]

    test'
      FCVTZU
      (ThreeOperands (OprRegister X13, scalReg S14, OprFbits 0x1Buy))
      [| 0x9euy; 0x19uy; 0x95uy; 0xcduy |]

    test'
      SCVTF
      (ThreeOperands (scalReg D5, OprRegister X28, OprFbits 0x1Euy))
      [| 0x9euy; 0x42uy; 0x8buy; 0x85uy |]

    test'
      UCVTF
      (ThreeOperands (scalReg D5, OprRegister X14, OprFbits 0xFuy))
      [| 0x9euy; 0x43uy; 0xc5uy; 0xc5uy |]

    test'
      FCVTZS
      (ThreeOperands (OprRegister X17, scalReg D22, OprFbits 7uy))
      [| 0x9euy; 0x58uy; 0xe6uy; 0xd1uy |]

    test'
      FCVTZU
      (ThreeOperands (OprRegister X18, scalReg D14, OprFbits 0xCuy))
      [| 0x9euy; 0x59uy; 0xd1uy; 0xd2uy |]

  /// C4.6.30 Conversion between floating-point and integer
  [<TestMethod>]
  member __.``[AArch64] Conversion between FP and integer Parse Test`` () =
    test'
      FCVTNS
      (TwoOperands (OprRegister W20, scalReg S10))
      [| 0x1euy; 0x20uy; 0x01uy; 0x54uy |]

    test'
      FCVTNS
      (TwoOperands (OprRegister W10, scalReg D26))
      [| 0x1euy; 0x60uy; 0x03uy; 0x4auy |]

    test'
      FCVTNS
      (TwoOperands (OprRegister X2, scalReg S11))
      [| 0x9euy; 0x20uy; 0x01uy; 0x62uy |]

    test'
      FCVTNS
      (TwoOperands (OprRegister X23, scalReg D18))
      [| 0x9euy; 0x60uy; 0x02uy; 0x57uy |]

    test'
      FCVTNU
      (TwoOperands (OprRegister W24, scalReg S5))
      [| 0x1euy; 0x21uy; 0x00uy; 0xb8uy |]

    test'
      FCVTNU
      (TwoOperands (OprRegister W18, scalReg D21))
      [| 0x1euy; 0x61uy; 0x02uy; 0xb2uy |]

    test'
      FCVTNU
      (TwoOperands (OprRegister X27, scalReg S5))
      [| 0x9euy; 0x21uy; 0x00uy; 0xbbuy |]

    test'
      FCVTNU
      (TwoOperands (OprRegister X28, scalReg D13))
      [| 0x9euy; 0x61uy; 0x01uy; 0xbcuy |]

    test'
      SCVTF
      (TwoOperands (scalReg S26, OprRegister W5))
      [| 0x1euy; 0x22uy; 0x00uy; 0xbauy |]

    test'
      SCVTF
      (TwoOperands (scalReg D8, OprRegister W15))
      [| 0x1euy; 0x62uy; 0x01uy; 0xe8uy |]

    test'
      SCVTF
      (TwoOperands (scalReg S2, OprRegister X14))
      [| 0x9euy; 0x22uy; 0x01uy; 0xc2uy |]

    test'
      SCVTF
      (TwoOperands (scalReg D29, OprRegister X14))
      [| 0x9euy; 0x62uy; 0x01uy; 0xdduy |]

    test'
      UCVTF
      (TwoOperands (scalReg S29, OprRegister W21))
      [| 0x1euy; 0x23uy; 0x02uy; 0xbduy |]

    test'
      UCVTF
      (TwoOperands (scalReg D7, OprRegister W14))
      [| 0x1euy; 0x63uy; 0x01uy; 0xc7uy |]

    test'
      UCVTF
      (TwoOperands (scalReg S30, OprRegister X14))
      [| 0x9euy; 0x23uy; 0x01uy; 0xdeuy |]

    test'
      UCVTF
      (TwoOperands (scalReg D25, OprRegister X21))
      [| 0x9euy; 0x63uy; 0x02uy; 0xb9uy |]

    test'
      FCVTAS
      (TwoOperands (OprRegister W10, scalReg S12))
      [| 0x1euy; 0x24uy; 0x01uy; 0x8auy |]

    test'
      FCVTAS
      (TwoOperands (OprRegister W25, scalReg D20))
      [| 0x1euy; 0x64uy; 0x02uy; 0x99uy |]

    test'
      FCVTAS
      (TwoOperands (OprRegister X21, scalReg S18))
      [| 0x9euy; 0x24uy; 0x02uy; 0x55uy |]

    test'
      FCVTAS
      (TwoOperands (OprRegister X24, scalReg D25))
      [| 0x9euy; 0x64uy; 0x03uy; 0x38uy |]

    test'
      FCVTAU
      (TwoOperands (OprRegister W29, scalReg S26))
      [| 0x1euy; 0x25uy; 0x03uy; 0x5duy |]

    test'
      FCVTAU
      (TwoOperands (OprRegister W5, scalReg D26))
      [| 0x1euy; 0x65uy; 0x03uy; 0x45uy |]

    test'
      FCVTAU
      (TwoOperands (OprRegister X17, scalReg S24))
      [| 0x9euy; 0x25uy; 0x03uy; 0x11uy |]

    test'
      FCVTAU
      (TwoOperands (OprRegister X20, scalReg D27))
      [| 0x9euy; 0x65uy; 0x03uy; 0x74uy |]

    test'
      FMOV
      (TwoOperands (OprRegister W14, scalReg S25))
      [| 0x1euy; 0x26uy; 0x03uy; 0x2euy |]

    test'
      FMOV
      (TwoOperands (scalReg S3, OprRegister W14))
      [| 0x1euy; 0x27uy; 0x01uy; 0xc3uy |]

    test'
      FMOV
      (TwoOperands (OprRegister X11, scalReg D21))
      [| 0x9euy; 0x66uy; 0x02uy; 0xabuy |]

    test'
      FMOV
      (TwoOperands (scalReg D3, OprRegister X15))
      [| 0x9euy; 0x67uy; 0x01uy; 0xe3uy |]

    test'
      FMOV
      (TwoOperands (
        OprRegister X29,
        OprSIMD (sVRegIdx V16 VecD 1uy)
      ))
      [| 0x9euy; 0xaeuy; 0x02uy; 0x1duy |]

    test'
      FMOV
      (TwoOperands (
        OprSIMD (sVRegIdx V24 VecD 1uy),
        OprRegister X23
      ))
      [| 0x9euy; 0xafuy; 0x02uy; 0xf8uy |]

    test'
      FCVTPS
      (TwoOperands (OprRegister W14, scalReg S6))
      [| 0x1euy; 0x28uy; 0x00uy; 0xceuy |]

    test'
      FCVTPS
      (TwoOperands (OprRegister W6, scalReg D3))
      [| 0x1euy; 0x68uy; 0x00uy; 0x66uy |]

    test'
      FCVTPS
      (TwoOperands (OprRegister X3, scalReg S17))
      [| 0x9euy; 0x28uy; 0x02uy; 0x23uy |]

    test'
      FCVTPS
      (TwoOperands (OprRegister X26, scalReg D27))
      [| 0x9euy; 0x68uy; 0x03uy; 0x7auy |]

    test'
      FCVTPU
      (TwoOperands (OprRegister W28, scalReg S16))
      [| 0x1euy; 0x29uy; 0x02uy; 0x1cuy |]

    test'
      FCVTPU
      (TwoOperands (OprRegister W19, scalReg D9))
      [| 0x1euy; 0x69uy; 0x01uy; 0x33uy |]

    test'
      FCVTPU
      (TwoOperands (OprRegister X9, scalReg S3))
      [| 0x9euy; 0x29uy; 0x00uy; 0x69uy |]

    test'
      FCVTPU
      (TwoOperands (OprRegister X21, scalReg D19))
      [| 0x9euy; 0x69uy; 0x02uy; 0x75uy |]

    test'
      FCVTMS
      (TwoOperands (OprRegister W29, scalReg S14))
      [| 0x1euy; 0x30uy; 0x01uy; 0xdduy |]

    test'
      FCVTMS
      (TwoOperands (OprRegister W2, scalReg D27))
      [| 0x1euy; 0x70uy; 0x03uy; 0x62uy |]

    test'
      FCVTMS
      (TwoOperands (OprRegister X25, scalReg S3))
      [| 0x9euy; 0x30uy; 0x00uy; 0x79uy |]

    test'
      FCVTMS
      (TwoOperands (OprRegister X6, scalReg D4))
      [| 0x9euy; 0x70uy; 0x00uy; 0x86uy |]

    test'
      FCVTMU
      (TwoOperands (OprRegister W5, scalReg S12))
      [| 0x1euy; 0x31uy; 0x01uy; 0x85uy |]

    test'
      FCVTMU
      (TwoOperands (OprRegister W29, scalReg D19))
      [| 0x1euy; 0x71uy; 0x02uy; 0x7duy |]

    test'
      FCVTMU
      (TwoOperands (OprRegister XZR, scalReg S31))
      [| 0x9euy; 0x31uy; 0x03uy; 0xffuy |]

    test'
      FCVTMU
      (TwoOperands (OprRegister X0, scalReg D0))
      [| 0x9euy; 0x71uy; 0x00uy; 0x00uy |]

    test'
      FCVTZS
      (TwoOperands (OprRegister W3, scalReg S26))
      [| 0x1euy; 0x38uy; 0x03uy; 0x43uy |]

    test'
      FCVTZS
      (TwoOperands (OprRegister W13, scalReg D6))
      [| 0x1euy; 0x78uy; 0x00uy; 0xcduy |]

    test'
      FCVTZS
      (TwoOperands (OprRegister X25, scalReg S19))
      [| 0x9euy; 0x38uy; 0x02uy; 0x79uy |]

    test'
      FCVTZS
      (TwoOperands (OprRegister X6, scalReg D10))
      [| 0x9euy; 0x78uy; 0x01uy; 0x46uy |]

    test'
      FCVTZU
      (TwoOperands (OprRegister W1, scalReg S19))
      [| 0x1euy; 0x39uy; 0x02uy; 0x61uy |]

    test'
      FCVTZU
      (TwoOperands (OprRegister W27, scalReg D25))
      [| 0x1euy; 0x79uy; 0x03uy; 0x3buy |]

    test'
      FCVTZU
      (TwoOperands (OprRegister X19, scalReg S2))
      [| 0x9euy; 0x39uy; 0x00uy; 0x53uy |]

    test'
      FCVTZU
      (TwoOperands (OprRegister X2, scalReg D19))
      [| 0x9euy; 0x79uy; 0x02uy; 0x62uy |]
