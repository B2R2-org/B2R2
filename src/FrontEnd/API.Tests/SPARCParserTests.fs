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

namespace B2R2.FrontEnd.API.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.SPARC
open type Opcode
open type Register
open type ConditionCode

/// Shortcut for creating operands.
[<AutoOpen>]
module private SPARCShortcut =
  type O =
    static member Reg (r) =
      OprReg r

    static member Imm (v) =
      OprImm v

    static member Addr (v) =
      OprAddr v

    static member CC (cond) =
      OprCC cond

[<TestClass>]
type SPARCParserTests () =
  let test (bytes: byte[]) (opcode, oprs: Operands) =
    let reader = BinReader.Init Endian.Little
    let span = System.ReadOnlySpan bytes
    let ins = ParsingMain.parse span reader 0UL
    Assert.AreEqual<Opcode> (opcode, ins.Info.Opcode)
    Assert.AreEqual<Operands> (oprs, ins.Info.Operands)

  let operandsFromArray oprList =
    let oprs = Array.ofList oprList
    match oprs.Length with
    | 0 -> NoOperand
    | 1 -> OneOperand oprs[0]
    | 2 -> TwoOperands (oprs[0], oprs[1])
    | 3 -> ThreeOperands (oprs[0], oprs[1], oprs[2])
    | 4 -> FourOperands (oprs[0], oprs[1], oprs[2], oprs[3])
    | 5 -> FiveOperands (oprs[0], oprs[1], oprs[2], oprs[3], oprs[4])
    | _ -> Terminator.impossible ()

  let ( ** ) opcode oprList = (opcode, operandsFromArray oprList)

  let ( ++ ) byteString pair = (ByteArray.ofHexString byteString, pair)

  [<TestMethod>]
  member __.``[SPARC] Three Reg Operands ADD Parse Test`` () =
    "0d80029e"
    ++ ADD ** [ O.Reg O2; O.Reg O5; O.Reg O7 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Two Reg Op, One Imm Op ADD Parse Test`` () =
    "8ab6029e"
    ++ ADD ** [ O.Reg O2; O.Imm -2422; O.Reg O7 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Three Reg Operands SUB Parse Test`` () =
    "11802692"
    ++ SUB ** [ O.Reg I2; O.Reg L1; O.Reg O1 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Three Reg Operands SUBcc Parse Test`` () =
    "1380a2ba"
    ++ SUBcc ** [ O.Reg O2; O.Reg L3; O.Reg I5 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Three Reg Operands UMULcc Parse Test`` () =
    "0b40d5b2"
    ++ UMULcc ** [ O.Reg L5; O.Reg O3; O.Reg I1 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Three Reg Operands 64-bit MULX Parse Test`` () =
    "05404bb6"
    ++ MULX ** [ O.Reg O5; O.Reg G5; O.Reg I3 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Three Reg Operands SMUL Parse Test`` () =
    "1e8059a6"
    ++ SMUL ** [ O.Reg G6; O.Reg I6; O.Reg L3 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Three Reg Operands SDIVcc Parse Test`` () =
    "0bc0feac"
    ++ SDIVcc ** [ O.Reg I3; O.Reg O3; O.Reg L6 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Three Reg Operands UDIVX Parse Test`` () =
    "13406bb4"
    ++ UDIVX ** [ O.Reg O5; O.Reg L3; O.Reg I2 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Two Reg Ops, One Imm Op XOR Parse Test`` () =
    "ff631ea2"
    ++ XOR ** [ O.Reg I1; O.Imm 1023; O.Reg L1 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Three Reg Operands ANDN Parse Test`` () =
    "0a802cb4"
    ++ ANDN ** [ O.Reg L2; O.Reg O2; O.Reg I2 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Two Reg Operands NEG Parse Test`` () =
    "0a002096"
    ++ SUB ** [ O.Reg G0; O.Reg O2; O.Reg O3 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Three Reg Operands SLL Parse Test`` () =
    "0fa02a89"
    ++ SLL ** [ O.Reg O2; O.Imm 15; O.Reg G4 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Three Reg Operands SRL Parse Test`` () =
    "16c03693"
    ++ SRL ** [ O.Reg I3; O.Reg L6; O.Reg O1 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Two Reg Ops, One Imme Op 64-bit SRAX Parse Test`` () =
    "3f303c83"
    ++ SRAX ** [ O.Reg L0; O.Imm 63; O.Reg G1 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] One Reg Op, One Imm Op SETHI Parse Test`` () =
    "ffff3f23"
    ++ SETHI ** [ O.Imm -1024; O.Reg L1 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Three Reg Operands LDSB Parse Test`` () =
    "ffbf4efc"
    ++ LDSB ** [ O.Reg I2; O.Imm -1; O.Reg I6 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Three Reg Operands LDUH Parse Test`` () =
    "124017d8"
    ++ LDUH ** [ O.Reg I5; O.Reg L2; O.Reg O4 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Three Reg Operands LDD Parse Test`` () =
    "ff3f18ee"
    ++ LDD ** [ O.Reg G0; O.Imm -1; O.Reg L7 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Three Reg Operands STB Parse Test`` () =
    "552128e8"
    ++ STB ** [ O.Reg L4; O.Reg G0; O.Imm 341 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Two Reg Op, One Imm Op ST Parse Test`` () =
    "2ae024f8"
    ++ STW ** [ O.Reg I4; O.Reg L3; O.Imm 42] ||> test

  [<TestMethod>]
  member __.``[SPARC] Three Reg Operands STD Parse Test`` () =
    "0a403cc2"
    ++ STD ** [ O.Reg G1; O.Reg L1; O.Reg O2 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Three Reg Operands JMPL Parse Test`` () =
    "0600c09f"
    ++ JMPL ** [ O.Reg G0; O.Reg G6; O.Reg O7 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Two Reg Op, One Imm Op JMPL Parse Test`` () =
    "08e0c781"
    ++ JMPL ** [ O.Reg I7; O.Imm 8; O.Reg G0 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Two Reg Operands BNE Parse Test`` () =
    "04008012"
    ++ BNE ** [ O.Imm 0; O.Addr 16 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] No Operands NOP Parse Test`` () =
    "00000001"
    ++ NOP ** [ ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Two Reg Operands FMOVS Parse Test`` () =
    "2200a085"
    ++ FMOVs ** [ O.Reg F2; O.Reg F2 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] One Imm Op, One FLoat Reg Op LD Parse Test`` () =
    "002000f7"
    ++ LDF ** [ O.Reg G0; O.Imm 0; O.Reg F27 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] One FLoat Reg Op, One Imm Op STDF Parse Test`` () =
    "0a2038cd"
    ++ STDF ** [ O.Reg F6; O.Reg G0; O.Imm 10 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Three Float Reg Op Single FADDs Parse Test`` () =
    "2108a085"
    ++ FADDs ** [ O.Reg F0; O.Reg F1; O.Reg F2 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Two Float Reg Op FNEGd Parse Test`` () =
    "c100a085"
    ++ FNEGd ** [ O.Reg F32; O.Reg F2 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Two Float Reg Op FSQRTq Parse Test`` () =
    "6505a089"
    ++ FSQRTq ** [ O.Reg F36; O.Reg F4 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Two Float Reg Op FiTOs Parse Test`` () =
    "8218a085"
    ++ FiTOs ** [ O.Reg F2; O.Reg F2 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] One CC Op, Two Reg Op FCMPs Parse Test`` () =
    "238aa881"
    ++ FCMPs ** [ O.CC Fcc0; O.Reg F2; O.Reg F3 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] One CC Op, Two Reg Op FMOVFsE Parse Test`` () =
    "2050aa87"
    ++ FMOVFsE ** [ O.CC Fcc2; O.Reg F0; O.Reg F3 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Three Reg Op FMOVRqGZ Parse Test`` () =
    "e018a881"
    ++ FMOVRqGZ ** [ O.Reg G0; O.Reg F0; O.Reg F0 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Two Reg Op, 1 Imm STF Parse Test`` () =
    "012020c90"
    ++ STF ** [ O.Reg F4; O.Reg G0; O.Imm 1 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Two Reg Op, 1 Imm Op LDDF Parse Test`` () =
    "01a01cc5"
    ++ LDDF ** [ O.Reg L2; O.Imm 1; O.Reg F2 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Three Reg Op STFQ Parse Test`` () =
    "000035f3"
    ++ STQF ** [ O.Reg F56; O.Reg L4; O.Reg G0 ] ||> test

  [<TestMethod>]
  member __.``[SPARC] Three Reg Op LDFSR Parse Test`` () =
    "1d000dc1"
    ++ LDFSR ** [ O.Reg L4; O.Reg I5; O.Reg FSR ] ||> test
