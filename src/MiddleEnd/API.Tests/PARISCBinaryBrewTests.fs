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


namespace B2R2.MiddleEnd.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd

/// Tests the recovery of PA-RISC binaries.
[<TestClass>]
type PARISCBinaryBrewTests() =
  /// Recovers the functions of the given PA-RISC code, which starts at
  /// address zero with the entry of the binary.
  static let recoverCode (code: string list) =
    let bytes = code |> String.concat "" |> ByteArray.ofHexString
    let isa = ISA(Architecture.PARISC, Endian.Big, WordSize.Bit32)
    BinaryBrew(BinHandle.LoadRawImage(bytes, isa)).Functions

  (* A transfer through a register clears the low two bits of its target,
     which hold the privilege level there and which the address of code has
     clear anyway, so a table is read through the transfer as if it did not.
     A raw image has no section to hold a table, so the table is one of
     labels, which point into its function, before the next one: the code
     starts by calling a function that lies past its table. *)
  [<TestMethod>]
  member _.``A table is read through the mask of its jump``() =
    let code =
      [ "e8400060" (* 0x00: b,l 0x38,rp *)
        "08000240" (* nop *)
        "93408002" (* cmpiclr,<< 1,r26,r0 *)
        "e8000002" (* b,n 0x14 *)
        "e840c002" (* bv,n r0(rp) *)
        "34130040" (* 0x14: ldi 0x20,r19 *)
        "0e7a2093" (* ldw,s r26(r19),r19 *)
        "ea60c002" (* bv,n r0(r19) *)
        "00000028" (* 0x20: .word 0x28 *)
        "00000030" (* .word 0x30 *)
        "e840c000" (* 0x28: bv r0(rp) *)
        "341c0000" (* ldi 0,ret0 *)
        "e840c000" (* 0x30: bv r0(rp) *)
        "341c0002" (* ldi 1,ret0 *)
        "e840c002" (* 0x38: bv,n r0(rp) *) ]
    let fns = recoverCode code
    let entries = fns[0UL].JumpTables |> Array.map _.NumEntries
    CollectionAssert.AreEqual([| 2 |], entries)

  (* GCC jumps through a table by way of RP once a function has saved RP,
     which only what RP holds tells from a return, as both are BV through RP:
     the function here returns through RP once it has loaded it back, so the
     code past the call of it goes on to call a function there. The code
     calls the function past the table first, which bounds the table. *)
  [<TestMethod>]
  member _.``A table is read through RP once RP is saved``() =
    let code =
      [ "e8400098" (* 0x00: b,l 0x54,rp *)
        "08000240" (* nop *)
        "e8400018" (* b,l 0x1c,rp *)
        "08000240" (* nop *)
        "e8400080" (* b,l 0x58,rp *)
        "08000240" (* nop *)
        "e840c002" (* bv,n r0(rp) *)
        "6bc23fd9" (* 0x1c: stw rp,-14(sp) *)
        "93408002" (* cmpiclr,<< 1,r26,r0 *)
        "e8000002" (* b,n 0x2c *)
        "e800003a" (* b,n 0x4c *)
        "34130070" (* 0x2c: ldi 0x38,r19 *)
        "0e7a2082" (* ldw,s r26(r19),rp *)
        "e840c002" (* bv,n r0(rp) *)
        "00000040" (* 0x38: .word 0x40 *)
        "00000048" (* .word 0x48 *)
        "e8000008" (* 0x40: b 0x4c *)
        "341c0000" (* ldi 0,ret0 *)
        "341c0002" (* 0x48: ldi 1,ret0 *)
        "4bc23fd9" (* 0x4c: ldw -14(sp),rp *)
        "e840c002" (* bv,n r0(rp) *)
        "e840c002" (* 0x54: bv,n r0(rp) *)
        "e840c002" (* 0x58: bv,n r0(rp) *) ]
    let fns = recoverCode code
    let entries = fns[0x1cUL].JumpTables |> Array.map _.NumEntries
    CollectionAssert.AreEqual([| 2 |], entries)
    CollectionAssert.Contains(Seq.toArray fns.Addresses, 0x58UL)

  (* A function that returns through RP returns only where it gets there, as
     its return is a BV through RP: the one here does so only where its
     argument is zero, so the call that passes it one never returns, and the
     function that the code past the call would call is none. *)
  [<TestMethod>]
  member _.``A function returns through RP only where it gets there``() =
    let code =
      [ "341a0002" (* 0x00: ldi 1,r26 *)
        "e8400018" (* b,l 0x18,rp *)
        "08000240" (* nop *)
        "e8400048" (* b,l 0x38,rp *)
        "08000240" (* nop *)
        "e840c002" (* bv,n r0(rp) *)
        "6bc23fd9" (* 0x18: stw rp,-14(sp) *)
        "87402010" (* cmpib,= 0,r26,0x2c *)
        "08000240" (* nop *)
        "e8400010" (* b,l 0x34,rp *)
        "08000240" (* nop *)
        "4bc23fd9" (* 0x2c: ldw -14(sp),rp *)
        "e840c002" (* bv,n r0(rp) *)
        "04000000" (* 0x34: iitlbp r0,(sr0,r0) *)
        "e840c002" (* 0x38: bv,n r0(rp) *) ]
    let fns = recoverCode code
    CollectionAssert.AreEqual([| 0x0UL; 0x18UL; 0x34UL |],
                              Seq.toArray fns.Addresses |> Array.sort)
