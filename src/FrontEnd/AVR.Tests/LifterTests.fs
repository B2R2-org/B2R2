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

namespace B2R2.FrontEnd.AVR.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.AVR
open B2R2.BinIR.LowUIR.AST.InfixOp
open type Register

[<TestClass>]
type LifterTests() =
  let isa = ISA Architecture.AVR

  let reader = BinReader.Init Endian.Little

  let regFactory = RegisterFactory isa :> IRegisterFactory

  let unwrapStmts stmts = Array.sub stmts 1 (Array.length stmts - 2)

  let ( ++ ) (byteStr: string) givenStmts =
    ByteArray.ofHexString byteStr, givenStmts

  let ( !. ) reg = Register.toRegID reg |> regFactory.GetRegVar

  /// A byte of the guest's data space. AVR is a Harvard machine, so the lifter
  /// folds its data space and its program space into the one address space an
  /// emulator offers by biasing data addresses, which is what avr-gcc, GDB, and
  /// the AVR ELF format already do (see GeneralLifter's DataSpaceBase).
  let dataMem addr =
    AST.zext 32<rt> addr .+ LiftingUtils.numI32 0x800000 32<rt>
    |> AST.loadLE 8<rt>

  /// A constant at the width of a data address: a pointer pair, the stack
  /// pointer, or an I/O address.
  let numAddr n = LiftingUtils.numI32 n 16<rt>

  /// A constant at the width of the program counter, which is wider than AVR's
  /// own so that one width covers every core (see GeneralLifter's pcSize).
  let numPC n = LiftingUtils.numI32 n 32<rt>

  /// Lifts the bytes for the given core and compares the statements.
  let testOn (core: AVRCore) (bytes: byte[], givenStmts: Stmt[]) =
    let isa = ISA core
    let parser = AVRParser(isa, reader) :> IInstructionParsable
    let builder = ILowUIRBuilder.Default(isa, regFactory, LowUIRStream())
    let ins = parser.Parse(bytes, 0UL)
    CollectionAssert.AreEqual(givenStmts, unwrapStmts <| ins.Translate builder)

  let test input = testOn AVRCore.Classic input

  [<TestMethod>]
  member _.``[AVR] Instructions with start and end statements lift Test``() =
    "0000"
    ++ [||]
    |> test

  [<TestMethod>]
  member _.``[AVR] Instructions with Put statements lift Test (1)``() =
    "4c2f"
    ++ [| !.R20 := !.R28 |]
    |> test

  [<TestMethod>]
  member _.``[AVR] Instructions with Put statements lift Test (2)``() =
    "5401"
    ++ [| !.R10 := !.R8; !.R11 := !.R9 |]
    |> test

  [<TestMethod>]
  member _.``[AVR] Put statements for flag registers lift Test (1)``() =
    "f894"
    ++ [| !.IF := AST.b0 |]
    |> test

  [<TestMethod>]
  member _.``[AVR] Put statements for flag registers lift Test (2)``() =
    "1124"
    ++ [| !.R1 := !.R1 <+> !.R1
          !.VF := AST.b0
          !.NF := AST.xthi 1<rt> !.R1
          !.ZF := !.R1 == AST.num0 8<rt>
          !.SF := !.NF <+> !.VF |]
    |> test

  (* PUSH writes the byte where the stack pointer already points and lowers it
     after, so the pointer rests one below the newest entry. *)
  [<TestMethod>]
  member _.``[AVR] Load statements lift Test``() =
    "6f92"
    ++ [| dataMem !.SP := !.R6
          !.SP := !.SP .- LiftingUtils.numI32 1 16<rt> |]
    |> test

  (* POP is the reverse of PUSH: it raises the pointer first and reads the byte
     it then points at. Reading into the destination rather than writing out of
     it is what the assertion is really about. *)
  [<TestMethod>]
  member _.``[AVR] POP reads the stack into its destination test``() =
    let t = AST.tmpvar 16<rt> 1
    "6f90"
    ++ [| t := !.SP .+ LiftingUtils.numI32 1 16<rt>
          !.R6 := dataMem t
          !.SP := t |]
    |> test

  (* An I/O access is a data access at a fixed offset and nothing more. Which
     of those addresses is a peripheral register, which is the status register
     and which is the stack pointer is the platform's business: an emulator
     that models state at one of them answers whichever instruction arrives,
     including a pointer no translation could have recognized. Recognizing them
     here instead would give the same architectural state two meanings,
     depending on how a program happened to reach it. *)
  [<TestMethod>]
  member _.``[AVR] IN reads the data space below the I/O offset test``() =
    "8db7"                                        (* in r24, 0x3d -- SPL *)
    ++ [| !.R24 := dataMem (numAddr 0x5d) |]
    |> test

  [<TestMethod>]
  member _.``[AVR] OUT writes the data space below the I/O offset test``() =
    "8fbf"                                        (* out 0x3f, r24 -- SREG *)
    ++ [| dataMem (numAddr 0x5f) := !.R24 |]
    |> test

  [<TestMethod>]
  member _.``[AVR] OUT to a peripheral reaches data memory test``() =
    "88b9"                                        (* out 0x08, r24 *)
    ++ [| dataMem (numAddr 0x28) := !.R24 |]
    |> test

  (* A direct load names a constant address, but it is still an ordinary data
     access -- the same one a pointer would make. avr-libc reads SREG both ways
     and has to see the same thing. *)
  [<TestMethod>]
  member _.``[AVR] LDS reads the data space it names test``() =
    "80915f00"                                    (* lds r24, 0x5f *)
    ++ [| !.R24 := dataMem (numAddr 0x5f) |]
    |> test

  (* RCALL pushes the word address of the instruction after it, most significant
     byte first, and transfers control instead of assigning the PC -- so the
     return address is not the target and a block ends here. *)
  [<TestMethod>]
  member _.``[AVR] RCALL pushes a word return address test``() =
    "00d0"
    ++ [| dataMem !.SP := LiftingUtils.numI32 1 8<rt>
          dataMem (!.SP .- numAddr 1) := LiftingUtils.numI32 0 8<rt>
          !.SP := !.SP .- numAddr 2
          AST.interjmp (!.PC .+ numPC 0 .+ numPC 2) InterJmpKind.IsCall |]
    |> test

  (* An avr6 call frame holds three bytes of return address where every earlier
     core holds two, so the same RCALL lays out a different frame there. Getting
     this wrong puts every register libgcc's frame helpers save at the wrong
     offset. *)
  [<TestMethod>]
  member _.``[AVR] an avr6 RCALL pushes three return bytes test``() =
    "00d0"
    ++ [| dataMem !.SP := LiftingUtils.numI32 1 8<rt>
          dataMem (!.SP .- numAddr 1) := LiftingUtils.numI32 0 8<rt>
          dataMem (!.SP .- numAddr 2) := LiftingUtils.numI32 0 8<rt>
          !.SP := !.SP .- numAddr 3
          AST.interjmp (!.PC .+ numPC 0 .+ numPC 2) InterJmpKind.IsCall |]
    |> testOn AVRCore.Avr6

  (* A CALL past 64 KiB of program memory keeps its target. The program counter
     used to be 16 bits wide, which truncated every such target to nothing --
     and the cores with that much program memory are exactly the ones whose
     images are full of CALL and JMP. *)
  [<TestMethod>]
  member _.``[AVR] a CALL past 64 KiB keeps its target test``() =
    "0f940000"
    ++ [| dataMem !.SP := LiftingUtils.numI32 2 8<rt>
          dataMem (!.SP .- numAddr 1) := LiftingUtils.numI32 0 8<rt>
          !.SP := !.SP .- numAddr 2
          AST.interjmp (numPC 0x20000) InterJmpKind.IsCall |]
    |> test

  (* LPM reads the program space, so it is the one load that takes no bias. *)
  [<TestMethod>]
  member _.``[AVR] LPM reads the program space test``() =
    "c895"
    ++ [| !.R0 := AST.loadLE 8<rt> (AST.zext 32<rt> !.Z) |]
    |> test

  (* ELPM is LPM over an address RAMPZ extends past what Z alone reaches, RAMPZ
     being an ordinary I/O register that lives in data memory. *)
  [<TestMethod>]
  member _.``[AVR] ELPM reads through RAMPZ test``() =
    let rampz = dataMem (numAddr 0x5B)
    let far = AST.zext 32<rt> rampz << numPC 16 .| AST.zext 32<rt> !.Z
    "d895"
    ++ [| !.R0 := AST.loadLE 8<rt> far |]
    |> test

  (* EIJMP goes where EIND extends Z to name, and Z holds a word address, so the
     byte address is twice it. *)
  [<TestMethod>]
  member _.``[AVR] EIJMP goes through EIND test``() =
    let eind = dataMem (numAddr 0x5C)
    let far = AST.zext 32<rt> eind << numPC 16 .| AST.zext 32<rt> !.Z
    "1994"
    ++ [| AST.interjmp (far << numPC 1) InterJmpKind.Base |]
    |> testOn AVRCore.Avr6

  (* A compare sets flags and nothing else, and its carry is read off the
     complement of a bit. Both were wrong at once: the result was written back,
     so a compare corrupted the very register it compared, and the complement
     was written as two's-complement negation, which on a single bit is the
     identity -- so every carry was the bit itself, and every borrow, signed
     branch and multi-byte subtraction with it. Spelling the whole lifting out
     is what pins the algebra rather than merely the shape. *)
  [<TestMethod>]
  member _.``[AVR] CPI only sets flags, off complemented bits test``() =
    let struct (t1, t2, t3) =
      AST.tmpvar 8<rt> 1, AST.tmpvar 8<rt> 2, AST.tmpvar 8<rt> 3
    let hi e = AST.xthi 1<rt> e
    let borrow a b r =
      (hi a .& hi b) .| (hi a .& AST.not (hi r)) .| (hi b .& AST.not (hi r))
    let overflow a b r =
      (hi a .& hi b .& AST.not (hi r))
      .| (AST.not (hi a) .& AST.not (hi b) .& hi r)
    "c63b"
    ++ [| t1 := !.R28
          t2 := LiftingUtils.numI32 0xb6 8<rt>
          t3 := t1 .- t2
          !.HF := borrow t3 t2 t1
          !.CF := borrow t3 t2 t1
          !.VF := overflow t3 t2 t1
          !.NF := AST.xthi 1<rt> t3
          !.ZF := t3 == AST.num0 8<rt>
          !.SF := !.NF <+> !.VF |]
    |> test

  (* A skip jumps over whatever follows, and what follows is two bytes or four.
     avr-libc's isspace skips over a jump, which is four bytes on any part with
     more than 8 KiB of program memory, so taking every skip to be two bytes
     landed in the middle of that jump -- and scanf, which calls isspace on
     every leading space, went wrong from there. *)
  [<TestMethod>]
  member _.``a skip clears a four-byte successor test``() =
    "81ff0c941a09"
    ++ [| AST.intercjmp (AST.extract !.R24 1<rt> 1 == AST.b1)
            (!.PC .+ numPC 6) (!.PC .+ numPC 2) |]
    |> test

  [<TestMethod>]
  member _.``a skip clears a two-byte successor test``() =
    "81ff0000"
    ++ [| AST.intercjmp (AST.extract !.R24 1<rt> 1 == AST.b1)
            (!.PC .+ numPC 4) (!.PC .+ numPC 2) |]
    |> test

  (* SLEEP stops the core until something outside it intervenes. What that is,
     and whether anything can, belongs to the platform running the program --
     all this translation says is that the core stops, which is what Terminate
     means and what HLT lifts to elsewhere. *)
  [<TestMethod>]
  member _.``SLEEP stops the core test``() =
    "8895"                                        (* sleep *)
    ++ [| AST.sideEffect Terminate |]
    |> test
