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

namespace B2R2.FrontEnd.ARM32.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.ARM32
open B2R2.BinIR.LowUIR.AST.InfixOp
open type Register

[<TestClass>]
type LifterTests() =
  let num (v: uint32) = BitVector(v, 32<rt>) |> AST.num

  let num16 (v: uint16) = BitVector(v, 16<rt>) |> AST.num

  let num64 (v: uint64) = BitVector(v, 64<rt>) |> AST.num

  let t16 id = AST.tmpvar 16<rt> id

  let t32 id = AST.tmpvar 32<rt> id

  let t64 id = AST.tmpvar 64<rt> id

  let unwrapStmts stmts = Array.sub stmts 1 (Array.length stmts - 2)

  let isa = ISA(Architecture.ARMv7, Endian.Big)

  let reader = BinReader.Init Endian.Big

  let regFactory = RegisterFactory isa :> IRegisterFactory

  let ( !. ) name = Register.toRegID name |> regFactory.GetRegVar

  (* A VFP single- or double-precision register is half of a Q register in
     this front end, so it is reached through the pseudo-register accessor
     rather than by name: S0 is Q0's first half, S1 its second, S2 is Q1's
     first. *)
  let ( !@ ) (name, pos) =
    regFactory.GetPseudoRegVar(Register.toRegID name, pos)

  let ( ++ ) (byteStr: string) givenStmts =
    ByteArray.ofHexString byteStr, givenStmts

  let test isThumb (bytes: byte[]) (givenStmts: Stmt[]) =
    let parser = ARM32Parser(isa, isThumb, reader) :> IInstructionParsable
    let builder = ILowUIRBuilder.Default(isa, regFactory, LowUIRStream())
    let ins = parser.Parse(bytes, 0UL)
    let liftInstr = ins.Translate builder
    CollectionAssert.AreEqual(givenStmts, unwrapStmts liftInstr)

  let testARM (bytes: byte[], givenStmts: Stmt[]) = test false bytes givenStmts

  let testThumb (bytes: byte[], givenStmts: Stmt[]) = test true bytes givenStmts

  [<TestMethod>]
  member _.``[ARMv7] ADD (shifted register) lift test``() =
    let shiftAmt = AST.zext 32<rt> (AST.xtlo 8<rt> !.R8)
    "e080285e"
    ++ [| t32 1 :=
          !.R0 .+ (AST.ite (shiftAmt == num 0x0u) !.LR (!.LR ?>> shiftAmt))
            .+ num 0x0u
          !.R2 := t32 1 |]
    |> testARM

  [<TestMethod>]
  member _.``[ARMv7] ADD (immedate) lift test``() =
    "e28f0ff0"
    ++ [| t32 1 := !.PC .+ num 0x8u .+ num 0x3c0u .+ num 0x0u
          !.R0 := t32 1 |]
    |> testARM

  [<TestMethod>]
  member _.``[Thumb] ADD (Two Reg Operands) lift test``() =
    "448b"
    ++ [| t32 1 := !.FP .+ !.R1 .+ num 0u
          !.FP := t32 1 |]
    |> testThumb

  [<TestMethod>]
  member _.``[Thumb] ADD (Three Reg Operands) lift test``() =
    "44ec"
    ++ [| t32 1 := !.SP .+ !.IP .+ num 0u
          !.IP := t32 1 |]
    |> testThumb

  [<TestMethod>]
  member _.``[Thumb] ADD (Immediate) lift test``() =
    "b066"
    ++ [| t32 1 := !.SP .+ num 0x198u .+ num 0u
          !.SP := t32 1 |]
    |> testThumb

  [<TestMethod>]
  member _.``[ARMv7] QSAX saturates each lane to a signed halfword``() =
    let sat t =
      AST.xtlo 16<rt>
        (AST.ite (t ?> num 0x7fffu)
                 (num 0x7fffu)
                 (AST.ite (t ?< num 0xffff8000u) (num 0xffff8000u) t))
    "e6210f52"
    ++ [| t32 1 :=
            AST.sext 32<rt> (AST.xtlo 16<rt> !.R1)
              .+ AST.sext 32<rt> (AST.xthi 16<rt> !.R2)
          t32 2 :=
            AST.sext 32<rt> (AST.xthi 16<rt> !.R1)
              .- AST.sext 32<rt> (AST.xtlo 16<rt> !.R2)
          t32 5 := t32 1
          t16 3 := sat (t32 5)
          t32 6 := t32 2
          t16 4 := sat (t32 6)
          !.R0 := AST.concat (t16 4) (t16 3) |]
    |> testARM

  [<TestMethod>]
  member _.``[ARMv7] VNMLA sums the negated addends``() =
    let sign = num 0x80000000u
    let s0 = AST.xtlo 32<rt> !@(Q0, 1)
    let s1 = AST.xthi 32<rt> !@(Q0, 1)
    let s2 = AST.xtlo 32<rt> !@(Q0, 2)
    "ee100ac1"
    ++ [| !@(Q0, 1) :=
            (!@(Q0, 1) .& num64 0xffffffff00000000UL)
              .| AST.zext 64<rt>
                   (AST.fadd (s0 <+> sign)
                             (AST.fmul s1 s2 <+> sign)) |]
    |> testARM

  [<TestMethod>]
  member _.``[ARMv7] SMULBT sign-extends both halfword operands``() =
    "e16002c1"
    ++ [| t32 1 := AST.sext 32<rt> (AST.xtlo 16<rt> !.R1)
          t32 2 := AST.sext 32<rt> (AST.xthi 16<rt> !.R2)
          !.R0 := t32 1 .* t32 2 |]
    |> testARM

  (* MSR names which fields it writes, so it is a read-modify-write and not an
     assignment: everything outside the named field has to survive it. Only the
     flag field is modelled, which in user mode is the whole of what a program
     owns of CPSR. *)
  [<TestMethod>]
  member _.``[ARMv7] MSR writes the flag field and leaves the rest``() =
    let mask = num 0xf0000000u .| num 0x8000000u
    "e128f000"
    ++ [| !.CPSR := (!.CPSR .& AST.not mask) .| (!.R0 .& mask) |]
    |> testARM

  [<TestMethod>]
  member _.``[ARMv7] MRS reads CPSR``() =
    "e10f0000"
    ++ [| !.R0 := !.CPSR |]
    |> testARM

  [<TestMethod>]
  member _.``[ARMv7] a load takes the data byte order``() =
    (* The ISA this class lifts against is big-endian, which for ARM means
       BE8: instructions stay little-endian and data accesses follow the ISA.
       So a load here has to be a big-endian one. It used to be built with
       AST.loadLE regardless, which made every BE8 image read every word
       backwards -- and the printed IR looks identical either way, so only an
       assertion over the expression itself catches it. *)
    "e5910000"
    ++ [| t32 1 := AST.loadBE 32<rt> (!.R1 .+ num 0x0u)
          !.R0 := t32 1 |]
    |> testARM

  (* An element of a doubleword is written by rebuilding the whole register:
     the other elements are kept and the new one is shifted into place. These
     assertions are written the way the lifter writes them, so the shape below
     is a property of `elem` rather than of the instruction. *)
  /// <summary>
  /// VTST sets a lane to ones when the two lanes have a bit in common. Every
  /// other comparison in this front end answers with a mask and this one
  /// answered with the number one, which is the same thing only for a lane one
  /// bit wide.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VTST fills a lane that tests true``() =
    let low = num64 0xffffffff00000000UL
    let high = num64 0xffffffffUL
    let test e =
      let any = (e !@(Q0, 2) .& e !@(Q1, 1)) != num 0x0u
      AST.ite any (num 0xffffffffu) (num 0x0u)
    "f2210812"
    ++ [| !@(Q0, 1) :=
            (!@(Q0, 1) .& low) .| AST.zext 64<rt> (test (AST.xtlo 32<rt>))
          !@(Q0, 1) :=
            (!@(Q0, 1) .& high)
              .| (AST.zext 64<rt> (test (AST.xthi 32<rt>)) << num64 0x20UL) |]
    |> testARM

  /// <summary>
  /// VMLS subtracts the product. Adding the product's bitwise NOT instead is
  /// one short of that in every lane, because the two's complement wants the
  /// one back.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VMLS subtracts the product``() =
    let low = num64 0xffffffff00000000UL
    let high = num64 0xffffffffUL
    let diff e = e !@(Q0, 1) .- (e !@(Q0, 2) .* e !@(Q1, 1))
    "f3210902"
    ++ [| !@(Q0, 1) :=
            (!@(Q0, 1) .& low) .| AST.zext 64<rt> (diff (AST.xtlo 32<rt>))
          !@(Q0, 1) :=
            (!@(Q0, 1) .& high)
              .| (AST.zext 64<rt> (diff (AST.xthi 32<rt>)) << num64 0x20UL) |]
    |> testARM

  /// <summary>
  /// VSRA accumulates each lane of the shifted source into its OWN lane of the
  /// destination, and the shift is arithmetic for a signed type. The shift is
  /// made at twice the lane's width so that a shift by the whole width, which
  /// the encoding allows, still has somewhere to come from.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VSRA accumulates lane by lane``() =
    let low = num64 0xffffffff00000000UL
    let high = num64 0xffffffffUL
    let acc e =
      e !@(Q0, 1)
      .+ AST.xtlo 32<rt> (AST.sext 64<rt> (e !@(Q0, 2)) ?>> num64 0x1UL)
    "f2bf0111"
    ++ [| !@(Q0, 1) :=
            (!@(Q0, 1) .& low) .| AST.zext 64<rt> (acc (AST.xtlo 32<rt>))
          !@(Q0, 1) :=
            (!@(Q0, 1) .& high)
              .| (AST.zext 64<rt> (acc (AST.xthi 32<rt>)) << num64 0x20UL) |]
    |> testARM

  /// <summary>
  /// VFNMA is FPMulAdd(FPNeg(Sd), FPNeg(Sn), Sm), and FPNeg flips the sign bit
  /// of whatever it is handed -- a NaN included. Asking the fused multiply-add
  /// to negate its product and its addend instead agrees on every number and
  /// returns a propagated NaN with the sign it went in with.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VFNMA negates its operands, not its product``() =
    let low = num64 0xffffffff00000000UL
    let sign = num 0x80000000u
    let s0 = AST.xtlo 32<rt> !@(Q0, 1)
    let s1 = AST.xthi 32<rt> !@(Q0, 1)
    let s2 = AST.xtlo 32<rt> !@(Q0, 2)
    let flags = BitVector(0u, 8<rt>) |> AST.num
    "ee900ac1"
    ++ [| !@(Q0, 1) :=
            (!@(Q0, 1) .& low)
              .| AST.zext 64<rt>
                   (AST.app "FMA32" [ s1 <+> sign; s2; s0 <+> sign; flags ]
                      32<rt>) |]
    |> testARM
