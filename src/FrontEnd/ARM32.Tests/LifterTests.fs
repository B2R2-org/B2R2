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

  /// The target a branch reports through the analysis API, parsed at a
  /// given address. This is a different code path from the lifter's own
  /// branch handling, and the two are able to disagree.
  let branchTargetAt (isa: ISA) (hex: string) (addr: uint64) =
    let reader = BinReader.Init isa.Endian
    let parser = Parser(isa, true, reader) :> IInstructionParsable
    let ins = parser.Parse(ByteArray.ofHexString hex, addr)
    let mutable target = 0UL
    let ok = ins.DirectBranchTarget(&target)
    struct (ok, target)

  let ( ++ ) (byteStr: string) givenStmts =
    ByteArray.ofHexString byteStr, givenStmts

  let test isThumb (bytes: byte[]) (givenStmts: Stmt[]) =
    let parser = Parser(isa, isThumb, reader) :> IInstructionParsable
    let builder = ILowUIRBuilder.Default(isa, regFactory, LowUIRStream())
    let ins = parser.Parse(bytes, 0UL)
    let liftInstr = ins.Translate builder
    CollectionAssert.AreEqual(givenStmts, unwrapStmts liftInstr)

  let testARM (bytes: byte[], givenStmts: Stmt[]) = test false bytes givenStmts

  let testThumb (bytes: byte[], givenStmts: Stmt[]) = test true bytes givenStmts

  /// The statements one encoding lifts to.
  let liftedBy isThumb (hex: string) =
    let parser = Parser(isa, isThumb, reader) :> IInstructionParsable
    let builder = ILowUIRBuilder.Default(isa, regFactory, LowUIRStream())
    let ins = parser.Parse(ByteArray.ofHexString hex, 0UL)
    ins.Translate builder

  /// The registers the statements of one encoding write.
  let writtenBy isThumb hex =
    liftedBy isThumb hex
    |> Array.choose (function
      | Put(Dst = dst) -> Some dst
      | _ -> None)

  /// What the statements of one encoding assign to a register, if anything.
  let assignedBy isThumb hex dst =
    liftedBy isThumb hex
    |> Array.tryPick (function
      | Put(Dst = d; Src = src) when d = dst -> Some src
      | _ -> None)

  /// Whether the statements of one encoding raise an Undefined Instruction
  /// exception on some path through them.
  let canBeUndefined isThumb hex =
    liftedBy isThumb hex
    |> Array.exists (function
      | SideEffect(Effect = BinIR.SideEffect.UndefinedInstruction) -> true
      | _ -> false)

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
          t32 5 := t32 1
          t16 3 := sat (t32 5)
          t32 2 :=
            AST.sext 32<rt> (AST.xthi 16<rt> !.R1)
              .- AST.sext 32<rt> (AST.xtlo 16<rt> !.R2)
          t32 6 := t32 2
          t16 4 := sat (t32 6)
          !.R0 :=
            (AST.zext 32<rt> (t16 3) << AST.num0 32<rt>)
            .| (AST.zext 32<rt> (t16 4) << num 0x10u) |]
    |> testARM

  [<TestMethod>]
  member _.``[ARMv7] UQSAX saturates each lane to an unsigned halfword``() =
    (* The clamp is chosen at the WIDE width and narrowed once at the end,
       which is what keeps the value that went out of range around long
       enough to be recognised. *)
    let sat t =
      AST.xtlo 16<rt>
        (AST.ite (t ?> num 0xffffu)
                 (num 0xffffu)
                 (AST.ite (t ?< AST.num0 32<rt>) (AST.num0 32<rt>) t))
    "e6610f52"
    ++ [| t32 1 :=
            AST.zext 32<rt> (AST.xtlo 16<rt> !.R1)
              .+ AST.zext 32<rt> (AST.xthi 16<rt> !.R2)
          t16 3 := sat (t32 1)
          t32 2 :=
            AST.zext 32<rt> (AST.xthi 16<rt> !.R1)
              .- AST.zext 32<rt> (AST.xtlo 16<rt> !.R2)
          t16 4 := sat (t32 2)
          !.R0 :=
            (AST.zext 32<rt> (t16 3) << AST.num0 32<rt>)
            .| (AST.zext 32<rt> (t16 4) << num 0x10u) |]
    |> testARM

  [<TestMethod>]
  member _.``[ARMv7] UASX gives each GE half its own result half``() =
    (* The low half subtracts, so its GE bits say the subtraction did not
       borrow; the high half adds, so its say the addition carried out of the
       halfword. Each reads its own result and nothing else. *)
    let zero = AST.num0 32<rt>
    let geLo = AST.ite (t32 1 ?>= zero) (num 0x3u) zero
    let geHi = AST.ite (t32 2 ?>= num 0x10000u) (num 0xcu) zero
    "e6510f32"
    ++ [| t32 1 :=
            AST.zext 32<rt> (AST.xtlo 16<rt> !.R1)
              .- AST.zext 32<rt> (AST.xthi 16<rt> !.R2)
          t16 3 := AST.xtlo 16<rt> (t32 1)
          t32 2 :=
            AST.zext 32<rt> (AST.xthi 16<rt> !.R1)
              .+ AST.zext 32<rt> (AST.xtlo 16<rt> !.R2)
          t16 4 := AST.xtlo 16<rt> (t32 2)
          !.R0 :=
            (AST.zext 32<rt> (t16 3) << AST.num0 32<rt>)
            .| (AST.zext 32<rt> (t16 4) << num 0x10u)
          !.CPSR :=
            (!.CPSR .& num 0xfff0ffffu) .| ((geLo .| geHi) << num 0x10u) |]
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

  (* DDI0406C: a plain Thumb B is `BranchWritePC(PC + imm32)` with no
     alignment, and BL/BLX align the base only `if targetInstrSet ==
     InstrSet_ARM`. The analysis API aligned for every Thumb branch, so a
     four-byte-aligned base was used where the manual wants PC = addr + 4
     -- which changes the answer for every branch sitting at an address
     congruent to 2 mod 4, roughly half of them. The lifter's own path
     keys the alignment on the target mode and is right, so the two
     disagreed with each other. Only the analysis API is affected: the
     lifted IR never takes this path. *)
  [<TestMethod>]
  member _.``[Thumb] a branch at an odd halfword keeps its unaligned PC``() =
    let isa = ISA(Architecture.ARMv7, Endian.Little)
    (* B .+8 (T2), at an address congruent to 2 mod 4. *)
    let struct (ok, target) = branchTargetAt isa "02e0" 0x1002UL
    Assert.AreEqual<bool>(true, ok, "no branch target reported")
    Assert.AreEqual<uint64>(0x100AUL, target)

  [<TestMethod>]
  member _.``[Thumb] a branch at an even halfword is unchanged``() =
    let isa = ISA(Architecture.ARMv7, Endian.Little)
    let struct (ok, target) = branchTargetAt isa "02e0" 0x1000UL
    Assert.AreEqual<bool>(true, ok, "no branch target reported")
    Assert.AreEqual<uint64>(0x1008UL, target)

  (* A one-bit field is the width the guard used to exclude, and the width at
     which the difference between SBFX and UBFX is entirely the sign. The mask
     below is what the lifter builds for any width; at width 1 the extracted
     bit is itself the sign, so a set bit must fill the register. *)
  [<TestMethod>]
  member _.``[ARMv7] SBFX sign-extends a one-bit field``() =
    let bit = (!.R1 >> num 4u) .& num 1u
    "e7a00251"
    ++ [| t32 1 := bit
          t32 2 := AST.not (t32 1 .- num 1u) << num 1u
          !.R0 := bit .| t32 2 |]
    |> testARM

  (* SBFX takes its sign from Rn, so with Rd and Rn one register the sign has
     to be read before the field is written. Read after, it is a bit of the
     field shifted down -- zero whenever the field does not start at bit 0 --
     and the result never sign-extends. *)
  [<TestMethod>]
  member _.``[ARMv7] SBFX reads the sign before it writes Rd``() =
    "e7a31251"
    ++ [| t32 1 := (!.R1 >> num 7u) .& num 1u
          t32 2 := AST.not (t32 1 .- num 1u) << num 4u
          !.R1 := ((!.R1 >> num 4u) .& num 0xfu) .| t32 2 |]
    |> testARM

  [<TestMethod>]
  member _.``[ARMv7] SMULBT sign-extends both halfword operands``() =
    "e16002c1"
    ++ [| t32 1 := AST.sext 32<rt> (AST.xtlo 16<rt> !.R1)
          t32 2 := AST.sext 32<rt> (AST.xthi 16<rt> !.R2)
          !.R0 := t32 1 .* t32 2 |]
    |> testARM

  [<TestMethod>]
  member _.``[ARMv7] SMLAWB widens its accumulator before shifting``() =
    "e1203281"
    ++ [| t32 1 := AST.sext 32<rt> (AST.xtlo 16<rt> !.R2)
          t64 2 :=
            AST.sext 64<rt> !.R1 .* AST.sext 64<rt> (t32 1)
              .+ (AST.sext 64<rt> !.R3 << num64 0x10UL)
          !.R0 := AST.extract (t64 2) 32<rt> 16
          !.CPSR :=
            AST.ite ((t64 2 ?>> num64 0x10UL) != AST.sext 64<rt> !.R0)
                    (!.CPSR .| num 0x8000000u)
                    !.CPSR |]
    |> testARM

  (* MSR names which fields it writes, so it is a read-modify-write and not an
     assignment: everything outside the named field has to survive it. The flag
     field is the same in every mode, so its write needs no look at the one
     running. *)
  [<TestMethod>]
  member _.``[ARMv7] MSR writes the flag field and leaves the rest``() =
    "e128f000"
    ++ [| !.CPSR := (!.CPSR .& num 0x07ffffffu) .| (!.R0 .& num 0xf8000000u) |]
    |> testARM

  /// MRS of CPSR reads every field but the execution state -- the IT, J and T
  /// bits -- which read as zero (F5-4571).
  [<TestMethod>]
  member _.``[ARMv7] MRS of CPSR hides the execution state``() =
    "e10f0000"
    ++ [| !.R0 := !.CPSR .& num 0xf80f03dfu |]
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

  /// A hint changes nothing a program can see: with one thread and nothing
  /// to wait for, each of these lifts to no statement at all.
  [<TestMethod>]
  member _.``[ARMv7] YIELD lifts to nothing``() =
    "e320f001" ++ [||] |> testARM

  [<TestMethod>]
  member _.``[ARMv7] WFE lifts to nothing``() =
    "e320f002" ++ [||] |> testARM

  [<TestMethod>]
  member _.``[ARMv7] WFI lifts to nothing``() =
    "e320f003" ++ [||] |> testARM

  [<TestMethod>]
  member _.``[ARMv7] SEV lifts to nothing``() =
    "e320f004" ++ [||] |> testARM

  [<TestMethod>]
  member _.``[ARMv7] SEVL lifts to nothing``() =
    "e320f005" ++ [||] |> testARM

  [<TestMethod>]
  member _.``[ARMv7] ESB lifts to nothing``() =
    "e320f010" ++ [||] |> testARM

  [<TestMethod>]
  member _.``[ARMv7] TSB CSYNC lifts to nothing``() =
    "e320f012" ++ [||] |> testARM

  [<TestMethod>]
  member _.``[ARMv7] CSDB lifts to nothing``() =
    "e320f014" ++ [||] |> testARM

  [<TestMethod>]
  member _.``[ARMv7] DBG lifts to nothing``() =
    "e320f0f3" ++ [||] |> testARM

  [<TestMethod>]
  member _.``[ARMv7] SB lifts to nothing``() =
    "f57ff070" ++ [||] |> testARM

  [<TestMethod>]
  member _.``[Thumb] YIELD (narrow) lifts to nothing``() =
    "bf10" ++ [||] |> testThumb

  [<TestMethod>]
  member _.``[Thumb] WFE (narrow) lifts to nothing``() =
    "bf20" ++ [||] |> testThumb

  [<TestMethod>]
  member _.``[Thumb] WFI (narrow) lifts to nothing``() =
    "bf30" ++ [||] |> testThumb

  [<TestMethod>]
  member _.``[Thumb] SEV (narrow) lifts to nothing``() =
    "bf40" ++ [||] |> testThumb

  [<TestMethod>]
  member _.``[Thumb] SEVL (narrow) lifts to nothing``() =
    "bf50" ++ [||] |> testThumb

  [<TestMethod>]
  member _.``[Thumb] ESB.W (wide) lifts to nothing``() =
    "f3af8010" ++ [||] |> testThumb

  [<TestMethod>]
  member _.``[Thumb] TSB CSYNC (wide) lifts to nothing``() =
    "f3af8012" ++ [||] |> testThumb

  [<TestMethod>]
  member _.``[Thumb] CSDB.W (wide) lifts to nothing``() =
    "f3af8014" ++ [||] |> testThumb

  [<TestMethod>]
  member _.``[Thumb] DBG (wide) lifts to nothing``() =
    "f3af80f3" ++ [||] |> testThumb

  [<TestMethod>]
  member _.``[Thumb] SB (wide) lifts to nothing``() =
    "f3bf8f70" ++ [||] |> testThumb

  /// A constant is copied into every lane it names. These are the forms
  /// whose constant was expanded wrong, or written to one lane only.
  [<TestMethod>]
  member _.``[ARMv7] VMOV.F32 (immediate) fills both lanes``() =
    let imm = num64 0x40a00000UL
    "f2810f14"
    ++ [| !@(Q0, 1) := imm .| (imm << num64 0x20UL) |]
    |> testARM

  [<TestMethod>]
  member _.``[ARMv7] VMOV.F32 (immediate) fills a quadword``() =
    let imm = num64 0x40a00000UL
    let lanes = imm .| (imm << num64 0x20UL)
    "f2810f54"
    ++ [| !@(Q0, 2) := lanes
          !@(Q0, 1) := lanes |]
    |> testARM

  [<TestMethod>]
  member _.``[ARMv7] VMOV.I32 (immediate) shifts in ones``() =
    let imm = num64 0x5affUL
    "f2850c1a"
    ++ [| !@(Q0, 1) := imm .| (imm << num64 0x20UL) |]
    |> testARM

  [<TestMethod>]
  member _.``[ARMv7] VMVN.I32 (immediate) complements the ones``() =
    let imm = num64 0x5affUL
    "f2850c3a"
    ++ [| !@(Q0, 1) := AST.not (imm .| (imm << num64 0x20UL)) |]
    |> testARM

  /// A wide move of a register writes the register it names, not r0.
  [<TestMethod>]
  member _.``[Thumb] MOV (register, wide) writes its destination``() =
    let written = writtenBy true "ea4f0801"
    Assert.AreEqual<bool>(true, Array.contains !.R8 written)

  [<TestMethod>]
  member _.``[Thumb] MOVS.W (register) writes its destination``() =
    let written = writtenBy true "ea5f0801"
    Assert.AreEqual<bool>(true, Array.contains !.R8 written)

  [<TestMethod>]
  member _.``[Thumb] RRX (wide) writes its destination``() =
    let written = writtenBy true "ea4f0831"
    Assert.AreEqual<bool>(true, Array.contains !.R8 written)

  [<TestMethod>]
  member _.``[Thumb] RRXS (wide) writes its destination``() =
    let written = writtenBy true "ea5f0831"
    Assert.AreEqual<bool>(true, Array.contains !.R8 written)

  /// MRC reads a coprocessor 15 register into a core register: here MIDR, the
  /// processor's main ID.
  [<TestMethod>]
  member _.``[ARMv7] MRC reads MIDR``() =
    Assert.AreEqual<Expr option>(Some !.MIDR, assignedBy false "ee101f10" !.R1)

  /// REVIDR is not implemented, so its encoding reads as MIDR.
  [<TestMethod>]
  member _.``[ARMv7] MRC reads REVIDR as MIDR``() =
    Assert.AreEqual<Expr option>(Some !.MIDR, assignedBy false "ee101fd0" !.R1)

  /// TLBTR describes a TLB this processor does not have, and reads as zero.
  [<TestMethod>]
  member _.``[ARMv7] MRC reads TLBTR as zero``() =
    Assert.AreEqual<Expr option>(Some(num 0u), assignedBy false "ee101f70" !.R1)

  /// MCR writes a core register into one, keeping the bits it has.
  [<TestMethod>]
  member _.``[ARMv7] MCR writes TTBR0``() =
    Assert.AreEqual<Expr option>(Some !.R1, assignedBy false "ee021f10" !.TTBR0)

  [<TestMethod>]
  member _.``[ARMv7] MCR keeps VBAR aligned``() =
    let kept = !.R1 .& num 0xffffffe0u
    Assert.AreEqual<Expr option>(Some kept, assignedBy false "ee0c1f10" !.VBAR)

  /// TTBCR keeps the fields of the format its own EAE bit selects.
  [<TestMethod>]
  member _.``[ARMv7] MCR to TTBCR keeps its format's fields``() =
    let r1 = !.R1
    let kept =
      AST.ite (AST.xthi 1<rt> r1) (r1 .& num 0xffc73f87u) (r1 .& num 0x7u)
    Assert.AreEqual<Expr option>(Some kept, assignedBy false "ee021f50" !.TTBCR)

  /// The identification registers are the processor's, and writing one is
  /// UNDEFINED.
  [<TestMethod>]
  member _.``[ARMv7] MCR to MIDR is undefined``() =
    Assert.AreEqual<bool>(true, canBeUndefined false "ee001f10")

  /// The barriers are writes that change nothing a program can see.
  [<TestMethod>]
  member _.``[ARMv7] MCR of CP15DSB lifts to nothing``() =
    "ee071f9a" ++ [||] |> testARM

  /// Every register but the two thread IDs is PL1's, so reading one from User
  /// mode is UNDEFINED; TPIDRURO is the one User mode may read.
  [<TestMethod>]
  member _.``[ARMv7] MRC of SCTLR is refused in User mode``() =
    Assert.AreEqual<bool>(true, canBeUndefined false "ee111f10")

  [<TestMethod>]
  member _.``[ARMv7] MRC of TPIDRURO is allowed in User mode``() =
    Assert.AreEqual<bool>(false, canBeUndefined false "ee1d1f70")

  /// CCSIDR describes the cache CSSELR selects, which is not modelled.
  [<TestMethod>]
  member _.``[ARMv7] MRC of CCSIDR is unsupported``() =
    "ee301f10" ++ [| AST.sideEffect BinIR.SideEffect.UnsupportedInstruction |]
    |> testARM

  /// The cache maintenance operations need a memory system this front end
  /// does not have.
  [<TestMethod>]
  member _.``[ARMv7] MCR of DCCIMVAC is unsupported``() =
    "ee071f3e" ++ [| AST.sideEffect BinIR.SideEffect.UnsupportedInstruction |]
    |> testARM

  [<TestMethod>]
  member _.``[Thumb] MRC reads MIDR``() =
    Assert.AreEqual<Expr option>(Some !.MIDR, assignedBy true "ee101f10" !.R1)

  /// MRS of SPSR reads the current mode's SPSR, which User mode does not have.
  [<TestMethod>]
  member _.``[ARMv7] MRS of SPSR reads SPSR``() =
    Assert.AreEqual<Expr option>(Some !.SPSR, assignedBy false "e14f1000" !.R1)

  [<TestMethod>]
  member _.``[ARMv7] MRS of SPSR is refused in User mode``() =
    Assert.AreEqual<bool>(true, canBeUndefined false "e14f1000")

  /// MSR of SPSR writes the bytes it names and keeps the others.
  [<TestMethod>]
  member _.``[ARMv7] MSR of SPSR keeps the bytes it does not name``() =
    let kept = (!.SPSR .& num 0xffffff00u) .| (!.R1 .& num 0xffu)
    Assert.AreEqual<Expr option>(Some kept, assignedBy false "e161f001" !.SPSR)

  [<TestMethod>]
  member _.``[ARMv7] MSR of SPSR is refused in User mode``() =
    Assert.AreEqual<bool>(true, canBeUndefined false "e161f001")

  /// A write to CPSR.M changes mode, and a mode change swaps the banked
  /// registers: the old mode's SP goes back to its copy, and the new mode's
  /// copy becomes SP.
  [<TestMethod>]
  member _.``[ARMv7] MSR of CPSR_c swaps the banked registers``() =
    let written = writtenBy false "e121f001"
    Assert.AreEqual<bool>(true, Array.contains !.SPsvc written)

  [<TestMethod>]
  member _.``[ARMv7] CPS #mode swaps the banked registers``() =
    let written = writtenBy false "f1020012"
    Assert.AreEqual<bool>(true, Array.contains !.SPirq written)

  /// FIQ mode has copies of R8 to R12 as well.
  [<TestMethod>]
  member _.``[ARMv7] CPS to FIQ mode swaps R8``() =
    let written = writtenBy false "f1020011"
    Assert.AreEqual<bool>(true, Array.contains !.R8fiq written)

  /// CPSIE and CPSID clear and set the masks they name, at PL1; in User mode
  /// CPS does nothing at all.
  [<TestMethod>]
  member _.``[ARMv7] CPSIE I clears I at PL1``() =
    let user = (!.CPSR .& num 0x1fu) == num 0x10u
    let cleared = AST.ite user !.CPSR (!.CPSR .& num 0xffffff7fu)
    let written = assignedBy false "f1080080" !.CPSR
    Assert.AreEqual<Expr option>(Some cleared, written)

  [<TestMethod>]
  member _.``[ARMv7] CPSID F sets F at PL1``() =
    let user = (!.CPSR .& num 0x1fu) == num 0x10u
    let set = AST.ite user !.CPSR (!.CPSR .| num 0x40u)
    Assert.AreEqual<Expr option>(Some set, assignedBy false "f10c0040" !.CPSR)

  [<TestMethod>]
  member _.``[Thumb] CPSIE I (narrow) clears I at PL1``() =
    let user = (!.CPSR .& num 0x1fu) == num 0x10u
    let cleared = AST.ite user !.CPSR (!.CPSR .& num 0xffffff7fu)
    Assert.AreEqual<Expr option>(Some cleared, assignedBy true "b662" !.CPSR)

  /// A narrow shift by register is the wide one in sixteen bits, C included
  /// (DDI0487F.c F5.1.113).
  [<TestMethod>]
  member _.``[Thumb] LSLS (register, narrow) lifts as LSLS.W does``() =
    CollectionAssert.AreEqual(unwrapStmts (liftedBy true "fa10f001"),
                              unwrapStmts (liftedBy true "4088"))
