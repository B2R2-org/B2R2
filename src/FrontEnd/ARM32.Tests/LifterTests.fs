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

open System.Collections.Generic
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.Collections
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

  (* Dn is the half n % 2 of Q(n / 2), and S(2n) and S(2n + 1) are the low
     and the high word of Dn *)
  let dReg n = !@(enum<Register> (int Q0 + n / 2), n % 2 + 1)

  /// What an A32 encoding leaves in D0, D1 and FPSCR, run with FPSCR and the
  /// D registers given.
  let fpRun hex (fpscr: uint32) (ds: (int * uint64) list) =
    let inputs =
      (!.FPSCR, BitVector(fpscr, 32<rt>))
      :: [ for n, v in ds -> dReg n, BitVector(v, 64<rt>) ]
    let read = IRRunner.run (liftedBy false hex) inputs
    let d n = (read (dReg n)).ToUInt64()
    d 0, d 1, uint32 ((read !.FPSCR).ToUInt64())

  /// Whether an A32 encoding lifts to something other than a refusal.
  let liftsToIR hex =
    liftedBy false hex
    |> Array.exists (function
      | SideEffect _ -> true
      | _ -> false)
    |> not

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

  /// The statement that sets C to a constant, as a flag-setting logical
  /// instruction does from a rotated immediate: imm32<31>.
  let carryPut set =
    let bit = if set then AST.num1 1<rt> else AST.num0 1<rt>
    !.CPSR := (!.CPSR .& num 0xdfffffffu) .| (AST.zext 32<rt> bit << num 29u)

  /// Whether the statements of one encoding set C to the constant given.
  let writesCarry isThumb hex set =
    liftedBy isThumb hex |> Array.contains (carryPut set)

  /// Whether a statement after the one that writes a register reads it: the
  /// new value, where the instruction reads its operands before it writes.
  let readsAfterWriting isThumb hex reg =
    let stmts = liftedBy isThumb hex
    let rid = int (Register.toRegID reg)
    let writes = function
      | Put(Dst = Var(RegisterID = r)) -> int r = rid
      | _ -> false
    let reads = function
      | Put(Src = src) ->
        let regs = RegisterSet 0x10000
        AST.updateAllVarsUses regs (HashSet<int>()) src
        regs.Contains rid
      | _ ->
        false
    match Array.tryFindIndex writes stmts with
    | Some i -> Array.exists reads stmts[i + 1..]
    | None -> false

  /// The statements of one encoding as the text they print as, a line each.
  let liftedText isThumb hex =
    liftedBy isThumb hex |> Array.map string |> String.concat "\n"

  /// The kinds of the inter-jumps one encoding lifts to.
  let jumpKindsOf isThumb hex =
    liftedBy isThumb hex
    |> Array.choose (function
      | InterJmp(Kind = kind) -> Some kind
      | _ -> None)

  /// The condition under which the statements of one encoding raise an
  /// Undefined Instruction exception: what the jump guarding it tests.
  let undefinedWhen isThumb hex =
    let stmts = liftedBy isThumb hex
    stmts
    |> Array.tryFindIndex (function
      | SideEffect(Effect = BinIR.SideEffect.UndefinedInstruction) -> true
      | _ -> false)
    |> Option.bind (fun i ->
      match stmts[i - 2] with
      | CJmp(Cond = cond) -> Some cond
      | _ -> None)

  /// The test of CPSR.M for User or Hyp mode, where the returns from an
  /// exception and the transfers of the User mode registers are refused.
  let userOrHyp =
    let mode = !.CPSR .& num 0x1fu
    (mode == num 0x10u) .| (mode == num 0x1au)

  /// The modes in which the statements of one encoding raise an Undefined
  /// Instruction exception, worked out by running the guard for every mode
  /// CPSR.M can name, so that the answer does not hang on how it is written.
  let refusedModes isThumb hex =
    let modes =
      [| 0x10u; 0x11u; 0x12u; 0x13u; 0x16u; 0x17u; 0x1au; 0x1bu; 0x1fu |]
    match undefinedWhen isThumb hex with
    | Some guard ->
      let refused (mode: uint32) =
        let stmts = [| !.R0 := AST.zext 32<rt> guard |]
        let read = IRRunner.run stmts [ !.CPSR, BitVector(mode, 32<rt>) ]
        not (read !.R0).IsZero
      Array.filter refused modes
    | None ->
      [||]

  /// Whether CPSR.M names one of the given modes, as the lifter tests it.
  let modeIsOneOf (modes: uint32 list) =
    let mode = !.CPSR .& num 0x1fu
    modes |> List.map (fun m -> mode == num m) |> List.reduce (.|)

  /// The modes that bank SP away from User mode's: all but User and System.
  let spAway = modeIsOneOf [ 0x1au; 0x11u; 0x12u; 0x13u; 0x16u; 0x17u; 0x1bu ]

  /// The modes that bank LR away from it: those but Hyp, whose LR is User's.
  let lrAway = modeIsOneOf [ 0x11u; 0x12u; 0x13u; 0x16u; 0x17u; 0x1bu ]

  /// What the statements of one encoding store, in order.
  let storedBy isThumb hex =
    liftedBy isThumb hex
    |> Array.choose (function
      | Store(Value = value) -> Some value
      | _ -> None)

  /// Where the statements of one encoding store and what, in order.
  let storesBy isThumb hex =
    liftedBy isThumb hex
    |> Array.choose (function
      | Store(Addr = addr; Value = value) -> Some(addr, value)
      | _ -> None)

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

  /// VNMLA is FPAdd(FPNeg(Sd), FPNeg(product)), not FPNeg(FPAdd(Sd,
  /// product)): the two part company on zeros, where +0 accumulating -1 * +0
  /// is +0 the first way and -0 the second.
  [<TestMethod>]
  member _.``[ARMv7] VNMLA sums the negated addends``() =
    let d0, _, _ = fpRun "ee100ac1" 0u [ 0, 0xbf80000000000000UL ]
    Assert.AreEqual<uint64>(0xbf80000000000000UL, d0)

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
    let ds = [ 0, 0x7fc000003f800000UL; 1, 0x3f800000UL ]
    let d0, _, _ = fpRun "ee900ac1" 0u ds
    Assert.AreEqual<uint64>(0x7fc00000ffc00000UL, d0)

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

  /// VMRS reads the floating-point system register it names. Every one but
  /// FPSCR is PL1's, so User mode may not read it (DDI0406C B9.3.21).
  [<TestMethod>]
  member _.``[ARMv7] VMRS reads FPSID``() =
    Assert.AreEqual<Expr option>(Some !.FPSID, assignedBy false "eef00a10" !.R0)

  [<TestMethod>]
  member _.``[ARMv7] VMRS of FPSID is refused in User mode``() =
    Assert.AreEqual<bool>(true, canBeUndefined false "eef00a10")

  [<TestMethod>]
  member _.``[ARMv7] VMRS of FPSCR is allowed in User mode``() =
    Assert.AreEqual<bool>(false, canBeUndefined false "eef10a10")

  [<TestMethod>]
  member _.``[Thumb] VMRS reads MVFR0``() =
    Assert.AreEqual<Expr option>(Some !.MVFR0, assignedBy true "eef70a10" !.R0)

  /// APSR_nzcv takes FPSCR's flags, and the rest of CPSR stays as it was.
  [<TestMethod>]
  member _.``[ARMv7] VMRS APSR_nzcv takes FPSCR's flags``() =
    let others = !.CPSR .& AST.not (num 0xf0000000u)
    let flags = others .| (!.FPSCR .& num 0xf0000000u)
    Assert.AreEqual<Expr option>(Some flags, assignedBy false "eef1fa10" !.CPSR)

  [<TestMethod>]
  member _.``[Thumb] VMRS APSR_nzcv lifts as the A32 one does``() =
    CollectionAssert.AreEqual(unwrapStmts (liftedBy false "eef1fa10"),
                              unwrapStmts (liftedBy true "eef1fa10"))

  /// FPEXC keeps EN alone. What a write does to EX and to bits 29:0 is the
  /// subarchitecture's (DDI0406C B4.1.57), and nothing here traps a
  /// floating-point exception, so there is no state for them to hold; the
  /// reference keeps EN of all ones written.
  [<TestMethod>]
  member _.``[ARMv7] VMSR to FPEXC keeps EN``() =
    let kept = !.R0 .& num 0x40000000u
    Assert.AreEqual<Expr option>(Some kept, assignedBy false "eee80a10" !.FPEXC)

  [<TestMethod>]
  member _.``[ARMv7] VMSR to FPEXC is refused in User mode``() =
    Assert.AreEqual<bool>(true, canBeUndefined false "eee80a10")

  /// FPSCR keeps what VMSR has always kept of it: not the RES0 bits, nor the
  /// trap enables nothing here can take.
  [<TestMethod>]
  member _.``[ARMv7] VMSR to FPSCR keeps the bits FPSCR holds``() =
    let kept = !.R0 .& num 0xffff009fu
    Assert.AreEqual<Expr option>(Some kept, assignedBy false "eee10a10" !.FPSCR)

  /// FPSID is read-only, and PL1 writing it changes nothing (DDI0406C
  /// B9.3.22).
  [<TestMethod>]
  member _.``[ARMv7] VMSR to FPSID writes nothing``() =
    let written = writtenBy false "eee00a10"
    Assert.AreEqual<bool>(false, Array.contains !.FPSID written)

  /// At PL1 an instruction that writes the PC and sets the flags returns from
  /// an exception: CPSR takes SPSR's value, which is read before the change of
  /// mode it may make moves the register SPSR names (DDI0406C B9.3.20).
  [<TestMethod>]
  member _.``[ARMv7] SUBS PC, LR restores CPSR from SPSR``() =
    StringAssert.Contains(liftedText false "e25ef004", ":= SPSR\n")

  /// Hyp mode returns by ERET, and SUBS PC, LR is UNDEFINED there; User mode,
  /// which has no SPSR to return with, takes its UNPREDICTABLE as UNDEFINED.
  /// The guard names those two modes and no other.
  [<TestMethod>]
  member _.``[ARMv7] SUBS PC, LR is refused in User and Hyp mode``() =
    let guard = undefinedWhen false "e25ef004"
    Assert.AreEqual<Expr option>(Some userOrHyp, guard)

  /// A return whose condition fails does nothing at all, so its mode is
  /// checked behind the condition's own jump.
  [<TestMethod>]
  member _.``[ARMv7] SUBSNE PC, LR checks the mode only when it runs``() =
    let text = liftedText false "125ef004"
    let runs = text.IndexOf ":NeedToExec"
    Assert.AreEqual<bool>(true, runs >= 0 && runs < text.IndexOf "UserOrHyp")

  /// SPSR is read before the change of mode replaces it with the new mode's.
  [<TestMethod>]
  member _.``[ARMv7] SUBS PC, LR reads SPSR before changing mode``() =
    let lines = (liftedText false "e25ef004").Split '\n'
    let read = lines |> Array.findIndex (fun l -> l.EndsWith ":= SPSR")
    let swap = lines |> Array.findIndex (fun l -> l.StartsWith "SPSR :=")
    Assert.AreEqual<bool>(true, read < swap)

  /// The return goes to LR less the immediate.
  [<TestMethod>]
  member _.``[ARMv7] SUBS PC, LR returns to LR less the immediate``() =
    let result = "((LR + 0xfffffffb:I32) + 0x1:I32)"
    StringAssert.Contains(liftedText false "e25ef004", result)

  /// Where the return goes on is the instruction set the restored T bit
  /// names: Thumb, with bit 0 of the target clear, when T is set, and A32,
  /// with bits 1:0 clear, when it is not.
  [<TestMethod>]
  member _.``[ARMv7] SUBS PC, LR returns to the set its T bit names``() =
    let text = liftedText false "e25ef004"
    let thumb = BinIR.InterJmpKind.SwitchToThumb
    let arm = BinIR.InterJmpKind.SwitchToARM
    CollectionAssert.AreEqual([| thumb; arm |], jumpKindsOf false "e25ef004")
    StringAssert.Contains(text, "& 0x20:I32) != 0x0:I32) then jmp ReturnTo")
    StringAssert.Contains(text, ":ReturnToThumb\nijmp (T_2:I32 & 0xfffffffe")
    StringAssert.Contains(text, ":NotReturnToThumb\nijmp (T_2:I32 & 0xfffffffc")

  [<TestMethod>]
  member _.``[ARMv7] MOVS PC, LR restores CPSR from SPSR``() =
    StringAssert.Contains(liftedText false "e1b0f00e", ":= SPSR\n")

  /// Without S the same write of the PC is a branch and nothing more.
  [<TestMethod>]
  member _.``[ARMv7] SUB PC, LR leaves CPSR alone``() =
    let text = liftedText false "e24ef004"
    Assert.AreEqual<bool>(false, text.Contains ":= SPSR\n")

  /// SUBS PC, LR, #imm is an encoding of its own in T32 (B9.3.19).
  [<TestMethod>]
  member _.``[Thumb] SUBS PC, LR restores CPSR from SPSR``() =
    StringAssert.Contains(liftedText true "f3de8f04", ":= SPSR\n")

  /// It returns where the A32 SUBS PC, LR does, to LR less the immediate --
  /// not to the PC less it.
  [<TestMethod>]
  member _.``[Thumb] SUBS PC, LR returns where the A32 one does``() =
    let a32 = liftedText false "e25ef004"
    Assert.AreEqual<string>(a32, liftedText true "f3de8f04")

  /// LDM with the PC in its list and ^ returns from an exception too, with
  /// the state SPSR holds (DDI0406C B9.3.5).
  [<TestMethod>]
  member _.``[ARMv7] LDM with PC and ^ restores CPSR from SPSR``() =
    StringAssert.Contains(liftedText false "e8f08002", ":= SPSR\n")

  [<TestMethod>]
  member _.``[ARMv7] LDM with PC and ^ writes its base back``() =
    let written = writtenBy false "e8f08002"
    Assert.AreEqual<bool>(true, Array.contains !.R0 written)

  /// The registers that return loads are the running mode's own: SP takes the
  /// word itself, not a User mode copy.
  [<TestMethod>]
  member _.``[ARMv7] LDM with PC and ^ loads the running mode's SP``() =
    let word = AST.loadBE 32<rt> (t32 2 .+ num 4u)
    Assert.AreEqual<Expr option>(Some word, assignedBy false "e8f0e002" !.SP)

  /// Each form with ^ is UNDEFINED in Hyp mode, and User mode takes its
  /// UNPREDICTABLE as UNDEFINED (B9.3.5, B9.3.6 and B9.3.17).
  [<TestMethod>]
  member _.``[ARMv7] LDM and STM with ^ are refused in User and Hyp mode``() =
    for hex in [ "e8f08002"; "e8d06000"; "e8c06000" ] do
      let guard = undefinedWhen false hex
      Assert.AreEqual<Expr option>(Some userOrHyp, guard, hex)

  [<TestMethod>]
  member _.``[ARMv7] LDMNE with ^ checks the mode only when it runs``() =
    let text = liftedText false "18d06000"
    let runs = text.IndexOf ":NeedToExec"
    Assert.AreEqual<bool>(true, runs >= 0 && runs < text.IndexOf "UserOrHyp")

  /// Without the PC, ^ means the User mode registers, whatever mode runs
  /// (B9.3.6): the copy where the mode running banks the register away, and
  /// the live register where it does not. Every mode but User and System
  /// banks SP away, and every one but those and Hyp, whose LR is User mode's,
  /// banks LR.
  [<TestMethod>]
  member _.``[ARMv7] LDM with ^ loads User mode's SP and LR``() =
    let sp, lr = t32 3, t32 4
    let expected =
      [ !.SPusr, AST.ite spAway sp !.SPusr
        !.SP, AST.ite spAway !.SP sp
        !.LRusr, AST.ite lrAway lr !.LRusr
        !.LR, AST.ite lrAway !.LR lr ]
    for dst, value in expected do
      Assert.AreEqual<Expr option>(Some value, assignedBy false "e8d06000" dst)

  /// STM with ^ stores the same copies (B9.3.17).
  [<TestMethod>]
  member _.``[ARMv7] STM with ^ stores User mode's SP and LR``() =
    let stored = [| AST.ite spAway !.SPusr !.SP; AST.ite lrAway !.LRusr !.LR |]
    CollectionAssert.AreEqual(stored, storedBy false "e8c06000")

  /// FIQ mode alone banks R8 to R12 away.
  [<TestMethod>]
  member _.``[ARMv7] STM with ^ stores User mode's R8``() =
    let stored = [| AST.ite (modeIsOneOf [ 0x11u ]) !.R8usr !.R8 |]
    CollectionAssert.AreEqual(stored, storedBy false "e8c00100")

  /// Without ^ the same LDM is anyone's.
  [<TestMethod>]
  member _.``[ARMv7] LDM without ^ is allowed in User mode``() =
    Assert.AreEqual<bool>(false, canBeUndefined false "e8906000")

  /// SRS stores on the stack of the mode it names (DDI0406C B9.3.16): that
  /// mode's SP, which is the live SP when it is the mode running.
  [<TestMethod>]
  member _.``[ARMv7] SRS stores on the named mode's stack``() =
    let irqSP = AST.ite (modeIsOneOf [ 0x12u ]) !.SP !.SPirq
    let start = assignedBy false "f96d0512" (t32 1)
    Assert.AreEqual<Expr option>(Some irqSP, start)

  /// The two words go where the addressing mode puts them, LR below SPSR.
  [<TestMethod>]
  member _.``[ARMv7] SRS stores LR and SPSR where its mode says``() =
    let sp = t32 1
    let expected =
      [ "f84d0512", sp .- num 4u
        "f96d0512", sp .- num 8u
        "f8cd0512", sp
        "f9cd0512", sp .+ num 4u ]
    for hex, address in expected do
      Assert.AreEqual<Expr option>(Some address, assignedBy false hex (t32 2))
    let stores = [| t32 2, !.LR; t32 2 .+ num 4u, !.SPSR |]
    CollectionAssert.AreEqual(stores, storesBy false "f96d0512")

  /// User and System mode share one SP, and FIQ mode has its own.
  [<TestMethod>]
  member _.``[ARMv7] SRS reads the SP of the mode it names``() =
    let usrSP = AST.ite (modeIsOneOf [ 0x10u; 0x1fu ]) !.SP !.SPusr
    let fiqSP = AST.ite (modeIsOneOf [ 0x11u ]) !.SP !.SPfiq
    let start hex = assignedBy false hex (t32 1)
    Assert.AreEqual<Expr option>(Some usrSP, start "f96d0510")
    Assert.AreEqual<Expr option>(Some fiqSP, start "f96d0511")

  [<TestMethod>]
  member _.``[ARMv7] SRS writes the named mode's SP back``() =
    let isIRQ = modeIsOneOf [ 0x12u ]
    let down = AST.ite isIRQ !.SPirq (t32 1 .- num 8u)
    let up = AST.ite isIRQ !.SPirq (t32 1 .+ num 8u)
    Assert.AreEqual<Expr option>(Some down, assignedBy false "f96d0512" !.SPirq)
    Assert.AreEqual<Expr option>(Some up, assignedBy false "f8ed0512" !.SPirq)

  [<TestMethod>]
  member _.``[ARMv7] SRS without writeback leaves the SP``() =
    let written = writtenBy false "f8cd0512"
    Assert.AreEqual<bool>(false, Array.contains !.SPirq written)

  /// SRS is UNDEFINED in Hyp mode and UNPREDICTABLE in User and System mode,
  /// where the reference refuses it, unlike RFE (B9.3.16).
  [<TestMethod>]
  member _.``[ARMv7] SRS is refused in User, System and Hyp mode``() =
    let refused = modeIsOneOf [ 0x10u; 0x1fu; 0x1au ]
    Assert.AreEqual<Expr option>(Some refused, undefinedWhen false "f96d0512")

  /// Hyp mode's SP is not SRS's to name: UNPREDICTABLE, taken as UNDEFINED.
  [<TestMethod>]
  member _.``[ARMv7] SRS to Hyp mode's stack is undefined``() =
    "f96d051a" ++ [| AST.sideEffect BinIR.SideEffect.UndefinedInstruction |]
    |> testARM

  /// RFE loads the PC from the word at the address and CPSR from the one
  /// above it (B9.3.13), and the address is where its mode says: RFEDA and
  /// RFEIB had no lifter, and RFEDB loaded both words and used neither.
  [<TestMethod>]
  member _.``[ARMv7] RFE reads its two words where its mode says``() =
    let expected =
      [ "f8100a00", !.R0 .- num 4u
        "f9100a00", !.R0 .- num 8u
        "f8b00a00", !.R0
        "f9900a00", !.R0 .+ num 4u ]
    for hex, address in expected do
      Assert.AreEqual<Expr option>(Some address, assignedBy false hex (t32 1))
    let assigned = assignedBy false "f9100a00"
    let pc = AST.loadBE 32<rt> (t32 1)
    let cpsr = AST.loadBE 32<rt> (t32 1 .+ num 4u)
    Assert.AreEqual<Expr option>(Some pc, assigned (t32 2))
    Assert.AreEqual<Expr option>(Some cpsr, assigned (t32 3))

  /// CPSR takes the second word, and the T bit in it picks the instruction
  /// set the return goes on in.
  [<TestMethod>]
  member _.``[ARMv7] RFE restores CPSR from the word it loads``() =
    let text = liftedText false "f9100a00"
    StringAssert.Contains(text, "CPSR := ((T_3:I32 & 0xff0fffe0:I32) | ")
    StringAssert.Contains(text, "if ((T_3:I32 & 0x20:I32) != 0x0:I32) then")

  [<TestMethod>]
  member _.``[ARMv7] RFE writes its base back``() =
    let up = assignedBy false "f8b00a00" !.R0
    let down = assignedBy false "f9300a00" !.R0
    Assert.AreEqual<Expr option>(Some(!.R0 .+ num 8u), up)
    Assert.AreEqual<Expr option>(Some(!.R0 .- num 8u), down)

  /// The base is written back before the change of mode: an SP base is the
  /// running mode's SP, not the one the restored mode brings in.
  [<TestMethod>]
  member _.``[ARMv7] RFE writes SP back before changing mode``() =
    let first = assignedBy false "f8bd0a00" !.SP
    Assert.AreEqual<Expr option>(Some(!.SP .+ num 8u), first)

  [<TestMethod>]
  member _.``[ARMv7] RFE without writeback leaves its base``() =
    let written = writtenBy false "f9100a00"
    Assert.AreEqual<bool>(false, Array.contains !.R0 written)

  /// RFE is UNDEFINED in Hyp mode, and User mode takes its UNPREDICTABLE as
  /// UNDEFINED; the manual lets System mode run it, alone among the returns.
  [<TestMethod>]
  member _.``[ARMv7] RFE is refused in User and Hyp mode``() =
    let guard = undefinedWhen false "f9100a00"
    Assert.AreEqual<Expr option>(Some userOrHyp, guard)

  [<TestMethod>]
  member _.``[Thumb] RFE restores CPSR from the word it loads``() =
    let text = liftedText true "e9b0c000"
    StringAssert.Contains(text, "CPSR := ((T_3:I32 & 0xff0fffe0:I32) | ")

  [<TestMethod>]
  member _.``[Thumb] SRS stores on the named mode's stack``() =
    let irqSP = AST.ite (modeIsOneOf [ 0x12u ]) !.SP !.SPirq
    let assigned = assignedBy true "e82dc012"
    Assert.AreEqual<Expr option>(Some irqSP, assigned (t32 1))
    Assert.AreEqual<Expr option>(Some(t32 1 .- num 8u), assigned (t32 2))

  /// ERET returns from an exception with SPSR (DDI0406C B9.3.3): from Hyp mode
  /// to ELR_hyp, and from any other PL1 mode to LR, as MOVS PC, LR does.
  [<TestMethod>]
  member _.``[ARMv7] ERET returns to ELR_hyp or to LR``() =
    let target = AST.ite (modeIsOneOf [ 0x1au ]) !.ELRhyp !.LR
    let assigned = assignedBy false "e160006e" (t32 1)
    Assert.AreEqual<Expr option>(Some target, assigned)

  [<TestMethod>]
  member _.``[ARMv7] ERET restores CPSR from SPSR``() =
    StringAssert.Contains(liftedText false "e160006e", ":= SPSR\n")

  /// User mode has no SPSR; ERET there is UNPREDICTABLE, taken as UNDEFINED.
  [<TestMethod>]
  member _.``[ARMv7] ERET is refused in User mode``() =
    let guard = undefinedWhen false "e160006e"
    Assert.AreEqual<Expr option>(Some(modeIsOneOf [ 0x10u ]), guard)

  [<TestMethod>]
  member _.``[ARMv7] ERETNE checks the mode only when it runs``() =
    let text = liftedText false "1160006e"
    let runs = text.IndexOf ":NeedToExec"
    Assert.AreEqual<bool>(true, runs >= 0 && runs < text.IndexOf "UserMode")

  /// SPSR is read before the change of mode replaces it with the new mode's.
  [<TestMethod>]
  member _.``[ARMv7] ERET reads SPSR before changing mode``() =
    let lines = (liftedText false "e160006e").Split '\n'
    let read = lines |> Array.findIndex (fun l -> l.EndsWith ":= SPSR")
    let swap = lines |> Array.findIndex (fun l -> l.StartsWith "SPSR :=")
    Assert.AreEqual<bool>(true, read < swap)

  /// T32's ERET is SUBS PC, LR, #0's encoding, and returns as A32's does.
  [<TestMethod>]
  member _.``[Thumb] ERET returns as the A32 one does``() =
    let a32 = liftedText false "e160006e"
    Assert.AreEqual<string>(a32, liftedText true "f3de8f00")

  /// MRS and MSR (banked register) reach another mode's copy of a register
  /// (B9.3.9 and B9.3.10). Naming the copy that is the live register in the
  /// mode running is UNPREDICTABLE (B9.2.4), as is any of them in User mode,
  /// and both are taken as UNDEFINED.
  [<TestMethod>]
  member _.``[ARMv7] MRS (banked) reads IRQ mode's SP``() =
    let refused = modeIsOneOf [ 0x10u ] .| modeIsOneOf [ 0x12u ]
    Assert.AreEqual<Expr option>(Some !.SPirq, assignedBy false "e1010300" !.R0)
    Assert.AreEqual<Expr option>(Some refused, undefinedWhen false "e1010300")

  [<TestMethod>]
  member _.``[ARMv7] MSR (banked) writes IRQ mode's SP``() =
    Assert.AreEqual<Expr option>(Some !.R0, assignedBy false "e121f300" !.SPirq)
    CollectionAssert.AreEqual([| 0x10u; 0x12u |], refusedModes false "e121f300")

  [<TestMethod>]
  member _.``[ARMv7] MRS (banked) reads FIQ mode's SPSR``() =
    let assigned = assignedBy false "e14e0200" !.R0
    Assert.AreEqual<Expr option>(Some !.SPSRfiq, assigned)

  /// R8_usr to R12_usr are copies in FIQ mode alone: R8 to R12 are User
  /// mode's own in every other mode.
  [<TestMethod>]
  member _.``[ARMv7] MRS (banked) of R8_usr is FIQ mode's alone``() =
    let others = [| 0x10u; 0x12u; 0x13u; 0x16u; 0x17u; 0x1au; 0x1bu; 0x1fu |]
    CollectionAssert.AreEqual(others, refusedModes false "e1000200")

  /// SP_usr is the live SP in User and System mode, and LR_usr the live LR
  /// in those and Hyp mode, whose LR is User mode's (B9.2.4).
  [<TestMethod>]
  member _.``[ARMv7] SP_usr and LR_usr are refused where live``() =
    CollectionAssert.AreEqual([| 0x10u; 0x1fu |], refusedModes false "e1050200")
    let lrLive = [| 0x10u; 0x1au; 0x1fu |]
    CollectionAssert.AreEqual(lrLive, refusedModes false "e1060200")

  /// ELR_hyp and SPSR_hyp are Hyp mode's, which reaches SPSR_hyp as its own.
  [<TestMethod>]
  member _.``[ARMv7] MRS (banked) of ELR_hyp is Hyp mode's alone``() =
    let notHyp = (!.CPSR .& num 0x1fu) != num 0x1au
    let assigned = assignedBy false "e10e0300" !.R0
    Assert.AreEqual<Expr option>(Some !.ELRhyp, assigned)
    Assert.AreEqual<Expr option>(Some notHyp, undefinedWhen false "e10e0300")

  [<TestMethod>]
  member _.``[ARMv7] MSR (banked) of SPSR_hyp writes Hyp mode's SPSR``() =
    let notHyp = (!.CPSR .& num 0x1fu) != num 0x1au
    Assert.AreEqual<Expr option>(Some !.R0, assignedBy false "e16ef300" !.SPSR)
    Assert.AreEqual<Expr option>(Some notHyp, undefinedWhen false "e16ef300")

  /// Monitor mode's registers belong to the Security Extensions, which this
  /// model of the processor does not have: refused in every mode, but behind
  /// the condition, so that MRSEQ with Z clear does nothing.
  [<TestMethod>]
  member _.``[ARMv7] MRS (banked) of SP_mon is refused in every mode``() =
    let all =
      [| 0x10u; 0x11u; 0x12u; 0x13u; 0x16u; 0x17u; 0x1au; 0x1bu; 0x1fu |]
    CollectionAssert.AreEqual(all, refusedModes false "e10d0300")
    let text = liftedText false "010d0300"
    let runs = text.IndexOf ":NeedToExec"
    Assert.AreEqual<bool>(true, runs >= 0 && runs < text.IndexOf "Refused")

  [<TestMethod>]
  member _.``[Thumb] MRS (banked) reads IRQ mode's SP``() =
    Assert.AreEqual<Expr option>(Some !.SPirq, assignedBy true "f3e18030" !.R0)

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

  /// ThumbExpandImm_C (DDI0406C A6.3.2): a rotated constant gives
  /// carry_out = imm32<31>.
  [<TestMethod>]
  member _.``[Thumb] TST (immediate) takes C from a rotated constant``() =
    Assert.AreEqual<bool>(true, writesCarry true "f0114f7f" true)

  [<TestMethod>]
  member _.``[Thumb] MOVS (immediate) takes C from a rotated constant``() =
    Assert.AreEqual<bool>(true, writesCarry true "f45f007f" false)

  [<TestMethod>]
  member _.``[Thumb] ORNS (immediate) takes C from a rotated constant``() =
    Assert.AreEqual<bool>(true, writesCarry true "f071407f" true)

  /// ARMExpandImm_C (DDI0406C A5.2.4), whose carry the parser already passes
  /// and A32 TST already takes.
  [<TestMethod>]
  member _.``[ARMv7] TST (immediate) takes C from a rotated constant``() =
    Assert.AreEqual<bool>(true, writesCarry false "e31104ff" true)

  [<TestMethod>]
  member _.``[ARMv7] TEQ (immediate) takes C from a rotated constant``() =
    Assert.AreEqual<bool>(true, writesCarry false "e33104ff" true)

  [<TestMethod>]
  member _.``[ARMv7] MOVS (immediate) takes C from a rotated constant``() =
    Assert.AreEqual<bool>(true, writesCarry false "e3b008ff" false)

  [<TestMethod>]
  member _.``[ARMv7] MVNS (immediate) takes C from a rotated constant``() =
    Assert.AreEqual<bool>(true, writesCarry false "e3f004ff" true)

  /// Shift_C (DDI0406C A8.4.3) reads the operands as they were before the
  /// instruction, so where the destination is also the amount register the
  /// carry must not come from the result.
  [<TestMethod>]
  member _.``[ARMv7] LSLS (register) with Rd = Rm reads Rm first``() =
    Assert.AreEqual<bool>(false, readsAfterWriting false "e1b01110" R1)

  [<TestMethod>]
  member _.``[Thumb] LSLS.W (register) with Rd = Rm reads Rm first``() =
    Assert.AreEqual<bool>(false, readsAfterWriting true "fa10f101" R1)

  [<TestMethod>]
  member _.``[Thumb] LSLS (register, narrow) with Rdn = Rm reads Rm first``() =
    Assert.AreEqual<bool>(false, readsAfterWriting true "4080" R0)

  [<TestMethod>]
  member _.``[ARMv7] MVNS (immediate shift) with Rd = Rm reads Rm first``() =
    Assert.AreEqual<bool>(false, readsAfterWriting false "e1f00080" R0)

  [<TestMethod>]
  member _.``[Thumb] MVNS.W (immediate shift) with Rd = Rm reads Rm first``() =
    Assert.AreEqual<bool>(false, readsAfterWriting true "ea7f0040" R0)

  [<TestMethod>]
  member _.``[ARMv7] MVNS (register shift) with Rd = Rm reads Rm first``() =
    Assert.AreEqual<bool>(false, readsAfterWriting false "e1f00110" R0)

  [<TestMethod>]
  member _.``[ARMv7] MVNS (register shift) with Rd = Rs reads Rs first``() =
    Assert.AreEqual<bool>(false, readsAfterWriting false "e1f01110" R1)

  [<TestMethod>]
  member _.``[ARMv7] ANDS (register shift) with Rd = Rs reads Rs first``() =
    Assert.AreEqual<bool>(false, readsAfterWriting false "e0101110" R1)

  [<TestMethod>]
  member _.``[ARMv7] ORRS (register shift) with Rd = Rs reads Rs first``() =
    Assert.AreEqual<bool>(false, readsAfterWriting false "e1901130" R1)

  /// The registers of a list of singles take a word each (DDI0406C A8.8.413
  /// VSTM, A8.8.333 VLDM); VPUSH and VPOP are those on SP.
  [<TestMethod>]
  member _.``[ARMv7] VSTM of singles stores one word a register``() =
    let sizes =
      liftedBy false "ec800a04"
      |> Array.choose (function
        | Store(Value = value) -> Some(Expr.typeOf value)
        | _ -> None)
    CollectionAssert.AreEqual([| 32<rt>; 32<rt>; 32<rt>; 32<rt> |], sizes)

  [<TestMethod>]
  member _.``[ARMv7] VSTM of singles writes back a word a register``() =
    Assert.AreEqual<Expr option>(Some(!.R0 .+ num 8u),
                                 assignedBy false "eca00a02" !.R0)

  [<TestMethod>]
  member _.``[ARMv7] VLDM of singles loads one word a register``() =
    let halves = [ !@(Q0, 1); !@(Q0, 2) ]
    let writes =
      writtenBy false "ec900a04"
      |> Array.filter (fun d -> List.contains d halves)
    Assert.AreEqual<int>(4, writes.Length)

  [<TestMethod>]
  member _.``[ARMv7] VPUSH of singles moves SP a word a register``() =
    Assert.AreEqual<Expr option>(Some(!.SP .- num 8u),
                                 assignedBy false "ed2d0a02" !.SP)

  /// T32's unprivileged loads and stores and its exclusives add their
  /// unsigned offset to Rn (DDI0406C A8.8.93 LDRT, A8.8.76 LDREX, A8.8.213
  /// STREX).
  [<TestMethod>]
  member _.``[Thumb] LDRT adds its offset``() =
    let addrs =
      liftedBy true "f8510e03"
      |> Array.choose (function
        | Put(Src = Load(Addr = addr)) -> Some addr
        | _ -> None)
    CollectionAssert.AreEqual([| !.R1 .+ num 3u |], addrs)

  [<TestMethod>]
  member _.``[Thumb] STRT adds its offset``() =
    let addrs =
      liftedBy true "f8410e03"
      |> Array.choose (function
        | Store(Addr = addr) -> Some addr
        | _ -> None)
    CollectionAssert.AreEqual([| !.R1 .+ num 3u |], addrs)

  [<TestMethod>]
  member _.``[Thumb] LDREX adds its offset``() =
    Assert.AreEqual<Expr option>(Some(!.R1 .+ num 16u),
                                 assignedBy true "e8510f04" (t32 1))

  [<TestMethod>]
  member _.``[Thumb] STREX adds its offset``() =
    Assert.AreEqual<Expr option>(Some(!.R1 .+ num 16u),
                                 assignedBy true "e8410204" (t32 1))

  /// CLREX clears the reservation, leaving it on the last byte of memory, so
  /// that a store-exclusive after it fails (DDI0406C A8.8.32).
  [<TestMethod>]
  member _.``[ARMv7] CLREX clears the reservation``() =
    let reservedBy isThumb hex = assignedBy isThumb hex !.ExMonAddr
    let cleared = Some(num 0xffffffffu)
    Assert.AreEqual<Expr option>(cleared, reservedBy false "f57ff01f")
    Assert.AreEqual<Expr option>(cleared, reservedBy true "f3bf8f2f")

  /// VQRSHRN and VQRSHRUN add the rounding constant to the element's integer
  /// value, which no width bounds (DDI0406C A8.8.379), so a lane at the top of
  /// its range rounds up and saturates instead of wrapping.
  [<TestMethod>]
  member _.``[ARMv7] VQRSHRN.S16 rounds 0x7fff to the largest byte``() =
    let q1 = [ !@(Q1, 1), BitVector(0x7fffUL, 64<rt>) ]
    let read = IRRunner.run (liftedBy false "f28f0952") q1
    Assert.AreEqual<uint64>(0x7fUL, (read !@(Q0, 1)).ToUInt64() &&& 0xffUL)

  [<TestMethod>]
  member _.``[ARMv7] VQRSHRUN.S16 rounds 0x7fff to the largest byte``() =
    let q1 = [ !@(Q1, 1), BitVector(0x7fffUL, 64<rt>) ]
    let read = IRRunner.run (liftedBy false "f38f0852") q1
    Assert.AreEqual<uint64>(0xffUL, (read !@(Q0, 1)).ToUInt64() &&& 0xffUL)

  [<TestMethod>]
  member _.``[ARMv7] VQRSHRN.U16 rounds 0xffff to the largest byte``() =
    let q1 = [ !@(Q1, 1), BitVector(0xffffUL, 64<rt>) ]
    let read = IRRunner.run (liftedBy false "f38f0952") q1
    Assert.AreEqual<uint64>(0xffUL, (read !@(Q0, 1)).ToUInt64() &&& 0xffUL)
    Assert.AreEqual<uint64>(1UL, (read !.FPSCR).ToUInt64() >>> 27 &&& 1UL)

  /// SignedSatQ clamps a 64-bit result to [-2^63, 2^63 - 1] (DDI0406C A2.2.1),
  /// so one in range comes out as it is (A8.8.371 VQADD, A8.8.383 VQSUB,
  /// A8.8.374 VQDMULL).
  [<TestMethod>]
  member _.``[ARMv7] VQADD.S64 keeps a negative sum in range``() =
    let inputs =
      [ !@(Q3, 1), BitVector(0xfffffffffffffffbUL, 64<rt>)
        !@(Q3, 2), BitVector(3UL, 64<rt>) ]
    let read = IRRunner.run (liftedBy false "f2360017") inputs
    Assert.AreEqual<uint64>(0xfffffffffffffffeUL, (read !@(Q0, 1)).ToUInt64())

  [<TestMethod>]
  member _.``[ARMv7] VQSUB.S64 keeps a negative difference in range``() =
    let inputs =
      [ !@(Q3, 1), BitVector(0xfffffffffffffffbUL, 64<rt>)
        !@(Q3, 2), BitVector(3UL, 64<rt>) ]
    let read = IRRunner.run (liftedBy false "f2360217") inputs
    Assert.AreEqual<uint64>(0xfffffffffffffff8UL, (read !@(Q0, 1)).ToUInt64())

  [<TestMethod>]
  member _.``[ARMv7] VQDMULL.S32 keeps products in range``() =
    let inputs =
      [ !@(Q2, 1), BitVector(0x00000005fffffffdUL, 64<rt>)
        !@(Q2, 2), BitVector(0x0000000700000005UL, 64<rt>) ]
    let read = IRRunner.run (liftedBy false "f2a40d05") inputs
    Assert.AreEqual<uint64>(0xffffffffffffffe2UL, (read !@(Q0, 1)).ToUInt64())
    Assert.AreEqual<uint64>(70UL, (read !@(Q0, 2)).ToUInt64())

  [<TestMethod>]
  member _.``[ARMv7] VQADD.S64 saturates past the largest value``() =
    let inputs =
      [ !@(Q1, 1), BitVector(0x7fffffffffffffffUL, 64<rt>)
        !@(Q1, 2), BitVector(1UL, 64<rt>) ]
    let read = IRRunner.run (liftedBy false "f2320013") inputs
    Assert.AreEqual<uint64>(0x7fffffffffffffffUL, (read !@(Q0, 1)).ToUInt64())
    Assert.AreEqual<uint64>(1UL, (read !.FPSCR).ToUInt64() >>> 27 &&& 1UL)

  /// A by-scalar operation multiplies every element by the one lane Dm[x],
  /// read before any element is written (DDI0406C A8.8.373 VQDMULH, A8.8.377
  /// VQRDMULH, A8.8.374 VQDMULL, A8.8.353 VMUL (by scalar)).
  [<TestMethod>]
  member _.``[ARMv7] VQDMULH.S16 by scalar takes one lane``() =
    let inputs =
      [ !@(Q0, 2), BitVector(0x0400030002000100UL, 64<rt>)
        !@(Q1, 1), BitVector(0x4000300020001000UL, 64<rt>) ]
    let read = IRRunner.run (liftedBy false "f2910c4a") inputs
    Assert.AreEqual<uint64>(0x010000c000800040UL, (read !@(Q0, 1)).ToUInt64())

  [<TestMethod>]
  member _.``[ARMv7] VQRDMULH.S16 by scalar takes one lane``() =
    let inputs =
      [ !@(Q0, 2), BitVector(0x0400030002000100UL, 64<rt>)
        !@(Q1, 1), BitVector(0x4000300020001000UL, 64<rt>) ]
    let read = IRRunner.run (liftedBy false "f2910d4a") inputs
    Assert.AreEqual<uint64>(0x010000c000800040UL, (read !@(Q0, 1)).ToUInt64())

  [<TestMethod>]
  member _.``[ARMv7] VQDMULL.S16 by scalar takes one lane``() =
    let inputs =
      [ !@(Q1, 1), BitVector(0x4000300020001000UL, 64<rt>)
        !@(Q1, 2), BitVector(0x7fff8000c000e000UL, 64<rt>) ]
    let read = IRRunner.run (liftedBy false "f2920b4b") inputs
    Assert.AreEqual<uint64>(0xf0000000f8000000UL, (read !@(Q0, 1)).ToUInt64())
    Assert.AreEqual<uint64>(0xe0000000e8000000UL, (read !@(Q0, 2)).ToUInt64())

  [<TestMethod>]
  member _.``[ARMv7] VQDMULH.S16 by scalar works on Q registers``() =
    let inputs =
      [ !@(Q1, 1), BitVector(0x4000300020001000UL, 64<rt>)
        !@(Q1, 2), BitVector(0x7fff8000c000e000UL, 64<rt>)
        !@(Q2, 1), BitVector(0x0011002200330044UL, 64<rt>) ]
    let read = IRRunner.run (liftedBy false "f3920c4c") inputs
    Assert.AreEqual<uint64>(0x00190013000c0006UL, (read !@(Q0, 1)).ToUInt64())
    Assert.AreEqual<uint64>(0x0032ffcdffe6fff3UL, (read !@(Q0, 2)).ToUInt64())

  [<TestMethod>]
  member _.``[ARMv7] VMUL.I32 by a scalar inside Qd reads it first``() =
    let inputs =
      [ !@(Q1, 1), BitVector(0x4000000010000000UL, 64<rt>)
        !@(Q1, 2), BitVector(0x7fffffff80000000UL, 64<rt>) ]
    let read = IRRunner.run (liftedBy false "f3a22863") inputs
    Assert.AreEqual<uint64>(0xc0000000f0000000UL, (read !@(Q1, 1)).ToUInt64())
    Assert.AreEqual<uint64>(0x0000000180000000UL, (read !@(Q1, 2)).ToUInt64())

  /// VUZP of doublewords unzips D[m]:D[d], so the destination's lanes come
  /// first: its even lanes, then the source's, land in the destination
  /// (DDI0406C A8.8.423).
  [<TestMethod>]
  member _.``[ARMv7] VUZP of doublewords reads the destination first``() =
    let unzip hex dd dm =
      let inputs =
        [ dd, BitVector(0x0706050403020100UL, 64<rt>)
          dm, BitVector(0x0f0e0d0c0b0a0908UL, 64<rt>) ]
      let read = IRRunner.run (liftedBy false hex) inputs
      (read dd).ToUInt64(), (read dm).ToUInt64()
    Assert.AreEqual((0x0e0c0a0806040200UL, 0x0f0d0b0907050301UL),
                    unzip "f3b20101" !@(Q0, 1) !@(Q0, 2))
    Assert.AreEqual((0x0d0c090805040100UL, 0x0f0e0b0a07060302UL),
                    unzip "f3f6012f" !@(Q8, 1) !@(Q15, 2))

  /// <summary>
  /// The shifts by a register shift right for a negative amount (DDI0406C
  /// A8.8.397, A8.8.380, A8.8.389): VSHL.S16 takes -1, 3, -16 and -20 and
  /// leaves -1, 8, 0 and -1; a right shift of the element's width or more
  /// leaves nothing of an unsigned element, so VQSHL.U16 by -16 and -17
  /// gives zero; and rounding by the width itself carries an unsigned
  /// element's top bit, so VRSHL.U32 of 2^31 by -32 gives one.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] Shifts by a register go right for a negative amount``() =
    let shifted hex (dst, src, amounts) (vs: uint64) (ns: uint64) =
      let inputs =
        [ src, BitVector(vs, 64<rt>); amounts, BitVector(ns, 64<rt>) ]
      (IRRunner.run (liftedBy false hex) inputs dst).ToUInt64()
    let d0d1d2 = !@(Q0, 1), !@(Q0, 2), !@(Q1, 1)
    let d3d4d5 = !@(Q1, 2), !@(Q2, 1), !@(Q2, 2)
    let vshl = shifted "f2120401" d0d1d2
    let vqshl = shifted "f3153414" d3d4d5
    let vrshl = shifted "f3253504" d3d4d5
    Assert.AreEqual<uint64>(0xffff00000008ffffUL,
                            vshl 0x80007fff0001ffffUL 0x00ec00f0000300ffUL)
    Assert.AreEqual<uint64>(0x8000000100000000UL,
                            vqshl 0x00018000ffffffffUL 0x000f00f100ef00f0UL)
    Assert.AreEqual<uint64>(0x0000000000000001UL,
                            vrshl 0x7fffffff80000000UL 0x000000e0000000e0UL)

  /// <summary>
  /// A VFP operation rounds in the direction FPSCR.RMode names, which is what
  /// an expression no RoundCtrl encloses rounds by; an Advanced SIMD one
  /// rounds to nearest whatever FPSCR says (DDI0406C A2.7), so a RoundCtrl
  /// naming nearest encloses it.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VADD.F32 on S registers rounds as FPSCR says``() =
    let text = liftedBy false "ee320a04" |> Array.map string |> String.concat ""
    Assert.AreEqual<bool>(false, text.Contains "rnd(", text)

  [<TestMethod>]
  member _.``[ARMv7] VADD.F32 on D registers rounds to nearest``() =
    let text = liftedBy false "f2010d02" |> Array.map string |> String.concat ""
    Assert.AreEqual<bool>(true, text.Contains "rnd(0x0:I8", text)

  /// FPSCR.FZ flushes a result tiny before rounding to zero, raising
  /// Underflow alone: 2^-126 times a half is 2^-127, a subnormal.
  [<TestMethod>]
  member _.``[ARMv7] VMUL.F32 flushes a tiny product under FZ``() =
    let ds = [ 2, 0x00800000UL; 4, 0x3f000000UL ]
    let d0, _, fpscr = fpRun "ee220a04" 0x01000000u ds
    Assert.AreEqual<uint64 * uint32>((0UL, 0x01000008u), (d0, fpscr))

  /// And a denormal operand is a zero of its sign, raising Input Denormal.
  [<TestMethod>]
  member _.``[ARMv7] VADD.F32 flushes a denormal operand under FZ``() =
    let ds = [ 2, 0x80000001UL; 4, 0x3f800000UL ]
    let d0, _, fpscr = fpRun "ee320a04" 0x01000000u ds
    Assert.AreEqual<uint64 * uint32>((0x3f800000UL, 0x01000080u), (d0, fpscr))

  /// Advanced SIMD flushes whatever FPSCR.FZ says, and still sets the flags.
  [<TestMethod>]
  member _.``[ARMv7] VADD.F32 on D registers always flushes``() =
    let ds = [ 1, 0x3f80000000000001UL; 2, 0x3f8000003f800000UL ]
    let d0, _, fpscr = fpRun "f2010d02" 0u ds
    Assert.AreEqual<uint64 * uint32>((0x400000003f800000UL, 0x80u), (d0, fpscr))

  /// <summary>
  /// VCVTB.F16.F32 writes the half it narrows to into the bottom of Sd and
  /// leaves the top: 1 + 2^-11 is a tie, and goes to the even 1.0. VCVTT
  /// writes the top and leaves the bottom.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VCVTB.F16.F32 keeps the top of Sd``() =
    let ds = [ 0, 0x3f800000UL; 2, 0x3f801000UL ]
    let d0, _, fpscr = fpRun "eeb30a42" 0u ds
    Assert.AreEqual<uint64 * uint32>((0x3f803c00UL, 0x10u), (d0, fpscr))

  [<TestMethod>]
  member _.``[ARMv7] VCVTT.F16.F32 keeps the bottom of Sd``() =
    let ds = [ 0, 0x3f800000UL; 2, 0x3f801000UL ]
    let d0, _, fpscr = fpRun "eeb30ac2" 0u ds
    Assert.AreEqual<uint64 * uint32>((0x3c000000UL, 0x10u), (d0, fpscr))

  /// VCVTB.F32.F16 reads the bottom half of Sm, a NaN coming back quiet.
  [<TestMethod>]
  member _.``[ARMv7] VCVTB.F32.F16 widens the bottom of Sm``() =
    let d0, _, fpscr = fpRun "eeb20a42" 0u [ 2, 0x3c007d00UL ]
    Assert.AreEqual<uint64 * uint32>((0x7fe00000UL, 1u), (d0, fpscr))

  /// <summary>
  /// VCMP sets FPSCR's NZCV to 0011 for an unordered pair and raises Invalid
  /// for a signalling NaN; VCMPE raises it for a quiet one too, and VCMP does
  /// not.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VCMP of a signalling NaN raises Invalid``() =
    let _, _, fpscr = fpRun "eeb42a44" 0u [ 2, 0x7fa00000UL ]
    Assert.AreEqual<uint32>(0x30000001u, fpscr)

  [<TestMethod>]
  member _.``[ARMv7] VCMP of a quiet NaN raises nothing``() =
    let _, _, fpscr = fpRun "eeb42a44" 0u [ 2, 0x7fc00000UL ]
    Assert.AreEqual<uint32>(0x30000000u, fpscr)

  [<TestMethod>]
  member _.``[ARMv7] VCMPE of a quiet NaN raises Invalid``() =
    let _, _, fpscr = fpRun "eeb42ac4" 0u [ 2, 0x7fc00000UL ]
    Assert.AreEqual<uint32>(0x30000001u, fpscr)

  [<TestMethod>]
  member _.``[ARMv7] VCMP orders less than``() =
    let _, _, fpscr = fpRun "eeb42a44" 0u [ 2, 0x3f800000UL; 4, 0x40000000UL ]
    Assert.AreEqual<uint32>(0x80000000u, fpscr)

  /// The Advanced SIMD floating-point forms the issue found unlifted, or
  /// throwing, or rejected by a Debug build's type check, which these tests
  /// run under.
  [<TestMethod>]
  member _.``[ARMv7] The Advanced SIMD F32 forms lift``() =
    [ "f2020e44"
      "f2020f44"
      "f3020d04"
      "f3220d04"
      "f3b90742"
      "f2020c54"
      "f3b90702"
      "f2020c14"
      "eebd0a42"
      "eebe0aef" ]
    |> List.iter (fun hex -> Assert.AreEqual<bool>(true, liftsToIR hex, hex))

  /// VCEQ.F32 compares lane by lane: all ones where equal, which a zero of
  /// either sign is, and never with a NaN.
  [<TestMethod>]
  member _.``[ARMv7] VCEQ.F32 compares every lane``() =
    let ds =
      [ 2, 0x800000003f800000UL
        3, 0x7fc000003f800000UL
        4, 0x000000003f800000UL
        5, 0x7fc0000040000000UL ]
    let d0, d1, _ = fpRun "f2020e44" 0u ds
    Assert.AreEqual<uint64 * uint64>((0xffffffffffffffffUL, 0UL), (d0, d1))

  /// VMAX.F32 answers the default NaN for a NaN operand, Advanced SIMD being
  /// in default-NaN mode, and raises Invalid for a signalling one.
  [<TestMethod>]
  member _.``[ARMv7] VMAX.F32 answers the default NaN``() =
    let ds = [ 1, 0x7f80000140000000UL; 2, 0x3f8000003f800000UL ]
    let d0, _, fpscr = fpRun "f2010f02" 0u ds
    Assert.AreEqual<uint64 * uint32>((0x7fc0000040000000UL, 1u), (d0, fpscr))

  /// VABS.F32 on a quadword clears the sign of all four lanes.
  [<TestMethod>]
  member _.``[ARMv7] VABS.F32 on Q registers clears every sign``() =
    let ds = [ 2, 0x80000000bf800000UL; 3, 0xffc00000c0000000UL ]
    let d0, d1, _ = fpRun "f3b90742" 0u ds
    Assert.AreEqual<uint64 * uint64>((0x3f800000UL, 0x7fc0000040000000UL),
                                     (d0, d1))

  /// VNEG.F32 on a doubleword negates both lanes.
  [<TestMethod>]
  member _.``[ARMv7] VNEG.F32 on D registers negates both lanes``() =
    let d0, _, _ = fpRun "f3b90782" 0u [ 2, 0x3f800000bf800000UL ]
    Assert.AreEqual<uint64>(0xbf8000003f800000UL, d0)

  /// <summary>
  /// VMUL, VMLA and VMLS work lane by lane on singles (A8.8.352, A8.8.338,
  /// A8.8.339): with d0 = {1.0, 1.0}, d1 = {1.5, 2.0} and d2 = {3.0, -0.5}.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VMUL.F32 on D registers multiplies lanes``() =
    let ds =
      [ 0, 0x3f8000003f800000UL
        1, 0x400000003fc00000UL
        2, 0xbf00000040400000UL ]
    let d0, _, _ = fpRun "f3010d12" 0u ds
    Assert.AreEqual<uint64>(0xbf80000040900000UL, d0)

  [<TestMethod>]
  member _.``[ARMv7] VMLA.F32 on D registers accumulates lanes``() =
    let ds =
      [ 0, 0x3f8000003f800000UL
        1, 0x400000003fc00000UL
        2, 0xbf00000040400000UL ]
    let d0, _, _ = fpRun "f2010d12" 0u ds
    Assert.AreEqual<uint64>(0x0000000040b00000UL, d0)

  [<TestMethod>]
  member _.``[ARMv7] VMLA.F32 by scalar accumulates lanes``() =
    let ds =
      [ 0, 0x3f8000003f800000UL
        1, 0x400000003fc00000UL
        2, 0xbf00000040400000UL ]
    let d0, _, _ = fpRun "f2a10162" 0u ds
    Assert.AreEqual<uint64>(0x000000003e800000UL, d0)

  /// VFMA.F32 on a doubleword is fused lane by lane.
  [<TestMethod>]
  member _.``[ARMv7] VFMA.F32 on D registers fuses every lane``() =
    let ds =
      [ 0, 0x3f8000003f800000UL
        2, 0x400000003fc00000UL
        4, 0xbf00000040400000UL ]
    let d0, _, _ = fpRun "f2020c14" 0u ds
    Assert.AreEqual<uint64>(0x0000000040b00000UL, d0)

  /// <summary>
  /// VCVT to an integer is FPToFixed, which saturates and raises Invalid for
  /// what does not fit: 5e9 is 0x7fffffff signed and 0xffffffff unsigned
  /// (A8.8.307).
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VCVT.S32.F32 saturates 5e9``() =
    let d0, _, fpscr = fpRun "eebd0ac1" 0u [ 1, 0x4f9502f9UL ]
    Assert.AreEqual<uint64 * uint32>((0x7fffffffUL, 1u), (d0, fpscr))

  [<TestMethod>]
  member _.``[ARMv7] VCVT.U32.F32 saturates 5e9``() =
    let d0, _, fpscr = fpRun "eebc0ac1" 0u [ 1, 0x4f9502f9UL ]
    Assert.AreEqual<uint64 * uint32>((0xffffffffUL, 1u), (d0, fpscr))

  [<TestMethod>]
  member _.``[ARMv7] VCVT.U32.F32 of -1.5 is zero``() =
    let d0, _, fpscr = fpRun "eebc0ac1" 0u [ 1, 0xbfc00000UL ]
    Assert.AreEqual<uint64 * uint32>((0UL, 1u), (d0, fpscr))

  /// VCVTR rounds as FPSCR names, to nearest here, and VCVT toward zero.
  [<TestMethod>]
  member _.``[ARMv7] VCVTR.S32.F32 rounds 3.5 to 4``() =
    let d0, _, fpscr = fpRun "eebd0a42" 0u [ 2, 0x40600000UL ]
    Assert.AreEqual<uint64 * uint32>((4UL, 0x10u), (d0, fpscr))

  [<TestMethod>]
  member _.``[ARMv7] VCVT.S32.F32 rounds 3.5 to 3``() =
    let d0, _, fpscr = fpRun "eebd0ac2" 0u [ 2, 0x40600000UL ]
    Assert.AreEqual<uint64 * uint32>((3UL, 0x10u), (d0, fpscr))

  /// The fixed-point VCVT scales by its fraction bits and rounds toward zero:
  /// 1.75 with one fraction bit is 3.
  [<TestMethod>]
  member _.``[ARMv7] VCVT.S32.F32 with a fraction bit gives 3``() =
    let d0, _, fpscr = fpRun "eebe0aef" 0u [ 0, 0x3fe00000UL ]
    Assert.AreEqual<uint64 * uint32>((3UL, 0x10u), (d0, fpscr))

  /// <summary>
  /// What each arithmetic form computes, one value apiece: VSUB takes its
  /// second operand from its first, VDIV divides, VSQRT takes the root, VMLS
  /// and VFMS subtract the product from the destination, and VABS clears the
  /// sign.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VSUB.F32 takes the second operand from the first``() =
    let d0, _, fpscr = fpRun "ee320a44" 0u [ 2, 0x40400000UL; 4, 0x3f800000UL ]
    Assert.AreEqual<uint64 * uint32>((0x40000000UL, 0u), (d0, fpscr))

  [<TestMethod>]
  member _.``[ARMv7] VDIV.F32 divides``() =
    let d0, _, fpscr = fpRun "ee820a04" 0u [ 2, 0x40c00000UL; 4, 0x40000000UL ]
    Assert.AreEqual<uint64 * uint32>((0x40400000UL, 0u), (d0, fpscr))

  [<TestMethod>]
  member _.``[ARMv7] VSQRT.F32 takes the square root``() =
    let d0, _, fpscr = fpRun "eeb10ac2" 0u [ 2, 0x40800000UL ]
    Assert.AreEqual<uint64 * uint32>((0x40000000UL, 0u), (d0, fpscr))

  [<TestMethod>]
  member _.``[ARMv7] VMLS.F32 subtracts the product``() =
    let ds = [ 0, 0x41200000UL; 2, 0x40000000UL; 4, 0x40400000UL ]
    let d0, _, fpscr = fpRun "ee020a44" 0u ds
    Assert.AreEqual<uint64 * uint32>((0x40800000UL, 0u), (d0, fpscr))

  [<TestMethod>]
  member _.``[ARMv7] VFMS.F32 subtracts the fused product``() =
    let ds = [ 0, 0x41200000UL; 2, 0x40000000UL; 4, 0x40400000UL ]
    let d0, _, fpscr = fpRun "eea20a44" 0u ds
    Assert.AreEqual<uint64 * uint32>((0x40800000UL, 0u), (d0, fpscr))

  [<TestMethod>]
  member _.``[ARMv7] VABS.F32 on S registers clears the sign``() =
    let d0, _, fpscr = fpRun "eeb00ac2" 0u [ 2, 0xc0000000UL ]
    Assert.AreEqual<uint64 * uint32>((0x40000000UL, 0u), (d0, fpscr))

  /// <summary>
  /// The Advanced SIMD compares and the lane operations, one value apiece:
  /// VCLT #0 is false for zero, which tells it from VCLE; VACGT compares
  /// magnitudes; VABD is the absolute difference; and VPADD adds the pairs of
  /// its first operand into the low lane and of its second into the high.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VCLT.F32 #0 is false for zero``() =
    let d0, _, _ = fpRun "f3b90602" 0u [ 2, 0xbf80000000000000UL ]
    Assert.AreEqual<uint64>(0xffffffff00000000UL, d0)

  [<TestMethod>]
  member _.``[ARMv7] VACGT.F32 compares magnitudes``() =
    let ds = [ 1, 0x3f800000c0400000UL; 2, 0x4000000040000000UL ]
    let d0, _, _ = fpRun "f3210e12" 0u ds
    Assert.AreEqual<uint64>(0x00000000ffffffffUL, d0)

  [<TestMethod>]
  member _.``[ARMv7] VABD.F32 is the absolute difference``() =
    let ds = [ 1, 0x40a000003f800000UL; 2, 0x4000000040800000UL ]
    let d0, _, _ = fpRun "f3210d02" 0u ds
    Assert.AreEqual<uint64>(0x4040000040400000UL, d0)

  [<TestMethod>]
  member _.``[ARMv7] VPADD.F32 adds the pairs of each operand``() =
    let ds = [ 1, 0x400000003f800000UL; 2, 0x4080000040400000UL ]
    let d0, _, _ = fpRun "f3010d02" 0u ds
    Assert.AreEqual<uint64>(0x40e0000040400000UL, d0)

  /// VRECPS of an infinity and a zero is 2.0, whichever is which.
  [<TestMethod>]
  member _.``[ARMv7] VRECPS.F32 of an infinity and a zero is two``() =
    let ds = [ 1, 0x000000007f800000UL; 2, 0x7f80000000000000UL ]
    let d0, _, _ = fpRun "f2010f12" 0u ds
    Assert.AreEqual<uint64>(0x4000000040000000UL, d0)

  /// <summary>
  /// A signalling NaN is the result before a quiet one, and of two signalling
  /// NaNs the first operand's, made quiet (FPProcessNaNs, DDI0406C A2.7.6).
  /// The Invalid it raises comes from the exception query, which the runner
  /// answers with nothing.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VADD.F32 answers a signalling NaN first``() =
    let ds = [ 2, 0x7fc00000UL; 4, 0x7f800001UL ]
    let d0, _, _ = fpRun "ee320a04" 0u ds
    Assert.AreEqual<uint64>(0x7fc00001UL, d0)

  [<TestMethod>]
  member _.``[ARMv7] VADD.F32 answers the first of two signalling NaNs``() =
    let ds = [ 2, 0x7f800002UL; 4, 0x7f800001UL ]
    let d0, _, _ = fpRun "ee320a04" 0u ds
    Assert.AreEqual<uint64>(0x7fc00002UL, d0)

  /// VMAX takes +0 over -0 and VMIN -0 over +0, whichever operand holds which.
  [<TestMethod>]
  member _.``[ARMv7] VMAX.F32 takes plus zero over minus zero``() =
    let ds = [ 1, 0x8000000000000000UL; 2, 0x0000000080000000UL ]
    let d0, _, _ = fpRun "f2010f02" 0u ds
    Assert.AreEqual<uint64>(0UL, d0)

  [<TestMethod>]
  member _.``[ARMv7] VMIN.F32 takes minus zero over plus zero``() =
    let ds = [ 1, 0x8000000000000000UL; 2, 0x0000000080000000UL ]
    let d0, _, _ = fpRun "f2210f02" 0u ds
    Assert.AreEqual<uint64>(0x8000000080000000UL, d0)

  /// <summary>
  /// FPSCR.AHP picks the alternative half format, which has no infinity: a
  /// single past its largest magnitude, 131008.0, such as 2^17, saturates to
  /// 0x7fff and raises Invalid alone (DDI0406C A2.7.4).
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VCVTB.F16.F32 saturates under AHP``() =
    let d0, _, fpscr = fpRun "eeb30a42" 0x04000000u [ 2, 0x48000000UL ]
    Assert.AreEqual<uint64 * uint32>((0x7fffUL, 0x04000001u), (d0, fpscr))

  /// FPSCR.DN makes the NaN a half widens to the default one.
  [<TestMethod>]
  member _.``[ARMv7] VCVTB.F32.F16 answers the default NaN under DN``() =
    let d0, _, fpscr = fpRun "eeb20a42" 0x02000000u [ 2, 0x7d00UL ]
    Assert.AreEqual<uint64 * uint32>((0x7fc00000UL, 0x02000001u), (d0, fpscr))

  /// <summary>
  /// The narrowing to a half rounds the way FPSCR.RMode names, which it does
  /// itself: toward plus infinity, 1 + 2^-11 is 1 + 2^-10 rather than 1.0.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VCVTB.F16.F32 rounds as RMode names``() =
    let ds = [ 0, 0x3f800000UL; 2, 0x3f801000UL ]
    let d0, _, fpscr = fpRun "eeb30a42" 0x00400000u ds
    Assert.AreEqual<uint64 * uint32>((0x3f803c01UL, 0x00400010u), (d0, fpscr))

  /// <summary>
  /// A short vector of doubles wraps round its bank of four: VADD.F64 d7, d5,
  /// d6 with Len = 1 is d7 = d5 + d6, then d4 = d6 + d7. A destination in the
  /// first bank of the upper half, D16-D19, keeps the instruction scalar.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VADD.F64 wraps round its bank of four``() =
    let ds = [ 5, 0x3ff0000000000000UL; 6, 0x4000000000000000UL ]
    let inputs =
      (!.FPSCR, BitVector(0x10000u, 32<rt>))
      :: [ for n, v in ds -> dReg n, BitVector(v, 64<rt>) ]
    let read = IRRunner.run (liftedBy false "ee357b06") inputs
    Assert.AreEqual<uint64>(0x4008000000000000UL, (read (dReg 7)).ToUInt64())
    Assert.AreEqual<uint64>(0x4014000000000000UL, (read (dReg 4)).ToUInt64())

  [<TestMethod>]
  member _.``[ARMv7] VADD.F64 into d16 stays scalar under Len 1``() =
    let ds = [ 17, 0x3ff0000000000000UL; 18, 0x4000000000000000UL ]
    let inputs =
      (!.FPSCR, BitVector(0x10000u, 32<rt>))
      :: [ for n, v in ds -> dReg n, BitVector(v, 64<rt>) ]
    let read = IRRunner.run (liftedBy false "ee710ba2") inputs
    Assert.AreEqual<uint64>(0x4008000000000000UL, (read (dReg 16)).ToUInt64())
    Assert.AreEqual<uint64>(0x3ff0000000000000UL, (read (dReg 17)).ToUInt64())

  /// <summary>
  /// With FPSCR.Len = 1, VADD.F32 s8, s16, s24 is two additions: s8 and s9,
  /// from s16 and s17 and from s24 and s25 (DDI0406C Appendix D11). With a
  /// destination in the first bank, s0-s7, it stays scalar.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VADD.F32 adds a short vector of two under Len 1``() =
    let one, two = 0x3f800000UL, 0x40000000UL
    let ds = [ 8, (two <<< 32) ||| one; 12, (one <<< 32) ||| one ]
    let inputs =
      (!.FPSCR, BitVector(0x10000u, 32<rt>))
      :: [ for n, v in ds -> dReg n, BitVector(v, 64<rt>) ]
    let read = IRRunner.run (liftedBy false "ee384a0c") inputs
    Assert.AreEqual<uint64>(0x4040000040000000UL, (read (dReg 4)).ToUInt64())

  [<TestMethod>]
  member _.``[ARMv7] VADD.F32 into s0 stays scalar under Len 1``() =
    let one = 0x3f800000UL
    let ds = [ 2, one; 4, (one <<< 32) ||| one ]
    let d0, _, _ = fpRun "ee320a04" 0x10000u ds
    Assert.AreEqual<uint64>(0x40000000UL, d0)

  /// <summary>
  /// A second operand in the first bank is a scalar to every step, and the
  /// steps wrap round inside the bank: VMUL.F32 s14, s15, s3 with Len = 1
  /// and a stride of two is s14 = s15 * s3, then s8 = s9 * s3.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VMUL.F32 wraps round its bank with a scalar``() =
    let one, two = 0x3f800000UL, 0x40000000UL
    let ds = [ 7, one <<< 32; 4, one <<< 32; 1, two <<< 32 ]
    let inputs =
      (!.FPSCR, BitVector(0x310000u, 32<rt>))
      :: [ for n, v in ds -> dReg n, BitVector(v, 64<rt>) ]
    let read = IRRunner.run (liftedBy false "ee277aa1") inputs
    Assert.AreEqual<uint64>(0x3f80000040000000UL, (read (dReg 7)).ToUInt64())
    Assert.AreEqual<uint64>(0x3f80000040000000UL, (read (dReg 4)).ToUInt64())
