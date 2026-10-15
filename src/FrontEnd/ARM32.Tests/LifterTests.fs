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
open B2R2.BinIR
open B2R2.FrontEnd.ARM32.Tests.ManualLifting

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

  /// The statements one A32 encoding lifts to under an ISA that names VFP
  /// short vectors, without which Len or Stride makes a VFP instruction
  /// UNDEFINED.
  let liftedWithShortVectors (hex: string) =
    let flags = int ARMv7Extension.ShortVectors
    let shvec = ISA(Architecture.ARMv7, Endian.Big, WordSize.Bit32, flags)
    let parser = Parser(shvec, false, reader) :> IInstructionParsable
    let builder = ILowUIRBuilder.Default(shvec, regFactory, LowUIRStream())
    let ins = parser.Parse(ByteArray.ofHexString hex, 0UL)
    ins.Translate builder

  /// The statements one T32 encoding lifts to as the one instruction of an
  /// IT EQ block, parsed where the IT instruction leaves ITSTATE at 0x08.
  let liftedInITBlock (hex: string) =
    let parser = Parser(isa, true, reader)
    (parser :> IModeSwitchable).ITState <- 0x08uy
    let builder = ILowUIRBuilder.Default(isa, regFactory, LowUIRStream())
    let bytes = ByteArray.ofHexString hex
    let ins = (parser :> IInstructionParsable).Parse(bytes, 0UL)
    ins.Translate builder

  (* Dn is the half n % 2 of Q(n / 2), and S(2n) and S(2n + 1) are the low
     and the high word of Dn *)
  let dReg n = !@(enum<Register> (int Q0 + n / 2), n % 2 + 1)

  /// FPSCR's status fields, which the front end keeps in FPSR apart from the
  /// controls it keeps in FPSCR: N, Z, C, V, QC and the cumulative flags.
  let fpscrStatus = 0xf800009fu

  /// What an A32 encoding leaves in D0, D1 and FPSCR, run with FPSCR and the
  /// D registers given. FPSCR is its two halves, as VMRS reads it.
  let fpRun hex (fpscr: uint32) (ds: (int * uint64) list) =
    let inputs =
      (!.FPSCR, BitVector(fpscr &&& ~~~fpscrStatus, 32<rt>))
      :: (!.FPSR, BitVector(fpscr &&& fpscrStatus, 32<rt>))
      :: [ for n, v in ds -> dReg n, BitVector(v, 64<rt>) ]
    let read = IRRunner.run (liftedBy false hex) inputs
    let d n = (read (dReg n)).ToUInt64()
    let after = (read !.FPSCR).ToUInt64() ||| (read !.FPSR).ToUInt64()
    d 0, d 1, uint32 after

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

  /// The C an encoding leaves in CPSR, run with C given and with every
  /// register else zero.
  let carryAfter isThumb hex carryIn =
    let cpsr = if carryIn then 0x20000000u else 0u
    let read =
      IRRunner.run (liftedBy isThumb hex) [ !.CPSR, BitVector(cpsr, 32<rt>) ]
    (read !.CPSR).ToUInt64() &&& 0x20000000UL <> 0UL

  /// Whether one encoding sets C to the constant given, whatever C was, as a
  /// flag-setting logical instruction does from a rotated immediate:
  /// imm32<31>.
  let writesCarry isThumb hex set =
    carryAfter isThumb hex true = set && carryAfter isThumb hex false = set

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

  /// The loads the registers some statements write are read from, in order.
  let loadsIn (stmts: Stmt[]) =
    let rec loads e =
      match e with
      | Load(Addr = a) ->
        e :: loads a
      | UnOp(Operand = x) | Cast(Operand = x) | Extract(Operand = x) ->
        loads x
      | BinOp(Left = x; Right = y) | RelOp(Left = x; Right = y) ->
        loads x @ loads y
      | Ite(Cond = c; TrueExpr = x; FalseExpr = y) ->
        loads c @ loads x @ loads y
      | _ ->
        []
    stmts
    |> Array.toList
    |> List.collect (function
      | Put(Src = e) -> loads e
      | _ -> [])

  /// The widths of the loads the registers one encoding writes are read
  /// from, in order.
  let loadWidthsBy isThumb hex =
    loadsIn (liftedBy isThumb hex) |> List.map Expr.typeOf

  /// The statements one A32 encoding lifts to where memory is
  /// little-endian, which every other test here takes big-endian.
  let liftedLittle (hex: string) =
    let little = ISA(Architecture.ARMv7, Endian.Little)
    let parser = Parser(little, false, reader) :> IInstructionParsable
    let builder = ILowUIRBuilder.Default(little, regFactory, LowUIRStream())
    let ins = parser.Parse(ByteArray.ofHexString hex, 0UL)
    ins.Translate builder

  /// What an encoding leaves in R0, run with R1 and R2 given.
  let r0After isThumb hex (r1: uint32) (r2: uint32) =
    let inputs = [ !.R1, BitVector(r1, 32<rt>); !.R2, BitVector(r2, 32<rt>) ]
    let read = IRRunner.run (liftedBy isThumb hex) inputs
    uint32 ((read !.R0).ToUInt64())

  /// What an encoding leaves in Q0, low doubleword first, run with Q0, Q1 and
  /// Q2 holding what optest-arm/probes/v8crypto-vectors.c gives them.
  let qRun isThumb hex =
    let ds =
      [ 0x0123456789abcdefUL
        0xfedcba9876543210UL
        0x0f1e2d3c4b5a6978UL
        0x8796a5b4c3d2e1f0UL
        0x1122334455667788UL
        0x99aabbccddeeff00UL ]
    let inputs = ds |> List.mapi (fun n v -> dReg n, BitVector(v, 64<rt>))
    let read = IRRunner.run (liftedBy isThumb hex) inputs
    (read (dReg 0)).ToUInt64(), (read (dReg 1)).ToUInt64()

  /// What an A32 encoding leaves in S0 and FPSCR, run with FPSCR, S1 and S2
  /// given: S1 is the high word of D0, and S2 the low word of D1.
  let s0After hex (fpscr: uint32) (s1: uint32) (s2: uint32) =
    let d0, _, fpscr = fpRun hex fpscr [ 0, uint64 s1 <<< 32; 1, uint64 s2 ]
    uint32 d0, fpscr

  /// What an A32 VSEL leaves in S0, run with CPSR given and with S1 and S2
  /// holding 0x11111111 and 0x22222222.
  let selAfter hex (cpsr: uint32) =
    let inputs =
      [ !.CPSR, BitVector(cpsr, 32<rt>)
        dReg 0, BitVector(0x1111111100000000UL, 64<rt>)
        dReg 1, BitVector(0x22222222UL, 64<rt>) ]
    let read = IRRunner.run (liftedBy false hex) inputs
    uint32 ((read (dReg 0)).ToUInt64())

  /// The names of the operations one encoding calls, in order.
  let callsBy isThumb hex =
    liftedBy isThumb hex
    |> Array.choose (function
      | Put(Src = BinOp(Op = BinIR.BinOpType.APP; Left = FuncName(Name = n))) ->
        Some n
      | _ ->
        None)

  /// What an address expression comes to with R1 = 0x1000.
  let atR1 (addr: Expr) =
    let r1 = !.R1, BitVector(0x1000u, 32<rt>)
    let read = IRRunner.run [| !.R2 := addr |] [ r1 ]
    (read !.R2).ToUInt64()

  /// The width and the address, with R1 = 0x1000, of every load and every
  /// store one encoding lifts to, in order. A load narrower than a word is
  /// extended to one, so it is found under its cast.
  let accessesBy isThumb hex =
    liftedBy isThumb hex
    |> Array.choose (function
      | Put(Src = Load(Type = rt; Addr = addr))
      | Put(Src = Cast(Operand = Load(Type = rt; Addr = addr))) ->
        Some("load", rt, atR1 addr)
      | Store(Addr = addr; Value = v) ->
        Some("store", Expr.typeOf v, atR1 addr)
      | _ ->
        None)

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

  /// BLX (immediate) writes LR and changes the instruction set (A8.8.25):
  /// its jump is a call that switches from A32 to T32 or back.
  [<TestMethod>]
  member _.``[ARMv7] BLX with an immediate is a call``() =
    let call = BinIR.InterJmpKind.IsCall
    let toThumb = call ||| BinIR.InterJmpKind.SwitchToThumb
    let toArm = call ||| BinIR.InterJmpKind.SwitchToARM
    CollectionAssert.AreEqual([| toThumb |], jumpKindsOf false "faffffff")
    CollectionAssert.AreEqual([| toArm |], jumpKindsOf true "f000e802")

  /// BLX (register) writes LR like BL and interworks like BX (A8.8.26): both
  /// of its jumps are calls.
  [<TestMethod>]
  member _.``[ARMv7] BLX with a register is a call``() =
    let call = BinIR.InterJmpKind.IsCall
    let toThumb = call ||| BinIR.InterJmpKind.SwitchToThumb
    let toArm = call ||| BinIR.InterJmpKind.SwitchToARM
    let kinds = [| toThumb; toArm |]
    CollectionAssert.AreEqual(kinds, jumpKindsOf false "e12fff31")
    CollectionAssert.AreEqual(kinds, jumpKindsOf true "4788")

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
  /// bits -- which read as zero (F5-4571), and PAN with them, which SETPAN
  /// writes (DDI0487F.c F5.1.117).
  [<TestMethod>]
  member _.``[ARMv7] MRS of CPSR hides the execution state``() =
    "e10f0000"
    ++ [| !.R0 := !.CPSR .& num 0xf84f03dfu |]
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

  /// An MRC whose Rt field is 15 writes APSR_nzcv, never the PC. Coprocessor
  /// 15 leaves that form UNPREDICTABLE (DDI0406C B3.15.2), so it is not lifted.
  [<TestMethod>]
  member _.``[ARMv7] MRC of MIDR to APSR_nzcv is unsupported``() =
    "ee10ff10" ++ [| AST.sideEffect BinIR.SideEffect.UnsupportedInstruction |]
    |> testARM

  [<TestMethod>]
  member _.``[ARMv7] MRC to APSR_nzcv never writes the PC``() =
    let written = writtenBy false "ee10ff10"
    Assert.AreEqual<bool>(false, Array.contains !.PC written)

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

  /// FPSCR is its controls, kept in FPSCR, and its status, kept in FPSR.
  [<TestMethod>]
  member _.``[ARMv7] VMRS of FPSCR reads its controls and status``() =
    let both = !.FPSCR .| !.FPSR
    Assert.AreEqual<Expr option>(Some both, assignedBy false "eef10a10" !.R0)

  [<TestMethod>]
  member _.``[Thumb] VMRS reads MVFR0``() =
    Assert.AreEqual<Expr option>(Some !.MVFR0, assignedBy true "eef70a10" !.R0)

  /// APSR_nzcv takes FPSCR's flags, which FPSR keeps, and the rest of CPSR
  /// stays as it was.
  [<TestMethod>]
  member _.``[ARMv7] VMRS APSR_nzcv takes FPSCR's flags``() =
    let others = !.CPSR .& AST.not (num 0xf0000000u)
    let flags = others .| (!.FPSR .& num 0xf0000000u)
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
  /// trap enables nothing here can take. Its controls go to FPSCR and its
  /// status to FPSR.
  [<TestMethod>]
  member _.``[ARMv7] VMSR to FPSCR keeps the bits FPSCR holds``() =
    let controls = !.R0 .& num 0x07ff0000u
    let status = !.R0 .& num 0xf800009fu
    let hex = "eee10a10"
    Assert.AreEqual<Expr option>(Some controls, assignedBy false hex !.FPSCR)
    Assert.AreEqual<Expr option>(Some status, assignedBy false hex !.FPSR)

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

  /// A B<c> that carries its own condition, T1 or T3, cannot sit in an IT
  /// block (DDI0406C A8.8.18), so ITSTATE is zero when it runs and it has no
  /// ITSTATE to advance.
  [<TestMethod>]
  member _.``[Thumb] B<c> with its own condition leaves CPSR alone``() =
    CollectionAssert.DoesNotContain(writtenBy true "d100", !.CPSR)
    CollectionAssert.DoesNotContain(writtenBy true "f0008096", !.CPSR)

  /// An instruction in an IT block advances ITSTATE whether its condition
  /// holds or not (ITAdvance, DDI0406C A2.5.2): the last one of a block ends
  /// it.
  [<TestMethod>]
  member _.``[Thumb] An IT block's last instruction ends the block``() =
    let itAfter (cpsr: uint32) =
      let inputs = [ !.CPSR, BitVector(cpsr, 32<rt>) ]
      let read = IRRunner.run (liftedInITBlock "4608") inputs
      uint32 ((read !.CPSR).ToUInt64()) &&& 0x0600fc00u
    Assert.AreEqual<uint32>(0u, itAfter 0x40000800u)
    Assert.AreEqual<uint32>(0u, itAfter 0x00000800u)

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

  /// A doubleword register moves as one doubleword: the two words the manual
  /// moves it as, taken together in the order the endianness puts them
  /// (DDI0406C A8.8.332 VLDM, A8.8.333 VLDR, A8.8.412 VSTM, A8.8.413 VSTR;
  /// VPUSH and VPOP are VSTMDB and VLDMIA on SP).
  [<TestMethod>]
  member _.``[ARMv7] A doubleword register moves as one doubleword``() =
    let doubles n = List.replicate n 64<rt>
    (* vldr d0, [r1, #8]; vldmia r1, {d0, d1}; vpop {d8, d9} *)
    for hex, n in [ "ed910b02", 1; "ec910b04", 2; "ecbd8b04", 2 ] do
      Assert.AreEqual<RegType list>(doubles n, loadWidthsBy false hex, hex)
    (* vstr d0, [r1, #8]; vstmia r1, {d0, d1}; vpush {d8, d9} *)
    for hex, n in [ "ed810b02", 1; "ec810b04", 2; "ed2d8b04", 2 ] do
      let widths = storedBy false hex |> Array.map Expr.typeOf |> List.ofArray
      Assert.AreEqual<RegType list>(doubles n, widths, hex)

  /// VLD1 and VST1 of whole registers move each register as one doubleword
  /// where memory is little-endian, whatever the size of their elements.
  /// Where it is big-endian, bytes, which have no order, and a doubleword
  /// still do, but halfwords and words move an element at a time (DDI0406C
  /// A8.8.320 VLD1, A8.8.404 VST1).
  [<TestMethod>]
  member _.``[ARMv7] VLD1 and VST1 move a whole register in one access``() =
    let doubles n = List.replicate n 64<rt>
    let loads =
      [ "f421070d", 1 (* vld1.8 {d0}, [r1]! *)
        "f4210a4f", 2 (* vld1.16 {d0-d1}, [r1] *)
        "f421028d", 4 (* vld1.32 {d0-d3}, [r1]! *)
        "f42107cf", 1 (* vld1.64 {d0}, [r1] *)
        "f4210a02", 2 (* vld1.8 {d0-d1}, [r1], r2 *) ]
    for hex, n in loads do
      let widths = loadsIn (liftedLittle hex) |> List.map Expr.typeOf
      Assert.AreEqual<RegType list>(doubles n, widths, hex)
    let stores =
      [ "f401070d", 1 (* vst1.8 {d0}, [r1]! *)
        "f4010a4f", 2 (* vst1.16 {d0-d1}, [r1] *)
        "f401028d", 4 (* vst1.32 {d0-d3}, [r1]! *)
        "f40107cf", 1 (* vst1.64 {d0}, [r1] *) ]
    for hex, n in stores do
      let widths =
        liftedLittle hex
        |> Array.choose (function
          | Store(Value = v) -> Some(Expr.typeOf v)
          | _ -> None)
        |> List.ofArray
      Assert.AreEqual<RegType list>(doubles n, widths, hex)
    let loadsOnly hex (expected: (Endian * RegType) list) =
      let got =
        loadsIn (liftedBy false hex)
        |> List.map (function
          | Load(Endian = e; Type = t) -> e, t
          | e -> failwith $"not a load: {e}")
      Assert.AreEqual<(Endian * RegType) list>(expected, got, hex)
    loadsOnly "f421070d" [ Endian.Little, 64<rt> ]
    loadsOnly "f42107cf" [ Endian.Big, 64<rt> ]
    loadsOnly "f4210a4f" (List.replicate 8 (Endian.Big, 16<rt>))

  /// <summary>
  /// A little-endian VLD1 or VST1 of whole registers moves the doublewords
  /// of memory, whatever the size of its elements: element i of a register
  /// lies at byte i times that size, as the bytes of one doubleword do.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VLD1 and VST1 move memory's doublewords``() =
    let word i = 0x0123456789abcdefUL * uint64 (2 * i + 1)
    let dWord r = 0xfedcba9876543210UL + uint64 r
    let mems = [ for i in 0 .. 7 -> M(8 * i, word i) ]
    let ds = [ for r in 0 .. 3 -> D(r, dWord r) ]
    let rn = 0x20000810u
    let r1 n back = Gpr(1, if back then rn + uint32 (8 * n) else rn)
    let loads =
      [ "f421070d", 1, true
        "f4210a4f", 2, false
        "f421028d", 4, true
        "f42107cf", 1, false ]
    for hex, n, back in loads do
      let loaded = [ for r in 0 .. n - 1 -> D(r, word (2 + r)) ]
      check false hex [ Gpr(1, rn) :: mems @ ds ] [ r1 n back :: loaded ]
    let stores =
      [ "f401070d", 1, true
        "f4010a4f", 2, false
        "f401028d", 4, true
        "f40107cf", 1, false ]
    for hex, n, back in stores do
      let stored = [ for r in 0 .. n - 1 -> M(16 + 8 * r, dWord r) ]
      check false hex [ Gpr(1, rn) :: mems @ ds ] [ r1 n back :: stored ]

  [<TestMethod>]
  member _.``[ARMv7] VLDM of singles loads one word a register``() =
    let halves = [ !@(Q0, 1); !@(Q0, 2) ]
    let writes =
      writtenBy false "ec900a04"
      |> Array.filter (fun d -> List.contains d halves)
    Assert.AreEqual<int>(4, writes.Length)

  /// FLDMX and FSTMX are VLDM and VSTM of doublewords whose imm8 is odd, one
  /// more than twice the registers they transfer, and they step the base
  /// over that one more word too (DDI0487F.c F6.1.5 and F6.1.6).
  [<TestMethod>]
  member _.``[ARMv7] FLDMX and FSTMX step over one more word``() =
    let expect (e: Expr) got = Assert.AreEqual<Expr option>(Some e, got)
    expect (!.R0 .+ num 28u) (assignedBy false "ecb00b07" !.R0)
    expect (!.R1 .- num 20u) (assignedBy false "ed314b05" !.R1)
    expect (!.R3 .- num 36u) (assignedBy true "ed238b09" !.R3)
    let ds = [ !@(Q0, 1); !@(Q0, 2); !@(Q1, 1) ]
    let loaded =
      writtenBy false "ecb00b07" |> Array.filter (fun d -> List.contains d ds)
    Assert.AreEqual<int>(3, loaded.Length)
    Assert.AreEqual<int>(1, (storesBy false "ec821b03").Length)

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
    Assert.AreEqual<uint64>(1UL, (read !.FPSR).ToUInt64() >>> 27 &&& 1UL)

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
    Assert.AreEqual<uint64>(1UL, (read !.FPSR).ToUInt64() >>> 27 &&& 1UL)

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

  /// SSBB and PSSBB, like the other barriers, order nothing a single observer
  /// can see, so they lift to nothing.
  [<TestMethod>]
  member _.``[ARMv7] SSBB and PSSBB lift to nothing``() =
    "f57ff040" ++ [||] |> testARM
    "f57ff044" ++ [||] |> testARM

  /// UDF is permanently UNDEFINED (DDI0487F.c F5.1.269): its immediate is
  /// for a debugger to read, and it is no call to the supervisor, which is
  /// what an interrupt numbered by it would be taken for.
  [<TestMethod>]
  member _.``[ARMv7] UDF is undefined``() =
    let undefined = [| AST.sideEffect BinIR.SideEffect.UndefinedInstruction |]
    "e7f000f0" ++ undefined |> testARM
    "e7f123f4" ++ undefined |> testARM
    "de00" ++ undefined |> testThumb
    "f7f0a000" ++ undefined |> testThumb

  /// No processor this front end models has ThumbEE, and without it ENTERX is
  /// UNDEFINED (DDI0406C B1.8.10), and LEAVEX's encoding is ThumbEE's alone
  /// (A6.3.4).
  [<TestMethod>]
  member _.``[ARMv7] ENTERX and LEAVEX are undefined``() =
    let undefined = [| AST.sideEffect BinIR.SideEffect.UndefinedInstruction |]
    "f3bf8f1f" ++ undefined |> testThumb
    "f3bf8f0f" ++ undefined |> testThumb

  /// Halting and Debug state belong to an external debugger, which this front
  /// end does not model: with halting not allowed HLT is UNDEFINED, and so
  /// are DCPS1, DCPS2 and DCPS3 in Non-debug state (DDI0487F.c F5.1.53 and
  /// F5.1.43 to F5.1.45).
  [<TestMethod>]
  member _.``[ARMv7] HLT and DCPS are undefined``() =
    let undefined = [| AST.sideEffect BinIR.SideEffect.UndefinedInstruction |]
    "e1000070" ++ undefined |> testARM
    "ba80" ++ undefined |> testThumb
    for hex in [ "f78f8001"; "f78f8002"; "f78f8003" ] do
      hex ++ undefined |> testThumb

  /// <summary>
  /// SETEND writes CPSR.E, bit 9, in any mode (DDI0406C A8.8.168), and ends
  /// the block with a jump to the instruction after it.
  ///
  /// A load or a store is lifted in the byte order of the ISA it is lifted
  /// for, not in the one E names when it runs, so what follows a SETEND has
  /// to be lifted again, in the order it set.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] SETEND writes CPSR.E and ends the block``() =
    let after isThumb hex (cpsr: uint32) =
      let inputs = [ !.CPSR, BitVector(cpsr, 32<rt>) ]
      let read = IRRunner.run (liftedBy isThumb hex) inputs
      uint32 ((read !.CPSR).ToUInt64())
    Assert.AreEqual<uint32>(0x60000210u, after false "f1010200" 0x60000010u)
    Assert.AreEqual<uint32>(0x60000010u, after false "f1010000" 0x60000210u)
    Assert.AreEqual<uint32>(0x60000230u, after true "b658" 0x60000030u)
    Assert.AreEqual<uint32>(0x60000030u, after true "b650" 0x60000230u)
    let targets isThumb hex =
      liftedBy isThumb hex
      |> Array.choose (function
        | InterJmp(Target = Num(Value = v)) -> Some(v.ToUInt64())
        | _ -> None)
    CollectionAssert.AreEqual([| 4UL |], targets false "f1010200")
    CollectionAssert.AreEqual([| 2UL |], targets true "b650")

  /// SETPAN writes PSTATE.PAN, which is CPSR bit 22, and does nothing in User
  /// mode (DDI0487F.c F5.1.183).
  [<TestMethod>]
  member _.``[ARMv7] SETPAN writes CPSR.PAN outside User mode``() =
    let after isThumb hex (cpsr: uint32) =
      let inputs = [ !.CPSR, BitVector(cpsr, 32<rt>) ]
      let read = IRRunner.run (liftedBy isThumb hex) inputs
      uint32 ((read !.CPSR).ToUInt64())
    Assert.AreEqual<uint32>(0x204001d3u, after false "f1100200" 0x200001d3u)
    Assert.AreEqual<uint32>(0x200001d3u, after false "f1100000" 0x204001d3u)
    Assert.AreEqual<uint32>(0x6040001fu, after true "b618" 0x6000001fu)
    Assert.AreEqual<uint32>(0x6000001fu, after true "b610" 0x6040001fu)
    Assert.AreEqual<uint32>(0x00000010u, after false "f1100200" 0x00000010u)
    Assert.AreEqual<uint32>(0x00400010u, after true "b610" 0x00400010u)

  /// MSR of CPSR's s field writes PAN outside User mode, and GE in any mode
  /// (DDI0487F.c J1.2, CPSRWriteByInstr).
  [<TestMethod>]
  member _.``[ARMv7] MSR writes CPSR.PAN outside User mode``() =
    let after isThumb hex (cpsr: uint32) (r0: uint32) =
      let inputs =
        [ !.CPSR, BitVector(cpsr, 32<rt>); !.R0, BitVector(r0, 32<rt>) ]
      let read = IRRunner.run (liftedBy isThumb hex) inputs
      uint32 ((read !.CPSR).ToUInt64())
    let check expected isThumb hex cpsr r0 =
      Assert.AreEqual<uint32>(expected, after isThumb hex cpsr r0, hex)
    check 0x604501d3u false "e124f000" 0x600001d3u 0x00450000u
    check 0x600001d3u false "e124f000" 0x604501d3u 0u
    check 0x6045001fu true "f3808400" 0x6000001fu 0x00450000u
    check 0x60050010u false "e124f000" 0x60000010u 0x00450000u

  /// HVC and SMC are UNDEFINED in User mode (DDI0487F.c F5.1.54 and
  /// F5.1.192). The exceptions they take into Hyp and Monitor mode are not
  /// modelled, so in every other mode they are unsupported.
  [<TestMethod>]
  member _.``[ARMv7] HVC and SMC are refused in User mode``() =
    let unsupported isThumb hex =
      liftedBy isThumb hex
      |> Array.exists (function
        | SideEffect(Effect = BinIR.SideEffect.UnsupportedInstruction) -> true
        | _ -> false)
    let calls =
      [ false, "e14ff070"
        true, "f7e18234"
        false, "e1600070"
        true, "f7f38000" ]
    for isThumb, hex in calls do
      CollectionAssert.AreEqual([| 0x10u |], refusedModes isThumb hex, hex)
      Assert.AreEqual<bool>(true, unsupported isThumb hex, hex)

  /// <summary>
  /// VSHLL by the element's own width has an encoding of its own, whose data
  /// type has no sign (DDI0487F.c F6.1.226, A2 and T2): either extension
  /// gives the same answer, every element landing in the top half of its
  /// widened lane.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VSHLL by the element width moves it to the top half``() =
    let cases =
      [ false, "f3b60302", 0x4b5a000069780000UL, 0x0f1e00002d3c0000UL
        false, "f3b20303", 0xc300d200e100f000UL, 0x87009600a500b400UL
        false, "f3ba0303", 0xc3d2e1f000000000UL, 0x8796a5b400000000UL
        true, "ffb60302", 0x4b5a000069780000UL, 0x0f1e00002d3c0000UL ]
    for isThumb, hex, lo, hi in cases do
      Assert.AreEqual<uint64 * uint64>((lo, hi), qRun isThumb hex, hex)

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
    let read = IRRunner.run (liftedWithShortVectors "ee357b06") inputs
    Assert.AreEqual<uint64>(0x4008000000000000UL, (read (dReg 7)).ToUInt64())
    Assert.AreEqual<uint64>(0x4014000000000000UL, (read (dReg 4)).ToUInt64())

  [<TestMethod>]
  member _.``[ARMv7] VADD.F64 into d16 stays scalar under Len 1``() =
    let ds = [ 17, 0x3ff0000000000000UL; 18, 0x4000000000000000UL ]
    let inputs =
      (!.FPSCR, BitVector(0x10000u, 32<rt>))
      :: [ for n, v in ds -> dReg n, BitVector(v, 64<rt>) ]
    let read = IRRunner.run (liftedWithShortVectors "ee710ba2") inputs
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
    let read = IRRunner.run (liftedWithShortVectors "ee384a0c") inputs
    Assert.AreEqual<uint64>(0x4040000040000000UL, (read (dReg 4)).ToUInt64())

  [<TestMethod>]
  member _.``[ARMv7] VADD.F32 into s0 stays scalar under Len 1``() =
    let one = 0x3f800000UL
    let ds = [ 2, one; 4, (one <<< 32) ||| one ]
    let inputs =
      (!.FPSCR, BitVector(0x10000u, 32<rt>))
      :: [ for n, v in ds -> dReg n, BitVector(v, 64<rt>) ]
    let read = IRRunner.run (liftedWithShortVectors "ee320a04") inputs
    Assert.AreEqual<uint64>(0x40000000UL, (read (dReg 0)).ToUInt64())

  /// Without short vectors, as on a Cortex-A15 or anything Armv8, a length or
  /// a stride in FPSCR makes a VFP data-processing instruction UNDEFINED.
  [<TestMethod>]
  member _.``[ARMv7] VADD.F32 without short vectors refuses a length``() =
    let named = (!.FPSCR .& num 0x370000u) != AST.num0 32<rt>
    Assert.AreEqual<Expr option>(Some named, undefinedWhen false "ee384a0c")

  /// And with neither, VADD.F32 s8, s16, s24 is the one addition: s8 = 1 + 2,
  /// and s9 keeps its 5 where a vector would have put s17 + s25 = 0.
  [<TestMethod>]
  member _.``[ARMv7] VADD.F32 without short vectors adds one pair``() =
    let one, two, five = 0x3f800000UL, 0x40000000UL, 0x40a00000UL
    let ds = [ 4, five <<< 32; 8, one; 12, two ]
    let inputs = [ for n, v in ds -> dReg n, BitVector(v, 64<rt>) ]
    let read = IRRunner.run (liftedBy false "ee384a0c") inputs
    Assert.AreEqual<uint64>(0x40a0000040400000UL, (read (dReg 4)).ToUInt64())

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
    let read = IRRunner.run (liftedWithShortVectors "ee277aa1") inputs
    Assert.AreEqual<uint64>(0x3f80000040000000UL, (read (dReg 7)).ToUInt64())
    Assert.AreEqual<uint64>(0x3f80000040000000UL, (read (dReg 4)).ToUInt64())

  /// <summary>
  /// VRECPE.F32 and VRSQRTE.F32 are FPRecipEstimate and FPRSqrtEstimate
  /// (A2.7, A8.8.385, A8.8.392), not the unsigned integer estimates: the
  /// reciprocal of {3.0, -0.5} is {0.333, -1.996} and the reciprocal square
  /// root of {4.0, 1.0} is {0.499, 0.998}, to eight bits.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VRECPE.F32 estimates reciprocals``() =
    let d0, _, _ = fpRun "f3bb0502" 0u [ 2, 0xbf00000040400000UL ]
    Assert.AreEqual<uint64>(0xbfff80003eaa8000UL, d0)

  /// <summary>
  /// The estimates' special cases: the reciprocal of a zero is an infinity of
  /// its sign, raising Division by Zero; of a magnitude of 2^126 or more it is
  /// a zero of its sign, raising Underflow; and the reciprocal square root of
  /// a negative number is the default NaN, raising Invalid.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VRECPE.F32 of a zero is an infinity``() =
    let d0, _, fpscr = fpRun "f3bb0502" 0u [ 2, 0x8000000000000000UL ]
    Assert.AreEqual<uint64 * uint32>((0xff8000007f800000UL, 2u), (d0, fpscr))

  [<TestMethod>]
  member _.``[ARMv7] VRECPE.F32 of 2^126 is a zero``() =
    let d0, _, fpscr = fpRun "f3bb0502" 0u [ 2, 0xfe8000007e800000UL ]
    Assert.AreEqual<uint64 * uint32>((0x8000000000000000UL, 8u), (d0, fpscr))

  [<TestMethod>]
  member _.``[ARMv7] VRSQRTE.F32 of a negative number is the default NaN``() =
    let d0, _, fpscr = fpRun "f3bb0582" 0u [ 2, 0xbf800000bf800000UL ]
    Assert.AreEqual<uint64 * uint32>((0x7fc000007fc00000UL, 1u), (d0, fpscr))

  [<TestMethod>]
  member _.``[ARMv7] VRSQRTE.F32 estimates reciprocal square roots``() =
    let d0, _, _ = fpRun "f3bb0582" 0u [ 2, 0x3f80000040800000UL ]
    Assert.AreEqual<uint64>(0x3f7f80003eff8000UL, d0)

  /// <summary>
  /// The Advanced SIMD VCVT between singles and 32-bit integers rounds toward
  /// zero and saturates, lane by lane, to an integer, and to nearest from one
  /// (A8.8.306): -2.5 is -2 and 3e9 is 0x7fffffff; 16777217 is 16777216.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VCVT.S32.F32 on D registers converts both lanes``() =
    let d0, _, fpscr = fpRun "f3bb0702" 0u [ 2, 0x4f32d05ec0200000UL ]
    Assert.AreEqual<uint64 * uint32>((0x7ffffffffffffffeUL, 0x11u),
                                     (d0, fpscr))

  [<TestMethod>]
  member _.``[ARMv7] VCVT.F32.S32 on D registers converts both lanes``() =
    let d0, _, fpscr = fpRun "f3bb0602" 0u [ 2, 0xffffffff01000001UL ]
    Assert.AreEqual<uint64 * uint32>((0xbf8000004b800000UL, 0x10u),
                                     (d0, fpscr))

  /// <summary>
  /// The fixed-point form saturates an unsigned result at zero: with one
  /// fraction bit, 1.75 is 3, rounded toward zero, and -1.0 is 0 (A8.8.308).
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VCVT.U32.F32 to fixed point saturates at zero``() =
    let d0, _, fpscr = fpRun "f3bf0f12" 0u [ 2, 0xbf8000003fe00000UL ]
    Assert.AreEqual<uint64 * uint32>((3UL, 0x11u), (d0, fpscr))

  /// The Advanced SIMD VCVT between singles and halves narrows a quadword of
  /// singles into a doubleword of halves, and widens one back (A8.8.311).
  [<TestMethod>]
  member _.``[ARMv7] VCVT.F16.F32 narrows four singles``() =
    let ds = [ 2, 0xc00000003f800000UL; 3, 0x478000003f000000UL ]
    let d0, _, fpscr = fpRun "f3b60602" 0u ds
    Assert.AreEqual<uint64 * uint32>((0x7c003800c0003c00UL, 0x14u), (d0, fpscr))

  [<TestMethod>]
  member _.``[ARMv7] VCVT.F32.F16 widens four halves``() =
    let d0, d1, fpscr = fpRun "f3b60702" 0u [ 2, 0x00017c00c0003c00UL ]
    let expected = 0xc00000003f800000UL, 0x338000007f800000UL, 0u
    Assert.AreEqual<uint64 * uint64 * uint32>(expected, (d0, d1, fpscr))

  /// <summary>
  /// VCADD adds the second operand rotated: with d1 = 1 + 2i and d2 = 3 + 4i,
  /// #90 gives (1 - 4) + (2 + 3)i and #270 (1 + 4) + (2 - 3)i (DDI0487F.c
  /// F6.1.39).
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VCADD.F32 rotates by 90``() =
    let ds = [ 1, 0x400000003f800000UL; 2, 0x4080000040400000UL ]
    let d0, _, _ = fpRun "fc910802" 0u ds
    Assert.AreEqual<uint64>(0x40a00000c0400000UL, d0)

  [<TestMethod>]
  member _.``[ARMv7] VCADD.F32 rotates by 270``() =
    let ds = [ 1, 0x400000003f800000UL; 2, 0x4080000040400000UL ]
    let d0, _, _ = fpRun "fd910802" 0u ds
    Assert.AreEqual<uint64>(0xbf80000040a00000UL, d0)

  /// On halves, pair by pair: (1 + 2i) + i(0.5 + i) and (3 + 4i) + i(2 +
  /// 0.25i).
  [<TestMethod>]
  member _.``[ARMv7] VCADD.F16 rotates every pair``() =
    let ds = [ 1, 0x4400420040003c00UL; 2, 0x340040003c003800UL ]
    let d0, _, _ = fpRun "fc810802" 0u ds
    Assert.AreEqual<uint64>(0x4600418041000000UL, d0)

  /// <summary>
  /// VCMLA accumulates one part of the complex product per rotation: with
  /// d1 = 1 + 2i and d2 = 3 + 4i into zero, #0 gives 1 * (3 + 4i), #90
  /// 2i * (3 + 4i) = -8 + 6i, #180 -(3 + 4i) and #270 the negation of #90's.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VCMLA.F32 accumulates at every rotation``() =
    let ds = [ 1, 0x400000003f800000UL; 2, 0x4080000040400000UL ]
    let run hex = let d0, _, _ = fpRun hex 0u ds in d0
    Assert.AreEqual<uint64>(0x4080000040400000UL, run "fc310802")
    Assert.AreEqual<uint64>(0x40c00000c1000000UL, run "fcb10802")
    Assert.AreEqual<uint64>(0xc0800000c0400000UL, run "fd310802")
    Assert.AreEqual<uint64>(0xc0c0000041000000UL, run "fdb10802")

  /// By element, every pair meets the one pair the index names, and adds to
  /// what the destination held.
  [<TestMethod>]
  member _.``[ARMv7] VCMLA.F32 by element accumulates``() =
    let ds =
      [ 0, 0x3f0000003f000000UL
        1, 0x400000003f800000UL
        2, 0x4080000040400000UL ]
    let d0, _, _ = fpRun "fe810802" 0u ds
    Assert.AreEqual<uint64>(0x4090000040600000UL, d0)

  /// <summary>
  /// On a quadword by element, both pairs meet the one pair the index names,
  /// and the second doubleword is written too: (1 + 0i) and (3 + 0i) times
  /// (2 + 5i) at #0 are 2 + 5i and 6 + 15i.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VCMLA.F32 by element on a quadword writes both``() =
    let ds = [ 2, 0x3f800000UL; 3, 0x40400000UL; 4, 0x40a0000040000000UL ]
    let d0, d1, _ = fpRun "fe820844" 0u ds
    let expected = 0x40a0000040000000UL, 0x4170000040c00000UL
    Assert.AreEqual<uint64 * uint64>(expected, (d0, d1))

  /// <summary>
  /// On halves at #90 into 1 + 1i: (1 - 3 * 5) + (1 + 3 * 4)i is -14 + 13i,
  /// with d1 = 2 + 3i and d2 = 4 + 5i.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VCMLA.F16 accumulates at 90``() =
    let ds = [ 0, 0x3c003c00UL; 1, 0x42004000UL; 2, 0x45004400UL ]
    let d0, _, _ = fpRun "fca10802" 0u ds
    Assert.AreEqual<uint64>(0x4a80cb00UL, d0)

  /// <summary>
  /// The product is fused into the sum: (1 + 2^-12)^2 - (1 + 2^-11) is 2^-24,
  /// where a product rounded first to a single would leave nothing.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VCMLA.F32 fuses the product``() =
    let ds = [ 0, 0xbf801000UL; 1, 0x3f800800UL; 2, 0x3f800800UL ]
    let d0, _, _ = fpRun "fc310802" 0u ds
    Assert.AreEqual<uint64>(0x33800000UL, d0)

  /// <summary>
  /// The rotation negates the factor itself, a minus zero included: at #180,
  /// -0 plus 2 * -(+0) is -0 in both lanes.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VCMLA.F32 keeps a negative zero``() =
    let ds = [ 0, 0x8000000080000000UL; 1, 0x40000000UL ]
    let d0, _, _ = fpRun "fd310802" 0u ds
    Assert.AreEqual<uint64>(0x8000000080000000UL, d0)

  /// <summary>
  /// A half result below the smallest normal is a zero under FPSCR.FZ16,
  /// raising Underflow alone, and is kept without it: 2^-14 (1 + 2^-10) less
  /// 2^-14 is 2^-24, at VCADD.F16 #90.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VCADD.F16 flushes a tiny result under FZ16``() =
    let ds = [ 1, 0x0401UL; 2, 0x04000000UL ]
    let d0, _, fpscr = fpRun "fc810802" 0x00080000u ds
    Assert.AreEqual<uint64 * uint32>((0UL, 0x00080008u), (d0, fpscr))

  [<TestMethod>]
  member _.``[ARMv7] VCADD.F16 keeps a tiny result without FZ16``() =
    let ds = [ 1, 0x0401UL; 2, 0x04000000UL ]
    let d0, _, fpscr = fpRun "fc810802" 0u ds
    Assert.AreEqual<uint64 * uint32>((1UL, 0u), (d0, fpscr))

  /// On halves by element the index picks the second pair of d2.
  [<TestMethod>]
  member _.``[ARMv7] VCMLA.F16 by element takes the pair indexed``() =
    let ds = [ 1, 0x4400420040003c00UL; 2, 0x3400380000000000UL ]
    let d0, _, _ = fpRun "fe010822" 0u ds
    Assert.AreEqual<uint64>(0x3a003e0034003800UL, d0)

  /// <summary>
  /// LDA, LDAB and LDAH load with acquire order, and STL, STLB and STLH store
  /// with release order (DDI0487F.c F5.1.57, F5.1.58, F5.1.63, F5.1.217,
  /// F5.1.218 and F5.1.223). A lone observer sees no order, so each is the
  /// access of its size through the base, with no offset and no writeback.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] LDA, LDAB and LDAH load their size at the base``() =
    let one = accessesBy false
    CollectionAssert.AreEqual([| "load", 32<rt>, 0x1000UL |], one "e1910c9f")
    CollectionAssert.AreEqual([| "load", 8<rt>, 0x1000UL |], one "e1d10c9f")
    CollectionAssert.AreEqual([| "load", 16<rt>, 0x1000UL |], one "e1f10c9f")
    let thumb = accessesBy true "e8d10faf"
    CollectionAssert.AreEqual([| "load", 32<rt>, 0x1000UL |], thumb)

  [<TestMethod>]
  member _.``[ARMv7] STL, STLB and STLH store their size at the base``() =
    let one = accessesBy false
    CollectionAssert.AreEqual([| "store", 32<rt>, 0x1000UL |], one "e181fc90")
    CollectionAssert.AreEqual([| "store", 8<rt>, 0x1000UL |], one "e1c1fc90")
    CollectionAssert.AreEqual([| "store", 16<rt>, 0x1000UL |], one "e1e1fc90")
    let thumb = accessesBy true "e8c10f9f"
    CollectionAssert.AreEqual([| "store", 16<rt>, 0x1000UL |], thumb)

  /// <summary>
  /// CRC32 and CRC32C fold Rm's byte, halfword or word into the remainder in
  /// Rn, inverting neither before nor after (DDI0487F.c F5.1.39 and
  /// F5.1.40): from 0xffffffff over "a" and over "abcd" they give the
  /// complement of zlib's crc32, and over "a" for CRC32C the complement of
  /// that string's CRC-32C, 0xc1d04330.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] CRC32 folds a byte, a halfword and a word``() =
    let crc = r0After false
    let ones, abcd = 0xffffffffu, 0x64636261u
    Assert.AreEqual<uint32>(0x174841bcu, crc "e1010042" ones 0x61u)
    Assert.AreEqual<uint32>(0x90d164a3u, crc "e1210042" 0x12345678u 0xbeefu)
    Assert.AreEqual<uint32>(0x127d32eeu, crc "e1410042" ones abcd)

  [<TestMethod>]
  member _.``[ARMv7] CRC32C folds by the Castagnoli polynomial``() =
    let crc = r0After false
    let ones, abcd = 0xffffffffu, 0x64636261u
    Assert.AreEqual<uint32>(0x3e2fbccfu, crc "e1010242" ones 0x61u)
    Assert.AreEqual<uint32>(0xd78220dcu, crc "e1210242" 0x12345678u 0xbeefu)
    Assert.AreEqual<uint32>(0x6d37f5ceu, crc "e1410242" ones abcd)

  [<TestMethod>]
  member _.``[ARMv7] CRC32 reads the same in T32``() =
    let crc = r0After true
    let ones, abcd = 0xffffffffu, 0x64636261u
    Assert.AreEqual<uint32>(0x127d32eeu, crc "fac1f0a2" ones abcd)
    Assert.AreEqual<uint32>(0x3e2fbccfu, crc "fad1f082" ones 0x61u)

  /// <summary>
  /// The SHA-1 and SHA-256 instructions (DDI0487F.c F6.1.7-F6.1.16), each
  /// over the one input optest-arm/probes/v8crypto-vectors.c measured under
  /// QEMU: what is left in Q0, low doubleword then high.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] the SHA instructions give the measured answers``() =
    let cases =
      [ "f2020c44", 0x3d70505e6b6b8c5eUL, 0x7545d662ea51c49bUL (* SHA1C *)
        "f2120c44", 0x627e917b62d68d5fUL, 0x17f99b385320ee23UL (* SHA1P *)
        "f2220c44", 0x58c9ee35d5554b2aUL, 0x5323b440988877d7UL (* SHA1M *)
        "f3b902c2", 0x0000000012d69a5eUL, 0x0000000000000000UL (* SHA1H *)
        "f2320c44", 0xeeddccbbaa998877UL, 0x68682c68e0e0a468UL (* SHA1SU0 *)
        "f3ba0382", 0x85e3492f0d6bc1a7UL, 0xe76ef67fe3852f49UL (* SHA1SU1 *)
        "f3020c44", 0x985165435bd4a46bUL, 0xeeeccb2bee37a382UL (* SHA256H *)
        "f3120c44", 0x7ba32c032acba172UL, 0x2982bcd5644a655bUL (* SHA256H2 *)
        "f3ba03c2", 0x23c5791aa92bbc5dUL, 0x6280a5c376d443a1UL (* SHA256SU0 *)
        "f3220c44", 0xcfafdca539210a20UL, 0x6a38e7f5a2452bbaUL (* SHA256SU1 *) ]
    for hex, lo, hi in cases do
      Assert.AreEqual<uint64 * uint64>((lo, hi), qRun false hex, hex)
    let expected = 0x985165435bd4a46bUL, 0xeeeccb2bee37a382UL
    Assert.AreEqual<uint64 * uint64>(expected, qRun true "ff020c44")

  /// <summary>
  /// AESE and AESD are x86's last-round operation, with a zero key, over the
  /// state already added to the round key; AESMC undoes a round's shift and
  /// substitution with AESDECLAST and keeps the mixing of AESENC; AESIMC goes
  /// straight across (DDI0487F.c F6.1.1-F6.1.4).
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] the AES instructions name the x86 operations``() =
    let calls = callsBy false
    CollectionAssert.AreEqual([| "AESENCLAST" |], calls "f3b00302")
    CollectionAssert.AreEqual([| "AESDECLAST" |], calls "f3b00342")
    CollectionAssert.AreEqual([| "AESDECLAST"; "AESENC" |], calls "f3b00382")
    CollectionAssert.AreEqual([| "AESIMC" |], calls "f3b003c2")
    CollectionAssert.AreEqual([| "AESENCLAST" |], callsBy true "ffb00302")

  /// <summary>
  /// VRINTA, VRINTN, VRINTP, VRINTM and VRINTZ round in the direction each
  /// names (DDI0487F.c F6.1.199-F6.1.211): 2.5 goes to 3 away from zero and
  /// to 2 to even, and -0.5 rounds up to minus zero.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VRINT rounds each way it names``() =
    let r hex v = fst (s0After hex 0u v 0u)
    Assert.AreEqual<uint32>(0x40400000u, r "feb80a60" 0x40200000u)
    Assert.AreEqual<uint32>(0xc0400000u, r "feb80a60" 0xc0200000u)
    Assert.AreEqual<uint32>(0x40000000u, r "feb90a60" 0x40200000u)
    Assert.AreEqual<uint32>(0x80000000u, r "feba0a60" 0xbf000000u)
    Assert.AreEqual<uint32>(0x00000000u, r "febb0a60" 0x3f000000u)
    Assert.AreEqual<uint32>(0xbf800000u, r "eeb60ae0" 0xbfd9999au)

  /// VRINTR and VRINTX round as FPSCR.RMode says, here to nearest, and only
  /// VRINTX raises Inexact for the fraction it drops.
  [<TestMethod>]
  member _.``[ARMv7] VRINTX alone raises Inexact``() =
    let r, f = s0After "eeb60a60" 0u 0x3fc00000u 0u
    Assert.AreEqual<uint32 * uint32>((0x40000000u, 0u), (r, f))
    let x, g = s0After "eeb70a60" 0u 0x3fc00000u 0u
    Assert.AreEqual<uint32 * uint32>((0x40000000u, 0x10u), (x, g))

  /// <summary>
  /// VCVTA, VCVTN, VCVTP and VCVTM convert to an integer rounding as each
  /// names (F6.1.66, F6.1.72, F6.1.74 and F6.1.70), and an unsigned one of a
  /// negative number gives zero and raises Invalid.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VCVTA, VCVTN, VCVTP and VCVTM round as named``() =
    let c hex v = fst (s0After hex 0u v 0u)
    Assert.AreEqual<uint32>(3u, c "febc0ae0" 0x40200000u)
    Assert.AreEqual<uint32>(0xfffffffdu, c "febc0ae0" 0xc0200000u)
    Assert.AreEqual<uint32>(2u, c "febd0ae0" 0x40200000u)
    Assert.AreEqual<uint32>(3u, c "febe0ae0" 0x40066666u)
    Assert.AreEqual<uint32>(0xfffffffdu, c "febf0ae0" 0xc0066666u)
    let u, f = s0After "febc0a60" 0u 0xbf800000u 0u
    Assert.AreEqual<uint32 * uint32>((0u, 1u), (u, f))

  /// VMAXNM and VMINNM take the number over a quiet NaN, where VMAX and VMIN
  /// propagate the NaN (F6.1.117 and F6.1.120).
  [<TestMethod>]
  member _.``[ARMv7] VMAXNM and VMINNM take a number over a quiet NaN``() =
    let one, two, nan = 0x3f800000u, 0x40000000u, 0x7fc00000u
    Assert.AreEqual<uint32>(one, fst (s0After "fe800a81" 0u nan one))
    Assert.AreEqual<uint32>(one, fst (s0After "fe800ac1" 0u one nan))
    Assert.AreEqual<uint32>(two, fst (s0After "fe800a81" 0u one two))
    Assert.AreEqual<uint32>(one, fst (s0After "fe800ac1" 0u one two))

  /// VSELEQ, VSELGE, VSELGT and VSELVS take S1 where the condition holds on
  /// the flags and S2 where it does not (F6.1.223).
  [<TestMethod>]
  member _.``[ARMv7] VSEL picks by the condition it names``() =
    let s1, s2 = 0x11111111u, 0x22222222u
    Assert.AreEqual<uint32>(s1, selAfter "fe000a81" 0x40000000u)
    Assert.AreEqual<uint32>(s2, selAfter "fe000a81" 0u)
    Assert.AreEqual<uint32>(s1, selAfter "fe200a81" 0x90000000u)
    Assert.AreEqual<uint32>(s2, selAfter "fe200a81" 0x80000000u)
    Assert.AreEqual<uint32>(s1, selAfter "fe300a81" 0u)
    Assert.AreEqual<uint32>(s2, selAfter "fe300a81" 0x40000000u)
    Assert.AreEqual<uint32>(s1, selAfter "fe100a81" 0x10000000u)
    Assert.AreEqual<uint32>(s2, selAfter "fe100a81" 0u)

  /// <summary>
  /// VJCVT truncates and wraps where VCVT saturates, and says in FPSCR.Z
  /// whether the conversion was exact (F6.1.99): 2^31 + 0.5 comes back as
  /// 0x80000000 and raises Invalid, 42.0 is exact, and -3.7 gives -3 and
  /// raises Inexact.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VJCVT wraps and sets Z when exact``() =
    let run (d: uint64) =
      let d0, _, fpscr = fpRun "eeb90bc1" 0u [ 1, d ]
      uint32 d0, fpscr
    let wrapped = run 0x41e0000000100000UL
    Assert.AreEqual<uint32 * uint32>((0x80000000u, 0x1u), wrapped)
    let exact = run 0x4045000000000000UL
    Assert.AreEqual<uint32 * uint32>((42u, 0x40000000u), exact)
    let dropped = run 0xc00d99999999999aUL
    Assert.AreEqual<uint32 * uint32>((0xfffffffdu, 0x10u), dropped)

  /// <summary>
  /// Under FZ a denormal is flushed to a zero, raising Input Denormal, and
  /// FPToFixedJS calls the conversion of a flushed one inexact whichever its
  /// sign (DDI0487F.c J1-7895): Z clear for both, set for a true plus zero.
  /// QEMU 8.2.2 sets Z for both (optest-arm/probes/vjcvt-z.c).
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VJCVT calls a flushed denormal inexact``() =
    let run (d: uint64) =
      let d0, _, fpscr = fpRun "eeb90bc1" 0x01000000u [ 1, d ]
      uint32 d0, fpscr
    let positive = run 0x0000000000000001UL
    Assert.AreEqual<uint32 * uint32>((0u, 0x01000080u), positive)
    let negative = run 0x8000000000000001UL
    Assert.AreEqual<uint32 * uint32>((0u, 0x01000080u), negative)
    Assert.AreEqual<uint32 * uint32>((0u, 0x41000000u), run 0UL)

  /// <summary>
  /// VQRDMLAH and VQRDMLSH accumulate the rounding doubled product into each
  /// element's high half: 0x1000 with 0x4000 * 0x4000 added is 0x3000 and
  /// taken away 0xf000, 0x123 with 0xfedc * 0x456 is 0x119, and 0x7fff with
  /// 0x7fff * 0x7fff added, or 0x8000 with it taken away, saturates and
  /// raises QC.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VQRDMLAH and VQRDMLSH accumulate and saturate``() =
    let ds =
      [ 0, 0x000001237fff1000UL
        1, 0x0000fedc7fff4000UL
        2, 0x000004567fff4000UL ]
    let d0, _, fpscr = fpRun "f3110b12" 0u ds
    Assert.AreEqual<uint64 * uint32>((0x000001197fff3000UL, 0x08000000u),
                                     (d0, fpscr))
    let ds =
      [ 0, 0x0000000080001000UL
        1, 0x000000007fff4000UL
        2, 0x000000007fff4000UL ]
    let d0, _, fpscr = fpRun "f3110c12" 0u ds
    Assert.AreEqual<uint64 * uint32>((0x000000008000f000UL, 0x08000000u),
                                     (d0, fpscr))

  /// By scalar, every element multiplies the one element named, here D2[1].
  [<TestMethod>]
  member _.``[ARMv7] VQRDMLAH by scalar reads the element named``() =
    let ds = [ 0, 0x1000UL; 1, 0x4000UL; 2, 0x40000000UL ]
    let d0, _, fpscr = fpRun "f2910e4a" 0u ds
    Assert.AreEqual<uint64 * uint32>((0x3000UL, 0u), (d0, fpscr))

  /// <summary>
  /// VSDOT, VUDOT, VUSDOT and VSUDOT add four byte products to each word, each
  /// byte read with its own operand's signedness: with D1's low word -4, -3,
  /// -2 and -1 and D2's 4, 3, 2 and 1, the signed sum is -30 and the unsigned
  /// one 2530; by element every word reads D2's word 1, 8, 7, 6 and 5.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] the dot products sum four byte products a word``() =
    let ds =
      [ 0, 0x0000001000000100UL
        1, 0x01020304fffefdfcUL
        2, 0x0506070801020304UL ]
    let dot hex =
      let d0, _, _ = fpRun hex 0u ds
      d0
    Assert.AreEqual<uint64>(0x00000056000000e2UL, dot "fc210d02")
    Assert.AreEqual<uint64>(0x0000005600000ae2UL, dot "fc210d12")
    Assert.AreEqual<uint64>(0x00000056000000baUL, dot "fe210d22")
    Assert.AreEqual<uint64>(0x0000005600000ae2UL, dot "fca10d02")
    Assert.AreEqual<uint64>(0x00000056000000baUL, dot "fe810d32")

  /// <summary>
  /// VSMMLA, VUMMLA and VUSMMLA: word (i, j) of Q0 adds the eight byte
  /// products of row i of Q1 with row j of Q2. Q1's rows are all 1 and all 2,
  /// Q2's all 3 and all 0xff, which is -1 signed and 255 unsigned.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] the matrix multiplies take rows against rows``() =
    let ds =
      [ 2, 0x0101010101010101UL
        3, 0x0202020202020202UL
        4, 0x0303030303030303UL
        5, 0xffffffffffffffffUL ]
    let mm hex =
      let d0, d1, _ = fpRun hex 0u ds
      d0, d1
    let signed = 0xfffffff800000018UL, 0xfffffff000000030UL
    Assert.AreEqual<uint64 * uint64>(signed, mm "fc220c44")
    let unsigned = 0x000007f800000018UL, 0x00000ff000000030UL
    Assert.AreEqual<uint64 * uint64>(unsigned, mm "fc220c54")
    Assert.AreEqual<uint64 * uint64>(signed, mm "fca20c44")

  /// <summary>
  /// A VFP half-precision form reads the bottom half of its singles, writes
  /// its result there with the top cleared, and rounds as FPSCR says: 1 +
  /// 2^-11 is a tie, to 1 at nearest and to the next half up toward plus
  /// infinity, raising Inexact either way.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VADD.F16 rounds as FPSCR says``() =
    let nearest = s0After "ee300981" 0u 0xabcd3c00u 0x12341000u
    Assert.AreEqual<uint32 * uint32>((0x3c00u, 0x10u), nearest)
    let up = s0After "ee300981" 0x00400000u 0xabcd3c00u 0x12341000u
    Assert.AreEqual<uint32 * uint32>((0x3c01u, 0x00400010u), up)

  /// VCMP.F16 sets FPSCR's condition flags: +0 against 1 is less.
  [<TestMethod>]
  member _.``[ARMv7] VCMP.F16 compares the bottom halves``() =
    let r = s0After "eeb40960" 0u 0xffff3c00u 0u
    Assert.AreEqual<uint32>(0x80000000u, snd r)

  /// <summary>
  /// VCVT between a half and an integer: -5 converts to 0xfffffffb, and 2049,
  /// a tie between 2048 and 2050, rounds to even at nearest and up toward plus
  /// infinity, raising Inexact.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VCVT converts between halves and integers``() =
    Assert.AreEqual<uint32>(0xfffffffbu, fst (s0After "eebd09e0" 0u 0xc500u 0u))
    let nearest = s0After "eeb809e0" 0u 2049u 0u
    Assert.AreEqual<uint32 * uint32>((0x6800u, 0x10u), nearest)
    let up = s0After "eeb809e0" 0x00400000u 2049u 0u
    Assert.AreEqual<uint32 * uint32>((0x6801u, 0x00400010u), up)

  /// VMAXNM.F16 by lanes: a number over a quiet NaN, either way round, and
  /// plus zero over minus zero.
  [<TestMethod>]
  member _.``[ARMv7] VMAXNM.F16 takes numbers over quiet NaNs``() =
    let ds = [ 1, 0x0000bc003c007e00UL; 2, 0x80003c007e004000UL ]
    let d0, _, _ = fpRun "f3110f12" 0u ds
    Assert.AreEqual<uint64>(0x00003c003c004000UL, d0)

  /// <summary>
  /// VCVTB from a single to a bfloat16 rounds its top half as FPSCR says and
  /// writes the bottom half of Sd: 0x3f808000 is a tie and stays 0x3f80 at
  /// nearest, an even last bit, where 0x3f818000 goes up to 0x3f82, both
  /// raising Inexact (DDI0487F.c F6.1.68).
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VCVTB to a bfloat16 rounds to even``() =
    Assert.AreEqual<uint32 * uint32>((0x3f80u, 0x10u),
                                     s0After "eeb30960" 0u 0x3f808000u 0u)
    Assert.AreEqual<uint32 * uint32>((0x3f82u, 0x10u),
                                     s0After "eeb30960" 0u 0x3f818000u 0u)

  /// <summary>
  /// VFMAL and VFMSL add to each single of Dd the product of the halves of Sn
  /// and Sm under it (F6.1.89 and F6.1.92): 1 + 1 * 3 and 2 + 2 * 0.5, and
  /// with the first halves negated, 1 - 3 and 2 - 1.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VFMAL and VFMSL widen the halves into singles``() =
    let ds = [ 0, 0x400000003f800000UL; 1, 0x3800420040003c00UL ]
    let add, _, _ = fpRun "fc210831" 0u ds
    Assert.AreEqual<uint64>(0x4040000040800000UL, add)
    let sub, _, _ = fpRun "fca10831" 0u ds
    Assert.AreEqual<uint64>(0x3f800000c0000000UL, sub)

  [<TestMethod>]
  member _.``[ARMv7] LDA writes the loaded word to Rt``() =
    let written = writtenBy false "e1910c9f"
    Assert.AreEqual<bool>(true, Array.contains !.R0 written)

  /// <summary>
  /// VLDR.16 and VSTR.16 move a halfword, the bottom half of the
  /// single-precision register, which a load clears the top of (DDI0487F.c
  /// F6.1.113 and F6.1.245).
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VLDR.16 loads a halfword``() =
    let loads =
      liftedBy false "ed1b7947"
      |> Array.choose (function
        | Put(Src = Load(Type = rt; Addr = addr)) -> Some(rt, addr)
        | _ -> None)
    CollectionAssert.AreEqual([| 16<rt>, !.FP .- num 0x8eu |], loads)

  [<TestMethod>]
  member _.``[ARMv7] VSTR.16 stores a halfword``() =
    let sizes =
      liftedBy false "ed0b7947"
      |> Array.choose (function
        | Store(Value = value) -> Some(Expr.typeOf value)
        | _ -> None)
    CollectionAssert.AreEqual([| 16<rt> |], sizes)

  /// <summary>
  /// The PC as a base reads ahead of the instruction, eight bytes in A32 and
  /// four in T32: VLDR aligns what it reads to a word (DDI0487F.c F6.1.113),
  /// and VSTR, which only A32 allows it in, takes it as it reads (F6.1.245).
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VLDR and VSTR count from the PC as it reads``() =
    let addresses isThumb hex =
      liftedBy isThumb hex
      |> Array.choose (function
        | Put(Src = Load(Addr = addr)) -> Some addr
        | Store(Addr = addr) -> Some addr
        | _ -> None)
    let alignedPC = num 4u .* ((!.PC .+ num 4u) ./ num 4u)
    let ldr = addresses true "ed9f0a01"
    CollectionAssert.AreEqual([| alignedPC .+ num 4u |], ldr)
    let str = addresses false "ed8f0a01"
    CollectionAssert.AreEqual([| !.PC .+ num 8u .+ num 4u |], str)

  (* One test for each instruction DDI0406C and DDI0487F.c describes, in the
     order of its sections. A value test runs a word's lifting over inputs QEMU
     ran the word on (qemu-arm -cpu max) and asserts what QEMU left. A
     structural test is for a word a user-mode run cannot execute alone; its doc
     comment says what it checks, and its expectation is the manual's. *)
  /// <summary>
  /// A8.8.1 ADC: adc r0, r1, #0x0. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.1 ADC``() =
    let inputs =
      [ [ Gpr(0, 0xe0c8cefdu); Gpr(1, 0x1bab4a35u); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x69eee27au); Gpr(1, 0x31d527aeu); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu); Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x1bab4a36u) ]
        [ Gpr(0, 0x31d527aeu) ]
        [ Gpr(0, 0x0000ffffu) ] ]
    check false "e2a10000" inputs outputs

  /// <summary>
  /// A8.8.4 ADD: add r0, r1, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.4 ADD``() =
    let inputs =
      [ [ Gpr(0, 0x1b448276u); Gpr(1, 0x696f80c2u); Gpr(2, 0xf5999afcu) ]
        [ Gpr(0, 0x24229f4cu); Gpr(1, 0x37ba9a16u); Gpr(2, 0xa5f85e88u) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu); Gpr(2, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x5f091bbeu) ]
        [ Gpr(0, 0xddb2f89eu) ]
        [ Gpr(0, 0x00017fffu) ] ]
    check false "e0810002" inputs outputs

  /// <summary>
  /// A8.8.12 ADR: add r0, pc, #8. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.12 ADR``() =
    let inputs =
      [ [ Gpr(0, 0xa7d5b5a1u) ]
        [ Gpr(0, 0x8d61377au) ]
        [ Gpr(0, 0x00000001u) ] ]
    let outputs =
      [ [ Gpr(0, 0x30000010u) ]
        [ Gpr(0, 0x30000010u) ]
        [ Gpr(0, 0x30000010u) ] ]
    check false "e28f0008" inputs outputs

  /// <summary>
  /// A8.8.13 AND: and r0, r0, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.13 AND``() =
    let inputs =
      [ [ Gpr(0, 0xedab0028u); Gpr(2, 0x36ce21b5u) ]
        [ Gpr(0, 0x062f47bdu); Gpr(2, 0x383a6503u) ]
        [ Gpr(0, 0x00000001u); Gpr(2, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x248a0020u) ]
        [ Gpr(0, 0x002a4501u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e0000002" inputs outputs

  /// <summary>
  /// A8.8.16 ASR: asr r0, r0, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.16 ASR``() =
    let inputs =
      [ [ Gpr(0, 0xe648e16au); Gpr(2, 0x33101e1fu) ]
        [ Gpr(0, 0xe95c9fd9u); Gpr(2, 0x41f03d3fu) ]
        [ Gpr(0, 0x00000001u); Gpr(2, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xffffffffu) ]
        [ Gpr(0, 0xffffffffu) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e1a00250" inputs outputs

  /// <summary>
  /// A8.8.18 B: b 0x4 ; . This checks where it goes, PC + 8 + imm24:00
  /// (CodeAddr + 4 for an offset of -4), by a plain jump. It is not a value
  /// test because it branches, and a run inside one instruction cannot follow
  /// it to what QEMU would show.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.18 B``() =
    let run = runWith false "eaffffff" [] []
    Assert.AreEqual(Some(CodeAddr + 4UL), run.Target)
    let kinds = kindsOf false "eaffffff"
    CollectionAssert.AreEqual([| InterJmpKind.Base |], kinds)

  /// <summary>
  /// A8.8.19 BFC: bfc r0, #0x3, #0x5. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.19 BFC``() =
    let inputs =
      [ [ Gpr(0, 0xdf25423bu) ]
        [ Gpr(0, 0x03202094u) ]
        [ Gpr(0, 0x00000001u) ] ]
    let outputs =
      [ [ Gpr(0, 0xdf254203u) ]
        [ Gpr(0, 0x03202004u) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e7c7019f" inputs outputs

  /// <summary>
  /// A8.8.20 BFI: bfi r0, r1, #0x3, #0x5. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.20 BFI``() =
    let inputs =
      [ [ Gpr(0, 0x8805ae92u); Gpr(1, 0xc177b71cu) ]
        [ Gpr(0, 0xdfba69f1u); Gpr(1, 0xa5a3bec0u) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x8805aee2u) ]
        [ Gpr(0, 0xdfba6901u) ]
        [ Gpr(0, 0x000000f9u) ] ]
    check false "e7c70191" inputs outputs

  /// <summary>
  /// A8.8.21 BIC: bic r0, r1, #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.21 BIC``() =
    let inputs =
      [ [ Gpr(0, 0xce0bf691u); Gpr(1, 0x6b5d0b4eu) ]
        [ Gpr(0, 0xf6843868u); Gpr(1, 0xd0cc89c7u) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x6b5d0b4eu) ]
        [ Gpr(0, 0xd0cc89c7u) ]
        [ Gpr(0, 0x0000ffffu) ] ]
    check false "e3c10000" inputs outputs

  /// <summary>
  /// A8.8.24 BKPT: bkpt #0x3. This checks that it takes a breakpoint. It is not
  /// a value test because it takes an exception, which a user-mode run cannot
  /// return from.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.24 BKPT``() =
    let run = runWith false "e1200073" [ Cell.CPSR 0x10u ] []
    Assert.AreEqual(Some SideEffect.Breakpoint, run.Effect)

  /// <summary>
  /// A8.8.25 BL: bl 0x4 ; . This checks that it goes to PC + 8 - 4, puts the
  /// address of the next instruction in LR and stays in A32, and that the jump
  /// is a call. It is not a value test because it branches, and a run inside
  /// one instruction cannot follow it to what QEMU would show.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.25 BL``() =
    let run = runWith false "ebffffff" [ Cell.CPSR 0x10u ] []
    Assert.AreEqual(Some(CodeAddr + 4UL), run.Target)
    Assert.AreEqual(uint32 CodeAddr + 4u, run.Reg Register.LR)
    Assert.AreEqual(Cell.CPSR 0x10u, run.After(Cell.CPSR 0u))
    let kinds = kindsOf false "ebffffff"
    CollectionAssert.AreEqual([| InterJmpKind.IsCall |], kinds)

  /// <summary>
  /// A8.8.25 BLX: blx 0x4 ; . This checks that it goes to Align(PC, 4) - 4,
  /// puts the address of the next instruction in LR and selects T32. It is not
  /// a value test because it branches, and a run inside one instruction cannot
  /// follow it to what QEMU would show.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.25 BLX``() =
    let run = runWith false "faffffff" [ Cell.CPSR 0x10u ] []
    Assert.AreEqual(Some(CodeAddr + 4UL), run.Target)
    Assert.AreEqual(uint32 CodeAddr + 4u, run.Reg Register.LR)
    Assert.AreEqual(Cell.CPSR 0x30u, run.After(Cell.CPSR 0u))

  /// <summary>
  /// A8.8.27 BX: bx r1. This checks that it goes to Rm with bit 0 cleared,
  /// selecting T32 where bit 0 is set and A32 where it is clear. It is not a
  /// value test because it branches, and a run inside one instruction cannot
  /// follow it to what QEMU would show.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.27 BX``() =
    let thumb = [ Gpr(1, 0x30001001u); Cell.CPSR 0x10u ]
    let arm = [ Gpr(1, 0x30001000u); Cell.CPSR 0x30u ]
    let toThumb = runWith false "e12fff11" thumb []
    let toArm = runWith false "e12fff11" arm []
    Assert.AreEqual(Some 0x30001000UL, toThumb.Target)
    Assert.AreEqual(Cell.CPSR 0x30u, toThumb.After(Cell.CPSR 0u))
    Assert.AreEqual(Some 0x30001000UL, toArm.Target)
    Assert.AreEqual(Cell.CPSR 0x10u, toArm.After(Cell.CPSR 0u))

  /// <summary>
  /// A8.8.28 BXJ: bxj r1. This checks that it goes to Rm with bit 0 cleared,
  /// selecting T32 where bit 0 is set and A32 where it is clear: with no
  /// Jazelle state BXJ is BX. It is not a value test because it branches, and a
  /// run inside one instruction cannot follow it to what QEMU would show.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.28 BXJ``() =
    let thumb = [ Gpr(1, 0x30001001u); Cell.CPSR 0x10u ]
    let arm = [ Gpr(1, 0x30001000u); Cell.CPSR 0x30u ]
    let toThumb = runWith false "e12fff21" thumb []
    let toArm = runWith false "e12fff21" arm []
    Assert.AreEqual(Some 0x30001000UL, toThumb.Target)
    Assert.AreEqual(Cell.CPSR 0x30u, toThumb.After(Cell.CPSR 0u))
    Assert.AreEqual(Some 0x30001000UL, toArm.Target)
    Assert.AreEqual(Cell.CPSR 0x10u, toArm.After(Cell.CPSR 0u))

  /// <summary>
  /// A8.8.29 CBNZ: cbnz r0, 0x4 ; . This checks that it goes to PC + imm
  /// (CodeAddr + 4) when Rn is not zero and to the next instruction when it is.
  /// It is not a value test because it branches, and a run inside one
  /// instruction cannot follow it to what QEMU would show.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.29 CBNZ``() =
    let taken = runWith true "b900" [ Gpr(0, 5u) ] []
    let fallen = runWith true "b900" [ Gpr(0, 0u) ] []
    Assert.AreEqual(Some(CodeAddr + 4UL), taken.Target)
    Assert.AreEqual(Some(CodeAddr + 2UL), fallen.Target)

  /// <summary>
  /// A8.8.29 CBZ: cbz r0, 0x4 ; . This checks that it goes to PC + imm
  /// (CodeAddr + 4) when Rn is zero and to the next instruction when it is not.
  /// It is not a value test because it branches, and a run inside one
  /// instruction cannot follow it to what QEMU would show.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.29 CBZ``() =
    let taken = runWith true "b100" [ Gpr(0, 0u) ] []
    let fallen = runWith true "b100" [ Gpr(0, 5u) ] []
    Assert.AreEqual(Some(CodeAddr + 4UL), taken.Target)
    Assert.AreEqual(Some(CodeAddr + 2UL), fallen.Target)

  /// <summary>
  /// A8.8.30 CDP: cdp 7, 1, cr1, cr2, cr3, {4}. This checks that the lift says
  /// the instruction is unsupported: coprocessor 7 is none this front end
  /// models. It is not a value test because it reaches a coprocessor, which a
  /// user-mode run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.30 CDP``() =
    let run = runWith false "ee121783" [ Cell.CPSR 0x13u ] []
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.30 CDP2: cdp2 7, 1, cr1, cr2, cr3, {4}. This checks that the lift
  /// says the instruction is unsupported: coprocessor 7 is none this front end
  /// models. It is not a value test because it reaches a coprocessor, which a
  /// user-mode run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.30 CDP2``() =
    let run = runWith false "fe121783" [ Cell.CPSR 0x13u ] []
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.32 CLREX: clrex. This checks that it clears a reservation: STREX
  /// succeeds while one is held and fails after CLREX. It is not a value test
  /// because what it clears is a reservation no register shows.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.32 CLREX``() =
    let w = uint32 Window
    let held =
      [ Register.ExMonAddr, w + 16u; Register.ExMonVal, 0x1234u ]
    let cells = [ Gpr(1, w + 16u); Gpr(2, 0x5678u); M(16, 0x1234UL) ]
    let cleared = runWith false "f57ff01f" [] held
    let after = [ for r, _ in held -> r, cleared.Reg r ]
    let strex = "e1810f92"
    let holds = runWith false strex cells held
    let fails = runWith false strex cells after
    Assert.AreEqual(Gpr(0, 0u), holds.After(Gpr(0, 0u)))
    Assert.AreEqual(M(16, 0x5678UL), holds.After(M(16, 0UL)))
    Assert.AreEqual(Gpr(0, 1u), fails.After(Gpr(0, 0u)))
    Assert.AreEqual(M(16, 0x1234UL), fails.After(M(16, 0UL)))

  /// <summary>
  /// A8.8.33 CLZ: clz r0, r1. The outputs are what QEMU left after running it
  /// on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.33 CLZ``() =
    let inputs =
      [ [ Gpr(0, 0x58e22cb5u); Gpr(1, 0x0db78ed1u) ]
        [ Gpr(0, 0x3d880c9fu); Gpr(1, 0xb298e20eu) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000004u) ]
        [ Gpr(0, 0x00000000u) ]
        [ Gpr(0, 0x00000010u) ] ]
    check false "e16f0f11" inputs outputs

  /// <summary>
  /// A8.8.34 CMN: cmn r1, r2. The outputs are what QEMU left after running it
  /// on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.34 CMN``() =
    let inputs =
      [ [ Gpr(1, 0x693a999du); Gpr(2, 0xd5edf592u); Cell.CPSR 0x20000010u ]
        [ Gpr(1, 0x71e55c4eu); Gpr(2, 0xa50e2e7du); Cell.CPSR 0x900a0010u ]
        [ Gpr(1, 0x0000ffffu); Gpr(2, 0x00008000u); Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Cell.CPSR 0x20000010u ]
        [ Cell.CPSR 0x200a0010u ]
        [ Cell.CPSR 0x08050010u ] ]
    check false "e1710002" inputs outputs

  /// <summary>
  /// A8.8.37 CMP: cmp r1, #0x3. The outputs are what QEMU left after running it
  /// on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.37 CMP``() =
    let inputs =
      [ [ Gpr(1, 0x27db8b8au); Cell.CPSR 0x20000010u ]
        [ Gpr(1, 0x490867b1u); Cell.CPSR 0x900a0010u ]
        [ Gpr(1, 0x0000ffffu); Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Cell.CPSR 0x20000010u ]
        [ Cell.CPSR 0x200a0010u ]
        [ Cell.CPSR 0x28050010u ] ]
    check false "e3510003" inputs outputs

  /// <summary>
  /// A8.8.40 CPS: cps #0x13. This checks that it changes System mode to
  /// Supervisor mode and that in User mode it changes nothing. It is not a
  /// value test because it needs a privileged mode, which a user-mode run does
  /// not have.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.40 CPS``() =
    let user = runWith false "f1020013" [ Cell.CPSR 0x10u ] []
    let system = runWith false "f1020013" [ Cell.CPSR 0x1fu ] []
    Assert.AreEqual(Cell.CPSR 0x10u, user.After(Cell.CPSR 0u))
    Assert.AreEqual(Cell.CPSR 0x13u, system.After(Cell.CPSR 0u))

  /// <summary>
  /// A8.8.41 CPY: mov r0, r1. The outputs are what QEMU left after running it
  /// on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.41 CPY``() =
    let inputs =
      [ [ Gpr(0, 0x7d6ea74bu); Gpr(1, 0x8a4a883du) ]
        [ Gpr(0, 0x3310184fu); Gpr(1, 0xbd451676u) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x8a4a883du) ]
        [ Gpr(0, 0xbd451676u) ]
        [ Gpr(0, 0x0000ffffu) ] ]
    check false "e1a00001" inputs outputs

  /// <summary>
  /// A8.8.42 CSDB: csdb. It lifts to no statements: what it does is a hint or
  /// an ordering of memory accesses that one run cannot observe, and QEMU's
  /// runs of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.42 CSDB``() =
    Assert.AreEqual(0, (lift false "e320f014").Length)

  /// <summary>
  /// A8.8.43 DBG: dbg #0x4. It lifts to no statements: what it does is a hint
  /// or an ordering of memory accesses that one run cannot observe, and QEMU's
  /// runs of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.43 DBG``() =
    Assert.AreEqual(0, (lift false "e320f0f4").Length)

  /// <summary>
  /// A8.8.44 DMB: dmb sy. It lifts to no statements: what it does is a hint or
  /// an ordering of memory accesses that one run cannot observe, and QEMU's
  /// runs of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.44 DMB``() =
    Assert.AreEqual(0, (lift false "f57ff05f").Length)

  /// <summary>
  /// A8.8.45 DSB: dsb sy. It lifts to no statements: what it does is a hint or
  /// an ordering of memory accesses that one run cannot observe, and QEMU's
  /// runs of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.45 DSB``() =
    Assert.AreEqual(0, (lift false "f57ff04f").Length)

  /// <summary>
  /// A8.8.46 ENTERX: .inst 0xf3bf8f1f. This checks that it takes the Undefined
  /// Instruction exception. It is not a value test because it belongs to
  /// ThumbEE, which no QEMU model implements.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.46 ENTERX``() =
    let run = runWith true "f3bf8f1f" [ Cell.CPSR 0x10u ] []
    Assert.AreEqual(Some SideEffect.UndefinedInstruction, run.Effect)

  /// <summary>
  /// A8.8.47 EOR: eor r0, r1, #0xff00000. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.47 EOR``() =
    let inputs =
      [ [ Gpr(0, 0xc40db144u); Gpr(1, 0x357dcb85u) ]
        [ Gpr(0, 0xd7dff138u); Gpr(1, 0x78730531u) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x3a8dcb85u) ]
        [ Gpr(0, 0x77830531u) ]
        [ Gpr(0, 0x0ff0ffffu) ] ]
    check false "e22106ff" inputs outputs

  /// <summary>
  /// A8.8.50 ERET: eret. This checks that User mode refuses it, and that from
  /// Supervisor mode it returns to LR with CPSR taken from SPSR. It is not a
  /// value test because it needs a privileged mode, which a user-mode run does
  /// not have.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.50 ERET``() =
    let others =
      [ Register.SPSR, 0x80000010u; Register.LR, 0x30002000u ]
    let run = runWith false "e160006e" [ Cell.CPSR 0x13u ] others
    let refused = ManualLifting.refusedModes false "e160006e" [] others
    CollectionAssert.AreEqual([| 0x10u |], refused)
    Assert.AreEqual(Some 0x30002000UL, run.Target)
    Assert.AreEqual(Cell.CPSR 0x80000010u, run.After(Cell.CPSR 0u))

  /// <summary>
  /// A8.8.53 HVC: hvc 1. This checks that User mode refuses it and that every
  /// other mode reaches a call the lift does not model. It is not a value test
  /// because it takes an exception, which a user-mode run cannot return from.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.53 HVC``() =
    let run = runWith false "e1400071" [ Cell.CPSR 0x13u ] []
    let refused = ManualLifting.refusedModes false "e1400071" [] []
    CollectionAssert.AreEqual([| 0x10u |], refused)
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.54 ISB: isb sy. It lifts to no statements: what it does is a hint or
  /// an ordering of memory accesses that one run cannot observe, and QEMU's
  /// runs of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.54 ISB``() =
    Assert.AreEqual(0, (lift false "f57ff06f").Length)

  /// <summary>
  /// A8.8.55 IT: it eq. This checks that IT EQ sets ITSTATE to 0x08: firstcond
  /// 0000 and mask 1000, ITSTATE&lt;7:2&gt; in CPSR&lt;15:10&gt;. It is not a
  /// value test because it only conditions the instructions after it, and its
  /// state is none MRS shows.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.55 IT``() =
    let run = runWith true "bf08" [ Cell.CPSR 0x30u ] []
    Assert.AreEqual(Cell.CPSR 0x830u, run.After(Cell.CPSR 0u))

  /// <summary>
  /// A8.8.56 LDC: ldc 7, cr1, [r1, #8]. This checks that the lift says the
  /// instruction is unsupported: coprocessor 7 is none this front end models.
  /// It is not a value test because it reaches a coprocessor, which a user-mode
  /// run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.56 LDC``() =
    let run = runWith false "ed911702" [ Cell.CPSR 0x13u ] []
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.56 LDC2: ldc2 7, cr1, [r1, #8]. This checks that the lift says the
  /// instruction is unsupported: coprocessor 7 is none this front end models.
  /// It is not a value test because it reaches a coprocessor, which a user-mode
  /// run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.56 LDC2``() =
    let run = runWith false "fd911702" [ Cell.CPSR 0x13u ] []
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.58 LDM: ldm r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.58 LDM``() =
    let inputs =
      [ [ Gpr(1, 0x20000818u)
          Gpr(2, 0xd24a816fu)
          Gpr(3, 0x6be77da5u)
          M(0, 0x2cd339e848e68bc1UL)
          M(8, 0xd53f4c3c6778110bUL)
          M(16, 0xf3d4c4a053822300UL)
          M(24, 0x9420bb3b8537e308UL)
          M(32, 0xe17559e0263abd6aUL)
          M(40, 0x5fd3109124a1b109UL)
          M(48, 0x72ff09ed5f2d1a46UL)
          M(56, 0xc8505b3d50a96beeUL) ]
        [ Gpr(1, 0x20000818u)
          Gpr(2, 0x54ca4cf8u)
          Gpr(3, 0x65a5d067u)
          M(0, 0x78b17a43de12b5bfUL)
          M(8, 0xb76a29481d2c7e0cUL)
          M(16, 0xe21a8e9e682d8e44UL)
          M(24, 0x7e25f38febe799d5UL)
          M(32, 0xccb1e1f072c4732fUL)
          M(40, 0x8a06041236dd11e4UL)
          M(48, 0xf0168d4a83e87ff7UL)
          M(56, 0xa820166edc82280dUL) ]
        [ Gpr(1, 0x20000818u)
          Gpr(2, 0x00008000u)
          Gpr(3, 0x7fff8000u)
          M(0, 0x47ae094c18ae62f2UL)
          M(8, 0x2df60ad976519323UL)
          M(16, 0xafd4b7e54da726d3UL)
          M(24, 0x87998130450b401fUL)
          M(32, 0xb32b6b3e7b785829UL)
          M(40, 0x79516c8f1d9bf382UL)
          M(48, 0x92404ee3d00df791UL)
          M(56, 0x6186b929b530673bUL) ] ]
    let outputs =
      [ [ Gpr(2, 0x8537e308u); Gpr(3, 0x9420bb3bu) ]
        [ Gpr(2, 0xebe799d5u); Gpr(3, 0x7e25f38fu) ]
        [ Gpr(2, 0x450b401fu); Gpr(3, 0x87998130u) ] ]
    check false "e891000c" inputs outputs

  /// <summary>
  /// A8.8.58 LDMFD: ldm r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.58 LDMFD``() =
    let inputs =
      [ [ Gpr(1, 0x20000818u)
          Gpr(2, 0x124d92f3u)
          Gpr(3, 0x4a9abec4u)
          M(0, 0x75cb864c08686fabUL)
          M(8, 0xc27abc98673f7f06UL)
          M(16, 0x0e4a46cd8a6a6adaUL)
          M(24, 0x390f9714617c45c6UL)
          M(32, 0x81f83c29133b627fUL)
          M(40, 0xef515b4a037cbf27UL)
          M(48, 0x80d968b669720aa4UL)
          M(56, 0xafd2aa5b47de6220UL) ]
        [ Gpr(1, 0x20000818u)
          Gpr(2, 0xd4c16d3cu)
          Gpr(3, 0xad5a68fbu)
          M(0, 0x693ef7414799c979UL)
          M(8, 0x25e1bfdc0c2871f1UL)
          M(16, 0x36ed4db66488d611UL)
          M(24, 0xd46d7315b49a5808UL)
          M(32, 0x240842e25342c78bUL)
          M(40, 0xc1ecd028ae3609cfUL)
          M(48, 0x9443130721bd98deUL)
          M(56, 0xf36c491ae5995590UL) ]
        [ Gpr(1, 0x20000818u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0x48ba9e83608a3710UL)
          M(8, 0xe8e1981cc9731b8cUL)
          M(16, 0xa6fd0ee28bc4976fUL)
          M(24, 0xc4c6e415c9842addUL)
          M(32, 0xb476528cc233fad3UL)
          M(40, 0xc1b4ce0afdab871bUL)
          M(48, 0x8e323d87d3a586cbUL)
          M(56, 0x7b3199c86d5a9206UL) ] ]
    let outputs =
      [ [ Gpr(2, 0x617c45c6u); Gpr(3, 0x390f9714u) ]
        [ Gpr(2, 0xb49a5808u); Gpr(3, 0xd46d7315u) ]
        [ Gpr(2, 0xc9842addu); Gpr(3, 0xc4c6e415u) ] ]
    check false "e891000c" inputs outputs

  /// <summary>
  /// A8.8.58 LDMIA: ldm r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.58 LDMIA``() =
    let inputs =
      [ [ Gpr(1, 0x20000818u)
          Gpr(2, 0x79a0344fu)
          Gpr(3, 0x5472203du)
          M(0, 0xc6643cb493abf870UL)
          M(8, 0x0fae0a19dfffbcdbUL)
          M(16, 0xf7a5a1c760a9fd09UL)
          M(24, 0x3cdb2970f00b501bUL)
          M(32, 0xb9218517cca38865UL)
          M(40, 0x4748099dca94f92bUL)
          M(48, 0x5bc83ffc61db8e27UL)
          M(56, 0x9e042615945c4816UL) ]
        [ Gpr(1, 0x20000818u)
          Gpr(2, 0x3f554437u)
          Gpr(3, 0x34c945b9u)
          M(0, 0x70583fdc3a4efdc3UL)
          M(8, 0xbbbd6ba4962ac2f6UL)
          M(16, 0x5658cab48888051aUL)
          M(24, 0xbb4de7b6d461577bUL)
          M(32, 0x387aa9bac491745fUL)
          M(40, 0x5dbbc0b75cfc06eeUL)
          M(48, 0x9899d07392cbfdf1UL)
          M(56, 0x457196a944390b8dUL) ]
        [ Gpr(1, 0x20000818u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0xd7845906e43b5653UL)
          M(8, 0x9cc5c6ba40b5bfb8UL)
          M(16, 0x5754af4d470cdcb4UL)
          M(24, 0x594902ab0cbc0f0bUL)
          M(32, 0x5f1f6b1931ca72a7UL)
          M(40, 0xb34c6e5e855579cdUL)
          M(48, 0x83547cec7f51db32UL)
          M(56, 0x07289a99ef902212UL) ] ]
    let outputs =
      [ [ Gpr(2, 0xf00b501bu); Gpr(3, 0x3cdb2970u) ]
        [ Gpr(2, 0xd461577bu); Gpr(3, 0xbb4de7b6u) ]
        [ Gpr(2, 0x0cbc0f0bu); Gpr(3, 0x594902abu) ] ]
    check false "e891000c" inputs outputs

  /// <summary>
  /// A8.8.60 LDMDA: ldmda r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.60 LDMDA``() =
    let inputs =
      [ [ Gpr(1, 0x2000081cu)
          Gpr(2, 0xcd6c990cu)
          Gpr(3, 0xfb0c1475u)
          M(0, 0xa90df2360216823fUL)
          M(8, 0x9ff10eb6de06545fUL)
          M(16, 0xf38ecf80ded00e54UL)
          M(24, 0x568684f98fdd238aUL)
          M(32, 0x9c1204e4006ae531UL)
          M(40, 0xec476a400ab72d3fUL)
          M(48, 0x93bf397e46b8df8dUL)
          M(56, 0xfc3620ec7f40980fUL) ]
        [ Gpr(1, 0x2000081cu)
          Gpr(2, 0x74c85b15u)
          Gpr(3, 0x284bc57cu)
          M(0, 0xe4e83ae7ac34f1aaUL)
          M(8, 0x561d580594b8ba89UL)
          M(16, 0x293911e78458c9e0UL)
          M(24, 0x8cae4207f888e286UL)
          M(32, 0xa73a01030f658c38UL)
          M(40, 0x74d796418f75e775UL)
          M(48, 0xd059577ffc4b8bbfUL)
          M(56, 0x0392db73d8ab5298UL) ]
        [ Gpr(1, 0x2000081cu)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0x3998b24fc4176732UL)
          M(8, 0x5ce4fc8548aa948dUL)
          M(16, 0xdf702025d16dbf6fUL)
          M(24, 0xd6ca3b98c3dd80ccUL)
          M(32, 0xbef4fc1b826307dbUL)
          M(40, 0x3f68bad5a175b1f9UL)
          M(48, 0xc35d3f314f09f4e2UL)
          M(56, 0x2f424440e715f707UL) ] ]
    let outputs =
      [ [ Gpr(2, 0x8fdd238au); Gpr(3, 0x568684f9u) ]
        [ Gpr(2, 0xf888e286u); Gpr(3, 0x8cae4207u) ]
        [ Gpr(2, 0xc3dd80ccu); Gpr(3, 0xd6ca3b98u) ] ]
    check false "e811000c" inputs outputs

  /// <summary>
  /// A8.8.60 LDMFA: ldmda r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.60 LDMFA``() =
    let inputs =
      [ [ Gpr(1, 0x2000081cu)
          Gpr(2, 0x3344dda3u)
          Gpr(3, 0xda7c9e92u)
          M(0, 0xb51b9bb75bfc34f4UL)
          M(8, 0x9849a6f5141c5845UL)
          M(16, 0xc0fd8e6d31bd275dUL)
          M(24, 0x06ae0646b8e5b3c6UL)
          M(32, 0x81f7c668efaaaf7cUL)
          M(40, 0x070d099b98c4f1f3UL)
          M(48, 0x75f6fd6e5937e35bUL)
          M(56, 0xe732a8ac9e6d03e9UL) ]
        [ Gpr(1, 0x2000081cu)
          Gpr(2, 0x1ff68a97u)
          Gpr(3, 0x37eecf5fu)
          M(0, 0x33ef4651063c1e7aUL)
          M(8, 0x81dcce4b10848bd7UL)
          M(16, 0x2f768baf2bfc6e5dUL)
          M(24, 0x0420b47c0b102ad0UL)
          M(32, 0xd5d3465fb33d3145UL)
          M(40, 0x05e689b0408c9704UL)
          M(48, 0x7a593ad163389912UL)
          M(56, 0xda468af198b5b17eUL) ]
        [ Gpr(1, 0x2000081cu)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0x7d9a997fb642030bUL)
          M(8, 0x322d765c46db1c7eUL)
          M(16, 0x3386c48440a316e3UL)
          M(24, 0x5195d90cf96f7e4aUL)
          M(32, 0x2363d2ffa30f2e57UL)
          M(40, 0x1f695b76393a254eUL)
          M(48, 0x83fc8a2224faff09UL)
          M(56, 0xb315e6816322063cUL) ] ]
    let outputs =
      [ [ Gpr(2, 0xb8e5b3c6u); Gpr(3, 0x06ae0646u) ]
        [ Gpr(2, 0x0b102ad0u); Gpr(3, 0x0420b47cu) ]
        [ Gpr(2, 0xf96f7e4au); Gpr(3, 0x5195d90cu) ] ]
    check false "e811000c" inputs outputs

  /// <summary>
  /// A8.8.61 LDMDB: ldmdb r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.61 LDMDB``() =
    let inputs =
      [ [ Gpr(1, 0x20000820u)
          Gpr(2, 0xe796a698u)
          Gpr(3, 0x28340f56u)
          M(0, 0x9960477f3280cef1UL)
          M(8, 0xef68c8e1ea560eb1UL)
          M(16, 0x6f1e9f493991fdf6UL)
          M(24, 0x55e48fcec851ebdfUL)
          M(32, 0x0df14a1be35d1ceeUL)
          M(40, 0x3bad1ae401c23ec1UL)
          M(48, 0xd7338cf7847dd0aaUL)
          M(56, 0x1d56f7f36b9c9797UL) ]
        [ Gpr(1, 0x20000820u)
          Gpr(2, 0x4c497544u)
          Gpr(3, 0x3d65d360u)
          M(0, 0x97160615553fa5d7UL)
          M(8, 0x41f9f230dde24fffUL)
          M(16, 0xad931d77c2d5ec1eUL)
          M(24, 0xfbd32aa0102392b7UL)
          M(32, 0xec43f6f90f439eb9UL)
          M(40, 0x65f9035e0d1f8ca1UL)
          M(48, 0x8eaa5bfaadbe1c9eUL)
          M(56, 0xce2f381f68c781feUL) ]
        [ Gpr(1, 0x20000820u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0xbdaeab6467b18b4cUL)
          M(8, 0xe0742fc49a7c1acdUL)
          M(16, 0xed3329abd5a4b5d3UL)
          M(24, 0x7e9e8993f8c05ceeUL)
          M(32, 0x0f871c588d6036e2UL)
          M(40, 0x73c28e4da420c6f5UL)
          M(48, 0xfb4ebc724af97956UL)
          M(56, 0x62ffe685a4bfcb11UL) ] ]
    let outputs =
      [ [ Gpr(2, 0xc851ebdfu); Gpr(3, 0x55e48fceu) ]
        [ Gpr(2, 0x102392b7u); Gpr(3, 0xfbd32aa0u) ]
        [ Gpr(2, 0xf8c05ceeu); Gpr(3, 0x7e9e8993u) ] ]
    check false "e911000c" inputs outputs

  /// <summary>
  /// A8.8.61 LDMEA: ldmdb r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.61 LDMEA``() =
    let inputs =
      [ [ Gpr(1, 0x20000820u)
          Gpr(2, 0x31a686acu)
          Gpr(3, 0xa390e527u)
          M(0, 0x1518d869360e7c83UL)
          M(8, 0x401652cebe12d0b0UL)
          M(16, 0x740eb761058f2e5dUL)
          M(24, 0x1376537667476efdUL)
          M(32, 0x28c2a7f0f09ea2a3UL)
          M(40, 0x6f63e35379257423UL)
          M(48, 0x10b1489dcabfe1dfUL)
          M(56, 0xf13ece45389af25fUL) ]
        [ Gpr(1, 0x20000820u)
          Gpr(2, 0xbe07b4a8u)
          Gpr(3, 0x1d561767u)
          M(0, 0x90b21a0a2f4e2cd6UL)
          M(8, 0x322b5e2aa94b1c1dUL)
          M(16, 0xffae00b86cf00b7bUL)
          M(24, 0xe0dc0c3289703abfUL)
          M(32, 0x44cea8662326dcf4UL)
          M(40, 0xd278a57cb7d87f30UL)
          M(48, 0x48469aa0b82a2316UL)
          M(56, 0x81fea5e4ee777e19UL) ]
        [ Gpr(1, 0x20000820u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0x3d70f58985e724f9UL)
          M(8, 0xf51c4919039ef43eUL)
          M(16, 0x50f65e5df3670fb3UL)
          M(24, 0x7827d75d8080d297UL)
          M(32, 0x95f4a98bd188e081UL)
          M(40, 0xa048e1217047a98aUL)
          M(48, 0x62f4c17b079fd4b1UL)
          M(56, 0x4697d017bab24d67UL) ] ]
    let outputs =
      [ [ Gpr(2, 0x67476efdu); Gpr(3, 0x13765376u) ]
        [ Gpr(2, 0x89703abfu); Gpr(3, 0xe0dc0c32u) ]
        [ Gpr(2, 0x8080d297u); Gpr(3, 0x7827d75du) ] ]
    check false "e911000c" inputs outputs

  /// <summary>
  /// A8.8.62 LDMED: ldmib r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.62 LDMED``() =
    let inputs =
      [ [ Gpr(1, 0x20000814u)
          Gpr(2, 0x0aa9bf99u)
          Gpr(3, 0x90aafb50u)
          M(0, 0xd6cb60d98f94dd7fUL)
          M(8, 0x77d96f44f9593d6aUL)
          M(16, 0x20701e2fd8f6f590UL)
          M(24, 0xa22dc6205bdc0cc7UL)
          M(32, 0xfff09d722b69b794UL)
          M(40, 0x85fb9d9d49665d45UL)
          M(48, 0xe901d37398ca5f13UL)
          M(56, 0x41416cda4a8726bdUL) ]
        [ Gpr(1, 0x20000814u)
          Gpr(2, 0x2290a5fau)
          Gpr(3, 0x9bec9711u)
          M(0, 0xf1a62f558b13cec4UL)
          M(8, 0x6cd4c75c1899a470UL)
          M(16, 0x9c95fb2821dccd96UL)
          M(24, 0x2bd3cf2dc674750cUL)
          M(32, 0xd99927734cade9e9UL)
          M(40, 0xfae580895e65413cUL)
          M(48, 0xfe1c3848d96bbf74UL)
          M(56, 0xf863637441095337UL) ]
        [ Gpr(1, 0x20000814u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0xa5ab364b71874969UL)
          M(8, 0x41546f8808b418f9UL)
          M(16, 0x7db3eb3478c17746UL)
          M(24, 0x8c762c95a4b0c643UL)
          M(32, 0xc67c2821c1ec6ee5UL)
          M(40, 0x2923d62839e57ab7UL)
          M(48, 0xdef4915103e86e46UL)
          M(56, 0xac28315b5bf85459UL) ] ]
    let outputs =
      [ [ Gpr(2, 0x5bdc0cc7u); Gpr(3, 0xa22dc620u) ]
        [ Gpr(2, 0xc674750cu); Gpr(3, 0x2bd3cf2du) ]
        [ Gpr(2, 0xa4b0c643u); Gpr(3, 0x8c762c95u) ] ]
    check false "e991000c" inputs outputs

  /// <summary>
  /// A8.8.62 LDMIB: ldmib r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.62 LDMIB``() =
    let inputs =
      [ [ Gpr(1, 0x20000814u)
          Gpr(2, 0x2fec3e87u)
          Gpr(3, 0xff3a144fu)
          M(0, 0x3126ac99e85f7c06UL)
          M(8, 0xc37e96ca504ffd8cUL)
          M(16, 0x4bea083d8d0c8212UL)
          M(24, 0x586d75fd201cabb7UL)
          M(32, 0x8aa3f093b3770661UL)
          M(40, 0x07c6acaa0549a9edUL)
          M(48, 0x272bfb4058ea97c3UL)
          M(56, 0x954f6e08b5d4addaUL) ]
        [ Gpr(1, 0x20000814u)
          Gpr(2, 0xc0d348c2u)
          Gpr(3, 0x5fd921bdu)
          M(0, 0x3900e8215fdfa943UL)
          M(8, 0x7bc5cd08a9876666UL)
          M(16, 0x1ee5fddad9c654bfUL)
          M(24, 0xd7913351a7de87b1UL)
          M(32, 0xe3ad285f7232e362UL)
          M(40, 0x943ad20628a8d4acUL)
          M(48, 0xd1f40e4979af5396UL)
          M(56, 0x0cf2f16e5a32f5fdUL) ]
        [ Gpr(1, 0x20000814u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0x6bad15c9586d7073UL)
          M(8, 0x21fa406cac0bcedcUL)
          M(16, 0x87107521624b8671UL)
          M(24, 0x84a97f3bfb5bfea3UL)
          M(32, 0x331901464f18b4deUL)
          M(40, 0xa832f34d6e4d7770UL)
          M(48, 0x941b9e416547bb42UL)
          M(56, 0xbf4487ca7675e946UL) ] ]
    let outputs =
      [ [ Gpr(2, 0x201cabb7u); Gpr(3, 0x586d75fdu) ]
        [ Gpr(2, 0xa7de87b1u); Gpr(3, 0xd7913351u) ]
        [ Gpr(2, 0xfb5bfea3u); Gpr(3, 0x84a97f3bu) ] ]
    check false "e991000c" inputs outputs

  /// <summary>
  /// A8.8.63 LDR: ldr r0, [r1, #16]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.63 LDR``() =
    let inputs =
      [ [ Gpr(0, 0x04bd2e00u)
          Gpr(1, 0x20000800u)
          M(0, 0x8689c7c835fbd53dUL)
          M(8, 0x21fb1579ff1e6a54UL)
          M(16, 0xf921a829847e8183UL)
          M(24, 0x907df7bd430037b6UL)
          M(32, 0x23316a10c3edf8fdUL)
          M(40, 0xa414d6162d701b0aUL)
          M(48, 0xce7589bd84a086ffUL)
          M(56, 0x77ccdc9460479ffdUL) ]
        [ Gpr(0, 0x5ea4f477u)
          Gpr(1, 0x20000800u)
          M(0, 0x933ffeb11b4b5d5bUL)
          M(8, 0x047dc1c73cc753bdUL)
          M(16, 0x3b738ed706309ebbUL)
          M(24, 0x0555c461fc76f264UL)
          M(32, 0x3cb545c5eb3f8dcdUL)
          M(40, 0xa950d2a2eec57dc4UL)
          M(48, 0x1e8584f1743e0597UL)
          M(56, 0x55dbd2eaeeac5a74UL) ]
        [ Gpr(0, 0x00000001u)
          Gpr(1, 0x20000800u)
          M(0, 0xf13e828cb5dc1ba9UL)
          M(8, 0xc5bd485e85bec730UL)
          M(16, 0xc17dcd59b04e3a25UL)
          M(24, 0x32de44a2e51b247cUL)
          M(32, 0xa4a71a5877e06a80UL)
          M(40, 0x76dbba6404b63589UL)
          M(48, 0xffd7d33ec1889273UL)
          M(56, 0x1dbbff83afed1af7UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x847e8183u) ]
        [ Gpr(0, 0x06309ebbu) ]
        [ Gpr(0, 0xb04e3a25u) ] ]
    check false "e5910010" inputs outputs

  /// <summary>
  /// A8.8.68 LDRB: ldrb r0, [r1, #3]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.68 LDRB``() =
    let inputs =
      [ [ Gpr(0, 0x1cccd6e0u)
          Gpr(1, 0x2000080du)
          M(0, 0xf4d54c7bff247718UL)
          M(8, 0x624c1a7a4d3187bbUL)
          M(16, 0xce7d3d9d9a1f76e8UL)
          M(24, 0x812bcb1587ef5c1cUL)
          M(32, 0xf83e8aea900ac0f3UL)
          M(40, 0x8f5da4549ee3529dUL)
          M(48, 0xa3136681e097aa10UL)
          M(56, 0x840789a98e1cdd7cUL) ]
        [ Gpr(0, 0xe9f96710u)
          Gpr(1, 0x2000080du)
          M(0, 0x87be41d9aee6a283UL)
          M(8, 0xb0039419601899a9UL)
          M(16, 0xac108e274ee6c2b0UL)
          M(24, 0x4697ac42bedc66d2UL)
          M(32, 0x41fbe5c5b562028dUL)
          M(40, 0x85e956ab8d3198fcUL)
          M(48, 0x09ae4fd7dbd832a6UL)
          M(56, 0x6afdc9a714610ce2UL) ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x2000080du)
          M(0, 0x70d57d8fe0cad224UL)
          M(8, 0xf2cabb38356c6730UL)
          M(16, 0x63f21f9654753738UL)
          M(24, 0x9f58cc9a8946a1a0UL)
          M(32, 0xb52170f6ef06f063UL)
          M(40, 0xe98db227d68d1b5eUL)
          M(48, 0x217ca53fcdaae8f5UL)
          M(56, 0x702b529a3cf512fdUL) ] ]
    let outputs =
      [ [ Gpr(0, 0x000000e8u) ]
        [ Gpr(0, 0x000000b0u) ]
        [ Gpr(0, 0x00000038u) ] ]
    check false "e5d10003" inputs outputs

  /// <summary>
  /// A8.8.72 LDRBT: ldrbt r0, [r1], #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.72 LDRBT``() =
    let inputs =
      [ [ Gpr(0, 0x3999396eu)
          Gpr(1, 0x20000810u)
          M(0, 0x88d3d2693a5d1f51UL)
          M(8, 0xe1e70c3a2ce2121fUL)
          M(16, 0x195ef490da4a1496UL)
          M(24, 0x04724b9327eaeb4bUL)
          M(32, 0x14bad4c91a3f4270UL)
          M(40, 0x6fa532b2bf7d772aUL)
          M(48, 0x9085a979c94bb7e6UL)
          M(56, 0x3d8c2ea07b7d9067UL) ]
        [ Gpr(0, 0x657aa484u)
          Gpr(1, 0x20000810u)
          M(0, 0x10d07e559025ef7aUL)
          M(8, 0xd2e7a19903831534UL)
          M(16, 0xde6736f480835285UL)
          M(24, 0xdccc5bb678e14446UL)
          M(32, 0x11a1f67ee6a95e5dUL)
          M(40, 0x954f66df5d181b61UL)
          M(48, 0x3f8ea2eb6aab3701UL)
          M(56, 0xe6668c4cd1cc1df5UL) ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x20000810u)
          M(0, 0x5423f3028f380715UL)
          M(8, 0x12de2bddb40a9721UL)
          M(16, 0xf61840217466f4e4UL)
          M(24, 0x2b0cb0001e13d205UL)
          M(32, 0xde42d5d2ff19e263UL)
          M(40, 0xe2a4d290b795c6f5UL)
          M(48, 0xde3ee721511c61a5UL)
          M(56, 0x94119308b89d8c99UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000096u); Gpr(1, 0x20000810u) ]
        [ Gpr(0, 0x00000085u); Gpr(1, 0x20000810u) ]
        [ Gpr(0, 0x000000e4u); Gpr(1, 0x20000810u) ] ]
    check false "e4f10000" inputs outputs

  /// <summary>
  /// A8.8.73 LDRD: ldrd r2, [r1, #8]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.73 LDRD``() =
    let inputs =
      [ [ Gpr(1, 0x20000808u)
          Gpr(2, 0x4984ac2du)
          Gpr(3, 0xff49f626u)
          M(0, 0x610ae07dc1483933UL)
          M(8, 0x52a5b2f270622f94UL)
          M(16, 0xa3ffa68170b501dfUL)
          M(24, 0xae0b65c20768c1daUL)
          M(32, 0x5a5f91d827e8a1e4UL)
          M(40, 0xe9b2c3b3ae6e3997UL)
          M(48, 0x96c4d41237b92d27UL)
          M(56, 0x4ada33b99512f8b8UL) ]
        [ Gpr(1, 0x20000808u)
          Gpr(2, 0x9a4df448u)
          Gpr(3, 0x998d863au)
          M(0, 0x3e7e241972643271UL)
          M(8, 0x7576aac7f4391a56UL)
          M(16, 0x078448a1f6810c56UL)
          M(24, 0x942c196cb6cd21aaUL)
          M(32, 0x598fa67639bec77aUL)
          M(40, 0xa071082451bc6449UL)
          M(48, 0x053014e749f1d92cUL)
          M(56, 0x327e6a3433969ebdUL) ]
        [ Gpr(1, 0x20000808u)
          Gpr(2, 0x7fff8000u)
          Gpr(3, 0x00000000u)
          M(0, 0x6eca43b10d2766c0UL)
          M(8, 0x785904bc24b28df1UL)
          M(16, 0xd72d918d81383fecUL)
          M(24, 0x162167fe720fe1ccUL)
          M(32, 0xac28432f6e00ed3fUL)
          M(40, 0x01d790a5bdfdf325UL)
          M(48, 0x74d5dcc2e751dd87UL)
          M(56, 0x19e2436052be505fUL) ] ]
    let outputs =
      [ [ Gpr(2, 0x70b501dfu); Gpr(3, 0xa3ffa681u) ]
        [ Gpr(2, 0xf6810c56u); Gpr(3, 0x078448a1u) ]
        [ Gpr(2, 0x81383fecu); Gpr(3, 0xd72d918du) ] ]
    check false "e1c120d8" inputs outputs

  /// <summary>
  /// A8.8.76 LDREX: ldrex r0, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.76 LDREX``() =
    let inputs =
      [ [ Gpr(0, 0x86a0ff5du)
          Gpr(1, 0x20000810u)
          M(0, 0xa49f9c2a7378cba7UL)
          M(8, 0x4418aefe37907debUL)
          M(16, 0xc62ec65fff5727c7UL)
          M(24, 0x9c0bdeb95ec4f3a6UL)
          M(32, 0x9b058465748808edUL)
          M(40, 0x9c9e90360bd3e22eUL)
          M(48, 0x57c37ac7b9fb3cfaUL)
          M(56, 0xb4598f41d2839c94UL) ]
        [ Gpr(0, 0x436d2684u)
          Gpr(1, 0x20000810u)
          M(0, 0x6efcffae455c9da8UL)
          M(8, 0x4bd4525bdee03ce6UL)
          M(16, 0xdfe8e00a80fea8faUL)
          M(24, 0xff610aacdc24eabbUL)
          M(32, 0x16602b15dbfb83b6UL)
          M(40, 0x5356ea201b4dbfc8UL)
          M(48, 0x071e459d06bd7c9dUL)
          M(56, 0x5dc17afa270b58d3UL) ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x20000810u)
          M(0, 0xddddddd82d003151UL)
          M(8, 0x4fb0eed07e7b3c2eUL)
          M(16, 0x1fc0d2a6c1c66032UL)
          M(24, 0x3c3811ff2aa6c78fUL)
          M(32, 0xd80fe55aa3edbc82UL)
          M(40, 0xf99dfe5b6c2c9dc9UL)
          M(48, 0x1501b6e8eaf8355cUL)
          M(56, 0x692a16ffd70afee3UL) ] ]
    let outputs =
      [ [ Gpr(0, 0xff5727c7u) ]
        [ Gpr(0, 0x80fea8fau) ]
        [ Gpr(0, 0xc1c66032u) ] ]
    check false "e1910f9f" inputs outputs

  /// <summary>
  /// A8.8.77 LDREXB: ldrexb r0, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.77 LDREXB``() =
    let inputs =
      [ [ Gpr(0, 0x2f1241e4u)
          Gpr(1, 0x20000810u)
          M(0, 0xfdfe8c9b3166df0cUL)
          M(8, 0xa319c63ed1d4c115UL)
          M(16, 0x1a6170a6fabf85d7UL)
          M(24, 0x7a38e76b550b1adeUL)
          M(32, 0xe9c04654e4fcb76fUL)
          M(40, 0x45de861b496a492cUL)
          M(48, 0x844e11d0be70f405UL)
          M(56, 0x86ab9dbc32b6ba08UL) ]
        [ Gpr(0, 0x896c2345u)
          Gpr(1, 0x20000810u)
          M(0, 0x5fc42983fd7341c5UL)
          M(8, 0x412185914cd13ae8UL)
          M(16, 0x3e5289f451595979UL)
          M(24, 0xc6f8f739d2037661UL)
          M(32, 0xf72d85aee5c584ffUL)
          M(40, 0x6d7a4c7fb913bd0cUL)
          M(48, 0xd23f641a92a250a0UL)
          M(56, 0xb7f8a02a4f677b5bUL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          M(0, 0xc14906c5e513f6d5UL)
          M(8, 0x993a86dc74434eccUL)
          M(16, 0xaba83205a57a7603UL)
          M(24, 0x12f5a3863658f9ddUL)
          M(32, 0x9e5e60eebad8e0b0UL)
          M(40, 0xaaca678119f6ac18UL)
          M(48, 0x6ab16a14fedc6b75UL)
          M(56, 0x5df040510bee62e6UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x000000d7u) ]
        [ Gpr(0, 0x00000079u) ]
        [ Gpr(0, 0x00000003u) ] ]
    check false "e1d10f9f" inputs outputs

  /// <summary>
  /// A8.8.78 LDREXD: ldrexd r0, r1, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.78 LDREXD``() =
    let inputs =
      [ [ Gpr(0, 0x03c3746cu)
          Gpr(1, 0x20000810u)
          M(0, 0x0ea25c347938ff83UL)
          M(8, 0x73d9e8adab118f1dUL)
          M(16, 0xe195001548643fe1UL)
          M(24, 0x98c2260e2afd08c7UL)
          M(32, 0xf62eb49d49de2eaaUL)
          M(40, 0xd937716b09ffb51aUL)
          M(48, 0x804ae97321ede4fdUL)
          M(56, 0xf21acad8b58d57f6UL) ]
        [ Gpr(0, 0x991abe20u)
          Gpr(1, 0x20000810u)
          M(0, 0xf5ebb1f73cdb6872UL)
          M(8, 0x4a09021b81cabb73UL)
          M(16, 0x12118163298b861bUL)
          M(24, 0xbea786f6de51993dUL)
          M(32, 0x3a34e0cce850457eUL)
          M(40, 0x188a6781fa0e0d38UL)
          M(48, 0x1a39527d9c225ea9UL)
          M(56, 0x929cb001941f147cUL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          M(0, 0x763e7a3a463458e4UL)
          M(8, 0xe1cb9153b3f43e4dUL)
          M(16, 0xc4a96013cb774e4bUL)
          M(24, 0xd4fb436cc92da1aeUL)
          M(32, 0x4ab4ae2db1325d29UL)
          M(40, 0x82f28d761fe8864dUL)
          M(48, 0x5b0a3bc48f31640fUL)
          M(56, 0xc02fbd4faa7e405fUL) ] ]
    let outputs =
      [ [ Gpr(0, 0x48643fe1u); Gpr(1, 0xe1950015u) ]
        [ Gpr(0, 0x298b861bu); Gpr(1, 0x12118163u) ]
        [ Gpr(0, 0xcb774e4bu); Gpr(1, 0xc4a96013u) ] ]
    check false "e1b10f9f" inputs outputs

  /// <summary>
  /// A8.8.79 LDREXH: ldrexh r0, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.79 LDREXH``() =
    let inputs =
      [ [ Gpr(0, 0x4031bf2eu)
          Gpr(1, 0x20000810u)
          M(0, 0x0e221378efa81fe7UL)
          M(8, 0x864fc5ee6404e96fUL)
          M(16, 0x59be87309e963537UL)
          M(24, 0x62dcec3e9ea4d644UL)
          M(32, 0xec7e2e3c096fb341UL)
          M(40, 0x9bff0fd4297dc0a6UL)
          M(48, 0x75aaa9df2143a29bUL)
          M(56, 0xc5f13c38d6070ddbUL) ]
        [ Gpr(0, 0xbe48ff61u)
          Gpr(1, 0x20000810u)
          M(0, 0x6f29321612335bf2UL)
          M(8, 0xc186dd79666b6b5dUL)
          M(16, 0x8c848a2a76de5a97UL)
          M(24, 0xd4fd9a2119235d88UL)
          M(32, 0x5065f4cad5d0355bUL)
          M(40, 0xd02529b1ffb1c241UL)
          M(48, 0x09992f7f5c1e310aUL)
          M(56, 0xf8e31e87ab096925UL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          M(0, 0xed1d1ee57dbd279dUL)
          M(8, 0xc9846d213a41ba64UL)
          M(16, 0x8c33f28f4790f36eUL)
          M(24, 0xc686bd39bc957846UL)
          M(32, 0x96bf00e41f4f94a5UL)
          M(40, 0x55762c519a6f44a1UL)
          M(48, 0x873c4d499d10b72dUL)
          M(56, 0xb5485ada73066d54UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x00003537u) ]
        [ Gpr(0, 0x00005a97u) ]
        [ Gpr(0, 0x0000f36eu) ] ]
    check false "e1f10f9f" inputs outputs

  /// <summary>
  /// A8.8.80 LDRH: ldrh r0, [r1, #16]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.80 LDRH``() =
    let inputs =
      [ [ Gpr(0, 0xbf9c9227u)
          Gpr(1, 0x20000800u)
          M(0, 0x6f45c34ade7c3dfcUL)
          M(8, 0x68c7303c1a4330a9UL)
          M(16, 0xfe1f52bbcc51f04aUL)
          M(24, 0x13388208ad91a066UL)
          M(32, 0x257c9ee9c05fd720UL)
          M(40, 0xe6b9ce50b1a61470UL)
          M(48, 0xe731074be8c3793cUL)
          M(56, 0x2114da5021b1a3eeUL) ]
        [ Gpr(0, 0xd228a9a1u)
          Gpr(1, 0x20000800u)
          M(0, 0x86ec73d85e2fc15bUL)
          M(8, 0x7629d89e9fbe0dccUL)
          M(16, 0xcccbb18ce743c6ffUL)
          M(24, 0x1ebd517f73d2676fUL)
          M(32, 0x750bb0a033c6e495UL)
          M(40, 0x3302be62c0164731UL)
          M(48, 0x094c9e75b7384de9UL)
          M(56, 0x76eaa254ac5cef7bUL) ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x20000800u)
          M(0, 0x02345517d452bda5UL)
          M(8, 0x3bb56cb123cc198fUL)
          M(16, 0x631429e53103683fUL)
          M(24, 0x49bfd15f982ac691UL)
          M(32, 0xe2a93fddef792cdbUL)
          M(40, 0x3c1c101535fa8aebUL)
          M(48, 0x4643071eae19014eUL)
          M(56, 0x4ecd2f380ae21dbdUL) ] ]
    let outputs =
      [ [ Gpr(0, 0x0000f04au) ]
        [ Gpr(0, 0x0000c6ffu) ]
        [ Gpr(0, 0x0000683fu) ] ]
    check false "e1d101b0" inputs outputs

  /// <summary>
  /// A8.8.84 LDRHT: ldrht r0, [r1], #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.84 LDRHT``() =
    let inputs =
      [ [ Gpr(0, 0x569a327bu)
          Gpr(1, 0x20000810u)
          M(0, 0x9bb11245c0227cd2UL)
          M(8, 0x65e3423a28c3e341UL)
          M(16, 0x5b97015d4b17224dUL)
          M(24, 0x3170c5b768dce70fUL)
          M(32, 0xb1756625089fbdacUL)
          M(40, 0xeccb741318be5520UL)
          M(48, 0xa5097fc31de95b0fUL)
          M(56, 0x5dfd287430d273f3UL) ]
        [ Gpr(0, 0x139054e3u)
          Gpr(1, 0x20000810u)
          M(0, 0x778dcd5ae0ca0b4bUL)
          M(8, 0x888430fbae22e14dUL)
          M(16, 0x0d3d8d6c97e20ad7UL)
          M(24, 0x315134998e13fc8eUL)
          M(32, 0x30388ad657005a24UL)
          M(40, 0x20ef8383c631e87bUL)
          M(48, 0x9a8d8bcb8968df79UL)
          M(56, 0xe2b6f8b5c6208c53UL) ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x20000810u)
          M(0, 0xf33a0d586fe00b63UL)
          M(8, 0x8b1fda7042a32b7aUL)
          M(16, 0xc926a0dc0e7afe71UL)
          M(24, 0x739a669833cc61cdUL)
          M(32, 0x60f6a49f692cd89eUL)
          M(40, 0x1574a6430b62bfc8UL)
          M(48, 0xd1f0c4a4591da64fUL)
          M(56, 0x192c0433ab006eddUL) ] ]
    let outputs =
      [ [ Gpr(0, 0x0000224du); Gpr(1, 0x20000810u) ]
        [ Gpr(0, 0x00000ad7u); Gpr(1, 0x20000810u) ]
        [ Gpr(0, 0x0000fe71u); Gpr(1, 0x20000810u) ] ]
    check false "e0f100b0" inputs outputs

  /// <summary>
  /// A8.8.85 LDRSB: ldrsb r0, [r1, #7]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.85 LDRSB``() =
    let inputs =
      [ [ Gpr(0, 0xc056ea76u)
          Gpr(1, 0x20000809u)
          M(0, 0x6c3e384f7e82e617UL)
          M(8, 0x89528d2cc01e9544UL)
          M(16, 0x6bf3d1be88d36dc4UL)
          M(24, 0x44ce3b61646e6e3cUL)
          M(32, 0x438b52a4d241b5ecUL)
          M(40, 0xc99a8062506cceb5UL)
          M(48, 0x53e6e32da13a6ce3UL)
          M(56, 0xe075d1f9aabafdceUL) ]
        [ Gpr(0, 0xf2b1faa1u)
          Gpr(1, 0x20000809u)
          M(0, 0xc929cd2131c4cbe1UL)
          M(8, 0xd38fc3ff35cc6356UL)
          M(16, 0x1d0057ea83646cc0UL)
          M(24, 0xb0b59d8800786f6fUL)
          M(32, 0x641c521994b39e82UL)
          M(40, 0x82b23b24c804e88dUL)
          M(48, 0xa555f0aa7d3a4bf0UL)
          M(56, 0xc1c20b8eb5b2a73aUL) ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x20000809u)
          M(0, 0xde9630c43abeb143UL)
          M(8, 0xf2ec2235eadbb148UL)
          M(16, 0x0de10dba99c28fe1UL)
          M(24, 0xc0216afa16183631UL)
          M(32, 0x4271cb09ca4f2d3fUL)
          M(40, 0x284279c1af2cc434UL)
          M(48, 0x28542e008ee1f1b8UL)
          M(56, 0xbf9a2ff4df575f37UL) ] ]
    let outputs =
      [ [ Gpr(0, 0xffffffc4u) ]
        [ Gpr(0, 0xffffffc0u) ]
        [ Gpr(0, 0xffffffe1u) ] ]
    check false "e1d100d7" inputs outputs

  /// <summary>
  /// A8.8.88 LDRSBT: ldrsbt r0, [r1], #0x0. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.88 LDRSBT``() =
    let inputs =
      [ [ Gpr(0, 0x21791b37u)
          Gpr(1, 0x20000810u)
          M(0, 0x97e6e0b267adfc3bUL)
          M(8, 0x40357af517e786f4UL)
          M(16, 0x067ccdc517fa9861UL)
          M(24, 0x42c4a0c9815f6868UL)
          M(32, 0x5b83c7364f28d313UL)
          M(40, 0x6b30a308beaa916dUL)
          M(48, 0xb05b7212e727c7c0UL)
          M(56, 0x20c85bb0bc3d8f3bUL) ]
        [ Gpr(0, 0xa6de0565u)
          Gpr(1, 0x20000810u)
          M(0, 0xaac502aa14708f8cUL)
          M(8, 0x3c628e865aebca1cUL)
          M(16, 0x97b414b2ce641ccaUL)
          M(24, 0xd8205218aa89f54aUL)
          M(32, 0x2601aec6b7201fe5UL)
          M(40, 0x29cfb830720a8570UL)
          M(48, 0xebea3f4426e00329UL)
          M(56, 0x18d0179347426f97UL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          M(0, 0x3476575a353364adUL)
          M(8, 0x71e3ac63ed214c7fUL)
          M(16, 0x4bae8c97c3e1f48bUL)
          M(24, 0x9c7cd85182080b63UL)
          M(32, 0xfe60a2a891bbe896UL)
          M(40, 0x0561267058e6bfbaUL)
          M(48, 0x17974e14ee44b736UL)
          M(56, 0x22b935599f77365fUL) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000061u); Gpr(1, 0x20000810u) ]
        [ Gpr(0, 0xffffffcau); Gpr(1, 0x20000810u) ]
        [ Gpr(0, 0xffffff8bu); Gpr(1, 0x20000810u) ] ]
    check false "e0f100d0" inputs outputs

  /// <summary>
  /// A8.8.89 LDRSH: ldrsh r0, [r1, #6]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.89 LDRSH``() =
    let inputs =
      [ [ Gpr(0, 0xb16b483cu)
          Gpr(1, 0x2000080au)
          M(0, 0x72719f501cded2ffUL)
          M(8, 0xee8b0a754406e09eUL)
          M(16, 0x4efba9562174c884UL)
          M(24, 0xcf1bd535af83342dUL)
          M(32, 0x33cf2e5d47f57600UL)
          M(40, 0x10db5e643dba5662UL)
          M(48, 0x1f8a645e307a1290UL)
          M(56, 0xf4a007288a1688adUL) ]
        [ Gpr(0, 0x1fb3c91eu)
          Gpr(1, 0x2000080au)
          M(0, 0x5b1743d665468afaUL)
          M(8, 0xcadd6a5e6533ea08UL)
          M(16, 0x742ebfc86efe9345UL)
          M(24, 0x3f512b95fed3af5aUL)
          M(32, 0x9987dd55155505c4UL)
          M(40, 0xe9c1e1101fac69c8UL)
          M(48, 0x4a77170f76983eb3UL)
          M(56, 0x02fc96b8fc26b394UL) ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x2000080au)
          M(0, 0x2329339ce06b1041UL)
          M(8, 0x9b73ea764f8e6923UL)
          M(16, 0x2d81b18782861de7UL)
          M(24, 0xb9377ede6678d0c8UL)
          M(32, 0x47985e0714ffd7a7UL)
          M(40, 0xb287143925cdb829UL)
          M(48, 0xac01365a5259a05cUL)
          M(56, 0x6c6dc8c76749b757UL) ] ]
    let outputs =
      [ [ Gpr(0, 0xffffc884u) ]
        [ Gpr(0, 0xffff9345u) ]
        [ Gpr(0, 0x00001de7u) ] ]
    check false "e1d100f6" inputs outputs

  /// <summary>
  /// A8.8.92 LDRSHT: ldrsht r0, [r1], #0x0. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.92 LDRSHT``() =
    let inputs =
      [ [ Gpr(0, 0xdf9b2810u)
          Gpr(1, 0x20000810u)
          M(0, 0xae49ef172f0d67acUL)
          M(8, 0xbf54ea3255ae5e12UL)
          M(16, 0x99f291ee1e6a28c2UL)
          M(24, 0xb929c74f35b3774fUL)
          M(32, 0xd711f6d302838b94UL)
          M(40, 0xf6867e1fd5289454UL)
          M(48, 0xbd9dbb83ad9aec5bUL)
          M(56, 0xef528ac443b07b09UL) ]
        [ Gpr(0, 0xa2a5c122u)
          Gpr(1, 0x20000810u)
          M(0, 0x1fe3782f79937bacUL)
          M(8, 0x0a0207782760ab07UL)
          M(16, 0xf01811283f759d81UL)
          M(24, 0x0b74a2b629db1b2eUL)
          M(32, 0x96dc13bae138241bUL)
          M(40, 0xe2baf4c24c0ebc6eUL)
          M(48, 0xce875e9be0fa700aUL)
          M(56, 0x7c4c0eaeed832bf0UL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          M(0, 0x43ba1eed34c2eed2UL)
          M(8, 0x92f4f5d7c4f6f6f8UL)
          M(16, 0x0b718f49ad20c910UL)
          M(24, 0x289c7df50d1414f8UL)
          M(32, 0xef117f0c5e6e8221UL)
          M(40, 0xb4a7f85d78a2651aUL)
          M(48, 0xeb3a5f47b86970afUL)
          M(56, 0xa7d6b159cdfa4c46UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x000028c2u); Gpr(1, 0x20000810u) ]
        [ Gpr(0, 0xffff9d81u); Gpr(1, 0x20000810u) ]
        [ Gpr(0, 0xffffc910u); Gpr(1, 0x20000810u) ] ]
    check false "e0f100f0" inputs outputs

  /// <summary>
  /// A8.8.93 LDRT: ldrt r0, [r1], #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.93 LDRT``() =
    let inputs =
      [ [ Gpr(0, 0x6cb2eb70u)
          Gpr(1, 0x20000810u)
          M(0, 0x91ec17dbbd487959UL)
          M(8, 0x7a9981c9fc36fe68UL)
          M(16, 0x718f6265837fb45dUL)
          M(24, 0x0795f46c47771214UL)
          M(32, 0x69da38b53a0a72b9UL)
          M(40, 0x0d926178c0c4f5c5UL)
          M(48, 0xea1504481c2874e5UL)
          M(56, 0x0dfc288c835698bfUL) ]
        [ Gpr(0, 0xc4c28f98u)
          Gpr(1, 0x20000810u)
          M(0, 0x26d40126f3a17251UL)
          M(8, 0xab0aa646fadb1efbUL)
          M(16, 0x5b4c03c3c3a61a0fUL)
          M(24, 0xafaaec3f28d0ca73UL)
          M(32, 0xe89af24157eb37c3UL)
          M(40, 0x2ced84f80cb93fc8UL)
          M(48, 0xf1bba0724b8ee208UL)
          M(56, 0xf0f4a9ed718fe7e3UL) ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x20000810u)
          M(0, 0xa0fcd111e85cf69dUL)
          M(8, 0x206ffcd1d6e15be2UL)
          M(16, 0xb9e3b4ca08c77b68UL)
          M(24, 0x955b393e7d223ccdUL)
          M(32, 0x44461d87ec744b91UL)
          M(40, 0x858a3114f1e0b480UL)
          M(48, 0x11ffc6f20ac97ac8UL)
          M(56, 0xab217bd0fb01dfc5UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x837fb45du); Gpr(1, 0x20000810u) ]
        [ Gpr(0, 0xc3a61a0fu); Gpr(1, 0x20000810u) ]
        [ Gpr(0, 0x08c77b68u); Gpr(1, 0x20000810u) ] ]
    check false "e4b10000" inputs outputs

  /// <summary>
  /// A8.8.94 LEAVEX: .inst 0xf3bf8f0f. This checks that it takes the Undefined
  /// Instruction exception. It is not a value test because it belongs to
  /// ThumbEE, which no QEMU model implements.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.94 LEAVEX``() =
    let run = runWith true "f3bf8f0f" [ Cell.CPSR 0x10u ] []
    Assert.AreEqual(Some SideEffect.UndefinedInstruction, run.Effect)

  /// <summary>
  /// A8.8.95 LSL: lsl r0, r0, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.95 LSL``() =
    let inputs =
      [ [ Gpr(0, 0xb6b64876u); Gpr(2, 0xdbcf9404u) ]
        [ Gpr(0, 0xf1800aa7u); Gpr(2, 0xa6861ff0u) ]
        [ Gpr(0, 0x00000001u); Gpr(2, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x6b648760u) ]
        [ Gpr(0, 0x00000000u) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e1a00210" inputs outputs

  /// <summary>
  /// A8.8.97 LSR: lsr r0, r0, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.97 LSR``() =
    let inputs =
      [ [ Gpr(0, 0x0e1478a8u); Gpr(2, 0x6c56ce6au) ]
        [ Gpr(0, 0xf49bc22bu); Gpr(2, 0x8c85c5bdu) ]
        [ Gpr(0, 0x00000001u); Gpr(2, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000000u) ]
        [ Gpr(0, 0x00000000u) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e1a00230" inputs outputs

  /// <summary>
  /// A8.8.99 MCR: mcr p15, #0x0, r0, c1, c0, #0x0. This checks that User mode
  /// refuses it and that Supervisor mode writes Rt to SCTLR. It is not a value
  /// test because it reaches a coprocessor, which a user-mode run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.99 MCR``() =
    let cells = [ Gpr(0, 0x00c5187du); Cell.CPSR 0x13u ]
    let run = runWith false "ee010f10" cells []
    let refused = ManualLifting.refusedModes false "ee010f10" [] []
    CollectionAssert.AreEqual([| 0x10u |], refused)
    Assert.AreEqual(0x00c5187du, run.Reg Register.SCTLR)

  /// <summary>
  /// A8.8.99 MCR2: mcr2 7, 1, r0, cr1, cr2, {4}. This checks that the lift says
  /// the instruction is unsupported: coprocessor 7 is none this front end
  /// models. It is not a value test because it reaches a coprocessor, which a
  /// user-mode run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.99 MCR2``() =
    let run = runWith false "fe210792" [ Cell.CPSR 0x13u ] []
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.100 MCRR: mcrr 7, 1, r0, r1, cr2. This checks that the lift says the
  /// instruction is unsupported: coprocessor 7 is none this front end models.
  /// It is not a value test because it reaches a coprocessor, which a user-mode
  /// run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.100 MCRR``() =
    let run = runWith false "ec410712" [ Cell.CPSR 0x13u ] []
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.100 MCRR2: mcrr2 7, 1, r0, r1, cr2. This checks that the lift says
  /// the instruction is unsupported: coprocessor 7 is none this front end
  /// models. It is not a value test because it reaches a coprocessor, which a
  /// user-mode run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.100 MCRR2``() =
    let run = runWith false "fc410712" [ Cell.CPSR 0x13u ] []
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.101 MLA: mla r0, r1, r2, r3. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.101 MLA``() =
    let inputs =
      [ [ Gpr(0, 0x8fd94f76u)
          Gpr(1, 0x90733e54u)
          Gpr(2, 0x70cfced5u)
          Gpr(3, 0xb118c1b4u) ]
        [ Gpr(0, 0x8ae29ec9u)
          Gpr(1, 0x7b522254u)
          Gpr(2, 0xa7beace8u)
          Gpr(3, 0xa80fdc3cu) ]
        [ Gpr(0, 0x00000001u)
          Gpr(1, 0x0000ffffu)
          Gpr(2, 0x00008000u)
          Gpr(3, 0x7fff8000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xc30f3598u) ]
        [ Gpr(0, 0xdfe7685cu) ]
        [ Gpr(0, 0xffff0000u) ] ]
    check false "e0203291" inputs outputs

  /// <summary>
  /// A8.8.102 MLS: mls r0, r1, r2, r3. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.102 MLS``() =
    let inputs =
      [ [ Gpr(0, 0x74663e7cu)
          Gpr(1, 0xa2023a81u)
          Gpr(2, 0xd721b901u)
          Gpr(3, 0x91937feeu) ]
        [ Gpr(0, 0x566bf270u)
          Gpr(1, 0x96c6816eu)
          Gpr(2, 0xfcd6a92du)
          Gpr(3, 0x2244405eu) ]
        [ Gpr(0, 0x00000001u)
          Gpr(1, 0x0000ffffu)
          Gpr(2, 0x00008000u)
          Gpr(3, 0x7fff8000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x71a90c6du) ]
        [ Gpr(0, 0x1bf9e208u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e0603291" inputs outputs

  /// <summary>
  /// A8.8.103 MOV: mov r0, #0x3. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.103 MOV``() =
    let inputs =
      [ [ Gpr(0, 0x7f469402u) ]
        [ Gpr(0, 0xa97e757eu) ]
        [ Gpr(0, 0x00000001u) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000003u) ]
        [ Gpr(0, 0x00000003u) ]
        [ Gpr(0, 0x00000003u) ] ]
    check false "e3a00003" inputs outputs

  /// <summary>
  /// A8.8.107 MOVT: movt r0, #0x7. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.107 MOVT``() =
    let inputs =
      [ [ Gpr(0, 0x8871760du) ]
        [ Gpr(0, 0x2bd0ad71u) ]
        [ Gpr(0, 0x0000ffffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x0007760du) ]
        [ Gpr(0, 0x0007ad71u) ]
        [ Gpr(0, 0x0007ffffu) ] ]
    check false "e3400007" inputs outputs

  /// <summary>
  /// A8.8.108 MRC: mrc p15, #0x0, r0, c1, c0, #0x0. This checks that User mode
  /// refuses it and that Supervisor mode reads SCTLR into Rt. It is not a value
  /// test because it reaches a coprocessor, which a user-mode run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.108 MRC``() =
    let sctlr = [ Register.SCTLR, 0x00c5187du ]
    let run = runWith false "ee110f10" [ Cell.CPSR 0x13u ] sctlr
    let refused = ManualLifting.refusedModes false "ee110f10" [] sctlr
    CollectionAssert.AreEqual([| 0x10u |], refused)
    Assert.AreEqual(Gpr(0, 0x00c5187du), run.After(Gpr(0, 0u)))

  /// <summary>
  /// A8.8.108 MRC2: mrc2 7, 1, r0, cr1, cr2, {4}. This checks that the lift
  /// says the instruction is unsupported: coprocessor 7 is none this front end
  /// models. It is not a value test because it reaches a coprocessor, which a
  /// user-mode run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.108 MRC2``() =
    let run = runWith false "fe310792" [ Cell.CPSR 0x13u ] []
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.109 MRRC: mrrc 7, 1, r0, r1, cr2. This checks that the lift says the
  /// instruction is unsupported: coprocessor 7 is none this front end models.
  /// It is not a value test because it reaches a coprocessor, which a user-mode
  /// run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.109 MRRC``() =
    let run = runWith false "ec510712" [ Cell.CPSR 0x13u ] []
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.109 MRRC2: mrrc2 7, 1, r0, r1, cr2. This checks that the lift says
  /// the instruction is unsupported: coprocessor 7 is none this front end
  /// models. It is not a value test because it reaches a coprocessor, which a
  /// user-mode run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.109 MRRC2``() =
    let run = runWith false "fc510712" [ Cell.CPSR 0x13u ] []
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.110 MRS: mrs r0, CPSR. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.110 MRS``() =
    let inputs =
      [ [ Gpr(0, 0xbc54ed89u); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xfc686becu); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000001u); Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x20000010u) ]
        [ Gpr(0, 0x900a0010u) ]
        [ Gpr(0, 0x48050010u) ] ]
    check false "e10f0000" inputs outputs

  /// <summary>
  /// A8.8.112 MSR: msr CPSR_fs, r1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.112 MSR``() =
    let inputs =
      [ [ Gpr(1, 0x7f398e31u); Cell.CPSR 0x20000010u ]
        [ Gpr(1, 0x5023c4f0u); Cell.CPSR 0x900a0010u ]
        [ Gpr(1, 0x0000ffffu); Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Cell.CPSR 0x78090010u ]
        [ Cell.CPSR 0x50030010u ]
        [ Cell.CPSR 0x00000010u ] ]
    check false "e12cf001" inputs outputs

  /// <summary>
  /// A8.8.115 MUL: mul r0, r1, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.115 MUL``() =
    let inputs =
      [ [ Gpr(0, 0xdd744c85u); Gpr(1, 0x01daa50fu); Gpr(2, 0xac890f40u) ]
        [ Gpr(0, 0x59dfda8du); Gpr(1, 0xc5758aa0u); Gpr(2, 0x4ab943bdu) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu); Gpr(2, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xaf5c24c0u) ]
        [ Gpr(0, 0xf8af3820u) ]
        [ Gpr(0, 0x7fff8000u) ] ]
    check false "e0000291" inputs outputs

  /// <summary>
  /// A8.8.116 MVN: mvn r0, #0x3fc. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.116 MVN``() =
    let inputs =
      [ [ Gpr(0, 0xd3fc2658u) ]
        [ Gpr(0, 0xd8849ca5u) ]
        [ Gpr(0, 0x00000001u) ] ]
    let outputs =
      [ [ Gpr(0, 0xfffffc03u) ]
        [ Gpr(0, 0xfffffc03u) ]
        [ Gpr(0, 0xfffffc03u) ] ]
    check false "e3e00fff" inputs outputs

  /// <summary>
  /// A8.8.119 NEG: rsb r0, r1, #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.119 NEG``() =
    let inputs =
      [ [ Gpr(0, 0x606650d9u); Gpr(1, 0x9eed76e8u) ]
        [ Gpr(0, 0xc129b95eu); Gpr(1, 0xedc4897bu) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x61128918u) ]
        [ Gpr(0, 0x123b7685u) ]
        [ Gpr(0, 0xffff0001u) ] ]
    check false "e2610000" inputs outputs

  /// <summary>
  /// A8.8.120 NOP: nop {0}. It lifts to no statements: what it does is a hint
  /// or an ordering of memory accesses that one run cannot observe, and QEMU's
  /// runs of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.120 NOP``() =
    Assert.AreEqual(0, (lift false "e320f000").Length)

  /// <summary>
  /// A8.8.121 ORN: orn r0, r1, #0x1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.121 ORN``() =
    let inputs =
      [ [ Gpr(0, 0x7f6f1011u); Gpr(1, 0xc7baf5a6u) ]
        [ Gpr(0, 0x6b938619u); Gpr(1, 0x753d35aeu) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu) ] ]
    let outputs =
      [ [ Gpr(0, 0xfffffffeu) ]
        [ Gpr(0, 0xfffffffeu) ]
        [ Gpr(0, 0xffffffffu) ] ]
    check true "f0610001" inputs outputs

  /// <summary>
  /// A8.8.123 ORR: orr r0, r0, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.123 ORR``() =
    let inputs =
      [ [ Gpr(0, 0xfba8736fu); Gpr(2, 0x5e059d95u) ]
        [ Gpr(0, 0xbe74fc54u); Gpr(2, 0x48dce66eu) ]
        [ Gpr(0, 0x00000001u); Gpr(2, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xffadffffu) ]
        [ Gpr(0, 0xfefcfe7eu) ]
        [ Gpr(0, 0x00008001u) ] ]
    check false "e1800002" inputs outputs

  /// <summary>
  /// A8.8.126 PKH: pkhbt r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.126 PKH``() =
    let inputs =
      [ [ Gpr(0, 0x2fdd0430u); Gpr(1, 0x23ff1b3au); Gpr(2, 0x95f20b0au) ]
        [ Gpr(0, 0x62e2cf6du); Gpr(1, 0xea167f72u); Gpr(2, 0x56e1a4b2u) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu); Gpr(2, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x95f21b3au) ]
        [ Gpr(0, 0x56e17f72u) ]
        [ Gpr(0, 0x0000ffffu) ] ]
    check false "e6810012" inputs outputs

  /// <summary>
  /// A8.8.127 PLD: pld [r1, #7]. It lifts to no statements: what it does is a
  /// hint or an ordering of memory accesses that one run cannot observe, and
  /// QEMU's runs of it changed no register and no byte, so a value test would
  /// assert nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.127 PLD``() =
    Assert.AreEqual(0, (lift false "f5d1f007").Length)

  /// <summary>
  /// A8.8.127 PLDW: pldw [r1]. It lifts to no statements: what it does is a
  /// hint or an ordering of memory accesses that one run cannot observe, and
  /// QEMU's runs of it changed no register and no byte, so a value test would
  /// assert nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.127 PLDW``() =
    Assert.AreEqual(0, (lift false "f591f000").Length)

  /// <summary>
  /// A8.8.130 PLI: pli [r1, #7]. It lifts to no statements: what it does is a
  /// hint or an ordering of memory accesses that one run cannot observe, and
  /// QEMU's runs of it changed no register and no byte, so a value test would
  /// assert nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.130 PLI``() =
    Assert.AreEqual(0, (lift false "f4d1f007").Length)

  /// <summary>
  /// A8.8.132 POP: pop {r2, r3}. This checks that it loads R2 then R3 from SP
  /// and moves SP up by eight. It is not a value test because it moves SP,
  /// which the run itself stands on.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.132 POP``() =
    let w = uint32 Window
    let cells = [ M(16, 0x3333333322222222UL) ]
    let run = runWith false "e8bd000c" cells [ Register.SP, w + 16u ]
    Assert.AreEqual(Gpr(2, 0x22222222u), run.After(Gpr(2, 0u)))
    Assert.AreEqual(Gpr(3, 0x33333333u), run.After(Gpr(3, 0u)))
    Assert.AreEqual(w + 24u, run.Reg Register.SP)

  /// <summary>
  /// A8.8.134 PUSH: push {r2, r3}. This checks that it stores R2 then R3 below
  /// SP and moves SP down by eight. It is not a value test because it moves SP,
  /// which the run itself stands on.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.134 PUSH``() =
    let w = uint32 Window
    let cells = [ Gpr(2, 0x22222222u); Gpr(3, 0x33333333u); M(24, 0UL) ]
    let run = runWith false "e92d000c" cells [ Register.SP, w + 32u ]
    Assert.AreEqual(M(24, 0x3333333322222222UL), run.After(M(24, 0UL)))
    Assert.AreEqual(w + 24u, run.Reg Register.SP)

  /// <summary>
  /// A8.8.135 QADD: qadd r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.135 QADD``() =
    let inputs =
      [ [ Gpr(0, 0x95e3e24bu)
          Gpr(1, 0xe4ede70du)
          Gpr(2, 0x7db134deu)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x634ad02du)
          Gpr(1, 0x413a0e10u)
          Gpr(2, 0xdab58cbbu)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x629f1bebu); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x1bef9acbu); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fffffffu); Cell.CPSR 0x48050010u ] ]
    check false "e1020051" inputs outputs

  /// <summary>
  /// A8.8.136 QADD16: qadd16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.136 QADD16``() =
    let inputs =
      [ [ Gpr(0, 0x738cc871u); Gpr(1, 0xbea259a9u); Gpr(2, 0x95ee682au) ]
        [ Gpr(0, 0x1e30cb0bu); Gpr(1, 0x55fb2443u); Gpr(2, 0x5c39f1c0u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x80007fffu) ]
        [ Gpr(0, 0x7fff1603u) ]
        [ Gpr(0, 0x80007fffu) ] ]
    check false "e6210f12" inputs outputs

  /// <summary>
  /// A8.8.137 QADD8: qadd8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.137 QADD8``() =
    let inputs =
      [ [ Gpr(0, 0x6b3f9d24u); Gpr(1, 0xee69105bu); Gpr(2, 0x40522619u) ]
        [ Gpr(0, 0xdacacb05u); Gpr(1, 0x1eded8eeu); Gpr(2, 0xe8dfbca8u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x2e7f3674u) ]
        [ Gpr(0, 0x06bd9496u) ]
        [ Gpr(0, 0x7fff8000u) ] ]
    check false "e6210f92" inputs outputs

  /// <summary>
  /// A8.8.138 QASX: qasx r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.138 QASX``() =
    let inputs =
      [ [ Gpr(0, 0x32874adfu); Gpr(1, 0xee9dcaa7u); Gpr(2, 0xf3ae3443u) ]
        [ Gpr(0, 0x8821a092u); Gpr(1, 0x770c7135u); Gpr(2, 0xd6b6210cu) ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u); Gpr(2, 0x7fff8000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x22e0d6f9u) ]
        [ Gpr(0, 0x7fff7fffu) ]
        [ Gpr(0, 0x80008000u) ] ]
    check false "e6210f32" inputs outputs

  /// <summary>
  /// A8.8.139 QDADD: qdadd r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.139 QDADD``() =
    let inputs =
      [ [ Gpr(0, 0x68ff03f5u)
          Gpr(1, 0xd1da6683u)
          Gpr(2, 0x66e98107u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x62f18a4au)
          Gpr(1, 0x65243a93u)
          Gpr(2, 0xf26e6de3u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x7fff8000u)
          Gpr(2, 0x00000000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x51da6682u); Cell.CPSR 0x28000010u ]
        [ Gpr(0, 0x4a011659u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u); Cell.CPSR 0x48050010u ] ]
    check false "e1420051" inputs outputs

  /// <summary>
  /// A8.8.140 QDSUB: qdsub r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.140 QDSUB``() =
    let inputs =
      [ [ Gpr(0, 0x8096d00eu)
          Gpr(1, 0x121622cfu)
          Gpr(2, 0xac5a31ffu)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x413b8117u)
          Gpr(1, 0x16d4400cu)
          Gpr(2, 0x658004f3u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x7fff8000u)
          Gpr(2, 0x00000000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x7fffffffu); Cell.CPSR 0x28000010u ]
        [ Gpr(0, 0x96d4400du); Cell.CPSR 0x980a0010u ]
        [ Gpr(0, 0x7fff8000u); Cell.CPSR 0x48050010u ] ]
    check false "e1620051" inputs outputs

  /// <summary>
  /// A8.8.141 QSAX: qsax r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.141 QSAX``() =
    let inputs =
      [ [ Gpr(0, 0x24d437c1u); Gpr(1, 0x1eebe6b0u); Gpr(2, 0x61e06aedu) ]
        [ Gpr(0, 0x112434afu); Gpr(1, 0x81593ee7u); Gpr(2, 0x5549ad48u) ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u); Gpr(2, 0x7fff8000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xb3fe4890u) ]
        [ Gpr(0, 0xd4117fffu) ]
        [ Gpr(0, 0x7fffffffu) ] ]
    check false "e6210f52" inputs outputs

  /// <summary>
  /// A8.8.142 QSUB: qsub r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.142 QSUB``() =
    let inputs =
      [ [ Gpr(0, 0x51534be8u)
          Gpr(1, 0x923d850fu)
          Gpr(2, 0xbf7d6334u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x73d852cau)
          Gpr(1, 0xeaf5ef3cu)
          Gpr(2, 0x62acccbau)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xd2c021dbu); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x88492282u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x80010000u); Cell.CPSR 0x48050010u ] ]
    check false "e1220051" inputs outputs

  /// <summary>
  /// A8.8.143 QSUB16: qsub16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.143 QSUB16``() =
    let inputs =
      [ [ Gpr(0, 0xa5785c29u); Gpr(1, 0xe156bb86u); Gpr(2, 0x2489fc2du) ]
        [ Gpr(0, 0x804b2b20u); Gpr(1, 0xe84ba678u); Gpr(2, 0x1d82fef9u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0xbccdbf59u) ]
        [ Gpr(0, 0xcac9a77fu) ]
        [ Gpr(0, 0x7fff8001u) ] ]
    check false "e6210f72" inputs outputs

  /// <summary>
  /// A8.8.144 QSUB8: qsub8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.144 QSUB8``() =
    let inputs =
      [ [ Gpr(0, 0x1d6433c7u); Gpr(1, 0x8f27a4d7u); Gpr(2, 0x3e9595a2u) ]
        [ Gpr(0, 0x76302c9au); Gpr(1, 0x8857fb1eu); Gpr(2, 0xdb2d599eu) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x807f0f35u) ]
        [ Gpr(0, 0xad2aa27fu) ]
        [ Gpr(0, 0x7fff8000u) ] ]
    check false "e6210ff2" inputs outputs

  /// <summary>
  /// A8.8.145 RBIT: rbit r0, r1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.145 RBIT``() =
    let inputs =
      [ [ Gpr(0, 0xb4078668u); Gpr(1, 0xb5fb8056u) ]
        [ Gpr(0, 0xab4ca879u); Gpr(1, 0xf0b38fa3u) ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x6a01dfadu) ]
        [ Gpr(0, 0xc5f1cd0fu) ]
        [ Gpr(0, 0x00010000u) ] ]
    check false "e6ff0f31" inputs outputs

  /// <summary>
  /// A8.8.146 REV: rev r0, r1. The outputs are what QEMU left after running it
  /// on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.146 REV``() =
    let inputs =
      [ [ Gpr(0, 0x1a284233u); Gpr(1, 0x05b26339u) ]
        [ Gpr(0, 0x535b0313u); Gpr(1, 0xe04de60cu) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x3963b205u) ]
        [ Gpr(0, 0x0ce64de0u) ]
        [ Gpr(0, 0xffff0000u) ] ]
    check false "e6bf0f31" inputs outputs

  /// <summary>
  /// A8.8.147 REV16: rev16 r0, r1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.147 REV16``() =
    let inputs =
      [ [ Gpr(0, 0x606ec9dcu); Gpr(1, 0x86db9f95u) ]
        [ Gpr(0, 0xefcf8eb7u); Gpr(1, 0x636fe20fu) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xdb86959fu) ]
        [ Gpr(0, 0x6f630fe2u) ]
        [ Gpr(0, 0xff7f0080u) ] ]
    check false "e6bf0fb1" inputs outputs

  /// <summary>
  /// A8.8.148 REVSH: revsh r0, r1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.148 REVSH``() =
    let inputs =
      [ [ Gpr(0, 0xb5b79a81u); Gpr(1, 0xb331f549u) ]
        [ Gpr(0, 0x1324fba3u); Gpr(1, 0xbdff79beu) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x000049f5u) ]
        [ Gpr(0, 0xffffbe79u) ]
        [ Gpr(0, 0x00000080u) ] ]
    check false "e6ff0fb1" inputs outputs

  /// <summary>
  /// A8.8.149 RFE: rfeia r1. This checks, in Supervisor mode with Rn pointing
  /// at a return address of 0x30003000 and a saved CPSR of 0x20000010, that it
  /// returns there with that CPSR and leaves Rn, and that User and Hyp mode
  /// refuse it. It is not a value test because it needs a privileged mode,
  /// which a user-mode run does not have.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.149 RFE``() =
    let w = uint32 Window
    let cells = [ Gpr(1, w + 16u); M(16, 0x2000001030003000UL) ]
    let run = runWith false "f8910a00" (Cell.CPSR 0x13u :: cells) []
    let refused = ManualLifting.refusedModes false "f8910a00" cells []
    CollectionAssert.AreEqual([| 0x10u; 0x1au |], refused)
    Assert.AreEqual(Some 0x30003000UL, run.Target)
    Assert.AreEqual(Cell.CPSR 0x20000010u, run.After(Cell.CPSR 0u))
    Assert.AreEqual(Gpr(1, w + 16u), run.After(Gpr(1, 0u)))

  /// <summary>
  /// A8.8.150 ROR: ror r0, r0, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.150 ROR``() =
    let inputs =
      [ [ Gpr(0, 0x61c3ad38u); Gpr(2, 0x5ce0c57cu) ]
        [ Gpr(0, 0x4250725fu); Gpr(2, 0xfb5f0424u) ]
        [ Gpr(0, 0x00000001u); Gpr(2, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x1c3ad386u) ]
        [ Gpr(0, 0xf4250725u) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e1a00270" inputs outputs

  /// <summary>
  /// A8.8.152 RRX: rrx r0, r2. The outputs are what QEMU left after running it
  /// on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.152 RRX``() =
    let inputs =
      [ [ Gpr(0, 0xf7e27f49u); Gpr(2, 0x0feae58eu); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xb34a13cbu); Gpr(2, 0xc98d547du); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000001u); Gpr(2, 0x00008000u); Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x87f572c7u) ]
        [ Gpr(0, 0x64c6aa3eu) ]
        [ Gpr(0, 0x00004000u) ] ]
    check false "e1a00062" inputs outputs

  /// <summary>
  /// A8.8.153 RSB: rsb r0, r1, #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.153 RSB``() =
    let inputs =
      [ [ Gpr(0, 0x7cda3cb2u); Gpr(1, 0xa8ad7298u) ]
        [ Gpr(0, 0x4015a117u); Gpr(1, 0x5e597e75u) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x57528d68u) ]
        [ Gpr(0, 0xa1a6818bu) ]
        [ Gpr(0, 0xffff0001u) ] ]
    check false "e2610000" inputs outputs

  /// <summary>
  /// A8.8.156 RSC: rsc r0, r1, #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.156 RSC``() =
    let inputs =
      [ [ Gpr(0, 0xb65d6c93u); Gpr(1, 0xe665d0b7u); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xc175b69du); Gpr(1, 0x4315ed7au); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu); Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x199a2f49u) ]
        [ Gpr(0, 0xbcea1285u) ]
        [ Gpr(0, 0xffff0000u) ] ]
    check false "e2e10000" inputs outputs

  /// <summary>
  /// A8.8.159 SADD16: sadd16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.159 SADD16``() =
    let inputs =
      [ [ Gpr(0, 0x41ed877bu)
          Gpr(1, 0xfd9f6f38u)
          Gpr(2, 0xbbb7fb23u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xaa869e8du)
          Gpr(1, 0x1db9f2e5u)
          Gpr(2, 0x13c3777eu)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xb9566a5bu); Cell.CPSR 0x20030010u ]
        [ Gpr(0, 0x317c6a63u); Cell.CPSR 0x900f0010u ]
        [ Gpr(0, 0x80007fffu); Cell.CPSR 0x48030010u ] ]
    check false "e6110f12" inputs outputs

  /// <summary>
  /// A8.8.160 SADD8: sadd8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.160 SADD8``() =
    let inputs =
      [ [ Gpr(0, 0x5825e689u)
          Gpr(1, 0xe9e737f1u)
          Gpr(2, 0xa2f2b72cu)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xf73b7188u)
          Gpr(1, 0x7683e0c6u)
          Gpr(2, 0x782c6a95u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x7fff8000u)
          Gpr(2, 0x00000000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x8bd9ee1du); Cell.CPSR 0x20010010u ]
        [ Gpr(0, 0xeeaf4a5bu); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u); Cell.CPSR 0x48090010u ] ]
    check false "e6110f92" inputs outputs

  /// <summary>
  /// A8.8.161 SASX: sasx r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.161 SASX``() =
    let inputs =
      [ [ Gpr(0, 0xaf045024u)
          Gpr(1, 0xbcbc46bdu)
          Gpr(2, 0xfd43f0ecu)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x6e2015d6u)
          Gpr(1, 0x7611b8c6u)
          Gpr(2, 0x8855ced6u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xada8497au); Cell.CPSR 0x20030010u ]
        [ Gpr(0, 0x44e73071u); Cell.CPSR 0x900f0010u ]
        [ Gpr(0, 0x80000001u); Cell.CPSR 0x48000010u ] ]
    check false "e6110f32" inputs outputs

  /// <summary>
  /// A8.8.162 SBC: sbc r0, r1, #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.162 SBC``() =
    let inputs =
      [ [ Gpr(0, 0x2fbe1e65u); Gpr(1, 0xfd33ad5eu); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xee17e647u); Gpr(1, 0x38e43f81u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu); Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xfd33ad5eu) ]
        [ Gpr(0, 0x38e43f80u) ]
        [ Gpr(0, 0x0000fffeu) ] ]
    check false "e2c10000" inputs outputs

  /// <summary>
  /// A8.8.165 SBFX: sbfx r0, r1, #0x3, #0x5. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.165 SBFX``() =
    let inputs =
      [ [ Gpr(0, 0x446600e8u); Gpr(1, 0x0dd6491du) ]
        [ Gpr(0, 0x3486b9ffu); Gpr(1, 0xfc82b7f7u) ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000003u) ]
        [ Gpr(0, 0xfffffffeu) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e7a401d1" inputs outputs

  /// <summary>
  /// A8.8.166 SDIV: sdiv r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.166 SDIV``() =
    let inputs =
      [ [ Gpr(0, 0xbf1746c3u); Gpr(1, 0xb35859beu); Gpr(2, 0xb3a1fb4bu) ]
        [ Gpr(0, 0x79f03877u); Gpr(1, 0xb2845ac3u); Gpr(2, 0x258ac730u) ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u); Gpr(2, 0x7fff8000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0xfffffffeu) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e710f211" inputs outputs

  /// <summary>
  /// A8.8.167 SEL: sel r0, r1, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.167 SEL``() =
    let inputs =
      [ [ Gpr(0, 0xf739cd68u)
          Gpr(1, 0x5092acf3u)
          Gpr(2, 0xfef48850u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xbe5a627cu)
          Gpr(1, 0xbad07c2du)
          Gpr(2, 0xec84a171u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000001u)
          Gpr(1, 0x0000ffffu)
          Gpr(2, 0x00008000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xfef48850u) ]
        [ Gpr(0, 0xba847c71u) ]
        [ Gpr(0, 0x000080ffu) ] ]
    check false "e6810fb2" inputs outputs

  /// <summary>
  /// A8.8.168 SETEND: setend be. This checks that it sets E, CPSR bit 9, and
  /// goes on to the next instruction by a jump, so that what follows is lifted
  /// again. It is not a value test because it changes the byte order of every
  /// access after it, the run's own included.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.168 SETEND``() =
    let run = runWith false "f1010200" [ Cell.CPSR 0x10u ] []
    Assert.AreEqual(Cell.CPSR 0x210u, run.After(Cell.CPSR 0u))
    Assert.AreEqual(Some(CodeAddr + 4UL), run.Target)

  /// <summary>
  /// A8.8.169 SEV: sev. It lifts to no statements: what it does is a hint or an
  /// ordering of memory accesses that one run cannot observe, and QEMU's runs
  /// of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.169 SEV``() =
    Assert.AreEqual(0, (lift false "e320f004").Length)

  /// <summary>
  /// A8.8.170 SHADD16: shadd16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.170 SHADD16``() =
    let inputs =
      [ [ Gpr(0, 0x47419e4eu); Gpr(1, 0x2d149c95u); Gpr(2, 0xc2a883d6u) ]
        [ Gpr(0, 0xffe59b75u); Gpr(1, 0x893245beu); Gpr(2, 0xeb1d2abcu) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x80007fffu); Gpr(2, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0xf7de9035u) ]
        [ Gpr(0, 0xba27383du) ]
        [ Gpr(0, 0xc0004001u) ] ]
    check false "e6310f12" inputs outputs

  /// <summary>
  /// A8.8.171 SHADD8: shadd8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.171 SHADD8``() =
    let inputs =
      [ [ Gpr(0, 0xbd09fe41u); Gpr(1, 0xc93c0ffeu); Gpr(2, 0x060064c1u) ]
        [ Gpr(0, 0xeab044e6u); Gpr(1, 0x1d536558u); Gpr(2, 0x6d36aa94u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0xe71e39dfu) ]
        [ Gpr(0, 0x454407f6u) ]
        [ Gpr(0, 0xc0003fffu) ] ]
    check false "e6310f92" inputs outputs

  /// <summary>
  /// A8.8.172 SHASX: shasx r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.172 SHASX``() =
    let inputs =
      [ [ Gpr(0, 0x1aabd766u); Gpr(1, 0xb01c465au); Gpr(2, 0x153632e2u) ]
        [ Gpr(0, 0xea5a08f8u); Gpr(1, 0xdc5691e5u); Gpr(2, 0xcda161cdu) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xf17f1892u) ]
        [ Gpr(0, 0x1f11e222u) ]
        [ Gpr(0, 0x3fffc000u) ] ]
    check false "e6310f32" inputs outputs

  /// <summary>
  /// A8.8.173 SHSAX: shsax r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.173 SHSAX``() =
    let inputs =
      [ [ Gpr(0, 0x5747f428u); Gpr(1, 0xc183c385u); Gpr(2, 0xa70bab64u) ]
        [ Gpr(0, 0x5a55ce37u); Gpr(1, 0x655447beu); Gpr(2, 0x2b1d711eu) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x0b0fb548u) ]
        [ Gpr(0, 0xfa1b396du) ]
        [ Gpr(0, 0x3fffc000u) ] ]
    check false "e6310f52" inputs outputs

  /// <summary>
  /// A8.8.174 SHSUB16: shsub16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.174 SHSUB16``() =
    let inputs =
      [ [ Gpr(0, 0x264626fdu); Gpr(1, 0x489d7220u); Gpr(2, 0xf2ff8ce1u) ]
        [ Gpr(0, 0xada90877u); Gpr(1, 0xcc378f63u); Gpr(2, 0x2ad43612u) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x80007fffu); Gpr(2, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0x2acf729fu) ]
        [ Gpr(0, 0xd0b1aca8u) ]
        [ Gpr(0, 0xc0003ffeu) ] ]
    check false "e6310f72" inputs outputs

  /// <summary>
  /// A8.8.175 SHSUB8: shsub8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.175 SHSUB8``() =
    let inputs =
      [ [ Gpr(0, 0x269c11e4u); Gpr(1, 0x1749554du); Gpr(2, 0x2b8f2aa5u) ]
        [ Gpr(0, 0x4e8880f0u); Gpr(1, 0x3761f65eu); Gpr(2, 0x10b62441u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0xf65d1554u) ]
        [ Gpr(0, 0x1355e90eu) ]
        [ Gpr(0, 0x4000c000u) ] ]
    check false "e6310ff2" inputs outputs

  /// <summary>
  /// A8.8.176 SMC: smc 1. This checks that User mode refuses it and that every
  /// other mode reaches a call the lift does not model. It is not a value test
  /// because it takes an exception, which a user-mode run cannot return from.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.176 SMC``() =
    let run = runWith false "e1600071" [ Cell.CPSR 0x13u ] []
    let refused = ManualLifting.refusedModes false "e1600071" [] []
    CollectionAssert.AreEqual([| 0x10u |], refused)
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.177 SMLABB: smlabb r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.177 SMLABB``() =
    let inputs =
      [ [ Gpr(0, 0xb42b3feau)
          Gpr(1, 0x1d294439u)
          Gpr(2, 0x40ba6fedu)
          Gpr(3, 0x8f2c9f26u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x98e4d05eu)
          Gpr(1, 0xcc3e059du)
          Gpr(2, 0x51d79b3cu)
          Gpr(3, 0xf6f84595u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xad007eebu); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xf4c2a561u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000003u); Cell.CPSR 0x48050010u ] ]
    check false "e1003281" inputs outputs

  /// <summary>
  /// A8.8.177 SMLABT: smlabt r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.177 SMLABT``() =
    let inputs =
      [ [ Gpr(0, 0x34c26e19u)
          Gpr(1, 0x3e14b576u)
          Gpr(2, 0xe1ac481du)
          Gpr(3, 0x100e3090u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xeb2356e0u)
          Gpr(1, 0x6d22209fu)
          Gpr(2, 0x7e1bbf23u)
          Gpr(3, 0xb20c5b9bu)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x18e2d1d8u); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xc21e0e60u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000003u); Cell.CPSR 0x48050010u ] ]
    check false "e10032c1" inputs outputs

  /// <summary>
  /// A8.8.177 SMLATB: smlatb r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.177 SMLATB``() =
    let inputs =
      [ [ Gpr(0, 0x4f8f23c2u)
          Gpr(1, 0x12ede41bu)
          Gpr(2, 0xd204fd6cu)
          Gpr(3, 0xa3589811u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x1e4ba1d0u)
          Gpr(1, 0x745d9ec4u)
          Gpr(2, 0xd0dd84a4u)
          Gpr(3, 0xc5ccb9d7u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xa327cd0du); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x8dba396bu); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000003u); Cell.CPSR 0x48050010u ] ]
    check false "e10032a1" inputs outputs

  /// <summary>
  /// A8.8.177 SMLATT: smlatt r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.177 SMLATT``() =
    let inputs =
      [ [ Gpr(0, 0x071393d1u)
          Gpr(1, 0x4ace3d91u)
          Gpr(2, 0x82f50bedu)
          Gpr(3, 0x84fe217fu)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x5a35e897u)
          Gpr(1, 0xfe887406u)
          Gpr(2, 0x7279efd1u)
          Gpr(3, 0xeb0d8981u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x607454a5u); Cell.CPSR 0x28000010u ]
        [ Gpr(0, 0xea6567c9u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000003u); Cell.CPSR 0x48050010u ] ]
    check false "e10032e1" inputs outputs

  /// <summary>
  /// A8.8.178 SMLAD: smlad r0, r1, r2, r3. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.178 SMLAD``() =
    let inputs =
      [ [ Gpr(0, 0xebb26d6bu)
          Gpr(1, 0x1eecdf9bu)
          Gpr(2, 0x707a2135u)
          Gpr(3, 0x5aa89feau)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x9909d3a9u)
          Gpr(1, 0x8b415745u)
          Gpr(2, 0xa05294abu)
          Gpr(3, 0xd05d79bcu)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x7fff8000u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x640ae279u); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xd768e3a5u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x80007fffu); Cell.CPSR 0x48050010u ] ]
    check false "e7003211" inputs outputs

  /// <summary>
  /// A8.8.179 SMLAL: smlal r0, r1, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.179 SMLAL``() =
    let inputs =
      [ [ Gpr(0, 0xe4322896u); Gpr(1, 0x42dfea09u); Gpr(2, 0xa39680d3u) ]
        [ Gpr(0, 0x674d7b6au); Gpr(1, 0xe5542e81u); Gpr(2, 0x8f10c123u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xd40a8e01u); Gpr(1, 0x2abbe2deu) ]
        [ Gpr(0, 0x2fef180du); Gpr(1, 0xf118471eu) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u) ] ]
    check false "e0e10291" inputs outputs

  /// <summary>
  /// A8.8.180 SMLALBB: smlalbb r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.180 SMLALBB``() =
    let inputs =
      [ [ Gpr(0, 0x237756d0u)
          Gpr(1, 0xe2041f82u)
          Gpr(2, 0xeb98a5b7u)
          Gpr(3, 0x07c714c4u) ]
        [ Gpr(0, 0x053ebd69u)
          Gpr(1, 0xf0defea6u)
          Gpr(2, 0x092d5367u)
          Gpr(3, 0x6ec996a6u) ]
        [ Gpr(0, 0x00000000u)
          Gpr(1, 0x80007fffu)
          Gpr(2, 0x00000003u)
          Gpr(3, 0xfffffffeu) ] ]
    let outputs =
      [ [ Gpr(0, 0x1c2482ecu); Gpr(1, 0xe2041f82u) ]
        [ Gpr(0, 0xe2ec2c33u); Gpr(1, 0xf0defea5u) ]
        [ Gpr(0, 0xfffffffau); Gpr(1, 0x80007ffeu) ] ]
    check false "e1410382" inputs outputs

  /// <summary>
  /// A8.8.180 SMLALBT: smlalbt r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.180 SMLALBT``() =
    let inputs =
      [ [ Gpr(0, 0x32d5e91au)
          Gpr(1, 0x40a3741au)
          Gpr(2, 0x13ece276u)
          Gpr(3, 0x512b0238u) ]
        [ Gpr(0, 0x230233d0u)
          Gpr(1, 0x77c62879u)
          Gpr(2, 0x263256b7u)
          Gpr(3, 0x593e2acdu) ]
        [ Gpr(0, 0x00000000u)
          Gpr(1, 0x80007fffu)
          Gpr(2, 0x00000003u)
          Gpr(3, 0xfffffffeu) ] ]
    let outputs =
      [ [ Gpr(0, 0x297848ecu); Gpr(1, 0x40a3741au) ]
        [ Gpr(0, 0x413cd322u); Gpr(1, 0x77c62879u) ]
        [ Gpr(0, 0xfffffffdu); Gpr(1, 0x80007ffeu) ] ]
    check false "e14103c2" inputs outputs

  /// <summary>
  /// A8.8.180 SMLALTB: smlaltb r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.180 SMLALTB``() =
    let inputs =
      [ [ Gpr(0, 0x7a45fae9u)
          Gpr(1, 0xe90b2a03u)
          Gpr(2, 0x82a317e7u)
          Gpr(3, 0x109a5539u) ]
        [ Gpr(0, 0x7e5f734eu)
          Gpr(1, 0xc1d7a288u)
          Gpr(2, 0x47e1c87bu)
          Gpr(3, 0x6db0b338u) ]
        [ Gpr(0, 0x00000000u)
          Gpr(1, 0x80007fffu)
          Gpr(2, 0x00000003u)
          Gpr(3, 0xfffffffeu) ] ]
    let outputs =
      [ [ Gpr(0, 0x508a3034u); Gpr(1, 0xe90b2a03u) ]
        [ Gpr(0, 0x68d07f86u); Gpr(1, 0xc1d7a288u) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x80007fffu) ] ]
    check false "e14103a2" inputs outputs

  /// <summary>
  /// A8.8.180 SMLALTT: smlaltt r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.180 SMLALTT``() =
    let inputs =
      [ [ Gpr(0, 0x57073d05u)
          Gpr(1, 0xf9862a25u)
          Gpr(2, 0x37d7852bu)
          Gpr(3, 0x3ec2d0e4u) ]
        [ Gpr(0, 0x69ad168bu)
          Gpr(1, 0xded2b966u)
          Gpr(2, 0x84c80323u)
          Gpr(3, 0x4a8f0854u) ]
        [ Gpr(0, 0x00000000u)
          Gpr(1, 0x80007fffu)
          Gpr(2, 0x00000003u)
          Gpr(3, 0xfffffffeu) ] ]
    let outputs =
      [ [ Gpr(0, 0x64b79ff3u); Gpr(1, 0xf9862a25u) ]
        [ Gpr(0, 0x45ca1243u); Gpr(1, 0xded2b966u) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x80007fffu) ] ]
    check false "e14103e2" inputs outputs

  /// <summary>
  /// A8.8.181 SMLALD: smlald r0, r1, r1, r2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.181 SMLALD``() =
    let inputs =
      [ [ Gpr(0, 0x46c23d9fu); Gpr(1, 0x83a19dc8u); Gpr(2, 0x66b4a365u) ]
        [ Gpr(0, 0x752ec863u); Gpr(1, 0x48f6b25cu); Gpr(2, 0x8e914375u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x386488bbu); Gpr(1, 0x83a19dc8u) ]
        [ Gpr(0, 0x406527c5u); Gpr(1, 0x48f6b25cu) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u) ] ]
    check false "e7410211" inputs outputs

  /// <summary>
  /// A8.8.182 SMLAWB: smlawb r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.182 SMLAWB``() =
    let inputs =
      [ [ Gpr(0, 0xef79185eu)
          Gpr(1, 0x86a6dd5au)
          Gpr(2, 0x174acf61u)
          Gpr(3, 0x5e22ba38u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x152e780au)
          Gpr(1, 0x3801570bu)
          Gpr(2, 0x201ba6d1u)
          Gpr(3, 0x527c1c48u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x752ecf13u); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x3ef95cc6u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000003u); Cell.CPSR 0x48050010u ] ]
    check false "e1203281" inputs outputs

  /// <summary>
  /// A8.8.182 SMLAWT: smlawt r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.182 SMLAWT``() =
    let inputs =
      [ [ Gpr(0, 0xfc02e268u)
          Gpr(1, 0xc2212160u)
          Gpr(2, 0xe437a02au)
          Gpr(3, 0xc13af77au)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xae45a41au)
          Gpr(1, 0xdf96d7e3u)
          Gpr(2, 0xff6d0240u)
          Gpr(3, 0x8286e763u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xc7f20cf1u); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x829983c5u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000003u); Cell.CPSR 0x48050010u ] ]
    check false "e12032c1" inputs outputs

  /// <summary>
  /// A8.8.183 SMLSD: smlsd r0, r1, r2, r3. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.183 SMLSD``() =
    let inputs =
      [ [ Gpr(0, 0x9126d238u)
          Gpr(1, 0x47a9e6b2u)
          Gpr(2, 0x6b15b150u)
          Gpr(3, 0xdfad2bcfu)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x888fb61cu)
          Gpr(1, 0x7df39321u)
          Gpr(2, 0x91ec0156u)
          Gpr(3, 0x4eb7062cu)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x7fff8000u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xc97ad192u); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x844dd53eu); Cell.CPSR 0x980a0010u ]
        [ Gpr(0, 0x80007fffu); Cell.CPSR 0x48050010u ] ]
    check false "e7003251" inputs outputs

  /// <summary>
  /// A8.8.184 SMLSLD: smlsld r0, r1, r1, r2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.184 SMLSLD``() =
    let inputs =
      [ [ Gpr(0, 0x392855b7u); Gpr(1, 0xa675ba2bu); Gpr(2, 0x4ca0f399u) ]
        [ Gpr(0, 0xab4aed93u); Gpr(1, 0x59c53329u); Gpr(2, 0x45e7e999u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x5757a54au); Gpr(1, 0xa675ba2bu) ]
        [ Gpr(0, 0x8e4db851u); Gpr(1, 0x59c53329u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u) ] ]
    check false "e7410251" inputs outputs

  /// <summary>
  /// A8.8.185 SMMLA: smmla r0, r1, r2, r3. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.185 SMMLA``() =
    let inputs =
      [ [ Gpr(0, 0x502ba0c2u)
          Gpr(1, 0xdb50fa01u)
          Gpr(2, 0x58735cb2u)
          Gpr(3, 0x805e3b32u) ]
        [ Gpr(0, 0x246b34bau)
          Gpr(1, 0xd9a6da60u)
          Gpr(2, 0x0bc49ac7u)
          Gpr(3, 0x382fc7beu) ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x7fff8000u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x73b1893au) ]
        [ Gpr(0, 0x366c7fafu) ]
        [ Gpr(0, 0x80007fffu) ] ]
    check false "e7503211" inputs outputs

  /// <summary>
  /// A8.8.186 SMMLS: smmls r0, r1, r2, r3. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.186 SMMLS``() =
    let inputs =
      [ [ Gpr(0, 0x3002ae5au)
          Gpr(1, 0x45897846u)
          Gpr(2, 0x80260911u)
          Gpr(3, 0xde17a13du) ]
        [ Gpr(0, 0x3926299bu)
          Gpr(1, 0xbe348583u)
          Gpr(2, 0x48dc8ebfu)
          Gpr(3, 0x00647f8eu) ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x7fff8000u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x00d20881u) ]
        [ Gpr(0, 0x131e698eu) ]
        [ Gpr(0, 0x80007fffu) ] ]
    check false "e75032d1" inputs outputs

  /// <summary>
  /// A8.8.187 SMMUL: smmul r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.187 SMMUL``() =
    let inputs =
      [ [ Gpr(0, 0x985d0884u); Gpr(1, 0x4004d9acu); Gpr(2, 0x4b0ae800u) ]
        [ Gpr(0, 0x9069b7d8u); Gpr(1, 0x62357becu); Gpr(2, 0x8f6afe46u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x12c425fau) ]
        [ Gpr(0, 0xd4cf6ffeu) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e750f211" inputs outputs

  /// <summary>
  /// A8.8.188 SMUAD: smuad r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.188 SMUAD``() =
    let inputs =
      [ [ Gpr(0, 0xcf4d369au)
          Gpr(1, 0xd578ea79u)
          Gpr(2, 0x52160ae5u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xfcd85d11u)
          Gpr(1, 0x7af0e7b7u)
          Gpr(2, 0x5c512903u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x7fff8000u)
          Gpr(2, 0x00000000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xf172408du); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x28712c15u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000000u); Cell.CPSR 0x48050010u ] ]
    check false "e700f211" inputs outputs

  /// <summary>
  /// A8.8.189 SMULBB: smulbb r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.189 SMULBB``() =
    let inputs =
      [ [ Gpr(0, 0x9020a6e0u); Gpr(1, 0x376039fcu); Gpr(2, 0xbbde03a3u) ]
        [ Gpr(0, 0xd6e1ab29u); Gpr(1, 0x33e2c228u); Gpr(2, 0x0ccac701u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x00d2df74u) ]
        [ Gpr(0, 0x0dc4da28u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e1600281" inputs outputs

  /// <summary>
  /// A8.8.189 SMULBT: smulbt r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.189 SMULBT``() =
    let inputs =
      [ [ Gpr(0, 0x75c719ccu); Gpr(1, 0xe8e15c7fu); Gpr(2, 0x890a1ba4u) ]
        [ Gpr(0, 0x359e9a3du); Gpr(1, 0x747cb694u); Gpr(2, 0x1d281a92u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0xd50493f6u) ]
        [ Gpr(0, 0xf7a34b20u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e16002c1" inputs outputs

  /// <summary>
  /// A8.8.189 SMULTB: smultb r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.189 SMULTB``() =
    let inputs =
      [ [ Gpr(0, 0x4cc64deeu); Gpr(1, 0x2ac62fcau); Gpr(2, 0x0f0155c7u) ]
        [ Gpr(0, 0xe126c41bu); Gpr(1, 0x68eb3a10u); Gpr(2, 0xc0c70632u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x0e54fdeau) ]
        [ Gpr(0, 0x0289ffe6u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e16002a1" inputs outputs

  /// <summary>
  /// A8.8.189 SMULTT: smultt r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.189 SMULTT``() =
    let inputs =
      [ [ Gpr(0, 0xf84cc9b5u); Gpr(1, 0x98cd2d66u); Gpr(2, 0xcb8d1c21u) ]
        [ Gpr(0, 0x574a0e03u); Gpr(1, 0x6f02130fu); Gpr(2, 0xbfb8f1a9u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x1524b7e9u) ]
        [ Gpr(0, 0xe4204770u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e16002e1" inputs outputs

  /// <summary>
  /// A8.8.190 SMULL: smull r0, r1, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.190 SMULL``() =
    let inputs =
      [ [ Gpr(0, 0x97785c93u); Gpr(1, 0x270df5cbu); Gpr(2, 0x1193ba79u) ]
        [ Gpr(0, 0xca8d68c1u); Gpr(1, 0x38e297d0u); Gpr(2, 0x7f437946u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x38bfaaf3u); Gpr(1, 0x02ae76c9u) ]
        [ Gpr(0, 0x9326d2e0u); Gpr(1, 0x1c476790u) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x00000000u) ] ]
    check false "e0c10291" inputs outputs

  /// <summary>
  /// A8.8.191 SMULWB: smulwb r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.191 SMULWB``() =
    let inputs =
      [ [ Gpr(0, 0x2a8b37abu); Gpr(1, 0x4784f655u); Gpr(2, 0x758f2c51u) ]
        [ Gpr(0, 0xff65d9a7u); Gpr(1, 0xee2073cfu); Gpr(2, 0xef899a57u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x0c617b68u) ]
        [ Gpr(0, 0x0718fee2u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e12002a1" inputs outputs

  /// <summary>
  /// A8.8.191 SMULWT: smulwt r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.191 SMULWT``() =
    let inputs =
      [ [ Gpr(0, 0x677d6fafu); Gpr(1, 0x91b30a20u); Gpr(2, 0x9db5c86bu) ]
        [ Gpr(0, 0x7bb0e4c1u); Gpr(1, 0x339dc936u); Gpr(2, 0x896c20d8u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x2a59c6abu) ]
        [ Gpr(0, 0xe8176e08u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e12002e1" inputs outputs

  /// <summary>
  /// A8.8.192 SMUSD: smusd r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.192 SMUSD``() =
    let inputs =
      [ [ Gpr(0, 0xce89da6bu); Gpr(1, 0x7a78e1dfu); Gpr(2, 0xd420d93eu) ]
        [ Gpr(0, 0x47538b08u); Gpr(1, 0xc09d9a49u); Gpr(2, 0x78bcb88eu) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x198d0c02u) ]
        [ Gpr(0, 0x3a480132u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e700f251" inputs outputs

  /// <summary>
  /// A8.8.193 SRS: srsia sp, #0x13. This checks, from IRQ mode with SP_svc
  /// pointing into memory, that it stores LR then SPSR on Supervisor mode's
  /// stack and leaves SP_svc, and that User, Hyp and System mode refuse it. It
  /// is not a value test because it needs a privileged mode, which a user-mode
  /// run does not have.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.193 SRS``() =
    let w = uint32 Window
    let others =
      [ Register.LR, 0x11112222u
        Register.SPSR, 0x600001d3u
        Register.SP, w + 16u
        Register.SPsvc, w + 16u ]
    let cells = [ M(16, 0UL) ]
    let run = runWith false "f8cd0513" (Cell.CPSR 0x12u :: cells) others
    let refused = ManualLifting.refusedModes false "f8cd0513" cells others
    CollectionAssert.AreEqual([| 0x10u; 0x1au; 0x1fu |], refused)
    Assert.AreEqual(M(16, 0x600001d311112222UL), run.After(M(16, 0UL)))
    Assert.AreEqual(w + 16u, run.Reg Register.SPsvc)

  /// <summary>
  /// A8.8.194 SSAT: ssat r0, #0x8, r1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.194 SSAT``() =
    let inputs =
      [ [ Gpr(0, 0x737cb173u); Gpr(1, 0xba8dbda8u); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x233427beu); Gpr(1, 0x4e7dfa6cu); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u); Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xffffff80u); Cell.CPSR 0x28000010u ]
        [ Gpr(0, 0x0000007fu); Cell.CPSR 0x980a0010u ]
        [ Gpr(0, 0x0000007fu); Cell.CPSR 0x48050010u ] ]
    check false "e6a70011" inputs outputs

  /// <summary>
  /// A8.8.195 SSAT16: ssat16 r0, #0x8, r1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.195 SSAT16``() =
    let inputs =
      [ [ Gpr(0, 0xfcd49780u); Gpr(1, 0x02632342u); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x83f80af0u); Gpr(1, 0x6d4bcf68u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x007f007fu); Cell.CPSR 0x28000010u ]
        [ Gpr(0, 0x007fff80u); Cell.CPSR 0x980a0010u ]
        [ Gpr(0, 0x00000000u); Cell.CPSR 0x48050010u ] ]
    check false "e6a70f31" inputs outputs

  /// <summary>
  /// A8.8.196 SSAX: ssax r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.196 SSAX``() =
    let inputs =
      [ [ Gpr(0, 0xcd0cfc36u)
          Gpr(1, 0x28adae44u)
          Gpr(2, 0xae1fb76cu)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xe45693f2u)
          Gpr(1, 0xa68784f5u)
          Gpr(2, 0xd8960805u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x71415c63u); Cell.CPSR 0x200c0010u ]
        [ Gpr(0, 0x9e825d8bu); Cell.CPSR 0x90000010u ]
        [ Gpr(0, 0x8000ffffu); Cell.CPSR 0x480c0010u ] ]
    check false "e6110f52" inputs outputs

  /// <summary>
  /// A8.8.197 SSUB16: ssub16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.197 SSUB16``() =
    let inputs =
      [ [ Gpr(0, 0x3605a797u)
          Gpr(1, 0xfe18c72eu)
          Gpr(2, 0x437a0074u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xa1fce275u)
          Gpr(1, 0x89842624u)
          Gpr(2, 0xea2034d7u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xba9ec6bau); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x9f64f14du); Cell.CPSR 0x90000010u ]
        [ Gpr(0, 0x80008001u); Cell.CPSR 0x480c0010u ] ]
    check false "e6110f72" inputs outputs

  /// <summary>
  /// A8.8.198 SSUB8: ssub8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.198 SSUB8``() =
    let inputs =
      [ [ Gpr(0, 0x4d96c04au)
          Gpr(1, 0x254d2237u)
          Gpr(2, 0x9dd2e951u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x8d0559fau)
          Gpr(1, 0xd7acdda7u)
          Gpr(2, 0x03fc2b88u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x7fff8000u)
          Gpr(2, 0x00000000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x887b39e6u); Cell.CPSR 0x200e0010u ]
        [ Gpr(0, 0xd4b0b21fu); Cell.CPSR 0x90010010u ]
        [ Gpr(0, 0x7fff8000u); Cell.CPSR 0x48090010u ] ]
    check false "e6110ff2" inputs outputs

  /// <summary>
  /// A8.8.199 STC: stc 7, cr1, [r1, #8]. This checks that the lift says the
  /// instruction is unsupported: coprocessor 7 is none this front end models.
  /// It is not a value test because it reaches a coprocessor, which a user-mode
  /// run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.199 STC``() =
    let run = runWith false "ed811702" [ Cell.CPSR 0x13u ] []
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.199 STC2: stc2 7, cr1, [r1, #8]. This checks that the lift says the
  /// instruction is unsupported: coprocessor 7 is none this front end models.
  /// It is not a value test because it reaches a coprocessor, which a user-mode
  /// run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.199 STC2``() =
    let run = runWith false "fd811702" [ Cell.CPSR 0x13u ] []
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.200 STM: stm r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.200 STM``() =
    let inputs =
      [ [ Gpr(1, 0x20000818u)
          Gpr(2, 0x54d35318u)
          Gpr(3, 0xc5d88dc4u)
          M(0, 0xe0eac52665eb627dUL)
          M(8, 0x8e0cb381fbdebc1eUL)
          M(16, 0x5c251b935100c407UL)
          M(24, 0xb0fac97f24b14f8eUL)
          M(32, 0xa5d2db291c927115UL)
          M(40, 0xfcfb62a08d1fb51dUL)
          M(48, 0xd0ea678bce3bbcecUL)
          M(56, 0x0bbcd38d74b1d3fcUL) ]
        [ Gpr(1, 0x20000818u)
          Gpr(2, 0xe155b86fu)
          Gpr(3, 0x8cdaccc0u)
          M(0, 0xef4ec48a0f75a804UL)
          M(8, 0x3423e81072a7f607UL)
          M(16, 0x1b501efb5fed418aUL)
          M(24, 0xb86a0f24a827bfa6UL)
          M(32, 0xbe87527f8adf8825UL)
          M(40, 0x3fb8939f6236a1dfUL)
          M(48, 0xeb80d76534230fe1UL)
          M(56, 0x103c4005f83ba18cUL) ]
        [ Gpr(1, 0x20000818u)
          Gpr(2, 0x00008000u)
          Gpr(3, 0x7fff8000u)
          M(0, 0x789e9e4f7330fb04UL)
          M(8, 0x9a317e8afe0568fcUL)
          M(16, 0xf578c5c33237935aUL)
          M(24, 0x88fadf1161868303UL)
          M(32, 0x3721f6e1a5b525fcUL)
          M(40, 0x6a2650987a01155eUL)
          M(48, 0x3f485aa365d5a6feUL)
          M(56, 0x54880859a1bd5adeUL) ] ]
    let outputs =
      [ [ M(24, 0xc5d88dc454d35318UL) ]
        [ M(24, 0x8cdaccc0e155b86fUL) ]
        [ M(24, 0x7fff800000008000UL) ] ]
    check false "e881000c" inputs outputs

  /// <summary>
  /// A8.8.201 STMDA: stmda r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.201 STMDA``() =
    let inputs =
      [ [ Gpr(1, 0x2000081cu)
          Gpr(2, 0x390b745eu)
          Gpr(3, 0x4b6cb3cfu)
          M(0, 0x495152a12765be07UL)
          M(8, 0x2dfa37cdfa218b78UL)
          M(16, 0x4e9865a63bbe8507UL)
          M(24, 0x0d58a8142915c89bUL)
          M(32, 0x21c30d8334593979UL)
          M(40, 0x2a26a65c271e9eb7UL)
          M(48, 0xd23e8c51416e9633UL)
          M(56, 0x796b5a9fcd7fda2aUL) ]
        [ Gpr(1, 0x2000081cu)
          Gpr(2, 0x5b74c126u)
          Gpr(3, 0x67c4bdc4u)
          M(0, 0x386f88c1642d4293UL)
          M(8, 0x8c3d151ca7e2631aUL)
          M(16, 0x6f89a80316f3205eUL)
          M(24, 0xc4a537bd78ea6a23UL)
          M(32, 0x6e9445b1e56e0480UL)
          M(40, 0x3ce46b5b2d18b131UL)
          M(48, 0xad413fe4c9281da6UL)
          M(56, 0x5d941c11c16b964cUL) ]
        [ Gpr(1, 0x2000081cu)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0xcd414b85d7fe611eUL)
          M(8, 0x4928995332a1a3d7UL)
          M(16, 0x474178a7b8748d15UL)
          M(24, 0xca8b42212a4ca712UL)
          M(32, 0xaebdada55c158030UL)
          M(40, 0x664fdcdbce30c9e2UL)
          M(48, 0xb9855c69e42be12fUL)
          M(56, 0x43643d5cbbd7c8f8UL) ] ]
    let outputs =
      [ [ M(24, 0x4b6cb3cf390b745eUL) ]
        [ M(24, 0x67c4bdc45b74c126UL) ]
        [ M(24, 0x80007fff00000000UL) ] ]
    check false "e801000c" inputs outputs

  /// <summary>
  /// A8.8.202 STMDB: stmdb r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.202 STMDB``() =
    let inputs =
      [ [ Gpr(1, 0x20000820u)
          Gpr(2, 0x89467f26u)
          Gpr(3, 0xcb19a67bu)
          M(0, 0xae8e25a01519ed3eUL)
          M(8, 0x29286e1e81437e59UL)
          M(16, 0xba5d8741330b0711UL)
          M(24, 0x036d34bd2e436a70UL)
          M(32, 0x8edebc0aa8eafa7eUL)
          M(40, 0xd1536459ec39e541UL)
          M(48, 0xc43ddcf55edc3f47UL)
          M(56, 0x06009d2365902a0cUL) ]
        [ Gpr(1, 0x20000820u)
          Gpr(2, 0x8bdbf9ccu)
          Gpr(3, 0x6f82dd6au)
          M(0, 0x9da2b0f055dd0631UL)
          M(8, 0x2f266da05fc88563UL)
          M(16, 0xbfcbb0b0cab9bff6UL)
          M(24, 0xcedc4ebbfcab2de4UL)
          M(32, 0x82aa65d9c4183d67UL)
          M(40, 0xaae1d513a2a46d2cUL)
          M(48, 0x852aace2e6d9e5b8UL)
          M(56, 0xe2304e208644a565UL) ]
        [ Gpr(1, 0x20000820u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0x49b17ad0dd5e43acUL)
          M(8, 0x0da5055d2dcce084UL)
          M(16, 0x645a0ad4e08ca6d1UL)
          M(24, 0x434025f88cc61b24UL)
          M(32, 0xf4e3fd18a26d501dUL)
          M(40, 0xfe077fb67e9c9497UL)
          M(48, 0xf387808db38835e3UL)
          M(56, 0xe4c291d9bdecd77fUL) ] ]
    let outputs =
      [ [ M(24, 0xcb19a67b89467f26UL) ]
        [ M(24, 0x6f82dd6a8bdbf9ccUL) ]
        [ M(24, 0x80007fff00000000UL) ] ]
    check false "e901000c" inputs outputs

  /// <summary>
  /// A8.8.203 STMIB: stmib r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.203 STMIB``() =
    let inputs =
      [ [ Gpr(1, 0x20000814u)
          Gpr(2, 0x5572a46cu)
          Gpr(3, 0xf532e49fu)
          M(0, 0x1906a1d5044f85dfUL)
          M(8, 0xf4f1b603e4aa2563UL)
          M(16, 0x6c60a7830edecad3UL)
          M(24, 0xa4bc52f03062d836UL)
          M(32, 0xefa4f2312d228169UL)
          M(40, 0x8a238d4a7f7bc1fdUL)
          M(48, 0x2cac180bab4e64b1UL)
          M(56, 0x90d43a7db8ac8ef8UL) ]
        [ Gpr(1, 0x20000814u)
          Gpr(2, 0x9c8b5a1cu)
          Gpr(3, 0x47e80981u)
          M(0, 0xb7ac97daca95454eUL)
          M(8, 0xfe576c566dbd496aUL)
          M(16, 0x722671d72bde66fbUL)
          M(24, 0xeb6564684683afddUL)
          M(32, 0x1961af94da51ff6eUL)
          M(40, 0xf8dfd11eefba9590UL)
          M(48, 0xd847aff29dd51bb4UL)
          M(56, 0xc32031f2ec81de92UL) ]
        [ Gpr(1, 0x20000814u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0x3ce72a121f5e3669UL)
          M(8, 0x3a8b96344d7bb8e4UL)
          M(16, 0xe49efacbe9a168daUL)
          M(24, 0x354d4f37d3725a26UL)
          M(32, 0x1856c4ef774a945aUL)
          M(40, 0xf3a548268dde11d0UL)
          M(48, 0x4b43fd068610aff9UL)
          M(56, 0xe3343ae4ee85438bUL) ] ]
    let outputs =
      [ [ M(24, 0xf532e49f5572a46cUL) ]
        [ M(24, 0x47e809819c8b5a1cUL) ]
        [ M(24, 0x80007fff00000000UL) ] ]
    check false "e981000c" inputs outputs

  /// <summary>
  /// A8.8.204 STR: str r0, [r1]. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.204 STR``() =
    let inputs =
      [ [ Gpr(0, 0xa5a39373u)
          Gpr(1, 0x20000810u)
          M(0, 0x596b3fdf6fac6b4dUL)
          M(8, 0x3232352e1e649024UL)
          M(16, 0x4903074abaaa8070UL)
          M(24, 0x396cb3c0d285dcfdUL)
          M(32, 0x0408f4be184db736UL)
          M(40, 0x73e1e37b19b6429eUL)
          M(48, 0x5d8d0fc56c0d4eabUL)
          M(56, 0x0245ab00118d812eUL) ]
        [ Gpr(0, 0x693c3bc3u)
          Gpr(1, 0x20000810u)
          M(0, 0xbb48230a620415aaUL)
          M(8, 0x1c74a683c95cccb0UL)
          M(16, 0x68f58ba8fbbdb2b2UL)
          M(24, 0xd444df27b03c94cdUL)
          M(32, 0xfd38843581b0e36bUL)
          M(40, 0xd7f33713ebb73184UL)
          M(48, 0xbcc11aebd1c4ce9cUL)
          M(56, 0xe2720eb384986a07UL) ]
        [ Gpr(0, 0x00000001u)
          Gpr(1, 0x20000810u)
          M(0, 0x09b49c52c4e649d8UL)
          M(8, 0x34fd4d07d1e6675aUL)
          M(16, 0x6f8b3e0f8043321aUL)
          M(24, 0x7ca675d4618bc5b9UL)
          M(32, 0x2eee9405bc8ad949UL)
          M(40, 0x26c7d9a6fbd20d46UL)
          M(48, 0xa027f3431bf9b8bdUL)
          M(56, 0x7a2d9e4e4382628fUL) ] ]
    let outputs =
      [ [ M(16, 0x4903074aa5a39373UL) ]
        [ M(16, 0x68f58ba8693c3bc3UL) ]
        [ M(16, 0x6f8b3e0f00000001UL) ] ]
    check false "e5810000" inputs outputs

  /// <summary>
  /// A8.8.207 STRB: strb r0, [r1]. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.207 STRB``() =
    let inputs =
      [ [ Gpr(0, 0x2905ba39u)
          Gpr(1, 0x20000810u)
          M(0, 0x3327c003e4626732UL)
          M(8, 0xc3b4ff84c957e374UL)
          M(16, 0x4a5662615458d9f6UL)
          M(24, 0xf2d269e95190ed5dUL)
          M(32, 0xbf9d4310a592ea7cUL)
          M(40, 0x0cbd3213f1c18f7cUL)
          M(48, 0x1f5b1c1fa8d2816aUL)
          M(56, 0x0104088472587c7eUL) ]
        [ Gpr(0, 0xfd7cda94u)
          Gpr(1, 0x20000810u)
          M(0, 0x49b8c53f0cb29e0bUL)
          M(8, 0x7b0ee1b4f99cd667UL)
          M(16, 0xea85a2022fb822b1UL)
          M(24, 0x6787f5e6070424a8UL)
          M(32, 0x9043df65823c0665UL)
          M(40, 0x0586d6790adcf704UL)
          M(48, 0x31c5df381e3f49a1UL)
          M(56, 0xc17616edefc2eaebUL) ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x20000810u)
          M(0, 0x9071293676c7767bUL)
          M(8, 0xe658a24ba02cab3aUL)
          M(16, 0x7ce76c5663557f2aUL)
          M(24, 0xa56e4c3f01e6f59eUL)
          M(32, 0x97a0c2ded840dcc0UL)
          M(40, 0xc5ee2375130bfdcbUL)
          M(48, 0x5190fc2113eefaafUL)
          M(56, 0x0901da1adf33f837UL) ] ]
    let outputs =
      [ [ M(16, 0x4a5662615458d939UL) ]
        [ M(16, 0xea85a2022fb82294UL) ]
        [ M(16, 0x7ce76c5663557fffUL) ] ]
    check false "e5c10000" inputs outputs

  /// <summary>
  /// A8.8.210 STRBT: strbt r0, [r1], #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.210 STRBT``() =
    let inputs =
      [ [ Gpr(0, 0xc7bc4775u)
          Gpr(1, 0x20000810u)
          M(0, 0xaa9c7d4f5ea1b0ffUL)
          M(8, 0xf2334cf6c549ffadUL)
          M(16, 0xd93465b1abb2a7d5UL)
          M(24, 0xfb50a9e2e2b1c24fUL)
          M(32, 0x002d4b324a840b8cUL)
          M(40, 0x633e108fcf215f47UL)
          M(48, 0x27df4dedaeffce6aUL)
          M(56, 0x0127a069462df4e0UL) ]
        [ Gpr(0, 0xb8b3c37bu)
          Gpr(1, 0x20000810u)
          M(0, 0xa6921f738b9ed8a7UL)
          M(8, 0xb2a5428737016ca5UL)
          M(16, 0x4d433a5ec6e4ccd5UL)
          M(24, 0xe1294d2c235a250dUL)
          M(32, 0xa8189bd91e1a121aUL)
          M(40, 0xd9e2764c9339d837UL)
          M(48, 0x68fad320e9212c54UL)
          M(56, 0x9572af45933f3c87UL) ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x20000810u)
          M(0, 0x23ff3fcffc93cbe9UL)
          M(8, 0x353b838ae79d198eUL)
          M(16, 0xf0db7e41a061913cUL)
          M(24, 0x9524d33d8db86c13UL)
          M(32, 0xe635650e9bc18375UL)
          M(40, 0xfa329c999a37ef2dUL)
          M(48, 0x61d13fa570b1ef7fUL)
          M(56, 0xc3f21390aeb44669UL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000810u); M(16, 0xd93465b1abb2a775UL) ]
        [ Gpr(1, 0x20000810u); M(16, 0x4d433a5ec6e4cc7bUL) ]
        [ Gpr(1, 0x20000810u); M(16, 0xf0db7e41a0619100UL) ] ]
    check false "e4e10000" inputs outputs

  /// <summary>
  /// A8.8.211 STRD: strd r2, [r1, #8]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.211 STRD``() =
    let inputs =
      [ [ Gpr(1, 0x20000808u)
          Gpr(2, 0xc870fe96u)
          Gpr(3, 0x7a5a74b6u)
          M(0, 0x52364cf42eb668abUL)
          M(8, 0x56dd44db7d8c8cc3UL)
          M(16, 0x720c4925505e5977UL)
          M(24, 0x1fd681733efb5663UL)
          M(32, 0xf8f00931fe7054f4UL)
          M(40, 0x9ccbefe23e78a353UL)
          M(48, 0x5058294359ef2ab4UL)
          M(56, 0x974832f1681fe69fUL) ]
        [ Gpr(1, 0x20000808u)
          Gpr(2, 0x7ebc889bu)
          Gpr(3, 0xcf6119b8u)
          M(0, 0x24cccfbc71874e6cUL)
          M(8, 0x327e08d1d81a4c0aUL)
          M(16, 0xe025256b99801bd3UL)
          M(24, 0xbcbc76cf0422c04cUL)
          M(32, 0x1af538e3de1234fbUL)
          M(40, 0x9c0935a69bbe69e7UL)
          M(48, 0xd5d41fa8f51916aaUL)
          M(56, 0xbb43f6c842dea9bbUL) ]
        [ Gpr(1, 0x20000808u)
          Gpr(2, 0x7fff8000u)
          Gpr(3, 0x00000000u)
          M(0, 0xe1de7b5403cbde0bUL)
          M(8, 0x0898a1e3d9b3c3e3UL)
          M(16, 0xf45938a950fa74f1UL)
          M(24, 0xf3434f5f31d8386dUL)
          M(32, 0x97e395b69e395abfUL)
          M(40, 0x76997aea24e33d4eUL)
          M(48, 0x0783a1d9e49e7366UL)
          M(56, 0xb7909cc0e908af6fUL) ] ]
    let outputs =
      [ [ M(16, 0x7a5a74b6c870fe96UL) ]
        [ M(16, 0xcf6119b87ebc889bUL) ]
        [ M(16, 0x000000007fff8000UL) ] ]
    check false "e1c120f8" inputs outputs

  /// <summary>
  /// A8.8.213 STREX: strex r0, r2, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.213 STREX``() =
    let inputs =
      [ [ Gpr(0, 0x7474c3f4u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x8bd01c1bu)
          M(0, 0x93b2bf27fa513e78UL)
          M(8, 0xfcbdf736ebb61dbbUL)
          M(16, 0xc596abfad9608d45UL)
          M(24, 0x6cb4e8317bd3bd16UL)
          M(32, 0x02ef899a70057a7eUL)
          M(40, 0xdba6611c690713c8UL)
          M(48, 0xfc6749f9449402e8UL)
          M(56, 0xb4093a3f3165faddUL) ]
        [ Gpr(0, 0x5220b0edu)
          Gpr(1, 0x20000810u)
          Gpr(2, 0xfc73400fu)
          M(0, 0x6da4458adfeb75c7UL)
          M(8, 0xbd6e069a3f871412UL)
          M(16, 0x0acd2aa75b3fa3b0UL)
          M(24, 0x84d8ac95e2e47becUL)
          M(32, 0xaa180cac70d5de78UL)
          M(40, 0x261eecfc3e65dec7UL)
          M(48, 0xfaa71c0dc0928e67UL)
          M(56, 0x46c0c422dbbfc474UL) ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x00000000u)
          M(0, 0x490f9590cc09b2daUL)
          M(8, 0x275f6a166315b2f7UL)
          M(16, 0x5ceac70580dc43a3UL)
          M(24, 0xb06bdba3a0b03a9dUL)
          M(32, 0xa43c4ee423070e2dUL)
          M(40, 0xba50d51541b45db0UL)
          M(48, 0x54eac34c4f950d44UL)
          M(56, 0x5f1edb9f2d24e053UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e1810f92" inputs outputs

  /// <summary>
  /// A8.8.214 STREXB: strexb r0, r2, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.214 STREXB``() =
    let inputs =
      [ [ Gpr(0, 0x20c6e37fu)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x58eda946u)
          M(0, 0x6c800c4442ce59c9UL)
          M(8, 0xdeda1fcb5b28a339UL)
          M(16, 0xa256b110bf01391cUL)
          M(24, 0x5d4c3d697d462818UL)
          M(32, 0x610ce6f0f9f1a471UL)
          M(40, 0x470ca9f25b578facUL)
          M(48, 0x141b6be6317acd0dUL)
          M(56, 0x8187283acf4750aeUL) ]
        [ Gpr(0, 0x83d35f9bu)
          Gpr(1, 0x20000810u)
          Gpr(2, 0xb3e81174u)
          M(0, 0xca13cc955a555de2UL)
          M(8, 0x4ffb68810d8a02d2UL)
          M(16, 0x40c93de1c506561dUL)
          M(24, 0xdb2184a10f72822eUL)
          M(32, 0x43c942abbc9e7191UL)
          M(40, 0x303784907f3be8b9UL)
          M(48, 0x795f69e3b7bf8d43UL)
          M(56, 0x46663dcbc2d0003fUL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x80007fffu)
          M(0, 0x89e98c40be0f24c1UL)
          M(8, 0x0765dd78135fb7fcUL)
          M(16, 0x86c7030bc7538399UL)
          M(24, 0xce072ccba10d6f92UL)
          M(32, 0x391127f5e707d175UL)
          M(40, 0x077311b7a12ccf3fUL)
          M(48, 0xc8fefc9dac4b4215UL)
          M(56, 0x1c05352b1e95778eUL) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e1c10f92" inputs outputs

  /// <summary>
  /// A8.8.215 STREXD: strexd r0, r2, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.215 STREXD``() =
    let inputs =
      [ [ Gpr(0, 0x31785c3fu)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x4f63f99bu)
          Gpr(3, 0x7267883cu)
          M(0, 0xda51882b0fecae33UL)
          M(8, 0x12792f061b009b76UL)
          M(16, 0x8934ca36aa0cf1d8UL)
          M(24, 0xef169991c896376cUL)
          M(32, 0xc6ca4bfaae79f744UL)
          M(40, 0xcd56b4612bb879a7UL)
          M(48, 0x6976c50f8649ff7fUL)
          M(56, 0x3acd3b75d89d82e4UL) ]
        [ Gpr(0, 0xc74b91ffu)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x42027c81u)
          Gpr(3, 0xd78752c4u)
          M(0, 0x47664dbb1982fd4cUL)
          M(8, 0xdf5ee4744a6f2fb6UL)
          M(16, 0x7088202de4c21e1aUL)
          M(24, 0xfd98a1a82b0ba89dUL)
          M(32, 0xf91c4f229efb02b6UL)
          M(40, 0x717b1ec75d53e43bUL)
          M(48, 0x803917b99c5f48afUL)
          M(56, 0xe2b8a9e623102a9bUL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u)
          M(0, 0x019c1f6087441951UL)
          M(8, 0xd91325d86c174030UL)
          M(16, 0x03f4b9d3e4afd593UL)
          M(24, 0x887a4da7a1032bfbUL)
          M(32, 0xcd92397f6fd048d4UL)
          M(40, 0x28f519ebf222751cUL)
          M(48, 0x95d083b4b353ee6eUL)
          M(56, 0x914e2ca8655faa17UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e1a10f92" inputs outputs

  /// <summary>
  /// A8.8.216 STREXH: strexh r0, r2, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.216 STREXH``() =
    let inputs =
      [ [ Gpr(0, 0xbc42704cu)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x92b2a905u)
          M(0, 0x55e0248400b71411UL)
          M(8, 0xbec365b3e0091887UL)
          M(16, 0xcf7e66db8e542701UL)
          M(24, 0xbb59ac93ee67424bUL)
          M(32, 0x4285b72b4ce8ad9fUL)
          M(40, 0xf2d5b8c363110c3bUL)
          M(48, 0x7468b0925266ec4dUL)
          M(56, 0xdc57d281a59b83d5UL) ]
        [ Gpr(0, 0xe8b60f12u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x923378bau)
          M(0, 0x495d3a05b613b00dUL)
          M(8, 0x1829600eac9fc905UL)
          M(16, 0x51ba8d1ee9b27f63UL)
          M(24, 0x373542fc279aae3dUL)
          M(32, 0xe510ec83bb34e823UL)
          M(40, 0x80d11cb8afef0015UL)
          M(48, 0x2d0cbadc5686ca41UL)
          M(56, 0xeedf419cb9169c77UL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x80007fffu)
          M(0, 0xef7f19a846a29c32UL)
          M(8, 0x1af89f4c2d0fcb7fUL)
          M(16, 0x3ca35c3ad57c6fe7UL)
          M(24, 0xc2a828892e992d18UL)
          M(32, 0x66f9fde1a52ce3a5UL)
          M(40, 0x706286ac3d7f5c31UL)
          M(48, 0x499c5c305e171390UL)
          M(56, 0x5cfd516e45911719UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e1e10f92" inputs outputs

  /// <summary>
  /// A8.8.217 STRH: strh r0, [r1]. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.217 STRH``() =
    let inputs =
      [ [ Gpr(0, 0x8703e21au)
          Gpr(1, 0x20000810u)
          M(0, 0xbcb68aca41cd6e8aUL)
          M(8, 0x1ce0df4ebc1d2894UL)
          M(16, 0xb8e0076a016723a8UL)
          M(24, 0x379dd998a8b055c4UL)
          M(32, 0x0cc7ed822b791282UL)
          M(40, 0xb9982b513eb18d19UL)
          M(48, 0xd3d8953c24b5a005UL)
          M(56, 0x4aa65177c33238c7UL) ]
        [ Gpr(0, 0x52534fe4u)
          Gpr(1, 0x20000810u)
          M(0, 0x07fe643cb723c38aUL)
          M(8, 0x2d97dab3899424a5UL)
          M(16, 0xbfd5434febe0784bUL)
          M(24, 0x5af6d9c143def620UL)
          M(32, 0xcb4a28cb4031359bUL)
          M(40, 0x935755aa7caea7ccUL)
          M(48, 0x628c1d83458a1e87UL)
          M(56, 0x08221937c78f523eUL) ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x20000810u)
          M(0, 0x4be63d3442ef5305UL)
          M(8, 0x0d1ee70e1430c87cUL)
          M(16, 0x71aafb5d3a03c455UL)
          M(24, 0xf988804f455192d1UL)
          M(32, 0x244341bce9199b09UL)
          M(40, 0x5ae6284c15326ec4UL)
          M(48, 0xd3a06dbff4cddb16UL)
          M(56, 0xa38de1d0d8abc023UL) ] ]
    let outputs =
      [ [ M(16, 0xb8e0076a0167e21aUL) ]
        [ M(16, 0xbfd5434febe04fe4UL) ]
        [ M(16, 0x71aafb5d3a03ffffUL) ] ]
    check false "e1c100b0" inputs outputs

  /// <summary>
  /// A8.8.220 STRHT: strht r0, [r1], #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.220 STRHT``() =
    let inputs =
      [ [ Gpr(0, 0x9463c311u)
          Gpr(1, 0x20000810u)
          M(0, 0xa5bb907747280ee9UL)
          M(8, 0x1ee6ebaaa9ff0eeaUL)
          M(16, 0xc7279c5c3c39070dUL)
          M(24, 0x428b9eec92c136d5UL)
          M(32, 0xf56277411494942eUL)
          M(40, 0x151e407a4991ad84UL)
          M(48, 0x401886686f54af01UL)
          M(56, 0x7d3499c394c5cfafUL) ]
        [ Gpr(0, 0x4e9e5105u)
          Gpr(1, 0x20000810u)
          M(0, 0x42e73779373142daUL)
          M(8, 0x16ade9b22ed300e6UL)
          M(16, 0x482ea4da10c6f007UL)
          M(24, 0x2aec4e00daab4351UL)
          M(32, 0x1e6b48cf4f80b2d9UL)
          M(40, 0x23fd8e5512f89d56UL)
          M(48, 0x12b0f1c3f42ce96dUL)
          M(56, 0x32a91d7cf0047852UL) ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x20000810u)
          M(0, 0xc78a04f22a082e2dUL)
          M(8, 0x085345ea0726b6a5UL)
          M(16, 0x6bb22cc0543fdc84UL)
          M(24, 0x36ae58625a460a76UL)
          M(32, 0xbc4e3b2efdf07dd2UL)
          M(40, 0x37e05ff83b3de911UL)
          M(48, 0x9ff53706edf04071UL)
          M(56, 0x6c828b64cf5ee5f6UL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000810u); M(16, 0xc7279c5c3c39c311UL) ]
        [ Gpr(1, 0x20000810u); M(16, 0x482ea4da10c65105UL) ]
        [ Gpr(1, 0x20000810u); M(16, 0x6bb22cc0543f8000UL) ] ]
    check false "e0e100b0" inputs outputs

  /// <summary>
  /// A8.8.221 STRT: strt r0, [r1], #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.221 STRT``() =
    let inputs =
      [ [ Gpr(0, 0xcf4d1abcu)
          Gpr(1, 0x20000810u)
          M(0, 0xadb8ead0ea0113cfUL)
          M(8, 0x3049a18e6f6eb763UL)
          M(16, 0x5592b7e14a7c94b2UL)
          M(24, 0xa0cf2887478e9a03UL)
          M(32, 0x813ce67cf043898fUL)
          M(40, 0xdf3ec0952e5575aaUL)
          M(48, 0x2bbfe04e7c4b8b17UL)
          M(56, 0xe01466782dbf3d6cUL) ]
        [ Gpr(0, 0x94d4b92eu)
          Gpr(1, 0x20000810u)
          M(0, 0x9dc64013a602bf5fUL)
          M(8, 0x039e5d610e7cde7fUL)
          M(16, 0xe320da4bc57ef02dUL)
          M(24, 0xac09afa3ebf621b9UL)
          M(32, 0x0f7f0e86123d2b80UL)
          M(40, 0xe2604d1707484952UL)
          M(48, 0x21a52fe78b846222UL)
          M(56, 0x917fb018c1b45164UL) ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x20000810u)
          M(0, 0x611fca9db8dc67a7UL)
          M(8, 0xc3fe370d077ea48aUL)
          M(16, 0x476ff4799bbc3547UL)
          M(24, 0xa6ca4544de092bc1UL)
          M(32, 0xd4499e3912eee099UL)
          M(40, 0x171666b12c697bafUL)
          M(48, 0xdb9c4a141f0dca74UL)
          M(56, 0x553c9dca4deebf8eUL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000810u); M(16, 0x5592b7e1cf4d1abcUL) ]
        [ Gpr(1, 0x20000810u); M(16, 0xe320da4b94d4b92eUL) ]
        [ Gpr(1, 0x20000810u); M(16, 0x476ff4790000ffffUL) ] ]
    check false "e4a10000" inputs outputs

  /// <summary>
  /// A8.8.222 SUB: sub r0, r1, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.222 SUB``() =
    let inputs =
      [ [ Gpr(0, 0xf2ff0243u); Gpr(1, 0xfc45a56fu); Gpr(2, 0x9e56b737u) ]
        [ Gpr(0, 0x63f0e3deu); Gpr(1, 0x323e4537u); Gpr(2, 0xbc767841u) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu); Gpr(2, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x5deeee38u) ]
        [ Gpr(0, 0x75c7ccf6u) ]
        [ Gpr(0, 0x00007fffu) ] ]
    check false "e0410002" inputs outputs

  /// <summary>
  /// A8.8.228 SUBS: subs r0, r1, #0x3f0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.228 SUBS``() =
    let inputs =
      [ [ Gpr(0, 0x69e9fe84u); Gpr(1, 0xa37d472du); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xee7f0296u); Gpr(1, 0xe4afc26eu); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u); Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xa37d433du); Cell.CPSR 0xa0000010u ]
        [ Gpr(0, 0xe4afbe7eu); Cell.CPSR 0xa00a0010u ]
        [ Gpr(0, 0x00007c10u); Cell.CPSR 0x28050010u ] ]
    check false "e2510e3f" inputs outputs

  /// <summary>
  /// A8.8.229 SVC: svc #0x12004. This checks that it calls the supervisor with
  /// its immediate. It is not a value test because it takes an exception, which
  /// a user-mode run cannot return from.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.229 SVC``() =
    let run = runWith false "ef012004" [ Cell.CPSR 0x10u ] []
    Assert.AreEqual(Some(SideEffect.Interrupt 0x12004), run.Effect)

  /// <summary>
  /// A8.8.230 SWP: swp r0, r1, [r2]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.230 SWP``() =
    let inputs =
      [ [ Gpr(0, 0x02e6b309u)
          Gpr(1, 0x09b8ec33u)
          Gpr(2, 0x20000810u)
          M(0, 0xb2303c58084f8573UL)
          M(8, 0x85e2748352dd8ce5UL)
          M(16, 0x3860d2f5aca3ca63UL)
          M(24, 0xe03bfc4e57a7a898UL)
          M(32, 0xde0c578d9d5a20dfUL)
          M(40, 0x35ebed9e835feb49UL)
          M(48, 0x6d36782a15c2dab4UL)
          M(56, 0x94c406456bb2fa64UL) ]
        [ Gpr(0, 0x5a143f54u)
          Gpr(1, 0x245b7007u)
          Gpr(2, 0x20000810u)
          M(0, 0xcfc8291efe384860UL)
          M(8, 0x9c3fad25aab52049UL)
          M(16, 0xd0ec9bbcdd226365UL)
          M(24, 0xad9056661a19d1f2UL)
          M(32, 0xbd920abd369dc6e4UL)
          M(40, 0x94c0d4169d8cf640UL)
          M(48, 0xda690b68769de80fUL)
          M(56, 0x37ea93bd5950c7efUL) ]
        [ Gpr(0, 0x00000001u)
          Gpr(1, 0x0000ffffu)
          Gpr(2, 0x20000810u)
          M(0, 0x76feef21be05f9b8UL)
          M(8, 0xd1e410845e18f9dcUL)
          M(16, 0xe4de3c399466d533UL)
          M(24, 0x20d7f5e90ff375ebUL)
          M(32, 0x140a959b2551a3cdUL)
          M(40, 0xa49ad91cd1e23f75UL)
          M(48, 0x7a67979d79fd106eUL)
          M(56, 0xad5a16505a10f75dUL) ] ]
    let outputs =
      [ [ Gpr(0, 0xaca3ca63u); M(16, 0x3860d2f509b8ec33UL) ]
        [ Gpr(0, 0xdd226365u); M(16, 0xd0ec9bbc245b7007UL) ]
        [ Gpr(0, 0x9466d533u); M(16, 0xe4de3c390000ffffUL) ] ]
    check false "e1020091" inputs outputs

  /// <summary>
  /// A8.8.230 SWPB: swpb r0, r1, [r2]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.230 SWPB``() =
    let inputs =
      [ [ Gpr(0, 0x63a86bf4u)
          Gpr(1, 0xe545e4e5u)
          Gpr(2, 0x20000810u)
          M(0, 0xfa217c750309031bUL)
          M(8, 0x26484fed15a3c03fUL)
          M(16, 0xa444812a9dff56aaUL)
          M(24, 0x2028bc53ca8961f2UL)
          M(32, 0xdeb21255aef2c408UL)
          M(40, 0xd3187f8e16222c53UL)
          M(48, 0x550aca19b8e9c5c0UL)
          M(56, 0x77b5e2ea19095d25UL) ]
        [ Gpr(0, 0x63b61ce4u)
          Gpr(1, 0x78df086eu)
          Gpr(2, 0x20000810u)
          M(0, 0x76e1e4a573521895UL)
          M(8, 0x7c8c2fdcd327a127UL)
          M(16, 0x6d9424cd86942455UL)
          M(24, 0xd123248f9abd78bfUL)
          M(32, 0x02a3e776240d484eUL)
          M(40, 0xed94ad677dc923cbUL)
          M(48, 0x122cf149d4e3a889UL)
          M(56, 0x4b14e7b39fa3e1fdUL) ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x20000810u)
          M(0, 0xebc0f46d2223605cUL)
          M(8, 0x940cef9b5673bd2bUL)
          M(16, 0x4c65afc71ffdd90aUL)
          M(24, 0x164a8a587396fa89UL)
          M(32, 0x06ee63852e9041f6UL)
          M(40, 0x61b5d21f46656bbeUL)
          M(48, 0xd0785727234b364cUL)
          M(56, 0xdaabcf320eb8f337UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x000000aau); M(16, 0xa444812a9dff56e5UL) ]
        [ Gpr(0, 0x00000055u); M(16, 0x6d9424cd8694246eUL) ]
        [ Gpr(0, 0x0000000au); M(16, 0x4c65afc71ffdd900UL) ] ]
    check false "e1420091" inputs outputs

  /// <summary>
  /// A8.8.231 SXTAB: sxtab r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.231 SXTAB``() =
    let inputs =
      [ [ Gpr(0, 0x3cd0e642u); Gpr(1, 0x51573fd1u); Gpr(2, 0x945c229cu) ]
        [ Gpr(0, 0x88aa534du); Gpr(1, 0xc8cc1122u); Gpr(2, 0xbb39a395u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x51573f6du) ]
        [ Gpr(0, 0xc8cc10b7u) ]
        [ Gpr(0, 0x7fff8000u) ] ]
    check false "e6a10072" inputs outputs

  /// <summary>
  /// A8.8.232 SXTAB16: sxtab16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.232 SXTAB16``() =
    let inputs =
      [ [ Gpr(0, 0x226310fbu); Gpr(1, 0x2e3284b0u); Gpr(2, 0xfcd71e2fu) ]
        [ Gpr(0, 0x4f4b89a4u); Gpr(1, 0x22e1c60eu); Gpr(2, 0x66066e24u) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x80007fffu); Gpr(2, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0x2e0984dfu) ]
        [ Gpr(0, 0x22e7c632u) ]
        [ Gpr(0, 0x80008002u) ] ]
    check false "e6810072" inputs outputs

  /// <summary>
  /// A8.8.233 SXTAH: sxtah r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.233 SXTAH``() =
    let inputs =
      [ [ Gpr(0, 0x883f85a0u); Gpr(1, 0xdc70d6aau); Gpr(2, 0xfbf4bebeu) ]
        [ Gpr(0, 0xf0ddfd6cu); Gpr(1, 0xc21d8e79u); Gpr(2, 0x26c8c4d0u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xdc709568u) ]
        [ Gpr(0, 0xc21d5349u) ]
        [ Gpr(0, 0x7fff8000u) ] ]
    check false "e6b10072" inputs outputs

  /// <summary>
  /// A8.8.234 SXTB: sxtb r0, r1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.234 SXTB``() =
    let inputs =
      [ [ Gpr(0, 0x59c35db0u); Gpr(1, 0xd3fa08cdu) ]
        [ Gpr(0, 0xcc25ec2du); Gpr(1, 0x1323282au) ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xffffffcdu) ]
        [ Gpr(0, 0x0000002au) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e6af0071" inputs outputs

  /// <summary>
  /// A8.8.235 SXTB16: sxtb16 r0, r1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.235 SXTB16``() =
    let inputs =
      [ [ Gpr(0, 0xc297f29au); Gpr(1, 0xcbaa2d71u) ]
        [ Gpr(0, 0x028ac0ccu); Gpr(1, 0xa4c096f8u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xffaa0071u) ]
        [ Gpr(0, 0xffc0fff8u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e68f0071" inputs outputs

  /// <summary>
  /// A8.8.236 SXTH: sxth r0, r1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.236 SXTH``() =
    let inputs =
      [ [ Gpr(0, 0x1983dae6u); Gpr(1, 0x482904f1u) ]
        [ Gpr(0, 0x5f29e24eu); Gpr(1, 0x8ad378e4u) ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x000004f1u) ]
        [ Gpr(0, 0x000078e4u) ]
        [ Gpr(0, 0xffff8000u) ] ]
    check false "e6bf0071" inputs outputs

  /// <summary>
  /// A8.8.237 TBB: tbb [r1, r2]. This checks that it goes to PC plus twice the
  /// byte at Rn + Rm, here 0x10. It is not a value test because it branches,
  /// and a run inside one instruction cannot follow it to what QEMU would show.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.237 TBB``() =
    let w = uint32 Window
    let cells = [ Gpr(1, w + 8u); Gpr(2, 3u); M(8, 0x10000000UL) ]
    let run = runWith true "e8d1f002" cells []
    Assert.AreEqual(Some(CodeAddr + 0x24UL), run.Target)

  /// <summary>
  /// A8.8.237 TBH: tbh [r1, r2, lsl #1]. This checks that it goes to PC plus
  /// twice the halfword at Rn + Rm * 2, here 0x30. It is not a value test
  /// because it branches, and a run inside one instruction cannot follow it to
  /// what QEMU would show.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.237 TBH``() =
    let w = uint32 Window
    let cells = [ Gpr(1, w + 8u); Gpr(2, 1u); M(8, 0x300000UL) ]
    let run = runWith true "e8d1f012" cells []
    Assert.AreEqual(Some(CodeAddr + 0x64UL), run.Target)

  /// <summary>
  /// A8.8.238 TEQ: teq r1, #0x0. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.238 TEQ``() =
    let inputs =
      [ [ Gpr(1, 0xa3484b20u); Cell.CPSR 0x20000010u ]
        [ Gpr(1, 0x55812e8bu); Cell.CPSR 0x900a0010u ]
        [ Gpr(1, 0x0000ffffu); Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Cell.CPSR 0xa0000010u ]
        [ Cell.CPSR 0x100a0010u ]
        [ Cell.CPSR 0x08050010u ] ]
    check false "e3310000" inputs outputs

  /// <summary>
  /// A8.8.241 TST: tst r1, r2. The outputs are what QEMU left after running it
  /// on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.241 TST``() =
    let inputs =
      [ [ Gpr(1, 0x5309626eu); Gpr(2, 0xa7fc9211u); Cell.CPSR 0x20000010u ]
        [ Gpr(1, 0x93b9198fu); Gpr(2, 0x11096717u); Cell.CPSR 0x900a0010u ]
        [ Gpr(1, 0x0000ffffu); Gpr(2, 0x00008000u); Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Cell.CPSR 0x20000010u ]
        [ Cell.CPSR 0x100a0010u ]
        [ Cell.CPSR 0x08050010u ] ]
    check false "e1110002" inputs outputs

  /// <summary>
  /// A8.8.244 UADD16: uadd16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.244 UADD16``() =
    let inputs =
      [ [ Gpr(0, 0x57a7c716u)
          Gpr(1, 0x94dddf74u)
          Gpr(2, 0xc8850e87u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x5b170891u)
          Gpr(1, 0x49d1b136u)
          Gpr(2, 0x1512ae13u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x5d62edfbu); Cell.CPSR 0x200c0010u ]
        [ Gpr(0, 0x5ee35f49u); Cell.CPSR 0x90030010u ]
        [ Gpr(0, 0x80007fffu); Cell.CPSR 0x48000010u ] ]
    check false "e6510f12" inputs outputs

  /// <summary>
  /// A8.8.245 UADD8: uadd8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.245 UADD8``() =
    let inputs =
      [ [ Gpr(0, 0x546c144du)
          Gpr(1, 0x599ebbf0u)
          Gpr(2, 0x90c3de1fu)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x0b7701a8u)
          Gpr(1, 0x0fe518b6u)
          Gpr(2, 0xdf7d791du)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x7fff8000u)
          Gpr(2, 0x00000000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xe961990fu); Cell.CPSR 0x20070010u ]
        [ Gpr(0, 0xee6291d3u); Cell.CPSR 0x90040010u ]
        [ Gpr(0, 0x7fff8000u); Cell.CPSR 0x48000010u ] ]
    check false "e6510f92" inputs outputs

  /// <summary>
  /// A8.8.246 UASX: uasx r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.246 UASX``() =
    let inputs =
      [ [ Gpr(0, 0x88d061f7u)
          Gpr(1, 0x8260ac82u)
          Gpr(2, 0xca0265ceu)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x0f90fccfu)
          Gpr(1, 0x030d0eebu)
          Gpr(2, 0x676a6f9au)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xe82ee280u); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x72a7a781u); Cell.CPSR 0x90000010u ]
        [ Gpr(0, 0x80000001u); Cell.CPSR 0x48030010u ] ]
    check false "e6510f32" inputs outputs

  /// <summary>
  /// A8.8.247 UBFX: ubfx r0, r1, #0x3, #0x5. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.247 UBFX``() =
    let inputs =
      [ [ Gpr(0, 0xdd557924u); Gpr(1, 0x38f5c451u) ]
        [ Gpr(0, 0x0cb7961cu); Gpr(1, 0x76c43496u) ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x0000000au) ]
        [ Gpr(0, 0x00000012u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e7e401d1" inputs outputs

  /// <summary>
  /// A8.8.248 UDF: udf #0x1204. This checks that it takes the Undefined
  /// Instruction exception. It is not a value test because it takes an
  /// exception, which a user-mode run cannot return from.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.248 UDF``() =
    let run = runWith false "e7f120f4" [ Cell.CPSR 0x10u ] []
    Assert.AreEqual(Some SideEffect.UndefinedInstruction, run.Effect)

  /// <summary>
  /// A8.8.249 UDIV: udiv r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.249 UDIV``() =
    let inputs =
      [ [ Gpr(0, 0x55b70c20u); Gpr(1, 0xf2b03f3cu); Gpr(2, 0xd89c261bu) ]
        [ Gpr(0, 0xe8d8e115u); Gpr(1, 0x7a734270u); Gpr(2, 0x4fae4587u) ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u); Gpr(2, 0x7fff8000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e730f211" inputs outputs

  /// <summary>
  /// A8.8.250 UHADD16: uhadd16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.250 UHADD16``() =
    let inputs =
      [ [ Gpr(0, 0x4814e457u); Gpr(1, 0x469f3b16u); Gpr(2, 0x578f38d2u) ]
        [ Gpr(0, 0x526c61c7u); Gpr(1, 0x6bd760c8u); Gpr(2, 0xb246317du) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x80007fffu); Gpr(2, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0x4f1739f4u) ]
        [ Gpr(0, 0x8f0e4922u) ]
        [ Gpr(0, 0x40004001u) ] ]
    check false "e6710f12" inputs outputs

  /// <summary>
  /// A8.8.251 UHADD8: uhadd8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.251 UHADD8``() =
    let inputs =
      [ [ Gpr(0, 0x19b4313du); Gpr(1, 0x6a46c515u); Gpr(2, 0x6969a2bfu) ]
        [ Gpr(0, 0xdb8d64f1u); Gpr(1, 0x1d3e2768u); Gpr(2, 0xf48bc355u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x6957b36au) ]
        [ Gpr(0, 0x8864755eu) ]
        [ Gpr(0, 0x40003f7fu) ] ]
    check false "e6710f92" inputs outputs

  /// <summary>
  /// A8.8.252 UHASX: uhasx r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.252 UHASX``() =
    let inputs =
      [ [ Gpr(0, 0xf2dbd45au); Gpr(1, 0xda407e57u); Gpr(2, 0x360850b5u) ]
        [ Gpr(0, 0x7d070062u); Gpr(1, 0x947e603bu); Gpr(2, 0x09239876u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x957a2427u) ]
        [ Gpr(0, 0x967a2b8cu) ]
        [ Gpr(0, 0x3fff4000u) ] ]
    check false "e6710f32" inputs outputs

  /// <summary>
  /// A8.8.253 UHSAX: uhsax r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.253 UHSAX``() =
    let inputs =
      [ [ Gpr(0, 0x2de2ae3eu); Gpr(1, 0xa40a6b75u); Gpr(2, 0xc3231718u) ]
        [ Gpr(0, 0x63b4d0edu); Gpr(1, 0x291640f8u); Gpr(2, 0x47fe356au) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x4679974cu) ]
        [ Gpr(0, 0xf9d6447bu) ]
        [ Gpr(0, 0x3fff4000u) ] ]
    check false "e6710f52" inputs outputs

  /// <summary>
  /// A8.8.254 UHSUB16: uhsub16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.254 UHSUB16``() =
    let inputs =
      [ [ Gpr(0, 0xf4b5c734u); Gpr(1, 0x83401106u); Gpr(2, 0x90024214u) ]
        [ Gpr(0, 0x095496cfu); Gpr(1, 0x4a7bca4fu); Gpr(2, 0x8753b553u) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x80007fffu); Gpr(2, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0xf99fe779u) ]
        [ Gpr(0, 0xe1940a7eu) ]
        [ Gpr(0, 0x40003ffeu) ] ]
    check false "e6710f72" inputs outputs

  /// <summary>
  /// A8.8.255 UHSUB8: uhsub8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.255 UHSUB8``() =
    let inputs =
      [ [ Gpr(0, 0x17a456eeu); Gpr(1, 0x8b3dadd8u); Gpr(2, 0x2d748789u) ]
        [ Gpr(0, 0x9fa3c6dau); Gpr(1, 0x80f8d3c4u); Gpr(2, 0x0aa7c88eu) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x2fe41327u) ]
        [ Gpr(0, 0x3b28051bu) ]
        [ Gpr(0, 0xc000c080u) ] ]
    check false "e6710ff2" inputs outputs

  /// <summary>
  /// A8.8.256 UMAAL: umaal r0, r1, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.256 UMAAL``() =
    let inputs =
      [ [ Gpr(0, 0x6acb38a0u); Gpr(1, 0xd0f98a2eu); Gpr(2, 0xf9a0a853u) ]
        [ Gpr(0, 0xe96aa7c8u); Gpr(1, 0x4460ebcbu); Gpr(2, 0x3223904du) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xda1abfb8u); Gpr(1, 0xcbc5dcc5u) ]
        [ Gpr(0, 0x2655afa2u); Gpr(1, 0x0d646ddau) ]
        [ Gpr(0, 0x80000000u); Gpr(1, 0x00000000u) ] ]
    check false "e0410291" inputs outputs

  /// <summary>
  /// A8.8.257 UMLAL: umlal r0, r1, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.257 UMLAL``() =
    let inputs =
      [ [ Gpr(0, 0x49d5921au); Gpr(1, 0x214caf5fu); Gpr(2, 0x447ae81du) ]
        [ Gpr(0, 0xb7301873u); Gpr(1, 0x1ff67ea1u); Gpr(2, 0x2cba3d69u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x5db987ddu); Gpr(1, 0x2a350ab1u) ]
        [ Gpr(0, 0x3c70657cu); Gpr(1, 0x258c1d28u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u) ] ]
    check false "e0a10291" inputs outputs

  /// <summary>
  /// A8.8.258 UMULL: umull r0, r1, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.258 UMULL``() =
    let inputs =
      [ [ Gpr(0, 0x7179f9a0u); Gpr(1, 0x582d39ccu); Gpr(2, 0x78b13401u) ]
        [ Gpr(0, 0x369efe58u); Gpr(1, 0xca6fcc0du); Gpr(2, 0x139880fau) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x1df6a9ccu); Gpr(1, 0x29923c46u) ]
        [ Gpr(0, 0xb5ebc4b2u); Gpr(1, 0x0f7ee483u) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x00000000u) ] ]
    check false "e0810291" inputs outputs

  /// <summary>
  /// A8.8.259 UQADD16: uqadd16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.259 UQADD16``() =
    let inputs =
      [ [ Gpr(0, 0x86536460u); Gpr(1, 0x1ab4c76cu); Gpr(2, 0x226b0bc1u) ]
        [ Gpr(0, 0x4b6bfde0u); Gpr(1, 0x3448c38au); Gpr(2, 0xed22f60du) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x80007fffu); Gpr(2, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0x3d1fd32du) ]
        [ Gpr(0, 0xffffffffu) ]
        [ Gpr(0, 0x80008002u) ] ]
    check false "e6610f12" inputs outputs

  /// <summary>
  /// A8.8.260 UQADD8: uqadd8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.260 UQADD8``() =
    let inputs =
      [ [ Gpr(0, 0xc0379efeu); Gpr(1, 0x5d43f187u); Gpr(2, 0x8b0f297eu) ]
        [ Gpr(0, 0x8f7719ffu); Gpr(1, 0xd3809f0cu); Gpr(2, 0xd2da2177u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0xe852ffffu) ]
        [ Gpr(0, 0xffffc083u) ]
        [ Gpr(0, 0x80007fffu) ] ]
    check false "e6610f92" inputs outputs

  /// <summary>
  /// A8.8.261 UQASX: uqasx r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.261 UQASX``() =
    let inputs =
      [ [ Gpr(0, 0x8880e1e1u); Gpr(1, 0x93341aebu); Gpr(2, 0x5e480292u) ]
        [ Gpr(0, 0x0b57b39fu); Gpr(1, 0xd5288c8fu); Gpr(2, 0x1cf2a7dbu) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x95c60000u) ]
        [ Gpr(0, 0xffff6f9du) ]
        [ Gpr(0, 0x7fff8000u) ] ]
    check false "e6610f32" inputs outputs

  /// <summary>
  /// A8.8.262 UQSAX: uqsax r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.262 UQSAX``() =
    let inputs =
      [ [ Gpr(0, 0x8d8c6e05u); Gpr(1, 0xcaf6211fu); Gpr(2, 0xdfaaa154u) ]
        [ Gpr(0, 0x6ade2150u); Gpr(1, 0xd3d55345u); Gpr(2, 0xf312b434u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x29a2ffffu) ]
        [ Gpr(0, 0x1fa1ffffu) ]
        [ Gpr(0, 0x7fff8000u) ] ]
    check false "e6610f52" inputs outputs

  /// <summary>
  /// A8.8.263 UQSUB16: uqsub16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.263 UQSUB16``() =
    let inputs =
      [ [ Gpr(0, 0x5d375db1u); Gpr(1, 0x9a852d14u); Gpr(2, 0xfc791db2u) ]
        [ Gpr(0, 0x094e41c2u); Gpr(1, 0xd6f1e6fdu); Gpr(2, 0xe6cde1a6u) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x80007fffu); Gpr(2, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000f62u) ]
        [ Gpr(0, 0x00000557u) ]
        [ Gpr(0, 0x80007ffcu) ] ]
    check false "e6610f72" inputs outputs

  /// <summary>
  /// A8.8.264 UQSUB8: uqsub8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.264 UQSUB8``() =
    let inputs =
      [ [ Gpr(0, 0xe99e5253u); Gpr(1, 0x0fc81c85u); Gpr(2, 0xdb3e3308u) ]
        [ Gpr(0, 0x1abd43b8u); Gpr(1, 0x52768212u); Gpr(2, 0xa0a4479au) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x008a007du) ]
        [ Gpr(0, 0x00003b00u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e6610ff2" inputs outputs

  /// <summary>
  /// A8.8.265 USAD8: usad8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.265 USAD8``() =
    let inputs =
      [ [ Gpr(0, 0x4dbfa8b0u); Gpr(1, 0xae101b0fu); Gpr(2, 0xf9b12514u) ]
        [ Gpr(0, 0x280118dcu); Gpr(1, 0xa4eeaa5au); Gpr(2, 0xe53946a0u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x000000fbu) ]
        [ Gpr(0, 0x000001a0u) ]
        [ Gpr(0, 0x000001feu) ] ]
    check false "e780f211" inputs outputs

  /// <summary>
  /// A8.8.266 USADA8: usada8 r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.266 USADA8``() =
    let inputs =
      [ [ Gpr(0, 0xb88f9b1du)
          Gpr(1, 0x8a08dea2u)
          Gpr(2, 0xdb56130au)
          Gpr(3, 0x065716c5u) ]
        [ Gpr(0, 0xaf3396aau)
          Gpr(1, 0x4d87dd37u)
          Gpr(2, 0x7b4be4ddu)
          Gpr(3, 0xf9ce750du) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0x065718c7u) ]
        [ Gpr(0, 0xf9ce7624u) ]
        [ Gpr(0, 0x00000201u) ] ]
    check false "e7803211" inputs outputs

  /// <summary>
  /// A8.8.267 USAT: usat r0, #0x3, r1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.267 USAT``() =
    let inputs =
      [ [ Gpr(0, 0xff225d82u); Gpr(1, 0x2e71154cu); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xbad24a42u); Gpr(1, 0x55b5136cu); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u); Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x00000007u); Cell.CPSR 0x28000010u ]
        [ Gpr(0, 0x00000007u); Cell.CPSR 0x980a0010u ]
        [ Gpr(0, 0x00000007u); Cell.CPSR 0x48050010u ] ]
    check false "e6e30011" inputs outputs

  /// <summary>
  /// A8.8.268 USAT16: usat16 r0, #0x3, r1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.268 USAT16``() =
    let inputs =
      [ [ Gpr(0, 0xd6912eb0u); Gpr(1, 0x57e1de5au); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x26641ae8u); Gpr(1, 0x1792315eu); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x00070000u); Cell.CPSR 0x28000010u ]
        [ Gpr(0, 0x00070007u); Cell.CPSR 0x980a0010u ]
        [ Gpr(0, 0x00000000u); Cell.CPSR 0x48050010u ] ]
    check false "e6e30f31" inputs outputs

  /// <summary>
  /// A8.8.269 USAX: usax r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.269 USAX``() =
    let inputs =
      [ [ Gpr(0, 0xd5d26d44u)
          Gpr(1, 0x7990403au)
          Gpr(2, 0x254053a3u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x49b4885cu)
          Gpr(1, 0xa65fae60u)
          Gpr(2, 0x71067a8au)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x25ed657au); Cell.CPSR 0x200c0010u ]
        [ Gpr(0, 0x2bd51f66u); Cell.CPSR 0x900f0010u ]
        [ Gpr(0, 0x8000ffffu); Cell.CPSR 0x48000010u ] ]
    check false "e6510f52" inputs outputs

  /// <summary>
  /// A8.8.270 USUB16: usub16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.270 USUB16``() =
    let inputs =
      [ [ Gpr(0, 0x59ba4996u)
          Gpr(1, 0x5d094aa4u)
          Gpr(2, 0x72ea34d8u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x072827dbu)
          Gpr(1, 0xafffcb8bu)
          Gpr(2, 0x0c3f37b0u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xea1f15ccu); Cell.CPSR 0x20030010u ]
        [ Gpr(0, 0xa3c093dbu); Cell.CPSR 0x900f0010u ]
        [ Gpr(0, 0x80008001u); Cell.CPSR 0x48000010u ] ]
    check false "e6510f72" inputs outputs

  /// <summary>
  /// A8.8.271 USUB8: usub8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.271 USUB8``() =
    let inputs =
      [ [ Gpr(0, 0x3403ed21u)
          Gpr(1, 0xef6f22e1u)
          Gpr(2, 0x1910fb96u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xda568efau)
          Gpr(1, 0x6f7a3ea2u)
          Gpr(2, 0xb03ede03u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x7fff8000u)
          Gpr(2, 0x00000000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xd65f274bu); Cell.CPSR 0x200d0010u ]
        [ Gpr(0, 0xbf3c609fu); Cell.CPSR 0x90050010u ]
        [ Gpr(0, 0x7fff8000u); Cell.CPSR 0x480f0010u ] ]
    check false "e6510ff2" inputs outputs

  /// <summary>
  /// A8.8.272 UXTAB: uxtab r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.272 UXTAB``() =
    let inputs =
      [ [ Gpr(0, 0x13341b72u); Gpr(1, 0xfc77a1f0u); Gpr(2, 0x602664dbu) ]
        [ Gpr(0, 0x00a7a90au); Gpr(1, 0x53cca7a7u); Gpr(2, 0x9d862cadu) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xfc77a2cbu) ]
        [ Gpr(0, 0x53cca854u) ]
        [ Gpr(0, 0x7fff8000u) ] ]
    check false "e6e10072" inputs outputs

  /// <summary>
  /// A8.8.273 UXTAB16: uxtab16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.273 UXTAB16``() =
    let inputs =
      [ [ Gpr(0, 0x9cb1d82fu); Gpr(1, 0x946a83dbu); Gpr(2, 0x28594f20u) ]
        [ Gpr(0, 0xd6c717e0u); Gpr(1, 0x44f1197du); Gpr(2, 0x3fa3b295u) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x80007fffu); Gpr(2, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0x94c383fbu) ]
        [ Gpr(0, 0x45941a12u) ]
        [ Gpr(0, 0x80008002u) ] ]
    check false "e6c10072" inputs outputs

  /// <summary>
  /// A8.8.274 UXTAH: uxtah r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.274 UXTAH``() =
    let inputs =
      [ [ Gpr(0, 0x44a54a97u); Gpr(1, 0x86b10abau); Gpr(2, 0x1b81a0a5u) ]
        [ Gpr(0, 0x5309c972u); Gpr(1, 0xc44157ddu); Gpr(2, 0x27674f64u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x86b1ab5fu) ]
        [ Gpr(0, 0xc441a741u) ]
        [ Gpr(0, 0x7fff8000u) ] ]
    check false "e6f10072" inputs outputs

  /// <summary>
  /// A8.8.275 UXTB: uxtb r0, r1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.275 UXTB``() =
    let inputs =
      [ [ Gpr(0, 0x799fe8bau); Gpr(1, 0x270a2230u) ]
        [ Gpr(0, 0x02492aa5u); Gpr(1, 0x9d410817u) ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000030u) ]
        [ Gpr(0, 0x00000017u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e6ef0071" inputs outputs

  /// <summary>
  /// A8.8.276 UXTB16: uxtb16 r0, r1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.276 UXTB16``() =
    let inputs =
      [ [ Gpr(0, 0x9961713cu); Gpr(1, 0xcc5c0dd2u) ]
        [ Gpr(0, 0xc341aac9u); Gpr(1, 0xda697c90u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x005c00d2u) ]
        [ Gpr(0, 0x00690090u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e6cf0071" inputs outputs

  /// <summary>
  /// A8.8.277 UXTH: uxth r0, r1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.277 UXTH``() =
    let inputs =
      [ [ Gpr(0, 0xc6d59ab8u); Gpr(1, 0x3e999ac8u) ]
        [ Gpr(0, 0x5071f0ffu); Gpr(1, 0x072ccf15u) ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x00009ac8u) ]
        [ Gpr(0, 0x0000cf15u) ]
        [ Gpr(0, 0x00008000u) ] ]
    check false "e6ff0071" inputs outputs

  /// <summary>
  /// A8.8.278 VABA: vaba.s32 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.278 VABA``() =
    let inputs =
      [ [ D(0, 0xf7287e15921ac7e9UL)
          D(1, 0x7e8070ebe13f7785UL)
          D(2, 0x333b9560c8011f90UL)
          D(3, 0x87db9401e034b5c5UL)
          D(4, 0xf003dd3a70840f79UL)
          D(5, 0xed5171538e3f0a17UL) ]
        [ D(0, 0xc803a0935d406519UL)
          D(1, 0x7d7d773af1fff0a6UL)
          D(2, 0x356a85abd3fcb6ecUL)
          D(3, 0x53fd1b9bf3f6a157UL)
          D(4, 0xe99afb5a18167ed6UL)
          D(5, 0xee29fbbb2cf87789UL) ]
        [ D(0, 0x8001800180018001UL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0xffffffffffffffffUL)
          D(3, 0x7f80ff00807fffffUL)
          D(4, 0x7f80ff00807fffffUL)
          D(5, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x3a60363b3a9db7d2UL); D(1, 0xe3f64e3d33352333UL) ]
        [ D(0, 0x13d32ae4a15a2d03UL); D(1, 0xe350971a2b01c6d8UL) ]
        [ D(0, 0xff827f02ff818001UL); D(1, 0x007f00fe7f7fffffUL) ] ]
    check false "f2220754" inputs outputs

  /// <summary>
  /// A8.8.278 VABAL: vabal.s8 q0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.278 VABAL``() =
    let inputs =
      [ [ D(0, 0xc301a6c80452798dUL)
          D(1, 0xbb89ba4ba96fc071UL)
          D(2, 0x28149c1e0137ef2bUL) ]
        [ D(0, 0x25253408a08cd0c6UL)
          D(1, 0x13733fb15755bb69UL)
          D(2, 0xc7e12afe06412a7eUL) ]
        [ D(0, 0x00ff00ff00ff00ffUL)
          D(1, 0x8000000000000000UL)
          D(2, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0xc359a700048179d3UL); D(1, 0xbbf6bad6a98dc09eUL) ]
        [ D(0, 0x2576341ca0fbd0dbUL); D(1, 0x13bf4043576abbb6UL) ]
        [ D(0, 0x00ff010000ff0100UL); D(1, 0x8080000100000001UL) ] ]
    check false "f2810502" inputs outputs

  /// <summary>
  /// A8.8.279 VABD: vabd.f32 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.279 VABD``() =
    let inputs =
      [ [ D(0, 0xc040000040200000UL)
          D(1, 0x3fe00000c0600000UL)
          D(2, 0x4140000040800000UL)
          D(3, 0xc010000040200000UL)
          D(4, 0x3fc0000044800000UL)
          D(5, 0xc0100000c0400000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x3e00000040c00000UL)
          D(1, 0xc0d0000040200000UL)
          D(2, 0xc01000003e800000UL)
          D(3, 0x40400000c0d00000UL)
          D(4, 0x448000003fc00000UL)
          D(5, 0x3d800000bf800000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x40400000ff800000UL)
          D(1, 0x3fc000007f800000UL)
          D(2, 0xc01000007f800000UL)
          D(3, 0x80000000c0100000UL)
          D(4, 0x404000003f000000UL)
          D(5, 0x3f0000007f800000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x41280000447f0000UL)
          D(1, 0x0000000040b00000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x448048003fa00000UL)
          D(1, 0x403c000040b00000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x40a800007f800000UL)
          D(1, 0x3f0000007f800000UL)
          Cell.FPSCR 0x00000000u ] ]
    check false "f3220d44" inputs outputs

  /// <summary>
  /// A8.8.279 VABDL: vabdl.s8 q0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.279 VABDL``() =
    let inputs =
      [ [ D(0, 0xf48fecfee65c4e60UL)
          D(1, 0x5fb8e46daa7dca43UL)
          D(2, 0xfc55079899f5661aUL) ]
        [ D(0, 0x58b36b12059477c4UL)
          D(1, 0x2363cd68fde2e6b2UL)
          D(2, 0x5108450000f15402UL) ]
        [ D(0, 0x0102030405060708UL)
          D(1, 0x8000000000000000UL)
          D(2, 0x0102030405060708UL) ] ]
    let outputs =
      [ [ D(0, 0x00110088009c0029UL); D(1, 0x0063009d002300d5UL) ]
        [ D(0, 0x0003000f006e0050UL); D(1, 0x002e005b00780068UL) ]
        [ D(0, 0x0005000600070008UL); D(1, 0x0081000200030004UL) ] ]
    check false "f2810702" inputs outputs

  /// <summary>
  /// A8.8.281 VABS: vabs.f32 s0, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.281 VABS``() =
    let inputs =
      [ [ D(0, 0xbf00000042c90000UL); D(1, 0x40c0000040800000UL) ]
        [ D(0, 0xc0d00000bec00000UL); D(1, 0xc240000041400000UL) ]
        [ D(0, 0xc0100000c0100000UL); D(1, 0x7f8000007f800000UL) ] ]
    let outputs =
      [ [ D(0, 0xbf00000040800000UL) ]
        [ D(0, 0xc0d0000041400000UL) ]
        [ D(0, 0xc01000007f800000UL) ] ]
    check false "eeb00ac1" inputs outputs

  /// <summary>
  /// A8.8.282 VACGE: vacge.f32 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.282 VACGE``() =
    let inputs =
      [ [ D(0, 0x4120000040c00000UL)
          D(1, 0xbf000000bf800000UL)
          D(2, 0xbf00000040200000UL)
          D(3, 0x40e80000c0d00000UL)
          D(4, 0xbf000000bf800000UL)
          D(5, 0x40000000bf000000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xc2400000c2400000UL)
          D(1, 0x408000003fe00000UL)
          D(2, 0xc0d00000c0600000UL)
          D(3, 0xc06000003fe00000UL)
          D(4, 0x40400000c0100000UL)
          D(5, 0x40400000bf800000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3f00000080000000UL)
          D(1, 0x3f000000c0100000UL)
          D(2, 0x7f80000040400000UL)
          D(3, 0xff800000ff800000UL)
          D(4, 0xff80000080000000UL)
          D(5, 0xc0100000c0100000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xffffffffffffffffUL)
          D(1, 0xffffffffffffffffUL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xffffffffffffffffUL)
          D(1, 0xffffffffffffffffUL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0xffffffffffffffffUL)
          D(1, 0xffffffffffffffffUL)
          Cell.FPSCR 0x00000000u ] ]
    check false "f3020e54" inputs outputs

  /// <summary>
  /// A8.8.282 VACGT: vacgt.f32 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.282 VACGT``() =
    let inputs =
      [ [ D(0, 0xc0d000003e000000UL)
          D(1, 0xc040000040800000UL)
          D(2, 0xc010000040c00000UL)
          D(3, 0x41200000c0100000UL)
          D(4, 0xbf800000bf800000UL)
          D(5, 0xbf8000003e000000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x3fe00000bec00000UL)
          D(1, 0x41200000c0d00000UL)
          D(2, 0xc060000040800000UL)
          D(3, 0xc040000044800000UL)
          D(4, 0x40c00000bf800000UL)
          D(5, 0xc0400000c2400000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x80000000ff800000UL)
          D(1, 0x7f80000040400000UL)
          D(2, 0x7f80000040400000UL)
          D(3, 0x80000000ff800000UL)
          D(4, 0x3fc000007f800000UL)
          D(5, 0xff80000000000000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xffffffffffffffffUL)
          D(1, 0xffffffffffffffffUL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x00000000ffffffffUL)
          D(1, 0x00000000ffffffffUL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0xffffffff00000000UL)
          D(1, 0x00000000ffffffffUL)
          Cell.FPSCR 0x00000000u ] ]
    check false "f3220e54" inputs outputs

  /// <summary>
  /// A8.8.282 VACLE: vacge.f32 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.282 VACLE``() =
    let inputs =
      [ [ D(0, 0x3d800000bec00000UL)
          D(1, 0x3d8000003f400000UL)
          D(2, 0x4000000040800000UL)
          D(3, 0x3fc0000040e80000UL)
          D(4, 0xc06000003e800000UL)
          D(5, 0x40c000003e800000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xc06000003e000000UL)
          D(1, 0x3fc00000c0d00000UL)
          D(2, 0x3e800000bf000000UL)
          D(3, 0x3f400000bf800000UL)
          D(4, 0xc040000040e80000UL)
          D(5, 0x4120000041400000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3f00000040400000UL)
          D(1, 0xc010000000000000UL)
          D(2, 0x3f0000003fc00000UL)
          D(3, 0x8000000040400000UL)
          D(4, 0x3f000000ff800000UL)
          D(5, 0x7f80000040400000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x00000000ffffffffUL)
          D(1, 0x00000000ffffffffUL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x0000000000000000UL)
          D(1, 0x0000000000000000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0xffffffff00000000UL)
          D(1, 0x00000000ffffffffUL)
          Cell.FPSCR 0x00000000u ] ]
    check false "f3020e54" inputs outputs

  /// <summary>
  /// A8.8.282 VACLT: vacgt.f32 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.282 VACLT``() =
    let inputs =
      [ [ D(0, 0x3fe0000041200000UL)
          D(1, 0x4080000042c90000UL)
          D(2, 0x3fc0000041200000UL)
          D(3, 0x40e8000041200000UL)
          D(4, 0x3d800000c0600000UL)
          D(5, 0xc010000040e80000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x402000003d800000UL)
          D(1, 0x40800000c0600000UL)
          D(2, 0xbf00000040200000UL)
          D(3, 0xc0400000c0100000UL)
          D(4, 0x3e00000041400000UL)
          D(5, 0x400000003d800000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0xc01000007f800000UL)
          D(1, 0x3fc0000040400000UL)
          D(2, 0x000000003fc00000UL)
          D(3, 0x4040000040400000UL)
          D(4, 0x7f80000040400000UL)
          D(5, 0x7f80000080000000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xffffffffffffffffUL)
          D(1, 0xffffffffffffffffUL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xffffffff00000000UL)
          D(1, 0xffffffffffffffffUL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x0000000000000000UL)
          D(1, 0x00000000ffffffffUL)
          Cell.FPSCR 0x00000000u ] ]
    check false "f3220e54" inputs outputs

  /// <summary>
  /// A8.8.283 VADD: vadd.f32 s0, s1, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.283 VADD``() =
    let inputs =
      [ [ D(0, 0x4480000041200000UL)
          D(1, 0x4080000041200000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x40c0000041200000UL)
          D(1, 0x4080000040200000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x40400000c0100000UL)
          D(1, 0xff8000007f800000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x4480000044814000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x40c0000041080000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x404000007f800000UL); Cell.FPSCR 0x00000000u ] ]
    check false "ee300a81" inputs outputs

  /// <summary>
  /// A8.8.285 VADDHN: vaddhn.i32 d0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.285 VADDHN``() =
    let inputs =
      [ [ D(0, 0x8fa5a98a00cca5f2UL)
          D(2, 0x09476fffbadd635fUL)
          D(3, 0xd7b37d35df6c535cUL)
          D(4, 0x6e455ca26a910a03UL)
          D(5, 0xb5e0523400db875cUL) ]
        [ D(0, 0xeed8ca8725835d7eUL)
          D(2, 0xf386217080c4c352UL)
          D(3, 0x929e54d8f82b3d2eUL)
          D(4, 0x01c5085cdb750b00UL)
          D(5, 0x0d1715a26274fd15UL) ]
        [ D(0, 0x00ff00ff00ff00ffUL)
          D(2, 0x0102030405060708UL)
          D(3, 0x7f80ff00807fffffUL)
          D(4, 0x7f80ff00807fffffUL)
          D(5, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0x8d93e047778c256eUL) ]
        [ D(0, 0x9fb55aa0f54b5c39UL) ]
        [ D(0, 0x807f817f80838586UL) ] ]
    check false "f2920404" inputs outputs

  /// <summary>
  /// A8.8.286 VADDL: vaddl.s32 q0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.286 VADDL``() =
    let inputs =
      [ [ D(0, 0x5e12011b0bc61bd1UL)
          D(1, 0xbfce12dc52a43b82UL)
          D(2, 0x013057ae7594e638UL) ]
        [ D(0, 0x0c70a9b18fd96809UL)
          D(1, 0x58db655d8ab7f14fUL)
          D(2, 0xf8b0bf69e1110b56UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x00ff00ff00ff00ffUL)
          D(2, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x00000000c83921baUL); D(1, 0xffffffffc0fe6a8aUL) ]
        [ D(0, 0xffffffff6bc8fca5UL); D(1, 0x00000000518c24c6UL) ]
        [ D(0, 0x0000000000ff00feUL); D(1, 0x0000000080ff00feUL) ] ]
    check false "f2a10002" inputs outputs

  /// <summary>
  /// A8.8.286 VADDW: vaddw.s8 q0, q0, d1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.286 VADDW``() =
    let inputs =
      [ [ D(0, 0x5edef6a08932c0e5UL); D(1, 0x00dbde28de5ea4a9UL) ]
        [ D(0, 0xf02caedb331a92a4UL); D(1, 0x9d6d550586cfcabcUL) ]
        [ D(0, 0x00ff00ff00ff00ffUL); D(1, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0x5ebcf6fe88d6c08eUL); D(1, 0x00dbde03de3ca4d1UL) ]
        [ D(0, 0xefb2aeaa32e49260UL); D(1, 0x9d0a55728724cac1UL) ]
        [ D(0, 0x00ff00fe00ff00feUL); D(1, 0x00ff00fe00ff00feUL) ] ]
    check false "f2800101" inputs outputs

  /// <summary>
  /// A8.8.287 VAND: vand q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.287 VAND``() =
    let inputs =
      [ [ D(0, 0x67b35580692dc62cUL)
          D(1, 0x149ef507ef2e2c93UL)
          D(2, 0xa5710873507213e7UL)
          D(3, 0xe1c20eacda4ad417UL)
          D(4, 0xfc709659ec661f57UL)
          D(5, 0x6382526b242b11c3UL) ]
        [ D(0, 0xc24ff5ee3726cc36UL)
          D(1, 0x5eca19cd149279c1UL)
          D(2, 0xc55bfdb249a8eb0eUL)
          D(3, 0x143701d21cee9474UL)
          D(4, 0x9e2d49ea374a2ad9UL)
          D(5, 0x90fc95eb23d2d85eUL) ]
        [ D(0, 0xffffffffffffffffUL)
          D(1, 0x7fffffffffffffffUL)
          D(2, 0x0102030405060708UL)
          D(3, 0x7f80ff00807fffffUL)
          D(4, 0x7fffffffffffffffUL)
          D(5, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0xa470005140621347UL); D(1, 0x61820228000a1003UL) ]
        [ D(0, 0x840949a201082a08UL); D(1, 0x103401c200c29054UL) ]
        [ D(0, 0x0102030405060708UL); D(1, 0x00800000007f00ffUL) ] ]
    check false "f2020154" inputs outputs

  /// <summary>
  /// A8.8.289 VBIC: vbic.i32 q0, #0x10. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.289 VBIC``() =
    let inputs =
      [ [ D(0, 0x6a79494a496a4921UL); D(1, 0x5ca0049476afc743UL) ]
        [ D(0, 0x982307198df69294UL); D(1, 0x9fcd8087ab29652dUL) ]
        [ D(0, 0x8000000000000000UL); D(1, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x6a79494a496a4921UL); D(1, 0x5ca0048476afc743UL) ]
        [ D(0, 0x982307098df69284UL); D(1, 0x9fcd8087ab29652dUL) ]
        [ D(0, 0x8000000000000000UL); D(1, 0x7fffffefffffffefUL) ] ]
    check false "f2810170" inputs outputs

  /// <summary>
  /// A8.8.291 VBIF: vbif q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.291 VBIF``() =
    let inputs =
      [ [ D(0, 0xd33c3f9168c310a4UL)
          D(1, 0x7567f58548138a12UL)
          D(2, 0x093a5f5dff6580fdUL)
          D(3, 0x70e6f50e69edc0ecUL)
          D(4, 0x0520ab3c7dc91528UL)
          D(5, 0x7663ad3a08e96d79UL) ]
        [ D(0, 0xd05120fbf86280dbUL)
          D(1, 0x776193105776c905UL)
          D(2, 0x72e18a6c5682c2d7UL)
          D(3, 0x5bed1bba2acac8b0UL)
          D(4, 0x15409f8b5d2beab3UL)
          D(5, 0xdf42d5ec1184ede5UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x8000000000000000UL)
          D(3, 0x00ff00ff00ff00ffUL)
          D(4, 0x8001800180018001UL)
          D(5, 0x0000000000000001UL) ] ]
    let outputs =
      [ [ D(0, 0x093a7f51eae590f5UL); D(1, 0x74e7f50469058894UL) ]
        [ D(0, 0x72e100ef5aa280d7UL); D(1, 0x57ed9b123b4ec915UL) ]
        [ D(0, 0x0000800080018001UL); D(1, 0x00ff00ff00ff00ffUL) ] ]
    check false "f3320154" inputs outputs

  /// <summary>
  /// A8.8.291 VBIT: vbit q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.291 VBIT``() =
    let inputs =
      [ [ D(0, 0x1640bc5a0551b073UL)
          D(1, 0x00f2033d83f15a79UL)
          D(2, 0xdfb3bc436311bacbUL)
          D(3, 0x88dbadda17fecf6eUL)
          D(4, 0x908713f483331574UL)
          D(5, 0x4e0090f8664e8e43UL) ]
        [ D(0, 0xaa2e3119f48f8c1dUL)
          D(1, 0xbaf63939937d2fd0UL)
          D(2, 0x6e71e2d1ecb87225UL)
          D(3, 0x8bfd06b4030751bbUL)
          D(4, 0xcafacf4a629fdebdUL)
          D(5, 0xea70f12427fd67b6UL) ]
        [ D(0, 0x8001800180018001UL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x00ff00ff00ff00ffUL)
          D(3, 0x0102030405060708UL)
          D(4, 0x7f80ff00807fffffUL)
          D(5, 0x7f80ff00807fffffUL) ] ]
    let outputs =
      [ [ D(0, 0x96c3bc4a0751b043UL); D(1, 0x08f283dd87ffde7aUL) ]
        [ D(0, 0x6a74f251f4985225UL); D(1, 0x9af6083d930549f2UL) ]
        [ D(0, 0x80810001007f00ffUL); D(1, 0x817f03ff7f860708UL) ] ]
    check false "f3220154" inputs outputs

  /// <summary>
  /// A8.8.291 VBSL: vbsl q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.291 VBSL``() =
    let inputs =
      [ [ D(0, 0x7980a23c9fa97998UL)
          D(1, 0x34285f19f2140a79UL)
          D(2, 0x306d8207f3c79a21UL)
          D(3, 0xb7bf89b070effcfaUL)
          D(4, 0x2e3e6e51944e2469UL)
          D(5, 0x45761623a27377faUL) ]
        [ D(0, 0xcca5fbdee34d371bUL)
          D(1, 0x230458c6e0c8aefbUL)
          D(2, 0xa3382ec15ca5d491UL)
          D(3, 0xb6b1ed9488063842UL)
          D(4, 0x3389d4872f5447e3UL)
          D(5, 0x8cb97f6a354ff27cUL) ]
        [ D(0, 0xffffffffffffffffUL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0xffffffffffffffffUL)
          D(3, 0x8000000000000000UL)
          D(4, 0x0102030405060708UL)
          D(5, 0x0102030405060708UL) ] ]
    let outputs =
      [ [ D(0, 0x363ece4593c71c61UL); D(1, 0x757e093270677dfaUL) ]
        [ D(0, 0xb3282ec14c1554f1UL); D(1, 0xaeb96fac95077846UL) ]
        [ D(0, 0xffffffffffffffffUL); D(1, 0x8000000000000000UL) ] ]
    check false "f3120154" inputs outputs

  /// <summary>
  /// A8.8.292 VCEQ: vceq.f32 d0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.292 VCEQ``() =
    let inputs =
      [ [ D(0, 0xbec000003d800000UL)
          D(1, 0x3f40000042c90000UL)
          D(2, 0x3f40000041400000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xc040000044800000UL)
          D(1, 0x4080000042c90000UL)
          D(2, 0x3d8000003f400000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3fc00000ff800000UL)
          D(1, 0x3fc000007f800000UL)
          D(2, 0x7f80000040400000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xffffffff00000000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x0000000000000000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x0000000000000000UL); Cell.FPSCR 0x00000000u ] ]
    check false "f2010e02" inputs outputs

  /// <summary>
  /// A8.8.294 VCGE: vcge.f32 d0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.294 VCGE``() =
    let inputs =
      [ [ D(0, 0x41400000c0d00000UL)
          D(1, 0xbf00000042c90000UL)
          D(2, 0xc040000040400000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xc24000003fe00000UL)
          D(1, 0x3e800000bf000000UL)
          D(2, 0x40e8000040000000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3f0000003f000000UL)
          D(1, 0x404000007f800000UL)
          D(2, 0x00000000c0100000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xffffffffffffffffUL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x0000000000000000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0xffffffffffffffffUL); Cell.FPSCR 0x00000000u ] ]
    check false "f3010e02" inputs outputs

  /// <summary>
  /// A8.8.296 VCGT: vcgt.f32 d0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.296 VCGT``() =
    let inputs =
      [ [ D(0, 0xc0100000c0100000UL)
          D(1, 0x40e800003e000000UL)
          D(2, 0x3e8000003f400000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xbf00000040e80000UL)
          D(1, 0x44800000c2400000UL)
          D(2, 0x4480000040800000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0xc01000007f800000UL)
          D(1, 0xff80000000000000UL)
          D(2, 0xff8000007f800000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xffffffff00000000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x0000000000000000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x0000000000000000UL); Cell.FPSCR 0x00000000u ] ]
    check false "f3210e02" inputs outputs

  /// <summary>
  /// A8.8.298 VCLE: vcle.f32 q0, q2, #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.298 VCLE``() =
    let inputs =
      [ [ D(0, 0xc0400000c0600000UL)
          D(1, 0x4000000042c90000UL)
          D(4, 0x42c900003fc00000UL)
          D(5, 0x4140000041400000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x4040000041400000UL)
          D(1, 0x44800000c0100000UL)
          D(4, 0x3d800000c0400000UL)
          D(5, 0xc0600000c0d00000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x80000000c0100000UL)
          D(1, 0xc0100000c0100000UL)
          D(4, 0x00000000c0100000UL)
          D(5, 0x8000000040400000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x0000000000000000UL)
          D(1, 0x0000000000000000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x00000000ffffffffUL)
          D(1, 0xffffffffffffffffUL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0xffffffffffffffffUL)
          D(1, 0xffffffff00000000UL)
          Cell.FPSCR 0x00000000u ] ]
    check false "f3b905c4" inputs outputs

  /// <summary>
  /// A8.8.300 VCLS: vcls.s32 q0, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.300 VCLS``() =
    let inputs =
      [ [ D(0, 0x61518dd9d0bddc5dUL)
          D(1, 0x546dcf189b0f90fbUL)
          D(4, 0x8a5155387b6b587bUL)
          D(5, 0x784de809cf17fca2UL) ]
        [ D(0, 0x4d18d56390dd4a05UL)
          D(1, 0x7dcfaba365499c09UL)
          D(4, 0xc19e18e20aa1f286UL)
          D(5, 0xf1ee666648267de5UL) ]
        [ D(0, 0x0000000000000001UL)
          D(1, 0x8001800180018001UL)
          D(4, 0x8001800180018001UL)
          D(5, 0x0102030405060708UL) ] ]
    let outputs =
      [ [ D(0, 0x0000000000000000UL); D(1, 0x0000000000000001UL) ]
        [ D(0, 0x0000000100000003UL); D(1, 0x0000000300000000UL) ]
        [ D(0, 0x0000000000000000UL); D(1, 0x0000000600000004UL) ] ]
    check false "f3b80444" inputs outputs

  /// <summary>
  /// A8.8.301 VCLT: vclt.f32 q0, q2, #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.301 VCLT``() =
    let inputs =
      [ [ D(0, 0x42c90000bec00000UL)
          D(1, 0xbf8000003fc00000UL)
          D(4, 0x3fe0000041400000UL)
          D(5, 0x3fe000003fc00000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x4000000040e80000UL)
          D(1, 0x404000003e000000UL)
          D(4, 0x4140000040000000UL)
          D(5, 0xbf0000003fc00000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x000000007f800000UL)
          D(1, 0xff8000003f000000UL)
          D(4, 0xff8000007f800000UL)
          D(5, 0x3fc0000040400000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x0000000000000000UL)
          D(1, 0x0000000000000000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x0000000000000000UL)
          D(1, 0xffffffff00000000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0xffffffff00000000UL)
          D(1, 0x0000000000000000UL)
          Cell.FPSCR 0x00000000u ] ]
    check false "f3b90644" inputs outputs

  /// <summary>
  /// A8.8.303 VCLZ: vclz.i32 q0, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.303 VCLZ``() =
    let inputs =
      [ [ D(0, 0x57c2e10c114fb5dbUL)
          D(1, 0x31f971a8d627aefcUL)
          D(4, 0x2c512e68aacf7a8eUL)
          D(5, 0x5f8da5338bbd9897UL) ]
        [ D(0, 0xef81da491f17bb65UL)
          D(1, 0x6b79a3ad3a412244UL)
          D(4, 0x786404bc6217c084UL)
          D(5, 0x667f7842800509c4UL) ]
        [ D(0, 0x7fffffffffffffffUL)
          D(1, 0x7fffffffffffffffUL)
          D(4, 0x0102030405060708UL)
          D(5, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0x0000000200000000UL); D(1, 0x0000000100000000UL) ]
        [ D(0, 0x0000000100000001UL); D(1, 0x0000000100000000UL) ]
        [ D(0, 0x0000000700000005UL); D(1, 0x0000000000000000UL) ] ]
    check false "f3b804c4" inputs outputs

  /// <summary>
  /// A8.8.304 VCMP: vcmp.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.304 VCMP``() =
    let inputs =
      [ [ D(0, 0xc0d000003fc00000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x40000000c0d00000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3f0000007f800000UL); Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ Cell.FPSCR 0x20000000u ]
        [ Cell.FPSCR 0x80000000u ]
        [ Cell.FPSCR 0x20000000u ] ]
    check false "eeb40a60" inputs outputs

  /// <summary>
  /// A8.8.304 VCMPE: vcmpe.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.304 VCMPE``() =
    let inputs =
      [ [ D(0, 0x414000003e000000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x40c0000040000000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7f80000080000000UL); Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ Cell.FPSCR 0x80000000u ]
        [ Cell.FPSCR 0x80000000u ]
        [ Cell.FPSCR 0x80000000u ] ]
    check false "eeb40ae0" inputs outputs

  /// <summary>
  /// A8.8.305 VCNT: vcnt.8 q0, q1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.305 VCNT``() =
    let inputs =
      [ [ D(0, 0x08ba6cf3031fb354UL)
          D(1, 0xf8193ccb3569f65dUL)
          D(2, 0xf9c243798e1a6eabUL)
          D(3, 0xe71d3f623c3ca742UL) ]
        [ D(0, 0xb1a7e452c6c3ed3eUL)
          D(1, 0x90447b8b8d4af6b1UL)
          D(2, 0x42932e290c7cbe7cUL)
          D(3, 0x5b7a554cc015d8feUL) ]
        [ D(0, 0x00ff00ff00ff00ffUL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x0102030405060708UL)
          D(3, 0xffffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x0603030504030505UL); D(1, 0x0604060304040502UL) ]
        [ D(0, 0x0204040302050605UL); D(1, 0x0505040302030407UL) ]
        [ D(0, 0x0101020102020301UL); D(1, 0x0808080808080808UL) ] ]
    check false "f3b00542" inputs outputs

  /// <summary>
  /// A8.8.306 VCVT: vcvt.f32.f64 s0, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.306 VCVT``() =
    let inputs =
      [ [ D(0, 0x4008000000000000UL)
          D(2, 0x4059200000000000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xc002000000000000UL)
          D(2, 0xbff0000000000000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x8000000000000000UL)
          D(2, 0x3ff8000000000000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x4008000042c90000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0xc0020000bf800000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x800000003fc00000UL); Cell.FPSCR 0x00000000u ] ]
    check false "eeb70bc2" inputs outputs

  /// <summary>
  /// A8.8.307 VCVTR: vcvtr.s32.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.307 VCVTR``() =
    let inputs =
      [ [ D(0, 0x3d80000040e80000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0xbf800000c0600000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x404000003f000000UL); Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x3d80000000000000UL); Cell.FPSCR 0x00000010u ]
        [ D(0, 0xbf800000ffffffffUL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x4040000000000003UL); Cell.FPSCR 0x00000000u ] ]
    check false "eebd0a60" inputs outputs

  /// <summary>
  /// A8.8.312 VCVTB: vcvtb.f32.f16 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.312 VCVTB``() =
    let inputs =
      [ [ D(0, 0x3a003a003e004400UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x4a004600b600c200UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x000042008000c080UL); Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x3a003a003f400000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x4a00460040c00000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x0000420040400000UL); Cell.FPSCR 0x00000000u ] ]
    check false "eeb20a60" inputs outputs

  /// <summary>
  /// A8.8.312 VCVTT: vcvtt.f32.f16 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.312 VCVTT``() =
    let inputs =
      [ [ D(0, 0x4a004740d2004600UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x40004a00c3003e00UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0xfc003e00c0803e00UL); Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x4a00474041400000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x40004a0040000000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0xfc003e00ff800000UL); Cell.FPSCR 0x00000000u ] ]
    check false "eeb20ae0" inputs outputs

  /// <summary>
  /// A8.8.313 VDIV: vdiv.f32 s0, s1, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.313 VDIV``() =
    let inputs =
      [ [ D(0, 0x3e0000003d800000UL)
          D(1, 0xc240000042c90000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xbf80000040200000UL)
          D(1, 0xbf800000c0600000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x404000003f000000UL)
          D(1, 0x3fc0000000000000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x3e0000003aa3065eUL); Cell.FPSCR 0x00000010u ]
        [ D(0, 0xbf8000003e924925UL); Cell.FPSCR 0x60000010u ]
        [ D(0, 0x404000007f800000UL); Cell.FPSCR 0x00000002u ] ]
    check false "ee800a81" inputs outputs

  /// <summary>
  /// A8.8.314 VDUP: vdup.8 d0, r1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.314 VDUP``() =
    let inputs =
      [ [ Gpr(1, 0x2447aff9u); D(0, 0x06865995f3c3933bUL) ]
        [ Gpr(1, 0x834cb9e5u); D(0, 0xc9bb5f2c7cdedb74UL) ]
        [ Gpr(1, 0x00008000u); D(0, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0xf9f9f9f9f9f9f9f9UL) ]
        [ D(0, 0xe5e5e5e5e5e5e5e5UL) ]
        [ D(0, 0x0000000000000000UL) ] ]
    check false "eec01b10" inputs outputs

  /// <summary>
  /// A8.8.316 VEOR: veor q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.316 VEOR``() =
    let inputs =
      [ [ D(0, 0x0267842d78c38535UL)
          D(1, 0xca321d5129e0208bUL)
          D(2, 0xaf44bffa1de8a818UL)
          D(3, 0x491f525966285a1fUL)
          D(4, 0xab577f3bad25a837UL)
          D(5, 0xaed3c74a515ba094UL) ]
        [ D(0, 0x31ee508c7090436eUL)
          D(1, 0xe1963a3ea98e88ceUL)
          D(2, 0x10882e5951e36f10UL)
          D(3, 0xb1e83987cd76c196UL)
          D(4, 0x8b5f3900d4946de2UL)
          D(5, 0x6492b8c8aafb7658UL) ]
        [ D(0, 0x0000000000000001UL)
          D(1, 0x0000000000000001UL)
          D(2, 0x7fffffffffffffffUL)
          D(3, 0x0102030405060708UL)
          D(4, 0x8000000000000000UL)
          D(5, 0xffffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x0413c0c1b0cd002fUL); D(1, 0xe7cc95133773fa8bUL) ]
        [ D(0, 0x9bd71759857702f2UL); D(1, 0xd57a814f678db7ceUL) ]
        [ D(0, 0xffffffffffffffffUL); D(1, 0xfefdfcfbfaf9f8f7UL) ] ]
    check false "f3020154" inputs outputs

  /// <summary>
  /// A8.8.317 VEXT: vext.8 q0, q0, q1, #0x1. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.317 VEXT``() =
    let inputs =
      [ [ D(0, 0x51da26db469e0ccbUL)
          D(1, 0x69e12900a46377eeUL)
          D(2, 0x944bb4acf895ac8cUL)
          D(3, 0x6df64de0db4c0d71UL) ]
        [ D(0, 0xe31c5dea357cdd5eUL)
          D(1, 0xcec45037fc797bb0UL)
          D(2, 0x2e7c7c60275dc8d1UL)
          D(3, 0xfd0e7eff8ba0e880UL) ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0x0102030405060708UL)
          D(2, 0x0000000000000001UL)
          D(3, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0xee51da26db469e0cUL); D(1, 0x8c69e12900a46377UL) ]
        [ D(0, 0xb0e31c5dea357cddUL); D(1, 0xd1cec45037fc797bUL) ]
        [ D(0, 0x0880000000000000UL); D(1, 0x0101020304050607UL) ] ]
    check false "f2b00142" inputs outputs

  /// <summary>
  /// A8.8.318 VFMA: vfma.f32 s0, s1, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.318 VFMA``() =
    let inputs =
      [ [ D(0, 0xbec000003d800000UL)
          D(1, 0x41400000bf000000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x414000003fe00000UL)
          D(1, 0x3fe0000041200000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7f80000080000000UL)
          D(1, 0xc01000003f000000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xbec000003e800000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x4140000042f38000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7f8000007f800000UL); Cell.FPSCR 0x00000000u ] ]
    check false "eea00a81" inputs outputs

  /// <summary>
  /// A8.8.318 VFMS: vfms.f32 s0, s1, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.318 VFMS``() =
    let inputs =
      [ [ D(0, 0xc0600000c2400000UL)
          D(1, 0x3fc0000044800000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x40c00000c0400000UL)
          D(1, 0xbec0000042c90000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3f00000080000000UL)
          D(1, 0x4040000000000000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xc0600000455d0000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x40c00000c4178000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3f00000080000000UL); Cell.FPSCR 0x00000000u ] ]
    check false "eea00ac1" inputs outputs

  /// <summary>
  /// A8.8.319 VFNMA: vfnma.f32 s0, s1, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.319 VFNMA``() =
    let inputs =
      [ [ D(0, 0xc060000040200000UL)
          D(1, 0x412000003fc00000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x3fc00000bf800000UL)
          D(1, 0xc06000003e800000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7f800000c0100000UL)
          D(1, 0x40400000c0100000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xc060000040300000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x3fc000003f200000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7f8000007f800000UL); Cell.FPSCR 0x00000000u ] ]
    check false "ee900ac1" inputs outputs

  /// <summary>
  /// A8.8.319 VFNMS: vfnms.f32 s0, s1, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.319 VFNMS``() =
    let inputs =
      [ [ D(0, 0x3d800000c0100000UL)
          D(1, 0xc040000040800000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x44800000c0600000UL)
          D(1, 0x412000003f400000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0xc0100000ff800000UL)
          D(1, 0x3fc0000080000000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x3d80000040200000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x448000004440e000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0xc01000007f800000UL); Cell.FPSCR 0x00000000u ] ]
    check false "ee900a81" inputs outputs

  /// <summary>
  /// A8.8.320 VHADD: vhadd.s8 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.320 VHADD``() =
    let inputs =
      [ [ D(0, 0xf3ff4fa143e2db51UL)
          D(1, 0xf2b07aea1bf4407eUL)
          D(2, 0xa4ddaec7fee0d4a0UL)
          D(3, 0x380cdef7584cc00cUL)
          D(4, 0x7f0a6471411284b9UL)
          D(5, 0xfac0a4fdf01203b5UL) ]
        [ D(0, 0xe201276e926fe205UL)
          D(1, 0xdc1049e3465edd74UL)
          D(2, 0x48cf306d367c3e6cUL)
          D(3, 0x9c65a4142ace0c5fUL)
          D(4, 0x843ed809c89aa457UL)
          D(5, 0xe6f0c44b5d7cbb5aUL) ]
        [ D(0, 0xffffffffffffffffUL)
          D(1, 0x7fffffffffffffffUL)
          D(2, 0x8001800180018001UL)
          D(3, 0x8000000000000000UL)
          D(4, 0x8000000000000000UL)
          D(5, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x11f3091c1ff9acacUL); D(1, 0x19e6c1fa242fe1e0UL) ]
        [ D(0, 0xe606043bff0bf161UL); D(1, 0xc12ab42f4325e35cUL) ]
        [ D(0, 0x8000c000c000c000UL); D(1, 0xffffffffffffffffUL) ] ]
    check false "f2020044" inputs outputs

  /// <summary>
  /// A8.8.320 VHSUB: vhsub.s8 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.320 VHSUB``() =
    let inputs =
      [ [ D(0, 0xc11ca04a92f75cc9UL)
          D(1, 0xcf55930657711301UL)
          D(2, 0xe461c2da322208d3UL)
          D(3, 0x4c189f5161cf3f18UL)
          D(4, 0x8307e27b4ba95d38UL)
          D(5, 0xd3628b5a2b5ce1f3UL) ]
        [ D(0, 0x6401ca788da8a261UL)
          D(1, 0x37b01f7fcf4d02beUL)
          D(2, 0xf57b7774a9fdfdedUL)
          D(3, 0xadb9412872bf3201UL)
          D(4, 0x31ef53bd1188a703UL)
          D(5, 0xbdfbaaa3ce926878UL) ]
        [ D(0, 0x0102030405060708UL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x8001800180018001UL)
          D(3, 0x8000000000000000UL)
          D(4, 0x8001800180018001UL)
          D(5, 0x0000000000000001UL) ] ]
    let outputs =
      [ [ D(0, 0x302df0aff33cd5cdUL); D(1, 0x3cdb0afb1bb92f12UL) ]
        [ D(0, 0xe246125bcc3a2bf5UL); D(1, 0xf8df4b425216e5c4UL) ]
        [ D(0, 0x0000000000000000UL); D(1, 0xc0000000000000ffUL) ] ]
    check false "f2020244" inputs outputs

  /// <summary>
  /// A8.8.321 VLD1: vld1.8 {d0}, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.321 VLD1``() =
    let inputs =
      [ [ Gpr(1, 0x20000810u)
          D(0, 0xf29182db8de23a75UL)
          M(0, 0x287e27533cfb21d3UL)
          M(8, 0x15647879dfaacfcbUL)
          M(16, 0x75275800b6ee1375UL)
          M(24, 0x7102829825835242UL)
          M(32, 0x332e01d7a68bf8d8UL)
          M(40, 0x5703018c9463b557UL)
          M(48, 0x4226bd0d5cd3a6ceUL)
          M(56, 0x491c46055ee775b3UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x74dd1bd73ee81118UL)
          M(0, 0x748e93cdbf765745UL)
          M(8, 0x316b0ee34490d886UL)
          M(16, 0x8f014e9a7568cce0UL)
          M(24, 0xfa6265a8447446efUL)
          M(32, 0x659ff9061663ff78UL)
          M(40, 0x83fed3264b30ec2dUL)
          M(48, 0x129d5799b498c290UL)
          M(56, 0x3a7e8b4a8aa7144aUL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x8000000000000000UL)
          M(0, 0x6c4a40ce047a8155UL)
          M(8, 0x633d12919f8789aaUL)
          M(16, 0xa6e75709701b7af4UL)
          M(24, 0x8cb707efa4c06271UL)
          M(32, 0x909107d037254f03UL)
          M(40, 0x197f5f7a6eb2f13cUL)
          M(48, 0xf284c1981234953dUL)
          M(56, 0x49132993f11bf5baUL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000810u); D(0, 0x75275800b6ee1375UL) ]
        [ Gpr(1, 0x20000810u); D(0, 0x8f014e9a7568cce0UL) ]
        [ Gpr(1, 0x20000810u); D(0, 0xa6e75709701b7af4UL) ] ]
    check false "f421070f" inputs outputs

  /// <summary>
  /// A8.8.324 VLD2: vld2.8 {d0, d1}, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.324 VLD2``() =
    let inputs =
      [ [ Gpr(1, 0x20000810u)
          D(0, 0x952db694e26a5165UL)
          D(1, 0xa3d5d12d7ee59ac3UL)
          M(0, 0x05192f28f65b12c6UL)
          M(8, 0x5febb41a6b4d06aaUL)
          M(16, 0x65c27fe6030fd3c4UL)
          M(24, 0x0c1b283a45fe3007UL)
          M(32, 0xc264f0b3dc0714dbUL)
          M(40, 0xfa879bff62a6d542UL)
          M(48, 0x78b164e6fe1a371dUL)
          M(56, 0xd4d3421effbb56e0UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0xaf870fb0fdd5dd6aUL)
          D(1, 0x297f07ffcef032e7UL)
          M(0, 0x11b0a1f290c7fb46UL)
          M(8, 0x701bf861270e3f66UL)
          M(16, 0xb979a1d118e6fa0bUL)
          M(24, 0xb84aa6e9514c7141UL)
          M(32, 0x3072c14cb5935e37UL)
          M(40, 0x97701b04a2c29196UL)
          M(48, 0xbd4dbd01778bc8daUL)
          M(56, 0x9b40a6d9a55b689dUL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x7f80ff00807fffffUL)
          D(1, 0xffffffffffffffffUL)
          M(0, 0xd4bdeb894bd54b81UL)
          M(8, 0x6e1b95962a4515d8UL)
          M(16, 0x9184f3ef56e26de5UL)
          M(24, 0x2a71a26b6b95b543UL)
          M(32, 0x01d7bb187684d85aUL)
          M(40, 0x488604ebe20acabbUL)
          M(48, 0x173be1bffa6dd90cUL)
          M(56, 0x6d887ca5cdc79ed5UL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000810u)
          D(0, 0x1b3afe07c2e60fc4UL)
          D(1, 0x0c284530657f03d3UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x4ae94c4179d1e60bUL)
          D(1, 0xb8a65171b9a118faUL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x716b954384efe2e5UL)
          D(1, 0x2aa26bb591f3566dUL) ] ]
    check false "f421080f" inputs outputs

  /// <summary>
  /// A8.8.327 VLD3: vld3.8 {d0, d1, d2}, [r1]. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.327 VLD3``() =
    let inputs =
      [ [ Gpr(1, 0x20000810u)
          D(0, 0xe48a21e57b7ca134UL)
          D(1, 0x6f4785549973c2a5UL)
          D(2, 0x0458bc630ebb3b1aUL)
          M(0, 0x97b46f597a4c0176UL)
          M(8, 0x9e123d89cb7fcf55UL)
          M(16, 0x1d018e07b3d22a6fUL)
          M(24, 0x18c515226a2e8bbeUL)
          M(32, 0xdf863ae95250a8f7UL)
          M(40, 0x055d7ee2cda592e8UL)
          M(48, 0x31097f037a35ac9dUL)
          M(56, 0x4c86295b7ceb0a9bUL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0xf977f4b4491eee49UL)
          D(1, 0x512f6c88e0e55c6bUL)
          D(2, 0xbeb79ceb6c0eff5dUL)
          M(0, 0x0edd1b22c73e37c1UL)
          M(8, 0x6547cd9c962e7a08UL)
          M(16, 0x25c4de06b887831eUL)
          M(24, 0x0fb8a6131a81687aUL)
          M(32, 0x74a934174bf589c4UL)
          M(40, 0xf8411446996bbd37UL)
          M(48, 0xe5ce1a9887723857UL)
          M(56, 0x4529878a20af333fUL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x7f80ff00807fffffUL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x7fffffffffffffffUL)
          M(0, 0xe3f7accfeb5cb856UL)
          M(8, 0x0dffa6d8606140feUL)
          M(16, 0xe6c51e21e9d2f0e6UL)
          M(24, 0xf8ea3574c6412e4aUL)
          M(32, 0xbd075e03924ae669UL)
          M(40, 0x79c40b52efb925d3UL)
          M(48, 0xad87285baf6ff53cUL)
          M(56, 0x516d10e7df8e4b4cUL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000810u)
          D(0, 0x3a5018228b01b36fUL)
          D(1, 0x8652f7152e1d072aUL)
          D(2, 0xdfe9a8c56abe8ed2UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x34f50f1368c4b81eUL)
          D(1, 0xa94bc4a681250683UL)
          D(2, 0x741789b81a7ade87UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x5e4af8742ec5e9e6UL)
          D(1, 0x0792693541e621f0UL)
          D(2, 0xbd03e6eac64a1ed2UL) ] ]
    check false "f421040f" inputs outputs

  /// <summary>
  /// A8.8.330 VLD4: vld4.8 {d0, d1, d2, d3}, [r1]. The outputs are what QEMU
  /// left after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.330 VLD4``() =
    let inputs =
      [ [ Gpr(1, 0x20000810u)
          D(0, 0xb2b817bd8f13d6e0UL)
          D(1, 0x0aa47df515a31af1UL)
          D(2, 0xcffe8ecbc79695e3UL)
          D(3, 0x16293101021a95cfUL)
          M(0, 0xfa7b4eed5507ed86UL)
          M(8, 0x4ef45c6714f7467dUL)
          M(16, 0x79927526a51bfe9cUL)
          M(24, 0x052b72007a62f07cUL)
          M(32, 0xe4779354b7d8bd1bUL)
          M(40, 0xf505b56436903c79UL)
          M(48, 0x1017111ba0e6208eUL)
          M(56, 0x5db928ac4f10ef3bUL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0xc0e5d3ba63048995UL)
          D(1, 0x30b993f964e79ee2UL)
          D(2, 0x35f251a2e4799f69UL)
          D(3, 0x2491db2680ffb839UL)
          M(0, 0x2e3547eb4c3c3cebUL)
          M(8, 0xa38d567510eaf326UL)
          M(16, 0x31f4e64a934c3719UL)
          M(24, 0xee3d5d0dff7afec5UL)
          M(32, 0x8b1008b0a8975582UL)
          M(40, 0xf122a28d88fb8cccUL)
          M(48, 0xbfaba2279982a1a8UL)
          M(56, 0x772268d787edb7f9UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x0102030405060708UL)
          D(1, 0x7f80ff00807fffffUL)
          D(2, 0x8001800180018001UL)
          D(3, 0xffffffffffffffffUL)
          M(0, 0x2c99d169b47a3b98UL)
          M(8, 0x0d1a3b654b48e285UL)
          M(16, 0x3145ab8cf1b78c60UL)
          M(24, 0xe4174f2ef5d42ab2UL)
          M(32, 0x208dcfbdf855dd8bUL)
          M(40, 0x6fbf127e6a90db01UL)
          M(48, 0x79f444dbd791f8f7UL)
          M(56, 0x95bd2f7c19aaf8b0UL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000810u)
          D(0, 0x6479541b007c269cUL)
          D(1, 0xb53c93bd72f075feUL)
          D(2, 0x059077d82b62921bUL)
          D(3, 0xf536e4b7057a79a5UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x8dccb0820dc54a19UL)
          D(1, 0xa28c08555dfee637UL)
          D(2, 0x22fb10973d7af44cUL)
          D(3, 0xf1888ba8eeff3193UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x7e01bd8b2eb28c60UL)
          D(1, 0x12dbcfdd4f2aab8cUL)
          D(2, 0xbf908d5517d445b7UL)
          D(3, 0x6f6a20f8e4f531f1UL) ] ]
    check false "f421000f" inputs outputs

  /// <summary>
  /// A8.8.333 VLDM: vldmia r1, {d0, d1}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.333 VLDM``() =
    let inputs =
      [ [ Gpr(1, 0x20000818u)
          D(0, 0xcb6813eccef19e3fUL)
          D(1, 0xf4799afdc500e8ddUL)
          M(0, 0x7c815fc83f89d5dcUL)
          M(8, 0x0110c7a8a7d99f07UL)
          M(16, 0x25c3222beb6d7955UL)
          M(24, 0x24c64c73663798f7UL)
          M(32, 0x76ffced30bee1d2fUL)
          M(40, 0x3c517fe412a3f00fUL)
          M(48, 0xb054517e2aa4ecb1UL)
          M(56, 0x7bb3f7851fb04c5eUL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0x869fc8e6be15bc20UL)
          D(1, 0x57ecfd69040ae787UL)
          M(0, 0xf3ed8cce4dbb2bd7UL)
          M(8, 0x8dd22a0f084c3bf7UL)
          M(16, 0x2363912313d3f71bUL)
          M(24, 0xb355571a5324e0e5UL)
          M(32, 0x30f060f96e23b741UL)
          M(40, 0xca63b345a85b054aUL)
          M(48, 0x50cb2ffa403b5973UL)
          M(56, 0xcbb6a3718caa3192UL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0x00ff00ff00ff00ffUL)
          D(1, 0x7f80ff00807fffffUL)
          M(0, 0x3ccd22263bec8b59UL)
          M(8, 0xc8219001957b1a62UL)
          M(16, 0x80b07120c0d57240UL)
          M(24, 0x8db75f07e88ca8ccUL)
          M(32, 0x7f60c45d622fb81aUL)
          M(40, 0x52a5bcff73a10a21UL)
          M(48, 0x9c0889207d71c5d5UL)
          M(56, 0x5e0ce031502774fdUL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000818u)
          D(0, 0x24c64c73663798f7UL)
          D(1, 0x76ffced30bee1d2fUL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0xb355571a5324e0e5UL)
          D(1, 0x30f060f96e23b741UL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0x8db75f07e88ca8ccUL)
          D(1, 0x7f60c45d622fb81aUL) ] ]
    check false "ec910b04" inputs outputs

  /// <summary>
  /// A8.8.334 VLDR: vldr d0, [r1, #8]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.334 VLDR``() =
    let inputs =
      [ [ Gpr(1, 0x20000808u)
          D(0, 0x563e3b5bab720799UL)
          M(0, 0x129580f1379442daUL)
          M(8, 0xb85b7c4e449e0859UL)
          M(16, 0xbd4b871713d1da02UL)
          M(24, 0x103a7bac6591bf45UL)
          M(32, 0xc8288fe15ad4e857UL)
          M(40, 0x78954fae9f193240UL)
          M(48, 0x1ffecb2582629c64UL)
          M(56, 0x16d36e92b3d618afUL) ]
        [ Gpr(1, 0x20000808u)
          D(0, 0x77a137e4ff24eb4dUL)
          M(0, 0xdf925e443ee0b1c4UL)
          M(8, 0x90b6824aed8944b7UL)
          M(16, 0x3ef17a15840e842bUL)
          M(24, 0xeeb1c1fc73391cf0UL)
          M(32, 0xe583f8ff8777fcc1UL)
          M(40, 0xb6751a9d80fd5c68UL)
          M(48, 0x9597663ec49d3f8bUL)
          M(56, 0x2b6d451e202dc484UL) ]
        [ Gpr(1, 0x20000808u)
          D(0, 0xffffffffffffffffUL)
          M(0, 0xbad319c1dac0cb36UL)
          M(8, 0x8fab233b6e74554fUL)
          M(16, 0xa31a9ffdd70f0797UL)
          M(24, 0x9015ef2cb8d0c28aUL)
          M(32, 0xbb72b1d984c1ab21UL)
          M(40, 0x39ab3a636bd884c1UL)
          M(48, 0x1850a45f66628a22UL)
          M(56, 0x9623ba05be6142caUL) ] ]
    let outputs =
      [ [ D(0, 0xbd4b871713d1da02UL) ]
        [ D(0, 0x3ef17a15840e842bUL) ]
        [ D(0, 0xa31a9ffdd70f0797UL) ] ]
    check false "ed910b02" inputs outputs

  /// <summary>
  /// A8.8.335 VMAX: vmax.s8 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.335 VMAX``() =
    let inputs =
      [ [ D(0, 0x7bf3e3e4d04d2188UL)
          D(1, 0x72d5e856fe2d8d60UL)
          D(2, 0x8be3e07fa6edada0UL)
          D(3, 0x35d5b94b0f20b77fUL)
          D(4, 0xc1720a57472fe211UL)
          D(5, 0x1a03e6078cd9384fUL) ]
        [ D(0, 0xfc72af1a424c0afaUL)
          D(1, 0x53c793b1ea89a32aUL)
          D(2, 0x09ae625293d7dfa6UL)
          D(3, 0xf1b12801175dfc4aUL)
          D(4, 0x80343ed870a93fdbUL)
          D(5, 0x9cbdc760b01568d0UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x7f80ff00807fffffUL)
          D(2, 0x8001800180018001UL)
          D(3, 0x0102030405060708UL)
          D(4, 0x8000000000000000UL)
          D(5, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0xc1720a7f472fe211UL); D(1, 0x3503e64b0f20387fUL) ]
        [ D(0, 0x0934625270d73fdbUL); D(1, 0xf1bd2860175d684aUL) ]
        [ D(0, 0x8001000100010001UL); D(1, 0x0102030405060708UL) ] ]
    check false "f2020644" inputs outputs

  /// <summary>
  /// A8.8.335 VMIN: vmin.s8 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.335 VMIN``() =
    let inputs =
      [ [ D(0, 0xc34eb6d5f9da95aeUL)
          D(1, 0xc4d3eb1094b8ffc0UL)
          D(2, 0x7c2e571ddc860403UL)
          D(3, 0x8dbb253af49df2bfUL)
          D(4, 0x0840ad52f4f2cca6UL)
          D(5, 0x6ced8a34490a1f03UL) ]
        [ D(0, 0x37a3d63f7953eb7dUL)
          D(1, 0x0e1a4675c924957eUL)
          D(2, 0x6cd7dedd299abe6dUL)
          D(3, 0xdeecf967c244bf11UL)
          D(4, 0x494f7be115cba6b7UL)
          D(5, 0x72881482b976e31dUL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x7f80ff00807fffffUL)
          D(2, 0x0102030405060708UL)
          D(3, 0xffffffffffffffffUL)
          D(4, 0x0102030405060708UL)
          D(5, 0xffffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x082ead1ddc86cca6UL); D(1, 0x8dbb8a34f49df2bfUL) ]
        [ D(0, 0x49d7dedd159aa6b7UL); D(1, 0xde88f982b944bf11UL) ]
        [ D(0, 0x0102030405060708UL); D(1, 0xffffffffffffffffUL) ] ]
    check false "f2020654" inputs outputs

  /// <summary>
  /// A8.8.337 VMLA: vmla.i8 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.337 VMLA``() =
    let inputs =
      [ [ D(0, 0xfadbdf52cfc5f391UL)
          D(1, 0x4f2f74e8f212d007UL)
          D(2, 0xc49c0aa4dd9605b4UL)
          D(3, 0xd672dcbf7cb4903bUL)
          D(4, 0x5767c1c8e9e48919UL)
          D(5, 0x65c5f9c9d0fd68afUL) ]
        [ D(0, 0xe935792274ac3fc7UL)
          D(1, 0x468b0d5a3e1b68e1UL)
          D(2, 0x951d095ae5d77841UL)
          D(3, 0x1347ee9129ec1a37UL)
          D(4, 0x20e95f2e84905213UL)
          D(5, 0xf9311c995bec5607UL) ]
        [ D(0, 0x0000000000000001UL)
          D(1, 0x7f80ff00807fffffUL)
          D(2, 0x7f80ff00807fffffUL)
          D(3, 0xffffffffffffffffUL)
          D(4, 0x0102030405060708UL)
          D(5, 0x0000000000000001UL) ] ]
    let outputs =
      [ [ D(0, 0x969f6972f45da025UL); D(1, 0xbde970dfb2f6505cUL) ]
        [ D(0, 0x899ad04e889caf9aUL); D(1, 0xc1221503d1ab2462UL) ]
        [ D(0, 0x7f00fd0080faf9f9UL); D(1, 0x7f80ff00807ffffeUL) ] ]
    check false "f2020944" inputs outputs

  /// <summary>
  /// A8.8.337 VMLAL: vmlal.s8 q0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.337 VMLAL``() =
    let inputs =
      [ [ D(0, 0xe594ea681f98275cUL)
          D(1, 0x3b51dc5b5b5b46caUL)
          D(2, 0xaffee423d5faa848UL) ]
        [ D(0, 0x61e6902866715754UL)
          D(1, 0xdd70f203fcc73b14UL)
          D(2, 0x62b0233ec6d27762UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x7fffffffffffffffUL)
          D(2, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0xd64be8460788182cUL); D(1, 0x28a6dbb95f4b533bUL) ]
        [ D(0, 0x62ce9a6681de5efcUL); D(1, 0xd00acf03fadd3bceUL) ]
        [ D(0, 0x7f80ff01807f0000UL); D(1, 0x7fff0000ffff0000UL) ] ]
    check false "f2810802" inputs outputs

  /// <summary>
  /// A8.8.337 VMLS: vmls.i8 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.337 VMLS``() =
    let inputs =
      [ [ D(0, 0x99871de95292b276UL)
          D(1, 0xd1fc565256f60395UL)
          D(2, 0x183cd0710c9c20b0UL)
          D(3, 0x9326b74bcc267d43UL)
          D(4, 0x01b55d0cd2b37f48UL)
          D(5, 0x5be6b4798c48e6b7UL) ]
        [ D(0, 0x2817050a589c0adfUL)
          D(1, 0x0b9e5c582f273111UL)
          D(2, 0x13cc4d6c9baedc44UL)
          D(3, 0xbeb70b05f73762bdUL)
          D(4, 0xa74f9d97a2ae38e6UL)
          D(5, 0x2946681ef01f75b5UL) ]
        [ D(0, 0x8001800180018001UL)
          D(1, 0x00ff00ff00ff00ffUL)
          D(2, 0x8000000000000000UL)
          D(3, 0x0000000000000001UL)
          D(4, 0x7fffffffffffffffUL)
          D(5, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x811b8d9d7a7ed2f6UL); D(1, 0x90d8aadfc646b5b0UL) ]
        [ D(0, 0xc323cc564258eac7UL); D(1, 0x9d94e4c29f7e6770UL) ]
        [ D(0, 0x0001800180018001UL); D(1, 0x00ff00ff00ff0000UL) ] ]
    check false "f3020944" inputs outputs

  /// <summary>
  /// A8.8.337 VMLSL: vmlsl.s8 q0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.337 VMLSL``() =
    let inputs =
      [ [ D(0, 0xcb9d29275ba80ebdUL)
          D(1, 0xee88c1e1317c3dafUL)
          D(2, 0x0f0c152f7f8de425UL) ]
        [ D(0, 0xb1174050404f9210UL)
          D(1, 0x54112b5393249f70UL)
          D(2, 0x5bd43c9348eb1638UL) ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0x0102030405060708UL)
          D(2, 0x7f80ff00807fffffUL) ] ]
    let outputs =
      [ [ D(0, 0xb34e60db62541a72UL); D(1, 0xef96c78136a74360UL) ]
        [ D(0, 0xcfbf434448a57990UL); D(1, 0x36352e3f8910c2c7UL) ]
        [ D(0, 0x8280fd0600070008UL); D(1, 0x0083040405090708UL) ] ]
    check false "f2810a02" inputs outputs

  /// <summary>
  /// A8.8.340 VMOV: vmov d0, r2, r3. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.340 VMOV``() =
    let inputs =
      [ [ Gpr(2, 0x26344926u); Gpr(3, 0xe8154720u); D(0, 0x789b450ddb5a3ee3UL) ]
        [ Gpr(2, 0xca5f649bu); Gpr(3, 0xd45b0fe9u); D(0, 0x40b74d74fb4e32dbUL) ]
        [ Gpr(2, 0x7fff8000u)
          Gpr(3, 0x00000000u)
          D(0, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0xe815472026344926UL) ]
        [ D(0, 0xd45b0fe9ca5f649bUL) ]
        [ D(0, 0x000000007fff8000UL) ] ]
    check false "ec432b10" inputs outputs

  /// <summary>
  /// A8.8.347 VMOVL: vmovl.s32 q0, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.347 VMOVL``() =
    let inputs =
      [ [ D(0, 0x6b45e1cc0e9e4ba2UL)
          D(1, 0x414af6fb10ec1d86UL)
          D(2, 0x6407e173d41c1499UL) ]
        [ D(0, 0x2639b1fcae558314UL)
          D(1, 0xaeaba144258a1fbaUL)
          D(2, 0x2f2992c7de6fe87eUL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x8001800180018001UL)
          D(2, 0x0102030405060708UL) ] ]
    let outputs =
      [ [ D(0, 0xffffffffd41c1499UL); D(1, 0x000000006407e173UL) ]
        [ D(0, 0xffffffffde6fe87eUL); D(1, 0x000000002f2992c7UL) ]
        [ D(0, 0x0000000005060708UL); D(1, 0x0000000001020304UL) ] ]
    check false "f2a00a12" inputs outputs

  /// <summary>
  /// A8.8.348 VMOVN: vmovn.i32 d0, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.348 VMOVN``() =
    let inputs =
      [ [ D(0, 0x673c8e3af726ace0UL)
          D(4, 0xe9b46dc666435f83UL)
          D(5, 0xabc30a907d005660UL) ]
        [ D(0, 0xd7c11a3243d857adUL)
          D(4, 0x9b64b8b1b41db136UL)
          D(5, 0x5cbe4245e0cf9a9bUL) ]
        [ D(0, 0x0000000000000001UL)
          D(4, 0x7fffffffffffffffUL)
          D(5, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x0a9056606dc65f83UL) ]
        [ D(0, 0x42459a9bb8b1b136UL) ]
        [ D(0, 0xffffffffffffffffUL) ] ]
    check false "f3b60204" inputs outputs

  /// <summary>
  /// A8.8.349 VMRS: vmrs r0, fpscr. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.349 VMRS``() =
    let inputs =
      [ [ Gpr(0, 0xa5c75178u); Cell.FPSCR 0x00000000u ]
        [ Gpr(0, 0x9f8c8148u); Cell.FPSCR 0x60000000u ]
        [ Gpr(0, 0x0000ffffu); Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ Gpr(0, 0x00000000u) ]
        [ Gpr(0, 0x60000000u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "eef10a10" inputs outputs

  /// <summary>
  /// A8.8.350 VMSR: vmsr fpscr, r0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.350 VMSR``() =
    let inputs =
      [ [ Gpr(0, 0x33ee013eu); Cell.FPSCR 0x00000000u ]
        [ Gpr(0, 0xd8b255adu); Cell.FPSCR 0x60000000u ]
        [ Gpr(0, 0x0000ffffu); Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ Cell.FPSCR 0x33ee001eu ]
        [ Cell.FPSCR 0xd8b2008du ]
        [ Cell.FPSCR 0x0000009fu ] ]
    check false "eee10a10" inputs outputs

  /// <summary>
  /// A8.8.351 VMUL: vmul.f32 s0, s1, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.351 VMUL``() =
    let inputs =
      [ [ D(0, 0xbec000003f400000UL)
          D(1, 0x40e8000040800000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xc2400000c0600000UL)
          D(1, 0x3fc0000040800000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3f0000003f000000UL)
          D(1, 0x404000003f000000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xbec00000bfc00000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0xc2400000c3400000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3f0000003e800000UL); Cell.FPSCR 0x00000000u ] ]
    check false "ee200a81" inputs outputs

  /// <summary>
  /// A8.8.351 VMULL: vmull.s8 q0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.351 VMULL``() =
    let inputs =
      [ [ D(0, 0xb670d5a902b493a4UL)
          D(1, 0xa73b80bb07e27609UL)
          D(2, 0x3429b17ecfd77564UL) ]
        [ D(0, 0xb7e8ea6f1f1ab9cdUL)
          D(1, 0x104099c4d7035d81UL)
          D(2, 0xd0c7ba57a83ddddeUL) ]
        [ D(0, 0x00ff00ff00ff00ffUL)
          D(1, 0x7f80ff00807fffffUL)
          D(2, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0xfea904ce35ee0384UL); D(1, 0xedec09732780de0aUL) ]
        [ D(0, 0x0e1800b7f34910deUL); D(1, 0xfd00f1c01c2aeb9cUL) ]
        [ D(0, 0x4000007f0080ffffUL); D(1, 0xc080ff8000800000UL) ] ]
    check false "f2810c02" inputs outputs

  /// <summary>
  /// A8.8.354 VMVN: vmvn.i32 q0, #0x10. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.354 VMVN``() =
    let inputs =
      [ [ D(0, 0x41905544972ed968UL); D(1, 0xb580e69d93c70529UL) ]
        [ D(0, 0x09a2f32164ac1617UL); D(1, 0x5e8cfcc4d4b77a6cUL) ]
        [ D(0, 0x7f80ff00807fffffUL); D(1, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0xffffffefffffffefUL); D(1, 0xffffffefffffffefUL) ]
        [ D(0, 0xffffffefffffffefUL); D(1, 0xffffffefffffffefUL) ]
        [ D(0, 0xffffffefffffffefUL); D(1, 0xffffffefffffffefUL) ] ]
    check false "f2810070" inputs outputs

  /// <summary>
  /// A8.8.356 VNEG: vneg.f32 s0, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.356 VNEG``() =
    let inputs =
      [ [ D(0, 0x4000000044800000UL); D(1, 0xbec0000044800000UL) ]
        [ D(0, 0x3d800000c0100000UL); D(1, 0x40e80000c0100000UL) ]
        [ D(0, 0x4040000040400000UL); D(1, 0xc01000003f000000UL) ] ]
    let outputs =
      [ [ D(0, 0x40000000c4800000UL) ]
        [ D(0, 0x3d80000040100000UL) ]
        [ D(0, 0x40400000bf000000UL) ] ]
    check false "eeb10a41" inputs outputs

  /// <summary>
  /// A8.8.357 VNMLA: vnmla.f32 s0, s1, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.357 VNMLA``() =
    let inputs =
      [ [ D(0, 0x3e80000040200000UL)
          D(1, 0x40000000bec00000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xc06000003e000000UL)
          D(1, 0x3f40000040800000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x000000003f000000UL)
          D(1, 0x404000003fc00000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x3e800000c01a0000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0xc0600000415e0000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x00000000bf000000UL); Cell.FPSCR 0x00000000u ] ]
    check false "ee100ac1" inputs outputs

  /// <summary>
  /// A8.8.357 VNMLS: vnmls.f32 s0, s1, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.357 VNMLS``() =
    let inputs =
      [ [ D(0, 0x42c9000041200000UL)
          D(1, 0x42c9000040000000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xbec0000041400000UL)
          D(1, 0xbec0000041400000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3f000000c0100000UL)
          D(1, 0x7f80000000000000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x42c90000433f0000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0xbec00000c1840000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3f00000040100000UL); Cell.FPSCR 0x00000000u ] ]
    check false "ee100a81" inputs outputs

  /// <summary>
  /// A8.8.357 VNMUL: vnmul.f32 s0, s1, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.357 VNMUL``() =
    let inputs =
      [ [ D(0, 0x4120000040800000UL)
          D(1, 0x404000003e800000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x3fc0000041400000UL)
          D(1, 0xc040000040200000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x800000003fc00000UL)
          D(1, 0x7f80000040400000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x41200000c0200000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x3fc00000c0700000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x8000000000000000UL); Cell.FPSCR 0x00000000u ] ]
    check false "ee200ac1" inputs outputs

  /// <summary>
  /// A8.8.358 VORN: vorn q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.358 VORN``() =
    let inputs =
      [ [ D(0, 0xfa08115855022c56UL)
          D(1, 0xcc6a78d43467d5a8UL)
          D(2, 0x5d77bf4b8d6a4718UL)
          D(3, 0x6bb16728c1bc3359UL)
          D(4, 0x285abc441d6c52f5UL)
          D(5, 0x886282ed80e362baUL) ]
        [ D(0, 0xed348accc4272f8aUL)
          D(1, 0x8a8c6365d6ff07eeUL)
          D(2, 0x1fea4cb17f8f9e67UL)
          D(3, 0x0982680e4b41201aUL)
          D(4, 0xc9c582ab1deb6e13UL)
          D(5, 0x641f0002da68ffa1UL) ]
        [ D(0, 0x8001800180018001UL)
          D(1, 0x7fffffffffffffffUL)
          D(2, 0x00ff00ff00ff00ffUL)
          D(3, 0x8001800180018001UL)
          D(4, 0x00ff00ff00ff00ffUL)
          D(5, 0x0102030405060708UL) ] ]
    let outputs =
      [ [ D(0, 0xdff7fffbeffbef1aUL); D(1, 0x7fbd7f3affbcbf5dUL) ]
        [ D(0, 0x3ffa7df5ff9f9fefUL); D(1, 0x9be2ffff6fd7205eUL) ]
        [ D(0, 0xffffffffffffffffUL); D(1, 0xfefdfcfbfaf9f8f7UL) ] ]
    check false "f2320154" inputs outputs

  /// <summary>
  /// A8.8.360 VORR: vorr.i32 q0, #0x10. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.360 VORR``() =
    let inputs =
      [ [ D(0, 0x2a68a8df16d5a64eUL); D(1, 0x1f093bd8790807f3UL) ]
        [ D(0, 0xb13e2170ebced17dUL); D(1, 0xd98cad61b263409fUL) ]
        [ D(0, 0x7fffffffffffffffUL); D(1, 0x0102030405060708UL) ] ]
    let outputs =
      [ [ D(0, 0x2a68a8df16d5a65eUL); D(1, 0x1f093bd8790807f3UL) ]
        [ D(0, 0xb13e2170ebced17dUL); D(1, 0xd98cad71b263409fUL) ]
        [ D(0, 0x7fffffffffffffffUL); D(1, 0x0102031405060718UL) ] ]
    check false "f2810150" inputs outputs

  /// <summary>
  /// A8.8.362 VPADAL: vpadal.s32 q0, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.362 VPADAL``() =
    let inputs =
      [ [ D(0, 0x532641a9d0c0504dUL)
          D(1, 0x5ebb46ec3069b759UL)
          D(4, 0x78fe6a56bdf007a9UL)
          D(5, 0x69770d34950b4593UL) ]
        [ D(0, 0x77bc3e7d93cd2365UL)
          D(1, 0x59656e1ae6ddf107UL)
          D(4, 0x9f57232460c17462UL)
          D(5, 0xec812e9730fa7f88UL) ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0xffffffffffffffffUL)
          D(4, 0x8001800180018001UL)
          D(5, 0x0102030405060708UL) ] ]
    let outputs =
      [ [ D(0, 0x532641aa07aec24cUL); D(1, 0x5ebb46ec2eec0a20UL) ]
        [ D(0, 0x77bc3e7d93e5baebUL); D(1, 0x59656e1b04599f26UL) ]
        [ D(0, 0x7fffffff00030002UL); D(1, 0x0000000006080a0bUL) ] ]
    check false "f3b80644" inputs outputs

  /// <summary>
  /// A8.8.363 VPADD: vpadd.f32 d0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.363 VPADD``() =
    let inputs =
      [ [ D(0, 0xc0d000003fe00000UL)
          D(1, 0x4000000040400000UL)
          D(2, 0xbec000003d800000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x3e00000044800000UL)
          D(1, 0xc0400000bf800000UL)
          D(2, 0x3e80000044800000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3f000000ff800000UL)
          D(1, 0x3f00000080000000UL)
          D(2, 0x000000007f800000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xbea0000040a00000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x44800800c0800000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7f8000003f000000UL); Cell.FPSCR 0x00000000u ] ]
    check false "f3010d02" inputs outputs

  /// <summary>
  /// A8.8.363 VPADD, the integer forms: vpadd.i16 d0, d1, d2. The pairs of Dn
  /// fill the low half of Dd and the pairs of Dm the high half; the outputs are
  /// computed from the manual's Operation, over lanes at each extreme of their
  /// type.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.363 VPADD (integer)``() =
    let inputs =
      [ [ D(0, 0x5555555555555555UL)
          D(1, 0x80017ffe05fa7f80UL)
          D(2, 0x00ff01028081fe7fUL) ] ]
    check false "f2110b12" inputs [ [ D(0, 0x02017f00ffff857aUL) ] ]

  /// <summary>
  /// A8.8.365 VPADDL: vpaddl.s32 q0, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.365 VPADDL``() =
    let inputs =
      [ [ D(0, 0xdb04cc13dbc42314UL)
          D(1, 0xa9d6347d76f14cf4UL)
          D(4, 0x3dd1fd6135b81945UL)
          D(5, 0x6d183ef90909cf50UL) ]
        [ D(0, 0xf7aa3ce13b632526UL)
          D(1, 0xac339420a670a220UL)
          D(4, 0x330d81ff4ad4fc4dUL)
          D(5, 0x07f2ceb5e84175f3UL) ]
        [ D(0, 0x00ff00ff00ff00ffUL)
          D(1, 0x7f80ff00807fffffUL)
          D(4, 0x8000000000000000UL)
          D(5, 0x8000000000000000UL) ] ]
    let outputs =
      [ [ D(0, 0x00000000738a16a6UL); D(1, 0x0000000076220e49UL) ]
        [ D(0, 0x000000007de27e4cUL); D(1, 0xfffffffff03444a8UL) ]
        [ D(0, 0xffffffff80000000UL); D(1, 0xffffffff80000000UL) ] ]
    check false "f3b80244" inputs outputs

  /// <summary>
  /// A8.8.366 VPMAX: vpmax.f32 d0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.366 VPMAX``() =
    let inputs =
      [ [ D(0, 0xbf0000003fe00000UL)
          D(1, 0xc0100000bec00000UL)
          D(2, 0xc24000003d800000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x4000000042c90000UL)
          D(1, 0xc2400000c0600000UL)
          D(2, 0x40c0000040c00000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x0000000040400000UL)
          D(1, 0x0000000080000000UL)
          D(2, 0x3fc00000ff800000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x3d800000bec00000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x40c00000c0600000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3fc0000000000000UL); Cell.FPSCR 0x00000000u ] ]
    check false "f3010f02" inputs outputs

  /// <summary>
  /// A8.8.366 VPMAX, the integer forms: vpmax.s8 d0, d1, d2; vpmax.s16 d0, d1,
  /// d2. The pairs of Dn fill the low half of Dd and the pairs of Dm the high
  /// half; the outputs are computed from the manual's Operation, over lanes at
  /// each extreme of their type.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.366 VPMAX (integer)``() =
    let inputs =
      [ [ D(0, 0x5555555555555555UL)
          D(1, 0x80017ffe05fa7f80UL)
          D(2, 0x00ff01028081fe7fUL) ] ]
    check false "f2010a02" inputs [ [ D(0, 0x0002817f017f057fUL) ] ]
    check false "f2110a02" inputs [ [ D(0, 0x0102fe7f7ffe7f80UL) ] ]

  /// <summary>
  /// A8.8.366 VPMIN: vpmin.f32 d0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.366 VPMIN``() =
    let inputs =
      [ [ D(0, 0x3fc000003e800000UL)
          D(1, 0xc0d000003fe00000UL)
          D(2, 0x3e000000bf800000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xc0100000c0d00000UL)
          D(1, 0x4080000040e80000UL)
          D(2, 0xc0600000c0600000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7f8000003fc00000UL)
          D(1, 0x8000000080000000UL)
          D(2, 0xc010000000000000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xbf800000c0d00000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0xc060000040800000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0xc010000080000000UL); Cell.FPSCR 0x00000000u ] ]
    check false "f3210f02" inputs outputs

  /// <summary>
  /// A8.8.366 VPMIN, the integer forms: vpmin.s8 d0, d1, d2; vpmin.u32 d0, d1,
  /// d2. The pairs of Dn fill the low half of Dd and the pairs of Dm the high
  /// half; the outputs are computed from the manual's Operation, over lanes at
  /// each extreme of their type.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.366 VPMIN (integer)``() =
    let inputs =
      [ [ D(0, 0x5555555555555555UL)
          D(1, 0x80017ffe05fa7f80UL)
          D(2, 0x00ff01028081fe7fUL) ] ]
    check false "f2010a12" inputs [ [ D(0, 0xff0180fe80fefa80UL) ] ]
    check false "f3210a12" inputs [ [ D(0, 0x00ff010205fa7f80UL) ] ]

  /// <summary>
  /// A8.8.368 VPOP: vldmia sp!, {d0, d1}. This checks that it loads D0 and D1
  /// from SP and moves SP up by sixteen. It is not a value test because it
  /// moves SP, which the run itself stands on.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.368 VPOP``() =
    let w = uint32 Window
    let d0, d1 = 0x1111111100000000UL, 0x3333333322222222UL
    let cells = [ M(16, d0); M(24, d1) ]
    let run = runWith false "ecbd0b04" cells [ Register.SP, w + 16u ]
    Assert.AreEqual(D(0, d0), run.After(D(0, 0UL)))
    Assert.AreEqual(D(1, d1), run.After(D(1, 0UL)))
    Assert.AreEqual(w + 32u, run.Reg Register.SP)

  /// <summary>
  /// A8.8.369 VPUSH: vstmdb sp!, {s0, s1, s2, s3}. This checks that it stores
  /// S0 to S3 below SP, in order, and moves SP down by sixteen. It is not a
  /// value test because it moves SP, which the run itself stands on.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.369 VPUSH``() =
    let w = uint32 Window
    let d0, d1 = 0x1111111100000000UL, 0x3333333322222222UL
    let cells = [ D(0, d0); D(1, d1); M(16, 0UL); M(24, 0UL) ]
    let run = runWith false "ed2d0a04" cells [ Register.SP, w + 32u ]
    Assert.AreEqual(M(16, d0), run.After(M(16, 0UL)))
    Assert.AreEqual(M(24, d1), run.After(M(24, 0UL)))
    Assert.AreEqual(w + 16u, run.Reg Register.SP)

  /// <summary>
  /// A8.8.370 VQABS: vqabs.s32 q0, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.370 VQABS``() =
    let inputs =
      [ [ D(0, 0x59daa02e49344175UL)
          D(1, 0x83612ebb30c256cfUL)
          D(4, 0x422b8ae4b88bcd56UL)
          D(5, 0x20e78bdfb64d369eUL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xbf594f116a28e30dUL)
          D(1, 0xeed0f7959c320b38UL)
          D(4, 0x6cc5e622542060e5UL)
          D(5, 0xf4e6d5380b6e0657UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7fffffffffffffffUL)
          D(1, 0x0102030405060708UL)
          D(4, 0x7f80ff00807fffffUL)
          D(5, 0x00ff00ff00ff00ffUL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x422b8ae4477432aaUL)
          D(1, 0x20e78bdf49b2c962UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x6cc5e622542060e5UL)
          D(1, 0x0b192ac80b6e0657UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7f80ff007f800001UL)
          D(1, 0x00ff00ff00ff00ffUL)
          Cell.FPSCR 0x00000000u ] ]
    check false "f3b80744" inputs outputs

  /// <summary>
  /// A8.8.371 VQADD: vqadd.s32 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.371 VQADD``() =
    let inputs =
      [ [ D(0, 0xe8a6f33abc6915f3UL)
          D(1, 0xa3110ddee7334becUL)
          D(2, 0xf5cba359b577378dUL)
          D(3, 0x23a8fe33d30921fdUL)
          D(4, 0x7f54ed34bebcab51UL)
          D(5, 0x39945b1699dddbc5UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x15b95ad1738a0301UL)
          D(1, 0xd5c9ec76f48a7f6dUL)
          D(2, 0x535bae450945a539UL)
          D(3, 0x7d5dd7058606a03dUL)
          D(4, 0xac731efa03d6ef09UL)
          D(5, 0x1a156a1b5380ee6aUL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x0000000000000001UL)
          D(3, 0x7fffffffffffffffUL)
          D(4, 0x00ff00ff00ff00ffUL)
          D(5, 0xffffffffffffffffUL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x7520908d80000000UL)
          D(1, 0x5d3d594980000000UL)
          Cell.FPSCR 0x08000000u ]
        [ D(0, 0xffcecd3f0d1c9442UL)
          D(1, 0x7fffffffd9878ea7UL)
          Cell.FPSCR 0x68000000u ]
        [ D(0, 0x00ff00ff00ff0100UL)
          D(1, 0x7ffffffefffffffeUL)
          Cell.FPSCR 0x00000000u ] ]
    check false "f2220054" inputs outputs

  /// <summary>
  /// A8.8.372 VQDMLAL: vqdmlal.s16 q0, d1, d2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.372 VQDMLAL``() =
    let inputs =
      [ [ D(0, 0x98773d68edab7b2fUL)
          D(1, 0x71a573da64c6b3bcUL)
          D(2, 0x2a0170f40c60295aUL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xd85a68ac6021cbbcUL)
          D(1, 0xb666382a7e889fd6UL)
          D(2, 0x3d92476beb95f8f6UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0xffffffffffffffffUL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xa23561e8d508135fUL)
          D(1, 0x7fffffff7fffffffUL)
          Cell.FPSCR 0x08000000u ]
        [ D(0, 0xc42b62fc656b9b04UL)
          D(1, 0x92fee0827fffffffUL)
          Cell.FPSCR 0x68000000u ]
        [ D(0, 0x7f80ff0280800001UL)
          D(1, 0x0000000100000001UL)
          Cell.FPSCR 0x00000000u ] ]
    check false "f2910902" inputs outputs

  /// <summary>
  /// A8.8.372 VQDMLSL: vqdmlsl.s16 q0, d1, d2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.372 VQDMLSL``() =
    let inputs =
      [ [ D(0, 0xc9595dc3281d5cffUL)
          D(1, 0x97b539ec250ad876UL)
          D(2, 0x36b7868a6de5f0ffUL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x2a550e0baf852f13UL)
          D(1, 0x4b3841206c884a3aUL)
          D(2, 0x1b93843d7ba0b8d6UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x7f80ff00807fffffUL)
          D(2, 0x7f80ff00807fffffUL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xa98c95df237ae1ebUL)
          D(1, 0xc449f9265c015606UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xc182b40bd8c9b61bUL)
          D(1, 0x3b040ed07fffffffUL)
          Cell.FPSCR 0x68000000u ]
        [ D(0, 0x007e80fe807ffffdUL)
          D(1, 0x00807f00807dffffUL)
          Cell.FPSCR 0x00000000u ] ]
    check false "f2910b02" inputs outputs

  /// <summary>
  /// A8.8.373 VQDMULH: vqdmulh.s32 q0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.373 VQDMULH``() =
    let inputs =
      [ [ D(0, 0x3afe8916228e6a8dUL)
          D(1, 0x04a69c18c8f74e07UL)
          D(2, 0x8906d23f87a43584UL)
          D(3, 0xf3ad24c7b4821937UL)
          D(4, 0xa0e1aa7a35043cc3UL)
          D(5, 0x073173fce1e56c6eUL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xffc11bebf137c3d7UL)
          D(1, 0x22b3907a98bfbbf7UL)
          D(2, 0x1a00115cf06e75bcUL)
          D(3, 0x490128d8dddfba9dUL)
          D(4, 0x221793171098095dUL)
          D(5, 0xf9ae12ead05fd393UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x00ff00ff00ff00ffUL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x0000000000000001UL)
          D(3, 0x8000000000000000UL)
          D(4, 0x8000000000000000UL)
          D(5, 0x0000000000000001UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x586921d9ce260227UL)
          D(1, 0xff4eb52011c12eb2UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x06ecce80fdfb50bfUL)
          D(1, 0xfc6538210cb28da9UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x0000000000000000UL)
          D(1, 0x0000000000000000UL)
          Cell.FPSCR 0x00000000u ] ]
    check false "f2220b44" inputs outputs

  /// <summary>
  /// A8.8.374 VQDMULL: vqdmull.s32 q0, d1, d2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.374 VQDMULL``() =
    let inputs =
      [ [ D(0, 0x3bc6e64e4d679eeaUL)
          D(1, 0xd9d8cd7c01410d16UL)
          D(2, 0xfe0de0b203503b44UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x65b551cc326fafe3UL)
          D(1, 0xf23e3b988b21275cUL)
          D(2, 0x9a3c5f43ffbf5841UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x8001800180018001UL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x7f80ff00807fffffUL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x00084f8b585717b0UL)
          D(1, 0x009479d547aec070UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x003b0895752d3cb8UL)
          D(1, 0x0aefeb71cc0e0190UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x00000000ff000002UL)
          D(1, 0xffffffff00fe0200UL)
          Cell.FPSCR 0x00000000u ] ]
    check false "f2a10d02" inputs outputs

  /// <summary>
  /// A8.8.375 VQMOVN: vqmovn.s16 d0, q1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.375 VQMOVN``() =
    let inputs =
      [ [ D(0, 0x23d808ce18157c75UL)
          D(2, 0x55c9b2c8e8059596UL)
          D(3, 0xeb30af4c3705b91bUL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x8ca58b8ed7c4886dUL)
          D(2, 0x97ba240e233fc97aUL)
          D(3, 0x3fddc01e84491c5eUL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7fffffffffffffffUL)
          D(2, 0x0000000000000001UL)
          D(3, 0x00ff00ff00ff00ffUL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x80807f807f808080UL); Cell.FPSCR 0x08000000u ]
        [ D(0, 0x7f80807f807f7f80UL); Cell.FPSCR 0x68000000u ]
        [ D(0, 0x7f7f7f7f00000001UL); Cell.FPSCR 0x08000000u ] ]
    check false "f3b20282" inputs outputs

  /// <summary>
  /// A8.8.375 VQMOVUN: vqmovun.s16 d0, q1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.375 VQMOVUN``() =
    let inputs =
      [ [ D(0, 0x70459ef4909004aaUL)
          D(2, 0x73ce40f9257ec817UL)
          D(3, 0x3f418505cd01d469UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x643e9c2cd44deee9UL)
          D(2, 0xa9b180ec3e9a1064UL)
          D(3, 0x9ae201291cdb2594UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x0000000000000001UL)
          D(2, 0x0102030405060708UL)
          D(3, 0x0000000000000001UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xff000000ffffff00UL); Cell.FPSCR 0x08000000u ]
        [ D(0, 0x00ffffff0000ffffUL); Cell.FPSCR 0x68000000u ]
        [ D(0, 0x00000001ffffffffUL); Cell.FPSCR 0x08000000u ] ]
    check false "f3b20242" inputs outputs

  /// <summary>
  /// A8.8.376 VQNEG: vqneg.s32 q0, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.376 VQNEG``() =
    let inputs =
      [ [ D(0, 0xc3f057737ea51493UL)
          D(1, 0xd476dda43a34bd4aUL)
          D(4, 0x2c16e94dc4376c72UL)
          D(5, 0xcbf0fdbb3135bce5UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x2a35d5c74d79e6c2UL)
          D(1, 0x496b87030b39aea4UL)
          D(4, 0xd7366acbc78a3896UL)
          D(5, 0x40c3cc0e8c7ab06fUL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x8001800180018001UL)
          D(4, 0x8000000000000000UL)
          D(5, 0x0102030405060708UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xd3e916b33bc8938eUL)
          D(1, 0x340f0245ceca431bUL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x28c995353875c76aUL)
          D(1, 0xbf3c33f273854f91UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7fffffff00000000UL)
          D(1, 0xfefdfcfcfaf9f8f8UL)
          Cell.FPSCR 0x08000000u ] ]
    check false "f3b807c4" inputs outputs

  /// <summary>
  /// A8.8.377 VQRDMULH: vqrdmulh.s32 q0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.377 VQRDMULH``() =
    let inputs =
      [ [ D(0, 0x709b9e841ac9f4ccUL)
          D(1, 0xc5ea7bbc3d1df061UL)
          D(2, 0x98d4fdcc17fa3680UL)
          D(3, 0xf08c856fc1508ecfUL)
          D(4, 0xe2d14397cff74810UL)
          D(5, 0xb8939c0355e09c36UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xd255bd82153c53cdUL)
          D(1, 0x08f5257160a1a2e2UL)
          D(2, 0x01d982a78af386a9UL)
          D(3, 0xb65bddd6f53168e2UL)
          D(4, 0x8c5eab7368032b8fUL)
          D(5, 0x6c6e69b5bb57a58bUL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x8001800180018001UL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x8000000000000000UL)
          D(3, 0x8000000000000000UL)
          D(4, 0x8001800180018001UL)
          D(5, 0x00ff00ff00ff00ffUL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x178569d0f7008978UL)
          D(1, 0x089f237ed5f17f4fUL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xfe543fcfa0e2f74aUL)
          D(1, 0xc19dfd4e05cbf711UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7ffe7fff00000000UL)
          D(1, 0xff00ff0100000000UL)
          Cell.FPSCR 0x00000000u ] ]
    check false "f3220b44" inputs outputs

  /// <summary>
  /// A8.8.378 VQRSHL: vqrshl.s8 q0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.378 VQRSHL``() =
    let inputs =
      [ [ D(0, 0xefaae4a5e8845254UL)
          D(1, 0xe3f0550038c80cd5UL)
          D(2, 0x3650e10728b8c899UL)
          D(3, 0xa41eb82cb8987e6fUL)
          D(4, 0xb6e316f1fa9e23adUL)
          D(5, 0xe94ac28cdc699f4fUL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x9347cbe0fb8c16d7UL)
          D(1, 0x3f704887d7016521UL)
          D(2, 0xa316a7427f296428UL)
          D(3, 0x0b74276f716133f1UL)
          D(4, 0x99a53766f9230be4UL)
          D(5, 0x2597c507f8edf5e5UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0xffffffffffffffffUL)
          D(1, 0x00ff00ff00ff00ffUL)
          D(2, 0x00ff00ff00ff00ffUL)
          D(3, 0x00ff00ff00ff00ffUL)
          D(4, 0x0000000000000001UL)
          D(5, 0x7fffffffffffffffUL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x0000800001008000UL)
          D(1, 0x007f00000080007fUL)
          Cell.FPSCR 0x08000000u ]
        [ D(0, 0x0000807f017f7f00UL)
          D(1, 0x7f00007f00000000UL)
          Cell.FPSCR 0x68000000u ]
        [ D(0, 0x00ff00ff00ff00feUL)
          D(1, 0x0000000000000000UL)
          Cell.FPSCR 0x00000000u ] ]
    check false "f2040552" inputs outputs

  /// <summary>
  /// A8.8.379 VQRSHRN: vqrshrn.s16 d0, q1, #0x1. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.379 VQRSHRN``() =
    let inputs =
      [ [ D(0, 0x2c7dfcca2e70d125UL)
          D(2, 0x4597463793294016UL)
          D(3, 0xa2422b5be9f38b6eUL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xa5643895b4f56516UL)
          D(2, 0x46ec049da3a437b9UL)
          D(3, 0xc28e4e8e8215d708UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7fffffffffffffffUL)
          D(2, 0xffffffffffffffffUL)
          D(3, 0x8000000000000000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x807f80807f7f807fUL); Cell.FPSCR 0x08000000u ]
        [ D(0, 0x807f80807f7f807fUL); Cell.FPSCR 0x68000000u ]
        [ D(0, 0x8000000000000000UL); Cell.FPSCR 0x08000000u ] ]
    check false "f28f0952" inputs outputs

  /// <summary>
  /// A8.8.379 VQRSHRUN: vqrshrun.s16 d0, q1, #0x1. The outputs are what QEMU
  /// left after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.379 VQRSHRUN``() =
    let inputs =
      [ [ D(0, 0xb851b15478c29ac2UL)
          D(2, 0xf737437f5263266fUL)
          D(3, 0xefe957cdb57fedccUL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xf8e327fba026ab02UL)
          D(2, 0x0be717fb4654392eUL)
          D(3, 0x920650e52d30a309UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0xffffffffffffffffUL)
          D(2, 0x8001800180018001UL)
          D(3, 0x8001800180018001UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x00ff000000ffffffUL); Cell.FPSCR 0x08000000u ]
        [ D(0, 0x00ffff00ffffffffUL); Cell.FPSCR 0x68000000u ]
        [ D(0, 0x0000000000000000UL); Cell.FPSCR 0x08000000u ] ]
    check false "f38f0852" inputs outputs

  /// <summary>
  /// A8.8.380 VQSHL: vqshl.s8 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.380 VQSHL``() =
    let inputs =
      [ [ D(0, 0x86b6f75634a39e0cUL)
          D(1, 0x7b7770373c99c845UL)
          D(2, 0xd6fe785a9c7eff78UL)
          D(3, 0x64508ef01df5a093UL)
          D(4, 0xdc746519d3681b29UL)
          D(5, 0xbb16f5ff30fff92eUL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x979e9b36e44431f3UL)
          D(1, 0xc5eaa121cd1ff37eUL)
          D(2, 0xb8acfe50b41e9566UL)
          D(3, 0x183f7dda3f5fd8ecUL)
          D(4, 0xebb2ffa1dc35305bUL)
          D(5, 0x78f254dd6f320d76UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x00ff00ff00ff00ffUL)
          D(1, 0x0000000000000001UL)
          D(2, 0x8001800180018001UL)
          D(3, 0x8001800180018001UL)
          D(4, 0x7fffffffffffffffUL)
          D(5, 0x8000000000000000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xff807f7fff7f807fUL)
          D(1, 0x007ffff87ffaff80UL)
          Cell.FPSCR 0x08000000u ]
        [ D(0, 0xffffff00ff7f807fUL)
          D(1, 0x7f007fff7f7f8080UL)
          Cell.FPSCR 0x68000000u ]
        [ D(0, 0x8000c000c000c000UL)
          D(1, 0xff01800180018001UL)
          Cell.FPSCR 0x08000000u ] ]
    check false "f2040452" inputs outputs

  /// <summary>
  /// A8.8.381 VQSHLU: vqshlu.s8 q0, q1, #0x1. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.381 VQSHLU``() =
    let inputs =
      [ [ D(0, 0x76ea85eddbd63d9eUL)
          D(1, 0xa5eef923e2661208UL)
          D(2, 0x8ef345fea89f90e1UL)
          D(3, 0x1ed13f77a08dafd5UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x0e0cc69e51810b80UL)
          D(1, 0xb43d5f10e9910958UL)
          D(2, 0x08cb5e256d3bc7fdUL)
          D(3, 0x9b525514d874118cUL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0x7f80ff00807fffffUL)
          D(2, 0x00ff00ff00ff00ffUL)
          D(3, 0x0102030405060708UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x00008a0000000000UL)
          D(1, 0x3c007eee00000000UL)
          Cell.FPSCR 0x08000000u ]
        [ D(0, 0x1000bc4ada760000UL)
          D(1, 0x00a4aa2800e82200UL)
          Cell.FPSCR 0x68000000u ]
        [ D(0, 0x0000000000000000UL)
          D(1, 0x020406080a0c0e10UL)
          Cell.FPSCR 0x08000000u ] ]
    check false "f3890652" inputs outputs

  /// <summary>
  /// A8.8.382 VQSHRN: vqshrn.s16 d0, q1, #0x1. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.382 VQSHRN``() =
    let inputs =
      [ [ D(0, 0x4800e080127dfa94UL)
          D(2, 0x5dd0d9a650e8983cUL)
          D(3, 0x3d5ba258e379623dUL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xa16d785d9b94596fUL)
          D(2, 0xa27b6cc6de11e4caUL)
          D(3, 0xa275ab9eec13c55eUL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x8001800180018001UL)
          D(2, 0x0102030405060708UL)
          D(3, 0x0000000000000001UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x7f80807f7f807f80UL); Cell.FPSCR 0x08000000u ]
        [ D(0, 0x80808080807f8080UL); Cell.FPSCR 0x68000000u ]
        [ D(0, 0x000000007f7f7f7fUL); Cell.FPSCR 0x08000000u ] ]
    check false "f28f0912" inputs outputs

  /// <summary>
  /// A8.8.382 VQSHRUN: vqshrun.s16 d0, q1, #0x1. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.382 VQSHRUN``() =
    let inputs =
      [ [ D(0, 0xdc34f8bc85fe22b3UL)
          D(2, 0x898899b96987e18fUL)
          D(3, 0x3fb177144373c427UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x6c4325a0e0456407UL)
          D(2, 0xd39dda21b99c9b28UL)
          D(3, 0xea6ada94effce543UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(2, 0xffffffffffffffffUL)
          D(3, 0x7fffffffffffffffUL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xffffff000000ff00UL); Cell.FPSCR 0x08000000u ]
        [ D(0, 0x0000000000000000UL); Cell.FPSCR 0x68000000u ]
        [ D(0, 0xff00000000000000UL); Cell.FPSCR 0x08000000u ] ]
    check false "f38f0812" inputs outputs

  /// <summary>
  /// A8.8.383 VQSUB: vqsub.s8 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.383 VQSUB``() =
    let inputs =
      [ [ D(0, 0xc721548bc972f6e6UL)
          D(1, 0x9e879585d4ef8a6dUL)
          D(2, 0x6eaa9a2441bee20cUL)
          D(3, 0x06d1aa97181360a7UL)
          D(4, 0xd456d963909e2b37UL)
          D(5, 0x3fb296097a4ba266UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xf3c66f8e207d6577UL)
          D(1, 0x7a723ee55c1cb3a9UL)
          D(2, 0xd32dfea99749867dUL)
          D(3, 0x947538cfb0292c08UL)
          D(4, 0x6fa241e6c0178cfbUL)
          D(5, 0x9c401dbcd53dff64UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x8000000000000000UL)
          D(2, 0x7fffffffffffffffUL)
          D(3, 0x0102030405060708UL)
          D(4, 0x0000000000000001UL)
          D(5, 0x8001800180018001UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x7f80c1c17f20b7d5UL)
          D(1, 0xc71f148e9ec87f80UL)
          Cell.FPSCR 0x08000000u ]
        [ D(0, 0x807fbdc3d732fa7fUL)
          D(1, 0xf8351b13dbec2da4UL)
          Cell.FPSCR 0x68000000u ]
        [ D(0, 0x7ffffffffffffffeUL)
          D(1, 0x7f017f037f057f07UL)
          Cell.FPSCR 0x08000000u ] ]
    check false "f2020254" inputs outputs

  /// <summary>
  /// A8.8.384 VRADDHN: vraddhn.i32 d0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.384 VRADDHN``() =
    let inputs =
      [ [ D(0, 0x2db2251cb9939f86UL)
          D(2, 0xc8a18ba54f395538UL)
          D(3, 0xe00dee9c3020bccfUL)
          D(4, 0x06922c7d61513aa8UL)
          D(5, 0x69fdaa7c69ab1c65UL) ]
        [ D(0, 0xc4a581c0f4e2af61UL)
          D(2, 0x235303bc44dd8a1dUL)
          D(3, 0x609e429c153d624fUL)
          D(4, 0xbc48fc28eb84a2c2UL)
          D(5, 0x759c5cd2605946e7UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(2, 0x7fffffffffffffffUL)
          D(3, 0x8000000000000000UL)
          D(4, 0x7f80ff00807fffffUL)
          D(5, 0x7f80ff00807fffffUL) ] ]
    let outputs =
      [ [ D(0, 0x4a0c99cccf34b08bUL) ]
        [ D(0, 0xd63b7597df9c3062UL) ]
        [ D(0, 0xff818080ff818080UL) ] ]
    check false "f3920404" inputs outputs

  /// <summary>
  /// A8.8.385 VRECPE: vrecpe.f32 d0, d1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.385 VRECPE``() =
    let inputs =
      [ [ D(0, 0x40e8000041400000UL)
          D(1, 0x40e800003e000000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xbf80000041200000UL)
          D(1, 0x40e8000040400000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7f800000c0100000UL)
          D(1, 0x3f00000000000000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x3e0d000040ff8000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x3e0d00003eaa8000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3fff80007f800000UL); Cell.FPSCR 0x00000002u ] ]
    check false "f3bb0501" inputs outputs

  /// <summary>
  /// A8.8.386 VRECPS: vrecps.f32 d0, d1, d2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.386 VRECPS``() =
    let inputs =
      [ [ D(0, 0x40e80000c0400000UL)
          D(1, 0x42c9000040200000UL)
          D(2, 0x3e0000003e800000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x3e800000bf000000UL)
          D(1, 0xc060000041200000UL)
          D(2, 0x44800000bf800000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x80000000c0100000UL)
          D(1, 0xc010000000000000UL)
          D(2, 0xc0100000c0100000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xc12900003fb00000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x4560200041400000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0xc044000040000000UL); Cell.FPSCR 0x00000000u ] ]
    check false "f2010f12" inputs outputs

  /// <summary>
  /// A8.8.387 VREV16: vrev16.8 q0, q1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.387 VREV16``() =
    let inputs =
      [ [ D(0, 0x42aa91d83192ce99UL)
          D(1, 0x063a38bfe0e3251eUL)
          D(2, 0xa6fa64fe717d25c3UL)
          D(3, 0xfa32b8f3c55ae158UL) ]
        [ D(0, 0x8d7cb441f3305ee0UL)
          D(1, 0xccac40b5bfbba3f8UL)
          D(2, 0xf56ad0bde369ee2cUL)
          D(3, 0x1cb0cc576891aa91UL) ]
        [ D(0, 0x0000000000000001UL)
          D(1, 0x8001800180018001UL)
          D(2, 0x0102030405060708UL)
          D(3, 0xffffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0xfaa6fe647d71c325UL); D(1, 0x32faf3b85ac558e1UL) ]
        [ D(0, 0x6af5bdd069e32ceeUL); D(1, 0xb01c57cc916891aaUL) ]
        [ D(0, 0x0201040306050807UL); D(1, 0xffffffffffffffffUL) ] ]
    check false "f3b00142" inputs outputs

  /// <summary>
  /// A8.8.387 VREV32: vrev32.8 q0, q1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.387 VREV32``() =
    let inputs =
      [ [ D(0, 0xc933685e40707a4bUL)
          D(1, 0x54f70a10818e5766UL)
          D(2, 0x2c40ce84c05abb09UL)
          D(3, 0x2b7da4193d230f6bUL) ]
        [ D(0, 0xa45993cf42c27856UL)
          D(1, 0xa114190b59aa1cc5UL)
          D(2, 0xfe595ee2f13b9c43UL)
          D(3, 0x850e33dde63f1425UL) ]
        [ D(0, 0x0000000000000001UL)
          D(1, 0x0102030405060708UL)
          D(2, 0x8001800180018001UL)
          D(3, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x84ce402c09bb5ac0UL); D(1, 0x19a47d2b6b0f233dUL) ]
        [ D(0, 0xe25e59fe439c3bf1UL); D(1, 0xdd330e8525143fe6UL) ]
        [ D(0, 0x0180018001800180UL); D(1, 0xffffff7fffffffffUL) ] ]
    check false "f3b000c2" inputs outputs

  /// <summary>
  /// A8.8.387 VREV64: vrev64.8 q0, q1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.387 VREV64``() =
    let inputs =
      [ [ D(0, 0x92f57b571bf6b4bdUL)
          D(1, 0x69e9a3652707ee22UL)
          D(2, 0x887d07ccaf2e4e47UL)
          D(3, 0x4fce5332adc80b79UL) ]
        [ D(0, 0x73f459ad874f1d83UL)
          D(1, 0xbc7ee98b6f0d4d4eUL)
          D(2, 0xf90d30abc5348f6cUL)
          D(3, 0x221a8c3551204782UL) ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0x0000000000000001UL)
          D(2, 0x7f80ff00807fffffUL)
          D(3, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0x474e2eafcc077d88UL); D(1, 0x790bc8ad3253ce4fUL) ]
        [ D(0, 0x6c8f34c5ab300df9UL); D(1, 0x82472051358c1a22UL) ]
        [ D(0, 0xffff7f8000ff807fUL); D(1, 0xff00ff00ff00ff00UL) ] ]
    check false "f3b00042" inputs outputs

  /// <summary>
  /// A8.8.388 VRHADD: vrhadd.s32 q1, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.388 VRHADD``() =
    let inputs =
      [ [ D(2, 0x0818dd52a8e548a6UL)
          D(3, 0x4ed3d98050826c73UL)
          D(4, 0x9227f1de836a6c39UL)
          D(5, 0x56c2ca59a074ea14UL) ]
        [ D(2, 0x400e3e90bb2f6a77UL)
          D(3, 0x7620210a0ea8547fUL)
          D(4, 0xac3d61e625c797faUL)
          D(5, 0xd0beeb2b8554f67aUL) ]
        [ D(2, 0x7fffffffffffffffUL)
          D(3, 0x00ff00ff00ff00ffUL)
          D(4, 0x7f80ff00807fffffUL)
          D(5, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(2, 0xcd2067989627da70UL); D(3, 0x52cb51edf87bab44UL) ]
        [ D(2, 0xf625d03bf07b8139UL); D(3, 0x236f861bc9fea57dUL) ]
        [ D(2, 0x7fc07f80c03fffffUL); D(3, 0xc0804080c0804080UL) ] ]
    check false "f2222144" inputs outputs

  /// <summary>
  /// A8.8.389 VRSHL: vrshl.s8 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.389 VRSHL``() =
    let inputs =
      [ [ D(0, 0x014ca156c3993f4cUL)
          D(1, 0x65b510f31788a883UL)
          D(2, 0x02f508ff54bc6979UL)
          D(3, 0xa2466fb96156441eUL)
          D(4, 0x0f1d6e324acb8db2UL)
          D(5, 0x611598e438a7b98bUL) ]
        [ D(0, 0x199db6d8eeaea754UL)
          D(1, 0x632c96f550ccab4dUL)
          D(2, 0x38d27dd622d0a500UL)
          D(3, 0x18eb9b1d13e9789aUL)
          D(4, 0x9f7ba29c36c18728UL)
          D(5, 0x5d4310f200823d8eUL) ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0x8000000000000000UL)
          D(2, 0x8000000000000000UL)
          D(3, 0x0000000000000001UL)
          D(4, 0x0000000000000001UL)
          D(5, 0x0000000000000001UL) ] ]
    let outputs =
      [ [ D(0, 0x0000000000000000UL); D(1, 0x0000000000000000UL) ]
        [ D(0, 0x0000000000000000UL); D(1, 0x0000000013000000UL) ]
        [ D(0, 0x8000000000000000UL); D(1, 0x0000000000000002UL) ] ]
    check false "f2040542" inputs outputs

  /// <summary>
  /// A8.8.390 VRSHR: vrshr.s32 d2, d4, #0x1f. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.390 VRSHR``() =
    let inputs =
      [ [ D(2, 0x0f6e6c643f22c542UL); D(4, 0x257a6c0b45c5d05fUL) ]
        [ D(2, 0xb88099fca8f747e3UL); D(4, 0xe09801d4685e1905UL) ]
        [ D(2, 0x00ff00ff00ff00ffUL); D(4, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(2, 0x0000000000000001UL) ]
        [ D(2, 0x0000000000000001UL) ]
        [ D(2, 0x0000000100000000UL) ] ]
    check false "f2a12214" inputs outputs

  /// <summary>
  /// A8.8.391 VRSHRN: vrshrn.i16 d0, q1, #0x1. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.391 VRSHRN``() =
    let inputs =
      [ [ D(0, 0xb95ec055d2621f9aUL)
          D(2, 0xf737f32884bfe382UL)
          D(3, 0xa8e4a58d88de30d0UL) ]
        [ D(0, 0x0de266da0cef0d62UL)
          D(2, 0x01c16e2048abc096UL)
          D(3, 0x922d83f28eca0990UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(2, 0x0102030405060708UL)
          D(3, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x72c76f689c9460c1UL) ]
        [ D(0, 0x17f965c8e110564bUL) ]
        [ D(0, 0x0000000081828384UL) ] ]
    check false "f28f0852" inputs outputs

  /// <summary>
  /// A8.8.392 VRSQRTE: vrsqrte.f32 d0, d1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.392 VRSQRTE``() =
    let inputs =
      [ [ D(0, 0x3e8000003e800000UL)
          D(1, 0x3e80000044800000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xc0100000c0100000UL)
          D(1, 0x3f400000c2400000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3fc0000000000000UL)
          D(1, 0xc0100000ff800000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x3fff80003cff8000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x3f9380007fc00000UL); Cell.FPSCR 0x60000001u ]
        [ D(0, 0x7fc000007fc00000UL); Cell.FPSCR 0x00000001u ] ]
    check false "f3bb0581" inputs outputs

  /// <summary>
  /// A8.8.393 VRSQRTS: vrsqrts.f32 d0, d1, d2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.393 VRSQRTS``() =
    let inputs =
      [ [ D(0, 0x3e00000042c90000UL)
          D(1, 0xc010000040000000UL)
          D(2, 0x414000003fc00000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x41200000bf800000UL)
          D(1, 0xc010000040800000UL)
          D(2, 0x40200000bec00000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7f8000007f800000UL)
          D(1, 0x000000003fc00000UL)
          D(2, 0x4040000000000000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x4170000000000000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x408a000040100000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3fc000003fc00000UL); Cell.FPSCR 0x00000000u ] ]
    check false "f2210f12" inputs outputs

  /// <summary>
  /// A8.8.394 VRSRA: vrsra.s8 q0, q1, #0x1. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.394 VRSRA``() =
    let inputs =
      [ [ D(0, 0x29185ffec19a3b7eUL)
          D(1, 0xe62b6b7e2071aa26UL)
          D(2, 0x023dffc8b4ce551fUL)
          D(3, 0x779a08ab87f2f70bUL) ]
        [ D(0, 0xa202ddb9f8bee9b6UL)
          D(1, 0xca80ae6c388ff48eUL)
          D(2, 0x4ad51ad37017f97dUL)
          D(3, 0x42a3ae14b75bfe64UL) ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0x0102030405060708UL)
          D(2, 0x7f80ff00807fffffUL)
          D(3, 0xffffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x2a375fe29b81668eUL); D(1, 0x22f86f54e46aa62cUL) ]
        [ D(0, 0xc7edeaa330cae6f5UL); D(1, 0xeb52857614bdf3c0UL) ]
        [ D(0, 0xc0c00000c0400000UL); D(1, 0x0102030405060708UL) ] ]
    check false "f28f0352" inputs outputs

  /// <summary>
  /// A8.8.395 VRSUBHN: vrsubhn.i32 d0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.395 VRSUBHN``() =
    let inputs =
      [ [ D(0, 0x978954b3bc0d99d4UL)
          D(2, 0x768d2c4c63eea13fUL)
          D(3, 0x6f3f987aa8de3a14UL)
          D(4, 0xd3d502e2923734f2UL)
          D(5, 0x8ab3a1d28d62b8acUL) ]
        [ D(0, 0x7130b39bde9a8f4aUL)
          D(2, 0x7f969cb8bf369d57UL)
          D(3, 0x6ce08a9537311a67UL)
          D(4, 0x82484dddff6b2becUL)
          D(5, 0xb85146ea30719c99UL) ]
        [ D(0, 0x8001800180018001UL)
          D(2, 0x0000000000000001UL)
          D(3, 0x7fffffffffffffffUL)
          D(4, 0x7f80ff00807fffffUL)
          D(5, 0x0000000000000001UL) ] ]
    let outputs =
      [ [ D(0, 0xe48c1b7ca2b8d1b7UL) ]
        [ D(0, 0xb48f06bffd4ebfcbUL) ]
        [ D(0, 0x80000000807f7f80UL) ] ]
    check false "f3920604" inputs outputs

  /// <summary>
  /// A8.8.396 VSHL: vshl.i8 q0, q1, #0x1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.396 VSHL``() =
    let inputs =
      [ [ D(0, 0x894e1e0c79ec5b12UL)
          D(1, 0xe64701cd0534a80cUL)
          D(2, 0x373cf1a699a13691UL)
          D(3, 0x0119a510a07f6f94UL) ]
        [ D(0, 0x62995182874c3d76UL)
          D(1, 0xd09fde520d4b9ab9UL)
          D(2, 0x408c08abe8198688UL)
          D(3, 0x517b95f470f9f9b1UL) ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0x00ff00ff00ff00ffUL)
          D(2, 0x8001800180018001UL)
          D(3, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0x6e78e24c32426c22UL); D(1, 0x02324a2040fede28UL) ]
        [ D(0, 0x80181056d0320c10UL); D(1, 0xa2f62ae8e0f2f262UL) ]
        [ D(0, 0x0002000200020002UL); D(1, 0x00fe00fe00fe00feUL) ] ]
    check false "f2890552" inputs outputs

  /// <summary>
  /// A8.8.398 VSHLL: vshll.s8 q0, d1, #0x1. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.398 VSHLL``() =
    let inputs =
      [ [ D(0, 0x520479750d09d4a9UL); D(1, 0x1117c560c8e29096UL) ]
        [ D(0, 0xd30e551b11cf5a1eUL); D(1, 0x0a650a87a8d6b543UL) ]
        [ D(0, 0x7fffffffffffffffUL); D(1, 0x7f80ff00807fffffUL) ] ]
    let outputs =
      [ [ D(0, 0xff90ffc4ff20ff2cUL); D(1, 0x0022002eff8a00c0UL) ]
        [ D(0, 0xff50ffacff6a0086UL); D(1, 0x001400ca0014ff0eUL) ]
        [ D(0, 0xff0000fefffefffeUL); D(1, 0x00feff00fffe0000UL) ] ]
    check false "f2890a11" inputs outputs

  /// <summary>
  /// A8.8.399 VSHR: vshr.s32 d2, d4, #0x1f. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.399 VSHR``() =
    let inputs =
      [ [ D(2, 0xd8d3f2c7d7c2424cUL); D(4, 0xbc60268149375531UL) ]
        [ D(2, 0x85e42eaecb70f1b1UL); D(4, 0x9cacc906804942a6UL) ]
        [ D(2, 0x0102030405060708UL); D(4, 0x0102030405060708UL) ] ]
    let outputs =
      [ [ D(2, 0xffffffff00000000UL) ]
        [ D(2, 0xffffffffffffffffUL) ]
        [ D(2, 0x0000000000000000UL) ] ]
    check false "f2a12014" inputs outputs

  /// <summary>
  /// A8.8.400 VSHRN: vshrn.i16 d0, q1, #0x1. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.400 VSHRN``() =
    let inputs =
      [ [ D(0, 0xef13993844e55501UL)
          D(2, 0x07afb87443cb5b8dUL)
          D(3, 0xd0c8442e3b8440bcUL) ]
        [ D(0, 0xdd8cf630550df5e8UL)
          D(2, 0x610cd525c22618efUL)
          D(3, 0x1c807737967c3f25UL) ]
        [ D(0, 0x8000000000000000UL)
          D(2, 0x7f80ff00807fffffUL)
          D(3, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x6417c25ed73ae5c6UL) ]
        [ D(0, 0x409b3e9286921377UL) ]
        [ D(0, 0xffffffffc0803fffUL) ] ]
    check false "f28f0812" inputs outputs

  /// <summary>
  /// A8.8.401 VSLI: vsli.8 q0, q1, #0x1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.401 VSLI``() =
    let inputs =
      [ [ D(0, 0x59129c1e3f15898dUL)
          D(1, 0x244e12fa64e0493eUL)
          D(2, 0x715550123432c166UL)
          D(3, 0x3cf5266c43a93989UL) ]
        [ D(0, 0x183368a4a74408d1UL)
          D(1, 0x938e64f076f89f78UL)
          D(2, 0x2a48abd8a1df2d36UL)
          D(3, 0x812c27c6438c6a3cUL) ]
        [ D(0, 0x0000000000000001UL)
          D(1, 0x0102030405060708UL)
          D(2, 0x0000000000000001UL)
          D(3, 0xffffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0xe3aaa024696583cdUL); D(1, 0x78ea4cd886527312UL) ]
        [ D(0, 0x549156b043be5a6dUL); D(1, 0x03584e8c8618d578UL) ]
        [ D(0, 0x0000000000000003UL); D(1, 0xfffefffefffefffeUL) ] ]
    check false "f3890552" inputs outputs

  /// <summary>
  /// A8.8.402 VSQRT: vsqrt.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.402 VSQRT``() =
    let inputs =
      [ [ D(0, 0xc240000040c00000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x4140000044800000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x8000000080000000UL); Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xc24000007fc00000UL); Cell.FPSCR 0x00000001u ]
        [ D(0, 0x41400000405db3d7UL); Cell.FPSCR 0x60000010u ]
        [ D(0, 0x8000000080000000UL); Cell.FPSCR 0x00000000u ] ]
    check false "eeb10ae0" inputs outputs

  /// <summary>
  /// A8.8.403 VSRA: vsra.s8 q0, q1, #0x1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.403 VSRA``() =
    let inputs =
      [ [ D(0, 0x7e2e30565dbc8febUL)
          D(1, 0x087603bc220715ebUL)
          D(2, 0x97b069ff1448a2f4UL)
          D(3, 0x4db7158e29dce822UL) ]
        [ D(0, 0x42c538b6a44d8181UL)
          D(1, 0x747634d5c04c9376UL)
          D(2, 0x25f38d572d2b9570UL)
          D(3, 0xde5163dc7940ab24UL) ]
        [ D(0, 0xffffffffffffffffUL)
          D(1, 0x7fffffffffffffffUL)
          D(2, 0x7fffffffffffffffUL)
          D(3, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0x4906645567e060e5UL); D(1, 0x2e510d8336f509fcUL) ]
        [ D(0, 0x54befee1ba624bb9UL); D(1, 0x639e65c3fc6c6888UL) ]
        [ D(0, 0x3efefefefefefefeUL); D(1, 0x7ffefffefffefffeUL) ] ]
    check false "f28f0152" inputs outputs

  /// <summary>
  /// A8.8.404 VSRI: vsri.8 q0, q1, #0x1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.404 VSRI``() =
    let inputs =
      [ [ D(0, 0x443a15fe77524705UL)
          D(1, 0x2d5565b2d89936ecUL)
          D(2, 0xec078401ec5cd015UL)
          D(3, 0x8795dc548c922f3dUL) ]
        [ D(0, 0xec9c4d40f36bc973UL)
          D(1, 0x7b7fd3761fe52a44UL)
          D(2, 0x27b28ac8e4a31955UL)
          D(3, 0x8a40a2548220fe63UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x7fffffffffffffffUL)
          D(2, 0x8001800180018001UL)
          D(3, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0x76034280762e680aUL); D(1, 0x434a6eaac6c9179eUL) ]
        [ D(0, 0x93d94564f2518c2aUL); D(1, 0x4520d12a41907f31UL) ]
        [ D(0, 0x4080c000c000c080UL); D(1, 0x00ff80ff80ff80ffUL) ] ]
    check false "f38f0452" inputs outputs

  /// <summary>
  /// A8.8.405 VST1: vst1.8 {d0}, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.405 VST1``() =
    let inputs =
      [ [ Gpr(1, 0x20000810u)
          D(0, 0xc81687b8189b7ad3UL)
          M(0, 0xb873a7e1387dc8bfUL)
          M(8, 0xe8a2d3e73f42f85eUL)
          M(16, 0xb49990bfceef2c68UL)
          M(24, 0xb5bfaf05ae4f98d5UL)
          M(32, 0x508a3c2f7d90484dUL)
          M(40, 0x61f2a972562591a6UL)
          M(48, 0x100cec07294e5b99UL)
          M(56, 0xcc817018887719d6UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x87abb58e698f2200UL)
          M(0, 0xbf3c0952ec371973UL)
          M(8, 0x5d24e3bda58c4073UL)
          M(16, 0x8c51ec73221c9fa8UL)
          M(24, 0xd02f3444782da932UL)
          M(32, 0xba42870de28152dcUL)
          M(40, 0xf2f30edff8af6d38UL)
          M(48, 0x25d7998a0eec1d76UL)
          M(56, 0x776a80a1626ed7b9UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x7f80ff00807fffffUL)
          M(0, 0xd6a0fd4a8d47dafdUL)
          M(8, 0xca8c9e4f52f3d4dbUL)
          M(16, 0x744010f080154440UL)
          M(24, 0x2133474bd8e58ab9UL)
          M(32, 0x1366e0e9c363f5d3UL)
          M(40, 0xbed8291ad38bc3b5UL)
          M(48, 0xcb3c3eb830019600UL)
          M(56, 0xfa156b41080d8ebbUL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000810u); M(16, 0xc81687b8189b7ad3UL) ]
        [ Gpr(1, 0x20000810u); M(16, 0x87abb58e698f2200UL) ]
        [ Gpr(1, 0x20000810u); M(16, 0x7f80ff00807fffffUL) ] ]
    check false "f401070f" inputs outputs

  /// <summary>
  /// A8.8.407 VST2: vst2.8 {d0, d1}, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.407 VST2``() =
    let inputs =
      [ [ Gpr(1, 0x20000810u)
          D(0, 0x9fed5ee8bc843367UL)
          D(1, 0x9e27b8e2ed94763aUL)
          M(0, 0x6ee5f018ff523b09UL)
          M(8, 0x7fb5223b74757476UL)
          M(16, 0x65317b04c57369c1UL)
          M(24, 0x7d879e1994bc4127UL)
          M(32, 0x20cf00b2ed586e38UL)
          M(40, 0x1224671e692494fcUL)
          M(48, 0xa68b2b22707ec6aeUL)
          M(56, 0x5ff8c61887aacb3fUL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x7f02832685081303UL)
          D(1, 0xde9dbe04d0c8b3d9UL)
          M(0, 0x5c8841e46c4550ceUL)
          M(8, 0x7ab131d0f9ab6e2dUL)
          M(16, 0x0a6fa99cf30f2be4UL)
          M(24, 0x681347e6b0bbb990UL)
          M(32, 0x9ad7c3fd0842cffbUL)
          M(40, 0x55c8094bc7abb431UL)
          M(48, 0x322c078f2f3ed6ddUL)
          M(56, 0x5418568dbf3e544cUL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x00ff00ff00ff00ffUL)
          D(1, 0x0102030405060708UL)
          M(0, 0x3eea7321833b8f00UL)
          M(8, 0x3e98d429a98c9e65UL)
          M(16, 0x695b760a87c2797dUL)
          M(24, 0xbf56ad3d7900b8e1UL)
          M(32, 0x76bd10b77dd07971UL)
          M(40, 0xdc8c4291f3e9c15bUL)
          M(48, 0xa5a768d4c9b34825UL)
          M(56, 0xdf33186d621d1b78UL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000810u)
          M(16, 0xedbc948476333a67UL)
          M(24, 0x9e9f27edb85ee2e8UL) ]
        [ Gpr(1, 0x20000810u)
          M(16, 0xd085c808b313d903UL)
          M(24, 0xde7f9d02be830426UL) ]
        [ Gpr(1, 0x20000810u)
          M(16, 0x050006ff070008ffUL)
          M(24, 0x010002ff030004ffUL) ] ]
    check false "f401080f" inputs outputs

  /// <summary>
  /// A8.8.409 VST3: vst3.8 {d0, d1, d2}, [r1]. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.409 VST3``() =
    let inputs =
      [ [ Gpr(1, 0x20000810u)
          D(0, 0x1cb019db55ed5c6cUL)
          D(1, 0x81f7ee669fbcd9b3UL)
          D(2, 0xcaf0d332082dbf42UL)
          M(0, 0x76d538f5581a1086UL)
          M(8, 0xe774ffe0d6091917UL)
          M(16, 0xd88c72b788ed69e2UL)
          M(24, 0xe8886096b628c7a0UL)
          M(32, 0xd278d96bece7f1b4UL)
          M(40, 0x00997e5d67a7db32UL)
          M(48, 0xd62c1ff9b8d7aa67UL)
          M(56, 0x9ab93960e510baf3UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0xa92055884fa12055UL)
          D(1, 0x238f384cafe3d884UL)
          D(2, 0xd8aaf2a140848849UL)
          M(0, 0xa19a286d83ad4ccaUL)
          M(8, 0x044296510848e074UL)
          M(16, 0xfdc9b77d5d5b0d72UL)
          M(24, 0x47ea9e0b04467ac9UL)
          M(32, 0xd12c4e5f797fb8f8UL)
          M(40, 0x7fb0b0189137570aUL)
          M(48, 0xe6bda5f8d20b1f9bUL)
          M(56, 0xb3254558b8a6eb64UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0xffffffffffffffffUL)
          D(1, 0x00ff00ff00ff00ffUL)
          D(2, 0x8000000000000000UL)
          M(0, 0x32a67d82b2bd9ee1UL)
          M(8, 0xda9628fe09e93714UL)
          M(16, 0x231fa93f9cdaf054UL)
          M(24, 0x9b8235c1c660450fUL)
          M(32, 0xc595a42d79bff805UL)
          M(40, 0xa39a866b9ef816f1UL)
          M(48, 0x032e0eb1f668a93dUL)
          M(56, 0xdaf524ce4d8e0db0UL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000810u)
          M(16, 0xbcedbfd95c42b36cUL)
          M(24, 0x193266db089f552dUL)
          M(32, 0xca811cf0f7b0d3eeUL) ]
        [ Gpr(1, 0x20000810u)
          M(16, 0xe3a188d820498455UL)
          M(24, 0x55a14c8840af4f84UL)
          M(32, 0xd823a9aa8f20f238UL) ]
        [ Gpr(1, 0x20000810u)
          M(16, 0xffff0000ff00ffffUL)
          M(24, 0xff00ffff0000ff00UL)
          M(32, 0x8000ff00ffff0000UL) ] ]
    check false "f401040f" inputs outputs

  /// <summary>
  /// A8.8.411 VST4: vst4.8 {d0, d1, d2, d3}, [r1]. The outputs are what QEMU
  /// left after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.411 VST4``() =
    let inputs =
      [ [ Gpr(1, 0x20000810u)
          D(0, 0xd9ebf535901f2dabUL)
          D(1, 0x00cf39102482b417UL)
          D(2, 0x684028d018bd7a70UL)
          D(3, 0x98ed5f42d6491acdUL)
          M(0, 0xac8bfbbf0026870dUL)
          M(8, 0x7748f8edfcfa242aUL)
          M(16, 0x2c4a922b584dd61dUL)
          M(24, 0x2fed19877ac1151cUL)
          M(32, 0xa037a9a66f2d350aUL)
          M(40, 0xc1ed81c820a3c9eeUL)
          M(48, 0x9add4b529b498ef9UL)
          M(56, 0xe603c48503cfe133UL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x1d85611341ef2e2bUL)
          D(1, 0xdda2010715a18cd3UL)
          D(2, 0xe9db2a132e06ef29UL)
          D(3, 0x6dfb482502895ffaUL)
          M(0, 0xace39f6efd19c849UL)
          M(8, 0x7eeba68b2d344bc6UL)
          M(16, 0x547f6fc40c512caaUL)
          M(24, 0xc194fc70be800f0aUL)
          M(32, 0x9c91f2f8c13be28dUL)
          M(40, 0x9a245c77befcbe8dUL)
          M(48, 0xfd33fb734b8c324eUL)
          M(56, 0x97ac8d5f670640daUL) ]
        [ Gpr(1, 0x20000810u)
          D(0, 0x0000000000000001UL)
          D(1, 0x7f80ff00807fffffUL)
          D(2, 0x8000000000000000UL)
          D(3, 0x7f80ff00807fffffUL)
          M(0, 0x6a873d9c5bc02fa4UL)
          M(8, 0x3506d1bc52c29ed7UL)
          M(16, 0x0365d0d8d5210488UL)
          M(24, 0x331ba257f021aff6UL)
          M(32, 0x40aad3653407aedaUL)
          M(40, 0x233c0e72514cfd4fUL)
          M(48, 0xb9681cbb0b288d6fUL)
          M(56, 0xb9538c6127ebfb52UL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000810u)
          M(16, 0x1a7ab42dcd7017abUL)
          M(24, 0xd618249049bd821fUL)
          M(32, 0x5f2839f542d01035UL)
          M(40, 0x986800d9ed40cfebUL) ]
        [ Gpr(1, 0x20000810u)
          M(16, 0x5fef8c2efa29d32bUL)
          M(24, 0x022e15418906a1efUL)
          M(32, 0x482a016125130713UL)
          M(40, 0x6de9dd1dfbdba285UL) ]
        [ Gpr(1, 0x20000810u)
          M(16, 0xff00ff00ff00ff01UL)
          M(24, 0x800080007f007f00UL)
          M(32, 0xff00ff0000000000UL)
          M(40, 0x7f807f0080008000UL) ] ]
    check false "f401000f" inputs outputs

  /// <summary>
  /// A8.8.413 VSTM: vstmia r1, {s0, s1, s2, s3}. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.413 VSTM``() =
    let inputs =
      [ [ Gpr(1, 0x20000818u)
          D(0, 0x44c67f3d988f1ba9UL)
          D(1, 0x31c1bc0b21f12996UL)
          M(0, 0x8e4f33ef81461b7eUL)
          M(8, 0x8b498304512f8278UL)
          M(16, 0xba037898f678082dUL)
          M(24, 0x20f441b93b0046e0UL)
          M(32, 0x0b4654c56e02a738UL)
          M(40, 0xa2a7cf02fb38b269UL)
          M(48, 0x173b0aae318abfbfUL)
          M(56, 0x6d41d20044b6cb54UL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0x3f23f4d623cb4199UL)
          D(1, 0x4d742de38bbc5f9cUL)
          M(0, 0xd7bde531c6dedfbaUL)
          M(8, 0xb2c578f1efac86f1UL)
          M(16, 0x81b8e8c7465b8144UL)
          M(24, 0x07d055de8258003bUL)
          M(32, 0x875eefa48d110953UL)
          M(40, 0x004fb7d00079e71cUL)
          M(48, 0x1579020c5e2d6bedUL)
          M(56, 0x55d1c12f78bc623eUL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0x7fffffffffffffffUL)
          D(1, 0x8000000000000000UL)
          M(0, 0x060a73194f8b13e9UL)
          M(8, 0xe5174cc528babdf8UL)
          M(16, 0x8524eff3847b1e82UL)
          M(24, 0x260f9a68edd6ba04UL)
          M(32, 0xe00fdb5fcce06decUL)
          M(40, 0x2d6fcdbd69cf2db2UL)
          M(48, 0xe78002e91b31e629UL)
          M(56, 0x66554dd27dec02abUL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000818u)
          M(24, 0x44c67f3d988f1ba9UL)
          M(32, 0x31c1bc0b21f12996UL) ]
        [ Gpr(1, 0x20000818u)
          M(24, 0x3f23f4d623cb4199UL)
          M(32, 0x4d742de38bbc5f9cUL) ]
        [ Gpr(1, 0x20000818u)
          M(24, 0x7fffffffffffffffUL)
          M(32, 0x8000000000000000UL) ] ]
    check false "ec810a04" inputs outputs

  /// <summary>
  /// A8.8.414 VSTR: vstr d0, [r1, #8]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.414 VSTR``() =
    let inputs =
      [ [ Gpr(1, 0x20000808u)
          D(0, 0x34843c9c99df8264UL)
          M(0, 0x7071a01abae6c42dUL)
          M(8, 0x090fb1beeb4ac693UL)
          M(16, 0x8188f04a41ab4dacUL)
          M(24, 0xeb166cb14337278bUL)
          M(32, 0x901ffa70498d771eUL)
          M(40, 0x22e081fe4a09531bUL)
          M(48, 0xa5e73423d086ac91UL)
          M(56, 0xfb3af1068d4f8638UL) ]
        [ Gpr(1, 0x20000808u)
          D(0, 0x6b29df7c41995380UL)
          M(0, 0x157e9f22902648e6UL)
          M(8, 0xd2eb850ed6a64c0aUL)
          M(16, 0x5e5aecf52ef40cf8UL)
          M(24, 0x3958ca1fde7663f6UL)
          M(32, 0x8171b116e37a9725UL)
          M(40, 0xf8a2b00f240ef833UL)
          M(48, 0x28970ed86daf36e0UL)
          M(56, 0x5229e30dada912acUL) ]
        [ Gpr(1, 0x20000808u)
          D(0, 0x8000000000000000UL)
          M(0, 0xd926077cac41e30eUL)
          M(8, 0x8f8d3b27ad88e9deUL)
          M(16, 0x95db823b059fad8cUL)
          M(24, 0xc726cba552f075ceUL)
          M(32, 0xa77f8b6176f7f42eUL)
          M(40, 0x82b863f23c4a0cd5UL)
          M(48, 0x7eb5c841ab8a40bcUL)
          M(56, 0xf8cb4ed1ac7e2cecUL) ] ]
    let outputs =
      [ [ M(16, 0x34843c9c99df8264UL) ]
        [ M(16, 0x6b29df7c41995380UL) ]
        [ M(16, 0x8000000000000000UL) ] ]
    check false "ed810b02" inputs outputs

  /// <summary>
  /// A8.8.415 VSUB: vsub.f32 s0, s1, s2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.415 VSUB``() =
    let inputs =
      [ [ D(0, 0x3fe00000c0100000UL)
          D(1, 0xbf800000c2400000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xc06000003d800000UL)
          D(1, 0x4480000044800000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3f0000003f000000UL)
          D(1, 0x3f00000000000000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x3fe0000042470000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0xc0600000c4807000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3f0000003f000000UL); Cell.FPSCR 0x00000000u ] ]
    check false "ee300ac1" inputs outputs

  /// <summary>
  /// A8.8.417 VSUBHN: vsubhn.i32 d0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.417 VSUBHN``() =
    let inputs =
      [ [ D(0, 0xcf3849858be1b545UL)
          D(2, 0x9bd6eb47e16dfa0fUL)
          D(3, 0x5e8ec89c85de1317UL)
          D(4, 0x46c2e71b3d32b430UL)
          D(5, 0xdc1d6985c46fbc94UL) ]
        [ D(0, 0x4d57c944130a0065UL)
          D(2, 0x4a8fdfe817b8a629UL)
          D(3, 0x32fc2059f7a5716fUL)
          D(4, 0x581a8f70097287bfUL)
          D(5, 0x467b90551cc42308UL) ]
        [ D(0, 0x7fffffffffffffffUL)
          D(2, 0x0000000000000001UL)
          D(3, 0x00ff00ff00ff00ffUL)
          D(4, 0x7fffffffffffffffUL)
          D(5, 0x7f80ff00807fffffUL) ] ]
    let outputs =
      [ [ D(0, 0x8271c16e5514a43bUL) ]
        [ D(0, 0xec80dae1f2750e46UL) ]
        [ D(0, 0x817e807f80000000UL) ] ]
    check false "f2920604" inputs outputs

  /// <summary>
  /// A8.8.418 VSUBL: vsubl.s32 q0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.418 VSUBL``() =
    let inputs =
      [ [ D(0, 0x25e4b1369ac3d5c5UL)
          D(1, 0x4f14d1835777e3a5UL)
          D(2, 0x6fe1604d791ec2c6UL) ]
        [ D(0, 0x93e387c3aeba78f7UL)
          D(1, 0xa204957b0201ad25UL)
          D(2, 0xf9678778a3b87192UL) ]
        [ D(0, 0x0102030405060708UL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0xffffffffde5920dfUL); D(1, 0xffffffffdf337136UL) ]
        [ D(0, 0x000000005e493b93UL); D(1, 0xffffffffa89d0e03UL) ]
        [ D(0, 0xffffffffff00ff00UL); D(1, 0xffffffffff00ff00UL) ] ]
    check false "f2a10202" inputs outputs

  /// <summary>
  /// A8.8.418 VSUBW: vsubw.s8 q0, q0, d1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.418 VSUBW``() =
    let inputs =
      [ [ D(0, 0x70304e839f2165b5UL); D(1, 0xadc0885b609fe3d2UL) ]
        [ D(0, 0x85a1b096505509e0UL); D(1, 0x82c7e011bf4365cfUL) ]
        [ D(0, 0x8001800180018001UL); D(1, 0x0000000000000001UL) ] ]
    let outputs =
      [ [ D(0, 0x6fd04ee49f3e65e3UL); D(1, 0xae13889b6117e377UL) ]
        [ D(0, 0x85e2b0534ff00a11UL); D(1, 0x8345e04abf6365beUL) ]
        [ D(0, 0x8001800180018000UL); D(1, 0x0000000000000001UL) ] ]
    check false "f2800301" inputs outputs

  /// <summary>
  /// A8.8.419 VSWP: vswp q0, q1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.419 VSWP``() =
    let inputs =
      [ [ D(0, 0xbfcd0832405e4f85UL)
          D(1, 0x4c75673b5c776c3bUL)
          D(2, 0xebec652c4493095aUL)
          D(3, 0xc91dded8e26d5e2fUL) ]
        [ D(0, 0x310cb2039720ca99UL)
          D(1, 0x5d528fb24368ac83UL)
          D(2, 0x2381d9bad8b2eb84UL)
          D(3, 0xe36a4de5c2e79c74UL) ]
        [ D(0, 0x00ff00ff00ff00ffUL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x7fffffffffffffffUL)
          D(3, 0x8000000000000000UL) ] ]
    let outputs =
      [ [ D(0, 0xebec652c4493095aUL)
          D(1, 0xc91dded8e26d5e2fUL)
          D(2, 0xbfcd0832405e4f85UL)
          D(3, 0x4c75673b5c776c3bUL) ]
        [ D(0, 0x2381d9bad8b2eb84UL)
          D(1, 0xe36a4de5c2e79c74UL)
          D(2, 0x310cb2039720ca99UL)
          D(3, 0x5d528fb24368ac83UL) ]
        [ D(0, 0x7fffffffffffffffUL)
          D(1, 0x8000000000000000UL)
          D(2, 0x00ff00ff00ff00ffUL)
          D(3, 0xffffffffffffffffUL) ] ]
    check false "f3b20042" inputs outputs

  /// <summary>
  /// A8.8.420 VTBL: vtbl.8 d0, {d1}, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.420 VTBL``() =
    let inputs =
      [ [ D(0, 0x2899e80e3892b370UL)
          D(1, 0x2e80bc9dd6830b41UL)
          D(2, 0xbe9283ddb0a3f202UL) ]
        [ D(0, 0x998ad0c761a44e0fUL)
          D(1, 0x4bfab8b1a069d893UL)
          D(2, 0x1855b0e51cc06ab1UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x8000000000000000UL)
          D(2, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x0000000000000083UL) ]
        [ D(0, 0x0000000000000000UL) ]
        [ D(0, 0x0000000000000000UL) ] ]
    check false "f3b10802" inputs outputs

  /// <summary>
  /// A8.8.420 VTBX: vtbx.8 d0, {d1}, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.420 VTBX``() =
    let inputs =
      [ [ D(0, 0xad9e4ece8c5764d4UL)
          D(1, 0x7a5b626d65fc8b89UL)
          D(2, 0x0f36c6f2ad64d125UL) ]
        [ D(0, 0x44c8bde09518b949UL)
          D(1, 0xe03c5f92f92f8b51UL)
          D(2, 0x45ee01d4a3cb913cUL) ]
        [ D(0, 0x0102030405060708UL)
          D(1, 0x0000000000000001UL)
          D(2, 0x7f80ff00807fffffUL) ] ]
    let outputs =
      [ [ D(0, 0xad9e4ece8c5764d4UL) ]
        [ D(0, 0x44c88be09518b949UL) ]
        [ D(0, 0x0102030105060708UL) ] ]
    check false "f3b10842" inputs outputs

  /// <summary>
  /// A8.8.421 VTRN: vtrn.8 q0, q1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.421 VTRN``() =
    let inputs =
      [ [ D(0, 0x1bf6050411880d32UL)
          D(1, 0x4e528acb75efb270UL)
          D(2, 0xeed669703032a77fUL)
          D(3, 0x071894c53ba7cef8UL) ]
        [ D(0, 0x9bef6c3f77db5349UL)
          D(1, 0xee5f0faa1a5f81e4UL)
          D(2, 0x95ea20efb15010d8UL)
          D(3, 0xd920eea139287a10UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x7f80ff00807fffffUL)
          D(2, 0x8000000000000000UL)
          D(3, 0xffffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0xd6f6700432887f32UL)
          D(1, 0x1852c5cba7eff870UL)
          D(2, 0xee1b69053011a70dUL)
          D(3, 0x074e948a3b75ceb2UL) ]
        [ D(0, 0xeaefef3f50dbd849UL)
          D(1, 0x205fa1aa285f10e4UL)
          D(2, 0x959b206cb1771053UL)
          D(3, 0xd9eeee0f391a7a81UL) ]
        [ D(0, 0x00800000007f00ffUL)
          D(1, 0xff80ff00ff7fffffUL)
          D(2, 0x807f00ff008000ffUL)
          D(3, 0xff7fffffff80ffffUL) ] ]
    check false "f3b200c2" inputs outputs

  /// <summary>
  /// A8.8.422 VTST: vtst.8 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.422 VTST``() =
    let inputs =
      [ [ D(0, 0xa5537c0b2dbe226fUL)
          D(1, 0xb0764bef9cc7bedbUL)
          D(2, 0xe94af54229b61773UL)
          D(3, 0x34cf6e882aff9237UL)
          D(4, 0xeae0f30dfab48431UL)
          D(5, 0x8eb83348375b67d8UL) ]
        [ D(0, 0xb69aee3698100f59UL)
          D(1, 0x58a8f083e2671e41UL)
          D(2, 0xa367000990e72d88UL)
          D(3, 0xa715c5dbea71b4e1UL)
          D(4, 0xa0a8dc88263bab17UL)
          D(5, 0x6b76a377c34bee2cUL) ]
        [ D(0, 0x7fffffffffffffffUL)
          D(1, 0x00ff00ff00ff00ffUL)
          D(2, 0x8000000000000000UL)
          D(3, 0x0102030405060708UL)
          D(4, 0x8000000000000000UL)
          D(5, 0x0102030405060708UL) ] ]
    let outputs =
      [ [ D(0, 0xffffff00ffffffffUL); D(1, 0xffffffffffffffffUL) ]
        [ D(0, 0xffff00ff00ffff00UL); D(1, 0xffffffffffffffffUL) ]
        [ D(0, 0xff00000000000000UL); D(1, 0xffffffffffffffffUL) ] ]
    check false "f2020854" inputs outputs

  /// <summary>
  /// A8.8.423 VUZP: vuzp.8 q0, q1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.423 VUZP``() =
    let inputs =
      [ [ D(0, 0x76f4f51a271863e0UL)
          D(1, 0x2049f4b9874a1c91UL)
          D(2, 0xfe7717a75c0f3255UL)
          D(3, 0xd4d6b69265c0cd60UL) ]
        [ D(0, 0xe949263359af6b33UL)
          D(1, 0x793d85175ec92f58UL)
          D(2, 0x4b53aa4cddd1224eUL)
          D(3, 0xad69319f5793df67UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x7f80ff00807fffffUL)
          D(2, 0x8000000000000000UL)
          D(3, 0xffffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x49b94a91f41a18e0UL)
          D(1, 0xd692c06077a70f55UL)
          D(2, 0x20f4871c76f52763UL)
          D(3, 0xd4b665cdfe175c32UL) ]
        [ D(0, 0x3d17c9584933af33UL)
          D(1, 0x699f9367534cd14eUL)
          D(2, 0x79855e2fe926596bUL)
          D(3, 0xad3157df4baadd22UL) ]
        [ D(0, 0x80007fff80007fffUL)
          D(1, 0xffffffff00000000UL)
          D(2, 0x7fff80ff7fff80ffUL)
          D(3, 0xffffffff80000000UL) ] ]
    check false "f3b20142" inputs outputs

  /// <summary>
  /// A8.8.424 VZIP: vzip.8 q0, q1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.424 VZIP``() =
    let inputs =
      [ [ D(0, 0xcb0e77fbcbe6b2dfUL)
          D(1, 0x86e452c04f4e266fUL)
          D(2, 0x9b7c7be1a03e78c0UL)
          D(3, 0x31addc63a6400c50UL) ]
        [ D(0, 0x2d404a79c380f090UL)
          D(1, 0x778bb773e945f5e0UL)
          D(2, 0x12ed3f1cfe9e9fe8UL)
          D(3, 0xf9fac96fab62c931UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x8000000000000000UL)
          D(2, 0x7fffffffffffffffUL)
          D(3, 0x8000000000000000UL) ] ]
    let outputs =
      [ [ D(0, 0xa0cb3ee678b2c0dfUL)
          D(1, 0x9bcb7c0e7b77e1fbUL)
          D(2, 0xa64f404e0c26506fUL)
          D(3, 0x3186ade4dc5263c0UL) ]
        [ D(0, 0xfec39e809ff0e890UL)
          D(1, 0x122ded403f4a1c79UL)
          D(2, 0xabe96245c9f531e0UL)
          D(3, 0xf977fa8bc9b76f73UL) ]
        [ D(0, 0xff80ff7fffffffffUL)
          D(1, 0x7f7fff80ffffff00UL)
          D(2, 0x0000000000000000UL)
          D(3, 0x8080000000000000UL) ] ]
    check false "f3b201c2" inputs outputs

  /// <summary>
  /// A8.8.425 WFE: wfe. It lifts to no statements: what it does is a hint or an
  /// ordering of memory accesses that one run cannot observe, and QEMU's runs
  /// of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.425 WFE``() =
    Assert.AreEqual(0, (lift false "e320f002").Length)

  /// <summary>
  /// A8.8.426 WFI: wfi. It lifts to no statements: what it does is a hint or an
  /// ordering of memory accesses that one run cannot observe, and QEMU's runs
  /// of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.426 WFI``() =
    Assert.AreEqual(0, (lift false "e320f003").Length)

  /// <summary>
  /// A8.8.427 YIELD: yield. It lifts to no statements: what it does is a hint
  /// or an ordering of memory accesses that one run cannot observe, and QEMU's
  /// runs of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.427 YIELD``() =
    Assert.AreEqual(0, (lift false "e320f001").Length)

  /// <summary>
  /// F5.1.1 ADCS: adcs r0, r1, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.1 ADCS``() =
    let inputs =
      [ [ Gpr(0, 0x4128e91fu)
          Gpr(1, 0xa6fa4bf0u)
          Gpr(2, 0xa14662f0u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x192afffcu)
          Gpr(1, 0x6e4d9f8cu)
          Gpr(2, 0xf50b5b6fu)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x4840aee1u); Cell.CPSR 0x30000010u ]
        [ Gpr(0, 0x6358fafbu); Cell.CPSR 0x200a0010u ]
        [ Gpr(0, 0x80000000u); Cell.CPSR 0x98050010u ] ]
    check false "e0b10002" inputs outputs

  /// <summary>
  /// F5.1.4 ADDS: adds r1, r1, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.4 ADDS``() =
    let inputs =
      [ [ Gpr(1, 0x228453e0u); Gpr(2, 0x77f62eddu); Cell.CPSR 0x20000010u ]
        [ Gpr(1, 0x9509b2a4u); Gpr(2, 0x13e2a296u); Cell.CPSR 0x900a0010u ]
        [ Gpr(1, 0x00008000u); Gpr(2, 0x7fff8000u); Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(1, 0x9a7a82bdu); Cell.CPSR 0x90000010u ]
        [ Gpr(1, 0xa8ec553au); Cell.CPSR 0x800a0010u ]
        [ Gpr(1, 0x80000000u); Cell.CPSR 0x98050010u ] ]
    check false "e0911002" inputs outputs

  /// <summary>
  /// F5.1.11 ANDS: ands r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.11 ANDS``() =
    let inputs =
      [ [ Gpr(0, 0x7aa3a745u)
          Gpr(1, 0xab00eb4au)
          Gpr(2, 0xd5214273u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xa8bc3ab5u)
          Gpr(1, 0x96fecd6fu)
          Gpr(2, 0x9b7c0c31u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x81004242u); Cell.CPSR 0xa0000010u ]
        [ Gpr(0, 0x927c0c21u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00008000u); Cell.CPSR 0x08050010u ] ]
    check false "e0110002" inputs outputs

  /// <summary>
  /// F5.1.16 ASRS: asrs r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.16 ASRS``() =
    let inputs =
      [ [ Gpr(0, 0x80ca8f87u)
          Gpr(1, 0x99254a54u)
          Gpr(2, 0x91229f4cu)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x708ba151u)
          Gpr(1, 0xbf021a22u)
          Gpr(2, 0xa5644eefu)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xffffffffu); Cell.CPSR 0xa0000010u ]
        [ Gpr(0, 0xffffffffu); Cell.CPSR 0xb00a0010u ]
        [ Gpr(0, 0x00008000u); Cell.CPSR 0x08050010u ] ]
    check false "e1b00251" inputs outputs

  /// <summary>
  /// F5.1.21 BICS: bics r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.21 BICS``() =
    let inputs =
      [ [ Gpr(0, 0x341eb3ceu)
          Gpr(1, 0x28661f69u)
          Gpr(2, 0x8a18f21cu)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xf8474a15u)
          Gpr(1, 0xa65e9ae4u)
          Gpr(2, 0x5b8f94dfu)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x20660d61u); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xa4500a20u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000000u); Cell.CPSR 0x48050010u ] ]
    check false "e1d10002" inputs outputs

  /// <summary>
  /// F5.1.38 CPSID: cpsid if, #0x13. This checks that from System mode it masks
  /// IRQ and FIQ and enters Supervisor mode, and that in User mode it changes
  /// nothing. It is not a value test because it needs a privileged mode, which
  /// a user-mode run does not have.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.38 CPSID``() =
    let user = runWith false "f10e00d3" [ Cell.CPSR 0x10u ] []
    let system = runWith false "f10e00d3" [ Cell.CPSR 0x1fu ] []
    Assert.AreEqual(Cell.CPSR 0x10u, user.After(Cell.CPSR 0u))
    Assert.AreEqual(Cell.CPSR 0xd3u, system.After(Cell.CPSR 0u))

  /// <summary>
  /// F5.1.38 CPSIE: cpsie i. This checks that it unmasks IRQ in Supervisor mode
  /// and that in User mode it changes nothing. It is not a value test because
  /// it needs a privileged mode, which a user-mode run does not have.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.38 CPSIE``() =
    let user = runWith false "f1080080" [ Cell.CPSR 0x90u ] []
    let svc = runWith false "f1080080" [ Cell.CPSR 0x93u ] []
    Assert.AreEqual(Cell.CPSR 0x90u, user.After(Cell.CPSR 0u))
    Assert.AreEqual(Cell.CPSR 0x13u, svc.After(Cell.CPSR 0u))

  /// <summary>
  /// F5.1.39 CRC32: crc32w r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.39 CRC32``() =
    let inputs =
      [ [ Gpr(0, 0xb0a0ae68u); Gpr(1, 0xb30c1f4au); Gpr(2, 0xddcd7798u) ]
        [ Gpr(0, 0xcbb3a351u); Gpr(1, 0x4ccfdd3au); Gpr(2, 0x3d44fd43u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xb27241dau) ]
        [ Gpr(0, 0xd10fa9dcu) ]
        [ Gpr(0, 0xb2ab8a5fu) ] ]
    check false "e1410042" inputs outputs

  /// <summary>
  /// F5.1.40 CRC32C: crc32cw r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.40 CRC32C``() =
    let inputs =
      [ [ Gpr(0, 0xacb3c881u); Gpr(1, 0x12dcf8f6u); Gpr(2, 0xdb37da7eu) ]
        [ Gpr(0, 0xf1bf7f82u); Gpr(1, 0xb49a5096u); Gpr(2, 0xe69c5d2fu) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x635c4a16u) ]
        [ Gpr(0, 0x9dff5660u) ]
        [ Gpr(0, 0xb0d78fd1u) ] ]
    check false "e1410242" inputs outputs

  /// <summary>
  /// F5.1.43 DCPS1: dcps1. This checks that it takes the Undefined Instruction
  /// exception. It is not a value test because it takes an exception, which a
  /// user-mode run cannot return from.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.43 DCPS1``() =
    let run = runWith true "f78f8001" [ Cell.CPSR 0x10u ] []
    Assert.AreEqual(Some SideEffect.UndefinedInstruction, run.Effect)

  /// <summary>
  /// F5.1.44 DCPS2: dcps2. This checks that it takes the Undefined Instruction
  /// exception. It is not a value test because it takes an exception, which a
  /// user-mode run cannot return from.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.44 DCPS2``() =
    let run = runWith true "f78f8002" [ Cell.CPSR 0x10u ] []
    Assert.AreEqual(Some SideEffect.UndefinedInstruction, run.Effect)

  /// <summary>
  /// F5.1.45 DCPS3: dcps3. This checks that it takes the Undefined Instruction
  /// exception. It is not a value test because it takes an exception, which a
  /// user-mode run cannot return from.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.45 DCPS3``() =
    let run = runWith true "f78f8003" [ Cell.CPSR 0x10u ] []
    Assert.AreEqual(Some SideEffect.UndefinedInstruction, run.Effect)

  /// <summary>
  /// F5.1.48 EORS: eors r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.48 EORS``() =
    let inputs =
      [ [ Gpr(0, 0x6edfdb79u)
          Gpr(1, 0x90073113u)
          Gpr(2, 0xbf5d8ea2u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xadefba22u)
          Gpr(1, 0x62ec6571u)
          Gpr(2, 0xa8355e59u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x2f5abfb1u); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xcad93b28u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff0000u); Cell.CPSR 0x08050010u ] ]
    check false "e0310002" inputs outputs

  /// <summary>
  /// F5.1.52 ESB: esb. It lifts to no statements: what it does is a hint or an
  /// ordering of memory accesses that one run cannot observe, and QEMU's runs
  /// of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.52 ESB``() =
    Assert.AreEqual(0, (lift false "e320f010").Length)

  /// <summary>
  /// F5.1.53 HLT: hlt #0x0. This checks that it takes the Undefined Instruction
  /// exception. It is not a value test because it takes an exception, which a
  /// user-mode run cannot return from.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.53 HLT``() =
    let run = runWith false "e1000070" [ Cell.CPSR 0x10u ] []
    Assert.AreEqual(Some SideEffect.UndefinedInstruction, run.Effect)

  /// <summary>
  /// F5.1.57 LDA: lda r0, [r1]. The outputs are what QEMU left after running it
  /// on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.57 LDA``() =
    let inputs =
      [ [ Gpr(0, 0xac6cb53du)
          Gpr(1, 0x20000810u)
          M(0, 0x8b004b9390ed7761UL)
          M(8, 0x73e211b4d2088986UL)
          M(16, 0xfde76fb794cff7dfUL)
          M(24, 0x89d8239bebb545b4UL)
          M(32, 0x2bc961bdf65d4ac8UL)
          M(40, 0x5c790a60c63d6fdeUL)
          M(48, 0x088bf20b40c36ee9UL)
          M(56, 0x3a79cb1c02750585UL) ]
        [ Gpr(0, 0x2acb53dfu)
          Gpr(1, 0x20000810u)
          M(0, 0x0658e84db3859909UL)
          M(8, 0xf81b4fa599b662d8UL)
          M(16, 0xbf99212096a4a177UL)
          M(24, 0x7bffa19440a565b3UL)
          M(32, 0x7c11e5fa7024b9adUL)
          M(40, 0x17255f79bd570095UL)
          M(48, 0x7b68256322228c01UL)
          M(56, 0x26d047893b217db9UL) ]
        [ Gpr(0, 0x00000001u)
          Gpr(1, 0x20000810u)
          M(0, 0x0b02e0432c23d769UL)
          M(8, 0x293b766744d4abf8UL)
          M(16, 0xc136fdf86ae278d1UL)
          M(24, 0x32608776ad3bef6dUL)
          M(32, 0x256c7aba676beb9aUL)
          M(40, 0x1c5634c07fdbb03dUL)
          M(48, 0xcff3c2b88069f8beUL)
          M(56, 0x128be0f8c2609ae3UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x94cff7dfu) ]
        [ Gpr(0, 0x96a4a177u) ]
        [ Gpr(0, 0x6ae278d1u) ] ]
    check false "e1910c9f" inputs outputs

  /// <summary>
  /// F5.1.58 LDAB: ldab r0, [r1]. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.58 LDAB``() =
    let inputs =
      [ [ Gpr(0, 0xd4453508u)
          Gpr(1, 0x20000810u)
          M(0, 0x7378d890ce4d9715UL)
          M(8, 0xf9a005bf1f5981a4UL)
          M(16, 0x3b737a94a2f78917UL)
          M(24, 0x616d8ae46d8a0fe2UL)
          M(32, 0xd587238f2b555a65UL)
          M(40, 0x3ef49ff00d456e70UL)
          M(48, 0xe24a231841cc1c60UL)
          M(56, 0xdfa7f1737a67b5bdUL) ]
        [ Gpr(0, 0x15c34f02u)
          Gpr(1, 0x20000810u)
          M(0, 0x2d8bf49635d52bb1UL)
          M(8, 0x76399fac73960f98UL)
          M(16, 0xf00cde1cbc5639efUL)
          M(24, 0x1721be047c9c4b1dUL)
          M(32, 0x475ddd175ca85595UL)
          M(40, 0xaf5f079cd6d295efUL)
          M(48, 0x453573308350180aUL)
          M(56, 0x5590a9a6a66b9859UL) ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x20000810u)
          M(0, 0xcead6442205674f2UL)
          M(8, 0xd73fa58bd7df408eUL)
          M(16, 0xb85aeb4480a00b12UL)
          M(24, 0x43d46f220d9ace7aUL)
          M(32, 0xf0c3a80f665ab849UL)
          M(40, 0x565831cdd08f7f1cUL)
          M(48, 0xd2f5120af3769c17UL)
          M(56, 0x0f2362c1a0bbe142UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000017u) ]
        [ Gpr(0, 0x000000efu) ]
        [ Gpr(0, 0x00000012u) ] ]
    check false "e1d10c9f" inputs outputs

  /// <summary>
  /// F5.1.59 LDAEX: ldaex r0, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.59 LDAEX``() =
    let inputs =
      [ [ Gpr(0, 0x4747fd80u)
          Gpr(1, 0x20000810u)
          M(0, 0x431387fb287f6869UL)
          M(8, 0x4d62f208f767c9e5UL)
          M(16, 0x83f16a5144a3ddd2UL)
          M(24, 0xdbbf81ea265b1416UL)
          M(32, 0x8aca65872249effeUL)
          M(40, 0xd93dc6ba6e8d6971UL)
          M(48, 0x169cb7a7f32fb07cUL)
          M(56, 0x66512233f0c55e37UL) ]
        [ Gpr(0, 0x762104d5u)
          Gpr(1, 0x20000810u)
          M(0, 0xf426adb8c2abf523UL)
          M(8, 0x3a34996ff8362d25UL)
          M(16, 0xec83763e5d34ae15UL)
          M(24, 0xb7db87e072096a20UL)
          M(32, 0x9e589d07dcb902cdUL)
          M(40, 0xdc30d339f68b860eUL)
          M(48, 0xe3ead63899e97a46UL)
          M(56, 0x70f94e665d5bc2acUL) ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x20000810u)
          M(0, 0xc067f0dab4cce439UL)
          M(8, 0x473c4831e7f0dcd7UL)
          M(16, 0x1bd7c27730747de6UL)
          M(24, 0xefd142a78af3605bUL)
          M(32, 0xee778cf1f654ef95UL)
          M(40, 0x04db71d60049bbe6UL)
          M(48, 0x2caa2c2409a181e1UL)
          M(56, 0xd926085cacaf7892UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x44a3ddd2u) ]
        [ Gpr(0, 0x5d34ae15u) ]
        [ Gpr(0, 0x30747de6u) ] ]
    check false "e1910e9f" inputs outputs

  /// <summary>
  /// F5.1.60 LDAEXB: ldaexb r0, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.60 LDAEXB``() =
    let inputs =
      [ [ Gpr(0, 0xfc23ed22u)
          Gpr(1, 0x20000810u)
          M(0, 0xea20288267de4569UL)
          M(8, 0xb6e974e9192f7a6aUL)
          M(16, 0xd7ca8ba94bb46d6bUL)
          M(24, 0xd1bb8d23b716a13eUL)
          M(32, 0x297e83bd5dde45b8UL)
          M(40, 0x002e4d5ffc10eb4eUL)
          M(48, 0x19e1e4e1f3fc14acUL)
          M(56, 0xad2eb0a1a69f2e3dUL) ]
        [ Gpr(0, 0x5ddd5ea5u)
          Gpr(1, 0x20000810u)
          M(0, 0xd37c4f3a8a5090d0UL)
          M(8, 0xf31960aa1cf09387UL)
          M(16, 0xc260218a80e355f4UL)
          M(24, 0xca8841804d380ca7UL)
          M(32, 0xf1e26b24ad746135UL)
          M(40, 0xaf421dd75d10be04UL)
          M(48, 0xe226442ae2cae371UL)
          M(56, 0x204ccd33917b3857UL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          M(0, 0x72fbd22c8415078bUL)
          M(8, 0x665f65541768fb9eUL)
          M(16, 0x95a6918b359530daUL)
          M(24, 0xb3ffd885ab0b0b3fUL)
          M(32, 0x6e4d3eea8f9db82dUL)
          M(40, 0xdaa54e99aceb1a37UL)
          M(48, 0xaa88968987aa0085UL)
          M(56, 0x0d515394805d8e06UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x0000006bu) ]
        [ Gpr(0, 0x000000f4u) ]
        [ Gpr(0, 0x000000dau) ] ]
    check false "e1d10e9f" inputs outputs

  /// <summary>
  /// F5.1.61 LDAEXD: ldaexd r2, r3, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.61 LDAEXD``() =
    let inputs =
      [ [ Gpr(1, 0x20000810u)
          Gpr(2, 0xb8347b47u)
          Gpr(3, 0xf295b6a7u)
          M(0, 0xb6643a8edd40d07dUL)
          M(8, 0xf46aeaae9278b9beUL)
          M(16, 0xfd1347ab353732d6UL)
          M(24, 0x470e6e7f5f14dbd9UL)
          M(32, 0xbca2c1c9ef5f2330UL)
          M(40, 0xa74ef2477aa2499fUL)
          M(48, 0x0b49ee4bc90f3385UL)
          M(56, 0x21e70c227ab40f52UL) ]
        [ Gpr(1, 0x20000810u)
          Gpr(2, 0x18d1edbau)
          Gpr(3, 0xbdc3b9cau)
          M(0, 0xdb5b8cd70f3a2964UL)
          M(8, 0x131cacbcfdbb87d7UL)
          M(16, 0x7ae3918085605be4UL)
          M(24, 0x06455c73d567a4baUL)
          M(32, 0xd42e35c421839d81UL)
          M(40, 0x107343da379a542aUL)
          M(48, 0x9130c37d47b8894bUL)
          M(56, 0x254f2e61293a556fUL) ]
        [ Gpr(1, 0x20000810u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u)
          M(0, 0x7fe72312bc23d034UL)
          M(8, 0xa03c6720b8ce486cUL)
          M(16, 0x3cbac98f8ffc9792UL)
          M(24, 0x6dd3012892418cd0UL)
          M(32, 0xa55fbb213a774460UL)
          M(40, 0xd071f118442f7085UL)
          M(48, 0x3f930a3689efb2eeUL)
          M(56, 0x24842035e61ff0eaUL) ] ]
    let outputs =
      [ [ Gpr(2, 0x353732d6u); Gpr(3, 0xfd1347abu) ]
        [ Gpr(2, 0x85605be4u); Gpr(3, 0x7ae39180u) ]
        [ Gpr(2, 0x8ffc9792u); Gpr(3, 0x3cbac98fu) ] ]
    check false "e1b12e9f" inputs outputs

  /// <summary>
  /// F5.1.62 LDAEXH: ldaexh r0, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.62 LDAEXH``() =
    let inputs =
      [ [ Gpr(0, 0x47b9cb5cu)
          Gpr(1, 0x20000810u)
          M(0, 0x88345a8fd4705317UL)
          M(8, 0x07ade15b2df0e021UL)
          M(16, 0x4dac23be7981296aUL)
          M(24, 0xde3d66891ce1f9e1UL)
          M(32, 0x5352f1f061e4d06aUL)
          M(40, 0xc3809b9ee895799eUL)
          M(48, 0x78cc97a9a4b4a798UL)
          M(56, 0x29efcc8610dc7bd9UL) ]
        [ Gpr(0, 0xa6cfdd75u)
          Gpr(1, 0x20000810u)
          M(0, 0x338fdf2c32b2e7a2UL)
          M(8, 0x3692663cff2b22e3UL)
          M(16, 0x6649400a1dfa480cUL)
          M(24, 0x80635b671a9d2730UL)
          M(32, 0x3086f73d21a2ec00UL)
          M(40, 0x12bb8de606f3cffeUL)
          M(48, 0x843458580782ce77UL)
          M(56, 0xe7ec411335fd8457UL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          M(0, 0xcbc52b25a5d11ce6UL)
          M(8, 0xa4ed7c1de58e0c2dUL)
          M(16, 0xebed2e4f45a3a5c9UL)
          M(24, 0x7c219b388e9e9692UL)
          M(32, 0x6d7182e1f5d1e62eUL)
          M(40, 0x7be9ead5b558c480UL)
          M(48, 0xbbb16cbad272831bUL)
          M(56, 0xe16c82658f89091fUL) ] ]
    let outputs =
      [ [ Gpr(0, 0x0000296au) ]
        [ Gpr(0, 0x0000480cu) ]
        [ Gpr(0, 0x0000a5c9u) ] ]
    check false "e1f10e9f" inputs outputs

  /// <summary>
  /// F5.1.63 LDAH: ldah r0, [r1]. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.63 LDAH``() =
    let inputs =
      [ [ Gpr(0, 0x0854d596u)
          Gpr(1, 0x20000810u)
          M(0, 0xd7541156748800ddUL)
          M(8, 0x9bb5f1e8772363b5UL)
          M(16, 0xf29ad30572e180deUL)
          M(24, 0xab9c5edad865463fUL)
          M(32, 0x7b7cc69fe967595bUL)
          M(40, 0xb7e60b36d10c49dfUL)
          M(48, 0x2c58eff058679d1aUL)
          M(56, 0xedbce3d295fa9d52UL) ]
        [ Gpr(0, 0x2fae49cdu)
          Gpr(1, 0x20000810u)
          M(0, 0x1b4c20db47480c99UL)
          M(8, 0x09dbd2206d8117edUL)
          M(16, 0x0c847734c7155c52UL)
          M(24, 0xa920d05af68707bdUL)
          M(32, 0x32a8f7fa26ee538aUL)
          M(40, 0x03febb036d1b3483UL)
          M(48, 0xfaf8aefa121645abUL)
          M(56, 0x627ae52e0e22e083UL) ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x20000810u)
          M(0, 0x8d97cb016e10d645UL)
          M(8, 0x396c81ac075d2345UL)
          M(16, 0xe91c96880b9b3609UL)
          M(24, 0x1127c71c67ee6d65UL)
          M(32, 0x629574c5c75093d7UL)
          M(40, 0x59bc8ebeac7bfbb7UL)
          M(48, 0x59a542dae6bac8e2UL)
          M(56, 0x7c170edf3358e96bUL) ] ]
    let outputs =
      [ [ Gpr(0, 0x000080deu) ]
        [ Gpr(0, 0x00005c52u) ]
        [ Gpr(0, 0x00003609u) ] ]
    check false "e1f10c9f" inputs outputs

  /// <summary>
  /// F5.1.101 LSLS: lsls r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.101 LSLS``() =
    let inputs =
      [ [ Gpr(0, 0x127f9ab7u)
          Gpr(1, 0x72fd49bau)
          Gpr(2, 0xdf57764eu)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x3b7e7eabu)
          Gpr(1, 0x17ae87abu)
          Gpr(2, 0xb04dfda2u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x00000000u); Cell.CPSR 0x40000010u ]
        [ Gpr(0, 0x00000000u); Cell.CPSR 0x500a0010u ]
        [ Gpr(0, 0x00008000u); Cell.CPSR 0x08050010u ] ]
    check false "e1b00211" inputs outputs

  /// <summary>
  /// F5.1.105 LSRS: lsrs r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.105 LSRS``() =
    let inputs =
      [ [ Gpr(0, 0xe9158f30u)
          Gpr(1, 0xf193ce01u)
          Gpr(2, 0xc4dc0d77u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xab431617u)
          Gpr(1, 0x0f098ce6u)
          Gpr(2, 0x8081724du)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x00000000u); Cell.CPSR 0x40000010u ]
        [ Gpr(0, 0x00000000u); Cell.CPSR 0x500a0010u ]
        [ Gpr(0, 0x00008000u); Cell.CPSR 0x08050010u ] ]
    check false "e1b00231" inputs outputs

  /// <summary>
  /// F5.1.109 MLAS: mlas r0, r1, r2, r3. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.109 MLAS``() =
    let inputs =
      [ [ Gpr(0, 0xeab26a87u)
          Gpr(1, 0xf491cc6fu)
          Gpr(2, 0x605eb262u)
          Gpr(3, 0x27c4ed70u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xed5fcc86u)
          Gpr(1, 0xe493c995u)
          Gpr(2, 0xc7c36a96u)
          Gpr(3, 0x8a3f9853u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          Gpr(3, 0x00000000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xd87c5deeu); Cell.CPSR 0xa0000010u ]
        [ Gpr(0, 0x09ce67a1u); Cell.CPSR 0x100a0010u ]
        [ Gpr(0, 0xc0000000u); Cell.CPSR 0x88050010u ] ]
    check false "e0303291" inputs outputs

  /// <summary>
  /// F5.1.111 MOVS: movs r0, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.111 MOVS``() =
    let inputs =
      [ [ Gpr(0, 0xa307d6edu); Gpr(2, 0x98895201u); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x73cacb81u); Gpr(2, 0x94ff1792u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu); Gpr(2, 0x7fff8000u); Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x98895201u); Cell.CPSR 0xa0000010u ]
        [ Gpr(0, 0x94ff1792u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u); Cell.CPSR 0x08050010u ] ]
    check false "e1b00002" inputs outputs

  /// <summary>
  /// F5.1.122 MULS: muls r0, r1, r0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.122 MULS``() =
    let inputs =
      [ [ Gpr(0, 0x16ee9265u); Gpr(1, 0x7ead47a3u); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x160d463bu); Gpr(1, 0xbef02b60u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u); Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x68c2394fu); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x21163f20u); Cell.CPSR 0x100a0010u ]
        [ Gpr(0, 0x7fff8000u); Cell.CPSR 0x08050010u ] ]
    check false "e0100091" inputs outputs

  /// <summary>
  /// F5.1.123 MVNS: mvns r0, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.123 MVNS``() =
    let inputs =
      [ [ Gpr(0, 0xc4521089u); Gpr(2, 0x39ccc950u); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x7ba83cc8u); Gpr(2, 0xe9c40ac5u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu); Gpr(2, 0x7fff8000u); Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xc63336afu); Cell.CPSR 0xa0000010u ]
        [ Gpr(0, 0x163bf53au); Cell.CPSR 0x100a0010u ]
        [ Gpr(0, 0x80007fffu); Cell.CPSR 0x88050010u ] ]
    check false "e1f00002" inputs outputs

  /// <summary>
  /// F5.1.127 ORNS: orns r0, r1, #0xff000000. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.127 ORNS``() =
    let inputs =
      [ [ Gpr(0, 0x2e5f1036u); Gpr(1, 0x368dfffbu); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xcda2aedeu); Gpr(1, 0x4f1c5636u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u); Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x36ffffffu); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x4fffffffu); Cell.CPSR 0x300a0010u ]
        [ Gpr(0, 0x00ffffffu); Cell.CPSR 0x28050010u ] ]
    check true "f071407f" inputs outputs

  /// <summary>
  /// F5.1.129 ORRS: orrs r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.129 ORRS``() =
    let inputs =
      [ [ Gpr(0, 0x95db05a9u)
          Gpr(1, 0x32ff4ff2u)
          Gpr(2, 0x2b0c52e8u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x7afdbde2u)
          Gpr(1, 0xfa992fa7u)
          Gpr(2, 0x32d88184u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x3bff5ffau); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xfad9afa7u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u); Cell.CPSR 0x08050010u ] ]
    check false "e1910002" inputs outputs

  /// <summary>
  /// F5.1.132 PKHBT: pkhbt r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.132 PKHBT``() =
    let inputs =
      [ [ Gpr(0, 0x651f4ec7u); Gpr(1, 0xf1f5128bu); Gpr(2, 0x819d5405u) ]
        [ Gpr(0, 0x33bd8588u); Gpr(1, 0x1d29c8c5u); Gpr(2, 0xa95372deu) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x819d128bu) ]
        [ Gpr(0, 0xa953c8c5u) ]
        [ Gpr(0, 0x00008000u) ] ]
    check false "e6810012" inputs outputs

  /// <summary>
  /// F5.1.132 PKHTB: pkhtb r0, r1, r2, asr #0x4. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.132 PKHTB``() =
    let inputs =
      [ [ Gpr(0, 0xb5c7e303u); Gpr(1, 0xde1d9837u); Gpr(2, 0x4d9d59f6u) ]
        [ Gpr(0, 0x0f03b4dfu); Gpr(1, 0xee868f08u); Gpr(2, 0x40f9e1f6u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xde1dd59fu) ]
        [ Gpr(0, 0xee869e1fu) ]
        [ Gpr(0, 0x7fff0000u) ] ]
    check false "e6810252" inputs outputs

  /// <summary>
  /// F5.1.141 PSSBB: pssbb. It lifts to no statements: what it does is a hint
  /// or an ordering of memory accesses that one run cannot observe, and QEMU's
  /// runs of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.141 PSSBB``() =
    Assert.AreEqual(0, (lift false "f57ff044").Length)

  /// <summary>
  /// F5.1.159 RFEDA: rfeda r1!. This checks, in Supervisor mode with Rn
  /// pointing at a return address of 0x30003000 and a saved CPSR of 0x20000010,
  /// that it returns there with that CPSR and writes Rn back, and that User and
  /// Hyp mode refuse it. It is not a value test because it needs a privileged
  /// mode, which a user-mode run does not have.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.159 RFEDA``() =
    let w = uint32 Window
    let cells = [ Gpr(1, w + 20u); M(16, 0x2000001030003000UL) ]
    let run = runWith false "f8310a00" (Cell.CPSR 0x13u :: cells) []
    let refused = ManualLifting.refusedModes false "f8310a00" cells []
    CollectionAssert.AreEqual([| 0x10u; 0x1au |], refused)
    Assert.AreEqual(Some 0x30003000UL, run.Target)
    Assert.AreEqual(Cell.CPSR 0x20000010u, run.After(Cell.CPSR 0u))
    Assert.AreEqual(Gpr(1, w + 12u), run.After(Gpr(1, 0u)))

  /// <summary>
  /// F5.1.159 RFEDB: rfedb r1. This checks, in Supervisor mode with Rn pointing
  /// at a return address of 0x30003000 and a saved CPSR of 0x20000010, that it
  /// returns there with that CPSR and leaves Rn, and that User and Hyp mode
  /// refuse it. It is not a value test because it needs a privileged mode,
  /// which a user-mode run does not have.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.159 RFEDB``() =
    let w = uint32 Window
    let cells = [ Gpr(1, w + 24u); M(16, 0x2000001030003000UL) ]
    let run = runWith false "f9110a00" (Cell.CPSR 0x13u :: cells) []
    let refused = ManualLifting.refusedModes false "f9110a00" cells []
    CollectionAssert.AreEqual([| 0x10u; 0x1au |], refused)
    Assert.AreEqual(Some 0x30003000UL, run.Target)
    Assert.AreEqual(Cell.CPSR 0x20000010u, run.After(Cell.CPSR 0u))
    Assert.AreEqual(Gpr(1, w + 24u), run.After(Gpr(1, 0u)))

  /// <summary>
  /// F5.1.159 RFEIA: rfeia r1. This checks, in Supervisor mode with Rn pointing
  /// at a return address of 0x30003000 and a saved CPSR of 0x20000010, that it
  /// returns there with that CPSR and leaves Rn, and that User and Hyp mode
  /// refuse it. It is not a value test because it needs a privileged mode,
  /// which a user-mode run does not have.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.159 RFEIA``() =
    let w = uint32 Window
    let cells = [ Gpr(1, w + 16u); M(16, 0x2000001030003000UL) ]
    let run = runWith false "f8910a00" (Cell.CPSR 0x13u :: cells) []
    let refused = ManualLifting.refusedModes false "f8910a00" cells []
    CollectionAssert.AreEqual([| 0x10u; 0x1au |], refused)
    Assert.AreEqual(Some 0x30003000UL, run.Target)
    Assert.AreEqual(Cell.CPSR 0x20000010u, run.After(Cell.CPSR 0u))
    Assert.AreEqual(Gpr(1, w + 16u), run.After(Gpr(1, 0u)))

  /// <summary>
  /// F5.1.159 RFEIB: rfeib r1!. This checks, in Supervisor mode with Rn
  /// pointing at a return address of 0x30003000 and a saved CPSR of 0x20000010,
  /// that it returns there with that CPSR and writes Rn back, and that User and
  /// Hyp mode refuse it. It is not a value test because it needs a privileged
  /// mode, which a user-mode run does not have.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.159 RFEIB``() =
    let w = uint32 Window
    let cells = [ Gpr(1, w + 12u); M(16, 0x2000001030003000UL) ]
    let run = runWith false "f9b10a00" (Cell.CPSR 0x13u :: cells) []
    let refused = ManualLifting.refusedModes false "f9b10a00" cells []
    CollectionAssert.AreEqual([| 0x10u; 0x1au |], refused)
    Assert.AreEqual(Some 0x30003000UL, run.Target)
    Assert.AreEqual(Cell.CPSR 0x20000010u, run.After(Cell.CPSR 0u))
    Assert.AreEqual(Gpr(1, w + 20u), run.After(Gpr(1, 0u)))

  /// <summary>
  /// F5.1.162 RORS: rors r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.162 RORS``() =
    let inputs =
      [ [ Gpr(0, 0xd3b7a8c8u)
          Gpr(1, 0x3a2e2979u)
          Gpr(2, 0xc84ed0cbu)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x5cf14666u)
          Gpr(1, 0xa39709eau)
          Gpr(2, 0x14978227u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x2f2745c5u); Cell.CPSR 0x00000010u ]
        [ Gpr(0, 0xd5472e13u); Cell.CPSR 0xb00a0010u ]
        [ Gpr(0, 0x00008000u); Cell.CPSR 0x08050010u ] ]
    check false "e1b00271" inputs outputs

  /// <summary>
  /// F5.1.165 RRXS: rrxs r0, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.165 RRXS``() =
    let inputs =
      [ [ Gpr(0, 0x0e0b7e93u); Gpr(2, 0x3d4894afu); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x2ce1528fu); Gpr(2, 0x2ad2fafbu); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu); Gpr(2, 0x7fff8000u); Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x9ea44a57u); Cell.CPSR 0xa0000010u ]
        [ Gpr(0, 0x15697d7du); Cell.CPSR 0x300a0010u ]
        [ Gpr(0, 0x3fffc000u); Cell.CPSR 0x08050010u ] ]
    check false "e1b00062" inputs outputs

  /// <summary>
  /// F5.1.166 RSBS: rsbs r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.166 RSBS``() =
    let inputs =
      [ [ Gpr(0, 0xa060791eu)
          Gpr(1, 0xdb5d00feu)
          Gpr(2, 0x42a62fbeu)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xad30a34fu)
          Gpr(1, 0xff4681e0u)
          Gpr(2, 0x277ab335u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x67492ec0u); Cell.CPSR 0x00000010u ]
        [ Gpr(0, 0x28343155u); Cell.CPSR 0x000a0010u ]
        [ Gpr(0, 0x7fff0000u); Cell.CPSR 0x28050010u ] ]
    check false "e0710002" inputs outputs

  /// <summary>
  /// F5.1.169 RSCS: rscs r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.169 RSCS``() =
    let inputs =
      [ [ Gpr(0, 0x497d7e21u)
          Gpr(1, 0x3ef13624u)
          Gpr(2, 0xaea1de77u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xb6abc075u)
          Gpr(1, 0x93a7c607u)
          Gpr(2, 0x4666882au)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x6fb0a853u); Cell.CPSR 0x30000010u ]
        [ Gpr(0, 0xb2bec222u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7ffeffffu); Cell.CPSR 0x28050010u ] ]
    check false "e0f10002" inputs outputs

  /// <summary>
  /// F5.1.175 SB: sb. It lifts to no statements: what it does is a hint or an
  /// ordering of memory accesses that one run cannot observe, and QEMU's runs
  /// of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.175 SB``() =
    Assert.AreEqual(0, (lift false "f57ff070").Length)

  /// <summary>
  /// F5.1.176 SBCS: sbcs r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.176 SBCS``() =
    let inputs =
      [ [ Gpr(0, 0xaac4e759u)
          Gpr(1, 0x3205efc7u)
          Gpr(2, 0x35d6269bu)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x442bd01eu)
          Gpr(1, 0x81d4761cu)
          Gpr(2, 0x2927232fu)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xfc2fc92cu); Cell.CPSR 0x80000010u ]
        [ Gpr(0, 0x58ad52ecu); Cell.CPSR 0x300a0010u ]
        [ Gpr(0, 0x8000ffffu); Cell.CPSR 0x88050010u ] ]
    check false "e0d10002" inputs outputs

  /// <summary>
  /// F5.1.183 SETPAN: setpan #0x0. This checks that it clears PAN, CPSR bit 22,
  /// in Supervisor mode and changes nothing in User mode. It is not a value
  /// test because it needs a privileged mode, which a user-mode run does not
  /// have.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.183 SETPAN``() =
    let svc = runWith false "f1100000" [ Cell.CPSR 0x00400013u ] []
    let user = runWith false "f1100000" [ Cell.CPSR 0x00400010u ] []
    Assert.AreEqual(Cell.CPSR 0x13u, svc.After(Cell.CPSR 0u))
    Assert.AreEqual(Cell.CPSR 0x00400010u, user.After(Cell.CPSR 0u))

  /// <summary>
  /// F5.1.185 SEVL: sevl. It lifts to no statements: what it does is a hint or
  /// an ordering of memory accesses that one run cannot observe, and QEMU's
  /// runs of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.185 SEVL``() =
    Assert.AreEqual(0, (lift false "e320f005").Length)

  /// <summary>
  /// F5.1.194 SMLADX: smladx r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.194 SMLADX``() =
    let inputs =
      [ [ Gpr(0, 0xb24614aeu)
          Gpr(1, 0x42f23ad5u)
          Gpr(2, 0xdf0e10f9u)
          Gpr(3, 0x0b494391u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x4781606fu)
          Gpr(1, 0x1e6de73du)
          Gpr(2, 0x5cec20c1u)
          Gpr(3, 0xf6e7ba9au)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x08274399u); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xf1cf6303u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000003u); Cell.CPSR 0x48050010u ] ]
    check false "e7003231" inputs outputs

  /// <summary>
  /// F5.1.195 SMLALS: smlals r0, r1, r1, r2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.195 SMLALS``() =
    let inputs =
      [ [ Gpr(0, 0x92c7c486u)
          Gpr(1, 0x6bff063bu)
          Gpr(2, 0x4e27cf92u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x052b10d5u)
          Gpr(1, 0xd71eccaau)
          Gpr(2, 0x7deadc49u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x4d40072cu); Gpr(1, 0x8cf7858cu); Cell.CPSR 0xa0000010u ]
        [ Gpr(0, 0xea39854fu); Gpr(1, 0xc3035592u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Cell.CPSR 0x08050010u ] ]
    check false "e0f10291" inputs outputs

  /// <summary>
  /// F5.1.197 SMLALDX: smlaldx r0, r1, r1, r2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.197 SMLALDX``() =
    let inputs =
      [ [ Gpr(0, 0x44c55ba1u); Gpr(1, 0x873ea598u); Gpr(2, 0xb39bfc44u) ]
        [ Gpr(0, 0xfb93980eu); Gpr(1, 0x2e4310d6u); Gpr(2, 0xf5bff92bu) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x80007fffu); Gpr(2, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0x6182db21u); Gpr(1, 0x873ea598u) ]
        [ Gpr(0, 0xf9aae5f9u); Gpr(1, 0x2e4310d6u) ]
        [ Gpr(0, 0xfffe8000u); Gpr(1, 0x80007ffeu) ] ]
    check false "e7410231" inputs outputs

  /// <summary>
  /// F5.1.199 SMLSDX: smlsdx r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.199 SMLSDX``() =
    let inputs =
      [ [ Gpr(0, 0x0e9fa437u)
          Gpr(1, 0x2f9693b6u)
          Gpr(2, 0x1f244528u)
          Gpr(3, 0xcbeb9180u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x6969af05u)
          Gpr(1, 0xa6ce18fdu)
          Gpr(2, 0x9fc2f862u)
          Gpr(3, 0xfb3af588u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xb1e483a8u); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xef2e9d66u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000003u); Cell.CPSR 0x48050010u ] ]
    check false "e7003271" inputs outputs

  /// <summary>
  /// F5.1.200 SMLSLDX: smlsldx r0, r1, r1, r2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.200 SMLSLDX``() =
    let inputs =
      [ [ Gpr(0, 0x2e98da76u); Gpr(1, 0x1d7f8941u); Gpr(2, 0x3a3dd73bu) ]
        [ Gpr(0, 0xe6504e09u); Gpr(1, 0x5ecbe29bu); Gpr(2, 0xe465b5b6u) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x80007fffu); Gpr(2, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0x1847d3aeu); Gpr(1, 0x1d7f8941u) ]
        [ Gpr(0, 0x04fdd5deu); Gpr(1, 0x5ecbe29cu) ]
        [ Gpr(0, 0x00018000u); Gpr(1, 0x80007fffu) ] ]
    check false "e7410271" inputs outputs

  /// <summary>
  /// F5.1.201 SMMLAR: smmlar r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.201 SMMLAR``() =
    let inputs =
      [ [ Gpr(0, 0xdc7fb691u)
          Gpr(1, 0x6d29f3c7u)
          Gpr(2, 0xec478b80u)
          Gpr(3, 0x7e71af99u) ]
        [ Gpr(0, 0xa9852b83u)
          Gpr(1, 0xad5b0a77u)
          Gpr(2, 0x2704fdbeu)
          Gpr(3, 0xc5506a53u) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0x7608eaacu) ]
        [ Gpr(0, 0xb8b7ac6du) ]
        [ Gpr(0, 0x00000003u) ] ]
    check false "e7503231" inputs outputs

  /// <summary>
  /// F5.1.202 SMMLSR: smmlsr r0, r1, r2, r3. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.202 SMMLSR``() =
    let inputs =
      [ [ Gpr(0, 0x74aec40cu)
          Gpr(1, 0xf314f8a5u)
          Gpr(2, 0x8af4a257u)
          Gpr(3, 0xc5b98782u) ]
        [ Gpr(0, 0xa754d049u)
          Gpr(1, 0x056429a4u)
          Gpr(2, 0x1f0557eau)
          Gpr(3, 0x0b761c79u) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0xbfd18a52u) ]
        [ Gpr(0, 0x0acede9fu) ]
        [ Gpr(0, 0x00000003u) ] ]
    check false "e75032f1" inputs outputs

  /// <summary>
  /// F5.1.203 SMMULR: smmulr r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.203 SMMULR``() =
    let inputs =
      [ [ Gpr(0, 0xe4647335u); Gpr(1, 0x6ef30c77u); Gpr(2, 0xbc8c763bu) ]
        [ Gpr(0, 0x28885e34u); Gpr(1, 0x0ac65edeu); Gpr(2, 0x263ce5cau) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0xe2c450d9u) ]
        [ Gpr(0, 0x019c023fu) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e750f231" inputs outputs

  /// <summary>
  /// F5.1.204 SMUADX: smuadx r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.204 SMUADX``() =
    let inputs =
      [ [ Gpr(0, 0x27aef3d8u)
          Gpr(1, 0x9bc0f2d1u)
          Gpr(2, 0xfb978b4bu)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x8ee3583bu)
          Gpr(1, 0x67ffee36u)
          Gpr(2, 0x8772f330u)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x2dee0587u); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x032c1adcu); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000000u); Cell.CPSR 0x48050010u ] ]
    check false "e700f231" inputs outputs

  /// <summary>
  /// F5.1.206 SMULLS: smulls r0, r1, r1, r2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.206 SMULLS``() =
    let inputs =
      [ [ Gpr(0, 0xbfd54adeu)
          Gpr(1, 0x58a0b338u)
          Gpr(2, 0x45363553u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x843eddaeu)
          Gpr(1, 0xffd1f2a1u)
          Gpr(2, 0x7b3ab53bu)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xe704b328u); Gpr(1, 0x17f614a9u); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xb968c01bu); Gpr(1, 0xffe9d503u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x00000000u); Cell.CPSR 0x48050010u ] ]
    check false "e0d10291" inputs outputs

  /// <summary>
  /// F5.1.208 SMUSDX: smusdx r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.208 SMUSDX``() =
    let inputs =
      [ [ Gpr(0, 0xddaee962u); Gpr(1, 0xbe98fd38u); Gpr(2, 0x0d92d24fu) ]
        [ Gpr(0, 0x695fc06au); Gpr(1, 0xafd92535u); Gpr(2, 0x7f6dfa38u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0xf42dc108u) ]
        [ Gpr(0, 0x10b5c119u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e700f271" inputs outputs

  /// <summary>
  /// F5.1.209 SRSDA: srsda sp, #0x13. This checks, from IRQ mode with SP_svc
  /// pointing into memory, that it stores LR then SPSR on Supervisor mode's
  /// stack and leaves SP_svc, and that User, Hyp and System mode refuse it. It
  /// is not a value test because it needs a privileged mode, which a user-mode
  /// run does not have.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.209 SRSDA``() =
    let w = uint32 Window
    let others =
      [ Register.LR, 0x11112222u
        Register.SPSR, 0x600001d3u
        Register.SP, w + 20u
        Register.SPsvc, w + 20u ]
    let cells = [ M(16, 0UL) ]
    let run = runWith false "f84d0513" (Cell.CPSR 0x12u :: cells) others
    let refused = ManualLifting.refusedModes false "f84d0513" cells others
    CollectionAssert.AreEqual([| 0x10u; 0x1au; 0x1fu |], refused)
    Assert.AreEqual(M(16, 0x600001d311112222UL), run.After(M(16, 0UL)))
    Assert.AreEqual(w + 20u, run.Reg Register.SPsvc)

  /// <summary>
  /// F5.1.209 SRSDB: srsdb sp!, #0x13. This checks, from IRQ mode with SP_svc
  /// pointing into memory, that it stores LR then SPSR on Supervisor mode's
  /// stack and writes SP_svc back, and that User, Hyp and System mode refuse
  /// it. It is not a value test because it needs a privileged mode, which a
  /// user-mode run does not have.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.209 SRSDB``() =
    let w = uint32 Window
    let others =
      [ Register.LR, 0x11112222u
        Register.SPSR, 0x600001d3u
        Register.SP, w + 24u
        Register.SPsvc, w + 24u ]
    let cells = [ M(16, 0UL) ]
    let run = runWith false "f96d0513" (Cell.CPSR 0x12u :: cells) others
    let refused = ManualLifting.refusedModes false "f96d0513" cells others
    CollectionAssert.AreEqual([| 0x10u; 0x1au; 0x1fu |], refused)
    Assert.AreEqual(M(16, 0x600001d311112222UL), run.After(M(16, 0UL)))
    Assert.AreEqual(w + 16u, run.Reg Register.SPsvc)

  /// <summary>
  /// F5.1.209 SRSIA: srsia sp, #0x13. This checks, from IRQ mode with SP_svc
  /// pointing into memory, that it stores LR then SPSR on Supervisor mode's
  /// stack and leaves SP_svc, and that User, Hyp and System mode refuse it. It
  /// is not a value test because it needs a privileged mode, which a user-mode
  /// run does not have.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.209 SRSIA``() =
    let w = uint32 Window
    let others =
      [ Register.LR, 0x11112222u
        Register.SPSR, 0x600001d3u
        Register.SP, w + 16u
        Register.SPsvc, w + 16u ]
    let cells = [ M(16, 0UL) ]
    let run = runWith false "f8cd0513" (Cell.CPSR 0x12u :: cells) others
    let refused = ManualLifting.refusedModes false "f8cd0513" cells others
    CollectionAssert.AreEqual([| 0x10u; 0x1au; 0x1fu |], refused)
    Assert.AreEqual(M(16, 0x600001d311112222UL), run.After(M(16, 0UL)))
    Assert.AreEqual(w + 16u, run.Reg Register.SPsvc)

  /// <summary>
  /// F5.1.209 SRSIB: srsib sp, #0x13. This checks, from IRQ mode with SP_svc
  /// pointing into memory, that it stores LR then SPSR on Supervisor mode's
  /// stack and leaves SP_svc, and that User, Hyp and System mode refuse it. It
  /// is not a value test because it needs a privileged mode, which a user-mode
  /// run does not have.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.209 SRSIB``() =
    let w = uint32 Window
    let others =
      [ Register.LR, 0x11112222u
        Register.SPSR, 0x600001d3u
        Register.SP, w + 12u
        Register.SPsvc, w + 12u ]
    let cells = [ M(16, 0UL) ]
    let run = runWith false "f9cd0513" (Cell.CPSR 0x12u :: cells) others
    let refused = ManualLifting.refusedModes false "f9cd0513" cells others
    CollectionAssert.AreEqual([| 0x10u; 0x1au; 0x1fu |], refused)
    Assert.AreEqual(M(16, 0x600001d311112222UL), run.After(M(16, 0UL)))
    Assert.AreEqual(w + 12u, run.Reg Register.SPsvc)

  /// <summary>
  /// F5.1.213 SSBB: ssbb. It lifts to no statements: what it does is a hint or
  /// an ordering of memory accesses that one run cannot observe, and QEMU's
  /// runs of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.213 SSBB``() =
    Assert.AreEqual(0, (lift false "f57ff040").Length)

  /// <summary>
  /// F5.1.217 STL: stl r0, [r1]. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.217 STL``() =
    let inputs =
      [ [ Gpr(0, 0xb16e845eu)
          Gpr(1, 0x20000810u)
          M(0, 0xfe6688f69779bd87UL)
          M(8, 0x33db71dcab0ae78fUL)
          M(16, 0xd4cf0579966da04cUL)
          M(24, 0xa38f6464d7d92ea5UL)
          M(32, 0x93e0bc8c114941f2UL)
          M(40, 0xfd70ca8e7f203df2UL)
          M(48, 0x5393379bc11bcf0eUL)
          M(56, 0xe39a6f072aae7f0eUL) ]
        [ Gpr(0, 0x92ad2fc8u)
          Gpr(1, 0x20000810u)
          M(0, 0xe05432408c31c718UL)
          M(8, 0x242c5bf7c2e66635UL)
          M(16, 0xa61bd1a46650160aUL)
          M(24, 0x6f56c86510ff34baUL)
          M(32, 0x7f8149ff131cc7acUL)
          M(40, 0x2352be9bbfc0e43aUL)
          M(48, 0xdcd1d849bf6b6c85UL)
          M(56, 0x057a508ad9ed8267UL) ]
        [ Gpr(0, 0x00000001u)
          Gpr(1, 0x20000810u)
          M(0, 0x7caf10d6c160e4edUL)
          M(8, 0x6b808d20ed70c160UL)
          M(16, 0x1c5c1ff3ade8c8beUL)
          M(24, 0xe3dfe91d25393b33UL)
          M(32, 0xe394485c09877eedUL)
          M(40, 0xbe5d1c76242a96ddUL)
          M(48, 0x1b5c0f75fd201b37UL)
          M(56, 0xf74f18f9f78c4699UL) ] ]
    let outputs =
      [ [ M(16, 0xd4cf0579b16e845eUL) ]
        [ M(16, 0xa61bd1a492ad2fc8UL) ]
        [ M(16, 0x1c5c1ff300000001UL) ] ]
    check false "e181fc90" inputs outputs

  /// <summary>
  /// F5.1.218 STLB: stlb r0, [r1]. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.218 STLB``() =
    let inputs =
      [ [ Gpr(0, 0xf7c90586u)
          Gpr(1, 0x20000810u)
          M(0, 0x71fd41def1ae4630UL)
          M(8, 0xb1a9f11d2dc0875dUL)
          M(16, 0xd81568ab90102f31UL)
          M(24, 0x361a36c285a5b175UL)
          M(32, 0x36d8e26f1f768a23UL)
          M(40, 0x33d001a8dcb7c433UL)
          M(48, 0xb6d89d041f7d72e5UL)
          M(56, 0xaf252058d808f896UL) ]
        [ Gpr(0, 0x5dfef18au)
          Gpr(1, 0x20000810u)
          M(0, 0xbb0121c01dc0aafdUL)
          M(8, 0xa95bea36c2e109daUL)
          M(16, 0xdf281a1963b718fdUL)
          M(24, 0x320d4b558ee45e22UL)
          M(32, 0xa36d4e766bcb6d8dUL)
          M(40, 0x92131415a75a097fUL)
          M(48, 0x7eec4a204caf8c95UL)
          M(56, 0x0f55efacff8f4facUL) ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x20000810u)
          M(0, 0x4ddd8867a896069aUL)
          M(8, 0x41ad83e9c5a5bc40UL)
          M(16, 0xc3aa6eed623456a7UL)
          M(24, 0x52485cbbffbd3cb1UL)
          M(32, 0x3c8bea1c0a31e180UL)
          M(40, 0x473fa570e4851bf4UL)
          M(48, 0xfbb278b6ff8abff6UL)
          M(56, 0xf5723fea4bf6ec82UL) ] ]
    let outputs =
      [ [ M(16, 0xd81568ab90102f86UL) ]
        [ M(16, 0xdf281a1963b7188aUL) ]
        [ M(16, 0xc3aa6eed623456ffUL) ] ]
    check false "e1c1fc90" inputs outputs

  /// <summary>
  /// F5.1.219 STLEX: stlex r0, r2, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.219 STLEX``() =
    let inputs =
      [ [ Gpr(0, 0xb3118b01u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x439f1908u)
          M(0, 0x5fbd4d4ad42597efUL)
          M(8, 0xcca41c34f221813fUL)
          M(16, 0xc08de2320de5b108UL)
          M(24, 0x5bdc6a483e703775UL)
          M(32, 0x4b626328ed2f7c0cUL)
          M(40, 0x33f10616dc0542c8UL)
          M(48, 0xe8e5aa5860454751UL)
          M(56, 0xc1ab5e7bbd28118bUL) ]
        [ Gpr(0, 0x36bd4c69u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0xb4fd8628u)
          M(0, 0x0984d1dd5e0ff932UL)
          M(8, 0x0d6ea7dd30900eabUL)
          M(16, 0x952c0312db394bdcUL)
          M(24, 0xec646a6b232777dbUL)
          M(32, 0x131bd90a9e88c8c3UL)
          M(40, 0xc0fd403a3faf74d2UL)
          M(48, 0xeef727d4a3b42710UL)
          M(56, 0x9239c24f939f4e28UL) ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x00000000u)
          M(0, 0x9c180b0926efddd2UL)
          M(8, 0x4fe1cfa5762bb325UL)
          M(16, 0x3fba4bfb79557e47UL)
          M(24, 0x962e7598148ff9cdUL)
          M(32, 0xa4595cb90ecd5445UL)
          M(40, 0xd85b5b4d6c73ab8aUL)
          M(48, 0x06df580e7b885460UL)
          M(56, 0xbbeb3f9b5ad2d9f5UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e1810e92" inputs outputs

  /// <summary>
  /// F5.1.220 STLEXB: stlexb r0, r2, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.220 STLEXB``() =
    let inputs =
      [ [ Gpr(0, 0x0dba23c5u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x18267b81u)
          M(0, 0xb4f0a3da823f960cUL)
          M(8, 0x8346e459dff076e1UL)
          M(16, 0xa8f03889ce26f840UL)
          M(24, 0xb391f99d070ca7ccUL)
          M(32, 0xa991d7ca9c3ab1f7UL)
          M(40, 0x89e1c36a3e9eff2eUL)
          M(48, 0x9b2af612f4c3ffe6UL)
          M(56, 0x491a762f05dad95bUL) ]
        [ Gpr(0, 0xa609bde0u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0xcd2f4fdau)
          M(0, 0xe11772ce7e79c6c7UL)
          M(8, 0x6b24f405738f64c0UL)
          M(16, 0x804253af5df91064UL)
          M(24, 0xa2cf63a7e8bfb7deUL)
          M(32, 0x1274eb0ac4640318UL)
          M(40, 0x54b213db93757292UL)
          M(48, 0x253c3dc44021e65eUL)
          M(56, 0x6b0c2f865a7f06eaUL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x80007fffu)
          M(0, 0x38831e4db06589e9UL)
          M(8, 0x13749afc60df6f7dUL)
          M(16, 0xb82a48120fe091aeUL)
          M(24, 0x146a9b458362e82aUL)
          M(32, 0x7b54f55a75b6ed13UL)
          M(40, 0xaa39e76989e29aceUL)
          M(48, 0x360921c07a900b23UL)
          M(56, 0xa7c728b672f85deeUL) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e1c10e92" inputs outputs

  /// <summary>
  /// F5.1.221 STLEXD: stlexd r0, r2, r3, [r1]. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.221 STLEXD``() =
    let inputs =
      [ [ Gpr(0, 0x069163b7u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x3e733873u)
          Gpr(3, 0xb28eabd9u)
          M(0, 0x85e126dbf3718c73UL)
          M(8, 0xfbc3331d71cc3073UL)
          M(16, 0x2ee8f2f857266de3UL)
          M(24, 0xc8310433c94af8f5UL)
          M(32, 0xb604f41ed70fff53UL)
          M(40, 0x6c1cc30cd1570975UL)
          M(48, 0x93b1d1da02e5e3b1UL)
          M(56, 0xfc2be4e308d81dc5UL) ]
        [ Gpr(0, 0x4fb5fa7cu)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x264b6064u)
          Gpr(3, 0x80765e58u)
          M(0, 0x8527f9707abf44edUL)
          M(8, 0x0749646b58f2d5abUL)
          M(16, 0xf7ec9fb7d1ed46bbUL)
          M(24, 0xb5a37aade6cbbcf7UL)
          M(32, 0x214078c274d99a50UL)
          M(40, 0x7f280c4b5493464aUL)
          M(48, 0xbedd195698cc27f8UL)
          M(56, 0xd9166ca0bfe6a842UL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x80007fffu)
          Gpr(3, 0x00000003u)
          M(0, 0xace0d592c4874616UL)
          M(8, 0xf3f47556b0a77aaeUL)
          M(16, 0xb3f5b891616e81e8UL)
          M(24, 0x715642651d01c4b8UL)
          M(32, 0x4d6685914ddbc9c5UL)
          M(40, 0xef782f6da2a85b2cUL)
          M(48, 0x8c6a3d27a523bb6eUL)
          M(56, 0xaf969a7e02cb28adUL) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e1a10e92" inputs outputs

  /// <summary>
  /// F5.1.222 STLEXH: stlexh r0, r2, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.222 STLEXH``() =
    let inputs =
      [ [ Gpr(0, 0x60d587b4u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x7568d897u)
          M(0, 0xae696f46a5057b8eUL)
          M(8, 0xcada14d335fe4110UL)
          M(16, 0x300551ce9a795c20UL)
          M(24, 0x2411fb24fe41c368UL)
          M(32, 0x6736e6ed4980324fUL)
          M(40, 0x8abb45c1613bb3acUL)
          M(48, 0xe9184ed9c3ddb06fUL)
          M(56, 0x06442701df30f5d7UL) ]
        [ Gpr(0, 0x8443b0aau)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x99eeec80u)
          M(0, 0x14d830eaf8a1e0a8UL)
          M(8, 0x17fea1aae6d94d1cUL)
          M(16, 0x8ece25ecb3f2e3feUL)
          M(24, 0xf8c46e5af74eaf01UL)
          M(32, 0x6460133659e5d3d5UL)
          M(40, 0x9a914915a8976825UL)
          M(48, 0x02e7b2f1af49fbc4UL)
          M(56, 0x38ce1ed2732774c1UL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          Gpr(2, 0x80007fffu)
          M(0, 0x1aa66938e82bfcf9UL)
          M(8, 0x5541503ae0d3a7dcUL)
          M(16, 0x53363a84c2fc3178UL)
          M(24, 0xb7cd02d4a1522308UL)
          M(32, 0x18b37063aff209c1UL)
          M(40, 0x24659970a7669a3bUL)
          M(48, 0x334ab408ac40b7a9UL)
          M(56, 0xd12c0390712883b4UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e1e10e92" inputs outputs

  /// <summary>
  /// F5.1.223 STLH: stlh r0, [r1]. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.223 STLH``() =
    let inputs =
      [ [ Gpr(0, 0xac4afc49u)
          Gpr(1, 0x20000810u)
          M(0, 0xbe1ce781233afe42UL)
          M(8, 0xede251eb0665f515UL)
          M(16, 0x21ca763142d0a8a8UL)
          M(24, 0x52961bb0c2d525c1UL)
          M(32, 0xea7a2093d542d9d9UL)
          M(40, 0xdbf57bb392139af7UL)
          M(48, 0x39db2449f42aba66UL)
          M(56, 0x50e7f10eb9294378UL) ]
        [ Gpr(0, 0x59d0a7a1u)
          Gpr(1, 0x20000810u)
          M(0, 0x4c6ea9ae378edf59UL)
          M(8, 0x989db3c69277341dUL)
          M(16, 0xe7592cb69fba78ddUL)
          M(24, 0x8c24c67b179f7bc3UL)
          M(32, 0x4a0a8ec31412ac5aUL)
          M(40, 0xb24c3f48ba083ecbUL)
          M(48, 0xdbf9c2ed547f4c84UL)
          M(56, 0x2711af5c7eba5a52UL) ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x20000810u)
          M(0, 0xaf7f86c8b960dbd7UL)
          M(8, 0xc0de58539ea6b709UL)
          M(16, 0x8e3b2f52daa1e40fUL)
          M(24, 0xca1bc0764daa6a7aUL)
          M(32, 0xefdfc8e8d9d9af95UL)
          M(40, 0x6220c680be0883c5UL)
          M(48, 0xeef8cb43e1272f73UL)
          M(56, 0x0f29b85cf19ffa47UL) ] ]
    let outputs =
      [ [ M(16, 0x21ca763142d0fc49UL) ]
        [ M(16, 0xe7592cb69fbaa7a1UL) ]
        [ M(16, 0x8e3b2f52daa1ffffUL) ] ]
    check false "e1e1fc90" inputs outputs

  /// <summary>
  /// F5.1.224 STMEA: stm r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.224 STMEA``() =
    let inputs =
      [ [ Gpr(1, 0x20000818u)
          Gpr(2, 0xd073be5au)
          Gpr(3, 0x0e83b49au)
          M(0, 0x6692796ebe1b4370UL)
          M(8, 0x3523b80e250f6dd4UL)
          M(16, 0x3afa8ed75e09f9acUL)
          M(24, 0x1d89e659c0d105fcUL)
          M(32, 0x8aba5dd9552508dfUL)
          M(40, 0xeae90c90b0431a94UL)
          M(48, 0x512869cba0877619UL)
          M(56, 0x85b4292bc5cdbac5UL) ]
        [ Gpr(1, 0x20000818u)
          Gpr(2, 0x0dcb12c0u)
          Gpr(3, 0x693ae6c9u)
          M(0, 0xe4625d43508d5309UL)
          M(8, 0xc171509754e5e104UL)
          M(16, 0xa7d54b4f2306c121UL)
          M(24, 0xdca67d22596fe5aaUL)
          M(32, 0x7acf6b188a95b50dUL)
          M(40, 0xb8157b42932f8145UL)
          M(48, 0x7cf3017dad96544aUL)
          M(56, 0x8d67826111a935e8UL) ]
        [ Gpr(1, 0x20000818u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0xf91fe05d6098d811UL)
          M(8, 0x6ad643a47f5e765eUL)
          M(16, 0x9d4040e5effe6f1dUL)
          M(24, 0xd2b4ade04110d455UL)
          M(32, 0xe63d3a5f9f79350eUL)
          M(40, 0x64ba3ec30b6f8241UL)
          M(48, 0x09e073e067a9b70bUL)
          M(56, 0xede33f90270936a9UL) ] ]
    let outputs =
      [ [ M(24, 0x0e83b49ad073be5aUL) ]
        [ M(24, 0x693ae6c90dcb12c0UL) ]
        [ M(24, 0x80007fff00000000UL) ] ]
    check false "e881000c" inputs outputs

  /// <summary>
  /// F5.1.224 STMIA: stm r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.224 STMIA``() =
    let inputs =
      [ [ Gpr(1, 0x20000818u)
          Gpr(2, 0x48fa5639u)
          Gpr(3, 0xba49a316u)
          M(0, 0x882fa8f4baedb37bUL)
          M(8, 0x576f5bba80f046e2UL)
          M(16, 0x3a1b28ac86703beeUL)
          M(24, 0x13f24db1ee17a46cUL)
          M(32, 0x6728970a3b709f5dUL)
          M(40, 0x467ad221cedc293dUL)
          M(48, 0x4fbf0a99c191976eUL)
          M(56, 0x59293458b827f895UL) ]
        [ Gpr(1, 0x20000818u)
          Gpr(2, 0x7f3f42adu)
          Gpr(3, 0x4c0a4409u)
          M(0, 0x6faee5ffceb6e80dUL)
          M(8, 0x9c88a916122297f8UL)
          M(16, 0x7bf5d52165a0fb07UL)
          M(24, 0xa1d6d8fe6e40818fUL)
          M(32, 0xf098c91195d06e9fUL)
          M(40, 0x2b974fc2018f4256UL)
          M(48, 0x3724f35be18366e7UL)
          M(56, 0xf57030be58928556UL) ]
        [ Gpr(1, 0x20000818u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0x9e4dc9319a2d169bUL)
          M(8, 0x98da028315a74ed4UL)
          M(16, 0x495da23e41ab3ffeUL)
          M(24, 0x9d328dfd1095b96bUL)
          M(32, 0xf1b249b7b8289b7dUL)
          M(40, 0x2d172991af646576UL)
          M(48, 0xf81eb5e9e8e87504UL)
          M(56, 0xf6660dc7ae03e88fUL) ] ]
    let outputs =
      [ [ M(24, 0xba49a31648fa5639UL) ]
        [ M(24, 0x4c0a44097f3f42adUL) ]
        [ M(24, 0x80007fff00000000UL) ] ]
    check false "e881000c" inputs outputs

  /// <summary>
  /// F5.1.226 STMED: stmda r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.226 STMED``() =
    let inputs =
      [ [ Gpr(1, 0x2000081cu)
          Gpr(2, 0xe8c880f6u)
          Gpr(3, 0xdb303358u)
          M(0, 0x643e0c79e077727fUL)
          M(8, 0x1e2fca56361a8cacUL)
          M(16, 0x3d30fd3a50eed790UL)
          M(24, 0xc5d8dd7225a70490UL)
          M(32, 0xfecbc18dbbcdd0b5UL)
          M(40, 0x86254803f693fc4dUL)
          M(48, 0xbddffb6904901faaUL)
          M(56, 0x7febd21fc784b792UL) ]
        [ Gpr(1, 0x2000081cu)
          Gpr(2, 0x09206433u)
          Gpr(3, 0x26ac2e90u)
          M(0, 0x3a23e25aec3a005dUL)
          M(8, 0x0a9a1d298295bebbUL)
          M(16, 0x5110e2f9d1a559bdUL)
          M(24, 0xc917b8b3f314129bUL)
          M(32, 0x067eebed3b6c1592UL)
          M(40, 0x9a1a7b696663cf35UL)
          M(48, 0x7d58576ee3ba480aUL)
          M(56, 0x1de6185c467868e3UL) ]
        [ Gpr(1, 0x2000081cu)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0xd2c2f43fe66bd3bcUL)
          M(8, 0xc34bd9ddc0ba6676UL)
          M(16, 0x38a4f0630601c92fUL)
          M(24, 0xda1f4828ae27faf2UL)
          M(32, 0x7d209bfff9c2347bUL)
          M(40, 0x40701db16bb9f2d5UL)
          M(48, 0x7d04c513eb26a17eUL)
          M(56, 0xdba8bbeb4541c48aUL) ] ]
    let outputs =
      [ [ M(24, 0xdb303358e8c880f6UL) ]
        [ M(24, 0x26ac2e9009206433UL) ]
        [ M(24, 0x80007fff00000000UL) ] ]
    check false "e801000c" inputs outputs

  /// <summary>
  /// F5.1.227 STMFD: stmdb r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.227 STMFD``() =
    let inputs =
      [ [ Gpr(1, 0x20000820u)
          Gpr(2, 0xa9a87542u)
          Gpr(3, 0x4bc9ee2du)
          M(0, 0x1814b8d285f9d5f3UL)
          M(8, 0x3a5423f0a430ff3dUL)
          M(16, 0x87c30b9f37ee3cfeUL)
          M(24, 0xe3f06bf432d0a237UL)
          M(32, 0x96a39e4cf827f983UL)
          M(40, 0xe8f68e073d3d9310UL)
          M(48, 0x30b3cc9b5908a896UL)
          M(56, 0x2d6f7043a3da3084UL) ]
        [ Gpr(1, 0x20000820u)
          Gpr(2, 0x08161032u)
          Gpr(3, 0xa4f83bd9u)
          M(0, 0xe55e32476bfc0665UL)
          M(8, 0x4807589e02f6f900UL)
          M(16, 0xd1c84156799e08feUL)
          M(24, 0x04c8014745dc4e82UL)
          M(32, 0x62a24ca6bdd0664cUL)
          M(40, 0xc5cb885601136627UL)
          M(48, 0x1e94eaae015e7a20UL)
          M(56, 0xd840ce27b43a94c6UL) ]
        [ Gpr(1, 0x20000820u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0x1a5aa52e140e7c31UL)
          M(8, 0xe83d58e620f79a78UL)
          M(16, 0x652c08828506597bUL)
          M(24, 0xc8c53083d195f0b1UL)
          M(32, 0xce1fac865932c8c4UL)
          M(40, 0x9c94b3a412783b30UL)
          M(48, 0xf82ea165ef65256aUL)
          M(56, 0x7677d3379abc3f7fUL) ] ]
    let outputs =
      [ [ M(24, 0x4bc9ee2da9a87542UL) ]
        [ M(24, 0xa4f83bd908161032UL) ]
        [ M(24, 0x80007fff00000000UL) ] ]
    check false "e901000c" inputs outputs

  /// <summary>
  /// F5.1.228 STMFA: stmib r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.228 STMFA``() =
    let inputs =
      [ [ Gpr(1, 0x20000814u)
          Gpr(2, 0xc954f080u)
          Gpr(3, 0xa7bf4009u)
          M(0, 0x658c013148284121UL)
          M(8, 0x580a568b44a38b6eUL)
          M(16, 0xcf6335f16b735540UL)
          M(24, 0x82a0d9fa4ff902d7UL)
          M(32, 0x679965ed7505293fUL)
          M(40, 0x5fc902d87ab4b307UL)
          M(48, 0xa8fb6e52b0edf7d1UL)
          M(56, 0x75fef4115d8a2968UL) ]
        [ Gpr(1, 0x20000814u)
          Gpr(2, 0x5cb3f1efu)
          Gpr(3, 0x1af80a95u)
          M(0, 0xcb0442cbec2c1acbUL)
          M(8, 0x5036eaad6c49ea13UL)
          M(16, 0xf27857c998810012UL)
          M(24, 0x9983aaee267ae1d8UL)
          M(32, 0x8e8bf4587bbec069UL)
          M(40, 0x04d9c4d58abfa8d2UL)
          M(48, 0x22f6ee20dd592513UL)
          M(56, 0xab56dc7050f50d03UL) ]
        [ Gpr(1, 0x20000814u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0xd25ca76385850890UL)
          M(8, 0xaa6d5341c9db55ecUL)
          M(16, 0x8998b7db1050de28UL)
          M(24, 0x597c1949cb7b642fUL)
          M(32, 0x4474127d570f8684UL)
          M(40, 0x638610a6b9cdceacUL)
          M(48, 0xee752c0fc2c4f039UL)
          M(56, 0x5fbe4d66c0e900e1UL) ] ]
    let outputs =
      [ [ M(24, 0xa7bf4009c954f080UL) ]
        [ M(24, 0x1af80a955cb3f1efUL) ]
        [ M(24, 0x80007fff00000000UL) ] ]
    check false "e981000c" inputs outputs

  /// <summary>
  /// F5.1.261 TSB: .inst 0xe320f012. It lifts to no statements: what it does is
  /// a hint or an ordering of memory accesses that one run cannot observe, and
  /// QEMU's runs of it changed no register and no byte, so a value test would
  /// assert nothing.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.261 TSB``() =
    Assert.AreEqual(0, (lift false "e320f012").Length)

  /// <summary>
  /// F5.1.278 UMLALS: umlals r0, r1, r1, r2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.278 UMLALS``() =
    let inputs =
      [ [ Gpr(0, 0xb00ca214u)
          Gpr(1, 0x64c4b0adu)
          Gpr(2, 0x4efd9dceu)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xfab4c9e9u)
          Gpr(1, 0x95a5da71u)
          Gpr(2, 0x31fca8dbu)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xb7a5e64au); Gpr(1, 0x83dc7302u); Cell.CPSR 0xa0000010u ]
        [ Gpr(0, 0x7f2cd094u); Gpr(1, 0xb2de4b39u); Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Cell.CPSR 0x08050010u ] ]
    check false "e0b10291" inputs outputs

  /// <summary>
  /// F5.1.279 UMULLS: umulls r0, r1, r1, r2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F5.1.279 UMULLS``() =
    let inputs =
      [ [ Gpr(0, 0x01417434u)
          Gpr(1, 0x76dfa7efu)
          Gpr(2, 0xadd2add9u)
          Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0xae095c18u)
          Gpr(1, 0x54ae56afu)
          Gpr(2, 0xbf6b11beu)
          Cell.CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x2d1fdc97u); Gpr(1, 0x50b6f8aeu); Cell.CPSR 0x20000010u ]
        [ Gpr(0, 0x394af4e2u); Gpr(1, 0x3f517d69u); Cell.CPSR 0x100a0010u ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x00000000u); Cell.CPSR 0x48050010u ] ]
    check false "e0910291" inputs outputs

  /// <summary>
  /// F6.1.1 AESD: aesd.8 q0, q1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.1 AESD``() =
    let inputs =
      [ [ D(0, 0x0d2fb2c6294a7c6dUL)
          D(1, 0x124da8e9fea19c09UL)
          D(2, 0xf6ba7f27c90af1b7UL)
          D(3, 0xc980c34d74e2f06dUL) ]
        [ D(0, 0x27824ec557c30863UL)
          D(1, 0xd79e2f9f44385e16UL)
          D(2, 0x61ed714bb939598cUL)
          D(3, 0x408a2650e145a28eUL) ]
        [ D(0, 0x0000000000000001UL)
          D(1, 0x0102030405060708UL)
          D(2, 0x7fffffffffffffffUL)
          D(3, 0x0000000000000001UL) ] ]
    let outputs =
      [ [ D(0, 0xcf80b4e06364057aUL); D(1, 0xa0adb81d9f72808cUL) ]
        [ D(0, 0x299b70e698134061UL); D(1, 0x9906555f851425e2UL) ]
        [ D(0, 0x366a7d7d6ba5d50cUL); D(1, 0x7d7d3830097d7d40UL) ] ]
    check false "f3b00342" inputs outputs

  /// <summary>
  /// F6.1.2 AESE: aese.8 q0, q1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.2 AESE``() =
    let inputs =
      [ [ D(0, 0x863efd8194eab4b5UL)
          D(1, 0x05ced7976ae06b3fUL)
          D(2, 0x87adfc988316e1c1UL)
          D(3, 0x875525b0d4fccb3eUL) ]
        [ D(0, 0x6b9a370d21d87e48UL)
          D(1, 0x773539b049685686UL)
          D(2, 0xf5c74438767b1000UL)
          D(3, 0xa9ceae3ead9b42ddUL) ]
        [ D(0, 0x7fffffffffffffffUL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x0000000000000001UL)
          D(3, 0xffffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0xf014e0d4139c7c92UL); D(1, 0xaedcfccc7cb0897cUL) ]
        [ D(0, 0x5b0ffa961d0d8f52UL); D(1, 0x694c9f190b0a8839UL) ]
        [ D(0, 0x16636316636316bbUL); D(1, 0x63161663d2166363UL) ] ]
    check false "f3b00302" inputs outputs

  /// <summary>
  /// F6.1.3 AESIMC: aesimc.8 q0, q1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.3 AESIMC``() =
    let inputs =
      [ [ D(0, 0x4fb39d10cb4edab9UL)
          D(1, 0x875fc5b16bce3e66UL)
          D(2, 0x170fb37390da23e2UL)
          D(3, 0x7b3d9b4006a44469UL) ]
        [ D(0, 0x948329af7de9ea07UL)
          D(1, 0x75bb8d1c7a69f62bUL)
          D(2, 0x14a910db08ea0a3bUL)
          D(3, 0x5b6e5646f077b496UL) ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0x0000000000000001UL)
          D(2, 0x7fffffffffffffffUL)
          D(3, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0x3b96344131118f24UL); D(1, 0xb947781b507917b1UL) ]
        [ D(0, 0x6af0826e774dc821UL); D(1, 0x43b204d0cd31d881UL) ]
        [ D(0, 0xbe082513ffffffffUL); D(1, 0xe51ae51ae51ae51aUL) ] ]
    check false "f3b003c2" inputs outputs

  /// <summary>
  /// F6.1.4 AESMC: aesmc.8 q0, q1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.4 AESMC``() =
    let inputs =
      [ [ D(0, 0x7fcd0b4941102020UL)
          D(1, 0xa01f8fe98ff6d767UL)
          D(2, 0x507f833dd9f7e1f0UL)
          D(3, 0xa8397c95def534c4UL) ]
        [ D(0, 0xb12a3de6682d6b9cUL)
          D(1, 0x8abb26474d42e037UL)
          D(2, 0x9e01b09c969842c3UL)
          D(3, 0x6124588d3a55c822UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x00ff00ff00ff00ffUL)
          D(3, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0x1bb0f1cbb494f2edUL); D(1, 0xaa788e24317876e4UL) ]
        [ D(0, 0x29977a77b30b6255UL); D(1, 0x323e30ac8f0e6c68UL) ]
        [ D(0, 0xe51ae51ae51ae51aUL); D(1, 0xe51ae51ae51ae51aUL) ] ]
    check false "f3b00382" inputs outputs

  /// <summary>
  /// F6.1.6 FSTMDBX: fstmdbx r1!, {d0, d1, d2, d3, d4, d5, d6}. The outputs are
  /// what QEMU left after running it on the inputs, three runs paired by
  /// position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.6 FSTMDBX``() =
    let inputs =
      [ [ Gpr(1, 0x2000083cu)
          D(0, 0x07678a5e54e5bf78UL)
          D(1, 0x168e732e08e28ca8UL)
          D(2, 0x2eb4d674806f4dc3UL)
          D(3, 0xfb1c1916a79bfdf4UL)
          D(4, 0xb8a8407de29a3ef7UL)
          D(5, 0x55a8faa5b5acb48dUL)
          D(6, 0x61fac22701b513b3UL)
          M(0, 0x94d82ebe1ff745eeUL)
          M(8, 0xfa9e3a80b313de19UL)
          M(16, 0x376631d16d48f896UL)
          M(24, 0x1b4da5e5f9c57e85UL)
          M(32, 0x06eb4f026f55d4c2UL)
          M(40, 0x4eae48178df441aaUL)
          M(48, 0xe37cbeee04287c07UL)
          M(56, 0x1147eccca00cf0a2UL) ]
        [ Gpr(1, 0x2000083cu)
          D(0, 0x6c15746abb58fcecUL)
          D(1, 0x5f0ce07c6c973280UL)
          D(2, 0xd9dcb0d277b2225fUL)
          D(3, 0x8e820a4e73d02cefUL)
          D(4, 0x3fd5cedf51756795UL)
          D(5, 0xa3b103841a20522eUL)
          D(6, 0xc37627b8e2345991UL)
          M(0, 0xfd01d1dfe88e1e72UL)
          M(8, 0xcec248de80aea7fcUL)
          M(16, 0x15b161c508b31657UL)
          M(24, 0x71ff4e712be09b9dUL)
          M(32, 0x9423d09f64492cfeUL)
          M(40, 0x87836d937be2f0f9UL)
          M(48, 0x899a8a2a8cf636f4UL)
          M(56, 0x8281eec6a17cfeb7UL) ]
        [ Gpr(1, 0x2000083cu)
          D(0, 0x8001800180018001UL)
          D(1, 0x8001800180018001UL)
          D(2, 0x8000000000000000UL)
          D(3, 0x8000000000000000UL)
          D(4, 0x8000000000000000UL)
          D(5, 0x00ff00ff00ff00ffUL)
          D(6, 0x00ff00ff00ff00ffUL)
          M(0, 0x731db2a32964bd10UL)
          M(8, 0x3d443a743cf9b8cbUL)
          M(16, 0xbeddfbc2ea1782e4UL)
          M(24, 0x65cf65f40fe9b894UL)
          M(32, 0xb0ae5a2ff17b37e1UL)
          M(40, 0x69d7f1df93d4c45aUL)
          M(48, 0x1bbba2d2fd342612UL)
          M(56, 0x52143ffd921b85d0UL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000800u)
          M(0, 0x07678a5e54e5bf78UL)
          M(8, 0x168e732e08e28ca8UL)
          M(16, 0x2eb4d674806f4dc3UL)
          M(24, 0xfb1c1916a79bfdf4UL)
          M(32, 0xb8a8407de29a3ef7UL)
          M(40, 0x55a8faa5b5acb48dUL)
          M(48, 0x61fac22701b513b3UL) ]
        [ Gpr(1, 0x20000800u)
          M(0, 0x6c15746abb58fcecUL)
          M(8, 0x5f0ce07c6c973280UL)
          M(16, 0xd9dcb0d277b2225fUL)
          M(24, 0x8e820a4e73d02cefUL)
          M(32, 0x3fd5cedf51756795UL)
          M(40, 0xa3b103841a20522eUL)
          M(48, 0xc37627b8e2345991UL) ]
        [ Gpr(1, 0x20000800u)
          M(0, 0x8001800180018001UL)
          M(8, 0x8001800180018001UL)
          M(16, 0x8000000000000000UL)
          M(24, 0x8000000000000000UL)
          M(32, 0x8000000000000000UL)
          M(40, 0x00ff00ff00ff00ffUL)
          M(48, 0x00ff00ff00ff00ffUL) ] ]
    check false "ed210b0f" inputs outputs

  /// <summary>
  /// F6.1.6 FSTMIAX: fstmiax r1, {d0, d1, d2, d3, d4, d5, d6}. The outputs are
  /// what QEMU left after running it on the inputs, three runs paired by
  /// position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.6 FSTMIAX``() =
    let inputs =
      [ [ Gpr(1, 0x20000800u)
          D(0, 0xafa4f4613ec15eafUL)
          D(1, 0x6145421f2526df51UL)
          D(2, 0x7541fba90c9eb858UL)
          D(3, 0x90978029fd29c4c4UL)
          D(4, 0x0550c3cd4a6f4ea5UL)
          D(5, 0x101743a64db46dabUL)
          D(6, 0x3ff47d018aff3a32UL)
          M(0, 0x345f8e0bf40196e6UL)
          M(8, 0xc2b122bf8211195fUL)
          M(16, 0xace23c982701298dUL)
          M(24, 0xc74707ba0adb54aeUL)
          M(32, 0xa361f85bb292f487UL)
          M(40, 0x7a3539ca0e706e0fUL)
          M(48, 0xba8e75021c575c47UL)
          M(56, 0x67955acb54207455UL) ]
        [ Gpr(1, 0x20000800u)
          D(0, 0xb81bcccc11dfbf1dUL)
          D(1, 0x9964a950ecd72f0dUL)
          D(2, 0xaa93aa3759d4af2dUL)
          D(3, 0x7a15cd33ad79517eUL)
          D(4, 0x8027f2d36a4d294fUL)
          D(5, 0xe7a64594885bdf75UL)
          D(6, 0xaec544821e8702e9UL)
          M(0, 0xbda385fc977a7dc0UL)
          M(8, 0xba45c6571976ca7aUL)
          M(16, 0x46c211483fadcb77UL)
          M(24, 0x702e2f39e1792fddUL)
          M(32, 0x1913fb27149265f8UL)
          M(40, 0xfc8e45c55d228909UL)
          M(48, 0x0d43d9b8e7de162eUL)
          M(56, 0x2a03ea6ea500e404UL) ]
        [ Gpr(1, 0x20000800u)
          D(0, 0x8001800180018001UL)
          D(1, 0x7fffffffffffffffUL)
          D(2, 0x0000000000000001UL)
          D(3, 0x7f80ff00807fffffUL)
          D(4, 0xffffffffffffffffUL)
          D(5, 0x0102030405060708UL)
          D(6, 0x8000000000000000UL)
          M(0, 0xb639c176cfa41db5UL)
          M(8, 0xe7b98e4edb5b746eUL)
          M(16, 0x0b167af0857d8720UL)
          M(24, 0x655250ba868da109UL)
          M(32, 0x1e70a7887c82eb83UL)
          M(40, 0x537bb1abf60d971fUL)
          M(48, 0x3c2fb52001effde8UL)
          M(56, 0xbf000079f94401e6UL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000800u)
          M(0, 0xafa4f4613ec15eafUL)
          M(8, 0x6145421f2526df51UL)
          M(16, 0x7541fba90c9eb858UL)
          M(24, 0x90978029fd29c4c4UL)
          M(32, 0x0550c3cd4a6f4ea5UL)
          M(40, 0x101743a64db46dabUL)
          M(48, 0x3ff47d018aff3a32UL) ]
        [ Gpr(1, 0x20000800u)
          M(0, 0xb81bcccc11dfbf1dUL)
          M(8, 0x9964a950ecd72f0dUL)
          M(16, 0xaa93aa3759d4af2dUL)
          M(24, 0x7a15cd33ad79517eUL)
          M(32, 0x8027f2d36a4d294fUL)
          M(40, 0xe7a64594885bdf75UL)
          M(48, 0xaec544821e8702e9UL) ]
        [ Gpr(1, 0x20000800u)
          M(0, 0x8001800180018001UL)
          M(8, 0x7fffffffffffffffUL)
          M(16, 0x0000000000000001UL)
          M(24, 0x7f80ff00807fffffUL)
          M(32, 0xffffffffffffffffUL)
          M(40, 0x0102030405060708UL)
          M(48, 0x8000000000000000UL) ] ]
    check false "ec810b0f" inputs outputs

  /// <summary>
  /// F6.1.7 SHA1C: sha1c.32 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.7 SHA1C``() =
    let inputs =
      [ [ D(0, 0xe93f2cfd4b93682dUL)
          D(1, 0xced11a9385e8a1a3UL)
          D(2, 0xb02b7d32adee6002UL)
          D(4, 0xe7465ac62fed7affUL)
          D(5, 0xf3ef6baa0a8283cfUL) ]
        [ D(0, 0xc44dd3f05fab4424UL)
          D(1, 0xaf920199de2e1ba7UL)
          D(2, 0x006aeee402678076UL)
          D(4, 0x544f9400ac5a8cf6UL)
          D(5, 0xddadcd2a75188ca7UL) ]
        [ D(0, 0xffffffffffffffffUL)
          D(1, 0x8001800180018001UL)
          D(2, 0x8000000000000000UL)
          D(4, 0x00ff00ff00ff00ffUL)
          D(5, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0x578f181eb2668d7eUL); D(1, 0x760c44d3e2a96a30UL) ]
        [ D(0, 0x46d7a3eb00a838d7UL); D(1, 0x24f22968837f6a54UL) ]
        [ D(0, 0x22171df5c1d4bde3UL); D(1, 0xe040203fe844283bUL) ] ]
    check false "f2020c44" inputs outputs

  /// <summary>
  /// F6.1.8 SHA1H: sha1h.32 q0, q1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.8 SHA1H``() =
    let inputs =
      [ [ D(0, 0x86d72e878ffb46dfUL)
          D(1, 0xf6ecdebb7c976279UL)
          D(2, 0xbcf55d18d3c8751cUL) ]
        [ D(0, 0x505ced72e6be8d8eUL)
          D(1, 0xd56d73ca718639dfUL)
          D(2, 0xe4b2f433fdef2861UL) ]
        [ D(0, 0x00ff00ff00ff00ffUL)
          D(1, 0x7fffffffffffffffUL)
          D(2, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0x0000000034f21d47UL); D(1, 0x0000000000000000UL) ]
        [ D(0, 0x000000007f7bca18UL); D(1, 0x0000000000000000UL) ]
        [ D(0, 0x0000000060006000UL); D(1, 0x0000000000000000UL) ] ]
    check false "f3b902c2" inputs outputs

  /// <summary>
  /// F6.1.9 SHA1M: sha1m.32 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.9 SHA1M``() =
    let inputs =
      [ [ D(0, 0x09bf03a604f02544UL)
          D(1, 0xa7fcf07ef80589f6UL)
          D(2, 0x28096f58376211bfUL)
          D(4, 0x7f8682faacebe61aUL)
          D(5, 0x5ef3d89b1d7273caUL) ]
        [ D(0, 0x9481efa4ec8bda1fUL)
          D(1, 0x69d9776f5adab2afUL)
          D(2, 0x614c96e297a634c4UL)
          D(4, 0xf66816836e4c5652UL)
          D(5, 0x542590be270bc553UL) ]
        [ D(0, 0x7fffffffffffffffUL)
          D(1, 0x00ff00ff00ff00ffUL)
          D(2, 0x8000000000000000UL)
          D(4, 0x8000000000000000UL)
          D(5, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x535be62e560c689fUL); D(1, 0xcb0408934a7b4fd0UL) ]
        [ D(0, 0x2bb58ebfecf9d543UL); D(1, 0xbc11f1b0f571583fUL) ]
        [ D(0, 0xfce318cd7d62fa7cUL); D(1, 0x803fc03fa037c82fUL) ] ]
    check false "f2220c44" inputs outputs

  /// <summary>
  /// F6.1.10 SHA1P: sha1p.32 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.10 SHA1P``() =
    let inputs =
      [ [ D(0, 0x816fe4f937d13928UL)
          D(1, 0x9c1f75638f19714eUL)
          D(2, 0x25f5b5d67d1e34c3UL)
          D(4, 0x86e61de628f0db42UL)
          D(5, 0x14a7f250f9a3ef9dUL) ]
        [ D(0, 0x0f44f831212e6805UL)
          D(1, 0xf201ece1df35d4dfUL)
          D(2, 0x6e81548072e7ddfcUL)
          D(4, 0x2d8fbead2360911eUL)
          D(5, 0x42fffe0c4d30fb5bUL) ]
        [ D(0, 0x0000000000000001UL)
          D(1, 0x0000000000000001UL)
          D(2, 0x00ff00ff00ff00ffUL)
          D(4, 0x0102030405060708UL)
          D(5, 0xffffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0xdb4d147f6d66c743UL); D(1, 0xcca80577d3e70021UL) ]
        [ D(0, 0xc5c85fefd1a573fdUL); D(1, 0x77a18bf3eb888a07UL) ]
        [ D(0, 0x7a6608c0cce3621cUL); D(1, 0x0181420a3068c201UL) ] ]
    check false "f2120c44" inputs outputs

  /// <summary>
  /// F6.1.11 SHA1SU0: sha1su0.32 q0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.11 SHA1SU0``() =
    let inputs =
      [ [ D(0, 0xd62b650c0dae0da9UL)
          D(1, 0xd449f2b35622c769UL)
          D(2, 0x3d50e51dd6498250UL)
          D(4, 0x0858c8f2229444f3UL)
          D(5, 0xc9b513958e9d8760UL) ]
        [ D(0, 0x09e0011228968052UL)
          D(1, 0xe51ca4ce4d1b78cfUL)
          D(2, 0x26a7825dffbf2d2bUL)
          D(4, 0xd60a47b8d4047b4bUL)
          D(5, 0x38668cdd0644d1d2UL) ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0x8000000000000000UL)
          D(2, 0x7fffffffffffffffUL)
          D(4, 0x00ff00ff00ff00ffUL)
          D(5, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0x0a3a5f4d79188e33UL); D(1, 0x20ac043b0ef6c259UL) ]
        [ D(0, 0x3af6e264b18983d6UL); D(1, 0xfbddaa4eb4e08436UL) ]
        [ D(0, 0x00ff00ff00ff00ffUL); D(1, 0x7ffe7ffe7ffe7ffeUL) ] ]
    check false "f2320c44" inputs outputs

  /// <summary>
  /// F6.1.12 SHA1SU1: sha1su1.32 q0, q1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.12 SHA1SU1``() =
    let inputs =
      [ [ D(0, 0x5403ba2e401f2711UL)
          D(1, 0x49972c90ec965a7aUL)
          D(2, 0x3b375cb456cf4eecUL)
          D(3, 0xd38efd271ff7ef0dUL) ]
        [ D(0, 0xf34851f2e6e073ffUL)
          D(1, 0x207b3a434d977c36UL)
          D(2, 0xc34bcf7f4010609dUL)
          D(3, 0x1fcd597fa85af76fUL) ]
        [ D(0, 0x8001800180018001UL)
          D(1, 0x7f80ff00807fffffUL)
          D(2, 0x0102030405060708UL)
          D(3, 0x00ff00ff00ff00ffUL) ] ]
    let outputs =
      [ [ D(0, 0x97e8aa46f650f74aUL); D(1, 0x7f8fb7b57e314ebaUL) ]
        [ D(0, 0xb6254d3a4b577900UL); D(1, 0xd6588686a4b44a92UL) ]
        [ D(0, 0x01fd01fd0207060bUL); D(1, 0xfb0ff2160101fe01UL) ] ]
    check false "f3ba0382" inputs outputs

  /// <summary>
  /// F6.1.13 SHA256H: sha256h.32 q0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.13 SHA256H``() =
    let inputs =
      [ [ D(0, 0xe3b52a0dea123d84UL)
          D(1, 0x38f73a9368629ac0UL)
          D(2, 0xd8d6aed4cb0aec5dUL)
          D(3, 0x4f296536de4ecd50UL)
          D(4, 0xd938ac856e28c4e8UL)
          D(5, 0x929b3a64ba048fc8UL) ]
        [ D(0, 0x6ead86c6f3a2b647UL)
          D(1, 0x3031a0fe81923173UL)
          D(2, 0x3dae586568dc3afeUL)
          D(3, 0x3ba1f4e72f90c5bbUL)
          D(4, 0x863a3cc5e4e3457cUL)
          D(5, 0x06d2e7ba30a277dfUL) ]
        [ D(0, 0x00ff00ff00ff00ffUL)
          D(1, 0x8001800180018001UL)
          D(2, 0x0000000000000001UL)
          D(3, 0xffffffffffffffffUL)
          D(4, 0x00ff00ff00ff00ffUL)
          D(5, 0x0000000000000001UL) ] ]
    let outputs =
      [ [ D(0, 0xa49aada01c9d65d4UL); D(1, 0x9c044257201a840dUL) ]
        [ D(0, 0xc6256529c60e49ffUL); D(1, 0xc03611b1bd60376bUL) ]
        [ D(0, 0xe3be941c1bdca998UL); D(1, 0x41e23e3ff55d186eUL) ] ]
    check false "f3020c44" inputs outputs

  /// <summary>
  /// F6.1.14 SHA256H2: sha256h2.32 q0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.14 SHA256H2``() =
    let inputs =
      [ [ D(0, 0x3a084fd7c892a87eUL)
          D(1, 0x748df4b6c021f5efUL)
          D(2, 0x8086b688674f78eaUL)
          D(3, 0x5a3a3848a4eebefaUL)
          D(4, 0x9e007c317497259eUL)
          D(5, 0xea190394c0a959dbUL) ]
        [ D(0, 0xa2b563f23bfc686bUL)
          D(1, 0xca65ffae4fd23f97UL)
          D(2, 0x63de66ebbae4da35UL)
          D(3, 0x89465a4469f9b213UL)
          D(4, 0x29b7c5617f3983ecUL)
          D(5, 0xad66236ad380bb62UL) ]
        [ D(0, 0x8001800180018001UL)
          D(1, 0x8000000000000000UL)
          D(2, 0x00ff00ff00ff00ffUL)
          D(3, 0x8001800180018001UL)
          D(4, 0x8000000000000000UL)
          D(5, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0x80f4708be8b7180bUL); D(1, 0x09301803d17368d7UL) ]
        [ D(0, 0x06aea1a80071d280UL); D(1, 0x99591185a9dea726UL) ]
        [ D(0, 0xef248ceb8f5c0e90UL); D(1, 0x86f306f2edcb6b3aUL) ] ]
    check false "f3120c44" inputs outputs

  /// <summary>
  /// F6.1.15 SHA256SU0: sha256su0.32 q0, q1. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.15 SHA256SU0``() =
    let inputs =
      [ [ D(0, 0x841dc5a4a9a0c7d0UL)
          D(1, 0x8656d23f9edf3d59UL)
          D(2, 0x0a6cbcf39af1267fUL) ]
        [ D(0, 0x407ac9e86d6cd460UL)
          D(1, 0x35229fe622c9c983UL)
          D(2, 0x435b69d4b30bec68UL) ]
        [ D(0, 0x7fffffffffffffffUL)
          D(1, 0x8001800180018001UL)
          D(2, 0x0102030405060708UL) ] ]
    let outputs =
      [ [ D(0, 0xf3ce040ad2836a08UL); D(1, 0x2c4af27e7a28d3cfUL) ]
        [ D(0, 0xb0f72bf9d8629110UL); D(1, 0x713fe67d9001650eUL) ]
        [ D(0, 0xf30052ff0effdffeUL); D(1, 0x116a4daff301d301UL) ] ]
    check false "f3ba03c2" inputs outputs

  /// <summary>
  /// F6.1.16 SHA256SU1: sha256su1.32 q0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.16 SHA256SU1``() =
    let inputs =
      [ [ D(0, 0x56a83a557eac6b3aUL)
          D(1, 0xcbaa53b899bd44c7UL)
          D(2, 0x580b418c8647a02bUL)
          D(3, 0x816ee81fa6b12fcdUL)
          D(4, 0x4e336c6f437ebd62UL)
          D(5, 0x38bcc3a26f2033afUL) ]
        [ D(0, 0xfc2634ec09c107c1UL)
          D(1, 0xe6bc65820749c014UL)
          D(2, 0x1c2896e0bf129fa5UL)
          D(3, 0x66341ed054cad6edUL)
          D(4, 0x0b6897b89c9dccb2UL)
          D(5, 0x6e8cf7313bbd756dUL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x00ff00ff00ff00ffUL)
          D(2, 0x7fffffffffffffffUL)
          D(3, 0x8000000000000000UL)
          D(4, 0x8000000000000000UL)
          D(5, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0xf704de9bf6713f3eUL); D(1, 0x03cc556fd371669fUL) ]
        [ D(0, 0x3656458339ff7495UL); D(1, 0x6dd69aa4c2542301UL) ]
        [ D(0, 0x6fa1ef60f0a0f05eUL); D(1, 0xcb46d35ee7178f77UL) ] ]
    check false "f3220c44" inputs outputs

  /// <summary>
  /// F6.1.39 VCADD: vcadd.f32 d0, d1, d2, #0x5a. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.39 VCADD``() =
    let inputs =
      [ [ D(0, 0x40c0000041400000UL)
          D(1, 0x40000000bec00000UL)
          D(2, 0xbf8000003d800000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x4140000041200000UL)
          D(1, 0x3f400000bf000000UL)
          D(2, 0x3e800000c0d00000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x800000007f800000UL)
          D(1, 0x7f80000040400000UL)
          D(2, 0x8000000000000000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x400400003f200000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0xc0b80000bf400000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7f80000040400000UL); Cell.FPSCR 0x00000000u ] ]
    check false "fc910802" inputs outputs

  /// <summary>
  /// F6.1.52 VCMLA: vcmla.f32 d0, d1, d2, #0x0. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.52 VCMLA``() =
    let inputs =
      [ [ D(0, 0xbec0000040200000UL)
          D(1, 0x3fe0000041400000UL)
          D(2, 0xbf8000003e800000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xc240000040000000UL)
          D(1, 0xbf800000c0d00000UL)
          D(2, 0xc0d00000bec00000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x800000003f000000UL)
          D(1, 0xc010000040400000UL)
          D(2, 0xff80000040400000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xc146000040b00000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0xc0b80000408e0000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0xff80000041180000UL); Cell.FPSCR 0x00000000u ] ]
    check false "fc310802" inputs outputs

  /// <summary>
  /// F6.1.65 VCVTA: vcvta.s32.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.65 VCVTA``() =
    let inputs =
      [ [ D(0, 0xbec00000c0600000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0xc0d00000bec00000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x40400000ff800000UL); Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xbec0000000000000UL); Cell.FPSCR 0x00000010u ]
        [ D(0, 0xc0d00000fffffff9UL); Cell.FPSCR 0x60000010u ]
        [ D(0, 0x4040000000000003UL); Cell.FPSCR 0x00000000u ] ]
    check false "febc0ae0" inputs outputs

  /// <summary>
  /// F6.1.69 VCVTM: vcvtm.s32.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.69 VCVTM``() =
    let inputs =
      [ [ D(0, 0xbec0000040000000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x40400000bf800000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7f8000003fc00000UL); Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xbec00000ffffffffUL); Cell.FPSCR 0x00000010u ]
        [ D(0, 0x4040000000000003UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7f8000007fffffffUL); Cell.FPSCR 0x00000001u ] ]
    check false "febf0ae0" inputs outputs

  /// <summary>
  /// F6.1.71 VCVTN: vcvtn.s32.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.71 VCVTN``() =
    let inputs =
      [ [ D(0, 0x40400000bec00000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x41200000bec00000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0xff8000003f000000UL); Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x4040000000000003UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x412000000000000aUL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0xff80000080000000UL); Cell.FPSCR 0x00000001u ] ]
    check false "febd0ae0" inputs outputs

  /// <summary>
  /// F6.1.73 VCVTP: vcvtp.s32.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.73 VCVTP``() =
    let inputs =
      [ [ D(0, 0xc060000040000000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x42c9000042c90000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3f00000000000000UL); Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xc0600000fffffffdUL); Cell.FPSCR 0x00000010u ]
        [ D(0, 0x42c9000000000065UL); Cell.FPSCR 0x60000010u ]
        [ D(0, 0x3f00000000000001UL); Cell.FPSCR 0x00000010u ] ]
    check false "febe0ae0" inputs outputs

  /// <summary>
  /// F6.1.79 VDOT: vdot.bf16 d0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.79 VDOT``() =
    let inputs =
      [ [ D(0, 0xbf003f40c0103fc0UL)
          D(1, 0xbf003e00bf004020UL)
          D(2, 0x3fc04140c010c0d0UL) ]
        [ D(0, 0x3e00c060c240bf80UL)
          D(1, 0x40e84480c0404080UL)
          D(2, 0x448040803e004040UL) ]
        [ D(0, 0x40400000c0104040UL)
          D(1, 0xc0100000c0104040UL)
          D(2, 0xc0103fc03fc07f80UL) ] ]
    let outputs =
      [ [ D(0, 0x3e7f0300c18b07f8UL) ]
        [ D(0, 0x46340081c2123f80UL) ]
        [ D(0, 0x410100007f800000UL) ] ]
    check false "fc010d02" inputs outputs

  /// <summary>
  /// F6.1.87 VFMAB: vfmab.bf16 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.87 VFMAB``() =
    let inputs =
      [ [ D(0, 0x3d804040c2404040UL)
          D(1, 0x3d803fe0c06042c9UL)
          D(2, 0x4120c2404140bf00UL)
          D(3, 0xc0403fe0408040c0UL)
          D(4, 0x40203fc0c240c0d0UL)
          D(5, 0xbec0c04040c04020UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x40c03d80c0604040UL)
          D(1, 0xbf80c010bf80c010UL)
          D(2, 0x3d8040804080bf80UL)
          D(3, 0x40c042c9c040c0d0UL)
          D(4, 0xc0404000c240c060UL)
          D(5, 0x3fe03fe03e00bf00UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0xff803f003f003fc0UL)
          D(1, 0x3f003fc080000000UL)
          D(2, 0xc01000000000c010UL)
          D(3, 0xc010ff807f80c010UL)
          D(4, 0x800080004040ff80UL)
          D(5, 0x3fc080003fc07f80UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xc28fdff0c2334040UL)
          D(1, 0xc0a5ff004137ef4eUL)
          Cell.FPSCR 0x00000010u ]
        [ D(0, 0x41601ec0bb808000UL)
          D(1, 0x432ede80400f9ff8UL)
          Cell.FPSCR 0x60000010u ]
        [ D(0, 0x7fc000007f800000UL)
          D(1, 0x7fc00000ff800000UL)
          Cell.FPSCR 0x00000001u ] ]
    check false "fc320814" inputs outputs

  /// <summary>
  /// F6.1.87 VFMAT: vfmat.bf16 q0, q1, q2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.87 VFMAT``() =
    let inputs =
      [ [ D(0, 0x3e80c0403f403e80UL)
          D(1, 0xc010bf003d8040c0UL)
          D(2, 0x412042c944803e00UL)
          D(3, 0xbf804140c0604140UL)
          D(4, 0xbf803f404000bf00UL)
          D(5, 0xc24040e8c0d03d80UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xc0403f40c0104040UL)
          D(1, 0xc0403e003e00bf00UL)
          D(2, 0xc0d0402040203d80UL)
          D(3, 0x3d803e003d8040e8UL)
          D(4, 0x42c9c0604020c240UL)
          D(5, 0x3f4042c93fc0c0d0UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3fc0c0103f00ff80UL)
          D(1, 0x80003f007f803f00UL)
          D(2, 0x800040403f004040UL)
          D(3, 0xff807f803f000000UL)
          D(4, 0x3fc00000c0104040UL)
          D(5, 0x7f80c0103f000000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xc11bf9fe45000c04UL)
          D(1, 0x4236f41041b68041UL)
          Cell.FPSCR 0x00000010u ]
        [ D(0, 0xc424103f407fbfc0UL)
          D(1, 0xc03d3e003e60bf00UL)
          Cell.FPSCR 0x60000010u ]
        [ D(0, 0x3fc0c010bf1f0080UL)
          D(1, 0xff8000007fc00000UL)
          Cell.FPSCR 0x00000081u ] ]
    check false "fc320854" inputs outputs

  /// <summary>
  /// F6.1.89 VFMAL: vfmal.f16 d0, s2, s3. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.89 VFMAL``() =
    let inputs =
      [ [ D(0, 0x2c003a003f00bc00UL)
          D(1, 0x56484a00c2003a00UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xb600c0804a00c200UL)
          D(1, 0x3a00440056484740UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3e00fc0042003800UL)
          D(1, 0xfc0000003e008000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xc396c00041180bc0UL); Cell.FPSCR 0x00000010u ]
        [ D(0, 0x4296c0004a00c274UL); Cell.FPSCR 0x60000010u ]
        [ D(0, 0xff80000042003800UL); Cell.FPSCR 0x00000000u ] ]
    check false "fc210831" inputs outputs

  /// <summary>
  /// F6.1.92 VFMSL: vfmsl.f16 q0, d2, d3[1]. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.92 VFMSL``() =
    let inputs =
      [ [ D(0, 0x47406400c300d200UL)
          D(1, 0xc3003e0034004100UL)
          D(2, 0x2c00410046006400UL)
          D(3, 0xb8004a00c2004400UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x5648d2004100d200UL)
          D(1, 0x4600d200b800c680UL)
          D(2, 0x3a00c68056482c00UL)
          D(3, 0xc2003000c080d200UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x4200420038003800UL)
          D(1, 0x0000fc000000fc00UL)
          D(2, 0xc080fc003e008000UL)
          D(3, 0x3800c0803e00c080UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x474076004537f2e0UL)
          D(1, 0xc3000e0040f00000UL)
          Cell.FPSCR 0x00000010u ]
        [ D(0, 0x5648d20041031200UL)
          D(1, 0x4600d8c0c16a0020UL)
          Cell.FPSCR 0x60000010u ]
        [ D(0, 0x41ee840038003800UL)
          D(1, 0x405800007f800000UL)
          Cell.FPSCR 0x00000080u ] ]
    check false "fe12085b" inputs outputs

  /// <summary>
  /// F6.1.98 VINS: vins.f16 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.98 VINS``() =
    let inputs =
      [ [ D(0, 0xd2003a00bc00c680UL) ]
        [ D(0, 0xb800c0806400d200UL) ]
        [ D(0, 0xfc00c080fc008000UL) ] ]
    let outputs =
      [ [ D(0, 0xd2003a003a00c680UL) ]
        [ D(0, 0xb800c080c080d200UL) ]
        [ D(0, 0xfc00c080c0808000UL) ] ]
    check false "feb00ae0" inputs outputs

  /// <summary>
  /// F6.1.99 VJCVT: vjcvt.s32.f64 s0, d1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.99 VJCVT``() =
    let inputs =
      [ [ D(0, 0x4028000000000000UL)
          D(1, 0xc008000000000000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x3ff8000000000000UL)
          D(1, 0xbff0000000000000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x0000000000000000UL)
          D(1, 0xfff0000000000000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x40280000fffffffdUL); Cell.FPSCR 0x40000000u ]
        [ D(0, 0x3ff80000ffffffffUL); Cell.FPSCR 0x40000000u ]
        [ D(0, 0x0000000000000000UL); Cell.FPSCR 0x00000001u ] ]
    check false "eeb90bc1" inputs outputs

  /// <summary>
  /// F6.1.112 VLDMDB: vldmdb r1!, {d0-d1}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.112 VLDMDB``() =
    let inputs =
      [ [ Gpr(1, 0x20000828u)
          D(0, 0x2780e0bd8044664dUL)
          D(1, 0x8ca7a6b62a7c01ebUL)
          M(0, 0x45ebf4f3be85ecb7UL)
          M(8, 0xc060fc165b638c40UL)
          M(16, 0x0ee19469b936ca63UL)
          M(24, 0xbedd48a0a282ec8fUL)
          M(32, 0x4c4c704b09f830e6UL)
          M(40, 0x32655a75d9d444c8UL)
          M(48, 0x7aa09596654bbf72UL)
          M(56, 0xd0ba5b2e9c29a13bUL) ]
        [ Gpr(1, 0x20000828u)
          D(0, 0xe33d5766aff6fe63UL)
          D(1, 0x7f92834a7baade4bUL)
          M(0, 0x4a216e96b3ab1207UL)
          M(8, 0x22f7d5df91690663UL)
          M(16, 0xee92c4825621f97aUL)
          M(24, 0x1fdd3de8770e5e5fUL)
          M(32, 0xb1430aed643a9193UL)
          M(40, 0x24e5453b071996ecUL)
          M(48, 0xd8772e517431be16UL)
          M(56, 0x9ff44e9b5ffb09b4UL) ]
        [ Gpr(1, 0x20000828u)
          D(0, 0x0000000000000001UL)
          D(1, 0x0102030405060708UL)
          M(0, 0x11e9fa9cc5e0a99eUL)
          M(8, 0x10b07445280196d7UL)
          M(16, 0xf953a203c304a408UL)
          M(24, 0xe07588bd26c83012UL)
          M(32, 0x74b91fb568ec2b0dUL)
          M(40, 0xfa4c2ea51755137eUL)
          M(48, 0xe0f3f6baf421557dUL)
          M(56, 0xf0ac4335048da08fUL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000818u)
          D(0, 0xbedd48a0a282ec8fUL)
          D(1, 0x4c4c704b09f830e6UL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0x1fdd3de8770e5e5fUL)
          D(1, 0xb1430aed643a9193UL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0xe07588bd26c83012UL)
          D(1, 0x74b91fb568ec2b0dUL) ] ]
    check false "ed310b04" inputs outputs

  /// <summary>
  /// F6.1.112 VLDMIA: vldmia r1, {d0, d1}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.112 VLDMIA``() =
    let inputs =
      [ [ Gpr(1, 0x20000818u)
          D(0, 0x83bc6c9b190eb214UL)
          D(1, 0xe97484b45bebf069UL)
          M(0, 0x3d211825d75102fcUL)
          M(8, 0x343dd935186b4f68UL)
          M(16, 0xbc73709a9a16a801UL)
          M(24, 0xdb4436cb3b2123e8UL)
          M(32, 0xc498789f0fa4bdfcUL)
          M(40, 0x4da392d37b35befdUL)
          M(48, 0xe1b763bbdabb9bd5UL)
          M(56, 0xaaefe924a58386ffUL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0x6f1aef6dea093f37UL)
          D(1, 0xcaee11044270bdf3UL)
          M(0, 0x2805316dbfafabfbUL)
          M(8, 0x8a425ce994812938UL)
          M(16, 0x26ec7a5bb6b0ea1dUL)
          M(24, 0x18159b77ab924b67UL)
          M(32, 0xecd08420edc71f7dUL)
          M(40, 0xaf87ada7b4e6ab88UL)
          M(48, 0x2c738aa547eaf026UL)
          M(56, 0x6086cf98f417d6c7UL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0xffffffffffffffffUL)
          D(1, 0x0102030405060708UL)
          M(0, 0x055416a862f9201bUL)
          M(8, 0xa60fe3b358a7c151UL)
          M(16, 0x658df459229e42bfUL)
          M(24, 0x7c4f3b41cd6a06efUL)
          M(32, 0x0e7c34d8f43e788dUL)
          M(40, 0xb6201d84b2efed12UL)
          M(48, 0x8b8cd8cd44165d53UL)
          M(56, 0x57b5207be3e1d941UL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000818u)
          D(0, 0xdb4436cb3b2123e8UL)
          D(1, 0xc498789f0fa4bdfcUL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0x18159b77ab924b67UL)
          D(1, 0xecd08420edc71f7dUL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0x7c4f3b41cd6a06efUL)
          D(1, 0x0e7c34d8f43e788dUL) ] ]
    check false "ec910b04" inputs outputs

  /// <summary>
  /// F6.1.117 VMAXNM: vmaxnm.f32 s0, s1, s2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.117 VMAXNM``() =
    let inputs =
      [ [ D(0, 0x3e000000bf800000UL)
          D(1, 0x44800000c0400000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xc010000040400000UL)
          D(1, 0xc0d000003e800000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3fc000003fc00000UL)
          D(1, 0x0000000080000000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x3e0000003e000000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0xc01000003e800000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3fc000003fc00000UL); Cell.FPSCR 0x00000000u ] ]
    check false "fe800a81" inputs outputs

  /// <summary>
  /// F6.1.120 VMINNM: vminnm.f32 s0, s1, s2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.120 VMINNM``() =
    let inputs =
      [ [ D(0, 0xc010000041400000UL)
          D(1, 0x3d800000c0400000UL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x4480000044800000UL)
          D(1, 0xbec000003d800000UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3f000000c0100000UL)
          D(1, 0xc01000003fc00000UL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xc0100000c0400000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x448000003d800000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x3f0000003f000000UL); Cell.FPSCR 0x00000000u ] ]
    check false "fe800ac1" inputs outputs

  /// <summary>
  /// F6.1.131 VMMLA: vmmla.bf16 q0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.131 VMMLA``() =
    let inputs =
      [ [ D(0, 0x3d80c0d0c06040c0UL)
          D(1, 0xc0104020bf0040c0UL)
          D(2, 0xc0d0c0d03e00c010UL)
          D(3, 0x4040c010bec042c9UL)
          D(4, 0xbf80bec040e84120UL)
          D(5, 0xc060c04040e83fc0UL) ]
        [ D(0, 0xbf803fc040203fe0UL)
          D(1, 0xbf0040c0bf00bf00UL)
          D(2, 0xc240404040c03d80UL)
          D(3, 0x40204480c0103d80UL)
          D(4, 0xc0403fe03e804020UL)
          D(5, 0x41203fc03fc04020UL) ]
        [ D(0, 0xff8040407f807f80UL)
          D(1, 0x80003fc03fc0ff80UL)
          D(2, 0xff8000003fc03f00UL)
          D(3, 0xff80c0107f808000UL)
          D(4, 0x3f003fc00000ff80UL)
          D(5, 0x40403f003fc03f00UL) ] ]
    let outputs =
      [ [ D(0, 0x421f6061c1814818UL); D(1, 0x430e06ff4479e7efUL) ]
        [ D(0, 0xc3e9ac3f431968ffUL); D(1, 0x44c2a8f744def2e9UL) ]
        [ D(0, 0x7fc000007fc00000UL); D(1, 0x7fc000007fc00000UL) ] ]
    check false "fc020c44" inputs outputs

  /// <summary>
  /// F6.1.143 VMOVX: vmovx.f16 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.143 VMOVX``() =
    let inputs =
      [ [ D(0, 0xb8003e00c200d200UL) ]
        [ D(0, 0xb600340042004900UL) ]
        [ D(0, 0x8000c0804200c080UL) ] ]
    let outputs =
      [ [ D(0, 0xb8003e000000b800UL) ]
        [ D(0, 0xb60034000000b600UL) ]
        [ D(0, 0x8000c08000008000UL) ] ]
    check false "feb00a60" inputs outputs

  /// <summary>
  /// F6.1.179 VQRDMLAH: vqrdmlah.s16 d0, d1, d2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.179 VQRDMLAH``() =
    let inputs =
      [ [ D(0, 0x50f799b1b81fe00dUL)
          D(1, 0x5fb1b16843acebfcUL)
          D(2, 0x7a8374fc5e04963cUL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0x6dc514eacb5475b7UL)
          D(1, 0x4351107805653974UL)
          D(2, 0x706fb28f54e2201bUL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0xffffffffffffffffUL)
          D(1, 0x8000000000000000UL)
          D(2, 0x7fffffffffffffffUL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x7fff8000e9d3f097UL); Cell.FPSCR 0x08000000u ]
        [ D(0, 0x7fff0af3cee87fffUL); Cell.FPSCR 0x68000000u ]
        [ D(0, 0x8000ffffffffffffUL); Cell.FPSCR 0x00000000u ] ]
    check false "f3110b12" inputs outputs

  /// <summary>
  /// F6.1.180 VQRDMLSH: vqrdmlsh.s32 q0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.180 VQRDMLSH``() =
    let inputs =
      [ [ D(0, 0x7012a9bd0701855eUL)
          D(1, 0xdf70e97c7b4b1eb0UL)
          D(2, 0x3ed9b2a494c1c0e6UL)
          D(3, 0x9609e4a2cb306429UL)
          D(4, 0x183bc4c7bf28c51fUL)
          D(5, 0x6920a02b6db1307dUL)
          Cell.FPSCR 0x00000000u ]
        [ D(0, 0xc21a0cf10e60d174UL)
          D(1, 0x08f603c74d3ddedcUL)
          D(2, 0x69ca6c67b7da2282UL)
          D(3, 0x73165db5c67d1a93UL)
          D(4, 0x38df555544e46549UL)
          D(5, 0x9b73fbe4d72ad0b7UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7fffffffffffffffUL)
          D(1, 0x7fffffffffffffffUL)
          D(2, 0x7fffffffffffffffUL)
          D(3, 0x0000000000000001UL)
          D(4, 0x00ff00ff00ff00ffUL)
          D(5, 0xffffffffffffffffUL)
          Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x642c7f47d0ae11eeUL)
          D(1, 0x3677ce0d7fffffffUL)
          Cell.FPSCR 0x08000000u ]
        [ D(0, 0x9318e8543535aba8UL)
          D(1, 0x635d61253ae52e19UL)
          Cell.FPSCR 0x60000000u ]
        [ D(0, 0x7f00ff00ffffffffUL)
          D(1, 0x7fffffffffffffffUL)
          Cell.FPSCR 0x00000000u ] ]
    check false "f3220c54" inputs outputs

  /// <summary>
  /// F6.1.199 VRINTA: vrinta.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.199 VRINTA``() =
    let inputs =
      [ [ D(0, 0x42c9000041200000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x40c000003d800000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x000000007f800000UL); Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x42c9000042ca0000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x40c0000040c00000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x0000000000000000UL); Cell.FPSCR 0x00000000u ] ]
    check false "feb80a60" inputs outputs

  /// <summary>
  /// F6.1.201 VRINTM: vrintm.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.201 VRINTM``() =
    let inputs =
      [ [ D(0, 0x41400000c2400000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x4020000040800000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0xff800000ff800000UL); Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x4140000041400000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x4020000040000000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0xff800000ff800000UL); Cell.FPSCR 0x00000000u ] ]
    check false "febb0a60" inputs outputs

  /// <summary>
  /// F6.1.203 VRINTN: vrintn.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.203 VRINTN``() =
    let inputs =
      [ [ D(0, 0x40800000bec00000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x3fc00000c0d00000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x4040000040400000UL); Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x4080000040800000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x3fc0000040000000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x4040000040400000UL); Cell.FPSCR 0x00000000u ] ]
    check false "feb90a60" inputs outputs

  /// <summary>
  /// F6.1.205 VRINTP: vrintp.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.205 VRINTP``() =
    let inputs =
      [ [ D(0, 0x42c90000c0400000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x4080000040c00000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x000000003f000000UL); Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x42c9000042ca0000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x4080000040800000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x0000000000000000UL); Cell.FPSCR 0x00000000u ] ]
    check false "feba0a60" inputs outputs

  /// <summary>
  /// F6.1.207 VRINTR: vrintr.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.207 VRINTR``() =
    let inputs =
      [ [ D(0, 0xc04000003f400000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x4140000041200000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x4040000000000000UL); Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xc0400000c0400000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x4140000041400000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x4040000040400000UL); Cell.FPSCR 0x00000000u ] ]
    check false "eeb60a60" inputs outputs

  /// <summary>
  /// F6.1.208 VRINTX: vrintx.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.208 VRINTX``() =
    let inputs =
      [ [ D(0, 0x3e80000044800000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x3d8000003fe00000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x404000003f000000UL); Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0x3e80000000000000UL); Cell.FPSCR 0x00000010u ]
        [ D(0, 0x3d80000000000000UL); Cell.FPSCR 0x60000010u ]
        [ D(0, 0x4040000040400000UL); Cell.FPSCR 0x00000000u ] ]
    check false "eeb70a60" inputs outputs

  /// <summary>
  /// F6.1.210 VRINTZ: vrintz.f32 s0, s1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.210 VRINTZ``() =
    let inputs =
      [ [ D(0, 0xbec0000040e80000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x40e8000040e80000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x80000000ff800000UL); Cell.FPSCR 0x00000000u ] ]
    let outputs =
      [ [ D(0, 0xbec0000080000000UL); Cell.FPSCR 0x00000000u ]
        [ D(0, 0x40e8000040e00000UL); Cell.FPSCR 0x60000000u ]
        [ D(0, 0x8000000080000000UL); Cell.FPSCR 0x00000000u ] ]
    check false "eeb60ae0" inputs outputs

  /// <summary>
  /// F6.1.221 VSDOT: vsdot.s8 d0, d1, d2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.221 VSDOT``() =
    let inputs =
      [ [ D(0, 0x0c619891e00d53bcUL)
          D(1, 0xb8973d27234cc900UL)
          D(2, 0x9442102ac516a58bUL) ]
        [ D(0, 0xd9f0f00225b7a387UL)
          D(1, 0x45774dc44a542ef6UL)
          D(2, 0x5d680b55f06f0698UL) ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0x0000000000000001UL)
          D(2, 0x0000000000000001UL) ] ]
    let outputs =
      [ [ D(0, 0x0c61a615e00d65c0UL) ]
        [ D(0, 0xd9f128ce25b7c877UL) ]
        [ D(0, 0x8000000000000001UL) ] ]
    check false "fc210d02" inputs outputs

  /// <summary>
  /// F6.1.223 VSELEQ: vseleq.f32 s0, s1, s2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.223 VSELEQ``() =
    let inputs =
      [ [ D(0, 0x4480000042c90000UL)
          D(1, 0xc240000040e80000UL)
          Cell.CPSR 0x20000010u ]
        [ D(0, 0x3e8000003fe00000UL)
          D(1, 0x400000003f400000UL)
          Cell.CPSR 0x900a0010u ]
        [ D(0, 0xff8000003fc00000UL)
          D(1, 0x40400000c0100000UL)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ D(0, 0x4480000040e80000UL) ]
        [ D(0, 0x3e8000003f400000UL) ]
        [ D(0, 0xff800000ff800000UL) ] ]
    check false "fe000a81" inputs outputs

  /// <summary>
  /// F6.1.223 VSELGE: vselge.f64 d0, d1, d2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.223 VSELGE``() =
    let inputs =
      [ [ D(0, 0x4090000000000000UL)
          D(1, 0x4010000000000000UL)
          D(2, 0xc048000000000000UL)
          Cell.CPSR 0x20000010u ]
        [ D(0, 0xbfd8000000000000UL)
          D(1, 0x4000000000000000UL)
          D(2, 0x3fd0000000000000UL)
          Cell.CPSR 0x900a0010u ]
        [ D(0, 0x0000000000000000UL)
          D(1, 0xfff0000000000000UL)
          D(2, 0x3fe0000000000000UL)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ D(0, 0x4010000000000000UL) ]
        [ D(0, 0x4000000000000000UL) ]
        [ D(0, 0xfff0000000000000UL) ] ]
    check false "fe210b02" inputs outputs

  /// <summary>
  /// F6.1.223 VSELGT: vselgt.f32 s0, s1, s2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.223 VSELGT``() =
    let inputs =
      [ [ D(0, 0x3fc0000041400000UL)
          D(1, 0xbec00000c0d00000UL)
          Cell.CPSR 0x20000010u ]
        [ D(0, 0x414000003fc00000UL)
          D(1, 0x3d80000044800000UL)
          Cell.CPSR 0x900a0010u ]
        [ D(0, 0x4040000040400000UL)
          D(1, 0x7f800000ff800000UL)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ D(0, 0x3fc000003fc00000UL) ]
        [ D(0, 0x4140000041400000UL) ]
        [ D(0, 0x40400000ff800000UL) ] ]
    check false "fe300a81" inputs outputs

  /// <summary>
  /// F6.1.223 VSELVS: vselvs.f64 d0, d1, d2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.223 VSELVS``() =
    let inputs =
      [ [ D(0, 0x3fe8000000000000UL)
          D(1, 0xc008000000000000UL)
          D(2, 0xc048000000000000UL)
          Cell.CPSR 0x20000010u ]
        [ D(0, 0x4004000000000000UL)
          D(1, 0x4024000000000000UL)
          D(2, 0x3fd0000000000000UL)
          Cell.CPSR 0x900a0010u ]
        [ D(0, 0x0000000000000000UL)
          D(1, 0xc002000000000000UL)
          D(2, 0x4008000000000000UL)
          Cell.CPSR 0x48050010u ] ]
    let outputs =
      [ [ D(0, 0xc048000000000000UL) ]
        [ D(0, 0x4024000000000000UL) ]
        [ D(0, 0x4008000000000000UL) ] ]
    check false "fe110b02" inputs outputs

  /// <summary>
  /// F6.1.232 VSMMLA: vsmmla.s8 q0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.232 VSMMLA``() =
    let inputs =
      [ [ D(0, 0x08399930871cbc07UL)
          D(1, 0x4f36615dfa865b68UL)
          D(2, 0xbfa70c43df244d8fUL)
          D(3, 0x84460a27ca3f86b2UL)
          D(4, 0x773a4b94405be9e1UL)
          D(5, 0xd19018754fb0d73bUL) ]
        [ D(0, 0xec6c7b66f75a19f4UL)
          D(1, 0x61c51785cc970faaUL)
          D(2, 0x441d47efe3850154UL)
          D(3, 0x54f12d44b88b0f99UL)
          D(4, 0x48ae8a03b49716d4UL)
          D(5, 0xef683d0f01dc35e5UL) ]
        [ D(0, 0x0102030405060708UL)
          D(1, 0x0102030405060708UL)
          D(2, 0x00ff00ff00ff00ffUL)
          D(3, 0x7fffffffffffffffUL)
          D(4, 0x7f80ff00807fffffUL)
          D(5, 0x7f80ff00807fffffUL) ] ]
    let outputs =
      [ [ D(0, 0x0839afff871c7c36UL); D(1, 0x4f36497afa864167UL) ]
        [ D(0, 0xec6c9b1ef75a2f92UL); D(1, 0x61c538b2cc977081UL) ]
        [ D(0, 0x010203060506070aUL); D(1, 0x010242890506468dUL) ] ]
    check false "fc220c44" inputs outputs

  /// <summary>
  /// F6.1.244 VSTMDB: vstmdb r1!, {d0-d1}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.244 VSTMDB``() =
    let inputs =
      [ [ Gpr(1, 0x20000828u)
          D(0, 0x26e8748cb0889d8fUL)
          D(1, 0x945775ec06ac32a1UL)
          M(0, 0xe0e84594267c6e69UL)
          M(8, 0x706b77a67a00b853UL)
          M(16, 0x6836529ae674b9dfUL)
          M(24, 0x1e54c23af339a164UL)
          M(32, 0xed0a778b0b67c408UL)
          M(40, 0x25510bb00cdf7d54UL)
          M(48, 0xf949fc310988e293UL)
          M(56, 0x2a9894cc9f514790UL) ]
        [ Gpr(1, 0x20000828u)
          D(0, 0x8f6626099b06519bUL)
          D(1, 0x5ee04464810c34f0UL)
          M(0, 0x432793250d5e3b56UL)
          M(8, 0x91ac432fa435c69dUL)
          M(16, 0x457b537d8bb87a25UL)
          M(24, 0x64eafb033ca03dc0UL)
          M(32, 0x829b823f4cf0b740UL)
          M(40, 0xd5ee5cb7dd418228UL)
          M(48, 0xaddce65c0bf22febUL)
          M(56, 0x2b0c694e7eea1944UL) ]
        [ Gpr(1, 0x20000828u)
          D(0, 0x7f80ff00807fffffUL)
          D(1, 0x8000000000000000UL)
          M(0, 0x86bf248cb41ca10bUL)
          M(8, 0xfca38d81ec8e0f71UL)
          M(16, 0xa71e55045384cd5eUL)
          M(24, 0x246572c05c8462beUL)
          M(32, 0x6d6fc2b77e7b9beaUL)
          M(40, 0x17b65421800526c2UL)
          M(48, 0xa7ea9c3041cd5b85UL)
          M(56, 0x9b41d474edd7c35eUL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000818u)
          M(24, 0x26e8748cb0889d8fUL)
          M(32, 0x945775ec06ac32a1UL) ]
        [ Gpr(1, 0x20000818u)
          M(24, 0x8f6626099b06519bUL)
          M(32, 0x5ee04464810c34f0UL) ]
        [ Gpr(1, 0x20000818u)
          M(24, 0x7f80ff00807fffffUL)
          M(32, 0x8000000000000000UL) ] ]
    check false "ed210b04" inputs outputs

  /// <summary>
  /// F6.1.244 VSTMIA: vstmia r1, {s0, s1, s2, s3}. The outputs are what QEMU
  /// left after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.244 VSTMIA``() =
    let inputs =
      [ [ Gpr(1, 0x20000818u)
          D(0, 0x468a458beb0aaef3UL)
          D(1, 0x4ebfa1a84e07ac00UL)
          M(0, 0x8dcece674f57e441UL)
          M(8, 0x0dd9029501f981ddUL)
          M(16, 0xee5ee7e3b6dd1ac4UL)
          M(24, 0xcabcf9ee3bc888c6UL)
          M(32, 0x8838ca20293ed542UL)
          M(40, 0x92cde554d05a8016UL)
          M(48, 0xc277b3a305b559bbUL)
          M(56, 0xdbcacc1f71186025UL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0x32c54e39b0634b39UL)
          D(1, 0x387cf220b608a297UL)
          M(0, 0x870d9c1e783f3318UL)
          M(8, 0xe5f6e72ec4ce3cb0UL)
          M(16, 0x234c0a9114c6c8d7UL)
          M(24, 0x78280141ccf82a63UL)
          M(32, 0x5d4d2344897a2902UL)
          M(40, 0xae6656b7b482e035UL)
          M(48, 0x63a1367a2a109ce9UL)
          M(56, 0xf13f5a60960524d3UL) ]
        [ Gpr(1, 0x20000818u)
          D(0, 0x7f80ff00807fffffUL)
          D(1, 0x8000000000000000UL)
          M(0, 0x58869a2eee607bb7UL)
          M(8, 0xcff7354011277acdUL)
          M(16, 0x03a43e4cb9971e4aUL)
          M(24, 0x4be748f7e16b8145UL)
          M(32, 0x25f4d7db109ce623UL)
          M(40, 0xa345518439f4cea6UL)
          M(48, 0x02fcb34e0bf5a313UL)
          M(56, 0xeb242b565cf13000UL) ] ]
    let outputs =
      [ [ Gpr(1, 0x20000818u)
          M(24, 0x468a458beb0aaef3UL)
          M(32, 0x4ebfa1a84e07ac00UL) ]
        [ Gpr(1, 0x20000818u)
          M(24, 0x32c54e39b0634b39UL)
          M(32, 0x387cf220b608a297UL) ]
        [ Gpr(1, 0x20000818u)
          M(24, 0x7f80ff00807fffffUL)
          M(32, 0x8000000000000000UL) ] ]
    check false "ec810a04" inputs outputs

  /// <summary>
  /// F6.1.251 VSUDOT: vsudot.u8 d0, d1, d2[0]. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.251 VSUDOT``() =
    let inputs =
      [ [ D(0, 0xd5ac8e0692ef7939UL)
          D(1, 0x4708a54034aa2e74UL)
          D(2, 0x1c3130f010c02f4eUL) ]
        [ D(0, 0xa019bc888a601079UL)
          D(1, 0x105fd11bdf2b0861UL)
          D(2, 0xa6ac426bf2f3e89eUL) ]
        [ D(0, 0x8001800180018001UL)
          D(1, 0x8001800180018001UL)
          D(2, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0xd5ac9b4192ef67c3UL) ]
        [ D(0, 0xa01a0be78a605d36UL) ]
        [ D(0, 0x8001000380010003UL) ] ]
    check false "fe810d12" inputs outputs

  /// <summary>
  /// F6.1.256 VUDOT: vudot.u8 q0, q1, d4[1]. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.256 VUDOT``() =
    let inputs =
      [ [ D(0, 0xe10ec4b37cf8ddbcUL)
          D(1, 0x8440e59538196048UL)
          D(2, 0xcebe06c36bdc9f04UL)
          D(3, 0xf841311a4113b45bUL)
          D(4, 0x7433791bb15f69e7UL) ]
        [ D(0, 0xb56cdb80d6ee8c63UL)
          D(1, 0x4586b77ad6247258UL)
          D(2, 0xf0b82758a8fa83f6UL)
          D(3, 0x92d4835e52ca5940UL)
          D(4, 0xd98b9e130a615352UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x8001800180018001UL)
          D(3, 0x0102030405060708UL)
          D(4, 0x0000000000000001UL) ] ]
    let outputs =
      [ [ D(0, 0xe10f5f4c7cf9859fUL); D(1, 0x84417ccf3819e032UL) ]
        [ D(0, 0xb56e2972d6f005a5UL); D(1, 0x4587fe2cd6256136UL) ]
        [ D(0, 0x7f80ff00807fffffUL); D(1, 0xffffffffffffffffUL) ] ]
    check false "fe220d74" inputs outputs

  /// <summary>
  /// F6.1.258 VUMMLA: vummla.u8 q0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.258 VUMMLA``() =
    let inputs =
      [ [ D(0, 0x6aec4215af3c3d3eUL)
          D(1, 0x3b6491ddd14b07e8UL)
          D(2, 0xefcb79960b6cb6deUL)
          D(3, 0x2e54bb29aba08b60UL)
          D(4, 0xa567d3c4e67df49eUL)
          D(5, 0x9594e4f3d90bc9cbUL) ]
        [ D(0, 0xfe08260c54758a58UL)
          D(1, 0x34e3768cc262cd24UL)
          D(2, 0x9bb5a5f274e8fe7dUL)
          D(3, 0x67a468c6124e5127UL)
          D(4, 0x9c317c2cbd6f7b30UL)
          D(5, 0x3c3360f5264d1400UL) ]
        [ D(0, 0x8000000000000000UL)
          D(1, 0x8001800180018001UL)
          D(2, 0x8000000000000000UL)
          D(3, 0x00ff00ff00ff00ffUL)
          D(4, 0x8000000000000000UL)
          D(5, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0x6aef8999af3f74a3UL); D(1, 0x3b66fbc0d14da85dUL) ]
        [ D(0, 0xfe09fec15477d0abUL); D(1, 0x34e4b450c263dd0bUL) ]
        [ D(0, 0x80003f8000004000UL); D(1, 0x8005780580018001UL) ] ]
    check false "fc220c54" inputs outputs

  /// <summary>
  /// F6.1.259 VUSDOT: vusdot.s8 d0, d1, d2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.259 VUSDOT``() =
    let inputs =
      [ [ D(0, 0xfbdc73102f5858d8UL)
          D(1, 0xb588656eb1d3c0a8UL)
          D(2, 0x12ef1e1e4f1e496dUL) ]
        [ D(0, 0xc59c049b80bba252UL)
          D(1, 0x2a29edf0e5c31cabUL)
          D(2, 0xf1b7e945586b1f82UL) ]
        [ D(0, 0x7f80ff00807fffffUL)
          D(1, 0x8001800180018001UL)
          D(2, 0x7fffffffffffffffUL) ] ]
    let outputs =
      [ [ D(0, 0xfbdc8f7c2f592679UL) ]
        [ D(0, 0xc59c21d980bbf1c5UL) ]
        [ D(0, 0x7f813dfe807ffefdUL) ] ]
    check false "fca10d02" inputs outputs

  /// <summary>
  /// F6.1.261 VUSMMLA: vusmmla.s8 q0, q1, q2. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``F6.1.261 VUSMMLA``() =
    let inputs =
      [ [ D(0, 0x0a81120d5fce0f03UL)
          D(1, 0x27fc0e1f6d217189UL)
          D(2, 0x6d9b7f6ca7c16af0UL)
          D(3, 0x77c2f12dfdf1f1fcUL)
          D(4, 0x239836063980421fUL)
          D(5, 0xb931960bdf79f78aUL) ]
        [ D(0, 0xe6a33643cc201b27UL)
          D(1, 0x67202d3fe5fe3a33UL)
          D(2, 0x669b3a9a1158309cUL)
          D(3, 0xf1c2418981dc04dbUL)
          D(4, 0xe41de9f5e52ae9ccUL)
          D(5, 0x834873f83652442aUL) ]
        [ D(0, 0x7fffffffffffffffUL)
          D(1, 0xffffffffffffffffUL)
          D(2, 0x8000000000000000UL)
          D(3, 0x8001800180018001UL)
          D(4, 0x8001800180018001UL)
          D(5, 0x8001800180018001UL) ] ]
    let outputs =
      [ [ D(0, 0x0a80b4e35fcdf957UL); D(1, 0x27fb85106d21835dUL) ]
        [ D(0, 0xe6a38b69cc1ffe5fUL); D(1, 0x67208db9e5fe13bcUL) ]
        [ D(0, 0x7fffbfffffffbfffUL); D(1, 0xffff0003ffff0003UL) ] ]
    check false "fca20c44" inputs outputs
