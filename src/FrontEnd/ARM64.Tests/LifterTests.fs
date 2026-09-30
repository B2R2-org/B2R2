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

namespace B2R2.FrontEnd.ARM64.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.ARM64
open B2R2.BinIR.LowUIR.AST.InfixOp
open type Register

[<TestClass>]
type LifterTests() =
  let num (v: uint32) = BitVector(v, 32<rt>) |> AST.num

  let num64 (v: uint64) = BitVector(v, 64<rt>) |> AST.num

  let unwrapStmts stmts = Array.sub stmts 1 (Array.length stmts - 2)

  let isa = ISA(Architecture.ARMv8, Endian.Big)

  let reader = BinReader.Init Endian.Big

  let regFactory = RegisterFactory isa :> IRegisterFactory

  let ( !. ) name = Register.toRegID name |> regFactory.GetRegVar

  let ( ++ ) (byteStr: string) (givenStmts: Stmt[]) =
    ByteArray.ofHexString byteStr, givenStmts

  let unsupported = AST.sideEffect BinIR.SideEffect.UnsupportedInstruction

  /// The statements one encoding lifts to, for a test whose claim is that
  /// the encoding lifts at all rather than what it lifts to.
  let lifted (hex: string) =
    let parser = ARM64Parser reader :> IInstructionParsable
    let builder = ILowUIRBuilder.Default(isa, regFactory, LowUIRStream())
    let ins = parser.Parse(ByteArray.ofHexString hex, 0UL)
    ins.Translate builder

  let test (bytes: byte[], givenStmts) =
    let parser = ARM64Parser reader :> IInstructionParsable
    let builder = ILowUIRBuilder.Default(isa, regFactory, LowUIRStream())
    let ins = parser.Parse(bytes, 0UL)
    CollectionAssert.AreEqual(givenStmts, unwrapStmts <| ins.Translate builder)

  /// The statements one encoding lifts to, as the text they print as.
  let liftedText (hex: string) =
    lifted hex |> Array.map string |> String.concat "\n"

  /// How a failed authentication writes its error code over bits 62:61, as
  /// the lifted text spells it.
  let poison (code: uint64) =
    $"& 0x9fffffffffffffff:I64) | 0x{code:x16}:I64"

  /// Whether a statement jumps to the given expression.
  let jumpsTo target (stmt: Stmt) =
    match stmt with
    | InterJmp(t, _) -> t = target
    | _ -> false

  (* NGC, NGCS and a BFC with a non-zero lsb all reached the raising
     fall-through in `translate`, so a block containing one did not lift at
     all. The claim these pin is exactly that -- each encoding produces
     statements instead of NotImplementedIRException. *)
  [<TestMethod>]
  member _.``[AArch64] NGC lifts``() =
    Assert.AreEqual<bool>(true, (lifted "da0103e0").Length > 0, "NGC")

  [<TestMethod>]
  member _.``[AArch64] NGCS lifts``() =
    Assert.AreEqual<bool>(true, (lifted "fa0103e0").Length > 0, "NGCS")

  [<TestMethod>]
  member _.``[AArch64] BFC with a non-zero lsb lifts``() =
    Assert.AreEqual<bool>(true, (lifted "b3781fe0").Length > 0, "BFC")

  /// BLR X30 goes where X30 pointed, not to the instruction after it: the
  /// target is taken before the link register is written, so the jump is to
  /// that copy and never to X30 itself.
  [<TestMethod>]
  member _.``[AArch64] BLR X30 branches to the old X30``() =
    let jumps = lifted "d63f03c0" |> Array.exists (jumpsTo !.X30)
    Assert.AreEqual<bool>(false, jumps)

  [<TestMethod>]
  member _.``[AArch64] ADD (immedate) lift test``() =
    "114dc4ba"
    ++ [| !.X26 := AST.zext 64<rt>
           ((AST.xtlo 32<rt> !.X5 .+ num 0x371000u .+ num 0x0u)) |]
    |> test

  [<TestMethod>]
  member _.``[AArch64] ADD (extended register) lift test``() =
    "0b3f43ff"
    ++ [| !.SP := AST.zext 64<rt>
           (AST.xtlo 32<rt> !.SP .+ AST.xtlo 32<rt> !.XZR .+ num 0x0u) |]
    |> test

  [<TestMethod>]
  member _.``[AArch64] ADD (shifted register) lift test``() =
    "0b8e5f9b"
    ++ [| !.X27 := AST.zext 64<rt>
           (AST.xtlo 32<rt> !.X28 .+ (AST.xtlo 32<rt> !.X14 ?>> num 0x17u)
             .+ num 0x0u) |]
    |> test

  [<TestMethod>]
  member _.``[AArch64] ADD (extended register, UXTX) lift test``() =
    "8b336280"
    ++ [| !.X0 := !.X20 .+ (!.X19 << num64 0x0UL) .+ num64 0x0UL |]
    |> test

  /// DC ZVA clears the block DCZID_EL0 names, so the register has to be one
  /// this front end models, with a value from reset on.
  [<TestMethod>]
  member _.``[AArch64] DCZID_EL0 is a modelled system register``() =
    Assert.AreEqual<bool>(true, List.contains DCZIDEL0 SysReg.modelled)

  /// What it holds is what the processor holds: a Cortex-A57 clears sixteen
  /// words, which DCZID_EL0.BS spells as four.
  [<TestMethod>]
  member _.``[AArch64] DCZID_EL0 holds a Cortex-A57's block size``() =
    Assert.AreEqual<uint64>(0x4UL, SysReg.resetValue DCZIDEL0)

  /// DAIFSet and DAIFClr set and clear the masks their immediate names, at the
  /// bits DAIF keeps them in, and leave the other masks as they were.
  [<TestMethod>]
  member _.``[AArch64] MSR DAIFSet ORs its masks into DAIF``() =
    "d50345df"
    ++ [| !.DAIF := !.DAIF .| num64 0x140UL |]
    |> test

  [<TestMethod>]
  member _.``[AArch64] MSR DAIFClr clears its masks from DAIF``() =
    "d50343ff"
    ++ [| !.DAIF := !.DAIF .& num64 0xffffffffffffff3fUL |]
    |> test

  /// Every other field takes the low bit of the immediate and nothing else.
  [<TestMethod>]
  member _.``[AArch64] MSR PAN takes the low bit of its immediate``() =
    "d5004f9f"
    ++ [| !.PAN := num64 0x400000UL |]
    |> test

  /// A register that is a window onto PSTATE keeps only its field's bits.
  [<TestMethod>]
  member _.``[AArch64] MSR DAIF keeps only the mask bits``() =
    "d51b4220"
    ++ [| !.DAIF := !.X0 .& num64 0x3c0UL |]
    |> test

  /// What a system register with no name holds is the processor's own, so a
  /// read or a write of one is left to the emulator to report rather than
  /// given a value nothing stands behind.
  [<TestMethod>]
  member _.``[AArch64] MRS of an unnamed system register is unsupported``() =
    "d538f200" ++ [| unsupported |] |> test

  [<TestMethod>]
  member _.``[AArch64] MSR to an unnamed system register is unsupported``() =
    "d51ff001" ++ [| unsupported |] |> test

  /// A failed authentication puts key_number:NOT(key_number) in bits 62:61 in
  /// place of what was there (Auth(), J1-7662): 01 under an A key, 10 under a
  /// B key. Setting one bit on top of the address would leave an address in
  /// the upper half, whose top bits are all ones, exactly as it was.
  [<TestMethod>]
  member _.``[AArch64] A failed AUTIA leaves 01 in bits 62:61``() =
    StringAssert.Contains(liftedText "dac11020", poison 0x2000000000000000UL)

  [<TestMethod>]
  member _.``[AArch64] A failed AUTIB leaves 10 in bits 62:61``() =
    StringAssert.Contains(liftedText "dac11420", poison 0x4000000000000000UL)

  [<TestMethod>]
  member _.``[AArch64] A failed AUTDA leaves 01 in bits 62:61``() =
    StringAssert.Contains(liftedText "dac11820", poison 0x2000000000000000UL)

  [<TestMethod>]
  member _.``[AArch64] A failed AUTDB leaves 10 in bits 62:61``() =
    StringAssert.Contains(liftedText "dac11c20", poison 0x4000000000000000UL)

  /// A hint changes nothing a program can see: with one thread and nothing
  /// to wait for, each of these lifts to no statement at all.
  [<TestMethod>]
  member _.``[AArch64] YIELD lifts to nothing``() =
    "d503203f" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] WFE lifts to nothing``() =
    "d503205f" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] WFI lifts to nothing``() =
    "d503207f" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] SEV lifts to nothing``() =
    "d503209f" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] SEVL lifts to nothing``() =
    "d50320bf" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] BTI lifts to nothing``() =
    "d503241f" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] ESB lifts to nothing``() =
    "d503221f" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] PSB CSYNC lifts to nothing``() =
    "d503223f" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] TSB CSYNC lifts to nothing``() =
    "d503225f" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] CSDB lifts to nothing``() =
    "d503229f" ++ [||] |> test
