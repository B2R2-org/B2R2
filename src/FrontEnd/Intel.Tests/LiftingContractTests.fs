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

namespace B2R2.FrontEnd.Intel.Tests

open System
open System.IO
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Intel

/// <summary>
/// Checks that every row of the generated decode tables declares the number of
/// operands its lifter reads.
///
/// The two are written apart: the tables come out of the SDM, and the lifters
/// are hand-written against it. Nothing made them agree. PBLENDVB is the case
/// that prompted this - the manual writes its third operand as "&lt;XMM0&gt;",
/// the extractor dropped it, and SSELifter.pblendvb went on calling
/// getThreeOprs, so the instruction parsed and then raised the moment anything
/// tried to lift it. No parser test could see that, and no lifter test covered
/// the instruction.
///
/// Rather than synthesize an encoding for every row, this builds an
/// instruction carrying as many operands as the row declares and lifts it: the
/// getNOprs helpers match on arity alone, so a disagreement raises
/// InvalidOperandException and names itself. Every other failure means the
/// lifter is unwritten or wants operands of a particular shape, which is a
/// different question and is left alone.
/// </summary>
[<TestClass>]
type LiftingContractTests() =
  /// Every row of every generated table, flattened.
  static let allEntries =
    [| InstructionArrays.norOne
       InstructionArrays.norTwo
       InstructionArrays.norThree38
       InstructionArrays.norThree3A
       InstructionArrays.vexTwo
       InstructionArrays.vexThree38
       InstructionArrays.vexThree3A
       InstructionArrays.evexTwo
       InstructionArrays.evexThree38
       InstructionArrays.evexThree3A
       InstructionArrays.evexMap5
       InstructionArrays.evexMap6 |]
    |> Array.collect Array.concat

  /// The operand descriptors a row declares. A lone NoOpr means none at all.
  static let declaredOperands (core: InstructionCore) =
    match core.Operands with
    | [| NoOpr |] -> [||]
    | operands -> operands

  /// A register of the width the descriptor asks for. Which register does not
  /// matter; the class does, because a lifter reaching for a vector register
  /// where a general-purpose one arrived is a disagreement worth reporting.
  static let registerOfWidth = function
    | 8<rt> -> Register.AL
    | 16<rt> -> Register.AX
    | 32<rt> -> Register.EAX
    | 128<rt> -> Register.XMM0
    | 256<rt> -> Register.YMM0
    | 512<rt> -> Register.ZMM0
    | _ -> Register.RAX

  /// One operand of the kind a descriptor declares. Values are arbitrary -
  /// only the shape reaches the lifter's own pattern matches, which is what
  /// this test is asking about. A memory operand with no declared width takes
  /// the operation size, as the parser gives it.
  static let placeholderFor operationSize = function
    | Mem 0<rt> -> OprMem(Some Register.RAX, None, None, operationSize)
    | RM sz | RegSae sz | RMdiff(sz, _) | RMEr(sz, _) | RMSae(sz, _)
    | RMBcst(sz, _, _) | RMBcstEr(sz, _, _) | RMBcstSae(sz, _, _)
    | Reg(sz, _) -> OprReg(registerOfWidth sz)
    | Mem sz | MemVSIB sz | Moffs sz ->
      OprMem(Some Register.RAX, None, None, sz)
    | Imm sz -> OprImm(0L, sz)
    | FixedImm v -> OprImm(int64 v, 8<rt>)
    | FixedReg r -> OprReg r
    | Rel _ -> OprDirAddr(Relative 0L)
    | Far sz -> OprDirAddr(Absolute(0s, 0UL, sz))
    | OpMaskReg _ | KM _ -> OprReg Register.K1
    | MM _ | MMXReg _ -> OprReg Register.MM0
    | BM _ | BndReg -> OprReg Register.BND0
    | Sreg -> OprReg Register.DS
    | CtrlReg -> OprReg Register.CR0
    | DebugReg -> OprReg Register.DR0
    | STReg _ -> OprReg Register.ST0
    | RegAddr -> OprReg Register.RAX
    | NoOpr | Unknown _ -> OprReg Register.RAX

  /// The operation sizes to try. Several lifters branch on it and raise on
  /// anything they do not expect, so guessing one would report shapes that
  /// lift perfectly well at another. The question here is whether a shape can
  /// be lifted at all, so every plausible width gets a turn.
  static let operationSizes =
    [ 8<rt>; 16<rt>; 32<rt>; 64<rt>; 128<rt>; 256<rt>; 512<rt> ]

  static let operandsOf operationSize (descriptors: OperandType[]) =
    match descriptors |> Array.map (placeholderFor operationSize) with
    | [||] -> NoOperand
    | [| a |] -> OneOperand a
    | [| a; b |] -> TwoOperands(a, b)
    | [| a; b; c |] -> ThreeOperands(a, b, c)
    | operands -> FourOperands(operands[0], operands[1], operands[2],
                               operands[3])

  static let isa = ISA(Architecture.Intel, WordSize.Bit64)

  static let builder () =
    ILowUIRBuilder.Default(isa, RegisterFactory isa, LowUIRStream())

  /// The same liftable IntelParser hands to the instructions it produces.
  static let liftable =
    { new ILiftable with
        member _.Lift(ins, bld) = Lifter.translate ins ins.Length bld
        member _.Disasm(_, bld) = bld }

  /// Lifts one row's declared shape, reporting only the disagreement this test
  /// is about. Terminator.futureFeature prints a stack trace for every opcode
  /// without a lifter, which would bury the result, so stderr is muted.
  static let liftsAt (core: InstructionCore) declared operationSize =
    let ins =
      Instruction(0UL, 1u, WordSize.Bit64, Prefix.None, REXPrefix.NOREX, None,
                  core.Opcode, operandsOf operationSize declared, operationSize,
                  64<rt>, false, liftable)
    try
      (ins :> IInstruction).Translate(builder ()) |> ignore
      true
    with
    | :? InvalidOperandException -> false
    | _ -> true

  /// INTO shares INT's lifter, which reads the interrupt vector from an
  /// operand INTO does not have: the vector is fixed at 4 and the trap only
  /// happens while OF is set, neither of which that lifter can say. Writing it
  /// properly means deciding how a conditional trap is modelled, which is a
  /// question about the IR rather than about the tables, so it is named here
  /// until someone answers it.
  static let knownGaps = set [ Opcode.INTO ]

  static let disagrees (core: InstructionCore) =
    let declared = declaredOperands core
    if Set.contains core.Opcode knownGaps then None
    elif operationSizes |> List.exists (liftsAt core declared) then None
    else Some(core.Opcode, declared)

  static let mismatches =
    lazy (let saved = Console.Error
          Console.SetError TextWriter.Null
          let result =
            allEntries
            |> Array.choose disagrees
            |> Array.distinct
            |> Array.sortBy (fun (opcode, _) -> string opcode)
          Console.SetError saved
          result)

  [<TestMethod>]
  member _.``Every table row declares the operands its lifter reads``() =
    let reported =
      mismatches.Force()
      |> Array.map (fun (opcode, declared) ->
        let shape =
          declared |> Array.map (sprintf "%A") |> String.concat "; "
        $"%A{opcode} declares [{shape}], which its lifter rejects")
      |> String.concat "\n"
    Assert.AreEqual<string>(
      "",
      reported,
      "These opcodes parse but cannot be lifted: the table and the lifter \
       disagree on how many operands they have.")

// vim: set tw=80 sts=2 sw=2:
