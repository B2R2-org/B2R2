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

namespace B2R2.FrontEnd.Tests

open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type LiftingUnitTests() =
  static let isa = ISA(Architecture.Intel, WordSize.Bit64)

  /// "nop; nop; ret; nop".
  static let code = [| 0x90uy; 0x90uy; 0xc3uy; 0x90uy |]

  /// A raw image holding the code above.
  static let hdl = BinHandle.LoadRawImage(code, isa)

  static let lu = hdl.NewLiftingUnit()

  /// A unit over its own image, so that configuring the output format cannot
  /// leak into the tests that share the one above.
  static let freshUnit () = BinHandle.LoadRawImage(code, isa).NewLiftingUnit()

  /// An address outside the image, which resolves to a null pointer.
  static let unmapped = 0x9999UL

  /// Pointers that reach no readable file bytes: a null pointer, a region
  /// mapped to VM only, and a pointer advanced past its file-backed region.
  /// All three must be rejected before the span is sliced.
  static let unreadable =
    [| BinFilePointer.Null
       BinFilePointer.CreateVirtual(0x1000UL, 0x1fffUL)
       (hdl.File.GetBoundedPointer 0UL).Advance 4 |]

  static let emptyCode: byte[] = Array.zeroCreate 4

  /// A lifting unit over the empty image for the given architecture.
  static let unitFor (arch: Architecture) =
    BinHandle.LoadRawImage(emptyCode, ISA arch).NewLiftingUnit()

  /// The alignment every architecture with a parser must report. This list is
  /// deliberately kept next to the architectures ArchSupport can build a parser
  /// for: LiftingUnit used to reconstruct alignment from a separate table, and
  /// S390 was missing from it, so NewLiftingUnit raised NotImplementedException
  /// before it could return a unit.
  static let alignments =
    [| Architecture.Intel, 1
       Architecture.ARMv7, 4
       Architecture.ARMv8, 4
       Architecture.MIPS, 4
       Architecture.PPC, 4
       Architecture.RISCV, 2
       Architecture.SPARC, 2
       Architecture.S390, 2
       Architecture.SH4, 2
       Architecture.PARISC, 4
       Architecture.AVR, 2
       Architecture.TMS320C6000, 4
       Architecture.EVM, 1 |]

  static let assertRaises (f: unit -> unit) =
    Assert.ThrowsExactly<System.ArgumentException>(fun () -> f ()) |> ignore

  static let assertRejectsAll (f: BinFilePointer -> unit) =
    for ptr in unreadable do assertRaises (fun () -> f ptr)

  [<TestMethod>]
  member _.``[LiftingUnit] parse and lift within the image test``() =
    Assert.AreEqual<string>("nop", lu.DisasmInstruction(addr = 0UL))
    Assert.AreEqual<uint32>(1u, lu.ParseInstruction(addr = 0UL).Length)
    Assert.AreEqual<int>(1, (lu.DecomposeInstruction(addr = 0UL)).Length)
    let parsed = lu.ParseBBlock(addr = 0UL)
    Assert.AreEqual<bool>(true, parsed.IsTerminated)
    Assert.AreEqual<int>(3, parsed.Instructions.Length)

  [<TestMethod>]
  member _.``[LiftingUnit] lift a basic block within the image test``() =
    let lifted = lu.LiftBBlock(addr = 0UL)
    Assert.AreEqual<bool>(true, lifted.IsTerminated)
    Assert.AreEqual<int>(3, lifted.Statements.Length)

  (* The four members below slice the file span themselves. Each must reject an
     unreadable pointer instead of letting a span-level exception escape, so
     ThrowsExactly is used to rule out ArgumentOutOfRangeException. *)
  [<TestMethod>]
  member _.``[LiftingUnit] parse an unreadable pointer test``() =
    assertRejectsAll (fun p -> lu.ParseInstruction(ptr = p) |> ignore)

  [<TestMethod>]
  member _.``[LiftingUnit] lift an unreadable pointer test``() =
    assertRejectsAll (fun p -> lu.LiftInstruction(ptr = p) |> ignore)
    assertRejectsAll (fun p -> lu.LiftInstruction(p, true) |> ignore)

  [<TestMethod>]
  member _.``[LiftingUnit] disasm an unreadable pointer test``() =
    assertRejectsAll (fun p -> lu.DisasmInstruction(ptr = p) |> ignore)

  [<TestMethod>]
  member _.``[LiftingUnit] decompose an unreadable pointer test``() =
    assertRejectsAll (fun p -> lu.DecomposeInstruction(ptr = p) |> ignore)

  (* The addr overloads resolve the address to a pointer themselves, so an
     unmapped address has to be rejected the same way. *)
  [<TestMethod>]
  member _.``[LiftingUnit] unmapped address test``() =
    assertRaises (fun () -> lu.ParseInstruction(addr = unmapped) |> ignore)
    assertRaises (fun () -> lu.LiftInstruction(addr = unmapped) |> ignore)
    assertRaises (fun () -> lu.LiftInstruction(unmapped, true) |> ignore)
    assertRaises (fun () -> lu.DisasmInstruction(addr = unmapped) |> ignore)
    assertRaises (fun () -> lu.DecomposeInstruction(addr = unmapped) |> ignore)

  (* The Try variant must report the failure instead of raising. Which ErrorCase
     it reports is still open, so only the absence of an exception is pinned. *)
  [<TestMethod>]
  member _.``[LiftingUnit] try parse an unreadable pointer test``() =
    for p in unreadable do
      let res = lu.TryParseInstruction(ptr = p)
      Assert.AreEqual<bool>(true, Result.isError res)
    let res = lu.TryParseInstruction(addr = unmapped)
    Assert.AreEqual<bool>(true, Result.isError res)

  (* Both block APIs share parseBBLByPtr, which reports an unreadable pointer as
     an incomplete result rather than raising. *)
  [<TestMethod>]
  member _.``[LiftingUnit] block APIs at an unreadable pointer test``() =
    for p in unreadable do
      let parsed = lu.ParseBBlock(ptr = p)
      Assert.AreEqual<bool>(false, parsed.IsTerminated)
      Assert.AreEqual<int>(0, parsed.Instructions.Length)
    for p in unreadable do
      let lifted = lu.LiftBBlock(ptr = p)
      Assert.AreEqual<bool>(false, lifted.IsTerminated)
      Assert.AreEqual<int>(0, lifted.Statements.Length)

  [<TestMethod>]
  member _.``[LiftingUnit] block APIs at an unmapped address test``() =
    let parsed = lu.ParseBBlock(addr = unmapped)
    Assert.AreEqual<bool>(false, parsed.IsTerminated)
    Assert.AreEqual<int>(0, parsed.Instructions.Length)
    let lifted = lu.LiftBBlock(addr = unmapped)
    Assert.AreEqual<bool>(false, lifted.IsTerminated)
    Assert.AreEqual<int>(0, lifted.Statements.Length)

  (* The span overload parses bytes the caller supplies, which need not come
     from the file at all: the address only tells the parser where to pretend
     the instruction sits. Bounds are the caller's to get right. *)
  [<TestMethod>]
  member _.``[LiftingUnit] parse a caller-supplied span test``() =
    let bytes = [| 0xc3uy |] (* ret *)
    let ins = lu.ParseInstruction(System.ReadOnlySpan bytes, 0x400000UL)
    Assert.AreEqual<string>("ret", ins.Disasm())
    Assert.AreEqual<Addr>(0x400000UL, ins.Address)
    Assert.AreEqual<uint32>(1u, ins.Length)

  [<TestMethod>]
  member _.``[LiftingUnit] disassembly syntax test``() =
    let addEax = [| 0x05uy; 0x00uy; 0x00uy; 0x01uy; 0x00uy |]
    let x86 = ISA(Architecture.Intel, WordSize.Bit32)
    let x86Unit = BinHandle.LoadRawImage(addEax, x86).NewLiftingUnit()
    let disasm () =
      x86Unit.DisasmInstruction(addr = 0UL).ToLowerInvariant()
    Assert.AreEqual<DisasmSyntax>(DefaultSyntax, x86Unit.DisassemblySyntax)
    Assert.AreEqual<string>("add eax, 0x10000", disasm ())
    x86Unit.DisassemblySyntax <- ATTSyntax
    Assert.AreEqual<DisasmSyntax>(ATTSyntax, x86Unit.DisassemblySyntax)
    Assert.AreEqual<string>("add $0x10000, %eax", disasm ())

  (* Assigning a syntax the architecture cannot honour leaves the property
     unchanged, which is the only way a caller learns the request was dropped.
     This used to be a write-only method with no such signal. *)
  [<TestMethod>]
  member _.``[LiftingUnit] unsupported syntax is observable test``() =
    let armUnit = unitFor Architecture.ARMv7
    armUnit.DisassemblySyntax <- ATTSyntax
    Assert.AreEqual<DisasmSyntax>(DefaultSyntax, armUnit.DisassemblySyntax)

  (* The three Disasm overloads differ only in how they locate the instruction,
     so they must render it the same way. The addr and ptr ones used to call
     ins.Disasm(), which builds a fresh default builder inside the architecture,
     so ConfigureDisassembly reached the ins overload alone and the file's name
     resolver went with it. *)
  [<TestMethod>]
  member _.``[LiftingUnit] disasm overloads agree test``() =
    let unit = freshUnit ()
    let ptr = hdl.File.GetBoundedPointer 0UL
    let ins = unit.ParseInstruction(ptr = ptr)
    let rendered () =
      [| unit.DisasmInstruction(ins = ins)
         unit.DisasmInstruction(addr = 0UL)
         unit.DisasmInstruction(ptr = ptr) |]
      |> Array.distinct
      |> String.concat "|"
    Assert.AreEqual<string>("nop", rendered ())
    unit.ConfigureDisassembly true
    Assert.AreEqual<string>("0000000000000000: nop", rendered ())

  (* ConfigureDisassembly used to set the string builder alone, so an address
     asked for here never reached Decompose*. *)
  [<TestMethod>]
  member _.``[LiftingUnit] configuration reaches decompose test``() =
    let unit = freshUnit ()
    let hasAddr () =
      unit.DecomposeInstruction(addr = 0UL)
      |> Array.exists (fun w -> w.AsmWordKind = AsmWordKind.Address)
    Assert.AreEqual<bool>(false, hasAddr ())
    unit.ConfigureDisassembly true
    Assert.AreEqual<bool>(true, hasAddr ())

  (* The two builders used to disagree out of the box, the string one showing
     the address and the AsmWord one not, so the same instruction read
     differently depending on which member produced it. *)
  [<TestMethod>]
  member _.``[LiftingUnit] disasm and decompose agree test``() =
    let unit = freshUnit ()
    let joined () =
      unit.DecomposeInstruction(addr = 0UL)
      |> Array.map (fun w -> w.AsmWordValue)
      |> String.concat ""
    Assert.AreEqual<string>("nop", joined ())
    Assert.AreEqual<string>(unit.DisasmInstruction(addr = 0UL), joined ())
    unit.ConfigureDisassembly true
    Assert.AreEqual<string>("0000000000000000: nop", joined ())
    Assert.AreEqual<string>(unit.DisasmInstruction(addr = 0UL), joined ())

  [<TestMethod>]
  member _.``[LiftingUnit] instruction alignment test``() =
    Assert.AreEqual<int>(1, lu.InstructionAlignment)

  [<TestMethod>]
  member _.``[LiftingUnit] alignment of every architecture test``() =
    for arch, expected in alignments do
      let unit = unitFor arch
      Assert.AreEqual<int>(expected, unit.InstructionAlignment)

  (* An odd entry point selects Thumb mode. ArchSupport builds an ARM32Parser
     for every ISA the ARM32 pattern covers, AArch32 included, but BinHandle
     used to test for ARMv7 alone and so left AArch32 in ARM mode. *)
  [<TestMethod>]
  member _.``[LiftingUnit] thumb entry point test``() =
    for arch in [| Architecture.ARMv7; Architecture.ARMv8 |] do
      let isa = ISA(arch, WordSize.Bit32)
      let hdl = BinHandle.LoadRawImage(emptyCode, isa, 0x1001UL, OS.UnknownOS)
      let lu = hdl.NewLiftingUnit()
      Assert.AreEqual<bool>(true, lu.IsThumb)
      Assert.AreEqual<int>(2, lu.InstructionAlignment)

  (* ARM32 alignment follows the mode, so it cannot come from a table keyed by
     ISA alone. Setting the mode is inert where there is no Thumb to switch to,
     which is what lets callers skip the architecture test. *)
  [<TestMethod>]
  member _.``[LiftingUnit] thumb mode toggling test``() =
    let armUnit = unitFor Architecture.ARMv7
    Assert.AreEqual<int>(4, armUnit.InstructionAlignment)
    armUnit.IsThumb <- true
    Assert.AreEqual<int>(2, armUnit.InstructionAlignment)
    let x86Unit = BinHandle.LoadRawImage(emptyCode, isa).NewLiftingUnit()
    x86Unit.IsThumb <- true
    Assert.AreEqual<bool>(false, x86Unit.IsThumb)
    Assert.AreEqual<int>(1, x86Unit.InstructionAlignment)
