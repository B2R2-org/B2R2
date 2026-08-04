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

namespace B2R2.Assembly.Tests

open System
open System.IO
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Intel
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.Intel

/// Represents what happened when a reference encoding was round-tripped.
type internal RoundTripOutcome =
  /// The re-encoded bytes disassemble back to the text we started from.
  | Preserved
  /// The re-encoded bytes mean something other than the text we started from.
  | Altered of expected: string * actual: string
  /// The assembler cannot encode this instruction yet.
  | Unsupported

/// <summary>
/// Checks the Intel assembler against B2R2's own Intel decoder, which is far
/// better tested (see B2R2.FrontEnd.Intel.Tests). For each reference encoding
/// we disassemble it into canonical Intel syntax, hand that text back to the
/// assembler, and disassemble the result again. Comparing the resulting *text*
/// rather than the bytes means that picking a valid-but-different encoding is
/// not a failure, while emitting bytes that mean something else is.
///
/// Nothing here is a hand-written expectation, and nothing is a hand-written
/// input either: IntelSweep walks the encoding space and the decoder says what
/// each byte pattern means, so the set of instructions under test is whatever
/// the decoder currently understands. Forms that canonical disassembly cannot
/// express - unsized memory operands, labels, mnemonic aliases - live in
/// IntelEncodingTests instead.
///
/// The hand-written opcode families below stay because they pin every operand
/// shape of one encoding path at once, which is how a path can be rewritten
/// without quietly dropping a shape the sweep only reaches from one direction.
/// </summary>
[<TestClass>]
type IntelRoundTripTests() =

  /// Runs the given action with stderr muted. Terminator.futureFeature writes a
  /// stack trace there for every unsupported opcode, which would bury the
  /// actual test output; the library ought to raise without printing at all.
  static let mutingStderr action =
    let saved = Console.Error
    Console.SetError TextWriter.Null
    try action () finally Console.SetError saved

  static let disasm wordSize (bytes: byte[]) =
    let parser =
      IntelParser(wordSize, BinReader.Init Endian.Little)
      :> IInstructionParsable
    (parser.Parse(bytes, 0UL).Disasm()).ToLowerInvariant()

  /// One assembler per word size, reused across the whole sweep. Building one
  /// costs a table of encoders, and the sweep asks for tens of thousands of
  /// encodings, so a fresh assembler each time would dominate the run.
  static let assemblers =
    [ for wordSize in [ WordSize.Bit32; WordSize.Bit64 ] do
        let isa = ISA(Architecture.Intel, wordSize)
        wordSize, (Assembler(isa, 0UL) :> ILowerable) ]
    |> Map.ofList

  static let encodeFirst (wordSize: WordSize) text =
    match assemblers[wordSize].Lower text with
    | Ok((_, bytes) :: _) -> Some bytes
    | Ok [] | Error _ -> None

  /// Decides whether two disassemblies name the same two operands in the other
  /// order. XCHG is commutative and its short form encodes the accumulator in
  /// the opcode byte, so the decoder renders that form in its own canonical
  /// order; the bytes still mean what the source asked for.
  static let swapsOperands (expected: string) (actual: string) =
    match expected.Split(' '), actual.Split(' ') with
    | [| m1; a; b |], [| m2; c; d |] ->
      m1 = m2 && a.TrimEnd(',') = d && c.TrimEnd(',') = b
    | _ -> false

  /// Encodes the given source and disassembles the result, so that a source
  /// text stands in for the bytes a probe was decoded from.
  static let sourceRoundTrip wordSize (source: string) =
    match (try encodeFirst wordSize source with _ -> None) with
    | None -> Unsupported
    | Some encoded ->
      let actual = try disasm wordSize encoded with _ -> "<undecodable>"
      if actual = source || swapsOperands source actual then Preserved
      else Altered(source, actual)

  /// Round-trips every probe the sweep produces, under both word sizes. The
  /// sweep is the expensive part of this file, so it runs once for the class
  /// rather than once for each test that reads it.
  static let sweepOutcomes =
    lazy (mutingStderr (fun () ->
      [ for wordSize in [ WordSize.Bit32; WordSize.Bit64 ] do
          for probe in IntelSweep.probes wordSize ->
            wordSize, probe, sourceRoundTrip wordSize probe.Text ]))

  /// The eight classic ALU instructions, which share one encoding path.
  let aluOpcodes = [ "add"; "or"; "adc"; "sbb"; "and"; "sub"; "xor"; "cmp" ]

  /// Every operand shape that encoding path accepts, as a source template.
  /// Crossed with aluOpcodes below, so that collapsing the eight encoders into
  /// one cannot quietly change a single shape for a single opcode.
  let alu32Shapes =
    [ "OP al, 0x12"
      "OP ax, 0x1234"
      "OP eax, 0x12345678"
      "OP bl, 0x12"
      "OP bx, 0x12"
      "OP ebx, 0x12"
      "OP bx, 0x1234"
      "OP ebx, 0x12345678"
      "OP byte ptr [ecx], 0x12"
      "OP word ptr [ecx], 0x12"
      "OP dword ptr [ecx], 0x12"
      "OP word ptr [ecx], 0x1234"
      "OP dword ptr [ecx], 0x12345678"
      "OP byte ptr [ecx], bl"
      "OP word ptr [ecx], bx"
      "OP dword ptr [ecx], ebx"
      "OP bl, cl"
      "OP bx, cx"
      "OP ebx, ecx"
      "OP bl, byte ptr [ecx]"
      "OP bx, word ptr [ecx]"
      "OP ebx, dword ptr [ecx]"
      "OP dword ptr [ecx+edx*4+0x10], ebx"
      "OP dword ptr [ecx+edx*4+0x10], 0x12345678"
      "OP ebx, dword ptr [ecx+edx*4+0x10]" ]

  let alu64Shapes =
    [ "OP rax, 0x12345678"
      "OP rbx, 0x12"
      "OP rbx, 0x12345678"
      "OP qword ptr [rcx], 0x12"
      "OP qword ptr [rcx], 0x12345678"
      "OP qword ptr [rcx], rbx"
      "OP rbx, rcx"
      "OP rbx, qword ptr [rcx]"
      "OP qword ptr [rax+r8*2], 0x1"
      "OP r8, r9"
      "OP r8b, r9b"
      "OP r8, qword ptr [r9+r10*8+0x20]" ]

  /// Describes every source that does not encode to bytes meaning the same.
  let brokenSources sources =
    mutingStderr (fun () ->
      sources
      |> List.choose (fun (wordSize, source) ->
        match sourceRoundTrip wordSize source with
        | Preserved -> None
        | Altered(_, actual) -> Some $"'{source}' encoded as '{actual}'"
        | Unsupported -> Some $"'{source}' is not encodable"))
    |> List.sort

  /// Crosses a list of source templates with the opcodes that share them.
  let expand wordSize (opcodes: string list) (shapes: string list) =
    [ for shape in shapes do
        for opcode in opcodes -> wordSize, shape.Replace("OP", opcode) ]

  /// The group 3 unary instructions, which share one encoding path.
  let unaryOpcodes = [ "not"; "neg"; "mul"; "div"; "idiv" ]

  let unary32Shapes =
    [ "OP bl"
      "OP byte ptr [ecx]"
      "OP bx"
      "OP word ptr [ecx]"
      "OP ebx"
      "OP dword ptr [ecx]"
      "OP dword ptr [ecx+edx*4+0x10]"
      "OP word ptr [ecx+edx*4]" ]

  let unary64Shapes =
    [ "OP rbx"
      "OP qword ptr [rcx]"
      "OP r8"
      "OP r8b"
      "OP r9d"
      "OP qword ptr [r9+r10*8+0x20]" ]

  /// SSE instructions sharing the XMM register-or-memory encoding path, each
  /// paired with the memory operand size it takes.
  let sseOpcodes =
    [ "addpd", "xmmword"
      "addps", "xmmword"
      "addsd", "qword"
      "addss", "dword"
      "andpd", "xmmword"
      "andps", "xmmword"
      "cvtsd2ss", "qword"
      "divsd", "qword"
      "divss", "dword"
      "movss", "dword"
      "mulsd", "qword"
      "mulss", "dword"
      "orpd", "xmmword"
      "paddd", "xmmword"
      "subsd", "qword"
      "subss", "dword"
      "ucomiss", "dword"
      "xorps", "xmmword" ]

  /// SSE moves, which additionally encode a store to memory.
  let sseMovOpcodes =
    [ "movaps", "xmmword"
      "movdqa", "xmmword"
      "movdqu", "xmmword"
      "movups", "xmmword" ]

  /// String instructions, which take no operands.
  let stringOpcodes =
    [ "cmpsb"; "scasb"; "scasd"; "scasw"; "stosb"; "stosd"; "stosw" ]

  /// Every conditional jump, plus the two unconditional branches that also
  /// take a label.
  let branchOpcodes =
    [ "ja"
      "jb"
      "jbe"
      "jg"
      "jl"
      "jle"
      "jnb"
      "jnl"
      "jno"
      "jnp"
      "jns"
      "jnz"
      "jo"
      "jp"
      "js"
      "jz"
      "jmp"
      "call" ]

  /// Padding long enough to push a label past the reach of a rel8 branch.
  let farPadding = String.replicate 200 "  nop\n"

  /// Sources that exercise both branch directions at both displacement
  /// widths. The near cases matter most: a label 128 bytes away selects a
  /// wider displacement, and the opcode has to agree about how wide.
  let branchSources opcode =
    [ $"  {opcode} L\n  nop\nL:\n  ret"
      $"L:\n  nop\n  {opcode} L\n  ret"
      $"  {opcode} L\n{farPadding}L:\n  ret"
      $"L:\n{farPadding}  {opcode} L\n  ret" ]

  /// Decodes one instruction from the given bytes, padded so that an encoding
  /// claiming to be longer than it is still decodes, and reports the length
  /// the decoder believes it has.
  let decodedLength wordSize (bytes: byte[]) =
    let parser =
      IntelParser(wordSize, BinReader.Init Endian.Little)
      :> IInstructionParsable
    try
      let ins = parser.Parse(Array.append bytes (Array.zeroCreate 16), 0UL)
      Some(int ins.Length, (ins.Disasm()).ToLowerInvariant())
    with _ -> None

  /// The x87 arithmetic instructions sharing one encoding path. Their register
  /// forms are worth exercising in both operand orders, because the subtract
  /// and divide pairs swap opcode slots between the two.
  let x87Opcodes = [ "fadd"; "fdiv"; "fmul"; "fsub"; "fsubr" ]

  let x87Shapes =
    [ "OP dword ptr [ecx]"
      "OP qword ptr [ecx]"
      "OP dword ptr [ecx+edx*4+0x10]"
      "OP qword ptr [ecx+edx*4+0x10]"
      "OP st0, st0"
      "OP st0, st1"
      "OP st1, st0"
      "OP st0, st7"
      "OP st7, st0" ]

  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``Every instruction the decoder decodes, the assembler encodes``() =
    let broken =
      sweepOutcomes.Force()
      |> List.choose (fun (wordSize, probe, outcome) ->
        match outcome with
        | Preserved ->
          None
        | Altered(_, actual) ->
          Some $"%A{wordSize} '{probe.Text}' encoded as '{actual}'"
        | Unsupported ->
          Some $"%A{wordSize} '{probe.Text}' is not encodable")
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" broken,
      "These instructions decode but no longer encode, or encode to bytes \
       that mean something else.")

  [<TestMethod>]
  member _.``Every ALU opcode encodes every operand shape correctly``() =
    let wrong =
      expand WordSize.Bit32 aluOpcodes alu32Shapes
      @ expand WordSize.Bit64 aluOpcodes alu64Shapes
      |> brokenSources
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These ALU operand shapes no longer encode correctly.")

  [<TestMethod>]
  member _.``Every group 3 unary opcode encodes every shape correctly``() =
    let wrong =
      expand WordSize.Bit32 unaryOpcodes unary32Shapes
      @ expand WordSize.Bit64 unaryOpcodes unary64Shapes
      |> brokenSources
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These unary operand shapes no longer encode correctly.")

  [<TestMethod>]
  member _.``Branches to a label encode as wide as their opcode claims``() =
    let wrong =
      mutingStderr (fun () ->
        [ for wordSize in [ WordSize.Bit32; WordSize.Bit64 ] do
            for opcode in branchOpcodes do
              for source in branchSources opcode -> wordSize, source ]
        |> List.collect (fun (wordSize, source) ->
          let asm =
            Assembler(ISA(Architecture.Intel, wordSize), 0UL) :> ILowerable
          match (try asm.Lower source with _ -> Result.Error "raised") with
          | Result.Error _ -> [ $"'{source}' does not assemble" ]
          | Ok encoded ->
            encoded
            |> List.choose (fun (_, bytes) ->
              let hex =
                bytes |> Array.map (sprintf "%02x") |> String.concat ""
              match decodedLength wordSize bytes with
              | None -> Some $"{hex} does not decode"
              | Some(length, text) when length <> bytes.Length ->
                Some $"emitted {bytes.Length}B as {hex}, decoder reads \
                       {length}B as '{text}'"
              | Some _ -> None)))
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These encodings are narrower than the decoder expects, which makes \
       every following instruction decode at the wrong offset.")

  [<TestMethod>]
  member _.``Every x87 arithmetic opcode encodes every shape correctly``() =
    let wrong =
      expand WordSize.Bit32 x87Opcodes x87Shapes
      @ expand WordSize.Bit64 x87Opcodes x87Shapes
      |> brokenSources
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These x87 operand shapes no longer encode correctly.")

  [<TestMethod>]
  member _.``Every SSE and string opcode encodes every shape correctly``() =
    let arithmetic =
      [ for opcode, memory in sseOpcodes @ sseMovOpcodes do
          WordSize.Bit32, $"{opcode} xmm0, xmm1"
          WordSize.Bit32, $"{opcode} xmm2, {memory} ptr [ecx]"
          WordSize.Bit32, $"{opcode} xmm2, {memory} ptr [ecx+edx*4+0x10]"
          WordSize.Bit64, $"{opcode} xmm8, xmm9"
          WordSize.Bit64, $"{opcode} xmm8, {memory} ptr [r9+r10*8+0x20]" ]
    let stores =
      [ for opcode, memory in sseMovOpcodes do
          WordSize.Bit32, $"{opcode} {memory} ptr [ecx], xmm2"
          WordSize.Bit64, $"{opcode} {memory} ptr [r9+r10*8+0x20], xmm8" ]
    let strings =
      [ for opcode in stringOpcodes do
          WordSize.Bit32, opcode
          WordSize.Bit32, $"repnz {opcode}"
          WordSize.Bit64, opcode
        for opcode in [ "scasq"; "stosq" ] do
          WordSize.Bit64, opcode
          WordSize.Bit64, $"repnz {opcode}" ]
    let wrong = arithmetic @ stores @ strings |> brokenSources
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These SSE or string operand shapes no longer encode correctly.")

  /// The control register moves select their register with the ModRM.reg field,
  /// and the indices the manual reserves - CR1, and CR5 to CR7 - name no
  /// register, so the decoder rejects them rather than reading past the end of
  /// its register table. The sweep covers the forms that do exist; this pins
  /// the ones that must not decode at all.
  [<TestMethod>]
  member _.``A reserved control register does not decode``() =
    let reserved =
      [ [| 0x0Fuy; 0x20uy; 0xC9uy |] (* 0F 20 /1, so CR1 *)
        [| 0x0Fuy; 0x20uy; 0xE9uy |] (* 0F 20 /5, so CR5 *)
        [| 0x0Fuy; 0x20uy; 0xF1uy |] (* 0F 20 /6, so CR6 *)
        [| 0x0Fuy; 0x22uy; 0xF9uy |] (* 0F 22 /7, so CR7 *) ]
    let decoded =
      reserved
      |> List.choose (fun bytes ->
        try Some(disasm WordSize.Bit32 bytes) with _ -> None)
    Assert.AreEqual<string>(
      "",
      String.concat "\n" decoded,
      "These name a register the manual reserves, so they must not decode.")
