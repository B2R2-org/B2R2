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
/// Nothing here is a hand-written expectation: the decoder supplies both the
/// input syntax and the expected output, so the corpus grows by adding bytes.
/// Forms that canonical disassembly cannot express - unsized memory operands,
/// labels, mnemonic aliases - live in IntelEncodingTests instead.
/// </summary>
[<TestClass>]
type IntelRoundTripTests() =

  let x86Corpus =
    [| "c70518bb210002000000"
       "0fbe7fff"
       "6bfa0a"
       "f720"
       "f7f1"
       "212414"
       "212542424242"
       "c1000a"
       "c0000a"
       "f6000a"
       "ffe4"
       "ea123456789000"
       "65ff1510000000"
       "9a987654321000"
       "cd01"
       "66ef"
       "c40f"
       "c511"
       "df84ca01020304"
       "df20"
       "dff1"
       "dfe9" |]

  let x64Corpus =
    [| "6811223344"
       "4863c8"
       "4803c8"
       "c4e1f9d6d0"
       "0f7501"
       "0f75c1"
       "660f7501"
       "660f75c1"
       "62f1fd486f4c2401"
       "0f380101"
       "0f3801c1"
       "660f380101"
       "660f3801c1"
       "0f380301"
       "0f3803c1"
       "660f380301"
       "660f3803c1"
       "0f380201"
       "0f3802c1"
       "660f380201"
       "660f3802c1"
       "0f380501"
       "0f3805c1"
       "660f380501"
       "660f3805c1"
       "0f380701"
       "0f3807c1"
       "660f380701"
       "660f3807c1"
       "0f380601"
       "0f3806c1"
       "660f380601"
       "660f3806c1"
       "0f381c01"
       "0f381cc1"
       "660f381c01"
       "660f381cc1"
       "0f381e01"
       "0f381ec1"
       "660f381e01"
       "660f381ec1"
       "0f381d01"
       "0f381dc1"
       "660f381d01"
       "660f381dc1"
       "0f380b01"
       "0f380bc1"
       "660f380b01"
       "660f380bc1"
       "0f380801"
       "0f3808c1"
       "660f380801"
       "660f3808c1"
       "0f380901"
       "0f3809c1"
       "660f380901"
       "660f3809c1"
       "0f380a01"
       "0f380ac1"
       "660f380a01"
       "660f380ac1"
       "660f3a0fd101"
       "660f384002"
       "660f3840c2"
       "660f382802"
       "660f3828c2"
       "660f383a02"
       "660f383ac2"
       "660f383902"
       "660f3839c2"
       "660f383e02"
       "660f383ec2"
       "660f383f02"
       "660f383fc2"
       "660f383c02"
       "660f383cc2"
       "660f383d02"
       "660f383dc2"
       "660f382102"
       "660f3821c2"
       "660f382202"
       "660f3822c2"
       "660f382002"
       "660f3820c2"
       "660f382502"
       "660f3825c2"
       "660f382302"
       "660f3823c2"
       "660f382402"
       "660f3824c2"
       "660f383102"
       "660f3831c2"
       "660f383202"
       "660f3832c2"
       "660f383002"
       "660f3830c2"
       "660f383502"
       "660f3835c2"
       "660f383302"
       "660f3833c2"
       "660f383402"
       "660f3834c2"
       "660f384102"
       "660f3841c2"
       "660f382b02"
       "660f382bc2"
       "660f383702"
       "660f3837c2"
       "660f1b842400020000"
       "c4e1297503"
       "c4e12975c3"
       "c4e12d7503"
       "c4e12d75c3"
       "c4e2611c03"
       "c4e2611cc3"
       "c4e2651c03"
       "c4e2651cc3"
       "c4e2611e03"
       "c4e2611ec3"
       "c4e2651e03"
       "c4e2651ec3"
       "c4e2611d03"
       "c4e2611dc3"
       "c4e2651d03"
       "c4e2651dc3"
       "c4e2610203"
       "c4e26102c3"
       "c4e2650203"
       "c4e26502c3"
       "c4e2610303"
       "c4e26103c3"
       "c4e2650303"
       "c4e26503c3"
       "c4e2610103"
       "c4e26101c3"
       "c4e2650103"
       "c4e26501c3"
       "c4e2610603"
       "c4e26106c3"
       "c4e2650603"
       "c4e26506c3"
       "c4e2610703"
       "c4e26107c3"
       "c4e2650703"
       "c4e26507c3"
       "c4e2610503"
       "c4e26105c3"
       "c4e2650503"
       "c4e26505c3"
       "c4e2610b03"
       "c4e2610bc3"
       "c4e2650b03"
       "c4e2650bc3"
       "c4e2610803"
       "c4e26108c3"
       "c4e2650803"
       "c4e26508c3"
       "c4e2610a03"
       "c4e2610ac3"
       "c4e2650a03"
       "c4e2650ac3"
       "c4e2610903"
       "c4e26109c3"
       "c4e2650903"
       "c4e26509c3"
       "c4e2612b03"
       "c4e2612bc3"
       "c4e2652b03"
       "c4e2652bc3"
       "c4e2613703"
       "c4e26137c3"
       "c4e2653703"
       "c4e26537c3"
       "c4e2614103"
       "c4e26141c3"
       "c4e2613c03"
       "c4e2613cc3"
       "c4e2653c03"
       "c4e2653cc3"
       "c4e2613d03"
       "c4e2613dc3"
       "c4e2653d03"
       "c4e2653dc3"
       "c4e2613f03"
       "c4e2613fc3"
       "c4e2653f03"
       "c4e2653fc3"
       "c4e2613e03"
       "c4e2613ec3"
       "c4e2653e03"
       "c4e2653ec3"
       "c4e2613803"
       "c4e26138c3"
       "c4e2653803"
       "c4e26538c3"
       "c4e2613903"
       "c4e26139c3"
       "c4e2653903"
       "c4e26539c3"
       "c4e2613a03"
       "c4e2613ac3"
       "c4e2653a03"
       "c4e2653ac3"
       "c4e2612103"
       "c4e26121c3"
       "c4e2652103"
       "c4e26521c3"
       "c4e2612203"
       "c4e26122c3"
       "c4e2652203"
       "c4e26522c3"
       "c4e2612003"
       "c4e26120c3"
       "c4e2652003"
       "c4e26520c3"
       "c4e2612503"
       "c4e26125c3"
       "c4e2652503"
       "c4e26525c3"
       "c4e2612303"
       "c4e26123c3"
       "c4e2652303"
       "c4e26523c3"
       "c4e2612403"
       "c4e26124c3"
       "c4e2652403"
       "c4e26524c3"
       "c4e2613103"
       "c4e26131c3"
       "c4e2653103"
       "c4e26531c3"
       "c4e2613203"
       "c4e26132c3"
       "c4e2653203"
       "c4e26532c3"
       "c4e2613003"
       "c4e26130c3"
       "c4e2653003"
       "c4e26530c3"
       "c4e2613503"
       "c4e26135c3"
       "c4e2653503"
       "c4e26535c3"
       "c4e2613303"
       "c4e26133c3"
       "c4e2653303"
       "c4e26533c3"
       "c4e2613403"
       "c4e26134c3"
       "c4e2653403"
       "c4e26534c3"
       "c4e2612803"
       "c4e26128c3"
       "c4e2652803"
       "c4e26528c3"
       "c4e2614003"
       "c4e26140c3"
       "c4e2654003"
       "c4e26540c3" |]

  /// How many reference encodings the assembler can encode at all. This is a
  /// ratchet guarding against lost coverage: raise it as support grows.
  let encodableFloor = 19

  /// Runs the given action with stderr muted. Terminator.futureFeature writes a
  /// stack trace there for every unsupported opcode, which would bury the
  /// actual test output; the library ought to raise without printing at all.
  let mutingStderr action =
    let saved = Console.Error
    Console.SetError TextWriter.Null
    try action () finally Console.SetError saved

  let disasm wordSize (bytes: byte[]) =
    let parser =
      IntelParser(wordSize, BinReader.Init Endian.Little)
      :> IInstructionParsable
    (parser.Parse(bytes, 0UL).Disasm()).ToLowerInvariant()

  let encodeFirst (wordSize: WordSize) text =
    let asm = Assembler(ISA(Architecture.Intel, wordSize), 0UL) :> ILowerable
    match asm.Lower text with
    | Ok(bytes :: _) -> Some bytes
    | Ok [] | Error _ -> None

  let roundTrip wordSize hex =
    let expected = disasm wordSize (ByteArray.ofHexString hex)
    match (try encodeFirst wordSize expected with _ -> None) with
    | None -> Unsupported
    | Some encoded ->
      let actual = try disasm wordSize encoded with _ -> "<undecodable>"
      if actual = expected then Preserved else Altered(expected, actual)

  let runCorpus () =
    mutingStderr (fun () ->
      [ for hex in x86Corpus -> hex, roundTrip WordSize.Bit32 hex
        for hex in x64Corpus -> hex, roundTrip WordSize.Bit64 hex ])

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

  /// Encodes the given source and disassembles the result, so that a source
  /// text stands in for the reference bytes the corpus above supplies.
  let sourceRoundTrip wordSize (source: string) =
    match (try encodeFirst wordSize source with _ -> None) with
    | None -> Unsupported
    | Some encoded ->
      let actual = try disasm wordSize encoded with _ -> "<undecodable>"
      if actual = source then Preserved else Altered(source, actual)

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
  member _.``Canonical round-trip preserves the meaning of every encoding``() =
    let altered =
      runCorpus ()
      |> List.choose (fun (hex, outcome) ->
        match outcome with
        | Altered(expected, actual) ->
          Some $"{hex}: want '{expected}' got '{actual}'"
        | Preserved | Unsupported -> None)
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" altered,
      "Re-encoding changed what these encodings mean.")

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
            |> List.choose (fun bytes ->
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

  [<TestMethod>]
  member _.``Reference corpus coverage does not regress``() =
    let encodable =
      runCorpus ()
      |> List.filter (fun (_, outcome) ->
        match outcome with
        | Preserved | Altered _ -> true
        | Unsupported -> false)
      |> List.length
    Assert.AreEqual<int>(
      0,
      max 0 (encodableFloor - encodable),
      $"Encodable reference encodings dropped to {encodable}, "
      + $"below the floor of {encodableFloor}.")
