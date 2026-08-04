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
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.SPARC
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.SPARC

/// Represents what happened when a reference encoding was round-tripped.
type internal SPARCOutcome =
  /// The re-encoded word disassembles back to the text we started from.
  | SPARCPreserved
  /// The re-encoded word means something other than the text we started from.
  | SPARCAltered of actual: string
  /// The assembler cannot encode this instruction yet.
  | SPARCUnsupported

/// <summary>
/// Checks the SPARC assembler against B2R2's own SPARC decoder. For each
/// reference encoding we disassemble it into canonical SPARC syntax, hand that
/// text back to the assembler, and disassemble the result again. Comparing the
/// resulting *text* rather than the bytes means that picking a
/// valid-but-different encoding is not a failure, while emitting a word that
/// means something else is. The disassembler writes several instructions under
/// one name and tells them apart by the operands that follow, so text is also
/// the only thing the two ends of this agree on.
///
/// Nothing here is a hand-written expectation, and nothing is a hand-written
/// input either: SPARCSweep walks the encoding space and the decoder says what
/// each word means, so the set of instructions under test is whatever the
/// decoder currently understands. Forms that canonical disassembly cannot
/// express - labels above all - are pinned by the hand-written tests below.
/// </summary>
[<TestClass>]
type SPARCRoundTripTests() =

  static let isa = ISA(Architecture.SPARC, Endian.Big, WordSize.Bit64)

  /// One parser, reused across the whole sweep. The sweep asks for millions of
  /// decodings, so building one each time would dominate the run.
  static let parser =
    SPARCParser(BinReader.Init Endian.Big) :> IInstructionParsable

  static let assembler = Assembler(isa, 0UL) :> ILowerable

  static let disasm (bytes: byte[]) = (parser.Parse(bytes, 0UL)).Disasm()

  static let encodeFirst (assembler: ILowerable) text =
    match assembler.Lower text with
    | Ok((_, bytes) :: _) -> Some bytes
    | Ok [] | Error _ -> None

  /// Encodes the given source and disassembles the result, so that a source
  /// text stands in for the word a probe was decoded from.
  static let roundTrip (source: string) =
    match (try encodeFirst assembler source with _ -> None) with
    | None -> SPARCUnsupported
    | Some encoded ->
      let actual = try disasm encoded with _ -> "<undecodable>"
      if actual = source then SPARCPreserved else SPARCAltered actual

  /// Describes a source that does not encode to a word meaning the same.
  static let brokenSource source =
    match roundTrip source with
    | SPARCPreserved -> None
    | SPARCAltered actual -> Some $"'{source}' encoded as '{actual}'"
    | SPARCUnsupported -> Some $"'{source}' is not encodable"

  /// Every probe the sweep produces. The sweep is the expensive part of this
  /// file, so it runs once for the class rather than once for each test that
  /// reads it.
  static let probes = lazy (SPARCSweep.probes ())

  /// The instruction a place is written into, over and over, so that a label
  /// can be put out of reach of the instruction naming it.
  let padding = String.replicate 200 "  nop\n"

  /// <summary>
  /// The sources a branch to a label is tried in, each paired with the index of
  /// the instruction under test and how far away its label then is.
  ///
  /// A label is reached from below as well as from above, and from far enough
  /// away that an offset holding too few bits would not reach it.
  /// </summary>
  let branchCases source =
    [ $"L:\n  nop\n  {source}\n  nop", 1, -4
      $"  {source}\n{padding}L:\n  nop", 0, 0x324
      $"L:\n{padding}  {source}\n  nop", 200, -0x320 ]

  /// Every instruction that names a place, paired with how the disassembler
  /// writes it once it has worked out how far away that place is.
  let branchSources =
    [ "ba L", "ba"
      "ba,a L", "ba,a"
      "bne L", "bne"
      "ba,pt %icc, L", "ba,pt %icc,"
      "bne,a,pn %xcc, L", "bne,a,pn %xcc,"
      "fbe,pt %fcc2, L", "fbe,pt %fcc2,"
      "brz,pn %g1, L", "brz,pn %g1,"
      "brnz,a,pt %o0, L", "brnz,a,pt %o0,"
      "call L", "call" ]

  /// Sources that name no instruction at all, either because a number does not
  /// fit where it is written or because a register cannot be named there.
  let unencodableSources =
    [ "add %g1, 0x1000, %g2"
      "add %g1, -4097, %g2"
      "sll %g1, 0x20, %g2"
      "sllx %g1, 0x40, %g2"
      "mova %icc, 0x400, %g2"
      "movrz %g1, 0x200, %g2"
      "ta %icc, 0x100"
      "membar 0x10"
      "sethi %hi(0x1401), %g1"
      "sethi %hi(0x100000000), %g1"
      "ba 0x1"
      "ba 0x800000"
      "ba,pt %icc, 0x100000"
      "brz,pn %g1, 0x20000"
      "call 0x2"
      "add %f0, %g1, %g2"
      "faddd %f1, %f2, %f4"
      "faddq %f2, %f4, %f8"
      "lduw [%g1 + %g2], %f0"
      "add %g1, %g2"
      "nop %g1"
      "add,a %g1, %g2, %g3"
      "ba,pt 0x14"
      "ba %icc, 0x14"
      "movleu %fcc0, %g1, %g2"
      "movu %icc, %g1, %g2"
      "tcs %fcc0, %g1"
      "lduwa [%g1 + %g2] %asi, %g3"
      "lduwa [%g1 + 0x8] 0x80, %g3"
      "frobnicate %g1, %g2" ]

  /// Sources written the way a person writes one rather than the way the
  /// disassembler does, each paired with the instruction it names.
  let writtenSources =
    [ "  add %g1, 1, %g2  ! what a person writes", "add %g1, 0x1, %g2     ! 1"
      "add %g1, -1, %g2", "add %g1, 0xffffffff, %g2     ! -1"
      "ADD %G1, %G2, %G3", "add %g1, %g2, %g3"
      "ldub [%g1+%g2], %g3", "ldub [%g1 + %g2], %g3"
      "ldub [ %g1 + 8 ], %g3", "ldub [%g1 + 0x8], %g3     ! 8"
      "stw %g1, [%g2+0]", "stw %g1, [%g2 + 0x0]     ! 0"
      "or %g1, 0, %g2", "or %g1, %g0, %g2"
      "casa [%g1] %asi, %g2, %g3", "casa [%g1] %asi, %g2, %g3"
      "jmpl %g1 + 0x8, %o7", "jmpl %g1 + 0x8, %o7     ! 8"
      "sethi %hi(0x1400), %g1", "sethi %hi(0x1400), %g1     ! 5120"
      "faddd %f2, %f34, %f62", "faddd %f2, %f34, %f62"
      "nop", "nop" ]

  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``Every instruction the decoder decodes, the assembler encodes``() =
    let broken =
      probes.Force()
      |> List.choose (fun probe -> brokenSource probe.Text)
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" broken,
      "These instructions decode but no longer encode, or encode to a word \
       that means something else.")

  [<TestMethod>]
  member _.``Branches to a label reach it in both directions``() =
    let wrong =
      [ for written, expected in branchSources do
          for source, index, distance in branchCases written ->
            expected, source, index, distance ]
      |> List.choose (fun (expected, source, index, distance) ->
        match (try assembler.Lower source with _ -> Error "raised") with
        | Error _ | Ok [] -> Some $"'{expected} L' does not assemble"
        | Ok encoded ->
          let addr = uint64 (4 * index)
          let text =
            try (parser.Parse(snd (List.item index encoded), addr)).Disasm()
            with _ -> "<undecodable>"
          if text = $"{expected} 0x{distance:x}" then None
          else Some $"'{expected} L' at 0x{addr:x} became '{text}'")
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These branches no longer reach the instruction their label marks.")

  /// <summary>
  /// Checks that a source asking for what no encoding can say is refused rather
  /// than encoded.
  ///
  /// A field that silently drops what does not fit encodes an instruction the
  /// source did not ask for, which is worse than encoding nothing at all.
  /// </summary>
  [<TestMethod>]
  member _.``A source no encoding can say does not encode``() =
    let encoded =
      unencodableSources
      |> List.choose (fun source ->
        match (try encodeFirst assembler source with _ -> None) with
        | None -> None
        | Some bytes ->
          let text = try disasm bytes with _ -> "<undecodable>"
          Some $"'{source}' encoded as '{text}'")
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" encoded,
      "These ask for something no SPARC encoding can say.")

  /// Checks that a word comes out in the order the ISA stores its bytes in,
  /// which is the one thing about an encoding that the word itself cannot say.
  [<TestMethod>]
  member _.``The bytes come out in the order the ISA stores them``() =
    let isa = ISA(Architecture.SPARC, Endian.Little, WordSize.Bit64)
    let littleEndian = Assembler(isa, 0UL) :> ILowerable
    let source = "add %g1, 0x1, %g2"
    let hex (bytes: byte[]) = Convert.ToHexString bytes
    match encodeFirst littleEndian source, encodeFirst assembler source with
    | Some little, Some big ->
      Assert.AreEqual<string>(hex (Array.rev big), hex little)
    | _ -> Assert.Fail $"'{source}' does not assemble"

  /// <summary>
  /// Checks that a source written the way a person writes one names the same
  /// instruction as the canonical text for it.
  ///
  /// What the disassembler writes is only part of what an assembler has to
  /// read: a source of its own writes a number below zero with a sign rather
  /// than as the bits it lands in, leaves out the spaces the disassembler puts
  /// around what an address is built from, and says in a comment what it is
  /// doing.
  /// </summary>
  [<TestMethod>]
  member _.``A source may be written the way a person writes one``() =
    let wrong =
      writtenSources
      |> List.choose (fun (source, expected) ->
        match (try encodeFirst assembler source with _ -> None) with
        | None -> Some $"'{source}' does not assemble"
        | Some bytes ->
          let text = try disasm bytes with _ -> "<undecodable>"
          if text = expected then None
          else Some $"'{source}' encoded as '{text}'")
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These are no longer read as the instruction they name.")

  /// Checks that a source the assembler refuses leaves it able to read the next
  /// one, which a parser keeping state across a failure would not.
  [<TestMethod>]
  member _.``A refused source leaves the assembler usable``() =
    for bad in unencodableSources do
      (try encodeFirst assembler bad |> ignore with _ -> ())
      match assembler.Lower "  nop\n  add %g1, 0x1, %g2" with
      | Ok [ _; _ ] -> ()
      | Ok _ | Error _ -> Assert.Fail $"'{bad}' left the assembler unusable"

// vim: set tw=80 sts=2 sw=2:
