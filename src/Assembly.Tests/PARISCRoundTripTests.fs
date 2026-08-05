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
open B2R2.FrontEnd.PARISC
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.PARISC

/// Represents what happened when a reference encoding was round-tripped.
type internal PARISCOutcome =
  /// The re-encoded word disassembles back to the text we started from.
  | PARISCPreserved
  /// The re-encoded word means something other than the text we started from.
  | PARISCAltered of actual: string
  /// The assembler cannot encode this instruction yet.
  | PARISCUnsupported

/// <summary>
/// Checks the PA-RISC assembler against B2R2's own PA-RISC decoder. For each
/// reference encoding we disassemble it into canonical PA-RISC syntax, hand
/// that text back to the assembler, and disassemble the result again.
/// Comparing the resulting *text* rather than the bytes means that picking a
/// valid-but-different encoding is not a failure, while emitting a word that
/// means something else is. PA-RISC writes several instructions under one
/// name and tells them apart by the operands that follow, so text is also the
/// only thing the two ends of this agree on.
///
/// Nothing here is a hand-written expectation, and nothing is a hand-written
/// input either: PARISCSweep walks the encoding space and the decoder says
/// what each word means, so the set of instructions under test is whatever the
/// decoder currently understands. Forms that canonical disassembly cannot
/// express - labels above all - are pinned by the hand-written tests below.
/// </summary>
[<TestClass>]
type PARISCRoundTripTests() =

  static let isa = ISA(Architecture.PARISC, Endian.Big, WordSize.Bit64)

  /// One parser, reused across the whole sweep. The sweep asks for millions of
  /// decodings, so building one each time would dominate the run.
  static let parser =
    PARISCParser(isa, BinReader.Init Endian.Big) :> IInstructionParsable

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
    | None ->
      PARISCUnsupported
    | Some encoded ->
      let actual = try disasm encoded with _ -> "<undecodable>"
      if actual = source then PARISCPreserved else PARISCAltered actual

  /// Describes a source that does not encode to a word meaning the same.
  static let brokenSource source =
    match roundTrip source with
    | PARISCPreserved -> None
    | PARISCAltered actual -> Some $"'{source}' encoded as '{actual}'"
    | PARISCUnsupported -> Some $"'{source}' is not encodable"

  /// Every probe the sweep produces. The sweep is the expensive part of this
  /// file, so it runs once for the class rather than once for each test that
  /// reads it.
  static let probes = lazy (PARISCSweep.probes ())

  /// The instruction that does nothing, written over and over, so that a label
  /// can be put out of reach of the instruction naming it. PA-RISC has no name
  /// of its own for doing nothing; a bitwise or into the register that is
  /// always zero is what stands in for one.
  let padding = String.replicate 200 "  or flags, flags, flags\n"

  /// <summary>
  /// The sources a branch to a label is tried in, each paired with the index of
  /// the instruction under test and how far away its label then is.
  ///
  /// A label is reached from below as well as from above, and from far enough
  /// away that an offset holding too few bits would not reach it.
  /// </summary>
  let branchCases source =
    [ $"L:\n  or flags, flags, flags\n  {source}\n  or flags, flags, flags",
        1, 0xFFFFFFFFFFFFFFFCUL
      $"  {source}\n{padding}L:\n  or flags, flags, flags", 0, 0x324UL
      $"L:\n{padding}  {source}\n  or flags, flags, flags", 200,
        0xFFFFFFFFFFFFFCE0UL ]

  /// Every instruction that names a place, paired with how the disassembler
  /// writes it once it has worked out how far away that place is, with the
  /// distance itself left standing as a mark.
  let branchSources =
    [ "b,l L, r5", "b,l @, r5"
      "b,l,n L, r5", "b,l,n @, r5"
      "b,gate L, r5", "b,gate @, r5"
      "cmpb,= r3, r5, L", "cmpb,= r3, r5, @"
      "cmpb,*<,n r3, r5, L", "cmpb,*<,n r3, r5, @"
      "cmpib,= 0x3, r5, L", "cmpib,= 0x3, r5, @"
      "cmpib,*<< 0x3, r5, L", "cmpib,*<< 0x3, r5, @"
      "addb,< r3, r5, L", "addb,< r3, r5, @"
      "addib,>= 0x3, r5, L", "addib,>= 0x3, r5, @"
      "movb,= r3, r5, L", "movb,= r3, r5, @"
      "movib,= 0x3, r5, L", "movib,= 0x3, r5, @"
      "bb,< r3, sar, L", "bb,< r3, sar, @"
      "bb,*>=,n r3, 0x5, L", "bb,*>=,n r3, 0x5, @" ]

  /// Sources that name no instruction at all, either because a number does not
  /// fit where it is written, or because a register cannot be named there, or
  /// because the words hung off the name say two different things.
  let unencodableSources =
    [ "addi 0x400, r5, r3"
      "ldb 0x2000(r5), r3"
      "ldd 0x24(r5), r3"
      "ldw,ma -0x101(r5), r3"
      "shladd r3, 0x0, r5, flags"
      "shladd r3, 0x4, r5, flags"
      "extrw,s r5, 0x0, 0x21, r3"
      "extrw,s r5, 0x20, 0x10, r3"
      "depd,z,* r3, sar, 0x41, r5"
      "break 0x20, 0x0"
      "diag 0x4000000"
      "ldil 0x1, r5"
      "b,l 0x3, r5"
      "b,l 0x1000000, r5"
      "cmpb,= r3, r5, 0x3000"
      "add,c,*= r3, r5, flags"
      "add,l,c r3, r5, flags"
      "ds,* r3, r5, flags"
      "hadd,xy r3, r5, flags"
      "mfctl,w rctr, r3"
      "mtsp r3, r5"
      "fmpyadd fr5, fpe6, fpsr, fpsr, fpsr"
      "fcnv,sgl,sgl fr5"
      "ssm 0x400, flags"
      "probe,x (r5), r3, flags"
      "bve,l (r5), r3"
      "be,l 0x100(r5), sr1, r31"
      "cldw,1 r3(r5), flags"
      "cldd,0 r3(r5), flags"
      "spop1,8,0 r3"
      "permh,3341 r5, flags"
      "popbts 0x0"
      "fadd,quad fr5R, fr6, fr7"
      "fmpyadd,sgl fr15, fr19, fr16, fr16, fr16"
      "bve,push (r5)"
      "bve,l,pop (r5), rp"
      "frobnicate r3, r5" ]

  /// Sources written the way a person writes one rather than the way the
  /// disassembler does, each paired with the instruction it names.
  let writtenSources =
    [ "  add r3, r5, flags  ; what a person writes", "add r3, r5, flags"
      "ADD R3, R5, FLAGS", "add r3, r5, flags"
      "addi -1, r5, r3", "addi 0xffffffffffffffff, r5, r3"
      "ldb 0(r5), r3", "ldb 0x0(r5), r3"
      "ldb 16(sr1,r5), r3", "ldb 0x10(sr1,r5), r3"
      "ldb 16 ( sr1 , r5 ), r3", "ldb 0x10(sr1,r5), r3"
      "ldw 100(sp), r3", "ldw 0x64(sp), r3"
      "ldw,ma -0x100(r5), r3", "ldw,ma 0xffffffffffffff00(r5), r3"
      "ldw,mb 0x100(r5), r3", "ldw,mb 0x100(r5), r3"
      "b,l 8, r5", "b,l 0x8, r5"
      "fadd,dbl fr5, fr6, fr7", "fadd,dbl fr5, fr6, fr7"
      "sync", "sync"
      "fadd,sgl fr5r, fpe7, fpsr", "fadd,sgl fr5R, fpe7, fpsr"
      "fldw r3(r5), fpe1", "fldw r3(r5), fpe1"
      "fmpyadd,sgl fr21, fr19, fr16, fr16, fr16",
        "fmpyadd,sgl fr21, fr19, fr16, fr16, fr16"
      "popbts 16", "popbts 0x10"
      "bve,pop (r5)", "bve,pop (r5)"
      "bve,l,push,n (r5), rp", "bve,l,push,n (r5), rp"
      "or flags, flags, flags", "or flags, flags, flags" ]

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
        | Error _ | Ok [] ->
          Some $"'{expected}' does not assemble"
        | Ok encoded ->
          let addr = uint64 (4 * index)
          let text =
            try (parser.Parse(snd (List.item index encoded), addr)).Disasm()
            with _ -> "<undecodable>"
          let wanted = expected.Replace("@", $"0x{distance:x}")
          if text = wanted then None
          else Some $"'{expected}' at 0x{addr:x} became '{text}'")
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
        | None ->
          None
        | Some bytes ->
          let text = try disasm bytes with _ -> "<undecodable>"
          Some $"'{source}' encoded as '{text}'")
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" encoded,
      "These ask for something no PA-RISC encoding can say.")

  /// Checks that a word comes out in the order the ISA stores its bytes in,
  /// which is the one thing about an encoding that the word itself cannot say.
  [<TestMethod>]
  member _.``The bytes come out in the order the ISA stores them``() =
    let isa = ISA(Architecture.PARISC, Endian.Little, WordSize.Bit64)
    let littleEndian = Assembler(isa, 0UL) :> ILowerable
    let source = "add r3, r5, flags"
    let hex (bytes: byte[]) = Convert.ToHexString bytes
    match encodeFirst littleEndian source, encodeFirst assembler source with
    | Some little, Some big ->
      Assert.AreEqual<string>(hex (Array.rev big), hex little)
    | _ ->
      Assert.Fail $"'{source}' does not assemble"

  /// <summary>
  /// Checks that a source written the way a person writes one names the same
  /// instruction as the canonical text for it.
  ///
  /// What the disassembler writes is only part of what an assembler has to
  /// read: a source of its own writes a number below zero with a sign rather
  /// than as the bits it lands in, writes it in the base a person counts in,
  /// puts spaces where the disassembler puts none, and says in a comment what
  /// it is doing.
  /// </summary>
  [<TestMethod>]
  member _.``A source may be written the way a person writes one``() =
    let wrong =
      writtenSources
      |> List.choose (fun (source, expected) ->
        match (try encodeFirst assembler source with _ -> None) with
        | None ->
          Some $"'{source}' does not assemble"
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
      match assembler.Lower "  sync\n  add r3, r5, flags" with
      | Ok [ _; _ ] -> ()
      | Ok _ | Error _ -> Assert.Fail $"'{bad}' left the assembler unusable"

// vim: set tw=80 sts=2 sw=2:
