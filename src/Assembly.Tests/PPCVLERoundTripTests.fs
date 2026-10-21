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
open B2R2.FrontEnd.PPC
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.PPC

/// <summary>
/// Checks the PPC assembler's encoding of Variable Length Encoding against
/// B2R2's own decoder of it, the way the base encoding is checked: each
/// instruction the decoder reads is disassembled into canonical syntax, the
/// text is handed back to the assembler, and the result is disassembled again.
/// An instruction of the second encoding is also required to come back as long
/// as it started, because a different length is a different instruction
/// stream rather than another spelling of the same one.
/// </summary>
[<TestClass>]
type PPCVLERoundTripTests() =

  static let isa32 =
    ISA(Architecture.PPC, Endian.Big, WordSize.Bit32, int Category.VLE)

  static let isa64 =
    ISA(Architecture.PPC, Endian.Big, WordSize.Bit64, int Category.VLE)

  static let parser32 =
    Parser(WordSize.Bit32, Category.VLE, BinReader.Init Endian.Big)
    :> IInstructionParsable

  static let parser64 =
    Parser(WordSize.Bit64, Category.VLE, BinReader.Init Endian.Big)
    :> IInstructionParsable

  static let assembler32 = Assembler(isa32, 0UL) :> ILowerable

  static let assembler64 = Assembler(isa64, 0UL) :> ILowerable

  static let disasm (parser: IInstructionParsable) (bytes: byte[]) =
    (parser.Parse(bytes, 0UL)).Disasm()

  static let disasm' (parser: IInstructionParsable) (bytes: byte[]) addr =
    (parser.Parse(bytes, addr)).Disasm()

  static let encodeFirst (assembler: ILowerable) text =
    match assembler.Lower text with
    | Ok((_, bytes) :: _) -> Some bytes
    | Ok [] | Error _ -> None

  /// Describes a probe whose text does not assemble back to an instruction of
  /// the same text and the same length.
  static let brokenProbe assembler parser (probe: PPCVLEProbe) =
    match (try encodeFirst assembler probe.Text with _ -> None) with
    | None ->
      Some $"'{probe.Text}' is not encodable"
    | Some encoded when encoded.Length <> probe.Bytes.Length ->
      Some $"'{probe.Text}' encoded as {encoded.Length} bytes"
    | Some encoded ->
      let actual = try disasm parser encoded with _ -> "<undecodable>"
      if actual = probe.Text then None
      else Some $"'{probe.Text}' encoded as '{actual}'"

  /// Every probe the sweep produces at either word size, once for the class
  /// because it is the expensive part of this file.
  static let probes32 = lazy (PPCVLESweep.probes WordSize.Bit32)

  static let probes64 = lazy (PPCVLESweep.probes WordSize.Bit64)

  /// Sources that name no instruction of the second encoding, because a number
  /// does not fit where it is written or a register cannot be named there.
  let unencodableSources = [ "se_blr r3"; "se_isync 0x1" ]

  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``Every VLE instruction the decoder decodes encodes``() =
    let broken =
      probes32.Force()
      |> List.choose (brokenProbe assembler32 parser32)
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" broken,
      "These VLE instructions decode but no longer encode, or encode to a word \
       that means something else."
    )

  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``Every VLE instruction encodes where the source is 64-bit``() =
    let broken =
      probes64.Force()
      |> List.choose (brokenProbe assembler64 parser64)
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" broken,
      "These VLE instructions no longer encode where the source is 64-bit."
    )

  /// An instruction takes two bytes or four and is stored big-endian, and the
  /// ones of the two encodings can follow one another.
  [<TestMethod>]
  member _.``A source mixes instructions of two bytes and of four``() =
    match assembler32.Lower "  se_blr\n  nop\n  se_isync" with
    | Ok encoded ->
      let hex = encoded |> List.map (snd >> Convert.ToHexString)
      Assert.AreEqual<string list>([ "0004"; "60000000"; "0001" ], hex)
    | Error e ->
      Assert.Fail e

  /// A source that asks for what no encoding can say is refused rather than
  /// encoded, which is worse than encoding nothing at all.
  [<TestMethod>]
  member _.``A VLE source no encoding can say does not encode``() =
    let encoded =
      unencodableSources
      |> List.choose (fun source ->
        match (try encodeFirst assembler32 source with _ -> None) with
        | None -> None
        | Some bytes -> Some $"'{source}' encoded as '{disasm parser32 bytes}'")
    Assert.AreEqual<string>("", String.concat "\n" encoded)

  /// The instructions of the second encoding are no instructions of the base
  /// one: a source that is not written in it does not encode them.
  [<TestMethod>]
  member _.``A VLE instruction does not encode where the source is not VLE``() =
    let base32 = ISA(Architecture.PPC, Endian.Big, WordSize.Bit32)
    let assembler = Assembler(base32, 0UL) :> ILowerable
    let encodes source =
      (try encodeFirst assembler source with _ -> None).IsSome
    Assert.AreEqual<bool>(false, encodes "se_blr")
    Assert.AreEqual<bool>(true, encodes "nop")

  /// <summary>
  /// A branch to a label reaches it whichever way it lies, counting the
  /// distance in bytes whatever mix of two-byte and four-byte instructions lies
  /// between: the label is above the branch in one source and below it in the
  /// other, with a halfword and a word between.
  /// </summary>
  [<TestMethod>]
  member _.``A VLE branch to a label reaches it in both directions``() =
    let branches =
      [ "se_b L", "se_b"
        "se_bl L", "se_bl"
        "se_bc 0x1, 0x4 * cr0 + eq, L", "se_bc 0x1, 0x4 * cr0 + eq," ]
    let wrong =
      [ for written, expected in branches do
          yield expected, $"L:
  nop
  se_isync
  {written}", 2, 6UL, 0UL
          let above = $"  {written}
  nop
  se_isync
L:
  nop"
          yield expected, above, 0, 0UL, 8UL ]
      |> List.choose (fun (expected, source, index, addr, target) ->
        match (try assembler32.Lower source with _ -> Error "raised") with
        | Error _ | Ok [] ->
          Some $"'{expected} L' does not assemble"
        | Ok encoded ->
          let bytes = snd (List.item index encoded)
          let text = try disasm' parser32 bytes addr with _ -> "<undecodable>"
          if text = $"{expected} 0x{target:x}" then None
          else Some $"'{expected} L' at 0x{addr:x} became '{text}'")
    Assert.AreEqual<string>("", String.concat "
" wrong)

  /// A 16-bit branch counts its distance in eight bits of halfwords, so a label
  /// farther than that is out of its reach and the source is refused.
  [<TestMethod>]
  member _.``A VLE branch to a label out of reach does not encode``() =
    let padding = String.replicate 200 "  se_isync
"
    let source = $"  se_b L
{padding}L:
  nop"
    let encoded = try encodeFirst assembler32 source with _ -> None
    Assert.AreEqual<bool>(false, encoded.IsSome)

// vim: set tw=80 sts=2 sw=2:
