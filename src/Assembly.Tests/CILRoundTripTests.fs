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
open B2R2.FrontEnd.CIL
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.CIL

/// Represents what happened when a reference encoding was round-tripped.
type internal CILOutcome =
  /// The re-encoded instruction disassembles back to the text we started from.
  | CILPreserved
  /// The re-encoded instruction means something other than that text.
  | CILAltered of actual: string
  /// The assembler cannot encode this instruction yet.
  | CILUnsupported

/// <summary>
/// Checks the CIL assembler against B2R2's own CIL decoder. For each reference
/// encoding we disassemble it into canonical syntax, hand that text back to
/// the assembler, and disassemble the result again. The text is what is
/// compared, as in the other sweeps; here it settles the bytes as well, since
/// every CIL operand has one width and one way of being written, and so the
/// width of what comes back is checked against the probe too.
///
/// The assembler derives its table from the decoder, so what the sweep says
/// about which bytes name an instruction, it says of one table twice. The
/// instructions written out by hand below are the independent word on that:
/// every one of them is an encoding read off ECMA-335 Partition III.
/// </summary>
[<TestClass>]
type CILRoundTripTests() =

  static let isa = ISA Architecture.CIL

  /// One parser, reused across the whole sweep.
  static let parser =
    CILParser(BinReader.Init Endian.Little) :> IInstructionParsable

  static let assembler = Assembler(isa, 0UL) :> ILowerable

  static let disasm (bytes: byte[]) = (parser.Parse(bytes, 0UL)).Disasm()

  static let encodeFirst (assembler: ILowerable) text =
    match assembler.Lower text with
    | Ok((_, bytes) :: _) -> Some bytes
    | Ok [] | Error _ -> None

  /// Encodes the given source and disassembles the result, so that a source
  /// text stands in for the bytes a probe was decoded from.
  static let roundTrip (source: string) =
    match (try encodeFirst assembler source with _ -> None) with
    | None ->
      CILUnsupported
    | Some encoded ->
      let actual = try disasm encoded with _ -> "<undecodable>"
      if actual = source then CILPreserved else CILAltered actual

  /// <summary>
  /// Describes a probe whose text does not encode to an instruction meaning
  /// the same, naming the bytes it was decoded from so that a failure says
  /// where to look.
  ///
  /// How wide the instruction came out is checked as well as what it means,
  /// because an instruction of the wrong width leaves everything after it in a
  /// source at the wrong address, and the text of that one instruction says
  /// nothing about it.
  /// </summary>
  static let brokenProbe (probe: CILProbe) =
    let source = probe.Text
    let where = Convert.ToHexString probe.Bytes
    match (try encodeFirst assembler source with _ -> None) with
    | None ->
      Some $"{where} '{source}' is not encodable"
    | Some encoded when encoded.Length <> probe.Length ->
      Some $"{where} '{source}' encoded {encoded.Length} bytes wide"
    | Some _ ->
      match roundTrip source with
      | CILPreserved -> None
      | CILAltered actual -> Some $"{where} '{source}' encoded as '{actual}'"
      | CILUnsupported -> Some $"{where} '{source}' is not encodable"

  /// Every probe the sweep produces, run once for the class rather than once
  /// for each test that reads it.
  static let probes = lazy (CILSweep.probes ())

  /// Names every source among the given ones that does not come out as the
  /// bytes written beside it, with the given assembler.
  static let wrongBytes (assembler: ILowerable) cases =
    cases
    |> List.choose (fun (source, hex) ->
      match (try encodeFirst assembler source with _ -> None) with
      | None -> Some $"'{source}' does not assemble"
      | Some bytes when Convert.ToHexString bytes = hex -> None
      | Some bytes -> Some $"'{source}' came out {Convert.ToHexString bytes}")
    |> List.sort
    |> String.concat "\n"

  /// <summary>
  /// Instructions written out from the specification rather than read back
  /// from the decoder, each paired with the bytes the specification gives it.
  ///
  /// This is the one test here the decoder has no hand in. Everything else
  /// derives what it expects from the decoder, and so would go on passing if
  /// the decoder itself came to read a byte as the wrong instruction; these
  /// would not. A branch is written by the address it reaches, and the
  /// assembler is placed at zero, so a branch to the instruction after itself
  /// is a distance of nothing.
  /// </summary>
  let specifiedEncodings =
    [ "nop", "00"
      "break", "01"
      "ldarg.0", "02"
      "ldloc.3", "09"
      "stloc.0", "0A"
      "ldarg.s 4", "0E04"
      "ldarga.s 4", "0F04"
      "starg.s 4", "1004"
      "ldloc.s 4", "1104"
      "ldloca.s 4", "1204"
      "stloc.s 4", "1304"
      "ldnull", "14"
      "ldc.i4.m1", "15"
      "ldc.i4.0", "16"
      "ldc.i4.8", "1E"
      "ldc.i4.s -1", "1FFF"
      "ldc.i4 1", "2001000000"
      "ldc.i8 1", "210100000000000000"
      "ldc.r4 1", "220000803F"
      "ldc.r8 1", "23000000000000F03F"
      "dup", "25"
      "pop", "26"
      "jmp 0x06000001", "2701000006"
      "call 0x0a000001", "280100000A"
      "calli 0x11000001", "2901000011"
      "ret", "2A"
      "br.s 0x2", "2B00"
      "brfalse.s 0x2", "2C00"
      "brtrue.s 0x2", "2D00"
      "beq.s 0x2", "2E00"
      "bge.s 0x2", "2F00"
      "bgt.s 0x2", "3000"
      "ble.s 0x2", "3100"
      "blt.s 0x2", "3200"
      "bne.un.s 0x2", "3300"
      "bge.un.s 0x2", "3400"
      "bgt.un.s 0x2", "3500"
      "ble.un.s 0x2", "3600"
      "blt.un.s 0x2", "3700"
      "br 0x5", "3800000000"
      "brfalse 0x5", "3900000000"
      "brtrue 0x5", "3A00000000"
      "beq 0x5", "3B00000000"
      "blt.un 0x5", "4400000000"
      "switch ()", "4500000000"
      "switch (0x9)", "450100000000000000"
      "ldind.i1", "46"
      "ldind.ref", "50"
      "stind.ref", "51"
      "stind.r8", "57"
      "add", "58"
      "shr.un", "64"
      "conv.i1", "67"
      "conv.u8", "6E"
      "callvirt 0x0a000001", "6F0100000A"
      "cpobj 0x02000001", "7001000002"
      "ldobj 0x02000001", "7101000002"
      "ldstr 0x70000001", "7201000070"
      "newobj 0x06000001", "7301000006"
      "castclass 0x02000001", "7401000002"
      "isinst 0x02000001", "7501000002"
      "conv.r.un", "76"
      "unbox 0x02000001", "7901000002"
      "throw", "7A"
      "ldfld 0x04000001", "7B01000004"
      "stsfld 0x04000001", "8001000004"
      "stobj 0x02000001", "8101000002"
      "conv.ovf.i1.un", "82"
      "conv.ovf.u.un", "8B"
      "box 0x02000001", "8C01000002"
      "newarr 0x02000001", "8D01000002"
      "ldlen", "8E"
      "ldelema 0x02000001", "8F01000002"
      "ldelem.i1", "90"
      "stelem.ref", "A2"
      "ldelem 0x02000001", "A301000002"
      "stelem 0x02000001", "A401000002"
      "unbox.any 0x02000001", "A501000002"
      "conv.ovf.i1", "B3"
      "conv.ovf.u8", "BA"
      "refanyval 0x02000001", "C201000002"
      "ckfinite", "C3"
      "mkrefany 0x02000001", "C601000002"
      "ldtoken 0x02000001", "D001000002"
      "conv.u2", "D1"
      "conv.ovf.u", "D5"
      "add.ovf", "D6"
      "sub.ovf.un", "DB"
      "endfinally", "DC"
      "leave 0x5", "DD00000000"
      "leave.s 0x2", "DE00"
      "stind.i", "DF"
      "conv.u", "E0"
      "arglist", "FE00"
      "ceq", "FE01"
      "clt.un", "FE05"
      "ldftn 0x06000001", "FE0601000006"
      "ldvirtftn 0x06000001", "FE0701000006"
      "ldarg 4", "FE090400"
      "ldarga 4", "FE0A0400"
      "starg 4", "FE0B0400"
      "ldloc 4", "FE0C0400"
      "ldloca 4", "FE0D0400"
      "stloc 4", "FE0E0400"
      "localloc", "FE0F"
      "endfilter", "FE11"
      "unaligned. 4", "FE1204"
      "volatile.", "FE13"
      "tail.", "FE14"
      "initobj 0x02000001", "FE1501000002"
      "constrained. 0x02000001", "FE1601000002"
      "cpblk", "FE17"
      "initblk", "FE18"
      "no. 1", "FE1901"
      "rethrow", "FE1A"
      "sizeof 0x02000001", "FE1C01000002"
      "refanytype", "FE1D"
      "readonly.", "FE1E" ]

  /// Sources that name no instruction at all, either because a number does not
  /// fit where it is written, because a branch reaches further than its width
  /// allows, because the instruction takes something other than what was
  /// written, or because nothing of that name exists. A number that fits the
  /// width as the bits it lands in is not among them: 255 written for a byte
  /// is the byte it names, however the disassembler would have written it.
  let unencodableSources =
    [ "ldarg.s 256"
      "ldarg.s -1"
      "ldarg 65536"
      "ldc.i4.s -129"
      "ldc.i4.s 0x100"
      "ldc.i4 4294967296"
      "ldc.i4 -2147483649"
      "ldc.i4"
      "ldc.i4 1 2"
      "ldc.r4 abc"
      "br.s"
      "br.s 0x100"
      "br.s 0xffffffffffffff00"
      "br 0x80000005"
      "switch (0x80000009)"
      "switch x"
      "call 0x100000000"
      "call -1"
      "unaligned. 256"
      "no."
      "nop 1"
      "ret 0"
      "frobnicate"
      "ldc.i4.9" ]

  /// <summary>
  /// Sources written the way a person writes one rather than the way the
  /// disassembler does, each paired with the instruction it names.
  ///
  /// What the disassembler writes is only part of what an assembler has to
  /// read: a source of its own writes a number in whichever base suits what it
  /// means, spells the values a decimal point cannot the way ilasm does, uses
  /// the second name ECMA-335 gives a few instructions, and says in a comment
  /// what it is doing.
  /// </summary>
  let writtenSources =
    [ "  nop  // what a person writes", "nop"
      "  nop  ; and what B2R2 writes", "nop"
      "LDC.I4.S 5", "ldc.i4.s 5"
      "0000000000000010: nop", "nop"
      "ldc.i4 0x2a", "ldc.i4 42"
      "ldc.i4 0b1010", "ldc.i4 10"
      "ldc.i4 0o17", "ldc.i4 15"
      "ldc.i4 +1", "ldc.i4 1"
      "ldc.i4 0xffffffff", "ldc.i4 -1"
      "ldc.i4.s 0xff", "ldc.i4.s -1"
      "ldc.i8 0xffffffffffffffff", "ldc.i8 -1"
      "ldc.r4 inf", "ldc.r4 Infinity"
      "ldc.r4 -inf", "ldc.r4 -Infinity"
      "ldc.r8 nan", "ldc.r8 NaN"
      "ldc.r8 1e10", "ldc.r8 10000000000"
      "br.s 7", "br.s 0x7"
      "Call 0x0A000001", "call 0x0a000001"
      "switch 0xd 0xd", "switch (0xd, 0xd)"
      "switch (0xd,0xd)", "switch (0xd, 0xd)"
      "endfault", "endfinally"
      "brnull.s 0x2", "brfalse.s 0x2"
      "brzero 0x5", "brfalse 0x5"
      "brinst 0x5", "brtrue 0x5"
      "ldelem.any 0x02000001", "ldelem 0x02000001"
      "stelem.any 0x02000001", "stelem 0x02000001" ]

  /// <summary>
  /// Checks that the sweep reaches the whole of the encoding space.
  ///
  /// Every test below it says that nothing among the instructions it found is
  /// broken, which a sweep finding nothing at all would also say. There are
  /// over two hundred instructions, each padded out three ways, so a sweep
  /// reaching what it should reaches a good many more probes than this.
  /// </summary>
  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``The sweep reaches the whole of the encoding space``() =
    Assert.IsGreaterThan(500, List.length (probes.Force()))

  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``Every instruction the decoder decodes, the assembler encodes``() =
    let broken =
      probes.Force()
      |> List.choose brokenProbe
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" broken,
      "These instructions decode but no longer encode, or encode to an \
       instruction that means something else."
    )

  /// <summary>
  /// Checks the instructions whose encoding is written out from the
  /// specification, which is the one word here the decoder has no hand in.
  /// </summary>
  [<TestMethod>]
  member _.``The bytes come out the way the specification says``() =
    Assert.AreEqual<string>(
      "",
      wrongBytes assembler specifiedEncodings,
      "These no longer come out the way the specification says."
    )

  /// <summary>
  /// Checks that a source asking for what no encoding can say is refused
  /// rather than encoded.
  ///
  /// An instruction that silently drops what does not fit encodes something
  /// the source did not ask for, which is worse than encoding nothing at all.
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
      "These ask for something no CIL encoding can say."
    )

  /// <summary>
  /// Checks that a source written the way a person writes one names the same
  /// instruction as the canonical text for it.
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
      "These are no longer read as the instruction they name."
    )

  /// <summary>
  /// Checks that a branch is encoded as the distance from the instruction
  /// after it, measured from where the assembler was told it is.
  ///
  /// A branch is written by the address it reaches, so the same text encodes
  /// to different bytes at different addresses, and a switch is measured from
  /// after the whole of its table rather than from each entry.
  /// </summary>
  [<TestMethod>]
  member _.``A branch is measured from the instruction after it``() =
    let placed = Assembler(isa, 0x1000UL) :> ILowerable
    Assert.AreEqual<string>(
      "",
      wrongBytes placed
        [ "br.s 0x1008", "2B06"
          "br.s 0x1000", "2BFE"
          "br 0x1000", "38FBFFFFFF"
          "beq.s 0x1002", "2E00"
          "leave 0x1105", "DD00010000"
          "switch (0x1000)", "4501000000F7FFFFFF"
          "switch (0x100d, 0x100d)", "45020000000000000000000000" ],
      "These branches are no longer measured from where they should be."
    )

  /// <summary>
  /// Checks that a source is read one line at a time, each line placed behind
  /// the last, so that a branch on a later line is measured from where the
  /// lines before it put it.
  /// </summary>
  [<TestMethod>]
  member _.``A source is read one line at a time``() =
    let placed = Assembler(isa, 0x1000UL) :> ILowerable
    let source = "  nop\n  br.s 0x1000\n\n  ldc.i4.s 1\n  br 0x1004\n  ret"
    match placed.Lower source with
    | Ok encoded ->
      let bytes = encoded |> List.map snd |> Array.concat
      Assert.AreEqual<int>(5, List.length encoded)
      Assert.AreEqual<string>("002BFD1F0138FAFFFFFF2A",
                              Convert.ToHexString bytes)
    | Error err ->
      Assert.Fail $"a source of several lines no longer assembles: {err}"

  /// Checks that a source the assembler refuses leaves it able to read the
  /// next one, which a parser keeping state across a failure would not.
  [<TestMethod>]
  member _.``A refused source leaves the assembler usable``() =
    for bad in unencodableSources do
      (try encodeFirst assembler bad |> ignore with _ -> ())
      match assembler.Lower "  nop\n  ldc.i4.s 1" with
      | Ok [ _; _ ] -> ()
      | Ok _ | Error _ -> Assert.Fail $"'{bad}' left the assembler unusable"

// vim: set tw=80 sts=2 sw=2:
