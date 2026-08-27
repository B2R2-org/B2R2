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

open System.IO
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.Python
open B2R2.Assembly.BinLowerer

/// Represents what happened when a reference encoding was round-tripped.
type internal PythonOutcome =
  /// The re-encoded instruction disassembles back to the text we started from.
  | PythonPreserved
  /// The re-encoded instruction means something other than that text.
  | PythonAltered of actual: string
  /// The assembler cannot encode this instruction yet.
  | PythonUnsupported

/// <summary>
/// Checks the Python assembler against B2R2's own Python decoder. For each
/// reference encoding we disassemble it into canonical Python syntax, hand
/// that text back to the assembler, and disassemble the result again.
/// Comparing the resulting <i>text</i> rather than the bytes means that
/// picking a valid-but-different encoding is not a failure, while emitting an
/// instruction that means something else is.
///
/// Nothing here is a hand-written expectation, and nothing is a hand-written
/// input either: PythonSweep walks every byte there is, against every version
/// the front end reads, and the decoder says what each one means.
/// </summary>
[<TestClass>]
type PythonRoundTripTests() =

  static let assembler (ver: PythonVersion) =
    B2R2.Assembly.Python.Assembler(ISA ver, 0UL) :> ILowerable

  static let assemblers =
    System.Collections.Concurrent.ConcurrentDictionary<PythonVersion,
                                                       ILowerable>()

  /// One directory for every file this class writes, cleaned up at the end.
  static let dir =
    let d = Path.Combine(Path.GetTempPath(),
                         $"b2r2-pyrt-{Path.GetRandomFileName()}")
    Directory.CreateDirectory d |> ignore
    d

  static let encodeFirst ver text =
    let asm = assemblers.GetOrAdd(ver, assembler)
    match (try asm.Lower text with _ -> Result.Error "threw") with
    | Ok((_, bytes) :: _) -> Some bytes
    | Ok [] | Result.Error _ -> None

  /// Disassembles a block of bytes as the given version, taking the first
  /// instruction in it. The block goes into a file of its own because a
  /// Python argument indexes a table only a code object carries.
  static let disasmFirst (ver: PythonVersion) (bytes: byte[]) =
    let path = Path.Combine(dir, $"{int ver}-{bytes.Length}.pyc")
    let code = Array.append bytes (Array.zeroCreate 64)
    let pyc = Builder.build ver (Builder.magicOf ver) (Builder.codeOf code)
    File.WriteAllBytes(path, pyc)
    let hdl = BinHandle.LoadFile path
    let unit = hdl.NewLiftingUnit()
    match (hdl.File :?> PythonBinFile).CodeObj with
    | PyCode co ->
      let ins = unit.ParseInstruction(fst co.Code)
      Some(ins.Disasm(), int ins.Length)
    | _ ->
      None

  /// <summary>
  /// Encodes the given source and disassembles the result.
  ///
  /// The bytes are compared against what the decoder makes of *them*, not
  /// against the probe they came from. A probe can carry an EXTENDED_ARG the
  /// argument does not need -- every byte is tried as the start of an
  /// instruction, and the prefix byte is one of them, so its probe is the
  /// instruction after it with three bytes of prefix folded in. Writing that
  /// instruction without the prefix is the right answer and a shorter one, so
  /// holding the assembler to the probe's width would fail it for being
  /// correct. What may not differ is the meaning, and that is the text.
  /// </summary>
  static let roundTrip ver (source: string) =
    match encodeFirst ver source with
    | None ->
      PythonUnsupported
    | Some encoded ->
      match (try disasmFirst ver encoded with _ -> None) with
      | Some(actual, length) when actual = source ->
        (* The decoder must read exactly what was written, no more and no
           less: too few inline caches leaves bytes behind that the next
           instruction would start in the middle of. *)
        if length = encoded.Length then PythonPreserved
        else PythonAltered $"{length} of {encoded.Length} bytes"
      | Some(actual, _) ->
        PythonAltered actual
      | None ->
        PythonUnsupported

  static let brokenProbe (probe: PythonProbe) =
    let where = $"{probe.Version}"
    let source = probe.Text
    match roundTrip probe.Version source with
    | PythonPreserved -> None
    | PythonAltered actual -> Some $"{where} '{source}' encoded as '{actual}'"
    | PythonUnsupported -> Some $"{where} '{source}' is not encodable"

  /// Every probe the sweep produces, run once for the class rather than once
  /// for each test that reads it.
  static let probes = lazy (PythonSweep.probes ())

  /// <summary>
  /// The arguments every instruction that takes one is tried holding.
  ///
  /// A sweep over the encoding space reaches each instruction once, with
  /// whatever argument its bytes happened to carry, so on its own it says
  /// nothing about the widths. These are the values either side of every
  /// boundary where an argument stops fitting and gains an EXTENDED_ARG: one
  /// prefix from 256, two from 65536.
  /// </summary>
  static let widths = [ 0; 1; 255; 256; 65535; 65536 ]

  /// Tables have to reach the widest argument tried, or the parse fails on
  /// the lookup rather than on anything the assembler did.
  static let width = 65537

  /// How far apart the variants are laid out: wider than the longest
  /// instruction there is, two prefixes and eighteen cache bytes included.
  static let stride = 64

  /// A line reduced to what the two sides must agree on: the mnemonic, and
  /// the argument's own value rather than merely its presence. An argument
  /// written without the EXTENDED_ARG prefixes it needs still reads back as
  /// the same mnemonic with an argument still there, so a check that stops at
  /// "has one" says nothing about the widths it was written to test.
  static let split (text: string) =
    let sep = [| ' '; '\t' |]
    match text.Split(sep, System.StringSplitOptions.RemoveEmptyEntries) with
    | [||] ->
      None
    | parts ->
      let arg =
        if parts.Length > 1 then
          match System.Int32.TryParse parts[1] with
          | true, n -> Some n
          | _ -> None
        else
          None
      Some(parts[0], arg)

  /// What one encoded instruction, read back from where it was laid down, has
  /// to say for itself: nothing at all where it round-tripped, and otherwise
  /// how it failed to. It would not encode, it would not decode, it came back
  /// a different length than was written, or it came back reading differently.
  static let roundTripFailure (unit: LiftingUnit)
                             version
                             (at: Addr)
                             (source, bytes) =
    match bytes with
    | None ->
      Some $"{version} '{source}' is not encodable"
    | Some(bs: byte[]) ->
      let read =
        try
          let ins = unit.ParseInstruction at
          Some(ins.Disasm(), int ins.Length)
        with _ ->
          None
      match read with
      | None ->
        Some $"{version} '{source}' did not decode"
      | Some(text, len) ->
        if len <> bs.Length then
          Some $"{version} '{source}' wrote {bs.Length}, read {len}"
        elif split text <> split source then
          Some $"{version} '{source}' read back as '{text}'"
        else
          None

  /// <summary>
  /// Every instruction that takes an argument, tried holding each width, for
  /// one version.
  ///
  /// All of them go into one file rather than one file each: the round trip
  /// needs the bytes read back through a code object, and writing a table
  /// wide enough for the widest argument once per instruction would cost more
  /// than the test is worth.
  /// </summary>
  static let widthFailures version (probes: PythonProbe list) =
    let sources =
      [ for p in probes do
          match split p.Text with
          | Some(mnemonic, Some _) -> for w in widths -> $"{mnemonic} {w}"
          | _ -> () ]
      |> List.distinct
    let encoded = sources |> List.map (fun s -> s, encodeFirst version s)
    let laid =
      [| for _, bytes in encoded do
           match bytes with
           | Some bs ->
             yield! bs
             yield! Array.zeroCreate (stride - bs.Length)
           | None ->
             yield! Array.zeroCreate stride |]
    let path = Path.Combine(dir, $"widths-{int version}.pyc")
    let pyc = Builder.build version
                            (Builder.magicOf version)
                            (Builder.codeWith width laid)
    File.WriteAllBytes(path, pyc)
    let hdl = BinHandle.LoadFile path
    let unit = hdl.NewLiftingUnit()
    match (hdl.File :?> PythonBinFile).CodeObj with
    | PyCode co ->
      encoded
      |> List.indexed
      |> List.choose (fun (i, entry) ->
        let at = fst co.Code + uint64 (i * stride)
        roundTripFailure unit version at entry)
    | _ ->
      [ $"{version} produced no code object" ]

  /// <summary>
  /// Every test below it says that nothing among the instructions it found is
  /// broken, which a sweep finding nothing at all would also say. Sixteen
  /// versions of roughly a hundred and fifty instructions each comes to a
  /// couple of thousand.
  /// </summary>
  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``The sweep reaches the whole of the encoding space``() =
    Assert.IsGreaterThan(1500, List.length (probes.Force()))

  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``Every version the front end reads is swept``() =
    let seen = probes.Force() |> List.map (fun p -> p.Version) |> List.distinct
    Assert.AreEqual<int>(List.length PythonSweep.versions, List.length seen)

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
      $"{List.length broken} instruction(s) the assembler gets wrong"
    )

  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``Every argument width the encoding allows round-trips``() =
    let byVersion = probes.Force() |> List.groupBy (fun p -> p.Version)
    let broken =
      byVersion
      |> List.collect (fun (version, ps) -> widthFailures version ps)
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" broken,
      $"{List.length broken} argument(s) the assembler gets wrong"
    )

  [<TestMethod>]
  member _.``A name no version knows is refused rather than encoded``() =
    match (assembler PythonVersion.Python312).Lower "no_such_instruction 1" with
    | Result.Error _ -> ()
    | Ok _ -> Assert.Fail "an unknown mnemonic was encoded"

  [<TestMethod>]
  member _.``An argument on an instruction that takes none is refused``() =
    match (assembler PythonVersion.Python312).Lower "nop 3" with
    | Result.Error _ -> ()
    | Ok _ -> Assert.Fail "a spurious argument was accepted"

  [<TestMethod>]
  member _.``An instruction needing an argument is not encoded without one``() =
    match (assembler PythonVersion.Python312).Lower "load_const" with
    | Result.Error _ -> ()
    | Ok _ -> Assert.Fail "a missing argument was accepted"

// vim: set tw=80 sts=2 sw=2:
