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
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.Python

/// Represents one instruction the decoder produced from a probe, paired with
/// the bytes it came from and the canonical text that gets handed back to the
/// assembler.
type internal PythonProbe =
  { /// The version whose encoding space the bytes came from.
    Version: PythonVersion
    /// The bytes the decoder made this instruction of.
    Bytes: byte[]
    /// How many of them it read.
    Length: int
    /// Canonical disassembly, which doubles as assembler input.
    Text: string }

/// <summary>
/// Sweeps the Python encoding space by handing every byte there is to B2R2's
/// own decoder, so that the set of instructions the assembler has to encode is
/// derived from the decoder rather than listed by hand.
///
/// It is not one space but sixteen. The same byte is a different instruction
/// on either side of a release, an instruction was one byte or three before
/// 3.6 and is two from 3.6 on, and from 3.11 a number of two-byte inline
/// caches follows it that is a property of the opcode and of the version both.
/// So every byte is tried against every version rather than once.
///
/// Handing bytes to the decoder needs a file around them, which for Python is
/// not a formality: an argument indexes a table the code object carries, and
/// there is nowhere else to read a name from. Each version therefore gets a
/// synthesised <c>.pyc</c> holding the probe bytes and tables wide enough for
/// any argument tried here to land in.
/// </summary>
module internal PythonSweep =

  /// The bytes a probe is padded out with. Not zero and not all alike, so that
  /// an argument that went missing, or came out the wrong way round, shows up
  /// as text that changed rather than as text that happened to agree. Enough
  /// of them for the widest instruction there is, caches included.
  let private filler = Array.init 64 (fun i -> byte (0x11 + i % 0xEF))

  /// Every version the front end reads.
  let versions = [ for v in 0 .. 15 -> enum<PythonVersion> (300 + v) ]

  /// Loads a file holding the given bytecode and returns the lifting unit
  /// alongside where the code sits, so a probe can be parsed at an address.
  let private load (dir: string) version (code: byte[]) =
    let path = Path.Combine(dir, $"{int version}.pyc")
    let pyc = Builder.build version
                            (Builder.magicOf version)
                            (Builder.codeOf code)
    File.WriteAllBytes(path, pyc)
    let hdl = BinHandle.LoadFile path
    let unit = hdl.NewLiftingUnit()
    match (hdl.File :?> PythonBinFile).CodeObj with
    | PyCode co -> Some(unit, fst co.Code)
    | _ -> None

  /// Decodes one probe: the bytes at the given index of the block, as the
  /// decoder reads them.
  let private decode (unit: LiftingUnit) baseAddr (bytes: byte[]) index =
    try
      let ins = unit.ParseInstruction(baseAddr + uint64 index)
      let length = int ins.Length
      if length <= 0 || index + length > bytes.Length then
        None
      else
        Some { Version = enum<PythonVersion> 0
               Bytes = bytes[index..index + length - 1]
               Length = length
               Text = ins.Disasm() }
    with _ ->
      None

  /// <summary>
  /// Every byte there is, tried as the start of an instruction, for one
  /// version.
  ///
  /// Each opcode is laid out with its own filler rather than all of them in
  /// one block, so that an instruction reading past its own length reads the
  /// filler and not the next opcode -- which would make a wrong length look
  /// like a right one.
  /// </summary>
  let private probesOf dir version =
    let stride = filler.Length + 1
    let code =
      [| for b in 0 .. 0xFF do
           yield byte b
           yield! filler |]
    match load dir version code with
    | None ->
      []
    | Some(unit, baseAddr) ->
      [ for b in 0 .. 0xFF do
          match decode unit baseAddr code (b * stride) with
          | Some probe -> yield { probe with Version = version }
          | None -> () ]

  /// Every instruction every version decodes.
  let probes () =
    let name = $"b2r2-pysweep-{Path.GetRandomFileName()}"
    let dir = Path.Combine(Path.GetTempPath(), name)
    Directory.CreateDirectory dir |> ignore
    try versions |> List.collect (probesOf dir)
    finally try Directory.Delete(dir, true) with _ -> ()

// vim: set tw=80 sts=2 sw=2:
