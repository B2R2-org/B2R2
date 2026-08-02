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
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.SH4

/// Represents one instruction the decoder produced from a probe, paired with
/// the word it came from and the canonical text that gets handed back to the
/// assembler.
type internal SH4Probe =
  { /// Word the probe was decoded from.
    Word: uint16
    /// Canonical disassembly, which doubles as assembler input.
    Text: string }

/// <summary>
/// Sweeps the SH4 encoding space by handing every word there is to B2R2's own
/// decoder, so that the set of instructions the assembler has to encode is
/// derived from the decoder rather than listed by hand.
///
/// The rule this encodes is that anything the decoder decodes, the assembler
/// encodes. Every SH4 instruction is one sixteen-bit word, and there are only
/// sixty-five thousand of those, so nothing here has to choose which words are
/// worth trying: the sweep is linear and reaches all of them. Which registers
/// and which numbers an instruction names is therefore covered as thoroughly as
/// which instruction it is, and that is exactly where a mistake in an encoder
/// hides.
/// </summary>
module internal SH4Sweep =

  /// Every word there is, in the order the machine reads them.
  let private words =
    seq { for w in 0 .. 0xFFFF -> uint16 w }

  let private decode (parser: IInstructionParsable) (probe: uint16) =
    try
      let parsed = parser.Parse(BitConverter.GetBytes probe, 0UL)
      Some { Word = probe; Text = parsed.Disasm() }
    with _ ->
      None

  /// Every word the decoder makes an instruction of. The words arrive as a
  /// sequence rather than a list because most of them are nothing at all and
  /// only the ones kept are worth holding on to.
  let probes () =
    let parser = SH4Parser(BinReader.Init Endian.Little) :> IInstructionParsable
    words |> Seq.choose (decode parser) |> Seq.toList

// vim: set tw=80 sts=2 sw=2:
