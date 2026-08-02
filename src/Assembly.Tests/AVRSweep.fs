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
open B2R2.FrontEnd.AVR

/// Represents one instruction the decoder produced from a probe, paired with
/// the words it came from and the canonical text that gets handed back to the
/// assembler.
type internal AVRProbe =
  { /// First word the probe was decoded from.
    Word: uint16
    /// Second word, which only an instruction two words wide reads.
    Extra: uint16
    /// How many bytes the decoder made of the words it was given.
    Length: int
    /// Canonical disassembly, which doubles as assembler input.
    Text: string }

/// <summary>
/// Sweeps the AVR encoding space by handing every word there is to B2R2's own
/// decoder, so that the set of instructions the assembler has to encode is
/// derived from the decoder rather than listed by hand.
///
/// The rule this encodes is that anything the decoder decodes, the assembler
/// encodes. Almost every AVR instruction is one sixteen-bit word, and there are
/// only sixty-five thousand of those, so nothing here has to choose which words
/// are worth trying: the sweep is linear and reaches all of them. Which
/// registers and which numbers an instruction names is therefore covered as
/// thoroughly as which instruction it is, and that is exactly where a mistake
/// in an encoder hides.
///
/// Four instructions are two words wide, and for each of those the second word
/// is swept whole as well, because what it holds is an address reaching the
/// whole of the code space or the whole of the data space.
/// </summary>
module internal AVRSweep =

  /// Every word there is, in the order the machine reads them.
  let private words =
    seq { for w in 0 .. 0xFFFF -> uint16 w }

  /// <summary>
  /// The word each instruction two words wide is reached by, holding the lowest
  /// register and the lowest bits of the address.
  ///
  /// A long call appears twice because the highest bit of the address it holds
  /// sits in the word naming it rather than in the word below, and a decoder
  /// that overlooks that reads the whole instruction as something else.
  /// </summary>
  let private wideWords = [ 0x9000us; 0x9200us; 0x940Cus; 0x940Eus; 0x940Fus ]

  /// The two bytes a word is stored as, in the order this architecture stores
  /// them.
  let private bytesOf (word: uint16) = BitConverter.GetBytes word

  let private decode (parser: IInstructionParsable) first second =
    let bytes = Array.append (bytesOf first) (bytesOf second)
    try
      let parsed = parser.Parse(bytes, 0UL)
      Some { Word = first
             Extra = second
             Length = int parsed.Length
             Text = parsed.Disasm() }
    with _ ->
      None

  /// <summary>
  /// Every word the decoder makes an instruction of.
  ///
  /// The words arrive as a sequence rather than a list because most of them are
  /// nothing at all and only the ones kept are worth holding on to. The second
  /// word every probe of the first pass is given is not zero, so that an
  /// instruction two words wide whose second word went missing shows up as text
  /// that changed rather than as text that happened to agree.
  /// </summary>
  let probes () =
    let parser = AVRParser(BinReader.Init Endian.Little) :> IInstructionParsable
    let short = words |> Seq.choose (fun w -> decode parser w 0x1234us)
    let wide =
      seq { for first in wideWords do
              for w in words -> decode parser first w }
      |> Seq.choose id
    Seq.append short wide |> Seq.toList

// vim: set tw=80 sts=2 sw=2:
