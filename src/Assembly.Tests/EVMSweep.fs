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

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.EVM

/// Represents one instruction the decoder produced from a probe, paired with
/// the bytes it came from and the canonical text that gets handed back to the
/// assembler.
type internal EVMProbe =
  { /// The bytes the decoder made this instruction of.
    Bytes: byte[]
    /// How many of them it read.
    Length: int
    /// Canonical disassembly, which doubles as assembler input.
    Text: string }

/// <summary>
/// Sweeps the EVM encoding space by handing every byte there is to B2R2's own
/// decoder, so that the set of instructions the assembler has to encode is
/// derived from the decoder rather than listed by hand.
///
/// The rule this encodes is that anything the decoder decodes, the assembler
/// encodes. Which instruction an EVM byte names is the whole of what that byte
/// says, and there are only two hundred and fifty-six bytes, so the first pass
/// here is not a choice of what is worth trying: it is the encoding space
/// entire. That matters more for this architecture than for most, because what
/// the decoder knows grows with the chain, and a list written out by hand would
/// fall quietly behind the next instruction added to it.
///
/// What no sweep reaches is what a push holds, which for the widest of them is
/// two hundred and fifty-six bits. The second pass therefore hands each push
/// the numbers an encoder gets wrong rather than every number there is.
/// </summary>
module internal EVMSweep =

  /// <summary>
  /// The bytes a probe of the first pass is padded out with.
  ///
  /// They are neither zero nor all alike, so that a push whose number went
  /// missing, or came out the wrong way round, shows up as text that changed
  /// rather than as text that happened to agree. There are as many of them as
  /// the widest push holds, so that every byte can be tried the same way.
  /// </summary>
  let private filler = Array.init 32 (fun i -> byte (0x11 + i))

  let private decode (parser: IInstructionParsable) (bytes: byte[]) =
    try
      let parsed = parser.Parse(bytes, 0UL)
      let length = int parsed.Length
      Some { Bytes = bytes[..length - 1]
             Length = length
             Text = parsed.Disasm() }
    with _ ->
      None

  /// Every byte there is, each padded out so that a push finds a number to
  /// hold.
  let private opcodeProbes parser =
    [ for b in 0 .. 0xFF -> Array.append [| byte b |] filler ]
    |> List.choose (decode parser)

  /// <summary>
  /// The numbers a push of the given width is tried holding.
  ///
  /// Nothing at all and the smallest number there is say whether the bytes
  /// above a written number are filled in; the largest and a run of alternating
  /// bits say whether every byte is written at all; and a number whose bytes
  /// all differ says whether they came out in the order the machine reads them,
  /// which nothing symmetrical can. The last has the highest bit set and no
  /// other, because a number read as signed where it should not be is a number
  /// below zero exactly there.
  /// </summary>
  let private immediates width =
    [ Array.zeroCreate width
      Array.init width (fun i -> if i = width - 1 then 1uy else 0uy)
      Array.create width 0xFFuy
      Array.init width (fun i -> if i % 2 = 0 then 0xAAuy else 0x55uy)
      Array.init width (fun i -> byte (i + 1))
      Array.init width (fun i -> if i = 0 then 0x80uy else 0uy) ]

  /// Every push that holds anything, holding each of the numbers above.
  let private pushProbes parser =
    [ for width in 1 .. 32 do
        let code = [| byte (0x5F + width) |]
        for imm in immediates width -> Array.append code imm ]
    |> List.choose (decode parser)

  /// Every byte the decoder makes an instruction of, together with every push
  /// holding a number worth trying.
  let probes () =
    let parser = EVMParser(ISA Architecture.EVM) :> IInstructionParsable
    opcodeProbes parser @ pushProbes parser

// vim: set tw=80 sts=2 sw=2:
