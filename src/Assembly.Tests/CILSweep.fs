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
open B2R2.FrontEnd.CIL

/// Represents one instruction the decoder produced from a probe, paired with
/// the bytes it came from and the canonical text that gets handed back to the
/// assembler.
type internal CILProbe =
  { /// The bytes the decoder made this instruction of.
    Bytes: byte[]
    /// How many of them it read.
    Length: int
    /// Canonical disassembly, which doubles as assembler input.
    Text: string }

/// <summary>
/// Sweeps the CIL encoding space by handing every opcode there is to B2R2's
/// own decoder, so that the set of instructions the assembler has to encode is
/// derived from the decoder rather than listed by hand.
///
/// The rule this encodes is that anything the decoder decodes, the assembler
/// encodes. The assembler derives its own table the same way, so what the
/// sweep says about which bytes name an instruction, it says of one table
/// twice; what it says on its own is that every operand the decoder reads, the
/// encoder writes back at the same width and meaning the same. What no sweep
/// of opcodes reaches is what an operand holds, so a second pass hands the
/// instructions that take one the numbers an encoder gets wrong rather than
/// every number there is.
/// </summary>
module internal CILSweep =

  /// <summary>
  /// The bytes a probe is padded out with.
  ///
  /// Three of them. Zeroes say what each instruction is at its narrowest, and
  /// are the one padding a switch survives, its count being read out of them.
  /// The run of small numbers gives every byte of an operand something
  /// different to hold, so that a byte gone missing or swapped shows up as
  /// text that changed. The run of large ones has the top bit of every byte
  /// set, so that every signed operand reads below zero and every branch goes
  /// backwards from the bottom of the address space and comes around at the
  /// top of it.
  /// </summary>
  let private zeroes = Array.zeroCreate 64

  let private ascending = Array.init 64 (fun i -> byte (i + 1))

  let private descending = Array.init 64 (fun i -> byte (0xff - i))

  let private fillers = [ zeroes; ascending; descending ]

  /// Every opcode there is: the one-byte space less the prefix byte, and the
  /// space behind that byte.
  let private opcodes =
    [ for b in List.except [ 0xfe ] [ 0 .. 0xff ] do
        yield [| byte b |]
      for sub in 0 .. 0xff do
        yield [| 0xfeuy; byte sub |] ]

  let private decode (parser: IInstructionParsable) (bytes: byte[]) =
    try
      let parsed = parser.Parse(bytes, 0UL)
      let length = int parsed.Length
      Some { Bytes = bytes[..length - 1]
             Length = length
             Text = parsed.Disasm() }
    with _ ->
      None

  /// Every opcode, each padded out three ways.
  let private opcodeProbes parser =
    [ for code in opcodes do
        for filler in fillers -> Array.append code filler ]
    |> List.choose (decode parser)

  let private wordBytes (v: uint32) =
    [| byte v; byte (v >>> 8); byte (v >>> 16); byte (v >>> 24) |]

  let private longBytes (v: uint64) =
    Array.append (wordBytes (uint32 v)) (wordBytes (uint32 (v >>> 32)))

  /// <summary>
  /// The values an operand is tried holding: zero and one, and the widest of
  /// each sign, which say whether a number reaching the end of its width still
  /// fits what is written for it and whether the top bit was read as a sign
  /// where it is one. The one-byte operands are ldc.i4.s, br.s and leave.s,
  /// which are signed, and ldarg.s, unaligned. and no., which are not.
  /// </summary>
  let private bytes = [ 0x00uy; 0x01uy; 0x7fuy; 0x80uy; 0xffuy ]

  let private oneByteCodes =
    [ [| 0x1fuy |]
      [| 0x2buy |]
      [| 0xdeuy |]
      [| 0x0euy |]
      [| 0xfeuy; 0x12uy |]
      [| 0xfeuy; 0x19uy |] ]

  let private oneByteProbes =
    [ for code in oneByteCodes do
        for v in bytes -> Array.append code [| v |] ]

  /// The long form of a variable, whose index is two bytes.
  let private twoByteProbes =
    [ for v in [ 0us; 1us; 0xffus; 0x100us; 0xffffus ] ->
        [| 0xfeuy; 0x09uy; byte v; byte (v >>> 8) |] ]

  /// The four-byte operands: ldc.i4, br and leave, which are signed, and a
  /// call, whose token is not.
  let private words = [ 0u; 1u; 0x7fffffffu; 0x80000000u; 0xffffffffu ]

  let private fourByteProbes =
    [ for code in [ 0x20uy; 0x38uy; 0xdduy; 0x28uy ] do
        for v in words -> Array.append [| code |] (wordBytes v) ]

  let private longs =
    [ 0UL
      1UL
      0x7fffffffffffffffUL
      0x8000000000000000UL
      0xffffffffffffffffUL ]

  let private eightByteProbes =
    [ for v in longs -> Array.append [| 0x21uy |] (longBytes v) ]

  /// <summary>
  /// The bits a float is tried holding.
  ///
  /// Both zeroes, because the sign of a zero is a bit no decimal point shows;
  /// both infinities and a quiet NaN, because none of the three is a number a
  /// decimal point can spell at all; the smallest number there is, which is
  /// written in an exponent no ordinary number reaches; and the largest, which
  /// is written in the most digits any of them takes.
  /// </summary>
  let private r4Bits =
    [ 0x00000000u
      0x80000000u
      0x3f800000u
      0xbf800000u
      0x7f800000u
      0xff800000u
      0x7fc00000u
      0x00000001u
      0x7f7fffffu
      0x40490fdbu ]

  let private r8Bits =
    [ 0x0000000000000000UL
      0x8000000000000000UL
      0x3ff0000000000000UL
      0x7ff0000000000000UL
      0xfff0000000000000UL
      0x7ff8000000000000UL
      0x0000000000000001UL
      0x7fefffffffffffffUL
      0x400921fb54442d18UL ]

  let private r4Probes =
    [ for bits in r4Bits -> Array.append [| 0x22uy |] (wordBytes bits) ]

  let private r8Probes =
    [ for bits in r8Bits -> Array.append [| 0x23uy |] (longBytes bits) ]

  /// The tables a switch is tried with, since how many targets it has is read
  /// out of the stream rather than said by the opcode: none, one, and several
  /// going both ways and as far as a target goes. The first word of each is
  /// the count.
  let private switchProbes =
    [ [ 0u ]
      [ 1u; 0x10u ]
      [ 3u; 0u; 0xffffffffu; 0x7fffffffu ]
      [ 2u; 0x80000000u; 0xfffffff7u ] ]
    |> List.map (fun words ->
      Array.append [| 0x45uy |] (List.map wordBytes words |> Array.concat))

  /// Every instruction that holds a number, holding each of the numbers worth
  /// trying.
  let private operandProbes parser =
    oneByteProbes @ twoByteProbes @ fourByteProbes @ eightByteProbes
    @ r4Probes @ r8Probes @ switchProbes
    |> List.choose (decode parser)

  /// Every opcode the decoder makes an instruction of, together with every
  /// operand worth trying.
  let probes () =
    let parser = CILParser(BinReader.Init Endian.Little)
    let parser = parser :> IInstructionParsable
    opcodeProbes parser @ operandProbes parser

// vim: set tw=80 sts=2 sw=2:
