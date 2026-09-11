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
open B2R2.FrontEnd.WASM

/// Represents one instruction the decoder produced from a probe, paired with
/// the bytes it came from and the canonical text that gets handed back to the
/// assembler.
type internal WASMProbe =
  { /// The bytes the decoder made this instruction of.
    Bytes: byte[]
    /// How many of them it read.
    Length: int
    /// Canonical disassembly, which doubles as assembler input.
    Text: string }

/// <summary>
/// Sweeps the WASM encoding space by handing every opcode there is to B2R2's
/// own decoder, so that the set of instructions the assembler has to encode is
/// derived from the decoder rather than listed by hand.
///
/// The rule this encodes is that anything the decoder decodes, the assembler
/// encodes. The assembler derives its own table the same way, which would make
/// this vacuous were the two sweeps the same, so they are deliberately not: the
/// SIMD space has no end of its own to stop at, and this one walks further into
/// it than the table does. A new instruction landing past where the table stops
/// therefore shows up here as one that decodes and no longer encodes.
///
/// What no sweep of opcodes reaches is what an immediate holds, so a second
/// pass hands the instructions that take one the numbers an encoder gets wrong
/// rather than every number there is.
/// </summary>
module internal WASMSweep =

  /// <summary>
  /// The bytes a probe is padded out with.
  ///
  /// Three of them, because what an instruction takes is not always decided by
  /// which instruction it is: a br_table reads how many labels it has out of
  /// the stream, and a memarg reads out of it whether a memory index is there.
  /// Zeroes say what each instruction is at its narrowest; the run of small
  /// numbers gives every field something different to hold, so that a field
  /// gone missing shows up as text that changed; and the third sets the bit
  /// that puts a memory index in the middle of a memarg.
  ///
  /// Nothing in them reaches 0x40, so that every count read out of them leaves
  /// the probe inside its own padding and every number they spell is one byte
  /// wide however it is read.
  /// </summary>
  let private zeroes = Array.zeroCreate 128

  let private ascending = Array.init 128 (fun i -> byte (i % 0x3f + 1))

  let private flagged = Array.append [| 0x41uy |] ascending[1..]

  let private fillers = [ zeroes; ascending; flagged ]

  /// <summary>
  /// The last SIMD opcode a probe is made for.
  ///
  /// This is past where the assembler's own table stops, on purpose: the two
  /// are derived the same way, and a sweep that stopped where the table does
  /// could not say that the table stops too early.
  /// </summary>
  let [<Literal>] private SimdLimit = 0x4ff

  /// Every opcode there is: the one-byte space less the three prefixes, the
  /// two prefixed spaces whose opcode is a byte, and the SIMD space, whose
  /// opcode is a LEB128 u32.
  let private prefixes = [ 0xfc; 0xfd; 0xfe ]

  let private opcodes =
    [ for b in List.except prefixes [ 0 .. 0xff ] do
        yield [| byte b |]
      for sub in 0 .. 0xff do
        yield [| 0xfcuy; byte sub |]
        yield [| 0xfeuy; byte sub |]
      for sub in 0 .. SimdLimit do
        yield Array.append [| 0xfduy |] (LEB128.encodeUInt32 (uint32 sub)) ]

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

  /// <summary>
  /// The numbers a constant is tried holding.
  ///
  /// Zero and one say whether a number is written out at all; the two either
  /// side of 0x40 say whether the bit that carries the sign of a LEB128 number
  /// was counted, which is where an encoder that writes one byte too few gets
  /// it wrong; and the widest of each sign says whether a number reaching the
  /// end of its type still fits what is written for it.
  /// </summary>
  let private signedEdges =
    [ 0L; 1L; -1L; 63L; 64L; -64L; -65L; 8191L; 8192L; -624485L ]

  let private i32Probes =
    [ for v in signedEdges @ [ 2147483647L; -2147483648L ] ->
        Array.append [| 0x41uy |] (LEB128.encodeSInt32 (int32 v)) ]

  let private i64Probes =
    [ for v in signedEdges @ [ 9223372036854775807L; -9223372036854775808L ] ->
        Array.append [| 0x42uy |] (LEB128.encodeSInt64 v) ]

  /// <summary>
  /// The bits a float is tried holding.
  ///
  /// Both zeroes, because the sign of a zero is a bit no decimal point shows;
  /// both infinities and a quiet NaN, because none of the three is a number a
  /// decimal point can spell at all; the smallest number there is, which is
  /// written in an exponent no ordinary number reaches; and the largest, which
  /// is written in the most digits any of them takes.
  /// </summary>
  let private f32Bits =
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

  let private f64Bits =
    [ 0x0000000000000000UL
      0x8000000000000000UL
      0x3ff0000000000000UL
      0x7ff0000000000000UL
      0xfff0000000000000UL
      0x7ff8000000000000UL
      0x0000000000000001UL
      0x7fefffffffffffffUL
      0x400921fb54442d18UL ]

  let private wordBytes (v: uint32) =
    [| byte v; byte (v >>> 8); byte (v >>> 16); byte (v >>> 24) |]

  let private f32Probes =
    [ for bits in f32Bits -> Array.append [| 0x43uy |] (wordBytes bits) ]

  let private f64Probes =
    [ for bits in f64Bits do
        let low = wordBytes (uint32 bits)
        let high = wordBytes (uint32 (bits >>> 32))
        yield Array.concat [ [| 0x44uy |]; low; high ] ]

  /// The 128-bit constants a probe is made for: nothing, every bit, a run of
  /// alternating bits, and a value whose every byte differs, which is the only
  /// one of the four that says the words came out in the order they went in.
  let private v128Probes =
    [ Array.zeroCreate 16
      Array.create 16 0xffuy
      Array.init 16 (fun i -> if i % 2 = 0 then 0xaauy else 0x55uy)
      Array.init 16 (fun i -> byte (i + 1)) ]
    |> List.map (Array.append [| 0xfduy; 0x0cuy |])

  /// <summary>
  /// The memargs a load is tried with.
  ///
  /// Bit 6 of the alignment is not part of the alignment: it says a memory
  /// index sits between the two fields. So the alignments either side of it
  /// are tried both ways, and one above it as well, since an alignment wider
  /// than the flag still has to be written out whole.
  /// </summary>
  let private memArgs =
    [ [| 0x00uy; 0x00uy |]
      [| 0x02uy; 0x10uy |]
      [| 0x3fuy; 0x80uy; 0x01uy |]
      [| 0x80uy; 0x01uy; 0x00uy |]
      [| 0x40uy; 0x00uy; 0x00uy |]
      [| 0x43uy; 0x07uy; 0x80uy; 0x02uy |] ]
    |> List.map (Array.append [| 0x28uy |])

  /// The counted runs a br_table and a select are tried with, since how many
  /// either holds is read out of the stream rather than said by the opcode.
  let private countedProbes =
    [ [| 0x0euy; 0x00uy; 0x03uy |]
      [| 0x0euy; 0x01uy; 0x00uy; 0x03uy |]
      [| 0x0euy; 0x03uy; 0x00uy; 0x01uy; 0x02uy; 0x03uy |]
      [| 0x1cuy; 0x00uy |]
      [| 0x1cuy; 0x01uy; 0x7fuy |]
      [| 0x1cuy; 0x03uy; 0x7fuy; 0x7euy; 0x7buy |] ]

  /// The lanes and the models a probe is made for, which are the operands the
  /// encoding carries as one byte rather than as a LEB128 number.
  let private byteProbes =
    [ [| 0xfduy; 0x15uy; 0x00uy |]
      [| 0xfduy; 0x15uy; 0x0fuy |]
      [| 0xfduy; 0x15uy; 0xffuy |]
      [| 0xfeuy; 0x03uy; 0x00uy |] ]

  /// Every instruction that holds a number, holding each of the numbers worth
  /// trying.
  let private immediateProbes parser =
    i32Probes @ i64Probes @ f32Probes @ f64Probes @ v128Probes @ memArgs
    @ countedProbes @ byteProbes
    |> List.choose (decode parser)

  /// Every opcode the decoder makes an instruction of, together with every
  /// immediate worth trying.
  let probes () =
    let parser = WASMParser(BinReader.Init Endian.Little)
    let parser = parser :> IInstructionParsable
    opcodeProbes parser @ immediateProbes parser

// vim: set tw=80 sts=2 sw=2:
