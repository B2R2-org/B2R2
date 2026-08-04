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
open System.Text.RegularExpressions
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.M68K

/// Represents one instruction the decoder produced from a probe, paired with
/// the words it came from and the canonical text that gets handed back to the
/// assembler.
type internal M68KProbe =
  { /// The words the probe was decoded from, the opcode word first.
    Words: uint16[]
    /// How many bytes of them the instruction the decoder found is made of.
    Length: int
    /// Canonical disassembly, which doubles as assembler input.
    Text: string }

/// <summary>
/// Enumerates the m68k encoding space by handing every combination of the bits
/// that name an instruction to B2R2's own decoder, so that the set of
/// instructions the assembler has to encode is derived from the decoder rather
/// than listed by hand.
///
/// The rule this encodes is that anything the decoder decodes, the assembler
/// encodes. Which instruction a halfword is comes from the opcode word alone,
/// so the whole of that space is walked; what follows it is an operand rather
/// than a name, save for the handful of instructions that carry a field of
/// their own in an extension word, so what follows is tried at a set of
/// patterns leaving no such field holding nothing. The addressing modes
/// reaching through memory are named in a full extension word, and every one of
/// those is walked wherever an opcode word names such a mode; the
/// floating-point unit reads a command word of its own, which is walked over
/// the operations, the formats, and the shapes it holds; and the one
/// instruction naming a control register by a code rather than by a field has
/// every code walked. Every four-bit run of every form so reached is then
/// walked over all sixteen of its values, because which register a run of bits
/// names, and how large a number it holds, is exactly where a mistake in an
/// encoder hides.
/// </summary>
module internal M68KSweep =

  /// How many words a probe holds, which is the longest an m68k instruction
  /// gets: one opcode word and ten bytes of extension words on either side of a
  /// MOVE whose source and destination each use a full extension word with two
  /// long displacements.
  let [<Literal>] private WordCount = 11

  /// The extension words a probe carries where nothing in particular is wanted
  /// of them, which is every nibble of them different, so that whichever field
  /// of whichever of them an instruction reads holds something.
  let private filler = [| 0x1234us; 0x5678us; 0x9abcus; 0xdef0us |]

  /// A probe of the given opcode word, whose extension words are the given ones
  /// and then the filler.
  let private probeOf (bin: uint16) (exts: uint16 list) =
    Array.init WordCount (fun i ->
      if i = 0 then bin
      elif i - 1 < List.length exts then exts[i - 1]
      else filler[(i - 1) % 4])

  /// The bytes of a probe, the more significant byte of each word first, which
  /// is how m68k stores one.
  let private bytesOf (words: uint16[]) =
    Array.init (2 * WordCount) (fun i ->
      if i % 2 = 0 then uint8 (words[i / 2] >>> 8) else uint8 words[i / 2])

  /// The values the first extension word is tried at, which between them leave
  /// no field of any of the instructions that read one holding nothing. A field
  /// of nothing is worth trying too, a handful of these being told from one
  /// another by whether such a field holds anything.
  let private extPatterns =
    [ 0x0000us
      0xffffus
      0x5555us
      0xaaaaus
      0x1234us
      0x8000us
      0x0800us
      0x0080us
      0x0008us
      0x0100us ]

  /// Every probe of the whole of the space an opcode word is named in, tried
  /// against each of those patterns.
  let private everyOpcode =
    seq {
      for bin in 0u .. 0xffffu do
        for ext in extPatterns do
          yield probeOf (uint16 bin) [ ext ] }

  /// Every probe of the whole of that space again with the first two extension
  /// words the same, because the one instruction that compares and swaps two
  /// places at once carries two of them and reads a field of each, so nothing
  /// that fills the second with something of its own would ever reach it.
  let private everyPair =
    seq {
      for bin in 0u .. 0xffffu do
        for ext in [ 0x0000us; 0x8000us; 0xffffus ] do
          yield probeOf (uint16 bin) [ ext; ext ] }

  /// Whether an opcode word names one of the indexed modes in either of the two
  /// effective-address fields a MOVE has, which is where a full extension word
  /// may sit. A MOVE whose source is a register carries the extension words of
  /// its destination first, so that is where the destination field is worth
  /// walking.
  let private namesIndexed (bin: uint16) =
    let srcMode = (bin >>> 3) &&& 7us
    let dstMode = (bin >>> 6) &&& 7us
    srcMode = 6us
    || (bin &&& 0x3fus) = 0x3bus
    || (dstMode = 6us && srcMode = 0us)

  /// Every full extension word, which is what says which of the modes reaching
  /// through memory is meant: whether the base and the index are there at all,
  /// and how wide each of the two displacements is.
  let private fullExts =
    [ for suppress in [ 0x00us; 0x40us; 0x80us; 0xc0us ] do
        for bd in 1us .. 3us do
          for iis in [ 0us; 1us; 2us; 3us; 5us; 6us; 7us ] ->
            0x100us ||| suppress ||| (bd <<< 4) ||| iis ]

  /// Every probe of those words against the opcode words that name such a mode.
  let private indexedWords =
    seq { 0 .. 0xffff }
    |> Seq.map uint16
    |> Seq.filter namesIndexed
    |> Seq.collect (fun bin ->
      fullExts |> Seq.map (fun ext -> probeOf bin [ ext ]))

  /// The command words of the arithmetic of the unit, which name the operation
  /// in seven bits, the format the source is read in in three, and the register
  /// the answer is kept in in three.
  let private arithCmds =
    [ for kind in [ 0x0000us; 0x4000us ] do
        for spec in 0us .. 7us do
          for dst in [ 0us; 3us ] do
            for opmode in 0us .. 0x7fus ->
              kind ||| (spec <<< 10) ||| (dst <<< 7) ||| opmode ]

  /// The command words of the move out to an address, of the moves of the
  /// registers the unit keeps for itself, and of the move of a list of the ones
  /// it computes with.
  let private otherCmds =
    [ for spec in 0us .. 7us do
        for dst in [ 0us; 3us ] do
          for low in [ 0us; 1us; 0x40us; 0x7fus ] ->
            0x6000us ||| (spec <<< 10) ||| (dst <<< 7) ||| low
      for select in 0us .. 7us do
        for dir in [ 0us; 0x2000us ] ->
          0x8000us ||| dir ||| (select <<< 10)
      for mmode in 0us .. 3us do
        for dir in [ 0us; 0x2000us ] do
          for low in [ 0us; 0x12us; 0xffus; 0x30us ] ->
            0xc000us ||| dir ||| (mmode <<< 11) ||| low ]

  /// Every probe of the instructions of the floating-point unit, whose second
  /// word the coprocessor rather than the processor reads and which is
  /// therefore where the operation is named at all.
  let private floatWords =
    seq {
      for ea in 0us .. 0x3fus do
        for cmd in arithCmds do
          yield probeOf (0xf200us ||| ea) [ cmd ]
        for cmd in otherCmds do
          yield probeOf (0xf200us ||| ea) [ cmd ]
        for cond in 0us .. 0x3fus do
          yield probeOf (0xf240us ||| ea) [ cond ] }

  /// Every code a MOVEC may name a control register by, which is a table of its
  /// own rather than a field naming a register.
  let private movecWords =
    seq {
      for bin in [ 0x4e7aus; 0x4e7bus ] do
        for code in 0us .. 0xfffus do
          yield probeOf bin [ code ] }

  /// Every probe reached by walking each nibble of the given one over all
  /// sixteen of its values. Only the nibbles the instruction is made of are
  /// walked; what lies past its end is not its own.
  let private fieldWords (probe: M68KProbe) =
    seq {
      for index in 0 .. 2 * probe.Length - 1 do
        for value in 0us .. 15us do
          let shift = 4 * (3 - index % 4)
          let copy = Array.copy probe.Words
          let kept = probe.Words[index / 4] &&& ~~~(0xfus <<< shift)
          copy[index / 4] <- kept ||| (value <<< shift)
          yield copy }

  /// Whether the text is a written number, which is what tells an operand
  /// naming a value from one naming a register.
  let private isNumber (token: string) =
    token.Length > 0 && Char.IsDigit token[0]

  /// What an operand names, keeping which register it was and how many digits a
  /// number was written with, because how large a number is is what tells one
  /// that fits its field from one that does not.
  let private shapeOfToken (token: string) =
    if isNumber token then $"imm{token.Length}" else token

  /// What an operand names and nothing else, which is the coarser of the two
  /// keys: one form is worth reaching once however many registers it is written
  /// with.
  let private kindOfToken (token: string) =
    if isNumber token then "imm" else token.TrimEnd [| '0' .. '9' |]

  /// <summary>
  /// The key a probe is kept once for.
  ///
  /// What the disassembler writes has every run of letters and digits of its
  /// operands passed through the given function, and every mark between them is
  /// kept as it is, so that two instructions share a key only where they are
  /// written the same way. The name is left alone: it is what says which
  /// encoder runs at all.
  /// </summary>
  let private keyOf kind (text: string) =
    match text.IndexOf ' ' with
    | -1 ->
      text
    | at ->
      let map = MatchEvaluator(fun m -> kind m.Value)
      let mapped = Regex.Replace(text[at + 1..], "[0-9a-zA-Z]+", map)
      text[..at] + mapped

  let private decode (parser: IInstructionParsable) (words: uint16[]) =
    try
      let parsed = parser.Parse(bytesOf words, 0UL)
      Some { Words = words; Length = int parsed.Length; Text = parsed.Disasm() }
    with _ ->
      None

  /// Probes the given words, keeping one instruction per distinct key. The
  /// words arrive as a sequence rather than a list because there are millions
  /// of them and only the ones kept are worth holding on to.
  let private survey parser key words =
    words |> Seq.choose (decode parser) |> Seq.distinctBy key |> Seq.toList

  /// The decoder of the given member of the family, which is what says whether
  /// a halfword is an instruction at all: the family shares one encoding space
  /// and every model both added to it and dropped from it.
  let parserFor model =
    let isa = ISA(model: M68KModel)
    M68KParser(isa, BinReader.Init Endian.Big) :> IInstructionParsable

  /// The instructions of the given probes that the given member of the family
  /// reads, which is how the part of the space an earlier model shares is
  /// reached without walking the whole of it again.
  let readableBy model probes =
    let parser = parserFor model
    probes |> List.choose (fun probe -> decode parser probe.Words)

  /// Probes the whole space this sweep covers, keeping one instruction per
  /// distinct operand shape.
  let probes model =
    let parser = parserFor model
    let walked =
      Seq.concat
        [ everyOpcode; everyPair; indexedWords; floatWords; movecWords ]
    let shape (probe: M68KProbe) = keyOf shapeOfToken probe.Text
    let kind (probe: M68KProbe) = keyOf kindOfToken probe.Text
    let byForm = survey parser kind walked
    byForm @ survey parser shape (Seq.collect fieldWords byForm)
    |> List.distinctBy shape

// vim: set tw=80 sts=2 sw=2:
