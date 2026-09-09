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

namespace B2R2.FrontEnd.Alpha

/// <summary>
/// Reads the function code field of an Alpha floating-point instruction, in
/// both directions.
///
/// The architecture spends this field on three things at once: what the
/// instruction computes, what it traps on, and how it rounds. Which
/// combinations of the last two an instruction takes is not the same from one
/// to the next -- a comparison rounds no way at all, a conversion from a
/// quadword cannot underflow -- so the combinations are listed here per
/// instruction and every other part of the front end and of the assembler is
/// derived from that one listing. A word carrying a combination its instruction
/// does not take names no instruction, and is read as none.
/// </summary>
[<RequireQualifiedAccess>]
module FloatFunction =
  (* What bits 10:8 of the field hold, paired with what that is written as. The
     values are not a dense range: the architecture reserves the bit above the
     two saying what is trapped on for saying that the trap is completed in
     software, so the sets below skip whatever the instructions in them cannot
     ask for. *)

  /// The trapping an IEEE instruction that can underflow takes.
  let private ieeeTrapping = [ 0x0u, ""; 0x1u, "u"; 0x5u, "su"; 0x7u, "sui" ]

  /// The trapping an IEEE conversion to an integer takes, which overflows
  /// rather than underflows and says so with another letter.
  let private ieeeOverflowTrapping =
    [ 0x0u, ""; 0x1u, "v"; 0x5u, "sv"; 0x7u, "svi" ]

  /// The trapping a conversion from a quadword takes, which can only lose
  /// precision and so is either left alone or trapped on for both reasons at
  /// once.
  let private inexactTrapping = [ 0x0u, ""; 0x7u, "sui" ]

  /// The trapping an IEEE comparison takes, which raises nothing of its own and
  /// so only ever says that a trap is completed in software.
  let private ieeeCompareTrapping = [ 0x0u, ""; 0x5u, "su" ]

  /// The trapping a VAX instruction takes.
  let private vaxTrapping = [ 0x0u, ""; 0x1u, "u"; 0x4u, "s"; 0x5u, "su" ]

  /// The trapping a VAX conversion to an integer takes.
  let private vaxOverflowTrapping =
    [ 0x0u, ""; 0x1u, "v"; 0x4u, "s"; 0x5u, "sv" ]

  /// The trapping a VAX comparison takes.
  let private vaxCompareTrapping = [ 0x0u, ""; 0x4u, "s" ]

  /// The trapping the conversion to the wider IEEE format takes, which is the
  /// one instruction whose field says the trap is not completed in software by
  /// holding something other than zero.
  let private widenTrapping = [ 0x2u, ""; 0x6u, "s" ]

  /// The trapping the conversion of a quadword to a longword takes.
  let private longwordTrapping = [ 0x0u, ""; 0x1u, "v"; 0x5u, "sv" ]

  /// What an instruction that traps no particular way holds there.
  let private noTrapping = [ 0x0u, "" ]

  /// <summary>
  /// The rounding an IEEE instruction takes, which is all four ways.
  ///
  /// What bits 7:6 of the field hold is paired here with what that is written
  /// as, the way the sets above pair what bits 10:8 hold; the value standing
  /// for the machine's own way of rounding is written by writing nothing.
  /// </summary>
  let private allRounding = [ 0x0u, "c"; 0x1u, "m"; 0x2u, ""; 0x3u, "d" ]

  /// The rounding a VAX instruction takes, which is the machine's own way or
  /// chopped and nothing else.
  let private vaxRounding = [ 0x0u, "c"; 0x2u, "" ]

  /// What an instruction that rounds no way holds there.
  let private noRounding = [ 0x2u, "" ]

  /// <summary>
  /// The instructions whose function code says how they round, each with the
  /// major opcode it is written under, the six bits of the field that name it,
  /// and what it traps on and rounds.
  ///
  /// The conversion to the wider IEEE format shares the six bits naming it with
  /// the conversion to the narrower one; what tells the two apart is that
  /// neither takes what the other traps on.
  /// </summary>
  let private roundedRows =
    [ Op.SQRTF, 0x14u, 0x0Au, vaxTrapping, vaxRounding
      Op.SQRTG, 0x14u, 0x2Au, vaxTrapping, vaxRounding
      Op.SQRTS, 0x14u, 0x0Bu, ieeeTrapping, allRounding
      Op.SQRTT, 0x14u, 0x2Bu, ieeeTrapping, allRounding
      Op.ADDF, 0x15u, 0x00u, vaxTrapping, vaxRounding
      Op.SUBF, 0x15u, 0x01u, vaxTrapping, vaxRounding
      Op.MULF, 0x15u, 0x02u, vaxTrapping, vaxRounding
      Op.DIVF, 0x15u, 0x03u, vaxTrapping, vaxRounding
      Op.CVTDG, 0x15u, 0x1Eu, vaxTrapping, vaxRounding
      Op.ADDG, 0x15u, 0x20u, vaxTrapping, vaxRounding
      Op.SUBG, 0x15u, 0x21u, vaxTrapping, vaxRounding
      Op.MULG, 0x15u, 0x22u, vaxTrapping, vaxRounding
      Op.DIVG, 0x15u, 0x23u, vaxTrapping, vaxRounding
      Op.CMPGEQ, 0x15u, 0x25u, vaxCompareTrapping, noRounding
      Op.CMPGLT, 0x15u, 0x26u, vaxCompareTrapping, noRounding
      Op.CMPGLE, 0x15u, 0x27u, vaxCompareTrapping, noRounding
      Op.CVTGF, 0x15u, 0x2Cu, vaxTrapping, vaxRounding
      Op.CVTGD, 0x15u, 0x2Du, vaxTrapping, vaxRounding
      Op.CVTGQ, 0x15u, 0x2Fu, vaxOverflowTrapping, vaxRounding
      Op.CVTQF, 0x15u, 0x3Cu, noTrapping, vaxRounding
      Op.CVTQG, 0x15u, 0x3Eu, noTrapping, vaxRounding
      Op.ADDS, 0x16u, 0x00u, ieeeTrapping, allRounding
      Op.SUBS, 0x16u, 0x01u, ieeeTrapping, allRounding
      Op.MULS, 0x16u, 0x02u, ieeeTrapping, allRounding
      Op.DIVS, 0x16u, 0x03u, ieeeTrapping, allRounding
      Op.ADDT, 0x16u, 0x20u, ieeeTrapping, allRounding
      Op.SUBT, 0x16u, 0x21u, ieeeTrapping, allRounding
      Op.MULT, 0x16u, 0x22u, ieeeTrapping, allRounding
      Op.DIVT, 0x16u, 0x23u, ieeeTrapping, allRounding
      Op.CMPTUN, 0x16u, 0x24u, ieeeCompareTrapping, noRounding
      Op.CMPTEQ, 0x16u, 0x25u, ieeeCompareTrapping, noRounding
      Op.CMPTLT, 0x16u, 0x26u, ieeeCompareTrapping, noRounding
      Op.CMPTLE, 0x16u, 0x27u, ieeeCompareTrapping, noRounding
      Op.CVTTS, 0x16u, 0x2Cu, ieeeTrapping, allRounding
      Op.CVTST, 0x16u, 0x2Cu, widenTrapping, noRounding
      Op.CVTTQ, 0x16u, 0x2Fu, ieeeOverflowTrapping, allRounding
      Op.CVTQS, 0x16u, 0x3Cu, inexactTrapping, allRounding
      Op.CVTQT, 0x16u, 0x3Eu, inexactTrapping, allRounding ]

  /// <summary>
  /// The instructions whose function code says nothing about how they round,
  /// each with the major opcode it is written under, the eight bits of the
  /// field that name it, and what it traps on.
  ///
  /// These spend on naming the instruction the two bits the ones above spend on
  /// rounding, so a word holding anything but their own value there names no
  /// instruction.
  /// </summary>
  let private plainRows =
    [ Op.ITOFS, 0x14u, 0x04u, noTrapping
      Op.ITOFF, 0x14u, 0x14u, noTrapping
      Op.ITOFT, 0x14u, 0x24u, noTrapping
      Op.CVTLQ, 0x17u, 0x10u, noTrapping
      Op.CPYS, 0x17u, 0x20u, noTrapping
      Op.CPYSN, 0x17u, 0x21u, noTrapping
      Op.CPYSE, 0x17u, 0x22u, noTrapping
      Op.MT_FPCR, 0x17u, 0x24u, noTrapping
      Op.MF_FPCR, 0x17u, 0x25u, noTrapping
      Op.FCMOVEQ, 0x17u, 0x2Au, noTrapping
      Op.FCMOVNE, 0x17u, 0x2Bu, noTrapping
      Op.FCMOVLT, 0x17u, 0x2Cu, noTrapping
      Op.FCMOVGE, 0x17u, 0x2Du, noTrapping
      Op.FCMOVLE, 0x17u, 0x2Eu, noTrapping
      Op.FCMOVGT, 0x17u, 0x2Fu, noTrapping
      Op.CVTQL, 0x17u, 0x30u, longwordTrapping ]

  /// The qualifier the given trapping and rounding are written as together.
  /// Both are read off the same field, and what they are written as is
  /// likewise one word rather than two.
  let private qualifierOf (trapping: string) (rounding: string) =
    Qualifier.ofString (trapping + rounding)

  /// <summary>
  /// Every floating-point instruction, each paired with one qualifier it takes
  /// and with the major opcode and the function code field that name the two
  /// together.
  ///
  /// An instruction appears once for each qualifier it takes, because a
  /// qualifier is part of how a word is written rather than something added to
  /// a word afterwards. Everything else here is read off this.
  /// </summary>
  [<CompiledName "All">]
  let all =
    [ for op, major, code, trapping, rounding in roundedRows do
        for trapBits, trapText in trapping do
          for roundBits, roundText in rounding do
            let func = (trapBits <<< 8) ||| (roundBits <<< 6) ||| code
            yield op, qualifierOf trapText roundText, major, func
      for op, major, code, trapping in plainRows do
        for trapBits, trapText in trapping do
          yield op, qualifierOf trapText "", major, (trapBits <<< 8) ||| code ]

  /// What each major opcode and function code name, built once so that reading
  /// a word is a lookup rather than a walk of the whole listing.
  let private byEncoding =
    all
    |> List.map (fun (op, qualifier, major, func) ->
      struct (major, func), struct (op, qualifier))
    |> Map.ofList

  /// What each instruction and qualifier are written as, built the same way.
  let private byOpcode =
    all
    |> List.map (fun (op, qualifier, major, func) ->
      struct (op, qualifier), struct (major, func))
    |> Map.ofList

  /// <summary>
  /// Returns the instruction and the qualifier the given major opcode and
  /// function code name, or None where the two name no instruction.
  /// </summary>
  [<CompiledName "Decode">]
  let decode major func = Map.tryFind (struct (major, func)) byEncoding

  /// <summary>
  /// Returns the major opcode and the function code field the given instruction
  /// and qualifier are written with, or None where the instruction is not a
  /// floating-point one or does not take that qualifier.
  /// </summary>
  [<CompiledName "Encode">]
  let encode op qualifier = Map.tryFind (struct (op, qualifier)) byOpcode

// vim: set tw=80 sts=2 sw=2:
