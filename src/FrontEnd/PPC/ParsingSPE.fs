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

/// <summary>
/// Decodes the instructions of the Signal Processing Engine, which take
/// primary opcode 4 from the vector facility on the processors that have it.
/// ParsingMain hands a word here first; a word of another primary opcode, or
/// of a processor whose categories do not include the engine, goes on to its
/// own decoder.
/// </summary>
module internal B2R2.FrontEnd.PPC.ParsingSPE

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ParsingUtils
open B2R2.FrontEnd.PPC.OperandHelper

/// The general register a field of the word names.
let private gpr bin hi lo = getRegister (Bits.extract bin hi lo) |> OprReg

/// The registers the three register fields of the word name.
let private rtOf bin = gpr bin 25u 21u

let private raOf bin = gpr bin 20u 16u

let private rbOf bin = gpr bin 15u 11u

/// The unsigned number a field of the word holds.
let private uimm bin hi lo = Bits.extract bin hi lo |> uint64 |> OprImm

/// The signed number a five-bit field of the word holds, as a doubleword.
let private simm5 bin hi lo =
  Bits.extract bin hi lo |> uint64 |> Bits.signExtend 5 64 |> uint64 |> OprImm

/// A field of the word a form keeps reserved, which is zero where the
/// instruction is valid.
let private reserved bin hi lo =
  if Bits.extract bin hi lo <> 0u then raise ParsingFailureException else ()

/// An EVX-form "RT, RA, RB".
let private rrr op bin =
  struct (op, ThreeOperands(rtOf bin, raOf bin, rbOf bin))

/// An EVX-form "RT, RA" whose RB field is reserved.
let private rr op bin =
  reserved bin 15u 11u
  struct (op, TwoOperands(rtOf bin, raOf bin))

/// An EVX-form "RT, RB" whose RA field is reserved.
let private rb op bin =
  reserved bin 20u 16u
  struct (op, TwoOperands(rtOf bin, rbOf bin))

/// An EVX-form "RT, RB, UI" whose UI is in the RA field.
let private rbUi op bin =
  struct (op, ThreeOperands(rtOf bin, rbOf bin, uimm bin 20u 16u))

/// An EVX-form "RT, UI, RB" whose UI is in the RA field.
let private uiRb op bin =
  struct (op, ThreeOperands(rtOf bin, uimm bin 20u 16u, rbOf bin))

/// An EVX-form "RT, RA, UI" whose UI is in the RB field.
let private raUi op bin =
  struct (op, ThreeOperands(rtOf bin, raOf bin, uimm bin 15u 11u))

/// An EVX-form "RT, SI" whose SI is in the RA field and whose RB field is
/// reserved.
let private si op bin =
  reserved bin 15u 11u
  struct (op, TwoOperands(rtOf bin, simm5 bin 20u 16u))

/// An EVX-form "BF, RA, RB" whose two bits below BF are reserved.
let private crf op bin =
  reserved bin 22u 21u
  let bf = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
  struct (op, ThreeOperands(bf, raOf bin, rbOf bin))

/// An EVS-form "RT, RA, RB, BFA", the CR field in the low three bits.
let private sel op bin =
  let bfa = getCondRegister (Bits.extract bin 2u 0u) |> OprReg
  struct (op, FourOperands(rtOf bin, raOf bin, rbOf bin, bfa))

/// An EVX-form access "RT, D(RA)" whose five-bit UI is scaled by the size of
/// what the instruction reaches.
let private disp op size bin =
  let d = int (Bits.extract bin 15u 11u) * size
  let ra = getRegister (Bits.extract bin 20u 16u)
  struct (op, TwoOperands(rtOf bin, OprMem(d, ra)))

/// The instruction a word of primary opcode 4 is, by the eleven bits
/// below the register fields.
let private parseWord bin =
  match Bits.extract bin 10u 0u with
  | 512u -> rrr Op.EVADDW bin
  | 514u -> rbUi Op.EVADDIW bin
  | 516u -> rrr Op.EVSUBFW bin
  | 518u -> uiRb Op.EVSUBIFW bin
  | 529u -> rrr Op.EVAND bin
  | 530u -> rrr Op.EVANDC bin
  | 534u -> rrr Op.EVXOR bin
  | 535u -> rrr Op.EVOR bin
  | 536u -> rrr Op.EVNOR bin
  | 537u -> rrr Op.EVEQV bin
  | 539u -> rrr Op.EVORC bin
  | 542u -> rrr Op.EVNAND bin
  | _ -> raise ParsingFailureException

/// Whether the categories give primary opcode 4 to the Signal Processing
/// Engine.
let private hasSignalProcessing category =
  Category.includes Category.SignalProcessing category

/// The instruction a word is, if it is one this module takes on a processor
/// implementing the categories given.
let tryParse category bin =
  match bin >>> 26 with
  | 4u when hasSignalProcessing category -> ValueSome(parseWord bin)
  | _ -> ValueNone
