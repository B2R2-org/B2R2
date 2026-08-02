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
/// Encodes the floating-point unit at each of the three widths a number is
/// kept at, the conversions between those widths and the whole numbers, the
/// comparisons, the instructions doing two things at once, and what a program
/// says to any other unit outside the processor.
/// </summary>
module internal B2R2.Assembly.PARISC.AsmFloat

open B2R2.Assembly.PARISC.ParserHelper
open B2R2.Assembly.PARISC.AsmField

(* The six bits the instructions meant for a unit outside the processor begin
   with, already in the place they sit. The floating-point unit is one of
   those, and is the one such an instruction names where it names none. *)
let [<Literal>] private OpCoprocessor = 0x30000000u
let [<Literal>] private OpSpecial = 0x10000000u
let [<Literal>] private OpFused = 0xB8000000u
let [<Literal>] private OpFloatOnly = 0x38000000u

/// One word of the kind the floating-point unit computes with, given the two
/// bits saying which family of them it is.
let private floating family rest =
  OpCoprocessor ||| (family <<< 9) ||| rest

/// <summary>
/// One word of the kind the floating-point unit alone answers for.
///
/// The unit is named here rather than reached as one coprocessor among
/// several, and the registers such a word names are halves rather than whole
/// doublewords, so it holds only the two widths one bit tells apart.
/// </summary>
let private halved family subop fmt rest =
  OpFloatOnly ||| (subop <<< 13) ||| (fmt <<< 11) ||| (family <<< 9) ||| rest

/// The five bits naming a floating-point register and the bit saying which
/// half of it is meant, each in the place the encoding keeps it.
let private atHalf shift pos reg =
  let n, right = fprHalf reg
  (n <<< shift) ||| (right <<< pos)

/// The one bit telling the two widths a halved word reaches apart.
let private narrowFormat = function
  | [ "sgl" ] -> 0u
  | [ "dbl" ] -> 1u
  | _ -> fail "a word naming half a register is kept single or double"

/// An instruction computing from one whole floating-point register into
/// another.
let private wideUnary subop ins =
  let fmt = floatFormat ins.Suffixes
  match ins.Operands with
  | [ Rg s; Rg d ] ->
    floating 0u ((fpr s <<< 21) ||| (subop <<< 13) ||| (fmt <<< 11) ||| fpr d)
  | _ -> wrongOperands ins

/// The same, where what it computes from and what it lands in are halves.
let private halfUnary subop ins =
  let fmt = narrowFormat ins.Suffixes
  match ins.Operands with
  | [ Rg s; Rg d ] ->
    halved 0u subop fmt (atHalf 21 7 s ||| atHalf 0 6 d)
  | _ -> wrongOperands ins

/// An instruction computing from one floating-point register into another,
/// whichever of the two ways it is written.
let private unary subop ins = orTry (wideUnary subop) (halfUnary subop) ins

/// An instruction computing from two whole floating-point registers into a
/// third.
let private wideBinary subop ins =
  let fmt = floatFormat ins.Suffixes
  match ins.Operands with
  | [ Rg s2; Rg s1; Rg d ] ->
    floating 3u ((fpr s2 <<< 21) ||| (fpr s1 <<< 16) ||| (subop <<< 13)
                 ||| (fmt <<< 11) ||| fpr d)
  | _ -> wrongOperands ins

/// The same, where all three are halves.
let private halfBinary subop ins =
  let fmt = narrowFormat ins.Suffixes
  match ins.Operands with
  | [ Rg s2; Rg s1; Rg d ] ->
    halved 3u subop fmt (atHalf 21 7 s2 ||| atHalf 16 12 s1 ||| atHalf 0 6 d)
  | _ -> wrongOperands ins

/// An instruction computing from two floating-point registers into a third.
let private binary subop ins = orTry (wideBinary subop) (halfBinary subop) ins

/// The instruction saying which floating-point unit a program is running on,
/// which carries nothing at all.
let private fid ins =
  nothingLeft ins ins.Suffixes
  match ins.Operands with
  | [] -> OpCoprocessor
  | _ -> wrongOperands ins

/// The three widths a pair of bits may name, together with the bits naming
/// them; the fourth thing such a pair may say is that the width is not written
/// at all.
let private widths (names: string[]) =
  [ 0u, names[0]; 1u, names[1]; 3u, names[2] ]

/// <summary>
/// Every pair of widths a conversion may be written with, together with the
/// four bits naming the pair.
///
/// Either half of a pair may be left unwritten, in which case the other half
/// stands for both, and where neither is written the instruction says nothing
/// about width at all.
/// </summary>
let private conversions from into =
  [ for a, x in widths from do
      for b, y in widths into -> [ x; y ], (a <<< 2) ||| b ]
  @ [ for a, x in widths from -> [ x ], (a <<< 2) ||| 2u ]
  @ [ for b, y in widths into -> [ y ], 0b1000u ||| b ]
  @ [ [], 0b1010u ]

/// <summary>
/// Every way a conversion may be written, paired with the three bits naming
/// which kind of conversion it is and the four naming the widths.
///
/// A conversion turning a floating-point number into a whole one is written
/// with a word saying that it rounds toward zero rather than the way the
/// program asked for, and that word is part of which kind of conversion it is.
/// </summary>
let private conversionForms () =
  let real = [| "sgl"; "dbl"; "quad" |]
  let whole = [| "w"; "dw"; "qw" |]
  let counting = [| "uw"; "udw"; "uqw" |]
  let rows subop prefix table =
    table |> List.map (fun (names, bits) -> prefix @ names, (subop, bits))
  rows 0u [] (conversions real real)
  @ rows 1u [] (conversions whole real)
  @ rows 2u [] (conversions real whole)
  @ rows 3u [ "t" ] (conversions real whole)
  @ rows 5u [] (conversions counting real)
  @ rows 6u [] (conversions real counting)
  @ rows 7u [ "t" ] (conversions real counting)

/// The instruction turning a number of one width into a number of another,
/// which is the one floating-point instruction whose name says which two.
let private wideFcnv forms ins =
  match List.tryFind (fst >> (=) ins.Suffixes) forms with
  | None -> fail "no conversion is written this way"
  | Some(_, (subop, bits)) ->
    match ins.Operands with
    | [ Rg s; Rg d ] ->
      floating 1u ((fpr s <<< 21) ||| (subop <<< 15) ||| ((bits &&& 3u) <<< 13)
                   ||| ((bits >>> 2) <<< 11) ||| fpr d)
    | _ -> wrongOperands ins

/// <summary>
/// The same, where what is converted and where it lands are halves.
///
/// One bit is left for each of the two widths rather than two, so only the
/// narrower of the three widths can be named, and naming neither of them is
/// not written this way at all.
/// </summary>
let private halfFcnv forms ins =
  match List.tryFind (fst >> (=) ins.Suffixes) forms with
  | None -> fail "no conversion is written this way"
  | Some(_, (subop, bits)) when bits &&& 0b1010u = 0u ->
    match ins.Operands with
    | [ Rg s; Rg d ] ->
      halved 1u 0u 0u ((subop <<< 15) ||| ((bits &&& 1u) <<< 13)
                       ||| (((bits >>> 2) &&& 1u) <<< 11) ||| atHalf 21 7 s
                       ||| atHalf 0 6 d)
    | _ -> wrongOperands ins
  | Some _ -> fail "no conversion of a half register is written this way"

/// The instruction turning a number of one width into a number of another.
let private fcnv forms ins = orTry (wideFcnv forms) (halfFcnv forms) ins

/// One word of the kind reading what a comparison of floating-point numbers
/// left behind, or leaving it.
let private decide subop fmt reads c rest =
  floating 2u ((subop <<< 13) ||| (fmt <<< 11) ||| (reads <<< 5) ||| c ||| rest)

/// <summary>
/// The comparison of two floating-point numbers.
///
/// Where a program is asking more than one question of the numbers at once it
/// says which of the answers this comparison is to leave behind, and the field
/// saying so counts from one, so that leaving it unwritten means the first.
/// </summary>
let private wideFcmp ins =
  let flags, rest = split [ "sgl"; "dbl"; "quad" ] ins.Suffixes
  let fmt = floatFormat flags
  let c = floatCompareCondition (condition rest)
  match ins.Operands with
  | [ Rg s2; Rg s1 ] -> decide 0u fmt 0u c ((fpr s2 <<< 21) ||| (fpr s1 <<< 16))
  | [ Rg s2; Rg s1; Im which ] when which < 7UL ->
    decide (uint32 which + 1u) fmt 0u c
      ((fpr s2 <<< 21) ||| (fpr s1 <<< 16))
  | _ -> wrongOperands ins

/// The same, where what is compared are halves, which leaves no room for
/// saying which of several answers the comparison is to leave behind.
let private halfFcmp ins =
  let flags, rest = split [ "sgl"; "dbl" ] ins.Suffixes
  let fmt = narrowFormat flags
  let c = floatCompareCondition (condition rest)
  match ins.Operands with
  | [ Rg s2; Rg s1 ] ->
    halved 2u 0u fmt (atHalf 21 7 s2 ||| atHalf 16 12 s1 ||| c)
  | _ -> wrongOperands ins

/// The comparison of two floating-point numbers.
let private fcmp ins = orTry wideFcmp halfFcmp ins

/// <summary>
/// The instruction reading what one or more earlier comparisons left behind.
///
/// Where it asks after a single answer it names which by a number, and the
/// three bits holding that number count in an order of their own; where it
/// asks after several at once it says which several by a word after its name.
/// </summary>
let private ftest ins =
  match ins.Suffixes, ins.Operands with
  | [], [] -> decide 1u 0u 1u 0u 0u
  | [ token ], [] -> decide 1u 0u 1u (floatTestCondition token) 0u
  | [], [ Im which ] when which < 7UL ->
    decide ((uint32 which + 1u) ^^^ 1u) 0u 1u 0u 0u
  | _, [] -> wrongSuffixes ins
  | _ -> wrongOperands ins

/// One word of the kind turning on or off the coprocessor watching how a
/// program runs, which names that coprocessor rather than the floating-point
/// unit and carries nothing else.
let private monitor bits nullified ins =
  match ins.Operands with
  | [] -> OpCoprocessor ||| bits ||| (2u <<< 6) ||| (nullified <<< 5)
  | _ -> wrongOperands ins

/// The instruction turning that coprocessor off, which is written with a word
/// saying whether the instruction after it is thrown away.
let private pmdis ins =
  let flags, rest = split [ "n" ] ins.Suffixes
  nothingLeft ins rest
  monitor 0x200u (bit "n" flags) ins

/// The instruction turning it back on.
let private pmenb ins =
  nothingLeft ins ins.Suffixes
  monitor 0x600u 0u ins

/// <summary>
/// An instruction left to whichever unit outside the processor it names to
/// give a meaning to.
///
/// Nothing of what it says is written as anything but two numbers: which unit
/// it is meant for, and what that unit is to do. The second of the two lies in
/// two pieces on either side of everything else the word holds.
/// </summary>
let private copr ins =
  let numbers, rest = takeNumbers 2 ins.Suffixes
  let flags, rest = split [ "n" ] rest
  nothingLeft ins rest
  match numbers, ins.Operands with
  | [ uid; sop ], [] ->
    let sop = unsigned 22 sop
    OpCoprocessor ||| ((sop >>> 5) <<< 9) ||| (unsigned 3 uid <<< 6)
    ||| (bit "n" flags <<< 5) ||| (sop &&& 0x1Fu)
  | _, [] -> fail "this names no unit and nothing for it to do"
  | _ -> wrongOperands ins

/// The instruction multiplying two whole numbers held in floating-point
/// registers, which the floating-point unit alone is asked for.
let private xmpyu ins =
  nothingLeft ins ins.Suffixes
  match ins.Operands with
  | [ Rg s2; Rg s1; Rg d ] ->
    halved 3u 2u 0u
      (atHalf 21 7 s2 ||| atHalf 16 12 s1 ||| (1u <<< 8) ||| fpr d)
  | _ -> wrongOperands ins

/// <summary>
/// The instruction multiplying and then adding without rounding in between.
///
/// The register it adds is named in two pieces that lie on either side of the
/// bit saying which width the numbers are kept at, because the one field wide
/// enough for it would have crossed everything else the word holds.
/// </summary>
let private fused negated ins =
  let fmt =
    match ins.Suffixes with
    | [ "sgl" ] -> 0u
    | [ "dbl" ] -> 1u
    | _ -> fail "this names no floating-point width"
  match ins.Operands with
  | [ Rg s2; Rg s1; Rg a; Rg d ] ->
    let n, right = fprHalf a
    OpFused ||| atHalf 21 7 s2 ||| atHalf 16 12 s1 ||| ((n >>> 2) <<< 13)
    ||| (fmt <<< 11) ||| ((n &&& 3u) <<< 9) ||| (right <<< 8)
    ||| (negated <<< 5) ||| atHalf 0 6 d
  | _ -> wrongOperands ins

/// The instructions doing a multiplication and an addition or a subtraction at
/// once, which name five registers because the two share nothing.
let private twoAtOnce opcode ins =
  let sgl =
    match ins.Suffixes with
    | [ "dbl" ] -> 0u
    | [ "sgl" ] -> 1u
    | _ -> fail "this names no floating-point width"
  let upper reg =
    let n = fpr reg
    if sgl = 1u && n < 16u then
      fail "a word is multiplied only out of the upper half of the registers"
    else
      n
  match ins.Operands with
  | [ Rg m1; Rg m2; Rg tm; Rg a; Rg ta ] ->
    (opcode <<< 26) ||| (upper m1 <<< 21) ||| (upper m2 <<< 16)
    ||| (upper ta <<< 11) ||| (upper a <<< 6) ||| (sgl <<< 5) ||| upper tm
  | _ -> wrongOperands ins

/// <summary>
/// An instruction left to a unit outside the processor that is not the
/// floating-point one.
///
/// The four of them differ in how much room is left for saying what the unit
/// is to do, because what room there is, is whatever the registers they name
/// leave over.
/// </summary>
let private spop family high shift build ins =
  let numbers, rest = takeNumbers 2 ins.Suffixes
  let flags, rest = split [ "n" ] rest
  nothingLeft ins rest
  match numbers with
  | [ sfu; sop ] ->
    let sop = unsigned high sop
    let low = if shift then sop &&& 0x1Fu else 0u
    let upper = if shift then sop >>> 5 else sop
    OpSpecial ||| (upper <<< 11) ||| (family <<< 9) ||| (unsigned 3 sfu <<< 6)
    ||| (bit "n" flags <<< 5) ||| low ||| build ins
  | _ -> fail "this names no unit and nothing for it to do"

/// What an instruction left to a unit outside the processor names besides the
/// unit itself, which for two of the four is nothing.
let private noRegister ins =
  match ins.Operands with
  | [] -> 0u
  | _ -> wrongOperands ins

/// The same, where one general register is named to land in.
let private oneTarget ins =
  match ins.Operands with
  | [ Rg d ] -> gpr d
  | _ -> wrongOperands ins

/// The same, where one general register is named to read.
let private oneSource ins =
  match ins.Operands with
  | [ Rg s ] -> gpr s <<< 21
  | _ -> wrongOperands ins

/// The same, where two are named to read.
let private twoSources ins =
  match ins.Operands with
  | [ Rg s1; Rg s2 ] -> (gpr s2 <<< 21) ||| (gpr s1 <<< 16)
  | _ -> wrongOperands ins

/// The instructions the floating-point unit and every other unit outside the
/// processor compute with.
let floatEncoders () =
  [ "fid", fid
    "fcpy", unary 2u
    "fabs", unary 3u
    "fsqrt", unary 4u
    "frnd", unary 5u
    "fneg", unary 6u
    "fnegabs", unary 7u
    "fcnv", fcnv (conversionForms ())
    "fcmp", fcmp
    "ftest", ftest
    "fadd", binary 0u
    "fsub", binary 1u
    "fmpy", binary 2u
    "fdiv", binary 3u
    "pmdis", pmdis
    "pmenb", pmenb
    "copr", copr
    "xmpyu", xmpyu
    "fmpyfadd", fused 0u
    "fmpynfadd", fused 1u
    "fmpyadd", twoAtOnce 0b000110u
    "fmpysub", twoAtOnce 0b100110u
    "spop0", spop 0u 20 true noRegister
    "spop1", spop 1u 15 false oneTarget
    "spop2", spop 2u 15 true oneSource
    "spop3", spop 3u 10 true twoSources ]

// vim: set tw=80 sts=2 sw=2:
