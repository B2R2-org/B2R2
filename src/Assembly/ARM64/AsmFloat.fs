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
/// Encodes the instructions that work on one element at a time: the ones that
/// read a single element of a vector register, which are written the way the
/// ones on whole vectors are but name a register by the width of that element,
/// and the ones on the floating-point registers, which are their own space
/// again and say how wide they are in a field of two bits.
/// </summary>
module internal B2R2.Assembly.ARM64.AsmFloat

open B2R2.FrontEnd.ARM64
open B2R2.Assembly.ARM64.ParserHelper
open B2R2.Assembly.ARM64.AsmField
open B2R2.Assembly.ARM64.AsmSIMD

/// The number of a SIMD register, whatever width it is written at.
let private simdNumber ins reg =
  match tryScalarWidth reg with
  | Some width -> simdReg width reg
  | None -> wrongOperands ins

/// <summary>
/// Which widths of one element a family member accepts, of which the manual
/// leaves a different set out for almost every one of them.
/// </summary>
type Widths =
  /// Every width one element is read at.
  | AnyElement
  /// A doubleword, which is the only width most of these read.
  | LongElement
  /// A halfword or a word, which is what a doubling multiply reads.
  | HalfOrWord
  /// A word or a doubleword, which is what a floating-point element is.
  | WordOrLong

/// Rejects a width the family member does not accept, which is one the manual
/// reserves rather than one the encoding cannot hold.
let private checkWidth (ins: AsmInsInfo) allowed reg =
  let accepts =
    match allowed, tryScalarWidth reg with
    | AnyElement, Some _ -> true
    | LongElement, Some 64 -> true
    | HalfOrWord, Some 16 | HalfOrWord, Some 32 -> true
    | WordOrLong, Some 32 | WordOrLong, Some 64 -> true
    | _ -> false
  if accepts then () else fail $"{ins.Opcode} does not read {reg}"

/// The size field the width of one element stands for, together with the number
/// of the register holding it.
let private scalarFields ins reg =
  match tryScalarWidth reg with
  | Some 8 -> 0b00u, simdReg 8 reg
  | Some 16 -> 0b01u, simdReg 16 reg
  | Some 32 -> 0b10u, simdReg 32 reg
  | Some 64 -> 0b11u, simdReg 64 reg
  | _ -> wrongOperands ins

/// The sz bit that says whether one element is a doubleword, together with the
/// number of the register holding it.
let private floatFields ins reg =
  match tryScalarWidth reg with
  | Some 32 -> 0u, simdReg 32 reg
  | Some 64 -> 1u, simdReg 64 reg
  | _ -> wrongOperands ins

/// Rejects a pair of registers that do not hold elements of one width.
let private sameWidth ins one other =
  if tryScalarWidth one <> tryScalarWidth other then wrongOperands ins else ()

/// The width one step up from the one the given register holds, which is what a
/// narrowing instruction reads and a lengthening one writes.
let private wider ins reg =
  match tryScalarWidth reg with
  | Some 8 -> 16
  | Some 16 -> 32
  | Some 32 -> 64
  | _ -> wrongOperands ins

/// Rejects a source that is not one step wider than the destination.
let private checkWider ins rd rn =
  if tryScalarWidth rn <> Some(wider ins rd) then wrongOperands ins else ()

(* The instructions that work on one element of a vector register. *)
/// The bits every one of them shares. They are written the way the ones on
/// whole vectors are, with the bit that would say how many lanes to read set
/// to say that there is only the one.
let private scalarHead u size =
  (1u <<< 30) ||| (u <<< 29) ||| (0b11110u <<< 24) ||| (size <<< 22)

/// <V><d>, <V><n>, <V><m>
let private scalarThreeSame allowed u opcode ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rn, Rg rm) ->
    sameWidth ins rd rn
    sameWidth ins rd rm
    checkWidth ins allowed rd
    let size, d = scalarFields ins rd
    scalarHead u size ||| (1u <<< 21) ||| (simdNumber ins rm <<< 16)
    ||| (opcode <<< 11) ||| (1u <<< 10) ||| (simdNumber ins rn <<< 5) ||| d
  | _ -> wrongOperands ins

/// The same, on floating-point elements, of which the size field says only
/// whether they are doublewords.
let private scalarThreeSameFP u hi opcode ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rn, Rg rm) ->
    sameWidth ins rd rn
    sameWidth ins rd rm
    let sz, d = floatFields ins rd
    scalarHead u ((hi <<< 1) ||| sz) ||| (1u <<< 21)
    ||| (simdNumber ins rm <<< 16) ||| (opcode <<< 11) ||| (1u <<< 10)
    ||| (simdNumber ins rn <<< 5) ||| d
  | _ -> wrongOperands ins

/// The bits an instruction reading one element into another shares.
let private scalarTwoRegWith u size opcode rn rd =
  scalarHead u size ||| (0b10000u <<< 17) ||| (opcode <<< 12) ||| (0b10u <<< 10)
  ||| (rn <<< 5) ||| rd

/// <V><d>, <V><n>
let private scalarTwoReg allowed u opcode ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Rg rn) ->
    sameWidth ins rd rn
    checkWidth ins allowed rd
    let size, d = scalarFields ins rd
    scalarTwoRegWith u size opcode (simdNumber ins rn) d
  | _ -> wrongOperands ins

/// The same, on floating-point elements.
let private scalarTwoRegFP u hi opcode ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Rg rn) ->
    sameWidth ins rd rn
    let sz, d = floatFields ins rd
    scalarTwoRegWith u ((hi <<< 1) ||| sz) opcode (simdNumber ins rn) d
  | _ -> wrongOperands ins

/// <V><d>, <V><n>, #0, the comparisons against nothing.
let private scalarCompareZero u opcode ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rn, Im 0L) ->
    sameWidth ins rd rn
    checkWidth ins LongElement rd
    let size, d = scalarFields ins rd
    scalarTwoRegWith u size opcode (simdNumber ins rn) d
  | _ -> wrongOperands ins

/// The same, on floating-point elements, whose nothing is written as one.
let private scalarCompareZeroFP u hi opcode ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rn, OprFPImm 0.0) ->
    sameWidth ins rd rn
    let sz, d = floatFields ins rd
    scalarTwoRegWith u ((hi <<< 1) ||| sz) opcode (simdNumber ins rn) d
  | _ -> wrongOperands ins

/// <V><d>, <V><n>, the ones whose destination is half as wide as what they
/// read.
let private scalarNarrowing u opcode ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Rg rn) ->
    checkWider ins rd rn
    let size, d = scalarFields ins rd
    scalarTwoRegWith u size opcode (simdNumber ins rn) d
  | _ -> wrongOperands ins

/// FCVTXN, which reads a doubleword into a word and says which it is in the bit
/// that says how wide one element is elsewhere.
let private scalarConvertNarrowing ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Rg rn) ->
    checkWider ins rd rn
    let _, d = floatFields ins rd
    scalarTwoRegWith 1u 0b01u 0b10110u (simdNumber ins rn) d
  | _ -> wrongOperands ins

/// <V><d>, <Vn>.<T>, the ones that read a pair of elements into one.
let private scalarPairwise u opcode ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Vec(rn, TwoD)) ->
    checkWidth ins LongElement rd
    let size, d = scalarFields ins rd
    scalarHead u size ||| (0b11000u <<< 17) ||| (opcode <<< 12)
    ||| (0b10u <<< 10) ||| (vectorReg rn <<< 5) ||| d
  | _ -> wrongOperands ins

/// <summary>
/// The same, on floating-point elements, which read a pair of either width.
///
/// A pair is all there is to read, so the arrangement is settled by the width
/// of what is written: nothing in the encoding says how many lanes to read, the
/// way it does for an operation on a whole vector.
/// </summary>
let private scalarPairwiseFP u hi opcode ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Vec(rn, t)) ->
    let sz, d = floatFields ins rd
    if t <> (if sz = 0u then TwoS else TwoD) then
      wrongOperands ins
    else
      scalarHead u ((hi <<< 1) ||| sz) ||| (0b11000u <<< 17) ||| (opcode <<< 12)
      ||| (0b10u <<< 10) ||| (vectorReg rn <<< 5) ||| d
  | _ -> wrongOperands ins

/// <V><d>, <V><n>, <V><m>, the ones whose destination is twice as wide as what
/// they read.
let private scalarThreeDiff u opcode ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rn, Rg rm) ->
    sameWidth ins rn rm
    checkWider ins rn rd
    checkWidth ins HalfOrWord rn
    let size, _ = scalarFields ins rn
    scalarHead u size ||| (1u <<< 21) ||| (simdNumber ins rm <<< 16)
    ||| (opcode <<< 12) ||| (simdNumber ins rn <<< 5) ||| simdNumber ins rd
  | _ -> wrongOperands ins

/// The bits an instruction shifting one element by an immediate shares, whose
/// immh and immb fields say both how wide the element is and how far to shift.
let private scalarShiftWith u opcode immhb rn rd =
  (1u <<< 30) ||| (u <<< 29) ||| (0b111110u <<< 23) ||| (immhb <<< 16)
  ||| (opcode <<< 11) ||| (1u <<< 10) ||| (rn <<< 5) ||| rd

/// The arrangement of one element of the given width, which is what says how
/// far the immh field reaches.
let private elementOf ins reg =
  match tryScalarWidth reg with
  | Some 8 -> EightB
  | Some 16 -> FourH
  | Some 32 -> TwoS
  | Some 64 -> OneD
  | _ -> wrongOperands ins

/// <V><d>, <V><n>, #<shift>
let private scalarShiftImm allowed u opcode toField ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rn, Im amount) ->
    sameWidth ins rd rn
    checkWidth ins allowed rd
    let field = toField ins (elementOf ins rd) amount
    scalarShiftWith u opcode field (simdNumber ins rn) (simdNumber ins rd)
  | _ -> wrongOperands ins

/// The same, for the ones whose destination is half as wide as what they read
/// and which count the shift in the narrower of the two.
let private scalarShiftNarrow u opcode ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rn, Im amount) ->
    checkWider ins rd rn
    let field = rightShift ins (elementOf ins rd) amount
    scalarShiftWith u opcode field (simdNumber ins rn) (simdNumber ins rd)
  | _ -> wrongOperands ins

/// <V><d>, <V><n>, #<fbits>, the conversions between a floating-point element
/// and one holding a fraction of that many bits.
let private scalarConvertFixed u opcode ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rn, Im amount) ->
    sameWidth ins rd rn
    checkWidth ins WordOrLong rd
    let field = rightShift ins (elementOf ins rd) amount
    scalarShiftWith u opcode field (simdNumber ins rn) (simdNumber ins rd)
  | _ -> wrongOperands ins

/// The bits an instruction reading one element of its second source shares.
let private scalarIndexedWith u opcode size source rn rd =
  (1u <<< 30) ||| (u <<< 29) ||| (0b11111u <<< 24) ||| (size <<< 22) ||| source
  ||| (opcode <<< 12) ||| (rn <<< 5) ||| rd

/// <V><d>, <V><n>, <Vm>.<Ts>[<index>]
let private scalarIndexed u opcode ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rn, Elem(rm, vec, index)) ->
    sameWidth ins rd rn
    checkWidth ins HalfOrWord rd
    let size, d = scalarFields ins rd
    let selected, source = indexedSource ins vec rm index
    if size <> selected then wrongOperands ins
    else scalarIndexedWith u opcode size source (simdNumber ins rn) d
  | _ -> wrongOperands ins

/// The same, on floating-point elements.
let private scalarIndexedFP u opcode ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rn, Elem(rm, vec, index)) ->
    sameWidth ins rd rn
    let sz, d = floatFields ins rd
    let selected, source = indexedSource ins vec rm index
    if selected <> (0b10u ||| sz) then
      wrongOperands ins
    else
      scalarIndexedWith u opcode (0b10u ||| sz) source (simdNumber ins rn) d
  | _ -> wrongOperands ins

/// The same, for the ones whose destination is twice as wide as what they read.
let private scalarIndexedLong u opcode ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rn, Elem(rm, vec, index)) ->
    checkWider ins rn rd
    checkWidth ins HalfOrWord rn
    let size, _ = scalarFields ins rn
    let selected, source = indexedSource ins vec rm index
    if size <> selected then
      wrongOperands ins
    else
      scalarIndexedWith u opcode size source (simdNumber ins rn)
                        (simdNumber ins rd)
  | _ -> wrongOperands ins

/// <V><d>, <Vn>.<Ts>[<index>], which reads one element into a register of its
/// own width. The manual writes it as a move, which is what it is.
let private scalarCopy ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Elem(rn, vec, index)) ->
    (1u <<< 30) ||| (0b11110000u <<< 21)
    ||| (elementSelector ins vec index <<< 16) ||| (1u <<< 10)
    ||| (vectorReg rn <<< 5) ||| simdNumber ins rd
  | _ -> wrongOperands ins

(* The instructions that scramble a hash. *)
/// The bits every one of them that reads three registers shares.
let private shaThreeReg opcode rn rm rd =
  (0b01011110u <<< 24) ||| (vectorReg rm <<< 16) ||| (opcode <<< 12)
  ||| (rn <<< 5) ||| rd

/// The ones whose second source is a whole register and whose first is a
/// register of a width of their own.
let private shaScalar width opcode ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rn, Vec(rm, FourS)) ->
    shaThreeReg opcode (simdReg width rn) rm (simdReg 128 rd)
  | _ -> wrongOperands ins

/// The ones that read three whole registers.
let private shaVector opcode ins =
  match ins.Operands with
  | ThreeOperands(Vec(rd, FourS), Vec(rn, FourS), Vec(rm, FourS)) ->
    shaThreeReg opcode (vectorReg rn) rm (vectorReg rd)
  | _ -> wrongOperands ins

/// The ones that read one register into another.
let private shaTwoReg opcode ins =
  let head rn rd =
    (0b01011110u <<< 24) ||| (0b10100u <<< 17) ||| (opcode <<< 12)
    ||| (0b10u <<< 10) ||| (rn <<< 5) ||| rd
  match ins.Operands with
  | TwoOperands(Vec(rd, FourS), Vec(rn, FourS)) ->
    head (vectorReg rn) (vectorReg rd)
  | TwoOperands(Rg rd, Rg rn) -> head (simdReg 32 rn) (simdReg 32 rd)
  | _ -> wrongOperands ins

(* The instructions on the floating-point registers. *)
/// The two bits that say how wide a floating-point register is, of which a
/// half-precision one is reached by the conversions alone.
let private floatType ins reg =
  match tryScalarWidth reg with
  | Some 32 -> 0b00u
  | Some 64 -> 0b01u
  | Some 16 -> 0b11u
  | _ -> wrongOperands ins

/// The same, for the instructions that read no half-precision register at all.
let private floatWideType ins reg =
  checkWidth ins WordOrLong reg
  floatType ins reg

/// The bits every one of them shares.
let private floatHead ty =
  (0b11110u <<< 24) ||| (ty <<< 22) ||| (1u <<< 21)

/// <Vd>, <Vn>, the ones that read one register into another.
let private floatOneSource opcode ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Rg rn) ->
    sameWidth ins rd rn
    floatHead (floatWideType ins rn) ||| (opcode <<< 15) ||| (0b10000u <<< 10)
    ||| (simdNumber ins rn <<< 5) ||| simdNumber ins rd
  | _ -> wrongOperands ins

/// FCVT, whose destination is of a different width from its source, and which
/// says which width that is in the bottom of its opcode.
let private convertFloat ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Rg rn) ->
    floatHead (floatType ins rn) ||| ((0b0001u <<< 2) <<< 15)
    ||| (floatType ins rd <<< 15) ||| (0b10000u <<< 10)
    ||| (simdNumber ins rn <<< 5) ||| simdNumber ins rd
  | _ -> wrongOperands ins

/// <Vd>, <Vn>, <Vm>, the ones that read two registers into one.
let private floatTwoSource opcode ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rn, Rg rm) ->
    sameWidth ins rd rn
    sameWidth ins rd rm
    floatHead (floatWideType ins rd) ||| (simdNumber ins rm <<< 16)
    ||| (opcode <<< 12) ||| (0b10u <<< 10) ||| (simdNumber ins rn <<< 5)
    ||| simdNumber ins rd
  | _ -> wrongOperands ins

/// <Vd>, <Vn>, <Vm>, <Va>, the ones that read three.
let private floatThreeSource o1 o0 ins =
  match ins.Operands with
  | FourOperands(Rg rd, Rg rn, Rg rm, Rg ra) ->
    sameWidth ins rd rn
    sameWidth ins rd rm
    sameWidth ins rd ra
    (0b11111u <<< 24) ||| (floatWideType ins rd <<< 22) ||| (o1 <<< 21)
    ||| (simdNumber ins rm <<< 16) ||| (o0 <<< 15)
    ||| (simdNumber ins ra <<< 10) ||| (simdNumber ins rn <<< 5)
    ||| simdNumber ins rd
  | _ -> wrongOperands ins

/// <Vn>, <Vm>|#0.0, the comparisons, which name no destination and say in the
/// bottom of their opcode whether they read a register at all.
let private floatCompare opcode2 ins =
  match ins.Operands with
  | TwoOperands(Rg rn, Rg rm) ->
    sameWidth ins rn rm
    floatHead (floatWideType ins rn) ||| (simdNumber ins rm <<< 16)
    ||| (0b001000u <<< 10) ||| (simdNumber ins rn <<< 5) ||| opcode2
  | TwoOperands(Rg rn, OprFPImm 0.0) ->
    floatHead (floatWideType ins rn) ||| (0b001000u <<< 10)
    ||| (simdNumber ins rn <<< 5) ||| opcode2 ||| 0b01000u
  | _ -> wrongOperands ins

/// <Vn>, <Vm>, #<nzcv>, <cond>, the comparisons that run under a condition.
let private floatCondCompare op ins =
  match ins.Operands with
  | FourOperands(Rg rn, Rg rm, Im nzcv, OprCond cond) ->
    sameWidth ins rn rm
    floatHead (floatWideType ins rn) ||| (simdNumber ins rm <<< 16)
    ||| (condField cond <<< 12) ||| (0b01u <<< 10)
    ||| (simdNumber ins rn <<< 5) ||| (op <<< 4) ||| unsignedImm 4 nzcv
  | _ -> wrongOperands ins

/// <Vd>, <Vn>, <Vm>, <cond>, which reads one of its sources or the other.
let private floatCondSelect ins =
  match ins.Operands with
  | FourOperands(Rg rd, Rg rn, Rg rm, OprCond cond) ->
    sameWidth ins rd rn
    sameWidth ins rd rm
    floatHead (floatWideType ins rd) ||| (simdNumber ins rm <<< 16)
    ||| (condField cond <<< 12) ||| (0b11u <<< 10)
    ||| (simdNumber ins rn <<< 5) ||| simdNumber ins rd
  | _ -> wrongOperands ins

/// <Vd>, #<imm>, a move of a value the eight bits of the encoding stand for.
let private floatImmediate ins =
  match ins.Operands with
  | TwoOperands(Rg rd, OprFPImm value) ->
    floatHead (floatWideType ins rd) ||| (floatImm value <<< 13)
    ||| (0b100u <<< 10) ||| simdNumber ins rd
  | _ -> wrongOperands ins

/// The bits a move between a floating-point register and a general one shares:
/// the type field says how wide the floating-point side is and the sf bit how
/// wide the other.
let private convertWith sf ty rmode opcode rn rd =
  (sf <<< 31) ||| floatHead ty ||| (rmode <<< 19) ||| (opcode <<< 16)
  ||| (rn <<< 5) ||| rd

/// <Rd>, <Vn>, the ones that read a floating-point register into a general one.
let private convertToGeneral rmode opcode ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Rg rn) ->
    convertWith (if is64Reg rd then 1u else 0u) (floatWideType ins rn) rmode
                opcode
                (simdNumber ins rn) (coreReg rd)
  | _ -> wrongOperands ins

/// <Vd>, <Rn>, the ones that write one. Only the conversion of a signed number
/// reaches a half-precision register, so what type the destination may be comes
/// from the caller.
let private convertToFloat toType rmode opcode ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Rg rn) ->
    convertWith (if is64Reg rn then 1u else 0u) (toType ins rd) rmode opcode
                (coreReg rn) (simdNumber ins rd)
  | _ -> wrongOperands ins

/// <summary>
/// The bits a conversion that keeps a count of fractional bits shares.
///
/// What the encoding holds is how many bits of the whole number are not a
/// fraction, and how many there are of those follows from the width of the
/// general register, which is why nothing else says it.
/// </summary>
let private convertFixedWith general ty rmode opcode fbits rn rd =
  let width = if is64Reg general then 64L else 32L
  if fbits < 1L || fbits > width then
    fail $"#{fbits} is not a count of fractional bits"
  else
    (if is64Reg general then 1u <<< 31 else 0u) ||| (0b11110u <<< 24)
    ||| (ty <<< 22) ||| (rmode <<< 19) ||| (opcode <<< 16)
    ||| (unsignedImm 6 (64L - fbits) <<< 10) ||| (rn <<< 5) ||| rd

/// <Vd>, <Rn>, #<fbits>, which reads a whole number into a floating-point
/// register.
let private convertFixedToFloat toType rmode opcode ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rn, Im fbits) ->
    convertFixedWith rn (toType ins rd) rmode opcode fbits (coreReg rn)
                     (simdNumber ins rd)
  | _ -> wrongOperands ins

/// <Rd>, <Vn>, #<fbits>, which reads one the other way.
let private convertFixedToGeneral rmode opcode ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rn, Im fbits) ->
    convertFixedWith rd (floatWideType ins rn) rmode opcode fbits
                     (simdNumber ins rn) (coreReg rd)
  | _ -> wrongOperands ins

/// Rejects a floating-point register and a general one that are not of one
/// width, which a move of the bits as they stand needs and a conversion does
/// not.
let private checkPaired ins float general =
  let paired =
    match tryScalarWidth float with
    | Some 32 -> not (is64Reg general)
    | Some 64 -> is64Reg general
    | _ -> false
  if paired then () else wrongOperands ins

/// <summary>
/// FMOV, which the manual defines as five instructions: a move between two
/// floating-point registers, one of an immediate, one either way between a
/// floating-point register and a general one, one either way between the top
/// half of a vector and a general register, and a move of an immediate into
/// every lane of a vector.
/// </summary>
let private move ins =
  match ins.Operands with
  | TwoOperands(Vec _, OprFPImm _) -> moveFloatImm ins
  | TwoOperands(Rg _, OprFPImm _) -> floatImmediate ins
  | TwoOperands(Elem(rd, VecD, 1uy), Rg rn) ->
    convertWith 1u 0b10u 0b01u 0b111u (coreReg rn) (vectorReg rd)
  | TwoOperands(Rg rd, Elem(rn, VecD, 1uy)) ->
    convertWith 1u 0b10u 0b01u 0b110u (vectorReg rn) (coreReg rd)
  | TwoOperands(Rg rd, Rg rn) when tryScalarWidth rd = tryScalarWidth rn ->
    floatOneSource 0b000000u ins
  | TwoOperands(Rg rd, Rg rn) when (tryScalarWidth rd).IsSome ->
    checkPaired ins rd rn
    convertToFloat floatWideType 0b00u 0b111u ins
  | TwoOperands(Rg rd, Rg rn) when (tryScalarWidth rn).IsSome ->
    checkPaired ins rn rd
    convertToGeneral 0b00u 0b110u ins
  | _ -> wrongOperands ins

/// MOV, which reads one element of a vector either into a register of its own
/// width or, where the manual writes it as something else, out of one.
let private moveElement ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Elem _) when (tryScalarWidth rd).IsSome -> scalarCopy ins
  | _ -> AsmSIMD.move ins

/// <summary>
/// The conversions between a floating-point value and a whole number, of which
/// there are four: one that reads an element into itself, one that reads it
/// into a general register or the other way round, and two more that keep a
/// count of fractional bits.
/// </summary>
let private convert toType u hi opcode rmode intOpcode toFloat ins =
  let scalarOpcode = if toFloat then 0b11100u else 0b11111u
  match getOperandsAsList ins.Operands with
  | [ Rg rd; Rg rn ] when tryScalarWidth rd = tryScalarWidth rn ->
    scalarTwoRegFP u hi opcode ins
  | [ Rg _; Rg _ ] when toFloat -> convertToFloat toType rmode intOpcode ins
  | [ Rg _; Rg _ ] -> convertToGeneral rmode intOpcode ins
  | [ Rg rd; Rg rn; Im _ ] when tryScalarWidth rd = tryScalarWidth rn ->
    scalarConvertFixed u scalarOpcode ins
  | [ Rg _; Rg _; Im _ ] when toFloat ->
    convertFixedToFloat toType rmode intOpcode ins
  | [ Rg _; Rg _; Im _ ] -> convertFixedToGeneral rmode intOpcode ins
  | _ -> wrongOperands ins

/// The ones that reach both the element they read and a general register.
let private convertOrRound u hi opcode rmode intOpcode ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Rg rn) when tryScalarWidth rd = tryScalarWidth rn ->
    scalarTwoRegFP u hi opcode ins
  | _ -> convertToGeneral rmode intOpcode ins

/// The multiplies, which read either the whole of their second source or one
/// element of it.
let private multiply opcode indexU indexOpcode ins =
  match ins.Operands with
  | ThreeOperands(_, _, Elem _) -> scalarIndexedFP indexU indexOpcode ins
  | _ -> floatTwoSource opcode ins

/// The same, for the ones on whole numbers.
let private multiplyScalar u opcode indexOpcode ins =
  match ins.Operands with
  | ThreeOperands(_, _, Elem _) -> scalarIndexed 0u indexOpcode ins
  | _ -> scalarThreeSame HalfOrWord u opcode ins

/// The same, for the ones whose result is twice as wide as what they read.
let private multiplyLong opcode indexOpcode ins =
  match ins.Operands with
  | ThreeOperands(_, _, Elem _) -> scalarIndexedLong 0u indexOpcode ins
  | _ -> scalarThreeDiff 0u opcode ins

/// The comparisons, which read either another element or nothing at all.
let private compare u opcode zeroU zeroOpcode ins =
  match ins.Operands with
  | ThreeOperands(_, _, Im _) -> scalarCompareZero zeroU zeroOpcode ins
  | _ -> scalarThreeSame LongElement u opcode ins

/// The same, on floating-point elements.
let private compareFP u hi opcode zeroU zeroHi zeroOpcode ins =
  match ins.Operands with
  | ThreeOperands(_, _, OprFPImm _) ->
    scalarCompareZeroFP zeroU zeroHi zeroOpcode ins
  | _ -> scalarThreeSameFP u hi opcode ins

/// The saturating shifts, which shift by either another element or an
/// immediate.
let private saturatingShift u sameOpcode shiftOpcode ins =
  match ins.Operands with
  | ThreeOperands(_, _, Im _) ->
    scalarShiftImm AnyElement u shiftOpcode leftShift ins
  | _ -> scalarThreeSame AnyElement u sameOpcode ins

/// FMULX, which reads either the whole of its second source or one element.
let private multiplyExtended ins =
  match ins.Operands with
  | ThreeOperands(_, _, Elem _) -> scalarIndexedFP 1u 0b1001u ins
  | _ -> scalarThreeSameFP 0u 0u 0b11011u ins

let floatEncoders () =
  [ Opcode.SQADD, scalarThreeSame AnyElement 0u 0b00001u
    Opcode.SQSUB, scalarThreeSame AnyElement 0u 0b00101u
    Opcode.SSHL, scalarThreeSame LongElement 0u 0b01000u
    Opcode.SRSHL, scalarThreeSame LongElement 0u 0b01010u
    Opcode.SQRSHL, scalarThreeSame AnyElement 0u 0b01011u
    Opcode.ADD, scalarThreeSame LongElement 0u 0b10000u
    Opcode.CMTST, scalarThreeSame LongElement 0u 0b10001u
    Opcode.UQADD, scalarThreeSame AnyElement 1u 0b00001u
    Opcode.UQSUB, scalarThreeSame AnyElement 1u 0b00101u
    Opcode.CMHI, scalarThreeSame LongElement 1u 0b00110u
    Opcode.CMHS, scalarThreeSame LongElement 1u 0b00111u
    Opcode.USHL, scalarThreeSame LongElement 1u 0b01000u
    Opcode.URSHL, scalarThreeSame LongElement 1u 0b01010u
    Opcode.UQRSHL, scalarThreeSame AnyElement 1u 0b01011u
    Opcode.SUB, scalarThreeSame LongElement 1u 0b10000u
    Opcode.FRECPS, scalarThreeSameFP 0u 0u 0b11111u
    Opcode.FRSQRTS, scalarThreeSameFP 0u 1u 0b11111u
    Opcode.FACGE, scalarThreeSameFP 1u 0u 0b11101u
    Opcode.FABD, scalarThreeSameFP 1u 1u 0b11010u
    Opcode.FACGT, scalarThreeSameFP 1u 1u 0b11101u
    Opcode.SUQADD, scalarTwoReg AnyElement 0u 0b00011u
    Opcode.SQABS, scalarTwoReg AnyElement 0u 0b00111u
    Opcode.ABS, scalarTwoReg LongElement 0u 0b01011u
    Opcode.USQADD, scalarTwoReg AnyElement 1u 0b00011u
    Opcode.SQNEG, scalarTwoReg AnyElement 1u 0b00111u
    Opcode.NEG, scalarTwoReg LongElement 1u 0b01011u
    Opcode.CMLT, scalarCompareZero 0u 0b01010u
    Opcode.CMLE, scalarCompareZero 1u 0b01001u
    Opcode.FCMLT, scalarCompareZeroFP 0u 1u 0b01110u
    Opcode.FCMLE, scalarCompareZeroFP 1u 1u 0b01101u
    Opcode.SQXTN, scalarNarrowing 0u 0b10100u
    Opcode.SQXTUN, scalarNarrowing 1u 0b10010u
    Opcode.UQXTN, scalarNarrowing 1u 0b10100u
    Opcode.FCVTXN, scalarConvertNarrowing
    Opcode.FRECPE, scalarTwoRegFP 0u 1u 0b11101u
    Opcode.FRECPX, scalarTwoRegFP 0u 1u 0b11111u
    Opcode.FRSQRTE, scalarTwoRegFP 1u 1u 0b11101u
    Opcode.ADDP, scalarPairwise 0u 0b11011u
    Opcode.FMAXNMP, scalarPairwiseFP 1u 0u 0b01100u
    Opcode.FADDP, scalarPairwiseFP 1u 0u 0b01101u
    Opcode.FMAXP, scalarPairwiseFP 1u 0u 0b01111u
    Opcode.FMINNMP, scalarPairwiseFP 1u 1u 0b01100u
    Opcode.FMINP, scalarPairwiseFP 1u 1u 0b01111u
    Opcode.SSHR, scalarShiftImm LongElement 0u 0b00000u rightShift
    Opcode.SSRA, scalarShiftImm LongElement 0u 0b00010u rightShift
    Opcode.SRSHR, scalarShiftImm LongElement 0u 0b00100u rightShift
    Opcode.SRSRA, scalarShiftImm LongElement 0u 0b00110u rightShift
    Opcode.SHL, scalarShiftImm LongElement 0u 0b01010u leftShift
    Opcode.USHR, scalarShiftImm LongElement 1u 0b00000u rightShift
    Opcode.USRA, scalarShiftImm LongElement 1u 0b00010u rightShift
    Opcode.URSHR, scalarShiftImm LongElement 1u 0b00100u rightShift
    Opcode.URSRA, scalarShiftImm LongElement 1u 0b00110u rightShift
    Opcode.SRI, scalarShiftImm LongElement 1u 0b01000u rightShift
    Opcode.SLI, scalarShiftImm LongElement 1u 0b01010u leftShift
    Opcode.SQSHLU, scalarShiftImm AnyElement 1u 0b01100u leftShift
    Opcode.SQSHRN, scalarShiftNarrow 0u 0b10010u
    Opcode.SQRSHRN, scalarShiftNarrow 0u 0b10011u
    Opcode.SQSHRUN, scalarShiftNarrow 1u 0b10000u
    Opcode.SQRSHRUN, scalarShiftNarrow 1u 0b10001u
    Opcode.UQSHRN, scalarShiftNarrow 1u 0b10010u
    Opcode.UQRSHRN, scalarShiftNarrow 1u 0b10011u
    Opcode.SHA1C, shaScalar 32 0b000u
    Opcode.SHA1P, shaScalar 32 0b001u
    Opcode.SHA1M, shaScalar 32 0b010u
    Opcode.SHA1SU0, shaVector 0b011u
    Opcode.SHA256H, shaScalar 128 0b100u
    Opcode.SHA256H2, shaScalar 128 0b101u
    Opcode.SHA256SU1, shaVector 0b110u
    Opcode.SHA1H, shaTwoReg 0b00000u
    Opcode.SHA1SU1, shaTwoReg 0b00001u
    Opcode.SHA256SU0, shaTwoReg 0b00010u
    Opcode.FABS, floatOneSource 0b000001u
    Opcode.FNEG, floatOneSource 0b000010u
    Opcode.FSQRT, floatOneSource 0b000011u
    Opcode.FRINTN, floatOneSource 0b001000u
    Opcode.FRINTP, floatOneSource 0b001001u
    Opcode.FRINTM, floatOneSource 0b001010u
    Opcode.FRINTZ, floatOneSource 0b001011u
    Opcode.FRINTA, floatOneSource 0b001100u
    Opcode.FRINTX, floatOneSource 0b001110u
    Opcode.FRINTI, floatOneSource 0b001111u
    Opcode.FCVT, convertFloat
    Opcode.FDIV, floatTwoSource 0b0001u
    Opcode.FADD, floatTwoSource 0b0010u
    Opcode.FSUB, floatTwoSource 0b0011u
    Opcode.FMAX, floatTwoSource 0b0100u
    Opcode.FMIN, floatTwoSource 0b0101u
    Opcode.FMAXNM, floatTwoSource 0b0110u
    Opcode.FMINNM, floatTwoSource 0b0111u
    Opcode.FNMUL, floatTwoSource 0b1000u
    Opcode.FMADD, floatThreeSource 0u 0u
    Opcode.FMSUB, floatThreeSource 0u 1u
    Opcode.FNMADD, floatThreeSource 1u 0u
    Opcode.FNMSUB, floatThreeSource 1u 1u
    Opcode.FCMP, floatCompare 0b00000u
    Opcode.FCMPE, floatCompare 0b10000u
    Opcode.FCCMP, floatCondCompare 0u
    Opcode.FCCMPE, floatCondCompare 1u
    Opcode.FCSEL, floatCondSelect
    Opcode.FMOV, move
    Opcode.MOV, moveElement
    Opcode.SCVTF, convert floatType 0u 0u 0b11101u 0b00u 0b010u true
    Opcode.UCVTF, convert floatWideType 1u 0u 0b11101u 0b00u 0b011u true
    Opcode.FCVTZS, convert floatWideType 0u 1u 0b11011u 0b11u 0b000u false
    Opcode.FCVTZU, convert floatWideType 1u 1u 0b11011u 0b11u 0b001u false
    Opcode.FCVTNS, convertOrRound 0u 0u 0b11010u 0b00u 0b000u
    Opcode.FCVTNU, convertOrRound 1u 0u 0b11010u 0b00u 0b001u
    Opcode.FCVTAS, convertOrRound 0u 0u 0b11100u 0b00u 0b100u
    Opcode.FCVTAU, convertOrRound 1u 0u 0b11100u 0b00u 0b101u
    Opcode.FCVTMS, convertOrRound 0u 0u 0b11011u 0b10u 0b000u
    Opcode.FCVTMU, convertOrRound 1u 0u 0b11011u 0b10u 0b001u
    Opcode.FCVTPS, convertOrRound 0u 1u 0b11010u 0b01u 0b000u
    Opcode.FCVTPU, convertOrRound 1u 1u 0b11010u 0b01u 0b001u
    Opcode.FMUL, multiply 0b0000u 0u 0b1001u
    Opcode.FMLA, scalarIndexedFP 0u 0b0001u
    Opcode.FMLS, scalarIndexedFP 0u 0b0101u
    Opcode.FMULX, multiplyExtended
    Opcode.SQDMULH, multiplyScalar 0u 0b10110u 0b1100u
    Opcode.SQRDMULH, multiplyScalar 1u 0b10110u 0b1101u
    Opcode.SQDMLAL, multiplyLong 0b1001u 0b0011u
    Opcode.SQDMLSL, multiplyLong 0b1011u 0b0111u
    Opcode.SQDMULL, multiplyLong 0b1101u 0b1011u
    Opcode.CMGT, compare 0u 0b00110u 0u 0b01000u
    Opcode.CMGE, compare 0u 0b00111u 1u 0b01000u
    Opcode.CMEQ, compare 1u 0b10001u 0u 0b01001u
    Opcode.FCMEQ, compareFP 0u 0u 0b11100u 0u 1u 0b01101u
    Opcode.FCMGE, compareFP 1u 0u 0b11100u 1u 1u 0b01100u
    Opcode.FCMGT, compareFP 1u 1u 0b11100u 0u 1u 0b01100u
    Opcode.SQSHL, saturatingShift 0u 0b01001u 0b01110u
    Opcode.UQSHL, saturatingShift 1u 0b01001u 0b01110u ]
