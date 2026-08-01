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
/// Encodes the instructions that work on whole vectors, which are one space of
/// their own: every one of them says how wide its elements are in the
/// arrangement its registers are written with rather than in its name, so the
/// families here are one function reading that arrangement and a few bits that
/// say which member of the family it is.
///
/// Which arrangements each of them reads is checked as well as that they fit
/// together, because the manual reserves a different set of them for almost
/// every member of a family and one it reserves names no instruction at all.
/// Each row below says which set is its own.
/// </summary>
module internal B2R2.Assembly.ARM64.AsmSIMD

open B2R2.FrontEnd.ARM64
open B2R2.Assembly.ARM64.ParserHelper
open B2R2.Assembly.ARM64.AsmField

/// The arrangement of twice the width and half as many lanes, which is what a
/// widening instruction writes and a narrowing one reads.
let widened = function
  | EightB | SixteenB -> EightH
  | FourH | EightH -> FourS
  | TwoS | FourS -> TwoD
  | OneD | TwoD -> OneQ
  | vec -> fail $"{vec} has no arrangement of twice its width"

/// <summary>
/// The arrangement a pairwise widening operation writes, which holds half as
/// many elements of twice the width: it reads its lanes in pairs, so the count
/// halves where the ordinary widening leaves it alone and drops half the source
/// instead.
/// </summary>
let private paired = function
  | EightB -> FourH
  | SixteenB -> EightH
  | FourH -> TwoS
  | EightH -> FourS
  | TwoS -> OneD
  | FourS -> TwoD
  | vec -> fail $"{vec} has no arrangement of twice its width"

/// The width of one element of an arrangement, which is what an operand naming
/// one element of a register has to agree with.
let private elementKind = function
  | EightB | SixteenB -> VecB
  | FourH | EightH -> VecH
  | TwoS | FourS -> VecS
  | OneD | TwoD -> VecD
  | vec -> fail $"{vec} holds no element of its own"

/// The sz bit and Q bit of a floating-point arrangement, which says only
/// whether its elements are doublewords and how many of them there are.
let floatArrangement = function
  | TwoS -> 0u, 0u
  | FourS -> 0u, 1u
  | TwoD -> 1u, 1u
  | vec -> fail $"{vec} is not an arrangement a floating-point vector takes"

/// Rejects a pair of arrangements that are not the same, which every operation
/// reading and writing one arrangement needs.
let private sameArrangement ins one other =
  if one <> other then wrongOperands ins else ()

(* The operations on three vectors of one arrangement. *)
/// The bits every one of them shares.
let private threeSameWith u size opcode q rd rn rm =
  (q <<< 30) ||| (u <<< 29) ||| (0b01110u <<< 24) ||| (size <<< 22)
  ||| (1u <<< 21) ||| (vectorReg rm <<< 16) ||| (opcode <<< 11) ||| (1u <<< 10)
  ||| (vectorReg rn <<< 5) ||| vectorReg rd

/// <Vd>.<T>, <Vn>.<T>, <Vm>.<T>, whose elements are as wide as the arrangement
/// says.
let private threeSame allowed u opcode ins =
  match ins.Operands with
  | ThreeOperands(Vec(rd, t), Vec(rn, tn), Vec(rm, tm)) ->
    sameArrangement ins t tn
    sameArrangement ins t tm
    checkArrangement ins allowed t
    let size, q = arrangement t
    threeSameWith u size opcode q rd rn rm
  | _ -> wrongOperands ins

/// The same, for the operations on floating-point elements: only one bit of
/// the size field is theirs, and the other says which half of the family the
/// instruction belongs to.
let private threeSameFP u hi opcode ins =
  match ins.Operands with
  | ThreeOperands(Vec(rd, t), Vec(rn, tn), Vec(rm, tm)) ->
    sameArrangement ins t tn
    sameArrangement ins t tm
    let sz, q = floatArrangement t
    threeSameWith u ((hi <<< 1) ||| sz) opcode q rd rn rm
  | _ -> wrongOperands ins

/// The same, for the operations that read whole registers rather than
/// elements: what would say how wide an element is says which of them it is.
let private threeSameLogical u size ins =
  match ins.Operands with
  | ThreeOperands(Vec(rd, t), Vec(rn, tn), Vec(rm, tm)) ->
    sameArrangement ins t tn
    sameArrangement ins t tm
    let q =
      match t with
      | EightB -> 0u
      | SixteenB -> 1u
      | vec -> fail $"{vec} is not an arrangement a logical operation takes"
    threeSameWith u size 0b00011u q rd rn rm
  | _ -> wrongOperands ins

(* The operations that read two vectors and interleave them. *)
/// <Vd>.<T>, <Vn>.<T>, <Vm>.<T>, which take the elements of their sources in
/// an order of their own.
let private permute opcode ins =
  match ins.Operands with
  | ThreeOperands(Vec(rd, t), Vec(rn, tn), Vec(rm, tm)) ->
    sameArrangement ins t tn
    sameArrangement ins t tm
    checkArrangement ins NotLone t
    let size, q = arrangement t
    (q <<< 30) ||| (0b001110u <<< 24) ||| (size <<< 22)
    ||| (vectorReg rm <<< 16) ||| (opcode <<< 12) ||| (0b10u <<< 10)
    ||| (vectorReg rn <<< 5) ||| vectorReg rd
  | _ -> wrongOperands ins

/// <Vd>.<T>, <Vn>.<T>, <Vm>.<T>, #<index>, which reads one run of elements
/// spanning two registers.
let private extract ins =
  match ins.Operands with
  | FourOperands(Vec(rd, t), Vec(rn, tn), Vec(rm, tm), Im index) ->
    sameArrangement ins t tn
    sameArrangement ins t tm
    let q =
      match t with
      | EightB -> 0u
      | SixteenB -> 1u
      | vec -> fail $"{vec} is not an arrangement an extraction takes"
    let limit = if q = 1u then 16L else 8L
    if index < 0L || index >= limit then
      fail $"a vector of {t} has no element #{index}"
    else
      (q <<< 30) ||| (0b101110u <<< 24) ||| (vectorReg rm <<< 16)
      ||| (unsignedImm 4 index <<< 11) ||| (vectorReg rn <<< 5) ||| vectorReg rd
  | _ -> wrongOperands ins

/// <Vd>.<Ta>, { <Vn>.16B ... }, <Vm>.<Ta>, which reads its result out of a
/// table of up to four registers.
let private tableLookup op ins =
  match ins.Operands with
  | ThreeOperands(Vec(rd, t), OprSIMDList table, Vec(rm, tm)) ->
    sameArrangement ins t tm
    let q =
      match t with
      | EightB -> 0u
      | SixteenB -> 1u
      | vec -> fail $"{vec} is not an arrangement a table lookup takes"
    let registers =
      table |> List.map (function
        | VecReg(reg, SixteenB) -> vectorReg reg
        | _ -> wrongOperands ins)
    let first = List.head registers
    let consecutive =
      registers
      |> List.mapi (fun i number -> (first + uint32 i) % 32u = number)
      |> List.forall id
    if not consecutive then
      fail "a table has to name a run of registers"
    else
      (q <<< 30) ||| (0b001110u <<< 24) ||| (vectorReg rm <<< 16)
      ||| (uint32 (List.length registers - 1) <<< 13) ||| (op <<< 12)
      ||| (first <<< 5) ||| vectorReg rd
  | _ -> wrongOperands ins

(* The operations that move an element between a vector and somewhere else. *)
/// How far up a field the index of an element sits, which is as many places as
/// the element has bytes.
let elementShift ins = function
  | VecB -> 0
  | VecH -> 1
  | VecS -> 2
  | VecD -> 3
  | vec -> fail $"{vec} is not the width of one element"

/// Rejects an element a vector of that width does not hold.
let checkIndex ins vec (index: uint8) =
  if uint32 index >= (16u >>> elementShift ins vec) then
    fail $"a vector of {vec} elements has no element #{index}"
  else ()

/// <summary>
/// The imm5 field, which says both how wide the element it names is and which
/// of them it is: the width is a one with as many zeroes below it as the
/// element has bytes, and the index sits above that.
/// </summary>
let elementSelector ins vec (index: uint8) =
  checkIndex ins vec index
  let shift = elementShift ins vec
  (uint32 index <<< (shift + 1)) ||| (1u <<< shift)

/// The bits every move of an element shares.
let private copyWith q op imm5 imm4 rn rd =
  (q <<< 30) ||| (op <<< 29) ||| (0b01110000u <<< 21) ||| (imm5 <<< 16)
  ||| (imm4 <<< 11) ||| (1u <<< 10) ||| (rn <<< 5) ||| rd

/// DUP, which fills every lane of its destination with one element, read
/// either out of another vector or out of a general register.
let private duplicate ins =
  match ins.Operands with
  | TwoOperands(Vec(rd, t), Elem(rn, vec, index)) ->
    checkArrangement ins NotLone t
    if elementKind t <> vec then
      wrongOperands ins
    else
      let _, q = arrangement t
      copyWith q 0u (elementSelector ins vec index) 0b0000u (vectorReg rn)
               (vectorReg rd)
  | TwoOperands(Vec(rd, t), Rg rn) ->
    checkArrangement ins NotLone t
    let vec = elementKind t
    if is64Reg rn <> (vec = VecD) then
      wrongOperands ins
    else
      let _, q = arrangement t
      copyWith q 0u (elementSelector ins vec 0uy) 0b0001u (coreReg rn)
               (vectorReg rd)
  | _ -> wrongOperands ins

/// <summary>
/// SMOV and UMOV, which read one element into a general register. How wide that
/// register is says nothing about the element, so it goes in the Q bit of its
/// own.
///
/// Which elements each of them reaches follows from what it leaves above the
/// one it read: the one that copies the element as it stands reaches only the
/// elements that leave something above them, while the one that extends it
/// reaches only the ones that do not fill the register.
/// </summary>
let private moveToGeneral extends imm4 ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Elem(rn, vec, index)) ->
    let is64 = is64Reg rd
    let reached =
      match extends, is64 with
      | true, false -> [ VecB; VecH ]
      | true, true -> [ VecB; VecH; VecS ]
      | false, false -> [ VecB; VecH; VecS ]
      | false, true -> [ VecD ]
    if not (List.contains vec reached) then
      wrongOperands ins
    else
      copyWith (if is64 then 1u else 0u) 0u (elementSelector ins vec index) imm4
               (vectorReg rn) (coreReg rd)
  | _ -> wrongOperands ins

/// INS, which writes one element, taking it either from a general register or
/// from an element of another vector.
let private insert ins =
  match ins.Operands with
  | TwoOperands(Elem(rd, vec, index), Elem(rn, vecn, index2)) ->
    sameArrangement ins vec vecn
    (* The imm4 field holds the element the source is read from with nothing
       below it to say how wide that element is, so the index sits at the top of
       the field rather than at the bottom of it. *)
    checkIndex ins vec index2
    let source = uint32 index2 <<< elementShift ins vec
    copyWith 1u 1u (elementSelector ins vec index) source (vectorReg rn)
             (vectorReg rd)
  | TwoOperands(Elem(rd, vec, index), Rg rn) ->
    if is64Reg rn <> (vec = VecD) then
      wrongOperands ins
    else
      copyWith 1u 0u (elementSelector ins vec index) 0b0011u (coreReg rn)
               (vectorReg rd)
  | _ -> wrongOperands ins

(* The operations that read one vector. *)
/// The bits every one of them shares.
let private twoRegWith u size opcode q rd rn =
  (q <<< 30) ||| (u <<< 29) ||| (0b01110u <<< 24) ||| (size <<< 22)
  ||| (0b10000u <<< 17) ||| (opcode <<< 12) ||| (0b10u <<< 10)
  ||| (vectorReg rn <<< 5) ||| vectorReg rd

/// <Vd>.<T>, <Vn>.<T>
let private twoReg allowed u opcode ins =
  match ins.Operands with
  | TwoOperands(Vec(rd, t), Vec(rn, tn)) ->
    sameArrangement ins t tn
    checkArrangement ins allowed t
    let size, q = arrangement t
    twoRegWith u size opcode q rd rn
  | _ -> wrongOperands ins

/// The same, for the operations that read whole registers: what would say how
/// wide an element is says which of them it is instead.
let private twoRegLogical u size opcode ins =
  match ins.Operands with
  | TwoOperands(Vec(rd, t), Vec(rn, tn)) ->
    sameArrangement ins t tn
    let q =
      match t with
      | EightB -> 0u
      | SixteenB -> 1u
      | vec -> fail $"{vec} is not an arrangement this operation takes"
    twoRegWith u size opcode q rd rn
  | _ -> wrongOperands ins

/// The same, for floating-point elements.
let private twoRegFP allowed u hi opcode ins =
  match ins.Operands with
  | TwoOperands(Vec(rd, t), Vec(rn, tn)) ->
    sameArrangement ins t tn
    checkArrangement ins allowed t
    let sz, q = floatArrangement t
    twoRegWith u ((hi <<< 1) ||| sz) opcode q rd rn
  | _ -> wrongOperands ins

/// <Vd>.<T>, <Vn>.<T>, #0, the comparisons against nothing.
let private compareZero u opcode ins =
  match ins.Operands with
  | ThreeOperands(Vec(rd, t), Vec(rn, tn), Im 0L) ->
    sameArrangement ins t tn
    checkArrangement ins NotLone t
    let size, q = arrangement t
    twoRegWith u size opcode q rd rn
  | _ -> wrongOperands ins

/// The same, for floating-point elements, whose nothing is written as one.
let private compareZeroFP u hi opcode ins =
  match ins.Operands with
  | ThreeOperands(Vec(rd, t), Vec(rn, tn), OprFPImm 0.0) ->
    sameArrangement ins t tn
    let sz, q = floatArrangement t
    twoRegWith u ((hi <<< 1) ||| sz) opcode q rd rn
  | _ -> wrongOperands ins

/// <Vd>.<Ta>, <Vn>.<Tb>, the operations that write elements twice as wide as
/// the ones they read.
let private twoRegWidening u opcode ins =
  match ins.Operands with
  | TwoOperands(Vec(rd, t), Vec(rn, tn)) ->
    sameArrangement ins t (paired tn)
    checkArrangement ins NotLong tn
    let size, q = arrangement tn
    twoRegWith u size opcode q rd rn
  | _ -> wrongOperands ins

/// <Vd>.<Tb>, <Vn>.<Ta>, the operations that write elements half as wide as
/// the ones they read, of which the second half writes the top of its
/// destination and says so in its name.
let private twoRegNarrowing u opcode ins =
  match ins.Operands with
  | TwoOperands(Vec(rd, t), Vec(rn, tn)) ->
    sameArrangement ins (widened t) tn
    checkArrangement ins NotLong t
    let size, q = arrangement t
    twoRegWith u size opcode q rd rn
  | _ -> wrongOperands ins

/// The same, for the conversions between floating-point widths, which say only
/// whether the narrower of the two is a word.
let private convertNarrowing allowed u opcode ins =
  match ins.Operands with
  | TwoOperands(Vec(rd, t), Vec(rn, tn)) ->
    sameArrangement ins (widened t) tn
    checkArrangement ins allowed t
    let size, q = arrangement t
    twoRegWith u (size >>> 1) opcode q rd rn
  | _ -> wrongOperands ins

/// The same the other way round, which reads the narrower of the two.
let private convertWidening u opcode ins =
  match ins.Operands with
  | TwoOperands(Vec(rd, t), Vec(rn, tn)) ->
    sameArrangement ins t (widened tn)
    let size, q = arrangement tn
    twoRegWith u (size >>> 1) opcode q rd rn
  | _ -> wrongOperands ins

/// SHLL, which widens every element by shifting it up by its own width, and so
/// writes that width as the amount it shifts by.
let private shiftLong ins =
  match ins.Operands with
  | ThreeOperands(Vec(rd, t), Vec(rn, tn), OprShift(LSL, Imm amount)) ->
    sameArrangement ins t (widened tn)
    checkArrangement ins NotLong tn
    let size, q = arrangement tn
    if amount <> (8L <<< int size) then
      fail $"#{amount} is not how far {ins.Opcode} shifts {tn}"
    else twoRegWith 1u size 0b10011u q rd rn
  | _ -> wrongOperands ins

(* The operations that read every lane of one vector into one element. *)
/// The bits every one of them shares.
let private acrossWith u size opcode q rd rn =
  (q <<< 30) ||| (u <<< 29) ||| (0b01110u <<< 24) ||| (size <<< 22)
  ||| (0b11000u <<< 17) ||| (opcode <<< 12) ||| (0b10u <<< 10)
  ||| (vectorReg rn <<< 5) ||| rd

/// The width in bits of one element of an arrangement.
let private elementWidth vec = 8 <<< int (fst (arrangement vec))

/// <V><d>, <Vn>.<T>, whose destination is one element as wide as the ones it
/// read.
let private across u opcode ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Vec(rn, tn)) ->
    checkArrangement ins Across tn
    let size, q = arrangement tn
    acrossWith u size opcode q (simdReg (elementWidth tn) rd) rn
  | _ -> wrongOperands ins

/// The same, for the ones whose destination is twice as wide as what they
/// read.
let private acrossWidening u opcode ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Vec(rn, tn)) ->
    checkArrangement ins Across tn
    let size, q = arrangement tn
    acrossWith u size opcode q (simdReg (2 * elementWidth tn) rd) rn
  | _ -> wrongOperands ins

/// The same, for floating-point elements, of which they read four words.
let private acrossFP u hi opcode ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Vec(rn, tn)) ->
    checkArrangement ins FloatFourS tn
    let sz, q = floatArrangement tn
    acrossWith u ((hi <<< 1) ||| sz) opcode q (simdReg 32 rd) rn
  | _ -> wrongOperands ins

(* The operations that read and write elements of different widths. *)
/// The bits every one of them shares.
let private threeDiffWith u size opcode q rd rn rm =
  (q <<< 30) ||| (u <<< 29) ||| (0b01110u <<< 24) ||| (size <<< 22)
  ||| (1u <<< 21) ||| (vectorReg rm <<< 16) ||| (opcode <<< 12)
  ||| (vectorReg rn <<< 5) ||| vectorReg rd

/// <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>, which writes elements twice as wide as the
/// ones it reads.
let private threeDiffLong allowed u opcode ins =
  match ins.Operands with
  | ThreeOperands(Vec(rd, t), Vec(rn, tn), Vec(rm, tm)) ->
    sameArrangement ins tn tm
    sameArrangement ins t (widened tn)
    checkArrangement ins allowed tn
    let size, q = arrangement tn
    threeDiffWith u size opcode q rd rn rm
  | _ -> wrongOperands ins

/// <Vd>.<Ta>, <Vn>.<Ta>, <Vm>.<Tb>, which reads one source at the width it
/// writes and the other at half of it.
let private threeDiffWide u opcode ins =
  match ins.Operands with
  | ThreeOperands(Vec(rd, t), Vec(rn, tn), Vec(rm, tm)) ->
    sameArrangement ins t tn
    sameArrangement ins t (widened tm)
    checkArrangement ins NotLong tm
    let size, q = arrangement tm
    threeDiffWith u size opcode q rd rn rm
  | _ -> wrongOperands ins

/// <Vd>.<Tb>, <Vn>.<Ta>, <Vm>.<Ta>, which writes elements half as wide as the
/// ones it reads.
let private threeDiffNarrow u opcode ins =
  match ins.Operands with
  | ThreeOperands(Vec(rd, t), Vec(rn, tn), Vec(rm, tm)) ->
    sameArrangement ins tn tm
    sameArrangement ins (widened t) tn
    checkArrangement ins NotLong t
    let size, q = arrangement t
    threeDiffWith u size opcode q rd rn rm
  | _ -> wrongOperands ins

(* The operations that hold their second source as an immediate. *)
/// <summary>
/// The cmode and immediate fields of a modified immediate, which stand for a
/// byte placed somewhere in an element of the width the arrangement names.
///
/// Where the byte lands is written as the shift that puts it there, so what
/// arrives here is that shift; a shift that fills what it leaves behind with
/// ones is written as one of its own.
/// </summary>
let private modifiedImm ins vec shift =
  match vec, shift with
  | (EightB | SixteenB), None -> 0b1110u
  | (FourH | EightH), None -> 0b1000u
  | (FourH | EightH), Some(LSL, 0L) -> 0b1000u
  | (FourH | EightH), Some(LSL, 8L) -> 0b1010u
  | (TwoS | FourS), None -> 0b0000u
  | (TwoS | FourS), Some(LSL, 0L) -> 0b0000u
  | (TwoS | FourS), Some(LSL, 8L) -> 0b0010u
  | (TwoS | FourS), Some(LSL, 16L) -> 0b0100u
  | (TwoS | FourS), Some(LSL, 24L) -> 0b0110u
  | (TwoS | FourS), Some(MSL, 8L) -> 0b1100u
  | (TwoS | FourS), Some(MSL, 16L) -> 0b1101u
  | _ -> wrongOperands ins

/// The bits every one of them shares, where the byte it holds is split in two.
let private modImmWith q op cmode imm8 rd =
  (q <<< 30) ||| (op <<< 29) ||| (0b0111100000u <<< 19)
  ||| ((imm8 >>> 5) <<< 16) ||| (cmode <<< 12) ||| (1u <<< 10)
  ||| ((imm8 &&& 0b11111u) <<< 5) ||| rd

/// The shift written after a modified immediate, which is absent where the
/// byte lands at the bottom of its element.
let private immShift ins = function
  | [] -> None
  | [ OprShift(shift, Imm amount) ] -> Some(shift, amount)
  | _ -> wrongOperands ins

/// <summary>
/// &lt;Vd&gt;.&lt;T&gt;, #&lt;imm8&gt;{, LSL|MSL #&lt;amount&gt;}
///
/// The two that read what is already there rather than replacing it say so in
/// the bottom bit of the cmode field, which leaves them the two ways of placing
/// a byte that the bit does not name something else.
/// </summary>
let private modImm allowed op logical ins =
  match getOperandsAsList ins.Operands with
  | Vec(rd, t) :: Im imm :: rest ->
    checkArrangement ins allowed t
    let _, q = arrangement t
    let cmode = modifiedImm ins t (immShift ins rest)
    let cmode =
      if not logical then cmode
      elif cmode &&& 0b1001u = 0b0000u || cmode &&& 0b1101u = 0b1000u then
        cmode ||| 1u
      else wrongOperands ins
    modImmWith q op cmode (unsignedImm 8 imm) (vectorReg rd)
  | _ -> wrongOperands ins

/// <summary>
/// The byte a move of a long immediate holds, which stands for the whole of it
/// one bit per byte.
///
/// Only a value whose every byte is empty or full has such a byte, because
/// that is all the encoding can say.
/// </summary>
let private replicatedByte (value: int64) =
  let value = uint64 value
  let rec build acc index =
    if index = 8 then
      acc
    else
      match (value >>> (index * 8)) &&& 0xffUL with
      | 0UL -> build acc (index + 1)
      | 0xffUL -> build (acc ||| (1u <<< index)) (index + 1)
      | _ -> fail $"#{int64 value} is not a move of a long immediate"
  build 0u 0

/// MOVI of a doubleword, which fills each byte of its destination with either
/// nothing or everything, and so holds one bit per byte.
let private moveLongImm ins =
  match ins.Operands with
  | TwoOperands(Vec(rd, TwoD), Im imm) ->
    modImmWith 1u 1u 0b1110u (replicatedByte imm) (vectorReg rd)
  | TwoOperands(Rg rd, Im imm) ->
    modImmWith 0u 1u 0b1110u (replicatedByte imm) (simdReg 64 rd)
  | _ -> wrongOperands ins

/// <summary>
/// The eight bits a floating-point immediate stands for, which hold a sign, a
/// short exponent and four bits of significand.
///
/// The manual gives the expansion rather than its inverse, so this searches for
/// the byte that expands to the value asked for: there are only two hundred and
/// fifty-six of them, and no other byte expands to the same value.
/// </summary>
let floatImm (value: float) =
  let expand (imm8: uint32) =
    let sign = if imm8 &&& 0b10000000u = 0u then 1.0 else -1.0
    let exponent = (int ((imm8 >>> 4) &&& 0b111u) + 4) % 8 - 3
    let fraction = 1.0 + float (imm8 &&& 0b1111u) / 16.0
    sign * fraction * (2.0 ** float exponent)
  match [ 0u .. 255u ] |> List.tryFind (fun imm8 -> expand imm8 = value) with
  | Some imm8 -> imm8
  | None -> fail $"#{value} is not a floating-point immediate"

/// FMOV, which fills every lane of its destination with one value.
let moveFloatImm ins =
  match ins.Operands with
  | TwoOperands(Vec(rd, TwoD), OprFPImm value) ->
    modImmWith 1u 1u 0b1111u (floatImm value) (vectorReg rd)
  | TwoOperands(Vec(rd, t), OprFPImm value) ->
    checkArrangement ins Float t
    let _, q = arrangement t
    modImmWith q 0u 0b1111u (floatImm value) (vectorReg rd)
  | _ -> wrongOperands ins

(* The operations that shift by an immediate. *)
/// The bits every one of them shares, whose immh and immb fields say both how
/// wide the elements are and how far to shift them.
let private shiftImmWith u opcode q immhb rd rn =
  (q <<< 30) ||| (u <<< 29) ||| (0b011110u <<< 23) ||| (immhb <<< 16)
  ||| (opcode <<< 11) ||| (1u <<< 10) ||| (vectorReg rn <<< 5) ||| vectorReg rd

/// The immh and immb fields of a shift to the right, which hold what is left
/// of twice the width of one element once the shift has been taken off it.
let rightShift ins vec amount =
  let width = int64 (elementWidth vec)
  if amount < 1L || amount > width then
    fail $"a vector of {vec} cannot be shifted right by #{amount}"
  else uint32 (2L * width - amount)

/// The same for a shift to the left, which holds the width and the shift added
/// together.
let leftShift ins vec amount =
  let width = int64 (elementWidth vec)
  if amount < 0L || amount >= width then
    fail $"a vector of {vec} cannot be shifted left by #{amount}"
  else uint32 (width + amount)

/// <Vd>.<T>, <Vn>.<T>, #<shift>
let private shiftImm u opcode toField ins =
  match ins.Operands with
  | ThreeOperands(Vec(rd, t), Vec(rn, tn), Im amount) ->
    sameArrangement ins t tn
    checkArrangement ins NotLone t
    let _, q = arrangement t
    shiftImmWith u opcode q (toField ins t amount) rd rn
  | _ -> wrongOperands ins

/// <Vd>.<Tb>, <Vn>.<Ta>, #<shift>, which writes elements half as wide as the
/// ones it reads and counts the shift in the narrower of the two.
let private shiftImmNarrow u opcode ins =
  match ins.Operands with
  | ThreeOperands(Vec(rd, t), Vec(rn, tn), Im amount) ->
    sameArrangement ins (widened t) tn
    checkArrangement ins NotLong t
    let _, q = arrangement t
    shiftImmWith u opcode q (rightShift ins t amount) rd rn
  | _ -> wrongOperands ins

/// <Vd>.<Ta>, <Vn>.<Tb>, #<shift>, which writes elements twice as wide.
let private shiftImmLong u opcode ins =
  match ins.Operands with
  | ThreeOperands(Vec(rd, t), Vec(rn, tn), Im amount) ->
    sameArrangement ins t (widened tn)
    checkArrangement ins NotLong tn
    let _, q = arrangement tn
    shiftImmWith u opcode q (leftShift ins tn amount) rd rn
  | _ -> wrongOperands ins

/// <Vd>.<T>, <Vn>.<T>, #<fbits>, the conversions between a floating-point
/// element and one holding a fraction of that many bits.
let private convertFixed u opcode ins =
  match ins.Operands with
  | ThreeOperands(Vec(rd, t), Vec(rn, tn), Im amount) ->
    sameArrangement ins t tn
    checkArrangement ins Float t
    let _, q = arrangement t
    shiftImmWith u opcode q (rightShift ins t amount) rd rn
  | _ -> wrongOperands ins

(* The operations that read one element of their second source. *)
/// <summary>
/// The fields that name one element of the second source.
///
/// Which of them holds what depends on how wide the element is: a halfword
/// leaves only four bits to name the register, because the fifth is the bit the
/// index needs, while a word has the whole register field and two bits of index
/// above it.
/// </summary>
let indexedSource ins vec (reg: Register) (index: uint8) =
  let number = vectorReg reg
  let index = uint32 index
  match vec with
  | VecH when number < 16u && index < 8u ->
    0b01u, ((index &&& 0b11u) <<< 20) ||| (number <<< 16)
           ||| ((index >>> 2) <<< 11)
  | VecS when index < 4u ->
    0b10u, ((index &&& 0b1u) <<< 21) ||| (number <<< 16)
           ||| ((index >>> 1) <<< 11)
  | VecD when index < 2u -> 0b11u, (number <<< 16) ||| (index <<< 11)
  | _ -> wrongOperands ins

/// The bits every one of them shares.
let private indexedWith u opcode q size source rd rn =
  (q <<< 30) ||| (u <<< 29) ||| (0b01111u <<< 24) ||| (size <<< 22) ||| source
  ||| (opcode <<< 12) ||| (vectorReg rn <<< 5) ||| vectorReg rd

/// <Vd>.<T>, <Vn>.<T>, <Vm>.<Ts>[<index>]
let private indexed u opcode ins =
  match ins.Operands with
  | ThreeOperands(Vec(rd, t), Vec(rn, tn), Elem(rm, vec, index)) ->
    sameArrangement ins t tn
    checkArrangement ins HalfAndWord t
    let size, q = arrangement t
    let selected, source = indexedSource ins vec rm index
    if size <> selected then wrongOperands ins
    else indexedWith u opcode q size source rd rn
  | _ -> wrongOperands ins

/// The same, for floating-point elements, whose size field says only whether
/// they are doublewords.
let private indexedFP u opcode ins =
  match ins.Operands with
  | ThreeOperands(Vec(rd, t), Vec(rn, tn), Elem(rm, vec, index)) ->
    sameArrangement ins t tn
    let sz, q = floatArrangement t
    let selected, source = indexedSource ins vec rm index
    if selected <> (0b10u ||| sz) then wrongOperands ins
    else indexedWith u opcode q (0b10u ||| sz) source rd rn
  | _ -> wrongOperands ins

/// <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Ts>[<index>], which writes elements twice as
/// wide as the ones it reads.
let private indexedLong u opcode ins =
  match ins.Operands with
  | ThreeOperands(Vec(rd, t), Vec(rn, tn), Elem(rm, vec, index)) ->
    sameArrangement ins t (widened tn)
    checkArrangement ins HalfAndWord tn
    let size, q = arrangement tn
    let selected, source = indexedSource ins vec rm index
    if size <> selected then wrongOperands ins
    else indexedWith u opcode q size source rd rn
  | _ -> wrongOperands ins

/// The instructions that scramble the bytes of one register, which name no
/// element width of their own.
let private crypto opcode ins =
  match ins.Operands with
  | TwoOperands(Vec(rd, SixteenB), Vec(rn, SixteenB)) ->
    (0b01001110u <<< 24) ||| (0b10100u <<< 17) ||| (opcode <<< 12)
    ||| (0b10u <<< 10) ||| (vectorReg rn <<< 5) ||| vectorReg rd
  | _ -> wrongOperands ins

/// <summary>
/// The operations written under one name in more than one of these families,
/// which say which of them they are by what their last operand is: another
/// whole vector, one element of one, or a number.
/// </summary>
let private byLastOperand vector element immediate ins =
  match List.tryLast (getOperandsAsList ins.Operands) with
  | Some(Elem _) -> element ins
  | Some(Vec _) -> vector ins
  | _ -> immediate ins

/// The comparisons, which read either another vector or nothing at all.
let private compare allowed u opcode zeroU zeroOpcode =
  byLastOperand (threeSame allowed u opcode) wrongOperands
                (compareZero zeroU zeroOpcode)

/// The same, for floating-point elements.
let private compareFP u hi opcode zeroU zeroHi zeroOpcode =
  byLastOperand (threeSameFP u hi opcode) wrongOperands
                (compareZeroFP zeroU zeroHi zeroOpcode)

/// The saturating shifts, which shift by either a register or an immediate.
let private saturatingShift u sameOpcode shiftOpcode =
  byLastOperand (threeSame NotLone u sameOpcode) wrongOperands
                (shiftImm u shiftOpcode leftShift)

/// The conversions between a floating-point element and a whole number, which
/// read the fraction they keep as an immediate where they keep one at all.
let private convert u hi opcode fixedOpcode =
  byLastOperand (twoRegFP Float u hi opcode) wrongOperands
                (convertFixed u fixedOpcode)

/// The multiplies, which read either the whole of their second source or one
/// element of it. Which half of the family a name is in is not the same in the
/// two forms, so each has its own U bit.
let private multiply allowed u opcode indexU indexOpcode =
  byLastOperand (threeSame allowed u opcode) (indexed indexU indexOpcode)
                wrongOperands

/// The same, for the ones whose result is twice as wide as what they read.
let private multiplyLong allowed u opcode indexOpcode =
  byLastOperand (threeDiffLong allowed u opcode) (indexedLong u indexOpcode)
                wrongOperands

/// The same, for floating-point elements.
let private multiplyFP u hi opcode indexU indexOpcode =
  byLastOperand (threeSameFP u hi opcode) (indexedFP indexU indexOpcode)
                wrongOperands

/// ORR and BIC, which read either another vector or a byte placed somewhere in
/// each of their elements.
let private inclusiveOr =
  byLastOperand (threeSameLogical 0u 0b10u) wrongOperands
                (modImm HalfAndWord 0u true)

let private bitClear = byLastOperand (threeSameLogical 0u 0b01u) wrongOperands
                                     (modImm HalfAndWord 1u true)

/// MOVI, whose longest immediate stands for a whole doubleword rather than for
/// a byte of one.
let private moveImm ins =
  match ins.Operands with
  | TwoOperands(Vec(_, TwoD), _) | TwoOperands(OprSIMD(ScalarReg _), _) ->
    moveLongImm ins
  | _ -> modImm Any 0u false ins

/// <summary>
/// MOV, which the manual defines as three instructions: an inclusive or of a
/// register with itself, a read of one element into a general register, and a
/// write of one element from another.
/// </summary>
let move ins =
  match ins.Operands with
  | TwoOperands(Vec(rd, t), Vec(rn, _)) ->
    threeSameLogical 0u 0b10u
      { ins with Operands = ThreeOperands(OprSIMD(VecReg(rd, t)),
                                          OprSIMD(VecReg(rn, t)),
                                          OprSIMD(VecReg(rn, t))) }
  | TwoOperands(Rg _, Elem _) -> moveToGeneral false 0b0111u ins
  | _ -> insert ins

let vectorEncoders () =
  [ Opcode.SHADD, threeSame NotLong 0u 0b00000u
    Opcode.SQADD, threeSame NotLone 0u 0b00001u
    Opcode.SRHADD, threeSame NotLong 0u 0b00010u
    Opcode.SHSUB, threeSame NotLong 0u 0b00100u
    Opcode.SQSUB, threeSame NotLone 0u 0b00101u
    Opcode.SSHL, threeSame NotLone 0u 0b01000u
    Opcode.SRSHL, threeSame NotLone 0u 0b01010u
    Opcode.SQRSHL, threeSame NotLone 0u 0b01011u
    Opcode.SMAX, threeSame NotLong 0u 0b01100u
    Opcode.SMIN, threeSame NotLong 0u 0b01101u
    Opcode.SABD, threeSame NotLong 0u 0b01110u
    Opcode.SABA, threeSame NotLong 0u 0b01111u
    Opcode.CMTST, threeSame NotLone 0u 0b10001u
    Opcode.SMAXP, threeSame NotLong 0u 0b10100u
    Opcode.SMINP, threeSame NotLong 0u 0b10101u
    Opcode.SQDMULH, threeSame HalfAndWord 0u 0b10110u
    Opcode.ADDP, threeSame NotLone 0u 0b10111u
    Opcode.UHADD, threeSame NotLong 1u 0b00000u
    Opcode.UQADD, threeSame NotLone 1u 0b00001u
    Opcode.URHADD, threeSame NotLong 1u 0b00010u
    Opcode.UHSUB, threeSame NotLong 1u 0b00100u
    Opcode.UQSUB, threeSame NotLone 1u 0b00101u
    Opcode.CMHI, threeSame NotLone 1u 0b00110u
    Opcode.CMHS, threeSame NotLone 1u 0b00111u
    Opcode.USHL, threeSame NotLone 1u 0b01000u
    Opcode.URSHL, threeSame NotLone 1u 0b01010u
    Opcode.UQRSHL, threeSame NotLone 1u 0b01011u
    Opcode.UMAX, threeSame NotLong 1u 0b01100u
    Opcode.UMIN, threeSame NotLong 1u 0b01101u
    Opcode.UABD, threeSame NotLong 1u 0b01110u
    Opcode.UABA, threeSame NotLong 1u 0b01111u
    Opcode.PMUL, threeSame ByteOnly 1u 0b10011u
    Opcode.UMAXP, threeSame NotLong 1u 0b10100u
    Opcode.UMINP, threeSame NotLong 1u 0b10101u
    Opcode.SQRDMULH, threeSame HalfAndWord 1u 0b10110u
    Opcode.FMAXNM, threeSameFP 0u 0u 0b11000u
    Opcode.FADD, threeSameFP 0u 0u 0b11010u
    Opcode.FMULX, threeSameFP 0u 0u 0b11011u
    Opcode.FMAX, threeSameFP 0u 0u 0b11110u
    Opcode.FRECPS, threeSameFP 0u 0u 0b11111u
    Opcode.FMINNM, threeSameFP 0u 1u 0b11000u
    Opcode.FSUB, threeSameFP 0u 1u 0b11010u
    Opcode.FMIN, threeSameFP 0u 1u 0b11110u
    Opcode.FRSQRTS, threeSameFP 0u 1u 0b11111u
    Opcode.FMAXNMP, threeSameFP 1u 0u 0b11000u
    Opcode.FADDP, threeSameFP 1u 0u 0b11010u
    Opcode.FACGE, threeSameFP 1u 0u 0b11101u
    Opcode.FMAXP, threeSameFP 1u 0u 0b11110u
    Opcode.FDIV, threeSameFP 1u 0u 0b11111u
    Opcode.FMINNMP, threeSameFP 1u 1u 0b11000u
    Opcode.FABD, threeSameFP 1u 1u 0b11010u
    Opcode.FACGT, threeSameFP 1u 1u 0b11101u
    Opcode.FMINP, threeSameFP 1u 1u 0b11110u
    Opcode.BSL, threeSameLogical 1u 0b01u
    Opcode.BIT, threeSameLogical 1u 0b10u
    Opcode.BIF, threeSameLogical 1u 0b11u
    Opcode.UZP1, permute 0b001u
    Opcode.TRN1, permute 0b010u
    Opcode.ZIP1, permute 0b011u
    Opcode.UZP2, permute 0b101u
    Opcode.TRN2, permute 0b110u
    Opcode.ZIP2, permute 0b111u
    Opcode.EXT, extract
    Opcode.TBL, tableLookup 0u
    Opcode.TBX, tableLookup 1u
    Opcode.DUP, duplicate
    Opcode.SMOV, moveToGeneral true 0b0101u
    Opcode.UMOV, moveToGeneral false 0b0111u
    Opcode.INS, insert
    Opcode.REV64, twoReg NotLone 0u 0b00000u
    Opcode.REV16, twoReg ByteOnly 0u 0b00001u
    Opcode.SUQADD, twoReg NotLong 0u 0b00011u
    Opcode.CLS, twoReg NotLong 0u 0b00100u
    Opcode.CNT, twoReg ByteOnly 0u 0b00101u
    Opcode.SQABS, twoReg NotLone 0u 0b00111u
    Opcode.ABS, twoReg NotLone 0u 0b01011u
    Opcode.REV32, twoReg UpToHalf 1u 0b00000u
    Opcode.USQADD, twoReg NotLone 1u 0b00011u
    Opcode.CLZ, twoReg NotLong 1u 0b00100u
    Opcode.SQNEG, twoReg NotLone 1u 0b00111u
    Opcode.NEG, twoReg NotLone 1u 0b01011u
    Opcode.MVN, twoRegLogical 1u 0b00u 0b00101u
    Opcode.RBIT, twoRegLogical 1u 0b01u 0b00101u
    Opcode.SADDLP, twoRegWidening 0u 0b00010u
    Opcode.SADALP, twoRegWidening 0u 0b00110u
    Opcode.UADDLP, twoRegWidening 1u 0b00010u
    Opcode.UADALP, twoRegWidening 1u 0b00110u
    Opcode.XTN, twoRegNarrowing 0u 0b10010u
    Opcode.XTN2, twoRegNarrowing 0u 0b10010u
    Opcode.SQXTN, twoRegNarrowing 0u 0b10100u
    Opcode.SQXTN2, twoRegNarrowing 0u 0b10100u
    Opcode.SQXTUN, twoRegNarrowing 1u 0b10010u
    Opcode.SQXTUN2, twoRegNarrowing 1u 0b10010u
    Opcode.UQXTN, twoRegNarrowing 1u 0b10100u
    Opcode.UQXTN2, twoRegNarrowing 1u 0b10100u
    Opcode.SHLL, shiftLong
    Opcode.SHLL2, shiftLong
    Opcode.FCVTN, convertNarrowing Any 0u 0b10110u
    Opcode.FCVTN2, convertNarrowing Any 0u 0b10110u
    Opcode.FCVTXN, convertNarrowing FloatWord 1u 0b10110u
    Opcode.FCVTXN2, convertNarrowing FloatWord 1u 0b10110u
    Opcode.FCVTL, convertWidening 0u 0b10111u
    Opcode.FCVTL2, convertWidening 0u 0b10111u
    Opcode.FRINTN, twoRegFP Float 0u 0u 0b11000u
    Opcode.FRINTM, twoRegFP Float 0u 0u 0b11001u
    Opcode.FCVTNS, twoRegFP Float 0u 0u 0b11010u
    Opcode.FCVTMS, twoRegFP Float 0u 0u 0b11011u
    Opcode.FCVTAS, twoRegFP Float 0u 0u 0b11100u
    Opcode.FABS, twoRegFP Float 0u 1u 0b01111u
    Opcode.FRINTP, twoRegFP Float 0u 1u 0b11000u
    Opcode.FRINTZ, twoRegFP Float 0u 1u 0b11001u
    Opcode.FCVTPS, twoRegFP Float 0u 1u 0b11010u
    Opcode.URECPE, twoRegFP FloatWord 0u 1u 0b11100u
    Opcode.FRECPE, twoRegFP Float 0u 1u 0b11101u
    Opcode.FRINTA, twoRegFP Float 1u 0u 0b11000u
    Opcode.FRINTX, twoRegFP Float 1u 0u 0b11001u
    Opcode.FCVTNU, twoRegFP Float 1u 0u 0b11010u
    Opcode.FCVTMU, twoRegFP Float 1u 0u 0b11011u
    Opcode.FCVTAU, twoRegFP Float 1u 0u 0b11100u
    Opcode.FNEG, twoRegFP Float 1u 1u 0b01111u
    Opcode.FRINTI, twoRegFP Float 1u 1u 0b11001u
    Opcode.FCVTPU, twoRegFP Float 1u 1u 0b11010u
    Opcode.URSQRTE, twoRegFP FloatWord 1u 1u 0b11100u
    Opcode.FRSQRTE, twoRegFP Float 1u 1u 0b11101u
    Opcode.FSQRT, twoRegFP Float 1u 1u 0b11111u
    Opcode.CMLT, compareZero 0u 0b01010u
    Opcode.CMLE, compareZero 1u 0b01001u
    Opcode.SADDLV, acrossWidening 0u 0b00011u
    Opcode.SMAXV, across 0u 0b01010u
    Opcode.SMINV, across 0u 0b11010u
    Opcode.ADDV, across 0u 0b11011u
    Opcode.UADDLV, acrossWidening 1u 0b00011u
    Opcode.UMAXV, across 1u 0b01010u
    Opcode.UMINV, across 1u 0b11010u
    Opcode.FMAXNMV, acrossFP 1u 0u 0b01100u
    Opcode.FMAXV, acrossFP 1u 0u 0b01111u
    Opcode.FMINNMV, acrossFP 1u 1u 0b01100u
    Opcode.FMINV, acrossFP 1u 1u 0b01111u
    Opcode.SADDL, threeDiffLong NotLong 0u 0b0000u
    Opcode.SADDL2, threeDiffLong NotLong 0u 0b0000u
    Opcode.SSUBL, threeDiffLong NotLong 0u 0b0010u
    Opcode.SSUBL2, threeDiffLong NotLong 0u 0b0010u
    Opcode.SABAL, threeDiffLong NotLong 0u 0b0101u
    Opcode.SABAL2, threeDiffLong NotLong 0u 0b0101u
    Opcode.SABDL, threeDiffLong NotLong 0u 0b0111u
    Opcode.SABDL2, threeDiffLong NotLong 0u 0b0111u
    Opcode.PMULL, threeDiffLong ByteAndLong 0u 0b1110u
    Opcode.PMULL2, threeDiffLong ByteAndLong 0u 0b1110u
    Opcode.UADDL, threeDiffLong NotLong 1u 0b0000u
    Opcode.UADDL2, threeDiffLong NotLong 1u 0b0000u
    Opcode.USUBL, threeDiffLong NotLong 1u 0b0010u
    Opcode.USUBL2, threeDiffLong NotLong 1u 0b0010u
    Opcode.UABAL, threeDiffLong NotLong 1u 0b0101u
    Opcode.UABAL2, threeDiffLong NotLong 1u 0b0101u
    Opcode.UABDL, threeDiffLong NotLong 1u 0b0111u
    Opcode.UABDL2, threeDiffLong NotLong 1u 0b0111u
    Opcode.SADDW, threeDiffWide 0u 0b0001u
    Opcode.SADDW2, threeDiffWide 0u 0b0001u
    Opcode.SSUBW, threeDiffWide 0u 0b0011u
    Opcode.SSUBW2, threeDiffWide 0u 0b0011u
    Opcode.UADDW, threeDiffWide 1u 0b0001u
    Opcode.UADDW2, threeDiffWide 1u 0b0001u
    Opcode.USUBW, threeDiffWide 1u 0b0011u
    Opcode.USUBW2, threeDiffWide 1u 0b0011u
    Opcode.ADDHN, threeDiffNarrow 0u 0b0100u
    Opcode.ADDHN2, threeDiffNarrow 0u 0b0100u
    Opcode.SUBHN, threeDiffNarrow 0u 0b0110u
    Opcode.SUBHN2, threeDiffNarrow 0u 0b0110u
    Opcode.RADDHN, threeDiffNarrow 1u 0b0100u
    Opcode.RADDHN2, threeDiffNarrow 1u 0b0100u
    Opcode.RSUBHN, threeDiffNarrow 1u 0b0110u
    Opcode.RSUBHN2, threeDiffNarrow 1u 0b0110u
    Opcode.MOVI, moveImm
    Opcode.MVNI, modImm HalfAndWord 1u false
    Opcode.AND, threeSameLogical 0u 0b00u
    Opcode.ORN, threeSameLogical 0u 0b11u
    Opcode.EOR, threeSameLogical 1u 0b00u
    Opcode.ORR, inclusiveOr
    Opcode.BIC, bitClear
    Opcode.ADD, threeSame NotLone 0u 0b10000u
    Opcode.SUB, threeSame NotLone 1u 0b10000u
    Opcode.CMGT, compare NotLone 0u 0b00110u 0u 0b01000u
    Opcode.CMGE, compare NotLone 0u 0b00111u 1u 0b01000u
    Opcode.CMEQ, compare NotLone 1u 0b10001u 0u 0b01001u
    Opcode.FCMEQ, compareFP 0u 0u 0b11100u 0u 1u 0b01101u
    Opcode.FCMGE, compareFP 1u 0u 0b11100u 1u 1u 0b01100u
    Opcode.FCMGT, compareFP 1u 1u 0b11100u 0u 1u 0b01100u
    Opcode.FCMLE, compareZeroFP 1u 1u 0b01101u
    Opcode.FCMLT, compareZeroFP 0u 1u 0b01110u
    Opcode.SQSHL, saturatingShift 0u 0b01001u 0b01110u
    Opcode.UQSHL, saturatingShift 1u 0b01001u 0b01110u
    Opcode.SCVTF, convert 0u 0u 0b11101u 0b11100u
    Opcode.UCVTF, convert 1u 0u 0b11101u 0b11100u
    Opcode.FCVTZS, convert 0u 1u 0b11011u 0b11111u
    Opcode.FCVTZU, convert 1u 1u 0b11011u 0b11111u
    Opcode.MUL, multiply NotLong 0u 0b10011u 0u 0b1000u
    Opcode.MLA, multiply NotLong 0u 0b10010u 1u 0b0000u
    Opcode.MLS, multiply NotLong 1u 0b10010u 1u 0b0100u
    Opcode.SQDMULH, multiply HalfAndWord 0u 0b10110u 0u 0b1100u
    Opcode.SQRDMULH, multiply HalfAndWord 1u 0b10110u 0u 0b1101u
    Opcode.SMLAL, multiplyLong NotLong 0u 0b1000u 0b0010u
    Opcode.SMLAL2, multiplyLong NotLong 0u 0b1000u 0b0010u
    Opcode.SMLSL, multiplyLong NotLong 0u 0b1010u 0b0110u
    Opcode.SMLSL2, multiplyLong NotLong 0u 0b1010u 0b0110u
    Opcode.SMULL, multiplyLong NotLong 0u 0b1100u 0b1010u
    Opcode.SMULL2, multiplyLong NotLong 0u 0b1100u 0b1010u
    Opcode.SQDMLAL, multiplyLong HalfAndWord 0u 0b1001u 0b0011u
    Opcode.SQDMLSL, multiplyLong HalfAndWord 0u 0b1011u 0b0111u
    Opcode.SQDMULL, multiplyLong HalfAndWord 0u 0b1101u 0b1011u
    Opcode.SQDMLAL2, multiplyLong HalfAndWord 0u 0b1001u 0b0011u
    Opcode.SQDMLSL2, multiplyLong HalfAndWord 0u 0b1011u 0b0111u
    Opcode.SQDMULL2, multiplyLong HalfAndWord 0u 0b1101u 0b1011u
    Opcode.UMLAL, multiplyLong NotLong 1u 0b1000u 0b0010u
    Opcode.UMLAL2, multiplyLong NotLong 1u 0b1000u 0b0010u
    Opcode.UMLSL, multiplyLong NotLong 1u 0b1010u 0b0110u
    Opcode.UMLSL2, multiplyLong NotLong 1u 0b1010u 0b0110u
    Opcode.UMULL, multiplyLong NotLong 1u 0b1100u 0b1010u
    Opcode.UMULL2, multiplyLong NotLong 1u 0b1100u 0b1010u
    Opcode.FMLA, multiplyFP 0u 0u 0b11001u 0u 0b0001u
    Opcode.FMLS, multiplyFP 0u 1u 0b11001u 0u 0b0101u
    Opcode.FMUL, multiplyFP 1u 0u 0b11011u 0u 0b1001u
    Opcode.FMULX, multiplyFP 0u 0u 0b11011u 1u 0b1001u
    Opcode.SSHR, shiftImm 0u 0b00000u rightShift
    Opcode.SSRA, shiftImm 0u 0b00010u rightShift
    Opcode.SRSHR, shiftImm 0u 0b00100u rightShift
    Opcode.SRSRA, shiftImm 0u 0b00110u rightShift
    Opcode.SHL, shiftImm 0u 0b01010u leftShift
    Opcode.USHR, shiftImm 1u 0b00000u rightShift
    Opcode.USRA, shiftImm 1u 0b00010u rightShift
    Opcode.URSHR, shiftImm 1u 0b00100u rightShift
    Opcode.URSRA, shiftImm 1u 0b00110u rightShift
    Opcode.SRI, shiftImm 1u 0b01000u rightShift
    Opcode.SLI, shiftImm 1u 0b01010u leftShift
    Opcode.SQSHLU, shiftImm 1u 0b01100u leftShift
    Opcode.SHRN, shiftImmNarrow 0u 0b10000u
    Opcode.SHRN2, shiftImmNarrow 0u 0b10000u
    Opcode.RSHRN, shiftImmNarrow 0u 0b10001u
    Opcode.RSHRN2, shiftImmNarrow 0u 0b10001u
    Opcode.SQSHRN, shiftImmNarrow 0u 0b10010u
    Opcode.SQSHRN2, shiftImmNarrow 0u 0b10010u
    Opcode.SQRSHRN, shiftImmNarrow 0u 0b10011u
    Opcode.SQRSHRN2, shiftImmNarrow 0u 0b10011u
    Opcode.SQSHRUN, shiftImmNarrow 1u 0b10000u
    Opcode.SQSHRUN2, shiftImmNarrow 1u 0b10000u
    Opcode.SQRSHRUN, shiftImmNarrow 1u 0b10001u
    Opcode.SQRSHRUN2, shiftImmNarrow 1u 0b10001u
    Opcode.UQSHRN, shiftImmNarrow 1u 0b10010u
    Opcode.UQSHRN2, shiftImmNarrow 1u 0b10010u
    Opcode.UQRSHRN, shiftImmNarrow 1u 0b10011u
    Opcode.UQRSHRN2, shiftImmNarrow 1u 0b10011u
    Opcode.SSHLL, shiftImmLong 0u 0b10100u
    Opcode.SSHLL2, shiftImmLong 0u 0b10100u
    Opcode.USHLL, shiftImmLong 1u 0b10100u
    Opcode.USHLL2, shiftImmLong 1u 0b10100u
    Opcode.AESE, crypto 0b00100u
    Opcode.AESD, crypto 0b00101u
    Opcode.AESMC, crypto 0b00110u
    Opcode.AESIMC, crypto 0b00111u
    Opcode.MOV, move ]
