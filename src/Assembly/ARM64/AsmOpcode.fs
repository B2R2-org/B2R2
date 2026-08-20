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
/// Encodes one instruction into the A64 word that means it. Every encoder here
/// takes the instruction as the source wrote it and returns that word, so the
/// families whose members differ only in a few bits are one function applied to
/// different bits rather than one function each.
/// </summary>
module internal B2R2.Assembly.ARM64.AsmOpcode

open B2R2.FrontEnd.ARM64
open B2R2.Assembly.ARM64.ParserHelper
open B2R2.Assembly.ARM64.AsmField

/// A place the instruction names, which arrives here as the distance to it.
let private (|Place|_|) = function
  | OprMemory(LiteralMode(ImmOffset(Lbl offset))) -> Some offset
  | _ -> None

let private isStackPointer reg = reg = Register.SP || reg = Register.WSP

/// The width in bits an instruction works in, which its registers say.
let private widthOf reg = if is64Reg reg then 64 else 32

(* Data processing - immediate. *)
/// The "lsl #<amount>" written after an immediate, which is absent when the
/// immediate is not shifted at all.
let private lslAmount ins = function
  | [] -> 0L
  | [ OprShift(LSL, Imm amount) ] -> amount
  | _ -> wrongOperands ins

/// ADR and ADRP, which name a place rather than a value. How far away that
/// place is was worked out before encoding, so what arrives here is a distance:
/// for ADRP the distance between the page this instruction sits in and the one
/// it names.
let private pcRelative isPage ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Place offset) ->
    let offset = if isPage then scaled 4096 offset else offset
    let imm = signedImm 21 offset
    (if isPage then 1u <<< 31 else 0u) ||| ((imm &&& 0b11u) <<< 29)
    ||| (0b10000u <<< 24) ||| ((imm >>> 2) <<< 5) ||| coreReg rd
  | _ ->
    wrongOperands ins

/// The bits an add or subtract of an immediate shares, given the destination
/// field its own form supplies.
let private addSubImmWith op s ins rd rn imm rest =
  let shift =
    match lslAmount ins rest with
    | 0L -> 0u
    | 12L -> 1u
    | amount -> fail $"an immediate cannot be shifted by #{amount}"
  (op <<< 30) ||| (s <<< 29) ||| (0b100010u <<< 23) ||| (shift <<< 22)
  ||| (unsignedImm 12 imm <<< 10) ||| (coreRegSP rn <<< 5) ||| rd

/// <Rd|SP>, <Rn|SP>, #<imm>{, LSL #12}
let private addSubImm op ins =
  match getOperandsAsList ins.Operands with
  | Rg rd :: Rg rn :: Im imm :: rest ->
    sfBit rd ||| addSubImmWith op 0u ins (coreRegSP rd) rn imm rest
  | _ ->
    wrongOperands ins

/// <Rd>, <Rn|SP>, #<imm>{, LSL #12}, the form that sets the flags.
let private addSubImmFlags op ins =
  match getOperandsAsList ins.Operands with
  | Rg rd :: Rg rn :: Im imm :: rest ->
    sfBit rd ||| addSubImmWith op 1u ins (coreReg rd) rn imm rest
  | _ ->
    wrongOperands ins

/// <Rn|SP>, #<imm>{, LSL #12}, the form that only sets them.
let private compareImm op ins =
  match getOperandsAsList ins.Operands with
  | Rg rn :: Im imm :: rest ->
    sfBit rn ||| addSubImmWith op 1u ins 31u rn imm rest
  | _ ->
    wrongOperands ins

/// The bits a logical instruction that takes an immediate shares.
let private logicalImmWith opc ins rd rn imm =
  let n, immr, imms = logicalImm (widthOf rn) imm
  (opc <<< 29) ||| (0b100100u <<< 23) ||| (n <<< 22) ||| (immr <<< 16)
  ||| (imms <<< 10) ||| (coreReg rn <<< 5) ||| rd

/// <Rd|SP>, <Rn>, #<imm>
let private logicalImmediate opc ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rn, Im imm) ->
    sfBit rd ||| logicalImmWith opc ins (coreRegSP rd) rn imm
  | _ ->
    wrongOperands ins

/// <Rd>, <Rn>, #<imm>, the form that sets the flags.
let private logicalImmediateFlags opc ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rn, Im imm) ->
    sfBit rd ||| logicalImmWith opc ins (coreReg rd) rn imm
  | _ ->
    wrongOperands ins

/// The hw field, which says which sixteen bits of the register an immediate
/// lands in. A thirty-two bit move reaches only the lower half of the register,
/// so only half the values name a place in it.
let private halfwordShift is64 amount =
  match amount with
  | 0L -> 0u
  | 16L -> 1u
  | 32L when is64 -> 2u
  | 48L when is64 -> 3u
  | amount -> fail $"a wide immediate cannot be shifted by #{amount}"

/// <Rd>, #<imm>{, LSL #<amount>}
let private moveWide opc ins =
  match getOperandsAsList ins.Operands with
  | Rg rd :: Im imm :: rest ->
    let hw = halfwordShift (is64Reg rd) (lslAmount ins rest)
    sfBit rd ||| (opc <<< 29) ||| (0b100101u <<< 23) ||| (hw <<< 21)
    ||| (unsignedImm 16 imm <<< 5) ||| coreReg rd
  | _ ->
    wrongOperands ins

/// The bits a bitfield move shares. The N bit repeats what the width says,
/// because the field it names is as wide as the register.
let private bitfieldWith opc rd rn immr imms =
  let is64 = is64Reg rd
  sfBit rd ||| (opc <<< 29) ||| (0b100110u <<< 23)
  ||| ((if is64 then 1u else 0u) <<< 22) ||| (unsignedImm 6 immr <<< 16)
  ||| (unsignedImm 6 imms <<< 10) ||| (coreReg rn <<< 5) ||| coreReg rd

/// <Rd>, <Rn>, #<immr>, #<imms>
let private bitfield opc ins =
  match ins.Operands with
  | FourOperands(Rg rd, Rg rn, Im immr, Im imms) ->
    bitfieldWith opc rd rn immr imms
  | _ ->
    wrongOperands ins

/// The bitfield move a "start here, this many bits" alias stands for, whose
/// encoding says where the field ends rather than how long it is.
let private bitfieldInsert opc ins =
  match ins.Operands with
  | FourOperands(Rg rd, Rg rn, Im lsb, Im width) ->
    let bits = int64 (widthOf rd)
    if width < 1L || lsb + width > bits then
      fail $"a field of #{width} bits cannot start at #{lsb}"
    else
      bitfieldWith opc rd rn ((bits - lsb) % bits) (width - 1L)
  | _ ->
    wrongOperands ins

/// The same for the aliases that take the field where it lies rather than
/// moving it down to the bottom of the register.
let private bitfieldExtract opc ins =
  match ins.Operands with
  | FourOperands(Rg rd, Rg rn, Im lsb, Im width) ->
    let bits = int64 (widthOf rd)
    if width < 1L || lsb + width > bits then
      fail $"a field of #{width} bits cannot start at #{lsb}"
    else
      bitfieldWith opc rd rn lsb (lsb + width - 1L)
  | _ ->
    wrongOperands ins

/// The extensions, which the manual defines as bitfield moves of the bottom
/// byte, halfword or word of a register.
let private extendAlias opc imms ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Rg rn) -> bitfieldWith opc rd rn 0L imms
  | _ -> wrongOperands ins

/// The bits an extraction shares, which reads one field spanning two registers.
let private extractWith rd rn rm lsb =
  let is64 = is64Reg rd
  sfBit rd ||| (0b100111u <<< 23) ||| ((if is64 then 1u else 0u) <<< 22)
  ||| (coreReg rm <<< 16) ||| (unsignedImm 6 lsb <<< 10) ||| (coreReg rn <<< 5)
  ||| coreReg rd

let private extract ins =
  match ins.Operands with
  | FourOperands(Rg rd, Rg rn, Rg rm, Im lsb) -> extractWith rd rn rm lsb
  | _ -> wrongOperands ins

(* Data processing - register. *)
/// The shift written after the second source of a logical or arithmetic
/// instruction, which is absent when it shifts by nothing.
let private shiftOf ins = function
  | [] -> LSL, 0L
  | [ OprShift(shift, Imm amount) ] -> shift, amount
  | _ -> wrongOperands ins

/// The bits every logical instruction on a shifted register shares.
let private logicalShiftedWith opc n ins rd rn rm rest =
  let shift, amount = shiftOf ins rest
  let width = if is64Reg rd then 6 else 5
  sfBit rd ||| (opc <<< 29) ||| (0b01010u <<< 24) ||| (shiftType shift <<< 22)
  ||| (n <<< 21) ||| (coreReg rm <<< 16) ||| (unsignedImm width amount <<< 10)
  ||| (coreReg rn <<< 5) ||| coreReg rd

/// <Rd>, <Rn>, <Rm>{, <shift> #<amount>}
let private logicalShifted opc n ins =
  match getOperandsAsList ins.Operands with
  | Rg rd :: Rg rn :: Rg rm :: rest ->
    logicalShiftedWith opc n ins rd rn rm rest
  | _ ->
    wrongOperands ins

/// The bits an addition or subtraction of a shifted register shares.
let private addSubShiftedWith op s ins rd rn rm rest =
  let shift, amount = shiftOf ins rest
  let width = if is64Reg rd then 6 else 5
  if shift = ROR then
    fail "an addition cannot rotate its second source"
  else
    sfBit rd ||| (op <<< 30) ||| (s <<< 29) ||| (0b01011u <<< 24)
    ||| (shiftType shift <<< 22) ||| (coreReg rm <<< 16)
    ||| (unsignedImm width amount <<< 10) ||| (coreReg rn <<< 5) ||| coreReg rd

/// The extension written after the second source, which says which part of it
/// to read and how far to shift what was read.
let private extendOf ins is64 = function
  | [] -> (if is64 then UXTX else UXTW), 0L
  | [ OprExtReg(Some(ExtRegOffset(ext, amount))) ] -> ext, defaultArg amount 0L
  | [ OprExtReg(Some(ShiftOffset(LSL, Imm amount))) ]
  | [ OprShift(LSL, Imm amount) ] -> (if is64 then UXTX else UXTW), amount
  | _ -> wrongOperands ins

/// <summary>
/// Whether the second source of an extended operand is read whole.
///
/// Only an extension that reads a doubleword names one, and only where the
/// instruction works in doublewords at all: a thirty-two bit instruction reads
/// a word however far its extension would reach.
/// </summary>
let private extendedSourceIs64 is64 = function
  | UXTX | SXTX -> is64
  | _ -> false

/// The bits an addition or subtraction of an extended register shares.
let private addSubExtendedWith op s ins rd rn rm rest =
  let is64 = is64Reg rd
  let ext, amount = extendOf ins is64 rest
  if is64Reg rm <> extendedSourceIs64 is64 ext then
    fail $"{Register.toString rm} is not the width {ext} reads"
  elif amount > 4L then
    fail $"an extended source cannot be shifted by #{amount}"
  else
    (if is64 then 1u <<< 31 else 0u) ||| (op <<< 30) ||| (s <<< 29)
    ||| (0b01011001u <<< 21) ||| (coreReg rm <<< 16)
    ||| (extendType ext <<< 13) ||| (unsignedImm 3 amount <<< 10)
    ||| (coreRegSP rn <<< 5)

/// <summary>
/// The additions and subtractions of a register, which name their second
/// source either shifted or extended.
///
/// Only the extended form can read the stack pointer, so a source that names it
/// has said which form it means; anything else is the shifted one, which is
/// what the disassembler writes wherever both would do.
/// </summary>
let private addSubReg op s ins =
  match getOperandsAsList ins.Operands with
  | Rg rd :: Rg rn :: Rg rm :: rest ->
    let extended =
      isStackPointer rd || isStackPointer rn
      || (match rest with
          | [ OprExtReg _ ] -> true
          | _ -> false)
    if extended then
      let rdField = if s = 1u then coreReg rd else coreRegSP rd
      addSubExtendedWith op s ins rd rn rm rest ||| rdField
    else
      addSubShiftedWith op s ins rd rn rm rest
  | _ ->
    wrongOperands ins

/// The zero register of the width the given one is written in, which is what
/// the aliases naming one register fewer read or write in its place.
let private zeroLike reg = if is64Reg reg then Register.XZR else Register.WZR

/// <Rn|SP>, <Rm>{, <extend>|<shift>}, the form that names no destination.
let private compareReg op ins =
  match getOperandsAsList ins.Operands with
  | Rg rn :: Rg rm :: rest ->
    let extended =
      isStackPointer rn
      || (match rest with
          | [ OprExtReg _ ] -> true
          | _ -> false)
    if extended then addSubExtendedWith op 1u ins rn rn rm rest ||| 31u
    else addSubShiftedWith op 1u ins (zeroLike rn) rn rm rest
  | _ ->
    wrongOperands ins

/// <Rd>, <Rm>{, <shift> #<amount>}, which subtracts from the zero register.
let private negate s ins =
  match getOperandsAsList ins.Operands with
  | Rg rd :: Rg rm :: rest ->
    addSubShiftedWith 1u s ins rd (zeroLike rd) rm rest
  | _ ->
    wrongOperands ins

/// The bits an addition or subtraction that reads the carry flag shares.
let private addSubCarryWith op s rd rn rm =
  sfBit rd ||| (op <<< 30) ||| (s <<< 29) ||| (0b11010000u <<< 21)
  ||| (coreReg rm <<< 16) ||| (coreReg rn <<< 5) ||| coreReg rd

let private addSubCarry op s ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rn, Rg rm) -> addSubCarryWith op s rd rn rm
  | _ -> wrongOperands ins

/// <Rd>, <Rm>, which subtracts from the zero register with the carry flag.
let private negateCarry s ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Rg rm) -> addSubCarryWith 1u s rd rd rm ||| (31u <<< 5)
  | _ -> wrongOperands ins

/// The bits a conditional compare shares.
let private condCompareWith op rn cond nzcv isImm second =
  sfBit rn ||| (op <<< 30) ||| (1u <<< 29) ||| (0b11010010u <<< 21)
  ||| (second <<< 16) ||| (condField cond <<< 12)
  ||| ((if isImm then 1u else 0u) <<< 11) ||| (coreReg rn <<< 5)
  ||| unsignedImm 4 nzcv

/// <Rn>, <Rm>|#<imm>, #<nzcv>, <cond>
let private condCompare op ins =
  match ins.Operands with
  | FourOperands(Rg rn, Im imm, Im nzcv, OprCond cond) ->
    condCompareWith op rn cond nzcv true (unsignedImm 5 imm)
  | FourOperands(Rg rn, Rg rm, Im nzcv, OprCond cond) ->
    condCompareWith op rn cond nzcv false (coreReg rm)
  | _ ->
    wrongOperands ins

/// The bits a conditional select shares.
let private condSelectWith op op2 rd rn rm cond =
  sfBit rd ||| (op <<< 30) ||| (0b11010100u <<< 21) ||| (coreReg rm <<< 16)
  ||| (cond <<< 12) ||| (op2 <<< 10) ||| (coreReg rn <<< 5) ||| coreReg rd

/// <Rd>, <Rn>, <Rm>, <cond>
let private condSelect op op2 ins =
  match ins.Operands with
  | FourOperands(Rg rd, Rg rn, Rg rm, OprCond cond) ->
    condSelectWith op op2 rd rn rm (condField cond)
  | _ ->
    wrongOperands ins

/// <summary>
/// The conditional selects written as one register and a condition, which read
/// that register under the opposite condition and the zero register otherwise.
///
/// The condition an alias names is the one the instruction it stands for runs
/// the other half of, so the field holds its opposite.
/// </summary>
let private condSelectAlias op op2 ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rn, OprCond cond) ->
    condSelectWith op op2 rd rn rn (invertCondition cond)
  | TwoOperands(Rg rd, OprCond cond) ->
    condSelectWith op op2 rd (zeroLike rd) (zeroLike rd) (invertCondition cond)
  | _ ->
    wrongOperands ins

/// The bits a three-source multiply shares.
let private mulWith op31 o0 rd rn rm ra =
  sfBit rd ||| (0b11011u <<< 24) ||| (op31 <<< 21) ||| (coreReg rm <<< 16)
  ||| (o0 <<< 15) ||| (coreReg ra <<< 10) ||| (coreReg rn <<< 5) ||| coreReg rd

/// <Rd>, <Rn>, <Rm>, <Ra>
let private mulAccumulate op31 o0 ins =
  match ins.Operands with
  | FourOperands(Rg rd, Rg rn, Rg rm, Rg ra) -> mulWith op31 o0 rd rn rm ra
  | _ -> wrongOperands ins

/// <Rd>, <Rn>, <Rm>, which accumulates into the zero register.
let private multiply op31 o0 ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rn, Rg rm) -> mulWith op31 o0 rd rn rm (zeroLike rd)
  | _ -> wrongOperands ins

/// The bits an instruction reading two registers into one shares.
let private dataProc2SrcWith opcode rd rn rm =
  sfBit rd ||| (0b11010110u <<< 21) ||| (coreReg rm <<< 16)
  ||| (opcode <<< 10) ||| (coreReg rn <<< 5) ||| coreReg rd

/// <Rd>, <Rn>, <Rm>
let private dataProc2Src opcode ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rn, Rg rm) -> dataProc2SrcWith opcode rd rn rm
  | _ -> wrongOperands ins

/// The cyclic redundancy checks, whose source is as wide as the data it reads
/// while their result is always a word.
let private crc32 opcode ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rn, Rg rm) ->
    (if is64Reg rm then 1u <<< 31 else 0u) ||| (0b11010110u <<< 21)
    ||| (coreReg rm <<< 16) ||| (opcode <<< 10) ||| (coreReg rn <<< 5)
    ||| coreReg rd
  | _ ->
    wrongOperands ins

/// <Rd>, <Rn>, the instructions that read one register into another.
let private dataProc1Src opcode ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Rg rn) ->
    sfBit rd ||| (0b10u <<< 29) ||| (0b11010110u <<< 21) ||| (opcode <<< 10)
    ||| (coreReg rn <<< 5) ||| coreReg rd
  | _ ->
    wrongOperands ins

/// <summary>
/// REV, whose opcode says how wide a piece it leaves in place, and so differs
/// between the two widths it runs in: reversing a word inside a word and
/// reversing a doubleword are the same instruction spelt one way.
/// </summary>
let private reverse ins =
  match ins.Operands with
  | TwoOperands(Rg rd, _) when is64Reg rd -> dataProc1Src 0b000011u ins
  | _ -> dataProc1Src 0b000010u ins

(* The shifts, which are two instructions apiece. *)
/// LSL by an immediate, which the manual defines as a bitfield move that keeps
/// everything below where the field ends.
let private shiftLeftImm rd rn amount =
  let bits = int64 (widthOf rd)
  if amount < 0L || amount >= bits then
    fail $"a register of {bits} bits cannot be shifted by #{amount}"
  else
    bitfieldWith 0b10u rd rn ((bits - amount) % bits) (bits - 1L - amount)

/// The right shifts, which keep the field from where they start to the top.
let private shiftRightImm opc rd rn amount =
  let bits = int64 (widthOf rd)
  if amount < 0L || amount >= bits then
    fail $"a register of {bits} bits cannot be shifted by #{amount}"
  else
    bitfieldWith opc rd rn amount (bits - 1L)

/// <summary>
/// A shift, which is a bitfield move when it shifts by an immediate and an
/// instruction of its own when it shifts by a register.
/// </summary>
let private shift byImmediate opcode ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rn, Im amount) -> byImmediate rd rn amount
  | ThreeOperands(Rg rd, Rg rn, Rg rm) -> dataProc2SrcWith opcode rd rn rm
  | _ -> wrongOperands ins

/// ROR, which rotates a register into itself when it rotates by an immediate.
let private rotateRight ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rn, Im amount) -> extractWith rd rn rn amount
  | ThreeOperands(Rg rd, Rg rn, Rg rm) -> dataProc2SrcWith 0b001011u rd rn rm
  | _ -> wrongOperands ins

(* The moves, which stand for one of four instructions. *)
/// The hw field and immediate of a wide move that would hold the given value,
/// if one would.
let private tryWideImm (value: uint64) =
  [ 0; 16; 32; 48 ]
  |> List.tryPick (fun shift ->
    let half = (value >>> shift) &&& 0xffffUL
    if half <<< shift = value && (half <> 0UL || shift = 0) then
      Some(uint32 (shift / 16), int64 half)
    else
      None)

/// <summary>
/// A move of an immediate, which the manual writes as a wide move of the value,
/// a wide move of its inverse, or an inclusive or with the zero register.
///
/// The order is the one the disassembler reads back: a value a wide move can
/// hold is written as one, so encoding it any other way would come back as an
/// ORR rather than as the move the source wrote.
/// </summary>
let private moveImmediate rd (value: int64) =
  let is64 = is64Reg rd
  let width = if is64 then 64 else 32
  let value = if is64 then uint64 value else uint64 (uint32 value)
  let inverse = if is64 then ~~~value else uint64 (~~~(uint32 value))
  let wide opc (hw, imm) =
    sfBit rd ||| (opc <<< 29) ||| (0b100101u <<< 23) ||| (hw <<< 21)
    ||| (unsignedImm 16 imm <<< 5) ||| coreReg rd
  let inverseFits (hw, imm) = is64 || (imm <> 0xffffL && (imm <> 0L || hw = 0u))
  match tryWideImm value with
  | Some fields ->
    wide 0b10u fields
  | None ->
    match tryWideImm inverse |> Option.filter inverseFits with
    | Some fields ->
      wide 0b00u fields
    | None ->
      let n, immr, imms = logicalImm width (int64 value)
      if moveWidePreferred is64 (n, immr, imms) then
        fail $"#{value} is not a move of an immediate"
      else
        sfBit rd ||| (0b01u <<< 29) ||| (0b100100u <<< 23) ||| (n <<< 22)
        ||| (immr <<< 16) ||| (imms <<< 10) ||| (31u <<< 5) ||| coreReg rd

/// <summary>
/// MOV, which the manual defines as four instructions: a wide move either way
/// round, an inclusive or with the zero register, and an addition of nothing.
///
/// Which one a source means follows from what it names. Only the addition
/// reaches the stack pointer, and only the inclusive or can put an immediate
/// there, so naming it says which of the four was meant.
/// </summary>
let private move ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Rg rm) when isStackPointer rd || isStackPointer rm ->
    sfBit rd ||| addSubImmWith 0u 0u ins (coreRegSP rd) rm 0L []
  | TwoOperands(Rg rd, Rg rm) ->
    logicalShiftedWith 0b01u 0u ins rd (zeroLike rd) rm []
  | TwoOperands(Rg rd, Im imm) when isStackPointer rd ->
    sfBit rd ||| logicalImmWith 0b01u ins (coreRegSP rd) (zeroLike rd) imm
  | TwoOperands(Rg rd, Im imm) ->
    moveImmediate rd imm
  | _ ->
    wrongOperands ins

/// MVN, which the manual defines as an inclusive or of the inverse of a
/// register with the zero register.
let private moveNot ins =
  match getOperandsAsList ins.Operands with
  | Rg rd :: Rg rm :: rest ->
    logicalShiftedWith 0b01u 1u ins rd (zeroLike rd) rm rest
  | _ ->
    wrongOperands ins

/// TST, which is an AND that keeps nothing but the flags, so it names no
/// destination and reads either an immediate or a shifted register.
let private test ins =
  match getOperandsAsList ins.Operands with
  | [ Rg rn; Im imm ] ->
    sfBit rn ||| logicalImmWith 0b11u ins 31u rn imm
  | Rg rn :: Rg rm :: rest ->
    logicalShiftedWith 0b11u 0u ins (zeroLike rn) rn rm rest
  | _ ->
    wrongOperands ins

/// <summary>
/// The arithmetic and logical instructions, which read either an immediate or a
/// register and say which by what they name rather than by what they are
/// called.
///
/// One opcode takes one encoder, so the encoder of an instruction written both
/// ways has to reach both encodings.
/// </summary>
let private addSub op s ins =
  match getOperandsAsList ins.Operands with
  | _ :: _ :: Im _ :: _ when s = 1u -> addSubImmFlags op ins
  | _ :: _ :: Im _ :: _ -> addSubImm op ins
  | _ -> addSubReg op s ins

let private compareOperand op ins =
  match getOperandsAsList ins.Operands with
  | _ :: Im _ :: _ -> compareImm op ins
  | _ -> compareReg op ins

/// The logical instructions. Only the four that read their second source as it
/// stands have a form that takes an immediate; the ones that invert it first do
/// not, so naming one of them with an immediate names nothing at all.
let private logical opc n ins =
  match getOperandsAsList ins.Operands with
  | _ :: _ :: Im _ :: _ when n = 0u && opc = 0b11u ->
    logicalImmediateFlags opc ins
  | _ :: _ :: Im _ :: _ when n = 0u ->
    logicalImmediate opc ins
  | _ ->
    logicalShifted opc n ins

(* Branches, exception generating and system instructions. *)
/// A branch that runs under a condition, which spells that condition into its
/// own name rather than taking it as an operand.
let private conditionalBranch cond ins =
  match ins.Operands with
  | OneOperand(Place offset) ->
    (0b01010100u <<< 24) ||| (signedImm 19 (scaled 4 offset) <<< 5) ||| cond
  | _ ->
    wrongOperands ins

/// B and BL, which reach the furthest of any branch.
let private branchImm op ins =
  match ins.Operands with
  | OneOperand(Place offset) ->
    (op <<< 31) ||| (0b00101u <<< 26) ||| signedImm 26 (scaled 4 offset)
  | _ ->
    wrongOperands ins

/// The branches that read where to go from a register.
let private branchReg opc ins =
  match ins.Operands with
  | OneOperand(Rg rn) ->
    (0b1101011u <<< 25) ||| (opc <<< 21) ||| (0b11111u <<< 16)
    ||| (coreReg rn <<< 5)
  | _ ->
    wrongOperands ins

/// RET, whose register the disassembler leaves out when it is the one a return
/// reads by default.
let private returnBranch ins =
  match ins.Operands with
  | NoOperand ->
    (0b1101011u <<< 25) ||| (0b0010u <<< 21) ||| (0b11111u <<< 16)
    ||| (30u <<< 5)
  | _ ->
    branchReg 0b0010u ins

/// ERET and DRPS, which read nowhere and so name nothing.
let private branchNoReg opc ins =
  match ins.Operands with
  | NoOperand ->
    (0b1101011u <<< 25) ||| (opc <<< 21) ||| (0b11111u <<< 16) ||| (31u <<< 5)
  | _ ->
    wrongOperands ins

/// CBZ and CBNZ, which branch on whether a register holds zero.
let private compareBranch op ins =
  match ins.Operands with
  | TwoOperands(Rg rt, Place offset) ->
    sfBit rt ||| (0b011010u <<< 25) ||| (op <<< 24)
    ||| (signedImm 19 (scaled 4 offset) <<< 5) ||| coreReg rt
  | _ ->
    wrongOperands ins

/// TBZ and TBNZ, which branch on one bit of a register. Which bit that is
/// decides the width the instruction is written in, so its top bit sits where
/// every other instruction keeps the bit that says so.
let private testBranch op ins =
  match ins.Operands with
  | ThreeOperands(Rg rt, Im bit, Place offset) ->
    let bit = unsignedImm 6 bit
    ((bit >>> 5) <<< 31) ||| (0b011011u <<< 25) ||| (op <<< 24)
    ||| ((bit &&& 0b11111u) <<< 19) ||| (signedImm 14 (scaled 4 offset) <<< 5)
    ||| coreReg rt
  | _ ->
    wrongOperands ins

/// The instructions that raise an exception, which name what to raise it with.
let private exceptionGen opc ll ins =
  match ins.Operands with
  | OneOperand(Im imm) ->
    (0b11010100u <<< 24) ||| (opc <<< 21) ||| (unsignedImm 16 imm <<< 5) ||| ll
  | _ ->
    wrongOperands ins

/// The bits every instruction in the system space shares.
let private systemHead l = (0b1101010100u <<< 22) ||| (l <<< 21)

/// A hint, which does nothing a program can see and so names nothing.
let private namedHint crm op2 ins =
  match ins.Operands with
  | NoOperand ->
    systemHead 0u ||| (0b011u <<< 16) ||| (0b0010u <<< 12) ||| (crm <<< 8)
    ||| (op2 <<< 5) ||| 0b11111u
  | _ ->
    wrongOperands ins

/// HINT, which names by number the hint it gives.
let private hint ins =
  match ins.Operands with
  | OneOperand(Im imm) ->
    let imm = unsignedImm 7 imm
    systemHead 0u ||| (0b011u <<< 16) ||| (0b0010u <<< 12)
    ||| ((imm >>> 3) <<< 8) ||| ((imm &&& 0b111u) <<< 5) ||| 0b11111u
  | _ ->
    wrongOperands ins

/// The barriers and CLREX, which take an option written either by its name or
/// as the number that names it.
let private barrier op2 ins =
  let crm =
    match ins.Operands with
    | NoOperand -> 0b1111u
    | OneOperand(OprOption option) -> barrierOption option
    | OneOperand(Im imm) -> unsignedImm 4 imm
    | _ -> wrongOperands ins
  systemHead 0u ||| (0b011u <<< 16) ||| (0b0011u <<< 12) ||| (crm <<< 8)
  ||| (op2 <<< 5) ||| 0b11111u

/// SYS and SYSL, which hand an instruction to whatever the numbers name.
let private systemInstruction l ins =
  let fields op1 cn cm op2 rt =
    systemHead l ||| (0b01u <<< 19) ||| (unsignedImm 3 op1 <<< 16)
    ||| (coprocReg cn <<< 12) ||| (coprocReg cm <<< 8)
    ||| (unsignedImm 3 op2 <<< 5) ||| rt
  match ins.Operands with
  | FiveOperands(Im op1, Rg cn, Rg cm, Im op2, Rg rt) when l = 0u ->
    fields op1 cn cm op2 (coreReg rt)
  | FourOperands(Im op1, Rg cn, Rg cm, Im op2) when l = 0u ->
    fields op1 cn cm op2 31u
  | FiveOperands(Rg rt, Im op1, Rg cn, Rg cm, Im op2) ->
    fields op1 cn cm op2 (coreReg rt)
  | _ ->
    wrongOperands ins

/// The cache maintenance instructions, which the manual defines as a system
/// instruction whose numbers say which of them it is.
let private cacheInstruction op1 cn cm op2 ins =
  match ins.Operands with
  | OneOperand(Rg rt) ->
    systemHead 0u ||| (0b01u <<< 19) ||| (op1 <<< 16) ||| (cn <<< 12)
    ||| (cm <<< 8) ||| (op2 <<< 5) ||| coreReg rt
  | _ ->
    wrongOperands ins

/// <summary>
/// The sixteen bits that name a system register, which the encoding keeps in
/// one field split across the instruction the way the manual writes it: an
/// access level, an operation, two register numbers and a second operation.
///
/// The list is the one the disassembler reads, inverted. A register missing
/// from it is one the disassembler cannot name, so a source naming it has
/// nothing to be assembled back into.
/// </summary>
let private systemRegisters =
  [ Register.ACTLREL1, 0b1100000010000001u
    Register.ACTLREL2, 0b1110000010000001u
    Register.ACTLREL3, 0b1111000010000001u
    Register.AFSR0EL1, 0b1100001010001000u
    Register.AFSR0EL2, 0b1110001010001000u
    Register.AFSR0EL3, 0b1111001010001000u
    Register.AFSR1EL1, 0b1100001010001001u
    Register.AFSR1EL2, 0b1110001010001001u
    Register.AFSR1EL3, 0b1111001010001001u
    Register.AIDREL1, 0b1100100000000111u
    Register.AMAIREL1, 0b1100010100011000u
    Register.AMAIREL2, 0b1110010100011000u
    Register.AMAIREL3, 0b1111010100011000u
    Register.CCSIDREL1, 0b1100100000000000u
    Register.CLIDREL1, 0b1100100000000001u
    Register.CONTEXTIDREL1, 0b1100011010000001u
    Register.CPACREL1, 0b1100000010000010u
    Register.CPTREL2, 0b1110000010001010u
    Register.CPTREL3, 0b1111000010001010u
    Register.CSSELREL1, 0b1101000000000000u
    Register.CTREL0, 0b1101100000000001u
    Register.DACR32EL2, 0b1110000110000000u
    Register.DCZIDEL0, 0b1101100000000111u
    Register.ESREL1, 0b1100001010010000u
    Register.ESREL2, 0b1110001010010000u
    Register.ESREL3, 0b1111001010010000u
    Register.HPFAREL2, 0b1110001100000100u
    Register.TPIDREL0, 0b1101111010000010u
    Register.FPCR, 0b1101101000100000u
    Register.FPSR, 0b1101101000100001u
    Register.MIDREL1, 0b1100000000000000u
    Register.NZCV, 0b1101101000010000u
    Register.S3_5_C3_C2_0, 0b1110100110010000u
    Register.S3_7_C2_C2_7, 0b1011100100010111u
    Register.S0_0_C2_C9_3, 0b0000000101001011u
    Register.S2_7_C12_C7_6, 0b1011111000111110u
    Register.CNTVCT_EL0, 0b1101111100000010u ]
  |> Map.ofList

let private systemRegister reg =
  match Map.tryFind reg systemRegisters with
  | Some value -> value
  | None -> fail $"{Register.toString reg} is not a system register"

/// MSR, which writes either a system register or one of the fields of the
/// processor state that has a name of its own.
let private moveToSystem ins =
  match ins.Operands with
  | TwoOperands(OprPstate state, Im imm) ->
    let field = pstateField state
    systemHead 0u ||| ((field >>> 3) <<< 16) ||| (0b0100u <<< 12)
    ||| (unsignedImm 4 imm <<< 8) ||| ((field &&& 0b111u) <<< 5) ||| 0b11111u
  | TwoOperands(Rg sreg, Rg rt) ->
    systemHead 0u ||| (systemRegister sreg <<< 5) ||| coreReg rt
  | _ ->
    wrongOperands ins

/// MRS, which reads a system register into a general one.
let private moveFromSystem ins =
  match ins.Operands with
  | TwoOperands(Rg rt, Rg sreg) ->
    systemHead 1u ||| (systemRegister sreg <<< 5) ||| coreReg rt
  | _ ->
    wrongOperands ins

(* Loads and stores. *)
/// What a load or store moves, which decides how wide the access is and so how
/// far a scaled offset reaches.
type private Access =
  /// The mnemonic says nothing about the width, so the register does.
  | ByRegister of load: bool
  /// The mnemonic says both the width and which way the value moves.
  | Fixed of size: uint32 * opc: uint32 * bytes: int
  /// The mnemonic says the width, and the register says how far the value is
  /// extended once it has been read.
  | Signed of size: uint32 * bytes: int
  /// A prefetch, which moves nothing and so names what to prefetch instead of a
  /// register.
  | Prefetch

/// The size and V fields of an access that says its width in the register it
/// names, together with how many bytes that is and the opc bit a quadword adds:
/// sixteen bytes is one more than the size field can say, so it says the rest
/// where the direction goes.
let private widthFields ins reg =
  match tryScalarWidth reg with
  | Some 8 -> 0b00u, 1u, 0u, 1
  | Some 16 -> 0b01u, 1u, 0u, 2
  | Some 32 -> 0b10u, 1u, 0u, 4
  | Some 64 -> 0b11u, 1u, 0u, 8
  | Some 128 -> 0b00u, 1u, 0b10u, 16
  | Some _ -> wrongOperands ins
  | None -> (if is64Reg reg then 0b11u, 0u, 0u, 8 else 0b10u, 0u, 0u, 4)

/// The fields a load or store reads off what it moves: how wide the access is,
/// which way it goes, and the five bits that name what moves.
let private accessFields access ins operand =
  match access, operand with
  | ByRegister load, Rg reg ->
    let size, v, extra, bytes = widthFields ins reg
    let field = if v = 1u then simdReg (bytes * 8) reg else coreReg reg
    size, v, extra ||| (if load then 1u else 0u), bytes, field
  | Fixed(size, opc, bytes), Rg reg ->
    size, 0u, opc, bytes, coreReg reg
  | Signed(size, bytes), Rg reg ->
    size, 0u, (if is64Reg reg then 0b10u else 0b11u), bytes, coreReg reg
  | Prefetch, OprPrfOp operation ->
    0b11u, 0u, 0b10u, 8, prefetchOperation operation
  | Prefetch, Im imm ->
    0b11u, 0u, 0b10u, 8, unsignedImm 5 imm
  | _ ->
    wrongOperands ins

/// The bits every load and store of one register shares.
let private loadStoreHead size v opc =
  (size <<< 30) ||| (0b111u <<< 27) ||| (v <<< 26) ||| (opc <<< 22)

/// [<Xn|SP>{, #<imm>}], whose offset is a whole number of accesses.
let private unsignedOffset access ins rt rn offset =
  let size, v, opc, bytes, field = accessFields access ins rt
  loadStoreHead size v opc ||| (0b01u <<< 24)
  ||| (unsignedImm 12 (scaled bytes offset) <<< 10) ||| (coreRegSP rn <<< 5)
  ||| field

/// The three forms whose offset is a plain byte count: one that adds it, one
/// that adds it and keeps the sum, and one that keeps the sum after reading.
let private simm9Offset access ins kind rt rn offset =
  let size, v, opc, _, field = accessFields access ins rt
  loadStoreHead size v opc ||| (signedImm 9 offset <<< 12) ||| (kind <<< 10)
  ||| (coreRegSP rn <<< 5) ||| field

/// [<Xn|SP>, <Rm>{, <extend> {#<amount>}}], whose offset is a register, read as
/// itself or as the part of itself the extension names.
let private registerOffset access ins rt rn rm shift =
  let size, v, opc, bytes, field = accessFields access ins rt
  let scale = int64 (scaleOf bytes)
  let shifted amount =
    if amount = scale then 1u
    else fail $"an offset of {bytes} bytes cannot be shifted by #{amount}"
  let ext, s =
    match shift with
    | None -> (if is64Reg rm then UXTX else UXTW), 0u
    | Some(ShiftOffset(LSL, Imm amount)) -> UXTX, shifted amount
    | Some(ExtRegOffset(ext, None))
    | Some(ExtRegOffset(ext, Some 0L)) -> ext, 0u
    | Some(ExtRegOffset(ext, Some amount)) -> ext, shifted amount
    | Some _ -> wrongOperands ins
  if is64Reg rm <> extendedSourceIs64 true ext then
    fail $"{Register.toString rm} is not the width {ext} reads"
  else
    loadStoreHead size v opc ||| (1u <<< 21) ||| (coreReg rm <<< 16)
    ||| (extendType ext <<< 13) ||| (s <<< 12) ||| (0b10u <<< 10)
    ||| (coreRegSP rn <<< 5) ||| field

/// <Rt>, <label>, which reads what sits a distance away from here.
let private loadLiteral opc v ins rt offset =
  let field =
    match rt with
    | Rg reg when v = 1u ->
      let _, _, _, bytes = widthFields ins reg
      simdReg (bytes * 8) reg
    | Rg reg ->
      coreReg reg
    | OprPrfOp operation ->
      prefetchOperation operation
    | Im imm ->
      unsignedImm 5 imm
    | _ ->
      wrongOperands ins
  (opc <<< 30) ||| (0b011u <<< 27) ||| (v <<< 26)
  ||| (signedImm 19 (scaled 4 offset) <<< 5) ||| field

/// The opc and V fields of a load of a literal, which name what it reads into.
let private literalFields ins = function
  | Rg reg ->
    match tryScalarWidth reg with
    | Some 32 -> 0b00u, 1u
    | Some 64 -> 0b01u, 1u
    | Some 128 -> 0b10u, 1u
    | Some _ -> wrongOperands ins
    | None -> (if is64Reg reg then 0b01u, 0u else 0b00u, 0u)
  | _ ->
    wrongOperands ins

/// <summary>
/// A load or store of one register, which is written the same way whichever of
/// the six ways of naming a place it uses.
///
/// Which way that is decides the encoding, so the memory operand rather than
/// the mnemonic picks it apart. What the mnemonic says is only how wide the
/// access is, which arrives here already read off it.
/// </summary>
let private loadStore access ins =
  match ins.Operands with
  | TwoOperands(rt, OprMemory(BaseMode(ImmOffset(BaseOffset(rn, offset))))) ->
    unsignedOffset access ins rt rn (defaultArg offset 0L)
  | TwoOperands(rt, OprMemory(PreIdxMode(ImmOffset(BaseOffset(rn, off))))) ->
    simm9Offset access ins 0b11u rt rn (defaultArg off 0L)
  | TwoOperands(rt, OprMemory(PostIdxMode(ImmOffset(BaseOffset(rn, off))))) ->
    simm9Offset access ins 0b01u rt rn (defaultArg off 0L)
  | TwoOperands(rt, OprMemory(BaseMode(RegOffset(rn, rm, shift)))) ->
    registerOffset access ins rt rn rm shift
  | TwoOperands(rt, Place offset) ->
    let opc, v = literalFields ins rt
    loadLiteral opc v ins rt offset
  | _ ->
    wrongOperands ins

/// The loads and stores whose offset the encoding holds as it stands, which
/// reach half as far as a scaled one and both ways from where they start.
let private loadStoreUnscaled access kind ins =
  match ins.Operands with
  | TwoOperands(rt, OprMemory(BaseMode(ImmOffset(BaseOffset(rn, offset))))) ->
    simm9Offset access ins kind rt rn (defaultArg offset 0L)
  | _ ->
    wrongOperands ins

/// LDRSW and PRFM, which read a literal as well as a place.
let private loadStoreOrLiteral access opc v ins =
  match ins.Operands with
  | TwoOperands(rt, Place offset) -> loadLiteral opc v ins rt offset
  | _ -> loadStore access ins

/// The opc, V fields and access width of a transfer of a pair of registers,
/// which the registers themselves say.
let private pairFields ins reg =
  match tryScalarWidth reg with
  | Some 32 -> 0b00u, 1u, 4
  | Some 64 -> 0b01u, 1u, 8
  | Some 128 -> 0b10u, 1u, 16
  | Some _ -> wrongOperands ins
  | None -> (if is64Reg reg then 0b10u, 0u, 8 else 0b00u, 0u, 4)

/// The five bits naming one register of a transferred pair.
let private pairReg v bytes reg =
  if v = 1u then simdReg (bytes * 8) reg else coreReg reg

/// The bits a transfer of a pair of registers shares. Which of the four ways of
/// naming a place it uses sits above the bit that says which way it moves.
let private pairWith kind l ins rt1 rt2 rn offset fields =
  let opc, v, bytes = fields
  (opc <<< 30) ||| (0b101u <<< 27) ||| (v <<< 26) ||| (kind <<< 23)
  ||| (l <<< 22) ||| (signedImm 7 (scaled bytes offset) <<< 15)
  ||| (pairReg v bytes rt2 <<< 10) ||| (coreRegSP rn <<< 5)
  ||| pairReg v bytes rt1

/// <Rt1>, <Rt2>, [<Xn|SP>{, #<imm>}] and the two forms that keep the sum.
let private loadStorePair l ins =
  let fields rt = pairFields ins rt
  match ins.Operands with
  | ThreeOperands(Rg rt1,
                  Rg rt2,
                  OprMemory(BaseMode(ImmOffset(BaseOffset(rn, off))))) ->
    pairWith 0b010u l ins rt1 rt2 rn (defaultArg off 0L) (fields rt1)
  | ThreeOperands(Rg rt1,
                  Rg rt2,
                  OprMemory(PreIdxMode(ImmOffset(BaseOffset(rn, off))))) ->
    pairWith 0b011u l ins rt1 rt2 rn (defaultArg off 0L) (fields rt1)
  | ThreeOperands(Rg rt1,
                  Rg rt2,
                  OprMemory(PostIdxMode(ImmOffset(BaseOffset(rn, off))))) ->
    pairWith 0b001u l ins rt1 rt2 rn (defaultArg off 0L) (fields rt1)
  | _ ->
    wrongOperands ins

/// The pair transfers that promise the memory will not be read again soon,
/// which name a place one way only.
let private loadStorePairNoAlloc l ins =
  match ins.Operands with
  | ThreeOperands(Rg rt1,
                  Rg rt2,
                  OprMemory(BaseMode(ImmOffset(BaseOffset(rn, off))))) ->
    pairWith 0b000u l ins rt1 rt2 rn (defaultArg off 0L) (pairFields ins rt1)
  | _ ->
    wrongOperands ins

/// LDPSW, whose pair is as wide as a word each and lands sign-extended.
let private loadPairSigned ins =
  let fields _ = 0b01u, 0u, 4
  match ins.Operands with
  | ThreeOperands(Rg rt1,
                  Rg rt2,
                  OprMemory(BaseMode(ImmOffset(BaseOffset(rn, off))))) ->
    pairWith 0b010u 1u ins rt1 rt2 rn (defaultArg off 0L) (fields rt1)
  | ThreeOperands(Rg rt1,
                  Rg rt2,
                  OprMemory(PreIdxMode(ImmOffset(BaseOffset(rn, off))))) ->
    pairWith 0b011u 1u ins rt1 rt2 rn (defaultArg off 0L) (fields rt1)
  | ThreeOperands(Rg rt1,
                  Rg rt2,
                  OprMemory(PostIdxMode(ImmOffset(BaseOffset(rn, off))))) ->
    pairWith 0b001u 1u ins rt1 rt2 rn (defaultArg off 0L) (fields rt1)
  | _ ->
    wrongOperands ins

/// The base register of a memory operand that names nothing but one.
let private plainBase ins = function
  | OprMemory(BaseMode(ImmOffset(BaseOffset(rn, None)))) -> rn
  | OprMemory(BaseMode(ImmOffset(BaseOffset(rn, Some 0L)))) -> rn
  | _ -> wrongOperands ins

/// The bits an exclusive or ordered access shares.
let private exclusiveWith size o2 l o1 o0 rs rt2 rn rt =
  (size <<< 30) ||| (0b001000u <<< 24) ||| (o2 <<< 23) ||| (l <<< 22)
  ||| (o1 <<< 21) ||| (rs <<< 16) ||| (o0 <<< 15) ||| (rt2 <<< 10)
  ||| (coreRegSP rn <<< 5) ||| rt

/// The size field of an access whose mnemonic does not say how wide it is, so
/// that the register it moves says instead.
let private accessSize rt = if is64Reg rt then 0b11u else 0b10u

/// <Rt>, [<Xn|SP>], the accesses that name one register and a place.
let private exclusiveOne size o2 l o0 ins =
  match ins.Operands with
  | TwoOperands(Rg rt, mem) ->
    let size = defaultArg size (accessSize rt)
    exclusiveWith size o2 l 0u o0 31u 31u (plainBase ins mem) (coreReg rt)
  | _ ->
    wrongOperands ins

/// <Ws>, <Rt>, [<Xn|SP>], the stores that say whether they succeeded.
let private exclusiveStore size o0 ins =
  match ins.Operands with
  | ThreeOperands(Rg rs, Rg rt, mem) ->
    let size = defaultArg size (accessSize rt)
    exclusiveWith size
                  0u
                  0u
                  0u
                  o0
                  (coreReg rs)
                  31u
                  (plainBase ins mem)
                  (coreReg rt)
  | _ ->
    wrongOperands ins

/// <Rt1>, <Rt2>, [<Xn|SP>], the loads that read a pair at once.
let private exclusivePairLoad o0 ins =
  match ins.Operands with
  | ThreeOperands(Rg rt1, Rg rt2, mem) ->
    exclusiveWith (accessSize rt1)
                  0u
                  1u
                  1u
                  o0
                  31u
                  (coreReg rt2)
                  (plainBase ins mem)
                  (coreReg rt1)
  | _ ->
    wrongOperands ins

/// <Ws>, <Rt1>, <Rt2>, [<Xn|SP>], the stores that write a pair at once.
let private exclusivePairStore o0 ins =
  match ins.Operands with
  | FourOperands(Rg rs, Rg rt1, Rg rt2, mem) ->
    exclusiveWith (accessSize rt1)
                  0u
                  0u
                  1u
                  o0
                  (coreReg rs)
                  (coreReg rt2)
                  (plainBase ins mem)
                  (coreReg rt1)
  | _ ->
    wrongOperands ins

/// <Rs>, <Rt>, [<Xn|SP>], the compare-and-swap accesses, whose size the
/// registers say and whose mnemonic says only how ordered they are.
let private compareAndSwap l o0 ins =
  match ins.Operands with
  | ThreeOperands(Rg rs, Rg rt, mem) ->
    exclusiveWith (accessSize rs)
                  1u
                  l
                  1u
                  o0
                  (coreReg rs)
                  31u
                  (plainBase ins mem)
                  (coreReg rt)
  | _ ->
    wrongOperands ins

(* The accesses that move whole structures of vector registers. *)
/// <summary>
/// Where a list of vector registers starts, how many it holds and what they all
/// hold.
///
/// The registers have to run consecutively, wrapping round after the last one,
/// because the encoding says only where the run starts and how long it is.
/// </summary>
let private simdList ins = function
  | OprSIMDList regs ->
    let parts =
      regs |> List.map (function
        | VecReg(reg, vec) -> vectorReg reg, vec, None
        | VecRegWithIdx(reg, vec, index) -> vectorReg reg, vec, Some index
        | ScalarReg reg -> vectorReg reg, VecD, None)
    match parts with
    | [] ->
      wrongOperands ins
    | (first, vec, index) :: _ ->
      let consecutive =
        parts
        |> List.mapi (fun i (number, _, _) -> (first + uint32 i) % 32u = number)
        |> List.forall id
      let alike = parts |> List.forall (fun (_, v, _) -> v = vec)
      if consecutive && alike then first, List.length parts, vec, index
      else fail "a list has to name a run of registers of one arrangement"
  | _ ->
    wrongOperands ins

/// The opcode field, which says both how many registers a structure access
/// moves and how far apart the elements it reads are: one instruction reads a
/// run of registers whole, and the others take one element from each in turn.
let private structureOpcode ins listed structures =
  match structures, listed with
  | 1, 1 -> 0b0111u
  | 1, 2 -> 0b1010u
  | 1, 3 -> 0b0110u
  | 1, 4 -> 0b0010u
  | 2, 2 -> 0b1000u
  | 3, 3 -> 0b0100u
  | 4, 4 -> 0b0000u
  | _ -> wrongOperands ins

/// The bits a structure access shares, given how it names where it reads.
let private structureWith l opcode size q rn rt =
  (q <<< 30) ||| (0b0011u <<< 26) ||| (l <<< 22) ||| (opcode <<< 12)
  ||| (size <<< 10) ||| (coreRegSP rn <<< 5) ||| rt

/// <summary>
/// The accesses that move whole vector registers at a time, of which there are
/// three: one that names a place, one that steps the base on by a register, and
/// one that steps it on by however much it moved.
/// </summary>
let private structureAccess l structures ins =
  let encode list mem =
    let first, listed, vec, index = simdList ins list
    if structures > 1 then checkArrangement ins NotLone vec else ()
    let size, q = arrangement vec
    if index.IsSome then
      wrongOperands ins
    else
      let head = structureWith l (structureOpcode ins listed structures) size q
      match mem with
      | OprMemory(BaseMode(ImmOffset(BaseOffset(rn, None)))) ->
        head rn first
      | OprMemory(PostIdxMode(RegOffset(rn, rm, None))) ->
        head rn first ||| (1u <<< 23) ||| (coreReg rm <<< 16)
      | OprMemory(PostIdxMode(ImmOffset(BaseOffset(rn, Some offset)))) ->
        let moved = int64 (listed * (if q = 1u then 16 else 8))
        if offset <> moved then
          fail $"#{offset} is not how far {ins.Opcode} steps the base"
        else
          head rn first ||| (1u <<< 23) ||| (0b11111u <<< 16)
      | _ ->
        wrongOperands ins
  match ins.Operands with
  | TwoOperands(list, mem) -> encode list mem
  | _ -> wrongOperands ins

/// <summary>
/// The size, S and Q fields that say which element of a register a single
/// structure access reads.
///
/// Those three fields hold four bits between them, and the index sits at the
/// top of them: the wider one element is, the fewer of them the index needs and
/// the further up it starts. A doubleword is the exception, and says that it is
/// one in the bit the index leaves free.
/// </summary>
let private elementFields ins vec (index: uint8) =
  let shift, extra =
    match vec with
    | VecB -> 0, 0b0000u
    | VecH -> 1, 0b0000u
    | VecS -> 2, 0b0000u
    | VecD -> 3, 0b0001u
    | _ -> wrongOperands ins
  let index = uint32 index
  if index >= (16u >>> shift) then
    fail $"a vector of {vec} has no element #{index}"
  else
    let bits = (index <<< shift) ||| extra
    bits &&& 0b11u, (bits >>> 2) &&& 0b1u, bits >>> 3

/// The opcode field of a single structure access, whose top two bits say how
/// wide one element is and whose bottom bit says whether it moves an odd number
/// of registers.
let private elementOpcode ins count vec =
  let width =
    match vec with
    | VecB -> 0b000u
    | VecH -> 0b010u
    | VecS | VecD -> 0b100u
    | _ -> wrongOperands ins
  width ||| (if count = 3 || count = 4 then 1u else 0u)

/// <summary>
/// The accesses that move one element of each of up to four registers, which
/// name the element they move rather than an arrangement.
/// </summary>
let private elementAccess l count ins =
  let encode list mem =
    let first, listed, vec, index = simdList ins list
    match index with
    | None ->
      wrongOperands ins
    | Some _ when listed <> count ->
      fail $"{ins.Opcode} moves {count} registers rather than {listed}"
    | Some index ->
      let size, s, q = elementFields ins vec index
      let r = if count = 2 || count = 4 then 1u else 0u
      let head rn =
        (q <<< 30) ||| (0b0011010u <<< 23) ||| (l <<< 22) ||| (r <<< 21)
        ||| (elementOpcode ins count vec <<< 13) ||| (s <<< 12)
        ||| (size <<< 10) ||| (coreRegSP rn <<< 5) ||| first
      match mem with
      | OprMemory(BaseMode(ImmOffset(BaseOffset(rn, None)))) ->
        head rn
      | OprMemory(PostIdxMode(RegOffset(rn, rm, None))) ->
        head rn ||| (1u <<< 23) ||| (coreReg rm <<< 16)
      | OprMemory(PostIdxMode(ImmOffset(BaseOffset(rn, Some offset)))) ->
        let width =
          match vec with
          | VecB -> 1L
          | VecH -> 2L
          | VecS -> 4L
          | _ -> 8L
        if offset <> width * int64 count then
          fail $"#{offset} is not how far {ins.Opcode} steps the base"
        else
          head rn ||| (1u <<< 23) ||| (0b11111u <<< 16)
      | _ ->
        wrongOperands ins
  match ins.Operands with
  | TwoOperands(list, mem) -> encode list mem
  | _ -> wrongOperands ins

/// The accesses that read one element into every lane of their registers, which
/// name an arrangement even though they read one element.
let private replicateAccess count ins =
  let encode list mem =
    let first, listed, vec, index = simdList ins list
    let size, q = arrangement vec
    if index.IsSome || listed <> count then
      wrongOperands ins
    else
      let r = if count = 2 || count = 4 then 1u else 0u
      let opcode = if count = 1 || count = 2 then 0b110u else 0b111u
      let head rn =
        (q <<< 30) ||| (0b0011010u <<< 23) ||| (1u <<< 22) ||| (r <<< 21)
        ||| (opcode <<< 13) ||| (size <<< 10) ||| (coreRegSP rn <<< 5) ||| first
      match mem with
      | OprMemory(BaseMode(ImmOffset(BaseOffset(rn, None)))) ->
        head rn
      | OprMemory(PostIdxMode(RegOffset(rn, rm, None))) ->
        head rn ||| (1u <<< 23) ||| (coreReg rm <<< 16)
      | OprMemory(PostIdxMode(ImmOffset(BaseOffset(rn, Some offset)))) ->
        let width = 1L <<< int size
        if offset <> width * int64 count then
          fail $"#{offset} is not how far {ins.Opcode} steps the base"
        else
          head rn ||| (1u <<< 23) ||| (0b11111u <<< 16)
      | _ ->
        wrongOperands ins
  match ins.Operands with
  | TwoOperands(list, mem) -> encode list mem
  | _ -> wrongOperands ins

/// <summary>
/// The structure accesses, which name either whole registers or one element of
/// each of them, and which the source tells apart by writing an index.
/// </summary>
let private structureOrElement l count ins =
  match ins.Operands with
  | TwoOperands(OprSIMDList(VecRegWithIdx _ :: _), _) ->
    elementAccess l count ins
  | _ ->
    structureAccess l count ins

(* The tables. *)
let dataProcImmEncoders () =
  [ Opcode.ADR, pcRelative false
    Opcode.ADRP, pcRelative true
    Opcode.MOVN, moveWide 0b00u
    Opcode.MOVZ, moveWide 0b10u
    Opcode.MOVK, moveWide 0b11u
    Opcode.SBFM, bitfield 0b00u
    Opcode.BFM, bitfield 0b01u
    Opcode.UBFM, bitfield 0b10u
    Opcode.SBFIZ, bitfieldInsert 0b00u
    Opcode.BFI, bitfieldInsert 0b01u
    Opcode.UBFIZ, bitfieldInsert 0b10u
    Opcode.SBFX, bitfieldExtract 0b00u
    Opcode.BFXIL, bitfieldExtract 0b01u
    Opcode.UBFX, bitfieldExtract 0b10u
    Opcode.SXTB, extendAlias 0b00u 7L
    Opcode.SXTH, extendAlias 0b00u 15L
    Opcode.SXTW, extendAlias 0b00u 31L
    Opcode.UXTB, extendAlias 0b10u 7L
    Opcode.UXTH, extendAlias 0b10u 15L
    Opcode.EXTR, extract ]

let branchEncoders () =
  [ Opcode.B, branchImm 0u
    Opcode.BL, branchImm 1u
    Opcode.BEQ, conditionalBranch 0b0000u
    Opcode.BNE, conditionalBranch 0b0001u
    Opcode.BCS, conditionalBranch 0b0010u
    Opcode.BHS, conditionalBranch 0b0010u
    Opcode.BCC, conditionalBranch 0b0011u
    Opcode.BLO, conditionalBranch 0b0011u
    Opcode.BMI, conditionalBranch 0b0100u
    Opcode.BPL, conditionalBranch 0b0101u
    Opcode.BVS, conditionalBranch 0b0110u
    Opcode.BVC, conditionalBranch 0b0111u
    Opcode.BHI, conditionalBranch 0b1000u
    Opcode.BLS, conditionalBranch 0b1001u
    Opcode.BGE, conditionalBranch 0b1010u
    Opcode.BLT, conditionalBranch 0b1011u
    Opcode.BGT, conditionalBranch 0b1100u
    Opcode.BLE, conditionalBranch 0b1101u
    Opcode.BAL, conditionalBranch 0b1110u
    Opcode.BNV, conditionalBranch 0b1111u
    Opcode.BR, branchReg 0b0000u
    Opcode.BLR, branchReg 0b0001u
    Opcode.RET, returnBranch
    Opcode.ERET, branchNoReg 0b0100u
    Opcode.DRPS, branchNoReg 0b0101u
    Opcode.CBZ, compareBranch 0u
    Opcode.CBNZ, compareBranch 1u
    Opcode.TBZ, testBranch 0u
    Opcode.TBNZ, testBranch 1u ]

let systemEncoders () =
  [ Opcode.SVC, exceptionGen 0b000u 0b01u
    Opcode.HVC, exceptionGen 0b000u 0b10u
    Opcode.SMC, exceptionGen 0b000u 0b11u
    Opcode.BRK, exceptionGen 0b001u 0b00u
    Opcode.HLT, exceptionGen 0b010u 0b00u
    Opcode.DCPS1, exceptionGen 0b101u 0b01u
    Opcode.DCPS2, exceptionGen 0b101u 0b10u
    Opcode.DCPS3, exceptionGen 0b101u 0b11u
    Opcode.NOP, namedHint 0b0000u 0b000u
    Opcode.YIELD, namedHint 0b0000u 0b001u
    Opcode.WFE, namedHint 0b0000u 0b010u
    Opcode.WFI, namedHint 0b0000u 0b011u
    Opcode.SEV, namedHint 0b0000u 0b100u
    Opcode.SEVL, namedHint 0b0000u 0b101u
    Opcode.HINT, hint
    Opcode.CLREX, barrier 0b010u
    Opcode.DSB, barrier 0b100u
    Opcode.DMB, barrier 0b101u
    Opcode.ISB, barrier 0b110u
    Opcode.SYS, systemInstruction 0u
    Opcode.SYSL, systemInstruction 1u
    Opcode.MSR, moveToSystem
    Opcode.MRS, moveFromSystem
    Opcode.DCZVA, cacheInstruction 0b011u 0b0111u 0b0100u 0b001u
    Opcode.DCIVAC, cacheInstruction 0b000u 0b0111u 0b0110u 0b001u
    Opcode.DCISW, cacheInstruction 0b000u 0b0111u 0b0110u 0b010u
    Opcode.DCCVAC, cacheInstruction 0b011u 0b0111u 0b1010u 0b001u
    Opcode.DCCSW, cacheInstruction 0b000u 0b0111u 0b1010u 0b010u
    Opcode.DCCVAU, cacheInstruction 0b011u 0b0111u 0b1011u 0b001u
    Opcode.DCCIVAC, cacheInstruction 0b011u 0b0111u 0b1110u 0b001u
    Opcode.DCCISW, cacheInstruction 0b000u 0b0111u 0b1110u 0b010u ]

let loadStoreEncoders () =
  [ Opcode.LDR, loadStore (ByRegister true)
    Opcode.STR, loadStore (ByRegister false)
    Opcode.LDRB, loadStore (Fixed(0b00u, 0b01u, 1))
    Opcode.STRB, loadStore (Fixed(0b00u, 0b00u, 1))
    Opcode.LDRH, loadStore (Fixed(0b01u, 0b01u, 2))
    Opcode.STRH, loadStore (Fixed(0b01u, 0b00u, 2))
    Opcode.LDRSB, loadStore (Signed(0b00u, 1))
    Opcode.LDRSH, loadStore (Signed(0b01u, 2))
    Opcode.LDRSW, loadStoreOrLiteral (Signed(0b10u, 4)) 0b10u 0u
    Opcode.PRFM, loadStoreOrLiteral Prefetch 0b11u 0u
    Opcode.LDUR, loadStoreUnscaled (ByRegister true) 0b00u
    Opcode.STUR, loadStoreUnscaled (ByRegister false) 0b00u
    Opcode.LDURB, loadStoreUnscaled (Fixed(0b00u, 0b01u, 1)) 0b00u
    Opcode.STURB, loadStoreUnscaled (Fixed(0b00u, 0b00u, 1)) 0b00u
    Opcode.LDURH, loadStoreUnscaled (Fixed(0b01u, 0b01u, 2)) 0b00u
    Opcode.STURH, loadStoreUnscaled (Fixed(0b01u, 0b00u, 2)) 0b00u
    Opcode.LDURSB, loadStoreUnscaled (Signed(0b00u, 1)) 0b00u
    Opcode.LDURSH, loadStoreUnscaled (Signed(0b01u, 2)) 0b00u
    Opcode.LDURSW, loadStoreUnscaled (Signed(0b10u, 4)) 0b00u
    Opcode.PRFUM, loadStoreUnscaled Prefetch 0b00u
    Opcode.LDTR, loadStoreUnscaled (ByRegister true) 0b10u
    Opcode.STTR, loadStoreUnscaled (ByRegister false) 0b10u
    Opcode.LDTRB, loadStoreUnscaled (Fixed(0b00u, 0b01u, 1)) 0b10u
    Opcode.STTRB, loadStoreUnscaled (Fixed(0b00u, 0b00u, 1)) 0b10u
    Opcode.LDTRH, loadStoreUnscaled (Fixed(0b01u, 0b01u, 2)) 0b10u
    Opcode.STTRH, loadStoreUnscaled (Fixed(0b01u, 0b00u, 2)) 0b10u
    Opcode.LDTRSB, loadStoreUnscaled (Signed(0b00u, 1)) 0b10u
    Opcode.LDTRSH, loadStoreUnscaled (Signed(0b01u, 2)) 0b10u
    Opcode.LDTRSW, loadStoreUnscaled (Signed(0b10u, 4)) 0b10u
    Opcode.LDP, loadStorePair 1u
    Opcode.STP, loadStorePair 0u
    Opcode.LDNP, loadStorePairNoAlloc 1u
    Opcode.STNP, loadStorePairNoAlloc 0u
    Opcode.LDPSW, loadPairSigned
    Opcode.STXRB, exclusiveStore (Some 0b00u) 0u
    Opcode.STLXRB, exclusiveStore (Some 0b00u) 1u
    Opcode.STXRH, exclusiveStore (Some 0b01u) 0u
    Opcode.STLXRH, exclusiveStore (Some 0b01u) 1u
    Opcode.LDXRB, exclusiveOne (Some 0b00u) 0u 1u 0u
    Opcode.LDAXRB, exclusiveOne (Some 0b00u) 0u 1u 1u
    Opcode.LDXRH, exclusiveOne (Some 0b01u) 0u 1u 0u
    Opcode.LDAXRH, exclusiveOne (Some 0b01u) 0u 1u 1u
    Opcode.STLRB, exclusiveOne (Some 0b00u) 1u 0u 1u
    Opcode.LDARB, exclusiveOne (Some 0b00u) 1u 1u 1u
    Opcode.STLRH, exclusiveOne (Some 0b01u) 1u 0u 1u
    Opcode.LDARH, exclusiveOne (Some 0b01u) 1u 1u 1u
    Opcode.STXR, exclusiveStore None 0u
    Opcode.STLXR, exclusiveStore None 1u
    Opcode.LDXR, exclusiveOne None 0u 1u 0u
    Opcode.LDAXR, exclusiveOne None 0u 1u 1u
    Opcode.STLR, exclusiveOne None 1u 0u 1u
    Opcode.LDAR, exclusiveOne None 1u 1u 1u
    Opcode.STXP, exclusivePairStore 0u
    Opcode.STLXP, exclusivePairStore 1u
    Opcode.LDXP, exclusivePairLoad 0u
    Opcode.LDAXP, exclusivePairLoad 1u
    Opcode.CAS, compareAndSwap 0u 0u
    Opcode.CASL, compareAndSwap 0u 1u
    Opcode.CASA, compareAndSwap 1u 0u
    Opcode.CASAL, compareAndSwap 1u 1u
    Opcode.LD1, structureOrElement 1u 1
    Opcode.LD2, structureOrElement 1u 2
    Opcode.LD3, structureOrElement 1u 3
    Opcode.LD4, structureOrElement 1u 4
    Opcode.ST1, structureOrElement 0u 1
    Opcode.ST2, structureOrElement 0u 2
    Opcode.ST3, structureOrElement 0u 3
    Opcode.ST4, structureOrElement 0u 4
    Opcode.LD1R, replicateAccess 1
    Opcode.LD2R, replicateAccess 2
    Opcode.LD3R, replicateAccess 3
    Opcode.LD4R, replicateAccess 4 ]

let dataProcRegEncoders () =
  [ Opcode.ADD, addSub 0u 0u
    Opcode.ADDS, addSub 0u 1u
    Opcode.SUB, addSub 1u 0u
    Opcode.SUBS, addSub 1u 1u
    Opcode.CMN, compareOperand 0u
    Opcode.CMP, compareOperand 1u
    Opcode.NEG, negate 0u
    Opcode.NEGS, negate 1u
    Opcode.ADC, addSubCarry 0u 0u
    Opcode.ADCS, addSubCarry 0u 1u
    Opcode.SBC, addSubCarry 1u 0u
    Opcode.SBCS, addSubCarry 1u 1u
    Opcode.NGC, negateCarry 0u
    Opcode.NGCS, negateCarry 1u
    Opcode.AND, logical 0b00u 0u
    Opcode.BIC, logical 0b00u 1u
    Opcode.ORR, logical 0b01u 0u
    Opcode.ORN, logical 0b01u 1u
    Opcode.EOR, logical 0b10u 0u
    Opcode.EON, logical 0b10u 1u
    Opcode.ANDS, logical 0b11u 0u
    Opcode.BICS, logical 0b11u 1u
    Opcode.MOV, move
    Opcode.MVN, moveNot
    Opcode.TST, test
    Opcode.CCMN, condCompare 0u
    Opcode.CCMP, condCompare 1u
    Opcode.CSEL, condSelect 0u 0b00u
    Opcode.CSINC, condSelect 0u 0b01u
    Opcode.CSINV, condSelect 1u 0b00u
    Opcode.CSNEG, condSelect 1u 0b01u
    Opcode.CINC, condSelectAlias 0u 0b01u
    Opcode.CSET, condSelectAlias 0u 0b01u
    Opcode.CINV, condSelectAlias 1u 0b00u
    Opcode.CSETM, condSelectAlias 1u 0b00u
    Opcode.CNEG, condSelectAlias 1u 0b01u
    Opcode.MADD, mulAccumulate 0b000u 0u
    Opcode.MSUB, mulAccumulate 0b000u 1u
    Opcode.SMADDL, mulAccumulate 0b001u 0u
    Opcode.SMSUBL, mulAccumulate 0b001u 1u
    Opcode.UMADDL, mulAccumulate 0b101u 0u
    Opcode.UMSUBL, mulAccumulate 0b101u 1u
    Opcode.MUL, multiply 0b000u 0u
    Opcode.MNEG, multiply 0b000u 1u
    Opcode.SMULL, multiply 0b001u 0u
    Opcode.SMNEGL, multiply 0b001u 1u
    Opcode.UMULL, multiply 0b101u 0u
    Opcode.UMNEGL, multiply 0b101u 1u
    Opcode.SMULH, multiply 0b010u 0u
    Opcode.UMULH, multiply 0b110u 0u
    Opcode.UDIV, dataProc2Src 0b000010u
    Opcode.SDIV, dataProc2Src 0b000011u
    Opcode.RORV, dataProc2Src 0b001011u
    Opcode.LSL, shift shiftLeftImm 0b001000u
    Opcode.LSR, shift (shiftRightImm 0b10u) 0b001001u
    Opcode.ASR, shift (shiftRightImm 0b00u) 0b001010u
    Opcode.ROR, rotateRight
    Opcode.CRC32B, crc32 0b010000u
    Opcode.CRC32H, crc32 0b010001u
    Opcode.CRC32W, crc32 0b010010u
    Opcode.CRC32X, crc32 0b010011u
    Opcode.CRC32CB, crc32 0b010100u
    Opcode.CRC32CH, crc32 0b010101u
    Opcode.CRC32CW, crc32 0b010110u
    Opcode.CRC32CX, crc32 0b010111u
    Opcode.RBIT, dataProc1Src 0b000000u
    Opcode.REV16, dataProc1Src 0b000001u
    Opcode.REV32, dataProc1Src 0b000010u
    Opcode.CLZ, dataProc1Src 0b000100u
    Opcode.CLS, dataProc1Src 0b000101u
    Opcode.CTZ, dataProc1Src 0b000110u
    Opcode.REV, reverse ]
