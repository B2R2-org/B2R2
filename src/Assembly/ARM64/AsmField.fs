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
/// Turns the pieces of an instruction into the bit fields an A64 encoding is
/// built from. Every function here rejects what does not fit rather than
/// truncating it, because a field that silently drops a bit encodes an
/// instruction the source did not ask for.
/// </summary>
module internal B2R2.Assembly.ARM64.AsmField

open B2R2.FrontEnd.ARM64
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.ARM64.ParserHelper

/// Reports a source this assembler cannot encode.
let fail msg = raise <| EncodingFailureException msg

/// Reports operands that do not belong to the given opcode.
let wrongOperands (ins: AsmInsInfo) =
  fail $"{ins.Opcode} does not take these operands"

/// <summary>
/// The number a general register field holds, together with whether the
/// register is one of the sixty-four bit ones.
///
/// The stack pointer and the zero register share the number thirty-one. Which
/// of the two an encoding reads is fixed by the instruction rather than by the
/// field, so the two are told apart here only to reject a source that names the
/// one an instruction cannot reach.
/// </summary>
let private generalReg (reg: Register) =
  let number = int reg
  if number >= int Register.X0 && number <= int Register.XZR then
    uint32 number, true
  elif number >= int Register.W0 && number <= int Register.WZR then
    uint32 (number - int Register.W0), false
  elif reg = Register.SP then
    31u, true
  elif reg = Register.WSP then
    31u, false
  else
    fail $"{Register.toString reg} is not a general register"

/// Whether the register is one of the sixty-four bit general registers, which
/// is what the sf bit of an instruction says.
let is64Reg reg = snd (generalReg reg)

/// The sf bit, bit 31, which says an instruction works on the full width of its
/// registers rather than on the lower half.
let sfBit reg = if is64Reg reg then 1u <<< 31 else 0u

/// The five bits of a register field that reads the zero register where
/// thirty-one stands.
let coreReg (reg: Register) =
  match reg with
  | Register.SP | Register.WSP ->
    fail $"{Register.toString reg} cannot be named here"
  | reg ->
    fst (generalReg reg)

/// The same field where thirty-one is the stack pointer instead.
let coreRegSP (reg: Register) =
  match reg with
  | Register.XZR | Register.WZR ->
    fail $"{Register.toString reg} cannot be named here"
  | reg ->
    fst (generalReg reg)

/// The number of a SIMD or floating-point register named by its width, together
/// with that width in bits.
let scalarReg (reg: Register) =
  let number = int reg
  let ranges =
    [ Register.B0, 8
      Register.H0, 16
      Register.S0, 32
      Register.D0, 64
      Register.Q0, 128 ]
  match ranges |> List.tryFind (fun (first, _) ->
          number >= int first && number <= int first + 31) with
  | Some(first, width) -> uint32 (number - int first), width
  | None -> fail $"{Register.toString reg} is not a SIMD register"

/// How wide a SIMD or floating-point register is, if the register is one of
/// them at all, which is what says how wide an access naming it is.
let tryScalarWidth (reg: Register) =
  let number = int reg
  if number >= int Register.B0 && number <= int Register.Q31 then
    Some(snd (scalarReg reg))
  else
    None

/// The number of a SIMD or floating-point register of the given width in bits.
let simdReg width reg =
  let number, actual = scalarReg reg
  if actual = width then number
  else fail $"{Register.toString reg} is not {width} bits wide"

/// The number of a vector register, which is written by its own name rather
/// than by the width of one of its parts.
let vectorReg (reg: Register) =
  let number = int reg
  if number >= int Register.V0 && number <= int Register.V31 then
    uint32 (number - int Register.V0)
  else
    fail $"{Register.toString reg} is not a vector register"

/// The number of one of the sixteen registers a system instruction names.
let coprocReg (reg: Register) =
  let number = int reg
  if number >= int Register.C0 && number <= int Register.C15 then
    uint32 (number - int Register.C0)
  else
    fail $"{Register.toString reg} is not a system register"

/// A register operand, whichever of the two ways of writing one it took: a
/// SIMD register that names no part of itself is a register like any other.
let (|Rg|_|) = function
  | OprRegister reg -> Some reg
  | OprSIMD(ScalarReg reg) -> Some reg
  | _ -> None

/// An operand that stands for a number, whichever kind of number it is. The
/// disassembler tells a bit position from a count of bits from an immediate,
/// but a source writes all three the same way.
let (|Im|_|) = function
  | OprImm value -> Some value
  | OprNZCV value -> Some(int64 value)
  | OprLSB value -> Some(int64 value)
  | OprFbits value -> Some(int64 value)
  | _ -> None

/// A vector operand, which names the register and the arrangement it is read
/// in.
let (|Vec|_|) = function
  | OprSIMD(VecReg(reg, vec)) -> Some(reg, vec)
  | _ -> None

/// One element of a vector, which names how wide the elements are as well as
/// which of them is meant.
let (|Elem|_|) = function
  | OprSIMD(VecRegWithIdx(reg, vec, index)) -> Some(reg, vec, index)
  | _ -> None

/// <summary>
/// The size field and Q bit an arrangement stands for: how wide one element is
/// and whether the register holds twice as many of them.
/// </summary>
let arrangement = function
  | EightB -> 0b00u, 0u
  | SixteenB -> 0b00u, 1u
  | FourH -> 0b01u, 0u
  | EightH -> 0b01u, 1u
  | TwoS -> 0b10u, 0u
  | FourS -> 0b10u, 1u
  | OneD -> 0b11u, 0u
  | TwoD -> 0b11u, 1u
  | vec -> fail $"{vec} is not an arrangement a vector is read in"

/// <summary>
/// Which arrangements one member of a family accepts.
///
/// The manual leaves a different set of them out for almost every member, and
/// an arrangement it leaves out names no instruction at all, so each row of the
/// encoder tables says which set is its own rather than taking whatever the
/// registers it names happen to be written with.
/// </summary>
type Arrangements =
  /// Every arrangement a whole vector is read in.
  | Any
  /// Every one but the two of doubleword elements.
  | NotLong
  /// Every one but a lone doubleword, which is what a vector holding a single
  /// element would be.
  | NotLone
  /// The ones of halfword and word elements.
  | HalfAndWord
  /// The ones of byte elements.
  | ByteOnly
  /// The ones of byte and halfword elements.
  | UpToHalf
  /// The ones of byte, halfword and word elements, of which a word element
  /// leaves too few lanes to read across when there are only two of them.
  | Across
  /// The ones of byte elements and of doubleword ones, which is what a
  /// polynomial multiply of a long operand reaches.
  | ByteAndLong
  /// The ones of floating-point elements.
  | Float
  /// The ones of single-precision elements.
  | FloatWord
  /// The one arrangement of four single-precision elements.
  | FloatFourS

/// Whether the arrangement is one the family member accepts.
let private accepts allowed vec =
  match allowed, vec with
  | Any, _ -> true
  | NotLong, (EightB | SixteenB | FourH | EightH | TwoS | FourS) -> true
  | NotLone, (EightB | SixteenB | FourH | EightH | TwoS | FourS | TwoD) -> true
  | HalfAndWord, (FourH | EightH | TwoS | FourS) -> true
  | ByteOnly, (EightB | SixteenB) -> true
  | UpToHalf, (EightB | SixteenB | FourH | EightH) -> true
  | Across, (EightB | SixteenB | FourH | EightH | FourS) -> true
  | ByteAndLong, (EightB | SixteenB | OneD | TwoD) -> true
  | Float, (TwoS | FourS | TwoD) -> true
  | FloatWord, (TwoS | FourS) -> true
  | FloatFourS, FourS -> true
  | _ -> false

/// Rejects an arrangement the family member does not accept, which is one the
/// manual reserves rather than one the encoding cannot hold.
let checkArrangement (ins: AsmInsInfo) allowed vec =
  if accepts allowed vec then ()
  else fail $"{ins.Opcode} does not read a vector of {vec}"

/// The four bits that stand for a condition.
let condField = function
  | EQ -> 0b0000u
  | NE -> 0b0001u
  | CS | HS -> 0b0010u
  | CC | LO -> 0b0011u
  | MI -> 0b0100u
  | PL -> 0b0101u
  | VS -> 0b0110u
  | VC -> 0b0111u
  | HI -> 0b1000u
  | LS -> 0b1001u
  | GE -> 0b1010u
  | LT -> 0b1011u
  | GT -> 0b1100u
  | LE -> 0b1101u
  | AL -> 0b1110u
  | NV -> 0b1111u

/// <summary>
/// The condition that holds exactly when the given one does not.
///
/// The aliases of the conditional selects name the condition they run under,
/// which is the opposite of the one their encoding holds, so encoding one means
/// inverting what the source wrote.
/// </summary>
let invertCondition cond = condField cond ^^^ 1u

/// A value that has to fit an unsigned field of the given width.
let unsignedImm width (value: int64) =
  if value >= 0L && value < (1L <<< width) then uint32 value
  else fail $"#{value} does not fit in an unsigned {width}-bit field"

/// A value that has to fit a signed field of the given width, kept as the bit
/// pattern the field holds.
let signedImm width (value: int64) =
  let limit = 1L <<< (width - 1)
  if value >= -limit && value < limit then
    uint32 value &&& ((1u <<< width) - 1u)
  else
    fail $"#{value} does not fit in a signed {width}-bit field"

/// <summary>
/// A byte offset that the encoding holds divided by how wide one access is,
/// which is how every scaled offset is written.
///
/// An offset that is not a whole number of accesses has no encoding at all
/// rather than one that reaches somewhere else.
/// </summary>
let scaled (size: int) (value: int64) =
  if value % int64 size = 0L then value / int64 size
  else fail $"#{value} is not a multiple of {size}"

/// The number of bits by which an access of the given size scales its offset.
let scaleOf = function
  | 1 -> 0
  | 2 -> 1
  | 4 -> 2
  | 8 -> 3
  | 16 -> 4
  | size -> fail $"an access of {size} bytes has no scale"

/// The two bits that name a shift, which every shifted register operand holds
/// in the same place.
let shiftType = function
  | LSL -> 0b00u
  | LSR -> 0b01u
  | ASR -> 0b10u
  | ROR -> 0b11u
  | shift -> fail $"{shift} is not a shift a register operand takes"

/// The three bits that name an extension.
let extendType = function
  | UXTB -> 0b000u
  | UXTH -> 0b001u
  | UXTW -> 0b010u
  | UXTX -> 0b011u
  | SXTB -> 0b100u
  | SXTH -> 0b101u
  | SXTW -> 0b110u
  | SXTX -> 0b111u

/// The four bits that name a barrier's option.
let barrierOption = function
  | OSHLD -> 0b0001u
  | OSHST -> 0b0010u
  | OSH -> 0b0011u
  | NSHLD -> 0b0101u
  | NSHST -> 0b0110u
  | NSH -> 0b0111u
  | ISHLD -> 0b1001u
  | ISHST -> 0b1010u
  | ISH -> 0b1011u
  | LD -> 0b1101u
  | ST -> 0b1110u
  | SY -> 0b1111u

/// The five bits that name what a prefetch reads and where it keeps it.
let prefetchOperation = function
  | PLDL1KEEP -> 0b00000u
  | PLDL1STRM -> 0b00001u
  | PLDL2KEEP -> 0b00010u
  | PLDL2STRM -> 0b00011u
  | PLDL3KEEP -> 0b00100u
  | PLDL3STRM -> 0b00101u
  | PLIL1KEEP -> 0b01000u
  | PLIL1STRM -> 0b01001u
  | PLIL2KEEP -> 0b01010u
  | PLIL2STRM -> 0b01011u
  | PLIL3KEEP -> 0b01100u
  | PLIL3STRM -> 0b01101u
  | PSTL1KEEP -> 0b10000u
  | PSTL1STRM -> 0b10001u
  | PSTL2KEEP -> 0b10010u
  | PSTL2STRM -> 0b10011u
  | PSTL3KEEP -> 0b10100u
  | PSTL3STRM -> 0b10101u

/// The op1 and op2 fields that name the part of the processor state an
/// immediate move writes.
let pstateField = function
  | SPSEL -> 0b000101u
  | DAIFSET -> 0b011110u
  | DAIFCLR -> 0b011111u

/// The low bits of a value, as many of them as the given width has.
let private lowBits width (value: uint64) =
  if width >= 64 then value else value &&& ((1UL <<< width) - 1UL)

/// The value repeated to fill the given width, which is what one element of a
/// logical immediate stands for.
let private repeated width size element =
  let rec build acc shift =
    if shift >= width then acc
    else build (acc ||| (element <<< shift)) (shift + size)
  lowBits width (build 0UL 0)

/// The shortest element the value repeats in, which is the one its encoding
/// names.
let private elementSize width value =
  let rec search size =
    if size > width then fail $"#{value} is not a logical immediate"
    elif repeated width size (lowBits size value) = value then size
    else search (size * 2)
  search 2

/// Where the ones of an element sit, as the rotation that brings them together
/// at the bottom, which is the one the encoding holds.
let private rotationOf size count element =
  let ones = lowBits count System.UInt64.MaxValue
  let rotate amount =
    if amount = 0 then ones
    else lowBits size ((ones >>> amount) ||| (ones <<< (size - amount)))
  [ 0 .. size - 1 ] |> List.tryFind (fun amount -> rotate amount = element)

/// <summary>
/// The N, immr and imms fields of a logical immediate, which stand for a run of
/// ones of some length, rotated, and repeated to fill the register.
///
/// The manual gives the expansion rather than its inverse, so this looks for
/// the shortest element the value repeats in and then for the rotation that
/// brings the ones of that element together at the bottom. A value with no ones
/// in it, or with nothing but ones, has no encoding at all.
/// </summary>
let logicalImm width (value: int64) =
  let value = lowBits width (uint64 value)
  let size = elementSize width value
  let element = lowBits size value
  let count = System.Numerics.BitOperations.PopCount element
  if count = 0 || count = size then
    fail $"#{value} is not a logical immediate"
  else
    match rotationOf size count element with
    | None ->
      fail $"#{value} is not a logical immediate"
    | Some rotation ->
      let length = System.Numerics.BitOperations.Log2(uint32 size)
      let n = if size = 64 then 1u else 0u
      let imms =
        ((0b111111u <<< (length + 1)) &&& 0b111111u) ||| uint32 (count - 1)
      n, uint32 rotation, imms

/// <summary>
/// Whether a value a logical immediate could hold is one a move of a wide
/// immediate could hold too, which is what decides whether an ORR of an
/// immediate is written as a move.
///
/// This mirrors the manual's MoveWidePreferred, whose answer the disassembler
/// reads off the fields rather than off the value.
/// </summary>
let moveWidePreferred is64 (n: uint32, immr: uint32, imms: uint32) =
  let width = if is64 then 64 else 32
  let combined = (n <<< 6) ||| imms
  if is64 && combined &&& 0b1000000u <> 0b1000000u then false
  elif is64 && combined &&& 0b1100000u <> 0b0000000u then false
  elif imms < 16u then 0xf &&& (-(int immr) % 16) <= (15 - int imms)
  elif int imms >= width - 15 then int immr % 16 <= int imms - (width - 15)
  else false
