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

module internal B2R2.Assembly.S390.AsmField

open System
open B2R2.FrontEnd.S390
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.S390.ParserHelper

/// Represents the bank of registers a field names.
type RegKind =
  /// A general register.
  | Gpr
  /// A floating-point register.
  | Fpr
  /// An access register.
  | Apr
  /// A control register.
  | Cpr
  /// A vector register, together with where the bit above the four its own
  /// field holds is kept, which is in the byte such an instruction ends with.
  | Vpr of int

/// Represents a run of bits, counted from the first bit of the instruction the
/// way the architecture counts them.
type Field =
  { Pos: int
    Width: int }

/// Represents how wide the number a field holds is written out as.
type ImmForm =
  /// Written as the bits the field holds and nothing more.
  | Unsigned
  /// Widened to the given number of bits before being written, so that a
  /// number below zero is written as the bits it lands in once widened.
  | Signed of int

/// Represents where the number counted off a base register sits: in twelve
/// bits on their own, or in those twelve with eight more above them.
type Disp =
  | Short of Field
  | Long of Field * Field

/// <summary>
/// Represents one operand, said as the fields it is built out of.
///
/// Which fields those are is read off B2R2's own S390 decoder, one slot list
/// per shape of operands the decoder builds, so that what the assembler writes
/// cannot drift from what the decoder reads.
/// </summary>
type Slot =
  | RegField of RegKind * Field
  | MaskField of Field
  | ImmField of Field * ImmForm
  /// How far away a place is, which the encoding holds half of because every
  /// instruction is an even number of bytes long.
  | RelField of Field
  /// The memory an instruction reaches, as the register added to a base one,
  /// the base one, and the number counted off it.
  | MemField of (RegKind * Field) option * Field * Disp
  /// The memory an instruction reaches, together with how many bytes of it the
  /// instruction touches, which its field holds a fixed amount less than.
  | LenMemField of Field * uint16 * Field * Disp

/// The bits the given number of them holds when they are all set.
let private maskOf width =
  if width >= 64 then UInt64.MaxValue else (1UL <<< width) - 1UL

/// Puts the given bits into the given field of an instruction of the given
/// length, leaving the rest of it alone.
let place length fld value word =
  word ||| ((value &&& maskOf fld.Width) <<< (length * 8 - fld.Pos - fld.Width))

/// The bits the given field of an instruction of the given length holds.
let peek length fld word =
  (word >>> (length * 8 - fld.Pos - fld.Width)) &&& maskOf fld.Width

/// The first register of each bank, which a register's number is counted from.
let private firstOf = function
  | Gpr -> Register.R0
  | Fpr -> Register.FPR0
  | Apr -> Register.AR0
  | Cpr -> Register.CR0
  | Vpr _ -> Register.VR0

/// How many registers each bank holds.
let private sizeOf = function
  | Vpr _ -> 32
  | _ -> 16

/// The number the given register is known by within its own bank. A register
/// of another bank cannot be named where this one is, and saying so is what
/// keeps a source from naming one the encoding has no room for.
let private numberOf kind reg =
  let index = int reg - int (firstOf kind)
  if index < 0 || index >= sizeOf kind then
    raise
    <| EncodingFailureException $"{Register.toString reg} cannot be named here"
  else
    uint64 index

/// <summary>
/// Puts a register into its field.
///
/// A vector register is named by five bits rather than four, and the fifth of
/// them is kept away from the other four, in the byte such an instruction ends
/// with.
/// </summary>
let private encodeReg length kind fld reg word =
  let value = numberOf kind reg
  match kind with
  | Vpr bit ->
    place length fld value word
    |> place length { Pos = bit; Width = 1 } (value >>> 4)
  | Gpr | Fpr | Apr | Cpr ->
    place length fld value word

/// <summary>
/// Whether the given bits are something the given field can hold.
///
/// A field holding a number that never goes below zero holds any bits there are
/// few enough of. One that does go below zero holds half as many upwards, and
/// what is below zero arrives as the bits it lands in once widened, either to
/// the width the disassembler widens it to before writing it or to the whole of
/// a word, which is how a source of its own writes one. It is the widened forms
/// and not the bits themselves that are read as being below zero, so that a
/// source asking for a number too large to say is refused rather than quietly
/// given the negative one those bits stand for.
/// </summary>
let private fits form fld (value: uint64) =
  let sign = 1UL <<< (fld.Width - 1)
  let widened width =
    let bound = maskOf width
    value <= bound && value >= bound - sign + 1UL
  match form with
  | Unsigned -> value <= maskOf fld.Width || widened 64
  | Signed width -> value < sign || widened width || widened 64

/// Puts a written number into its field.
let private encodeImm length form fld value word =
  if fits form fld value then place length fld value word
  else raise <| EncodingFailureException $"0x{value:x} does not fit here"

/// Puts a set of bits selecting what an instruction does into its field.
let private encodeMask length fld (value: uint16) word =
  if uint64 value <= maskOf fld.Width then place length fld (uint64 value) word
  else raise <| EncodingFailureException $"a mask of 0x{value:x} is too wide"

/// Puts how far away a place is into its field, which holds half of it.
let private encodeRel length fld (value: uint64) word =
  let bound = 1L <<< (fld.Width - 1)
  let half = int64 value / 2L
  if int64 value % 2L <> 0L then
    raise <| EncodingFailureException $"0x{value:x} is an odd distance"
  elif half < -bound || half >= bound then
    raise <| EncodingFailureException $"0x{value:x} is too far to reach"
  else
    place length fld (uint64 half) word

/// Puts the number counted off a base register into the field or the two
/// fields holding it, the lower twelve bits of it first.
let private encodeDisp length disp value word =
  match disp with
  | Short fld ->
    encodeImm length Unsigned fld value word
  | Long(low, high) ->
    let whole = { Pos = low.Pos; Width = low.Width + high.Width }
    if fits (Signed 32) whole value then
      place length low value word |> place length high (value >>> low.Width)
    else
      raise <| EncodingFailureException $"0x{value:x} does not fit here"

/// Puts how many bytes an instruction touches into its field, which holds a
/// fixed amount less than that.
let private encodeLen length fld bias (value: uint16) word =
  if value < bias || uint64 (value - bias) > maskOf fld.Width then
    raise <| EncodingFailureException $"a length of {value} is not encodable"
  else
    place length fld (uint64 (value - bias)) word

/// Puts the register added to a base one into its field, refusing one where
/// the encoding holds none and asking for one where it does.
let private encodeIndex length slot index word =
  match slot, index with
  | Some(kind, fld), Some reg ->
    encodeReg length kind fld reg word
  | None, None ->
    word
  | Some _, None ->
    raise <| EncodingFailureException "this address names no index register"
  | None, Some _ ->
    raise <| EncodingFailureException "this address takes no index register"

/// Puts one operand into the fields its slot names, refusing one that is not
/// the kind of thing the slot holds.
let private encodeSlot length slot operand word =
  match slot, operand with
  | RegField(kind, fld), AsmReg reg ->
    encodeReg length kind fld reg word
  | MaskField fld, AsmMask value ->
    encodeMask length fld value word
  | ImmField(fld, form), AsmImm value ->
    encodeImm length form fld value word
  | RelField fld, AsmImm value ->
    encodeRel length fld value word
  | MemField(idx, bse, disp), AsmMem(index, baseReg, value) ->
    encodeIndex length idx index word
    |> encodeReg length Gpr bse baseReg
    |> encodeDisp length disp value
  | LenMemField(fld, bias, bse, disp), AsmMemLen(len, baseReg, value) ->
    encodeLen length fld bias len word
    |> encodeReg length Gpr bse baseReg
    |> encodeDisp length disp value
  | _ ->
    raise <| EncodingFailureException "an operand is not of the kind wanted"

/// Puts every operand of an instruction into the fields its slots name,
/// starting from the word the opcode alone makes.
let encode length slots operands word =
  if List.length slots <> List.length operands then
    raise <| EncodingFailureException "the wrong number of operands"
  else
    List.fold2 (fun acc slot opr -> encodeSlot length slot opr acc)
      word
      slots
      operands

// vim: set tw=80 sts=2 sw=2:
