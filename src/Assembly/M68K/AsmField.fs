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
/// Turns the pieces of an instruction into the fields an m68k encoding is built
/// from, the effective-address field above all: it is what says how long an
/// instruction is, and every function here rejects what does not fit rather
/// than truncating it, because a field that silently drops a bit encodes an
/// instruction the source did not ask for.
/// </summary>
module internal B2R2.Assembly.M68K.AsmField

open B2R2
open B2R2.FrontEnd.M68K
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.M68K.ParserHelper

/// Reports a source this assembler cannot encode.
let fail msg = raise <| EncodingFailureException msg

/// Reports operands that do not belong to the given mnemonic.
let wrongOperands (ins: AsmInsInfo) =
  fail $"{ins.Mnemonic} does not take these operands"

/// Refuses an instruction that the member of the family being written for could
/// not read back, there being no point in writing one it would call illegal.
let requireModel (ins: AsmInsInfo) model what =
  if ins.Model >= model then () else fail $"{what} needs a later model"

/// Refuses a mnemonic that does not carry the width the encoding works at.
let requireSize (ins: AsmInsInfo) size =
  if ins.Size = size then ()
  else fail $"{ins.Mnemonic} is not written at this width"

/// Refuses a mnemonic that carries a width other than the one the encoding
/// works at. A source may leave the suffix off where there is only one width
/// the instruction has, which is what a person writing one does.
let requireOnlySize (ins: AsmInsInfo) size =
  if ins.Size = size || ins.Size = Sz.NoSize then ()
  else fail $"{ins.Mnemonic} is not written at this width"

/// Refuses a mnemonic that carries neither of the two widths an instruction
/// taking a whole address register works at, there being no byte of one.
let requireWordOrLong (ins: AsmInsInfo) =
  if ins.Size = Sz.Word || ins.Size = Sz.Long then ()
  else fail $"{ins.Mnemonic} is written at word or long width"

/// Whether a register is one of the eight a program computes with.
let isDataReg (reg: Register) = reg >= Register.D0 && reg <= Register.D7

/// Whether a register is one of the eight that hold an address.
let isAddrReg (reg: Register) = reg >= Register.A0 && reg <= Register.A7

/// Whether a register is one of the eight the floating-point unit computes
/// with.
let isFloatReg (reg: Register) = reg >= Register.FP0 && reg <= Register.FP7

/// Whether a register is one of the sixteen a program computes addresses and
/// values with, which is what every instruction naming a register in an
/// extension word names.
let isGeneralReg reg = isDataReg reg || isAddrReg reg

/// The three bits naming one of the eight data registers.
let dataNum (reg: Register) =
  if isDataReg reg then uint16 (int reg - int Register.D0)
  else fail $"{Register.toString reg} is not a data register"

/// The three bits naming one of the eight address registers.
let addrNum (reg: Register) =
  if isAddrReg reg then uint16 (int reg - int Register.A0)
  else fail $"{Register.toString reg} is not an address register"

/// The three bits naming one of the eight floating-point data registers.
let floatNum (reg: Register) =
  if isFloatReg reg then uint16 (int reg - int Register.FP0)
  else fail $"{Register.toString reg} is not a floating-point register"

/// The four bits naming a general register, the topmost of them saying which of
/// the two banks it belongs to.
let generalNum (reg: Register) =
  if isDataReg reg then dataNum reg
  elif isAddrReg reg then 8us ||| addrNum reg
  else fail $"{Register.toString reg} is not a general register"

/// The two bits saying how wide the operation is, which every instruction
/// carrying such a field spells the same way.
let sizeField (ins: AsmInsInfo) =
  match ins.Size with
  | Sz.Byte -> 0us
  | Sz.Word -> 1us
  | Sz.Long -> 2us
  | _ -> fail $"{ins.Mnemonic} is not written at this width"

/// The two words a long word occupies, the more significant of them first.
let longWords (v: uint32) = [ uint16 (v >>> 16); uint16 v ]

/// The bits one byte of immediate data holds, which a source may write either
/// as the bits themselves or as the number below zero they stand for.
let byteOf v =
  if v >= -128L && v <= 255L then uint16 (uint8 v)
  else fail $"{v} does not fit in one byte"

/// The bits one word of immediate data holds.
let wordOf v =
  if v >= -32768L && v <= 65535L then uint16 v
  else fail $"{v} does not fit in one word"

/// The bits one long word of immediate data holds.
let longOf v =
  if v >= -2147483648L && v <= 4294967295L then uint32 v
  else fail $"{v} does not fit in one long word"

/// How many bytes a number of the given real format occupies.
let private byteCount ins size =
  match size with
  | Sz.Single -> 4
  | Sz.Double -> 8
  | Sz.Extended | Sz.Packed -> 12
  | _ -> wrongOperands ins

/// The bytes a number of a real format is written as. A source writes the bits
/// themselves, either as an integer where they fit in one or as the bytes they
/// are where they do not.
let private floatBytes ins count opr =
  match opr with
  | AsmWideImm bytes when bytes.Length <= count ->
    Array.append (Array.zeroCreate (count - bytes.Length)) bytes
  | AsmImm v when count >= 8 || (v >= -2147483648L && v <= 4294967295L) ->
    Array.init count (fun i -> uint8 (uint64 v >>> ((count - 1 - i) * 8)))
  | _ ->
    fail $"{ins.Mnemonic} cannot hold this number"

/// The words a run of bytes holds, the more significant byte of each first.
let private wordsOfBytes (bytes: byte[]) =
  [ for i in 0 .. 2 .. bytes.Length - 2 ->
      (uint16 bytes[i] <<< 8) ||| uint16 bytes[i + 1] ]

/// The words immediate data of the given width occupies. Byte data sits in the
/// low half of one whole word, and a real format is written out as the bytes it
/// is, there being no integer wide enough for the widest of them.
let immWords ins size opr =
  match size, opr with
  | Sz.Byte, AsmImm v -> [ byteOf v ]
  | Sz.Word, AsmImm v -> [ wordOf v ]
  | Sz.Long, AsmImm v -> longWords (longOf v)
  | (Sz.Byte | Sz.Word | Sz.Long), _ -> wrongOperands ins
  | _ -> wordsOfBytes (floatBytes ins (byteCount ins size) opr)

/// Whether an effective address names data, which is anything but an address
/// register.
let isData mode (_: uint16) = mode <> 1us

/// Whether an effective address names memory, which is anything but a register.
let isMemory mode (_: uint16) = mode > 1us

/// Whether an effective address names a memory location without incrementing or
/// decrementing anything to reach it, which is what the manual calls control.
let isControl mode reg =
  isMemory mode reg && mode <> 3us && mode <> 4us && (mode <> 7us || reg < 4us)

/// Whether an effective address names something that can be written to, which
/// rules out the two modes counting from where the instruction sits and
/// immediate data.
let isAlterable mode (reg: uint16) = mode <> 7us || reg < 2us

/// Whether an effective address is anything at all, which is what an
/// instruction ruling out none of the modes allows.
let isAny (_: uint16) (_: uint16) = true

/// Whether an effective address is anything but immediate data.
let notImmediate mode reg = mode <> 7us || reg <> 4us

/// Whether an effective address is a data register or a control address, which
/// is what a bit field instruction names.
let isRegOrControl mode reg = mode = 0us || isControl mode reg

/// Whether an effective address belongs to both of the given categories.
let both f g mode reg = f mode reg && g mode reg

/// Whether an address is one that a run of values may be written to, which a
/// predecrement address and an alterable control address are the two ways of.
let isWritableRun mode reg =
  mode = 4us || (isControl mode reg && isAlterable mode reg)

/// Whether an address is one that a run of values may be read from, which is
/// the mirror of what it may be written to.
let isReadableRun mode reg = mode = 3us || isControl mode reg

/// Whether an absolute address fits the short form, which the processor
/// sign-extends from one word to the whole of an address.
let private fitsShort (v: uint64) =
  v <= 0x7fffUL || (v >= 0xffff8000UL && v <= 0xffffffffUL)

/// The register field and the extension words of an absolute address, which is
/// written in one word where sign-extending one reaches it and in two where
/// nothing but two will do.
let private addrWords (v: uint64) =
  if v > 0xffffffffUL then fail $"0x{v:x} is not an address"
  elif fitsShort v then 0us, [ uint16 v ]
  else 1us, longWords (uint32 v)

/// The bits naming the index register of an indexed mode, which say the
/// register, the width it is read at, and the factor it is scaled by.
let private indexBits ins (idx: AsmIndexReg) =
  let scale =
    match idx.Scale with
    | 1 -> 0us
    | 2 -> 1us
    | 4 -> 2us
    | 8 -> 3us
    | _ -> fail "an index is scaled by 1, 2, 4, or 8"
  if scale <> 0us then requireModel ins M68KModel.M68020 "a scaled index"
  else ()
  (generalNum idx.Reg <<< 12) ||| (if idx.IsLong then 0x800us else 0us)
  ||| (scale <<< 9)

/// The bits saying how wide a displacement of a full extension word is written,
/// which is null where it is zero, one word where it fits in one, and two words
/// where it does not.
let private dispSize v =
  if v = 0L then 1us elif v >= -32768L && v <= 32767L then 2us else 3us

/// The words a displacement of the given width occupies.
let private dispWords size v =
  match size with
  | 1us -> []
  | 2us -> [ uint16 v ]
  | _ when v >= -2147483648L && v <= 4294967295L -> longWords (uint32 v)
  | _ -> fail $"{v} is not a displacement"

/// Whether an indexed operand is one the brief extension word can say, which
/// holds a base register, an index, and a displacement of one byte.
let private isBrief (m: AsmIndex) =
  m.Base.IsSome && m.Index.IsSome && m.OuterDisp.IsNone
  && m.BaseDisp >= -128L && m.BaseDisp <= 127L

/// The extension word of a brief format indexed mode, whose displacement is the
/// signed byte in its low half.
let private briefWord ins (m: AsmIndex) =
  indexBits ins m.Index.Value ||| uint16 (uint8 m.BaseDisp)

/// <summary>
/// The extension words of a full format indexed mode, which the 68020 added.
///
/// How wide each of the two displacements is written is what says which of the
/// memory indirect modes this is, together with whether the index is added
/// before the indirect memory access or after it.
/// </summary>
let private fullWords ins (m: AsmIndex) =
  requireModel ins M68KModel.M68020 "this addressing mode"
  let bd = dispSize m.BaseDisp
  let od = m.OuterDisp |> Option.map dispSize |> Option.defaultValue 0us
  let iis =
    if m.Index.IsNone || m.OuterDisp.IsNone then od
    elif m.IsPreIndexed then od
    else 4us ||| od
  let index =
    m.Index |> Option.map (indexBits ins) |> Option.defaultValue 0x40us
  let baseBit = if m.Base.IsNone then 0x80us else 0us
  let outer = m.OuterDisp |> Option.map (dispWords od) |> Option.defaultValue []
  let ext = 0x100us ||| index ||| baseBit ||| (bd <<< 4) ||| iis
  ext :: (dispWords bd m.BaseDisp @ outer)

/// <summary>
/// The mode and register fields of an indexed mode, together with the extension
/// words it calls for.
///
/// A suppressed base leaves nothing to say whether the mode counted off a
/// register or the one counted off where the instruction sits was meant, so the
/// former is written, both of them meaning the same thing once the base is
/// gone.
/// </summary>
let private indexedEA ins (m: AsmIndex) =
  let words = if isBrief m then [ briefWord ins m ] else fullWords ins m
  match m.Base with
  | Some reg when reg = Register.PC -> 7us, 3us, words
  | Some reg -> 6us, addrNum reg, words
  | None -> 6us, 0us, words

/// The mode and register fields of a written distance from a register, which
/// falls back on the full extension word format where the distance is too wide
/// for the one word the simple mode holds.
let private dispEA ins v reg =
  if v >= -32768L && v <= 32767L then
    if reg = Register.PC then 7us, 2us, [ uint16 v ]
    else 5us, addrNum reg, [ uint16 v ]
  else
    { Base = Some reg
      Index = None
      BaseDisp = v
      OuterDisp = None
      IsPreIndexed = false }
    |> indexedEA ins

/// <summary>
/// The mode and register fields naming an effective address, together with the
/// extension words the mode calls for.
///
/// This is where the length of an m68k instruction is decided, the mnemonic
/// saying nothing about it. A place named by a label is reached by an absolute
/// address of two words, which is the widest form and so the one whose length
/// is known before it is known where anything sits.
/// </summary>
let encodeEA ins size opr =
  match opr with
  | AsmReg reg when isDataReg reg ->
    0us, dataNum reg, []
  | AsmReg reg when isAddrReg reg ->
    1us, addrNum reg, []
  | AsmMem(AsmDirect reg) ->
    2us, addrNum reg, []
  | AsmMem(AsmPostInc reg) ->
    3us, addrNum reg, []
  | AsmMem(AsmPreDec reg) ->
    4us, addrNum reg, []
  | AsmMem(AsmDisp(v, reg)) ->
    dispEA ins v reg
  | AsmMem(AsmIndexed m) ->
    indexedEA ins m
  | AsmAddr v ->
    let reg, words = addrWords v
    7us, reg, words
  | AsmTarget target ->
    7us, 1us, longWords (uint32 (defaultArg target 0UL))
  | AsmImm _ | AsmWideImm _ ->
    7us, 4us, immWords ins size opr
  | _ ->
    fail "this operand names no address"

/// The effective address an operand names, refused unless it belongs to the
/// category the instruction requires of it.
let eaOf allows ins size opr =
  let mode, reg, words = encodeEA ins size opr
  if allows mode reg then mode, reg, words
  else fail "this address cannot be named here"

/// The effective address a floating-point instruction names, which is any data
/// addressing mode the instruction itself allows. A data register holds no more
/// than a long word, so it can stand in only for the narrower of the formats.
let floatEA allows ins size opr =
  let mode, reg, words = eaOf (both isData allows) ins size opr
  let narrow =
    size = Sz.Byte || size = Sz.Word || size = Sz.Long || size = Sz.Single
  if mode = 0us && not narrow then
    fail "a register is too narrow to hold this format"
  else
    mode, reg, words

/// The opcode word of an instruction naming an effective address, given the
/// bits above that field.
let eaWord (head: uint16) mode reg = head ||| (mode <<< 3) ||| reg

/// <summary>
/// The mask naming a list of registers.
///
/// Which bit stands for which register depends on the addressing mode:
/// predecrement runs the mask the other way round, so that its lowest bit
/// stands for the last register of the bank rather than the first.
/// </summary>
let regMask (first: Register) count reversed regs =
  regs
  |> List.fold (fun mask reg ->
    let n = int reg - int first
    if n < 0 || n >= count then
      fail $"{Register.toString reg} cannot be named in this list"
    else
      mask ||| (1us <<< (if reversed then count - 1 - n else n))) 0us

/// <summary>
/// The registers a list operand names.
///
/// A list of one register is written as that register alone, which is how the
/// disassembler writes one, and a list of none as the zero the mask holding it
/// is, there being nothing else to write.
/// </summary>
let regsOf ins opr =
  match opr with
  | AsmRegList regs -> regs
  | AsmReg reg -> [ reg ]
  | AsmImm 0L -> []
  | _ -> wrongOperands ins

/// Whether an operand is one that names a list of registers.
let isRegListLike opr =
  match opr with
  | AsmRegList _ | AsmReg _ | AsmImm 0L -> true
  | _ -> false

/// <summary>
/// How far away the place an instruction names is, counted from the extension
/// word that would hold the answer, which is where the program counter points
/// once the opcode word has been read.
///
/// A source may write that distance itself, with the sign the disassembler
/// writes it with, or say where it wants to end up, either by naming a label or
/// by writing the address. A place whose address is not settled yet answers
/// with a distance every width can hold, so that how long the instruction is
/// can be counted before it is known where anything sits.
/// </summary>
let relOf (ins: AsmInsInfo) opr =
  match opr with
  | AsmRel v -> v
  | AsmAddr v -> int64 v - int64 (ins.Address + 2UL)
  | AsmTarget(Some target) -> int64 target - int64 (ins.Address + 2UL)
  | AsmTarget None -> 2L
  | _ -> wrongOperands ins

/// The one word a displacement of a word-sized branch occupies.
let relWord v =
  if v >= -32768L && v <= 32767L then [ uint16 v ]
  else fail $"{v} is too far to reach in one word"

/// The two words a displacement of a long branch occupies.
let relLongWords v =
  if v >= -2147483648L && v <= 2147483647L then longWords (uint32 v)
  else fail $"{v} is too far to reach"

/// The two words an absolute address written in full occupies, which is how the
/// block move names the place it does not count off a register.
let absLongWords ins opr =
  match opr with
  | AsmAddr v when v <= 0xffffffffUL -> longWords (uint32 v)
  | AsmTarget target -> longWords (uint32 (defaultArg target 0UL))
  | _ -> wrongOperands ins

/// <summary>
/// Represents what a mnemonic encodes as, together with the members of the
/// family that read it.
///
/// Which models read which instruction is Table A-1 of the manual read across,
/// and it is what the decoder itself asks before it accepts one, so an
/// instruction outside the range of the target is one that target could not
/// read back.
/// </summary>
type Row =
  { Encode: AsmInsInfo -> uint16 list
    /// The earliest member of the family that reads it.
    Since: M68KModel
    /// The latest one, which is the last of the family for all but the two the
    /// 68020 alone has.
    Until: M68KModel }

/// A mnemonic every member of the family reads.
let always encode =
  { Encode = encode; Since = M68KModel.M68000; Until = M68KModel.M68060 }

/// A mnemonic the given member of the family added.
let since model encode =
  { Encode = encode; Since = model; Until = M68KModel.M68060 }

/// A mnemonic one member of the family alone reads.
let onlyOn model encode = { Encode = encode; Since = model; Until = model }

// vim: set tw=80 sts=2 sw=2:
