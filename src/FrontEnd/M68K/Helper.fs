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

module internal B2R2.FrontEnd.M68K.Helper

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ParsingUtils

/// <summary>
/// Reads the extension words that follow an opcode word, tracking how far it
/// has read so that the length of the instruction falls out of where it stops.
/// An m68k instruction says how long it is only through the addressing modes
/// its operands use, and those are not known until the operands are decoded, so
/// nothing can measure the instruction ahead of decoding it.
/// </summary>
type ParsingHelper(reader: IBinReader, addr: Addr, model: M68KModel) =
  (* The opcode word is behind us: whoever built this has already read it. *)
  let mutable pos = 2

  /// Address of the instruction being parsed.
  member _.InsAddr with get(): Addr = addr

  /// The member of the family whose code is being parsed.
  member _.Model with get(): M68KModel = model

  /// Length in bytes of what has been read so far, which once the operands are
  /// decoded is the length of the instruction.
  member _.Length with get() = uint32 pos

  /// Reads the next extension word.
  member _.ReadInt16(span: ByteSpan) =
    let v = reader.ReadInt16(span, pos)
    pos <- pos + 2
    v

  /// Reads the next two extension words as one long word.
  member _.ReadInt32(span: ByteSpan) =
    let v = reader.ReadInt32(span, pos)
    pos <- pos + 4
    v

  /// Reads the given number of bytes, which is how the wider floating-point
  /// formats are carried: there is no integer wide enough to hold one.
  member _.ReadBytes(span: ByteSpan, count) =
    let v = span.Slice(pos, count).ToArray()
    pos <- pos + count
    v

/// Returns the index register that an extension word names, together with the
/// width it is read at and the factor it is scaled by. The 68000 and the 68010
/// do not decode the scale bits at all, so an index scaled for a 68020 counts
/// once on them, which is what they would really do with such an encoding.
let private toIndexReg (phlp: ParsingHelper) (ext: uint16) =
  let regNum = Bits.extract (uint32 ext) 14u 12u
  let reg =
    if ext &&& 0x8000us = 0us then RegisterHelper.toDataReg regNum
    else RegisterHelper.toAddrReg regNum
  let scale =
    if phlp.Model < M68KModel.M68020 then 1
    else 1 <<< int (Bits.extract (uint32 ext) 10u 9u)
  { Reg = reg; IsLong = ext &&& 0x800us <> 0us; Scale = scale }

/// Builds the operand of a brief extension word format, whose displacement is
/// the signed byte in its low half.
let private parseBrief phlp (ext: uint16) baseReg =
  { Base = Some baseReg
    Index = Some(toIndexReg phlp ext)
    BaseDisp = int32 (sbyte ext)
    OuterDisp = None
    IsPreIndexed = false }
  |> Indexed
  |> OpMem

/// Rejects the encodings of a full extension word that the manual leaves
/// reserved: a base displacement size of zero, a nonzero bit 3, and the
/// index/indirect selections that Table 2-2 marks reserved.
let private checkFull (ext: uint16) bdSize iis =
  if bdSize = 0u || ext &&& 0x8us <> 0us then raise ParsingFailureException
  elif iis = 4u then raise ParsingFailureException
  elif ext &&& 0x40us <> 0us && iis > 3u then raise ParsingFailureException
  else ()

/// Reads the base displacement, whose size field says whether it is absent, one
/// word, or two.
let private readBaseDisp (phlp: ParsingHelper) span bdSize =
  match bdSize with
  | 1u -> 0
  | 2u -> int32 (phlp.ReadInt16 span)
  | _ -> phlp.ReadInt32 span

/// Reads the outer displacement, whose size field says whether the mode is
/// indirect at all and, where it is, how wide the displacement is.
let private readOuterDisp (phlp: ParsingHelper) span odSize =
  match odSize with
  | 0u -> None
  | 1u -> Some 0
  | 2u -> Some(int32 (phlp.ReadInt16 span))
  | _ -> Some(phlp.ReadInt32 span)

/// Builds the operand of a full extension word format, reading the base
/// displacement and then the outer one, which is the order they appear in.
let private parseFull (phlp: ParsingHelper) span (ext: uint16) baseReg =
  let bdSize = Bits.extract (uint32 ext) 5u 4u
  let iis = Bits.extract (uint32 ext) 2u 0u
  checkFull ext bdSize iis
  let index =
    if ext &&& 0x40us <> 0us then None else Some(toIndexReg phlp ext)
  let baseDisp = readBaseDisp phlp span bdSize
  let outerDisp = readOuterDisp phlp span (iis &&& 0b11u)
  { Base = if ext &&& 0x80us <> 0us then None else Some baseReg
    Index = index
    BaseDisp = baseDisp
    OuterDisp = outerDisp
    IsPreIndexed = outerDisp.IsSome && index.IsSome && iis < 4u }
  |> Indexed
  |> OpMem

/// Reads the extension word of an indexed mode and builds the operand it names.
/// The 68000 and the 68010 read every such word as the brief format, because
/// the bit that selects the full one is among those they do not decode.
let private parseIndexed (phlp: ParsingHelper) span baseReg =
  let ext = phlp.ReadInt16 span |> uint16
  if phlp.Model < M68KModel.M68020 then parseBrief phlp ext baseReg
  elif ext &&& 0x100us = 0us then parseBrief phlp ext baseReg
  else parseFull phlp span ext baseReg

/// Reads the immediate operand that follows, whose width the size of the
/// operation gives. Byte data occupies the low half of one whole word, and a
/// real format is kept as the bytes it is, there being no integer wide enough
/// for the widest of them.
let parseImmData (phlp: ParsingHelper) span size =
  match size with
  | Sz.Byte -> OpImm(int64 (uint8 (phlp.ReadInt16 span)))
  | Sz.Word -> OpImm(int64 (uint16 (phlp.ReadInt16 span)))
  | Sz.Long -> OpImm(int64 (uint32 (phlp.ReadInt32 span)))
  | Sz.Single -> OpFImm(phlp.ReadBytes(span, 4))
  | Sz.Double -> OpFImm(phlp.ReadBytes(span, 8))
  | Sz.Extended | Sz.Packed -> OpFImm(phlp.ReadBytes(span, 12))
  | _ -> raise ParsingFailureException

/// Decodes the effective addresses whose mode field reads 111, where the
/// register field names the mode rather than a register.
let private parseEA7 (phlp: ParsingHelper) span size reg =
  match reg with
  | 0b000u -> OpAddr(uint64 (uint32 (int32 (phlp.ReadInt16 span))))
  | 0b001u -> OpAddr(uint64 (uint32 (phlp.ReadInt32 span)))
  | 0b010u -> OpMem(Disp(phlp.ReadInt16 span, R.PC))
  | 0b011u -> parseIndexed phlp span R.PC
  | 0b100u -> parseImmData phlp span size
  | _ -> raise ParsingFailureException

/// Decodes a six-bit effective-address field, reading whatever extension words
/// the addressing mode it names calls for. This is where the length of an m68k
/// instruction is decided.
let parseEA (phlp: ParsingHelper) span size mode reg =
  match mode with
  | 0b000u -> OpReg(RegisterHelper.toDataReg reg)
  | 0b001u -> OpReg(RegisterHelper.toAddrReg reg)
  | 0b010u -> OpMem(Direct(RegisterHelper.toAddrReg reg))
  | 0b011u -> OpMem(PostInc(RegisterHelper.toAddrReg reg))
  | 0b100u -> OpMem(PreDec(RegisterHelper.toAddrReg reg))
  | 0b101u -> OpMem(Disp(phlp.ReadInt16 span, RegisterHelper.toAddrReg reg))
  | 0b110u -> parseIndexed phlp span (RegisterHelper.toAddrReg reg)
  | _ -> parseEA7 phlp span size reg
