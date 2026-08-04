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

(*
  What this reads is the integer, supervisor, and floating-point instruction
  sets of the 68000 through the 68060, together with the cache, translation, and
  block move instructions the 68040 added. Three things share the encoding space
  and are not read: the generic coprocessor interface (cpGEN and its
  conditionals), the 68851 memory management coprocessor, which answers to
  coprocessor identifier zero, and what belongs to the CPU32 alone (BGND,
  LPSTOP, and the table lookup instructions).

  Where the manual and binutils disagree about whether an encoding is an
  instruction at all, this follows the manual. Those places are few and each is
  noted where it arises; the lengths agree everywhere.
*)

module internal B2R2.FrontEnd.M68K.ParsingMain

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ParsingUtils
open B2R2.FrontEnd.M68K.Helper

/// Shortcut for the parsing cursor.
type private Phlp = ParsingHelper

/// Raises a parsing failure unless the effective address belongs to the
/// category the instruction requires of it.
let private require ok = if ok then () else raise ParsingFailureException

/// Whether the effective address names data, which is anything but an address
/// register.
let private isData mode = mode <> 0b001u

/// Whether the effective address names memory, which is anything but a
/// register.
let private isMemory mode = mode > 0b001u

/// Whether the effective address names a memory location without incrementing
/// or decrementing anything to reach it, which is what the manual calls
/// control.
let private isControl mode reg =
  isMemory mode && mode <> 0b011u && mode <> 0b100u
  && (mode <> 0b111u || reg < 0b100u)

/// Whether the effective address names something that can be written to, which
/// rules out the two program counter relative modes and immediate data.
let private isAlterable mode reg = mode <> 0b111u || reg < 0b010u

/// Returns the size that a two-bit size field names, rejecting the fourth
/// value, which every instruction carrying such a field uses for something
/// else.
let private toSize field =
  match field with
  | 0b00u -> Sz.Byte
  | 0b01u -> Sz.Word
  | 0b10u -> Sz.Long
  | _ -> raise ParsingFailureException

/// The four families of conditional instruction, one entry per condition and
/// indexed by the four-bit condition field. The branch column holds BRA and BSR
/// where the others hold their always and never conditions, because those two
/// are what the encodings 0000 and 0001 of a Bcc name.
let private condOpcodes =
  [| Op.BRA, Op.ST, Op.DBT, Op.TRAPT
     Op.BSR, Op.SF, Op.DBF, Op.TRAPF
     Op.BHI, Op.SHI, Op.DBHI, Op.TRAPHI
     Op.BLS, Op.SLS, Op.DBLS, Op.TRAPLS
     Op.BCC, Op.SCC, Op.DBCC, Op.TRAPCC
     Op.BCS, Op.SCS, Op.DBCS, Op.TRAPCS
     Op.BNE, Op.SNE, Op.DBNE, Op.TRAPNE
     Op.BEQ, Op.SEQ, Op.DBEQ, Op.TRAPEQ
     Op.BVC, Op.SVC, Op.DBVC, Op.TRAPVC
     Op.BVS, Op.SVS, Op.DBVS, Op.TRAPVS
     Op.BPL, Op.SPL, Op.DBPL, Op.TRAPPL
     Op.BMI, Op.SMI, Op.DBMI, Op.TRAPMI
     Op.BGE, Op.SGE, Op.DBGE, Op.TRAPGE
     Op.BLT, Op.SLT, Op.DBLT, Op.TRAPLT
     Op.BGT, Op.SGT, Op.DBGT, Op.TRAPGT
     Op.BLE, Op.SLE, Op.DBLE, Op.TRAPLE |]

/// <summary>
/// Returns the registers that a register list mask names, lowest first. Which
/// bit stands for which register depends on the addressing mode: predecrement
/// runs the mask the other way round, so that its bit 0 stands for the last
/// register of the bank rather than the first.
/// </summary>
let private maskToRegs (mask: uint16) isReversed (first: Register) count =
  let baseNum = LanguagePrimitives.EnumToValue first
  [| for i in 0 .. count - 1 do
       if (mask >>> i) &&& 1us = 1us then
         let n = if isReversed then count - 1 - i else i
         LanguagePrimitives.EnumOfValue(baseNum + n): Register
       else () |]
  |> Array.sortBy LanguagePrimitives.EnumToValue

/// Returns the data register that the three bits ending at the given offset of
/// an extension word name.
let private dataAt (ext: uint16) hi =
  Bits.extract (uint32 ext) hi (hi - 2u) |> RegisterHelper.toDataReg

/// Returns the register that the top four bits of an extension word name, which
/// is how every instruction that carries one names a general register.
let private regOfExt (ext: uint16) =
  let num = Bits.extract (uint32 ext) 14u 12u
  if ext &&& 0x8000us = 0us then RegisterHelper.toDataReg num
  else RegisterHelper.toAddrReg num

/// Returns the immediate instruction that bits 11-9 of the opcode word name.
let private immOpcode hi =
  match hi with
  | 0b000u -> Op.ORI
  | 0b001u -> Op.ANDI
  | 0b010u -> Op.SUBI
  | 0b011u -> Op.ADDI
  | 0b101u -> Op.EORI
  | _ -> Op.CMPI

/// Returns the bit instruction that a two-bit field names.
let private bitOpcode field =
  match field with
  | 0b00u -> Op.BTST
  | 0b01u -> Op.BCHG
  | 0b10u -> Op.BCLR
  | _ -> Op.BSET

/// Parses one of the immediate instructions, including the forms of ORI, ANDI,
/// and EORI that name the condition code register or the whole status register
/// rather than an effective address.
let private parseImmediate (phlp: Phlp) span opcode sizeField mode reg =
  let size = toSize sizeField
  if mode = 0b111u && reg = 0b100u then
    require (opcode = Op.ORI || opcode = Op.ANDI || opcode = Op.EORI)
    require (size <> Sz.Long)
    let dst = if size = Sz.Byte then R.CCR else R.SR
    opcode, size, TwoOperands(parseImmData phlp span size, OpReg dst)
  else
    let readOnly = opcode = Op.CMPI && phlp.Model >= M68KModel.M68020
    require (isData mode && (readOnly || isAlterable mode reg))
    let imm = parseImmData phlp span size
    opcode, size, TwoOperands(imm, parseEA phlp span size mode reg)

/// Parses a MOVEP, which moves alternating bytes between a data register and a
/// peripheral, and so names its memory operand by a displacement alone.
let private parseMovep (phlp: Phlp) span dn opmode reg =
  let size = if opmode &&& 0b01u = 0u then Sz.Word else Sz.Long
  let mem = OpMem(Disp(phlp.ReadInt16 span, RegisterHelper.toAddrReg reg))
  if opmode &&& 0b10u = 0u then
    Op.MOVEP, size, TwoOperands(mem, OpReg dn)
  else
    Op.MOVEP, size, TwoOperands(OpReg dn, mem)

/// Parses one of the bit instructions whose bit number is in a register, or the
/// MOVEP that shares those encodings and is told apart by naming the one
/// addressing mode a bit instruction cannot reach. A bit of a data register is
/// one of thirty-two, and a bit of memory one of eight.
let private parseBitDynamic (phlp: Phlp) span (bin: uint16) mode reg =
  let dn = Bits.extract (uint32 bin) 11u 9u |> RegisterHelper.toDataReg
  let opmode = Bits.extract (uint32 bin) 7u 6u
  if mode = 0b001u then
    parseMovep phlp span dn opmode reg
  else
    let opcode = bitOpcode opmode
    require (isData mode && (opcode = Op.BTST || isAlterable mode reg))
    let size = if mode = 0b000u then Sz.Long else Sz.Byte
    opcode, size, TwoOperands(OpReg dn, parseEA phlp span size mode reg)

/// Parses one of the bit instructions whose bit number is immediate data, which
/// occupies the low half of the whole word that follows.
let private parseBitStatic (phlp: Phlp) span sizeField mode reg =
  let opcode = bitOpcode sizeField
  let readOnly = opcode = Op.BTST && (mode <> 0b111u || reg <> 0b100u)
  require (isData mode && (readOnly || isAlterable mode reg))
  let bit = OpImm(int64 (uint8 (phlp.ReadInt16 span)))
  let size = if mode = 0b000u then Sz.Long else Sz.Byte
  opcode, size, TwoOperands(bit, parseEA phlp span size mode reg)

/// Parses a CMP2 or a CHK2, which share every bit of the opcode word and differ
/// only in one bit of the extension word.
let private parseCmp2Chk2 (phlp: Phlp) span hi mode reg =
  require (isControl mode reg)
  let size = toSize hi
  let ext = uint16 (phlp.ReadInt16 span)
  require (ext &&& 0x7ffus = 0us)
  let bounds = parseEA phlp span size mode reg
  let opcode = if ext &&& 0x800us = 0us then Op.CMP2 else Op.CHK2
  opcode, size, TwoOperands(bounds, OpReg(regOfExt ext))

/// Parses a CALLM, or the RTM that shares its bits 11-6 and is told apart by
/// naming a register where CALLM names a control address.
let private parseCallmRtm (phlp: Phlp) span mode reg =
  if mode < 0b010u then
    let r =
      if mode = 0b000u then RegisterHelper.toDataReg reg
      else RegisterHelper.toAddrReg reg
    Op.RTM, Sz.NoSize, OneOperand(OpReg r)
  else
    require (isControl mode reg)
    let count = OpImm(int64 (uint8 (phlp.ReadInt16 span)))
    let ea = parseEA phlp span Sz.NoSize mode reg
    Op.CALLM, Sz.NoSize, TwoOperands(count, ea)

/// Parses a CAS2, which compares and swaps two memory locations at once, and so
/// carries two extension words and names three pairs of registers.
let private parseCas2 (phlp: Phlp) span size =
  let ext1 = uint16 (phlp.ReadInt16 span)
  let ext2 = uint16 (phlp.ReadInt16 span)
  require (ext1 &&& 0xe38us = 0us && ext2 &&& 0xe38us = 0us)
  let dc = OpRegPair(dataAt ext1 2u, dataAt ext2 2u)
  let du = OpRegPair(dataAt ext1 8u, dataAt ext2 8u)
  let mem = OpMemPair(regOfExt ext1, regOfExt ext2)
  Op.CAS2, size, ThreeOperands(dc, du, mem)

/// Parses a CAS, or the CAS2 that occupies the one encoding of its addressing
/// mode field naming no address at all. The size field here counts from one,
/// the zero it leaves free being where the bit instructions live.
let private parseCas (phlp: Phlp) span hi mode reg =
  let size = toSize ((hi &&& 0b011u) - 1u)
  if mode = 0b111u && reg = 0b100u then
    parseCas2 phlp span size
  else
    require (isMemory mode && isAlterable mode reg)
    let ext = uint16 (phlp.ReadInt16 span)
    require (ext &&& 0xfe38us = 0us)
    let dst = parseEA phlp span size mode reg
    Op.CAS, size, ThreeOperands(OpReg(dataAt ext 2u), OpReg(dataAt ext 8u), dst)

/// Parses a MOVES, which moves between a register and the address space that a
/// function code register selects.
let private parseMoves (phlp: Phlp) span sizeField mode reg =
  require (isMemory mode && isAlterable mode reg)
  let size = toSize sizeField
  let ext = uint16 (phlp.ReadInt16 span)
  require (ext &&& 0x7ffus = 0us)
  let ea = parseEA phlp span size mode reg
  let r = OpReg(regOfExt ext)
  if ext &&& 0x800us = 0us then
    Op.MOVES, size, TwoOperands(ea, r)
  else
    Op.MOVES, size, TwoOperands(r, ea)

/// Parses the group 0000 encodings that a size field of three sets aside: the
/// two that check a register against a pair of bounds, the two that call and
/// return from a module, and the two that compare and swap.
let private parseGroup0Escape (phlp: Phlp) span hi mode reg =
  match hi with
  | 0b000u | 0b001u | 0b010u -> parseCmp2Chk2 phlp span hi mode reg
  | 0b011u -> parseCallmRtm phlp span mode reg
  | _ -> parseCas phlp span hi mode reg

/// Parses group 0000, where the immediate instructions sit alongside the bit
/// instructions, MOVEP, and a handful the 68020 fitted into the encodings that
/// a size field of three leaves free.
let private parseGroup0 (phlp: Phlp) span (bin: uint16) =
  let hi = Bits.extract (uint32 bin) 11u 9u
  let sizeField = Bits.extract (uint32 bin) 7u 6u
  let mode = Bits.extract (uint32 bin) 5u 3u
  let reg = Bits.extract (uint32 bin) 2u 0u
  if bin &&& 0x100us <> 0us then parseBitDynamic phlp span bin mode reg
  elif hi = 0b100u then parseBitStatic phlp span sizeField mode reg
  elif sizeField = 0b11u then parseGroup0Escape phlp span hi mode reg
  elif hi = 0b111u then parseMoves phlp span sizeField mode reg
  else parseImmediate phlp span (immOpcode hi) sizeField mode reg

/// Rejects the effective addresses that a MOVE cannot name. Its destination has
/// to be data alterable, which rules out the two program counter relative modes
/// and immediate data, and a byte-sized MOVE cannot name an address register on
/// either side, there being no byte of one to move.
let private checkMove size srcMode dstMode dstReg =
  if size = Sz.Byte && (srcMode = 0b001u || dstMode = 0b001u) then
    raise ParsingFailureException
  elif dstMode = 0b111u && dstReg > 0b001u then
    raise ParsingFailureException
  else ()

/// Parses the three MOVE groups, whose bits 15-12 give the size of the
/// operation. The source extension words precede the destination's, so the
/// source has to be decoded first even though the destination field sits higher
/// in the opcode word. A destination that names an address register makes the
/// instruction a MOVEA.
let private parseMove (phlp: Phlp) span size (bin: uint16) =
  let srcMode = Bits.extract (uint32 bin) 5u 3u
  let srcReg = Bits.extract (uint32 bin) 2u 0u
  let dstMode = Bits.extract (uint32 bin) 8u 6u
  let dstReg = Bits.extract (uint32 bin) 11u 9u
  checkMove size srcMode dstMode dstReg
  let src = parseEA phlp span size srcMode srcReg
  if dstMode = 0b001u then
    let dst = OpReg(RegisterHelper.toAddrReg dstReg)
    Op.MOVEA, size, TwoOperands(src, dst)
  else
    let dst = parseEA phlp span size dstMode dstReg
    Op.MOVE, size, TwoOperands(src, dst)

/// Parses a CHK, whose bounds come from a data addressing mode. The long form
/// is a 68020 addition, so reading one on an earlier model means we are not
/// looking at code.
let private parseChk (phlp: Phlp) span size (bin: uint16) mode reg =
  require (isData mode)
  require (size = Sz.Word || phlp.Model >= M68KModel.M68020)
  let dst = Bits.extract (uint32 bin) 11u 9u |> RegisterHelper.toDataReg
  let src = parseEA phlp span size mode reg
  Op.CHK, size, TwoOperands(src, OpReg dst)

/// Parses a LEA, whose source has to be a control address, there being no
/// address to load otherwise.
let private parseLea (phlp: Phlp) span (bin: uint16) mode reg =
  require (isControl mode reg)
  let dst = Bits.extract (uint32 bin) 11u 9u |> RegisterHelper.toAddrReg
  let src = parseEA phlp span Sz.Long mode reg
  Op.LEA, Sz.Long, TwoOperands(src, OpReg dst)

/// Parses one of the one-operand instructions that write their result back
/// where they found it, so that their operand has to be data alterable.
let private parseUnary (phlp: Phlp) span opcode opmode mode reg =
  require (isData mode && isAlterable mode reg)
  let size = toSize opmode
  opcode, size, OneOperand(parseEA phlp span size mode reg)

/// Parses a MOVE that reads the status register or its low byte, whose
/// destination has to be data alterable. Reading the low byte alone is a 68010
/// addition.
let private parseMoveFrom (phlp: Phlp) span src mode reg =
  require (isData mode && isAlterable mode reg)
  require (src = R.SR || phlp.Model >= M68KModel.M68010)
  let dst = parseEA phlp span Sz.Word mode reg
  Op.MOVE, Sz.Word, TwoOperands(OpReg src, dst)

/// Parses a MOVE that writes the status register or its low byte, whose source
/// is any data addressing mode.
let private parseMoveTo (phlp: Phlp) span dst mode reg =
  require (isData mode)
  let src = parseEA phlp span Sz.Word mode reg
  Op.MOVE, Sz.Word, TwoOperands(src, OpReg dst)

/// Parses an NBCD, or the long form of LINK that shares its bits 11-6 and is
/// told apart by naming an address register, which NBCD cannot.
let private parseNbcdOrLink (phlp: Phlp) span mode reg =
  if mode = 0b001u then
    require (phlp.Model >= M68KModel.M68020)
    let disp = OpImm(int64 (phlp.ReadInt32 span))
    Op.LINK, Sz.Long, TwoOperands(OpReg(RegisterHelper.toAddrReg reg), disp)
  else
    require (isData mode && isAlterable mode reg)
    Op.NBCD, Sz.Byte, OneOperand(parseEA phlp span Sz.Byte mode reg)

/// Parses the two instructions that share bits 11-6 with PEA, each of which
/// names something PEA cannot: a data register to swap, or the vector of a
/// breakpoint.
let private parseSwapBkptPea (phlp: Phlp) span mode reg =
  match mode with
  | 0b000u ->
    Op.SWAP, Sz.Word, OneOperand(OpReg(RegisterHelper.toDataReg reg))
  | 0b001u ->
    require (phlp.Model >= M68KModel.M68010)
    Op.BKPT, Sz.NoSize, OneOperand(OpImm(int64 reg))
  | _ ->
    require (isControl mode reg)
    Op.PEA, Sz.Long, OneOperand(parseEA phlp span Sz.Long mode reg)

/// Parses an EXT, or the store form of MOVEM that shares its bits 11-6 and is
/// told apart by naming anything but a data register. The register list is the
/// first extension word, ahead of whatever the addressing mode calls for.
let private parseExtOrMovem (phlp: Phlp) span opmode mode reg =
  let size = if opmode = 0b010u then Sz.Word else Sz.Long
  if mode = 0b000u then
    Op.EXT, size, OneOperand(OpReg(RegisterHelper.toDataReg reg))
  else
    require (mode = 0b100u || (isControl mode reg && isAlterable mode reg))
    let mask = uint16 (phlp.ReadInt16 span)
    let regs = OpRegList(maskToRegs mask (mode = 0b100u) R.D0 16)
    Op.MOVEM, size, TwoOperands(regs, parseEA phlp span size mode reg)

/// Parses the load form of MOVEM, whose source is a control address or a
/// postincrement, the mirror of what the store form allows.
let private parseMovemLoad (phlp: Phlp) span opmode mode reg =
  require (mode = 0b011u || isControl mode reg)
  let size = if opmode = 0b010u then Sz.Word else Sz.Long
  let mask = uint16 (phlp.ReadInt16 span)
  let regs = OpRegList(maskToRegs mask false R.D0 16)
  Op.MOVEM, size, TwoOperands(parseEA phlp span size mode reg, regs)

/// Parses a TST, whose operand the 68020 widened to any addressing mode at all,
/// there being nothing to write back. An address register is still no operand
/// at byte size, there being no byte of one to test.
let private parseTst (phlp: Phlp) span opmode mode reg =
  let legacy = isData mode && isAlterable mode reg
  require (phlp.Model >= M68KModel.M68020 || legacy)
  let size = toSize opmode
  require (size <> Sz.Byte || mode <> 0b001u)
  Op.TST, size, OneOperand(parseEA phlp span size mode reg)

/// Parses a TAS, or the ILLEGAL instruction that occupies the one encoding of
/// its bits 11-6 naming no operand at all.
let private parseTasOrIllegal (phlp: Phlp) span mode reg =
  if mode = 0b111u && reg = 0b100u then
    Op.ILLEGAL, Sz.NoSize, NoOperand
  else
    require (isData mode && isAlterable mode reg)
    Op.TAS, Sz.Byte, OneOperand(parseEA phlp span Sz.Byte mode reg)

/// Parses the long form of a multiply, a 68020 addition whose extension word
/// says whether it is signed and whether the product fills one register or two.
let private parseMulLong (phlp: Phlp) span mode reg =
  require (phlp.Model >= M68KModel.M68020 && isData mode)
  let ext = uint16 (phlp.ReadInt16 span)
  require (ext &&& 0x83f8us = 0us)
  let src = parseEA phlp span Sz.Long mode reg
  let opcode = if ext &&& 0x800us = 0us then Op.MULU else Op.MULS
  let dst =
    if ext &&& 0x400us = 0us then OpReg(dataAt ext 14u)
    else OpRegPair(dataAt ext 2u, dataAt ext 14u)
  opcode, Sz.Long, TwoOperands(src, dst)

/// Parses the long form of a divide, whose extension word says whether it is
/// signed and whether the dividend fills one register or two. A dividend of one
/// register is what makes the mnemonic the DIVSL or DIVUL form.
let private parseDivLong (phlp: Phlp) span mode reg =
  require (phlp.Model >= M68KModel.M68020 && isData mode)
  let ext = uint16 (phlp.ReadInt16 span)
  require (ext &&& 0x83f8us = 0us)
  let src = parseEA phlp span Sz.Long mode reg
  let opcode =
    match ext &&& 0xc00us with
    | 0xc00us -> Op.DIVS
    | 0x800us -> Op.DIVSL
    | 0x400us -> Op.DIVU
    | _ -> Op.DIVUL
  let dst = OpRegPair(dataAt ext 2u, dataAt ext 14u)
  opcode, Sz.Long, TwoOperands(src, dst)

/// Parses a JMP or a JSR, whose target has to be a control address, there being
/// no address to jump to otherwise.
let private parseJump (phlp: Phlp) span opcode mode reg =
  require (isControl mode reg)
  opcode, Sz.NoSize, OneOperand(parseEA phlp span Sz.NoSize mode reg)

/// Returns the control register that the twelve-bit field of a MOVEC extension
/// word names. Which codes are assigned depends on the model, and any other one
/// is an illegal instruction.
let private toControlReg model code =
  match code with
  | 0x000u -> R.SFC
  | 0x001u -> R.DFC
  | 0x800u -> R.USP
  | 0x801u -> R.VBR
  | 0x002u when model >= M68KModel.M68020 -> R.CACR
  | 0x802u when model >= M68KModel.M68020 -> R.CAAR
  | 0x803u when model >= M68KModel.M68020 -> R.MSP
  | 0x804u when model >= M68KModel.M68020 -> R.ISP
  | 0x003u when model >= M68KModel.M68040 -> R.TC
  | 0x004u when model >= M68KModel.M68040 -> R.ITT0
  | 0x005u when model >= M68KModel.M68040 -> R.ITT1
  | 0x006u when model >= M68KModel.M68040 -> R.DTT0
  | 0x007u when model >= M68KModel.M68040 -> R.DTT1
  | 0x805u when model >= M68KModel.M68040 -> R.MMUSR
  | 0x806u when model >= M68KModel.M68040 -> R.URP
  | 0x807u when model >= M68KModel.M68040 -> R.SRP
  | _ -> raise ParsingFailureException

/// Parses a MOVEC, whose extension word names a control register by a code of
/// its own and a general register the way the rest of the family does.
let private parseMovec (phlp: Phlp) span toControl =
  let ext = uint16 (phlp.ReadInt16 span)
  let rc = OpReg(toControlReg phlp.Model (Bits.extract (uint32 ext) 11u 0u))
  let rn = OpReg(regOfExt ext)
  if toControl then Op.MOVEC, Sz.Long, TwoOperands(rn, rc)
  else Op.MOVEC, Sz.Long, TwoOperands(rc, rn)

/// Parses the system instructions from 0x4e40 to 0x4e6f, each of which names a
/// register or a vector in the low bits of the opcode word.
let private parseSystemReg (phlp: Phlp) span low reg =
  let an = OpReg(RegisterHelper.toAddrReg reg)
  match low >>> 3 with
  | 0b000u | 0b001u ->
    Op.TRAP, Sz.NoSize, OneOperand(OpImm(int64 (low &&& 0b1111u)))
  | 0b010u ->
    let disp = OpImm(int64 (phlp.ReadInt16 span))
    Op.LINK, Sz.Word, TwoOperands(an, disp)
  | 0b011u ->
    Op.UNLK, Sz.NoSize, OneOperand an
  | 0b100u ->
    Op.MOVE, Sz.Long, TwoOperands(an, OpReg R.USP)
  | _ ->
    Op.MOVE, Sz.Long, TwoOperands(OpReg R.USP, an)

/// Parses the system instructions from 0x4e70 up, none of which names a
/// register.
let private parseSystemFixed (phlp: Phlp) span low =
  match low with
  | 0b110000u ->
    Op.RESET, Sz.NoSize, NoOperand
  | 0b110001u ->
    Op.NOP, Sz.NoSize, NoOperand
  | 0b110010u ->
    let imm = OpImm(int64 (uint16 (phlp.ReadInt16 span)))
    Op.STOP, Sz.NoSize, OneOperand imm
  | 0b110011u ->
    Op.RTE, Sz.NoSize, NoOperand
  | 0b110100u ->
    require (phlp.Model >= M68KModel.M68010)
    Op.RTD, Sz.NoSize, OneOperand(OpImm(int64 (phlp.ReadInt16 span)))
  | 0b110101u ->
    Op.RTS, Sz.NoSize, NoOperand
  | 0b110110u ->
    Op.TRAPV, Sz.NoSize, NoOperand
  | 0b110111u ->
    Op.RTR, Sz.NoSize, NoOperand
  | 0b111010u | 0b111011u ->
    require (phlp.Model >= M68KModel.M68010)
    parseMovec phlp span (low = 0b111011u)
  | _ ->
    raise ParsingFailureException

/// Parses the system instructions, which share bits 11-6 and are told apart by
/// the six bits below them.
let private parseSystem (phlp: Phlp) span (bin: uint16) =
  let low = Bits.extract (uint32 bin) 5u 0u
  if low < 0b110000u then
    parseSystemReg phlp span low (Bits.extract (uint32 bin) 2u 0u)
  else
    parseSystemFixed phlp span low

/// Parses group 0100, whose members share almost nothing but the four bits that
/// name the group. Bits 11-9 and 8-6 between them name all but a few, which
/// give away which one they are by the addressing mode they use.
let private parseMisc (phlp: Phlp) span (bin: uint16) =
  let hi = Bits.extract (uint32 bin) 11u 9u
  let opmode = Bits.extract (uint32 bin) 8u 6u
  let mode = Bits.extract (uint32 bin) 5u 3u
  let reg = Bits.extract (uint32 bin) 2u 0u
  match hi, opmode with
  | _, 0b101u -> raise ParsingFailureException
  | _, 0b100u -> parseChk phlp span Sz.Long bin mode reg
  | _, 0b110u -> parseChk phlp span Sz.Word bin mode reg
  | 0b100u, 0b111u when mode = 0b000u ->
    Op.EXTB, Sz.Long, OneOperand(OpReg(RegisterHelper.toDataReg reg))
  | _, 0b111u -> parseLea phlp span bin mode reg
  | 0b000u, 0b011u -> parseMoveFrom phlp span R.SR mode reg
  | 0b001u, 0b011u -> parseMoveFrom phlp span R.CCR mode reg
  | 0b010u, 0b011u -> parseMoveTo phlp span R.CCR mode reg
  | 0b011u, 0b011u -> parseMoveTo phlp span R.SR mode reg
  | 0b000u, _ -> parseUnary phlp span Op.NEGX opmode mode reg
  | 0b001u, _ -> parseUnary phlp span Op.CLR opmode mode reg
  | 0b010u, _ -> parseUnary phlp span Op.NEG opmode mode reg
  | 0b011u, _ -> parseUnary phlp span Op.NOT opmode mode reg
  | 0b100u, 0b000u -> parseNbcdOrLink phlp span mode reg
  | 0b100u, 0b001u -> parseSwapBkptPea phlp span mode reg
  | 0b100u, _ -> parseExtOrMovem phlp span opmode mode reg
  | 0b101u, 0b011u -> parseTasOrIllegal phlp span mode reg
  | 0b101u, _ -> parseTst phlp span opmode mode reg
  | 0b110u, 0b000u -> parseMulLong phlp span mode reg
  | 0b110u, 0b001u -> parseDivLong phlp span mode reg
  | 0b110u, _ -> parseMovemLoad phlp span opmode mode reg
  | 0b111u, 0b001u -> parseSystem phlp span bin
  | 0b111u, 0b010u -> parseJump phlp span Op.JSR mode reg
  | 0b111u, 0b011u -> parseJump phlp span Op.JMP mode reg
  | _ -> raise ParsingFailureException

/// Parses an ADDQ or a SUBQ. A data field of zero means eight, there being no
/// use for adding an immediate zero, and the destination has to be alterable.
/// An address register takes part whole, so the manual allows one only at word
/// and long size; binutils enforces that for ADDQ and not for SUBQ, which is a
/// difference the manual draws between neither.
let private parseAddqSubq (phlp: Phlp) span size (bin: uint16) =
  let mode = Bits.extract (uint32 bin) 5u 3u
  let reg = Bits.extract (uint32 bin) 2u 0u
  require (isAlterable mode reg)
  require (size <> Sz.Byte || mode <> 0b001u)
  let field = Bits.extract (uint32 bin) 11u 9u
  let data = if field = 0u then 8L else int64 field
  let opcode = if bin &&& 0x100us = 0us then Op.ADDQ else Op.SUBQ
  opcode, size, TwoOperands(OpImm data, parseEA phlp span size mode reg)

/// Parses a TRAPcc, whose operand the low three bits of the opcode word name:
/// one word of immediate data, two, or none at all.
let private parseTrapcc (phlp: Phlp) span opcode reg =
  match reg with
  | 0b010u ->
    let imm = OpImm(int64 (uint16 (phlp.ReadInt16 span)))
    opcode, Sz.Word, OneOperand imm
  | 0b011u ->
    let imm = OpImm(int64 (uint32 (phlp.ReadInt32 span)))
    opcode, Sz.Long, OneOperand imm
  | _ ->
    require (reg = 0b100u)
    opcode, Sz.NoSize, NoOperand

/// Parses group 0101, which holds the quick add and subtract alongside the
/// three conditional instructions that carry no displacement of their own. A
/// size field of three is what tells the latter from the former.
let private parseGroup5 (phlp: Phlp) span (bin: uint16) =
  let sizeField = Bits.extract (uint32 bin) 7u 6u
  if sizeField <> 0b11u then
    parseAddqSubq phlp span (toSize sizeField) bin
  else
    let cc = Bits.extract (uint32 bin) 11u 8u |> int
    let _, scc, dbcc, trapcc = condOpcodes[cc]
    let mode = Bits.extract (uint32 bin) 5u 3u
    let reg = Bits.extract (uint32 bin) 2u 0u
    if mode = 0b001u then
      let counter = OpReg(RegisterHelper.toDataReg reg)
      let disp = OpRelAddr(int32 (phlp.ReadInt16 span))
      dbcc, Sz.Word, TwoOperands(counter, disp)
    elif mode = 0b111u && reg > 0b001u then
      parseTrapcc phlp span trapcc reg
    else
      require (isData mode && isAlterable mode reg)
      scc, Sz.Byte, OneOperand(parseEA phlp span Sz.Byte mode reg)

/// Parses group 0110, the branches. A displacement byte of zero means the
/// displacement is the extension word that follows, and one of all ones that it
/// is the two words that follow, which the 68020 added; the earlier models read
/// that byte as the displacement it looks like.
let private parseBranch (phlp: Phlp) span (bin: uint16) =
  let cc = Bits.extract (uint32 bin) 11u 8u |> int
  let opcode, _, _, _ = condOpcodes[cc]
  let disp = int (sbyte bin)
  if disp = 0 then
    opcode, Sz.Word, OneOperand(OpRelAddr(int32 (phlp.ReadInt16 span)))
  elif disp = -1 && phlp.Model >= M68KModel.M68020 then
    opcode, Sz.Long, OneOperand(OpRelAddr(phlp.ReadInt32 span))
  else
    opcode, Sz.Byte, OneOperand(OpRelAddr(int32 disp))

/// Parses group 0111, which holds MOVEQ alone. Its data is a byte the processor
/// sign-extends to the whole of the register, so bit 8 is not a size field but
/// a bit that has to be zero.
let private parseMoveq (bin: uint16) =
  require (bin &&& 0x100us = 0us)
  let reg = Bits.extract (uint32 bin) 11u 9u |> RegisterHelper.toDataReg
  Op.MOVEQ, Sz.Long, TwoOperands(OpImm(int64 (sbyte bin)), OpReg reg)

/// Returns the pair of operands that the decimal and the extended arithmetic
/// name: either two data registers, or two predecremented addresses.
let private pairOperands (bin: uint16) =
  let mode = Bits.extract (uint32 bin) 5u 3u
  let src = Bits.extract (uint32 bin) 2u 0u
  let dst = Bits.extract (uint32 bin) 11u 9u
  if mode = 0b000u then
    let s = OpReg(RegisterHelper.toDataReg src)
    s, OpReg(RegisterHelper.toDataReg dst)
  else
    let s = OpMem(PreDec(RegisterHelper.toAddrReg src))
    s, OpMem(PreDec(RegisterHelper.toAddrReg dst))

/// Parses one of the instructions that work on such a pair of operands.
let private parsePairOp (bin: uint16) opcode size =
  let src, dst = pairOperands bin
  opcode, size, TwoOperands(src, dst)

/// Parses a PACK or an UNPK, which carry an adjustment word of their own
/// between the two halves of a decimal digit and the byte holding them.
let private parsePackUnpk (phlp: Phlp) span opcode (bin: uint16) =
  let src, dst = pairOperands bin
  let adj = OpImm(int64 (uint16 (phlp.ReadInt16 span)))
  opcode, Sz.NoSize, ThreeOperands(src, dst, adj)

/// Parses one of the word-sized divides or multiplies, whose source is any data
/// addressing mode and whose destination is a data register.
let private parseDivMulWord (phlp: Phlp) span opcode (bin: uint16) =
  let mode = Bits.extract (uint32 bin) 5u 3u
  let reg = Bits.extract (uint32 bin) 2u 0u
  require (isData mode)
  let dn = Bits.extract (uint32 bin) 11u 9u |> RegisterHelper.toDataReg
  let src = parseEA phlp span Sz.Word mode reg
  opcode, Sz.Word, TwoOperands(src, OpReg dn)

/// Parses one of the logical instructions, whose source is any data addressing
/// mode where the result goes to the register, and whose destination is
/// alterable memory where it goes the other way.
let private parseLogical (phlp: Phlp) span opcode opmode (bin: uint16) =
  let mode = Bits.extract (uint32 bin) 5u 3u
  let reg = Bits.extract (uint32 bin) 2u 0u
  let dn = Bits.extract (uint32 bin) 11u 9u |> RegisterHelper.toDataReg
  let size = toSize (opmode &&& 0b011u)
  if opmode < 0b100u then
    require (isData mode)
    opcode, size, TwoOperands(parseEA phlp span size mode reg, OpReg dn)
  else
    require (isMemory mode && isAlterable mode reg)
    opcode, size, TwoOperands(OpReg dn, parseEA phlp span size mode reg)

/// Parses an ADD, a SUB, or a CMP. Its source may be an address register at
/// word and long size, there being no byte of one, and where the result goes
/// back to memory the destination has to be alterable.
let private parseArith (phlp: Phlp) span opcode opmode (bin: uint16) =
  let mode = Bits.extract (uint32 bin) 5u 3u
  let reg = Bits.extract (uint32 bin) 2u 0u
  let dn = Bits.extract (uint32 bin) 11u 9u |> RegisterHelper.toDataReg
  let size = toSize (opmode &&& 0b011u)
  if opmode < 0b100u then
    require (isData mode || size <> Sz.Byte)
    opcode, size, TwoOperands(parseEA phlp span size mode reg, OpReg dn)
  else
    require (isMemory mode && isAlterable mode reg)
    opcode, size, TwoOperands(OpReg dn, parseEA phlp span size mode reg)

/// Parses an ADDA, a SUBA, or a CMPA, whose source is any addressing mode at
/// all and whose destination is an address register taken whole.
let private parseArithAddr (phlp: Phlp) span opcode size (bin: uint16) =
  let mode = Bits.extract (uint32 bin) 5u 3u
  let reg = Bits.extract (uint32 bin) 2u 0u
  let an = Bits.extract (uint32 bin) 11u 9u |> RegisterHelper.toAddrReg
  opcode, size, TwoOperands(parseEA phlp span size mode reg, OpReg an)

/// Parses an EOR, which has only the one direction and whose destination is
/// data alterable rather than the alterable memory that the OR and the AND
/// require of theirs, a data register being something one can exclusive-OR
/// into.
let private parseEor (phlp: Phlp) span opmode (bin: uint16) =
  let mode = Bits.extract (uint32 bin) 5u 3u
  let reg = Bits.extract (uint32 bin) 2u 0u
  let dn = Bits.extract (uint32 bin) 11u 9u |> RegisterHelper.toDataReg
  let size = toSize (opmode &&& 0b011u)
  require (isData mode && isAlterable mode reg)
  Op.EOR, size, TwoOperands(OpReg dn, parseEA phlp span size mode reg)

/// Parses a CMPM, which walks two blocks of memory a postincrement at a time.
let private parseCmpm (bin: uint16) size =
  let src = Bits.extract (uint32 bin) 2u 0u |> RegisterHelper.toAddrReg
  let dst = Bits.extract (uint32 bin) 11u 9u |> RegisterHelper.toAddrReg
  Op.CMPM, size, TwoOperands(OpMem(PostInc src), OpMem(PostInc dst))

/// Parses an EXG, whose two registers the size field and the addressing mode
/// between them say the kind of. There is no exchange of a data register with
/// an address register the other way round, so one of the four combinations
/// names nothing.
let private parseExg (bin: uint16) opmode mode =
  let x = Bits.extract (uint32 bin) 11u 9u
  let y = Bits.extract (uint32 bin) 2u 0u
  if opmode = 0b101u && mode = 0b000u then
    let dx = OpReg(RegisterHelper.toDataReg x)
    Op.EXG, Sz.Long, TwoOperands(dx, OpReg(RegisterHelper.toDataReg y))
  elif opmode = 0b101u then
    let ax = OpReg(RegisterHelper.toAddrReg x)
    Op.EXG, Sz.Long, TwoOperands(ax, OpReg(RegisterHelper.toAddrReg y))
  else
    let dx = OpReg(RegisterHelper.toDataReg x)
    Op.EXG, Sz.Long, TwoOperands(dx, OpReg(RegisterHelper.toAddrReg y))

/// Parses group 1000, which holds the inclusive OR alongside the word divide
/// and the three instructions that work on a pair of registers or a pair of
/// predecremented addresses.
let private parseGroup8 (phlp: Phlp) span (bin: uint16) =
  let opmode = Bits.extract (uint32 bin) 8u 6u
  let mode = Bits.extract (uint32 bin) 5u 3u
  match opmode with
  | 0b011u -> parseDivMulWord phlp span Op.DIVU bin
  | 0b111u -> parseDivMulWord phlp span Op.DIVS bin
  | 0b100u when mode < 0b010u -> parsePairOp bin Op.SBCD Sz.Byte
  | 0b101u when mode < 0b010u -> parsePackUnpk phlp span Op.PACK bin
  | 0b110u when mode < 0b010u -> parsePackUnpk phlp span Op.UNPK bin
  | _ -> parseLogical phlp span Op.OR opmode bin

/// Parses group 1001, the subtractions.
let private parseGroup9 (phlp: Phlp) span (bin: uint16) =
  let opmode = Bits.extract (uint32 bin) 8u 6u
  let mode = Bits.extract (uint32 bin) 5u 3u
  match opmode with
  | 0b011u -> parseArithAddr phlp span Op.SUBA Sz.Word bin
  | 0b111u -> parseArithAddr phlp span Op.SUBA Sz.Long bin
  | _ when opmode > 0b011u && mode < 0b010u ->
    parsePairOp bin Op.SUBX (toSize (opmode &&& 0b011u))
  | _ -> parseArith phlp span Op.SUB opmode bin

/// Parses group 1011, which holds the comparisons alongside the exclusive OR.
/// The direction bit that makes the others write back to memory makes this one
/// an EOR, or a CMPM where the addressing mode is a postincrement.
let private parseGroupB (phlp: Phlp) span (bin: uint16) =
  let opmode = Bits.extract (uint32 bin) 8u 6u
  let mode = Bits.extract (uint32 bin) 5u 3u
  match opmode with
  | 0b011u -> parseArithAddr phlp span Op.CMPA Sz.Word bin
  | 0b111u -> parseArithAddr phlp span Op.CMPA Sz.Long bin
  | _ when opmode > 0b011u && mode = 0b001u ->
    parseCmpm bin (toSize (opmode &&& 0b011u))
  | _ when opmode > 0b011u -> parseEor phlp span opmode bin
  | _ -> parseArith phlp span Op.CMP opmode bin

/// Parses group 1100, which holds the logical AND alongside the word multiply,
/// the decimal add, and the register exchange.
let private parseGroupC (phlp: Phlp) span (bin: uint16) =
  let opmode = Bits.extract (uint32 bin) 8u 6u
  let mode = Bits.extract (uint32 bin) 5u 3u
  match opmode with
  | 0b011u -> parseDivMulWord phlp span Op.MULU bin
  | 0b111u -> parseDivMulWord phlp span Op.MULS bin
  | 0b100u when mode < 0b010u -> parsePairOp bin Op.ABCD Sz.Byte
  | 0b101u when mode < 0b010u -> parseExg bin opmode mode
  | 0b110u when mode = 0b001u -> parseExg bin opmode mode
  | _ -> parseLogical phlp span Op.AND opmode bin

/// Parses group 1101, the additions.
let private parseGroupD (phlp: Phlp) span (bin: uint16) =
  let opmode = Bits.extract (uint32 bin) 8u 6u
  let mode = Bits.extract (uint32 bin) 5u 3u
  match opmode with
  | 0b011u -> parseArithAddr phlp span Op.ADDA Sz.Word bin
  | 0b111u -> parseArithAddr phlp span Op.ADDA Sz.Long bin
  | _ when opmode > 0b011u && mode < 0b010u ->
    parsePairOp bin Op.ADDX (toSize (opmode &&& 0b011u))
  | _ -> parseArith phlp span Op.ADD opmode bin

/// The four families of shift and rotate, indexed by the type field and then by
/// the bit that says which way it goes.
let private shiftOpcodes =
  [| Op.ASR, Op.ASL
     Op.LSR, Op.LSL
     Op.ROXR, Op.ROXL
     Op.ROR, Op.ROL |]

/// The eight bit field instructions, indexed by bits 10-8 of the opcode word.
let private bitFieldOpcodes =
  [| Op.BFTST
     Op.BFEXTU
     Op.BFCHG
     Op.BFEXTS
     Op.BFCLR
     Op.BFFFO
     Op.BFSET
     Op.BFINS |]

/// Returns the shift or rotate that a type field and a direction bit name.
let private shiftOpcode kind isLeft =
  let right, left = shiftOpcodes[int kind]
  if isLeft then left else right

/// Parses a shift or rotate of a data register, whose count is either immediate
/// data of one to eight -- a field of zero meaning eight -- or another
/// register.
let private parseShiftReg (bin: uint16) size =
  let kind = Bits.extract (uint32 bin) 4u 3u
  let opcode = shiftOpcode kind (bin &&& 0x100us <> 0us)
  let field = Bits.extract (uint32 bin) 11u 9u
  let dst = Bits.extract (uint32 bin) 2u 0u |> RegisterHelper.toDataReg
  let count =
    if bin &&& 0x20us <> 0us then OpReg(RegisterHelper.toDataReg field)
    elif field = 0u then OpImm 8L
    else OpImm(int64 field)
  opcode, size, TwoOperands(count, OpReg dst)

/// Parses a shift or rotate of a word in memory, which moves it by one place
/// and so names no count at all.
let private parseShiftMem (phlp: Phlp) span (bin: uint16) mode reg =
  require (isMemory mode && isAlterable mode reg)
  let kind = Bits.extract (uint32 bin) 10u 9u
  let opcode = shiftOpcode kind (bin &&& 0x100us <> 0us)
  opcode, Sz.Word, OneOperand(parseEA phlp span Sz.Word mode reg)

/// Reads the extension word of a bit field instruction, whose offset and width
/// are each either a literal or the data register holding one. A width of zero
/// means the whole thirty-two bits, there being no field of no bits.
let private parseBitFieldSpec (phlp: Phlp) span =
  let ext = uint16 (phlp.ReadInt16 span)
  let offset =
    if ext &&& 0x800us = 0us then
      OpImm(int64 (Bits.extract (uint32 ext) 10u 6u))
    else
      require (Bits.extract (uint32 ext) 10u 9u = 0u)
      OpReg(dataAt ext 8u)
  let width =
    if ext &&& 0x20us = 0us then
      let w = Bits.extract (uint32 ext) 4u 0u
      OpImm(if w = 0u then 32L else int64 w)
    else
      require (Bits.extract (uint32 ext) 4u 3u = 0u)
      OpReg(dataAt ext 2u)
  ext, { Offset = offset; Width = width }

/// Parses one of the bit field instructions. The four that only read the field
/// may name a control address or a data register, and the four that write it
/// need that address to be alterable; of the eight, the four that move the
/// field to or from a register name it in the extension word.
let private parseBitField (phlp: Phlp) span (bin: uint16) mode reg =
  let opcode = bitFieldOpcodes[int (Bits.extract (uint32 bin) 10u 8u)]
  let writes = opcode = Op.BFCHG || opcode = Op.BFCLR || opcode = Op.BFSET
  require (mode = 0b000u || isControl mode reg)
  require (not (writes || opcode = Op.BFINS) || isAlterable mode reg)
  let ext, spec = parseBitFieldSpec phlp span
  let field = OpBitField(parseEA phlp span Sz.NoSize mode reg, spec)
  match opcode with
  | Op.BFINS ->
    require (ext &&& 0x8000us = 0us)
    opcode, Sz.NoSize, TwoOperands(OpReg(dataAt ext 14u), field)
  | Op.BFEXTU | Op.BFEXTS | Op.BFFFO ->
    require (ext &&& 0x8000us = 0us)
    opcode, Sz.NoSize, TwoOperands(field, OpReg(dataAt ext 14u))
  | _ ->
    require (ext &&& 0xf000us = 0us)
    opcode, Sz.NoSize, OneOperand field

/// Parses group 1110, which holds the shifts and rotates and, in the encodings
/// that a size field of three sets aside, the bit field instructions the 68020
/// added.
let private parseGroupE (phlp: Phlp) span (bin: uint16) =
  let sizeField = Bits.extract (uint32 bin) 7u 6u
  let mode = Bits.extract (uint32 bin) 5u 3u
  let reg = Bits.extract (uint32 bin) 2u 0u
  if sizeField <> 0b11u then parseShiftReg bin (toSize sizeField)
  elif bin &&& 0x800us = 0us then parseShiftMem phlp span bin mode reg
  else parseBitField phlp span bin mode reg

/// The floating-point conditional predicates, one entry per encoding, in the
/// order of Table 8-1 and each with the four families it names an instruction
/// in: a branch, a set, a decrement and branch, and a trap.
let private fpuCondOpcodes =
  [| Op.FBF, Op.FSF, Op.FDBF, Op.FTRAPF
     Op.FBEQ, Op.FSEQ, Op.FDBEQ, Op.FTRAPEQ
     Op.FBOGT, Op.FSOGT, Op.FDBOGT, Op.FTRAPOGT
     Op.FBOGE, Op.FSOGE, Op.FDBOGE, Op.FTRAPOGE
     Op.FBOLT, Op.FSOLT, Op.FDBOLT, Op.FTRAPOLT
     Op.FBOLE, Op.FSOLE, Op.FDBOLE, Op.FTRAPOLE
     Op.FBOGL, Op.FSOGL, Op.FDBOGL, Op.FTRAPOGL
     Op.FBOR, Op.FSOR, Op.FDBOR, Op.FTRAPOR
     Op.FBUN, Op.FSUN, Op.FDBUN, Op.FTRAPUN
     Op.FBUEQ, Op.FSUEQ, Op.FDBUEQ, Op.FTRAPUEQ
     Op.FBUGT, Op.FSUGT, Op.FDBUGT, Op.FTRAPUGT
     Op.FBUGE, Op.FSUGE, Op.FDBUGE, Op.FTRAPUGE
     Op.FBULT, Op.FSULT, Op.FDBULT, Op.FTRAPULT
     Op.FBULE, Op.FSULE, Op.FDBULE, Op.FTRAPULE
     Op.FBNE, Op.FSNE, Op.FDBNE, Op.FTRAPNE
     Op.FBT, Op.FST, Op.FDBT, Op.FTRAPT
     Op.FBSF, Op.FSSF, Op.FDBSF, Op.FTRAPSF
     Op.FBSEQ, Op.FSSEQ, Op.FDBSEQ, Op.FTRAPSEQ
     Op.FBGT, Op.FSGT, Op.FDBGT, Op.FTRAPGT
     Op.FBGE, Op.FSGE, Op.FDBGE, Op.FTRAPGE
     Op.FBLT, Op.FSLT, Op.FDBLT, Op.FTRAPLT
     Op.FBLE, Op.FSLE, Op.FDBLE, Op.FTRAPLE
     Op.FBGL, Op.FSGL, Op.FDBGL, Op.FTRAPGL
     Op.FBGLE, Op.FSGLE, Op.FDBGLE, Op.FTRAPGLE
     Op.FBNGLE, Op.FSNGLE, Op.FDBNGLE, Op.FTRAPNGLE
     Op.FBNGL, Op.FSNGL, Op.FDBNGL, Op.FTRAPNGL
     Op.FBNLE, Op.FSNLE, Op.FDBNLE, Op.FTRAPNLE
     Op.FBNLT, Op.FSNLT, Op.FDBNLT, Op.FTRAPNLT
     Op.FBNGE, Op.FSNGE, Op.FDBNGE, Op.FTRAPNGE
     Op.FBNGT, Op.FSNGT, Op.FDBNGT, Op.FTRAPNGT
     Op.FBSNE, Op.FSSNE, Op.FDBSNE, Op.FTRAPSNE
     Op.FBST, Op.FSST, Op.FDBST, Op.FTRAPST |]

/// Returns the floating-point operation that a seven-bit opmode field names.
/// Everything above 0x40 is a 68040 addition: the same operation with its
/// result rounded to a narrower precision than the extended one it works in.
let private fpuOpcode opmode =
  match opmode with
  | 0x00u -> Op.FMOVE
  | 0x01u -> Op.FINT
  | 0x02u -> Op.FSINH
  | 0x03u -> Op.FINTRZ
  | 0x04u -> Op.FSQRT
  | 0x06u -> Op.FLOGNP1
  | 0x08u -> Op.FETOXM1
  | 0x09u -> Op.FTANH
  | 0x0au -> Op.FATAN
  | 0x0cu -> Op.FASIN
  | 0x0du -> Op.FATANH
  | 0x0eu -> Op.FSIN
  | 0x0fu -> Op.FTAN
  | 0x10u -> Op.FETOX
  | 0x11u -> Op.FTWOTOX
  | 0x12u -> Op.FTENTOX
  | 0x14u -> Op.FLOGN
  | 0x15u -> Op.FLOG10
  | 0x16u -> Op.FLOG2
  | 0x18u -> Op.FABS
  | 0x19u -> Op.FCOSH
  | 0x1au -> Op.FNEG
  | 0x1cu -> Op.FACOS
  | 0x1du -> Op.FCOS
  | 0x1eu -> Op.FGETEXP
  | 0x1fu -> Op.FGETMAN
  | 0x20u -> Op.FDIV
  | 0x21u -> Op.FMOD
  | 0x22u -> Op.FADD
  | 0x23u -> Op.FMUL
  | 0x24u -> Op.FSGLDIV
  | 0x25u -> Op.FREM
  | 0x26u -> Op.FSCALE
  | 0x27u -> Op.FSGLMUL
  | 0x28u -> Op.FSUB
  | 0x38u -> Op.FCMP
  | 0x3au -> Op.FTST
  | 0x40u -> Op.FSMOVE
  | 0x41u -> Op.FSSQRT
  | 0x44u -> Op.FDMOVE
  | 0x45u -> Op.FDSQRT
  | 0x58u -> Op.FSABS
  | 0x5au -> Op.FSNEG
  | 0x5cu -> Op.FDABS
  | 0x5eu -> Op.FDNEG
  | 0x60u -> Op.FSDIV
  | 0x62u -> Op.FSADD
  | 0x63u -> Op.FSMUL
  | 0x64u -> Op.FDDIV
  | 0x66u -> Op.FDADD
  | 0x67u -> Op.FDMUL
  | 0x68u -> Op.FSSUB
  | 0x6cu -> Op.FDSUB
  | _ when opmode &&& 0x78u = 0x30u -> Op.FSINCOS
  | _ -> raise ParsingFailureException

/// Returns the format that a source specifier names, which is what an
/// instruction reading its operand from memory carries as its suffix.
let private toFloatSize spec =
  match spec with
  | 0b000u -> Sz.Long
  | 0b001u -> Sz.Single
  | 0b010u -> Sz.Extended
  | 0b011u -> Sz.Packed
  | 0b100u -> Sz.Word
  | 0b101u -> Sz.Double
  | 0b110u -> Sz.Byte
  | _ -> raise ParsingFailureException

/// Reads the operand of a floating-point instruction that takes one from
/// memory. A data register holds no more than a long word, so it can stand in
/// only for the narrower formats.
let private parseFloatEA (phlp: Phlp) span size mode reg =
  require (isData mode)
  let narrow =
    size = Sz.Byte || size = Sz.Word || size = Sz.Long || size = Sz.Single
  require (mode <> 0b000u || narrow)
  parseEA phlp span size mode reg

/// Parses one of the floating-point arithmetic instructions. Where the source
/// is an effective address, the source specifier names the format to read it
/// in, which is what the mnemonic's suffix says; where it is a register, the
/// format is the extended precision the unit works in throughout.
let private parseFloatArith (phlp: Phlp) span (cmd: uint16) mode reg =
  let spec = Bits.extract (uint32 cmd) 12u 10u
  let dst = Bits.extract (uint32 cmd) 9u 7u |> RegisterHelper.toFloatReg
  let opmode = Bits.extract (uint32 cmd) 6u 0u
  let opcode = fpuOpcode opmode
  let fromEA = cmd &&& 0x4000us <> 0us
  let size = if fromEA then toFloatSize spec else Sz.Extended
  let src =
    if fromEA then parseFloatEA phlp span size mode reg
    else OpReg(RegisterHelper.toFloatReg spec)
  if opcode = Op.FTST then
    opcode, size, OneOperand src
  elif opcode = Op.FSINCOS then
    let cos = OpReg(RegisterHelper.toFloatReg (opmode &&& 0b111u))
    opcode, size, ThreeOperands(src, cos, OpReg dst)
  else
    opcode, size, TwoOperands(src, OpReg dst)

/// Parses an FMOVECR, which loads one of the constants the unit keeps in a
/// table of its own and so names no address at all.
let private parseFmovecr (cmd: uint16) =
  let dst = Bits.extract (uint32 cmd) 9u 7u |> RegisterHelper.toFloatReg
  let offset = OpImm(int64 (Bits.extract (uint32 cmd) 6u 0u))
  Op.FMOVECR, Sz.Extended, TwoOperands(offset, OpReg dst)

/// Parses an FMOVE that writes a register out to memory. A packed decimal
/// destination carries a k-factor saying how much of the number to write, and
/// which of the two packed specifiers is used says whether that k-factor is a
/// literal or the data register holding one.
let private parseFloatToMem (phlp: Phlp) span (cmd: uint16) mode reg =
  let spec = Bits.extract (uint32 cmd) 12u 10u
  let dynamic = spec = 0b111u
  let size = if dynamic then Sz.Packed else toFloatSize spec
  let src = OpReg(RegisterHelper.toFloatReg (Bits.extract (uint32 cmd) 9u 7u))
  require (isMemory mode && isAlterable mode reg || mode = 0b000u)
  let dst = parseFloatEA phlp span size mode reg
  if dynamic then
    require (cmd &&& 0xfus = 0us)
    let k = OpReg(RegisterHelper.toDataReg (Bits.extract (uint32 cmd) 6u 4u))
    Op.FMOVE, size, ThreeOperands(src, dst, k)
  elif size = Sz.Packed then
    (* A static k-factor is seven bits of two's complement, so the top of that
       range is where the negative half of it starts. *)
    let raw = int32 (cmd &&& 0x7fus)
    let k = OpImm(int64 (if raw >= 0x40 then raw - 0x80 else raw))
    Op.FMOVE, size, ThreeOperands(src, dst, k)
  else
    require (cmd &&& 0x7fus = 0us)
    Op.FMOVE, size, TwoOperands(src, dst)

/// Parses an FMOVE or an FMOVEM that names the control registers. One register
/// makes it an FMOVE and any other number of them an FMOVEM, there being no
/// single register for the latter to move. An address register is allowed here,
/// which is what the instruction address register is for.
let private parseFloatCtrl (phlp: Phlp) span (cmd: uint16) mode reg =
  require (cmd &&& 0x3ffus = 0us)
  let select = Bits.extract (uint32 cmd) 12u 10u
  let regs =
    [| if select &&& 0b100u <> 0u then R.FPCR else ()
       if select &&& 0b010u <> 0u then R.FPSR else ()
       if select &&& 0b001u <> 0u then R.FPIAR else () |]
  require (regs.Length > 0)
  let single = regs.Length = 1
  require (cmd &&& 0x2000us = 0us || isAlterable mode reg)
  (* A register holds one long word, so it can stand for one control register
     and no more; a list of several has to be somewhere in memory. *)
  require (single || isMemory mode)
  let opcode = if single then Op.FMOVE else Op.FMOVEM
  let list = if single then OpReg regs[0] else OpRegList regs
  let ea = parseEA phlp span Sz.Long mode reg
  if cmd &&& 0x2000us = 0us then
    opcode, Sz.Long, TwoOperands(ea, list)
  else
    opcode, Sz.Long, TwoOperands(list, ea)

/// Whether the addressing mode of an FMOVEM agrees with the mode field of its
/// command word and with the direction it moves. A predecrement address walks
/// memory downwards, which is what writing the registers out to it does; a
/// postincrement one walks upwards, which is what reading them back in does;
/// and a control address, which walks nowhere, serves either way.
let private isFmovemMode mmode toMem mode reg =
  if mode = 0b100u then mmode < 0b10u && toMem
  elif mode = 0b011u then mmode >= 0b10u && not toMem
  elif not (isControl mode reg) then false
  else mmode >= 0b10u && (not toMem || isAlterable mode reg)

/// Parses an FMOVEM of the data registers, whose list is either the eight bits
/// of the command word or a data register holding them. Predecrement addressing
/// runs a static list the other way round, as it does for an integer MOVEM.
let private parseFmovem (phlp: Phlp) span (cmd: uint16) mode reg =
  require (Bits.extract (uint32 cmd) 10u 8u = 0u)
  let mmode = Bits.extract (uint32 cmd) 12u 11u
  require (isFmovemMode mmode (cmd &&& 0x2000us <> 0us) mode reg)
  let list =
    if mmode &&& 0b01u <> 0u then
      require (cmd &&& 0x8fus = 0us)
      OpReg(RegisterHelper.toDataReg (Bits.extract (uint32 cmd) 6u 4u))
    else
      let reversed = mmode = 0b00u
      OpRegList(maskToRegs (cmd &&& 0xffus) reversed R.FP0 8)
  let ea = parseFloatEA phlp span Sz.Extended mode reg
  if cmd &&& 0x2000us = 0us then
    Op.FMOVEM, Sz.Extended, TwoOperands(ea, list)
  else
    Op.FMOVEM, Sz.Extended, TwoOperands(list, ea)

/// Parses one of the instructions whose second word is the command word that
/// the coprocessor rather than the processor reads. Which of them it is turns
/// on the top three bits of that word.
let private parseFloatGeneral (phlp: Phlp) span mode reg =
  let cmd = uint16 (phlp.ReadInt16 span)
  match Bits.extract (uint32 cmd) 15u 13u with
  (* Where the source is a register, no operand is fetched, so the coprocessor
     never asks the processor to evaluate the effective address field and
     nothing decodes it. Whatever it holds is therefore not a reason to refuse
     the instruction, and it costs no extension words either. *)
  | 0b000u -> parseFloatArith phlp span cmd mode reg
  | 0b010u when Bits.extract (uint32 cmd) 12u 10u = 0b111u ->
    (* An FMOVECR names no address, and the manual encodes the whole of the
       effective address field as zero rather than leaving it a field. *)
    require (mode = 0u && reg = 0u)
    parseFmovecr cmd
  | 0b010u -> parseFloatArith phlp span cmd mode reg
  | 0b011u -> parseFloatToMem phlp span cmd mode reg
  | 0b100u | 0b101u -> parseFloatCtrl phlp span cmd mode reg
  | 0b110u | 0b111u -> parseFmovem phlp span cmd mode reg
  | _ -> raise ParsingFailureException

/// Parses an FScc, an FDBcc, or an FTRAPcc, which share bits 8-6 and are told
/// apart the way their integer counterparts are: by the addressing mode field.
let private parseFloatCond (phlp: Phlp) span mode reg =
  let cond = uint16 (phlp.ReadInt16 span)
  require (cond &&& 0xffc0us = 0us)
  let _, scc, dbcc, trapcc = fpuCondOpcodes[int (cond &&& 0x3fus)]
  if mode = 0b001u then
    let counter = OpReg(RegisterHelper.toDataReg reg)
    let disp = OpRelAddr(int32 (phlp.ReadInt16 span))
    dbcc, Sz.Word, TwoOperands(counter, disp)
  elif mode = 0b111u && reg > 0b001u then
    parseTrapcc phlp span trapcc reg
  else
    require (isData mode && isAlterable mode reg)
    scc, Sz.Byte, OneOperand(parseEA phlp span Sz.Byte mode reg)

/// Parses an FBcc, whose condition is in the opcode word itself and whose
/// displacement is one word or two, as bit 6 says.
let private parseFBcc (phlp: Phlp) span (bin: uint16) size =
  let opcode, _, _, _ = fpuCondOpcodes[int (bin &&& 0x3fus)]
  let disp =
    if size = Sz.Word then int32 (phlp.ReadInt16 span)
    else phlp.ReadInt32 span
  opcode, size, OneOperand(OpRelAddr disp)

/// Parses an FSAVE or an FRESTORE, which move the whole internal state of the
/// coprocessor and so name a control address and no format.
let private parseFloatState (phlp: Phlp) span opcode mode reg =
  if opcode = Op.FSAVE then
    require (mode = 0b100u || (isControl mode reg && isAlterable mode reg))
  else
    require (mode = 0b011u || isControl mode reg)
  opcode, Sz.NoSize, OneOperand(parseEA phlp span Sz.NoSize mode reg)

/// Parses the instructions of the floating-point coprocessor, whose bits 8-6
/// say which shape the instruction has rather than which operation it performs.
let private parseFloat (phlp: Phlp) span (bin: uint16) =
  let mode = Bits.extract (uint32 bin) 5u 3u
  let reg = Bits.extract (uint32 bin) 2u 0u
  match Bits.extract (uint32 bin) 8u 6u with
  | 0b000u -> parseFloatGeneral phlp span mode reg
  | 0b001u -> parseFloatCond phlp span mode reg
  | 0b010u -> parseFBcc phlp span bin Sz.Word
  | 0b011u -> parseFBcc phlp span bin Sz.Long
  | 0b100u -> parseFloatState phlp span Op.FSAVE mode reg
  | 0b101u -> parseFloatState phlp span Op.FRESTORE mode reg
  | _ -> raise ParsingFailureException

/// Parses a CINV or a CPUSH, whose scope the 68040 spells into the mnemonic and
/// whose caches it names as an operand.
let private parseCache (phlp: Phlp) (bin: uint16) =
  require (phlp.Model >= M68KModel.M68040)
  let caches = OpCaches(uint8 (Bits.extract (uint32 bin) 7u 6u))
  let an = RegisterHelper.toAddrReg (Bits.extract (uint32 bin) 2u 0u)
  let isPush = bin &&& 0x20us <> 0us
  match Bits.extract (uint32 bin) 4u 3u with
  | 0b01u ->
    let opcode = if isPush then Op.CPUSHL else Op.CINVL
    opcode, Sz.NoSize, TwoOperands(caches, OpMem(Direct an))
  | 0b10u ->
    let opcode = if isPush then Op.CPUSHP else Op.CINVP
    opcode, Sz.NoSize, TwoOperands(caches, OpMem(Direct an))
  | 0b11u ->
    let opcode = if isPush then Op.CPUSHA else Op.CINVA
    opcode, Sz.NoSize, OneOperand caches
  | _ -> raise ParsingFailureException

/// Parses a PFLUSH or a PTEST, the two translation cache instructions the 68040
/// puts in this group. Both spell what they reach into the mnemonic.
let private parseMmu (phlp: Phlp) (bin: uint16) =
  require (phlp.Model >= M68KModel.M68040)
  let reg = Bits.extract (uint32 bin) 2u 0u
  let an = OpMem(Direct(RegisterHelper.toAddrReg reg))
  let opmode = Bits.extract (uint32 bin) 4u 3u
  match Bits.extract (uint32 bin) 7u 5u with
  | 0b000u ->
    match opmode with
    | 0b00u -> Op.PFLUSHN, Sz.NoSize, OneOperand an
    | 0b01u -> Op.PFLUSH, Sz.NoSize, OneOperand an
    | 0b10u -> Op.PFLUSHAN, Sz.NoSize, NoOperand
    | _ -> Op.PFLUSHA, Sz.NoSize, NoOperand
  | 0b010u | 0b011u ->
    require (opmode = 0b01u)
    let opcode = if bin &&& 0x20us = 0us then Op.PTESTW else Op.PTESTR
    opcode, Sz.NoSize, OneOperand an
  | _ -> raise ParsingFailureException

/// Parses a MOVE16, which copies an aligned block of sixteen bytes. One form
/// names two postincremented address registers and carries a second word for
/// the destination; the other four name one such register and an absolute
/// address.
let private parseMove16 (phlp: Phlp) span (bin: uint16) =
  require (phlp.Model >= M68KModel.M68040)
  require (Bits.extract (uint32 bin) 7u 6u = 0u)
  let ay = RegisterHelper.toAddrReg (Bits.extract (uint32 bin) 2u 0u)
  if bin &&& 0x20us <> 0us then
    require (Bits.extract (uint32 bin) 4u 3u = 0u)
    let ext = uint16 (phlp.ReadInt16 span)
    require (ext &&& 0x8fffus = 0x8000us)
    let ax = RegisterHelper.toAddrReg (Bits.extract (uint32 ext) 14u 12u)
    let src = OpMem(PostInc ay)
    Op.MOVE16, Sz.NoSize, TwoOperands(src, OpMem(PostInc ax))
  else
    let abs = OpAddr(uint64 (uint32 (phlp.ReadInt32 span)))
    match Bits.extract (uint32 bin) 4u 3u with
    | 0b00u -> Op.MOVE16, Sz.NoSize, TwoOperands(OpMem(PostInc ay), abs)
    | 0b01u -> Op.MOVE16, Sz.NoSize, TwoOperands(abs, OpMem(PostInc ay))
    | 0b10u -> Op.MOVE16, Sz.NoSize, TwoOperands(OpMem(Direct ay), abs)
    | _ -> Op.MOVE16, Sz.NoSize, TwoOperands(abs, OpMem(Direct ay))

/// Parses group 1111, the coprocessor line. The floating-point unit answers to
/// the coprocessor identifier of one, and the 68040 put its cache, translation,
/// and block move instructions in the two identifiers above it.
let private parseGroupF (phlp: Phlp) span (bin: uint16) =
  match Bits.extract (uint32 bin) 11u 8u with
  | 0b0010u | 0b0011u -> parseFloat phlp span bin
  | 0b0100u -> parseCache phlp bin
  | 0b0101u -> parseMmu phlp bin
  | 0b0110u -> parseMove16 phlp span bin
  | _ -> raise ParsingFailureException

/// Dispatches on bits 15-12 of the opcode word, which is the operation code map
/// of Table 8-2. Every group the parser does not read yet, and the whole of the
/// unassigned group 1010, is bytes it can say nothing about.
let private parseByGroup (phlp: Phlp) span (bin: uint16) =
  match Bits.extract (uint32 bin) 15u 12u with
  | 0b0000u -> parseGroup0 phlp span bin
  | 0b0001u -> parseMove phlp span Sz.Byte bin
  | 0b0010u -> parseMove phlp span Sz.Long bin
  | 0b0011u -> parseMove phlp span Sz.Word bin
  | 0b0100u -> parseMisc phlp span bin
  | 0b0101u -> parseGroup5 phlp span bin
  | 0b0110u -> parseBranch phlp span bin
  | 0b0111u -> parseMoveq bin
  | 0b1000u -> parseGroup8 phlp span bin
  | 0b1001u -> parseGroup9 phlp span bin
  | 0b1011u -> parseGroupB phlp span bin
  | 0b1100u -> parseGroupC phlp span bin
  | 0b1101u -> parseGroupD phlp span bin
  | 0b1110u -> parseGroupE phlp span bin
  | 0b1111u -> parseGroupF phlp span bin
  | _ -> raise ParsingFailureException

let parse lifter (span: ByteSpan) (reader: IBinReader) model addr =
  let bin = reader.ReadUInt16(span, 0)
  let phlp = ParsingHelper(reader, addr, model)
  let opcode, size, operands = parseByGroup phlp span bin
  if not (OpcodeInfo.isAvailable model opcode) then
    raise ParsingFailureException
  else
    Instruction(addr, phlp.Length, opcode, size, operands, lifter)
