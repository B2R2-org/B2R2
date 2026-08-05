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
/// Encodes the integer and the supervisor instruction sets: the arithmetic and
/// the logic at all three widths, the moves, the bit and the bit field
/// instructions, the shifts and the rotates, the branches and the conditionals,
/// what a program says to the machine it runs on, and the cache, translation,
/// and block move instructions the 68040 added.
/// </summary>
module internal B2R2.Assembly.M68K.AsmOpcode

open B2R2
open B2R2.FrontEnd.M68K
open B2R2.Assembly.M68K.ParserHelper
open B2R2.Assembly.M68K.AsmField

/// <summary>
/// The conditions, in the order the four-bit field holding one counts them.
///
/// The first two name no condition at all: they are where a branch names an
/// unconditional one and a call, and where the other three families name their
/// always and never conditions.
/// </summary>
let private conditions =
  [ "t"
    "f"
    "hi"
    "ls"
    "cc"
    "cs"
    "ne"
    "eq"
    "vc"
    "vs"
    "pl"
    "mi"
    "ge"
    "lt"
    "gt"
    "le" ]

/// Refuses the form naming the condition code register or the whole status
/// register where the instruction is one that has no such form.
let private requireStatusForm ins hi =
  if hi = 0us || hi = 1us || hi = 5us then ()
  else fail $"{ins.Mnemonic} does not name the status register"

/// <summary>
/// One of the instructions computing from a written number.
///
/// Three of them name the condition code register or the whole status register
/// in place of an address, that being the one encoding of the effective-address
/// field which names no address at all. A comparison on a 68020 or later may
/// name any data address, there being nothing for it to write back.
/// </summary>
let private immediate hi ins =
  match ins.Operands with
  | [ (AsmImm _ as imm); AsmReg Register.CCR ] ->
    requireStatusForm ins hi
    requireSize ins Sz.Byte
    (0x003cus ||| (hi <<< 9)) :: immWords ins Sz.Byte imm
  | [ (AsmImm _ as imm); AsmReg Register.SR ] ->
    requireStatusForm ins hi
    requireSize ins Sz.Word
    (0x007cus ||| (hi <<< 9)) :: immWords ins Sz.Word imm
  | [ (AsmImm _ as imm); dst ] ->
    let readable = hi = 6us && ins.Model >= M68KModel.M68020
    let allows = if readable then isData else both isData isAlterable
    let mode, reg, exts = eaOf allows ins ins.Size dst
    let head = (hi <<< 9) ||| (sizeField ins <<< 6)
    eaWord head mode reg :: (immWords ins ins.Size imm @ exts)
  | _ ->
    wrongOperands ins

/// The word holding a written bit number, whose low byte is all of it the
/// processor reads.
let private bitNumber v =
  if v >= 0L && v <= 255L then uint16 v
  else fail $"{v} is not a bit number"

/// <summary>
/// One of the instructions testing or changing one bit, whose number is either
/// written out or held in a data register.
///
/// A bit of a data register is one of thirty-two and a bit of memory one of
/// eight, and which of those it is is what the width the mnemonic carries says,
/// so the width has to agree with the operand rather than being free.
/// </summary>
let private bitOp code ins =
  match ins.Operands with
  | [ AsmReg src; dst ] when isDataReg src ->
    let allows = if code = 0us then isData else both isData isAlterable
    let mode, reg, exts = eaOf allows ins ins.Size dst
    requireSize ins (if mode = 0us then Sz.Long else Sz.Byte)
    let head = 0x0100us ||| (dataNum src <<< 9) ||| (code <<< 6)
    eaWord head mode reg :: exts
  | [ AsmImm v; dst ] ->
    let allows =
      if code = 0us then both isData notImmediate else both isData isAlterable
    let mode, reg, exts = eaOf allows ins ins.Size dst
    requireSize ins (if mode = 0us then Sz.Long else Sz.Byte)
    eaWord (0x0800us ||| (code <<< 6)) mode reg :: (bitNumber v :: exts)
  | _ ->
    wrongOperands ins

/// A MOVEP, which moves alternating bytes between a data register and a
/// peripheral, and so names its memory operand by a distance from an address
/// register alone.
let private movep ins =
  requireWordOrLong ins
  let code = if ins.Size = Sz.Long then 1us else 0us
  match ins.Operands with
  | [ AsmReg dn; AsmMem(AsmDisp(v, an)) ] ->
    let head = 0x0188us ||| (dataNum dn <<< 9) ||| (code <<< 6)
    [ head ||| addrNum an; wordOf v ]
  | [ AsmMem(AsmDisp(v, an)); AsmReg dn ] ->
    let head = 0x0108us ||| (dataNum dn <<< 9) ||| (code <<< 6)
    [ head ||| addrNum an; wordOf v ]
  | _ ->
    wrongOperands ins

/// A CMP2 or a CHK2, which check a register against a pair of bounds. They
/// share every bit of the opcode word, one bit of the extension word telling
/// them apart.
let private compareBounds isCheck ins =
  match ins.Operands with
  | [ bounds; AsmReg rn ] ->
    let mode, reg, exts = eaOf isControl ins ins.Size bounds
    let head = 0x00c0us ||| (sizeField ins <<< 9)
    let ext = (if isCheck then 0x800us else 0us) ||| (generalNum rn <<< 12)
    eaWord head mode reg :: (ext :: exts)
  | _ ->
    wrongOperands ins

/// A CALLM, which calls a module whose descriptor a control address names.
let private callm ins =
  requireOnlySize ins Sz.NoSize
  match ins.Operands with
  | [ AsmImm v; dst ] ->
    let mode, reg, exts = eaOf isControl ins Sz.NoSize dst
    eaWord 0x06c0us mode reg :: (bitNumber v :: exts)
  | _ ->
    wrongOperands ins

/// An RTM, which shares its bits 11-6 with CALLM and is told apart by naming a
/// register where CALLM names a control address.
let private rtm ins =
  requireOnlySize ins Sz.NoSize
  match ins.Operands with
  | [ AsmReg rn ] -> [ 0x06c0us ||| generalNum rn ]
  | _ -> wrongOperands ins

/// The bits above the effective-address field of a compare and swap, whose
/// width field counts from one, the zero it leaves free being where the bit
/// instructions live.
let private casHead ins = 0x00c0us ||| ((sizeField ins + 5us) <<< 9)

/// A CAS, which compares one place against a register and writes another
/// register there where the two were the same.
let private cas ins =
  match ins.Operands with
  | [ AsmReg dc; AsmReg du; dst ] ->
    let mode, reg, exts = eaOf (both isMemory isAlterable) ins ins.Size dst
    let ext = (dataNum du <<< 6) ||| dataNum dc
    eaWord (casHead ins) mode reg :: (ext :: exts)
  | _ ->
    wrongOperands ins

/// A CAS2, which compares and swaps two places at once, and so carries two
/// extension words and names three pairs of registers.
let private cas2 ins =
  match ins.Operands with
  | [ AsmRegPair(dc1, dc2); AsmRegPair(du1, du2); AsmMemPair(rn1, rn2) ] ->
    let ext1 = (generalNum rn1 <<< 12) ||| (dataNum du1 <<< 6) ||| dataNum dc1
    let ext2 = (generalNum rn2 <<< 12) ||| (dataNum du2 <<< 6) ||| dataNum dc2
    [ casHead ins ||| 0x3cus; ext1; ext2 ]
  | _ ->
    wrongOperands ins

/// A MOVES, which moves between a register and the address space that a
/// function code register selects.
let private moves ins =
  let head = 0x0e00us ||| (sizeField ins <<< 6)
  let allows = both isMemory isAlterable
  match ins.Operands with
  | [ AsmReg rn; dst ] when isGeneralReg rn ->
    let mode, reg, exts = eaOf allows ins ins.Size dst
    let ext = 0x800us ||| (generalNum rn <<< 12)
    eaWord head mode reg :: (ext :: exts)
  | [ src; AsmReg rn ] ->
    let mode, reg, exts = eaOf allows ins ins.Size src
    eaWord head mode reg :: ((generalNum rn <<< 12) :: exts)
  | _ ->
    wrongOperands ins

/// The four bits naming which of the three groups a MOVE belongs to, which is
/// how it says how wide it is.
let private moveGroup ins =
  match ins.Size with
  | Sz.Byte -> 0x1000us
  | Sz.Word -> 0x3000us
  | Sz.Long -> 0x2000us
  | _ -> fail $"{ins.Mnemonic} is not written at this width"

/// A MOVE that reads the status register or its low byte, whose destination has
/// to be data alterable. Reading the low byte alone is a 68010 addition.
let private moveFromStatus ins hi dst =
  requireOnlySize ins Sz.Word
  if hi = 1us then requireModel ins M68KModel.M68010 "move from ccr" else ()
  let mode, reg, exts = eaOf (both isData isAlterable) ins Sz.Word dst
  eaWord (0x40c0us ||| (hi <<< 9)) mode reg :: exts

/// A MOVE that writes the status register or its low byte, whose source is any
/// data addressing mode.
let private moveToStatus ins hi src =
  requireOnlySize ins Sz.Word
  let mode, reg, exts = eaOf isData ins Sz.Word src
  eaWord (0x40c0us ||| (hi <<< 9)) mode reg :: exts

/// A MOVE reaching from one addressing mode to another, or one of the ones
/// naming a register a program does not compute with, which sit elsewhere in
/// the encoding space and only share the name.
let private move ins =
  match ins.Operands with
  | [ AsmReg Register.SR; dst ] ->
    moveFromStatus ins 0us dst
  | [ AsmReg Register.CCR; dst ] ->
    moveFromStatus ins 1us dst
  | [ src; AsmReg Register.CCR ] ->
    moveToStatus ins 2us src
  | [ src; AsmReg Register.SR ] ->
    moveToStatus ins 3us src
  | [ AsmReg an; AsmReg Register.USP ] ->
    requireOnlySize ins Sz.Long
    [ 0x4e60us ||| addrNum an ]
  | [ AsmReg Register.USP; AsmReg an ] ->
    requireOnlySize ins Sz.Long
    [ 0x4e68us ||| addrNum an ]
  | [ src; dst ] ->
    let group = moveGroup ins
    let sm, sr, se = eaOf isAny ins ins.Size src
    if ins.Size = Sz.Byte && sm = 1us then
      fail "there is no byte of an address register"
    else
      ()
    let dm, dr, de = eaOf (both isData isAlterable) ins ins.Size dst
    (group ||| (dr <<< 9) ||| (dm <<< 6) ||| (sm <<< 3) ||| sr) :: (se @ de)
  | _ ->
    wrongOperands ins

/// A MOVEA, which is a MOVE whose destination is an address register taken
/// whole, there being no byte of one to move.
let private movea ins =
  requireWordOrLong ins
  match ins.Operands with
  | [ src; AsmReg an ] ->
    let sm, sr, se = eaOf isAny ins ins.Size src
    let head = moveGroup ins ||| (addrNum an <<< 9) ||| 0x40us
    (head ||| (sm <<< 3) ||| sr) :: se
  | _ ->
    wrongOperands ins

/// A MOVEQ, whose data is a byte the processor widens to the whole of the
/// register it lands in.
let private moveq ins =
  requireOnlySize ins Sz.Long
  match ins.Operands with
  | [ AsmImm v; AsmReg dn ] -> [ 0x7000us ||| (dataNum dn <<< 9) ||| byteOf v ]
  | _ -> wrongOperands ins

/// A CHK, whose bounds come from a data addressing mode. The long form is a
/// 68020 addition.
let private chk ins =
  let opmode =
    match ins.Size with
    | Sz.Word -> 6us
    | Sz.Long -> 4us
    | _ -> fail $"{ins.Mnemonic} is written at word or long width"
  if opmode = 4us then requireModel ins M68KModel.M68020 "chk.l" else ()
  match ins.Operands with
  | [ src; AsmReg dn ] ->
    let mode, reg, exts = eaOf isData ins ins.Size src
    let head = 0x4000us ||| (dataNum dn <<< 9) ||| (opmode <<< 6)
    eaWord head mode reg :: exts
  | _ ->
    wrongOperands ins

/// A LEA, whose source has to be a control address, there being no address to
/// load otherwise.
let private lea ins =
  requireOnlySize ins Sz.Long
  match ins.Operands with
  | [ src; AsmReg an ] ->
    let mode, reg, exts = eaOf isControl ins Sz.Long src
    eaWord (0x41c0us ||| (addrNum an <<< 9)) mode reg :: exts
  | _ ->
    wrongOperands ins

/// One of the instructions that write their result back where they found it, so
/// that their operand has to be data alterable.
let private unary hi ins =
  match ins.Operands with
  | [ dst ] ->
    let mode, reg, exts = eaOf (both isData isAlterable) ins ins.Size dst
    let head = 0x4000us ||| (hi <<< 9) ||| (sizeField ins <<< 6)
    eaWord head mode reg :: exts
  | _ ->
    wrongOperands ins

/// An NBCD, which negates the two decimal digits one byte holds.
let private nbcd ins =
  requireOnlySize ins Sz.Byte
  match ins.Operands with
  | [ dst ] ->
    let mode, reg, exts = eaOf (both isData isAlterable) ins Sz.Byte dst
    eaWord 0x4800us mode reg :: exts
  | _ ->
    wrongOperands ins

/// A LINK, which sets up a frame of the size it names. The long form is a 68020
/// addition and sits where an NBCD naming an address register would.
let private link ins =
  match ins.Operands with
  | [ AsmReg an; AsmImm v ] when ins.Size = Sz.Long ->
    requireModel ins M68KModel.M68020 "link.l"
    (0x4808us ||| addrNum an) :: longWords (longOf v)
  | [ AsmReg an; AsmImm v ] ->
    requireOnlySize ins Sz.Word
    [ 0x4e50us ||| addrNum an; wordOf v ]
  | _ ->
    wrongOperands ins

/// A SWAP, which exchanges the two halves of a data register.
let private swap ins =
  requireOnlySize ins Sz.Word
  match ins.Operands with
  | [ AsmReg dn ] -> [ 0x4840us ||| dataNum dn ]
  | _ -> wrongOperands ins

/// A BKPT, whose vector is the low three bits of the opcode word.
let private bkpt ins =
  requireOnlySize ins Sz.NoSize
  match ins.Operands with
  | [ AsmImm v ] when v >= 0L && v <= 7L -> [ 0x4848us ||| uint16 v ]
  | _ -> wrongOperands ins

/// A PEA, which pushes the address a control mode names.
let private pea ins =
  requireOnlySize ins Sz.Long
  match ins.Operands with
  | [ src ] ->
    let mode, reg, exts = eaOf isControl ins Sz.Long src
    eaWord 0x4840us mode reg :: exts
  | _ ->
    wrongOperands ins

/// An EXT, which widens the low half of a data register to the whole of it.
let private ext ins =
  requireWordOrLong ins
  let opmode = if ins.Size = Sz.Word then 2us else 3us
  match ins.Operands with
  | [ AsmReg dn ] -> [ 0x4800us ||| (opmode <<< 6) ||| dataNum dn ]
  | _ -> wrongOperands ins

/// An EXTB, which widens the low byte of a data register to the whole of it,
/// and which the 68020 added.
let private extb ins =
  requireOnlySize ins Sz.Long
  requireModel ins M68KModel.M68020 "extb"
  match ins.Operands with
  | [ AsmReg dn ] -> [ 0x49c0us ||| dataNum dn ]
  | _ -> wrongOperands ins

/// <summary>
/// A MOVEM, which moves a list of registers to or from memory.
///
/// Which way it goes is which side of it the list is written on, and a
/// predecrement destination runs the mask the other way round, so that its
/// lowest bit stands for the last register of the bank.
/// </summary>
let private movem ins =
  requireWordOrLong ins
  let opmode = if ins.Size = Sz.Word then 2us else 3us
  match ins.Operands with
  | [ list; dst ] when isRegListLike list ->
    let mode, reg, exts = eaOf isWritableRun ins ins.Size dst
    let mask = regMask Register.D0 16 (mode = 4us) (regsOf ins list)
    eaWord (0x4800us ||| (opmode <<< 6)) mode reg :: (mask :: exts)
  | [ src; list ] ->
    let mode, reg, exts = eaOf isReadableRun ins ins.Size src
    let mask = regMask Register.D0 16 false (regsOf ins list)
    eaWord (0x4c00us ||| (opmode <<< 6)) mode reg :: (mask :: exts)
  | _ ->
    wrongOperands ins

/// A TAS, which tests one byte and sets its topmost bit without letting
/// anything else at it in between.
let private tas ins =
  requireOnlySize ins Sz.Byte
  match ins.Operands with
  | [ dst ] ->
    let mode, reg, exts = eaOf (both isData isAlterable) ins Sz.Byte dst
    eaWord 0x4ac0us mode reg :: exts
  | _ ->
    wrongOperands ins

/// A TST, whose operand the 68020 widened to any addressing mode at all, there
/// being nothing to write back. An address register is still no operand at byte
/// width, there being no byte of one to test.
let private tst ins =
  match ins.Operands with
  | [ dst ] ->
    let allows =
      if ins.Model >= M68KModel.M68020 then isAny else both isData isAlterable
    let mode, reg, exts = eaOf allows ins ins.Size dst
    if ins.Size = Sz.Byte && mode = 1us then
      fail "there is no byte of an address register"
    else
      ()
    eaWord (0x4a00us ||| (sizeField ins <<< 6)) mode reg :: exts
  | _ ->
    wrongOperands ins

/// One of the word-wide divides or multiplies, whose source is any data
/// addressing mode and whose destination is a data register.
let private divMulWord head ins =
  match ins.Operands with
  | [ src; AsmReg dn ] ->
    let mode, reg, exts = eaOf isData ins Sz.Word src
    eaWord (head ||| (dataNum dn <<< 9)) mode reg :: exts
  | _ ->
    wrongOperands ins

/// The long form of a multiply, a 68020 addition whose extension word says
/// whether it is signed and whether the product fills one register or two.
let private mulLong signed ins =
  requireModel ins M68KModel.M68020 $"{ins.Mnemonic}.l"
  let signBit = if signed then 0x800us else 0us
  match ins.Operands with
  | [ src; dst ] ->
    let mode, reg, exts = eaOf isData ins Sz.Long src
    let ext =
      match dst with
      | AsmReg dl ->
        (dataNum dl <<< 12) ||| signBit
      | AsmRegPair(dh, dl) ->
        (dataNum dl <<< 12) ||| signBit ||| 0x400us ||| dataNum dh
      | _ ->
        wrongOperands ins
    eaWord 0x4c00us mode reg :: (ext :: exts)
  | _ ->
    wrongOperands ins

/// The long form of a divide, whose extension word says whether it is signed
/// and whether the dividend fills one register or two.
let private divLong code ins =
  requireModel ins M68KModel.M68020 $"{ins.Mnemonic}.l"
  match ins.Operands with
  | [ src; AsmRegPair(dr, dq) ] ->
    let mode, reg, exts = eaOf isData ins Sz.Long src
    let ext = (dataNum dq <<< 12) ||| code ||| dataNum dr
    eaWord 0x4c40us mode reg :: (ext :: exts)
  | _ ->
    wrongOperands ins

/// A multiply, which is one instruction at word width and another at long
/// width.
let private multiply signed ins =
  if ins.Size = Sz.Long then
    mulLong signed ins
  else
    requireOnlySize ins Sz.Word
    divMulWord (if signed then 0xc1c0us else 0xc0c0us) ins

/// A divide, of which the long form keeps a remainder the word form has no room
/// for.
let private divide signed ins =
  if ins.Size = Sz.Long then
    divLong (if signed then 0xc00us else 0x400us) ins
  else
    requireOnlySize ins Sz.Word
    divMulWord (if signed then 0x81c0us else 0x80c0us) ins

/// A divide keeping a dividend of one register rather than two, which is what
/// makes the mnemonic the DIVSL or the DIVUL form.
let private divideLong signed ins =
  requireOnlySize ins Sz.Long
  divLong (if signed then 0x800us else 0x000us) ins

/// A JMP or a JSR, whose target has to be a control address, there being no
/// address to jump to otherwise.
let private jump head ins =
  requireOnlySize ins Sz.NoSize
  match ins.Operands with
  | [ dst ] ->
    let mode, reg, exts = eaOf isControl ins Sz.NoSize dst
    eaWord head mode reg :: exts
  | _ ->
    wrongOperands ins

/// A code the given member of the family and every later one reads.
let private laterCode ins model code =
  requireModel ins model "this control register"
  code

/// The twelve bits naming a control register, which are codes of their own.
/// Which of them are assigned depends on the model, and any other one is an
/// illegal instruction.
let private controlCode ins reg =
  match reg with
  | Register.SFC -> 0x000us
  | Register.DFC -> 0x001us
  | Register.USP -> 0x800us
  | Register.VBR -> 0x801us
  | Register.CACR -> laterCode ins M68KModel.M68020 0x002us
  | Register.CAAR -> laterCode ins M68KModel.M68020 0x802us
  | Register.MSP -> laterCode ins M68KModel.M68020 0x803us
  | Register.ISP -> laterCode ins M68KModel.M68020 0x804us
  | Register.TC -> laterCode ins M68KModel.M68040 0x003us
  | Register.ITT0 -> laterCode ins M68KModel.M68040 0x004us
  | Register.ITT1 -> laterCode ins M68KModel.M68040 0x005us
  | Register.DTT0 -> laterCode ins M68KModel.M68040 0x006us
  | Register.DTT1 -> laterCode ins M68KModel.M68040 0x007us
  | Register.MMUSR -> laterCode ins M68KModel.M68040 0x805us
  | Register.URP -> laterCode ins M68KModel.M68040 0x806us
  | Register.SRP -> laterCode ins M68KModel.M68040 0x807us
  | _ -> fail $"{Register.toString reg} is not a control register"

/// A MOVEC, whose extension word names a control register by a code of its own
/// and a general register the way the rest of the family does.
let private movec ins =
  requireOnlySize ins Sz.Long
  match ins.Operands with
  | [ AsmReg rn; AsmReg rc ] when isGeneralReg rn ->
    [ 0x4e7bus; (generalNum rn <<< 12) ||| controlCode ins rc ]
  | [ AsmReg rc; AsmReg rn ] ->
    [ 0x4e7aus; (generalNum rn <<< 12) ||| controlCode ins rc ]
  | _ ->
    wrongOperands ins

/// An instruction naming nothing at all, and therefore one word spelt out to
/// the last bit.
let private noOperand word ins =
  requireOnlySize ins Sz.NoSize
  match ins.Operands with
  | [] -> [ word ]
  | _ -> wrongOperands ins

/// An instruction naming an address register and nothing else.
let private oneAddrReg head ins =
  requireOnlySize ins Sz.NoSize
  match ins.Operands with
  | [ AsmReg an ] -> [ head ||| addrNum an ]
  | _ -> wrongOperands ins

/// A TRAP, whose vector is the low four bits of the opcode word.
let private trap ins =
  requireOnlySize ins Sz.NoSize
  match ins.Operands with
  | [ AsmImm v ] when v >= 0L && v <= 15L -> [ 0x4e40us ||| uint16 v ]
  | _ -> wrongOperands ins

/// A STOP or an RTD, each of which names one word of immediate data.
let private oneImmWord word ins =
  requireOnlySize ins Sz.NoSize
  match ins.Operands with
  | [ AsmImm v ] -> [ word; wordOf v ]
  | _ -> wrongOperands ins

/// An ADDQ or a SUBQ, whose data is one to eight, a field of zero meaning eight
/// because there is no use for adding an immediate zero.
let private quick isSub ins =
  match ins.Operands with
  | [ AsmImm v; dst ] when v >= 1L && v <= 8L ->
    let mode, reg, exts = eaOf isAlterable ins ins.Size dst
    if ins.Size = Sz.Byte && mode = 1us then
      fail "there is no byte of an address register"
    else
      ()
    let data = if v = 8L then 0us else uint16 v
    let subBit = if isSub then 0x100us else 0us
    let head =
      0x5000us ||| subBit ||| (data <<< 9) ||| (sizeField ins <<< 6)
    eaWord head mode reg :: exts
  | _ ->
    wrongOperands ins

/// An Scc, which writes one byte saying whether its condition holds.
let private setcc cc ins =
  requireOnlySize ins Sz.Byte
  match ins.Operands with
  | [ dst ] ->
    let mode, reg, exts = eaOf (both isData isAlterable) ins Sz.Byte dst
    eaWord (0x50c0us ||| (cc <<< 8)) mode reg :: exts
  | _ ->
    wrongOperands ins

/// A DBcc, which counts a register down and branches while the count lasts and
/// its condition does not hold.
let private dbcc cc ins =
  requireOnlySize ins Sz.Word
  match ins.Operands with
  | [ AsmReg dn; target ] ->
    let head = 0x50c8us ||| (cc <<< 8) ||| dataNum dn
    head :: relWord (relOf ins target)
  | _ ->
    wrongOperands ins

/// A TRAPcc, whose operand the low three bits of the opcode word name: one word
/// of immediate data, two, or none at all.
let private trapcc cc ins =
  let head = 0x50f8us ||| (cc <<< 8)
  match ins.Operands with
  | [] ->
    requireOnlySize ins Sz.NoSize
    [ head ||| 4us ]
  | [ AsmImm v ] when ins.Size = Sz.Long ->
    (head ||| 3us) :: longWords (longOf v)
  | [ AsmImm v ] ->
    requireOnlySize ins Sz.Word
    [ head ||| 2us; wordOf v ]
  | _ ->
    wrongOperands ins

/// <summary>
/// The byte of the opcode word that holds a short branch's displacement.
///
/// A byte of zero says that the displacement is the word that follows, and one
/// of all ones that it is the two words that follow, which the 68020 added; the
/// earlier models read that byte as the displacement it looks like, so it is
/// only for them that a branch of that distance is a branch at all.
/// </summary>
let private byteDisp ins v =
  if v < -128L || v > 127L then
    fail $"{v} is too far to reach in one byte"
  elif v = 0L then
    fail "a branch of no distance is written at word width"
  elif v = -1L && ins.Model >= M68KModel.M68020 then
    fail "a branch of this distance is written at word width"
  else
    uint16 (uint8 v)

/// A branch, whose displacement is one byte of the opcode word, one extension
/// word, or two, as the width the mnemonic carries says.
let private branch cc ins =
  match ins.Operands with
  | [ target ] ->
    let head = 0x6000us ||| (cc <<< 8)
    let disp = relOf ins target
    match ins.Size with
    | Sz.Byte ->
      [ head ||| byteDisp ins disp ]
    | Sz.Long ->
      requireModel ins M68KModel.M68020 "a branch of this width"
      (head ||| 0xffus) :: relLongWords disp
    | _ ->
      requireOnlySize ins Sz.Word
      head :: relWord disp
  | _ ->
    wrongOperands ins

/// The bits naming the pair of operands that the decimal and the extended
/// arithmetic work on, which is either two data registers or two predecremented
/// addresses.
let private pairFields ins =
  match ins.Operands with
  | AsmReg src :: AsmReg dst :: _ when isDataReg src ->
    (dataNum dst <<< 9) ||| dataNum src
  | AsmMem(AsmPreDec src) :: AsmMem(AsmPreDec dst) :: _ ->
    (addrNum dst <<< 9) ||| 8us ||| addrNum src
  | _ ->
    wrongOperands ins

/// A decimal addition or subtraction, which works on one byte holding two
/// digits.
let private decimal head ins =
  requireOnlySize ins Sz.Byte
  match ins.Operands with
  | [ _; _ ] -> [ head ||| pairFields ins ]
  | _ -> wrongOperands ins

/// An addition or a subtraction that reads the carry of the one before it, so
/// that a run of them works on a number of any width.
let private extended head ins =
  match ins.Operands with
  | [ _; _ ] -> [ head ||| (sizeField ins <<< 6) ||| pairFields ins ]
  | _ -> wrongOperands ins

/// A PACK or an UNPK, which carry an adjustment word of their own between the
/// two halves of a decimal digit and the byte holding them.
let private packing head ins =
  requireOnlySize ins Sz.NoSize
  match ins.Operands with
  | [ src; dst; AsmImm adj ] ->
    let fields = pairFields { ins with Operands = [ src; dst ] }
    [ head ||| fields; wordOf adj ]
  | _ ->
    wrongOperands ins

/// One of the logical instructions, whose source is any data addressing mode
/// where the result goes to the register, and whose destination is alterable
/// memory where it goes the other way.
let private logical head ins =
  let size = sizeField ins
  match ins.Operands with
  | [ src; AsmReg dn ] when isDataReg dn ->
    let mode, reg, exts = eaOf isData ins ins.Size src
    let head = head ||| (dataNum dn <<< 9) ||| (size <<< 6)
    eaWord head mode reg :: exts
  | [ AsmReg dn; dst ] ->
    let mode, reg, exts = eaOf (both isMemory isAlterable) ins ins.Size dst
    let head = head ||| (dataNum dn <<< 9) ||| ((size ||| 4us) <<< 6)
    eaWord head mode reg :: exts
  | _ ->
    wrongOperands ins

/// An ADD or a SUB. Its source may be an address register at word and long
/// width, there being no byte of one, and where the result goes back to memory
/// the destination has to be alterable.
let private arith head ins =
  let size = sizeField ins
  match ins.Operands with
  | [ src; AsmReg dn ] when isDataReg dn ->
    let allows = if ins.Size = Sz.Byte then isData else isAny
    let mode, reg, exts = eaOf allows ins ins.Size src
    let head = head ||| (dataNum dn <<< 9) ||| (size <<< 6)
    eaWord head mode reg :: exts
  | [ AsmReg dn; dst ] ->
    let mode, reg, exts = eaOf (both isMemory isAlterable) ins ins.Size dst
    let head = head ||| (dataNum dn <<< 9) ||| ((size ||| 4us) <<< 6)
    eaWord head mode reg :: exts
  | _ ->
    wrongOperands ins

/// A CMP, which has only the one direction, there being nothing to write back.
let private compare ins =
  match ins.Operands with
  | [ src; AsmReg dn ] ->
    let allows = if ins.Size = Sz.Byte then isData else isAny
    let mode, reg, exts = eaOf allows ins ins.Size src
    let head = 0xb000us ||| (dataNum dn <<< 9) ||| (sizeField ins <<< 6)
    eaWord head mode reg :: exts
  | _ ->
    wrongOperands ins

/// An EOR, whose destination is data alterable rather than the alterable memory
/// the OR and the AND require of theirs, a data register being something one
/// can exclusive-OR into.
let private exclusiveOr ins =
  match ins.Operands with
  | [ AsmReg dn; dst ] ->
    let mode, reg, exts = eaOf (both isData isAlterable) ins ins.Size dst
    let size = sizeField ins ||| 4us
    let head = 0xb000us ||| (dataNum dn <<< 9) ||| (size <<< 6)
    eaWord head mode reg :: exts
  | _ ->
    wrongOperands ins

/// An ADDA, a SUBA, or a CMPA, whose source is any addressing mode at all and
/// whose destination is an address register taken whole.
let private arithAddr head ins =
  requireWordOrLong ins
  let opmode = if ins.Size = Sz.Word then 3us else 7us
  match ins.Operands with
  | [ src; AsmReg an ] ->
    let mode, reg, exts = eaOf isAny ins ins.Size src
    let head = head ||| (addrNum an <<< 9) ||| (opmode <<< 6)
    eaWord head mode reg :: exts
  | _ ->
    wrongOperands ins

/// A CMPM, which walks two blocks of memory a postincrement at a time.
let private cmpm ins =
  match ins.Operands with
  | [ AsmMem(AsmPostInc src); AsmMem(AsmPostInc dst) ] ->
    let head = 0xb108us ||| (addrNum dst <<< 9) ||| (sizeField ins <<< 6)
    [ head ||| addrNum src ]
  | _ ->
    wrongOperands ins

/// An EXG, whose two registers the width field and the addressing mode between
/// them say the kind of. There is no exchange of an address register with a
/// data register the other way round, so one of the four combinations names
/// nothing.
let private exg ins =
  requireOnlySize ins Sz.Long
  match ins.Operands with
  | [ AsmReg x; AsmReg y ] when isDataReg x && isDataReg y ->
    [ 0xc140us ||| (dataNum x <<< 9) ||| dataNum y ]
  | [ AsmReg x; AsmReg y ] when isAddrReg x && isAddrReg y ->
    [ 0xc148us ||| (addrNum x <<< 9) ||| addrNum y ]
  | [ AsmReg x; AsmReg y ] ->
    [ 0xc188us ||| (dataNum x <<< 9) ||| addrNum y ]
  | _ ->
    wrongOperands ins

/// A shift or a rotate, which moves a data register by a written number of
/// places or by what another register holds, or one word of memory by one
/// place.
let private shift kind isLeft ins =
  let dir = if isLeft then 0x100us else 0us
  match ins.Operands with
  | [ AsmImm v; AsmReg dn ] when v >= 1L && v <= 8L ->
    let count = if v = 8L then 0us else uint16 v
    let head = 0xe000us ||| (count <<< 9) ||| dir ||| (sizeField ins <<< 6)
    [ head ||| (kind <<< 3) ||| dataNum dn ]
  | [ AsmReg cnt; AsmReg dn ] when isDataReg cnt ->
    let head = 0xe020us ||| (dataNum cnt <<< 9) ||| dir
    [ head ||| (sizeField ins <<< 6) ||| (kind <<< 3) ||| dataNum dn ]
  | [ dst ] ->
    requireOnlySize ins Sz.Word
    let mode, reg, exts = eaOf (both isMemory isAlterable) ins Sz.Word dst
    eaWord (0xe0c0us ||| (kind <<< 9) ||| dir) mode reg :: exts
  | _ ->
    wrongOperands ins

/// The bits of a bit field extension word saying where the field starts and how
/// many bits it holds, each of which is either written out or held in a data
/// register. A width of zero means the whole thirty-two, there being no field
/// of no bits.
let private fieldBits offset width =
  let offsetBits =
    match offset with
    | AsmImm v when v >= 0L && v <= 31L -> uint16 v <<< 6
    | AsmReg dn -> 0x800us ||| (dataNum dn <<< 6)
    | _ -> fail "a field starts at one of thirty-two places"
  let widthBits =
    match width with
    | AsmImm 32L -> 0us
    | AsmImm v when v >= 1L && v <= 31L -> uint16 v
    | AsmReg dn -> 0x20us ||| dataNum dn
    | _ -> fail "a field holds one to thirty-two bits"
  offsetBits ||| widthBits

/// The bits above the effective-address field of a bit field instruction, which
/// the 68020 added.
let private fieldHead ins code =
  requireOnlySize ins Sz.NoSize
  requireModel ins M68KModel.M68020 ins.Mnemonic
  0xe8c0us ||| (code <<< 8)

/// One of the bit field instructions naming the field alone, which may be a
/// data register or a control address and has to be alterable where the
/// instruction writes it.
let private fieldOnly code ins =
  let head = fieldHead ins code
  let writes = code <> 0us
  match ins.Operands with
  | [ AsmBitField(ea, offset, width) ] ->
    let allows =
      if writes then both isRegOrControl isAlterable else isRegOrControl
    let mode, reg, exts = eaOf allows ins Sz.NoSize ea
    eaWord head mode reg :: (fieldBits offset width :: exts)
  | _ ->
    wrongOperands ins

/// One of the bit field instructions moving the field to a register, which the
/// extension word names.
let private fieldExtract code ins =
  let head = fieldHead ins code
  match ins.Operands with
  | [ AsmBitField(ea, offset, width); AsmReg dn ] ->
    let mode, reg, exts = eaOf isRegOrControl ins Sz.NoSize ea
    let ext = (dataNum dn <<< 12) ||| fieldBits offset width
    eaWord head mode reg :: (ext :: exts)
  | _ ->
    wrongOperands ins

/// A BFINS, which moves a register into the field, and so needs the field to be
/// alterable.
let private fieldInsert ins =
  let head = fieldHead ins 7us
  match ins.Operands with
  | [ AsmReg dn; AsmBitField(ea, offset, width) ] ->
    let allows = both isRegOrControl isAlterable
    let mode, reg, exts = eaOf allows ins Sz.NoSize ea
    let ext = (dataNum dn <<< 12) ||| fieldBits offset width
    eaWord head mode reg :: (ext :: exts)
  | _ ->
    wrongOperands ins

/// A CINV or a CPUSH, whose scope the mnemonic spells out and whose caches it
/// names as an operand.
let private cache isPush scope ins =
  requireOnlySize ins Sz.NoSize
  requireModel ins M68KModel.M68040 ins.Mnemonic
  let pushBit = if isPush then 0x20us else 0us
  let head = 0xf400us ||| pushBit ||| (scope <<< 3)
  match ins.Operands with
  | [ AsmCaches c ] when scope = 3us ->
    [ head ||| (uint16 c <<< 6) ]
  | [ AsmCaches c; AsmMem(AsmDirect an) ] when scope <> 3us ->
    [ head ||| (uint16 c <<< 6) ||| addrNum an ]
  | _ ->
    wrongOperands ins

/// A PFLUSH, which throws away what the translation cache holds, either of one
/// page or of the whole of it.
let private pflush opmode ins =
  requireOnlySize ins Sz.NoSize
  requireModel ins M68KModel.M68040 ins.Mnemonic
  let head = 0xf500us ||| (opmode <<< 3)
  match ins.Operands with
  | [] when opmode > 1us -> [ head ]
  | [ AsmMem(AsmDirect an) ] when opmode < 2us -> [ head ||| addrNum an ]
  | _ -> wrongOperands ins

/// A PTEST, which asks the translation cache what it holds for one page.
let private ptest isRead ins =
  requireOnlySize ins Sz.NoSize
  requireModel ins M68KModel.M68040 ins.Mnemonic
  let head = if isRead then 0xf568us else 0xf548us
  match ins.Operands with
  | [ AsmMem(AsmDirect an) ] -> [ head ||| addrNum an ]
  | _ -> wrongOperands ins

/// A MOVE16, which copies an aligned block of sixteen bytes. One form names two
/// postincremented address registers and carries a second word for the
/// destination; the other four name one such register and an absolute address.
let private move16 ins =
  requireOnlySize ins Sz.NoSize
  requireModel ins M68KModel.M68040 "move16"
  match ins.Operands with
  | [ AsmMem(AsmPostInc ay); AsmMem(AsmPostInc ax) ] ->
    [ 0xf620us ||| addrNum ay; 0x8000us ||| (addrNum ax <<< 12) ]
  | [ AsmMem(AsmPostInc ay); dst ] ->
    (0xf600us ||| addrNum ay) :: absLongWords ins dst
  | [ src; AsmMem(AsmPostInc ay) ] ->
    (0xf608us ||| addrNum ay) :: absLongWords ins src
  | [ AsmMem(AsmDirect ay); dst ] ->
    (0xf610us ||| addrNum ay) :: absLongWords ins dst
  | [ src; AsmMem(AsmDirect ay) ] ->
    (0xf618us ||| addrNum ay) :: absLongWords ins src
  | _ ->
    wrongOperands ins

/// The instructions computing from a written number, testing or changing one
/// bit, and the handful the 68020 fitted in beside them.
let private group0Encoders () =
  [ "ori", always (immediate 0us)
    "andi", always (immediate 1us)
    "subi", always (immediate 2us)
    "addi", always (immediate 3us)
    "eori", always (immediate 5us)
    "cmpi", always (immediate 6us)
    "btst", always (bitOp 0us)
    "bchg", always (bitOp 1us)
    "bclr", always (bitOp 2us)
    "bset", always (bitOp 3us)
    "movep", always movep
    "cmp2", since M68KModel.M68020 (compareBounds false)
    "chk2", since M68KModel.M68020 (compareBounds true)
    "callm", onlyOn M68KModel.M68020 callm
    "rtm", onlyOn M68KModel.M68020 rtm
    "cas", since M68KModel.M68020 cas
    "cas2", since M68KModel.M68020 cas2
    "moves", since M68KModel.M68010 moves ]

/// The moves, of which the plain one reaches from any addressing mode to any
/// other and the rest each have a place of their own in the encoding space.
let private moveEncoders () =
  [ "move", always move
    "movea", always movea
    "moveq", always moveq
    "movem", always movem
    "movec", since M68KModel.M68010 movec
    "move16", since M68KModel.M68040 move16 ]

/// The instructions of the group whose members share almost nothing but the
/// four bits naming the group.
let private miscEncoders () =
  [ "chk", always chk
    "lea", always lea
    "negx", always (unary 0us)
    "clr", always (unary 1us)
    "neg", always (unary 2us)
    "not", always (unary 3us)
    "nbcd", always nbcd
    "link", always link
    "swap", always swap
    "bkpt", since M68KModel.M68010 bkpt
    "pea", always pea
    "ext", always ext
    "extb", since M68KModel.M68020 extb
    "tas", always tas
    "illegal", always (noOperand 0x4afcus)
    "tst", always tst
    "mulu", always (multiply false)
    "muls", always (multiply true)
    "divu", always (divide false)
    "divs", always (divide true)
    "divul", since M68KModel.M68020 (divideLong false)
    "divsl", since M68KModel.M68020 (divideLong true)
    "jsr", always (jump 0x4e80us)
    "jmp", always (jump 0x4ec0us)
    "trap", always trap
    "unlk", always (oneAddrReg 0x4e58us)
    "reset", always (noOperand 0x4e70us)
    "nop", always (noOperand 0x4e71us)
    "stop", always (oneImmWord 0x4e72us)
    "rte", always (noOperand 0x4e73us)
    "rtd", since M68KModel.M68010 (oneImmWord 0x4e74us)
    "rts", always (noOperand 0x4e75us)
    "trapv", always (noOperand 0x4e76us)
    "rtr", always (noOperand 0x4e77us) ]

/// The instructions whose condition is part of their name, of which the
/// branches name two things that are no condition at all.
let private conditionalEncoders () =
  [ for index, name in List.indexed conditions do
      let cc = uint16 index
      yield $"s{name}", always (setcc cc)
      yield $"db{name}", always (dbcc cc)
      yield $"trap{name}", since M68KModel.M68020 (trapcc cc)
      match cc with
      | 0us -> yield "bra", always (branch 0us)
      | 1us -> yield "bsr", always (branch 1us)
      | _ -> yield $"b{name}", always (branch cc) ]

/// The arithmetic and the logic, together with the quick forms of the addition
/// and the subtraction and the exchange of two registers.
let private arithEncoders () =
  [ "addq", always (quick false)
    "subq", always (quick true)
    "or", always (logical 0x8000us)
    "and", always (logical 0xc000us)
    "eor", always exclusiveOr
    "add", always (arith 0xd000us)
    "sub", always (arith 0x9000us)
    "cmp", always compare
    "adda", always (arithAddr 0xd000us)
    "suba", always (arithAddr 0x9000us)
    "cmpa", always (arithAddr 0xb000us)
    "addx", always (extended 0xd100us)
    "subx", always (extended 0x9100us)
    "abcd", always (decimal 0xc100us)
    "sbcd", always (decimal 0x8100us)
    "pack", since M68KModel.M68020 (packing 0x8140us)
    "unpk", since M68KModel.M68020 (packing 0x8180us)
    "cmpm", always cmpm
    "exg", always exg ]

/// The shifts and the rotates, and the bit field instructions that share the
/// encodings a width field of three sets aside.
let private shiftEncoders () =
  [ "asr", always (shift 0us false)
    "asl", always (shift 0us true)
    "lsr", always (shift 1us false)
    "lsl", always (shift 1us true)
    "roxr", always (shift 2us false)
    "roxl", always (shift 2us true)
    "ror", always (shift 3us false)
    "rol", always (shift 3us true)
    "bftst", since M68KModel.M68020 (fieldOnly 0us)
    "bfchg", since M68KModel.M68020 (fieldOnly 2us)
    "bfclr", since M68KModel.M68020 (fieldOnly 4us)
    "bfset", since M68KModel.M68020 (fieldOnly 6us)
    "bfextu", since M68KModel.M68020 (fieldExtract 1us)
    "bfexts", since M68KModel.M68020 (fieldExtract 3us)
    "bfffo", since M68KModel.M68020 (fieldExtract 5us)
    "bfins", since M68KModel.M68020 fieldInsert ]

/// The cache and the translation instructions the 68040 put in the group the
/// coprocessors answer in.
let private cacheEncoders () =
  [ "cinvl", since M68KModel.M68040 (cache false 1us)
    "cinvp", since M68KModel.M68040 (cache false 2us)
    "cinva", since M68KModel.M68040 (cache false 3us)
    "cpushl", since M68KModel.M68040 (cache true 1us)
    "cpushp", since M68KModel.M68040 (cache true 2us)
    "cpusha", since M68KModel.M68040 (cache true 3us)
    "pflushn", since M68KModel.M68040 (pflush 0us)
    "pflush", since M68KModel.M68040 (pflush 1us)
    "pflushan", since M68KModel.M68040 (pflush 2us)
    "pflusha", since M68KModel.M68040 (pflush 3us)
    "ptestw", since M68KModel.M68040 (ptest false)
    "ptestr", since M68KModel.M68040 (ptest true) ]

/// Every instruction that is not the floating-point unit's.
let integerEncoders () =
  [ group0Encoders ()
    moveEncoders ()
    miscEncoders ()
    conditionalEncoders ()
    arithEncoders ()
    shiftEncoders ()
    cacheEncoders () ]
  |> List.concat

// vim: set tw=80 sts=2 sw=2:
