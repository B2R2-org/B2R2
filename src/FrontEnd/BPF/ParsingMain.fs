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
/// Reads one eBPF word and says which instruction it is and what it works on.
///
/// Every word is eight bytes wide and begins with the byte naming the
/// instruction: three bits saying what kind it is, and above them the bits
/// naming it within its kind. What follows is a byte holding the two registers
/// it names, a halfword holding how far from a register to reach or how far
/// away to jump, and a word holding a number.
///
/// The machine leaves nothing free: a field an instruction does not use is
/// required to hold zero, and a word holding something else there is read as no
/// instruction at all, as is one naming a register the machine does not have.
/// The one instruction reaching past its own eight bytes is the one carrying a
/// whole quadword, which holds the upper half of it in the word after.
/// </summary>
module internal B2R2.FrontEnd.BPF.ParsingMain

open B2R2
open B2R2.FrontEnd.BinLifter

/// Represents the fields one eBPF word holds, which every instruction is read
/// out of.
type private Word =
  { Code: uint32
    Dst: uint32
    Src: uint32
    Off: int16
    Imm: int32 }

/// The three bits every word begins with, which say what kind of instruction it
/// is.
let private insClass code = code &&& 0x07u

/// The four bits naming which instruction of its kind one computing or jumping
/// is.
let private operation code = code &&& 0xF0u

/// Whether what an instruction computes from is a register rather than a
/// number, which is what the bit just above the class says.
let private readsRegister code = code &&& 0x08u <> 0u

/// The three bits saying how an instruction reaching memory says where to
/// reach.
let private accessMode code = code &&& 0xE0u

/// The two bits saying how wide the thing an instruction reaching memory reads
/// or writes is.
let private accessSize code = code &&& 0x18u

/// Reports a word this decoder reads as no instruction at all.
let private undecodable () = raise ParsingFailureException

/// The register a four-bit field names. The machine keeps eleven of them, so a
/// field naming anything above them names no register.
let private reg (n: uint32): Register =
  if n <= 10u then LanguagePrimitives.EnumOfValue(int n) else undecodable ()

/// Checks a register field the instruction does not use, which the machine
/// requires to hold zero.
let private unusedReg (n: uint32) = if n <> 0u then undecodable () else ()

/// Checks the halfword an instruction not counting a distance does not use.
let private unusedOff (off: int16) = if off <> 0s then undecodable () else ()

/// Checks the word an instruction carrying no number does not use.
let private unusedImm (imm: int32) = if imm <> 0 then undecodable () else ()

/// The bits a number field holds, which is what is written wherever an
/// instruction carries a number.
let private immOf (imm: int32) = uint64 (uint32 imm)

/// The opcode a byte-reversing instruction names, given whether it works on the
/// whole of a register, which of the two orders it writes back in, and how much
/// of the register its number field asks it to reverse.
let private swapOpcode isWide readsReg (imm: int32) =
  match isWide, readsReg, imm with
  | true, false, 16 -> Opcode.BSWAP16
  | true, false, 32 -> Opcode.BSWAP32
  | true, false, 64 -> Opcode.BSWAP64
  | false, false, 16 -> Opcode.LE16
  | false, false, 32 -> Opcode.LE32
  | false, false, 64 -> Opcode.LE64
  | false, true, 16 -> Opcode.BE16
  | false, true, 32 -> Opcode.BE32
  | false, true, 64 -> Opcode.BE64
  | _ -> undecodable ()

/// <summary>
/// The opcode an instruction computing on the whole of a register names.
///
/// What names it is the four bits above the class together with the halfword
/// where a distance would sit, that halfword being what tells a division
/// reading both sides as signed from one reading them as unsigned, and a move
/// widening what it reads from a plain one.
/// </summary>
let private wideArithmeticOpcode w =
  match operation w.Code, w.Off with
  | 0x00u, 0s -> Opcode.ADD
  | 0x10u, 0s -> Opcode.SUB
  | 0x20u, 0s -> Opcode.MUL
  | 0x30u, 0s -> Opcode.DIV
  | 0x30u, 1s -> Opcode.SDIV
  | 0x40u, 0s -> Opcode.OR
  | 0x50u, 0s -> Opcode.AND
  | 0x60u, 0s -> Opcode.LSH
  | 0x70u, 0s -> Opcode.RSH
  | 0x80u, 0s -> Opcode.NEG
  | 0x90u, 0s -> Opcode.MOD
  | 0x90u, 1s -> Opcode.SMOD
  | 0xA0u, 0s -> Opcode.XOR
  | 0xB0u, 0s -> Opcode.MOV
  | 0xB0u, (8s | 16s | 32s) -> Opcode.MOVSX
  | 0xC0u, 0s -> Opcode.ARSH
  | 0xD0u, 0s -> swapOpcode true (readsRegister w.Code) w.Imm
  | _ -> undecodable ()

/// The opcode an instruction computing on the lower half of a register names.
/// A move widening what it reads cannot read a whole word here, that being the
/// whole of what such an instruction writes.
let private narrowArithmeticOpcode w =
  match operation w.Code, w.Off with
  | 0x00u, 0s -> Opcode.ADD32
  | 0x10u, 0s -> Opcode.SUB32
  | 0x20u, 0s -> Opcode.MUL32
  | 0x30u, 0s -> Opcode.DIV32
  | 0x30u, 1s -> Opcode.SDIV32
  | 0x40u, 0s -> Opcode.OR32
  | 0x50u, 0s -> Opcode.AND32
  | 0x60u, 0s -> Opcode.LSH32
  | 0x70u, 0s -> Opcode.RSH32
  | 0x80u, 0s -> Opcode.NEG32
  | 0x90u, 0s -> Opcode.MOD32
  | 0x90u, 1s -> Opcode.SMOD32
  | 0xA0u, 0s -> Opcode.XOR32
  | 0xB0u, 0s -> Opcode.MOV32
  | 0xB0u, (8s | 16s) -> Opcode.MOVSX32
  | 0xC0u, 0s -> Opcode.ARSH32
  | 0xD0u, 0s -> swapOpcode false (readsRegister w.Code) w.Imm
  | _ -> undecodable ()

/// The register an instruction computing writes, and what it computes from,
/// which is either a second register or a number written in its place.
let private arithmeticOperands w =
  if readsRegister w.Code then
    unusedImm w.Imm
    TwoOperands(OprReg(reg w.Dst), OprReg(reg w.Src))
  else
    unusedReg w.Src
    TwoOperands(OprReg(reg w.Dst), OprImm(immOf w.Imm))

/// The one register a negation names, it computing from nothing else.
let private negateOperands w =
  if readsRegister w.Code then undecodable () else ()
  unusedReg w.Src
  unusedImm w.Imm
  OneOperand(OprReg(reg w.Dst))

/// The register a widening move writes, the one it reads, and how much of that
/// one it reads, which is what the halfword where a distance would sit holds.
let private widenOperands w =
  if readsRegister w.Code then () else undecodable ()
  unusedImm w.Imm
  ThreeOperands(OprReg(reg w.Dst), OprReg(reg w.Src), OprImm(uint64 w.Off))

/// The one register a byte-reversing instruction names, how much of it to
/// reverse being part of the name rather than an operand.
let private swapOperands w =
  unusedReg w.Src
  OneOperand(OprReg(reg w.Dst))

/// Reads an instruction computing on a register, given whether it computes on
/// the whole of one or on its lower half.
let private parseArithmetic isWide w =
  let opcode =
    if isWide then wideArithmeticOpcode w else narrowArithmeticOpcode w
  let operands =
    match opcode with
    | Opcode.NEG | Opcode.NEG32 -> negateOperands w
    | Opcode.MOVSX | Opcode.MOVSX32 -> widenOperands w
    | Opcode.LE16 | Opcode.LE32 | Opcode.LE64
    | Opcode.BE16 | Opcode.BE32 | Opcode.BE64
    | Opcode.BSWAP16 | Opcode.BSWAP32 | Opcode.BSWAP64 -> swapOperands w
    | _ -> arithmeticOperands w
  struct (opcode, operands, 8u)

/// How far away the place a jump goes to is, which the encoding counts in
/// instructions and which is written here in the bytes an address counts.
let private jumpRel (off: int16) = int64 off * 8L

/// Reads the jump going where it names whatever holds, which counts how far
/// away that is in the halfword every other jump counts it in.
let private parseGoto w =
  if readsRegister w.Code then undecodable () else ()
  unusedReg w.Dst
  unusedReg w.Src
  unusedImm w.Imm
  struct (Opcode.JA, OneOperand(OprAddr(jumpRel w.Off)), 8u)

/// Reads a call, whose source field says what kind of thing it calls rather
/// than naming a register. A call to a function of this same program counts how
/// far away that function is where the others hold a number.
let private parseCall w =
  if readsRegister w.Code then undecodable () else ()
  unusedReg w.Dst
  unusedOff w.Off
  match w.Src with
  | 0u ->
    struct (Opcode.CALL, OneOperand(OprImm(immOf w.Imm)), 8u)
  | 1u ->
    struct (Opcode.CALL_LOCAL, OneOperand(OprAddr(int64 w.Imm * 8L)), 8u)
  | 2u ->
    struct (Opcode.CALL_KFUNC, OneOperand(OprImm(immOf w.Imm)), 8u)
  | _ ->
    undecodable ()

/// Reads the instruction returning to whatever called this, which names nothing
/// at all.
let private parseExit w =
  if readsRegister w.Code then undecodable () else ()
  unusedReg w.Dst
  unusedReg w.Src
  unusedOff w.Off
  unusedImm w.Imm
  struct (Opcode.EXIT, NoOperand, 8u)

/// The opcode a jump comparing the whole of what two registers hold names.
let private wideCompareOpcode op =
  match op with
  | 0x10u -> Opcode.JEQ
  | 0x20u -> Opcode.JGT
  | 0x30u -> Opcode.JGE
  | 0x40u -> Opcode.JSET
  | 0x50u -> Opcode.JNE
  | 0x60u -> Opcode.JSGT
  | 0x70u -> Opcode.JSGE
  | 0xA0u -> Opcode.JLT
  | 0xB0u -> Opcode.JLE
  | 0xC0u -> Opcode.JSLT
  | 0xD0u -> Opcode.JSLE
  | _ -> undecodable ()

/// The two things a jump compares and where it goes if they compare as its name
/// says. What it compares the first against is either a second register or a
/// number written in its place.
let private compareOperands w =
  let target = OprAddr(jumpRel w.Off)
  if readsRegister w.Code then
    unusedImm w.Imm
    ThreeOperands(OprReg(reg w.Dst), OprReg(reg w.Src), target)
  else
    unusedReg w.Src
    ThreeOperands(OprReg(reg w.Dst), OprImm(immOf w.Imm), target)

/// Reads a jump comparing the whole of what a register holds, or a call, or a
/// return: those two are kept among the jumps, and belong to this class alone.
let private parseWideJump w =
  match operation w.Code with
  | 0x00u -> parseGoto w
  | 0x80u -> parseCall w
  | 0x90u -> parseExit w
  | op -> struct (wideCompareOpcode op, compareOperands w, 8u)

/// Reads the jump reaching further than the one every other jump counts its
/// distance the same way as, this one counting it in the word a number sits in.
let private parseLongGoto w =
  if readsRegister w.Code then undecodable () else ()
  unusedReg w.Dst
  unusedReg w.Src
  unusedOff w.Off
  struct (Opcode.GOTOL, OneOperand(OprAddr(int64 w.Imm * 8L)), 8u)

/// The opcode a jump comparing the lower half of what two registers hold names.
let private narrowCompareOpcode op =
  match op with
  | 0x10u -> Opcode.JEQ32
  | 0x20u -> Opcode.JGT32
  | 0x30u -> Opcode.JGE32
  | 0x40u -> Opcode.JSET32
  | 0x50u -> Opcode.JNE32
  | 0x60u -> Opcode.JSGT32
  | 0x70u -> Opcode.JSGE32
  | 0xA0u -> Opcode.JLT32
  | 0xB0u -> Opcode.JLE32
  | 0xC0u -> Opcode.JSLT32
  | 0xD0u -> Opcode.JSLE32
  | _ -> undecodable ()

/// Reads a jump comparing the lower half of what a register holds. Neither a
/// call nor a return belongs to this class.
let private parseNarrowJump w =
  match operation w.Code with
  | 0x00u -> parseLongGoto w
  | op -> struct (narrowCompareOpcode op, compareOperands w, 8u)

/// The opcode the instruction carrying a whole quadword names, whose source
/// field says what the loader is to put there rather than naming a register.
let private wideLoadOpcode src =
  match src with
  | 0u -> Opcode.LDDW
  | 1u -> Opcode.LDDW_MAPFD
  | 2u -> Opcode.LDDW_MAPVAL
  | 3u -> Opcode.LDDW_BTFID
  | 4u -> Opcode.LDDW_FUNC
  | 5u -> Opcode.LDDW_MAPIDX
  | 6u -> Opcode.LDDW_MAPIDXVAL
  | _ -> undecodable ()

/// <summary>
/// Reads the one instruction two words wide.
///
/// The upper half of what it carries sits in the word after it, every other
/// field of which is required to hold zero; a span too short to hold that word
/// holds no such instruction either.
/// </summary>
let private parseWideLoad w (span: ByteSpan) (reader: IBinReader) =
  unusedOff w.Off
  if span[8] <> 0uy || span[9] <> 0uy then undecodable () else ()
  unusedOff (reader.ReadInt16(span, 10))
  let value = (immOf (reader.ReadInt32(span, 12)) <<< 32) ||| immOf w.Imm
  let opcode = wideLoadOpcode w.Src
  struct (opcode, TwoOperands(OprReg(reg w.Dst), OprImm value), 16u)

/// The opcode a read of the packet names, given how it says where in the packet
/// to read and how wide the read is. Nothing reads a quadword of a packet.
let private packetOpcode w =
  match accessMode w.Code, accessSize w.Code with
  | 0x20u, 0x10u -> Opcode.LDABSB
  | 0x20u, 0x08u -> Opcode.LDABSH
  | 0x20u, 0x00u -> Opcode.LDABSW
  | 0x40u, 0x10u -> Opcode.LDINDB
  | 0x40u, 0x08u -> Opcode.LDINDH
  | 0x40u, 0x00u -> Opcode.LDINDW
  | _ -> undecodable ()

/// <summary>
/// Reads a read of the packet.
///
/// Where in the packet to read is a number, counted from what a register holds
/// where the instruction names one, and what is read always lands in the first
/// register, which the instruction therefore does not name.
/// </summary>
let private parsePacketLoad w =
  let opcode = packetOpcode w
  unusedReg w.Dst
  unusedOff w.Off
  if accessMode w.Code = 0x20u then
    unusedReg w.Src
    struct (opcode, OneOperand(OprImm(immOf w.Imm)), 8u)
  else
    struct (opcode, TwoOperands(OprReg(reg w.Src), OprImm(immOf w.Imm)), 8u)

/// Reads an instruction of the class carrying what it loads within itself,
/// which is the one instruction two words wide together with the reads of a
/// packet the classic filters had.
let private parseLoad w span reader =
  if w.Code = 0x18u then parseWideLoad w span reader else parsePacketLoad w

/// The opcode a load from the memory a register points into names, given
/// whether it brings in the sign of what it read and how wide that was. Nothing
/// brings in the sign of a quadword, that being the whole of a register.
let private loadOpcode w =
  match accessMode w.Code, accessSize w.Code with
  | 0x60u, 0x10u -> Opcode.LDXB
  | 0x60u, 0x08u -> Opcode.LDXH
  | 0x60u, 0x00u -> Opcode.LDXW
  | 0x60u, 0x18u -> Opcode.LDXDW
  | 0x80u, 0x10u -> Opcode.LDXSB
  | 0x80u, 0x08u -> Opcode.LDXSH
  | 0x80u, 0x00u -> Opcode.LDXSW
  | _ -> undecodable ()

/// Reads a load from the memory a register points into.
let private parseRegisterLoad w =
  let opcode = loadOpcode w
  unusedImm w.Imm
  let memory = OprMem(reg w.Src, int32 w.Off)
  struct (opcode, TwoOperands(OprReg(reg w.Dst), memory), 8u)

/// The opcode a store of a number written in the instruction itself names.
let private immediateStoreOpcode w =
  match accessMode w.Code, accessSize w.Code with
  | 0x60u, 0x10u -> Opcode.STB
  | 0x60u, 0x08u -> Opcode.STH
  | 0x60u, 0x00u -> Opcode.STW
  | 0x60u, 0x18u -> Opcode.STDW
  | _ -> undecodable ()

/// Reads a store of a number written in the instruction itself.
let private parseImmediateStore w =
  let opcode = immediateStoreOpcode w
  unusedReg w.Src
  let memory = OprMem(reg w.Dst, int32 w.Off)
  struct (opcode, TwoOperands(memory, OprImm(immOf w.Imm)), 8u)

/// The opcode a store of what a register holds names.
let private registerStoreOpcode w =
  match accessSize w.Code with
  | 0x10u -> Opcode.STXB
  | 0x08u -> Opcode.STXH
  | 0x00u -> Opcode.STXW
  | 0x18u -> Opcode.STXDW
  | _ -> undecodable ()

/// The opcode an atomic store names, which is the operation held where a number
/// would sit together with how wide the memory it reaches is. The ones reading
/// what was there before them hold the bit below the operation as well.
let private atomicOpcode (imm: int32) isWide =
  match imm, isWide with
  | 0x00, false -> Opcode.ATOMIC_ADD_W
  | 0x00, true -> Opcode.ATOMIC_ADD_DW
  | 0x01, false -> Opcode.ATOMIC_FADD_W
  | 0x01, true -> Opcode.ATOMIC_FADD_DW
  | 0x40, false -> Opcode.ATOMIC_OR_W
  | 0x40, true -> Opcode.ATOMIC_OR_DW
  | 0x41, false -> Opcode.ATOMIC_FOR_W
  | 0x41, true -> Opcode.ATOMIC_FOR_DW
  | 0x50, false -> Opcode.ATOMIC_AND_W
  | 0x50, true -> Opcode.ATOMIC_AND_DW
  | 0x51, false -> Opcode.ATOMIC_FAND_W
  | 0x51, true -> Opcode.ATOMIC_FAND_DW
  | 0xA0, false -> Opcode.ATOMIC_XOR_W
  | 0xA0, true -> Opcode.ATOMIC_XOR_DW
  | 0xA1, false -> Opcode.ATOMIC_FXOR_W
  | 0xA1, true -> Opcode.ATOMIC_FXOR_DW
  | 0xE1, false -> Opcode.ATOMIC_XCHG_W
  | 0xE1, true -> Opcode.ATOMIC_XCHG_DW
  | 0xF1, false -> Opcode.ATOMIC_CMPXCHG_W
  | 0xF1, true -> Opcode.ATOMIC_CMPXCHG_DW
  | _ -> undecodable ()

/// Reads a store of what a register holds, atomic or otherwise. An atomic one
/// reaches a word or a quadword and nothing narrower.
let private parseRegisterStore w =
  let operands =
    TwoOperands(OprMem(reg w.Dst, int32 w.Off), OprReg(reg w.Src))
  match accessMode w.Code, accessSize w.Code with
  | 0x60u, _ ->
    unusedImm w.Imm
    struct (registerStoreOpcode w, operands, 8u)
  | 0xC0u, 0x00u ->
    struct (atomicOpcode w.Imm false, operands, 8u)
  | 0xC0u, 0x18u ->
    struct (atomicOpcode w.Imm true, operands, 8u)
  | _ ->
    undecodable ()

/// <summary>
/// Reads the word at the beginning of the given span into the fields every
/// instruction is read out of.
///
/// Which nibble of the second byte names which register follows the order the
/// bytes are stored in: the machine's own header declares the two as bitfields
/// of one byte, and a compiler lays the first of them in the low nibble on a
/// little-endian machine and in the high nibble on a big-endian one.
/// </summary>
let private wordOf (span: ByteSpan) (reader: IBinReader) =
  let regs = uint32 span[1]
  let struct (dst, src) =
    if reader.Endianness = Endian.Little then
      struct (regs &&& 0xFu, regs >>> 4)
    else
      struct (regs >>> 4, regs &&& 0xFu)
  { Code = uint32 span[0]
    Dst = dst
    Src = src
    Off = reader.ReadInt16(span, 2)
    Imm = reader.ReadInt32(span, 4) }

let parse lifter (span: ByteSpan) (reader: IBinReader) addr =
  let w = wordOf span reader
  let struct (opcode, operands, len) =
    match insClass w.Code with
    | 0x00u -> parseLoad w span reader
    | 0x01u -> parseRegisterLoad w
    | 0x02u -> parseImmediateStore w
    | 0x03u -> parseRegisterStore w
    | 0x04u -> parseArithmetic false w
    | 0x05u -> parseWideJump w
    | 0x06u -> parseNarrowJump w
    | _ -> parseArithmetic true w
  Instruction(addr, len, opcode, operands, lifter)

// vim: set tw=80 sts=2 sw=2:
