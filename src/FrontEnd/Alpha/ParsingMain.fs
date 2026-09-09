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
/// Reads one Alpha word and says which instruction it is and what it works on.
///
/// Every word is four bytes wide and begins with the six bits saying what kind
/// of instruction it is. What names the instruction within its kind is a
/// function code, and where the kind holds no function code the six bits name
/// the instruction on their own. A word whose function code names nothing, or
/// whose six bits name a kind the architecture keeps for itself, is read as no
/// instruction at all.
/// </summary>
module internal B2R2.FrontEnd.Alpha.ParsingMain

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ParsingUtils

/// The six bits every Alpha word begins with, which say what kind of
/// instruction it is.
let private majorOpcode bin = Bits.extract bin 31u 26u

/// The field naming the register an instruction reads first, which a branch
/// spends on the register it tests and a call on the one it writes where it
/// came from.
let private raField bin = Bits.extract bin 25u 21u

/// The field naming the register an instruction reads second, which is also
/// the register the memory it reaches is counted from.
let private rbField bin = Bits.extract bin 20u 16u

/// The field naming the register an instruction writes to.
let private rcField bin = Bits.extract bin 4u 0u

/// The general register a five-bit field names.
let private intReg (n: uint32): Register = LanguagePrimitives.EnumOfValue(int n)

/// The floating-point register a five-bit field names.
let private fltReg (n: uint32): Register =
  LanguagePrimitives.EnumOfValue(int Register.F0 + int n)

/// The displacement an instruction reaching memory holds, widened to the word
/// the machine adds it to an address as.
let private memDisp bin = Bits.extract bin 15u 0u |> uint16 |> int16 |> int32

/// The memory an instruction reaches, counted from a register.
let private memOperand bin = OprMem(intReg (rbField bin), memDisp bin)

/// Ra, and the memory the instruction reaches.
let private intMemory bin =
  TwoOperands(OprReg(intReg (raField bin)), memOperand bin)

/// The same, where the register the instruction names is a floating-point one.
let private fltMemory bin =
  TwoOperands(OprReg(fltReg (raField bin)), memOperand bin)

/// <summary>
/// Reads a load of a general register, which is a prefetch instead where the
/// register it loads into is the one that always reads as zero.
///
/// The two share an opcode, because a load whose result is thrown away is
/// exactly what a prefetch is and the architecture spends no opcode of its own
/// on it.
/// </summary>
let private intLoad op prefetch bin =
  if raField bin = 31u then prefetch, OneOperand(memOperand bin)
  else op, intMemory bin

/// The same, for a load of a floating-point register.
let private fltLoad op prefetch bin =
  if raField bin = 31u then prefetch, OneOperand(memOperand bin)
  else op, fltMemory bin

/// The routine a trap to PALcode names, which is the whole of the word below
/// the six bits saying that it is one.
let private palOperand bin =
  OneOperand(OprImm(uint64 (Bits.extract bin 25u 0u)))

/// <summary>
/// What an Operate instruction computes from where a second register would be.
///
/// The bit above that field says which of the two it holds: a register, or a
/// number between nothing and two hundred fifty-five that the machine widens
/// to a whole word.
/// </summary>
let private operateSource bin =
  if Bits.pick bin 12u = 1u then OprImm(uint64 (Bits.extract bin 20u 13u))
  else OprReg(intReg (rbField bin))

/// Ra, what stands where a second register would, and Rc.
let private threeOperate bin =
  ThreeOperands(OprReg(intReg (raField bin)),
                operateSource bin,
                OprReg(intReg (rcField bin)))

/// The same, without the first register, which the instructions reading only
/// one leave unused.
let private twoOperate bin =
  TwoOperands(operateSource bin, OprReg(intReg (rcField bin)))

/// Fa, Rc: what the two instructions moving a floating-point number into a
/// general register name.
let private floatToInt bin =
  TwoOperands(OprReg(fltReg (raField bin)), OprReg(intReg (rcField bin)))

/// The instructions adding, subtracting and comparing whole numbers.
let private parseIntegerArithmetic bin =
  match Bits.extract bin 11u 5u with
  | 0x00u -> Op.ADDL, threeOperate bin
  | 0x02u -> Op.S4ADDL, threeOperate bin
  | 0x09u -> Op.SUBL, threeOperate bin
  | 0x0Bu -> Op.S4SUBL, threeOperate bin
  | 0x0Fu -> Op.CMPBGE, threeOperate bin
  | 0x12u -> Op.S8ADDL, threeOperate bin
  | 0x1Bu -> Op.S8SUBL, threeOperate bin
  | 0x1Du -> Op.CMPULT, threeOperate bin
  | 0x20u -> Op.ADDQ, threeOperate bin
  | 0x22u -> Op.S4ADDQ, threeOperate bin
  | 0x29u -> Op.SUBQ, threeOperate bin
  | 0x2Bu -> Op.S4SUBQ, threeOperate bin
  | 0x2Du -> Op.CMPEQ, threeOperate bin
  | 0x32u -> Op.S8ADDQ, threeOperate bin
  | 0x3Bu -> Op.S8SUBQ, threeOperate bin
  | 0x3Du -> Op.CMPULE, threeOperate bin
  | 0x40u -> Op.ADDLV, threeOperate bin
  | 0x49u -> Op.SUBLV, threeOperate bin
  | 0x4Du -> Op.CMPLT, threeOperate bin
  | 0x60u -> Op.ADDQV, threeOperate bin
  | 0x69u -> Op.SUBQV, threeOperate bin
  | 0x6Du -> Op.CMPLE, threeOperate bin
  | _ -> raise ParsingFailureException

/// The instructions taking a word apart bit by bit, and the ones moving only
/// where something holds.
let private parseIntegerLogic bin =
  match Bits.extract bin 11u 5u with
  | 0x00u -> Op.AND, threeOperate bin
  | 0x08u -> Op.BIC, threeOperate bin
  | 0x14u -> Op.CMOVLBS, threeOperate bin
  | 0x16u -> Op.CMOVLBC, threeOperate bin
  | 0x20u -> Op.BIS, threeOperate bin
  | 0x24u -> Op.CMOVEQ, threeOperate bin
  | 0x26u -> Op.CMOVNE, threeOperate bin
  | 0x28u -> Op.ORNOT, threeOperate bin
  | 0x40u -> Op.XOR, threeOperate bin
  | 0x44u -> Op.CMOVLT, threeOperate bin
  | 0x46u -> Op.CMOVGE, threeOperate bin
  | 0x48u -> Op.EQV, threeOperate bin
  | 0x61u -> Op.AMASK, twoOperate bin
  | 0x64u -> Op.CMOVLE, threeOperate bin
  | 0x66u -> Op.CMOVGT, threeOperate bin
  | 0x6Cu -> Op.IMPLVER, OneOperand(OprReg(intReg (rcField bin)))
  | _ -> raise ParsingFailureException

/// The instructions shifting a word, and the ones reaching a byte, a word or a
/// longword inside one.
let private parseIntegerShift bin =
  match Bits.extract bin 11u 5u with
  | 0x02u -> Op.MSKBL, threeOperate bin
  | 0x06u -> Op.EXTBL, threeOperate bin
  | 0x0Bu -> Op.INSBL, threeOperate bin
  | 0x12u -> Op.MSKWL, threeOperate bin
  | 0x16u -> Op.EXTWL, threeOperate bin
  | 0x1Bu -> Op.INSWL, threeOperate bin
  | 0x22u -> Op.MSKLL, threeOperate bin
  | 0x26u -> Op.EXTLL, threeOperate bin
  | 0x2Bu -> Op.INSLL, threeOperate bin
  | 0x30u -> Op.ZAP, threeOperate bin
  | 0x31u -> Op.ZAPNOT, threeOperate bin
  | 0x32u -> Op.MSKQL, threeOperate bin
  | 0x34u -> Op.SRL, threeOperate bin
  | 0x36u -> Op.EXTQL, threeOperate bin
  | 0x39u -> Op.SLL, threeOperate bin
  | 0x3Bu -> Op.INSQL, threeOperate bin
  | 0x3Cu -> Op.SRA, threeOperate bin
  | 0x52u -> Op.MSKWH, threeOperate bin
  | 0x57u -> Op.INSWH, threeOperate bin
  | 0x5Au -> Op.EXTWH, threeOperate bin
  | 0x62u -> Op.MSKLH, threeOperate bin
  | 0x67u -> Op.INSLH, threeOperate bin
  | 0x6Au -> Op.EXTLH, threeOperate bin
  | 0x72u -> Op.MSKQH, threeOperate bin
  | 0x77u -> Op.INSQH, threeOperate bin
  | 0x7Au -> Op.EXTQH, threeOperate bin
  | _ -> raise ParsingFailureException

/// The instructions multiplying whole numbers.
let private parseIntegerMultiply bin =
  match Bits.extract bin 11u 5u with
  | 0x00u -> Op.MULL, threeOperate bin
  | 0x20u -> Op.MULQ, threeOperate bin
  | 0x30u -> Op.UMULH, threeOperate bin
  | 0x40u -> Op.MULLV, threeOperate bin
  | 0x60u -> Op.MULQV, threeOperate bin
  | _ -> raise ParsingFailureException

/// The instructions the later members of the family added: the ones widening a
/// byte or a word, the ones counting bits, the ones working on every byte of a
/// word at once, and the ones moving a floating-point number into a general
/// register.
let private parseExtension bin =
  match Bits.extract bin 11u 5u with
  | 0x00u -> Op.SEXTB, twoOperate bin
  | 0x01u -> Op.SEXTW, twoOperate bin
  | 0x30u -> Op.CTPOP, twoOperate bin
  | 0x31u -> Op.PERR, threeOperate bin
  | 0x32u -> Op.CTLZ, twoOperate bin
  | 0x33u -> Op.CTTZ, twoOperate bin
  | 0x34u -> Op.UNPKBW, twoOperate bin
  | 0x35u -> Op.UNPKBL, twoOperate bin
  | 0x36u -> Op.PKWB, twoOperate bin
  | 0x37u -> Op.PKLB, twoOperate bin
  | 0x38u -> Op.MINSB8, threeOperate bin
  | 0x39u -> Op.MINSW4, threeOperate bin
  | 0x3Au -> Op.MINUB8, threeOperate bin
  | 0x3Bu -> Op.MINUW4, threeOperate bin
  | 0x3Cu -> Op.MAXUB8, threeOperate bin
  | 0x3Du -> Op.MAXUW4, threeOperate bin
  | 0x3Eu -> Op.MAXSB8, threeOperate bin
  | 0x3Fu -> Op.MAXSW4, threeOperate bin
  | 0x70u -> Op.FTOIT, floatToInt bin
  | 0x78u -> Op.FTOIS, floatToInt bin
  | _ -> raise ParsingFailureException

/// Ra alone, which is what the instructions reading a counter or a flag name.
let private raOperand bin = OneOperand(OprReg(intReg (raField bin)))

/// The memory an instruction reaches named by a register alone, which is what
/// the instructions spending the displacement field on a function code reach.
let private baseOperand bin = OneOperand(OprBase(intReg (rbField bin)))

/// <summary>
/// The instructions ordering memory, hinting at it, and reading the counters.
///
/// These spend the whole of the field a displacement would sit in on saying
/// which of them a word is, so what is left for them to name is a register at
/// most.
/// </summary>
let private parseMiscellaneous bin =
  match Bits.extract bin 15u 0u with
  | 0x0000u -> Op.TRAPB, NoOperand
  | 0x0400u -> Op.EXCB, NoOperand
  | 0x4000u -> Op.MB, NoOperand
  | 0x4400u -> Op.WMB, NoOperand
  | 0x8000u -> Op.FETCH, baseOperand bin
  | 0xA000u -> Op.FETCH_M, baseOperand bin
  | 0xC000u -> Op.RPCC, raOperand bin
  | 0xE000u -> Op.RC, raOperand bin
  | 0xE800u -> Op.ECB, baseOperand bin
  | 0xF000u -> Op.RS, raOperand bin
  | 0xF800u -> Op.WH64, baseOperand bin
  | 0xFC00u -> Op.WH64EN, baseOperand bin
  | _ -> raise ParsingFailureException

/// Which of the four branches to a computed address a word is, which the two
/// bits at the top of the field a displacement would sit in say.
let private parseJump bin =
  match Bits.extract bin 15u 14u with
  | 0b00u -> Op.JMP
  | 0b01u -> Op.JSR
  | 0b10u -> Op.RET
  | _ -> Op.JSR_COROUTINE

/// <summary>
/// Ra, the register holding where to go, and the hint the word carries.
///
/// What is left of the displacement field is a guess at where the branch ends
/// up, which the machine reads to fill its pipeline and is free to be wrong,
/// so it is written out rather than folded into an address.
/// </summary>
let private jumpOperands bin =
  ThreeOperands(OprReg(intReg (raField bin)),
                OprBase(intReg (rbField bin)),
                OprImm(uint64 (Bits.extract bin 13u 0u)))

/// <summary>
/// How far away the place a branch names is, counted in bytes from the
/// instruction after it, which is where the machine counts from.
///
/// The field counts in words, because the two bits no aligned instruction can
/// differ by are worth two more bits of reach than they are worth kept.
/// </summary>
let private branchDisp bin = (int32 (Bits.extract bin 20u 0u <<< 11) >>> 11) * 4

/// The register a branch tests, and how far away the place it names is.
let private intBranch bin =
  TwoOperands(OprReg(intReg (raField bin)), OprAddr(branchDisp bin))

/// The same, where what it tests is a floating-point register.
let private fltBranch bin =
  TwoOperands(OprReg(fltReg (raField bin)), OprAddr(branchDisp bin))

/// What a floating-point instruction works on, which is three floating-point
/// registers unless it converts between formats, moves a general register in,
/// or names the control register.
let private floatOperands op bin =
  match op with
  | Op.ITOFS | Op.ITOFF | Op.ITOFT ->
    TwoOperands(OprReg(intReg (raField bin)), OprReg(fltReg (rcField bin)))
  | Op.MT_FPCR | Op.MF_FPCR ->
    OneOperand(OprReg(fltReg (raField bin)))
  | Op.SQRTF | Op.SQRTG | Op.SQRTS | Op.SQRTT | Op.CVTDG | Op.CVTGF | Op.CVTGD
  | Op.CVTGQ | Op.CVTQF | Op.CVTQG | Op.CVTTS | Op.CVTST | Op.CVTTQ | Op.CVTQS
  | Op.CVTQT | Op.CVTLQ | Op.CVTQL ->
    TwoOperands(OprReg(fltReg (rbField bin)), OprReg(fltReg (rcField bin)))
  | Op.ADDF | Op.SUBF | Op.MULF | Op.DIVF | Op.ADDG | Op.SUBG | Op.MULG
  | Op.DIVG | Op.CMPGEQ | Op.CMPGLT | Op.CMPGLE | Op.ADDS | Op.SUBS | Op.MULS
  | Op.DIVS | Op.ADDT | Op.SUBT | Op.MULT | Op.DIVT | Op.CMPTUN | Op.CMPTEQ
  | Op.CMPTLT | Op.CMPTLE | Op.CPYS | Op.CPYSN | Op.CPYSE | Op.FCMOVEQ
  | Op.FCMOVNE | Op.FCMOVLT | Op.FCMOVLE | Op.FCMOVGT | Op.FCMOVGE ->
    ThreeOperands(OprReg(fltReg (raField bin)),
                  OprReg(fltReg (rbField bin)),
                  OprReg(fltReg (rcField bin)))
  | _ ->
    raise ParsingFailureException

/// <summary>
/// The floating-point instructions, whose function code says what they compute
/// and how at once.
///
/// Which combinations of trapping and rounding each of them takes is not the
/// same from one to the next, so both ends of that are read off the one listing
/// in <see cref='T:B2R2.FrontEnd.Alpha.FloatFunction'/>.
/// </summary>
let private parseFloat bin =
  match FloatFunction.decode (majorOpcode bin) (Bits.extract bin 15u 5u) with
  | Some(struct (op, qualifier)) -> op, qualifier, floatOperands op bin
  | None -> raise ParsingFailureException

/// What an instruction carrying no qualifier reads as, which is every
/// instruction but the floating-point ones.
let private plain (op, operands) = op, Qualifier.NoQualifier, operands

/// Which instruction a whole word is, given the six bits it begins with.
let private parseInstruction bin =
  match majorOpcode bin with
  | 0x00u -> plain (Op.CALL_PAL, palOperand bin)
  | 0x08u -> plain (Op.LDA, intMemory bin)
  | 0x09u -> plain (Op.LDAH, intMemory bin)
  | 0x0Au -> plain (Op.LDBU, intMemory bin)
  | 0x0Bu -> plain (Op.LDQ_U, intMemory bin)
  | 0x0Cu -> plain (Op.LDWU, intMemory bin)
  | 0x0Du -> plain (Op.STW, intMemory bin)
  | 0x0Eu -> plain (Op.STB, intMemory bin)
  | 0x0Fu -> plain (Op.STQ_U, intMemory bin)
  | 0x10u -> parseIntegerArithmetic bin |> plain
  | 0x11u -> parseIntegerLogic bin |> plain
  | 0x12u -> parseIntegerShift bin |> plain
  | 0x13u -> parseIntegerMultiply bin |> plain
  | 0x14u | 0x15u | 0x16u | 0x17u -> parseFloat bin
  | 0x18u -> parseMiscellaneous bin |> plain
  | 0x1Au -> plain (parseJump bin, jumpOperands bin)
  | 0x1Cu -> parseExtension bin |> plain
  | 0x20u -> plain (Op.LDF, fltMemory bin)
  | 0x21u -> plain (Op.LDG, fltMemory bin)
  | 0x22u -> fltLoad Op.LDS Op.PREFETCH_M bin |> plain
  | 0x23u -> fltLoad Op.LDT Op.PREFETCH_MEN bin |> plain
  | 0x24u -> plain (Op.STF, fltMemory bin)
  | 0x25u -> plain (Op.STG, fltMemory bin)
  | 0x26u -> plain (Op.STS, fltMemory bin)
  | 0x27u -> plain (Op.STT, fltMemory bin)
  | 0x28u -> intLoad Op.LDL Op.PREFETCH bin |> plain
  | 0x29u -> intLoad Op.LDQ Op.PREFETCH_EN bin |> plain
  | 0x2Au -> plain (Op.LDL_L, intMemory bin)
  | 0x2Bu -> plain (Op.LDQ_L, intMemory bin)
  | 0x2Cu -> plain (Op.STL, intMemory bin)
  | 0x2Du -> plain (Op.STQ, intMemory bin)
  | 0x2Eu -> plain (Op.STL_C, intMemory bin)
  | 0x2Fu -> plain (Op.STQ_C, intMemory bin)
  | 0x30u -> plain (Op.BR, intBranch bin)
  | 0x31u -> plain (Op.FBEQ, fltBranch bin)
  | 0x32u -> plain (Op.FBLT, fltBranch bin)
  | 0x33u -> plain (Op.FBLE, fltBranch bin)
  | 0x34u -> plain (Op.BSR, intBranch bin)
  | 0x35u -> plain (Op.FBNE, fltBranch bin)
  | 0x36u -> plain (Op.FBGE, fltBranch bin)
  | 0x37u -> plain (Op.FBGT, fltBranch bin)
  | 0x38u -> plain (Op.BLBC, intBranch bin)
  | 0x39u -> plain (Op.BEQ, intBranch bin)
  | 0x3Au -> plain (Op.BLT, intBranch bin)
  | 0x3Bu -> plain (Op.BLE, intBranch bin)
  | 0x3Cu -> plain (Op.BLBS, intBranch bin)
  | 0x3Du -> plain (Op.BNE, intBranch bin)
  | 0x3Eu -> plain (Op.BGE, intBranch bin)
  | 0x3Fu -> plain (Op.BGT, intBranch bin)
  | _ -> raise ParsingFailureException

let parse lifter (span: ByteSpan) (reader: IBinReader) addr =
  let bin = reader.ReadUInt32(span, 0)
  let opcode, qualifier, operands = parseInstruction bin
  Instruction(addr, 4u, opcode, qualifier, operands, lifter)

// vim: set tw=80 sts=2 sw=2:
