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

module internal B2R2.FrontEnd.BinLifter.Intel.Lifter

open B2R2
open B2R2.BinIR
open B2R2.FrontEnd.BinLifter

type OP = Opcode (* Just to make it concise. *)

/// Translate IR.
let translate (ins: InsInfo) insAddr insLen ctxt =
  match ins.Opcode with
  | OP.AAA -> GeneralLifter.aaa ins insAddr insLen ctxt
  | OP.AAD -> GeneralLifter.aad ins insAddr insLen ctxt
  | OP.AAM -> GeneralLifter.aam ins insAddr insLen ctxt
  | OP.AAS -> GeneralLifter.aas ins insAddr insLen ctxt
  | OP.ADC -> GeneralLifter.adc ins insAddr insLen ctxt
  | OP.ADD -> GeneralLifter.add ins insAddr insLen ctxt
  | OP.AND -> GeneralLifter.``and`` ins insAddr insLen ctxt
  | OP.ANDN
  | OP.ARPL -> GeneralLifter.arpl ins insAddr insLen ctxt
  | OP.BNDMOV -> GeneralLifter.bndmov ins insAddr insLen ctxt
  | OP.BOUND -> GeneralLifter.nop insAddr insLen
  | OP.BSF -> GeneralLifter.bsf ins insAddr insLen ctxt
  | OP.BSR -> GeneralLifter.bsr ins insAddr insLen ctxt
  | OP.BSWAP -> GeneralLifter.bswap ins insAddr insLen ctxt
  | OP.BT -> GeneralLifter.bt ins insAddr insLen ctxt
  | OP.BTC -> GeneralLifter.btc ins insAddr insLen ctxt
  | OP.BTR -> GeneralLifter.btr ins insAddr insLen ctxt
  | OP.BTS -> GeneralLifter.bts ins insAddr insLen ctxt
  | OP.CALLNear -> GeneralLifter.call ins insAddr insLen ctxt
  | OP.CALLFar -> LiftingUtils.sideEffects insAddr insLen UnsupportedFAR
  | OP.CBW | OP.CWDE | OP.CDQE ->
    GeneralLifter.convBWQ ins insAddr insLen ctxt
  | OP.CLC -> GeneralLifter.clearFlag insAddr insLen ctxt R.CF
  | OP.CLD -> GeneralLifter.clearFlag insAddr insLen ctxt R.DF
  | OP.CLI -> GeneralLifter.clearFlag insAddr insLen ctxt R.IF
  | OP.CLRSSBSY -> GeneralLifter.nop insAddr insLen
  | OP.CMC -> GeneralLifter.cmc ins insAddr insLen ctxt
  | OP.CMOVO | OP.CMOVNO | OP.CMOVB | OP.CMOVAE
  | OP.CMOVZ | OP.CMOVNZ | OP.CMOVBE | OP.CMOVA
  | OP.CMOVS  | OP.CMOVNS | OP.CMOVP | OP.CMOVNP
  | OP.CMOVL | OP.CMOVGE | OP.CMOVLE | OP.CMOVG ->
    GeneralLifter.cmovcc ins insAddr insLen ctxt
  | OP.CMP -> GeneralLifter.cmp ins insAddr insLen ctxt
  | OP.CMPSB | OP.CMPSW | OP.CMPSQ ->
    GeneralLifter.cmps ins insAddr insLen ctxt
  | OP.CMPXCHG -> GeneralLifter.cmpxchg ins insAddr insLen ctxt
  | OP.CMPXCHG8B | OP.CMPXCHG16B ->
    GeneralLifter.compareExchangeBytes ins insAddr insLen ctxt
  | OP.CPUID -> LiftingUtils.sideEffects insAddr insLen ProcessorID
  | OP.CRC32 -> GeneralLifter.nop insAddr insLen
  | OP.CWD | OP.CDQ | OP.CQO ->
    GeneralLifter.convWDQ ins insAddr insLen ctxt
  | OP.DAA -> GeneralLifter.daa ins insAddr insLen ctxt
  | OP.DAS -> GeneralLifter.das ins insAddr insLen ctxt
  | OP.DEC -> GeneralLifter.dec ins insAddr insLen ctxt
  | OP.DIV | OP.IDIV -> GeneralLifter.div ins insAddr insLen ctxt
  | OP.ENDBR32 | OP.ENDBR64 -> GeneralLifter.nop insAddr insLen
  | OP.ENTER -> GeneralLifter.enter ins insAddr insLen ctxt
  | OP.HLT -> LiftingUtils.sideEffects insAddr insLen Halt
  | OP.IMUL -> GeneralLifter.imul ins insAddr insLen ctxt
  | OP.INC -> GeneralLifter.inc ins insAddr insLen ctxt
  | OP.INCSSPD | OP.INCSSPQ -> GeneralLifter.nop insAddr insLen
  | OP.INSB | OP.INSW | OP.INSD ->
    GeneralLifter.insinstr ins insAddr insLen ctxt
  | OP.INT -> GeneralLifter.interrupt ins insAddr insLen ctxt
  | OP.INT3 -> LiftingUtils.sideEffects insAddr insLen Breakpoint
  | OP.JMPFar | OP.JMPNear -> GeneralLifter.jmp ins insAddr insLen ctxt
  | OP.JO | OP.JNO | OP.JB | OP.JNB
  | OP.JZ | OP.JNZ | OP.JBE | OP.JA
  | OP.JS | OP.JNS | OP.JP | OP.JNP
  | OP.JL | OP.JNL | OP.JLE | OP.JG
  | OP.JECXZ | OP.JRCXZ -> GeneralLifter.jcc ins insAddr insLen ctxt
  | OP.LAHF -> LiftingUtils.sideEffects insAddr insLen ProcessorID
  | OP.LEA -> GeneralLifter.lea ins insAddr insLen ctxt
  | OP.LEAVE -> GeneralLifter.leave ins insAddr insLen ctxt
  | OP.LODSB | OP.LODSW | OP.LODSD | OP.LODSQ ->
    GeneralLifter.lods ins insAddr insLen ctxt
  | OP.LOOP | OP.LOOPE | OP.LOOPNE ->
    GeneralLifter.loop ins insAddr insLen ctxt
  | OP.LZCNT -> GeneralLifter.lzcnt ins insAddr insLen ctxt
  | OP.LDS | OP.LES | OP.LFS | OP.LGS | OP.LSS ->
    LiftingUtils.sideEffects insAddr insLen UnsupportedFAR
  | OP.MOV -> GeneralLifter.mov ins insAddr insLen ctxt
  | OP.MOVBE -> GeneralLifter.movbe ins insAddr insLen ctxt
  | OP.MOVSB | OP.MOVSW | OP.MOVSQ ->
    GeneralLifter.movs ins insAddr insLen ctxt
  | OP.MOVSX | OP.MOVSXD -> GeneralLifter.movsx ins insAddr insLen ctxt
  | OP.MOVZX -> GeneralLifter.movzx ins insAddr insLen ctxt
  | OP.MUL -> GeneralLifter.mul ins insAddr insLen ctxt
  | OP.NEG -> GeneralLifter.neg ins insAddr insLen ctxt
  | OP.NOP -> GeneralLifter.nop insAddr insLen
  | OP.NOT -> GeneralLifter.not ins insAddr insLen ctxt
  | OP.OR -> GeneralLifter.logOr ins insAddr insLen ctxt
  | OP.OUTSB | OP.OUTSW | OP.OUTSD ->
    GeneralLifter.outs ins insAddr insLen ctxt
  | OP.POP -> GeneralLifter.pop ins insAddr insLen ctxt
  | OP.POPA -> GeneralLifter.popa ins insAddr insLen ctxt 16<rt>
  | OP.POPAD -> GeneralLifter.popa ins insAddr insLen ctxt 32<rt>
  | OP.POPCNT -> GeneralLifter.popcnt ins insAddr insLen ctxt
  | OP.POPF | OP.POPFD | OP.POPFQ ->
    GeneralLifter.popf ins insAddr insLen ctxt
  | OP.PUSH -> GeneralLifter.push ins insAddr insLen ctxt
  | OP.PUSHA -> GeneralLifter.pusha ins insAddr insLen ctxt 16<rt>
  | OP.PUSHAD -> GeneralLifter.pusha ins insAddr insLen ctxt 32<rt>
  | OP.PUSHF | OP.PUSHFD | OP.PUSHFQ ->
    GeneralLifter.pushf ins insAddr insLen ctxt
  | OP.RCL -> GeneralLifter.rcl ins insAddr insLen ctxt
  | OP.RCR -> GeneralLifter.rcr ins insAddr insLen ctxt
  | OP.RDMSR | OP.RSM ->
    LiftingUtils.sideEffects insAddr insLen UnsupportedExtension
  | OP.RDPKRU -> GeneralLifter.rdpkru ins insAddr insLen ctxt
  | OP.RDPMC -> LiftingUtils.sideEffects insAddr insLen UnsupportedExtension
  | OP.RDRAND -> LiftingUtils.sideEffects insAddr insLen UnsupportedExtension
  | OP.RDSSPD | OP.RDSSPQ -> GeneralLifter.nop insAddr insLen
  | OP.RDTSC -> LiftingUtils.sideEffects insAddr insLen ClockCounter
  | OP.RDTSCP -> LiftingUtils.sideEffects insAddr insLen ClockCounter
  | OP.RETNear -> GeneralLifter.ret ins insAddr insLen ctxt
  | OP.RETNearImm -> GeneralLifter.retWithImm ins insAddr insLen ctxt
  | OP.RETFar -> LiftingUtils.sideEffects insAddr insLen UnsupportedFAR
  | OP.RETFarImm -> LiftingUtils.sideEffects insAddr insLen UnsupportedFAR
  | OP.ROL -> GeneralLifter.rol ins insAddr insLen ctxt
  | OP.ROR -> GeneralLifter.ror ins insAddr insLen ctxt
  | OP.RORX -> GeneralLifter.rorx ins insAddr insLen ctxt
  | OP.RSTORSSP -> GeneralLifter.nop insAddr insLen
  | OP.SAHF -> GeneralLifter.sahf ins insAddr insLen ctxt
  | OP.SAR | OP.SHR | OP.SHL ->
    GeneralLifter.shift ins insAddr insLen ctxt
  | OP.SAVEPREVSSP -> GeneralLifter.nop insAddr insLen
  | OP.SBB -> GeneralLifter.sbb ins insAddr insLen ctxt
  | OP.SCASB | OP.SCASW | OP.SCASD | OP.SCASQ ->
    GeneralLifter.scas ins insAddr insLen ctxt
  | OP.SETO | OP.SETNO | OP.SETB | OP.SETNB
  | OP.SETZ | OP.SETNZ | OP.SETBE | OP.SETA
  | OP.SETS | OP.SETNS | OP.SETP | OP.SETNP
  | OP.SETL | OP.SETNL | OP.SETLE | OP.SETG ->
    GeneralLifter.setcc ins insAddr insLen ctxt
  | OP.SETSSBSY -> GeneralLifter.nop insAddr insLen
  | OP.SHLD -> GeneralLifter.shld ins insAddr insLen ctxt
  | OP.SHLX -> GeneralLifter.shlx ins insAddr insLen ctxt
  | OP.SHRD -> GeneralLifter.shrd ins insAddr insLen ctxt
  | OP.STC -> GeneralLifter.stc insAddr insLen ctxt
  | OP.STD -> GeneralLifter.std insAddr insLen ctxt
  | OP.STI -> GeneralLifter.sti insAddr insLen ctxt
  | OP.STOSB | OP.STOSW | OP.STOSD | OP.STOSQ ->
    GeneralLifter.stos ins insAddr insLen ctxt
  | OP.SUB -> GeneralLifter.sub ins insAddr insLen ctxt
  | OP.SYSCALL | OP.SYSENTER -> LiftingUtils.sideEffects insAddr insLen SysCall
  | OP.TEST -> GeneralLifter.test ins insAddr insLen ctxt
  | OP.TZCNT -> GeneralLifter.tzcnt ins insAddr insLen ctxt
  | OP.UD2 -> LiftingUtils.sideEffects insAddr insLen UndefinedInstr
  | OP.WRFSBASE -> GeneralLifter.wrfsbase ins insAddr insLen ctxt
  | OP.WRGSBASE -> GeneralLifter.wrgsbase ins insAddr insLen ctxt
  | OP.WRPKRU -> GeneralLifter.wrpkru ins insAddr insLen ctxt
  | OP.WRSSD | OP.WRSSQ -> GeneralLifter.nop insAddr insLen
  | OP.WRUSSD | OP.WRUSSQ -> GeneralLifter.nop insAddr insLen
  | OP.XABORT -> LiftingUtils.sideEffects insAddr insLen UnsupportedExtension
  | OP.XADD -> GeneralLifter.xadd ins insAddr insLen ctxt
  | OP.XBEGIN -> LiftingUtils.sideEffects insAddr insLen UnsupportedExtension
  | OP.XCHG -> GeneralLifter.xchg ins insAddr insLen ctxt
  | OP.XEND -> LiftingUtils.sideEffects insAddr insLen UnsupportedExtension
  | OP.XGETBV -> LiftingUtils.sideEffects insAddr insLen UnsupportedExtension
  | OP.XLATB -> GeneralLifter.xlatb ins insAddr insLen ctxt
  | OP.XOR -> GeneralLifter.xor ins insAddr insLen ctxt
  | OP.XRSTOR | OP.XRSTORS | OP.XSAVE | OP.XSAVEC
  | OP.XSAVEC64 | OP.XSAVEOPT | OP.XSAVES | OP.XSAVES64 ->
    LiftingUtils.sideEffects insAddr insLen UnsupportedExtension
  | OP.XTEST -> LiftingUtils.sideEffects insAddr insLen UnsupportedExtension
  | OP.IN | OP.INTO | OP.INVD | OP.INVLPG | OP.IRETD
  | OP.IRETQ | OP.IRETW | OP.LAR | OP.LGDT | OP.LLDT
  | OP.LMSW | OP.LSL | OP.LTR | OP.OUT | OP.SGDT
  | OP.SIDT | OP.SLDT | OP.SMSW | OP.STR | OP.VERR
  | OP.MOVD -> MMXLifter.movd ins insAddr insLen ctxt
  | OP.MOVQ -> MMXLifter.movq ins insAddr insLen ctxt
  | OP.PACKSSDW -> MMXLifter.packssdw ins insAddr insLen ctxt
  | OP.PACKSSWB -> MMXLifter.packsswb ins insAddr insLen ctxt
  | OP.PACKUSWB -> MMXLifter.packuswb ins insAddr insLen ctxt
  | OP.PUNPCKHBW -> MMXLifter.punpckhbw ins insAddr insLen ctxt
  | OP.PUNPCKHWD -> MMXLifter.punpckhwd ins insAddr insLen ctxt
  | OP.PUNPCKHDQ -> MMXLifter.punpckhdq ins insAddr insLen ctxt
  | OP.PUNPCKLBW -> MMXLifter.punpcklbw ins insAddr insLen ctxt
  | OP.PUNPCKLWD -> MMXLifter.punpcklwd ins insAddr insLen ctxt
  | OP.PUNPCKLDQ -> MMXLifter.punpckldq ins insAddr insLen ctxt
  | OP.PADDB -> MMXLifter.paddb ins insAddr insLen ctxt
  | OP.PADDW -> MMXLifter.paddw ins insAddr insLen ctxt
  | OP.PADDD -> MMXLifter.paddd ins insAddr insLen ctxt
  | OP.PADDSB -> MMXLifter.paddsb ins insAddr insLen ctxt
  | OP.PADDSW -> MMXLifter.paddsw ins insAddr insLen ctxt
  | OP.PADDUSB -> MMXLifter.paddusb ins insAddr insLen ctxt
  | OP.PADDUSW -> MMXLifter.paddusw ins insAddr insLen ctxt
  | OP.PSUBB -> MMXLifter.psubb ins insAddr insLen ctxt
  | OP.PSUBW -> MMXLifter.psubw ins insAddr insLen ctxt
  | OP.PSUBD -> MMXLifter.psubd ins insAddr insLen ctxt
  | OP.PSUBSB -> MMXLifter.psubsb ins insAddr insLen ctxt
  | OP.PSUBSW -> MMXLifter.psubsw ins insAddr insLen ctxt
  | OP.PSUBUSB -> MMXLifter.psubusb ins insAddr insLen ctxt
  | OP.PSUBUSW -> MMXLifter.psubusw ins insAddr insLen ctxt
  | OP.PMULHW -> MMXLifter.pmulhw ins insAddr insLen ctxt
  | OP.PMULLW -> MMXLifter.pmullw ins insAddr insLen ctxt
  | OP.PMADDWD -> MMXLifter.pmaddwd ins insAddr insLen ctxt
  | OP.PCMPEQB -> MMXLifter.pcmpeqb ins insAddr insLen ctxt
  | OP.PCMPEQW -> MMXLifter.pcmpeqw ins insAddr insLen ctxt
  | OP.PCMPEQD -> MMXLifter.pcmpeqd ins insAddr insLen ctxt
  | OP.PCMPGTB -> MMXLifter.pcmpgtb ins insAddr insLen ctxt
  | OP.PCMPGTW -> MMXLifter.pcmpgtw ins insAddr insLen ctxt
  | OP.PCMPGTD -> MMXLifter.pcmpgtd ins insAddr insLen ctxt
  | OP.PAND -> MMXLifter.pand ins insAddr insLen ctxt
  | OP.PANDN -> MMXLifter.pandn ins insAddr insLen ctxt
  | OP.POR -> MMXLifter.por ins insAddr insLen ctxt
  | OP.PXOR -> MMXLifter.pxor ins insAddr insLen ctxt
  | OP.PSLLW -> MMXLifter.psllw ins insAddr insLen ctxt
  | OP.PSLLD -> MMXLifter.pslld ins insAddr insLen ctxt
  | OP.PSLLQ -> MMXLifter.psllq ins insAddr insLen ctxt
  | OP.PSRLW -> MMXLifter.psrlw ins insAddr insLen ctxt
  | OP.PSRLD -> MMXLifter.psrld ins insAddr insLen ctxt
  | OP.PSRLQ -> MMXLifter.psrlq ins insAddr insLen ctxt
  | OP.PSRAW -> MMXLifter.psraw ins insAddr insLen ctxt
  | OP.PSRAD -> MMXLifter.psrad ins insAddr insLen ctxt
  | OP.EMMS -> MMXLifter.emms ins insAddr insLen ctxt
  | OP.MOVAPS -> SSELifter.movaps ins insAddr insLen ctxt
  | OP.MOVAPD -> SSELifter.movapd ins insAddr insLen ctxt (* SSE2 *)
  | OP.MOVUPS -> SSELifter.movups ins insAddr insLen ctxt
  | OP.MOVUPD -> SSELifter.movupd ins insAddr insLen ctxt (* SSE2 *)
  | OP.MOVHPS -> SSELifter.movhps ins insAddr insLen ctxt
  | OP.MOVHPD -> SSELifter.movhpd ins insAddr insLen ctxt (* SSE2 *)
  | OP.MOVHLPS -> SSELifter.movhlps ins insAddr insLen ctxt
  | OP.MOVLPS -> SSELifter.movlps ins insAddr insLen ctxt
  | OP.MOVLPD -> SSELifter.movlpd ins insAddr insLen ctxt (* SSE2 *)
  | OP.MOVLHPS -> SSELifter.movlhps ins insAddr insLen ctxt
  | OP.MOVMSKPS -> SSELifter.movmskps ins insAddr insLen ctxt
  | OP.MOVMSKPD -> SSELifter.movmskpd ins insAddr insLen ctxt (* SSE2 *)
  | OP.MOVSS -> SSELifter.movss ins insAddr insLen ctxt
  | OP.MOVSD -> SSELifter.movsd ins insAddr insLen ctxt (* SSE2 *)
  | OP.ADDPS -> SSELifter.addps ins insAddr insLen ctxt
  | OP.ADDPD -> SSELifter.addpd ins insAddr insLen ctxt (* SSE2 *)
  | OP.ADDSS -> SSELifter.addss ins insAddr insLen ctxt
  | OP.ADDSD -> SSELifter.addsd ins insAddr insLen ctxt (* SSE2 *)
  | OP.SUBPS -> SSELifter.subps ins insAddr insLen ctxt
  | OP.SUBPD -> SSELifter.subpd ins insAddr insLen ctxt (* SSE2 *)
  | OP.SUBSS -> SSELifter.subss ins insAddr insLen ctxt
  | OP.SUBSD -> SSELifter.subsd ins insAddr insLen ctxt (* SSE2 *)
  | OP.MULPS -> SSELifter.mulps ins insAddr insLen ctxt
  | OP.MULPD -> SSELifter.mulpd ins insAddr insLen ctxt (* SSE2 *)
  | OP.MULSS -> SSELifter.mulss ins insAddr insLen ctxt
  | OP.MULSD -> SSELifter.mulsd ins insAddr insLen ctxt (* SSE2 *)
  | OP.DIVPS -> SSELifter.divps ins insAddr insLen ctxt
  | OP.DIVPD -> SSELifter.divpd ins insAddr insLen ctxt (* SSE2 *)
  | OP.DIVSS -> SSELifter.divss ins insAddr insLen ctxt
  | OP.DIVSD -> SSELifter.divsd ins insAddr insLen ctxt (* SSE2 *)
  | OP.RCPPS -> SSELifter.rcpps ins insAddr insLen ctxt
  | OP.RCPSS -> SSELifter.rcpss ins insAddr insLen ctxt
  | OP.SQRTPS -> SSELifter.sqrtps ins insAddr insLen ctxt
  | OP.SQRTPD -> SSELifter.sqrtpd ins insAddr insLen ctxt (* SSE2 *)
  | OP.SQRTSS -> SSELifter.sqrtss ins insAddr insLen ctxt
  | OP.SQRTSD -> SSELifter.sqrtsd ins insAddr insLen ctxt (* SSE2 *)
  | OP.RSQRTPS -> SSELifter.rsqrtps ins insAddr insLen ctxt
  | OP.RSQRTSS -> SSELifter.rsqrtss ins insAddr insLen ctxt
  | OP.MAXPS -> SSELifter.maxps ins insAddr insLen ctxt
  | OP.MAXPD -> SSELifter.maxpd ins insAddr insLen ctxt (* SSE2 *)
  | OP.MAXSS -> SSELifter.maxss ins insAddr insLen ctxt
  | OP.MAXSD -> SSELifter.maxsd ins insAddr insLen ctxt (* SSE2 *)
  | OP.MINPS -> SSELifter.minps ins insAddr insLen ctxt
  | OP.MINPD -> SSELifter.minpd ins insAddr insLen ctxt (* SSE2 *)
  | OP.MINSS -> SSELifter.minss ins insAddr insLen ctxt
  | OP.MINSD -> SSELifter.minsd ins insAddr insLen ctxt (* SSE2 *)
  | OP.CMPPS -> SSELifter.cmpps ins insAddr insLen ctxt
  | OP.CMPPD -> SSELifter.cmppd ins insAddr insLen ctxt (* SSE2 *)
  | OP.CMPSS -> SSELifter.cmpss ins insAddr insLen ctxt
  | OP.CMPSD -> SSELifter.cmpsd ins insAddr insLen ctxt (* SSE2 *)
  | OP.COMISS | OP.VCOMISS ->
    SSELifter.comiss ins insAddr insLen ctxt
  | OP.COMISD | OP.VCOMISD -> (* SSE2 *)
    SSELifter.comisd ins insAddr insLen ctxt
  | OP.UCOMISS | OP.VUCOMISS ->
    SSELifter.ucomiss ins insAddr insLen ctxt
  | OP.UCOMISD | OP.VUCOMISD -> (* SSE2 *)
    SSELifter.ucomisd ins insAddr insLen ctxt
  | OP.ANDPS -> SSELifter.andps ins insAddr insLen ctxt
  | OP.ANDPD -> SSELifter.andpd ins insAddr insLen ctxt (* SSE2 *)
  | OP.ANDNPS -> SSELifter.andnps ins insAddr insLen ctxt
  | OP.ANDNPD -> SSELifter.andnpd ins insAddr insLen ctxt (* SSE2 *)
  | OP.ORPS -> SSELifter.orps ins insAddr insLen ctxt
  | OP.ORPD -> SSELifter.orpd ins insAddr insLen ctxt (* SSE2 *)
  | OP.XORPS -> SSELifter.xorps ins insAddr insLen ctxt
  | OP.XORPD -> SSELifter.xorpd ins insAddr insLen ctxt (* SSE2 *)
  | OP.SHUFPS -> SSELifter.shufps ins insAddr insLen ctxt
  | OP.SHUFPD -> SSELifter.shufpd ins insAddr insLen ctxt (* SSE2 *)
  | OP.UNPCKHPS -> SSELifter.unpckhps ins insAddr insLen ctxt
  | OP.UNPCKHPD -> SSELifter.unpckhpd ins insAddr insLen ctxt (* SSE2 *)
  | OP.UNPCKLPS -> SSELifter.unpcklps ins insAddr insLen ctxt
  | OP.UNPCKLPD -> SSELifter.unpcklpd ins insAddr insLen ctxt (* SSE2 *)
  | OP.CVTPI2PS -> SSELifter.cvtpi2ps ins insAddr insLen ctxt
  | OP.CVTPI2PD -> SSELifter.cvtpi2pd ins insAddr insLen ctxt (* SSE2 *)
  | OP.CVTSI2SS -> SSELifter.cvtsi2ss ins insAddr insLen ctxt
  | OP.CVTSI2SD -> SSELifter.cvtsi2sd ins insAddr insLen ctxt (* SSE2 *)
  | OP.CVTPS2PI -> SSELifter.cvtps2pi ins insAddr insLen ctxt true
  | OP.CVTPS2PD -> SSELifter.cvtps2pd ins insAddr insLen ctxt (* SSE2 *)
  | OP.CVTPD2PS -> SSELifter.cvtpd2ps ins insAddr insLen ctxt (* SSE2 *)
  | OP.CVTPD2PI -> SSELifter.cvtpd2pi ins insAddr insLen ctxt true (* SSE2 *)
  | OP.CVTPD2DQ -> SSELifter.cvtpd2dq ins insAddr insLen ctxt true (* SSE2 *)
  | OP.CVTTPD2DQ -> SSELifter.cvtpd2dq ins insAddr insLen ctxt false (* SSE2 *)
  | OP.CVTDQ2PS -> SSELifter.cvtdq2ps ins insAddr insLen ctxt (* SSE2 *)
  | OP.CVTDQ2PD -> SSELifter.cvtdq2pd ins insAddr insLen ctxt (* SSE2 *)
  | OP.CVTPS2DQ -> SSELifter.cvtps2dq ins insAddr insLen ctxt true (* SSE2 *)
  | OP.CVTTPS2DQ -> SSELifter.cvtps2dq ins insAddr insLen ctxt false (* SSE2 *)
  | OP.CVTTPS2PI -> SSELifter.cvtps2pi ins insAddr insLen ctxt false
  | OP.CVTTPD2PI -> SSELifter.cvtpd2pi ins insAddr insLen ctxt false (* SSE2 *)
  | OP.CVTSS2SI | OP.VCVTSS2SI ->
    SSELifter.cvtss2si ins insAddr insLen ctxt true
  | OP.CVTSS2SD -> SSELifter.cvtss2sd ins insAddr insLen ctxt (* SSE2 *)
  | OP.CVTSD2SS -> SSELifter.cvtsd2ss ins insAddr insLen ctxt (* SSE2 *)
  | OP.CVTSD2SI | OP.VCVTSD2SI -> (* SSE2 *)
    SSELifter.cvtsd2si ins insAddr insLen ctxt true
  | OP.CVTTSS2SI | OP.VCVTTSS2SI ->
    SSELifter.cvtss2si ins insAddr insLen ctxt false
  | OP.CVTTSD2SI | OP.VCVTTSD2SI -> (* SSE2 *)
    SSELifter.cvtsd2si ins insAddr insLen ctxt false
  | OP.LDMXCSR -> SSELifter.ldmxcsr ins insAddr insLen ctxt
  | OP.STMXCSR -> SSELifter.stmxcsr ins insAddr insLen ctxt
  | OP.PAVGB -> SSELifter.pavgb ins insAddr insLen ctxt
  | OP.PAVGW -> SSELifter.pavgw ins insAddr insLen ctxt
  | OP.PEXTRW -> SSELifter.pextrw ins insAddr insLen ctxt
  | OP.PINSRW -> SSELifter.pinsrw ins insAddr insLen ctxt
  | OP.PMAXUB -> SSELifter.pmaxub ins insAddr insLen ctxt
  | OP.PMAXSW -> SSELifter.pmaxsw ins insAddr insLen ctxt
  | OP.PMAXSB -> SSELifter.pmaxsb ins insAddr insLen ctxt (* SSE4 *)
  | OP.PMINUB -> SSELifter.pminub ins insAddr insLen ctxt
  | OP.PMINSW -> SSELifter.pminsw ins insAddr insLen ctxt
  | OP.PMINUD -> SSELifter.pminud ins insAddr insLen ctxt (* SSE4 *)
  | OP.PMINSB -> SSELifter.pminsb ins insAddr insLen ctxt (* SSE4 *)
  | OP.PMOVMSKB -> SSELifter.pmovmskb ins insAddr insLen ctxt
  | OP.PMULHUW -> SSELifter.pmulhuw ins insAddr insLen ctxt
  | OP.PSADBW -> SSELifter.psadbw ins insAddr insLen ctxt
  | OP.PSHUFW -> SSELifter.pshufw ins insAddr insLen ctxt
  | OP.PSHUFD -> SSELifter.pshufd ins insAddr insLen ctxt (* SSE2 *)
  | OP.PSHUFLW -> SSELifter.pshuflw ins insAddr insLen ctxt (* SSE2 *)
  | OP.PSHUFHW -> SSELifter.pshufhw ins insAddr insLen ctxt (* SSE2 *)
  | OP.PSHUFB -> SSELifter.pshufb ins insAddr insLen ctxt (* SSE3 *)
  | OP.MOVDQA -> SSELifter.movdqa ins insAddr insLen ctxt (* SSE2 *)
  | OP.MOVDQU -> SSELifter.movdqu ins insAddr insLen ctxt (* SSE2 *)
  | OP.MOVQ2DQ -> SSELifter.movq2dq ins insAddr insLen ctxt (* SSE2 *)
  | OP.MOVDQ2Q -> SSELifter.movdq2q ins insAddr insLen ctxt (* SSE2 *)
  | OP.PMULUDQ -> SSELifter.pmuludq ins insAddr insLen ctxt (* SSE2 *)
  | OP.PADDQ -> SSELifter.paddq ins insAddr insLen ctxt (* SSE2 *)
  | OP.PSUBQ -> SSELifter.psubq ins insAddr insLen ctxt (* SSE2 *)
  | OP.PSLLDQ -> SSELifter.pslldq ins insAddr insLen ctxt (* SSE2 *)
  | OP.PSRLDQ -> SSELifter.psrldq ins insAddr insLen ctxt (* SSE2 *)
  | OP.PUNPCKHQDQ -> SSELifter.punpckhqdq ins insAddr insLen ctxt (* SSE2 *)
  | OP.PUNPCKLQDQ -> SSELifter.punpcklqdq ins insAddr insLen ctxt (* SSE2 *)
  | OP.MOVNTQ -> SSELifter.movntq ins insAddr insLen ctxt
  | OP.MOVNTPS -> SSELifter.movntps ins insAddr insLen ctxt
  | OP.PREFETCHNTA
  | OP.PREFETCHT0 | OP.PREFETCHT1
  | OP.PREFETCHW | OP.PREFETCHT2 -> GeneralLifter.nop insAddr insLen
  | OP.SFENCE -> LiftingUtils.sideEffects insAddr insLen Fence
  | OP.CLFLUSH -> GeneralLifter.nop insAddr insLen (* SSE2 *)
  | OP.LFENCE -> LiftingUtils.sideEffects insAddr insLen Fence (* SSE2 *)
  | OP.MFENCE -> LiftingUtils.sideEffects insAddr insLen Fence (* SSE2 *)
  | OP.PAUSE -> LiftingUtils.sideEffects insAddr insLen Pause (* SSE2 *)
  | OP.MOVNTPD -> SSELifter.movntpd ins insAddr insLen ctxt (* SSE2 *)
  | OP.MOVNTDQ -> SSELifter.movntdq ins insAddr insLen ctxt (* SSE2 *)
  | OP.MOVNTI -> SSELifter.movnti ins insAddr insLen ctxt (* SSE2 *)
  | OP.LDDQU -> SSELifter.lddqu ins insAddr insLen ctxt (* SSE3 *)
  | OP.MOVSHDUP -> SSELifter.movshdup ins insAddr insLen ctxt (* SSE3 *)
  | OP.MOVSLDUP -> SSELifter.movsldup ins insAddr insLen ctxt (* SSE3 *)
  | OP.MOVDDUP -> SSELifter.movddup ins insAddr insLen ctxt (* SSE3 *)
  | OP.PALIGNR -> SSELifter.palignr ins insAddr insLen ctxt (* SSE3 *)
  | OP.ROUNDSD -> SSELifter.roundsd ins insAddr insLen ctxt (* SSE4 *)
  | OP.PINSRB -> SSELifter.pinsrb ins insAddr insLen ctxt (* SSE4 *)
  | OP.PTEST -> SSELifter.ptest ins insAddr insLen ctxt (* SSE4 *)
  | OP.PCMPEQQ -> SSELifter.pcmpeqq ins insAddr insLen ctxt (* SSE4 *)
  | OP.PCMPESTRI | OP.PCMPESTRM | OP.PCMPISTRI | OP.PCMPISTRM ->
    SSELifter.pcmpstr ins insAddr insLen ctxt (* SSE4 *)
  | OP.VSQRTPS -> AVXLifter.vsqrtps ins insAddr insLen ctxt
  | OP.VSQRTPD -> AVXLifter.vsqrtpd ins insAddr insLen ctxt
  | OP.VSQRTSS -> AVXLifter.vsqrtss ins insAddr insLen ctxt
  | OP.VSQRTSD -> AVXLifter.vsqrtsd ins insAddr insLen ctxt
  | OP.VADDPS -> AVXLifter.vaddps ins insAddr insLen ctxt
  | OP.VADDPD -> AVXLifter.vaddpd ins insAddr insLen ctxt
  | OP.VADDSS -> AVXLifter.vaddss ins insAddr insLen ctxt
  | OP.VADDSD -> AVXLifter.vaddsd ins insAddr insLen ctxt
  | OP.VSUBPS -> AVXLifter.vsubps ins insAddr insLen ctxt
  | OP.VSUBPD -> AVXLifter.vsubpd ins insAddr insLen ctxt
  | OP.VSUBSS -> AVXLifter.vsubss ins insAddr insLen ctxt
  | OP.VSUBSD -> AVXLifter.vsubsd ins insAddr insLen ctxt
  | OP.VMULPS -> AVXLifter.vmulps ins insAddr insLen ctxt
  | OP.VMULPD -> AVXLifter.vmulpd ins insAddr insLen ctxt
  | OP.VMULSS -> AVXLifter.vmulss ins insAddr insLen ctxt
  | OP.VMULSD -> AVXLifter.vmulsd ins insAddr insLen ctxt
  | OP.VDIVPS -> AVXLifter.vdivps ins insAddr insLen ctxt
  | OP.VDIVPD -> AVXLifter.vdivpd ins insAddr insLen ctxt
  | OP.VDIVSS -> AVXLifter.vdivss ins insAddr insLen ctxt
  | OP.VDIVSD -> AVXLifter.vdivsd ins insAddr insLen ctxt
  | OP.VCVTSI2SS -> AVXLifter.vcvtsi2ss ins insAddr insLen ctxt
  | OP.VCVTSI2SD -> AVXLifter.vcvtsi2sd ins insAddr insLen ctxt
  | OP.VCVTSD2SS -> AVXLifter.vcvtsd2ss ins insAddr insLen ctxt
  | OP.VCVTSS2SD -> AVXLifter.vcvtss2sd ins insAddr insLen ctxt
  | OP.VMOVD -> AVXLifter.vmovd ins insAddr insLen ctxt
  | OP.VMOVQ -> AVXLifter.vmovq ins insAddr insLen ctxt
  | OP.VMOVAPS -> AVXLifter.vmovdqu ins insAddr insLen ctxt
  | OP.VMOVAPD -> AVXLifter.vmovdqu ins insAddr insLen ctxt
  | OP.VMOVDQU -> AVXLifter.vmovdqu ins insAddr insLen ctxt
  | OP.VMOVDQU16 -> AVXLifter.vmovdqu16 ins insAddr insLen ctxt
  | OP.VMOVDQU64 -> AVXLifter.vmovdqu64 ins insAddr insLen ctxt
  | OP.VMOVDQA -> AVXLifter.vmovdqa ins insAddr insLen ctxt
  | OP.VMOVDQA64 -> AVXLifter.vmovdqa64 ins insAddr insLen ctxt
  | OP.VMOVNTDQ -> AVXLifter.vmovntdq ins insAddr insLen ctxt
  | OP.VMOVUPS -> AVXLifter.vmovups ins insAddr insLen ctxt
  | OP.VMOVUPD -> AVXLifter.vmovupd ins insAddr insLen ctxt
  | OP.VMOVDDUP -> AVXLifter.vmovddup ins insAddr insLen ctxt
  | OP.VMOVNTPS -> AVXLifter.vmovntps ins insAddr insLen ctxt
  | OP.VMOVNTPD -> AVXLifter.vmovntpd ins insAddr insLen ctxt
  | OP.VMOVHLPS -> AVXLifter.vmovhlps ins insAddr insLen ctxt
  | OP.VMOVHPD | OP.VMOVHPS -> AVXLifter.vmovhpd ins insAddr insLen ctxt
  | OP.VMOVLHPS -> AVXLifter.vmovlhps ins insAddr insLen ctxt
  | OP.VMOVLPD | OP.VMOVLPS -> AVXLifter.vmovlpd ins insAddr insLen ctxt
  | OP.VMOVMSKPD -> AVXLifter.vmovmskpd ins insAddr insLen ctxt
  | OP.VMOVMSKPS -> AVXLifter.vmovmskps ins insAddr insLen ctxt
  | OP.VMOVSD -> AVXLifter.vmovsd ins insAddr insLen ctxt
  | OP.VMOVSHDUP -> AVXLifter.vmovshdup ins insAddr insLen ctxt
  | OP.VMOVSLDUP -> AVXLifter.vmovsldup ins insAddr insLen ctxt
  | OP.VMOVSS -> AVXLifter.vmovss ins insAddr insLen ctxt
  | OP.VANDPS -> AVXLifter.vandps ins insAddr insLen ctxt
  | OP.VANDPD -> AVXLifter.vandpd ins insAddr insLen ctxt
  | OP.VANDNPS -> AVXLifter.vandnps ins insAddr insLen ctxt
  | OP.VANDNPD -> AVXLifter.vandnpd ins insAddr insLen ctxt
  | OP.VORPS -> AVXLifter.vorps ins insAddr insLen ctxt
  | OP.VORPD -> AVXLifter.vorpd ins insAddr insLen ctxt
  | OP.VSHUFI32X4 -> AVXLifter.vshufi32x4 ins insAddr insLen ctxt
  | OP.VSHUFPS -> AVXLifter.vshufps ins insAddr insLen ctxt
  | OP.VSHUFPD -> AVXLifter.vshufpd ins insAddr insLen ctxt
  | OP.VUNPCKHPS -> AVXLifter.vunpckhps ins insAddr insLen ctxt
  | OP.VUNPCKHPD -> AVXLifter.vunpckhpd ins insAddr insLen ctxt
  | OP.VUNPCKLPS -> AVXLifter.vunpcklps ins insAddr insLen ctxt
  | OP.VUNPCKLPD -> AVXLifter.vunpcklpd ins insAddr insLen ctxt
  | OP.VXORPS -> AVXLifter.vxorps ins insAddr insLen ctxt
  | OP.VXORPD -> AVXLifter.vxorpd ins insAddr insLen ctxt
  | OP.VBROADCASTI128 -> AVXLifter.vbroadcasti128 ins insAddr insLen ctxt
  | OP.VBROADCASTSS -> AVXLifter.vbroadcastss ins insAddr insLen ctxt
  | OP.VEXTRACTF32X8 -> AVXLifter.vextracti32x8 ins insAddr insLen ctxt
  | OP.VEXTRACTI64X4 -> AVXLifter.vextracti64x4 ins insAddr insLen ctxt
  | OP.VINSERTI128 -> AVXLifter.vinserti128 ins insAddr insLen ctxt
  | OP.VMPTRLD -> LiftingUtils.sideEffects insAddr insLen UnsupportedExtension
  | OP.VPADDB -> AVXLifter.vpaddb ins insAddr insLen ctxt
  | OP.VPADDD -> AVXLifter.vpaddd ins insAddr insLen ctxt
  | OP.VPADDQ -> AVXLifter.vpaddq ins insAddr insLen ctxt
  | OP.VPALIGNR -> AVXLifter.vpalignr ins insAddr insLen ctxt
  | OP.VPAND -> AVXLifter.vpand ins insAddr insLen ctxt
  | OP.VPANDN -> AVXLifter.vpandn ins insAddr insLen ctxt
  | OP.VPBROADCASTB -> AVXLifter.vpbroadcastb ins insAddr insLen ctxt
  | OP.VPBROADCASTD -> AVXLifter.vpbroadcastd ins insAddr insLen ctxt
  | OP.VPCMPEQB -> AVXLifter.vpcmpeqb ins insAddr insLen ctxt
  | OP.VPCMPEQD -> AVXLifter.vpcmpeqd ins insAddr insLen ctxt
  | OP.VPCMPEQQ -> AVXLifter.vpcmpeqq ins insAddr insLen ctxt
  | OP.VPCMPESTRI | OP.VPCMPESTRM | OP.VPCMPISTRI
  | OP.VPCMPISTRM -> SSELifter.pcmpstr ins insAddr insLen ctxt
  | OP.VPCMPGTB -> AVXLifter.vpcmpgtb ins insAddr insLen ctxt
  | OP.VPINSRD -> AVXLifter.vpinsrd ins insAddr insLen ctxt
  | OP.VPMINUB -> AVXLifter.vpminub ins insAddr insLen ctxt
  | OP.VPMINUD -> AVXLifter.vpminud ins insAddr insLen ctxt
  | OP.VPMOVMSKB -> SSELifter.pmovmskb ins insAddr insLen ctxt
  | OP.VPMULUDQ -> AVXLifter.vpmuludq ins insAddr insLen ctxt
  | OP.VPOR -> AVXLifter.vpor ins insAddr insLen ctxt
  | OP.VPSHUFB -> AVXLifter.vpshufb ins insAddr insLen ctxt
  | OP.VPSHUFD -> AVXLifter.vpshufd ins insAddr insLen ctxt
  | OP.VPSLLD -> AVXLifter.vpslld ins insAddr insLen ctxt
  | OP.VPSLLDQ -> AVXLifter.vpslldq ins insAddr insLen ctxt
  | OP.VPSLLQ -> AVXLifter.vpsllq ins insAddr insLen ctxt
  | OP.VPSRLD -> AVXLifter.vpsrld ins insAddr insLen ctxt
  | OP.VPSRLDQ -> AVXLifter.vpsrldq ins insAddr insLen ctxt
  | OP.VPSRLQ -> AVXLifter.vpsrlq ins insAddr insLen ctxt
  | OP.VPSUBB -> AVXLifter.vpsubb ins insAddr insLen ctxt
  | OP.VPTEST -> AVXLifter.vptest ins insAddr insLen ctxt
  | OP.VPUNPCKHDQ -> AVXLifter.vpunpckhdq ins insAddr insLen ctxt
  | OP.VPUNPCKHQDQ -> AVXLifter.vpunpckhqdq ins insAddr insLen ctxt
  | OP.VPUNPCKLDQ -> AVXLifter.vpunpckldq ins insAddr insLen ctxt
  | OP.VPUNPCKLQDQ -> AVXLifter.vpunpcklqdq ins insAddr insLen ctxt
  | OP.VPXOR -> AVXLifter.vpxor ins insAddr insLen ctxt
  | OP.VPXORD -> AVXLifter.vpxord ins insAddr insLen ctxt
  | OP.VZEROUPPER -> AVXLifter.vzeroupper ins insAddr insLen ctxt
  | OP.VINSERTI64X4
  | OP.VPMOVWB | OP.VMOVDQU32 | OP.VPMOVZXWD
  | OP.VPSRLW | OP.VFMADD213SS ->
    GeneralLifter.nop insAddr insLen (* FIXME: #196 *)
  | OP.VERW -> LiftingUtils.sideEffects insAddr insLen UnsupportedPrivInstr
  | OP.VFMADD132SD -> AVXLifter.vfmadd132sd ins insAddr insLen ctxt
  | OP.VFMADD213SD -> AVXLifter.vfmadd213sd ins insAddr insLen ctxt
  | OP.VFMADD231SD -> AVXLifter.vfmadd231sd ins insAddr insLen ctxt
  | OP.VBROADCASTSD | OP.VCVTDQ2PD | OP.VCVTPD2PS
  | OP.VCVTPS2PD | OP.VEXTRACTF64X2 | OP.VEXTRACTF64X4
  | OP.VFMADD132PD | OP.VFMADD213PS | OP.VFMADD231PD
  | OP.VFMSUB132SS | OP.VFMSUB231SD | OP.VFNMADD132PD
  | OP.VFNMADD231PD | OP.VFNMADD132SD | OP.VFNMADD213SD
  | OP.VFNMADD231SD | OP.VINSERTF128 | OP.VINSERTF64X4
  | OP.VMAXPS | OP.VMAXSD | OP.VMAXSS | OP.VMINSS
  | OP.VPERMI2D | OP.VPERMI2PD | OP.VPERMI2W | OP.VPMOVWB
  | OP.VPTERNLOGD | OP.VCMPPD | OP.VCMPPS | OP.VGATHERDPS
  | OP.VPGATHERDD | OP.VMOVDQU8 ->
    GeneralLifter.nop insAddr insLen (* FIXME: #196 !211 *)
  | OP.FLD -> X87Lifter.fld ins insAddr insLen ctxt
  | OP.FST -> X87Lifter.ffst ins insAddr insLen ctxt false
  | OP.FSTP -> X87Lifter.ffst ins insAddr insLen ctxt true
  | OP.FILD -> X87Lifter.fild ins insAddr insLen ctxt
  | OP.FIST -> X87Lifter.fist ins insAddr insLen ctxt false
  | OP.FISTP -> X87Lifter.fist ins insAddr insLen ctxt true
  | OP.FISTTP -> X87Lifter.fisttp ins insAddr insLen ctxt (* SSE3 *)
  | OP.FBLD -> X87Lifter.fbld ins insAddr insLen ctxt
  | OP.FBSTP -> X87Lifter.fbstp ins insAddr insLen ctxt
  | OP.FXCH -> X87Lifter.fxch ins insAddr insLen ctxt
  | OP.FCMOVE -> X87Lifter.fcmove ins insAddr insLen ctxt
  | OP.FCMOVNE -> X87Lifter.fcmovne ins insAddr insLen ctxt
  | OP.FCMOVB -> X87Lifter.fcmovb ins insAddr insLen ctxt
  | OP.FCMOVBE -> X87Lifter.fcmovbe ins insAddr insLen ctxt
  | OP.FCMOVNB -> X87Lifter.fcmovnb ins insAddr insLen ctxt
  | OP.FCMOVNBE -> X87Lifter.fcmovnbe ins insAddr insLen ctxt
  | OP.FCMOVU -> X87Lifter.fcmovu ins insAddr insLen ctxt
  | OP.FCMOVNU -> X87Lifter.fcmovnu ins insAddr insLen ctxt
  | OP.FADD -> X87Lifter.fpuadd ins insAddr insLen ctxt false
  | OP.FADDP -> X87Lifter.fpuadd ins insAddr insLen ctxt true
  | OP.FIADD -> X87Lifter.fiadd ins insAddr insLen ctxt
  | OP.FSUB -> X87Lifter.fpusub ins insAddr insLen ctxt false
  | OP.FSUBP -> X87Lifter.fpusub ins insAddr insLen ctxt true
  | OP.FISUB -> X87Lifter.fisub ins insAddr insLen ctxt
  | OP.FSUBR -> X87Lifter.fsubr ins insAddr insLen ctxt false
  | OP.FSUBRP -> X87Lifter.fsubr ins insAddr insLen ctxt true
  | OP.FISUBR  -> X87Lifter.fisubr ins insAddr insLen ctxt
  | OP.FMUL -> X87Lifter.fpumul ins insAddr insLen ctxt false
  | OP.FMULP -> X87Lifter.fpumul ins insAddr insLen ctxt true
  | OP.FIMUL -> X87Lifter.fimul ins insAddr insLen ctxt
  | OP.FDIV -> X87Lifter.fpudiv ins insAddr insLen ctxt false
  | OP.FDIVP -> X87Lifter.fpudiv ins insAddr insLen ctxt true
  | OP.FIDIV -> X87Lifter.fidiv ins insAddr insLen ctxt
  | OP.FDIVR -> X87Lifter.fdivr ins insAddr insLen ctxt false
  | OP.FDIVRP -> X87Lifter.fdivr  ins insAddr insLen ctxt true
  | OP.FIDIVR -> X87Lifter.fidivr ins insAddr insLen ctxt
  | OP.FPREM -> X87Lifter.fprem ins insAddr insLen ctxt false
  | OP.FPREM1 -> X87Lifter.fprem ins insAddr insLen ctxt true
  | OP.FABS -> X87Lifter.fabs ins insAddr insLen ctxt
  | OP.FCHS -> X87Lifter.fchs ins insAddr insLen ctxt
  | OP.FRNDINT -> X87Lifter.frndint ins insAddr insLen ctxt
  | OP.FSCALE -> X87Lifter.fscale ins insAddr insLen ctxt
  | OP.FSQRT -> X87Lifter.fsqrt ins insAddr insLen ctxt
  | OP.FXTRACT -> X87Lifter.fxtract ins insAddr insLen ctxt
  | OP.FCOM -> X87Lifter.fcom ins insAddr insLen ctxt 0 false
  | OP.FCOMP -> X87Lifter.fcom ins insAddr insLen ctxt 1 false
  | OP.FCOMPP -> X87Lifter.fcom ins insAddr insLen ctxt 2 false
  | OP.FUCOM -> X87Lifter.fcom ins insAddr insLen ctxt 0 true
  | OP.FUCOMP -> X87Lifter.fcom ins insAddr insLen ctxt 1 true
  | OP.FUCOMPP -> X87Lifter.fcom ins insAddr insLen ctxt 2 true
  | OP.FICOM -> X87Lifter.ficom ins insAddr insLen ctxt false
  | OP.FICOMP -> X87Lifter.ficom ins insAddr insLen ctxt true
  | OP.FCOMI -> X87Lifter.fcomi ins insAddr insLen ctxt false
  | OP.FUCOMI -> X87Lifter.fcomi ins insAddr insLen ctxt false
  | OP.FCOMIP -> X87Lifter.fcomi ins insAddr insLen ctxt true
  | OP.FUCOMIP -> X87Lifter.fcomi ins insAddr insLen ctxt true
  | OP.FTST -> X87Lifter.ftst ins insAddr insLen ctxt
  | OP.FXAM -> X87Lifter.fxam ins insAddr insLen ctxt
  | OP.FSIN -> X87Lifter.fsin ins insAddr insLen ctxt
  | OP.FCOS -> X87Lifter.fcos ins insAddr insLen ctxt
  | OP.FSINCOS -> X87Lifter.fsincos ins insAddr insLen ctxt
  | OP.FPTAN -> X87Lifter.fptan ins insAddr insLen ctxt
  | OP.FPATAN -> X87Lifter.fpatan ins insAddr insLen ctxt
  | OP.F2XM1 -> X87Lifter.f2xm1 ins insAddr insLen ctxt
  | OP.FYL2X -> X87Lifter.fyl2x ins insAddr insLen ctxt
  | OP.FYL2XP1 -> X87Lifter.fyl2xp1 ins insAddr insLen ctxt
  | OP.FLD1 -> X87Lifter.fld1 ins insAddr insLen ctxt
  | OP.FLDZ -> X87Lifter.fldz ins insAddr insLen ctxt
  | OP.FLDPI -> X87Lifter.fldpi ins insAddr insLen ctxt
  | OP.FLDL2E -> X87Lifter.fldl2e ins insAddr insLen ctxt
  | OP.FLDLN2 -> X87Lifter.fldln2 ins insAddr insLen ctxt
  | OP.FLDL2T -> X87Lifter.fldl2t ins insAddr insLen ctxt
  | OP.FLDLG2 -> X87Lifter.fldlg2 ins insAddr insLen ctxt
  | OP.FINCSTP -> X87Lifter.fincstp ins insAddr insLen ctxt
  | OP.FDECSTP -> X87Lifter.fdecstp ins insAddr insLen ctxt
  | OP.FFREE -> X87Lifter.ffree ins insAddr insLen ctxt
  | OP.FINIT -> X87Lifter.finit ins insAddr insLen ctxt
  | OP.FNINIT -> X87Lifter.fninit ins insAddr insLen ctxt
  | OP.FCLEX -> X87Lifter.fclex ins insAddr insLen ctxt
  | OP.FSTCW -> X87Lifter.fstcw ins insAddr insLen ctxt
  | OP.FNSTCW -> X87Lifter.fnstcw ins insAddr insLen ctxt
  | OP.FLDCW -> X87Lifter.fldcw ins insAddr insLen ctxt
  | OP.FSTENV -> X87Lifter.fstenv ins insAddr insLen ctxt
  | OP.FLDENV -> X87Lifter.fldenv ins insAddr insLen ctxt
  | OP.FSAVE -> X87Lifter.fsave ins insAddr insLen ctxt
  | OP.FRSTOR -> X87Lifter.frstor ins insAddr insLen ctxt
  | OP.FSTSW -> X87Lifter.fstsw ins insAddr insLen ctxt
  | OP.FNSTSW -> X87Lifter.fnstsw ins insAddr insLen ctxt
  | OP.WAIT -> X87Lifter.wait ins insAddr insLen ctxt
  | OP.FNOP -> X87Lifter.fnop ins insAddr insLen ctxt
  | OP.FXSAVE | OP.FXSAVE64 -> X87Lifter.fxsave ins insAddr insLen ctxt
  | OP.FXRSTOR | OP.FXRSTOR64 -> X87Lifter.fxrstor ins insAddr insLen ctxt
  | o ->
#if DEBUG
         eprintfn "%A" o
         eprintfn "%A" ins
#endif
         raise <| NotImplementedIRException (Disasm.opCodeToString o)
  |> fun builder -> builder.ToStmts ()

// vim: set tw=80 sts=2 sw=2:
