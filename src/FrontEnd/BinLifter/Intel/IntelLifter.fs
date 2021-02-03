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
let translate (ins: InsInfo) insLen ctxt =
  match ins.Opcode with
  | OP.AAA -> GeneralLifter.aaa insLen ctxt
  | OP.AAD -> GeneralLifter.aad ins insLen ctxt
  | OP.AAM -> GeneralLifter.aam ins insLen ctxt
  | OP.AAS -> GeneralLifter.aas insLen ctxt
  | OP.ADC -> GeneralLifter.adc ins insLen ctxt
  | OP.ADD -> GeneralLifter.add ins insLen ctxt
  | OP.AND -> GeneralLifter.``and`` ins insLen ctxt
  | OP.ANDN
  | OP.ARPL -> GeneralLifter.arpl ins insLen ctxt
  | OP.BNDMOV -> GeneralLifter.bndmov ins insLen ctxt
  | OP.BOUND -> GeneralLifter.nop insLen
  | OP.BSF -> GeneralLifter.bsf ins insLen ctxt
  | OP.BSR -> GeneralLifter.bsr ins insLen ctxt
  | OP.BSWAP -> GeneralLifter.bswap ins insLen ctxt
  | OP.BT -> GeneralLifter.bt ins insLen ctxt
  | OP.BTC -> GeneralLifter.btc ins insLen ctxt
  | OP.BTR -> GeneralLifter.btr ins insLen ctxt
  | OP.BTS -> GeneralLifter.bts ins insLen ctxt
  | OP.CALLNear -> GeneralLifter.call ins insLen ctxt
  | OP.CALLFar -> LiftingUtils.sideEffects insLen UnsupportedFAR
  | OP.CBW | OP.CWDE | OP.CDQE ->
    GeneralLifter.convBWQ ins insLen ctxt
  | OP.CLC -> GeneralLifter.clearFlag insLen ctxt R.CF
  | OP.CLD -> GeneralLifter.clearFlag insLen ctxt R.DF
  | OP.CLI -> GeneralLifter.clearFlag insLen ctxt R.IF
  | OP.CLRSSBSY -> GeneralLifter.nop insLen
  | OP.CLTS -> LiftingUtils.sideEffects insLen UnsupportedPrivInstr
  | OP.CMC -> GeneralLifter.cmc ins insLen ctxt
  | OP.CMOVO | OP.CMOVNO | OP.CMOVB | OP.CMOVAE
  | OP.CMOVZ | OP.CMOVNZ | OP.CMOVBE | OP.CMOVA
  | OP.CMOVS  | OP.CMOVNS | OP.CMOVP | OP.CMOVNP
  | OP.CMOVL | OP.CMOVGE | OP.CMOVLE | OP.CMOVG ->
    GeneralLifter.cmovcc ins insLen ctxt
  | OP.CMP -> GeneralLifter.cmp ins insLen ctxt
  | OP.CMPSB | OP.CMPSW | OP.CMPSQ ->
    GeneralLifter.cmps ins insLen ctxt
  | OP.CMPXCHG -> GeneralLifter.cmpxchg ins insLen ctxt
  | OP.CMPXCHG8B | OP.CMPXCHG16B ->
    GeneralLifter.compareExchangeBytes ins insLen ctxt
  | OP.CPUID -> LiftingUtils.sideEffects insLen ProcessorID
  | OP.CRC32 -> GeneralLifter.nop insLen
  | OP.CWD | OP.CDQ | OP.CQO ->
    GeneralLifter.convWDQ ins insLen ctxt
  | OP.DAA -> GeneralLifter.daa insLen ctxt
  | OP.DAS -> GeneralLifter.das insLen ctxt
  | OP.DEC -> GeneralLifter.dec ins insLen ctxt
  | OP.DIV | OP.IDIV -> GeneralLifter.div ins insLen ctxt
  | OP.ENDBR32 | OP.ENDBR64 -> GeneralLifter.nop insLen
  | OP.ENTER -> GeneralLifter.enter ins insLen ctxt
  | OP.HLT -> LiftingUtils.sideEffects insLen Halt
  | OP.IMUL -> GeneralLifter.imul ins insLen ctxt
  | OP.INC -> GeneralLifter.inc ins insLen ctxt
  | OP.INCSSPD | OP.INCSSPQ -> GeneralLifter.nop insLen
  | OP.INSB | OP.INSW | OP.INSD ->
    GeneralLifter.insinstr ins insLen ctxt
  | OP.INT | OP.INTO -> GeneralLifter.interrupt ins insLen ctxt
  | OP.INT3 -> LiftingUtils.sideEffects insLen Breakpoint
  | OP.JMPFar | OP.JMPNear -> GeneralLifter.jmp ins insLen ctxt
  | OP.JO | OP.JNO | OP.JB | OP.JNB
  | OP.JZ | OP.JNZ | OP.JBE | OP.JA
  | OP.JS | OP.JNS | OP.JP | OP.JNP
  | OP.JL | OP.JNL | OP.JLE | OP.JG
  | OP.JECXZ | OP.JRCXZ -> GeneralLifter.jcc ins insLen ctxt
  | OP.LAHF -> LiftingUtils.sideEffects insLen ProcessorID
  | OP.LEA -> GeneralLifter.lea ins insLen ctxt
  | OP.LEAVE -> GeneralLifter.leave ins insLen ctxt
  | OP.LODSB | OP.LODSW | OP.LODSD | OP.LODSQ ->
    GeneralLifter.lods ins insLen ctxt
  | OP.LOOP | OP.LOOPE | OP.LOOPNE ->
    GeneralLifter.loop ins insLen ctxt
  | OP.LZCNT -> GeneralLifter.lzcnt ins insLen ctxt
  | OP.LDS | OP.LES | OP.LFS | OP.LGS | OP.LSS ->
    LiftingUtils.sideEffects insLen UnsupportedFAR
  | OP.MOV -> GeneralLifter.mov ins insLen ctxt
  | OP.MOVBE -> GeneralLifter.movbe ins insLen ctxt
  | OP.MOVSB | OP.MOVSW | OP.MOVSQ ->
    GeneralLifter.movs ins insLen ctxt
  | OP.MOVSX | OP.MOVSXD -> GeneralLifter.movsx ins insLen ctxt
  | OP.MOVZX -> GeneralLifter.movzx ins insLen ctxt
  | OP.MUL -> GeneralLifter.mul ins insLen ctxt
  | OP.NEG -> GeneralLifter.neg ins insLen ctxt
  | OP.NOP -> GeneralLifter.nop insLen
  | OP.NOT -> GeneralLifter.not ins insLen ctxt
  | OP.OR -> GeneralLifter.logOr ins insLen ctxt
  | OP.OUTSB | OP.OUTSW | OP.OUTSD ->
    GeneralLifter.outs ins insLen ctxt
  | OP.POP -> GeneralLifter.pop ins insLen ctxt
  | OP.POPA -> GeneralLifter.popa insLen ctxt 16<rt>
  | OP.POPAD -> GeneralLifter.popa insLen ctxt 32<rt>
  | OP.POPCNT -> GeneralLifter.popcnt ins insLen ctxt
  | OP.POPF | OP.POPFD | OP.POPFQ ->
    GeneralLifter.popf ins insLen ctxt
  | OP.PUSH -> GeneralLifter.push ins insLen ctxt
  | OP.PUSHA -> GeneralLifter.pusha ins insLen ctxt 16<rt>
  | OP.PUSHAD -> GeneralLifter.pusha ins insLen ctxt 32<rt>
  | OP.PUSHF | OP.PUSHFD | OP.PUSHFQ ->
    GeneralLifter.pushf ins insLen ctxt
  | OP.RCL -> GeneralLifter.rcl ins insLen ctxt
  | OP.RCR -> GeneralLifter.rcr ins insLen ctxt
  | OP.RDMSR | OP.RSM ->
    LiftingUtils.sideEffects insLen UnsupportedExtension
  | OP.RDPKRU -> GeneralLifter.rdpkru ins insLen ctxt
  | OP.RDPMC -> LiftingUtils.sideEffects insLen UnsupportedExtension
  | OP.RDRAND -> LiftingUtils.sideEffects insLen UnsupportedExtension
  | OP.RDSSPD | OP.RDSSPQ -> GeneralLifter.nop insLen
  | OP.RDTSC -> LiftingUtils.sideEffects insLen ClockCounter
  | OP.RDTSCP -> LiftingUtils.sideEffects insLen ClockCounter
  | OP.RETNear -> GeneralLifter.ret ins insLen ctxt
  | OP.RETNearImm -> GeneralLifter.retWithImm ins insLen ctxt
  | OP.RETFar -> LiftingUtils.sideEffects insLen UnsupportedFAR
  | OP.RETFarImm -> LiftingUtils.sideEffects insLen UnsupportedFAR
  | OP.ROL -> GeneralLifter.rol ins insLen ctxt
  | OP.ROR -> GeneralLifter.ror ins insLen ctxt
  | OP.RORX -> GeneralLifter.rorx ins insLen ctxt
  | OP.RSTORSSP -> GeneralLifter.nop insLen
  | OP.SAHF -> GeneralLifter.sahf ins insLen ctxt
  | OP.SAR | OP.SHR | OP.SHL ->
    GeneralLifter.shift ins insLen ctxt
  | OP.SAVEPREVSSP -> GeneralLifter.nop insLen
  | OP.SBB -> GeneralLifter.sbb ins insLen ctxt
  | OP.SCASB | OP.SCASW | OP.SCASD | OP.SCASQ ->
    GeneralLifter.scas ins insLen ctxt
  | OP.SETO | OP.SETNO | OP.SETB | OP.SETNB
  | OP.SETZ | OP.SETNZ | OP.SETBE | OP.SETA
  | OP.SETS | OP.SETNS | OP.SETP | OP.SETNP
  | OP.SETL | OP.SETNL | OP.SETLE | OP.SETG ->
    GeneralLifter.setcc ins insLen ctxt
  | OP.SETSSBSY -> GeneralLifter.nop insLen
  | OP.SHLD -> GeneralLifter.shld ins insLen ctxt
  | OP.SHLX -> GeneralLifter.shlx ins insLen ctxt
  | OP.SHRD -> GeneralLifter.shrd ins insLen ctxt
  | OP.STC -> GeneralLifter.stc insLen ctxt
  | OP.STD -> GeneralLifter.std insLen ctxt
  | OP.STI -> GeneralLifter.sti insLen ctxt
  | OP.STOSB | OP.STOSW | OP.STOSD | OP.STOSQ ->
    GeneralLifter.stos ins insLen ctxt
  | OP.SUB -> GeneralLifter.sub ins insLen ctxt
  | OP.SYSCALL | OP.SYSENTER -> LiftingUtils.sideEffects insLen SysCall
  | OP.SYSEXIT | OP.SYSRET ->
    LiftingUtils.sideEffects insLen UnsupportedPrivInstr
  | OP.TEST -> GeneralLifter.test ins insLen ctxt
  | OP.TZCNT -> GeneralLifter.tzcnt ins insLen ctxt
  | OP.UD2 -> LiftingUtils.sideEffects insLen UndefinedInstr
  | OP.WBINVD -> LiftingUtils.sideEffects insLen UnsupportedPrivInstr
  | OP.WRFSBASE -> GeneralLifter.wrfsbase ins insLen ctxt
  | OP.WRGSBASE -> GeneralLifter.wrgsbase ins insLen ctxt
  | OP.WRPKRU -> GeneralLifter.wrpkru ins insLen ctxt
  | OP.WRMSR -> LiftingUtils.sideEffects insLen UnsupportedPrivInstr
  | OP.WRSSD | OP.WRSSQ -> GeneralLifter.nop insLen
  | OP.WRUSSD | OP.WRUSSQ -> GeneralLifter.nop insLen
  | OP.XABORT -> LiftingUtils.sideEffects insLen UnsupportedExtension
  | OP.XADD -> GeneralLifter.xadd ins insLen ctxt
  | OP.XBEGIN -> LiftingUtils.sideEffects insLen UnsupportedExtension
  | OP.XCHG -> GeneralLifter.xchg ins insLen ctxt
  | OP.XEND -> LiftingUtils.sideEffects insLen UnsupportedExtension
  | OP.XGETBV -> LiftingUtils.sideEffects insLen UnsupportedExtension
  | OP.XLATB -> GeneralLifter.xlatb ins insLen ctxt
  | OP.XOR -> GeneralLifter.xor ins insLen ctxt
  | OP.XRSTOR | OP.XRSTORS | OP.XSAVE | OP.XSAVEC
  | OP.XSAVEC64 | OP.XSAVEOPT | OP.XSAVES | OP.XSAVES64 ->
    LiftingUtils.sideEffects insLen UnsupportedExtension
  | OP.XTEST -> LiftingUtils.sideEffects insLen UnsupportedExtension
  | OP.IN | OP.INVD | OP.INVLPG | OP.IRET | OP.IRETQ | OP.IRETW | OP.IRETD
  | OP.LAR | OP.LGDT | OP.LIDT | OP.LLDT
  | OP.LMSW | OP.LSL | OP.LTR | OP.OUT | OP.SGDT
  | OP.SIDT | OP.SLDT | OP.SMSW | OP.STR | OP.VERR ->
    LiftingUtils.sideEffects insLen UnsupportedPrivInstr
  | OP.MOVD -> MMXLifter.movd ins insLen ctxt
  | OP.MOVQ -> MMXLifter.movq ins insLen ctxt
  | OP.PACKSSDW -> MMXLifter.packssdw ins insLen ctxt
  | OP.PACKSSWB -> MMXLifter.packsswb ins insLen ctxt
  | OP.PACKUSWB -> MMXLifter.packuswb ins insLen ctxt
  | OP.PUNPCKHBW -> MMXLifter.punpckhbw ins insLen ctxt
  | OP.PUNPCKHWD -> MMXLifter.punpckhwd ins insLen ctxt
  | OP.PUNPCKHDQ -> MMXLifter.punpckhdq ins insLen ctxt
  | OP.PUNPCKLBW -> MMXLifter.punpcklbw ins insLen ctxt
  | OP.PUNPCKLWD -> MMXLifter.punpcklwd ins insLen ctxt
  | OP.PUNPCKLDQ -> MMXLifter.punpckldq ins insLen ctxt
  | OP.PADDB -> MMXLifter.paddb ins insLen ctxt
  | OP.PADDW -> MMXLifter.paddw ins insLen ctxt
  | OP.PADDD -> MMXLifter.paddd ins insLen ctxt
  | OP.PADDSB -> MMXLifter.paddsb ins insLen ctxt
  | OP.PADDSW -> MMXLifter.paddsw ins insLen ctxt
  | OP.PADDUSB -> MMXLifter.paddusb ins insLen ctxt
  | OP.PADDUSW -> MMXLifter.paddusw ins insLen ctxt
  | OP.PSUBB -> MMXLifter.psubb ins insLen ctxt
  | OP.PSUBW -> MMXLifter.psubw ins insLen ctxt
  | OP.PSUBD -> MMXLifter.psubd ins insLen ctxt
  | OP.PSUBSB -> MMXLifter.psubsb ins insLen ctxt
  | OP.PSUBSW -> MMXLifter.psubsw ins insLen ctxt
  | OP.PSUBUSB -> MMXLifter.psubusb ins insLen ctxt
  | OP.PSUBUSW -> MMXLifter.psubusw ins insLen ctxt
  | OP.PMULHW -> MMXLifter.pmulhw ins insLen ctxt
  | OP.PMULLW -> MMXLifter.pmullw ins insLen ctxt
  | OP.PMADDWD -> MMXLifter.pmaddwd ins insLen ctxt
  | OP.PCMPEQB -> MMXLifter.pcmpeqb ins insLen ctxt
  | OP.PCMPEQW -> MMXLifter.pcmpeqw ins insLen ctxt
  | OP.PCMPEQD -> MMXLifter.pcmpeqd ins insLen ctxt
  | OP.PCMPGTB -> MMXLifter.pcmpgtb ins insLen ctxt
  | OP.PCMPGTW -> MMXLifter.pcmpgtw ins insLen ctxt
  | OP.PCMPGTD -> MMXLifter.pcmpgtd ins insLen ctxt
  | OP.PAND -> MMXLifter.pand ins insLen ctxt
  | OP.PANDN -> MMXLifter.pandn ins insLen ctxt
  | OP.POR -> MMXLifter.por ins insLen ctxt
  | OP.PXOR -> MMXLifter.pxor ins insLen ctxt
  | OP.PSLLW -> MMXLifter.psllw ins insLen ctxt
  | OP.PSLLD -> MMXLifter.pslld ins insLen ctxt
  | OP.PSLLQ -> MMXLifter.psllq ins insLen ctxt
  | OP.PSRLW -> MMXLifter.psrlw ins insLen ctxt
  | OP.PSRLD -> MMXLifter.psrld ins insLen ctxt
  | OP.PSRLQ -> MMXLifter.psrlq ins insLen ctxt
  | OP.PSRAW -> MMXLifter.psraw ins insLen ctxt
  | OP.PSRAD -> MMXLifter.psrad ins insLen ctxt
  | OP.EMMS -> MMXLifter.emms ins insLen ctxt
  | OP.MOVAPS -> SSELifter.movaps ins insLen ctxt
  | OP.MOVAPD -> SSELifter.movapd ins insLen ctxt (* SSE2 *)
  | OP.MOVUPS -> SSELifter.movups ins insLen ctxt
  | OP.MOVUPD -> SSELifter.movupd ins insLen ctxt (* SSE2 *)
  | OP.MOVHPS -> SSELifter.movhps ins insLen ctxt
  | OP.MOVHPD -> SSELifter.movhpd ins insLen ctxt (* SSE2 *)
  | OP.MOVHLPS -> SSELifter.movhlps ins insLen ctxt
  | OP.MOVLPS -> SSELifter.movlps ins insLen ctxt
  | OP.MOVLPD -> SSELifter.movlpd ins insLen ctxt (* SSE2 *)
  | OP.MOVLHPS -> SSELifter.movlhps ins insLen ctxt
  | OP.MOVMSKPS -> SSELifter.movmskps ins insLen ctxt
  | OP.MOVMSKPD -> SSELifter.movmskpd ins insLen ctxt (* SSE2 *)
  | OP.MOVSS -> SSELifter.movss ins insLen ctxt
  | OP.MOVSD -> SSELifter.movsd ins insLen ctxt (* SSE2 *)
  | OP.ADDPS -> SSELifter.addps ins insLen ctxt
  | OP.ADDPD -> SSELifter.addpd ins insLen ctxt (* SSE2 *)
  | OP.ADDSS -> SSELifter.addss ins insLen ctxt
  | OP.ADDSD -> SSELifter.addsd ins insLen ctxt (* SSE2 *)
  | OP.SUBPS -> SSELifter.subps ins insLen ctxt
  | OP.SUBPD -> SSELifter.subpd ins insLen ctxt (* SSE2 *)
  | OP.SUBSS -> SSELifter.subss ins insLen ctxt
  | OP.SUBSD -> SSELifter.subsd ins insLen ctxt (* SSE2 *)
  | OP.MULPS -> SSELifter.mulps ins insLen ctxt
  | OP.MULPD -> SSELifter.mulpd ins insLen ctxt (* SSE2 *)
  | OP.MULSS -> SSELifter.mulss ins insLen ctxt
  | OP.MULSD -> SSELifter.mulsd ins insLen ctxt (* SSE2 *)
  | OP.DIVPS -> SSELifter.divps ins insLen ctxt
  | OP.DIVPD -> SSELifter.divpd ins insLen ctxt (* SSE2 *)
  | OP.DIVSS -> SSELifter.divss ins insLen ctxt
  | OP.DIVSD -> SSELifter.divsd ins insLen ctxt (* SSE2 *)
  | OP.RCPPS -> SSELifter.rcpps ins insLen ctxt
  | OP.RCPSS -> SSELifter.rcpss ins insLen ctxt
  | OP.SQRTPS -> SSELifter.sqrtps ins insLen ctxt
  | OP.SQRTPD -> SSELifter.sqrtpd ins insLen ctxt (* SSE2 *)
  | OP.SQRTSS -> SSELifter.sqrtss ins insLen ctxt
  | OP.SQRTSD -> SSELifter.sqrtsd ins insLen ctxt (* SSE2 *)
  | OP.RSQRTPS -> SSELifter.rsqrtps ins insLen ctxt
  | OP.RSQRTSS -> SSELifter.rsqrtss ins insLen ctxt
  | OP.MAXPS -> SSELifter.maxps ins insLen ctxt
  | OP.MAXPD -> SSELifter.maxpd ins insLen ctxt (* SSE2 *)
  | OP.MAXSS -> SSELifter.maxss ins insLen ctxt
  | OP.MAXSD -> SSELifter.maxsd ins insLen ctxt (* SSE2 *)
  | OP.MINPS -> SSELifter.minps ins insLen ctxt
  | OP.MINPD -> SSELifter.minpd ins insLen ctxt (* SSE2 *)
  | OP.MINSS -> SSELifter.minss ins insLen ctxt
  | OP.MINSD -> SSELifter.minsd ins insLen ctxt (* SSE2 *)
  | OP.CMPPS -> SSELifter.cmpps ins insLen ctxt
  | OP.CMPPD -> SSELifter.cmppd ins insLen ctxt (* SSE2 *)
  | OP.CMPSS -> SSELifter.cmpss ins insLen ctxt
  | OP.CMPSD -> SSELifter.cmpsd ins insLen ctxt (* SSE2 *)
  | OP.COMISS | OP.VCOMISS ->
    SSELifter.comiss ins insLen ctxt
  | OP.COMISD | OP.VCOMISD -> (* SSE2 *)
    SSELifter.comisd ins insLen ctxt
  | OP.UCOMISS | OP.VUCOMISS ->
    SSELifter.ucomiss ins insLen ctxt
  | OP.UCOMISD | OP.VUCOMISD -> (* SSE2 *)
    SSELifter.ucomisd ins insLen ctxt
  | OP.ANDPS -> SSELifter.andps ins insLen ctxt
  | OP.ANDPD -> SSELifter.andpd ins insLen ctxt (* SSE2 *)
  | OP.ANDNPS -> SSELifter.andnps ins insLen ctxt
  | OP.ANDNPD -> SSELifter.andnpd ins insLen ctxt (* SSE2 *)
  | OP.ORPS -> SSELifter.orps ins insLen ctxt
  | OP.ORPD -> SSELifter.orpd ins insLen ctxt (* SSE2 *)
  | OP.XORPS -> SSELifter.xorps ins insLen ctxt
  | OP.XORPD -> SSELifter.xorpd ins insLen ctxt (* SSE2 *)
  | OP.XSETBV -> LiftingUtils.sideEffects insLen UnsupportedPrivInstr
  | OP.SHUFPS -> SSELifter.shufps ins insLen ctxt
  | OP.SHUFPD -> SSELifter.shufpd ins insLen ctxt (* SSE2 *)
  | OP.UNPCKHPS -> SSELifter.unpckhps ins insLen ctxt
  | OP.UNPCKHPD -> SSELifter.unpckhpd ins insLen ctxt (* SSE2 *)
  | OP.UNPCKLPS -> SSELifter.unpcklps ins insLen ctxt
  | OP.UNPCKLPD -> SSELifter.unpcklpd ins insLen ctxt (* SSE2 *)
  | OP.CVTPI2PS -> SSELifter.cvtpi2ps ins insLen ctxt
  | OP.CVTPI2PD -> SSELifter.cvtpi2pd ins insLen ctxt (* SSE2 *)
  | OP.CVTSI2SS -> SSELifter.cvtsi2ss ins insLen ctxt
  | OP.CVTSI2SD -> SSELifter.cvtsi2sd ins insLen ctxt (* SSE2 *)
  | OP.CVTPS2PI -> SSELifter.cvtps2pi ins insLen ctxt true
  | OP.CVTPS2PD -> SSELifter.cvtps2pd ins insLen ctxt (* SSE2 *)
  | OP.CVTPD2PS -> SSELifter.cvtpd2ps ins insLen ctxt (* SSE2 *)
  | OP.CVTPD2PI -> SSELifter.cvtpd2pi ins insLen ctxt true (* SSE2 *)
  | OP.CVTPD2DQ -> SSELifter.cvtpd2dq ins insLen ctxt true (* SSE2 *)
  | OP.CVTTPD2DQ -> SSELifter.cvtpd2dq ins insLen ctxt false (* SSE2 *)
  | OP.CVTDQ2PS -> SSELifter.cvtdq2ps ins insLen ctxt (* SSE2 *)
  | OP.CVTDQ2PD -> SSELifter.cvtdq2pd ins insLen ctxt (* SSE2 *)
  | OP.CVTPS2DQ -> SSELifter.cvtps2dq ins insLen ctxt true (* SSE2 *)
  | OP.CVTTPS2DQ -> SSELifter.cvtps2dq ins insLen ctxt false (* SSE2 *)
  | OP.CVTTPS2PI -> SSELifter.cvtps2pi ins insLen ctxt false
  | OP.CVTTPD2PI -> SSELifter.cvtpd2pi ins insLen ctxt false (* SSE2 *)
  | OP.CVTSS2SI | OP.VCVTSS2SI ->
    SSELifter.cvtss2si ins insLen ctxt true
  | OP.CVTSS2SD -> SSELifter.cvtss2sd ins insLen ctxt (* SSE2 *)
  | OP.CVTSD2SS -> SSELifter.cvtsd2ss ins insLen ctxt (* SSE2 *)
  | OP.CVTSD2SI | OP.VCVTSD2SI -> (* SSE2 *)
    SSELifter.cvtsd2si ins insLen ctxt true
  | OP.CVTTSS2SI | OP.VCVTTSS2SI ->
    SSELifter.cvtss2si ins insLen ctxt false
  | OP.CVTTSD2SI | OP.VCVTTSD2SI -> (* SSE2 *)
    SSELifter.cvtsd2si ins insLen ctxt false
  | OP.LDMXCSR -> SSELifter.ldmxcsr ins insLen ctxt
  | OP.STMXCSR -> SSELifter.stmxcsr ins insLen ctxt
  | OP.PAVGB -> SSELifter.pavgb ins insLen ctxt
  | OP.PAVGW -> SSELifter.pavgw ins insLen ctxt
  | OP.PEXTRW -> SSELifter.pextrw ins insLen ctxt
  | OP.PINSRW -> SSELifter.pinsrw ins insLen ctxt
  | OP.PMAXUB -> SSELifter.pmaxub ins insLen ctxt
  | OP.PMAXSW -> SSELifter.pmaxsw ins insLen ctxt
  | OP.PMAXSB -> SSELifter.pmaxsb ins insLen ctxt (* SSE4 *)
  | OP.PMINUB -> SSELifter.pminub ins insLen ctxt
  | OP.PMINSW -> SSELifter.pminsw ins insLen ctxt
  | OP.PMINUD -> SSELifter.pminud ins insLen ctxt (* SSE4 *)
  | OP.PMINSB -> SSELifter.pminsb ins insLen ctxt (* SSE4 *)
  | OP.PMOVMSKB -> SSELifter.pmovmskb ins insLen ctxt
  | OP.PMULHUW -> SSELifter.pmulhuw ins insLen ctxt
  | OP.PSADBW -> SSELifter.psadbw ins insLen ctxt
  | OP.PSHUFW -> SSELifter.pshufw ins insLen ctxt
  | OP.PSHUFD -> SSELifter.pshufd ins insLen ctxt (* SSE2 *)
  | OP.PSHUFLW -> SSELifter.pshuflw ins insLen ctxt (* SSE2 *)
  | OP.PSHUFHW -> SSELifter.pshufhw ins insLen ctxt (* SSE2 *)
  | OP.PSHUFB -> SSELifter.pshufb ins insLen ctxt (* SSE3 *)
  | OP.MOVDQA -> SSELifter.movdqa ins insLen ctxt (* SSE2 *)
  | OP.MOVDQU -> SSELifter.movdqu ins insLen ctxt (* SSE2 *)
  | OP.MOVQ2DQ -> SSELifter.movq2dq ins insLen ctxt (* SSE2 *)
  | OP.MOVDQ2Q -> SSELifter.movdq2q ins insLen ctxt (* SSE2 *)
  | OP.PMULUDQ -> SSELifter.pmuludq ins insLen ctxt (* SSE2 *)
  | OP.PADDQ -> SSELifter.paddq ins insLen ctxt (* SSE2 *)
  | OP.PSUBQ -> SSELifter.psubq ins insLen ctxt (* SSE2 *)
  | OP.PSLLDQ -> SSELifter.pslldq ins insLen ctxt (* SSE2 *)
  | OP.PSRLDQ -> SSELifter.psrldq ins insLen ctxt (* SSE2 *)
  | OP.PUNPCKHQDQ -> SSELifter.punpckhqdq ins insLen ctxt (* SSE2 *)
  | OP.PUNPCKLQDQ -> SSELifter.punpcklqdq ins insLen ctxt (* SSE2 *)
  | OP.MOVNTQ -> SSELifter.movntq ins insLen ctxt
  | OP.MOVNTPS -> SSELifter.movntps ins insLen ctxt
  | OP.PREFETCHNTA
  | OP.PREFETCHT0 | OP.PREFETCHT1
  | OP.PREFETCHW | OP.PREFETCHT2 -> GeneralLifter.nop insLen
  | OP.SFENCE -> LiftingUtils.sideEffects insLen Fence
  | OP.CLFLUSH -> GeneralLifter.nop insLen (* SSE2 *)
  | OP.LFENCE -> LiftingUtils.sideEffects insLen Fence (* SSE2 *)
  | OP.MFENCE -> LiftingUtils.sideEffects insLen Fence (* SSE2 *)
  | OP.PAUSE -> LiftingUtils.sideEffects insLen Pause (* SSE2 *)
  | OP.MOVNTPD -> SSELifter.movntpd ins insLen ctxt (* SSE2 *)
  | OP.MOVNTDQ -> SSELifter.movntdq ins insLen ctxt (* SSE2 *)
  | OP.MOVNTI -> SSELifter.movnti ins insLen ctxt (* SSE2 *)
  | OP.LDDQU -> SSELifter.lddqu ins insLen ctxt (* SSE3 *)
  | OP.MOVSHDUP -> SSELifter.movshdup ins insLen ctxt (* SSE3 *)
  | OP.MOVSLDUP -> SSELifter.movsldup ins insLen ctxt (* SSE3 *)
  | OP.MOVDDUP -> SSELifter.movddup ins insLen ctxt (* SSE3 *)
  | OP.PALIGNR -> SSELifter.palignr ins insLen ctxt (* SSE3 *)
  | OP.ROUNDSD -> SSELifter.roundsd ins insLen ctxt (* SSE4 *)
  | OP.PINSRB -> SSELifter.pinsrb ins insLen ctxt (* SSE4 *)
  | OP.PTEST -> SSELifter.ptest ins insLen ctxt (* SSE4 *)
  | OP.PCMPEQQ -> SSELifter.pcmpeqq ins insLen ctxt (* SSE4 *)
  | OP.PCMPESTRI | OP.PCMPESTRM | OP.PCMPISTRI | OP.PCMPISTRM ->
    SSELifter.pcmpstr ins insLen ctxt (* SSE4 *)
  | OP.VSQRTPS -> AVXLifter.vsqrtps ins insLen ctxt
  | OP.VSQRTPD -> AVXLifter.vsqrtpd ins insLen ctxt
  | OP.VSQRTSS -> AVXLifter.vsqrtss ins insLen ctxt
  | OP.VSQRTSD -> AVXLifter.vsqrtsd ins insLen ctxt
  | OP.VADDPS -> AVXLifter.vaddps ins insLen ctxt
  | OP.VADDPD -> AVXLifter.vaddpd ins insLen ctxt
  | OP.VADDSS -> AVXLifter.vaddss ins insLen ctxt
  | OP.VADDSD -> AVXLifter.vaddsd ins insLen ctxt
  | OP.VSUBPS -> AVXLifter.vsubps ins insLen ctxt
  | OP.VSUBPD -> AVXLifter.vsubpd ins insLen ctxt
  | OP.VSUBSS -> AVXLifter.vsubss ins insLen ctxt
  | OP.VSUBSD -> AVXLifter.vsubsd ins insLen ctxt
  | OP.VMULPS -> AVXLifter.vmulps ins insLen ctxt
  | OP.VMULPD -> AVXLifter.vmulpd ins insLen ctxt
  | OP.VMULSS -> AVXLifter.vmulss ins insLen ctxt
  | OP.VMULSD -> AVXLifter.vmulsd ins insLen ctxt
  | OP.VDIVPS -> AVXLifter.vdivps ins insLen ctxt
  | OP.VDIVPD -> AVXLifter.vdivpd ins insLen ctxt
  | OP.VDIVSS -> AVXLifter.vdivss ins insLen ctxt
  | OP.VDIVSD -> AVXLifter.vdivsd ins insLen ctxt
  | OP.VCVTSI2SS -> AVXLifter.vcvtsi2ss ins insLen ctxt
  | OP.VCVTSI2SD -> AVXLifter.vcvtsi2sd ins insLen ctxt
  | OP.VCVTSD2SS -> AVXLifter.vcvtsd2ss ins insLen ctxt
  | OP.VCVTSS2SD -> AVXLifter.vcvtss2sd ins insLen ctxt
  | OP.VMOVD -> AVXLifter.vmovd ins insLen ctxt
  | OP.VMOVQ -> AVXLifter.vmovq ins insLen ctxt
  | OP.VMOVAPS -> AVXLifter.vmovdqu ins insLen ctxt
  | OP.VMOVAPD -> AVXLifter.vmovdqu ins insLen ctxt
  | OP.VMOVDQU -> AVXLifter.vmovdqu ins insLen ctxt
  | OP.VMOVDQU16 -> AVXLifter.vmovdqu16 ins insLen ctxt
  | OP.VMOVDQU64 -> AVXLifter.vmovdqu64 ins insLen ctxt
  | OP.VMOVDQA -> AVXLifter.vmovdqa ins insLen ctxt
  | OP.VMOVDQA64 -> AVXLifter.vmovdqa64 ins insLen ctxt
  | OP.VMOVNTDQ -> AVXLifter.vmovntdq ins insLen ctxt
  | OP.VMOVUPS -> AVXLifter.vmovups ins insLen ctxt
  | OP.VMOVUPD -> AVXLifter.vmovupd ins insLen ctxt
  | OP.VMOVDDUP -> AVXLifter.vmovddup ins insLen ctxt
  | OP.VMOVNTPS -> AVXLifter.vmovntps ins insLen ctxt
  | OP.VMOVNTPD -> AVXLifter.vmovntpd ins insLen ctxt
  | OP.VMOVHLPS -> AVXLifter.vmovhlps ins insLen ctxt
  | OP.VMOVHPD | OP.VMOVHPS -> AVXLifter.vmovhpd ins insLen ctxt
  | OP.VMOVLHPS -> AVXLifter.vmovlhps ins insLen ctxt
  | OP.VMOVLPD | OP.VMOVLPS -> AVXLifter.vmovlpd ins insLen ctxt
  | OP.VMOVMSKPD -> AVXLifter.vmovmskpd ins insLen ctxt
  | OP.VMOVMSKPS -> AVXLifter.vmovmskps ins insLen ctxt
  | OP.VMOVSD -> AVXLifter.vmovsd ins insLen ctxt
  | OP.VMOVSHDUP -> AVXLifter.vmovshdup ins insLen ctxt
  | OP.VMOVSLDUP -> AVXLifter.vmovsldup ins insLen ctxt
  | OP.VMOVSS -> AVXLifter.vmovss ins insLen ctxt
  | OP.VANDPS -> AVXLifter.vandps ins insLen ctxt
  | OP.VANDPD -> AVXLifter.vandpd ins insLen ctxt
  | OP.VANDNPS -> AVXLifter.vandnps ins insLen ctxt
  | OP.VANDNPD -> AVXLifter.vandnpd ins insLen ctxt
  | OP.VORPS -> AVXLifter.vorps ins insLen ctxt
  | OP.VORPD -> AVXLifter.vorpd ins insLen ctxt
  | OP.VSHUFI32X4 -> AVXLifter.vshufi32x4 ins insLen ctxt
  | OP.VSHUFPS -> AVXLifter.vshufps ins insLen ctxt
  | OP.VSHUFPD -> AVXLifter.vshufpd ins insLen ctxt
  | OP.VUNPCKHPS -> AVXLifter.vunpckhps ins insLen ctxt
  | OP.VUNPCKHPD -> AVXLifter.vunpckhpd ins insLen ctxt
  | OP.VUNPCKLPS -> AVXLifter.vunpcklps ins insLen ctxt
  | OP.VUNPCKLPD -> AVXLifter.vunpcklpd ins insLen ctxt
  | OP.VXORPS -> AVXLifter.vxorps ins insLen ctxt
  | OP.VXORPD -> AVXLifter.vxorpd ins insLen ctxt
  | OP.VBROADCASTI128 -> AVXLifter.vbroadcasti128 ins insLen ctxt
  | OP.VBROADCASTSS -> AVXLifter.vbroadcastss ins insLen ctxt
  | OP.VEXTRACTF32X8 -> AVXLifter.vextracti32x8 ins insLen ctxt
  | OP.VEXTRACTI64X4 -> AVXLifter.vextracti64x4 ins insLen ctxt
  | OP.VINSERTI128 -> AVXLifter.vinserti128 ins insLen ctxt
  | OP.VMPTRLD -> LiftingUtils.sideEffects insLen UnsupportedExtension
  | OP.VPADDB -> AVXLifter.vpaddb ins insLen ctxt
  | OP.VPADDD -> AVXLifter.vpaddd ins insLen ctxt
  | OP.VPADDQ -> AVXLifter.vpaddq ins insLen ctxt
  | OP.VPALIGNR -> AVXLifter.vpalignr ins insLen ctxt
  | OP.VPAND -> AVXLifter.vpand ins insLen ctxt
  | OP.VPANDN -> AVXLifter.vpandn ins insLen ctxt
  | OP.VPBROADCASTB -> AVXLifter.vpbroadcastb ins insLen ctxt
  | OP.VPBROADCASTD -> AVXLifter.vpbroadcastd ins insLen ctxt
  | OP.VPCMPEQB -> AVXLifter.vpcmpeqb ins insLen ctxt
  | OP.VPCMPEQD -> AVXLifter.vpcmpeqd ins insLen ctxt
  | OP.VPCMPEQQ -> AVXLifter.vpcmpeqq ins insLen ctxt
  | OP.VPCMPESTRI | OP.VPCMPESTRM | OP.VPCMPISTRI
  | OP.VPCMPISTRM -> SSELifter.pcmpstr ins insLen ctxt
  | OP.VPCMPGTB -> AVXLifter.vpcmpgtb ins insLen ctxt
  | OP.VPINSRD -> AVXLifter.vpinsrd ins insLen ctxt
  | OP.VPMINUB -> AVXLifter.vpminub ins insLen ctxt
  | OP.VPMINUD -> AVXLifter.vpminud ins insLen ctxt
  | OP.VPMOVMSKB -> SSELifter.pmovmskb ins insLen ctxt
  | OP.VPMULUDQ -> AVXLifter.vpmuludq ins insLen ctxt
  | OP.VPOR -> AVXLifter.vpor ins insLen ctxt
  | OP.VPSHUFB -> AVXLifter.vpshufb ins insLen ctxt
  | OP.VPSHUFD -> AVXLifter.vpshufd ins insLen ctxt
  | OP.VPSLLD -> AVXLifter.vpslld ins insLen ctxt
  | OP.VPSLLDQ -> AVXLifter.vpslldq ins insLen ctxt
  | OP.VPSLLQ -> AVXLifter.vpsllq ins insLen ctxt
  | OP.VPSRLD -> AVXLifter.vpsrld ins insLen ctxt
  | OP.VPSRLDQ -> AVXLifter.vpsrldq ins insLen ctxt
  | OP.VPSRLQ -> AVXLifter.vpsrlq ins insLen ctxt
  | OP.VPSUBB -> AVXLifter.vpsubb ins insLen ctxt
  | OP.VPTEST -> AVXLifter.vptest ins insLen ctxt
  | OP.VPUNPCKHDQ -> AVXLifter.vpunpckhdq ins insLen ctxt
  | OP.VPUNPCKHQDQ -> AVXLifter.vpunpckhqdq ins insLen ctxt
  | OP.VPUNPCKLDQ -> AVXLifter.vpunpckldq ins insLen ctxt
  | OP.VPUNPCKLQDQ -> AVXLifter.vpunpcklqdq ins insLen ctxt
  | OP.VPXOR -> AVXLifter.vpxor ins insLen ctxt
  | OP.VPXORD -> AVXLifter.vpxord ins insLen ctxt
  | OP.VZEROUPPER -> AVXLifter.vzeroupper ins insLen ctxt
  | OP.VINSERTI64X4
  | OP.VPMOVWB | OP.VMOVDQU32 | OP.VPMOVZXWD
  | OP.VPSRLW | OP.VFMADD213SS ->
    GeneralLifter.nop insLen (* FIXME: #196 *)
  | OP.VERW -> LiftingUtils.sideEffects insLen UnsupportedPrivInstr
  | OP.VFMADD132SD -> AVXLifter.vfmadd132sd ins insLen ctxt
  | OP.VFMADD213SD -> AVXLifter.vfmadd213sd ins insLen ctxt
  | OP.VFMADD231SD -> AVXLifter.vfmadd231sd ins insLen ctxt
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
    GeneralLifter.nop insLen (* FIXME: #196 !211 *)
  | OP.FLD -> X87Lifter.fld ins insLen ctxt
  | OP.FST -> X87Lifter.ffst ins insLen ctxt false
  | OP.FSTP -> X87Lifter.ffst ins insLen ctxt true
  | OP.FILD -> X87Lifter.fild ins insLen ctxt
  | OP.FIST -> X87Lifter.fist ins insLen ctxt false
  | OP.FISTP -> X87Lifter.fist ins insLen ctxt true
  | OP.FISTTP -> X87Lifter.fisttp ins insLen ctxt (* SSE3 *)
  | OP.FBLD -> X87Lifter.fbld ins insLen ctxt
  | OP.FBSTP -> X87Lifter.fbstp ins insLen ctxt
  | OP.FXCH -> X87Lifter.fxch ins insLen ctxt
  | OP.FCMOVE -> X87Lifter.fcmove ins insLen ctxt
  | OP.FCMOVNE -> X87Lifter.fcmovne ins insLen ctxt
  | OP.FCMOVB -> X87Lifter.fcmovb ins insLen ctxt
  | OP.FCMOVBE -> X87Lifter.fcmovbe ins insLen ctxt
  | OP.FCMOVNB -> X87Lifter.fcmovnb ins insLen ctxt
  | OP.FCMOVNBE -> X87Lifter.fcmovnbe ins insLen ctxt
  | OP.FCMOVU -> X87Lifter.fcmovu ins insLen ctxt
  | OP.FCMOVNU -> X87Lifter.fcmovnu ins insLen ctxt
  | OP.FADD -> X87Lifter.fpuadd ins insLen ctxt false
  | OP.FADDP -> X87Lifter.fpuadd ins insLen ctxt true
  | OP.FIADD -> X87Lifter.fiadd ins insLen ctxt
  | OP.FSUB -> X87Lifter.fpusub ins insLen ctxt false
  | OP.FSUBP -> X87Lifter.fpusub ins insLen ctxt true
  | OP.FISUB -> X87Lifter.fisub ins insLen ctxt
  | OP.FSUBR -> X87Lifter.fsubr ins insLen ctxt false
  | OP.FSUBRP -> X87Lifter.fsubr ins insLen ctxt true
  | OP.FISUBR  -> X87Lifter.fisubr ins insLen ctxt
  | OP.FMUL -> X87Lifter.fpumul ins insLen ctxt false
  | OP.FMULP -> X87Lifter.fpumul ins insLen ctxt true
  | OP.FIMUL -> X87Lifter.fimul ins insLen ctxt
  | OP.FDIV -> X87Lifter.fpudiv ins insLen ctxt false
  | OP.FDIVP -> X87Lifter.fpudiv ins insLen ctxt true
  | OP.FIDIV -> X87Lifter.fidiv ins insLen ctxt
  | OP.FDIVR -> X87Lifter.fdivr ins insLen ctxt false
  | OP.FDIVRP -> X87Lifter.fdivr  ins insLen ctxt true
  | OP.FIDIVR -> X87Lifter.fidivr ins insLen ctxt
  | OP.FPREM -> X87Lifter.fprem ins insLen ctxt false
  | OP.FPREM1 -> X87Lifter.fprem ins insLen ctxt true
  | OP.FABS -> X87Lifter.fabs ins insLen ctxt
  | OP.FCHS -> X87Lifter.fchs ins insLen ctxt
  | OP.FRNDINT -> X87Lifter.frndint ins insLen ctxt
  | OP.FSCALE -> X87Lifter.fscale ins insLen ctxt
  | OP.FSQRT -> X87Lifter.fsqrt ins insLen ctxt
  | OP.FXTRACT -> X87Lifter.fxtract ins insLen ctxt
  | OP.FCOM -> X87Lifter.fcom ins insLen ctxt 0 false
  | OP.FCOMP -> X87Lifter.fcom ins insLen ctxt 1 false
  | OP.FCOMPP -> X87Lifter.fcom ins insLen ctxt 2 false
  | OP.FUCOM -> X87Lifter.fcom ins insLen ctxt 0 true
  | OP.FUCOMP -> X87Lifter.fcom ins insLen ctxt 1 true
  | OP.FUCOMPP -> X87Lifter.fcom ins insLen ctxt 2 true
  | OP.FICOM -> X87Lifter.ficom ins insLen ctxt false
  | OP.FICOMP -> X87Lifter.ficom ins insLen ctxt true
  | OP.FCOMI -> X87Lifter.fcomi ins insLen ctxt false
  | OP.FUCOMI -> X87Lifter.fcomi ins insLen ctxt false
  | OP.FCOMIP -> X87Lifter.fcomi ins insLen ctxt true
  | OP.FUCOMIP -> X87Lifter.fcomi ins insLen ctxt true
  | OP.FTST -> X87Lifter.ftst ins insLen ctxt
  | OP.FXAM -> X87Lifter.fxam ins insLen ctxt
  | OP.FSIN -> X87Lifter.fsin ins insLen ctxt
  | OP.FCOS -> X87Lifter.fcos ins insLen ctxt
  | OP.FSINCOS -> X87Lifter.fsincos ins insLen ctxt
  | OP.FPTAN -> X87Lifter.fptan ins insLen ctxt
  | OP.FPATAN -> X87Lifter.fpatan ins insLen ctxt
  | OP.F2XM1 -> X87Lifter.f2xm1 ins insLen ctxt
  | OP.FYL2X -> X87Lifter.fyl2x ins insLen ctxt
  | OP.FYL2XP1 -> X87Lifter.fyl2xp1 ins insLen ctxt
  | OP.FLD1 -> X87Lifter.fld1 ins insLen ctxt
  | OP.FLDZ -> X87Lifter.fldz ins insLen ctxt
  | OP.FLDPI -> X87Lifter.fldpi ins insLen ctxt
  | OP.FLDL2E -> X87Lifter.fldl2e ins insLen ctxt
  | OP.FLDLN2 -> X87Lifter.fldln2 ins insLen ctxt
  | OP.FLDL2T -> X87Lifter.fldl2t ins insLen ctxt
  | OP.FLDLG2 -> X87Lifter.fldlg2 ins insLen ctxt
  | OP.FINCSTP -> X87Lifter.fincstp ins insLen ctxt
  | OP.FDECSTP -> X87Lifter.fdecstp ins insLen ctxt
  | OP.FFREE -> X87Lifter.ffree ins insLen ctxt
  | OP.FINIT -> X87Lifter.finit ins insLen ctxt
  | OP.FNINIT -> X87Lifter.fninit ins insLen ctxt
  | OP.FCLEX -> X87Lifter.fclex ins insLen ctxt
  | OP.FSTCW -> X87Lifter.fstcw ins insLen ctxt
  | OP.FNSTCW -> X87Lifter.fnstcw ins insLen ctxt
  | OP.FLDCW -> X87Lifter.fldcw ins insLen ctxt
  | OP.FSTENV -> X87Lifter.fstenv ins insLen ctxt
  | OP.FLDENV -> X87Lifter.fldenv ins insLen ctxt
  | OP.FSAVE -> X87Lifter.fsave ins insLen ctxt
  | OP.FRSTOR -> X87Lifter.frstor ins insLen ctxt
  | OP.FSTSW -> X87Lifter.fstsw ins insLen ctxt
  | OP.FNSTSW -> X87Lifter.fnstsw ins insLen ctxt
  | OP.WAIT -> X87Lifter.wait ins insLen ctxt
  | OP.FNOP -> X87Lifter.fnop ins insLen ctxt
  | OP.FXSAVE | OP.FXSAVE64 -> X87Lifter.fxsave ins insLen ctxt
  | OP.FXRSTOR | OP.FXRSTOR64 -> X87Lifter.fxrstor ins insLen ctxt
  | o ->
#if DEBUG
         eprintfn "%A" o
         eprintfn "%A" ins
#endif
         raise <| NotImplementedIRException (Disasm.opCodeToString o)
  |> fun builder -> builder.ToStmts ()

// vim: set tw=80 sts=2 sw=2:
