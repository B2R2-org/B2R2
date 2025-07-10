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

module internal B2R2.FrontEnd.Intel.Lifter

open B2R2
open B2R2.BinIR

type OP = Opcode (* Just to make it concise. *)

/// Translate IR.
let translate (ins: Instruction) insLen bld =
  match ins.Opcode with
  | OP.AAA -> GeneralLifter.aaa ins insLen bld
  | OP.AAD -> GeneralLifter.aad ins insLen bld
  | OP.AAM -> GeneralLifter.aam ins insLen bld
  | OP.AAS -> GeneralLifter.aas ins insLen bld
  | OP.ADC -> GeneralLifter.adc ins insLen bld
  | OP.ADD -> GeneralLifter.add ins insLen bld
  | OP.ADOX-> GeneralLifter.adox ins insLen bld
  | OP.AND -> GeneralLifter.``and`` ins insLen bld
  | OP.ANDN -> GeneralLifter.andn ins insLen bld
  | OP.ARPL -> GeneralLifter.arpl ins insLen bld
  | OP.BEXTR -> GeneralLifter.bextr ins insLen bld
  | OP.BLSI -> GeneralLifter.blsi ins insLen bld
  | OP.BNDMOV -> GeneralLifter.bndmov ins insLen bld
  | OP.BOUND -> GeneralLifter.nop ins.Address insLen bld
  | OP.BSF -> GeneralLifter.bsf ins insLen bld
  | OP.BSR -> GeneralLifter.bsr ins insLen bld
  | OP.BSWAP -> GeneralLifter.bswap ins insLen bld
  | OP.BT -> GeneralLifter.bt ins insLen bld
  | OP.BTC -> GeneralLifter.btc ins insLen bld
  | OP.BTR -> GeneralLifter.btr ins insLen bld
  | OP.BTS -> GeneralLifter.bts ins insLen bld
  | OP.BZHI -> GeneralLifter.bzhi ins insLen bld
  | OP.CALLNear -> GeneralLifter.call ins insLen bld
  | OP.CALLFar -> LiftingUtils.sideEffects bld ins insLen UnsupportedFAR
  | OP.CBW | OP.CWDE | OP.CDQE ->
    GeneralLifter.convBWQ ins insLen bld
  | OP.CLC -> GeneralLifter.clearFlag ins insLen bld R.CF
  | OP.CLD -> GeneralLifter.clearFlag ins insLen bld R.DF
  | OP.CLI -> GeneralLifter.clearFlag ins insLen bld R.IF
  | OP.CLRSSBSY -> GeneralLifter.nop ins.Address insLen bld
  | OP.CLTS -> LiftingUtils.sideEffects bld ins insLen UnsupportedPrivInstr
  | OP.CMC -> GeneralLifter.cmc ins insLen bld
  | OP.CMOVO | OP.CMOVNO | OP.CMOVB | OP.CMOVAE
  | OP.CMOVZ | OP.CMOVNZ | OP.CMOVBE | OP.CMOVA
  | OP.CMOVS  | OP.CMOVNS | OP.CMOVP | OP.CMOVNP
  | OP.CMOVL | OP.CMOVGE | OP.CMOVLE | OP.CMOVG ->
    GeneralLifter.cmovcc ins insLen bld
  | OP.CMP -> GeneralLifter.cmp ins insLen bld
  | OP.CMPSB | OP.CMPSW | OP.CMPSQ ->
    GeneralLifter.cmps ins insLen bld
  | OP.CMPXCHG -> GeneralLifter.cmpxchg ins insLen bld
  | OP.CMPXCHG8B | OP.CMPXCHG16B ->
    GeneralLifter.compareExchangeBytes ins insLen bld
  | OP.CPUID -> LiftingUtils.sideEffects bld ins insLen ProcessorID
  | OP.CRC32 -> GeneralLifter.crc32 ins insLen bld
  | OP.CWD | OP.CDQ | OP.CQO ->
    GeneralLifter.convWDQ ins insLen bld
  | OP.DAA -> GeneralLifter.daa ins.Address insLen bld
  | OP.DAS -> GeneralLifter.das ins.Address insLen bld
  | OP.DEC -> GeneralLifter.dec ins insLen bld
  | OP.DIV | OP.IDIV -> GeneralLifter.div ins insLen bld
  | OP.ENDBR32 | OP.ENDBR64 -> GeneralLifter.nop ins.Address insLen bld
  | OP.ENTER -> GeneralLifter.enter ins insLen bld
  | OP.HLT -> LiftingUtils.sideEffects bld ins insLen Terminate
  | OP.IMUL -> GeneralLifter.imul ins insLen bld
  | OP.INC -> GeneralLifter.inc ins insLen bld
  | OP.INCSSPD | OP.INCSSPQ -> GeneralLifter.nop ins.Address insLen bld
  | OP.INSB | OP.INSW | OP.INSD ->
    LiftingUtils.sideEffects bld ins insLen UnsupportedPrivInstr
  | OP.INT | OP.INTO -> GeneralLifter.interrupt ins insLen bld
  | OP.INT3 -> LiftingUtils.sideEffects bld ins insLen Breakpoint
  | OP.JMPFar | OP.JMPNear -> GeneralLifter.jmp ins insLen bld
  | OP.JO | OP.JNO | OP.JB | OP.JNB
  | OP.JZ | OP.JNZ | OP.JBE | OP.JA
  | OP.JS | OP.JNS | OP.JP | OP.JNP
  | OP.JL | OP.JNL | OP.JLE | OP.JG
  | OP.JECXZ | OP.JRCXZ -> GeneralLifter.jcc ins insLen bld
  | OP.LAHF -> GeneralLifter.lahf ins insLen bld
  | OP.LEA -> GeneralLifter.lea ins insLen bld
  | OP.LEAVE -> GeneralLifter.leave ins insLen bld
  | OP.LODSB | OP.LODSW | OP.LODSD | OP.LODSQ ->
    GeneralLifter.lods ins insLen bld
  | OP.LOOP | OP.LOOPE | OP.LOOPNE ->
    GeneralLifter.loop ins insLen bld
  | OP.LZCNT -> GeneralLifter.lzcnt ins insLen bld
  | OP.LDS | OP.LES | OP.LFS | OP.LGS | OP.LSS ->
    LiftingUtils.sideEffects bld ins insLen UnsupportedFAR
  | OP.MOV -> GeneralLifter.mov ins insLen bld
  | OP.MOVBE -> GeneralLifter.movbe ins insLen bld
  | OP.MOVSB | OP.MOVSW | OP.MOVSQ ->
    GeneralLifter.movs ins insLen bld
  | OP.MOVSX | OP.MOVSXD -> GeneralLifter.movsx ins insLen bld
  | OP.MOVZX -> GeneralLifter.movzx ins insLen bld
  | OP.MUL -> GeneralLifter.mul ins insLen bld
  | OP.MULX -> GeneralLifter.mulx ins insLen bld
  | OP.NEG -> GeneralLifter.neg ins insLen bld
  | OP.NOP -> GeneralLifter.nop ins.Address insLen bld
  | OP.NOT -> GeneralLifter.not ins insLen bld
  | OP.OR -> GeneralLifter.logOr ins insLen bld
  | OP.OUTSB | OP.OUTSW | OP.OUTSD ->
    LiftingUtils.sideEffects bld ins insLen UnsupportedPrivInstr
  | OP.PDEP -> GeneralLifter.pdep ins insLen bld
  | OP.PEXT -> GeneralLifter.pext ins insLen bld
  | OP.POP -> GeneralLifter.pop ins insLen bld
  | OP.POPA -> GeneralLifter.popa ins insLen bld 16<rt>
  | OP.POPAD -> GeneralLifter.popa ins insLen bld 32<rt>
  | OP.POPCNT -> GeneralLifter.popcnt ins insLen bld
  | OP.POPF | OP.POPFD | OP.POPFQ ->
    GeneralLifter.popf ins insLen bld
  | OP.PUSH -> GeneralLifter.push ins insLen bld
  | OP.PUSHA -> GeneralLifter.pusha ins insLen bld 16<rt>
  | OP.PUSHAD -> GeneralLifter.pusha ins insLen bld 32<rt>
  | OP.PUSHF | OP.PUSHFD | OP.PUSHFQ ->
    GeneralLifter.pushf ins insLen bld
  | OP.RCL -> GeneralLifter.rcl ins insLen bld
  | OP.RCR -> GeneralLifter.rcr ins insLen bld
  | OP.RDMSR | OP.RSM ->
    LiftingUtils.sideEffects bld ins insLen UnsupportedExtension
  | OP.RDPKRU -> GeneralLifter.rdpkru ins insLen bld
  | OP.RDPMC -> LiftingUtils.sideEffects bld ins insLen UnsupportedExtension
  | OP.RDRAND -> LiftingUtils.sideEffects bld ins insLen UnsupportedExtension
  | OP.RDSSPD | OP.RDSSPQ -> GeneralLifter.nop ins.Address insLen bld
  | OP.RDTSC -> LiftingUtils.sideEffects bld ins insLen ClockCounter
  | OP.RDTSCP -> LiftingUtils.sideEffects bld ins insLen ClockCounter
  | OP.RETNear -> GeneralLifter.ret ins insLen bld
  | OP.RETNearImm -> GeneralLifter.retWithImm ins insLen bld
  | OP.RETFar -> LiftingUtils.sideEffects bld ins insLen UnsupportedFAR
  | OP.RETFarImm -> LiftingUtils.sideEffects bld ins insLen UnsupportedFAR
  | OP.ROL -> GeneralLifter.rol ins insLen bld
  | OP.ROR -> GeneralLifter.ror ins insLen bld
  | OP.RORX -> GeneralLifter.rorx ins insLen bld
  | OP.RSTORSSP -> GeneralLifter.nop ins.Address insLen bld
  | OP.SAHF -> GeneralLifter.sahf ins insLen bld
  | OP.SAR | OP.SHR | OP.SHL ->
    GeneralLifter.shift ins insLen bld
  | OP.SAVEPREVSSP -> GeneralLifter.nop ins.Address insLen bld
  | OP.SBB -> GeneralLifter.sbb ins insLen bld
  | OP.SCASB | OP.SCASW | OP.SCASD | OP.SCASQ ->
    GeneralLifter.scas ins insLen bld
  | OP.SETO | OP.SETNO | OP.SETB | OP.SETNB
  | OP.SETZ | OP.SETNZ | OP.SETBE | OP.SETA
  | OP.SETS | OP.SETNS | OP.SETP | OP.SETNP
  | OP.SETL | OP.SETNL | OP.SETLE | OP.SETG ->
    GeneralLifter.setcc ins insLen bld
  | OP.SETSSBSY -> GeneralLifter.nop ins.Address insLen bld
  | OP.SHLD -> GeneralLifter.shld ins insLen bld
  | OP.SARX -> GeneralLifter.sarx ins insLen bld
  | OP.SHLX -> GeneralLifter.shlx ins insLen bld
  | OP.SHRX -> GeneralLifter.shrx ins insLen bld
  | OP.SHRD -> GeneralLifter.shrd ins insLen bld
  | OP.STC -> GeneralLifter.stc ins insLen bld
  | OP.STD -> GeneralLifter.std ins insLen bld
  | OP.STI -> GeneralLifter.sti ins insLen bld
  | OP.STOSB | OP.STOSW | OP.STOSD | OP.STOSQ ->
    GeneralLifter.stos ins insLen bld
  | OP.SUB -> GeneralLifter.sub ins insLen bld
  | OP.SYSCALL | OP.SYSENTER -> LiftingUtils.sideEffects bld ins insLen SysCall
  | OP.SYSEXIT | OP.SYSRET ->
    LiftingUtils.sideEffects bld ins insLen UnsupportedPrivInstr
  | OP.TEST -> GeneralLifter.test ins insLen bld
  | OP.TZCNT -> GeneralLifter.tzcnt ins insLen bld
  | OP.UD2 -> LiftingUtils.sideEffects bld ins insLen UndefinedInstr
  | OP.WBINVD -> LiftingUtils.sideEffects bld ins insLen UnsupportedPrivInstr
  | OP.WRFSBASE -> GeneralLifter.wrfsbase ins insLen bld
  | OP.WRGSBASE -> GeneralLifter.wrgsbase ins insLen bld
  | OP.WRPKRU -> GeneralLifter.wrpkru ins insLen bld
  | OP.WRMSR -> LiftingUtils.sideEffects bld ins insLen UnsupportedPrivInstr
  | OP.WRSSD | OP.WRSSQ -> GeneralLifter.nop ins.Address insLen bld
  | OP.WRUSSD | OP.WRUSSQ -> GeneralLifter.nop ins.Address insLen bld
  | OP.XABORT -> LiftingUtils.sideEffects bld ins insLen UnsupportedExtension
  | OP.XADD -> GeneralLifter.xadd ins insLen bld
  | OP.XBEGIN -> LiftingUtils.sideEffects bld ins insLen UnsupportedExtension
  | OP.XCHG -> GeneralLifter.xchg ins insLen bld
  | OP.XEND -> LiftingUtils.sideEffects bld ins insLen UnsupportedExtension
  | OP.XGETBV -> LiftingUtils.sideEffects bld ins insLen UnsupportedExtension
  | OP.XLATB -> GeneralLifter.xlatb ins insLen bld
  | OP.XOR -> GeneralLifter.xor ins insLen bld
  | OP.XRSTOR | OP.XRSTORS | OP.XSAVE | OP.XSAVEC
  | OP.XSAVEC64 | OP.XSAVEOPT | OP.XSAVES | OP.XSAVES64 ->
    LiftingUtils.sideEffects bld ins insLen UnsupportedExtension
  | OP.XTEST -> LiftingUtils.sideEffects bld ins insLen UnsupportedExtension
  | OP.IN | OP.INVD | OP.INVLPG | OP.IRET | OP.IRETQ | OP.IRETW | OP.IRETD
  | OP.LAR | OP.LGDT | OP.LIDT | OP.LLDT
  | OP.LMSW | OP.LSL | OP.LTR | OP.OUT | OP.SGDT
  | OP.SIDT | OP.SLDT | OP.SMSW | OP.STR | OP.VERR ->
    LiftingUtils.sideEffects bld ins insLen UnsupportedPrivInstr
  | OP.MOVD -> MMXLifter.movd ins insLen bld
  | OP.MOVQ -> MMXLifter.movq ins insLen bld
  | OP.PACKSSDW -> MMXLifter.packssdw ins insLen bld
  | OP.PACKSSWB -> MMXLifter.packsswb ins insLen bld
  | OP.PACKUSWB -> MMXLifter.packuswb ins insLen bld
  | OP.PUNPCKHBW -> MMXLifter.punpckhbw ins insLen bld
  | OP.PUNPCKHWD -> MMXLifter.punpckhwd ins insLen bld
  | OP.PUNPCKHDQ -> MMXLifter.punpckhdq ins insLen bld
  | OP.PUNPCKLBW -> MMXLifter.punpcklbw ins insLen bld
  | OP.PUNPCKLWD -> MMXLifter.punpcklwd ins insLen bld
  | OP.PUNPCKLDQ -> MMXLifter.punpckldq ins insLen bld
  | OP.PADDB -> MMXLifter.paddb ins insLen bld
  | OP.PADDW -> MMXLifter.paddw ins insLen bld
  | OP.PADDD -> MMXLifter.paddd ins insLen bld
  | OP.PADDSB -> MMXLifter.paddsb ins insLen bld
  | OP.PADDSW -> MMXLifter.paddsw ins insLen bld
  | OP.PADDUSB -> MMXLifter.paddusb ins insLen bld
  | OP.PADDUSW -> MMXLifter.paddusw ins insLen bld
  | OP.PHADDD -> MMXLifter.phaddd ins insLen bld
  | OP.PHADDW -> MMXLifter.phaddw ins insLen bld
  | OP.PHADDSW -> MMXLifter.phaddsw ins insLen bld
  | OP.PSUBB -> MMXLifter.psubb ins insLen bld
  | OP.PSUBW -> MMXLifter.psubw ins insLen bld
  | OP.PSUBD -> MMXLifter.psubd ins insLen bld
  | OP.PSUBSB -> MMXLifter.psubsb ins insLen bld
  | OP.PSUBSW -> MMXLifter.psubsw ins insLen bld
  | OP.PSUBUSB -> MMXLifter.psubusb ins insLen bld
  | OP.PSUBUSW -> MMXLifter.psubusw ins insLen bld
  | OP.PHSUBD -> MMXLifter.phsubd ins insLen bld
  | OP.PHSUBW -> MMXLifter.phsubw ins insLen bld
  | OP.PHSUBSW -> MMXLifter.phsubsw ins insLen bld
  | OP.PMULHW -> MMXLifter.pmulhw ins insLen bld
  | OP.PMULLW -> MMXLifter.pmullw ins insLen bld
  | OP.PMULLD -> SSELifter.pmulld ins insLen bld
  | OP.PMADDWD -> MMXLifter.pmaddwd ins insLen bld
  | OP.PCMPEQB -> MMXLifter.pcmpeqb ins insLen bld
  | OP.PCMPEQW -> MMXLifter.pcmpeqw ins insLen bld
  | OP.PCMPEQD -> MMXLifter.pcmpeqd ins insLen bld
  | OP.PCMPGTB -> MMXLifter.pcmpgtb ins insLen bld
  | OP.PCMPGTW -> MMXLifter.pcmpgtw ins insLen bld
  | OP.PCMPGTD -> MMXLifter.pcmpgtd ins insLen bld
  | OP.PAND -> MMXLifter.pand ins insLen bld
  | OP.PANDN -> MMXLifter.pandn ins insLen bld
  | OP.POR -> MMXLifter.por ins insLen bld
  | OP.PXOR -> MMXLifter.pxor ins insLen bld
  | OP.PSLLW -> MMXLifter.psllw ins insLen bld
  | OP.PSLLD -> MMXLifter.pslld ins insLen bld
  | OP.PSLLQ -> MMXLifter.psllq ins insLen bld
  | OP.PSRLW -> MMXLifter.psrlw ins insLen bld
  | OP.PSRLD -> MMXLifter.psrld ins insLen bld
  | OP.PSRLQ -> MMXLifter.psrlq ins insLen bld
  | OP.PSRAW -> MMXLifter.psraw ins insLen bld
  | OP.PSRAD -> MMXLifter.psrad ins insLen bld
  | OP.EMMS -> MMXLifter.emms ins insLen bld
  | OP.ADDSUBPD -> SSELifter.addsubpd ins insLen bld
  | OP.ADDSUBPS -> SSELifter.addsubps ins insLen bld
  | OP.MOVAPS -> SSELifter.movaps ins insLen bld
  | OP.MOVAPD -> SSELifter.movapd ins insLen bld (* SSE2 *)
  | OP.MOVUPS -> SSELifter.movups ins insLen bld
  | OP.MOVUPD -> SSELifter.movupd ins insLen bld (* SSE2 *)
  | OP.MOVHPS -> SSELifter.movhps ins insLen bld
  | OP.MOVHPD -> SSELifter.movhpd ins insLen bld (* SSE2 *)
  | OP.MOVHLPS -> SSELifter.movhlps ins insLen bld
  | OP.MOVLPS -> SSELifter.movlps ins insLen bld
  | OP.MOVLPD -> SSELifter.movlpd ins insLen bld (* SSE2 *)
  | OP.MOVLHPS -> SSELifter.movlhps ins insLen bld
  | OP.MOVMSKPS -> SSELifter.movmskps ins insLen bld
  | OP.MOVMSKPD -> SSELifter.movmskpd ins insLen bld (* SSE2 *)
  | OP.MOVSS -> SSELifter.movss ins insLen bld
  | OP.MOVSD -> SSELifter.movsd ins insLen bld (* SSE2 *)
  | OP.ADDPS -> SSELifter.addps ins insLen bld
  | OP.ADDPD -> SSELifter.addpd ins insLen bld (* SSE2 *)
  | OP.ADDSS -> SSELifter.addss ins insLen bld
  | OP.ADDSD -> SSELifter.addsd ins insLen bld (* SSE2 *)
  | OP.SUBPS -> SSELifter.subps ins insLen bld
  | OP.SUBPD -> SSELifter.subpd ins insLen bld (* SSE2 *)
  | OP.SUBSS -> SSELifter.subss ins insLen bld
  | OP.SUBSD -> SSELifter.subsd ins insLen bld (* SSE2 *)
  | OP.MULPS -> SSELifter.mulps ins insLen bld
  | OP.MULPD -> SSELifter.mulpd ins insLen bld (* SSE2 *)
  | OP.MULSS -> SSELifter.mulss ins insLen bld
  | OP.MULSD -> SSELifter.mulsd ins insLen bld (* SSE2 *)
  | OP.DIVPS -> SSELifter.divps ins insLen bld
  | OP.DIVPD -> SSELifter.divpd ins insLen bld (* SSE2 *)
  | OP.DIVSS -> SSELifter.divss ins insLen bld
  | OP.DIVSD -> SSELifter.divsd ins insLen bld (* SSE2 *)
  | OP.RCPPS -> SSELifter.rcpps ins insLen bld
  | OP.RCPSS -> SSELifter.rcpss ins insLen bld
  | OP.SQRTPS -> SSELifter.sqrtps ins insLen bld
  | OP.SQRTPD -> SSELifter.sqrtpd ins insLen bld (* SSE2 *)
  | OP.SQRTSS -> SSELifter.sqrtss ins insLen bld
  | OP.SQRTSD -> SSELifter.sqrtsd ins insLen bld (* SSE2 *)
  | OP.RSQRTPS -> SSELifter.rsqrtps ins insLen bld
  | OP.RSQRTSS -> SSELifter.rsqrtss ins insLen bld
  | OP.MAXPS -> SSELifter.maxps ins insLen bld
  | OP.MAXPD -> SSELifter.maxpd ins insLen bld (* SSE2 *)
  | OP.MAXSS -> SSELifter.maxss ins insLen bld
  | OP.MAXSD -> SSELifter.maxsd ins insLen bld (* SSE2 *)
  | OP.MINPS -> SSELifter.minps ins insLen bld
  | OP.MINPD -> SSELifter.minpd ins insLen bld (* SSE2 *)
  | OP.MINSS -> SSELifter.minss ins insLen bld
  | OP.MINSD -> SSELifter.minsd ins insLen bld (* SSE2 *)
  | OP.CMPPS -> SSELifter.cmpps ins insLen bld
  | OP.CMPPD -> SSELifter.cmppd ins insLen bld (* SSE2 *)
  | OP.CMPSS -> SSELifter.cmpss ins insLen bld
  | OP.CMPSD -> SSELifter.cmpsd ins insLen bld (* SSE2 *)
  | OP.COMISS | OP.VCOMISS ->
    SSELifter.comiss ins insLen bld
  | OP.COMISD | OP.VCOMISD -> (* SSE2 *)
    SSELifter.comisd ins insLen bld
  | OP.UCOMISS | OP.VUCOMISS ->
    SSELifter.ucomiss ins insLen bld
  | OP.UCOMISD | OP.VUCOMISD -> (* SSE2 *)
    SSELifter.ucomisd ins insLen bld
  | OP.ANDPS -> SSELifter.andps ins insLen bld
  | OP.ANDPD -> SSELifter.andpd ins insLen bld (* SSE2 *)
  | OP.ANDNPS -> SSELifter.andnps ins insLen bld
  | OP.ANDNPD -> SSELifter.andnpd ins insLen bld (* SSE2 *)
  | OP.ORPS -> SSELifter.orps ins insLen bld
  | OP.ORPD -> SSELifter.orpd ins insLen bld (* SSE2 *)
  | OP.XORPS -> SSELifter.xorps ins insLen bld
  | OP.XORPD -> SSELifter.xorpd ins insLen bld (* SSE2 *)
  | OP.XSETBV -> LiftingUtils.sideEffects bld ins insLen UnsupportedPrivInstr
  | OP.SHUFPS -> SSELifter.shufps ins insLen bld
  | OP.SHUFPD -> SSELifter.shufpd ins insLen bld (* SSE2 *)
  | OP.UNPCKHPS -> SSELifter.unpckhps ins insLen bld
  | OP.UNPCKHPD -> SSELifter.unpckhpd ins insLen bld (* SSE2 *)
  | OP.UNPCKLPS -> SSELifter.unpcklps ins insLen bld
  | OP.UNPCKLPD -> SSELifter.unpcklpd ins insLen bld (* SSE2 *)
  | OP.BLENDPD -> SSELifter.blendpd ins insLen bld
  | OP.BLENDPS -> SSELifter.blendps ins insLen bld
  | OP.BLENDVPD -> SSELifter.blendvpd ins insLen bld
  | OP.BLENDVPS -> SSELifter.blendvps ins insLen bld
  | OP.CVTPI2PS -> SSELifter.cvtpi2ps ins insLen bld
  | OP.CVTPI2PD -> SSELifter.cvtpi2pd ins insLen bld (* SSE2 *)
  | OP.CVTSI2SS -> SSELifter.cvtsi2ss ins insLen bld
  | OP.CVTSI2SD -> SSELifter.cvtsi2sd ins insLen bld (* SSE2 *)
  | OP.CVTPS2PI -> SSELifter.cvtps2pi ins insLen bld true
  | OP.CVTPS2PD -> SSELifter.cvtps2pd ins insLen bld (* SSE2 *)
  | OP.CVTPD2PS -> SSELifter.cvtpd2ps ins insLen bld (* SSE2 *)
  | OP.CVTPD2PI -> SSELifter.cvtpd2pi ins insLen bld true (* SSE2 *)
  | OP.CVTPD2DQ -> SSELifter.cvtpd2dq ins insLen bld true (* SSE2 *)
  | OP.CVTTPD2DQ -> SSELifter.cvtpd2dq ins insLen bld false (* SSE2 *)
  | OP.CVTDQ2PS -> SSELifter.cvtdq2ps ins insLen bld (* SSE2 *)
  | OP.CVTDQ2PD -> SSELifter.cvtdq2pd ins insLen bld (* SSE2 *)
  | OP.CVTPS2DQ -> SSELifter.cvtps2dq ins insLen bld true (* SSE2 *)
  | OP.CVTTPS2DQ -> SSELifter.cvtps2dq ins insLen bld false (* SSE2 *)
  | OP.CVTTPS2PI -> SSELifter.cvtps2pi ins insLen bld false
  | OP.CVTTPD2PI -> SSELifter.cvtpd2pi ins insLen bld false (* SSE2 *)
  | OP.CVTSS2SI | OP.VCVTSS2SI ->
    SSELifter.cvtss2si ins insLen bld true
  | OP.CVTSS2SD -> SSELifter.cvtss2sd ins insLen bld (* SSE2 *)
  | OP.CVTSD2SS -> SSELifter.cvtsd2ss ins insLen bld (* SSE2 *)
  | OP.CVTSD2SI | OP.VCVTSD2SI -> (* SSE2 *)
    SSELifter.cvtsd2si ins insLen bld true
  | OP.CVTTSS2SI | OP.VCVTTSS2SI ->
    SSELifter.cvtss2si ins insLen bld false
  | OP.CVTTSD2SI | OP.VCVTTSD2SI -> (* SSE2 *)
    SSELifter.cvtsd2si ins insLen bld false
  | OP.EXTRACTPS -> SSELifter.extractps ins insLen bld
  | OP.LDMXCSR -> SSELifter.ldmxcsr ins insLen bld
  | OP.STMXCSR -> SSELifter.stmxcsr ins insLen bld
  | OP.PACKUSDW -> SSELifter.packusdw ins insLen bld
  | OP.PAVGB -> SSELifter.pavgb ins insLen bld
  | OP.PAVGW -> SSELifter.pavgw ins insLen bld
  | OP.PBLENDVB -> SSELifter.pblendvb ins insLen bld
  | OP.PBLENDW -> SSELifter.pblendw ins insLen bld
  | OP.PEXTRB -> SSELifter.pextrb ins insLen bld
  | OP.PEXTRD -> SSELifter.pextrd ins insLen bld
  | OP.PEXTRQ -> SSELifter.pextrq ins insLen bld
  | OP.PEXTRW -> SSELifter.pextrw ins insLen bld
  | OP.PINSRW -> SSELifter.pinsrw ins insLen bld
  | OP.PMAXUB -> SSELifter.pmaxub ins insLen bld
  | OP.PMAXUD -> SSELifter.pmaxud ins insLen bld
  | OP.PMAXUW -> SSELifter.pmaxuw ins insLen bld
  | OP.PMAXSB -> SSELifter.pmaxsb ins insLen bld
  | OP.PMAXSD -> SSELifter.pmaxsd ins insLen bld
  | OP.PMAXSW -> SSELifter.pmaxsw ins insLen bld
  | OP.PMINUB -> SSELifter.pminub ins insLen bld
  | OP.PMINUD -> SSELifter.pminud ins insLen bld
  | OP.PMINUW -> SSELifter.pminuw ins insLen bld
  | OP.PMINSB -> SSELifter.pminsb ins insLen bld
  | OP.PMINSD -> SSELifter.pminsd ins insLen bld
  | OP.PMINSW -> SSELifter.pminsw ins insLen bld
  | OP.PMOVMSKB -> SSELifter.pmovmskb ins insLen bld
  | OP.PMOVSXBW -> SSELifter.pmovbw ins insLen bld 8<rt> true (* SSE4 *)
  | OP.PMOVSXBD -> SSELifter.pmovbd ins insLen bld 8<rt> true (* SSE4 *)
  | OP.PMOVSXBQ -> SSELifter.pmovbq ins insLen bld 8<rt> true (* SSE4 *)
  | OP.PMOVSXWD -> SSELifter.pmovbw ins insLen bld 16<rt> true (* SSE4 *)
  | OP.PMOVSXWQ -> SSELifter.pmovbd ins insLen bld 16<rt> true (* SSE4 *)
  | OP.PMOVSXDQ -> SSELifter.pmovbw ins insLen bld 32<rt> true (* SSE4 *)
  | OP.PMOVZXBW -> SSELifter.pmovbw ins insLen bld 8<rt> false (* SSE4 *)
  | OP.PMOVZXBD -> SSELifter.pmovbd ins insLen bld 8<rt> false (* SSE4 *)
  | OP.PMOVZXBQ -> SSELifter.pmovbq ins insLen bld 8<rt> false (* SSE4 *)
  | OP.PMOVZXWD -> SSELifter.pmovbw ins insLen bld 16<rt> false (* SSE4 *)
  | OP.PMOVZXWQ -> SSELifter.pmovbd ins insLen bld 16<rt> false (* SSE4 *)
  | OP.PMOVZXDQ -> SSELifter.pmovbw ins insLen bld 32<rt> false (* SSE4 *)
  | OP.PMULHUW -> SSELifter.pmulhuw ins insLen bld
  | OP.PSADBW -> SSELifter.psadbw ins insLen bld
  | OP.PSHUFW -> SSELifter.pshufw ins insLen bld
  | OP.PSHUFD -> SSELifter.pshufd ins insLen bld (* SSE2 *)
  | OP.PSHUFLW -> SSELifter.pshuflw ins insLen bld (* SSE2 *)
  | OP.PSHUFHW -> SSELifter.pshufhw ins insLen bld (* SSE2 *)
  | OP.PSHUFB -> SSELifter.pshufb ins insLen bld (* SSE3 *)
  | OP.MOVDQA -> SSELifter.movdqa ins insLen bld (* SSE2 *)
  | OP.MOVDQU -> SSELifter.movdqu ins insLen bld (* SSE2 *)
  | OP.MOVQ2DQ -> SSELifter.movq2dq ins insLen bld (* SSE2 *)
  | OP.MOVDQ2Q -> SSELifter.movdq2q ins insLen bld (* SSE2 *)
  | OP.PMULUDQ -> SSELifter.pmuludq ins insLen bld (* SSE2 *)
  | OP.PADDQ -> SSELifter.paddq ins insLen bld (* SSE2 *)
  | OP.PSUBQ -> SSELifter.psubq ins insLen bld (* SSE2 *)
  | OP.PSLLDQ -> SSELifter.pslldq ins insLen bld (* SSE2 *)
  | OP.PSRLDQ -> SSELifter.psrldq ins insLen bld (* SSE2 *)
  | OP.PUNPCKHQDQ -> SSELifter.punpckhqdq ins insLen bld (* SSE2 *)
  | OP.PUNPCKLQDQ -> SSELifter.punpcklqdq ins insLen bld (* SSE2 *)
  | OP.MOVNTQ -> SSELifter.movntq ins insLen bld
  | OP.MOVNTPS -> SSELifter.movntps ins insLen bld
  | OP.PREFETCHNTA
  | OP.PREFETCHT0 | OP.PREFETCHT1
  | OP.PREFETCHW | OP.PREFETCHT2 -> GeneralLifter.nop ins.Address insLen bld
  | OP.SFENCE -> LiftingUtils.sideEffects bld ins insLen Fence
  | OP.CLFLUSH -> GeneralLifter.nop ins.Address insLen bld (* SSE2 *)
  | OP.LFENCE -> LiftingUtils.sideEffects bld ins insLen Fence (* SSE2 *)
  | OP.MFENCE -> LiftingUtils.sideEffects bld ins insLen Fence (* SSE2 *)
  | OP.PAUSE -> LiftingUtils.sideEffects bld ins insLen Delay (* SSE2 *)
  | OP.MOVNTPD -> SSELifter.movntpd ins insLen bld (* SSE2 *)
  | OP.MOVNTDQ -> SSELifter.movntdq ins insLen bld (* SSE2 *)
  | OP.MOVNTI -> SSELifter.movnti ins insLen bld (* SSE2 *)
  | OP.HADDPD -> SSELifter.haddpd ins insLen bld (* SSE3 *)
  | OP.HADDPS -> SSELifter.haddps ins insLen bld (* SSE3 *)
  | OP.HSUBPD -> SSELifter.hsubpd ins insLen bld (* SSE3 *)
  | OP.HSUBPS -> SSELifter.hsubps ins insLen bld (* SSE3 *)
  | OP.LDDQU -> SSELifter.lddqu ins insLen bld (* SSE3 *)
  | OP.MOVSHDUP -> SSELifter.movshdup ins insLen bld (* SSE3 *)
  | OP.MOVSLDUP -> SSELifter.movsldup ins insLen bld (* SSE3 *)
  | OP.MOVDDUP -> SSELifter.movddup ins insLen bld (* SSE3 *)
  | OP.PALIGNR -> SSELifter.palignr ins insLen bld (* SSE3 *)
  | OP.ROUNDSD -> SSELifter.roundsd ins insLen bld (* SSE4 *)
  | OP.PINSRB -> SSELifter.pinsrb ins insLen bld (* SSE4 *)
  | OP.PSIGNB -> SSELifter.psign ins insLen bld 8<rt> (* SSE3 *)
  | OP.PSIGNW -> SSELifter.psign ins insLen bld 16<rt> (* SSE3 *)
  | OP.PSIGND -> SSELifter.psign ins insLen bld 32<rt> (* SSE3 *)
  | OP.PTEST -> SSELifter.ptest ins insLen bld (* SSE4 *)
  | OP.PCMPEQQ -> SSELifter.pcmpeqq ins insLen bld (* SSE4 *)
  | OP.PCMPESTRI | OP.PCMPESTRM | OP.PCMPISTRI | OP.PCMPISTRM ->
    SSELifter.pcmpstr ins insLen bld (* SSE4 *)
  | OP.VSQRTPS -> AVXLifter.vsqrtps ins insLen bld
  | OP.VSQRTPD -> AVXLifter.vsqrtpd ins insLen bld
  | OP.VSQRTSS -> AVXLifter.vsqrtss ins insLen bld
  | OP.VSQRTSD -> AVXLifter.vsqrtsd ins insLen bld
  | OP.VADDPS -> AVXLifter.vaddps ins insLen bld
  | OP.VADDPD -> AVXLifter.vaddpd ins insLen bld
  | OP.VADDSS -> AVXLifter.vaddss ins insLen bld
  | OP.VADDSD -> AVXLifter.vaddsd ins insLen bld
  | OP.VBLENDVPD -> AVXLifter.vblendvpd ins insLen bld
  | OP.VBLENDVPS -> AVXLifter.vblendvps ins insLen bld
  | OP.VSUBPS -> AVXLifter.vsubps ins insLen bld
  | OP.VSUBPD -> AVXLifter.vsubpd ins insLen bld
  | OP.VSUBSS -> AVXLifter.vsubss ins insLen bld
  | OP.VSUBSD -> AVXLifter.vsubsd ins insLen bld
  | OP.VMULPS -> AVXLifter.vmulps ins insLen bld
  | OP.VMULPD -> AVXLifter.vmulpd ins insLen bld
  | OP.VMULSS -> AVXLifter.vmulss ins insLen bld
  | OP.VMULSD -> AVXLifter.vmulsd ins insLen bld
  | OP.VDIVPS -> AVXLifter.vdivps ins insLen bld
  | OP.VDIVPD -> AVXLifter.vdivpd ins insLen bld
  | OP.VDIVSS -> AVXLifter.vdivss ins insLen bld
  | OP.VDIVSD -> AVXLifter.vdivsd ins insLen bld
  | OP.VCVTSI2SS -> AVXLifter.vcvtsi2ss ins insLen bld
  | OP.VCVTSI2SD -> AVXLifter.vcvtsi2sd ins insLen bld
  | OP.VCVTSD2SS -> AVXLifter.vcvtsd2ss ins insLen bld
  | OP.VCVTSS2SD -> AVXLifter.vcvtss2sd ins insLen bld
  | OP.VMOVD -> AVXLifter.vmovd ins insLen bld
  | OP.VMOVQ -> AVXLifter.vmovq ins insLen bld
  | OP.VMOVAPS -> AVXLifter.vmovaps ins insLen bld
  | OP.VMOVAPD -> AVXLifter.vmovapd ins insLen bld
  | OP.VMOVDQU -> AVXLifter.vmovdqu ins insLen bld
  | OP.VMOVDQU16 -> AVXLifter.vmovdqu16 ins insLen bld
  | OP.VMOVDQU64 -> AVXLifter.vmovdqu64 ins insLen bld
  | OP.VMOVDQA -> AVXLifter.vmovdqa ins insLen bld
  | OP.VMOVDQA64 -> AVXLifter.vmovdqa64 ins insLen bld
  | OP.VMOVNTDQ -> AVXLifter.vmovntdq ins insLen bld
  | OP.VMOVUPS -> AVXLifter.vmovups ins insLen bld
  | OP.VMOVUPD -> AVXLifter.vmovupd ins insLen bld
  | OP.VMOVDDUP -> AVXLifter.vmovddup ins insLen bld
  | OP.VMOVNTPS -> AVXLifter.vmovntps ins insLen bld
  | OP.VMOVNTPD -> AVXLifter.vmovntpd ins insLen bld
  | OP.VMOVHLPS -> AVXLifter.vmovhlps ins insLen bld
  | OP.VMOVHPD | OP.VMOVHPS -> AVXLifter.vmovhpd ins insLen bld
  | OP.VMOVLHPS -> AVXLifter.vmovlhps ins insLen bld
  | OP.VMOVLPD | OP.VMOVLPS -> AVXLifter.vmovlpd ins insLen bld
  | OP.VMOVMSKPD -> AVXLifter.vmovmskpd ins insLen bld
  | OP.VMOVMSKPS -> AVXLifter.vmovmskps ins insLen bld
  | OP.VMOVSD -> AVXLifter.vmovsd ins insLen bld
  | OP.VMOVSHDUP -> AVXLifter.vmovshdup ins insLen bld
  | OP.VMOVSLDUP -> AVXLifter.vmovsldup ins insLen bld
  | OP.VMOVSS -> AVXLifter.vmovss ins insLen bld
  | OP.VANDPS -> AVXLifter.vandps ins insLen bld
  | OP.VANDPD -> AVXLifter.vandpd ins insLen bld
  | OP.VANDNPS -> AVXLifter.vandnps ins insLen bld
  | OP.VANDNPD -> AVXLifter.vandnpd ins insLen bld
  | OP.VORPS -> AVXLifter.vorps ins insLen bld
  | OP.VORPD -> AVXLifter.vorpd ins insLen bld
  | OP.VSHUFI32X4 -> AVXLifter.vshufi32x4 ins insLen bld
  | OP.VSHUFPS -> AVXLifter.vshufps ins insLen bld
  | OP.VSHUFPD -> AVXLifter.vshufpd ins insLen bld
  | OP.VUNPCKHPS -> AVXLifter.vunpckhps ins insLen bld
  | OP.VUNPCKHPD -> AVXLifter.vunpckhpd ins insLen bld
  | OP.VUNPCKLPS -> AVXLifter.vunpcklps ins insLen bld
  | OP.VUNPCKLPD -> AVXLifter.vunpcklpd ins insLen bld
  | OP.VXORPS -> AVXLifter.vxorps ins insLen bld
  | OP.VXORPD -> AVXLifter.vxorpd ins insLen bld
  | OP.VBROADCASTI128 -> AVXLifter.vbroadcasti128 ins insLen bld
  | OP.VBROADCASTSS -> AVXLifter.vbroadcastss ins insLen bld
  | OP.VEXTRACTF32X8 -> AVXLifter.vextracti32x8 ins insLen bld
  | OP.VEXTRACTI128 -> AVXLifter.vextracti128 ins insLen bld
  | OP.VEXTRACTI64X4 -> AVXLifter.vextracti64x4 ins insLen bld
  | OP.VEXTRACTPS -> SSELifter.extractps ins insLen bld
  | OP.VINSERTI128 -> AVXLifter.vinserti128 ins insLen bld
  | OP.VMPTRLD -> LiftingUtils.sideEffects bld ins insLen UnsupportedExtension
  | OP.VPADDB -> AVXLifter.vpaddb ins insLen bld
  | OP.VPADDD -> AVXLifter.vpaddd ins insLen bld
  | OP.VPADDQ -> AVXLifter.vpaddq ins insLen bld
  | OP.VPALIGNR -> AVXLifter.vpalignr ins insLen bld
  | OP.VPAND -> AVXLifter.vpand ins insLen bld
  | OP.VPANDN -> AVXLifter.vpandn ins insLen bld
  | OP.VPBLENDD -> AVXLifter.vpblendd ins insLen bld
  | OP.VPBLENDW -> AVXLifter.vpblendw ins insLen bld
  | OP.VPBLENDVB -> AVXLifter.vpblendvb ins insLen bld
  | OP.VPACKUSDW -> AVXLifter.vpackusdw ins insLen bld
  | OP.VPACKUSWB -> AVXLifter.vpackuswb ins insLen bld
  | OP.VPAVGB -> AVXLifter.vpavgb ins insLen bld
  | OP.VPAVGW -> AVXLifter.vpavgw ins insLen bld
  | OP.VPBROADCASTB -> AVXLifter.vpbroadcastb ins insLen bld
  | OP.VPBROADCASTW -> AVXLifter.vpbroadcastw ins insLen bld
  | OP.VPBROADCASTD -> AVXLifter.vpbroadcastd ins insLen bld
  | OP.VPCMPEQB -> AVXLifter.vpcmpeqb ins insLen bld
  | OP.VPCMPEQD -> AVXLifter.vpcmpeqd ins insLen bld
  | OP.VPCMPEQQ -> AVXLifter.vpcmpeqq ins insLen bld
  | OP.VPCMPESTRI | OP.VPCMPESTRM | OP.VPCMPISTRI
  | OP.VPCMPISTRM -> SSELifter.pcmpstr ins insLen bld
  | OP.VPCMPGTB -> AVXLifter.vpcmpgtb ins insLen bld
  | OP.VPERM2I128 -> AVXLifter.vperm2i128 ins insLen bld
  | OP.VPERMD -> AVXLifter.vpermd ins insLen bld
  | OP.VPERMQ -> AVXLifter.vpermq ins insLen bld
  | OP.VPEXTRD -> SSELifter.pextrd ins insLen bld
  | OP.VPEXTRB -> SSELifter.pextrb ins insLen bld
  | OP.VPINSRB -> AVXLifter.vpinsrb ins insLen bld
  | OP.VPINSRD -> AVXLifter.vpinsrd ins insLen bld
  | OP.VPMINSB -> AVXLifter.vpminsb ins insLen bld
  | OP.VPMINSD -> AVXLifter.vpminsd ins insLen bld
  | OP.VPMINUB -> AVXLifter.vpminub ins insLen bld
  | OP.VPMINUD -> AVXLifter.vpminud ins insLen bld
  | OP.VPMOVSXBW -> AVXLifter.vpmovx ins insLen bld 8<rt> 16<rt> true
  | OP.VPMOVSXBD -> AVXLifter.vpmovx ins insLen bld 8<rt> 32<rt> true
  | OP.VPMOVSXBQ -> AVXLifter.vpmovx ins insLen bld 8<rt> 64<rt> true
  | OP.VPMOVSXWD -> AVXLifter.vpmovx ins insLen bld 16<rt> 32<rt> true
  | OP.VPMOVSXWQ -> AVXLifter.vpmovx ins insLen bld 16<rt> 64<rt> true
  | OP.VPMOVSXDQ -> AVXLifter.vpmovx ins insLen bld 32<rt> 64<rt> true
  | OP.VPMOVZXBW -> AVXLifter.vpmovx ins insLen bld 8<rt> 16<rt> false
  | OP.VPMOVZXBD -> AVXLifter.vpmovx ins insLen bld 8<rt> 32<rt> false
  | OP.VPMOVZXBQ -> AVXLifter.vpmovx ins insLen bld 8<rt> 64<rt> false
  | OP.VPMOVZXWD -> AVXLifter.vpmovx ins insLen bld 16<rt> 32<rt> false
  | OP.VPMOVZXWQ -> AVXLifter.vpmovx ins insLen bld 16<rt> 64<rt> false
  | OP.VPMOVZXDQ -> AVXLifter.vpmovx ins insLen bld 32<rt> 64<rt> false
  | OP.VPMOVD2M -> AVXLifter.vpmovd2m ins insLen bld
  | OP.VPMOVMSKB -> SSELifter.pmovmskb ins insLen bld
  | OP.VPMULLD -> AVXLifter.vpmulld ins insLen bld
  | OP.VPMULUDQ -> AVXLifter.vpmuludq ins insLen bld
  | OP.VPMULHUW -> AVXLifter.vpmulhuw ins insLen bld
  | OP.VPMULLW -> AVXLifter.vpmullw ins insLen bld
  | OP.VPOR -> AVXLifter.vpor ins insLen bld
  | OP.VPINSRW -> AVXLifter.vpinsrw ins insLen bld
  | OP.VPSHUFB -> AVXLifter.vpshufb ins insLen bld
  | OP.VPSHUFD -> AVXLifter.vpshufd ins insLen bld
  | OP.VPSLLD -> AVXLifter.vpslld ins insLen bld
  | OP.VPSLLDQ -> AVXLifter.vpslldq ins insLen bld
  | OP.VPSLLQ -> AVXLifter.vpsllq ins insLen bld
  | OP.VPSRAD -> AVXLifter.vpsrad ins insLen bld
  | OP.VPSRAW -> AVXLifter.vpsraw ins insLen bld
  | OP.VPSRAVD -> AVXLifter.vpsravd ins insLen bld
  | OP.VPSRLD -> AVXLifter.vpsrld ins insLen bld
  | OP.VPSRLW -> AVXLifter.vpsrlw ins insLen bld
  | OP.VPSRLDQ -> AVXLifter.vpsrldq ins insLen bld
  | OP.VPSRLQ -> AVXLifter.vpsrlq ins insLen bld
  | OP.VPSUBB -> AVXLifter.vpsubb ins insLen bld
  | OP.VPSUBD -> AVXLifter.vpsubd ins insLen bld
  | OP.VPTEST -> AVXLifter.vptest ins insLen bld
  | OP.VPUNPCKHDQ -> AVXLifter.vpunpckhdq ins insLen bld
  | OP.VPUNPCKHQDQ -> AVXLifter.vpunpckhqdq ins insLen bld
  | OP.VPUNPCKHWD -> AVXLifter.vpunpckhwd ins insLen bld
  | OP.VPUNPCKLDQ -> AVXLifter.vpunpckldq ins insLen bld
  | OP.VPUNPCKLQDQ -> AVXLifter.vpunpcklqdq ins insLen bld
  | OP.VPUNPCKLWD -> AVXLifter.vpunpcklwd ins insLen bld
  | OP.VPXOR -> AVXLifter.vpxor ins insLen bld
  | OP.VPXORD -> AVXLifter.vpxord ins insLen bld
  | OP.VZEROUPPER -> AVXLifter.vzeroupper ins insLen bld
  | OP.VEXTRACTI32X8 -> AVXLifter.vextracti32x8 ins insLen bld
  | OP.VERW -> LiftingUtils.sideEffects bld ins insLen UnsupportedPrivInstr
  | OP.VFMADD132SD -> AVXLifter.vfmadd132sd ins insLen bld
  | OP.VFMADD213SD -> AVXLifter.vfmadd213sd ins insLen bld
  | OP.VFMADD231SD -> AVXLifter.vfmadd231sd ins insLen bld
  | OP.FLD -> X87Lifter.fld ins insLen bld
  | OP.FST -> X87Lifter.ffst ins insLen bld false
  | OP.FSTP -> X87Lifter.ffst ins insLen bld true
  | OP.FILD -> X87Lifter.fild ins insLen bld
  | OP.FIST -> X87Lifter.fist ins insLen bld false
  | OP.FISTP -> X87Lifter.fist ins insLen bld true
  | OP.FISTTP -> X87Lifter.fisttp ins insLen bld (* SSE3 *)
  | OP.FBLD -> X87Lifter.fbld ins insLen bld
  | OP.FBSTP -> X87Lifter.fbstp ins insLen bld
  | OP.FXCH -> X87Lifter.fxch ins insLen bld
  | OP.FCMOVE -> X87Lifter.fcmove ins insLen bld
  | OP.FCMOVNE -> X87Lifter.fcmovne ins insLen bld
  | OP.FCMOVB -> X87Lifter.fcmovb ins insLen bld
  | OP.FCMOVBE -> X87Lifter.fcmovbe ins insLen bld
  | OP.FCMOVNB -> X87Lifter.fcmovnb ins insLen bld
  | OP.FCMOVNBE -> X87Lifter.fcmovnbe ins insLen bld
  | OP.FCMOVU -> X87Lifter.fcmovu ins insLen bld
  | OP.FCMOVNU -> X87Lifter.fcmovnu ins insLen bld
  | OP.FADD -> X87Lifter.fpuadd ins insLen bld false
  | OP.FADDP -> X87Lifter.fpuadd ins insLen bld true
  | OP.FIADD -> X87Lifter.fiadd ins insLen bld
  | OP.FSUB -> X87Lifter.fpusub ins insLen bld false
  | OP.FSUBP -> X87Lifter.fpusub ins insLen bld true
  | OP.FISUB -> X87Lifter.fisub ins insLen bld
  | OP.FSUBR -> X87Lifter.fsubr ins insLen bld false
  | OP.FSUBRP -> X87Lifter.fsubr ins insLen bld true
  | OP.FISUBR  -> X87Lifter.fisubr ins insLen bld
  | OP.FMUL -> X87Lifter.fpumul ins insLen bld false
  | OP.FMULP -> X87Lifter.fpumul ins insLen bld true
  | OP.FIMUL -> X87Lifter.fimul ins insLen bld
  | OP.FDIV -> X87Lifter.fpudiv ins insLen bld false
  | OP.FDIVP -> X87Lifter.fpudiv ins insLen bld true
  | OP.FIDIV -> X87Lifter.fidiv ins insLen bld
  | OP.FDIVR -> X87Lifter.fdivr ins insLen bld false
  | OP.FDIVRP -> X87Lifter.fdivr ins insLen bld true
  | OP.FIDIVR -> X87Lifter.fidivr ins insLen bld
  | OP.FPREM -> X87Lifter.fprem ins insLen bld false
  | OP.FPREM1 -> X87Lifter.fprem ins insLen bld true
  | OP.FABS -> X87Lifter.fabs ins insLen bld
  | OP.FCHS -> X87Lifter.fchs ins insLen bld
  | OP.FRNDINT -> X87Lifter.frndint ins insLen bld
  | OP.FSCALE -> X87Lifter.fscale ins insLen bld
  | OP.FSQRT -> X87Lifter.fsqrt ins insLen bld
  | OP.FXTRACT -> X87Lifter.fxtract ins insLen bld
  | OP.FCOM -> X87Lifter.fcom ins insLen bld 0 false
  | OP.FCOMP -> X87Lifter.fcom ins insLen bld 1 false
  | OP.FCOMPP -> X87Lifter.fcom ins insLen bld 2 false
  | OP.FUCOM -> X87Lifter.fcom ins insLen bld 0 true
  | OP.FUCOMP -> X87Lifter.fcom ins insLen bld 1 true
  | OP.FUCOMPP -> X87Lifter.fcom ins insLen bld 2 true
  | OP.FICOM -> X87Lifter.ficom ins insLen bld false
  | OP.FICOMP -> X87Lifter.ficom ins insLen bld true
  | OP.FCOMI -> X87Lifter.fcomi ins insLen bld false
  | OP.FUCOMI -> X87Lifter.fcomi ins insLen bld false
  | OP.FCOMIP -> X87Lifter.fcomi ins insLen bld true
  | OP.FUCOMIP -> X87Lifter.fcomi ins insLen bld true
  | OP.FTST -> X87Lifter.ftst ins insLen bld
  | OP.FXAM -> X87Lifter.fxam ins insLen bld
  | OP.FSIN -> X87Lifter.fsin ins insLen bld
  | OP.FCOS -> X87Lifter.fcos ins insLen bld
  | OP.FSINCOS -> X87Lifter.fsincos ins insLen bld
  | OP.FPTAN -> X87Lifter.fptan ins insLen bld
  | OP.FPATAN -> X87Lifter.fpatan ins insLen bld
  | OP.F2XM1 -> X87Lifter.f2xm1 ins insLen bld
  | OP.FYL2X -> X87Lifter.fyl2x ins insLen bld
  | OP.FYL2XP1 -> X87Lifter.fyl2xp1 ins insLen bld
  | OP.FLD1 -> X87Lifter.fld1 ins insLen bld
  | OP.FLDZ -> X87Lifter.fldz ins insLen bld
  | OP.FLDPI -> X87Lifter.fldpi ins insLen bld
  | OP.FLDL2E -> X87Lifter.fldl2e ins insLen bld
  | OP.FLDLN2 -> X87Lifter.fldln2 ins insLen bld
  | OP.FLDL2T -> X87Lifter.fldl2t ins insLen bld
  | OP.FLDLG2 -> X87Lifter.fldlg2 ins insLen bld
  | OP.FINCSTP -> X87Lifter.fincstp ins insLen bld
  | OP.FDECSTP -> X87Lifter.fdecstp ins insLen bld
  | OP.FFREE -> X87Lifter.ffree ins insLen bld
  | OP.FINIT -> X87Lifter.finit ins insLen bld
  | OP.FNINIT -> X87Lifter.fninit ins insLen bld
  | OP.FCLEX -> X87Lifter.fclex ins insLen bld
  | OP.FSTCW -> X87Lifter.fstcw ins insLen bld
  | OP.FNSTCW -> X87Lifter.fnstcw ins insLen bld
  | OP.FLDCW -> X87Lifter.fldcw ins insLen bld
  | OP.FNSTENV -> X87Lifter.fnstenv ins insLen bld
  | OP.FLDENV -> X87Lifter.fldenv ins insLen bld
  | OP.FNSAVE -> X87Lifter.fnsave ins insLen bld
  | OP.FRSTOR -> X87Lifter.frstor ins insLen bld
  | OP.FNSTSW -> X87Lifter.fnstsw ins insLen bld
  | OP.WAIT -> X87Lifter.wait ins insLen bld
  | OP.FNOP -> X87Lifter.fnop ins insLen bld
  | OP.FXSAVE | OP.FXSAVE64 -> X87Lifter.fxsave ins insLen bld
  | OP.FXRSTOR | OP.FXRSTOR64 -> X87Lifter.fxrstor ins insLen bld
  | o ->
#if DEBUG
         eprintfn $"Unsupported: {Disasm.opCodeToString o}"
#endif
         LiftingUtils.sideEffects bld ins insLen UnsupportedExtension
