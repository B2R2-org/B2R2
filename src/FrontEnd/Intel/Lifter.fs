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
open B2R2.FrontEnd.BinLifter

type OP = Opcode (* Just to make it concise. *)

/// Translate IR.
let translate (ins: Instruction) bld =
  match ins.Opcode with
  | OP.AAA ->
    GeneralLifter.aaa ins bld
  | OP.AAD ->
    GeneralLifter.aad ins bld
  | OP.AAM ->
    GeneralLifter.aam ins bld
  | OP.AAS ->
    GeneralLifter.aas ins bld
  | OP.ADC ->
    GeneralLifter.adc ins bld
  | OP.ADD ->
    GeneralLifter.add ins bld
  | OP.ADOX ->
    GeneralLifter.adox ins bld
  | OP.AND ->
    GeneralLifter.``and`` ins bld
  | OP.ANDN ->
    GeneralLifter.andn ins bld
  | OP.ARPL ->
    GeneralLifter.arpl ins bld
  | OP.BEXTR ->
    GeneralLifter.bextr ins bld
  | OP.BLSI ->
    GeneralLifter.blsi ins bld
  | OP.BNDMOV ->
    GeneralLifter.bndmov ins bld
  | OP.BOUND ->
    GeneralLifter.nop ins bld
  | OP.BSF ->
    GeneralLifter.bsf ins bld
  | OP.BSR ->
    GeneralLifter.bsr ins bld
  | OP.BSWAP ->
    GeneralLifter.bswap ins bld
  | OP.BT ->
    GeneralLifter.bt ins bld
  | OP.BTC ->
    GeneralLifter.btc ins bld
  | OP.BTR ->
    GeneralLifter.btr ins bld
  | OP.BTS ->
    GeneralLifter.bts ins bld
  | OP.BZHI ->
    GeneralLifter.bzhi ins bld
  | OP.CALL when ins.IsFar ->
    LiftingUtils.unsupported ins bld
  | OP.CALL ->
    GeneralLifter.call ins bld
  | OP.CBW | OP.CWDE | OP.CDQE ->
    GeneralLifter.convBWQ ins bld
  | OP.CLC ->
    GeneralLifter.clearFlag ins bld R.CF
  | OP.CLD ->
    GeneralLifter.clearFlag ins bld R.DF
  | OP.CLI ->
    GeneralLifter.clearFlag ins bld R.IF
  | OP.CLRSSBSY ->
    GeneralLifter.nop ins bld
  | OP.CLTS ->
    LiftingUtils.unsupported ins bld
  | OP.CMC ->
    GeneralLifter.cmc ins bld
  | OP.CMOVO | OP.CMOVNO | OP.CMOVB | OP.CMOVAE
  | OP.CMOVZ | OP.CMOVNZ | OP.CMOVBE | OP.CMOVA
  | OP.CMOVS  | OP.CMOVNS | OP.CMOVP | OP.CMOVNP
  | OP.CMOVL | OP.CMOVGE | OP.CMOVLE | OP.CMOVG ->
    GeneralLifter.cmovcc ins bld
  | OP.CMP ->
    GeneralLifter.cmp ins bld
  | OP.CMPSB | OP.CMPSW | OP.CMPSQ ->
    GeneralLifter.cmps ins bld
  | OP.CMPXCHG ->
    GeneralLifter.cmpxchg ins bld
  | OP.CMPXCHG8B | OP.CMPXCHG16B ->
    GeneralLifter.compareExchangeBytes ins bld
  | OP.CPUID ->
    LiftingUtils.sideEffects ins bld ProcessorInfoRead
  | OP.CRC32 ->
    GeneralLifter.crc32 ins bld
  | OP.CWD | OP.CDQ | OP.CQO ->
    GeneralLifter.convWDQ ins bld
  | OP.DAA ->
    GeneralLifter.daa ins bld
  | OP.DAS ->
    GeneralLifter.das ins bld
  | OP.DEC ->
    GeneralLifter.dec ins bld
  | OP.DIV | OP.IDIV ->
    GeneralLifter.div ins bld
  | OP.ENDBR32 | OP.ENDBR64 ->
    GeneralLifter.nop ins bld
  | OP.ENTER ->
    GeneralLifter.enter ins bld
  | OP.HLT ->
    LiftingUtils.sideEffects ins bld Terminate
  | OP.IMUL ->
    GeneralLifter.imul ins bld
  | OP.INC ->
    GeneralLifter.inc ins bld
  | OP.INCSSPD | OP.INCSSPQ ->
    GeneralLifter.nop ins bld
  | OP.INSB | OP.INSW | OP.INSD ->
    LiftingUtils.unsupported ins bld
  | OP.INT | OP.INTO ->
    GeneralLifter.interrupt ins bld
  | OP.INT3 ->
    LiftingUtils.sideEffects ins bld Breakpoint
  | OP.JMP ->
    GeneralLifter.jmp ins bld
  | OP.JO | OP.JNO | OP.JB | OP.JNB
  | OP.JZ | OP.JNZ | OP.JBE | OP.JA
  | OP.JS | OP.JNS | OP.JP | OP.JNP
  | OP.JL | OP.JNL | OP.JLE | OP.JG
  | OP.JECXZ | OP.JRCXZ ->
    GeneralLifter.jcc ins bld
  | OP.LAHF ->
    GeneralLifter.lahf ins bld
  | OP.LEA ->
    GeneralLifter.lea ins bld
  | OP.LEAVE ->
    GeneralLifter.leave ins bld
  | OP.LODSB | OP.LODSW | OP.LODSD | OP.LODSQ ->
    GeneralLifter.lods ins bld
  | OP.LOOP | OP.LOOPE | OP.LOOPNE ->
    GeneralLifter.loop ins bld
  | OP.LZCNT ->
    GeneralLifter.lzcnt ins bld
  | OP.LDS | OP.LES | OP.LFS | OP.LGS | OP.LSS ->
    LiftingUtils.unsupported ins bld
  | OP.MOV ->
    GeneralLifter.mov ins bld
  | OP.MOVBE ->
    GeneralLifter.movbe ins bld
  | OP.MOVSB | OP.MOVSW | OP.MOVSQ ->
    GeneralLifter.movs ins bld
  | OP.MOVSX | OP.MOVSXD ->
    GeneralLifter.movsx ins bld
  | OP.MOVZX ->
    GeneralLifter.movzx ins bld
  | OP.MUL ->
    GeneralLifter.mul ins bld
  | OP.MULX ->
    GeneralLifter.mulx ins bld
  | OP.NEG ->
    GeneralLifter.neg ins bld
  | OP.NOP ->
    GeneralLifter.nop ins bld
  | OP.NOT ->
    GeneralLifter.not ins bld
  | OP.OR ->
    GeneralLifter.logOr ins bld
  | OP.OUTSB | OP.OUTSW | OP.OUTSD ->
    LiftingUtils.unsupported ins bld
  | OP.PDEP ->
    GeneralLifter.pdep ins bld
  | OP.PEXT ->
    GeneralLifter.pext ins bld
  | OP.POP ->
    GeneralLifter.pop ins bld
  | OP.POPA ->
    GeneralLifter.popa ins bld 16<rt>
  | OP.POPAD ->
    GeneralLifter.popa ins bld 32<rt>
  | OP.POPCNT ->
    GeneralLifter.popcnt ins bld
  | OP.POPF | OP.POPFD | OP.POPFQ ->
    GeneralLifter.popf ins bld
  | OP.PUSH ->
    GeneralLifter.push ins bld
  | OP.PUSHA ->
    GeneralLifter.pusha ins bld 16<rt>
  | OP.PUSHAD ->
    GeneralLifter.pusha ins bld 32<rt>
  | OP.PUSHF | OP.PUSHFD | OP.PUSHFQ ->
    GeneralLifter.pushf ins bld
  | OP.RCL ->
    GeneralLifter.rcl ins bld
  | OP.RCR ->
    GeneralLifter.rcr ins bld
  | OP.RDMSR | OP.RSM ->
    LiftingUtils.unsupported ins bld
  | OP.RDPKRU ->
    GeneralLifter.rdpkru ins bld
  | OP.RDPMC ->
    LiftingUtils.unsupported ins bld
  | OP.RDRAND ->
    LiftingUtils.unsupported ins bld
  | OP.RDSSPD | OP.RDSSPQ ->
    GeneralLifter.nop ins bld
  | OP.RDTSC ->
    LiftingUtils.sideEffects ins bld (ClockCounterRead None)
  | OP.RDTSCP ->
    LiftingUtils.sideEffects ins bld (ClockCounterRead None)
  | OP.RET when ins.IsFar ->
    LiftingUtils.unsupported ins bld
  | OP.RET ->
    GeneralLifter.ret ins bld
  | OP.ROL ->
    GeneralLifter.rol ins bld
  | OP.ROR ->
    GeneralLifter.ror ins bld
  | OP.RORX ->
    GeneralLifter.rorx ins bld
  | OP.RSTORSSP ->
    GeneralLifter.nop ins bld
  | OP.SAHF ->
    GeneralLifter.sahf ins bld
  | OP.SAR | OP.SHR | OP.SHL ->
    GeneralLifter.shift ins bld
  | OP.SAVEPREVSSP ->
    GeneralLifter.nop ins bld
  | OP.SBB ->
    GeneralLifter.sbb ins bld
  | OP.SCASB | OP.SCASW | OP.SCASD | OP.SCASQ ->
    GeneralLifter.scas ins bld
  | OP.SETO | OP.SETNO | OP.SETB | OP.SETNB
  | OP.SETZ | OP.SETNZ | OP.SETBE | OP.SETA
  | OP.SETS | OP.SETNS | OP.SETP | OP.SETNP
  | OP.SETL | OP.SETNL | OP.SETLE | OP.SETG ->
    GeneralLifter.setcc ins bld
  | OP.SETSSBSY ->
    GeneralLifter.nop ins bld
  | OP.SHLD ->
    GeneralLifter.shld ins bld
  | OP.SARX ->
    GeneralLifter.sarx ins bld
  | OP.SHLX ->
    GeneralLifter.shlx ins bld
  | OP.SHRX ->
    GeneralLifter.shrx ins bld
  | OP.SHRD ->
    GeneralLifter.shrd ins bld
  | OP.STC ->
    GeneralLifter.stc ins bld
  | OP.STD ->
    GeneralLifter.std ins bld
  | OP.STI ->
    GeneralLifter.sti ins bld
  | OP.STOSB | OP.STOSW | OP.STOSD | OP.STOSQ ->
    GeneralLifter.stos ins bld
  | OP.SUB ->
    GeneralLifter.sub ins bld
  | OP.SYSCALL | OP.SYSENTER ->
    LiftingUtils.sideEffects ins bld SysCall
  | OP.SYSEXIT | OP.SYSRET ->
    LiftingUtils.unsupported ins bld
  | OP.TEST ->
    GeneralLifter.test ins bld
  | OP.TZCNT ->
    GeneralLifter.tzcnt ins bld
  (* The encodings that exist in order to fault: the three Intel reserves for
     it, and D6, which this parser calls UDB and its table admits in 64-bit
     mode only, where no instruction claims it. Only UD2 used to say so, the
     rest reaching the catch-all and coming back as an instruction merely
     awaiting implementation. *)
  | OP.UD0 | OP.UD1 | OP.UD2 | OP.UDB ->
    LiftingUtils.undefined ins bld
  | OP.WBINVD ->
    LiftingUtils.unsupported ins bld
  | OP.WRFSBASE ->
    GeneralLifter.wrfsbase ins bld
  | OP.WRGSBASE ->
    GeneralLifter.wrgsbase ins bld
  | OP.WRPKRU ->
    GeneralLifter.wrpkru ins bld
  | OP.WRMSR ->
    LiftingUtils.unsupported ins bld
  | OP.WRSSD | OP.WRSSQ ->
    GeneralLifter.nop ins bld
  | OP.WRUSSD | OP.WRUSSQ ->
    GeneralLifter.nop ins bld
  | OP.XABORT ->
    LiftingUtils.unsupported ins bld
  | OP.XADD ->
    GeneralLifter.xadd ins bld
  | OP.XBEGIN ->
    LiftingUtils.unsupported ins bld
  | OP.XCHG ->
    GeneralLifter.xchg ins bld
  | OP.XEND ->
    LiftingUtils.unsupported ins bld
  | OP.XGETBV ->
    LiftingUtils.unsupported ins bld
  | OP.XLATB ->
    GeneralLifter.xlatb ins bld
  | OP.XOR ->
    GeneralLifter.xor ins bld
  | OP.XRSTOR | OP.XRSTORS | OP.XSAVE | OP.XSAVEC
  | OP.XSAVEC64 | OP.XSAVEOPT | OP.XSAVES | OP.XSAVES64 ->
    LiftingUtils.unsupported ins bld
  | OP.XTEST ->
    LiftingUtils.unsupported ins bld
  | OP.IN | OP.INVD | OP.INVLPG | OP.IRET | OP.IRETQ | OP.IRETW | OP.IRETD
  | OP.LAR | OP.LGDT | OP.LIDT | OP.LLDT
  | OP.LMSW | OP.LSL | OP.LTR | OP.OUT | OP.SGDT
  | OP.SIDT | OP.SLDT | OP.SMSW | OP.STR | OP.VERR ->
    LiftingUtils.unsupported ins bld
  | OP.SHA1NEXTE | OP.SHA1MSG1 | OP.SHA1MSG2 | OP.SHA256RNDS2 | OP.SHA256MSG1
  | OP.SHA256MSG2 | OP.SHA1RNDS4 ->
    LiftingUtils.unsupported ins bld
  | OP.MOVD ->
    MMXLifter.movd ins bld
  | OP.MOVQ ->
    MMXLifter.movq ins bld
  | OP.PACKSSDW ->
    MMXLifter.packssdw ins bld
  | OP.PACKSSWB ->
    MMXLifter.packsswb ins bld
  | OP.PACKUSWB ->
    MMXLifter.packuswb ins bld
  | OP.PUNPCKHBW ->
    MMXLifter.punpckhbw ins bld
  | OP.PUNPCKHWD ->
    MMXLifter.punpckhwd ins bld
  | OP.PUNPCKHDQ ->
    MMXLifter.punpckhdq ins bld
  | OP.PUNPCKLBW ->
    MMXLifter.punpcklbw ins bld
  | OP.PUNPCKLWD ->
    MMXLifter.punpcklwd ins bld
  | OP.PUNPCKLDQ ->
    MMXLifter.punpckldq ins bld
  | OP.PADDB ->
    MMXLifter.paddb ins bld
  | OP.PADDW ->
    MMXLifter.paddw ins bld
  | OP.PADDD ->
    MMXLifter.paddd ins bld
  | OP.PADDSB ->
    MMXLifter.paddsb ins bld
  | OP.PADDSW ->
    MMXLifter.paddsw ins bld
  | OP.PADDUSB ->
    MMXLifter.paddusb ins bld
  | OP.PADDUSW ->
    MMXLifter.paddusw ins bld
  | OP.PHADDD ->
    MMXLifter.phaddd ins bld
  | OP.PHADDW ->
    MMXLifter.phaddw ins bld
  | OP.PHADDSW ->
    MMXLifter.phaddsw ins bld
  | OP.PSUBB ->
    MMXLifter.psubb ins bld
  | OP.PSUBW ->
    MMXLifter.psubw ins bld
  | OP.PSUBD ->
    MMXLifter.psubd ins bld
  | OP.PSUBSB ->
    MMXLifter.psubsb ins bld
  | OP.PSUBSW ->
    MMXLifter.psubsw ins bld
  | OP.PSUBUSB ->
    MMXLifter.psubusb ins bld
  | OP.PSUBUSW ->
    MMXLifter.psubusw ins bld
  | OP.PHSUBD ->
    MMXLifter.phsubd ins bld
  | OP.PHSUBW ->
    MMXLifter.phsubw ins bld
  | OP.PHSUBSW ->
    MMXLifter.phsubsw ins bld
  | OP.PMULHW ->
    MMXLifter.pmulhw ins bld
  | OP.PMULLW ->
    MMXLifter.pmullw ins bld
  | OP.PMULLD ->
    SSELifter.pmulld ins bld
  | OP.PMADDWD ->
    MMXLifter.pmaddwd ins bld
  | OP.PCMPEQB ->
    MMXLifter.pcmpeqb ins bld
  | OP.PCMPEQW ->
    MMXLifter.pcmpeqw ins bld
  | OP.PCMPEQD ->
    MMXLifter.pcmpeqd ins bld
  | OP.PCMPGTB ->
    MMXLifter.pcmpgtb ins bld
  | OP.PCMPGTW ->
    MMXLifter.pcmpgtw ins bld
  | OP.PCMPGTD ->
    MMXLifter.pcmpgtd ins bld
  | OP.PAND ->
    MMXLifter.pand ins bld
  | OP.PANDN ->
    MMXLifter.pandn ins bld
  | OP.POR ->
    MMXLifter.por ins bld
  | OP.PXOR ->
    MMXLifter.pxor ins bld
  | OP.PSLLW ->
    MMXLifter.psllw ins bld
  | OP.PSLLD ->
    MMXLifter.pslld ins bld
  | OP.PSLLQ ->
    MMXLifter.psllq ins bld
  | OP.PSRLW ->
    MMXLifter.psrlw ins bld
  | OP.PSRLD ->
    MMXLifter.psrld ins bld
  | OP.PSRLQ ->
    MMXLifter.psrlq ins bld
  | OP.PSRAW ->
    MMXLifter.psraw ins bld
  | OP.PSRAD ->
    MMXLifter.psrad ins bld
  | OP.EMMS ->
    MMXLifter.emms ins bld
  | OP.ADDSUBPD ->
    SSELifter.addsubpd ins bld
  | OP.ADDSUBPS ->
    SSELifter.addsubps ins bld
  | OP.MOVAPS ->
    SSELifter.movaps ins bld
  | OP.MOVAPD ->
    SSELifter.movapd ins bld (* SSE2 *)
  | OP.MOVUPS ->
    SSELifter.movups ins bld
  | OP.MOVUPD ->
    SSELifter.movupd ins bld (* SSE2 *)
  | OP.MOVHPS ->
    SSELifter.movhps ins bld
  | OP.MOVHPD ->
    SSELifter.movhpd ins bld (* SSE2 *)
  | OP.MOVHLPS ->
    SSELifter.movhlps ins bld
  | OP.MOVLPS ->
    SSELifter.movlps ins bld
  | OP.MOVLPD ->
    SSELifter.movlpd ins bld (* SSE2 *)
  | OP.MOVLHPS ->
    SSELifter.movlhps ins bld
  | OP.MOVMSKPS ->
    SSELifter.movmskps ins bld
  | OP.MOVMSKPD ->
    SSELifter.movmskpd ins bld (* SSE2 *)
  | OP.MOVSS ->
    SSELifter.movss ins bld
  | OP.MOVSD ->
    SSELifter.movsd ins bld (* SSE2 *)
  | OP.ADDPS ->
    SSELifter.addps ins bld
  | OP.ADDPD ->
    SSELifter.addpd ins bld (* SSE2 *)
  | OP.ADDSS ->
    SSELifter.addss ins bld
  | OP.ADDSD ->
    SSELifter.addsd ins bld (* SSE2 *)
  | OP.SUBPS ->
    SSELifter.subps ins bld
  | OP.SUBPD ->
    SSELifter.subpd ins bld (* SSE2 *)
  | OP.SUBSS ->
    SSELifter.subss ins bld
  | OP.SUBSD ->
    SSELifter.subsd ins bld (* SSE2 *)
  | OP.MULPS ->
    SSELifter.mulps ins bld
  | OP.MULPD ->
    SSELifter.mulpd ins bld (* SSE2 *)
  | OP.MULSS ->
    SSELifter.mulss ins bld
  | OP.MULSD ->
    SSELifter.mulsd ins bld (* SSE2 *)
  | OP.DIVPS ->
    SSELifter.divps ins bld
  | OP.DIVPD ->
    SSELifter.divpd ins bld (* SSE2 *)
  | OP.DIVSS ->
    SSELifter.divss ins bld
  | OP.DIVSD ->
    SSELifter.divsd ins bld (* SSE2 *)
  | OP.RCPPS ->
    SSELifter.rcpps ins bld
  | OP.RCPSS ->
    SSELifter.rcpss ins bld
  | OP.SQRTPS ->
    SSELifter.sqrtps ins bld
  | OP.SQRTPD ->
    SSELifter.sqrtpd ins bld (* SSE2 *)
  | OP.SQRTSS ->
    SSELifter.sqrtss ins bld
  | OP.SQRTSD ->
    SSELifter.sqrtsd ins bld (* SSE2 *)
  | OP.RSQRTPS ->
    SSELifter.rsqrtps ins bld
  | OP.RSQRTSS ->
    SSELifter.rsqrtss ins bld
  | OP.MAXPS ->
    SSELifter.maxps ins bld
  | OP.MAXPD ->
    SSELifter.maxpd ins bld (* SSE2 *)
  | OP.MAXSS ->
    SSELifter.maxss ins bld
  | OP.MAXSD ->
    SSELifter.maxsd ins bld (* SSE2 *)
  | OP.MINPS ->
    SSELifter.minps ins bld
  | OP.MINPD ->
    SSELifter.minpd ins bld (* SSE2 *)
  | OP.MINSS ->
    SSELifter.minss ins bld
  | OP.MINSD ->
    SSELifter.minsd ins bld (* SSE2 *)
  | OP.CMPPS ->
    SSELifter.cmpps ins bld
  | OP.CMPPD ->
    SSELifter.cmppd ins bld (* SSE2 *)
  | OP.CMPSS ->
    SSELifter.cmpss ins bld
  | OP.CMPSD ->
    SSELifter.cmpsd ins bld (* SSE2 *)
  | OP.COMISS | OP.VCOMISS ->
    SSELifter.comiss ins bld
  | OP.COMISD | OP.VCOMISD -> (* SSE2 *)
    SSELifter.comisd ins bld
  | OP.UCOMISS | OP.VUCOMISS ->
    SSELifter.ucomiss ins bld
  | OP.UCOMISD | OP.VUCOMISD -> (* SSE2 *)
    SSELifter.ucomisd ins bld
  | OP.ANDPS ->
    SSELifter.andps ins bld
  | OP.ANDPD ->
    SSELifter.andpd ins bld (* SSE2 *)
  | OP.ANDNPS ->
    SSELifter.andnps ins bld
  | OP.ANDNPD ->
    SSELifter.andnpd ins bld (* SSE2 *)
  | OP.ORPS ->
    SSELifter.orps ins bld
  | OP.ORPD ->
    SSELifter.orpd ins bld (* SSE2 *)
  | OP.XORPS ->
    SSELifter.xorps ins bld
  | OP.XORPD ->
    SSELifter.xorpd ins bld (* SSE2 *)
  | OP.XSETBV ->
    LiftingUtils.unsupported ins bld
  | OP.SHUFPS ->
    SSELifter.shufps ins bld
  | OP.SHUFPD ->
    SSELifter.shufpd ins bld (* SSE2 *)
  | OP.UNPCKHPS ->
    SSELifter.unpckhps ins bld
  | OP.UNPCKHPD ->
    SSELifter.unpckhpd ins bld (* SSE2 *)
  | OP.UNPCKLPS ->
    SSELifter.unpcklps ins bld
  | OP.UNPCKLPD ->
    SSELifter.unpcklpd ins bld (* SSE2 *)
  | OP.BLENDPD ->
    SSELifter.blendpd ins bld
  | OP.BLENDPS ->
    SSELifter.blendps ins bld
  | OP.BLENDVPD ->
    SSELifter.blendvpd ins bld
  | OP.BLENDVPS ->
    SSELifter.blendvps ins bld
  | OP.CVTPI2PS ->
    SSELifter.cvtpi2ps ins bld
  | OP.CVTPI2PD ->
    SSELifter.cvtpi2pd ins bld (* SSE2 *)
  | OP.CVTSI2SS ->
    SSELifter.cvtsi2ss ins bld
  | OP.CVTSI2SD ->
    SSELifter.cvtsi2sd ins bld (* SSE2 *)
  | OP.CVTPS2PI ->
    SSELifter.cvtps2pi ins bld true
  | OP.CVTPS2PD ->
    SSELifter.cvtps2pd ins bld (* SSE2 *)
  | OP.CVTPD2PS ->
    SSELifter.cvtpd2ps ins bld (* SSE2 *)
  | OP.CVTPD2PI ->
    SSELifter.cvtpd2pi ins bld true (* SSE2 *)
  | OP.CVTPD2DQ ->
    SSELifter.cvtpd2dq ins bld true (* SSE2 *)
  | OP.CVTTPD2DQ ->
    SSELifter.cvtpd2dq ins bld false (* SSE2 *)
  | OP.CVTDQ2PS ->
    SSELifter.cvtdq2ps ins bld (* SSE2 *)
  | OP.CVTDQ2PD ->
    SSELifter.cvtdq2pd ins bld (* SSE2 *)
  | OP.CVTPS2DQ ->
    SSELifter.cvtps2dq ins bld true (* SSE2 *)
  | OP.CVTTPS2DQ ->
    SSELifter.cvtps2dq ins bld false (* SSE2 *)
  | OP.CVTTPS2PI ->
    SSELifter.cvtps2pi ins bld false
  | OP.CVTTPD2PI ->
    SSELifter.cvtpd2pi ins bld false (* SSE2 *)
  | OP.CVTSS2SI | OP.VCVTSS2SI ->
    SSELifter.cvtss2si ins bld true
  | OP.CVTSS2SD ->
    SSELifter.cvtss2sd ins bld (* SSE2 *)
  | OP.CVTSD2SS ->
    SSELifter.cvtsd2ss ins bld (* SSE2 *)
  | OP.CVTSD2SI | OP.VCVTSD2SI -> (* SSE2 *)
    SSELifter.cvtsd2si ins bld true
  | OP.CVTTSS2SI | OP.VCVTTSS2SI ->
    SSELifter.cvtss2si ins bld false
  | OP.CVTTSD2SI | OP.VCVTTSD2SI -> (* SSE2 *)
    SSELifter.cvtsd2si ins bld false
  | OP.EXTRACTPS ->
    SSELifter.extractps ins bld
  | OP.LDMXCSR ->
    SSELifter.ldmxcsr ins bld
  | OP.STMXCSR ->
    SSELifter.stmxcsr ins bld
  | OP.PACKUSDW ->
    SSELifter.packusdw ins bld
  | OP.PAVGB ->
    SSELifter.pavgb ins bld
  | OP.PAVGW ->
    SSELifter.pavgw ins bld
  | OP.PBLENDVB ->
    SSELifter.pblendvb ins bld
  | OP.PBLENDW ->
    SSELifter.pblendw ins bld
  | OP.PEXTRB ->
    SSELifter.pextrb ins bld
  | OP.PEXTRD ->
    SSELifter.pextrd ins bld
  | OP.PEXTRQ ->
    SSELifter.pextrq ins bld
  | OP.PEXTRW ->
    SSELifter.pextrw ins bld
  | OP.PINSRW ->
    SSELifter.pinsrw ins bld
  | OP.PMAXUB ->
    SSELifter.pmaxub ins bld
  | OP.PMAXUD ->
    SSELifter.pmaxud ins bld
  | OP.PMAXUW ->
    SSELifter.pmaxuw ins bld
  | OP.PMAXSB ->
    SSELifter.pmaxsb ins bld
  | OP.PMAXSD ->
    SSELifter.pmaxsd ins bld
  | OP.PMAXSW ->
    SSELifter.pmaxsw ins bld
  | OP.PMINUB ->
    SSELifter.pminub ins bld
  | OP.PMINUD ->
    SSELifter.pminud ins bld
  | OP.PMINUW ->
    SSELifter.pminuw ins bld
  | OP.PMINSB ->
    SSELifter.pminsb ins bld
  | OP.PMINSD ->
    SSELifter.pminsd ins bld
  | OP.PMINSW ->
    SSELifter.pminsw ins bld
  | OP.PMOVMSKB ->
    SSELifter.pmovmskb ins bld
  | OP.PMOVSXBW ->
    SSELifter.pmovbw ins bld 8<rt> true (* SSE4 *)
  | OP.PMOVSXBD ->
    SSELifter.pmovbd ins bld 8<rt> true (* SSE4 *)
  | OP.PMOVSXBQ ->
    SSELifter.pmovbq ins bld 8<rt> true (* SSE4 *)
  | OP.PMOVSXWD ->
    SSELifter.pmovbw ins bld 16<rt> true (* SSE4 *)
  | OP.PMOVSXWQ ->
    SSELifter.pmovbd ins bld 16<rt> true (* SSE4 *)
  | OP.PMOVSXDQ ->
    SSELifter.pmovbw ins bld 32<rt> true (* SSE4 *)
  | OP.PMOVZXBW ->
    SSELifter.pmovbw ins bld 8<rt> false (* SSE4 *)
  | OP.PMOVZXBD ->
    SSELifter.pmovbd ins bld 8<rt> false (* SSE4 *)
  | OP.PMOVZXBQ ->
    SSELifter.pmovbq ins bld 8<rt> false (* SSE4 *)
  | OP.PMOVZXWD ->
    SSELifter.pmovbw ins bld 16<rt> false (* SSE4 *)
  | OP.PMOVZXWQ ->
    SSELifter.pmovbd ins bld 16<rt> false (* SSE4 *)
  | OP.PMOVZXDQ ->
    SSELifter.pmovbw ins bld 32<rt> false (* SSE4 *)
  | OP.PMULHUW ->
    SSELifter.pmulhuw ins bld
  | OP.PSADBW ->
    SSELifter.psadbw ins bld
  | OP.PSHUFW ->
    SSELifter.pshufw ins bld
  | OP.PSHUFD ->
    SSELifter.pshufd ins bld (* SSE2 *)
  | OP.PSHUFLW ->
    SSELifter.pshuflw ins bld (* SSE2 *)
  | OP.PSHUFHW ->
    SSELifter.pshufhw ins bld (* SSE2 *)
  | OP.PSHUFB ->
    SSELifter.pshufb ins bld (* SSE3 *)
  | OP.MOVDQA ->
    SSELifter.movdqa ins bld (* SSE2 *)
  | OP.MOVDQU ->
    SSELifter.movdqu ins bld (* SSE2 *)
  | OP.MOVQ2DQ ->
    SSELifter.movq2dq ins bld (* SSE2 *)
  | OP.MOVDQ2Q ->
    SSELifter.movdq2q ins bld (* SSE2 *)
  | OP.PMULUDQ ->
    SSELifter.pmuludq ins bld (* SSE2 *)
  | OP.PADDQ ->
    SSELifter.paddq ins bld (* SSE2 *)
  | OP.PSUBQ ->
    SSELifter.psubq ins bld (* SSE2 *)
  | OP.PSLLDQ ->
    SSELifter.pslldq ins bld (* SSE2 *)
  | OP.PSRLDQ ->
    SSELifter.psrldq ins bld (* SSE2 *)
  | OP.PUNPCKHQDQ ->
    SSELifter.punpckhqdq ins bld (* SSE2 *)
  | OP.PUNPCKLQDQ ->
    SSELifter.punpcklqdq ins bld (* SSE2 *)
  | OP.MOVNTQ ->
    SSELifter.movntq ins bld
  | OP.MOVNTPS ->
    SSELifter.movntps ins bld
  | OP.PREFETCHNTA
  | OP.PREFETCHT0 | OP.PREFETCHT1
  | OP.PREFETCHW | OP.PREFETCHT2 ->
    GeneralLifter.nop ins bld
  | OP.SFENCE ->
    LiftingUtils.sideEffects ins bld Fence
  | OP.CLFLUSH ->
    GeneralLifter.nop ins bld (* SSE2 *)
  | OP.LFENCE ->
    LiftingUtils.sideEffects ins bld Fence (* SSE2 *)
  | OP.MFENCE ->
    LiftingUtils.sideEffects ins bld Fence (* SSE2 *)
  | OP.PAUSE ->
    LiftingUtils.sideEffects ins bld Delay (* SSE2 *)
  | OP.MOVNTPD ->
    SSELifter.movntpd ins bld (* SSE2 *)
  | OP.MOVNTDQ ->
    SSELifter.movntdq ins bld (* SSE2 *)
  | OP.MOVNTI ->
    SSELifter.movnti ins bld (* SSE2 *)
  | OP.HADDPD ->
    SSELifter.haddpd ins bld (* SSE3 *)
  | OP.HADDPS ->
    SSELifter.haddps ins bld (* SSE3 *)
  | OP.HSUBPD ->
    SSELifter.hsubpd ins bld (* SSE3 *)
  | OP.HSUBPS ->
    SSELifter.hsubps ins bld (* SSE3 *)
  | OP.LDDQU ->
    SSELifter.lddqu ins bld (* SSE3 *)
  | OP.MOVSHDUP ->
    SSELifter.movshdup ins bld (* SSE3 *)
  | OP.MOVSLDUP ->
    SSELifter.movsldup ins bld (* SSE3 *)
  | OP.MOVDDUP ->
    SSELifter.movddup ins bld (* SSE3 *)
  | OP.PALIGNR ->
    SSELifter.palignr ins bld (* SSE3 *)
  | OP.ROUNDSD ->
    SSELifter.roundsd ins bld (* SSE4 *)
  | OP.PINSRB ->
    SSELifter.pinsrb ins bld (* SSE4 *)
  | OP.PSIGNB ->
    SSELifter.psign ins bld 8<rt> (* SSE3 *)
  | OP.PSIGNW ->
    SSELifter.psign ins bld 16<rt> (* SSE3 *)
  | OP.PSIGND ->
    SSELifter.psign ins bld 32<rt> (* SSE3 *)
  | OP.PTEST ->
    SSELifter.ptest ins bld (* SSE4 *)
  | OP.PCMPEQQ ->
    SSELifter.pcmpeqq ins bld (* SSE4 *)
  | OP.PCMPESTRI | OP.PCMPESTRM | OP.PCMPISTRI | OP.PCMPISTRM ->
    SSELifter.pcmpstr ins bld (* SSE4 *)
  | OP.VSQRTPS ->
    AVXLifter.vsqrtps ins bld
  | OP.VSQRTPD ->
    AVXLifter.vsqrtpd ins bld
  | OP.VSQRTSS ->
    AVXLifter.vsqrtss ins bld
  | OP.VSQRTSD ->
    AVXLifter.vsqrtsd ins bld
  | OP.VADDPS ->
    AVXLifter.vaddps ins bld
  | OP.VADDPD ->
    AVXLifter.vaddpd ins bld
  | OP.VADDSS ->
    AVXLifter.vaddss ins bld
  | OP.VADDSD ->
    AVXLifter.vaddsd ins bld
  | OP.VBLENDVPD ->
    AVXLifter.vblendvpd ins bld
  | OP.VBLENDVPS ->
    AVXLifter.vblendvps ins bld
  | OP.VSUBPS ->
    AVXLifter.vsubps ins bld
  | OP.VSUBPD ->
    AVXLifter.vsubpd ins bld
  | OP.VSUBSS ->
    AVXLifter.vsubss ins bld
  | OP.VSUBSD ->
    AVXLifter.vsubsd ins bld
  | OP.VMULPS ->
    AVXLifter.vmulps ins bld
  | OP.VMULPD ->
    AVXLifter.vmulpd ins bld
  | OP.VMULSS ->
    AVXLifter.vmulss ins bld
  | OP.VMULSD ->
    AVXLifter.vmulsd ins bld
  | OP.VDIVPS ->
    AVXLifter.vdivps ins bld
  | OP.VDIVPD ->
    AVXLifter.vdivpd ins bld
  | OP.VDIVSS ->
    AVXLifter.vdivss ins bld
  | OP.VDIVSD ->
    AVXLifter.vdivsd ins bld
  | OP.VCVTSI2SS ->
    AVXLifter.vcvtsi2ss ins bld
  | OP.VCVTSI2SD ->
    AVXLifter.vcvtsi2sd ins bld
  | OP.VCVTSD2SS ->
    AVXLifter.vcvtsd2ss ins bld
  | OP.VCVTSS2SD ->
    AVXLifter.vcvtss2sd ins bld
  | OP.VMOVD ->
    AVXLifter.vmovd ins bld
  | OP.VMOVQ ->
    AVXLifter.vmovq ins bld
  | OP.VMOVAPS ->
    AVXLifter.vmovaps ins bld
  | OP.VMOVAPD ->
    AVXLifter.vmovapd ins bld
  | OP.VMOVDQU ->
    AVXLifter.vmovdqu ins bld
  | OP.VMOVDQU16 ->
    AVXLifter.vmovdqu16 ins bld
  | OP.VMOVDQU64 ->
    AVXLifter.vmovdqu64 ins bld
  | OP.VMOVDQA ->
    AVXLifter.vmovdqa ins bld
  | OP.VMOVDQA64 ->
    AVXLifter.vmovdqa64 ins bld
  | OP.VMOVNTDQ ->
    AVXLifter.vmovntdq ins bld
  | OP.VMOVUPS ->
    AVXLifter.vmovups ins bld
  | OP.VMOVUPD ->
    AVXLifter.vmovupd ins bld
  | OP.VMOVDDUP ->
    AVXLifter.vmovddup ins bld
  | OP.VMOVNTPS ->
    AVXLifter.vmovntps ins bld
  | OP.VMOVNTPD ->
    AVXLifter.vmovntpd ins bld
  | OP.VMOVHLPS ->
    AVXLifter.vmovhlps ins bld
  | OP.VMOVHPD | OP.VMOVHPS ->
    AVXLifter.vmovhpd ins bld
  | OP.VMOVLHPS ->
    AVXLifter.vmovlhps ins bld
  | OP.VMOVLPD | OP.VMOVLPS ->
    AVXLifter.vmovlpd ins bld
  | OP.VMOVMSKPD ->
    AVXLifter.vmovmskpd ins bld
  | OP.VMOVMSKPS ->
    AVXLifter.vmovmskps ins bld
  | OP.VMOVSD ->
    AVXLifter.vmovsd ins bld
  | OP.VMOVSHDUP ->
    AVXLifter.vmovshdup ins bld
  | OP.VMOVSLDUP ->
    AVXLifter.vmovsldup ins bld
  | OP.VMOVSS ->
    AVXLifter.vmovss ins bld
  | OP.VANDPS ->
    AVXLifter.vandps ins bld
  | OP.VANDPD ->
    AVXLifter.vandpd ins bld
  | OP.VANDNPS ->
    AVXLifter.vandnps ins bld
  | OP.VANDNPD ->
    AVXLifter.vandnpd ins bld
  | OP.VORPS ->
    AVXLifter.vorps ins bld
  | OP.VORPD ->
    AVXLifter.vorpd ins bld
  | OP.VSHUFI32X4 ->
    AVXLifter.vshufi32x4 ins bld
  | OP.VSHUFPS ->
    AVXLifter.vshufps ins bld
  | OP.VSHUFPD ->
    AVXLifter.vshufpd ins bld
  | OP.VUNPCKHPS ->
    AVXLifter.vunpckhps ins bld
  | OP.VUNPCKHPD ->
    AVXLifter.vunpckhpd ins bld
  | OP.VUNPCKLPS ->
    AVXLifter.vunpcklps ins bld
  | OP.VUNPCKLPD ->
    AVXLifter.vunpcklpd ins bld
  | OP.VXORPS ->
    AVXLifter.vxorps ins bld
  | OP.VXORPD ->
    AVXLifter.vxorpd ins bld
  | OP.VBROADCASTI128 ->
    AVXLifter.vbroadcasti128 ins bld
  | OP.VBROADCASTSS ->
    AVXLifter.vbroadcastss ins bld
  | OP.VEXTRACTF32X8 ->
    AVXLifter.vextracti32x8 ins bld
  | OP.VEXTRACTI128 ->
    AVXLifter.vextracti128 ins bld
  | OP.VEXTRACTI64X4 ->
    AVXLifter.vextracti64x4 ins bld
  | OP.VEXTRACTPS ->
    SSELifter.extractps ins bld
  | OP.VINSERTI128 ->
    AVXLifter.vinserti128 ins bld
  | OP.VMPTRLD ->
    LiftingUtils.unsupported ins bld
  | OP.VPADDB ->
    AVXLifter.vpaddb ins bld
  | OP.VPADDD ->
    AVXLifter.vpaddd ins bld
  | OP.VPADDQ ->
    AVXLifter.vpaddq ins bld
  | OP.VPALIGNR ->
    AVXLifter.vpalignr ins bld
  | OP.VPAND ->
    AVXLifter.vpand ins bld
  | OP.VPANDN ->
    AVXLifter.vpandn ins bld
  | OP.VPBLENDD ->
    AVXLifter.vpblendd ins bld
  | OP.VPBLENDW ->
    AVXLifter.vpblendw ins bld
  | OP.VPBLENDVB ->
    AVXLifter.vpblendvb ins bld
  | OP.VPACKUSDW ->
    AVXLifter.vpackusdw ins bld
  | OP.VPACKUSWB ->
    AVXLifter.vpackuswb ins bld
  | OP.VPAVGB ->
    AVXLifter.vpavgb ins bld
  | OP.VPAVGW ->
    AVXLifter.vpavgw ins bld
  | OP.VPBROADCASTB ->
    AVXLifter.vpbroadcastb ins bld
  | OP.VPBROADCASTW ->
    AVXLifter.vpbroadcastw ins bld
  | OP.VPBROADCASTD ->
    AVXLifter.vpbroadcastd ins bld
  | OP.VPCMPEQB ->
    AVXLifter.vpcmpeqb ins bld
  | OP.VPCMPEQD ->
    AVXLifter.vpcmpeqd ins bld
  | OP.VPCMPEQQ ->
    AVXLifter.vpcmpeqq ins bld
  | OP.VPCMPESTRI | OP.VPCMPESTRM | OP.VPCMPISTRI
  | OP.VPCMPISTRM ->
    SSELifter.pcmpstr ins bld
  | OP.VPCMPGTB ->
    AVXLifter.vpcmpgtb ins bld
  | OP.VPERM2I128 ->
    AVXLifter.vperm2i128 ins bld
  | OP.VPERMD ->
    AVXLifter.vpermd ins bld
  | OP.VPERMQ ->
    AVXLifter.vpermq ins bld
  | OP.VPEXTRD ->
    SSELifter.pextrd ins bld
  | OP.VPEXTRB ->
    SSELifter.pextrb ins bld
  | OP.VPINSRB ->
    AVXLifter.vpinsrb ins bld
  | OP.VPINSRD ->
    AVXLifter.vpinsrd ins bld
  | OP.VPMINSB ->
    AVXLifter.vpminsb ins bld
  | OP.VPMINSD ->
    AVXLifter.vpminsd ins bld
  | OP.VPMINUB ->
    AVXLifter.vpminub ins bld
  | OP.VPMINUD ->
    AVXLifter.vpminud ins bld
  | OP.VPMOVSXBW ->
    AVXLifter.vpmovx ins bld 8<rt> 16<rt> true
  | OP.VPMOVSXBD ->
    AVXLifter.vpmovx ins bld 8<rt> 32<rt> true
  | OP.VPMOVSXBQ ->
    AVXLifter.vpmovx ins bld 8<rt> 64<rt> true
  | OP.VPMOVSXWD ->
    AVXLifter.vpmovx ins bld 16<rt> 32<rt> true
  | OP.VPMOVSXWQ ->
    AVXLifter.vpmovx ins bld 16<rt> 64<rt> true
  | OP.VPMOVSXDQ ->
    AVXLifter.vpmovx ins bld 32<rt> 64<rt> true
  | OP.VPMOVZXBW ->
    AVXLifter.vpmovx ins bld 8<rt> 16<rt> false
  | OP.VPMOVZXBD ->
    AVXLifter.vpmovx ins bld 8<rt> 32<rt> false
  | OP.VPMOVZXBQ ->
    AVXLifter.vpmovx ins bld 8<rt> 64<rt> false
  | OP.VPMOVZXWD ->
    AVXLifter.vpmovx ins bld 16<rt> 32<rt> false
  | OP.VPMOVZXWQ ->
    AVXLifter.vpmovx ins bld 16<rt> 64<rt> false
  | OP.VPMOVZXDQ ->
    AVXLifter.vpmovx ins bld 32<rt> 64<rt> false
  | OP.VPMOVD2M ->
    AVXLifter.vpmovd2m ins bld
  | OP.VPMOVMSKB ->
    SSELifter.pmovmskb ins bld
  | OP.VPMULLD ->
    AVXLifter.vpmulld ins bld
  | OP.VPMULUDQ ->
    AVXLifter.vpmuludq ins bld
  | OP.VPMULHUW ->
    AVXLifter.vpmulhuw ins bld
  | OP.VPMULLW ->
    AVXLifter.vpmullw ins bld
  | OP.VPOR ->
    AVXLifter.vpor ins bld
  | OP.VPINSRW ->
    AVXLifter.vpinsrw ins bld
  | OP.VPSHUFB ->
    AVXLifter.vpshufb ins bld
  | OP.VPSHUFD ->
    AVXLifter.vpshufd ins bld
  | OP.VPSLLD ->
    AVXLifter.vpslld ins bld
  | OP.VPSLLDQ ->
    AVXLifter.vpslldq ins bld
  | OP.VPSLLQ ->
    AVXLifter.vpsllq ins bld
  | OP.VPSRAD ->
    AVXLifter.vpsrad ins bld
  | OP.VPSRAW ->
    AVXLifter.vpsraw ins bld
  | OP.VPSRAVD ->
    AVXLifter.vpsravd ins bld
  | OP.VPSRLD ->
    AVXLifter.vpsrld ins bld
  | OP.VPSRLW ->
    AVXLifter.vpsrlw ins bld
  | OP.VPSRLDQ ->
    AVXLifter.vpsrldq ins bld
  | OP.VPSRLQ ->
    AVXLifter.vpsrlq ins bld
  | OP.VPSUBB ->
    AVXLifter.vpsubb ins bld
  | OP.VPSUBD ->
    AVXLifter.vpsubd ins bld
  | OP.VPTEST ->
    AVXLifter.vptest ins bld
  | OP.VPUNPCKHDQ ->
    AVXLifter.vpunpckhdq ins bld
  | OP.VPUNPCKHQDQ ->
    AVXLifter.vpunpckhqdq ins bld
  | OP.VPUNPCKHWD ->
    AVXLifter.vpunpckhwd ins bld
  | OP.VPUNPCKLDQ ->
    AVXLifter.vpunpckldq ins bld
  | OP.VPUNPCKLQDQ ->
    AVXLifter.vpunpcklqdq ins bld
  | OP.VPUNPCKLWD ->
    AVXLifter.vpunpcklwd ins bld
  | OP.VPXOR ->
    AVXLifter.vpxor ins bld
  | OP.VPXORD ->
    AVXLifter.vpxord ins bld
  | OP.VZEROUPPER ->
    AVXLifter.vzeroupper ins bld
  | OP.VEXTRACTI32X8 ->
    AVXLifter.vextracti32x8 ins bld
  | OP.VERW ->
    LiftingUtils.unsupported ins bld
  | OP.VFMADD132SD ->
    AVXLifter.vfmadd132sd ins bld
  | OP.VFMADD213SD ->
    AVXLifter.vfmadd213sd ins bld
  | OP.VFMADD231SD ->
    AVXLifter.vfmadd231sd ins bld
  | OP.FLD ->
    X87Lifter.fld ins bld
  | OP.FST ->
    X87Lifter.ffst ins bld false
  | OP.FSTP ->
    X87Lifter.ffst ins bld true
  | OP.FILD ->
    X87Lifter.fild ins bld
  | OP.FIST ->
    X87Lifter.fist ins bld false
  | OP.FISTP ->
    X87Lifter.fist ins bld true
  | OP.FISTTP ->
    X87Lifter.fisttp ins bld (* SSE3 *)
  | OP.FBLD ->
    X87Lifter.fbld ins bld
  | OP.FBSTP ->
    X87Lifter.fbstp ins bld
  | OP.FXCH ->
    X87Lifter.fxch ins bld
  | OP.FCMOVE ->
    X87Lifter.fcmove ins bld
  | OP.FCMOVNE ->
    X87Lifter.fcmovne ins bld
  | OP.FCMOVB ->
    X87Lifter.fcmovb ins bld
  | OP.FCMOVBE ->
    X87Lifter.fcmovbe ins bld
  | OP.FCMOVNB ->
    X87Lifter.fcmovnb ins bld
  | OP.FCMOVNBE ->
    X87Lifter.fcmovnbe ins bld
  | OP.FCMOVU ->
    X87Lifter.fcmovu ins bld
  | OP.FCMOVNU ->
    X87Lifter.fcmovnu ins bld
  | OP.FADD ->
    X87Lifter.fpuadd ins bld false
  | OP.FADDP ->
    X87Lifter.fpuadd ins bld true
  | OP.FIADD ->
    X87Lifter.fiadd ins bld
  | OP.FSUB ->
    X87Lifter.fpusub ins bld false
  | OP.FSUBP ->
    X87Lifter.fpusub ins bld true
  | OP.FISUB ->
    X87Lifter.fisub ins bld
  | OP.FSUBR ->
    X87Lifter.fsubr ins bld false
  | OP.FSUBRP ->
    X87Lifter.fsubr ins bld true
  | OP.FISUBR ->
    X87Lifter.fisubr ins bld
  | OP.FMUL ->
    X87Lifter.fpumul ins bld false
  | OP.FMULP ->
    X87Lifter.fpumul ins bld true
  | OP.FIMUL ->
    X87Lifter.fimul ins bld
  | OP.FDIV ->
    X87Lifter.fpudiv ins bld false
  | OP.FDIVP ->
    X87Lifter.fpudiv ins bld true
  | OP.FIDIV ->
    X87Lifter.fidiv ins bld
  | OP.FDIVR ->
    X87Lifter.fdivr ins bld false
  | OP.FDIVRP ->
    X87Lifter.fdivr ins bld true
  | OP.FIDIVR ->
    X87Lifter.fidivr ins bld
  | OP.FPREM ->
    X87Lifter.fprem ins bld false
  | OP.FPREM1 ->
    X87Lifter.fprem ins bld true
  | OP.FABS ->
    X87Lifter.fabs ins bld
  | OP.FCHS ->
    X87Lifter.fchs ins bld
  | OP.FRNDINT ->
    X87Lifter.frndint ins bld
  | OP.FSCALE ->
    X87Lifter.fscale ins bld
  | OP.FSQRT ->
    X87Lifter.fsqrt ins bld
  | OP.FXTRACT ->
    X87Lifter.fxtract ins bld
  | OP.FCOM ->
    X87Lifter.fcom ins bld 0 false
  | OP.FCOMP ->
    X87Lifter.fcom ins bld 1 false
  | OP.FCOMPP ->
    X87Lifter.fcom ins bld 2 false
  | OP.FUCOM ->
    X87Lifter.fcom ins bld 0 true
  | OP.FUCOMP ->
    X87Lifter.fcom ins bld 1 true
  | OP.FUCOMPP ->
    X87Lifter.fcom ins bld 2 true
  | OP.FICOM ->
    X87Lifter.ficom ins bld false
  | OP.FICOMP ->
    X87Lifter.ficom ins bld true
  | OP.FCOMI ->
    X87Lifter.fcomi ins bld false
  | OP.FUCOMI ->
    X87Lifter.fcomi ins bld false
  | OP.FCOMIP ->
    X87Lifter.fcomi ins bld true
  | OP.FUCOMIP ->
    X87Lifter.fcomi ins bld true
  | OP.FTST ->
    X87Lifter.ftst ins bld
  | OP.FXAM ->
    X87Lifter.fxam ins bld
  | OP.FSIN ->
    X87Lifter.fsin ins bld
  | OP.FCOS ->
    X87Lifter.fcos ins bld
  | OP.FSINCOS ->
    X87Lifter.fsincos ins bld
  | OP.FPTAN ->
    X87Lifter.fptan ins bld
  | OP.FPATAN ->
    X87Lifter.fpatan ins bld
  | OP.F2XM1 ->
    X87Lifter.f2xm1 ins bld
  | OP.FYL2X ->
    X87Lifter.fyl2x ins bld
  | OP.FYL2XP1 ->
    X87Lifter.fyl2xp1 ins bld
  | OP.FLD1 ->
    X87Lifter.fld1 ins bld
  | OP.FLDZ ->
    X87Lifter.fldz ins bld
  | OP.FLDPI ->
    X87Lifter.fldpi ins bld
  | OP.FLDL2E ->
    X87Lifter.fldl2e ins bld
  | OP.FLDLN2 ->
    X87Lifter.fldln2 ins bld
  | OP.FLDL2T ->
    X87Lifter.fldl2t ins bld
  | OP.FLDLG2 ->
    X87Lifter.fldlg2 ins bld
  | OP.FINCSTP ->
    X87Lifter.fincstp ins bld
  | OP.FDECSTP ->
    X87Lifter.fdecstp ins bld
  | OP.FFREE ->
    X87Lifter.ffree ins bld
  | OP.FINIT ->
    X87Lifter.finit ins bld
  | OP.FNINIT ->
    X87Lifter.fninit ins bld
  | OP.FCLEX ->
    X87Lifter.fclex ins bld
  | OP.FSTCW ->
    X87Lifter.fstcw ins bld
  | OP.FNSTCW ->
    X87Lifter.fnstcw ins bld
  | OP.FLDCW ->
    X87Lifter.fldcw ins bld
  | OP.FNSTENV ->
    X87Lifter.fnstenv ins bld
  | OP.FLDENV ->
    X87Lifter.fldenv ins bld
  | OP.FNSAVE ->
    X87Lifter.fnsave ins bld
  | OP.FRSTOR ->
    X87Lifter.frstor ins bld
  | OP.FNSTSW ->
    X87Lifter.fnstsw ins bld
  | OP.WAIT ->
    X87Lifter.wait ins bld
  | OP.FNOP ->
    X87Lifter.fnop ins bld
  | OP.FXSAVE | OP.FXSAVE64 ->
    X87Lifter.fxsave ins bld
  | OP.FXRSTOR | OP.FXRSTOR64 ->
    X87Lifter.fxrstor ins bld
  | o ->
    raise <| NotImplementedIRException(Opcode.toString o)
