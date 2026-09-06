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
  | OP.ADCX ->
    GeneralLifter.adcx ins bld
  | OP.ADD ->
    GeneralLifter.add ins bld
  | OP.ADOX ->
    GeneralLifter.adox ins bld
  | OP.AESENC ->
    SSELifter.aesenc ins bld
  | OP.AESENCLAST ->
    SSELifter.aesenclast ins bld
  | OP.AESDEC ->
    SSELifter.aesdec ins bld
  | OP.AESDECLAST ->
    SSELifter.aesdeclast ins bld
  | OP.AESIMC ->
    SSELifter.aesimc ins bld
  | OP.AESKEYGENASSIST ->
    SSELifter.aeskeygenassist ins bld
  | OP.GF2P8MULB ->
    SSELifter.gf2p8mulb ins bld
  | OP.GF2P8AFFINEQB ->
    SSELifter.gf2p8affineqb ins bld
  | OP.GF2P8AFFINEINVQB ->
    SSELifter.gf2p8affineinvqb ins bld
  | OP.PCLMULQDQ ->
    SSELifter.pclmulqdq ins bld
  | OP.VAESENC ->
    AVXLifter.vaesenc ins bld
  | OP.VAESENCLAST ->
    AVXLifter.vaesenclast ins bld
  | OP.VAESDEC ->
    AVXLifter.vaesdec ins bld
  | OP.VAESDECLAST ->
    AVXLifter.vaesdeclast ins bld
  | OP.VAESIMC ->
    AVXLifter.vaesimc ins bld
  | OP.VAESKEYGENASSIST ->
    AVXLifter.vaeskeygenassist ins bld
  | OP.VPCLMULQDQ ->
    AVXLifter.vpclmulqdq ins bld
  | OP.BLSR ->
    GeneralLifter.blsr ins bld
  | OP.BLSMSK ->
    GeneralLifter.blsmsk ins bld
  | OP.RDFSBASE ->
    GeneralLifter.rdfsbase ins bld
  | OP.RDGSBASE ->
    GeneralLifter.rdgsbase ins bld
  | OP.MASKMOVDQU ->
    SSELifter.maskmovdqu ins bld
  | OP.MASKMOVQ ->
    SSELifter.maskmovq ins bld
  (* MOVDIRI is a store that bypasses the cache, and the bypass is all that
     sets it apart: what it writes, and where, is what MOV writes. *)
  | OP.MOVDIRI ->
    GeneralLifter.mov ins bld
  (* Hints to the cache and to the trace unit. An emulator has neither to hint
     at, and the architecture guarantees nothing they change. *)
  | OP.CLDEMOTE | OP.CLFLUSHOPT | OP.CLWB | OP.PREFETCHIT0 | OP.PREFETCHIT1
  | OP.PREFETCHWT1 | OP.PTWRITE | OP.XRESLDTRK | OP.XSUSLDTRK ->
    GeneralLifter.nop ins bld
  | OP.SERIALIZE ->
    LiftingUtils.sideEffects ins bld Fence
  (* ICEBP: an interrupt of its own, undocumented but every debugger's. *)
  | OP.INT1 ->
    LiftingUtils.sideEffects ins bld Breakpoint
  (* A prefix the parser met with nothing it can prefix, which faults. *)
  | OP.LOCK | OP.XACQUIRE | OP.XRELEASE ->
    LiftingUtils.undefined ins bld
  (* Extensions whose architectural state this emulator does not keep: the
     tile registers of AMX, Key Locker's internal wrapping key, the user
     interrupt state, and the bounds registers of MPX. Every one of them needs
     a design decision before a lifter would mean anything, so each says so
     rather than being quietly wrong. *)
  | OP.LDTILECFG | OP.STTILECFG | OP.TILELOADD | OP.TILELOADDT1
  | OP.TILERELEASE | OP.TILESTORED | OP.TILEZERO
  | OP.TDPBF16PS | OP.TDPBSSD | OP.TDPBSUD | OP.TDPBUSD | OP.TDPBUUD
  | OP.TDPFP16PS
  | OP.AESDEC128KL | OP.AESDEC256KL | OP.AESDECWIDE128KL | OP.AESDECWIDE256KL
  | OP.AESENC128KL | OP.AESENC256KL | OP.AESENCWIDE128KL | OP.AESENCWIDE256KL
  | OP.ENCODEKEY128 | OP.ENCODEKEY256 | OP.LOADIWKEY
  | OP.CLUI | OP.STUI | OP.TESTUI | OP.SENDUIPI | OP.UIRET
  | OP.BNDCL | OP.BNDCN | OP.BNDCU | OP.BNDLDX | OP.BNDMK | OP.BNDSTX ->
    LiftingUtils.unsupported ins bld
  (* Privileged, or resting on a platform facility with no model here: the
     MSR list forms, the accelerator enqueue stores, the configuration and
     history-reset leaves, and the monitor-wait family. *)
  | OP.RDMSRLIST | OP.WRMSRLIST | OP.WRMSRNS | OP.PCONFIG | OP.HRESET
  | OP.WBNOINVD | OP.ENQCMD | OP.ENQCMDS | OP.MOVDIR64B
  | OP.TPAUSE | OP.UMONITOR | OP.UMWAIT ->
    LiftingUtils.unsupported ins bld
  (* A random source and a processor id this emulator does not pretend to
     have, alongside the compare-and-add family whose flag semantics are not
     modelled yet. *)
  | OP.RDSEED | OP.RDPID
  | OP.CMPBEXADD | OP.CMPBXADD | OP.CMPLEXADD | OP.CMPLXADD | OP.CMPNBEXADD
  | OP.CMPNBXADD | OP.CMPNLEXADD | OP.CMPNLXADD | OP.CMPNOXADD | OP.CMPNPXADD
  | OP.CMPNSXADD | OP.CMPNZXADD | OP.CMPOXADD | OP.CMPPXADD | OP.CMPSXADD
  | OP.CMPZXADD ->
    LiftingUtils.unsupported ins bld
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
  | OP.CMOVL | OP.CMOVGE | OP.CMOVLE | OP.CMOVG
  (* The names the manual gives the same condition twice over. *)
  | OP.CMOVE | OP.CMOVNA | OP.CMOVNAE | OP.CMOVNBE
  | OP.CMOVNC | OP.CMOVNGE | OP.CMOVNL | OP.CMOVPO ->
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
  | OP.JNE | OP.JNG | OP.JNLE | OP.JPE
  | OP.JCXZ | OP.JECXZ | OP.JRCXZ ->
    GeneralLifter.jcc ins bld
  | OP.KADDB ->
    OpMaskLifter.kaddb ins bld
  | OP.KADDW ->
    OpMaskLifter.kaddw ins bld
  | OP.KADDD ->
    OpMaskLifter.kaddd ins bld
  | OP.KADDQ ->
    OpMaskLifter.kaddq ins bld
  | OP.KANDB ->
    OpMaskLifter.kandb ins bld
  | OP.KANDW ->
    OpMaskLifter.kandw ins bld
  | OP.KANDD ->
    OpMaskLifter.kandd ins bld
  | OP.KANDQ ->
    OpMaskLifter.kandq ins bld
  | OP.KANDNB ->
    OpMaskLifter.kandnb ins bld
  | OP.KANDNW ->
    OpMaskLifter.kandnw ins bld
  | OP.KANDND ->
    OpMaskLifter.kandnd ins bld
  | OP.KANDNQ ->
    OpMaskLifter.kandnq ins bld
  | OP.KMOVB ->
    OpMaskLifter.kmovb ins bld
  | OP.KMOVW ->
    OpMaskLifter.kmovw ins bld
  | OP.KMOVD ->
    OpMaskLifter.kmovd ins bld
  | OP.KMOVQ ->
    OpMaskLifter.kmovq ins bld
  | OP.KNOTB ->
    OpMaskLifter.knotb ins bld
  | OP.KNOTW ->
    OpMaskLifter.knotw ins bld
  | OP.KNOTD ->
    OpMaskLifter.knotd ins bld
  | OP.KNOTQ ->
    OpMaskLifter.knotq ins bld
  | OP.KORB ->
    OpMaskLifter.korb ins bld
  | OP.KORW ->
    OpMaskLifter.korw ins bld
  | OP.KORD ->
    OpMaskLifter.kord ins bld
  | OP.KORQ ->
    OpMaskLifter.korq ins bld
  | OP.KORTESTB ->
    OpMaskLifter.kortestb ins bld
  | OP.KORTESTW ->
    OpMaskLifter.kortestw ins bld
  | OP.KORTESTD ->
    OpMaskLifter.kortestd ins bld
  | OP.KORTESTQ ->
    OpMaskLifter.kortestq ins bld
  | OP.KSHIFTLB ->
    OpMaskLifter.kshiftlb ins bld
  | OP.KSHIFTLW ->
    OpMaskLifter.kshiftlw ins bld
  | OP.KSHIFTLD ->
    OpMaskLifter.kshiftld ins bld
  | OP.KSHIFTLQ ->
    OpMaskLifter.kshiftlq ins bld
  | OP.KSHIFTRB ->
    OpMaskLifter.kshiftrb ins bld
  | OP.KSHIFTRW ->
    OpMaskLifter.kshiftrw ins bld
  | OP.KSHIFTRD ->
    OpMaskLifter.kshiftrd ins bld
  | OP.KSHIFTRQ ->
    OpMaskLifter.kshiftrq ins bld
  | OP.KTESTB ->
    OpMaskLifter.ktestb ins bld
  | OP.KTESTW ->
    OpMaskLifter.ktestw ins bld
  | OP.KTESTD ->
    OpMaskLifter.ktestd ins bld
  | OP.KTESTQ ->
    OpMaskLifter.ktestq ins bld
  | OP.KUNPCKBW ->
    OpMaskLifter.kunpckbw ins bld
  | OP.KUNPCKWD ->
    OpMaskLifter.kunpckwd ins bld
  | OP.KUNPCKDQ ->
    OpMaskLifter.kunpckdq ins bld
  | OP.KXNORB ->
    OpMaskLifter.kxnorb ins bld
  | OP.KXNORW ->
    OpMaskLifter.kxnorw ins bld
  | OP.KXNORD ->
    OpMaskLifter.kxnord ins bld
  | OP.KXNORQ ->
    OpMaskLifter.kxnorq ins bld
  | OP.KXORB ->
    OpMaskLifter.kxorb ins bld
  | OP.KXORW ->
    OpMaskLifter.kxorw ins bld
  | OP.KXORD ->
    OpMaskLifter.kxord ins bld
  | OP.KXORQ ->
    OpMaskLifter.kxorq ins bld
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
  | OP.SETL | OP.SETNL | OP.SETLE | OP.SETG
  | OP.SETAE | OP.SETNAE | OP.SETNLE ->
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
    GeneralLifter.xgetbv ins bld
  | OP.XLATB ->
    GeneralLifter.xlatb ins bld
  | OP.XOR ->
    GeneralLifter.xor ins bld
  | OP.XSAVE | OP.XSAVE64 | OP.XSAVEOPT | OP.XSAVEOPT64 ->
    X87Lifter.xsave ins bld
  | OP.XSAVEC | OP.XSAVEC64 ->
    X87Lifter.xsavec ins bld
  | OP.XRSTOR | OP.XRSTOR64 ->
    X87Lifter.xrstor ins bld
  | OP.XTEST ->
    LiftingUtils.unsupported ins bld
  (* What a user-mode guest cannot execute at all: each of these faults outside
     ring 0, or outside the I/O privilege level, so the fault is what they mean
     here -- and to an analysis reading one, that it has reached kernel code.
     Lifting them to a side effect says exactly that. Letting them fall through
     to the catch-all instead raises out of the lifter, which is no answer for
     a tool that is only disassembling a kernel image. *)
  | OP.CLAC | OP.GETSEC | OP.IN | OP.INVD | OP.INVLPG | OP.INVPCID
  | OP.IRET | OP.IRETQ | OP.IRETW | OP.IRETD
  | OP.LAR | OP.LGDT | OP.LIDT | OP.LLDT
  | OP.LMSW | OP.LSL | OP.LTR | OP.MONITOR | OP.MWAIT | OP.OUT | OP.SGDT
  | OP.SIDT | OP.SLDT | OP.SMSW | OP.STAC | OP.STR | OP.SWAPGS
  | OP.VERR | OP.XRSTORS | OP.XRSTORS64 | OP.XSAVES | OP.XSAVES64 ->
    LiftingUtils.unsupported ins bld
  | OP.SHA1NEXTE ->
    SSELifter.sha1nexte ins bld
  | OP.SHA1MSG1 ->
    SSELifter.sha1msg1 ins bld
  | OP.SHA1MSG2 ->
    SSELifter.sha1msg2 ins bld
  | OP.SHA1RNDS4 ->
    SSELifter.sha1rnds4 ins bld
  | OP.SHA256RNDS2 ->
    SSELifter.sha256rnds2 ins bld
  | OP.SHA256MSG1 ->
    SSELifter.sha256msg1 ins bld
  | OP.SHA256MSG2 ->
    SSELifter.sha256msg2 ins bld
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
  | OP.PMADDUBSW ->
    MMXLifter.pmaddubsw ins bld
  | OP.PMULHRSW ->
    MMXLifter.pmulhrsw ins bld
  | OP.PABSB ->
    MMXLifter.pabsb ins bld
  | OP.PABSW ->
    MMXLifter.pabsw ins bld
  | OP.PABSD ->
    MMXLifter.pabsd ins bld
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
  | OP.PCMPGTQ ->
    MMXLifter.pcmpgtq ins bld
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
  | OP.MPSADBW ->
    SSELifter.mpsadbw ins bld
  | OP.PHMINPOSUW ->
    SSELifter.phminposuw ins bld
  | OP.DPPD ->
    SSELifter.dppd ins bld
  | OP.DPPS ->
    SSELifter.dpps ins bld
  | OP.INSERTPS ->
    SSELifter.insertps ins bld
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
  | OP.PMULDQ ->
    SSELifter.pmuldq ins bld (* SSE4.1 *)
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
  | OP.MOVNTDQA ->
    SSELifter.movntdqa ins bld (* SSE4.1 *)
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
  | OP.ROUNDPD ->
    SSELifter.roundpd ins bld
  | OP.ROUNDPS ->
    SSELifter.roundps ins bld
  | OP.ROUNDSS ->
    SSELifter.roundss ins bld
  | OP.ROUNDSD ->
    SSELifter.roundsd ins bld (* SSE4 *)
  | OP.PINSRD ->
    SSELifter.pinsrd ins bld
  | OP.PINSRQ ->
    SSELifter.pinsrq ins bld
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
  | OP.VMOVDQU8 ->
    AVXLifter.vmovdqu8 ins bld
  | OP.VMOVDQU16 ->
    AVXLifter.vmovdqu16 ins bld
  | OP.VMOVDQU32 ->
    AVXLifter.vmovdqu32 ins bld
  | OP.VMOVDQA32 ->
    AVXLifter.vmovdqa32 ins bld
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
    AVX512Lifter.vshufi32x4 ins bld
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
    AVX512Lifter.vextractf32x8 ins bld
  | OP.VEXTRACTI128 ->
    AVXLifter.vextracti128 ins bld
  | OP.VEXTRACTI64X4 ->
    AVX512Lifter.vextracti64x4 ins bld
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
  (* The VEX forms of the packed integer operations. *)
  (* The VEX forms whose operation is the legacy one exactly: the lifter
     reads its sources through the shim that answers for either encoding,
     and clears the register above the vector length where the encoding
     is a VEX one. *)
  | OP.VPHADDD ->
    MMXLifter.phaddd ins bld
  | OP.VPHADDW ->
    MMXLifter.phaddw ins bld
  | OP.VPHADDSW ->
    MMXLifter.phaddsw ins bld
  | OP.VPHSUBD ->
    MMXLifter.phsubd ins bld
  | OP.VPHSUBW ->
    MMXLifter.phsubw ins bld
  | OP.VPHSUBSW ->
    MMXLifter.phsubsw ins bld
  | OP.VHADDPD ->
    SSELifter.haddpd ins bld
  | OP.VHADDPS ->
    SSELifter.haddps ins bld
  | OP.VHSUBPD ->
    SSELifter.hsubpd ins bld
  | OP.VHSUBPS ->
    SSELifter.hsubps ins bld
  | OP.VPACKSSDW ->
    MMXLifter.packssdw ins bld
  | OP.VPACKSSWB ->
    MMXLifter.packsswb ins bld
  | OP.VPSIGNB ->
    SSELifter.psign ins bld 8<rt>
  | OP.VPSIGNW ->
    SSELifter.psign ins bld 16<rt>
  | OP.VPSIGND ->
    SSELifter.psign ins bld 32<rt>
  | OP.VPSADBW ->
    SSELifter.psadbw ins bld
  | OP.VMAXPD ->
    SSELifter.maxpd ins bld
  | OP.VMAXPS ->
    SSELifter.maxps ins bld
  | OP.VMAXSD ->
    SSELifter.maxsd ins bld
  | OP.VMAXSS ->
    SSELifter.maxss ins bld
  | OP.VMINPD ->
    SSELifter.minpd ins bld
  | OP.VMINPS ->
    SSELifter.minps ins bld
  | OP.VMINSD ->
    SSELifter.minsd ins bld
  | OP.VMINSS ->
    SSELifter.minss ins bld
  | OP.VADDSUBPD ->
    SSELifter.addsubpd ins bld
  | OP.VADDSUBPS ->
    SSELifter.addsubps ins bld
  | OP.VPHMINPOSUW ->
    SSELifter.phminposuw ins bld
  | OP.VMOVNTDQA ->
    SSELifter.movntdqa ins bld
  | OP.VLDDQU ->
    SSELifter.lddqu ins bld
  | OP.VLDMXCSR ->
    SSELifter.ldmxcsr ins bld
  | OP.VSTMXCSR ->
    SSELifter.stmxcsr ins bld
  | OP.VMASKMOVDQU ->
    SSELifter.maskmovdqu ins bld
  | OP.VPSHUFHW ->
    SSELifter.pshufhw ins bld
  | OP.VPSHUFLW ->
    SSELifter.pshuflw ins bld
  | OP.VBLENDPD ->
    SSELifter.blendpd ins bld
  | OP.VBLENDPS ->
    SSELifter.blendps ins bld
  | OP.VDPPD ->
    SSELifter.dppd ins bld
  | OP.VDPPS ->
    SSELifter.dpps ins bld
  | OP.VPEXTRW ->
    SSELifter.pextrw ins bld
  | OP.VPEXTRQ ->
    SSELifter.pextrq ins bld
  | OP.VGF2P8MULB ->
    AVXLifter.vgf2p8mulb ins bld
  | OP.VGF2P8AFFINEQB ->
    AVXLifter.vgf2p8affineqb ins bld
  | OP.VGF2P8AFFINEINVQB ->
    AVXLifter.vgf2p8affineinvqb ins bld
  | OP.VMPSADBW ->
    SSELifter.mpsadbw ins bld
  | OP.VINSERTPS ->
    SSELifter.insertps ins bld
  | OP.VPINSRQ ->
    SSELifter.pinsrq ins bld
  | OP.VCMPPD ->
    AVX512Lifter.vcmppd ins bld
  | OP.VCMPPS ->
    AVX512Lifter.vcmpps ins bld
  | OP.VCMPSD ->
    AVX512Lifter.vcmpsd ins bld
  | OP.VCMPSS ->
    AVX512Lifter.vcmpss ins bld
  | OP.VBROADCASTSD ->
    AVXLifter.vbroadcastsd ins bld
  | OP.VPBROADCASTQ ->
    AVXLifter.vpbroadcastq ins bld
  | OP.VBROADCASTF128 ->
    AVXLifter.vbroadcastf128 ins bld
  | OP.VEXTRACTF128 ->
    AVXLifter.vextractf128 ins bld
  | OP.VINSERTF128 ->
    AVXLifter.vinsertf128 ins bld
  | OP.VZEROALL ->
    AVXLifter.vzeroall ins bld
  | OP.VTESTPS ->
    AVXLifter.vtestps ins bld
  | OP.VTESTPD ->
    AVXLifter.vtestpd ins bld
  | OP.VPSLLVD ->
    AVXLifter.vpsllvd ins bld
  | OP.VPSLLVQ ->
    AVXLifter.vpsllvq ins bld
  | OP.VPSRLVD ->
    AVXLifter.vpsrlvd ins bld
  | OP.VPSRLVQ ->
    AVXLifter.vpsrlvq ins bld
  | OP.VPSLLW ->
    AVXLifter.vpsllw ins bld
  | OP.VPERMILPS ->
    AVXLifter.vpermilps ins bld
  | OP.VPERMILPD ->
    AVXLifter.vpermilpd ins bld
  | OP.VPERM2F128 ->
    AVXLifter.vperm2f128 ins bld
  | OP.VPERMPD ->
    AVXLifter.vpermpd ins bld
  | OP.VPERMPS ->
    AVXLifter.vpermps ins bld
  | OP.VMASKMOVPS ->
    AVXLifter.vmaskmovps ins bld
  | OP.VMASKMOVPD ->
    AVXLifter.vmaskmovpd ins bld
  | OP.VPMASKMOVD ->
    AVXLifter.vpmaskmovd ins bld
  | OP.VPMASKMOVQ ->
    AVXLifter.vpmaskmovq ins bld
  | OP.VCVTDQ2PS ->
    AVXLifter.vcvtdq2ps ins bld
  | OP.VCVTPS2DQ ->
    AVXLifter.vcvtps2dq ins bld
  | OP.VCVTTPS2DQ ->
    AVXLifter.vcvttps2dq ins bld
  | OP.VCVTPD2PS ->
    AVXLifter.vcvtpd2ps ins bld
  | OP.VCVTPD2DQ ->
    AVXLifter.vcvtpd2dq ins bld
  | OP.VCVTTPD2DQ ->
    AVXLifter.vcvttpd2dq ins bld
  | OP.VCVTDQ2PD ->
    AVXLifter.vcvtdq2pd ins bld
  | OP.VCVTPS2PD ->
    AVXLifter.vcvtps2pd ins bld
  | OP.VGATHERDPD ->
    AVX512Lifter.vgatherdpd ins bld
  | OP.VGATHERQPD ->
    AVX512Lifter.vgatherqpd ins bld
  | OP.VGATHERDPS ->
    AVX512Lifter.vgatherdps ins bld
  | OP.VGATHERQPS ->
    AVX512Lifter.vgatherqps ins bld
  | OP.VPGATHERDD ->
    AVX512Lifter.vpgatherdd ins bld
  | OP.VPGATHERDQ ->
    AVX512Lifter.vpgatherdq ins bld
  | OP.VPGATHERQD ->
    AVX512Lifter.vpgatherqd ins bld
  | OP.VPGATHERQQ ->
    AVX512Lifter.vpgatherqq ins bld
  | OP.VRCPPS ->
    AVXLifter.vrcpps ins bld
  | OP.VRSQRTPS ->
    AVXLifter.vrsqrtps ins bld
  | OP.VRCPSS ->
    AVXLifter.vrcpss ins bld
  | OP.VRSQRTSS ->
    AVXLifter.vrsqrtss ins bld
  | OP.VPMAXSD ->
    AVXLifter.vpmaxsd ins bld
  | OP.VROUNDPD ->
    SSELifter.vroundpd ins bld
  | OP.VROUNDPS ->
    SSELifter.vroundps ins bld
  | OP.VROUNDSD ->
    SSELifter.vroundsd ins bld
  | OP.VROUNDSS ->
    SSELifter.vroundss ins bld
  | OP.VPADDW ->
    AVXLifter.vpaddw ins bld
  | OP.VPADDSB ->
    AVXLifter.vpaddsb ins bld
  | OP.VPADDSW ->
    AVXLifter.vpaddsw ins bld
  | OP.VPADDUSB ->
    AVXLifter.vpaddusb ins bld
  | OP.VPADDUSW ->
    AVXLifter.vpaddusw ins bld
  | OP.VPSUBW ->
    AVXLifter.vpsubw ins bld
  | OP.VPSUBQ ->
    AVXLifter.vpsubq ins bld
  | OP.VPSUBSB ->
    AVXLifter.vpsubsb ins bld
  | OP.VPSUBSW ->
    AVXLifter.vpsubsw ins bld
  | OP.VPSUBUSB ->
    AVXLifter.vpsubusb ins bld
  | OP.VPSUBUSW ->
    AVXLifter.vpsubusw ins bld
  | OP.VPCMPEQW ->
    AVX512Lifter.vpcmpeqw ins bld
  | OP.VPCMPGTW ->
    AVX512Lifter.vpcmpgtw ins bld
  | OP.VPCMPGTD ->
    AVX512Lifter.vpcmpgtd ins bld
  | OP.VPCMPGTQ ->
    AVX512Lifter.vpcmpgtq ins bld
  | OP.VPMAXSB ->
    AVXLifter.vpmaxsb ins bld
  | OP.VPMAXSW ->
    AVXLifter.vpmaxsw ins bld
  | OP.VPMAXUB ->
    AVXLifter.vpmaxub ins bld
  | OP.VPMAXUW ->
    AVXLifter.vpmaxuw ins bld
  | OP.VPMAXUD ->
    AVXLifter.vpmaxud ins bld
  | OP.VPMINSW ->
    AVXLifter.vpminsw ins bld
  | OP.VPMINUW ->
    AVXLifter.vpminuw ins bld
  | OP.VPMULHW ->
    AVXLifter.vpmulhw ins bld
  | OP.VPMULHRSW ->
    AVXLifter.vpmulhrsw ins bld
  | OP.VPMULDQ ->
    AVXLifter.vpmuldq ins bld
  | OP.VPMADDWD ->
    AVXLifter.vpmaddwd ins bld
  | OP.VPMADDUBSW ->
    AVXLifter.vpmaddubsw ins bld
  | OP.VPABSB ->
    AVXLifter.vpabsb ins bld
  | OP.VPABSW ->
    AVXLifter.vpabsw ins bld
  | OP.VPABSD ->
    AVXLifter.vpabsd ins bld
  | OP.VPUNPCKHBW ->
    AVXLifter.vpunpckhbw ins bld
  | OP.VPUNPCKLBW ->
    AVXLifter.vpunpcklbw ins bld
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
    AVX512Lifter.vpcmpeqb ins bld
  | OP.VPCMPEQD ->
    AVX512Lifter.vpcmpeqd ins bld
  | OP.VPCMPEQQ ->
    AVX512Lifter.vpcmpeqq ins bld
  | OP.VPCMPESTRI | OP.VPCMPESTRM | OP.VPCMPISTRI
  | OP.VPCMPISTRM ->
    SSELifter.pcmpstr ins bld
  | OP.VPCMPGTB ->
    AVX512Lifter.vpcmpgtb ins bld
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
    AVX512Lifter.vpmovd2m ins bld
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
    AVX512Lifter.vextracti32x8 ins bld
  | OP.VERW ->
    LiftingUtils.unsupported ins bld
  | OP.VFMADD132PD ->
    AVXLifter.vfmadd132pd ins bld
  | OP.VFMADD132PS ->
    AVXLifter.vfmadd132ps ins bld
  | OP.VFMADD132SD ->
    AVXLifter.vfmadd132sd ins bld
  | OP.VFMADD132SS ->
    AVXLifter.vfmadd132ss ins bld
  | OP.VFMSUB132PD ->
    AVXLifter.vfmsub132pd ins bld
  | OP.VFMSUB132PS ->
    AVXLifter.vfmsub132ps ins bld
  | OP.VFMSUB132SD ->
    AVXLifter.vfmsub132sd ins bld
  | OP.VFMSUB132SS ->
    AVXLifter.vfmsub132ss ins bld
  | OP.VFNMADD132PD ->
    AVXLifter.vfnmadd132pd ins bld
  | OP.VFNMADD132PS ->
    AVXLifter.vfnmadd132ps ins bld
  | OP.VFNMADD132SD ->
    AVXLifter.vfnmadd132sd ins bld
  | OP.VFNMADD132SS ->
    AVXLifter.vfnmadd132ss ins bld
  | OP.VFNMSUB132PD ->
    AVXLifter.vfnmsub132pd ins bld
  | OP.VFNMSUB132PS ->
    AVXLifter.vfnmsub132ps ins bld
  | OP.VFNMSUB132SD ->
    AVXLifter.vfnmsub132sd ins bld
  | OP.VFNMSUB132SS ->
    AVXLifter.vfnmsub132ss ins bld
  | OP.VFMADDSUB132PD ->
    AVXLifter.vfmaddsub132pd ins bld
  | OP.VFMADDSUB132PS ->
    AVXLifter.vfmaddsub132ps ins bld
  | OP.VFMSUBADD132PD ->
    AVXLifter.vfmsubadd132pd ins bld
  | OP.VFMSUBADD132PS ->
    AVXLifter.vfmsubadd132ps ins bld
  | OP.VFMADD213PD ->
    AVXLifter.vfmadd213pd ins bld
  | OP.VFMADD213PS ->
    AVXLifter.vfmadd213ps ins bld
  | OP.VFMADD213SD ->
    AVXLifter.vfmadd213sd ins bld
  | OP.VFMADD213SS ->
    AVXLifter.vfmadd213ss ins bld
  | OP.VFMSUB213PD ->
    AVXLifter.vfmsub213pd ins bld
  | OP.VFMSUB213PS ->
    AVXLifter.vfmsub213ps ins bld
  | OP.VFMSUB213SD ->
    AVXLifter.vfmsub213sd ins bld
  | OP.VFMSUB213SS ->
    AVXLifter.vfmsub213ss ins bld
  | OP.VFNMADD213PD ->
    AVXLifter.vfnmadd213pd ins bld
  | OP.VFNMADD213PS ->
    AVXLifter.vfnmadd213ps ins bld
  | OP.VFNMADD213SD ->
    AVXLifter.vfnmadd213sd ins bld
  | OP.VFNMADD213SS ->
    AVXLifter.vfnmadd213ss ins bld
  | OP.VFNMSUB213PD ->
    AVXLifter.vfnmsub213pd ins bld
  | OP.VFNMSUB213PS ->
    AVXLifter.vfnmsub213ps ins bld
  | OP.VFNMSUB213SD ->
    AVXLifter.vfnmsub213sd ins bld
  | OP.VFNMSUB213SS ->
    AVXLifter.vfnmsub213ss ins bld
  | OP.VFMADDSUB213PD ->
    AVXLifter.vfmaddsub213pd ins bld
  | OP.VFMADDSUB213PS ->
    AVXLifter.vfmaddsub213ps ins bld
  | OP.VFMSUBADD213PD ->
    AVXLifter.vfmsubadd213pd ins bld
  | OP.VFMSUBADD213PS ->
    AVXLifter.vfmsubadd213ps ins bld
  | OP.VFMADD231PD ->
    AVXLifter.vfmadd231pd ins bld
  | OP.VFMADD231PS ->
    AVXLifter.vfmadd231ps ins bld
  | OP.VFMADD231SD ->
    AVXLifter.vfmadd231sd ins bld
  | OP.VFMADD231SS ->
    AVXLifter.vfmadd231ss ins bld
  | OP.VFMSUB231PD ->
    AVXLifter.vfmsub231pd ins bld
  | OP.VFMSUB231PS ->
    AVXLifter.vfmsub231ps ins bld
  | OP.VFMSUB231SD ->
    AVXLifter.vfmsub231sd ins bld
  | OP.VFMSUB231SS ->
    AVXLifter.vfmsub231ss ins bld
  | OP.VFNMADD231PD ->
    AVXLifter.vfnmadd231pd ins bld
  | OP.VFNMADD231PS ->
    AVXLifter.vfnmadd231ps ins bld
  | OP.VFNMADD231SD ->
    AVXLifter.vfnmadd231sd ins bld
  | OP.VFNMADD231SS ->
    AVXLifter.vfnmadd231ss ins bld
  | OP.VFNMSUB231PD ->
    AVXLifter.vfnmsub231pd ins bld
  | OP.VFNMSUB231PS ->
    AVXLifter.vfnmsub231ps ins bld
  | OP.VFNMSUB231SD ->
    AVXLifter.vfnmsub231sd ins bld
  | OP.VFNMSUB231SS ->
    AVXLifter.vfnmsub231ss ins bld
  | OP.VFMADDSUB231PD ->
    AVXLifter.vfmaddsub231pd ins bld
  | OP.VFMADDSUB231PS ->
    AVXLifter.vfmaddsub231ps ins bld
  | OP.VFMSUBADD231PD ->
    AVXLifter.vfmsubadd231pd ins bld
  | OP.VFMSUBADD231PS ->
    AVXLifter.vfmsubadd231ps ins bld
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
  | OP.FNCLEX ->
    X87Lifter.fclex ins bld
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
  | OP.WAIT | OP.FWAIT ->
    X87Lifter.wait ins bld
  | OP.FNOP ->
    X87Lifter.fnop ins bld
  | OP.FXSAVE | OP.FXSAVE64 ->
    X87Lifter.fxsave ins bld
  | OP.FXRSTOR | OP.FXRSTOR64 ->
    X87Lifter.fxrstor ins bld
  (* The instructions EVEX introduced, rather than the ones it widened. *)
  | OP.VPANDD ->
    AVX512Lifter.vpandd ins bld
  | OP.VPANDQ ->
    AVX512Lifter.vpandq ins bld
  | OP.VPANDND ->
    AVX512Lifter.vpandnd ins bld
  | OP.VPANDNQ ->
    AVX512Lifter.vpandnq ins bld
  | OP.VPORD ->
    AVX512Lifter.vpord ins bld
  | OP.VPORQ ->
    AVX512Lifter.vporq ins bld
  | OP.VPXORQ ->
    AVX512Lifter.vpxorq ins bld
  | OP.VPABSQ ->
    AVX512Lifter.vpabsq ins bld
  | OP.VPMAXSQ ->
    AVX512Lifter.vpmaxsq ins bld
  | OP.VPMAXUQ ->
    AVX512Lifter.vpmaxuq ins bld
  | OP.VPMINSQ ->
    AVX512Lifter.vpminsq ins bld
  | OP.VPMINUQ ->
    AVX512Lifter.vpminuq ins bld
  | OP.VPMULLQ ->
    AVX512Lifter.vpmullq ins bld
  | OP.VPROLD ->
    AVX512Lifter.vprold ins bld
  | OP.VPROLQ ->
    AVX512Lifter.vprolq ins bld
  | OP.VPRORD ->
    AVX512Lifter.vprord ins bld
  | OP.VPRORQ ->
    AVX512Lifter.vprorq ins bld
  | OP.VPROLVD ->
    AVX512Lifter.vprolvd ins bld
  | OP.VPROLVQ ->
    AVX512Lifter.vprolvq ins bld
  | OP.VPRORVD ->
    AVX512Lifter.vprorvd ins bld
  | OP.VPRORVQ ->
    AVX512Lifter.vprorvq ins bld
  | OP.VPSRAVQ ->
    AVX512Lifter.vpsravq ins bld
  | OP.VPSRAVW ->
    AVX512Lifter.vpsravw ins bld
  | OP.VPSRLVW ->
    AVX512Lifter.vpsrlvw ins bld
  | OP.VPSLLVW ->
    AVX512Lifter.vpsllvw ins bld
  | OP.VPSRAQ ->
    AVX512Lifter.vpsraq ins bld
  | OP.VPOPCNTB ->
    AVX512Lifter.vpopcntb ins bld
  | OP.VPOPCNTW ->
    AVX512Lifter.vpopcntw ins bld
  | OP.VPOPCNTD ->
    AVX512Lifter.vpopcntd ins bld
  | OP.VPOPCNTQ ->
    AVX512Lifter.vpopcntq ins bld
  | OP.VPLZCNTD ->
    AVX512Lifter.vplzcntd ins bld
  | OP.VPLZCNTQ ->
    AVX512Lifter.vplzcntq ins bld
  | OP.VPCONFLICTD ->
    AVX512Lifter.vpconflictd ins bld
  | OP.VPCONFLICTQ ->
    AVX512Lifter.vpconflictq ins bld
  | OP.VPTERNLOGD ->
    AVX512Lifter.vpternlogd ins bld
  | OP.VPTERNLOGQ ->
    AVX512Lifter.vpternlogq ins bld
  | OP.VPSHLDW ->
    AVX512Lifter.vpshldw ins bld
  | OP.VPSHLDD ->
    AVX512Lifter.vpshldd ins bld
  | OP.VPSHLDQ ->
    AVX512Lifter.vpshldq ins bld
  | OP.VPSHRDW ->
    AVX512Lifter.vpshrdw ins bld
  | OP.VPSHRDD ->
    AVX512Lifter.vpshrdd ins bld
  | OP.VPSHRDQ ->
    AVX512Lifter.vpshrdq ins bld
  | OP.VPSHLDVW ->
    AVX512Lifter.vpshldvw ins bld
  | OP.VPSHLDVD ->
    AVX512Lifter.vpshldvd ins bld
  | OP.VPSHLDVQ ->
    AVX512Lifter.vpshldvq ins bld
  | OP.VPSHRDVW ->
    AVX512Lifter.vpshrdvw ins bld
  | OP.VPSHRDVD ->
    AVX512Lifter.vpshrdvd ins bld
  | OP.VPSHRDVQ ->
    AVX512Lifter.vpshrdvq ins bld
  | OP.VPDPBUSD ->
    AVX512Lifter.vpdpbusd ins bld
  | OP.VPDPBUSDS ->
    AVX512Lifter.vpdpbusds ins bld
  | OP.VPDPBSSD ->
    AVX512Lifter.vpdpbssd ins bld
  | OP.VPDPBSSDS ->
    AVX512Lifter.vpdpbssds ins bld
  | OP.VPDPBSUD ->
    AVX512Lifter.vpdpbsud ins bld
  | OP.VPDPBSUDS ->
    AVX512Lifter.vpdpbsuds ins bld
  | OP.VPDPBUUD ->
    AVX512Lifter.vpdpbuud ins bld
  | OP.VPDPBUUDS ->
    AVX512Lifter.vpdpbuuds ins bld
  | OP.VPDPWSSD ->
    AVX512Lifter.vpdpwssd ins bld
  | OP.VPDPWSSDS ->
    AVX512Lifter.vpdpwssds ins bld
  | OP.VPDPWSUD ->
    AVX512Lifter.vpdpwsud ins bld
  | OP.VPDPWSUDS ->
    AVX512Lifter.vpdpwsuds ins bld
  | OP.VPDPWUSD ->
    AVX512Lifter.vpdpwusd ins bld
  | OP.VPDPWUSDS ->
    AVX512Lifter.vpdpwusds ins bld
  | OP.VPDPWUUD ->
    AVX512Lifter.vpdpwuud ins bld
  | OP.VPDPWUUDS ->
    AVX512Lifter.vpdpwuuds ins bld
  | OP.VPMULTISHIFTQB ->
    AVX512Lifter.vpmultishiftqb ins bld
  | OP.VPMADD52LUQ ->
    AVX512Lifter.vpmadd52luq ins bld
  | OP.VPMADD52HUQ ->
    AVX512Lifter.vpmadd52huq ins bld
  | OP.VDBPSADBW ->
    AVX512Lifter.vdbpsadbw ins bld
  | OP.VPCMPB ->
    AVX512Lifter.vpcmpb ins bld
  | OP.VPCMPW ->
    AVX512Lifter.vpcmpw ins bld
  | OP.VPCMPD ->
    AVX512Lifter.vpcmpd ins bld
  | OP.VPCMPQ ->
    AVX512Lifter.vpcmpq ins bld
  | OP.VPCMPUB ->
    AVX512Lifter.vpcmpub ins bld
  | OP.VPCMPUW ->
    AVX512Lifter.vpcmpuw ins bld
  | OP.VPCMPUD ->
    AVX512Lifter.vpcmpud ins bld
  | OP.VPCMPUQ ->
    AVX512Lifter.vpcmpuq ins bld
  | OP.VPTESTMB ->
    AVX512Lifter.vptestmb ins bld
  | OP.VPTESTMW ->
    AVX512Lifter.vptestmw ins bld
  | OP.VPTESTMD ->
    AVX512Lifter.vptestmd ins bld
  | OP.VPTESTMQ ->
    AVX512Lifter.vptestmq ins bld
  | OP.VPTESTNMB ->
    AVX512Lifter.vptestnmb ins bld
  | OP.VPTESTNMW ->
    AVX512Lifter.vptestnmw ins bld
  | OP.VPTESTNMD ->
    AVX512Lifter.vptestnmd ins bld
  | OP.VPTESTNMQ ->
    AVX512Lifter.vptestnmq ins bld
  | OP.VPMOVB2M ->
    AVX512Lifter.vpmovb2m ins bld
  | OP.VPMOVW2M ->
    AVX512Lifter.vpmovw2m ins bld
  | OP.VPMOVQ2M ->
    AVX512Lifter.vpmovq2m ins bld
  | OP.VPMOVM2B ->
    AVX512Lifter.vpmovm2b ins bld
  | OP.VPMOVM2W ->
    AVX512Lifter.vpmovm2w ins bld
  | OP.VPMOVM2D ->
    AVX512Lifter.vpmovm2d ins bld
  | OP.VPMOVM2Q ->
    AVX512Lifter.vpmovm2q ins bld
  | OP.VPBROADCASTMB2Q ->
    AVX512Lifter.vpbroadcastmb2q ins bld
  | OP.VPBROADCASTMW2D ->
    AVX512Lifter.vpbroadcastmw2d ins bld
  | OP.VPSHUFBITQMB ->
    AVX512Lifter.vpshufbitqmb ins bld
  | OP.VP2INTERSECTD ->
    AVX512Lifter.vp2intersectd ins bld
  | OP.VP2INTERSECTQ ->
    AVX512Lifter.vp2intersectq ins bld
  | OP.VFPCLASSPD ->
    AVX512Lifter.vfpclasspd ins bld
  | OP.VFPCLASSPS ->
    AVX512Lifter.vfpclassps ins bld
  | OP.VFPCLASSSD ->
    AVX512Lifter.vfpclasssd ins bld
  | OP.VFPCLASSSS ->
    AVX512Lifter.vfpclassss ins bld
  | OP.VALIGND ->
    AVX512Lifter.valignd ins bld
  | OP.VALIGNQ ->
    AVX512Lifter.valignq ins bld
  | OP.VBLENDMPD ->
    AVX512Lifter.vblendmpd ins bld
  | OP.VBLENDMPS ->
    AVX512Lifter.vblendmps ins bld
  | OP.VPBLENDMB ->
    AVX512Lifter.vpblendmb ins bld
  | OP.VPBLENDMW ->
    AVX512Lifter.vpblendmw ins bld
  | OP.VPBLENDMD ->
    AVX512Lifter.vpblendmd ins bld
  | OP.VPBLENDMQ ->
    AVX512Lifter.vpblendmq ins bld
  | OP.VBROADCASTF32X2 ->
    AVX512Lifter.vbroadcastf32x2 ins bld
  | OP.VBROADCASTI32X2 ->
    AVX512Lifter.vbroadcasti32x2 ins bld
  | OP.VBROADCASTF32X4 ->
    AVX512Lifter.vbroadcastf32x4 ins bld
  | OP.VBROADCASTI32X4 ->
    AVX512Lifter.vbroadcasti32x4 ins bld
  | OP.VBROADCASTF32X8 ->
    AVX512Lifter.vbroadcastf32x8 ins bld
  | OP.VBROADCASTI32X8 ->
    AVX512Lifter.vbroadcasti32x8 ins bld
  | OP.VBROADCASTF64X2 ->
    AVX512Lifter.vbroadcastf64x2 ins bld
  | OP.VBROADCASTI64X2 ->
    AVX512Lifter.vbroadcasti64x2 ins bld
  | OP.VBROADCASTF64X4 ->
    AVX512Lifter.vbroadcastf64x4 ins bld
  | OP.VBROADCASTI64X4 ->
    AVX512Lifter.vbroadcasti64x4 ins bld
  | OP.VEXTRACTF32X4 ->
    AVX512Lifter.vextractf32x4 ins bld
  | OP.VEXTRACTI32X4 ->
    AVX512Lifter.vextracti32x4 ins bld
  | OP.VEXTRACTF64X2 ->
    AVX512Lifter.vextractf64x2 ins bld
  | OP.VEXTRACTI64X2 ->
    AVX512Lifter.vextracti64x2 ins bld
  | OP.VEXTRACTF64X4 ->
    AVX512Lifter.vextractf64x4 ins bld
  | OP.VINSERTF32X4 ->
    AVX512Lifter.vinsertf32x4 ins bld
  | OP.VINSERTI32X4 ->
    AVX512Lifter.vinserti32x4 ins bld
  | OP.VINSERTF32X8 ->
    AVX512Lifter.vinsertf32x8 ins bld
  | OP.VINSERTI32X8 ->
    AVX512Lifter.vinserti32x8 ins bld
  | OP.VINSERTF64X2 ->
    AVX512Lifter.vinsertf64x2 ins bld
  | OP.VINSERTI64X2 ->
    AVX512Lifter.vinserti64x2 ins bld
  | OP.VINSERTF64X4 ->
    AVX512Lifter.vinsertf64x4 ins bld
  | OP.VINSERTI64X4 ->
    AVX512Lifter.vinserti64x4 ins bld
  | OP.VSHUFF32X4 ->
    AVX512Lifter.vshuff32x4 ins bld
  | OP.VSHUFF64X2 ->
    AVX512Lifter.vshuff64x2 ins bld
  | OP.VSHUFI64X2 ->
    AVX512Lifter.vshufi64x2 ins bld
  | OP.VPERMB ->
    AVX512Lifter.vpermb ins bld
  | OP.VPERMW ->
    AVX512Lifter.vpermw ins bld
  | OP.VPERMI2B ->
    AVX512Lifter.vpermi2b ins bld
  | OP.VPERMI2W ->
    AVX512Lifter.vpermi2w ins bld
  | OP.VPERMI2D ->
    AVX512Lifter.vpermi2d ins bld
  | OP.VPERMI2Q ->
    AVX512Lifter.vpermi2q ins bld
  | OP.VPERMI2PS ->
    AVX512Lifter.vpermi2ps ins bld
  | OP.VPERMI2PD ->
    AVX512Lifter.vpermi2pd ins bld
  | OP.VPERMT2B ->
    AVX512Lifter.vpermt2b ins bld
  | OP.VPERMT2W ->
    AVX512Lifter.vpermt2w ins bld
  | OP.VPERMT2D ->
    AVX512Lifter.vpermt2d ins bld
  | OP.VPERMT2Q ->
    AVX512Lifter.vpermt2q ins bld
  | OP.VPERMT2PS ->
    AVX512Lifter.vpermt2ps ins bld
  | OP.VPERMT2PD ->
    AVX512Lifter.vpermt2pd ins bld
  | OP.VPMOVWB ->
    AVX512Lifter.vpmovwb ins bld
  | OP.VPMOVDB ->
    AVX512Lifter.vpmovdb ins bld
  | OP.VPMOVDW ->
    AVX512Lifter.vpmovdw ins bld
  | OP.VPMOVQB ->
    AVX512Lifter.vpmovqb ins bld
  | OP.VPMOVQW ->
    AVX512Lifter.vpmovqw ins bld
  | OP.VPMOVQD ->
    AVX512Lifter.vpmovqd ins bld
  | OP.VPMOVSWB ->
    AVX512Lifter.vpmovswb ins bld
  | OP.VPMOVSDB ->
    AVX512Lifter.vpmovsdb ins bld
  | OP.VPMOVSDW ->
    AVX512Lifter.vpmovsdw ins bld
  | OP.VPMOVSQB ->
    AVX512Lifter.vpmovsqb ins bld
  | OP.VPMOVSQW ->
    AVX512Lifter.vpmovsqw ins bld
  | OP.VPMOVSQD ->
    AVX512Lifter.vpmovsqd ins bld
  | OP.VPMOVUSWB ->
    AVX512Lifter.vpmovuswb ins bld
  | OP.VPMOVUSDB ->
    AVX512Lifter.vpmovusdb ins bld
  | OP.VPMOVUSDW ->
    AVX512Lifter.vpmovusdw ins bld
  | OP.VPMOVUSQB ->
    AVX512Lifter.vpmovusqb ins bld
  | OP.VPMOVUSQW ->
    AVX512Lifter.vpmovusqw ins bld
  | OP.VPMOVUSQD ->
    AVX512Lifter.vpmovusqd ins bld
  | OP.VSCATTERDPD ->
    AVX512Lifter.vscatterdpd ins bld
  | OP.VSCATTERQPD ->
    AVX512Lifter.vscatterqpd ins bld
  | OP.VSCATTERDPS ->
    AVX512Lifter.vscatterdps ins bld
  | OP.VSCATTERQPS ->
    AVX512Lifter.vscatterqps ins bld
  | OP.VPSCATTERDD ->
    AVX512Lifter.vpscatterdd ins bld
  | OP.VPSCATTERDQ ->
    AVX512Lifter.vpscatterdq ins bld
  | OP.VPSCATTERQD ->
    AVX512Lifter.vpscatterqd ins bld
  | OP.VPSCATTERQQ ->
    AVX512Lifter.vpscatterqq ins bld
  | OP.VEXPANDPD ->
    AVX512Lifter.vexpandpd ins bld
  | OP.VEXPANDPS ->
    AVX512Lifter.vexpandps ins bld
  | OP.VPEXPANDB ->
    AVX512Lifter.vpexpandb ins bld
  | OP.VPEXPANDW ->
    AVX512Lifter.vpexpandw ins bld
  | OP.VPEXPANDD ->
    AVX512Lifter.vpexpandd ins bld
  | OP.VPEXPANDQ ->
    AVX512Lifter.vpexpandq ins bld
  | OP.VCOMPRESSPD ->
    AVX512Lifter.vcompresspd ins bld
  | OP.VCOMPRESSPS ->
    AVX512Lifter.vcompressps ins bld
  | OP.VPCOMPRESSB ->
    AVX512Lifter.vpcompressb ins bld
  | OP.VPCOMPRESSW ->
    AVX512Lifter.vpcompressw ins bld
  | OP.VPCOMPRESSD ->
    AVX512Lifter.vpcompressd ins bld
  | OP.VPCOMPRESSQ ->
    AVX512Lifter.vpcompressq ins bld
  | OP.VMOVW ->
    AVX512Lifter.vmovw ins bld
  | OP.VGATHERPF0DPD
  | OP.VGATHERPF0DPS
  | OP.VGATHERPF0QPD
  | OP.VGATHERPF0QPS
  | OP.VGATHERPF1DPD
  | OP.VGATHERPF1DPS
  | OP.VGATHERPF1QPD
  | OP.VGATHERPF1QPS
  | OP.VSCATTERPF0DPD
  | OP.VSCATTERPF0DPS
  | OP.VSCATTERPF0QPD
  | OP.VSCATTERPF0QPS
  | OP.VSCATTERPF1DPD
  | OP.VSCATTERPF1DPS
  | OP.VSCATTERPF1QPD
  | OP.VSCATTERPF1QPS ->
    AVX512Lifter.vgatherpf ins bld
  | OP.VCVTPD2QQ ->
    AVX512Lifter.vcvtpd2qq ins bld
  | OP.VCVTTPD2QQ ->
    AVX512Lifter.vcvttpd2qq ins bld
  | OP.VCVTPS2QQ ->
    AVX512Lifter.vcvtps2qq ins bld
  | OP.VCVTTPS2QQ ->
    AVX512Lifter.vcvttps2qq ins bld
  | OP.VCVTPD2UDQ ->
    AVX512Lifter.vcvtpd2udq ins bld
  | OP.VCVTTPD2UDQ ->
    AVX512Lifter.vcvttpd2udq ins bld
  | OP.VCVTPS2UDQ ->
    AVX512Lifter.vcvtps2udq ins bld
  | OP.VCVTTPS2UDQ ->
    AVX512Lifter.vcvttps2udq ins bld
  | OP.VCVTPD2UQQ ->
    AVX512Lifter.vcvtpd2uqq ins bld
  | OP.VCVTTPD2UQQ ->
    AVX512Lifter.vcvttpd2uqq ins bld
  | OP.VCVTPS2UQQ ->
    AVX512Lifter.vcvtps2uqq ins bld
  | OP.VCVTTPS2UQQ ->
    AVX512Lifter.vcvttps2uqq ins bld
  | OP.VCVTQQ2PD ->
    AVX512Lifter.vcvtqq2pd ins bld
  | OP.VCVTQQ2PS ->
    AVX512Lifter.vcvtqq2ps ins bld
  | OP.VCVTUQQ2PD ->
    AVX512Lifter.vcvtuqq2pd ins bld
  | OP.VCVTUQQ2PS ->
    AVX512Lifter.vcvtuqq2ps ins bld
  | OP.VCVTUDQ2PD ->
    AVX512Lifter.vcvtudq2pd ins bld
  | OP.VCVTUDQ2PS ->
    AVX512Lifter.vcvtudq2ps ins bld
  | OP.VCVTUSI2SD ->
    AVX512Lifter.vcvtusi2sd ins bld
  | OP.VCVTUSI2SS ->
    AVX512Lifter.vcvtusi2ss ins bld
  | OP.VCVTSD2USI ->
    AVX512Lifter.vcvtsd2usi ins bld
  | OP.VCVTTSD2USI ->
    AVX512Lifter.vcvttsd2usi ins bld
  | OP.VCVTSS2USI ->
    AVX512Lifter.vcvtss2usi ins bld
  | OP.VCVTTSS2USI ->
    AVX512Lifter.vcvttss2usi ins bld
  | OP.VGETEXPPD ->
    AVX512Lifter.vgetexppd ins bld
  | OP.VGETEXPPS ->
    AVX512Lifter.vgetexpps ins bld
  | OP.VGETEXPSD ->
    AVX512Lifter.vgetexpsd ins bld
  | OP.VGETEXPSS ->
    AVX512Lifter.vgetexpss ins bld
  | OP.VGETMANTPD ->
    AVX512Lifter.vgetmantpd ins bld
  | OP.VGETMANTPS ->
    AVX512Lifter.vgetmantps ins bld
  | OP.VGETMANTSD ->
    AVX512Lifter.vgetmantsd ins bld
  | OP.VGETMANTSS ->
    AVX512Lifter.vgetmantss ins bld
  | OP.VRNDSCALEPD ->
    AVX512Lifter.vrndscalepd ins bld
  | OP.VRNDSCALEPS ->
    AVX512Lifter.vrndscaleps ins bld
  | OP.VRNDSCALESD ->
    AVX512Lifter.vrndscalesd ins bld
  | OP.VRNDSCALESS ->
    AVX512Lifter.vrndscaless ins bld
  | OP.VREDUCEPD ->
    AVX512Lifter.vreducepd ins bld
  | OP.VREDUCEPS ->
    AVX512Lifter.vreduceps ins bld
  | OP.VREDUCESD ->
    AVX512Lifter.vreducesd ins bld
  | OP.VREDUCESS ->
    AVX512Lifter.vreducess ins bld
  | OP.VRANGEPD ->
    AVX512Lifter.vrangepd ins bld
  | OP.VRANGEPS ->
    AVX512Lifter.vrangeps ins bld
  | OP.VRANGESD ->
    AVX512Lifter.vrangesd ins bld
  | OP.VRANGESS ->
    AVX512Lifter.vrangess ins bld
  | OP.VSCALEFPD ->
    AVX512Lifter.vscalefpd ins bld
  | OP.VSCALEFPS ->
    AVX512Lifter.vscalefps ins bld
  | OP.VSCALEFSD ->
    AVX512Lifter.vscalefsd ins bld
  | OP.VSCALEFSS ->
    AVX512Lifter.vscalefss ins bld
  | OP.VRCP14PD ->
    AVX512Lifter.vrcp14pd ins bld
  | OP.VRCP14PS ->
    AVX512Lifter.vrcp14ps ins bld
  | OP.VRCP14SD ->
    AVX512Lifter.vrcp14sd ins bld
  | OP.VRCP14SS ->
    AVX512Lifter.vrcp14ss ins bld
  | OP.VRCP28PD ->
    AVX512Lifter.vrcp28pd ins bld
  | OP.VRCP28PS ->
    AVX512Lifter.vrcp28ps ins bld
  | OP.VRCP28SD ->
    AVX512Lifter.vrcp28sd ins bld
  | OP.VRCP28SS ->
    AVX512Lifter.vrcp28ss ins bld
  | OP.VRSQRT14PD ->
    AVX512Lifter.vrsqrt14pd ins bld
  | OP.VRSQRT14PS ->
    AVX512Lifter.vrsqrt14ps ins bld
  | OP.VRSQRT14SD ->
    AVX512Lifter.vrsqrt14sd ins bld
  | OP.VRSQRT14SS ->
    AVX512Lifter.vrsqrt14ss ins bld
  | OP.VRSQRT28PD ->
    AVX512Lifter.vrsqrt28pd ins bld
  | OP.VRSQRT28PS ->
    AVX512Lifter.vrsqrt28ps ins bld
  | OP.VRSQRT28SD ->
    AVX512Lifter.vrsqrt28sd ins bld
  | OP.VRSQRT28SS ->
    AVX512Lifter.vrsqrt28ss ins bld
  | OP.VFIXUPIMMPD ->
    AVX512Lifter.vfixupimmpd ins bld
  | OP.VFIXUPIMMPS ->
    AVX512Lifter.vfixupimmps ins bld
  | OP.VFIXUPIMMSD ->
    AVX512Lifter.vfixupimmsd ins bld
  | OP.VFIXUPIMMSS ->
    AVX512Lifter.vfixupimmss ins bld
  | OP.VCVTNE2PS2BF16 ->
    AVX512Lifter.vcvtne2ps2bf16 ins bld
  | OP.VCVTNEPS2BF16 ->
    AVX512Lifter.vcvtneps2bf16 ins bld
  | OP.VDPBF16PS ->
    AVX512Lifter.vdpbf16ps ins bld
  | OP.VBCSTNEBF162PS ->
    AVX512Lifter.vbcstnebf162ps ins bld
  | OP.VCVTNEEBF162PS ->
    AVX512Lifter.vcvtneebf162ps ins bld
  | OP.VCVTNEOBF162PS ->
    AVX512Lifter.vcvtneobf162ps ins bld
  | OP.VADDPH ->
    AVX512Lifter.vaddph ins bld
  | OP.VADDSH ->
    AVX512Lifter.vaddsh ins bld
  | OP.VSUBPH ->
    AVX512Lifter.vsubph ins bld
  | OP.VSUBSH ->
    AVX512Lifter.vsubsh ins bld
  | OP.VMULPH ->
    AVX512Lifter.vmulph ins bld
  | OP.VMULSH ->
    AVX512Lifter.vmulsh ins bld
  | OP.VDIVPH ->
    AVX512Lifter.vdivph ins bld
  | OP.VDIVSH ->
    AVX512Lifter.vdivsh ins bld
  | OP.VMINPH ->
    AVX512Lifter.vminph ins bld
  | OP.VMINSH ->
    AVX512Lifter.vminsh ins bld
  | OP.VMAXPH ->
    AVX512Lifter.vmaxph ins bld
  | OP.VMAXSH ->
    AVX512Lifter.vmaxsh ins bld
  | OP.VSQRTPH ->
    AVX512Lifter.vsqrtph ins bld
  | OP.VSQRTSH ->
    AVX512Lifter.vsqrtsh ins bld
  | OP.VRCPPH ->
    AVX512Lifter.vrcpph ins bld
  | OP.VRCPSH ->
    AVX512Lifter.vrcpsh ins bld
  | OP.VRSQRTPH ->
    AVX512Lifter.vrsqrtph ins bld
  | OP.VRSQRTSH ->
    AVX512Lifter.vrsqrtsh ins bld
  | OP.VSCALEFPH ->
    AVX512Lifter.vscalefph ins bld
  | OP.VSCALEFSH ->
    AVX512Lifter.vscalefsh ins bld
  | OP.VRNDSCALEPH ->
    AVX512Lifter.vrndscaleph ins bld
  | OP.VRNDSCALESH ->
    AVX512Lifter.vrndscalesh ins bld
  | OP.VREDUCEPH ->
    AVX512Lifter.vreduceph ins bld
  | OP.VREDUCESH ->
    AVX512Lifter.vreducesh ins bld
  | OP.VGETMANTPH ->
    AVX512Lifter.vgetmantph ins bld
  | OP.VGETMANTSH ->
    AVX512Lifter.vgetmantsh ins bld
  | OP.VGETEXPPH ->
    AVX512Lifter.vgetexpph ins bld
  | OP.VGETEXPSH ->
    AVX512Lifter.vgetexpsh ins bld
  | OP.VCMPPH ->
    AVX512Lifter.vcmpph ins bld
  | OP.VCMPSH ->
    AVX512Lifter.vcmpsh ins bld
  | OP.VFPCLASSPH ->
    AVX512Lifter.vfpclassph ins bld
  | OP.VFPCLASSSH ->
    AVX512Lifter.vfpclasssh ins bld
  | OP.VCOMISH ->
    AVX512Lifter.vcomish ins bld
  | OP.VUCOMISH ->
    AVX512Lifter.vucomish ins bld
  | OP.VMOVSH ->
    AVX512Lifter.vmovsh ins bld
  | OP.VCVTPH2PS ->
    AVX512Lifter.vcvtph2ps ins bld
  | OP.VCVTPH2PSX ->
    AVX512Lifter.vcvtph2psx ins bld
  | OP.VCVTPH2PD ->
    AVX512Lifter.vcvtph2pd ins bld
  | OP.VCVTPD2PH ->
    AVX512Lifter.vcvtpd2ph ins bld
  | OP.VCVTPS2PHX ->
    AVX512Lifter.vcvtps2phx ins bld
  | OP.VCVTPS2PH ->
    AVX512Lifter.vcvtps2ph ins bld
  | OP.VCVTPH2DQ ->
    AVX512Lifter.vcvtph2dq ins bld
  | OP.VCVTTPH2DQ ->
    AVX512Lifter.vcvttph2dq ins bld
  | OP.VCVTPH2QQ ->
    AVX512Lifter.vcvtph2qq ins bld
  | OP.VCVTTPH2QQ ->
    AVX512Lifter.vcvttph2qq ins bld
  | OP.VCVTPH2UDQ ->
    AVX512Lifter.vcvtph2udq ins bld
  | OP.VCVTTPH2UDQ ->
    AVX512Lifter.vcvttph2udq ins bld
  | OP.VCVTPH2UQQ ->
    AVX512Lifter.vcvtph2uqq ins bld
  | OP.VCVTTPH2UQQ ->
    AVX512Lifter.vcvttph2uqq ins bld
  | OP.VCVTPH2W ->
    AVX512Lifter.vcvtph2w ins bld
  | OP.VCVTTPH2W ->
    AVX512Lifter.vcvttph2w ins bld
  | OP.VCVTPH2UW ->
    AVX512Lifter.vcvtph2uw ins bld
  | OP.VCVTTPH2UW ->
    AVX512Lifter.vcvttph2uw ins bld
  | OP.VCVTW2PH ->
    AVX512Lifter.vcvtw2ph ins bld
  | OP.VCVTUW2PH ->
    AVX512Lifter.vcvtuw2ph ins bld
  | OP.VCVTDQ2PH ->
    AVX512Lifter.vcvtdq2ph ins bld
  | OP.VCVTUDQ2PH ->
    AVX512Lifter.vcvtudq2ph ins bld
  | OP.VCVTQQ2PH ->
    AVX512Lifter.vcvtqq2ph ins bld
  | OP.VCVTUQQ2PH ->
    AVX512Lifter.vcvtuqq2ph ins bld
  | OP.VCVTSH2SS ->
    AVX512Lifter.vcvtsh2ss ins bld
  | OP.VCVTSH2SD ->
    AVX512Lifter.vcvtsh2sd ins bld
  | OP.VCVTSS2SH ->
    AVX512Lifter.vcvtss2sh ins bld
  | OP.VCVTSD2SH ->
    AVX512Lifter.vcvtsd2sh ins bld
  | OP.VCVTSI2SH ->
    AVX512Lifter.vcvtsi2sh ins bld
  | OP.VCVTUSI2SH ->
    AVX512Lifter.vcvtusi2sh ins bld
  | OP.VCVTSH2SI ->
    AVX512Lifter.vcvtsh2si ins bld
  | OP.VCVTTSH2SI ->
    AVX512Lifter.vcvttsh2si ins bld
  | OP.VCVTSH2USI ->
    AVX512Lifter.vcvtsh2usi ins bld
  | OP.VCVTTSH2USI ->
    AVX512Lifter.vcvttsh2usi ins bld
  | OP.VBCSTNESH2PS ->
    AVX512Lifter.vbcstnesh2ps ins bld
  | OP.VCVTNEEPH2PS ->
    AVX512Lifter.vcvtneeph2ps ins bld
  | OP.VCVTNEOPH2PS ->
    AVX512Lifter.vcvtneoph2ps ins bld
  | OP.VFMULCPH ->
    AVX512Lifter.vfmulcph ins bld
  | OP.VFCMULCPH ->
    AVX512Lifter.vfcmulcph ins bld
  | OP.VFMADDCPH ->
    AVX512Lifter.vfmaddcph ins bld
  | OP.VFCMADDCPH ->
    AVX512Lifter.vfcmaddcph ins bld
  | OP.VFMULCSH ->
    AVX512Lifter.vfmulcsh ins bld
  | OP.VFCMULCSH ->
    AVX512Lifter.vfcmulcsh ins bld
  | OP.VFMADDCSH ->
    AVX512Lifter.vfmaddcsh ins bld
  | OP.VFCMADDCSH ->
    AVX512Lifter.vfcmaddcsh ins bld
  | OP.VFMADD132PH ->
    AVXLifter.vfmadd132ph ins bld
  | OP.VFMADD132SH ->
    AVXLifter.vfmadd132sh ins bld
  | OP.VFMADD213PH ->
    AVXLifter.vfmadd213ph ins bld
  | OP.VFMADD213SH ->
    AVXLifter.vfmadd213sh ins bld
  | OP.VFMADD231PH ->
    AVXLifter.vfmadd231ph ins bld
  | OP.VFMADD231SH ->
    AVXLifter.vfmadd231sh ins bld
  | OP.VFMSUB132PH ->
    AVXLifter.vfmsub132ph ins bld
  | OP.VFMSUB132SH ->
    AVXLifter.vfmsub132sh ins bld
  | OP.VFMSUB213PH ->
    AVXLifter.vfmsub213ph ins bld
  | OP.VFMSUB213SH ->
    AVXLifter.vfmsub213sh ins bld
  | OP.VFMSUB231PH ->
    AVXLifter.vfmsub231ph ins bld
  | OP.VFMSUB231SH ->
    AVXLifter.vfmsub231sh ins bld
  | OP.VFNMADD132PH ->
    AVXLifter.vfnmadd132ph ins bld
  | OP.VFNMADD132SH ->
    AVXLifter.vfnmadd132sh ins bld
  | OP.VFNMADD213PH ->
    AVXLifter.vfnmadd213ph ins bld
  | OP.VFNMADD213SH ->
    AVXLifter.vfnmadd213sh ins bld
  | OP.VFNMADD231PH ->
    AVXLifter.vfnmadd231ph ins bld
  | OP.VFNMADD231SH ->
    AVXLifter.vfnmadd231sh ins bld
  | OP.VFNMSUB132PH ->
    AVXLifter.vfnmsub132ph ins bld
  | OP.VFNMSUB132SH ->
    AVXLifter.vfnmsub132sh ins bld
  | OP.VFNMSUB213PH ->
    AVXLifter.vfnmsub213ph ins bld
  | OP.VFNMSUB213SH ->
    AVXLifter.vfnmsub213sh ins bld
  | OP.VFNMSUB231PH ->
    AVXLifter.vfnmsub231ph ins bld
  | OP.VFNMSUB231SH ->
    AVXLifter.vfnmsub231sh ins bld
  | OP.VFMADDSUB132PH ->
    AVXLifter.vfmaddsub132ph ins bld
  | OP.VFMADDSUB213PH ->
    AVXLifter.vfmaddsub213ph ins bld
  | OP.VFMADDSUB231PH ->
    AVXLifter.vfmaddsub231ph ins bld
  | OP.VFMSUBADD132PH ->
    AVXLifter.vfmsubadd132ph ins bld
  | OP.VFMSUBADD213PH ->
    AVXLifter.vfmsubadd213ph ins bld
  | OP.VFMSUBADD231PH ->
    AVXLifter.vfmsubadd231ph ins bld
  | OP.VP4DPWSSD ->
    AVX512Lifter.vp4dpwssd ins bld
  | OP.VP4DPWSSDS ->
    AVX512Lifter.vp4dpwssds ins bld
  | OP.VEXP2PD ->
    AVX512Lifter.vexp2pd ins bld
  | OP.VEXP2PS ->
    AVX512Lifter.vexp2ps ins bld
  | OP.V4FMADDPS ->
    AVXLifter.v4fmaddps ins bld
  | OP.V4FNMADDPS ->
    AVXLifter.v4fnmaddps ins bld
  | OP.V4FMADDSS ->
    AVXLifter.v4fmaddss ins bld
  | OP.V4FNMADDSS ->
    AVXLifter.v4fnmaddss ins bld
  | o ->
    raise <| NotImplementedIRException(Opcode.toString o)
