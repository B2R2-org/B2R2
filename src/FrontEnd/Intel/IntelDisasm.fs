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

module B2R2.FrontEnd.Intel.Disasm

open B2R2
open B2R2.FrontEnd.BinLifter

type Disasm = delegate of INameReadable * DisasmBuilder * InsInfo -> unit

let opCodeToString = function
  | Opcode.AAA -> "aaa"
  | Opcode.AAD -> "aad"
  | Opcode.AAM -> "aam"
  | Opcode.AAS -> "aas"
  | Opcode.ADC -> "adc"
  | Opcode.ADCX -> "adcx"
  | Opcode.ADD -> "add"
  | Opcode.ADDPD -> "addpd"
  | Opcode.ADDPS -> "addps"
  | Opcode.ADDSD -> "addsd"
  | Opcode.ADDSS -> "addss"
  | Opcode.ADDSUBPD -> "addsubpd"
  | Opcode.ADDSUBPS -> "addsubps"
  | Opcode.ADOX -> "adox"
  | Opcode.AESDEC -> "aesdec"
  | Opcode.AESDECLAST -> "aesdeclast"
  | Opcode.AESENC -> "aesenc"
  | Opcode.AESENCLAST -> "aesenclast"
  | Opcode.AESIMC -> "aesimc"
  | Opcode.AESKEYGENASSIST -> "aeskeygenassist"
  | Opcode.AND -> "and"
  | Opcode.ANDN -> "andn"
  | Opcode.ANDNPD -> "andnpd"
  | Opcode.ANDNPS -> "andnps"
  | Opcode.ANDPD -> "andpd"
  | Opcode.ANDPS -> "andps"
  | Opcode.ARPL -> "arpl"
  | Opcode.BEXTR -> "bextr"
  | Opcode.BLENDPD -> "blendpd"
  | Opcode.BLENDPS -> "blendps"
  | Opcode.BLENDVPD -> "blendvpd"
  | Opcode.BLENDVPS -> "blendvps"
  | Opcode.BLSI -> "blsi"
  | Opcode.BLSMSK -> "blsmsk"
  | Opcode.BLSR -> "blsr"
  | Opcode.BNDCL -> "bndcl"
  | Opcode.BNDCN -> "bndcn"
  | Opcode.BNDCU -> "bndcu"
  | Opcode.BNDLDX -> "bndldx"
  | Opcode.BNDMK -> "bndmk"
  | Opcode.BNDMOV -> "bndmov"
  | Opcode.BNDSTX -> "bndstx"
  | Opcode.BOUND -> "bound"
  | Opcode.BSF -> "bsf"
  | Opcode.BSR -> "bsr"
  | Opcode.BSWAP -> "bswap"
  | Opcode.BT -> "bt"
  | Opcode.BTC -> "btc"
  | Opcode.BTR -> "btr"
  | Opcode.BTS -> "bts"
  | Opcode.BZHI -> "bzhi"
  | Opcode.CALLFar | Opcode.CALLNear -> "call"
  | Opcode.CBW -> "cbw"
  | Opcode.CDQ -> "cdq"
  | Opcode.CDQE -> "cdqe"
  | Opcode.CLAC -> "clac"
  | Opcode.CLC -> "clc"
  | Opcode.CLD -> "cld"
  | Opcode.CLFLUSH -> "clflush"
  | Opcode.CLFLUSHOPT -> "clflushopt"
  | Opcode.CLI -> "cli"
  | Opcode.CLRSSBSY -> "clrssbsy"
  | Opcode.CLTS -> "clts"
  | Opcode.CLWB -> "clwb"
  | Opcode.CMC -> "cmc"
  | Opcode.CMOVA -> "cmova"
  | Opcode.CMOVAE -> "cmovae"
  | Opcode.CMOVB -> "cmovb"
  | Opcode.CMOVBE -> "cmovbe"
  | Opcode.CMOVC -> "cmovc"
  | Opcode.CMOVG -> "cmovg"
  | Opcode.CMOVGE -> "cmovge"
  | Opcode.CMOVL -> "cmovl"
  | Opcode.CMOVLE -> "cmovle"
  | Opcode.CMOVNC -> "cmovnc"
  | Opcode.CMOVNO -> "cmovno"
  | Opcode.CMOVNP -> "cmovnp"
  | Opcode.CMOVNS -> "cmovns"
  | Opcode.CMOVNZ -> "cmovnz"
  | Opcode.CMOVO -> "cmovo"
  | Opcode.CMOVP -> "cmovp"
  | Opcode.CMOVS -> "cmovs"
  | Opcode.CMOVZ -> "cmovz"
  | Opcode.CMP -> "cmp"
  | Opcode.CMPPD -> "cmppd"
  | Opcode.CMPPS -> "cmpps"
  | Opcode.CMPSB -> "cmpsb"
  | Opcode.CMPSD -> "cmpsd"
  | Opcode.CMPSQ -> "cmpsq"
  | Opcode.CMPSS -> "cmpss"
  | Opcode.CMPSW -> "cmpsw"
  | Opcode.CMPXCHG -> "cmpxchg"
  | Opcode.CMPXCHG16B -> "cmpxchg16b"
  | Opcode.CMPXCHG8B -> "cmpxchg8b"
  | Opcode.COMISD -> "comisd"
  | Opcode.COMISS -> "comiss"
  | Opcode.CPUID -> "cpuid"
  | Opcode.CQO -> "cqo"
  | Opcode.CRC32 -> "crc32"
  | Opcode.CVTDQ2PD -> "cvtdq2pd"
  | Opcode.CVTDQ2PS -> "cvtdq2ps"
  | Opcode.CVTPD2DQ -> "cvtpd2dq"
  | Opcode.CVTPD2PI -> "cvtpd2pi"
  | Opcode.CVTPD2PS -> "cvtpd2ps"
  | Opcode.CVTPI2PD -> "cvtpi2pd"
  | Opcode.CVTPI2PS -> "cvtpi2ps"
  | Opcode.CVTPS2DQ -> "cvtps2dq"
  | Opcode.CVTPS2PD -> "cvtps2pd"
  | Opcode.CVTPS2PI -> "cvtps2pi"
  | Opcode.CVTSD2SI -> "cvtsd2si"
  | Opcode.CVTSD2SS -> "cvtsd2ss"
  | Opcode.CVTSI2SD -> "cvtsi2sd"
  | Opcode.CVTSI2SS -> "cvtsi2ss"
  | Opcode.CVTSS2SD -> "cvtss2sd"
  | Opcode.CVTSS2SI -> "cvtss2si"
  | Opcode.CVTTPD2DQ -> "cvttpd2dq"
  | Opcode.CVTTPD2PI -> "cvttpd2pi"
  | Opcode.CVTTPS2DQ -> "cvttps2dq"
  | Opcode.CVTTPS2PI -> "cvttps2pi"
  | Opcode.CVTTSD2SI -> "cvttsd2si"
  | Opcode.CVTTSS2SI -> "cvttss2si"
  | Opcode.CWD -> "cwd"
  | Opcode.CWDE -> "cwde"
  | Opcode.DAA -> "daa"
  | Opcode.DAS -> "das"
  | Opcode.DEC -> "dec"
  | Opcode.DIV -> "div"
  | Opcode.DIVPD -> "divpd"
  | Opcode.DIVPS -> "divps"
  | Opcode.DIVSD -> "divsd"
  | Opcode.DIVSS -> "divss"
  | Opcode.DPPD -> "dppd"
  | Opcode.DPPS -> "dpps"
  | Opcode.EMMS -> "emms"
  | Opcode.ENCLS -> "encls"
  | Opcode.ENCLU -> "enclu"
  | Opcode.ENDBR32 -> "endbr32"
  | Opcode.ENDBR64 -> "endbr64"
  | Opcode.ENTER -> "enter"
  | Opcode.EXTRACTPS -> "extractps"
  | Opcode.EXTRQ -> "extrq"
  | Opcode.F2XM1 -> "f2xm1"
  | Opcode.FABS -> "fabs"
  | Opcode.FADD -> "fadd"
  | Opcode.FADDP -> "faddp"
  | Opcode.FBLD -> "fbld"
  | Opcode.FBSTP -> "fbstp"
  | Opcode.FCHS -> "fchs"
  | Opcode.FCLEX -> "fclex"
  | Opcode.FCMOVB -> "fcmovb"
  | Opcode.FCMOVBE -> "fcmovbe"
  | Opcode.FCMOVE -> "fcmove"
  | Opcode.FCMOVNB -> "fcmovnb"
  | Opcode.FCMOVNBE -> "fcmovnbe"
  | Opcode.FCMOVNE -> "fcmovne"
  | Opcode.FCMOVNU -> "fcmovnu"
  | Opcode.FCMOVU -> "fcmovu"
  | Opcode.FCOM -> "fcom"
  | Opcode.FCOMI -> "fcomi"
  | Opcode.FCOMIP -> "fcomip"
  | Opcode.FCOMP -> "fcomp"
  | Opcode.FCOMPP -> "fcompp"
  | Opcode.FCOS -> "fcos"
  | Opcode.FDECSTP -> "fdecstp"
  | Opcode.FDIV -> "fdiv"
  | Opcode.FDIVP -> "fdivp"
  | Opcode.FDIVR -> "fdivr"
  | Opcode.FDIVRP -> "fdivrp"
  | Opcode.FFREE -> "ffree"
  | Opcode.FFREEP -> "ffreep"
  | Opcode.FIADD -> "fiadd"
  | Opcode.FICOM -> "ficom"
  | Opcode.FICOMP -> "ficomp"
  | Opcode.FIDIV -> "fidiv"
  | Opcode.FIDIVR -> "fidivr"
  | Opcode.FILD -> "fild"
  | Opcode.FIMUL -> "fimul"
  | Opcode.FINCSTP -> "fincstp"
  | Opcode.FINIT -> "finit"
  | Opcode.FIST -> "fist"
  | Opcode.FISTP -> "fistp"
  | Opcode.FISTTP -> "fisttp"
  | Opcode.FISUB -> "fisub"
  | Opcode.FISUBR -> "fisubr"
  | Opcode.FLD -> "fld"
  | Opcode.FLD1 -> "fld1"
  | Opcode.FLDCW -> "fldcw"
  | Opcode.FLDENV -> "fldenv"
  | Opcode.FLDL2E -> "fldl2e"
  | Opcode.FLDL2T -> "fldl2t"
  | Opcode.FLDLG2 -> "fldlg2"
  | Opcode.FLDLN2 -> "fldln2"
  | Opcode.FLDPI -> "fldpi"
  | Opcode.FLDZ -> "fldz"
  | Opcode.FMUL -> "fmul"
  | Opcode.FMULP -> "fmulp"
  | Opcode.FNCLEX -> "fnclex"
  | Opcode.FNINIT -> "fninit"
  | Opcode.FNOP -> "fnop"
  | Opcode.FNSAVE -> "fnsave"
  | Opcode.FNSTCW -> "fnstcw"
  | Opcode.FNSTENV -> "fnstenv"
  | Opcode.FNSTSW -> "fnstsw"
  | Opcode.FPATAN -> "fpatan"
  | Opcode.FPREM -> "fprem"
  | Opcode.FPREM1 -> "fprem1"
  | Opcode.FPTAN -> "fptan"
  | Opcode.FRNDINT -> "frndint"
  | Opcode.FRSTOR -> "frstor"
  | Opcode.FSAVE -> "fsave"
  | Opcode.FSCALE -> "fscale"
  | Opcode.FSIN -> "fsin"
  | Opcode.FSINCOS -> "fsincos"
  | Opcode.FSQRT -> "fsqrt"
  | Opcode.FST -> "fst"
  | Opcode.FSTCW -> "fstcw"
  | Opcode.FSTENV -> "fstenv"
  | Opcode.FSTP -> "fstp"
  | Opcode.FSTSW -> "fstsw"
  | Opcode.FSUB -> "fsub"
  | Opcode.FSUBP -> "fsubp"
  | Opcode.FSUBR -> "fsubr"
  | Opcode.FSUBRP -> "fsubrp"
  | Opcode.FTST -> "ftst"
  | Opcode.FUCOM -> "fucom"
  | Opcode.FUCOMI -> "fucomi"
  | Opcode.FUCOMIP -> "fucomip"
  | Opcode.FUCOMP -> "fucomp"
  | Opcode.FUCOMPP -> "fucompp"
  | Opcode.FWAIT -> "fwait"
  | Opcode.FXAM -> "fxam"
  | Opcode.FXCH -> "fxch"
  | Opcode.FXRSTOR -> "fxrstor"
  | Opcode.FXRSTOR64 -> "fxrstor64"
  | Opcode.FXSAVE -> "fxsave"
  | Opcode.FXSAVE64 -> "fxsave64"
  | Opcode.FXTRACT -> "fxtract"
  | Opcode.FYL2X -> "fyl2x"
  | Opcode.FYL2XP1 -> "fyl2xp1"
  | Opcode.GETSEC -> "getsec"
  | Opcode.GF2P8AFFINEINVQB -> "gf2p8affineinvqb"
  | Opcode.GF2P8AFFINEQB -> "gf2p8affineqb"
  | Opcode.GF2P8MULB -> "gf2p8mulb"
  | Opcode.HADDPD -> "haddpd"
  | Opcode.HADDPS -> "haddps"
  | Opcode.HLT -> "hlt"
  | Opcode.HSUBPD -> "hsubpd"
  | Opcode.HSUBPS -> "hsubps"
  | Opcode.IDIV -> "idiv"
  | Opcode.IMUL -> "imul"
  | Opcode.IN -> "in"
  | Opcode.INC -> "inc"
  | Opcode.INCSSPD -> "incsspd"
  | Opcode.INCSSPQ -> "incsspq"
  | Opcode.INS -> "ins"
  | Opcode.INSB -> "insb"
  | Opcode.INSD -> "insd"
  | Opcode.INSERTPS -> "insertps"
  | Opcode.INSERTQ -> "insertq"
  | Opcode.INSW -> "insw"
  | Opcode.INT -> "int"
  | Opcode.INT1 -> "int1" (* ICEBP *)
  | Opcode.INT3 -> "int3"
  | Opcode.INTO -> "into"
  | Opcode.INVD -> "invd"
  | Opcode.INVEPT -> "invept"
  | Opcode.INVLPG -> "invlpg"
  | Opcode.INVPCID -> "invpcid"
  | Opcode.INVVPID -> "invvpid"
  | Opcode.IRET -> "iret"
  | Opcode.IRETD -> "iretd"
  | Opcode.IRETQ -> "iretq"
  | Opcode.IRETW -> "iretw"
  | Opcode.JNB -> "jnb"
  | Opcode.JB -> "jb"
  | Opcode.JCXZ -> "jcxz"
  | Opcode.JECXZ -> "jecxz"
  | Opcode.JNL -> "jnl"
  | Opcode.JMPFar | Opcode.JMPNear -> "jmp"
  | Opcode.JBE -> "jbe"
  | Opcode.JA -> "ja"
  | Opcode.JLE -> "jle"
  | Opcode.JL -> "jl"
  | Opcode.JG -> "jg"
  | Opcode.JNO -> "jno"
  | Opcode.JNS -> "jns"
  | Opcode.JNZ -> "jnz"
  | Opcode.JO -> "jo"
  | Opcode.JP -> "jp"
  | Opcode.JNP -> "jnp"
  | Opcode.JRCXZ -> "jrcxz"
  | Opcode.JS -> "js"
  | Opcode.JZ -> "jz"
  | Opcode.KADDB -> "kaddb"
  | Opcode.KADDD -> "kaddd"
  | Opcode.KADDQ -> "kaddq"
  | Opcode.KADDW -> "kaddw"
  | Opcode.KANDB -> "kandb"
  | Opcode.KANDD -> "kandd"
  | Opcode.KANDNB -> "kandnb"
  | Opcode.KANDND -> "kandnd"
  | Opcode.KANDNQ -> "kandnq"
  | Opcode.KANDNW -> "kandnw"
  | Opcode.KANDQ -> "kandq"
  | Opcode.KANDW -> "kandw"
  | Opcode.KMOVB -> "kmovb"
  | Opcode.KMOVD -> "kmovd"
  | Opcode.KMOVQ -> "kmovq"
  | Opcode.KMOVW -> "kmovw"
  | Opcode.KNOTB -> "knotb"
  | Opcode.KNOTD -> "knotd"
  | Opcode.KNOTQ -> "knotq"
  | Opcode.KNOTW -> "knotw"
  | Opcode.KORB -> "korb"
  | Opcode.KORD -> "kord"
  | Opcode.KORQ -> "korq"
  | Opcode.KORTESTB -> "kortestb"
  | Opcode.KORTESTD -> "kortestd"
  | Opcode.KORTESTQ -> "kortestq"
  | Opcode.KORTESTW -> "kortestw"
  | Opcode.KORW -> "korw"
  | Opcode.KSHIFTLB -> "kshiftlb"
  | Opcode.KSHIFTLD -> "kshiftld"
  | Opcode.KSHIFTLQ -> "kshiftlq"
  | Opcode.KSHIFTLW -> "kshiftlw"
  | Opcode.KSHIFTRB -> "kshiftrb"
  | Opcode.KSHIFTRD -> "kshiftrd"
  | Opcode.KSHIFTRQ -> "kshiftrq"
  | Opcode.KSHIFTRW -> "kshiftrw"
  | Opcode.KTESTB -> "ktestb"
  | Opcode.KTESTD -> "ktestd"
  | Opcode.KTESTQ -> "ktestq"
  | Opcode.KTESTW -> "ktestw"
  | Opcode.KUNPCKBW -> "kunpckbw"
  | Opcode.KUNPCKDQ -> "kunpckdq"
  | Opcode.KUNPCKWD -> "kunpckwd"
  | Opcode.KXNORB -> "kxnorb"
  | Opcode.KXNORD -> "kxnord"
  | Opcode.KXNORQ -> "kxnorq"
  | Opcode.KXNORW -> "kxnorw"
  | Opcode.KXORB -> "kxorb"
  | Opcode.KXORD -> "kxord"
  | Opcode.KXORQ -> "kxorq"
  | Opcode.KXORW -> "kxorw"
  | Opcode.LAHF -> "lahf"
  | Opcode.LAR -> "lar"
  | Opcode.LDDQU -> "lddqu"
  | Opcode.LDMXCSR -> "ldmxcsr"
  | Opcode.LDS -> "lds"
  | Opcode.LEA -> "lea"
  | Opcode.LEAVE -> "leave"
  | Opcode.LES -> "les"
  | Opcode.LFENCE -> "lfence"
  | Opcode.LFS -> "lfs"
  | Opcode.LGDT -> "lgdt"
  | Opcode.LGS -> "lgs"
  | Opcode.LIDT -> "lidt"
  | Opcode.LLDT -> "lldt"
  | Opcode.LMSW -> "lmsw"
  | Opcode.LOCK -> "lock"
  | Opcode.LODSB -> "lodsb"
  | Opcode.LODSD -> "lodsd"
  | Opcode.LODSQ -> "lodsq"
  | Opcode.LODSW -> "lodsw"
  | Opcode.LOOP -> "loop"
  | Opcode.LOOPE -> "loope"
  | Opcode.LOOPNE -> "loopne"
  | Opcode.LSL -> "lsl"
  | Opcode.LSS -> "lss"
  | Opcode.LTR -> "ltr"
  | Opcode.LZCNT -> "lzcnt"
  | Opcode.MASKMOVDQU -> "maskmovdqu"
  | Opcode.MASKMOVQ -> "maskmovq"
  | Opcode.MAXPD -> "maxpd"
  | Opcode.MAXPS -> "maxps"
  | Opcode.MAXSD -> "maxsd"
  | Opcode.MAXSS -> "maxss"
  | Opcode.MFENCE -> "mfence"
  | Opcode.MINPD -> "minpd"
  | Opcode.MINPS -> "minps"
  | Opcode.MINSD -> "minsd"
  | Opcode.MINSS -> "minss"
  | Opcode.MONITOR -> "monitor"
  | Opcode.MOV -> "mov"
  | Opcode.MOVAPD -> "movapd"
  | Opcode.MOVAPS -> "movaps"
  | Opcode.MOVBE -> "movbe"
  | Opcode.MOVD -> "movd"
  | Opcode.MOVDDUP -> "movddup"
  | Opcode.MOVDQ2Q -> "movdq2q"
  | Opcode.MOVDQA -> "movdqa"
  | Opcode.MOVDQU -> "movdqu"
  | Opcode.MOVHLPS -> "movhlps"
  | Opcode.MOVHPD -> "movhpd"
  | Opcode.MOVHPS -> "movhps"
  | Opcode.MOVLHPS -> "movlhps"
  | Opcode.MOVLPD -> "movlpd"
  | Opcode.MOVLPS -> "movlps"
  | Opcode.MOVMSKPD -> "movmskpd"
  | Opcode.MOVMSKPS -> "movmskps"
  | Opcode.MOVNTDQ -> "movntdq"
  | Opcode.MOVNTDQA -> "movntdqa"
  | Opcode.MOVNTI -> "movnti"
  | Opcode.MOVNTPD -> "movntpd"
  | Opcode.MOVNTPS -> "movntps"
  | Opcode.MOVNTQ -> "movntq"
  | Opcode.MOVQ -> "movq"
  | Opcode.MOVQ2DQ -> "movq2dq"
  | Opcode.MOVSB -> "movsb"
  | Opcode.MOVSD -> "movsd"
  | Opcode.MOVSHDUP -> "movshdup"
  | Opcode.MOVSLDUP -> "movsldup"
  | Opcode.MOVSQ -> "movsq"
  | Opcode.MOVSS -> "movss"
  | Opcode.MOVSW -> "movsw"
  | Opcode.MOVSX -> "movsx"
  | Opcode.MOVSXD -> "movsxd"
  | Opcode.MOVUPD -> "movupd"
  | Opcode.MOVUPS -> "movups"
  | Opcode.MOVZX -> "movzx"
  | Opcode.MPSADBW -> "mpsadbw"
  | Opcode.MUL -> "mul"
  | Opcode.MULPD -> "mulpd"
  | Opcode.MULPS -> "mulps"
  | Opcode.MULSD -> "mulsd"
  | Opcode.MULSS -> "mulss"
  | Opcode.MULX -> "mulx"
  | Opcode.MWAIT -> "mwait"
  | Opcode.NEG -> "neg"
  | Opcode.NOP -> "nop"
  | Opcode.NOT -> "not"
  | Opcode.OR -> "or"
  | Opcode.ORPD -> "orpd"
  | Opcode.ORPS -> "orps"
  | Opcode.OUT -> "out"
  | Opcode.OUTS -> "outs"
  | Opcode.OUTSB -> "outsb"
  | Opcode.OUTSD -> "outsd"
  | Opcode.OUTSW -> "outsw"
  | Opcode.PABSB -> "pabsb"
  | Opcode.PABSD -> "pabsd"
  | Opcode.PABSW -> "pabsw"
  | Opcode.PACKSSDW -> "packssdw"
  | Opcode.PACKSSWB -> "packsswb"
  | Opcode.PACKUSDW -> "packusdw"
  | Opcode.PACKUSWB -> "packuswb"
  | Opcode.PADDB -> "paddb"
  | Opcode.PADDD -> "paddd"
  | Opcode.PADDQ -> "paddq"
  | Opcode.PADDSB -> "paddsb"
  | Opcode.PADDSW -> "paddsw"
  | Opcode.PADDUSB -> "paddusb"
  | Opcode.PADDUSW -> "paddusw"
  | Opcode.PADDW -> "paddw"
  | Opcode.PALIGNR -> "palignr"
  | Opcode.PAND -> "pand"
  | Opcode.PANDN -> "pandn"
  | Opcode.PAUSE -> "pause"
  | Opcode.PAVGB -> "pavgb"
  | Opcode.PAVGW -> "pavgw"
  | Opcode.PBLENDVB -> "pblendvb"
  | Opcode.PBLENDW -> "pblendw"
  | Opcode.PCLMULQDQ -> "pclmulqdq"
  | Opcode.PCMPEQB -> "pcmpeqb"
  | Opcode.PCMPEQD -> "pcmpeqd"
  | Opcode.PCMPEQQ -> "pcmpeqq"
  | Opcode.PCMPEQW -> "pcmpeqw"
  | Opcode.PCMPESTRI -> "pcmpestri"
  | Opcode.PCMPESTRM -> "pcmpestrm"
  | Opcode.PCMPGTB -> "pcmpgtb"
  | Opcode.PCMPGTD -> "pcmpgtd"
  | Opcode.PCMPGTQ -> "pcmpgtq"
  | Opcode.PCMPGTW -> "pcmpgtw"
  | Opcode.PCMPISTRI -> "pcmpistri"
  | Opcode.PCMPISTRM -> "pcmpistrm"
  | Opcode.PDEP -> "pdep"
  | Opcode.PEXT -> "pext"
  | Opcode.PEXTRB -> "pextrb"
  | Opcode.PEXTRD -> "pextrd"
  | Opcode.PEXTRQ -> "pextrq"
  | Opcode.PEXTRW -> "pextrw"
  | Opcode.PHADDD -> "phaddd"
  | Opcode.PHADDSW -> "phaddsw"
  | Opcode.PHADDW -> "phaddw"
  | Opcode.PHMINPOSUW -> "phminposuw"
  | Opcode.PHSUBD -> "phsubd"
  | Opcode.PHSUBSW -> "phsubsw"
  | Opcode.PHSUBW -> "phsubw"
  | Opcode.PINSRB -> "pinsrb"
  | Opcode.PINSRD -> "pinsrd"
  | Opcode.PINSRQ -> "pinsrq"
  | Opcode.PINSRW -> "pinsrw"
  | Opcode.PMADDUBSW -> "pmaddubsw"
  | Opcode.PMADDWD -> "pmaddwd"
  | Opcode.PMAXSB -> "pmaxsb"
  | Opcode.PMAXSD -> "pmaxsd"
  | Opcode.PMAXSW -> "pmaxsw"
  | Opcode.PMAXUB -> "pmaxub"
  | Opcode.PMAXUD -> "pmaxud"
  | Opcode.PMAXUW -> "pmaxuw"
  | Opcode.PMINSB -> "pminsb"
  | Opcode.PMINSD -> "pminsd"
  | Opcode.PMINSW -> "pminsw"
  | Opcode.PMINUB -> "pminub"
  | Opcode.PMINUD -> "pminud"
  | Opcode.PMINUW -> "pminuw"
  | Opcode.PMOVMSKB -> "pmovmskb"
  | Opcode.PMOVSXBD -> "pmovsxbd"
  | Opcode.PMOVSXBQ -> "pmovsxbq"
  | Opcode.PMOVSXBW -> "pmovsxbw"
  | Opcode.PMOVSXDQ -> "pmovsxdq"
  | Opcode.PMOVSXWD -> "pmovsxwd"
  | Opcode.PMOVSXWQ -> "pmovsxwq"
  | Opcode.PMOVZXBD -> "pmovzxbd"
  | Opcode.PMOVZXBQ -> "pmovzxbq"
  | Opcode.PMOVZXBW -> "pmovzxbw"
  | Opcode.PMOVZXDQ -> "pmovzxdq"
  | Opcode.PMOVZXWD -> "pmovzxwd"
  | Opcode.PMOVZXWQ -> "pmovzxwq"
  | Opcode.PMULDQ -> "pmuldq"
  | Opcode.PMULHRSW -> "pmulhrsw"
  | Opcode.PMULHUW -> "pmulhuw"
  | Opcode.PMULHW -> "pmulhw"
  | Opcode.PMULLD -> "pmulld"
  | Opcode.PMULLW -> "pmullw"
  | Opcode.PMULUDQ -> "pmuludq"
  | Opcode.POP -> "pop"
  | Opcode.POPA -> "popa"
  | Opcode.POPAD -> "popad"
  | Opcode.POPCNT -> "popcnt"
  | Opcode.POPF -> "popf"
  | Opcode.POPFD -> "popfd"
  | Opcode.POPFQ -> "popfq"
  | Opcode.POR -> "por"
  | Opcode.PREFETCHNTA -> "prefetchnta"
  | Opcode.PREFETCHT0 -> "prefetcht0"
  | Opcode.PREFETCHT1 -> "prefetcht1"
  | Opcode.PREFETCHT2 -> "prefetcht2"
  | Opcode.PREFETCHW -> "prefetchw"
  | Opcode.PREFETCHWT1 -> "prefetchwt1"
  | Opcode.PSADBW -> "psadbw"
  | Opcode.PSHUFB -> "pshufb"
  | Opcode.PSHUFD -> "pshufd"
  | Opcode.PSHUFHW -> "pshufhw"
  | Opcode.PSHUFLW -> "pshuflw"
  | Opcode.PSHUFW -> "pshufw"
  | Opcode.PSIGNB -> "psignb"
  | Opcode.PSIGND -> "psignd"
  | Opcode.PSIGNW -> "psignw"
  | Opcode.PSLLD -> "pslld"
  | Opcode.PSLLDQ -> "pslldq"
  | Opcode.PSLLQ -> "psllq"
  | Opcode.PSLLW -> "psllw"
  | Opcode.PSRAD -> "psrad"
  | Opcode.PSRAW -> "psraw"
  | Opcode.PSRLD -> "psrld"
  | Opcode.PSRLDQ -> "psrldq"
  | Opcode.PSRLQ -> "psrlq"
  | Opcode.PSRLW -> "psrlw"
  | Opcode.PSUBB -> "psubb"
  | Opcode.PSUBD -> "psubd"
  | Opcode.PSUBQ -> "psubq"
  | Opcode.PSUBSB -> "psubsb"
  | Opcode.PSUBSW -> "psubsw"
  | Opcode.PSUBUSB -> "psubusb"
  | Opcode.PSUBUSW -> "psubusw"
  | Opcode.PSUBW -> "psubw"
  | Opcode.PTEST -> "ptest"
  | Opcode.PUNPCKHBW -> "punpckhbw"
  | Opcode.PUNPCKHDQ -> "punpckhdq"
  | Opcode.PUNPCKHQDQ -> "punpckhqdq"
  | Opcode.PUNPCKHWD -> "punpckhwd"
  | Opcode.PUNPCKLBW -> "punpcklbw"
  | Opcode.PUNPCKLDQ -> "punpckldq"
  | Opcode.PUNPCKLQDQ -> "punpcklqdq"
  | Opcode.PUNPCKLWD -> "punpcklwd"
  | Opcode.PUSH -> "push"
  | Opcode.PUSHA -> "pusha"
  | Opcode.PUSHAD -> "pushad"
  | Opcode.PUSHF -> "pushf"
  | Opcode.PUSHFD -> "pushfd"
  | Opcode.PUSHFQ -> "pushfq"
  | Opcode.PXOR -> "pxor"
  | Opcode.RCL -> "rcl"
  | Opcode.RCPPS -> "rcpps"
  | Opcode.RCPSS -> "rcpss"
  | Opcode.RCR -> "rcr"
  | Opcode.RDFSBASE -> "rdfsbase"
  | Opcode.RDGSBASE -> "rdgsbase"
  | Opcode.RDMSR -> "rdmsr"
  | Opcode.RDPKRU -> "rdpkru"
  | Opcode.RDPMC -> "rdpmc"
  | Opcode.RDRAND -> "rdrand"
  | Opcode.RDSEED -> "rdseed"
  | Opcode.RDSSPD -> "rdsspd"
  | Opcode.RDSSPQ -> "rdsspq"
  | Opcode.RDTSC -> "rdtsc"
  | Opcode.RDTSCP -> "rdtscp"
  | Opcode.REP -> "rep"
  | Opcode.REPE -> "repe"
  | Opcode.REPNE -> "repne"
  | Opcode.REPNZ -> "repnz"
  | Opcode.REPZ -> "repz"
  | Opcode.RETFar | Opcode.RETFarImm
  | Opcode.RETNear | Opcode.RETNearImm -> "ret"
  | Opcode.ROL -> "rol"
  | Opcode.ROR -> "ror"
  | Opcode.RORX -> "rorx"
  | Opcode.ROUNDPD -> "roundpd"
  | Opcode.ROUNDPS -> "roundps"
  | Opcode.ROUNDSD -> "roundsd"
  | Opcode.ROUNDSS -> "roundss"
  | Opcode.RSM -> "rsm"
  | Opcode.RSQRTPS -> "rsqrtps"
  | Opcode.RSQRTSS -> "rsqrtss"
  | Opcode.RSTORSSP -> "rstorssp"
  | Opcode.SAHF -> "sahf"
  | Opcode.SAR -> "sar"
  | Opcode.SARX -> "sarx"
  | Opcode.SAVEPREVSSP -> "saveprevssp"
  | Opcode.SBB -> "sbb"
  | Opcode.SCASB -> "scasb"
  | Opcode.SCASD -> "scasd"
  | Opcode.SCASQ -> "scasq"
  | Opcode.SCASW -> "scasw"
  | Opcode.SETA -> "seta"
  | Opcode.SETB -> "setb"
  | Opcode.SETBE -> "setbe"
  | Opcode.SETG -> "setg"
  | Opcode.SETL -> "setl"
  | Opcode.SETLE -> "setle"
  | Opcode.SETNB -> "setnb"
  | Opcode.SETNL -> "setnl"
  | Opcode.SETNO -> "setno"
  | Opcode.SETNP -> "setnp"
  | Opcode.SETNS -> "setns"
  | Opcode.SETNZ -> "setnz"
  | Opcode.SETO -> "seto"
  | Opcode.SETP -> "setp"
  | Opcode.SETS -> "sets"
  | Opcode.SETSSBSY -> "setssbsy"
  | Opcode.SETZ -> "setz"
  | Opcode.SFENCE -> "sfence"
  | Opcode.SGDT -> "sgdt"
  | Opcode.SHA1MSG1 -> "sha1msg1"
  | Opcode.SHA1MSG2 -> "sha1msg2"
  | Opcode.SHA1NEXTE -> "sha1nexte"
  | Opcode.SHA1RNDS4 -> "sha1rnds4"
  | Opcode.SHA256MSG1 -> "sha256msg1"
  | Opcode.SHA256MSG2 -> "sha256msg2"
  | Opcode.SHA256RNDS2 -> "sha256rnds2"
  | Opcode.SHL -> "shl"
  | Opcode.SHLD -> "shld"
  | Opcode.SHLX -> "shlx"
  | Opcode.SHR -> "shr"
  | Opcode.SHRD -> "shrd"
  | Opcode.SHRX -> "shrx"
  | Opcode.SHUFPD -> "shufpd"
  | Opcode.SHUFPS -> "shufps"
  | Opcode.SIDT -> "sidt"
  | Opcode.SLDT -> "sldt"
  | Opcode.SMSW -> "smsw"
  | Opcode.SQRTPD -> "sqrtpd"
  | Opcode.SQRTPS -> "sqrtps"
  | Opcode.SQRTSD -> "sqrtsd"
  | Opcode.SQRTSS -> "sqrtss"
  | Opcode.STAC -> "stac"
  | Opcode.STC -> "stc"
  | Opcode.STD -> "std"
  | Opcode.STI -> "sti"
  | Opcode.STMXCSR -> "stmxcsr"
  | Opcode.STOSB -> "stosb"
  | Opcode.STOSD -> "stosd"
  | Opcode.STOSQ -> "stosq"
  | Opcode.STOSW -> "stosw"
  | Opcode.STR -> "str"
  | Opcode.SUB -> "sub"
  | Opcode.SUBPD -> "subpd"
  | Opcode.SUBPS -> "subps"
  | Opcode.SUBSD -> "subsd"
  | Opcode.SUBSS -> "subss"
  | Opcode.SWAPGS -> "swapgs"
  | Opcode.SYSCALL -> "syscall"
  | Opcode.SYSENTER -> "sysenter"
  | Opcode.SYSEXIT -> "sysexit"
  | Opcode.SYSRET -> "sysret"
  | Opcode.TEST -> "test"
  | Opcode.TZCNT -> "tzcnt"
  | Opcode.UCOMISD -> "ucomisd"
  | Opcode.UCOMISS -> "ucomiss"
  | Opcode.UD0 -> "ud0"
  | Opcode.UD1 -> "ud1"
  | Opcode.UD2 -> "ud2"
  | Opcode.UNPCKHPD -> "unpckhpd"
  | Opcode.UNPCKHPS -> "unpckhps"
  | Opcode.UNPCKLPD -> "unpcklpd"
  | Opcode.UNPCKLPS -> "unpcklps"
  | Opcode.V4FMADDPS -> "v4fmaddps"
  | Opcode.V4FMADDSS -> "v4fmaddss"
  | Opcode.V4FNMADDPS -> "v4fnmaddps"
  | Opcode.V4FNMADDSS -> "v4fnmaddss"
  | Opcode.VADDPD -> "vaddpd"
  | Opcode.VADDPS -> "vaddps"
  | Opcode.VADDSD -> "vaddsd"
  | Opcode.VADDSS -> "vaddss"
  | Opcode.VADDSUBPD -> "vaddsubpd"
  | Opcode.VADDSUBPS -> "vaddsubps"
  | Opcode.VAESDEC -> "vaesdec"
  | Opcode.VAESDECLAST -> "vaesdeclast"
  | Opcode.VAESENC -> "vaesenc"
  | Opcode.VAESENCLAST -> "vaesenclast"
  | Opcode.VALIGND -> "valignd"
  | Opcode.VALIGNQ -> "valignq"
  | Opcode.VANDNPD -> "vandnpd"
  | Opcode.VANDNPS -> "vandnps"
  | Opcode.VANDPD -> "vandpd"
  | Opcode.VANDPS -> "vandps"
  | Opcode.VBLENDMPD -> "vblendmpd"
  | Opcode.VBLENDMPS -> "vblendmps"
  | Opcode.VBLENDPD -> "vblendpd"
  | Opcode.VBLENDPS -> "vblendps"
  | Opcode.VBLENDVPD -> "vblendvpd"
  | Opcode.VBLENDVPS -> "vblendvps"
  | Opcode.VBROADCASTF128 -> "vbroadcastf128"
  | Opcode.VBROADCASTI128 -> "vbroadcasti128"
  | Opcode.VBROADCASTI32X2 -> "vbroadcasti32x2"
  | Opcode.VBROADCASTI32X4 -> "vbroadcasti32x4"
  | Opcode.VBROADCASTI32X8 -> "vbroadcasti32x8"
  | Opcode.VBROADCASTI64X2 -> "vbroadcasti64x2"
  | Opcode.VBROADCASTI64X4 -> "vbroadcasti64x4"
  | Opcode.VBROADCASTSD -> "vbroadcastsd"
  | Opcode.VBROADCASTSS -> "vbroadcastss"
  | Opcode.VCMPPD -> "vcmppd"
  | Opcode.VCMPPS -> "vcmpps"
  | Opcode.VCMPSD -> "vcmpsd"
  | Opcode.VCMPSS -> "vcmpss"
  | Opcode.VCOMISD -> "vcomisd"
  | Opcode.VCOMISS -> "vcomiss"
  | Opcode.VCOMPRESSPD -> "vcompresspd"
  | Opcode.VCOMPRESSPS -> "vcompressps"
  | Opcode.VCVTDQ2PD -> "vcvtdq2pd"
  | Opcode.VCVTDQ2PS -> "vcvtdq2ps"
  | Opcode.VCVTNE2PS2BF16 -> "vcvtne2ps2bf16"
  | Opcode.VCVTNEPS2BF16 -> "vcvtneps2bf16"
  | Opcode.VCVTPD2DQ -> "vcvtpd2dq"
  | Opcode.VCVTPD2PS -> "vcvtpd2ps"
  | Opcode.VCVTPD2QQ -> "vcvtpd2qq"
  | Opcode.VCVTPD2UDQ -> "vcvtpd2udq"
  | Opcode.VCVTPD2UQQ -> "vcvtpd2uqq"
  | Opcode.VCVTPH2PS -> "vcvtph2ps"
  | Opcode.VCVTPS2DQ -> "vcvtps2dq"
  | Opcode.VCVTPS2PD -> "vcvtps2pd"
  | Opcode.VCVTPS2PH -> "vcvtps2ph"
  | Opcode.VCVTPS2QQ -> "vcvtps2qq"
  | Opcode.VCVTPS2UDQ -> "vcvtps2udq"
  | Opcode.VCVTPS2UQQ -> "vcvtps2uqq"
  | Opcode.VCVTQQ2PD -> "vcvtqq2pd"
  | Opcode.VCVTQQ2PS -> "vcvtqq2ps"
  | Opcode.VCVTSD2SI -> "vcvtsd2si"
  | Opcode.VCVTSD2SS -> "vcvtsd2ss"
  | Opcode.VCVTSD2USI -> "vcvtsd2usi"
  | Opcode.VCVTSI2SD -> "vcvtsi2sd"
  | Opcode.VCVTSI2SS -> "vcvtsi2ss"
  | Opcode.VCVTSS2SD -> "vcvtss2sd"
  | Opcode.VCVTSS2SI -> "vcvtss2si"
  | Opcode.VCVTSS2USI -> "vcvtss2usi"
  | Opcode.VCVTTPD2DQ -> "vcvttpd2dq"
  | Opcode.VCVTTPD2QQ -> "vcvttpd2qq"
  | Opcode.VCVTTPD2UDQ -> "vcvttpd2udq"
  | Opcode.VCVTTPD2UQQ -> "vcvttpd2uqq"
  | Opcode.VCVTTPS2DQ -> "vcvttps2dq"
  | Opcode.VCVTTPS2QQ -> "vcvttps2qq"
  | Opcode.VCVTTPS2UDQ -> "vcvttps2udq"
  | Opcode.VCVTTPS2UQQ -> "vcvttps2uqq"
  | Opcode.VCVTTSD2SI -> "vcvttsd2si"
  | Opcode.VCVTTSD2USI -> "vcvttsd2usi"
  | Opcode.VCVTTSS2SI -> "vcvttss2si"
  | Opcode.VCVTTSS2USI -> "vcvttss2usi"
  | Opcode.VCVTUDQ2PD -> "vcvtudq2pd"
  | Opcode.VCVTUDQ2PS -> "vcvtudq2ps"
  | Opcode.VCVTUQQ2PD -> "vcvtuqq2pd"
  | Opcode.VCVTUQQ2PS -> "vcvtuqq2ps"
  | Opcode.VCVTUSI2SD -> "vcvtusi2sd"
  | Opcode.VCVTUSI2SS -> "vcvtusi2ss"
  | Opcode.VCVTUSI2USD -> "vcvtusi2usd"
  | Opcode.VCVTUSI2USS -> "vcvtusi2uss"
  | Opcode.VDBPSADBW -> "vdbpsadbw"
  | Opcode.VDIVPD -> "vdivpd"
  | Opcode.VDIVPS -> "vdivps"
  | Opcode.VDIVSD -> "vdivsd"
  | Opcode.VDIVSS -> "vdivss"
  | Opcode.VDPBF16PS -> "vdpbf16ps"
  | Opcode.VDPPD -> "vdppd"
  | Opcode.VDPPS -> "vdpps"
  | Opcode.VERR -> "verr"
  | Opcode.VERW -> "verw"
  | Opcode.VEXP2PD -> "vexp2pd"
  | Opcode.VEXP2PS -> "vexp2ps"
  | Opcode.VEXP2SD -> "vexp2sd"
  | Opcode.VEXP2SS -> "vexp2ss"
  | Opcode.VEXPANDPD -> "vexpandpd"
  | Opcode.VEXPANDPS -> "vexpandps"
  | Opcode.VEXTRACTF128 -> "vextractf128"
  | Opcode.VEXTRACTF32X4 -> "vextractf32x4"
  | Opcode.VEXTRACTF32X8 -> "vextractf32x8"
  | Opcode.VEXTRACTF64X2 -> "vextractf64x2"
  | Opcode.VEXTRACTF64X4 -> "vextractf64x4"
  | Opcode.VEXTRACTI128 -> "vextracti128"
  | Opcode.VEXTRACTI32X4 -> "vextracti32x4"
  | Opcode.VEXTRACTI32X8 -> "vextracti32x8"
  | Opcode.VEXTRACTI64X2 -> "vextracti64x2"
  | Opcode.VEXTRACTI64X4 -> "vextracti64x4"
  | Opcode.VEXTRACTPS -> "vextractps"
  | Opcode.VFIXUPIMMPD -> "vfixupimmpd"
  | Opcode.VFIXUPIMMPS -> "vfixupimmps"
  | Opcode.VFIXUPIMMSD -> "vfixupimmsd"
  | Opcode.VFIXUPIMMSS -> "vfixupimmss"
  | Opcode.VFMADD132PD -> "vfmadd132pd"
  | Opcode.VFMADD132PS -> "vfmadd132ps"
  | Opcode.VFMADD132SD -> "vfmadd132sd"
  | Opcode.VFMADD132SS -> "vfmadd132ss"
  | Opcode.VFMADD213PD -> "vfmadd213pd"
  | Opcode.VFMADD213PS -> "vfmadd213ps"
  | Opcode.VFMADD213SD -> "vfmadd213sd"
  | Opcode.VFMADD213SS -> "vfmadd213ss"
  | Opcode.VFMADD231PD -> "vfmadd231pd"
  | Opcode.VFMADD231PS -> "vfmadd231ps"
  | Opcode.VFMADD231SD -> "vfmadd231sd"
  | Opcode.VFMADD231SS -> "vfmadd231ss"
  | Opcode.VFMADDPD -> "vfmaddpd"
  | Opcode.VFMADDPS -> "vfmaddps"
  | Opcode.VFMADDSD -> "vfmaddsd"
  | Opcode.VFMADDSS -> "vfmaddss"
  | Opcode.VFMADDSUB132PD -> "vfmaddsub132pd"
  | Opcode.VFMADDSUB132PS -> "vfmaddsub132ps"
  | Opcode.VFMADDSUB213PD -> "vfmaddsub213pd"
  | Opcode.VFMADDSUB213PS -> "vfmaddsub213ps"
  | Opcode.VFMADDSUB231PD -> "vfmaddsub231pd"
  | Opcode.VFMADDSUB231PS -> "vfmaddsub231ps"
  | Opcode.VFMSUB132PD -> "vfmsub132pd"
  | Opcode.VFMSUB132PS -> "vfmsub132ps"
  | Opcode.VFMSUB132SD -> "vfmsub132sd"
  | Opcode.VFMSUB132SS -> "vfmsub132ss"
  | Opcode.VFMSUB213PD -> "vfmsub213pd"
  | Opcode.VFMSUB213PS -> "vfmsub213ps"
  | Opcode.VFMSUB213SD -> "vfmsub213sd"
  | Opcode.VFMSUB213SS -> "vfmsub213ss"
  | Opcode.VFMSUB231PD -> "vfmsub231pd"
  | Opcode.VFMSUB231PS -> "vfmsub231ps"
  | Opcode.VFMSUB231SD -> "vfmsub231sd"
  | Opcode.VFMSUB231SS -> "vfmsub231ss"
  | Opcode.VFMSUBADD132PD -> "vfmsubadd132pd"
  | Opcode.VFMSUBADD132PS -> "vfmsubadd132ps"
  | Opcode.VFMSUBADD213PD -> "vfmsubadd213pd"
  | Opcode.VFMSUBADD213PS -> "vfmsubadd213ps"
  | Opcode.VFMSUBADD231PD -> "vfmsubadd231pd"
  | Opcode.VFMSUBADD231PS -> "vfmsubadd231ps"
  | Opcode.VFNMADD132PD -> "vfnmadd132pd"
  | Opcode.VFNMADD132PS -> "vfnmadd132ps"
  | Opcode.VFNMADD132SD -> "vfnmadd132sd"
  | Opcode.VFNMADD132SS -> "vfnmadd132ss"
  | Opcode.VFNMADD213PD -> "vfnmadd213pd"
  | Opcode.VFNMADD213PS -> "vfnmadd213ps"
  | Opcode.VFNMADD213SD -> "vfnmadd213sd"
  | Opcode.VFNMADD213SS -> "vfnmadd213ss"
  | Opcode.VFNMADD231PD -> "vfnmadd231pd"
  | Opcode.VFNMADD231PS -> "vfnmadd231ps"
  | Opcode.VFNMADD231SD -> "vfnmadd231sd"
  | Opcode.VFNMADD231SS -> "vfnmadd231ss"
  | Opcode.VFNMSUB132PD -> "vfnmsub132pd"
  | Opcode.VFNMSUB132PS -> "vfnmsub132ps"
  | Opcode.VFNMSUB132SD -> "vfnmsub132sd"
  | Opcode.VFNMSUB132SS -> "vfnmsub132ss"
  | Opcode.VFNMSUB213PD -> "vfnmsub213pd"
  | Opcode.VFNMSUB213PS -> "vfnmsub213ps"
  | Opcode.VFNMSUB213SD -> "vfnmsub213sd"
  | Opcode.VFNMSUB213SS -> "vfnmsub213ss"
  | Opcode.VFNMSUB231PD -> "vfnmsub231pd"
  | Opcode.VFNMSUB231PS -> "vfnmsub231ps"
  | Opcode.VFNMSUB231SD -> "vfnmsub231sd"
  | Opcode.VFNMSUB231SS -> "vfnmsub231ss"
  | Opcode.VFPCLASSPD -> "vfpclasspd"
  | Opcode.VFPCLASSPS -> "vfpclassps"
  | Opcode.VFPCLASSSD -> "vfpclasssd"
  | Opcode.VFPCLASSSS -> "vfpclassss"
  | Opcode.VGATHERDPD -> "vgatherdpd"
  | Opcode.VGATHERDPS -> "vgatherdps"
  | Opcode.VGATHERPF0DPD -> "vgatherpf0dpd"
  | Opcode.VGATHERPF0DPS -> "vgatherpf0dps"
  | Opcode.VGATHERPF0QPD -> "vgatherpf0qpd"
  | Opcode.VGATHERPF0QPS -> "vgatherpf0qps"
  | Opcode.VGATHERPF1DPD -> "vgatherpf1dpd"
  | Opcode.VGATHERPF1DPS -> "vgatherpf1dps"
  | Opcode.VGATHERPF1QPD -> "vgatherpf1qpd"
  | Opcode.VGATHERPF1QPS -> "vgatherpf1qps"
  | Opcode.VGATHERQPD -> "vgatherqpd"
  | Opcode.VGATHERQPS -> "vgatherqps"
  | Opcode.VGETEXPPD -> "vgetexppd"
  | Opcode.VGETEXPPS -> "vgetexpps"
  | Opcode.VGETEXPSD -> "vgetexpsd"
  | Opcode.VGETEXPSS -> "vgetexpss"
  | Opcode.VGETMANTPD -> "vgetmantpd"
  | Opcode.VGETMANTPS -> "vgetmantps"
  | Opcode.VGETMANTSD -> "vgetmantsd"
  | Opcode.VGETMANTSS -> "vgetmantss"
  | Opcode.VGF2P8AFFINEINVQB -> "vgf2p8affineinvqb"
  | Opcode.VGF2P8AFFINEQB -> "vgf2p8affineqb"
  | Opcode.VGF2P8MULB -> "vgf2p8mulb"
  | Opcode.VHADDPD -> "vhaddpd"
  | Opcode.VHADDPS -> "vhaddps"
  | Opcode.VHSUBPD -> "vhsubpd"
  | Opcode.VHSUBPS -> "vhsubps"
  | Opcode.VINSERTF128 -> "vinsertf128"
  | Opcode.VINSERTF32X4 -> "vinsertf32x4"
  | Opcode.VINSERTF64X2 -> "vinsertf64x2"
  | Opcode.VINSERTF64X4 -> "vinsertf64x4"
  | Opcode.VINSERTI128 -> "vinserti128"
  | Opcode.VINSERTI32X8 -> "vinserti32x8"
  | Opcode.VINSERTI64X2 -> "vinserti64x2"
  | Opcode.VINSERTI64X4 -> "vinserti64x4"
  | Opcode.VINSERTPS -> "vinsertps"
  | Opcode.VLDDQU -> "vlddqu"
  | Opcode.VMASKMOVDQU -> "vmaskmovdqu"
  | Opcode.VMASKMOVPD -> "vmaskmovpd"
  | Opcode.VMASKMOVPS -> "vmaskmovps"
  | Opcode.VMAXPD -> "vmaxpd"
  | Opcode.VMAXPS -> "vmaxps"
  | Opcode.VMAXSD -> "vmaxsd"
  | Opcode.VMAXSS -> "vmaxss"
  | Opcode.VMCALL -> "vmcall"
  | Opcode.VMCLEAR -> "vmclear"
  | Opcode.VMFUNC -> "vmfunc"
  | Opcode.VMINPD -> "vminpd"
  | Opcode.VMINPS -> "vminps"
  | Opcode.VMINSD -> "vminsd"
  | Opcode.VMINSS -> "vminss"
  | Opcode.VMLAUNCH -> "vmlaunch"
  | Opcode.VMOVAPD -> "vmovapd"
  | Opcode.VMOVAPS -> "vmovaps"
  | Opcode.VMOVD -> "vmovd"
  | Opcode.VMOVDDUP -> "vmovddup"
  | Opcode.VMOVDQA -> "vmovdqa"
  | Opcode.VMOVDQA32 -> "vmovdqa32"
  | Opcode.VMOVDQA64 -> "vmovdqa64"
  | Opcode.VMOVDQU -> "vmovdqu"
  | Opcode.VMOVDQU16 -> "vmovdqu16"
  | Opcode.VMOVDQU32 -> "vmovdqu32"
  | Opcode.VMOVDQU64 -> "vmovdqu64"
  | Opcode.VMOVDQU8 -> "vmovdqu8"
  | Opcode.VMOVHLPS -> "vmovhlps"
  | Opcode.VMOVHPD -> "vmovhpd"
  | Opcode.VMOVHPS -> "vmovhps"
  | Opcode.VMOVLHPS -> "vmovlhps"
  | Opcode.VMOVLPD -> "vmovlpd"
  | Opcode.VMOVLPS -> "vmovlps"
  | Opcode.VMOVMSKPD -> "vmovmskpd"
  | Opcode.VMOVMSKPS -> "vmovmskps"
  | Opcode.VMOVNTDQ -> "vmovntdq"
  | Opcode.VMOVNTDQA -> "vmovntdqa"
  | Opcode.VMOVNTPD -> "vmovntpd"
  | Opcode.VMOVNTPS -> "vmovntps"
  | Opcode.VMOVQ -> "vmovq"
  | Opcode.VMOVSD -> "vmovsd"
  | Opcode.VMOVSHDUP -> "vmovshdup"
  | Opcode.VMOVSLDUP -> "vmovsldup"
  | Opcode.VMOVSS -> "vmovss"
  | Opcode.VMOVUPD -> "vmovupd"
  | Opcode.VMOVUPS -> "vmovups"
  | Opcode.VMPSADBW -> "vmpsadbw"
  | Opcode.VMPTRLD -> "vmptrld"
  | Opcode.VMPTRST -> "vmptrst"
  | Opcode.VMREAD -> "vmread"
  | Opcode.VMRESUME -> "vmresume"
  | Opcode.VMULPD -> "vmulpd"
  | Opcode.VMULPS -> "vmulps"
  | Opcode.VMULSD -> "vmulsd"
  | Opcode.VMULSS -> "vmulss"
  | Opcode.VMWRITE -> "vmwrite"
  | Opcode.VMXOFF -> "vmxoff"
  | Opcode.VMXON -> "vmxon"
  | Opcode.VORPD -> "vorpd"
  | Opcode.VORPS -> "vorps"
  | Opcode.VP2INTERSECTD -> "vp2intersectd"
  | Opcode.VP2INTERSECTQ -> "vp2intersectq"
  | Opcode.VP4DPWSSD -> "vp4dpwssd"
  | Opcode.VP4DPWSSDS -> "vp4dpwssds"
  | Opcode.VPABSB -> "vpabsb"
  | Opcode.VPABSD -> "vpabsd"
  | Opcode.VPABSQ -> "vpabsq"
  | Opcode.VPABSW -> "vpabsw"
  | Opcode.VPACKSSDW -> "vpackssdw"
  | Opcode.VPACKSSWB -> "vpacksswb"
  | Opcode.VPACKUSDW -> "vpackusdw"
  | Opcode.VPACKUSWB -> "vpackuswb"
  | Opcode.VPADDB -> "vpaddb"
  | Opcode.VPADDD -> "vpaddd"
  | Opcode.VPADDQ -> "vpaddq"
  | Opcode.VPADDSB -> "vpaddsb"
  | Opcode.VPADDSW -> "vpaddsw"
  | Opcode.VPADDUSB -> "vpaddusb"
  | Opcode.VPADDUSW -> "vpaddusw"
  | Opcode.VPADDW -> "vpaddw"
  | Opcode.VPALIGNR -> "vpalignr"
  | Opcode.VPAND -> "vpand"
  | Opcode.VPANDD -> "vpandd"
  | Opcode.VPANDN -> "vpandn"
  | Opcode.VPANDQ -> "vpandnq"
  | Opcode.VPAVGB -> "vpavgb"
  | Opcode.VPAVGW -> "vpavgw"
  | Opcode.VPBLENDD -> "vpblendd"
  | Opcode.VPBLENDMB -> "vpblendmb"
  | Opcode.VPBLENDMD -> "vpblendmd"
  | Opcode.VPBLENDMQ -> "vpblendmq"
  | Opcode.VPBLENDMW -> "vpblendmw"
  | Opcode.VPBLENDVB -> "vpblendvb"
  | Opcode.VPBLENDW -> "vpblendw"
  | Opcode.VPBROADCASTB -> "vpbroadcastb"
  | Opcode.VPBROADCASTD -> "vpbroadcastd"
  | Opcode.VPBROADCASTM -> "vpbroadcastm"
  | Opcode.VPBROADCASTMB2Q -> "vpbroadcastmb2q"
  | Opcode.VPBROADCASTMW2D -> "vpbroadcastmw2d"
  | Opcode.VPBROADCASTQ -> "vpbroadcastq"
  | Opcode.VPBROADCASTW -> "vpbroadcastw"
  | Opcode.VPCLMULQDQ -> "vpclmulqdq"
  | Opcode.VPCMPB -> "vpcmpb"
  | Opcode.VPCMPD -> "vpcmpd"
  | Opcode.VPCMPEQB -> "vpcmpeqb"
  | Opcode.VPCMPEQD -> "vpcmpeqd"
  | Opcode.VPCMPEQQ -> "vpcmpeqq"
  | Opcode.VPCMPEQW -> "vpcmpeqw"
  | Opcode.VPCMPESTRI -> "vpcmpestri"
  | Opcode.VPCMPESTRM -> "vpcmpestrm"
  | Opcode.VPCMPGTB -> "vpcmpgtb"
  | Opcode.VPCMPGTD -> "vpcmpgtd"
  | Opcode.VPCMPGTQ -> "vpcmpgtq"
  | Opcode.VPCMPGTW -> "vpcmpgtw"
  | Opcode.VPCMPISTRI -> "vpcmpistri"
  | Opcode.VPCMPISTRM -> "vpcmpistrm"
  | Opcode.VPCMPQ -> "vpcmpq"
  | Opcode.VPCMPUB -> "vpcmpub"
  | Opcode.VPCMPUD -> "vpcmpud"
  | Opcode.VPCMPUQ -> "vpcmpuq"
  | Opcode.VPCMPUW -> "vpcmpuw"
  | Opcode.VPCMPW -> "vpcmpw"
  | Opcode.VPCMUB -> "vpcmub"
  | Opcode.VPCMUD -> "vpcmud"
  | Opcode.VPCMUQ -> "vpcmuq"
  | Opcode.VPCMUW -> "vpcmuw"
  | Opcode.VPCOMPRESSB -> "vpcompressb"
  | Opcode.VPCOMPRESSD -> "vpcompressd"
  | Opcode.VPCOMPRESSQ -> "vpcompressq"
  | Opcode.VPCOMPRESSW -> "vpcompressw"
  | Opcode.VPCONFLICTD -> "vpconflictd"
  | Opcode.VPCONFLICTQ -> "vpconflictq"
  | Opcode.VPDPBUSD -> "vpdpbusd"
  | Opcode.VPDPBUSDS -> "vpdpbusds"
  | Opcode.VPDPWSSD -> "vpdpwssd"
  | Opcode.VPDPWSSDS -> "vpdpwssds"
  | Opcode.VPERM2F128 -> "vperm2f128"
  | Opcode.VPERM2I128 -> "vperm2i128"
  | Opcode.VPERMB -> "vpermb"
  | Opcode.VPERMD -> "vpermd"
  | Opcode.VPERMI2B -> "vpermi2b"
  | Opcode.VPERMI2D -> "vpermi2d"
  | Opcode.VPERMI2PD -> "vpermi2pd"
  | Opcode.VPERMI2PS -> "vpermi2ps"
  | Opcode.VPERMI2Q -> "vpermi2q"
  | Opcode.VPERMI2W -> "vpermi2w"
  | Opcode.VPERMILPD -> "vpermilpd"
  | Opcode.VPERMILPS -> "vpermilps"
  | Opcode.VPERMPD -> "vpermpd"
  | Opcode.VPERMPS -> "vpermps"
  | Opcode.VPERMQ -> "vpermq"
  | Opcode.VPERMT2B -> "vpermt2b"
  | Opcode.VPERMT2D -> "vpermt2d"
  | Opcode.VPERMT2PD -> "vpermt2pd"
  | Opcode.VPERMT2PS -> "vpermt2ps"
  | Opcode.VPERMT2Q -> "vpermt2q"
  | Opcode.VPERMT2W -> "vpermt2w"
  | Opcode.VPERMW -> "vpermw"
  | Opcode.VPEXPANDB -> "vpexpandb"
  | Opcode.VPEXPANDD -> "vpexpandd"
  | Opcode.VPEXPANDQ -> "vpexpandq"
  | Opcode.VPEXPANDW -> "vpexpandw"
  | Opcode.VPEXTRB -> "vpextrb"
  | Opcode.VPEXTRD -> "vpextrd"
  | Opcode.VPEXTRQ -> "vpextrq"
  | Opcode.VPEXTRW -> "vpextrw"
  | Opcode.VPGATHERDD -> "vpgatherdd"
  | Opcode.VPGATHERDQ -> "vpgatherdq"
  | Opcode.VPGATHERQD -> "vpgatherqd"
  | Opcode.VPGATHERQQ -> "vpgatherqq"
  | Opcode.VPHADDD -> "vphaddd"
  | Opcode.VPHADDSW -> "vphaddsw"
  | Opcode.VPHADDW -> "vphaddw"
  | Opcode.VPHMINPOSUW -> "vphminposuw"
  | Opcode.VPHSUBD -> "vphsubd"
  | Opcode.VPHSUBSW -> "vphsubsw"
  | Opcode.VPHSUBW -> "vphsubw"
  | Opcode.VPINSRB -> "vpinsrb"
  | Opcode.VPINSRD -> "vpinsrd"
  | Opcode.VPINSRQ -> "vpinsrq"
  | Opcode.VPINSRW -> "vpinsrw"
  | Opcode.VPLZCNTD -> "vplzcntd"
  | Opcode.VPLZCNTQ -> "vplzcntq"
  | Opcode.VPMADD52HUQ -> "vpmadd52huq"
  | Opcode.VPMADD52LUQ -> "vpmadd52luq"
  | Opcode.VPMADDUBSW -> "vpmaddubsw"
  | Opcode.VPMADDWD -> "vpmaddwd"
  | Opcode.VPMASKMOVD -> "vpmaskmovd"
  | Opcode.VPMASKMOVQ -> "vpmaskmovq"
  | Opcode.VPMAXSB -> "vpmaxsb"
  | Opcode.VPMAXSD -> "vpmaxsd"
  | Opcode.VPMAXSQ -> "vpmaxsq"
  | Opcode.VPMAXSW -> "vpmaxsw"
  | Opcode.VPMAXUB -> "vpmaxub"
  | Opcode.VPMAXUD -> "vpmaxud"
  | Opcode.VPMAXUQ -> "vpmaxuq"
  | Opcode.VPMAXUW -> "vpmaxuw"
  | Opcode.VPMINSB -> "vpminsb"
  | Opcode.VPMINSD -> "vpminsd"
  | Opcode.VPMINSQ -> "vpminsq"
  | Opcode.VPMINSW -> "vpminsw"
  | Opcode.VPMINUB -> "vpminub"
  | Opcode.VPMINUD -> "vpminud"
  | Opcode.VPMINUQ -> "vpminuq"
  | Opcode.VPMINUW -> "vpminuw"
  | Opcode.VPMOVB2D -> "vpmovb2d"
  | Opcode.VPMOVB2M -> "vpmovb2m"
  | Opcode.VPMOVD2M -> "vpmovd2m"
  | Opcode.VPMOVDB -> "vpmovdb"
  | Opcode.VPMOVDW -> "vpmovdw"
  | Opcode.VPMOVM2B -> "vpmovm2b"
  | Opcode.VPMOVM2D -> "vpmovm2d"
  | Opcode.VPMOVM2Q -> "vpmovm2q"
  | Opcode.VPMOVM2W -> "vpmovm2w"
  | Opcode.VPMOVMSKB -> "vpmovmskb"
  | Opcode.VPMOVQ2M -> "vpmovq2m"
  | Opcode.VPMOVQB -> "vpmovqb"
  | Opcode.VPMOVQD -> "vpmovqd"
  | Opcode.VPMOVQW -> "vpmovqw"
  | Opcode.VPMOVSDB -> "vpmovsdb"
  | Opcode.VPMOVSDW -> "vpmovsdw"
  | Opcode.VPMOVSQB -> "vpmovsqb"
  | Opcode.VPMOVSQD -> "vpmovsqd"
  | Opcode.VPMOVSQW -> "vpmovsqw"
  | Opcode.VPMOVSWB -> "vpmovswb"
  | Opcode.VPMOVSXBD -> "vpmovsxbd"
  | Opcode.VPMOVSXBQ -> "vpmovsxbq"
  | Opcode.VPMOVSXBW -> "vpmovsxbw"
  | Opcode.VPMOVSXDQ -> "vpmovsxdq"
  | Opcode.VPMOVSXWD -> "vpmovsxwd"
  | Opcode.VPMOVSXWQ -> "vpmovsxwq"
  | Opcode.VPMOVUSDB -> "vpmovusdb"
  | Opcode.VPMOVUSDW -> "vpmovusdw"
  | Opcode.VPMOVUSQB -> "vpmovusqb"
  | Opcode.VPMOVUSQD -> "vpmovusqd"
  | Opcode.VPMOVUSQW -> "vpmovusqw"
  | Opcode.VPMOVUSWB -> "vpmovuswb"
  | Opcode.VPMOVW2M -> "vpmovw2m"
  | Opcode.VPMOVWB -> "vpmovwb"
  | Opcode.VPMOVZXBD -> "vpmovzxbd"
  | Opcode.VPMOVZXBQ -> "vpmovzxbq"
  | Opcode.VPMOVZXBW -> "vpmovzxbw"
  | Opcode.VPMOVZXDQ -> "vpmovzxdq"
  | Opcode.VPMOVZXWD -> "vpmovzxwd"
  | Opcode.VPMOVZXWQ -> "vpmovzxwq"
  | Opcode.VPMULHRSW -> "vpmulhrsw"
  | Opcode.VPMULHUW -> "vpmulhuw"
  | Opcode.VPMULHW -> "vpmulhw"
  | Opcode.VPMULLD -> "vpmulld"
  | Opcode.VPMULLQ -> "vpmullq"
  | Opcode.VPMULLW -> "vpmullw"
  | Opcode.VPMULTISHIFTQB -> "vpmultishiftqb"
  | Opcode.VPMULUDQ -> "vpmuludq"
  | Opcode.VPOPCNTB -> "vpopcntb"
  | Opcode.VPOPCNTD -> "vpopcntd"
  | Opcode.VPOPCNTQ -> "vpopcntq"
  | Opcode.VPOPCNTW -> "vpopcntw"
  | Opcode.VPOR -> "vpor"
  | Opcode.VPORD -> "vpord"
  | Opcode.VPORQ -> "vporq"
  | Opcode.VPROLD -> "vprold"
  | Opcode.VPROLQ -> "vprolq"
  | Opcode.VPROLVD -> "vprolvd"
  | Opcode.VPROLVQ -> "vprolvq"
  | Opcode.VPRORD -> "vprord"
  | Opcode.VPRORQ -> "vprorq"
  | Opcode.VPRORRD -> "vprorrd"
  | Opcode.VPRORRQ -> "vprorrq"
  | Opcode.VPRORVD -> "vprorvd"
  | Opcode.VPRORVQ -> "vprorvq"
  | Opcode.VPSADBW -> "vpsadbw"
  | Opcode.VPSCATTERDD -> "vpscatterdd"
  | Opcode.VPSCATTERDQ -> "vpscatterdq"
  | Opcode.VPSCATTERQD -> "vpscatterqd"
  | Opcode.VPSCATTERQQ -> "vpscatterqq"
  | Opcode.VPSHLDD -> "vpshldd"
  | Opcode.VPSHLDQ -> "vpshldq"
  | Opcode.VPSHLDVD -> "vpshldvd"
  | Opcode.VPSHLDVQ -> "vpshldvq"
  | Opcode.VPSHLDVW -> "vpshldvw"
  | Opcode.VPSHLDW -> "vpshldw"
  | Opcode.VPSHRDD -> "vpshrdd"
  | Opcode.VPSHRDQ -> "vpshrdq"
  | Opcode.VPSHRDVD -> "vpshrdvd"
  | Opcode.VPSHRDVQ -> "vpshrdvq"
  | Opcode.VPSHRDVW -> "vpshrdvw"
  | Opcode.VPSHRDW -> "vpshrdw"
  | Opcode.VPSHUFB -> "vpshufb"
  | Opcode.VPSHUFBITQMB -> "vpshufbitqmb"
  | Opcode.VPSHUFD -> "vpshufd"
  | Opcode.VPSHUFHW -> "vpshufhw"
  | Opcode.VPSHUFLW -> "vpshuflw"
  | Opcode.VPSIGNB -> "vpsignb"
  | Opcode.VPSIGND -> "vpsignd"
  | Opcode.VPSIGNW -> "vpsignw"
  | Opcode.VPSLLD -> "vpslld"
  | Opcode.VPSLLDQ -> "vpslldq"
  | Opcode.VPSLLQ -> "vpsllq"
  | Opcode.VPSLLVD -> "vpsllvd"
  | Opcode.VPSLLVQ -> "vpsllvq"
  | Opcode.VPSLLVW -> "vpsllvw"
  | Opcode.VPSLLW -> "vpsllw"
  | Opcode.VPSRAD -> "vpsrad"
  | Opcode.VPSRAQ -> "vpsraq"
  | Opcode.VPSRAVD -> "vpsravd"
  | Opcode.VPSRAVQ -> "vpsravq"
  | Opcode.VPSRAVW -> "vpsravw"
  | Opcode.VPSRAW -> "vpsraw"
  | Opcode.VPSRLD -> "vpsrld"
  | Opcode.VPSRLDQ -> "vpsrldq"
  | Opcode.VPSRLQ -> "vpsrlq"
  | Opcode.VPSRLVD -> "vpsrlvd"
  | Opcode.VPSRLVQ -> "vpsrlvq"
  | Opcode.VPSRLVW -> "vpsrlvw"
  | Opcode.VPSRLW -> "vpsrlw"
  | Opcode.VPSUBB -> "vpsubb"
  | Opcode.VPSUBD -> "vpsubd"
  | Opcode.VPSUBQ -> "vpsubq"
  | Opcode.VPSUBSB -> "vpsubsb"
  | Opcode.VPSUBSW -> "vpsubsw"
  | Opcode.VPSUBUSB -> "vpsubusb"
  | Opcode.VPSUBUSW -> "vpsubusw"
  | Opcode.VPSUBW -> "vpsubw"
  | Opcode.VPTERLOGD -> "vpterlogd"
  | Opcode.VPTERLOGQ -> "vpterlogq"
  | Opcode.VPTERNLOGD -> "vpternlogd"
  | Opcode.VPTERNLOGQ -> "vpternlogq"
  | Opcode.VPTEST -> "vptest"
  | Opcode.VPTESTMB -> "vptestmb"
  | Opcode.VPTESTMD -> "vptestmd"
  | Opcode.VPTESTMQ -> "vptestmq"
  | Opcode.VPTESTMW -> "vptestmw"
  | Opcode.VPTESTNMB -> "vptestnmb"
  | Opcode.VPTESTNMD -> "vptestnmd"
  | Opcode.VPTESTNMQ -> "vptestnmq"
  | Opcode.VPTESTNMW -> "vptestnmw"
  | Opcode.VPUNPCKHBW -> "vpunpckhbw"
  | Opcode.VPUNPCKHDQ -> "vpunpckhdq"
  | Opcode.VPUNPCKHQDQ -> "vpunpckhqdq"
  | Opcode.VPUNPCKHWD -> "vpunpckhwd"
  | Opcode.VPUNPCKLBW -> "vpunpcklbw"
  | Opcode.VPUNPCKLDQ -> "vpunpckldq"
  | Opcode.VPUNPCKLQDQ -> "vpunpcklqdq"
  | Opcode.VPUNPCKLWD -> "vpunpcklwd"
  | Opcode.VPXOR -> "vpxor"
  | Opcode.VPXORD -> "vpxord"
  | Opcode.VPXORQ -> "vpxorq"
  | Opcode.VRANGEPD -> "vrangepd"
  | Opcode.VRANGEPS -> "vrangeps"
  | Opcode.VRANGESD -> "vrangesd"
  | Opcode.VRANGESS -> "vrangess"
  | Opcode.VRCP14PD -> "vrcp14pd"
  | Opcode.VRCP14PS -> "vrcp14ps"
  | Opcode.VRCP14SD -> "vrcp14sd"
  | Opcode.VRCP14SS -> "vrcp14ss"
  | Opcode.VRCP28PD -> "vrcp28pd"
  | Opcode.VRCP28PS -> "vrcp28ps"
  | Opcode.VRCP28SD -> "vrcp28sd"
  | Opcode.VRCP28SS -> "vrcp28ss"
  | Opcode.VRCPPS -> "vrcpps"
  | Opcode.VRCPSS -> "vrcpss"
  | Opcode.VREDUCEPD -> "vreducepd"
  | Opcode.VREDUCEPS -> "vreduceps"
  | Opcode.VREDUCESD -> "vreducesd"
  | Opcode.VREDUCESS -> "vreducess"
  | Opcode.VRNDSCALEPD -> "vrndscalepd"
  | Opcode.VRNDSCALEPS -> "vrndscaleps"
  | Opcode.VRNDSCALESD -> "vrndscalesd"
  | Opcode.VRNDSCALESS -> "vrndscaless"
  | Opcode.VROUNDPD -> "vroundpd"
  | Opcode.VROUNDPS -> "vroundps"
  | Opcode.VROUNDSD -> "vroundsd"
  | Opcode.VROUNDSS -> "vroundss"
  | Opcode.VRSQRT14PD -> "vrsqrt14pd"
  | Opcode.VRSQRT14PS -> "vrsqrt14ps"
  | Opcode.VRSQRT14SD -> "vrsqrt14sd"
  | Opcode.VRSQRT14SS -> "vrsqrt14ss"
  | Opcode.VRSQRT28PD -> "vrsqrt28pd"
  | Opcode.VRSQRT28PS -> "vrsqrt28ps"
  | Opcode.VRSQRT28SD -> "vrsqrt28sd"
  | Opcode.VRSQRT28SS -> "vrsqrt28ss"
  | Opcode.VRSQRTPS -> "vrsqrtps"
  | Opcode.VRSQRTSS -> "vrsqrtss"
  | Opcode.VSCALEFPD -> "vscalefpd"
  | Opcode.VSCALEFPS -> "vscalefps"
  | Opcode.VSCALEFSD -> "vscalefsd"
  | Opcode.VSCALEFSS -> "vscalefss"
  | Opcode.VSCALEPD -> "vscalepd"
  | Opcode.VSCALEPS -> "vscaleps"
  | Opcode.VSCALESD -> "vscalesd"
  | Opcode.VSCALESS -> "vscaless"
  | Opcode.VSCATTERDD -> "vscatterdd"
  | Opcode.VSCATTERDPD -> "vscatterdpd"
  | Opcode.VSCATTERDPS -> "vscatterdps"
  | Opcode.VSCATTERDQ -> "vscatterdq"
  | Opcode.VSCATTERPF0DPD -> "vscatterpf0dpd"
  | Opcode.VSCATTERPF0DPS -> "vscatterpf0dps"
  | Opcode.VSCATTERPF0QPD -> "vscatterpf0qpd"
  | Opcode.VSCATTERPF0QPS -> "vscatterpf0qps"
  | Opcode.VSCATTERPF1DPD -> "vscatterpf1dpd"
  | Opcode.VSCATTERPF1DPS -> "vscatterpf1dps"
  | Opcode.VSCATTERPF1QPD -> "vscatterpf1qpd"
  | Opcode.VSCATTERPF1QPS -> "vscatterpf1qps"
  | Opcode.VSCATTERQD -> "vscatterqd"
  | Opcode.VSCATTERQPD -> "vscatterqpd"
  | Opcode.VSCATTERQPS -> "vscatterqps"
  | Opcode.VSCATTERQQ -> "vscatterqq"
  | Opcode.VSHUFF32X4 -> "vshuff32x4"
  | Opcode.VSHUFF64X2 -> "vshuff64x2"
  | Opcode.VSHUFI32X4 -> "vshufi32x4"
  | Opcode.VSHUFI64X2 -> "vshufi64x2"
  | Opcode.VSHUFPD -> "vshufpd"
  | Opcode.VSHUFPS -> "vshufps"
  | Opcode.VSQRTPD -> "vsqrtpd"
  | Opcode.VSQRTPS -> "vsqrtps"
  | Opcode.VSQRTSD -> "vsqrtsd"
  | Opcode.VSQRTSS -> "vsqrtss"
  | Opcode.VSUBPD -> "vsubpd"
  | Opcode.VSUBPS -> "vsubps"
  | Opcode.VSUBSD -> "vsubsd"
  | Opcode.VSUBSS -> "vsubss"
  | Opcode.VTESTPD -> "vtestpd"
  | Opcode.VTESTPS -> "vtestps"
  | Opcode.VUCOMISD -> "vucomisd"
  | Opcode.VUCOMISS -> "vucomiss"
  | Opcode.VUNPCKHPD -> "vunpckhpd"
  | Opcode.VUNPCKHPS -> "vunpckhps"
  | Opcode.VUNPCKLPD -> "vunpcklpd"
  | Opcode.VUNPCKLPS -> "vunpcklps"
  | Opcode.VXORPD -> "vxorpd"
  | Opcode.VXORPS -> "vxorps"
  | Opcode.VZEROUPPER -> "vzeroupper"
  | Opcode.WAIT -> "wait"
  | Opcode.WBINVD -> "wbinvd"
  | Opcode.WRFSBASE -> "wrfsbase"
  | Opcode.WRGSBASE -> "wrgsbase"
  | Opcode.WRMSR -> "wrmsr"
  | Opcode.WRPKRU -> "wrpkru"
  | Opcode.WRSSD -> "wrssd"
  | Opcode.WRSSQ -> "wrssq"
  | Opcode.WRUSSD -> "wrussd"
  | Opcode.WRUSSQ -> "wrussq"
  | Opcode.XABORT -> "xabort"
  | Opcode.XACQUIRE -> "xacquire"
  | Opcode.XADD -> "xadd"
  | Opcode.XBEGIN -> "xbegin"
  | Opcode.XCHG -> "xchg"
  | Opcode.XEND -> "xend"
  | Opcode.XGETBV -> "xgetbv"
  | Opcode.XLAT -> "xlat"
  | Opcode.XLATB -> "xlatb"
  | Opcode.XOR -> "xor"
  | Opcode.XORPD -> "xorpd"
  | Opcode.XORPS -> "xorps"
  | Opcode.XRELEASE -> "xrelease"
  | Opcode.XRSTOR -> "xrstor"
  | Opcode.XRSTORS -> "xrstors"
  | Opcode.XRSTORS64 -> "xrstors64"
  | Opcode.XSAVE -> "xsave"
  | Opcode.XSAVEC -> "xsavec"
  | Opcode.XSAVEC64 -> "xsavec64"
  | Opcode.XSAVEOPT -> "xsaveopt"
  | Opcode.XSAVES -> "xsaves"
  | Opcode.XSAVES64 -> "xsaves64"
  | Opcode.XSETBV -> "xsetbv"
  | Opcode.XTEST -> "xtest"
  | _ -> raise InvalidOpcodeException

let inline private iToHexStr (i: int64) (builder: DisasmBuilder) =
  builder.Accumulate AsmWordKind.Value (HexString.ofInt64 i)

let inline private uToHexStr (i: uint64) (builder: DisasmBuilder) =
  builder.Accumulate AsmWordKind.Value (HexString.ofUInt64 i)

let inline private getMask sz =
  match sz with
  | 8<rt> -> 0xFFL
  | 16<rt> -> 0xFFFFL
  | 32<rt> -> 0xFFFFFFFFL
  | _ -> 0xFFFFFFFFFFFFFFFFL

let inline private buildPref (prefs: Prefix) (builder: DisasmBuilder) =
  if prefs = Prefix.PrxNone then ()
  elif (prefs &&& Prefix.PrxLOCK) <> Prefix.PrxNone then
    builder.Accumulate AsmWordKind.String "lock "
  elif (prefs &&& Prefix.PrxREPNZ) <> Prefix.PrxNone then
    builder.Accumulate AsmWordKind.String "repnz "
  elif (prefs &&& Prefix.PrxREPZ) <> Prefix.PrxNone then
    builder.Accumulate AsmWordKind.String "repz "
  elif (prefs &&& Prefix.PrxBND) <> Prefix.PrxNone then
    builder.Accumulate AsmWordKind.String "bnd "
  else ()

let inline private buildOpcode opcode (builder: DisasmBuilder) =
  builder.Accumulate AsmWordKind.Mnemonic (opCodeToString opcode)

let private buildDisplacement showSign (disp: Disp) (builder: DisasmBuilder) =
  let mask = WordSize.toRegType builder.WordSize |> RegType.getMask |> uint64
  if showSign && disp < 0L then
    builder.Accumulate AsmWordKind.String "-"
    iToHexStr (- disp) builder
  elif showSign then
    builder.Accumulate AsmWordKind.String "+"
    iToHexStr disp builder
  else
    uToHexStr (uint64 disp &&& mask) builder

let inline private buildAbsAddr selector (offset: Addr) builder =
  uToHexStr (uint64 selector) builder
  builder.Accumulate AsmWordKind.String ":"
  uToHexStr offset builder

let private buildComment (reader: INameReadable) targetAddr builder =
  if (builder: DisasmBuilder).ResolveSymbol then
    match reader.TryFindFunctionName targetAddr with
    | Error _ ->
      (builder: DisasmBuilder).Accumulate AsmWordKind.String " ; "
      uToHexStr targetAddr builder
    | Ok "" -> ()
    | Ok name ->
      builder.Accumulate AsmWordKind.String " ; <"
      builder.Accumulate AsmWordKind.Value name
      builder.Accumulate AsmWordKind.String ">"
  else ()

let inline private buildRelAddr offset reader (builder: DisasmBuilder) =
  if offset < 0L then builder.Accumulate AsmWordKind.String "-"
  else builder.Accumulate AsmWordKind.String "+"
  iToHexStr (abs offset) builder
  buildComment reader (builder.Address + uint64 offset) builder

/// Zeroing/Merging (EVEX.z)
let inline buildEVEXZ ev (builder: DisasmBuilder) =
  if ev.Z = Zeroing then builder.Accumulate AsmWordKind.String "{z}"
  else ()

module private IntelSyntax = begin

  let inline private memDispToStr showSign disp builder =
    match disp with
    | None -> ()
    | Some d -> buildDisplacement showSign d builder

  let inline scaleToString (scale: Scale) (builder: DisasmBuilder) =
    if scale = Scale.X1 then ()
    else
      builder.Accumulate AsmWordKind.String "*"
      builder.Accumulate AsmWordKind.Value ((int scale).ToString())

  let private memScaleDispToStr emptyBase si d builder =
    match si with
    | None -> memDispToStr (not emptyBase) d builder
    | Some (i, scale) ->
      if emptyBase then () else builder.Accumulate AsmWordKind.String "+"
      builder.Accumulate AsmWordKind.Variable (Register.toString i)
      scaleToString scale builder
      memDispToStr true d builder

  let private memAddrToStr b si disp builder =
    match b with
    | None -> memScaleDispToStr true si disp builder
    | Some b ->
      builder.Accumulate AsmWordKind.Variable (Register.toString b)
      memScaleDispToStr false si disp builder

  let inline private isFar (ins: InsInfo) =
    match ins.Opcode with
    | Opcode.JMPFar | Opcode.CALLFar -> true
    | _ -> false

  let private ptrDirectiveString isFar = function
    | 8<rt> -> "byte ptr"
    | 16<rt> -> "word ptr"
    | 32<rt> -> if isFar then "word far ptr" else "dword ptr"
    | 48<rt> -> "fword ptr"
    | 64<rt> -> "qword ptr"
    | 80<rt> -> if isFar then "fword ptr" else "tbyte ptr"
    | 128<rt> -> "xmmword ptr"
    | 256<rt> -> "ymmword ptr"
    | 512<rt> -> "zmmword ptr"
    | 224<rt> | 864<rt> -> "" (* x87 FPU state *)
    | _ -> Terminator.impossible ()

  let mToString (ins: InsInfo) (builder: DisasmBuilder) b si d oprSz =
    let ptrDirective = ptrDirectiveString (isFar ins) oprSz
    match Helper.getSegment ins.Prefixes with
    | None ->
      builder.Accumulate AsmWordKind.String ptrDirective
      builder.Accumulate AsmWordKind.String (" [")
      memAddrToStr b si d builder
      builder.Accumulate AsmWordKind.String "]"
    | Some seg ->
      builder.Accumulate AsmWordKind.String ptrDirective
      builder.Accumulate AsmWordKind.String (" [")
      builder.Accumulate AsmWordKind.Variable (Register.toString seg)
      builder.Accumulate AsmWordKind.String ":"
      memAddrToStr b si d builder
      builder.Accumulate AsmWordKind.String "]"

  /// Opmask register
  let buildOpMask ePrx (builder: DisasmBuilder) =
    if ePrx.AAA = 0uy then ()
    else
      builder.Accumulate AsmWordKind.String "{"
      builder.Accumulate AsmWordKind.Variable
        (ePrx.AAA |> int |> Register.opmask |> Register.toString)
      builder.Accumulate AsmWordKind.String "}"

  let buildMask (ins: InsInfo) builder =
    match ins.VEXInfo with
    | Some { EVEXPrx = Some ePrx } ->
      buildOpMask ePrx builder
      buildEVEXZ ePrx builder
    | _ -> ()

  let buildBroadcast (ins: InsInfo) (builder: DisasmBuilder) memSz =
    match ins.VEXInfo with
    | Some { EVEXPrx = Some ePrx; VectorLength = vl } ->
      if ePrx.B = 1uy then
        builder.Accumulate AsmWordKind.String "{1to"
        builder.Accumulate AsmWordKind.Value ((vl / memSz).ToString())
        builder.Accumulate AsmWordKind.String "}"
      else ()
    | _ -> ()

  let buildRoundingControl (ins: InsInfo) (builder: DisasmBuilder) =
    match ins.VEXInfo with
    | Some { EVEXPrx = Some ePrx }->
      if ePrx.B = 1uy then
        builder.Accumulate AsmWordKind.String ", {"
        builder.Accumulate AsmWordKind.String (ePrx.RC.ToString().ToLower())
        builder.Accumulate AsmWordKind.String "-sae}"
      else ()
    | _ -> ()

  let oprToString ins reader opr (builder: DisasmBuilder) =
    match opr with
    | OprReg reg ->
      builder.Accumulate AsmWordKind.Variable (Register.toString reg)
    | OprMem (b, si, disp, oprSz) ->
      mToString ins builder b si disp oprSz
    | OprImm (imm, _) ->
      iToHexStr (imm &&& getMask ins.MainOperationSize) builder
    | OprDirAddr (Absolute (sel, offset, _)) -> buildAbsAddr sel offset builder
    | OprDirAddr (Relative (offset)) -> buildRelAddr offset reader builder
    | Label _ -> Terminator.impossible ()

  let buildOprs (ins: InsInfo) reader (builder: DisasmBuilder) =
    match ins.Operands with
    | NoOperand -> ()
    | OneOperand (OprMem (Some Register.RIP, None, Some off, 64<rt>)) ->
      builder.Accumulate AsmWordKind.String (" ")
      mToString ins builder (Some Register.RIP) None (Some off) 64<rt>
      buildComment reader
        (builder.Address + uint64 builder.InsLength + uint64 off) builder
    | OneOperand opr ->
      builder.Accumulate AsmWordKind.String " "
      oprToString ins reader opr builder
    | TwoOperands (OprMem (Some R.RIP, None, Some disp, sz), opr) ->
      builder.Accumulate AsmWordKind.String " "
      mToString ins builder (Some Register.RIP) None (Some disp) sz
      builder.Accumulate AsmWordKind.String ", "
      oprToString ins reader opr builder
      buildComment reader
        (builder.Address + uint64 builder.InsLength + uint64 disp) builder
    | TwoOperands (opr, OprMem (Some R.RIP, None, Some disp, sz)) ->
      builder.Accumulate AsmWordKind.String " "
      oprToString ins reader opr builder
      builder.Accumulate AsmWordKind.String ", "
      mToString ins builder (Some Register.RIP) None (Some disp) sz
      buildComment reader
        (builder.Address + uint64 builder.InsLength + uint64 disp) builder
    | TwoOperands (opr1, (OprMem (_, _, _, memSz) as opr2)) ->
      builder.Accumulate AsmWordKind.String " "
      oprToString ins reader opr1 builder
      buildMask ins builder
      builder.Accumulate AsmWordKind.String ", "
      oprToString ins reader opr2 builder
      buildBroadcast ins builder memSz
    | TwoOperands (opr1, opr2) ->
      builder.Accumulate AsmWordKind.String " "
      oprToString ins reader opr1 builder
      buildMask ins builder
      builder.Accumulate AsmWordKind.String ", "
      oprToString ins reader opr2 builder
    | ThreeOperands (opr1, opr2, (OprMem (_, _, _, memSz) as opr3)) ->
      builder.Accumulate AsmWordKind.String " "
      oprToString ins reader opr1 builder
      buildMask ins builder
      builder.Accumulate AsmWordKind.String ", "
      oprToString ins reader opr2 builder
      builder.Accumulate AsmWordKind.String ", "
      oprToString ins reader opr3 builder
      buildBroadcast ins builder memSz
    | ThreeOperands (opr1, opr2, (OprReg _ as opr3)) ->
      builder.Accumulate AsmWordKind.String " "
      oprToString ins reader opr1 builder
      buildMask ins builder
      builder.Accumulate AsmWordKind.String ", "
      oprToString ins reader opr2 builder
      builder.Accumulate AsmWordKind.String ", "
      oprToString ins reader opr3 builder
      buildRoundingControl ins builder
    | ThreeOperands (opr1, opr2, opr3) ->
      builder.Accumulate AsmWordKind.String " "
      oprToString ins reader opr1 builder
      buildMask ins builder
      builder.Accumulate AsmWordKind.String ", "
      oprToString ins reader opr2 builder
      builder.Accumulate AsmWordKind.String ", "
      oprToString ins reader opr3 builder
    | FourOperands (opr1, opr2, (OprMem (_, _, _, memSz) as opr3), opr4) ->
      builder.Accumulate AsmWordKind.String " "
      oprToString ins reader opr1 builder
      buildMask ins builder
      builder.Accumulate AsmWordKind.String ", "
      oprToString ins reader opr2 builder
      builder.Accumulate AsmWordKind.String ", "
      oprToString ins reader opr3 builder
      buildBroadcast ins builder memSz
      builder.Accumulate AsmWordKind.String ", "
      oprToString ins reader opr4 builder
    | FourOperands (opr1, opr2, opr3, opr4) ->
      builder.Accumulate AsmWordKind.String " "
      oprToString ins reader opr1 builder
      buildMask ins builder
      builder.Accumulate AsmWordKind.String ", "
      oprToString ins reader opr2 builder
      builder.Accumulate AsmWordKind.String ", "
      oprToString ins reader opr3 builder
      builder.Accumulate AsmWordKind.String ", "
      oprToString ins reader opr4 builder

  let disasm reader (builder: DisasmBuilder) ins =
    if builder.ShowAddr then builder.AccumulateAddr () else ()
    buildPref (ins: InsInfo).Prefixes builder
    buildOpcode ins.Opcode builder
    buildOprs ins reader builder

end

module private ATTSyntax = begin

  let buildDisp disp showSign builder =
    match disp with
    | Some d -> buildDisplacement showSign d builder
    | None -> ()

  let buildScaledIndex si (builder: DisasmBuilder) =
    match si with
    | None -> ()
    | Some (i, Scale.X1) ->
      builder.Accumulate AsmWordKind.String ", %"
      builder.Accumulate AsmWordKind.Variable (Register.toString i)
    | Some (i, scale) ->
      builder.Accumulate AsmWordKind.String ", %"
      builder.Accumulate AsmWordKind.Variable (Register.toString i)
      builder.Accumulate AsmWordKind.String ", "
      builder.Accumulate AsmWordKind.Value ((int scale).ToString())

  let buildSeg seg (builder: DisasmBuilder) =
    builder.Accumulate AsmWordKind.String "%"
    builder.Accumulate AsmWordKind.Variable (Register.toString seg)
    builder.Accumulate AsmWordKind.String ":"

  let buildBasedMemory b si d builder =
    buildDisp d true builder
    builder.Accumulate AsmWordKind.String "(%"
    builder.Accumulate AsmWordKind.Variable (Register.toString b)
    buildScaledIndex si builder
    builder.Accumulate AsmWordKind.String ")"

  let buildNobaseMemory (i, s) d builder =
    buildDisp d true builder
    match s with
    | Scale.X1 ->
      builder.Accumulate AsmWordKind.String "(%"
      builder.Accumulate AsmWordKind.Variable (Register.toString i)
    | _ ->
      builder.Accumulate AsmWordKind.String "(, %"
      builder.Accumulate AsmWordKind.Variable (Register.toString i)
      builder.Accumulate AsmWordKind.String ", "
      builder.Accumulate AsmWordKind.Value ((int s).ToString())
    builder.Accumulate AsmWordKind.String ")"

  let buildMemOp (ins: InsInfo) (builder: DisasmBuilder) b si d oprSz isFst =
    if ins.IsBranch () then
      builder.Accumulate AsmWordKind.String " *"
    elif isFst then
      builder.Accumulate AsmWordKind.String " "
    else
      builder.Accumulate AsmWordKind.String ", "
    match Helper.getSegment ins.Prefixes, b, si with
    | None, Some b, _ ->
      buildBasedMemory b si d builder
    | None, None, None ->
      buildDisp d false builder
    | None, None, Some si ->
      buildNobaseMemory si d builder
    | Some seg, Some b, _ ->
      buildSeg seg builder
      buildBasedMemory b si d builder
    | Some seg, None, _ ->
      buildSeg seg builder
      buildDisp d false builder

  let buildMask (ins: InsInfo) (builder: DisasmBuilder) =
    match ins.VEXInfo with
    | Some { EVEXPrx = Some ePrx }->
      if ePrx.AAA = 0uy then ()
      else
        builder.Accumulate AsmWordKind.String "{%"
        builder.Accumulate AsmWordKind.Variable
          (ePrx.AAA |> int |> Register.opmask |> Register.toString)
        builder.Accumulate AsmWordKind.String "}"
      buildEVEXZ ePrx builder
    | _ -> ()

  let buildOpr (ins: InsInfo) reader isFst (builder: DisasmBuilder) opr =
    match opr with
    | OprReg reg ->
      if isFst then
        if ins.IsBranch () then builder.Accumulate AsmWordKind.String " *%"
        else builder.Accumulate AsmWordKind.String " %"
      else builder.Accumulate AsmWordKind.String ", %"
      builder.Accumulate AsmWordKind.Variable (Register.toString reg)
    | OprMem (b, si, disp, oprSz) ->
      buildMemOp ins builder b si disp oprSz isFst
    | OprImm (imm, _) ->
      if isFst then builder.Accumulate AsmWordKind.String " $"
      else builder.Accumulate AsmWordKind.String ", $"
      iToHexStr (imm &&& getMask ins.MainOperationSize) builder
    | OprDirAddr (Absolute (sel, offset, _)) ->
      builder.Accumulate AsmWordKind.String " "
      buildAbsAddr sel offset builder
    | OprDirAddr (Relative (offset)) ->
      builder.Accumulate AsmWordKind.String " "
      buildRelAddr offset reader builder
    | Label _ -> Terminator.impossible ()

  let addOpSuffix (builder: DisasmBuilder) = function
    | 8<rt> -> builder.Accumulate AsmWordKind.Mnemonic "b"
    | 16<rt> -> builder.Accumulate AsmWordKind.Mnemonic "w"
    | 32<rt> -> builder.Accumulate AsmWordKind.Mnemonic "l"
    | 64<rt> -> builder.Accumulate AsmWordKind.Mnemonic "q"
    | 80<rt> -> builder.Accumulate AsmWordKind.Mnemonic "t"
    | _ -> ()

  let buildOpSuffix operands builder =
    match operands with
    | OneOperand (OprMem (_, _, _, sz)) -> addOpSuffix builder sz
    | TwoOperands (OprMem (_, _, _, sz), _)
    | TwoOperands (_, OprMem (_, _, _, sz)) -> addOpSuffix builder sz
    | ThreeOperands (OprMem (_, _, _, sz), _, _)
    | ThreeOperands (_, OprMem (_, _, _, sz), _)
    | ThreeOperands (_, _, OprMem (_, _, _, sz)) -> addOpSuffix builder sz
    | FourOperands (OprMem (_, _, _, sz), _, _, _)
    | FourOperands (_, OprMem (_, _, _, sz), _, _)
    | FourOperands (_, _, OprMem (_, _, _, sz), _)
    | FourOperands (_, _, _, OprMem (_, _, _, sz)) -> addOpSuffix builder sz
    | _ -> ()

  let buildSrcSizeSuffix operands builder =
    match operands with
    | TwoOperands (_, OprMem (_, _, _, sz)) -> addOpSuffix builder sz
    | TwoOperands (_, OprReg dst) ->
      Register.toRegType builder.WordSize dst |> addOpSuffix builder
    | _ -> Terminator.impossible ()

  let buildDstSizeSuffix operands (builder: DisasmBuilder) =
    match operands with
    | TwoOperands (OprReg dst, _) ->
      Register.toRegType builder.WordSize dst |> addOpSuffix builder
    | _ -> Terminator.impossible ()

  let buildOprs (ins: InsInfo) reader (builder: DisasmBuilder) =
    match ins.Operands with
    | NoOperand -> ()
    | OneOperand opr ->
      buildOpr ins reader true builder opr
    | TwoOperands (opr1, opr2) ->
      buildOpr ins reader true builder opr2
      buildOpr ins reader false builder opr1
      buildMask ins builder
    | ThreeOperands (opr1, opr2, opr3) ->
      buildOpr ins reader true builder opr3
      buildOpr ins reader false builder opr2
      buildOpr ins reader false builder opr1
      buildMask ins builder
    | FourOperands (opr1, opr2, opr3, opr4) ->
      buildOpr ins reader true builder opr4
      buildOpr ins reader false builder opr3
      buildOpr ins reader false builder opr2
      buildOpr ins reader false builder opr1
      buildMask ins builder

  let disasm reader (builder: DisasmBuilder) ins =
    if builder.ShowAddr then builder.AccumulateAddr () else ()
    buildPref (ins: InsInfo).Prefixes builder
    match ins.Opcode with
    | Opcode.MOVSX ->
      builder.Accumulate AsmWordKind.Mnemonic "movs"
      buildSrcSizeSuffix ins.Operands builder
      buildDstSizeSuffix ins.Operands builder
    | Opcode.MOVZX ->
      builder.Accumulate AsmWordKind.Mnemonic "movz"
      buildSrcSizeSuffix ins.Operands builder
      buildDstSizeSuffix ins.Operands builder
    | Opcode.MOVSXD ->
      builder.Accumulate AsmWordKind.Mnemonic "movslq"
    (* Below are the list of opcodes that should not be used with a suffix. *)
    | Opcode.ADDSD
    | Opcode.ADDSS
    | Opcode.CMPSD
    | Opcode.CMPSS
    | Opcode.COMISD
    | Opcode.COMISS
    | Opcode.CVTDQ2PD
    | Opcode.CVTPI2PS
    | Opcode.CVTPS2PD
    | Opcode.CVTPS2PI
    | Opcode.CVTSD2SS
    | Opcode.CVTSS2SD
    | Opcode.CVTTPS2PI
    | Opcode.CVTTSD2SI
    | Opcode.CVTTSS2SI
    | Opcode.DIVSD
    | Opcode.DIVSS
    | Opcode.FBLD
    | Opcode.FBSTP
    | Opcode.FCOMP
    | Opcode.FCOM
    | Opcode.FDIV
    | Opcode.FDIVR
    | Opcode.FIADD
    | Opcode.FICOMP
    | Opcode.FICOM
    | Opcode.FIDIVR
    | Opcode.FIDIV
    | Opcode.FILD
    | Opcode.FIMUL
    | Opcode.FISTP
    | Opcode.FISTTP
    | Opcode.FISUBR
    | Opcode.FISUB
    | Opcode.FMUL
    | Opcode.FST
    | Opcode.FSUB
    | Opcode.FSUBR
    | Opcode.IRET
    | Opcode.LAR
    | Opcode.LDMXCSR
    | Opcode.MAXSD
    | Opcode.MAXSS
    | Opcode.MINSD
    | Opcode.MINSS
    | Opcode.MOVD
    | Opcode.MOVHPD
    | Opcode.MOVHPS
    | Opcode.MOVLPD
    | Opcode.MOVLPS
    | Opcode.MOVQ
    | Opcode.MOVSD
    | Opcode.MOVSS
    | Opcode.MULSD
    | Opcode.MULSS
    | Opcode.PACKUSWB
    | Opcode.PADDSW
    | Opcode.PCMPEQB
    | Opcode.PCMPGTD
    | Opcode.PINSRW
    | Opcode.PMAXSW
    | Opcode.POR
    | Opcode.PREFETCHNTA
    | Opcode.PREFETCHT0
    | Opcode.PSADBW
    | Opcode.PSLLD
    | Opcode.PSUBSB
    | Opcode.PXOR
    | Opcode.SGDT
    | Opcode.SIDT
    | Opcode.SQRTSD
    | Opcode.SQRTSS
    | Opcode.STMXCSR
    | Opcode.SUBSD
    | Opcode.SUBSS
    | Opcode.UCOMISD
    | Opcode.UCOMISS
    | Opcode.VFMSUB213SD
    | Opcode.VFMSUB213PD
    | Opcode.VFNMSUB231SD
    | Opcode.VFNMSUB231PD
    | Opcode.VMOVDDUP
    | Opcode.VMOVD
    | Opcode.VMOVQ
    | Opcode.VPBROADCASTB
    | Opcode.VPBROADCASTQ ->
      buildOpcode ins.Opcode builder
    (* Far jmp/call *)
    | Opcode.JMPFar ->
      builder.Accumulate AsmWordKind.Mnemonic "ljmp"
      buildOpSuffix ins.Operands builder
    | Opcode.CALLFar ->
      builder.Accumulate AsmWordKind.Mnemonic "lcall"
      buildOpSuffix ins.Operands builder
    | opcode ->
      buildOpcode opcode builder
      buildOpSuffix ins.Operands builder
    buildOprs ins reader builder

end

let mutable disasm = Disasm IntelSyntax.disasm

let setDisassemblyFlavor = function
  | DefaultSyntax -> disasm <- Disasm IntelSyntax.disasm
  | ATTSyntax -> disasm <- Disasm ATTSyntax.disasm
