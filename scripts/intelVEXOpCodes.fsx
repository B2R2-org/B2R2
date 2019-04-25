#!/usr/bin/env fsharpi
#load "../src/Core/TypeExtensions.fs"
#load "../src/Core/RegType.fs"
#load "../src/Core/RegisterID.fs"
#load "../src/Core/WordSize.fs"
#load "../src/Core/AddrRange.fs"
#load "../src/FrontEnd/Intel/IntelRegister.fs"
#load "../src/FrontEnd/Intel/IntelTypes.fs"
(*
  B2R2 - the Next-Generation Reversing Platform

  Author: DongYeop Oh <oh51dy@kaist.ac.kr>
          Seung Il Jung <sijung@kaist.ac.kr>

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
open B2R2.FrontEnd.Intel

let opVEX =
  [
   ("opNor0F1A", [| Opcode.InvalOP; Opcode.BNDMOV;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F1B", [| Opcode.InvalOP; Opcode.BNDMOV;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F10", [| Opcode.MOVUPS; Opcode.MOVUPD;
                    Opcode.MOVSS; Opcode.MOVSD |])
   ("opVex0F10Mem", [| Opcode.VMOVUPS; Opcode.VMOVUPD;
                       Opcode.VMOVSS; Opcode.VMOVSD |])
   ("opVex0F10Reg", [| Opcode.VMOVUPS; Opcode.VMOVUPD;
                       Opcode.VMOVSS; Opcode.VMOVSD |])
   ("opNor0F11", [| Opcode.MOVUPS; Opcode.MOVUPD;
                    Opcode.MOVSS; Opcode.MOVSD |])
   ("opVex0F11Mem", [| Opcode.VMOVUPS; Opcode.VMOVUPD;
                       Opcode.VMOVSS; Opcode.VMOVSD |])
   ("opVex0F11Reg", [| Opcode.VMOVUPS; Opcode.VMOVUPD;
                       Opcode.VMOVSS; Opcode.VMOVSD |])
   ("opNor0F12Mem", [| Opcode.MOVLPS; Opcode.MOVLPD;
                       Opcode.MOVSLDUP; Opcode.MOVDDUP |])
   ("opNor0F12Reg", [| Opcode.MOVHLPS; Opcode.MOVLPD;
                       Opcode.MOVSLDUP; Opcode.MOVDDUP |])
   ("opVex0F12Mem", [| Opcode.VMOVLPS; Opcode.VMOVLPD;
                       Opcode.VMOVSLDUP; Opcode.VMOVDDUP |])
   ("opVex0F12Reg", [| Opcode.VMOVHLPS; Opcode.VMOVLPD;
                       Opcode.VMOVSLDUP; Opcode.VMOVDDUP |])
   ("opNor0F13", [| Opcode.MOVLPS; Opcode.MOVLPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F13", [| Opcode.VMOVLPS; Opcode.VMOVLPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F14", [| Opcode.UNPCKLPS; Opcode.UNPCKLPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F14", [| Opcode.VUNPCKLPS; Opcode.VUNPCKLPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F15", [| Opcode.UNPCKHPS; Opcode.UNPCKHPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F15", [| Opcode.VUNPCKHPS; Opcode.VUNPCKHPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F16Mem", [| Opcode.MOVHPS; Opcode.MOVHPD;
                       Opcode.MOVSHDUP; Opcode.InvalOP |])
   ("opNor0F16Reg", [| Opcode.MOVLHPS; Opcode.MOVHPD;
                       Opcode.MOVSHDUP; Opcode.InvalOP |])
   ("opVex0F16Mem", [| Opcode.VMOVHPS; Opcode.VMOVHPD;
                       Opcode.VMOVSHDUP; Opcode.InvalOP |])
   ("opVex0F16Reg", [| Opcode.VMOVLHPS; Opcode.VMOVHPD;
                       Opcode.VMOVSHDUP; Opcode.InvalOP |])
   ("opNor0F17", [| Opcode.MOVHPS; Opcode.MOVHPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F17", [| Opcode.VMOVHPS; Opcode.VMOVHPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F28", [| Opcode.MOVAPS; Opcode.MOVAPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F28", [| Opcode.VMOVAPS; Opcode.VMOVAPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F29", [| Opcode.MOVAPS; Opcode.MOVAPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F29", [| Opcode.VMOVAPS; Opcode.VMOVAPS;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F2A", [| Opcode.CVTPI2PS; Opcode.CVTPI2PD;
                    Opcode.CVTSI2SS; Opcode.CVTSI2SD |])
   ("opVex0F2A", [| Opcode.InvalOP; Opcode.InvalOP;
                    Opcode.VCVTSI2SS; Opcode.VCVTSI2SD |])
   ("opNor0F2B", [| Opcode.MOVNTPS; Opcode.MOVNTPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F2B", [| Opcode.VMOVNTPS; Opcode.VMOVNTPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F2C", [| Opcode.CVTTPS2PI; Opcode.CVTTPD2PI;
                    Opcode.CVTTSS2SI; Opcode.CVTTSD2SI |])
   ("opVex0F2C", [| Opcode.InvalOP; Opcode.InvalOP;
                    Opcode.VCVTTSS2SI; Opcode.VCVTTSD2SI |])
   ("opNor0F2D", [| Opcode.CVTPS2PI; Opcode.CVTPD2PI;
                    Opcode.CVTSS2SI; Opcode.CVTSD2SI |])
   ("opVex0F2D", [| Opcode.InvalOP; Opcode.InvalOP;
                    Opcode.VCVTSS2SI; Opcode.VCVTSD2SI |])
   ("opNor0F2E", [| Opcode.UCOMISS; Opcode.UCOMISD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F2E", [| Opcode.VUCOMISS; Opcode.VUCOMISD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F2F", [| Opcode.COMISS; Opcode.COMISD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F2F", [| Opcode.VCOMISS; Opcode.VCOMISD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F50", [| Opcode.MOVMSKPS; Opcode.MOVMSKPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F50", [| Opcode.VMOVMSKPS; Opcode.VMOVMSKPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F54", [| Opcode.ANDPS; Opcode.ANDPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F54", [| Opcode.VANDPS; Opcode.VANDPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F55", [| Opcode.ANDNPS; Opcode.ANDNPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F55", [| Opcode.VANDNPS; Opcode.VANDNPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F56", [| Opcode.ORPS; Opcode.ORPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F56", [| Opcode.VORPS; Opcode.VORPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F57", [| Opcode.XORPS; Opcode.XORPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F57", [| Opcode.VXORPS; Opcode.VXORPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F58", [| Opcode.ADDPS; Opcode.ADDPD;
                    Opcode.ADDSS; Opcode.ADDSD |])
   ("opVex0F58", [| Opcode.VADDPS; Opcode.VADDPD;
                    Opcode.VADDSS; Opcode.VADDSD |])
   ("opNor0F59", [| Opcode.MULPS; Opcode.MULPD;
                    Opcode.MULSS; Opcode.MULSD |])
   ("opVex0F59", [| Opcode.VMULPS; Opcode.VMULPD;
                    Opcode.VMULSS; Opcode.VMULSD |])
   ("opNor0F5A", [| Opcode.CVTPS2PD; Opcode.CVTPD2PS;
                    Opcode.CVTSS2SD; Opcode.CVTSD2SS |])
   ("opVex0F5A", [| Opcode.InvalOP; Opcode.InvalOP;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F5B", [| Opcode.CVTDQ2PS; Opcode.CVTPS2DQ;
                    Opcode.CVTTPS2DQ; Opcode.InvalOP |])
   ("opVex0F5B", [| Opcode.InvalOP; Opcode.InvalOP;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F5C", [| Opcode.SUBPS; Opcode.SUBPD;
                    Opcode.SUBSS; Opcode.SUBSD |])
   ("opVex0F5C", [| Opcode.VSUBPS; Opcode.VSUBPD;
                    Opcode.VSUBSS; Opcode.VSUBSD |])
   ("opNor0F5D", [| Opcode.MINPS; Opcode.MINPD;
                    Opcode.MINSS; Opcode.MINSD |])
   ("opVex0F5D", [| Opcode.InvalOP; Opcode.InvalOP;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F5E", [| Opcode.DIVPS; Opcode.DIVPD;
                    Opcode.DIVSS; Opcode.DIVSD |])
   ("opVex0F5E", [| Opcode.VDIVPS; Opcode.VDIVPD;
                    Opcode.VDIVSS; Opcode.VDIVSD |])
   ("opNor0F5F", [| Opcode.MAXPS; Opcode.MAXPD;
                    Opcode.MAXSS; Opcode.MAXSD |])
   ("opVex0F5F", [| Opcode.InvalOP; Opcode.InvalOP;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F60", [| Opcode.PUNPCKLBW; Opcode.PUNPCKLBW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F60", [| Opcode.InvalOP; Opcode.VPUNPCKLBW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F61", [| Opcode.PUNPCKLWD; Opcode.PUNPCKLWD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F61", [| Opcode.InvalOP; Opcode.VPUNPCKLWD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F62", [| Opcode.PUNPCKLDQ; Opcode.PUNPCKLDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F62", [| Opcode.InvalOP; Opcode.VPUNPCKLDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F63", [| Opcode.PACKSSWB; Opcode.PACKSSWB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F63", [| Opcode.InvalOP; Opcode.VPACKSSWB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F64", [| Opcode.PCMPGTB; Opcode.PCMPGTB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F64", [| Opcode.InvalOP; Opcode.VPCMPGTB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F65", [| Opcode.PCMPGTW; Opcode.PCMPGTW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F65", [| Opcode.InvalOP; Opcode.VPCMPGTW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F66", [| Opcode.PCMPGTD; Opcode.PCMPGTD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F66", [| Opcode.InvalOP; Opcode.VPCMPGTD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F67", [| Opcode.PACKUSWB; Opcode.PACKUSWB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F67", [| Opcode.InvalOP; Opcode.VPACKUSWB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F68", [| Opcode.PUNPCKHBW; Opcode.PUNPCKHBW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F68", [| Opcode.InvalOP; Opcode.VPUNPCKHBW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F69", [| Opcode.PUNPCKHWD; Opcode.PUNPCKHWD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F69", [| Opcode.InvalOP; Opcode.VPUNPCKHWD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F6A", [| Opcode.PUNPCKHDQ; Opcode.PUNPCKHDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F6A", [| Opcode.InvalOP; Opcode.VPUNPCKHDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F6B", [| Opcode.PACKSSDW; Opcode.PACKSSDW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F6B", [| Opcode.InvalOP; Opcode.VPACKSSDW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F6C", [| Opcode.InvalOP; Opcode.PUNPCKLQDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F6C", [| Opcode.InvalOP; Opcode.VPUNPCKLQDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F6D", [| Opcode.InvalOP; Opcode.PUNPCKHQDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F6D", [| Opcode.InvalOP; Opcode.VPUNPCKHQDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F6EB64", [| Opcode.MOVQ; Opcode.MOVQ;
                       Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F6EB32", [| Opcode.MOVD; Opcode.MOVD;
                       Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F6EB64", [| Opcode.InvalOP; Opcode.VMOVQ;
                       Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F6EB32", [| Opcode.InvalOP; Opcode.VMOVD;
                       Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F6F", [| Opcode.MOVQ; Opcode.MOVDQA;
                    Opcode.MOVDQU; Opcode.InvalOP |])
   ("opVex0F6F", [| Opcode.InvalOP; Opcode.VMOVDQA;
                    Opcode.VMOVDQU; Opcode.InvalOP |])
   ("opEVex0F6FB64", [| Opcode.InvalOP; Opcode.VMOVDQA64;
                        Opcode.VMOVDQU64; Opcode.InvalOP |])
   ("opEVex0F6FB32", [| Opcode.InvalOP; Opcode.VMOVDQA32;
                        Opcode.VMOVDQU32; Opcode.InvalOP |])
   ("opNor0F70", [| Opcode.PSHUFW; Opcode.PSHUFD;
                    Opcode.PSHUFHW; Opcode.PSHUFLW |])
   ("opVex0F70", [| Opcode.InvalOP; Opcode.VPSHUFD;
                    Opcode.VPSHUFHW; Opcode.VPSHUFLW |])
   ("opNor0F74", [| Opcode.PCMPEQB; Opcode.PCMPEQB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F74", [| Opcode.InvalOP; Opcode.VPCMPEQB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F75", [| Opcode.PCMPEQW; Opcode.PCMPEQW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F75", [| Opcode.InvalOP; Opcode.VPCMPEQW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F76", [| Opcode.PCMPEQD; Opcode.PCMPEQD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F76", [| Opcode.InvalOP; Opcode.VPCMPEQD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F77", [| Opcode.InvalOP; Opcode.InvalOP;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F77", [| Opcode.VZEROUPPER; Opcode.InvalOP;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F7EB64", [| Opcode.MOVQ; Opcode.MOVQ;
                       Opcode.MOVQ; Opcode.InvalOP |])
   ("opNor0F7EB32", [| Opcode.MOVD; Opcode.MOVD;
                       Opcode.MOVQ; Opcode.InvalOP |])
   ("opVex0F7EB64", [| Opcode.InvalOP; Opcode.VMOVQ;
                       Opcode.VMOVQ; Opcode.InvalOP |])
   ("opVex0F7EB32", [| Opcode.InvalOP; Opcode.VMOVD;
                       Opcode.VMOVQ; Opcode.InvalOP |])
   ("opNor0F7F", [| Opcode.MOVQ; Opcode.MOVDQA;
                    Opcode.MOVDQU; Opcode.InvalOP |])
   ("opVex0F7F", [| Opcode.InvalOP; Opcode.VMOVDQA;
                    Opcode.VMOVDQU; Opcode.InvalOP |])
   ("opEVex0F7FB64", [| Opcode.InvalOP; Opcode.VMOVDQA64;
                        Opcode.InvalOP; Opcode.InvalOP |])
   ("opEVex0F7FB32", [| Opcode.InvalOP; Opcode.VMOVDQA32;
                        Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FC4", [| Opcode.PINSRW; Opcode.PINSRW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FC4", [| Opcode.InvalOP; Opcode.VPINSRW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FC5", [| Opcode.PEXTRW; Opcode.PEXTRW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FC5", [| Opcode.InvalOP; Opcode.VPEXTRW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FC6", [| Opcode.SHUFPS; Opcode.SHUFPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FC6", [| Opcode.VSHUFPS; Opcode.VSHUFPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FD1", [| Opcode.PSRLW; Opcode.PSRLW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FD1", [| Opcode.InvalOP; Opcode.VPSRLW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FD2", [| Opcode.PSRLD; Opcode.PSRLD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FD2", [| Opcode.InvalOP; Opcode.VPSRLD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FD3", [| Opcode.PSRLQ; Opcode.PSRLQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FD3", [| Opcode.InvalOP; Opcode.VPSRLQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FD4", [| Opcode.PADDQ; Opcode.PADDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FD4", [| Opcode.InvalOP; Opcode.VPADDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FD5", [| Opcode.PMULLW; Opcode.PMULLW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FD5", [| Opcode.InvalOP; Opcode.VPMULLW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FD6", [| Opcode.InvalOP; Opcode.MOVQ;
                    Opcode.MOVQ2DQ; Opcode.MOVDQ2Q |])
   ("opVex0FD6", [| Opcode.InvalOP; Opcode.VMOVQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FD7", [| Opcode.PMOVMSKB; Opcode.PMOVMSKB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FD7", [| Opcode.InvalOP; Opcode.VPMOVMSKB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FD8", [| Opcode.PSUBUSB; Opcode.PSUBUSB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FD8", [| Opcode.InvalOP; Opcode.VPSUBUSB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FD9", [| Opcode.PSUBUSW; Opcode.PSUBUSW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FD9", [| Opcode.InvalOP; Opcode.VPSUBUSW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FDA", [| Opcode.PMINUB; Opcode.PMINUB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FDA", [| Opcode.InvalOP; Opcode.VPMINUB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FDB", [| Opcode.PAND; Opcode.PAND;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FDB", [| Opcode.InvalOP; Opcode.VPAND;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FDC", [| Opcode.PADDUSB; Opcode.PADDUSB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FDC", [| Opcode.InvalOP; Opcode.VPADDUSB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FDD", [| Opcode.PADDUSW; Opcode.PADDUSW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FDD", [| Opcode.InvalOP; Opcode.VPADDUSW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FDE", [| Opcode.PMAXUB; Opcode.PMAXUB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FDE", [| Opcode.InvalOP; Opcode.VPMAXUB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FDF", [| Opcode.PANDN; Opcode.PANDN;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FDF", [| Opcode.InvalOP; Opcode.VPANDN;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FE0", [| Opcode.PAVGB; Opcode.PAVGB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FE0", [| Opcode.InvalOP; Opcode.VPAVGB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FE1", [| Opcode.PSRAW; Opcode.PSRAW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FE1", [| Opcode.InvalOP; Opcode.VPSRAW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FE2", [| Opcode.PSRAD; Opcode.PSRAD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FE2", [| Opcode.InvalOP; Opcode.VPSRAD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FE3", [| Opcode.PAVGW; Opcode.PAVGW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FE3", [| Opcode.InvalOP; Opcode.VPAVGW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FE4", [| Opcode.PMULHUW; Opcode.PMULHUW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FE4", [| Opcode.InvalOP; Opcode.VPMULHUW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FE5", [| Opcode.PMULHW; Opcode.PMULHW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FE5", [| Opcode.InvalOP; Opcode.VPMULHW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FE6", [| Opcode.InvalOP; Opcode.CVTTPD2DQ;
                    Opcode.CVTDQ2PD; Opcode.CVTPD2DQ |])
   ("opVex0FE6", [| Opcode.InvalOP; Opcode.InvalOP;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FE7", [| Opcode.MOVNTQ; Opcode.MOVNTDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FE7", [| Opcode.InvalOP; Opcode.VMOVNTDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opEVex0FE7B64", [| Opcode.InvalOP; Opcode.InvalOP;
                        Opcode.InvalOP; Opcode.InvalOP |])
   ("opEVex0FE7B32", [| Opcode.InvalOP; Opcode.VMOVNTDQ;
                        Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FE8", [| Opcode.PSUBSB; Opcode.PSUBSB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FE8", [| Opcode.InvalOP; Opcode.VPSUBSB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FE9", [| Opcode.PSUBSW; Opcode.PSUBSW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FE9", [| Opcode.InvalOP; Opcode.VPSUBSW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FEA", [| Opcode.PMINSW; Opcode.PMINSW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FEA", [| Opcode.InvalOP; Opcode.VPMINSW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FEB", [| Opcode.POR; Opcode.POR; Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FEB", [| Opcode.InvalOP; Opcode.VPOR;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FEC", [| Opcode.PADDSB; Opcode.PADDSB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FEC", [| Opcode.InvalOP; Opcode.VPADDSB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FED", [| Opcode.PADDSW; Opcode.PADDSW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FED", [| Opcode.InvalOP; Opcode.VPADDSW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FEE", [| Opcode.PMAXSW; Opcode.PMAXSW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FEE", [| Opcode.InvalOP; Opcode.VPMAXSW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FEF", [| Opcode.PXOR; Opcode.PXOR;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FEF", [| Opcode.InvalOP; Opcode.VPXOR;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FF0", [| Opcode.InvalOP; Opcode.InvalOP;
                    Opcode.InvalOP; Opcode.LDDQU |])
   ("opVex0FF0", [| Opcode.InvalOP; Opcode.InvalOP;
                    Opcode.InvalOP; Opcode.VLDDQU |])
   ("opNor0FF1", [| Opcode.PSLLW; Opcode.PSLLW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FF1", [| Opcode.InvalOP; Opcode.VPSLLW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FF2", [| Opcode.PSLLD; Opcode.PSLLD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FF2", [| Opcode.InvalOP; Opcode.VPSLLD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FF3", [| Opcode.PSLLQ; Opcode.PSLLQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FF3", [| Opcode.InvalOP; Opcode.VPSLLQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FF4", [| Opcode.PMULUDQ; Opcode.PMULUDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FF4", [| Opcode.InvalOP; Opcode.VPMULUDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FF5", [| Opcode.PMADDWD; Opcode.PMADDWD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FF5", [| Opcode.InvalOP; Opcode.VPMADDWD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FF6", [| Opcode.PSADBW; Opcode.PSADBW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FF6", [| Opcode.InvalOP; Opcode.VPSADBW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FF8", [| Opcode.PSUBB; Opcode.PSUBB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FF8", [| Opcode.InvalOP; Opcode.VPSUBB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FF9", [| Opcode.PSUBW; Opcode.PSUBW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FF9", [| Opcode.InvalOP; Opcode.VPSUBW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FFA", [| Opcode.PSUBD; Opcode.PSUBD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FFA", [| Opcode.InvalOP; Opcode.VPSUBD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FFB", [| Opcode.PSUBQ; Opcode.PSUBQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FFB", [| Opcode.InvalOP; Opcode.VPSUBQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FFC", [| Opcode.PADDB; Opcode.PADDB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FFC", [| Opcode.InvalOP; Opcode.VPADDB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FFD", [| Opcode.PADDW; Opcode.PADDW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FFD", [| Opcode.InvalOP; Opcode.VPADDW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FFE", [| Opcode.PADDD; Opcode.PADDD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FFE", [| Opcode.InvalOP; Opcode.VPADDD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3800", [| Opcode.PSHUFB; Opcode.PSHUFB;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3800", [| Opcode.InvalOP; Opcode.VPSHUFB;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3801", [| Opcode.PHADDW; Opcode.PHADDW;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3801", [| Opcode.InvalOP; Opcode.InvalOP;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3802", [| Opcode.PHADDD; Opcode.PHADDD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3802", [| Opcode.InvalOP; Opcode.InvalOP;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3803", [| Opcode.PHADDSW; Opcode.PHADDSW;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3803", [| Opcode.InvalOP; Opcode.VPHADDSW;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3805", [| Opcode.PHSUBW; Opcode.PHSUBW;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3805", [| Opcode.InvalOP; Opcode.VPHSUBW;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3806", [| Opcode.PHSUBD; Opcode.PHSUBD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3806", [| Opcode.InvalOP; Opcode.VPHSUBD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3807", [| Opcode.PHSUBSW; Opcode.PHSUBSW;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3807", [| Opcode.InvalOP; Opcode.VPHSUBSW;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3808", [| Opcode.PSIGNB; Opcode.PSIGNB;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3808", [| Opcode.InvalOP; Opcode.VPSIGNB;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3809", [| Opcode.PSIGNW; Opcode.PSIGNW;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3809", [| Opcode.InvalOP; Opcode.VPSIGNW;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F380A", [| Opcode.PSIGND; Opcode.PSIGND;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F380A", [| Opcode.InvalOP; Opcode.VPSIGND;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F380B", [| Opcode.PMULHRSW; Opcode.PMULHRSW;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F380B", [| Opcode.InvalOP; Opcode.VPMULHRSW;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3817", [| Opcode.InvalOP; Opcode.PTEST;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3817", [| Opcode.InvalOP; Opcode.VPTEST;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3818", [| Opcode.InvalOP; Opcode.InvalOP;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3818", [| Opcode.InvalOP; Opcode.VBROADCASTSS;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opEVex0F3818", [| Opcode.InvalOP; Opcode.VBROADCASTSS;
                       Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F381C", [| Opcode.PABSB; Opcode.PABSB;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F381C", [| Opcode.InvalOP; Opcode.VPABSB;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F381D", [| Opcode.PABSW; Opcode.PABSW;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F381D", [| Opcode.InvalOP; Opcode.VPABSW;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F381E", [| Opcode.PABSD; Opcode.PABSD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F381E", [| Opcode.InvalOP; Opcode.VPABSD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3820", [| Opcode.InvalOP; Opcode.PMOVSXBW;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3820", [| Opcode.InvalOP; Opcode.VPMOVSXBW;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3821", [| Opcode.InvalOP; Opcode.PMOVSXBD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3821", [| Opcode.InvalOP; Opcode.VPMOVSXBD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3822", [| Opcode.InvalOP; Opcode.PMOVSXBQ;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3822", [| Opcode.InvalOP; Opcode.VPMOVSXBQ;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3823", [| Opcode.InvalOP; Opcode.PMOVSXWD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3823", [| Opcode.InvalOP; Opcode.VPMOVSXWD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3824", [| Opcode.InvalOP; Opcode.PMOVSXWQ;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3824", [| Opcode.InvalOP; Opcode.VPMOVSXWQ;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3825", [| Opcode.InvalOP; Opcode.PMOVSXDQ;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3825", [| Opcode.InvalOP; Opcode.VPMOVSXDQ;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3828", [| Opcode.InvalOP; Opcode.PMULDQ;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3828", [| Opcode.InvalOP; Opcode.VPMULDQ;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3829", [| Opcode.InvalOP; Opcode.PCMPEQQ;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3829", [| Opcode.InvalOP; Opcode.VPCMPEQQ;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F382B", [| Opcode.InvalOP; Opcode.PACKUSDW;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F382B", [| Opcode.InvalOP; Opcode.VPACKUSDW;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3830", [| Opcode.InvalOP; Opcode.PMOVZXBW;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3830", [| Opcode.InvalOP; Opcode.VPMOVZXBW;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3831", [| Opcode.InvalOP; Opcode.PMOVZXBD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3831", [| Opcode.InvalOP; Opcode.VPMOVZXBD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3832", [| Opcode.InvalOP; Opcode.PMOVZXBQ;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3832", [| Opcode.InvalOP; Opcode.VPMOVZXBQ;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3833", [| Opcode.InvalOP; Opcode.PMOVZXWD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3833", [| Opcode.InvalOP; Opcode.VPMOVZXWD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3834", [| Opcode.InvalOP; Opcode.PMOVZXWQ;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3834", [| Opcode.InvalOP; Opcode.VPMOVZXWQ;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3835", [| Opcode.InvalOP; Opcode.PMOVZXDQ;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3835", [| Opcode.InvalOP; Opcode.VPMOVZXDQ;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3837", [| Opcode.InvalOP; Opcode.PCMPGTQ;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3837", [| Opcode.InvalOP; Opcode.VPCMPGTQ;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3838", [| Opcode.InvalOP; Opcode.PMINSB;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3838", [| Opcode.InvalOP; Opcode.VPMINSB;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3839", [| Opcode.InvalOP; Opcode.PMINSD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3839", [| Opcode.InvalOP; Opcode.VPMINSD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F383A", [| Opcode.InvalOP; Opcode.PMINUW;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F383A", [| Opcode.InvalOP; Opcode.InvalOP;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F383B", [| Opcode.InvalOP; Opcode.PMINUD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F383B", [| Opcode.InvalOP; Opcode.VPMINUD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F383C", [| Opcode.InvalOP; Opcode.PMAXSB;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F383C", [| Opcode.InvalOP; Opcode.VPMAXSB;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F383D", [| Opcode.InvalOP; Opcode.PMAXSD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F383D", [| Opcode.InvalOP; Opcode.VPMAXSD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F383E", [| Opcode.InvalOP; Opcode.PMAXUW;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F383E", [| Opcode.InvalOP; Opcode.VPMAXUW;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F383F", [| Opcode.InvalOP; Opcode.PMAXUD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F383F", [| Opcode.InvalOP; Opcode.VPMAXUD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3840", [| Opcode.InvalOP; Opcode.PMULLD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3840", [| Opcode.InvalOP; Opcode.VPMULLD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3841", [| Opcode.InvalOP; Opcode.PHMINPOSUW;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3841", [| Opcode.InvalOP; Opcode.InvalOP;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F385A", [| Opcode.InvalOP; Opcode.InvalOP;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F385A", [| Opcode.InvalOP; Opcode.VBROADCASTI128;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3878", [| Opcode.InvalOP; Opcode.InvalOP;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3878", [| Opcode.InvalOP; Opcode.VPBROADCASTB;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F38F0", [| Opcode.MOVBE; Opcode.MOVBE;
                      Opcode.InvalOP; Opcode.CRC32; Opcode.CRC32 |])
   ("opNor0F38F1", [| Opcode.MOVBE; Opcode.MOVBE;
                      Opcode.InvalOP; Opcode.CRC32; Opcode.CRC32 |])
   ("opNor0F3A0F", [| Opcode.PALIGNR; Opcode.PALIGNR;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3A0F", [| Opcode.InvalOP; Opcode.VPALIGNR;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3A20", [| Opcode.InvalOP; Opcode.PINSRB;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3A20", [| Opcode.InvalOP; Opcode.InvalOP;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3A38", [| Opcode.InvalOP; Opcode.InvalOP;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3A38", [| Opcode.InvalOP; Opcode.VINSERTI128;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3A60", [| Opcode.InvalOP; Opcode.PCMPESTRM;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3A60", [| Opcode.InvalOP; Opcode.VPCMPESTRM;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3A61", [| Opcode.InvalOP; Opcode.PCMPESTRI;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3A61", [| Opcode.InvalOP; Opcode.VPCMPESTRI;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3A62", [| Opcode.InvalOP; Opcode.PCMPISTRM;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3A62", [| Opcode.InvalOP; Opcode.VPCMPISTRM;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3A63", [| Opcode.InvalOP; Opcode.PCMPISTRI;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3A63", [| Opcode.InvalOP; Opcode.VPCMPISTRI;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3A0B", [| Opcode.InvalOP; Opcode.ROUNDSD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3A0B", [| Opcode.InvalOP; Opcode.InvalOP;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opEmpty", [| Opcode.InvalOP; Opcode.InvalOP;
                  Opcode.InvalOP; Opcode.InvalOP |])
]


let toInt64 (opcode: Opcode) =
  LanguagePrimitives.EnumToValue opcode |> int64

let combineDescs descs =
  descs
  |> Array.mapi (fun idx desc -> desc <<< (48 - idx * 16))
  |> Array.fold (fun acc desc -> desc ||| acc) 0L

let main _args =
  opVEX
  |> List.iter (fun (var, desc) ->
       printfn "let [<Literal>] %s = 0x%xL"
               var (Array.map toInt64 desc |> combineDescs))

fsi.CommandLineArgs |> main
