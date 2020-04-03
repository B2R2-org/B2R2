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

namespace B2R2.FrontEnd.Intel

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST

type internal RegExprs (wordSize) =
  let var sz t name = AST.var sz t name (IntelRegisterSet.singleton t)

  let reg64 wordSize t name =
    if wordSize = WordSize.Bit32 then unDef 64<rt> name else var 64<rt> t name

  let reg32 wordSize t name r64 =
    if wordSize = WordSize.Bit32 then var 32<rt> t name
    else extractLow 32<rt> r64

  let reg32ext wordSize name r64 =
    if wordSize = WordSize.Bit32 then unDef 32<rt> name
    else extractLow 32<rt> r64

  let reg16 wordSize r32 r64 =
    extractLow 16<rt> (if wordSize = WordSize.Bit32 then r32 else r64)

  let reg16ext wordSize name r64 =
    if wordSize = WordSize.Bit32 then unDef 16<rt> name
    else extractLow 16<rt> r64

  let regL8 wordSize r32 r64 =
    extractLow 8<rt> (if wordSize = WordSize.Bit32 then r32 else r64)

  let regH8 wordSize r32 r64 =
    extract (if wordSize = WordSize.Bit32 then r32 else r64) 8<rt> 8

  let regL8ext wordSize name r64 =
    if wordSize = WordSize.Bit32 then unDef 16<rt> name else extractLow 8<rt> r64

  let assert64Bit wordSize =
    if wordSize = WordSize.Bit64 then () else raise InvalidRegAccessException

  let assert32Bit wordSize =
    if wordSize = WordSize.Bit32 then () else raise InvalidRegAccessException

  (* Registers *)
  let rax  = reg64 wordSize (Register.toRegID Register.RAX) "RAX"
  let rbx  = reg64 wordSize (Register.toRegID Register.RBX) "RBX"
  let rcx  = reg64 wordSize (Register.toRegID Register.RCX) "RCX"
  let rdx  = reg64 wordSize (Register.toRegID Register.RDX) "RDX"
  let rsi  = reg64 wordSize (Register.toRegID Register.RSI) "RSI"
  let rdi  = reg64 wordSize (Register.toRegID Register.RDI) "RDI"
  let rsp  = reg64 wordSize (Register.toRegID Register.RSP) "RSP"
  let rbp  = reg64 wordSize (Register.toRegID Register.RBP) "RBP"
  let r8   = reg64 wordSize (Register.toRegID Register.R8) "R8"
  let r9   = reg64 wordSize (Register.toRegID Register.R9) "R9"
  let r10  = reg64 wordSize (Register.toRegID Register.R10) "R10"
  let r11  = reg64 wordSize (Register.toRegID Register.R11) "R11"
  let r12  = reg64 wordSize (Register.toRegID Register.R12) "R12"
  let r13  = reg64 wordSize (Register.toRegID Register.R13) "R13"
  let r14  = reg64 wordSize (Register.toRegID Register.R14) "R14"
  let r15  = reg64 wordSize (Register.toRegID Register.R15) "R15"
  let eax  = reg32 wordSize (Register.toRegID Register.EAX) "EAX" rax
  let ebx  = reg32 wordSize (Register.toRegID Register.EBX) "EBX" rbx
  let ecx  = reg32 wordSize (Register.toRegID Register.ECX) "ECX" rcx
  let edx  = reg32 wordSize (Register.toRegID Register.EDX) "EDX" rdx
  let esi  = reg32 wordSize (Register.toRegID Register.ESI) "ESI" rsi
  let edi  = reg32 wordSize (Register.toRegID Register.EDI) "EDI" rdi
  let esp  = reg32 wordSize (Register.toRegID Register.ESP) "ESP" rsp
  let ebp  = reg32 wordSize (Register.toRegID Register.EBP) "EBP" rbp
  let ax   = reg16 wordSize eax rax
  let bx   = reg16 wordSize ebx rbx
  let cx   = reg16 wordSize ecx rcx
  let dx   = reg16 wordSize edx rdx
  let fcw = var 16<rt> (Register.toRegID Register.FCW) "FCW"
  let fsw = var 16<rt> (Register.toRegID Register.FSW) "FSW"
  let ftw = var 16<rt> (Register.toRegID Register.FTW) "FTW"
  let fop = var 16<rt> (Register.toRegID Register.FOP) "FOP"
  let fip = var 64<rt> (Register.toRegID Register.FIP) "FIP"
  let fcs = var 16<rt> (Register.toRegID Register.FCS) "FCS"
  let fdp = var 64<rt> (Register.toRegID Register.FDP) "FDP"
  let fds = var 16<rt> (Register.toRegID Register.FDS) "FDS"
  let st0 = var 80<rt> (Register.toRegID Register.ST0) "ST0"
  let st1 = var 80<rt> (Register.toRegID Register.ST1) "ST1"
  let st2 = var 80<rt> (Register.toRegID Register.ST2) "ST2"
  let st3 = var 80<rt> (Register.toRegID Register.ST3) "ST3"
  let st4 = var 80<rt> (Register.toRegID Register.ST4) "ST4"
  let st5 = var 80<rt> (Register.toRegID Register.ST5) "ST5"
  let st6 = var 80<rt> (Register.toRegID Register.ST6) "ST6"
  let st7 = var 80<rt> (Register.toRegID Register.ST7) "ST7"
  let mxcsr = var 32<rt> (Register.toRegID Register.MXCSR) "MXCSR"
  let mxcsrmask = var 32<rt> (Register.toRegID Register.MXCSRMASK) "MXCSR_MASK"
  let pkru = var 32<rt> (Register.toRegID Register.PKRU) "PKRU"
  let k0 = var 64<rt> (Register.toRegID Register.K0) "K0"
  let k1 = var 64<rt> (Register.toRegID Register.K1) "K1"
  let k2 = var 64<rt> (Register.toRegID Register.K2) "K2"
  let k3 = var 64<rt> (Register.toRegID Register.K3) "K3"
  let k4 = var 64<rt> (Register.toRegID Register.K4) "K4"
  let k5 = var 64<rt> (Register.toRegID Register.K5) "K5"
  let k6 = var 64<rt> (Register.toRegID Register.K6) "K6"
  let k7 = var 64<rt> (Register.toRegID Register.K7) "K7"

  (* QWORD regs *)
  member val RAX = rax with get
  member val RBX = rbx with get
  member val RCX = rcx with get
  member val RDX = rdx with get
  member val RSI = rsi with get
  member val RDI = rdi with get
  member val RSP = rsp with get
  member val RBP = rbp with get
  member val R8  = r8  with get
  member val R9  = r9  with get
  member val R10 = r10 with get
  member val R11 = r11 with get
  member val R12 = r12 with get
  member val R13 = r13 with get
  member val R14 = r14 with get
  member val R15 = r15 with get
  (* DWORD regs *)
  member val EAX = eax with get
  member val EBX = ebx with get
  member val ECX = ecx with get
  member val EDX = edx with get
  member val ESI = esi with get
  member val EDI = edi with get
  member val ESP = esp with get
  member val EBP = ebp with get
  member val R8D = reg32ext wordSize "R8D" r8 with get
  member val R9D = reg32ext wordSize "R9D" r9 with get
  member val R10D = reg32ext wordSize "R10D" r10 with get
  member val R11D = reg32ext wordSize "R11D" r11 with get
  member val R12D = reg32ext wordSize "R12D" r12 with get
  member val R13D = reg32ext wordSize "R13D" r13 with get
  member val R14D = reg32ext wordSize "R14D" r14 with get
  member val R15D = reg32ext wordSize "R15D" r15 with get
  (* WORD regs *)
  member val AX  = ax with get
  member val BX  = bx with get
  member val CX  = cx with get
  member val DX  = dx with get
  member val SI  = reg16 wordSize esi rsi with get
  member val DI  = reg16 wordSize edi rdi with get
  member val SP  = reg16 wordSize esp rsp with get
  member val BP  = reg16 wordSize ebp rbp with get
  member val R8W = reg16ext wordSize "R8W" r8 with get
  member val R9W = reg16ext wordSize "R9W" r9 with get
  member val R10W = reg16ext wordSize "R10W" r10 with get
  member val R11W = reg16ext wordSize "R11W" r11 with get
  member val R12W = reg16ext wordSize "R12W" r12 with get
  member val R13W = reg16ext wordSize "R13W" r13 with get
  member val R14W = reg16ext wordSize "R14W" r14 with get
  member val R15W = reg16ext wordSize "R15W" r15 with get
  (* BYTE regs *)
  member val AL = regL8 wordSize eax rax with get
  member val AH = regH8 wordSize eax rax with get
  member val BL = regL8 wordSize ebx rbx with get
  member val BH = regH8 wordSize ebx rbx with get
  member val CL = regL8 wordSize ecx rcx with get
  member val CH = regH8 wordSize ecx rcx with get
  member val DL = regL8 wordSize edx rdx with get
  member val DH = regH8 wordSize edx rdx with get
  member val R8L = regL8ext wordSize "R8L" r8 with get
  member val R9L = regL8ext wordSize "R9L" r9 with get
  member val R10L = regL8ext wordSize "R10L" r10 with get
  member val R11L = regL8ext wordSize "R11L" r11 with get
  member val R12L = regL8ext wordSize "R12L" r12 with get
  member val R13L = regL8ext wordSize "R13L" r13 with get
  member val R14L = regL8ext wordSize "R14L" r14 with get
  member val R15L = regL8ext wordSize "R15L" r15 with get
  member val SPL = regL8ext wordSize "SPL" rsp with get
  member val BPL = regL8ext wordSize "BPL" rbp with get
  member val SIL = regL8ext wordSize "SIL" rsi with get
  member val DIL = regL8ext wordSize "DIL" rdi with get
  (* Program counters *)
  member val EIP = pcVar 32<rt> "EIP"
  member val RIP = pcVar 64<rt> "RIP"
  (* Segment selector *)
  member val CS = var 16<rt> (Register.toRegID Register.CS) "CS"
  member val DS = var 16<rt> (Register.toRegID Register.DS) "DS"
  member val ES = var 16<rt> (Register.toRegID Register.ES) "ES"
  member val FS = var 16<rt> (Register.toRegID Register.FS) "FS"
  member val GS = var 16<rt> (Register.toRegID Register.GS) "GS"
  member val SS = var 16<rt> (Register.toRegID Register.SS) "SS"
  (* Segment base regs *)
  member val CSBase =
    var (WordSize.toRegType wordSize) (Register.toRegID Register.CSBase) "CSBase"
  member val DSBase =
    var (WordSize.toRegType wordSize) (Register.toRegID Register.DSBase) "DSBase"
  member val ESBase =
    var (WordSize.toRegType wordSize) (Register.toRegID Register.ESBase) "ESBase"
  member val FSBase =
    var (WordSize.toRegType wordSize) (Register.toRegID Register.FSBase) "FSBase"
  member val GSBase =
    var (WordSize.toRegType wordSize) (Register.toRegID Register.GSBase) "GSBase"
  member val SSBase =
    var (WordSize.toRegType wordSize) (Register.toRegID Register.SSBase) "SSBase"
  (* Control regs *)
  member val CR0 =
    var (WordSize.toRegType wordSize) (Register.toRegID Register.CR0) "CR0"
  member val CR2 =
    var (WordSize.toRegType wordSize) (Register.toRegID Register.CR2) "CR2"
  member val CR3 =
    var (WordSize.toRegType wordSize) (Register.toRegID Register.CR3) "CR3"
  member val CR4 =
    var (WordSize.toRegType wordSize) (Register.toRegID Register.CR4) "CR4"
  member val CR8 =
    var (WordSize.toRegType wordSize) (Register.toRegID Register.CR8) "CR8"
  (* EFLAGS *)
  member val OF = var 1<rt> (Register.toRegID Register.OF) "OF" with get
  member val DF = var 1<rt> (Register.toRegID Register.DF) "DF" with get
  member val IF = var 1<rt> (Register.toRegID Register.IF) "IF" with get
  member val TF = var 1<rt> (Register.toRegID Register.TF) "TF" with get
  member val SF = var 1<rt> (Register.toRegID Register.SF) "SF" with get
  member val ZF = var 1<rt> (Register.toRegID Register.ZF) "ZF" with get
  member val AF = var 1<rt> (Register.toRegID Register.AF) "AF" with get
  member val PF = var 1<rt> (Register.toRegID Register.PF) "PF" with get
  member val CF = var 1<rt> (Register.toRegID Register.CF) "CF" with get
  (* MMX Registers *)
  member val MM0 = var 64<rt> (Register.toRegID Register.MM0) "MM0" with get
  member val MM1 = var 64<rt> (Register.toRegID Register.MM1) "MM1" with get
  member val MM2 = var 64<rt> (Register.toRegID Register.MM2) "MM2" with get
  member val MM3 = var 64<rt> (Register.toRegID Register.MM3) "MM3" with get
  member val MM4 = var 64<rt> (Register.toRegID Register.MM4) "MM4" with get
  member val MM5 = var 64<rt> (Register.toRegID Register.MM5) "MM5" with get
  member val MM6 = var 64<rt> (Register.toRegID Register.MM6) "MM6" with get
  member val MM7 = var 64<rt> (Register.toRegID Register.MM7) "MM7" with get
  (* SSE Registers *)
  member val ZMM0A =
    var 64<rt> (Register.toRegID Register.ZMM0A) "ZMM0A" with get
  member val ZMM0B =
    var 64<rt> (Register.toRegID Register.ZMM0B) "ZMM0B" with get
  member val ZMM0C =
    var 64<rt> (Register.toRegID Register.ZMM0C) "ZMM0C" with get
  member val ZMM0D =
    var 64<rt> (Register.toRegID Register.ZMM0D) "ZMM0D" with get
  member val ZMM0E =
    var 64<rt> (Register.toRegID Register.ZMM0E) "ZMM0E" with get
  member val ZMM0F =
    var 64<rt> (Register.toRegID Register.ZMM0F) "ZMM0F" with get
  member val ZMM0G =
    var 64<rt> (Register.toRegID Register.ZMM0G) "ZMM0G" with get
  member val ZMM0H =
    var 64<rt> (Register.toRegID Register.ZMM0H) "ZMM0H" with get
  member val ZMM1A =
    var 64<rt> (Register.toRegID Register.ZMM1A) "ZMM1A" with get
  member val ZMM1B =
    var 64<rt> (Register.toRegID Register.ZMM1B) "ZMM1B" with get
  member val ZMM1C =
    var 64<rt> (Register.toRegID Register.ZMM1C) "ZMM1C" with get
  member val ZMM1D =
    var 64<rt> (Register.toRegID Register.ZMM1D) "ZMM1D" with get
  member val ZMM1E =
    var 64<rt> (Register.toRegID Register.ZMM1E) "ZMM1E" with get
  member val ZMM1F =
    var 64<rt> (Register.toRegID Register.ZMM1F) "ZMM1F" with get
  member val ZMM1G =
    var 64<rt> (Register.toRegID Register.ZMM1G) "ZMM1G" with get
  member val ZMM1H =
    var 64<rt> (Register.toRegID Register.ZMM1H) "ZMM1H" with get
  member val ZMM2A =
    var 64<rt> (Register.toRegID Register.ZMM2A) "ZMM2A" with get
  member val ZMM2B =
    var 64<rt> (Register.toRegID Register.ZMM2B) "ZMM2B" with get
  member val ZMM2C =
    var 64<rt> (Register.toRegID Register.ZMM2C) "ZMM2C" with get
  member val ZMM2D =
    var 64<rt> (Register.toRegID Register.ZMM2D) "ZMM2D" with get
  member val ZMM2E =
    var 64<rt> (Register.toRegID Register.ZMM2E) "ZMM2E" with get
  member val ZMM2F =
    var 64<rt> (Register.toRegID Register.ZMM2F) "ZMM2F" with get
  member val ZMM2G =
    var 64<rt> (Register.toRegID Register.ZMM2G) "ZMM2G" with get
  member val ZMM2H =
    var 64<rt> (Register.toRegID Register.ZMM2H) "ZMM2H" with get
  member val ZMM3A =
    var 64<rt> (Register.toRegID Register.ZMM3A) "ZMM3A" with get
  member val ZMM3B =
    var 64<rt> (Register.toRegID Register.ZMM3B) "ZMM3B" with get
  member val ZMM3C =
    var 64<rt> (Register.toRegID Register.ZMM3C) "ZMM3C" with get
  member val ZMM3D =
    var 64<rt> (Register.toRegID Register.ZMM3D) "ZMM3D" with get
  member val ZMM3E =
    var 64<rt> (Register.toRegID Register.ZMM3E) "ZMM3E" with get
  member val ZMM3F =
    var 64<rt> (Register.toRegID Register.ZMM3F) "ZMM3F" with get
  member val ZMM3G =
    var 64<rt> (Register.toRegID Register.ZMM3G) "ZMM3G" with get
  member val ZMM3H =
    var 64<rt> (Register.toRegID Register.ZMM3H) "ZMM3H" with get
  member val ZMM4A =
    var 64<rt> (Register.toRegID Register.ZMM4A) "ZMM4A" with get
  member val ZMM4B =
    var 64<rt> (Register.toRegID Register.ZMM4B) "ZMM4B" with get
  member val ZMM4C =
    var 64<rt> (Register.toRegID Register.ZMM4C) "ZMM4C" with get
  member val ZMM4D =
    var 64<rt> (Register.toRegID Register.ZMM4D) "ZMM4D" with get
  member val ZMM4E =
    var 64<rt> (Register.toRegID Register.ZMM4E) "ZMM4E" with get
  member val ZMM4F =
    var 64<rt> (Register.toRegID Register.ZMM4F) "ZMM4F" with get
  member val ZMM4G =
    var 64<rt> (Register.toRegID Register.ZMM4G) "ZMM4G" with get
  member val ZMM4H =
    var 64<rt> (Register.toRegID Register.ZMM4H) "ZMM4H" with get
  member val ZMM5A =
    var 64<rt> (Register.toRegID Register.ZMM5A) "ZMM5A" with get
  member val ZMM5B =
    var 64<rt> (Register.toRegID Register.ZMM5B) "ZMM5B" with get
  member val ZMM5C =
    var 64<rt> (Register.toRegID Register.ZMM5C) "ZMM5C" with get
  member val ZMM5D =
    var 64<rt> (Register.toRegID Register.ZMM5D) "ZMM5D" with get
  member val ZMM5E =
    var 64<rt> (Register.toRegID Register.ZMM5E) "ZMM5E" with get
  member val ZMM5F =
    var 64<rt> (Register.toRegID Register.ZMM5F) "ZMM5F" with get
  member val ZMM5G =
    var 64<rt> (Register.toRegID Register.ZMM5G) "ZMM5G" with get
  member val ZMM5H =
    var 64<rt> (Register.toRegID Register.ZMM5H) "ZMM5H" with get
  member val ZMM6A =
    var 64<rt> (Register.toRegID Register.ZMM6A) "ZMM6A" with get
  member val ZMM6B =
    var 64<rt> (Register.toRegID Register.ZMM6B) "ZMM6B" with get
  member val ZMM6C =
    var 64<rt> (Register.toRegID Register.ZMM6C) "ZMM6C" with get
  member val ZMM6D =
    var 64<rt> (Register.toRegID Register.ZMM6D) "ZMM6D" with get
  member val ZMM6E =
    var 64<rt> (Register.toRegID Register.ZMM6E) "ZMM6E" with get
  member val ZMM6F =
    var 64<rt> (Register.toRegID Register.ZMM6F) "ZMM6F" with get
  member val ZMM6G =
    var 64<rt> (Register.toRegID Register.ZMM6G) "ZMM6G" with get
  member val ZMM6H =
    var 64<rt> (Register.toRegID Register.ZMM6H) "ZMM6H" with get
  member val ZMM7A =
    var 64<rt> (Register.toRegID Register.ZMM7A) "ZMM7A" with get
  member val ZMM7B =
    var 64<rt> (Register.toRegID Register.ZMM7B) "ZMM7B" with get
  member val ZMM7C =
    var 64<rt> (Register.toRegID Register.ZMM7C) "ZMM7C" with get
  member val ZMM7D =
    var 64<rt> (Register.toRegID Register.ZMM7D) "ZMM7D" with get
  member val ZMM7E =
    var 64<rt> (Register.toRegID Register.ZMM7E) "ZMM7E" with get
  member val ZMM7F =
    var 64<rt> (Register.toRegID Register.ZMM7F) "ZMM7F" with get
  member val ZMM7G =
    var 64<rt> (Register.toRegID Register.ZMM7G) "ZMM7G" with get
  member val ZMM7H =
    var 64<rt> (Register.toRegID Register.ZMM7H) "ZMM7H" with get
  member val ZMM8A =
    var 64<rt> (Register.toRegID Register.ZMM8A) "ZMM8A" with get
  member val ZMM8B =
    var 64<rt> (Register.toRegID Register.ZMM8B) "ZMM8B" with get
  member val ZMM8C =
    var 64<rt> (Register.toRegID Register.ZMM8C) "ZMM8C" with get
  member val ZMM8D =
    var 64<rt> (Register.toRegID Register.ZMM8D) "ZMM8D" with get
  member val ZMM8E =
    var 64<rt> (Register.toRegID Register.ZMM8E) "ZMM8E" with get
  member val ZMM8F =
    var 64<rt> (Register.toRegID Register.ZMM8F) "ZMM8F" with get
  member val ZMM8G =
    var 64<rt> (Register.toRegID Register.ZMM8G) "ZMM8G" with get
  member val ZMM8H =
    var 64<rt> (Register.toRegID Register.ZMM8H) "ZMM8H" with get
  member val ZMM9A =
    var 64<rt> (Register.toRegID Register.ZMM9A) "ZMM9A" with get
  member val ZMM9B =
    var 64<rt> (Register.toRegID Register.ZMM9B) "ZMM9B" with get
  member val ZMM9C =
    var 64<rt> (Register.toRegID Register.ZMM9C) "ZMM9C" with get
  member val ZMM9D =
    var 64<rt> (Register.toRegID Register.ZMM9D) "ZMM9D" with get
  member val ZMM9E =
    var 64<rt> (Register.toRegID Register.ZMM9E) "ZMM9E" with get
  member val ZMM9F =
    var 64<rt> (Register.toRegID Register.ZMM9F) "ZMM9F" with get
  member val ZMM9G =
    var 64<rt> (Register.toRegID Register.ZMM9G) "ZMM9G" with get
  member val ZMM9H =
    var 64<rt> (Register.toRegID Register.ZMM9H) "ZMM9H" with get
  member val ZMM10A =
    var 64<rt> (Register.toRegID Register.ZMM10A) "ZMM10A" with get
  member val ZMM10B =
    var 64<rt> (Register.toRegID Register.ZMM10B) "ZMM10B" with get
  member val ZMM10C =
    var 64<rt> (Register.toRegID Register.ZMM10C) "ZMM10C" with get
  member val ZMM10D =
    var 64<rt> (Register.toRegID Register.ZMM10D) "ZMM10D" with get
  member val ZMM10E =
    var 64<rt> (Register.toRegID Register.ZMM10E) "ZMM10E" with get
  member val ZMM10F =
    var 64<rt> (Register.toRegID Register.ZMM10F) "ZMM10F" with get
  member val ZMM10G =
    var 64<rt> (Register.toRegID Register.ZMM10G) "ZMM10G" with get
  member val ZMM10H =
    var 64<rt> (Register.toRegID Register.ZMM10H) "ZMM10H" with get
  member val ZMM11A =
    var 64<rt> (Register.toRegID Register.ZMM11A) "ZMM11A" with get
  member val ZMM11B =
    var 64<rt> (Register.toRegID Register.ZMM11B) "ZMM11B" with get
  member val ZMM11C =
    var 64<rt> (Register.toRegID Register.ZMM11C) "ZMM11C" with get
  member val ZMM11D =
    var 64<rt> (Register.toRegID Register.ZMM11D) "ZMM11D" with get
  member val ZMM11E =
    var 64<rt> (Register.toRegID Register.ZMM11E) "ZMM11E" with get
  member val ZMM11F =
    var 64<rt> (Register.toRegID Register.ZMM11F) "ZMM11F" with get
  member val ZMM11G =
    var 64<rt> (Register.toRegID Register.ZMM11G) "ZMM11G" with get
  member val ZMM11H =
    var 64<rt> (Register.toRegID Register.ZMM11H) "ZMM11H" with get
  member val ZMM12A =
    var 64<rt> (Register.toRegID Register.ZMM12A) "ZMM12A" with get
  member val ZMM12B =
    var 64<rt> (Register.toRegID Register.ZMM12B) "ZMM12B" with get
  member val ZMM12C =
    var 64<rt> (Register.toRegID Register.ZMM12C) "ZMM12C" with get
  member val ZMM12D =
    var 64<rt> (Register.toRegID Register.ZMM12D) "ZMM12D" with get
  member val ZMM12E =
    var 64<rt> (Register.toRegID Register.ZMM12E) "ZMM12E" with get
  member val ZMM12F =
    var 64<rt> (Register.toRegID Register.ZMM12F) "ZMM12F" with get
  member val ZMM12G =
    var 64<rt> (Register.toRegID Register.ZMM12G) "ZMM12G" with get
  member val ZMM12H =
    var 64<rt> (Register.toRegID Register.ZMM12H) "ZMM12H" with get
  member val ZMM13A =
    var 64<rt> (Register.toRegID Register.ZMM13A) "ZMM13A" with get
  member val ZMM13B =
    var 64<rt> (Register.toRegID Register.ZMM13B) "ZMM13B" with get
  member val ZMM13C =
    var 64<rt> (Register.toRegID Register.ZMM13C) "ZMM13C" with get
  member val ZMM13D =
    var 64<rt> (Register.toRegID Register.ZMM13D) "ZMM13D" with get
  member val ZMM13E =
    var 64<rt> (Register.toRegID Register.ZMM13E) "ZMM13E" with get
  member val ZMM13F =
    var 64<rt> (Register.toRegID Register.ZMM13F) "ZMM13F" with get
  member val ZMM13G =
    var 64<rt> (Register.toRegID Register.ZMM13G) "ZMM13G" with get
  member val ZMM13H =
    var 64<rt> (Register.toRegID Register.ZMM13H) "ZMM13H" with get
  member val ZMM14A =
    var 64<rt> (Register.toRegID Register.ZMM14A) "ZMM14A" with get
  member val ZMM14B =
    var 64<rt> (Register.toRegID Register.ZMM14B) "ZMM14B" with get
  member val ZMM14C =
    var 64<rt> (Register.toRegID Register.ZMM14C) "ZMM14C" with get
  member val ZMM14D =
    var 64<rt> (Register.toRegID Register.ZMM14D) "ZMM14D" with get
  member val ZMM14E =
    var 64<rt> (Register.toRegID Register.ZMM14E) "ZMM14E" with get
  member val ZMM14F =
    var 64<rt> (Register.toRegID Register.ZMM14F) "ZMM14F" with get
  member val ZMM14G =
    var 64<rt> (Register.toRegID Register.ZMM14G) "ZMM14G" with get
  member val ZMM14H =
    var 64<rt> (Register.toRegID Register.ZMM14H) "ZMM14H" with get
  member val ZMM15A =
    var 64<rt> (Register.toRegID Register.ZMM15A) "ZMM15A" with get
  member val ZMM15B =
    var 64<rt> (Register.toRegID Register.ZMM15B) "ZMM15B" with get
  member val ZMM15C =
    var 64<rt> (Register.toRegID Register.ZMM15C) "ZMM15C" with get
  member val ZMM15D =
    var 64<rt> (Register.toRegID Register.ZMM15D) "ZMM15D" with get
  member val ZMM15E =
    var 64<rt> (Register.toRegID Register.ZMM15E) "ZMM15E" with get
  member val ZMM15F =
    var 64<rt> (Register.toRegID Register.ZMM15F) "ZMM15F" with get
  member val ZMM15G =
    var 64<rt> (Register.toRegID Register.ZMM15G) "ZMM15G" with get
  member val ZMM15H =
    var 64<rt> (Register.toRegID Register.ZMM15H) "ZMM15H" with get

  (* MPX Registers *)
  member val BND0A =
    var 64<rt> (Register.toRegID Register.BND0A) "BND0A" with get
  member val BND0B =
    var 64<rt> (Register.toRegID Register.BND0B) "BND0B" with get
  member val BND1A =
    var 64<rt> (Register.toRegID Register.BND1A) "BND1A" with get
  member val BND1B =
    var 64<rt> (Register.toRegID Register.BND1B) "BND1B" with get
  member val BND2A =
    var 64<rt> (Register.toRegID Register.BND2A) "BND2A" with get
  member val BND2B =
    var 64<rt> (Register.toRegID Register.BND2B) "BND2B" with get
  member val BND3A =
    var 64<rt> (Register.toRegID Register.BND3A) "BND3A" with get
  member val BND3B =
    var 64<rt> (Register.toRegID Register.BND3B) "BND3B" with get
  (* x87 FPU registers *)
  member val FCW = fcw with get
  member val FSW = fsw with get
  member val FTW = ftw with get
  member val FOP = fop with get
  member val FIP = fip with get
  member val FCS = fcs with get
  member val FDP = fdp with get
  member val FDS = fds with get
  member val MXCSR = mxcsr with get
  member val MXCSRMASK = mxcsrmask with get
  member val PKRU = pkru with get
  (* x87 FPU stack registers - Using 64 bits instead of the actual 80.*)
  member val ST0 = st0 with get
  member val ST1 = st1 with get
  member val ST2 = st2 with get
  member val ST3 = st3 with get
  member val ST4 = st4 with get
  member val ST5 = st5 with get
  member val ST6 = st6 with get
  member val ST7 = st7 with get
  (* x87 FPU Top register *)
  member val FTOP = extract fsw 3<rt> 11
  (* x87 FPU Tag word sections*)
  member val FTW0 = extract ftw 2<rt> 0
  member val FTW1 = extract ftw 2<rt> 2
  member val FTW2 = extract ftw 2<rt> 4
  member val FTW3 = extract ftw 2<rt> 6
  member val FTW4 = extract ftw 2<rt> 8
  member val FTW5 = extract ftw 2<rt> 10
  member val FTW6 = extract ftw 2<rt> 12
  member val FTW7 = extract ftw 2<rt> 14
  (* x87 Status Word Flags *)
  member val FSWC0 = extract fsw 1<rt> 8
  member val FSWC1 = extract fsw 1<rt> 9
  member val FSWC2 = extract fsw 1<rt> 10
  member val FSWC3 = extract fsw 1<rt> 14
  (* Opmask registers *)
  member val K0 = k0 with get
  member val K1 = k1 with get
  member val K2 = k2 with get
  member val K3 = k3 with get
  member val K4 = k4 with get
  member val K5 = k5 with get
  member val K6 = k6 with get
  member val K7 = k7 with get

  member __.GetRegVar (name) =
    match name with
    | R.RAX -> assert64Bit wordSize; __.RAX
    | R.RBX -> assert64Bit wordSize; __.RBX
    | R.RCX -> assert64Bit wordSize; __.RCX
    | R.RDX -> assert64Bit wordSize; __.RDX
    | R.RSP -> assert64Bit wordSize; __.RSP
    | R.RBP -> assert64Bit wordSize; __.RBP
    | R.RSI -> assert64Bit wordSize; __.RSI
    | R.RDI -> assert64Bit wordSize; __.RDI
    | R.EAX -> __.EAX
    | R.EBX -> __.EBX
    | R.ECX -> __.ECX
    | R.EDX -> __.EDX
    | R.ESP -> __.ESP
    | R.EBP -> __.EBP
    | R.ESI -> __.ESI
    | R.EDI -> __.EDI
    | R.AX -> __.AX
    | R.BX -> __.BX
    | R.CX -> __.CX
    | R.DX -> __.DX
    | R.SP -> __.SP
    | R.BP -> __.BP
    | R.SI -> __.SI
    | R.DI -> __.DI
    | R.AL -> __.AL
    | R.BL -> __.BL
    | R.CL -> __.CL
    | R.DL -> __.DL
    | R.AH -> __.AH
    | R.BH -> __.BH
    | R.CH -> __.CH
    | R.DH -> __.DH
    | R.R8 -> assert64Bit wordSize; __.R8
    | R.R9 -> assert64Bit wordSize; __.R9
    | R.R10 -> assert64Bit wordSize; __.R10
    | R.R11 -> assert64Bit wordSize; __.R11
    | R.R12 -> assert64Bit wordSize; __.R12
    | R.R13 -> assert64Bit wordSize; __.R13
    | R.R14 -> assert64Bit wordSize; __.R14
    | R.R15 -> assert64Bit wordSize; __.R15
    | R.R8D -> assert64Bit wordSize; __.R8D
    | R.R9D -> assert64Bit wordSize; __.R9D
    | R.R10D -> assert64Bit wordSize; __.R10D
    | R.R11D -> assert64Bit wordSize; __.R11D
    | R.R12D -> assert64Bit wordSize; __.R12D
    | R.R13D -> assert64Bit wordSize; __.R13D
    | R.R14D -> assert64Bit wordSize; __.R14D
    | R.R15D -> assert64Bit wordSize; __.R15D
    | R.R8W -> assert64Bit wordSize; __.R8W
    | R.R9W -> assert64Bit wordSize; __.R9W
    | R.R10W -> assert64Bit wordSize; __.R10W
    | R.R11W -> assert64Bit wordSize; __.R11W
    | R.R12W -> assert64Bit wordSize; __.R12W
    | R.R13W -> assert64Bit wordSize; __.R13W
    | R.R14W -> assert64Bit wordSize; __.R14W
    | R.R15W -> assert64Bit wordSize; __.R15W
    | R.R8L -> assert64Bit wordSize; __.R8L
    | R.R9L -> assert64Bit wordSize; __.R9L
    | R.R10L -> assert64Bit wordSize; __.R10L
    | R.R11L -> assert64Bit wordSize; __.R11L
    | R.R12L -> assert64Bit wordSize; __.R12L
    | R.R13L -> assert64Bit wordSize; __.R13L
    | R.R14L -> assert64Bit wordSize; __.R14L
    | R.R15L -> assert64Bit wordSize; __.R15L
    | R.SPL -> assert64Bit wordSize; __.SPL
    | R.BPL -> assert64Bit wordSize; __.BPL
    | R.SIL -> assert64Bit wordSize; __.SIL
    | R.DIL -> assert64Bit wordSize; __.DIL
    | R.EIP -> assert32Bit wordSize; __.EIP
    | R.RIP -> assert64Bit wordSize; __.RIP
    | R.CS -> __.CS
    | R.DS -> __.DS
    | R.ES -> __.ES
    | R.FS -> __.FS
    | R.GS -> __.GS
    | R.SS -> __.SS
    | R.CSBase -> __.CSBase
    | R.DSBase -> __.DSBase
    | R.ESBase -> __.ESBase
    | R.FSBase -> __.FSBase
    | R.GSBase -> __.GSBase
    | R.SSBase -> __.SSBase
    | R.CR0 -> __.CR0
    | R.CR2 -> __.CR2
    | R.CR3 -> __.CR3
    | R.CR4 -> __.CR4
    | R.CR8 -> assert64Bit wordSize; __.CR8
    | R.OF -> __.OF
    | R.DF -> __.DF
    | R.IF -> __.IF
    | R.TF -> __.TF
    | R.SF -> __.SF
    | R.ZF -> __.ZF
    | R.AF -> __.AF
    | R.PF -> __.PF
    | R.CF -> __.CF
    | R.MM0 -> __.MM0
    | R.MM1 -> __.MM1
    | R.MM2 -> __.MM2
    | R.MM3 -> __.MM3
    | R.MM4 -> __.MM4
    | R.MM5 -> __.MM5
    | R.MM6 -> __.MM6
    | R.MM7 -> __.MM7
    | R.FCW -> __.FCW
    | R.FSW -> __.FSW
    | R.FTW -> __.FTW
    | R.FOP -> __.FOP
    | R.FIP -> __.FIP
    | R.FCS -> __.FCS
    | R.FDP -> __.FDP
    | R.FDS -> __.FDS
    | R.FTOP -> __.FTOP
    | R.FTW0 -> __.FTW0
    | R.FTW1 -> __.FTW1
    | R.FTW2 -> __.FTW2
    | R.FTW3 -> __.FTW3
    | R.FTW4 -> __.FTW4
    | R.FTW5 -> __.FTW5
    | R.FTW6 -> __.FTW6
    | R.FTW7 -> __.FTW7
    | R.FSWC0 -> __.FSWC0
    | R.FSWC1 -> __.FSWC1
    | R.FSWC2 -> __.FSWC2
    | R.FSWC3 -> __.FSWC3
    | R.MXCSR -> __.MXCSR
    | R.MXCSRMASK -> __.MXCSRMASK
    | R.PKRU -> __.PKRU
    | R.ST0 -> __.ST0
    | R.ST1 -> __.ST1
    | R.ST2 -> __.ST2
    | R.ST3 -> __.ST3
    | R.ST4 -> __.ST4
    | R.ST5 -> __.ST5
    | R.ST6 -> __.ST6
    | R.ST7 -> __.ST7
    | R.K0 -> __.K0
    | R.K1 -> __.K1
    | R.K2 -> __.K2
    | R.K3 -> __.K3
    | R.K4 -> __.K4
    | R.K5 -> __.K5
    | R.K6 -> __.K6
    | R.K7 -> __.K7
    | _ -> failwith "Unhandled register."

  member __.GetPseudoRegVar name pos =
    match name, pos with
    | R.XMM0, 1 -> __.ZMM0A
    | R.XMM0, 2 -> __.ZMM0B
    | R.XMM1, 1 -> __.ZMM1A
    | R.XMM1, 2 -> __.ZMM1B
    | R.XMM2, 1 -> __.ZMM2A
    | R.XMM2, 2 -> __.ZMM2B
    | R.XMM3, 1 -> __.ZMM3A
    | R.XMM3, 2 -> __.ZMM3B
    | R.XMM4, 1 -> __.ZMM4A
    | R.XMM4, 2 -> __.ZMM4B
    | R.XMM5, 1 -> __.ZMM5A
    | R.XMM5, 2 -> __.ZMM5B
    | R.XMM6, 1 -> __.ZMM6A
    | R.XMM6, 2 -> __.ZMM6B
    | R.XMM7, 1 -> __.ZMM7A
    | R.XMM7, 2 -> __.ZMM7B
    | R.XMM8, 1 -> assert64Bit wordSize; __.ZMM8A
    | R.XMM8, 2 -> assert64Bit wordSize; __.ZMM8B
    | R.XMM9, 1 -> assert64Bit wordSize; __.ZMM9A
    | R.XMM9, 2 -> assert64Bit wordSize; __.ZMM9B
    | R.XMM10, 1 -> assert64Bit wordSize; __.ZMM10A
    | R.XMM10, 2 -> assert64Bit wordSize; __.ZMM10B
    | R.XMM11, 1 -> assert64Bit wordSize; __.ZMM11A
    | R.XMM11, 2 -> assert64Bit wordSize; __.ZMM11B
    | R.XMM12, 1 -> assert64Bit wordSize; __.ZMM12A
    | R.XMM12, 2 -> assert64Bit wordSize; __.ZMM12B
    | R.XMM13, 1 -> assert64Bit wordSize; __.ZMM13A
    | R.XMM13, 2 -> assert64Bit wordSize; __.ZMM13B
    | R.XMM14, 1 -> assert64Bit wordSize; __.ZMM14A
    | R.XMM14, 2 -> assert64Bit wordSize; __.ZMM14B
    | R.XMM15, 1 -> assert64Bit wordSize; __.ZMM15A
    | R.XMM15, 2 -> assert64Bit wordSize; __.ZMM15B
    | R.YMM0, 1 -> __.ZMM0A
    | R.YMM0, 2 -> __.ZMM0B
    | R.YMM0, 3 -> __.ZMM0C
    | R.YMM0, 4 -> __.ZMM0D
    | R.YMM1, 1 -> __.ZMM1A
    | R.YMM1, 2 -> __.ZMM1B
    | R.YMM1, 3 -> __.ZMM1C
    | R.YMM1, 4 -> __.ZMM1D
    | R.YMM2, 1 -> __.ZMM2A
    | R.YMM2, 2 -> __.ZMM2B
    | R.YMM2, 3 -> __.ZMM2C
    | R.YMM2, 4 -> __.ZMM2D
    | R.YMM3, 1 -> __.ZMM3A
    | R.YMM3, 2 -> __.ZMM3B
    | R.YMM3, 3 -> __.ZMM3C
    | R.YMM3, 4 -> __.ZMM3D
    | R.YMM4, 1 -> __.ZMM4A
    | R.YMM4, 2 -> __.ZMM4B
    | R.YMM4, 3 -> __.ZMM4C
    | R.YMM4, 4 -> __.ZMM4D
    | R.YMM5, 1 -> __.ZMM5A
    | R.YMM5, 2 -> __.ZMM5B
    | R.YMM5, 3 -> __.ZMM5C
    | R.YMM5, 4 -> __.ZMM5D
    | R.YMM6, 1 -> __.ZMM6A
    | R.YMM6, 2 -> __.ZMM6B
    | R.YMM6, 3 -> __.ZMM6C
    | R.YMM6, 4 -> __.ZMM6D
    | R.YMM7, 1 -> __.ZMM7A
    | R.YMM7, 2 -> __.ZMM7B
    | R.YMM7, 3 -> __.ZMM7C
    | R.YMM7, 4 -> __.ZMM7D
    | R.YMM8, 1 -> assert64Bit wordSize; __.ZMM8A
    | R.YMM8, 2 -> assert64Bit wordSize; __.ZMM8B
    | R.YMM8, 3 -> assert64Bit wordSize; __.ZMM8C
    | R.YMM8, 4 -> assert64Bit wordSize; __.ZMM8D
    | R.YMM9, 1 -> assert64Bit wordSize; __.ZMM9A
    | R.YMM9, 2 -> assert64Bit wordSize; __.ZMM9B
    | R.YMM9, 3 -> assert64Bit wordSize; __.ZMM9C
    | R.YMM9, 4 -> assert64Bit wordSize; __.ZMM9D
    | R.YMM10, 1 -> assert64Bit wordSize; __.ZMM10A
    | R.YMM10, 2 -> assert64Bit wordSize; __.ZMM10B
    | R.YMM10, 3 -> assert64Bit wordSize; __.ZMM10C
    | R.YMM10, 4 -> assert64Bit wordSize; __.ZMM10D
    | R.YMM11, 1 -> assert64Bit wordSize; __.ZMM11A
    | R.YMM11, 2 -> assert64Bit wordSize; __.ZMM11B
    | R.YMM11, 3 -> assert64Bit wordSize; __.ZMM11C
    | R.YMM11, 4 -> assert64Bit wordSize; __.ZMM11D
    | R.YMM12, 1 -> assert64Bit wordSize; __.ZMM12A
    | R.YMM12, 2 -> assert64Bit wordSize; __.ZMM12B
    | R.YMM12, 3 -> assert64Bit wordSize; __.ZMM12C
    | R.YMM12, 4 -> assert64Bit wordSize; __.ZMM12D
    | R.YMM13, 1 -> assert64Bit wordSize; __.ZMM13A
    | R.YMM13, 2 -> assert64Bit wordSize; __.ZMM13B
    | R.YMM13, 3 -> assert64Bit wordSize; __.ZMM13C
    | R.YMM13, 4 -> assert64Bit wordSize; __.ZMM13D
    | R.YMM14, 1 -> assert64Bit wordSize; __.ZMM14A
    | R.YMM14, 2 -> assert64Bit wordSize; __.ZMM14B
    | R.YMM14, 3 -> assert64Bit wordSize; __.ZMM14C
    | R.YMM14, 4 -> assert64Bit wordSize; __.ZMM14D
    | R.YMM15, 1 -> assert64Bit wordSize; __.ZMM15A
    | R.YMM15, 2 -> assert64Bit wordSize; __.ZMM15B
    | R.YMM15, 3 -> assert64Bit wordSize; __.ZMM15C
    | R.YMM15, 4 -> assert64Bit wordSize; __.ZMM15D
    | R.ZMM0, 1 -> __.ZMM0A
    | R.ZMM0, 2 -> __.ZMM0B
    | R.ZMM0, 3 -> __.ZMM0C
    | R.ZMM0, 4 -> __.ZMM0D
    | R.ZMM0, 5 -> __.ZMM0E
    | R.ZMM0, 6 -> __.ZMM0F
    | R.ZMM0, 7 -> __.ZMM0G
    | R.ZMM0, 8 -> __.ZMM0H
    | R.ZMM1, 1 -> __.ZMM1A
    | R.ZMM1, 2 -> __.ZMM1B
    | R.ZMM1, 3 -> __.ZMM1C
    | R.ZMM1, 4 -> __.ZMM1D
    | R.ZMM1, 5 -> __.ZMM1E
    | R.ZMM1, 6 -> __.ZMM1F
    | R.ZMM1, 7 -> __.ZMM1G
    | R.ZMM1, 8 -> __.ZMM1H
    | R.ZMM2, 1 -> __.ZMM2A
    | R.ZMM2, 2 -> __.ZMM2B
    | R.ZMM2, 3 -> __.ZMM2C
    | R.ZMM2, 4 -> __.ZMM2D
    | R.ZMM2, 5 -> __.ZMM2E
    | R.ZMM2, 6 -> __.ZMM2F
    | R.ZMM2, 7 -> __.ZMM2G
    | R.ZMM2, 8 -> __.ZMM2H
    | R.ZMM3, 1 -> __.ZMM3A
    | R.ZMM3, 2 -> __.ZMM3B
    | R.ZMM3, 3 -> __.ZMM3C
    | R.ZMM3, 4 -> __.ZMM3D
    | R.ZMM3, 5 -> __.ZMM3E
    | R.ZMM3, 6 -> __.ZMM3F
    | R.ZMM3, 7 -> __.ZMM3G
    | R.ZMM3, 8 -> __.ZMM3H
    | R.ZMM4, 1 -> __.ZMM4A
    | R.ZMM4, 2 -> __.ZMM4B
    | R.ZMM4, 3 -> __.ZMM4C
    | R.ZMM4, 4 -> __.ZMM4D
    | R.ZMM4, 5 -> __.ZMM4E
    | R.ZMM4, 6 -> __.ZMM4F
    | R.ZMM4, 7 -> __.ZMM4G
    | R.ZMM4, 8 -> __.ZMM4H
    | R.ZMM5, 1 -> __.ZMM5A
    | R.ZMM5, 2 -> __.ZMM5B
    | R.ZMM5, 3 -> __.ZMM5C
    | R.ZMM5, 4 -> __.ZMM5D
    | R.ZMM5, 5 -> __.ZMM5E
    | R.ZMM5, 6 -> __.ZMM5F
    | R.ZMM5, 7 -> __.ZMM5G
    | R.ZMM5, 8 -> __.ZMM5H
    | R.ZMM6, 1 -> __.ZMM6A
    | R.ZMM6, 2 -> __.ZMM6B
    | R.ZMM6, 3 -> __.ZMM6C
    | R.ZMM6, 4 -> __.ZMM6D
    | R.ZMM6, 5 -> __.ZMM6E
    | R.ZMM6, 6 -> __.ZMM6F
    | R.ZMM6, 7 -> __.ZMM6G
    | R.ZMM6, 8 -> __.ZMM6H
    | R.ZMM7, 1 -> __.ZMM7A
    | R.ZMM7, 2 -> __.ZMM7B
    | R.ZMM7, 3 -> __.ZMM7C
    | R.ZMM7, 4 -> __.ZMM7D
    | R.ZMM7, 5 -> __.ZMM7E
    | R.ZMM7, 6 -> __.ZMM7F
    | R.ZMM7, 7 -> __.ZMM7G
    | R.ZMM7, 8 -> __.ZMM7H
    | R.ZMM8, 1 -> assert64Bit wordSize; __.ZMM8A
    | R.ZMM8, 2 -> assert64Bit wordSize; __.ZMM8B
    | R.ZMM8, 3 -> assert64Bit wordSize; __.ZMM8C
    | R.ZMM8, 4 -> assert64Bit wordSize; __.ZMM8D
    | R.ZMM8, 5 -> assert64Bit wordSize; __.ZMM8E
    | R.ZMM8, 6 -> assert64Bit wordSize; __.ZMM8F
    | R.ZMM8, 7 -> assert64Bit wordSize; __.ZMM8G
    | R.ZMM8, 8 -> assert64Bit wordSize; __.ZMM8F
    | R.ZMM9, 1 -> assert64Bit wordSize; __.ZMM9A
    | R.ZMM9, 2 -> assert64Bit wordSize; __.ZMM9B
    | R.ZMM9, 3 -> assert64Bit wordSize; __.ZMM9C
    | R.ZMM9, 4 -> assert64Bit wordSize; __.ZMM9D
    | R.ZMM9, 5 -> assert64Bit wordSize; __.ZMM9E
    | R.ZMM9, 6 -> assert64Bit wordSize; __.ZMM9F
    | R.ZMM9, 7 -> assert64Bit wordSize; __.ZMM9G
    | R.ZMM9, 8 -> assert64Bit wordSize; __.ZMM9F
    | R.ZMM10, 1 -> assert64Bit wordSize; __.ZMM10A
    | R.ZMM10, 2 -> assert64Bit wordSize; __.ZMM10B
    | R.ZMM10, 3 -> assert64Bit wordSize; __.ZMM10C
    | R.ZMM10, 4 -> assert64Bit wordSize; __.ZMM10D
    | R.ZMM10, 5 -> assert64Bit wordSize; __.ZMM10E
    | R.ZMM10, 6 -> assert64Bit wordSize; __.ZMM10F
    | R.ZMM10, 7 -> assert64Bit wordSize; __.ZMM10G
    | R.ZMM10, 8 -> assert64Bit wordSize; __.ZMM10F
    | R.ZMM11, 1 -> assert64Bit wordSize; __.ZMM11A
    | R.ZMM11, 2 -> assert64Bit wordSize; __.ZMM11B
    | R.ZMM11, 3 -> assert64Bit wordSize; __.ZMM11C
    | R.ZMM11, 4 -> assert64Bit wordSize; __.ZMM11D
    | R.ZMM11, 5 -> assert64Bit wordSize; __.ZMM11E
    | R.ZMM11, 6 -> assert64Bit wordSize; __.ZMM11F
    | R.ZMM11, 7 -> assert64Bit wordSize; __.ZMM11G
    | R.ZMM11, 8 -> assert64Bit wordSize; __.ZMM11F
    | R.ZMM12, 1 -> assert64Bit wordSize; __.ZMM12A
    | R.ZMM12, 2 -> assert64Bit wordSize; __.ZMM12B
    | R.ZMM12, 3 -> assert64Bit wordSize; __.ZMM12C
    | R.ZMM12, 4 -> assert64Bit wordSize; __.ZMM12D
    | R.ZMM12, 5 -> assert64Bit wordSize; __.ZMM12E
    | R.ZMM12, 6 -> assert64Bit wordSize; __.ZMM12F
    | R.ZMM12, 7 -> assert64Bit wordSize; __.ZMM12G
    | R.ZMM12, 8 -> assert64Bit wordSize; __.ZMM12F
    | R.ZMM13, 1 -> assert64Bit wordSize; __.ZMM13A
    | R.ZMM13, 2 -> assert64Bit wordSize; __.ZMM13B
    | R.ZMM13, 3 -> assert64Bit wordSize; __.ZMM13C
    | R.ZMM13, 4 -> assert64Bit wordSize; __.ZMM13D
    | R.ZMM13, 5 -> assert64Bit wordSize; __.ZMM13E
    | R.ZMM13, 6 -> assert64Bit wordSize; __.ZMM13F
    | R.ZMM13, 7 -> assert64Bit wordSize; __.ZMM13G
    | R.ZMM13, 8 -> assert64Bit wordSize; __.ZMM13F
    | R.ZMM14, 1 -> assert64Bit wordSize; __.ZMM14A
    | R.ZMM14, 2 -> assert64Bit wordSize; __.ZMM14B
    | R.ZMM14, 3 -> assert64Bit wordSize; __.ZMM14C
    | R.ZMM14, 4 -> assert64Bit wordSize; __.ZMM14D
    | R.ZMM14, 5 -> assert64Bit wordSize; __.ZMM14E
    | R.ZMM14, 6 -> assert64Bit wordSize; __.ZMM14F
    | R.ZMM14, 7 -> assert64Bit wordSize; __.ZMM14G
    | R.ZMM14, 8 -> assert64Bit wordSize; __.ZMM14F
    | R.ZMM15, 1 -> assert64Bit wordSize; __.ZMM15A
    | R.ZMM15, 2 -> assert64Bit wordSize; __.ZMM15B
    | R.ZMM15, 3 -> assert64Bit wordSize; __.ZMM15C
    | R.ZMM15, 4 -> assert64Bit wordSize; __.ZMM15D
    | R.ZMM15, 5 -> assert64Bit wordSize; __.ZMM15E
    | R.ZMM15, 6 -> assert64Bit wordSize; __.ZMM15F
    | R.ZMM15, 7 -> assert64Bit wordSize; __.ZMM15G
    | R.ZMM15, 8 -> assert64Bit wordSize; __.ZMM15F
    | R.BND0, 1 -> __.BND0A
    | R.BND0, 2 -> __.BND0B
    | R.BND1, 1 -> __.BND1A
    | R.BND1, 2 -> __.BND1B
    | R.BND2, 1 -> __.BND2A
    | R.BND2, 2 -> __.BND2B
    | R.BND3, 1 -> __.BND3A
    | R.BND3, 2 -> __.BND3B
    | _ -> raise B2R2.FrontEnd.UnhandledRegExprException

// vim: set tw=80 sts=2 sw=2:
