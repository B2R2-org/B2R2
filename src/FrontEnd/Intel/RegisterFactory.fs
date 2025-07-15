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
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open type Register
open type WordSize

/// Represents a factory for accessing various Intel register variables.
type RegisterFactory (wordSize) =
  let reg64 wordSize t name =
    if wordSize = Bit32 then AST.undef 64<rt> name
    else AST.var 64<rt> t name

  let reg32 wordSize t name r64 =
    if wordSize = Bit32 then AST.var 32<rt> t name
    else AST.xtlo 32<rt> r64

  let reg32ext wordSize name r64 =
    if wordSize = Bit32 then AST.undef 32<rt> name
    else AST.xtlo 32<rt> r64

  let reg16 wordSize r32 r64 =
    AST.xtlo 16<rt> (if wordSize = Bit32 then r32 else r64)

  let reg16ext wordSize name r64 =
    if wordSize = Bit32 then AST.undef 16<rt> name
    else AST.xtlo 16<rt> r64

  let regL8 wordSize r32 r64 =
    AST.xtlo 8<rt> (if wordSize = Bit32 then r32 else r64)

  let regH8 wordSize r32 r64 =
    AST.extract (if wordSize = Bit32 then r32 else r64) 8<rt> 8

  let regL8ext wordSize name r64 =
    if wordSize = Bit32 then AST.undef 16<rt> name
    else AST.xtlo 8<rt> r64

  let regBasic reg regString =
    AST.var (WordSize.toRegType wordSize) reg regString

#if DEBUG
  let assert64Bit wordSize =
    if wordSize = Bit64 then () else raise InvalidRegisterException

  let assert32Bit wordSize =
    if wordSize = Bit32 then () else raise InvalidRegisterException
#endif

  (* Registers *)
  let rax = reg64 wordSize (Register.toRegID RAX) "RAX"
  let rbx = reg64 wordSize (Register.toRegID RBX) "RBX"
  let rcx = reg64 wordSize (Register.toRegID RCX) "RCX"
  let rdx = reg64 wordSize (Register.toRegID RDX) "RDX"
  let rsi = reg64 wordSize (Register.toRegID RSI) "RSI"
  let rdi = reg64 wordSize (Register.toRegID RDI) "RDI"
  let rsp = reg64 wordSize (Register.toRegID RSP) "RSP"
  let rbp = reg64 wordSize (Register.toRegID RBP) "RBP"
  let r8 = reg64 wordSize (Register.toRegID R8) "R8"
  let r9 = reg64 wordSize (Register.toRegID R9) "R9"
  let r10 = reg64 wordSize (Register.toRegID R10) "R10"
  let r11 = reg64 wordSize (Register.toRegID R11) "R11"
  let r12 = reg64 wordSize (Register.toRegID R12) "R12"
  let r13 = reg64 wordSize (Register.toRegID R13) "R13"
  let r14 = reg64 wordSize (Register.toRegID R14) "R14"
  let r15 = reg64 wordSize (Register.toRegID R15) "R15"
  let eax = reg32 wordSize (Register.toRegID EAX) "EAX" rax
  let ebx = reg32 wordSize (Register.toRegID EBX) "EBX" rbx
  let ecx = reg32 wordSize (Register.toRegID ECX) "ECX" rcx
  let edx = reg32 wordSize (Register.toRegID EDX) "EDX" rdx
  let esi = reg32 wordSize (Register.toRegID ESI) "ESI" rsi
  let edi = reg32 wordSize (Register.toRegID EDI) "EDI" rdi
  let esp = reg32 wordSize (Register.toRegID ESP) "ESP" rsp
  let ebp = reg32 wordSize (Register.toRegID EBP) "EBP" rbp
  let r8d = reg32ext wordSize "R8D" r8
  let r9d = reg32ext wordSize "R9D" r9
  let r10d = reg32ext wordSize "R10D" r10
  let r11d = reg32ext wordSize "R11D" r11
  let r12d = reg32ext wordSize "R12D" r12
  let r13d = reg32ext wordSize "R13D" r13
  let r14d = reg32ext wordSize "R14D" r14
  let r15d = reg32ext wordSize "R15D" r15
  let ax = reg16 wordSize eax rax
  let bx = reg16 wordSize ebx rbx
  let cx = reg16 wordSize ecx rcx
  let dx = reg16 wordSize edx rdx
  let si = reg16 wordSize esi rsi
  let di = reg16 wordSize edi rdi
  let sp = reg16 wordSize esp rsp
  let bp = reg16 wordSize ebp rbp
  let r8w = reg16ext wordSize "R8W" r8
  let r9w = reg16ext wordSize "R9W" r9
  let r10w = reg16ext wordSize "R10W" r10
  let r11w = reg16ext wordSize "R11W" r11
  let r12w = reg16ext wordSize "R12W" r12
  let r13w = reg16ext wordSize "R13W" r13
  let r14w = reg16ext wordSize "R14W" r14
  let r15w = reg16ext wordSize "R15W" r15
  let al = regL8 wordSize eax rax
  let ah = regH8 wordSize eax rax
  let bl = regL8 wordSize ebx rbx
  let bh = regH8 wordSize ebx rbx
  let cl = regL8 wordSize ecx rcx
  let ch = regH8 wordSize ecx rcx
  let dl = regL8 wordSize edx rdx
  let dh = regH8 wordSize edx rdx
  let r8b = regL8ext wordSize "R8B" r8
  let r9b = regL8ext wordSize "R9B" r9
  let r10b = regL8ext wordSize "R10B" r10
  let r11b = regL8ext wordSize "R11B" r11
  let r12b = regL8ext wordSize "R12B" r12
  let r13b = regL8ext wordSize "R13B" r13
  let r14b = regL8ext wordSize "R14B" r14
  let r15b = regL8ext wordSize "R15B" r15
  let spl = regL8ext wordSize "SPL" rsp
  let bpl = regL8ext wordSize "BPL" rbp
  let sil = regL8ext wordSize "SIL" rsi
  let dil = regL8ext wordSize "DIL" rdi
  let eip = AST.pcvar 32<rt> "EIP"
  let rip = AST.pcvar 64<rt> "RIP"
  let cs = AST.var 16<rt> (Register.toRegID CS) "CS"
  let ds = AST.var 16<rt> (Register.toRegID DS) "DS"
  let es = AST.var 16<rt> (Register.toRegID ES) "ES"
  let fs = AST.var 16<rt> (Register.toRegID FS) "FS"
  let gs = AST.var 16<rt> (Register.toRegID GS) "GS"
  let ss = AST.var 16<rt> (Register.toRegID SS) "SS"
  let csbase = regBasic (Register.toRegID CSBase) "CSBase"
  let dsbase = regBasic (Register.toRegID DSBase) "DSBase"
  let esbase = regBasic (Register.toRegID ESBase) "ESBase"
  let fsbase = regBasic (Register.toRegID FSBase) "FSBase"
  let gsbase = regBasic (Register.toRegID GSBase) "GSBase"
  let ssbase = regBasic (Register.toRegID SSBase) "SSBase"
  let cr0 = regBasic (Register.toRegID CR0) "CR0"
  let cr2 = regBasic (Register.toRegID CR2) "CR2"
  let cr3 = regBasic (Register.toRegID CR3) "CR3"
  let cr4 = regBasic (Register.toRegID CR4) "CR4"
  let cr8 = regBasic (Register.toRegID CR8) "CR8"
  let oFlag = AST.var 1<rt> (Register.toRegID OF) "OF"
  let dFlag = AST.var 1<rt> (Register.toRegID DF) "DF"
  let iFlag = AST.var 1<rt> (Register.toRegID IF) "IF"
  let tFlag = AST.var 1<rt> (Register.toRegID TF) "TF"
  let sFlag = AST.var 1<rt> (Register.toRegID SF) "SF"
  let zFlag = AST.var 1<rt> (Register.toRegID ZF) "ZF"
  let aFlag = AST.var 1<rt> (Register.toRegID AF) "AF"
  let pFlag = AST.var 1<rt> (Register.toRegID PF) "PF"
  let cFlag = AST.var 1<rt> (Register.toRegID CF) "CF"
  let fcw = AST.var 16<rt> (Register.toRegID FCW) "FCW"
  let fsw = AST.var 16<rt> (Register.toRegID FSW) "FSW"
  let ftw = AST.var 16<rt> (Register.toRegID FTW) "FTW"
  let fop = AST.var 16<rt> (Register.toRegID FOP) "FOP"
  let fip = AST.var 64<rt> (Register.toRegID FIP) "FIP"
  let fcs = AST.var 16<rt> (Register.toRegID FCS) "FCS"
  let fdp = AST.var 64<rt> (Register.toRegID FDP) "FDP"
  let fds = AST.var 16<rt> (Register.toRegID FDS) "FDS"
  let st0a = AST.var 64<rt> (Register.toRegID ST0A) "ST0A"
  let st0b = AST.var 16<rt> (Register.toRegID ST0B) "ST0B"
  let st1a = AST.var 64<rt> (Register.toRegID ST1A) "ST1A"
  let st1b = AST.var 16<rt> (Register.toRegID ST1B) "ST1B"
  let st2a = AST.var 64<rt> (Register.toRegID ST2A) "ST2A"
  let st2b = AST.var 16<rt> (Register.toRegID ST2B) "ST2B"
  let st3a = AST.var 64<rt> (Register.toRegID ST3A) "ST3A"
  let st3b = AST.var 16<rt> (Register.toRegID ST3B) "ST3B"
  let st4a = AST.var 64<rt> (Register.toRegID ST4A) "ST4A"
  let st4b = AST.var 16<rt> (Register.toRegID ST4B) "ST4B"
  let st5a = AST.var 64<rt> (Register.toRegID ST5A) "ST5A"
  let st5b = AST.var 16<rt> (Register.toRegID ST5B) "ST5B"
  let st6a = AST.var 64<rt> (Register.toRegID ST6A) "ST6A"
  let st6b = AST.var 16<rt> (Register.toRegID ST6B) "ST6B"
  let st7a = AST.var 64<rt> (Register.toRegID ST7A) "ST7A"
  let st7b = AST.var 16<rt> (Register.toRegID ST7B) "ST7B"
  let ftop =
    AST.shr (AST.``and`` fsw (numI32 0x3800 16<rt>)) (numI32 11 16<rt>)
    |> AST.xtlo 8<rt>
  let ftw0 =
    AST.shr (AST.``and`` ftw (numI32 0x3 16<rt>)) (numI32 0 16<rt>)
    |> AST.xtlo 8<rt>
  let ftw1 =
    AST.shr (AST.``and`` ftw (numI32 0xC 16<rt>)) (numI32 2 16<rt>)
    |> AST.xtlo 8<rt>
  let ftw2 =
    AST.shr (AST.``and`` ftw (numI32 0x30 16<rt>)) (numI32 4 16<rt>)
    |> AST.xtlo 8<rt>
  let ftw3 =
    AST.shr (AST.``and`` ftw (numI32 0xC0 16<rt>)) (numI32 6 16<rt>)
    |> AST.xtlo 8<rt>
  let ftw4 =
    AST.shr (AST.``and`` ftw (numI32 0x300 16<rt>)) (numI32 8 16<rt>)
    |> AST.xtlo 8<rt>
  let ftw5 =
    AST.shr (AST.``and`` ftw (numI32 0xC00 16<rt>)) (numI32 10 16<rt>)
    |> AST.xtlo 8<rt>
  let ftw6 =
    AST.shr (AST.``and`` ftw (numI32 0x3000 16<rt>)) (numI32 12 16<rt>)
    |> AST.xtlo 8<rt>
  let ftw7 =
    AST.shr (AST.``and`` ftw (numI32 0xC000 16<rt>)) (numI32 14 16<rt>)
    |> AST.xtlo 8<rt>
  let fswc0 = AST.extract fsw 1<rt> 8
  let fswc1 = AST.extract fsw 1<rt> 9
  let fswc2 = AST.extract fsw 1<rt> 10
  let fswc3 = AST.extract fsw 1<rt> 14
  let zmm0a = AST.var 64<rt> (Register.toRegID ZMM0A) "ZMM0A"
  let zmm0b = AST.var 64<rt> (Register.toRegID ZMM0B) "ZMM0B"
  let zmm0c = AST.var 64<rt> (Register.toRegID ZMM0C) "ZMM0C"
  let zmm0d = AST.var 64<rt> (Register.toRegID ZMM0D) "ZMM0D"
  let zmm0e = AST.var 64<rt> (Register.toRegID ZMM0E) "ZMM0E"
  let zmm0f = AST.var 64<rt> (Register.toRegID ZMM0F) "ZMM0F"
  let zmm0g = AST.var 64<rt> (Register.toRegID ZMM0G) "ZMM0G"
  let zmm0h = AST.var 64<rt> (Register.toRegID ZMM0H) "ZMM0H"
  let zmm1a = AST.var 64<rt> (Register.toRegID ZMM1A) "ZMM1A"
  let zmm1b = AST.var 64<rt> (Register.toRegID ZMM1B) "ZMM1B"
  let zmm1c = AST.var 64<rt> (Register.toRegID ZMM1C) "ZMM1C"
  let zmm1d = AST.var 64<rt> (Register.toRegID ZMM1D) "ZMM1D"
  let zmm1e = AST.var 64<rt> (Register.toRegID ZMM1E) "ZMM1E"
  let zmm1f = AST.var 64<rt> (Register.toRegID ZMM1F) "ZMM1F"
  let zmm1g = AST.var 64<rt> (Register.toRegID ZMM1G) "ZMM1G"
  let zmm1h = AST.var 64<rt> (Register.toRegID ZMM1H) "ZMM1H"
  let zmm2a = AST.var 64<rt> (Register.toRegID ZMM2A) "ZMM2A"
  let zmm2b = AST.var 64<rt> (Register.toRegID ZMM2B) "ZMM2B"
  let zmm2c = AST.var 64<rt> (Register.toRegID ZMM2C) "ZMM2C"
  let zmm2d = AST.var 64<rt> (Register.toRegID ZMM2D) "ZMM2D"
  let zmm2e = AST.var 64<rt> (Register.toRegID ZMM2E) "ZMM2E"
  let zmm2f = AST.var 64<rt> (Register.toRegID ZMM2F) "ZMM2F"
  let zmm2g = AST.var 64<rt> (Register.toRegID ZMM2G) "ZMM2G"
  let zmm2h = AST.var 64<rt> (Register.toRegID ZMM2H) "ZMM2H"
  let zmm3a = AST.var 64<rt> (Register.toRegID ZMM3A) "ZMM3A"
  let zmm3b = AST.var 64<rt> (Register.toRegID ZMM3B) "ZMM3B"
  let zmm3c = AST.var 64<rt> (Register.toRegID ZMM3C) "ZMM3C"
  let zmm3d = AST.var 64<rt> (Register.toRegID ZMM3D) "ZMM3D"
  let zmm3e = AST.var 64<rt> (Register.toRegID ZMM3E) "ZMM3E"
  let zmm3f = AST.var 64<rt> (Register.toRegID ZMM3F) "ZMM3F"
  let zmm3g = AST.var 64<rt> (Register.toRegID ZMM3G) "ZMM3G"
  let zmm3h = AST.var 64<rt> (Register.toRegID ZMM3H) "ZMM3H"
  let zmm4a = AST.var 64<rt> (Register.toRegID ZMM4A) "ZMM4A"
  let zmm4b = AST.var 64<rt> (Register.toRegID ZMM4B) "ZMM4B"
  let zmm4c = AST.var 64<rt> (Register.toRegID ZMM4C) "ZMM4C"
  let zmm4d = AST.var 64<rt> (Register.toRegID ZMM4D) "ZMM4D"
  let zmm4e = AST.var 64<rt> (Register.toRegID ZMM4E) "ZMM4E"
  let zmm4f = AST.var 64<rt> (Register.toRegID ZMM4F) "ZMM4F"
  let zmm4g = AST.var 64<rt> (Register.toRegID ZMM4G) "ZMM4G"
  let zmm4h = AST.var 64<rt> (Register.toRegID ZMM4H) "ZMM4H"
  let zmm5a = AST.var 64<rt> (Register.toRegID ZMM5A) "ZMM5A"
  let zmm5b = AST.var 64<rt> (Register.toRegID ZMM5B) "ZMM5B"
  let zmm5c = AST.var 64<rt> (Register.toRegID ZMM5C) "ZMM5C"
  let zmm5d = AST.var 64<rt> (Register.toRegID ZMM5D) "ZMM5D"
  let zmm5e = AST.var 64<rt> (Register.toRegID ZMM5E) "ZMM5E"
  let zmm5f = AST.var 64<rt> (Register.toRegID ZMM5F) "ZMM5F"
  let zmm5g = AST.var 64<rt> (Register.toRegID ZMM5G) "ZMM5G"
  let zmm5h = AST.var 64<rt> (Register.toRegID ZMM5H) "ZMM5H"
  let zmm6a = AST.var 64<rt> (Register.toRegID ZMM6A) "ZMM6A"
  let zmm6b = AST.var 64<rt> (Register.toRegID ZMM6B) "ZMM6B"
  let zmm6c = AST.var 64<rt> (Register.toRegID ZMM6C) "ZMM6C"
  let zmm6d = AST.var 64<rt> (Register.toRegID ZMM6D) "ZMM6D"
  let zmm6e = AST.var 64<rt> (Register.toRegID ZMM6E) "ZMM6E"
  let zmm6f = AST.var 64<rt> (Register.toRegID ZMM6F) "ZMM6F"
  let zmm6g = AST.var 64<rt> (Register.toRegID ZMM6G) "ZMM6G"
  let zmm6h = AST.var 64<rt> (Register.toRegID ZMM6H) "ZMM6H"
  let zmm7a = AST.var 64<rt> (Register.toRegID ZMM7A) "ZMM7A"
  let zmm7b = AST.var 64<rt> (Register.toRegID ZMM7B) "ZMM7B"
  let zmm7c = AST.var 64<rt> (Register.toRegID ZMM7C) "ZMM7C"
  let zmm7d = AST.var 64<rt> (Register.toRegID ZMM7D) "ZMM7D"
  let zmm7e = AST.var 64<rt> (Register.toRegID ZMM7E) "ZMM7E"
  let zmm7f = AST.var 64<rt> (Register.toRegID ZMM7F) "ZMM7F"
  let zmm7g = AST.var 64<rt> (Register.toRegID ZMM7G) "ZMM7G"
  let zmm7h = AST.var 64<rt> (Register.toRegID ZMM7H) "ZMM7H"
  let zmm8a = AST.var 64<rt> (Register.toRegID ZMM8A) "ZMM8A"
  let zmm8b = AST.var 64<rt> (Register.toRegID ZMM8B) "ZMM8B"
  let zmm8c = AST.var 64<rt> (Register.toRegID ZMM8C) "ZMM8C"
  let zmm8d = AST.var 64<rt> (Register.toRegID ZMM8D) "ZMM8D"
  let zmm8e = AST.var 64<rt> (Register.toRegID ZMM8E) "ZMM8E"
  let zmm8f = AST.var 64<rt> (Register.toRegID ZMM8F) "ZMM8F"
  let zmm8g = AST.var 64<rt> (Register.toRegID ZMM8G) "ZMM8G"
  let zmm8h = AST.var 64<rt> (Register.toRegID ZMM8H) "ZMM8H"
  let zmm9a = AST.var 64<rt> (Register.toRegID ZMM9A) "ZMM9A"
  let zmm9b = AST.var 64<rt> (Register.toRegID ZMM9B) "ZMM9B"
  let zmm9c = AST.var 64<rt> (Register.toRegID ZMM9C) "ZMM9C"
  let zmm9d = AST.var 64<rt> (Register.toRegID ZMM9D) "ZMM9D"
  let zmm9e = AST.var 64<rt> (Register.toRegID ZMM9E) "ZMM9E"
  let zmm9f = AST.var 64<rt> (Register.toRegID ZMM9F) "ZMM9F"
  let zmm9g = AST.var 64<rt> (Register.toRegID ZMM9G) "ZMM9G"
  let zmm9h = AST.var 64<rt> (Register.toRegID ZMM9H) "ZMM9H"
  let zmm10a = AST.var 64<rt> (Register.toRegID ZMM10A) "ZMM10A"
  let zmm10b = AST.var 64<rt> (Register.toRegID ZMM10B) "ZMM10B"
  let zmm10c = AST.var 64<rt> (Register.toRegID ZMM10C) "ZMM10C"
  let zmm10d = AST.var 64<rt> (Register.toRegID ZMM10D) "ZMM10D"
  let zmm10e = AST.var 64<rt> (Register.toRegID ZMM10E) "ZMM10E"
  let zmm10f = AST.var 64<rt> (Register.toRegID ZMM10F) "ZMM10F"
  let zmm10g = AST.var 64<rt> (Register.toRegID ZMM10G) "ZMM10G"
  let zmm10h = AST.var 64<rt> (Register.toRegID ZMM10H) "ZMM10H"
  let zmm11a = AST.var 64<rt> (Register.toRegID ZMM11A) "ZMM11A"
  let zmm11b = AST.var 64<rt> (Register.toRegID ZMM11B) "ZMM11B"
  let zmm11c = AST.var 64<rt> (Register.toRegID ZMM11C) "ZMM11C"
  let zmm11d = AST.var 64<rt> (Register.toRegID ZMM11D) "ZMM11D"
  let zmm11e = AST.var 64<rt> (Register.toRegID ZMM11E) "ZMM11E"
  let zmm11f = AST.var 64<rt> (Register.toRegID ZMM11F) "ZMM11F"
  let zmm11g = AST.var 64<rt> (Register.toRegID ZMM11G) "ZMM11G"
  let zmm11h = AST.var 64<rt> (Register.toRegID ZMM11H) "ZMM11H"
  let zmm12a = AST.var 64<rt> (Register.toRegID ZMM12A) "ZMM12A"
  let zmm12b = AST.var 64<rt> (Register.toRegID ZMM12B) "ZMM12B"
  let zmm12c = AST.var 64<rt> (Register.toRegID ZMM12C) "ZMM12C"
  let zmm12d = AST.var 64<rt> (Register.toRegID ZMM12D) "ZMM12D"
  let zmm12e = AST.var 64<rt> (Register.toRegID ZMM12E) "ZMM12E"
  let zmm12f = AST.var 64<rt> (Register.toRegID ZMM12F) "ZMM12F"
  let zmm12g = AST.var 64<rt> (Register.toRegID ZMM12G) "ZMM12G"
  let zmm12h = AST.var 64<rt> (Register.toRegID ZMM12H) "ZMM12H"
  let zmm13a = AST.var 64<rt> (Register.toRegID ZMM13A) "ZMM13A"
  let zmm13b = AST.var 64<rt> (Register.toRegID ZMM13B) "ZMM13B"
  let zmm13c = AST.var 64<rt> (Register.toRegID ZMM13C) "ZMM13C"
  let zmm13d = AST.var 64<rt> (Register.toRegID ZMM13D) "ZMM13D"
  let zmm13e = AST.var 64<rt> (Register.toRegID ZMM13E) "ZMM13E"
  let zmm13f = AST.var 64<rt> (Register.toRegID ZMM13F) "ZMM13F"
  let zmm13g = AST.var 64<rt> (Register.toRegID ZMM13G) "ZMM13G"
  let zmm13h = AST.var 64<rt> (Register.toRegID ZMM13H) "ZMM13H"
  let zmm14a = AST.var 64<rt> (Register.toRegID ZMM14A) "ZMM14A"
  let zmm14b = AST.var 64<rt> (Register.toRegID ZMM14B) "ZMM14B"
  let zmm14c = AST.var 64<rt> (Register.toRegID ZMM14C) "ZMM14C"
  let zmm14d = AST.var 64<rt> (Register.toRegID ZMM14D) "ZMM14D"
  let zmm14e = AST.var 64<rt> (Register.toRegID ZMM14E) "ZMM14E"
  let zmm14f = AST.var 64<rt> (Register.toRegID ZMM14F) "ZMM14F"
  let zmm14g = AST.var 64<rt> (Register.toRegID ZMM14G) "ZMM14G"
  let zmm14h = AST.var 64<rt> (Register.toRegID ZMM14H) "ZMM14H"
  let zmm15a = AST.var 64<rt> (Register.toRegID ZMM15A) "ZMM15A"
  let zmm15b = AST.var 64<rt> (Register.toRegID ZMM15B) "ZMM15B"
  let zmm15c = AST.var 64<rt> (Register.toRegID ZMM15C) "ZMM15C"
  let zmm15d = AST.var 64<rt> (Register.toRegID ZMM15D) "ZMM15D"
  let zmm15e = AST.var 64<rt> (Register.toRegID ZMM15E) "ZMM15E"
  let zmm15f = AST.var 64<rt> (Register.toRegID ZMM15F) "ZMM15F"
  let zmm15g = AST.var 64<rt> (Register.toRegID ZMM15G) "ZMM15G"
  let zmm15h = AST.var 64<rt> (Register.toRegID ZMM15H) "ZMM15H"
  let bnd0a = AST.var 64<rt> (Register.toRegID BND0A) "BND0A"
  let bnd0b = AST.var 64<rt> (Register.toRegID BND0B) "BND0B"
  let bnd1a = AST.var 64<rt> (Register.toRegID BND1A) "BND1A"
  let bnd1b = AST.var 64<rt> (Register.toRegID BND1B) "BND1B"
  let bnd2a = AST.var 64<rt> (Register.toRegID BND2A) "BND2A"
  let bnd2b = AST.var 64<rt> (Register.toRegID BND2B) "BND2B"
  let bnd3a = AST.var 64<rt> (Register.toRegID BND3A) "BND3A"
  let bnd3b = AST.var 64<rt> (Register.toRegID BND3B) "BND3B"
  let mxcsr = AST.var 32<rt> (Register.toRegID MXCSR) "MXCSR"
  let mxcsrmask = AST.var 32<rt> (Register.toRegID MXCSRMASK) "MXCSR_MASK"
  let pkru = AST.var 32<rt> (Register.toRegID PKRU) "PKRU"
  let k0 = AST.var 64<rt> (Register.toRegID K0) "K0"
  let k1 = AST.var 64<rt> (Register.toRegID K1) "K1"
  let k2 = AST.var 64<rt> (Register.toRegID K2) "K2"
  let k3 = AST.var 64<rt> (Register.toRegID K3) "K3"
  let k4 = AST.var 64<rt> (Register.toRegID K4) "K4"
  let k5 = AST.var 64<rt> (Register.toRegID K5) "K5"
  let k6 = AST.var 64<rt> (Register.toRegID K6) "K6"
  let k7 = AST.var 64<rt> (Register.toRegID K7) "K7"
  let dr0 = AST.var 32<rt> (Register.toRegID DR0) "DR0"
  let dr1 = AST.var 32<rt> (Register.toRegID DR1) "DR1"
  let dr2 = AST.var 32<rt> (Register.toRegID DR2) "DR2"
  let dr3 = AST.var 32<rt> (Register.toRegID DR3) "DR3"
  let dr6 = AST.var 32<rt> (Register.toRegID DR6) "DR6"
  let dr7 = AST.var 32<rt> (Register.toRegID DR7) "DR7"

#if EMULATION
  let ccOp =
    AST.var 8<rt> (Register.toRegID CCOP) "CCOP"
  let ccDst =
    AST.var (WordSize.toRegType wordSize) (Register.toRegID CCDST) "CCDST"
  let ccDstD =
    if wordSize = Bit32 then ccDst
    else AST.xtlo 32<rt> ccDst
  let ccDstW = AST.xtlo 16<rt> ccDst
  let ccDstB = AST.xtlo 8<rt> ccDst
  let ccSrc1 =
    AST.var (WordSize.toRegType wordSize) (Register.toRegID CCSRC1) "CCSRC1"
  let ccSrc1D =
    if wordSize = Bit32 then ccSrc1
    else AST.xtlo 32<rt> ccSrc1
  let ccSrc1W = AST.xtlo 16<rt> ccSrc1
  let ccSrc1B = AST.xtlo 8<rt> ccSrc1
  let ccSrc2 =
    AST.var (WordSize.toRegType wordSize) (Register.toRegID CCSRC2) "CCSRC2"
  let ccSrc2D =
    if wordSize = Bit32 then ccSrc2
    else AST.xtlo 32<rt> ccSrc2
  let ccSrc2W = AST.xtlo 16<rt> ccSrc2
  let ccSrc2B = AST.xtlo 8<rt> ccSrc2
#endif

  interface IRegisterFactory with
    member _.GetRegVar rid =
      match Register.ofRegID rid with
      | R.RAX ->
#if DEBUG
        assert64Bit wordSize
#endif
        rax
      | R.RBX ->
#if DEBUG
        assert64Bit wordSize
#endif
        rbx
      | R.RCX ->
#if DEBUG
        assert64Bit wordSize
#endif
        rcx
      | R.RDX ->
#if DEBUG
        assert64Bit wordSize
#endif
        rdx
      | R.RSP ->
#if DEBUG
        assert64Bit wordSize
#endif
        rsp
      | R.RBP ->
#if DEBUG
        assert64Bit wordSize
#endif
        rbp
      | R.RSI ->
#if DEBUG
        assert64Bit wordSize
#endif
        rsi
      | R.RDI ->
#if DEBUG
        assert64Bit wordSize
#endif
        rdi
      | R.EAX -> eax
      | R.EBX -> ebx
      | R.ECX -> ecx
      | R.EDX -> edx
      | R.ESP -> esp
      | R.EBP -> ebp
      | R.ESI -> esi
      | R.EDI -> edi
      | R.AX -> ax
      | R.BX -> bx
      | R.CX -> cx
      | R.DX -> dx
      | R.SP -> sp
      | R.BP -> bp
      | R.SI -> si
      | R.DI -> di
      | R.AL -> al
      | R.BL -> bl
      | R.CL -> cl
      | R.DL -> dl
      | R.AH -> ah
      | R.BH -> bh
      | R.CH -> ch
      | R.DH -> dh
      | R.R8 ->
#if DEBUG
        assert64Bit wordSize
#endif
        r8
      | R.R9 ->
#if DEBUG
        assert64Bit wordSize
#endif
        r9
      | R.R10 ->
#if DEBUG
        assert64Bit wordSize
#endif
        r10
      | R.R11 ->
#if DEBUG
        assert64Bit wordSize
#endif
        r11
      | R.R12 ->
#if DEBUG
        assert64Bit wordSize
#endif
        r12
      | R.R13 ->
#if DEBUG
        assert64Bit wordSize
#endif
        r13
      | R.R14 ->
#if DEBUG
        assert64Bit wordSize
#endif
        r14
      | R.R15 ->
#if DEBUG
        assert64Bit wordSize
#endif
        r15
      | R.R8D ->
#if DEBUG
        assert64Bit wordSize
#endif
        r8d
      | R.R9D ->
#if DEBUG
        assert64Bit wordSize
#endif
        r9d
      | R.R10D ->
#if DEBUG
        assert64Bit wordSize
#endif
        r10d
      | R.R11D ->
#if DEBUG
        assert64Bit wordSize
#endif
        r11d
      | R.R12D ->
#if DEBUG
        assert64Bit wordSize
#endif
        r12d
      | R.R13D ->
#if DEBUG
        assert64Bit wordSize
#endif
        r13d
      | R.R14D ->
#if DEBUG
        assert64Bit wordSize
#endif
        r14d
      | R.R15D ->
#if DEBUG
        assert64Bit wordSize
#endif
        r15d
      | R.R8W ->
#if DEBUG
        assert64Bit wordSize
#endif
        r8w
      | R.R9W ->
#if DEBUG
        assert64Bit wordSize
#endif
        r9w
      | R.R10W ->
#if DEBUG
        assert64Bit wordSize
#endif
        r10w
      | R.R11W ->
#if DEBUG
        assert64Bit wordSize
#endif
        r11w
      | R.R12W ->
#if DEBUG
        assert64Bit wordSize
#endif
        r12w
      | R.R13W ->
#if DEBUG
        assert64Bit wordSize
#endif
        r13w
      | R.R14W ->
#if DEBUG
        assert64Bit wordSize
#endif
        r14w
      | R.R15W ->
#if DEBUG
        assert64Bit wordSize
#endif
        r15w
      | R.R8B ->
#if DEBUG
        assert64Bit wordSize
#endif
        r8b
      | R.R9B ->
#if DEBUG
        assert64Bit wordSize
#endif
        r9b
      | R.R10B ->
#if DEBUG
        assert64Bit wordSize
#endif
        r10b
      | R.R11B ->
#if DEBUG
        assert64Bit wordSize
#endif
        r11b
      | R.R12B ->
#if DEBUG
        assert64Bit wordSize
#endif
        r12b
      | R.R13B ->
#if DEBUG
        assert64Bit wordSize
#endif
        r13b
      | R.R14B ->
#if DEBUG
        assert64Bit wordSize
#endif
        r14b
      | R.R15B ->
#if DEBUG
        assert64Bit wordSize
#endif
        r15b
      | R.SPL ->
#if DEBUG
        assert64Bit wordSize
#endif
        spl
      | R.BPL ->
#if DEBUG
        assert64Bit wordSize
#endif
        bpl
      | R.SIL ->
#if DEBUG
        assert64Bit wordSize
#endif
        sil
      | R.DIL ->
#if DEBUG
        assert64Bit wordSize
#endif
        dil
      | R.EIP ->
        eip
      | R.RIP ->
#if DEBUG
        assert64Bit wordSize
#endif
        rip
      | R.CS -> cs
      | R.DS -> ds
      | R.ES -> es
      | R.FS -> fs
      | R.GS -> gs
      | R.SS -> ss
      | R.CSBase -> csbase
      | R.DSBase -> dsbase
      | R.ESBase -> esbase
      | R.FSBase -> fsbase
      | R.GSBase -> gsbase
      | R.SSBase -> ssbase
      | R.CR0 -> cr0
      | R.CR2 -> cr2
      | R.CR3 -> cr3
      | R.CR4 -> cr4
      | R.CR8 ->
#if DEBUG
        assert64Bit wordSize
#endif
        cr8
      | R.OF -> oFlag
      | R.DF -> dFlag
      | R.IF -> iFlag
      | R.TF -> tFlag
      | R.SF -> sFlag
      | R.ZF -> zFlag
      | R.AF -> aFlag
      | R.PF -> pFlag
      | R.CF -> cFlag
      | R.MM0 -> st0a
      | R.MM1 -> st1a
      | R.MM2 -> st2a
      | R.MM3 -> st3a
      | R.MM4 -> st4a
      | R.MM5 -> st5a
      | R.MM6 -> st6a
      | R.MM7 -> st7a
      | R.FCW -> fcw
      | R.FSW -> fsw
      | R.FTW -> ftw
      | R.FOP -> fop
      | R.FIP -> fip
      | R.FCS -> fcs
      | R.FDP -> fdp
      | R.FDS -> fds
      | R.FTOP -> ftop
      | R.FTW0 -> ftw0
      | R.FTW1 -> ftw1
      | R.FTW2 -> ftw2
      | R.FTW3 -> ftw3
      | R.FTW4 -> ftw4
      | R.FTW5 -> ftw5
      | R.FTW6 -> ftw6
      | R.FTW7 -> ftw7
      | R.FSWC0 -> fswc0
      | R.FSWC1 -> fswc1
      | R.FSWC2 -> fswc2
      | R.FSWC3 -> fswc3
      | R.MXCSR -> mxcsr
      | R.MXCSRMASK -> mxcsrmask
      | R.PKRU -> pkru
      | R.ST0 -> AST.concat st0b st0a
      | R.ST1 -> AST.concat st1b st1a
      | R.ST2 -> AST.concat st2b st2a
      | R.ST3 -> AST.concat st3b st3a
      | R.ST4 -> AST.concat st4b st4a
      | R.ST5 -> AST.concat st5b st5a
      | R.ST6 -> AST.concat st6b st6a
      | R.ST7 -> AST.concat st7b st7a
      | R.K0 -> k0
      | R.K1 -> k1
      | R.K2 -> k2
      | R.K3 -> k3
      | R.K4 -> k4
      | R.K5 -> k5
      | R.K6 -> k6
      | R.K7 -> k7
      | R.DR0 -> dr0
      | R.DR1 -> dr1
      | R.DR2 -> dr2
      | R.DR3 -> dr3
      | R.DR6 -> dr6
      | R.DR7 -> dr7
#if EMULATION
      | R.CCOP -> ccOp
      | R.CCDST -> ccDst
      | R.CCDSTD -> ccDstD
      | R.CCDSTW -> ccDstW
      | R.CCDSTB -> ccDstB
      | R.CCSRC1 -> ccSrc1
      | R.CCSRC1D -> ccSrc1D
      | R.CCSRC1W -> ccSrc1W
      | R.CCSRC1B -> ccSrc1B
      | R.CCSRC2 -> ccSrc2
      | R.CCSRC2D -> ccSrc2D
      | R.CCSRC2W -> ccSrc2W
      | R.CCSRC2B -> ccSrc2B
#endif
      | _ -> failwith "Unhandled register."

    member _.GetRegVar (name: string) =
      match name.ToUpperInvariant () with
      | "RAX" -> rax
      | "RBX" -> rbx
      | "RCX" -> rcx
      | "RDX" -> rdx
      | "RSP" -> rsp
      | "RBP" -> rbp
      | "RSI" -> rsi
      | "RDI" -> rdi
      | "EAX" -> eax
      | "EBX" -> ebx
      | "ECX" -> ecx
      | "EDX" -> edx
      | "ESP" -> esp
      | "EBP" -> ebp
      | "ESI" -> esi
      | "EDI" -> edi
      | "AX" -> ax
      | "BX" -> bx
      | "CX" -> cx
      | "DX" -> dx
      | "SP" -> sp
      | "BP" -> bp
      | "SI" -> si
      | "DI" -> di
      | "AL" -> al
      | "BL" -> bl
      | "CL" -> cl
      | "DL" -> dl
      | "AH" -> ah
      | "BH" -> bh
      | "CH" -> ch
      | "DH" -> dh
      | "R8" -> r8
      | "R9" -> r9
      | "R10" -> r10
      | "R11" -> r11
      | "R12" -> r12
      | "R13" -> r13
      | "R14" -> r14
      | "R15" -> r15
      | "R8D" -> r8d
      | "R9D" -> r9d
      | "R10D" -> r10d
      | "R11D" -> r11d
      | "R12D" -> r12d
      | "R13D" -> r13d
      | "R14D" -> r14d
      | "R15D" -> r15d
      | "R8W" -> r8w
      | "R9W" -> r9w
      | "R10W" -> r10w
      | "R11W" -> r11w
      | "R12W" -> r12w
      | "R13W" -> r13w
      | "R14W" -> r14w
      | "R15W" -> r15w
      | "R8B" -> r8b
      | "R9B" -> r9b
      | "R10B" -> r10b
      | "R11B" -> r11b
      | "R12B" -> r12b
      | "R13B" -> r13b
      | "R14B" -> r14b
      | "R15B" -> r15b
      | "SPL" -> spl
      | "BPL" -> bpl
      | "SIL" -> sil
      | "DIL" -> dil
      | "EIP" -> eip
      | "RIP" -> rip
      | "MM0" -> st0a
      | "MM1" -> st1a
      | "MM2" -> st2a
      | "MM3" -> st3a
      | "MM4" -> st4a
      | "MM5" -> st5a
      | "MM6" -> st6a
      | "MM7" -> st7a
      | "CS" -> cs
      | "DS" -> ds
      | "SS" -> ss
      | "ES" -> es
      | "FS" -> fs
      | "GS" -> gs
      | "CSBASE" -> csbase
      | "DSBASE" -> dsbase
      | "ESBASE" -> esbase
      | "FSBASE" -> fsbase
      | "GSBASE" -> gsbase
      | "SSBASE" -> ssbase
      | "CR0" -> cr0
      | "CR2" -> cr2
      | "CR3" -> cr3
      | "CR4" -> cr4
      | "CR8" -> cr8
      | "OF" -> oFlag
      | "DF" -> dFlag
      | "IF" -> iFlag
      | "TF" -> tFlag
      | "SF" -> sFlag
      | "ZF" -> zFlag
      | "AF" -> aFlag
      | "PF" -> pFlag
      | "CF" -> cFlag
      | "K0" -> k0
      | "K1" -> k1
      | "K2" -> k2
      | "K3" -> k3
      | "K4" -> k4
      | "K5" -> k5
      | "K6" -> k6
      | "K7" -> k7
      | "ST0A" -> st0a
      | "ST0B" -> st0b
      | "ST1A" -> st1a
      | "ST1B" -> st1b
      | "ST2A" -> st2a
      | "ST2B" -> st2b
      | "ST3A" -> st3a
      | "ST3B" -> st3b
      | "ST4A" -> st4a
      | "ST4B" -> st4b
      | "ST5A" -> st5a
      | "ST5B" -> st5b
      | "ST6A" -> st6a
      | "ST6B" -> st6b
      | "ST7A" -> st7a
      | "ST7B" -> st7b
      | "FCW" -> fcw
      | "FSW" -> fsw
      | "FTW" -> ftw
      | "FOP" -> fop
      | "FIP" -> fip
      | "FCS" -> fcs
      | "FDP" -> fdp
      | "FDS" -> fds
      | "FTOP" -> ftop
      | "FTW0" -> ftw0
      | "FTW1" -> ftw1
      | "FTW2" -> ftw2
      | "FTW3" -> ftw3
      | "FTW4" -> ftw4
      | "FTW5" -> ftw5
      | "FTW6" -> ftw6
      | "FTW7" -> ftw7
      | "FSWC0" -> fswc0
      | "FSWC1" -> fswc1
      | "FSWC2" -> fswc2
      | "FSWC3" -> fswc3
      | "MXCSR" -> mxcsr
      | "MXCSRMASK" -> mxcsrmask
      | "ZMM0A" -> zmm0a
      | "ZMM0B" -> zmm0b
      | "ZMM0C" -> zmm0c
      | "ZMM0D" -> zmm0d
      | "ZMM0E" -> zmm0e
      | "ZMM0F" -> zmm0f
      | "ZMM0G" -> zmm0g
      | "ZMM0H" -> zmm0h
      | "ZMM1A" -> zmm1a
      | "ZMM1B" -> zmm1b
      | "ZMM1C" -> zmm1c
      | "ZMM1D" -> zmm1d
      | "ZMM1E" -> zmm1e
      | "ZMM1F" -> zmm1f
      | "ZMM1G" -> zmm1g
      | "ZMM1H" -> zmm1h
      | "ZMM2A" -> zmm2a
      | "ZMM2B" -> zmm2b
      | "ZMM2C" -> zmm2c
      | "ZMM2D" -> zmm2d
      | "ZMM2E" -> zmm2e
      | "ZMM2F" -> zmm2f
      | "ZMM2G" -> zmm2g
      | "ZMM2H" -> zmm2h
      | "ZMM3A" -> zmm3a
      | "ZMM3B" -> zmm3b
      | "ZMM3C" -> zmm3c
      | "ZMM3D" -> zmm3d
      | "ZMM3E" -> zmm3e
      | "ZMM3F" -> zmm3f
      | "ZMM3G" -> zmm3g
      | "ZMM3H" -> zmm3h
      | "ZMM4A" -> zmm4a
      | "ZMM4B" -> zmm4b
      | "ZMM4C" -> zmm4c
      | "ZMM4D" -> zmm4d
      | "ZMM4E" -> zmm4e
      | "ZMM4F" -> zmm4f
      | "ZMM4G" -> zmm4g
      | "ZMM4H" -> zmm4h
      | "ZMM5A" -> zmm5a
      | "ZMM5B" -> zmm5b
      | "ZMM5C" -> zmm5c
      | "ZMM5D" -> zmm5d
      | "ZMM5E" -> zmm5e
      | "ZMM5F" -> zmm5f
      | "ZMM5G" -> zmm5g
      | "ZMM5H" -> zmm5h
      | "ZMM6A" -> zmm6a
      | "ZMM6B" -> zmm6b
      | "ZMM6C" -> zmm6c
      | "ZMM6D" -> zmm6d
      | "ZMM6E" -> zmm6e
      | "ZMM6F" -> zmm6f
      | "ZMM6G" -> zmm6g
      | "ZMM6H" -> zmm6h
      | "ZMM7A" -> zmm7a
      | "ZMM7B" -> zmm7b
      | "ZMM7C" -> zmm7c
      | "ZMM7D" -> zmm7d
      | "ZMM7E" -> zmm7e
      | "ZMM7F" -> zmm7f
      | "ZMM7G" -> zmm7g
      | "ZMM7H" -> zmm7h
      | "ZMM8A" -> zmm8a
      | "ZMM8B" -> zmm8b
      | "ZMM8C" -> zmm8c
      | "ZMM8D" -> zmm8d
      | "ZMM8E" -> zmm8e
      | "ZMM8F" -> zmm8f
      | "ZMM8G" -> zmm8g
      | "ZMM8H" -> zmm8h
      | "ZMM9A" -> zmm9a
      | "ZMM9B" -> zmm9b
      | "ZMM9C" -> zmm9c
      | "ZMM9D" -> zmm9d
      | "ZMM9E" -> zmm9e
      | "ZMM9F" -> zmm9f
      | "ZMM9G" -> zmm9g
      | "ZMM9H" -> zmm9h
      | "ZMM10A" -> zmm10a
      | "ZMM10B" -> zmm10b
      | "ZMM10C" -> zmm10c
      | "ZMM10D" -> zmm10d
      | "ZMM10E" -> zmm10e
      | "ZMM10F" -> zmm10f
      | "ZMM10G" -> zmm10g
      | "ZMM10H" -> zmm10h
      | "ZMM11A" -> zmm11a
      | "ZMM11B" -> zmm11b
      | "ZMM11C" -> zmm11c
      | "ZMM11D" -> zmm11d
      | "ZMM11E" -> zmm11e
      | "ZMM11F" -> zmm11f
      | "ZMM11G" -> zmm11g
      | "ZMM11H" -> zmm11h
      | "ZMM12A" -> zmm12a
      | "ZMM12B" -> zmm12b
      | "ZMM12C" -> zmm12c
      | "ZMM12D" -> zmm12d
      | "ZMM12E" -> zmm12e
      | "ZMM12F" -> zmm12f
      | "ZMM12G" -> zmm12g
      | "ZMM12H" -> zmm12h
      | "ZMM13A" -> zmm13a
      | "ZMM13B" -> zmm13b
      | "ZMM13C" -> zmm13c
      | "ZMM13D" -> zmm13d
      | "ZMM13E" -> zmm13e
      | "ZMM13F" -> zmm13f
      | "ZMM13G" -> zmm13g
      | "ZMM13H" -> zmm13h
      | "ZMM14A" -> zmm14a
      | "ZMM14B" -> zmm14b
      | "ZMM14C" -> zmm14c
      | "ZMM14D" -> zmm14d
      | "ZMM14E" -> zmm14e
      | "ZMM14F" -> zmm14f
      | "ZMM14G" -> zmm14g
      | "ZMM14H" -> zmm14h
      | "ZMM15A" -> zmm15a
      | "ZMM15B" -> zmm15b
      | "ZMM15C" -> zmm15c
      | "ZMM15D" -> zmm15d
      | "ZMM15E" -> zmm15e
      | "ZMM15F" -> zmm15f
      | "ZMM15G" -> zmm15g
      | "ZMM15H" -> zmm15h
      | "PKRU" -> pkru
      | "DR0" -> dr0
      | "DR1" -> dr1
      | "DR2" -> dr2
      | "DR3" -> dr3
      | "DR6" -> dr6
      | "DR7" -> dr7
      | _ -> raise InvalidRegisterException

    member _.GetPseudoRegVar rid pos =
      match Register.ofRegID rid, pos with
      | R.XMM0, 1 -> zmm0a
      | R.XMM0, 2 -> zmm0b
      | R.XMM1, 1 -> zmm1a
      | R.XMM1, 2 -> zmm1b
      | R.XMM2, 1 -> zmm2a
      | R.XMM2, 2 -> zmm2b
      | R.XMM3, 1 -> zmm3a
      | R.XMM3, 2 -> zmm3b
      | R.XMM4, 1 -> zmm4a
      | R.XMM4, 2 -> zmm4b
      | R.XMM5, 1 -> zmm5a
      | R.XMM5, 2 -> zmm5b
      | R.XMM6, 1 -> zmm6a
      | R.XMM6, 2 -> zmm6b
      | R.XMM7, 1 -> zmm7a
      | R.XMM7, 2 -> zmm7b
      | R.XMM8, 1 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm8a
      | R.XMM8, 2 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm8b
      | R.XMM9, 1 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm9a
      | R.XMM9, 2 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm9b
      | R.XMM10, 1 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm10a
      | R.XMM10, 2 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm10b
      | R.XMM11, 1 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm11a
      | R.XMM11, 2 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm11b
      | R.XMM12, 1 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm12a
      | R.XMM12, 2 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm12b
      | R.XMM13, 1 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm13a
      | R.XMM13, 2 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm13b
      | R.XMM14, 1 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm14a
      | R.XMM14, 2 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm14b
      | R.XMM15, 1 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm15a
      | R.XMM15, 2 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm15b
      | R.YMM0, 1 -> zmm0a
      | R.YMM0, 2 -> zmm0b
      | R.YMM0, 3 -> zmm0c
      | R.YMM0, 4 -> zmm0d
      | R.YMM1, 1 -> zmm1a
      | R.YMM1, 2 -> zmm1b
      | R.YMM1, 3 -> zmm1c
      | R.YMM1, 4 -> zmm1d
      | R.YMM2, 1 -> zmm2a
      | R.YMM2, 2 -> zmm2b
      | R.YMM2, 3 -> zmm2c
      | R.YMM2, 4 -> zmm2d
      | R.YMM3, 1 -> zmm3a
      | R.YMM3, 2 -> zmm3b
      | R.YMM3, 3 -> zmm3c
      | R.YMM3, 4 -> zmm3d
      | R.YMM4, 1 -> zmm4a
      | R.YMM4, 2 -> zmm4b
      | R.YMM4, 3 -> zmm4c
      | R.YMM4, 4 -> zmm4d
      | R.YMM5, 1 -> zmm5a
      | R.YMM5, 2 -> zmm5b
      | R.YMM5, 3 -> zmm5c
      | R.YMM5, 4 -> zmm5d
      | R.YMM6, 1 -> zmm6a
      | R.YMM6, 2 -> zmm6b
      | R.YMM6, 3 -> zmm6c
      | R.YMM6, 4 -> zmm6d
      | R.YMM7, 1 -> zmm7a
      | R.YMM7, 2 -> zmm7b
      | R.YMM7, 3 -> zmm7c
      | R.YMM7, 4 -> zmm7d
      | R.YMM8, 1 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm8a
      | R.YMM8, 2 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm8b
      | R.YMM8, 3 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm8c
      | R.YMM8, 4 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm8d
      | R.YMM9, 1 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm9a
      | R.YMM9, 2 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm9b
      | R.YMM9, 3 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm9c
      | R.YMM9, 4 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm9d
      | R.YMM10, 1 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm10a
      | R.YMM10, 2 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm10b
      | R.YMM10, 3 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm10c
      | R.YMM10, 4 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm10d
      | R.YMM11, 1 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm11a
      | R.YMM11, 2 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm11b
      | R.YMM11, 3 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm11c
      | R.YMM11, 4 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm11d
      | R.YMM12, 1 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm12a
      | R.YMM12, 2 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm12b
      | R.YMM12, 3 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm12c
      | R.YMM12, 4 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm12d
      | R.YMM13, 1 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm13a
      | R.YMM13, 2 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm13b
      | R.YMM13, 3 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm13c
      | R.YMM13, 4 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm13d
      | R.YMM14, 1 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm14a
      | R.YMM14, 2 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm14b
      | R.YMM14, 3 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm14c
      | R.YMM14, 4 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm14d
      | R.YMM15, 1 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm15a
      | R.YMM15, 2 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm15b
      | R.YMM15, 3 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm15c
      | R.YMM15, 4 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm15d
      | R.ZMM0, 1 -> zmm0a
      | R.ZMM0, 2 -> zmm0b
      | R.ZMM0, 3 -> zmm0c
      | R.ZMM0, 4 -> zmm0d
      | R.ZMM0, 5 -> zmm0e
      | R.ZMM0, 6 -> zmm0f
      | R.ZMM0, 7 -> zmm0g
      | R.ZMM0, 8 -> zmm0h
      | R.ZMM1, 1 -> zmm1a
      | R.ZMM1, 2 -> zmm1b
      | R.ZMM1, 3 -> zmm1c
      | R.ZMM1, 4 -> zmm1d
      | R.ZMM1, 5 -> zmm1e
      | R.ZMM1, 6 -> zmm1f
      | R.ZMM1, 7 -> zmm1g
      | R.ZMM1, 8 -> zmm1h
      | R.ZMM2, 1 -> zmm2a
      | R.ZMM2, 2 -> zmm2b
      | R.ZMM2, 3 -> zmm2c
      | R.ZMM2, 4 -> zmm2d
      | R.ZMM2, 5 -> zmm2e
      | R.ZMM2, 6 -> zmm2f
      | R.ZMM2, 7 -> zmm2g
      | R.ZMM2, 8 -> zmm2h
      | R.ZMM3, 1 -> zmm3a
      | R.ZMM3, 2 -> zmm3b
      | R.ZMM3, 3 -> zmm3c
      | R.ZMM3, 4 -> zmm3d
      | R.ZMM3, 5 -> zmm3e
      | R.ZMM3, 6 -> zmm3f
      | R.ZMM3, 7 -> zmm3g
      | R.ZMM3, 8 -> zmm3h
      | R.ZMM4, 1 -> zmm4a
      | R.ZMM4, 2 -> zmm4b
      | R.ZMM4, 3 -> zmm4c
      | R.ZMM4, 4 -> zmm4d
      | R.ZMM4, 5 -> zmm4e
      | R.ZMM4, 6 -> zmm4f
      | R.ZMM4, 7 -> zmm4g
      | R.ZMM4, 8 -> zmm4h
      | R.ZMM5, 1 -> zmm5a
      | R.ZMM5, 2 -> zmm5b
      | R.ZMM5, 3 -> zmm5c
      | R.ZMM5, 4 -> zmm5d
      | R.ZMM5, 5 -> zmm5e
      | R.ZMM5, 6 -> zmm5f
      | R.ZMM5, 7 -> zmm5g
      | R.ZMM5, 8 -> zmm5h
      | R.ZMM6, 1 -> zmm6a
      | R.ZMM6, 2 -> zmm6b
      | R.ZMM6, 3 -> zmm6c
      | R.ZMM6, 4 -> zmm6d
      | R.ZMM6, 5 -> zmm6e
      | R.ZMM6, 6 -> zmm6f
      | R.ZMM6, 7 -> zmm6g
      | R.ZMM6, 8 -> zmm6h
      | R.ZMM7, 1 -> zmm7a
      | R.ZMM7, 2 -> zmm7b
      | R.ZMM7, 3 -> zmm7c
      | R.ZMM7, 4 -> zmm7d
      | R.ZMM7, 5 -> zmm7e
      | R.ZMM7, 6 -> zmm7f
      | R.ZMM7, 7 -> zmm7g
      | R.ZMM7, 8 -> zmm7h
      | R.ZMM8, 1 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm8a
      | R.ZMM8, 2 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm8b
      | R.ZMM8, 3 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm8c
      | R.ZMM8, 4 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm8d
      | R.ZMM8, 5 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm8e
      | R.ZMM8, 6 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm8f
      | R.ZMM8, 7 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm8g
      | R.ZMM8, 8 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm8h
      | R.ZMM9, 1 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm9a
      | R.ZMM9, 2 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm9b
      | R.ZMM9, 3 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm9c
      | R.ZMM9, 4 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm9d
      | R.ZMM9, 5 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm9e
      | R.ZMM9, 6 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm9f
      | R.ZMM9, 7 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm9g
      | R.ZMM9, 8 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm9h
      | R.ZMM10, 1 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm10a
      | R.ZMM10, 2 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm10b
      | R.ZMM10, 3 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm10c
      | R.ZMM10, 4 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm10d
      | R.ZMM10, 5 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm10e
      | R.ZMM10, 6 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm10f
      | R.ZMM10, 7 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm10g
      | R.ZMM10, 8 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm10h
      | R.ZMM11, 1 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm11a
      | R.ZMM11, 2 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm11b
      | R.ZMM11, 3 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm11c
      | R.ZMM11, 4 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm11d
      | R.ZMM11, 5 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm11e
      | R.ZMM11, 6 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm11f
      | R.ZMM11, 7 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm11g
      | R.ZMM11, 8 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm11h
      | R.ZMM12, 1 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm12a
      | R.ZMM12, 2 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm12b
      | R.ZMM12, 3 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm12c
      | R.ZMM12, 4 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm12d
      | R.ZMM12, 5 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm12e
      | R.ZMM12, 6 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm12f
      | R.ZMM12, 7 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm12g
      | R.ZMM12, 8 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm12h
      | R.ZMM13, 1 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm13a
      | R.ZMM13, 2 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm13b
      | R.ZMM13, 3 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm13c
      | R.ZMM13, 4 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm13d
      | R.ZMM13, 5 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm13e
      | R.ZMM13, 6 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm13f
      | R.ZMM13, 7 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm13g
      | R.ZMM13, 8 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm13h
      | R.ZMM14, 1 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm14a
      | R.ZMM14, 2 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm14b
      | R.ZMM14, 3 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm14c
      | R.ZMM14, 4 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm14d
      | R.ZMM14, 5 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm14e
      | R.ZMM14, 6 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm14f
      | R.ZMM14, 7 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm14g
      | R.ZMM14, 8 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm14h
      | R.ZMM15, 1 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm15a
      | R.ZMM15, 2 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm15b
      | R.ZMM15, 3 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm15c
      | R.ZMM15, 4 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm15d
      | R.ZMM15, 5 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm15e
      | R.ZMM15, 6 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm15f
      | R.ZMM15, 7 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm15g
      | R.ZMM15, 8 ->
#if DEBUG
        assert64Bit wordSize
#endif
        zmm15h
      | R.BND0, 1 -> bnd0a
      | R.BND0, 2 -> bnd0b
      | R.BND1, 1 -> bnd1a
      | R.BND1, 2 -> bnd1b
      | R.BND2, 1 -> bnd2a
      | R.BND2, 2 -> bnd2b
      | R.BND3, 1 -> bnd3a
      | R.BND3, 2 -> bnd3b
      | R.ST0, 1 -> st0a
      | R.ST0, 2 -> st0b
      | R.ST1, 1 -> st1a
      | R.ST1, 2 -> st1b
      | R.ST2, 1 -> st2a
      | R.ST2, 2 -> st2b
      | R.ST3, 1 -> st3a
      | R.ST3, 2 -> st3b
      | R.ST4, 1 -> st4a
      | R.ST4, 2 -> st4b
      | R.ST5, 1 -> st5a
      | R.ST5, 2 -> st5b
      | R.ST6, 1 -> st6a
      | R.ST6, 2 -> st6b
      | R.ST7, 1 -> st7a
      | R.ST7, 2 -> st7b
      | _ -> raise InvalidRegisterException

    member _.GetAllRegVars () =
      if WordSize.is32 wordSize then
        [| eax
           ebx
           ecx
           edx
           esp
           ebp
           esi
           edi
           eip
           csbase
           dsbase
           esbase
           fsbase
           gsbase
           ssbase
           cr0
           cr2
           cr3
           cr4
           oFlag
           dFlag
           iFlag
           tFlag
           sFlag
           zFlag
           aFlag
           pFlag
           cFlag
           fcw
           fsw
           ftw
           fop
           fip
           fcs
           fdp
           fds
           mxcsr
           mxcsrmask
           pkru
           k0
           k1
           k2
           k3
           k4
           k5
           k6
           k7
           st0a
           st0b
           st1a
           st1b
           st2a
           st2b
           st3a
           st3b
           st4a
           st4b
           st5a
           st5b
           st6a
           st6b
           st7a
           st7b
           zmm0a
           zmm0b
           zmm0c
           zmm0d
           zmm0e
           zmm0f
           zmm0g
           zmm0h
           zmm1a
           zmm1b
           zmm1c
           zmm1d
           zmm1e
           zmm1f
           zmm1g
           zmm1h
           zmm2a
           zmm2b
           zmm2c
           zmm2d
           zmm2e
           zmm2f
           zmm2g
           zmm2h
           zmm3a
           zmm3b
           zmm3c
           zmm3d
           zmm3e
           zmm3f
           zmm3g
           zmm3h
           zmm4a
           zmm4b
           zmm4c
           zmm4d
           zmm4e
           zmm4f
           zmm4g
           zmm4h
           zmm5a
           zmm5b
           zmm5c
           zmm5d
           zmm5e
           zmm5f
           zmm5g
           zmm5h
           zmm6a
           zmm6b
           zmm6c
           zmm6d
           zmm6e
           zmm6f
           zmm6g
           zmm6h
           zmm7a
           zmm7b
           zmm7c
           zmm7d
           zmm7e
           zmm7f
           zmm7g
           zmm7h
           cs
           ds
           es
           fs
           gs
           ss
           dr0
           dr1
           dr2
           dr3
           dr6
           dr7 |]
      else
        [| rax
           rbx
           rcx
           rdx
           rsp
           rbp
           rsi
           rdi
           r8
           r9
           r10
           r11
           r12
           r13
           r14
           r15
           rip
           csbase
           dsbase
           esbase
           fsbase
           gsbase
           ssbase
           cr0
           cr2
           cr3
           cr4
           cr8
           oFlag
           dFlag
           iFlag
           tFlag
           sFlag
           zFlag
           aFlag
           pFlag
           cFlag
           fcw
           fsw
           ftw
           fop
           fip
           fcs
           fdp
           fds
           mxcsr
           mxcsrmask
           pkru
           k0
           k1
           k2
           k3
           k4
           k5
           k6
           k7
           st0a
           st0b
           st1a
           st1b
           st2a
           st2b
           st3a
           st3b
           st4a
           st4b
           st5a
           st5b
           st6a
           st6b
           st7a
           st7b
           zmm0a
           zmm0b
           zmm0c
           zmm0d
           zmm0e
           zmm0f
           zmm0g
           zmm0h
           zmm1a
           zmm1b
           zmm1c
           zmm1d
           zmm1e
           zmm1f
           zmm1g
           zmm1h
           zmm2a
           zmm2b
           zmm2c
           zmm2d
           zmm2e
           zmm2f
           zmm2g
           zmm2h
           zmm3a
           zmm3b
           zmm3c
           zmm3d
           zmm3e
           zmm3f
           zmm3g
           zmm3h
           zmm4a
           zmm4b
           zmm4c
           zmm4d
           zmm4e
           zmm4f
           zmm4g
           zmm4h
           zmm5a
           zmm5b
           zmm5c
           zmm5d
           zmm5e
           zmm5f
           zmm5g
           zmm5h
           zmm6a
           zmm6b
           zmm6c
           zmm6d
           zmm6e
           zmm6f
           zmm6g
           zmm6h
           zmm7a
           zmm7b
           zmm7c
           zmm7d
           zmm7e
           zmm7f
           zmm7g
           zmm7h
           zmm8a
           zmm8b
           zmm8c
           zmm8d
           zmm8e
           zmm8f
           zmm8g
           zmm8h
           zmm9a
           zmm9b
           zmm9c
           zmm9d
           zmm9e
           zmm9f
           zmm9g
           zmm9h
           zmm10a
           zmm10b
           zmm10c
           zmm10d
           zmm10e
           zmm10f
           zmm10g
           zmm10h
           zmm11a
           zmm11b
           zmm11c
           zmm11d
           zmm11e
           zmm11f
           zmm11g
           zmm11h
           zmm12a
           zmm12b
           zmm12c
           zmm12d
           zmm12e
           zmm12f
           zmm12g
           zmm12h
           zmm13a
           zmm13b
           zmm13c
           zmm13d
           zmm13e
           zmm13f
           zmm13g
           zmm13h
           zmm14a
           zmm14b
           zmm14c
           zmm14d
           zmm14e
           zmm14f
           zmm14g
           zmm14h
           zmm15a
           zmm15b
           zmm15c
           zmm15d
           zmm15e
           zmm15f
           zmm15g
           zmm15h
           cs
           ds
           es
           fs
           gs
           ss
           dr0
           dr1
           dr2
           dr3
           dr6
           dr7 |]

    member _.GetGeneralRegVars () =
      if WordSize.is32 wordSize then
        [| eax
           ebx
           ecx
           edx
           esp
           ebp
           esi
           edi
           eip
           oFlag
           dFlag
           iFlag
           sFlag
           zFlag
           aFlag
           pFlag
           cFlag |]
      else
        [| rax
           rbx
           rcx
           rdx
           rsp
           rbp
           rsi
           rdi
           r8
           r9
           r10
           r11
           r12
           r13
           r14
           r15
           rip
           oFlag
           dFlag
           iFlag
           sFlag
           zFlag
           aFlag
           pFlag
           cFlag |]

    member _.GetRegisterID expr =
      match expr with
      | Var (_,id, _, _) -> id
      | PCVar (regT, _, _) ->
        if regT = 32<rt> then Register.toRegID EIP
        else Register.toRegID RIP
      | _ -> raise InvalidRegisterException

    member _.GetRegisterID name =
      Register.ofString name |> Register.toRegID

    member _.GetRegisterIDAliases rid =
      Register.ofRegID rid
      |> Register.getAliases
      |> Array.map Register.toRegID

    member _.GetRegString rid =
      Register.ofRegID rid |> Register.toString

    member this.GetAllRegStrings () =
      let regFactory = this :> IRegisterFactory
      regFactory.GetAllRegVars ()
      |> Array.map (regFactory.GetRegisterID >> regFactory.GetRegString)

    member _.GetRegType rid =
      Register.ofRegID rid |> Register.toRegType wordSize

    member _.ProgramCounter =
      if WordSize.is32 wordSize then EIP |> Register.toRegID
      else RIP |> Register.toRegID

    member _.StackPointer =
      if WordSize.is32 wordSize then ESP |> Register.toRegID
      else RSP |> Register.toRegID
      |> Some

    member _.FramePointer =
      if WordSize.is32 wordSize then EBP |> Register.toRegID
      else RBP |> Register.toRegID
      |> Some

    member this.IsProgramCounter regid =
      (this :> IRegisterFactory).ProgramCounter = regid

    member this.IsStackPointer regid =
      (this :> IRegisterFactory).StackPointer |> Option.get = regid

    member this.IsFramePointer regid =
      (this :> IRegisterFactory).FramePointer |> Option.get = regid
