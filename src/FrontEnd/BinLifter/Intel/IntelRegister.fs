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

namespace B2R2.FrontEnd.BinLifter.Intel

open System.Runtime.CompilerServices
open B2R2
open B2R2.FrontEnd

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.BinLifter.Tests")>]
do ()

/// This exception occurs when an UnknownReg is explicitly used. This exception
/// should not happen in general.
exception UnknownRegException

/// Shortcut for Register type.
type internal R = Register.Intel

/// This module exposes several useful functions to handle Intel registers.
[<RequireQualifiedAccess>]
module Register = begin
  /// Intel register kind, which is based on their usage.
  type Kind =
    /// General purpose registers.
    | GP = 0x0
    /// Floating-point registers.
    | FPU = 0x1
    /// MMX registers.
    | MMX = 0x2
    /// XMM registers.
    | XMM = 0x3
    /// YMM registers.
    | YMM = 0x4
    /// ZMM registers.
    | ZMM = 0x5
    /// Segment registers.
    | Segment = 0x6
    /// Registers represeting a segment base.
    | SegBase = 0x7
    /// Control registers.
    | Control = 0x8
    /// Debug registers.
    | Debug = 0x9
    /// Bound registers.
    | Bound = 0xA
    /// Flags registers.
    | Flags = 0xB
    /// Unclassified registers.
    | Unclassified = 0xC
    /// PseudoRegisters are the ones that we create to ease handling AVX
    /// registers and operations. Each AVX register is divided into a series of
    /// 64-bit pseudoregisters, and we name each pseudoregister using a suffix
    /// character from 'A' to 'H'. For example, XMM0A refers to the first 64-bit
    /// chunk of XMM0.
    | PseudoRegister = 0xD
    /// OpMask registers of EVEX.
    | OpMaskRegister = 0xE

  let getKind (reg: Register.Intel): Kind =
    let regNum = int reg
    if regNum <= 0x45 then Kind.GP
    elif regNum <= 0x64 then Kind.FPU
    elif regNum <= 0x6c then Kind.MMX
    elif regNum <= 0x7c then Kind.XMM
    elif regNum <= 0x8c then Kind.YMM
    elif regNum <= 0x9c then Kind.ZMM
    elif regNum <= 0xa2 then Kind.Segment
    elif regNum <= 0xa8 then Kind.SegBase
    elif regNum <= 0xad then Kind.Control
    elif regNum <= 0xb3 then Kind.Debug
    elif regNum <= 0xb7 then Kind.Bound
    elif regNum <= 0xc0 then Kind.Flags
    elif regNum <= 0xc1 then Kind.Unclassified
    elif regNum <= 0x159 then Kind.PseudoRegister
    elif regNum <= 0x161 then Kind.OpMaskRegister
    else Kind.Unclassified

  /// Get the ST(n) register from the given index.
  let streg n =
    0x46 + n
    |> LanguagePrimitives.EnumOfValue<int, Register.Intel>

  /// Get the MM(n) register from the given index.
  let mm n =
    0x65 + n
    |> LanguagePrimitives.EnumOfValue<int, Register.Intel>

  /// Get the XMM(n) register from the given index.
  let xmm n =
    0x6d + n
    |> LanguagePrimitives.EnumOfValue<int, Register.Intel>

  /// Get the YMM(n) register from the given index.
  let ymm n =
    0x7d + n
    |> LanguagePrimitives.EnumOfValue<int, Register.Intel>

  /// Get the ZMM(n) register from the given index.
  let zmm n =
    0x8d + n
    |> LanguagePrimitives.EnumOfValue<int, Register.Intel>

  /// Get the segment register of the given index.
  let seg n =
    0x9d + n
    |> LanguagePrimitives.EnumOfValue<int, Register.Intel>

  /// Get the bound register of the given index.
  let bound n =
    0xb4 + n
    |> LanguagePrimitives.EnumOfValue<int, Register.Intel>

  /// Get the control register of the given index.
  let control n =
    0xa9 + n
    |> LanguagePrimitives.EnumOfValue<int, Register.Intel>

  /// Get the debug register of the given index.
  let debug n =
    0xae + n
    |> LanguagePrimitives.EnumOfValue<int, Register.Intel>

  /// Get the OpMask register of the given index.
  let opmask n =
    0x15A + n
    |> LanguagePrimitives.EnumOfValue<int, Register.Intel>

  let toRegType wordSize = function
    | R.MM0 | R.MM1 | R.MM2 | R.MM3 | R.MM4 | R.MM5 | R.MM6 | R.MM7
    | R.ST0A | R.ST1A | R.ST2A | R.ST3A | R.ST4A | R.ST5A | R.ST6A | R.ST7A
    | R.RIP | R.R8 | R.R9 | R.R10 | R.R11 | R.R12 | R.R13 | R.R14 | R.R15
    | R.RAX | R.RBX | R.RCX | R.RDX | R.RSP | R.RBP | R.RSI | R.RDI
    | R.ZMM0A | R.ZMM1A | R.ZMM2A | R.ZMM3A
    | R.ZMM4A | R.ZMM5A | R.ZMM6A | R.ZMM7A
    | R.ZMM8A | R.ZMM9A | R.ZMM10A | R.ZMM11A
    | R.ZMM12A | R.ZMM13A | R.ZMM14A | R.ZMM15A
    | R.ZMM0B | R.ZMM1B | R.ZMM2B | R.ZMM3B
    | R.ZMM4B | R.ZMM5B | R.ZMM6B | R.ZMM7B
    | R.ZMM8B | R.ZMM9B | R.ZMM10B | R.ZMM11B
    | R.ZMM12B | R.ZMM13B | R.ZMM14B | R.ZMM15B
    | R.ZMM0C | R.ZMM1C | R.ZMM2C | R.ZMM3C
    | R.ZMM4C | R.ZMM5C | R.ZMM6C | R.ZMM7C
    | R.ZMM8C | R.ZMM9C | R.ZMM10C | R.ZMM11C
    | R.ZMM12C | R.ZMM13C | R.ZMM14C | R.ZMM15C
    | R.ZMM0D | R.ZMM1D | R.ZMM2D | R.ZMM3D
    | R.ZMM4D | R.ZMM5D | R.ZMM6D | R.ZMM7D
    | R.ZMM8D | R.ZMM9D | R.ZMM10D | R.ZMM11D
    | R.ZMM12D | R.ZMM13D | R.ZMM14D | R.ZMM15D
    | R.ZMM0E | R.ZMM1E | R.ZMM2E | R.ZMM3E
    | R.ZMM4E | R.ZMM5E | R.ZMM6E | R.ZMM7E
    | R.ZMM8E | R.ZMM9E | R.ZMM10E | R.ZMM11E
    | R.ZMM12E | R.ZMM13E | R.ZMM14E | R.ZMM15E
    | R.ZMM0F | R.ZMM1F | R.ZMM2F | R.ZMM3F
    | R.ZMM4F | R.ZMM5F | R.ZMM6F | R.ZMM7F
    | R.ZMM8F | R.ZMM9F | R.ZMM10F | R.ZMM11F
    | R.ZMM12F | R.ZMM13F | R.ZMM14F | R.ZMM15F
    | R.ZMM0G | R.ZMM1G | R.ZMM2G | R.ZMM3G
    | R.ZMM4G | R.ZMM5G | R.ZMM6G | R.ZMM7G
    | R.ZMM8G | R.ZMM9G | R.ZMM10G | R.ZMM11G
    | R.ZMM12G | R.ZMM13G | R.ZMM14G | R.ZMM15G
    | R.ZMM0H | R.ZMM1H | R.ZMM2H | R.ZMM3H
    | R.ZMM4H | R.ZMM5H | R.ZMM6H | R.ZMM7H
    | R.ZMM8H | R.ZMM9H | R.ZMM10H | R.ZMM11H
    | R.ZMM12H | R.ZMM13H | R.ZMM14H | R.ZMM15H
    | R.FIP | R.FDP -> 64<rt>
    | R.R8D | R.R9D | R.R10D | R.R11D
    | R.R12D | R.R13D | R.R14D | R.R15D
    | R.EAX | R.EBX | R.ECX | R.EDX
    | R.ESP | R.EBP | R.ESI | R.EDI | R.EIP | R.PKRU
    | R.MXCSR | R.MXCSRMASK -> 32<rt>
    | R.R8W | R.R9W | R.R10W | R.R11W
    | R.R12W | R.R13W | R.R14W | R.R15W
    | R.ST0B | R.ST1B | R.ST2B | R.ST3B | R.ST4B | R.ST5B | R.ST6B | R.ST7B
    | R.ES | R.CS | R.SS | R.DS | R.FS | R.GS
    | R.AX | R.BX | R.CX | R.DX | R.SP | R.BP | R.SI | R.DI
    | R.FCW | R.FSW | R.FTW | R.FOP | R.FCS | R.FDS
    | R.K0 | R.K1 | R.K2 | R.K3 | R.K4 | R.K5 | R.K6 | R.K7 -> 16<rt>
    | R.R8B | R.R9B | R.R10B | R.R11B
    | R.R12B | R.R13B | R.R14B | R.R15B
    | R.SPL | R.BPL | R.SIL | R.DIL
    | R.AL | R.BL | R.CL | R.DL | R.AH | R.BH | R.CH | R.DH -> 8<rt>
    | R.XMM0 | R.XMM1 | R.XMM2 | R.XMM3
    | R.XMM4 | R.XMM5 | R.XMM6 | R.XMM7
    | R.XMM8 | R.XMM9 | R.XMM10 | R.XMM11
    | R.XMM12 | R.XMM13 | R.XMM14 | R.XMM15
    | R.BND0 | R.BND1 | R.BND2 | R.BND3 -> 128<rt>
    | R.YMM0 | R.YMM1 | R.YMM2 | R.YMM3
    | R.YMM4 | R.YMM5 | R.YMM6 | R.YMM7
    | R.YMM8 | R.YMM9 | R.YMM10 | R.YMM11
    | R.YMM12 | R.YMM13 | R.YMM14 | R.YMM15 -> 256<rt>
    | R.ZMM0 | R.ZMM1 | R.ZMM2 | R.ZMM3
    | R.ZMM4 | R.ZMM5 | R.ZMM6 | R.ZMM7
    | R.ZMM8 | R.ZMM9 | R.ZMM10 | R.ZMM11
    | R.ZMM12 | R.ZMM13 | R.ZMM14 | R.ZMM15 -> 512<rt>
    | R.ST0 | R.ST1 | R.ST2 | R.ST3 | R.ST4 | R.ST5 | R.ST6 | R.ST7 -> 80<rt>
    | R.DF | R.CF | R.PF | R.AF | R.ZF | R.SF | R.OF | R.IF
    | R.FSWC0 | R.FSWC1 | R.FSWC2 | R.FSWC3 -> 1<rt>
    | R.FTW0 | R.FTW1 | R.FTW2 | R.FTW3
    | R.FTW4 | R.FTW5 | R.FTW6 | R.FTW7
    | R.FTOP -> 8<rt>
    | R.FSBase | R.GSBase -> WordSize.toRegType wordSize
    | _ -> raise UnknownRegException

  let extendRegister32 = function
    | R.EAX | R.AX | R.AL | R.AH -> R.EAX
    | R.EBX | R.BX | R.BL | R.BH -> R.EBX
    | R.ECX | R.CX | R.CL | R.CH -> R.ECX
    | R.EDX | R.DX | R.DL | R.DH -> R.EDX
    | R.ESP | R.SP | R.SPL -> R.ESP
    | R.EBP | R.BP | R.BPL -> R.EBP
    | R.ESI | R.SI | R.SIL -> R.ESI
    | R.EDI | R.DI | R.DIL -> R.EDI
    | R.XMM0 | R.YMM0 | R.ZMM0 -> R.YMM0
    | R.XMM1 | R.YMM1 | R.ZMM1 -> R.YMM1
    | R.XMM2 | R.YMM2 | R.ZMM2 -> R.YMM2
    | R.XMM3 | R.YMM3 | R.ZMM3 -> R.YMM3
    | R.XMM4 | R.YMM4 | R.ZMM4 -> R.YMM4
    | R.XMM5 | R.YMM5 | R.ZMM5 -> R.YMM5
    | R.XMM6 | R.YMM6 | R.ZMM6 -> R.YMM6
    | R.XMM7 | R.YMM7 | R.ZMM7 -> R.YMM7
    | R.DF | R.CF | R.PF | R.AF | R.ZF | R.SF | R.OF
    | R.BND0 | R.BND1 | R.BND2 | R.BND3 as e -> e
    | R.ESBase | R.ES -> R.ESBase
    | R.CSBase | R.CS -> R.CSBase
    | R.SSBase | R.SS -> R.SSBase
    | R.DSBase | R.DS -> R.DSBase
    | R.FSBase | R.FS -> R.FSBase
    | R.GSBase | R.GS -> R.GSBase
    | R.EIP -> R.EIP
    | e -> e

  let extendRegister64 = function
    | R.RAX | R.EAX | R.AX | R.AL | R.AH -> R.RAX
    | R.RBX | R.EBX | R.BX | R.BL | R.BH -> R.RBX
    | R.RCX | R.ECX | R.CX | R.CL | R.CH -> R.RCX
    | R.RDX | R.EDX | R.DX | R.DL | R.DH -> R.RDX
    | R.RSP | R.ESP | R.SP | R.SPL -> R.RSP
    | R.RBP | R.EBP | R.BP | R.BPL -> R.RBP
    | R.RSI | R.ESI | R.SI | R.SIL -> R.RSI
    | R.RDI | R.EDI | R.DI | R.DIL-> R.RDI
    | R.R8  | R.R8D | R.R8B | R.R8W -> R.R8
    | R.R9  | R.R9D | R.R9B | R.R9W -> R.R9
    | R.R10 | R.R10D | R.R10B | R.R10W -> R.R10
    | R.R11 | R.R11D | R.R11B | R.R11W -> R.R11
    | R.R12 | R.R12D | R.R12B | R.R12W -> R.R12
    | R.R13 | R.R13D | R.R13B | R.R13W -> R.R13
    | R.R14 | R.R14D | R.R14B | R.R14W -> R.R14
    | R.R15 | R.R15D | R.R15B | R.R15W -> R.R15
    | R.XMM0 | R.YMM0 | R.ZMM0 -> R.YMM0
    | R.XMM1 | R.YMM1 | R.ZMM1 -> R.YMM1
    | R.XMM2 | R.YMM2 | R.ZMM2 -> R.YMM2
    | R.XMM3 | R.YMM3 | R.ZMM3 -> R.YMM3
    | R.XMM4 | R.YMM4 | R.ZMM4 -> R.YMM4
    | R.XMM5 | R.YMM5 | R.ZMM5 -> R.YMM5
    | R.XMM6 | R.YMM6 | R.ZMM6 -> R.YMM6
    | R.XMM7 | R.YMM7 | R.ZMM7 -> R.YMM7
    | R.XMM8 | R.YMM8 | R.ZMM8 -> R.YMM8
    | R.XMM9 | R.YMM9 | R.ZMM9 -> R.YMM9
    | R.XMM10 | R.YMM10 | R.ZMM10 -> R.YMM10
    | R.XMM11 | R.YMM11 | R.ZMM11 -> R.YMM11
    | R.XMM12 | R.YMM12 | R.ZMM12 -> R.YMM12
    | R.XMM13 | R.YMM13 | R.ZMM13 -> R.YMM13
    | R.XMM14 | R.YMM14 | R.ZMM14 -> R.YMM14
    | R.XMM15 | R.YMM15 | R.ZMM15 -> R.YMM15
    | R.DF | R.CF | R.PF | R.AF | R.ZF | R.SF | R.OF
    | R.BND0 | R.BND1 | R.BND2 | R.BND3 as e -> e
    | R.ESBase | R.ES -> R.ESBase
    | R.CSBase | R.CS -> R.CSBase
    | R.SSBase | R.SS -> R.SSBase
    | R.DSBase | R.DS -> R.DSBase
    | R.FSBase | R.FS -> R.FSBase
    | R.GSBase | R.GS -> R.GSBase
    | R.RIP | R.EIP -> R.RIP
    | e -> e

  let getAliases = function
    | R.RAX | R.EAX | R.AX | R.AL | R.AH -> [| R.RAX; R.EAX; R.AX; R.AL; R.AH |]
    | R.RBX | R.EBX | R.BX | R.BL | R.BH -> [| R.RBX; R.EBX; R.BX; R.BL; R.BH |]
    | R.RCX | R.ECX | R.CX | R.CL | R.CH -> [| R.RCX; R.ECX; R.CX; R.CL; R.CH |]
    | R.RDX | R.EDX | R.DX | R.DL | R.DH -> [| R.RDX; R.EDX; R.DX; R.DL; R.DH |]
    | R.RSP | R.ESP | R.SP | R.SPL -> [| R.RSP; R.ESP; R.SP; R.SPL |]
    | R.RBP | R.EBP | R.BP | R.BPL -> [| R.RBP; R.EBP; R.BP; R.BPL |]
    | R.RSI | R.ESI | R.SI | R.SIL -> [| R.RSI; R.ESI; R.SI; R.SIL |]
    | R.RDI | R.EDI | R.DI | R.DIL -> [| R.RDI; R.EDI; R.DI; R.DIL |]
    | R.R8  | R.R8D | R.R8B | R.R8W -> [| R.R8; R.R8D; R.R8B; R.R8W |]
    | R.R9  | R.R9D | R.R9B | R.R9W -> [| R.R9; R.R9D; R.R9B; R.R9W |]
    | R.R10  | R.R10D | R.R10B | R.R10W -> [| R.R10; R.R10D; R.R10B; R.R10W |]
    | R.R11  | R.R11D | R.R11B | R.R11W -> [| R.R11; R.R11D; R.R11B; R.R11W |]
    | R.R12  | R.R12D | R.R12B | R.R12W -> [| R.R12; R.R12D; R.R12B; R.R12W |]
    | R.R13  | R.R13D | R.R13B | R.R13W -> [| R.R13; R.R13D; R.R13B; R.R13W |]
    | R.R14  | R.R14D | R.R14B | R.R14W -> [| R.R14; R.R14D; R.R14B; R.R14W |]
    | R.R15  | R.R15D | R.R15B | R.R15W -> [| R.R15; R.R15D; R.R15B; R.R15W |]
    | R.XMM0 | R.YMM0 | R.ZMM0 -> [| R.XMM0; R.YMM0; R.ZMM0 |]
    | R.XMM1 | R.YMM1 | R.ZMM1 -> [| R.XMM1; R.YMM1; R.ZMM1 |]
    | R.XMM2 | R.YMM2 | R.ZMM2 -> [| R.XMM2; R.YMM2; R.ZMM2 |]
    | R.XMM3 | R.YMM3 | R.ZMM3 -> [| R.XMM3; R.YMM3; R.ZMM3 |]
    | R.XMM4 | R.YMM4 | R.ZMM4 -> [| R.XMM4; R.YMM4; R.ZMM4 |]
    | R.XMM5 | R.YMM5 | R.ZMM5 -> [| R.XMM5; R.YMM5; R.ZMM5 |]
    | R.XMM6 | R.YMM6 | R.ZMM6 -> [| R.XMM6; R.YMM6; R.ZMM6 |]
    | R.XMM7 | R.YMM7 | R.ZMM7 -> [| R.XMM7; R.YMM7; R.ZMM7 |]
    | R.XMM8 | R.YMM8 | R.ZMM8 -> [| R.XMM8; R.YMM8; R.ZMM8 |]
    | R.XMM9 | R.YMM9 | R.ZMM9 -> [| R.XMM9; R.YMM9; R.ZMM9 |]
    | R.XMM10 | R.YMM10 | R.ZMM10 -> [| R.XMM10; R.YMM10; R.ZMM10 |]
    | R.XMM11 | R.YMM11 | R.ZMM11 -> [| R.XMM11; R.YMM11; R.ZMM11 |]
    | R.XMM12 | R.YMM12 | R.ZMM12 -> [| R.XMM12; R.YMM12; R.ZMM12 |]
    | R.XMM13 | R.YMM13 | R.ZMM13 -> [| R.XMM13; R.YMM13; R.ZMM13 |]
    | R.XMM14 | R.YMM14 | R.ZMM14 -> [| R.XMM14; R.YMM14; R.ZMM14 |]
    | R.XMM15 | R.YMM15 | R.ZMM15 -> [| R.XMM15; R.YMM15; R.ZMM15 |]
    | R.EIP | R.RIP -> [| R.EIP; R.RIP |]
    | r -> [| r |]

  let regToPseudoReg = function
    | R.XMM0  -> [ R.ZMM0B; R.ZMM0A ]
    | R.XMM1  -> [ R.ZMM1B; R.ZMM1A ]
    | R.XMM2  -> [ R.ZMM2B; R.ZMM2A ]
    | R.XMM3  -> [ R.ZMM3B; R.ZMM3A ]
    | R.XMM4  -> [ R.ZMM4B; R.ZMM4A ]
    | R.XMM5  -> [ R.ZMM5B; R.ZMM5A ]
    | R.XMM6  -> [ R.ZMM6B; R.ZMM6A ]
    | R.XMM7  -> [ R.ZMM7B; R.ZMM7A ]
    | R.XMM8  -> [ R.ZMM8B; R.ZMM8A ]
    | R.XMM9  -> [ R.ZMM9B; R.ZMM9A ]
    | R.XMM10 -> [ R.ZMM10B; R.ZMM10A ]
    | R.XMM11 -> [ R.ZMM11B; R.ZMM11A ]
    | R.XMM12 -> [ R.ZMM12B; R.ZMM12A ]
    | R.XMM13 -> [ R.ZMM13B; R.ZMM13A ]
    | R.XMM14 -> [ R.ZMM14B; R.ZMM14A ]
    | R.XMM15 -> [ R.ZMM15B; R.ZMM15A ]
    | R.YMM0  -> [ R.ZMM0D; R.ZMM0C; R.ZMM0B; R.ZMM0A ]
    | R.YMM1  -> [ R.ZMM1D; R.ZMM1C; R.ZMM1B; R.ZMM1A ]
    | R.YMM2  -> [ R.ZMM2D; R.ZMM2C; R.ZMM2B; R.ZMM2A ]
    | R.YMM3  -> [ R.ZMM3D; R.ZMM3C; R.ZMM3B; R.ZMM3A ]
    | R.YMM4  -> [ R.ZMM4D; R.ZMM4C; R.ZMM4B; R.ZMM4A ]
    | R.YMM5  -> [ R.ZMM5D; R.ZMM5C; R.ZMM5B; R.ZMM5A ]
    | R.YMM6  -> [ R.ZMM6D; R.ZMM6C; R.ZMM6B; R.ZMM6A ]
    | R.YMM7  -> [ R.ZMM7D; R.ZMM7C; R.ZMM7B; R.ZMM7A ]
    | R.YMM8  -> [ R.ZMM8D; R.ZMM8C; R.ZMM8B; R.ZMM8A ]
    | R.YMM9  -> [ R.ZMM9D; R.ZMM9C; R.ZMM9B; R.ZMM9A ]
    | R.YMM10 -> [ R.ZMM10D; R.ZMM10C; R.ZMM10B; R.ZMM10A ]
    | R.YMM11 -> [ R.ZMM11D; R.ZMM11C; R.ZMM11B; R.ZMM11A ]
    | R.YMM12 -> [ R.ZMM12D; R.ZMM12C; R.ZMM12B; R.ZMM12A ]
    | R.YMM13 -> [ R.ZMM13D; R.ZMM13C; R.ZMM13B; R.ZMM13A ]
    | R.YMM14 -> [ R.ZMM14D; R.ZMM14C; R.ZMM14B; R.ZMM14A ]
    | R.YMM15 -> [ R.ZMM15D; R.ZMM15C; R.ZMM15B; R.ZMM15A ]
    | R.ST0 -> [ R.ST0B; R.ST0A ]
    | R.ST1 -> [ R.ST1B; R.ST1A ]
    | R.ST2 -> [ R.ST2B; R.ST2A ]
    | R.ST3 -> [ R.ST3B; R.ST3A ]
    | R.ST4 -> [ R.ST4B; R.ST4A ]
    | R.ST5 -> [ R.ST5B; R.ST5A ]
    | R.ST6 -> [ R.ST6B; R.ST6A ]
    | R.ST7 -> [ R.ST7B; R.ST7A ]
    | R.MM0 -> [ R.ST0A ]
    | R.MM1 -> [ R.ST1A ]
    | R.MM2 -> [ R.ST2A ]
    | R.MM3 -> [ R.ST3A ]
    | R.MM4 -> [ R.ST4A ]
    | R.MM5 -> [ R.ST5A ]
    | R.MM6 -> [ R.ST6A ]
    | R.MM7 -> [ R.ST7A ]
    | e -> failwithf "Unhandled register: %A" e

  let pseudoRegToReg = function
    | R.ZMM0A
    | R.ZMM0B
    | R.ZMM0C
    | R.ZMM0D
    | R.ZMM0E
    | R.ZMM0F
    | R.ZMM0G
    | R.ZMM0H -> R.ZMM0
    | R.ZMM1A
    | R.ZMM1B
    | R.ZMM1C
    | R.ZMM1D
    | R.ZMM1E
    | R.ZMM1F
    | R.ZMM1G
    | R.ZMM1H -> R.ZMM1
    | R.ZMM2A
    | R.ZMM2B
    | R.ZMM2C
    | R.ZMM2D
    | R.ZMM2E
    | R.ZMM2F
    | R.ZMM2G
    | R.ZMM2H -> R.ZMM2
    | R.ZMM3A
    | R.ZMM3B
    | R.ZMM3C
    | R.ZMM3D
    | R.ZMM3E
    | R.ZMM3F
    | R.ZMM3G
    | R.ZMM3H -> R.ZMM3
    | R.ZMM4A
    | R.ZMM4B
    | R.ZMM4C
    | R.ZMM4D
    | R.ZMM4E
    | R.ZMM4F
    | R.ZMM4G
    | R.ZMM4H -> R.ZMM4
    | R.ZMM5A
    | R.ZMM5B
    | R.ZMM5C
    | R.ZMM5D
    | R.ZMM5E
    | R.ZMM5F
    | R.ZMM5G
    | R.ZMM5H -> R.ZMM5
    | R.ZMM6A
    | R.ZMM6B
    | R.ZMM6C
    | R.ZMM6D
    | R.ZMM6E
    | R.ZMM6F
    | R.ZMM6G
    | R.ZMM6H -> R.ZMM6
    | R.ZMM7A
    | R.ZMM7B
    | R.ZMM7C
    | R.ZMM7D
    | R.ZMM7E
    | R.ZMM7F
    | R.ZMM7G
    | R.ZMM7H -> R.ZMM7
    | R.ZMM8A
    | R.ZMM8B
    | R.ZMM8C
    | R.ZMM8D
    | R.ZMM8E
    | R.ZMM8F
    | R.ZMM8G
    | R.ZMM8H -> R.ZMM8
    | R.ZMM9A
    | R.ZMM9B
    | R.ZMM9C
    | R.ZMM9D
    | R.ZMM9E
    | R.ZMM9F
    | R.ZMM9G
    | R.ZMM9H -> R.ZMM9
    | R.ZMM10A
    | R.ZMM10B
    | R.ZMM10C
    | R.ZMM10D
    | R.ZMM10E
    | R.ZMM10F
    | R.ZMM10G
    | R.ZMM10H -> R.ZMM10
    | R.ZMM11A
    | R.ZMM11B
    | R.ZMM11C
    | R.ZMM11D
    | R.ZMM11E
    | R.ZMM11F
    | R.ZMM11G
    | R.ZMM11H -> R.ZMM11
    | R.ZMM12A
    | R.ZMM12B
    | R.ZMM12C
    | R.ZMM12D
    | R.ZMM12E
    | R.ZMM12F
    | R.ZMM12G
    | R.ZMM12H -> R.ZMM12
    | R.ZMM13A
    | R.ZMM13B
    | R.ZMM13C
    | R.ZMM13D
    | R.ZMM13E
    | R.ZMM13F
    | R.ZMM13G
    | R.ZMM13H -> R.ZMM13
    | R.ZMM14A
    | R.ZMM14B
    | R.ZMM14C
    | R.ZMM14D
    | R.ZMM14E
    | R.ZMM14F
    | R.ZMM14G
    | R.ZMM14H -> R.ZMM14
    | R.ZMM15A
    | R.ZMM15B
    | R.ZMM15C
    | R.ZMM15D
    | R.ZMM15E
    | R.ZMM15F
    | R.ZMM15G
    | R.ZMM15H -> R.ZMM15
    | R.ST0A | R.ST0B -> R.ST0
    | R.ST1A | R.ST1B -> R.ST1
    | R.ST2A | R.ST2B -> R.ST2
    | R.ST3A | R.ST3B -> R.ST3
    | R.ST4A | R.ST4B -> R.ST4
    | R.ST5A | R.ST5B -> R.ST5
    | R.ST6A | R.ST6B -> R.ST6
    | R.ST7A | R.ST7B -> R.ST7
    | e -> failwithf "Unhandled register: %A" e
end

/// This module defines sets of registers that are frequently grouped by Intel.
/// Table 3-1. Register Codes Associated With +rb, +rw, +rd, +ro
module internal RegGroup = begin
  /// Grp 0.
  let grpEAX = function
    | 64<rt> -> R.RAX
    | 32<rt> -> R.EAX
    | 16<rt> -> R.AX
    | 8<rt> -> R.AL
    | 128<rt> -> R.XMM0
    | 256<rt> -> R.YMM0
    | 512<rt> -> R.ZMM0
    | _ -> Utils.impossible ()

  /// Grp 1.
  let grpECX = function
    | 64<rt> -> R.RCX
    | 32<rt> -> R.ECX
    | 16<rt> -> R.CX
    | 8<rt> -> R.CL
    | 128<rt> -> R.XMM1
    | 256<rt> -> R.YMM1
    | 512<rt> -> R.ZMM1
    | _ -> Utils.impossible ()

  /// Grp 2.
  let grpEDX = function
    | 64<rt> -> R.RDX
    | 32<rt> -> R.EDX
    | 16<rt> -> R.DX
    | 8<rt> -> R.DL
    | 128<rt> -> R.XMM2
    | 256<rt> -> R.YMM2
    | 512<rt> -> R.ZMM2
    | _ -> Utils.impossible ()

  /// Grp 3.
  let grpEBX = function
    | 64<rt> -> R.RBX
    | 32<rt> -> R.EBX
    | 16<rt> -> R.BX
    | 8<rt> -> R.BL
    | 128<rt> -> R.XMM3
    | 256<rt> -> R.YMM3
    | 512<rt> -> R.ZMM3
    | _ -> Utils.impossible ()
end
