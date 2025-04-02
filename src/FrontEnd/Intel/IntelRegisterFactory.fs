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
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR
open type Register

type IntelRegisterFactory (wordSize, r: RegExprs) =
  inherit RegisterFactory ()

  override __.GetAllRegExprs () =
    if WordSize.is32 wordSize then
      [ r.EAX; r.EBX; r.ECX; r.EDX; r.ESP; r.EBP; r.ESI; r.EDI; r.EIP; r.CSBase;
        r.DSBase; r.ESBase; r.FSBase; r.GSBase; r.SSBase; r.CR0; r.CR2; r.CR3;
        r.CR4; r.OF; r.DF; r.IF; r.TF; r.SF; r.ZF; r.AF; r.PF; r.CF; r.FCW;
        r.FSW; r.FTW; r.FOP; r.FIP; r.FCS; r.FDP; r.FDS; r.MXCSR; r.MXCSRMASK;
        r.PKRU; r.K0; r.K1; r.K2; r.K3; r.K4; r.K5; r.K6; r.K7; r.ST0A; r.ST0B;
        r.ST1A; r.ST1B; r.ST2A; r.ST2B; r.ST3A; r.ST3B; r.ST4A; r.ST4B; r.ST5A;
        r.ST5B; r.ST6A; r.ST6B; r.ST7A; r.ST7B; r.ZMM0A; r.ZMM0B; r.ZMM0C;
        r.ZMM0D; r.ZMM0E; r.ZMM0F; r.ZMM0G; r.ZMM0H; r.ZMM1A; r.ZMM1B; r.ZMM1C;
        r.ZMM1D; r.ZMM1E; r.ZMM1F; r.ZMM1G; r.ZMM1H; r.ZMM2A; r.ZMM2B; r.ZMM2C;
        r.ZMM2D; r.ZMM2E; r.ZMM2F; r.ZMM2G; r.ZMM2H; r.ZMM3A; r.ZMM3B; r.ZMM3C;
        r.ZMM3D; r.ZMM3E; r.ZMM3F; r.ZMM3G; r.ZMM3H; r.ZMM4A; r.ZMM4B; r.ZMM4C;
        r.ZMM4D; r.ZMM4E; r.ZMM4F; r.ZMM4G; r.ZMM4H; r.ZMM5A; r.ZMM5B; r.ZMM5C;
        r.ZMM5D; r.ZMM5E; r.ZMM5F; r.ZMM5G; r.ZMM5H; r.ZMM6A; r.ZMM6B; r.ZMM6C;
        r.ZMM6D; r.ZMM6E; r.ZMM6F; r.ZMM6G; r.ZMM6H; r.ZMM7A; r.ZMM7B; r.ZMM7C;
        r.ZMM7D; r.ZMM7E; r.ZMM7F; r.ZMM7G; r.ZMM7H; r.CS; r.DS; r.ES; r.FS;
        r.GS; r.SS; r.DR0; r.DR1; r.DR2; r.DR3; r.DR6; r.DR7 ]
    else
      [ r.RAX; r.RBX; r.RCX; r.RDX; r.RSP; r.RBP; r.RSI; r.RDI; r.R8; r.R9;
        r.R10; r.R11; r.R12; r.R13; r.R14; r.R15; r.RIP; r.CSBase; r.DSBase;
        r.ESBase; r.FSBase; r.GSBase; r.SSBase; r.CR0;r.CR2; r.CR3; r.CR4;
        r.CR8; r.OF; r.DF; r.IF; r.TF; r.SF; r.ZF; r.AF; r.PF; r.CF; r.FCW;
        r.FSW; r.FTW; r.FOP; r.FIP; r.FCS; r.FDP; r.FDS; r.MXCSR; r.MXCSRMASK;
        r.PKRU; r.K0; r.K1; r.K2; r.K3; r.K4; r.K5; r.K6; r.K7; r.ST0A; r.ST0B;
        r.ST1A; r.ST1B; r.ST2A; r.ST2B; r.ST3A; r.ST3B; r.ST4A; r.ST4B; r.ST5A;
        r.ST5B; r.ST6A; r.ST6B; r.ST7A; r.ST7B; r.ZMM0A; r.ZMM0B; r.ZMM0C;
        r.ZMM0D; r.ZMM0E; r.ZMM0F; r.ZMM0G; r.ZMM0H; r.ZMM1A; r.ZMM1B; r.ZMM1C;
        r.ZMM1D; r.ZMM1E; r.ZMM1F; r.ZMM1G; r.ZMM1H; r.ZMM2A; r.ZMM2B; r.ZMM2C;
        r.ZMM2D; r.ZMM2E; r.ZMM2F; r.ZMM2G; r.ZMM2H; r.ZMM3A; r.ZMM3B; r.ZMM3C;
        r.ZMM3D; r.ZMM3E; r.ZMM3F; r.ZMM3G; r.ZMM3H; r.ZMM4A; r.ZMM4B; r.ZMM4C;
        r.ZMM4D; r.ZMM4E; r.ZMM4F; r.ZMM4G; r.ZMM4H; r.ZMM5A; r.ZMM5B; r.ZMM5C;
        r.ZMM5D; r.ZMM5E; r.ZMM5F; r.ZMM5G; r.ZMM5H; r.ZMM6A; r.ZMM6B; r.ZMM6C;
        r.ZMM6D; r.ZMM6E; r.ZMM6F; r.ZMM6G; r.ZMM6H; r.ZMM7A; r.ZMM7B; r.ZMM7C;
        r.ZMM7D; r.ZMM7E; r.ZMM7F; r.ZMM7G; r.ZMM7H; r.ZMM8A; r.ZMM8B; r.ZMM8C;
        r.ZMM8D; r.ZMM8E; r.ZMM8F; r.ZMM8G; r.ZMM8H; r.ZMM9A; r.ZMM9B; r.ZMM9C;
        r.ZMM9D; r.ZMM9E; r.ZMM9F; r.ZMM9G; r.ZMM9H; r.ZMM10A; r.ZMM10B;
        r.ZMM10C; r.ZMM10D; r.ZMM10E; r.ZMM10F; r.ZMM10G; r.ZMM10H; r.ZMM11A;
        r.ZMM11B; r.ZMM11C; r.ZMM11D; r.ZMM11E; r.ZMM11F; r.ZMM11G; r.ZMM11H;
        r.ZMM12A; r.ZMM12B; r.ZMM12C; r.ZMM12D; r.ZMM12E; r.ZMM12F; r.ZMM12G;
        r.ZMM12H; r.ZMM13A; r.ZMM13B; r.ZMM13C; r.ZMM13D; r.ZMM13E; r.ZMM13F;
        r.ZMM13G; r.ZMM13H; r.ZMM14A; r.ZMM14B; r.ZMM14C; r.ZMM14D; r.ZMM14E;
        r.ZMM14F; r.ZMM14G; r.ZMM14H; r.ZMM15A; r.ZMM15B; r.ZMM15C; r.ZMM15D;
        r.ZMM15E; r.ZMM15F; r.ZMM15G; r.ZMM15H; r.CS; r.DS; r.ES; r.FS; r.GS;
        r.SS; r.DR0; r.DR1; r.DR2; r.DR3; r.DR6; r.DR7 ]

  override __.GetAllRegNames () =
    __.GetAllRegExprs ()
    |> List.map (__.RegIDFromRegExpr >> __.RegIDToString)

  override __.GetGeneralRegExprs () =
    if WordSize.is32 wordSize then
      [ r.EAX; r.EBX; r.ECX; r.EDX; r.ESP; r.EBP; r.ESI; r.EDI; r.EIP
        r.OF; r.DF; r.IF; r.SF; r.ZF; r.AF; r.PF; r.CF ]
    else
      [ r.RAX; r.RBX; r.RCX; r.RDX; r.RSP; r.RBP; r.RSI; r.RDI; r.R8; r.R9
        r.R10; r.R11; r.R12; r.R13; r.R14; r.R15; r.RIP
        r.OF; r.DF; r.IF; r.SF; r.ZF; r.AF; r.PF; r.CF ]

  override __.RegIDFromRegExpr (e) =
    match e.E with
    | Var (_,id, _) -> id
    | PCVar (regT, _) ->
      if regT = 32<rt> then Register.toRegID EIP
      else Register.toRegID RIP
    | _ -> raise InvalidRegisterException

  override __.RegIDToRegExpr (id) =
    Register.ofRegID id |> r.GetRegVar

  override __.StrToRegExpr (s: string) =
    match s.ToUpper () with
    | "RAX" -> r.RAX
    | "RBX" -> r.RBX
    | "RCX" -> r.RCX
    | "RDX" -> r.RDX
    | "RSP" -> r.RSP
    | "RBP" -> r.RBP
    | "RSI" -> r.RSI
    | "RDI" -> r.RDI
    | "EAX" -> r.EAX
    | "EBX" -> r.EBX
    | "ECX" -> r.ECX
    | "EDX" -> r.EDX
    | "ESP" -> r.ESP
    | "EBP" -> r.EBP
    | "ESI" -> r.ESI
    | "EDI" -> r.EDI
    | "AX" -> r.AX
    | "BX" -> r.BX
    | "CX" -> r.CX
    | "DX" -> r.DX
    | "SP" -> r.SP
    | "BP" -> r.BP
    | "SI" -> r.SI
    | "DI" -> r.DI
    | "AL" -> r.AL
    | "BL" -> r.BL
    | "CL" -> r.CL
    | "DL" -> r.DL
    | "AH" -> r.AH
    | "BH" -> r.BH
    | "CH" -> r.CH
    | "DH" -> r.DH
    | "R8" -> r.R8
    | "R9" -> r.R9
    | "R10" -> r.R10
    | "R11" -> r.R11
    | "R12" -> r.R12
    | "R13" -> r.R13
    | "R14" -> r.R14
    | "R15" -> r.R15
    | "R8D" -> r.R8D
    | "R9D" -> r.R9D
    | "R10D" -> r.R10D
    | "R11D" -> r.R11D
    | "R12D" -> r.R12D
    | "R13D" -> r.R13D
    | "R14D" -> r.R14D
    | "R15D" -> r.R15D
    | "R8W" -> r.R8W
    | "R9W" -> r.R9W
    | "R10W" -> r.R10W
    | "R11W" -> r.R11W
    | "R12W" -> r.R12W
    | "R13W" -> r.R13W
    | "R14W" -> r.R14W
    | "R15W" -> r.R15W
    | "R8B" -> r.R8B
    | "R9B" -> r.R9B
    | "R10B" -> r.R10B
    | "R11B" -> r.R11B
    | "R12B" -> r.R12B
    | "R13B" -> r.R13B
    | "R14B" -> r.R14B
    | "R15B" -> r.R15B
    | "SPL" -> r.SPL
    | "BPL" -> r.BPL
    | "SIL" -> r.SIL
    | "DIL" -> r.DIL
    | "EIP" -> r.EIP
    | "RIP" -> r.RIP
    | "MM0" -> r.MM0
    | "MM1" -> r.MM1
    | "MM2" -> r.MM2
    | "MM3" -> r.MM3
    | "MM4" -> r.MM4
    | "MM5" -> r.MM5
    | "MM6" -> r.MM6
    | "MM7" -> r.MM7
    | "CS" -> r.CS
    | "DS" -> r.DS
    | "SS" -> r.SS
    | "ES" -> r.ES
    | "FS" -> r.FS
    | "GS" -> r.GS
    | "CSBASE" -> r.CSBase
    | "DSBASE" -> r.DSBase
    | "ESBASE" -> r.ESBase
    | "FSBASE" -> r.FSBase
    | "GSBASE" -> r.GSBase
    | "SSBASE" -> r.SSBase
    | "CR0" -> r.CR0
    | "CR2" -> r.CR2
    | "CR3" -> r.CR3
    | "CR4" -> r.CR4
    | "CR8" -> r.CR8
    | "OF" -> r.OF
    | "DF" -> r.DF
    | "IF" -> r.IF
    | "TF" -> r.TF
    | "SF" -> r.SF
    | "ZF" -> r.ZF
    | "AF" -> r.AF
    | "PF" -> r.PF
    | "CF" -> r.CF
    | "K0" -> r.K0
    | "K1" -> r.K1
    | "K2" -> r.K2
    | "K3" -> r.K3
    | "K4" -> r.K4
    | "K5" -> r.K5
    | "K6" -> r.K6
    | "K7" -> r.K7
    | "ST0A" -> r.ST0A
    | "ST0B" -> r.ST0B
    | "ST1A" -> r.ST1A
    | "ST1B" -> r.ST1B
    | "ST2A" -> r.ST2A
    | "ST2B" -> r.ST2B
    | "ST3A" -> r.ST3A
    | "ST3B" -> r.ST3B
    | "ST4A" -> r.ST4A
    | "ST4B" -> r.ST4B
    | "ST5A" -> r.ST5A
    | "ST5B" -> r.ST5B
    | "ST6A" -> r.ST6A
    | "ST6B" -> r.ST6B
    | "ST7A" -> r.ST7A
    | "ST7B" -> r.ST7B
    | "FCW" -> r.FCW
    | "FSW" -> r.FSW
    | "FTW" -> r.FTW
    | "FOP" -> r.FOP
    | "FIP" -> r.FIP
    | "FCS" -> r.FCS
    | "FDP" -> r.FDP
    | "FDS" -> r.FDS
    | "FTOP" -> r.FTOP
    | "FTW0" -> r.FTW0
    | "FTW1" -> r.FTW1
    | "FTW2" -> r.FTW2
    | "FTW3" -> r.FTW3
    | "FTW4" -> r.FTW4
    | "FTW5" -> r.FTW5
    | "FTW6" -> r.FTW6
    | "FTW7" -> r.FTW7
    | "FSWC0" -> r.FSWC0
    | "FSWC1" -> r.FSWC1
    | "FSWC2" -> r.FSWC2
    | "FSWC3" -> r.FSWC3
    | "MXCSR" -> r.MXCSR
    | "MXCSRMASK" -> r.MXCSRMASK
    | "ZMM0A" -> r.ZMM0A
    | "ZMM0B" -> r.ZMM0B
    | "ZMM0C" -> r.ZMM0C
    | "ZMM0D" -> r.ZMM0D
    | "ZMM0E" -> r.ZMM0E
    | "ZMM0F" -> r.ZMM0F
    | "ZMM0G" -> r.ZMM0G
    | "ZMM0H" -> r.ZMM0H
    | "ZMM1A" -> r.ZMM1A
    | "ZMM1B" -> r.ZMM1B
    | "ZMM1C" -> r.ZMM1C
    | "ZMM1D" -> r.ZMM1D
    | "ZMM1E" -> r.ZMM1E
    | "ZMM1F" -> r.ZMM1F
    | "ZMM1G" -> r.ZMM1G
    | "ZMM1H" -> r.ZMM1H
    | "ZMM2A" -> r.ZMM2A
    | "ZMM2B" -> r.ZMM2B
    | "ZMM2C" -> r.ZMM2C
    | "ZMM2D" -> r.ZMM2D
    | "ZMM2E" -> r.ZMM2E
    | "ZMM2F" -> r.ZMM2F
    | "ZMM2G" -> r.ZMM2G
    | "ZMM2H" -> r.ZMM2H
    | "ZMM3A" -> r.ZMM3A
    | "ZMM3B" -> r.ZMM3B
    | "ZMM3C" -> r.ZMM3C
    | "ZMM3D" -> r.ZMM3D
    | "ZMM3E" -> r.ZMM3E
    | "ZMM3F" -> r.ZMM3F
    | "ZMM3G" -> r.ZMM3G
    | "ZMM3H" -> r.ZMM3H
    | "ZMM4A" -> r.ZMM4A
    | "ZMM4B" -> r.ZMM4B
    | "ZMM4C" -> r.ZMM4C
    | "ZMM4D" -> r.ZMM4D
    | "ZMM4E" -> r.ZMM4E
    | "ZMM4F" -> r.ZMM4F
    | "ZMM4G" -> r.ZMM4G
    | "ZMM4H" -> r.ZMM4H
    | "ZMM5A" -> r.ZMM5A
    | "ZMM5B" -> r.ZMM5B
    | "ZMM5C" -> r.ZMM5C
    | "ZMM5D" -> r.ZMM5D
    | "ZMM5E" -> r.ZMM5E
    | "ZMM5F" -> r.ZMM5F
    | "ZMM5G" -> r.ZMM5G
    | "ZMM5H" -> r.ZMM5H
    | "ZMM6A" -> r.ZMM6A
    | "ZMM6B" -> r.ZMM6B
    | "ZMM6C" -> r.ZMM6C
    | "ZMM6D" -> r.ZMM6D
    | "ZMM6E" -> r.ZMM6E
    | "ZMM6F" -> r.ZMM6F
    | "ZMM6G" -> r.ZMM6G
    | "ZMM6H" -> r.ZMM6H
    | "ZMM7A" -> r.ZMM7A
    | "ZMM7B" -> r.ZMM7B
    | "ZMM7C" -> r.ZMM7C
    | "ZMM7D" -> r.ZMM7D
    | "ZMM7E" -> r.ZMM7E
    | "ZMM7F" -> r.ZMM7F
    | "ZMM7G" -> r.ZMM7G
    | "ZMM7H" -> r.ZMM7H
    | "ZMM8A" -> r.ZMM8A
    | "ZMM8B" -> r.ZMM8B
    | "ZMM8C" -> r.ZMM8C
    | "ZMM8D" -> r.ZMM8D
    | "ZMM8E" -> r.ZMM8E
    | "ZMM8F" -> r.ZMM8F
    | "ZMM8G" -> r.ZMM8G
    | "ZMM8H" -> r.ZMM8H
    | "ZMM9A" -> r.ZMM9A
    | "ZMM9B" -> r.ZMM9B
    | "ZMM9C" -> r.ZMM9C
    | "ZMM9D" -> r.ZMM9D
    | "ZMM9E" -> r.ZMM9E
    | "ZMM9F" -> r.ZMM9F
    | "ZMM9G" -> r.ZMM9G
    | "ZMM9H" -> r.ZMM9H
    | "ZMM10A" -> r.ZMM10A
    | "ZMM10B" -> r.ZMM10B
    | "ZMM10C" -> r.ZMM10C
    | "ZMM10D" -> r.ZMM10D
    | "ZMM10E" -> r.ZMM10E
    | "ZMM10F" -> r.ZMM10F
    | "ZMM10G" -> r.ZMM10G
    | "ZMM10H" -> r.ZMM10H
    | "ZMM11A" -> r.ZMM11A
    | "ZMM11B" -> r.ZMM11B
    | "ZMM11C" -> r.ZMM11C
    | "ZMM11D" -> r.ZMM11D
    | "ZMM11E" -> r.ZMM11E
    | "ZMM11F" -> r.ZMM11F
    | "ZMM11G" -> r.ZMM11G
    | "ZMM11H" -> r.ZMM11H
    | "ZMM12A" -> r.ZMM12A
    | "ZMM12B" -> r.ZMM12B
    | "ZMM12C" -> r.ZMM12C
    | "ZMM12D" -> r.ZMM12D
    | "ZMM12E" -> r.ZMM12E
    | "ZMM12F" -> r.ZMM12F
    | "ZMM12G" -> r.ZMM12G
    | "ZMM12H" -> r.ZMM12H
    | "ZMM13A" -> r.ZMM13A
    | "ZMM13B" -> r.ZMM13B
    | "ZMM13C" -> r.ZMM13C
    | "ZMM13D" -> r.ZMM13D
    | "ZMM13E" -> r.ZMM13E
    | "ZMM13F" -> r.ZMM13F
    | "ZMM13G" -> r.ZMM13G
    | "ZMM13H" -> r.ZMM13H
    | "ZMM14A" -> r.ZMM14A
    | "ZMM14B" -> r.ZMM14B
    | "ZMM14C" -> r.ZMM14C
    | "ZMM14D" -> r.ZMM14D
    | "ZMM14E" -> r.ZMM14E
    | "ZMM14F" -> r.ZMM14F
    | "ZMM14G" -> r.ZMM14G
    | "ZMM14H" -> r.ZMM14H
    | "ZMM15A" -> r.ZMM15A
    | "ZMM15B" -> r.ZMM15B
    | "ZMM15C" -> r.ZMM15C
    | "ZMM15D" -> r.ZMM15D
    | "ZMM15E" -> r.ZMM15E
    | "ZMM15F" -> r.ZMM15F
    | "ZMM15G" -> r.ZMM15G
    | "ZMM15H" -> r.ZMM15H
    | "PKRU" -> r.PKRU
    | "DR0" -> r.DR0
    | "DR1" -> r.DR1
    | "DR2" -> r.DR2
    | "DR3" -> r.DR3
    | "DR6" -> r.DR6
    | "DR7" -> r.DR7
    | _ -> raise UnhandledRegExprException

  override __.RegIDFromString str =
    Register.ofString str |> Register.toRegID

  override __.RegIDToString rid =
    Register.ofRegID rid |> Register.toString

  override __.RegIDToRegType rid =
    Register.ofRegID rid |> Register.toRegType wordSize

  override __.GetRegisterAliases rid =
    Register.ofRegID rid
    |> Register.getAliases
    |> Array.map Register.toRegID

  override __.ProgramCounter =
    if WordSize.is32 wordSize then EIP |> Register.toRegID
    else RIP |> Register.toRegID

  override __.StackPointer =
    if WordSize.is32 wordSize then ESP |> Register.toRegID
    else RSP |> Register.toRegID
    |> Some

  override __.FramePointer =
    if WordSize.is32 wordSize then EBP |> Register.toRegID
    else RBP |> Register.toRegID
    |> Some

  override __.IsProgramCounter regid =
    __.ProgramCounter = regid

  override __.IsStackPointer regid =
    (__.StackPointer |> Option.get) = regid

  override __.IsFramePointer regid =
    (__.FramePointer |> Option.get) = regid
