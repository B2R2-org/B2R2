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

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR

type IntelRegisterBay internal (wordSize, R: RegExprs) =

  inherit RegisterBay ()

  override __.GetAllRegExprs () =
    if WordSize.is32 wordSize then
      [ R.EAX; R.EBX; R.ECX; R.EDX; R.ESP; R.EBP; R.ESI; R.EDI; R.EIP; R.CSBase;
        R.DSBase; R.ESBase; R.FSBase; R.GSBase; R.SSBase; R.CR0; R.CR2; R.CR3;
        R.CR4; R.OF; R.DF; R.IF; R.TF; R.SF; R.ZF; R.AF; R.PF; R.CF; R.FCW;
        R.FSW; R.FTW; R.FOP; R.FIP; R.FCS; R.FDP; R.FDS; R.MXCSR; R.MXCSRMASK;
        R.PKRU; R.K0; R.K1; R.K2; R.K3; R.K4; R.K5; R.K6; R.K7; R.ST0A; R.ST0B;
        R.ST1A; R.ST1B; R.ST2A; R.ST2B; R.ST3A; R.ST3B; R.ST4A; R.ST4B; R.ST5A;
        R.ST5B; R.ST6A; R.ST6B; R.ST7A; R.ST7B; R.ZMM0A; R.ZMM0B; R.ZMM0C;
        R.ZMM0D; R.ZMM0E; R.ZMM0F; R.ZMM0G; R.ZMM0H; R.ZMM1A; R.ZMM1B; R.ZMM1C;
        R.ZMM1D; R.ZMM1E; R.ZMM1F; R.ZMM1G; R.ZMM1H; R.ZMM2A; R.ZMM2B; R.ZMM2C;
        R.ZMM2D; R.ZMM2E; R.ZMM2F; R.ZMM2G; R.ZMM2H; R.ZMM3A; R.ZMM3B; R.ZMM3C;
        R.ZMM3D; R.ZMM3E; R.ZMM3F; R.ZMM3G; R.ZMM3H; R.ZMM4A; R.ZMM4B; R.ZMM4C;
        R.ZMM4D; R.ZMM4E; R.ZMM4F; R.ZMM4G; R.ZMM4H; R.ZMM5A; R.ZMM5B; R.ZMM5C;
        R.ZMM5D; R.ZMM5E; R.ZMM5F; R.ZMM5G; R.ZMM5H; R.ZMM6A; R.ZMM6B; R.ZMM6C;
        R.ZMM6D; R.ZMM6E; R.ZMM6F; R.ZMM6G; R.ZMM6H; R.ZMM7A; R.ZMM7B; R.ZMM7C;
        R.ZMM7D; R.ZMM7E; R.ZMM7F; R.ZMM7G; R.ZMM7H; R.CS; R.DS; R.ES; R.FS;
        R.GS; R.SS; R.DR0; R.DR1; R.DR2; R.DR3; R.DR6; R.DR7 ]
    else
      [ R.RAX; R.RBX; R.RCX; R.RDX; R.RSP; R.RBP; R.RSI; R.RDI; R.R8; R.R9;
        R.R10; R.R11; R.R12; R.R13; R.R14; R.R15; R.RIP; R.CSBase; R.DSBase;
        R.ESBase; R.FSBase; R.GSBase; R.SSBase; R.CR0;R.CR2; R.CR3; R.CR4;
        R.CR8; R.OF; R.DF; R.IF; R.TF; R.SF; R.ZF; R.AF; R.PF; R.CF; R.FCW;
        R.FSW; R.FTW; R.FOP; R.FIP; R.FCS; R.FDP; R.FDS; R.MXCSR; R.MXCSRMASK;
        R.PKRU; R.K0; R.K1; R.K2; R.K3; R.K4; R.K5; R.K6; R.K7; R.ST0A; R.ST0B;
        R.ST1A; R.ST1B; R.ST2A; R.ST2B; R.ST3A; R.ST3B; R.ST4A; R.ST4B; R.ST5A;
        R.ST5B; R.ST6A; R.ST6B; R.ST7A; R.ST7B; R.ZMM0A; R.ZMM0B; R.ZMM0C;
        R.ZMM0D; R.ZMM0E; R.ZMM0F; R.ZMM0G; R.ZMM0H; R.ZMM1A; R.ZMM1B; R.ZMM1C;
        R.ZMM1D; R.ZMM1E; R.ZMM1F; R.ZMM1G; R.ZMM1H; R.ZMM2A; R.ZMM2B; R.ZMM2C;
        R.ZMM2D; R.ZMM2E; R.ZMM2F; R.ZMM2G; R.ZMM2H; R.ZMM3A; R.ZMM3B; R.ZMM3C;
        R.ZMM3D; R.ZMM3E; R.ZMM3F; R.ZMM3G; R.ZMM3H; R.ZMM4A; R.ZMM4B; R.ZMM4C;
        R.ZMM4D; R.ZMM4E; R.ZMM4F; R.ZMM4G; R.ZMM4H; R.ZMM5A; R.ZMM5B; R.ZMM5C;
        R.ZMM5D; R.ZMM5E; R.ZMM5F; R.ZMM5G; R.ZMM5H; R.ZMM6A; R.ZMM6B; R.ZMM6C;
        R.ZMM6D; R.ZMM6E; R.ZMM6F; R.ZMM6G; R.ZMM6H; R.ZMM7A; R.ZMM7B; R.ZMM7C;
        R.ZMM7D; R.ZMM7E; R.ZMM7F; R.ZMM7G; R.ZMM7H; R.ZMM8A; R.ZMM8B; R.ZMM8C;
        R.ZMM8D; R.ZMM8E; R.ZMM8F; R.ZMM8G; R.ZMM8H; R.ZMM9A; R.ZMM9B; R.ZMM9C;
        R.ZMM9D; R.ZMM9E; R.ZMM9F; R.ZMM9G; R.ZMM9H; R.ZMM10A; R.ZMM10B;
        R.ZMM10C; R.ZMM10D; R.ZMM10E; R.ZMM10F; R.ZMM10G; R.ZMM10H; R.ZMM11A;
        R.ZMM11B; R.ZMM11C; R.ZMM11D; R.ZMM11E; R.ZMM11F; R.ZMM11G; R.ZMM11H;
        R.ZMM12A; R.ZMM12B; R.ZMM12C; R.ZMM12D; R.ZMM12E; R.ZMM12F; R.ZMM12G;
        R.ZMM12H; R.ZMM13A; R.ZMM13B; R.ZMM13C; R.ZMM13D; R.ZMM13E; R.ZMM13F;
        R.ZMM13G; R.ZMM13H; R.ZMM14A; R.ZMM14B; R.ZMM14C; R.ZMM14D; R.ZMM14E;
        R.ZMM14F; R.ZMM14G; R.ZMM14H; R.ZMM15A; R.ZMM15B; R.ZMM15C; R.ZMM15D;
        R.ZMM15E; R.ZMM15F; R.ZMM15G; R.ZMM15H; R.CS; R.DS; R.ES; R.FS; R.GS;
        R.SS; R.DR0; R.DR1; R.DR2; R.DR3; R.DR6; R.DR7 ]

  override __.GetAllRegNames () =
    __.GetAllRegExprs ()
    |> List.map (__.RegIDFromRegExpr >> __.RegIDToString)

  override __.GetGeneralRegExprs () =
    if WordSize.is32 wordSize then
      [ R.EAX; R.EBX; R.ECX; R.EDX; R.ESP; R.EBP; R.ESI; R.EDI; R.EIP
        R.OF; R.DF; R.IF; R.SF; R.ZF; R.AF; R.PF; R.CF ]
    else
      [ R.RAX; R.RBX; R.RCX; R.RDX; R.RSP; R.RBP; R.RSI; R.RDI; R.R8; R.R9
        R.R10; R.R11; R.R12; R.R13; R.R14; R.R15; R.RIP
        R.OF; R.DF; R.IF; R.SF; R.ZF; R.AF; R.PF; R.CF ]

  override __.RegIDFromRegExpr (e) =
    match e with
    | Var (_,id, _,_) -> id
    | PCVar (regT, _) ->
      if regT = 32<rt> then Register.toRegID Register.EIP
      else Register.toRegID Register.RIP
    | _ -> failwith "not a register expression"

  override __.RegIDToRegExpr (id) =
    Register.ofRegID id |> R.GetRegVar

  override __.StrToRegExpr (s: string) =
    match s.ToUpper () with
    | "RAX" -> R.RAX
    | "RBX" -> R.RBX
    | "RCX" -> R.RCX
    | "RDX" -> R.RDX
    | "RSP" -> R.RSP
    | "RBP" -> R.RBP
    | "RSI" -> R.RSI
    | "RDI" -> R.RDI
    | "EAX" -> R.EAX
    | "EBX" -> R.EBX
    | "ECX" -> R.ECX
    | "EDX" -> R.EDX
    | "ESP" -> R.ESP
    | "EBP" -> R.EBP
    | "ESI" -> R.ESI
    | "EDI" -> R.EDI
    | "AX" -> R.AX
    | "BX" -> R.BX
    | "CX" -> R.CX
    | "DX" -> R.DX
    | "SP" -> R.SP
    | "BP" -> R.BP
    | "SI" -> R.SI
    | "DI" -> R.DI
    | "AL" -> R.AL
    | "BL" -> R.BL
    | "CL" -> R.CL
    | "DL" -> R.DL
    | "AH" -> R.AH
    | "BH" -> R.BH
    | "CH" -> R.CH
    | "DH" -> R.DH
    | "R8" -> R.R8
    | "R9" -> R.R9
    | "R10" -> R.R10
    | "R11" -> R.R11
    | "R12" -> R.R12
    | "R13" -> R.R13
    | "R14" -> R.R14
    | "R15" -> R.R15
    | "R8D" -> R.R8D
    | "R9D" -> R.R9D
    | "R10D" -> R.R10D
    | "R11D" -> R.R11D
    | "R12D" -> R.R12D
    | "R13D" -> R.R13D
    | "R14D" -> R.R14D
    | "R15D" -> R.R15D
    | "R8W" -> R.R8W
    | "R9W" -> R.R9W
    | "R10W" -> R.R10W
    | "R11W" -> R.R11W
    | "R12W" -> R.R12W
    | "R13W" -> R.R13W
    | "R14W" -> R.R14W
    | "R15W" -> R.R15W
    | "R8L" -> R.R8L
    | "R9L" -> R.R9L
    | "R10L" -> R.R10L
    | "R11L" -> R.R11L
    | "R12L" -> R.R12L
    | "R13L" -> R.R13L
    | "R14L" -> R.R14L
    | "R15L" -> R.R15L
    | "SPL" -> R.SPL
    | "BPL" -> R.BPL
    | "SIL" -> R.SIL
    | "DIL" -> R.DIL
    | "EIP" -> R.EIP
    | "RIP" -> R.RIP
    | "MM0" -> R.MM0
    | "MM1" -> R.MM1
    | "MM2" -> R.MM2
    | "MM3" -> R.MM3
    | "MM4" -> R.MM4
    | "MM5" -> R.MM5
    | "MM6" -> R.MM6
    | "MM7" -> R.MM7
    | "CS" -> R.CS
    | "DS" -> R.DS
    | "SS" -> R.SS
    | "ES" -> R.ES
    | "FS" -> R.FS
    | "GS" -> R.GS
    | "CSBASE" -> R.CSBase
    | "DSBASE" -> R.DSBase
    | "ESBASE" -> R.ESBase
    | "FSBASE" -> R.FSBase
    | "GSBASE" -> R.GSBase
    | "SSBASE" -> R.SSBase
    | "CR0" -> R.CR0
    | "CR2" -> R.CR2
    | "CR3" -> R.CR3
    | "CR4" -> R.CR4
    | "CR8" -> R.CR8
    | "OF" -> R.OF
    | "DF" -> R.DF
    | "IF" -> R.IF
    | "TF" -> R.TF
    | "SF" -> R.SF
    | "ZF" -> R.ZF
    | "AF" -> R.AF
    | "PF" -> R.PF
    | "CF" -> R.CF
    | "K0" -> R.K0
    | "K1" -> R.K1
    | "K2" -> R.K2
    | "K3" -> R.K3
    | "K4" -> R.K4
    | "K5" -> R.K5
    | "K6" -> R.K6
    | "K7" -> R.K7
    | "ST0A" -> R.ST0A
    | "ST0B" -> R.ST0B
    | "ST1A" -> R.ST1A
    | "ST1B" -> R.ST1B
    | "ST2A" -> R.ST2A
    | "ST2B" -> R.ST2B
    | "ST3A" -> R.ST3A
    | "ST3B" -> R.ST3B
    | "ST4A" -> R.ST4A
    | "ST4B" -> R.ST4B
    | "ST5A" -> R.ST5A
    | "ST5B" -> R.ST5B
    | "ST6A" -> R.ST6A
    | "ST6B" -> R.ST6B
    | "ST7A" -> R.ST7A
    | "ST7B" -> R.ST7B
    | "FCW" -> R.FCW
    | "FSW" -> R.FSW
    | "FTW" -> R.FTW
    | "FOP" -> R.FOP
    | "FIP" -> R.FIP
    | "FCS" -> R.FCS
    | "FDP" -> R.FDP
    | "FDS" -> R.FDS
    | "FTOP" -> R.FTOP
    | "FTW0" -> R.FTW0
    | "FTW1" -> R.FTW1
    | "FTW2" -> R.FTW2
    | "FTW3" -> R.FTW3
    | "FTW4" -> R.FTW4
    | "FTW5" -> R.FTW5
    | "FTW6" -> R.FTW6
    | "FTW7" -> R.FTW7
    | "FSWC0" -> R.FSWC0
    | "FSWC1" -> R.FSWC1
    | "FSWC2" -> R.FSWC2
    | "FSWC3" -> R.FSWC3
    | "MXCSR" -> R.MXCSR
    | "MXCSRMASK" -> R.MXCSRMASK
    | "ZMM0A" -> R.ZMM0A
    | "ZMM0B" -> R.ZMM0B
    | "ZMM0C" -> R.ZMM0C
    | "ZMM0D" -> R.ZMM0D
    | "ZMM0E" -> R.ZMM0E
    | "ZMM0F" -> R.ZMM0F
    | "ZMM0G" -> R.ZMM0G
    | "ZMM0H" -> R.ZMM0H
    | "ZMM1A" -> R.ZMM1A
    | "ZMM1B" -> R.ZMM1B
    | "ZMM1C" -> R.ZMM1C
    | "ZMM1D" -> R.ZMM1D
    | "ZMM1E" -> R.ZMM1E
    | "ZMM1F" -> R.ZMM1F
    | "ZMM1G" -> R.ZMM1G
    | "ZMM1H" -> R.ZMM1H
    | "ZMM2A" -> R.ZMM2A
    | "ZMM2B" -> R.ZMM2B
    | "ZMM2C" -> R.ZMM2C
    | "ZMM2D" -> R.ZMM2D
    | "ZMM2E" -> R.ZMM2E
    | "ZMM2F" -> R.ZMM2F
    | "ZMM2G" -> R.ZMM2G
    | "ZMM2H" -> R.ZMM2H
    | "ZMM3A" -> R.ZMM3A
    | "ZMM3B" -> R.ZMM3B
    | "ZMM3C" -> R.ZMM3C
    | "ZMM3D" -> R.ZMM3D
    | "ZMM3E" -> R.ZMM3E
    | "ZMM3F" -> R.ZMM3F
    | "ZMM3G" -> R.ZMM3G
    | "ZMM3H" -> R.ZMM3H
    | "ZMM4A" -> R.ZMM4A
    | "ZMM4B" -> R.ZMM4B
    | "ZMM4C" -> R.ZMM4C
    | "ZMM4D" -> R.ZMM4D
    | "ZMM4E" -> R.ZMM4E
    | "ZMM4F" -> R.ZMM4F
    | "ZMM4G" -> R.ZMM4G
    | "ZMM4H" -> R.ZMM4H
    | "ZMM5A" -> R.ZMM5A
    | "ZMM5B" -> R.ZMM5B
    | "ZMM5C" -> R.ZMM5C
    | "ZMM5D" -> R.ZMM5D
    | "ZMM5E" -> R.ZMM5E
    | "ZMM5F" -> R.ZMM5F
    | "ZMM5G" -> R.ZMM5G
    | "ZMM5H" -> R.ZMM5H
    | "ZMM6A" -> R.ZMM6A
    | "ZMM6B" -> R.ZMM6B
    | "ZMM6C" -> R.ZMM6C
    | "ZMM6D" -> R.ZMM6D
    | "ZMM6E" -> R.ZMM6E
    | "ZMM6F" -> R.ZMM6F
    | "ZMM6G" -> R.ZMM6G
    | "ZMM6H" -> R.ZMM6H
    | "ZMM7A" -> R.ZMM7A
    | "ZMM7B" -> R.ZMM7B
    | "ZMM7C" -> R.ZMM7C
    | "ZMM7D" -> R.ZMM7D
    | "ZMM7E" -> R.ZMM7E
    | "ZMM7F" -> R.ZMM7F
    | "ZMM7G" -> R.ZMM7G
    | "ZMM7H" -> R.ZMM7H
    | "ZMM8A" -> R.ZMM8A
    | "ZMM8B" -> R.ZMM8B
    | "ZMM8C" -> R.ZMM8C
    | "ZMM8D" -> R.ZMM8D
    | "ZMM8E" -> R.ZMM8E
    | "ZMM8F" -> R.ZMM8F
    | "ZMM8G" -> R.ZMM8G
    | "ZMM8H" -> R.ZMM8H
    | "ZMM9A" -> R.ZMM9A
    | "ZMM9B" -> R.ZMM9B
    | "ZMM9C" -> R.ZMM9C
    | "ZMM9D" -> R.ZMM9D
    | "ZMM9E" -> R.ZMM9E
    | "ZMM9F" -> R.ZMM9F
    | "ZMM9G" -> R.ZMM9G
    | "ZMM9H" -> R.ZMM9H
    | "ZMM10A" -> R.ZMM10A
    | "ZMM10B" -> R.ZMM10B
    | "ZMM10C" -> R.ZMM10C
    | "ZMM10D" -> R.ZMM10D
    | "ZMM10E" -> R.ZMM10E
    | "ZMM10F" -> R.ZMM10F
    | "ZMM10G" -> R.ZMM10G
    | "ZMM10H" -> R.ZMM10H
    | "ZMM11A" -> R.ZMM11A
    | "ZMM11B" -> R.ZMM11B
    | "ZMM11C" -> R.ZMM11C
    | "ZMM11D" -> R.ZMM11D
    | "ZMM11E" -> R.ZMM11E
    | "ZMM11F" -> R.ZMM11F
    | "ZMM11G" -> R.ZMM11G
    | "ZMM11H" -> R.ZMM11H
    | "ZMM12A" -> R.ZMM12A
    | "ZMM12B" -> R.ZMM12B
    | "ZMM12C" -> R.ZMM12C
    | "ZMM12D" -> R.ZMM12D
    | "ZMM12E" -> R.ZMM12E
    | "ZMM12F" -> R.ZMM12F
    | "ZMM12G" -> R.ZMM12G
    | "ZMM12H" -> R.ZMM12H
    | "ZMM13A" -> R.ZMM13A
    | "ZMM13B" -> R.ZMM13B
    | "ZMM13C" -> R.ZMM13C
    | "ZMM13D" -> R.ZMM13D
    | "ZMM13E" -> R.ZMM13E
    | "ZMM13F" -> R.ZMM13F
    | "ZMM13G" -> R.ZMM13G
    | "ZMM13H" -> R.ZMM13H
    | "ZMM14A" -> R.ZMM14A
    | "ZMM14B" -> R.ZMM14B
    | "ZMM14C" -> R.ZMM14C
    | "ZMM14D" -> R.ZMM14D
    | "ZMM14E" -> R.ZMM14E
    | "ZMM14F" -> R.ZMM14F
    | "ZMM14G" -> R.ZMM14G
    | "ZMM14H" -> R.ZMM14H
    | "ZMM15A" -> R.ZMM15A
    | "ZMM15B" -> R.ZMM15B
    | "ZMM15C" -> R.ZMM15C
    | "ZMM15D" -> R.ZMM15D
    | "ZMM15E" -> R.ZMM15E
    | "ZMM15F" -> R.ZMM15F
    | "ZMM15G" -> R.ZMM15G
    | "ZMM15H" -> R.ZMM15H
    | "PKRU" -> R.PKRU
    | "DR0" -> R.DR0
    | "DR1" -> R.DR1
    | "DR2" -> R.DR2
    | "DR3" -> R.DR3
    | "DR6" -> R.DR6
    | "DR7" -> R.DR7
    | _ -> raise UnhandledRegExprException

  override __.RegIDFromString str =
    Register.ofString str |> Register.toRegID

  override __.RegIDToString rid =
    Register.ofRegID rid |> Register.toString

  override __.RegIDToRegType rid =
    Register.ofRegID rid |> Register.toRegType

  override __.GetRegisterAliases rid =
    Register.ofRegID rid
    |> Register.getAliases
    |> Array.map Register.toRegID

  override __.ProgramCounter =
    if WordSize.is32 wordSize then Register.EIP |> Register.toRegID
    else Register.RIP |> Register.toRegID

  override __.StackPointer =
    if WordSize.is32 wordSize then Register.ESP |> Register.toRegID
    else Register.RSP |> Register.toRegID
    |> Some

  override __.FramePointer =
    if WordSize.is32 wordSize then Register.EBP |> Register.toRegID
    else Register.RBP |> Register.toRegID
    |> Some

  override __.IsProgramCounter regid =
    __.ProgramCounter = regid

  override __.IsStackPointer regid =
    (__.StackPointer |> Option.get) = regid

  override __.IsFramePointer regid =
    (__.FramePointer |> Option.get) = regid
