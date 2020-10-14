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

type IntelRegisterBay (wordSize) =

  inherit RegisterBay ()

  let R = RegExprs (wordSize)

  override __.GetAllRegExprs () =
    if WordSize.is32 wordSize then
      [ R.EAX; R.EBX; R.ECX; R.EDX; R.ESP; R.EBP; R.ESI; R.EDI; R.EIP; R.CS;
        R.DS; R.ES; R.FS; R.GS; R.SS; R.CSBase; R.DSBase; R.ESBase; R.FSBase;
        R.GSBase; R.SSBase; R.CR0; R.CR2; R.CR3; R.CR4; R.OF; R.DF; R.IF; R.TF;
        R.SF; R.ZF; R.AF; R.PF; R.CF; R.FCW; R.FSW; R.FTW; R.FOP; R.FIP; R.FCS;
        R.FDP; R.FDS; R.MXCSR; R.MXCSRMASK; R.PKRU; R.K0; R.K1; R.K2; R.K3;
        R.K4; R.K5; R.K6; R.K7; R.ST0A; R.ST0B; R.ST1A; R.ST1B; R.ST2A; R.ST2B;
        R.ST3A; R.ST3B; R.ST4A; R.ST4B; R.ST5A; R.ST5B; R.ST6A; R.ST6B; R.ST7A;
        R.ST7B; R.ZMM0A; R.ZMM0B; R.ZMM1A; R.ZMM1B; R.ZMM2A; R.ZMM2B; R.ZMM3A;
        R.ZMM3B; R.ZMM4A; R.ZMM4B; R.ZMM5A; R.ZMM5B; R.ZMM6A; R.ZMM6B; R.ZMM7A;
        R.ZMM7B; R.ZMM8A; R.ZMM8B ]
    else
      [ R.RAX; R.RBX; R.RCX; R.RDX; R.RSP; R.RBP; R.RSI; R.RDI; R.R8; R.R9;
        R.R10; R.R11; R.R12; R.R13; R.R14; R.R15; R.RIP; R.CS; R.DS; R.ES; R.FS;
        R.GS; R.SS; R.CSBase; R.DSBase; R.ESBase; R.FSBase; R.GSBase; R.SSBase;
        R.CR0;R.CR2; R.CR3; R.CR4; R.CR8; R.OF; R.DF; R.IF; R.TF; R.SF; R.ZF;
        R.AF; R.PF; R.CF; R.FCW; R.FSW; R.FTW; R.FOP; R.FIP; R.FCS; R.FDP;
        R.FDS; R.MXCSR; R.MXCSRMASK; R.PKRU; R.K0; R.K1; R.K2; R.K3; R.K4; R.K5;
        R.K6; R.K7; R.ST0A; R.ST0B; R.ST1A; R.ST1B; R.ST2A; R.ST2B; R.ST3A;
        R.ST3B; R.ST4A; R.ST4B; R.ST5A; R.ST5B; R.ST6A; R.ST6B; R.ST7A; R.ST7B;
        R.ZMM0A; R.ZMM0B; R.ZMM1A; R.ZMM1B; R.ZMM2A; R.ZMM2B; R.ZMM3A; R.ZMM3B;
        R.ZMM4A; R.ZMM4B; R.ZMM5A; R.ZMM5B; R.ZMM6A; R.ZMM6B; R.ZMM7A; R.ZMM7B;
        R.ZMM8A; R.ZMM8B ]

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

  override __.StrToRegExpr s =
    match s with
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
    | "CSBase" -> R.CSBase
    | "DSBase" -> R.DSBase
    | "ESBase" -> R.ESBase
    | "FSBase" -> R.FSBase
    | "GSBase" -> R.GSBase
    | "SSBase" -> R.SSBase
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
    | "ZMM0A" -> R.ZMM0A
    | "ZMM0B" -> R.ZMM0B
    | "ZMM1A" -> R.ZMM1A
    | "ZMM1B" -> R.ZMM1B
    | "ZMM2A" -> R.ZMM2A
    | "ZMM2B" -> R.ZMM2B
    | "ZMM3A" -> R.ZMM3A
    | "ZMM3B" -> R.ZMM3B
    | "ZMM4A" -> R.ZMM4A
    | "ZMM4B" -> R.ZMM4B
    | "ZMM5A" -> R.ZMM5A
    | "ZMM5B" -> R.ZMM5B
    | "ZMM6A" -> R.ZMM6A
    | "ZMM6B" -> R.ZMM6B
    | "ZMM7A" -> R.ZMM7A
    | "ZMM7B" -> R.ZMM7B
    | "ZMM8A" -> R.ZMM8A
    | "ZMM8B" -> R.ZMM8B
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
