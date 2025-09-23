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

namespace B2R2.FrontEnd.SH4

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR

/// Represents a factory for accessing various SH4 register variables.
type RegisterFactory(wordSize) =
  let rt = WordSize.toRegType wordSize

  let r0 = AST.var rt (Register.toRegID R.R0) "R0"
  let r1 = AST.var rt (Register.toRegID R.R1) "R1"
  let r2 = AST.var rt (Register.toRegID R.R2) "R2"
  let r3 = AST.var rt (Register.toRegID R.R3) "R3"
  let r4 = AST.var rt (Register.toRegID R.R4) "R4"
  let r5 = AST.var rt (Register.toRegID R.R5) "R5"
  let r6 = AST.var rt (Register.toRegID R.R6) "R6"
  let r7 = AST.var rt (Register.toRegID R.R7) "R7"
  let r8 = AST.var rt (Register.toRegID R.R8) "R8"
  let r9 = AST.var rt (Register.toRegID R.R9) "R9"
  let r10 = AST.var rt (Register.toRegID R.R10) "R10"
  let r11 = AST.var rt (Register.toRegID R.R11) "R11"
  let r12 = AST.var rt (Register.toRegID R.R12) "R12"
  let r13 = AST.var rt (Register.toRegID R.R13) "R13"
  let r14 = AST.var rt (Register.toRegID R.R14) "R14"
  let r15 = AST.var rt (Register.toRegID R.R15) "R15"
  let r0BANK = AST.var rt (Register.toRegID R.R0_BANK) "R0_BANK"
  let r1BANK = AST.var rt (Register.toRegID R.R1_BANK) "R1_BANK"
  let r2BANK = AST.var rt (Register.toRegID R.R2_BANK) "R2_BANK"
  let r3BANK = AST.var rt (Register.toRegID R.R3_BANK) "R3_BANK"
  let r4BANK = AST.var rt (Register.toRegID R.R4_BANK) "R4_BANK"
  let r5BANK = AST.var rt (Register.toRegID R.R5_BANK) "R5_BANK"
  let r6BANK = AST.var rt (Register.toRegID R.R6_BANK) "R6_BANK"
  let r7BANK = AST.var rt (Register.toRegID R.R7_BANK) "R7_BANK"
  let sr = AST.var rt (Register.toRegID R.SR) "SR"
  let gbr = AST.var rt (Register.toRegID R.GBR) "GBR"
  let ssr = AST.var rt (Register.toRegID R.SSR) "SSR"
  let spc = AST.var rt (Register.toRegID R.SPC) "SPC"
  let sgr = AST.var rt (Register.toRegID R.SGR) "SGR"
  let dbr = AST.var rt (Register.toRegID R.DBR) "DBR"
  let vbr = AST.var rt (Register.toRegID R.VBR) "VBR"
  let mach = AST.var rt (Register.toRegID R.MACH) "MACH"
  let macl = AST.var rt (Register.toRegID R.MACL) "MACL"
  let pr = AST.var rt (Register.toRegID R.PR) "PR"
  let fpul = AST.var rt (Register.toRegID R.FPUL) "FPUL"
  let pc = AST.var rt (Register.toRegID R.PC) "PC"
  let fpscr = AST.var rt (Register.toRegID R.FPSCR) "FPSCR"
  let fpr0 = AST.var rt (Register.toRegID R.FPR0) "FPR0"
  let fpr1 = AST.var rt (Register.toRegID R.FPR1) "FPR1"
  let fpr2 = AST.var rt (Register.toRegID R.FPR2) "FPR2"
  let fpr3 = AST.var rt (Register.toRegID R.FPR3) "FPR3"
  let fpr4 = AST.var rt (Register.toRegID R.FPR4) "FPR4"
  let fpr5 = AST.var rt (Register.toRegID R.FPR5) "FPR5"
  let fpr6 = AST.var rt (Register.toRegID R.FPR6) "FPR6"
  let fpr7 = AST.var rt (Register.toRegID R.FPR7) "FPR7"
  let fpr8 = AST.var rt (Register.toRegID R.FPR8) "FPR8"
  let fpr9 = AST.var rt (Register.toRegID R.FPR9) "FPR9"
  let fpr10 = AST.var rt (Register.toRegID R.FPR10) "FPR10"
  let fpr11 = AST.var rt (Register.toRegID R.FPR11) "FPR11"
  let fpr12 = AST.var rt (Register.toRegID R.FPR12) "FPR12"
  let fpr13 = AST.var rt (Register.toRegID R.FPR13) "FPR13"
  let fpr14 = AST.var rt (Register.toRegID R.FPR14) "FPR14"
  let fpr15 = AST.var rt (Register.toRegID R.FPR15) "FPR15"
  let fr0 = AST.var rt (Register.toRegID R.FR0) "FR0"
  let fr1 = AST.var rt (Register.toRegID R.FR1) "FR1"
  let fr2 = AST.var rt (Register.toRegID R.FR2) "FR2"
  let fr3 = AST.var rt (Register.toRegID R.FR3) "FR3"
  let fr4 = AST.var rt (Register.toRegID R.FR4) "FR4"
  let fr5 = AST.var rt (Register.toRegID R.FR5) "FR5"
  let fr6 = AST.var rt (Register.toRegID R.FR6) "FR6"
  let fr7 = AST.var rt (Register.toRegID R.FR7) "FR7"
  let fr8 = AST.var rt (Register.toRegID R.FR8) "FR8"
  let fr9 = AST.var rt (Register.toRegID R.FR9) "FR9"
  let fr10 = AST.var rt (Register.toRegID R.FR10) "FR10"
  let fr11 = AST.var rt (Register.toRegID R.FR11) "FR11"
  let fr12 = AST.var rt (Register.toRegID R.FR12) "FR12"
  let fr13 = AST.var rt (Register.toRegID R.FR13) "FR13"
  let fr14 = AST.var rt (Register.toRegID R.FR14) "FR14"
  let fr15 = AST.var rt (Register.toRegID R.FR15) "FR15"
  let dr0 = AST.var rt (Register.toRegID R.DR0) "DR0"
  let dr2 = AST.var rt (Register.toRegID R.DR2) "DR2"
  let dr4 = AST.var rt (Register.toRegID R.DR4) "DR4"
  let dr6 = AST.var rt (Register.toRegID R.DR6) "DR6"
  let dr8 = AST.var rt (Register.toRegID R.DR8) "DR8"
  let dr10 = AST.var rt (Register.toRegID R.DR10) "DR10"
  let dr12 = AST.var rt (Register.toRegID R.DR12) "DR12"
  let dr14 = AST.var rt (Register.toRegID R.DR14) "DR14"
  let fv0 = AST.var rt (Register.toRegID R.FV0) "FV0"
  let fv4 = AST.var rt (Register.toRegID R.FV4) "FV4"
  let fv8 = AST.var rt (Register.toRegID R.FV8) "FV8"
  let fv12 = AST.var rt (Register.toRegID R.FV12) "FV12"
  let xd0 = AST.var rt (Register.toRegID R.XD0) "XD0"
  let xd2 = AST.var rt (Register.toRegID R.XD2) "XD2"
  let xd4 = AST.var rt (Register.toRegID R.XD4) "XD4"
  let xd6 = AST.var rt (Register.toRegID R.XD6) "XD6"
  let xd8 = AST.var rt (Register.toRegID R.XD8) "XD8"
  let xd10 = AST.var rt (Register.toRegID R.XD10) "XD10"
  let xd12 = AST.var rt (Register.toRegID R.XD12) "XD12"
  let xd14 = AST.var rt (Register.toRegID R.XD14) "XD14"
  let xf0 = AST.var rt (Register.toRegID R.XF0) "XF0"
  let xf1 = AST.var rt (Register.toRegID R.XF1) "XF1"
  let xf2 = AST.var rt (Register.toRegID R.XF2) "XF2"
  let xf3 = AST.var rt (Register.toRegID R.XF3) "XF3"
  let xf4 = AST.var rt (Register.toRegID R.XF4) "XF4"
  let xf5 = AST.var rt (Register.toRegID R.XF5) "XF5"
  let xf6 = AST.var rt (Register.toRegID R.XF6) "XF6"
  let xf7 = AST.var rt (Register.toRegID R.XF7) "XF7"
  let xf8 = AST.var rt (Register.toRegID R.XF8) "XF8"
  let xf9 = AST.var rt (Register.toRegID R.XF9) "XF9"
  let xf10 = AST.var rt (Register.toRegID R.XF10) "XF10"
  let xf11 = AST.var rt (Register.toRegID R.XF11) "XF11"
  let xf12 = AST.var rt (Register.toRegID R.XF12) "XF12"
  let xf13 = AST.var rt (Register.toRegID R.XF13) "XF13"
  let xf14 = AST.var rt (Register.toRegID R.XF14) "XF14"
  let xf15 = AST.var rt (Register.toRegID R.XF15) "XF15"
  let xmtrx = AST.var rt (Register.toRegID R.XMTRX) "XMTRX"
  let pteh = AST.var rt (Register.toRegID R.PTEH) "PTEH"
  let ptel = AST.var rt (Register.toRegID R.PTEL) "PTEL"
  let ptea = AST.var rt (Register.toRegID R.PTEA) "PTEA"
  let ttb = AST.var rt (Register.toRegID R.TTB) "TTB"
  let tea = AST.var rt (Register.toRegID R.TEA) "TEA"
  let mmucr = AST.var rt (Register.toRegID R.MMUCR) "MMUCR"
  let ccr = AST.var rt (Register.toRegID R.CCR) "CCR"
  let qACR0 = AST.var rt (Register.toRegID R.QACR0) "QACR0"
  let qACR1 = AST.var rt (Register.toRegID R.QACR1) "QACR1"
  let tra = AST.var rt (Register.toRegID R.TRA) "TRA"
  let expevt = AST.var rt (Register.toRegID R.EXPEVT) "EXPEVT"
  let intevt = AST.var rt (Register.toRegID R.INTEVT) "INTEVT"
  let md = AST.var rt (Register.toRegID R.MD) "MD"
  let rb = AST.var rt (Register.toRegID R.RB) "RB"
  let bl = AST.var rt (Register.toRegID R.BL) "BL"
  let fd = AST.var rt (Register.toRegID R.FD) "FD"
  let m = AST.var rt (Register.toRegID R.M) "M"
  let q = AST.var rt (Register.toRegID R.Q) "Q"
  let iMASK = AST.var rt (Register.toRegID R.IMASK) "IMASK"
  let s = AST.var rt (Register.toRegID R.S) "S"
  let t = AST.var rt (Register.toRegID R.T) "T"
  let fpscrRM = AST.var rt (Register.toRegID R.FPSCR_RM) "FPSCR_RM"
  let fpscrFLAG = AST.var rt (Register.toRegID R.FPSCR_FLAG) "FPSCR_FLAG"
  let fpscrENABLE = AST.var rt (Register.toRegID R.FPSCR_ENABLE) "FPSCR_ENABLE"
  let fpscrCAUSE = AST.var rt (Register.toRegID R.FPSCR_CAUSE) "FPSCR_CAUSE"
  let fpscrDN = AST.var rt (Register.toRegID R.FPSCR_DN) "FPSCR_DN"
  let fpscrPR = AST.var rt (Register.toRegID R.FPSCR_PR) "FPSCR_PR"
  let fpscrSZ = AST.var rt (Register.toRegID R.FPSCR_SZ) "FPSCR_SZ"
  let fpscrFR = AST.var rt (Register.toRegID R.FPSCR_FR) "FPSCR_FR"

  interface IRegisterFactory with
    member _.GetRegVar id =
      match Register.ofRegID id with
      | R.R0 -> r0
      | R.R1 -> r1
      | R.R2 -> r2
      | R.R3 -> r3
      | R.R4 -> r4
      | R.R5 -> r5
      | R.R6 -> r6
      | R.R7 -> r7
      | R.R8 -> r8
      | R.R9 -> r9
      | R.R10 -> r10
      | R.R11 -> r11
      | R.R12 -> r12
      | R.R13 -> r13
      | R.R14 -> r14
      | R.R15 -> r15
      | R.R0_BANK -> r0BANK
      | R.R1_BANK -> r1BANK
      | R.R2_BANK -> r2BANK
      | R.R3_BANK -> r3BANK
      | R.R4_BANK -> r4BANK
      | R.R5_BANK -> r5BANK
      | R.R6_BANK -> r6BANK
      | R.R7_BANK -> r7BANK
      | R.SR -> sr
      | R.GBR -> gbr
      | R.SSR -> ssr
      | R.SPC -> spc
      | R.SGR -> sgr
      | R.DBR -> dbr
      | R.VBR -> vbr
      | R.MACH -> mach
      | R.MACL -> macl
      | R.PR -> pr
      | R.FPUL -> fpul
      | R.PC -> pc
      | R.FPSCR -> fpscr
      | R.FPR0 -> fpr0
      | R.FPR1 -> fpr1
      | R.FPR2 -> fpr2
      | R.FPR3 -> fpr3
      | R.FPR4 -> fpr4
      | R.FPR5 -> fpr5
      | R.FPR6 -> fpr6
      | R.FPR7 -> fpr7
      | R.FPR8 -> fpr8
      | R.FPR9 -> fpr9
      | R.FPR10 -> fpr10
      | R.FPR11 -> fpr11
      | R.FPR12 -> fpr12
      | R.FPR13 -> fpr13
      | R.FPR14 -> fpr14
      | R.FPR15 -> fpr15
      | R.FR0 -> fr0
      | R.FR1 -> fr1
      | R.FR2 -> fr2
      | R.FR3 -> fr3
      | R.FR4 -> fr4
      | R.FR5 -> fr5
      | R.FR6 -> fr6
      | R.FR7 -> fr7
      | R.FR8 -> fr8
      | R.FR9 -> fr9
      | R.FR10 -> fr10
      | R.FR11 -> fr11
      | R.FR12 -> fr12
      | R.FR13 -> fr13
      | R.FR14 -> fr14
      | R.FR15 -> fr15
      | R.DR0 -> dr0
      | R.DR2 -> dr2
      | R.DR4 -> dr4
      | R.DR6 -> dr6
      | R.DR8 -> dr8
      | R.DR10 -> dr10
      | R.DR12 -> dr12
      | R.DR14 -> dr14
      | R.FV0 -> fv0
      | R.FV4 -> fv4
      | R.FV8 -> fv8
      | R.FV12 -> fv12
      | R.XD0 -> xd0
      | R.XD2 -> xd2
      | R.XD4 -> xd4
      | R.XD6 -> xd6
      | R.XD8 -> xd8
      | R.XD10 -> xd10
      | R.XD12 -> xd12
      | R.XD14 -> xd14
      | R.XF0 -> xf0
      | R.XF1 -> xf1
      | R.XF2 -> xf2
      | R.XF3 -> xf3
      | R.XF4 -> xf4
      | R.XF5 -> xf5
      | R.XF6 -> xf6
      | R.XF7 -> xf7
      | R.XF8 -> xf8
      | R.XF9 -> xf9
      | R.XF10 -> xf10
      | R.XF11 -> xf11
      | R.XF12 -> xf12
      | R.XF13 -> xf13
      | R.XF14 -> xf14
      | R.XF15 -> xf15
      | R.XMTRX -> xmtrx
      | R.PTEH -> pteh
      | R.PTEL -> ptel
      | R.PTEA -> ptea
      | R.TTB -> ttb
      | R.TEA -> tea
      | R.MMUCR -> mmucr
      | R.CCR -> ccr
      | R.QACR0 -> qACR0
      | R.QACR1 -> qACR1
      | R.TRA -> tra
      | R.EXPEVT -> expevt
      | R.INTEVT -> intevt
      | R.MD -> md
      | R.RB -> rb
      | R.BL -> bl
      | R.FD -> fd
      | R.M -> m
      | R.Q -> q
      | R.IMASK -> iMASK
      | R.S -> s
      | R.T -> t
      | R.FPSCR_RM -> fpscrRM
      | R.FPSCR_FLAG -> fpscrFLAG
      | R.FPSCR_ENABLE -> fpscrENABLE
      | R.FPSCR_CAUSE -> fpscrCAUSE
      | R.FPSCR_DN -> fpscrDN
      | R.FPSCR_PR -> fpscrPR
      | R.FPSCR_SZ -> fpscrSZ
      | R.FPSCR_FR -> fpscrFR
      | _ -> raise InvalidRegisterException

    member _.GetRegVar(name: string) =
      match name.ToLowerInvariant() with
      | "r0" -> r0
      | "r1" -> r1
      | "r2" -> r2
      | "r3" -> r3
      | "r4" -> r4
      | "r5" -> r5
      | "r6" -> r6
      | "r7" -> r7
      | "r8" -> r8
      | "r9" -> r9
      | "r10" -> r10
      | "r11" -> r11
      | "r12" -> r12
      | "r13" -> r13
      | "r14" -> r14
      | "r15" -> r15
      | "pc" -> pc
      | _ -> raise InvalidRegisterException

    member _.GetPseudoRegVar(_id, _idx) = Terminator.impossible ()

    member _.GetAllRegVars() =
      [| r0
         r1
         r2
         r3
         r4
         r5
         r6
         r7
         r8
         r9
         r10
         r11
         r12
         r13
         r14
         r15
         pc |]

    member _.GetGeneralRegVars() =
      [| r0
         r1
         r2
         r3
         r4
         r5
         r6
         r7
         r8
         r9
         r10
         r11
         r12
         r13
         r14
         r15 |]

    member _.GetRegisterID expr =
      match expr with
      | Var(_, id, _, _) -> id
      | PCVar(_) -> Register.toRegID Register.PC
      | _ -> raise InvalidRegisterException

    member _.GetRegisterID name =
      Register.ofString name |> Register.toRegID

    member _.GetRegisterIDAliases _ =
      Terminator.futureFeature ()

    member _.GetRegisterName rid =
      Register.ofRegID rid |> Register.toString

    member this.GetAllRegisterNames() =
      let regFactory = this :> IRegisterFactory
      regFactory.GetAllRegVars()
      |> Array.map (regFactory.GetRegisterID >> regFactory.GetRegisterName)

    member _.GetRegType rid =
      Register.ofRegID rid |> Register.toRegType

    member _.ProgramCounter =
      Register.PC |> Register.toRegID

    member _.StackPointer =
      Register.R15 |> Register.toRegID |> Some

    member _.FramePointer =
      Register.R14 |> Register.toRegID |> Some

    member _.IsProgramCounter rid =
      Register.toRegID Register.PC = rid

    member _.IsStackPointer rid =
      Register.toRegID Register.R15 = rid

    member _.IsFramePointer rid =
      Register.toRegID Register.R14 = rid
