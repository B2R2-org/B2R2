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
type RegisterFactory(isa: ISA) =
  (* Each variable takes the width RegisterHelper assigns it, so a register
     variable and the GetRegType this factory reports for it agree: the T bit is
     one bit wide, a double-precision pair is sixty-four. Building them all at
     the word size instead made every flag a thirty-two-bit variable that the
     same factory then described as one bit. *)
  let var r =
    let name = Register.toString r
    let rt = RegisterHelper.toRegType r
    AST.var rt (Register.toRegID r) (name.ToUpperInvariant())

  let r0 = var R.R0
  let r1 = var R.R1
  let r2 = var R.R2
  let r3 = var R.R3
  let r4 = var R.R4
  let r5 = var R.R5
  let r6 = var R.R6
  let r7 = var R.R7
  let r8 = var R.R8
  let r9 = var R.R9
  let r10 = var R.R10
  let r11 = var R.R11
  let r12 = var R.R12
  let r13 = var R.R13
  let r14 = var R.R14
  let r15 = var R.R15
  let r0BANK = var R.R0_BANK
  let r1BANK = var R.R1_BANK
  let r2BANK = var R.R2_BANK
  let r3BANK = var R.R3_BANK
  let r4BANK = var R.R4_BANK
  let r5BANK = var R.R5_BANK
  let r6BANK = var R.R6_BANK
  let r7BANK = var R.R7_BANK
  let sr = var R.SR
  let gbr = var R.GBR
  let ssr = var R.SSR
  let spc = var R.SPC
  let sgr = var R.SGR
  let dbr = var R.DBR
  let vbr = var R.VBR
  let mach = var R.MACH
  let macl = var R.MACL
  let pr = var R.PR
  let fpul = var R.FPUL
  let pc = var R.PC
  let npc = var R.NPC
  let fpscr = var R.FPSCR
  let fpr0 = var R.FPR0
  let fpr1 = var R.FPR1
  let fpr2 = var R.FPR2
  let fpr3 = var R.FPR3
  let fpr4 = var R.FPR4
  let fpr5 = var R.FPR5
  let fpr6 = var R.FPR6
  let fpr7 = var R.FPR7
  let fpr8 = var R.FPR8
  let fpr9 = var R.FPR9
  let fpr10 = var R.FPR10
  let fpr11 = var R.FPR11
  let fpr12 = var R.FPR12
  let fpr13 = var R.FPR13
  let fpr14 = var R.FPR14
  let fpr15 = var R.FPR15
  let fr0 = var R.FR0
  let fr1 = var R.FR1
  let fr2 = var R.FR2
  let fr3 = var R.FR3
  let fr4 = var R.FR4
  let fr5 = var R.FR5
  let fr6 = var R.FR6
  let fr7 = var R.FR7
  let fr8 = var R.FR8
  let fr9 = var R.FR9
  let fr10 = var R.FR10
  let fr11 = var R.FR11
  let fr12 = var R.FR12
  let fr13 = var R.FR13
  let fr14 = var R.FR14
  let fr15 = var R.FR15
  let dr0 = var R.DR0
  let dr2 = var R.DR2
  let dr4 = var R.DR4
  let dr6 = var R.DR6
  let dr8 = var R.DR8
  let dr10 = var R.DR10
  let dr12 = var R.DR12
  let dr14 = var R.DR14
  let fv0 = var R.FV0
  let fv4 = var R.FV4
  let fv8 = var R.FV8
  let fv12 = var R.FV12
  let xd0 = var R.XD0
  let xd2 = var R.XD2
  let xd4 = var R.XD4
  let xd6 = var R.XD6
  let xd8 = var R.XD8
  let xd10 = var R.XD10
  let xd12 = var R.XD12
  let xd14 = var R.XD14
  let xf0 = var R.XF0
  let xf1 = var R.XF1
  let xf2 = var R.XF2
  let xf3 = var R.XF3
  let xf4 = var R.XF4
  let xf5 = var R.XF5
  let xf6 = var R.XF6
  let xf7 = var R.XF7
  let xf8 = var R.XF8
  let xf9 = var R.XF9
  let xf10 = var R.XF10
  let xf11 = var R.XF11
  let xf12 = var R.XF12
  let xf13 = var R.XF13
  let xf14 = var R.XF14
  let xf15 = var R.XF15
  let xmtrx = var R.XMTRX
  let pteh = var R.PTEH
  let ptel = var R.PTEL
  let ptea = var R.PTEA
  let ttb = var R.TTB
  let tea = var R.TEA
  let mmucr = var R.MMUCR
  let ccr = var R.CCR
  let qACR0 = var R.QACR0
  let qACR1 = var R.QACR1
  let tra = var R.TRA
  let expevt = var R.EXPEVT
  let intevt = var R.INTEVT
  let md = var R.MD
  let rb = var R.RB
  let bl = var R.BL
  let fd = var R.FD
  let m = var R.M
  let q = var R.Q
  let iMASK = var R.IMASK
  let s = var R.S
  let t = var R.T
  let fpscrRM = var R.FPSCR_RM
  let fpscrFLAG = var R.FPSCR_FLAG
  let fpscrENABLE = var R.FPSCR_ENABLE
  let fpscrCAUSE = var R.FPSCR_CAUSE
  let fpscrDN = var R.FPSCR_DN
  let fpscrPR = var R.FPSCR_PR
  let fpscrSZ = var R.FPSCR_SZ
  let fpscrFR = var R.FPSCR_FR

  interface IRegisterFactory with
    member _.ISA = isa

    member _.ProgramCounter = Register.PC |> Register.toRegID

    member _.StackPointer = Register.R15 |> Register.toRegID |> Some

    member _.FramePointer = Register.R14 |> Register.toRegID |> Some

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
      | R.NPC -> npc
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
      | "npc" -> npc
      | "pr" -> pr
      | "gbr" -> gbr
      | "t" -> t
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
         pc
         npc
         pr
         gbr
         mach
         macl
         t |]

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

    member _.GetRegisterID name = Register.ofString name |> Register.toRegID

    member _.GetRegisterIDAliases _ = Terminator.futureFeature ()

    member _.GetRegisterName rid = Register.ofRegID rid |> Register.toString

    member this.GetAllRegisterNames() =
      let regFactory = this :> IRegisterFactory
      regFactory.GetAllRegVars()
      |> Array.map (regFactory.GetRegisterID >> regFactory.GetRegisterName)

    member _.GetRegType rid = Register.ofRegID rid |> RegisterHelper.toRegType

    member _.IsProgramCounter rid = Register.toRegID Register.PC = rid

    member _.IsStackPointer rid = Register.toRegID Register.R15 = rid

    member _.IsFramePointer rid = Register.toRegID Register.R14 = rid
