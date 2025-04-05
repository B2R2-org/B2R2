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

namespace B2R2.FrontEnd.PARISC

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter

/// Shortcut for Register type.
type internal R = Register

type RegExprs (wordSize) =
  let var sz t name = AST.var sz t name

  (* PARISCs *)
  let regType = WordSize.toRegType wordSize

  member val GR0 = var regType (Register.toRegID R.GR0) "GR0" with get
  member val GR1 = var regType (Register.toRegID R.GR1) "GR1" with get
  member val GR2 = var regType (Register.toRegID R.GR2) "GR2" with get
  member val GR3 = var regType (Register.toRegID R.GR3) "GR3" with get
  member val GR4 = var regType (Register.toRegID R.GR4) "GR4" with get
  member val GR5 = var regType (Register.toRegID R.GR5) "GR5" with get
  member val GR6 = var regType (Register.toRegID R.GR6) "GR6" with get
  member val GR7 = var regType (Register.toRegID R.GR7) "GR7" with get
  member val GR8 = var regType (Register.toRegID R.GR8) "GR8" with get
  member val GR9 = var regType (Register.toRegID R.GR9) "GR9" with get
  member val GR10 = var regType (Register.toRegID R.GR10) "GR10" with get
  member val GR11 = var regType (Register.toRegID R.GR11) "GR11" with get
  member val GR12 = var regType (Register.toRegID R.GR12) "GR12" with get
  member val GR13 = var regType (Register.toRegID R.GR13) "GR13" with get
  member val GR14 = var regType (Register.toRegID R.GR14) "GR14" with get
  member val GR15 = var regType (Register.toRegID R.GR15) "GR15" with get
  member val GR16 = var regType (Register.toRegID R.GR16) "GR16" with get
  member val GR17 = var regType (Register.toRegID R.GR17) "GR17" with get
  member val GR18 = var regType (Register.toRegID R.GR18) "GR18" with get
  member val GR19 = var regType (Register.toRegID R.GR19) "GR19" with get
  member val GR20 = var regType (Register.toRegID R.GR20) "GR20" with get
  member val GR21 = var regType (Register.toRegID R.GR21) "GR21" with get
  member val GR22 = var regType (Register.toRegID R.GR22) "GR22" with get
  member val GR23 = var regType (Register.toRegID R.GR23) "GR23" with get
  member val GR24 = var regType (Register.toRegID R.GR24) "GR24" with get
  member val GR25 = var regType (Register.toRegID R.GR25) "GR25" with get
  member val GR26 = var regType (Register.toRegID R.GR26) "GR26" with get
  member val GR27 = var regType (Register.toRegID R.GR27) "GR27" with get
  member val GR28 = var regType (Register.toRegID R.GR28) "GR28" with get
  member val GR29 = var regType (Register.toRegID R.GR29) "GR29" with get
  member val GR30 = var regType (Register.toRegID R.GR30) "GR30" with get
  member val GR31 = var regType (Register.toRegID R.GR31) "GR31" with get
  member val SR0 = var regType (Register.toRegID R.SR0) "SR0" with get
  member val SR1 = var regType (Register.toRegID R.SR1) "SR1" with get
  member val SR2 = var regType (Register.toRegID R.SR2) "SR2" with get
  member val SR3 = var regType (Register.toRegID R.SR3) "SR3" with get
  member val SR4 = var regType (Register.toRegID R.SR4) "SR4" with get
  member val SR5 = var regType (Register.toRegID R.SR5) "SR5" with get
  member val SR6 = var regType (Register.toRegID R.SR6) "SR6" with get
  member val SR7 = var regType (Register.toRegID R.SR7) "SR7" with get
  member val IAOQBACK =
    var regType (Register.toRegID R.IAOQ_Back) "IAOQ_BACK" with get
  member val IAOQFRONT =
    var regType (Register.toRegID R.IAOQ_Front) "IAOQ_FRONT" with get
  member val IASQBACK =
    var regType (Register.toRegID R.IASQ_Back) "IASQ_BACK" with get
  member val IASQFRONT =
    var regType (Register.toRegID R.IASQ_Front) "IASQ_FRONT" with get
  member val PSW = var 64<rt> (Register.toRegID R.PSW) "PSW" with get
  member val CR0 = var regType (Register.toRegID R.CR0) "CR0" with get
  member val CR1 = var regType (Register.toRegID R.CR1) "CR1" with get
  member val CR2 = var regType (Register.toRegID R.CR2) "CR2" with get
  member val CR3 = var regType (Register.toRegID R.CR3) "CR3" with get
  member val CR4 = var regType (Register.toRegID R.CR4) "CR4" with get
  member val CR5 = var regType (Register.toRegID R.CR5) "CR5" with get
  member val CR6 = var regType (Register.toRegID R.CR6) "CR6" with get
  member val CR7 = var regType (Register.toRegID R.CR7) "CR7" with get
  member val CR8 = var regType (Register.toRegID R.CR8) "CR8" with get
  member val CR9 = var regType (Register.toRegID R.CR9) "CR9" with get
  member val CR10 = var regType (Register.toRegID R.CR10) "CR10" with get
  member val CR11 = var regType (Register.toRegID R.CR11) "CR11" with get
  member val CR12 = var regType (Register.toRegID R.CR12) "CR12" with get
  member val CR13 = var regType (Register.toRegID R.CR13) "CR13" with get
  member val CR14 = var regType (Register.toRegID R.CR14) "CR14" with get
  member val CR15 = var regType (Register.toRegID R.CR15) "CR15" with get
  member val CR16 = var regType (Register.toRegID R.CR16) "CR16" with get
  member val CR17 = var regType (Register.toRegID R.CR17) "CR17" with get
  member val CR18 = var regType (Register.toRegID R.CR18) "CR18" with get
  member val CR19 = var regType (Register.toRegID R.CR19) "CR19" with get
  member val CR20 = var regType (Register.toRegID R.CR20) "CR20" with get
  member val CR21 = var regType (Register.toRegID R.CR21) "CR21" with get
  member val CR22 = var regType (Register.toRegID R.CR22) "CR22" with get
  member val CR23 = var regType (Register.toRegID R.CR23) "CR23" with get
  member val CR24 = var regType (Register.toRegID R.CR24) "CR24" with get
  member val CR25 = var regType (Register.toRegID R.CR25) "CR25" with get
  member val CR26 = var regType (Register.toRegID R.CR26) "CR26" with get
  member val CR27 = var regType (Register.toRegID R.CR27) "CR27" with get
  member val CR28 = var regType (Register.toRegID R.CR28) "CR28" with get
  member val CR29 = var regType (Register.toRegID R.CR29) "CR29" with get
  member val CR30 = var regType (Register.toRegID R.CR30) "CR30" with get
  member val CR31 = var regType (Register.toRegID R.CR31) "CR31" with get
  member val FPR0 = var regType (Register.toRegID R.FPR0) "FPR0" with get
  member val FPR1 = var regType (Register.toRegID R.FPR1) "FPR1" with get
  member val FPR2 = var regType (Register.toRegID R.FPR2) "FPR2" with get
  member val FPR3 = var regType (Register.toRegID R.FPR3) "FPR3" with get
  member val FPR4 = var regType (Register.toRegID R.FPR4) "FPR4" with get
  member val FPR5 = var regType (Register.toRegID R.FPR5) "FPR5" with get
  member val FPR6 = var regType (Register.toRegID R.FPR6) "FPR6" with get
  member val FPR7 = var regType (Register.toRegID R.FPR7) "FPR7" with get
  member val FPR8 = var regType (Register.toRegID R.FPR8) "FPR8" with get
  member val FPR9 = var regType (Register.toRegID R.FPR9) "FPR9" with get
  member val FPR10 =
    var regType (Register.toRegID R.FPR10) "FPR10" with get
  member val FPR11 =
    var regType (Register.toRegID R.FPR11) "FPR11" with get
  member val FPR12 =
    var regType (Register.toRegID R.FPR12) "FPR12" with get
  member val FPR13 =
    var regType (Register.toRegID R.FPR13) "FPR13" with get
  member val FPR14 =
    var regType (Register.toRegID R.FPR14) "FPR14" with get
  member val FPR15 =
    var regType (Register.toRegID R.FPR15) "FPR15" with get
  member val FPR16 =
    var regType (Register.toRegID R.FPR16) "FPR16" with get
  member val FPR17 =
    var regType (Register.toRegID R.FPR17) "FPR17" with get
  member val FPR18 =
    var regType (Register.toRegID R.FPR18) "FPR18" with get
  member val FPR19 =
    var regType (Register.toRegID R.FPR19) "FPR19" with get
  member val FPR20 =
    var regType (Register.toRegID R.FPR20) "FPR20" with get
  member val FPR21 =
    var regType (Register.toRegID R.FPR21) "FPR21" with get
  member val FPR22 =
    var regType (Register.toRegID R.FPR22) "FPR22" with get
  member val FPR23 =
    var regType (Register.toRegID R.FPR23) "FPR23" with get
  member val FPR24 =
    var regType (Register.toRegID R.FPR24) "FPR24" with get
  member val FPR25 =
    var regType (Register.toRegID R.FPR25) "FPR25" with get
  member val FPR26 =
    var regType (Register.toRegID R.FPR26) "FPR26" with get
  member val FPR27 =
    var regType (Register.toRegID R.FPR27) "FPR27" with get
  member val FPR28 =
    var regType (Register.toRegID R.FPR28) "FPR28" with get
  member val FPR29 =
    var regType (Register.toRegID R.FPR29) "FPR29" with get
  member val FPR30 =
    var regType (Register.toRegID R.FPR30) "FPR30" with get
  member val FPR31 =
    var regType (Register.toRegID R.FPR31) "FPR31" with get

  member this.GetRegVar (name) =
    match name with
    | R.GR0 -> this.GR0
    | R.GR1 -> this.GR1
    | R.GR2 -> this.GR2
    | R.GR3 -> this.GR3
    | R.GR4 -> this.GR4
    | R.GR5 -> this.GR5
    | R.GR6 -> this.GR6
    | R.GR7 -> this.GR7
    | R.GR8 -> this.GR8
    | R.GR9 -> this.GR9
    | R.GR10 -> this.GR10
    | R.GR11 -> this.GR11
    | R.GR12 -> this.GR12
    | R.GR13 -> this.GR13
    | R.GR14 -> this.GR14
    | R.GR15 -> this.GR15
    | R.GR16 -> this.GR16
    | R.GR17 -> this.GR17
    | R.GR18 -> this.GR18
    | R.GR19 -> this.GR19
    | R.GR20 -> this.GR20
    | R.GR21 -> this.GR21
    | R.GR22 -> this.GR22
    | R.GR23 -> this.GR23
    | R.GR24 -> this.GR24
    | R.GR25 -> this.GR25
    | R.GR26 -> this.GR26
    | R.GR27 -> this.GR27
    | R.GR28 -> this.GR28
    | R.GR29 -> this.GR29
    | R.GR30 -> this.GR30
    | R.GR31 -> this.GR31
    | R.SR0 -> this.SR0
    | R.SR1 -> this.SR1
    | R.SR2 -> this.SR2
    | R.SR3 -> this.SR3
    | R.SR4 -> this.SR4
    | R.SR5 -> this.SR5
    | R.SR6 -> this.SR6
    | R.SR7 -> this.SR7
    | R.IAOQ_Back -> this.IAOQBACK
    | R.IAOQ_Front -> this.IAOQFRONT
    | R.IASQ_Back -> this.IASQBACK
    | R.IASQ_Front -> this.IASQFRONT
    | R.PSW -> this.PSW
    | R.CR0 -> this.CR0
    | R.CR1 -> this.CR1
    | R.CR2 -> this.CR2
    | R.CR3 -> this.CR3
    | R.CR4 -> this.CR4
    | R.CR5 -> this.CR5
    | R.CR6 -> this.CR6
    | R.CR7 -> this.CR7
    | R.CR8 -> this.CR8
    | R.CR9 -> this.CR9
    | R.CR10 -> this.CR10
    | R.CR11 -> this.CR11
    | R.CR12 -> this.CR12
    | R.CR13 -> this.CR13
    | R.CR14 -> this.CR14
    | R.CR15 -> this.CR15
    | R.CR16 -> this.CR16
    | R.CR17 -> this.CR17
    | R.CR18 -> this.CR18
    | R.CR19 -> this.CR19
    | R.CR20 -> this.CR20
    | R.CR21 -> this.CR21
    | R.CR22 -> this.CR22
    | R.CR23 -> this.CR23
    | R.CR24 -> this.CR24
    | R.CR25 -> this.CR25
    | R.CR26 -> this.CR26
    | R.CR27 -> this.CR27
    | R.CR28 -> this.CR28
    | R.CR29 -> this.CR29
    | R.CR30 -> this.CR30
    | R.CR31 -> this.CR31
    | R.FPR0 -> this.FPR0
    | R.FPR1 -> this.FPR1
    | R.FPR2 -> this.FPR2
    | R.FPR3 -> this.FPR3
    | R.FPR4 -> this.FPR4
    | R.FPR5 -> this.FPR5
    | R.FPR6 -> this.FPR6
    | R.FPR7 -> this.FPR7
    | R.FPR8 -> this.FPR8
    | R.FPR9 -> this.FPR9
    | R.FPR10 -> this.FPR10
    | R.FPR11 -> this.FPR11
    | R.FPR12 -> this.FPR12
    | R.FPR13 -> this.FPR13
    | R.FPR14 -> this.FPR14
    | R.FPR15 -> this.FPR15
    | R.FPR16 -> this.FPR16
    | R.FPR17 -> this.FPR17
    | R.FPR18 -> this.FPR18
    | R.FPR19 -> this.FPR19
    | R.FPR20 -> this.FPR20
    | R.FPR21 -> this.FPR21
    | R.FPR22 -> this.FPR22
    | R.FPR23 -> this.FPR23
    | R.FPR24 -> this.FPR24
    | R.FPR25 -> this.FPR25
    | R.FPR26 -> this.FPR26
    | R.FPR27 -> this.FPR27
    | R.FPR28 -> this.FPR28
    | R.FPR29 -> this.FPR29
    | R.FPR30 -> this.FPR30
    | R.FPR31 -> this.FPR31
    | _ -> raise UnhandledRegExprException

// vim: set tw=80 sts=2 sw=2:
