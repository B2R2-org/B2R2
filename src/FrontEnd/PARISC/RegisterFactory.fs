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

open System.Runtime.CompilerServices
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter
open type Register

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.PARISC.Tests")>]
do ()

/// Represents a factory for accessing various PARISC register variables.
type RegisterFactory(wordSize) =
  let rt = WordSize.toRegType wordSize

  let gr0 = AST.var rt (Register.toRegID GR0) "GR0"
  let gr1 = AST.var rt (Register.toRegID GR1) "GR1"
  let gr2 = AST.var rt (Register.toRegID GR2) "GR2"
  let gr3 = AST.var rt (Register.toRegID GR3) "GR3"
  let gr4 = AST.var rt (Register.toRegID GR4) "GR4"
  let gr5 = AST.var rt (Register.toRegID GR5) "GR5"
  let gr6 = AST.var rt (Register.toRegID GR6) "GR6"
  let gr7 = AST.var rt (Register.toRegID GR7) "GR7"
  let gr8 = AST.var rt (Register.toRegID GR8) "GR8"
  let gr9 = AST.var rt (Register.toRegID GR9) "GR9"
  let gr10 = AST.var rt (Register.toRegID GR10) "GR10"
  let gr11 = AST.var rt (Register.toRegID GR11) "GR11"
  let gr12 = AST.var rt (Register.toRegID GR12) "GR12"
  let gr13 = AST.var rt (Register.toRegID GR13) "GR13"
  let gr14 = AST.var rt (Register.toRegID GR14) "GR14"
  let gr15 = AST.var rt (Register.toRegID GR15) "GR15"
  let gr16 = AST.var rt (Register.toRegID GR16) "GR16"
  let gr17 = AST.var rt (Register.toRegID GR17) "GR17"
  let gr18 = AST.var rt (Register.toRegID GR18) "GR18"
  let gr19 = AST.var rt (Register.toRegID GR19) "GR19"
  let gr20 = AST.var rt (Register.toRegID GR20) "GR20"
  let gr21 = AST.var rt (Register.toRegID GR21) "GR21"
  let gr22 = AST.var rt (Register.toRegID GR22) "GR22"
  let gr23 = AST.var rt (Register.toRegID GR23) "GR23"
  let gr24 = AST.var rt (Register.toRegID GR24) "GR24"
  let gr25 = AST.var rt (Register.toRegID GR25) "GR25"
  let gr26 = AST.var rt (Register.toRegID GR26) "GR26"
  let gr27 = AST.var rt (Register.toRegID GR27) "GR27"
  let gr28 = AST.var rt (Register.toRegID GR28) "GR28"
  let gr29 = AST.var rt (Register.toRegID GR29) "GR29"
  let gr30 = AST.var rt (Register.toRegID GR30) "GR30"
  let gr31 = AST.var rt (Register.toRegID GR31) "GR31"
  let sr0 = AST.var rt (Register.toRegID SR0) "SR0"
  let sr1 = AST.var rt (Register.toRegID SR1) "SR1"
  let sr2 = AST.var rt (Register.toRegID SR2) "SR2"
  let sr3 = AST.var rt (Register.toRegID SR3) "SR3"
  let sr4 = AST.var rt (Register.toRegID SR4) "SR4"
  let sr5 = AST.var rt (Register.toRegID SR5) "SR5"
  let sr6 = AST.var rt (Register.toRegID SR6) "SR6"
  let sr7 = AST.var rt (Register.toRegID SR7) "SR7"
  let iaoqback = AST.var rt (Register.toRegID IAOQ_Back) "IAOQ_BACK"
  let iaoqfront = AST.var rt (Register.toRegID IAOQ_Front) "IAOQ_FRONT"
  let iasqback = AST.var rt (Register.toRegID IASQ_Back) "IASQ_BACK"
  let iasqfront = AST.var rt (Register.toRegID IASQ_Front) "IASQ_FRONT"
  let psw = AST.var 64<rt> (Register.toRegID PSW) "PSW"
  let cr0 = AST.var rt (Register.toRegID CR0) "CR0"
  let cr1 = AST.var rt (Register.toRegID CR1) "CR1"
  let cr2 = AST.var rt (Register.toRegID CR2) "CR2"
  let cr3 = AST.var rt (Register.toRegID CR3) "CR3"
  let cr4 = AST.var rt (Register.toRegID CR4) "CR4"
  let cr5 = AST.var rt (Register.toRegID CR5) "CR5"
  let cr6 = AST.var rt (Register.toRegID CR6) "CR6"
  let cr7 = AST.var rt (Register.toRegID CR7) "CR7"
  let cr8 = AST.var rt (Register.toRegID CR8) "CR8"
  let cr9 = AST.var rt (Register.toRegID CR9) "CR9"
  let cr10 = AST.var rt (Register.toRegID CR10) "CR10"
  let cr11 = AST.var rt (Register.toRegID CR11) "CR11"
  let cr12 = AST.var rt (Register.toRegID CR12) "CR12"
  let cr13 = AST.var rt (Register.toRegID CR13) "CR13"
  let cr14 = AST.var rt (Register.toRegID CR14) "CR14"
  let cr15 = AST.var rt (Register.toRegID CR15) "CR15"
  let cr16 = AST.var rt (Register.toRegID CR16) "CR16"
  let cr17 = AST.var rt (Register.toRegID CR17) "CR17"
  let cr18 = AST.var rt (Register.toRegID CR18) "CR18"
  let cr19 = AST.var rt (Register.toRegID CR19) "CR19"
  let cr20 = AST.var rt (Register.toRegID CR20) "CR20"
  let cr21 = AST.var rt (Register.toRegID CR21) "CR21"
  let cr22 = AST.var rt (Register.toRegID CR22) "CR22"
  let cr23 = AST.var rt (Register.toRegID CR23) "CR23"
  let cr24 = AST.var rt (Register.toRegID CR24) "CR24"
  let cr25 = AST.var rt (Register.toRegID CR25) "CR25"
  let cr26 = AST.var rt (Register.toRegID CR26) "CR26"
  let cr27 = AST.var rt (Register.toRegID CR27) "CR27"
  let cr28 = AST.var rt (Register.toRegID CR28) "CR28"
  let cr29 = AST.var rt (Register.toRegID CR29) "CR29"
  let cr30 = AST.var rt (Register.toRegID CR30) "CR30"
  let cr31 = AST.var rt (Register.toRegID CR31) "CR31"
  let fpr0 = AST.var rt (Register.toRegID FPR0) "FPR0"
  let fpr1 = AST.var rt (Register.toRegID FPR1) "FPR1"
  let fpr2 = AST.var rt (Register.toRegID FPR2) "FPR2"
  let fpr3 = AST.var rt (Register.toRegID FPR3) "FPR3"
  let fpr4 = AST.var rt (Register.toRegID FPR4) "FPR4"
  let fpr5 = AST.var rt (Register.toRegID FPR5) "FPR5"
  let fpr6 = AST.var rt (Register.toRegID FPR6) "FPR6"
  let fpr7 = AST.var rt (Register.toRegID FPR7) "FPR7"
  let fpr8 = AST.var rt (Register.toRegID FPR8) "FPR8"
  let fpr9 = AST.var rt (Register.toRegID FPR9) "FPR9"
  let fpr10 = AST.var rt (Register.toRegID FPR10) "FPR10"
  let fpr11 = AST.var rt (Register.toRegID FPR11) "FPR11"
  let fpr12 = AST.var rt (Register.toRegID FPR12) "FPR12"
  let fpr13 = AST.var rt (Register.toRegID FPR13) "FPR13"
  let fpr14 = AST.var rt (Register.toRegID FPR14) "FPR14"
  let fpr15 = AST.var rt (Register.toRegID FPR15) "FPR15"
  let fpr16 = AST.var rt (Register.toRegID FPR16) "FPR16"
  let fpr17 = AST.var rt (Register.toRegID FPR17) "FPR17"
  let fpr18 = AST.var rt (Register.toRegID FPR18) "FPR18"
  let fpr19 = AST.var rt (Register.toRegID FPR19) "FPR19"
  let fpr20 = AST.var rt (Register.toRegID FPR20) "FPR20"
  let fpr21 = AST.var rt (Register.toRegID FPR21) "FPR21"
  let fpr22 = AST.var rt (Register.toRegID FPR22) "FPR22"
  let fpr23 = AST.var rt (Register.toRegID FPR23) "FPR23"
  let fpr24 = AST.var rt (Register.toRegID FPR24) "FPR24"
  let fpr25 = AST.var rt (Register.toRegID FPR25) "FPR25"
  let fpr26 = AST.var rt (Register.toRegID FPR26) "FPR26"
  let fpr27 = AST.var rt (Register.toRegID FPR27) "FPR27"
  let fpr28 = AST.var rt (Register.toRegID FPR28) "FPR28"
  let fpr29 = AST.var rt (Register.toRegID FPR29) "FPR29"
  let fpr30 = AST.var rt (Register.toRegID FPR30) "FPR30"
  let fpr31 = AST.var rt (Register.toRegID FPR31) "FPR31"

  interface IRegisterFactory with

    member _.GetRegVar rid =
      match Register.ofRegID rid with
      | Register.GR0 -> gr0
      | Register.GR1 -> gr1
      | Register.GR2 -> gr2
      | Register.GR3 -> gr3
      | Register.GR4 -> gr4
      | Register.GR5 -> gr5
      | Register.GR6 -> gr6
      | Register.GR7 -> gr7
      | Register.GR8 -> gr8
      | Register.GR9 -> gr9
      | Register.GR10 -> gr10
      | Register.GR11 -> gr11
      | Register.GR12 -> gr12
      | Register.GR13 -> gr13
      | Register.GR14 -> gr14
      | Register.GR15 -> gr15
      | Register.GR16 -> gr16
      | Register.GR17 -> gr17
      | Register.GR18 -> gr18
      | Register.GR19 -> gr19
      | Register.GR20 -> gr20
      | Register.GR21 -> gr21
      | Register.GR22 -> gr22
      | Register.GR23 -> gr23
      | Register.GR24 -> gr24
      | Register.GR25 -> gr25
      | Register.GR26 -> gr26
      | Register.GR27 -> gr27
      | Register.GR28 -> gr28
      | Register.GR29 -> gr29
      | Register.GR30 -> gr30
      | Register.GR31 -> gr31
      | Register.SR0 -> sr0
      | Register.SR1 -> sr1
      | Register.SR2 -> sr2
      | Register.SR3 -> sr3
      | Register.SR4 -> sr4
      | Register.SR5 -> sr5
      | Register.SR6 -> sr6
      | Register.SR7 -> sr7
      | Register.IAOQ_Back -> iaoqback
      | Register.IAOQ_Front -> iaoqfront
      | Register.IASQ_Back -> iasqback
      | Register.IASQ_Front -> iasqfront
      | Register.PSW -> psw
      | Register.CR0 -> cr0
      | Register.CR1 -> cr1
      | Register.CR2 -> cr2
      | Register.CR3 -> cr3
      | Register.CR4 -> cr4
      | Register.CR5 -> cr5
      | Register.CR6 -> cr6
      | Register.CR7 -> cr7
      | Register.CR8 -> cr8
      | Register.CR9 -> cr9
      | Register.CR10 -> cr10
      | Register.CR11 -> cr11
      | Register.CR12 -> cr12
      | Register.CR13 -> cr13
      | Register.CR14 -> cr14
      | Register.CR15 -> cr15
      | Register.CR16 -> cr16
      | Register.CR17 -> cr17
      | Register.CR18 -> cr18
      | Register.CR19 -> cr19
      | Register.CR20 -> cr20
      | Register.CR21 -> cr21
      | Register.CR22 -> cr22
      | Register.CR23 -> cr23
      | Register.CR24 -> cr24
      | Register.CR25 -> cr25
      | Register.CR26 -> cr26
      | Register.CR27 -> cr27
      | Register.CR28 -> cr28
      | Register.CR29 -> cr29
      | Register.CR30 -> cr30
      | Register.CR31 -> cr31
      | Register.FPR0 -> fpr0
      | Register.FPR1 -> fpr1
      | Register.FPR2 -> fpr2
      | Register.FPR3 -> fpr3
      | Register.FPR4 -> fpr4
      | Register.FPR5 -> fpr5
      | Register.FPR6 -> fpr6
      | Register.FPR7 -> fpr7
      | Register.FPR8 -> fpr8
      | Register.FPR9 -> fpr9
      | Register.FPR10 -> fpr10
      | Register.FPR11 -> fpr11
      | Register.FPR12 -> fpr12
      | Register.FPR13 -> fpr13
      | Register.FPR14 -> fpr14
      | Register.FPR15 -> fpr15
      | Register.FPR16 -> fpr16
      | Register.FPR17 -> fpr17
      | Register.FPR18 -> fpr18
      | Register.FPR19 -> fpr19
      | Register.FPR20 -> fpr20
      | Register.FPR21 -> fpr21
      | Register.FPR22 -> fpr22
      | Register.FPR23 -> fpr23
      | Register.FPR24 -> fpr24
      | Register.FPR25 -> fpr25
      | Register.FPR26 -> fpr26
      | Register.FPR27 -> fpr27
      | Register.FPR28 -> fpr28
      | Register.FPR29 -> fpr29
      | Register.FPR30 -> fpr30
      | Register.FPR31 -> fpr31
      | _ -> raise InvalidRegisterException

    member _.GetPseudoRegVar(_id, _idx) = Terminator.impossible ()

    member _.GetAllRegVars() =
      [| gr0
         gr1
         gr2
         gr3
         gr4
         gr5
         gr6
         gr7
         gr8
         gr9
         gr10
         gr11
         gr12
         gr13
         gr14
         gr15
         gr16
         gr17
         gr18
         gr19
         gr20
         gr21
         gr22
         gr23
         gr24
         gr25
         gr26
         gr27
         gr28
         gr29
         gr30
         gr31
         sr0
         sr1
         sr2
         sr3
         sr4
         sr5
         sr6
         sr7
         iaoqback
         iaoqfront
         iasqback
         iasqfront
         cr0
         cr1
         cr2
         cr3
         cr4
         cr5
         cr6
         cr7
         cr8
         cr9
         cr10
         cr11
         cr12
         cr13
         cr14
         cr15
         cr16
         cr17
         cr18
         cr19
         cr20
         cr21
         cr22
         cr23
         cr24
         cr25
         cr26
         cr27
         cr28
         cr29
         cr30
         cr31
         fpr0
         fpr1
         fpr2
         fpr3
         fpr4
         fpr5
         fpr6
         fpr7
         fpr8
         fpr9
         fpr10
         fpr11
         fpr12
         fpr13
         fpr14
         fpr15
         fpr16
         fpr17
         fpr18
         fpr19
         fpr20
         fpr21
         fpr22
         fpr23
         fpr24
         fpr25
         fpr26
         fpr27
         fpr28
         fpr29
         fpr30
         fpr31 |]

    member this.GetAllRegStrings() =
      let regFactory = this :> IRegisterFactory
      regFactory.GetAllRegVars()
      |> Array.map (regFactory.GetRegisterID >> regFactory.GetRegString)

    member _.GetGeneralRegVars() =
      [| gr0
         gr1
         gr2
         gr3
         gr4
         gr5
         gr6
         gr7
         gr8
         gr9
         gr10
         gr11
         gr12
         gr13
         gr14
         gr15
         gr16
         gr17
         gr18
         gr19
         gr20
         gr21
         gr22
         gr23
         gr24
         gr25
         gr26
         gr27
         gr28
         gr29
         gr30
         gr31 |]

    member _.GetRegisterID e =
      match e with
      | Var(_, id, _, _) -> id
      | PCVar _ -> Register.toRegID CR18
      | _ -> raise InvalidRegisterException

    member this.GetRegVar str =
      Register.ofString str
      |> Register.toRegID
      |> (this :> IRegisterFactory).GetRegVar

    member _.GetRegisterID str =
      Register.ofString str |> Register.toRegID

    member _.GetRegString rid =
      Register.toString (Register.ofRegID rid)

    member _.GetRegType _rid =
      WordSize.toRegType wordSize

    member _.GetRegisterIDAliases rid =
      [| rid |]

    member _.ProgramCounter =
      IAOQ_Front |> Register.toRegID

    member _.StackPointer =
      GR30 |> Register.toRegID |> Some

    member _.FramePointer =
      GR3 |> Register.toRegID |> Some

    member this.IsProgramCounter rid =
      (this :> IRegisterFactory).ProgramCounter = rid

    member _.IsStackPointer rid =
      Register.toRegID GR30 = rid

    member _.IsFramePointer rid =
      Register.toRegID GR3 = rid
