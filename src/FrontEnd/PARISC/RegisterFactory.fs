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
type RegisterFactory(isa: ISA) =
  let rt = WordSize.toRegType isa.WordSize

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
  let fpr0l = AST.var rt (Register.toRegID FPR0L) "FPR0L"
  let fpr1l = AST.var rt (Register.toRegID FPR1L) "FPR1L"
  let fpr2l = AST.var rt (Register.toRegID FPR2L) "FPR2L"
  let fpr3l = AST.var rt (Register.toRegID FPR3L) "FPR3L"
  let fpr4l = AST.var rt (Register.toRegID FPR4L) "FPR4L"
  let fpr5l = AST.var rt (Register.toRegID FPR5L) "FPR5L"
  let fpr6l = AST.var rt (Register.toRegID FPR6L) "FPR6L"
  let fpr7l = AST.var rt (Register.toRegID FPR7L) "FPR7L"
  let fpr8l = AST.var rt (Register.toRegID FPR8L) "FPR8L"
  let fpr9l = AST.var rt (Register.toRegID FPR9L) "FPR9L"
  let fpr10l = AST.var rt (Register.toRegID FPR10L) "FPR10L"
  let fpr11l = AST.var rt (Register.toRegID FPR11L) "FPR11L"
  let fpr12l = AST.var rt (Register.toRegID FPR12L) "FPR12L"
  let fpr13l = AST.var rt (Register.toRegID FPR13L) "FPR13L"
  let fpr14l = AST.var rt (Register.toRegID FPR14L) "FPR14L"
  let fpr15l = AST.var rt (Register.toRegID FPR15L) "FPR15L"
  let fpr16l = AST.var rt (Register.toRegID FPR16L) "FPR16L"
  let fpr17l = AST.var rt (Register.toRegID FPR17L) "FPR17L"
  let fpr18l = AST.var rt (Register.toRegID FPR18L) "FPR18L"
  let fpr19l = AST.var rt (Register.toRegID FPR19L) "FPR19L"
  let fpr20l = AST.var rt (Register.toRegID FPR20L) "FPR20L"
  let fpr21l = AST.var rt (Register.toRegID FPR21L) "FPR21L"
  let fpr22l = AST.var rt (Register.toRegID FPR22L) "FPR22L"
  let fpr23l = AST.var rt (Register.toRegID FPR23L) "FPR23L"
  let fpr24l = AST.var rt (Register.toRegID FPR24L) "FPR24L"
  let fpr25l = AST.var rt (Register.toRegID FPR25L) "FPR25L"
  let fpr26l = AST.var rt (Register.toRegID FPR26L) "FPR26L"
  let fpr27l = AST.var rt (Register.toRegID FPR27L) "FPR27L"
  let fpr28l = AST.var rt (Register.toRegID FPR28L) "FPR28L"
  let fpr29l = AST.var rt (Register.toRegID FPR29L) "FPR29L"
  let fpr30l = AST.var rt (Register.toRegID FPR30L) "FPR30L"
  let fpr31l = AST.var rt (Register.toRegID FPR31L) "FPR31L"
  let fpr0r = AST.var rt (Register.toRegID FPR0R) "FPR0R"
  let fpr1r = AST.var rt (Register.toRegID FPR1R) "FPR1R"
  let fpr2r = AST.var rt (Register.toRegID FPR2R) "FPR2R"
  let fpr3r = AST.var rt (Register.toRegID FPR3R) "FPR3R"
  let fpr4r = AST.var rt (Register.toRegID FPR4R) "FPR4R"
  let fpr5r = AST.var rt (Register.toRegID FPR5R) "FPR5R"
  let fpr6r = AST.var rt (Register.toRegID FPR6R) "FPR6R"
  let fpr7r = AST.var rt (Register.toRegID FPR7R) "FPR7R"
  let fpr8r = AST.var rt (Register.toRegID FPR8R) "FPR8R"
  let fpr9r = AST.var rt (Register.toRegID FPR9R) "FPR9R"
  let fpr10r = AST.var rt (Register.toRegID FPR10R) "FPR10R"
  let fpr11r = AST.var rt (Register.toRegID FPR11R) "FPR11R"
  let fpr12r = AST.var rt (Register.toRegID FPR12R) "FPR12R"
  let fpr13r = AST.var rt (Register.toRegID FPR13R) "FPR13R"
  let fpr14r = AST.var rt (Register.toRegID FPR14R) "FPR14R"
  let fpr15r = AST.var rt (Register.toRegID FPR15R) "FPR15R"
  let fpr16r = AST.var rt (Register.toRegID FPR16R) "FPR16R"
  let fpr17r = AST.var rt (Register.toRegID FPR17R) "FPR17R"
  let fpr18r = AST.var rt (Register.toRegID FPR18R) "FPR18R"
  let fpr19r = AST.var rt (Register.toRegID FPR19R) "FPR19R"
  let fpr20r = AST.var rt (Register.toRegID FPR20R) "FPR20R"
  let fpr21r = AST.var rt (Register.toRegID FPR21R) "FPR21R"
  let fpr22r = AST.var rt (Register.toRegID FPR22R) "FPR22R"
  let fpr23r = AST.var rt (Register.toRegID FPR23R) "FPR23R"
  let fpr24r = AST.var rt (Register.toRegID FPR24R) "FPR24R"
  let fpr25r = AST.var rt (Register.toRegID FPR25R) "FPR25R"
  let fpr26r = AST.var rt (Register.toRegID FPR26R) "FPR26R"
  let fpr27r = AST.var rt (Register.toRegID FPR27R) "FPR27R"
  let fpr28r = AST.var rt (Register.toRegID FPR28R) "FPR28R"
  let fpr29r = AST.var rt (Register.toRegID FPR29R) "FPR29R"
  let fpr30r = AST.var rt (Register.toRegID FPR30R) "FPR30R"
  let fpr31r = AST.var rt (Register.toRegID FPR31R) "FPR31R"
  let pswN = AST.var rt (Register.toRegID PSW_N) "PSW_N"
  let pswV = AST.var rt (Register.toRegID PSW_V) "PSW_V"
  let pswCB = AST.var rt (Register.toRegID PSW_CB) "PSW_CB"

  interface IRegisterFactory with
    member _.ISA = isa

    member _.ProgramCounter = IAOQ_Front |> Register.toRegID

    member _.StackPointer = GR30 |> Register.toRegID |> Some

    member _.FramePointer = GR3 |> Register.toRegID |> Some

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
      | Register.FPR0L -> fpr0l
      | Register.FPR1L -> fpr1l
      | Register.FPR2L -> fpr2l
      | Register.FPR3L -> fpr3l
      | Register.FPR4L -> fpr4l
      | Register.FPR5L -> fpr5l
      | Register.FPR6L -> fpr6l
      | Register.FPR7L -> fpr7l
      | Register.FPR8L -> fpr8l
      | Register.FPR9L -> fpr9l
      | Register.FPR10L -> fpr10l
      | Register.FPR11L -> fpr11l
      | Register.FPR12L -> fpr12l
      | Register.FPR13L -> fpr13l
      | Register.FPR14L -> fpr14l
      | Register.FPR15L -> fpr15l
      | Register.FPR16L -> fpr16l
      | Register.FPR17L -> fpr17l
      | Register.FPR18L -> fpr18l
      | Register.FPR19L -> fpr19l
      | Register.FPR20L -> fpr20l
      | Register.FPR21L -> fpr21l
      | Register.FPR22L -> fpr22l
      | Register.FPR23L -> fpr23l
      | Register.FPR24L -> fpr24l
      | Register.FPR25L -> fpr25l
      | Register.FPR26L -> fpr26l
      | Register.FPR27L -> fpr27l
      | Register.FPR28L -> fpr28l
      | Register.FPR29L -> fpr29l
      | Register.FPR30L -> fpr30l
      | Register.FPR31L -> fpr31l
      | Register.FPR0R -> fpr0r
      | Register.FPR1R -> fpr1r
      | Register.FPR2R -> fpr2r
      | Register.FPR3R -> fpr3r
      | Register.FPR4R -> fpr4r
      | Register.FPR5R -> fpr5r
      | Register.FPR6R -> fpr6r
      | Register.FPR7R -> fpr7r
      | Register.FPR8R -> fpr8r
      | Register.FPR9R -> fpr9r
      | Register.FPR10R -> fpr10r
      | Register.FPR11R -> fpr11r
      | Register.FPR12R -> fpr12r
      | Register.FPR13R -> fpr13r
      | Register.FPR14R -> fpr14r
      | Register.FPR15R -> fpr15r
      | Register.FPR16R -> fpr16r
      | Register.FPR17R -> fpr17r
      | Register.FPR18R -> fpr18r
      | Register.FPR19R -> fpr19r
      | Register.FPR20R -> fpr20r
      | Register.FPR21R -> fpr21r
      | Register.FPR22R -> fpr22r
      | Register.FPR23R -> fpr23r
      | Register.FPR24R -> fpr24r
      | Register.FPR25R -> fpr25r
      | Register.FPR26R -> fpr26r
      | Register.FPR27R -> fpr27r
      | Register.FPR28R -> fpr28r
      | Register.FPR29R -> fpr29r
      | Register.FPR30R -> fpr30r
      | Register.FPR31R -> fpr31r
      | Register.PSW_N -> pswN
      | Register.PSW_V -> pswV
      | Register.PSW_CB -> pswCB
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
         fpr0l
         fpr1l
         fpr2l
         fpr3l
         fpr4l
         fpr5l
         fpr6l
         fpr7l
         fpr8l
         fpr9l
         fpr10l
         fpr11l
         fpr12l
         fpr13l
         fpr14l
         fpr15l
         fpr16l
         fpr17l
         fpr18l
         fpr19l
         fpr20l
         fpr21l
         fpr22l
         fpr23l
         fpr24l
         fpr25l
         fpr26l
         fpr27l
         fpr28l
         fpr29l
         fpr30l
         fpr31l
         fpr0r
         fpr1r
         fpr2r
         fpr3r
         fpr4r
         fpr5r
         fpr6r
         fpr7r
         fpr8r
         fpr9r
         fpr10r
         fpr11r
         fpr12r
         fpr13r
         fpr14r
         fpr15r
         fpr16r
         fpr17r
         fpr18r
         fpr19r
         fpr20r
         fpr21r
         fpr22r
         fpr23r
         fpr24r
         fpr25r
         fpr26r
         fpr27r
         fpr28r
         fpr29r
         fpr30r
         fpr31r
         pswN
         pswV
         pswCB |]

    member this.GetAllRegisterNames() =
      let regFactory = this :> IRegisterFactory
      regFactory.GetAllRegVars()
      |> Array.map (regFactory.GetRegisterID >> regFactory.GetRegisterName)

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

    member _.GetRegisterID str = Register.ofString str |> Register.toRegID

    member _.GetRegisterName rid = Register.toString (Register.ofRegID rid)

    member _.GetRegType _rid = WordSize.toRegType isa.WordSize

    member _.GetRegisterIDAliases rid = [| rid |]

    member this.IsProgramCounter rid =
      (this :> IRegisterFactory).ProgramCounter = rid

    member _.IsStackPointer rid = Register.toRegID GR30 = rid

    member _.IsFramePointer rid = Register.toRegID GR3 = rid
