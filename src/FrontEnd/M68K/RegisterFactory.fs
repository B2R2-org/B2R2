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

namespace B2R2.FrontEnd.M68K

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR

/// Represents a factory for accessing various m68k register variables.
type RegisterFactory(isa: ISA) =
  let d0 = AST.var 32<rt> (Register.toRegID Register.D0) "d0"
  let d1 = AST.var 32<rt> (Register.toRegID Register.D1) "d1"
  let d2 = AST.var 32<rt> (Register.toRegID Register.D2) "d2"
  let d3 = AST.var 32<rt> (Register.toRegID Register.D3) "d3"
  let d4 = AST.var 32<rt> (Register.toRegID Register.D4) "d4"
  let d5 = AST.var 32<rt> (Register.toRegID Register.D5) "d5"
  let d6 = AST.var 32<rt> (Register.toRegID Register.D6) "d6"
  let d7 = AST.var 32<rt> (Register.toRegID Register.D7) "d7"
  let a0 = AST.var 32<rt> (Register.toRegID Register.A0) "a0"
  let a1 = AST.var 32<rt> (Register.toRegID Register.A1) "a1"
  let a2 = AST.var 32<rt> (Register.toRegID Register.A2) "a2"
  let a3 = AST.var 32<rt> (Register.toRegID Register.A3) "a3"
  let a4 = AST.var 32<rt> (Register.toRegID Register.A4) "a4"
  let a5 = AST.var 32<rt> (Register.toRegID Register.A5) "a5"
  let a6 = AST.var 32<rt> (Register.toRegID Register.A6) "a6"
  let a7 = AST.var 32<rt> (Register.toRegID Register.A7) "a7"
  let pc = AST.var 32<rt> (Register.toRegID Register.PC) "pc"
  let ccr = AST.var 8<rt> (Register.toRegID Register.CCR) "ccr"
  let sr = AST.var 16<rt> (Register.toRegID Register.SR) "sr"
  let usp = AST.var 32<rt> (Register.toRegID Register.USP) "usp"
  let isp = AST.var 32<rt> (Register.toRegID Register.ISP) "isp"
  let msp = AST.var 32<rt> (Register.toRegID Register.MSP) "msp"
  let vbr = AST.var 32<rt> (Register.toRegID Register.VBR) "vbr"
  let sfc = AST.var 32<rt> (Register.toRegID Register.SFC) "sfc"
  let dfc = AST.var 32<rt> (Register.toRegID Register.DFC) "dfc"
  let cacr = AST.var 32<rt> (Register.toRegID Register.CACR) "cacr"
  let caar = AST.var 32<rt> (Register.toRegID Register.CAAR) "caar"
  let tc = AST.var 32<rt> (Register.toRegID Register.TC) "tc"
  let itt0 = AST.var 32<rt> (Register.toRegID Register.ITT0) "itt0"
  let itt1 = AST.var 32<rt> (Register.toRegID Register.ITT1) "itt1"
  let dtt0 = AST.var 32<rt> (Register.toRegID Register.DTT0) "dtt0"
  let dtt1 = AST.var 32<rt> (Register.toRegID Register.DTT1) "dtt1"
  let mmusr = AST.var 32<rt> (Register.toRegID Register.MMUSR) "mmusr"
  let urp = AST.var 32<rt> (Register.toRegID Register.URP) "urp"
  let srp = AST.var 32<rt> (Register.toRegID Register.SRP) "srp"
  let fp0 = AST.var 80<rt> (Register.toRegID Register.FP0) "fp0"
  let fp1 = AST.var 80<rt> (Register.toRegID Register.FP1) "fp1"
  let fp2 = AST.var 80<rt> (Register.toRegID Register.FP2) "fp2"
  let fp3 = AST.var 80<rt> (Register.toRegID Register.FP3) "fp3"
  let fp4 = AST.var 80<rt> (Register.toRegID Register.FP4) "fp4"
  let fp5 = AST.var 80<rt> (Register.toRegID Register.FP5) "fp5"
  let fp6 = AST.var 80<rt> (Register.toRegID Register.FP6) "fp6"
  let fp7 = AST.var 80<rt> (Register.toRegID Register.FP7) "fp7"
  let fpcr = AST.var 32<rt> (Register.toRegID Register.FPCR) "fpcr"
  let fpsr = AST.var 32<rt> (Register.toRegID Register.FPSR) "fpsr"
  let fpiar = AST.var 32<rt> (Register.toRegID Register.FPIAR) "fpiar"

  interface IRegisterFactory with
    member _.ISA = isa

    member _.ProgramCounter = Register.PC |> Register.toRegID

    member _.StackPointer =
      Register.A7
      |> Register.toRegID
      |> Some

    member _.FramePointer =
      Register.A6
      |> Register.toRegID
      |> Some

    member _.GetRegVar id =
      match Register.ofRegID id with
      | R.D0 -> d0
      | R.D1 -> d1
      | R.D2 -> d2
      | R.D3 -> d3
      | R.D4 -> d4
      | R.D5 -> d5
      | R.D6 -> d6
      | R.D7 -> d7
      | R.A0 -> a0
      | R.A1 -> a1
      | R.A2 -> a2
      | R.A3 -> a3
      | R.A4 -> a4
      | R.A5 -> a5
      | R.A6 -> a6
      | R.A7 -> a7
      | R.PC -> pc
      | R.CCR -> ccr
      | R.SR -> sr
      | R.USP -> usp
      | R.ISP -> isp
      | R.MSP -> msp
      | R.VBR -> vbr
      | R.SFC -> sfc
      | R.DFC -> dfc
      | R.CACR -> cacr
      | R.CAAR -> caar
      | R.TC -> tc
      | R.ITT0 -> itt0
      | R.ITT1 -> itt1
      | R.DTT0 -> dtt0
      | R.DTT1 -> dtt1
      | R.MMUSR -> mmusr
      | R.URP -> urp
      | R.SRP -> srp
      | R.FP0 -> fp0
      | R.FP1 -> fp1
      | R.FP2 -> fp2
      | R.FP3 -> fp3
      | R.FP4 -> fp4
      | R.FP5 -> fp5
      | R.FP6 -> fp6
      | R.FP7 -> fp7
      | R.FPCR -> fpcr
      | R.FPSR -> fpsr
      | R.FPIAR -> fpiar
      | _ -> raise InvalidRegisterException

    member _.GetRegVar(name: string) =
      match name.ToLowerInvariant() with
      | "d0" -> d0
      | "d1" -> d1
      | "d2" -> d2
      | "d3" -> d3
      | "d4" -> d4
      | "d5" -> d5
      | "d6" -> d6
      | "d7" -> d7
      | "a0" -> a0
      | "a1" -> a1
      | "a2" -> a2
      | "a3" -> a3
      | "a4" -> a4
      | "a5" -> a5
      | "a6" -> a6
      | "a7" | "sp" -> a7
      | "pc" -> pc
      | "ccr" -> ccr
      | "sr" -> sr
      | "usp" -> usp
      | "isp" | "ssp" -> isp
      | "msp" -> msp
      | "vbr" -> vbr
      | "sfc" -> sfc
      | "dfc" -> dfc
      | "cacr" -> cacr
      | "caar" -> caar
      | "tc" -> tc
      | "itt0" -> itt0
      | "itt1" -> itt1
      | "dtt0" -> dtt0
      | "dtt1" -> dtt1
      | "mmusr" -> mmusr
      | "urp" -> urp
      | "srp" -> srp
      | "fp0" -> fp0
      | "fp1" -> fp1
      | "fp2" -> fp2
      | "fp3" -> fp3
      | "fp4" -> fp4
      | "fp5" -> fp5
      | "fp6" -> fp6
      | "fp7" -> fp7
      | "fpcr" -> fpcr
      | "fpsr" -> fpsr
      | "fpiar" -> fpiar
      | _ -> raise InvalidRegisterException

    member _.GetPseudoRegVar(_id, _idx) = Terminator.impossible ()

    member _.GetAllRegVars() =
      [| d0
         d1
         d2
         d3
         d4
         d5
         d6
         d7
         a0
         a1
         a2
         a3
         a4
         a5
         a6
         a7
         pc
         ccr
         sr
         usp
         isp
         msp
         vbr
         sfc
         dfc
         cacr
         caar
         tc
         itt0
         itt1
         dtt0
         dtt1
         mmusr
         urp
         srp
         fp0
         fp1
         fp2
         fp3
         fp4
         fp5
         fp6
         fp7
         fpcr
         fpsr
         fpiar |]

    member _.GetGeneralRegVars() =
      [| d0
         d1
         d2
         d3
         d4
         d5
         d6
         d7
         a0
         a1
         a2
         a3
         a4
         a5
         a6
         a7 |]

    member _.GetRegisterID expr =
      match expr with
      | Var(_, id, _, _) -> id
      | PCVar _ -> Register.toRegID Register.PC
      | _ -> raise InvalidRegisterException

    member _.GetRegisterID name = Register.ofString name |> Register.toRegID

    member _.GetRegisterIDAliases rid = [| rid |]

    member _.GetRegisterName rid = Register.ofRegID rid |> Register.toString

    member this.GetAllRegisterNames() =
      let regFactory = this :> IRegisterFactory
      regFactory.GetAllRegVars()
      |> Array.map (regFactory.GetRegisterID >> regFactory.GetRegisterName)

    member _.GetRegType rid = Register.ofRegID rid |> RegisterHelper.toRegType

    member _.IsProgramCounter rid = Register.toRegID Register.PC = rid

    member _.IsStackPointer rid = Register.toRegID Register.A7 = rid

    member _.IsFramePointer rid = Register.toRegID Register.A6 = rid
