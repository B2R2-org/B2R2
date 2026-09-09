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
  let tp = AST.var 32<rt> (Register.toRegID Register.TP) "tp"
  let fp0a = AST.var 64<rt> (Register.toRegID Register.FP0A) "fp0a"
  let fp0b = AST.var 16<rt> (Register.toRegID Register.FP0B) "fp0b"
  let fp1a = AST.var 64<rt> (Register.toRegID Register.FP1A) "fp1a"
  let fp1b = AST.var 16<rt> (Register.toRegID Register.FP1B) "fp1b"
  let fp2a = AST.var 64<rt> (Register.toRegID Register.FP2A) "fp2a"
  let fp2b = AST.var 16<rt> (Register.toRegID Register.FP2B) "fp2b"
  let fp3a = AST.var 64<rt> (Register.toRegID Register.FP3A) "fp3a"
  let fp3b = AST.var 16<rt> (Register.toRegID Register.FP3B) "fp3b"
  let fp4a = AST.var 64<rt> (Register.toRegID Register.FP4A) "fp4a"
  let fp4b = AST.var 16<rt> (Register.toRegID Register.FP4B) "fp4b"
  let fp5a = AST.var 64<rt> (Register.toRegID Register.FP5A) "fp5a"
  let fp5b = AST.var 16<rt> (Register.toRegID Register.FP5B) "fp5b"
  let fp6a = AST.var 64<rt> (Register.toRegID Register.FP6A) "fp6a"
  let fp6b = AST.var 16<rt> (Register.toRegID Register.FP6B) "fp6b"
  let fp7a = AST.var 64<rt> (Register.toRegID Register.FP7A) "fp7a"
  let fp7b = AST.var 16<rt> (Register.toRegID Register.FP7B) "fp7b"
  (* A floating-point data register is eighty bits, which is wider than any
     register file holds, so each is kept as the two that together are
     exactly that and read back as the pair concatenated. Only the halves
     are ever written. *)
  let fp0 = AST.concat fp0b fp0a
  let fp1 = AST.concat fp1b fp1a
  let fp2 = AST.concat fp2b fp2a
  let fp3 = AST.concat fp3b fp3a
  let fp4 = AST.concat fp4b fp4a
  let fp5 = AST.concat fp5b fp5a
  let fp6 = AST.concat fp6b fp6a
  let fp7 = AST.concat fp7b fp7a
  let fpcr = AST.var 32<rt> (Register.toRegID Register.FPCR) "fpcr"
  let fpsr = AST.var 32<rt> (Register.toRegID Register.FPSR) "fpsr"
  let fpiar = AST.var 32<rt> (Register.toRegID Register.FPIAR) "fpiar"
  let xf = AST.var 1<rt> (Register.toRegID Register.XF) "xf"
  let nf = AST.var 1<rt> (Register.toRegID Register.NF) "nf"
  let zf = AST.var 1<rt> (Register.toRegID Register.ZF) "zf"
  let vf = AST.var 1<rt> (Register.toRegID Register.VF) "vf"
  let cf = AST.var 1<rt> (Register.toRegID Register.CF) "cf"

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
      | R.FP0A -> fp0a
      | R.FP1A -> fp1a
      | R.FP2A -> fp2a
      | R.FP3A -> fp3a
      | R.FP4A -> fp4a
      | R.FP5A -> fp5a
      | R.FP6A -> fp6a
      | R.FP7A -> fp7a
      | R.FP0B -> fp0b
      | R.FP1B -> fp1b
      | R.FP2B -> fp2b
      | R.FP3B -> fp3b
      | R.FP4B -> fp4b
      | R.FP5B -> fp5b
      | R.FP6B -> fp6b
      | R.FP7B -> fp7b
      | R.TP -> tp
      | R.FPCR -> fpcr
      | R.FPSR -> fpsr
      | R.FPIAR -> fpiar
      | R.XF -> xf
      | R.NF -> nf
      | R.ZF -> zf
      | R.VF -> vf
      | R.CF -> cf
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
      | "fp0a" -> fp0a
      | "fp1a" -> fp1a
      | "fp2a" -> fp2a
      | "fp3a" -> fp3a
      | "fp4a" -> fp4a
      | "fp5a" -> fp5a
      | "fp6a" -> fp6a
      | "fp7a" -> fp7a
      | "fp0b" -> fp0b
      | "fp1b" -> fp1b
      | "fp2b" -> fp2b
      | "fp3b" -> fp3b
      | "fp4b" -> fp4b
      | "fp5b" -> fp5b
      | "fp6b" -> fp6b
      | "fp7b" -> fp7b
      | "tp" -> tp
      | "fpcr" -> fpcr
      | "fpsr" -> fpsr
      | "fpiar" -> fpiar
      | "xf" -> xf
      | "nf" -> nf
      | "zf" -> zf
      | "vf" -> vf
      | "cf" -> cf
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
         fp0a
         fp1a
         fp2a
         fp3a
         fp4a
         fp5a
         fp6a
         fp7a
         fp0b
         fp1b
         fp2b
         fp3b
         fp4b
         fp5b
         fp6b
         fp7b
         tp
         fpcr
         fpsr
         fpiar
         xf
         nf
         zf
         vf
         cf |]

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
