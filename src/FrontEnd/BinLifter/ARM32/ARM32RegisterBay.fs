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

namespace B2R2.FrontEnd.BinLifter.ARM32

open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR

type ARM32RegisterBay internal (r: RegExprs) =

  inherit RegisterBay ()

  override __.GetAllRegExprs () =
    [ r.R0; r.R1; r.R2 ; r.R3; r.R4; r.R5; r.R6; r.R7; r.R8; r.SB; r.SL; r.FP;
      r.IP; r.SP; r.LR; r.Q0; r.Q1; r.Q2; r.Q3; r.Q4; r.Q5; r.Q6; r.Q7; r.Q8;
      r.Q9; r.Q10; r.Q11; r.Q12; r.Q13; r.Q14; r.Q15; r.D0; r.D1; r.D2; r.D3;
      r.D4; r.D5; r.D6; r.D7; r.D8; r.D9; r.D10; r.D11; r.D12; r.D13; r.D14;
      r.D15; r.D16; r.D17; r.D18; r.D19; r.D20; r.D21; r.D22; r.D23; r.D24;
      r.D25; r.D26; r.D27; r.D28; r.D29; r.D30; r.D31; r.S0; r.S1; r.S2; r.S3;
      r.S4; r.S5; r.S6; r.S7; r.S8; r.S9; r.S10; r.S11; r.S12; r.S13; r.S14;
      r.S15; r.S16; r.S17; r.S18; r.S19; r.S20; r.S21; r.S22; r.S23; r.S24;
      r.S25; r.S26; r.S27; r.S28; r.S29; r.S30; r.S31; r.PC; r.APSR; r.SPSR;
      r.CPSR; r.FPSCR; r.SCTLR; r.SCR; r.NSACR ]

  override __.GetAllRegNames () =
    __.GetAllRegExprs ()
    |> List.map (__.RegIDFromRegExpr >> __.RegIDToString)

  override __.GetGeneralRegExprs () =
    [ r.R0; r.R1; r.R2 ; r.R3; r.R4; r.R5; r.R6; r.R7; r.R8; r.SB; r.SL; r.FP;
      r.IP; r.SP; r.LR; r.PC; r.APSR; r.SPSR; r.CPSR ]

  override __.RegIDFromRegExpr (e) =
    match e.E with
    | Var (_, id, _ ,_) -> id
    | PCVar _ -> Register.toRegID Register.PC
    | _ -> failwith "not a register expression"

  override __.RegIDToRegExpr (id) =
    Register.ofRegID id |> r.GetRegVar

  override __.StrToRegExpr s =
    match s with
    | "R0" -> r.R0
    | "R1" -> r.R1
    | "R2" -> r.R2
    | "R3" -> r.R3
    | "R4" -> r.R4
    | "R5" -> r.R5
    | "R6" -> r.R6
    | "R7" -> r.R7
    | "R8" -> r.R8
    | "SB" -> r.SB
    | "SL" -> r.SL
    | "FP" -> r.FP
    | "IP" -> r.IP
    | "SP" -> r.SP
    | "LR" -> r.LR
    | "Q0" -> r.Q0
    | "Q1" -> r.Q1
    | "Q2" -> r.Q2
    | "Q3" -> r.Q3
    | "Q4" -> r.Q4
    | "Q5" -> r.Q5
    | "Q6" -> r.Q6
    | "Q7" -> r.Q7
    | "Q8" -> r.Q8
    | "Q9" -> r.Q9
    | "Q10" -> r.Q10
    | "Q11" -> r.Q11
    | "Q12" -> r.Q12
    | "Q13" -> r.Q13
    | "Q14" -> r.Q14
    | "Q15" -> r.Q15
    | "D0" -> r.D0
    | "D1" -> r.D1
    | "D2" -> r.D2
    | "D3" -> r.D3
    | "D4" -> r.D4
    | "D5" -> r.D5
    | "D6" -> r.D6
    | "D7" -> r.D7
    | "D8" -> r.D8
    | "D9" -> r.D9
    | "D10" -> r.D10
    | "D11" -> r.D11
    | "D12" -> r.D12
    | "D13" -> r.D13
    | "D14" -> r.D14
    | "D15" -> r.D15
    | "D16" -> r.D16
    | "D17" -> r.D17
    | "D18" -> r.D18
    | "D19" -> r.D19
    | "D20" -> r.D20
    | "D21" -> r.D21
    | "D22" -> r.D22
    | "D23" -> r.D23
    | "D24" -> r.D24
    | "D25" -> r.D25
    | "D26" -> r.D26
    | "D27" -> r.D27
    | "D28" -> r.D28
    | "D29" -> r.D29
    | "D30" -> r.D30
    | "D31" -> r.D31
    | "S0" -> r.S0
    | "S1" -> r.S1
    | "S2" -> r.S2
    | "S3" -> r.S3
    | "S4" -> r.S4
    | "S5" -> r.S5
    | "S6" -> r.S6
    | "S7" -> r.S7
    | "S8" -> r.S8
    | "S9" -> r.S9
    | "S10" -> r.S10
    | "S11" -> r.S11
    | "S12" -> r.S12
    | "S13" -> r.S13
    | "S14" -> r.S14
    | "S15" -> r.S15
    | "S16" -> r.S16
    | "S17" -> r.S17
    | "S18" -> r.S18
    | "S19" -> r.S19
    | "S20" -> r.S20
    | "S21" -> r.S21
    | "S22" -> r.S22
    | "S23" -> r.S23
    | "S24" -> r.S24
    | "S25" -> r.S25
    | "S26" -> r.S26
    | "S27" -> r.S27
    | "S28" -> r.S28
    | "S29" -> r.S29
    | "S30" -> r.S30
    | "S31" -> r.S31
    | "PC" -> r.PC
    | "APSR" -> r.APSR
    | "SPSR" -> r.SPSR
    | "CPSR" -> r.CPSR
    | "FPSCR" -> r.FPSCR
    | "SCTLR" -> r.SCTLR
    | "SCR" -> r.SCR
    | "NSACR" -> r.NSACR
    | _ -> raise UnhandledRegExprException

  override __.RegIDFromString str =
    Register.ofString str |> Register.toRegID

  override __.RegIDToString rid =
    Register.ofRegID rid |> Register.toString

  override __.RegIDToRegType rid =
    Register.ofRegID rid |> Register.toRegType

  override __.GetRegisterAliases rid =
    [| rid |]

  override __.ProgramCounter =
    Register.PC |> Register.toRegID

  override __.StackPointer =
    Register.SP |> Register.toRegID |> Some

  override __.FramePointer =
    Register.FP |> Register.toRegID |> Some

  override __.IsProgramCounter regid =
    let pcid = Register.PC |> Register.toRegID
    pcid = regid

  override __.IsStackPointer regid =
    let spid = Register.SP |> Register.toRegID
    spid = regid

  override __.IsFramePointer regid =
    let fpid = Register.FP |> Register.toRegID
    fpid = regid
