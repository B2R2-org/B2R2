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

namespace B2R2.FrontEnd.ARM32

open B2R2.FrontEnd
open B2R2.BinIR.LowUIR

type ARM32RegisterBay () =

  inherit RegisterBay ()

  let R = RegExprs ()

  override __.GetAllRegExprs () =
    [ R.R0; R.R1; R.R2 ; R.R3; R.R4; R.R5; R.R6; R.R7; R.R8; R.SB; R.SL; R.FP;
      R.IP; R.SP; R.LR; R.Q0; R.Q1; R.Q2; R.Q3; R.Q4; R.Q5; R.Q6; R.Q7; R.Q8;
      R.Q9; R.Q10; R.Q11; R.Q12; R.Q13; R.Q14; R.Q15; R.D0; R.D1; R.D2; R.D3;
      R.D4; R.D5; R.D6; R.D7; R.D8; R.D9; R.D10; R.D11; R.D12; R.D13; R.D14;
      R.D15; R.D16; R.D17; R.D18; R.D19; R.D20; R.D21; R.D22; R.D23; R.D24;
      R.D25; R.D26; R.D27; R.D28; R.D29; R.D30; R.D31; R.S0; R.S1; R.S2; R.S3;
      R.S4; R.S5; R.S6; R.S7; R.S8; R.S9; R.S10; R.S11; R.S12; R.S13; R.S14;
      R.S15; R.S16; R.S17; R.S18; R.S19; R.S20; R.S21; R.S22; R.S23; R.S24;
      R.S25; R.S26; R.S27; R.S28; R.S29; R.S30; R.S31; R.PC; R.APSR; R.SPSR;
      R.CPSR; R.FPSCR; R.SCTLR; R.SCR; R.NSACR ]

  override __.GetAllRegNames () =
    __.GetAllRegExprs ()
    |> List.map (__.RegIDFromRegExpr >> __.RegIDToString)

  override __.RegIDFromRegExpr (e) =
    match e with
    | Var (_, id, _ ,_) -> id
    | PCVar (_, _) -> Register.toRegID Register.PC
    | _ -> failwith "not a register expression"

  override __.StrToRegExpr s =
    match s with
    | "R0" -> R.R0
    | "R1" -> R.R1
    | "R2" -> R.R2
    | "R3" -> R.R3
    | "R4" -> R.R4
    | "R5" -> R.R5
    | "R6" -> R.R6
    | "R7" -> R.R7
    | "R8" -> R.R8
    | "SB" -> R.SB
    | "SL" -> R.SL
    | "FP" -> R.FP
    | "IP" -> R.IP
    | "SP" -> R.SP
    | "LR" -> R.LR
    | "Q0" -> R.Q0
    | "Q1" -> R.Q1
    | "Q2" -> R.Q2
    | "Q3" -> R.Q3
    | "Q4" -> R.Q4
    | "Q5" -> R.Q5
    | "Q6" -> R.Q6
    | "Q7" -> R.Q7
    | "Q8" -> R.Q8
    | "Q9" -> R.Q9
    | "Q10" -> R.Q10
    | "Q11" -> R.Q11
    | "Q12" -> R.Q12
    | "Q13" -> R.Q13
    | "Q14" -> R.Q14
    | "Q15" -> R.Q15
    | "D0" -> R.D0
    | "D1" -> R.D1
    | "D2" -> R.D2
    | "D3" -> R.D3
    | "D4" -> R.D4
    | "D5" -> R.D5
    | "D6" -> R.D6
    | "D7" -> R.D7
    | "D8" -> R.D8
    | "D9" -> R.D9
    | "D10" -> R.D10
    | "D11" -> R.D11
    | "D12" -> R.D12
    | "D13" -> R.D13
    | "D14" -> R.D14
    | "D15" -> R.D15
    | "D16" -> R.D16
    | "D17" -> R.D17
    | "D18" -> R.D18
    | "D19" -> R.D19
    | "D20" -> R.D20
    | "D21" -> R.D21
    | "D22" -> R.D22
    | "D23" -> R.D23
    | "D24" -> R.D24
    | "D25" -> R.D25
    | "D26" -> R.D26
    | "D27" -> R.D27
    | "D28" -> R.D28
    | "D29" -> R.D29
    | "D30" -> R.D30
    | "D31" -> R.D31
    | "S0" -> R.S0
    | "S1" -> R.S1
    | "S2" -> R.S2
    | "S3" -> R.S3
    | "S4" -> R.S4
    | "S5" -> R.S5
    | "S6" -> R.S6
    | "S7" -> R.S7
    | "S8" -> R.S8
    | "S9" -> R.S9
    | "S10" -> R.S10
    | "S11" -> R.S11
    | "S12" -> R.S12
    | "S13" -> R.S13
    | "S14" -> R.S14
    | "S15" -> R.S15
    | "S16" -> R.S16
    | "S17" -> R.S17
    | "S18" -> R.S18
    | "S19" -> R.S19
    | "S20" -> R.S20
    | "S21" -> R.S21
    | "S22" -> R.S22
    | "S23" -> R.S23
    | "S24" -> R.S24
    | "S25" -> R.S25
    | "S26" -> R.S26
    | "S27" -> R.S27
    | "S28" -> R.S28
    | "S29" -> R.S29
    | "S30" -> R.S30
    | "S31" -> R.S31
    | "PC" -> R.PC
    | "APSR" -> R.APSR
    | "SPSR" -> R.SPSR
    | "CPSR" -> R.CPSR
    | "FPSCR" -> R.FPSCR
    | "SCTLR" -> R.SCTLR
    | "SCR" -> R.SCR
    | "NSACR" -> R.NSACR
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
