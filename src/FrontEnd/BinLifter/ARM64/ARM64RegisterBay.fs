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

namespace B2R2.FrontEnd.BinLifter.ARM64

open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR

type ARM64RegisterBay internal (R: RegExprs) =

  inherit RegisterBay ()

  override __.GetAllRegExprs () =
    [ R.X0; R.X1; R.X2; R.X3; R.X4; R.X5; R.X6; R.X7; R.X8; R.X9; R.X10; R.X11;
      R.X12; R.X13; R.X14; R.X15; R.X16; R.X17; R.X18; R.X19; R.X20; R.X21;
      R.X22; R.X23; R.X24; R.X25; R.X26; R.X27; R.X28; R.X29; R.X30; R.XZR;
      R.W0; R.W1; R.W2; R.W3; R.W4; R.W5; R.W6; R.W7; R.W8; R.W9; R.W10; R.W11;
      R.W12; R.W13; R.W14; R.W15; R.W16; R.W17; R.W18; R.W19; R.W20; R.W21;
      R.W22; R.W23; R.W24; R.W25; R.W26; R.W27; R.W28; R.W29; R.W30; R.WZR;
      R.SP; R.WSP; R.PC;
      R.V0; R.V1; R.V2; R.V3; R.V4; R.V5; R.V6; R.V7; R.V8; R.V9; R.V10; R.V11;
      R.V12; R.V13; R.V14; R.V15; R.V16; R.V17; R.V18; R.V19; R.V20; R.V21;
      R.V22; R.V23; R.V24; R.V25; R.V26; R.V27; R.V28; R.V29; R.V30; R.V31;
      R.Q0; R.Q1; R.Q2; R.Q3; R.Q4; R.Q5; R.Q6; R.Q7; R.Q8; R.Q9; R.Q10; R.Q11;
      R.Q12; R.Q13; R.Q14; R.Q15; R.Q16; R.Q17; R.Q18; R.Q19; R.Q20; R.Q21;
      R.Q22; R.Q23; R.Q24; R.Q25; R.Q26; R.Q27; R.Q28; R.Q29; R.Q30; R.Q31;
      R.D0; R.D1; R.D2; R.D3; R.D4; R.D5; R.D6; R.D7; R.D8; R.D9; R.D10; R.D11;
      R.D12; R.D13; R.D14; R.D15; R.D16; R.D17; R.D18; R.D19; R.D20; R.D21;
      R.D22; R.D23; R.D24; R.D25; R.D26; R.D27; R.D28; R.D29; R.D30; R.D31;
      R.S0; R.S1; R.S2; R.S3; R.S4; R.S5; R.S6; R.S7; R.S8; R.S9; R.S10; R.S11;
      R.S12; R.S13; R.S14; R.S15; R.S16; R.S17; R.S18; R.S19; R.S20; R.S21;
      R.S22; R.S23; R.S24; R.S25; R.S26; R.S27; R.S28; R.S29; R.S30; R.S31;
      R.H0; R.H1; R.H2; R.H3; R.H4; R.H5; R.H6; R.H7; R.H8; R.H9; R.H10; R.H11;
      R.H12; R.H13; R.H14; R.H15; R.H16; R.H17; R.H18; R.H19; R.H20; R.H21;
      R.H22; R.H23; R.H24; R.H25; R.H26; R.H27; R.H28; R.H29; R.H30; R.H31;
      R.B0; R.B1; R.B2; R.B3; R.B4; R.B5; R.B6; R.B7; R.B8; R.B9; R.B10; R.B11;
      R.B12; R.B13; R.B14; R.B15; R.B16; R.B17; R.B18; R.B19; R.B20; R.B21;
      R.B22; R.B23; R.B24; R.B25; R.B26; R.B27; R.B28; R.B29; R.B30; R.B31;
      R.FPCR;R.FPSR; R.N; R.Z; R.C ]

  override __.GetAllRegNames () =
    __.GetAllRegExprs ()
    |> List.map (__.RegIDFromRegExpr >> __.RegIDToString)

  override __.GetGeneralRegExprs () =
    [ R.X0; R.X1; R.X2; R.X3; R.X4; R.X5; R.X6; R.X7; R.X8; R.X9; R.X10; R.X11;
      R.X12; R.X13; R.X14; R.X15; R.X16; R.X17; R.X18; R.X19; R.X20; R.X21;
      R.X22; R.X23; R.X24; R.X25; R.X26; R.X27; R.X28; R.X29; R.X30; R.XZR;
      R.N; R.Z; R.C ]

  override __.RegIDFromRegExpr (e) =
    match e with
    | Var (_,id, _,_) -> id
    | PCVar (_, _) -> Register.toRegID Register.PC
    | _ -> failwith "not a register expression"

  override __.RegIDToRegExpr (id) =
    Register.ofRegID id |> R.GetRegVar

  override __.StrToRegExpr s =
    match s with
    | "X0"  -> R.X0
    | "X1" -> R.X1
    | "X2" -> R.X2
    | "X3" -> R.X3
    | "X4" -> R.X4
    | "X5" -> R.X5
    | "X6" -> R.X6
    | "X7" -> R.X7
    | "X8" -> R.X8
    | "X9" -> R.X9
    | "X10" -> R.X10
    | "X11" -> R.X11
    | "X12" -> R.X12
    | "X13" -> R.X13
    | "X14" -> R.X14
    | "X15" -> R.X15
    | "X16" -> R.X16
    | "X17" -> R.X17
    | "X18" -> R.X18
    | "X19" -> R.X19
    | "X20" -> R.X20
    | "X21" -> R.X21
    | "X22" -> R.X22
    | "X23" -> R.X23
    | "X24" -> R.X24
    | "X25" -> R.X25
    | "X26" -> R.X26
    | "X27" -> R.X27
    | "X28" -> R.X28
    | "X29" -> R.X29
    | "X30" -> R.X30
    | "XZR" -> R.XZR
    | "W0" -> R.W0
    | "W1" -> R.W1
    | "W2" -> R.W2
    | "W3" -> R.W3
    | "W4" -> R.W4
    | "W5" -> R.W5
    | "W6" -> R.W6
    | "W7" -> R.W7
    | "W8" -> R.W8
    | "W9" -> R.W9
    | "W10" -> R.W10
    | "W11" -> R.W11
    | "W12" -> R.W12
    | "W13" -> R.W13
    | "W14" -> R.W14
    | "W15" -> R.W15
    | "W16" -> R.W16
    | "W17" -> R.W17
    | "W18" -> R.W18
    | "W19" -> R.W19
    | "W20" -> R.W20
    | "W21" -> R.W21
    | "W22" -> R.W22
    | "W23" -> R.W23
    | "W24" -> R.W24
    | "W25" -> R.W25
    | "W26" -> R.W26
    | "W27" -> R.W27
    | "W28" -> R.W28
    | "W29" -> R.W29
    | "W30" -> R.W30
    | "WZR" -> R.WZR
    | "SP" -> R.SP
    | "WSP" -> R.WSP
    | "PC" -> R.PC
    | "V0" -> R.V0
    | "V1" -> R.V1
    | "V2" -> R.V2
    | "V3" -> R.V3
    | "V4" -> R.V4
    | "V5" -> R.V5
    | "V6" -> R.V6
    | "V7" -> R.V7
    | "V8" -> R.V8
    | "V9" -> R.V9
    | "V10" -> R.V10
    | "V11" -> R.V11
    | "V12" -> R.V12
    | "V13" -> R.V13
    | "V14" -> R.V14
    | "V15" -> R.V15
    | "V16" -> R.V16
    | "V17" -> R.V17
    | "V18" -> R.V18
    | "V19" -> R.V19
    | "V20" -> R.V20
    | "V21" -> R.V21
    | "V22" -> R.V22
    | "V23" -> R.V23
    | "V24" -> R.V24
    | "V25" -> R.V25
    | "V26" -> R.V26
    | "V27" -> R.V27
    | "V28" -> R.V28
    | "V29" -> R.V29
    | "V30" -> R.V30
    | "V31" -> R.V31
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
    | "Q16" -> R.Q16
    | "Q17" -> R.Q17
    | "Q18" -> R.Q18
    | "Q19" -> R.Q19
    | "Q20" -> R.Q20
    | "Q21" -> R.Q21
    | "Q22" -> R.Q22
    | "Q23" -> R.Q23
    | "Q24" -> R.Q24
    | "Q25" -> R.Q25
    | "Q26" -> R.Q26
    | "Q27" -> R.Q27
    | "Q28" -> R.Q28
    | "Q29" -> R.Q29
    | "Q30" -> R.Q30
    | "Q31" -> R.Q31
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
    | "H0" -> R.H0
    | "H1" -> R.H1
    | "H2" -> R.H2
    | "H3" -> R.H3
    | "H4" -> R.H4
    | "H5" -> R.H5
    | "H6" -> R.H6
    | "H7" -> R.H7
    | "H8" -> R.H8
    | "H9" -> R.H9
    | "H10" -> R.H10
    | "H11" -> R.H11
    | "H12" -> R.H12
    | "H13" -> R.H13
    | "H14" -> R.H14
    | "H15" -> R.H15
    | "H16" -> R.H16
    | "H17" -> R.H17
    | "H18" -> R.H18
    | "H19" -> R.H19
    | "H20" -> R.H20
    | "H21" -> R.H21
    | "H22" -> R.H22
    | "H23" -> R.H23
    | "H24" -> R.H24
    | "H25" -> R.H25
    | "H26" -> R.H26
    | "H27" -> R.H27
    | "H28" -> R.H28
    | "H29" -> R.H29
    | "H30" -> R.H30
    | "H31" -> R.H31
    | "B0" -> R.B0
    | "B1" -> R.B1
    | "B2" -> R.B2
    | "B3" -> R.B3
    | "B4" -> R.B4
    | "B5" -> R.B5
    | "B6" -> R.B6
    | "B7" -> R.B7
    | "B8" -> R.B8
    | "B9" -> R.B9
    | "B10" -> R.B10
    | "B11" -> R.B11
    | "B12" -> R.B12
    | "B13" -> R.B13
    | "B14" -> R.B14
    | "B15" -> R.B15
    | "B16" -> R.B16
    | "B17" -> R.B17
    | "B18" -> R.B18
    | "B19" -> R.B19
    | "B20" -> R.B20
    | "B21" -> R.B21
    | "B22" -> R.B22
    | "B23" -> R.B23
    | "B24" -> R.B24
    | "B25" -> R.B25
    | "B26" -> R.B26
    | "B27" -> R.B27
    | "B28" -> R.B28
    | "B29" -> R.B29
    | "B30" -> R.B30
    | "B31" -> R.B31
    | "FPCR" -> R.FPCR
    | "FPSR" -> R.FPSR
    | "N" -> R.N
    | "Z" -> R.Z
    | "C" -> R.C
    | "V" -> R.V
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
    None

  override __.IsProgramCounter regid =
    let pcid = Register.PC |> Register.toRegID
    pcid = regid

  override __.IsStackPointer regid =
    let spid = Register.SP |> Register.toRegID
    spid = regid

  override __.IsFramePointer _ = false
