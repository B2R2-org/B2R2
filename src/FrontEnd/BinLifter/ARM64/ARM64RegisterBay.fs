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

type ARM64RegisterBay internal (r: RegExprs) =

  inherit RegisterBay ()

  override __.GetAllRegExprs () =
    [ r.X0; r.X1; r.X2; r.X3; r.X4; r.X5; r.X6; r.X7; r.X8; r.X9; r.X10; r.X11;
      r.X12; r.X13; r.X14; r.X15; r.X16; r.X17; r.X18; r.X19; r.X20; r.X21;
      r.X22; r.X23; r.X24; r.X25; r.X26; r.X27; r.X28; r.X29; r.X30; r.XZR;
      r.W0; r.W1; r.W2; r.W3; r.W4; r.W5; r.W6; r.W7; r.W8; r.W9; r.W10; r.W11;
      r.W12; r.W13; r.W14; r.W15; r.W16; r.W17; r.W18; r.W19; r.W20; r.W21;
      r.W22; r.W23; r.W24; r.W25; r.W26; r.W27; r.W28; r.W29; r.W30; r.WZR;
      r.SP; r.WSP; r.PC;
      r.V0; r.V1; r.V2; r.V3; r.V4; r.V5; r.V6; r.V7; r.V8; r.V9; r.V10; r.V11;
      r.V12; r.V13; r.V14; r.V15; r.V16; r.V17; r.V18; r.V19; r.V20; r.V21;
      r.V22; r.V23; r.V24; r.V25; r.V26; r.V27; r.V28; r.V29; r.V30; r.V31;
      r.Q0; r.Q1; r.Q2; r.Q3; r.Q4; r.Q5; r.Q6; r.Q7; r.Q8; r.Q9; r.Q10; r.Q11;
      r.Q12; r.Q13; r.Q14; r.Q15; r.Q16; r.Q17; r.Q18; r.Q19; r.Q20; r.Q21;
      r.Q22; r.Q23; r.Q24; r.Q25; r.Q26; r.Q27; r.Q28; r.Q29; r.Q30; r.Q31;
      r.D0; r.D1; r.D2; r.D3; r.D4; r.D5; r.D6; r.D7; r.D8; r.D9; r.D10; r.D11;
      r.D12; r.D13; r.D14; r.D15; r.D16; r.D17; r.D18; r.D19; r.D20; r.D21;
      r.D22; r.D23; r.D24; r.D25; r.D26; r.D27; r.D28; r.D29; r.D30; r.D31;
      r.S0; r.S1; r.S2; r.S3; r.S4; r.S5; r.S6; r.S7; r.S8; r.S9; r.S10; r.S11;
      r.S12; r.S13; r.S14; r.S15; r.S16; r.S17; r.S18; r.S19; r.S20; r.S21;
      r.S22; r.S23; r.S24; r.S25; r.S26; r.S27; r.S28; r.S29; r.S30; r.S31;
      r.H0; r.H1; r.H2; r.H3; r.H4; r.H5; r.H6; r.H7; r.H8; r.H9; r.H10; r.H11;
      r.H12; r.H13; r.H14; r.H15; r.H16; r.H17; r.H18; r.H19; r.H20; r.H21;
      r.H22; r.H23; r.H24; r.H25; r.H26; r.H27; r.H28; r.H29; r.H30; r.H31;
      r.B0; r.B1; r.B2; r.B3; r.B4; r.B5; r.B6; r.B7; r.B8; r.B9; r.B10; r.B11;
      r.B12; r.B13; r.B14; r.B15; r.B16; r.B17; r.B18; r.B19; r.B20; r.B21;
      r.B22; r.B23; r.B24; r.B25; r.B26; r.B27; r.B28; r.B29; r.B30; r.B31;
      r.FPCR;r.FPSR; r.N; r.Z; r.C ]

  override __.GetAllRegNames () =
    __.GetAllRegExprs ()
    |> List.map (__.RegIDFromRegExpr >> __.RegIDToString)

  override __.GetGeneralRegExprs () =
    [ r.X0; r.X1; r.X2; r.X3; r.X4; r.X5; r.X6; r.X7; r.X8; r.X9; r.X10; r.X11;
      r.X12; r.X13; r.X14; r.X15; r.X16; r.X17; r.X18; r.X19; r.X20; r.X21;
      r.X22; r.X23; r.X24; r.X25; r.X26; r.X27; r.X28; r.X29; r.X30; r.XZR;
      r.N; r.Z; r.C ]

  override __.RegIDFromRegExpr (e) =
    match e.E with
    | Var (_, id, _, _) -> id
    | PCVar _ -> Register.toRegID Register.PC
    | _ -> failwith "not a register expression"

  override __.RegIDToRegExpr (id) =
    Register.ofRegID id |> r.GetRegVar

  override __.StrToRegExpr s =
    match s with
    | "X0"  -> r.X0
    | "X1" -> r.X1
    | "X2" -> r.X2
    | "X3" -> r.X3
    | "X4" -> r.X4
    | "X5" -> r.X5
    | "X6" -> r.X6
    | "X7" -> r.X7
    | "X8" -> r.X8
    | "X9" -> r.X9
    | "X10" -> r.X10
    | "X11" -> r.X11
    | "X12" -> r.X12
    | "X13" -> r.X13
    | "X14" -> r.X14
    | "X15" -> r.X15
    | "X16" -> r.X16
    | "X17" -> r.X17
    | "X18" -> r.X18
    | "X19" -> r.X19
    | "X20" -> r.X20
    | "X21" -> r.X21
    | "X22" -> r.X22
    | "X23" -> r.X23
    | "X24" -> r.X24
    | "X25" -> r.X25
    | "X26" -> r.X26
    | "X27" -> r.X27
    | "X28" -> r.X28
    | "X29" -> r.X29
    | "X30" -> r.X30
    | "XZR" -> r.XZR
    | "W0" -> r.W0
    | "W1" -> r.W1
    | "W2" -> r.W2
    | "W3" -> r.W3
    | "W4" -> r.W4
    | "W5" -> r.W5
    | "W6" -> r.W6
    | "W7" -> r.W7
    | "W8" -> r.W8
    | "W9" -> r.W9
    | "W10" -> r.W10
    | "W11" -> r.W11
    | "W12" -> r.W12
    | "W13" -> r.W13
    | "W14" -> r.W14
    | "W15" -> r.W15
    | "W16" -> r.W16
    | "W17" -> r.W17
    | "W18" -> r.W18
    | "W19" -> r.W19
    | "W20" -> r.W20
    | "W21" -> r.W21
    | "W22" -> r.W22
    | "W23" -> r.W23
    | "W24" -> r.W24
    | "W25" -> r.W25
    | "W26" -> r.W26
    | "W27" -> r.W27
    | "W28" -> r.W28
    | "W29" -> r.W29
    | "W30" -> r.W30
    | "WZR" -> r.WZR
    | "SP" -> r.SP
    | "WSP" -> r.WSP
    | "PC" -> r.PC
    | "V0" -> r.V0
    | "V1" -> r.V1
    | "V2" -> r.V2
    | "V3" -> r.V3
    | "V4" -> r.V4
    | "V5" -> r.V5
    | "V6" -> r.V6
    | "V7" -> r.V7
    | "V8" -> r.V8
    | "V9" -> r.V9
    | "V10" -> r.V10
    | "V11" -> r.V11
    | "V12" -> r.V12
    | "V13" -> r.V13
    | "V14" -> r.V14
    | "V15" -> r.V15
    | "V16" -> r.V16
    | "V17" -> r.V17
    | "V18" -> r.V18
    | "V19" -> r.V19
    | "V20" -> r.V20
    | "V21" -> r.V21
    | "V22" -> r.V22
    | "V23" -> r.V23
    | "V24" -> r.V24
    | "V25" -> r.V25
    | "V26" -> r.V26
    | "V27" -> r.V27
    | "V28" -> r.V28
    | "V29" -> r.V29
    | "V30" -> r.V30
    | "V31" -> r.V31
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
    | "Q16" -> r.Q16
    | "Q17" -> r.Q17
    | "Q18" -> r.Q18
    | "Q19" -> r.Q19
    | "Q20" -> r.Q20
    | "Q21" -> r.Q21
    | "Q22" -> r.Q22
    | "Q23" -> r.Q23
    | "Q24" -> r.Q24
    | "Q25" -> r.Q25
    | "Q26" -> r.Q26
    | "Q27" -> r.Q27
    | "Q28" -> r.Q28
    | "Q29" -> r.Q29
    | "Q30" -> r.Q30
    | "Q31" -> r.Q31
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
    | "H0" -> r.H0
    | "H1" -> r.H1
    | "H2" -> r.H2
    | "H3" -> r.H3
    | "H4" -> r.H4
    | "H5" -> r.H5
    | "H6" -> r.H6
    | "H7" -> r.H7
    | "H8" -> r.H8
    | "H9" -> r.H9
    | "H10" -> r.H10
    | "H11" -> r.H11
    | "H12" -> r.H12
    | "H13" -> r.H13
    | "H14" -> r.H14
    | "H15" -> r.H15
    | "H16" -> r.H16
    | "H17" -> r.H17
    | "H18" -> r.H18
    | "H19" -> r.H19
    | "H20" -> r.H20
    | "H21" -> r.H21
    | "H22" -> r.H22
    | "H23" -> r.H23
    | "H24" -> r.H24
    | "H25" -> r.H25
    | "H26" -> r.H26
    | "H27" -> r.H27
    | "H28" -> r.H28
    | "H29" -> r.H29
    | "H30" -> r.H30
    | "H31" -> r.H31
    | "B0" -> r.B0
    | "B1" -> r.B1
    | "B2" -> r.B2
    | "B3" -> r.B3
    | "B4" -> r.B4
    | "B5" -> r.B5
    | "B6" -> r.B6
    | "B7" -> r.B7
    | "B8" -> r.B8
    | "B9" -> r.B9
    | "B10" -> r.B10
    | "B11" -> r.B11
    | "B12" -> r.B12
    | "B13" -> r.B13
    | "B14" -> r.B14
    | "B15" -> r.B15
    | "B16" -> r.B16
    | "B17" -> r.B17
    | "B18" -> r.B18
    | "B19" -> r.B19
    | "B20" -> r.B20
    | "B21" -> r.B21
    | "B22" -> r.B22
    | "B23" -> r.B23
    | "B24" -> r.B24
    | "B25" -> r.B25
    | "B26" -> r.B26
    | "B27" -> r.B27
    | "B28" -> r.B28
    | "B29" -> r.B29
    | "B30" -> r.B30
    | "B31" -> r.B31
    | "FPCR" -> r.FPCR
    | "FPSR" -> r.FPSR
    | "N" -> r.N
    | "Z" -> r.Z
    | "C" -> r.C
    | "V" -> r.V
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
