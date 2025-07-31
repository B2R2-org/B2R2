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

namespace B2R2.FrontEnd.ARM64

open System.Runtime.CompilerServices
open B2R2

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.ARM64.Tests")>]
do ()

/// Shortcut for Register type.
type internal R = Register

/// Provides several useful functions for handling ARM64 registers.
[<RequireQualifiedAccess>]
module internal Register =
  let toRegType = function
    | R.X0 | R.X1 | R.X2 | R.X3 | R.X4 | R.X5 | R.X6 | R.X7 | R.X8 | R.X9
    | R.X10 | R.X11 | R.X12 | R.X13 | R.X14 | R.X15 | R.X16 | R.X17
    | R.X18 | R.X19 | R.X20 | R.X21 | R.X22 | R.X23 | R.X24 | R.X25
    | R.X26 | R.X27 | R.X28 | R.X29 | R.X30 | R.XZR | R.SP | R.PC
    | R.D0 | R.D1 | R.D2 | R.D3 | R.D4 | R.D5 | R.D6 | R.D7 | R.D8 | R.D9
    | R.D10 | R.D11 | R.D12 | R.D13 | R.D14 | R.D15 | R.D16 | R.D17 | R.D18
    | R.D19 | R.D20 | R.D21 | R.D22 | R.D23 | R.D24 | R.D25 | R.D26 | R.D27
    | R.D28 | R.D29 | R.D30 | R.D31
    | R.V0A | R.V0B | R.V1A | R.V1B | R.V2A | R.V2B | R.V3A | R.V3B
    | R.V4A | R.V4B | R.V5A | R.V5B | R.V6A | R.V6B | R.V7A | R.V7B
    | R.V8A | R.V8B | R.V9A | R.V9B | R.V10A | R.V10B | R.V11A | R.V11B
    | R.V12A | R.V12B | R.V13A | R.V13B | R.V14A | R.V14B | R.V15A | R.V15B
    | R.V16A | R.V16B | R.V17A | R.V17B | R.V18A | R.V18B | R.V19A | R.V19B
    | R.V20A | R.V20B | R.V21A | R.V21B | R.V22A | R.V22B | R.V23A | R.V23B
    | R.V24A | R.V24B | R.V25A | R.V25B | R.V26A | R.V26B | R.V27A | R.V27B
    | R.V28A | R.V28B | R.V29A | R.V29B | R.V30A | R.V30B | R.V31A | R.V31B
    | R.FPCR | R.FPSR | R.ERET | R.NZCV -> 64<rt>
    | R.W0 | R.W1 | R.W2 | R.W3 | R.W4 | R.W5 | R.W6 | R.W7 | R.W8 | R.W9
    | R.W10 | R.W11 | R.W12 | R.W13 | R.W14 | R.W15 | R.W16 | R.W17 | R.W18
    | R.W19 | R.W20 | R.W21 | R.W22 | R.W23 | R.W24 | R.W25 | R.W26 | R.W27
    | R.W28 | R.W29 | R.W30 | R.WZR | R.WSP
    | R.S0 | R.S1 | R.S2 | R.S3 | R.S4 | R.S5 | R.S6 | R.S7 | R.S8 | R.S9
    | R.S10 | R.S11 | R.S12 | R.S13 | R.S14 | R.S15 | R.S16 | R.S17 | R.S18
    | R.S19 | R.S20 | R.S21 | R.S22 | R.S23 | R.S24 | R.S25 | R.S26 | R.S27
    | R.S28 | R.S29 | R.S30 | R.S31 -> 32<rt>
    | R.H0 | R.H1 | R.H2 | R.H3 | R.H4 | R.H5 | R.H6 | R.H7 | R.H8 | R.H9
    | R.H10 | R.H11 | R.H12 | R.H13 | R.H14 | R.H15 | R.H16 | R.H17 | R.H18
    | R.H19 | R.H20 | R.H21 | R.H22 | R.H23 | R.H24 | R.H25 | R.H26 | R.H27
    | R.H28 | R.H29 | R.H30 | R.H31 -> 16<rt>
    | R.B0 | R.B1 | R.B2 | R.B3 | R.B4 | R.B5 | R.B6 | R.B7 | R.B8 | R.B9
    | R.B10 | R.B11 | R.B12 | R.B13 | R.B14 | R.B15 | R.B16 | R.B17 | R.B18
    | R.B19 | R.B20 | R.B21 | R.B22 | R.B23 | R.B24 | R.B25 | R.B26 | R.B27
    | R.B28 | R.B29 | R.B30 | R.B31 -> 8<rt>
    | R.V0 | R.V1 | R.V2 | R.V3 | R.V4 | R.V5 | R.V6 | R.V7 | R.V8 | R.V9
    | R.V10 | R.V11 | R.V12 | R.V13 | R.V14 | R.V15 | R.V16 | R.V17 | R.V18
    | R.V19 | R.V20 | R.V21 | R.V22 | R.V23 | R.V24 | R.V25 | R.V26 | R.V27
    | R.V28 | R.V29 | R.V30 | R.V31
    | R.Q0 | R.Q1 | R.Q2 | R.Q3 | R.Q4 | R.Q5 | R.Q6 | R.Q7 | R.Q8 | R.Q9
    | R.Q10 | R.Q11 | R.Q12 | R.Q13 | R.Q14 | R.Q15 | R.Q16 | R.Q17 | R.Q18
    | R.Q19 | R.Q20 | R.Q21 | R.Q22 | R.Q23 | R.Q24 | R.Q25 | R.Q26 | R.Q27
    | R.Q28 | R.Q29 | R.Q30 | R.Q31 -> 128<rt>
    | R.N | R.Z | R.C | R.V -> 1<rt>
    | _ -> Terminator.impossible ()

  let getOrgSIMDReg = function
    | R.B0 | R.H0 | R.S0 | R.D0 | R.Q0 -> R.V0
    | R.B1 | R.H1 | R.S1 | R.D1 | R.Q1 -> R.V1
    | R.B2 | R.H2 | R.S2 | R.D2 | R.Q2 -> R.V2
    | R.B3 | R.H3 | R.S3 | R.D3 | R.Q3 -> R.V3
    | R.B4 | R.H4 | R.S4 | R.D4 | R.Q4 -> R.V4
    | R.B5 | R.H5 | R.S5 | R.D5 | R.Q5 -> R.V5
    | R.B6 | R.H6 | R.S6 | R.D6 | R.Q6 -> R.V6
    | R.B7 | R.H7 | R.S7 | R.D7 | R.Q7 -> R.V7
    | R.B8 | R.H8 | R.S8 | R.D8 | R.Q8 -> R.V8
    | R.B9 | R.H9 | R.S9 | R.D9 | R.Q9 -> R.V9
    | R.B10 | R.H10 | R.S10 | R.D10 | R.Q10 -> R.V10
    | R.B11 | R.H11 | R.S11 | R.D11 | R.Q11 -> R.V11
    | R.B12 | R.H12 | R.S12 | R.D12 | R.Q12 -> R.V12
    | R.B13 | R.H13 | R.S13 | R.D13 | R.Q13 -> R.V13
    | R.B14 | R.H14 | R.S14 | R.D14 | R.Q14 -> R.V14
    | R.B15 | R.H15 | R.S15 | R.D15 | R.Q15 -> R.V15
    | R.B16 | R.H16 | R.S16 | R.D16 | R.Q16 -> R.V16
    | R.B17 | R.H17 | R.S17 | R.D17 | R.Q17 -> R.V17
    | R.B18 | R.H18 | R.S18 | R.D18 | R.Q18 -> R.V18
    | R.B19 | R.H19 | R.S19 | R.D19 | R.Q19 -> R.V19
    | R.B20 | R.H20 | R.S20 | R.D20 | R.Q20 -> R.V20
    | R.B21 | R.H21 | R.S21 | R.D21 | R.Q21 -> R.V21
    | R.B22 | R.H22 | R.S22 | R.D22 | R.Q22 -> R.V22
    | R.B23 | R.H23 | R.S23 | R.D23 | R.Q23 -> R.V23
    | R.B24 | R.H24 | R.S24 | R.D24 | R.Q24 -> R.V24
    | R.B25 | R.H25 | R.S25 | R.D25 | R.Q25 -> R.V25
    | R.B26 | R.H26 | R.S26 | R.D26 | R.Q26 -> R.V26
    | R.B27 | R.H27 | R.S27 | R.D27 | R.Q27 -> R.V27
    | R.B28 | R.H28 | R.S28 | R.D28 | R.Q28 -> R.V28
    | R.B29 | R.H29 | R.S29 | R.D29 | R.Q29 -> R.V29
    | R.B30 | R.H30 | R.S30 | R.D30 | R.Q30 -> R.V30
    | R.B31 | R.H31 | R.S31 | R.D31 | R.Q31 -> R.V31
    | _ -> Terminator.impossible ()

  let getAliases = function
    | R.X0 | R.W0 -> [| R.X0; R.W0 |]
    | R.X1 | R.W1 -> [| R.X1; R.W1 |]
    | R.X2 | R.W2 -> [| R.X2; R.W2 |]
    | R.X3 | R.W3 -> [| R.X3; R.W3 |]
    | R.X4 | R.W4 -> [| R.X4; R.W4 |]
    | R.X5 | R.W5 -> [| R.X5; R.W5 |]
    | R.X6 | R.W6 -> [| R.X6; R.W6 |]
    | R.X7 | R.W7 -> [| R.X7; R.W7 |]
    | R.X8 | R.W8 -> [| R.X8; R.W8 |]
    | R.X9 | R.W9 -> [| R.X9; R.W9 |]
    | R.X10 | R.W10 -> [| R.X10; R.W10 |]
    | R.X11 | R.W11 -> [| R.X11; R.W11 |]
    | R.X12 | R.W12 -> [| R.X12; R.W12 |]
    | R.X13 | R.W13 -> [| R.X13; R.W13 |]
    | R.X14 | R.W14 -> [| R.X14; R.W14 |]
    | R.X15 | R.W15 -> [| R.X15; R.W15 |]
    | R.X16 | R.W16 -> [| R.X16; R.W16 |]
    | R.X17 | R.W17 -> [| R.X17; R.W17 |]
    | R.X18 | R.W18 -> [| R.X18; R.W18 |]
    | R.X19 | R.W19 -> [| R.X19; R.W19 |]
    | R.X20 | R.W20 -> [| R.X20; R.W20 |]
    | R.X21 | R.W21 -> [| R.X21; R.W21 |]
    | R.X22 | R.W22 -> [| R.X22; R.W22 |]
    | R.X23 | R.W23 -> [| R.X23; R.W23 |]
    | R.X24 | R.W24 -> [| R.X24; R.W24 |]
    | R.X25 | R.W25 -> [| R.X25; R.W25 |]
    | R.X26 | R.W26 -> [| R.X26; R.W26 |]
    | R.X27 | R.W27 -> [| R.X27; R.W27 |]
    | R.X28 | R.W28 -> [| R.X28; R.W28 |]
    | R.X29 | R.W29 -> [| R.X29; R.W29 |]
    | R.X30 | R.W30 -> [| R.X30; R.W30 |]
    | R.V0 | R.D0 | R.S0 -> [| R.V0; R.D0; R.S0 |]
    | R.V1 | R.D1 | R.S1 -> [| R.V1; R.D1; R.S1 |]
    | R.V2 | R.D2 | R.S2 -> [| R.V2; R.D2; R.S2 |]
    | R.V3 | R.D3 | R.S3 -> [| R.V3; R.D3; R.S3 |]
    | R.V4 | R.D4 | R.S4 -> [| R.V4; R.D4; R.S4 |]
    | R.V5 | R.D5 | R.S5 -> [| R.V5; R.D5; R.S5 |]
    | R.V6 | R.D6 | R.S6 -> [| R.V6; R.D6; R.S6 |]
    | R.V7 | R.D7 | R.S7 -> [| R.V7; R.D7; R.S7 |]
    | R.V8 | R.D8 | R.S8 -> [| R.V8; R.D8; R.S8 |]
    | R.V9 | R.D9 | R.S9 -> [| R.V9; R.D9; R.S9 |]
    | R.V10 | R.D10 | R.S10 -> [| R.V10; R.D10; R.S10 |]
    | R.V11 | R.D11 | R.S11 -> [| R.V11; R.D11; R.S11 |]
    | R.V12 | R.D12 | R.S12 -> [| R.V12; R.D12; R.S12 |]
    | R.V13 | R.D13 | R.S13 -> [| R.V13; R.D13; R.S13 |]
    | R.V14 | R.D14 | R.S14 -> [| R.V14; R.D14; R.S14 |]
    | R.V15 | R.D15 | R.S15 -> [| R.V15; R.D15; R.S15 |]
    | R.V16 | R.D16 | R.S16 -> [| R.V16; R.D16; R.S16 |]
    | R.V17 | R.D17 | R.S17 -> [| R.V17; R.D17; R.S17 |]
    | R.V18 | R.D18 | R.S18 -> [| R.V18; R.D18; R.S18 |]
    | R.V19 | R.D19 | R.S19 -> [| R.V19; R.D19; R.S19 |]
    | R.V20 | R.D20 | R.S20 -> [| R.V20; R.D20; R.S20 |]
    | R.V21 | R.D21 | R.S21 -> [| R.V21; R.D21; R.S21 |]
    | R.V22 | R.D22 | R.S22 -> [| R.V22; R.D22; R.S22 |]
    | R.V23 | R.D23 | R.S23 -> [| R.V23; R.D23; R.S23 |]
    | R.V24 | R.D24 | R.S24 -> [| R.V24; R.D24; R.S24 |]
    | R.V25 | R.D25 | R.S25 -> [| R.V25; R.D25; R.S25 |]
    | R.V26 | R.D26 | R.S26 -> [| R.V26; R.D26; R.S26 |]
    | R.V27 | R.D27 | R.S27 -> [| R.V27; R.D27; R.S27 |]
    | R.V28 | R.D28 | R.S28 -> [| R.V28; R.D28; R.S28 |]
    | R.V29 | R.D29 | R.S29 -> [| R.V29; R.D29; R.S29 |]
    | R.V30 | R.D30 | R.S30 -> [| R.V30; R.D30; R.S30 |]
    | R.V31 | R.D31 | R.S31 -> [| R.V31; R.D31; R.S31 |]
    | r -> [| r |]
