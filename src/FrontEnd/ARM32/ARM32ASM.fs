module B2R2.FrontEnd.ARM32.ARM32ASM

open B2R2.FrontEnd.ARM32
open B2R2.BinIR.LowUIR
open B2R2

type ParseHelper () =

  inherit IRParseHelper.IRVarParseHelper ()

  let R = RegExprs ()

  override __.RegNames =
    [ "R0"; "R1"; "R2" ; "R3"; "R4"; "R5"; "R6";" R7"; "R8"; "SB"; "SL"; "FP";
    "IP"; "SP"; "LR"; "Q0"; "Q1"; "Q2"; "Q3"; "Q4"; "Q5"; "Q6";"Q7"; "Q8"; "Q9";
    "Q10"; "Q11"; "Q12"; "Q13"; "Q14"; "Q15"; "D0"; "D1"; "D2"; "D3"; "D4";
    "D5"; "D6"; "D7"; "D8"; "D9"; "D10"; "D11"; "D12"; "D13"; "D14"; "D15";
    "D16"; "D17"; "D18"; "D19"; "D20"; "D21"; "D22"; "D23"; "D24"; "D25"; "D26";
    "D27"; "D28"; "D29"; "D30"; "D31"; "S0"; "S1"; "S2"; "S3"; "S4"; "S5"; "S6";
    "S7"; "S8"; "S9"; "S10"; "S11"; "S12"; "S13"; "S14"; "S15"; "S16"; "S17";
    "S18"; "S19"; "S20"; "S21"; "S22"; "S23"; "S24"; "S25"; "S26"; "S27"; "S28";
    "S29"; "S30"; "S31";"PC";"APSR"; "SPSR"; "CPSR"; "FPSCR"; "SCTLR"; "SCR";
    "NSACR" ]

  override __.StrToVar s =
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
    | _ -> raise UnknownRegException

  // FIXME
  override __.InitStateRegs =
    [Register.toRegID Register.D11, BitVector.ofInt32 0 32<rt>]

  // FIXME
  override __.MainRegs = [R.D11]
