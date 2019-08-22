module B2R2.FrontEnd.MIPS.MIPSASM
open B2R2
open B2R2.FrontEnd.MIPS
open B2R2.BinIR.LowUIR

type ParseHelper (wordSize) =

  inherit IRParseHelper.IRVarParseHelper ()

  let R = RegExprs (wordSize)

  override __.RegNames =
    ["HI"; "LO"; "PC"; "R0"; "R1"; "R2"; "R3"; "R4"; "R5"; "R6"; "R7"; "R8";
    "R9"; "R10"; "R11"; "R12"; "R13"; "R14"; "R15"; "R16"; "R17"; "R18"; "R19";
    "R20"; "R21"; "R22"; "R23"; "R24"; "R25"; "R26"; "R27"; "R28"; "R29"; "R30";
    "R31"; "F0"; "F1"; "F2"; "F3"; "F4"; "F5"; "F6"; "F7"; "F8"; "F9"; "F10";
    "F11"; "F12"; "F13"; "F14"; "F15"; "F16"; "F17"; "F18"; "F19"; "F20"; "F21";
    "F22"; "F23"; "F24"; "F25"; "F26"; "F27"; "F28"; "F29"; "F30"; "F31" ]

  override __.StrToVar s =
    match s with
    | "HI" -> R.HI
    | "LO" -> R.LO
    | "PC" -> R.PC
    | "R0" -> R.R0
    | "R1" -> R.R1
    | "R2" -> R.R2
    | "R3" -> R.R3
    | "R4" -> R.R4
    | "R5" -> R.R5
    | "R6" -> R.R6
    | "R7" -> R.R7
    | "R8" -> R.R8
    | "R9" -> R.R9
    | "R10" -> R.R10
    | "R11" -> R.R11
    | "R12" -> R.R12
    | "R13" -> R.R13
    | "R14" -> R.R14
    | "R15" -> R.R15
    | "R16" -> R.R16
    | "R17" -> R.R17
    | "R18" -> R.R18
    | "R19" -> R.R19
    | "R20" -> R.R20
    | "R21" -> R.R21
    | "R22" -> R.R22
    | "R23" -> R.R23
    | "R24" -> R.R24
    | "R25" -> R.R25
    | "R26" -> R.R26
    | "R27" -> R.R27
    | "R28" -> R.R28
    | "R29" -> R.R29
    | "R30" -> R.R30
    | "R31" -> R.R31
    | "F0" -> R.F0
    | "F1" -> R.F1
    | "F2" -> R.F2
    | "F3" -> R.F3
    | "F4" -> R.F4
    | "F5" -> R.F5
    | "F6" -> R.F6
    | "F7" -> R.F7
    | "F8" -> R.F8
    | "F9" -> R.F9
    | "F10" -> R.F10
    | "F11"-> R.F11
    | "F12" -> R.F12
    | "F13" -> R.F13
    | "F14" -> R.F14
    | "F15" -> R.F15
    | "F16" -> R.F16
    | "F17" -> R.F17
    | "F18" -> R.F18
    | "F19" -> R.F19
    | "F20" -> R.F20
    | "F21" -> R.F21
    | "F22" -> R.F22
    | "F23" -> R.F23
    | "F24" -> R.F24
    | "F25" -> R.F25
    | "F26" -> R.F26
    | "F27" -> R.F27
    | "F28" -> R.F28
    | "F29" -> R.F29
    | "F30" -> R.F30
    | "F31" -> R.F31
    | _ -> raise B2R2.FrontEnd.UnhandledRegExprException

  (*override __.InitStateRegs =
    [R.HI; R.LO; R.PC; R.R0; R.R1; R.R2; R.R3; R.R4; R.R5; R.R6; R.R7; R.R8;
    R.R9; R.R10; R.R11; R.R12; R.R13; R.R14; R.R15; R.R16; R.R17; R.R18; R.R19;
    R.R20; R.R21; R.R22; R.R23; R.R24; R.R25; R.R26; R.R27; R.R28; R.R29; R.R30;
    R.R31; R.F0; R.F1; R.F2; R.F3; R.F4; R.F5; R.F6; R.F7; R.F8; R.F9; R.F10;
    R.F11; R.F12; R.F13; R.F14; R.F15; R.F16; R.F17; R.F18; R.F19; R.F20; R.F21;
    R.F22; R.F23; R.F24; R.F25; R.F26; R.F27; R.F28; R.F29; R.F30; R.F31 ]
    *)

  // FIXME
  override __.InitStateRegs =
    [Register.toRegID Register.F0, BitVector.ofInt32 0 32<rt>]

  // FIXME
  override __.MainRegs =
    [R.HI; R.LO; R.PC; R.R7; R.R8; R.R9; R.R10; R.R11; R.R12; R.R13;
    R.R14; R.R15; R.R16; R.R17; R.R18; R.R19; R.R20; R.R21; R.R22;
    R.R23; R.R24; R.R27; R.R28; R.R29; R.R30; R.R31; R.F0; R.F1; R.F2;
    R.F3; R.F4; R.F5; R.F6; R.F7; R.F8; R.F9; R.F10; R.F11; R.F12;
    R.F13; R.F14; R.F15; R.F16; R.F17; R.F18; R.F19; R.F20; R.F21;
    R.F22; R.F23; R.F24; R.F25; R.F26; R.F27; R.F28; R.F29; R.F30;
    R.F31 ]


