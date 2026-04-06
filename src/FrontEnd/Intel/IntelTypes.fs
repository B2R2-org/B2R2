namespace B2R2.FrontEnd.Intel

[<RequireQualifiedAccess>]
type OpcodeClass =
  | Normal of OpcodeMap
  | VEX of OpcodeMap
  | EVEX of OpcodeMap

and OpcodeMap =
  | OneByte
  | TwoBytes
  | ThreeBytes38
  | ThreeBytes3A
  | MAP4
  | MAP5
  | MAP6
  | MAP7

type VectorLength =
  | None = 0
  | V128 = 1
  | V256 = 2
  | V512 = 3

type PrefixType =
  | Legacy of PrefixKind
  | Mandatory of PrefixKind

and PrefixKind =
  | NP
  | P66
  | F3
  | F2

type REXPrefixType =
  | NOREX = 0
  | WIG = 1
  | W0 = 2
  | W1 = 3
  | REX = 4
  | REXW = 5

type OperandType =
  | NoOpr
  | RM of OprSize
  | RMdiff of OprSize * OprSize
  | Reg of OprSize
  | Sreg
  | FixedReg of Register * Visibility
  | STReg of Register option
  | BM of OprSize
  | BndReg
  | MM of OprSize
  | MMXReg
  | Mem of OprSize
  | Moffs of OprSize
  | Far of OprSize
  | Imm of OprSize
  | FixedImm of int
  | Rel of OprSize
  | Unknown of string (* XXX: Temp *)

and OprSize =
  | Sz8
  | Sz16
  | Sz32
  | Sz64
  | Sz80
  | Sz128
  | Sz256
  | Sz512
  | SzUnknown

and Visibility =
  | Explicit
  | Implicit

type ModRMType =
  | NoModRM
  | ModRM of OprType (* /r *)
  | ModRMOp0 of OprType (* /0 *)
  | ModRMOp1 of OprType (* /1 *)
  | ModRMOp2 of OprType (* /2 *)
  | ModRMOp3 of OprType (* /3 *)
  | ModRMOp4 of OprType (* /4 *)
  | ModRMOp5 of OprType (* /5 *)
  | ModRMOp6 of OprType (* /6 *)
  | ModRMOp7 of OprType (* /7 *)
  | FixedModRM of byte (* /digit: fully fixed ModRM byte *)
  | STiModRM of byte (* ex) C0+i: mod=11, low 3 bits select ST(i) *)

and OprType =
  | OpReg
  | OpMem
  | OpRegMem

type OpEn =
  | None = 0
  | A = 1
  | B = 2
  | C = 3
  | D = 4
  | E = 5
  | F = 6
  | FD = 7
  | G = 8
  | I = 9
  | II = 10
  | M = 11
  | M1 = 12
  | MC = 13
  | MI = 14
  | MR = 15
  | MRC = 16
  | MRI = 17
  | MVR = 18
  | O = 19
  | OI = 20
  | R = 21
  | RM = 22
  | RM0 = 23
  | RMI = 24
  | RMV = 25
  | RR = 26
  | RRI = 27
  | RVM = 28
  | RVMI = 29
  | RVMR = 30
  | RVR = 31
  | S = 32
  | TD = 33
  | VM = 34
  | ZO = 35

type Mode64 =
  | None = 0
  | NE = 1
  | NA = 2
  | NS = 3
  | Valid = 4
  | Invalid = 5
  | VNE = 6
  | Inv = 7

type CompatLegMode =
  | None = 0
  | NE = 1
  | NA = 2
  | Valid = 3
  | Invalid = 4

/// Core instruction representation used in the generated source code.
type InstructionCore =
  { OpcodeByte: uint32
    Opcode: Opcode
    PrefixType: PrefixType
    REXPrefixType: REXPrefixType
    VectorLength: VectorLength
    ModRM: ModRMType
    Operands: OperandType[]
    OpEn: OpEn
    Mode64: Mode64
    Compat: CompatLegMode }