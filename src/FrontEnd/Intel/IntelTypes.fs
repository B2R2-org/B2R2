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
  /// Register or Memory.
  | RM of OprSize
  /// Register or Memory operand with different sizes.
  | RMdiff of OprSize * OprSize
  /// Register or Memory with embedded rounding {er} (only EVEX).
  | RMEr of OprSize * OprSize
  /// Register or Memory with suppress-all-exceptions {sae} (only EVEX).
  | RMSae of OprSize * OprSize
  /// Register or Memory with broadcast (only EVEX).
  | RMBcst of OprSize * OprSize * OprSize
  /// Register or Memory with broadcast and {er} (only EVEX).
  | RMBcstEr of OprSize * OprSize * OprSize
  /// Register or Memory with broadcast and {sae} (only EVEX).
  | RMBcstSae of OprSize * OprSize * OprSize
  /// Register with suppress-all-exceptions {sae} (only EVEX).
  | RegSae of OprSize
  /// Register.
  | Reg of OprSize * OprRegType
  /// Address-size-dependent register operand.
  | RegAddr
  /// Opmask register.
  | OpMaskReg
  /// Opmask register or memory.
  | KM of OprSize
  /// Segment register.
  | Sreg
  /// Control register.
  | CtrlReg
  /// Debug register.
  | DebugReg
  /// Fixed register.
  | FixedReg of Register
  /// ST(i) register.
  | STReg of Register option
  /// Bound register or memory.
  | BM of OprSize
  /// Bound register.
  | BndReg
  /// MMX register or memory.
  | MM of OprSize
  /// MMX register.
  | MMXReg
  /// Memory.
  | Mem of OprSize
  /// Memory with VSIB addressing (eg. vm32x).
  | MemVSIB of OprSize
  /// Memory offset.
  | Moffs of OprSize
  /// Far memory offset.
  | Far of OprSize
  /// Immediate.
  | Imm of OprSize
  /// Fixed immediate.
  | FixedImm of int
  /// Relative offset.
  | Rel of OprSize
  | Unknown of string (* XXX: Temp *)

and OprSize =
  | Sz8
  | Sz16
  | Sz32
  | Sz48
  | Sz64
  | Sz80
  | Sz128
  | Sz256
  | Sz384
  | Sz512
  | Sz1024
  | SzUnknown

and OprRegType =
  | RegBit (* ModRM:reg *)
  | RMBit (* ModRM:r/m *)
  | VVVV (* (E)VEX.vvvv *)
  | IS4 (* imm8[7:4] *)
  | OpRd (* opcode + rd *)
  | Unused

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
  | VMI = 35
  | ZO = 36

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

/// The tupletype will be referenced in the instruction operand encoding table
/// in the reference page of each instruction, providing the cross reference for
/// the scaling factor N to encoding memory addressing operand.
type TupleType =
  /// Compressed Displacement (DISP8*N) Affected by Embedded Broadcast.
  | Full = 0
  | Half = 1
  /// EVEX DISP8*N for Instructions Not Affected by Embedded Broadcast.
  | FullMem = 2
  | Tuple1Scalar = 3
  | Tuple1Fixed = 4
  | Tuple2 = 5
  | Tuple4 = 6
  | Tuple8 = 7
  | HalfMem = 8
  | QuarterMem = 9
  | EighthMem = 10
  | Mem128 = 11
  | MOVDDUP = 12
  | Quarter = 13
  | Scalar = 14
  | Tuple1_4X = 15
  | NA = 16 (* N/A *)

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
    Compat: CompatLegMode
    TupleType: TupleType }