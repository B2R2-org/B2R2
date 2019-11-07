namespace B2R2.Assembler

open B2R2

type AsmInterface (isa: ISA, startAddress) =
  let parser =
    match isa.Arch with
    | Architecture.MIPS1
    | Architecture.MIPS2
    | Architecture.MIPS3
    | Architecture.MIPS32
    | Architecture.MIPS32R2
    | Architecture.MIPS32R6
    | Architecture.MIPS4
    | Architecture.MIPS5
    | Architecture.MIPS64 -> MIPS.AsmParser (isa, startAddress)
    | _ -> raise InvalidISAException

  member __.Run asm = parser.Run asm
