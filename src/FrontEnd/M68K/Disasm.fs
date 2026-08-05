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

module internal B2R2.FrontEnd.M68K.Disasm

open B2R2
open B2R2.FrontEnd.BinLifter

let opCodeToString = function
  | Op.ABCD -> "abcd"
  | Op.ADD -> "add"
  | Op.ADDA -> "adda"
  | Op.ADDI -> "addi"
  | Op.ADDQ -> "addq"
  | Op.ADDX -> "addx"
  | Op.AND -> "and"
  | Op.ANDI -> "andi"
  | Op.ASL -> "asl"
  | Op.ASR -> "asr"
  | Op.BCC -> "bcc"
  | Op.BCHG -> "bchg"
  | Op.BCLR -> "bclr"
  | Op.BCS -> "bcs"
  | Op.BEQ -> "beq"
  | Op.BFCHG -> "bfchg"
  | Op.BFCLR -> "bfclr"
  | Op.BFEXTS -> "bfexts"
  | Op.BFEXTU -> "bfextu"
  | Op.BFFFO -> "bfffo"
  | Op.BFINS -> "bfins"
  | Op.BFSET -> "bfset"
  | Op.BFTST -> "bftst"
  | Op.BGE -> "bge"
  | Op.BGT -> "bgt"
  | Op.BHI -> "bhi"
  | Op.BKPT -> "bkpt"
  | Op.BLE -> "ble"
  | Op.BLS -> "bls"
  | Op.BLT -> "blt"
  | Op.BMI -> "bmi"
  | Op.BNE -> "bne"
  | Op.BPL -> "bpl"
  | Op.BRA -> "bra"
  | Op.BSET -> "bset"
  | Op.BSR -> "bsr"
  | Op.BTST -> "btst"
  | Op.BVC -> "bvc"
  | Op.BVS -> "bvs"
  | Op.CALLM -> "callm"
  | Op.CAS -> "cas"
  | Op.CAS2 -> "cas2"
  | Op.CHK -> "chk"
  | Op.CHK2 -> "chk2"
  | Op.CINVA -> "cinva"
  | Op.CINVL -> "cinvl"
  | Op.CINVP -> "cinvp"
  | Op.CLR -> "clr"
  | Op.CMP -> "cmp"
  | Op.CMP2 -> "cmp2"
  | Op.CMPA -> "cmpa"
  | Op.CMPI -> "cmpi"
  | Op.CMPM -> "cmpm"
  | Op.CPUSHA -> "cpusha"
  | Op.CPUSHL -> "cpushl"
  | Op.CPUSHP -> "cpushp"
  | Op.DBCC -> "dbcc"
  | Op.DBCS -> "dbcs"
  | Op.DBEQ -> "dbeq"
  | Op.DBF -> "dbf"
  | Op.DBGE -> "dbge"
  | Op.DBGT -> "dbgt"
  | Op.DBHI -> "dbhi"
  | Op.DBLE -> "dble"
  | Op.DBLS -> "dbls"
  | Op.DBLT -> "dblt"
  | Op.DBMI -> "dbmi"
  | Op.DBNE -> "dbne"
  | Op.DBPL -> "dbpl"
  | Op.DBT -> "dbt"
  | Op.DBVC -> "dbvc"
  | Op.DBVS -> "dbvs"
  | Op.DIVS -> "divs"
  | Op.DIVSL -> "divsl"
  | Op.DIVU -> "divu"
  | Op.DIVUL -> "divul"
  | Op.EOR -> "eor"
  | Op.EORI -> "eori"
  | Op.EXG -> "exg"
  | Op.EXT -> "ext"
  | Op.EXTB -> "extb"
  | Op.FABS -> "fabs"
  | Op.FACOS -> "facos"
  | Op.FADD -> "fadd"
  | Op.FASIN -> "fasin"
  | Op.FATAN -> "fatan"
  | Op.FATANH -> "fatanh"
  | Op.FBEQ -> "fbeq"
  | Op.FBF -> "fbf"
  | Op.FBGE -> "fbge"
  | Op.FBGL -> "fbgl"
  | Op.FBGLE -> "fbgle"
  | Op.FBGT -> "fbgt"
  | Op.FBLE -> "fble"
  | Op.FBLT -> "fblt"
  | Op.FBNE -> "fbne"
  | Op.FBNGE -> "fbnge"
  | Op.FBNGL -> "fbngl"
  | Op.FBNGLE -> "fbngle"
  | Op.FBNGT -> "fbngt"
  | Op.FBNLE -> "fbnle"
  | Op.FBNLT -> "fbnlt"
  | Op.FBOGE -> "fboge"
  | Op.FBOGL -> "fbogl"
  | Op.FBOGT -> "fbogt"
  | Op.FBOLE -> "fbole"
  | Op.FBOLT -> "fbolt"
  | Op.FBOR -> "fbor"
  | Op.FBSEQ -> "fbseq"
  | Op.FBSF -> "fbsf"
  | Op.FBSNE -> "fbsne"
  | Op.FBST -> "fbst"
  | Op.FBT -> "fbt"
  | Op.FBUEQ -> "fbueq"
  | Op.FBUGE -> "fbuge"
  | Op.FBUGT -> "fbugt"
  | Op.FBULE -> "fbule"
  | Op.FBULT -> "fbult"
  | Op.FBUN -> "fbun"
  | Op.FCMP -> "fcmp"
  | Op.FCOS -> "fcos"
  | Op.FCOSH -> "fcosh"
  | Op.FDABS -> "fdabs"
  | Op.FDADD -> "fdadd"
  | Op.FDBEQ -> "fdbeq"
  | Op.FDBF -> "fdbf"
  | Op.FDBGE -> "fdbge"
  | Op.FDBGL -> "fdbgl"
  | Op.FDBGLE -> "fdbgle"
  | Op.FDBGT -> "fdbgt"
  | Op.FDBLE -> "fdble"
  | Op.FDBLT -> "fdblt"
  | Op.FDBNE -> "fdbne"
  | Op.FDBNGE -> "fdbnge"
  | Op.FDBNGL -> "fdbngl"
  | Op.FDBNGLE -> "fdbngle"
  | Op.FDBNGT -> "fdbngt"
  | Op.FDBNLE -> "fdbnle"
  | Op.FDBNLT -> "fdbnlt"
  | Op.FDBOGE -> "fdboge"
  | Op.FDBOGL -> "fdbogl"
  | Op.FDBOGT -> "fdbogt"
  | Op.FDBOLE -> "fdbole"
  | Op.FDBOLT -> "fdbolt"
  | Op.FDBOR -> "fdbor"
  | Op.FDBSEQ -> "fdbseq"
  | Op.FDBSF -> "fdbsf"
  | Op.FDBSNE -> "fdbsne"
  | Op.FDBST -> "fdbst"
  | Op.FDBT -> "fdbt"
  | Op.FDBUEQ -> "fdbueq"
  | Op.FDBUGE -> "fdbuge"
  | Op.FDBUGT -> "fdbugt"
  | Op.FDBULE -> "fdbule"
  | Op.FDBULT -> "fdbult"
  | Op.FDBUN -> "fdbun"
  | Op.FDDIV -> "fddiv"
  | Op.FDIV -> "fdiv"
  | Op.FDMOVE -> "fdmove"
  | Op.FDMUL -> "fdmul"
  | Op.FDNEG -> "fdneg"
  | Op.FDSQRT -> "fdsqrt"
  | Op.FDSUB -> "fdsub"
  | Op.FETOX -> "fetox"
  | Op.FETOXM1 -> "fetoxm1"
  | Op.FGETEXP -> "fgetexp"
  | Op.FGETMAN -> "fgetman"
  | Op.FINT -> "fint"
  | Op.FINTRZ -> "fintrz"
  | Op.FLOG10 -> "flog10"
  | Op.FLOG2 -> "flog2"
  | Op.FLOGN -> "flogn"
  | Op.FLOGNP1 -> "flognp1"
  | Op.FMOD -> "fmod"
  | Op.FMOVE -> "fmove"
  | Op.FMOVECR -> "fmovecr"
  | Op.FMOVEM -> "fmovem"
  | Op.FMUL -> "fmul"
  | Op.FNEG -> "fneg"
  | Op.FNOP -> "fnop"
  | Op.FREM -> "frem"
  | Op.FRESTORE -> "frestore"
  | Op.FSABS -> "fsabs"
  | Op.FSADD -> "fsadd"
  | Op.FSAVE -> "fsave"
  | Op.FSCALE -> "fscale"
  | Op.FSDIV -> "fsdiv"
  | Op.FSEQ -> "fseq"
  | Op.FSF -> "fsf"
  | Op.FSGE -> "fsge"
  | Op.FSGL -> "fsgl"
  | Op.FSGLDIV -> "fsgldiv"
  | Op.FSGLE -> "fsgle"
  | Op.FSGLMUL -> "fsglmul"
  | Op.FSGT -> "fsgt"
  | Op.FSIN -> "fsin"
  | Op.FSINCOS -> "fsincos"
  | Op.FSINH -> "fsinh"
  | Op.FSLE -> "fsle"
  | Op.FSLT -> "fslt"
  | Op.FSMOVE -> "fsmove"
  | Op.FSMUL -> "fsmul"
  | Op.FSNE -> "fsne"
  | Op.FSNEG -> "fsneg"
  | Op.FSNGE -> "fsnge"
  | Op.FSNGL -> "fsngl"
  | Op.FSNGLE -> "fsngle"
  | Op.FSNGT -> "fsngt"
  | Op.FSNLE -> "fsnle"
  | Op.FSNLT -> "fsnlt"
  | Op.FSOGE -> "fsoge"
  | Op.FSOGL -> "fsogl"
  | Op.FSOGT -> "fsogt"
  | Op.FSOLE -> "fsole"
  | Op.FSOLT -> "fsolt"
  | Op.FSOR -> "fsor"
  | Op.FSQRT -> "fsqrt"
  | Op.FSSEQ -> "fsseq"
  | Op.FSSF -> "fssf"
  | Op.FSSNE -> "fssne"
  | Op.FSSQRT -> "fssqrt"
  | Op.FSST -> "fsst"
  | Op.FSSUB -> "fssub"
  | Op.FST -> "fst"
  | Op.FSUB -> "fsub"
  | Op.FSUEQ -> "fsueq"
  | Op.FSUGE -> "fsuge"
  | Op.FSUGT -> "fsugt"
  | Op.FSULE -> "fsule"
  | Op.FSULT -> "fsult"
  | Op.FSUN -> "fsun"
  | Op.FTAN -> "ftan"
  | Op.FTANH -> "ftanh"
  | Op.FTENTOX -> "ftentox"
  | Op.FTRAPEQ -> "ftrapeq"
  | Op.FTRAPF -> "ftrapf"
  | Op.FTRAPGE -> "ftrapge"
  | Op.FTRAPGL -> "ftrapgl"
  | Op.FTRAPGLE -> "ftrapgle"
  | Op.FTRAPGT -> "ftrapgt"
  | Op.FTRAPLE -> "ftraple"
  | Op.FTRAPLT -> "ftraplt"
  | Op.FTRAPNE -> "ftrapne"
  | Op.FTRAPNGE -> "ftrapnge"
  | Op.FTRAPNGL -> "ftrapngl"
  | Op.FTRAPNGLE -> "ftrapngle"
  | Op.FTRAPNGT -> "ftrapngt"
  | Op.FTRAPNLE -> "ftrapnle"
  | Op.FTRAPNLT -> "ftrapnlt"
  | Op.FTRAPOGE -> "ftrapoge"
  | Op.FTRAPOGL -> "ftrapogl"
  | Op.FTRAPOGT -> "ftrapogt"
  | Op.FTRAPOLE -> "ftrapole"
  | Op.FTRAPOLT -> "ftrapolt"
  | Op.FTRAPOR -> "ftrapor"
  | Op.FTRAPSEQ -> "ftrapseq"
  | Op.FTRAPSF -> "ftrapsf"
  | Op.FTRAPSNE -> "ftrapsne"
  | Op.FTRAPST -> "ftrapst"
  | Op.FTRAPT -> "ftrapt"
  | Op.FTRAPUEQ -> "ftrapueq"
  | Op.FTRAPUGE -> "ftrapuge"
  | Op.FTRAPUGT -> "ftrapugt"
  | Op.FTRAPULE -> "ftrapule"
  | Op.FTRAPULT -> "ftrapult"
  | Op.FTRAPUN -> "ftrapun"
  | Op.FTST -> "ftst"
  | Op.FTWOTOX -> "ftwotox"
  | Op.ILLEGAL -> "illegal"
  | Op.JMP -> "jmp"
  | Op.JSR -> "jsr"
  | Op.LEA -> "lea"
  | Op.LINK -> "link"
  | Op.LSL -> "lsl"
  | Op.LSR -> "lsr"
  | Op.MOVE -> "move"
  | Op.MOVE16 -> "move16"
  | Op.MOVEA -> "movea"
  | Op.MOVEC -> "movec"
  | Op.MOVEM -> "movem"
  | Op.MOVEP -> "movep"
  | Op.MOVEQ -> "moveq"
  | Op.MOVES -> "moves"
  | Op.MULS -> "muls"
  | Op.MULU -> "mulu"
  | Op.NBCD -> "nbcd"
  | Op.NEG -> "neg"
  | Op.NEGX -> "negx"
  | Op.NOP -> "nop"
  | Op.NOT -> "not"
  | Op.OR -> "or"
  | Op.ORI -> "ori"
  | Op.PACK -> "pack"
  | Op.PEA -> "pea"
  | Op.PFLUSH -> "pflush"
  | Op.PFLUSHA -> "pflusha"
  | Op.PFLUSHAN -> "pflushan"
  | Op.PFLUSHN -> "pflushn"
  | Op.PTESTR -> "ptestr"
  | Op.PTESTW -> "ptestw"
  | Op.RESET -> "reset"
  | Op.ROL -> "rol"
  | Op.ROR -> "ror"
  | Op.ROXL -> "roxl"
  | Op.ROXR -> "roxr"
  | Op.RTD -> "rtd"
  | Op.RTE -> "rte"
  | Op.RTM -> "rtm"
  | Op.RTR -> "rtr"
  | Op.RTS -> "rts"
  | Op.SBCD -> "sbcd"
  | Op.SCC -> "scc"
  | Op.SCS -> "scs"
  | Op.SEQ -> "seq"
  | Op.SF -> "sf"
  | Op.SGE -> "sge"
  | Op.SGT -> "sgt"
  | Op.SHI -> "shi"
  | Op.SLE -> "sle"
  | Op.SLS -> "sls"
  | Op.SLT -> "slt"
  | Op.SMI -> "smi"
  | Op.SNE -> "sne"
  | Op.SPL -> "spl"
  | Op.ST -> "st"
  | Op.STOP -> "stop"
  | Op.SUB -> "sub"
  | Op.SUBA -> "suba"
  | Op.SUBI -> "subi"
  | Op.SUBQ -> "subq"
  | Op.SUBX -> "subx"
  | Op.SVC -> "svc"
  | Op.SVS -> "svs"
  | Op.SWAP -> "swap"
  | Op.TAS -> "tas"
  | Op.TRAP -> "trap"
  | Op.TRAPCC -> "trapcc"
  | Op.TRAPCS -> "trapcs"
  | Op.TRAPEQ -> "trapeq"
  | Op.TRAPF -> "trapf"
  | Op.TRAPGE -> "trapge"
  | Op.TRAPGT -> "trapgt"
  | Op.TRAPHI -> "traphi"
  | Op.TRAPLE -> "traple"
  | Op.TRAPLS -> "trapls"
  | Op.TRAPLT -> "traplt"
  | Op.TRAPMI -> "trapmi"
  | Op.TRAPNE -> "trapne"
  | Op.TRAPPL -> "trappl"
  | Op.TRAPT -> "trapt"
  | Op.TRAPV -> "trapv"
  | Op.TRAPVC -> "trapvc"
  | Op.TRAPVS -> "trapvs"
  | Op.TST -> "tst"
  | Op.UNLK -> "unlk"
  | Op.UNPK -> "unpk"
  | _ -> Terminator.impossible ()

let private sizeToString = function
  | Sz.Byte -> ".b"
  | Sz.Word -> ".w"
  | Sz.Long -> ".l"
  | Sz.Single -> ".s"
  | Sz.Double -> ".d"
  | Sz.Extended -> ".x"
  | Sz.Packed -> ".p"
  | Sz.NoSize -> ""
  | _ -> Terminator.impossible ()

let private accumulateStr (str: string) (builder: IDisasmBuilder) =
  builder.Accumulate(AsmWordKind.String, str)

let private accumulateReg reg (builder: IDisasmBuilder) =
  builder.Accumulate(AsmWordKind.Variable, Register.toString reg)

/// Writes a displacement, which every addressing mode that has one treats as
/// signed, so a negative one reads as such rather than as a wide hex value.
let private accumulateDisp (v: int64) (builder: IDisasmBuilder) =
  if v < 0L then
    accumulateStr "-" builder
    builder.Accumulate(AsmWordKind.Value, HexString.ofInt64 -v)
  else
    builder.Accumulate(AsmWordKind.Value, HexString.ofInt64 v)

/// Writes the index register together with the width it is read at and the
/// factor it is scaled by, which is the "Xn.SIZE*SCALE" of the manual. A factor
/// of one is what every model reads when the scale bits are absent, so leaving
/// it off keeps those encodings from reading as though they had said something.
let private accumulateIndex (idx: IndexReg) (builder: IDisasmBuilder) =
  accumulateReg idx.Reg builder
  accumulateStr (if idx.IsLong then ".l" else ".w") builder
  if idx.Scale > 1 then
    accumulateStr "*" builder
    builder.Accumulate(AsmWordKind.Value, string idx.Scale)
  else
    ()

/// Writes the index of an indexed operand where it has one, preceded by the
/// comma that separates it from whatever came before.
let private accumulateIndexPart idx builder =
  match idx with
  | Some idx ->
    accumulateStr "," builder
    accumulateIndex idx builder
  | None ->
    ()

/// Writes the base displacement and the base register, which is what the
/// brackets of a memory indirect mode enclose and what an ordinary indexed mode
/// writes on its own.
let private accumulateBase (mem: IndexedMem) builder =
  accumulateDisp (int64 mem.BaseDisp) builder
  match mem.Base with
  | Some reg ->
    accumulateStr "," builder
    accumulateReg reg builder
  | None ->
    ()

/// Writes an indexed operand. Brackets enclose the values that form the
/// intermediate address of a memory indirect mode, and where the index sits
/// relative to the closing bracket is what tells preindexing from postindexing.
let private accumulateIndexed (mem: IndexedMem) builder =
  match mem.OuterDisp with
  | None ->
    accumulateStr "(" builder
    accumulateBase mem builder
    accumulateIndexPart mem.Index builder
    accumulateStr ")" builder
  | Some od when mem.IsPreIndexed ->
    accumulateStr "([" builder
    accumulateBase mem builder
    accumulateIndexPart mem.Index builder
    accumulateStr "]," builder
    accumulateDisp (int64 od) builder
    accumulateStr ")" builder
  | Some od ->
    accumulateStr "([" builder
    accumulateBase mem builder
    accumulateStr "]" builder
    accumulateIndexPart mem.Index builder
    accumulateStr "," builder
    accumulateDisp (int64 od) builder
    accumulateStr ")" builder

let private prefix = { AsmWordKind = AsmWordKind.String; AsmWordValue = "<" }

let private suffix = { AsmWordKind = AsmWordKind.String; AsmWordValue = ">" }

let private mapNoSymbol addr =
  [| { AsmWordKind = AsmWordKind.Value
       AsmWordValue = HexString.ofUInt64 addr } |]

/// Writes the address a relative branch reaches, as a comment after the
/// displacement the encoding actually carries.
let private accumulateTarget target (builder: IDisasmBuilder) =
  builder.Accumulate(AsmWordKind.CommentDelimiter, " ; ")
  builder.AccumulateSymbol(target, prefix, suffix, mapNoSymbol)

/// Whether a register belongs to a bank whose members an assembler writes as a
/// range. The general registers and the floating-point data registers each do;
/// the floating-point control registers, of which there are three and which no
/// list ever names in part, do not.
let private isRanged (reg: Register) =
  LanguagePrimitives.EnumToValue reg <= 42

/// Writes a register list, folding each run of consecutive registers into a
/// range the way an assembler writes one. A run may cross from the data
/// registers into the address registers, the two being consecutive in the mask
/// and an assembler reading "d0-a7" back as the whole of it.
let private accumulateRegList (regs: Register[]) (builder: IDisasmBuilder) =
  (* A mask that names no register at all still names a list, and writing it as
     the zero it is keeps the operand from vanishing from the line. *)
  if Array.isEmpty regs then
    accumulateStr "#" builder
    builder.Accumulate(AsmWordKind.Value, HexString.ofInt64 0L)
  else
    ()
  let runs =
    regs
    |> Array.fold (fun runs reg ->
      match runs with
      | (first, last) :: rest when isRanged reg
                                   && LanguagePrimitives.EnumToValue last + 1
                                      = LanguagePrimitives.EnumToValue reg ->
        (first, reg) :: rest
      | _ -> (reg, reg) :: runs) []
    |> List.rev
  runs
  |> List.iteri (fun i (first, last) ->
    if i > 0 then accumulateStr "/" builder else ()
    accumulateReg first builder
    if first <> last then
      accumulateStr "-" builder
      accumulateReg last builder
    else
      ())

/// Writes the offset or the width of a bit field, which is a literal or the
/// data register holding one. Neither carries the hash an immediate operand
/// does, there being nothing else either of them could be.
let private accumulateField opr (builder: IDisasmBuilder) =
  match opr with
  | OpReg reg -> accumulateReg reg builder
  | OpImm v -> accumulateDisp v builder
  | _ -> Terminator.impossible ()

let rec oprToString (ins: Instruction) opr delim (builder: IDisasmBuilder) =
  accumulateStr delim builder
  match opr with
  | OpReg reg ->
    accumulateReg reg builder
  | OpImm imm ->
    accumulateStr "#" builder
    accumulateDisp imm builder
  | OpAddr addr ->
    builder.Accumulate(AsmWordKind.Value, HexString.ofUInt64 addr)
  | OpMem(Direct reg) ->
    accumulateStr "(" builder
    accumulateReg reg builder
    accumulateStr ")" builder
  | OpMem(PostInc reg) ->
    accumulateStr "(" builder
    accumulateReg reg builder
    accumulateStr ")+" builder
  | OpMem(PreDec reg) ->
    accumulateStr "-(" builder
    accumulateReg reg builder
    accumulateStr ")" builder
  | OpMem(Disp(disp, reg)) ->
    accumulateStr "(" builder
    accumulateDisp (int64 disp) builder
    accumulateStr "," builder
    accumulateReg reg builder
    accumulateStr ")" builder
  | OpMem(Indexed mem) ->
    accumulateIndexed mem builder
  | OpRelAddr disp ->
    accumulateStr (if disp < 0 then "-" else "+") builder
    builder.Accumulate(AsmWordKind.Value, HexString.ofInt64 (abs (int64 disp)))
    accumulateTarget (ins.TargetOf disp) builder
  | OpRegList regs ->
    accumulateRegList regs builder
  | OpCaches caches ->
    let name =
      match caches with
      | 0uy -> "nc"
      | 1uy -> "dc"
      | 2uy -> "ic"
      | _ -> "bc"
    builder.Accumulate(AsmWordKind.Variable, name)
  | OpFImm bytes ->
    accumulateStr "#" builder
    let hex = bytes |> Array.map (fun b -> b.ToString "x2") |> String.concat ""
    builder.Accumulate(AsmWordKind.Value, "0x" + hex)
  | OpRegPair(reg1, reg2) ->
    accumulateReg reg1 builder
    accumulateStr ":" builder
    accumulateReg reg2 builder
  | OpMemPair(reg1, reg2) ->
    accumulateStr "(" builder
    accumulateReg reg1 builder
    accumulateStr "):(" builder
    accumulateReg reg2 builder
    accumulateStr ")" builder
  | OpBitField(ea, spec) ->
    oprToString ins ea "" builder
    accumulateStr "{" builder
    accumulateField spec.Offset builder
    accumulateStr ":" builder
    accumulateField spec.Width builder
    accumulateStr "}" builder

let inline buildOpcode (ins: Instruction) (builder: IDisasmBuilder) =
  let mnemonic = opCodeToString ins.Opcode + sizeToString ins.Size
  builder.Accumulate(AsmWordKind.Mnemonic, mnemonic)

let inline buildOprs (ins: Instruction) (builder: IDisasmBuilder) =
  match ins.Operands with
  | NoOperand ->
    ()
  | OneOperand op1 ->
    oprToString ins op1 " " builder
  | TwoOperands(op1, op2) ->
    oprToString ins op1 " " builder
    oprToString ins op2 ", " builder
  | ThreeOperands(op1, op2, op3) ->
    oprToString ins op1 " " builder
    oprToString ins op2 ", " builder
    oprToString ins op3 ", " builder
  | FourOperands(op1, op2, op3, op4) ->
    oprToString ins op1 " " builder
    oprToString ins op2 ", " builder
    oprToString ins op3 ", " builder
    oprToString ins op4 ", " builder

let disasm (ins: Instruction) (builder: IDisasmBuilder) =
  builder.AccumulateAddrMarker ins.Address
  buildOpcode ins builder
  buildOprs ins builder
