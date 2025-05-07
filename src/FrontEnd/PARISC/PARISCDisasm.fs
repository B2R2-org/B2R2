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

module B2R2.FrontEnd.PARISC.Disasm

open B2R2
open B2R2.FrontEnd.BinLifter

let opCodeToString = function
  (* System Control Instructions *)
  | Op.BREAK -> "break"
  | Op.SYNC -> "sync"
  | Op.SYNCDMA -> "syncdma"
  | Op.RFI -> "rfi"
  | Op.SSM -> "ssm"
  | Op.RSM -> "rsm"
  | Op.MTSM -> "mtsm"
  | Op.LDSID -> "ldsid"
  | Op.MTSP -> "mtsp"
  | Op.MFSP -> "mfsp"
  | Op.MTCTL -> "mtctl"
  | Op.MTSARCM -> "mtsarcm"
  | Op.MFIA -> "mfia"
  | Op.MFCTL -> "mfctl"
  | Op.DIAG -> "diag"
  (* Memory Management Instructions *)
  | Op.IITLBT -> "iitlbt"
  | Op.PITLB -> "pitlb"
  | Op.PITLBE -> "pitlbe"
  | Op.FIC -> "fic"
  | Op.FICE -> "fice"
  | Op.IDTLBT -> "idtlbt"
  | Op.PDTLB -> "pdtlb"
  | Op.PDTLBE -> "pdtlbe"
  | Op.FDC -> "fdc"
  | Op.FDCE -> "fdce"
  | Op.PDC -> "pdc"
  | Op.PROBE -> "probe"
  | Op.PROBEI -> "probei"
  | Op.LPA -> "lpa"
  | Op.LCI -> "lci"
  (* Arithmetic & Logical Instructions *)
  | Op.ADD -> "add"
  | Op.SHLADD -> "shladd"
  | Op.SUB -> "sub"
  | Op.DS -> "ds"
  | Op.ANDCM -> "andcm"
  | Op.AND -> "and"
  | Op.OR -> "or"
  | Op.XOR -> "xor"
  | Op.UXOR -> "uxor"
  | Op.CMPCLR -> "cmpclr"
  | Op.UADDCM -> "uaddcm"
  | Op.DCOR -> "dcor"
  | Op.HADD -> "hadd"
  | Op.HSUB -> "hsub"
  | Op.HAVG -> "havg"
  | Op.HSHLADD -> "hshladd"
  | Op.HSHRADD -> "hshradd"
  (* Load & Store Instructions *)
  | Op.LDB -> "ldb"
  | Op.LDH -> "ldh"
  | Op.LDW -> "ldw"
  | Op.LDD -> "ldd"
  | Op.LDDA -> "ldda"
  | Op.LDCD -> "ldcd"
  | Op.LDWA -> "ldwa"
  | Op.LDCW -> "ldcw"
  | Op.STB -> "stb"
  | Op.STH -> "sth"
  | Op.STW -> "stw"
  | Op.STD -> "std"
  | Op.STBY -> "stby"
  | Op.STDBY -> "stdby"
  | Op.STWA -> "stwa"
  | Op.STDA -> "stda"
  | Op.FLDW -> "fldw"
  | Op.FSTW -> "fstw"
  | Op.FLDD -> "fldd"
  | Op.FSTD -> "fstd"
  (* Arithmetic Immediate Instructions *)
  | Op.ADDI -> "addi"
  | Op.SUBI -> "subi"
  (* Shift & Extract & Deposit Instructions *)
  | Op.SHRPD -> "shrpd"
  | Op.SHRPW -> "shrpw"
  | Op.EXTRD -> "extrd"
  | Op.EXTRW -> "extrw"
  | Op.DEPD -> "depd"
  | Op.DEPDI -> "depdi"
  | Op.DEPW -> "depw"
  | Op.DEPWI -> "depwi"
  (* Multimedia Instructions *)
  | Op.PERMH -> "permh"
  | Op.HSHL -> "hshl"
  | Op.HSHR -> "hshr"
  | Op.MIXW -> "mixw"
  | Op.MIXH -> "mixh"
  (* Branch Instructions *)
  | Op.B -> "b"
  | Op.BLR -> "blr"
  | Op.BV -> "bv"
  | Op.BE -> "be"
  | Op.BVE -> "bve"
  | Op.ADDB -> "addb"
  | Op.ADDIB -> "addib"
  | Op.BB -> "bb"
  | Op.CMPB -> "cmpb"
  | Op.CMPIB -> "cmpib"
  | Op.MOVB -> "movb"
  | Op.MOVIB -> "movib"
  | Op.CMPICLR -> "cmpiclr"
  (* Coprocessor Instructions *)
  | Op.CLDW -> "cldw"
  | Op.CLDD -> "cldd"
  | Op.CSTW -> "cstw"
  | Op.CSTD -> "cstd"
  | Op.COPR -> "copr"
  (* Special Function Instructions *)
  | Op.SPOP0 -> "spop0"
  | Op.SPOP1 -> "spop1"
  | Op.SPOP2 -> "spop2"
  | Op.SPOP3 -> "spop3"
  (* Floating-Point Conversion and Arithmetic Instructions *)
  | Op.FID -> "fid"
  | Op.FCPY -> "fcpy"
  | Op.FABS -> "fabs"
  | Op.FSQRT -> "fsqrt"
  | Op.FRND -> "frnd"
  | Op.FNEG -> "fneg"
  | Op.FNEGABS -> "fnegabs"
  | Op.FCNV -> "fcnv"
  | Op.FCMP -> "fcmp"
  | Op.FTEST -> "ftest"
  | Op.FADD -> "fadd"
  | Op.FSUB -> "fsub"
  | Op.FMPY -> "fmpy"
  | Op.FDIV -> "fdiv"
  (* Floating-Point Fused-Operation Instructions *)
  | Op.FMPYFADD -> "fmpyfadd"
  | Op.FMPYNFADD -> "fmpynfadd"
  (* Performance Monitor Coprocessor Instructions *)
  | Op.PMDIS -> "pmdis"
  | Op.PMENB -> "pmenb"
  (* Long Immediate Instructions *)
  | Op.LDO -> "ldo"
  | Op.LDIL -> "ldil"
  | Op.ADDIL -> "addil"
  (* PUSH Instructions *)
  | Op.PUSHBTS -> "pushbts"
  | Op.PUSHNOM -> "pushnom"
  | Op.CLRBTS -> "clrbts"
  (* Multiple-Operation Instructions *)
  | Op.FMPYADD -> "fmpyadd"
  | Op.FMPYSUB -> "fmpysub"
  (* FIXED-POINT MULTIPLY UNSIGNED Instruction *)
  | Op.XMPYU -> "xmpyu"
  | _ -> raise ParsingFailureException

let roundModeToString = function
  | RoundMode.RN -> "rn"
  | RoundMode.RZ -> "rz"
  | RoundMode.RP -> "rp"
  | RoundMode.RM -> "rm"
  | _ -> failwith "Invalid rounding mode"

let condToString c =
  match c with
  | Completer.NEVER -> ""
  | Completer.EQ -> "="
  | Completer.LT -> "<"
  | Completer.LE -> "<="
  | Completer.LTU -> "<<"
  | Completer.LEU -> "<<="
  | Completer.SV -> "sv"
  | Completer.OD -> "od"
  | Completer.TR -> "tr"
  | Completer.NEQ -> "<>"
  | Completer.GE -> ">="
  | Completer.GT -> ">"
  | Completer.GEU -> ">>="
  | Completer.GTU -> ">>"
  | Completer.NSV -> "nsv"
  | Completer.EV -> "ev"
  | Completer.NUV -> "nuv"
  | Completer.ZNV -> "znv"
  | Completer.UV -> "uv"
  | Completer.VNZ -> "vnz"
  | Completer.NWC -> "nwc"
  | Completer.NWZ -> "nwz"
  | Completer.NHC -> "nhc"
  | Completer.NHZ -> "nhz"
  | Completer.NBC -> "nbc"
  | Completer.NBZ -> "nbz"
  | Completer.NDC -> "ndc"
  | Completer.SWC -> "swc"
  | Completer.SWZ -> "swz"
  | Completer.SHC -> "shc"
  | Completer.SHZ -> "shz"
  | Completer.SBC -> "sbc"
  | Completer.SBZ -> "sbz"
  | Completer.SDC -> "sdc"
  | Completer.DNEVER -> "*"
  | Completer.DEQ -> "*="
  | Completer.DLT -> "*<"
  | Completer.DLE -> "*<="
  | Completer.DLTU -> "*<<"
  | Completer.DLEU -> "*<<="
  | Completer.DSV -> "*sv"
  | Completer.DOD -> "*od"
  | Completer.DTR -> "*tr"
  | Completer.DNEQ -> "*<>"
  | Completer.DGE -> "*>="
  | Completer.DGT -> "*>"
  | Completer.DGEU -> "*>>="
  | Completer.DGTU -> "*>>"
  | Completer.DNSV -> "*nsv"
  | Completer.DEV -> "*ev"
  | Completer.DNUV -> "*nuv"
  | Completer.DZNV -> "*znv"
  | Completer.DUV -> "*uv"
  | Completer.DVNZ -> "*vnz"
  | Completer.DNWC -> "*nwc"
  | Completer.DNWZ -> "*nwz"
  | Completer.DNHC -> "*nhc"
  | Completer.DNHZ -> "*nhz"
  | Completer.DNBC -> "*nbc"
  | Completer.DNBZ -> "*nbz"
  | Completer.DNDC -> "*ndc"
  | Completer.DSWC -> "*swc"
  | Completer.DSWZ -> "*swz"
  | Completer.DSHC -> "*shc"
  | Completer.DSHZ -> "*shz"
  | Completer.DSBC -> "*sbc"
  | Completer.DSBZ -> "*sbz"
  | Completer.DSDC -> "*sdc"
  | Completer.B -> "b"
  | Completer.C -> "c"
  | Completer.GATE -> "gate"
  | Completer.I -> "i"
  | Completer.L -> "l"
  | Completer.R -> "r"
  | Completer.S -> "s"
  | Completer.T -> "t"
  | Completer.U -> "u"
  | Completer.W -> "w"
  | Completer.Z -> "z"
  | Completer.M -> "m"
  | Completer.O -> "o"
  | Completer.E -> "e"
  | Completer.DB -> "db"
  | Completer.DC -> "dc"
  | Completer.TC -> "tc"
  | Completer.TSV -> "tsv"
  | Completer.MA -> "ma"
  | Completer.MB -> "mb"
  | Completer.SM -> "sm"
  | Completer.SGL -> "sgl"
  | Completer.DBL -> "dbl"
  | Completer.QUAD -> "quad"
  | Completer.UW -> "uw"
  | Completer.DW -> "dw"
  | Completer.UDW -> "udw"
  | Completer.QW -> "qw"
  | Completer.UQW -> "uqw"
  | Completer.SS -> "ss"
  | Completer.US -> "us"
  | Completer.LDISP -> "ldisp"
  | Completer.SDISP -> "sdisp"
  | Completer.N -> "n"
  | Completer.BC -> "bc"
  | Completer.SL -> "sl"
  | Completer.PUSH -> "push"
  | Completer.FALSEQ -> "false?"
  | Completer.FALSE -> "false"
  | Completer.FQ -> "?"
  | Completer.FBGTLE -> "!<=>"
  | Completer.FEQ -> "="
  | Completer.FEQT -> "=t"
  | Completer.FQEQ -> "?="
  | Completer.FBNEQ -> "!<>"
  | Completer.FBQGE -> "!?>="
  | Completer.FLT -> "<"
  | Completer.FQLT -> "?<"
  | Completer.FBGE -> "!>="
  | Completer.FBQGT -> "!?>"
  | Completer.FLE -> "<="
  | Completer.FQLE -> "?<="
  | Completer.FBGT -> "!>"
  | Completer.FBQLE -> "!?<="
  | Completer.FGT -> ">"
  | Completer.FQGT -> "?>"
  | Completer.FBLE -> "!<="
  | Completer.FBQLT -> "!?<"
  | Completer.FGE -> ">="
  | Completer.FQGE -> "?>="
  | Completer.FBLT -> "!<"
  | Completer.FBQEQ -> "!?="
  | Completer.FNEQ -> "<>"
  | Completer.FBEQ -> "!="
  | Completer.FBEQT -> "!=t"
  | Completer.FBQ -> "!?"
  | Completer.FGTLE -> "<=>"
  | Completer.TRUEQ -> "true?"
  | Completer.TRUE -> "true"
  | Completer.ACC -> "acc"
  | Completer.ACC2 -> "acc2"
  | Completer.ACC4 -> "acc4"
  | Completer.ACC6 -> "acc6"
  | Completer.ACC8 -> "acc8"
  | Completer.REJ -> "rej"
  | Completer.REJ8 -> "rej8"
  | Completer.CO -> "co"
  | _ -> failwith "Invalid condition"

let shtostring = function
  | SHIFTST.SARSHFT -> "sar"
  | _ -> failwith "invalid sarshift"

let inline attachPrefixer (ins: Instruction) opcode =
  let formatCompleter c = "," + condToString c
  let baseOpcode =
    match ins.ID with
    | Some arr when arr.Length > 0 ->
      opcode + "," + (arr |> Array.map string |> String.concat ",")
    | _ -> opcode
  let formatCompleterArray cmpltArr =
    if Array.isEmpty cmpltArr then ""
    else
      cmpltArr
      |> Array.map formatCompleter
      |> String.concat ""
  match ins.Completer, ins.Condition with
  | Some cmpltArr, Some cond ->
    let cmpltStr =
      formatCompleterArray (Array.filter ((<>) Completer.NEVER) cmpltArr)
    let condStr = if cond <> Completer.NEVER then formatCompleter cond else ""
    baseOpcode + cmpltStr + condStr
  | Some cmpltArr, None ->
    let cmpltStr =
      formatCompleterArray (Array.filter ((<>) Completer.NEVER) cmpltArr)
    baseOpcode + cmpltStr
  | None, Some cond ->
    if cond = Completer.NEVER then baseOpcode
    else baseOpcode + formatCompleter cond
  | None, None -> baseOpcode

let inline buildOpcode (ins: Instruction) (builder: IDisasmBuilder) =
  let str = opCodeToString ins.Opcode |> attachPrefixer ins
  builder.Accumulate AsmWordKind.Mnemonic str

let inline relToString pc offset (builder: IDisasmBuilder) =
  let targetAddr = pc + uint64 offset
  builder.Accumulate AsmWordKind.Value (HexString.ofUInt64 targetAddr)

let printSpace space =
  space <> Some Register.SR0 && space <> None

let oprToString (ins: Instruction) opr delim (builder: IDisasmBuilder) =
  match opr with
  | OpReg reg ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Variable (Register.toString reg)
  | OpImm imm
  | OpShiftAmount imm ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (HexString.ofUInt64 imm)
  | OpMem (b, space, offset, _) ->
    builder.Accumulate AsmWordKind.String delim
    match offset with
    | Some (Imm off) ->
      builder.Accumulate AsmWordKind.Value (HexString.ofInt64 off)
    | Some (Reg off) ->
      builder.Accumulate AsmWordKind.Variable (Register.toString off)
    | _ -> ()
    builder.Accumulate AsmWordKind.String "("
    if printSpace space then
      builder.Accumulate AsmWordKind.Variable
        (Register.toString (Option.get space))
      builder.Accumulate AsmWordKind.String ","
    builder.Accumulate AsmWordKind.Variable (Register.toString b)
    builder.Accumulate AsmWordKind.String ")"
  | OpAddr (Relative offset) ->
    builder.Accumulate AsmWordKind.String delim
    relToString ins.Address offset builder
  | OpAddr (RelativeBase (b, off)) ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (off.ToString ("D"))
    builder.Accumulate AsmWordKind.String "("
    builder.Accumulate AsmWordKind.Variable (Register.toString b)
    builder.Accumulate AsmWordKind.String ")"
  | OpAtomMemOper (aq, rl) ->
    if aq then builder.Accumulate AsmWordKind.String "aq"
    if rl then builder.Accumulate AsmWordKind.String "rl"
  | OpRoundMode rm ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.String (roundModeToString rm)
  | OpCSR csr ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (HexString.ofUInt16 csr)
  | OpCond cond ->
    builder.Accumulate AsmWordKind.String ","
    builder.Accumulate AsmWordKind.String (condToString cond)

let buildOprs (ins: Instruction) builder =
  match ins.Operands with
  | NoOperand -> ()
  | OneOperand opr ->
    oprToString ins opr " " builder
  | TwoOperands (opr1, opr2) ->
    oprToString ins opr1 " " builder
    oprToString ins opr2 ", " builder
  | ThreeOperands (opr1, opr2, opr3) ->
    oprToString ins opr1 " " builder
    oprToString ins opr2 ", " builder
    oprToString ins opr3 ", " builder
  | FourOperands (opr1, opr2, opr3, opr4) ->
    oprToString ins opr1 " " builder
    oprToString ins opr2 ", " builder
    oprToString ins opr3 ", " builder
    oprToString ins opr4 ", " builder
  | FiveOperands (opr1, opr2, opr3, opr4, opr5) ->
    oprToString ins opr1 " " builder
    oprToString ins opr2 ", " builder
    oprToString ins opr3 ", " builder
    oprToString ins opr4 ", " builder
    oprToString ins opr5 ", " builder

let disasm (ins: Instruction) (builder: IDisasmBuilder) =
  builder.AccumulateAddrMarker ins.Address
  buildOpcode ins builder
  buildOprs ins builder
