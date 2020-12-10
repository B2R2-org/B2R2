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

module B2R2.FrontEnd.BinLifter.TMS320C6000.Disasm

open B2R2
open B2R2.FrontEnd.BinLifter

let opCodeToString = function
  | Op.ABS -> "ABS"
  | Op.ABS2 -> "ABS2"
  | Op.ABSDP -> "ABSDP"
  | Op.ABSSP -> "ABSSP"
  | Op.ADD -> "ADD"
  | Op.ADD2 -> "ADD2"
  | Op.ADD4 -> "ADD4"
  | Op.ADDAB -> "ADDAB"
  | Op.ADDAD -> "ADDAD"
  | Op.ADDAH -> "ADDAH"
  | Op.ADDAW -> "ADDAW"
  | Op.ADDDP -> "ADDDP"
  | Op.ADDK -> "ADDK"
  | Op.ADDKPC -> "ADDKPC"
  | Op.ADDSP -> "ADDSP"
  | Op.ADDSUB -> "ADDSUB"
  | Op.ADDSUB2 -> "ADDSUB2"
  | Op.ADDU -> "ADDU"
  | Op.AND -> "AND"
  | Op.ANDN -> "ANDN"
  | Op.AVG2 -> "AVG2"
  | Op.AVGU4 -> "AVGU4"
  | Op.B -> "B"
  | Op.BDEC -> "BDEC"
  | Op.BITC4 -> "BITC4"
  | Op.BITR -> "BITR"
  | Op.BNOP -> "BNOP"
  | Op.BPOS -> "BPOS"
  | Op.CALLP -> "CALLP"
  | Op.CLR -> "CLR"
  | Op.CMPEQ -> "CMPEQ"
  | Op.CMPEQ2 -> "CMPEQ2"
  | Op.CMPEQ4 -> "CMPEQ4"
  | Op.CMPEQDP -> "CMPEQDP"
  | Op.CMPEQSP -> "CMPEQSP"
  | Op.CMPGT -> "CMPGT"
  | Op.CMPGT2 -> "CMPGT2"
  | Op.CMPGTDP -> "CMPGTDP"
  | Op.CMPGTSP -> "CMPGTSP"
  | Op.CMPGTU -> "CMPGTU"
  | Op.CMPGTU4 -> "CMPGTU4"
  | Op.CMPLT -> "CMPLT"
  | Op.CMPLT2 -> "CMPLT2"
  | Op.CMPLTDP -> "CMPLTDP"
  | Op.CMPLTSP -> "CMPLTSP"
  | Op.CMPLTU -> "CMPLTU"
  | Op.CMPLTU4 -> "CMPLTU4"
  | Op.CMPY -> "CMPY"
  | Op.CMPYR -> "CMPYR"
  | Op.CMPYR1 -> "CMPYR1"
  | Op.DDOTP4 -> "DDOTP4"
  | Op.DDOTPH2 -> "DDOTPH2"
  | Op.DDOTPH2R -> "DDOTPH2R"
  | Op.DDOTPL2 -> "DDOTPL2"
  | Op.DDOTPL2R -> "DDOTPL2R"
  | Op.DEAL -> "DEAL"
  | Op.DINT -> "DINT"
  | Op.DMV -> "DMV"
  | Op.DOTP2 -> "DOTP2"
  | Op.DOTPN2 -> "DOTPN2"
  | Op.DOTPNRSU2 -> "DOTPNRSU2"
  | Op.DOTPNRUS2 -> "DOTPNRUS2"
  | Op.DOTPRSU2 -> "DOTPRSU2"
  | Op.DOTPRUS2 -> "DOTPRUS2"
  | Op.DOTPSU4 -> "DOTPSU4"
  | Op.DOTPU4 -> "DOTPU4"
  | Op.DOTPUS4 -> "DOTPUS4"
  | Op.DPACK2 -> "DPACK2"
  | Op.DPACKX2 -> "DPACKX2"
  | Op.DPINT -> "DPINT"
  | Op.DPSP -> "DPSP"
  | Op.DPTRUNC -> "DPTRUNC"
  | Op.EXT -> "EXT"
  | Op.EXTU -> "EXTU"
  | Op.GMPY -> "GMPY"
  | Op.GMPY4 -> "GMPY4"
  | Op.IDLE -> "IDLE"
  | Op.INTDP -> "INTDP"
  | Op.INTDPU -> "INTDPU"
  | Op.INTSP -> "INTSP"
  | Op.INTSPU -> "INTSPU"
  | Op.LDB -> "LDB"
  | Op.LDBU -> "LDBU"
  | Op.LDDW -> "LDDW"
  | Op.LDH -> "LDH"
  | Op.LDHU -> "LDHU"
  | Op.LDNDW -> "LDNDW"
  | Op.LDNW -> "LDNW"
  | Op.LDW -> "LDW"
  | Op.LMBD -> "LMBD"
  | Op.MAX2 -> "MAX2"
  | Op.MAXU4 -> "MAXU4"
  | Op.MIN2 -> "MIN2"
  | Op.MINU4 -> "MINU4"
  | Op.MPY -> "MPY"
  | Op.MPY2 -> "MPY2"
  | Op.MPY2IR -> "MPY2IR"
  | Op.MPY32 -> "MPY32"
  | Op.MPY32SU -> "MPY32SU"
  | Op.MPY32U -> "MPY32U"
  | Op.MPY32US -> "MPY32US"
  | Op.MPYDP -> "MPYDP"
  | Op.MPYH -> "MPYH"
  | Op.MPYHI -> "MPYHI"
  | Op.MPYHIR -> "MPYHIR"
  | Op.MPYHL -> "MPYHL"
  | Op.MPYHLU -> "MPYHLU"
  | Op.MPYHSLU -> "MPYHSLU"
  | Op.MPYHSU -> "MPYHSU"
  | Op.MPYHU -> "MPYHU"
  | Op.MPYHULS -> "MPYHULS"
  | Op.MPYHUS -> "MPYHUS"
  | Op.MPYI -> "MPYI"
  | Op.MPYID -> "MPYID"
  | Op.MPYIH -> "MPYIH"
  | Op.MPYIHR -> "MPYIHR"
  | Op.MPYIL -> "MPYIL"
  | Op.MPYILR -> "MPYILR"
  | Op.MPYLH -> "MPYLH"
  | Op.MPYLHU -> "MPYLHU"
  | Op.MPYLI -> "MPYLI"
  | Op.MPYLIR -> "MPYLIR"
  | Op.MPYLSHU -> "MPYLSHU"
  | Op.MPYLUHS -> "MPYLUHS"
  | Op.MPYSP -> "MPYSP"
  | Op.MPYSP2DP -> "MPYSP2DP"
  | Op.MPYSPDP -> "MPYSPDP"
  | Op.MPYSU -> "MPYSU"
  | Op.MPYSU4 -> "MPYSU4"
  | Op.MPYU -> "MPYU"
  | Op.MPYU4 -> "MPYU4"
  | Op.MPYUS -> "MPYUS"
  | Op.MPYUS4 -> "MPYUS4"
  | Op.MV -> "MV"
  | Op.MVC -> "MVC"
  | Op.MVD -> "MVD"
  | Op.MVK -> "MVK"
  | Op.MVKH -> "MVKH"
  | Op.MVKL -> "MVKL"
  | Op.MVKLH -> "MVKLH"
  | Op.NEG -> "NEG"
  | Op.NOP -> "NOP"
  | Op.NORM -> "NORM"
  | Op.NOT -> "NOT"
  | Op.OR -> "OR"
  | Op.PACK2 -> "PACK2"
  | Op.PACKH2 -> "PACKH2"
  | Op.PACKH4 -> "PACKH4"
  | Op.PACKHL2 -> "PACKHL2"
  | Op.PACKL4 -> "PACKL4"
  | Op.PACKLH2 -> "PACKLH2"
  | Op.RCPDP -> "RCPDP"
  | Op.RCPSP -> "RCPSP"
  | Op.RINT -> "RINT"
  | Op.ROTL -> "ROTL"
  | Op.RPACK2 -> "RPACK2"
  | Op.RSQRDP -> "RSQRDP"
  | Op.RSQRSP -> "RSQRSP"
  | Op.SADD -> "SADD"
  | Op.SADD2 -> "SADD2"
  | Op.SADDSU2 -> "SADDSU2"
  | Op.SADDSUB -> "SADDSUB"
  | Op.SADDSUB2 -> "SADDSUB2"
  | Op.SADDU4 -> "SADDU4"
  | Op.SADDUS2 -> "SADDUS2"
  | Op.SAT -> "SAT"
  | Op.SET -> "SET"
  | Op.SHFL -> "SHFL"
  | Op.SHFL3 -> "SHFL3"
  | Op.SHL -> "SHL"
  | Op.SHLMB -> "SHLMB"
  | Op.SHR -> "SHR"
  | Op.SHR2 -> "SHR2"
  | Op.SHRMB -> "SHRMB"
  | Op.SHRU -> "SHRU"
  | Op.SHRU2 -> "SHRU2"
  | Op.SMPY -> "SMPY"
  | Op.SMPY2 -> "SMPY2"
  | Op.SMPY32 -> "SMPY32"
  | Op.SMPYH -> "SMPYH"
  | Op.SMPYHL -> "SMPYHL"
  | Op.SMPYLH -> "SMPYLH"
  | Op.SPACK2 -> "SPACK2"
  | Op.SPACKU4 -> "SPACKU4"
  | Op.SPDP -> "SPDP"
  | Op.SPINT -> "SPINT"
  | Op.SPKERNEL -> "SPKERNEL"
  | Op.SPKERNELR -> "SPKERNELR"
  | Op.SPLOOP -> "SPLOOP"
  | Op.SPLOOPD -> "SPLOOPD"
  | Op.SPLOOPW -> "SPLOOPW"
  | Op.SPMASK -> "SPMASK"
  | Op.SPMASKR -> "SPMASKR"
  | Op.SPTRUNC -> "SPTRUNC"
  | Op.SSHL -> "SSHL"
  | Op.SSHVL -> "SSHVL"
  | Op.SSHVR -> "SSHVR"
  | Op.SSUB -> "SSUB"
  | Op.SSUB2 -> "SSUB2"
  | Op.STB -> "STB"
  | Op.STDW -> "STDW"
  | Op.STH -> "STH"
  | Op.STNDW -> "STNDW"
  | Op.STNW -> "STNW"
  | Op.STW -> "STW"
  | Op.SUB -> "SUB"
  | Op.SUB2 -> "SUB2"
  | Op.SUB4 -> "SUB4"
  | Op.SUBAB -> "SUBAB"
  | Op.SUBABS4 -> "SUBABS4"
  | Op.SUBAH -> "SUBAH"
  | Op.SUBAW -> "SUBAW"
  | Op.SUBC -> "SUBC"
  | Op.SUBDP -> "SUBDP"
  | Op.SUBSP -> "SUBSP"
  | Op.SUBU -> "SUBU"
  | Op.SWAP2 -> "SWAP2"
  | Op.SWAP4 -> "SWAP4"
  | Op.SWE -> "SWE"
  | Op.SWENR -> "SWENR"
  | Op.UNPKHU4 -> "UNPKHU4"
  | Op.UNPKLU4 -> "UNPKLU4"
  | Op.XOR -> "XOR"
  | Op.XORMPY -> "XORMPY"
  | Op.XPND2 -> "XPND2"
  | Op.XPND4 -> "XPND4"
  | Op.ZERO -> "ZERO"
  | _ -> Utils.impossible ()

let inline appendUnit insInfo opcode =
  match insInfo.FunctionalUnit with
  | L1Unit -> opcode + ".L1"
  | L2Unit -> opcode + ".L2"
  | L1XUnit -> opcode + ".L1X"
  | L2XUnit -> opcode + ".L2X"
  | S1Unit -> opcode + ".S1"
  | S2Unit -> opcode + ".S2"
  | S1XUnit -> opcode + ".S1X"
  | S2XUnit -> opcode + ".S2X"
  | M1Unit -> opcode + ".M1"
  | M2Unit -> opcode + ".M2"
  | M1XUnit -> opcode + ".M1X"
  | M2XUnit -> opcode + ".M2X"
  | D1Unit -> opcode + ".D1"
  | D2Unit -> opcode + ".D2"
  | D1XUnit -> opcode + ".D1X"
  | D2XUnit -> opcode + ".D2X"
  | NoUnit -> opcode

let buildParallelPipe ins builder acc =
  if ins.IsParallel then builder AsmWordKind.String "|| " acc
  else acc

let inline buildOpcode ins builder acc =
  let str = opCodeToString ins.Opcode |> appendUnit ins
  builder AsmWordKind.Mnemonic str acc

let buildMemBase builder baseR acc = function
  | NegativeOffset ->
    builder AsmWordKind.String "-" acc
    |> builder AsmWordKind.Variable (Register.toString baseR)
  | PositiveOffset ->
    builder AsmWordKind.String "+" acc
    |> builder AsmWordKind.Variable (Register.toString baseR)
  | PreDecrement ->
    builder AsmWordKind.String "--" acc
    |> builder AsmWordKind.Variable (Register.toString baseR)
  | PreIncrement ->
    builder AsmWordKind.String "++" acc
    |> builder AsmWordKind.Variable (Register.toString baseR)
  | PostDecrement ->
    builder AsmWordKind.Variable (Register.toString baseR) acc
    |> builder AsmWordKind.String "--"
  | PostIncrement ->
    builder AsmWordKind.Variable (Register.toString baseR) acc
    |> builder AsmWordKind.String "++"

let private offsetToString builder offset acc =
  match offset with
  | UCst5 i -> builder AsmWordKind.Value (i.ToString()) acc
  | UCst15 i -> builder AsmWordKind.Value (i.ToString()) acc
  | OffsetR reg -> builder AsmWordKind.Variable (Register.toString reg) acc

let private buildMemOffset builder offset acc =
  match offset with
  | UCst5 0UL -> acc
  | offset ->
    builder AsmWordKind.String "[" acc
    |> offsetToString builder offset
    |> builder AsmWordKind.String "]"

let memToString builder baseR modification offset acc =
  buildMemBase builder baseR acc modification
  |> buildMemOffset builder offset

let oprToString insInfo opr delim builder acc =
  match opr with
  | OpReg reg ->
    builder AsmWordKind.String delim acc
    |> builder AsmWordKind.Variable (Register.toString reg)
  | RegisterPair (r1, r2) ->
    builder AsmWordKind.String delim acc
    |> builder AsmWordKind.Variable (Register.toString r1)
    |> builder AsmWordKind.String ":"
    |> builder AsmWordKind.Variable (Register.toString r2)
  | OprMem (baseR, modification, offset) ->
    builder AsmWordKind.String delim acc
    |> builder AsmWordKind.String " *"
    |> memToString builder baseR modification offset
  | Immediate imm ->
    builder AsmWordKind.String delim acc
    |> builder AsmWordKind.Value (String.u64ToHex imm)

let buildOprs insInfo builder acc =
  match insInfo.Operands with
  | NoOperand -> acc
  | OneOperand opr ->
    oprToString insInfo opr " " builder acc
  | TwoOperands (opr1, opr2) ->
    oprToString insInfo opr1 " " builder acc
    |> oprToString insInfo opr2 ", " builder
  | ThreeOperands (opr1, opr2, opr3) ->
    oprToString insInfo opr1 " " builder acc
    |> oprToString insInfo opr2 ", " builder
    |> oprToString insInfo opr3 ", " builder
  | FourOperands (opr1, opr2, opr3, opr4) ->
    oprToString insInfo opr1 " " builder acc
    |> oprToString insInfo opr2 ", " builder
    |> oprToString insInfo opr3 ", " builder
    |> oprToString insInfo opr4 ", " builder

let disasm showAddr insInfo builder acc =
  let pc = insInfo.Address
  DisasmBuilder.addr pc WordSize.Bit32 showAddr builder acc
  |> buildParallelPipe insInfo builder
  |> buildOpcode insInfo builder
  |> buildOprs insInfo builder
