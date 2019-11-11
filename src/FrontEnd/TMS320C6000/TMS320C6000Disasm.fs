(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Seung Il Jung <sijung@kaist.ac.kr>
          Sang Kil Cha <sangkilc@kaist.ac.kr>

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

module B2R2.FrontEnd.TMS320C6000.Disasm

open B2R2
open B2R2.FrontEnd

let opCodeToString = function
  | Op.ABS -> "ABS"
  | Op.ABSDP -> "ABSDP"
  | Op.ABSSP -> "ABSSP"
  | Op.ADD -> "ADD"
  | Op.ADD2 -> "ADD2"
  | Op.ADDAB -> "ADDAB"
  | Op.ADDAD -> "ADDAD"
  | Op.ADDAH -> "ADDAH"
  | Op.ADDAW -> "ADDAW"
  | Op.ADDDP -> "ADDDP"
  | Op.ADDK -> "ADDK"
  | Op.ADDSP -> "ADDSP"
  | Op.ADDU -> "ADDU"
  | Op.AND -> "AND"
  | Op.B -> "B"
  | Op.CLR -> "CLR"
  | Op.CMPEQ -> "CMPEQ"
  | Op.CMPEQDP -> "CMPEQDP"
  | Op.CMPEQSP -> "CMPEQSP"
  | Op.CMPGT -> "CMPGT"
  | Op.CMPGTDP -> "CMPGTDP"
  | Op.CMPGTSP -> "CMPGTSP"
  | Op.CMPGTU -> "CMPGTU"
  | Op.CMPLT -> "CMPLT"
  | Op.CMPLTDP -> "CMPLTDP"
  | Op.CMPLTSP -> "CMPLTSP"
  | Op.CMPLTU -> "CMPLTU"
  | Op.DPINT -> "DPINT"
  | Op.DPSP -> "DPSP"
  | Op.DPTRUNC -> "DPTRUNC"
  | Op.EXT -> "EXT"
  | Op.EXTU -> "EXTU"
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
  | Op.LDW -> "LDW"
  | Op.LMBD -> "LMBD"
  | Op.MPY -> "MPY"
  | Op.MPYDP -> "MPYDP"
  | Op.MPYH -> "MPYH"
  | Op.MPYHL -> "MPYHL"
  | Op.MPYHLU -> "MPYHLU"
  | Op.MPYHSLU -> "MPYHSLU"
  | Op.MPYHSU -> "MPYHSU"
  | Op.MPYHU -> "MPYHU"
  | Op.MPYHULS -> "MPYHULS"
  | Op.MPYHUS -> "MPYHUS"
  | Op.MPYI -> "MPYI"
  | Op.MPYID -> "MPYID"
  | Op.MPYLH -> "MPYLH"
  | Op.MPYLHU -> "MPYLHU"
  | Op.MPYLSHU -> "MPYLSHU"
  | Op.MPYLUHS -> "MPYLUHS"
  | Op.MPYSP -> "MPYSP"
  | Op.MPYSP2DP -> "MPYSP2DP"
  | Op.MPYSPDP -> "MPYSPDP"
  | Op.MPYSU -> "MPYSU"
  | Op.MPYU -> "MPYU"
  | Op.MPYUS -> "MPYUS"
  | Op.MV -> "MV"
  | Op.MVC -> "MVC"
  | Op.MVK -> "MVK"
  | Op.MVKH -> "MVKH"
  | Op.MVKL -> "MVKL"
  | Op.MVKLH -> "MVKLH"
  | Op.NEG -> "NEG"
  | Op.NOP -> "NOP"
  | Op.NORM -> "NORM"
  | Op.NOT -> "NOT"
  | Op.OR -> "OR"
  | Op.RCPDP -> "RCPDP"
  | Op.RCPSP -> "RCPSP"
  | Op.RSQRDP -> "RSQRDP"
  | Op.RSQRSP -> "RSQRSP"
  | Op.SADD -> "SADD"
  | Op.SAT -> "SAT"
  | Op.SET -> "SET"
  | Op.SHL -> "SHL"
  | Op.SHR -> "SHR"
  | Op.SHRU -> "SHRU"
  | Op.SMPY -> "SMPY"
  | Op.SMPYH -> "SMPYH"
  | Op.SMPYHL -> "SMPYHL"
  | Op.SMPYLH -> "SMPYLH"
  | Op.SPDP -> "SPDP"
  | Op.SPINT -> "SPINT"
  | Op.SPTRUNC -> "SPTRUNC"
  | Op.SSHL -> "SSHL"
  | Op.SSUB -> "SSUB"
  | Op.STB -> "STB"
  | Op.STH -> "STH"
  | Op.STW -> "STW"
  | Op.SUB -> "SUB"
  | Op.SUB2 -> "SUB2"
  | Op.SUBAB -> "SUBAB"
  | Op.SUBAH -> "SUBAH"
  | Op.SUBAW -> "SUBAW"
  | Op.SUBC -> "SUBC"
  | Op.SUBDP -> "SUBDP"
  | Op.SUBSP -> "SUBSP"
  | Op.SUBU -> "SUBU"
  | Op.XOR -> "XOR"
  | Op.ZERO -> "ZERO"
  | _ -> Utils.impossible ()

let regToStr = function
  | R.A0 -> "A0"
  | R.A1 -> "A1"
  | R.A2 -> "A2"
  | R.A3 -> "A3"
  | R.A4 -> "A4"
  | R.A5 -> "A5"
  | R.A6 -> "A6"
  | R.A7 -> "A7"
  | R.A8 -> "A8"
  | R.A9 -> "A9"
  | R.A10 -> "A10"
  | R.A11 -> "A11"
  | R.A12 -> "A12"
  | R.A13 -> "A13"
  | R.A14 -> "A14"
  | R.A15 -> "A15"
  | R.A16 -> "A16"
  | R.A17 -> "A17"
  | R.A18 -> "A18"
  | R.A19 -> "A19"
  | R.A20 -> "A20"
  | R.A21 -> "A21"
  | R.A22 -> "A22"
  | R.A23 -> "A23"
  | R.A24 -> "A24"
  | R.A25 -> "A25"
  | R.A26 -> "A26"
  | R.A27 -> "A27"
  | R.A28 -> "A28"
  | R.A29 -> "A29"
  | R.A30 -> "A30"
  | R.A31 -> "A31"
  | R.B0 -> "B0"
  | R.B1 -> "B1"
  | R.B2 -> "B2"
  | R.B3 -> "B3"
  | R.B4 -> "B4"
  | R.B5 -> "B5"
  | R.B6 -> "B6"
  | R.B7 -> "B7"
  | R.B8 -> "B8"
  | R.B9 -> "B9"
  | R.B10 -> "B10"
  | R.B11 -> "B11"
  | R.B12 -> "B12"
  | R.B13 -> "B13"
  | R.B14 -> "B14"
  | R.B15 -> "B15"
  | R.B16 -> "B16"
  | R.B17 -> "B17"
  | R.B18 -> "B18"
  | R.B19 -> "B19"
  | R.B20 -> "B20"
  | R.B21 -> "B21"
  | R.B22 -> "B22"
  | R.B23 -> "B23"
  | R.B24 -> "B24"
  | R.B25 -> "B25"
  | R.B26 -> "B26"
  | R.B27 -> "B27"
  | R.B28 -> "B28"
  | R.B29 -> "B29"
  | R.B30 -> "B30"
  | R.B31 -> "B31"
  | _ -> Utils.impossible ()

let inline appendUnit insInfo opcode =
  match insInfo.FunctionalUnit with
  | L1 -> opcode + ".L1"
  | L2 -> opcode + ".L2"
  | L1X -> opcode + ".L1X"
  | L2X -> opcode + ".L2X"
  | S1 -> opcode + ".S1"
  | S2 -> opcode + ".S2"
  | S1X -> opcode + ".S1X"
  | S2X -> opcode + ".S2X"
  | M1 -> opcode + ".M1"
  | M2 -> opcode + ".M2"
  | M1X -> opcode + ".M1X"
  | M2X -> opcode + ".M2X"
  | D1 -> opcode + ".D1"
  | D2 -> opcode + ".D2"
  | NoUnit -> opcode

let buildParallelPipe ins builder acc =
  if ins.IsParallel then builder AsmWordKind.String "|| " acc
  else acc

let inline buildOpcode ins builder acc =
  let str = opCodeToString ins.Opcode |> appendUnit ins
  builder AsmWordKind.Mnemonic str acc

let oprToString insInfo opr delim builder acc =
  match opr with
  | Register reg ->
    builder AsmWordKind.String delim acc
    |> builder AsmWordKind.Variable (regToStr reg)
  | RegisterPair (r1, r2) ->
    builder AsmWordKind.String delim acc
    |> builder AsmWordKind.Variable (regToStr r1)
    |> builder AsmWordKind.String ":"
    |> builder AsmWordKind.Variable (regToStr r2)
  | Immediate imm ->
    builder AsmWordKind.String delim acc
    |> builder AsmWordKind.Value ("0x" + imm.ToString ("X"))

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
