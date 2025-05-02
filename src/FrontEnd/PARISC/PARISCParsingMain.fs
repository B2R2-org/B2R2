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

module internal B2R2.FrontEnd.PARISC.ParsingMain

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ParsingUtils
open B2R2.FrontEnd.PARISC.Helper
open type Completer

let internal wrap opt = Option.map (fun x -> [| x |]) opt

let parseSystemControlInstruction bin wordSz =
  match Bits.extract bin 12u 5u with
  | 0b00000000u -> Op.BREAK, None, getPos0Pos13 bin
  | 0b00100000u ->
    match Bits.extract bin 20u 16u with
    | 0b00000u -> Op.SYNC, None, NoOperand
    | 0b10000u -> Op.SYNCDMA, None, NoOperand
    | _ -> raise ParsingFailureException
  | 0b01100000u -> Op.RFI, None, NoOperand
  | 0b01100101u -> Op.RFI, Some [| R |], NoOperand
  | 0b01101011u -> Op.SSM, None, getPos16to25Rd bin
  | 0b01110011u -> Op.RSM, None, getPos16to25Rd bin
  | 0b11000011u -> Op.MTSM, None, getRs1 bin
  | 0b10000101u -> Op.LDSID, None, getMemSpaceRd bin (sr bin) wordSz
  | 0b11000001u -> Op.MTSP, None, getRs1Sr bin (srImm3 bin)
  | 0b00100101u -> Op.MFSP, None, getSrRd bin (srImm3 bin)
  | 0b11000010u -> Op.MTCTL, None, getRs1Cr bin
  | 0b01000101u ->
    if Bits.extract bin 25u 21u = 0b01011u && Bits.pick bin 14u = 1u then
      Op.MFCTL, Some [| W |], getCrRd bin
    else
      Op.MFCTL, None, getCrRd bin
  | 0b11000110u -> Op.MTSARCM, None, getRs1 bin
  | 0b10100101u -> Op.MFIA, None, getRd bin
  | _ -> raise ParsingFailureException

let parseMemoryManagementInstruction bin wordSz =
  let bit18 = Bits.pick bin 13u
  let bit19 = Bits.pick bin 12u
  let bit20to25 = Bits.extract bin 11u 6u
  let cmplt = if Bits.pick bin 5u = 1u then Some [| M |] else None
  let cmpltLM = if Bits.pick bin 5u = 1u then Some [| L; M |] else None
  if bit19 = 0u then
    let offset = getRegFromRange bin 20u 16u
    let oprs = getMemSpaceRegOff bin (srImm3 bin) offset wordSz
    match bit20to25 with
    | 0b100000u -> Op.IITLBT, None, getRs1Rs2 bin
    | 0b001000u -> Op.PITLB, cmplt, oprs
    | 0b011000u -> Op.PITLB, cmpltLM, oprs
    | 0b001001u -> Op.PITLBE, cmplt, oprs
    | 0b001010u -> Op.FIC, cmplt, oprs
    | 0b001011u -> Op.FICE, cmplt, oprs
    | _ -> raise ParsingFailureException
  else
    let offset = getRegFromRange bin 20u 16u
    match bit20to25 with
    | 0b100000u -> Op.IDTLBT, None, getRs1Rs2 bin
    | 0b001000u -> Op.PDTLB, cmplt, getMemSpaceRegOff bin (sr bin) offset wordSz
    | 0b011000u ->
      Op.PDTLB, cmpltLM, getMemSpaceRegOff bin (sr bin) offset wordSz
    | 0b001001u ->
      Op.PDTLBE, cmplt, getMemSpaceRegOff bin (sr bin) offset wordSz
    | 0b001010u ->
      if bit18 = 0u then
        Op.FDC, cmplt, getMemSpaceRegOff bin (sr bin) offset wordSz
      else
        let offset = getImmLowSignExt bin 20u 16u wordSz
        Op.FDC, cmplt, getMemSpaceOff bin (sr bin) offset wordSz
    | 0b001011u -> Op.FDCE, cmplt, getMemSpaceRegOff bin (sr bin) offset wordSz
    | 0b001110u -> Op.PDC, cmplt, getMemSpaceRegOff bin (sr bin) offset wordSz
    | 0b001111u -> Op.FIC, cmplt, getMemSpaceRegOff bin (sr bin) offset wordSz
    | 0b000110u ->
      if bit18 = 0u then
        Op.PROBE, Some [| R |], getMemSpaceRs1Rd bin (sr bin) wordSz
      else
        Op.PROBEI, Some [| R |], getMemSpaceIRs1Rd bin (sr bin) wordSz
    | 0b000111u ->
      if bit18 = 0u then
        Op.PROBE, Some [| W |], getMemSpaceRs1Rd bin (sr bin) wordSz
      else
        Op.PROBEI, Some [| W |], getMemSpaceIRs1Rd bin (sr bin) wordSz
    | 0b001101u -> Op.LPA, cmplt, getMemSpaceRegOffRd bin (sr bin) offset wordSz
    | 0b001100u -> Op.LCI, None, getMemSpaceRegOffRd bin (sr bin) offset wordSz
    | _ -> raise ParsingFailureException

let parseArithmeticLogicalInst bin =
  let cf =
    Bits.extract bin 15u 13u <<< 2 ||| (Bits.pick bin 12u <<< 1)
    ||| if Bits.pick bin 5u = 1u then 0b1u else 0b0u
  match Bits.extract bin 11u 6u, Bits.pick bin 5u = 1u with
  | 0b011000u, _ -> Op.ADD, None, getAddCondition cf, getRs1Rs2Rd bin
  | 0b101000u, _ -> Op.ADD, Some [| L |], getAddCondition cf, getRs1Rs2Rd bin
  | 0b111000u, _ -> Op.ADD, Some [| TSV |], getAddCondition cf, getRs1Rs2Rd bin
  | 0b011100u, false ->
    Op.ADD, Some [| C |], getAddCondition cf, getRs1Rs2Rd bin
  | 0b011100u, true ->
    Op.ADD, Some [| DC |], getAddCondition cf, getRs1Rs2Rd bin
  | 0b111100u, false ->
    Op.ADD, Some [| C; TSV |], getAddCondition cf, getRs1Rs2Rd bin
  | 0b111100u, true ->
    Op.ADD, Some [| DC; TSV |], getAddCondition cf, getRs1Rs2Rd bin
  | (0b011001u | 0b011010u | 0b011011u), _ ->
    Op.SHLADD, None, getAddCondition cf, getRs1SaRs2Rd bin 6u 1u
  | (0b101001u | 0b101010u | 0b101011u), _ ->
    Op.SHLADD, Some [| L |], getAddCondition cf, getRs1SaRs2Rd bin 6u 1u
  | (0b111001u | 0b111010u | 0b111011u), _ ->
    Op.SHLADD, Some [| TSV |], getAddCondition cf, getRs1SaRs2Rd bin 6u 1u
  | 0b010000u, _ -> Op.SUB, None, getCompSubCondition cf, getRs1Rs2Rd bin
  | 0b110000u, _ ->
    Op.SUB, Some [| TSV |], getCompSubCondition cf, getRs1Rs2Rd bin
  | 0b010011u, _ ->
    Op.SUB, Some [| TC |], getCompSubCondition cf, getRs1Rs2Rd bin
  | 0b110011u, _ ->
    Op.SUB, Some [| TSV; TC |], getCompSubCondition cf, getRs1Rs2Rd bin
  | 0b010100u, false ->
    Op.SUB, Some [| B |], getCompSubCondition cf, getRs1Rs2Rd bin
  | 0b010100u, true ->
    Op.SUB, Some [| DB |], getCompSubCondition cf, getRs1Rs2Rd bin
  | 0b110100u, false ->
    Op.SUB, Some [| B; TSV |], getCompSubCondition cf, getRs1Rs2Rd bin
  | 0b110100u, true ->
    Op.SUB, Some [| DB; TSV |], getCompSubCondition cf, getRs1Rs2Rd bin
  | 0b010001u, false -> Op.DS, None, getCompSubCondition cf, getRs1Rs2Rd bin
  | 0b000000u, _ -> Op.ANDCM, None, getLogicalCondition cf, getRs1Rs2Rd bin
  | 0b001000u, _ -> Op.AND, None, getLogicalCondition cf, getRs1Rs2Rd bin
  | 0b001001u, _ -> Op.OR, None, getLogicalCondition cf, getRs1Rs2Rd bin
  | 0b001010u, _ -> Op.XOR, None, getLogicalCondition cf, getRs1Rs2Rd bin
  | 0b001110u, _ -> Op.UXOR, None, getUnitCondition cf, getRs1Rs2Rd bin
  | 0b100010u, _ -> Op.CMPCLR, None, getCompSubCondition cf, getRs1Rs2Rd bin
  | 0b100110u, _ -> Op.UADDCM, None, getUnitCondition cf, getRs1Rs2Rd bin
  | 0b100111u, _ ->
    Op.UADDCM, Some [| TC |], getUnitCondition cf, getRs1Rs2Rd bin
  | 0b101110u, _ -> Op.DCOR, None, getUnitCondition cf, getRs2Rd bin
  | 0b101111u, _ -> Op.DCOR, Some [| I |], getUnitCondition cf, getRs2Rd bin
  | 0b001111u, false -> Op.HADD, None, None, getRs1Rs2Rd bin
  | 0b001101u, false -> Op.HADD, Some [| SS |], None, getRs1Rs2Rd bin
  | 0b001100u, false -> Op.HADD, Some [| US |], None, getRs1Rs2Rd bin
  | 0b000111u, false -> Op.HSUB, None, None, getRs1Rs2Rd bin
  | 0b000101u, false -> Op.HSUB, Some [| SS |], None, getRs1Rs2Rd bin
  | 0b000100u, false -> Op.HSUB, Some [| US |], None, getRs1Rs2Rd bin
  | 0b001011u, false -> Op.HAVG, None, None, getRs1Rs2Rd bin
  | (0b011101u | 0b011110u | 0b011111u), false ->
    Op.HSHLADD, None, None, getRs1SaRs2Rd bin 6u 1u
  | (0b010101u | 0b010110u | 0b010111u), false ->
    Op.HSHRADD, None, None, getRs1SaRs2Rd bin 6u 1u
  | _ -> raise ParsingFailureException

let parseArithmeticImmediateInstruction bin wordSz =
  let imm = getImmLowSignExt bin 10u 0u wordSz |> uint64
  let cf = Bits.extract bin 15u 13u <<< 2 ||| (Bits.pick bin 12u <<< 1)
  let bit11 = Bits.pick bin 11u
  let oprs = getImmRs2Rs1 bin imm
  match Bits.extract bin 31u 26u, bit11 with
  | 0b101101u, 0b0u -> Op.ADDI, None, getAddCondition cf, oprs
  | 0b101101u, 0b1u -> Op.ADDI, Some [| TSV |], getAddCondition cf, oprs
  | 0b100101u, 0b0u -> Op.SUBI, None, getCompSubCondition cf, oprs
  | 0b100101u, 0b1u -> Op.SUBI, Some [| TSV |], getCompSubCondition cf, oprs
  | 0b101100u, 0b0u -> Op.ADDI, Some [| TC |], getAddCondition cf, oprs
  | 0b101100u, 0b1u -> Op.ADDI, Some [| TSV; TC |], getAddCondition cf, oprs
  | _ -> raise ParsingFailureException

let parseLoadStoreOffset bin wordSz =
  let offset = getImmAssemble16 bin
  match Bits.extract bin 31u 26u with
  | 0b010000u -> Op.LDB, None, getMemSpaceOffRs1 bin (sr bin) offset wordSz
  | 0b010001u -> Op.LDH, None, getMemSpaceOffRs1 bin (sr bin) offset wordSz
  | 0b010010u -> Op.LDW, None, getMemSpaceOffRs1 bin (sr bin) offset wordSz
  | 0b010011u ->
    let cmplt =
      if getImmAssemble16 bin < 0 then Some [| MB |] else Some [| MA |]
    Op.LDW, cmplt, getMemSpaceOffRs1 bin (sr bin) offset wordSz
  | 0b011000u -> Op.STB, None, getRs1MemSpaceOff bin (sr bin) offset wordSz
  | 0b011001u -> Op.STH, None, getRs1MemSpaceOff bin (sr bin) offset wordSz
  | 0b011010u -> Op.STW, None, getRs1MemSpaceOff bin (sr bin) offset wordSz
  | 0b011011u ->
    let cmplt =
      if getImmAssemble16 bin < 0 then Some [| MB |] else Some [| MA |]
    Op.STW, cmplt, getRs1MemSpaceOff bin (sr bin) offset wordSz
  | _ -> raise ParsingFailureException

let parseIndexShortLoadStoreInstruction bin wordSz =
  if Bits.pick bin 12u = 0u then
    let cmplt = getIndexedCompleter (Bits.pick bin 13u <<< 1 ||| Bits.pick bin 5u)
    let cond = Bits.extract bin 11u 10u |> getLoadCacheHints
    let offset = getRegFromRange bin 20u 16u
    let oprs = getMemRegOffRd bin offset wordSz
    let spaceOprs = getMemSpaceRegOffRd bin (sr bin) offset wordSz
    match Bits.extract bin 9u 6u with
    | 0b0000u -> Op.LDB, cmplt, cond, spaceOprs
    | 0b0001u -> Op.LDH, cmplt, cond, spaceOprs
    | 0b0010u -> Op.LDW, cmplt, cond, spaceOprs
    | 0b0011u -> Op.LDD, cmplt, cond, spaceOprs
    | 0b0100u -> Op.LDDA, cmplt, cond, oprs
    | 0b0101u ->
      Op.LDCD, cmplt, Bits.extract bin 11u 10u |> getLoadCWordCacheHints, spaceOprs
    | 0b0110u -> Op.LDWA, cmplt, cond, oprs
    | 0b0111u ->
      Op.LDCW, cmplt, Bits.extract bin 11u 10u |> getLoadCWordCacheHints, spaceOprs
    | _ -> raise ParsingFailureException
  else
    let a = Bits.pick bin 13u
    let m = Bits.pick bin 5u
    let cc = Bits.extract bin 11u 10u
    let loadOff = getImmLowSignExt bin 20u 16u wordSz
    let storeOff = getImmLowSignExt bin 4u 0u wordSz
    let cmplt, cond =
      if Bits.extract bin 9u 6u < 0b1000u then
        getShortLoadStoreCmplt a m (Bits.extract bin 20u 16u),
        cc |> getLoadCacheHints
      else
        getShortLoadStoreCmplt a m (Bits.extract bin 4u 0u),
        cc |> getStoreCacheHints
    match Bits.extract bin 9u 6u with
    | 0b0000u ->
      Op.LDB, cmplt, cond, getMemSpaceOffRd bin (sr bin) loadOff wordSz
    | 0b0001u ->
      Op.LDH, cmplt, cond, getMemSpaceOffRd bin (sr bin) loadOff wordSz
    | 0b0010u ->
      Op.LDW, cmplt, cond, getMemSpaceOffRd bin (sr bin) loadOff wordSz
    | 0b0011u ->
      Op.LDD, cmplt, cond, getMemSpaceOffRd bin (sr bin) loadOff wordSz
    | 0b0100u ->
      Op.LDDA, cmplt, cond, getMemOffRd bin loadOff wordSz
    | 0b0101u ->
      let cond = getLoadCWordCacheHints cc
      Op.LDCD, cmplt, cond, getMemSpaceOffRd bin (sr bin) loadOff wordSz
    | 0b0110u ->
      Op.LDWA, cmplt, cond, getMemOffRd bin loadOff wordSz
    | 0b0111u ->
      let cond = getLoadCWordCacheHints cc
      Op.LDCW, cmplt, cond, getMemSpaceOffRd bin (sr bin) loadOff wordSz
    | 0b1000u ->
      Op.STB, cmplt, cond, getRs1MemSpaceOff bin (sr bin) storeOff wordSz
    | 0b1001u ->
      Op.STH, cmplt, cond, getRs1MemSpaceOff bin (sr bin) storeOff wordSz
    | 0b1010u ->
      Op.STW, cmplt, cond, getRs1MemSpaceOff bin (sr bin) storeOff wordSz
    | 0b1011u ->
      Op.STD, cmplt, cond, getRs1MemSpaceOff bin (sr bin) storeOff wordSz
    | 0b1100u ->
      let cmplt = getStoreBytesCmplt a m
      Op.STBY, cmplt, cond, getRs1MemSpaceOff bin (sr bin) storeOff wordSz
    | 0b1101u ->
      let cmplt = getStoreBytesCmplt a m
      Op.STDBY, cmplt, cond, getRs1MemSpaceOff bin (sr bin) storeOff wordSz
    | 0b1110u ->
      Op.STWA, cmplt, cond, getRs1MemOff bin storeOff wordSz
    | 0b1111u ->
      Op.STDA, cmplt, cond, getRs1MemOff bin storeOff wordSz
    | _ -> raise ParsingFailureException

let parseLoadStoreWordInstruction bin wordSz =
  let bit1to2 = Bits.extract bin 2u 1u
  let imm = getImmAssemble16 bin &&& -4
  if bit1to2 <> 0b010u then
    match Bits.extract bin 31u 26u with
    | 0b010111u -> Op.FLDW, None, getMemSpaceOffFrs1 bin (sr bin) imm wordSz
    | 0b011111u -> Op.FSTW, None, getFrs1MemSpaceOff bin (sr bin) imm wordSz
    | _ -> raise ParsingFailureException
  else
    let cmplt = Some [| if int64 imm >= 0 then MB else MA |]
    match Bits.extract bin 31u 26u with
    | 0b010111u -> Op.LDW, cmplt, getMemSpaceOffRs1 bin (sr bin) imm wordSz
    | 0b011111u -> Op.STW, cmplt, getRs1MemSpaceOff bin (sr bin) imm wordSz
    | _ -> raise ParsingFailureException

let parseLoadStoreDoublewordInstruction bin wordSz =
  let bit30 = Bits.pick bin 1u
  let a = Bits.pick bin 2u
  let m = Bits.pick bin 3u
  let imm = getImmAssemble16 bin &&& -8
  let cmplt = getShortLoadStoreCmplt a m (uint32 imm)
  if bit30 <> 0u then
    match Bits.extract bin 31u 26u with
    | 0b010100u -> Op.FLDD, cmplt, getMemSpaceOffFrs1 bin (sr bin) imm wordSz
    | 0b011100u -> Op.FSTD, cmplt, getFrs1MemSpaceOff bin (sr bin) imm wordSz
    | _ -> raise ParsingFailureException
  else
    match Bits.extract bin 31u 26u with
    | 0b010100u -> Op.LDD, cmplt, getMemSpaceOffRs1 bin (sr bin) imm wordSz
    | 0b011100u -> Op.STD, cmplt, getRs1MemSpaceOff bin (sr bin) imm wordSz
    | _ -> raise ParsingFailureException

let parseVariableShiftExtractDepositInstruction bin wordSz =
  let cond isDword =
    if isDword then Bits.extract bin 15u 13u <<< 1 ||| 0b1u
    else Bits.extract bin 15u 13u <<< 1
    |> getShfExtDepCondition
  match Bits.extract bin 31u 26u, Bits.extract bin 12u 9u with
  | 0b110100u, 0b0001u -> Op.SHRPD, None, cond true, getRs1Rs2SarRd bin
  | 0b110100u, 0b0000u -> Op.SHRPW, None, cond false, getRs1Rs2SarRd bin
  | 0b110100u, (0b1001u | 0b1011u) ->
    let se = Bits.pick bin 10u
    let clen = 32u - Bits.extract bin 4u 0u |> uint64
    Op.EXTRD, getExtractCmplt se, cond true, getRs2SarLenRs1 bin clen
  | 0b110100u, (0b1000u | 0b1010u) ->
    let se = Bits.pick bin 10u
    let clen = getImmAssemble6 0u (Bits.extract bin 4u 0u)
    Op.EXTRW, getExtractCmplt se, cond false,
    getRs2SarLenRs1 bin clen
  | 0b110101u, (0b0001u | 0b0011u) ->
    let nz = Bits.pick bin 10u
    let cl = Bits.pick bin 8u
    let clen = getImmAssemble6 cl (Bits.extract bin 4u 0u)
    Op.DEPD, getDepositCmplt nz, cond true,
    getRs1SarLenRs2 bin clen
  | 0b110101u, (0b1001u | 0b1011u) ->
    let nz = Bits.pick bin 10u
    let cl = Bits.pick bin 8u
    let clen = getImmAssemble6 cl (Bits.extract bin 4u 0u)
    let imm = getImmLowSignExt bin 20u 16u wordSz |> uint64
    Op.DEPDI, getDepositCmplt nz, cond true,
    getImmSarLenRs2 bin imm clen
  | 0b110101u, (0b0000u | 0b0010u) ->
    let nz = Bits.pick bin 10u
    let clen = getImmAssemble6 0u (Bits.extract bin 4u 0u)
    Op.DEPW, getDepositCmplt nz, cond true,
    getRs1SarLenRs2 bin clen
  | 0b110101u, (0b1000u | 0b1010u) ->
    let nz = Bits.pick bin 10u
    let clen = getImmAssemble6 0u (Bits.extract bin 4u 0u)
    let imm = getImmLowSignExt bin 20u 16u wordSz |> uint64
    Op.DEPWI, getDepositCmplt nz, cond true,
    getImmSarLenRs2 bin imm clen
  | _ -> raise ParsingFailureException

let parseFixedShiftExtractDepositInstruction bin wordSz =
  let cond isDword =
    if isDword then Bits.extract bin 15u 13u <<< 1 ||| 0b1u
    else Bits.extract bin 15u 13u <<< 1
    |> getShfExtDepCondition
  match Bits.extract bin 31u 26u, Bits.extract bin 12u 10u with
  | 0b110100u, (0b001u | 0b011u) ->
    let cp = Bits.pick bin 11u
    let cpos = Bits.extract bin 9u 5u
    Op.SHRPD, None, cond true,
    getRs1Rs2cCposRd bin cp cpos
  | 0b110100u, 0b010u ->
    let cpos = Bits.extract bin 9u 5u
    Op.SHRPW, None, cond false,
    getRs1Rs2cCposRd bin 1u cpos
  | 0b110110u, _ ->
    let se = Bits.pick bin 10u
    let cl = Bits.pick bin 12u
    let clen = Bits.extract bin 4u 0u
    let len = getImmAssembleExtDWord cl clen
    Op.EXTRD, getExtractCmplt se, cond true,
    getRs2PosP5to9LenRs1 bin len
  | 0b110100u, (0b110u | 0b111u) ->
    let se = Bits.pick bin 10u
    let clen = getImmAssemble6 0u (Bits.extract bin 4u 0u)
    Op.EXTRW, getExtractCmplt se, cond false,
    getRs2Pos5to9LenRs1 bin clen
  | 0b111100u, _ ->
    let nz = Bits.pick bin 10u
    let cp = Bits.pick bin 11u
    let cl = Bits.pick bin 12u
    let cpos = Bits.extract bin 9u 5u
    let clen = Bits.extract bin 4u 0u
    let len = getImmAssembleExtDWord cl clen
    Op.DEPD, getDepositCmplt nz, cond true,
    getRs1CCposLenRs2 bin cp cpos len
  | 0b111101u, _ ->
    let nz = Bits.pick bin 10u
    let cp = Bits.pick bin 11u
    let cl = Bits.pick bin 12u
    let cpos = Bits.extract bin 9u 5u
    let clen = Bits.extract bin 4u 0u
    let len = getImmAssembleExtDWord cl clen
    let imm = getImmLowSignExt bin 20u 16u wordSz |> uint64
    let cond = cond true
    Op.DEPDI, getDepositCmplt nz, cond,
    getImmCCposLenRs2 bin imm cp cpos len
  | 0b110101u, (0b010u | 0b011u) ->
    let nz = Bits.pick bin 10u
    let clen = getImmAssemble6 0u (Bits.extract bin 4u 0u)
    let cpos = Bits.extract bin 9u 5u
    Op.DEPW, getDepositCmplt nz, cond false,
    getRs1CCposLenRs2 bin 1u cpos clen
  | 0b110101u, (0b110u | 0b111u) ->
    let nz = Bits.pick bin 10u
    let clen = getImmAssemble6 0u (Bits.extract bin 4u 0u)
    let cpos = Bits.extract bin 9u 5u
    let imm = getImmLowSignExt bin 20u 16u wordSz |> uint64
    Op.DEPWI, getDepositCmplt nz, cond false,
    getImmCCposLenRs2 bin imm 1u cpos clen
  | _ -> raise ParsingFailureException

let parseMultimediaInstruction bin =
  if Bits.pick bin 15u = 0b0u then
    let c =
      Bits.extract bin 14u 13u * 1000u + Bits.extract bin 11u 10u * 100u +
      Bits.extract bin 9u 8u * 10u + Bits.extract bin 7u 6u
    Op.PERMH, None, None, Some [| uint64 c |], getRs2Rd bin
  else
    match Bits.concat (Bits.extract bin 14u 13u)
                      (Bits.extract bin 11u 10u) 2 with
    | 0b0010u -> Op.HSHL, None, None, None, getRs1SaRd bin 6u 3u
    | 0b1010u -> Op.HSHR, Some [| U |], None, None, getRs2SaRd bin 6u 3u
    | 0b1011u -> Op.HSHR, Some [| S |], None, None, getRs2SaRd bin 6u 3u
    | 0b0000u -> Op.MIXW, Some [| L |], None, None, getRs1Rs2Rd bin
    | 0b1000u -> Op.MIXW, Some [| R |], None, None, getRs1Rs2Rd bin
    | 0b0001u -> Op.MIXH, Some [| L |], None, None, getRs1Rs2Rd bin
    | 0b1001u -> Op.MIXH, Some [| R |], None, None, getRs1Rs2Rd bin
    | _ -> raise ParsingFailureException

let parseUnconditionalBranchInstuction bin wordSz =
  match Bits.extract bin 25u 0u with
  | 16389u -> Op.CLRBTS, None, None, NoOperand
  | 16385u -> Op.PUSHNOM, None, None, NoOperand
  | _ ->
    let condN = if Bits.pick bin 1u = 1u then Some N else None
    match Bits.extract bin 15u 13u, Bits.pick bin 12u with
    | 0b000u, _ ->
      Op.B, Some [| L |], condN, getImmRs2 bin (getImmAssemble17 bin + 8UL)
    | 0b001u, _ ->
      Op.B, Some [| GATE |], condN, getImmRs2 bin (getImmAssemble17 bin + 8UL)
    | 0b100u, _ ->
      Op.B, Some [| L; PUSH |], condN, getImmRs2 bin (getImmAssemble22 bin
        + 8UL)
    | 0b101u, _ ->
      Op.B, Some [| L |], condN, getImmRs2 bin (getImmAssemble22 bin + 8UL)
    | 0b010u, 0u ->
      match Bits.extract bin 25u 21u, Bits.extract bin 11u 0u with
      | 0u, 0u -> Op.PUSHBTS, None, None, getRs1 bin
      | _->
        Op.BLR, Some [| N |], None, getRs1Rs2 bin
    | 0b110u, 0u ->
      Op.BV, Some [| N |], None, getMemBaseRegOff bin (getRegFromRange bin 20u
        16u) wordSz
    | 0b110u, 1u -> Op.BVE, Some [| N |], None, getMemBase bin wordSz
    | 0b111u, 1u -> Op.BVE, Some [| L |], condN, getMemBaseRP bin wordSz
    | _ -> raise ParsingFailureException

let parseCoprocessorLoadStoreInstruction bin wordSz =
  let bit18 = Bits.pick bin 13u
  let bit26 = Bits.pick bin 5u
  let cc = Bits.extract bin 11u 10u
  let uid = Bits.extract bin 8u 6u
  let ldC = getLoadCacheHints cc
  let swC = getStoreCacheHints cc
  let short = getShortLoadStoreCmplt bit18 bit26 (Bits.extract bin 20u 16u)
  let index = getIndexedCompleter (bit18 <<< 1 ||| bit26)
  if Bits.extract bin 31u 26u = 0b001001u then
    match Bits.concat (Bits.pick bin 12u) (Bits.pick bin 9u) 1, uid with
    | 0b00u, (0b0u | 0b1u) ->
      let offset = getRegFromRange bin 20u 16u
      Op.FLDW, index, ldC, None, getMemSpaceRegOffFrd bin (sr bin) offset wordSz
    | 0b10u, (0b0u | 0b1u) ->
      let offset = getImmLowSignExt bin 20u 16u wordSz
      Op.FLDW, short, ldC, None, getMemSpaceOffFrd bin (sr bin) offset wordSz
    | 0b00u, _ ->
      let offset = getRegFromRange bin 20u 16u
      let uid = [| getImmediate bin 8u 6u |] |> Some
      Op.CLDW, index, ldC, uid, getMemSpaceRegOffRd bin (sr bin) offset wordSz
    | 0b10u, _ ->
      let offset = getImmLowSignExt bin 20u 16u wordSz
      let uid = [| getImmediate bin 8u 6u |] |> Some
      Op.CLDW, short, ldC, uid, getMemSpaceOffRd bin (sr bin) offset wordSz
    | 0b01u, (0b0u | 0b1u) ->
      let offset = getRegFromRange bin 20u 16u
      Op.FSTW, index, swC, None, getFrdMemSpaceRegOff bin (sr bin) offset wordSz
    | 0b11u, (0b0u | 0b1u) ->
      let offset = getImmLowSignExt bin 20u 16u wordSz
      Op.FSTW, short, swC, None, getFrdMemSpaceOff bin (sr bin) offset wordSz
    | 0b01u, _ ->
      let offset = getRegFromRange bin 20u 16u
      let uid = [| getImmediate bin 8u 6u |] |> Some
      Op.CSTW, index, swC, uid, getRdMemSpaceRegOff bin (sr bin) offset wordSz
    | 0b11u, _ ->
      let offset = getImmLowSignExt bin 20u 16u wordSz
      let uid = [| getImmediate bin 8u 6u |] |> Some
      Op.CSTW, short, swC, uid, getRdMemSpaceOff bin (sr bin) offset wordSz
    | _ -> raise ParsingFailureException
  else
    match Bits.concat (Bits.pick bin 12u) (Bits.pick bin 9u) 1, uid with
    | 0b00u, 0b0u ->
      let offset = getRegFromRange bin 20u 16u
      Op.FLDD, index, ldC, None, getMemSpaceRegOffFrd bin (sr bin) offset wordSz
    | 0b10u, 0b0u ->
      let offset = getImmLowSignExt bin 20u 16u wordSz
      Op.FLDD, short, ldC, None, getMemSpaceOffFrd bin (sr bin) offset wordSz
    | 0b00u, _ ->
      let offset = getRegFromRange bin 20u 16u
      let uid = [| getImmediate bin 8u 6u |] |> Some
      Op.CLDD, index, ldC, uid, getMemSpaceRegOffRd bin (sr bin) offset wordSz
    | 0b10u, _ ->
      let offset = getImmLowSignExt bin 20u 16u wordSz
      let uid = [| getImmediate bin 8u 6u |] |> Some
      Op.CLDD, short, ldC, uid, getMemSpaceOffRd bin (sr bin) offset wordSz
    | 0b01u, 0b0u ->
      let offset = getRegFromRange bin 20u 16u
      Op.FSTD, index, swC, None, getFrdMemSpaceRegOff bin (sr bin) offset wordSz
    | 0b11u, 0b0u ->
      let offset = getImmLowSignExt bin 20u 16u wordSz
      Op.FSTD, short, swC, None, getFrdMemSpaceOff bin (sr bin) offset wordSz
    | 0b01u, _ ->
      let offset = getRegFromRange bin 20u 16u
      let uid = [| getImmediate bin 8u 6u |] |> Some
      Op.CSTD, index, swC, uid, getRdMemSpaceRegOff bin (sr bin) offset wordSz
    | 0b11u, _ ->
      let offset = getImmLowSignExt bin 20u 16u wordSz
      let uid = [| getImmediate bin 8u 6u |] |> Some
      Op.CSTD, short, swC, uid, getRdMemSpaceOff bin (sr bin) offset wordSz
    | _ -> raise ParsingFailureException

let parseFloatingPointCoprocessorInstruction bin =
  let uid = Bits.extract bin 8u 6u
  let classBit = Bits.extract bin 10u 9u
  let fmt = Bits.extract bin 12u 11u
  let copr =
    let sop = Bits.extract bin 25u 9u <<< 5 ||| Bits.extract bin 4u 0u
    let cmplt = if Bits.pick bin 5u = 1u then Some [| N |] else None
    Op.COPR, cmplt, None, Some [| uint64 uid; uint64 sop |], NoOperand
  match uid, classBit with
  | 0u, 0u ->
    let cmplt = getFloatFormat fmt
    match Bits.extract bin 15u 13u with
    | 0u -> Op.FID, None, None, None, NoOperand
    | 2u -> Op.FCPY, cmplt, None, None, getFrs2Frd bin
    | 3u -> Op.FABS, cmplt, None, None, getFrs2Frd bin
    | 4u -> Op.FSQRT, cmplt, None, None, getFrs2Frd bin
    | 5u -> Op.FRND, cmplt, None, None, getFrs2Frd bin
    | 6u -> Op.FNEG, cmplt, None, None, getFrs2Frd bin
    | 7u -> Op.FNEGABS, cmplt, None, None, getFrs2Frd bin
    | _ -> copr
  | 0u, 1u ->
    let cmplt = fmt <<< 2 ||| Bits.extract bin 14u 13u
    match Bits.extract bin 17u 15u with
    | 0u -> Op.FCNV, getFloatFloatFormat cmplt, None, None, getFrs2Frd bin
    | 1u -> Op.FCNV, getFixedFloatFormat cmplt, None, None, getFrs2Frd bin
    | 2u -> Op.FCNV, getFloatFixedFormat false cmplt, None, None, getFrs2Frd bin
    | 3u -> Op.FCNV, getFloatFixedFormat true cmplt, None, None, getFrs2Frd bin
    | 7u -> Op.FCNV, getFloatUFixedFormat true cmplt, None, None, getFrs2Frd bin
    | 5u -> Op.FCNV, getUFixedFloatFormat cmplt, None, None, getFrs2Frd bin
    | 6u ->
      Op.FCNV, getFloatUFixedFormat false cmplt, None, None, getFrs2Frd bin
    | _ -> copr
  | 0u, 2u ->
    let subop = Bits.extract bin 15u 13u
    let fmt = Bits.extract bin 12u 11u
    let c = Bits.extract bin 4u 0u
    if Bits.pick bin 5u = 0u then
      let opr =
        if subop <> 0u then getFrs2Frs1Imm bin (subop - 1u |> uint64)
        else getFrs2Frs1 bin
      Op.FCMP, getFloatFormat fmt, getFloatCompareCondition c, None, opr
    else
      let cond = if subop = 1u then getFloatTestCondition c else None
      let opr =
        if subop <> 1u then getImm (uint64 ((subop ^^^ 1u) - 1u)) else NoOperand
      Op.FTEST, None, cond, None, opr
  | 0u, 3u ->
    let cmplt = getFloatFormat fmt
    match Bits.extract bin 15u 13u with
    | 0u -> Op.FADD, cmplt, None, None, getFrs2Frs1Frd bin
    | 1u -> Op.FSUB, cmplt, None, None, getFrs2Frs1Frd bin
    | 2u -> Op.FMPY, cmplt, None, None, getFrs2Frs1Frd bin
    | 3u -> Op.FDIV, cmplt, None, None, getFrs2Frs1Frd bin
    | _ -> copr
  | 2u, _ ->
    match Bits.extract bin 13u 9u with
    | 1u ->
      let cmplt = if Bits.pick bin 5u = 1u then Some [| N |] else None
      Op.PMDIS, cmplt, None, None, NoOperand
    | 3u -> Op.PMENB, None, None, None, NoOperand
    | _ -> copr
  | _ -> copr

let parseFloatingPointInstruction bin =
  match Bits.extract bin 10u 9u with
  | 0b00u ->
    let subop = Bits.extract bin 15u 13u
    let cmplt = getFloatFormat (Bits.extract bin 12u 11u)
    match subop with
    | 0b010u -> Op.FCPY, cmplt, None, getFrs2Frd bin
    | 0b011u -> Op.FABS, cmplt, None, getFrs2Frd bin
    | 0b100u -> Op.FSQRT, cmplt, None, getFrs2Frd bin
    | 0b101u -> Op.FRND, cmplt, None, getFrs2Frd bin
    | 0b110u -> Op.FNEG, cmplt, None, getFrs2Frd bin
    | 0b111u -> Op.FNEGABS, cmplt, None, getFrs2Frd bin
    | _ -> raise ParsingFailureException
  | 0b01u ->
    let subop = Bits.extract bin 17u 15u
    let cmplt = Bits.extract bin 12u 11u <<< 2 ||| Bits.extract bin 14u 13u
    match subop with
    | 0b000u -> Op.FCNV, getFloatFloatFormat cmplt, None, getFrs2Frd bin
    | 0b001u -> Op.FCNV, getFixedFloatFormat cmplt, None, getFrs2Frd bin
    | 0b011u -> Op.FCNV, getFloatFixedFormat true cmplt, None, getFrs2Frd bin
    | 0b111u -> Op.FCNV, getFloatUFixedFormat true cmplt, None, getFrs2Frd bin
    | 0b010u -> Op.FCNV, getFloatFixedFormat false cmplt, None, getFrs2Frd bin
    | 0b101u -> Op.FCNV, getUFixedFloatFormat cmplt, None, getFrs2Frd bin
    | 0b110u -> Op.FCNV, getFloatUFixedFormat false cmplt, None, getFrs2Frd bin
    | _ -> raise ParsingFailureException
  | 0b10u ->
    let cond = Bits.extract bin 4u 0u |> getFloatTestCondition
    let oprs = getFrs2Frs1 bin
    Op.FCMP, getFloatFormat (Bits.pick bin 11u), cond, oprs
  | 0b11u ->
    let subop = Bits.extract bin 15u 13u
    let fBit = Bits.pick bin 8u
    if fBit = 0u then
      let cmplt = Bits.pick bin 11u |> getFloatFormat
      match subop with
      | 0b000u -> Op.FADD, cmplt, None, getFrs2Frs1Frd bin
      | 0b001u -> Op.FSUB, cmplt, None, getFrs2Frs1Frd bin
      | 0b010u -> Op.FMPY, cmplt, None, getFrs2Frs1Frd bin
      | 0b011u -> Op.FDIV, cmplt, None, getFrs2Frs1Frd bin
      | _ -> raise ParsingFailureException
    elif subop = 0b010u then Op.XMPYU, None, None, getFrs2Frs1Frd bin
    else raise ParsingFailureException
  | _ -> raise ParsingFailureException

let parseSpecialFunctionInstruction bin =
  let sfu = Bits.extract bin 8u 6u |> uint64
  let cmplt = if Bits.pick bin 5u = 0b0u then None else Some [| N |]
  match Bits.extract bin 10u 9u with
  | 0b00u ->
    let sop = Bits.extract bin 25u 11u <<< 5 ||| Bits.extract bin 4u 0u |> uint64
    Op.SPOP0, cmplt, Some [| sfu; sop |], NoOperand
  | 0b01u ->
    let sop = Bits.extract bin 25u 11u |> uint64
    Op.SPOP1, cmplt, Some [| sfu; sop |], getRd bin
  | 0b10u ->
    let sop = Bits.extract bin 20u 11u <<< 5 ||| Bits.extract bin 4u 0u |> uint64
    Op.SPOP2, cmplt, Some [| sfu; sop |], getRs2 bin
  | 0b11u ->
    let sop = Bits.extract bin 15u 11u <<< 5 ||| Bits.extract bin 4u 0u |> uint64
    Op.SPOP3, cmplt, Some [| sfu; sop |], getRs1Rs2 bin
  | _ -> raise ParsingFailureException

let parseFloatingPointFusedOperationInstruction bin =
  let cmplt = getFloatFormat (Bits.pick bin 11u)
  if Bits.pick bin 5u = 0u then Op.FMPYFADD, cmplt, getFrs2Frs1FraFrd bin
  else Op.FMPYNFADD, cmplt, getFrs2Frs1FraFrd bin

let parseFloatingPointLoadStoreInstruction bin wordSz =
  let cmplt = Some [| if Bits.pick bin 2u = 0u then MA else MB |]
  let imm = getImmAssemble16 bin &&& -4
  if Bits.extract bin 31u 26u = 0b010110u then
    Op.FLDW, cmplt, getMemSpaceOffFrs1 bin (sr bin) imm wordSz
  else
    Op.FSTW, cmplt, getFrs1MemSpaceOff bin (sr bin) imm wordSz

let parseConditionalLocalBranchInstruction bin wordSz =
  let cBit = Bits.extract bin 15u 13u
  let cond fBit isDword =
    cBit <<< 2 ||| (fBit <<< 1) ||| if isDword then 0b1u else 0b0u
  let target = getImmAssemble12 bin + 8UL
  let n = if Bits.pick bin 1u = 0u then None else Some N
  match Bits.extract bin 31u 26u with
  | 0b100000u ->
    Op.CMPB, getCompSubCondition (cond 0u false) |> wrap, n
    , getRs1Rs2Imm bin target
  | 0b100010u ->
    Op.CMPB, getCompSubCondition (cond 1u false) |> wrap, n
    , getRs1Rs2Imm bin target
  | 0b100111u ->
    Op.CMPB, getCompSubCondition (cond 0u true) |> wrap, n
    , getRs1Rs2Imm bin target
  | 0b101111u ->
    Op.CMPB, getCompSubCondition (cond 1u true) |> wrap, n
    , getRs1Rs2Imm bin target
  | 0b101000u ->
    Op.ADDB, getAddCondition (cond 0u false) |> wrap, n, getRs1Rs2Imm bin target
  | 0b101010u ->
    Op.ADDB, getAddCondition (cond 1u false) |> wrap, n, getRs1Rs2Imm bin target
  | 0b110010u ->
    Op.MOVB, getShfExtDepCondition (cBit <<< 1) |> wrap, n
    , getRs1Rs2Imm bin target
  | 0b100001u ->
    Op.CMPIB, getCompSubCondition (cond 0u false) |> wrap, n,
    getExtRs1Rs2Imm bin target wordSz
  | 0b100011u ->
    Op.CMPIB, getCompSubCondition (cond 1u false) |> wrap, n,
    getExtRs1Rs2Imm bin target wordSz
  | 0b111011u ->
    Op.CMPIB, getCmpibCondition cBit |> wrap, n
    , getExtRs1Rs2Imm bin target wordSz
  | 0b101001u ->
    Op.ADDIB, getAddCondition (cond 0u false) |> wrap, n,
    getExtRs1Rs2Imm bin target wordSz
  | 0b101011u ->
    Op.ADDIB, getAddCondition (cond 1u false) |> wrap, n,
    getExtRs1Rs2Imm bin target wordSz
  | 0b110011u ->
    Op.MOVIB, getShfExtDepCondition (cBit <<< 1) |> wrap, n,
    getExtRs1Rs2Imm bin target wordSz
  | 0b110000u | 0b110001u as bb ->
    let cd = Bits.pick bin 15u <<< 1 ||| Bits.pick bin 13u
    Op.BB, getBranchOnBitCondition cd |> wrap, n,
    if bb = 0b110001u then getRs1Pos21to25Imm bin target
    else getRs1SarImm bin target
  | _ -> raise ParsingFailureException

let parseMultipleOperationInstruction bin =
  let rm1 = Bits.extract bin 25u 21u
  let rm2 = Bits.extract bin 20u 16u
  let ta = Bits.extract bin 15u 11u
  let ra = Bits.extract bin 10u 6u
  let tm = Bits.extract bin 4u 0u
  let oprs =
    let cmplt = if Bits.pick bin 5u = 0u then Some [| DBL |] else Some [| SGL|]
    cmplt,
    (rm1 |> getFRegister |> OpReg,
     rm2 |> getFRegister |> OpReg,
     tm |> getFRegister |> OpReg,
     ra |> getFRegister |> OpReg,
     ta |> getFRegister |> OpReg)
    |> FiveOperands
  if Bits.extract bin 31u 26u = 0b000110u then Op.FMPYADD, oprs else Op.FMPYSUB, oprs

let private parseInstruction bin wordSz =
  let opcode = Bits.extract bin 31u 26u
  match opcode with
  | 0b000000u ->
    let opcode, completer, operands = parseSystemControlInstruction bin wordSz
    opcode, completer, None, None, operands
  | 0b000001u ->
    let opcode, completer, operands =
      parseMemoryManagementInstruction bin wordSz
    opcode, completer, None, None, operands
  | 0b000010u ->
    let opcode, completer, cond, operands =
      parseArithmeticLogicalInst bin
    opcode, completer, cond, None, operands
  | 0b101101u | 0b100101u | 0b101100u->
    let opcode, completer, cond, operands =
      parseArithmeticImmediateInstruction bin wordSz
    opcode, completer, cond, None, operands
  | 0b010000u | 0b010001u | 0b010010u | 0b010011u
  | 0b011000u | 0b011001u | 0b011010u | 0b011011u ->
    let opcode, completer, operands = parseLoadStoreOffset bin wordSz
    opcode, completer, None, None, operands
  | 0b000011u ->
    let opcode, completer, cond, operands =
      parseIndexShortLoadStoreInstruction bin wordSz
    opcode, completer, cond, None, operands
  | 0b010111u | 0b011111u ->
    let opcode, completer, operands = parseLoadStoreWordInstruction bin wordSz
    opcode, completer, None, None, operands
  | 0b010100u | 0b011100u ->
    let opcode, completer, operands =
      parseLoadStoreDoublewordInstruction bin wordSz
    opcode, completer, None, None, operands
  | 0b110100u | 0b110101u ->
    let bits19to20 = Bits.extract bin 12u 11u
    let opcode, completer, cond, operands =
      match bits19to20 with
      | 0b00u ->
        let bit21 = Bits.pick bin 10u
        if bit21 = 0u then
          parseVariableShiftExtractDepositInstruction bin wordSz
        else
          parseFixedShiftExtractDepositInstruction bin wordSz
      | 0b10u ->
        parseVariableShiftExtractDepositInstruction bin wordSz
      | _ ->
        parseFixedShiftExtractDepositInstruction bin wordSz
    opcode, completer, cond, None, operands
  | 0b110110u | 0b111100u | 0b111101u ->
    let opcode, completer, cond, operands =
      parseFixedShiftExtractDepositInstruction bin wordSz
    opcode, completer, cond, None, operands
  | 0b111110u -> parseMultimediaInstruction bin
  | 0b111010u ->
    let opcode, completer, cond, operands =
      parseUnconditionalBranchInstuction bin wordSz
    opcode, completer, cond, None, operands
  | 0b001001u | 0b001011u -> parseCoprocessorLoadStoreInstruction bin wordSz
  | 0b001100u -> parseFloatingPointCoprocessorInstruction bin
  | 0b001110u ->
    let opcode, completer, cond, operands = parseFloatingPointInstruction bin
    opcode, completer, cond, None, operands
  | 0b000100u ->
    let opcode, completer, id, operands = parseSpecialFunctionInstruction bin
    opcode, completer, None, id, operands
  | 0b101110u ->
    let opcode, completer, operands =
      parseFloatingPointFusedOperationInstruction bin
    opcode, completer, None, None, operands
  | 0b010110u | 0b011110u ->
    let opcode, completer, operands =
      parseFloatingPointLoadStoreInstruction bin wordSz
    opcode, completer, None, None, operands
  | 0b100111u | 0b101111u | 0b111011u | 0b110010u | 0b110001u | 0b110011u
  | 0b110000u | 0b100000u | 0b100010u | 0b101000u | 0b101010u | 0b100001u
  | 0b100011u | 0b101001u | 0b101011u  ->
    let opcode, completer, cond, operands =
      parseConditionalLocalBranchInstruction bin wordSz
    opcode, completer, cond, None, operands
  | 0b000101u ->
    Op.DIAG, None, None, None, getImm (Bits.extract bin 25u 0u |> uint64)
  | 0b000110u | 0b100110u ->
    let opcode, (completer, operands) = parseMultipleOperationInstruction bin
    opcode, completer, None, None, operands
  | 0b001000u -> Op.LDIL, None, None, None, getImmRs2 bin (getImmAssemble21 bin)
  | 0b001010u ->
    Op.ADDIL, None, None, None, getImmRs2 bin (getImmAssemble21 bin)
  | 0b001101u ->
    Op.LDO, None, None, None, getMemBaseOffRs1 bin (getImmAssemble16 bin) wordSz
  | 0b100100u ->
    let cond = Bits.extract bin 15u 11u
    let imm = getImmLowSignExt bin 10u 0u wordSz |> uint64
    Op.CMPICLR, getCompSubCondition cond |> wrap, None, None
    , getImmRs2Rs1 bin imm
  | 0b111000u ->
    let n = if Bits.pick bin 1u = 0u then None else Some N
    let offset = getImmAssemble17 bin |> int64
    Op.BE, None, n, None, getMemSpaceOff bin (srImm3 bin) offset wordSz
  | 0b111001u ->
    let n = if Bits.pick bin 1u = 0u then None else Some N
    let offset = getImmAssemble17 bin |> int64
    Op.BE, Some [| L |], n, None,
    getMemSpaceOffSr0R31 bin (srImm3 bin) offset wordSz
  | _ -> raise ParsingFailureException

let getOperationSize opcode wordSz =
  match opcode with
  | Op.STB -> 8<rt>
  | Op.STH -> 16<rt>
  | Op.STW -> 32<rt>
  | Op.STD -> 64<rt>
  | _ -> WordSize.toRegType wordSz

let parse (span: ByteSpan) (reader: IBinReader) arch wordSize addr =
  let bin = reader.ReadUInt32 (span, 0)
  let wordSz = WordSize.toRegType wordSize
  let opcode, completer, (cond: option<Completer>), id, operands =
    parseInstruction bin wordSz
  let insInfo =
    { Address = addr
      NumBytes = 4u
      Completer = completer
      Condition = cond
      ID = id
      Opcode = opcode
      Operands = operands
      OperationSize = getOperationSize opcode wordSize
      Arch = arch }
  PARISCInstruction (addr, 4u, insInfo, wordSize)

// vim: set tw=80 sts=2 sw=2:
