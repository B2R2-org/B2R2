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

module internal B2R2.FrontEnd.ARM64.LiftingUtils

open System
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.ARM64

let getPC bld = regVar bld R.PC

let rorForIR src amount width = (src >> amount) .| (src << (width .- amount))

let ror x amount width = (x >>> amount) ||| (x <<< (width - amount))

let oprSzToExpr oprSize = numI32 (RegType.toBitWidth oprSize) oprSize

let memSizeToExpr rt = numI32 (RegType.toByteWidth rt) 64<rt>

let vectorToList vector esize =
  List.init (64 / int esize) (fun e -> AST.extract vector esize (e * int esize))

let getTwoOprs (ins: Instruction) =
  match ins.Operands with
  | TwoOperands (o1, o2) -> struct (o1, o2)
  | _ -> raise InvalidOperandException

let getThreeOprs (ins: Instruction) =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> struct (o1, o2, o3)
  | _ -> raise InvalidOperandException

let getFourOprs (ins: Instruction) =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) -> struct (o1, o2, o3, o4)
  | _ -> raise InvalidOperandException

let getPseudoRegVarToArr bld reg eSize dataSize elems =
  let regA = pseudoRegVar bld reg 1
  let pos = int eSize
  if dataSize = 128<rt> then
    let regB = pseudoRegVar bld reg 2
    let elems = elems / 2
    let regA = Array.init elems (fun i -> AST.extract regA eSize (i * pos))
    let regB = Array.init elems (fun i -> AST.extract regB eSize (i * pos))
    Array.append regA regB
  else Array.init elems (fun i -> AST.extract regA eSize (i * pos))

let private getMemExpr128 expr =
  match expr with
  | Load (e, 128<rt>, expr, _) ->
    struct (AST.load e 64<rt> (expr .+ numI32 8 (Expr.TypeOf expr)),
            AST.load e 64<rt> expr)
  | _ -> raise InvalidOperandException

let getImmValue imm =
  match imm with
  | OprImm imm -> imm
  | _ -> raise InvalidOperandException

/// shared/functions/integer/AddWithCarry
/// AddWithCarry()
/// ==============
/// Integer addition with carry input, returning result and NZCV flags
let addWithCarry opr1 opr2 carryIn oSz =
  let result = opr1 .+ opr2 .+ carryIn
  let n = AST.xthi 1<rt> result
  let z = result == (AST.num0 oSz)
  let c =
    let zext64 = AST.zext 64<rt>
    let hi32 = AST.xthi 32<rt>
    let lo32 = AST.xtlo 32<rt>
    if oSz = 32<rt> then
      let unsignedSum = zext64 opr1 .+ zext64 opr2 .+ zext64 carryIn
      unsignedSum != (zext64 result)
    else
      let s1H, s1L = opr1 |> hi32 |> zext64, opr1 |> lo32 |> zext64
      let s2H, s2L = opr2 |> hi32 |> zext64, opr2 |> lo32 |> zext64
      let loRes = s1L .+ s2L .+ carryIn
      let over = hi32 loRes |> zext64
      let unsignedSumHigh = s1H .+ s2H .+ over
      unsignedSumHigh != (unsignedSumHigh |> lo32 |> zext64)
  let o1 = AST.xthi 1<rt> opr1
  let o2 = AST.xthi 1<rt> opr2
  let r = AST.xthi 1<rt> result
  let v = (o1 == o2) .& (o1 <+> r)
  result, (n, z, c, v)

/// aarch64/instrs/integer/shiftreg/ShiftReg
/// ShiftReg()
/// ==========
/// Perform shift of a register operand
let shiftReg reg amount oprSize = function
  | SRTypeLSL -> reg << amount
  | SRTypeLSR -> reg >> amount
  | SRTypeASR -> reg ?>> amount
  | SRTypeROR -> rorForIR reg amount (oprSzToExpr oprSize)
  | _ -> raise InvalidOperandException

let transShiftAmout bld oprSize = function
  | Imm amt -> numI64 amt oprSize
  | Reg amt -> regVar bld amt

/// shared/functions/common/Extend
/// Extend()
/// ========
let extend reg oprSz regSize isUnsigned =
  let uMask = numI64 ((1L <<< regSize) - 1L) oprSz
  if isUnsigned then reg .& uMask
  else
    if regSize = 64 then reg
    else
      let mBit = AST.extract reg 1<rt> (regSize - 1)
      let sMask = ~~~ ((1L <<< regSize) - 1L)
      AST.ite mBit (reg .| numI64 sMask oprSz) (reg .& uMask)

/// aarch64/instrs/extendreg/ExtendReg
/// ExtendReg()
/// ===========
/// Perform a register extension and shift
let extendReg bld reg typ shift oprSize =
  let shift =
    match shift with
    | Some shf -> shf |> int
    | None -> 0L |> int
  let isUnsigned, len =
    match typ with
    | ExtSXTB -> false, 8
    | ExtSXTH -> false, 16
    | ExtSXTW -> false, 32
    | ExtSXTX -> false, 64
    | ExtUXTB -> true, 8
    | ExtUXTH -> true, 16
    | ExtUXTW -> true, 32
    | ExtUXTX -> true, 64
  let reg = regVar bld reg |> AST.zext oprSize
  let len = min len ((RegType.toBitWidth oprSize) - shift)
  extend (reg << numI32 shift oprSize) oprSize (len + shift) isUnsigned

let getElemDataSzAndElemsByVector = function
  (* Vector register names with element index *)
  | VecB -> struct (8<rt>, 8<rt>, 1)
  | VecH -> struct (16<rt>, 16<rt>, 1)
  | VecS -> struct (32<rt>, 32<rt>, 1)
  | VecD -> struct (64<rt>, 64<rt>, 1)
  (* SIMD vector register names *)
  | EightB -> struct (8<rt>, 64<rt>, 8)
  | SixteenB -> struct (8<rt>, 128<rt>, 16)
  | FourH -> struct (16<rt>, 64<rt>, 4)
  | EightH -> struct (16<rt>, 128<rt>, 8)
  | TwoS -> struct (32<rt>, 64<rt>, 2)
  | FourS -> struct (32<rt>, 128<rt>, 4)
  | OneD -> struct (64<rt>, 64<rt>, 1)
  | TwoD -> struct (64<rt>, 128<rt>, 2)
  | OneQ -> struct (128<rt>, 128<rt>, 1)

/// esize, datasize, elements
let rec getElemDataSzAndElems = function
  | OprSIMD (SIMDFPScalarReg v) ->
    struct (Register.toRegType v, Register.toRegType v, 1)
  | OprSIMD (SIMDVecReg (_, v)) -> getElemDataSzAndElemsByVector v
  | OprSIMD (SIMDVecRegWithIdx (_, v, _)) -> getElemDataSzAndElemsByVector v
  | OprSIMDList simds -> getElemDataSzAndElems (OprSIMD simds[0])
  | _ -> raise InvalidOperandException

let transSIMDOprVPart bld eSize part = function
  | OprSIMD (SIMDVecReg (reg, _)) ->
    let pos = int eSize
    let elems = 64<rt> / eSize
    if part = 128<rt> then
      let regB = pseudoRegVar bld reg 2
      Array.init elems (fun i -> AST.extract regB eSize (i * pos))
    else
      let regA = pseudoRegVar bld reg 1
      Array.init elems (fun i -> AST.extract regA eSize (i * pos))
  | _ -> raise InvalidOperandException

let transSIMDReg bld = function (* FIXME *)
  | SIMDVecRegWithIdx (reg, v, idx) ->
    let struct (regB, regA) = pseudoRegVar128 bld reg
    let struct (esize, _, _) = getElemDataSzAndElemsByVector v
    let index = int idx * int esize
    if index < 64 then [| AST.extract regA esize index |]
    else [| AST.extract regB esize (index % 64) |]
  | SIMDVecReg (reg, v) ->
    let struct (eSize, dataSize, elements) = getElemDataSzAndElemsByVector v
    getPseudoRegVarToArr bld reg eSize dataSize elements
  | _ (* SIMDFPScalarReg *) -> raise InvalidOperandException

let transSIMDListToExpr bld = function (* FIXME *)
  | OprSIMDList simds -> Array.map (transSIMDReg bld) (List.toArray simds)
  | _ -> raise InvalidOperandException

let transSIMD bld = function (* FIXME *)
  | SIMDFPScalarReg reg -> regVar bld reg
  | SIMDVecReg _ -> raise InvalidOperandException
  | SIMDVecRegWithIdx (reg, v, idx) ->
    let struct (regB, regA) = pseudoRegVar128 bld reg
    let struct (esize, _, _) = getElemDataSzAndElemsByVector v
    let index = int idx * int esize
    if index < 64 then AST.extract regA esize index
    else AST.extract regB esize (index % 64)

let transImmOffset bld = function
  | BaseOffset (bReg, Some imm) ->
    regVar bld bReg .+ numI64 imm 64<rt> |> AST.loadLE 64<rt>
  | BaseOffset (bReg, None) -> regVar bld bReg |> AST.loadLE 64<rt>
  | Lbl lbl -> numI64 lbl 64<rt>

let transRegOff (ins: Instruction) bld reg = function
  | ShiftOffset (shfTyp, amt) ->
    let reg = regVar bld reg
    let amount = transShiftAmout bld 64<rt> amt
    shiftReg reg amount ins.OprSize shfTyp
  | ExtRegOffset (extTyp, shf) -> extendReg bld reg extTyp shf 64<rt>

let transRegOffset ins bld = function
  | bReg, reg, Some regOffset ->
    regVar bld bReg .+ transRegOff ins bld reg regOffset
  | bReg, reg, None -> regVar bld bReg .+ regVar bld reg

let transMemOffset ins bld = function
  | ImmOffset immOffset -> transImmOffset bld immOffset
  | RegOffset (bReg, reg, regOffset) ->
    transRegOffset ins bld (bReg, reg, regOffset) |> AST.loadLE 64<rt>

let transBaseMode ins bld offset =
  transMemOffset ins bld offset

let transMem ins bld _addr = function
  | BaseMode offset -> transBaseMode ins bld offset
  | PreIdxMode offset -> transBaseMode ins bld offset
  | PostIdxMode offset -> transBaseMode ins bld offset
  | LiteralMode offset -> transBaseMode ins bld offset

let transOprToExpr ins bld addr = function
  | OprRegister reg -> regVar bld reg
  | OprMemory mem -> transMem ins bld addr mem
  | OprSIMD reg -> transSIMD bld reg
  | OprImm imm -> numI64 imm ins.OprSize
  | OprNZCV nzcv -> numI64 (int64 nzcv) ins.OprSize
  | OprLSB lsb -> numI64 (int64 lsb) ins.OprSize
  | OprFbits fbits -> numI64 (int64 fbits) ins.OprSize
  | OprFPImm float ->
    if ins.OprSize = 64<rt> then
      numI64 (BitConverter.DoubleToInt64Bits float) ins.OprSize
    else numI64 (BitConverter.SingleToInt32Bits (float32 float)) ins.OprSize
  | _ -> raise <| NotImplementedIRException "transOprToExpr"

let transOprToExprFPImm (ins: Instruction) eSize src =
  match eSize, src with
  | 32<rt>, OprFPImm float ->
    numI64 (BitConverter.SingleToInt32Bits (float32 float)) ins.OprSize
  | 64<rt>, OprFPImm float ->
    numI64 (BitConverter.DoubleToInt64Bits float) ins.OprSize
  | _ -> raise InvalidOperandException

let separateMemExpr expr =
  match expr with
  | Load (_, _, BinOp (BinOpType.ADD, _, b, o, _), _) -> b, o
  | Load (_, _, e, _) -> e, AST.num0 64<rt>
  | _ -> raise InvalidOperandException

let transOneOpr (ins: Instruction) bld addr =
  match ins.Operands with
  | OneOperand o -> transOprToExpr ins bld addr o
  | _ -> raise InvalidOperandException

let transTwoOprs (ins: Instruction) bld addr =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    transOprToExpr ins bld addr o1,
    transOprToExpr ins bld addr o2
  | _ -> raise InvalidOperandException

let transTwoOprsSepMem (ins: Instruction) bld addr =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    transOprToExpr ins bld addr o1,
    transOprToExpr ins bld addr o2 |> separateMemExpr
  | _ -> raise InvalidOperandException

let transThreeOprs (ins: Instruction) bld addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    transOprToExpr ins bld addr o1,
    transOprToExpr ins bld addr o2,
    transOprToExpr ins bld addr o3
  | _ -> raise InvalidOperandException

let transThreeOprsSepMem (ins: Instruction) bld addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    transOprToExpr ins bld addr o1,
    transOprToExpr ins bld addr o2,
    transOprToExpr ins bld addr o3 |> separateMemExpr
  | _ -> raise InvalidOperandException

let transFourOprs (ins: Instruction) bld addr =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    transOprToExpr ins bld addr o1,
    transOprToExpr ins bld addr o2,
    transOprToExpr ins bld addr o3,
    transOprToExpr ins bld addr o4
  | _ -> raise InvalidOperandException

let transFourOprsSepMem (ins: Instruction) bld addr =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    transOprToExpr ins bld addr o1,
    transOprToExpr ins bld addr o2,
    transOprToExpr ins bld addr o3,
    transOprToExpr ins bld addr o4 |> separateMemExpr
  | _ -> raise InvalidOperandException

let transOprToExpr128 ins bld addr = function
  | OprSIMD (SIMDFPScalarReg reg) -> pseudoRegVar128 bld reg
  | OprSIMD (SIMDVecReg (reg, _)) -> pseudoRegVar128 bld reg
  | OprSIMD (SIMDVecRegWithIdx (reg, _, _)) -> pseudoRegVar128 bld reg
  | OprMemory mem -> transMem ins bld addr mem |> getMemExpr128
  | _ -> raise InvalidOperandException

let transSIMDOprToExpr bld eSize dataSize elements = function
  | OprSIMD (SIMDFPScalarReg reg) ->
    if dataSize = 128<rt> then
      let struct (regB, regA) = pseudoRegVar128 bld reg
      [| regB; regA |]
    else [| regVar bld reg |]
  | OprSIMD (SIMDVecReg (reg, _)) ->
    getPseudoRegVarToArr bld reg eSize dataSize elements
  | OprSIMD (SIMDVecRegWithIdx _) -> raise InvalidOperandException
  | _ -> raise InvalidOperandException

(* Barrel shift *)
let transBarrelShiftToExpr oprSize bld src shift =
  match src, shift with
  | OprImm imm, OprShift (typ, Imm amt) ->
    let imm =
      match typ with
      | SRTypeLSL -> imm <<< int32 amt
      | SRTypeLSR -> imm >>> int32 amt
      | SRTypeMSL -> (imm <<< int32 amt) + (1L <<< int32 amt) - 1L
      | _ -> failwith "Not implement"
    numI64 imm oprSize
  | OprRegister reg, OprShift (typ, amt) ->
    let reg = regVar bld reg
    let amount = transShiftAmout bld oprSize amt
    shiftReg reg amount oprSize typ
  | OprRegister reg, OprExtReg (Some (ShiftOffset (typ, amt))) ->
    let reg = regVar bld reg
    let amount = transShiftAmout bld oprSize amt
    shiftReg reg amount oprSize typ
  | OprRegister reg, OprExtReg (Some (ExtRegOffset (typ, shf))) ->
    extendReg bld reg typ shf oprSize
  | OprRegister reg, OprExtReg None -> regVar bld reg
  | _ -> raise <| NotImplementedIRException "transBarrelShiftToExpr"

let transThreeOprsWithBarrelShift (ins: Instruction) bld addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    transOprToExpr ins bld addr o1,
    transBarrelShiftToExpr ins.OprSize bld o2 o3
  | _ -> raise InvalidOperandException

let transFourOprsWithBarrelShift (ins: Instruction) bld addr =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    transOprToExpr ins bld addr o1,
    transOprToExpr ins bld addr o2,
    transBarrelShiftToExpr ins.OprSize bld o3 o4
  | _ -> raise InvalidOperandException

let isRegOffset opr =
  match opr with
  | OprMemory (BaseMode (RegOffset _)) | OprMemory (PreIdxMode (RegOffset _))
  | OprMemory (PostIdxMode (RegOffset _))
  | OprMemory (LiteralMode (RegOffset _)) -> true
  | _ -> false

let isSIMDScalar opr =
  match opr with
  | OprSIMD (SIMDFPScalarReg _) -> true
  | _ -> false

let isSIMDVector opr =
  match opr with
  | OprSIMD (SIMDVecReg _) -> true
  | _ -> false

let isSIMDVectorIdx opr =
  match opr with
  | OprSIMD (SIMDVecRegWithIdx _) -> true
  | _ -> false

let transOprToExprOfAND (ins: Instruction) bld addr =
  match ins.Operands with
  | ThreeOperands _ -> transThreeOprs ins bld addr
  | FourOperands _ -> transFourOprsWithBarrelShift ins bld addr
  | _ -> raise InvalidOperandException

let unwrapCond = function
  | OprCond cond -> cond
  | _ -> raise InvalidOperandException

let invertCond = function
  | EQ -> NE
  | NE -> EQ
  | CS | HS -> CC
  | CC | LO -> CS
  | MI -> PL
  | PL -> MI
  | VS -> VC
  | VC -> VS
  | HI -> LS
  | LS -> HI
  | GE -> LT
  | LT -> GE
  | GT -> LE
  | LE -> GT
  | AL -> NV
  | NV -> AL

let transOprToExprOfCCMN (ins: Instruction) bld addr =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    transOprToExpr ins bld addr o1,
    transOprToExpr ins bld addr o2,
    transOprToExpr ins bld addr o3,
    o4 |> unwrapCond
  | _ -> raise InvalidOperandException

let transOprToExprOfCCMP (ins: Instruction) bld addr =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    transOprToExpr ins bld addr o1,
    transOprToExpr ins bld addr o2,
    transOprToExpr ins bld addr o3,
    o4 |> unwrapCond
  | _ -> raise InvalidOperandException

let transOprToExprOfCMP (ins: Instruction) bld addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    transOprToExpr ins bld addr o1,
    transBarrelShiftToExpr ins.OprSize bld o2 o3
  | _ -> raise InvalidOperandException

let transOprToExprOfCSEL (ins: Instruction) bld addr =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    transOprToExpr ins bld addr o1,
    transOprToExpr ins bld addr o2,
    transOprToExpr ins bld addr o3,
    o4 |> unwrapCond
  | _ -> raise InvalidOperandException

let transOprToExprOfFCSEL (ins: Instruction) bld addr =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    o1,
    transOprToExpr ins bld addr o2,
    transOprToExpr ins bld addr o3,
    o4 |> unwrapCond
  | _ -> raise InvalidOperandException

let transOprToExprOfCSINC (ins: Instruction) bld addr =
  match ins.Operands with
  | TwoOperands (o1, o2) -> (* CSET *)
    transOprToExpr ins bld addr o1,
    regVar bld (if ins.OprSize = 64<rt> then R.XZR else R.WZR),
    regVar bld (if ins.OprSize = 64<rt> then R.XZR else R.WZR),
    o2 |> unwrapCond |> invertCond
  | ThreeOperands (o1, o2, o3) -> (* CINC *)
    transOprToExpr ins bld addr o1,
    transOprToExpr ins bld addr o2,
    transOprToExpr ins bld addr o2,
    o3 |> unwrapCond |> invertCond
  | FourOperands (o1, o2, o3, o4) ->
    transOprToExpr ins bld addr o1,
    transOprToExpr ins bld addr o2,
    transOprToExpr ins bld addr o3,
    o4 |> unwrapCond
  | _ -> raise InvalidOperandException

let transOprToExprOfCSINV (ins: Instruction) bld addr =
  match ins.Operands with
  | TwoOperands (o1, o2) -> (* CSETM *)
    transOprToExpr ins bld addr o1,
    regVar bld (if ins.OprSize = 64<rt> then R.XZR else R.WZR),
    regVar bld (if ins.OprSize = 64<rt> then R.XZR else R.WZR),
    o2 |> unwrapCond |> invertCond
  | ThreeOperands (o1, o2, o3) -> (* CINV *)
    let o2 = transOprToExpr ins bld addr o2
    transOprToExpr ins bld addr o1, o2, o2,
    o3 |> unwrapCond |> invertCond
  | FourOperands (o1, o2, o3, o4) -> (* CSINV *)
    transOprToExpr ins bld addr o1,
    transOprToExpr ins bld addr o2,
    transOprToExpr ins bld addr o3,
    o4 |> unwrapCond
  | _ -> raise InvalidOperandException

let transOprToExprOfCSNEG (ins: Instruction) bld addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, OprCond o3) -> (* CNEG *)
    let o2 = transOprToExpr ins bld addr o2
    transOprToExpr ins bld addr o1, o2, o2, invertCond o3
  | FourOperands (o1, o2, o3, o4) -> (* CSNEG *)
    transOprToExpr ins bld addr o1,
    transOprToExpr ins bld addr o2,
    transOprToExpr ins bld addr o3,
    o4|> unwrapCond
  | _ -> raise InvalidOperandException

let transOprToExprOfEOR (ins: Instruction) bld addr =
  match ins.Operands with
  | ThreeOperands _ -> transThreeOprs ins bld addr
  | FourOperands (o1, o2, o3, o4) when ins.Opcode = Opcode.EOR ->
    transOprToExpr ins bld addr o1,
    transOprToExpr ins bld addr o2,
    transBarrelShiftToExpr ins.OprSize bld o3 o4
  | FourOperands (o1, o2, o3, o4) when ins.Opcode = Opcode.EON ->
    transOprToExpr ins bld addr o1,
    transOprToExpr ins bld addr o2,
    transBarrelShiftToExpr ins.OprSize bld o3 o4 |> AST.not
  | _ -> raise InvalidOperandException

let transOprToExprOfEXTR (ins: Instruction) bld addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> (* ROR *)
    let o2 = transOprToExpr ins bld addr o2
    transOprToExpr ins bld addr o1, o2, o2, transOprToExpr ins bld addr o3
  | FourOperands _ -> transFourOprs ins bld addr
  | _ -> raise InvalidOperandException

let getIsWBackAndIsPostIndexByAddrMode = function
  | BaseMode _ -> false, false
  | PreIdxMode _ -> true, false
  | PostIdxMode _ -> true, true
  | _ -> raise InvalidOperandException

let getIsWBackAndIsPostIndex = function
  | TwoOperands (_, OprMemory mem) -> getIsWBackAndIsPostIndexByAddrMode mem
  | ThreeOperands (_, _, OprMemory mem) ->
    getIsWBackAndIsPostIndexByAddrMode mem
  | _ -> raise InvalidOperandException

let transOprToExprOfMADD (ins: Instruction) bld addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> (* MUL *)
    transOprToExpr ins bld addr o1,
    transOprToExpr ins bld addr o2,
    transOprToExpr ins bld addr o3,
    regVar bld (if ins.OprSize = 64<rt> then R.XZR else R.WZR)
  | FourOperands _ -> transFourOprs ins bld addr
  | _ -> raise InvalidOperandException

let transOprToExprOfORN (ins: Instruction) bld addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) when ins.Opcode = Opcode.MVN -> (* MVN *)
    transOprToExpr ins bld addr o1,
    regVar bld (if ins.OprSize = 64<rt> then R.XZR else R.WZR),
    transBarrelShiftToExpr ins.OprSize bld o2 o3
  | FourOperands (o1, o2, o3, o4) when ins.Opcode = Opcode.ORN -> (* ORN *)
    transOprToExpr ins bld addr o1,
    transOprToExpr ins bld addr o2,
    transBarrelShiftToExpr ins.OprSize bld o3 o4
  | _ -> raise InvalidOperandException

let transOprToExprOfORR (ins: Instruction) bld addr =
  match ins.Operands with
  | ThreeOperands _ -> transThreeOprs ins bld addr
  | FourOperands (o1, o2, o3, o4) ->
    transOprToExpr ins bld addr o1,
    transOprToExpr ins bld addr o2,
    transBarrelShiftToExpr ins.OprSize bld o3 o4
  | _ -> raise InvalidOperandException

let unwrapReg e =
  match e with
  | Extract (e, 32<rt>, 0, _) -> e
  | _ -> failwith "Invalid register"

let transOprToExprOfSMSUBL (ins: Instruction) bld addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    transOprToExpr ins bld addr o1,
    transOprToExpr ins bld addr o2,
    transOprToExpr ins bld addr o3,
    regVar bld R.XZR
  | FourOperands _ -> transFourOprs ins bld addr
  | _ -> raise InvalidOperandException

let transOprToExprOfSUB (ins: Instruction) bld addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3)
    when ins.Opcode = Opcode.NEG ->
    transOprToExpr ins bld addr o1,
    regVar bld (if ins.OprSize = 64<rt> then R.XZR else R.WZR),
    transBarrelShiftToExpr ins.OprSize bld o2 o3 |> AST.not
  | FourOperands (o1, o2, o3, o4) -> (* Arithmetic *)
    transOprToExpr ins bld addr o1,
    transOprToExpr ins bld addr o2,
    transBarrelShiftToExpr ins.OprSize bld o3 o4 |> AST.not
  | _ -> raise InvalidOperandException

let transOprToExprOfMSUB (ins: Instruction) bld addr =
  let oprSize = ins.OprSize
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> (* MNEG *)
    transOprToExpr ins bld addr o1,
    transOprToExpr ins bld addr o2,
    transOprToExpr ins bld addr o3,
    regVar bld (if ins.OprSize = 64<rt> then R.XZR else R.WZR)
  | FourOperands _ -> transFourOprs ins bld addr (* MSUB *)
  | _ -> raise InvalidOperandException

let transOprToExprOfUMADDL (ins: Instruction) bld addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> (* UMULL / UMNEGL *)
    transOprToExpr ins bld addr o1,
    transOprToExpr ins bld addr o2,
    transOprToExpr ins bld addr o3,
    regVar bld R.XZR
  | FourOperands _ -> transFourOprs ins bld addr
  | _ -> raise InvalidOperandException

let transOprToExprOfSUBS (ins: Instruction) bld addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    transOprToExpr ins bld addr o1,
    regVar bld (if ins.OprSize = 64<rt> then R.XZR else R.WZR),
    transBarrelShiftToExpr ins.OprSize bld o2 o3 |> AST.not
  | FourOperands (o1, o2, o3, o4) ->
    transOprToExpr ins bld addr o1,
    transOprToExpr ins bld addr o2,
    transBarrelShiftToExpr ins.OprSize bld o3 o4 |> AST.not
  | _ -> raise InvalidOperandException

let transOprToExprOfTST (ins: Instruction) bld addr =
  match ins.Operands with
  | TwoOperands (o1, o2) (* immediate *) ->
    transOprToExpr ins bld addr o1, transOprToExpr ins bld addr o2
  | ThreeOperands (o1, o2, o3) (* shfed *) ->
    transOprToExpr ins bld addr o1,
    transBarrelShiftToExpr ins.OprSize bld o2 o3
  | _ -> raise InvalidOperandException

type BranchType =
  | BrTypeCALL
  | BrTypeERET
  | BrTypeDBGEXIT
  | BrTypeRET
  | BrTypeJMP
  | BrTypeEXCEPTION
  | BrTypeUNKNOWN

/// shared/functions/registers/BranchTo
/// BranchTo()
/// ==========
/// Set program counter to a new address, which may include a tag in the top
/// eight bits, with a branch reason hint for possible use by hardware fetching
/// the next instruction.
let branchTo ins bld target brType i =
  bld <+ (AST.interjmp target i) // FIXME: BranchAddr function

/// shared/functions/system/ConditionHolds
/// ConditionHolds()
/// ================
/// Return TRUE iff COND currently holds
let conditionHolds bld = function
  | EQ -> regVar bld R.Z == AST.b1
  | NE -> regVar bld R.Z == AST.b0
  | CS -> regVar bld R.C == AST.b1
  | CC -> regVar bld R.C == AST.b0
  | MI -> regVar bld R.N == AST.b1
  | PL -> regVar bld R.N == AST.b0
  | VS -> regVar bld R.V == AST.b1
  | VC -> regVar bld R.V == AST.b0
  | HI -> (regVar bld R.C == AST.b1) .& (regVar bld R.Z == AST.b0)
  | LS -> AST.not ((regVar bld R.C == AST.b1) .&
                  (regVar bld R.Z == AST.b0))
  | GE -> regVar bld R.N == regVar bld R.V
  | LT -> regVar bld R.N != regVar bld R.V
  | GT -> (regVar bld R.N == regVar bld R.V) .&
          (regVar bld R.Z == AST.b0)
  | LE -> AST.not ((regVar bld R.N == regVar bld R.V) .&
                  (regVar bld R.Z == AST.b0))
  (* Condition flag values in the set '111x' indicate always true *)
  | AL | NV -> AST.b1
  | _ -> failwith "Invalid condition"

/// shared/functions/common/HighestSetBit
/// HighestSetBit()
/// ===============
let highestSetBitForIR expr width oprSz bld =
  let struct (highest, n1) = tmpVars2 bld oprSz
  bld <+ (highest := numI32 -1 oprSz)
  bld <+ (n1 := AST.num1 oprSz)
  let inline pos i =
    let elem = tmpVar bld oprSz
    let bit = AST.extract expr 1<rt> i |> AST.zext oprSz
    bld <+ (elem := (bit .* ((numI32 i oprSz) .+ n1)) .- n1)
    elem
  Array.init width pos
  |> Array.iter (fun e -> bld <+ (highest := AST.ite (highest ?<= e) e highest))
  highest

let highestSetBit x size =
  let rec loop i =
    if i < 0 then -1
    elif (x >>> i) &&& 1 = 1 then i
    else loop (i - 1)
  loop (size - 1)

/// shared/functions/common/Replicate
/// Replicate()
/// ===========
let replicateForIR expr exprSize repSize bld =
  let repeat = repSize / exprSize
  let repVal = tmpVar bld repSize
  bld <+ (repVal := AST.zext repSize expr)
  Array.init repeat (fun i -> repVal << numI32 (int exprSize * i) repSize)
  |> Array.reduce (.|)

let replicate x eSize dstSize =
  let rec loop x i = if i = 1 then x else loop (x <<< eSize ||| x) (i - 1)
  loop x (dstSize / eSize)

let advSIMDExpandImm bld eSize src =
  let src = AST.xtlo 64<rt> src
  replicateForIR src eSize 64<rt> bld

let getIntMax eSize isUnsigned =
  let shfAmt = int eSize - 1
  let signBit = AST.num1 eSize << numI64 shfAmt eSize
  let maskBit = signBit .- AST.num1 eSize
  if isUnsigned then signBit .| maskBit else maskBit

/// aarch64/instrs/integer/bitmasks/DecodeBitMasks
/// DecodeBitMasks()
/// ================
/// Decode AArch64 bitfield and logical immediate masks which use a similar
/// encoding structure
let decodeBitMasks immr imms dataSize =
  let immN = dataSize / 64
  let immr = getImmValue immr |> int
  let imms = getImmValue imms |> int
  let immNNot = immN <<< 6 ||| (~~~ imms &&& 0x3F)
  let len = highestSetBit immNNot 7
  assert (len > 0)
  assert (int dataSize >= (1 <<< len))
  let levels = (1 <<< len) - 1
  (* if immediate && (imms AND levels) == levels then UNDEFINED; *)
  let s = imms &&& levels
  let r = immr &&& levels
  let diff = s - r
  let eSize = 1 <<< len
  let d = diff &&& levels
  let welem = if (s + 1) = 64 then -1L else (1L <<< (s + 1)) - 1L
  let telem = if (d + 1) = 64 then -1L else (1L <<< (d + 1)) - 1L
  let wmask = replicate (ror welem r dataSize) eSize dataSize
  let tmask = replicate telem eSize dataSize
  struct (wmask, tmask)

/// shared/functions/crc/BitReverse
/// BitReverse()
/// ============
let bitReverse expr oprSz =
  let rev i =
    let bit = AST.zext oprSz (AST.extract expr 1<rt> i)
    bit << (numI32 (int oprSz - 1 - i) oprSz)
  Array.init (int oprSz) rev |> Array.reduce (.+)

/// shared/functions/common/CountLeadingZeroBits
/// CountLeadingZeroBits()
/// ======================
let countLeadingZeroBitsForIR src bitSize oprSize bld =
  let res = highestSetBitForIR src bitSize oprSize bld
  (numI32 bitSize oprSize) .- (res .+ AST.num1 oprSize)

/// shared/functions/common/CountLeadingSignBits
/// CountLeadingSignBits()
/// ======================
let countLeadingSignBitsForIR expr oprSize bld =
  let n1 = AST.num1 oprSize
  let struct (expr1, expr2, xExpr) = tmpVars3 bld oprSize
  bld <+ (expr1 := expr >> n1)
  bld <+ (expr2 := (expr << n1) >> n1)
  bld <+ (xExpr := (expr1 <+> expr2))
  /// This count does not include the most significant bit of the source
  /// register.
  let bitSize = int oprSize - 1
  countLeadingZeroBitsForIR xExpr bitSize oprSize bld

/// shared/functions/vector/UnsignedSatQ
/// UnsignedSatQ()
/// ==============
let unsignedSatQ bld i n =
  let struct (max, min) = tmpVars2 bld n
  let struct (overflow, underflow) = tmpVars2 bld 1<rt>
  let bitQC = AST.extract (regVar bld R.FPSR) 1<rt> 27
  bld <+ (max := getIntMax n true)
  bld <+ (min := AST.num0 n)
  bld <+ (overflow := i ?> AST.zext (2 * n) max)
  bld <+ (underflow := i ?< AST.zext (2 * n) min)
  bld <+ (bitQC := bitQC .| overflow .| underflow)
  AST.ite overflow max (AST.ite underflow min (AST.xtlo n i))

/// shared/functions/vector/SignedSatQ
/// SignedSatQ()
/// ============
let signedSatQ bld i n =
  let struct (max, min) = tmpVars2 bld n
  let struct (overflow, underflow) = tmpVars2 bld 1<rt>
  let bitQC = AST.extract (regVar bld R.FPSR) 1<rt> 27
  bld <+ (max := getIntMax n false)
  bld <+ (min := AST.not max)
  bld <+ (overflow := i ?> AST.sext (2 * n) max)
  bld <+ (underflow := i ?< AST.sext (2 * n) min)
  bld <+ (bitQC := bitQC .| overflow .| underflow)
  AST.ite overflow max (AST.ite underflow min (AST.xtlo n i))

/// shared/functions/vector/SatQ
/// SatQ()
/// ======
let satQ bld i n isUnsigned =
  if isUnsigned then unsignedSatQ bld i n else signedSatQ bld i n

/// Exception
let isNaN oprSize expr =
  match oprSize with
  | 32<rt> -> IEEE754Single.isNaN expr
  | 64<rt> -> IEEE754Double.isNaN expr
  | _ -> Terminator.impossible ()

let isSNaN oprSize expr =
  match oprSize with
  | 32<rt> -> IEEE754Single.isSNaN expr
  | 64<rt> -> IEEE754Double.isSNaN expr
  | _ -> Terminator.impossible ()

let isQNaN oprSize expr =
  match oprSize with
  | 32<rt> -> IEEE754Single.isQNaN expr
  | 64<rt> -> IEEE754Double.isQNaN expr
  | _ -> Terminator.impossible ()

let isInfinity oprSize expr =
  match oprSize with
  | 32<rt> -> IEEE754Single.isInfinity expr
  | 64<rt> -> IEEE754Double.isInfinity expr
  | _ -> Terminator.impossible ()

let isZero oprSize expr =
  match oprSize with
  | 32<rt> -> IEEE754Single.isZero expr
  | 64<rt> -> IEEE754Double.isZero expr
  | _ -> Terminator.impossible ()

/// shared/functions/float/fproundingmode/FPRoundingMode
/// FPRoundingMode()
let fpRoundingMode src oprSz bld =
  let fpcr = regVar bld R.FPCR |> AST.xtlo 32<rt>
  let rm = tmpVar bld 32<rt>
  let struct (rm1, rm0) = tmpVars2 bld 1<rt>
  let res = tmpVar bld oprSz
  bld <+ (rm := (fpcr >> (numI32 22 32<rt>)) .& (numI32 0b11 32<rt>))
  bld <+ (rm0 := AST.xtlo 1<rt> rm) (* rm[0] *)
  bld <+ (rm1 := rm >> (AST.num1 32<rt>) |> AST.xtlo 1<rt>) (* rm[1] *)
  let cast kind = AST.cast kind oprSz src
  let lblRNRP = label bld "RNorRP"
  let lblRMRZ = label bld "RMorRZ"
  let lblEnd = label bld "End"
  bld <+ (AST.cjmp rm1 (AST.jmpDest lblRMRZ) (AST.jmpDest lblRNRP))
  bld <+ (AST.lmark lblRMRZ)
  bld <+ (res := AST.ite rm0
                         (cast CastKind.FtoFTrunc) (cast CastKind.FtoFFloor))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblRNRP)
  bld <+ (res := AST.ite rm0 (cast CastKind.FtoFCeil) (cast CastKind.FtoFRound))
  bld <+ (AST.lmark lblEnd)
  res

/// shared/functions/float/fproundingmode/FPRoundingMode
/// FtoI
let fpRoundingToInt src oprSz bld =
  let fpcr = regVar bld R.FPCR |> AST.xtlo 32<rt>
  let rm = AST.shr (AST.shl fpcr (numI32 8 32<rt>)) (numI32 0x1E 32<rt>)
  AST.ite (rm == numI32 0 32<rt>)
    (AST.cast CastKind.FtoIRound oprSz src) // 0 RN
    (AST.ite (rm == numI32 1 32<rt>)
      (AST.cast CastKind.FtoICeil oprSz src) // 1 RP
      (AST.ite (rm == numI32 2 32<rt>)
        (AST.cast CastKind.FtoIFloor oprSz src) // 2 RMP
        (AST.ite (rm == numI32 3 32<rt>)
          (AST.cast CastKind.FtoITrunc oprSz src) // 3 RZ
          src)))

/// shared/functions/float/fpdefaultnan/FPDefaultNan
/// FPDefaultNan()
let fpDefaultNan fbit =
  match fbit with
  | 64<rt> -> numU64 0x7ff8000000000000UL 64<rt>
  | 32<rt> -> numU64 0x7fc00000UL 32<rt>
  | 16<rt> -> numU64 0x7e00UL 16<rt>
  | _ -> raise InvalidOperandException

/// shared/functions/float/fpinfinity/FPInfinity
/// FPInfinity()
let fpDefaultInfinity src fbit =
  match fbit with
  | 64<rt> ->
    let signbit = src .& numU64 0x8000000000000000UL 64<rt>
    signbit .| (numU64 0x7ff0000000000000UL 64<rt>)
  | 32<rt> ->
    let signbit = src .& numU64 0x80000000UL 32<rt>
    signbit .| numU64 0x7f800000UL 32<rt>
  | 16<rt> ->
    let signbit = src .& numU64 0x8000UL 16<rt>
    signbit .| numU64 0x7c00UL 16<rt>
  | _ -> raise InvalidOperandException

let fpInfinity sign dataSize =
  match dataSize with
  | 64<rt> ->
    let signbit =
      AST.ite sign (numU64 0x8000000000000000UL 64<rt>) (AST.num0 64<rt>)
    signbit .| (numU64 0x7ff0000000000000UL 64<rt>)
  | 32<rt> ->
    let signbit = AST.ite sign (numU64 0x80000000UL 32<rt>) (AST.num0 32<rt>)
    signbit .| numU64 0x7f800000UL 32<rt>
  | 16<rt> ->
    let signbit = AST.ite sign (numU64 0x8000UL 16<rt>) (AST.num0 16<rt>)
    signbit .| numU64 0x7c00UL 16<rt>
  | _ -> raise InvalidOperandException

/// shared/functions/float/fpzero/FPZero
/// FPZero()
let fpZero src fbit =
  match fbit with
  | 64<rt> -> src .& numU64 0x8000000000000000UL 64<rt>
  | 32<rt> -> src .& numU64 0x80000000UL 32<rt>
  | 16<rt> -> src .& numU64 0x8000UL 16<rt>
  | _ -> raise InvalidOperandException

let fpMinMax src fbit =
  let sign = AST.xthi 1<rt> src
  match fbit with
  | 64<rt> ->
    let max = numU64 0x7fffffffffffffffUL 64<rt>
    let min = numU64 0x8000000000000001UL 64<rt>
    AST.ite sign min max
  | 32<rt> ->
    let max = numU64 0x7fffffffUL 32<rt>
    let min = numU64 0x80000001UL 32<rt>
    AST.ite sign min max
  | 16<rt> ->
    let max = numU64 0x7fffUL 16<rt>
    let min = numU64 0x8001UL 16<rt>
    AST.ite sign min max
  | _ -> raise InvalidOperandException

/// shared/functions/float/fpprocessnan/FPProcessNaN
/// FPProcessNaN()
let fpProcessNan bld eSize element =
  let struct (res, tf) = tmpVars2 bld eSize
  let fpcr = regVar bld R.FPCR
  let dnBit = AST.extract fpcr 1<rt> 25
  let topfrac =
    match eSize with
    | 64<rt> -> numU64 0x8000000000000UL 64<rt>
    | 32<rt> -> numU64 0x400000UL 32<rt>
    | 16<rt> -> numU64 0x200UL 16<rt>
    | _ -> raise InvalidOperandException
  bld <+ (tf := AST.ite (isSNaN eSize element) (element .| topfrac) element)
  bld <+ (res := AST.ite dnBit (fpDefaultNan eSize) tf)
  res

let fpProcessNaNs bld dataSize e1 e2 =
  let struct (isSNaN1, isSNaN2, isQNaN1, isQNaN2) = tmpVars4 bld 1<rt>
  let isNaN = tmpVar bld 1<rt>
  let resNaN = tmpVar bld dataSize
  bld <+ (isSNaN1 := isSNaN dataSize e1)
  bld <+ (isSNaN2 := isSNaN dataSize e2)
  bld <+ (isQNaN1 := isQNaN dataSize e1)
  bld <+ (isQNaN2 := isQNaN dataSize e2)
  bld <+ (isNaN := isSNaN1 .| isSNaN2 .| isQNaN1 .| isQNaN2)
  let fpNaN expr = fpProcessNan bld dataSize expr
  let lblSFT = label bld "isSFT" (* SNaN1 Fall Through *)
  let lblQNaN = label bld "isQNaN"
  let lblSNaN1 = label bld "isSNaN1"
  let lblSNaN2 = label bld "isSNaN2"
  let lblQNaN1 = label bld "isQNaN1"
  let lblQNaN2 = label bld "isQNaN2"
  let lblEnd = label bld "End"
  bld <+ (AST.cjmp isSNaN1 (AST.jmpDest lblSNaN1) (AST.jmpDest lblSFT))
  bld <+ (AST.lmark lblSNaN1)
  bld <+ (resNaN := fpNaN e1)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblSFT)
  bld <+ (AST.cjmp isSNaN2 (AST.jmpDest lblSNaN2) (AST.jmpDest lblQNaN))
  bld <+ (AST.lmark lblSNaN2)
  bld <+ (resNaN := fpNaN e2)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblQNaN)
  bld <+ (AST.cjmp isQNaN1 (AST.jmpDest lblQNaN1) (AST.jmpDest lblQNaN2))
  bld <+ (AST.lmark lblQNaN1)
  bld <+ (resNaN := fpNaN e1)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblQNaN2)
  bld <+ (resNaN := AST.ite isQNaN2 (fpNaN e2) (AST.num0 dataSize))
  bld <+ (AST.lmark lblEnd)
  struct (isNaN, resNaN)

/// shared/functions/float/fpadd/FPAdd
/// FPAdd()
let fpAdd bld dSz src1 src2 =
  let struct (isZero1, isInf1, isZero2, isInf2) = tmpVars4 bld 1<rt>
  let struct (sign1, sign2) = tmpVars2 bld 1<rt>
  let res = tmpVar bld dSz
  let lblNan = label bld "NaN"
  let lblCond = label bld "Cond"
  let lblInvalid = label bld "Invalidop"
  let lblInf = label bld "Inf"
  let lblChkInf = label bld "CheckInf"
  let lblChkZero = label bld "CheckZero"
  let lblEnd = label bld "End"
  let cond1 = isInf1 .& isInf2 .& (sign1 == AST.not sign2)
  let cond2 = (isInf1 .& (AST.not sign1)) .| (isInf2 .& (AST.not sign2))
  let cond3 = (isInf1 .& sign1) .| (isInf2 .& sign2)
  let cond4 = isZero1 .& isZero2 .& (sign1 == sign2)
  let struct (isNaN, resNaN) = fpProcessNaNs bld dSz src1 src2
  bld <+ (AST.cjmp (isNaN) (AST.jmpDest lblNan) (AST.jmpDest lblCond))
  bld <+ (AST.lmark lblNan)
  bld <+ (res := resNaN)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblCond)
  bld <+ (sign1 := AST.xthi 1<rt> src1)
  bld <+ (sign2 := AST.xthi 1<rt> src2)
  bld <+ (isZero1 := isZero dSz src1)
  bld <+ (isZero2 := isZero dSz src2)
  bld <+ (isInf1 := isInfinity dSz src1)
  bld <+ (isInf2 := isInfinity dSz src2)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblInvalid) (AST.jmpDest lblChkInf))
  bld <+ (AST.lmark lblInvalid)
  bld <+ (res := fpDefaultNan dSz)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblChkInf)
  bld <+ (AST.cjmp (cond2 .| cond3)
                   (AST.jmpDest lblInf) (AST.jmpDest lblChkZero))
  bld <+ (AST.lmark lblInf)
  bld <+ (res := AST.ite cond2 (fpInfinity AST.b0 dSz) (fpInfinity AST.b1 dSz))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblChkZero)
  bld <+ (res := AST.ite cond4 (fpZero src1 dSz) (AST.fadd src1 src2))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblEnd)
  res

/// shared/functions/float/fpadd/FPSub
/// FPSub()
let fpSub bld dSz src1 src2 =
  let struct (isZero1, isInf1, isZero2, isInf2) = tmpVars4 bld 1<rt>
  let struct (sign1, sign2) = tmpVars2 bld 1<rt>
  let res = tmpVar bld dSz
  let lblNan = label bld "NaN"
  let lblCond = label bld "Cond"
  let lblInvalid = label bld "Invalidop"
  let lblInf = label bld "Inf"
  let lblChkInf = label bld "CheckInf"
  let lblChkZero = label bld "CheckZero"
  let lblEnd = label bld "End"
  let cond1 = isInf1 .& isInf2 .& (sign1 == sign2)
  let cond2 = (isInf1 .& (AST.not sign1)) .| (isInf2 .& sign2)
  let cond3 = (isInf1 .& sign1) .| (isInf2 .& (AST.not sign2))
  let cond4 = isZero1 .& isZero2 .& (sign1 == (AST.not sign2))
  let struct (isNaN, resNaN) = fpProcessNaNs bld dSz src1 src2
  bld <+ (AST.cjmp (isNaN) (AST.jmpDest lblNan) (AST.jmpDest lblCond))
  bld <+ (AST.lmark lblNan)
  bld <+ (res := resNaN)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblCond)
  bld <+ (sign1 := AST.xthi 1<rt> src1)
  bld <+ (sign2 := AST.xthi 1<rt> src2)
  bld <+ (isZero1 := isZero dSz src1)
  bld <+ (isZero2 := isZero dSz src2)
  bld <+ (isInf1 := isInfinity dSz src1)
  bld <+ (isInf2 := isInfinity dSz src2)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblInvalid) (AST.jmpDest lblChkInf))
  bld <+ (AST.lmark lblInvalid)
  bld <+ (res := fpDefaultNan dSz)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblChkInf)
  bld <+ (AST.cjmp (cond2 .| cond3)
                   (AST.jmpDest lblInf) (AST.jmpDest lblChkZero))
  bld <+ (AST.lmark lblInf)
  bld <+ (res := AST.ite cond2 (fpInfinity AST.b0 dSz) (fpInfinity AST.b1 dSz))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblChkZero)
  bld <+ (res := AST.ite cond4 (fpZero src1 dSz) (AST.fsub src1 src2))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblEnd)
  res

/// shared/functions/float/fpmul/FPMul
/// FPMul()
let fpMul bld dataSize src1 src2 =
  let struct (isZero1, isInf1, isZero2, isInf2) = tmpVars4 bld 1<rt>
  let struct (sign1, sign2) = tmpVars2 bld 1<rt>
  let res = tmpVar bld dataSize
  let lblNan = label bld "NaN"
  let lblCond = label bld "Cond"
  let lblInvalid = label bld "Invalidop"
  let lblInf = label bld "Inf"
  let lblMul = label bld "Mul"
  let lblChkInf = label bld "CheckInf"
  let lblEnd = label bld "End"
  let cond1 = (isInf1 .& isZero2) .| (isZero1 .& isInf2)
  let cond2 = isInf1 .| isInf2
  let cond3 = isZero1 .| isZero2
  let struct (isNaN, resNaN) = fpProcessNaNs bld dataSize src1 src2
  bld <+ (AST.cjmp (isNaN) (AST.jmpDest lblNan) (AST.jmpDest lblCond))
  bld <+ (AST.lmark lblNan)
  bld <+ (res := resNaN)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblCond)
  bld <+ (sign1 := AST.xthi 1<rt> src1)
  bld <+ (sign2 := AST.xthi 1<rt> src2)
  bld <+ (isZero1 := isZero dataSize src1)
  bld <+ (isZero2 := isZero dataSize src2)
  bld <+ (isInf1 := isInfinity dataSize src1)
  bld <+ (isInf2 := isInfinity dataSize src2)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblInvalid) (AST.jmpDest lblChkInf))
  bld <+ (AST.lmark lblInvalid)
  bld <+ (res := fpDefaultNan dataSize)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblChkInf)
  bld <+ (AST.cjmp (cond2 .| cond3) (AST.jmpDest lblInf)(AST.jmpDest lblMul))
  bld <+ (AST.lmark lblInf)
  bld <+ (res := AST.ite cond2 (fpInfinity (sign1 <+> sign2) dataSize)
                               (fpZero (src1 <+> src2) dataSize))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblMul)
  bld <+ (res := AST.fmul src1 src2)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblEnd)
  res

/// shared/functions/float/fpdiv/FPDiv
/// FPDiv()
let fpDiv bld dataSize src1 src2 =
  let struct (isZero1, isInf1, isZero2, isInf2) = tmpVars4 bld 1<rt>
  let struct (sign1, sign2) = tmpVars2 bld 1<rt>
  let res = tmpVar bld dataSize
  let lblNan = label bld "NaN"
  let lblCond = label bld "Cond"
  let lblInvalid = label bld "Invalidop"
  let lblInf = label bld "Inf"
  let lblDiv = label bld "Div"
  let lblChkInf = label bld "CheckInf"
  let lblEnd = label bld "End"
  let cond1 = (isInf1 .& isInf2) .| (isZero1 .& isZero2)
  let cond2 = isInf1 .| isZero2
  let cond3 = isZero1 .| isInf2
  let struct (isNaN, resNaN) = fpProcessNaNs bld dataSize src1 src2
  bld <+ (AST.cjmp (isNaN) (AST.jmpDest lblNan) (AST.jmpDest lblCond))
  bld <+ (AST.lmark lblNan)
  bld <+ (res := resNaN)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblCond)
  bld <+ (sign1 := AST.xthi 1<rt> src1)
  bld <+ (sign2 := AST.xthi 1<rt> src2)
  bld <+ (isZero1 := isZero dataSize src1)
  bld <+ (isZero2 := isZero dataSize src2)
  bld <+ (isInf1 := isInfinity dataSize src1)
  bld <+ (isInf2 := isInfinity dataSize src2)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblInvalid) (AST.jmpDest lblChkInf))
  bld <+ (AST.lmark lblInvalid)
  bld <+ (res := fpDefaultNan dataSize)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblChkInf)
  bld <+ (AST.cjmp (cond2 .| cond3) (AST.jmpDest lblInf)(AST.jmpDest lblDiv))
  bld <+ (AST.lmark lblInf)
  bld <+ (res := AST.ite cond2 (fpInfinity (sign1 <+> sign2) dataSize)
                               (fpZero (src1 <+> src2) dataSize))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblDiv)
  bld <+ (res := AST.fdiv src1 src2)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblEnd)
  res

/// shared/functions/float/FPToFixed
/// FPToFixed()
/// ======
let fpToFixed dstSz src fbits unsigned round bld =
  let srcSz = src |> Expr.TypeOf
  let sign = AST.xthi 1<rt> src
  let trunc = AST.cast CastKind.FtoFTrunc srcSz src
  let convertBit =
    if dstSz > srcSz then AST.xtlo srcSz fbits elif dstSz = srcSz then fbits
    else AST.zext srcSz fbits
  let mulBits =
    AST.cast CastKind.UIntToFloat srcSz (numU64 0x1UL srcSz << convertBit)
  let bigint = AST.fmul src mulBits
  let fpFix cast =
    match dstSz, srcSz with
    | d, s when d >= s -> cast bigint
    | _ -> cast bigint |> AST.xtlo dstSz
    |> if unsigned then AST.zext dstSz else AST.sext dstSz
  let fpcheck cast =
    let res = tmpVar bld dstSz
    let struct (checkNan, checkInf, checkfbit) = tmpVars3 bld 1<rt>
    let lblNan = label bld "NaN"
    let lblCon = label bld "Continue"
    let lblEnd = label bld "End"
    bld <+ (checkNan := isNaN srcSz src)
    bld <+ (checkInf := isInfinity srcSz src)
    bld <+ (checkfbit := AST.zext srcSz fbits == AST.num0 srcSz)
    bld <+ (AST.cjmp (checkNan .| checkInf)
                   (AST.jmpDest lblNan) (AST.jmpDest lblCon))
    bld <+ (AST.lmark lblNan)
    bld <+ (res := AST.ite checkNan (AST.num0 dstSz) (fpMinMax src dstSz))
    bld <+ (AST.jmp (AST.jmpDest lblEnd))
    bld <+ (AST.lmark lblCon)
    bld <+ (res := fpFix cast)
    bld <+ (AST.lmark lblEnd)
    res
  match round with
  | FPRounding_TIEEVEN -> fpcheck (AST.cast CastKind.FtoIRound srcSz)
  | FPRounding_TIEAWAY ->
    let t = tmpVar bld srcSz
    let comp1 =
      match srcSz with
      | 32<rt> -> numI32 0x3F000000 srcSz (* 0.5 *)
      | 64<rt> -> numI64 0x3FE0000000000000L srcSz (* 0.5 *)
      | _ -> raise InvalidOperandSizeException
    let comp2 =
      match srcSz with
      | 32<rt> -> numI32 0xBF000000 srcSz (* -0.5 *)
      | 64<rt> -> numI64 0xBFE0000000000000L srcSz (* -0.5 *)
      | _ -> raise InvalidOperandSizeException
    bld <+ (t := AST.fsub src trunc)
    let ceil = fpcheck (AST.cast CastKind.FtoICeil srcSz)
    let floor = fpcheck (AST.cast CastKind.FtoIFloor srcSz)
    let pRes = AST.ite (AST.fge t comp1) ceil floor
    let nRes = AST.ite (AST.fle t comp2) floor ceil
    AST.ite sign nRes pRes
  | FPRounding_Zero -> fpcheck (AST.cast CastKind.FtoITrunc srcSz)
  | FPRounding_POSINF -> fpcheck (AST.cast CastKind.FtoICeil srcSz)
  | FPRounding_NEGINF -> fpcheck (AST.cast CastKind.FtoIFloor srcSz)


/// shared/functions/common/BitCount
// BitCount()
// ==========
let bitCount bitSize x =
  let size = int bitSize
  Array.init size (fun i -> (x >> (numI32 i bitSize)) .& (AST.num1 bitSize))
  |> Array.reduce (.+)

/// 64-bit operands generate a 64-bit result in the destination general-purpose
/// register. 32-bit operands generate a 32-bit result, zero-extended to a
/// 64-bit result in the destination general-purpose register.
let dstAssign oprSize dst src bld =
  let orgDst = AST.unwrap dst
  let orgDstSz = orgDst |> Expr.TypeOf
  match orgDst with
  | Var (_, rid, _, _) when rid = Register.toRegID R.XZR ->
    bld <+ (orgDst := AST.num0 orgDstSz)
  | _ ->
    if orgDstSz > oprSize then bld <+ (orgDst := AST.zext orgDstSz src)
    elif orgDstSz = oprSize then bld <+ (orgDst := src)
    else raise InvalidOperandSizeException

/// The SIMDFP Scalar register needs a function to get the upper 64-bit.
let dstAssignScalar ins bld addr dst src eSize =
  match dst with
  | OprSIMD (SIMDFPScalarReg reg) ->
    let reg = OprSIMD (SIMDFPScalarReg (Register.getOrgSIMDReg reg))
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr reg
    dstAssign eSize dstA src bld
    bld <+ (dstB := AST.num0 64<rt>)
  | _ -> raise InvalidOperandException

let dstAssign128 ins bld addr dst srcA srcB dataSize =
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  if dataSize = 128<rt> then
    bld <+ (dstA := srcA)
    bld <+ (dstB := srcB)
  else
    bld <+ (dstA := srcA)
    bld <+ (dstB := AST.num0 64<rt>)

let dstAssignForSIMD dstA dstB result dataSize elements bld =
  if dataSize = 128<rt> then
    let elems = elements / 2
    bld <+ (dstA := AST.revConcat (Array.sub result 0 elems))
    bld <+ (dstB := AST.revConcat (Array.sub result elems elems))
  else
    bld <+ (dstA := AST.revConcat result)
    bld <+ (dstB := AST.num0 64<rt>)

let mark bld addr size =
  bld <+ (AST.extCall <| AST.app "Mark" [ addr; size ] bld.RegType)

let unmark bld addr size =
  bld <+ (AST.extCall <| AST.app "Unmark" [ addr; size ] bld.RegType)

let isMarked bld addr size =
  bld <+ (AST.extCall <| AST.app "IsMarked" [ addr; size ] bld.RegType)

let exclusiveMonitorsPass bld address size data =
  let lblPass = label bld "EMPass"
  let lblEnd = label bld "End"
  let emval = regVar bld R.ERET
  let status = tmpVar bld 32<rt>
  bld <+ (status := AST.num1 32<rt>)
  isMarked bld address (memSizeToExpr size)
  let cond = emval == AST.num1 64<rt>
  bld <+ (AST.cjmp cond (AST.jmpDest lblPass) (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblPass)
  unmark bld address (memSizeToExpr size)
  bld <+ (AST.loadLE size address := data)
  bld <+ (status := AST.num0 32<rt>)
  bld <+ (AST.lmark lblEnd)
  status

let exclusiveMonitorsPassPair bld address size data1 data2 =
  let lblPass = label bld "EMPass"
  let lblEnd = label bld "End"
  let emval = regVar bld R.ERET
  let status = tmpVar bld 32<rt>
  bld <+ (status := AST.num1 32<rt>)
  isMarked bld address (memSizeToExpr size)
  let cond = emval == AST.num1 64<rt>
  bld <+ (AST.cjmp cond (AST.jmpDest lblPass) (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblPass)
  unmark bld address (memSizeToExpr size)
  bld <+ (AST.loadLE size address := data1)
  bld <+ (AST.loadLE size (address .+ numI32 8 64<rt>) := data2)
  bld <+ (status := AST.num0 32<rt>)
  bld <+ (AST.lmark lblEnd)
  status

// vim: set tw=80 sts=2 sw=2:
