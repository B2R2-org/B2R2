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

module internal B2R2.FrontEnd.BinLifter.ARM64.LiftingUtils

open System
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingOperators
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.BinLifter.ARM64

let inline getRegVar (ctxt: TranslationContext) name =
  Register.toRegID name |> ctxt.GetRegVar

let inline getPseudoRegVar (ctxt: TranslationContext) name pos =
  ctxt.GetPseudoRegVar (Register.toRegID name) pos

let getPC ctxt = getRegVar ctxt R.PC

let rorForIR src amount width = (src >> amount) .| (src << (width .- amount))

let ror x amount width = (x >>> amount) ||| (x <<< (width - amount))

let oprSzToExpr oprSize = numI32 (RegType.toBitWidth oprSize) oprSize

let memSizeToExpr rt = numI32 (RegType.toByteWidth rt) 64<rt>

let inline private (<!) (ir: IRBuilder) (s) = ir.Append (s)

let vectorToList vector esize =
  List.init (64 / int esize) (fun e -> AST.extract vector esize (e * int esize))

let getTwoOprs ins =
  match ins.Operands with
  | TwoOperands (o1, o2) -> struct (o1, o2)
  | _ -> raise InvalidOperandException

let getThreeOprs ins =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> struct (o1, o2, o3)
  | _ -> raise InvalidOperandException

let getFourOprs ins =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) -> struct (o1, o2, o3, o4)
  | _ -> raise InvalidOperandException

let getPseudoRegVar128 ctxt r =
  getPseudoRegVar ctxt r 2, getPseudoRegVar ctxt r 1

let getPseudoRegVarToArr ctxt reg eSize dataSize elems =
  let regA = getPseudoRegVar ctxt reg 1
  let pos = int eSize
  if dataSize = 128<rt> then
    let regB = getPseudoRegVar ctxt reg 2
    let elems = elems / 2
    let regA = Array.init elems (fun i -> AST.extract regA eSize (i * pos))
    let regB = Array.init elems (fun i -> AST.extract regB eSize (i * pos))
    Array.append regA regB
  else Array.init elems (fun i -> AST.extract regA eSize (i * pos))

let private getMemExpr128 expr =
  match expr.E with
  | Load (e, 128<rt>, expr, _) ->
    AST.load e 64<rt> (expr .+ numI32 8 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> expr
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
  let z = AST.relop RelOpType.EQ result (AST.num0 oSz)
  let c = AST.ge opr1 result
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

let transShiftAmout ctxt oprSize = function
  | Imm amt -> numI64 amt oprSize
  | Reg amt -> getRegVar ctxt amt

/// shared/functions/common/Extend
/// Extend()
/// ========
let extend reg oprSize isUnsigned =
  if isUnsigned then AST.zext oprSize reg else AST.sext oprSize reg

/// aarch64/instrs/extendreg/ExtendReg
/// ExtendReg()
/// ===========
/// Perform a register extension and shift
let extendReg ctxt reg typ shift oprSize =
  let regType = Register.toRegType reg
  let reg = getRegVar ctxt reg
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
  let len = min len ((RegType.toBitWidth oprSize) - shift)
  let mask = numI64 (if len = 64 then -1L else (1L <<< len) - 1L) regType
  extend ((reg .& mask) << numI32 shift regType) oprSize isUnsigned

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

let vectorPart ctxt eSize src = (* FIXME *)
  let struct (_, part, elements) = getElemDataSzAndElems src
  let pos = int eSize
  match src with
  | OprSIMD (SIMDVecReg (reg, _)) ->
    let regA = getPseudoRegVar ctxt reg 1
    if part = 128<rt> then
      let regB = getPseudoRegVar ctxt reg 2
      Array.init (elements / 2) (fun i -> AST.extract regB eSize (i * pos))
    else Array.init elements (fun i -> AST.extract regA eSize (i * pos))
  | _ -> raise InvalidOperandException

let transSIMDReg ctxt = function (* FIXME *)
  | SIMDVecRegWithIdx (reg, v, idx) ->
    let regB, regA = getPseudoRegVar128 ctxt reg
    let struct (esize, _, _) = getElemDataSzAndElemsByVector v
    let index = int idx * int esize
    if index < 64 then [| AST.extract regA esize index |]
    else [| AST.extract regB esize (index % 64) |]
  | SIMDVecReg (reg, v) ->
    let struct (eSize, dataSize, elements) = getElemDataSzAndElemsByVector v
    getPseudoRegVarToArr ctxt reg eSize dataSize elements
  | _ (* SIMDFPScalarReg *) -> raise InvalidOperandException

let transSIMDListToExpr ctxt = function (* FIXME *)
  | OprSIMDList simds -> Array.map (transSIMDReg ctxt) (List.toArray simds)
  | _ -> raise InvalidOperandException

let transSIMD ctxt = function (* FIXME *)
  | SIMDFPScalarReg reg -> getRegVar ctxt reg
  | SIMDVecReg _ -> raise InvalidOperandException
  | SIMDVecRegWithIdx (reg, v, idx) ->
    let regB, regA = getPseudoRegVar128 ctxt reg
    let struct (esize, _, _) = getElemDataSzAndElemsByVector v
    let index = int idx * int esize
    if index < 64 then AST.extract regA esize index
    else AST.extract regB esize (index % 64)

let transImmOffset ctxt = function
  | BaseOffset (bReg, Some imm) ->
    getRegVar ctxt bReg .+ numI64 imm 64<rt> |> AST.loadLE 64<rt>
  | BaseOffset (bReg, None) -> getRegVar ctxt bReg |> AST.loadLE 64<rt>
  | Lbl lbl -> numI64 lbl 64<rt>

let transRegOff ins ctxt reg = function
  | ShiftOffset (shfTyp, amt) ->
    let reg = getRegVar ctxt reg
    let amount = transShiftAmout ctxt 64<rt> amt
    shiftReg reg amount ins.OprSize shfTyp
  | ExtRegOffset (extTyp, shf) -> extendReg ctxt reg extTyp shf 64<rt>

let transRegOffset ins ctxt = function
  | bReg, reg, Some regOffset ->
    getRegVar ctxt bReg .+ transRegOff ins ctxt reg regOffset
  | bReg, reg, None -> getRegVar ctxt bReg .+ getRegVar ctxt reg

let transMemOffset ins ctxt = function
  | ImmOffset immOffset -> transImmOffset ctxt immOffset
  | RegOffset (bReg, reg, regOffset) ->
    transRegOffset ins ctxt (bReg, reg, regOffset) |> AST.loadLE 64<rt>

let transBaseMode ins ctxt offset =
  transMemOffset ins ctxt offset

let transMem ins ctxt _addr = function
  | BaseMode offset -> transBaseMode ins ctxt offset
  | PreIdxMode offset -> transBaseMode ins ctxt offset
  | PostIdxMode offset -> transBaseMode ins ctxt offset
  | LiteralMode offset -> transBaseMode ins ctxt offset

let transOprToExpr ins ctxt addr = function
  | OprRegister reg -> getRegVar ctxt reg
  | OprMemory mem -> transMem ins ctxt addr mem
  | OprSIMD reg -> transSIMD ctxt reg
  | OprImm imm -> numI64 imm ins.OprSize
  | OprNZCV nzcv -> numI64 (int64 nzcv) ins.OprSize
  | OprLSB lsb -> numI64 (int64 lsb) ins.OprSize
  | OprFbits fbits -> numI64 (int64 fbits) ins.OprSize
  | OprFPImm float ->
    if ins.OprSize = 64<rt> then
      numI64 (BitConverter.DoubleToInt64Bits float) ins.OprSize
    else numI64 (BitConverter.SingleToInt32Bits (float32 float)) ins.OprSize
  | _ -> raise <| NotImplementedIRException "transOprToExpr"

let transOprToExprFPImm ins eSize src =
  match eSize, src with
  | 32<rt>, OprFPImm float ->
    numI64 (BitConverter.SingleToInt32Bits (float32 float)) ins.OprSize
  | 64<rt>, OprFPImm float ->
    numI64 (BitConverter.DoubleToInt64Bits float) ins.OprSize
  | _ -> raise InvalidOperandException

let separateMemExpr expr =
  match expr.E with
  | Load (_, _, { E = BinOp (BinOpType.ADD, _, b, o, _) }, _) -> b, o
  | Load (_, _, e, _) -> e, AST.num0 64<rt>
  | _ -> raise InvalidOperandException

let transOneOpr ins ctxt addr =
  match ins.Operands with
  | OneOperand o -> transOprToExpr ins ctxt addr o
  | _ -> raise InvalidOperandException

let transTwoOprs ins ctxt addr =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2
  | _ -> raise InvalidOperandException

let transTwoOprsSepMem ins ctxt addr =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2 |> separateMemExpr
  | _ -> raise InvalidOperandException

let transThreeOprs ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3
  | _ -> raise InvalidOperandException

let transThreeOprsSepMem ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3 |> separateMemExpr
  | _ -> raise InvalidOperandException

let transFourOprs ins ctxt addr =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3,
    transOprToExpr ins ctxt addr o4
  | _ -> raise InvalidOperandException

let transFourOprsSepMem ins ctxt addr =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3,
    transOprToExpr ins ctxt addr o4 |> separateMemExpr
  | _ -> raise InvalidOperandException

let transOprToExpr128 ins ctxt addr = function
  | OprSIMD (SIMDFPScalarReg reg) -> getPseudoRegVar128 ctxt reg
  | OprSIMD (SIMDVecReg (reg, _)) -> getPseudoRegVar128 ctxt reg
  | OprSIMD (SIMDVecRegWithIdx (reg, _, _)) -> getPseudoRegVar128 ctxt reg
  | OprMemory mem -> transMem ins ctxt addr mem |> getMemExpr128
  | _ -> raise InvalidOperandException

let transSIMDOprToExpr ctxt eSize dataSize elements = function
  | OprSIMD (SIMDFPScalarReg reg) ->
    if dataSize = 128<rt> then
      let regB, regA = getPseudoRegVar128 ctxt reg
      [| regB; regA |]
    else [| getRegVar ctxt reg |]
  | OprSIMD (SIMDVecReg (reg, _)) ->
    getPseudoRegVarToArr ctxt reg eSize dataSize elements
  | OprSIMD (SIMDVecRegWithIdx _) -> raise InvalidOperandException
  | _ -> raise InvalidOperandException

(* Barrel shift *)
let transBarrelShiftToExpr oprSize ctxt src shift =
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
    let reg = getRegVar ctxt reg
    let amount = transShiftAmout ctxt oprSize amt
    shiftReg reg amount oprSize typ
  | OprRegister reg, OprExtReg (Some (ShiftOffset (typ, amt))) ->
    let reg = getRegVar ctxt reg
    let amount = transShiftAmout ctxt oprSize amt
    shiftReg reg amount oprSize typ
  | OprRegister reg, OprExtReg (Some (ExtRegOffset (typ, shf))) ->
    extendReg ctxt reg typ shf oprSize
  | OprRegister reg, OprExtReg None -> getRegVar ctxt reg
  | _ -> raise <| NotImplementedIRException "transBarrelShiftToExpr"

let transThreeOprsWithBarrelShift ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    transOprToExpr ins ctxt addr o1,
    transBarrelShiftToExpr ins.OprSize ctxt o2 o3
  | _ -> raise InvalidOperandException

let transFourOprsWithBarrelShift ins ctxt addr =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transBarrelShiftToExpr ins.OprSize ctxt o3 o4
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

let transOprToExprOfAND ins ctxt addr =
  match ins.Operands with
  | ThreeOperands _ -> transThreeOprs ins ctxt addr
  | FourOperands _ -> transFourOprsWithBarrelShift ins ctxt addr
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

let transOprToExprOfCCMN ins ctxt addr =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3,
    o4 |> unwrapCond
  | _ -> raise InvalidOperandException

let transOprToExprOfCCMP ins ctxt addr =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3,
    o4 |> unwrapCond
  | _ -> raise InvalidOperandException

let transOprToExprOfCMP ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    transOprToExpr ins ctxt addr o1,
    transBarrelShiftToExpr ins.OprSize ctxt o2 o3
  | _ -> raise InvalidOperandException

let transOprToExprOfCSEL ins ctxt addr =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3,
    o4 |> unwrapCond
  | _ -> raise InvalidOperandException

let transOprToExprOfCSINC ins ctxt addr =
  match ins.Operands with
  | TwoOperands (o1, o2) -> (* CSET *)
    transOprToExpr ins ctxt addr o1,
    getRegVar ctxt (if ins.OprSize = 64<rt> then R.XZR else R.WZR),
    getRegVar ctxt (if ins.OprSize = 64<rt> then R.XZR else R.WZR),
    o2 |> unwrapCond |> invertCond
  | ThreeOperands (o1, o2, o3) -> (* CINC *)
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o2,
    o3 |> unwrapCond |> invertCond
  | FourOperands (o1, o2, o3, o4) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3,
    o4 |> unwrapCond
  | _ -> raise InvalidOperandException

let transOprToExprOfCSINV ins ctxt addr =
  match ins.Operands with
  | TwoOperands (o1, o2) -> (* CSETM *)
    transOprToExpr ins ctxt addr o1,
    getRegVar ctxt (if ins.OprSize = 64<rt> then R.XZR else R.WZR),
    getRegVar ctxt (if ins.OprSize = 64<rt> then R.XZR else R.WZR),
    o2 |> unwrapCond |> invertCond
  | ThreeOperands (o1, o2, o3) -> (* CINV *)
    let o2 = transOprToExpr ins ctxt addr o2
    transOprToExpr ins ctxt addr o1, o2, o2, o3 |> unwrapCond
  | FourOperands (o1, o2, o3, o4) -> (* CSINV *)
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3,
    o4 |> unwrapCond
  | _ -> raise InvalidOperandException

let transOprToExprOfCSNEG ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, OprCond o3) -> (* CNEG *)
    let o2 = transOprToExpr ins ctxt addr o2
    transOprToExpr ins ctxt addr o1, o2, o2, invertCond o3
  | FourOperands (o1, o2, o3, o4) -> (* CSNEG *)
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3,
    o4|> unwrapCond
  | _ -> raise InvalidOperandException

let transOprToExprOfEOR ins ctxt addr =
  match ins.Operands with
  | ThreeOperands _ -> transThreeOprs ins ctxt addr
  | FourOperands (o1, o2, o3, o4) when ins.Opcode = Opcode.EOR ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transBarrelShiftToExpr ins.OprSize ctxt o3 o4
  | FourOperands (o1, o2, o3, o4) when ins.Opcode = Opcode.EON ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transBarrelShiftToExpr ins.OprSize ctxt o3 o4 |> AST.not
  | _ -> raise InvalidOperandException

let transOprToExprOfEXTR ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> (* ROR *)
    let o2 = transOprToExpr ins ctxt addr o2
    transOprToExpr ins ctxt addr o1, o2, o2, transOprToExpr ins ctxt addr o3
  | FourOperands _ -> transFourOprs ins ctxt addr
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

let transOprToExprOfMADD ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> (* MUL *)
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3,
    getRegVar ctxt (if ins.OprSize = 64<rt> then R.XZR else R.WZR)
  | FourOperands _ -> transFourOprs ins ctxt addr
  | _ -> raise InvalidOperandException

let transOprToExprOfORN ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) when ins.Opcode = Opcode.MVN -> (* MVN *)
    transOprToExpr ins ctxt addr o1,
    getRegVar ctxt (if ins.OprSize = 64<rt> then R.XZR else R.WZR),
    transBarrelShiftToExpr ins.OprSize ctxt o2 o3
  | FourOperands (o1, o2, o3, o4) when ins.Opcode = Opcode.ORN -> (* ORN *)
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transBarrelShiftToExpr ins.OprSize ctxt o3 o4
  | _ -> raise InvalidOperandException

let transOprToExprOfORR ins ctxt addr =
  match ins.Operands with
  | ThreeOperands _ -> transThreeOprs ins ctxt addr
  | FourOperands (o1, o2, o3, o4) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transBarrelShiftToExpr ins.OprSize ctxt o3 o4
  | _ -> raise InvalidOperandException

let unwrapReg e =
  match e.E with
  | Extract (e, 32<rt>, 0, _) -> e
  | _ -> failwith "Invalid register"

let transOprToExprOfSMSUBL ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3,
    getRegVar ctxt R.XZR
  | FourOperands _ -> transFourOprs ins ctxt addr
  | _ -> raise InvalidOperandException

let transOprToExprOfSUB ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3)
    when ins.Opcode = Opcode.NEG ->
    transOprToExpr ins ctxt addr o1,
    getRegVar ctxt (if ins.OprSize = 64<rt> then R.XZR else R.WZR),
    transBarrelShiftToExpr ins.OprSize ctxt o2 o3 |> AST.not
  | FourOperands (o1, o2, o3, o4) -> (* Arithmetic *)
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transBarrelShiftToExpr ins.OprSize ctxt o3 o4 |> AST.not
  | _ -> raise InvalidOperandException

let transOprToExprOfMSUB ins ctxt addr =
  let oprSize = ins.OprSize
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> (* MNEG *)
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3,
    getRegVar ctxt (if ins.OprSize = 64<rt> then R.XZR else R.WZR)
  | FourOperands _ -> transFourOprs ins ctxt addr (* MSUB *)
  | _ -> raise InvalidOperandException

let transOprToExprOfUMADDL ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> (* UMULL / UMNEGL *)
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3,
    getRegVar ctxt R.XZR
  | FourOperands _ -> transFourOprs ins ctxt addr
  | _ -> raise InvalidOperandException

let transOprToExprOfSUBS ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    transOprToExpr ins ctxt addr o1,
    getRegVar ctxt (if ins.OprSize = 64<rt> then R.XZR else R.WZR),
    transBarrelShiftToExpr ins.OprSize ctxt o2 o3 |> AST.not
  | FourOperands (o1, o2, o3, o4) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transBarrelShiftToExpr ins.OprSize ctxt o3 o4 |> AST.not
  | _ -> raise InvalidOperandException

let transOprToExprOfTST ins ctxt addr =
  match ins.Operands with
  | TwoOperands (o1, o2) (* immediate *) ->
    transOprToExpr ins ctxt addr o1, transOprToExpr ins ctxt addr o2
  | ThreeOperands (o1, o2, o3) (* shfed *) ->
    transOprToExpr ins ctxt addr o1,
    transBarrelShiftToExpr ins.OprSize ctxt o2 o3
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
let branchTo ins ctxt target brType i (ir: IRBuilder) =
  !!ir (AST.interjmp target i) // FIXME: BranchAddr function

/// shared/functions/system/ConditionHolds
/// ConditionHolds()
/// ================
/// Return TRUE iff COND currently holds
let conditionHolds ctxt = function
  | EQ -> getRegVar ctxt R.Z == AST.b1
  | NE -> getRegVar ctxt R.Z == AST.b0
  | CS -> getRegVar ctxt R.C == AST.b1
  | CC -> getRegVar ctxt R.C == AST.b0
  | MI -> getRegVar ctxt R.N == AST.b1
  | PL -> getRegVar ctxt R.N == AST.b0
  | VS -> getRegVar ctxt R.V == AST.b1
  | VC -> getRegVar ctxt R.V == AST.b0
  | HI -> (getRegVar ctxt R.C == AST.b1) .& (getRegVar ctxt R.Z == AST.b0)
  | LS -> AST.not ((getRegVar ctxt R.C == AST.b1) .&
                  (getRegVar ctxt R.Z == AST.b0))
  | GE -> getRegVar ctxt R.N == getRegVar ctxt R.V
  | LT -> getRegVar ctxt R.N != getRegVar ctxt R.V
  | GT -> (getRegVar ctxt R.N == getRegVar ctxt R.V) .&
          (getRegVar ctxt R.Z == AST.b0)
  | LE -> AST.not ((getRegVar ctxt R.N == getRegVar ctxt R.V) .&
                  (getRegVar ctxt R.Z == AST.b0))
  (* Condition flag values in the set '111x' indicate always true *)
  | AL | NV -> AST.b1
  | _ -> failwith "Invalid condition"

/// shared/functions/common/HighestSetBit
/// HighestSetBit()
/// ===============
let highestSetBitForIR expr width oprSz ir =
  let struct (high, n1) = tmpVars2 ir oprSz
  !!ir (high := numI32 -1 oprSz)
  !!ir (n1 := AST.num1 oprSz)
  let inline pos i =
    let bit = AST.extract expr 1<rt> i |> AST.zext oprSz
    (bit .* ((numI32 i oprSz) .+ n1)) .- n1
  Array.init width pos
  |> Array.iter (fun e -> !!ir (high := AST.ite (high ?<= e) e high))
  high

let highestSetBit x size =
  let rec loop i =
    if i < 0 then -1
    elif (x >>> i) &&& 1 = 1 then i
    else loop (i - 1)
  loop (size - 1)

/// shared/functions/common/Replicate
/// Replicate()
/// ===========
let replicateForIR expr exprSize repSize ir =
  let repeat = repSize / exprSize
  let repVal = !+ir repSize
  !!ir (repVal := AST.zext repSize expr)
  Array.init repeat (fun i -> repVal << numI32 (int exprSize * i) repSize)
  |> Array.reduce (.|)

let replicate x eSize dstSize =
  let rec loop x i = if i = 1 then x else loop (x <<< eSize ||| x) (i - 1)
  loop x (dstSize / eSize)

let advSIMDExpandImm ir eSize src =
  let src = AST.xtlo 64<rt> src
  replicateForIR src eSize 64<rt> ir

let getMaskForIR n oprSize = (AST.num1 oprSize << n) .- AST.num1 oprSize

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
let countLeadingZeroBitsForIR src bitSize oprSize ir =
  let res = highestSetBitForIR src bitSize oprSize ir
  (numI32 bitSize oprSize) .- (res .+ AST.num1 oprSize)

/// shared/functions/common/CountLeadingSignBits
/// CountLeadingSignBits()
/// ======================
let countLeadingSignBitsForIR expr oprSize ir =
  let n1 = AST.num1 oprSize
  let struct (expr1, expr2, xExpr) = tmpVars3 ir oprSize
  !!ir (expr1 := expr >> n1)
  !!ir (expr2 := (expr << n1) >> n1)
  !!ir (xExpr := (expr1 <+> expr2))
  /// This count does not include the most significant bit of the source
  /// register.
  let bitSize = int oprSize - 1
  countLeadingZeroBitsForIR expr bitSize oprSize ir

/// shared/functions/vector/UnsignedSatQ
/// UnsignedSatQ()
/// ==============
let unsignedSatQ i (n: RegType) ir =
  let struct (max, n0) = tmpVars2 ir n
  let res = !+ir 64<rt>
  !!ir (res := i)
  !!ir (max := getMaskForIR (numI64 (int n) n) n)
  !!ir (n0 := AST.num0 n)
  let cond1 = res .> AST.sext 64<rt> max
  let cond2 = res ?< AST.zext 64<rt> n0
  AST.ite cond1 max (AST.ite cond2 n0 (AST.xtlo n res))

/// shared/functions/vector/SignedSatQ
/// SignedSatQ()
/// ============
let signedSatQ i n ir =
  let struct (max, negRes) = tmpVars2 ir n
  let res = !+ir 64<rt>
  !!ir (res := i)
  !!ir (max := getMaskForIR (numI64 (int n) n) n)
  !!ir (negRes := AST.neg max)
  let cond1 = res ?> AST.zext 64<rt> max
  let cond2 = res ?< AST.zext 64<rt> negRes
  AST.ite cond1 max (AST.ite cond2 negRes (AST.xtlo n res))

/// shared/functions/vector/SatQ
/// SatQ()
/// ======
let satQ i n isUnsigned ir = (* FIMXE: return saturated (FPSR.QC = '1') *)
  if isUnsigned then unsignedSatQ i n ir else signedSatQ i n ir

/// shared/functions/float/FPToFixed
/// FPToFixed()
/// ======
let fpToFixed dstSz src fbits unsigned round =
  let srcSz = src |> TypeCheck.typeOf
  let convertBit =
    if dstSz > srcSz then AST.xtlo srcSz fbits elif dstSz = srcSz then fbits
    else AST.zext srcSz fbits
  let mulBits =
    AST.cast CastKind.UIntToFloat srcSz (numU64 0x1UL srcSz << convertBit)
  let bigint = AST.fmul src mulBits
  let round =
    match round with
    | FPRounding_TIEEVEN
    | FPRounding_TIEAWAY -> AST.cast CastKind.FtoIRound srcSz
    | FPRounding_Zero -> AST.cast CastKind.FtoITrunc srcSz
    | FPRounding_POSINF -> AST.cast CastKind.FtoICeil srcSz
    | FPRounding_NEGINF -> AST.cast CastKind.FtoIFloor srcSz
  match dstSz, srcSz with
  | d, s when d >=s -> round bigint
  | _ -> round bigint |> AST.xtlo dstSz
  |> if unsigned then AST.zext dstSz else AST.sext dstSz

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
let dstAssign oprSize dst src ir =
  let orgDst = AST.unwrap dst
  let orgDstSz = orgDst |> TypeCheck.typeOf
  match orgDst with
  | { E = Var (_, rid, _, _) } when rid = Register.toRegID R.XZR ->
    !!ir (orgDst := AST.num0 orgDstSz)
  | _ ->
    if orgDstSz > oprSize then !!ir (orgDst := AST.zext orgDstSz src)
    elif orgDstSz = oprSize then !!ir (orgDst := src)
    else raise InvalidOperandSizeException

/// The SIMDFP Scalar register needs a function to get the upper 64-bit.
let dstAssignScalar ins ctxt addr dst src eSize ir =
  match dst with
  | OprSIMD (SIMDFPScalarReg reg) ->
    let reg = OprSIMD (SIMDFPScalarReg (Register.getOrgSIMDReg reg))
    let dstB, dstA = transOprToExpr128 ins ctxt addr reg
    dstAssign eSize dstA src ir
    !!ir (dstB := AST.num0 64<rt>)
  | _ -> raise InvalidOperandException

let dstAssign128 ins ctxt addr dst srcA srcB dataSize ir =
  let dstB, dstA = transOprToExpr128 ins ctxt addr dst
  if dataSize = 128<rt> then
    !!ir (dstA := srcA)
    !!ir (dstB := srcB)
  else
    !!ir (dstA := srcA)
    !!ir (dstB := AST.num0 64<rt>)

let dstAssignForSIMD dstA dstB result dataSize elements ir =
  if dataSize = 128<rt> then
    let elems = elements / 2
    !!ir (dstA := AST.concatArr (Array.sub result 0 elems))
    !!ir (dstB := AST.concatArr (Array.sub result elems elems))
  else
    !!ir (dstA := AST.concatArr result)
    !!ir (dstB := AST.num0 64<rt>)

let mark (ctxt: TranslationContext) addr size ir =
  !!ir (AST.extCall <| AST.app "Mark" [addr; size] ctxt.WordBitSize)

let unmark (ctxt: TranslationContext) addr size ir =
  !!ir (AST.extCall <| AST.app "Unmark" [addr; size] ctxt.WordBitSize)

let isMarked (ctxt: TranslationContext) addr size ir =
  !!ir (AST.extCall <| AST.app "IsMarked" [addr; size] ctxt.WordBitSize)

let exclusiveMonitorsPass ctxt address size data ir =
  let lblPass = !%ir "EMPass"
  let lblEnd = !%ir "End"
  let emval = getRegVar ctxt R.ERET
  let status = !+ir 32<rt>
  !!ir (status := AST.num1 32<rt>)
  isMarked ctxt address (memSizeToExpr size) ir
  let cond = emval == AST.num1 64<rt>
  !!ir (AST.cjmp cond (AST.name lblPass) (AST.name lblEnd))
  !!ir (AST.lmark lblPass)
  unmark ctxt address (memSizeToExpr size) ir
  !!ir (AST.loadLE size address := data)
  !!ir (status := AST.num0 32<rt>)
  !!ir (AST.lmark lblEnd)
  status

let exclusiveMonitorsPassPair ctxt address size data1 data2 ir =
  let lblPass = !%ir "EMPass"
  let lblEnd = !%ir "End"
  let emval = getRegVar ctxt R.ERET
  let status = !+ir 32<rt>
  !!ir (status := AST.num1 32<rt>)
  isMarked ctxt address (memSizeToExpr size) ir
  let cond = emval == AST.num1 64<rt>
  !!ir (AST.cjmp cond (AST.name lblPass) (AST.name lblEnd))
  !!ir (AST.lmark lblPass)
  unmark ctxt address (memSizeToExpr size) ir
  !!ir (AST.loadLE size address := data1)
  !!ir (AST.loadLE size (address .+ numI32 8 64<rt>) := data2)
  !!ir (status := AST.num0 32<rt>)
  !!ir (AST.lmark lblEnd)
  status

// vim: set tw=80 sts=2 sw=2:
