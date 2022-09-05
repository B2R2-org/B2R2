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

let ror src amount width = (src >> amount) .| (src << (width .- amount))

let oprSzToExpr oprSize = numI32 (RegType.toBitWidth oprSize) oprSize

let inline private (<!) (ir: IRBuilder) (s) = ir.Append (s)

let getTwoOprs ins =
  match ins.Operands with
  | TwoOperands (o1, o2) -> struct (o1, o2)
  | _ -> raise InvalidOperandException

let getThreeOprs ins =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> struct (o1, o2, o3)
  | _ -> raise InvalidOperandException

let getPseudoRegVar128 ctxt r =
  getPseudoRegVar ctxt r 2, getPseudoRegVar ctxt r 1

let private getMemExpr128 expr =
  match expr.E with
  | Load (e, 128<rt>, expr, _) ->
    AST.load e 64<rt> (expr .+ numI32 8 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> expr
  | _ -> raise InvalidOperandException

/// shared/functions/integer/AddWithCarry
/// AddWithCarry()
/// ==============
/// Integer addition with carry input, returning result and NZCV flags
let addWithCarry opr1 opr2 carryIn oSz =
  let result = opr1 .+ opr2 .+ carryIn
  let n = AST.xthi 1<rt> result
  let z = AST.relop RelOpType.EQ result (AST.num0 oSz)
  let c = AST.gt opr1 result
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
  | SRTypeROR -> ror reg amount (oprSzToExpr oprSize)
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
  let rTyp = RegType.fromBitWidth len
  extend ((AST.xtlo rTyp  reg) << numI32 shift rTyp) oprSize isUnsigned

let transSIMDRegToExpr ctxt = function (* FIXME *)
  | SIMDFPScalarReg reg -> getRegVar ctxt reg
  | SIMDVecReg (reg, v) -> getRegVar ctxt reg
  | SIMDVecRegWithIdx (reg, v, idx) -> getRegVar ctxt reg

let transSIMD ctxt = function (* FIXME *)
  | SFReg reg -> transSIMDRegToExpr ctxt reg
  | OneReg s -> raise <| NotImplementedIRException "OneReg"
  | TwoRegs (s1, s2) -> raise <| NotImplementedIRException "TwoRegs"
  | ThreeRegs (s1, s2, s3) -> raise <| NotImplementedIRException "ThreeRegs"
  | FourRegs (s1, s2, s3, s4) -> raise <| NotImplementedIRException "FourRegs"

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

let transMem ins ctxt addr = function
  | BaseMode offset -> transBaseMode ins ctxt offset
  | PreIdxMode offset -> transBaseMode ins ctxt offset
  | PostIdxMode offset -> transBaseMode ins ctxt offset
  | LiteralMode offset -> transBaseMode ins ctxt offset

let transOprToExpr ins ctxt addr = function
  | OprRegister reg -> getRegVar ctxt reg
  | Memory mem -> transMem ins ctxt addr mem
  | SIMDOpr simd -> transSIMD ctxt simd
  | Immediate imm -> numI64 imm ins.OprSize
  | NZCV nzcv -> numI64 (int64 nzcv) ins.OprSize
  | LSB lsb -> numI64 (int64 lsb) ins.OprSize
  | _ -> raise <| NotImplementedIRException "transOprToExpr"

let separateMemExpr expr =
  match expr.E with
  | Load (_, _, { E = BinOp (BinOpType.ADD, _, b, o, _) }, _) -> b, o
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

let transOprToExpr128 ins ctxt addr = function
  | SIMDOpr (SFReg (SIMDFPScalarReg reg)) -> getPseudoRegVar128 ctxt reg
  | SIMDOpr (SFReg (SIMDVecReg (reg, _))) -> getPseudoRegVar128 ctxt reg
  | SIMDOpr (SFReg (SIMDVecRegWithIdx (reg, _, _))) ->
    getPseudoRegVar128 ctxt reg
  | Memory mem -> transMem ins ctxt addr mem |> getMemExpr128
  | _ -> raise InvalidOperandException

(* Barrel shift *)
let transBarrelShiftToExpr ins ctxt src shift =
  match src, shift with
  | Immediate imm, Shift (typ, Imm amt) ->
    let imm = match typ with
              | SRTypeLSL -> imm <<< int32 amt
              | SRTypeLSR -> imm >>> int32 amt
              | _ -> failwith "Not implement"
    numI64 imm ins.OprSize
  | OprRegister reg, Shift (typ, amt) ->
    let reg = getRegVar ctxt reg
    let amount = transShiftAmout ctxt ins.OprSize amt
    shiftReg reg amount ins.OprSize typ
  | OprRegister reg, ExtReg (Some (ShiftOffset (typ, amt))) ->
    let reg = getRegVar ctxt reg
    let amount = transShiftAmout ctxt ins.OprSize amt
    shiftReg reg amount ins.OprSize typ
  | OprRegister reg, ExtReg (Some (ExtRegOffset (typ, shf))) ->
    extendReg ctxt reg typ shf ins.OprSize
  | OprRegister reg, ExtReg None -> getRegVar ctxt reg
  | _ -> raise <| NotImplementedIRException "transBarrelShiftToExpr"

let transFourOprsWithBarrelShift ins ctxt addr =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transBarrelShiftToExpr ins ctxt o3 o4
  | _ -> raise InvalidOperandException

/// Number and size of elements
let getElemNumAndSizeBySIMDVector = function
  | VecB -> 1, 8<rt>       (* Vector register names with element index *)
  | VecH -> 1, 16<rt>
  | VecS -> 1, 32<rt>
  | VecD -> 1, 64<rt>
  | EightB -> 8, 8<rt>     (* SIMD vector register names *)
  | SixteenB -> 16, 8<rt>
  | FourH -> 4, 16<rt>
  | EightH -> 8, 16<rt>
  | TwoS -> 2, 32<rt>
  | FourS -> 4, 32<rt>
  | OneD -> 1, 64<rt>
  | TwoD -> 2, 64<rt>
  | OneQ -> 1, 128<rt>

let getElemNumAndSize oprSize = function
  | SIMDFPScalarReg _ -> 1, oprSize
  | SIMDVecReg (_, v) -> getElemNumAndSizeBySIMDVector v
  | SIMDVecRegWithIdx (_, v, _) -> getElemNumAndSizeBySIMDVector v

let getSIMDReg = function
  | SIMDOpr (SFReg sReg) -> sReg
  | _ -> raise InvalidOperandException

let isSIMDScalar opr =
  match opr with
  | SIMDOpr (SFReg (SIMDFPScalarReg _)) -> true
  | _ -> false

let isSIMDVector opr =
  match opr with
  | SIMDOpr (SFReg (SIMDVecReg _)) -> true
  | _ -> false

let isSIMDVectorIdx opr =
  match opr with
  | SIMDOpr (SFReg (SIMDVecRegWithIdx _)) -> true
  | _ -> false

let transOprToExprOfADDS ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> (* CMN *)
    getRegVar ctxt (if ins.OprSize = 64<rt> then R.XZR else R.WZR),
    transOprToExpr ins ctxt addr o1,
    transBarrelShiftToExpr ins ctxt o2 o3
  | FourOperands _ -> transFourOprsWithBarrelShift ins ctxt addr
  | _ -> raise InvalidOperandException

let transOprToExprOfAND ins ctxt addr =
  match ins.Operands with
  | ThreeOperands _ -> transThreeOprs ins ctxt addr
  | FourOperands _ -> transFourOprsWithBarrelShift ins ctxt addr
  | _ -> raise InvalidOperandException

let transOprToExprOfANDS ins ctxt addr =
  match ins.Operands with
  | TwoOperands (o1, o2) -> (* TST (immediate) *)
    getRegVar ctxt (if ins.OprSize = 64<rt> then R.XZR else R.WZR),
    transOprToExpr ins ctxt addr o1, transOprToExpr ins ctxt addr o2
  | ThreeOperands (o1, o2, o3) when ins.Opcode = Opcode.TST -> (* TST (shfed) *)
    getRegVar ctxt (if ins.OprSize = 64<rt> then R.XZR else R.WZR),
    transOprToExpr ins ctxt addr o1, transBarrelShiftToExpr ins ctxt o2 o3
  | ThreeOperands _ -> transThreeOprs ins ctxt addr
  | FourOperands _ -> transFourOprsWithBarrelShift ins ctxt addr
  | _ -> raise InvalidOperandException

let transOprToExprOfBFM ins ctxt addr =
  match ins.Operands with
  | FourOperands (o1, o2, o3, Immediate o4) when ins.Opcode = Opcode.BFI ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3, (* FIXME: #(-<lsb> MOD 32/64) *)
    transOprToExpr ins ctxt addr (Immediate (o4 + 1L))
  | FourOperands (o1, o2, Immediate o3, Immediate o4)
    when ins.Opcode = Opcode.BFXIL ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr (Immediate o3),
    transOprToExpr ins ctxt addr (Immediate (o4 - o3 + 1L))
  | FourOperands _ -> transFourOprs ins ctxt addr
  | _ -> raise InvalidOperandException

let unwrapCond = function
  | Cond cond -> cond
  | _ -> raise InvalidOperandException

let invertCond = function
  | EQ -> NV
  | NE -> AL
  | CS | HS -> LE
  | CC | LO -> GT
  | MI -> LT
  | PL -> GE
  | VS -> LS
  | VC -> HI
  | HI -> VC
  | LS -> VS
  | GE -> PL
  | LT -> MI
  | GT -> CC
  | LE -> CS
  | AL -> NE
  | NV -> EQ

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
    transBarrelShiftToExpr ins ctxt o2 o3
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
  | ThreeOperands (o1, o2, Cond o3) -> (* CNEG *)
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
    transBarrelShiftToExpr ins ctxt o3 o4
  | FourOperands (o1, o2, o3, o4) when ins.Opcode = Opcode.EON ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transBarrelShiftToExpr ins ctxt o3 o4 |> AST.not
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
  | TwoOperands (_, Memory mem) -> getIsWBackAndIsPostIndexByAddrMode mem
  | ThreeOperands (_, _, Memory mem) -> getIsWBackAndIsPostIndexByAddrMode mem
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

let transOprToExprOfMOV ins ctxt addr =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    transOprToExpr ins ctxt addr o1, transOprToExpr ins ctxt addr o2
  | ThreeOperands (o1, o2, o3) ->
    transOprToExpr ins ctxt addr o1, transBarrelShiftToExpr ins ctxt o2 o3
  | _ -> raise InvalidOperandException

let transOprToExprOfORN ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) when ins.Opcode = Opcode.MVN -> (* MVN *)
    transOprToExpr ins ctxt addr o1,
    getRegVar ctxt (if ins.OprSize = 64<rt> then R.XZR else R.WZR),
    transBarrelShiftToExpr ins ctxt o2 o3
  | FourOperands (o1, o2, o3, o4) when ins.Opcode = Opcode.ORN -> (* ORN *)
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transBarrelShiftToExpr ins ctxt o3 o4
  | _ -> raise InvalidOperandException

let transOprToExprOfORR ins ctxt addr =
  match ins.Operands with
  | ThreeOperands _ -> transThreeOprs ins ctxt addr
  | FourOperands (o1, o2, o3, o4) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transBarrelShiftToExpr ins ctxt o3 o4
  | _ -> raise InvalidOperandException

let unwrapReg e =
  match e.E with
  | Extract (e, 32<rt>, 0, _) -> e
  | _ -> failwith "Invalid register"

let transOprToExprOfSBFM ins ctxt addr =
  match ins.Operands with
  | TwoOperands (o1, o2) (* SXTB *)
    when ins.Opcode = Opcode.SXTB ->
    let o1 = transOprToExpr ins ctxt addr o1
    let o2 = transOprToExpr ins ctxt addr o2
    let o2 = if ins.OprSize = 64<rt> then o2 |> unwrapReg else o2
    o1, o2, AST.num0 ins.OprSize, numI32 7 ins.OprSize
  | TwoOperands (o1, o2) (* SXTH *)
    when ins.Opcode = Opcode.SXTH ->
    let o1 = transOprToExpr ins ctxt addr o1
    let o2 = transOprToExpr ins ctxt addr o2
    let o2 = if ins.OprSize = 64<rt> then o2 |> unwrapReg else o2
    o1, o2, AST.num0 ins.OprSize, numI32 15 ins.OprSize
  | TwoOperands (o1, o2) (* SXTW *)
    when ins.Opcode = Opcode.SXTW ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2 |> unwrapReg,
    AST.num0 ins.OprSize,
    numI32 31 ins.OprSize
  | FourOperands (o1, o2, o3, Immediate o4) when ins.Opcode = Opcode.SBFIZ ->
    let o3 = transOprToExpr ins ctxt addr o3
    let o3 = (* #(-<lsb> MOD 32/64) *)
      (o3 .* numI32 -1 ins.OprSize) .% (numI32 (int ins.OprSize) ins.OprSize)
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2, o3,
    transOprToExpr ins ctxt addr (Immediate (o4 - 1L))
  | FourOperands (o1, o2, Immediate o3, Immediate o4)
    when ins.Opcode = Opcode.SBFX ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr (Immediate o3),
    transOprToExpr ins ctxt addr (Immediate (o4 - o3 + 1L))
  | FourOperands _ -> transFourOprs ins ctxt addr
  | _ -> raise InvalidOperandException

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
    transBarrelShiftToExpr ins ctxt o2 o3 |> AST.not
  | FourOperands (o1, o2, o3, o4) -> (* Arithmetic *)
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transBarrelShiftToExpr ins ctxt o3 o4 |> AST.not
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
    transBarrelShiftToExpr ins ctxt o2 o3 |> AST.not
  | FourOperands (o1, o2, o3, o4) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transBarrelShiftToExpr ins ctxt o3 o4 |> AST.not
  | _ -> raise InvalidOperandException

let transOprToExprOfUBFM ins ctxt addr =
  match ins.Operands with
  | TwoOperands (o1, o2) when ins.Opcode = Opcode.UXTB ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    numI64 0L ins.OprSize,
    numI64 7L ins.OprSize
  | TwoOperands (o1, o2) when ins.Opcode = Opcode.UXTH ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    numI64 0L ins.OprSize,
    numI64 15L ins.OprSize
  | ThreeOperands (o1, o2, Immediate o3) when ins.Opcode = Opcode.LSL ->
    let opr3 = Immediate o3 (* FIXME: #(-<shift> MOD 32/64) *)
    let width = RegType.toBitWidth ins.OprSize - 1 |> int64
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr opr3,
    transOprToExpr ins ctxt addr (Immediate (width - o3))
  | ThreeOperands (o1, o2, o3) when ins.Opcode = Opcode.LSR ->
    let width = RegType.toBitWidth ins.OprSize - 1 |> int64
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3,
    transOprToExpr ins ctxt addr (Immediate width)
  | FourOperands (o1, o2, o3, Immediate o4) when ins.Opcode = Opcode.UBFIZ ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3, (* FIXME: #(-<lsb> MOD 32/64) *)
    transOprToExpr ins ctxt addr (Immediate (o4 + 1L))
  | FourOperands (o1, o2, Immediate o3, Immediate o4)
    when ins.Opcode = Opcode.UBFX ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr (Immediate o3),
    transOprToExpr ins ctxt addr (Immediate (o4 - o3 + 1L))
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
let highestSetBitForIR dst src width oprSz (ir: IRBuilder) =
  let lblLoop = !%ir "Loop"
  let lblLoopCont = !%ir "LoopContinue"
  let lblUpdateTmp = !%ir "UpdateTmp"
  let lblEnd = !%ir "End"
  let t = !+ir oprSz
  let cond = !+ir 1<rt>
  let width = numI32 (width - 1) oprSz
  !!ir (t := width)
  !!ir (AST.lmark lblLoop)
  !!ir (cond := (src >> t) .& AST.num1 oprSz == AST.num1 oprSz)
  !!ir (AST.cjmp cond (AST.name lblEnd) (AST.name lblLoopCont))
  !!ir (AST.lmark lblLoopCont)
  !!ir (cond := t == AST.num0 oprSz)
  !!ir (AST.cjmp cond (AST.name lblEnd) (AST.name lblUpdateTmp))
  !!ir (AST.lmark lblUpdateTmp)
  !!ir (t := t .- AST.num1 oprSz)
  !!ir (AST.jmp (AST.name lblLoop))
  !!ir (AST.lmark lblEnd)
  !!ir (dst := t)

/// shared/functions/common/Replicate
/// Replicate()
/// ===========
let replicateForIR dst value bits oprSize (ir: IRBuilder) =
  let lblLoop = !%ir "Loop"
  let lblEnd = !%ir "End"
  let lblLoopContinue = !%ir "LoopContinue"
  let tAmt = !+ir oprSize
  let oSz = oprSzToExpr oprSize
  let tVal = !+ir oprSize
  !!ir (tAmt := bits)
  !!ir (tVal := value)
  !!ir (AST.lmark lblLoop)
  !!ir (AST.cjmp (AST.ge tAmt oSz) (AST.name lblEnd) (AST.name lblLoopContinue))
  !!ir (AST.lmark lblLoopContinue)
  !!ir (tVal := value << tAmt)
  !!ir (tAmt := tAmt .+ bits)
  !!ir (AST.jmp (AST.name lblLoop))
  !!ir (AST.lmark lblEnd)
  !!ir (dst := tVal)  (* FIXME: Check value *)

let getMaskForIR n oprSize = (AST.num1 oprSize << n) .- AST.num1 oprSize

/// aarch64/instrs/integer/bitmasks/DecodeBitMasks
/// DecodeBitMasks()
/// ================
/// Decode AArch64 bitfield and logical immediate masks which use a similar
/// encoding structure
let decodeBitMasksForIR wmask tmask immN imms immr oprSize ir =
  let imms = AST.xtlo 8<rt> imms
  let immr = AST.xtlo 8<rt> immr
  let immN = immN << numI32 6 8<rt>
  let struct (len, levels) = tmpVars2 ir 8<rt>
  let struct (s, r) = tmpVars2 ir oprSize
  let struct (diff, esize, d) = tmpVars3 ir oprSize
  let struct (welem, telem) = tmpVars2 ir oprSize
  let n1 = AST.num1 oprSize
  let notImms = (AST.not imms) .& numI32 0x3F 8<rt>
  highestSetBitForIR len (immN .| notImms) 7 8<rt> ir
  !!ir (levels := getMaskForIR len 8<rt>) (* ZeroExtend (Ones(len), 6) *)
  !!ir (s := (imms .& levels) |> AST.zext oprSize)
  !!ir (r := (immr .& levels) |> AST.zext oprSize)
  !!ir (diff := s .- r)
  !!ir (esize := AST.num1 oprSize << AST.zext oprSize len)
  !!ir (d := diff .& getMaskForIR (AST.zext oprSize len) oprSize)
  !!ir (welem := getMaskForIR (s .+ n1) oprSize)
  !!ir (telem := getMaskForIR (d .+ n1) oprSize)
  replicateForIR wmask (ror welem r (oprSzToExpr oprSize)) esize oprSize ir
  replicateForIR tmask telem esize oprSize ir

/// shared/functions/common/CountLeadingZeroBits
/// CountLeadingZeroBits()
/// ======================
let countLeadingZeroBitsForIR dst src oprSize ir =
  highestSetBitForIR dst src (RegType.toBitWidth oprSize) oprSize ir

/// 64-bit operands generate a 64-bit result in the destination general-purpose
/// register. 32-bit operands generate a 32-bit result, zero-extended to a
/// 64-bit result in the destination general-purpose register.
let dstAssign oprSize dst src =
  let orgDst = AST.unwrap dst
  let orgDstSz = orgDst |> TypeCheck.typeOf
  if orgDstSz > oprSize then orgDst := AST.zext orgDstSz src
  elif orgDstSz = oprSize then orgDst := src
  else raise InvalidOperandSizeException

// vim: set tw=80 sts=2 sw=2:
