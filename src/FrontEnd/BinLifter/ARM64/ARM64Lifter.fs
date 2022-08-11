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

module internal B2R2.FrontEnd.BinLifter.ARM64.Lifter

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

let getPC ctxt = getRegVar ctxt R.PC

let ror src amount width = (src >> amount) .| (src << (width .- amount))

let oprSzToExpr oprSize = numI32 (RegType.toBitWidth oprSize) oprSize

let inline private (<!) (ir: IRBuilder) (s) = ir.Append (s)

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

let transOneOpr ins ctxt addr =
  match ins.Operands with
  | OneOperand o -> transOprToExpr ins ctxt addr o
  | _ -> raise InvalidOperandException

let transTwoOprs ins ctxt addr =
  match ins.Operands with
  | TwoOperands (o1, o2) -> transOprToExpr ins ctxt addr o1,
                            transOprToExpr ins ctxt addr o2
  | _ -> raise InvalidOperandException

let transThreeOprs ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> transOprToExpr ins ctxt addr o1,
                                  transOprToExpr ins ctxt addr o2,
                                  transOprToExpr ins ctxt addr o3
  | _ -> raise InvalidOperandException

let transFourOprs ins ctxt addr =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) -> transOprToExpr ins ctxt addr o1,
                                     transOprToExpr ins ctxt addr o2,
                                     transOprToExpr ins ctxt addr o3,
                                     transOprToExpr ins ctxt addr o4
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
  | VecB -> 1u, 8<rt>       (* Vector register names with element index *)
  | VecH -> 1u, 16<rt>
  | VecS -> 1u, 32<rt>
  | VecD -> 1u, 64<rt>
  | EightB -> 8u, 8<rt>     (* SIMD vector register names *)
  | SixteenB -> 16u, 8<rt>
  | FourH -> 4u, 16<rt>
  | EightH -> 8u, 16<rt>
  | TwoS -> 2u, 32<rt>
  | FourS -> 4u, 32<rt>
  | OneD -> 1u, 64<rt>
  | TwoD -> 2u, 64<rt>
  | OneQ -> 1u, 128<rt>

let getElemNumAndSize oprSize = function
  | SIMDFPScalarReg _ -> 1u, oprSize
  | SIMDVecReg (_, v) -> getElemNumAndSizeBySIMDVector v
  | SIMDVecRegWithIdx (_, v, _) -> getElemNumAndSizeBySIMDVector v

let getSIMDReg = function
  | SIMDOpr simd -> match simd with
                    | SFReg sReg -> sReg
                    | _ -> raise <| NotImplementedIRException "getSIMDReg"
  | _ -> failwith "Invalid SIMD operand"

let transOprToExprOfADD ins ctxt addr (ir: IRBuilder) =
  match ins.Operands with
  | ThreeOperands (o1, _, _) -> (* SIMD arithmetic *)
    (*
    let oSz = ins.OprSize
    let dst, s1, s2 = transThreeOprs ins ctxt addr
    let eNum, eSz = getElemNumAndSize oSz (getSIMDReg o1)
    let s1Tmps = Array.init (int eNum) (fun _ -> !+ir eSz)
    let s2Tmps = Array.init (int eNum) (fun _ -> !+ir eSz)
    let resTmps = Array.init (int eNum) (fun _ -> !+ir eSz)
    let amt = RegType.toBitWidth eSz
    for i in 0 .. (int eNum) - 1 do
      !!ir (s1Tmps[i] := AST.extract s1 eSz (i * amt))
      !!ir (s2Tmps[i] := AST.extract s2 eSz (i * amt))
      !!ir (resTmps[i] := s1Tmps[i] .+ s2Tmps[i])
    done
    !!ir (dst := AST.concatArr resTmps)
    *)
    !!ir (AST.sideEffect UnsupportedFP) (* FIXME *)
  | FourOperands _ -> (* Arithmetic *)
    let dst, s1, s2 = transFourOprsWithBarrelShift ins ctxt addr
    let result, _ = addWithCarry s1 s2 (AST.num0 ins.OprSize) ins.OprSize
    !!ir (dst := result)
  | _ -> raise InvalidOperandException

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

let separateMemExpr expr =
  match expr.E with
  | Load (_, _, { E = BinOp (BinOpType.ADD, _, b, o, _) }, _) -> b, o
  | _ -> raise InvalidOperandException

let transOprToExprOfLDP ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3 |> separateMemExpr
  | _ -> raise InvalidOperandException

let transOprToExprOfLDR ins ctxt addr (ir: IRBuilder) =
  match ins.Operands with
  | TwoOperands (o1, Memory (LiteralMode o2)) -> (* LDR (literal) *)
    let dst = transOprToExpr ins ctxt addr o1
    let offset = transOprToExpr ins ctxt addr (Memory (LiteralMode o2))
    let address = !+ir 64<rt>
    let data = !+ir ins.OprSize
    !!ir (address := getPC ctxt .+ offset)
    !!ir (data := AST.loadLE ins.OprSize address)
    !!ir (dst := data)
  | TwoOperands (o1, o2) ->
    let dst = transOprToExpr ins ctxt addr o1
    let bReg, offset = transOprToExpr ins ctxt addr o2 |> separateMemExpr
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = !+ir 64<rt>
    let data = !+ir ins.OprSize
    !!ir (address := bReg)
    !!ir (address := if isPostIndex then address .+ offset else address)
    !!ir (data := AST.loadLE ins.OprSize address)
    !!ir (dst := AST.zext ins.OprSize data)
    if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
    else if isWBack then !!ir (bReg := address) else ()
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
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3, (* FIXME: #(-<lsb> MOD 32/64) *)
    transOprToExpr ins ctxt addr (Immediate (o4 + 1L))
  | FourOperands (o1, o2, Immediate o3, Immediate o4)
    when ins.Opcode = Opcode.SBFX ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr (Immediate o3),
    transOprToExpr ins ctxt addr (Immediate (o4 - o3 + 1L))
  | FourOperands _ -> transFourOprs ins ctxt addr
  | _ -> raise InvalidOperandException

let transOprToExprOfSMADDL ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> (* SMULL *)
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3,
    getRegVar ctxt R.XZR
  | FourOperands _ -> transFourOprs ins ctxt addr
  | _ -> raise InvalidOperandException

let transOprToExprOfLDRB ins ctxt addr =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2 |> separateMemExpr
  | _ -> raise InvalidOperandException

let transOprToExprOfLDRSW ins ctxt addr (ir: IRBuilder) =
  let address = !+ir 64<rt>
  let data = !+ir 32<rt>
  match ins.Operands with
  | TwoOperands (o1, Memory (LiteralMode o2)) ->
    let dst = transOprToExpr ins ctxt addr o1
    let offset = transOprToExpr ins ctxt addr (Memory (LiteralMode o2))
    !!ir (address := getPC ctxt .+ offset)
    !!ir (data := AST.loadLE 32<rt> address)
    !!ir (dst := AST.sext 64<rt> data)

  | TwoOperands (o1, o2) ->
    let dst = transOprToExpr ins ctxt addr o1
    let bReg, offset = transOprToExpr ins ctxt addr o2 |> separateMemExpr
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    !!ir (address := bReg)
    !!ir (address :=  address .+ offset)
    !!ir (data := AST.loadLE 32<rt> address)
    !!ir (dst := AST.sext 64<rt> data)
    if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
    else if isWBack then !!ir (bReg := address) else ()
  | _ -> raise InvalidOperandException

let transOprToExprOfSTP ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3 |> separateMemExpr
  | _ -> raise InvalidOperandException

let transOprToExprOfSTR ins ctxt addr =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2 |> separateMemExpr
  | _ -> raise InvalidOperandException

let transOprToExprOfSTRB ins ctxt addr =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2 |> separateMemExpr
  | _ -> raise InvalidOperandException

let transOprToExprOfSTUR ins ctxt addr =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2 |> separateMemExpr
  | _ -> raise InvalidOperandException

let transOprToExprOfSUB ins ctxt addr ir =
  let oprSize = ins.OprSize
  match ins.Operands with
  | TwoOperands (SIMDOpr _, SIMDOpr _) -> (* FIXME: NEG SIMD Register *)
    !!ir (AST.sideEffect UnsupportedFP)
  | ThreeOperands (o1, o2, o3)
    when ins.Opcode = Opcode.SUB -> (* FIXME: SUB SIMD Register *)
    !!ir (AST.sideEffect UnsupportedFP)
  | ThreeOperands (o1, o2, o3)
    when ins.Opcode = Opcode.NEG ->
    let dst = transOprToExpr ins ctxt addr o1
    let s1 = getRegVar ctxt (if oprSize = 64<rt> then R.XZR else R.WZR)
    let s2 = transBarrelShiftToExpr ins ctxt o2 o3 |> AST.not
    let result, _ = addWithCarry s1 s2 (AST.num1 oprSize) oprSize
    !!ir (dst := result)
  | FourOperands (o1, o2, o3, o4) -> (* Arithmetic *)
    let dst = transOprToExpr ins ctxt addr o1
    let s1 = transOprToExpr ins ctxt addr o2
    let s2 = transBarrelShiftToExpr ins ctxt o3 o4 |> AST.not
    let result, _ = addWithCarry s1 s2 (AST.num1 oprSize) oprSize
    !!ir (dst := result)
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

let transOprToExprOfSUBS ins ctxt addr ir =
  let oprSize = ins.OprSize
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    let dst = transOprToExpr ins ctxt addr o1
    let s1 = getRegVar ctxt (if ins.OprSize = 64<rt> then R.XZR else R.WZR)
    let s2 = transBarrelShiftToExpr ins ctxt o2 o3 |> AST.not
    let result, (n, z, c, v) = addWithCarry s1 s2 (AST.num1 oprSize) oprSize
    !!ir (getRegVar ctxt R.N := n)
    !!ir (getRegVar ctxt R.Z := z)
    !!ir (getRegVar ctxt R.C := c)
    !!ir (getRegVar ctxt R.V := v)
    !!ir (dst := result)

  | FourOperands (o1, o2, o3, o4) ->
    let dst = transOprToExpr ins ctxt addr o1
    let s1 = transOprToExpr ins ctxt addr o2
    let s2 = transBarrelShiftToExpr ins ctxt o3 o4 |> AST.not
    let result, (n, z, c, v) = addWithCarry s1 s2 (AST.num1 oprSize) oprSize
    !!ir (getRegVar ctxt R.N := n)
    !!ir (getRegVar ctxt R.Z := z)
    !!ir (getRegVar ctxt R.C := c)
    !!ir (getRegVar ctxt R.V := v)
    !!ir (dst := result)
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
  /// Condition flag values in the set '111x' indicate always true
  | AL | NV -> AST.b1
  | _ -> failwith "Invalid condition"

// shared/functions/common/HighestSetBit
// HighestSetBit()
// ===============
let highestSetBitForIR dst src width oprSz (ir: IRBuilder) =
  let lblLoop = !%ir "Loop"
  let lblLoopCont = !%ir "LoopContinue"
  let lblUpdateTmp = !%ir "UpdateTmp"
  let lblEnd = !%ir "End"
  let t = !+ir oprSz
  let width = numI32 (width - 1) oprSz
  !!ir (t := width)
  !!ir (AST.lmark lblLoop)
  !!ir (AST.cjmp (src >> t == AST.num1 oprSz) (AST.name lblEnd)
                                               (AST.name lblLoopCont))
  !!ir (AST.lmark lblLoopCont)
  !!ir (AST.cjmp (t == AST.num0 oprSz) (AST.name lblEnd)
                                        (AST.name lblUpdateTmp))
  !!ir (AST.lmark lblUpdateTmp)
  !!ir (t := t .- AST.num1 oprSz)
  !!ir (AST.jmp (AST.name lblLoop))
  !!ir (AST.lmark lblEnd)
  !!ir (dst := width .- t)

// shared/functions/common/Replicate
// Replicate()
// ===========
let replicateForIR dst value bits oprSize (ir: IRBuilder) =
  let lblLoop = !%ir "Loop"
  let lblEnd = !%ir "End"
  let lblLoopContinue = !%ir "LoopContinue"
  let tmpAmt = !+ir oprSize
  let oSz = oprSzToExpr oprSize
  let tmpVal = !+ir oprSize
  !!ir (tmpAmt := bits)
  !!ir (tmpVal := value)
  !!ir (AST.lmark lblLoop)
  !!ir (AST.cjmp (AST.ge tmpAmt oSz)
                       (AST.name lblEnd) (AST.name lblLoopContinue))
  !!ir (AST.lmark lblLoopContinue)
  !!ir (tmpVal := value << tmpAmt)
  !!ir (tmpAmt := tmpAmt .+ bits)
  !!ir (AST.jmp (AST.name lblLoop))
  !!ir (AST.lmark lblEnd)
  !!ir (dst := tmpVal)  (* FIXME: Check value *)

let getMaskForIR n oprSize = (AST.num1 oprSize << n) .- AST.num1 oprSize

// aarch64/instrs/integer/bitmasks/DecodeBitMasks
// DecodeBitMasks()
// ================
// Decode AArch64 bitfield and logical immediate masks which use a similar
// encoding structure
let decodeBitMasksForIR wmask tmask immN imms immr oprSize ir = (* FIXME *)
  let concatSz = RegType.fromBitWidth ((RegType.toBitWidth oprSize) * 2)
  let tLen = !+ir concatSz
  let levels = !+ir oprSize
  let s, r = !+ir oprSize, !+ir oprSize
  let diff = !+ir oprSize
  let esize = !+ir oprSize
  let d = !+ir oprSize
  let welem = !+ir oprSize
  let telem = !+ir oprSize
  let n1 = AST.num1 oprSize
  let len = !+ir oprSize
  highestSetBitForIR tLen (AST.concat immN (AST.not imms))
                     (RegType.toBitWidth oprSize) concatSz ir
  !!ir (len := AST.xtlo oprSize tLen)
  !!ir (levels := AST.zext oprSize len) // ZeroExtend (Ones(len), 6)
  !!ir (s := imms .& levels)
  !!ir (r := immr .& levels)
  !!ir (diff := s .- r)
  !!ir (esize := AST.num1 oprSize << len)
  !!ir (d := diff .& getMaskForIR len oprSize)
  !!ir (welem := AST.zext oprSize (s .+ n1))
  !!ir (telem := AST.zext oprSize (d .+ n1))
  replicateForIR wmask (ror welem r (oprSzToExpr oprSize)) esize oprSize ir
  replicateForIR tmask welem esize oprSize ir

// shared/functions/common/CountLeadingZeroBits
// CountLeadingZeroBits()
// ======================
let countLeadingZeroBitsForIR dst src oprSize ir =
  highestSetBitForIR dst src (RegType.toBitWidth oprSize) oprSize ir

let sideEffects ins insLen ctxt addr name =
  let ir = !*ctxt
  !<ir insLen
  !!ir (AST.sideEffect name)
  !>ir insLen

/// A module for all AArch64-IR translation functions
let adc ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let c = AST.zext ins.OprSize (getRegVar ctxt R.C)
  !<ir insLen
  let result, _ = addWithCarry src1 src2 c ins.OprSize
  !!ir (dst := result)
  !>ir insLen

let add ins insLen ctxt addr =
  let ir = !*ctxt // FIXME
  !<ir insLen
  transOprToExprOfADD ins ctxt addr ir
  !>ir insLen

let adds ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transOprToExprOfADDS ins ctxt addr
  let oSz = ins.OprSize
  !<ir insLen
  let result, (n, z, c, v) = addWithCarry src1 src2 (AST.num0 oSz) oSz
  !!ir (getRegVar ctxt R.N := n)
  !!ir (getRegVar ctxt R.Z := z)
  !!ir (getRegVar ctxt R.C := c)
  !!ir (getRegVar ctxt R.V := v)
  !!ir (dst := result)
  !>ir insLen

let adr ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, label = transTwoOprs ins ctxt addr
  !<ir insLen
  !!ir (dst := getPC ctxt .+ label)
  !>ir insLen

let adrp ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, lbl = transTwoOprs ins ctxt addr
  !<ir insLen
  !!ir (dst := (getPC ctxt .& numI64 0xfffffffffffff000L 64<rt>) .+ lbl)
  !>ir insLen

let logAnd ins insLen ctxt addr = (* AND *)
  let ir = !*ctxt
  let dst, src1, src2 = transOprToExprOfAND ins ctxt addr
  !<ir insLen
  !!ir (dst := src1 .& src2)
  !>ir insLen

let asrv ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let amount = src2 .% oprSzToExpr ins.OprSize
  !<ir insLen
  !!ir (dst := shiftReg src1 amount ins.OprSize SRTypeASR)
  !>ir insLen

let ands ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transOprToExprOfANDS ins ctxt addr
  !<ir insLen
  !!ir (dst := src1 .& src2)
  !>ir insLen

let b ins insLen ctxt addr =
  let ir = !*ctxt
  let label = transOneOpr ins ctxt addr
  let pc = getPC ctxt
  !<ir insLen
  !!ir (AST.interjmp (pc .+ label) InterJmpKind.Base)
  !>ir insLen

let bCond ins insLen ctxt addr cond =
  let ir = !*ctxt
  let label = transOneOpr ins ctxt addr
  let pc = getPC ctxt
  !<ir insLen
  !!ir (AST.intercjmp (conditionHolds ctxt cond) (pc .+ label) pc)
  !>ir insLen

let bfm ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let dst, src, imms, immr = transOprToExprOfBFM ins ctxt addr
  let oSz = ins.OprSize
  let wmask, tmask = !+ir oSz, !+ir oSz
  let immN = if ins.OprSize = 64<rt> then AST.num1 oSz else AST.num0 oSz
  decodeBitMasksForIR wmask tmask immN imms immr oSz ir
  let width = oprSzToExpr ins.OprSize
  let bot = !+ir ins.OprSize
  !!ir (bot := (dst .& AST.not wmask) .| (ror src immr width .& wmask))
  !!ir (dst := (dst .& AST.not tmask) .| (bot .& tmask))
  !>ir insLen

let bic ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | TwoOperands _ -> (* FIXME: SIMD Register *)
    !!ir (AST.sideEffect UnsupportedFP)
  | ThreeOperands _ -> (* FIXME: SIMD Register *)
    !!ir (AST.sideEffect UnsupportedFP)
  | _ ->
    let dst, src1, src2 = transFourOprsWithBarrelShift ins ctxt addr
    !!ir (dst := src1 .& AST.not src2)
  !>ir insLen

let bics ins insLen ctxt addr =
  let dst, src1, src2 = transFourOprsWithBarrelShift ins ctxt addr
  let z = if ins.OprSize = 64<rt> then AST.num0 64<rt> else AST.num0 32<rt>
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .& AST.not src2)
  !!ir (getRegVar ctxt R.N := AST.xthi 1<rt> dst)
  !!ir (getRegVar ctxt R.Z := if dst = z then AST.b1 else AST.b0)
  !!ir (getRegVar ctxt R.C := AST.b0)
  !!ir (getRegVar ctxt R.V := AST.b0)
  !>ir insLen

let bl ins insLen ctxt addr =
  let ir = !*ctxt
  let label = transOneOpr ins ctxt addr
  let pc = getPC ctxt
  !<ir insLen
  !!ir (getRegVar ctxt R.X30 := pc .+ numI64 4L ins.OprSize)
  // FIXME: BranchTo (BType_CALL)
  !!ir (AST.interjmp (pc .+ label) InterJmpKind.IsCall)
  !>ir insLen

let blr ins insLen ctxt addr =
  let ir = !*ctxt
  let src = transOneOpr ins ctxt addr
  let pc = getPC ctxt
  !<ir insLen
  !!ir (getRegVar ctxt R.X30 := pc .+ numI64 4L ins.OprSize)
  // FIXME: BranchTo (BranchType_CALL)
  !!ir (AST.interjmp src InterJmpKind.IsCall)
  !>ir insLen

let br ins insLen ctxt addr =
  let ir = !*ctxt
  let dst = transOneOpr ins ctxt addr
  !<ir insLen
  // FIXME: BranchTo (BType_JMP)
  !!ir (AST.interjmp dst InterJmpKind.Base)
  !>ir insLen

let cbnz ins insLen ctxt addr =
  let ir = !*ctxt
  let test, label = transTwoOprs ins ctxt addr
  let pc = getPC ctxt
  !<ir insLen
  !!ir (AST.intercjmp (test != AST.num0 ins.OprSize) (pc .+ label) pc)
  !>ir insLen

let cbz ins insLen ctxt addr =
  let ir = !*ctxt
  let test, label = transTwoOprs ins ctxt addr
  let pc = getPC ctxt
  !<ir insLen
  !!ir (AST.intercjmp (test == AST.num0 ins.OprSize) (pc .+ label) pc)
  !>ir insLen

let ccmn ins insLen ctxt addr =
  let ir = !*ctxt
  let src, imm, nzcv, cond = transOprToExprOfCCMN ins ctxt addr
  !<ir insLen
  let oSz = ins.OprSize
  let tCond = !+ir 1<rt>
  !!ir (tCond := conditionHolds ctxt cond)
  let _, (n, z, c, v) = addWithCarry src imm (AST.num0 oSz) oSz
  !!ir (getRegVar ctxt R.N := (AST.ite tCond n (AST.extract nzcv 1<rt> 3)))
  !!ir (getRegVar ctxt R.Z := (AST.ite tCond z (AST.extract nzcv 1<rt> 2)))
  !!ir (getRegVar ctxt R.C := (AST.ite tCond c (AST.extract nzcv 1<rt> 1)))
  !!ir (getRegVar ctxt R.V := (AST.ite tCond v (AST.xtlo 1<rt> nzcv)))
  !>ir insLen

let ccmp ins insLen ctxt addr =
  let ir = !*ctxt
  let src, imm, nzcv, cond = transOprToExprOfCCMP ins ctxt addr
  !<ir insLen
  let tCond = conditionHolds ctxt cond
  let oSz = ins.OprSize
  let _, (n, z, c, v) = addWithCarry src (AST.not imm) (AST.num1 oSz) oSz
  !!ir (getRegVar ctxt R.N := (AST.ite tCond n (AST.extract nzcv 1<rt> 3)))
  !!ir (getRegVar ctxt R.Z := (AST.ite tCond z (AST.extract nzcv 1<rt> 2)))
  !!ir (getRegVar ctxt R.C := (AST.ite tCond c (AST.extract nzcv 1<rt> 1)))
  !!ir (getRegVar ctxt R.V := (AST.ite tCond v (AST.xtlo 1<rt> nzcv)))
  !>ir insLen

let clz ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src = transTwoOprs ins ctxt addr
  !<ir insLen
  countLeadingZeroBitsForIR dst src ins.OprSize ir
  !>ir insLen

let cmp ins insLen ctxt addr =
  let ir = !*ctxt
  let src, imm = transOprToExprOfCMP ins ctxt addr
  let oSz = ins.OprSize
  let dst = getRegVar ctxt (if oSz = 64<rt> then R.XZR else R.WZR)
  !<ir insLen
  let result, (n, z, c, v) = addWithCarry src (AST.not imm) (AST.num1 oSz) oSz
  !!ir (getRegVar ctxt R.N := n)
  !!ir (getRegVar ctxt R.Z := z)
  !!ir (getRegVar ctxt R.C := c)
  !!ir (getRegVar ctxt R.V := v)
  !!ir (dst := result)
  !>ir insLen

let csel ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2, cond = transOprToExprOfCSEL ins ctxt addr
  !<ir insLen
  !!ir (dst := AST.ite (conditionHolds ctxt cond) src1 src2)
  !>ir insLen

let csinc ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, s1, s2, cond = transOprToExprOfCSINC ins ctxt addr
  !<ir insLen
  let cond = conditionHolds ctxt cond
  !!ir (dst := AST.ite cond s1 (s2 .+ AST.num1 ins.OprSize))
  !>ir insLen

let csinv ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2, cond = transOprToExprOfCSINV ins ctxt addr
  !<ir insLen
  !!ir (dst := AST.ite (conditionHolds ctxt cond) src1 (AST.not src2))
  !>ir insLen

let csneg ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2, cond = transOprToExprOfCSNEG ins ctxt addr
  !<ir insLen
  let cond = conditionHolds ctxt cond
  !!ir (dst := AST.ite cond src1 (AST.not src2 .+ AST.num1 ins.OprSize))
  !>ir insLen

let eor ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transOprToExprOfEOR ins ctxt addr
  !<ir insLen
  !!ir (dst := src1 <+> src2)
  !>ir insLen

let extr ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2, lsb = transOprToExprOfEXTR ins ctxt addr
  let oSz = ins.OprSize
  !<ir insLen
  if oSz = 32<rt> then
    let con = !+ir 64<rt>
    !!ir (con := AST.concat src1 src2)
    let mask = numI32 0xFFFFFFFF 64<rt>
    !!ir (dst := AST.xtlo 32<rt> ((con >> (AST.zext 64<rt> lsb)) .& mask))
  elif oSz = 64<rt> then
    let lsb =
      match ins.Operands with
      | ThreeOperands (_, _, LSB shift) -> int32 shift
      | FourOperands (_, _, _, LSB lsb) -> int32 lsb
      | _ -> raise InvalidOperandException
    if lsb = 0 then !!ir (dst := src2)
    else
      let leftAmt = numI32 (64 - lsb) 64<rt>
      !!ir (dst := (src1 << leftAmt) .| (src2 >> (numI32 lsb 64<rt>)))
  else raise InvalidOperandSizeException
  !>ir insLen

let ldp ins insLen ctxt addr =
  let ir = !*ctxt
  let src1, src2, (bReg, offset) = transOprToExprOfLDP ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = !+ir 64<rt>
  let dByte = numI32 (RegType.toBitWidth ins.OprSize) 64<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := if isPostIndex then address else address .+ offset)
  !!ir (src1 := AST.loadLE ins.OprSize address)
  !!ir (src2 := AST.loadLE ins.OprSize (address .+ dByte))
  if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
  else if isWBack then !!ir (bReg := address) else ()
  !>ir insLen

let ldpsw ins insLen ctxt addr =
  let ir = !*ctxt
  let src1, src2, (bReg, offset) = transOprToExprOfLDP ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = !+ir 64<rt>
  let data1 = !+ir 32<rt>
  let data2 = !+ir 32<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := if isPostIndex then address else address .+ offset)
  !!ir (data1 := AST.loadLE 32<rt> address)
  !!ir (data2 := AST.loadLE 32<rt> (address .+ numI32 4 64<rt>))
  !!ir (src1 := AST.sext 64<rt> data1)
  !!ir (src2 := AST.sext 64<rt> data2)
  if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
  else if isWBack then !!ir (bReg := address) else ()
  !>ir insLen

let ldr ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  transOprToExprOfLDR ins ctxt addr ir
  !>ir insLen

let ldrb ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, (bReg, offset) = transOprToExprOfLDRB ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = !+ir 64<rt>
  let data = !+ir 8<rt>
  !<ir insLen
  !!ir (address := bReg)
  (* FIXME: isPostIndex *)
  !!ir (address := if isPostIndex then address .+ offset else address)
  !!ir (data := AST.loadLE 8<rt> address)
  !!ir (dst := AST.zext 32<rt> data)
  if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
  else if isWBack then !!ir (bReg := address) else ()
  !>ir insLen

let ldrh ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, (bReg, offset) = transOprToExprOfLDRB ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = !+ir 64<rt>
  let data = !+ir 16<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := if isPostIndex then address .+ offset else address)
  !!ir (data := AST.loadLE 16<rt> address)
  !!ir (dst := AST.zext 32<rt> data)
  if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
  else if isWBack then !!ir (bReg := address) else ()
  !>ir insLen

let ldrsb ins insLen ctxt addr =
  let dst, (bReg, offset) = transOprToExprOfLDRB ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let ir = !*ctxt
  let address = !+ir 64<rt>
  let data = !+ir 8<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := if isPostIndex then address else address .+ offset)
  !!ir (data := AST.loadLE 8<rt> address)
  !!ir (dst := AST.sext ins.OprSize data)
  if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
  else if isWBack then !!ir (bReg := address) else ()
  !>ir insLen

let ldrsh ins insLen ctxt addr =
  let dst, (bReg, offset) = transOprToExprOfLDRB ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let ir = !*ctxt
  let address = !+ir 64<rt>
  let data = !+ir 16<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := if isPostIndex then address else address .+ offset)
  !!ir (data := AST.loadLE 16<rt> address)
  !!ir (dst := AST.sext ins.OprSize data)
  if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
  else if isWBack then !!ir (bReg := address) else ()
  !>ir insLen

let ldrsw ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  transOprToExprOfLDRSW ins ctxt addr ir
  !>ir insLen

let ldtr ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, (bReg, offset) = transOprToExprOfLDRB ins ctxt addr
  let address = !+ir 64<rt>
  let data = !+ir ins.OprSize
  !<ir insLen
  !!ir (address := bReg .+ offset)
  !!ir (data := AST.loadLE ins.OprSize address)
  !!ir (dst := AST.zext ins.OprSize data)
  !>ir insLen

let ldur ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, (bReg, offset) = transOprToExprOfLDRB ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = !+ir 64<rt>
  let data = !+ir ins.OprSize
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := if isPostIndex then address else address .+ offset)
  !!ir (data := AST.loadLE ins.OprSize address)
  !!ir (dst := data)
  if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
  else if isWBack then !!ir (bReg := address) else ()
  !>ir insLen

let ldurb ins insLen ctxt addr =
  let ir = !*ctxt
  let src, (bReg, offset) = transOprToExprOfLDRB ins ctxt addr
  let address = !+ir 64<rt>
  let data = !+ir 8<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := address .+ offset)
  !!ir (data := AST.loadLE 8<rt> address)
  !!ir (src := AST.zext 32<rt> data)
  !>ir insLen

let ldurh ins insLen ctxt addr =
  let ir = !*ctxt
  let src, (bReg, offset) = transOprToExprOfLDRB ins ctxt addr
  let address = !+ir 64<rt>
  let data = !+ir 16<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := address .+ offset)
  !!ir (data := AST.loadLE 16<rt> address)
  !!ir (src := AST.zext 32<rt> data)
  !>ir insLen

let ldursb ins insLen ctxt addr =
  let dst, (bReg, offset) = transOprToExprOfLDRB ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let ir = !*ctxt
  let address = !+ir 64<rt>
  let data = !+ir 8<rt>
  !<ir insLen
  !!ir (address := bReg.+ offset)
  !!ir (data := AST.loadLE 8<rt> address)
  !!ir (dst := AST.sext ins.OprSize data)
  !>ir insLen

let ldursh ins insLen ctxt addr =
  let dst, (bReg, offset) = transOprToExprOfLDRB ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let ir = !*ctxt
  let address = !+ir 64<rt>
  let data = !+ir 16<rt>
  !<ir insLen
  !!ir (address := bReg.+ offset)
  !!ir (data := AST.loadLE 16<rt> address)
  !!ir (dst := AST.sext ins.OprSize data)
  !>ir insLen

let ldursw ins insLen ctxt addr =
  let dst, (bReg, offset) = transOprToExprOfLDRB ins ctxt addr
  let ir = !*ctxt
  let address = !+ir 64<rt>
  let data = !+ir 32<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := address .+ offset)
  !!ir (data := AST.loadLE 32<rt> address)
  !!ir (dst := AST.sext 64<rt> data)
  !>ir insLen

let lslv ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let oprSz = ins.OprSize
  let dataSize = numI32 (RegType.toBitWidth ins.OprSize) oprSz
  !<ir insLen
  !!ir (dst := shiftReg src1 (src2 .% dataSize) oprSz SRTypeLSL)
  !>ir insLen

let lsrv ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let oprSz = ins.OprSize
  let dataSize = numI32 (RegType.toBitWidth oprSz) oprSz
  !<ir insLen
  !!ir (dst := shiftReg src1 (src2 .% dataSize) oprSz SRTypeLSR)
  !>ir insLen

let madd ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | ThreeOperands (SIMDOpr _, SIMDOpr _, SIMDOpr _) ->
    !!ir (AST.sideEffect UnsupportedFP)
  | _ ->
    let dst, src1, src2, src3 = transOprToExprOfMADD ins ctxt addr
    !!ir (dst := src3 .+ (src1 .* src2))
  !>ir insLen

let mov ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | TwoOperands (_, SIMDOpr _) -> !!ir (AST.sideEffect UnsupportedFP)
  | _ ->
    let dst, src = transOprToExprOfMOV ins ctxt addr
    if ins.Opcode = Opcode.MOVN then !!ir (dst := AST.not src)
    else !!ir (dst := src)
  !>ir insLen

let mrs ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src = transTwoOprs ins ctxt addr
  !<ir insLen
  !!ir (dst := src) (* FIXME: AArch64.SysRegRead *)
  !>ir insLen

let msub ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2, src3 = transOprToExprOfMSUB ins ctxt addr
  !<ir insLen
  !!ir (dst := src3 .- (src1 .* src2))
  !>ir insLen

let nop insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  !>ir insLen

let orn ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | TwoOperands _ -> !!ir (AST.sideEffect UnsupportedFP)
  | ThreeOperands(SIMDOpr _, SIMDOpr _, SIMDOpr _) ->
    !!ir (AST.sideEffect UnsupportedFP)
  | _ ->
    let dst, src1, src2 = transOprToExprOfORN ins ctxt addr
    !!ir (dst := src1 .| AST.not src2)
  !>ir insLen

let orr ins insLen ctxt addr =
  let dst, src1, src2 = transOprToExprOfORR ins ctxt addr
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .| src2)
  !>ir insLen

let rbit ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src = transTwoOprs ins ctxt addr
  let datasize = if ins.OprSize = 64<rt> then 64 else 32
  let tmp = !+ir ins.OprSize
  !<ir insLen
  for i in 0 .. (datasize - 1) do
    !!ir (AST.extract tmp 1<rt> (datasize - 1 - i) := AST.extract src 1<rt> i)
  !!ir (dst := tmp)
  !>ir insLen

let ret ins insLen ctxt addr =
  let ir = !*ctxt
  let src = transOneOpr ins ctxt addr
  let target = !+ir 64<rt>
  !<ir insLen
  !!ir (target := src)
  branchTo ins ctxt target BrTypeRET InterJmpKind.IsRet ir
  !>ir insLen

let rev ins insLen ctxt addr =
  let ir = !*ctxt
  let e = if ins.OprSize = 64<rt> then 7 else 3
  let t = !+ir ins.OprSize
  !<ir insLen
  match ins.Operands with
  | TwoOperands(SIMDOpr _, SIMDOpr _) -> (* FIXME: SIMD Register *)
    !!ir (AST.sideEffect UnsupportedFP)
  | _ ->
    let dst, src = transTwoOprs ins ctxt addr
    for i in 0 .. e do
      !!ir (AST.extract t 8<rt> ((e - i) * 8) := AST.extract src 8<rt> (i * 8))
    !!ir (dst := t)
  !>ir insLen

let rev16 ins insLen ctxt addr =
  let ir = !*ctxt
  let tmp = !+ir ins.OprSize
  !<ir insLen
  match ins.Operands with
  | TwoOperands(SIMDOpr _, SIMDOpr _) -> (* FIXME: SIMD Register *)
    !!ir (AST.sideEffect UnsupportedFP)
  | _ ->
    let dst, src = transTwoOprs ins ctxt addr
    !!ir (AST.extract tmp 8<rt> 8  := AST.extract src 8<rt> 0)
    !!ir (AST.extract tmp 8<rt> 0 := AST.extract src 8<rt> 8)
    !!ir (AST.extract tmp 8<rt> 24 := AST.extract src 8<rt> 16)
    !!ir (AST.extract tmp 8<rt> 16 := AST.extract src 8<rt> 24)
    if ins.OprSize = 64<rt> then
      !!ir (AST.extract tmp 8<rt> 40:= AST.extract src 8<rt> 32)
      !!ir (AST.extract tmp 8<rt> 32:= AST.extract src 8<rt> 40)
      !!ir (AST.extract tmp 8<rt> 52:= AST.extract src 8<rt> 48)
      !!ir (AST.extract tmp 8<rt> 48:= AST.extract src 8<rt> 56)
      !!ir (dst := tmp)
    !!ir (dst := tmp)
  !>ir insLen

let rev32 ins insLen ctxt addr =
  let ir = !*ctxt
  let tmp = !+ir ins.OprSize
  !<ir insLen
  match ins.Operands with
  | TwoOperands(SIMDOpr _, SIMDOpr _) -> (* FIXME: SIMD Register *)
    !!ir (AST.sideEffect UnsupportedFP)
  | _ ->
    let dst, src = transTwoOprs ins ctxt addr
    !!ir (AST.extract tmp 8<rt> 24:= AST.extract src 8<rt> 0)
    !!ir (AST.extract tmp 8<rt> 16:= AST.extract src 8<rt> 8)
    !!ir (AST.extract tmp 8<rt> 8:= AST.extract src 8<rt> 16)
    !!ir (AST.extract tmp 8<rt> 0:= AST.extract src 8<rt> 24)
    if ins.OprSize = 64<rt> then
      !!ir (AST.extract tmp 8<rt> 56:= AST.extract src 8<rt> 32)
      !!ir (AST.extract tmp 8<rt> 48:= AST.extract src 8<rt> 40)
      !!ir (AST.extract tmp 8<rt> 40:= AST.extract src 8<rt> 48)
      !!ir (AST.extract tmp 8<rt> 32:= AST.extract src 8<rt> 56)
      !!ir (dst := tmp)
    else
    !!ir (dst := tmp)
  !>ir insLen

let rorv ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let amount = src2 .% oprSzToExpr ins.OprSize
  !<ir insLen
  !!ir (dst := shiftReg src1 amount ins.OprSize SRTypeROR)
  !>ir insLen

let sbc ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let c = AST.zext ins.OprSize (getRegVar ctxt R.C)
  !<ir insLen
  let result, _ = addWithCarry src1 (AST.not src2) c ins.OprSize
  !!ir (dst := result)
  !>ir insLen

let sbfm ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src, immr, imms = transOprToExprOfSBFM ins ctxt addr
  let oprSz = ins.OprSize
  let bot, top = !+ir oprSz, !+ir oprSz
  let wmask, tmask = !+ir oprSz, !+ir oprSz
  let immN = if oprSz = 64<rt> then AST.num1 oprSz else AST.num0 oprSz
  let width = oprSzToExpr oprSz
  !<ir insLen
  decodeBitMasksForIR wmask tmask immN imms immr oprSz ir
  !!ir (bot := ror src immr width .& wmask)
  replicateForIR top src imms oprSz ir
  !!ir (dst := (top .& AST.not tmask) .| (bot .& tmask))
  !>ir insLen

let sdiv ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let cond = src2 == AST.num0 ins.OprSize
  !<ir insLen
  (* FIXME: RoundTowardsZero *)
  !!ir (dst := AST.ite cond (AST.num0 ins.OprSize) (src1 ./ src2))
  !>ir insLen

let smaddl ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2, src3 = transOprToExprOfSMADDL ins ctxt addr
  !<ir insLen
  !!ir (dst := src3 .+ (AST.sext 64<rt> src1 .* AST.sext 64<rt> src2))
  !>ir insLen

let smsubl ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2, src3 = transOprToExprOfSMADDL ins ctxt addr
  !<ir insLen
  !!ir (dst := src3 .- (AST.sext 64<rt> src1 .* AST.sext 64<rt> src2))
  !>ir insLen

let smulh ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let tSrc1B = !+ir 64<rt>
  let tSrc1A = !+ir 64<rt>
  let tSrc2B = !+ir 64<rt>
  let tSrc2A = !+ir 64<rt>
  let n32 = numI32 32 64<rt>
  let mask = numI64 0xFFFFFFFFL 64<rt>
  !<ir insLen
  !!ir (tSrc1B := (src1 >> n32) .& mask)
  !!ir (tSrc1A := src1 .& mask)
  !!ir (tSrc2B := (src2 >> n32) .& mask)
  !!ir (tSrc2A := src2 .& mask)
  let high = tSrc1B .* tSrc2B
  let mid = (tSrc1A .* tSrc2B) .+ (tSrc1B .* tSrc2A)
  let low = (tSrc1A .* tSrc2A) >> n32
  !!ir (dst := high .+ ((mid .+ low) >> n32)) (* [127:64] *)
  !>ir insLen

let stp ins insLen ctxt addr =
  let ir = !*ctxt
  let src1, src2, (bReg, offset) = transOprToExprOfSTP ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = !+ir 64<rt>
  let dByte = numI32 (RegType.toBitWidth ins.OprSize) 64<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := if isPostIndex then address else address .+ offset)
  !!ir (AST.loadLE ins.OprSize address := src1)
  !!ir (AST.loadLE ins.OprSize (address .+ dByte) := src2)
  if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
  else if isWBack then !!ir (bReg := address) else ()
  !>ir insLen

let str ins insLen ctxt addr =
  let ir = !*ctxt
  let src, (bReg, offset) = transOprToExprOfSTR ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = !+ir 64<rt>
  let data = !+ir ins.OprSize
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := if isPostIndex then address else address .+ offset)
  !!ir (data := src)
  !!ir (AST.loadLE ins.OprSize address := data)
  if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
  else if isWBack then !!ir (bReg := address) else ()
  !>ir insLen

let strb ins insLen ctxt addr =
  let ir = !*ctxt
  let src, (bReg, offset) = transOprToExprOfSTRB ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = !+ir 64<rt>
  let data = !+ir 8<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := if isPostIndex then address else address .+ offset)
  !!ir (data := AST.xtlo 8<rt> src)
  !!ir (AST.loadLE 8<rt> address := data)
  if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
  else if isWBack then !!ir (bReg := address) else ()
  !>ir insLen

let strh ins insLen ctxt addr =
  let ir = !*ctxt
  let src, (bReg, offset) = transOprToExprOfSTRB ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = !+ir 64<rt>
  let data = !+ir 16<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := if isPostIndex then address else address .+ offset)
  !!ir (data := AST.xtlo 16<rt> src)
  !!ir (AST.loadLE 16<rt> address := data)
  if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
  else if isWBack then !!ir (bReg := address) else ()
  !>ir insLen

let stur ins insLen ctxt addr =
  let ir = !*ctxt
  let src, (bReg, offset) = transOprToExprOfSTUR ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = !+ir 64<rt>
  let data = !+ir ins.OprSize
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := if isPostIndex then address else address .+ offset)
  !!ir (data := src)
  !!ir (AST.loadLE ins.OprSize address := data)
  if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
  else if isWBack then !!ir (bReg := address) else ()
  !>ir insLen

let sturb ins insLen ctxt addr =
  let ir = !*ctxt
  let src, (bReg, offset) = transOprToExprOfSTUR ins ctxt addr
  let address = !+ir 64<rt>
  let data = !+ir 8<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := address .+ offset)
  !!ir (data := AST.xtlo 8<rt> src)
  !!ir (AST.loadLE 8<rt> address := data)
  !>ir insLen

let sturh ins insLen ctxt addr =
  let ir = !*ctxt
  let src, (bReg, offset) = transOprToExprOfSTUR ins ctxt addr
  let address = !+ir 64<rt>
  let data = !+ir 16<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := address .+ offset)
  !!ir (data := AST.xtlo 16<rt> src)
  !!ir (AST.loadLE 16<rt> address := data)
  !>ir insLen

let sub ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  transOprToExprOfSUB ins ctxt addr ir
  !>ir insLen

let subs ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  transOprToExprOfSUBS ins ctxt addr ir
  !>ir insLen

let tbnz ins insLen ctxt addr =
  let ir = !*ctxt
  let test, imm, label = transThreeOprs ins ctxt addr
  let pc = getPC ctxt
  let cond = (test >> imm .& AST.num1 ins.OprSize) == AST.num1 ins.OprSize
  !<ir insLen
  !!ir (AST.intercjmp cond (pc .+ label) pc)
  !>ir insLen

let tbz ins insLen ctxt addr =
  let ir = !*ctxt
  let test, imm, label = transThreeOprs ins ctxt addr
  let pc = getPC ctxt
  let cond = (test >> imm .& AST.num1 ins.OprSize) == AST.num0 ins.OprSize
  !<ir insLen
  !!ir (AST.intercjmp cond (pc .+ label) pc)
  !>ir insLen

let udiv ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let cond = src2 == AST.num0 ins.OprSize
  !<ir insLen
  !!ir // FIXME: RoundTwoardsZero
    (dst := AST.ite cond (AST.num0 ins.OprSize) (src1 ./ src2))
  !>ir insLen

let umaddl ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2, src3 = transOprToExprOfUMADDL ins ctxt addr
  !<ir insLen
  !!ir (dst := src3 .+ (AST.zext 64<rt> src1 .* AST.zext 64<rt> src2))
  !>ir insLen

let umsubl ins insLen ctxt addr =
  let dst, src1, src2, src3 = transOprToExprOfUMADDL ins ctxt addr
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src3 .- (AST.zext 64<rt> src1 .* AST.zext 64<rt> src2))
  !>ir insLen

let umulh ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let tSrc1B = !+ir 64<rt>
  let tSrc1A = !+ir 64<rt>
  let tSrc2B = !+ir 64<rt>
  let tSrc2A = !+ir 64<rt>
  let n32 = numI32 32 64<rt>
  let mask = numI64 0xFFFFFFFFL 64<rt>
  !<ir insLen
  !!ir (tSrc1B := (src1 >> n32) .& mask)
  !!ir (tSrc1A := src1 .& mask)
  !!ir (tSrc2B := (src2 >> n32) .& mask)
  !!ir (tSrc2A := src2 .& mask)
  let high = tSrc1B .* tSrc2B
  let mid = (tSrc1A .* tSrc2B) .+ (tSrc1B .* tSrc2A)
  let low = (tSrc1A .* tSrc2A) >> n32
  !!ir (dst := high .+ ((mid .+ low) >> n32)) (* [127:64] *)
  !>ir insLen

let ubfm ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src, immr, imms = transOprToExprOfUBFM ins ctxt addr
  let oSz = ins.OprSize
  let bot = !+ir oSz
  let wmask, tmask = !+ir oSz, !+ir oSz
  let immN = if ins.OprSize = 64<rt> then AST.num1 oSz else AST.num0 oSz
  decodeBitMasksForIR wmask tmask immN imms immr oSz ir
  let width = oprSzToExpr ins.OprSize
  !<ir insLen
  !!ir (bot := ror src immr width .& wmask)
  !!ir (dst := bot .& tmask)
  !>ir insLen

/// The logical shift left(or right) is the alias of LS{L|R}V and UBFM.
/// Therefore, it is necessary to distribute to the original instruction.
let distLogcalShift ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (_, _, Immediate _) -> ubfm ins ctxt addr
  | ThreeOperands (_, _, OprRegister _) when ins.Opcode = Opcode.LSL ->
    lslv ins ctxt addr
  | ThreeOperands (_, _, OprRegister _) when ins.Opcode = Opcode.LSR ->
    lsrv ins ctxt addr
  | _ -> raise InvalidOperandException

/// Translate IR.
let translate ins insLen ctxt =
  let addr = ins.Address
  match ins.Opcode with
  | Opcode.ADC -> adc ins insLen ctxt addr
  | Opcode.ADD -> add ins insLen ctxt addr
  | Opcode.ADDS | Opcode.CMN -> adds ins insLen ctxt addr
  | Opcode.ADDP | Opcode.ADDV -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.ADR -> adr ins insLen ctxt addr
  | Opcode.ADRP -> adrp ins insLen ctxt addr
  | Opcode.AND -> logAnd ins insLen ctxt addr
  | Opcode.ANDS -> ands ins insLen ctxt addr
  | Opcode.ASR -> asrv ins insLen ctxt addr
  | Opcode.B -> b ins insLen ctxt addr
  | Opcode.BEQ -> bCond ins insLen ctxt addr EQ
  | Opcode.BNE -> bCond ins insLen ctxt addr NE
  | Opcode.BCS -> bCond ins insLen ctxt addr CS
  | Opcode.BCC -> bCond ins insLen ctxt addr CC
  | Opcode.BMI -> bCond ins insLen ctxt addr MI
  | Opcode.BPL -> bCond ins insLen ctxt addr PL
  | Opcode.BVS -> bCond ins insLen ctxt addr VS
  | Opcode.BVC -> bCond ins insLen ctxt addr VC
  | Opcode.BHI -> bCond ins insLen ctxt addr HI
  | Opcode.BLS -> bCond ins insLen ctxt addr LS
  | Opcode.BGE -> bCond ins insLen ctxt addr GE
  | Opcode.BLT -> bCond ins insLen ctxt addr LT
  | Opcode.BGT -> bCond ins insLen ctxt addr GT
  | Opcode.BLE -> bCond ins insLen ctxt addr LE
  | Opcode.BAL -> bCond ins insLen ctxt addr AL
  | Opcode.BNV -> bCond ins insLen ctxt addr NV
  | Opcode.BFI | Opcode.BFXIL -> bfm ins insLen ctxt addr
  | Opcode.BIC -> bic ins insLen ctxt addr
  | Opcode.BICS -> bics ins insLen ctxt addr
  | Opcode.BIF | Opcode.BIT -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.BL -> bl ins insLen ctxt addr
  | Opcode.BLR -> blr ins insLen ctxt addr
  | Opcode.BR -> br ins insLen ctxt addr
  | Opcode.BRK -> sideEffects ins insLen ctxt addr Breakpoint
  | Opcode.BSL -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.CBNZ -> cbnz ins insLen ctxt addr
  | Opcode.CBZ -> cbz ins insLen ctxt addr
  | Opcode.CCMN -> ccmn ins insLen ctxt addr
  | Opcode.CCMP -> ccmp ins insLen ctxt addr
  | Opcode.CLZ -> clz ins insLen ctxt addr
  | Opcode.CMP -> cmp ins insLen ctxt addr
  | Opcode.CMEQ -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.CMGE | Opcode.CMLT | Opcode.CMTST ->
    sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.CMHI | Opcode.CMHS -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.CNEG | Opcode.CSNEG -> csneg ins insLen ctxt addr
  | Opcode.CNT -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.CSEL -> csel ins insLen ctxt addr
  | Opcode.CSETM | Opcode.CINV | Opcode.CSINV -> csinv ins insLen ctxt addr
  | Opcode.CSINC | Opcode.CINC | Opcode.CSET -> csinc ins insLen ctxt addr
  | Opcode.DUP -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.EOR | Opcode.EON -> eor ins insLen ctxt addr
  | Opcode.EXT -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.EXTR | Opcode.ROR -> extr ins insLen ctxt addr
  | Opcode.FABS -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.FABD | Opcode.FADD -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.FADDP -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.FCCMP -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.FCMP -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.FCMPE -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.FCSEL -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.FCVT | Opcode.FCVTMU ->
    sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.FCVTZS -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.FCVTZU -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.FDIV -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.FMAX -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.FMADD -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.FMOV -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.FMUL -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.FNEG -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.FNMUL -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.FRINTM | Opcode.FRINTA | Opcode.FRINTP ->
    sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.FSUB -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.FSQRT -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.FMSUB -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.INS -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.LDP -> ldp ins insLen ctxt addr
  | Opcode.LDPSW -> ldpsw ins insLen ctxt addr
  | Opcode.LDR -> ldr ins insLen ctxt addr
  | Opcode.LDRB -> ldrb ins insLen ctxt addr
  | Opcode.LDRSB -> ldrsb ins insLen ctxt addr
  | Opcode.LDRH -> ldrh ins insLen ctxt addr
  | Opcode.LDRSW -> ldrsw ins insLen ctxt addr
  | Opcode.LDRSH -> ldrsh ins insLen ctxt addr
  | Opcode.LDUR -> ldur ins insLen ctxt addr
  | Opcode.LDURB -> ldurb ins insLen ctxt addr
  | Opcode.LDURH -> ldurh ins insLen ctxt addr
  | Opcode.LDURSB -> ldursb ins insLen ctxt addr
  | Opcode.LDURSH -> ldursh ins insLen ctxt addr
  | Opcode.LDURSW -> ldursw ins insLen ctxt addr
  | Opcode.LD1 | Opcode.LD1R | Opcode.LD2 | Opcode.LD2R | Opcode.LD3
  | Opcode.LD3R | Opcode.LD4 | Opcode.LD4R ->
    sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.LSL | Opcode.LSR -> distLogcalShift ins insLen ctxt addr
  | Opcode.MADD -> madd ins insLen ctxt addr
  | Opcode.MLA -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.MNEG -> msub ins insLen ctxt addr
  | Opcode.MOV | Opcode.MOVN | Opcode.MOVK | Opcode.MOVZ ->
    mov ins insLen ctxt addr
  | Opcode.MOVI | Opcode.MVNI -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.MRS -> mrs ins insLen ctxt addr
  | Opcode.MSUB -> msub ins insLen ctxt addr
  | Opcode.MUL -> madd ins insLen ctxt addr
  | Opcode.MVN -> orn ins insLen ctxt addr
  | Opcode.NEG -> sub ins insLen ctxt addr
  | Opcode.NEGS -> subs ins insLen ctxt addr
  | Opcode.NOP -> nop insLen ctxt
  | Opcode.ORN -> orn ins insLen ctxt addr
  | Opcode.ORR -> orr ins insLen ctxt addr
  | Opcode.RBIT -> rbit ins insLen ctxt addr
  | Opcode.RET -> ret ins insLen ctxt addr
  | Opcode.REV -> rev ins insLen ctxt addr
  | Opcode.REV16 -> rev16 ins insLen ctxt addr
  | Opcode.REV32 -> rev32 ins insLen ctxt addr
  | Opcode.REV64 -> rev ins insLen ctxt addr
  | Opcode.RORV -> rorv ins insLen ctxt addr
  | Opcode.SBC -> sbc ins insLen ctxt addr
  | Opcode.SBFIZ | Opcode.SBFX | Opcode.SXTB | Opcode.SXTH | Opcode.SXTW ->
    sbfm ins insLen ctxt addr
  | Opcode.SCVTF -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.SDIV -> sdiv ins insLen ctxt addr
  | Opcode.SMADDL | Opcode.SMULL -> smaddl ins insLen ctxt addr
  | Opcode.SMSUBL | Opcode.SMNEGL -> smsubl ins insLen ctxt addr
  | Opcode.SMULH -> smulh ins insLen ctxt addr
  | Opcode.SSHR | Opcode.SSHL |Opcode.SSHLL | Opcode.SSHLL2 | Opcode.SHL ->
    sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.ST1 | Opcode.ST2 | Opcode.ST3 | Opcode.ST4 ->
    sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.STP -> stp ins insLen ctxt addr
  | Opcode.STR -> str ins insLen ctxt addr
  | Opcode.STRB -> strb ins insLen ctxt addr
  | Opcode.STRH -> strh ins insLen ctxt addr
  | Opcode.STUR -> stur ins insLen ctxt addr
  | Opcode.STURB -> sturb ins insLen ctxt addr
  | Opcode.STURH -> sturh ins insLen ctxt addr
  | Opcode.SUB -> sub ins insLen ctxt addr
  | Opcode.SUBS -> subs ins insLen ctxt addr
  | Opcode.TBL -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.TBNZ -> tbnz ins insLen ctxt addr
  | Opcode.TBZ -> tbz ins insLen ctxt addr
  | Opcode.TST -> ands ins insLen ctxt addr
  | Opcode.UADDLV | Opcode.UADDW | Opcode.UMAXV | Opcode.UMINV ->
    sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.UBFIZ | Opcode.UBFX | Opcode.UXTB | Opcode.UXTH ->
    ubfm ins insLen ctxt addr
  | Opcode.UCVTF -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.UDIV -> udiv ins insLen ctxt addr
  | Opcode.UMAX -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.UMADDL | Opcode.UMULL -> umaddl ins insLen ctxt addr
  | Opcode.UMLAL | Opcode.UMLAL2 ->
    sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.UMSUBL | Opcode.UMNEGL -> umsubl ins insLen ctxt addr
  | Opcode.UMULH -> umulh ins insLen ctxt addr
  | Opcode.UMOV -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.URSHL ->  sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.USHL -> sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.USHLL | Opcode.USHLL2 | Opcode.USHR ->
    sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.UZP1 | Opcode.UZP2 | Opcode.ZIP1 | Opcode.ZIP2 ->
    sideEffects ins insLen ctxt addr UnsupportedFP
  | Opcode.XTN | Opcode.XTN2 -> sideEffects ins insLen ctxt addr UnsupportedFP
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException (Disasm.opCodeToString o)

// vim: set tw=80 sts=2 sw=2:
