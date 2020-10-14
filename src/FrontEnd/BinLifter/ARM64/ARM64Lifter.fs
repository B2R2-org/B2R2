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
open B2R2.BinIR.LowUIR.AST
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ARM64

let inline getRegVar (ctxt: TranslationContext) name =
  Register.toRegID name |> ctxt.GetRegVar

let getPC ctxt = getRegVar ctxt R.PC

let ror src amount width = (src >> amount) .| (src << (width .- amount))

let numI32 n t = BitVector.ofInt32 n t |> num // FIXME: exists in IntelLifter
let numI64 n t = BitVector.ofInt64 n t |> num

let oprSzToExpr oprSize = numI32 (RegType.toBitWidth oprSize) oprSize

let inline private (<!) (builder: StmtBuilder) (s) = builder.Append (s)

// shared/functions/integer/AddWithCarry
// AddWithCarry()
// ==============
// Integer addition with carry input, returning result and NZCV flags
let addWithCarry opr1 opr2 carryIn oSz =
  let result = opr1 .+ opr2 .+ carryIn
  let n = extractHigh 1<rt> result
  let z = relop RelOpType.EQ result (num0 oSz)
  let c = gt opr1 result
  let o1 = extractHigh 1<rt> opr1
  let o2 = extractHigh 1<rt> opr2
  let r = extractHigh 1<rt> result
  let v = (o1 == o2) .& (o1 <+> r)
  result, (n, z, c, v)

// aarch64/instrs/integer/shiftreg/ShiftReg
// ShiftReg()
// ==========
// Perform shift of a register operand
let shiftReg reg amount oprSize = function
  | SRTypeLSL -> reg << amount
  | SRTypeLSR -> reg >> amount
  | SRTypeASR -> reg ?>> amount
  | SRTypeROR -> ror reg amount (oprSzToExpr oprSize)
  | _ -> raise InvalidOperandException

let transShiftAmout ctxt oprSize = function
  | Imm amt -> numI64 amt oprSize
  | Reg amt -> getRegVar ctxt amt

// shared/functions/common/Extend
// Extend()
// ========
let extend reg oprSize isUnsigned =
  if isUnsigned then zExt oprSize reg else sExt oprSize reg

// aarch64/instrs/extendreg/ExtendReg
// ExtendReg()
// ===========
// Perform a register extension and shift
let extendReg ctxt reg typ shift oprSize =
  let reg = getRegVar ctxt reg
  let shift = match shift with
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
  extend ((extractLow rTyp  reg) << numI32 shift rTyp) oprSize isUnsigned

let transSIMDRegToExpr ctxt = function
  | SIMDFPScalarReg reg -> getRegVar ctxt reg
  | SIMDVecReg (reg, v) -> getRegVar ctxt reg
  | SIMDVecRegWithIdx (reg, v, idx) -> getRegVar ctxt reg

let transSIMD ctxt = function
  | SFReg reg -> transSIMDRegToExpr ctxt reg
  | OneReg s -> raise <| NotImplementedIRException "OneReg"
  | TwoRegs (s1, s2) -> raise <| NotImplementedIRException "TwoRegs"
  | ThreeRegs (s1, s2, s3) -> raise <| NotImplementedIRException "ThreeRegs"
  | FourRegs (s1, s2, s3, s4) -> raise <| NotImplementedIRException "FourRegs"

let transImmOffset ctxt (addr: Addr) = function
  | BaseOffset (bReg, Some imm) -> getRegVar ctxt bReg .+ numI64 imm 64<rt>
  | BaseOffset (bReg, None) -> getRegVar ctxt bReg
  | Lbl lbl -> numI64 (int64 addr + lbl) 64<rt>

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

let transMemOffset ins ctxt addr = function
  | ImmOffset immOffset -> transImmOffset ctxt addr immOffset
  | RegOffset (bReg, reg, regOffset) ->
    transRegOffset ins ctxt (bReg, reg, regOffset)

let transBaseMode ins ctxt addr offset =
  transMemOffset ins ctxt addr offset |> loadLE 64<rt>

let transMem ins ctxt addr = function
  | BaseMode offset -> transBaseMode ins ctxt addr offset
  | PreIdxMode offset -> transBaseMode ins ctxt addr offset
  | PostIdxMode offset -> transBaseMode ins ctxt addr offset
  | LiteralMode offset -> transBaseMode ins ctxt addr offset

let transOprToExpr ins ctxt addr = function
  | OprRegister reg -> getRegVar ctxt reg
  | Memory mem -> transMem ins ctxt addr mem
  | SIMDOpr simd -> transSIMD ctxt simd
  | Immediate imm -> num <| BitVector.ofInt64 imm ins.OprSize
  | NZCV nzcv -> num <| BitVector.ofInt64 (int64 nzcv) ins.OprSize
  | LSB lsb -> num <| BitVector.ofInt64 (int64 lsb) ins.OprSize
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

let transOprToExprOfADD ins ctxt addr (builder: StmtBuilder) =
  match ins.Operands with
  | ThreeOperands (o1, _, _) -> (* SIMD arithmetic *)
    let oSz = ins.OprSize
    let dst, s1, s2 = transThreeOprs ins ctxt addr
    let eNum, eSz = getElemNumAndSize oSz (getSIMDReg o1)
    let s1Tmps = Array.init (int eNum) (fun _ -> tmpVar eSz)
    let s2Tmps = Array.init (int eNum) (fun _ -> tmpVar eSz)
    let resTmps = Array.init (int eNum) (fun _ -> tmpVar eSz)
    let amt = RegType.toBitWidth eSz
    for i in 0 .. (int eNum) - 1 do
      builder <! (s1Tmps.[i] := extract s1 eSz (i * amt))
      builder <! (s2Tmps.[i] := extract s2 eSz (i * amt))
      builder <! (resTmps.[i] := s1Tmps.[i] .+ s2Tmps.[i])
    done
    builder <! (dst := concatExprs resTmps)
  | FourOperands (_, _, _, _) -> (* Arithmetic *)
    let dst, s1, s2 = transFourOprsWithBarrelShift ins ctxt addr
    let result, _ = addWithCarry s1 s2 (num0 ins.OprSize) ins.OprSize
    builder <! (dst := result)
  | _ -> raise InvalidOperandException

let transOprToExprOfADDS ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> (* CMN *)
    getRegVar ctxt (if ins.OprSize = 64<rt> then R.XZR else R.WZR),
    transOprToExpr ins ctxt addr o1,
    transBarrelShiftToExpr ins ctxt o2 o3
  | FourOperands (_, _, _, _) ->
    transFourOprsWithBarrelShift ins ctxt addr
  | _ -> raise InvalidOperandException

let transOprToExprOfAND ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (_, _, _) -> transThreeOprs ins ctxt addr
  | FourOperands (_, _, _, _) ->
    transFourOprsWithBarrelShift ins ctxt addr
  | _ -> raise InvalidOperandException

let transOprToExprOfANDS ins ctxt addr =
  match ins.Operands with
  | TwoOperands (o1, o2) -> (* TST (immediate) *)
    getRegVar ctxt (if ins.OprSize = 64<rt> then R.XZR else R.WZR),
    transOprToExpr ins ctxt addr o1, transOprToExpr ins ctxt addr o2
  | ThreeOperands (o1, o2, o3) when ins.Opcode = Opcode.TST -> (* TST (shfed) *)
    getRegVar ctxt (if ins.OprSize = 64<rt> then R.XZR else R.WZR),
    transOprToExpr ins ctxt addr o1, transBarrelShiftToExpr ins ctxt o2 o3
  | ThreeOperands (_, _, _) -> transThreeOprs ins ctxt addr
  | FourOperands (_, _, _, _) -> transFourOprsWithBarrelShift ins ctxt addr
  | _ -> raise InvalidOperandException

let transOprToExprOfBFM ins ctxt addr =
  match ins.Operands with
  | FourOperands (o1, o2, o3, Immediate o4) when ins.Opcode = Opcode.BFI ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3, (* FIXME: #(-<lsb> MOD 32/64) *)
    transOprToExpr ins ctxt addr (Immediate (o4 + 1L))
  | FourOperands (o1, o2, Immediate o3, Immediate o4) when ins.Opcode = Opcode.BFXIL ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr (Immediate o3),
    transOprToExpr ins ctxt addr (Immediate (o4 - o3 + 1L))
  | FourOperands (_, _, _, _) -> transFourOprs ins ctxt addr
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
  | _ -> raise InvalidOperandException

let transOprToExprOfCSNEG ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, Cond o3) -> (* CNEG *)
    let o2 = transOprToExpr ins ctxt addr o2
    transOprToExpr ins ctxt addr o1, o2, o2, invertCond o3
  | _ -> raise InvalidOperandException

let transOprToExprOfEOR ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (_, _, _) -> transThreeOprs ins ctxt addr
  | FourOperands (o1, o2, o3, o4) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transBarrelShiftToExpr ins ctxt o3 o4
  | _ -> raise InvalidOperandException

let transOprToExprOfEXTR ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> (* ROR *)
    let o2 = transOprToExpr ins ctxt addr o2
    transOprToExpr ins ctxt addr o1, o2, o2, transOprToExpr ins ctxt addr o3
  | FourOperands (_, _, _, _) -> transFourOprs ins ctxt addr
  | _ -> raise InvalidOperandException

let getIsWBackAndIsPostIndexByAddrMode = function
  | BaseMode _ -> false, false
  | PreIdxMode _ -> true, false
  | PostIdxMode _ -> true, true
  | _ -> failwith "None"

let getIsWBackAndIsPostIndex = function
  | TwoOperands (_, Memory mem) -> getIsWBackAndIsPostIndexByAddrMode mem
  | ThreeOperands (_, _, Memory mem) -> getIsWBackAndIsPostIndexByAddrMode mem
  | _ -> raise InvalidOperandException

let separateMemExpr expr =
  let getExpr = function
    | Load (e, t, expr, _, _) -> expr
    | _ -> failwith "None"
  match getExpr expr with
  | BinOp (BinOpType.ADD, _, b, o, _, _) -> b, o
  | _ -> failwith "None"

let transOprToExprOfLDP ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3 |> separateMemExpr
  | _ -> raise InvalidOperandException

let transOprToExprOfLDR ins ctxt addr (builder: StmtBuilder) =
  match ins.Operands with
  | TwoOperands (o1, Memory (LiteralMode o2)) -> (* LDR (literal) *)
    let dst = transOprToExpr ins ctxt addr o1
    let offset = transOprToExpr ins ctxt addr (Memory (LiteralMode o2))
    let address = tmpVar 64<rt>
    let data = tmpVar ins.OprSize
    builder <! (address := getPC ctxt .+ offset)
    builder <! (data := loadLE ins.OprSize address)
    builder <! (dst := data)
  | TwoOperands (o1, o2) ->
    let dst = transOprToExpr ins ctxt addr o1
    let bReg, offset = transOprToExpr ins ctxt addr o2 |> separateMemExpr
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar 64<rt>
    let data = tmpVar ins.OprSize
    builder <! (address := bReg)
    builder <! (address := if isPostIndex then address .+ offset else address)
    builder <! (data := loadLE ins.OprSize address)
    builder <! (dst := zExt ins.OprSize data)
    if isWBack && isPostIndex then builder <! (bReg := address .+ offset)
    else if isWBack then builder <! (bReg := address) else ()
  | _ -> raise InvalidOperandException

let transOprToExprOfMADD ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3,
    getRegVar ctxt (if ins.OprSize = 64<rt> then R.XZR else R.WZR)
  | FourOperands (_, _, _, _) -> transFourOprs ins ctxt addr
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
  | _ -> raise InvalidOperandException

let transOprToExprOfORR ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (_, _, _) -> transThreeOprs ins ctxt addr
  | FourOperands (o1, o2, o3, o4) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transBarrelShiftToExpr ins ctxt o3 o4
  | _ -> raise InvalidOperandException

let unwrapReg = function
  | Extract (e, 32<rt>, 0, _, _) -> e
  | _ -> failwith "Invalid register"

let transOprToExprOfSBFM ins ctxt addr =
  match ins.Operands with
  | TwoOperands (o1, o2) -> (* SXTW *)
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2 |> unwrapReg,
    num0 ins.OprSize,
    numI32 32 ins.OprSize
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
  | FourOperands (_, _, _, _) -> transFourOprs ins ctxt addr
  | _ -> raise InvalidOperandException

let transOprToExprOfSMADDL ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> (* SMULL *)
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3,
    getRegVar ctxt R.XZR
  | FourOperands (_, _, _, _) -> transFourOprs ins ctxt addr
  | _ -> raise InvalidOperandException

let transOprToExprOfLDRB ins ctxt addr =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2 |> separateMemExpr
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

let transOprToExprOfSUB ins ctxt addr builder =
  let oprSize = ins.OprSize
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> (* NEG: Arithmetic *)
    let dst = transOprToExpr ins ctxt addr o1
    let s1 = getRegVar ctxt (if oprSize = 64<rt> then R.XZR else R.WZR)
    let s2 = transBarrelShiftToExpr ins ctxt o2 o3 |> not
    let result, _ = addWithCarry s1 s2 (num1 oprSize) oprSize
    builder <! (dst := result)
  | FourOperands (o1, o2, o3, o4) -> (* Arithmetic *)
    let dst = transOprToExpr ins ctxt addr o1
    let s1 = transOprToExpr ins ctxt addr o2
    let s2 = transBarrelShiftToExpr ins ctxt o3 o4 |> not
    let result, _ = addWithCarry s1 s2 (num1 oprSize) oprSize
    builder <! (dst := result)
  | _ -> raise InvalidOperandException

let transOprToExprOfUMADDL ins ctxt addr =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> (* UMULL *)
    transOprToExpr ins ctxt addr o1,
    transOprToExpr ins ctxt addr o2,
    transOprToExpr ins ctxt addr o3,
    getRegVar ctxt R.XZR
  | FourOperands (_, _, _, _) -> transFourOprs ins ctxt addr
  | _ -> raise InvalidOperandException

let transOprToExprOfSUBS ins ctxt addr builder =
  let oprSize = ins.OprSize
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    let dst = transOprToExpr ins ctxt addr o1
    let s1 = transOprToExpr ins ctxt addr o2
    let s2 = transBarrelShiftToExpr ins ctxt o3 o4 |> not
    let result, (n, z, c, v) = addWithCarry s1 s2 (num1 oprSize) oprSize
    builder <! (getRegVar ctxt R.N := n)
    builder <! (getRegVar ctxt R.Z := z)
    builder <! (getRegVar ctxt R.C := c)
    builder <! (getRegVar ctxt R.V := v)
    builder <! (dst := result)
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

// shared/functions/memory/BranchAddr
// BranchAddr()
// ============
// Return the virtual address with tag bits removed for storing to the
// program counter.
// let branchAddr vaddress el

// shared/functions/registers/BranchTo
// BranchTo()
// ==========
// Set program counter to a new address, which may include a tag in the top
// eight bits, with a branch reason hint for possible use by hardware fetching
// the next instruction.
let branchTo ins ctxt target brType i (builder: StmtBuilder) =
  builder <! (InterJmp (getPC ctxt, target, i)) // FIXME: BranchAddr function

// shared/functions/system/ConditionHolds
// ConditionHolds()
// ================
// Return TRUE iff COND currently holds
let conditionHolds ctxt = function
  | EQ -> getRegVar ctxt R.Z == b1
  | NE -> getRegVar ctxt R.Z == b0
  | CS -> getRegVar ctxt R.C == b1
  | CC -> getRegVar ctxt R.C == b0
  | MI -> getRegVar ctxt R.N == b1
  | PL -> getRegVar ctxt R.N == b0
  | VS -> getRegVar ctxt R.V == b1
  | VC -> getRegVar ctxt R.V == b0
  | HI -> (getRegVar ctxt R.C == b1) .& (getRegVar ctxt R.Z == b0)
  | LS -> not ((getRegVar ctxt R.C == b1) .& (getRegVar ctxt R.Z == b0))
  | GE -> getRegVar ctxt R.N == getRegVar ctxt R.V
  | LT -> getRegVar ctxt R.N != getRegVar ctxt R.V
  | GT -> (getRegVar ctxt R.N == getRegVar ctxt R.V) .&
          (getRegVar ctxt R.Z == b0)
  | LE -> not ((getRegVar ctxt R.N == getRegVar ctxt R.V) .&
               (getRegVar ctxt R.Z == b0))
  /// Condition flag values in the set '111x' indicate always true
  | AL | NV -> b1
  | _ -> failwith "Invalid condition"

// shared/functions/common/HighestSetBit
// HighestSetBit()
// ===============
let highestSetBitForIR dst src width oprSz (builder: StmtBuilder) =
  let lblLoop = lblSymbol "Loop"
  let lblLoopCont = lblSymbol "LoopContinue"
  let lblUpdateTmp = lblSymbol "UpdateTmp"
  let lblEnd = lblSymbol "End"
  let t = tmpVar oprSz
  let width = numI32 (width - 1) oprSz
  builder <! (t := width)
  builder <! (LMark lblLoop)
  builder <! (CJmp (src >> t == num1 oprSz, Name lblEnd, Name lblLoopCont))
  builder <! (LMark lblLoopCont)
  builder <! (CJmp (t == num0 oprSz, Name lblEnd, Name lblUpdateTmp))
  builder <! (LMark lblUpdateTmp)
  builder <! (t := t .- num1 oprSz)
  builder <! (Jmp (Name lblLoop))
  builder <! (LMark lblEnd)
  builder <! (dst := width .- t)

// shared/functions/common/Replicate
// Replicate()
// ===========
let replicateForIR dst value bits oprSize (builder: StmtBuilder) =
  let lblLoop = lblSymbol "Loop"
  let lblEnd = lblSymbol "End"
  let lblLoopContinue = lblSymbol "LoopContinue"
  let tmpAmt = tmpVar oprSize
  let oSz = oprSzToExpr oprSize
  let tmpVal = tmpVar oprSize
  builder <! (tmpAmt := bits)
  builder <! (tmpVal := value)
  builder <! (LMark lblLoop)
  builder <! (CJmp (ge tmpAmt oSz, Name lblEnd, Name lblLoopContinue))
  builder <! (LMark lblLoopContinue)
  builder <! (tmpVal := value << tmpAmt)
  builder <! (tmpAmt := tmpAmt .+ bits)
  builder <! (Jmp (Name lblLoop))
  builder <! (LMark lblEnd)
  builder <! (dst := tmpVal)  (* FIXME: Check value *)

let getMaskForIR n oprSize = (num1 oprSize << n) .- num1 oprSize

// aarch64/instrs/integer/bitmasks/DecodeBitMasks
// DecodeBitMasks()
// ================
// Decode AArch64 bitfield and logical immediate masks which use a similar
// encoding structure
let decodeBitMasksForIR wmask tmask immN imms immr isImm oprSize builder =
  let concatSz = RegType.fromBitWidth ((RegType.toBitWidth oprSize) * 2)
  let tLen = tmpVar concatSz
  let levels = tmpVar oprSize
  let S, R = tmpVar oprSize, tmpVar oprSize
  let diff = tmpVar oprSize
  let esize = tmpVar oprSize
  let d = tmpVar oprSize
  let welem = tmpVar oprSize
  let telem = tmpVar oprSize
  let n1 = num1 oprSize
  let len = tmpVar oprSize
  highestSetBitForIR tLen (concat immN (not imms)) (RegType.toBitWidth oprSize)
    concatSz builder
  builder <! (len := extractLow oprSize tLen)
  builder <! (levels := zExt oprSize len) // ZeroExtend (Ones(len), 6)
  builder <! (S := imms .& levels)
  builder <! (R := immr .& levels)
  builder <! (diff := S .- R)
  builder <! (esize := num1 oprSize << len)
  builder <! (d := diff .& getMaskForIR len oprSize)
  builder <! (welem := zExt oprSize (S .+ n1))
  builder <! (telem := zExt oprSize (d .+ n1))
  replicateForIR wmask (ror welem R (oprSzToExpr oprSize)) esize oprSize builder
  replicateForIR tmask welem esize oprSize builder

// shared/functions/common/CountLeadingZeroBits
// CountLeadingZeroBits()
// ======================
let countLeadingZeroBitsForIR dst src oprSize builder =
  highestSetBitForIR dst src (RegType.toBitWidth oprSize) oprSize builder

let startMark ins addr (builder: StmtBuilder) =
  builder <! (ISMark (addr, ins.NumBytes))

let endMark ins addr (builder: StmtBuilder) =
  builder <! (IEMark (uint64 ins.NumBytes + addr)); builder

let sideEffects ins addr name =
  let builder = new StmtBuilder (4)
  startMark ins addr builder
  builder <! (SideEffect name)
  endMark ins addr builder

/// A module for all AArch64-IR translation functions
let add ins ctxt addr =
  let builder = new StmtBuilder (32) // FIXME
  startMark ins addr builder
  transOprToExprOfADD ins ctxt addr builder
  endMark ins addr builder

let adds ins ctxt addr =
  let builder = new StmtBuilder (8)
  let dst, src1, src2 = transOprToExprOfADDS ins ctxt addr
  let oSz = ins.OprSize
  startMark ins addr builder
  let result, (n, z, c, v) = addWithCarry src1 src2 (num0 oSz) oSz
  builder <! (getRegVar ctxt R.N := n)
  builder <! (getRegVar ctxt R.Z := z)
  builder <! (getRegVar ctxt R.C := c)
  builder <! (getRegVar ctxt R.V := v)
  builder <! (dst := result)
  endMark ins addr builder

let adr ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst, label = transTwoOprs ins ctxt addr
  startMark ins addr builder
  builder <! (dst := getPC ctxt .+ label)
  endMark ins addr builder

let adrp ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst, lbl = transTwoOprs ins ctxt addr
  startMark ins addr builder
  builder <! (dst := (getPC ctxt .& numI64 0xfffffffffffff000L 64<rt>) .+ lbl)
  endMark ins addr builder

let logAnd ins ctxt addr = (* AND *)
  let builder = new StmtBuilder (4)
  let dst, src1, src2 = transOprToExprOfAND ins ctxt addr
  startMark ins addr builder
  builder <! (dst := src1 .& src2)
  endMark ins addr builder

let asrv ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let amount = src2 .% oprSzToExpr ins.OprSize
  startMark ins addr builder
  builder <! (dst := shiftReg src1 amount ins.OprSize SRTypeASR)
  endMark ins addr builder

let ands ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst, src1, src2 = transOprToExprOfANDS ins ctxt addr
  startMark ins addr builder
  builder <! (dst := src1 .& src2)
  endMark ins addr builder

let b ins ctxt addr =
  let builder = new StmtBuilder (4)
  let label = transOneOpr ins ctxt addr
  let pc = getPC ctxt
  startMark ins addr builder
  builder <! (InterJmp (pc, pc .+ label, InterJmpInfo.Base))
  endMark ins addr builder

let bCond ins ctxt addr cond =
  let builder = new StmtBuilder (4)
  let label = transOneOpr ins ctxt addr
  let pc = getPC ctxt
  startMark ins addr builder
  builder <! (InterCJmp (conditionHolds ctxt cond, pc, pc .+ label, pc))
  endMark ins addr builder

let bfm ins ctxt addr =
  let builder = new StmtBuilder (64)
  let dst, src, imms, immr = transOprToExprOfBFM ins ctxt addr
  let oSz = ins.OprSize
  let wmask, tmask = tmpVar oSz, tmpVar oSz
  let immN = if ins.OprSize = 64<rt> then num1 oSz else num0 oSz
  decodeBitMasksForIR wmask tmask immN imms immr (num0 oSz) oSz builder
  let width = oprSzToExpr ins.OprSize
  let bot = tmpVar ins.OprSize
  startMark ins addr builder
  builder <! (bot := (dst .& not wmask) .| (ror src immr width .& wmask))
  builder <! (dst := (dst .& not tmask) .| (bot .& tmask))
  endMark ins addr builder

let bic ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst, src1, src2 = transFourOprsWithBarrelShift ins ctxt addr
  startMark ins addr builder
  builder <! (dst := src1 .& not src2)
  endMark ins addr builder

let bl ins ctxt addr =
  let builder = new StmtBuilder (4)
  let label = transOneOpr ins ctxt addr
  let pc = getPC ctxt
  startMark ins addr builder
  builder <! (getRegVar ctxt R.X30 := pc .+ numI64 4L ins.OprSize)
  // FIXME: BranchTo (BType_CALL)
  builder <! (InterJmp (pc, pc .+ label, InterJmpInfo.IsCall))
  endMark ins addr builder

let blr ins ctxt addr =
  let builder = new StmtBuilder (4)
  let src = transOneOpr ins ctxt addr
  let pc = getPC ctxt
  startMark ins addr builder
  builder <! (getRegVar ctxt R.X30 := pc .+ numI64 4L ins.OprSize)
  // FIXME: BranchTo (BranchType_CALL)
  builder <! (InterJmp (pc, src, InterJmpInfo.IsCall))
  endMark ins addr builder

let br ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst = transOneOpr ins ctxt addr
  startMark ins addr builder
  // FIXME: BranchTo (BType_JMP)
  builder <! (InterJmp (getPC ctxt, dst, InterJmpInfo.Base))
  endMark ins addr builder

let cbnz ins ctxt addr =
  let builder = new StmtBuilder (4)
  let test, label = transTwoOprs ins ctxt addr
  let pc = getPC ctxt
  startMark ins addr builder
  builder <! (InterCJmp (test != num0 ins.OprSize, pc, pc .+ label, pc))
  endMark ins addr builder

let cbz ins ctxt addr =
  let builder = new StmtBuilder (4)
  let test, label = transTwoOprs ins ctxt addr
  let pc = getPC ctxt
  startMark ins addr builder
  builder <! (InterCJmp (test == num0 ins.OprSize, pc, pc .+ label, pc))
  endMark ins addr builder

let ccmn ins ctxt addr =
  let builder = new StmtBuilder (8)
  let src, imm, nzcv, cond = transOprToExprOfCCMN ins ctxt addr
  startMark ins addr builder
  let oSz = ins.OprSize
  let tCond = tmpVar 1<rt>
  builder <! (tCond := conditionHolds ctxt cond)
  let _, (n, z, c, v) = addWithCarry src imm (num0 oSz) oSz
  builder <! (getRegVar ctxt R.N := (ite tCond n (extract nzcv 1<rt> 3)))
  builder <! (getRegVar ctxt R.Z := (ite tCond z (extract nzcv 1<rt> 2)))
  builder <! (getRegVar ctxt R.C := (ite tCond c (extract nzcv 1<rt> 1)))
  builder <! (getRegVar ctxt R.V := (ite tCond v (extractLow 1<rt> nzcv)))
  endMark ins addr builder

let ccmp ins ctxt addr =
  let builder = new StmtBuilder (8)
  let src, imm, nzcv, cond = transOprToExprOfCCMP ins ctxt addr
  startMark ins addr builder
  let tCond = conditionHolds ctxt cond
  let oSz = ins.OprSize
  let _, (n, z, c, v) = addWithCarry src (not imm) (num1 oSz) oSz
  builder <! (getRegVar ctxt R.N := (ite tCond n (extract nzcv 1<rt> 3)))
  builder <! (getRegVar ctxt R.Z := (ite tCond z (extract nzcv 1<rt> 2)))
  builder <! (getRegVar ctxt R.C := (ite tCond c (extract nzcv 1<rt> 1)))
  builder <! (getRegVar ctxt R.V := (ite tCond v (extractLow 1<rt> nzcv)))
  endMark ins addr builder

let clz ins ctxt addr =
  let builder = new StmtBuilder (16)
  let dst, src = transTwoOprs ins ctxt addr
  startMark ins addr builder
  countLeadingZeroBitsForIR dst src ins.OprSize builder
  endMark ins addr builder

let cmp ins ctxt addr =
  let builder = StmtBuilder (8)
  let src, imm = transOprToExprOfCMP ins ctxt addr
  let oSz = ins.OprSize
  let dst = getRegVar ctxt (if oSz = 64<rt> then R.XZR else R.WZR)
  let opr1 = tmpVar oSz
  let opr2 = tmpVar oSz
  startMark ins addr builder
  let result, (n, z, c, v) = addWithCarry src (not imm) (num1 oSz) oSz
  builder <! (getRegVar ctxt R.N := n)
  builder <! (getRegVar ctxt R.Z := z)
  builder <! (getRegVar ctxt R.C := c)
  builder <! (getRegVar ctxt R.V := v)
  builder <! (dst := result)
  endMark ins addr builder

let csel ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst, src1, src2, cond = transOprToExprOfCSEL ins ctxt addr
  startMark ins addr builder
  builder <! (dst := ite (conditionHolds ctxt cond) src1 src2)
  endMark ins addr builder

let csinc ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst, s1, s2, cond = transOprToExprOfCSINC ins ctxt addr
  startMark ins addr builder
  builder <! (dst := ite (conditionHolds ctxt cond) s1 (s2 .+ num1 ins.OprSize))
  endMark ins addr builder

let csinv ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst, src1, src2, cond = transOprToExprOfCSINV ins ctxt addr
  startMark ins addr builder
  builder <! (dst := ite (conditionHolds ctxt cond) src1 (not src2))
  endMark ins addr builder

let csneg ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst, src1, src2, cond = transOprToExprOfCSNEG ins ctxt addr
  startMark ins addr builder
  let cond = conditionHolds ctxt cond
  builder <! (dst := ite cond src1 (not src2 .+ num1 ins.OprSize))
  endMark ins addr builder

let eor ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst, src1, src2 = transOprToExprOfEOR ins ctxt addr
  startMark ins addr builder
  builder <! (dst := src1 <+> src2)
  endMark ins addr builder

let extr ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst, src1, src2, lsb = transOprToExprOfEXTR ins ctxt addr
  let oSz = ins.OprSize
  let conSize = if oSz = 64<rt> then 128<rt> else 64<rt>
  let con = tmpVar conSize
  let mask = num (BitVector.ofUBInt (RegType.getMask oSz) conSize)
  startMark ins addr builder
  builder <! (con := concat src1 src2)
  builder <! (dst := extractLow oSz ((con >> (zExt conSize lsb)) .& mask))
  endMark ins addr builder

let ldp ins ctxt addr =
  let builder = new StmtBuilder (8)
  let src1, src2, (bReg, offset) = transOprToExprOfLDP ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = tmpVar 64<rt>
  let dByte = numI32 (RegType.toBitWidth ins.OprSize) 64<rt>
  startMark ins addr builder
  builder <! (address := bReg)
  builder <! (address := if isPostIndex then address else address .+ offset)
  builder <! (src1 := loadLE ins.OprSize address)
  builder <! (src2 := loadLE ins.OprSize (address .+ dByte))
  if isWBack && isPostIndex then builder <! (bReg := address .+ offset)
  else if isWBack then builder <! (bReg := address) else ()
  endMark ins addr builder

let ldr ins ctxt addr =
  let builder = new StmtBuilder (8)
  startMark ins addr builder
  transOprToExprOfLDR ins ctxt addr builder
  endMark ins addr builder

let ldrb ins ctxt addr =
  let builder = new StmtBuilder (8)
  let dst, (bReg, offset) = transOprToExprOfLDRB ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = tmpVar 64<rt>
  let data = tmpVar 8<rt>
  startMark ins addr builder
  builder <! (address := bReg)
  builder <! (address := if isPostIndex then address .+ offset else address)
  builder <! (data := loadLE 8<rt> address)
  builder <! (dst := zExt 32<rt> data)
  if isWBack && isPostIndex then builder <! (bReg := address .+ offset)
  else if isWBack then builder <! (bReg := address) else ()
  endMark ins addr builder

let ldrh ins ctxt addr =
  let builder = new StmtBuilder (8)
  let dst, (bReg, offset) = transOprToExprOfLDRB ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = tmpVar 64<rt>
  let data = tmpVar 16<rt>
  startMark ins addr builder
  builder <! (address := bReg)
  builder <! (address := if isPostIndex then address .+ offset else address)
  builder <! (data := loadLE 16<rt> address)
  builder <! (dst := zExt 32<rt> data)
  if isWBack && isPostIndex then builder <! (bReg := address .+ offset)
  else if isWBack then builder <! (bReg := address) else ()
  endMark ins addr builder

let ldrsw ins ctxt addr =
  let builder = new StmtBuilder (8)
  let dst, (bReg, offset) = transOprToExprOfLDRB ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = tmpVar 64<rt>
  let data = tmpVar 32<rt>
  startMark ins addr builder
  builder <! (address := bReg)
  builder <! (address := if isPostIndex then address else address .+ offset)
  builder <! (data := loadLE 32<rt> address)
  builder <! (dst := sExt 64<rt> data)
  if isWBack && isPostIndex then builder <! (bReg := address .+ offset)
  else if isWBack then builder <! (bReg := address) else ()
  endMark ins addr builder

let ldur ins ctxt addr =
  let builder = new StmtBuilder (8)
  let dst, (bReg, offset) = transOprToExprOfLDRB ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = tmpVar 64<rt>
  let data = tmpVar ins.OprSize
  startMark ins addr builder
  builder <! (address := bReg)
  builder <! (address := if isPostIndex then address else address .+ offset)
  builder <! (data := loadLE ins.OprSize address)
  builder <! (dst := data)
  if isWBack && isPostIndex then builder <! (bReg := address .+ offset)
  else if isWBack then builder <! (bReg := address) else ()
  endMark ins addr builder

let ldurb ins ctxt addr =
  let builder = new StmtBuilder (8)
  let src, (bReg, offset) = transOprToExprOfLDRB ins ctxt addr
  let address = tmpVar 64<rt>
  let data = tmpVar 8<rt>
  startMark ins addr builder
  builder <! (address := bReg)
  builder <! (address := address .+ offset)
  builder <! (data := loadLE 8<rt> address)
  builder <! (src := zExt 32<rt> data)
  endMark ins addr builder

let lslv ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let oprSz = ins.OprSize
  let dataSize = numI32 (RegType.toBitWidth ins.OprSize) oprSz
  startMark ins addr builder
  builder <! (dst := shiftReg src1 (src2 .% dataSize) oprSz SRTypeLSL)
  endMark ins addr builder

let lsrv ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let oprSz = ins.OprSize
  let dataSize = numI32 (RegType.toBitWidth oprSz) oprSz
  startMark ins addr builder
  builder <! (dst := shiftReg src1 (src2 .% dataSize) oprSz SRTypeLSR)
  endMark ins addr builder

let madd ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst, src1, src2, src3 = transOprToExprOfMADD ins ctxt addr
  startMark ins addr builder
  builder <! (dst := src3 .+ (src1 .* src2))
  endMark ins addr builder

let mov ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst, src = transOprToExprOfMOV ins ctxt addr
  startMark ins addr builder
  match ins.Opcode with
  | Opcode.MOVN -> builder <! (dst := not src)
  | Opcode.MOVZ | Opcode.MOVK | Opcode.MOV -> builder <! (dst := src)
  | _ -> failwith "Invalid Move wide Opcode"
  endMark ins addr builder

let mrs ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst, src = transTwoOprs ins ctxt addr
  startMark ins addr builder
  builder <! (dst := src) (* FIXME: AArch64.SysRegRead *)
  endMark ins addr builder

let msub ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst, src1, src2, src3 = transFourOprs ins ctxt addr
  startMark ins addr builder
  builder <! (dst := src3 .- (src1 .* src2))
  endMark ins addr builder

let nop ins addr =
  let builder = new StmtBuilder (4)
  startMark ins addr builder
  endMark ins addr builder

let orn ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst, src1, src2 = transOprToExprOfORN ins ctxt addr
  startMark ins addr builder
  builder <! (dst := src1 .| not src2)
  endMark ins addr builder

let orr ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst, src1, src2 = transOprToExprOfORR ins ctxt addr
  startMark ins addr builder
  builder <! (dst := src1 .| src2)
  endMark ins addr builder

let ret ins ctxt addr =
  let builder = new StmtBuilder (4)
  let src = transOneOpr ins ctxt addr
  let target = tmpVar 64<rt>
  startMark ins addr builder
  builder <! (target := src)
  branchTo ins ctxt target BrTypeRET InterJmpInfo.IsRet builder
  endMark ins addr builder

let sbc ins ctxt addr =
  let builder = StmtBuilder (8)
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let c = zExt ins.OprSize (getRegVar ctxt R.C)
  startMark ins addr builder
  let result, _ = addWithCarry src1 src2 c ins.OprSize
  builder <! (dst := result)
  endMark ins addr builder

let sbfm ins ctxt addr =
  let builder = new StmtBuilder (64)
  let dst, src, immr, imms = transOprToExprOfSBFM ins ctxt addr
  let oprSz = ins.OprSize
  let bot, top = tmpVar oprSz, tmpVar oprSz
  let wmask, tmask = tmpVar oprSz, tmpVar oprSz
  let immN = if oprSz = 64<rt> then num1 oprSz else num0 oprSz
  let width = oprSzToExpr oprSz
  startMark ins addr builder
  decodeBitMasksForIR wmask tmask immN imms immr (num0 oprSz) oprSz builder
  builder <! (bot := ror src immr width .& wmask)
  replicateForIR top src imms oprSz builder
  builder <! (dst := (top .& not tmask) .| (bot .& tmask))
  endMark ins addr builder

let smaddl ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst, src1, src2, src3 = transOprToExprOfSMADDL ins ctxt addr
  startMark ins addr builder
  builder <! (dst := src3 .+ (sExt 64<rt> src1 .* sExt 64<rt> src2))
  endMark ins addr builder

let smulh ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let result = tmpVar 128<rt>
  startMark ins addr builder
  builder <! (result := sExt 128<rt> src1 .* sExt 128<rt> src2)
  builder <! (dst := extractHigh 64<rt> result)
  endMark ins addr builder

let stp ins ctxt addr =
  let builder = new StmtBuilder (8)
  let src1, src2, (bReg, offset) = transOprToExprOfSTP ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = tmpVar 64<rt>
  let dByte = numI32 (RegType.toBitWidth ins.OprSize) 64<rt>
  startMark ins addr builder
  builder <! (address := bReg)
  builder <! (address := if isPostIndex then address else address .+ offset)
  builder <! (loadLE ins.OprSize address := src1)
  builder <! (loadLE ins.OprSize (address .+ dByte) := src2)
  if isWBack && isPostIndex then builder <! (bReg := address .+ offset)
  else if isWBack then builder <! (bReg := address) else ()
  endMark ins addr builder

let str ins ctxt addr =
  let builder = new StmtBuilder (8)
  let src, (bReg, offset) = transOprToExprOfSTR ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = tmpVar 64<rt>
  let data = tmpVar ins.OprSize
  startMark ins addr builder
  builder <! (address := bReg)
  builder <! (address := if isPostIndex then address else address .+ offset)
  builder <! (data := src)
  builder <! (loadLE ins.OprSize address := data)
  if isWBack && isPostIndex then builder <! (bReg := address .+ offset)
  else if isWBack then builder <! (bReg := address) else ()
  endMark ins addr builder

let strb ins ctxt addr =
  let builder = new StmtBuilder (8)
  let src, (bReg, offset) = transOprToExprOfSTRB ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = tmpVar 64<rt>
  let data = tmpVar 8<rt>
  startMark ins addr builder
  builder <! (address := bReg)
  builder <! (address := if isPostIndex then address else address .+ offset)
  builder <! (data := extractLow 8<rt> src)
  builder <! (loadLE 8<rt> address := data)
  if isWBack && isPostIndex then builder <! (bReg := address .+ offset)
  else if isWBack then builder <! (bReg := address) else ()
  endMark ins addr builder

let strh ins ctxt addr =
  let builder = new StmtBuilder (8)
  let src, (bReg, offset) = transOprToExprOfSTRB ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = tmpVar 64<rt>
  let data = tmpVar 16<rt>
  startMark ins addr builder
  builder <! (address := bReg)
  builder <! (address := if isPostIndex then address else address .+ offset)
  builder <! (data := extractLow 16<rt> src)
  builder <! (loadLE 16<rt> address := data)
  if isWBack && isPostIndex then builder <! (bReg := address .+ offset)
  else if isWBack then builder <! (bReg := address) else ()
  endMark ins addr builder

let stur ins ctxt addr =
  let builder = new StmtBuilder (8)
  let src, (bReg, offset) = transOprToExprOfSTUR ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = tmpVar 64<rt>
  let data = tmpVar ins.OprSize
  startMark ins addr builder
  builder <! (address := bReg)
  builder <! (address := if isPostIndex then address else address .+ offset)
  builder <! (data := src)
  builder <! (loadLE ins.OprSize address := data)
  if isWBack && isPostIndex then builder <! (bReg := address .+ offset)
  else if isWBack then builder <! (bReg := address) else ()
  endMark ins addr builder

let sturb ins ctxt addr =
  let builder = new StmtBuilder (8)
  let src, (bReg, offset) = transOprToExprOfSTUR ins ctxt addr
  let address = tmpVar 64<rt>
  let data = tmpVar 8<rt>
  startMark ins addr builder
  builder <! (address := bReg)
  builder <! (address := address .+ offset)
  builder <! (data := extractLow 8<rt> src)
  builder <! (loadLE 8<rt> address := data)
  endMark ins addr builder

let sturh ins ctxt addr =
  let builder = new StmtBuilder (8)
  let src, (bReg, offset) = transOprToExprOfSTUR ins ctxt addr
  let address = tmpVar 64<rt>
  let data = tmpVar 16<rt>
  startMark ins addr builder
  builder <! (address := bReg)
  builder <! (address := address .+ offset)
  builder <! (data := extractLow 16<rt> src)
  builder <! (loadLE 16<rt> address := data)
  endMark ins addr builder

let sub ins ctxt addr =
  let builder = new StmtBuilder (8)
  startMark ins addr builder
  transOprToExprOfSUB ins ctxt addr builder
  endMark ins addr builder

let subs ins ctxt addr =
  let builder = new StmtBuilder (8)
  startMark ins addr builder
  transOprToExprOfSUBS ins ctxt addr builder
  endMark ins addr builder

let tbnz ins ctxt addr =
  let builder = new StmtBuilder (4)
  let test, imm, label = transThreeOprs ins ctxt addr
  let pc = getPC ctxt
  let cond = (test >> imm .& num1 ins.OprSize) == num1 ins.OprSize
  startMark ins addr builder
  builder <! (InterCJmp (cond, pc, pc .+ label, pc))
  endMark ins addr builder

let tbz ins ctxt addr =
  let builder = new StmtBuilder (4)
  let test, imm, label = transThreeOprs ins ctxt addr
  let pc = getPC ctxt
  let cond = (test >> imm .& num1 ins.OprSize) == num0 ins.OprSize
  startMark ins addr builder
  builder <! (InterCJmp (cond, pc, pc .+ label, pc))
  endMark ins addr builder

let udiv ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let cond = src2 == num0 ins.OprSize
  startMark ins addr builder
  builder <! // FIXME: RoundTwoardsZero
    (dst := ite cond (num0 ins.OprSize) (src1 ./ src2))
  endMark ins addr builder

let umaddl ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst, src1, src2, src3 = transOprToExprOfUMADDL ins ctxt addr
  startMark ins addr builder
  builder <! (dst := src3 .+ (zExt 64<rt> src1 .* zExt 64<rt> src2))
  endMark ins addr builder

let umulh ins ctxt addr =
  let builder = new StmtBuilder (4)
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let result = tmpVar 128<rt>
  startMark ins addr builder
  builder <! (result := zExt 128<rt> src1 .* zExt 128<rt> src2)
  builder <! (dst := extractHigh 64<rt> result)
  endMark ins addr builder

let ubfm ins ctxt addr =
  let builder = new StmtBuilder (64)
  let dst, src, immr, imms = transOprToExprOfUBFM ins ctxt addr
  let oSz = ins.OprSize
  let bot = tmpVar oSz
  let wmask, tmask = tmpVar oSz, tmpVar oSz
  let immN = if ins.OprSize = 64<rt> then num1 oSz else num0 oSz
  decodeBitMasksForIR wmask tmask immN imms immr (num0 oSz) oSz builder
  let width = oprSzToExpr ins.OprSize
  startMark ins addr builder
  builder <! (bot := ror src immr width .& wmask)
  builder <! (dst := bot .& tmask)
  endMark ins addr builder

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
let translate ins ctxt =
  let addr = ins.Address
  match ins.Opcode with
  | Opcode.ADD -> add ins ctxt addr
  | Opcode.ADDS | Opcode.CMN -> adds ins ctxt addr
  | Opcode.ADR -> adr ins ctxt addr
  | Opcode.ADRP -> adrp ins ctxt addr
  | Opcode.AND -> logAnd ins ctxt addr
  | Opcode.ANDS -> ands ins ctxt addr
  | Opcode.ASR -> asrv ins ctxt addr
  | Opcode.B -> b ins ctxt addr
  | Opcode.BEQ -> bCond ins ctxt addr EQ
  | Opcode.BNE -> bCond ins ctxt addr NE
  | Opcode.BCS -> bCond ins ctxt addr CS
  | Opcode.BCC -> bCond ins ctxt addr CC
  | Opcode.BMI -> bCond ins ctxt addr MI
  | Opcode.BPL -> bCond ins ctxt addr PL
  | Opcode.BVS -> bCond ins ctxt addr VS
  | Opcode.BVC -> bCond ins ctxt addr VC
  | Opcode.BHI -> bCond ins ctxt addr HI
  | Opcode.BLS -> bCond ins ctxt addr LS
  | Opcode.BGE -> bCond ins ctxt addr GE
  | Opcode.BLT -> bCond ins ctxt addr LT
  | Opcode.BGT -> bCond ins ctxt addr GT
  | Opcode.BLE -> bCond ins ctxt addr LE
  | Opcode.BAL -> bCond ins ctxt addr AL
  | Opcode.BNV -> bCond ins ctxt addr NV
  | Opcode.BFI | Opcode.BFXIL -> bfm ins ctxt addr
  | Opcode.BIC -> bic ins ctxt addr
  | Opcode.BL -> bl ins ctxt addr
  | Opcode.BLR -> blr ins ctxt addr
  | Opcode.BR -> br ins ctxt addr
  | Opcode.CBNZ -> cbnz ins ctxt addr
  | Opcode.CBZ -> cbz ins ctxt addr
  | Opcode.CCMN -> ccmn ins ctxt addr
  | Opcode.CCMP -> ccmp ins ctxt addr
  | Opcode.CLZ -> clz ins ctxt addr
  | Opcode.CMP -> cmp ins ctxt addr
  | Opcode.CNEG -> csneg ins ctxt addr
  | Opcode.CSEL -> csel ins ctxt addr
  | Opcode.CSETM -> csinv ins ctxt addr
  | Opcode.CSINC | Opcode.CINC | Opcode.CSET -> csinc ins ctxt addr
  | Opcode.EOR -> eor ins ctxt addr
  | Opcode.EXTR | Opcode.ROR -> extr ins ctxt addr
  | Opcode.FADD -> sideEffects ins addr UnsupportedFP
  | Opcode.FADDP -> sideEffects ins addr UnsupportedFP
  | Opcode.FCMPE -> sideEffects ins addr UnsupportedFP
  | Opcode.FCVTZU -> sideEffects ins addr UnsupportedFP
  | Opcode.FDIV -> sideEffects ins addr UnsupportedFP
  | Opcode.FMOV -> sideEffects ins addr UnsupportedFP
  | Opcode.FMUL -> sideEffects ins addr UnsupportedFP
  | Opcode.FSUB -> sideEffects ins addr UnsupportedFP
  | Opcode.LDP -> ldp ins ctxt addr
  | Opcode.LDR -> ldr ins ctxt addr
  | Opcode.LDRB -> ldrb ins ctxt addr
  | Opcode.LDRH -> ldrh ins ctxt addr
  | Opcode.LDRSW -> ldrsw ins ctxt addr
  | Opcode.LDUR -> ldur ins ctxt addr
  | Opcode.LDURB -> ldur ins ctxt addr
  | Opcode.LSL | Opcode.LSR -> distLogcalShift ins ctxt addr
  | Opcode.MADD -> madd ins ctxt addr
  | Opcode.MOV | Opcode.MOVN | Opcode.MOVZ | Opcode.MOVK -> mov ins ctxt addr
  | Opcode.MRS -> mrs ins ctxt addr
  | Opcode.MSUB -> msub ins ctxt addr
  | Opcode.MUL -> madd ins ctxt addr
  | Opcode.MVN -> orn ins ctxt addr
  | Opcode.NEG -> sub ins ctxt addr
  | Opcode.NOP -> nop ins addr
  | Opcode.ORR -> orr ins ctxt addr
  | Opcode.RET -> ret ins ctxt addr
  | Opcode.SBC -> sbc ins ctxt addr
  | Opcode.SBFIZ | Opcode.SBFX -> sbfm ins ctxt addr
  | Opcode.SMADDL | Opcode.SMULL -> smaddl ins ctxt addr
  | Opcode.SMULH -> smulh ins ctxt addr
  | Opcode.STP -> stp ins ctxt addr
  | Opcode.STR -> str ins ctxt addr
  | Opcode.STRB -> strb ins ctxt addr
  | Opcode.STRH -> strh ins ctxt addr
  | Opcode.STUR -> stur ins ctxt addr
  | Opcode.STURB -> sturb ins ctxt addr
  | Opcode.STURH -> sturh ins ctxt addr
  | Opcode.SUB -> sub ins ctxt addr
  | Opcode.SUBS -> subs ins ctxt addr
  | Opcode.SXTW -> sbfm ins ctxt addr
  | Opcode.TBNZ -> tbnz ins ctxt addr
  | Opcode.TBZ -> tbz ins ctxt addr
  | Opcode.TST -> ands ins ctxt addr
  | Opcode.UBFIZ | Opcode.UBFX | Opcode.UXTB | Opcode.UXTH -> ubfm ins ctxt addr
  | Opcode.UCVTF -> sideEffects ins addr UnsupportedFP
  | Opcode.UDIV -> udiv ins ctxt addr
  | Opcode.UMULL -> umaddl ins ctxt addr
  | Opcode.UMULH -> umulh ins ctxt addr
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException (Disasm.opCodeToString o)
  |> fun builder -> builder.ToStmts ()

// vim: set tw=80 sts=2 sw=2:
