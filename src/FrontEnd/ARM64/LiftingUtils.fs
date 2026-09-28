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

/// Assigns to an operand of the given size. 64-bit operands generate a 64-bit
/// result in the destination general-purpose register, and 32-bit operands a
/// 32-bit result zero-extended to a 64-bit one. A write to XZR is discarded,
/// which is written as a write of zero to it. Unlike the shared rule of
/// LiftingUtils.assignSized, the destination is unwrapped at every operand
/// size, so this cannot share it.
let assignXZRAware size dst src =
  let orgDst = AST.unwrap dst
  let orgDstSz = Expr.typeOf orgDst
  match orgDst with
  | Var(RegisterID = rid) when rid = Register.toRegID R.XZR ->
    AST.assign orgDst (AST.num0 orgDstSz)
  | _ ->
    if orgDstSz > size then AST.assign orgDst (AST.zext orgDstSz src)
    elif orgDstSz = size then AST.assign orgDst src
    else raise InvalidOperandSizeException

/// Assigns to the given target, shadowing the plain assignment operator. A
/// direct target is written exactly as given; a sized one is an instruction
/// operand written under A64's operand-size rules.
let inline (:=) target src =
  match target with
  | AssignTarget.Direct dst -> AST.assign dst src
  | AssignTarget.Sized(size, dst) -> assignXZRAware size dst src

type RoundMode =
  | FPRounding_TIEEVEN
  | FPRounding_TIEAWAY
  | FPRounding_Zero
  | FPRounding_POSINF
  | FPRounding_NEGINF

let getPC bld = regVar bld R.PC

let rorForIR src amount width = (src >> amount) .| (src << (width .- amount))

let ror x amount width = (x >>> amount) ||| (x <<< (width - amount))

let oprSzToExpr oprSize = numI32 (RegType.toBitWidth oprSize) oprSize

let vectorToList vector esize =
  List.init (64 / int esize) (fun e -> AST.extract vector esize (e * int esize))

let getTwoOprs (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(o1, o2) -> struct (o1, o2)
  | _ -> raise InvalidOperandException

let getThreeOprs (ins: Instruction) =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) -> struct (o1, o2, o3)
  | _ -> raise InvalidOperandException

let getFourOprs (ins: Instruction) =
  match ins.Operands with
  | FourOperands(o1, o2, o3, o4) -> struct (o1, o2, o3, o4)
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
  else
    Array.init elems (fun i -> AST.extract regA eSize (i * pos))

let private getMemExpr128 expr =
  match expr with
  | Load(Endian = e; Type = 128<rt>; Addr = expr) ->
    let add = AST.load e 64<rt> (expr .+ numI32 8 (Expr.typeOf expr))
    struct (add, AST.load e 64<rt> expr)
  | _ ->
    raise InvalidOperandException

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
  | ShiftOp.LSL -> reg << amount
  | ShiftOp.LSR -> reg >> amount
  | ShiftOp.ASR -> reg ?>> amount
  | ShiftOp.ROR -> rorForIR reg amount (oprSzToExpr oprSize)
  | _ -> raise InvalidOperandException

let transShiftAmount bld oprSize = function
  | Imm amt -> numI64 amt oprSize
  | Reg amt -> regVar bld amt

/// shared/functions/common/Extend
/// Extend()
/// ========
let extend reg oprSz regSize isUnsigned =
  (* Extending to the operand's own width is the identity, and it has to be
     taken before the mask is built rather than after: 1L <<< 64 shifts by a
     count the CLR reduces modulo 64, so it yields 1L and the mask below comes
     out as zero. The signed branch used to carry that guard on its own, which
     left every unsigned full-width extension -- UXTX, and the UXTX form of a
     register memory offset -- masking its operand away to nothing. *)
  if regSize >= RegType.toBitWidth oprSz then
    reg
  else
    let uMask = numI64 ((1L <<< regSize) - 1L) oprSz
    if isUnsigned then
      reg .& uMask
    else
      let mBit = AST.extract reg 1<rt> (regSize - 1)
      let sMask = ~~~((1L <<< regSize) - 1L)
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
    | SXTB -> false, 8
    | SXTH -> false, 16
    | SXTW -> false, 32
    | SXTX -> false, 64
    | UXTB -> true, 8
    | UXTH -> true, 16
    | UXTW -> true, 32
    | UXTX -> true, 64
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
  | OprSIMD(ScalarReg v) ->
    struct (RegisterHelper.toRegType v, RegisterHelper.toRegType v, 1)
  | OprSIMD(VecReg(_, v)) ->
    getElemDataSzAndElemsByVector v
  | OprSIMD(VecRegWithIdx(_, v, _)) ->
    getElemDataSzAndElemsByVector v
  | OprSIMDList simds ->
    getElemDataSzAndElems (OprSIMD simds[0])
  | _ ->
    raise InvalidOperandException

let transSIMDOprVPart bld eSize part = function
  | OprSIMD(VecReg(reg, _)) ->
    let pos = int eSize
    let elems = 64<rt> / eSize
    if part = 128<rt> then
      let regB = pseudoRegVar bld reg 2
      Array.init elems (fun i -> AST.extract regB eSize (i * pos))
    else
      let regA = pseudoRegVar bld reg 1
      Array.init elems (fun i -> AST.extract regA eSize (i * pos))
  | _ ->
    raise InvalidOperandException

let transSIMDReg bld = function (* FIXME *)
  | VecRegWithIdx(reg, v, idx) ->
    let struct (regB, regA) = pseudoRegVar128 bld reg
    let struct (esize, _, _) = getElemDataSzAndElemsByVector v
    let index = int idx * int esize
    if index < 64 then [| AST.extract regA esize index |]
    else [| AST.extract regB esize (index % 64) |]
  | VecReg(reg, v) ->
    let struct (eSize, dataSize, elements) = getElemDataSzAndElemsByVector v
    getPseudoRegVarToArr bld reg eSize dataSize elements
  | _ (* SIMDFPScalarReg *) ->
    raise InvalidOperandException

let transSIMDListToExpr bld = function (* FIXME *)
  | OprSIMDList simds -> Array.map (transSIMDReg bld) (List.toArray simds)
  | _ -> raise InvalidOperandException

let transSIMD bld = function (* FIXME *)
  | ScalarReg reg ->
    regVar bld reg
  | VecReg _ ->
    raise InvalidOperandException
  | VecRegWithIdx(reg, v, idx) ->
    let struct (regB, regA) = pseudoRegVar128 bld reg
    let struct (esize, _, _) = getElemDataSzAndElemsByVector v
    let index = int idx * int esize
    if index < 64 then AST.extract regA esize index
    else AST.extract regB esize (index % 64)

let transImmOffset bld = function
  | BaseOffset(bReg, Some imm) ->
    regVar bld bReg .+ numI64 imm 64<rt> |> AST.loadLE 64<rt>
  | BaseOffset(bReg, None) ->
    regVar bld bReg |> AST.loadLE 64<rt>
  | Lbl lbl ->
    numI64 lbl 64<rt>

let transRegOff (ins: Instruction) bld reg = function
  | ShiftOffset(shfTyp, amt) ->
    let reg = regVar bld reg
    let amount = transShiftAmount bld 64<rt> amt
    shiftReg reg amount ins.OprSize shfTyp
  | ExtRegOffset(extTyp, shf) ->
    extendReg bld reg extTyp shf 64<rt>

let transRegOffset ins bld = function
  | bReg, reg, Some regOffset ->
    regVar bld bReg .+ transRegOff ins bld reg regOffset
  | bReg, reg, None ->
    regVar bld bReg .+ regVar bld reg

let transMemOffset ins bld = function
  | ImmOffset immOffset ->
    transImmOffset bld immOffset
  | RegOffset(bReg, reg, regOffset) ->
    transRegOffset ins bld (bReg, reg, regOffset) |> AST.loadLE 64<rt>

let transBaseMode ins bld offset = transMemOffset ins bld offset

let transMem ins bld = function
  | BaseMode offset -> transBaseMode ins bld offset
  | PreIdxMode offset -> transBaseMode ins bld offset
  | PostIdxMode offset -> transBaseMode ins bld offset
  | LiteralMode offset -> transBaseMode ins bld offset

let transOpr ins bld = function
  | OprRegister reg ->
    regVar bld reg
  | OprMemory mem ->
    transMem ins bld mem
  | OprSIMD reg ->
    transSIMD bld reg
  | OprImm imm ->
    numI64 imm ins.OprSize
  | OprNZCV nzcv ->
    numI64 (int64 nzcv) ins.OprSize
  | OprLSB lsb ->
    numI64 (int64 lsb) ins.OprSize
  | OprFbits fbits ->
    numI64 (int64 fbits) ins.OprSize
  | OprFPImm float ->
    if ins.OprSize = 64<rt> then
      numI64 (BitConverter.DoubleToInt64Bits float) ins.OprSize
    else
      BitConverter.SingleToInt32Bits(float32 float)
      |> int64
      |> fun bits -> numI64 bits ins.OprSize
  | _ ->
    raise <| NotImplementedIRException "transOpr"

let transOprFPImm (ins: Instruction) eSize src =
  match eSize, src with
  | 32<rt>, OprFPImm float ->
    numI64 (int64 (BitConverter.SingleToInt32Bits(float32 float))) ins.OprSize
  | 64<rt>, OprFPImm float ->
    numI64 (BitConverter.DoubleToInt64Bits float) ins.OprSize
  | _ ->
    raise InvalidOperandException

let separateMemExpr expr =
  match expr with
  | Load(Addr = BinOp(Op = BinOpType.ADD; Left = b; Right = o)) -> b, o
  | Load(Addr = e) -> e, AST.num0 64<rt>
  | _ -> raise InvalidOperandException

let transOneOpr (ins: Instruction) bld =
  match ins.Operands with
  | OneOperand o -> transOpr ins bld o
  | _ -> raise InvalidOperandException

let transTwoOprs (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(o1, o2) ->
    transOpr ins bld o1, transOpr ins bld o2
  | _ ->
    raise InvalidOperandException

let transTwoOprsSepMem (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(o1, o2) ->
    let memExpr = transOpr ins bld o2 |> separateMemExpr
    transOpr ins bld o1, memExpr
  | _ ->
    raise InvalidOperandException

let transThreeOprs (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) ->
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    let o3 = transOpr ins bld o3
    o1, o2, o3
  | _ ->
    raise InvalidOperandException

let transThreeOprsSepMem (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) ->
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    let o3 = transOpr ins bld o3 |> separateMemExpr
    o1, o2, o3
  | _ ->
    raise InvalidOperandException

let transFourOprs (ins: Instruction) bld =
  match ins.Operands with
  | FourOperands(o1, o2, o3, o4) ->
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    let o3 = transOpr ins bld o3
    let o4 = transOpr ins bld o4
    o1, o2, o3, o4
  | _ ->
    raise InvalidOperandException

let transFourOprsSepMem (ins: Instruction) bld =
  match ins.Operands with
  | FourOperands(o1, o2, o3, o4) ->
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    let o3 = transOpr ins bld o3
    let o4 = transOpr ins bld o4 |> separateMemExpr
    o1, o2, o3, o4
  | _ ->
    raise InvalidOperandException

let transOpr128 ins bld = function
  | OprSIMD(ScalarReg reg) -> pseudoRegVar128 bld reg
  | OprSIMD(VecReg(reg, _)) -> pseudoRegVar128 bld reg
  | OprSIMD(VecRegWithIdx(reg, _, _)) -> pseudoRegVar128 bld reg
  | OprMemory mem -> transMem ins bld mem |> getMemExpr128
  | _ -> raise InvalidOperandException

let transSIMDOprToExpr bld eSize dataSize elements = function
  | OprSIMD(ScalarReg reg) ->
    if dataSize = 128<rt> then
      let struct (regB, regA) = pseudoRegVar128 bld reg
      [| regB; regA |]
    else
      [| regVar bld reg |]
  | OprSIMD(VecReg(reg, _)) ->
    getPseudoRegVarToArr bld reg eSize dataSize elements
  | OprSIMD(VecRegWithIdx _) ->
    raise InvalidOperandException
  | _ ->
    raise InvalidOperandException

(* Barrel shift *)
let transBarrelShiftToExpr oprSize bld src shift =
  match src, shift with
  | OprImm imm, OprShift(typ, Imm amt) ->
    let imm =
      match typ with
      | LSL -> imm <<< int32 amt
      | LSR -> imm >>> int32 amt
      | MSL -> (imm <<< int32 amt) + (1L <<< int32 amt) - 1L
      | _ -> raise <| NotImplementedIRException "transBarrelShiftToExpr"
    numI64 imm oprSize
  | OprRegister reg, OprShift(typ, amt) ->
    let reg = regVar bld reg
    let amount = transShiftAmount bld oprSize amt
    shiftReg reg amount oprSize typ
  | OprRegister reg, OprExtReg(Some(ShiftOffset(typ, amt))) ->
    let reg = regVar bld reg
    let amount = transShiftAmount bld oprSize amt
    shiftReg reg amount oprSize typ
  | OprRegister reg, OprExtReg(Some(ExtRegOffset(typ, shf))) ->
    extendReg bld reg typ shf oprSize
  | OprRegister reg, OprExtReg None ->
    regVar bld reg
  | _ ->
    raise <| NotImplementedIRException "transBarrelShiftToExpr"

let transThreeOprsWithBarrelShift (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) ->
    transOpr ins bld o1, transBarrelShiftToExpr ins.OprSize bld o2 o3
  | _ ->
    raise InvalidOperandException

let transFourOprsWithBarrelShift (ins: Instruction) bld =
  match ins.Operands with
  | FourOperands(o1, o2, o3, o4) ->
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    o1, o2, transBarrelShiftToExpr ins.OprSize bld o3 o4
  | _ ->
    raise InvalidOperandException

let isRegOffset opr =
  match opr with
  | OprMemory(BaseMode(RegOffset _)) | OprMemory(PreIdxMode(RegOffset _))
  | OprMemory(PostIdxMode(RegOffset _))
  | OprMemory(LiteralMode(RegOffset _)) -> true
  | _ -> false

let isSIMDScalar opr =
  match opr with
  | OprSIMD(ScalarReg _) -> true
  | _ -> false

let isSIMDVector opr =
  match opr with
  | OprSIMD(VecReg _) -> true
  | _ -> false

let isSIMDVectorIdx opr =
  match opr with
  | OprSIMD(VecRegWithIdx _) -> true
  | _ -> false

let transOprOfAND (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands _ -> transThreeOprs ins bld
  | FourOperands _ -> transFourOprsWithBarrelShift ins bld
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

let transOprOfCCMN (ins: Instruction) bld =
  match ins.Operands with
  | FourOperands(o1, o2, o3, o4) ->
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    let o3 = transOpr ins bld o3
    o1, o2, o3, o4 |> unwrapCond
  | _ ->
    raise InvalidOperandException

let transOprOfCCMP (ins: Instruction) bld =
  match ins.Operands with
  | FourOperands(o1, o2, o3, o4) ->
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    let o3 = transOpr ins bld o3
    o1, o2, o3, o4 |> unwrapCond
  | _ ->
    raise InvalidOperandException

let transOprOfCMP (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) ->
    transOpr ins bld o1, transBarrelShiftToExpr ins.OprSize bld o2 o3
  | _ ->
    raise InvalidOperandException

let transOprOfCSEL (ins: Instruction) bld =
  match ins.Operands with
  | FourOperands(o1, o2, o3, o4) ->
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    let o3 = transOpr ins bld o3
    o1, o2, o3, o4 |> unwrapCond
  | _ ->
    raise InvalidOperandException

let transOprOfFCSEL (ins: Instruction) bld =
  match ins.Operands with
  | FourOperands(o1, o2, o3, o4) ->
    let o2 = transOpr ins bld o2
    let o3 = transOpr ins bld o3
    o1, o2, o3, o4 |> unwrapCond
  | _ ->
    raise InvalidOperandException

let transOprOfCSINC (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(o1, o2) -> (* CSET *)
    let o1 = transOpr ins bld o1
    let cond = regVar bld (if ins.OprSize = 64<rt> then R.XZR else R.WZR)
    o1, cond, cond, o2 |> unwrapCond |> invertCond
  | ThreeOperands(o1, o2, o3) -> (* CINC *)
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    o1, o2, o2, o3 |> unwrapCond |> invertCond
  | FourOperands(o1, o2, o3, o4) ->
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    let o3 = transOpr ins bld o3
    o1, o2, o3, o4 |> unwrapCond
  | _ ->
    raise InvalidOperandException

let transOprOfCSINV (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(o1, o2) -> (* CSETM *)
    let o1 = transOpr ins bld o1
    let cond = regVar bld (if ins.OprSize = 64<rt> then R.XZR else R.WZR)
    o1, cond, cond, o2 |> unwrapCond |> invertCond
  | ThreeOperands(o1, o2, o3) -> (* CINV *)
    let o2 = transOpr ins bld o2
    transOpr ins bld o1, o2, o2, o3 |> unwrapCond |> invertCond
  | FourOperands(o1, o2, o3, o4) -> (* CSINV *)
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    let o3 = transOpr ins bld o3
    o1, o2, o3, o4 |> unwrapCond
  | _ ->
    raise InvalidOperandException

let transOprOfCSNEG (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(o1, o2, OprCond o3) -> (* CNEG *)
    let o2 = transOpr ins bld o2
    transOpr ins bld o1, o2, o2, invertCond o3
  | FourOperands(o1, o2, o3, o4) -> (* CSNEG *)
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    let o3 = transOpr ins bld o3
    o1, o2, o3, o4 |> unwrapCond
  | _ ->
    raise InvalidOperandException

let transOprOfEOR (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands _ ->
    transThreeOprs ins bld
  | FourOperands(o1, o2, o3, o4) when ins.Opcode = Opcode.EOR ->
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    o1, o2, transBarrelShiftToExpr ins.OprSize bld o3 o4
  | FourOperands(o1, o2, o3, o4) when ins.Opcode = Opcode.EON ->
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    o1, o2, transBarrelShiftToExpr ins.OprSize bld o3 o4 |> AST.not
  | _ ->
    raise InvalidOperandException

let transOprOfEXTR (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) -> (* ROR *)
    let o2 = transOpr ins bld o2
    transOpr ins bld o1, o2, o2, transOpr ins bld o3
  | FourOperands _ ->
    transFourOprs ins bld
  | _ ->
    raise InvalidOperandException

let getIsWBackAndIsPostIndexByAddrMode = function
  | BaseMode _ -> false, false
  | PreIdxMode _ -> true, false
  | PostIdxMode _ -> true, true
  | _ -> raise InvalidOperandException

let getIsWBackAndIsPostIndex = function
  | TwoOperands(_, OprMemory mem) -> getIsWBackAndIsPostIndexByAddrMode mem
  | ThreeOperands(_, _, OprMemory mem) -> getIsWBackAndIsPostIndexByAddrMode mem
  | _ -> raise InvalidOperandException

let transOprOfMADD (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) -> (* MUL *)
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    let o3 = transOpr ins bld o3
    o1, o2, o3, regVar bld (if ins.OprSize = 64<rt> then R.XZR else R.WZR)
  | FourOperands _ ->
    transFourOprs ins bld
  | _ ->
    raise InvalidOperandException

let transOprOfORN (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) when ins.Opcode = Opcode.MVN -> (* MVN *)
    let o1 = transOpr ins bld o1
    let cond = regVar bld (if ins.OprSize = 64<rt> then R.XZR else R.WZR)
    o1, cond, transBarrelShiftToExpr ins.OprSize bld o2 o3
  | FourOperands(o1, o2, o3, o4) when ins.Opcode = Opcode.ORN -> (* ORN *)
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    o1, o2, transBarrelShiftToExpr ins.OprSize bld o3 o4
  | _ ->
    raise InvalidOperandException

let transOprOfORR (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands _ ->
    transThreeOprs ins bld
  | FourOperands(o1, o2, o3, o4) ->
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    o1, o2, transBarrelShiftToExpr ins.OprSize bld o3 o4
  | _ ->
    raise InvalidOperandException

let unwrapReg e =
  match e with
  | Extract(Operand = e; Type = 32<rt>; StartPos = 0) -> e
  | _ -> raise InvalidOperandException

let transOprOfSMSUBL (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) ->
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    let o3 = transOpr ins bld o3
    o1, o2, o3, regVar bld R.XZR
  | FourOperands _ ->
    transFourOprs ins bld
  | _ ->
    raise InvalidOperandException

let transOprOfSUB (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3)
    when ins.Opcode = Opcode.NEG ->
    let o1 = transOpr ins bld o1
    let cond = regVar bld (if ins.OprSize = 64<rt> then R.XZR else R.WZR)
    o1, cond, transBarrelShiftToExpr ins.OprSize bld o2 o3 |> AST.not
  | FourOperands(o1, o2, o3, o4) -> (* Arithmetic *)
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    o1, o2, transBarrelShiftToExpr ins.OprSize bld o3 o4 |> AST.not
  | _ ->
    raise InvalidOperandException

let transOprOfMSUB (ins: Instruction) bld =
  let oprSize = ins.OprSize
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) -> (* MNEG *)
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    let o3 = transOpr ins bld o3
    o1, o2, o3, regVar bld (if ins.OprSize = 64<rt> then R.XZR else R.WZR)
  | FourOperands _ ->
    transFourOprs ins bld (* MSUB *)
  | _ ->
    raise InvalidOperandException

let transOprOfUMADDL (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) -> (* UMULL / UMNEGL *)
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    let o3 = transOpr ins bld o3
    o1, o2, o3, regVar bld R.XZR
  | FourOperands _ ->
    transFourOprs ins bld
  | _ ->
    raise InvalidOperandException

let transOprOfSUBS (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) ->
    let o1 = transOpr ins bld o1
    let cond = regVar bld (if ins.OprSize = 64<rt> then R.XZR else R.WZR)
    o1, cond, transBarrelShiftToExpr ins.OprSize bld o2 o3 |> AST.not
  | FourOperands(o1, o2, o3, o4) ->
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    o1, o2, transBarrelShiftToExpr ins.OprSize bld o3 o4 |> AST.not
  | _ ->
    raise InvalidOperandException

let transOprOfTST (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(o1, o2) (* immediate *) ->
    transOpr ins bld o1, transOpr ins bld o2
  | ThreeOperands(o1, o2, o3) (* shfed *) ->
    transOpr ins bld o1, transBarrelShiftToExpr ins.OprSize bld o2 o3
  | _ ->
    raise InvalidOperandException

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
  append bld {
    append bld { AST.interjmp target i } // FIXME: BranchAddr function
  }

/// shared/functions/system/ConditionHolds
/// ConditionHolds()
/// ================
/// Return TRUE iff COND currently holds
let conditionHolds bld = function
  | EQ -> regVar bld R.Z == AST.b1
  | NE -> regVar bld R.Z == AST.b0
  | CS | HS -> regVar bld R.C == AST.b1
  | CC | LO -> regVar bld R.C == AST.b0
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

/// shared/functions/common/HighestSetBit
/// HighestSetBit()
/// ===============
let highestSetBitForIR expr width oprSz bld =
  let struct (highest, n1) = tmpVars2 bld oprSz
  append bld {
    direct highest := numI32 -1 oprSz
    direct n1 := AST.num1 oprSz
  }
  let inline pos i =
    let elem = tmpVar bld oprSz
    let bit = AST.extract expr 1<rt> i |> AST.zext oprSz
    append bld {
      direct elem := (bit .* ((numI32 i oprSz) .+ n1)) .- n1
    }
    elem
  Array.init width pos
  |> Array.iter (fun e ->
    append bld { direct highest := AST.ite (highest ?<= e) e highest })
  highest

let highestSetBit x size =
  let rec loop i =
    if i < 0 then
      -1
    elif (x >>> i) &&& 1 = 1 then
      i
    else
      loop (i - 1)
  loop (size - 1)

/// shared/functions/common/Replicate
/// Replicate()
/// ===========
let replicateForIR expr exprSize repSize bld =
  let repeat = repSize / exprSize
  let repVal = tmpVar bld repSize
  append bld {
    direct repVal := AST.zext repSize expr
  }
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
  let signBit = AST.num1 eSize << numI64 (int64 shfAmt) eSize
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
  let immNNot = immN <<< 6 ||| (~~~imms &&& 0x3F)
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
  append bld {
    direct expr1 := expr >> n1
    direct expr2 := (expr << n1) >> n1
    direct xExpr := (expr1 <+> expr2)
  }
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
  append bld {
    direct max := getIntMax n true
    direct min := AST.num0 n
    direct overflow := i ?> AST.zext (2 * n) max
    direct underflow := i ?< AST.zext (2 * n) min
    direct bitQC := bitQC .| overflow .| underflow
  }
  AST.ite overflow max (AST.ite underflow min (AST.xtlo n i))

/// shared/functions/vector/SignedSatQ
/// SignedSatQ()
/// ============
let signedSatQ bld i n =
  let struct (max, min) = tmpVars2 bld n
  let struct (overflow, underflow) = tmpVars2 bld 1<rt>
  let bitQC = AST.extract (regVar bld R.FPSR) 1<rt> 27
  append bld {
    direct max := getIntMax n false
    direct min := AST.not max
    direct overflow := i ?> AST.sext (2 * n) max
    direct underflow := i ?< AST.sext (2 * n) min
    direct bitQC := bitQC .| overflow .| underflow
  }
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

/// <summary>
/// shared/functions/float/fproundingmode/FPRoundingMode
///
/// The source rounded to a whole number in whichever direction FPCR.RMode
/// names, which is what a bare <c>RoundToIntegral</c> is: an expression no
/// <c>RoundCtrl</c> encloses rounds by the target's own control register, so
/// the four directions the field can name need not be spelled out and the body
/// need not be built four times over.
/// </summary>
let fpRoundingMode src oprSz = AST.cast CastKind.RoundToIntegral oprSz src

/// <summary>
/// shared/functions/float/fproundingmode/FPRoundingMode
///
/// FtoI, in the direction FPCR.RMode names -- a bare conversion, for the same
/// reason as above.
/// </summary>
let fpRoundingToInt src oprSz = AST.cast CastKind.FloatToSInt oprSz src

/// shared/functions/float/fpdefaultnan/FPDefaultNan
/// FPDefaultNan()
let fpDefaultNan fbit =
  match fbit with
  | 64<rt> -> numU64 0x7ff8000000000000UL 64<rt>
  | 32<rt> -> numU64 0x7fc00000UL 32<rt>
  | 16<rt> -> numU64 0x7e00UL 16<rt>
  | _ -> raise InvalidOperandException

/// Two, with the given sign: the exponent one above the bias and an empty
/// mantissa.
let fpTwo sign fbit =
  let bits =
    match fbit with
    | 64<rt> -> numU64 0x4000000000000000UL 64<rt>
    | 32<rt> -> numU64 0x40000000UL 32<rt>
    | 16<rt> -> numU64 0x4000UL 16<rt>
    | _ -> raise InvalidOperandException
  let signBit =
    match fbit with
    | 64<rt> -> numU64 0x8000000000000000UL 64<rt>
    | 32<rt> -> numU64 0x80000000UL 32<rt>
    | 16<rt> -> numU64 0x8000UL 16<rt>
    | _ -> raise InvalidOperandException
  bits .| AST.ite sign signBit (AST.num0 fbit)

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
  | _ ->
    raise InvalidOperandException

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
  | _ ->
    raise InvalidOperandException

/// shared/functions/float/fpzero/FPZero
/// FPZero()
let fpZero src fbit =
  match fbit with
  | 64<rt> -> src .& numU64 0x8000000000000000UL 64<rt>
  | 32<rt> -> src .& numU64 0x80000000UL 32<rt>
  | 16<rt> -> src .& numU64 0x8000UL 16<rt>
  | _ -> raise InvalidOperandException

/// <summary>
/// Two to the power of k, as a float of the given width.
///
/// Built from the exponent field rather than converted from an integer,
/// because the powers wanted here run past what an integer of the SOURCE
/// width can hold: the bound a 64-bit unsigned conversion saturates at is
/// 2^64, and no 64-bit integer names it. Where the power is past what the
/// format can reach -- only ever in half precision -- the answer is infinity,
/// which is what the comparison wants there anyway.
/// </summary>
let private powerOfTwo srcSz k =
  match srcSz with
  | 64<rt> ->
    numU64 (uint64 (1023 + k) <<< 52) 64<rt>
  | 32<rt> ->
    numU64 (uint64 (127 + k) <<< 23) 32<rt>
  | 16<rt> ->
    if k > 15 then numU64 0x7C00UL 16<rt>
    else numU64 (uint64 (15 + k) <<< 10) 16<rt>
  | _ ->
    raise InvalidOperandSizeException

/// The same with the sign bit set, which is exact: a power of two negates
/// without rounding.
let private negPowerOfTwo srcSz k =
  let signBit =
    match srcSz with
    | 64<rt> -> numU64 0x8000000000000000UL 64<rt>
    | 32<rt> -> numU64 0x80000000UL 32<rt>
    | 16<rt> -> numU64 0x8000UL 16<rt>
    | _ -> raise InvalidOperandSizeException
  powerOfTwo srcSz k .| signBit

/// <summary>
/// Two to a power the instruction computes, as the float it is: the biased
/// power in the exponent field and a clear fraction. A fixed-point operand has
/// up to 64 fraction bits, and as an integer that power does not fit a
/// single's width.
/// </summary>
let powerOfTwoOf srcSz k =
  let bias, mBits = if srcSz = 64<rt> then 1023, 52 else 127, 23
  let kSz = Expr.typeOf k
  let k =
    if kSz > srcSz then AST.xtlo srcSz k
    elif kSz < srcSz then AST.zext srcSz k
    else k
  (numI32 bias srcSz .+ k) << numI32 mBits srcSz

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
  append bld {
    direct tf := AST.ite (isSNaN eSize element) (element .| topfrac) element
    direct res := AST.ite dnBit (fpDefaultNan eSize) tf
  }
  res

let fpProcessNaNs bld dataSize e1 e2 =
  let struct (isSNaN1, isSNaN2, isQNaN1, isQNaN2) = tmpVars4 bld 1<rt>
  let isNaN = tmpVar bld 1<rt>
  let resNaN = tmpVar bld dataSize
  append bld {
    direct isSNaN1 := isSNaN dataSize e1
    direct isSNaN2 := isSNaN dataSize e2
    direct isQNaN1 := isQNaN dataSize e1
    direct isQNaN2 := isQNaN dataSize e2
    direct isNaN := isSNaN1 .| isSNaN2 .| isQNaN1 .| isQNaN2
  }
  let fpNaN expr = fpProcessNan bld dataSize expr
  let lblSFT = label bld "isSFT" (* SNaN1 Fall Through *)
  let lblQNaN = label bld "isQNaN"
  let lblSNaN1 = label bld "isSNaN1"
  let lblSNaN2 = label bld "isSNaN2"
  let lblQNaN1 = label bld "isQNaN1"
  let lblQNaN2 = label bld "isQNaN2"
  let lblEnd = label bld "End"
  append bld {
    AST.cjmp isSNaN1 (AST.jmpDest lblSNaN1) (AST.jmpDest lblSFT)
    AST.lmark lblSNaN1
    direct resNaN := fpNaN e1
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblSFT
    AST.cjmp isSNaN2 (AST.jmpDest lblSNaN2) (AST.jmpDest lblQNaN)
    AST.lmark lblSNaN2
    direct resNaN := fpNaN e2
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblQNaN
    AST.cjmp isQNaN1 (AST.jmpDest lblQNaN1) (AST.jmpDest lblQNaN2)
    AST.lmark lblQNaN1
    direct resNaN := fpNaN e1
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblQNaN2
    direct resNaN := AST.ite isQNaN2 (fpNaN e2) (AST.num0 dataSize)
    AST.lmark lblEnd
  }
  struct (isNaN, resNaN)

/// shared/functions/float/fpprocessnans3/FPProcessNaNs3
/// FPProcessNaNs3()
///
/// The NaN a three-operand operation answers with. The order is the
/// pseudocode's: a signalling NaN ahead of a quiet one, and within each the
/// operands in the order they are written, which for a fused multiply-add puts
/// the addend first. Every candidate is quieted up front and the choice made
/// with a select rather than with branches -- the quieting is two statements
/// per operand and reaching it through six labels would be the longer way to
/// say the same thing.
let fpProcessNaNs3 bld dataSize e1 e2 e3 =
  let anyNaN = tmpVar bld 1<rt>
  let resNaN = tmpVar bld dataSize
  let n1 = fpProcessNan bld dataSize e1
  let n2 = fpProcessNan bld dataSize e2
  let n3 = fpProcessNan bld dataSize e3
  let candidates =
    [ isSNaN dataSize e1, n1
      isSNaN dataSize e2, n2
      isSNaN dataSize e3, n3
      isQNaN dataSize e1, n1
      isQNaN dataSize e2, n2
      isQNaN dataSize e3, n3 ]
  let pick = List.foldBack (fun (c, v) acc -> AST.ite c v acc) candidates
  append bld {
    direct anyNaN := isNaN dataSize e1 .| isNaN dataSize e2 .| isNaN dataSize e3
    direct resNaN := pick (AST.num0 dataSize)
  }
  struct (anyNaN, resNaN)

/// <summary>
/// A fused multiply-add: x times y plus z, rounded once.
///
/// It goes out as a named call because that is what the IR already offers for
/// an operation of three arguments. The negations ride along as a flag rather
/// than being applied to the operands: a negation flips a sign bit, and
/// flipping a NaN operand's sign before the operation would change which NaN
/// the answer carries. Bit 0 of the flag negates the product and bit 1 the
/// addend.
/// </summary>
let fma sz negProduct negAddend x y z =
  let prodBit = if negProduct then 1UL else 0UL
  let addBit = if negAddend then 2UL else 0UL
  let args = [ x; y; z; numU64 (prodBit ||| addBit) 8<rt> ]
  let name =
    match sz with
    | 32<rt> -> "FMA32"
    | 64<rt> -> "FMA64"
    | _ -> raise InvalidRegTypeException
  AST.app name args sz

/// <summary>
/// The arithmetic an IEEE exception can be raised by.
///
/// Which operation it was decides the arithmetic its rounding is asked about,
/// and the divide is the only one of the five that can raise the zero divide.
/// </summary>
type FPArith =
  | FPAdd
  | FPSub
  | FPMul
  | FPDiv
  | FPSqrt

/// Everything below the sign bit, which is the magnitude.
let private magnitudeOfWidth oprSz =
  if oprSz = 32<rt> then numU32 0x7fffffffu 32<rt>
  else numU64 0x7fffffff_ffffffffUL 64<rt>

/// The biased exponent as a number, which is zero for a subnormal and for a
/// zero, and all ones for an infinity and for a NaN.
let private biasedExponent oprSz v =
  if oprSz = 32<rt> then (v >> numI32 23 32<rt>) .& numI32 0xff 32<rt>
  else (v >> numI32 52 64<rt>) .& numI32 0x7ff 64<rt>

/// <summary>
/// An expression with a rounding direction of its own in force, whatever
/// FPCR.RMode names.
/// </summary>
let private roundedIn mode e = AST.roundCtrl (AST.roundingMode mode) e

/// <summary>
/// The arithmetic of an operation, bare: what it rounds when its operands are
/// finite, with none of the pseudocode's case analysis around it. The square
/// root reads one operand.
/// </summary>
let private fpArith op a b =
  match op with
  | FPAdd -> AST.fadd a b
  | FPSub -> AST.fsub a b
  | FPMul -> AST.fmul a b
  | FPDiv -> AST.fdiv a b
  | FPSqrt -> AST.fsqrt a

/// One half, at a width.
let private fpOneHalf oprSz =
  if oprSz = 32<rt> then numU32 0x3f000000u 32<rt>
  else numU64 0x3fe0000000000000UL 64<rt>

/// <summary>
/// The same arithmetic with its answer halved, by halving what it scales
/// with: both operands of a sum, the first of the others.
/// </summary>
let private fpHalved oprSz op a b =
  let half e = AST.fmul e (fpOneHalf oprSz)
  match op with
  | FPAdd | FPSub -> fpArith op (half a) (half b)
  | FPMul | FPDiv | FPSqrt -> fpArith op (half a) b

/// <summary>
/// Whether the exact answer is at least two to the power one past the largest
/// exponent, which FPRound overflows on whichever way it rounds.
///
/// Rounding to nearest, or toward the infinity of the answer's own sign,
/// makes such an answer infinite. Rounding the other way makes it the largest
/// finite number, which an answer below that power can round to as well, so
/// the question is asked of the answer halved and rounded toward zero -- which
/// cannot overflow, and reaches two to the largest exponent exactly when the
/// whole answer reaches the next power. An operand too small to halve exactly
/// makes an answer too small for that to matter.
/// </summary>
let private fpIsBeyondRange oprSz halved =
  let top =
    if oprSz = 32<rt> then numU32 0x7f000000u 32<rt>
    else numU64 0x7fe0000000000000UL 64<rt>
  let magnitude = roundedIn RoundingMode.TowardZero halved
  (magnitude .& magnitudeOfWidth oprSz) .>= top

/// <summary>
/// Whether the arithmetic lost nothing to rounding.
///
/// Rounded up and rounded down, it gives the same value exactly when the
/// exact answer is representable, and its two neighbours otherwise -- which
/// asks the answer itself rather than an error term computed beside it, so it
/// holds however small the answer or its error and whichever way the
/// instruction rounded. The two are compared as numbers, so that a zero, which
/// the two directions sign differently, is the one value.
///
/// It is as good as the evaluator's RoundCtrl: one that rounds every body to
/// nearest, whatever direction it names, finds every answer exact. And the
/// arithmetic is evaluated again, so it must be built from operands already
/// rounded: an operand that still has a rounding in it is rounded again.
/// </summary>
let fpIsExact arith =
  let up = roundedIn RoundingMode.TowardPositive arith
  let down = roundedIn RoundingMode.TowardNegative arith
  AST.feq up down

/// <summary>
/// Whether the exact answer is below the smallest normal number, which is
/// where FPRound detects tininess: BEFORE rounding, so an answer that rounds
/// up to the smallest normal was tiny. Rounded toward zero, the answer is
/// below the smallest normal exactly when the exact one is.
/// </summary>
let private fpIsTinyBeforeRounding oprSz arith =
  biasedExponent oprSz (roundedIn RoundingMode.TowardZero arith)
  == AST.num0 oprSz

/// The five exceptions as the bits FPSR keeps them in -- Invalid lowest and
/// Inexact highest -- from one-bit conditions.
let fpBits invalid divZero overflow underflow inexact =
  AST.zext 64<rt> invalid
  .| (AST.zext 64<rt> divZero << numI32 1 64<rt>)
  .| (AST.zext 64<rt> overflow << numI32 2 64<rt>)
  .| (AST.zext 64<rt> underflow << numI32 3 64<rt>)
  .| (AST.zext 64<rt> inexact << numI32 4 64<rt>)

/// Nothing raised, for the exceptions an operation cannot have.
let private fpNone = AST.num0 1<rt>

/// <summary>
/// Records in FPSR the IEEE exceptions an operation raised.
///
/// AArch64 keeps them once. FPSR.{IOC,DZC,OFC,UFC,IXC} are cumulative: an
/// operation sets the ones it raised and clears nothing, and they stay until
/// software writes the register. There is no second copy saying what THIS
/// instruction did, which is the difference from the MIPS status word.
///
/// The trap enables in FPCR are not read, because nothing here traps: an
/// implementation without trapped exceptions leaves them read-as-zero, and
/// that is the one this models.
/// </summary>
let fpRecord bld raised =
  let fpsr = regVar bld R.FPSR
  append bld {
    direct fpsr := fpsr .| raised
  }

/// <summary>
/// The exceptions an arithmetic operation raised, as the five bits FPSR
/// keeps them in.
///
/// Invalid and Divide-by-zero are read off the operands and the result. The
/// other three are about the rounding, and each is asked of the arithmetic
/// again, rounded in a direction of its own: whether it lost anything,
/// whether its exact answer was tiny, whether it was out of range. Losing
/// something is also what makes a tiny answer an underflow rather than merely
/// small, and an overflow always loses something.
///
/// The square root reads one operand, and its caller passes that one twice.
/// </summary>
let fpRaised bld oprSz op src1 src2 result =
  let struct (invalid, divZero, overflow) = tmpVars3 bld 1<rt>
  let struct (underflow, inexact, special) = tmpVars3 bld 1<rt>
  let finiteIn = tmpVar bld 1<rt>
  let raised = tmpVar bld 64<rt>
  let nanIn = isNaN oprSz src1 .| isNaN oprSz src2
  let infIn = isInfinity oprSz src1 .| isInfinity oprSz src2
  let divZeroCond =
    if op = FPDiv then
      isZero oprSz src2 .& AST.not (isZero oprSz src1) .& finiteIn
    else
      AST.num0 1<rt>
  let arith = fpArith op src1 src2
  let beyond = fpIsBeyondRange oprSz (fpHalved oprSz op src1 src2)
  append bld {
    direct finiteIn := AST.not (nanIn .| infIn)
    (* A NaN nothing brought in is one the operation manufactured, which is
       what Invalid means: zero over zero, infinity less infinity, the square
       root of a negative. *)
    direct invalid :=
      isSNaN oprSz src1 .| isSNaN oprSz src2
      .| (isNaN oprSz result .& AST.not nanIn)
    direct divZero := divZeroCond
    direct special := isNaN oprSz result .| invalid .| divZero
    direct overflow :=
      AST.not special .& finiteIn .& (isInfinity oprSz result .| beyond)
    (* An infinite operand gives an exact answer -- infinity plus a finite is
       that infinity, and a finite over an infinity is zero -- so only an
       overflow makes an infinite RESULT inexact. *)
    direct inexact :=
      AST.not special .& finiteIn .& (overflow .| AST.not (fpIsExact arith))
    direct underflow :=
      inexact .& AST.not overflow .& fpIsTinyBeforeRounding oprSz arith
    direct raised := fpBits invalid divZero overflow underflow inexact
  }
  raised

let fpExceptions bld oprSz op src1 src2 result =
  fpRecord bld (fpRaised bld oprSz op src1 src2 result)

/// <summary>
/// What a conversion to an INTEGER raises, which is two of the five and
/// neither of them a rounding of the kind the arithmetic does.
///
/// Invalid is the operand having no integer at all -- a NaN, an infinity, or
/// a magnitude the destination cannot hold -- which the architecture answers
/// with a saturated result rather than with the number, and which the caller
/// has already worked out in order to choose that result.
///
/// Inexact is the operand having a fraction for the conversion to discard,
/// and it is asked of the OPERAND rather than of the answer: every rounding
/// leaves an exact integer alone, so which direction the instruction rounds
/// in does not come into it.
/// </summary>
let fpExceptionsToInt bld oprSz src noInteger =
  let struct (invalid, inexact) = tmpVars2 bld 1<rt>
  append bld {
    direct invalid := noInteger
    direct inexact :=
      AST.not invalid
      .& (AST.roundToIntegral RoundingMode.TowardZero oprSz src != src)
  }
  fpRecord bld (fpBits invalid fpNone fpNone fpNone inexact)

/// <summary>
/// What a comparison raises, which is Invalid and nothing else.
///
/// A signalling NaN always raises it. A quiet one raises it only for the
/// signalling half of the predicates -- FCMPE, and the compares the manual
/// spells twice for exactly this reason -- which is what the caller passes.
/// </summary>
let fpExceptionsCompare bld oprSz signalsOnQuiet a b =
  let invalid =
    if signalsOnQuiet then isNaN oprSz a .| isNaN oprSz b
    else isSNaN oprSz a .| isSNaN oprSz b
  fpRecord bld (fpBits invalid fpNone fpNone fpNone fpNone)

/// <summary>
/// What a FUSED multiply-add raised.
///
/// It is one operation with one rounding, so it is not the union of a
/// multiply's exceptions and an add's -- an intermediate product that would
/// have overflowed on its own does not overflow here, because there is no
/// intermediate product. Its rounding is asked about as an operation's is, of
/// the multiply-add itself, whose answer halves with the multiplicand and the
/// addend.
///
/// Invalid has a case the arithmetic does not: FPMulAdd raises it for a zero
/// times an infinity even with a quiet NaN to add, before it lets that NaN
/// through. The step instructions pass their own answer for such a product,
/// which is a number and raises nothing.
/// </summary>
let fpExceptionsFused bld oprSz negProduct src1 src2 addend result =
  let struct (invalid, overflow, underflow) = tmpVars3 bld 1<rt>
  let struct (inexact, finiteIn) = tmpVars2 bld 1<rt>
  let b, d = src2, addend
  let anyNaN = isNaN oprSz src1 .| isNaN oprSz b .| isNaN oprSz d
  let anyInf =
    isInfinity oprSz src1 .| isInfinity oprSz b .| isInfinity oprSz d
  let badProduct =
    (isInfinity oprSz src1 .& isZero oprSz b)
    .| (isZero oprSz src1 .& isInfinity oprSz b)
  let fused = fma oprSz negProduct false src1 b d
  let half e = AST.fmul e (fpOneHalf oprSz)
  let halved = fma oprSz negProduct false (half src1) b (half d)
  append bld {
    direct finiteIn := AST.not (anyNaN .| anyInf)
    direct invalid :=
      isSNaN oprSz src1 .| isSNaN oprSz b .| isSNaN oprSz d
      .| (isQNaN oprSz d .& badProduct)
      .| (isNaN oprSz result .& AST.not anyNaN)
    direct overflow :=
      AST.not invalid .& finiteIn
      .& (isInfinity oprSz result .| fpIsBeyondRange oprSz halved)
    direct inexact :=
      AST.not invalid .& finiteIn .& (overflow .| AST.not (fpIsExact fused))
    direct underflow :=
      inexact .& AST.not overflow .& fpIsTinyBeforeRounding oprSz fused
  }
  fpRecord bld (fpBits invalid fpNone overflow underflow inexact)

/// What an operation raises where rounding is all it can lose: Invalid for a
/// signalling operand and Inexact for a result that was rounded. Nothing it
/// answers can overflow or be subnormal, so the other three cannot happen.
let fpExceptionsRounded bld invalid inexact =
  fpRecord bld (fpBits invalid fpNone fpNone fpNone inexact)

/// What an operation raises where the only thing it can raise is Invalid: a
/// signalling NaN met by an operation that does no arithmetic on it.
let fpExceptionsInvalidOnly bld invalid =
  fpRecord bld (fpBits invalid fpNone fpNone fpNone fpNone)

/// The seven labels every floating-point arithmetic primitive branches
/// through, in the order they are reached.
let private fpArithLabels bld =
  let lblNan = label bld "NaN"
  let lblCond = label bld "Cond"
  let lblInvalid = label bld "Invalidop"
  let lblInf = label bld "Inf"
  let lblChkInf = label bld "CheckInf"
  let lblChkZero = label bld "CheckZero"
  let lblEnd = label bld "End"
  struct (lblNan, lblCond, lblInvalid, lblInf, lblChkInf, lblChkZero, lblEnd)

/// shared/functions/float/fpadd/FPAdd
/// FPAdd()
let fpAdd bld dSz src1 src2 =
  let struct (isZero1, isInf1, isZero2, isInf2) = tmpVars4 bld 1<rt>
  let struct (sign1, sign2) = tmpVars2 bld 1<rt>
  let res = tmpVar bld dSz
  let struct (lblNan, lblCond, lblInvalid, lblInf, lblChkInf, lblChkZero,
              lblEnd) = fpArithLabels bld
  let cond1 = isInf1 .& isInf2 .& (sign1 == AST.not sign2)
  let cond2 = (isInf1 .& (AST.not sign1)) .| (isInf2 .& (AST.not sign2))
  let cond3 = (isInf1 .& sign1) .| (isInf2 .& sign2)
  let cond4 = isZero1 .& isZero2 .& (sign1 == sign2)
  let struct (isNaN, resNaN) = fpProcessNaNs bld dSz src1 src2
  append bld {
    AST.cjmp (isNaN) (AST.jmpDest lblNan) (AST.jmpDest lblCond)
    AST.lmark lblNan
    direct res := resNaN
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblCond
    direct sign1 := AST.xthi 1<rt> src1
    direct sign2 := AST.xthi 1<rt> src2
    direct isZero1 := isZero dSz src1
    direct isZero2 := isZero dSz src2
    direct isInf1 := isInfinity dSz src1
    direct isInf2 := isInfinity dSz src2
    AST.cjmp cond1 (AST.jmpDest lblInvalid) (AST.jmpDest lblChkInf)
    AST.lmark lblInvalid
    direct res := fpDefaultNan dSz
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblChkInf
    AST.cjmp (cond2 .| cond3) (AST.jmpDest lblInf)
                              (AST.jmpDest lblChkZero)
    AST.lmark lblInf
    direct res := AST.ite cond2 (fpInfinity AST.b0 dSz) (fpInfinity AST.b1 dSz)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblChkZero
    direct res := AST.ite cond4 (fpZero src1 dSz) (AST.fadd src1 src2)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblEnd
  }
  fpExceptions bld dSz FPAdd src1 src2 res
  res

/// shared/functions/float/fpadd/FPSub
/// FPSub()
let fpSub bld dSz src1 src2 =
  let struct (isZero1, isInf1, isZero2, isInf2) = tmpVars4 bld 1<rt>
  let struct (sign1, sign2) = tmpVars2 bld 1<rt>
  let res = tmpVar bld dSz
  let struct (lblNan, lblCond, lblInvalid, lblInf, lblChkInf, lblChkZero,
              lblEnd) = fpArithLabels bld
  let cond1 = isInf1 .& isInf2 .& (sign1 == sign2)
  let cond2 = (isInf1 .& (AST.not sign1)) .| (isInf2 .& sign2)
  let cond3 = (isInf1 .& sign1) .| (isInf2 .& (AST.not sign2))
  let cond4 = isZero1 .& isZero2 .& (sign1 == (AST.not sign2))
  let struct (isNaN, resNaN) = fpProcessNaNs bld dSz src1 src2
  append bld {
    AST.cjmp (isNaN) (AST.jmpDest lblNan) (AST.jmpDest lblCond)
    AST.lmark lblNan
    direct res := resNaN
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblCond
    direct sign1 := AST.xthi 1<rt> src1
    direct sign2 := AST.xthi 1<rt> src2
    direct isZero1 := isZero dSz src1
    direct isZero2 := isZero dSz src2
    direct isInf1 := isInfinity dSz src1
    direct isInf2 := isInfinity dSz src2
    AST.cjmp cond1 (AST.jmpDest lblInvalid) (AST.jmpDest lblChkInf)
    AST.lmark lblInvalid
    direct res := fpDefaultNan dSz
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblChkInf
    AST.cjmp (cond2 .| cond3) (AST.jmpDest lblInf)
                              (AST.jmpDest lblChkZero)
    AST.lmark lblInf
    direct res := AST.ite cond2 (fpInfinity AST.b0 dSz) (fpInfinity AST.b1 dSz)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblChkZero
    direct res := AST.ite cond4 (fpZero src1 dSz) (AST.fsub src1 src2)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblEnd
  }
  fpExceptions bld dSz FPSub src1 src2 res
  res

/// <summary>
/// FPMul and FPMulX, which differ in one answer.
///
/// Zero times infinity is an invalid operation for the ordinary multiply and
/// answers the default NaN. FMULX answers two, with the sign the product
/// would have had -- the value that makes it useful for a reciprocal step,
/// where an infinity and a zero are the two ends of the same estimate.
/// </summary>
let private fpMultiplyCases bld dataSize extended src1 src2 res =
  let struct (isZero1, isInf1, isZero2, isInf2) = tmpVars4 bld 1<rt>
  let struct (sign1, sign2) = tmpVars2 bld 1<rt>
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
  append bld {
    AST.cjmp (isNaN) (AST.jmpDest lblNan) (AST.jmpDest lblCond)
    AST.lmark lblNan
    direct res := resNaN
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblCond
    direct sign1 := AST.xthi 1<rt> src1
    direct sign2 := AST.xthi 1<rt> src2
    direct isZero1 := isZero dataSize src1
    direct isZero2 := isZero dataSize src2
    direct isInf1 := isInfinity dataSize src1
    direct isInf2 := isInfinity dataSize src2
    AST.cjmp cond1 (AST.jmpDest lblInvalid) (AST.jmpDest lblChkInf)
    AST.lmark lblInvalid
    direct res :=
      if extended then fpTwo (sign1 <+> sign2) dataSize
      else fpDefaultNan dataSize
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblChkInf
    AST.cjmp (cond2 .| cond3) (AST.jmpDest lblInf) (AST.jmpDest lblMul)
    AST.lmark lblInf
    direct res := AST.ite cond2 (fpInfinity (sign1 <+> sign2) dataSize)
                                (fpZero (src1 <+> src2) dataSize)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblMul
    direct res := AST.fmul src1 src2
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblEnd
  }

/// FPMul and FPMulX, which differ only in what they answer for a zero times
/// an infinity: a default NaN, or the two that a reciprocal step wants.
let private fpMultiply bld dataSize extended src1 src2 =
  let res = tmpVar bld dataSize
  fpMultiplyCases bld dataSize extended src1 src2 res
  fpExceptions bld dataSize FPMul src1 src2 res
  res

/// shared/functions/float/fpmul/FPMul
/// FPMul()
let fpMul bld dataSize src1 src2 = fpMultiply bld dataSize false src1 src2

let fpMulX bld dataSize src1 src2 = fpMultiply bld dataSize true src1 src2

/// The three facts about an operand that FPMulAdd's case analysis turns on,
/// each in a temporary of its own so that the conditions below can be written
/// once and read three times.
let private fpClassify bld dSz src =
  let struct (sign, isZ, isI) = tmpVars3 bld 1<rt>
  append bld {
    direct sign := AST.xthi 1<rt> src
    direct isZ := isZero dSz src
    direct isI := isInfinity dSz src
  }
  struct (sign, isZ, isI)

/// shared/functions/float/fpmuladd/FPMulAdd
/// FPMulAdd()
///
/// Fused is the whole of what this is: the product is formed exactly, at twice
/// the significand, and only the sum is rounded. That cannot be said as an
/// FPMul inside an FPAdd -- the multiply's own rounding is precisely what the
/// instruction exists to leave out, and putting it back costs an ulp on the
/// operands where the discarded bits would have decided the sum. So the
/// arithmetic here is the evaluator's own single-rounding multiply-add,
/// reached through an APP node, which rounds once in whatever direction FPCR
/// names; everything around it is the pseudocode's case analysis, which the
/// composition of two operations would have got right on its own.
///
/// The four multiply-add instructions negate their operands before arriving,
/// exactly as the pseudocode does, so no sign flag is passed along: the fourth
/// argument of the primitive, which the Intel FMA forms use to say which of
/// the product and the addend to negate, is always zero here.
let fpMulAdd bld dSz addend src1 src2 =
  let struct (signA, isZeroA, isInfA) = fpClassify bld dSz addend
  let struct (sign1, isZero1, isInf1) = fpClassify bld dSz src1
  let struct (sign2, isZero2, isInf2) = fpClassify bld dSz src2
  let res = tmpVar bld dSz
  let signP = sign1 <+> sign2
  let isInfP = isInf1 .| isInf2
  let isZeroP = isZero1 .| isZero2
  (* Zero times infinity: the product is what is invalid, whatever the addend
     turns out to be. *)
  let badProduct = (isInf1 .& isZero2) .| (isZero1 .& isInf2)
  let product = fma dSz false false src1 src2 addend
  let struct (isNaN, resNaN) = fpProcessNaNs3 bld dSz addend src1 src2
  (* A quiet NaN addend does not win over an invalid product: zero times
     infinity makes the answer the default NaN however the addend read. A
     signalling one still comes back as itself, quieted. *)
  let nan = AST.ite (isQNaN dSz addend .& badProduct) (fpDefaultNan dSz) resNaN
  (* The answers, in the order the pseudocode decides them. Unlike the
     primitives above, this one is a chain of selects rather than a ladder of
     labels: every arm here is a value and none of them is a statement, so
     there is nothing to branch around. *)
  let invalid = badProduct .| (isInfA .& isInfP .& (signA <+> signP))
  let plusInf = (isInfA .& AST.not signA) .| (isInfP .& AST.not signP)
  let minusInf = (isInfA .& signA) .| (isInfP .& signP)
  let zero = isZeroA .& isZeroP .& (signA == signP)
  let answers =
    [ isNaN, nan
      invalid, fpDefaultNan dSz
      plusInf, fpInfinity AST.b0 dSz
      minusInf, fpInfinity AST.b1 dSz
      zero, fpZero addend dSz ]
  append bld {
    direct res :=
      List.foldBack (fun (c, v) acc -> AST.ite c v acc) answers product
  }
  fpExceptionsFused bld dSz false src1 src2 addend res
  res

/// shared/functions/float/fpdiv/FPDiv
/// FPDiv()
let private fpDivCases bld dataSize src1 src2 res =
  let struct (isZero1, isInf1, isZero2, isInf2) = tmpVars4 bld 1<rt>
  let struct (sign1, sign2) = tmpVars2 bld 1<rt>
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
  append bld {
    AST.cjmp (isNaN) (AST.jmpDest lblNan) (AST.jmpDest lblCond)
    AST.lmark lblNan
    direct res := resNaN
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblCond
    direct sign1 := AST.xthi 1<rt> src1
    direct sign2 := AST.xthi 1<rt> src2
    direct isZero1 := isZero dataSize src1
    direct isZero2 := isZero dataSize src2
    direct isInf1 := isInfinity dataSize src1
    direct isInf2 := isInfinity dataSize src2
    AST.cjmp cond1 (AST.jmpDest lblInvalid) (AST.jmpDest lblChkInf)
    AST.lmark lblInvalid
    direct res := fpDefaultNan dataSize
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblChkInf
    AST.cjmp (cond2 .| cond3) (AST.jmpDest lblInf) (AST.jmpDest lblDiv)
    AST.lmark lblInf
    direct res := AST.ite cond2 (fpInfinity (sign1 <+> sign2) dataSize)
                                (fpZero (src1 <+> src2) dataSize)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblDiv
    direct res := AST.fdiv src1 src2
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblEnd
  }

/// FPDiv, which the case analysis above answers for every operand pair that
/// does not reach the division itself.
let fpDiv bld dataSize src1 src2 =
  let res = tmpVar bld dataSize
  fpDivCases bld dataSize src1 src2 res
  fpExceptions bld dataSize FPDiv src1 src2 res
  res

/// <summary>
/// shared/functions/float/fpsqrt/FPSqrt
///
/// FPSqrt(). A NaN operand is propagated; a negative operand that is not a
/// zero is an invalid operation and answers the default NaN; everything else,
/// including minus zero and positive infinity, is what the arithmetic already
/// gives.
///
/// The negative arm is the reason this is written out rather than left to a
/// bare <c>AST.fsqrt</c>. IEEE 754 does not say which NaN an invalid
/// operation produces, so an evaluator answers with its host's -- and the one
/// x86 produces has its sign bit set where AArch64's FPDefaultNaN has not.
/// Nothing but the front end knows which of the two the architecture means.
/// </summary>
let fpSqrt bld dSz src =
  let res = tmpVar bld dSz
  let struct (nan, zero, sign) = tmpVars3 bld 1<rt>
  let resNaN = fpProcessNan bld dSz src
  append bld {
    direct nan := isNaN dSz src
    direct zero := isZero dSz src
    direct sign := AST.xthi 1<rt> src
    let negative = sign .& AST.not zero
    let ofNumber = AST.ite negative (fpDefaultNan dSz) (AST.fsqrt src)
    direct res := AST.ite nan resNaN ofNumber
  }
  fpExceptions bld dSz FPSqrt src src res
  res

/// <summary>
/// shared/functions/float/fpmax/FPMax and shared/functions/float/fpmin/FPMin
///
/// The comparison is not the whole of it, which is why these are not the
/// select on a bare "greater than" they look like.
///
/// A NaN operand is PROPAGATED, in the order FPProcessNaNs gives. A select on
/// a comparison cannot do that: every comparison against a NaN is false, so
/// the other operand wins and the NaN is lost.
///
/// And where the answer is a zero, its sign is not the chosen operand's but
/// the two together -- "sign = sign1 AND sign2" for the maximum, OR for the
/// minimum -- so that FPMax of plus and minus zero is plus zero whichever way
/// round they are written. A zero is nothing but its sign bit, so combining
/// the two operands' sign bits builds the answer outright.
/// </summary>
let fpMaxMin bld dSz isMax src1 src2 =
  let res = tmpVar bld dSz
  let struct (isNaN, resNaN) = fpProcessNaNs bld dSz src1 src2
  let cmp = if isMax then AST.fgt src1 src2 else AST.flt src1 src2
  let zeroSign =
    if isMax then fpZero src1 dSz .& fpZero src2 dSz
    else fpZero src1 dSz .| fpZero src2 dSz
  append bld {
    direct res := AST.ite cmp src1 src2
    direct res := AST.ite (isZero dSz res) zeroSign res
    direct res := AST.ite isNaN resNaN res
  }
  fpExceptionsInvalidOnly bld (isSNaN dSz src1 .| isSNaN dSz src2)
  res

/// <summary>
/// shared/functions/float/fpmaxnum/FPMaxNum and its minimum
///
/// The numeric forms differ from the plain ones in one step: a QUIET NaN
/// operand is replaced, before the comparison, by the infinity that loses it
/// -- minus infinity for the maximum, plus for the minimum -- so that the
/// other operand is the answer. A signalling NaN is not replaced and still
/// propagates, which is why this hands the substituted operands to FPMax
/// rather than reimplementing it.
/// </summary>
let fpMaxMinNum bld dSz isMax src1 src2 =
  let struct (q1, q2) = tmpVars2 bld 1<rt>
  let struct (o1, o2) = tmpVars2 bld dSz
  let losing = fpInfinity (if isMax then AST.b1 else AST.b0) dSz
  append bld {
    direct q1 := isQNaN dSz src1
    direct q2 := isQNaN dSz src2
    direct o1 := AST.ite (q1 .& AST.not q2) losing src1
    direct o2 := AST.ite (q2 .& AST.not q1) losing src2
  }
  fpMaxMin bld dSz isMax o1 o2

/// Positive and negative one half, in the width being converted from. Ties
/// away from zero go up once the fraction reaches one of these.
let private halvesOf srcSz =
  match srcSz with
  | 32<rt> ->
    numI32 0x3F000000 srcSz, numI32 0xBF000000 srcSz
  | 64<rt> ->
    numI64 0x3FE0000000000000L srcSz, numI64 0xBFE0000000000000L srcSz
  | _ ->
    raise InvalidOperandSizeException

/// <summary>
/// The conversion itself, for a value the guard has already found to fit.
///
/// It converts at the DESTINATION's width, because that is the width the
/// answer has to fit in. Converting at the source's -- which is what this
/// used to do -- gives FCVTZS Xd, Sn of 2^40 the answer a 32-bit conversion
/// would have produced, although the operand is well inside a 64-bit range.
///
/// LowUIR has no float-to-unsigned cast, so the top half of an unsigned
/// destination is reached by bias: a value at or above 2^(W-1) has that much
/// taken off it before the signed conversion and put back after. The
/// subtraction is exact, since a float that large is a multiple of its own
/// unit in the last place and so is 2^(W-1), so the operand does not lose
/// anything on the way in and the answer is rounded exactly once.
/// </summary>
let private fpFixed dstSz srcSz unsigned mode bigint =
  let conv e = AST.floatToSInt mode dstSz e
  if unsigned then
    let half = powerOfTwo srcSz (int dstSz - 1)
    let bias = AST.num1 dstSz << numI32 (int dstSz - 1) dstSz
    let biased = conv (AST.fsub bigint half) .+ bias
    AST.ite (AST.fge bigint half) biased (conv bigint)
  else
    conv bigint

/// <summary>
/// What a float-to-integer conversion answers where the answer does not fit.
///
/// FPToFixed saturates: "if int_result &gt; max_int then result = max_int",
/// and the same at the bottom. A conversion that simply hands the operand to
/// the hardware gets whatever that produces out of range, which is
/// 0x8000000000000000 on every value too large for a signed 64-bit
/// destination -- the architecture answers 0x7fffffffffffffff there, and
/// 0xffffffffffffffff for the unsigned form.
///
/// The test is against the ROUNDED value and not the operand, because the
/// architecture rounds to an unbounded integer first and only then saturates:
/// FCVTPS of 2^31 - 0.5 into a 32-bit register rounds up to 2^31, which does
/// not fit, where the operand it came from does.
///
/// The bound at the top is the first value that does NOT fit -- 2^63 for a
/// signed 64-bit destination, whose largest value is 2^63 - 1 and which no
/// float can name -- so that test is inclusive. The bound at the bottom is
/// the smallest value that DOES fit, and is exact in any float wide enough to
/// hold it, so that test is not. Infinity needs no arm of its own: it fails
/// both comparisons the way any out-of-range value does. A NaN answers zero,
/// which is the one answer here that is not a bound.
///
/// Those same three conditions are what the conversion raises Invalid for, so
/// the exceptions are recorded here rather than by the caller: this is the
/// only place that has worked out whether the operand had an integer at all.
/// </summary>
let private fpGuardSpecials bld sizes unsigned roundTo src bigint convert =
  let dstSz, srcSz = sizes
  let res = tmpVar bld dstSz
  let rounded = tmpVar bld srcSz
  let struct (checkNan, tooHigh, tooLow) = tmpVars3 bld 1<rt>
  let lblSat = label bld "Saturate"
  let lblCon = label bld "Continue"
  let lblEnd = label bld "End"
  let width = int dstSz
  let hi = powerOfTwo srcSz (if unsigned then width else width - 1)
  let lo =
    if unsigned then AST.num0 srcSz else negPowerOfTwo srcSz (width - 1)
  let allOnes = AST.num0 dstSz |> AST.not
  let hiVal = if unsigned then allOnes else allOnes >> AST.num1 dstSz
  let loVal =
    if unsigned then AST.num0 dstSz
    else AST.num1 dstSz << numI32 (width - 1) dstSz
  append bld {
    direct rounded := roundTo bigint
    direct checkNan := isNaN srcSz src
    direct tooHigh := AST.fge rounded hi
    direct tooLow := AST.flt rounded lo
    AST.cjmp (checkNan .| tooHigh .| tooLow) (AST.jmpDest lblSat)
                                             (AST.jmpDest lblCon)
    AST.lmark lblSat
    direct res :=
      AST.ite checkNan (AST.num0 dstSz) (AST.ite tooHigh hiVal loVal)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblCon
    direct res := convert ()
    AST.lmark lblEnd
  }
  fpExceptionsToInt bld srcSz bigint (checkNan .| tooHigh .| tooLow)
  res

/// <summary>
/// The value rounded to a whole number with a tie going away from zero,
/// chosen between its neighbours below and above on its fraction.
///
/// The neighbours are had by rounding up and down rather than by a ties-away
/// rounding the IR could name, because an evaluator with no notion of a
/// direction rounds that one to even.
/// </summary>
let private tieAwayValue bld srcSz src bigint =
  let struct (t, away) = tmpVars2 bld srcSz
  let comp1, comp2 = halvesOf srcSz
  let trunc = AST.roundToIntegral RoundingMode.TowardZero srcSz src
  let up = AST.roundToIntegral RoundingMode.TowardPositive srcSz bigint
  let down = AST.roundToIntegral RoundingMode.TowardNegative srcSz bigint
  let pRes = AST.ite (AST.fge t comp1) up down
  let nRes = AST.ite (AST.fle t comp2) down up
  append bld {
    direct t := AST.fsub src trunc
    direct away := AST.ite (AST.xthi 1<rt> src) nRes pRes
  }
  away

/// shared/functions/float/FPToFixed
/// FPToFixed()
/// ======
let fpToFixed dstSz src fbits unsigned round bld =
  let srcSz = src |> Expr.typeOf
  (* fbits arrives sized to the destination register, but the fixed-point math
     below works in the source's width, so normalize it to srcSz. Otherwise a
     wider destination (e.g. fcvtzs Xd, Sn) leaves AST.zext srcSz fbits a zero-
     extend to a narrower width, which raises InvalidRegTypeException. *)
  let fbits =
    let fbSz = Expr.typeOf fbits
    if fbSz = srcSz then fbits
    elif fbSz > srcSz then AST.xtlo srcSz fbits
    else AST.zext srcSz fbits
  let convertBit =
    if dstSz > srcSz then AST.xtlo srcSz fbits
    elif dstSz = srcSz then fbits
    else AST.zext srcSz fbits
  let mulBits = powerOfTwoOf srcSz convertBit
  let bigint = AST.fmul src mulBits
  let fpcheck mode =
    let roundTo v = AST.roundToIntegral mode srcSz v
    fpGuardSpecials bld (dstSz, srcSz) unsigned roundTo src bigint (fun () ->
      fpFixed dstSz srcSz unsigned mode bigint)
  match round with
  | FPRounding_TIEEVEN ->
    fpcheck RoundingMode.ToNearestEven
  | FPRounding_TIEAWAY ->
    (* only the value chosen is converted: converting both neighbours
       recorded what the one not chosen raised as well *)
    let away = tieAwayValue bld srcSz src bigint
    let whole () = fpFixed dstSz srcSz unsigned RoundingMode.TowardZero away
    fpGuardSpecials bld (dstSz, srcSz) unsigned (fun _ -> away) src bigint whole
  | FPRounding_Zero ->
    fpcheck RoundingMode.TowardZero
  | FPRounding_POSINF ->
    fpcheck RoundingMode.TowardPositive
  | FPRounding_NEGINF ->
    fpcheck RoundingMode.TowardNegative

/// shared/functions/common/BitCount
// BitCount()
// ==========
let bitCount bitSize x =
  let size = int bitSize
  Array.init size (fun i -> (x >> (numI32 i bitSize)) .& (AST.num1 bitSize))
  |> Array.reduce (.+)

/// The SIMDFP Scalar register needs a function to get the upper 64-bit.
let dstAssignScalar ins bld dst src eSize =
  match dst with
  | OprSIMD(ScalarReg reg) ->
    let reg = OprSIMD(ScalarReg(RegisterHelper.getOrgSIMDReg reg))
    let struct (dstB, dstA) = transOpr128 ins bld reg
    append bld {
      sized eSize dstA := src
      direct dstB := AST.num0 64<rt>
    }
  | _ ->
    raise InvalidOperandException

let dstAssign128 ins bld dst srcA srcB dataSize =
  append bld {
    let struct (dstB, dstA) = transOpr128 ins bld dst
    if dataSize = 128<rt> then
      direct dstA := srcA
      direct dstB := srcB
    else
      direct dstA := srcA
      direct dstB := AST.num0 64<rt>
  }

let dstAssignForSIMD dstA dstB result dataSize elements bld =
  append bld {
    if dataSize = 128<rt> then
      let elems = elements / 2
      direct dstA := AST.revConcat (Array.sub result 0 elems)
      direct dstB := AST.revConcat (Array.sub result elems elems)
    else
      direct dstA := AST.revConcat result
      direct dstB := AST.num0 64<rt>
  }

/// Writes the base register of a load or store back where the addressing mode
/// asks for it, applying the offset that a post-indexed form leaves to the
/// write-back and a pre-indexed one has applied already.
let writeBack bld isWBack isPostIndex bReg address offset =
  if isWBack && isPostIndex then
    append bld { direct bReg := address .+ offset }
  elif isWBack then
    append bld { direct bReg := address }
  else
    ()

/// Records an exclusive reservation for a load-exclusive: the reserved address
/// and the value read there. Under single-observer emulation this is all a
/// later store-exclusive needs to tell whether the location was written in
/// between, so no external call and no per-store instrumentation are required.
let reserveExclusive bld address value =
  append bld {
    direct (regVar bld R.ExMonAddr) := address
    direct (regVar bld R.ExMonVal) := AST.zext 64<rt> value
  }

/// A store-exclusive (STXR/STLXR): stores and returns success (0) only if the
/// reservation still holds -- the address matches and memory still holds the
/// reserved value; otherwise memory is left unchanged and it returns failure
/// (1). The conditional store is expressed as a store of ite(matched, data,
/// old), as compareAndSwap does, so no branch or label is emitted.
let storeExclusive bld address size data =
  let cur = tmpVar bld size
  let matched = tmpVar bld 1<rt>
  let status = tmpVar bld 32<rt>
  append bld {
    direct cur := AST.loadLE size address
    direct matched := (address == regVar bld R.ExMonAddr)
               .& (cur == AST.xtlo size (regVar bld R.ExMonVal))
    direct (AST.loadLE size address) := AST.ite matched data cur
    direct status := AST.ite matched (AST.num0 32<rt>) (AST.num1 32<rt>)
  }
  status

/// A store-exclusive pair (STXP/STLXP): as storeExclusive, verifying the
/// reserved low word; on success both words are stored.
let storeExclusivePair bld address size data1 data2 =
  let hi = address .+ numI32 8 64<rt>
  let cur = tmpVar bld size
  let matched = tmpVar bld 1<rt>
  let status = tmpVar bld 32<rt>
  append bld {
    direct cur := AST.loadLE size address
    direct matched := (address == regVar bld R.ExMonAddr)
               .& (cur == AST.xtlo size (regVar bld R.ExMonVal))
    direct (AST.loadLE size address) := AST.ite matched data1 cur
    direct (AST.loadLE size hi) := AST.ite matched data2 (AST.loadLE size hi)
    direct status := AST.ite matched (AST.num0 32<rt>) (AST.num1 32<rt>)
  }
  status
