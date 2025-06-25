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

module internal B2R2.FrontEnd.Intel.LiftingUtils

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.Intel.Helper

open type BinOpType

let numInsLen insLen (bld: ILowUIRBuilder) =
  numU32 insLen bld.RegType

let numOprSize = function
  | 8<rt> | 16<rt> | 32<rt> | 64<rt> | 128<rt> | 256<rt> | 512<rt> as rt ->
    numI32 (int rt) rt
  | _ -> raise InvalidOperandSizeException

let inline is64bit (bld: ILowUIRBuilder) =
  bld.RegType = 64<rt>

let is64REXW bld (ins: Instruction) =
  is64bit bld && hasREXW ins.REXPrefix

#if DEBUG
let assert32 bld =
  if is64bit bld then raise InvalidISAException else ()
#endif

let inline getOperationSize (i: Instruction) = i.MainOperationSize

let inline getEffAddrSz (i: Instruction) = i.PointerSize

let inline getImmValue imm =
  match imm with
  | OprImm (imm, _) -> imm
  | _ -> raise InvalidOperandException

let inline isConst (e: Expr) =
  match e with
  | Num _ -> true
  | _ -> false

let private getMemExpr128 expr =
  match expr with
  | Load (e, 128<rt>, BinOp (BinOpType.ADD, _, b, Num (n, _), _), _)
  | Load (e, 128<rt>, BinOp (BinOpType.ADD, _, Num (n, _), b, _), _) ->
    let off1 = AST.num n
    let off2 = BitVector.Add (n, BitVector.OfInt32 8 n.Length) |> AST.num
    struct (AST.load e 64<rt> (b .+ off2),
            AST.load e 64<rt> (b .+ off1))
  | Load (e, 128<rt>, expr, _) ->
    struct (AST.load e 64<rt> (expr .+ numI32 8 (Expr.TypeOf expr)),
            AST.load e 64<rt> expr)
  | _ -> raise InvalidOperandException

let private getMemExpr256 expr =
  match expr with
  | Load (e, 256<rt>, BinOp (BinOpType.ADD, _, b, Num (n, _), _), _)
  | Load (e, 256<rt>, BinOp (BinOpType.ADD, _, Num (n, _), b, _), _) ->
    let off1 = AST.num n
    let off2 = BitVector.Add (n, BitVector.OfInt32 8 n.Length) |> AST.num
    let off3 = BitVector.Add (n, BitVector.OfInt32 16 n.Length) |> AST.num
    let off4 = BitVector.Add (n, BitVector.OfInt32 24 n.Length) |> AST.num
    struct (AST.load e 64<rt> (b .+ off4),
            AST.load e 64<rt> (b .+ off3),
            AST.load e 64<rt> (b .+ off2),
            AST.load e 64<rt> (b .+ off1))
  | Load (e, 256<rt>, expr, _) ->
    struct (AST.load e 64<rt> (expr .+ numI32 24 (Expr.TypeOf expr)),
            AST.load e 64<rt> (expr .+ numI32 16 (Expr.TypeOf expr)),
            AST.load e 64<rt> (expr .+ numI32 8 (Expr.TypeOf expr)),
            AST.load e 64<rt> expr)
  | _ -> raise InvalidOperandException

let private getMemExpr512 expr =
  match expr with
  | Load (e, 512<rt>, BinOp (BinOpType.ADD, _, b, Num (n, _), _), _)
  | Load (e, 512<rt>, BinOp (BinOpType.ADD, _, Num (n, _), b, _), _) ->
    let off1 = AST.num n
    let off2 = BitVector.Add (n, BitVector.OfInt32 8 n.Length) |> AST.num
    let off3 = BitVector.Add (n, BitVector.OfInt32 16 n.Length) |> AST.num
    let off4 = BitVector.Add (n, BitVector.OfInt32 24 n.Length) |> AST.num
    let off5 = BitVector.Add (n, BitVector.OfInt32 32 n.Length) |> AST.num
    let off6 = BitVector.Add (n, BitVector.OfInt32 40 n.Length) |> AST.num
    let off7 = BitVector.Add (n, BitVector.OfInt32 48 n.Length) |> AST.num
    let off8 = BitVector.Add (n, BitVector.OfInt32 56 n.Length) |> AST.num
    struct (AST.load e 64<rt> (b .+ off8),
            AST.load e 64<rt> (b .+ off7),
            AST.load e 64<rt> (b .+ off6),
            AST.load e 64<rt> (b .+ off5),
            AST.load e 64<rt> (b .+ off4),
            AST.load e 64<rt> (b .+ off3),
            AST.load e 64<rt> (b .+ off2),
            AST.load e 64<rt> (b .+ off1))
  | Load (e, 512<rt>, expr, _) ->
    struct (AST.load e 64<rt> (expr .+ numI32 56 (Expr.TypeOf expr)),
            AST.load e 64<rt> (expr .+ numI32 48 (Expr.TypeOf expr)),
            AST.load e 64<rt> (expr .+ numI32 40 (Expr.TypeOf expr)),
            AST.load e 64<rt> (expr .+ numI32 32 (Expr.TypeOf expr)),
            AST.load e 64<rt> (expr .+ numI32 24 (Expr.TypeOf expr)),
            AST.load e 64<rt> (expr .+ numI32 16 (Expr.TypeOf expr)),
            AST.load e 64<rt> (expr .+ numI32 8 (Expr.TypeOf expr)),
            AST.load e 64<rt> expr)
  | _ -> raise InvalidOperandException

let private getMemExprs expr =
  match expr with
  | Load (e, 128<rt>, expr, _) ->
    [ AST.load e 64<rt> expr
      AST.load e 64<rt> (expr .+ numI32 8 (Expr.TypeOf expr)) ]
  | Load (e, 256<rt>, expr, _) ->
    [ AST.load e 64<rt> expr
      AST.load e 64<rt> (expr .+ numI32 8 (Expr.TypeOf expr))
      AST.load e 64<rt> (expr .+ numI32 16 (Expr.TypeOf expr))
      AST.load e 64<rt> (expr .+ numI32 24 (Expr.TypeOf expr)) ]
  | Load (e, 512<rt>, expr, _) ->
    [ AST.load e 64<rt> expr
      AST.load e 64<rt> (expr .+ numI32 8 (Expr.TypeOf expr))
      AST.load e 64<rt> (expr .+ numI32 16 (Expr.TypeOf expr))
      AST.load e 64<rt> (expr .+ numI32 24 (Expr.TypeOf expr))
      AST.load e 64<rt> (expr .+ numI32 32 (Expr.TypeOf expr))
      AST.load e 64<rt> (expr .+ numI32 40 (Expr.TypeOf expr))
      AST.load e 64<rt> (expr .+ numI32 48 (Expr.TypeOf expr))
      AST.load e 64<rt> (expr .+ numI32 56 (Expr.TypeOf expr)) ]
  | _ -> raise InvalidOperandException

let private pseudoRegVars bld r =
  match Register.getKind r with
  | Register.Kind.XMM -> [ pseudoRegVar bld r 1; pseudoRegVar bld r 2 ]
  | Register.Kind.YMM ->
    [ pseudoRegVar bld r 1
      pseudoRegVar bld r 2
      pseudoRegVar bld r 3
      pseudoRegVar bld r 4 ]
  | Register.Kind.ZMM ->
    [ pseudoRegVar bld r 1
      pseudoRegVar bld r 2
      pseudoRegVar bld r 3
      pseudoRegVar bld r 4
      pseudoRegVar bld r 5
      pseudoRegVar bld r 6
      pseudoRegVar bld r 7
      pseudoRegVar bld r 8 ]
  | _ -> raise InvalidOperandException

let isSegReg = function
  | Register.CS
  | Register.DS
  | Register.SS
  | Register.ES
  | Register.FS
  | Register.GS -> true
  | _ -> false

let isMemOpr = function
  | OprMem _ -> true
  | _ -> false

let private segRegToBase = function
  | R.CS -> R.CSBase
  | R.DS -> R.DSBase
  | R.ES -> R.ESBase
  | R.FS -> R.FSBase
  | R.GS -> R.GSBase
  | R.SS -> R.SSBase
  | _ -> Terminator.impossible ()

let private ldMem (ins: Instruction) bld oprSize e =
  match getSegment ins.Prefixes with
  | Some s -> regVar bld (segRegToBase s) .+ e
  | None -> e
  |> AST.loadLE oprSize

let private numOfAddrSz (ins: Instruction) (bld: ILowUIRBuilder) n =
  let pref = ins.Prefixes
  let sz =
    if bld.RegType = 32<rt> then if hasAddrSz pref then 16<rt> else 32<rt>
    else if hasAddrSz pref then 32<rt> else 64<rt>
  numI64 n sz

let inline private sIdx ins bld (r, s: Scale) =
  match s with
  | Scale.X1 -> regVar bld r
  | Scale.X2 -> regVar bld r << numOfAddrSz ins bld 1
  | Scale.X4 -> regVar bld r << numOfAddrSz ins bld 2
  | Scale.X8 -> regVar bld r << numOfAddrSz ins bld 3
  | _ -> Terminator.impossible ()

let private transMem bld useTmpVar ins insLen b index disp oprSize =
  let address =
    match b, index, (disp: Disp option) with
    | None, None, Some d ->
      numOfAddrSz ins bld d
    | None, Some i, Some d ->
      let e = (sIdx ins bld i) .+ (numOfAddrSz ins bld d)
      if not useTmpVar then e
      else
        let tAddress = tmpVar bld bld.RegType
        bld <+ (tAddress := e)
        tAddress
    | Some b, None, None ->
      regVar bld b
    | Some R.RIP, None, Some d -> (* RIP-relative addressing *)
      let pc =
#if EMULATION
        numOfAddrSz ins bld (int64 (ins: Instruction).Address)
#else
        regVar bld R.RIP
#endif
      let e = pc .+ numOfAddrSz ins bld (d + int64 (insLen: uint32))
      if not useTmpVar then e
      else
        let tAddress = tmpVar bld bld.RegType
        bld <+ (tAddress := e)
        tAddress
    | Some b, None, Some d ->
      let e = regVar bld b .+ (numOfAddrSz ins bld d)
      if not useTmpVar then e
      else
        let tAddress = tmpVar bld bld.RegType
        bld <+ (tAddress := e)
        tAddress
    | Some b, Some i, None ->
      let e = regVar bld b .+ (sIdx ins bld i)
      if not useTmpVar then e
      else
        let tAddress = tmpVar bld bld.RegType
        bld <+ (tAddress := e)
        tAddress
    | Some b, Some i, Some d ->
      let e = regVar bld b .+ (sIdx ins bld i) .+ (numOfAddrSz ins bld d)
      if not useTmpVar then e
      else
        let tAddress = tmpVar bld bld.RegType
        bld <+ (tAddress := e)
        tAddress
    | _, _, _ -> raise InvalidOperandException
  ldMem ins bld oprSize address

let transOprToExpr bld useTmpVar ins insLen = function
  | OprReg reg -> regVar bld reg
  | OprMem (b, index, disp, oprSize) ->
    transMem bld useTmpVar ins insLen b index disp oprSize
  | OprImm (imm, _) -> numI64 imm (getOperationSize ins)
  | OprDirAddr (Relative offset) -> numI64 offset bld.RegType
  | OprDirAddr (Absolute (_, addr, _)) -> numU64 addr bld.RegType
  | _ -> Terminator.impossible ()

let transOprToExprVec bld useTmpVar ins insLen opr =
  match opr with
  | OprReg r -> pseudoRegVars bld r
  | OprMem (b, index, disp, oprSize) ->
    transMem bld useTmpVar ins insLen b index disp oprSize |> getMemExprs
  | OprImm (imm, _) -> [ numI64 imm (getOperationSize ins) ]
  | _ -> raise InvalidOperandException

let transOprToExpr16 (bld: ILowUIRBuilder) useTmpVar ins insLen opr =
  match opr with
  | OprReg r when Register.toRegType bld.WordSize r > 64<rt> ->
    pseudoRegVar bld r 1 |> AST.xtlo 16<rt>
  | OprReg r -> regVar bld r
  | OprMem (b, index, disp, 16<rt>) ->
    transMem bld useTmpVar ins insLen b index disp 16<rt>
  | _ -> raise InvalidOperandException

let transOprToExpr32 (bld: ILowUIRBuilder) useTmpVar ins insLen opr =
  match opr with
  | OprReg r when Register.toRegType bld.WordSize r > 64<rt> ->
    pseudoRegVar bld r 1 |> AST.xtlo 32<rt>
  | OprReg r -> regVar bld r
  | OprMem (b, index, disp, 32<rt>) ->
    transMem bld useTmpVar ins insLen b index disp 32<rt>
  | _ -> raise InvalidOperandException

let transOprToExpr64 (bld: ILowUIRBuilder) useTmpVar ins insLen opr =
  match opr with
  | OprReg r when Register.toRegType bld.WordSize r > 64<rt> ->
    pseudoRegVar bld r 1
  | OprReg r -> regVar bld r
  | OprMem (b, index, disp, 64<rt>) ->
    transMem bld useTmpVar ins insLen b index disp 64<rt>
  | _ -> raise InvalidOperandException

let transOprToExpr128 bld useTmpVar ins insLen opr =
  match opr with
  | OprReg r -> pseudoRegVar128 bld r
  | OprMem (b, index, disp, oprSize) ->
    transMem bld useTmpVar ins insLen b index disp oprSize |> getMemExpr128
  | _ -> raise InvalidOperandException

let transOprToExpr256 bld useTmpVar ins insLen opr =
  match opr with
  | OprReg r -> pseudoRegVar256 bld r
  | OprMem (b, index, disp, oprSize) ->
    transMem bld useTmpVar ins insLen b index disp oprSize |> getMemExpr256
  | _ -> raise InvalidOperandException

let transOprToExpr512 bld useTmpVar ins insLen opr =
  match opr with
  | OprReg r -> pseudoRegVar512 bld r
  | OprMem (b, index, disp, oprSize) ->
    transMem bld useTmpVar ins insLen b index disp oprSize |> getMemExpr512
  | _ -> raise InvalidOperandException

/// Return a tuple (jump target expr, is pc-relative?)
let transJumpTargetOpr (bld: ILowUIRBuilder) useTmpVar ins pc insLen =
  match (ins: Instruction).Operands with
  | OneOperand (OprDirAddr (Absolute (_, addr, _))) ->
    struct (numU64 addr bld.RegType, false)
  | OneOperand (OprDirAddr (Relative offset)) ->
    let wordSize = bld.RegType
    let offset = numI64 offset wordSize |> AST.sext wordSize
    struct (pc .+ offset, true)
  | OneOperand (OprReg reg) -> struct (regVar bld reg, false)
  | OneOperand (OprMem (b, index, disp, oprSize)) ->
    struct (transMem bld useTmpVar ins insLen b index disp oprSize, false)
  | _ -> raise InvalidOperandException

let transOprToArr bld useTmpVars ins insLen packSz packNum oprSize opr =
  let pos = int packSz
  let exprArr =
    match opr with
    | OprImm _ ->
      let opr = transOprToExpr bld false ins insLen opr
      Array.init (oprSize / packSz) (fun i -> AST.extract opr packSz (i * pos))
    | OprMem _ ->
      match oprSize with
      | 64<rt> ->
        let opr = transOprToExpr bld false ins insLen opr
        let mem = tmpVar bld oprSize
        bld <+ (mem := AST.zext oprSize opr)
        Array.init packNum (fun i -> AST.extract mem packSz (i * pos))
      | 128<rt> ->
        let struct (oB, oA) = transOprToExpr128 bld false ins insLen opr
        let struct (mB, mA) = tmpVars2 bld 64<rt>
        bld <+ (mA := oA)
        bld <+ (mB := oB)
        let oprA = Array.init packNum (fun i -> AST.extract mA packSz (i * pos))
        let oprB = Array.init packNum (fun i -> AST.extract mB packSz (i * pos))
        Array.append oprA oprB
      | 256<rt> ->
        let struct (oD, oC, oB, oA) = transOprToExpr256 bld false ins insLen opr
        let struct (mD, mC, mB, mA) = tmpVars4 bld 64<rt>
        bld <+ (mA := oA)
        bld <+ (mB := oB)
        bld <+ (mC := oC)
        bld <+ (mD := oD)
        let oprA = Array.init packNum (fun i -> AST.extract mA packSz (i * pos))
        let oprB = Array.init packNum (fun i -> AST.extract mB packSz (i * pos))
        let oprC = Array.init packNum (fun i -> AST.extract mC packSz (i * pos))
        let oprD = Array.init packNum (fun i -> AST.extract mD packSz (i * pos))
        Array.concat [| oprA; oprB; oprC; oprD |]
      | 512<rt> ->
        let struct (oH, oG, oF, oE, oD, oC, oB, oA) =
          transOprToExpr512 bld false ins insLen opr
        let struct (mD, mC, mB, mA) = tmpVars4 bld 64<rt>
        let struct (mH, mG, mF, mE) = tmpVars4 bld 64<rt>
        bld <+ (mA := oA)
        bld <+ (mB := oB)
        bld <+ (mC := oC)
        bld <+ (mD := oD)
        bld <+ (mE := oE)
        bld <+ (mF := oF)
        bld <+ (mG := oG)
        bld <+ (mH := oH)
        let oprA = Array.init packNum (fun i -> AST.extract mA packSz (i * pos))
        let oprB = Array.init packNum (fun i -> AST.extract mB packSz (i * pos))
        let oprC = Array.init packNum (fun i -> AST.extract mC packSz (i * pos))
        let oprD = Array.init packNum (fun i -> AST.extract mD packSz (i * pos))
        let oprE = Array.init packNum (fun i -> AST.extract mE packSz (i * pos))
        let oprF = Array.init packNum (fun i -> AST.extract mF packSz (i * pos))
        let oprG = Array.init packNum (fun i -> AST.extract mG packSz (i * pos))
        let oprH = Array.init packNum (fun i -> AST.extract mH packSz (i * pos))
        Array.concat [| oprA; oprB; oprC; oprD; oprE; oprF; oprG; oprH |]
      | _ -> raise InvalidOperandSizeException
    | _ ->
      match oprSize with
      | 64<rt> ->
        let opr = transOprToExpr bld false ins insLen opr
        Array.init packNum (fun i -> AST.extract opr packSz (i * pos))
      | 128<rt> ->
        let struct (oB, oA) = transOprToExpr128 bld false ins insLen opr
        let oprA = Array.init packNum (fun i -> AST.extract oA packSz (i * pos))
        let oprB = Array.init packNum (fun i -> AST.extract oB packSz (i * pos))
        Array.append oprA oprB
      | 256<rt> ->
        let struct (oD, oC, oB, oA) = transOprToExpr256 bld false ins insLen opr
        let oprA = Array.init packNum (fun i -> AST.extract oA packSz (i * pos))
        let oprB = Array.init packNum (fun i -> AST.extract oB packSz (i * pos))
        let oprC = Array.init packNum (fun i -> AST.extract oC packSz (i * pos))
        let oprD = Array.init packNum (fun i -> AST.extract oD packSz (i * pos))
        Array.concat [| oprA; oprB; oprC; oprD |]
      | 512<rt> ->
        let struct (oH, oG, oF, oE, oD, oC, oB, oA) =
          transOprToExpr512 bld false ins insLen opr
        let oprA = Array.init packNum (fun i -> AST.extract oA packSz (i * pos))
        let oprB = Array.init packNum (fun i -> AST.extract oB packSz (i * pos))
        let oprC = Array.init packNum (fun i -> AST.extract oC packSz (i * pos))
        let oprD = Array.init packNum (fun i -> AST.extract oD packSz (i * pos))
        let oprE = Array.init packNum (fun i -> AST.extract oE packSz (i * pos))
        let oprF = Array.init packNum (fun i -> AST.extract oF packSz (i * pos))
        let oprG = Array.init packNum (fun i -> AST.extract oG packSz (i * pos))
        let oprH = Array.init packNum (fun i -> AST.extract oH packSz (i * pos))
        Array.concat [| oprA; oprB; oprC; oprD; oprE; oprF; oprG; oprH |]
      | _ -> raise InvalidOperandSizeException
  if useTmpVars then
    let tmps = Array.init (oprSize / packSz) (fun _ -> tmpVar bld packSz)
    Array.iter2 (fun e1 e2 -> bld <+ (e1 := e2)) tmps exprArr
    tmps
  else exprArr

let private isMMXReg = function
  | OprReg r -> Register.getKind r = Register.Kind.MMX
  | _ -> false

let private convMMXToST = function
  | OprReg R.MM0 -> R.ST0
  | OprReg R.MM1 -> R.ST1
  | OprReg R.MM2 -> R.ST2
  | OprReg R.MM3 -> R.ST3
  | OprReg R.MM4 -> R.ST4
  | OprReg R.MM5 -> R.ST5
  | OprReg R.MM6 -> R.ST6
  | OprReg R.MM7 -> R.ST7
  | _ -> raise InvalidOperandException

let fillOnesToMMXHigh16 bld (ins: Instruction) =
  match ins.Operands with
  | TwoOperands (OprReg _ as o, _)
  | ThreeOperands (OprReg _ as o, _, _) ->
    bld <+ (pseudoRegVar bld (convMMXToST o) 2 := AST.num BitVector.MaxUInt16)
  | _ -> ()

let assignPackedInstr bld useTmpVar ins insLen packNum oprSize dst result =
  match oprSize with
  | 64<rt> when isMMXReg dst ->
    let dst = transOprToExpr bld useTmpVar ins insLen dst
    bld <+ (dst := result |> AST.revConcat)
    fillOnesToMMXHigh16 bld ins
  | 64<rt> ->
    let dst = transOprToExpr bld useTmpVar ins insLen dst
    bld <+ (dst := result |> AST.revConcat)
  | 128<rt> ->
    let struct (dstB, dstA) = transOprToExpr128 bld useTmpVar ins insLen dst
    bld <+ (dstA := Array.sub result 0 packNum |> AST.revConcat)
    bld <+ (dstB := Array.sub result packNum packNum |> AST.revConcat)
  | 256<rt> ->
    let struct (dstD, dstC, dstB, dstA) =
      transOprToExpr256 bld false ins insLen dst
    bld <+ (dstA := Array.sub result 0 packNum |> AST.revConcat)
    bld <+ (dstB := Array.sub result (1 * packNum) packNum |> AST.revConcat)
    bld <+ (dstC := Array.sub result (2 * packNum) packNum |> AST.revConcat)
    bld <+ (dstD := Array.sub result (3 * packNum) packNum |> AST.revConcat)
  | 512<rt> ->
    let struct (dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA) =
      transOprToExpr512 bld false ins insLen dst
    bld <+ (dstA := Array.sub result 0 packNum |> AST.revConcat)
    bld <+ (dstB := Array.sub result (1 * packNum) packNum |> AST.revConcat)
    bld <+ (dstC := Array.sub result (2 * packNum) packNum |> AST.revConcat)
    bld <+ (dstD := Array.sub result (3 * packNum) packNum |> AST.revConcat)
    bld <+ (dstE := Array.sub result (4 * packNum) packNum |> AST.revConcat)
    bld <+ (dstF := Array.sub result (5 * packNum) packNum |> AST.revConcat)
    bld <+ (dstG := Array.sub result (6 * packNum) packNum |> AST.revConcat)
    bld <+ (dstH := Array.sub result (7 * packNum) packNum |> AST.revConcat)
  | _ -> raise InvalidOperandSizeException

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

let transOneOpr bld (ins: Instruction) insLen =
  match ins.Operands with
  | OneOperand opr -> transOprToExpr bld true ins insLen opr
  | _ -> raise InvalidOperandException

let transReg bld useTmpVar expr =
  if useTmpVar then
    match expr with
    | Extract (_, rt, _, _) ->
      let t = tmpVar bld rt
      bld <+ (t := expr)
      t
    | _ -> expr
  else expr

let transTwoOprs bld useTmpVar (ins: Instruction) insLen =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    let o1 = transOprToExpr bld useTmpVar ins insLen o1
    let o2 = transOprToExpr bld false ins insLen o2 |> transReg bld useTmpVar
    struct (o1, o2)
  | _ -> raise InvalidOperandException

let transThreeOprs bld useTmpVar (ins: Instruction) insLen =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    struct (transOprToExpr bld useTmpVar ins insLen o1,
            transOprToExpr bld useTmpVar ins insLen o2,
            transOprToExpr bld useTmpVar ins insLen o3)
  | _ -> raise InvalidOperandException

/// This is an Intel-specific assignment to a destination operand.
/// Unlike typical assignments, this function performs zero-padding when
/// necessary (See Intel Manual 3.4.1.1).
/// In 64-bit mode, operand size determines the number of valid bits.
/// 64-bit operands generate a 64-bit result in the destination general-purpose
/// register. 32-bit operands generate a 32-bit result, zero-extended to a
/// 64-bit result in the destination general-purpose register. 8-bit and 16-bit
/// operands generate 8-bit or 16-bit result. The upper 56 or 48 bits
/// (respectively) of the destination general-purpose register are not modified.
let dstAssign oprSize dst src =
  match oprSize with
  | 8<rt> | 16<rt> -> dst := src (* No extension for 8- and 16-bit operands *)
  | _ -> let dst = AST.unwrap dst
         let dstOrigSz = dst |> Expr.TypeOf
         let oprBitSize = RegType.toBitWidth oprSize
         let dstBitSize = RegType.toBitWidth dstOrigSz
         if dstBitSize > oprBitSize then dst := AST.zext dstOrigSz src
         elif dstBitSize = oprBitSize then dst := src
         else raise InvalidOperandSizeException

/// For x87 FPU Top register or x87 FPU Tag word sections.
let extractDstAssign e1 e2 =
  match e1 with
  | Extract (BinOp (BinOpType.SHR, 16<rt>,
                    BinOp (BinOpType.AND, 16<rt>,
                           (Var (16<rt>, rId, _, _) as e1),
                           mask, _),
                    amt, _),
             8<rt>, 0, _) when int rId = 0x4F (* FSW *)
                            || int rId = 0x50 (* FTW *) ->
    e1 := (e1 .& (AST.not mask)) .| (((AST.zext 16<rt> e2) << amt) .& mask)
  | e -> printfn "%A" e; raise InvalidAssignmentException

let maxNum rt =
  match rt with
  | 8<rt> -> BitVector.MaxUInt8
  | 16<rt> -> BitVector.MaxUInt16
  | 32<rt> -> BitVector.MaxUInt32
  | 64<rt> -> BitVector.MaxUInt64
  | _ -> raise InvalidOperandSizeException
  |> AST.num

let castNum newType e =
  match e with
  | Num (n, _) -> BitVector.Cast (n, newType) |> AST.num
  | _ -> raise InvalidOperandException

let getMask oprSize =
  match oprSize with
  | 8<rt> -> numI64 0xffL oprSize
  | 16<rt> -> numI64 0xffffL oprSize
  | 32<rt> -> numI64 0xffffffffL oprSize
  | 64<rt> -> numI64 0xffffffffffffffffL oprSize
  | _ -> raise InvalidOperandSizeException

let sideEffects bld (ins: Instruction) insLen name =
  bld <!-- (ins.Address, insLen)
#if EMULATION
  if bld.ConditionCodeOp <> ConditionCodeOp.TraceStart then
    bld <+ (regVar bld R.CCOP := numI32 (int bld.ConditionCodeOp) 8<rt>)
  else ()
  bld.ConditionCodeOp <- ConditionCodeOp.TraceStart
#endif
  bld <+ (AST.sideEffect name)
  bld --!> insLen

let hasStackPtr (ins: Instruction) =
  match ins.Operands with
  | OneOperand (OprReg Register.ESP)
  | OneOperand (OprReg Register.RSP)
  | OneOperand (OprMem (Some Register.ESP, _, _, _))
  | OneOperand (OprMem (Some Register.RSP, _, _, _))
  | OneOperand (OprMem (_, Some (Register.ESP, _), _, _))
  | OneOperand (OprMem (_, Some (Register.RSP, _), _, _)) -> true
  | _ -> false

let buildAF bld e1 e2 r size =
  let t1 = r <+> e1
  let t2 = t1 <+> e2
  let t3 = (AST.num1 size) << (numU32 4ul size)
  let t4 = t2 .& t3
  regVar bld R.AF := t4 == t3

let isExprZero e =
  match e with
  | Num (bv, _) when bv.IsZero () -> true
  | _ -> false

let buildPF bld r size cond =
  let pf = regVar bld R.PF
  let computedPF =
    if isExprZero r then
      AST.num1 1<rt>
    else
      let struct (t1, t2) = tmpVars2 bld size
      let s2 = r <+> (r >> (AST.zext size (numU32 4ul 8<rt>)))
      let s4 = t1 <+> (t1 >> (AST.zext size (numU32 2ul 8<rt>)))
      let s5 = t2 <+> (t2 >> (AST.zext size (AST.num1 8<rt>)))
      bld <+ (t1 := s2)
      bld <+ (t2 := s4)
      AST.unop UnOpType.NOT (AST.xtlo 1<rt> s5)
  bld <+ (match cond with
          | None -> pf := computedPF
          | Some cond -> pf := AST.ite cond pf computedPF)

let enumSZPFlags bld r size sf =
  bld <+ (regVar bld R.SF := sf)
  bld <+ (regVar bld R.ZF := r == (AST.num0 size))
  buildPF bld r size None

let enumASZPFlags bld e1 e2 r size sf =
  bld <+ (buildAF bld e1 e2 r size)
  enumSZPFlags bld r size sf

let enumEFLAGS bld e1 e2 e3 size cf ofl sf =
  bld <+ (regVar bld R.CF := cf)
  bld <+ (regVar bld R.OF := ofl)
  bld <+ (buildAF bld e1 e2 e3 size)
  bld <+ (regVar bld R.SF := sf)
  bld <+ (regVar bld R.ZF := e3 == (AST.num0 size))
  buildPF bld e3 size None

/// CF on add.
let cfOnAdd e1 r = r .< e1

/// CF on sub.
let cfOnSub e1 e2 = e1 .< e2

/// OF and SF on add.
let osfOnAdd e1 e2 r bld =
  if e1 = e2 then
    let rHigh = tmpVar bld 1<rt>
    let e1High = AST.xthi 1<rt> e1
    bld <+ (rHigh := AST.xthi 1<rt> r)
    struct ((e1High <+> rHigh), rHigh)
  else
    let struct (t1, t2) = tmpVars2 bld 1<rt>
    let e1High = AST.xthi 1<rt> e1
    let e2High = AST.xthi 1<rt> e2
    let rHigh = AST.xthi 1<rt> r
    bld <+ (t1 := e1High)
    bld <+ (t2 := rHigh)
    struct ((t1 == e2High) .& (t1 <+> t2), t2)

/// OF on sub.
let ofOnSub e1 e2 r =
  AST.xthi 1<rt> ((e1 <+> e2) .& (e1 <+> r))

#if EMULATION
let getCCSrc1 bld regType =
  match regType with
  | 8<rt> -> regVar bld R.CCSRC1B
  | 16<rt> -> regVar bld R.CCSRC1W
  | 32<rt> -> regVar bld R.CCSRC1D
  | 64<rt> -> regVar bld R.CCSRC1
  | _ -> Terminator.impossible ()

let getCCSrc2 bld regType =
  match regType with
  | 8<rt> -> regVar bld R.CCSRC2B
  | 16<rt> -> regVar bld R.CCSRC2W
  | 32<rt> -> regVar bld R.CCSRC2D
  | 64<rt> -> regVar bld R.CCSRC2
  | _ -> Terminator.impossible ()

let getCCDst bld regType =
  match regType with
  | 8<rt> -> regVar bld R.CCDSTB
  | 16<rt> -> regVar bld R.CCDSTW
  | 32<rt> -> regVar bld R.CCDSTD
  | 64<rt> -> regVar bld R.CCDST
  | _ -> Terminator.impossible ()

let setCCOperands2 bld src1 dst =
  let ccSrc1 = regVar bld R.CCSRC1
  let ccDst = regVar bld R.CCDST
  bld <+ (ccSrc1 := AST.zext bld.RegType src1)
  bld <+ (ccDst := AST.zext bld.RegType dst)

let setCCOperands3 bld src1 src2 dst =
  let ccSrc1 = regVar bld R.CCSRC1
  let ccSrc2 = regVar bld R.CCSRC2
  let ccDst = regVar bld R.CCDST
  bld <+ (ccSrc1 := AST.zext bld.RegType src1)
  bld <+ (ccSrc2 := AST.zext bld.RegType src2)
  bld <+ (ccDst := AST.zext bld.RegType dst)

let setCCDst bld dst =
  let ccDst = regVar bld R.CCDST
  bld <+ (ccDst := AST.zext bld.RegType dst)

let setCCOp (bld: ILowUIRBuilder) =
  if bld.ConditionCodeOp <> ConditionCodeOp.TraceStart then
    bld <+ (regVar bld R.CCOP := numI32 (int bld.ConditionCodeOp) 8<rt>)
  else ()

let genDynamicFlagsUpdate bld =
  setCCOp bld
  bld <+ (AST.sideEffect FlagsUpdate)
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags

let getOFLazy (bld: ILowUIRBuilder) =
  let ccOp = bld.ConditionCodeOp
  match ccOp with
  | ConditionCodeOp.SUBB
  | ConditionCodeOp.SUBW
  | ConditionCodeOp.SUBD
  | ConditionCodeOp.SUBQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 bld regType
    let src1 = getCCSrc1 bld regType
    let dst = getCCDst bld regType
    bld <+ (t3 := dst)
    bld <+ (t2 := src1)
    bld <+ (t1 := t3 .+ t2)
    let sf = t3 ?< AST.num0 regType
    let cf = cfOnSub t1 t2
    let ofl = ofOnSub t1 t2 t3
    enumEFLAGS bld t1 t2 t3 regType cf ofl sf
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
    regVar bld R.OF
  | ConditionCodeOp.DECB
  | ConditionCodeOp.DECW
  | ConditionCodeOp.DECD
  | ConditionCodeOp.DECQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 bld regType
    let src1 = getCCSrc1 bld regType
    let dst = getCCDst bld regType
    bld <+ (t3 := dst)
    bld <+ (t2 := src1)
    bld <+ (t1 := t3 .+ t2)
    let sf = t3 ?< AST.num0 regType
    let cf = regVar bld R.CF
    let ofl = ofOnSub t1 t2 t3
    enumEFLAGS bld t1 t2 t3 regType cf ofl sf
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
    regVar bld R.OF
  | ConditionCodeOp.ADDB
  | ConditionCodeOp.ADDW
  | ConditionCodeOp.ADDD
  | ConditionCodeOp.ADDQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 bld regType
    let src1 = getCCSrc1 bld regType
    let dst = getCCDst bld regType
    bld <+ (t3 := dst)
    bld <+ (t1 := src1)
    bld <+ (t2 := t3 .- t1)
    let cf = cfOnAdd t1 t3
    let struct (ofl, sf) = osfOnAdd t1 t2 t3 bld
    enumEFLAGS bld t1 t2 t3 regType cf ofl sf
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
    regVar bld R.OF
  | ConditionCodeOp.INCB
  | ConditionCodeOp.INCW
  | ConditionCodeOp.INCD
  | ConditionCodeOp.INCQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 bld regType
    let src1 = getCCSrc1 bld regType
    let dst = getCCDst bld regType
    bld <+ (t3 := dst)
    bld <+ (t1 := src1)
    bld <+ (t2 := t3 .- t1)
    let cf = regVar bld R.CF
    let struct (ofl, sf) = osfOnAdd t1 t2 t3 bld
    enumEFLAGS bld t1 t2 t3 regType cf ofl sf
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
    regVar bld R.OF
  | ConditionCodeOp.SHLB
  | ConditionCodeOp.SHLW
  | ConditionCodeOp.SHLD
  | ConditionCodeOp.SHLQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 bld regType
    let src1 = getCCSrc1 bld regType
    let src2 = getCCSrc2 bld regType
    let dst = getCCDst bld regType
    let n0 = AST.num0 regType
    let n1 = AST.num1 regType
    let cond1 = src2 == n1
    let cond2 = src2 == n0
    let cf = regVar bld R.CF
    let sf = regVar bld R.SF
    let zf = regVar bld R.ZF
    let ofl = regVar bld R.OF
    let newOf = AST.xthi 1<rt> dst <+> cf
    bld <+ (t1 := src1)
    bld <+ (t2 := src2)
    bld <+ (t3 := dst)
    bld <+ (cf := AST.ite cond2 cf (AST.xthi 1<rt> (t1 << (t2 .- n1))))
    bld <+ (ofl := AST.ite cond1 newOf ofl)
    bld <+ (sf := AST.ite cond2 sf (AST.xthi 1<rt> t3))
    buildPF bld dst regType (Some cond2)
    bld <+ (zf := AST.ite cond2 zf (t3 == n0))
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
    regVar bld R.OF
  | ConditionCodeOp.SHRB
  | ConditionCodeOp.SHRW
  | ConditionCodeOp.SHRD
  | ConditionCodeOp.SHRQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 bld regType
    let src1 = getCCSrc1 bld regType
    let src2 = getCCSrc2 bld regType
    let dst = getCCDst bld regType
    let n0 = AST.num0 regType
    let n1 = AST.num1 regType
    let cond1 = src2 == n1
    let cond2 = src2 == n0
    let cf = regVar bld R.CF
    let sf = regVar bld R.SF
    let zf = regVar bld R.ZF
    let ofl = regVar bld R.OF
    bld <+ (t1 := src1)
    bld <+ (t2 := src2)
    bld <+ (t3 := dst)
    bld <+ (cf := AST.ite cond2 cf (AST.xtlo 1<rt> (t1 ?>> (t2 .- n1))))
    bld <+ (ofl := AST.ite cond1 (AST.xthi 1<rt> t1) ofl)
    bld <+ (sf := AST.ite cond2 sf (AST.xthi 1<rt> t3))
    buildPF bld dst regType (Some cond2)
    bld <+ (zf := AST.ite cond2 zf (t3 == n0))
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
    regVar bld R.OF
  | ConditionCodeOp.SARB
  | ConditionCodeOp.SARW
  | ConditionCodeOp.SARD
  | ConditionCodeOp.SARQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 bld regType
    let src1 = getCCSrc1 bld regType
    let src2 = getCCSrc2 bld regType
    let dst = getCCDst bld regType
    let n0 = AST.num0 regType
    let n1 = AST.num1 regType
    let cond1 = src2 == n1
    let cond2 = src2 == n0
    let cf = regVar bld R.CF
    let sf = regVar bld R.SF
    let zf = regVar bld R.ZF
    let ofl = regVar bld R.OF
    bld <+ (t1 := src1)
    bld <+ (t2 := src2)
    bld <+ (t3 := dst)
    bld <+ (cf := AST.ite cond2 cf (AST.xtlo 1<rt> (t1 ?>> (t2 .- n1))))
    bld <+ (ofl := AST.ite cond1 AST.b0 ofl)
    bld <+ (sf := AST.ite cond2 sf (AST.xthi 1<rt> t3))
    buildPF bld dst regType (Some cond2)
    bld <+ (zf := AST.ite cond2 zf (t3 == n0))
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
    regVar bld R.OF
  | ConditionCodeOp.LOGICB
  | ConditionCodeOp.LOGICW
  | ConditionCodeOp.LOGICD
  | ConditionCodeOp.LOGICQ
  | ConditionCodeOp.XORXX ->
    AST.b0
  | ConditionCodeOp.TraceStart ->
    genDynamicFlagsUpdate bld
    regVar bld R.OF
  | ConditionCodeOp.EFlags ->
    regVar bld R.OF
  | _ -> Terminator.futureFeature ()

let getSFLazy (bld: ILowUIRBuilder) =
  let ccOp = bld.ConditionCodeOp
  match ccOp with
  | ConditionCodeOp.SUBB
  | ConditionCodeOp.SUBW
  | ConditionCodeOp.SUBD
  | ConditionCodeOp.SUBQ
  | ConditionCodeOp.LOGICB
  | ConditionCodeOp.LOGICW
  | ConditionCodeOp.LOGICD
  | ConditionCodeOp.LOGICQ
  | ConditionCodeOp.ADDB
  | ConditionCodeOp.ADDW
  | ConditionCodeOp.ADDD
  | ConditionCodeOp.ADDQ
  | ConditionCodeOp.INCB
  | ConditionCodeOp.INCW
  | ConditionCodeOp.INCD
  | ConditionCodeOp.INCQ
  | ConditionCodeOp.DECB
  | ConditionCodeOp.DECW
  | ConditionCodeOp.DECD
  | ConditionCodeOp.DECQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let t = getCCDst bld regType
    t ?< AST.num0 regType
  | ConditionCodeOp.SHLB
  | ConditionCodeOp.SHLW
  | ConditionCodeOp.SHLD
  | ConditionCodeOp.SHLQ
  | ConditionCodeOp.SHRB
  | ConditionCodeOp.SHRW
  | ConditionCodeOp.SHRD
  | ConditionCodeOp.SHRQ
  | ConditionCodeOp.SARB
  | ConditionCodeOp.SARW
  | ConditionCodeOp.SARD
  | ConditionCodeOp.SARQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let t = getCCDst bld regType
    let cnt = getCCSrc2 bld regType
    AST.ite (cnt == AST.num0 regType) (regVar bld R.SF) (t ?< AST.num0 regType)
  | ConditionCodeOp.XORXX ->
    AST.b0
  | ConditionCodeOp.TraceStart ->
    genDynamicFlagsUpdate bld
    regVar bld R.SF
  | ConditionCodeOp.EFlags ->
    regVar bld R.SF
  | _ -> Terminator.futureFeature ()

let getZFLazy (bld: ILowUIRBuilder) =
  let ccOp = bld.ConditionCodeOp
  match ccOp with
  | ConditionCodeOp.SUBB
  | ConditionCodeOp.SUBW
  | ConditionCodeOp.SUBD
  | ConditionCodeOp.SUBQ
  | ConditionCodeOp.LOGICB
  | ConditionCodeOp.LOGICW
  | ConditionCodeOp.LOGICD
  | ConditionCodeOp.LOGICQ
  | ConditionCodeOp.ADDB
  | ConditionCodeOp.ADDW
  | ConditionCodeOp.ADDD
  | ConditionCodeOp.ADDQ
  | ConditionCodeOp.INCB
  | ConditionCodeOp.INCW
  | ConditionCodeOp.INCD
  | ConditionCodeOp.INCQ
  | ConditionCodeOp.DECB
  | ConditionCodeOp.DECW
  | ConditionCodeOp.DECD
  | ConditionCodeOp.DECQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let t = getCCDst bld regType
    t == AST.num0 regType
  | ConditionCodeOp.SHLB
  | ConditionCodeOp.SHLW
  | ConditionCodeOp.SHLD
  | ConditionCodeOp.SHLQ
  | ConditionCodeOp.SHRB
  | ConditionCodeOp.SHRW
  | ConditionCodeOp.SHRD
  | ConditionCodeOp.SHRQ
  | ConditionCodeOp.SARB
  | ConditionCodeOp.SARW
  | ConditionCodeOp.SARD
  | ConditionCodeOp.SARQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let t = getCCDst bld regType
    let cnt = getCCSrc2 bld regType
    AST.ite (cnt == AST.num0 regType) (regVar bld R.ZF) (t == AST.num0 regType)
  | ConditionCodeOp.XORXX ->
    AST.b1
  | ConditionCodeOp.TraceStart ->
    genDynamicFlagsUpdate bld
    regVar bld R.ZF
  | ConditionCodeOp.EFlags ->
    regVar bld R.ZF
  | _ -> Terminator.futureFeature ()

let getAFLazy (bld: ILowUIRBuilder) =
  let ccOp = bld.ConditionCodeOp
  match ccOp with
  | ConditionCodeOp.SUBB
  | ConditionCodeOp.SUBW
  | ConditionCodeOp.SUBD
  | ConditionCodeOp.SUBQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 bld regType
    let src1 = getCCSrc1 bld regType
    let dst = getCCDst bld regType
    bld <+ (t3 := dst)
    bld <+ (t2 := src1)
    bld <+ (t1 := t3 .+ t2)
    let sf = t3 ?< AST.num0 regType
    let cf = cfOnSub t1 t2
    let ofl = ofOnSub t1 t2 t3
    enumEFLAGS bld t1 t2 t3 regType cf ofl sf
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
    regVar bld R.AF
  | ConditionCodeOp.DECB
  | ConditionCodeOp.DECW
  | ConditionCodeOp.DECD
  | ConditionCodeOp.DECQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 bld regType
    let src1 = getCCSrc1 bld regType
    let dst = getCCDst bld regType
    bld <+ (t3 := dst)
    bld <+ (t2 := src1)
    bld <+ (t1 := t3 .+ t2)
    let sf = t3 ?< AST.num0 regType
    let cf = regVar bld R.CF
    let ofl = ofOnSub t1 t2 t3
    enumEFLAGS bld t1 t2 t3 regType cf ofl sf
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
    regVar bld R.AF
  | ConditionCodeOp.ADDB
  | ConditionCodeOp.ADDW
  | ConditionCodeOp.ADDD
  | ConditionCodeOp.ADDQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 bld regType
    let src1 = getCCSrc1 bld regType
    let dst = getCCDst bld regType
    bld <+ (t3 := dst)
    bld <+ (t1 := src1)
    bld <+ (t2 := t3 .- t1)
    let cf = cfOnAdd t1 t3
    let struct (ofl, sf) = osfOnAdd t1 t2 t3 bld
    enumEFLAGS bld t1 t2 t3 regType cf ofl sf
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
    regVar bld R.AF
  | ConditionCodeOp.INCB
  | ConditionCodeOp.INCW
  | ConditionCodeOp.INCD
  | ConditionCodeOp.INCQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 bld regType
    let src1 = getCCSrc1 bld regType
    let dst = getCCDst bld regType
    bld <+ (t3 := dst)
    bld <+ (t1 := src1)
    bld <+ (t2 := t3 .- t1)
    let cf = regVar bld R.CF
    let struct (ofl, sf) = osfOnAdd t1 t2 t3 bld
    enumEFLAGS bld t1 t2 t3 regType cf ofl sf
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
    regVar bld R.AF
  | ConditionCodeOp.SHLB
  | ConditionCodeOp.SHLW
  | ConditionCodeOp.SHLD
  | ConditionCodeOp.SHLQ
  | ConditionCodeOp.SHRB
  | ConditionCodeOp.SHRW
  | ConditionCodeOp.SHRD
  | ConditionCodeOp.SHRQ
  | ConditionCodeOp.SARB
  | ConditionCodeOp.SARW
  | ConditionCodeOp.SARD
  | ConditionCodeOp.SARQ
  | ConditionCodeOp.LOGICB
  | ConditionCodeOp.LOGICW
  | ConditionCodeOp.LOGICD
  | ConditionCodeOp.LOGICQ
  | ConditionCodeOp.XORXX ->
    regVar bld R.AF
  | ConditionCodeOp.TraceStart ->
    genDynamicFlagsUpdate bld
    regVar bld R.AF
  | ConditionCodeOp.EFlags ->
    regVar bld R.AF
  | _ -> Terminator.futureFeature ()

let getPFLazy (bld: ILowUIRBuilder) =
  let ccOp = bld.ConditionCodeOp
  match ccOp with
  | ConditionCodeOp.SUBB
  | ConditionCodeOp.SUBW
  | ConditionCodeOp.SUBD
  | ConditionCodeOp.SUBQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 bld regType
    let src1 = getCCSrc1 bld regType
    let dst = getCCDst bld regType
    bld <+ (t3 := dst)
    bld <+ (t2 := src1)
    bld <+ (t1 := t3 .+ t2)
    let sf = t3 ?< AST.num0 regType
    let cf = cfOnSub t1 t2
    let ofl = ofOnSub t1 t2 t3
    enumEFLAGS bld t1 t2 t3 regType cf ofl sf
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
    regVar bld R.PF
  | ConditionCodeOp.DECB
  | ConditionCodeOp.DECW
  | ConditionCodeOp.DECD
  | ConditionCodeOp.DECQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 bld regType
    let src1 = getCCSrc1 bld regType
    let dst = getCCDst bld regType
    bld <+ (t3 := dst)
    bld <+ (t2 := src1)
    bld <+ (t1 := t3 .+ t2)
    let sf = t3 ?< AST.num0 regType
    let cf = regVar bld R.CF
    let ofl = ofOnSub t1 t2 t3
    enumEFLAGS bld t1 t2 t3 regType cf ofl sf
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
    regVar bld R.PF
  | ConditionCodeOp.ADDB
  | ConditionCodeOp.ADDW
  | ConditionCodeOp.ADDD
  | ConditionCodeOp.ADDQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 bld regType
    let src1 = getCCSrc1 bld regType
    let dst = getCCDst bld regType
    bld <+ (t3 := dst)
    bld <+ (t1 := src1)
    bld <+ (t2 := t3 .- t1)
    let cf = cfOnAdd t1 t3
    let struct (ofl, sf) = osfOnAdd t1 t2 t3 bld
    enumEFLAGS bld t1 t2 t3 regType cf ofl sf
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
    regVar bld R.PF
  | ConditionCodeOp.INCB
  | ConditionCodeOp.INCW
  | ConditionCodeOp.INCD
  | ConditionCodeOp.INCQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 bld regType
    let src1 = getCCSrc1 bld regType
    let dst = getCCDst bld regType
    bld <+ (t3 := dst)
    bld <+ (t1 := src1)
    bld <+ (t2 := t3 .- t1)
    let cf = regVar bld R.CF
    let struct (ofl, sf) = osfOnAdd t1 t2 t3 bld
    enumEFLAGS bld t1 t2 t3 regType cf ofl sf
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
    regVar bld R.PF
  | ConditionCodeOp.SHLB
  | ConditionCodeOp.SHLW
  | ConditionCodeOp.SHLD
  | ConditionCodeOp.SHLQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 bld regType
    let src1 = getCCSrc1 bld regType
    let src2 = getCCSrc2 bld regType
    let dst = getCCDst bld regType
    let n0 = AST.num0 regType
    let n1 = AST.num1 regType
    let cond1 = src2 == n1
    let cond2 = src2 == n0
    let cf = regVar bld R.CF
    let sf = regVar bld R.SF
    let zf = regVar bld R.ZF
    let ofl = regVar bld R.OF
    let newOf = AST.xthi 1<rt> dst <+> cf
    bld <+ (t1 := src1)
    bld <+ (t2 := src2)
    bld <+ (t3 := dst)
    bld <+ (cf := AST.ite cond2 cf (AST.xthi 1<rt> (t1 << (t2 .- n1))))
    bld <+ (ofl := AST.ite cond1 newOf ofl)
    bld <+ (sf := AST.ite cond2 sf (AST.xthi 1<rt> t3))
    buildPF bld dst regType (Some cond2)
    bld <+ (zf := AST.ite cond2 zf (t3 == n0))
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
    regVar bld R.PF
  | ConditionCodeOp.SHRB
  | ConditionCodeOp.SHRW
  | ConditionCodeOp.SHRD
  | ConditionCodeOp.SHRQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 bld regType
    let src1 = getCCSrc1 bld regType
    let src2 = getCCSrc2 bld regType
    let dst = getCCDst bld regType
    let n0 = AST.num0 regType
    let n1 = AST.num1 regType
    let cond1 = src2 == n1
    let cond2 = src2 == n0
    let cf = regVar bld R.CF
    let sf = regVar bld R.SF
    let zf = regVar bld R.ZF
    let ofl = regVar bld R.OF
    bld <+ (t1 := src1)
    bld <+ (t2 := src2)
    bld <+ (t3 := dst)
    bld <+ (cf := AST.ite cond2 cf (AST.xtlo 1<rt> (t1 ?>> (t2 .- n1))))
    bld <+ (ofl := AST.ite cond1 (AST.xthi 1<rt> t1) ofl)
    bld <+ (sf := AST.ite cond2 sf (AST.xthi 1<rt> t3))
    buildPF bld dst regType (Some cond2)
    bld <+ (zf := AST.ite cond2 zf (t3 == n0))
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
    regVar bld R.PF
  | ConditionCodeOp.SARB
  | ConditionCodeOp.SARW
  | ConditionCodeOp.SARD
  | ConditionCodeOp.SARQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 bld regType
    let src1 = getCCSrc1 bld regType
    let src2 = getCCSrc2 bld regType
    let dst = getCCDst bld regType
    let n0 = AST.num0 regType
    let n1 = AST.num1 regType
    let cond1 = src2 == n1
    let cond2 = src2 == n0
    let cf = regVar bld R.CF
    let sf = regVar bld R.SF
    let zf = regVar bld R.ZF
    let ofl = regVar bld R.OF
    bld <+ (t1 := src1)
    bld <+ (t2 := src2)
    bld <+ (t3 := dst)
    bld <+ (cf := AST.ite cond2 cf (AST.xtlo 1<rt> (t1 ?>> (t2 .- n1))))
    bld <+ (ofl := AST.ite cond1 AST.b0 ofl)
    bld <+ (sf := AST.ite cond2 sf (AST.xthi 1<rt> t3))
    buildPF bld dst regType (Some cond2)
    bld <+ (zf := AST.ite cond2 zf (t3 == n0))
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
    regVar bld R.PF
  | ConditionCodeOp.LOGICB
  | ConditionCodeOp.LOGICW
  | ConditionCodeOp.LOGICD
  | ConditionCodeOp.LOGICQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let t = getCCDst bld regType
    bld <+ (regVar bld R.SF := AST.xthi 1<rt> t)
    bld <+ (regVar bld R.ZF := t == (AST.num0 regType))
    buildPF bld t regType None
    bld <+ (regVar bld R.CF := AST.b0)
    bld <+ (regVar bld R.OF := AST.b0)
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
    regVar bld R.PF
  | ConditionCodeOp.XORXX ->
    AST.b1
  | ConditionCodeOp.TraceStart ->
    genDynamicFlagsUpdate bld
    regVar bld R.PF
  | ConditionCodeOp.EFlags ->
    regVar bld R.PF
  | _ -> Terminator.futureFeature ()

let getCFLazy (bld: ILowUIRBuilder) =
  let ccOp = bld.ConditionCodeOp
  match ccOp with
  | ConditionCodeOp.SUBB
  | ConditionCodeOp.SUBW
  | ConditionCodeOp.SUBD
  | ConditionCodeOp.SUBQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let src1 = getCCSrc1 bld regType
    let dst = getCCDst bld regType
    cfOnSub (dst .+ src1) src1
  | ConditionCodeOp.ADDB
  | ConditionCodeOp.ADDW
  | ConditionCodeOp.ADDD
  | ConditionCodeOp.ADDQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let src1 = getCCSrc1 bld regType
    let dst = getCCDst bld regType
    cfOnAdd src1 dst
  | ConditionCodeOp.INCB
  | ConditionCodeOp.INCW
  | ConditionCodeOp.INCD
  | ConditionCodeOp.INCQ
  | ConditionCodeOp.DECB
  | ConditionCodeOp.DECW
  | ConditionCodeOp.DECD
  | ConditionCodeOp.DECQ ->
    regVar bld R.CF
  | ConditionCodeOp.SHLB
  | ConditionCodeOp.SHLW
  | ConditionCodeOp.SHLD
  | ConditionCodeOp.SHLQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let src1 = getCCSrc1 bld regType
    let src2 = getCCSrc2 bld regType
    let n0 = AST.num0 regType
    let n1 = AST.num1 regType
    let cond2 = src2 == n0
    let cf = regVar bld R.CF
    AST.ite cond2 cf (AST.xthi 1<rt> (src1 << (src2 .- n1)))
  | ConditionCodeOp.SHRB
  | ConditionCodeOp.SHRW
  | ConditionCodeOp.SHRD
  | ConditionCodeOp.SHRQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let src1 = getCCSrc1 bld regType
    let src2 = getCCSrc2 bld regType
    let n0 = AST.num0 regType
    let n1 = AST.num1 regType
    let cond2 = src2 == n0
    let cf = regVar bld R.CF
    AST.ite cond2 cf (AST.xtlo 1<rt> (src1 ?>> (src2 .- n1)))
  | ConditionCodeOp.SARB
  | ConditionCodeOp.SARW
  | ConditionCodeOp.SARD
  | ConditionCodeOp.SARQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let src1 = getCCSrc1 bld regType
    let src2 = getCCSrc2 bld regType
    let n0 = AST.num0 regType
    let n1 = AST.num1 regType
    let cond2 = src2 == n0
    let cf = regVar bld R.CF
    AST.ite cond2 cf (AST.xtlo 1<rt> (src1 ?>> (src2 .- n1)))
  | ConditionCodeOp.LOGICB
  | ConditionCodeOp.LOGICW
  | ConditionCodeOp.LOGICD
  | ConditionCodeOp.LOGICQ
  | ConditionCodeOp.XORXX ->
    AST.b0
  | ConditionCodeOp.TraceStart ->
    genDynamicFlagsUpdate bld
    regVar bld R.CF
  | ConditionCodeOp.EFlags ->
    regVar bld R.CF
  | _ -> Terminator.futureFeature ()
#endif
