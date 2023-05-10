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

module internal B2R2.FrontEnd.BinLifter.Intel.LiftingUtils

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingOperators
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.BinLifter.Intel.Helper

open type BinOpType

let inline ( !. ) (ctxt: TranslationContext) name =
  Register.toRegID name |> ctxt.GetRegVar

let inline getPseudoRegVar (ctxt: TranslationContext) name pos =
  ctxt.GetPseudoRegVar (Register.toRegID name) pos

let numInsLen insLen (ctxt: TranslationContext) = numU32 insLen ctxt.WordBitSize

let numOprSize = function
  | 8<rt> | 16<rt> | 32<rt> | 64<rt> | 128<rt> | 256<rt> | 512<rt> as rt ->
    numI32 (int rt) rt
  | _ -> raise InvalidOperandSizeException

let inline is64bit (ctxt: TranslationContext) = ctxt.WordBitSize = 64<rt>

let is64REXW ctxt (ins: InsInfo) =
  is64bit ctxt && hasREXW ins.REXPrefix

#if DEBUG
let assert32 ctxt =
  if is64bit ctxt then raise InvalidISAException else ()
#endif

let inline getOperationSize (i: InsInfo) = i.MainOperationSize

let inline getEffAddrSz (i: InsInfo) = i.PointerSize

let inline getImmValue imm =
  match imm with
  | OprImm (imm, _) -> imm
  | _ -> raise InvalidOperandException

let inline isConst (e: Expr) =
  match e.E with
  | Num _ -> true
  | _ -> false

let private getMemExpr128 expr =
  match expr.E with
  | Load (e, 128<rt>, { E = BinOp (BinOpType.ADD, _, b, { E = Num n }, _) }, _)
  | Load (e, 128<rt>, { E = BinOp (BinOpType.ADD, _, { E = Num n }, b, _) }, _)
    ->
    let off1 = AST.num n
    let off2 = BitVector.Add (n, BitVector.OfInt32 8 n.Length) |> AST.num
    AST.load e 64<rt> (b .+ off2),
    AST.load e 64<rt> (b .+ off1)
  | Load (e, 128<rt>, expr, _) ->
    AST.load e 64<rt> (expr .+ numI32 8 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> expr
  | _ -> raise InvalidOperandException

let private getMemExpr256 expr =
  match expr.E with
  | Load (e, 256<rt>, { E = BinOp (BinOpType.ADD, _, b, { E = Num n }, _) }, _)
  | Load (e, 256<rt>, { E = BinOp (BinOpType.ADD, _, { E = Num n }, b, _) }, _)
    ->
    let off1 = AST.num n
    let off2 = BitVector.Add (n, BitVector.OfInt32 8 n.Length) |> AST.num
    let off3 = BitVector.Add (n, BitVector.OfInt32 16 n.Length) |> AST.num
    let off4 = BitVector.Add (n, BitVector.OfInt32 24 n.Length) |> AST.num
    AST.load e 64<rt> (b .+ off4),
    AST.load e 64<rt> (b .+ off3),
    AST.load e 64<rt> (b .+ off2),
    AST.load e 64<rt> (b .+ off1)
  | Load (e, 256<rt>, expr, _) ->
    AST.load e 64<rt> (expr .+ numI32 24 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 16 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 8 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> expr
  | _ -> raise InvalidOperandException

let private getMemExpr512 expr =
  match expr.E with
  | Load (e, 512<rt>, { E = BinOp (BinOpType.ADD, _, b, { E = Num n }, _) }, _)
  | Load (e, 512<rt>, { E = BinOp (BinOpType.ADD, _, { E = Num n }, b, _) }, _)
    ->
    let off1 = AST.num n
    let off2 = BitVector.Add (n, BitVector.OfInt32 8 n.Length) |> AST.num
    let off3 = BitVector.Add (n, BitVector.OfInt32 16 n.Length) |> AST.num
    let off4 = BitVector.Add (n, BitVector.OfInt32 24 n.Length) |> AST.num
    let off5 = BitVector.Add (n, BitVector.OfInt32 32 n.Length) |> AST.num
    let off6 = BitVector.Add (n, BitVector.OfInt32 40 n.Length) |> AST.num
    let off7 = BitVector.Add (n, BitVector.OfInt32 48 n.Length) |> AST.num
    let off8 = BitVector.Add (n, BitVector.OfInt32 56 n.Length) |> AST.num
    AST.load e 64<rt> (b .+ off8),
    AST.load e 64<rt> (b .+ off7),
    AST.load e 64<rt> (b .+ off6),
    AST.load e 64<rt> (b .+ off5),
    AST.load e 64<rt> (b .+ off4),
    AST.load e 64<rt> (b .+ off3),
    AST.load e 64<rt> (b .+ off2),
    AST.load e 64<rt> (b .+ off1)
  | Load (e, 512<rt>, expr, _) ->
    AST.load e 64<rt> (expr .+ numI32 56 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 48 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 40 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 32 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 24 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 16 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 8 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> expr
  | _ -> raise InvalidOperandException

let private getMemExprs expr =
  match expr.E with
  | Load (e, 128<rt>, expr, _) ->
    [ AST.load e 64<rt> expr
      AST.load e 64<rt> (expr .+ numI32 8 (TypeCheck.typeOf expr)) ]
  | Load (e, 256<rt>, expr, _) ->
    [ AST.load e 64<rt> expr
      AST.load e 64<rt> (expr .+ numI32 8 (TypeCheck.typeOf expr))
      AST.load e 64<rt> (expr .+ numI32 16 (TypeCheck.typeOf expr))
      AST.load e 64<rt> (expr .+ numI32 24 (TypeCheck.typeOf expr)) ]
  | Load (e, 512<rt>, expr, _) ->
    [ AST.load e 64<rt> expr
      AST.load e 64<rt> (expr .+ numI32 8 (TypeCheck.typeOf expr))
      AST.load e 64<rt> (expr .+ numI32 16 (TypeCheck.typeOf expr))
      AST.load e 64<rt> (expr .+ numI32 24 (TypeCheck.typeOf expr))
      AST.load e 64<rt> (expr .+ numI32 32 (TypeCheck.typeOf expr))
      AST.load e 64<rt> (expr .+ numI32 40 (TypeCheck.typeOf expr))
      AST.load e 64<rt> (expr .+ numI32 48 (TypeCheck.typeOf expr))
      AST.load e 64<rt> (expr .+ numI32 56 (TypeCheck.typeOf expr)) ]
  | _ -> raise InvalidOperandException

let getPseudoRegVar128 ctxt r =
  getPseudoRegVar ctxt r 2, getPseudoRegVar ctxt r 1

let getPseudoRegVar256 ctxt r =
  getPseudoRegVar ctxt r 4, getPseudoRegVar ctxt r 3,
  getPseudoRegVar ctxt r 2, getPseudoRegVar ctxt r 1

let getPseudoRegVar512 ctxt r =
  getPseudoRegVar ctxt r 8, getPseudoRegVar ctxt r 7,
  getPseudoRegVar ctxt r 6, getPseudoRegVar ctxt r 5,
  getPseudoRegVar ctxt r 4, getPseudoRegVar ctxt r 3,
  getPseudoRegVar ctxt r 2, getPseudoRegVar ctxt r 1

let private getPseudoRegVars ctxt r =
  match Register.getKind r with
  | Register.Kind.XMM -> [ getPseudoRegVar ctxt r 1; getPseudoRegVar ctxt r 2 ]
  | Register.Kind.YMM -> [ getPseudoRegVar ctxt r 1; getPseudoRegVar ctxt r 2
                           getPseudoRegVar ctxt r 3; getPseudoRegVar ctxt r 4 ]
  | Register.Kind.ZMM -> [ getPseudoRegVar ctxt r 1; getPseudoRegVar ctxt r 2
                           getPseudoRegVar ctxt r 3; getPseudoRegVar ctxt r 4
                           getPseudoRegVar ctxt r 5; getPseudoRegVar ctxt r 6
                           getPseudoRegVar ctxt r 7; getPseudoRegVar ctxt r 8 ]
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
  | _ -> Utils.impossible ()

let private ldMem (ins: InsInfo) ctxt oprSize e =
  match getSegment ins.Prefixes with
  | Some s -> !.ctxt (segRegToBase s) .+ e
  | None -> e
  |> AST.loadLE oprSize

let private numOfAddrSz (ins: InsInfo) (ctxt: TranslationContext) n =
  let pref = ins.Prefixes
  let sz =
    if ctxt.WordBitSize = 32<rt> then if hasAddrSz pref then 16<rt> else 32<rt>
    else if hasAddrSz pref then 32<rt> else 64<rt>
  numI64 n sz

let inline private sIdx ins ctxt (r, s: Scale) =
  (!.ctxt r) .* (numOfAddrSz ins ctxt (int64 s))

let private transMem ir useTmpVar ins insLen ctxt b index disp oprSize =
  let address =
    match b, index, (disp: Disp option) with
    | None, None, Some d ->
      numOfAddrSz ins ctxt d
    | None, Some i, Some d ->
      let e = (sIdx ins ctxt i) .+ (numOfAddrSz ins ctxt d)
      if not useTmpVar then e
      else
        let tAddress = !+ir (ctxt: TranslationContext).WordBitSize
        !!ir (tAddress := e)
        tAddress
    | Some b, None, None ->
      !.ctxt b
    | Some R.RIP, None, Some d -> (* RIP-relative addressing *)
      let e = !.ctxt R.RIP .+ numOfAddrSz ins ctxt (d + int64 (insLen: uint32))
      if not useTmpVar then e
      else
        let tAddress = !+ir (ctxt: TranslationContext).WordBitSize
        !!ir (tAddress := e)
        tAddress
    | Some b, None, Some d ->
      let e = !.ctxt b .+ (numOfAddrSz ins ctxt d)
      if not useTmpVar then e
      else
        let tAddress = !+ir (ctxt: TranslationContext).WordBitSize
        !!ir (tAddress := e)
        tAddress
    | Some b, Some i, None ->
      let e = !.ctxt b .+ (sIdx ins ctxt i)
      if not useTmpVar then e
      else
        let tAddress = !+ir (ctxt: TranslationContext).WordBitSize
        !!ir (tAddress := e)
        tAddress
    | Some b, Some i, Some d ->
      let e = !.ctxt b .+ (sIdx ins ctxt i) .+ (numOfAddrSz ins ctxt d)
      if not useTmpVar then e
      else
        let tAddress = !+ir (ctxt: TranslationContext).WordBitSize
        !!ir (tAddress := e)
        tAddress
    | _, _, _ -> raise InvalidOperandException
  ldMem ins ctxt oprSize address

let transOprToExpr ir useTmpVar ins insLen ctxt = function
  | OprReg reg -> !.ctxt reg
  | OprMem (b, index, disp, oprSize) ->
    transMem ir useTmpVar ins insLen ctxt b index disp oprSize
  | OprImm (imm, _) -> numI64 imm (getOperationSize ins)
  | OprDirAddr (Relative offset) -> numI64 offset ctxt.WordBitSize
  | OprDirAddr (Absolute (_, addr, _)) -> numU64 addr ctxt.WordBitSize
  | _ -> Utils.impossible ()

let transOprToExprVec ir useTmpVar ins insLen ctxt opr =
  match opr with
  | OprReg r -> getPseudoRegVars ctxt r
  | OprMem (b, index, disp, oprSize) ->
    transMem ir useTmpVar ins insLen ctxt b index disp oprSize |> getMemExprs
  | OprImm (imm, _) -> [ numI64 imm (getOperationSize ins) ]
  | _ -> raise InvalidOperandException

let transOprToExpr16 ir useTmpVar ins insLen ctxt opr =
  match opr with
  | OprReg r when Register.toRegType r > 64<rt> ->
    getPseudoRegVar ctxt r 1 |> AST.xtlo 16<rt>
  | OprReg r -> !.ctxt r
  | OprMem (b, index, disp, 16<rt>) ->
    transMem ir useTmpVar ins insLen ctxt b index disp 16<rt>
  | _ -> raise InvalidOperandException

let transOprToExpr32 ir useTmpVar ins insLen ctxt opr =
  match opr with
  | OprReg r when Register.toRegType r > 64<rt> ->
    getPseudoRegVar ctxt r 1 |> AST.xtlo 32<rt>
  | OprReg r -> !.ctxt r
  | OprMem (b, index, disp, 32<rt>) ->
    transMem ir useTmpVar ins insLen ctxt b index disp 32<rt>
  | _ -> raise InvalidOperandException

let transOprToExpr64 ir useTmpVar ins insLen ctxt opr =
  match opr with
  | OprReg r when Register.toRegType r > 64<rt> -> getPseudoRegVar ctxt r 1
  | OprReg r -> !.ctxt r
  | OprMem (b, index, disp, 64<rt>) ->
    transMem ir useTmpVar ins insLen ctxt b index disp 64<rt>
  | _ -> raise InvalidOperandException

let transOprToExpr128 ir useTmpVar ins insLen ctxt opr =
  match opr with
  | OprReg r -> getPseudoRegVar128 ctxt r
  | OprMem (b, index, disp, oprSize) ->
    transMem ir useTmpVar ins insLen ctxt b index disp oprSize |> getMemExpr128
  | _ -> raise InvalidOperandException

let transOprToExpr256 ir useTmpVar ins insLen ctxt opr =
  match opr with
  | OprReg r -> getPseudoRegVar256 ctxt r
  | OprMem (b, index, disp, oprSize) ->
    transMem ir useTmpVar ins insLen ctxt b index disp oprSize |> getMemExpr256
  | _ -> raise InvalidOperandException

let transOprToExpr512 ir useTmpVar ins insLen ctxt opr =
  match opr with
  | OprReg r -> getPseudoRegVar512 ctxt r
  | OprMem (b, index, disp, oprSize) ->
    transMem ir useTmpVar ins insLen ctxt b index disp oprSize |> getMemExpr512
  | _ -> raise InvalidOperandException

/// Return a tuple (jump target expr, is pc-relative?)
let transJumpTargetOpr ir useTmpVar ins pc insLen (ctxt: TranslationContext) =
  match (ins: InsInfo).Operands with
  | OneOperand (OprDirAddr (Absolute (_, addr, _))) ->
    struct (numU64 addr ctxt.WordBitSize, false)
  | OneOperand (OprDirAddr (Relative offset)) ->
    let wordSize = ctxt.WordBitSize
    let offset = numI64 offset wordSize |> AST.sext wordSize
    struct (pc .+ offset, true)
  | OneOperand (OprReg reg) -> struct (!.ctxt reg, false)
  | OneOperand (OprMem (b, index, disp, oprSize)) ->
    struct (transMem ir useTmpVar ins insLen ctxt b index disp oprSize, false)
  | _ -> raise InvalidOperandException

let transOprToArr ir useTmpVars ins insLen ctxt packSz packNum oprSize opr =
  let pos = int packSz
  let exprArr =
    match opr with
    | OprImm _ ->
      let opr = transOprToExpr ir false ins insLen ctxt opr
      Array.init (oprSize / packSz) (fun i -> AST.extract opr packSz (i * pos))
    | OprMem _ ->
      match oprSize with
      | 64<rt> ->
        let opr = transOprToExpr ir false ins insLen ctxt opr
        let mem = !+ir 64<rt>
        !!ir (mem := opr)
        Array.init packNum (fun i -> AST.extract mem packSz (i * pos))
      | 128<rt> ->
        let oB, oA = transOprToExpr128 ir false ins insLen ctxt opr
        let struct (mB, mA) = tmpVars2 ir 64<rt>
        !!ir (mA := oA)
        !!ir (mB := oB)
        let oprA = Array.init packNum (fun i -> AST.extract mA packSz (i * pos))
        let oprB = Array.init packNum (fun i -> AST.extract mB packSz (i * pos))
        Array.append oprA oprB
      | 256<rt> ->
        let oD, oC, oB, oA =
          transOprToExpr256 ir false ins insLen ctxt opr
        let struct (mD, mC, mB, mA) = tmpVars4 ir 64<rt>
        !!ir (mA := oA)
        !!ir (mB := oB)
        !!ir (mC := oC)
        !!ir (mD := oD)
        let oprA = Array.init packNum (fun i -> AST.extract mA packSz (i * pos))
        let oprB = Array.init packNum (fun i -> AST.extract mB packSz (i * pos))
        let oprC = Array.init packNum (fun i -> AST.extract mC packSz (i * pos))
        let oprD = Array.init packNum (fun i -> AST.extract mD packSz (i * pos))
        Array.concat [| oprA; oprB; oprC; oprD |]
      | 512<rt> ->
        let oH, oG, oF, oE, oD, oC, oB, oA =
          transOprToExpr512 ir false ins insLen ctxt opr
        let struct (mD, mC, mB, mA) = tmpVars4 ir 64<rt>
        let struct (mH, mG, mF, mE) = tmpVars4 ir 64<rt>
        !!ir (mA := oA)
        !!ir (mB := oB)
        !!ir (mC := oC)
        !!ir (mD := oD)
        !!ir (mE := oE)
        !!ir (mF := oF)
        !!ir (mG := oG)
        !!ir (mH := oH)
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
        let opr = transOprToExpr ir false ins insLen ctxt opr
        Array.init packNum (fun i -> AST.extract opr packSz (i * pos))
      | 128<rt> ->
        let oB, oA = transOprToExpr128 ir false ins insLen ctxt opr
        let oprA = Array.init packNum (fun i -> AST.extract oA packSz (i * pos))
        let oprB = Array.init packNum (fun i -> AST.extract oB packSz (i * pos))
        Array.append oprA oprB
      | 256<rt> ->
        let oD, oC, oB, oA =
          transOprToExpr256 ir false ins insLen ctxt opr
        let oprA = Array.init packNum (fun i -> AST.extract oA packSz (i * pos))
        let oprB = Array.init packNum (fun i -> AST.extract oB packSz (i * pos))
        let oprC = Array.init packNum (fun i -> AST.extract oC packSz (i * pos))
        let oprD = Array.init packNum (fun i -> AST.extract oD packSz (i * pos))
        Array.concat [| oprA; oprB; oprC; oprD |]
      | 512<rt> ->
        let oH, oG, oF, oE, oD, oC, oB, oA =
          transOprToExpr512 ir false ins insLen ctxt opr
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
    let tmps = Array.init (oprSize / packSz) (fun _ -> !+ir packSz)
    Array.iter2 (fun e1 e2 -> !!ir (e1 := e2)) tmps exprArr
    tmps
  else exprArr

let assignPackedInstr ir useTmpVar ins insLen ctxt packNum oprSize dst result =
  match oprSize with
  | 64<rt> ->
    let dst = transOprToExpr ir useTmpVar ins insLen ctxt dst
    !!ir (dst := result |> AST.concatArr)
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ir useTmpVar ins insLen ctxt dst
    !!ir (dstA := Array.sub result 0 packNum |> AST.concatArr)
    !!ir (dstB := Array.sub result packNum packNum |> AST.concatArr)
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ir false ins insLen ctxt dst
    !!ir (dstA := Array.sub result 0 packNum |> AST.concatArr)
    !!ir (dstB := Array.sub result (1 * packNum) packNum |> AST.concatArr)
    !!ir (dstC := Array.sub result (2 * packNum) packNum |> AST.concatArr)
    !!ir (dstD := Array.sub result (3 * packNum) packNum |> AST.concatArr)
  | 512<rt> ->
    let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
      transOprToExpr512 ir false ins insLen ctxt dst
    !!ir (dstA := Array.sub result 0 packNum |> AST.concatArr)
    !!ir (dstB := Array.sub result (1 * packNum) packNum |> AST.concatArr)
    !!ir (dstC := Array.sub result (2 * packNum) packNum |> AST.concatArr)
    !!ir (dstD := Array.sub result (3 * packNum) packNum |> AST.concatArr)
    !!ir (dstE := Array.sub result (4 * packNum) packNum |> AST.concatArr)
    !!ir (dstF := Array.sub result (5 * packNum) packNum |> AST.concatArr)
    !!ir (dstG := Array.sub result (6 * packNum) packNum |> AST.concatArr)
    !!ir (dstH := Array.sub result (7 * packNum) packNum |> AST.concatArr)
  | _ -> raise InvalidOperandSizeException

let getTwoOprs (ins: InsInfo) =
  match ins.Operands with
  | TwoOperands (o1, o2) -> struct (o1, o2)
  | _ -> raise InvalidOperandException

let getThreeOprs (ins: InsInfo) =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> struct (o1, o2, o3)
  | _ -> raise InvalidOperandException

let getFourOprs (ins: InsInfo) =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) -> struct (o1, o2, o3, o4)
  | _ -> raise InvalidOperandException

let transOneOpr ir useTmpVar (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | OneOperand opr -> transOprToExpr ir useTmpVar ins insLen ctxt opr
  | _ -> raise InvalidOperandException

let transTwoOprs ir useTmpVar (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    struct (transOprToExpr ir useTmpVar ins insLen ctxt o1,
            transOprToExpr ir false ins insLen ctxt o2)
  | _ -> raise InvalidOperandException

let transThreeOprs ir useTmpVar (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    struct (transOprToExpr ir useTmpVar ins insLen ctxt o1,
            transOprToExpr ir useTmpVar ins insLen ctxt o2,
            transOprToExpr ir useTmpVar ins insLen ctxt o3)
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
         let dstOrigSz = dst |> TypeCheck.typeOf
         let oprBitSize = RegType.toBitWidth oprSize
         let dstBitSize = RegType.toBitWidth dstOrigSz
         if dstBitSize > oprBitSize then dst := AST.zext dstOrigSz src
         elif dstBitSize = oprBitSize then dst := src
         else raise InvalidOperandSizeException

/// For x87 FPU Top register or x87 FPU Tag word sections.
let extractDstAssign e1 e2 =
  match e1.E with
  | Extract ({ E = BinOp (BinOpType.SHR, 16<rt>,
    { E = BinOp (BinOpType.AND, 16<rt>,
      ({ E = Var (16<rt>, rId, _, _) } as e1), mask, _) }, amt, _) }, 8<rt>,
        0, _) when int rId = 0x4F (* FSW *) || int rId = 0x50 (* FTW *) ->
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
  match e.E with
  | Num n -> BitVector.Cast (n, newType) |> AST.num
  | _ -> raise InvalidOperandException

let getMask oprSize =
  match oprSize with
  | 8<rt> -> numI64 0xffL oprSize
  | 16<rt> -> numI64 0xffffL oprSize
  | 32<rt> -> numI64 0xffffffffL oprSize
  | 64<rt> -> numI64 0xffffffffffffffffL oprSize
  | _ -> raise InvalidOperandSizeException

let sideEffects ctxt insLen name =
  let ir = !*ctxt
  !<ir insLen
  !!ir (AST.sideEffect name)
  !>ir insLen

let hasStackPtr (ins: InsInfo) =
  match ins.Operands with
  | OneOperand (OprReg Register.ESP)
  | OneOperand (OprReg Register.RSP)
  | OneOperand (OprMem (Some Register.ESP, _, _, _))
  | OneOperand (OprMem (Some Register.RSP, _, _, _))
  | OneOperand (OprMem (_, Some (Register.ESP, _), _, _))
  | OneOperand (OprMem (_, Some (Register.RSP, _), _, _)) -> true
  | _ -> false