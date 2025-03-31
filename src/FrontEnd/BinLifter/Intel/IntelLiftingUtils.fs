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
open B2R2.FrontEnd.Register
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingOperators
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.BinLifter.Intel.Helper

open type BinOpType

let inline ( !. ) (ctxt: TranslationContext) name =
  IntelRegister.ID name |> ctxt.GetRegVar

let inline getPseudoRegVar (ctxt: TranslationContext) name pos =
  ctxt.GetPseudoRegVar (IntelRegister.ID name) pos

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
  | Load (e, 128<rt>, { E = BinOp (BinOpType.ADD, _, b, { E = Num n }) })
  | Load (e, 128<rt>, { E = BinOp (BinOpType.ADD, _, { E = Num n }, b) })
    ->
    let off1 = AST.num n
    let off2 = BitVector.Add (n, BitVector.OfInt32 8 n.Length) |> AST.num
    AST.load e 64<rt> (b .+ off2),
    AST.load e 64<rt> (b .+ off1)
  | Load (e, 128<rt>, expr) ->
    AST.load e 64<rt> (expr .+ numI32 8 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> expr
  | _ -> raise InvalidOperandException

let private getMemExpr256 expr =
  match expr.E with
  | Load (e, 256<rt>, { E = BinOp (BinOpType.ADD, _, b, { E = Num n }) })
  | Load (e, 256<rt>, { E = BinOp (BinOpType.ADD, _, { E = Num n }, b) })
    ->
    let off1 = AST.num n
    let off2 = BitVector.Add (n, BitVector.OfInt32 8 n.Length) |> AST.num
    let off3 = BitVector.Add (n, BitVector.OfInt32 16 n.Length) |> AST.num
    let off4 = BitVector.Add (n, BitVector.OfInt32 24 n.Length) |> AST.num
    AST.load e 64<rt> (b .+ off4),
    AST.load e 64<rt> (b .+ off3),
    AST.load e 64<rt> (b .+ off2),
    AST.load e 64<rt> (b .+ off1)
  | Load (e, 256<rt>, expr) ->
    AST.load e 64<rt> (expr .+ numI32 24 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 16 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 8 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> expr
  | _ -> raise InvalidOperandException

let private getMemExpr512 expr =
  match expr.E with
  | Load (e, 512<rt>, { E = BinOp (BinOpType.ADD, _, b, { E = Num n }) })
  | Load (e, 512<rt>, { E = BinOp (BinOpType.ADD, _, { E = Num n }, b) })
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
  | Load (e, 512<rt>, expr) ->
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
  | Load (e, 128<rt>, expr) ->
    [ AST.load e 64<rt> expr
      AST.load e 64<rt> (expr .+ numI32 8 (TypeCheck.typeOf expr)) ]
  | Load (e, 256<rt>, expr) ->
    [ AST.load e 64<rt> expr
      AST.load e 64<rt> (expr .+ numI32 8 (TypeCheck.typeOf expr))
      AST.load e 64<rt> (expr .+ numI32 16 (TypeCheck.typeOf expr))
      AST.load e 64<rt> (expr .+ numI32 24 (TypeCheck.typeOf expr)) ]
  | Load (e, 512<rt>, expr) ->
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
  | Intel.CS
  | Intel.DS
  | Intel.SS
  | Intel.ES
  | Intel.FS
  | Intel.GS -> true
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
  match s with
  | Scale.X1 -> !.ctxt r
  | Scale.X2 -> !.ctxt r << numOfAddrSz ins ctxt 1
  | Scale.X4 -> !.ctxt r << numOfAddrSz ins ctxt 2
  | Scale.X8 -> !.ctxt r << numOfAddrSz ins ctxt 3
  | _ -> Utils.impossible ()

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
      let pc =
#if EMULATION
        numOfAddrSz ins ctxt (int64 (ins: InsInfo).Address)
#else
        !.ctxt R.RIP
#endif
      let e = pc .+ numOfAddrSz ins ctxt (d + int64 (insLen: uint32))
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

let transOprToExpr16 ir useTmpVar ins insLen (ctxt: TranslationContext) opr =
  match opr with
  | OprReg r when Register.toRegType ctxt.WordSize r > 64<rt> ->
    getPseudoRegVar ctxt r 1 |> AST.xtlo 16<rt>
  | OprReg r -> !.ctxt r
  | OprMem (b, index, disp, 16<rt>) ->
    transMem ir useTmpVar ins insLen ctxt b index disp 16<rt>
  | _ -> raise InvalidOperandException

let transOprToExpr32 ir useTmpVar ins insLen (ctxt: TranslationContext) opr =
  match opr with
  | OprReg r when Register.toRegType ctxt.WordSize r > 64<rt> ->
    getPseudoRegVar ctxt r 1 |> AST.xtlo 32<rt>
  | OprReg r -> !.ctxt r
  | OprMem (b, index, disp, 32<rt>) ->
    transMem ir useTmpVar ins insLen ctxt b index disp 32<rt>
  | _ -> raise InvalidOperandException

let transOprToExpr64 ir useTmpVar ins insLen (ctxt: TranslationContext) opr =
  match opr with
  | OprReg r when Register.toRegType ctxt.WordSize r > 64<rt> ->
    getPseudoRegVar ctxt r 1
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
        let mem = !+ir oprSize
        !!ir (mem := AST.zext oprSize opr)
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
        let oD, oC, oB, oA = transOprToExpr256 ir false ins insLen ctxt opr
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

let fillOnesToMMXHigh16 ir (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprReg _ as o, _)
  | ThreeOperands (OprReg _ as o, _, _) ->
    !!ir (getPseudoRegVar ctxt (convMMXToST o) 2 := AST.num BitVector.MaxUInt16)
  | _ -> ()

let assignPackedInstr ir useTmpVar ins insLen ctxt packNum oprSize dst result =
  match oprSize with
  | 64<rt> when isMMXReg dst ->
    let dst = transOprToExpr ir useTmpVar ins insLen ctxt dst
    !!ir (dst := result |> AST.concatArr)
    fillOnesToMMXHigh16 ir ins ctxt
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

let transOneOpr ir (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | OneOperand opr -> transOprToExpr ir true ins insLen ctxt opr
  | _ -> raise InvalidOperandException

let transReg ir useTmpVar expr =
  if useTmpVar then
    match expr.E with
    | Extract (_, rt, _) ->
      let t = !+ir rt
      !!ir (t := expr)
      t
    | _ -> expr
  else expr

let transTwoOprs ir useTmpVar (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    let o1 = transOprToExpr ir useTmpVar ins insLen ctxt o1
    let o2 = transOprToExpr ir false ins insLen ctxt o2 |> transReg ir useTmpVar
    struct (o1, o2)
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
      ({ E = Var (16<rt>, rId, _) } as e1), mask) }, amt) }, 8<rt>, 0)
    when int rId = 0x4F (* FSW *) || int rId = 0x50 (* FTW *) ->
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
#if EMULATION
  if ctxt.ConditionCodeOp <> ConditionCodeOp.TraceStart then
    !!ir (!.ctxt R.CCOP := numI32 (int ctxt.ConditionCodeOp) 8<rt>)
  else ()
  ctxt.ConditionCodeOp <- ConditionCodeOp.TraceStart
#endif
  !!ir (AST.sideEffect name)
  !>ir insLen

let hasStackPtr (ins: InsInfo) =
  match ins.Operands with
  | OneOperand (OprReg Intel.ESP)
  | OneOperand (OprReg Intel.RSP)
  | OneOperand (OprMem (Some Intel.ESP, _, _, _))
  | OneOperand (OprMem (Some Intel.RSP, _, _, _))
  | OneOperand (OprMem (_, Some (Intel.ESP, _), _, _))
  | OneOperand (OprMem (_, Some (Intel.RSP, _), _, _)) -> true
  | _ -> false

let buildAF ctxt e1 e2 r size =
  let t1 = r <+> e1
  let t2 = t1 <+> e2
  let t3 = (AST.num1 size) << (numU32 4ul size)
  let t4 = t2 .& t3
  !.ctxt R.AF := t4 == t3

let isExprZero e =
  match e.E with
  | Num bv when bv.IsZero () -> true
  | _ -> false

let buildPF ctxt r size cond ir =
  let pf = !.ctxt R.PF
  let computedPF =
    if isExprZero r then
      AST.num1 1<rt>
    else
      let struct (t1, t2) = tmpVars2 ir size
      let s2 = r <+> (r >> (AST.zext size (numU32 4ul 8<rt>)))
      let s4 = t1 <+> (t1 >> (AST.zext size (numU32 2ul 8<rt>)))
      let s5 = t2 <+> (t2 >> (AST.zext size (AST.num1 8<rt>)))
      !!ir (t1 := s2)
      !!ir (t2 := s4)
      AST.unop UnOpType.NOT (AST.xtlo 1<rt> s5)
  !!ir (match cond with
        | None -> pf := computedPF
        | Some cond -> pf := AST.ite cond pf computedPF)

let enumSZPFlags ctxt r size sf ir =
  !!ir (!.ctxt R.SF := sf)
  !!ir (!.ctxt R.ZF := r == (AST.num0 size))
  !?ir (buildPF ctxt r size None)

let enumASZPFlags ctxt e1 e2 r size sf ir =
  !!ir (buildAF ctxt e1 e2 r size)
  !?ir (enumSZPFlags ctxt r size sf)

let enumEFLAGS ctxt e1 e2 e3 size cf ofl sf ir =
  !!ir (!.ctxt R.CF := cf)
  !!ir (!.ctxt R.OF := ofl)
  !!ir (buildAF ctxt e1 e2 e3 size)
  !!ir (!.ctxt R.SF := sf)
  !!ir (!.ctxt R.ZF := e3 == (AST.num0 size))
  !?ir (buildPF ctxt e3 size None)

/// CF on add.
let cfOnAdd e1 r = r .< e1

/// CF on sub.
let cfOnSub e1 e2 = e1 .< e2

/// OF and SF on add.
let osfOnAdd e1 e2 r ir =
  if e1 = e2 then
    let rHigh = !+ir 1<rt>
    let e1High = AST.xthi 1<rt> e1
    !!ir (rHigh := AST.xthi 1<rt> r)
    struct ((e1High <+> rHigh), rHigh)
  else
    let struct (t1, t2) = tmpVars2 ir 1<rt>
    let e1High = AST.xthi 1<rt> e1
    let e2High = AST.xthi 1<rt> e2
    let rHigh = AST.xthi 1<rt> r
    !!ir (t1 := e1High)
    !!ir (t2 := rHigh)
    struct ((t1 == e2High) .& (t1 <+> t2), t2)

/// OF on sub.
let ofOnSub e1 e2 r =
  AST.xthi 1<rt> ((e1 <+> e2) .& (e1 <+> r))

#if EMULATION
let getCCSrc1 (ctxt: TranslationContext) regType =
  match regType with
  | 8<rt> -> !.ctxt R.CCSRC1B
  | 16<rt> -> !.ctxt R.CCSRC1W
  | 32<rt> -> !.ctxt R.CCSRC1D
  | 64<rt> -> !.ctxt R.CCSRC1
  | _ -> Utils.impossible ()

let getCCSrc2 (ctxt: TranslationContext) regType =
  match regType with
  | 8<rt> -> !.ctxt R.CCSRC2B
  | 16<rt> -> !.ctxt R.CCSRC2W
  | 32<rt> -> !.ctxt R.CCSRC2D
  | 64<rt> -> !.ctxt R.CCSRC2
  | _ -> Utils.impossible ()

let getCCDst (ctxt: TranslationContext) regType =
  match regType with
  | 8<rt> -> !.ctxt R.CCDSTB
  | 16<rt> -> !.ctxt R.CCDSTW
  | 32<rt> -> !.ctxt R.CCDSTD
  | 64<rt> -> !.ctxt R.CCDST
  | _ -> Utils.impossible ()

let setCCOperands2 (ctxt: TranslationContext) src1 dst ir =
  let ccSrc1 = !.ctxt R.CCSRC1
  let ccDst = !.ctxt R.CCDST
  !!ir (ccSrc1 := AST.zext ctxt.WordBitSize src1)
  !!ir (ccDst := AST.zext ctxt.WordBitSize dst)

let setCCOperands3 (ctxt: TranslationContext) src1 src2 dst ir =
  let ccSrc1 = !.ctxt R.CCSRC1
  let ccSrc2 = !.ctxt R.CCSRC2
  let ccDst = !.ctxt R.CCDST
  !!ir (ccSrc1 := AST.zext ctxt.WordBitSize src1)
  !!ir (ccSrc2 := AST.zext ctxt.WordBitSize src2)
  !!ir (ccDst := AST.zext ctxt.WordBitSize dst)

let setCCDst (ctxt: TranslationContext) dst ir =
  let ccDst = !.ctxt R.CCDST
  !!ir (ccDst := AST.zext ctxt.WordBitSize dst)

let setCCOp (ctxt: TranslationContext) (ir: IRBuilder) =
  if ctxt.ConditionCodeOp <> ConditionCodeOp.TraceStart then
    !!ir (!.ctxt R.CCOP := numI32 (int ctxt.ConditionCodeOp) 8<rt>)
  else ()

let genDynamicFlagsUpdate (ctxt: TranslationContext) (ir: IRBuilder) =
  !?ir (setCCOp ctxt)
  !!ir (AST.sideEffect FlagsUpdate)
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags

let getOFLazy (ctxt: TranslationContext) (ir: IRBuilder) =
  let ccOp = ctxt.ConditionCodeOp
  match ccOp with
  | ConditionCodeOp.SUBB
  | ConditionCodeOp.SUBW
  | ConditionCodeOp.SUBD
  | ConditionCodeOp.SUBQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 ir regType
    let src1 = getCCSrc1 ctxt regType
    let dst = getCCDst ctxt regType
    !!ir (t3 := dst)
    !!ir (t2 := src1)
    !!ir (t1 := t3 .+ t2)
    let sf = t3 ?< AST.num0 regType
    let cf = cfOnSub t1 t2
    let ofl = ofOnSub t1 t2 t3
    !?ir (enumEFLAGS ctxt t1 t2 t3 regType cf ofl sf)
    ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
    !.ctxt R.OF
  | ConditionCodeOp.DECB
  | ConditionCodeOp.DECW
  | ConditionCodeOp.DECD
  | ConditionCodeOp.DECQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 ir regType
    let src1 = getCCSrc1 ctxt regType
    let dst = getCCDst ctxt regType
    !!ir (t3 := dst)
    !!ir (t2 := src1)
    !!ir (t1 := t3 .+ t2)
    let sf = t3 ?< AST.num0 regType
    let cf = !.ctxt R.CF
    let ofl = ofOnSub t1 t2 t3
    !?ir (enumEFLAGS ctxt t1 t2 t3 regType cf ofl sf)
    ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
    !.ctxt R.OF
  | ConditionCodeOp.ADDB
  | ConditionCodeOp.ADDW
  | ConditionCodeOp.ADDD
  | ConditionCodeOp.ADDQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 ir regType
    let src1 = getCCSrc1 ctxt regType
    let dst = getCCDst ctxt regType
    !!ir (t3 := dst)
    !!ir (t1 := src1)
    !!ir (t2 := t3 .- t1)
    let cf = cfOnAdd t1 t3
    let struct (ofl, sf) = osfOnAdd t1 t2 t3 ir
    !?ir (enumEFLAGS ctxt t1 t2 t3 regType cf ofl sf)
    ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
    !.ctxt R.OF
  | ConditionCodeOp.INCB
  | ConditionCodeOp.INCW
  | ConditionCodeOp.INCD
  | ConditionCodeOp.INCQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 ir regType
    let src1 = getCCSrc1 ctxt regType
    let dst = getCCDst ctxt regType
    !!ir (t3 := dst)
    !!ir (t1 := src1)
    !!ir (t2 := t3 .- t1)
    let cf = !.ctxt R.CF
    let struct (ofl, sf) = osfOnAdd t1 t2 t3 ir
    !?ir (enumEFLAGS ctxt t1 t2 t3 regType cf ofl sf)
    ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
    !.ctxt R.OF
  | ConditionCodeOp.SHLB
  | ConditionCodeOp.SHLW
  | ConditionCodeOp.SHLD
  | ConditionCodeOp.SHLQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 ir regType
    let src1 = getCCSrc1 ctxt regType
    let src2 = getCCSrc2 ctxt regType
    let dst = getCCDst ctxt regType
    let n0 = AST.num0 regType
    let n1 = AST.num1 regType
    let cond1 = src2 == n1
    let cond2 = src2 == n0
    let cf = !.ctxt R.CF
    let sf = !.ctxt R.SF
    let zf = !.ctxt R.ZF
    let ofl = !.ctxt R.OF
    let newOf = AST.xthi 1<rt> dst <+> cf
    !!ir (t1 := src1)
    !!ir (t2 := src2)
    !!ir (t3 := dst)
    !!ir (cf := AST.ite cond2 cf (AST.xthi 1<rt> (t1 << (t2 .- n1))))
    !!ir (ofl := AST.ite cond1 newOf ofl)
    !!ir (sf := AST.ite cond2 sf (AST.xthi 1<rt> t3))
    !?ir (buildPF ctxt dst regType (Some cond2))
    !!ir (zf := AST.ite cond2 zf (t3 == n0))
    ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
    !.ctxt R.OF
  | ConditionCodeOp.SHRB
  | ConditionCodeOp.SHRW
  | ConditionCodeOp.SHRD
  | ConditionCodeOp.SHRQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 ir regType
    let src1 = getCCSrc1 ctxt regType
    let src2 = getCCSrc2 ctxt regType
    let dst = getCCDst ctxt regType
    let n0 = AST.num0 regType
    let n1 = AST.num1 regType
    let cond1 = src2 == n1
    let cond2 = src2 == n0
    let cf = !.ctxt R.CF
    let sf = !.ctxt R.SF
    let zf = !.ctxt R.ZF
    let ofl = !.ctxt R.OF
    !!ir (t1 := src1)
    !!ir (t2 := src2)
    !!ir (t3 := dst)
    !!ir (cf := AST.ite cond2 cf (AST.xtlo 1<rt> (t1 ?>> (t2 .- n1))))
    !!ir (ofl := AST.ite cond1 (AST.xthi 1<rt> t1) ofl)
    !!ir (sf := AST.ite cond2 sf (AST.xthi 1<rt> t3))
    !?ir (buildPF ctxt dst regType (Some cond2))
    !!ir (zf := AST.ite cond2 zf (t3 == n0))
    ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
    !.ctxt R.OF
  | ConditionCodeOp.SARB
  | ConditionCodeOp.SARW
  | ConditionCodeOp.SARD
  | ConditionCodeOp.SARQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 ir regType
    let src1 = getCCSrc1 ctxt regType
    let src2 = getCCSrc2 ctxt regType
    let dst = getCCDst ctxt regType
    let n0 = AST.num0 regType
    let n1 = AST.num1 regType
    let cond1 = src2 == n1
    let cond2 = src2 == n0
    let cf = !.ctxt R.CF
    let sf = !.ctxt R.SF
    let zf = !.ctxt R.ZF
    let ofl = !.ctxt R.OF
    !!ir (t1 := src1)
    !!ir (t2 := src2)
    !!ir (t3 := dst)
    !!ir (cf := AST.ite cond2 cf (AST.xtlo 1<rt> (t1 ?>> (t2 .- n1))))
    !!ir (ofl := AST.ite cond1 AST.b0 ofl)
    !!ir (sf := AST.ite cond2 sf (AST.xthi 1<rt> t3))
    !?ir (buildPF ctxt dst regType (Some cond2))
    !!ir (zf := AST.ite cond2 zf (t3 == n0))
    ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
    !.ctxt R.OF
  | ConditionCodeOp.LOGICB
  | ConditionCodeOp.LOGICW
  | ConditionCodeOp.LOGICD
  | ConditionCodeOp.LOGICQ
  | ConditionCodeOp.XORXX ->
    AST.b0
  | ConditionCodeOp.TraceStart ->
    !?ir (genDynamicFlagsUpdate ctxt)
    !.ctxt R.OF
  | ConditionCodeOp.EFlags ->
    !.ctxt R.OF
  | _ -> Utils.futureFeature ()

let getSFLazy (ctxt: TranslationContext) (ir: IRBuilder) =
  let ccOp = ctxt.ConditionCodeOp
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
    let t = getCCDst ctxt regType
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
    let t = getCCDst ctxt regType
    let cnt = getCCSrc2 ctxt regType
    AST.ite (cnt == AST.num0 regType) (!.ctxt R.SF) (t ?< AST.num0 regType)
  | ConditionCodeOp.XORXX ->
    AST.b0
  | ConditionCodeOp.TraceStart ->
    !?ir (genDynamicFlagsUpdate ctxt)
    !.ctxt R.SF
  | ConditionCodeOp.EFlags ->
    !.ctxt R.SF
  | _ -> Utils.futureFeature ()

let getZFLazy (ctxt: TranslationContext) (ir: IRBuilder) =
  let ccOp = ctxt.ConditionCodeOp
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
    let t = getCCDst ctxt regType
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
    let t = getCCDst ctxt regType
    let cnt = getCCSrc2 ctxt regType
    AST.ite (cnt == AST.num0 regType) (!.ctxt R.ZF) (t == AST.num0 regType)
  | ConditionCodeOp.XORXX ->
    AST.b1
  | ConditionCodeOp.TraceStart ->
    !?ir (genDynamicFlagsUpdate ctxt)
    !.ctxt R.ZF
  | ConditionCodeOp.EFlags ->
    !.ctxt R.ZF
  | _ -> Utils.futureFeature ()

let getAFLazy (ctxt: TranslationContext) (ir: IRBuilder) =
  let ccOp = ctxt.ConditionCodeOp
  match ccOp with
  | ConditionCodeOp.SUBB
  | ConditionCodeOp.SUBW
  | ConditionCodeOp.SUBD
  | ConditionCodeOp.SUBQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 ir regType
    let src1 = getCCSrc1 ctxt regType
    let dst = getCCDst ctxt regType
    !!ir (t3 := dst)
    !!ir (t2 := src1)
    !!ir (t1 := t3 .+ t2)
    let sf = t3 ?< AST.num0 regType
    let cf = cfOnSub t1 t2
    let ofl = ofOnSub t1 t2 t3
    !?ir (enumEFLAGS ctxt t1 t2 t3 regType cf ofl sf)
    ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
    !.ctxt R.AF
  | ConditionCodeOp.DECB
  | ConditionCodeOp.DECW
  | ConditionCodeOp.DECD
  | ConditionCodeOp.DECQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 ir regType
    let src1 = getCCSrc1 ctxt regType
    let dst = getCCDst ctxt regType
    !!ir (t3 := dst)
    !!ir (t2 := src1)
    !!ir (t1 := t3 .+ t2)
    let sf = t3 ?< AST.num0 regType
    let cf = !.ctxt R.CF
    let ofl = ofOnSub t1 t2 t3
    !?ir (enumEFLAGS ctxt t1 t2 t3 regType cf ofl sf)
    ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
    !.ctxt R.AF
  | ConditionCodeOp.ADDB
  | ConditionCodeOp.ADDW
  | ConditionCodeOp.ADDD
  | ConditionCodeOp.ADDQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 ir regType
    let src1 = getCCSrc1 ctxt regType
    let dst = getCCDst ctxt regType
    !!ir (t3 := dst)
    !!ir (t1 := src1)
    !!ir (t2 := t3 .- t1)
    let cf = cfOnAdd t1 t3
    let struct (ofl, sf) = osfOnAdd t1 t2 t3 ir
    !?ir (enumEFLAGS ctxt t1 t2 t3 regType cf ofl sf)
    ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
    !.ctxt R.AF
  | ConditionCodeOp.INCB
  | ConditionCodeOp.INCW
  | ConditionCodeOp.INCD
  | ConditionCodeOp.INCQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 ir regType
    let src1 = getCCSrc1 ctxt regType
    let dst = getCCDst ctxt regType
    !!ir (t3 := dst)
    !!ir (t1 := src1)
    !!ir (t2 := t3 .- t1)
    let cf = !.ctxt R.CF
    let struct (ofl, sf) = osfOnAdd t1 t2 t3 ir
    !?ir (enumEFLAGS ctxt t1 t2 t3 regType cf ofl sf)
    ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
    !.ctxt R.AF
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
    !.ctxt R.AF
  | ConditionCodeOp.TraceStart ->
    !?ir (genDynamicFlagsUpdate ctxt)
    !.ctxt R.AF
  | ConditionCodeOp.EFlags ->
    !.ctxt R.AF
  | _ -> Utils.futureFeature ()

let getPFLazy (ctxt: TranslationContext) (ir: IRBuilder) =
  let ccOp = ctxt.ConditionCodeOp
  match ccOp with
  | ConditionCodeOp.SUBB
  | ConditionCodeOp.SUBW
  | ConditionCodeOp.SUBD
  | ConditionCodeOp.SUBQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 ir regType
    let src1 = getCCSrc1 ctxt regType
    let dst = getCCDst ctxt regType
    !!ir (t3 := dst)
    !!ir (t2 := src1)
    !!ir (t1 := t3 .+ t2)
    let sf = t3 ?< AST.num0 regType
    let cf = cfOnSub t1 t2
    let ofl = ofOnSub t1 t2 t3
    !?ir (enumEFLAGS ctxt t1 t2 t3 regType cf ofl sf)
    ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
    !.ctxt R.PF
  | ConditionCodeOp.DECB
  | ConditionCodeOp.DECW
  | ConditionCodeOp.DECD
  | ConditionCodeOp.DECQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 ir regType
    let src1 = getCCSrc1 ctxt regType
    let dst = getCCDst ctxt regType
    !!ir (t3 := dst)
    !!ir (t2 := src1)
    !!ir (t1 := t3 .+ t2)
    let sf = t3 ?< AST.num0 regType
    let cf = !.ctxt R.CF
    let ofl = ofOnSub t1 t2 t3
    !?ir (enumEFLAGS ctxt t1 t2 t3 regType cf ofl sf)
    ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
    !.ctxt R.PF
  | ConditionCodeOp.ADDB
  | ConditionCodeOp.ADDW
  | ConditionCodeOp.ADDD
  | ConditionCodeOp.ADDQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 ir regType
    let src1 = getCCSrc1 ctxt regType
    let dst = getCCDst ctxt regType
    !!ir (t3 := dst)
    !!ir (t1 := src1)
    !!ir (t2 := t3 .- t1)
    let cf = cfOnAdd t1 t3
    let struct (ofl, sf) = osfOnAdd t1 t2 t3 ir
    !?ir (enumEFLAGS ctxt t1 t2 t3 regType cf ofl sf)
    ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
    !.ctxt R.PF
  | ConditionCodeOp.INCB
  | ConditionCodeOp.INCW
  | ConditionCodeOp.INCD
  | ConditionCodeOp.INCQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 ir regType
    let src1 = getCCSrc1 ctxt regType
    let dst = getCCDst ctxt regType
    !!ir (t3 := dst)
    !!ir (t1 := src1)
    !!ir (t2 := t3 .- t1)
    let cf = !.ctxt R.CF
    let struct (ofl, sf) = osfOnAdd t1 t2 t3 ir
    !?ir (enumEFLAGS ctxt t1 t2 t3 regType cf ofl sf)
    ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
    !.ctxt R.PF
  | ConditionCodeOp.SHLB
  | ConditionCodeOp.SHLW
  | ConditionCodeOp.SHLD
  | ConditionCodeOp.SHLQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 ir regType
    let src1 = getCCSrc1 ctxt regType
    let src2 = getCCSrc2 ctxt regType
    let dst = getCCDst ctxt regType
    let n0 = AST.num0 regType
    let n1 = AST.num1 regType
    let cond1 = src2 == n1
    let cond2 = src2 == n0
    let cf = !.ctxt R.CF
    let sf = !.ctxt R.SF
    let zf = !.ctxt R.ZF
    let ofl = !.ctxt R.OF
    let newOf = AST.xthi 1<rt> dst <+> cf
    !!ir (t1 := src1)
    !!ir (t2 := src2)
    !!ir (t3 := dst)
    !!ir (cf := AST.ite cond2 cf (AST.xthi 1<rt> (t1 << (t2 .- n1))))
    !!ir (ofl := AST.ite cond1 newOf ofl)
    !!ir (sf := AST.ite cond2 sf (AST.xthi 1<rt> t3))
    !?ir (buildPF ctxt dst regType (Some cond2))
    !!ir (zf := AST.ite cond2 zf (t3 == n0))
    ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
    !.ctxt R.PF
  | ConditionCodeOp.SHRB
  | ConditionCodeOp.SHRW
  | ConditionCodeOp.SHRD
  | ConditionCodeOp.SHRQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 ir regType
    let src1 = getCCSrc1 ctxt regType
    let src2 = getCCSrc2 ctxt regType
    let dst = getCCDst ctxt regType
    let n0 = AST.num0 regType
    let n1 = AST.num1 regType
    let cond1 = src2 == n1
    let cond2 = src2 == n0
    let cf = !.ctxt R.CF
    let sf = !.ctxt R.SF
    let zf = !.ctxt R.ZF
    let ofl = !.ctxt R.OF
    !!ir (t1 := src1)
    !!ir (t2 := src2)
    !!ir (t3 := dst)
    !!ir (cf := AST.ite cond2 cf (AST.xtlo 1<rt> (t1 ?>> (t2 .- n1))))
    !!ir (ofl := AST.ite cond1 (AST.xthi 1<rt> t1) ofl)
    !!ir (sf := AST.ite cond2 sf (AST.xthi 1<rt> t3))
    !?ir (buildPF ctxt dst regType (Some cond2))
    !!ir (zf := AST.ite cond2 zf (t3 == n0))
    ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
    !.ctxt R.PF
  | ConditionCodeOp.SARB
  | ConditionCodeOp.SARW
  | ConditionCodeOp.SARD
  | ConditionCodeOp.SARQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let struct (t1, t2, t3) = tmpVars3 ir regType
    let src1 = getCCSrc1 ctxt regType
    let src2 = getCCSrc2 ctxt regType
    let dst = getCCDst ctxt regType
    let n0 = AST.num0 regType
    let n1 = AST.num1 regType
    let cond1 = src2 == n1
    let cond2 = src2 == n0
    let cf = !.ctxt R.CF
    let sf = !.ctxt R.SF
    let zf = !.ctxt R.ZF
    let ofl = !.ctxt R.OF
    !!ir (t1 := src1)
    !!ir (t2 := src2)
    !!ir (t3 := dst)
    !!ir (cf := AST.ite cond2 cf (AST.xtlo 1<rt> (t1 ?>> (t2 .- n1))))
    !!ir (ofl := AST.ite cond1 AST.b0 ofl)
    !!ir (sf := AST.ite cond2 sf (AST.xthi 1<rt> t3))
    !?ir (buildPF ctxt dst regType (Some cond2))
    !!ir (zf := AST.ite cond2 zf (t3 == n0))
    ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
    !.ctxt R.PF
  | ConditionCodeOp.LOGICB
  | ConditionCodeOp.LOGICW
  | ConditionCodeOp.LOGICD
  | ConditionCodeOp.LOGICQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let t = getCCDst ctxt regType
    !!ir (!.ctxt R.SF := AST.xthi 1<rt> t)
    !!ir (!.ctxt R.ZF := t == (AST.num0 regType))
    !?ir (buildPF ctxt t regType None)
    !!ir (!.ctxt R.CF := AST.b0)
    !!ir (!.ctxt R.OF := AST.b0)
    ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
    !.ctxt R.PF
  | ConditionCodeOp.XORXX ->
    AST.b1
  | ConditionCodeOp.TraceStart ->
    !?ir (genDynamicFlagsUpdate ctxt)
    !.ctxt R.PF
  | ConditionCodeOp.EFlags ->
    !.ctxt R.PF
  | _ -> Utils.futureFeature ()

let getCFLazy (ctxt: TranslationContext) (ir: IRBuilder) =
  let ccOp = ctxt.ConditionCodeOp
  match ccOp with
  | ConditionCodeOp.SUBB
  | ConditionCodeOp.SUBW
  | ConditionCodeOp.SUBD
  | ConditionCodeOp.SUBQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let src1 = getCCSrc1 ctxt regType
    let dst = getCCDst ctxt regType
    cfOnSub (dst .+ src1) src1
  | ConditionCodeOp.ADDB
  | ConditionCodeOp.ADDW
  | ConditionCodeOp.ADDD
  | ConditionCodeOp.ADDQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let src1 = getCCSrc1 ctxt regType
    let dst = getCCDst ctxt regType
    cfOnAdd src1 dst
  | ConditionCodeOp.INCB
  | ConditionCodeOp.INCW
  | ConditionCodeOp.INCD
  | ConditionCodeOp.INCQ
  | ConditionCodeOp.DECB
  | ConditionCodeOp.DECW
  | ConditionCodeOp.DECD
  | ConditionCodeOp.DECQ ->
    !.ctxt R.CF
  | ConditionCodeOp.SHLB
  | ConditionCodeOp.SHLW
  | ConditionCodeOp.SHLD
  | ConditionCodeOp.SHLQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let src1 = getCCSrc1 ctxt regType
    let src2 = getCCSrc2 ctxt regType
    let n0 = AST.num0 regType
    let n1 = AST.num1 regType
    let cond2 = src2 == n0
    let cf = !.ctxt R.CF
    AST.ite cond2 cf (AST.xthi 1<rt> (src1 << (src2 .- n1)))
  | ConditionCodeOp.SHRB
  | ConditionCodeOp.SHRW
  | ConditionCodeOp.SHRD
  | ConditionCodeOp.SHRQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let src1 = getCCSrc1 ctxt regType
    let src2 = getCCSrc2 ctxt regType
    let n0 = AST.num0 regType
    let n1 = AST.num1 regType
    let cond2 = src2 == n0
    let cf = !.ctxt R.CF
    AST.ite cond2 cf (AST.xtlo 1<rt> (src1 ?>> (src2 .- n1)))
  | ConditionCodeOp.SARB
  | ConditionCodeOp.SARW
  | ConditionCodeOp.SARD
  | ConditionCodeOp.SARQ ->
    let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
    let regType = RegType.fromByteWidth size
    let src1 = getCCSrc1 ctxt regType
    let src2 = getCCSrc2 ctxt regType
    let n0 = AST.num0 regType
    let n1 = AST.num1 regType
    let cond2 = src2 == n0
    let cf = !.ctxt R.CF
    AST.ite cond2 cf (AST.xtlo 1<rt> (src1 ?>> (src2 .- n1)))
  | ConditionCodeOp.LOGICB
  | ConditionCodeOp.LOGICW
  | ConditionCodeOp.LOGICD
  | ConditionCodeOp.LOGICQ
  | ConditionCodeOp.XORXX ->
    AST.b0
  | ConditionCodeOp.TraceStart ->
    !?ir (genDynamicFlagsUpdate ctxt)
    !.ctxt R.CF
  | ConditionCodeOp.EFlags ->
    !.ctxt R.CF
  | _ -> Utils.futureFeature ()
#endif
