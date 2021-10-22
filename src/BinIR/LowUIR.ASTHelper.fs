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

namespace B2R2.BinIR.LowUIR

open B2R2
open B2R2.BinIR

/// Concrete value optimization.
[<RequireQualifiedAccess>]
module internal ValueOptimizer =
  let inline unop n = function
    | UnOpType.NEG -> BitVector.neg n
    | UnOpType.NOT -> BitVector.bnot n
    | UnOpType.FSQRT -> BitVector.fsqrt n
    | UnOpType.FCOS -> BitVector.fcos n
    | UnOpType.FSIN -> BitVector.fsin n
    | UnOpType.FTAN -> BitVector.ftan n
    | UnOpType.FATAN -> BitVector.fatan n
    | _ -> Utils.impossible ()

  let inline binop n1 n2 = function
    | BinOpType.ADD  -> BitVector.add n1 n2
    | BinOpType.SUB  -> BitVector.sub n1 n2
    | BinOpType.MUL  -> BitVector.mul n1 n2
    | BinOpType.DIV  -> BitVector.div n1 n2
    | BinOpType.SDIV -> BitVector.sdiv n1 n2
    | BinOpType.MOD  -> BitVector.modulo n1 n2
    | BinOpType.SMOD -> BitVector.smodulo n1 n2
    | BinOpType.SHL  -> BitVector.shl n1 n2
    | BinOpType.SAR  -> BitVector.sar n1 n2
    | BinOpType.SHR  -> BitVector.shr n1 n2
    | BinOpType.AND  -> BitVector.band n1 n2
    | BinOpType.OR   -> BitVector.bor n1 n2
    | BinOpType.XOR  -> BitVector.bxor n1 n2
    | BinOpType.CONCAT -> BitVector.concat n1 n2
    | BinOpType.FADD -> BitVector.fadd n1 n2
    | BinOpType.FSUB -> BitVector.fsub n1 n2
    | BinOpType.FMUL -> BitVector.fmul n1 n2
    | BinOpType.FDIV -> BitVector.fdiv n1 n2
    | BinOpType.FPOW -> BitVector.fpow n1 n2
    | BinOpType.FLOG -> BitVector.flog n1 n2
    | _ -> Utils.impossible ()

  let inline relop n1 n2 = function
    | RelOpType.EQ  -> BitVector.eq n1 n2
    | RelOpType.NEQ -> BitVector.neq n1 n2
    | RelOpType.GT  -> BitVector.gt n1 n2
    | RelOpType.GE  -> BitVector.ge n1 n2
    | RelOpType.SGT -> BitVector.sgt n1 n2
    | RelOpType.SGE -> BitVector.sge n1 n2
    | RelOpType.LT  -> BitVector.lt n1 n2
    | RelOpType.LE  -> BitVector.le n1 n2
    | RelOpType.SLT -> BitVector.slt n1 n2
    | RelOpType.SLE -> BitVector.sle n1 n2
    | RelOpType.FLT -> BitVector.flt n1 n2
    | RelOpType.FLE -> BitVector.fle n1 n2
    | RelOpType.FGT -> BitVector.fgt n1 n2
    | RelOpType.FGE -> BitVector.fge n1 n2
    | _ -> Utils.impossible ()

  let inline cast t n = function
    | CastKind.SignExt -> BitVector.sext n t
    | CastKind.ZeroExt -> BitVector.zext n t
    | CastKind.FloatCast -> BitVector.fcast n t
    | CastKind.IntToFloat -> BitVector.itof n t
    | CastKind.FtoICeil -> BitVector.ftoiceil n t
    | CastKind.FtoIFloor -> BitVector.ftoifloor n t
    | CastKind.FtoIRound -> BitVector.ftoiround n t
    | CastKind.FtoITrunc -> BitVector.ftoitrunc n t
    | _ -> Utils.impossible ()

  let inline extract e t pos = BitVector.extract e t pos

[<RequireQualifiedAccess>]
module internal ASTHelper =
#if ! HASHCONS
  let inline buildExpr e =
    { E = e }

  let inline buildStmt s =
    { S = s }
#endif

  let emptyExprInfo =
    { HasLoad = false
      VarsUsed = RegisterSet.empty
      TempVarsUsed = Set.empty }

  let getExprInfo e =
    match e.E with
    | Num _ | PCVar _ | Nil | Name _ | FuncName _ | Undefined _ -> emptyExprInfo
    | Var (_, _, _, rset) ->
      { HasLoad = false; VarsUsed = rset; TempVarsUsed = Set.empty }
    | TempVar (_, name) ->
      { HasLoad = false
        VarsUsed = RegisterSet.empty
        TempVarsUsed = Set.singleton name }
    | UnOp (_, _, ei)
    | BinOp (_, _, _, _, ei)
    | RelOp (_, _, _, ei)
    | Load (_, _, _, ei)
    | Ite (_, _, _, ei)
    | Cast (_, _, _, ei)
    | Extract (_, _, _, ei) -> ei

  let mergeTwoExprInfo e1 e2 =
    let ei1 = getExprInfo e1
    let ei2 = getExprInfo e2
    { HasLoad = ei1.HasLoad || ei2.HasLoad
      VarsUsed = RegisterSet.union ei1.VarsUsed ei2.VarsUsed
      TempVarsUsed = Set.union ei1.TempVarsUsed ei2.TempVarsUsed }

  let mergeThreeExprInfo e1 e2 e3 =
    let ei1 = getExprInfo e1
    let ei2 = getExprInfo e2
    let ei3 = getExprInfo e3
    let vars =
      RegisterSet.union ei1.VarsUsed ei2.VarsUsed
      |> RegisterSet.union ei3.VarsUsed
    let tmps =
      Set.union ei1.TempVarsUsed ei2.TempVarsUsed
      |> Set.union ei3.TempVarsUsed
    { HasLoad = ei1.HasLoad || ei2.HasLoad || ei3.HasLoad
      VarsUsed = vars
      TempVarsUsed = tmps }
