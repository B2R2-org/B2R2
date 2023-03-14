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
    | UnOpType.NEG -> BitVector.Neg n
    | UnOpType.NOT -> BitVector.BNot n
    | UnOpType.FSQRT -> BitVector.FSqrt n
    | UnOpType.FCOS -> BitVector.FCos n
    | UnOpType.FSIN -> BitVector.FSin n
    | UnOpType.FTAN -> BitVector.FTan n
    | UnOpType.FATAN -> BitVector.FAtan n
    | _ -> Utils.impossible ()

  let inline binop n1 n2 = function
    | BinOpType.ADD  -> BitVector.Add (n1, n2)
    | BinOpType.SUB  -> BitVector.Sub (n1, n2)
    | BinOpType.MUL  -> BitVector.Mul (n1, n2)
    | BinOpType.DIV  -> BitVector.Div (n1, n2)
    | BinOpType.SDIV -> BitVector.SDiv (n1, n2)
    | BinOpType.MOD  -> BitVector.Modulo (n1, n2)
    | BinOpType.SMOD -> BitVector.SModulo (n1, n2)
    | BinOpType.SHL  -> BitVector.Shl (n1, n2)
    | BinOpType.SAR  -> BitVector.Sar (n1, n2)
    | BinOpType.SHR  -> BitVector.Shr (n1, n2)
    | BinOpType.AND  -> BitVector.BAnd (n1, n2)
    | BinOpType.OR   -> BitVector.BOr (n1, n2)
    | BinOpType.XOR  -> BitVector.BXor (n1, n2)
    | BinOpType.CONCAT -> BitVector.Concat (n1, n2)
    | BinOpType.FADD -> BitVector.FAdd (n1, n2)
    | BinOpType.FSUB -> BitVector.FSub (n1, n2)
    | BinOpType.FMUL -> BitVector.FMul (n1, n2)
    | BinOpType.FDIV -> BitVector.FDiv (n1, n2)
    | BinOpType.FPOW -> BitVector.FPow (n1, n2)
    | BinOpType.FLOG -> BitVector.FLog (n1, n2)
    | _ -> Utils.impossible ()

  let inline relop n1 n2 = function
    | RelOpType.EQ  -> BitVector.Eq (n1, n2)
    | RelOpType.NEQ -> BitVector.Neq (n1, n2)
    | RelOpType.GT  -> BitVector.Gt (n1, n2)
    | RelOpType.GE  -> BitVector.Ge (n1, n2)
    | RelOpType.SGT -> BitVector.SGt (n1, n2)
    | RelOpType.SGE -> BitVector.SGe (n1, n2)
    | RelOpType.LT  -> BitVector.Lt (n1, n2)
    | RelOpType.LE  -> BitVector.Le (n1, n2)
    | RelOpType.SLT -> BitVector.SLt (n1, n2)
    | RelOpType.SLE -> BitVector.SLe (n1, n2)
    | RelOpType.FLT -> BitVector.FLt (n1, n2)
    | RelOpType.FLE -> BitVector.FLe (n1, n2)
    | RelOpType.FGT -> BitVector.FGt (n1, n2)
    | RelOpType.FGE -> BitVector.FGe (n1, n2)
    | _ -> Utils.impossible ()

  let inline cast t n = function
    | CastKind.SignExt -> BitVector.SExt (n, t)
    | CastKind.ZeroExt -> BitVector.ZExt (n, t)
    | CastKind.FloatCast -> BitVector.FCast (n, t)
    | CastKind.SIntToFloat -> BitVector.Itof (n, t, true)
    | CastKind.UIntToFloat -> BitVector.Itof (n, t, false)
    | CastKind.FtoICeil -> BitVector.FtoiCeil (n, t)
    | CastKind.FtoIFloor -> BitVector.FtoiFloor (n, t)
    | CastKind.FtoIRound -> BitVector.FtoiRound (n, t)
    | CastKind.FtoITrunc -> BitVector.FtoiTrunc (n, t)
    | _ -> Utils.impossible ()

  let inline extract e t pos = BitVector.Extract (e, t, pos)

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
