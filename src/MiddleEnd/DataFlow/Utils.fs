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

module B2R2.MiddleEnd.DataFlow.Utils

open System.Collections.Generic
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.MiddleEnd.ControlFlowGraph

/// We use this constant for our data-flow analyses.
let [<Literal>] InitialStackPointer = 0x80000000UL

let rec private extractUseFromExpr e acc =
  match e.E with
  | Var (_, id, _) -> Regular id :: acc
  | TempVar (_, n) -> Temporary n :: acc
  | UnOp (_, e) -> extractUseFromExpr e acc
  | BinOp (_, _, e1, e2) -> extractUseFromExpr e1 (extractUseFromExpr e2 acc)
  | RelOp (_, e1, e2) -> extractUseFromExpr e1 (extractUseFromExpr e2 acc)
  | Load (_, _, e) -> extractUseFromExpr e acc
  | Ite (c, e1, e2) ->
    extractUseFromExpr c (extractUseFromExpr e1 (extractUseFromExpr e2 acc))
  | Cast (_, _, e) -> extractUseFromExpr e acc
  | Extract (e, _, _) -> extractUseFromExpr e acc
  | _ -> []

let private extractUseFromStmt s =
  match s.S with
  | Put (_, e)
  | Store (_, _, e)
  | Jmp (e)
  | CJmp (e, _, _)
  | InterJmp (e, _) -> extractUseFromExpr e []
  | InterCJmp (c, e1, e2) ->
    extractUseFromExpr c (extractUseFromExpr e1 (extractUseFromExpr e2 []))
  | _ -> []

let extractUses stmt =
  extractUseFromStmt stmt
  |> Set.ofList

let filterRegularVars vars =
  vars |> Set.filter (function
    | Regular _ -> true
    | _ -> false)

let inline initMemory () =
  let dict = Dictionary ()
  dict[0] <- (Map.empty, Set.empty)
  dict

let computeStackShift rt (blk: SSAVertex<_>) =
  let retAddrSize = RegType.toByteWidth rt |> int64
  let adj = blk.VData.AbstractContent.UnwindingBytes
  BitVector.OfInt64 (retAddrSize + adj) rt
