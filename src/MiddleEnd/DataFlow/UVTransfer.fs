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

module B2R2.MiddleEnd.DataFlow.UVTransfer

open B2R2
open B2R2.BinIR
open B2R2.BinIR.SSA

let evalVar st v =
  match CPState.tryFindReg st false v with
  | None ->
    if v.Identifier = 0 then Untouched (RegisterTag v) (* Initialize here. *)
    else Touched
  | Some c -> c

let rec evalExpr st blk = function
  | Var v -> evalVar st v
  | Extract (e, _, _)
  | Cast (CastKind.ZeroExt, _, e)
  | Cast (CastKind.SignExt, _, e) -> evalExpr st blk e
  | _ -> Touched (* Any other operations will be considered "touched". *)

let evalDef st blk dstVar e =
  match dstVar.Kind with
  | MemVar
  | PCVar _ -> () (* Just ignore PCVar as it will always be "touched". *)
  | _ -> evalExpr st blk e |> CPState.updateConst st dstVar

let evalPhi st cfg blk dst srcIDs =
  match CPState.getExecutableSources st cfg blk srcIDs with
  | [||] -> ()
  | executableSrcIDs ->
    match dst.Kind with
    | MemVar | PCVar _ -> ()
    | _ ->
      match CPState.tryFindReg st true dst with
      | Some Touched -> ()
      | _ ->
        executableSrcIDs
        |> Array.choose (fun i ->
          { dst with Identifier = i } |> CPState.tryFindReg st true)
        |> Array.reduce UVValue.meet
        |> fun merged -> CPState.updateConst st dst merged

let evalJmp st cfg blk = function
  | InterJmp _ -> CPState.markExceptCallFallThrough st cfg blk
  | _ -> CPState.markAllSuccessors st cfg blk

let evalStmt st cfg blk = function
  | Def (v, e) -> evalDef st blk v e
  | Phi (v, ns) -> evalPhi st cfg blk v ns
  | Jmp jmpTy -> evalJmp st cfg blk jmpTy
  | LMark _ | SideEffect _ -> ()
