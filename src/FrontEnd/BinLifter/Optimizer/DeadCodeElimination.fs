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

[<RequireQualifiedAccess>]
module B2R2.FrontEnd.BinLifter.DeadCodeElimination

open B2R2
open B2R2.BinIR.LowUIR

type DeadCodeRemovalContext = {
  UseRegisters: RegisterSet
  OutRegisters: RegisterSet
  UseTempVar: Set<int>
  OutTempVar: Set<int>
  IsLastBlock: bool
}

let emptyCtxt =
  { UseRegisters = RegisterSet.empty
    OutRegisters = RegisterSet.empty
    UseTempVar = Set.empty
    OutTempVar= Set.empty
    IsLastBlock = false }

let removeUse n ctxt =
  { ctxt with UseRegisters = RegisterSet.remove n ctxt.UseRegisters }

let removeTempUse n ctxt =
  { ctxt with UseTempVar = Set.remove n ctxt.UseTempVar }

let updateUse ei ctxt =
  { ctxt with UseTempVar = Set.union ei.TempVarsUsed ctxt.UseTempVar
              UseRegisters = RegisterSet.union ei.VarsUsed ctxt.UseRegisters }

let updateUse2 ei1 ei2 ctxt =
  { ctxt with
      UseTempVar = Set.union ei1.TempVarsUsed ctxt.UseTempVar
                   |> Set.union ei2.TempVarsUsed
      UseRegisters = RegisterSet.union ei1.VarsUsed ctxt.UseRegisters
                     |> RegisterSet.union ei2.VarsUsed }

let updateUse3 ei1 ei2 ei3 ctxt =
  { ctxt with
      UseTempVar = Set.union ei1.TempVarsUsed ctxt.UseTempVar
                   |> Set.union ei2.TempVarsUsed
                   |> Set.union ei3.TempVarsUsed
      UseRegisters = RegisterSet.union ei1.VarsUsed ctxt.UseRegisters
                     |> RegisterSet.union ei2.VarsUsed
                     |> RegisterSet.union ei3.VarsUsed }

let updateOut rs ctxt =
  { ctxt with OutRegisters = RegisterSet.union rs ctxt.OutRegisters }

let updateTempOut n ctxt =
  { ctxt with OutTempVar = Set.add n ctxt.OutTempVar }

let rec createLoop (outs: Stmt []) (ins: Stmt []) (used: bool []) iIdx oIdx =
  if oIdx < outs.Length then
    if used.[iIdx] then
      outs.[oIdx] <- ins.[iIdx]
      createLoop outs ins used (iIdx + 1) (oIdx + 1)
    else createLoop outs ins used (iIdx + 1) oIdx
  else outs

let createReducedStmts (stmts: Stmt []) reducedLen (used: bool []) =
  createLoop (Array.zeroCreate reducedLen) stmts used 0 0

let rec optimizeLoop (stmts: Stmt []) (used: bool []) idx len ctxt =
  if idx >= 0 then
    match stmts.[idx].S with
    | Store (_, e1, e2) ->
      let ei1 = AST.getExprInfo e1
      let ei2 = AST.getExprInfo e2
      optimizeLoop stmts used (idx - 1) len (updateUse2 ei1 ei2 ctxt)
    | InterJmp (e, _) ->
      let ei = AST.getExprInfo e
      optimizeLoop stmts used (idx - 1) len (updateUse ei ctxt)
    | InterCJmp (e, e1, e2) ->
      let ei = AST.getExprInfo e
      let ei1 = AST.getExprInfo e1
      let ei2 = AST.getExprInfo e2
      optimizeLoop stmts used (idx - 1) len (updateUse3 ei ei1 ei2 ctxt)
    | Jmp e ->
      let ei = AST.getExprInfo e
      optimizeLoop stmts used (idx - 1) len (updateUse ei ctxt)
    | CJmp (e, e1, e2) ->
      let ei = AST.getExprInfo e
      let ei1 = AST.getExprInfo e1
      let ei2 = AST.getExprInfo e2
      optimizeLoop stmts used (idx - 1) len (updateUse3 ei ei1 ei2 ctxt)
    | Put (v, e) when v = e ->
      used.[idx] <- false
      optimizeLoop stmts used (idx - 1) (len - 1) ctxt
    | Put ({ E = Var (_, rid, _, rs) }, rhs) ->
      let isUsed = RegisterSet.exist rid ctxt.UseRegisters
      let ctxt = if isUsed then removeUse rid ctxt else ctxt
      if not isUsed && RegisterSet.exist rid ctxt.OutRegisters then
        used.[idx] <- false
        optimizeLoop stmts used (idx - 1) (len - 1) ctxt
      else
        let ctxt = updateOut rs ctxt
        let ctxt = updateUse (AST.getExprInfo rhs) ctxt
        optimizeLoop stmts used (idx - 1) len ctxt
    | Put ({ E = TempVar (_, n) }, rhs) ->
      let isUsed = Set.contains n ctxt.UseTempVar
      let ctxt = if isUsed then removeTempUse n ctxt else ctxt
      if not isUsed && (ctxt.IsLastBlock || Set.contains n ctxt.OutTempVar) then
        used.[idx] <- false
        optimizeLoop stmts used (idx - 1) (len - 1) ctxt
      else
        let ctxt = updateTempOut n ctxt
        let ctxt = updateUse (AST.getExprInfo rhs) ctxt
        optimizeLoop stmts used (idx - 1) len ctxt
    | LMark _ ->
      optimizeLoop stmts used (idx - 1) len { ctxt with IsLastBlock = false }
    | ISMark _ ->
      optimizeLoop stmts used (idx - 1) len { ctxt with IsLastBlock = false }
    | IEMark _ ->
      optimizeLoop stmts used (idx - 1) len { ctxt with IsLastBlock = true }
    | _ -> optimizeLoop stmts used (idx - 1) len ctxt
  else createReducedStmts stmts len used

/// Assuming that the stmts are localized, i.e., those stmts represent a basic
/// block, perform dead code elimination.
let optimize (stmts: Stmt []) =
  let used = Array.init stmts.Length (fun _ -> true)
  let len = stmts.Length
  optimizeLoop stmts used (len - 1) len emptyCtxt
