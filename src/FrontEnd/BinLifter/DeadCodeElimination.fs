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
module B2R2.FrontEnd.DeadCodeElimination

open System.Collections.Generic
open B2R2.Collections
open B2R2.BinIR.LowUIR

type DeadCodeRemovalContext = {
  UseRegisters: RegisterSet
  OutRegisters: RegisterSet
  UseTempVar: HashSet<int>
  OutTempVar: HashSet<int>
  mutable IsLastBlock: bool
}

let rec createLoop (outs: Stmt[]) (ins: Stmt[]) (used: bool[]) iIdx oIdx =
  if oIdx < outs.Length then
    if used[iIdx] then
      outs[oIdx] <- ins[iIdx]
      createLoop outs ins used (iIdx + 1) (oIdx + 1)
    else createLoop outs ins used (iIdx + 1) oIdx
  else outs

let createReducedStmts (stmts: Stmt[]) reducedLen (used: bool[]) =
  createLoop (Array.zeroCreate reducedLen) stmts used 0 0

let rec optimizeLoop (stmts: Stmt[]) (used: bool[]) idx len ctxt =
  if idx >= 0 then
    match stmts[idx] with
    | Store (_, e1, e2, _) ->
      AST.updateAllVarsUses ctxt.UseRegisters ctxt.UseTempVar e1
      AST.updateAllVarsUses ctxt.UseRegisters ctxt.UseTempVar e2
      optimizeLoop stmts used (idx - 1) len ctxt
    | InterJmp (e, _, _) ->
      AST.updateAllVarsUses ctxt.UseRegisters ctxt.UseTempVar e
      optimizeLoop stmts used (idx - 1) len ctxt
    | InterCJmp (e, e1, e2, _) ->
      AST.updateAllVarsUses ctxt.UseRegisters ctxt.UseTempVar e
      AST.updateAllVarsUses ctxt.UseRegisters ctxt.UseTempVar e1
      AST.updateAllVarsUses ctxt.UseRegisters ctxt.UseTempVar e2
      optimizeLoop stmts used (idx - 1) len ctxt
    | Jmp (e, _) ->
      AST.updateAllVarsUses ctxt.UseRegisters ctxt.UseTempVar e
      optimizeLoop stmts used (idx - 1) len ctxt
    | CJmp (e, e1, e2, _) ->
      AST.updateAllVarsUses ctxt.UseRegisters ctxt.UseTempVar e
      AST.updateAllVarsUses ctxt.UseRegisters ctxt.UseTempVar e1
      AST.updateAllVarsUses ctxt.UseRegisters ctxt.UseTempVar e2
      optimizeLoop stmts used (idx - 1) len ctxt
    | Put (v, e, _) when v = e ->
      used[idx] <- false
      optimizeLoop stmts used (idx - 1) (len - 1) ctxt
    | Put (Var (_, rid, _, _), rhs, _) ->
      let isUsed = ctxt.UseRegisters.Contains (int rid)
      if isUsed then ctxt.UseRegisters.Remove (int rid) else ()
      if not isUsed && ctxt.OutRegisters.Contains (int rid) then
        used[idx] <- false
        optimizeLoop stmts used (idx - 1) (len - 1) ctxt
      else
        ctxt.OutRegisters.Add (int rid)
        AST.updateAllVarsUses ctxt.UseRegisters ctxt.UseTempVar rhs
        optimizeLoop stmts used (idx - 1) len ctxt
    | Put (TempVar (_, n, _), rhs, _) ->
      let isUsed = ctxt.UseTempVar.Contains n
      if isUsed then ctxt.UseTempVar.Remove n |> ignore else ()
      if not isUsed && (ctxt.IsLastBlock || ctxt.OutTempVar.Contains n) then
        used[idx] <- false
        optimizeLoop stmts used (idx - 1) (len - 1) ctxt
      else
        ctxt.OutTempVar.Add n |> ignore
        AST.updateAllVarsUses ctxt.UseRegisters ctxt.UseTempVar rhs
        optimizeLoop stmts used (idx - 1) len ctxt
    | ExternalCall (e, _) ->
      AST.updateAllVarsUses ctxt.UseRegisters ctxt.UseTempVar e
      optimizeLoop stmts used (idx - 1) len ctxt
    | LMark _ ->
      ctxt.IsLastBlock <- false
      optimizeLoop stmts used (idx - 1) len ctxt
    | ISMark _ ->
      ctxt.IsLastBlock <- false
      optimizeLoop stmts used (idx - 1) len ctxt
    | IEMark _ ->
      ctxt.IsLastBlock <- true
      optimizeLoop stmts used (idx - 1) len ctxt
    | _ ->
      optimizeLoop stmts used (idx - 1) len ctxt
  else createReducedStmts stmts len used

/// Assuming that the stmts are localized, i.e., those stmts represent a basic
/// block, perform dead code elimination.
let optimize (stmts: Stmt []) =
  let used = Array.init stmts.Length (fun _ -> true)
  let len = stmts.Length
  let ctxt =
    { UseRegisters = RegisterSet ()
      OutRegisters = RegisterSet ()
      UseTempVar = HashSet<int> ()
      OutTempVar= HashSet<int> ()
      IsLastBlock = false }
  optimizeLoop stmts used (len - 1) len ctxt
