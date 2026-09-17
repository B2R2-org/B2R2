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

/// Provides a function that performs dead code elimination for the lifted IR
/// statements. This function assumes that the statements are localized, i.e.,
/// they represent a basic block.
[<RequireQualifiedAccess>]
module B2R2.FrontEnd.BinLifter.DeadCodeElimination

open System.Collections.Generic
open B2R2.Collections
open B2R2.BinIR.LowUIR

type private DeadCodeRemovalContext =
  { UseRegisters: RegisterSet
    OutRegisters: RegisterSet
    UseTempVar: HashSet<int>
    OutTempVar: HashSet<int>
    mutable IsLastBlock: bool }

let rec private createLoop (outs: _[]) (ins: _[]) (used: bool[]) iIdx oIdx =
  if oIdx < outs.Length then
    if used[iIdx] then
      outs[oIdx] <- ins[iIdx]
      createLoop outs ins used (iIdx + 1) (oIdx + 1)
    else
      createLoop outs ins used (iIdx + 1) oIdx
  else
    outs

let inline private createReducedStmts stmts reducedLen (used: bool[]) =
  createLoop (Array.zeroCreate reducedLen) stmts used 0 0

let rec private optimizeLoop (stmts: Stmt[]) (used: bool[]) idx len ctx =
  if idx >= 0 then
    match stmts[idx] with
    | Store(Addr = e1; Value = e2) ->
      AST.updateAllVarsUses ctx.UseRegisters ctx.UseTempVar e1
      AST.updateAllVarsUses ctx.UseRegisters ctx.UseTempVar e2
      optimizeLoop stmts used (idx - 1) len ctx
    | InterJmp(Target = e) ->
      AST.updateAllVarsUses ctx.UseRegisters ctx.UseTempVar e
      optimizeLoop stmts used (idx - 1) len ctx
    | InterCJmp(Cond = e; TrueTarget = e1; FalseTarget = e2) ->
      AST.updateAllVarsUses ctx.UseRegisters ctx.UseTempVar e
      AST.updateAllVarsUses ctx.UseRegisters ctx.UseTempVar e1
      AST.updateAllVarsUses ctx.UseRegisters ctx.UseTempVar e2
      optimizeLoop stmts used (idx - 1) len ctx
    | Jmp(Target = e) ->
      AST.updateAllVarsUses ctx.UseRegisters ctx.UseTempVar e
      optimizeLoop stmts used (idx - 1) len ctx
    | CJmp(Cond = e; TrueTarget = e1; FalseTarget = e2) ->
      AST.updateAllVarsUses ctx.UseRegisters ctx.UseTempVar e
      AST.updateAllVarsUses ctx.UseRegisters ctx.UseTempVar e1
      AST.updateAllVarsUses ctx.UseRegisters ctx.UseTempVar e2
      optimizeLoop stmts used (idx - 1) len ctx
    | Put(Dst = v; Src = e) when v = e ->
      used[idx] <- false
      optimizeLoop stmts used (idx - 1) (len - 1) ctx
    | Put(Dst = Var(RegisterID = rid); Src = rhs) ->
      let isUsed = ctx.UseRegisters.Contains(int rid)
      if isUsed then ctx.UseRegisters.Remove(int rid) else ()
      if not isUsed && ctx.OutRegisters.Contains(int rid) then
        used[idx] <- false
        optimizeLoop stmts used (idx - 1) (len - 1) ctx
      else
        ctx.OutRegisters.Add(int rid)
        AST.updateAllVarsUses ctx.UseRegisters ctx.UseTempVar rhs
        optimizeLoop stmts used (idx - 1) len ctx
    | Put(Dst = TempVar(Index = n); Src = rhs) ->
      let isUsed = ctx.UseTempVar.Contains n
      if isUsed then ctx.UseTempVar.Remove n |> ignore else ()
      if not isUsed && (ctx.IsLastBlock || ctx.OutTempVar.Contains n) then
        used[idx] <- false
        optimizeLoop stmts used (idx - 1) (len - 1) ctx
      else
        ctx.OutTempVar.Add n |> ignore
        AST.updateAllVarsUses ctx.UseRegisters ctx.UseTempVar rhs
        optimizeLoop stmts used (idx - 1) len ctx
    | ExternalCall(Call = e) ->
      AST.updateAllVarsUses ctx.UseRegisters ctx.UseTempVar e
      optimizeLoop stmts used (idx - 1) len ctx
    | LMark _ ->
      ctx.IsLastBlock <- false
      optimizeLoop stmts used (idx - 1) len ctx
    | ISMark _ ->
      ctx.IsLastBlock <- false
      optimizeLoop stmts used (idx - 1) len ctx
    | IEMark _ ->
      ctx.IsLastBlock <- true
      optimizeLoop stmts used (idx - 1) len ctx
    | _ ->
      optimizeLoop stmts used (idx - 1) len ctx
  else
    createReducedStmts stmts len used

/// Assuming that the stmts are localized, i.e., those stmts represent a basic
/// block, perform dead code elimination.
let optimize (stmts: Stmt[]) =
  let used = Array.create stmts.Length true
  let len = stmts.Length
  let ctx =
    { UseRegisters = RegisterSet()
      OutRegisters = RegisterSet()
      UseTempVar = HashSet<int>()
      OutTempVar = HashSet<int>()
      IsLastBlock = false }
  optimizeLoop stmts used (len - 1) len ctx
