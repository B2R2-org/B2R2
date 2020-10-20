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

namespace B2R2.FrontEnd.BinLifter

open B2R2
open B2R2.BinIR.LowUIR

module internal DeadCodeEliminator =
  type DeadCodeRemovalState =
    | IntraBB
    | BB

  type DeadCodeRemovalContext = {
    UseRegisters : RegisterSet
    OutRegisters : RegisterSet
    UseTempVar   : Set<int>
    OutTempVar   : Set<int>
    State : DeadCodeRemovalState }

  let emptydrc st =
    { UseRegisters = RegisterSet.empty
      OutRegisters = RegisterSet.empty
      UseTempVar   = Set.empty
      OutTempVar   = Set.empty
      State        = st }

  let removeUse n drc =
    { drc with UseRegisters = RegisterSet.remove n drc.UseRegisters }

  let updateUse ei drc =
    let { VarInfo = var; TempVarInfo = tvar } = ei
    { drc with UseTempVar = Set.union tvar drc.UseTempVar
               UseRegisters = RegisterSet.union var drc.UseRegisters }

  let updateUse2 ei ei2 drc =
    let { VarInfo = var; TempVarInfo = tvar } = ei
    let { VarInfo = var2; TempVarInfo = tvar2 } = ei2
    { drc with UseTempVar = Set.union tvar drc.UseTempVar
                            |> Set.union tvar2
               UseRegisters = RegisterSet.union var drc.UseRegisters
                              |> RegisterSet.union var2 }

  let updateUse3 ei ei2 ei3 drc =
    let { VarInfo = var; TempVarInfo = tvar } = ei
    let { VarInfo = var2; TempVarInfo = tvar2 } = ei2
    let { VarInfo = var3; TempVarInfo = tvar3 } = ei3
    { drc with UseTempVar = Set.union tvar drc.UseTempVar
                            |> Set.union tvar2
                            |> Set.union tvar3
               UseRegisters = RegisterSet.union var drc.UseRegisters
                              |> RegisterSet.union var2
                              |> RegisterSet.union var3 }

  let updateOutUse rs ei drc =
    let { VarInfo = var; TempVarInfo = tvar } = ei
    { drc with UseTempVar = Set.union tvar drc.UseTempVar
               UseRegisters = RegisterSet.union var drc.UseRegisters
               OutRegisters = RegisterSet.union rs drc.OutRegisters }

  let createNewArr (stmts: Stmt []) newLen (useInfo: bool []) =
    let newStmts = Array.zeroCreate newLen
    let rec loop cFinger nFinger =
      if nFinger <> newLen then
        if useInfo.[cFinger] then
          newStmts.[nFinger] <- stmts.[cFinger]
          loop (cFinger + 1) (nFinger + 1)
        else loop (cFinger + 1) nFinger
      else newStmts
    loop 0 0

  let optimize (stmts: Stmt []): Stmt [] =
    let len = Array.length stmts
    let useInfo = Array.init len (fun _ -> true)
    let rec loop idx len drc =
      if idx >= 0 then
        match stmts.[idx] with
        | Store (_, e1, e2) ->
          let ei1 = AST.getExprInfo e1
          let ei2 = AST.getExprInfo e2
          loop (idx - 1) len (updateUse2 ei1 ei2 drc)
        | InterJmp (_, e, _) ->
          let ei = AST.getExprInfo e
          loop (idx - 1) len (updateUse ei drc)
        | InterCJmp (e, _, e1, e2) ->
          let ei = AST.getExprInfo e
          let ei1 = AST.getExprInfo e1
          let ei2 = AST.getExprInfo e2
          loop (idx - 1) len (updateUse3 ei ei1 ei2 drc)
        (* Need Barrier: Flush whole context *)
        | LMark _ -> loop (idx - 1) len (emptydrc IntraBB)
        | Jmp e ->
          let ei = AST.getExprInfo e
          loop (idx - 1) len (updateUse ei drc)
        | CJmp (e, e1, e2) ->
          let ei = AST.getExprInfo e
          let ei1 = AST.getExprInfo e1
          let ei2 = AST.getExprInfo e2
          loop (idx - 1) len (updateUse3 ei ei1 ei2 drc)
        (* Update ctx *)
        | Put (v, e) when v = e ->
          useInfo.[idx] <- false; loop (idx - 1) (len - 1) drc
        | Put (Var (_, n, nn, rs), rhs) ->
          let isUsed = RegisterSet.exist n drc.UseRegisters
          let drc = if isUsed then removeUse n drc else drc
          if not isUsed && RegisterSet.exist n drc.OutRegisters then
            useInfo.[idx] <- false; loop (idx - 1) (len - 1) drc
          else loop (idx - 1) len (updateOutUse rs (AST.getExprInfo rhs) drc)
        | Put (TempVar (_, n), rhs) ->
          match drc.State with
          | BB ->
            if Set.contains n drc.UseTempVar then
              loop (idx - 1) len (updateUse (AST.getExprInfo rhs) drc)
            else useInfo.[idx] <- false; loop (idx - 1) (len - 1) drc
          | IntraBB ->
            loop (idx - 1) len (updateUse (AST.getExprInfo rhs) drc)
        | ISMark _ ->
          loop (idx - 1) len { drc with UseTempVar = Set.empty; State = BB }
        (* Always out *)
        | _ -> loop (idx - 1) len drc
      else createNewArr stmts len useInfo
    loop (len - 1) len (emptydrc BB)

module internal ConstantFolder =
  let emptyCtx =
    { VarMap      = Map.empty
      TempVarMap  = Map.empty }

  let update cpc lhs rhs =
    (* Only capturing in case of Num *)
    match lhs, rhs with
    | Var (_, n, _, _), Num _ ->
      { cpc with VarMap = Map.add n rhs cpc.VarMap }
    (* FIXME: Ensure SSA
    | Var (_, n, _), Var _ ->
      { cpc with VarMap = Map.add n rhs cpc.VarMap } *)
    | Var (_, n, _, _), _ -> { cpc with VarMap = Map.remove n cpc.VarMap }
    | TempVar (_, n), Num _ ->
      { cpc with TempVarMap = Map.add n rhs cpc.TempVarMap }
    (* FIXME: Ensure SSA
    | TempVar (_, n), Var _ ->
      { cpc with TempVarMap = Map.add n rhs cpc.TempVarMap } *)
    | TempVar (_, n), _ ->
      { cpc with TempVarMap = Map.remove n cpc.TempVarMap }
    | _ -> cpc

  let optimize (stmts: Stmt []) =
    let stmts = Array.copy stmts
    let rec loop idx cpc =
      if Array.length stmts > idx then
        match stmts.[idx] with
        | Store (endian, e1, e2) ->
          let (nT1, e1') = ExprWalker.Replace (cpc, e1)
          let (nT2, e2') = ExprWalker.Replace (cpc, e2)
          if nT1 || nT2 then
            let e1' = if nT1 then e1' else e1
            let e2' = if nT2 then e2' else e2
            stmts.[idx] <- Store (endian, e1', e2')
          loop (idx + 1) cpc
        | InterJmp (pc, e, t) ->
          let (needTrans, e') = ExprWalker.Replace (cpc, e)
          if needTrans then stmts.[idx] <- InterJmp (pc, e', t)
          loop (idx + 1) cpc
        | InterCJmp (e, pc, e1, e2) ->
          let (nT, e') = ExprWalker.Replace (cpc, e)
          let (nT1, e1') = ExprWalker.Replace (cpc, e1)
          let (nT2, e2') = ExprWalker.Replace (cpc, e2)
          if nT || nT1 || nT2 then
            let e' = if nT then e' else e
            let e1' = if nT1 then e1' else e1
            let e2' = if nT2 then e2' else e2
            stmts.[idx] <- match e' with
                           | Num (n) when BitVector.isOne n ->
                             InterJmp (pc, e1', InterJmpInfo.Base)
                           | Num (n) -> InterJmp (pc, e2', InterJmpInfo.Base)
                           | _ -> InterCJmp (e', pc, e1', e2')
          loop (idx + 1) cpc
        (* Need Barrier: Flush whole context *)
        | LMark _ -> loop (idx + 1) emptyCtx
        | Jmp e ->
          let (needTrans, e') = ExprWalker.Replace (cpc, e)
          if needTrans then stmts.[idx] <- Jmp (e')
          loop (idx + 1) emptyCtx
        | CJmp (e, e1, e2) ->
          let (nT, e') = ExprWalker.Replace (cpc, e)
          let (nT1, e1') = ExprWalker.Replace (cpc, e1)
          let (nT2, e2') = ExprWalker.Replace (cpc, e2)
          if nT || nT1 || nT2 then
            let e' = if nT then e' else e
            let e1' = if nT1 then e1' else e1
            let e2' = if nT2 then e2' else e2
            stmts.[idx] <- match e' with
                           | Num (n) when BitVector.isOne n -> Jmp (e1')
                           | Num (n) -> Jmp (e2')
                           | _ -> CJmp (e', e1', e2')
          loop (idx + 1) emptyCtx
        (* Update ctx *)
        | Put (lhs, rhs) ->
          let rhs = match ExprWalker.Replace (cpc, rhs) with
                    | true, rhs -> stmts.[idx] <- Put (lhs, rhs); rhs
                    | _ -> rhs
          loop (idx + 1) (update cpc lhs rhs)
        (* Always out *)
        | ISMark _ | IEMark _ | SideEffect _ -> loop (idx + 1) cpc
      else stmts
    loop 0 emptyCtx

/// Intra-block local IR optimizer.
type LocalOptimizer =
  /// Run optimization on the basic block (an array of IR statements).
  static member Optimize stmts =
    ConstantFolder.optimize stmts
    |> DeadCodeEliminator.optimize
