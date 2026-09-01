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

namespace B2R2.MiddleEnd.DataFlow

open System.Collections.Generic
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

/// Caches the Low-UIR statements of every CFG vertex along with the program
/// point of each, and maps each program point back to the statement and the
/// vertex holding it.
type LowUIRStmtCache() =
  let stmtInfos = Dictionary<IVertex<LowUIRBasicBlock>, StmtInfo[]>()

  let stmtOfBBLs = Dictionary<ProgramPoint, StmtOfBBL>()

  let liftStatements (v: IVertex<LowUIRBasicBlock>) (pp: ProgramPoint) =
    if not v.VData.Internals.IsAbstract then (* regular vertex *)
      let startPos = pp.Position
      v.VData.Internals.LiftedInstructions
      |> Array.collect (fun ins ->
        ins.Stmts |> Array.mapi (fun i stmt ->
          stmt, ProgramPoint(ins.Original.Address, startPos + i)))
    else (* abstract vertex *)
      let startPos = 1 (* we reserve 0 for phi definitions. *)
      let cs = Option.get pp.CallSite
      let addr = pp.Address
      v.VData.Internals.AbstractContent.Rundown
      |> Array.mapi (fun i s -> s, ProgramPoint(cs, addr, startPos + i))

  /// Maps a program point to `StmtOfBBL`, which is a pair of a Low-UIR
  /// statement and the vertex that contains the statement.
  member _.StmtOfBBLs with get() = stmtOfBBLs

  /// Returns the statements of the given vertex, lifting them on the first
  /// request and remembering them afterwards.
  member _.GetStmtInfos(v: IVertex<LowUIRBasicBlock>) =
    match stmtInfos.TryGetValue v with
    | true, stmts ->
      stmts
    | false, _ ->
      let stmts = liftStatements v v.VData.Internals.PPoint
      for stmt, pp in stmts do stmtOfBBLs[pp] <- (stmt, v)
      stmtInfos[v] <- stmts
      stmts

  /// Forgets everything known about the given vertex.
  member this.Remove v =
    for _, pp in this.GetStmtInfos v do stmtOfBBLs.Remove pp |> ignore
    stmtInfos.Remove v |> ignore

  /// Forgets everything.
  member _.Clear() =
    stmtInfos.Clear()
    stmtOfBBLs.Clear()

/// Represents a Low-UIR statement and its corresponding program point.
and StmtInfo = Stmt * ProgramPoint

/// Represents a Low-UIR statement and its corresponding vertex in the Low-UIR
/// CFG.
and StmtOfBBL = Stmt * IVertex<LowUIRBasicBlock>
