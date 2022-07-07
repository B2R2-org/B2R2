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

namespace B2R2.MiddleEnd.ControlFlowAnalysis

open System.Collections.Generic
open B2R2
open B2R2.FrontEnd.BinInterface

[<AutoOpen>]
module private ExceptionTable =

  /// If an FDE contains an adderess which is referenced by a jump instruction
  /// belonging to a basic block at a landing pad, then we decide that the FDE
  /// is not for a valid function.
  let updateNoEntryFDEs hdl (noEntryFDEs: HashSet<Addr>) funcRange target =
    match BinHandle.ParseBBlock (hdl, addr=target) with
    | Ok (blk) ->
      let last = List.last blk
      if last.IsCall () |> not then
        match last.DirectBranchTarget () with
        | true, jmpTarget ->
          if (funcRange: AddrRange).Min <= jmpTarget
            && jmpTarget <= funcRange.Max
          then ()
          else
            match ARMap.tryFindKey jmpTarget hdl.FileInfo.ExceptionTable with
            | Some rng -> noEntryFDEs.Add rng.Min |> ignore
            | _ -> ()
        | _ -> ()
      else ()
    | _ -> ()

/// ExceptionTable holds parsed exception information of a binary code (given by
/// the BinHandle).
type ExceptionTable (hdl) =
  let tbl = Dictionary<Addr, ARMap<Addr>> ()
  let noEntryFDEs = HashSet<Addr> ()
  do
    hdl.FileInfo.ExceptionTable
    |> ARMap.iter (fun funcRange funcTbl ->
      let funcInfo =
        funcTbl
        |> ARMap.fold (fun funcTbl range target ->
          if target = 0UL then funcTbl
          else
            updateNoEntryFDEs hdl noEntryFDEs funcRange target
            ARMap.add range target funcTbl) ARMap.empty
      tbl[funcRange.Min] <- funcInfo)

  /// For the given function entry and an instruction address, find the landing
  /// pad (exception target) of the instruction.
  member __.TryFindExceptionTarget entry insAddr =
    match tbl.TryGetValue entry with
    | true, funcTbl -> ARMap.tryFindByAddr insAddr funcTbl
    | _ -> None

  member __.IsNoEntryFDE addr =
    noEntryFDEs.Contains addr

  /// Fold every table entry.
  member __.Fold fn acc =
    tbl |> Seq.fold fn acc
