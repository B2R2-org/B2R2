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

/// ExceptionTable holds parsed exception information of a binary code (given by
/// the BinHandle).
type ExceptionTable (hdl) =
  let tbl = Dictionary<Addr, ARMap<Addr>> ()
  do
    hdl.FileInfo.ExceptionTable
    |> ARMap.iter (fun funcRange funcTbl ->
      let funcInfo =
        funcTbl
        |> ARMap.fold (fun funcTbl range target ->
          if target = 0UL then funcTbl
          else ARMap.add range target funcTbl) ARMap.empty
      if ARMap.isEmpty funcInfo then ()
      else tbl.[funcRange.Min] <- funcInfo)

  /// For the given function entry and an instruction address, find the landing
  /// pad (exception target) of the instruction.
  member __.TryFindExceptionTarget entry insAddr =
    match tbl.TryGetValue entry with
    | true, funcTbl -> ARMap.tryFindByAddr insAddr funcTbl
    | _ -> None

  /// Fold every table entry.
  member __.Fold fn acc =
    tbl |> Seq.fold fn acc
