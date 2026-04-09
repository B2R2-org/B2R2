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

namespace B2R2.RearEnd.BinExplore.GUI

open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Represents a function entry in the UI.
type FunctionItem =
  { Function: Function
    FuncID: string
    Address: Addr
    mutable OffsetRange: (uint32 * uint32) option
    Name: string }

[<RequireQualifiedAccess>]
module FunctionItem =
  let displayName (item: FunctionItem) =
    $"{item.Address:X}: {item.Name}"

  let private computeMaxAddr (cfg: LowUIRCFG) =
    cfg.Vertices
    |> Array.fold (fun maxAddr v ->
      if v.VData.Internals.IsAbstract then maxAddr
      else max maxAddr v.VData.Internals.Range.Max
    ) 0UL

  let computeOffsetRange (file: IBinFile) (item: FunctionItem) =
    match item.OffsetRange with
    | Some(sOff, eOff) ->
      struct (sOff, eOff)
    | None ->
      let ptr = file.GetBoundedPointer item.Address
      let maxAddr = computeMaxAddr item.Function.CFG
      let maxPtr = file.GetBoundedPointer maxAddr
      item.OffsetRange <- Some(uint32 ptr.Offset, uint32 maxPtr.Offset)
      struct (uint32 ptr.Offset, uint32 maxPtr.Offset)

  /// Converts from a Function into a FunctionItem for display in the UI.
  let ofFunction (func: Function) =
    { Function = func
      FuncID = func.ID
      Address = func.EntryPoint
      OffsetRange = None
      Name = func.Name }