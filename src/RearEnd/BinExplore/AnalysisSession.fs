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

namespace B2R2.RearEnd.BinExplore

open System
open System.Collections.Generic
open System.IO
open B2R2.MiddleEnd
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Represents a session that holds the state of the current analysis.
type AnalysisSession<'FnCtx, 'GlCtx>
  public(brewLoader: IBrewLoadable<'FnCtx, 'GlCtx>) =

  let binaries = Dictionary<BinaryID, BinaryBrew<'FnCtx, 'GlCtx>>()

  let paths =
    let comparer =
      if OperatingSystem.IsWindows() then StringComparer.OrdinalIgnoreCase
      else StringComparer.Ordinal
    Dictionary<string, BinaryInfo>(comparer)

  let binaryOrder = ResizeArray<BinaryInfo>()

  let mutable currentBinaryID = None

  let tryFindInfo path =
    try
      match paths.TryGetValue(Path.GetFullPath path) with
      | true, info -> Some info
      | false, _ -> None
    with :? ArgumentException ->
      None

  /// Returns the opened binaries in the order they were first loaded.
  member _.Binaries with get() = List.ofSeq binaryOrder

  /// Returns a snapshot without exposing mutable session collections.
  member _.Snapshot with get() =
    { Binaries = List.ofSeq binaryOrder
      CurrentBinaryID = currentBinaryID }

  /// Returns the current binary instance.
  member _.CurrentBinary with get() =
    currentBinaryID |> Option.map (fun id -> binaries[id])

  /// Opens and selects a binary, reusing its identity if already loaded.
  member _.OpenBinary(path) =
    try
      let path = Path.GetFullPath path
      match paths.TryGetValue path with
      | true, info ->
        currentBinaryID <- Some info.BinaryID
        Ok info
      | false, _ ->
        let brew = brewLoader.LoadBrew path
        let info = { BinaryID = BinaryID.Create(); Path = path }
        binaries[info.BinaryID] <- brew
        paths[path] <- info
        binaryOrder.Add info
        currentBinaryID <- Some info.BinaryID
        Ok info
    with e ->
      Error e.Message

  /// Opens and selects a binary for callers that do not need its identity.
  member this.AddBinary(path) =
    this.OpenBinary(path) |> Result.map ignore

  /// Checks if a binary instance with the given file path is present in the
  /// session.
  member _.HasBinary path = tryFindInfo path |> Option.isSome

  /// Looks up a binary by path without changing the current selection.
  member _.TryFindBinary path =
    tryFindInfo path |> Option.map (fun info -> binaries[info.BinaryID])

  /// Looks up a binary by identity without changing the current selection.
  member _.TryGetBinary(id) =
    match binaries.TryGetValue id with
    | true, brew -> Some brew
    | false, _ -> None

  /// Explicitly selects the binary used by current-binary commands.
  member _.SelectBinary(id) =
    if binaries.ContainsKey id then
      currentBinaryID <- Some id
      Ok()
    else
      Error $"Binary ({id}) is not loaded."

and IBrewLoadable<'FnCtx, 'GlCtx> =
  abstract LoadBrew: path: string -> BinaryBrew<'FnCtx, 'GlCtx>
