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

open System.Collections.Generic
open B2R2
open B2R2.MiddleEnd
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Represents a workspace that holds the state of the current session of
/// BinExplore.
type Workspace<'FnCtx, 'GlCtx when 'FnCtx :> IResettable
                               and 'FnCtx: (new: unit -> 'FnCtx)
                               and 'GlCtx: (new: unit -> 'GlCtx)>
  public(brewLoader: IBrewLoadable<'FnCtx, 'GlCtx>) =

  let binaries = Dictionary<string, BinaryBrew<'FnCtx, 'GlCtx>>()

  let mutable currentBinary: BinaryBrew<'FnCtx, 'GlCtx> | null = null

  /// Target binaries that are currently open in the workspace. The key is
  /// the file path of the binary.
  member _.Binaries with get() = binaries

  /// Returns the current binary instance.
  member _.CurrentBinary with get() =
    if isNull currentBinary then None
    else Some currentBinary

  /// Adds a binary instance to the workspace. If the file path of the binary is
  /// already present in the workspace, it does nothing and returns an error.
  member _.AddBinary(path) =
    if binaries.ContainsKey path then
      Error $"File ({path}) is already loaded."
    else
      try
        let brew = brewLoader.LoadBrew path
        binaries[path] <- brew
        currentBinary <- brew
        Ok()
      with e ->
        Error e.Message

  /// Checks if a binary instance with the given file path is present in the
  /// workspace.
  member _.HasBinary path = binaries.ContainsKey path

  /// Finds a binary instance by the given file path. The file path must be
  /// present in the workspace, otherwise it returns None.
  member _.TryFindBinary path =
    match binaries.TryGetValue path with
    | true, brew -> currentBinary <- brew; Some brew
    | false, _ -> None

and IBrewLoadable<'FnCtx, 'GlCtx when 'FnCtx :> IResettable
                                          and 'FnCtx: (new: unit -> 'FnCtx)
                                          and 'GlCtx: (new: unit -> 'GlCtx)> =
  abstract LoadBrew: path: string -> BinaryBrew<'FnCtx, 'GlCtx>
