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

namespace B2R2.FrontEnd.BinFile.Mach

open B2R2

/// Represents the target of a dyld fixup, produced either by chained fixups
/// (LC_DYLD_CHAINED_FIXUPS) or by the LC_DYLD_INFO bind/rebase opcodes.
type FixupTarget =
  /// An internal pointer rebased to the given (unslid + base) address.
  | Rebase of target: Addr
  /// An imported symbol bound from another image, with its providing library
  /// and an addend.
  | Bind of symbol: string * library: string * addend: int64

/// Represents a single dyld fixup located at a virtual address.
type Fixup =
  { /// Virtual address of the fixed-up pointer slot.
    FixupAddr: Addr
    /// What the slot is fixed up to.
    FixupTarget: FixupTarget }

module Fixup =
  /// Builds a map from a fixed-up virtual address to its fixup.
  let buildMap (fixups: Fixup[]) =
    fixups |> Array.fold (fun map f -> Map.add f.FixupAddr f map) Map.empty

  /// Checks whether the given address holds a bind (import) fixup.
  let isBindAt map addr =
    match Map.tryFind addr map with
    | Some { FixupTarget = Bind _ } -> true
    | _ -> false

  /// Collects the names of the loaded dylibs in load-command order, so a bind
  /// library ordinal can be used as a 1-based index into the result.
  let dylibNames cmds =
    cmds
    |> Array.choose (function
      | DyLib(_, _, c) -> Some c.DyLibName
      | _ -> None)

  /// Resolves a dyld library ordinal to a library name. Non-positive ordinals
  /// denote special lookups (self, main executable, flat, or weak) that have
  /// no specific library name.
  let resolveLibrary (dylibs: string[]) ordinal =
    if ordinal > 0 && ordinal <= dylibs.Length then dylibs[ordinal - 1] else ""
