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


namespace B2R2.FrontEnd.BinFile

open System.Collections.Generic
open B2R2

/// Represents the code mode markers of a binary, arranged for walking a code
/// region in address order: it answers both what a marker at an address says,
/// and where the region that the marker starts ends.
type BinCodeModeTable(markers: BinCodeModeMarker[]) =
  /// The marked addresses in increasing order. Two markers at one address mark
  /// one region, so the later of them wins and each address appears once.
  let entries =
    let byAddr = Dictionary<Addr, BinCodeMode>()
    for m in markers do byAddr[m.Address] <- m.Mode
    byAddr
    |> Seq.map (fun kv -> kv.Key, kv.Value)
    |> Seq.sortBy fst
    |> Seq.toArray

  let addrs = entries |> Array.map fst

  /// Checks if the binary carries no marker at all, in which case looking up
  /// any address in it is pointless.
  member _.IsEmpty with get() = Array.isEmpty entries

  /// Returns the mode that a marker sets at exactly the given address, and
  /// None where no marker sits.
  member _.TryFindMode addr =
    match System.Array.BinarySearch(addrs, addr) with
    | idx when idx >= 0 -> Some(snd entries[idx])
    | _ -> None

  /// Returns the address at which the region covering the given address ends,
  /// which is the next marked address. None when no marker follows, in which
  /// case the region runs to wherever the caller stops reading.
  member _.TryFindRegionEnd addr =
    let idx = System.Array.BinarySearch(addrs, addr)
    let next = if idx >= 0 then idx + 1 else ~~~idx
    if next < addrs.Length then Some addrs[next] else None
