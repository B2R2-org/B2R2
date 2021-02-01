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

open B2R2

/// Maintain the address-level coverage information, and thereby, gap
/// information.
type CoverageMaintainer () =
  let mutable coverage = IntervalSet.empty

  let rec combineRanges minAddr maxAddr = function
    | (r: AddrRange) :: tl ->
      combineRanges (min r.Min minAddr) (max r.Max maxAddr) tl
    | [] -> AddrRange (minAddr, maxAddr)

  let rec computeGaps map myAddr = function
    | (r1: AddrRange) :: tl ->
      if r1.IsIncluding myAddr then computeGaps map r1.Max tl
      else
#if CFGDEBUG
        dbglog (nameof CoverageMaintainer) "Computed gap %x--%x" myAddr r1.Min
#endif
        computeGaps (Map.add myAddr r1.Min map) r1.Max tl
    | _ -> map

  /// Add covered address range.
  member __.AddCoverage range =
    let overlaps = IntervalSet.findAll range coverage
    let range = range :: overlaps |> combineRanges System.UInt64.MaxValue 0UL
    coverage <-
      overlaps |> List.fold (fun cov r -> IntervalSet.remove r cov) coverage
    coverage <- IntervalSet.add range coverage

  /// Make the address range uncovered.
  member __.RemoveCoverage (range: AddrRange) =
    let rec removeLoop = function
      | (r: AddrRange) :: tl ->
        if r.Min >= range.Min && r.Max <= range.Max then
          coverage <- IntervalSet.remove r coverage
        elif range.Min > r.Min && range.Max < r.Max then
          let left = AddrRange (r.Min, range.Min)
          let right = AddrRange (range.Max, r.Max)
          let c = IntervalSet.remove r coverage
          coverage <- IntervalSet.add left c |> IntervalSet.add right
        elif r.Min >= range.Min then
          let r' = AddrRange (range.Max, r.Max)
          coverage <- IntervalSet.remove r coverage |> IntervalSet.add r'
        else (* elif r.Max <= range.Max then *)
          let r' = AddrRange (r.Min, range.Min)
          coverage <- IntervalSet.remove r coverage |> IntervalSet.add r'
        removeLoop tl
      | [] -> ()
    IntervalSet.findAll range coverage |> removeLoop

  /// Is the given address is within the range of parsed code?
  member __.IsAddressCovered addr =
    IntervalSet.tryFindByAddr addr coverage |> Option.isSome

  /// For a given address range (from sAddr to eAddr), return a list of gap
  /// start addresses. A gap is a "uncovered chunk" in the binary code.
  member __.ComputeGapAddrs sAddr eAddr =
    let range = AddrRange (sAddr, eAddr)
    match IntervalSet.findAll range coverage with
    | [] -> (* Nothing covered; the whole range is a gap. *)
      Map.add sAddr eAddr Map.empty
    | [_] -> Map.empty (* Only a single overlap == No gap *)
    | overlaps -> (* Two or more overlaps == one or more gaps *)
      overlaps |> List.sortBy (fun r -> r.Min) |> computeGaps Map.empty sAddr
