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

/// Implements worklist-based dataflow analysis.
module B2R2.MiddleEnd.DataFlow.WorklistDataFlow

open System.Collections.Generic

/// Represents a state used in worklist-based dataflow analysis.
type State<'WorkUnit, 'AbsVal
  when 'WorkUnit: equality
  and 'AbsVal: equality>
  public(lattice: ILattice<'AbsVal>) =

  let workList = Queue<'WorkUnit>()

  let workSet = HashSet<'WorkUnit>()

  let pushWork (work: 'WorkUnit) =
    if workSet.Contains work then
      ()
    else
      workSet.Add work |> ignore
      workList.Enqueue work

  let popWork () =
    let work = workList.Dequeue()
    assert (workSet.Contains work)
    workSet.Remove work |> ignore
    work

  let absValues = Dictionary<'WorkUnit, 'AbsVal>()

  /// Returns true when the work list still has a work unit to process. The
  /// work list itself stays hidden because it is kept in sync with a set that
  /// an outside enqueue would not update.
  member _.HasWork with get() = workList.Count > 0

  /// Maps a work unit to the abstract value the analysis has settled on for
  /// it.
  member _.AbsValues with get() = absValues :> IReadOnlyDictionary<_, _>

  /// Checks whether the first abstract value subsumes the second under the
  /// lattice this state was built on, which is the only lattice the analysis
  /// gets to judge the order by.
  member internal _.Subsume(a, b) = lattice.Subsume(a, b)

  /// Records the abstract value that the given work unit settled on.
  member internal _.SetAbsValue(work, absValue) = absValues[work] <- absValue

  /// Enqueues the given work unit unless it is already waiting.
  member _.PushWork work = pushWork work

  /// Takes the next work unit off the work list.
  member _.PopWork() = popWork ()

  /// Forgets every abstract value along with any work left over, so that the
  /// next run starts from the bottom of the lattice again.
  member _.Reset() =
    workList.Clear()
    workSet.Clear()
    absValues.Clear()

  interface IAbsValProvider<'WorkUnit, 'AbsVal> with
    member _.GetAbsValue absLoc =
      match absValues.TryGetValue absLoc with
      | false, _ -> lattice.Bottom
      | true, absValue -> absValue

/// Represents an interface that defines how the worklist-based dataflow
/// analysis should be performed.
type IScheme<'WorkUnit, 'AbsVal
  when 'WorkUnit: equality
  and 'AbsVal: equality> =
  /// Gets the next set of works to perform.
  abstract GetNextWorks: 'WorkUnit -> IReadOnlyCollection<'WorkUnit>

  /// Computes the next abstract value from the current abstract value by
  /// executing the given 'WorkUnit.
  abstract Transfer: 'WorkUnit -> 'AbsVal

/// Runs the worklist-based dataflow analysis on the given initial work list.
let compute initialWorkList (sch: IScheme<_, _>) state =
  for work in initialWorkList do (state: State<_, _>).PushWork work
  while state.HasWork do
    let work = state.PopWork()
    let absValue = (state :> IAbsValProvider<_, _>).GetAbsValue work
    let transferedAbsValue = sch.Transfer work
    if state.Subsume(absValue, transferedAbsValue) then
      ()
    else
      state.SetAbsValue(work, transferedAbsValue)
      for work in sch.GetNextWorks work do state.PushWork work
  state
