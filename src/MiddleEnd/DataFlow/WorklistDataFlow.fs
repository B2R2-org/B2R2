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

/// Provides types and functions for worklist-based dataflow analysis.
module B2R2.MiddleEnd.DataFlow.WorklistDataFlow

open System.Collections.Generic

/// Represents a state used in worklist-based dataflow analysis.
type State<'WorkUnit,
           'Lattice,
           'V when 'WorkUnit: equality
               and 'Lattice: equality
               and 'V: equality>
  public(lattice: ILattice<'Lattice>) =

  let workList = Queue<'WorkUnit>()

  let workSet = HashSet<'WorkUnit>()

  let pushWork (work: 'WorkUnit) =
    if workSet.Contains work then ()
    else
      workSet.Add work |> ignore
      workList.Enqueue work

  let popWork () =
    let work = workList.Dequeue()
    assert (workSet.Contains work)
    workSet.Remove work |> ignore
    work

  let absValues = Dictionary<'WorkUnit, 'Lattice>()

  member _.WorkList with get() = workList

  member _.AbsValues with get() = absValues

  member _.PushWork work = pushWork work

  member _.PopWork() = popWork ()

  interface IAbsValProvider<'WorkUnit, 'Lattice> with
    member _.GetAbsValue absLoc =
      match absValues.TryGetValue absLoc with
      | false, _ -> lattice.Bottom
      | true, absValue -> absValue

/// Represents an interface that defines how the worklist-based dataflow
/// analysis should be performed.
type IScheme<'WorkUnit, 'AbsVal when 'WorkUnit: equality
                                 and 'AbsVal: equality> =
  /// Get the next set of works to perform.
  abstract GetNextWorks: 'WorkUnit -> IReadOnlyCollection<'WorkUnit>

  /// The transfer function, which computes the next abstract value from the
  /// current abstract value by executing the given 'WorkUnit.
  abstract Transfer: 'WorkUnit -> 'AbsVal

/// Runs the worklist-based dataflow analysis on the given initial work list.
let compute initialWorkList (lattice: ILattice<_>) (sch: IScheme<_, _>) state =
  for work in initialWorkList do (state: State<_, _, _>).PushWork work
  while not <| Seq.isEmpty state.WorkList do
    let work = state.PopWork()
    let absValue = (state :> IAbsValProvider<_, _>).GetAbsValue work
    let transferedAbsValue = sch.Transfer work
    if lattice.Subsume(absValue, transferedAbsValue) then ()
    else
      state.AbsValues[work] <- transferedAbsValue
      for work in sch.GetNextWorks work do state.PushWork work
  state
