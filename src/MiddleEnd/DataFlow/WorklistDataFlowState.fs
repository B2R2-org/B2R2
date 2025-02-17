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

namespace B2R2.MiddleEnd.DataFlow

open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

/// Worklist-based dataflow analysis state.
type WorklistDataFlowState<'WorkUnit,
                           'Lattice,
                           'V when 'WorkUnit: equality
                               and 'Lattice: equality
                               and 'V: equality>
  public (analysis: IWorklistDataFlowAnalysis<'WorkUnit, 'Lattice, 'V>) =

  let workList = Queue<'WorkUnit> ()

  let workSet = HashSet<'WorkUnit> ()

  let pushWork (work: 'WorkUnit) =
    if workSet.Contains work then ()
    else
      workSet.Add work |> ignore
      workList.Enqueue work

  let popWork () =
    let work = workList.Dequeue ()
    assert (workSet.Contains work)
    workSet.Remove work |> ignore
    work

  let absValues = Dictionary<'WorkUnit, 'Lattice> ()

  member _.WorkList with get() = workList

  member _.AbsValues with get() = absValues

  member _.PushWork work = pushWork work

  member _.PopWork () = popWork ()

  interface IDataFlowState<'WorkUnit, 'Lattice> with
    member __.GetAbsValue absLoc =
      match absValues.TryGetValue absLoc with
      | false, _ -> analysis.Bottom
      | true, absValue -> absValue

/// Worklist-based data-flow analysis interface.
and IWorklistDataFlowAnalysis<'WorkUnit,
                              'Lattice,
                              'V when 'WorkUnit: equality
                                  and 'Lattice: equality
                                  and 'V: equality> =
  /// The initial abstract value representing the bottom of the lattice. Our
  /// analysis starts with this value until it reaches a fixed point.
  abstract Bottom: 'Lattice

  /// Initialize the list of work units to start the analysis. This is a
  /// callback method that runs before the analysis starts, so any
  /// initialization logic should be implemented here.
  abstract InitializeWorkList:
    IDiGraphAccessible<'V, _> -> IReadOnlyCollection<'WorkUnit>

  /// The subsume operator, which checks if the first lattice subsumes the
  /// second. This is to know if the analysis should stop or not.
  abstract Subsume: 'Lattice * 'Lattice -> bool

  /// The transfer function, which computes the next abstract value from the
  /// current abstract value by executing the given 'WorkUnit.
  abstract Transfer:
       IDataFlowState<'WorkUnit, 'Lattice>
     * IDiGraphAccessible<'V, 'E>
     * 'WorkUnit
     * 'Lattice
    -> 'Lattice

  /// Get the next set of works to perform.
  abstract GetNextWorks:
       IDiGraphAccessible<'V, 'E>
     * 'WorkUnit
    -> IReadOnlyCollection<'WorkUnit>

