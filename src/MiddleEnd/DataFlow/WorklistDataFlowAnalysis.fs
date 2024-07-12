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

/// Worklist-based dataflow analysis.
[<AbstractClass>]
type WorklistDataFlowAnalysis<'WorkUnit, 'Lattice, 'V, 'E
                                                 when 'WorkUnit: equality
                                                  and 'Lattice: equality
                                                  and 'V: equality
                                                  and 'E: equality> () as this =
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

  let getAbsValue (loc: 'WorkUnit) =
    match absValues.TryGetValue loc with
    | false, _ -> this.Bottom
    | true, absValue -> absValue

  /// The initial abstract value. Our analysis starts with this value until
  /// a fixed point is reached.
  abstract Bottom: 'Lattice

  /// Initialize the list of work units to start the analysis. This is a
  /// callback method that runs before the analysis starts, so any
  /// initialization logic should be implemented here.
  abstract InitializeWorkList: IGraph<'V, 'E> -> IReadOnlyCollection<'WorkUnit>

  /// The subsume operator, which checks if the first lattice subsumes the
  /// second. This is to know if the analysis should stop or not.
  abstract Subsume: 'Lattice * 'Lattice -> bool

  /// The transfer function, which computes the next abstract value from the
  /// current abstract value by executing the given 'WorkUnit.
  abstract Transfer:
     IGraph<'V, 'E>
     * 'WorkUnit
     * 'Lattice
    -> 'Lattice

  /// Get the next set of works to perform.
  abstract GetNextWorks:
     IGraph<'V, 'E>
     * 'WorkUnit
    -> IReadOnlyCollection<'WorkUnit>

  member private __.Initialize g =
    for work in __.InitializeWorkList g do pushWork work

  interface IDataFlowAnalysis<'WorkUnit, 'Lattice, 'V, 'E> with
    member __.Compute g =
      __.Initialize g
      while not <| Seq.isEmpty workList do
        let work = popWork ()
        let absValue = getAbsValue work
        let transferedAbsValue = __.Transfer (g, work, absValue)
        if __.Subsume (absValue, transferedAbsValue) then ()
        else
          absValues[work] <- transferedAbsValue
          for work in __.GetNextWorks (g, work) do pushWork work

    member __.GetAbsValue absLoc = getAbsValue absLoc
