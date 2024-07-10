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

/// Dataflow analysis that runs under the abstract interpretation framework.
/// Abstract values are represented by 'Lattice and the unit of the analysis,
/// e.g., basic block, instruction, etc., is represented by 'WorkUnit.
[<AbstractClass>]
type DataFlowAnalysis<'Lattice, 'WorkUnit, 'V, 'E when 'Lattice: equality
                                                   and 'WorkUnit: equality
                                                   and 'V: equality
                                                   and 'E: equality> () =
  let workList = Queue<'WorkUnit> ()
  let workSet = HashSet<'WorkUnit> ()
  let absValues = Dictionary<'WorkUnit, 'Lattice> ()

  /// The initial abstract value. Our analysis starts with this value until
  /// a fixed point is reached.
  abstract Bottom: 'Lattice

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

  /// Get the abstract value for the given work unit.
  member __.GetAbsValue (work: 'WorkUnit) =
    match absValues.TryGetValue work with
    | false, _ -> __.Bottom
    | true, absValue -> absValue

  member __.PushWork (work: 'WorkUnit) =
    if workSet.Contains work then ()
    else
      workSet.Add work |> ignore
      workList.Enqueue work

  member private __.PopWork () =
    let work = workList.Dequeue ()
    assert (workSet.Contains work)
    workSet.Remove work |> ignore
    work

  /// Perform the dataflow analysis until a fixed point is reached.
  member __.Compute g =
    while not <| Seq.isEmpty workList do
      let work = __.PopWork ()
      let absValue = __.GetAbsValue work
      let transferedAbsValue = __.Transfer (g, work, absValue)
      if __.Subsume (absValue, transferedAbsValue) then ()
      else
        absValues[work] <- transferedAbsValue
        for work in __.GetNextWorks (g, work) do __.PushWork work

