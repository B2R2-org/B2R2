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

/// Worklist-based dataflow analysis.
type WorklistDataFlowAnalysis<'WorkUnit,
                              'Lattice,
                              'V when 'WorkUnit: equality
                                  and 'Lattice: equality
                                  and 'V: equality>
  public (analysis: IWorklistDataFlowAnalysis<'WorkUnit, 'Lattice, 'V>) =

  interface IDataFlowAnalysis<'WorkUnit,
                              'Lattice,
                              WorklistDataFlowState<'WorkUnit, 'Lattice, 'V>,
                              'V> with
    member _.InitializeState _vs =
      WorklistDataFlowState<'WorkUnit, 'Lattice, 'V> (analysis)

    member _.Compute g state =
      for work in analysis.InitializeWorkList g do state.PushWork work
      while not <| Seq.isEmpty state.WorkList do
        let work = state.PopWork ()
        let absValue = (state :> IDataFlowState<_, _>).GetAbsValue work
        let transferedAbsValue = analysis.Transfer (state, g, work, absValue)
        if analysis.Subsume (absValue, transferedAbsValue) then ()
        else
          state.AbsValues[work] <- transferedAbsValue
          for work in analysis.GetNextWorks (g, work) do state.PushWork work
      state
