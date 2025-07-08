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

namespace B2R2.FrontEnd

open B2R2
open B2R2.FrontEnd.BinFile

/// Represents a linear sweep instruction collector, which is the most basic
/// instruction collector performing linear sweep disassembly.
type LinearSweepInstructionCollector (hdl: BinHandle,
                                      liftingUnit: LiftingUnit) =
  let rec update updateFn (ptr: BinFilePointer) =
    if ptr.IsValid then
      match liftingUnit.TryParseInstruction (ptr=ptr) with
      | Ok ins ->
        updateFn (ptr.Addr, OnlyOne ins) |> ignore
        update updateFn (BinFilePointer.Advance ptr (int ins.Length))
      | Error _ ->
        let shiftAmount = liftingUnit.InstructionAlignment
        update updateFn (BinFilePointer.Advance ptr shiftAmount)
    else ()

  new (hdl: BinHandle) =
    LinearSweepInstructionCollector (hdl, hdl.NewLiftingUnit ())

  interface IInstructionCollectable with
    member _.Collect updateFn =
      let ptr = liftingUnit.File.GetTextSectionPointer ()
      update updateFn ptr

    member _.ParseInstructionCandidate addr =
      let liftingUnit = hdl.NewLiftingUnit () (* always create a new one! *)
      match liftingUnit.TryParseInstruction (addr=addr) with
      | Ok ins -> Ok (OnlyOne ins)
      | Error _ -> Error ErrorCase.ParsingFailure
