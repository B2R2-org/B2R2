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

namespace B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

open B2R2.FrontEnd
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Represents the strategy for identifying the function entry points of a
/// MIPS binary: those that the binary tells of, as the base strategy finds
/// them, along with those of the functions whose code finds gp from t9. A
/// caller of a PIC function puts the address of the function in t9, so the
/// constant that the function adds to t9 tells where it starts, though a
/// stripped binary tells of it nowhere else when only a pointer leads to it.
type MIPSFunctionIdentification(hdl: BinHandle, exnInfo: ExceptionInfo) =
  let metadata = FunctionIdentification(hdl, exnInfo) :> IFunctionIdentifiable

  interface IFunctionIdentifiable with
    member _.Identify() =
      Array.append (metadata.Identify()) (MIPSCode.findGPPrologueEntries hdl)
      |> Array.distinct
