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
open B2R2.FrontEnd

/// Provides the registers that a callee is assumed to modify.
[<RequireQualifiedAccess>]
module internal ClobberedRegisters =
  /// Returns the caller-saved registers that the calling convention lets a
  /// callee modify. The return value registers are excluded because a call
  /// summary defines them as return values. EVM has no such registers, as it
  /// summarizes a function by itself.
  let ofCallingConvention (hdl: BinHandle) =
    match hdl.ISA.Arch with
    | Architecture.EVM ->
      Set.empty
    | _ ->
      let cc = hdl.Conventions.Calling
      cc.CallerSavedRegisters
      |> Set.filter (fun rid ->
        rid <> cc.IntReturnRegister && rid <> cc.FloatReturnRegister)
