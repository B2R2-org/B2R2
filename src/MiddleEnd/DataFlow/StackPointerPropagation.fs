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
open B2R2
open B2R2.BinIR.SSA
open B2R2.FrontEnd

[<AutoOpen>]
module private StackPointerPropagation =
  let initRegister (hdl: BinHandle) =
    let dict = Dictionary ()
    match hdl.RegisterBay.StackPointer with
    | Some sp ->
      let rt = hdl.RegisterBay.RegIDToRegType sp
      let str = hdl.RegisterBay.RegIDToString sp
      let var = { Kind = RegVar (rt, sp, str); Identifier = 0 }
      dict[var] <- Const (BitVector.OfUInt64 Utils.InitialStackPointer rt)
      dict
    | None -> dict

/// This is a variant of the SparseConstantPropagation, which only tracks
/// the stack pointer used in a function. We initiate the stack pointer with a
/// constant first, and check how it propagates within the function.
/// StackPointerPropagation is generally much faster than
/// SparseConstantPropagation due to its simplicity.
type StackPointerPropagation (hdl, ssaCFG) as this =
  inherit ConstantPropagation<SPValue> (ssaCFG)

  let st = CPState.initState hdl ssaCFG (initRegister hdl) (Dictionary ()) this

  override __.State = st

  override __.Top = Undef

  interface IConstantPropagationCore<SPValue> with
    member __.Bottom = NotAConst
    member __.GoingUp a b = SPValue.goingUp a b
    member __.Meet a b = SPValue.meet a b
    member __.Transfer st cfg v _ stmt = SPTransfer.evalStmt st cfg v stmt
    member __.MemoryRead _addr _rt = None
