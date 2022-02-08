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
open B2R2.FrontEnd.BinInterface
open B2R2.MiddleEnd.DataFlow.Utils

[<AutoOpen>]
module private SparseConstantPropagation =

  let initRegister hdl =
    let dict = Dictionary ()
    match hdl.RegisterBay.StackPointer with
    | Some sp ->
      let rt = hdl.RegisterBay.RegIDToRegType sp
      let str = hdl.RegisterBay.RegIDToString sp
      let var = { Kind = RegVar (rt, sp, str); Identifier = 0 }
      dict[var] <- Const (BitVector.ofUInt64 InitialStackPointer rt)
      dict
    | None -> dict

/// The most basic constant propagation algorithm, which can track stack-based
/// memory objects and GOT pointers. The reader is to enable reading data
/// from external sections, e.g., rodata. If the reader is not given, we simply
/// ignore such global data.
type SparseConstantPropagation (hdl, ssaCFG, ?reader) as this =

  inherit ConstantPropagation<SCPValue> (ssaCFG)

  let reader = defaultArg reader (fun _ _ -> None)
  let st = CPState.initState hdl ssaCFG (initRegister hdl) (initMemory ()) this

  override __.State = st

  override __.Top = Undef

  interface IConstantPropagationCore<SCPValue> with
    member __.Bottom = NotAConst
    member __.GoingUp a b = SCPValue.goingUp a b
    member __.Meet a b = SCPValue.meet a b
    member __.Transfer st cfg blk _ stmt = SCPTransfer.evalStmt st cfg blk stmt
    member __.MemoryRead addr rt = reader addr rt
