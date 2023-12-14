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
open B2R2.BinIR.SSA
open B2R2.FrontEnd
open B2R2.MiddleEnd.DataFlow.Utils

[<AutoOpen>]
module private UntouchedValuePropagation =
  let initRegister (hdl: BinHandle) =
    let dict = Dictionary ()
    hdl.RegisterFactory.GetGeneralRegExprs ()
    |> List.iter (fun regExpr ->
      let rid = hdl.RegisterFactory.RegIDFromRegExpr regExpr
      let rt = hdl.RegisterFactory.RegIDToRegType rid
      let str = hdl.RegisterFactory.RegIDToString rid
      let var = { Kind = RegVar (rt, rid, str); Identifier = 0 }
      dict[var] <- Untouched (RegisterTag var)
    )
    match hdl.RegisterFactory.StackPointer with
    | Some sp ->
      let rt = hdl.RegisterFactory.RegIDToRegType sp
      let str = hdl.RegisterFactory.RegIDToString sp
      let var = { Kind = RegVar (rt, sp, str); Identifier = 0 }
      dict[var] <- Touched
      dict
    | None -> dict

/// This is a variant of the SparseConstantPropagation, which computes which
/// registers or memory cells are not re-defined (i.e., are untouched) within a
/// function. This algorithm assumes that the SSA has been promoted.
type UntouchedValuePropagation (hdl, ssaCFG) as this =
  inherit ConstantPropagation<UVValue> (ssaCFG)

  let st = CPState.initState hdl ssaCFG (initRegister hdl) (initMemory ()) this

  override __.State = st

  override __.Top = Undef

  interface IConstantPropagation<UVValue> with
    member __.Bottom = Touched
    member __.GoingUp a b = UVValue.goingUp a b
    member __.Meet a b = UVValue.meet a b
    member __.Transfer st cfg v _ppoint stmt = UVTransfer.evalStmt st cfg v stmt
    member __.MemoryRead _addr _rt = None
