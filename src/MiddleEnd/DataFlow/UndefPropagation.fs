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

open B2R2.BinIR.SSA
open B2R2.FrontEnd.BinInterface
open System.Collections.Generic

module UDPropState =

  let initRegister hdl (dict: Dictionary<_, _>) =
    match hdl.RegisterBay.StackPointer with
    | Some sp ->
      let rt = hdl.RegisterBay.RegIDToRegType sp
      let str = hdl.RegisterBay.RegIDToString sp
      let var = { Kind = RegVar (rt, sp, str); Identifier = 0 }
      dict.[var] <- Untainted
      dict
    | None -> dict

  let initMemory (dict: Dictionary<_, _>) =
    dict.[0] <- (Map.empty, Set.empty)
    dict

/// Modified version of sparse conditional constant propagation of Wegman et al.
type UndefPropagation (ssaCFG, tState) =
  inherit ConstantPropagation<UDPropValue> (ssaCFG, tState)

  static member Init hdl ssaCFG spState =
    let tState =
      CPState.initState hdl
                        ssaCFG
                        (UDPropState.initRegister hdl)
                        UDPropState.initMemory
                        Undef
                        Untainted
                        UDPropValue.goingUp
                        UDPropValue.meet
                        (UDPropTransfer.evalStmt spState)
    UndefPropagation (ssaCFG, tState)
