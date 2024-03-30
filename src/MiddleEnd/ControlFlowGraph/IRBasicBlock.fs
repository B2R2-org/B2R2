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

namespace B2R2.MiddleEnd.ControlFlowGraph

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR

/// Basic block type for IR-level CFGs.
type IRBasicBlock private (ppoint, funcAbs, liftedInstrs) =
  inherit AbstractableBasicBlock<FunctionAbstraction> (ppoint, funcAbs)

  member __.LiftedInstructions with get(): LiftedInstruction[] = liftedInstrs

  member __.LastInstruction with get() =
    if Array.isEmpty liftedInstrs then Utils.impossible ()
    else liftedInstrs[liftedInstrs.Length - 1].Original

  override __.Range with get() =
    match funcAbs with
    | Some _ -> raise AbstractBlockAccessException
    | None ->
      let lastIns = liftedInstrs[liftedInstrs.Length - 1].Original
      let lastAddr = lastIns.Address + uint64 lastIns.Length
      AddrRange (ppoint.Address, lastAddr - 1UL)

  override __.Cut (cutPoint: Addr) =
    match funcAbs with
    | Some _ -> raise AbstractBlockAccessException
    | None ->
      assert (__.Range.IsIncluding cutPoint)
      let before, after =
        liftedInstrs
        |> Array.partition (fun ins -> ins.Original.Address < cutPoint)
      IRBasicBlock.CreateRegular (before, ppoint),
      IRBasicBlock.CreateRegular (after, ppoint)

  override __.ToVisualBlock () =
    match funcAbs with
    | Some _ -> [||]
    | None ->
      liftedInstrs
      |> Array.collect (fun liftedIns -> liftedIns.Stmts)
      |> Array.map (fun stmt ->
        [| { AsmWordKind = AsmWordKind.String
             AsmWordValue = LowUIR.Pp.stmtToString stmt } |])

  static member CreateRegular (liftedInstrs, ppoint) =
    IRBasicBlock (ppoint, None, liftedInstrs)

  static member CreateAbstract (ppoint, callSiteAddr, retPoint,
                                ?fromTail, ?fromInd) =
    let fromTail = defaultArg fromTail false
    let fromInd = defaultArg fromInd false
    let info = FunctionAbstraction (callSiteAddr, retPoint, fromTail, fromInd)
    IRBasicBlock (ppoint, Some info, [||])

