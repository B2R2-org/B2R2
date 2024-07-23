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

open System
open System.Collections.Immutable
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR
open B2R2.BinIR.LowUIR

/// Basic block type for IR-level CFGs.
type IRBasicBlock internal (ppoint, funcAbs, liftedInstrs, labelMap) =
  inherit PossiblyAbstractBasicBlock (ppoint, funcAbs)

  let isTerminatingStmt stmt =
    match stmt.S with
    | Jmp _ | CJmp _ | InterJmp _ | InterCJmp _
    | SideEffect SysCall
    | SideEffect Terminate
    | SideEffect (Interrupt _) -> true
    | _ -> false

  member __.LiftedInstructions with get(): LiftedInstruction[] = liftedInstrs

  member __.LastLiftedInstruction with get() =
    assert (not <| Array.isEmpty liftedInstrs)
    liftedInstrs[liftedInstrs.Length - 1]

  /// Last instruction in the basic block.
  member __.LastInstruction with get() =
    assert (not <| Array.isEmpty liftedInstrs)
    liftedInstrs[liftedInstrs.Length - 1].Original

  /// Terminator statement of the basic block.
  member __.Terminator with get() =
    assert (not <| Array.isEmpty liftedInstrs)
    let stmts = liftedInstrs[liftedInstrs.Length - 1].Stmts
    stmts[stmts.Length - 2..]
    |> Array.filter isTerminatingStmt
    |> Array.tryExactlyOne
    |> Option.defaultValue stmts[stmts.Length - 1]

  /// Intra-instruction label information, which is a mapping from a label to
  /// the corresponding program point.
  member __.LabelMap
    with get(): ImmutableDictionary<Symbol, ProgramPoint> = labelMap

  /// Cut the basic block at the given address and return the two new basic
  /// blocks. This function does not modify the original basic block. We assume
  /// that the given address is within the range of the basic block. Otherwise,
  /// this function will raise an exception.
  member __.Cut (cutPoint: Addr) =
    if isNull funcAbs then
      assert (__.Range.IsIncluding cutPoint)
      let fstInstrs, sndInstrs =
        liftedInstrs
        |> Array.partition (fun ins -> ins.Original.Address < cutPoint)
      let sndInstrs =
        sndInstrs |> Array.map (fun ins -> { ins with BBLAddr = cutPoint })
      let cutPPoint = ProgramPoint (cutPoint, 0)
      let fstLabelMap = ImmutableDictionary.CreateRange [||]
      let sndLabelMap = ImmutableDictionary.CreateRange (Seq.toArray labelMap)
      IRBasicBlock.CreateRegular (fstInstrs, ppoint, fstLabelMap),
      IRBasicBlock.CreateRegular (sndInstrs, cutPPoint, sndLabelMap)
    else raise AbstractBlockAccessException

  override __.Range with get() =
    if isNull funcAbs then
      let lastIns = liftedInstrs[liftedInstrs.Length - 1].Original
      let lastAddr = lastIns.Address + uint64 lastIns.Length
      AddrRange (ppoint.Address, lastAddr - 1UL)
    else raise AbstractBlockAccessException

  override __.Visualize () =
    if isNull funcAbs then
      liftedInstrs
      |> Array.collect (fun liftedIns -> liftedIns.Stmts)
      |> Array.map (fun stmt ->
        [| { AsmWordKind = AsmWordKind.String
             AsmWordValue = Pp.stmtToString stmt } |])
    else [||]

  interface IEquatable<IRBasicBlock> with
    member __.Equals (other: IRBasicBlock) =
      __.PPoint = other.PPoint

  static member CreateRegular (liftedInstrs, ppoint) =
    IRBasicBlock (ppoint, null, liftedInstrs, ImmutableDictionary.Empty)

  static member CreateRegular (liftedInstrs, ppoint, labelMap) =
    IRBasicBlock (ppoint, null, liftedInstrs, labelMap)

  static member CreateAbstract (ppoint, summary) =
    assert (not (isNull summary))
    IRBasicBlock (ppoint, summary, [||], ImmutableDictionary.Empty)

