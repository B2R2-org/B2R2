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
type LowUIRBasicBlock internal (pp, funcAbs, liftedInss, lblMap) =
  /// Dominating jump table.
  let mutable domJT = None

  let isTerminatingStmt stmt =
    match stmt.S with
    | Jmp _ | CJmp _ | InterJmp _ | InterCJmp _
    | SideEffect SysCall
    | SideEffect Terminate
    | SideEffect (Interrupt _) -> true
    | _ -> false

  /// Return the `ILowUIRBasicBlock` interface to access the internal
  /// representation of the basic block.
  member inline __.Internals with get() = __ :> ILowUIRBasicBlock

  /// Intra-instruction label information, which is a mapping from a label to
  /// the corresponding program point.
  member __.LabelMap
    with get(): ImmutableDictionary<Symbol, ProgramPoint> = lblMap

  /// Dominating jump table entry (tbl address and index) is a jump table entry
  /// that dominates this basic block. In other words, this basic block is
  /// dominated by the indirect jump instruction that uses this jump table
  /// entry. This property is None if there's no such dominating jump table
  /// entry.
  member __.DominatingJumpTableEntry
    with get(): (Addr * int) option = domJT
     and set(v) = domJT <- v

  /// Cut the basic block at the given address and return the two new basic
  /// blocks. This function does not modify the original basic block. We assume
  /// that the given address is within the range of the basic block. Otherwise,
  /// this function will raise an exception.
  member __.Cut (cutPoint: Addr) =
    if isNull funcAbs then
      assert ((__ :> IAddressable).Range.IsIncluding cutPoint)
      let fstInstrs, sndInstrs =
        liftedInss
        |> Array.partition (fun ins -> ins.Original.Address < cutPoint)
      let sndInstrs =
        sndInstrs |> Array.map (fun ins -> { ins with BBLAddr = cutPoint })
      let cutPPoint = ProgramPoint (cutPoint, 0)
      let fstLabelMap = ImmutableDictionary.CreateRange [||]
      let sndLabelMap = ImmutableDictionary.CreateRange (Seq.toArray lblMap)
      LowUIRBasicBlock.CreateRegular (fstInstrs, pp, fstLabelMap),
      LowUIRBasicBlock.CreateRegular (sndInstrs, cutPPoint, sndLabelMap)
    else raise AbstractBlockAccessException

  override _.ToString () = $"{nameof LowUIRBasicBlock}({pp})"

  interface ILowUIRBasicBlock with
    member _.PPoint with get() = pp

    member _.Range with get() =
      if isNull funcAbs then
        let lastIns = liftedInss[liftedInss.Length - 1].Original
        let lastAddr = lastIns.Address + uint64 lastIns.Length
        AddrRange (pp.Address, lastAddr - 1UL)
      else raise AbstractBlockAccessException

    member _.IsAbstract with get() = not (isNull funcAbs)

    member _.AbstractContent with get() =
      if isNull funcAbs then raise AbstractBlockAccessException
      else funcAbs

    member _.LiftedInstructions with get() = liftedInss

    /// Terminator statement of the basic block.
    member _.Terminator with get() =
      assert (not <| Array.isEmpty liftedInss)
      let stmts = liftedInss[liftedInss.Length - 1].Stmts
      stmts[stmts.Length - 2..]
      |> Array.filter isTerminatingStmt
      |> Array.tryExactlyOne
      |> Option.defaultValue stmts[stmts.Length - 1]

    member _.Instructions with get() =
      liftedInss |> Array.map (fun liftedIns -> liftedIns.Original)

    member _.LastInstruction with get() =
      assert (not <| Array.isEmpty liftedInss)
      liftedInss[liftedInss.Length - 1].Original

    member _.Disassemblies with get() =
      liftedInss
      |> Array.map (fun liftedIns -> liftedIns.Original.Disasm ())

    member _.BlockAddress with get() = pp.Address

    member _.Visualize () =
      if isNull funcAbs then
        liftedInss
        |> Array.collect (fun liftedIns -> liftedIns.Stmts)
        |> Array.map (fun stmt ->
          [| { AsmWordKind = AsmWordKind.String
               AsmWordValue = Pp.stmtToString stmt } |])
      else [||]

  interface IEquatable<LowUIRBasicBlock> with
    member __.Equals (other: LowUIRBasicBlock) =
      (__ :> IAddressable).PPoint = (other :> IAddressable).PPoint

  static member CreateRegular (liftedInss, pp) =
    LowUIRBasicBlock (pp, null, liftedInss, ImmutableDictionary.Empty)

  static member CreateRegular (liftedInss, pp, lblMap) =
    LowUIRBasicBlock (pp, null, liftedInss, lblMap)

  static member CreateAbstract (pp, summary) =
    assert (not (isNull summary))
    LowUIRBasicBlock (pp, summary, [||], ImmutableDictionary.Empty)

/// Interface for a basic block containing a sequence of lifted LowUIR
/// statements.
and ILowUIRBasicBlock =
  inherit IAddressable
  inherit IAbstractable<LowUIR.Stmt>
  inherit ILowUIRAccessible
  inherit IInstructionAccessible
  inherit IVisualizable
