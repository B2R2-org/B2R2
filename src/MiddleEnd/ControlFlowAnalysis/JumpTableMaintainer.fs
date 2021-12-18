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

open System.Collections.Generic
open B2R2

/// Indirect branch jump table information.
type JumpTable = {
  /// The address of the owner function of the indirect branch.
  HostFunctionEntry: Addr
  /// The indirect branch instruction address.
  InstructionAddr: Addr
  /// The base address used to compute the final target address.
  BranchBaseAddr: Addr
  /// Start address of the jump table, i.e., the first table entry's address.
  JTStartAddr: Addr
  /// Jump table's entry size. Typically this is 4-byte.
  JTEntrySize: int
}
with
  static member Init entry ins bAddr tAddr rt =
    { HostFunctionEntry = entry
      InstructionAddr = ins
      BranchBaseAddr = bAddr
      JTStartAddr = tAddr
      JTEntrySize = RegType.toByteWidth rt }

type JumpTableMaintainer () =
  let jumpTables = SortedList<Addr, JumpTable> ()
  let potentialEndPoints = Dictionary<Addr, Addr> ()
  let confirmedEndPoints = Dictionary<Addr, Addr> ()

  member private __.FindOverlappingJumpTable addr =
    jumpTables.Values
    |> Seq.tryFind (fun jt ->
      jt.JTStartAddr <= addr && addr < confirmedEndPoints[jt.JTStartAddr])

  /// Register a new jump table.
  member __.Register funcEntry insAddr bAddr tAddr rt =
    let jt = JumpTable.Init funcEntry insAddr bAddr tAddr rt
    if jumpTables.ContainsKey tAddr then
      (* We had another jump table at the exactly the same location earlier.
         This means our rollback mechanism removed some history, and we just
         encountered the same indirect branch again. In this case, we will just
         reuse it. *)
      Ok ()
    else
      confirmedEndPoints[tAddr] <- tAddr
      potentialEndPoints[tAddr] <- System.UInt64.MaxValue
      match __.FindOverlappingJumpTable tAddr with
      | Some jt -> Error jt
      | None ->
        match SortedList.findGreatestLowerBoundKey tAddr jumpTables with
        | Some lbAddr -> potentialEndPoints[lbAddr] <- tAddr
        | None -> ()
        match SortedList.findLeastUpperBoundKey tAddr jumpTables with
        | Some ubAddr -> potentialEndPoints[tAddr] <- ubAddr
        | None -> ()
        jumpTables[tAddr] <- jt
        Ok ()

  /// Update the potential end-point information.
  member __.UpdatePotentialEndPoint tAddr pAddr =
    potentialEndPoints[tAddr] <- pAddr

  /// Find the current potential end-point for the given table address.
  member __.FindPotentialEndPoint tAddr =
    potentialEndPoints[tAddr]

  /// Update the confirmed end-point of the jump table located at the tAddr.
  member __.UpdateConfirmedEndPoint tAddr epAddr =
    confirmedEndPoints[tAddr] <- epAddr

  /// Find the currently confirmed end-point for the given table address.
  member __.FindConfirmedEndPoint tAddr =
    confirmedEndPoints[tAddr]

  member __.Item
    with get(addr) = jumpTables[addr]
     and set addr jt = jumpTables[addr] <- jt

  member __.ToSeq () = jumpTables |> seq
