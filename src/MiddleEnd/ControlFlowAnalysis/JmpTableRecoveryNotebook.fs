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

/// Global collection of jump table recovery notes. This is not thread-safe, so
/// it should be accessed only by TaskManager.
type JmpTableRecoveryNotebook () =
  let notes = SortedList<Addr, JmpTableRecoveryNote> ()

  let findOverlap addr =
    notes.Values
    |> Seq.tryFind (fun note ->
      note.StartingPoint <= addr && addr <= note.ConfirmedEndPoint)

  let updatePotentialEndPoint note newPoint =
    if note.PotentialEndPoint > newPoint then
      note.PotentialEndPoint <- newPoint
    else ()

  let syncAfterRegistration tblAddr note =
    let sz = uint64 note.EntrySize
    match SortedList.findGreatestLowerBoundKey tblAddr notes with
    | Some lb -> updatePotentialEndPoint notes[lb] (note.StartingPoint - sz)
    | None -> ()
    match SortedList.findLeastUpperBoundKey tblAddr notes with
    | Some ub -> updatePotentialEndPoint note (ub - sz)
    | None -> ()

  /// Create a new note for a newly found jump table, and return it. When we
  /// detect overlapping jump tables, we return the problematic jump table note,
  /// which should be reverted.
  member _.Register fnAddr jmptbl =
    let tblAddr = jmptbl.TableAddress
    if notes.ContainsKey tblAddr then
      (* Duplicate registeration is possible due to rollback in which case we
         simply reuse the existing note. *)
      Ok notes[tblAddr]
    else
      match findOverlap tblAddr with
      | Some note -> Error note
      | None ->
        let note = {
          HostFunctionAddr = fnAddr
          InsAddr = jmptbl.InsAddr
          BaseAddr = jmptbl.JumpBase
          EntrySize = RegType.toByteWidth jmptbl.EntrySize
          StartingPoint = tblAddr
          ConfirmedEndPoint = tblAddr
          PotentialEndPoint = System.UInt64.MaxValue }
        notes[tblAddr] <- note
        syncAfterRegistration tblAddr note
        Ok note

  /// Check if the given index is expandable within the jump table.
  member _.IsExpandable tblAddr idx =
    let note = notes[tblAddr]
    let target = note.StartingPoint + (uint64 idx * uint64 note.EntrySize)
    target <= note.PotentialEndPoint

  /// Get the confirmed end point of the jump table.
  member _.GetConfirmedEndPoint tblAddr =
    notes[tblAddr].ConfirmedEndPoint

  /// Set the confirmed end point of the jump table.
  member _.SetConfirmedEndPoint tblAddr idx =
    let note = notes[tblAddr]
    let newEndPoint = note.StartingPoint + uint64 (idx * note.EntrySize)
    note.ConfirmedEndPoint <- newEndPoint

  /// Set the potential end point of the jump table by giving the currently
  /// confirmed index.
  member _.SetPotentialEndPoint tblAddr confirmedIdx =
    let note = notes[tblAddr]
    let newPoint = note.StartingPoint + uint64 (confirmedIdx * note.EntrySize)
    updatePotentialEndPoint note newPoint

  /// Get the string representation of the note.
  member _.GetNoteString tblAddr =
    let n = notes[tblAddr]
    let confirmed = n.ConfirmedEndPoint
    $"{n.InsAddr:x} => {tblAddr:x}, {confirmed:x}, {n.PotentialEndPoint:x}"

/// A note (or a recovery state) for jump table recovery.
and JmpTableRecoveryNote = {
  /// Address of the host function that contains the indirect jump instruction.
  HostFunctionAddr: Addr
  /// Indirect jump instruction address.
  InsAddr: Addr
  /// Base address used to compute the final jump target.
  BaseAddr: Addr
  /// Jump table entry size.
  EntrySize: int
  /// Starting point of the jump table.
  StartingPoint: Addr
  /// Confirmed end point of the jump table. We use inclusive range.
  mutable ConfirmedEndPoint: Addr
  /// Potential end point (the upperbound) of the jump table. We use inclusive
  /// range.
  mutable PotentialEndPoint: Addr
}
