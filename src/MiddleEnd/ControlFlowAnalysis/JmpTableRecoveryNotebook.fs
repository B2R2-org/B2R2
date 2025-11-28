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
open B2R2.Collections

/// Global collection of jump table recovery notes. This is not thread-safe, so
/// it should be accessed only by TaskManager.
type JmpTableRecoveryNotebook() =
  let notes = SortedList<Addr, JmpTableRecoveryNote>()

  let findOverlap addr =
    notes.Values
    |> Seq.tryFind (fun note ->
      note.StartingPoint <= addr && addr <= note.PotentialEndPoint)

  let updatePotentialEndPoint note newPoint =
    if note.PotentialEndPoint > newPoint then
      note.PotentialEndPoint <- newPoint
    else ()

  let syncConfirmedEndPoint note newPoint =
    if note.ConfirmedEndPoint > newPoint then note.ConfirmedEndPoint <- newPoint
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
  member _.Register(fnAddr, jmptbl) =
    let tblAddr = jmptbl.TableAddress
    if notes.ContainsKey tblAddr then
      (* Duplicate registeration is possible due to rollback. *)
      let note = notes[tblAddr]
      match note.HostFunctionAddr = fnAddr, note.InsAddr = jmptbl.InsAddr with
      | true, true -> RegistrationSucceeded
      | true, false -> SharedByInstructions
      | false, _ -> SharedByFunctions note.HostFunctionAddr
    else
      match findOverlap tblAddr with
      | Some note -> OverlappingNote note (* Return the overlapping note. *)
      | None ->
        let potentialEndPoint =
          if jmptbl.IsSingleEntry then tblAddr
          else System.UInt64.MaxValue
        let note =
          { HostFunctionAddr = fnAddr
            InsAddr = jmptbl.InsAddr
            BaseAddr = jmptbl.JumpBase
            EntrySize = jmptbl.EntrySize
            StartingPoint = tblAddr
            ConfirmedEndPoint = tblAddr
            PotentialEndPoint = potentialEndPoint }
        notes[tblAddr] <- note
        syncAfterRegistration tblAddr note
        RegistrationSucceeded

  /// Unregister the given jump table note associated with the given function
  /// address. This means, we later found out that the jump table is really not
  /// a jump table.
  member _.Unregister(tblAddr, fnAddr) =
    match notes.TryGetValue tblAddr with
    | true, note when note.HostFunctionAddr = fnAddr ->
      notes.Remove tblAddr |> ignore
    | _ -> ()

  /// Check if the given index is expandable within the jump table.
  member _.IsExpandable(tblAddr, idx) =
    let note = notes[tblAddr]
    let target = note.StartingPoint + (uint64 idx * uint64 note.EntrySize)
    target <= note.PotentialEndPoint

  /// Get the confirmed end point of the jump table.
  member _.GetConfirmedEndPoint tblAddr =
    notes[tblAddr].ConfirmedEndPoint

  /// Set the confirmed end point of the jump table.
  member _.SetConfirmedEndPoint(tblAddr, idx) =
    let note = notes[tblAddr]
    let newEndPoint = note.StartingPoint + uint64 (idx * note.EntrySize)
    note.ConfirmedEndPoint <- newEndPoint

  /// Get the potential end point of the jump table.
  member _.GetPotentialEndPointIndex tblAddr =
    let note = notes[tblAddr]
    int (note.PotentialEndPoint - note.StartingPoint) / note.EntrySize

  /// Set the potential end point of the jump table by giving the currently
  /// confirmed index.
  member _.SetPotentialEndPointByIndex(tblAddr, confirmedIdx) =
    let note = notes[tblAddr]
    let newPoint = note.StartingPoint + uint64 (confirmedIdx * note.EntrySize)
    updatePotentialEndPoint note newPoint
    syncConfirmedEndPoint note newPoint

  /// Set the potential end point of the jump table by giving the currently
  /// confirmed address.
  member _.SetPotentialEndPointByAddr(tblAddr, confirmedAddr) =
    updatePotentialEndPoint notes[tblAddr] confirmedAddr
    syncConfirmedEndPoint notes[tblAddr] confirmedAddr

  /// Get the indirect branch address that is associated with the given jump
  /// table address.
  member _.GetIndBranchAddress tblAddr =
    notes[tblAddr].InsAddr

  /// Get the string representation of the note.
  member _.GetNoteString tblAddr =
    let n = notes[tblAddr]
    let confirmed = n.ConfirmedEndPoint
    $"{n.InsAddr:x} => {tblAddr:x}, {confirmed:x}, {n.PotentialEndPoint:x}"

/// The result of jump table registration.
and [<Struct>] JmpTableRegistrationResult =
  /// Registration has succeeded.
  | RegistrationSucceeded
  /// Registration has failed because there are two functions sharing the same
  /// table. We return the address of the function that previously registered
  /// the table.
  | SharedByFunctions of oldFnAddr: Addr
  /// Registration has failed because there are two different branches sharing
  /// the same table.
  | SharedByInstructions
  /// Registration has failed because there is an overlapping table. We return
  /// the address of the overlapping table.
  | OverlappingNote of note: JmpTableRecoveryNote

/// A note (or a recovery state) for jump table recovery.
and JmpTableRecoveryNote =
  { /// Address of the host function that contains the indirect
    /// jump instruction.
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
    mutable PotentialEndPoint: Addr }
