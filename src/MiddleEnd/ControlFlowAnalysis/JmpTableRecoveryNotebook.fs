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

/// Represents a global collection of jump table recovery notes. This is not
/// thread-safe, so it should be accessed only by TaskManager.
type JmpTableRecoveryNotebook() =
  let notes = SortedList<Addr, JmpTableRecoveryNote>()

  /// Starting points of the notes whose tables do not start there, which we
  /// call phantoms. We keep their notes for the functions still recovering
  /// them, but no table starts at a phantom, and none is cut short at one.
  let phantoms = HashSet<Addr>()

  let findOverlap addr =
    notes.Values
    |> Seq.tryFind (fun note ->
      note.StartingPoint <= addr && addr <= note.PotentialEndPoint)

  let updatePotentialEndPoint note newPoint =
    if note.PotentialEndPoint > newPoint then note.PotentialEndPoint <- newPoint
    else ()

  let syncConfirmedEndPoint note newPoint =
    if note.ConfirmedEndPoint > newPoint then note.ConfirmedEndPoint <- newPoint
    else ()

  /// Computes where the entries that the range check of the table of the given
  /// note admits end, if the table has a range check of its own.
  let tryGetHeldEnd note =
    note.OwnRangeEntries
    |> Option.map (fun n -> note.StartingPoint + uint64 (n * note.EntrySize))

  let markPhantom note =
    phantoms.Add note.StartingPoint |> ignore
    updatePotentialEndPoint note note.StartingPoint
    syncConfirmedEndPoint note note.StartingPoint

  /// Marks the notes that start after addr and before heldEnd as phantoms, and
  /// returns them, if their tables have no range check of their own. A table
  /// that has one starts where it does, so its note ends the search, unless it
  /// is a phantom already.
  let rec markPhantomsWithin heldEnd addr acc =
    match SortedList.tryFindNextKey addr notes with
    | Some key when key < heldEnd ->
      let note = notes[key]
      match note.OwnRangeEntries with
      | None ->
        markPhantom note
        markPhantomsWithin heldEnd key (note :: acc)
      | Some _ when phantoms.Contains key ->
        markPhantomsWithin heldEnd key acc
      | Some _ ->
        acc
    | _ ->
      acc

  let rec tryFindPreviousLiveKey addr =
    match SortedList.tryFindPreviousKey addr notes with
    | Some key when phantoms.Contains key -> tryFindPreviousLiveKey key
    | key -> key

  let rec tryFindNextLiveKey addr =
    match SortedList.tryFindNextKey addr notes with
    | Some key when phantoms.Contains key -> tryFindNextLiveKey key
    | key -> key

  let syncAfterRegistration tblAddr note =
    let sz = uint64 note.EntrySize
    match tryFindPreviousLiveKey tblAddr with
    | Some lb -> updatePotentialEndPoint notes[lb] (note.StartingPoint - sz)
    | None -> ()
    match tryFindNextLiveKey tblAddr with
    | Some ub -> updatePotentialEndPoint note (ub - sz)
    | None -> ()

  let registerAnew fnAddr jmptbl =
    let tblAddr = jmptbl.TableAddress
    let potentialEndPoint =
      if jmptbl.IsSingleEntry then tblAddr else System.UInt64.MaxValue
    let note =
      { HostFunctionAddr = fnAddr
        InsAddr = jmptbl.InsAddr
        BaseAddr = jmptbl.JumpBase
        EntrySize = jmptbl.EntrySize
        StartingPoint = tblAddr
        ConfirmedEndPoint = tblAddr
        PotentialEndPoint = potentialEndPoint
        OwnRangeEntries = jmptbl.OwnRangeEntries
        WaitingFunctions = HashSet() }
    notes[tblAddr] <- note
    let phantomNotes =
      match tryGetHeldEnd note with
      | Some heldEnd -> markPhantomsWithin heldEnd tblAddr []
      | None -> []
    syncAfterRegistration tblAddr note
    if List.isEmpty phantomNotes then RegistrationSucceeded
    else RegisteredOverPhantoms phantomNotes

  /// Creates a new note for a newly found jump table, and returns it. When we
  /// detect overlapping jump tables, we return the problematic jump table note,
  /// which should be reverted.
  member _.Register(fnAddr, jmptbl) =
    let tblAddr = jmptbl.TableAddress
    if phantoms.Contains tblAddr then
      PhantomStart
    elif notes.ContainsKey tblAddr then
      (* Duplicate registeration is possible due to rollback. *)
      let note = notes[tblAddr]
      match note.HostFunctionAddr = fnAddr, note.InsAddr = jmptbl.InsAddr with
      | true, true -> RegistrationSucceeded
      | true, false -> SharedByInstructions
      | false, _ -> SharedByFunctions note.HostFunctionAddr
    else
      match findOverlap tblAddr with
      | Some note ->
        OverlappingNote note (* Return the overlapping note. *)
      | None ->
        registerAnew fnAddr jmptbl

  /// Finds where the entries that the range check of the table before the
  /// given one admits end, if the given table starts within them, past the
  /// first, without a range check of its own. Such a table does not start
  /// where its code computes it to: the computation has folded the smallest
  /// index into the address of the table.
  member _.TryFindHeldEnd(jmptbl: JmpTableInfo) =
    let tblAddr = jmptbl.TableAddress
    match jmptbl.OwnRangeEntries, tryFindPreviousLiveKey tblAddr with
    | None, Some key ->
      tryGetHeldEnd notes[key]
      |> Option.filter (fun heldEnd -> tblAddr < heldEnd)
    | _ ->
      None

  /// Marks the given jump table as a phantom, since its first entry has turned
  /// out not to be one.
  member _.MarkPhantom tblAddr = markPhantom notes[tblAddr]

  /// Unregisters the given jump table note associated with the given function
  /// address. This means, we later found out that the jump table is really not
  /// a jump table.
  member _.Unregister(tblAddr, fnAddr) =
    match notes.TryGetValue tblAddr with
    | true, note when note.HostFunctionAddr = fnAddr ->
      notes.Remove tblAddr |> ignore
      phantoms.Remove tblAddr |> ignore
      note.WaitingFunctions |> Seq.toArray
    | _ ->
      Array.empty

  /// Records another function that recovers the same jump table without owning
  /// its global recovery note.
  member _.AddWaitingFunction(tblAddr, fnAddr) =
    notes[tblAddr].WaitingFunctions.Add(fnAddr) |> ignore

  /// Checks if the given index is expandable within the jump table.
  member _.IsExpandable(tblAddr, idx) =
    let note = notes[tblAddr]
    let target = note.StartingPoint + (uint64 idx * uint64 note.EntrySize)
    target <= note.PotentialEndPoint

  /// Gets the confirmed end point of the jump table.
  member _.GetConfirmedEndPoint tblAddr = notes[tblAddr].ConfirmedEndPoint

  /// Sets the confirmed end point of the jump table.
  member _.SetConfirmedEndPoint(tblAddr, idx) =
    let note = notes[tblAddr]
    let newEndPoint = note.StartingPoint + uint64 (idx * note.EntrySize)
    note.ConfirmedEndPoint <- newEndPoint

  /// Gets the potential end point of the jump table.
  member _.GetPotentialEndPointIndex tblAddr =
    let note = notes[tblAddr]
    int (note.PotentialEndPoint - note.StartingPoint) / note.EntrySize

  /// Sets the potential end point of the jump table by giving the currently
  /// confirmed index.
  member _.SetPotentialEndPointByIndex(tblAddr, confirmedIdx) =
    let note = notes[tblAddr]
    let newPoint = note.StartingPoint + uint64 (confirmedIdx * note.EntrySize)
    updatePotentialEndPoint note newPoint
    syncConfirmedEndPoint note newPoint

  /// Sets the potential end point of the jump table by giving the currently
  /// confirmed address.
  member _.SetPotentialEndPointByAddr(tblAddr, confirmedAddr) =
    updatePotentialEndPoint notes[tblAddr] confirmedAddr
    syncConfirmedEndPoint notes[tblAddr] confirmedAddr

  /// Gets the indirect branch address that is associated with the given jump
  /// table address.
  member _.GetIndBranchAddress tblAddr = notes[tblAddr].InsAddr

  /// Gets the string representation of the note.
  member _.GetNoteString tblAddr =
    let n = notes[tblAddr]
    let confirmed = n.ConfirmedEndPoint
    $"{n.InsAddr:x} => {tblAddr:x}, {confirmed:x}, {n.PotentialEndPoint:x}"

/// Represents the result of jump table registration.
and [<Struct>] JmpTableRegistrationResult =
  /// Registration has succeeded.
  | RegistrationSucceeded
  /// Registration has succeeded, but the entries that the range check of the
  /// table admits hold the starts of other tables, which have no range check
  /// of their own. We mark those as phantoms and return their notes.
  | RegisteredOverPhantoms of phantoms: JmpTableRecoveryNote list
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
  /// Registration has failed because the table starts at a phantom.
  | PhantomStart

/// Represents a note (or a recovery state) for jump table recovery.
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
    mutable PotentialEndPoint: Addr
    /// The number of entries, from the first, that the range check of the
    /// jump table admits, or None if no check of its own bounds the table.
    OwnRangeEntries: int option
    /// Functions that recover this table while another function owns its note.
    WaitingFunctions: HashSet<Addr> }
