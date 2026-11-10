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

namespace B2R2.MiddleEnd.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Tests how the notebook treats a jump table whose code computes it to start
/// within the entries that the range check of the table before it admits, as
/// when the code folds the smallest index into the address of the table. The
/// functions recovering the tables can register them in either order.
[<TestClass>]
type JmpTableRecoveryNotebookTests() =
  /// Builds a table of four-byte entries at the given address, whose range
  /// check admits the given number of entries from the first, if it has one.
  let table insAddr tblAddr ownRange =
    { InsAddr = insAddr
      JumpBase = 0UL
      TableAddress = tblAddr
      EntrySize = 4
      EntryShift = 0
      IsSignedEntry = true
      NumEntries = 0
      WaitingInstructions = []
      IsSingleEntry = false
      OwnRangeEntries = ownRange
      MaskedEntries = None
      IsFunctionPointerTable = false }

  (* Eight entries, the last four of which are where the folded table is
     computed to start, four entries before it really does. *)
  let holder = table 0x1010UL 0x400118UL (Some 8)

  let folded = table 0x2010UL 0x400128UL None

  [<TestMethod>]
  member _.``Notebook moves a table that starts within a registered one``() =
    let notes = JmpTableRecoveryNotebook()
    notes.Register(0x1000UL, holder) |> ignore
    Assert.AreEqual<Addr option>(Some 0x400138UL, notes.TryFindHeldEnd folded)

  [<TestMethod>]
  member _.``Notebook caps the end index of an unbounded table``() =
    let notes = JmpTableRecoveryNotebook()
    notes.Register(0x2000UL, folded) |> ignore
    let idx = notes.GetPotentialEndPointIndex folded.TableAddress
    Assert.AreEqual<int>(System.Int32.MaxValue, idx)

  [<TestMethod>]
  member _.``Notebook keeps a table that starts after a registered one``() =
    let notes = JmpTableRecoveryNotebook()
    notes.Register(0x1000UL, holder) |> ignore
    let next = table 0x2010UL 0x400138UL None
    Assert.AreEqual<Addr option>(None, notes.TryFindHeldEnd next)

  [<TestMethod>]
  member _.``Notebook keeps a table that checks its own range``() =
    let notes = JmpTableRecoveryNotebook()
    notes.Register(0x1000UL, holder) |> ignore
    let checking = { folded with OwnRangeEntries = Some 6 }
    Assert.AreEqual<Addr option>(None, notes.TryFindHeldEnd checking)

  [<TestMethod>]
  member _.``Notebook marks a table registered before its holder``() =
    let notes = JmpTableRecoveryNotebook()
    notes.Register(0x2000UL, folded) |> ignore
    match notes.Register(0x1000UL, holder) with
    | RegisteredOverPhantoms [ phantom ] ->
      Assert.AreEqual<Addr>(0x2000UL, phantom.HostFunctionAddr)
    | result ->
      Assert.Fail $"{result}"
    Assert.AreEqual<bool>(false, notes.IsExpandable(folded.TableAddress, 1))
    Assert.AreEqual<bool>(true, notes.IsExpandable(holder.TableAddress, 7))
    Assert.AreEqual<Addr option>(Some 0x400138UL, notes.TryFindHeldEnd folded)

  (* GCC on ARM may lay a table of halfwords right after a table of bytes, so
     the table before ends at its own last byte, one byte before the next
     table starts, rather than one halfword before. The overlap is resolved as
     the coordinator does, by ending the table before the next one. *)
  [<TestMethod>]
  member _.``Notebook ends a table of bytes right before one of halfwords``() =
    let notes = JmpTableRecoveryNotebook()
    let bytes = { table 0x1010UL 0x400100UL (Some 14) with EntrySize = 1 }
    let halves = { table 0x1020UL 0x40010eUL (Some 4) with EntrySize = 2 }
    notes.Register(0x1000UL, bytes) |> ignore
    match notes.Register(0x1000UL, halves) with
    | OverlappingNote note ->
      notes.EndBefore(note.StartingPoint, halves.TableAddress) |> ignore
    | result ->
      Assert.Fail $"{result}"
    notes.Register(0x1000UL, halves) |> ignore
    let idx = notes.GetPotentialEndPointIndex bytes.TableAddress
    Assert.AreEqual<int>(13, idx)

  [<TestMethod>]
  member _.``Notebook refuses a table that starts at a phantom``() =
    let notes = JmpTableRecoveryNotebook()
    notes.Register(0x2000UL, folded) |> ignore
    notes.MarkPhantom folded.TableAddress
    let result = notes.Register(0x2000UL, folded)
    Assert.AreEqual<JmpTableRegistrationResult>(PhantomStart, result)
