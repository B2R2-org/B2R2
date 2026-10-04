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

namespace B2R2.Collections

open System.Numerics
open System.Runtime.CompilerServices
open System.Runtime.InteropServices
open System.Threading

/// The shape of a WeakInternTable.
[<RequireQualifiedAccess>]
module private InternTableShape =
  /// How many bits of a mixed hash pick the stripe it falls into.
  [<Literal>]
  let StripeBits = 4

  /// How many slots a stripe has at the fewest.
  [<Literal>]
  let MinCapacity = 16

/// One lock's share of a WeakInternTable: an open-addressing table of weak
/// handles to the values interned in it, each beside the hash it was interned
/// under, probed linearly from the slot the hash picks. A handle whose value
/// has been collected stays in its slot, passed over by every probe, until
/// the stripe is next laid out again. A search goes through Candidate, Next
/// and Add, between Enter and Exit; none of them knows the key, so the code
/// specialized for each type of key is only the loop that runs them.
[<Sealed>]
type private InternStripe<'T when 'T: not struct>() =
  let mutable hashes = Array.zeroCreate<int> InternTableShape.MinCapacity

  let mutable handles = Array.zeroCreate<GCHandle> InternTableShape.MinCapacity

  /// How far a mixed hash, its stripe bits shifted out, is shifted down to
  /// pick a slot.
  let mutable shift = 32 - BitOperations.Log2(uint32 handles.Length)

  /// How many slots hold a handle, whether its value is still alive or not.
  let mutable used = 0

  let gate = Lock()

  let slotOf (mixed: uint32) =
    int ((mixed <<< InternTableShape.StripeBits) >>> shift)

  /// Puts a handle into the first empty slot from the one its hash picks.
  let place hash (handle: GCHandle) =
    let mask = handles.Length - 1
    let mutable i = slotOf (uint32 hash * 0x9E3779B9u)
    while handles[i].IsAllocated do i <- (i + 1) &&& mask
    hashes[i] <- hash
    handles[i] <- handle

  /// Frees the handles of collected values and counts the rest.
  let dropCollected (old: GCHandle[]) =
    let mutable live = 0
    for i in 0 .. old.Length - 1 do
      if not old[i].IsAllocated then
        ()
      elif isNull old[i].Target then
        old[i].Free()
        old[i] <- GCHandle()
      else
        live <- live + 1
    live

  /// Drops the handles of collected values and lays the rest out again, in
  /// about twice the slots they need: a stripe grows, and shrinks, with what
  /// it holds, so the cost of laying it out is spread over the values added
  /// since it last was.
  let relayout () =
    let oldHashes, oldHandles = hashes, handles
    let live = dropCollected oldHandles
    let wanted = uint32 (max InternTableShape.MinCapacity (live * 2))
    let capacity = int (BitOperations.RoundUpToPowerOf2 wanted)
    hashes <- Array.zeroCreate capacity
    handles <- Array.zeroCreate capacity
    shift <- 32 - BitOperations.Log2(uint32 capacity)
    used <- live
    for i in 0 .. oldHandles.Length - 1 do
      if oldHandles[i].IsAllocated then place oldHashes[i] oldHandles[i] else ()

  let freeAll () =
    for i in 0 .. handles.Length - 1 do
      if handles[i].IsAllocated then handles[i].Free() else ()

  /// How many slots hold a handle, whether its value is still alive or not.
  member _.Count = Volatile.Read &used

  /// Takes the stripe's lock, which a search holds throughout.
  member _.Enter() = gate.Enter()

  /// Releases the stripe's lock.
  member _.Exit() = gate.Exit()

  /// The slot a search for a mixed hash starts at.
  member _.SlotOf(mixed: uint32) = slotOf mixed

  /// The slot after slot i.
  member _.Next(i) = (i + 1) &&& (handles.Length - 1)

  /// The live value in the first slot from slot i on that holds one under
  /// hash, i moved to that slot; or null, i moved to the empty slot that ends
  /// the run, where a value made for hash goes.
  member _.Candidate(hash, i: byref<int>) =
    let mask = handles.Length - 1
    let mutable found = null
    while isNull found && handles[i].IsAllocated do
      if hashes[i] = hash then found <- handles[i].Target else ()
      if isNull found then i <- (i + 1) &&& mask else ()
    found

  /// Puts value, made for hash, into slot i, where a search for it ended,
  /// laying the stripe out again once three slots in four hold a handle. A
  /// probe compares hashes before it touches a handle, so the longer runs
  /// cost little next to the slots, twelve bytes each, that a sparser stripe
  /// would keep.
  member _.Add(value: 'T, hash, i) =
    hashes[i] <- hash
    handles[i] <- GCHandle.Alloc(value, GCHandleType.Weak)
    used <- used + 1
    if used * 4 > handles.Length * 3 then relayout () else ()
    value

  /// Drops the handles of collected values.
  member _.Compact() =
    gate.Enter()
    try relayout () finally gate.Exit()

  /// Drops every value.
  member _.Clear() =
    gate.Enter()
    try
      freeAll ()
      hashes <- Array.zeroCreate InternTableShape.MinCapacity
      handles <- Array.zeroCreate InternTableShape.MinCapacity
      shift <- 32 - BitOperations.Log2(uint32 handles.Length)
      used <- 0
    finally
      gate.Exit()

  override _.Finalize() = freeAll ()

/// Represents a thread-safe set of canonical values that does not keep them
/// alive. Intern looks a value up by an IInternKey and hands back the live
/// value the key describes, which the key makes when the table holds none.
/// Each value is held through a weak GC handle, so a value nothing else refers
/// to is collected as usual; the slot it leaves is passed over until the table
/// next grows or is compacted, and no lookup ever walks the whole table. The
/// table is split by hash into stripes, each behind a lock of its own, so that
/// threads interning at once seldom wait for each other.
[<Sealed>]
type WeakInternTable<'T when 'T: not struct>() =
  let stripes =
    Array.init (1 <<< InternTableShape.StripeBits) (fun _ -> InternStripe<'T>())

  /// Gets the number of values the table holds handles for. A value that has
  /// been collected is counted until its handle is dropped.
  member _.Count with get() = stripes |> Array.sumBy (fun s -> s.Count)

  /// Finds the live value <paramref name="key"/> describes, or makes it with
  /// the key and keeps it, under <paramref name="hash"/>. Keys that describe
  /// one value must come with one hash. Only values of type 'T are ever put
  /// in, so a candidate needs no type test.
  member _.Intern(key: inref<#IInternKey<'T>>, hash) =
    let mixed = uint32 hash * 0x9E3779B9u
    let stripe = stripes[int (mixed >>> (32 - InternTableShape.StripeBits))]
    stripe.Enter()
    try
      let mutable i = stripe.SlotOf mixed
      let mutable c = stripe.Candidate(hash, &i)
      while not (isNull c) && not (key.Matches(Unsafe.As<'T> c)) do
        i <- stripe.Next i
        c <- stripe.Candidate(hash, &i)
      if isNull c then stripe.Add(key.Create hash, hash, i) else Unsafe.As<'T> c
    finally
      stripe.Exit()

  /// Drops the handles of the values that have been collected.
  member _.Compact() =
    for stripe in stripes do stripe.Compact()

  /// Removes every value from the table.
  member _.Clear() =
    for stripe in stripes do stripe.Clear()
