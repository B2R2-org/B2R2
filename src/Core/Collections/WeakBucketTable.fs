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

open System
open System.Collections.Concurrent
open System.Threading

type private Bucket<'T when 'T: not struct>() =
  let entries = ResizeArray<WeakReference<'T>>()
  let gate = Object()

  member _.Entries = entries

  member _.Gate = gate

/// Represents a thread-safe weak interning table. Values are grouped by a
/// caller-supplied hash, and each bucket stores only weak references to the
/// interned values.
type WeakBucketTable<'T when 'T: not struct>
  public(equals: 'T -> 'T -> bool,
         initialize: 'T -> int -> unit,
         ?cleanupThreshold: int) =
  let buckets = ConcurrentDictionary<int, Bucket<'T>>()
  let cleanupThreshold = defaultArg cleanupThreshold 1024
  let cleanupGate = Object()
  let tableLock = new ReaderWriterLockSlim()
  let mutable entries = 0
  let mutable nextCleanup = cleanupThreshold

  do
    if cleanupThreshold <= 0 then
      invalidArg (nameof cleanupThreshold) "cleanupThreshold must be positive"
    else
      ()

  /// Gets the number of weak references currently stored in the table. Dead
  /// references may be included until a cleanup runs.
  member _.Count with get() = Volatile.Read(&entries)

  /// Gets the number of hash buckets currently stored in the table.
  member _.BucketCount with get() = buckets.Count

  member inline private _.Prune(bucket: Bucket<'T>) =
    let entries = bucket.Entries
    let mutable removed = 0
    for i = entries.Count - 1 downto 0 do
      match entries[i].TryGetTarget() with
      | true, _ -> ()
      | false, _ ->
        entries.RemoveAt i
        removed <- removed + 1
    removed

  member private this.SweepBucket(bucket: Bucket<'T>) =
    lock bucket.Gate (fun () -> this.Prune bucket)

  member private this.SweepIfNeeded() =
    if Volatile.Read(&entries) >= Volatile.Read(&nextCleanup) then
      lock cleanupGate (fun () ->
        if Volatile.Read(&entries) >= Volatile.Read(&nextCleanup) then
          this.Sweep()
          Volatile.Write(&nextCleanup,
                         Volatile.Read(&entries) + cleanupThreshold)
        else
          ())
    else
      ()

  /// Removes dead weak references from every bucket.
  member this.Sweep() =
    tableLock.EnterReadLock()
    try
      let mutable removed = 0
      for bucket in buckets.Values do
        removed <- removed + this.SweepBucket bucket
      if removed > 0 then Interlocked.Add(&entries, -removed) |> ignore else ()
    finally
      tableLock.ExitReadLock()

  /// Finds the live canonical value equal to <paramref name="value"/>, or
  /// initializes and inserts <paramref name="value"/> when none exists.
  member this.Intern(value: 'T, hash: int) =
    tableLock.EnterReadLock()
    try
      let bucket = buckets.GetOrAdd(hash, fun _ -> Bucket<'T>())
      lock bucket.Gate (fun () ->
        let mutable found = Unchecked.defaultof<'T>
        let mutable hasFound = false
        let mutable hasDead = false
        let bucketEntries = bucket.Entries
        let mutable i = 0
        while i < bucketEntries.Count && not hasFound do
          match bucketEntries[i].TryGetTarget() with
          | true, target when equals target value ->
            found <- target
            hasFound <- true
          | true, _ ->
            i <- i + 1
          | false, _ ->
            hasDead <- true
            i <- i + 1
        if hasFound then found
        else
          if hasDead || bucketEntries.Count >= cleanupThreshold then
            let removed = this.Prune bucket
            if removed > 0 then
              Interlocked.Add(&entries, -removed) |> ignore
            else
              ()
          else
            ()
          initialize value hash
          bucketEntries.Add(WeakReference<'T>(value))
          Interlocked.Increment(&entries) |> ignore
          value)
    finally
      tableLock.ExitReadLock()
    |> fun value ->
      this.SweepIfNeeded()
      value

  /// Removes all buckets and weak references from the table.
  member _.Clear() =
    tableLock.EnterWriteLock()
    try
      buckets.Clear()
      Volatile.Write(&entries, 0)
      Volatile.Write(&nextCleanup, cleanupThreshold)
    finally
      tableLock.ExitWriteLock()
