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

namespace B2R2

open System.Runtime.InteropServices

/// Raised when two RegisterSets with two distinct tags operate.
exception TagMismatchException

/// A tag used in RegisterSet for identifying distinct set of registers for
/// different ISAs.
type RegisterSetTag =
  | Empty = 0
  | Intel = 1
  | ARM32 = 2
  | ARM64 = 3
  | MIPS = 4
  | EVM = 5
  | TMS320C6000 = 6

/// RegisterSet is an efficient set data structure for managing a set of
/// registers.
[<AbstractClass>]
type RegisterSet () =
  /// Tag identifies ISA.
  abstract member Tag       : RegisterSetTag

  /// Create a new RegisterSet. This method should be overridden by ISA-specific
  /// RegisterSet implementation.
  abstract member New       : uint64 [] -> Set<RegisterID> -> RegisterSet

  /// Obtain an integer from a given RegisterID.
  abstract member Project   : RegisterID -> int

  /// Return an empty RegisterSet.
  abstract member Empty     : RegisterSet

  /// Size of the internal array.
  abstract member ArrSize   : int

  /// An empty array representing an empty set of registers. This array should
  /// be initialized based on the ArrSize.
  abstract member EmptyArr  : uint64 []

  /// An internal array storing the register set.
  abstract member BitArray  : uint64 []

  /// A backup storage for unknown variables, which does not have an unknown
  /// RegisterID. For example, when writing a symbolic executor, we may
  /// encounter unknown variables, i.e., fresh symbolic variables. We store them
  /// in this set.
  abstract member S         : Set<RegisterID>

  /// Add a register to the set.
  abstract member Add       : RegisterID -> RegisterSet

  /// Remove a register from the set.
  abstract member Remove    : RegisterID -> RegisterSet

  /// Union of two register sets.
  abstract member Union     : RegisterSet -> RegisterSet

  /// Intersection of two register sets.
  abstract member Intersect : RegisterSet -> RegisterSet

  /// Check if a register exists in the set.
  abstract member Exists    : RegisterID -> bool

  /// Check if the set is empty.
  abstract member IsEmpty   : unit -> bool

[<AbstractClass>]
type NonEmptyRegisterSet (bitArray: uint64 [], s: Set<RegisterID>) =
  inherit RegisterSet ()

  member __.CheckTag (o: RegisterSet) =
    if __.Tag = o.Tag then () else raise TagMismatchException

  (* Get Buckets and Index *)
  static member inline GetBI (x, [<Out>] index: int byref) =
    index <- x &&& 0x3F; x / 64

  override __.BitArray = bitArray
  override  __.S = s
  override __.Remove id =
    match __.Project id with
    | -1 -> __.New __.EmptyArr (Set.remove id s)
    | id ->
      let bucket, index = NonEmptyRegisterSet.GetBI id
      let newArr = Array.copy bitArray
      newArr.[bucket] <- newArr.[bucket] &&& ~~~(1UL <<< index)
      __.New newArr Set.empty

  override __.Add id =
    match __.Project id with
    | -1 -> __.New __.EmptyArr (Set.add id s)
    | id ->
      let bucket, index = NonEmptyRegisterSet.GetBI id
      let newArr = Array.copy bitArray
      newArr.[bucket] <- newArr.[bucket] ||| (1UL <<< index)
      __.New newArr s

  override __.Union (other: RegisterSet) =
    if other.Tag = RegisterSetTag.Empty then __ :> RegisterSet
    else
      __.CheckTag other
      let newArr = Array.copy bitArray
      let otherArr = other.BitArray
      for i = 0 to __.ArrSize - 1 do newArr.[i] <- newArr.[i] ||| otherArr.[i]
      __.New newArr <| Set.union __.S other.S

  override __.Intersect (other: RegisterSet) =
    if other.Tag = RegisterSetTag.Empty then __.Empty
    else
      __.CheckTag other
      let newArr = Array.copy bitArray
      let otherArr = other.BitArray
      for i = 0 to __.ArrSize - 1 do newArr.[i] <- newArr.[i] &&& otherArr.[i]
      __.New newArr <| Set.union __.S other.S

  override  __.Exists id =
    match __.Project id with
    | -1 -> Set.contains id __.S
    | id ->
      let bucket, index = NonEmptyRegisterSet.GetBI id
      bitArray.[bucket] &&& (1UL <<< index) <> 0UL

  override __.IsEmpty () =
    (Array.exists (fun x -> x <> 0UL) bitArray |> not) && Set.isEmpty __.S

type EmptyRegisterSet () =
  inherit RegisterSet ()
  static member Instance = EmptyRegisterSet () :> RegisterSet
  override __.Tag = RegisterSetTag.Empty
  override __.ArrSize = 0
  override __.New _ _ = invalidOp "Cannot call EmptyRegisterSet.New"
  override __.Project _ = invalidOp "Cannot call EmptyRegisterSet.Project"
  override __.Empty = EmptyRegisterSet.Instance
  override __.EmptyArr = [||]
  override __.BitArray = [||]
  override __.S = Set.empty
  override __.Add _ = invalidOp "Cannot call EmptyRegisterSet.Add"
  override __.Remove _ = __ :> RegisterSet
  override __.Union o = o
  override __.Intersect o = o.Empty
  override __.Exists _ = false
  override __.IsEmpty () = true

/// A helper module for building a RegisterSet.
module RegisterSetBuilder =
  let inline singletonBuilder (s: RegisterSet) =
    let impl id =
      match s.Project id with
      | -1 -> s.New s.EmptyArr (Set.singleton id)
      | id ->
        let bucket, index = NonEmptyRegisterSet.GetBI id
        let newArr = Array.init s.ArrSize (fun _ -> 0UL)
        newArr.[bucket] <- newArr.[bucket] ||| (1UL <<< index)
        s.New newArr Set.empty
    impl
