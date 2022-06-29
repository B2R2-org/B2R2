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

/// Raised when two RegisterSets with two distinct tags operate.
exception RegisterSetTagMismatchException

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
  | CIL = 7
  | AVR = 8
  | SH4 = 9
  | PPC32 = 10
  | Sparc64 = 11
  | RISCV64 = 12
  | WASM = 20

/// RegisterSet is an efficient set data structure using arrays for managing a
/// set of registers.
[<AbstractClass>]
type RegisterSet () =
  /// Tag identifies ISA.
  abstract member Tag: RegisterSetTag

  /// Create a new RegisterSet from a given array and a set. This method should
  /// be overridden by ISA-specific RegisterSet implementation.
  abstract member New: uint64 [] -> Set<RegisterID> -> RegisterSet

  /// Obtain a unique index to the internal array from a given RegisterID.
  abstract member RegIDToIndex: RegisterID -> int

  /// Obtain a RegisterID from a given index.
  abstract member IndexToRegID: int -> RegisterID

  /// Size of the internal array.
  abstract member ArrSize: int

  /// An internal array storing the register set.
  abstract member BitArray: uint64 []

  /// A backup storage for unknown variables, which does not have a RegisterID.
  /// For example, when writing a symbolic executor, we may encounter unknown
  /// variables, i.e., fresh symbolic variables. We store them in this set.
  abstract member AuxSet: Set<RegisterID>

  /// Add a register to the set.
  abstract member Add: RegisterID -> RegisterSet

  /// Remove a register from the set.
  abstract member Remove: RegisterID -> RegisterSet

  /// Union of two register sets.
  abstract member Union: RegisterSet -> RegisterSet

  /// Intersection of two register sets.
  abstract member Intersect: RegisterSet -> RegisterSet

  /// Check if a register exists in the set.
  abstract member Exists: RegisterID -> bool

  /// Check if the set is empty.
  abstract member IsEmpty: unit -> bool

  /// Return the set of register indices.
  abstract member ToSet: unit -> Set<RegisterID>

  /// Create an internal bit array of size.
  static member inline MakeInternalBitArray size =
    Array.zeroCreate size

  /// Get the bucket and the offset from the given index.
  static member inline GetBucketAndOffset (idx) =
    struct (idx / 64, idx &&& 0x3F)

  /// Get the register index from the given bucket id and the offset.
  static member inline GetIndex bucketId offset =
    bucketId * 64 + offset

  /// Check if the nth bit is set on the value v.
  static member inline IsBitSet nth v =
    (v &&& (1UL <<< nth)) <> 0UL

/// Empty register set.
type EmptyRegisterSet () =
  inherit RegisterSet ()
  override __.Tag = RegisterSetTag.Empty
  override __.ArrSize = 0
  override __.New _ _ = Utils.impossible ()
  override __.RegIDToIndex _ = Utils.impossible ()
  override __.IndexToRegID _ = Utils.impossible ()
  override __.BitArray = [||]
  override __.AuxSet = Set.empty
  override __.Add _ = Utils.impossible ()
  override __.Remove _ = __ :> RegisterSet
  override __.Union o = o
  override __.Intersect o = __ :> RegisterSet
  override __.Exists _ = false
  override __.IsEmpty () = true
  override __.ToSet () = Set.empty

module private EmptyRegisterSet =
  let instance = EmptyRegisterSet () :> RegisterSet

/// Non-empty register set.
[<AbstractClass>]
type NonEmptyRegisterSet (bitArray: uint64 [], s: Set<RegisterID>) =
  inherit RegisterSet ()

#if DEBUG
  member __.CheckTag (o: RegisterSet) =
    if __.Tag = o.Tag then ()
    else raise RegisterSetTagMismatchException
#endif

  override __.GetHashCode () = hash __.BitArray

  override __.Equals obj =
    match obj with
    | :? NonEmptyRegisterSet as rhs -> __.BitArray = rhs.BitArray
    | _ -> false

  override __.BitArray = bitArray

  override  __.AuxSet = s

  override __.Add rid =
    match __.RegIDToIndex rid with
    | -1 -> __.New bitArray (Set.add rid s)
    | idx ->
      let struct (bucket, offset) = RegisterSet.GetBucketAndOffset idx
      let newArr = Array.copy bitArray
      newArr[bucket] <- newArr[bucket] ||| (1UL <<< offset)
      __.New newArr s

  override __.Remove id =
    match __.RegIDToIndex id with
    | -1 -> __.New bitArray (Set.remove id s)
    | id ->
      let struct (bucket, offset) = RegisterSet.GetBucketAndOffset id
      let newArr = Array.copy bitArray
      newArr[bucket] <- newArr[bucket] &&& ~~~(1UL <<< offset)
      __.New newArr s

  override __.Union (other: RegisterSet) =
    if other.Tag = RegisterSetTag.Empty then __ :> RegisterSet
    else
#if DEBUG
      __.CheckTag other
#endif
      let newArr = Array.mapi (fun i e -> e ||| other.BitArray[i]) bitArray
      __.New newArr (Set.union __.AuxSet other.AuxSet)

  override __.Intersect (other: RegisterSet) =
    if other.Tag = RegisterSetTag.Empty then EmptyRegisterSet.instance
    else
#if DEBUG
      __.CheckTag other
#endif
      let newArr = Array.mapi (fun i e -> e &&& other.BitArray[i]) bitArray
      __.New newArr <| Set.intersect __.AuxSet other.AuxSet

  override  __.Exists id =
    match __.RegIDToIndex id with
    | -1 -> Set.contains id __.AuxSet
    | id ->
      let struct (bucket, offset) = RegisterSet.GetBucketAndOffset id
      (bitArray[bucket] &&& (1UL <<< offset)) <> 0UL

  override __.IsEmpty () =
    (Array.exists (fun x -> x <> 0UL) bitArray |> not) && Set.isEmpty __.AuxSet

  member private __.FoldRegIndicesAux set bid v offset =
    if offset < 64 then
      let set =
        if (v &&& 1UL) = 1UL then Set.add (RegisterSet.GetIndex bid offset) set
        else set
      __.FoldRegIndicesAux set bid (v >>> 1) (offset + 1)
    else set

  member private __.FoldRegIndices set bid v = __.FoldRegIndicesAux set bid v 0

  override __.ToSet () =
    Array.foldi __.FoldRegIndices Set.empty bitArray
    |> fst
    |> Set.map __.IndexToRegID
    |> Set.union __.AuxSet

/// A helper module for RegisterSet.
[<RequireQualifiedAccess>]
module RegisterSet =
  let empty = EmptyRegisterSet.instance

  let inline union (lhs: RegisterSet) rhs = lhs.Union rhs

  let inline intersect (lhs: RegisterSet) rhs = lhs.Intersect rhs

  let inline remove id (s: RegisterSet) = s.Remove id

  let inline add id (s: RegisterSet) = s.Add id

  let inline exist id (s: RegisterSet) = s.Exists id

  let inline isEmpty (s: RegisterSet) = s.IsEmpty ()
