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

namespace B2R2.BinIR

open B2R2

/// <summary>
/// Represents a symbolic label that can be a jump target. Each label has its
/// name and a unique identifier. We also associate an address with the label to
/// represent the location of the label in the binary, i.e., the address of the
/// instruction that the label belongs to.
/// </summary>
[<Sealed>]
type Label(name: string, id: int, addr: Addr) =
  /// <summary>
  /// Retrieves the symbolic name of the label.
  /// </summary>
  member _.Name with get() = name

  /// <summary>
  /// Retrieves the ID of the label. The ID is unique for each label and is used
  /// to distinguish between different labels.
  /// </summary>
  member _.Id with get() = id

  /// <summary>
  /// Retrieves the instruction address that this label belongs to.
  /// </summary>
  member _.Address with get() = addr

  /// <summary>
  /// Checks whether this label equals the given label.
  /// </summary>
  member _.Equals(other: Label) =
    id = other.Id && addr = other.Address && name = other.Name

  /// <summary>
  /// Checks whether this label equals the given object.
  /// </summary>
  override this.Equals obj =
    match obj with
    | :? Label as lbl -> this.Equals lbl
    | _ -> false

  /// <summary>
  /// Computes the hash code for the label.
  /// </summary>
  override _.GetHashCode() =
    System.HashCode.Combine(name, id, addr)

  /// <summary>
  /// Returns a string representation of the label.
  /// </summary>
  override _.ToString() =
    name + "_" + id.ToString() + "@" + addr.ToString "x"

  interface System.IEquatable<Label> with
    member this.Equals other = this.Equals other
