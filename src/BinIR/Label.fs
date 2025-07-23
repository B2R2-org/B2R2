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
type Label (name: string, id: int, addr: Addr) =
  /// <summary>
  /// Retrives the symbolic name of the label.
  /// </summary>
  member _.Name with get () = name

  /// <summary>
  /// Retrives the ID of the label. The ID is unique for each label and is used
  /// to distinguish between different labels.
  /// </summary>
  member _.Id with get () = id

  /// <summary>
  /// Retrives the instruction address that this label belongs to.
  /// </summary>
  member _.Address with get () = addr

  /// <summary>
  /// Compares two labels for equality.
  /// </summary>
  override _.Equals(obj) =
    match obj with
    | :? Label as lbl -> lbl.Name = name && lbl.Id = id && lbl.Address = addr
    | _ -> false

  /// <summary>
  /// Computes the hash code for the label.
  /// </summary>
  override _.GetHashCode() = name.GetHashCode() ^^^ id ^^^ addr.GetHashCode()

  /// <summary>
  /// Retrives a stirng representation of the symbol.
  /// </summary>
  override _.ToString() = name + "_" + id.ToString() + "@" + addr.ToString "x"
