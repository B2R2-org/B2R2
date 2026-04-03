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

namespace B2R2.FrontEnd.BinFile.ELF

open B2R2.BinIR

/// Debugging Information Entry (DIE) in DWARF format.
type DIE =
  { Offset: uint64
    Tag: DWTag
    HasChildren: bool
    Attributes: DWParsedAttribute list }

/// Represents a parsed DWARF attribute with its form and value.
and DWParsedAttribute =
  { Attribute: DWAttribute
    Form: DWForm
    Value: DWAttributeValue }

/// Represents a DWARF attribute value, which can be of various types depending
/// on the form.
and DWAttributeValue =
  | DWAddr of uint64
  | DWUInt of uint64
  | DWSInt of int64
  | DWBool of bool
  | DWString of string
  | DWStringOffset of string
  | DWLineStringOffset of uint64
  | DWBlock of byte[]
  | DWExprLoc of LowUIR.Expr
  | DWSectionOffset of uint64
  | DWUnitRef of uint64
  | DWDebugInfoRef of uint64
  | DWTypeSignature of uint64
  | DWSupRef of uint64
  | DWAddrIndex of uint64
  | DWStringIndex of uint64
  | DWLocListIndex of uint64
  | DWRangeListIndex of uint64
  | DWImplicitConst of int64
  | DWBytes of byte[]
  | DWIndirect of DWForm * DWAttributeValue
with
  static member ToString(value: DWAttributeValue) =
    match value with
    | DWAddr v -> $"0x{v:x}"
    | DWUInt v -> $"{v}"
    | DWSInt v -> $"{v}"
    | DWBool v -> if v then "true" else "false"
    | DWString s -> $"\"{s}\""
    | DWStringOffset s -> $"\"{s}\""
    | DWLineStringOffset off -> $"(line string offset: 0x{off:x})"
    | DWBlock bytes -> $"{B2R2.ByteArray.toHexString bytes}"
    | DWExprLoc expr -> $"{PrettyPrinter.ToString expr}"
    | DWSectionOffset off -> $"(section offset: 0x{off:x})"
    | DWUnitRef off -> $"(unit reference: 0x{off:x})"
    | DWDebugInfoRef off -> $"(debug info reference: 0x{off:x})"
    | DWTypeSignature sign -> $"(type signature: 0x{sign:x})"
    | DWSupRef off -> $"(sup reference: 0x{off:x})"
    | DWAddrIndex idx -> $"(address index: {idx})"
    | DWStringIndex idx -> $"(string index: {idx})"
    | DWLocListIndex idx -> $"(location list index: {idx})"
    | DWRangeListIndex idx -> $"(range list index: {idx})"
    | DWImplicitConst cst -> $"{cst}"
    | DWBytes bytes -> $"{B2R2.ByteArray.toHexString bytes}"
    | DWIndirect(form, v) ->
      $"indirect form: {form.ToString()}, value: {DWAttributeValue.ToString v}"