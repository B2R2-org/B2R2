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

namespace B2R2.FrontEnd.NameMangling

open B2R2

/// Represents a top-level module that provides functions for detecting and
/// demangling mangled names.
type Demangler =
  /// Detects the mangling scheme of the given string.
  static member Detect str =
    if MSDemangler.IsWellFormed str then Ok MSMangler
    elif ItaniumDemangler.IsWellFormed str then Ok ItaniumMangler
    else Error ErrorCase.InvalidFormat

  /// Creates a demangler instance based on the detected mangling scheme.
  static member Create str =
    if MSDemangler.IsWellFormed str then
      MSDemangler() :> IDemanglable
    elif ItaniumDemangler.IsWellFormed str then
      ItaniumDemangler() :> IDemanglable
    else
      (* Simply return the same string. *)
      { new IDemanglable with member _.Demangle s = Ok s }

  /// Automatically detects the mangling scheme and demangles the string. If the
  /// mangling scheme is unknown, it returns the original string.
  static member Demangle str =
    if MSDemangler.IsWellFormed str then
      (MSDemangler() :> IDemanglable).Demangle str
    elif ItaniumDemangler.IsWellFormed str then
      (ItaniumDemangler() :> IDemanglable).Demangle str
    else Ok str
