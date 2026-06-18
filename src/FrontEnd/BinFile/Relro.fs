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

namespace B2R2.FrontEnd.BinFile

/// Represents the RELRO (RELocation Read-Only) protection level of a binary.
/// This is a GNU/ELF-specific hardening concept, so formats without a notion of
/// RELRO report it as absent rather than as one of these levels.
type Relro =
  /// No RELRO protection.
  | NoRelro
  /// Partial RELRO: a GNU_RELRO segment is present, but the GOT remains
  /// writable since symbol resolution stays lazy.
  | PartialRelro
  /// Full RELRO: a GNU_RELRO segment is present and binding is eager
  /// (BIND_NOW), so the whole GOT is made read-only after relocation.
  | FullRelro

/// <summary>
/// Provides functions for working with <see
/// cref='T:B2R2.FrontEnd.BinFile.Relro'/> values.
/// </summary>
[<RequireQualifiedAccess>]
module Relro =
  /// Transforms a <see cref='T:B2R2.FrontEnd.BinFile.Relro'/> into a string.
  [<CompiledName "ToString">]
  let toString relro =
    match relro with
    | NoRelro -> "No RELRO"
    | PartialRelro -> "Partial RELRO"
    | FullRelro -> "Full RELRO"
