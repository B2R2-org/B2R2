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

namespace B2R2.FrontEnd.BinFile.PE

/// Represents the PDB symbol type (enum SYM_ENUM_e).
type PDBSymbolKind =
  /// Compile flags symbol.
  | S_COMPILE = 0x0001us
  /// Address of virtual function table.
  | S_VFTABLE32 = 0x100cus
  /// Public symbol.
  | S_PUB32 = 0x110eus
  /// Reference to a procedure.
  | S_PROCREF = 0x1125us
  /// Local Reference to a procedure.
  | S_LPROCREF = 0x1127us
  /// Local procedure start.
  | S_LPROC32 = 0x110fus
  /// Global procedure start.
  | S_GPROC32 = 0x1110us
