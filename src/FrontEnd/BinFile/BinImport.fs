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

open B2R2

/// Represents an imported symbol resolved through dynamic linking, e.g., a
/// PLT/GOT pair in ELF, an IAT entry in PE, a stub/pointer pair in Mach-O, or
/// an imported entry in Wasm.
type BinImport =
  { /// Name of the imported symbol, which can be a function or a data object.
    Name: string
    /// Name of the library (module) that provides the symbol. Empty when the
    /// providing library is unknown.
    LibraryName: string
    /// Address of the trampoline/stub that jumps to the import, e.g., a PLT
    /// entry or a Mach-O symbol stub. None for formats with no trampoline,
    /// such as PE (IAT-only) and Wasm.
    TrampolineAddress: Addr option
    /// Address of the slot that holds the resolved target address, e.g., a GOT
    /// slot, an IAT slot, or a Mach-O pointer-table entry.
    TableAddress: Addr }