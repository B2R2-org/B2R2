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

namespace B2R2.Peripheral.Assembly

open B2R2
open B2R2.Peripheral.Assembly.BinLowerer

/// <namespacedoc>
///   <summary>
///   Contains the APIs for the B2R2 assembly peripheral, which provides
///   functionalities to lower assembly code into binary instructions.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents the main assembler class that can lower assembly code into binary
/// instructions.
/// </summary>
type Assembler(isa: ISA, startAddress) =

  let assembler  =
    match isa with
    | Intel -> Intel.Assembler(isa, startAddress) :> ILowerable
    | _ -> raise InvalidISAException

  /// The start address of the binary instructions.
  member _.StartAddress with get() = startAddress

  /// Lowers the given assembly string down to a list of byte arrays, where each
  /// array corresponds to a binary instruction.
  member _.Lower asm = assembler.Lower asm
