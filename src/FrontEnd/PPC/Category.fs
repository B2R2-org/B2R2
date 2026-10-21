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


namespace B2R2.FrontEnd.PPC

open System
open B2R2

/// <summary>
/// The categories of the Power ISA that read an encoding another category
/// reads as well, so that a word of PowerPC code means one thing or the other
/// depending on which of them the processor implements.
/// <para>
/// A PowerPC ISA keeps them in its flags, which nothing else in B2R2 reads for
/// PowerPC. Zero, the default, is the server processors' reading: Book III-S,
/// with the vector facility in primary opcode 4. A category named here takes
/// only the encodings it gives another meaning; every other word reads the
/// same whatever the flags say. At most one category may take primary opcode
/// 4.
/// </para>
/// </summary>
[<Flags>]
type Category =
  /// Book III-S, the server environment, with the vector facility in primary
  /// opcode 4.
  | Server = 0x0
  /// Legacy Integer Multiply-Accumulate, the halfword multiplies and
  /// multiply-accumulates of the 405 and 440 cores, which take primary opcode
  /// 4 from the vector facility.
  | LegacyIntegerMultiplyAccumulate = 0x1
  /// Book III-E, the embedded environment, where the word that is eieio on a
  /// server processor is mbar, whose MO field the server reading leaves
  /// reserved.
  | Embedded = 0x2
  /// Legacy Move Assist, dlmzb of the 405 and 440 cores, whose word is the one
  /// a server processor reads as msgsndu when rS and rA are r0.
  | LegacyMoveAssist = 0x4

/// Provides functions to read the categories a PowerPC ISA names.
[<RequireQualifiedAccess>]
module Category =
  /// The categories a PowerPC ISA names in its flags.
  [<CompiledName "OfISA">]
  let ofISA (isa: ISA): Category = LanguagePrimitives.EnumOfValue isa.Flags

  /// Whether the categories include the one given.
  let includes (category: Category) (categories: Category) =
    categories &&& category = category
