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

/// Represents a mapping symbol, which marks the address where the instruction
/// encoding in use changes, or where a data region is embedded in code. Only
/// the two ARM ABIs define them; symbols of every other machine type parse to
/// None.
type internal MappingSymbol =
  /// ARM (A32) code starts here, as marked by $a.
  | ARM = 1
  /// Thumb (T32) code starts here, as marked by $t.
  | Thumb = 2
  /// AArch64 (A64) code starts here, as marked by $x.
  | A64 = 3
  /// A data region starts here, as marked by $d.
  | Data = 4
  /// The symbol is not a mapping symbol.
  | None = 5

[<RequireQualifiedAccess>]
module internal MappingSymbol =
  /// Checks if the given name is spelled the way both ARM ABIs spell a mapping
  /// symbol: a dollar, one letter naming what starts here, and optionally a
  /// period followed by anything, which lets a producer name each region
  /// distinctly (e.g., $d.1).
  let private isMappingSymbolName (name: string) =
    name.Length >= 2 && name[0] = '$' && (name.Length = 2 || name[2] = '.')

  /// Returns what the given letter marks for the given machine type. AArch64
  /// has a single instruction encoding, so it spells its code marker $x and
  /// uses neither $a nor $t.
  let private ofLetter machine letter =
    match machine, letter with
    | MachineType.EM_ARM, 'a' -> MappingSymbol.ARM
    | MachineType.EM_ARM, 't' -> MappingSymbol.Thumb
    | MachineType.EM_AARCH64, 'x' -> MappingSymbol.A64
    | MachineType.EM_ARM, 'd'
    | MachineType.EM_AARCH64, 'd' -> MappingSymbol.Data
    | _ -> MappingSymbol.None

  /// Returns the mapping symbol that the given symbol name marks, which is
  /// None unless the name is one of those the given machine type defines.
  let parse machine name =
    if isMappingSymbolName name then ofLetter machine name[1]
    else MappingSymbol.None
