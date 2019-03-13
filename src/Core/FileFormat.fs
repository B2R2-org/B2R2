(*
    B2R2 - the Next-Generation Reversing Platform

    Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

namespace B2R2

/// Types of binary file format.
type FileFormat =
    /// Raw binary without any specific file format: a sequence of bytes.
    | RawBinary = 1
    /// ELF binary.
    | ELFBinary = 2
    /// PE binary.
    | PEBinary = 3
    /// Mach-O binary.
    | MachBinary = 4

/// A helper module for FileFormat type.
module FileFormat =
    let ofString (str: string) =
        match str.ToLower () with
        | "elf" -> FileFormat.ELFBinary
        | "pe" -> FileFormat.PEBinary
        | "mach" | "mach-o" -> FileFormat.MachBinary
        | _ -> FileFormat.RawBinary

    let toString = function
        | FileFormat.RawBinary -> "Raw"
        | FileFormat.ELFBinary -> "ELF"
        | FileFormat.PEBinary -> "PE"
        | FileFormat.MachBinary -> "Mach-O"
        | _ -> invalidArg "FileFormat" "Unknown FileFormat used."

    /// Check whether the given format is ELF.
    let isELF fmt = fmt = FileFormat.ELFBinary
