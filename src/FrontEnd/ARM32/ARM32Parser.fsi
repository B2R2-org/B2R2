(*
    B2R2 - the Next-Generation Reversing Platform

    Author: DongYeop Oh <oh51dy@kaist.ac.kr>
                    Seung Il Jung <sijung@kaist.ac.kr>

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

/// ARMv7 instruction parser.
module B2R2.FrontEnd.ARM32.Parser

open B2R2

/// Read in bytes and return a parsed instruction for ARMv7. This function
/// returns ARM32Instruction, which is a specialized type for 32-bit ARM. If you
/// want to handle instructions in a platform-agnostic manner, you'd better use
/// the ARM32Parser class.
val parse: BinReader
                -> Architecture
                -> ArchOperationMode
                -> Addr
                -> int
                -> byte
                -> ARM32Instruction

