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

/// Provides constants for ELF section names.
[<RequireQualifiedAccess>]
module B2R2.FrontEnd.BinFile.ELF.Section

/// The name of the section that contains executable code: ".text".
let [<Literal>] Text = ".text"

/// The name of the section that contains staticly allocated, but not
/// initialized data: ".bss".
let [<Literal>] BSS = ".bss"

/// The name of the section that contains initialized read-only data: ".rodata".
let [<Literal>] ROData = ".rodata"

/// The name of the section that contains function addresses that are executed
/// when a program starts.
let [<Literal>] InitArray = ".init_array"

/// The name of the section that contains function addresses that are executed
/// when a program exits.
let [<Literal>] FiniArray = ".fini_array"

/// The name of the section holding executtable instructions that contribute to
/// the process initialization code.
let [<Literal>] Init = ".init"

/// The name of the section holding executtable instructions that contribute to
/// the process termination code.
let [<Literal>] Fini = ".fini"
