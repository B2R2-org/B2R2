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

module B2R2.BinIR.Utils

open B2R2.BinIR.LowUIR

/// Is this IR statement a branch statement?
let isBranch = function
    | Jmp _ | CJmp _ | InterJmp _ | InterCJmp _ -> true
    | ISMark _ | IEMark _ | LMark _ | Put _ | Store _ | SideEffect _ -> false

/// Does this IR statement halt the execution?
let isHalt = function
    | ISMark _ | IEMark _ | LMark _ | Put _ | Store _ -> false
    | Jmp _ | CJmp _ | InterJmp _ | InterCJmp _ -> false
    | SideEffect effect -> effect = Halt

/// Is this IR statement a branch statement or does it halt the execution? This
/// is equaivalent to (isBranch || isHalt), but defined separately just for
/// the performance reason.
let isBBEnd = function
    | ISMark _ | IEMark _ | LMark _ | Put _ | Store _ -> false
    | Jmp _ | CJmp _ | InterJmp _ | InterCJmp _ -> true
    | SideEffect effect -> effect = Halt

