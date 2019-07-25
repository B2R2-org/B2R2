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

namespace B2R2.NameMangling

open System.Runtime.InteropServices

module Demangler =
  [<CompiledName("Detect")>]
  let detect str =
    if MSDemangler.isMSMangled str then MSMangler
    elif ItaniumDemangler.isItaniumMangled str then ItaniumMangler
    else UnknownMangler

  [<CompiledName("Demangle")>]
  let demangle str ([<Out>] dest: byref<string>) =
    match detect str with
    | MSMangler -> MSDemangler.demangle str &dest
    | ItaniumMangler -> ItaniumDemangler.demangle str &dest
    | UnknownMangler-> false
