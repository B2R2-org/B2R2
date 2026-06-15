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

/// Provides constants for PE section names.
[<RequireQualifiedAccess>]
module B2R2.FrontEnd.BinFile.PE.Section

/// The name of the section that contains executable code: ".text".
let [<Literal>] Text = ".text"

/// The name of the section that contains initialized read-only data: ".rdata".
let [<Literal>] RData = ".rdata"

/// The name of the section that contains resources: ".rsrc".
let [<Literal>] Resource = ".rsrc"

/// The name prefix of sections that contain debug information: ".debug".
let [<Literal>] DebugPrefix = ".debug"

/// The name of the section that contains thread-local storage: ".tls".
let [<Literal>] TLS = ".tls"

/// The name of the section that contains base relocations: ".reloc".
let [<Literal>] Reloc = ".reloc"

/// The name of the section that contains the import directory: ".idata".
let [<Literal>] IData = ".idata"

/// The name of the section that contains the export directory: ".edata".
let [<Literal>] EData = ".edata"

/// The name of the section that contains exception information: ".pdata".
let [<Literal>] PData = ".pdata"

/// The name of the section that contains unwind information: ".xdata".
let [<Literal>] XData = ".xdata"

/// The name of the section that contains resource data: ".rsrc$01".
let [<Literal>] ResourceData = ".rsrc$01"
