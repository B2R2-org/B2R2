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

/// The encoding facts of every Python version B2R2 reads, taken from the very
/// tables that version's parser decodes with so that the assembler and the
/// decoder cannot come to disagree about which byte an instruction is: there
/// is only the one table, and this points at it.
module B2R2.Assembly.Python.Tables

open System
open B2R2
open B2R2.Assembly.Python
open B2R2.FrontEnd.Python

/// The opcode number a mnemonic names in the given version, or None when that
/// version has no such instruction.
let private lookup version (name: string) =
  let name = name.ToUpperInvariant()
  (* Enum.TryParse takes a number for a number, so a name that is all digits
     would resolve to whatever opcode holds that value rather than failing. *)
  if name |> Seq.forall Char.IsDigit then
    None
  else
    match Enum.TryParse<Opcode> name with
    | true, op -> B2R2.FrontEnd.Python.Tables.encode version op
    | _ -> None

/// How the given version encodes.
let specOf version =
  { Lookup = lookup version
    HasOperand = B2R2.FrontEnd.Python.Tables.hasOperand version
    CacheCount = B2R2.FrontEnd.Python.Tables.cacheCount version
    IsWordcode = B2R2.FrontEnd.Python.Tables.isWordcode version
    ExtendedArg = B2R2.FrontEnd.Python.Tables.extendedArg version }
