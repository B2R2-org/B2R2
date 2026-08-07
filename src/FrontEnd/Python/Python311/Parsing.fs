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

/// Implements parsing logic for Python 3.12.
module internal B2R2.FrontEnd.Python.Python311.Parsing

open System
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.Python
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Python

let private getTable (binFile: PythonBinFile) = function
  | Opcode.LOAD_CONST
  | Opcode.KW_NAMES -> binFile.Consts
  | Opcode.LOAD_NAME
  | Opcode.STORE_NAME
  | Opcode.DELETE_NAME
  | Opcode.STORE_ATTR
  | Opcode.DELETE_ATTR
  | Opcode.STORE_GLOBAL
  | Opcode.DELETE_GLOBAL
  | Opcode.LOAD_ATTR
  | Opcode.LOAD_METHOD
  | Opcode.IMPORT_NAME
  | Opcode.IMPORT_FROM
  | Opcode.LOAD_GLOBAL -> binFile.Names
  | Opcode.LOAD_FAST
  | Opcode.STORE_FAST
  | Opcode.DELETE_FAST
  | Opcode.MAKE_CELL
  | Opcode.LOAD_CLOSURE
  | Opcode.LOAD_DEREF
  | Opcode.STORE_DEREF
  | Opcode.LOAD_CLASSDEREF
  | Opcode.DELETE_DEREF -> binFile.Varnames
  | _ -> [||]

/// What an argument names, once the table it indexes is in hand.
let private resolveOperand (opcode: Opcode) (c: PyObject[]) idx =
  match opcode with
  (* namei's low bit is a push-NULL flag, so the co_names index sits one bit
     up. LOAD_ATTR only gains the same flag in 3.12, which is why it is not
     listed here. *)
  | Opcode.LOAD_GLOBAL ->
    OneOperand(idx, Some c[idx >>> 1])
  | _ ->
    if idx >= c.Length then failwith "Invalid instruction operand"
    else OneOperand(idx, Some c[idx])

/// What this version says about decoding; the loop itself is shared.
let spec =
  { Table = fun bf op -> getTable bf (enum<Opcode> op)
    Resolve = fun op entries idx -> resolveOperand (enum<Opcode> op) entries idx
    HasOperand = fun op -> Opcode.hasOperand (enum<Opcode> op)
    Length = fun op -> Opcode.length (enum<Opcode> op)
    IsDefined = fun op -> Enum.IsDefined(enum<Opcode> op)
    ExtendedArg = int Opcode.EXTENDED_ARG
    IsWordcode = true }

let parse semantics (span: ByteSpan) (reader: IBinReader) binFile addr =
  ParsingHelpers.parse spec semantics span reader binFile addr
