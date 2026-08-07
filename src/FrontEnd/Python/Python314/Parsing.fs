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
module internal B2R2.FrontEnd.Python.Python314.Parsing

open System
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.Python
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Python

let private getTable (binFile: PythonBinFile) = function
  | Opcode.LOAD_CONST -> binFile.Consts
  | Opcode.LOAD_NAME
  | Opcode.STORE_NAME
  | Opcode.DELETE_NAME
  | Opcode.STORE_ATTR
  | Opcode.DELETE_ATTR
  | Opcode.STORE_GLOBAL
  | Opcode.DELETE_GLOBAL
  | Opcode.LOAD_ATTR
  | Opcode.IMPORT_NAME
  | Opcode.IMPORT_FROM
  | Opcode.LOAD_GLOBAL
  | Opcode.LOAD_SUPER_ATTR
  | Opcode.LOAD_FROM_DICT_OR_GLOBALS
  | Opcode.INSTRUMENTED_LOAD_SUPER_ATTR -> binFile.Names
  | Opcode.LOAD_FAST
  | Opcode.STORE_FAST
  | Opcode.DELETE_FAST
  | Opcode.LOAD_FAST_CHECK
  | Opcode.LOAD_FAST_AND_CLEAR
  | Opcode.MAKE_CELL
  | Opcode.LOAD_CLOSURE
  | Opcode.LOAD_DEREF
  | Opcode.STORE_DEREF
  | Opcode.DELETE_DEREF
  | Opcode.LOAD_FAST_BORROW
  | Opcode.LOAD_FAST_LOAD_FAST
  | Opcode.LOAD_FAST_BORROW_LOAD_FAST_BORROW
  | Opcode.STORE_FAST_LOAD_FAST
  | Opcode.STORE_FAST_STORE_FAST
  | Opcode.LOAD_FROM_DICT_OR_DEREF -> binFile.Varnames
  | _ -> [||]

(* These pack TWO co_varnames indices into one oparg, the high
   nibble first, so the operand carries both resolved names. *)
let private isPairedLocal = function
  | Opcode.LOAD_FAST_LOAD_FAST
  | Opcode.LOAD_FAST_BORROW_LOAD_FAST_BORROW
  | Opcode.STORE_FAST_LOAD_FAST
  | Opcode.STORE_FAST_STORE_FAST -> true
  | _ -> false

/// What an argument names, once the table it indexes is in hand.
let private resolveOperand (opcode: Opcode) (c: PyObject[]) idx =
  match opcode with
  (* We truncate the LSB to correctly query the table while keeping the
     original index for complete information. *)
  | Opcode.LOAD_GLOBAL
  | Opcode.LOAD_ATTR ->
    OneOperand(idx, Some c[idx >>> 1])
  (* namei here packs two low flag bits (is-method-call, is-two-arg-super)
     ahead of the actual co_names index, unlike LOAD_ATTR/LOAD_GLOBAL's
     single flag bit -- so it needs a 2-bit shift. *)
  | Opcode.LOAD_SUPER_ATTR
  | Opcode.INSTRUMENTED_LOAD_SUPER_ATTR ->
    OneOperand(idx, Some c[idx >>> 2])
  | _ when isPairedLocal opcode ->
    let at i =
      if i >= c.Length then failwith "Invalid instruction operand" else c[i]
    OneOperand(idx, Some(PyTuple [| at (idx >>> 4); at (idx &&& 0xF) |]))
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
