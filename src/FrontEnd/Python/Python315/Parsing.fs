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

module internal B2R2.FrontEnd.Python.Python315.Parsing

open System
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.Python
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Python

let private getTable (binFile: PythonBinFile) = function
  | Opcode.LOAD_CONST -> binFile.Consts
  | Opcode.DELETE_ATTR
  | Opcode.DELETE_GLOBAL
  | Opcode.DELETE_NAME
  | Opcode.IMPORT_FROM
  | Opcode.IMPORT_NAME
  | Opcode.INSTRUMENTED_LOAD_SUPER_ATTR
  | Opcode.LOAD_ATTR
  | Opcode.LOAD_FROM_DICT_OR_GLOBALS
  | Opcode.LOAD_GLOBAL
  | Opcode.LOAD_NAME
  | Opcode.LOAD_SUPER_ATTR
  | Opcode.STORE_ATTR
  | Opcode.STORE_GLOBAL
  | Opcode.STORE_NAME -> binFile.Names
  | Opcode.DELETE_DEREF
  | Opcode.DELETE_FAST
  | Opcode.LOAD_DEREF
  | Opcode.LOAD_FAST
  | Opcode.LOAD_FAST_AND_CLEAR
  | Opcode.LOAD_FAST_BORROW
  | Opcode.LOAD_FAST_BORROW_LOAD_FAST_BORROW
  | Opcode.LOAD_FAST_CHECK
  | Opcode.LOAD_FAST_LOAD_FAST
  | Opcode.LOAD_FROM_DICT_OR_DEREF
  | Opcode.MAKE_CELL
  | Opcode.STORE_DEREF
  | Opcode.STORE_FAST
  | Opcode.STORE_FAST_LOAD_FAST
  | Opcode.STORE_FAST_STORE_FAST -> binFile.Varnames
  | _ -> [||]

(* LOAD_FAST_LOAD_FAST and friends pack TWO co_varnames indices into a single
   oparg -- the high nibble first, then the low one -- so the operand is the
   packed value CPython also reports, carrying both resolved names. *)
let private isPairedLocal = function
  | Opcode.LOAD_FAST_LOAD_FAST
  | Opcode.LOAD_FAST_BORROW_LOAD_FAST_BORROW
  | Opcode.STORE_FAST_LOAD_FAST
  | Opcode.STORE_FAST_STORE_FAST -> true
  | _ -> false

let private resolveOperand opcode (c: PyObject[]) idx =
  (* Bounds-checked on every path, not just the plain one: the shifted and
     nibble-split forms below can land out of range too, and naming the
     opcode makes a table/encoding mismatch diagnosable from the message. *)
  let get i =
    if i < 0 || i >= c.Length then
      failwithf "%A: oparg %d resolves to table index %d, but the table \
                 holds %d entries" opcode idx i c.Length
    else
      c[i]
  match opcode with
  | Opcode.LOAD_GLOBAL
  | Opcode.LOAD_ATTR ->
    (* namei's low bit is a flag (push-NULL / is-method), so the actual
       co_names index sits one bit up. Keep the raw value as the operand so
       it still matches the oparg CPython reports. *)
    OneOperand(idx, Some(get (idx >>> 1)))
  | Opcode.LOAD_SUPER_ATTR
  | Opcode.INSTRUMENTED_LOAD_SUPER_ATTR
  (* IMPORT_NAME gained low flag bits of its own in 3.15 -- unlike 3.10 and
     3.12, where its oparg is the bare co_names index -- so it needs the same
     2-bit shift LOAD_SUPER_ATTR does. Confirmed against CPython 3.15's own
     argrepr over the whole test corpus: every IMPORT_NAME there resolves at
     `oparg >>> 2` and none at `oparg`. *)
  | Opcode.IMPORT_NAME ->
    (* Two flag bits here (is-method-call, is-two-arg-super), not one. *)
    OneOperand(idx, Some(get (idx >>> 2)))
  | _ when isPairedLocal opcode ->
    OneOperand(idx, Some(PyTuple [| get (idx >>> 4); get (idx &&& 0xF) |]))
  | _ ->
    OneOperand(idx, Some(get idx))

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
