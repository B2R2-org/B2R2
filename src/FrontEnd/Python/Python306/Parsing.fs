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

/// Implements parsing logic for Python 3.6.
module internal B2R2.FrontEnd.Python.Python306.Parsing

open System
open B2R2.FrontEnd.BinFile
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
  | Opcode.STORE_ANNOTATION -> binFile.Names
  | Opcode.LOAD_FAST
  | Opcode.STORE_FAST
  | Opcode.DELETE_FAST -> binFile.Varnames
  (* LOAD_CLOSURE/LOAD_DEREF/STORE_DEREF/DELETE_DEREF/LOAD_CLASSDEREF index
     into `co_cellvars ++ co_freevars`, a completely separate 0-based space
     from co_varnames -- see FreeVars' own doc comment on PyCodeObject. *)
  | Opcode.LOAD_CLOSURE
  | Opcode.LOAD_DEREF
  | Opcode.STORE_DEREF
  | Opcode.DELETE_DEREF
  | Opcode.LOAD_CLASSDEREF -> binFile.FreeVars
  | _ -> [||]

(* Every 3.6 instruction is a fixed 2 bytes (opcode + one oparg byte): 3.6
   introduced this wordcode encoding, and the inline CACHE padding that makes
   some 3.11+ instructions longer is still years away. *)
let private parseOperand opcode
                         (span: ReadOnlySpan<byte>)
                         (reader: IBinReader)
                         binFile
                         addr
                         extArg =
  let tbl = getTable binFile opcode
  let idx = (reader.ReadUInt8(span, 1) |> int) ||| extArg
  let cons =
    tbl |> Array.tryFind (fun (ar, _) -> ar.Min <= addr && ar.Max >= addr)
  let opr =
    match cons with
    | Some(_, c) ->
      if idx >= c.Length then failwith "Invalid instruction operand"
      else OneOperand(idx, Some c[idx])
    (* This can happen when performing linear sweep on a non-code region,
       or the opcode's arg is just a plain integer (e.g. UNPACK_SEQUENCE,
       COMPARE_OP), which getTable already reports via an empty table. *)
    | None ->
      OneOperand(idx, None)
  opr

(* The byte IS the opcode: each version's Opcode enum carries CPython's own
   numbering, so decoding is a cast. *)
let rec private doParse semantics
                        (span: ReadOnlySpan<byte>)
                        (reader: IBinReader)
                        bf
                        s
                        c
                        e =
  let b = reader.ReadUInt8(span, 0) |> int
  let a = reader.ReadUInt8(span, 1) |> int
  if b = int Opcode.EXTENDED_ARG then
    doParse semantics (span.Slice 2) reader bf s (c + 2UL) ((e ||| a) <<< 8)
  else
    let opcode: Opcode = LanguagePrimitives.EnumOfValue b
    if not (Enum.IsDefined opcode) then raise ParsingFailureException
    else ()
    let opr =
      if Opcode.hasOperand opcode then parseOperand opcode span reader bf c e
      else NoOperand
    let total = uint32 (c - s) + Opcode.length opcode
    Instruction(s, total, b, opr, OperationSize.regType, bf.Version, bf,
                semantics)

let parse semantics (span: ByteSpan) (reader: IBinReader) binFile addr =
  doParse semantics span reader binFile addr addr 0
