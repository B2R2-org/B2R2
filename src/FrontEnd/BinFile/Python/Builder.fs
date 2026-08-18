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

/// Writes the smallest `.pyc` that holds a given block of bytecode, for any
/// version this front end reads.
///
/// A Python instruction's argument indexes a table the code object carries, so
/// there is no way to decode one without a file around it -- unlike every
/// other architecture here, whose parsers need only the bytes. That makes a
/// file the unit of test for anything below the parser, and a real `.pyc`
/// needs an interpreter of that version to produce. This builds one instead,
/// mirroring what Helper's reader reads, field for field.
module B2R2.FrontEnd.BinFile.Python.Builder

open System
open B2R2

let private i32 (n: int) =
  [| byte n; byte (n >>> 8); byte (n >>> 16); byte (n >>> 24) |]

let private u32 (n: uint32) =
  [| byte n; byte (n >>> 8); byte (n >>> 16); byte (n >>> 24) |]

/// A marshalled object carries its type in one byte. Nothing written here is
/// referenced twice, so the high "record this for later" bit is never set.
let private tagged (t: MarshalledType) payload =
  Array.append [| byte t |] payload

/// The empty tuple, which every table this file does not need is written as.
let private emptyTuple = tagged MarshalledType.TYPE_SMALL_TUPLE [| 0uy |]

let private bytesObj (bs: byte[]) =
  tagged MarshalledType.TYPE_STRING (Array.append (i32 bs.Length) bs)

let private shortAscii (s: string) =
  let bs = Text.Encoding.ASCII.GetBytes s
  tagged MarshalledType.TYPE_SHORT_ASCII (Array.append [| byte bs.Length |] bs)

/// A tuple of short ASCII names, which is what every table of names is.
/// Written as a full tuple rather than a small one because a small tuple
/// counts its entries in a single byte and these tables are wider than that.
let private nameTuple (names: string[]) =
  names
  |> Array.map shortAscii
  |> Array.concat
  |> Array.append (i32 names.Length)
  |> tagged MarshalledType.TYPE_TUPLE

/// The tables a code object carries, and what it is called. Anything left
/// empty simply has no entries, which is what a test that only cares about
/// opcodes wants.
type CodeObject =
  { Code: byte[]
    Consts: byte[][]
    Names: string[]
    Varnames: string[]
    Name: string
    FileName: string
    FirstLineNo: int
    /// The raw `co_exceptiontable` bytes, written only for 3.11 and later
    /// since no older code object has the field at all. Empty unless a test
    /// asks for guarded ranges.
    ExceptionTable: byte[] }

/// How many entries each table is given. An argument is an index into one of
/// them, and an index past the end is a parse failure rather than an
/// instruction, so a code object meant for trying instructions in has to be
/// wide enough for every argument that will be tried. A byte's worth covers
/// everything a single wordcode instruction can name without EXTENDED_ARG.
let tableWidth = 256

/// A code object holding the given bytecode, with tables of the given width.
/// Wider costs a bigger file for every table entry, so ask for what an
/// argument will actually reach and no more.
let codeWith width code =
  { Code = code
    Consts = Array.replicate width (tagged MarshalledType.TYPE_NONE [||])
    Names = Array.init width (sprintf "n%d")
    Varnames = Array.init width (sprintf "v%d")
    Name = "<module>"
    FileName = "<synthetic>"
    FirstLineNo = 1
    ExceptionTable = [||] }

/// A code object holding the given bytecode, with tables wide enough that any
/// single-byte argument resolves to something.
let codeOf code = codeWith tableWidth code

let private constTuple (consts: byte[][]) =
  consts
  |> Array.concat
  |> Array.append (i32 consts.Length)
  |> tagged MarshalledType.TYPE_TUPLE

/// The counts before the tables. 3.8 added co_posonlyargcount, and everything
/// up to 3.10 carried co_nlocals that 3.11 dropped -- read in Helper as
/// hasPosOnlyArgCount and isLegacyCodeObjectVersion, and written here to
/// match, because a field written that is not read shifts every table after
/// it and marshal reports bad data rather than a bad layout.
let private counts (version: PythonVersion) =
  let posonly = if int version >= 308 then i32 0 else [||]
  let nlocals = if int version <= 310 then i32 0 else [||]
  Array.concat [ i32 0            (* argcount *)
                 posonly
                 i32 0            (* kwonlyargcount *)
                 nlocals
                 i32 8            (* stacksize *)
                 i32 0 ]          (* flags *)

/// The tables, in the order the reader takes them. 3.11 merged co_varnames,
/// co_freevars and co_cellvars into localsplusnames beside a kinds table, and
/// added a qualified name and an exception table.
let private tables (version: PythonVersion) co =
  if int version >= 311 then
    [| bytesObj co.Code
       constTuple co.Consts
       nameTuple co.Names
       nameTuple co.Varnames                       (* localsplusnames *)
       bytesObj (Array.zeroCreate co.Varnames.Length) (* localspluskinds *)
       shortAscii co.FileName
       shortAscii co.Name
       shortAscii co.Name                          (* qualname *)
       i32 co.FirstLineNo
       bytesObj [||]                               (* linetable *)
       bytesObj co.ExceptionTable |]               (* exceptiontable *)
  else
    [| bytesObj co.Code
       constTuple co.Consts
       nameTuple co.Names
       nameTuple co.Varnames
       emptyTuple                                  (* freevars *)
       emptyTuple                                  (* cellvars *)
       shortAscii co.FileName
       shortAscii co.Name
       i32 co.FirstLineNo
       bytesObj [||] |]                            (* lnotab *)

/// The bytes before the code object: the magic, and the fields releases added
/// beside it. Their contents are never read, only their width.
let private header (version: PythonVersion) magic =
  Array.append (u32 magic) (Array.zeroCreate (Helper.headerSize version - 4))

/// A whole `.pyc` for the given version, holding one code object.
let build version magic co =
  [| header version magic
     tagged MarshalledType.TYPE_CODE (counts version)
     yield! tables version co |]
  |> Array.concat

/// The magic number the given version's files start with, which is what says
/// to the reader which version it is looking at.
let magicOf (version: PythonVersion) =
  match Helper.magicNumberOf version with
  | Some m -> m
  | None -> failwithf "No magic number for %A" version
