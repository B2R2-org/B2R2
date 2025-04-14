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

module internal B2R2.FrontEnd.BinFile.Python.Helper

open System
open System.Collections.Generic
open B2R2
open B2R2.Collections
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper

let defaultPyCodeCon = {
  FileName = "Default"
  Name = "Default"
  QualName = PyREF 0
  Flags = 0
  Code = 0, PyNone
  FirstLineNo = 0
  LineTable = PyNone
  Consts = PyNone
  Names = PyNone
  LocalPlusNames = PyNone
  LocalPlusKinds = PyNone
  ArgCount = 0
  PosonlyArgCount = 0
  KwonlyArgCount = 0
  StackSize = 0
  ExceptionTable = PyNone
}

let refs = [||]

[<Literal>]
let PyMagic = 0x0A0D0DCBu

let getEntryPoint () = Some 0UL

let isPython (bytes: byte[]) (reader: IBinReader) =
  if bytes.Length >= 4 then reader.ReadUInt32 (bytes, 0) = PyMagic
  else false

let parseMagic (bytes: byte[]) (reader: IBinReader) =
  reader.ReadUInt32 (bytes, 0)

let getPyType (bytes: byte[]) (reader: IBinReader) offset : (PyType * int) =
  let pyType = reader.ReadUInt8 (bytes, offset)
  (int pyType &&& (~~~ 0x80)) |> LanguagePrimitives.EnumOfValue, offset + 1

let rec pyObjToString = function
  | PyString s -> System.Text.Encoding.ASCII.GetString (s)
  | PyShortAsciiInterned a -> System.Text.Encoding.ASCII.GetString (a)
  | PyShortAscii a -> System.Text.Encoding.ASCII.GetString (a)
  | PyInt i -> i.ToString()
  | PyREF r -> r.ToString()
  | PyTuple t ->
    let t = Array.map pyObjToString t
    String.concat ", " t
  | PyNone -> "None"
  | o -> failwithf "Error PyObjToString (%A)" o

let readAndOffset (bytes: byte[]) (reader: IBinReader) offset size =
  match size with
  | 1 -> reader.ReadUInt8 (bytes, offset) |> int, offset + size
  | 4 -> reader.ReadUInt32 (bytes, offset) |> int, offset + size
  | _ -> failwithf "Invalid size %d" size

let rec parsePyType (bytes: byte[]) (reader: IBinReader) refs offset =
  //printfn "offset in 0x%X(%d)" offset offset
  let pyType, offset = getPyType bytes reader offset
  //printfn "offset out 0x%X(%d)" offset offset
  match pyType with
  | PyType.TYPE_CODE ->
    let argCout, offset = readAndOffset bytes reader offset 4
    let posonlyArgCout, offset = readAndOffset bytes reader offset 4
    let kwonposonlyArgCout, offset = readAndOffset bytes reader offset 4
    let stackSize, offset = readAndOffset bytes reader offset 4
    let flags, offset = readAndOffset bytes reader offset 4
    let codeOffset = offset + 5
    let code, refs, offset = parsePyType bytes reader refs offset
    let consts, refs, offset = parsePyType bytes reader refs offset
    let names, refs, offset = parsePyType bytes reader refs offset
    let localsplusnames, refs, offset = parsePyType bytes reader refs offset
    let localspluskinds, refs, offset = parsePyType bytes reader refs offset
    let filenames, refs, offset = parsePyType bytes reader refs offset
    let name, refs, offset = parsePyType bytes reader refs offset
    let qname, refs, offset = parsePyType bytes reader refs offset
    let fstline, offset = readAndOffset bytes reader offset 4
    let linetbl, refs, offset = parsePyType bytes reader refs offset
    let exceptbl, refs, offset = parsePyType bytes reader refs offset
    let con = {
      FileName = pyObjToString filenames
      Name = pyObjToString name
      QualName = qname
      Flags = flags
      Code = codeOffset, code
      FirstLineNo = fstline
      LineTable = linetbl
      Consts = consts
      Names = names
      LocalPlusNames = localsplusnames
      LocalPlusKinds = localspluskinds
      ArgCount = argCout
      PosonlyArgCount = posonlyArgCout
      KwonlyArgCount = kwonposonlyArgCout
      StackSize = stackSize
      ExceptionTable = exceptbl }
    PyCode con, refs, offset
  | PyType.TYPE_STRING ->
    let size, offset = readAndOffset bytes reader offset 4
    PyString (Array.sub bytes offset size), refs, offset + size
  | PyType.TYPE_INT ->
    let int, offset = readAndOffset bytes reader offset 4
    PyInt int, refs, offset
  | PyType.TYPE_NONE -> PyNone, refs, offset
  | PyType.TYPE_SMALL_TUPLE ->
    let size, offset = readAndOffset bytes reader offset 1
    if size <> 0 then
      let rec loop acc offset =
        if List.length acc = size then acc, offset
        else
          let contents, refs, offset = parsePyType bytes reader refs offset
          loop (contents :: acc) offset
      let tuples, offset = loop [] offset
      PyTuple (tuples |> List.toArray), refs, offset
    else PyTuple [||], refs, offset
  | PyType.TYPE_SHORT_ASCII | PyType.TYPE_SHORT_ASCII_INTERNED ->
    let n, offset = readAndOffset bytes reader offset 1
    PyShortAsciiInterned (Array.sub bytes offset n), refs, offset + n
  | PyType.TYPE_REF ->
    let n, offset = readAndOffset bytes reader offset 4
    PyREF n, refs, offset
  | _ -> printf "%A " pyType; failwith "Invalid parsePyType"

let parseCodeObject bytes reader = parsePyType bytes reader [||] 16

let getSections codeObjs =
  printfn "%A" codeObjs
  let rec extractCodeInfo (pyObj: PyCodeObject): (int * int * string) list =
    match pyObj with
    | PyCode code ->
      let current =
        let (offset, pyObj) = code.Code
        match pyObj with
        | PyString s -> offset, s.Length, code.Name
        | _ -> failwithf "Invalid PyCode(%A)" pyObj
      let nested =
        match code.Consts with
        | PyTuple t ->
          t |> Array.toList
          |> List.collect extractCodeInfo
        | _ -> failwithf "Invalid PyTuple(%A)" pyObj
      current :: nested
    | _ -> []
  extractCodeInfo codeObjs |> List.toArray
