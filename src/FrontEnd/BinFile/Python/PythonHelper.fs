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
  Code = 0, [| 0uy |]
  FirstLineNo = 0
  LineTable = [| 0uy |]
  Consts = [| PyNone |]
  Names = [| PyNone |]
  LocalPlusNames = [| PyNone |]
  LocalPlusKinds = [| 0uy |]
  ArgCount = 0
  PosonlyArgCount = 0
  KwonlyArgCount = 0
  StackSize = 0
  ExceptionTable = [| 0uy |]
}

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

let pyObjToString pyObjs =
  List.map (fun o ->
    match o with
    | PyString str -> str
    | PyInt i -> i.ToString()
    | PyNone -> "None"
    | _ -> failwithf "Error PyObjToString (%A)" o
  ) pyObjs

let readAndOffset (bytes: byte[]) (reader: IBinReader) offset size =
  match size with
  | 1 -> reader.ReadUInt8 (bytes, offset) |> int, offset + size
  | 4 -> reader.ReadUInt32 (bytes, offset) |> int, offset + size
  | _ -> failwithf "Invalid size %d" size

let rec parsePyType (bytes: byte[]) (reader: IBinReader) offset =
  let inline parsePyTypeObject offset =
    let pyObj, offset = parsePyType bytes reader offset
    match pyObj with
    | PyTuple tuple -> tuple, offset
    | PyREF _ as r -> [| r |], offset
    | _ -> failwithf "Invalid Python Type(%A)" pyObj

  let inline parsePyTypeObjectToByteArr offset =
    let pyObj, offset = parsePyType bytes reader offset
    match pyObj with
    | PyString str ->
      let size = int str
      Array.sub bytes offset (int size), offset + size
    | PyREF ref -> [| byte ref |], offset
    | PyShortAscii arr -> arr, offset
    | PyShortAsciiInterned arr -> arr, offset
    | _ -> failwithf "Invalid Python Type(%A)" pyObj

  let inline parsePyTypeObjectToREF offset =
    let pyObj, offset = parsePyType bytes reader offset
    match pyObj with
    | PyREF ref as p -> p, offset
    | _ -> failwithf "Invalid Python Type(%A)" pyObj

  let pyType, offset = getPyType bytes reader offset
  match pyType with
  | PyType.TYPE_CODE ->
    let argCout, offset = readAndOffset bytes reader offset 4
    let posonlyArgCout, offset = readAndOffset bytes reader offset 4
    let kwonposonlyArgCout, offset = readAndOffset bytes reader offset 4
    let stackSize, offset = readAndOffset bytes reader offset 4
    let flags, offset = readAndOffset bytes reader offset 4
    let code, codeOffset, offset =
      let codeSize, offset = parsePyType bytes reader offset
      let codeSize =
        match codeSize with
        | PyString str -> int str
        | _ -> raise ParsingFailureException
      Array.sub bytes offset codeSize, offset, (offset + codeSize)
    let consts, offset = parsePyTypeObject offset
    let names, offset = parsePyTypeObject offset
    let localsplusnames, offset = parsePyTypeObject offset
    let localspluskinds, offset = parsePyTypeObjectToByteArr offset
    let filenames, offset = parsePyTypeObjectToByteArr offset
    let name, offset = parsePyTypeObjectToByteArr offset
    let qname, offset = parsePyTypeObjectToREF offset
    let fstline, offset = readAndOffset bytes reader offset 4
    let linetbl, offset = parsePyTypeObjectToByteArr offset
    let exceptbl, offset = parsePyTypeObjectToByteArr offset
    let con = {
      FileName = System.Text.Encoding.ASCII.GetString (filenames)
      Name = System.Text.Encoding.ASCII.GetString (name)
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
    PyCode con, offset
  | PyType.TYPE_STRING ->
    let str, offset = readAndOffset bytes reader offset 4
    PyString (string str), offset
  | PyType.TYPE_INT ->
    let int, offset = readAndOffset bytes reader offset 4
    PyInt int, offset
  | PyType.TYPE_NONE -> PyNone, offset
  | PyType.TYPE_SMALL_TUPLE ->
    let size, offset = readAndOffset bytes reader offset 1
    if size <> 0 then
      let rec loop acc offset =
        if List.length acc = size then acc, offset
        else
          let contents, offset = parsePyType bytes reader offset
          loop (contents :: acc) offset
      let tuples, offset = loop [] offset
      PyTuple (tuples |> List.toArray), offset
    else PyTuple [||], offset
  | PyType.TYPE_SHORT_ASCII | PyType.TYPE_SHORT_ASCII_INTERNED ->
    let n, offset = readAndOffset bytes reader offset 1
    PyShortAsciiInterned (Array.sub bytes offset n), offset + n
  | PyType.TYPE_REF ->
    let n, offset = readAndOffset bytes reader offset 4
    PyREF n, offset
  | _ -> printf "%A " pyType; failwith "Invalid parsePyType"

let parseCodeObject bytes reader = parsePyType bytes reader 16

let getSections codeObjs =
  let rec extractCodeInfo (pyObj: PyCodeObject): (int * int * string) list =
    match pyObj with
    | PyCode code ->
      let current =
        let (offset, bytes) = code.Code
        (offset, bytes.Length, code.Name)
      let nested =
        code.Consts
        |> Array.toList
        |> List.collect extractCodeInfo
      current :: nested
    | _ -> []
  extractCodeInfo codeObjs |> List.toArray
