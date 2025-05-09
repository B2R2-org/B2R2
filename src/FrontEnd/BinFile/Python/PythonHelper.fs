﻿(*
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

open B2R2
open B2R2.FrontEnd.BinLifter

let defaultPyCodeCon = {
  FileName = "Default"
  Name = "Default"
  QualName = "Default"
  Flags = 0
  Code = 0UL, PyNone
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

[<Literal>]
let PyMagic = 0x0A0D0DCBu

let getEntryPoint () = Some 0UL

let isPython (bytes: byte[]) (reader: IBinReader) =
  if bytes.Length >= 4 then reader.ReadUInt32 (bytes, 0) = PyMagic
  else false

let parseMagic (bytes: byte[]) (reader: IBinReader) =
  reader.ReadUInt32 (bytes, 0)

let getFlagAndPyType (bytes: byte[]) (reader: IBinReader) offset =
  let byte = reader.ReadUInt8 (bytes, offset) |> int
  let flag = byte &&& 0x80
  let pyType =
    (byte &&& (~~~ 0x80)) |> LanguagePrimitives.EnumOfValue
  flag, pyType, offset + 1

let rec pyObjToString = function
  | PyString s ->  System.Text.Encoding.ASCII.GetString s
  | PyAscii str | PyShortAsciiInterned str | PyShortAscii str -> str
  | PyInt i -> i.ToString()
  | PyREF (n, r) -> r.ToString() + "(" + (n.ToString()) + ")"
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

let private appendRefs flag refs obj =
  if flag <> 0 then
    let refs = Array.append refs [| obj |]
    //printfn "flag: %X, refcnt: %d, pyobj: %A" flag (Array.length refs) obj
    refs
  else refs

let rec parsePyType (bytes: byte[]) (reader: IBinReader) refs offset =
  //printfn "offset in 0x%X(%d)(%d), refs %d"
  //  offset offset (offset - 16) (Array.length refs)
  let flag, pyType, offset = getFlagAndPyType bytes reader offset
  //printfn "offset out 0x%X, type 0x%X, flag %x" offset (int pyType) flag
  //Array.iteri (printf"[%d] %A; ") refs
  //printfn "\n"
  match pyType with
  | PyType.TYPE_CODE ->
    let refs = appendRefs flag refs "None" (* Reserve *)
    let argCout, offset = readAndOffset bytes reader offset 4
    let posonlyArgCout, offset = readAndOffset bytes reader offset 4
    let kwonposonlyArgCout, offset = readAndOffset bytes reader offset 4
    let stackSize, offset = readAndOffset bytes reader offset 4
    let flags, offset = readAndOffset bytes reader offset 4
    let codeOffset = offset + 5 |> uint64
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
      QualName = pyObjToString qname
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
    let bytes = Array.sub bytes offset size
    let str =
      Array.map (sprintf "0x%X") bytes
      |> String.concat ", "
    PyString bytes, appendRefs flag refs str, offset + size
  | PyType.TYPE_INT ->
    let i, offset = readAndOffset bytes reader offset 4
    PyInt i, appendRefs flag refs (i.ToString()), offset
  | PyType.TYPE_NONE -> PyNone, refs, offset
  | PyType.TYPE_SMALL_TUPLE ->
    let size, offset = readAndOffset bytes reader offset 1
    let str =
      if size = 0 then "()"
      else Array.create size "<Null>" |> String.concat ", "
    let refs = appendRefs flag refs str
    if size <> 0 then
      let rec loop acc refs offset =
        if List.length acc = size then acc, refs, offset
        else
          let contents, refs, offset = parsePyType bytes reader refs offset
          loop (contents :: acc) refs offset
      let tuples, refs, offset = loop [] refs offset
      PyTuple (tuples |> List.toArray |> Array.rev), refs, offset
    else PyTuple [||], refs, offset
  | PyType.TYPE_ASCII ->
    let n, offset = readAndOffset bytes reader offset 4
    let str = Array.sub bytes offset n |> System.Text.Encoding.ASCII.GetString
    PyAscii str, appendRefs flag refs str, offset + n
  | PyType.TYPE_SHORT_ASCII | PyType.TYPE_SHORT_ASCII_INTERNED ->
    let n, offset = readAndOffset bytes reader offset 1
    let str = Array.sub bytes offset n |> System.Text.Encoding.ASCII.GetString
    PyShortAsciiInterned str, appendRefs flag refs str, offset + n
  | PyType.TYPE_REF ->
    let n, offset = readAndOffset bytes reader offset 4
    //printfn "[TYPE_REF] len %d, n %d, %A" (Array.length refs) n refs
    PyREF (n, refs[n]), refs, offset
  | PyType.TYPE_FALSE -> PyFalse, appendRefs flag refs "PyFalse", offset
  | _ -> printf "%A " pyType; failwith "Invalid parsePyType"

let parseCodeObject bytes reader =
  let pyObject, refs, _ = parsePyType bytes reader [||] 16
  //printfn "%A" pyObject
  //Array.iteri (printfn "[%d] %A") refs
  pyObject

let private getCodeLen = function
  | PyString bytes -> Array.length bytes |> uint64
  | _ -> 0UL

let extractConsts pyObj =
  let rec collect acc = function
    | PyCode code ->
      let addr, codeObj = code.Code
      let len = getCodeLen codeObj
      let addrRange = AddrRange (addr, addr + len)
      match code.Consts with
      | PyTuple t -> Array.fold collect ((addrRange, t) :: acc) t
      | c -> collect acc c
    | _ -> acc
  collect [] pyObj |> List.toArray

let extractVarNames pyObj =
  let rec collect acc = function
    | PyCode code ->
      let addr, codeObj = code.Code
      let len = getCodeLen codeObj
      let addrRange = AddrRange (addr, addr + len)
      let acc =
        match code.LocalPlusNames with
        | PyTuple t -> (addrRange, t) :: acc
        | PyREF _ as ref -> (addrRange, [| ref |]) :: acc
        | o -> failwithf "Invalid PyCodeObject(%A)" o
      match code.Consts with
      | PyTuple t -> Array.fold collect acc t
      | PyREF _ as ref -> (addrRange, [| ref |]) :: acc
      | o -> failwithf "Invalid PyCodeObject(%A)" o
    | _ -> acc
  collect [] pyObj |> List.toArray

let extractNames pyObj =
  let rec collect acc = function
    | PyCode code ->
      let addr, codeObj = code.Code
      let len = getCodeLen codeObj
      let addrRange = AddrRange (addr, addr + len)
      let acc =
        match code.Names with
        | PyTuple t -> (addrRange, t) :: acc
        | PyREF _ as ref -> (addrRange, [| ref |]) :: acc
        | o -> failwithf "Invalid PyCodeObject(%A)" o
      match code.Consts with
      | PyTuple t -> Array.fold collect acc t
      | PyREF _ as ref -> (addrRange, [| ref |]) :: acc
      | o -> failwithf "Invalid PyCodeObject(%A)" o
    | _ -> acc
  collect [] pyObj |> List.toArray

let getSections codeObjs =
  let rec extractCodeInfo (pyObj: PyCodeObject) =
    match pyObj with
    | PyCode code ->
      let current =
        let (addr, pyObj) = code.Code
        match pyObj with
        | PyString s -> addr, s.Length, code.Name
        | o -> failwithf "Invalid PyCodeObject(%A)" o
      let nested =
        match code.Consts with
        | PyTuple t ->
          t |> Array.toList
          |> List.collect extractCodeInfo
        | PyREF _ -> []
        | o -> failwithf "Invalid PyCodeObject(%A)" o
      current :: nested
    | _ -> []
  extractCodeInfo codeObjs |> List.toArray
