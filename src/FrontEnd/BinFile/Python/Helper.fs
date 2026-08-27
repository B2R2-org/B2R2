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

open System.Collections.Generic
open B2R2
open B2R2.FrontEnd.BinLifter

type private PyMagic =
  | PyMagic300 = 0x0A0D0C3Bu (* 3.0: 3131 *)
  | PyMagic301 = 0x0A0D0C4Fu (* 3.1: 3151 *)
  | PyMagic302 = 0x0A0D0C6Cu (* 3.2: 3180 *)
  | PyMagic303 = 0x0A0D0C9Eu (* 3.3: 3230 *)
  | PyMagic304 = 0x0A0D0CEEu (* 3.4: 3310 *)
  | PyMagic305 = 0x0A0D0D17u (* 3.5: 3351 *)
  | PyMagic306 = 0x0A0D0D33u (* 3.6: 3379 *)
  | PyMagic307 = 0x0A0D0D42u (* 3.7: 3394 *)
  | PyMagic308 = 0x0A0D0D55u (* 3.8: 3413 *)
  | PyMagic309 = 0x0A0D0D61u (* 3.9: 3425 *)
  | PyMagic310 = 0x0A0D0D6Fu (* 3.10: 3439 *)
  | PyMagic311 = 0x0A0D0DA7u (* 3.11: 3495 *)
  | PyMagic312 = 0x0A0D0DCBu (* 3.12: 3531 *)
  | PyMagic313 = 0x0A0D0DF3u (* 3.13: 3571 *)
  | PyMagic314 = 0x0A0D0E2Bu (* 3.14: 3627 *)
  | PyMagic315 = 0x0A0D0E52u (* 3.15: 3666 *)

let isPythonBytecode (bytes: byte[]) (reader: IBinReader) =
  if bytes.Length >= 4 then
    let m = reader.ReadUInt32(bytes, 0)
    PyMagic.IsDefined(typeof<PyMagic>, m)
  else
    false

/// The magic number a version's files start with. The reverse of
/// getVersionFromMagicNumber, for anything that writes a .pyc rather than
/// reads one; the case names carry the version, so there is no second table
/// here to fall out of step with the first.
let magicNumberOf (version: PythonVersion) =
  match System.Enum.TryParse<PyMagic>("PyMagic" + string (int version)) with
  | true, m -> Some(LanguagePrimitives.EnumToValue m)
  | _ -> None

let private readFlagAndMarshalledType (bytes: byte[])
                                      (reader: IBinReader)
                                      offset =
  let b = reader.ReadUInt8(bytes, offset) |> int
  let flag = b &&& 0x80
  let typ: MarshalledType = (b &&& (~~~0x80)) |> LanguagePrimitives.EnumOfValue
  struct (flag, typ, offset + 1)

let rec private pyObjToString = function
  | PyString s ->
    System.Text.Encoding.ASCII.GetString s
  | PyAscii str | PySurrogateText(str, _)
  | PyShortAsciiInterned str | PyShortAscii str ->
    str
  | PyInt i ->
    i.ToString()
  | PyLong s ->
    s
  | PyFloat f ->
    f.ToString()
  | PyREF(_, r) ->
    pyObjToString r
  | PyTuple t ->
    let t = Array.map pyObjToString t
    String.concat ", " t
  | PyNone ->
    "None"
  | PyTrue ->
    "True"
  | PyFalse ->
    "False"
  | PyCode c ->
    c.Name
  | o ->
    failwithf "Error PyObjToString (%A)" o

let private readInt (bytes: byte[]) (reader: IBinReader) offset size =
  match size with
  | 1 -> reader.ReadUInt8(bytes, offset) |> int, offset + size
  | 4 -> reader.ReadUInt32(bytes, offset) |> int, offset + size
  | _ -> failwithf "Invalid size %d" size

let private readFloat (bytes: byte[]) (reader: IBinReader) offset size =
  match size with
  | 4 ->
    let f = bytes[offset..offset + 3] |> System.BitConverter.ToSingle
    double f, offset + size
  | 8 ->
    let f = bytes[offset..offset + 7] |> System.BitConverter.ToDouble
    f, offset + size
  | _ ->
    failwithf "Invalid size %d" size

let private appendRefs flag refs obj =
  if flag <> 0 then Array.append refs [| obj |] else refs

/// Decodes marshal's UTF-8. CPython writes str with the `surrogatepass`
/// error handler, so a lone surrogate -- legal in a Python str, and present
/// in CPython's own test data -- is stored as the three bytes that encode it.
/// .NET's UTF8 decoder rejects those and substitutes U+FFFD, which destroys
/// the code point: the constant then reads as replacement characters and no
/// consumer can recover what the file said. Decoding by hand keeps it.
/// Reports where the lone surrogates ended up as well, since that is the one
/// thing the decoded string can no longer be asked: two of them side by side
/// are indistinguishable from the one astral character they spell.
let private decodeMarshalledUtf8 (bs: byte[]) =
  let sb = System.Text.StringBuilder(bs.Length)
  let lone = ResizeArray()
  let mutable i = 0
  while i < bs.Length do
    let b0 = int bs[i]
    if b0 < 0x80 then
      sb.Append(char b0) |> ignore
      i <- i + 1
    elif b0 &&& 0xE0 = 0xC0 && i + 1 < bs.Length then
      sb.Append(char (((b0 &&& 0x1F) <<< 6) ||| (int bs[i + 1] &&& 0x3F)))
      |> ignore
      i <- i + 2
    elif b0 &&& 0xF0 = 0xE0 && i + 2 < bs.Length then
      (* This is the case that matters: a code point in D800-DFFF lands here
         and stays a lone surrogate, which a .NET string can hold. *)
      let cp =
        ((b0 &&& 0x0F) <<< 12)
        ||| ((int bs[i + 1] &&& 0x3F) <<< 6)
        ||| (int bs[i + 2] &&& 0x3F)
      if cp >= 0xD800 && cp <= 0xDFFF then lone.Add sb.Length else ()
      sb.Append(char cp) |> ignore
      i <- i + 3
    elif b0 &&& 0xF8 = 0xF0 && i + 3 < bs.Length then
      let cp =
        ((b0 &&& 0x07) <<< 18)
        ||| ((int bs[i + 1] &&& 0x3F) <<< 12)
        ||| ((int bs[i + 2] &&& 0x3F) <<< 6)
        ||| (int bs[i + 3] &&& 0x3F)
      sb.Append(System.Char.ConvertFromUtf32 cp) |> ignore
      i <- i + 4
    else
      sb.Append '�' |> ignore
      i <- i + 1
  sb.ToString(), lone.ToArray()

/// Returns the number of bytes before the marshalled code object. 3.3 added
/// a source-size field and 3.7 added PEP 552's bit field, so this is not one
/// constant: reading a pre-3.7 file at 16 lands four bytes inside the code
/// object, and marshal then reports bad data rather than a bad offset.
let headerSize (version: PythonVersion) =
  if int version >= 307 then 16 elif int version >= 303 then 12 else 8

let private isLegacyCodeObjectVersion = function
  | PythonVersion.Python300
  | PythonVersion.Python301
  | PythonVersion.Python302
  | PythonVersion.Python303
  | PythonVersion.Python304
  | PythonVersion.Python305
  | PythonVersion.Python306
  | PythonVersion.Python307
  | PythonVersion.Python308
  | PythonVersion.Python309
  | PythonVersion.Python310 -> true
  | _ -> false

(* co_posonlyargcount only exists from 3.8 (PEP 570). Reading it
   unconditionally shifts every later field by four bytes on 3.5-3.7. *)
let private hasPosOnlyArgCount (version: PythonVersion) = int version >= 308

let private unwrapRef = function
  | PyREF(_, o) -> o
  | o -> o

(* A code object's "code" field (its raw co_code bytes) is almost always a
   literal TYPE_STRING right here, so its content starts exactly 5 bytes
   past `offset` (1 flag+type byte + 4 length bytes) -- the assumption the
   caller used to make unconditionally. But when two code objects share
   byte-identical bytecode, CPython's marshal writer can instead emit the
   second one's "code" field as a TYPE_REF backreference to the first's
   already-written string, which has no inline bytes of its own at all: the
   real content lives wherever THAT ref index was first recorded (see
   `refPositions`, populated at every TYPE_STRING site below). Peeking here
   (without consuming) lets the two shapes resolve to the correct address
   either way, instead of pointing 5 bytes into an unrelated TYPE_REF's own
   encoding when the backreference case hits. *)
let private peekCodeOffset (bytes: byte[])
                           (reader: IBinReader)
                           offset
                           (refPositions: Dictionary<int, uint64>) =
  let b = reader.ReadUInt8(bytes, offset) |> int
  let typ: MarshalledType = (b &&& (~~~0x80)) |> LanguagePrimitives.EnumOfValue
  if typ = MarshalledType.TYPE_REF then
    let n, _ = readInt bytes reader (offset + 1) 4
    refPositions[n]
  else
    offset + 5 |> uint64

let rec parse version
              (bytes: byte[])
              (reader: IBinReader)
              refs
              offset
              (refPositions: Dictionary<int, uint64>) =
  let parseNext refs offset =
    parse version bytes reader refs offset refPositions
  let struct (flag, pyType, offset) =
    readFlagAndMarshalledType bytes reader offset
  match pyType with
  | MarshalledType.TYPE_CODE ->
    let refs = appendRefs flag refs PyNone (* Reserve *)
    let argCnt, offset = readInt bytes reader offset 4
    let posonlyArgCnt, offset =
      if hasPosOnlyArgCount version then readInt bytes reader offset 4
      else 0, offset
    let kwonposonlyArgCnt, offset = readInt bytes reader offset 4
    if isLegacyCodeObjectVersion version then
      let _, offset = readInt bytes reader offset 4 (* nlocals *)
      let stackSize, offset = readInt bytes reader offset 4
      let flags, offset = readInt bytes reader offset 4
      let codeOffset = peekCodeOffset bytes reader offset refPositions
      let code, refs, offset = parseNext refs offset
      let consts, refs, offset = parseNext refs offset
      let names, refs, offset = parseNext refs offset
      let varnames, refs, offset = parseNext refs offset
      let freevars, refs, offset = parseNext refs offset
      let cellvars, refs, offset = parseNext refs offset
      let filenames, refs, offset = parseNext refs offset
      let name, refs, offset = parseNext refs offset
      let fstline, offset = readInt bytes reader offset 4
      let linetbl, refs, offset = parseNext refs offset
      (* LOAD_CLOSURE/LOAD_DEREF/etc. index into `cellvars ++ freevars`, not
         co_varnames -- see FreeVars' own doc comment on PyCodeObject. *)
      let cellVarCount =
        match unwrapRef cellvars with
        | PyTuple c -> c.Length
        | _ -> 0
      let combinedFreeVars =
        match unwrapRef cellvars, unwrapRef freevars with
        | PyTuple c, PyTuple f -> PyTuple(Array.append c f)
        | PyTuple c, _ -> PyTuple c
        | _, PyTuple f -> PyTuple f
        | _ -> PyTuple [||]
      let codeObject =
        { FileName = pyObjToString filenames
          Name = pyObjToString name
          QualName = pyObjToString name
          Flags = flags
          Code = codeOffset, code
          FirstLineNo = fstline
          LineTable = linetbl
          Consts = consts
          Names = names
          LocalPlusNames = varnames
          LocalPlusKinds = PyTuple [||]
          ArgCount = argCnt
          PosonlyArgCount = posonlyArgCnt
          KwonlyArgCount = kwonposonlyArgCnt
          StackSize = stackSize
          ExceptionTable = PyTuple [||]
          FreeVars = combinedFreeVars
          CellVarCount = cellVarCount }
      PyCode codeObject, refs, offset
    else
      let stackSize, offset = readInt bytes reader offset 4
      let flags, offset = readInt bytes reader offset 4
      let codeOffset = peekCodeOffset bytes reader offset refPositions
      let code, refs, offset = parseNext refs offset
      let consts, refs, offset = parseNext refs offset
      let names, refs, offset = parseNext refs offset
      let localsplusnames, refs, offset = parseNext refs offset
      let localspluskinds, refs, offset = parseNext refs offset
      let filenames, refs, offset = parseNext refs offset
      let name, refs, offset = parseNext refs offset
      let qname, refs, offset = parseNext refs offset
      let fstline, offset = readInt bytes reader offset 4
      let linetbl, refs, offset = parseNext refs offset
      let exceptbl, refs, offset = parseNext refs offset
      let codeObject =
        { FileName = pyObjToString filenames
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
          ArgCount = argCnt
          PosonlyArgCount = posonlyArgCnt
          KwonlyArgCount = kwonposonlyArgCnt
          StackSize = stackSize
          ExceptionTable = exceptbl
          FreeVars = PyTuple [||]
          CellVarCount = 0 }
      PyCode codeObject, refs, offset
  | MarshalledType.TYPE_STRING ->
    let size, offset = readInt bytes reader offset 4
    let bs = Array.sub bytes offset size
    (* Record where this string's actual content starts, keyed by the ref
       slot it is about to occupy, so a later TYPE_REF pointing back to it
       (see peekCodeOffset) can resolve to the real address instead of
       guessing "5 bytes past the backreference's own encoding". *)
    if flag <> 0 then refPositions[Array.length refs] <- uint64 offset else ()
    PyString bs, appendRefs flag refs (PyString bs), offset + size
  | MarshalledType.TYPE_INT ->
    let i, offset = readInt bytes reader offset 4
    PyInt i, appendRefs flag refs (PyInt i), offset
  (* TYPE_LONG: an arbitrary-precision int, marshaled as a signed 32-bit
     digit count n (its sign is the value's sign; |n| is the digit count),
     followed by |n| little-endian 16-bit "digits" holding 15 bits apiece
     (mirrors CPython's marshal.c w_long/r_PyLong -- and CPython uses this
     for every `int` object except ones that fit the fixed-width TYPE_INT
     case above). Rendered straight to its decimal repr string so nothing
     downstream needs bignum arithmetic (see PyLong's own doc comment). *)
  | MarshalledType.TYPE_LONG ->
    let n, offset = readInt bytes reader offset 4
    let digitCount = abs n
    let mutable value = System.Numerics.BigInteger.Zero
    let mutable offset = offset
    for i in 0 .. digitCount - 1 do
      let digit = reader.ReadUInt16(bytes, offset) |> int
      value <- value + (System.Numerics.BigInteger digit
                         <<< (15 * i))
      offset <- offset + 2
    let value = if n < 0 then -value else value
    let s = value.ToString()
    PyLong s, appendRefs flag refs (PyLong s), offset
  | MarshalledType.TYPE_FLOAT ->
    let len = bytes[offset] |> int
    let bs = Array.sub bytes (offset + 1) len
    let str = System.Text.Encoding.ASCII.GetString bs
    PyFloat str, appendRefs flag refs (PyFloat str), offset + 1 + len
  | MarshalledType.TYPE_BINARY_FLOAT ->
    let f, offset = readFloat bytes reader offset 8
    PyBinaryFloat f, appendRefs flag refs (PyBinaryFloat f), offset
  (* Same layout as TYPE_FLOAT, twice in a row: the real part, then the
     imaginary part, each its own length-prefixed repr string. *)
  | MarshalledType.TYPE_COMPLEX ->
    let realLen = bytes[offset] |> int
    let real =
      Array.sub bytes (offset + 1) realLen
      |> System.Text.Encoding.ASCII.GetString
    let offset = offset + 1 + realLen
    let imagLen = bytes[offset] |> int
    let imag =
      Array.sub bytes (offset + 1) imagLen
      |> System.Text.Encoding.ASCII.GetString
    let offset = offset + 1 + imagLen
    let obj = PyComplex(real, imag)
    obj, appendRefs flag refs obj, offset
  (* Same layout as TYPE_BINARY_FLOAT, twice in a row: the real part, then
     the imaginary part, each an 8-byte double. *)
  | MarshalledType.TYPE_BINARY_COMPLEX ->
    let real, offset = readFloat bytes reader offset 8
    let imag, offset = readFloat bytes reader offset 8
    let obj = PyBinaryComplex(real, imag)
    obj, appendRefs flag refs obj, offset
  (* Three sub-objects in order, mirroring r_object's TYPE_SLICE case. Like a
     tuple it reserves its own slot before reading them, so the children take
     the indices after it rather than before -- appending afterwards shifts
     every later reference by one. *)
  | MarshalledType.TYPE_SLICE ->
    let refIdx = Array.length refs
    let refs = appendRefs flag refs PyNone
    let start, refs, offset =
      parse version bytes reader refs offset refPositions
    let stop, refs, offset = parse version bytes reader refs offset refPositions
    let step, refs, offset = parse version bytes reader refs offset refPositions
    let obj = PySlice(start, stop, step)
    if flag <> 0 then refs[refIdx] <- obj else ()
    obj, refs, offset
  | MarshalledType.TYPE_NONE ->
    PyNone, refs, offset
  | MarshalledType.TYPE_ELLIPSIS ->
    PyEllipsis, refs, offset
  | MarshalledType.TYPE_SMALL_TUPLE ->
    let size, offset = readInt bytes reader offset 1
    if size = 0 then
      let refs = appendRefs flag refs (PyTuple [||])
      PyTuple [||], refs, offset
    else
      let refIdx = Array.length refs
      let refs = appendRefs flag refs PyNone
      let rec loop acc refs offset =
        if List.length acc = size then
          acc, refs, offset
        else
          let contents, refs, offset = parseNext refs offset
          loop (contents :: acc) refs offset
      let tuples, refs, offset = loop [] refs offset
      let arr = tuples |> List.toArray |> Array.rev
      if flag <> 0 then refs[refIdx] <- PyTuple arr else ()
      PyTuple arr, refs, offset
  (* Same shape as TYPE_SMALL_TUPLE, but with a 4-byte size prefix -- used
     once a tuple's item count no longer fits in a single byte (256+). *)
  | MarshalledType.TYPE_TUPLE ->
    let size, offset = readInt bytes reader offset 4
    if size = 0 then
      let refs = appendRefs flag refs (PyTuple [||])
      PyTuple [||], refs, offset
    else
      let refIdx = Array.length refs
      let refs = appendRefs flag refs PyNone
      let rec loop acc refs offset =
        if List.length acc = size then
          acc, refs, offset
        else
          let contents, refs, offset = parseNext refs offset
          loop (contents :: acc) refs offset
      let tuples, refs, offset = loop [] refs offset
      let arr = tuples |> List.toArray |> Array.rev
      if flag <> 0 then refs[refIdx] <- PyTuple arr else ()
      PyTuple arr, refs, offset
  (* Same shape as TYPE_SMALL_TUPLE, but with a 4-byte size prefix (there is
     no "small" variant for frozensets in the marshal format). *)
  | MarshalledType.TYPE_FROZENSET ->
    let size, offset = readInt bytes reader offset 4
    if size = 0 then
      let refs = appendRefs flag refs (PyFrozenSet [||])
      PyFrozenSet [||], refs, offset
    else
      let refIdx = Array.length refs
      let refs = appendRefs flag refs PyNone
      let rec loop acc refs offset =
        if List.length acc = size then
          acc, refs, offset
        else
          let contents, refs, offset = parseNext refs offset
          loop (contents :: acc) refs offset
      let items, refs, offset = loop [] refs offset
      let arr = items |> List.toArray |> Array.rev
      if flag <> 0 then refs[refIdx] <- PyFrozenSet arr else ()
      PyFrozenSet arr, refs, offset
  (* TYPE_ASCII_INTERNED differs from TYPE_ASCII only in that the reader is
     asked to intern the result, which is a runtime concern with no bearing
     on the encoding -- see r_object in CPython's marshal.c, where the two
     share a case. Same for TYPE_INTERNED against TYPE_UNICODE below. *)
  | MarshalledType.TYPE_ASCII
  | MarshalledType.TYPE_ASCII_INTERNED ->
    let n, offset = readInt bytes reader offset 4
    let str = Array.sub bytes offset n |> System.Text.Encoding.ASCII.GetString
    PyAscii str, appendRefs flag refs (PyAscii str), offset + n
  (* Same layout as TYPE_ASCII, but the payload may contain non-ASCII text,
     so it must be decoded as UTF-8 instead. *)
  | MarshalledType.TYPE_UNICODE
  | MarshalledType.TYPE_INTERNED ->
    let n, offset = readInt bytes reader offset 4
    let str, lone = Array.sub bytes offset n |> decodeMarshalledUtf8
    let obj =
      if Array.isEmpty lone then PyAscii str else PySurrogateText(str, lone)
    obj, appendRefs flag refs obj, offset + n
  | MarshalledType.TYPE_SHORT_ASCII
  | MarshalledType.TYPE_SHORT_ASCII_INTERNED ->
    let n, offset = readInt bytes reader offset 1
    let str = Array.sub bytes offset n |> System.Text.Encoding.ASCII.GetString
    let str = PyShortAsciiInterned str
    str, appendRefs flag refs str, offset + n
  | MarshalledType.TYPE_REF ->
    let n, offset = readInt bytes reader offset 4
    refs[n], refs, offset
  | MarshalledType.TYPE_TRUE ->
    PyTrue, appendRefs flag refs PyTrue, offset
  | MarshalledType.TYPE_FALSE ->
    PyFalse, appendRefs flag refs PyFalse, offset
  | _ ->
    printf "%A " pyType; failwith "Invalid parse"

let private getCodeLen = function
  | PyString bytes -> Array.length bytes |> uint64
  | _ -> 0UL

/// Every code object reachable from one, itself first and then whatever its
/// constants hold. A nested code object arrives either directly or behind a
/// reference, and either way it is walked.
let private collectCodeObjects (root: PyCodeObject) =
  let allCodeObjs = ResizeArray<PyCodeObject>()
  let rec collectConstsObj = function
    | PyCode nested -> collect nested
    | PyREF(_, obj) -> collectConstsObj obj
    | _ -> ()
  and collect (co: PyCodeObject) =
    allCodeObjs.Add co
    match co.Consts with
    | PyTuple objs -> Array.iter collectConstsObj objs
    | PyREF(_, PyTuple objs) -> Array.iter collectConstsObj objs
    | _ -> ()
  collect root
  allCodeObjs

/// The same tree with every remapped code object standing at the address it
/// was given. Objects that were not remapped are rebuilt as they were, so
/// that a constant holding a rebuilt object names the rebuilt one.
let private rebuildWithRemap (remap: Dictionary<PyCodeObject, Addr>) root =
  let rec rebuildConstsObj = function
    | PyCode nested -> PyCode(rebuild nested)
    | PyREF(n, obj) -> PyREF(n, rebuildConstsObj obj)
    | other -> other
  and rebuild (co: PyCodeObject) =
    let newConsts =
      match co.Consts with
      | PyTuple objs ->
        PyTuple(Array.map rebuildConstsObj objs)
      | PyREF(n, PyTuple objs) ->
        PyREF(n, PyTuple(Array.map rebuildConstsObj objs))
      | other ->
        other
    match remap.TryGetValue co with
    | true, newAddr ->
      { co with Code = (newAddr, snd co.Code); Consts = newConsts }
    | false, _ ->
      { co with Consts = newConsts }
  rebuild root

(* Pre-3.11 marshal dedups a code object's `co_code` string by identity:
   the SECOND (and later) occurrence of a byte-identical `co_code` is
   written as a TYPE_REF backreference to the first's already-written
   bytes, rather than repeating them, whenever two DIFFERENT Python
   functions happen to compile to byte-identical bytecode (e.g. two
   `def f(): l = [... for ... if ...]; return l` comprehensions,
   differing only inside their own nested listcomp -- confirmed via
   `comprehension_1`/`comprehension_2` in a Python 3.10 build of
   regression.py). B2R2 addresses a function purely by its bytecode's
   file offset, so two code objects sharing one offset this way become
   indistinguishable everywhere downstream (CFG recovery, lifting,
   B2P2's own decompiler) -- there being only one physical instruction
   stream at that address, no per-consumer disambiguation downstream can
   ever recover which of the two a given reference inside it meant.
   Restores the address<->function invariant every other B2R2 pass
   already assumes, before any of them ever run: walks the whole parsed
   tree, and for every code object PAST THE FIRST to claim a given
   address, appends a fresh copy of that exact `co_code` byte range past
   the end of the file and rewrites its own `Code` address to point
   there instead -- giving it a real, distinct, otherwise-identical
   address of its own. Returns the extended byte buffer (which the
   caller must use as the file's own bytes/address space from here on)
   together with the corrected tree. *)
let deduplicateCodeOffsets (bytes: byte[]) (root: PyCodeObject) =
  let allCodeObjs = collectCodeObjects root
  let seenAddrs = HashSet<Addr>()
  let remap = Dictionary<PyCodeObject, Addr>(HashIdentity.Reference)
  let appended = ResizeArray<byte>()
  let mutable nextAddr = uint64 bytes.Length
  for co in allCodeObjs do
    let addr = fst co.Code
    if seenAddrs.Contains addr then
      let codeBytes =
        match snd co.Code with
        | PyString b -> b
        | _ -> [||]
      remap[co] <- nextAddr
      appended.AddRange codeBytes
      nextAddr <- nextAddr + uint64 codeBytes.Length
    else
      seenAddrs.Add addr |> ignore
  if appended.Count = 0 then
    bytes, root
  else
    let newRoot = rebuildWithRemap remap root
    let newBytes = Array.append bytes (appended.ToArray())
    newBytes, newRoot

let extractConsts pyObj =
  let rec collect acc = function
    | PyCode code ->
      let addr, codeObj = code.Code
      let len = getCodeLen codeObj
      let addrRange = AddrRange.create addr (addr + len)
      match code.Consts with
      | PyTuple t ->
        let t' = Array.map unwrapRef t
        Array.fold collect ((addrRange, t') :: acc) t'
      | PyREF(_, PyTuple t) ->
        let t' = Array.map unwrapRef t
        Array.fold collect ((addrRange, t') :: acc) t'
      | c ->
        collect acc c
    | _ ->
      acc
  collect [] pyObj |> List.toArray

let extractVarNames pyObj =
  let rec collect acc = function
    | PyCode code ->
      let addr, codeObj = code.Code
      let len = getCodeLen codeObj
      let addrRange = AddrRange.create addr (addr + len)
      let acc =
        match code.LocalPlusNames with
        | PyTuple t -> (addrRange, t) :: acc
        | PyREF(_, PyTuple t) -> (addrRange, t) :: acc
        | PyREF _ as ref -> (addrRange, [| ref |]) :: acc
        | o -> failwithf "Invalid PyCodeObject(%A)" o
      match code.Consts with
      | PyTuple t -> Array.fold collect acc t
      | PyREF _ as ref -> (addrRange, [| ref |]) :: acc
      | o -> failwithf "Invalid PyCodeObject(%A)" o
    | _ ->
      acc
  collect [] pyObj |> List.toArray

/// Pre-3.11 code objects only -- see FreeVars' own doc comment on
/// PyCodeObject for why LOAD_CLOSURE/LOAD_DEREF/etc. need this table
/// instead of the LocalPlusNames one extractVarNames above builds.
let extractFreeVars pyObj =
  let rec collect acc = function
    | PyCode code ->
      let addr, codeObj = code.Code
      let len = getCodeLen codeObj
      let addrRange = AddrRange.create addr (addr + len)
      let acc =
        match code.FreeVars with
        | PyTuple t -> (addrRange, t) :: acc
        | PyREF(_, PyTuple t) -> (addrRange, t) :: acc
        | PyREF _ as ref -> (addrRange, [| ref |]) :: acc
        | o -> failwithf "Invalid PyCodeObject(%A)" o
      match code.Consts with
      | PyTuple t -> Array.fold collect acc t
      | PyREF _ as ref -> (addrRange, [| ref |]) :: acc
      | o -> failwithf "Invalid PyCodeObject(%A)" o
    | _ ->
      acc
  collect [] pyObj |> List.toArray

let extractNames pyObj =
  let rec collect acc = function
    | PyCode code ->
      let addr, codeObj = code.Code
      let len = getCodeLen codeObj
      let addrRange = AddrRange.create addr (addr + len)
      let acc =
        match code.Names with
        | PyTuple t -> (addrRange, t) :: acc
        | PyREF(_, PyTuple t) -> (addrRange, t) :: acc
        | PyREF _ as ref -> (addrRange, [| ref |]) :: acc
        | o -> failwithf "Invalid PyCodeObject(%A)" o
      match code.Consts with
      | PyTuple t -> Array.fold collect acc t
      | PyREF _ as ref -> (addrRange, [| ref |]) :: acc
      | o -> failwithf "Invalid PyCodeObject(%A)" o
    | _ ->
      acc
  collect [] pyObj |> List.toArray

let getVersionFromMagicNumber (magic: uint32) =
  if System.Enum.IsDefined(typeof<PyMagic>, magic) then
      match LanguagePrimitives.EnumOfValue magic with
      | PyMagic.PyMagic300 -> PythonVersion.Python300
      | PyMagic.PyMagic301 -> PythonVersion.Python301
      | PyMagic.PyMagic302 -> PythonVersion.Python302
      | PyMagic.PyMagic303 -> PythonVersion.Python303
      | PyMagic.PyMagic304 -> PythonVersion.Python304
      | PyMagic.PyMagic305 -> PythonVersion.Python305
      | PyMagic.PyMagic306 -> PythonVersion.Python306
      | PyMagic.PyMagic307 -> PythonVersion.Python307
      | PyMagic.PyMagic308 -> PythonVersion.Python308
      | PyMagic.PyMagic309 -> PythonVersion.Python309
      | PyMagic.PyMagic310 -> PythonVersion.Python310
      | PyMagic.PyMagic311 -> PythonVersion.Python311
      | PyMagic.PyMagic312 -> PythonVersion.Python312
      | PyMagic.PyMagic313 -> PythonVersion.Python313
      | PyMagic.PyMagic314 -> PythonVersion.Python314
      | PyMagic.PyMagic315 -> PythonVersion.Python315
      | _ -> failwithf "Unsupported magic number: 0x%X" magic
    else
      failwithf "Unknown Python bytecode magic-number: 0x%X" magic

