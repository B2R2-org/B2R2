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

namespace B2R2.FrontEnd.BinFile.Python

open B2R2

/// <summary>
///   Python Type(Python 3.12).
/// </summary>
type PyType =
  | TYPE_NULL = 0x60 (* '0' *)
  | TYPE_NONE = 0x4E (* 'N' *)
  | TYPE_FALSE = 0x46 (* 'F' *)
  | TYPE_TRUE = 0x54 (* 'T' *)
  | TYPE_STOPITER = 0x53 (* 'S' *)
  | TYPE_ELLIPSIS = 0x2E (* '.' *)
  | TYPE_INT = 0x69 (* 'i' *)
  | TYPE_INT64 = 0x49 (* 'I' *)
  | TYPE_FLOAT = 0x66 (* 'f' *)
  | TYPE_BINARY_FLOAT = 0x67 (* 'g' *)
  | TYPE_COMPLEX = 0x78 (* 'x' *)
  | TYPE_BINARY_COMPLEX = 0x79 (* 'y' *)
  | TYPE_LONG = 0x6C (* 'l' *)
  | TYPE_STRING = 0x73 (* 's' *)
  | TYPE_INTERNED = 0x74 (* 't' *)
  | TYPE_REF = 0x72 (* 'r' *)
  | TYPE_TUPLE = 0x28 (* '(' *)
  | TYPE_LIST = 0x5B (* '[' *)
  | TYPE_DICT = 0x7B (* '{' *)
  | TYPE_CODE = 0x63 (* 'c' *)
  | TYPE_UNICODE = 0x75 (* 'u' *)
  | TYPE_UNKNOWN = 0x3F (* '?' *)
  | TYPE_SET = 0x3C (* '<' *)
  | TYPE_FROZENSET = 0x3E (* '>' *)
  | FLAG_REF = 0x80 (* '\x80' *)
  | TYPE_ASCII = 0x61 (* 'a' *)
  | TYPE_ASCII_INTERNED = 0x41 (* 'A' *)
  | TYPE_SMALL_TUPLE = 0x29 (* ')' *)
  | TYPE_SHORT_ASCII = 0x7A (* 'z' *)
  | TYPE_SHORT_ASCII_INTERNED = 0x5A (* 'Z' *)
  | WFERR_OK = 0x0
  | WFERR_UNMARSHALLABLE = 0x1
  | WFERR_NESTEDTOODEEP = 0x2
  | WFERR_NOMEMORY = 0x3

type PyCodeObject = {
  FileName: string
  Name: string
  QualName: string
  Flags: int
  Code: Addr * PyObject
  FirstLineNo: int
  LineTable: PyObject
  Consts: PyObject
  Names: PyObject
  LocalPlusNames: PyObject
  LocalPlusKinds: PyObject
  ArgCount: int
  PosonlyArgCount: int
  KwonlyArgCount: int
  StackSize: int
  ExceptionTable: PyObject
}
and PyObject =
  | PyString of byte[]
  | PyCode of PyCodeObject
  | PyTuple of PyObject[]
  | PyInt of int
  | PyAscii of string
  | PyShortAsciiInterned of string
  | PyShortAscii of string
  | PyREF of int * string
  | PyFalse
  | PyNone
