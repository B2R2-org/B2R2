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

namespace B2R2.RearEnd.Transformer

open System.IO
open B2R2
open B2R2.FrontEnd

/// The `load` action.
type LoadAction() =
  let load isa parseFileFormat s =
    if File.Exists(path = s) then
      lazy BinHandle(s, isa, None)
      |> Binary.PlainInit
      |> box
      |> Array.singleton
    elif Directory.Exists(path = s) then
      Directory.GetFiles s
      |> Array.map (fun f ->
        lazy BinHandle(f, isa, None)
        |> Binary.PlainInit |> box)
    else
      lazy BinHandle(ByteArray.ofHexString s, isa, None, false)
      |> Binary.PlainInit
      |> box
      |> Array.singleton

  interface IAction with
    member _.ActionID with get() = "load"
    member _.Signature with get() = "unit * <str> * [isa] : string -> Binary"
    member _.Description with get() = """
    Take in a string <str> and return a binary object. The given input string
    can either represent a file path or a hexstring. If the given string
    represents a valid file path, then the raw file content will be loaded.
    If the given string is a valid directory path, then every file in the
    directory will be loaded in bulk. Otherwise, we consider the input string as
    a hexstring, and return the corresponding binary.

      - [isa] : parse the binary for the given ISA.
"""
    member _.Transform(args, collection) =
      if collection.Values |> Array.forall isNull then ()
      else invalidArg (nameof collection) "Invalid argument type."
      match args with
      | s :: isaName :: "raw" :: [] ->
        let isa = ISA isaName
        { Values = load isa false s }
      | s :: isaName :: [] ->
        let isa = ISA isaName
        { Values = load isa true s }
      | s :: [] ->
        let isa = ISA Architecture.Intel
        { Values = load isa true s }
      | _ -> invalidArg (nameof args) "Invalid arguments given."
