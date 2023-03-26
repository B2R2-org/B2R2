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
open B2R2.FrontEnd.BinInterface

/// The `load` action.
type LoadAction () =
  let load isa mode parseFileFormat s =
    if File.Exists (path=s) then
      BinHandle.Init (isa, mode, parseFileFormat, None, s)
      |> Binary.PlainInit
      |> box
      |> Array.singleton
    elif Directory.Exists (path=s) then
      Directory.GetFiles s
      |> Array.map (fun f ->
        BinHandle.Init (isa, mode, parseFileFormat, None, f)
        |> Binary.PlainInit |> box)
    else
      BinHandle.Init (isa, mode, false, None, ByteArray.ofHexString s)
      |> Binary.PlainInit
      |> box
      |> Array.singleton

  interface IAction with
    member __.ActionID with get() = "load"
    member __.Signature
      with get() = "unit * <str> * [isa] * [mode]: string -> Binary"
    member __.Description with get() = """
    Take in a string <str> and return a binary object. The given input string
    can either represent a file path or a hexstring. If the given string
    represents a valid file path, then the raw file content will be loaded.
    If the given string is a valid directory path, then every file in the
    directory will be loaded in bulk. Otherwise, we consider the input string as
    a hexstring, and return the corresponding binary.

      - [isa] : parse the binary for the given ISA.
      - [mode]: parse the binary for the given operation mode.
"""
    member __.Transform args collection =
      if collection.Values |> Array.forall isNull then ()
      else invalidArg (nameof collection) "Invalid argument type."
      match args with
      | s :: isa :: mode :: "raw" :: [] ->
        let isa = ISA.OfString isa
        let mode = ArchOperationMode.ofString mode
        { Values = load isa mode false s }
      | s :: isa :: mode :: [] ->
        let isa = ISA.OfString isa
        let mode = ArchOperationMode.ofString mode
        { Values = load isa mode true s }
      | s :: isa :: [] ->
        let isa = ISA.OfString isa
        { Values = load isa ArchOperationMode.NoMode true s }
      | s :: [] ->
        { Values = load ISA.DefaultISA ArchOperationMode.NoMode true s }
      | _ -> invalidArg (nameof args) "Invalid arguments given."