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

open System
open System.IO
open B2R2
open B2R2.FrontEnd.BinInterface

/// The interface for a transforming action.
type IAction =
  abstract member ActionID: string
  abstract member InputType: Type
  abstract member OutputType: Type
  abstract member Description: string
  abstract member Transform: string list -> obj -> obj

/// The `parse` action.
type ParseAction () =
  let loadHexInput isa mode s =
    let bs = ByteArray.ofHexString s
    BinHandle.Init (isa, mode, false, None, bytes=bs)

  interface IAction with
    member __.ActionID with get() = "parse"
    member __.InputType with get() = typeof<string>
    member __.OutputType with get() = typeof<BinHandle>
    member __.Description with get() ="""
    Takes in an string and returns the parsed binary, i.e., BinHandle. The given
    input string can either represent a file path or a hexstring. If the given
    string represents a valid file path, then the file will be loaded.
    Otherwise, we consider the input string as a hexstring, and return a Binary
    with a raw binary format.
"""
    member __.Transform args _ =
      match args with
      | s :: isa :: mode :: [] ->
        let isa = ISA.OfString isa
        let mode = ArchOperationMode.ofString mode
        loadHexInput isa mode s
      | s :: isa :: [] ->
        let isa = ISA.OfString isa
        let mode = ArchOperationMode.NoMode
        loadHexInput isa mode s
      | s :: [] ->
        if File.Exists (path=s) then BinHandle.Init (ISA.DefaultISA, fileName=s)
        else loadHexInput ISA.DefaultISA ArchOperationMode.NoMode s
      | _ -> invalidArg (nameof ParseAction) "Invalid arguments given."

/// The `load` action.
type LoadAction () =
  interface IAction with
    member __.ActionID with get() = "load"
    member __.InputType with get() = typeof<string>
    member __.OutputType with get() = typeof<byte[]>
    member __.Description with get() ="""
    Takes in a string and returns the raw byte array. The given input string can
    either represent a file path or a hexstring. If the given string represents
    a valid file path, then the raw file content will be loaded. Otherwise, we
    consider the input string as a hexstring, and return it as is.
"""
    member __.Transform args _ =
      match args with
      | s :: [] ->
        if File.Exists (path=s) then File.ReadAllBytes s
        else ByteArray.ofHexString s
      | _ -> invalidArg (nameof LoadAction) "Invalid arguments given."

/// The `print` action.
type PrintAction () =
  let printByteArray (o: obj) =
    let bs = o :?> byte[]
    let s = bs[..16] |> Array.map (sprintf "%02x") |> String.concat " "
    let s = if bs.Length > 16 then s + " ..." else s
    printfn "%s" s

  interface IAction with
    member __.ActionID with get() = "print"
    member __.InputType with get() = typeof<obj>
    member __.OutputType with get() = typeof<unit>
    member __.Description with get() ="""
    Takes in an object and prints its value.
"""
    member __.Transform _args o =
      let typ = o.GetType ()
      if typ = typeof<byte[]> then printByteArray o
      else printfn "%s" <| o.ToString ()
      () (* This is to make compiler happy. *)