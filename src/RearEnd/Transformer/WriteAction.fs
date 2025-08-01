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
open B2R2.RearEnd.Utils

/// The `write` action.
type WriteAction() =
  let rec write fname (o: obj) =
    match o with
    | :? Binary as bin -> writeBinary fname bin
    | :? OutString as os -> writeOutString fname os
    | _ -> File.WriteAllText(fname, o.ToString())

  and writeBinary fname bin =
    let hdl = Binary.Handle bin
    File.WriteAllBytes(fname, hdl.File.RawBytes)

  and writeOutString fname os =
    File.WriteAllText(fname, OutString.toString os)

  interface IAction with
    member _.ActionID with get() = "write"
    member _.Signature with get() = "'a * <file> -> unit"
    member _.Description with get() = """
    Take in an input object and write out its content to the <file>.
"""
    member _.Transform(args, collection) =
      if args.Length = collection.Values.Length then
        let args = List.toArray args
        Array.iter2 write args collection.Values
        { Values = [||] }
      elif args.Length = 1 then
        let fname = List.head args
        let fnames = collection.Values |> Array.mapi (fun i _ -> $"{fname}.{i}")
        Array.iter2 write fnames collection.Values
        { Values = [||] }
      else invalidArg (nameof args) "Input lengths mismatch."
