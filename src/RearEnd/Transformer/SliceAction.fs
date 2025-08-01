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
open B2R2

/// The `slice` action.
type SliceAction() =
  let sliceByAddrRange bin a1 a2 =
    let hdl = Binary.Handle bin
    if a1 > a2 then invalidArg (nameof bin) "Invalid address range."
    elif not (hdl.File.IsAddrMappedToFile a1)
      || not (hdl.File.IsAddrMappedToFile a2) then
      invalidArg (nameof hdl) "Address out of range."
    else
      let slice = hdl.File.Slice(a1, int (a2 - a1 + 1UL))
      let bs = slice.ToArray()
      lazy hdl.MakeNew bs
      |> fun newBs ->
        Binary.Init(Binary.MakeAnnotation("Sliced from ", bin), newBs)

  let sliceBySectionName bin secName =
    Terminator.futureFeature ()

  let parseTwoArgs (a1: string) (a2: string) =
    let a1 = Convert.ToUInt64(a1, 16)
    let a2 =
      if a2.StartsWith '+' then
        let numBase = if a2.StartsWith "+0x" then 16 else 10
        a1 + Convert.ToUInt64(a2[1..], numBase) - 1UL
      else Convert.ToUInt64(a2, 16)
    a1, a2

  let sliceBin args bin =
    match args with
    | a1 :: a2 :: [] ->
      let a1, a2 = parseTwoArgs a1 a2
      sliceByAddrRange bin a1 a2 |> box
    | secName :: [] ->
      sliceBySectionName bin secName |> box
    | _ -> invalidArg (nameof args) "Invalid argument."

  let slice args (input: obj) =
    match input with
    | :? Binary as bin -> sliceBin args bin
    | _ -> invalidArg (nameof input) "Invalid input type."

  interface IAction with
    member _.ActionID with get() = "slice"
    member _.Signature with get() = "Binary * [optional arg(s)] -> Binary"
    member _.Description with get() = """
    Take in a byte array or a BinHandle and return a byte array of a part of the
    binary along with its starting address. Users can specify a specific address
    range or a section name as argument(s), which are listed below.

      - <a1> <a2>: returns a slice of the bianry from <a1> to <a2>.
      - <a1> +<n>: returns a slice of the bianry from <a1> to <a1 + n - 1>.
      - <sec_name>: returns a slice of the binary of the section <sec_name>.
"""
    member _.Transform(args, collection) =
      { Values = collection.Values |> Array.map (slice args) }
