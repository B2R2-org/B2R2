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
open B2R2.FrontEnd.BinInterface

/// The `slice` action.
type SliceAction () =
  let makeAnnotation bin =
    let hdl = Binary.Handle bin
    let path = hdl.BinFile.FilePath
    if String.IsNullOrEmpty path then Binary.Annotation bin
    else $" | Sliced from {path}"

  let sliceByAddrRange bin a1 a2 =
    let hdl = Binary.Handle bin
    if a1 > a2 then invalidArg (nameof bin) "Invalid address range."
    elif not (hdl.BinFile.IsInFileAddr a1)
      || not (hdl.BinFile.IsInFileAddr a2) then
      invalidArg (nameof hdl) "Address out of range."
    else
      let o1 = hdl.BinFile.TranslateAddress a1
      let o2 = hdl.BinFile.TranslateAddress a2
      let bs = hdl.BinFile.Span.Slice(o1, o2 - o1 + 1).ToArray ()
      lazy BinHandle.Init (hdl.ISA, hdl.Parser.OperationMode, false, None, bs)
      |> Binary.Init (makeAnnotation bin)

  let sliceBySectionName bin secName =
    let hdl = Binary.Handle bin
    let sec = hdl.BinFile.GetSections (name=secName) |> Seq.exactlyOne
    let a1 = sec.Address
    let a2 = a1 + sec.Size - 1UL
    sliceByAddrRange bin a1 a2

  let parseTwoArgs (a1: string) (a2: string) =
    let a1 = Convert.ToUInt64 (a1, 16)
    let a2 =
      if a2.StartsWith '+' then
        let numBase = if a2.StartsWith "+0x" then 16 else 10
        a1 + Convert.ToUInt64 (a2[1..], numBase) - 1UL
      else Convert.ToUInt64 (a2, 16)
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
    member __.ActionID with get() = "slice"
    member __.Signature with get() = "Binary * [optional arg(s)] -> Binary"
    member __.Description with get() = """
    Take in a byte array or a BinHandle and return a byte array of a part of the
    binary along with its starting address. Users can specify a specific address
    range or a section name as argument(s), which are listed below.

      - <a1> <a2>: returns a slice of the bianry from <a1> to <a2>.
      - <a1> +<n>: returns a slice of the bianry from <a1> to <a1 + n - 1>.
      - <sec_name>: returns a slice of the binary of the section <sec_name>.
"""
    member __.Transform args collection =
      { Values = collection.Values |> Array.map (slice args) }