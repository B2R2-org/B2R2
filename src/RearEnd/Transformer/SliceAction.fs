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
  let sliceByAddrRange (bin: BinHandle) a1 a2 =
    if a1 > a2 then invalidArg (nameof SliceAction) "Invalid address range."
    elif not (bin.BinFile.IsInFileAddr a1)
      || not (bin.BinFile.IsInFileAddr a2) then
      invalidArg (nameof SliceAction) "Address out of range."
    else
      let o1 = bin.BinFile.TranslateAddress a1
      let o2 = bin.BinFile.TranslateAddress a2
      { TaggedByteArray.Address = a1
        ISA = bin.ISA
        Bytes = bin.BinFile.Span.Slice(o1, o2 - o1 + 1).ToArray () }

  let sliceBySectionName (bin: BinHandle) secName =
    let sec = bin.BinFile.GetSections (name=secName) |> Seq.exactlyOne
    let a1 = sec.Address
    let a2 = a1 + sec.Size - 1UL
    sliceByAddrRange bin a1 a2

  interface IAction with
    member __.ActionID with get() = "slice"
    member __.InputType with get() = typeof<BinHandle>
    member __.OutputType with get() = typeof<TaggedByteArray>
    member __.Description with get() = """
    Takes in a parsed binary and returns a byte array of a part of the binary
    along with its starting address.  Users can specify a specific address range
    or a section name to slice the binary.

      - <a1> <a2>: returns a slice of the bianry from <a1> to <a2>.
      - <sec_name>: returns a slice of the binary of the section <sec_name>.
"""
    member __.Transform args bin =
      let bin = unbox<BinHandle> bin
      match args with
      | a1 :: a2 :: [] ->
        let a1 = Convert.ToUInt64 (a1, 16)
        let a2 = Convert.ToUInt64 (a2, 16)
        sliceByAddrRange bin a1 a2
      | secName :: [] ->
        sliceBySectionName bin secName
      | _ -> invalidArg (nameof ListAction) "Invalid argument."