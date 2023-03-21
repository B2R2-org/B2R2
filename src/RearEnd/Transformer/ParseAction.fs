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

open B2R2
open B2R2.FrontEnd.BinInterface

/// The `parse` action.
type ParseAction () =
  interface IAction with
    member __.ActionID with get() = "parse"
    member __.InputType with get() = typeof<byte[]>
    member __.OutputType with get() = typeof<BinHandle>
    member __.Description with get() = """
    Takes in a string and returns the parsed binary, i.e., BinHandle. The given
    input string can either represent a file path or a hexstring. If the given
    string represents a valid file path, then the file will be loaded.
    Otherwise, we consider the input string as a hexstring, and return a Binary
    with a raw binary format.

      - <isa> <mode>: parse the binary for the given ISA and mode.
      - <isa>: parse the binary for the given ISA.
"""
    member __.Transform args bs =
      let bs = unbox<byte[]> bs
      match args with
      | isa :: mode :: [] ->
        let isa = ISA.OfString isa
        let mode = ArchOperationMode.ofString mode
        BinHandle.Init (isa, mode, false, None, bytes=bs)
      | isa :: [] ->
        let isa = ISA.OfString isa
        let mode = ArchOperationMode.NoMode
        BinHandle.Init (isa, mode, false, None, bytes=bs)
      | [] ->
        let mode = ArchOperationMode.NoMode
        BinHandle.Init (ISA.DefaultISA, mode, true, None, bytes=bs)
      | _ -> invalidArg (nameof ParseAction) "Invalid arguments given."