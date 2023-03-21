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

open B2R2.FrontEnd.BinInterface

/// The `list` action.
type ListAction () =
  let listSections (bin: BinHandle) =
    bin.BinFile.GetSections ()
    |> Seq.toArray

  interface IAction with
    member __.ActionID with get() = "list"
    member __.InputType with get() = typeof<BinHandle>
    member __.OutputType with get() = typeof<obj>
    member __.Description with get() = """
    Takes in a parsed binary and returns a list of elements such as functions,
    sections, etc. The output type is determined by the extra argument.
    Currently, we support the following output types:

      - `sections` (sects|ss): returns a list of sections.
"""
    member __.Transform args bin =
      let bin = unbox<BinHandle> bin
      match args with
      | [ "sections" ] | [ "sects" ] | [ "ss" ] ->
        listSections bin
      | _ -> invalidArg (nameof ListAction) "Invalid argument."