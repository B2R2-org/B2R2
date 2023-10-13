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
open System.Text.RegularExpressions
open B2R2
open B2R2.FrontEnd.BinInterface
open B2R2.RearEnd.Transformer.Utils

/// The `grep` action.
type GrepAction () =
  let grepFromBinary (pattern: string) bytesBefore bytesAfter bin =
    let hdl = Binary.Handle bin
    let bs = hdl.BinFile.Content.RawBytes
    let hs = byteArrayToHexStringArray bs |> String.concat ""
    let regex = Regex (pattern.ToLowerInvariant ())
    regex.Matches hs
    |> Seq.choose (fun m ->
      if m.Index % 2 = 0 then Some (m.Index / 2, m.Length / 2)
      else None)
    |> Seq.toArray
    |> Array.map (fun (i, len) ->
      let soff = if (i - bytesBefore) < 0 then 0 else i - bytesBefore
      let eoff = i + len - 1
      let eoff = if (eoff + bytesAfter) >= bs.Length then bs.Length - 1
                 else eoff + bytesAfter
      lazy BinHandle.Init (hdl.BinFile.ISA, hdl.Parser.OperationMode,
                           false, Some (uint64 soff), bs[soff .. eoff])
      |> Binary.Init (Binary.MakeAnnotation "Greped from " bin))
    |> box

  let grep pattern bytesBefore bytesAfter (input: obj) =
    match input with
    | :? Binary as bin -> grepFromBinary pattern bytesBefore bytesAfter bin
    | _ -> invalidArg (nameof input) "Invalid object is given."

  interface IAction with
    member __.ActionID with get() = "grep"
    member __.Signature
      with get() =
        "'a array * <pattern> * [bytes before] * [bytes after] -> 'a array"
    member __.Description with get() = """
    Take in an array as input and return one or more matched items from the
    array as in the `grep` command. The <pattern> represents a binary pattern
    using a regular expression with hexstrings. For example, the pattern
    "3031.." will match a three-byte sequence {{ 0x30, 0x31, * }}, where * means
    any byte. Note that '.' means any 4-bit value in our regular expression.
    Similarly, the pattern "(30)+" means a sequence of 0x30s of any length,
    e.g., {{ 0x30, 0x30, 0x30, 0x30, 0x30 }} will match the pattern.

    Two optional arguments [bytes before] and [bytes after] can be given to get
    the context of the matched items. For example, if [bytes before] is 2 and
    [bytes after] is 1, then the matched items will be surrounded by two bytes
    before and one line after. If the matched items are at the beginning or end
    of the array, the context will be truncated accordingly.
"""
    member __.Transform args collection =
      match args with
      | pattern :: bytesBefore :: bytesAfter :: [] ->
        let bytesBefore = Convert.ToInt32 bytesBefore
        let bytesAfter = Convert.ToInt32 bytesAfter
        { Values = collection.Values
                   |> Array.map (grep pattern bytesBefore bytesAfter) }
      | pattern :: bytesBefore :: [] ->
        let bytesBefore = Convert.ToInt32 bytesBefore
        { Values = collection.Values
                   |> Array.map (grep pattern bytesBefore 0) }
      | [ pattern ] ->
        { Values = collection.Values |> Array.map (grep pattern 0 0) }
      | _ -> invalidArg (nameof args) "Single pattern should be given."
