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
open B2R2.FrontEnd.BinFile

/// One selectable analysis target shown by the interactive inspector.
type ReplInspectionItem =
  { Label: string
    Detail: string
    Command: string }

module TransformerReplInspection =
  let private quote (text: string) =
    if text |> Seq.exists Char.IsWhiteSpace then $"'{text}'" else text

  let private inspectBinary binary =
    let hdl = Binary.Handle binary
    let sections =
      BinFileOps.getSections hdl.File
      |> Array.filter (fun section ->
        section.FileSize > 0UL && not (String.IsNullOrWhiteSpace section.Name))
      |> Array.map (fun section ->
        { Label = $"section  {section.Name}"
          Detail =
            $"0x{section.Address:x}-0x{section.Address + section.Size:x}"
          Command = $"@slice section={quote section.Name}" })
      |> Array.toList
    let functions =
      BinFileOps.getFunctionAddresses hdl.File
      |> Array.sort
      |> Array.map (fun address ->
        { Label = $"function  0x{address:x}"
          Detail = "recover this function's CFG"
          Command = $"@cfg entry=0x{address:x}" })
      |> Array.toList
    sections @ functions

  let private inspectCFG index = function
    | CFG(addr, _, _) ->
      Some
        { Label = $"cfg       0x{addr:x}"
          Detail = "select this CFG"
          Command = $"@pick index={index}" }
    | NoCFG error ->
      Some
        { Label = $"cfg       failed"
          Detail = error
          Command = $"@pick index={index}" }

  let private inspectCFGs (values: obj array) =
    values
    |> Array.mapi (fun index value ->
      match value with
      | :? CFG as cfg ->
        inspectCFG index cfg
      | _ ->
        None)
    |> Array.choose id
    |> Array.toList

  let inspect value =
    let value: ReplValue = value
    value.Collection.Values
    |> Array.tryPick (function
      | :? Binary as binary ->
        Some(inspectBinary binary)
      | _ ->
        None)
    |> Option.defaultWith (fun () -> inspectCFGs value.Collection.Values)
