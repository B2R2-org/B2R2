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

module internal B2R2.FrontEnd.BinFile.Wasm.Helper

open B2R2.FrontEnd.BinFile

let entryPointOf wm =
  match wm.StartSection with
  | Some ss ->
    match ss.Contents with
    | Some fi ->
      let ii =
        wm.IndexMap
        |> Array.find (fun ii ->
          ii.Kind = IndexKind.Function
          && ii.Index = fi)
      Some(uint64 ii.ElemOffset)
    | None -> None
  | None -> None

let importToLinkageTableEntry (entry: Import) =
  { FuncName = entry.Name
    LibraryName = entry.ModuleName
    TrampolineAddress = 0UL
    TableAddress = uint64 entry.Offset }

let getImports wm =
  match wm.ImportSection with
  | Some sec ->
    match sec.Contents with
    | Some conts ->
      conts.Elements
      |> Array.filter (fun ie ->
          match ie.Desc with
          | ImpFunc _ -> true
          | _ -> false)
      |> Array.map importToLinkageTableEntry
    | None -> [||]
  | None -> [||]
