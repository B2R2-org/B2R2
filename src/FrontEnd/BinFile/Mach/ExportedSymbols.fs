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

namespace B2R2.FrontEnd.BinFile.Mach

open System
open B2R2
open B2R2.FrontEnd.BinLifter

/// Represents an array of exported symbols.
type ExportedSymbols = ExportedSymbol[]

/// Represents an exported symbol.
and ExportedSymbol = {
  /// Symbol name.
  ExportSymName: string
  /// Exported symbol address.
  ExportAddr: Addr
}

module internal ExportedSymbols =
  let private chooseDyLdInfo = function
    | DyLdInfo (_, _, c) -> Some c
    | _ -> None

  let rec private readStr (span: ByteSpan) pos acc =
    match span[pos] with
    | 0uy ->
      List.rev acc |> List.toArray |> Text.Encoding.ASCII.GetString, pos + 1
    | b -> readStr span (pos + 1) (b :: acc)

  let private buildExportEntry name addr =
    { ExportSymName = name; ExportAddr = addr }

  let rec private parseTrie toolBox (span: ByteSpan) offset str acc =
    let reader = toolBox.Reader
    if span[offset] = 0uy then (* non-terminal *)
      let nChilds, len = reader.ReadUInt64LEB128 (span, offset + 1)
      parseChildren toolBox span (offset + 1 + len) nChilds str acc
    else
      let _, shift = reader.ReadUInt64LEB128 (span, offset)
      let flagOffset = offset + shift
      let _flag = span[flagOffset]
      let symbOffset, _ = reader.ReadUInt64LEB128 (span, flagOffset + 1)
      buildExportEntry str (symbOffset + toolBox.BaseAddress) :: acc

  and private parseChildren toolBox span offset nChilds str acc =
    if nChilds = 0UL then acc
    else
      let pref, nextOffset = readStr span offset []
      let reader = toolBox.Reader
      let nextNode, len = reader.ReadUInt64LEB128 (span, nextOffset)
      let acc = parseTrie toolBox span (int nextNode) (str + pref) acc
      parseChildren toolBox span (nextOffset + len) (nChilds - 1UL) str acc

  /// The symbols exported by a dylib are encoded in a trie.
  let private parseExportTrieHead toolBox exportSpan =
    parseTrie toolBox exportSpan 0 "" []

  let private parseExports toolBox dyldinfo =
    match Array.tryHead dyldinfo with
    | None -> [||]
    | Some info ->
      let exportSize = int info.ExportSize
      let exportSpan = ReadOnlySpan (toolBox.Bytes, info.ExportOff, exportSize)
      parseExportTrieHead toolBox exportSpan
      |> List.toArray

  let parse toolBox cmds =
    let dyldinfo = Array.choose chooseDyLdInfo cmds
    parseExports toolBox dyldinfo
