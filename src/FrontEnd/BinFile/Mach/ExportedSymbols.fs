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
open B2R2.FrontEnd.BinFile.FileHelper

/// Represents an array of exported symbols.
type internal ExportedSymbols = ExportedSymbol[]

/// Represents an exported symbol.
and internal ExportedSymbol =
  { /// Symbol name.
    ExportSymName: string
    /// Exported symbol address.
    ExportAddr: Addr }

module internal ExportedSymbols =
  /// EXPORT_SYMBOL_FLAGS_REEXPORT: the name belongs to another image.
  let [<Literal>] private ReexportFlag = 0x08UL

  /// Picks the export trie, which a modern binary carries in its own load
  /// command and an older one embeds in LC_DYLD_INFO.
  let private chooseTrie = function
    | ExportsTrie(_, _, c) -> Some(c.TrieOffset, c.TrieSize)
    | DyLdInfo(_, _, c) -> Some(c.ExportOff, c.ExportSize)
    | _ -> None

  /// Reads the image-relative address a terminal node exports. A re-export
  /// names a symbol of another image and so has no address of its own. Every
  /// other kind leads with an address, which for a stub-and-resolver export is
  /// the stub this image calls rather than the resolver behind it.
  let private readTerminalAddr (reader: IBinReader) (span: ByteSpan) offset =
    let flags, n = reader.ReadUInt64LEB128(span, offset)
    if flags &&& ReexportFlag <> 0UL then
      None
    else
      let addr, _ = reader.ReadUInt64LEB128(span, offset + n)
      Some addr

  /// Walks one trie node, whose terminal payload, when it has one, names an
  /// export and whose children extend the accumulated prefix. A node is both
  /// terminal and a parent whenever one exported name prefixes another, so the
  /// children are walked either way.
  let rec private parseNode toolBox (span: ByteSpan) offset str acc =
    let reader = toolBox.Reader
    let termSize, n = reader.ReadUInt64LEB128(span, offset)
    if termSize > 0UL then
      readTerminalAddr reader span (offset + n)
      |> Option.iter (fun addr -> (acc: ResizeArray<_>).Add(str, addr))
    else
      ()
    let childOff = offset + n + int termSize
    let count = int span[childOff]
    parseChildren toolBox span (childOff + 1) count str acc

  and private parseChildren toolBox (span: ByteSpan) offset count str acc =
    if count = 0 then
      ()
    else
      let struct (pref, nextOffset) = readCStringWithNextOffset span offset
      let node, n = toolBox.Reader.ReadUInt64LEB128(span, nextOffset)
      parseNode toolBox span (int node) (str + pref) acc
      parseChildren toolBox span (nextOffset + n) (count - 1) str acc

  /// The symbols a Mach-O image exports are encoded in a trie whose addresses
  /// are relative to the image base.
  let parse toolBox cmds segCmds =
    match Array.tryPick chooseTrie cmds with
    | Some(offset, size) when size > 0u ->
      let imageBase =
        Segment.tryGetImageBase segCmds |> Option.defaultValue 0UL
      let acc = ResizeArray()
      parseNode toolBox (ReadOnlySpan(toolBox.Bytes, offset, int size)) 0 "" acc
      acc
      |> Seq.map (fun (name, addr) ->
        { ExportSymName = name; ExportAddr = imageBase + addr })
      |> Seq.toArray
    | _ ->
      [||]
