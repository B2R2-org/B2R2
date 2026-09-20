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

/// Recovers the instruction-set encodings in force across a Mach-O image. ARM
/// interleaves A32 and T32 code, which the N_ARM_THUMB_DEF bit of a symbol
/// tells apart, and both ARM architectures embed data in their text sections,
/// which LC_DATA_IN_CODE lists. The x86 architectures have one encoding and no
/// value in B2R2's model to name it with, so nothing is marked for them: a
/// data range there could be opened but never closed again.
module internal B2R2.FrontEnd.BinFile.Mach.CodeMode

open B2R2
open B2R2.FrontEnd.BinFile

/// N_ARM_THUMB_DEF: the symbol names a Thumb (T32) function.
let [<Literal>] private ArmThumbDef = 0x8s

/// Size of one data_in_code_entry.
let [<Literal>] private EntrySize = 8

/// Names the encoding that takes effect at an address. The field names are
/// shared with other records of this namespace, so the type is spelled out.
let private marker addr mode: BinCodeModeMarker =
  { Address = addr; Mode = mode }

let private chooseDataInCode = function
  | DataInCode(_, _, c) -> Some c
  | _ -> None

/// Returns the symbols defined in the text section, which are the ones that
/// can say what encoding the code around them is in. The ones B2R2 derives
/// from LC_FUNCTION_STARTS are left out: they carry a negative n_desc, whose
/// bits would otherwise read as a Thumb marking.
let private textSymbols secText symbols =
  symbols
  |> Array.filter (fun s ->
    Symbol.IsSection s && s.SecNum = secText + 1 && s.SymDesc >= 0s)

/// Marks the encoding each ARM symbol's code is in.
let private armSymbolMarkers secText symbols =
  textSymbols secText symbols
  |> Array.map (fun s ->
    let mode = if s.SymDesc &&& ArmThumbDef <> 0s then ThumbMode else ArmMode
    marker s.SymAddr mode)

/// Reads the LC_DATA_IN_CODE table into (start, end) address pairs. An entry
/// counts its start from the Mach-O header, so the image base places it.
let private dataRanges toolBox imageBase cmds =
  let bytes, reader = toolBox.Bytes, toolBox.Reader
  [| for cmd in Array.choose chooseDataInCode cmds do
       for i in 0 .. int cmd.TableSize / EntrySize - 1 do
         let at = cmd.TableOffset + i * EntrySize
         let start = imageBase + uint64 (reader.ReadUInt32(bytes, at))
         let len = uint64 (reader.ReadUInt16(bytes, at + 4))
         start, start + len |]

/// Marks each data range, and puts the encoding that the range interrupted
/// back where it ends, so the code after it is read the way the code before it
/// was. The fallback applies where no symbol covers the range.
let private dataMarkers toolBox imageBase cmds fallback marks =
  let modeAt addr =
    marks
    |> Array.filter (fun (m: BinCodeModeMarker) -> m.Address <= addr)
    |> Array.tryLast
    |> Option.map (fun m -> m.Mode)
    |> Option.defaultValue fallback
  [| for start, endAddr in dataRanges toolBox imageBase cmds do
       marker start DataMode
       marker endAddr (modeAt start) |]

/// Returns every encoding change across the image, in address order.
let compute toolBox cmds imageBase secText symbols =
  match toolBox.Header.CPUType with
  | CPUType.ARM ->
    let marks =
      armSymbolMarkers secText symbols |> Array.sortBy (fun m -> m.Address)
    dataMarkers toolBox imageBase cmds ArmMode marks
    |> Array.append marks
    |> Array.sortBy (fun m -> m.Address)
  | CPUType.ARM64 ->
    dataMarkers toolBox imageBase cmds A64Mode [||]
  | _ ->
    [||]
