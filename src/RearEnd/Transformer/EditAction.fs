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
open System.Globalization
open System.Threading
open B2R2
open B2R2.Assembly
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile

/// The `edit` action.
type EditAction() =
  let formatRange startAddress endAddress =
    $"0x{startAddress:x}-0x{endAddress:x} (end exclusive)"

  let makeBinary bin newbs =
    let hdl = Binary.Handle bin
    if hdl.File.Format = FileFormat.RawBinary then
      Binary.OfFragment("Editted from ", bin, newbs, hdl.File.BaseAddress)
    else
      Binary.OfEditedContent("Editted from ", bin, newbs)

  let makeResult (input: obj) bin newbs newSliceEnd =
    match input with
    | :? BinarySlice as slice ->
      { slice with
          Source = makeBinary bin newbs
          EndAddress = newSliceEnd slice.EndAddress }
      |> box
    | _ -> makeBinary bin newbs |> box

  let parseUInt64 (value: string) =
    let style, value =
      if value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
        NumberStyles.HexNumber, value[2..]
      else
        NumberStyles.Integer, value
    UInt64.Parse(value, style, CultureInfo.InvariantCulture)

  let tryParseUInt64 value =
    try parseUInt64 value |> Some with _ -> None

  let tryParseISA (name: string) =
    try Some(ISA name) with _ -> None

  let defaultISA = ISA(Architecture.Intel, WordSize.Bit64)

  let assemble code isa baseAddress =
    let asm = Assembler(isa, baseAddress)
    match asm.Lower code with
    | Ok lowered ->
      lowered
      |> List.collect (fun (_, bytes) -> bytes |> Array.toList)
      |> List.toArray
    | Error error -> invalidArg (nameof code) error

  let parseEndAddress startAddress (value: string) =
    if value.StartsWith "+" then
      startAddress + parseUInt64 value[1..]
    else
      parseUInt64 value

  let sectionRange (section: BinSection) =
    section.Address, section.Address + section.FileSize

  let fileBackedSections (hdl: BinHandle) =
    BinFileOps.getSections hdl.File
    |> Array.filter (fun section ->
      section.FileSize > 0UL && Option.isSome section.Offset)

  let rawRange (hdl: BinHandle) =
    let startAddress = hdl.File.BaseAddress
    startAddress, startAddress + uint64 hdl.File.Length

  let describeSections sections =
    if Array.isEmpty sections then
      "No file-backed sections are available."
    else
      sections
      |> Array.map (fun section ->
        let startAddress, endAddress = sectionRange section
        $"{section.Name} {formatRange startAddress endAddress}")
      |> String.concat "; "

  let checkedFileOffset section address =
    let section: BinSection = section
    let offset = Option.get section.Offset
    let fileOffset = offset + address - section.Address
    if fileOffset > uint64 Int32.MaxValue then
      invalidArg (nameof address) "File offset is too large."
    else
      int fileOffset

  let checkedRawOffset (hdl: BinHandle) address =
    let startAddress, endAddress = rawRange hdl
    if address < startAddress || address > endAddress then
      let range = formatRange startAddress endAddress
      invalidArg (nameof address)
        $"Address 0x{address:x} is outside raw binary range: {range}"
    else
      let fileOffset = address - startAddress
      if fileOffset > uint64 Int32.MaxValue then
        invalidArg (nameof address) "File offset is too large."
      else
        int fileOffset

  let findSectionForRange hdl startAddress endAddress =
    if startAddress >= endAddress then
      invalidArg (nameof startAddress) "Invalid address range."
    else
      let sections = fileBackedSections hdl
      let contains section =
        let sectionStart, sectionEnd = sectionRange section
        startAddress >= sectionStart && endAddress <= sectionEnd
      match sections |> Array.tryFind contains with
      | Some section -> section
      | None ->
        let range = formatRange startAddress endAddress
        let sections = describeSections sections
        invalidArg (nameof hdl)
          $"Edit range {range} is outside file-backed sections: {sections}"

  let findSectionForAddress hdl address =
    let sections = fileBackedSections hdl
    let contains section =
      let sectionStart, sectionEnd = sectionRange section
      address >= sectionStart && address <= sectionEnd
    match sections |> Array.tryFind contains with
    | Some section -> section
    | None ->
      let sections = describeSections sections
      let message =
        $"Edit address 0x{address:x} is outside file-backed sections: "
        + sections
      invalidArg (nameof hdl)
        message

  let offsetForRange bin startAddress endAddress =
    let hdl = Binary.Handle bin
    if hdl.File.Format = FileFormat.RawBinary then
      checkedRawOffset hdl startAddress,
      checkedRawOffset hdl endAddress
    else
      let section = findSectionForRange hdl startAddress endAddress
      checkedFileOffset section startAddress,
      checkedFileOffset section endAddress

  let offsetForAddress bin address =
    let hdl = Binary.Handle bin
    if hdl.File.Format = FileFormat.RawBinary then
      checkedRawOffset hdl address
    else
      findSectionForAddress hdl address |> fun section ->
        checkedFileOffset section address

  let binaryForEdit (input: obj) =
    match input with
    | :? Binary as bin -> bin
    | :? BinarySlice as slice -> slice.Source
    | _ -> invalidArg "input" "Invalid input type."

  let ensureSliceAddress (slice: BinarySlice) address =
    if address < slice.StartAddress || address > slice.EndAddress then
      let sliceRange = formatRange slice.StartAddress slice.EndAddress
      invalidArg (nameof address)
        $"Edit address 0x{address:x} is outside slice {sliceRange}."
    else
      ()

  let ensureSliceRange (slice: BinarySlice) startAddress endAddress =
    if startAddress < slice.StartAddress || endAddress > slice.EndAddress then
      let editRange = formatRange startAddress endAddress
      let sliceRange = formatRange slice.StartAddress slice.EndAddress
      invalidArg (nameof startAddress)
        $"Edit range {editRange} is outside slice {sliceRange}."
    else
      ()

  let ensureAddressInsideInput (input: obj) address =
    match input with
    | :? BinarySlice as slice -> ensureSliceAddress slice address
    | _ -> ()

  let ensureRangeInsideInput (input: obj) startAddress endAddress =
    match input with
    | :? BinarySlice as slice ->
      ensureSliceRange slice startAddress endAddress
    | _ -> ()

  let insert startAddress (snip: byte[]) o =
    ensureAddressInsideInput o startAddress
    let bin = binaryForEdit o
    let hdl = Binary.Handle bin
    let bs = hdl.File.RawBytes.ToArray()
    let off = offsetForAddress bin startAddress
    let newbs = Array.zeroCreate (bs.Length + snip.Length)
    if off > bs.Length then invalidArg (nameof off) "Offset is too large."
    elif off = 0 then
      Array.blit snip 0 newbs 0 snip.Length
      Array.blit bs 0 newbs snip.Length bs.Length
    else
      Array.blit bs 0 newbs 0 off
      Array.blit snip 0 newbs off snip.Length
      Array.blit bs off newbs (off + snip.Length) (bs.Length - off)
    makeResult o bin newbs (fun endAddress ->
      endAddress + uint64 snip.Length)

  let delete startAddress endAddress o =
    ensureRangeInsideInput o startAddress endAddress
    let bin = binaryForEdit o
    let hdl = Binary.Handle bin
    let bs = hdl.File.RawBytes.ToArray()
    let soff, eoff = offsetForRange bin startAddress endAddress
    let rmlen = eoff - soff
    let newbs = Array.zeroCreate (bs.Length - rmlen)
    if rmlen > bs.Length || eoff > bs.Length || soff >= bs.Length || soff < 0
    then invalidArg (nameof soff) "Wrong offset(s) given."
    elif soff = 0 then
      Array.blit bs rmlen newbs 0 (bs.Length - rmlen)
    else
      Array.blit bs 0 newbs 0 soff
      Array.blit bs (soff + rmlen) newbs soff (bs.Length - soff - rmlen)
    makeResult o bin newbs (fun endAddress -> endAddress - uint64 rmlen)

  (* The edited whole content is bs, into which newbs has just been blitted;
     newbs alone is only the replacement snippet. *)
  let replace startAddress endAddress newbs o =
    ensureRangeInsideInput o startAddress endAddress
    let bin = binaryForEdit o
    let hdl = Binary.Handle bin
    let bs = hdl.File.RawBytes.ToArray()
    let soff, eoff = offsetForRange bin startAddress endAddress
    Array.blit newbs 0 bs soff (eoff - soff)
    makeResult o bin bs id

  let replaceAsm startAddress code isa o =
    let newbs = assemble code isa startAddress
    let endAddress = startAddress + uint64 newbs.Length
    replace startAddress endAddress newbs o

  let map cancellationToken operation collection =
    let cancellationToken: CancellationToken = cancellationToken
    collection.Values
    |> Array.map (fun value ->
      cancellationToken.ThrowIfCancellationRequested()
      operation value)

  let transform cancellationToken args collection =
    match args with
    | "insert" :: start :: hexstr :: [] ->
      let start = parseUInt64 start
      let bs = ByteArray.ofHexString hexstr
      { Values = map cancellationToken (insert start bs) collection }
    | "delete" :: start :: finish :: [] ->
      let start = parseUInt64 start
      let finish = parseEndAddress start finish
      if finish > start then
        { Values = map cancellationToken (delete start finish) collection }
      else
        invalidArg (nameof args) "Invalid address range."
    | "replace" :: start :: finish :: hexstr :: [] ->
      let start = parseUInt64 start
      match tryParseUInt64 finish with
      | Some _ ->
        let finish = parseEndAddress start finish
        let newbs = ByteArray.ofHexString hexstr
        let editSize = finish - start
        if finish > start && editSize = uint64 newbs.Length then
          let replace = replace start finish newbs
          { Values = map cancellationToken replace collection }
        else
          invalidArg (nameof args) "Invalid address range or hexstring."
      | None ->
        match tryParseISA hexstr with
        | Some isa ->
          { Values = map cancellationToken (replaceAsm start finish isa)
                       collection }
        | None -> invalidArg (nameof hexstr) "Invalid ISA."
    | "replace" :: start :: code :: [] ->
      let start = parseUInt64 start
      { Values = map cancellationToken (replaceAsm start code defaultISA)
                   collection }
    | _ -> invalidArg (nameof args) "Invalid edit action."

  interface IAction with
    member _.ActionID with get() = "edit"
    member _.Signature with get() =
      "Binary -> edit insert start=<addr> hex=<hex> | "
      + "delete start=<addr> end=<addr> | "
      + "delete start=<addr> size=<n> | "
      + "replace start=<addr> end=<addr> hex=<hex> | "
      + "replace start=<addr> size=<n> hex=<hex> -> Binary; "
      + "replace start=<addr> asm=<instruction> [isa=<isa>] -> Binary; "
      + "BinarySlice -> edit ... -> BinarySlice"
    member _.Description with get() =
      """
    Take in a binary as well as edit action as input and return a modified
    binary as output. There are following supported edit actions.

      - `insert start=<addr> hex=<hex>`
        Insert bytes at address addr. This will increase the size of the
        resulting binary by the size of the given hex bytes.

      - `delete start=<addr> end=<end>`
        Remove bytes in the half-open range [addr, end). The resulting binary
        will have the size less than the original one.

      - `delete start=<addr> size=<sz>`
        Remove sz bytes starting at address addr.

      - `replace start=<addr> end=<end> hex=<hex>`
        Replace bytes in the half-open range [addr, end). The hex byte length
        should be equal to end - addr.

      - `replace start=<addr> size=<sz> hex=<hex>`
        Replace sz bytes starting at address addr.

      - `replace start=<addr> asm=<instruction> [isa=<isa>]`
        Assemble instruction at addr and replace the original bytes with the
        assembled bytes.
"""
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection
