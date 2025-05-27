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

namespace B2R2.FrontEnd.BinFile.ELF

open System
open B2R2
open B2R2.FrontEnd.BinLifter

/// Represents a map from the address of the LSDA to the LSDA itself. LSDATable
/// is used to store the parsed LSDA entries from the `.gcc_except_table`
/// section of the ELF file.
type LSDATable = Map<Addr, LSDA>

[<RequireQualifiedAccess>]
module internal LSDATable =
  let [<Literal>] SectionName = ".gcc_except_table"

  let findMinOrZero lst =
    match lst with
    | [] -> 0L
    | _ -> List.min lst

  let findMinFilter callsites =
    if List.isEmpty callsites then 0L
    else
      callsites
      |> List.map (fun cs -> cs.ActionTypeFilters |> findMinOrZero)
      |> List.min

  let rec readUntilNull (span: ByteSpan) offset =
    if span[offset] = 0uy then (offset + 1)
    else readUntilNull span (offset + 1)

  /// We currently just skip the type table by picking up the minimum filter
  /// value as we don't use the type table.
  let skipTypeTable span ttbase callsites =
    let minFilter = findMinFilter callsites
    if minFilter < 0L then
      let offset = ttbase - int minFilter - 1
      readUntilNull span offset (* Consume exception spec table. *)
    else ttbase

  /// Sometimes, we observe dummy zero bytes inserted by the compiler (icc);
  /// this is nothing to do with the alignment. This is likely to be the
  /// compiler error, but we should safely ignore those dummy bytes.
  let rec skipDummyAlign (span: ByteSpan) offset =
    if offset >= span.Length then offset
    else
      let b = span[offset]
      if b = 0uy then skipDummyAlign span (offset + 1)
      else offset

  /// Parses LSDA records from the `.gcc_except_table` section.
  let rec parseFromSection cls (span: ByteSpan) reader sAddr offset lsdas =
    if offset >= span.Length then lsdas
    else
      let lsdaAddr = sAddr + uint64 offset
      let struct (lsda, offset) = LSDA.parse cls span reader sAddr offset
      let offset =
        match lsda.TTBase with
        | Some ttbase -> int (ttbase - sAddr)
        | None -> offset
      let offset = skipTypeTable span offset lsda.CallSiteTable
      let offset = skipDummyAlign span offset
      let lsdas = Map.add lsdaAddr lsda lsdas
      parseFromSection cls span reader sAddr offset lsdas

  let parse toolBox cls shdrs =
    match Array.tryFind (fun s -> s.SecName = SectionName) shdrs with
    | Some sec ->
      let offset, size = int sec.SecOffset, int sec.SecSize
      let span = ReadOnlySpan (toolBox.Bytes, offset, size)
      parseFromSection cls span toolBox.Reader sec.SecAddr 0 Map.empty
    | None -> Map.empty
