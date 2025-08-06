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

open B2R2

/// Represents exception information.
type internal ExceptionData =
  { /// Exception frames.
    ExceptionFrame: ExceptionFrame
    /// LSDA (Language Specific Data Area) table is a collection of LSDAs.
    LSDATable: LSDATable
    /// Unwinding info table.
    UnwindingTbl: Map<Addr, UnwindingEntry> }

module internal ExceptionData =
  let private computeUnwindingTable exns =
    exns
    |> List.fold (fun tbl (f: CFI) ->
      f.FDEs |> Array.fold (fun tbl fde ->
        fde.UnwindingInfo |> List.fold (fun tbl i ->
          Map.add i.Location i tbl) tbl
        ) tbl) Map.empty

  let parse toolBox shdrs regFactory reloc =
    let hdr = toolBox.Header
    let cls = hdr.Class
    let isa = toolBox.ISA
    let relocInfo =
      if hdr.ELFType = ELFType.ET_REL then Some reloc else None
    let exns = ExceptionFrame.parse toolBox cls shdrs isa regFactory relocInfo
    let lsdas = LSDATable.parse toolBox cls shdrs
    match exns with
    | [] when isa.Arch = Architecture.ARMv7 ->
      let struct (exns, lsdas) = ARMExceptionData.parse toolBox cls shdrs
      { ExceptionFrame = exns; LSDATable = lsdas; UnwindingTbl = Map.empty }
    | _ ->
      let unwinds = computeUnwindingTable exns
      { ExceptionFrame = exns; LSDATable = lsdas; UnwindingTbl = unwinds }

