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

namespace B2R2.FrontEnd

open System.Collections.Generic
open B2R2
open B2R2.Collections
open B2R2.FrontEnd.BinFile

/// <summary>
/// Represents parsed exception information of a binary code. We currently only
/// support ELF binaries.
/// </summary>
type ExceptionInfo (liftingUnit: LiftingUnit) =
  let loadCallSiteTable lsdaPointer lsdaTbl =
    let lsda: ELF.LSDA = Map.find lsdaPointer lsdaTbl
    lsda.CallSiteTable

  /// If a landing pad has a direct branch to another function, then we consider
  /// the frame containing the lading pad as a non-function FDE.
  let checkIfFDEIsFunction (fde: ELF.FDE) landingPad =
    match liftingUnit.ParseBBlock (addr=landingPad) with
    | Ok (blk) ->
      let last = blk[blk.Length - 1]
      if last.IsCall () |> not then
        match last.DirectBranchTarget () with
        | true, jmpTarget -> fde.PCBegin <= jmpTarget && jmpTarget < fde.PCEnd
        | _ -> true
      else true
    | _ -> true

  let rec loopCallSiteTable (fde: ELF.FDE) isFDEFunc acc rs =
    match rs with
    | [] -> acc, isFDEFunc
    | (csrec: ELF.CallSiteRecord) :: rest ->
      let blockStart = fde.PCBegin + csrec.Position
      let blockEnd = fde.PCBegin + csrec.Position + csrec.Length - 1UL
      let landingPad =
        if csrec.LandingPad = 0UL then 0UL else fde.PCBegin + csrec.LandingPad
      if landingPad = 0UL then loopCallSiteTable fde isFDEFunc acc rest
      else
        let range = AddrRange (blockStart, blockEnd)
        let acc = NoOverlapIntervalMap.add range landingPad acc
        let isFDEFunc = checkIfFDEIsFunction fde landingPad
        loopCallSiteTable fde isFDEFunc acc rest

  let buildExceptionTable (fde: ELF.FDE) lsdaTbl tbl =
    match fde.LSDAPointer with
    | None -> tbl, true
    | Some lsdaPointer ->
      loopCallSiteTable fde true tbl (loadCallSiteTable lsdaPointer lsdaTbl)

  let fnRanges = HashSet ()

  let accumulateExceptionTableInfo acc fdes lsdaTbl =
    fdes
    |> Array.fold (fun exnTbl fde ->
       let exnTbl, isFDEFunction = buildExceptionTable fde lsdaTbl exnTbl
       if isFDEFunction then
        let range = AddrRange (fde.PCBegin, fde.PCEnd - 1UL)
        fnRanges.Add range |> ignore
       else ()
       exnTbl) acc

  let computeExceptionTable excframes lsdaTbl =
    excframes
    |> List.fold (fun acc (cfi: ELF.CFI) ->
      accumulateExceptionTableInfo acc cfi.FDEs lsdaTbl
    ) NoOverlapIntervalMap.empty

  let exnTbl =
    match liftingUnit.File.Format with
    | FileFormat.ELFBinary ->
      let elf = liftingUnit.File :?> ELFBinFile
      computeExceptionTable elf.ExceptionFrame elf.LSDATable
    | _ -> NoOverlapIntervalMap.empty

  new (hdl: BinHandle) =
    ExceptionInfo (hdl.NewLiftingUnit ())

  /// Returns the exception handler mapping.
  member _.ExceptionMap with get () = exnTbl

  /// Returns an array of function entry points identified by the exception
  /// table.
  member _.FunctionEntryPoints with get () =
    [| for range in fnRanges do range.Min |]

  /// Returns the coverage of the exception table, which is the ratio of
  /// addresses in the .text section that are covered by the exception table.
  member _.ExceptionCoverage with get () =
    let ptr = liftingUnit.File.GetTextSectionPointer ()
    let txtSize = float (ptr.MaxAddr - ptr.Addr)
    let mutable covered = 0.0
    for range in fnRanges do
      if ptr.Addr <= range.Min && range.Min <= ptr.MaxAddr then
        covered <- covered + float range.Count
      else ()
    covered / txtSize

  /// Finds the exception target (landing pad) for a given instruction address.
  /// If the address is not in the exception table, it returns None.
  member _.TryFindExceptionTarget insAddr =
    NoOverlapIntervalMap.tryFindByAddr insAddr exnTbl
