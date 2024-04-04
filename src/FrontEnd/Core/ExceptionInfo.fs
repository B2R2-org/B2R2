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

open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.ELF

/// ExceptionInfo holds parsed exception information of a binary code (given by
/// the BinHandle).
type ExceptionInfo (hdl: BinHandle) =
  let loadCallSiteTable lsdaPointer lsdas =
    let lsda = Map.find lsdaPointer lsdas
    lsda.CallSiteTable

  /// If a landing pad has a direct branch to another function, then we consider
  /// the frame containing the lading pad as a non-function FDE.
  let checkIfFDEIsFunction fde landingPad =
    match hdl.ParseBBlock (addr=landingPad) with
    | Ok (blk) ->
      let last = List.last blk
      if last.IsCall () |> not then
        match last.DirectBranchTarget () with
        | true, jmpTarget -> fde.PCBegin <= jmpTarget && jmpTarget < fde.PCEnd
        | _ -> true
      else true
    | _ -> true

  let rec loopCallSiteTable fde isFDEFunc acc = function
    | [] -> acc, isFDEFunc
    | csrec :: rest ->
      let blockStart = fde.PCBegin + csrec.Position
      let blockEnd = fde.PCBegin + csrec.Position + csrec.Length - 1UL
      let landingPad =
        if csrec.LandingPad = 0UL then 0UL else fde.PCBegin + csrec.LandingPad
      if landingPad = 0UL then loopCallSiteTable fde isFDEFunc acc rest
      else
        let acc = ARMap.add (AddrRange (blockStart, blockEnd)) landingPad acc
        let isFDEFunc = checkIfFDEIsFunction fde landingPad
        loopCallSiteTable fde isFDEFunc acc rest

  let buildExceptionTable fde lsdas tbl =
    match fde.LSDAPointer with
    | None -> tbl, true
    | Some lsdaPointer ->
      loopCallSiteTable fde true tbl (loadCallSiteTable lsdaPointer lsdas)

  let accumulateExceptionTableInfo acc fde lsdas =
    fde
    |> Array.fold (fun (exnTbl, fnEntryPoints) fde ->
       let exnTbl, isFDEFunction = buildExceptionTable fde lsdas exnTbl
       let fnEntryPoints =
        if isFDEFunction then Set.add fde.PCBegin fnEntryPoints
        else fnEntryPoints
       exnTbl, fnEntryPoints) acc

  let computeExceptionTable excframes lsdas =
    excframes
    |> List.fold (fun acc frame ->
      accumulateExceptionTableInfo acc frame.FDERecord lsdas
    ) (ARMap.empty, Set.empty)

  let buildELF (elf: ELFBinFile) =
    let exn = elf.ExceptionInfo
    computeExceptionTable exn.ExceptionFrames exn.LSDAs

  let exnTbl, funcEntryPoints =
    match hdl.File.Format with
    | FileFormat.ELFBinary -> buildELF (hdl.File :?> ELFBinFile)
    | _ -> ARMap.empty, Set.empty

  /// For a given instruction address, find the landing pad (exception target)
  /// of the instruction.
  member __.TryFindExceptionTarget insAddr =
    ARMap.tryFindByAddr insAddr exnTbl

  /// Return a set of function entry points that are visible from exception
  /// table information.
  member __.GetFunctionEntryPoints () =
    funcEntryPoints
