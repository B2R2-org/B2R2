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

module internal B2R2.FrontEnd.BinHandleNS.Helper

open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open System.Text

let initBasis isa =
  match isa.Arch with
  | Arch.IntelX64
  | Arch.IntelX86 -> Intel.Basis.init isa
  | Arch.ARMv7 -> ARM32.Basis.init isa
  | Arch.AARCH64 -> ARM64.Basis.init isa
  | Arch.MIPS1 | Arch.MIPS2 | Arch.MIPS3 | Arch.MIPS4 | Arch.MIPS5
  | Arch.MIPS32 | Arch.MIPS32R2 | Arch.MIPS32R6
  | Arch.MIPS64 | Arch.MIPS64R2 | Arch.MIPS64R6 -> MIPS.Basis.init isa
  | Arch.EVM -> EVM.Basis.init isa
  | Arch.TMS320C6000 -> TMS320C6000.Basis.init isa
  | _ -> Utils.futureFeature ()

let identifyFormatAndISA bytes path isa autoDetect =
  if autoDetect then
    if System.IO.File.Exists path then FormatDetector.identifyFromFile path isa
    else FormatDetector.identifyFromBuffer bytes isa
  else FileFormat.RawBinary, isa

let newFileInfo bytes (baddr: Addr) path fmt isa regbay =
  match fmt with
  | FileFormat.ELFBinary ->
    ELFFileInfo (bytes, path, baddr, Some regbay) :> FileInfo
  | FileFormat.PEBinary ->
    PEFileInfo (bytes, path, baddr) :> FileInfo
  | FileFormat.MachBinary ->
    MachFileInfo (bytes, path, isa, baddr) :> FileInfo
  | _ -> new RawFileInfo (bytes, isa, baddr) :> FileInfo

let detectThumb entryPoint (isa: ISA) =
  match entryPoint, isa.Arch with
  | Some entry, Arch.ARMv7 when entry % 2UL <> 0UL -> (* XXX: LIbraries? *)
    ArchOperationMode.ThumbMode
  | _ -> ArchOperationMode.ARMMode

let isARM (isa: ISA) =
  match isa.Arch with
  | Arch.ARMv7 | Arch.AARCH32 | Arch.AARCH64 -> true
  | _ -> false

let inline lift translator addr bbl =
  let liftFolder (stmts, nextAddr) (ins: Instruction) =
    ins.Translate translator :: stmts, nextAddr + uint64 ins.Length
  let stmts, addr = List.fold liftFolder ([], addr) bbl
  struct (List.rev stmts |> Array.concat, addr)

let inline disasm showAddr resolveSymbol disasmHelper addr bbl =
  let disasmFolder (sb: StringBuilder, nextAddr) (ins: Instruction) =
    let s = ins.Disasm (showAddr, resolveSymbol, disasmHelper)
    let s = if sb.Length = 0 then s else System.Environment.NewLine + s
    sb.Append(s), nextAddr + uint64 ins.Length
  let sb, addr = List.fold disasmFolder (StringBuilder (), addr) bbl
  struct (sb.ToString (), addr)

/// Classify ranges to be either in-file or not-in-file. The second parameter
/// (notinfiles) is a sequence of (exclusive) ranges within the myrange, which
/// represent the not-in-file ranges. This function will simply divide the
/// myrange into subranges where each subrange is labeled with either true or
/// false, where true means in-file, and false means not-in-file.
let classifyRanges myrange notinfiles =
  notinfiles
  |> Seq.fold (fun (infiles, saddr) r ->
       let l = AddrRange.GetMin r
       let h = AddrRange.GetMax r
       if saddr = l then (r, false) :: infiles, h
       else (r, false) :: ((AddrRange (saddr, l), true) :: infiles), h
     ) ([], AddrRange.GetMin myrange)
  |> (fun (infiles, saddr) ->
       if saddr = myrange.Max then infiles
       else ((AddrRange (saddr, myrange.Max), true) :: infiles))
  |> List.rev
