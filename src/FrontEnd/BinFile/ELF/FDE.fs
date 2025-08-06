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
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile

/// Represents the Frame Description Entry (FDE).
type FDE =
  { PCBegin: Addr
    PCEnd: Addr
    LSDAPointer: Addr option
    UnwindingInfo: UnwindingEntry list }

[<RequireQualifiedAccess>]
module internal FDE =
  /// Raised when CIE is not found by FDE
  exception CIENotFoundByFDEException

  let tryFindAugmentation cie format =
    cie.Augmentations |> List.tryFind (fun aug -> aug.Format = format)

  let adjustAddr app myAddr addr =
    match app with
    | ExceptionHeaderApplication.DW_EH_PE_pcrel -> addr + myAddr
    | _ -> addr

  let parsePCInfo cls span reader sAddr relOpt venc aenc offset =
    let myAddr = sAddr + uint64 offset
    let struct (addr, offset) =
      ExceptionHeaderValue.read cls span reader venc offset
    let struct (range, offset) =
      ExceptionHeaderValue.read cls span reader venc offset
    let beginAddr = adjustAddr aenc myAddr addr
    let endAddr = beginAddr + range
    match (relOpt: RelocationInfo option) with
    | Some relInfo ->
      match relInfo.TryFind beginAddr with
      | Ok rentry ->
        let beginAddr = addr + rentry.RelAddend
        struct (beginAddr, beginAddr + range, offset)
      | Error _ -> struct (beginAddr, endAddr, offset)
    | None -> struct (beginAddr, endAddr, offset)

  let parseLSDA cls span reader sAddr aug offset =
    let _, offset = FileHelper.readULEB128 span offset
    let myAddr = sAddr + uint64 offset
    let struct (addr, offset) =
      ExceptionHeaderValue.read cls span reader aug.ValueEncoding offset
    Some(adjustAddr aug.ApplicationEncoding myAddr addr), offset

  let parseCallFrameInstrs cie isa registerFactory span offset nextOffset loc =
    let span = (span: ByteSpan).Slice(offset, nextOffset - offset)
    let insarr = span.ToArray()
    if Array.forall (fun b -> b = 0uy) insarr then []
    else
      let cf = cie.CodeAlignmentFactor
      let df = cie.DataAlignmentFactor
      let rr = cie.ReturnAddressRegister
      let ir = cie.InitialCFARegister
      let r = cie.InitialRule
      let cfa = cie.InitialCFA
      let info, _, _ =
        CIE.getUnwind [] cfa r [] r isa registerFactory ir cf df rr span 0 loc
      info

  let parse cls isa regs span reader sAddr offset nextOffset reloc cie =
    match cie with
    | Some cie ->
      let venc, aenc =
        match tryFindAugmentation cie 'R' with
        | Some aug -> aug.ValueEncoding, aug.ApplicationEncoding
        | None -> ExceptionHeaderValue.DW_EH_PE_absptr,
                  ExceptionHeaderApplication.DW_EH_PE_omit
      let struct (b, e, offset) =
        parsePCInfo cls span reader sAddr reloc venc aenc offset
      let lsdaPointer, offset =
        match tryFindAugmentation cie 'L' with
        | Some aug -> parseLSDA cls span reader sAddr aug offset
        | None -> None, offset
      let info = parseCallFrameInstrs cie isa regs span offset nextOffset b
      { PCBegin = b
        PCEnd = e
        LSDAPointer = lsdaPointer
        UnwindingInfo = info }
    | None -> raise CIENotFoundByFDEException
