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

namespace B2R2.FrontEnd.BinLifter.ARM32

open System
open B2R2
open B2R2.FrontEnd.BinLifter

module private Parser =

  let parseARM (span: ByteSpan) (phlp: ParsingHelper) =
    let bin = phlp.BinReader.ReadUInt32 (span, 0)
    phlp.Len <- 4u
    ARMParser.parse phlp bin

  let parseThumb span phlp (itstate: byref<byte list>) =
    ThumbParser.parse span phlp &itstate

  let detectThumb entryPoint (isa: ISA) =
    match entryPoint, isa.Arch with
    | Some entry, Arch.ARMv7 when entry % 2UL <> 0UL -> (* XXX: LIbraries? *)
      ArchOperationMode.ThumbMode
    | _ -> ArchOperationMode.ARMMode

/// Parser for 32-bit ARM instructions. Parser will return a platform-agnostic
/// instruction type (Instruction).
type ARM32Parser (isa: ISA, mode, entryPoint: Addr option) =
  inherit Parser ()

  let oparsers = [|
    OprNo () :> OperandParser
    OprBankregRnA () :> OperandParser
    OprCoprocCRdMem () :> OperandParser
    OprCpOpc1CRdCRnCRmOpc2 () :> OperandParser
    OprCpOpc1RtCRnCRmOpc2 () :> OperandParser
    OprCpOpc1RtRt2CRm () :> OperandParser
    OprDd0Rt () :> OperandParser
    OprDd1Rt () :> OperandParser
    OprDd2Rt () :> OperandParser
    OprDd3Rt () :> OperandParser
    OprDd4Rt () :> OperandParser
    OprDd5Rt () :> OperandParser
    OprDd6Rt () :> OperandParser
    OprDd7Rt () :> OperandParser
    OprDdDm () :> OperandParser
    OprDdDmDn () :> OperandParser
    OprDdDmFbits () :> OperandParser
    OprDdDmImm () :> OperandParser
    OprDdDmImm0 () :> OperandParser
    OprDdDmImmLeft () :> OperandParser
    OprDdDmx () :> OperandParser
    OprDdDnDm () :> OperandParser
    OprDdDnDm0Rotate () :> OperandParser
    OprDdDnDmidx () :> OperandParser
    OprDdDnDmidxRotate () :> OperandParser
    OprDdDnDmImm () :> OperandParser
    OprDdDnDmRotate () :> OperandParser
    OprDdDnDmx () :> OperandParser
    OprDdImm0 () :> OperandParser
    OprDdImm8A () :> OperandParser
    OprDdImm16A () :> OperandParser
    OprDdImm32A () :> OperandParser
    OprDdImm64A () :> OperandParser
    OprDdImmF32A () :> OperandParser
    OprDdLabel () :> OperandParser
    OprDdListDm () :> OperandParser
    OprDdmDdmFbits () :> OperandParser
    OprDdMem () :> OperandParser
    OprDdQm () :> OperandParser
    OprDdQmImm () :> OperandParser
    OprDdQnQm () :> OperandParser
    OprDdRt () :> OperandParser
    OprDdSm () :> OperandParser
    OprDdSnSm () :> OperandParser
    OprDdSnSmidx () :> OperandParser
    OprDdVImm () :> OperandParser
    OprDmRtRt2 () :> OperandParser
    OprEndianA () :> OperandParser
    OprIflagsA () :> OperandParser
    OprIflagsModeA () :> OperandParser
    OprImm16A () :> OperandParser
    OprImm1A () :> OperandParser
    OprImm24 () :> OperandParser
    OprImm4A () :> OperandParser
    OprLabel12A () :> OperandParser
    OprLabelA () :> OperandParser
    OprLabelH () :> OperandParser
    OprListMem () :> OperandParser
    OprListMem1 () :> OperandParser
    OprListMem2 () :> OperandParser
    OprListMem3 () :> OperandParser
    OprListMem4 () :> OperandParser
    OprListMemA () :> OperandParser
    OprListMemB () :> OperandParser
    OprListMemC () :> OperandParser
    OprListMemD () :> OperandParser
    OprMemImm () :> OperandParser
    OprMemRegA () :> OperandParser
    OprMode () :> OperandParser
    OprOpt () :> OperandParser
    OprP14C5Label () :> OperandParser
    OprP14C5Mem () :> OperandParser
    OprP14C5Option () :> OperandParser
    OprQdDm () :> OperandParser
    OprQdDmImm () :> OperandParser
    OprQdDmImm16 () :> OperandParser
    OprQdDmImm32 () :> OperandParser
    OprQdDmImm8 () :> OperandParser
    OprQdDmx () :> OperandParser
    OprQdDnDm () :> OperandParser
    OprQdDnDmidx () :> OperandParser
    OprQdDnDmx () :> OperandParser
    OprQdImm8A () :> OperandParser
    OprQdImm16A () :> OperandParser
    OprQdImm32A () :> OperandParser
    OprQdImm64A () :> OperandParser
    OprQdImmF32A () :> OperandParser
    OprQdQm () :> OperandParser
    OprQdQmFbits () :> OperandParser
    OprQdQmImm () :> OperandParser
    OprQdQmImm0 () :> OperandParser
    OprQdQmImmLeft () :> OperandParser
    OprQdQmQn () :> OperandParser
    OprQdQnDm () :> OperandParser
    OprQdQnDm0Rotate () :> OperandParser
    OprQdQnDmidx () :> OperandParser
    OprQdQnDmidxm () :> OperandParser
    OprQdQnDmidxRotate () :> OperandParser
    OprQdQnDmx () :> OperandParser
    OprQdQnQm () :> OperandParser
    OprQdQnQmImm () :> OperandParser
    OprQdQnQmRotate () :> OperandParser
    OprQdRt () :> OperandParser
    OprRdBankregA () :> OperandParser
    OprRdConstA () :> OperandParser
    OprRdConstCF () :> OperandParser
    OprRdImm16A () :> OperandParser
    OprRdImmRnA () :> OperandParser
    OprRdImmRnShfA () :> OperandParser
    OprRdImmRnShfUA () :> OperandParser
    OprRdLabelA () :> OperandParser
    OprRdlRdhRnRmA () :> OperandParser
    OprRdLsbWidthA () :> OperandParser
    OprRdRm () :> OperandParser
    OprRdRmImmA () :> OperandParser
    OprRdRmRnA () :> OperandParser
    OprRdRmRorA () :> OperandParser
    OprRdRmRsA () :> OperandParser
    OprRdRmShf () :> OperandParser
    OprRdRmShfRsA () :> OperandParser
    OprRdRnConstA () :> OperandParser
    OprRdRnConstCF () :> OperandParser
    OprRdRnLsbWidthA () :> OperandParser
    OprRdRnLsbWidthM1A () :> OperandParser
    OprRdRnRm () :> OperandParser
    OprRdRnRmOpt () :> OperandParser
    OprRdRnRmRaA () :> OperandParser
    OprRdRnRmRorA () :> OperandParser
    OprRdRnRmShfA () :> OperandParser
    OprRdRnRmShfRs () :> OperandParser
    OprRdRtMemA () :> OperandParser
    OprRdRtMemImmA () :> OperandParser
    OprRdRtRt2MemA () :> OperandParser
    OprRdSPConstA () :> OperandParser
    OprRdSregA () :> OperandParser
    OprRegs () :> OperandParser
    OprRm () :> OperandParser
    OprRn () :> OperandParser
    OprRnConstA () :> OperandParser
    OprRnConstCF () :> OperandParser
    OprRnDreglist () :> OperandParser
    OprRnRegsA () :> OperandParser
    OprRnRegsCaret () :> OperandParser
    OprRnRmShfA () :> OperandParser
    OprRnRmShfRs () :> OperandParser
    OprRnSreglist () :> OperandParser
    OprRt15Mem () :> OperandParser
    OprRtDn0 () :> OperandParser
    OprRtDn1 () :> OperandParser
    OprRtDn2 () :> OperandParser
    OprRtDn3 () :> OperandParser
    OprRtDn4 () :> OperandParser
    OprRtDn5 () :> OperandParser
    OprRtDn6 () :> OperandParser
    OprRtDn7 () :> OperandParser
    OprRtLabelA () :> OperandParser
    OprRtLabelHL () :> OperandParser
    OprRtMem () :> OperandParser
    OprRtMemImm () :> OperandParser
    OprRtMemImm0A () :> OperandParser
    OprRtMemImm12A () :> OperandParser
    OprRtMemImm12P () :> OperandParser
    OprRtMemImmP () :> OperandParser
    OprRtMemReg () :> OperandParser
    OprRtMemRegP () :> OperandParser
    OprRtMemShf () :> OperandParser
    OprRtMemShfP () :> OperandParser
    OprRtRt2Dm () :> OperandParser
    OprRtRt2LabelA () :> OperandParser
    OprRtRt2Mem2 () :> OperandParser
    OprRtRt2MemA () :> OperandParser
    OprRtRt2MemImmA () :> OperandParser
    OprRtRt2MemReg () :> OperandParser
    OprRtRt2SmSm1 () :> OperandParser
    OprRtSn () :> OperandParser
    OprRtSreg () :> OperandParser
    OprSdDm () :> OperandParser
    OprSdImm0 () :> OperandParser
    OprSdLabel () :> OperandParser
    OprSdMem () :> OperandParser
    OprSdmSdmFbits () :> OperandParser
    OprSdSm () :> OperandParser
    OprSdSnSm () :> OperandParser
    OprSdVImm () :> OperandParser
    OprSingleRegsA () :> OperandParser
    OprSmSm1RtRt2 () :> OperandParser
    OprSnRt () :> OperandParser
    OprSPMode () :> OperandParser
    OprSregImm () :> OperandParser
    OprSregRnA () :> OperandParser
    OprSregRt () :> OperandParser
    OprBankregRnT () :> OperandParser
    OprCondition () :> OperandParser
    OprDdDm0 () :> OperandParser
    OprDdImm8T () :> OperandParser
    OprDdImm16T () :> OperandParser
    OprDdImm32T () :> OperandParser
    OprDdImm64T () :> OperandParser
    OprDdImmF32T () :> OperandParser
    OprEndianT () :> OperandParser
    OprIflagsModeT () :> OperandParser
    OprIflagsT16 () :> OperandParser
    OprIflagsT32 () :> OperandParser
    OprImm16T () :> OperandParser
    OprImm1T () :> OperandParser
    OprImm4T () :> OperandParser
    OprImm6 () :> OperandParser
    OprImm8 () :> OperandParser
    OprLabel12T () :> OperandParser
    OprLabel8 () :> OperandParser
    OprLabelT () :> OperandParser
    OprLabelT2 () :> OperandParser
    OprLabelT3 () :> OperandParser
    OprLabelT4 () :> OperandParser
    OprMemImm12 () :> OperandParser
    OprMemImm8M () :> OperandParser
    OprMemRegLSL () :> OperandParser
    OprMemRegLSL1 () :> OperandParser
    OprMemRegT () :> OperandParser
    OprOptImm () :> OperandParser
    OprPCLRImm8 () :> OperandParser
    OprQdImm8T () :> OperandParser
    OprQdImm16T () :> OperandParser
    OprQdImm32T () :> OperandParser
    OprQdImm64T () :> OperandParser
    OprQdImmF32T () :> OperandParser
    OprQdQm0 () :> OperandParser
    OprRdBankregT () :> OperandParser
    OprRdConstT () :> OperandParser
    OprRdImm16T () :> OperandParser
    OprRdImm8 () :> OperandParser
    OprRdImmRnShfT () :> OperandParser
    OprRdImmRnShfUT () :> OperandParser
    OprRdImmRnT () :> OperandParser
    OprRdImmRnU () :> OperandParser
    OprRdLabelT () :> OperandParser
    OprRdlRdhRnRmT () :> OperandParser
    OprRdLsbWidthT () :> OperandParser
    OprRdmRdmASRRs () :> OperandParser
    OprRdmRdmLSLRs () :> OperandParser
    OprRdmRdmLSRRs () :> OperandParser
    OprRdmRdmRORRs () :> OperandParser
    OprRdmRnRdm () :> OperandParser
    OprRdmSPRdm () :> OperandParser
    OprRdnImm8 () :> OperandParser
    OprRdnRdnRm () :> OperandParser
    OprRdnRm () :> OperandParser
    OprRdRmExt () :> OperandParser
    OprRdRmImmT16 () :> OperandParser
    OprRdRmImmT32 () :> OperandParser
    OprRdRmRnT () :> OperandParser
    OprRdRmRorT () :> OperandParser
    OprRdRmRsT () :> OperandParser
    OprRdRmShfT16 () :> OperandParser
    OprRdRmShfT32 () :> OperandParser
    OprRdRmT16 () :> OperandParser
    OprRdRmT32 () :> OperandParser
    OprRdRn0 () :> OperandParser
    OprRdRn0T32 () :> OperandParser
    OprRdRnConstT () :> OperandParser
    OprRdRnImm12 () :> OperandParser
    OprRdRnImm3 () :> OperandParser
    OprRdRnLsbWidthM1T () :> OperandParser
    OprRdRnLsbWidthT () :> OperandParser
    OprRdRnRmRaT () :> OperandParser
    OprRdRnRmRorT () :> OperandParser
    OprRdRnRmShfT () :> OperandParser
    OprRdRnRmT16 () :> OperandParser
    OprRdRnRmT32 () :> OperandParser
    OprRdRtMemImmT () :> OperandParser
    OprRdRtMemT () :> OperandParser
    OprRdRtRt2MemT () :> OperandParser
    OprRdSPConstT () :> OperandParser
    OprRdSPImm12 () :> OperandParser
    OprRdSPImm8 () :> OperandParser
    OprRdSPRmShf () :> OperandParser
    OprRdSregT () :> OperandParser
    OprRegsM () :> OperandParser
    OprRegsP () :> OperandParser
    OprRmT16 () :> OperandParser
    OprRmT32 () :> OperandParser
    OprRnConstT () :> OperandParser
    OprRnLabel () :> OperandParser
    OprRnRegsT16 () :> OperandParser
    OprRnRegsT32 () :> OperandParser
    OprRnRegsW () :> OperandParser
    OprRnRm () :> OperandParser
    OprRnRmExt () :> OperandParser
    OprRnRmShfT () :> OperandParser
    OprRtLabel12 () :> OperandParser
    OprRtLabelT () :> OperandParser
    OprRtMemImm0T () :> OperandParser
    OprRtMemImm1 () :> OperandParser
    OprRtMemImm12T () :> OperandParser
    OprRtMemImm2 () :> OperandParser
    OprRtMemImm8 () :> OperandParser
    OprRtMemImm8M () :> OperandParser
    OprRtMemImm8P () :> OperandParser
    OprRtMemImmPr () :> OperandParser
    OprRtMemImmPs () :> OperandParser
    OprRtMemReg16 () :> OperandParser
    OprRtMemReg32 () :> OperandParser
    OprRtMemRegLSL () :> OperandParser
    OprRtMemSP () :> OperandParser
    OprRtRt2LabelT () :> OperandParser
    OprRtRt2MemImmT () :> OperandParser
    OprRtRt2MemT () :> OperandParser
    OprSingleRegsT () :> OperandParser
    OprSPSPImm7 () :> OperandParser
    OprSPSPRm () :> OperandParser
    OprSregRnT () :> OperandParser |]

  let mutable mode: ArchOperationMode =
    if mode = ArchOperationMode.NoMode then
      Parser.detectThumb entryPoint isa
    else mode

  let reader = BinReader.Init isa.Endian

  let phlp = ParsingHelper (isa.Arch, reader, oparsers)

  let mutable itstate: byte list = []

  override __.OperationMode with get() = mode and set(m) = mode <- m

  override __.Parse (span: ByteSpan, addr) =
    phlp.Mode <- mode
    phlp.InsAddr <- addr
    match mode with
    | ArchOperationMode.ThumbMode ->
      Parser.parseThumb span phlp &itstate :> Instruction
    | ArchOperationMode.ARMMode ->
      Parser.parseARM span phlp :> Instruction
    | _-> raise InvalidTargetArchModeException

  override __.Parse (bs: byte[], addr) =
    let span = ReadOnlySpan bs
    __.Parse (span, addr)

// vim: set tw=80 sts=2 sw=2:
