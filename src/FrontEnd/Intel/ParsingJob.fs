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

namespace B2R2.FrontEnd.Intel

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Intel
open B2R2.FrontEnd.Intel.ParsingFunctions
open LanguagePrimitives

[<AbstractClass>]
type internal ParsingJob () =
  abstract Run: ByteSpan * ParsingHelper -> Instruction

type internal OneOp00 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RmGpr].Render (span, phlp)
    newInstruction phlp Opcode.ADD oprs

type internal OneOp01 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RmGpr].Render (span, phlp)
    newInstruction phlp Opcode.ADD oprs

type internal OneOp02 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.GprRm].Render (span, phlp)
    newInstruction phlp Opcode.ADD oprs

type internal OneOp03 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.GprRm].Render (span, phlp)
    newInstruction phlp Opcode.ADD oprs

type internal OneOp04 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RegImm8].Render (span, phlp)
    newInstruction phlp Opcode.ADD oprs

type internal OneOp05 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RegImm].Render (span, phlp)
    newInstruction phlp Opcode.ADD oprs

type internal OneOp06 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.RegW].Render phlp SzCond.Normal
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.Es].Render (span, phlp)
    newInstruction phlp Opcode.PUSH oprs

type internal OneOp07 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.RegW].Render phlp SzCond.Normal
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.Es].Render (span, phlp)
    newInstruction phlp Opcode.POP oprs

type internal OneOp08 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RmGpr].Render (span, phlp)
    newInstruction phlp Opcode.OR oprs

type internal OneOp09 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RmGpr].Render (span, phlp)
    newInstruction phlp Opcode.OR oprs

type internal OneOp0A () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.GprRm].Render (span, phlp)
    newInstruction phlp Opcode.OR oprs

type internal OneOp0B () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.GprRm].Render (span, phlp)
    newInstruction phlp Opcode.OR oprs

type internal OneOp0C () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RegImm8].Render (span, phlp)
    newInstruction phlp Opcode.OR oprs

type internal OneOp0D () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RegImm].Render (span, phlp)
    newInstruction phlp Opcode.OR oprs

type internal OneOp0E () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.RegW].Render phlp SzCond.Normal
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.Cs].Render (span, phlp)
    newInstruction phlp Opcode.PUSH oprs

type internal OneOp0F () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    parseTwoByteOpcode span phlp

type internal OneOp10 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RmGpr].Render (span, phlp)
    newInstruction phlp Opcode.ADC oprs

type internal OneOp11 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RmGpr].Render (span, phlp)
    newInstruction phlp Opcode.ADC oprs

type internal OneOp12 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.GprRm].Render (span, phlp)
    newInstruction phlp Opcode.ADC oprs

type internal OneOp13 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.GprRm].Render (span, phlp)
    newInstruction phlp Opcode.ADC oprs

type internal OneOp14 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RegImm8].Render (span, phlp)
    newInstruction phlp Opcode.ADC oprs

type internal OneOp15 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RegImm].Render (span, phlp)
    newInstruction phlp Opcode.ADC oprs

type internal OneOp16 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.RegW].Render phlp SzCond.Normal
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.Ss].Render (span, phlp)
    newInstruction phlp Opcode.PUSH oprs

type internal OneOp17 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.RegW].Render phlp SzCond.Normal
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.Ss].Render (span, phlp)
    newInstruction phlp Opcode.POP oprs

type internal OneOp18 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RmGpr].Render (span, phlp)
    newInstruction phlp Opcode.SBB oprs

type internal OneOp19 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RmGpr].Render (span, phlp)
    newInstruction phlp Opcode.SBB oprs

type internal OneOp1A () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.GprRm].Render (span, phlp)
    newInstruction phlp Opcode.SBB oprs

type internal OneOp1B () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.GprRm].Render (span, phlp)
    newInstruction phlp Opcode.SBB oprs

type internal OneOp1C () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RegImm8].Render (span, phlp)
    newInstruction phlp Opcode.SBB oprs

type internal OneOp1D () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RegImm].Render (span, phlp)
    newInstruction phlp Opcode.SBB oprs

type internal OneOp1E () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.RegW].Render phlp SzCond.Normal
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.Ds].Render (span, phlp)
    newInstruction phlp Opcode.PUSH oprs

type internal OneOp1F () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.RegW].Render phlp SzCond.Normal
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.Ds].Render (span, phlp)
    newInstruction phlp Opcode.POP oprs

type internal OneOp20 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RmGpr].Render (span, phlp)
    newInstruction phlp Opcode.AND oprs

type internal OneOp21 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RmGpr].Render (span, phlp)
    newInstruction phlp Opcode.AND oprs

type internal OneOp22 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.GprRm].Render (span, phlp)
    newInstruction phlp Opcode.AND oprs

type internal OneOp23 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.GprRm].Render (span, phlp)
    newInstruction phlp Opcode.AND oprs

type internal OneOp24 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RegImm8].Render (span, phlp)
    newInstruction phlp Opcode.AND oprs

type internal OneOp25 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RegImm].Render (span, phlp)
    newInstruction phlp Opcode.AND oprs

type internal OneOp26 () =
  inherit ParsingJob ()
  override _.Run (_, _) = raise ParsingFailureException

type internal OneOp27 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.DAA oprs

type internal OneOp28 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RmGpr].Render (span, phlp)
    newInstruction phlp Opcode.SUB oprs

type internal OneOp29 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RmGpr].Render (span, phlp)
    newInstruction phlp Opcode.SUB oprs

type internal OneOp2A () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.GprRm].Render (span, phlp)
    newInstruction phlp Opcode.SUB oprs

type internal OneOp2B () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.GprRm].Render (span, phlp)
    newInstruction phlp Opcode.SUB oprs

type internal OneOp2C () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RegImm8].Render (span, phlp)
    newInstruction phlp Opcode.SUB oprs

type internal OneOp2D () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RegImm].Render (span, phlp)
    newInstruction phlp Opcode.SUB oprs

type internal OneOp2E () =
  inherit ParsingJob ()
  override _.Run (_, _) = raise ParsingFailureException

type internal OneOp2F () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.DAS oprs

type internal OneOp30 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RmGpr].Render (span, phlp)
    newInstruction phlp Opcode.XOR oprs

type internal OneOp31 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RmGpr].Render (span, phlp)
    newInstruction phlp Opcode.XOR oprs

type internal OneOp32 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.GprRm].Render (span, phlp)
    newInstruction phlp Opcode.XOR oprs

type internal OneOp33 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.GprRm].Render (span, phlp)
    newInstruction phlp Opcode.XOR oprs

type internal OneOp34 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RegImm8].Render (span, phlp)
    newInstruction phlp Opcode.XOR oprs

type internal OneOp35 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RegImm].Render (span, phlp)
    newInstruction phlp Opcode.XOR oprs

type internal OneOp36 () =
  inherit ParsingJob ()
  override _.Run (_, _) = raise ParsingFailureException

type internal OneOp37 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.AAA oprs

type internal OneOp38 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RmGpr].Render (span, phlp)
    newInstruction phlp Opcode.CMP oprs

type internal OneOp39 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RmGpr].Render (span, phlp)
    newInstruction phlp Opcode.CMP oprs

type internal OneOp3A () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.GprRm].Render (span, phlp)
    newInstruction phlp Opcode.CMP oprs

type internal OneOp3B () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.GprRm].Render (span, phlp)
    newInstruction phlp Opcode.CMP oprs

type internal OneOp3C () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RegImm8].Render (span, phlp)
    newInstruction phlp Opcode.CMP oprs

type internal OneOp3D () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RegImm].Render (span, phlp)
    newInstruction phlp Opcode.CMP oprs

type internal OneOp3E () =
  inherit ParsingJob ()
  override _.Run (_, _) = raise ParsingFailureException

type internal OneOp3F () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.AAS oprs

type internal OneOp40 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.Eax].Render (span, phlp)
    newInstruction phlp Opcode.INC oprs

type internal OneOp41 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.Ecx].Render (span, phlp)
    newInstruction phlp Opcode.INC oprs

type internal OneOp42 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.Edx].Render (span, phlp)
    newInstruction phlp Opcode.INC oprs

type internal OneOp43 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.Ebx].Render (span, phlp)
    newInstruction phlp Opcode.INC oprs

type internal OneOp44 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.Esp].Render (span, phlp)
    newInstruction phlp Opcode.INC oprs

type internal OneOp45 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.Ebp].Render (span, phlp)
    newInstruction phlp Opcode.INC oprs

type internal OneOp46 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.Esi].Render (span, phlp)
    newInstruction phlp Opcode.INC oprs

type internal OneOp47 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.Edi].Render (span, phlp)
    newInstruction phlp Opcode.INC oprs

type internal OneOp48 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.Eax].Render (span, phlp)
    newInstruction phlp Opcode.DEC oprs

type internal OneOp49 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.Ecx].Render (span, phlp)
    newInstruction phlp Opcode.DEC oprs

type internal OneOp4A () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.Edx].Render (span, phlp)
    newInstruction phlp Opcode.DEC oprs

type internal OneOp4B () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.Ebx].Render (span, phlp)
    newInstruction phlp Opcode.DEC oprs

type internal OneOp4C () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.Esp].Render (span, phlp)
    newInstruction phlp Opcode.DEC oprs

type internal OneOp4D () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.Ebp].Render (span, phlp)
    newInstruction phlp Opcode.DEC oprs

type internal OneOp4E () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.Esi].Render (span, phlp)
    newInstruction phlp Opcode.DEC oprs

type internal OneOp4F () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.Edi].Render (span, phlp)
    newInstruction phlp Opcode.DEC oprs

type internal OneOp50 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.D64].Render phlp SzCond.D64
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.Rax].Render (span, phlp)
    newInstruction phlp Opcode.PUSH oprs

type internal OneOp51 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.D64].Render phlp SzCond.D64
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.Rcx].Render (span, phlp)
    newInstruction phlp Opcode.PUSH oprs

type internal OneOp52 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.D64].Render phlp SzCond.D64
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.Rdx].Render (span, phlp)
    newInstruction phlp Opcode.PUSH oprs

type internal OneOp53 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.D64].Render phlp SzCond.D64
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.Rbx].Render (span, phlp)
    newInstruction phlp Opcode.PUSH oprs

type internal OneOp54 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.D64].Render phlp SzCond.D64
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.Rsp].Render (span, phlp)
    newInstruction phlp Opcode.PUSH oprs

type internal OneOp55 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.D64].Render phlp SzCond.D64
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.Rbp].Render (span, phlp)
    newInstruction phlp Opcode.PUSH oprs

type internal OneOp56 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.D64].Render phlp SzCond.D64
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.Rsi].Render (span, phlp)
    newInstruction phlp Opcode.PUSH oprs

type internal OneOp57 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.D64].Render phlp SzCond.D64
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.Rdi].Render (span, phlp)
    newInstruction phlp Opcode.PUSH oprs

type internal OneOp58 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.D64].Render phlp SzCond.D64
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.Rax].Render (span, phlp)
    newInstruction phlp Opcode.POP oprs

type internal OneOp59 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.D64].Render phlp SzCond.D64
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.Rcx].Render (span, phlp)
    newInstruction phlp Opcode.POP oprs

type internal OneOp5A () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.D64].Render phlp SzCond.D64
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.Rdx].Render (span, phlp)
    newInstruction phlp Opcode.POP oprs

type internal OneOp5B () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.D64].Render phlp SzCond.D64
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.Rbx].Render (span, phlp)
    newInstruction phlp Opcode.POP oprs

type internal OneOp5C () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.D64].Render phlp SzCond.D64
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.Rsp].Render (span, phlp)
    newInstruction phlp Opcode.POP oprs

type internal OneOp5D () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.D64].Render phlp SzCond.D64
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.Rbp].Render (span, phlp)
    newInstruction phlp Opcode.POP oprs

type internal OneOp5E () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.D64].Render phlp SzCond.D64
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.Rsi].Render (span, phlp)
    newInstruction phlp Opcode.POP oprs

type internal OneOp5F () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.D64].Render phlp SzCond.D64
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.Rdi].Render (span, phlp)
    newInstruction phlp Opcode.POP oprs

type internal OneOp60 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    if Prefix.hasOprSz phlp.Prefixes then
      render span phlp Opcode.PUSHA SzCond.Normal OD.No SZ.Def
    else render span phlp Opcode.PUSHAD SzCond.Normal OD.No SZ.Def

type internal OneOp61 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    if Prefix.hasOprSz phlp.Prefixes then
      render span phlp Opcode.POPA SzCond.Normal OD.No SZ.Def
    else render span phlp Opcode.POPAD SzCond.Normal OD.No SZ.Def

type internal OneOp62 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    if (phlp.WordSize = WordSize.Bit64) || (phlp.PeekByte span >= 0xC0uy) then
      let mutable rex = phlp.REXPrefix
      let vInfo = getEVEXInfo span &rex phlp.CurrPos
      phlp.VEXInfo <- Some vInfo
      phlp.REXPrefix <- rex
      phlp.CurrPos <- phlp.CurrPos + 3
      match vInfo.VEXType &&& EnumOfValue<int, VEXType> 7 with
      | VEXType.VEXTwoByteOp -> parseTwoByteOpcode span phlp
      | VEXType.VEXThreeByteOpOne -> parseThreeByteOp1 span phlp
      | VEXType.VEXThreeByteOpTwo -> parseThreeByteOp2 span phlp
      | _ -> raise ParsingFailureException
    else
      phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
      let oprs = phlp.OprParsers[int OD.GprM].Render (span, phlp)
      newInstruction phlp Opcode.BOUND oprs

type internal OneOp63 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    if ParsingHelper.Is64bit phlp then
      render span phlp Opcode.MOVSXD SzCond.Normal OD.GprRm SZ.DV
    else render span phlp Opcode.ARPL SzCond.Normal OD.RmGpr SZ.Word

type internal OneOp64 () =
  inherit ParsingJob ()
  override _.Run (_, _) = raise ParsingFailureException

type internal OneOp65 () =
  inherit ParsingJob ()
  override _.Run (_, _) = raise ParsingFailureException

type internal OneOp66 () =
  inherit ParsingJob ()
  override _.Run (_, _) = raise ParsingFailureException

type internal OneOp67 () =
  inherit ParsingJob ()
  override _.Run (_, _) = raise ParsingFailureException

type internal OneOp68 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.D64
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.Imm].Render (span, phlp)
    newInstruction phlp Opcode.PUSH oprs

type internal OneOp69 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.GprRmImm].Render (span, phlp)
    newInstruction phlp Opcode.IMUL oprs

type internal OneOp6A () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.D64
    phlp.OperationSize <- phlp.MemEffOprSize
    let oprs = phlp.OprParsers[int OD.SImm8].Render (span, phlp)
    newInstruction phlp Opcode.PUSH oprs

type internal OneOp6B () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.GprRmImm8].Render (span, phlp)
    newInstruction phlp Opcode.IMUL oprs

type internal OneOp6C () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    phlp.OperationSize <- 8<rt>
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.INSB oprs

type internal OneOp6D () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    if Prefix.hasOprSz phlp.Prefixes then
      render span phlp Opcode.INSW SzCond.Normal OD.No SZ.Def
    else render span phlp Opcode.INSD SzCond.Normal OD.No SZ.Def

type internal OneOp6E () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    phlp.OperationSize <- 8<rt>
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.OUTSB oprs

type internal OneOp6F () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    if Prefix.hasOprSz phlp.Prefixes then
      render span phlp Opcode.OUTSW SzCond.Normal OD.No SZ.Def
    else render span phlp Opcode.OUTSD SzCond.Normal OD.No SZ.Def

type internal OneOp70 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    addBND phlp
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.Rel8].Render (span, phlp)
    newInstruction phlp Opcode.JO oprs

type internal OneOp71 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    addBND phlp
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.Rel8].Render (span, phlp)
    newInstruction phlp Opcode.JNO oprs

type internal OneOp72 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    addBND phlp
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.Rel8].Render (span, phlp)
    newInstruction phlp Opcode.JB oprs

type internal OneOp73 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    addBND phlp
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.Rel8].Render (span, phlp)
    newInstruction phlp Opcode.JNB oprs

type internal OneOp74 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    addBND phlp
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.Rel8].Render (span, phlp)
    newInstruction phlp Opcode.JZ oprs

type internal OneOp75 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    addBND phlp
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.Rel8].Render (span, phlp)
    newInstruction phlp Opcode.JNZ oprs

type internal OneOp76 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    addBND phlp
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.Rel8].Render (span, phlp)
    newInstruction phlp Opcode.JBE oprs

type internal OneOp77 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    addBND phlp
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.Rel8].Render (span, phlp)
    newInstruction phlp Opcode.JA oprs

type internal OneOp78 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    addBND phlp
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.Rel8].Render (span, phlp)
    newInstruction phlp Opcode.JS oprs

type internal OneOp79 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    addBND phlp
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.Rel8].Render (span, phlp)
    newInstruction phlp Opcode.JNS oprs

type internal OneOp7A () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    addBND phlp
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.Rel8].Render (span, phlp)
    newInstruction phlp Opcode.JP oprs

type internal OneOp7B () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    addBND phlp
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.Rel8].Render (span, phlp)
    newInstruction phlp Opcode.JNP oprs

type internal OneOp7C () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    addBND phlp
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.Rel8].Render (span, phlp)
    newInstruction phlp Opcode.JL oprs

type internal OneOp7D () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    addBND phlp
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.Rel8].Render (span, phlp)
    newInstruction phlp Opcode.JNL oprs

type internal OneOp7E () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    addBND phlp
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.Rel8].Render (span, phlp)
    newInstruction phlp Opcode.JLE oprs

type internal OneOp7F () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    addBND phlp
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.Rel8].Render (span, phlp)
    newInstruction phlp Opcode.JG oprs

type internal OneOp80 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span phlp OD.RmSImm8 SZ.Byte OpGroup.G1
    render span phlp op szCond oidx szidx

type internal OneOp81 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span phlp OD.RmImm SZ.Def OpGroup.G1
    render span phlp op szCond oidx szidx

type internal OneOp82 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span phlp OD.RmSImm8 SZ.Byte OpGroup.G1Inv64
    render span phlp op szCond oidx szidx

type internal OneOp83 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span phlp OD.RmSImm8 SZ.Def OpGroup.G1
    render span phlp op szCond oidx szidx

type internal OneOp84 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RmGpr].Render (span, phlp)
    newInstruction phlp Opcode.TEST oprs

type internal OneOp85 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RmGpr].Render (span, phlp)
    newInstruction phlp Opcode.TEST oprs

type internal OneOp86 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RmGpr].Render (span, phlp)
    newInstruction phlp Opcode.XCHG oprs

type internal OneOp87 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RmGpr].Render (span, phlp)
    newInstruction phlp Opcode.XCHG oprs

type internal OneOp88 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RmGpr].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOp89 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RmGpr].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOp8A () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.GprRm].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOp8B () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.GprRm].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOp8C () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Word].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RmSeg].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOp8D () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.GprM].Render (span, phlp)
    newInstruction phlp Opcode.LEA oprs

type internal OneOp8E () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Word].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.SegRm].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOp8F () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span phlp OD.Mem SZ.Def OpGroup.G1A
    render span phlp op szCond oidx szidx

type internal OneOp90 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    if Prefix.hasREPZ phlp.Prefixes then
      render span phlp Opcode.PAUSE SzCond.Normal OD.No SZ.Def
    elif REXPrefix.hasB phlp.REXPrefix then
      phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
      let oprs = phlp.OprParsers[int OD.RaxRax].Render (span, phlp)
      newInstruction phlp Opcode.XCHG oprs
    else render span phlp Opcode.NOP SzCond.Normal OD.No SZ.Def

type internal OneOp91 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RaxRcx].Render (span, phlp)
    newInstruction phlp Opcode.XCHG oprs

type internal OneOp92 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RaxRdx].Render (span, phlp)
    newInstruction phlp Opcode.XCHG oprs

type internal OneOp93 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RaxRbx].Render (span, phlp)
    newInstruction phlp Opcode.XCHG oprs

type internal OneOp94 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RaxRsp].Render (span, phlp)
    newInstruction phlp Opcode.XCHG oprs

type internal OneOp95 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RaxRbp].Render (span, phlp)
    newInstruction phlp Opcode.XCHG oprs

type internal OneOp96 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RaxRsi].Render (span, phlp)
    newInstruction phlp Opcode.XCHG oprs

type internal OneOp97 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RaxRdi].Render (span, phlp)
    newInstruction phlp Opcode.XCHG oprs

type internal OneOp98 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    if Prefix.hasOprSz phlp.Prefixes then
      render span phlp Opcode.CBW SzCond.Normal OD.No SZ.Def
    elif REXPrefix.hasW phlp.REXPrefix then
      render span phlp Opcode.CDQE SzCond.Normal OD.No SZ.Def
    else render span phlp Opcode.CWDE SzCond.Normal OD.No SZ.Def

type internal OneOp99 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    if Prefix.hasOprSz phlp.Prefixes then
      render span phlp Opcode.CWD SzCond.Normal OD.No SZ.Def
    elif REXPrefix.hasW phlp.REXPrefix then
      render span phlp Opcode.CQO SzCond.Normal OD.No SZ.Def
    else render span phlp Opcode.CDQ SzCond.Normal OD.No SZ.Def

type internal OneOp9A () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    addBND phlp
    phlp.SzComputers[int SZ.P].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.Dir].Render (span, phlp)
    newInstruction phlp Opcode.CALLFar oprs

type internal OneOp9B () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.WAIT oprs

type internal OneOp9C () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    if Prefix.hasOprSz phlp.Prefixes then
      let szcond =
        if ParsingHelper.Is64bit phlp then SzCond.D64 else SzCond.Normal
      render span phlp Opcode.PUSHF szcond OD.No SZ.Def
    elif ParsingHelper.Is64bit phlp then
      render span phlp Opcode.PUSHFQ SzCond.D64 OD.No SZ.Def
    else render span phlp Opcode.PUSHFD SzCond.Normal OD.No SZ.Def

type internal OneOp9D () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    if Prefix.hasOprSz phlp.Prefixes then
      let szcond =
        if ParsingHelper.Is64bit phlp then SzCond.D64 else SzCond.Normal
      render span phlp Opcode.POPF szcond OD.No SZ.Def
    elif ParsingHelper.Is64bit phlp then
      render span phlp Opcode.POPFQ SzCond.D64 OD.No SZ.Def
    else render span phlp Opcode.POPFD SzCond.Normal OD.No SZ.Def

type internal OneOp9E () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.SAHF oprs

type internal OneOp9F () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.LAHF oprs

type internal OneOpA0 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RaxFar].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOpA1 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RaxFar].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOpA2 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.FarRax].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOpA3 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.FarRax].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOpA4 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    phlp.OperationSize <- 8<rt>
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    if Prefix.hasREPNZ phlp.Prefixes then raise ParsingFailureException
    else newInstruction phlp Opcode.MOVSB oprs

type internal OneOpA5 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    if Prefix.hasOprSz phlp.Prefixes then
      render span phlp Opcode.MOVSW SzCond.Normal OD.No SZ.Def
    elif REXPrefix.hasW phlp.REXPrefix then
      render span phlp Opcode.MOVSQ SzCond.Normal OD.No SZ.Def
    else render span phlp Opcode.MOVSD SzCond.Normal OD.No SZ.Def

type internal OneOpA6 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.CMPSB oprs

type internal OneOpA7 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    if Prefix.hasOprSz phlp.Prefixes then
      render span phlp Opcode.CMPSW SzCond.Normal OD.No SZ.Def
    elif REXPrefix.hasW phlp.REXPrefix then
      render span phlp Opcode.CMPSQ SzCond.Normal OD.No SZ.Def
    else render span phlp Opcode.CMPSD SzCond.Normal OD.No SZ.Def

type internal OneOpA8 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RegImm8].Render (span, phlp)
    newInstruction phlp Opcode.TEST oprs

type internal OneOpA9 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RegImm].Render (span, phlp)
    newInstruction phlp Opcode.TEST oprs

type internal OneOpAA () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    phlp.OperationSize <- 8<rt>
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.STOSB oprs

type internal OneOpAB () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    if Prefix.hasOprSz phlp.Prefixes then
      render span phlp Opcode.STOSW SzCond.Normal OD.No SZ.Def
    elif REXPrefix.hasW phlp.REXPrefix then
      render span phlp Opcode.STOSQ SzCond.Normal OD.No SZ.Def
    else render span phlp Opcode.STOSD SzCond.Normal OD.No SZ.Def

type internal OneOpAC () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    phlp.OperationSize <- 8<rt>
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.LODSB oprs

type internal OneOpAD () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    if Prefix.hasOprSz phlp.Prefixes then
      render span phlp Opcode.LODSW SzCond.Normal OD.No SZ.Def
    elif REXPrefix.hasW phlp.REXPrefix then
      render span phlp Opcode.LODSQ SzCond.Normal OD.No SZ.Def
    else render span phlp Opcode.LODSD SzCond.Normal OD.No SZ.Def

type internal OneOpAE () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    phlp.OperationSize <- 8<rt>
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.SCASB oprs

type internal OneOpAF () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    if Prefix.hasOprSz phlp.Prefixes then
      render span phlp Opcode.SCASW SzCond.Normal OD.No SZ.Def
    elif REXPrefix.hasW phlp.REXPrefix then
      render span phlp Opcode.SCASQ SzCond.Normal OD.No SZ.Def
    else render span phlp Opcode.SCASD SzCond.Normal OD.No SZ.Def

type internal OneOpB0 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.ALImm8].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOpB1 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.CLImm8].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOpB2 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.DLImm8].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOpB3 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.BLImm8].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOpB4 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.AhImm8].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOpB5 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.ChImm8].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOpB6 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.DhImm8].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOpB7 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.BhImm8].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOpB8 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RaxImm].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOpB9 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RcxImm].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOpBA () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RdxImm].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOpBB () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RbxImm].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOpBC () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RspImm].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOpBD () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RbpImm].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOpBE () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RsiImm].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOpBF () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RdiImm].Render (span, phlp)
    newInstruction phlp Opcode.MOV oprs

type internal OneOpC0 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span phlp OD.RmSImm8 SZ.Byte OpGroup.G2
    render span phlp op szCond oidx szidx

type internal OneOpC1 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span phlp OD.RmSImm8 SZ.Def OpGroup.G2
    render span phlp op szCond oidx szidx

type internal OneOpC2 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    addBND phlp
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.Imm16].Render (span, phlp)
    newInstruction phlp Opcode.RETNearImm oprs

type internal OneOpC3 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    addBND phlp
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.RETNear oprs

type internal OneOpC4 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    if (phlp.WordSize = WordSize.Bit64) || (phlp.PeekByte span >= 0xC0uy) then
      let mutable rex = phlp.REXPrefix
      let vInfo = getThreeVEXInfo span &rex phlp.CurrPos
      phlp.VEXInfo <- Some vInfo
      phlp.REXPrefix <- rex
      phlp.CurrPos <- phlp.CurrPos + 2
      match vInfo.VEXType with
      | VEXType.VEXTwoByteOp -> parseTwoByteOpcode span phlp
      | VEXType.VEXThreeByteOpOne -> parseThreeByteOp1 span phlp
      | VEXType.VEXThreeByteOpTwo -> parseThreeByteOp2 span phlp
      | _ -> raise ParsingFailureException
    else
      phlp.SzComputers[int SZ.PZ].Render phlp SzCond.Normal
      let oprs = phlp.OprParsers[int OD.GprM].Render (span, phlp)
      newInstruction phlp Opcode.LES oprs

type internal OneOpC5 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    if (phlp.WordSize = WordSize.Bit64) || (phlp.PeekByte span >= 0xC0uy) then
      let mutable rex = phlp.REXPrefix
      phlp.VEXInfo <- Some (getTwoVEXInfo span &rex phlp.CurrPos)
      phlp.REXPrefix <- rex
      phlp.CurrPos <- phlp.CurrPos + 1
      parseTwoByteOpcode span phlp
    else
      phlp.SzComputers[int SZ.PZ].Render phlp SzCond.Normal
      let oprs = phlp.OprParsers[int OD.GprM].Render (span, phlp)
      newInstruction phlp Opcode.LDS oprs

type internal OneOpC6 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span phlp OD.RmSImm8 SZ.Byte OpGroup.G11A
    render span phlp op szCond oidx szidx

type internal OneOpC7 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span phlp OD.RmImm SZ.Def OpGroup.G11B
    render span phlp op szCond oidx szidx

type internal OneOpC8 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.ImmImm].Render (span, phlp)
    newInstruction phlp Opcode.ENTER oprs

type internal OneOpC9 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.D64
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.LEAVE oprs

type internal OneOpCA () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    addBND phlp
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.Imm16].Render (span, phlp)
    newInstruction phlp Opcode.RETFarImm oprs

type internal OneOpCB () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    addBND phlp
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.RETFar oprs

type internal OneOpCC () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.INT3 oprs

type internal OneOpCD () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.Imm8].Render (span, phlp)
    newInstruction phlp Opcode.INT oprs

type internal OneOpCE () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.INTO oprs

type internal OneOpCF () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    if Prefix.hasOprSz phlp.Prefixes then
      render span phlp Opcode.IRETW SzCond.Normal OD.No SZ.Def
    elif REXPrefix.hasW phlp.REXPrefix then
      render span phlp Opcode.IRETQ SzCond.Normal OD.No SZ.Def
    else render span phlp Opcode.IRETD SzCond.Normal OD.No SZ.Def

type internal OneOpD0 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span phlp OD.M1 SZ.Byte OpGroup.G2
    render span phlp op szCond oidx szidx

type internal OneOpD1 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span phlp OD.M1 SZ.Def OpGroup.G2
    render span phlp op szCond oidx szidx

type internal OneOpD2 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span phlp OD.RmCL SZ.Byte OpGroup.G2
    render span phlp op szCond oidx szidx

type internal OneOpD3 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span phlp OD.RmCL SZ.Def OpGroup.G2
    render span phlp op szCond oidx szidx

type internal OneOpD4 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.Imm8].Render (span, phlp)
    newInstruction phlp Opcode.AAM oprs

type internal OneOpD5 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.Imm8].Render (span, phlp)
    newInstruction phlp Opcode.AAD oprs

type internal OneOpD6 () =
  inherit ParsingJob ()
  override _.Run (_, _)= raise ParsingFailureException

type internal OneOpD7 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.XLATB oprs

type internal OneOpD8 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let modRM = phlp.ReadByte span
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    if modRM <= 0xBFuy then
      let op = getD8OpWithin00toBF modRM
      let effOprSize = getEscEffOprSizeByESCOp 0xD8uy
      phlp.MemEffOprSize <- effOprSize
      phlp.MemEffRegSize <- effOprSize
      let o = OperandParsers.parseMemory modRM span phlp
      newInstruction phlp op (OneOperand o)
    else
      let opcode, oprs = getD8OverBF modRM
      newInstruction phlp opcode oprs

type internal OneOpD9 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let modRM = phlp.ReadByte span
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    if modRM <= 0xBFuy then
      let op = getD9OpWithin00toBF modRM
      let effOprSize = Operands.getReg modRM |> getD9EscEffOprSizeByModRM
      phlp.MemEffOprSize <- effOprSize
      phlp.MemEffRegSize <- effOprSize
      let o = OperandParsers.parseMemory modRM span phlp
      newInstruction phlp op (OneOperand o)
    else
      let opcode, oprs = getD9OverBF modRM
      newInstruction phlp opcode oprs

type internal OneOpDA () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let modRM = phlp.ReadByte span
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    if modRM <= 0xBFuy then
      let op = getDAOpWithin00toBF modRM
      let effOprSize = getEscEffOprSizeByESCOp 0xDAuy
      phlp.MemEffOprSize <- effOprSize
      phlp.MemEffRegSize <- effOprSize
      let o = OperandParsers.parseMemory modRM span phlp
      newInstruction phlp op (OneOperand o)
    else
      let opcode, oprs = getDAOverBF modRM
      newInstruction phlp opcode oprs

type internal OneOpDB () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let modRM = phlp.ReadByte span
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    if modRM <= 0xBFuy then
      let op = getDBOpWithin00toBF modRM
      let effOprSize = Operands.getReg modRM |> getDBEscEffOprSizeByModRM
      phlp.MemEffOprSize <- effOprSize
      phlp.MemEffRegSize <- effOprSize
      let o = OperandParsers.parseMemory modRM span phlp
      newInstruction phlp op (OneOperand o)
    else
      let opcode, oprs = getDBOverBF modRM
      newInstruction phlp opcode oprs

type internal OneOpDC () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let modRM = phlp.ReadByte span
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    if modRM <= 0xBFuy then
      let op = getDCOpWithin00toBF modRM
      let effOprSize = getEscEffOprSizeByESCOp 0xDCuy
      phlp.MemEffOprSize <- effOprSize
      phlp.MemEffRegSize <- effOprSize
      let o = OperandParsers.parseMemory modRM span phlp
      newInstruction phlp op (OneOperand o)
    else
      let opcode, oprs = getDCOverBF modRM
      newInstruction phlp opcode oprs

type internal OneOpDD () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let modRM = phlp.ReadByte span
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    if modRM <= 0xBFuy then
      let op = getDDOpWithin00toBF modRM
      let effOprSize = Operands.getReg modRM |> getDDEscEffOprSizeByModRM
      phlp.MemEffOprSize <- effOprSize
      phlp.MemEffRegSize <- effOprSize
      let o = OperandParsers.parseMemory modRM span phlp
      newInstruction phlp op (OneOperand o)
    else
      let opcode, oprs = getDDOverBF modRM
      newInstruction phlp opcode oprs

type internal OneOpDE () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let modRM = phlp.ReadByte span
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    if modRM <= 0xBFuy then
      let op = getDEOpWithin00toBF modRM
      let effOprSize = getEscEffOprSizeByESCOp 0xDEuy
      phlp.MemEffOprSize <- effOprSize
      phlp.MemEffRegSize <- effOprSize
      let o = OperandParsers.parseMemory modRM span phlp
      newInstruction phlp op (OneOperand o)
    else
      let opcode, oprs = getDEOverBF modRM
      newInstruction phlp opcode oprs

type internal OneOpDF () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let modRM = phlp.ReadByte span
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    if modRM <= 0xBFuy then
      let op = getDFOpWithin00toBF modRM
      let effOprSize = Operands.getReg modRM |> getDFEscEffOprSizeByModRM
      phlp.MemEffOprSize <- effOprSize
      phlp.MemEffRegSize <- effOprSize
      let o = OperandParsers.parseMemory modRM span phlp
      newInstruction phlp op (OneOperand o)
    else
      let opcode, oprs = getDFOverBF modRM
      newInstruction phlp opcode oprs

type internal OneOpE0 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.Rel8].Render (span, phlp)
    newInstruction phlp Opcode.LOOPNE oprs

type internal OneOpE1 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.Rel8].Render (span, phlp)
    newInstruction phlp Opcode.LOOPE oprs

type internal OneOpE2 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.Rel8].Render (span, phlp)
    newInstruction phlp Opcode.LOOP oprs

type internal OneOpE3 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    if Prefix.hasAddrSz phlp.Prefixes then
      let opcode =
        if ParsingHelper.Is64bit phlp then Opcode.JECXZ else Opcode.JCXZ
      render span phlp opcode SzCond.F64 OD.Rel8 SZ.Byte
    elif ParsingHelper.Is64bit phlp then
      render span phlp Opcode.JRCXZ SzCond.F64 OD.Rel8 SZ.Byte
    else render span phlp Opcode.JECXZ SzCond.F64 OD.Rel8 SZ.Byte

type internal OneOpE4 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RegImm8].Render (span, phlp)
    newInstruction phlp Opcode.IN oprs

type internal OneOpE5 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.REXPrefix <- REXPrefix.NOREX
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.RegImm8].Render (span, phlp)
    newInstruction phlp Opcode.IN oprs

type internal OneOpE6 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.Imm8Reg].Render (span, phlp)
    newInstruction phlp Opcode.OUT oprs

type internal OneOpE7 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.REXPrefix <- REXPrefix.NOREX
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.Imm8Reg].Render (span, phlp)
    newInstruction phlp Opcode.OUT oprs

type internal OneOpE8 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    addBND phlp
    phlp.SzComputers[int SZ.D64].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.Rel].Render (span, phlp)
    newInstruction phlp Opcode.CALLNear oprs

type internal OneOpE9 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    addBND phlp
    phlp.SzComputers[int SZ.D64].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.Rel].Render (span, phlp)
    newInstruction phlp Opcode.JMPNear oprs

type internal OneOpEA () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
#if !EMULATION
    ensure32 phlp
#endif
    addBND phlp
    phlp.SzComputers[int SZ.P].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.Dir].Render (span, phlp)
    newInstruction phlp Opcode.JMPFar oprs

type internal OneOpEB () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    addBND phlp
    phlp.SzComputers[int SZ.Byte].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.Rel8].Render (span, phlp)
    newInstruction phlp Opcode.JMPNear oprs

type internal OneOpEC () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.ALDx].Render (span, phlp)
    newInstruction phlp Opcode.IN oprs

type internal OneOpED () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.EaxDx].Render (span, phlp)
    newInstruction phlp Opcode.IN oprs

type internal OneOpEE () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.DxAL].Render (span, phlp)
    newInstruction phlp Opcode.OUT oprs

type internal OneOpEF () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.DxEax].Render (span, phlp)
    newInstruction phlp Opcode.OUT oprs

type internal OneOpF0 () =
  inherit ParsingJob ()
  override _.Run (_, _) = raise ParsingFailureException

type internal OneOpF1 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.Normal
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.INT1 oprs

type internal OneOpF2 () =
  inherit ParsingJob ()
  override _.Run (_, _) = raise ParsingFailureException

type internal OneOpF3 () =
  inherit ParsingJob ()
  override _.Run (_, _) = raise ParsingFailureException

type internal OneOpF4 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.HLT oprs

type internal OneOpF5 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.CMC oprs

type internal OneOpF6 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span phlp OD.Mem SZ.Byte OpGroup.G3A
    render span phlp op szCond oidx szidx

type internal OneOpF7 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span phlp OD.Mem SZ.Def OpGroup.G3B
    render span phlp op szCond oidx szidx

type internal OneOpF8 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.CLC oprs

type internal OneOpF9 () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.STC oprs

type internal OneOpFA () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.CLI oprs

type internal OneOpFB () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.STI oprs

type internal OneOpFC () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.CLD oprs

type internal OneOpFD () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    phlp.SzComputers[int SZ.Def].Render phlp SzCond.F64
    let oprs = phlp.OprParsers[int OD.No].Render (span, phlp)
    newInstruction phlp Opcode.STD oprs

type internal OneOpFE () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span phlp OD.No SZ.Def OpGroup.G4
    render span phlp op szCond oidx szidx

type internal OneOpFF () =
  inherit ParsingJob ()
  override _.Run (span, phlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span phlp OD.No SZ.Def OpGroup.G5
    if Opcode.isBranch op then addBND phlp else ()
    render span phlp op szCond oidx szidx
