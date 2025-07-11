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
open B2R2.FrontEnd.Intel.ParsingHelper
open LanguagePrimitives

[<AbstractClass>]
type internal ParsingJob () =
  abstract Run: ByteSpan * ReadHelper -> Instruction

type internal OneOp00 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RmGpr].Render (span, rhlp)
    newInstruction rhlp Opcode.ADD oprs

type internal OneOp01 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RmGpr].Render (span, rhlp)
    newInstruction rhlp Opcode.ADD oprs

type internal OneOp02 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.GprRm].Render (span, rhlp)
    newInstruction rhlp Opcode.ADD oprs

type internal OneOp03 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.GprRm].Render (span, rhlp)
    newInstruction rhlp Opcode.ADD oprs

type internal OneOp04 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RegImm8].Render (span, rhlp)
    newInstruction rhlp Opcode.ADD oprs

type internal OneOp05 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RegImm].Render (span, rhlp)
    newInstruction rhlp Opcode.ADD oprs

type internal OneOp06 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.RegW].Render rhlp SzCond.Normal
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.Es].Render (span, rhlp)
    newInstruction rhlp Opcode.PUSH oprs

type internal OneOp07 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.RegW].Render rhlp SzCond.Normal
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.Es].Render (span, rhlp)
    newInstruction rhlp Opcode.POP oprs

type internal OneOp08 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RmGpr].Render (span, rhlp)
    newInstruction rhlp Opcode.OR oprs

type internal OneOp09 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RmGpr].Render (span, rhlp)
    newInstruction rhlp Opcode.OR oprs

type internal OneOp0A () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.GprRm].Render (span, rhlp)
    newInstruction rhlp Opcode.OR oprs

type internal OneOp0B () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.GprRm].Render (span, rhlp)
    newInstruction rhlp Opcode.OR oprs

type internal OneOp0C () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RegImm8].Render (span, rhlp)
    newInstruction rhlp Opcode.OR oprs

type internal OneOp0D () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RegImm].Render (span, rhlp)
    newInstruction rhlp Opcode.OR oprs

type internal OneOp0E () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.RegW].Render rhlp SzCond.Normal
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.Cs].Render (span, rhlp)
    newInstruction rhlp Opcode.PUSH oprs

type internal OneOp0F () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    pTwoByteOp span rhlp (rhlp.ReadByte span)

type internal OneOp10 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RmGpr].Render (span, rhlp)
    newInstruction rhlp Opcode.ADC oprs

type internal OneOp11 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RmGpr].Render (span, rhlp)
    newInstruction rhlp Opcode.ADC oprs

type internal OneOp12 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.GprRm].Render (span, rhlp)
    newInstruction rhlp Opcode.ADC oprs

type internal OneOp13 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.GprRm].Render (span, rhlp)
    newInstruction rhlp Opcode.ADC oprs

type internal OneOp14 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RegImm8].Render (span, rhlp)
    newInstruction rhlp Opcode.ADC oprs

type internal OneOp15 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RegImm].Render (span, rhlp)
    newInstruction rhlp Opcode.ADC oprs

type internal OneOp16 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.RegW].Render rhlp SzCond.Normal
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.Ss].Render (span, rhlp)
    newInstruction rhlp Opcode.PUSH oprs

type internal OneOp17 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.RegW].Render rhlp SzCond.Normal
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.Ss].Render (span, rhlp)
    newInstruction rhlp Opcode.POP oprs

type internal OneOp18 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RmGpr].Render (span, rhlp)
    newInstruction rhlp Opcode.SBB oprs

type internal OneOp19 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RmGpr].Render (span, rhlp)
    newInstruction rhlp Opcode.SBB oprs

type internal OneOp1A () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.GprRm].Render (span, rhlp)
    newInstruction rhlp Opcode.SBB oprs

type internal OneOp1B () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.GprRm].Render (span, rhlp)
    newInstruction rhlp Opcode.SBB oprs

type internal OneOp1C () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RegImm8].Render (span, rhlp)
    newInstruction rhlp Opcode.SBB oprs

type internal OneOp1D () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RegImm].Render (span, rhlp)
    newInstruction rhlp Opcode.SBB oprs

type internal OneOp1E () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.RegW].Render rhlp SzCond.Normal
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.Ds].Render (span, rhlp)
    newInstruction rhlp Opcode.PUSH oprs

type internal OneOp1F () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.RegW].Render rhlp SzCond.Normal
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.Ds].Render (span, rhlp)
    newInstruction rhlp Opcode.POP oprs

type internal OneOp20 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RmGpr].Render (span, rhlp)
    newInstruction rhlp Opcode.AND oprs

type internal OneOp21 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RmGpr].Render (span, rhlp)
    newInstruction rhlp Opcode.AND oprs

type internal OneOp22 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.GprRm].Render (span, rhlp)
    newInstruction rhlp Opcode.AND oprs

type internal OneOp23 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.GprRm].Render (span, rhlp)
    newInstruction rhlp Opcode.AND oprs

type internal OneOp24 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RegImm8].Render (span, rhlp)
    newInstruction rhlp Opcode.AND oprs

type internal OneOp25 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RegImm].Render (span, rhlp)
    newInstruction rhlp Opcode.AND oprs

type internal OneOp26 () =
  inherit ParsingJob ()
  override _.Run (_, _) = raise ParsingFailureException

type internal OneOp27 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.DAA oprs

type internal OneOp28 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RmGpr].Render (span, rhlp)
    newInstruction rhlp Opcode.SUB oprs

type internal OneOp29 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RmGpr].Render (span, rhlp)
    newInstruction rhlp Opcode.SUB oprs

type internal OneOp2A () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.GprRm].Render (span, rhlp)
    newInstruction rhlp Opcode.SUB oprs

type internal OneOp2B () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.GprRm].Render (span, rhlp)
    newInstruction rhlp Opcode.SUB oprs

type internal OneOp2C () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RegImm8].Render (span, rhlp)
    newInstruction rhlp Opcode.SUB oprs

type internal OneOp2D () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RegImm].Render (span, rhlp)
    newInstruction rhlp Opcode.SUB oprs

type internal OneOp2E () =
  inherit ParsingJob ()
  override _.Run (_, _) = raise ParsingFailureException

type internal OneOp2F () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.DAS oprs

type internal OneOp30 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RmGpr].Render (span, rhlp)
    newInstruction rhlp Opcode.XOR oprs

type internal OneOp31 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RmGpr].Render (span, rhlp)
    newInstruction rhlp Opcode.XOR oprs

type internal OneOp32 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.GprRm].Render (span, rhlp)
    newInstruction rhlp Opcode.XOR oprs

type internal OneOp33 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.GprRm].Render (span, rhlp)
    newInstruction rhlp Opcode.XOR oprs

type internal OneOp34 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RegImm8].Render (span, rhlp)
    newInstruction rhlp Opcode.XOR oprs

type internal OneOp35 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RegImm].Render (span, rhlp)
    newInstruction rhlp Opcode.XOR oprs

type internal OneOp36 () =
  inherit ParsingJob ()
  override _.Run (_, _) = raise ParsingFailureException

type internal OneOp37 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.AAA oprs

type internal OneOp38 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RmGpr].Render (span, rhlp)
    newInstruction rhlp Opcode.CMP oprs

type internal OneOp39 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RmGpr].Render (span, rhlp)
    newInstruction rhlp Opcode.CMP oprs

type internal OneOp3A () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.GprRm].Render (span, rhlp)
    newInstruction rhlp Opcode.CMP oprs

type internal OneOp3B () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.GprRm].Render (span, rhlp)
    newInstruction rhlp Opcode.CMP oprs

type internal OneOp3C () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RegImm8].Render (span, rhlp)
    newInstruction rhlp Opcode.CMP oprs

type internal OneOp3D () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RegImm].Render (span, rhlp)
    newInstruction rhlp Opcode.CMP oprs

type internal OneOp3E () =
  inherit ParsingJob ()
  override _.Run (_, _) = raise ParsingFailureException

type internal OneOp3F () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.AAS oprs

type internal OneOp40 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.Eax].Render (span, rhlp)
    newInstruction rhlp Opcode.INC oprs

type internal OneOp41 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.Ecx].Render (span, rhlp)
    newInstruction rhlp Opcode.INC oprs

type internal OneOp42 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.Edx].Render (span, rhlp)
    newInstruction rhlp Opcode.INC oprs

type internal OneOp43 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.Ebx].Render (span, rhlp)
    newInstruction rhlp Opcode.INC oprs

type internal OneOp44 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.Esp].Render (span, rhlp)
    newInstruction rhlp Opcode.INC oprs

type internal OneOp45 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.Ebp].Render (span, rhlp)
    newInstruction rhlp Opcode.INC oprs

type internal OneOp46 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.Esi].Render (span, rhlp)
    newInstruction rhlp Opcode.INC oprs

type internal OneOp47 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.Edi].Render (span, rhlp)
    newInstruction rhlp Opcode.INC oprs

type internal OneOp48 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.Eax].Render (span, rhlp)
    newInstruction rhlp Opcode.DEC oprs

type internal OneOp49 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.Ecx].Render (span, rhlp)
    newInstruction rhlp Opcode.DEC oprs

type internal OneOp4A () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.Edx].Render (span, rhlp)
    newInstruction rhlp Opcode.DEC oprs

type internal OneOp4B () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.Ebx].Render (span, rhlp)
    newInstruction rhlp Opcode.DEC oprs

type internal OneOp4C () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.Esp].Render (span, rhlp)
    newInstruction rhlp Opcode.DEC oprs

type internal OneOp4D () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.Ebp].Render (span, rhlp)
    newInstruction rhlp Opcode.DEC oprs

type internal OneOp4E () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.Esi].Render (span, rhlp)
    newInstruction rhlp Opcode.DEC oprs

type internal OneOp4F () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.Edi].Render (span, rhlp)
    newInstruction rhlp Opcode.DEC oprs

type internal OneOp50 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.D64].Render rhlp SzCond.D64
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.Rax].Render (span, rhlp)
    newInstruction rhlp Opcode.PUSH oprs

type internal OneOp51 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.D64].Render rhlp SzCond.D64
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.Rcx].Render (span, rhlp)
    newInstruction rhlp Opcode.PUSH oprs

type internal OneOp52 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.D64].Render rhlp SzCond.D64
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.Rdx].Render (span, rhlp)
    newInstruction rhlp Opcode.PUSH oprs

type internal OneOp53 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.D64].Render rhlp SzCond.D64
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.Rbx].Render (span, rhlp)
    newInstruction rhlp Opcode.PUSH oprs

type internal OneOp54 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.D64].Render rhlp SzCond.D64
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.Rsp].Render (span, rhlp)
    newInstruction rhlp Opcode.PUSH oprs

type internal OneOp55 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.D64].Render rhlp SzCond.D64
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.Rbp].Render (span, rhlp)
    newInstruction rhlp Opcode.PUSH oprs

type internal OneOp56 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.D64].Render rhlp SzCond.D64
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.Rsi].Render (span, rhlp)
    newInstruction rhlp Opcode.PUSH oprs

type internal OneOp57 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.D64].Render rhlp SzCond.D64
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.Rdi].Render (span, rhlp)
    newInstruction rhlp Opcode.PUSH oprs

type internal OneOp58 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.D64].Render rhlp SzCond.D64
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.Rax].Render (span, rhlp)
    newInstruction rhlp Opcode.POP oprs

type internal OneOp59 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.D64].Render rhlp SzCond.D64
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.Rcx].Render (span, rhlp)
    newInstruction rhlp Opcode.POP oprs

type internal OneOp5A () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.D64].Render rhlp SzCond.D64
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.Rdx].Render (span, rhlp)
    newInstruction rhlp Opcode.POP oprs

type internal OneOp5B () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.D64].Render rhlp SzCond.D64
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.Rbx].Render (span, rhlp)
    newInstruction rhlp Opcode.POP oprs

type internal OneOp5C () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.D64].Render rhlp SzCond.D64
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.Rsp].Render (span, rhlp)
    newInstruction rhlp Opcode.POP oprs

type internal OneOp5D () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.D64].Render rhlp SzCond.D64
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.Rbp].Render (span, rhlp)
    newInstruction rhlp Opcode.POP oprs

type internal OneOp5E () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.D64].Render rhlp SzCond.D64
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.Rsi].Render (span, rhlp)
    newInstruction rhlp Opcode.POP oprs

type internal OneOp5F () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.D64].Render rhlp SzCond.D64
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.Rdi].Render (span, rhlp)
    newInstruction rhlp Opcode.POP oprs

type internal OneOp60 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    if Prefix.hasOprSz rhlp.Prefixes then
      render span rhlp Opcode.PUSHA SzCond.Normal OD.No SZ.Def
    else render span rhlp Opcode.PUSHAD SzCond.Normal OD.No SZ.Def

type internal OneOp61 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    if Prefix.hasOprSz rhlp.Prefixes then
      render span rhlp Opcode.POPA SzCond.Normal OD.No SZ.Def
    else render span rhlp Opcode.POPAD SzCond.Normal OD.No SZ.Def

type internal OneOp62 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    if (rhlp.WordSize = WordSize.Bit64) || (rhlp.PeekByte span >= 0xC0uy) then
      let mutable rex = rhlp.REXPrefix
      let vInfo = getEVEXInfo span &rex rhlp.CurrPos
      rhlp.VEXInfo <- Some vInfo
      rhlp.REXPrefix <- rex
      rhlp.CurrPos <- rhlp.CurrPos + 3
      match vInfo.VEXType &&& EnumOfValue<int, VEXType> 7 with
      | VEXType.VEXTwoByteOp -> parseTwoByteOpcode span rhlp
      | VEXType.VEXThreeByteOpOne -> parseThreeByteOp1 span rhlp
      | VEXType.VEXThreeByteOpTwo -> parseThreeByteOp2 span rhlp
      | _ -> raise ParsingFailureException
    else
      rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
      let oprs = rhlp.OprParsers[int OD.GprM].Render (span, rhlp)
      newInstruction rhlp Opcode.BOUND oprs

type internal OneOp63 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    if ReadHelper.Is64bit rhlp then
      render span rhlp Opcode.MOVSXD SzCond.Normal OD.GprRm SZ.DV
    else render span rhlp Opcode.ARPL SzCond.Normal OD.RmGpr SZ.Word

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
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.D64
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.Imm].Render (span, rhlp)
    newInstruction rhlp Opcode.PUSH oprs

type internal OneOp69 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.GprRmImm].Render (span, rhlp)
    newInstruction rhlp Opcode.IMUL oprs

type internal OneOp6A () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.D64
    rhlp.OperationSize <- rhlp.MemEffOprSize
    let oprs = rhlp.OprParsers[int OD.SImm8].Render (span, rhlp)
    newInstruction rhlp Opcode.PUSH oprs

type internal OneOp6B () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.GprRmImm8].Render (span, rhlp)
    newInstruction rhlp Opcode.IMUL oprs

type internal OneOp6C () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    rhlp.OperationSize <- 8<rt>
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.INSB oprs

type internal OneOp6D () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    if Prefix.hasOprSz rhlp.Prefixes then
      render span rhlp Opcode.INSW SzCond.Normal OD.No SZ.Def
    else render span rhlp Opcode.INSD SzCond.Normal OD.No SZ.Def

type internal OneOp6E () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    rhlp.OperationSize <- 8<rt>
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.OUTSB oprs

type internal OneOp6F () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    if Prefix.hasOprSz rhlp.Prefixes then
      render span rhlp Opcode.OUTSW SzCond.Normal OD.No SZ.Def
    else render span rhlp Opcode.OUTSD SzCond.Normal OD.No SZ.Def

type internal OneOp70 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    addBND rhlp
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.Rel8].Render (span, rhlp)
    newInstruction rhlp Opcode.JO oprs

type internal OneOp71 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    addBND rhlp
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.Rel8].Render (span, rhlp)
    newInstruction rhlp Opcode.JNO oprs

type internal OneOp72 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    addBND rhlp
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.Rel8].Render (span, rhlp)
    newInstruction rhlp Opcode.JB oprs

type internal OneOp73 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    addBND rhlp
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.Rel8].Render (span, rhlp)
    newInstruction rhlp Opcode.JNB oprs

type internal OneOp74 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    addBND rhlp
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.Rel8].Render (span, rhlp)
    newInstruction rhlp Opcode.JZ oprs

type internal OneOp75 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    addBND rhlp
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.Rel8].Render (span, rhlp)
    newInstruction rhlp Opcode.JNZ oprs

type internal OneOp76 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    addBND rhlp
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.Rel8].Render (span, rhlp)
    newInstruction rhlp Opcode.JBE oprs

type internal OneOp77 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    addBND rhlp
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.Rel8].Render (span, rhlp)
    newInstruction rhlp Opcode.JA oprs

type internal OneOp78 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    addBND rhlp
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.Rel8].Render (span, rhlp)
    newInstruction rhlp Opcode.JS oprs

type internal OneOp79 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    addBND rhlp
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.Rel8].Render (span, rhlp)
    newInstruction rhlp Opcode.JNS oprs

type internal OneOp7A () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    addBND rhlp
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.Rel8].Render (span, rhlp)
    newInstruction rhlp Opcode.JP oprs

type internal OneOp7B () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    addBND rhlp
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.Rel8].Render (span, rhlp)
    newInstruction rhlp Opcode.JNP oprs

type internal OneOp7C () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    addBND rhlp
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.Rel8].Render (span, rhlp)
    newInstruction rhlp Opcode.JL oprs

type internal OneOp7D () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    addBND rhlp
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.Rel8].Render (span, rhlp)
    newInstruction rhlp Opcode.JNL oprs

type internal OneOp7E () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    addBND rhlp
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.Rel8].Render (span, rhlp)
    newInstruction rhlp Opcode.JLE oprs

type internal OneOp7F () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    addBND rhlp
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.Rel8].Render (span, rhlp)
    newInstruction rhlp Opcode.JG oprs

type internal OneOp80 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span rhlp OD.RmSImm8 SZ.Byte OpGroup.G1
    render span rhlp op szCond oidx szidx

type internal OneOp81 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span rhlp OD.RmImm SZ.Def OpGroup.G1
    render span rhlp op szCond oidx szidx

type internal OneOp82 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span rhlp OD.RmSImm8 SZ.Byte OpGroup.G1Inv64
    render span rhlp op szCond oidx szidx

type internal OneOp83 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span rhlp OD.RmSImm8 SZ.Def OpGroup.G1
    render span rhlp op szCond oidx szidx

type internal OneOp84 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RmGpr].Render (span, rhlp)
    newInstruction rhlp Opcode.TEST oprs

type internal OneOp85 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RmGpr].Render (span, rhlp)
    newInstruction rhlp Opcode.TEST oprs

type internal OneOp86 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RmGpr].Render (span, rhlp)
    newInstruction rhlp Opcode.XCHG oprs

type internal OneOp87 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RmGpr].Render (span, rhlp)
    newInstruction rhlp Opcode.XCHG oprs

type internal OneOp88 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RmGpr].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOp89 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RmGpr].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOp8A () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.GprRm].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOp8B () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.GprRm].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOp8C () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Word].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RmSeg].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOp8D () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.GprM].Render (span, rhlp)
    newInstruction rhlp Opcode.LEA oprs

type internal OneOp8E () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Word].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.SegRm].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOp8F () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span rhlp OD.Mem SZ.Def OpGroup.G1A
    render span rhlp op szCond oidx szidx

type internal OneOp90 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    if Prefix.hasREPZ rhlp.Prefixes then
      render span rhlp Opcode.PAUSE SzCond.Normal OD.No SZ.Def
    elif REXPrefix.hasB rhlp.REXPrefix then
      rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
      let oprs = rhlp.OprParsers[int OD.RaxRax].Render (span, rhlp)
      newInstruction rhlp Opcode.XCHG oprs
    else render span rhlp Opcode.NOP SzCond.Normal OD.No SZ.Def

type internal OneOp91 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RaxRcx].Render (span, rhlp)
    newInstruction rhlp Opcode.XCHG oprs

type internal OneOp92 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RaxRdx].Render (span, rhlp)
    newInstruction rhlp Opcode.XCHG oprs

type internal OneOp93 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RaxRbx].Render (span, rhlp)
    newInstruction rhlp Opcode.XCHG oprs

type internal OneOp94 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RaxRsp].Render (span, rhlp)
    newInstruction rhlp Opcode.XCHG oprs

type internal OneOp95 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RaxRbp].Render (span, rhlp)
    newInstruction rhlp Opcode.XCHG oprs

type internal OneOp96 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RaxRsi].Render (span, rhlp)
    newInstruction rhlp Opcode.XCHG oprs

type internal OneOp97 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RaxRdi].Render (span, rhlp)
    newInstruction rhlp Opcode.XCHG oprs

type internal OneOp98 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    if Prefix.hasOprSz rhlp.Prefixes then
      render span rhlp Opcode.CBW SzCond.Normal OD.No SZ.Def
    elif REXPrefix.hasW rhlp.REXPrefix then
      render span rhlp Opcode.CDQE SzCond.Normal OD.No SZ.Def
    else render span rhlp Opcode.CWDE SzCond.Normal OD.No SZ.Def

type internal OneOp99 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    if Prefix.hasOprSz rhlp.Prefixes then
      render span rhlp Opcode.CWD SzCond.Normal OD.No SZ.Def
    elif REXPrefix.hasW rhlp.REXPrefix then
      render span rhlp Opcode.CQO SzCond.Normal OD.No SZ.Def
    else render span rhlp Opcode.CDQ SzCond.Normal OD.No SZ.Def

type internal OneOp9A () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    addBND rhlp
    rhlp.SzComputers[int SZ.P].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.Dir].Render (span, rhlp)
    newInstruction rhlp Opcode.CALLFar oprs

type internal OneOp9B () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.WAIT oprs

type internal OneOp9C () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    if Prefix.hasOprSz rhlp.Prefixes then
      let szcond = if ReadHelper.Is64bit rhlp then SzCond.D64 else SzCond.Normal
      render span rhlp Opcode.PUSHF szcond OD.No SZ.Def
    elif ReadHelper.Is64bit rhlp then
      render span rhlp Opcode.PUSHFQ SzCond.D64 OD.No SZ.Def
    else render span rhlp Opcode.PUSHFD SzCond.Normal OD.No SZ.Def

type internal OneOp9D () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    if Prefix.hasOprSz rhlp.Prefixes then
      let szcond = if ReadHelper.Is64bit rhlp then SzCond.D64 else SzCond.Normal
      render span rhlp Opcode.POPF szcond OD.No SZ.Def
    elif ReadHelper.Is64bit rhlp then
      render span rhlp Opcode.POPFQ SzCond.D64 OD.No SZ.Def
    else render span rhlp Opcode.POPFD SzCond.Normal OD.No SZ.Def

type internal OneOp9E () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.SAHF oprs

type internal OneOp9F () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.LAHF oprs

type internal OneOpA0 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RaxFar].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOpA1 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RaxFar].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOpA2 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.FarRax].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOpA3 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.FarRax].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOpA4 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    rhlp.OperationSize <- 8<rt>
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    if Prefix.hasREPNZ rhlp.Prefixes then raise ParsingFailureException
    else newInstruction rhlp Opcode.MOVSB oprs

type internal OneOpA5 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    if Prefix.hasOprSz rhlp.Prefixes then
      render span rhlp Opcode.MOVSW SzCond.Normal OD.No SZ.Def
    elif REXPrefix.hasW rhlp.REXPrefix then
      render span rhlp Opcode.MOVSQ SzCond.Normal OD.No SZ.Def
    else render span rhlp Opcode.MOVSD SzCond.Normal OD.No SZ.Def

type internal OneOpA6 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.CMPSB oprs

type internal OneOpA7 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    if Prefix.hasOprSz rhlp.Prefixes then
      render span rhlp Opcode.CMPSW SzCond.Normal OD.No SZ.Def
    elif REXPrefix.hasW rhlp.REXPrefix then
      render span rhlp Opcode.CMPSQ SzCond.Normal OD.No SZ.Def
    else render span rhlp Opcode.CMPSD SzCond.Normal OD.No SZ.Def

type internal OneOpA8 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RegImm8].Render (span, rhlp)
    newInstruction rhlp Opcode.TEST oprs

type internal OneOpA9 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RegImm].Render (span, rhlp)
    newInstruction rhlp Opcode.TEST oprs

type internal OneOpAA () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    rhlp.OperationSize <- 8<rt>
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.STOSB oprs

type internal OneOpAB () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    if Prefix.hasOprSz rhlp.Prefixes then
      render span rhlp Opcode.STOSW SzCond.Normal OD.No SZ.Def
    elif REXPrefix.hasW rhlp.REXPrefix then
      render span rhlp Opcode.STOSQ SzCond.Normal OD.No SZ.Def
    else render span rhlp Opcode.STOSD SzCond.Normal OD.No SZ.Def

type internal OneOpAC () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    rhlp.OperationSize <- 8<rt>
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.LODSB oprs

type internal OneOpAD () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    if Prefix.hasOprSz rhlp.Prefixes then
      render span rhlp Opcode.LODSW SzCond.Normal OD.No SZ.Def
    elif REXPrefix.hasW rhlp.REXPrefix then
      render span rhlp Opcode.LODSQ SzCond.Normal OD.No SZ.Def
    else render span rhlp Opcode.LODSD SzCond.Normal OD.No SZ.Def

type internal OneOpAE () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    rhlp.OperationSize <- 8<rt>
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.SCASB oprs

type internal OneOpAF () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    if Prefix.hasOprSz rhlp.Prefixes then
      render span rhlp Opcode.SCASW SzCond.Normal OD.No SZ.Def
    elif REXPrefix.hasW rhlp.REXPrefix then
      render span rhlp Opcode.SCASQ SzCond.Normal OD.No SZ.Def
    else render span rhlp Opcode.SCASD SzCond.Normal OD.No SZ.Def

type internal OneOpB0 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.ALImm8].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOpB1 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.CLImm8].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOpB2 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.DLImm8].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOpB3 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.BLImm8].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOpB4 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.AhImm8].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOpB5 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.ChImm8].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOpB6 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.DhImm8].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOpB7 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.BhImm8].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOpB8 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RaxImm].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOpB9 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RcxImm].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOpBA () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RdxImm].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOpBB () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RbxImm].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOpBC () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RspImm].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOpBD () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RbpImm].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOpBE () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RsiImm].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOpBF () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RdiImm].Render (span, rhlp)
    newInstruction rhlp Opcode.MOV oprs

type internal OneOpC0 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span rhlp OD.RmSImm8 SZ.Byte OpGroup.G2
    render span rhlp op szCond oidx szidx

type internal OneOpC1 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span rhlp OD.RmSImm8 SZ.Def OpGroup.G2
    render span rhlp op szCond oidx szidx

type internal OneOpC2 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    addBND rhlp
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.Imm16].Render (span, rhlp)
    newInstruction rhlp Opcode.RETNearImm oprs

type internal OneOpC3 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    addBND rhlp
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.RETNear oprs

type internal OneOpC4 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    if (rhlp.WordSize = WordSize.Bit64) || (rhlp.PeekByte span >= 0xC0uy) then
      let mutable rex = rhlp.REXPrefix
      let vInfo = getThreeVEXInfo span &rex rhlp.CurrPos
      rhlp.VEXInfo <- Some vInfo
      rhlp.REXPrefix <- rex
      rhlp.CurrPos <- rhlp.CurrPos + 2
      match vInfo.VEXType with
      | VEXType.VEXTwoByteOp -> parseTwoByteOpcode span rhlp
      | VEXType.VEXThreeByteOpOne -> parseThreeByteOp1 span rhlp
      | VEXType.VEXThreeByteOpTwo -> parseThreeByteOp2 span rhlp
      | _ -> raise ParsingFailureException
    else
      rhlp.SzComputers[int SZ.PZ].Render rhlp SzCond.Normal
      let oprs = rhlp.OprParsers[int OD.GprM].Render (span, rhlp)
      newInstruction rhlp Opcode.LES oprs

type internal OneOpC5 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    if (rhlp.WordSize = WordSize.Bit64) || (rhlp.PeekByte span >= 0xC0uy) then
      let mutable rex = rhlp.REXPrefix
      rhlp.VEXInfo <- Some (getTwoVEXInfo span &rex rhlp.CurrPos)
      rhlp.REXPrefix <- rex
      rhlp.CurrPos <- rhlp.CurrPos + 1
      parseTwoByteOpcode span rhlp
    else
      rhlp.SzComputers[int SZ.PZ].Render rhlp SzCond.Normal
      let oprs = rhlp.OprParsers[int OD.GprM].Render (span, rhlp)
      newInstruction rhlp Opcode.LDS oprs

type internal OneOpC6 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span rhlp OD.RmSImm8 SZ.Byte OpGroup.G11A
    render span rhlp op szCond oidx szidx

type internal OneOpC7 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span rhlp OD.RmImm SZ.Def OpGroup.G11B
    render span rhlp op szCond oidx szidx

type internal OneOpC8 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.ImmImm].Render (span, rhlp)
    newInstruction rhlp Opcode.ENTER oprs

type internal OneOpC9 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.D64
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.LEAVE oprs

type internal OneOpCA () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    addBND rhlp
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.Imm16].Render (span, rhlp)
    newInstruction rhlp Opcode.RETFarImm oprs

type internal OneOpCB () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    addBND rhlp
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.RETFar oprs

type internal OneOpCC () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.INT3 oprs

type internal OneOpCD () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.Imm8].Render (span, rhlp)
    newInstruction rhlp Opcode.INT oprs

type internal OneOpCE () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.INTO oprs

type internal OneOpCF () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    if Prefix.hasOprSz rhlp.Prefixes then
      render span rhlp Opcode.IRETW SzCond.Normal OD.No SZ.Def
    elif REXPrefix.hasW rhlp.REXPrefix then
      render span rhlp Opcode.IRETQ SzCond.Normal OD.No SZ.Def
    else render span rhlp Opcode.IRETD SzCond.Normal OD.No SZ.Def

type internal OneOpD0 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span rhlp OD.M1 SZ.Byte OpGroup.G2
    render span rhlp op szCond oidx szidx

type internal OneOpD1 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span rhlp OD.M1 SZ.Def OpGroup.G2
    render span rhlp op szCond oidx szidx

type internal OneOpD2 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span rhlp OD.RmCL SZ.Byte OpGroup.G2
    render span rhlp op szCond oidx szidx

type internal OneOpD3 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span rhlp OD.RmCL SZ.Def OpGroup.G2
    render span rhlp op szCond oidx szidx

type internal OneOpD4 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.Imm8].Render (span, rhlp)
    newInstruction rhlp Opcode.AAM oprs

type internal OneOpD5 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.Imm8].Render (span, rhlp)
    newInstruction rhlp Opcode.AAD oprs

type internal OneOpD6 () =
  inherit ParsingJob ()
  override _.Run (_, _)= raise ParsingFailureException

type internal OneOpD7 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.XLATB oprs

type internal OneOpD8 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let modRM = rhlp.ReadByte span
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    if modRM <= 0xBFuy then
      let op = getD8OpWithin00toBF modRM
      let effOprSize = getEscEffOprSizeByESCOp 0xD8uy
      rhlp.MemEffOprSize <- effOprSize
      rhlp.MemEffRegSize <- effOprSize
      let o = OperandParsingHelper.parseMemory modRM span rhlp
      newInstruction rhlp op (OneOperand o)
    else
      let opcode, oprs = getD8OverBF modRM
      newInstruction rhlp opcode oprs

type internal OneOpD9 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let modRM = rhlp.ReadByte span
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    if modRM <= 0xBFuy then
      let op = getD9OpWithin00toBF modRM
      let effOprSize = Operands.getReg modRM |> getD9EscEffOprSizeByModRM
      rhlp.MemEffOprSize <- effOprSize
      rhlp.MemEffRegSize <- effOprSize
      let o = OperandParsingHelper.parseMemory modRM span rhlp
      newInstruction rhlp op (OneOperand o)
    else
      let opcode, oprs = getD9OverBF modRM
      newInstruction rhlp opcode oprs

type internal OneOpDA () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let modRM = rhlp.ReadByte span
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    if modRM <= 0xBFuy then
      let op = getDAOpWithin00toBF modRM
      let effOprSize = getEscEffOprSizeByESCOp 0xDAuy
      rhlp.MemEffOprSize <- effOprSize
      rhlp.MemEffRegSize <- effOprSize
      let o = OperandParsingHelper.parseMemory modRM span rhlp
      newInstruction rhlp op (OneOperand o)
    else
      let opcode, oprs = getDAOverBF modRM
      newInstruction rhlp opcode oprs

type internal OneOpDB () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let modRM = rhlp.ReadByte span
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    if modRM <= 0xBFuy then
      let op = getDBOpWithin00toBF modRM
      let effOprSize = Operands.getReg modRM |> getDBEscEffOprSizeByModRM
      rhlp.MemEffOprSize <- effOprSize
      rhlp.MemEffRegSize <- effOprSize
      let o = OperandParsingHelper.parseMemory modRM span rhlp
      newInstruction rhlp op (OneOperand o)
    else
      let opcode, oprs = getDBOverBF modRM
      newInstruction rhlp opcode oprs

type internal OneOpDC () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let modRM = rhlp.ReadByte span
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    if modRM <= 0xBFuy then
      let op = getDCOpWithin00toBF modRM
      let effOprSize = getEscEffOprSizeByESCOp 0xDCuy
      rhlp.MemEffOprSize <- effOprSize
      rhlp.MemEffRegSize <- effOprSize
      let o = OperandParsingHelper.parseMemory modRM span rhlp
      newInstruction rhlp op (OneOperand o)
    else
      let opcode, oprs = getDCOverBF modRM
      newInstruction rhlp opcode oprs

type internal OneOpDD () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let modRM = rhlp.ReadByte span
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    if modRM <= 0xBFuy then
      let op = getDDOpWithin00toBF modRM
      let effOprSize = Operands.getReg modRM |> getDDEscEffOprSizeByModRM
      rhlp.MemEffOprSize <- effOprSize
      rhlp.MemEffRegSize <- effOprSize
      let o = OperandParsingHelper.parseMemory modRM span rhlp
      newInstruction rhlp op (OneOperand o)
    else
      let opcode, oprs = getDDOverBF modRM
      newInstruction rhlp opcode oprs

type internal OneOpDE () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let modRM = rhlp.ReadByte span
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    if modRM <= 0xBFuy then
      let op = getDEOpWithin00toBF modRM
      let effOprSize = getEscEffOprSizeByESCOp 0xDEuy
      rhlp.MemEffOprSize <- effOprSize
      rhlp.MemEffRegSize <- effOprSize
      let o = OperandParsingHelper.parseMemory modRM span rhlp
      newInstruction rhlp op (OneOperand o)
    else
      let opcode, oprs = getDEOverBF modRM
      newInstruction rhlp opcode oprs

type internal OneOpDF () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let modRM = rhlp.ReadByte span
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    if modRM <= 0xBFuy then
      let op = getDFOpWithin00toBF modRM
      let effOprSize = Operands.getReg modRM |> getDFEscEffOprSizeByModRM
      rhlp.MemEffOprSize <- effOprSize
      rhlp.MemEffRegSize <- effOprSize
      let o = OperandParsingHelper.parseMemory modRM span rhlp
      newInstruction rhlp op (OneOperand o)
    else
      let opcode, oprs = getDFOverBF modRM
      newInstruction rhlp opcode oprs

type internal OneOpE0 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.Rel8].Render (span, rhlp)
    newInstruction rhlp Opcode.LOOPNE oprs

type internal OneOpE1 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.Rel8].Render (span, rhlp)
    newInstruction rhlp Opcode.LOOPE oprs

type internal OneOpE2 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.Rel8].Render (span, rhlp)
    newInstruction rhlp Opcode.LOOP oprs

type internal OneOpE3 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    if Prefix.hasAddrSz rhlp.Prefixes then
      let opcode = if ReadHelper.Is64bit rhlp then Opcode.JECXZ else Opcode.JCXZ
      render span rhlp opcode SzCond.F64 OD.Rel8 SZ.Byte
    elif ReadHelper.Is64bit rhlp then
      render span rhlp Opcode.JRCXZ SzCond.F64 OD.Rel8 SZ.Byte
    else render span rhlp Opcode.JECXZ SzCond.F64 OD.Rel8 SZ.Byte

type internal OneOpE4 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RegImm8].Render (span, rhlp)
    newInstruction rhlp Opcode.IN oprs

type internal OneOpE5 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.REXPrefix <- REXPrefix.NOREX
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.RegImm8].Render (span, rhlp)
    newInstruction rhlp Opcode.IN oprs

type internal OneOpE6 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.Imm8Reg].Render (span, rhlp)
    newInstruction rhlp Opcode.OUT oprs

type internal OneOpE7 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.REXPrefix <- REXPrefix.NOREX
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.Imm8Reg].Render (span, rhlp)
    newInstruction rhlp Opcode.OUT oprs

type internal OneOpE8 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    addBND rhlp
    rhlp.SzComputers[int SZ.D64].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.Rel].Render (span, rhlp)
    newInstruction rhlp Opcode.CALLNear oprs

type internal OneOpE9 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    addBND rhlp
    rhlp.SzComputers[int SZ.D64].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.Rel].Render (span, rhlp)
    newInstruction rhlp Opcode.JMPNear oprs

type internal OneOpEA () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
#if !EMULATION
    ensure32 rhlp
#endif
    addBND rhlp
    rhlp.SzComputers[int SZ.P].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.Dir].Render (span, rhlp)
    newInstruction rhlp Opcode.JMPFar oprs

type internal OneOpEB () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    addBND rhlp
    rhlp.SzComputers[int SZ.Byte].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.Rel8].Render (span, rhlp)
    newInstruction rhlp Opcode.JMPNear oprs

type internal OneOpEC () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.ALDx].Render (span, rhlp)
    newInstruction rhlp Opcode.IN oprs

type internal OneOpED () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.EaxDx].Render (span, rhlp)
    newInstruction rhlp Opcode.IN oprs

type internal OneOpEE () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.DxAL].Render (span, rhlp)
    newInstruction rhlp Opcode.OUT oprs

type internal OneOpEF () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.DxEax].Render (span, rhlp)
    newInstruction rhlp Opcode.OUT oprs

type internal OneOpF0 () =
  inherit ParsingJob ()
  override _.Run (_, _) = raise ParsingFailureException

type internal OneOpF1 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.Normal
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.INT1 oprs

type internal OneOpF2 () =
  inherit ParsingJob ()
  override _.Run (_, _) = raise ParsingFailureException

type internal OneOpF3 () =
  inherit ParsingJob ()
  override _.Run (_, _) = raise ParsingFailureException

type internal OneOpF4 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.HLT oprs

type internal OneOpF5 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.CMC oprs

type internal OneOpF6 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span rhlp OD.Mem SZ.Byte OpGroup.G3A
    render span rhlp op szCond oidx szidx

type internal OneOpF7 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span rhlp OD.Mem SZ.Def OpGroup.G3B
    render span rhlp op szCond oidx szidx

type internal OneOpF8 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.CLC oprs

type internal OneOpF9 () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.STC oprs

type internal OneOpFA () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.CLI oprs

type internal OneOpFB () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.STI oprs

type internal OneOpFC () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.CLD oprs

type internal OneOpFD () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    rhlp.SzComputers[int SZ.Def].Render rhlp SzCond.F64
    let oprs = rhlp.OprParsers[int OD.No].Render (span, rhlp)
    newInstruction rhlp Opcode.STD oprs

type internal OneOpFE () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span rhlp OD.No SZ.Def OpGroup.G4
    render span rhlp op szCond oidx szidx

type internal OneOpFF () =
  inherit ParsingJob ()
  override _.Run (span, rhlp) =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind span rhlp OD.No SZ.Def OpGroup.G5
    if Opcode.isBranch op then addBND rhlp else ()
    render span rhlp op szCond oidx szidx
