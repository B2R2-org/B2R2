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

namespace B2R2.FrontEnd.BinLifter.Intel

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.FrontEnd.BinLifter.Intel.Helper
open B2R2.FrontEnd.BinLifter.Intel.ParsingHelper
open LanguagePrimitives

[<AbstractClass>]
type internal ParsingJob () =
  abstract Run: ReadHelper -> IntelInstruction

type internal OneOp00 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RmGpr].Render rhlp insSize
    newInsInfo rhlp Opcode.ADD oprs insSize

type internal OneOp01 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RmGpr].Render rhlp insSize
    newInsInfo rhlp Opcode.ADD oprs insSize

type internal OneOp02 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.GprRm].Render rhlp insSize
    newInsInfo rhlp Opcode.ADD oprs insSize

type internal OneOp03 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.GprRm].Render rhlp insSize
    newInsInfo rhlp Opcode.ADD oprs insSize

type internal OneOp04 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RegImm8].Render rhlp insSize
    newInsInfo rhlp Opcode.ADD oprs insSize

type internal OneOp05 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RegImm].Render rhlp insSize
    newInsInfo rhlp Opcode.ADD oprs insSize

type internal OneOp06 () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.RegW].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Es].Render rhlp insSize
    newInsInfo rhlp Opcode.PUSH oprs insSize

type internal OneOp07 () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.RegW].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Es].Render rhlp insSize
    newInsInfo rhlp Opcode.POP oprs insSize

type internal OneOp08 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RmGpr].Render rhlp insSize
    newInsInfo rhlp Opcode.OR oprs insSize

type internal OneOp09 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RmGpr].Render rhlp insSize
    newInsInfo rhlp Opcode.OR oprs insSize

type internal OneOp0A () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.GprRm].Render rhlp insSize
    newInsInfo rhlp Opcode.OR oprs insSize

type internal OneOp0B () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.GprRm].Render rhlp insSize
    newInsInfo rhlp Opcode.OR oprs insSize

type internal OneOp0C () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RegImm8].Render rhlp insSize
    newInsInfo rhlp Opcode.OR oprs insSize

type internal OneOp0D () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RegImm].Render rhlp insSize
    newInsInfo rhlp Opcode.OR oprs insSize

type internal OneOp0E () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.RegW].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Cs].Render rhlp insSize
    newInsInfo rhlp Opcode.PUSH oprs insSize

type internal OneOp0F () =
  inherit ParsingJob ()
  override __.Run rhlp =
    rhlp.ReadByte () |> pTwoByteOp rhlp

type internal OneOp10 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RmGpr].Render rhlp insSize
    newInsInfo rhlp Opcode.ADC oprs insSize

type internal OneOp11 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RmGpr].Render rhlp insSize
    newInsInfo rhlp Opcode.ADC oprs insSize

type internal OneOp12 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.GprRm].Render rhlp insSize
    newInsInfo rhlp Opcode.ADC oprs insSize

type internal OneOp13 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.GprRm].Render rhlp insSize
    newInsInfo rhlp Opcode.ADC oprs insSize

type internal OneOp14 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RegImm8].Render rhlp insSize
    newInsInfo rhlp Opcode.ADC oprs insSize

type internal OneOp15 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RegImm].Render rhlp insSize
    newInsInfo rhlp Opcode.ADC oprs insSize

type internal OneOp16 () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.RegW].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Ss].Render rhlp insSize
    newInsInfo rhlp Opcode.PUSH oprs insSize

type internal OneOp17 () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.RegW].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Ss].Render rhlp insSize
    newInsInfo rhlp Opcode.POP oprs insSize

type internal OneOp18 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RmGpr].Render rhlp insSize
    newInsInfo rhlp Opcode.SBB oprs insSize

type internal OneOp19 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RmGpr].Render rhlp insSize
    newInsInfo rhlp Opcode.SBB oprs insSize

type internal OneOp1A () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.GprRm].Render rhlp insSize
    newInsInfo rhlp Opcode.SBB oprs insSize

type internal OneOp1B () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.GprRm].Render rhlp insSize
    newInsInfo rhlp Opcode.SBB oprs insSize

type internal OneOp1C () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RegImm8].Render rhlp insSize
    newInsInfo rhlp Opcode.SBB oprs insSize

type internal OneOp1D () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RegImm].Render rhlp insSize
    newInsInfo rhlp Opcode.SBB oprs insSize

type internal OneOp1E () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.RegW].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Ds].Render rhlp insSize
    newInsInfo rhlp Opcode.PUSH oprs insSize

type internal OneOp1F () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.RegW].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Ds].Render rhlp insSize
    newInsInfo rhlp Opcode.POP oprs insSize

type internal OneOp20 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RmGpr].Render rhlp insSize
    newInsInfo rhlp Opcode.AND oprs insSize

type internal OneOp21 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RmGpr].Render rhlp insSize
    newInsInfo rhlp Opcode.AND oprs insSize

type internal OneOp22 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.GprRm].Render rhlp insSize
    newInsInfo rhlp Opcode.AND oprs insSize

type internal OneOp23 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.GprRm].Render rhlp insSize
    newInsInfo rhlp Opcode.AND oprs insSize

type internal OneOp24 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RegImm8].Render rhlp insSize
    newInsInfo rhlp Opcode.AND oprs insSize

type internal OneOp25 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RegImm].Render rhlp insSize
    newInsInfo rhlp Opcode.AND oprs insSize

type internal OneOp26 () =
  inherit ParsingJob ()
  override __.Run _rhlp = raise ParsingFailureException

type internal OneOp27 () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.DAA oprs insSize

type internal OneOp28 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RmGpr].Render rhlp insSize
    newInsInfo rhlp Opcode.SUB oprs insSize

type internal OneOp29 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RmGpr].Render rhlp insSize
    newInsInfo rhlp Opcode.SUB oprs insSize

type internal OneOp2A () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.GprRm].Render rhlp insSize
    newInsInfo rhlp Opcode.SUB oprs insSize

type internal OneOp2B () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.GprRm].Render rhlp insSize
    newInsInfo rhlp Opcode.SUB oprs insSize

type internal OneOp2C () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RegImm8].Render rhlp insSize
    newInsInfo rhlp Opcode.SUB oprs insSize

type internal OneOp2D () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RegImm].Render rhlp insSize
    newInsInfo rhlp Opcode.SUB oprs insSize

type internal OneOp2E () =
  inherit ParsingJob ()
  override __.Run _rhlp = raise ParsingFailureException

type internal OneOp2F () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.DAS oprs insSize

type internal OneOp30 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RmGpr].Render rhlp insSize
    newInsInfo rhlp Opcode.XOR oprs insSize

type internal OneOp31 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RmGpr].Render rhlp insSize
    newInsInfo rhlp Opcode.XOR oprs insSize

type internal OneOp32 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.GprRm].Render rhlp insSize
    newInsInfo rhlp Opcode.XOR oprs insSize

type internal OneOp33 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.GprRm].Render rhlp insSize
    newInsInfo rhlp Opcode.XOR oprs insSize

type internal OneOp34 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RegImm8].Render rhlp insSize
    newInsInfo rhlp Opcode.XOR oprs insSize

type internal OneOp35 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RegImm].Render rhlp insSize
    newInsInfo rhlp Opcode.XOR oprs insSize

type internal OneOp36 () =
  inherit ParsingJob ()
  override __.Run _rhlp = raise ParsingFailureException

type internal OneOp37 () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.AAA oprs insSize

type internal OneOp38 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RmGpr].Render rhlp insSize
    newInsInfo rhlp Opcode.CMP oprs insSize

type internal OneOp39 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RmGpr].Render rhlp insSize
    newInsInfo rhlp Opcode.CMP oprs insSize

type internal OneOp3A () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.GprRm].Render rhlp insSize
    newInsInfo rhlp Opcode.CMP oprs insSize

type internal OneOp3B () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.GprRm].Render rhlp insSize
    newInsInfo rhlp Opcode.CMP oprs insSize

type internal OneOp3C () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RegImm8].Render rhlp insSize
    newInsInfo rhlp Opcode.CMP oprs insSize

type internal OneOp3D () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RegImm].Render rhlp insSize
    newInsInfo rhlp Opcode.CMP oprs insSize

type internal OneOp3E () =
  inherit ParsingJob ()
  override __.Run _rhlp = raise ParsingFailureException

type internal OneOp3F () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.AAS oprs insSize

type internal OneOp40 () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Eax].Render rhlp insSize
    newInsInfo rhlp Opcode.INC oprs insSize

type internal OneOp41 () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Ecx].Render rhlp insSize
    newInsInfo rhlp Opcode.INC oprs insSize

type internal OneOp42 () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Edx].Render rhlp insSize
    newInsInfo rhlp Opcode.INC oprs insSize

type internal OneOp43 () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Ebx].Render rhlp insSize
    newInsInfo rhlp Opcode.INC oprs insSize

type internal OneOp44 () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Esp].Render rhlp insSize
    newInsInfo rhlp Opcode.INC oprs insSize

type internal OneOp45 () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Ebp].Render rhlp insSize
    newInsInfo rhlp Opcode.INC oprs insSize

type internal OneOp46 () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Esi].Render rhlp insSize
    newInsInfo rhlp Opcode.INC oprs insSize

type internal OneOp47 () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Edi].Render rhlp insSize
    newInsInfo rhlp Opcode.INC oprs insSize

type internal OneOp48 () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Eax].Render rhlp insSize
    newInsInfo rhlp Opcode.DEC oprs insSize

type internal OneOp49 () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Ecx].Render rhlp insSize
    newInsInfo rhlp Opcode.DEC oprs insSize

type internal OneOp4A () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Edx].Render rhlp insSize
    newInsInfo rhlp Opcode.DEC oprs insSize

type internal OneOp4B () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Ebx].Render rhlp insSize
    newInsInfo rhlp Opcode.DEC oprs insSize

type internal OneOp4C () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Esp].Render rhlp insSize
    newInsInfo rhlp Opcode.DEC oprs insSize

type internal OneOp4D () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Ebp].Render rhlp insSize
    newInsInfo rhlp Opcode.DEC oprs insSize

type internal OneOp4E () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Esi].Render rhlp insSize
    newInsInfo rhlp Opcode.DEC oprs insSize

type internal OneOp4F () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Edi].Render rhlp insSize
    newInsInfo rhlp Opcode.DEC oprs insSize

type internal OneOp50 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.D64
    let insSize =
      rhlp.SzComputers.[int SZ.D64].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rax].Render rhlp insSize
    newInsInfo rhlp Opcode.PUSH oprs insSize

type internal OneOp51 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.D64
    let insSize =
      rhlp.SzComputers.[int SZ.D64].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rcx].Render rhlp insSize
    newInsInfo rhlp Opcode.PUSH oprs insSize

type internal OneOp52 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.D64
    let insSize =
      rhlp.SzComputers.[int SZ.D64].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rdx].Render rhlp insSize
    newInsInfo rhlp Opcode.PUSH oprs insSize

type internal OneOp53 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.D64
    let insSize =
      rhlp.SzComputers.[int SZ.D64].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rbx].Render rhlp insSize
    newInsInfo rhlp Opcode.PUSH oprs insSize

type internal OneOp54 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.D64
    let insSize =
      rhlp.SzComputers.[int SZ.D64].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rsp].Render rhlp insSize
    newInsInfo rhlp Opcode.PUSH oprs insSize

type internal OneOp55 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.D64
    let insSize =
      rhlp.SzComputers.[int SZ.D64].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rbp].Render rhlp insSize
    newInsInfo rhlp Opcode.PUSH oprs insSize

type internal OneOp56 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.D64
    let insSize =
      rhlp.SzComputers.[int SZ.D64].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rsi].Render rhlp insSize
    newInsInfo rhlp Opcode.PUSH oprs insSize

type internal OneOp57 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.D64
    let insSize =
      rhlp.SzComputers.[int SZ.D64].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rdi].Render rhlp insSize
    newInsInfo rhlp Opcode.PUSH oprs insSize

type internal OneOp58 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.D64
    let insSize =
      rhlp.SzComputers.[int SZ.D64].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rax].Render rhlp insSize
    newInsInfo rhlp Opcode.POP oprs insSize

type internal OneOp59 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.D64
    let insSize =
      rhlp.SzComputers.[int SZ.D64].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rcx].Render rhlp insSize
    newInsInfo rhlp Opcode.POP oprs insSize

type internal OneOp5A () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.D64
    let insSize =
      rhlp.SzComputers.[int SZ.D64].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rdx].Render rhlp insSize
    newInsInfo rhlp Opcode.POP oprs insSize

type internal OneOp5B () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.D64
    let insSize =
      rhlp.SzComputers.[int SZ.D64].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rbx].Render rhlp insSize
    newInsInfo rhlp Opcode.POP oprs insSize

type internal OneOp5C () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.D64
    let insSize =
      rhlp.SzComputers.[int SZ.D64].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rsp].Render rhlp insSize
    newInsInfo rhlp Opcode.POP oprs insSize

type internal OneOp5D () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.D64
    let insSize =
      rhlp.SzComputers.[int SZ.D64].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rbp].Render rhlp insSize
    newInsInfo rhlp Opcode.POP oprs insSize

type internal OneOp5E () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.D64
    let insSize =
      rhlp.SzComputers.[int SZ.D64].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rsi].Render rhlp insSize
    newInsInfo rhlp Opcode.POP oprs insSize

type internal OneOp5F () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.D64
    let insSize =
      rhlp.SzComputers.[int SZ.D64].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rdi].Render rhlp insSize
    newInsInfo rhlp Opcode.POP oprs insSize

type internal OneOp60 () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    if hasOprSz rhlp.Prefixes then
      render rhlp Opcode.PUSHA SzCond.Nor OD.No SZ.Def
    else render rhlp Opcode.PUSHAD SzCond.Nor OD.No SZ.Def

type internal OneOp61 () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    if hasOprSz rhlp.Prefixes then
      render rhlp Opcode.POPA SzCond.Nor OD.No SZ.Def
    else render rhlp Opcode.POPAD SzCond.Nor OD.No SZ.Def

type internal OneOp62 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    if (rhlp.WordSize = WordSize.Bit64) || (rhlp.PeekByte () >= 0xC0uy) then
      let mutable rex = rhlp.REXPrefix
      let vInfo = getEVEXInfo rhlp.BinReader &rex rhlp.CurrPos
      rhlp.VEXInfo <- Some vInfo
      rhlp.REXPrefix <- rex
      rhlp.CurrPos <- rhlp.CurrPos + 3
      match vInfo.VEXType &&& EnumOfValue<int, VEXType> 7 with
      | VEXType.VEXTwoByteOp -> parseTwoByteOpcode rhlp
      | VEXType.VEXThreeByteOpOne -> parseThreeByteOp1 rhlp
      | VEXType.VEXThreeByteOpTwo -> parseThreeByteOp2 rhlp
      | _ -> raise ParsingFailureException
    else
      let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
      let insSize =
        rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
      let struct (oprs, insSize) =
        rhlp.OprParsers.[int OD.GprM].Render rhlp insSize
      newInsInfo rhlp Opcode.BOUND oprs insSize

type internal OneOp63 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    if is64bit rhlp then
      if not (hasREXW rhlp.REXPrefix) then raise ParsingFailureException
      else render rhlp Opcode.MOVSXD SzCond.Nor OD.GprRm SZ.DV
    else render rhlp Opcode.ARPL SzCond.Nor OD.RmGpr SZ.Word

type internal OneOp64 () =
  inherit ParsingJob ()
  override __.Run _rhlp = raise ParsingFailureException

type internal OneOp65 () =
  inherit ParsingJob ()
  override __.Run _rhlp = raise ParsingFailureException

type internal OneOp66 () =
  inherit ParsingJob ()
  override __.Run _rhlp = raise ParsingFailureException

type internal OneOp67 () =
  inherit ParsingJob ()
  override __.Run _rhlp = raise ParsingFailureException

type internal OneOp68 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.D64
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Imm].Render rhlp insSize
    newInsInfo rhlp Opcode.PUSH oprs insSize

type internal OneOp69 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.GprRmImm].Render rhlp insSize
    newInsInfo rhlp Opcode.IMUL oprs insSize

type internal OneOp6A () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.D64
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = insSize.MemEffOprSize }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.SImm8].Render rhlp insSize
    newInsInfo rhlp Opcode.PUSH oprs insSize

type internal OneOp6B () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.GprRmImm8].Render rhlp insSize
    newInsInfo rhlp Opcode.IMUL oprs insSize

type internal OneOp6C () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = 8<rt> }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.INSB oprs insSize

type internal OneOp6D () =
  inherit ParsingJob ()
  override __.Run rhlp =
    if hasOprSz rhlp.Prefixes then
      render rhlp Opcode.INSW SzCond.Nor OD.No SZ.Def
    else render rhlp Opcode.INSD SzCond.Nor OD.No SZ.Def

type internal OneOp6E () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = 8<rt> }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.OUTSB oprs insSize

type internal OneOp6F () =
  inherit ParsingJob ()
  override __.Run rhlp =
    if hasOprSz rhlp.Prefixes then
      render rhlp Opcode.OUTSW SzCond.Nor OD.No SZ.Def
    else render rhlp Opcode.OUTSD SzCond.Nor OD.No SZ.Def

type internal OneOp70 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rel8].Render rhlp insSize
    newInsInfo rhlp Opcode.JO oprs insSize

type internal OneOp71 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rel8].Render rhlp insSize
    newInsInfo rhlp Opcode.JNO oprs insSize

type internal OneOp72 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rel8].Render rhlp insSize
    newInsInfo rhlp Opcode.JB oprs insSize

type internal OneOp73 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rel8].Render rhlp insSize
    newInsInfo rhlp Opcode.JNB oprs insSize

type internal OneOp74 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rel8].Render rhlp insSize
    newInsInfo rhlp Opcode.JZ oprs insSize

type internal OneOp75 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rel8].Render rhlp insSize
    newInsInfo rhlp Opcode.JNZ oprs insSize

type internal OneOp76 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rel8].Render rhlp insSize
    newInsInfo rhlp Opcode.JBE oprs insSize

type internal OneOp77 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rel8].Render rhlp insSize
    newInsInfo rhlp Opcode.JA oprs insSize

type internal OneOp78 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rel8].Render rhlp insSize
    newInsInfo rhlp Opcode.JS oprs insSize

type internal OneOp79 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rel8].Render rhlp insSize
    newInsInfo rhlp Opcode.JNS oprs insSize

type internal OneOp7A () =
  inherit ParsingJob ()
  override __.Run rhlp =
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rel8].Render rhlp insSize
    newInsInfo rhlp Opcode.JP oprs insSize

type internal OneOp7B () =
  inherit ParsingJob ()
  override __.Run rhlp =
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rel8].Render rhlp insSize
    newInsInfo rhlp Opcode.JNP oprs insSize

type internal OneOp7C () =
  inherit ParsingJob ()
  override __.Run rhlp =
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rel8].Render rhlp insSize
    newInsInfo rhlp Opcode.JL oprs insSize

type internal OneOp7D () =
  inherit ParsingJob ()
  override __.Run rhlp =
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rel8].Render rhlp insSize
    newInsInfo rhlp Opcode.JNL oprs insSize

type internal OneOp7E () =
  inherit ParsingJob ()
  override __.Run rhlp =
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rel8].Render rhlp insSize
    newInsInfo rhlp Opcode.JLE oprs insSize

type internal OneOp7F () =
  inherit ParsingJob ()
  override __.Run rhlp =
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rel8].Render rhlp insSize
    newInsInfo rhlp Opcode.JG oprs insSize

type internal OneOp80 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind rhlp OD.RmImm8 SZ.Byte OpGroup.G1
    render rhlp op szCond oidx szidx

type internal OneOp81 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind rhlp OD.RmImm SZ.Def OpGroup.G1
    render rhlp op szCond oidx szidx

type internal OneOp82 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind rhlp OD.RmImm8 SZ.Byte OpGroup.G1Inv64
    render rhlp op szCond oidx szidx

type internal OneOp83 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind rhlp OD.RmImm8 SZ.Def OpGroup.G1
    render rhlp op szCond oidx szidx

type internal OneOp84 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RmGpr].Render rhlp insSize
    newInsInfo rhlp Opcode.TEST oprs insSize

type internal OneOp85 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RmGpr].Render rhlp insSize
    newInsInfo rhlp Opcode.TEST oprs insSize

type internal OneOp86 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RmGpr].Render rhlp insSize
    newInsInfo rhlp Opcode.XCHG oprs insSize

type internal OneOp87 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RmGpr].Render rhlp insSize
    newInsInfo rhlp Opcode.XCHG oprs insSize

type internal OneOp88 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RmGpr].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOp89 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RmGpr].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOp8A () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.GprRm].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOp8B () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.GprRm].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOp8C () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Word].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RmSeg].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOp8D () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.GprM].Render rhlp insSize
    newInsInfo rhlp Opcode.LEA oprs insSize

type internal OneOp8E () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Word].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.SegRm].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOp8F () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind rhlp OD.Mem SZ.Def OpGroup.G1A
    render rhlp op szCond oidx szidx

type internal OneOp90 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    if hasNoPref rhlp && hasNoREX rhlp then
      render rhlp Opcode.NOP SzCond.Nor OD.No SZ.Def
    elif hasREPZ rhlp.Prefixes then
      render rhlp Opcode.PAUSE SzCond.Nor OD.No SZ.Def
    else render rhlp Opcode.XCHG SzCond.Nor OD.RaxRax SZ.Def

type internal OneOp91 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RaxRcx].Render rhlp insSize
    newInsInfo rhlp Opcode.XCHG oprs insSize

type internal OneOp92 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RaxRdx].Render rhlp insSize
    newInsInfo rhlp Opcode.XCHG oprs insSize

type internal OneOp93 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RaxRbx].Render rhlp insSize
    newInsInfo rhlp Opcode.XCHG oprs insSize

type internal OneOp94 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RaxRsp].Render rhlp insSize
    newInsInfo rhlp Opcode.XCHG oprs insSize

type internal OneOp95 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RaxRbp].Render rhlp insSize
    newInsInfo rhlp Opcode.XCHG oprs insSize

type internal OneOp96 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RaxRsi].Render rhlp insSize
    newInsInfo rhlp Opcode.XCHG oprs insSize

type internal OneOp97 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RaxRdi].Render rhlp insSize
    newInsInfo rhlp Opcode.XCHG oprs insSize

type internal OneOp98 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    if hasOprSz rhlp.Prefixes then
      render rhlp Opcode.CBW SzCond.Nor OD.No SZ.Def
    elif hasREXW rhlp.REXPrefix then
      render rhlp Opcode.CDQE SzCond.Nor OD.No SZ.Def
    else render rhlp Opcode.CWDE SzCond.Nor OD.No SZ.Def

type internal OneOp99 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    if hasOprSz rhlp.Prefixes then
      render rhlp Opcode.CWD SzCond.Nor OD.No SZ.Def
    elif hasREXW rhlp.REXPrefix then
      render rhlp Opcode.CQO SzCond.Nor OD.No SZ.Def
    else render rhlp Opcode.CDQ SzCond.Nor OD.No SZ.Def

type internal OneOp9A () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.P].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Dir].Render rhlp insSize
    newInsInfo rhlp Opcode.CALLFar oprs insSize

type internal OneOp9B () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.WAIT oprs insSize

type internal OneOp9C () =
  inherit ParsingJob ()
  override __.Run rhlp =
    if hasOprSz rhlp.Prefixes then
      let szcond = if is64bit rhlp then SzCond.D64 else SzCond.Nor
      render rhlp Opcode.PUSHF szcond OD.No SZ.Def
    elif is64bit rhlp then render rhlp Opcode.PUSHFQ SzCond.D64 OD.No SZ.Def
    else render rhlp Opcode.PUSHFD SzCond.Nor OD.No SZ.Def

type internal OneOp9D () =
  inherit ParsingJob ()
  override __.Run rhlp =
    if hasOprSz rhlp.Prefixes then
      let szcond = if is64bit rhlp then SzCond.D64 else SzCond.Nor
      render rhlp Opcode.POPF szcond OD.No SZ.Def
    elif is64bit rhlp then render rhlp Opcode.POPFQ SzCond.D64 OD.No SZ.Def
    else render rhlp Opcode.POPFD SzCond.Nor OD.No SZ.Def

type internal OneOp9E () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.SAHF oprs insSize

type internal OneOp9F () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.LAHF oprs insSize

type internal OneOpA0 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RaxFar].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOpA1 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RaxFar].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOpA2 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.FarRax].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOpA3 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.FarRax].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOpA4 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = 8<rt> }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.MOVSB oprs insSize

type internal OneOpA5 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    if hasOprSz rhlp.Prefixes then
      render rhlp Opcode.MOVSW SzCond.Nor OD.No SZ.Def
    elif hasREXW rhlp.REXPrefix then
      render rhlp Opcode.MOVSQ SzCond.Nor OD.No SZ.Def
    else render rhlp Opcode.MOVSD SzCond.Nor OD.No SZ.Def

type internal OneOpA6 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.CMPSB oprs insSize

type internal OneOpA7 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    if hasOprSz rhlp.Prefixes then
      render rhlp Opcode.CMPSW SzCond.Nor OD.No SZ.Def
    elif hasREXW rhlp.REXPrefix then
      render rhlp Opcode.CMPSQ SzCond.Nor OD.No SZ.Def
    else render rhlp Opcode.CMPSD SzCond.Nor OD.No SZ.Def

type internal OneOpA8 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RegImm8].Render rhlp insSize
    newInsInfo rhlp Opcode.TEST oprs insSize

type internal OneOpA9 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RegImm].Render rhlp insSize
    newInsInfo rhlp Opcode.TEST oprs insSize

type internal OneOpAA () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = 8<rt> }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.STOSB oprs insSize

type internal OneOpAB () =
  inherit ParsingJob ()
  override __.Run rhlp =
    if hasOprSz rhlp.Prefixes then
      render rhlp Opcode.STOSW SzCond.Nor OD.No SZ.Def
    elif hasREXW rhlp.REXPrefix then
      render rhlp Opcode.STOSQ SzCond.Nor OD.No SZ.Def
    else render rhlp Opcode.STOSD SzCond.Nor OD.No SZ.Def

type internal OneOpAC () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = 8<rt> }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.LODSB oprs insSize

type internal OneOpAD () =
  inherit ParsingJob ()
  override __.Run rhlp =
    if hasOprSz rhlp.Prefixes then
      render rhlp Opcode.LODSW SzCond.Nor OD.No SZ.Def
    elif hasREXW rhlp.REXPrefix then
      render rhlp Opcode.LODSQ SzCond.Nor OD.No SZ.Def
    else render rhlp Opcode.LODSD SzCond.Nor OD.No SZ.Def

type internal OneOpAE () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let insSize = { insSize with OperationSize = 8<rt> }
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.SCASB oprs insSize

type internal OneOpAF () =
  inherit ParsingJob ()
  override __.Run rhlp =
    if hasOprSz rhlp.Prefixes then
      render rhlp Opcode.SCASW SzCond.Nor OD.No SZ.Def
    elif hasREXW rhlp.REXPrefix then
      render rhlp Opcode.SCASQ SzCond.Nor OD.No SZ.Def
    else render rhlp Opcode.SCASD SzCond.Nor OD.No SZ.Def

type internal OneOpB0 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.ALImm8].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOpB1 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.CLImm8].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOpB2 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.DLImm8].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOpB3 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.BLImm8].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOpB4 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.AhImm8].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOpB5 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.ChImm8].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOpB6 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.DhImm8].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOpB7 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.BhImm8].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOpB8 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RaxImm].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOpB9 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RcxImm].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOpBA () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RdxImm].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOpBB () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RbxImm].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOpBC () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RspImm].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOpBD () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RbpImm].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOpBE () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RsiImm].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOpBF () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RdiImm].Render rhlp insSize
    newInsInfo rhlp Opcode.MOV oprs insSize

type internal OneOpC0 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind rhlp OD.RmImm8 SZ.Byte OpGroup.G2
    render rhlp op szCond oidx szidx

type internal OneOpC1 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind rhlp OD.RmImm8 SZ.Def OpGroup.G2
    render rhlp op szCond oidx szidx

type internal OneOpC2 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Imm16].Render rhlp insSize
    newInsInfo rhlp Opcode.RETNearImm oprs insSize

type internal OneOpC3 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.RETNear oprs insSize

type internal OneOpC4 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    if (rhlp.WordSize = WordSize.Bit64) || (rhlp.PeekByte () >= 0xC0uy) then
      let mutable rex = rhlp.REXPrefix
      let vInfo = getThreeVEXInfo rhlp.BinReader &rex rhlp.CurrPos
      rhlp.VEXInfo <- Some vInfo
      rhlp.REXPrefix <- rex
      rhlp.CurrPos <- rhlp.CurrPos + 2
      match vInfo.VEXType with
      | VEXType.VEXTwoByteOp -> parseTwoByteOpcode rhlp
      | VEXType.VEXThreeByteOpOne -> parseThreeByteOp1 rhlp
      | VEXType.VEXThreeByteOpTwo -> parseThreeByteOp2 rhlp
      | _ -> raise ParsingFailureException
    else
      let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
      let insSize =
        rhlp.SzComputers.[int SZ.PZ].Render rhlp effOprSize effAddrSize
      let struct (oprs, insSize) =
        rhlp.OprParsers.[int OD.GprM].Render rhlp insSize
      newInsInfo rhlp Opcode.LES oprs insSize

type internal OneOpC5 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    if (rhlp.WordSize = WordSize.Bit64) || (rhlp.PeekByte () >= 0xC0uy) then
      let mutable rex = rhlp.REXPrefix
      rhlp.VEXInfo <- Some <| getTwoVEXInfo rhlp.BinReader &rex rhlp.CurrPos
      rhlp.REXPrefix <- rex
      rhlp.CurrPos <- rhlp.CurrPos + 1
      parseTwoByteOpcode rhlp
    else
      let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
      let insSize =
        rhlp.SzComputers.[int SZ.PZ].Render rhlp effOprSize effAddrSize
      let struct (oprs, insSize) =
        rhlp.OprParsers.[int OD.GprM].Render rhlp insSize
      newInsInfo rhlp Opcode.LDS oprs insSize

type internal OneOpC6 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind rhlp OD.RmImm8 SZ.Byte OpGroup.G11A
    render rhlp op szCond oidx szidx

type internal OneOpC7 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind rhlp OD.RmImm SZ.Def OpGroup.G11B
    render rhlp op szCond oidx szidx

type internal OneOpC8 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.ImmImm].Render rhlp insSize
    newInsInfo rhlp Opcode.ENTER oprs insSize

type internal OneOpC9 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.D64
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.LEAVE oprs insSize

type internal OneOpCA () =
  inherit ParsingJob ()
  override __.Run rhlp =
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Imm16].Render rhlp insSize
    newInsInfo rhlp Opcode.RETFarImm oprs insSize

type internal OneOpCB () =
  inherit ParsingJob ()
  override __.Run rhlp =
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.RETFar oprs insSize

type internal OneOpCC () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.INT3 oprs insSize

type internal OneOpCD () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Imm8].Render rhlp insSize
    newInsInfo rhlp Opcode.INT oprs insSize

type internal OneOpCE () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.INTO oprs insSize

type internal OneOpCF () =
  inherit ParsingJob ()
  override __.Run rhlp =
    if hasOprSz rhlp.Prefixes then
      render rhlp Opcode.IRETW SzCond.Nor OD.No SZ.Def
    elif hasREXW rhlp.REXPrefix then
      render rhlp Opcode.IRETQ SzCond.Nor OD.No SZ.Def
    else render rhlp Opcode.IRETD SzCond.Nor OD.No SZ.Def

type internal OneOpD0 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind rhlp OD.M1 SZ.Byte OpGroup.G2
    render rhlp op szCond oidx szidx

type internal OneOpD1 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind rhlp OD.M1 SZ.Def OpGroup.G2
    render rhlp op szCond oidx szidx

type internal OneOpD2 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind rhlp OD.RmCL SZ.Byte OpGroup.G2
    render rhlp op szCond oidx szidx

type internal OneOpD3 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind rhlp OD.RmCL SZ.Def OpGroup.G2
    render rhlp op szCond oidx szidx

type internal OneOpD4 () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Imm8].Render rhlp insSize
    newInsInfo rhlp Opcode.AAM oprs insSize

type internal OneOpD5 () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Imm8].Render rhlp insSize
    newInsInfo rhlp Opcode.AAD oprs insSize

type internal OneOpD6 () =
  inherit ParsingJob ()
  override __.Run _rhlp = raise ParsingFailureException

type internal OneOpD7 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.XLATB oprs insSize

type internal OneOpD8 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let modRM = rhlp.ReadByte ()
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    if modRM <= 0xBFuy then
      let op = getD8OpWithin00toBF modRM
      let effOprSize = getEscEffOprSizeByESCOp 0xD8uy
      let insSize =
        { insSize with MemEffOprSize = effOprSize; MemEffRegSize = effOprSize }
      let o = OperandParsingHelper.parseMemory modRM insSize rhlp
      newInsInfo rhlp op (OneOperand o) insSize
    else
      let opcode, oprs = getD8OverBF modRM
      newInsInfo rhlp opcode oprs insSize

type internal OneOpD9 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let modRM = rhlp.ReadByte ()
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    if modRM <= 0xBFuy then
      let op = getD9OpWithin00toBF modRM
      let effOprSize = getReg modRM |> getD9EscEffOprSizeByModRM
      let insSize =
        { insSize with MemEffOprSize = effOprSize; MemEffRegSize = effOprSize }
      let o = OperandParsingHelper.parseMemory modRM insSize rhlp
      newInsInfo rhlp op (OneOperand o) insSize
    else
      let opcode, oprs = getD9OverBF modRM
      newInsInfo rhlp opcode oprs insSize

type internal OneOpDA () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let modRM = rhlp.ReadByte ()
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    if modRM <= 0xBFuy then
      let op = getDAOpWithin00toBF modRM
      let effOprSize = getEscEffOprSizeByESCOp 0xDAuy
      let insSize =
        { insSize with MemEffOprSize = effOprSize; MemEffRegSize = effOprSize }
      let o = OperandParsingHelper.parseMemory modRM insSize rhlp
      newInsInfo rhlp op (OneOperand o) insSize
    else
      let opcode, oprs = getDAOverBF modRM
      newInsInfo rhlp opcode oprs insSize

type internal OneOpDB () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let modRM = rhlp.ReadByte ()
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    if modRM <= 0xBFuy then
      let op = getDBOpWithin00toBF modRM
      let effOprSize = getReg modRM |> getDBEscEffOprSizeByModRM
      let insSize =
        { insSize with MemEffOprSize = effOprSize; MemEffRegSize = effOprSize }
      let o = OperandParsingHelper.parseMemory modRM insSize rhlp
      newInsInfo rhlp op (OneOperand o) insSize
    else
      let opcode, oprs = getDBOverBF modRM
      newInsInfo rhlp opcode oprs insSize

type internal OneOpDC () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let modRM = rhlp.ReadByte ()
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    if modRM <= 0xBFuy then
      let op = getDCOpWithin00toBF modRM
      let effOprSize = getEscEffOprSizeByESCOp 0xDCuy
      let insSize =
        { insSize with MemEffOprSize = effOprSize; MemEffRegSize = effOprSize }
      let o = OperandParsingHelper.parseMemory modRM insSize rhlp
      newInsInfo rhlp op (OneOperand o) insSize
    else
      let opcode, oprs = getDCOverBF modRM
      newInsInfo rhlp opcode oprs insSize

type internal OneOpDD () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let modRM = rhlp.ReadByte ()
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    if modRM <= 0xBFuy then
      let op = getDDOpWithin00toBF modRM
      let effOprSize = getReg modRM |> getDDEscEffOprSizeByModRM
      let insSize =
        { insSize with MemEffOprSize = effOprSize; MemEffRegSize = effOprSize }
      let o = OperandParsingHelper.parseMemory modRM insSize rhlp
      newInsInfo rhlp op (OneOperand o) insSize
    else
      let opcode, oprs = getDDOverBF modRM
      newInsInfo rhlp opcode oprs insSize

type internal OneOpDE () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let modRM = rhlp.ReadByte ()
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    if modRM <= 0xBFuy then
      let op = getDEOpWithin00toBF modRM
      let effOprSize = getEscEffOprSizeByESCOp 0xDEuy
      let insSize =
        { insSize with MemEffOprSize = effOprSize; MemEffRegSize = effOprSize }
      let o = OperandParsingHelper.parseMemory modRM insSize rhlp
      newInsInfo rhlp op (OneOperand o) insSize
    else
      let opcode, oprs = getDEOverBF modRM
      newInsInfo rhlp opcode oprs insSize

type internal OneOpDF () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let modRM = rhlp.ReadByte ()
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    if modRM <= 0xBFuy then
      let op = getDFOpWithin00toBF modRM
      let effOprSize = getReg modRM |> getDFEscEffOprSizeByModRM
      let insSize =
        { insSize with MemEffOprSize = effOprSize; MemEffRegSize = effOprSize }
      let o = OperandParsingHelper.parseMemory modRM insSize rhlp
      newInsInfo rhlp op (OneOperand o) insSize
    else
      let opcode, oprs = getDFOverBF modRM
      newInsInfo rhlp opcode oprs insSize

type internal OneOpE0 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rel8].Render rhlp insSize
    newInsInfo rhlp Opcode.LOOPNE oprs insSize

type internal OneOpE1 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rel8].Render rhlp insSize
    newInsInfo rhlp Opcode.LOOPE oprs insSize

type internal OneOpE2 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rel8].Render rhlp insSize
    newInsInfo rhlp Opcode.LOOP oprs insSize

type internal OneOpE3 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    if hasAddrSz rhlp.Prefixes then
      let opcode = if is64bit rhlp then Opcode.JECXZ else Opcode.JCXZ
      render rhlp opcode SzCond.F64 OD.Rel8 SZ.Byte
    elif is64bit rhlp then render rhlp Opcode.JRCXZ SzCond.F64 OD.Rel8 SZ.Byte
    else render rhlp Opcode.JECXZ SzCond.F64 OD.Rel8 SZ.Byte

type internal OneOpE4 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RegImm8].Render rhlp insSize
    newInsInfo rhlp Opcode.IN oprs insSize

type internal OneOpE5 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.RegImm8].Render rhlp insSize
    newInsInfo rhlp Opcode.IN oprs insSize

type internal OneOpE6 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Imm8Reg].Render rhlp insSize
    newInsInfo rhlp Opcode.OUT oprs insSize

type internal OneOpE7 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Imm8Reg].Render rhlp insSize
    newInsInfo rhlp Opcode.OUT oprs insSize

type internal OneOpE8 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.D64].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rel].Render rhlp insSize
    newInsInfo rhlp Opcode.CALLNear oprs insSize

type internal OneOpE9 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.D64].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rel].Render rhlp insSize
    newInsInfo rhlp Opcode.JMPNear oprs insSize

type internal OneOpEA () =
  inherit ParsingJob ()
  override __.Run rhlp =
#if !EMULATION
    ensure32 rhlp
#endif
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.P].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Dir].Render rhlp insSize
    newInsInfo rhlp Opcode.JMPFar oprs insSize

type internal OneOpEB () =
  inherit ParsingJob ()
  override __.Run rhlp =
    addBND rhlp
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Byte].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.Rel8].Render rhlp insSize
    newInsInfo rhlp Opcode.JMPNear oprs insSize

type internal OneOpEC () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.ALDx].Render rhlp insSize
    newInsInfo rhlp Opcode.IN oprs insSize

type internal OneOpED () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.EaxDx].Render rhlp insSize
    newInsInfo rhlp Opcode.IN oprs insSize

type internal OneOpEE () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.DxAL].Render rhlp insSize
    newInsInfo rhlp Opcode.OUT oprs insSize

type internal OneOpEF () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.Nor
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.DxEax].Render rhlp insSize
    newInsInfo rhlp Opcode.OUT oprs insSize

type internal OneOpF0 () =
  inherit ParsingJob ()
  override __.Run _rhlp = raise ParsingFailureException

type internal OneOpF1 () =
  inherit ParsingJob ()
  override __.Run _rhlp = raise ParsingFailureException

type internal OneOpF2 () =
  inherit ParsingJob ()
  override __.Run _rhlp = raise ParsingFailureException

type internal OneOpF3 () =
  inherit ParsingJob ()
  override __.Run _rhlp = raise ParsingFailureException

type internal OneOpF4 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.HLT oprs insSize

type internal OneOpF5 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.CMC oprs insSize

type internal OneOpF6 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind rhlp OD.Mem SZ.Byte OpGroup.G3A
    render rhlp op szCond oidx szidx

type internal OneOpF7 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind rhlp OD.Mem SZ.Def OpGroup.G3B
    render rhlp op szCond oidx szidx

type internal OneOpF8 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.CLC oprs insSize

type internal OneOpF9 () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.STC oprs insSize

type internal OneOpFA () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.CLI oprs insSize

type internal OneOpFB () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.STI oprs insSize

type internal OneOpFC () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.CLD oprs insSize

type internal OneOpFD () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (effOprSize, effAddrSize) = getSize rhlp SzCond.F64
    let insSize =
      rhlp.SzComputers.[int SZ.Def].Render rhlp effOprSize effAddrSize
    let struct (oprs, insSize) =
      rhlp.OprParsers.[int OD.No].Render rhlp insSize
    newInsInfo rhlp Opcode.STD oprs insSize

type internal OneOpFE () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind rhlp OD.No SZ.Def OpGroup.G4
    render rhlp op szCond oidx szidx

type internal OneOpFF () =
  inherit ParsingJob ()
  override __.Run rhlp =
    let struct (op, oidx, szidx, szCond) =
      parseGrpOpKind rhlp OD.No SZ.Def OpGroup.G5
    if isBranch op then addBND rhlp else ()
    render rhlp op szCond oidx szidx
