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

/// Lifts prefixed addresses and storage operations in the PPC front end.
module internal B2R2.FrontEnd.PPC.PrefixedLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC.LiftingUtils

/// The prefixed effective address uses CIA for R=1, otherwise RA|0.
let private addressOf (ins: Instruction) (bld: ILowUIRBuilder) =
  match ins.Operands with
  | ThreeOperands(_, OprMem64(d, ra), OprImm relative) ->
    let baseValue =
      if relative = 1UL then numU64 ins.Address 64<rt>
      elif ra = Register.R0 then AST.num0 64<rt>
      else regVar bld ra
    baseValue .+ numI64 d 64<rt>
  | _ ->
    raise InvalidOperandException

let private targetOf (ins: Instruction) =
  match ins.Operands with
  | ThreeOperands(target, _, _) -> target
  | _ -> raise InvalidOperandException

/// PADDI adds the signed 34-bit immediate without changing XER or CR.
let addImmediate (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    match ins.Operands with
    | FourOperands(OprReg rt, OprReg ra, OprImm imm, OprImm relative) ->
      let baseValue =
        if relative = 1UL then numU64 ins.Address 64<rt>
        elif ra = Register.R0 then AST.num0 64<rt>
        else regVar bld ra
      regVar bld rt := baseValue .+ numU64 imm 64<rt>
    | _ ->
      raise InvalidOperandException
  }

/// The scalar integer loads extend their byte, halfword or word as defined.
let loadInteger ins (bld: ILowUIRBuilder) width signed =
  lift bld ins {
    let ea = tmpVar bld 64<rt>
    ea := addressOf ins bld
    let value = loadNative bld width ea
    let value = if signed then AST.sext 64<rt> value else AST.zext 64<rt> value
    transOpr bld (targetOf ins) := value
  }

let storeInteger ins (bld: ILowUIRBuilder) width =
  lift bld ins {
    let ea = tmpVar bld 64<rt>
    ea := addressOf ins bld
    loadNative bld width ea := AST.xtlo width (transOpr bld (targetOf ins))
  }

let doubleOfSingle bld word =
  let w = tmpVar bld 32<rt>
  let res = tmpVar bld 64<rt>
  append bld {
    w := word
    let isNaN =
      (w .& numU32 0x7f800000u 32<rt> == numU32 0x7f800000u 32<rt>)
      .& (w .& numU32 0x007fffffu 32<rt> != AST.num0 32<rt>)
    let w64 = AST.zext 64<rt> w
    let nan =
      ((w64 .& numU64 0x80000000UL 64<rt>) << numI32 32 64<rt>)
      .| numU64 0x7ff0000000000000UL 64<rt>
      .| ((w64 .& numU64 0x007fffffUL 64<rt>) << numI32 29 64<rt>)
    res := AST.ite isNaN nan (AST.cast CastKind.FloatCast 64<rt> w)
  }
  res

/// Floating-point singles widen exactly; NaN payloads retain their bits.
let loadFloat ins (bld: ILowUIRBuilder) single vector =
  lift bld ins {
    let ea = tmpVar bld 64<rt>
    ea := addressOf ins bld
    let target = targetOf ins
    let value =
      if single then doubleOfSingle bld (loadNative bld 32<rt> ea)
      else loadNative bld 64<rt> ea
    transOpr bld target := value
    if vector then
      let struct (_, low) = VSXLifter.vsrOf bld target
      low := AST.num0 64<rt>
    else
      ()
  }

let storeFloat ins (bld: ILowUIRBuilder) single =
  lift bld ins {
    let ea = tmpVar bld 64<rt>
    ea := addressOf ins bld
    let source = transOpr bld (targetOf ins)
    if single then
      loadNative bld 32<rt> ea := GeneralLifter.singleBits bld source
    else
      loadNative bld 64<rt> ea := source
  }

/// PLQ and PSTQ keep the even GPR at EA in either byte order.
let gprPair ins (bld: ILowUIRBuilder) load =
  lift bld ins {
    let ea = tmpVar bld 64<rt>
    ea := addressOf ins bld
    let reg =
      match targetOf ins with
      | OprReg reg -> reg
      | _ -> raise InvalidOperandException
    for i in 0 .. 1 do
      let variable = enum<Register> (int reg + i) |> regVar bld
      let memory = loadNative bld 64<rt> (ea .+ numI32 (8 * i) 64<rt>)
      if load then variable := memory else memory := variable
  }

/// A VSR or VSR pair is a 128- or 256-bit value in the guest's byte order.
let vector ins (bld: ILowUIRBuilder) load pair =
  lift bld ins {
    let ea = tmpVar bld 64<rt>
    ea := addressOf ins bld
    let target = targetOf ins
    for row in 0 .. (if pair then 1 else 0) do
      let operand =
        if row = 0 then
          target
        else
          match target with
          | OprReg reg -> OprReg(VSXLifter.secondOfPair reg)
          | _ -> raise InvalidOperandException
      let struct (h, l) = VSXLifter.vsrOf bld operand
      let little = bld.Endianness = Endian.Little
      let index = if pair && little then 1 - row else row
      let offset = index * 16
      let highOffset = offset + (if little then 8 else 0)
      let lowOffset = offset + (if little then 0 else 8)
      let high = loadNative bld 64<rt> (ea .+ numI32 highOffset 64<rt>)
      let low = loadNative bld 64<rt> (ea .+ numI32 lowOffset 64<rt>)
      if load then
        h := high
        l := low
      else
        high := h
        low := l
  }
