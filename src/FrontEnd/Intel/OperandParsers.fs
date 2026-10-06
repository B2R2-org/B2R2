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

/// The register lookups the generated opcode maps (LegacyOpcodeMap,
/// VEXOpcodeMap) and their helpers (OpcodeMapHelper) read.
[<RequireQualifiedAccess>]
module internal B2R2.FrontEnd.Intel.OperandParsers

open System
open System.Runtime.CompilerServices
open B2R2
open B2R2.FrontEnd.BinLifter

/// The register of the given width at the given index. The general-purpose
/// widths come first, being asked for most; the registers from 16 up sit
/// outside the 0 to 15 run and go through the helpers, the extended GPRs of
/// Intel APX among them.
let inline private regOfIndex sz (n: int) =
  match sz with
  | 32<rt> when n < 16 ->
    int R.EAX + n |> LanguagePrimitives.EnumOfValue<int, Register>
  | 64<rt> when n < 16 ->
    int R.RAX + n |> LanguagePrimitives.EnumOfValue<int, Register>
  | 8<rt> when n < 16 ->
    int R.AL + n |> LanguagePrimitives.EnumOfValue<int, Register>
  | 16<rt> when n < 16 ->
    int R.AX + n |> LanguagePrimitives.EnumOfValue<int, Register>
  | 8<rt> | 16<rt> | 32<rt> | 64<rt> ->
    RegisterHelper.egpr sz n
  | 128<rt> ->
    RegisterHelper.xmm n
  | 256<rt> ->
    RegisterHelper.ymm n
  | 512<rt> ->
    RegisterHelper.zmm n
  (* The width the AMX rows give a tile operand. It is not a width a tile has
     -- the manual writes these operands tmm1, tmm2 and tmm3, with no size at
     all -- but the table has no other way to say which register file the
     field names, and 1024 is the one it spends on saying so. *)
  | 1024<rt> ->
    RegisterHelper.tmm n
  | _ ->
    raise ParsingFailureException

/// Find a specific reg. The bitmask will be used to extract a specific REX
/// bit (R/X/B); a fifth bit, where the encoding carries one, arrives added
/// to n as 16. The index is settled first and mapped to a register once:
/// mapping it on every branch had the compiler split the match into
/// continuation methods, and a call for every register read.
let inline private findReg sz rex bitmask (n: int) =
  if rex = REXPrefix.NOREX then
    regOfIndex sz n
  elif (int rex &&& bitmask) > 0 then
    regOfIndex sz (n + 8)
  elif sz = 8<rt> && (n &&& 0b10100) = 0b100 then
    (* SPL/BPL/SIL/DIL displace AH/CH/DH/BH once a REX byte is present; with
       the fifth bit set the same codes name R20B to R23B instead. *)
    int R.SPL + n - 4 |> LanguagePrimitives.EnumOfValue<int, Register>
  else
    regOfIndex sz n

/// The general-purpose register of the given width at the given index, 0 to
/// 31, as a field that no REX bit extends names it: (E)VEX.vvvv, with
/// EVEX.V4 as its fifth bit. Only an EVEX prefix reaches a byte register
/// here, and it stands in for REX, so codes 4 to 7 name SPL, BPL, SIL and DIL
/// rather than AH, CH, DH and BH.
[<MethodImpl(MethodImplOptions.AggressiveInlining)>]
let findGPR sz (n: int) =
  if sz = 8<rt> && (n &&& 0b11100) = 0b100 then
    int R.SPL + n - 4 |> LanguagePrimitives.EnumOfValue<int, Register>
  else
    regOfIndex sz n

/// Registers defined by the SIB index field.
[<MethodImpl(MethodImplOptions.AggressiveInlining)>]
let findRegSIBIdx sz rex (n: int) = findReg sz rex 2 n

/// Registers defined by the SIB base field, or base registers defined by the
/// RM field (first three rows of Table 2-2), or registers defined by REG bit
/// of the opcode, which can change the symbol by REX bits.
[<MethodImpl(MethodImplOptions.AggressiveInlining)>]
let findRegRmAndSIBBase sz rex (n: int) = findReg sz rex 1 n

/// Registers defined by REG field of the ModR/M byte.
[<MethodImpl(MethodImplOptions.AggressiveInlining)>]
let findRegRBits sz rex (n: int): Register = findReg sz rex 4 n

/// The register an /is4 operand names. Its four bits of imm8 already reach
/// every register the mode has, so nothing in the REX or VEX prefix extends
/// them; a 32-bit mode ignores the top one instead of adding to it.
let findRegIS4 wordSize sz (n: int) =
  if wordSize = WordSize.Bit32 then regOfIndex sz (n &&& 0b0111)
  else regOfIndex sz n

let parseMMXReg n = RegisterHelper.mm n |> Operands.oprReg

let parseSegReg n =
  if n < 6 then RegisterHelper.seg n |> Operands.oprReg
  else raise ParsingFailureException

let parseBoundRegister n =
  if n < 4 then RegisterHelper.bound n |> Operands.oprReg
  else raise ParsingFailureException

/// The index of a control or debug register: ModRM.reg, widened by REX.R.
let sysRegIndex modRM (rex: REXPrefix) =
  let n = Operands.getReg modRM
  if (int rex &&& 0b100) > 0 then n + 8 else n

let parseControlReg n =
  match n with
  | 0 -> Operands.oprReg R.CR0
  | 2 -> Operands.oprReg R.CR2
  | 3 -> Operands.oprReg R.CR3
  | 4 -> Operands.oprReg R.CR4
  | 8 -> Operands.oprReg R.CR8
  | _ -> raise ParsingFailureException

let parseDebugReg n =
  match n with
  | 0 -> Operands.oprReg R.DR0
  | 1 -> Operands.oprReg R.DR1
  | 2 -> Operands.oprReg R.DR2
  | 3 -> Operands.oprReg R.DR3
  | 4 | 6 -> Operands.oprReg R.DR6
  | 5 | 7 -> Operands.oprReg R.DR7
  | _ -> raise ParsingFailureException

let parseOpMaskReg n =
  if n > 7 then raise ParsingFailureException
  else RegisterHelper.opmask n |> Operands.oprReg

// vim: set tw=80 sts=2 sw=2:
