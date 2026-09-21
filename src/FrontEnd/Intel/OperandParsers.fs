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

/// The register lookups and the shared operand cells the generated opcode
/// code (DLegacy, DVex) and its runtime (DOps) read.
[<RequireQualifiedAccess>]
module internal B2R2.FrontEnd.Intel.OperandParsers

open System
open System.Runtime.CompilerServices
open B2R2
open B2R2.FrontEnd.BinLifter

/// The register of the given width at the given index. The general-purpose
/// widths come first, being asked for most; the vector registers go through
/// the helpers because 16 to 31 sit outside the 0 to 15 run.
let inline private regOfIndex sz (n: int) =
  match sz with
  | 32<rt> -> int R.EAX + n |> LanguagePrimitives.EnumOfValue<int, Register>
  | 64<rt> -> int R.RAX + n |> LanguagePrimitives.EnumOfValue<int, Register>
  | 8<rt> -> int R.AL + n |> LanguagePrimitives.EnumOfValue<int, Register>
  | 16<rt> -> int R.AX + n |> LanguagePrimitives.EnumOfValue<int, Register>
  | 128<rt> -> RegisterHelper.xmm n
  | 256<rt> -> RegisterHelper.ymm n
  | 512<rt> -> RegisterHelper.zmm n
  | _ -> raise ParsingFailureException

/// Find a specific reg. The bitmask will be used to extract a specific REX
/// bit (R/X/B). The index is settled first and mapped to a register once:
/// mapping it on every branch had the compiler split the match into
/// continuation methods, and a call for every register read.
let inline private findReg sz rex bitmask (n: int) =
  let n =
    if rex = REXPrefix.NOREX then n
    elif (int rex &&& bitmask) > 0 then n + 8
    elif sz > 8<rt> || ((n &&& 4) = 0) then n
    (* SPL/BPL/SIL/DIL displace AH/CH/DH/BH once a REX byte is present. *)
    else n + 12
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

/// Some r for every register, made once. A memory operand names its base
/// register through an option, and a fresh one for every operand was a heap
/// allocation for a value that never changes.
let someRegs =
  let regs = Enum.GetValues typeof<Register> :?> Register[]
  Array.init ((regs |> Array.map int |> Array.max) + 1) (fun i ->
    Some(LanguagePrimitives.EnumOfValue<int, Register> i))

let inline someReg (r: Register) = someRegs[int r]

/// Some (r, scale) for every register and scale, made once for the same
/// reason. Indexed by the two-bit SIB.scale field, then by the register.
let someScaledIndexes =
  Array.init 4 (fun s ->
    someRegs
    |> Array.mapi (fun i _ ->
      let r: Register = LanguagePrimitives.EnumOfValue i
      Some(r, LanguagePrimitives.EnumOfValue<int, Scale>(1 <<< s))))

let inline someScaledIndex (r: Register) s = someScaledIndexes[s][int r]

/// Some d for every displacement a byte can hold, made once. Most memory
/// operands carry one, and a fresh option per operand was an allocation for
/// one of 256 values.
let someDisp8 = Array.init 256 (fun i -> Some(int64 (i - 128)))

let inline someDisp (d: int64) =
  if d >= -128L && d <= 127L then someDisp8[int d + 128] else Some d

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
