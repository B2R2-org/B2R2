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

/// Represents a set of operands in an intel instruction.
type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | FourOperands of Operand * Operand * Operand * Operand

/// Represents four different types of intel operands:
/// register, memory, direct address, and immediate.
and Operand =
  /// A register operand.
  | OprReg of Register
  /// OprMem represents a memory operand. The OperandSize here means the memory
  /// access size of the operand, i.e., how many bytes do we read/write here.
  | OprMem of Register option
            * ScaledIndex option
            * Displacement option
            * OperandSize
  /// OprDirAddr is a direct branch target address.
  | OprDirAddr of JumpTarget
  /// OprImm represents an immediate operand. The OperandSize here means the
  /// size of the encoded immediate value.
  | OprImm of int64 * OperandSize
  /// Label is *not* encoded in the actual binary. This is only used when we
  /// assemble binaries.
  | Label of string * RegType

/// Represents a scaled index composed of a register and a scaling factor.
and ScaledIndex = Register * Scale

/// Represents the scaling factor used in index addressing.
and Scale =
  /// Times 1
  | X1 = 1
  /// Times 2
  | X2 = 2
  /// Times 4
  | X4 = 4
  /// Times 8
  | X8 = 8

/// Represents a displacement value used for memory offset calculations.
and Displacement = int64

/// Represents operand size.
and OperandSize = RegType

/// Represents the target of a jump instruction.
and JumpTarget =
  | Absolute of SegmentSelector * Addr * OperandSize
  | Relative of Offset

/// Represents a segment selector used in intel architecture.
and SegmentSelector = int16

/// Represents an offset value used for relative jump instructions.
and Offset = int64

/// Provides several accessor functions for operands.
[<RequireQualifiedAccess>]
module internal Operands =
  let inline getMod (byte: byte) = (int byte >>> 6) &&& 0b11

  let inline getReg (byte: byte) = (int byte >>> 3) &&& 0b111

  let inline getRM (byte: byte) = (int byte) &&& 0b111

  /// OprReg r for every register, made once. An operand is immutable, so one
  /// instance serves every instruction that names the register, and a fresh
  /// one per register operand was an allocation for a value that never
  /// changes.
  let oprRegs =
    let regs = System.Enum.GetValues typeof<Register> :?> Register[]
    Array.init ((regs |> Array.map int |> Array.max) + 1) (fun i ->
      OprReg(LanguagePrimitives.EnumOfValue<int, Register> i))

  /// The register operand naming the given register.
  let inline oprReg (r: Register) = oprRegs[int r]

  /// OneOperand over every register operand, made once for the same reason:
  /// PUSH, POP, INC and their kin name one register and nothing else.
  let private oneRegOperands = oprRegs |> Array.map OneOperand

  /// TwoOperands over every pair of general-purpose registers, made once for
  /// the same reason. The 64 general-purpose registers come first in the
  /// enumeration, so a pair indexes the array directly; MOV, TEST, XOR and
  /// CMP between two registers make up a fifth of compiled code.
  let private twoGprOperands =
    Array.init (64 * 64) (fun i ->
      TwoOperands(oprRegs[i >>> 6], oprRegs[i &&& 0x3F]))

  /// The operands value holding the given operand alone.
  let oneOperand o =
    match o with
    | OprReg r -> oneRegOperands[int r]
    | _ -> OneOperand o

  /// The operands value holding the two given operands, in that order.
  let twoOperands o1 o2 =
    match o1, o2 with
    | OprReg a, OprReg b when int a < 64 && int b < 64 ->
      twoGprOperands[(int a <<< 6) ||| int b]
    | _ ->
      TwoOperands(o1, o2)

  /// The immediate operands a byte can hold, read signed or unsigned, at each
  /// general-purpose width, made once: most immediates in compiled code fit
  /// in a byte, and each one allocated was a value out of these 1,536.
  let private byteImms =
    [| 8<rt>; 16<rt>; 32<rt>; 64<rt> |]
    |> Array.map (fun sz ->
      Array.init 384 (fun i -> OprImm(int64 (i - 128), sz)))

  /// The immediate operand of the given value and width.
  let oprImm (v: int64) sz =
    let szIdx =
      match sz with
      | 8<rt> -> 0
      | 16<rt> -> 1
      | 32<rt> -> 2
      | 64<rt> -> 3
      | _ -> -1
    if szIdx >= 0 && v >= -128L && v <= 255L then byteImms[szIdx][int v + 128]
    else OprImm(v, sz)

  /// The relative branch targets a short branch can name, made once: the
  /// offset a byte holds, plus the two to seven bytes of the instruction
  /// carrying it, lands in this range.
  let private shortRelTargets =
    Array.init 384 (fun i -> OprDirAddr(Relative(int64 (i - 128))))

  /// The direct-address operand of a branch to the given relative target.
  let relTarget (d: int64) =
    if d >= -128L && d <= 255L then shortRelTargets[int d + 128]
    else OprDirAddr(Relative d)

  let inline getSTReg n = RegisterHelper.streg n |> oprReg

  let inline modIsMemory b = (getMod b) <> 0b11

  let inline modIsReg b = (getMod b) = 0b11
