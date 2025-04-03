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

namespace B2R2.FrontEnd.WASM

open B2R2

type Register =
  // Stack pointer
  | SP = 0x1

/// Shortcut for Register type.
type internal R = Register

/// Operation Size.
type OperationSize = int
module internal OperationSize =
  let regType = 32<rt>

/// This module exposes several useful functions to handle WASM registers.
[<RequireQualifiedAccess>]
module Register =
  let inline ofRegID (n: RegisterID): Register =
    int n |> LanguagePrimitives.EnumOfValue

  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  let ofString (str: string) =
    match str.ToLowerInvariant () with
    | "SP" -> R.SP
    | _ -> Terminator.impossible ()

  let toString = function
    | R.SP -> "SP"
    | _ -> Terminator.impossible ()

  let toRegType = function
    | R.SP -> 32<rt>
    | _ -> Terminator.impossible ()

/// <summary>
///   WASM opcodes.
/// </summary>
type Opcode =
  | Unreachable
  | Nop
  | Block
  | Loop
  | If
  | Else
  | Try
  | Catch
  | Throw
  | Rethrow
  | End
  | Br
  | BrIf
  | BrTable
  | Return
  | Call
  | CallIndirect
  | ReturnCall
  | ReturnCallIndirect
  | CallRef
  | Delegate
  | CatchAll
  | Drop
  | Select
  | SelectT
  | LocalGet
  | LocalSet
  | LocalTee
  | GlobalGet
  | GlobalSet
  | I32Load
  | I64Load
  | F32Load
  | F64Load
  | I32Load8S
  | I32Load8U
  | I32Load16S
  | I32Load16U
  | I64Load8S
  | I64Load8U
  | I64Load16S
  | I64Load16U
  | I64Load32S
  | I64Load32U
  | I32Store
  | I64Store
  | F32Store
  | F64Store
  | I32Store8
  | I32Store16
  | I64Store8
  | I64Store16
  | I64Store32
  | MemorySize
  | MemoryGrow
  | I32Const
  | I64Const
  | F32Const
  | F64Const
  | I32Eqz
  | I32Eq
  | I32Ne
  | I32LtS
  | I32LtU
  | I32GtS
  | I32GtU
  | I32LeS
  | I32LeU
  | I32GeS
  | I32GeU
  | I64Eqz
  | I64Eq
  | I64Ne
  | I64LtS
  | I64LtU
  | I64GtS
  | I64GtU
  | I64LeS
  | I64LeU
  | I64GeS
  | I64GeU
  | F32Eq
  | F32Ne
  | F32Lt
  | F32Gt
  | F32Le
  | F32Ge
  | F64Eq
  | F64Ne
  | F64Lt
  | F64Gt
  | F64Le
  | F64Ge
  | I32Clz
  | I32Ctz
  | I32Popcnt
  | I32Add
  | I32Sub
  | I32Mul
  | I32DivS
  | I32DivU
  | I32RemS
  | I32RemU
  | I32And
  | I32Or
  | I32Xor
  | I32Shl
  | I32ShrS
  | I32ShrU
  | I32Rotl
  | I32Rotr
  | I64Clz
  | I64Ctz
  | I64Popcnt
  | I64Add
  | I64Sub
  | I64Mul
  | I64DivS
  | I64DivU
  | I64RemS
  | I64RemU
  | I64And
  | I64Or
  | I64Xor
  | I64Shl
  | I64ShrS
  | I64ShrU
  | I64Rotl
  | I64Rotr
  | F32Abs
  | F32Neg
  | F32Ceil
  | F32Floor
  | F32Trunc
  | F32Nearest
  | F32Sqrt
  | F32Add
  | F32Sub
  | F32Mul
  | F32Div
  | F32Min
  | F32Max
  | F32Copysign
  | F64Abs
  | F64Neg
  | F64Ceil
  | F64Floor
  | F64Trunc
  | F64Nearest
  | F64Sqrt
  | F64Add
  | F64Sub
  | F64Mul
  | F64Div
  | F64Min
  | F64Max
  | F64Copysign
  | I32WrapI64
  | I32TruncF32S
  | I32TruncF32U
  | I32TruncF64S
  | I32TruncF64U
  | I64ExtendI32S
  | I64ExtendI32U
  | I64TruncF32S
  | I64TruncF32U
  | I64TruncF64S
  | I64TruncF64U
  | F32ConvertI32S
  | F32ConvertI32U
  | F32ConvertI64S
  | F32ConvertI64U
  | F32DemoteF64
  | F64ConvertI32S
  | F64ConvertI32U
  | F64ConvertI64S
  | F64ConvertI64U
  | F64PromoteF32
  | I32ReinterpretF32
  | I64ReinterpretF64
  | F32ReinterpretI32
  | F64ReinterpretI64
  /// Sign-extension opcodes. (--enable-sign-extension)
  | I32Extend8S
  | I32Extend16S
  | I64Extend8S
  | I64Extend16S
  | I64Extend32S
  /// Interpreter-only opcodes.
  | InterpAlloca
  | InterpBrUnless
  | InterpCallImport
  | InterpData
  | InterpDropKeep
  | InterpCatchDrop
  | InterpAdjustFrameForReturnCall
  /// Saturating float-to-int opcodes. (--enable-saturating-float-to-int)
  | I32TruncSatF32S
  | I32TruncSatF32U
  | I32TruncSatF64S
  | I32TruncSatF64U
  | I64TruncSatF32S
  | I64TruncSatF32U
  | I64TruncSatF64S
  | I64TruncSatF64U
  /// Bulk-memory.
  | MemoryInit
  | DataDrop
  | MemoryCopy
  | MemoryFill
  | TableInit
  | ElemDrop
  | TableCopy
  /// Reference types.
  | TableGet
  | TableSet
  | TableGrow
  | TableSize
  | TableFill
  | RefNull
  | RefIsNull
  | RefFunc
  /// Simd opcodes.
  | V128Load
  | V128Load8X8S
  | V128Load8X8U
  | V128Load16X4S
  | V128Load16X4U
  | V128Load32X2S
  | V128Load32X2U
  | V128Load8Splat
  | V128Load16Splat
  | V128Load32Splat
  | V128Load64Splat
  | V128Store
  | V128Const
  | I8X16Shuffle
  | I8X16Swizzle
  | I8X16Splat
  | I16X8Splat
  | I32X4Splat
  | I64X2Splat
  | F32X4Splat
  | F64X2Splat
  | I8X16ExtractLaneS
  | I8X16ExtractLaneU
  | I8X16ReplaceLane
  | I16X8ExtractLaneS
  | I16X8ExtractLaneU
  | I16X8ReplaceLane
  | I32X4ExtractLane
  | I32X4ReplaceLane
  | I64X2ExtractLane
  | I64X2ReplaceLane
  | F32X4ExtractLane
  | F32X4ReplaceLane
  | F64X2ExtractLane
  | F64X2ReplaceLane
  | I8X16Eq
  | I8X16Ne
  | I8X16LtS
  | I8X16LtU
  | I8X16GtS
  | I8X16GtU
  | I8X16LeS
  | I8X16LeU
  | I8X16GeS
  | I8X16GeU
  | I16X8Eq
  | I16X8Ne
  | I16X8LtS
  | I16X8LtU
  | I16X8GtS
  | I16X8GtU
  | I16X8LeS
  | I16X8LeU
  | I16X8GeS
  | I16X8GeU
  | I32X4Eq
  | I32X4Ne
  | I32X4LtS
  | I32X4LtU
  | I32X4GtS
  | I32X4GtU
  | I32X4LeS
  | I32X4LeU
  | I32X4GeS
  | I32X4GeU
  | F32X4Eq
  | F32X4Ne
  | F32X4Lt
  | F32X4Gt
  | F32X4Le
  | F32X4Ge
  | F64X2Eq
  | F64X2Ne
  | F64X2Lt
  | F64X2Gt
  | F64X2Le
  | F64X2Ge
  | V128Not
  | V128And
  | V128Andnot
  | V128Or
  | V128Xor
  | V128BitSelect
  | V128AnyTrue
  | V128Load8Lane
  | V128Load16Lane
  | V128Load32Lane
  | V128Load64Lane
  | V128Store8Lane
  | V128Store16Lane
  | V128Store32Lane
  | V128Store64Lane
  | V128Load32Zero
  | V128Load64Zero
  | F32X4DemoteF64X2Zero
  | F64X2PromoteLowF32X4
  | I8X16Abs
  | I8X16Neg
  | I8X16Popcnt
  | I8X16AllTrue
  | I8X16Bitmask
  | I8X16NarrowI16X8S
  | I8X16NarrowI16X8U
  | I8X16Shl
  | I8X16ShrS
  | I8X16ShrU
  | I8X16Add
  | I8X16AddSatS
  | I8X16AddSatU
  | I8X16Sub
  | I8X16SubSatS
  | I8X16SubSatU
  | I8X16MinS
  | I8X16MinU
  | I8X16MaxS
  | I8X16MaxU
  | I8X16AvgrU
  | I16X8ExtaddPairwiseI8X16S
  | I16X8ExtaddPairwiseI8X16U
  | I32X4ExtaddPairwiseI16X8S
  | I32X4ExtaddPairwiseI16X8U
  | I16X8Abs
  | I16X8Neg
  | I16X8Q15mulrSatS
  | I16X8AllTrue
  | I16X8Bitmask
  | I16X8NarrowI32X4S
  | I16X8NarrowI32X4U
  | I16X8ExtendLowI8X16S
  | I16X8ExtendHighI8X16S
  | I16X8ExtendLowI8X16U
  | I16X8ExtendHighI8X16U
  | I16X8Shl
  | I16X8ShrS
  | I16X8ShrU
  | I16X8Add
  | I16X8AddSatS
  | I16X8AddSatU
  | I16X8Sub
  | I16X8SubSatS
  | I16X8SubSatU
  | I16X8Mul
  | I16X8MinS
  | I16X8MinU
  | I16X8MaxS
  | I16X8MaxU
  | I16X8AvgrU
  | I16X8ExtmulLowI8X16S
  | I16X8ExtmulHighI8X16S
  | I16X8ExtmulLowI8X16U
  | I16X8ExtmulHighI8X16U
  | I32X4Abs
  | I32X4Neg
  | I32X4AllTrue
  | I32X4Bitmask
  | I32X4ExtendLowI16X8S
  | I32X4ExtendHighI16X8S
  | I32X4ExtendLowI16X8U
  | I32X4ExtendHighI16X8U
  | I32X4Shl
  | I32X4ShrS
  | I32X4ShrU
  | I32X4Add
  | I32X4Sub
  | I32X4Mul
  | I32X4MinS
  | I32X4MinU
  | I32X4MaxS
  | I32X4MaxU
  | I32X4DotI16X8S
  | I32X4ExtmulLowI16X8S
  | I32X4ExtmulHighI16X8S
  | I32X4ExtmulLowI16X8U
  | I32X4ExtmulHighI16X8U
  | I64X2Abs
  | I64X2Neg
  | I64X2AllTrue
  | I64X2Bitmask
  | I64X2ExtendLowI32X4S
  | I64X2ExtendHighI32X4S
  | I64X2ExtendLowI32X4U
  | I64X2ExtendHighI32X4U
  | I64X2Shl
  | I64X2ShrS
  | I64X2ShrU
  | I64X2Add
  | I64X2Sub
  | I64X2Mul
  | I64X2Eq
  | I64X2Ne
  | I64X2LtS
  | I64X2GtS
  | I64X2LeS
  | I64X2GeS
  | I64X2ExtmulLowI32X4S
  | I64X2ExtmulHighI32X4S
  | I64X2ExtmulLowI32X4U
  | I64X2ExtmulHighI32X4U
  | F32X4Ceil
  | F32X4Floor
  | F32X4Trunc
  | F32X4Nearest
  | F64X2Ceil
  | F64X2Floor
  | F64X2Trunc
  | F64X2Nearest
  | F32X4Abs
  | F32X4Neg
  | F32X4Sqrt
  | F32X4Add
  | F32X4Sub
  | F32X4Mul
  | F32X4Div
  | F32X4Min
  | F32X4Max
  | F32X4PMin
  | F32X4PMax
  | F64X2Abs
  | F64X2Neg
  | F64X2Sqrt
  | F64X2Add
  | F64X2Sub
  | F64X2Mul
  | F64X2Div
  | F64X2Min
  | F64X2Max
  | F64X2PMin
  | F64X2PMax
  | I32X4TruncSatF32X4S
  | I32X4TruncSatF32X4U
  | F32X4ConvertI32X4S
  | F32X4ConvertI32X4U
  | I32X4TruncSatF64X2SZero
  | I32X4TruncSatF64X2UZero
  | F64X2ConvertLowI32X4S
  | F64X2ConvertLowI32X4U
  /// Thread opcodes (--enable-threads)
  | MemoryAtomicNotify
  | MemoryAtomicWait32
  | MemoryAtomicWait64
  | AtomicFence
  | I32AtomicLoad
  | I64AtomicLoad
  | I32AtomicLoad8U
  | I32AtomicLoad16U
  | I64AtomicLoad8U
  | I64AtomicLoad16U
  | I64AtomicLoad32U
  | I32AtomicStore
  | I64AtomicStore
  | I32AtomicStore8
  | I32AtomicStore16
  | I64AtomicStore8
  | I64AtomicStore16
  | I64AtomicStore32
  | I32AtomicRmwAdd
  | I64AtomicRmwAdd
  | I32AtomicRmw8AddU
  | I32AtomicRmw16AddU
  | I64AtomicRmw8AddU
  | I64AtomicRmw16AddU
  | I64AtomicRmw32AddU
  | I32AtomicRmwSub
  | I64AtomicRmwSub
  | I32AtomicRmw8SubU
  | I32AtomicRmw16SubU
  | I64AtomicRmw8SubU
  | I64AtomicRmw16SubU
  | I64AtomicRmw32SubU
  | I32AtomicRmwAnd
  | I64AtomicRmwAnd
  | I32AtomicRmw8AndU
  | I32AtomicRmw16AndU
  | I64AtomicRmw8AndU
  | I64AtomicRmw16AndU
  | I64AtomicRmw32AndU
  | I32AtomicRmwOr
  | I64AtomicRmwOr
  | I32AtomicRmw8OrU
  | I32AtomicRmw16OrU
  | I64AtomicRmw8OrU
  | I64AtomicRmw16OrU
  | I64AtomicRmw32OrU
  | I32AtomicRmwXor
  | I64AtomicRmwXor
  | I32AtomicRmw8XorU
  | I32AtomicRmw16XorU
  | I64AtomicRmw8XorU
  | I64AtomicRmw16XorU
  | I64AtomicRmw32XorU
  | I32AtomicRmwXchg
  | I64AtomicRmwXchg
  | I32AtomicRmw8XchgU
  | I32AtomicRmw16XchgU
  | I64AtomicRmw8XchgU
  | I64AtomicRmw16XchgU
  | I64AtomicRmw32XchgU
  | I32AtomicRmwCmpxchg
  | I64AtomicRmwCmpxchg
  | I32AtomicRmw8CmpxchgU
  | I32AtomicRmw16CmpxchgU
  | I64AtomicRmw8CmpxchgU
  | I64AtomicRmw16CmpxchgU
  | I64AtomicRmw32CmpxchgU

type internal Op = Opcode

type internal Instruction = Opcode

type Operand =
  | I32 of uint32
  | I64 of uint64
  | F32 of BitVector
  | F64 of BitVector
  | V128 of BitVector * BitVector * BitVector * BitVector
  | Type of int
  | RefType of int
  | Index of uint32
  | Alignment of uint32
  | Address of uint32
  | LaneIndex of uint8
  | ConsistencyModel of uint8

type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | Operands of Operand list

/// Basic information obtained by parsing a WASM instruction.
[<NoComparison; CustomEquality>]
type InsInfo = {
  /// Address.
  Address: Addr
  /// Instruction length.
  NumBytes: uint32
  /// Opcode.
  Opcode: Opcode
  /// Operands.
  Operands: Operands
}
with
  override __.GetHashCode () =
    hash (__.Address,
          __.NumBytes,
          __.Opcode,
          __.Operands)
  override __.Equals (i) =
    match i with
    | :? InsInfo as i ->
      i.Address = __.Address
      && i.NumBytes = __.NumBytes
      && i.Opcode = __.Opcode
      && i.Operands = __.Operands
    | _ -> false

// vim: set tw=80 sts=2 sw=2:
