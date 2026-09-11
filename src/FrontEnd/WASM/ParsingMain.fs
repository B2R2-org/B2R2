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

module internal B2R2.FrontEnd.WASM.ParsingMain

open B2R2
open B2R2.FrontEnd.BinLifter

let isPrefix = function
  | 0xfc | 0xfd | 0xfe -> true
  | _ -> false

let private readIndex (span: ByteSpan) (reader: IBinReader) pos =
  let value, cnt = reader.ReadUInt32LEB128(span, pos)
  struct (value |> Index, pos + cnt)

let private readType (span: ByteSpan) (reader: IBinReader) pos =
  let t, cnt = reader.ReadInt32LEB128(span, pos)
  struct (t |> Type, pos + cnt)

let private readAddress (span: ByteSpan) (reader: IBinReader) pos =
  let address, cnt = reader.ReadUInt32LEB128(span, pos)
  struct (address |> Address, pos + cnt)

/// Reads a memarg. Bit 6 of the alignment field is the flag the multi-memory
/// proposal adds for an explicit memory index, which sits between the two
/// fields and belongs to neither of them; a decoder blind to it reads the
/// index as the offset and stops one field short of the instruction's end.
let private readMemArg (span: ByteSpan) (reader: IBinReader) pos =
  let align, cnt = reader.ReadUInt32LEB128(span, pos)
  let pos = pos + cnt
  if align &&& 0x40u = 0u then
    let struct (offset, pos) = readAddress span reader pos
    struct ([ Alignment align; offset ], pos)
  else
    let struct (memIndex, pos) = readIndex span reader pos
    let struct (offset, pos) = readAddress span reader pos
    struct ([ Alignment(align &&& 0x3fu); memIndex; offset ], pos)

let private readLane (span: ByteSpan) (reader: IBinReader) pos =
  let lane = reader.ReadUInt8(span, pos)
  struct (lane |> LaneIndex, pos + 1)

/// Reads the opcode that follows the 0xfd prefix. The spec encodes it as a
/// u32, so the SIMD space runs past one byte, and a non-canonical encoding of
/// a value that would fit in fewer bytes names no opcode at all.
let private readSimdOpcode (span: ByteSpan) (reader: IBinReader) =
  let sub, cnt = reader.ReadUInt32LEB128(span, 1)
  if cnt > 1 && span[cnt] = 0uy then raise ParsingFailureException else ()
  struct (int sub, 1 + cnt)

let private parseI32LEB128 (span: ByteSpan) (reader: IBinReader) pos opcode =
  let value, cnt = reader.ReadInt32LEB128(span, pos)
  struct (opcode, OneOperand(value |> I32), uint32 (pos + cnt))

let private parseI64LEB128 (span: ByteSpan) (reader: IBinReader) pos opcode =
  let value, cnt = reader.ReadInt64LEB128(span, pos)
  struct (opcode, OneOperand(value |> I64), uint32 (pos + cnt))

let private parseF32 (span: ByteSpan) (reader: IBinReader) pos opcode =
  let value = reader.ReadUInt32(span, pos)
  let value = BitVector(value, 32<rt>)
  struct (opcode, OneOperand(value |> F32), uint32 (pos + 4))

let private parseF64 (span: ByteSpan) (reader: IBinReader) pos opcode =
  let value = reader.ReadUInt64(span, pos)
  let value = BitVector(value, 64<rt>)
  struct (opcode, OneOperand(value |> F64), uint32 (pos + 8))

let private parseV128 (span: ByteSpan) (reader: IBinReader) pos opcode =
  let i32One = reader.ReadUInt32(span, pos)
  let i32One = BitVector(i32One, 32<rt>)
  let i32Two = reader.ReadUInt32(span, pos + 4)
  let i32Two = BitVector(i32Two, 32<rt>)
  let i32Three = reader.ReadUInt32(span, pos + 8)
  let i32Three = BitVector(i32Three, 32<rt>)
  let i32Four = reader.ReadUInt32(span, pos + 12)
  let i32Four = BitVector(i32Four, 32<rt>)
  let v128 = (i32One, i32Two, i32Three, i32Four) |> V128
  struct (opcode, OneOperand v128, uint32 pos + 16u)

(* XXX: readIndex *)
let private parseIndex (span: ByteSpan) (reader: IBinReader) pos opcode =
  let index, cnt = reader.ReadUInt32LEB128(span, pos)
  struct (opcode, OneOperand(index |> Index), uint32 (pos + cnt))

let private parseType (span: ByteSpan) (reader: IBinReader) pos opcode =
  let t, cnt = reader.ReadInt32LEB128(span, pos)
  struct (opcode, OneOperand(t |> Type), uint32 (pos + cnt))

let private parseRefType (span: ByteSpan) (reader: IBinReader) pos opcode =
  let t, cnt = reader.ReadInt32LEB128(span, pos)
  struct (opcode, OneOperand(t |> RefType), uint32 (pos + cnt))

let rec private parseTypes span reader pos cnt ret =
  if cnt = 0 then
    struct (List.rev ret, pos)
  else
    let struct (t, nextPos) = readType span reader pos
    parseTypes span reader nextPos (cnt - 1) (t :: ret)

let rec private parseIndices span reader pos cnt ret =
  if cnt = 0 then
    struct (List.rev ret, pos)
  else
    let struct (index, nextPos) = readIndex span reader pos
    parseIndices span reader nextPos (cnt - 1) (index :: ret)

let private parseCount (span: ByteSpan) (reader: IBinReader) pos =
  let cnt, bcnt = reader.ReadUInt32LEB128(span, pos)
  struct (int cnt, pos + bcnt)

/// Packs a list of operands into the arity-specific case that holds it.
let private toOperands = function
  | [ opr ] -> OneOperand opr
  | [ opr1; opr2 ] -> TwoOperands(opr1, opr2)
  | [ opr1; opr2; opr3 ] -> ThreeOperands(opr1, opr2, opr3)
  | oprs -> Operands oprs

let private parseMemArg span reader pos opcode =
  let struct (oprs, nextPos) = readMemArg span reader pos
  struct (opcode, toOperands oprs, uint32 nextPos)

let private parseMemArgLane span reader pos opcode =
  let struct (oprs, nextPos) = readMemArg span reader pos
  let struct (lane, nextPos) = readLane span reader nextPos
  struct (opcode, toOperands (oprs @ [ lane ]), uint32 nextPos)

let private parseSimdLane span reader pos opcode =
  let struct (lane, nextPos) = readLane span reader pos
  struct (opcode, OneOperand lane, uint32 nextPos)

let private parseAtomicFence (span: ByteSpan) (reader: IBinReader) pos opcode =
  let consistencyModel = reader.ReadUInt8(span, pos)
  let opr = OneOperand(consistencyModel |> ConsistencyModel)
  struct (opcode, opr, uint32 pos + 1u)

let private parseInstruction (span: ByteSpan) (reader: IBinReader) =
  match span[0] with
  | 0xfcuy ->
    match span[1] with
    | 0x00uy ->
      struct (I32TruncSatF32S, NoOperand, 2u)
    | 0x01uy ->
      struct (I32TruncSatF32U, NoOperand, 2u)
    | 0x02uy ->
      struct (I32TruncSatF64S, NoOperand, 2u)
    | 0x03uy ->
      struct (I32TruncSatF64U, NoOperand, 2u)
    | 0x04uy ->
      struct (I64TruncSatF32S, NoOperand, 2u)
    | 0x05uy ->
      struct (I64TruncSatF32U, NoOperand, 2u)
    | 0x06uy ->
      struct (I64TruncSatF64S, NoOperand, 2u)
    | 0x07uy ->
      struct (I64TruncSatF64U, NoOperand, 2u)
    | 0x08uy ->
      let struct (segment, pos) = readIndex span reader 2
      let struct (memIndex, pos) = readIndex span reader pos
      struct (MemoryInit, TwoOperands(segment, memIndex), uint32 pos)
    | 0x09uy ->
      parseIndex span reader 2 DataDrop
    | 0x0auy ->
      let struct (destMemIndex, pos) = readIndex span reader 2
      let struct (srcMemIndex, pos) = readIndex span reader pos
      struct (MemoryCopy, TwoOperands(destMemIndex, srcMemIndex), uint32 pos)
    | 0x0buy ->
      parseIndex span reader 2 MemoryFill
    | 0x0cuy ->
      let struct (segment, pos) = readIndex span reader 2
      let struct (tableIndex, pos) = readIndex span reader pos
      struct (TableInit, TwoOperands(segment, tableIndex), uint32 pos)
    | 0x0duy ->
      parseIndex span reader 2 ElemDrop
    | 0x0euy ->
      let struct (destTable, pos) = readIndex span reader 2
      let struct (srcTable, pos) = readIndex span reader pos
      struct (TableCopy, TwoOperands(destTable, srcTable), uint32 pos)
    | 0x0fuy ->
      parseIndex span reader 2 TableGrow
    | 0x10uy ->
      parseIndex span reader 2 TableSize
    | 0x11uy ->
      parseIndex span reader 2 TableFill
    | _ ->
      raise ParsingFailureException
  | 0xfduy ->
    let struct (sub, pos) = readSimdOpcode span reader
    match sub with
    | 0x00 -> parseMemArg span reader pos V128Load
    | 0x01 -> parseMemArg span reader pos V128Load8X8S
    | 0x02 -> parseMemArg span reader pos V128Load8X8U
    | 0x03 -> parseMemArg span reader pos V128Load16X4S
    | 0x04 -> parseMemArg span reader pos V128Load16X4U
    | 0x05 -> parseMemArg span reader pos V128Load32X2S
    | 0x06 -> parseMemArg span reader pos V128Load32X2U
    | 0x07 -> parseMemArg span reader pos V128Load8Splat
    | 0x08 -> parseMemArg span reader pos V128Load16Splat
    | 0x09 -> parseMemArg span reader pos V128Load32Splat
    | 0x0a -> parseMemArg span reader pos V128Load64Splat
    | 0x0b -> parseMemArg span reader pos V128Store
    | 0x0c -> parseV128 span reader pos V128Const
    | 0x0d -> parseV128 span reader pos I8X16Shuffle
    | 0x0e -> struct (I8X16Swizzle, NoOperand, uint32 pos)
    | 0x0f -> struct (I8X16Splat, NoOperand, uint32 pos)
    | 0x10 -> struct (I16X8Splat, NoOperand, uint32 pos)
    | 0x11 -> struct (I32X4Splat, NoOperand, uint32 pos)
    | 0x12 -> struct (I64X2Splat, NoOperand, uint32 pos)
    | 0x13 -> struct (F32X4Splat, NoOperand, uint32 pos)
    | 0x14 -> struct (F64X2Splat, NoOperand, uint32 pos)
    | 0x15 -> parseSimdLane span reader pos I8X16ExtractLaneS
    | 0x16 -> parseSimdLane span reader pos I8X16ExtractLaneU
    | 0x17 -> parseSimdLane span reader pos I8X16ReplaceLane
    | 0x18 -> parseSimdLane span reader pos I16X8ExtractLaneS
    | 0x19 -> parseSimdLane span reader pos I16X8ExtractLaneU
    | 0x1a -> parseSimdLane span reader pos I16X8ReplaceLane
    | 0x1b -> parseSimdLane span reader pos I32X4ExtractLane
    | 0x1c -> parseSimdLane span reader pos I32X4ReplaceLane
    | 0x1d -> parseSimdLane span reader pos I64X2ExtractLane
    | 0x1e -> parseSimdLane span reader pos I64X2ReplaceLane
    | 0x1f -> parseSimdLane span reader pos F32X4ExtractLane
    | 0x20 -> parseSimdLane span reader pos F32X4ReplaceLane
    | 0x21 -> parseSimdLane span reader pos F64X2ExtractLane
    | 0x22 -> parseSimdLane span reader pos F64X2ReplaceLane
    | 0x23 -> struct (I8X16Eq, NoOperand, uint32 pos)
    | 0x24 -> struct (I8X16Ne, NoOperand, uint32 pos)
    | 0x25 -> struct (I8X16LtS, NoOperand, uint32 pos)
    | 0x26 -> struct (I8X16LtU, NoOperand, uint32 pos)
    | 0x27 -> struct (I8X16GtS, NoOperand, uint32 pos)
    | 0x28 -> struct (I8X16GtU, NoOperand, uint32 pos)
    | 0x29 -> struct (I8X16LeS, NoOperand, uint32 pos)
    | 0x2a -> struct (I8X16LeU, NoOperand, uint32 pos)
    | 0x2b -> struct (I8X16GeS, NoOperand, uint32 pos)
    | 0x2c -> struct (I8X16GeU, NoOperand, uint32 pos)
    | 0x2d -> struct (I16X8Eq, NoOperand, uint32 pos)
    | 0x2e -> struct (I16X8Ne, NoOperand, uint32 pos)
    | 0x2f -> struct (I16X8LtS, NoOperand, uint32 pos)
    | 0x30 -> struct (I16X8LtU, NoOperand, uint32 pos)
    | 0x31 -> struct (I16X8GtS, NoOperand, uint32 pos)
    | 0x32 -> struct (I16X8GtU, NoOperand, uint32 pos)
    | 0x33 -> struct (I16X8LeS, NoOperand, uint32 pos)
    | 0x34 -> struct (I16X8LeU, NoOperand, uint32 pos)
    | 0x35 -> struct (I16X8GeS, NoOperand, uint32 pos)
    | 0x36 -> struct (I16X8GeU, NoOperand, uint32 pos)
    | 0x37 -> struct (I32X4Eq, NoOperand, uint32 pos)
    | 0x38 -> struct (I32X4Ne, NoOperand, uint32 pos)
    | 0x39 -> struct (I32X4LtS, NoOperand, uint32 pos)
    | 0x3a -> struct (I32X4LtU, NoOperand, uint32 pos)
    | 0x3b -> struct (I32X4GtS, NoOperand, uint32 pos)
    | 0x3c -> struct (I32X4GtU, NoOperand, uint32 pos)
    | 0x3d -> struct (I32X4LeS, NoOperand, uint32 pos)
    | 0x3e -> struct (I32X4LeU, NoOperand, uint32 pos)
    | 0x3f -> struct (I32X4GeS, NoOperand, uint32 pos)
    | 0x40 -> struct (I32X4GeU, NoOperand, uint32 pos)
    | 0x41 -> struct (F32X4Eq, NoOperand, uint32 pos)
    | 0x42 -> struct (F32X4Ne, NoOperand, uint32 pos)
    | 0x43 -> struct (F32X4Lt, NoOperand, uint32 pos)
    | 0x44 -> struct (F32X4Gt, NoOperand, uint32 pos)
    | 0x45 -> struct (F32X4Le, NoOperand, uint32 pos)
    | 0x46 -> struct (F32X4Ge, NoOperand, uint32 pos)
    | 0x47 -> struct (F64X2Eq, NoOperand, uint32 pos)
    | 0x48 -> struct (F64X2Ne, NoOperand, uint32 pos)
    | 0x49 -> struct (F64X2Lt, NoOperand, uint32 pos)
    | 0x4a -> struct (F64X2Gt, NoOperand, uint32 pos)
    | 0x4b -> struct (F64X2Le, NoOperand, uint32 pos)
    | 0x4c -> struct (F64X2Ge, NoOperand, uint32 pos)
    | 0x4d -> struct (V128Not, NoOperand, uint32 pos)
    | 0x4e -> struct (V128And, NoOperand, uint32 pos)
    | 0x4f -> struct (V128Andnot, NoOperand, uint32 pos)
    | 0x50 -> struct (V128Or, NoOperand, uint32 pos)
    | 0x51 -> struct (V128Xor, NoOperand, uint32 pos)
    | 0x52 -> struct (V128BitSelect, NoOperand, uint32 pos)
    | 0x53 -> struct (V128AnyTrue, NoOperand, uint32 pos)
    | 0x54 -> parseMemArgLane span reader pos V128Load8Lane
    | 0x55 -> parseMemArgLane span reader pos V128Load16Lane
    | 0x56 -> parseMemArgLane span reader pos V128Load32Lane
    | 0x57 -> parseMemArgLane span reader pos V128Load64Lane
    | 0x58 -> parseMemArgLane span reader pos V128Store8Lane
    | 0x59 -> parseMemArgLane span reader pos V128Store16Lane
    | 0x5a -> parseMemArgLane span reader pos V128Store32Lane
    | 0x5b -> parseMemArgLane span reader pos V128Store64Lane
    | 0x5c -> parseMemArg span reader pos V128Load32Zero
    | 0x5d -> parseMemArg span reader pos V128Load64Zero
    | 0x5e -> struct (F32X4DemoteF64X2Zero, NoOperand, uint32 pos)
    | 0x5f -> struct (F64X2PromoteLowF32X4, NoOperand, uint32 pos)
    | 0x60 -> struct (I8X16Abs, NoOperand, uint32 pos)
    | 0x61 -> struct (I8X16Neg, NoOperand, uint32 pos)
    | 0x62 -> struct (I8X16Popcnt, NoOperand, uint32 pos)
    | 0x63 -> struct (I8X16AllTrue, NoOperand, uint32 pos)
    | 0x64 -> struct (I8X16Bitmask, NoOperand, uint32 pos)
    | 0x65 -> struct (I8X16NarrowI16X8S, NoOperand, uint32 pos)
    | 0x66 -> struct (I8X16NarrowI16X8U, NoOperand, uint32 pos)
    | 0x6b -> struct (I8X16Shl, NoOperand, uint32 pos)
    | 0x6c -> struct (I8X16ShrS, NoOperand, uint32 pos)
    | 0x6d -> struct (I8X16ShrU, NoOperand, uint32 pos)
    | 0x6e -> struct (I8X16Add, NoOperand, uint32 pos)
    | 0x6f -> struct (I8X16AddSatS, NoOperand, uint32 pos)
    | 0x70 -> struct (I8X16AddSatU, NoOperand, uint32 pos)
    | 0x71 -> struct (I8X16Sub, NoOperand, uint32 pos)
    | 0x72 -> struct (I8X16SubSatS, NoOperand, uint32 pos)
    | 0x73 -> struct (I8X16SubSatU, NoOperand, uint32 pos)
    | 0x76 -> struct (I8X16MinS, NoOperand, uint32 pos)
    | 0x77 -> struct (I8X16MinU, NoOperand, uint32 pos)
    | 0x78 -> struct (I8X16MaxS, NoOperand, uint32 pos)
    | 0x79 -> struct (I8X16MaxU, NoOperand, uint32 pos)
    | 0x7b -> struct (I8X16AvgrU, NoOperand, uint32 pos)
    | 0x7c -> struct (I16X8ExtaddPairwiseI8X16S, NoOperand, uint32 pos)
    | 0x7d -> struct (I16X8ExtaddPairwiseI8X16U, NoOperand, uint32 pos)
    | 0x7e -> struct (I32X4ExtaddPairwiseI16X8S, NoOperand, uint32 pos)
    | 0x7f -> struct (I32X4ExtaddPairwiseI16X8U, NoOperand, uint32 pos)
    | 0x80 -> struct (I16X8Abs, NoOperand, uint32 pos)
    | 0x81 -> struct (I16X8Neg, NoOperand, uint32 pos)
    | 0x82 -> struct (I16X8Q15mulrSatS, NoOperand, uint32 pos)
    | 0x83 -> struct (I16X8AllTrue, NoOperand, uint32 pos)
    | 0x84 -> struct (I16X8Bitmask, NoOperand, uint32 pos)
    | 0x85 -> struct (I16X8NarrowI32X4S, NoOperand, uint32 pos)
    | 0x86 -> struct (I16X8NarrowI32X4U, NoOperand, uint32 pos)
    | 0x87 -> struct (I16X8ExtendLowI8X16S, NoOperand, uint32 pos)
    | 0x88 -> struct (I16X8ExtendHighI8X16S, NoOperand, uint32 pos)
    | 0x89 -> struct (I16X8ExtendLowI8X16U, NoOperand, uint32 pos)
    | 0x8a -> struct (I16X8ExtendHighI8X16U, NoOperand, uint32 pos)
    | 0x8b -> struct (I16X8Shl, NoOperand, uint32 pos)
    | 0x8c -> struct (I16X8ShrS, NoOperand, uint32 pos)
    | 0x8d -> struct (I16X8ShrU, NoOperand, uint32 pos)
    | 0x8e -> struct (I16X8Add, NoOperand, uint32 pos)
    | 0x8f -> struct (I16X8AddSatS, NoOperand, uint32 pos)
    | 0x90 -> struct (I16X8AddSatU, NoOperand, uint32 pos)
    | 0x91 -> struct (I16X8Sub, NoOperand, uint32 pos)
    | 0x92 -> struct (I16X8SubSatS, NoOperand, uint32 pos)
    | 0x93 -> struct (I16X8SubSatU, NoOperand, uint32 pos)
    | 0x95 -> struct (I16X8Mul, NoOperand, uint32 pos)
    | 0x96 -> struct (I16X8MinS, NoOperand, uint32 pos)
    | 0x97 -> struct (I16X8MinU, NoOperand, uint32 pos)
    | 0x98 -> struct (I16X8MaxS, NoOperand, uint32 pos)
    | 0x99 -> struct (I16X8MaxU, NoOperand, uint32 pos)
    | 0x9b -> struct (I16X8AvgrU, NoOperand, uint32 pos)
    | 0x9c -> struct (I16X8ExtmulLowI8X16S, NoOperand, uint32 pos)
    | 0x9d -> struct (I16X8ExtmulHighI8X16S, NoOperand, uint32 pos)
    | 0x9e -> struct (I16X8ExtmulLowI8X16U, NoOperand, uint32 pos)
    | 0x9f -> struct (I16X8ExtmulHighI8X16U, NoOperand, uint32 pos)
    | 0xa0 -> struct (I32X4Abs, NoOperand, uint32 pos)
    | 0xa1 -> struct (I32X4Neg, NoOperand, uint32 pos)
    | 0xa3 -> struct (I32X4AllTrue, NoOperand, uint32 pos)
    | 0xa4 -> struct (I32X4Bitmask, NoOperand, uint32 pos)
    | 0xa7 -> struct (I32X4ExtendLowI16X8S, NoOperand, uint32 pos)
    | 0xa8 -> struct (I32X4ExtendHighI16X8S, NoOperand, uint32 pos)
    | 0xa9 -> struct (I32X4ExtendLowI16X8U, NoOperand, uint32 pos)
    | 0xaa -> struct (I32X4ExtendHighI16X8U, NoOperand, uint32 pos)
    | 0xab -> struct (I32X4Shl, NoOperand, uint32 pos)
    | 0xac -> struct (I32X4ShrS, NoOperand, uint32 pos)
    | 0xad -> struct (I32X4ShrU, NoOperand, uint32 pos)
    | 0xae -> struct (I32X4Add, NoOperand, uint32 pos)
    | 0xb1 -> struct (I32X4Sub, NoOperand, uint32 pos)
    | 0xb5 -> struct (I32X4Mul, NoOperand, uint32 pos)
    | 0xb6 -> struct (I32X4MinS, NoOperand, uint32 pos)
    | 0xb7 -> struct (I32X4MinU, NoOperand, uint32 pos)
    | 0xb8 -> struct (I32X4MaxS, NoOperand, uint32 pos)
    | 0xb9 -> struct (I32X4MaxU, NoOperand, uint32 pos)
    | 0xba -> struct (I32X4DotI16X8S, NoOperand, uint32 pos)
    | 0xbc -> struct (I32X4ExtmulLowI16X8S, NoOperand, uint32 pos)
    | 0xbd -> struct (I32X4ExtmulHighI16X8S, NoOperand, uint32 pos)
    | 0xbe -> struct (I32X4ExtmulLowI16X8U, NoOperand, uint32 pos)
    | 0xbf -> struct (I32X4ExtmulHighI16X8U, NoOperand, uint32 pos)
    | 0xc0 -> struct (I64X2Abs, NoOperand, uint32 pos)
    | 0xc1 -> struct (I64X2Neg, NoOperand, uint32 pos)
    | 0xc3 -> struct (I64X2AllTrue, NoOperand, uint32 pos)
    | 0xc4 -> struct (I64X2Bitmask, NoOperand, uint32 pos)
    | 0xc7 -> struct (I64X2ExtendLowI32X4S, NoOperand, uint32 pos)
    | 0xc8 -> struct (I64X2ExtendHighI32X4S, NoOperand, uint32 pos)
    | 0xc9 -> struct (I64X2ExtendLowI32X4U, NoOperand, uint32 pos)
    | 0xca -> struct (I64X2ExtendHighI32X4U, NoOperand, uint32 pos)
    | 0xcb -> struct (I64X2Shl, NoOperand, uint32 pos)
    | 0xcc -> struct (I64X2ShrS, NoOperand, uint32 pos)
    | 0xcd -> struct (I64X2ShrU, NoOperand, uint32 pos)
    | 0xce -> struct (I64X2Add, NoOperand, uint32 pos)
    | 0xd1 -> struct (I64X2Sub, NoOperand, uint32 pos)
    | 0xd5 -> struct (I64X2Mul, NoOperand, uint32 pos)
    | 0xd6 -> struct (I64X2Eq, NoOperand, uint32 pos)
    | 0xd7 -> struct (I64X2Ne, NoOperand, uint32 pos)
    | 0xd8 -> struct (I64X2LtS, NoOperand, uint32 pos)
    | 0xd9 -> struct (I64X2GtS, NoOperand, uint32 pos)
    | 0xda -> struct (I64X2LeS, NoOperand, uint32 pos)
    | 0xdb -> struct (I64X2GeS, NoOperand, uint32 pos)
    | 0xdc -> struct (I64X2ExtmulLowI32X4S, NoOperand, uint32 pos)
    | 0xdd -> struct (I64X2ExtmulHighI32X4S, NoOperand, uint32 pos)
    | 0xde -> struct (I64X2ExtmulLowI32X4U, NoOperand, uint32 pos)
    | 0xdf -> struct (I64X2ExtmulHighI32X4U, NoOperand, uint32 pos)
    | 0x67 -> struct (F32X4Ceil, NoOperand, uint32 pos)
    | 0x68 -> struct (F32X4Floor, NoOperand, uint32 pos)
    | 0x69 -> struct (F32X4Trunc, NoOperand, uint32 pos)
    | 0x6a -> struct (F32X4Nearest, NoOperand, uint32 pos)
    | 0x74 -> struct (F64X2Ceil, NoOperand, uint32 pos)
    | 0x75 -> struct (F64X2Floor, NoOperand, uint32 pos)
    | 0x7a -> struct (F64X2Trunc, NoOperand, uint32 pos)
    | 0x94 -> struct (F64X2Nearest, NoOperand, uint32 pos)
    | 0xe0 -> struct (F32X4Abs, NoOperand, uint32 pos)
    | 0xe1 -> struct (F32X4Neg, NoOperand, uint32 pos)
    | 0xe3 -> struct (F32X4Sqrt, NoOperand, uint32 pos)
    | 0xe4 -> struct (F32X4Add, NoOperand, uint32 pos)
    | 0xe5 -> struct (F32X4Sub, NoOperand, uint32 pos)
    | 0xe6 -> struct (F32X4Mul, NoOperand, uint32 pos)
    | 0xe7 -> struct (F32X4Div, NoOperand, uint32 pos)
    | 0xe8 -> struct (F32X4Min, NoOperand, uint32 pos)
    | 0xe9 -> struct (F32X4Max, NoOperand, uint32 pos)
    | 0xea -> struct (F32X4PMin, NoOperand, uint32 pos)
    | 0xeb -> struct (F32X4PMax, NoOperand, uint32 pos)
    | 0xec -> struct (F64X2Abs, NoOperand, uint32 pos)
    | 0xed -> struct (F64X2Neg, NoOperand, uint32 pos)
    | 0xef -> struct (F64X2Sqrt, NoOperand, uint32 pos)
    | 0xf0 -> struct (F64X2Add, NoOperand, uint32 pos)
    | 0xf1 -> struct (F64X2Sub, NoOperand, uint32 pos)
    | 0xf2 -> struct (F64X2Mul, NoOperand, uint32 pos)
    | 0xf3 -> struct (F64X2Div, NoOperand, uint32 pos)
    | 0xf4 -> struct (F64X2Min, NoOperand, uint32 pos)
    | 0xf5 -> struct (F64X2Max, NoOperand, uint32 pos)
    | 0xf6 -> struct (F64X2PMin, NoOperand, uint32 pos)
    | 0xf7 -> struct (F64X2PMax, NoOperand, uint32 pos)
    | 0xf8 -> struct (I32X4TruncSatF32X4S, NoOperand, uint32 pos)
    | 0xf9 -> struct (I32X4TruncSatF32X4U, NoOperand, uint32 pos)
    | 0xfa -> struct (F32X4ConvertI32X4S, NoOperand, uint32 pos)
    | 0xfb -> struct (F32X4ConvertI32X4U, NoOperand, uint32 pos)
    | 0xfc -> struct (I32X4TruncSatF64X2SZero, NoOperand, uint32 pos)
    | 0xfd -> struct (I32X4TruncSatF64X2UZero, NoOperand, uint32 pos)
    | 0xfe -> struct (F64X2ConvertLowI32X4S, NoOperand, uint32 pos)
    | 0xff -> struct (F64X2ConvertLowI32X4U, NoOperand, uint32 pos)
    | 0x100 -> struct (I8X16RelaxedSwizzle, NoOperand, uint32 pos)
    | 0x101 -> struct (I32X4RelaxedTruncF32X4S, NoOperand, uint32 pos)
    | 0x102 -> struct (I32X4RelaxedTruncF32X4U, NoOperand, uint32 pos)
    | 0x103 -> struct (I32X4RelaxedTruncF64X2SZero, NoOperand, uint32 pos)
    | 0x104 -> struct (I32X4RelaxedTruncF64X2UZero, NoOperand, uint32 pos)
    | 0x105 -> struct (F32X4RelaxedMadd, NoOperand, uint32 pos)
    | 0x106 -> struct (F32X4RelaxedNmadd, NoOperand, uint32 pos)
    | 0x107 -> struct (F64X2RelaxedMadd, NoOperand, uint32 pos)
    | 0x108 -> struct (F64X2RelaxedNmadd, NoOperand, uint32 pos)
    | 0x109 -> struct (I8X16RelaxedLaneselect, NoOperand, uint32 pos)
    | 0x10a -> struct (I16X8RelaxedLaneselect, NoOperand, uint32 pos)
    | 0x10b -> struct (I32X4RelaxedLaneselect, NoOperand, uint32 pos)
    | 0x10c -> struct (I64X2RelaxedLaneselect, NoOperand, uint32 pos)
    | 0x10d -> struct (F32X4RelaxedMin, NoOperand, uint32 pos)
    | 0x10e -> struct (F32X4RelaxedMax, NoOperand, uint32 pos)
    | 0x10f -> struct (F64X2RelaxedMin, NoOperand, uint32 pos)
    | 0x110 -> struct (F64X2RelaxedMax, NoOperand, uint32 pos)
    | 0x111 -> struct (I16X8RelaxedQ15mulrS, NoOperand, uint32 pos)
    | 0x112 -> struct (I16X8DotI8X16I7X16S, NoOperand, uint32 pos)
    | 0x113 -> struct (I32X4DotI8X16I7X16AddS, NoOperand, uint32 pos)
    | _ -> raise ParsingFailureException
  | 0xfeuy ->
    match span[1] with
    | 0x00uy -> parseMemArg span reader 2 MemoryAtomicNotify
    | 0x01uy -> parseMemArg span reader 2 MemoryAtomicWait32
    | 0x02uy -> parseMemArg span reader 2 MemoryAtomicWait64
    | 0x03uy -> parseAtomicFence span reader 2 AtomicFence
    | 0x10uy -> parseMemArg span reader 2 I32AtomicLoad
    | 0x11uy -> parseMemArg span reader 2 I64AtomicLoad
    | 0x12uy -> parseMemArg span reader 2 I32AtomicLoad8U
    | 0x13uy -> parseMemArg span reader 2 I32AtomicLoad16U
    | 0x14uy -> parseMemArg span reader 2 I64AtomicLoad8U
    | 0x15uy -> parseMemArg span reader 2 I64AtomicLoad16U
    | 0x16uy -> parseMemArg span reader 2 I64AtomicLoad32U
    | 0x17uy -> parseMemArg span reader 2 I32AtomicStore
    | 0x18uy -> parseMemArg span reader 2 I64AtomicStore
    | 0x19uy -> parseMemArg span reader 2 I32AtomicStore8
    | 0x1auy -> parseMemArg span reader 2 I32AtomicStore16
    | 0x1buy -> parseMemArg span reader 2 I64AtomicStore8
    | 0x1cuy -> parseMemArg span reader 2 I64AtomicStore16
    | 0x1duy -> parseMemArg span reader 2 I64AtomicStore32
    | 0x1euy -> parseMemArg span reader 2 I32AtomicRmwAdd
    | 0x1fuy -> parseMemArg span reader 2 I64AtomicRmwAdd
    | 0x20uy -> parseMemArg span reader 2 I32AtomicRmw8AddU
    | 0x21uy -> parseMemArg span reader 2 I32AtomicRmw16AddU
    | 0x22uy -> parseMemArg span reader 2 I64AtomicRmw8AddU
    | 0x23uy -> parseMemArg span reader 2 I64AtomicRmw16AddU
    | 0x24uy -> parseMemArg span reader 2 I64AtomicRmw32AddU
    | 0x25uy -> parseMemArg span reader 2 I32AtomicRmwSub
    | 0x26uy -> parseMemArg span reader 2 I64AtomicRmwSub
    | 0x27uy -> parseMemArg span reader 2 I32AtomicRmw8SubU
    | 0x28uy -> parseMemArg span reader 2 I32AtomicRmw16SubU
    | 0x29uy -> parseMemArg span reader 2 I64AtomicRmw8SubU
    | 0x2auy -> parseMemArg span reader 2 I64AtomicRmw16SubU
    | 0x2buy -> parseMemArg span reader 2 I64AtomicRmw32SubU
    | 0x2cuy -> parseMemArg span reader 2 I32AtomicRmwAnd
    | 0x2duy -> parseMemArg span reader 2 I64AtomicRmwAnd
    | 0x2euy -> parseMemArg span reader 2 I32AtomicRmw8AndU
    | 0x2fuy -> parseMemArg span reader 2 I32AtomicRmw16AndU
    | 0x30uy -> parseMemArg span reader 2 I64AtomicRmw8AndU
    | 0x31uy -> parseMemArg span reader 2 I64AtomicRmw16AndU
    | 0x32uy -> parseMemArg span reader 2 I64AtomicRmw32AndU
    | 0x33uy -> parseMemArg span reader 2 I32AtomicRmwOr
    | 0x34uy -> parseMemArg span reader 2 I64AtomicRmwOr
    | 0x35uy -> parseMemArg span reader 2 I32AtomicRmw8OrU
    | 0x36uy -> parseMemArg span reader 2 I32AtomicRmw16OrU
    | 0x37uy -> parseMemArg span reader 2 I64AtomicRmw8OrU
    | 0x38uy -> parseMemArg span reader 2 I64AtomicRmw16OrU
    | 0x39uy -> parseMemArg span reader 2 I64AtomicRmw32OrU
    | 0x3auy -> parseMemArg span reader 2 I32AtomicRmwXor
    | 0x3buy -> parseMemArg span reader 2 I64AtomicRmwXor
    | 0x3cuy -> parseMemArg span reader 2 I32AtomicRmw8XorU
    | 0x3duy -> parseMemArg span reader 2 I32AtomicRmw16XorU
    | 0x3euy -> parseMemArg span reader 2 I64AtomicRmw8XorU
    | 0x3fuy -> parseMemArg span reader 2 I64AtomicRmw16XorU
    | 0x40uy -> parseMemArg span reader 2 I64AtomicRmw32XorU
    | 0x41uy -> parseMemArg span reader 2 I32AtomicRmwXchg
    | 0x42uy -> parseMemArg span reader 2 I64AtomicRmwXchg
    | 0x43uy -> parseMemArg span reader 2 I32AtomicRmw8XchgU
    | 0x44uy -> parseMemArg span reader 2 I32AtomicRmw16XchgU
    | 0x45uy -> parseMemArg span reader 2 I64AtomicRmw8XchgU
    | 0x46uy -> parseMemArg span reader 2 I64AtomicRmw16XchgU
    | 0x47uy -> parseMemArg span reader 2 I64AtomicRmw32XchgU
    | 0x48uy -> parseMemArg span reader 2 I32AtomicRmwCmpxchg
    | 0x49uy -> parseMemArg span reader 2 I64AtomicRmwCmpxchg
    | 0x4auy -> parseMemArg span reader 2 I32AtomicRmw8CmpxchgU
    | 0x4buy -> parseMemArg span reader 2 I32AtomicRmw16CmpxchgU
    | 0x4cuy -> parseMemArg span reader 2 I64AtomicRmw8CmpxchgU
    | 0x4duy -> parseMemArg span reader 2 I64AtomicRmw16CmpxchgU
    | 0x4euy -> parseMemArg span reader 2 I64AtomicRmw32CmpxchgU
    | _ -> raise ParsingFailureException
  | 0x00uy ->
    struct (Unreachable, NoOperand, 1u)
  | 0x01uy ->
    struct (Nop, NoOperand, 1u)
  | 0x02uy ->
    parseType span reader 1 Block
  | 0x03uy ->
    parseType span reader 1 Loop
  | 0x04uy ->
    parseType span reader 1 If
  | 0x05uy ->
    struct (Else, NoOperand, 1u)
  | 0x06uy ->
    parseType span reader 1 Try
  | 0x07uy ->
    parseIndex span reader 1 Catch
  | 0x08uy ->
    parseIndex span reader 1 Throw
  | 0x09uy ->
    parseIndex span reader 1 Rethrow
  | 0x0buy ->
    struct (End, NoOperand, 1u)
  | 0x0cuy ->
    parseIndex span reader 1 Br
  | 0x0duy ->
    parseIndex span reader 1 BrIf
  | 0x0euy ->
    let struct (count, pos) = parseCount span reader 1
    let struct (labels, pos) = parseIndices span reader pos count []
    let struct (dflt, pos) = readIndex span reader pos
    struct (BrTable, Operands(labels @ [ dflt ]), uint32 pos)
  | 0x0fuy ->
    struct (Return, NoOperand, 1u)
  | 0x10uy ->
    parseIndex span reader 1 Call
  | 0x11uy ->
    let struct (sigIndex, pos) = readIndex span reader 1
    let struct (tableIndex, pos) = readIndex span reader pos
    struct (CallIndirect, TwoOperands(sigIndex, tableIndex), uint32 pos)
  | 0x12uy ->
    parseIndex span reader 1 ReturnCall
  | 0x13uy ->
    let struct (sigIndex, pos) = readIndex span reader 1
    let struct (tableIndex, pos) = readIndex span reader pos
    struct (ReturnCallIndirect, TwoOperands(sigIndex, tableIndex), uint32 pos)
  | 0x14uy ->
    struct (CallRef, NoOperand, 1u)
  | 0x18uy ->
    parseIndex span reader 1 Delegate
  | 0x19uy ->
    struct (CatchAll, NoOperand, 1u)
  | 0x1auy ->
    struct (Drop, NoOperand, 1u)
  | 0x1buy ->
    struct (Select, NoOperand, 1u)
  | 0x1cuy ->
    let struct (cnt, pos) = parseCount span reader 1
    let struct (operands, pos) = parseTypes span reader pos cnt []
    struct (SelectT, Operands operands, uint32 pos)
  | 0x20uy ->
    parseIndex span reader 1 LocalGet
  | 0x21uy ->
    parseIndex span reader 1 LocalSet
  | 0x22uy ->
    parseIndex span reader 1 LocalTee
  | 0x23uy ->
    parseIndex span reader 1 GlobalGet
  | 0x24uy ->
    parseIndex span reader 1 GlobalSet
  | 0x28uy ->
    parseMemArg span reader 1 I32Load
  | 0x29uy ->
    parseMemArg span reader 1 I64Load
  | 0x2auy ->
    parseMemArg span reader 1 F32Load
  | 0x2buy ->
    parseMemArg span reader 1 F64Load
  | 0x2cuy ->
    parseMemArg span reader 1 I32Load8S
  | 0x2duy ->
    parseMemArg span reader 1 I32Load8U
  | 0x2euy ->
    parseMemArg span reader 1 I32Load16S
  | 0x2fuy ->
    parseMemArg span reader 1 I32Load16U
  | 0x30uy ->
    parseMemArg span reader 1 I64Load8S
  | 0x31uy ->
    parseMemArg span reader 1 I64Load8U
  | 0x32uy ->
    parseMemArg span reader 1 I64Load16S
  | 0x33uy ->
    parseMemArg span reader 1 I64Load16U
  | 0x34uy ->
    parseMemArg span reader 1 I64Load32S
  | 0x35uy ->
    parseMemArg span reader 1 I64Load32U
  | 0x36uy ->
    parseMemArg span reader 1 I32Store
  | 0x37uy ->
    parseMemArg span reader 1 I64Store
  | 0x38uy ->
    parseMemArg span reader 1 F32Store
  | 0x39uy ->
    parseMemArg span reader 1 F64Store
  | 0x3auy ->
    parseMemArg span reader 1 I32Store8
  | 0x3buy ->
    parseMemArg span reader 1 I32Store16
  | 0x3cuy ->
    parseMemArg span reader 1 I64Store8
  | 0x3duy ->
    parseMemArg span reader 1 I64Store16
  | 0x3euy ->
    parseMemArg span reader 1 I64Store32
  | 0x3fuy ->
    parseIndex span reader 1 MemorySize
  | 0x40uy ->
    parseIndex span reader 1 MemoryGrow
  | 0x41uy ->
    parseI32LEB128 span reader 1 I32Const
  | 0x42uy ->
    parseI64LEB128 span reader 1 I64Const
  | 0x43uy ->
    parseF32 span reader 1 F32Const
  | 0x44uy ->
    parseF64 span reader 1 F64Const
  | 0x45uy ->
    struct (I32Eqz, NoOperand, 1u)
  | 0x46uy ->
    struct (I32Eq, NoOperand, 1u)
  | 0x47uy ->
    struct (I32Ne, NoOperand, 1u)
  | 0x48uy ->
    struct (I32LtS, NoOperand, 1u)
  | 0x49uy ->
    struct (I32LtU, NoOperand, 1u)
  | 0x4auy ->
    struct (I32GtS, NoOperand, 1u)
  | 0x4buy ->
    struct (I32GtU, NoOperand, 1u)
  | 0x4cuy ->
    struct (I32LeS, NoOperand, 1u)
  | 0x4duy ->
    struct (I32LeU, NoOperand, 1u)
  | 0x4euy ->
    struct (I32GeS, NoOperand, 1u)
  | 0x4fuy ->
    struct (I32GeU, NoOperand, 1u)
  | 0x50uy ->
    struct (I64Eqz, NoOperand, 1u)
  | 0x51uy ->
    struct (I64Eq, NoOperand, 1u)
  | 0x52uy ->
    struct (I64Ne, NoOperand, 1u)
  | 0x53uy ->
    struct (I64LtS, NoOperand, 1u)
  | 0x54uy ->
    struct (I64LtU, NoOperand, 1u)
  | 0x55uy ->
    struct (I64GtS, NoOperand, 1u)
  | 0x56uy ->
    struct (I64GtU, NoOperand, 1u)
  | 0x57uy ->
    struct (I64LeS, NoOperand, 1u)
  | 0x58uy ->
    struct (I64LeU, NoOperand, 1u)
  | 0x59uy ->
    struct (I64GeS, NoOperand, 1u)
  | 0x5auy ->
    struct (I64GeU, NoOperand, 1u)
  | 0x5buy ->
    struct (F32Eq, NoOperand, 1u)
  | 0x5cuy ->
    struct (F32Ne, NoOperand, 1u)
  | 0x5duy ->
    struct (F32Lt, NoOperand, 1u)
  | 0x5euy ->
    struct (F32Gt, NoOperand, 1u)
  | 0x5fuy ->
    struct (F32Le, NoOperand, 1u)
  | 0x60uy ->
    struct (F32Ge, NoOperand, 1u)
  | 0x61uy ->
    struct (F64Eq, NoOperand, 1u)
  | 0x62uy ->
    struct (F64Ne, NoOperand, 1u)
  | 0x63uy ->
    struct (F64Lt, NoOperand, 1u)
  | 0x64uy ->
    struct (F64Gt, NoOperand, 1u)
  | 0x65uy ->
    struct (F64Le, NoOperand, 1u)
  | 0x66uy ->
    struct (F64Ge, NoOperand, 1u)
  | 0x67uy ->
    struct (I32Clz, NoOperand, 1u)
  | 0x68uy ->
    struct (I32Ctz, NoOperand, 1u)
  | 0x69uy ->
    struct (I32Popcnt, NoOperand, 1u)
  | 0x6auy ->
    struct (I32Add, NoOperand, 1u)
  | 0x6buy ->
    struct (I32Sub, NoOperand, 1u)
  | 0x6cuy ->
    struct (I32Mul, NoOperand, 1u)
  | 0x6duy ->
    struct (I32DivS, NoOperand, 1u)
  | 0x6euy ->
    struct (I32DivU, NoOperand, 1u)
  | 0x6fuy ->
    struct (I32RemS, NoOperand, 1u)
  | 0x70uy ->
    struct (I32RemU, NoOperand, 1u)
  | 0x71uy ->
    struct (I32And, NoOperand, 1u)
  | 0x72uy ->
    struct (I32Or, NoOperand, 1u)
  | 0x73uy ->
    struct (I32Xor, NoOperand, 1u)
  | 0x74uy ->
    struct (I32Shl, NoOperand, 1u)
  | 0x75uy ->
    struct (I32ShrS, NoOperand, 1u)
  | 0x76uy ->
    struct (I32ShrU, NoOperand, 1u)
  | 0x77uy ->
    struct (I32Rotl, NoOperand, 1u)
  | 0x78uy ->
    struct (I32Rotr, NoOperand, 1u)
  | 0x79uy ->
    struct (I64Clz, NoOperand, 1u)
  | 0x7auy ->
    struct (I64Ctz, NoOperand, 1u)
  | 0x7buy ->
    struct (I64Popcnt, NoOperand, 1u)
  | 0x7cuy ->
    struct (I64Add, NoOperand, 1u)
  | 0x7duy ->
    struct (I64Sub, NoOperand, 1u)
  | 0x7euy ->
    struct (I64Mul, NoOperand, 1u)
  | 0x7fuy ->
    struct (I64DivS, NoOperand, 1u)
  | 0x80uy ->
    struct (I64DivU, NoOperand, 1u)
  | 0x81uy ->
    struct (I64RemS, NoOperand, 1u)
  | 0x82uy ->
    struct (I64RemU, NoOperand, 1u)
  | 0x83uy ->
    struct (I64And, NoOperand, 1u)
  | 0x84uy ->
    struct (I64Or, NoOperand, 1u)
  | 0x85uy ->
    struct (I64Xor, NoOperand, 1u)
  | 0x86uy ->
    struct (I64Shl, NoOperand, 1u)
  | 0x87uy ->
    struct (I64ShrS, NoOperand, 1u)
  | 0x88uy ->
    struct (I64ShrU, NoOperand, 1u)
  | 0x89uy ->
    struct (I64Rotl, NoOperand, 1u)
  | 0x8auy ->
    struct (I64Rotr, NoOperand, 1u)
  | 0x8buy ->
    struct (F32Abs, NoOperand, 1u)
  | 0x8cuy ->
    struct (F32Neg, NoOperand, 1u)
  | 0x8duy ->
    struct (F32Ceil, NoOperand, 1u)
  | 0x8euy ->
    struct (F32Floor, NoOperand, 1u)
  | 0x8fuy ->
    struct (F32Trunc, NoOperand, 1u)
  | 0x90uy ->
    struct (F32Nearest, NoOperand, 1u)
  | 0x91uy ->
    struct (F32Sqrt, NoOperand, 1u)
  | 0x92uy ->
    struct (F32Add, NoOperand, 1u)
  | 0x93uy ->
    struct (F32Sub, NoOperand, 1u)
  | 0x94uy ->
    struct (F32Mul, NoOperand, 1u)
  | 0x95uy ->
    struct (F32Div, NoOperand, 1u)
  | 0x96uy ->
    struct (F32Min, NoOperand, 1u)
  | 0x97uy ->
    struct (F32Max, NoOperand, 1u)
  | 0x98uy ->
    struct (F32Copysign, NoOperand, 1u)
  | 0x99uy ->
    struct (F64Abs, NoOperand, 1u)
  | 0x9auy ->
    struct (F64Neg, NoOperand, 1u)
  | 0x9buy ->
    struct (F64Ceil, NoOperand, 1u)
  | 0x9cuy ->
    struct (F64Floor, NoOperand, 1u)
  | 0x9duy ->
    struct (F64Trunc, NoOperand, 1u)
  | 0x9euy ->
    struct (F64Nearest, NoOperand, 1u)
  | 0x9fuy ->
    struct (F64Sqrt, NoOperand, 1u)
  | 0xa0uy ->
    struct (F64Add, NoOperand, 1u)
  | 0xa1uy ->
    struct (F64Sub, NoOperand, 1u)
  | 0xa2uy ->
    struct (F64Mul, NoOperand, 1u)
  | 0xa3uy ->
    struct (F64Div, NoOperand, 1u)
  | 0xa4uy ->
    struct (F64Min, NoOperand, 1u)
  | 0xa5uy ->
    struct (F64Max, NoOperand, 1u)
  | 0xa6uy ->
    struct (F64Copysign, NoOperand, 1u)
  | 0xa7uy ->
    struct (I32WrapI64, NoOperand, 1u)
  | 0xa8uy ->
    struct (I32TruncF32S, NoOperand, 1u)
  | 0xa9uy ->
    struct (I32TruncF32U, NoOperand, 1u)
  | 0xaauy ->
    struct (I32TruncF64S, NoOperand, 1u)
  | 0xabuy ->
    struct (I32TruncF64U, NoOperand, 1u)
  | 0xacuy ->
    struct (I64ExtendI32S, NoOperand, 1u)
  | 0xaduy ->
    struct (I64ExtendI32U, NoOperand, 1u)
  | 0xaeuy ->
    struct (I64TruncF32S, NoOperand, 1u)
  | 0xafuy ->
    struct (I64TruncF32U, NoOperand, 1u)
  | 0xb0uy ->
    struct (I64TruncF64S, NoOperand, 1u)
  | 0xb1uy ->
    struct (I64TruncF64U, NoOperand, 1u)
  | 0xb2uy ->
    struct (F32ConvertI32S, NoOperand, 1u)
  | 0xb3uy ->
    struct (F32ConvertI32U, NoOperand, 1u)
  | 0xb4uy ->
    struct (F32ConvertI64S, NoOperand, 1u)
  | 0xb5uy ->
    struct (F32ConvertI64U, NoOperand, 1u)
  | 0xb6uy ->
    struct (F32DemoteF64, NoOperand, 1u)
  | 0xb7uy ->
    struct (F64ConvertI32S, NoOperand, 1u)
  | 0xb8uy ->
    struct (F64ConvertI32U, NoOperand, 1u)
  | 0xb9uy ->
    struct (F64ConvertI64S, NoOperand, 1u)
  | 0xbauy ->
    struct (F64ConvertI64U, NoOperand, 1u)
  | 0xbbuy ->
    struct (F64PromoteF32, NoOperand, 1u)
  | 0xbcuy ->
    struct (I32ReinterpretF32, NoOperand, 1u)
  | 0xbduy ->
    struct (I64ReinterpretF64, NoOperand, 1u)
  | 0xbeuy ->
    struct (F32ReinterpretI32, NoOperand, 1u)
  | 0xbfuy ->
    struct (F64ReinterpretI64, NoOperand, 1u)
  | 0xc0uy ->
    struct (I32Extend8S, NoOperand, 1u)
  | 0xc1uy ->
    struct (I32Extend16S, NoOperand, 1u)
  | 0xc2uy ->
    struct (I64Extend8S, NoOperand, 1u)
  | 0xc3uy ->
    struct (I64Extend16S, NoOperand, 1u)
  | 0xc4uy ->
    struct (I64Extend32S, NoOperand, 1u)
  | 0x25uy ->
    parseIndex span reader 1 TableGet
  | 0x26uy ->
    parseIndex span reader 1 TableSet
  | 0xd0uy ->
    parseRefType span reader 1 RefNull
  | 0xd1uy ->
    struct (RefIsNull, NoOperand, 1u)
  | 0xd2uy ->
    parseIndex span reader 1 RefFunc
  | _ ->
    raise ParsingFailureException

let parse lifter (span: ByteSpan) (reader: IBinReader) addr =
  let struct (opcode, operands, instrLen) = parseInstruction span reader
  Instruction(addr, instrLen, opcode, operands, lifter)
