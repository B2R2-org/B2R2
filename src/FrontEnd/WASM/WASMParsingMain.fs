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
  let value, cnt = reader.ReadUInt32LEB128 (span, pos)
  struct (value |> Index, pos + cnt)

let private readType (span: ByteSpan) (reader: IBinReader) pos =
  let t, cnt = reader.ReadInt32LEB128 (span, pos)
  struct (t |> Type, pos + cnt)

let private readAlignment (span: ByteSpan) (reader: IBinReader) pos =
  let alignment, cnt = reader.ReadUInt32LEB128 (span, pos)
  struct (alignment |> Alignment, pos + cnt)

let private readAddress (span: ByteSpan) (reader: IBinReader) pos =
  let address, cnt = reader.ReadUInt32LEB128 (span, pos)
  struct (address |> Address, pos + cnt)

let private readLane (span: ByteSpan) (reader: IBinReader) pos =
  let lane = reader.ReadUInt8 (span, pos)
  struct (lane |> LaneIndex, pos + 1)

let private parseU32LEB128 (span: ByteSpan) (reader: IBinReader) pos opcode =
  let value, cnt = reader.ReadUInt32LEB128 (span, pos)
  struct (opcode, OneOperand (value |> I32), uint32 (pos + cnt))

let private parseU64LEB128 (span: ByteSpan) (reader: IBinReader) pos opcode =
  let value, cnt = reader.ReadUInt64LEB128 (span, pos)
  struct (opcode, OneOperand (value |> I64), uint32 (pos + cnt))

let private parseF32 (span: ByteSpan) (reader: IBinReader) pos opcode =
  let value = reader.ReadUInt32 (span, pos)
  let value = BitVector.OfUInt32 value 32<rt>
  struct (opcode, OneOperand (value |> F32), uint32 (pos + 4))

let private parseF64 (span: ByteSpan) (reader: IBinReader) pos opcode =
  let value = reader.ReadUInt64 (span, pos)
  let value = BitVector.OfUInt64 value 64<rt>
  struct (opcode, OneOperand (value |> F64), uint32 (pos + 8))

let private parseV128 (span: ByteSpan) (reader: IBinReader) pos opcode =
  let i32One = reader.ReadUInt32 (span, pos)
  let i32One = BitVector.OfUInt32 i32One 32<rt>
  let i32Two = reader.ReadUInt32 (span, pos + 4)
  let i32Two = BitVector.OfUInt32 i32Two 32<rt>
  let i32Three = reader.ReadUInt32 (span, pos + 8)
  let i32Three = BitVector.OfUInt32 i32Three 32<rt>
  let i32Four = reader.ReadUInt32 (span, pos + 12)
  let i32Four = BitVector.OfUInt32 i32Four 32<rt>
  let v128 = (i32One, i32Two, i32Three, i32Four) |> V128
  struct (opcode, OneOperand v128, uint32 pos + 16u)

(* XXX: readIndex *)
let private parseIndex (span: ByteSpan) (reader: IBinReader) pos opcode =
  let index, cnt = reader.ReadUInt32LEB128 (span, pos)
  struct (opcode, OneOperand (index |> Index), uint32 (pos + cnt))

(* XXX: readType *)
let private parseType (span: ByteSpan) (reader: IBinReader) pos opcode =
  let t, cnt = reader.ReadInt32LEB128 (span, pos)
  struct (opcode, OneOperand (t |> Type), uint32 (pos + cnt))

let private parseLoad span reader pos opcode =
  let struct (alignment, nextPos) = readAlignment span reader pos
  let struct (offset, nextPos) = readAddress span reader nextPos
  let operands = TwoOperands (alignment, offset)
  struct (opcode, operands, uint32 nextPos)

let private parseStore span reader pos opcode =
  let struct (alignment, nextPos) = readAlignment span reader pos
  let struct (offset, nextPos) = readAddress span reader nextPos
  let operands = TwoOperands (alignment, offset)
  struct (opcode, operands, uint32 nextPos)

let rec private parseTypes span reader pos cnt ret =
  if cnt = 0 then struct (ret, uint32 (pos + 1))
  else
    let struct (t, nextPos) = readType span reader pos
    parseTypes span reader nextPos (cnt - 1) (ret @ [ t ]) (* XXX *)

let rec private parseIndices span reader pos cnt ret =
  if cnt = 0 then struct (ret, uint32 (pos + 1))
  else
    let struct (index, nextPos) = readIndex span reader pos
    parseIndices span reader nextPos (cnt - 1) (ret @ [ index ]) (* XXX *)

let private parseCount (span: ByteSpan) (reader: IBinReader) pos =
  let cnt, bcnt = reader.ReadInt32LEB128 (span, pos)
  struct (cnt, uint32 (pos + bcnt))

let private parseSimdLane span reader pos opcode =
  let struct (lane, nextPos) = readLane span reader pos
  struct (opcode, OneOperand lane, uint32 nextPos)

let private parseSimdLoadLane span reader pos opcode =
  let struct (alignment, nextPos) = readAlignment span reader pos
  let struct (offset, nextPos) = readAddress span reader nextPos
  let struct (lane, nextPos) = readLane span reader nextPos
  struct (opcode, ThreeOperands (alignment, offset, lane), uint32 nextPos)

let private parseSimdLoadZero span reader pos opcode =
  let struct (alignment, nextPos) = readAlignment span reader pos
  let struct (offset, nextPos) = readAddress span reader nextPos
  struct (opcode, TwoOperands (alignment, offset), uint32 nextPos)

let private parseSimdStoreLane span reader pos opcode =
  let struct (alignment, nextPos) = readAlignment span reader pos
  let struct (offset, nextPos) = readAddress span reader nextPos
  let struct (lane, nextPos) = readLane span reader nextPos
  struct (opcode, ThreeOperands (alignment, offset, lane), uint32 nextPos)

let private parseSimdShuffle span reader pos opcode =
  parseV128 span reader pos opcode

let private parseSimdSplat span reader pos opcode =
  let struct (alignment, nextPos) = readAlignment span reader pos
  let struct (offset, nextPos) = readAddress span reader nextPos
  struct (opcode, TwoOperands (alignment, offset), uint32 nextPos)

let private parseAtomicNotify span reader pos opcode =
  let struct (alignment, nextPos) = readAlignment span reader pos
  let struct (offset, nextPos) = readAddress span reader nextPos
  struct (opcode, TwoOperands (alignment, offset), uint32 nextPos)

let private parseAtomicFence (span: ByteSpan) (reader: IBinReader) pos opcode =
  let consistencyModel = reader.ReadUInt8 (span, pos)
  struct (opcode, OneOperand (consistencyModel |> ConsistencyModel),
          uint32 pos + 1u)

let private parseAtomicLoad span reader pos opcode =
  let struct (alignment, nextPos) = readAlignment span reader pos
  let struct (offset, nextPos) = readAddress span reader nextPos
  struct (opcode, TwoOperands (alignment, offset), uint32 nextPos)

let private parseAtomicStore span reader pos opcode =
  let struct (alignment, nextPos) = readAlignment span reader pos
  let struct (offset, nextPos) = readAddress span reader nextPos
  struct (opcode, TwoOperands (alignment, offset), uint32 nextPos)

let private parseAtomicWait span reader pos opcode =
  let struct (alignment, nextPos) = readAlignment span reader pos
  let struct (offset, nextPos) = readAddress span reader nextPos
  struct (opcode, TwoOperands (alignment, offset), uint32 nextPos)

let private parseAtomicRmw span reader pos opcode =
  let struct (alignment, nextPos) = readAlignment span reader pos
  let struct (offset, nextPos) = readAddress span reader nextPos
  struct (opcode, TwoOperands (alignment, offset), uint32 nextPos)

let private parseInstruction (span: ByteSpan) (reader: IBinReader) =
  match span[0] with
  | 0xfcuy ->
    match span[1] with
    | 0x00uy -> struct (I32TruncSatF32S, NoOperand, 2u)
    | 0x01uy -> struct (I32TruncSatF32U, NoOperand, 2u)
    | 0x02uy -> struct (I32TruncSatF64S, NoOperand, 2u)
    | 0x03uy -> struct (I32TruncSatF64U, NoOperand, 2u)
    | 0x04uy -> struct (I64TruncSatF32S, NoOperand, 2u)
    | 0x05uy -> struct (I64TruncSatF32U, NoOperand, 2u)
    | 0x06uy -> struct (I64TruncSatF64S, NoOperand, 2u)
    | 0x07uy -> struct (I64TruncSatF64U, NoOperand, 2u)
    | 0x08uy ->
      let struct (segment, pos) = readIndex span reader 2
      let struct (memIndex, pos) = readIndex span reader pos
      struct (MemoryInit, TwoOperands (segment, memIndex), uint32 pos)
    | 0x09uy -> parseIndex span reader 2 DataDrop
    | 0x0auy ->
      let struct (destMemIndex, pos) = readIndex span reader 2
      let struct (srcMemIndex, pos) = readIndex span reader pos
      struct (MemoryCopy, TwoOperands (destMemIndex, srcMemIndex), uint32 pos)
    | 0x0buy -> parseIndex span reader 2 MemoryFill
    | 0x0cuy ->
      let struct (segment, pos) = readIndex span reader 2
      let struct (tableIndex, pos) = readIndex span reader pos
      struct (TableInit, TwoOperands (segment, tableIndex), uint32 pos)
    | 0x0duy -> struct (ElemDrop, NoOperand, 2u)
    | 0x0euy ->
      let struct (destTable, pos) = readIndex span reader 2
      let struct (srcTable, pos) = readIndex span reader pos
      struct (TableCopy, TwoOperands (destTable, srcTable), uint32 pos)
    | 0x0fuy -> parseIndex span reader 2 TableGrow
    | 0x10uy -> parseIndex span reader 2 TableSize
    | 0x11uy -> parseIndex span reader 2 TableFill
    | _ -> raise ParsingFailureException
  | 0xfduy ->
    match span[1] with
    | 0x00uy -> parseLoad span reader 2 V128Load
    | 0x01uy -> parseLoad span reader 2 V128Load8X8S
    | 0x02uy -> parseLoad span reader 2 V128Load8X8U
    | 0x03uy -> parseLoad span reader 2 V128Load16X4S
    | 0x04uy -> parseLoad span reader 2 V128Load16X4U
    | 0x05uy -> parseLoad span reader 2 V128Load32X2S
    | 0x06uy -> parseLoad span reader 2 V128Load32X2U
    | 0x07uy -> parseSimdSplat span reader 2 V128Load8Splat
    | 0x08uy -> parseSimdSplat span reader 2 V128Load16Splat
    | 0x09uy -> parseSimdSplat span reader 2 V128Load32Splat
    | 0x0auy -> parseSimdSplat span reader 2 V128Load64Splat
    | 0x0buy -> parseStore span reader 2 V128Store
    | 0x0cuy -> parseV128 span reader 2 V128Const
    | 0x0duy -> parseSimdShuffle span reader 2 I8X16Shuffle
    | 0x0euy -> struct (I8X16Swizzle, NoOperand, 2u)
    | 0x0fuy -> parseSimdSplat span reader 2 I8X16Splat
    | 0x10uy -> parseSimdSplat span reader 2 I16X8Splat
    | 0x11uy -> parseSimdSplat span reader 2 I32X4Splat
    | 0x12uy -> parseSimdSplat span reader 2 I64X2Splat
    | 0x13uy -> parseSimdSplat span reader 2 F32X4Splat
    | 0x14uy -> parseSimdSplat span reader 2 F64X2Splat
    | 0x15uy -> parseSimdLane span reader 2 I8X16ExtractLaneS
    | 0x16uy -> parseSimdLane span reader 2 I8X16ExtractLaneU
    | 0x17uy -> parseSimdLane span reader 2 I8X16ReplaceLane
    | 0x18uy -> parseSimdLane span reader 2 I16X8ExtractLaneS
    | 0x19uy -> parseSimdLane span reader 2 I16X8ExtractLaneU
    | 0x1auy -> parseSimdLane span reader 2 I16X8ReplaceLane
    | 0x1buy -> parseSimdLane span reader 2 I32X4ExtractLane
    | 0x1cuy -> parseSimdLane span reader 2 I32X4ReplaceLane
    | 0x1duy -> parseSimdLane span reader 2 I64X2ExtractLane
    | 0x1euy -> parseSimdLane span reader 2 I64X2ReplaceLane
    | 0x1fuy -> parseSimdLane span reader 2 F32X4ExtractLane
    | 0x20uy -> parseSimdLane span reader 2 F32X4ReplaceLane
    | 0x21uy -> parseSimdLane span reader 2 F64X2ExtractLane
    | 0x22uy -> parseSimdLane span reader 2 F64X2ReplaceLane
    | 0x23uy -> struct (I8X16Eq, NoOperand, 2u)
    | 0x24uy -> struct (I8X16Ne, NoOperand, 2u)
    | 0x25uy -> struct (I8X16LtS, NoOperand, 2u)
    | 0x26uy -> struct (I8X16LtU, NoOperand, 2u)
    | 0x27uy -> struct (I8X16GtS, NoOperand, 2u)
    | 0x28uy -> struct (I8X16GtU, NoOperand, 2u)
    | 0x29uy -> struct (I8X16LeS, NoOperand, 2u)
    | 0x2auy -> struct (I8X16LeU, NoOperand, 2u)
    | 0x2buy -> struct (I8X16GeS, NoOperand, 2u)
    | 0x2cuy -> struct (I8X16GeU, NoOperand, 2u)
    | 0x2duy -> struct (I16X8Eq, NoOperand, 2u)
    | 0x2euy -> struct (I16X8Ne, NoOperand, 2u)
    | 0x2fuy -> struct (I16X8LtS, NoOperand, 2u)
    | 0x30uy -> struct (I16X8LtU, NoOperand, 2u)
    | 0x31uy -> struct (I16X8GtS, NoOperand, 2u)
    | 0x32uy -> struct (I16X8GtU, NoOperand, 2u)
    | 0x33uy -> struct (I16X8LeS, NoOperand, 2u)
    | 0x34uy -> struct (I16X8LeU, NoOperand, 2u)
    | 0x35uy -> struct (I16X8GeS, NoOperand, 2u)
    | 0x36uy -> struct (I16X8GeU, NoOperand, 2u)
    | 0x37uy -> struct (I32X4Eq, NoOperand, 2u)
    | 0x38uy -> struct (I32X4Ne, NoOperand, 2u)
    | 0x39uy -> struct (I32X4LtS, NoOperand, 2u)
    | 0x3auy -> struct (I32X4LtU, NoOperand, 2u)
    | 0x3buy -> struct (I32X4GtS, NoOperand, 2u)
    | 0x3cuy -> struct (I32X4GtU, NoOperand, 2u)
    | 0x3duy -> struct (I32X4LeS, NoOperand, 2u)
    | 0x3euy -> struct (I32X4LeU, NoOperand, 2u)
    | 0x3fuy -> struct (I32X4GeS, NoOperand, 2u)
    | 0x40uy -> struct (I32X4GeU, NoOperand, 2u)
    | 0x41uy -> struct (F32X4Eq, NoOperand, 2u)
    | 0x42uy -> struct (F32X4Ne, NoOperand, 2u)
    | 0x43uy -> struct (F32X4Lt, NoOperand, 2u)
    | 0x44uy -> struct (F32X4Gt, NoOperand, 2u)
    | 0x45uy -> struct (F32X4Le, NoOperand, 2u)
    | 0x46uy -> struct (F32X4Ge, NoOperand, 2u)
    | 0x47uy -> struct (F64X2Eq, NoOperand, 2u)
    | 0x48uy -> struct (F64X2Ne, NoOperand, 2u)
    | 0x49uy -> struct (F64X2Lt, NoOperand, 2u)
    | 0x4auy -> struct (F64X2Gt, NoOperand, 2u)
    | 0x4buy -> struct (F64X2Le, NoOperand, 2u)
    | 0x4cuy -> struct (F64X2Ge, NoOperand, 2u)
    | 0x4duy -> struct (V128Not, NoOperand, 2u)
    | 0x4euy -> struct (V128And, NoOperand, 2u)
    | 0x4fuy -> struct (V128Andnot, NoOperand, 2u)
    | 0x50uy -> struct (V128Or, NoOperand, 2u)
    | 0x51uy -> struct (V128Xor, NoOperand, 2u)
    | 0x52uy -> struct (V128BitSelect, NoOperand, 2u)
    | 0x53uy -> struct (V128AnyTrue, NoOperand, 2u)
    | 0x54uy -> parseSimdLoadLane span reader 2 V128Load8Lane
    | 0x55uy -> parseSimdLoadLane span reader 2 V128Load16Lane
    | 0x56uy -> parseSimdLoadLane span reader 2 V128Load32Lane
    | 0x57uy -> parseSimdLoadLane span reader 2 V128Load64Lane
    | 0x58uy -> parseSimdStoreLane span reader 2 V128Store8Lane
    | 0x59uy -> parseSimdStoreLane span reader 2 V128Store16Lane
    | 0x5auy -> parseSimdStoreLane span reader 2 V128Store32Lane
    | 0x5buy -> parseSimdStoreLane span reader 2 V128Store64Lane
    | 0x5cuy -> parseSimdLoadZero span reader 2 V128Load32Zero
    | 0x5duy -> parseSimdLoadZero span reader 2 V128Load64Zero
    | 0x5euy -> struct (F32X4DemoteF64X2Zero, NoOperand, 2u)
    | 0x5fuy -> struct (F64X2PromoteLowF32X4, NoOperand, 2u)
    | 0x60uy -> struct (I8X16Abs, NoOperand, 2u)
    | 0x61uy -> struct (I8X16Neg, NoOperand, 2u)
    | 0x62uy -> struct (I8X16Popcnt, NoOperand, 2u)
    | 0x63uy -> struct (I8X16AllTrue, NoOperand, 2u)
    | 0x64uy -> struct (I8X16Bitmask, NoOperand, 2u)
    | 0x65uy -> struct (I8X16NarrowI16X8S, NoOperand, 2u)
    | 0x66uy -> struct (I8X16NarrowI16X8U, NoOperand, 2u)
    | 0x6buy -> struct (I8X16Shl, NoOperand, 2u)
    | 0x6cuy -> struct (I8X16ShrS, NoOperand, 2u)
    | 0x6duy -> struct (I8X16ShrU, NoOperand, 2u)
    | 0x6euy -> struct (I8X16Add, NoOperand, 2u)
    | 0x6fuy -> struct (I8X16AddSatS, NoOperand, 2u)
    | 0x70uy -> struct (I8X16AddSatU, NoOperand, 2u)
    | 0x71uy -> struct (I8X16Sub, NoOperand, 2u)
    | 0x72uy -> struct (I8X16SubSatS, NoOperand, 2u)
    | 0x73uy -> struct (I8X16SubSatU, NoOperand, 2u)
    | 0x76uy -> struct (I8X16MinS, NoOperand, 2u)
    | 0x77uy -> struct (I8X16MinU, NoOperand, 2u)
    | 0x78uy -> struct (I8X16MaxS, NoOperand, 2u)
    | 0x79uy -> struct (I8X16MaxU, NoOperand, 2u)
    | 0x7buy -> struct (I8X16AvgrU, NoOperand, 2u)
    | 0x7cuy -> struct (I16X8ExtaddPairwiseI8X16S, NoOperand, 2u)
    | 0x7duy -> struct (I16X8ExtaddPairwiseI8X16U, NoOperand, 2u)
    | 0x7euy -> struct (I32X4ExtaddPairwiseI16X8S, NoOperand, 2u)
    | 0x7fuy -> struct (I32X4ExtaddPairwiseI16X8U, NoOperand, 2u)
    | 0x80uy -> struct (I16X8Abs, NoOperand, 2u)
    | 0x81uy -> struct (I16X8Neg, NoOperand, 2u)
    | 0x82uy -> struct (I16X8Q15mulrSatS, NoOperand, 2u)
    | 0x83uy -> struct (I16X8AllTrue, NoOperand, 2u)
    | 0x84uy -> struct (I16X8Bitmask, NoOperand, 2u)
    | 0x85uy -> struct (I16X8NarrowI32X4S, NoOperand, 2u)
    | 0x86uy -> struct (I16X8NarrowI32X4U, NoOperand, 2u)
    | 0x87uy -> struct (I16X8ExtendLowI8X16S, NoOperand, 2u)
    | 0x88uy -> struct (I16X8ExtendHighI8X16S, NoOperand, 2u)
    | 0x89uy -> struct (I16X8ExtendLowI8X16U, NoOperand, 2u)
    | 0x8auy -> struct (I16X8ExtendHighI8X16U, NoOperand, 2u)
    | 0x8buy -> struct (I16X8Shl, NoOperand, 2u)
    | 0x8cuy -> struct (I16X8ShrS, NoOperand, 2u)
    | 0x8duy -> struct (I16X8ShrU, NoOperand, 2u)
    | 0x8euy -> struct (I16X8Add, NoOperand, 2u)
    | 0x8fuy -> struct (I16X8AddSatS, NoOperand, 2u)
    | 0x90uy -> struct (I16X8AddSatU, NoOperand, 2u)
    | 0x91uy -> struct (I16X8Sub, NoOperand, 2u)
    | 0x92uy -> struct (I16X8SubSatS, NoOperand, 2u)
    | 0x93uy -> struct (I16X8SubSatU, NoOperand, 2u)
    | 0x95uy -> struct (I16X8Mul, NoOperand, 2u)
    | 0x96uy -> struct (I16X8MinS, NoOperand, 2u)
    | 0x97uy -> struct (I16X8MinU, NoOperand, 2u)
    | 0x98uy -> struct (I16X8MaxS, NoOperand, 2u)
    | 0x99uy -> struct (I16X8MaxU, NoOperand, 2u)
    | 0x9buy -> struct (I16X8AvgrU, NoOperand, 2u)
    | 0x9cuy -> struct (I16X8ExtmulLowI8X16S, NoOperand, 2u)
    | 0x9duy -> struct (I16X8ExtmulHighI8X16S, NoOperand, 2u)
    | 0x9euy -> struct (I16X8ExtmulLowI8X16U, NoOperand, 2u)
    | 0x9fuy -> struct (I16X8ExtmulHighI8X16U, NoOperand, 2u)
    | 0xa0uy -> struct (I32X4Abs, NoOperand, 2u)
    | 0xa1uy -> struct (I32X4Neg, NoOperand, 2u)
    | 0xa3uy -> struct (I32X4AllTrue, NoOperand, 2u)
    | 0xa4uy -> struct (I32X4Bitmask, NoOperand, 2u)
    | 0xa7uy -> struct (I32X4ExtendLowI16X8S, NoOperand, 2u)
    | 0xa8uy -> struct (I32X4ExtendHighI16X8S, NoOperand, 2u)
    | 0xa9uy -> struct (I32X4ExtendLowI16X8U, NoOperand, 2u)
    | 0xaauy -> struct (I32X4ExtendHighI16X8U, NoOperand, 2u)
    | 0xabuy -> struct (I32X4Shl, NoOperand, 2u)
    | 0xacuy -> struct (I32X4ShrS, NoOperand, 2u)
    | 0xaduy -> struct (I32X4ShrU, NoOperand, 2u)
    | 0xaeuy -> struct (I32X4Add, NoOperand, 2u)
    | 0xb1uy -> struct (I32X4Sub, NoOperand, 2u)
    | 0xb5uy -> struct (I32X4Mul, NoOperand, 2u)
    | 0xb6uy -> struct (I32X4MinS, NoOperand, 2u)
    | 0xb7uy -> struct (I32X4MinU, NoOperand, 2u)
    | 0xb8uy -> struct (I32X4MaxS, NoOperand, 2u)
    | 0xb9uy -> struct (I32X4MaxU, NoOperand, 2u)
    | 0xbauy -> struct (I32X4DotI16X8S, NoOperand, 2u)
    | 0xbcuy -> struct (I32X4ExtmulLowI16X8S, NoOperand, 2u)
    | 0xbduy -> struct (I32X4ExtmulHighI16X8S, NoOperand, 2u)
    | 0xbeuy -> struct (I32X4ExtmulLowI16X8U, NoOperand, 2u)
    | 0xbfuy -> struct (I32X4ExtmulHighI16X8U, NoOperand, 2u)
    | 0xc0uy -> struct (I64X2Abs, NoOperand, 2u)
    | 0xc1uy -> struct (I64X2Neg, NoOperand, 2u)
    | 0xc3uy -> struct (I64X2AllTrue, NoOperand, 2u)
    | 0xc4uy -> struct (I64X2Bitmask, NoOperand, 2u)
    | 0xc7uy -> struct (I64X2ExtendLowI32X4S, NoOperand, 2u)
    | 0xc8uy -> struct (I64X2ExtendHighI32X4S, NoOperand, 2u)
    | 0xc9uy -> struct (I64X2ExtendLowI32X4U, NoOperand, 2u)
    | 0xcauy -> struct (I64X2ExtendHighI32X4U, NoOperand, 2u)
    | 0xcbuy -> struct (I64X2Shl, NoOperand, 2u)
    | 0xccuy -> struct (I64X2ShrS, NoOperand, 2u)
    | 0xcduy -> struct (I64X2ShrU, NoOperand, 2u)
    | 0xceuy -> struct (I64X2Add, NoOperand, 2u)
    | 0xd1uy -> struct (I64X2Sub, NoOperand, 2u)
    | 0xd5uy -> struct (I64X2Mul, NoOperand, 2u)
    | 0xd6uy -> struct (I64X2Eq, NoOperand, 2u)
    | 0xd7uy -> struct (I64X2Ne, NoOperand, 2u)
    | 0xd8uy -> struct (I64X2LtS, NoOperand, 2u)
    | 0xd9uy -> struct (I64X2GtS, NoOperand, 2u)
    | 0xdauy -> struct (I64X2LeS, NoOperand, 2u)
    | 0xdbuy -> struct (I64X2GeS, NoOperand, 2u)
    | 0xdcuy -> struct (I64X2ExtmulLowI32X4S, NoOperand, 2u)
    | 0xdduy -> struct (I64X2ExtmulHighI32X4S, NoOperand, 2u)
    | 0xdeuy -> struct (I64X2ExtmulLowI32X4U, NoOperand, 2u)
    | 0xdfuy -> struct (I64X2ExtmulHighI32X4U, NoOperand, 2u)
    | 0x67uy -> struct (F32X4Ceil, NoOperand, 2u)
    | 0x68uy -> struct (F32X4Floor, NoOperand, 2u)
    | 0x69uy -> struct (F32X4Trunc, NoOperand, 2u)
    | 0x6auy -> struct (F32X4Nearest, NoOperand, 2u)
    | 0x74uy -> struct (F64X2Ceil, NoOperand, 2u)
    | 0x75uy -> struct (F64X2Floor, NoOperand, 2u)
    | 0x7auy -> struct (F64X2Trunc, NoOperand, 2u)
    | 0x94uy -> struct (F64X2Nearest, NoOperand, 2u)
    | 0xe0uy -> struct (F32X4Abs, NoOperand, 2u)
    | 0xe1uy -> struct (F32X4Neg, NoOperand, 2u)
    | 0xe3uy -> struct (F32X4Sqrt, NoOperand, 2u)
    | 0xe4uy -> struct (F32X4Add, NoOperand, 2u)
    | 0xe5uy -> struct (F32X4Sub, NoOperand, 2u)
    | 0xe6uy -> struct (F32X4Mul, NoOperand, 2u)
    | 0xe7uy -> struct (F32X4Div, NoOperand, 2u)
    | 0xe8uy -> struct (F32X4Min, NoOperand, 2u)
    | 0xe9uy -> struct (F32X4Max, NoOperand, 2u)
    | 0xeauy -> struct (F32X4PMin, NoOperand, 2u)
    | 0xebuy -> struct (F32X4PMax, NoOperand, 2u)
    | 0xecuy -> struct (F64X2Abs, NoOperand, 2u)
    | 0xeduy -> struct (F64X2Neg, NoOperand, 2u)
    | 0xefuy -> struct (F64X2Sqrt, NoOperand, 2u)
    | 0xf0uy -> struct (F64X2Add, NoOperand, 2u)
    | 0xf1uy -> struct (F64X2Sub, NoOperand, 2u)
    | 0xf2uy -> struct (F64X2Mul, NoOperand, 2u)
    | 0xf3uy -> struct (F64X2Div, NoOperand, 2u)
    | 0xf4uy -> struct (F64X2Min, NoOperand, 2u)
    | 0xf5uy -> struct (F64X2Max, NoOperand, 2u)
    | 0xf6uy -> struct (F64X2PMin, NoOperand, 2u)
    | 0xf7uy -> struct (F64X2PMax, NoOperand, 2u)
    | 0xf8uy -> struct (I32X4TruncSatF32X4S, NoOperand, 2u)
    | 0xf9uy -> struct (I32X4TruncSatF32X4U, NoOperand, 2u)
    | 0xfauy -> struct (F32X4ConvertI32X4S, NoOperand, 2u)
    | 0xfbuy -> struct (F32X4ConvertI32X4U, NoOperand, 2u)
    | 0xfcuy -> struct (I32X4TruncSatF64X2SZero, NoOperand, 2u)
    | 0xfduy -> struct (I32X4TruncSatF64X2UZero, NoOperand, 2u)
    | 0xfeuy -> struct (F64X2ConvertLowI32X4S, NoOperand, 2u)
    | 0xffuy -> struct (F64X2ConvertLowI32X4U, NoOperand, 2u)
    | _ -> raise ParsingFailureException
  | 0xfeuy ->
    match span[1] with
    | 0x00uy -> parseAtomicNotify span reader 2 MemoryAtomicNotify
    | 0x01uy -> parseAtomicWait span reader 2 MemoryAtomicWait32
    | 0x02uy -> parseAtomicWait span reader 2 MemoryAtomicWait64
    | 0x03uy -> parseAtomicFence span reader 2 AtomicFence
    | 0x10uy -> parseAtomicLoad span reader 2 I32AtomicLoad
    | 0x11uy -> parseAtomicLoad span reader 2 I64AtomicLoad
    | 0x12uy -> parseAtomicLoad span reader 2 I32AtomicLoad8U
    | 0x13uy -> parseAtomicLoad span reader 2 I32AtomicLoad16U
    | 0x14uy -> parseAtomicLoad span reader 2 I64AtomicLoad8U
    | 0x15uy -> parseAtomicLoad span reader 2 I64AtomicLoad16U
    | 0x16uy -> parseAtomicLoad span reader 2 I64AtomicLoad32U
    | 0x17uy -> parseAtomicStore span reader 2 I32AtomicStore
    | 0x18uy -> parseAtomicStore span reader 2 I64AtomicStore
    | 0x19uy -> parseAtomicStore span reader 2 I32AtomicStore8
    | 0x1auy -> parseAtomicStore span reader 2 I32AtomicStore16
    | 0x1buy -> parseAtomicStore span reader 2 I64AtomicStore8
    | 0x1cuy -> parseAtomicStore span reader 2 I64AtomicStore16
    | 0x1duy -> parseAtomicStore span reader 2 I64AtomicStore32
    | 0x1euy -> parseAtomicRmw span reader 2 I32AtomicRmwAdd
    | 0x1fuy -> parseAtomicRmw span reader 2 I64AtomicRmwAdd
    | 0x20uy -> parseAtomicRmw span reader 2 I32AtomicRmw8AddU
    | 0x21uy -> parseAtomicRmw span reader 2 I32AtomicRmw16AddU
    | 0x22uy -> parseAtomicRmw span reader 2 I64AtomicRmw8AddU
    | 0x23uy -> parseAtomicRmw span reader 2 I64AtomicRmw16AddU
    | 0x24uy -> parseAtomicRmw span reader 2 I64AtomicRmw32AddU
    | 0x25uy -> parseAtomicRmw span reader 2 I32AtomicRmwSub
    | 0x26uy -> parseAtomicRmw span reader 2 I64AtomicRmw8SubU
    | 0x27uy -> parseAtomicRmw span reader 2 I32AtomicRmw8SubU
    | 0x28uy -> parseAtomicRmw span reader 2 I32AtomicRmw16SubU
    | 0x29uy -> parseAtomicRmw span reader 2 I64AtomicRmw8SubU
    | 0x2auy -> parseAtomicRmw span reader 2 I64AtomicRmw16SubU
    | 0x2buy -> parseAtomicRmw span reader 2 I64AtomicRmw32SubU
    | 0x2cuy -> parseAtomicRmw span reader 2 I32AtomicRmwAnd
    | 0x2duy -> parseAtomicRmw span reader 2 I64AtomicRmwAnd
    | 0x2euy -> parseAtomicRmw span reader 2 I32AtomicRmw8AndU
    | 0x2fuy -> parseAtomicRmw span reader 2 I32AtomicRmw16AndU
    | 0x30uy -> parseAtomicRmw span reader 2 I64AtomicRmw8AndU
    | 0x31uy -> parseAtomicRmw span reader 2 I64AtomicRmw16AndU
    | 0x32uy -> parseAtomicRmw span reader 2 I64AtomicRmw32AndU
    | 0x33uy -> parseAtomicRmw span reader 2 I32AtomicRmwOr
    | 0x34uy -> parseAtomicRmw span reader 2 I64AtomicRmwOr
    | 0x35uy -> parseAtomicRmw span reader 2 I32AtomicRmw8OrU
    | 0x36uy -> parseAtomicRmw span reader 2 I32AtomicRmw16OrU
    | 0x37uy -> parseAtomicRmw span reader 2 I64AtomicRmw8OrU
    | 0x38uy -> parseAtomicRmw span reader 2 I64AtomicRmw16OrU
    | 0x39uy -> parseAtomicRmw span reader 2 I64AtomicRmw32OrU
    | 0x3auy -> parseAtomicRmw span reader 2 I32AtomicRmwXor
    | 0x3buy -> parseAtomicRmw span reader 2 I64AtomicRmwXor
    | 0x3cuy -> parseAtomicRmw span reader 2 I32AtomicRmw8XorU
    | 0x3duy -> parseAtomicRmw span reader 2 I32AtomicRmw16XorU
    | 0x3euy -> parseAtomicRmw span reader 2 I64AtomicRmw8XorU
    | 0x3fuy -> parseAtomicRmw span reader 2 I64AtomicRmw16XorU
    | 0x40uy -> parseAtomicRmw span reader 2 I64AtomicRmw32XorU
    | 0x41uy -> parseAtomicRmw span reader 2 I32AtomicRmwXchg
    | 0x42uy -> parseAtomicRmw span reader 2 I64AtomicRmwXchg
    | 0x43uy -> parseAtomicRmw span reader 2 I32AtomicRmw8XchgU
    | 0x44uy -> parseAtomicRmw span reader 2 I32AtomicRmw16XchgU
    | 0x45uy -> parseAtomicRmw span reader 2 I64AtomicRmw8XchgU
    | 0x46uy -> parseAtomicRmw span reader 2 I64AtomicRmw16XchgU
    | 0x47uy -> parseAtomicRmw span reader 2 I64AtomicRmw32XchgU
    | 0x48uy -> parseAtomicRmw span reader 2 I32AtomicRmwCmpxchg
    | 0x49uy -> parseAtomicRmw span reader 2 I64AtomicRmwCmpxchg
    | 0x4auy -> parseAtomicRmw span reader 2 I32AtomicRmw8CmpxchgU
    | 0x4buy -> parseAtomicRmw span reader 2 I32AtomicRmw16CmpxchgU
    | 0x4cuy -> parseAtomicRmw span reader 2 I64AtomicRmw8CmpxchgU
    | 0x4duy -> parseAtomicRmw span reader 2 I64AtomicRmw16CmpxchgU
    | 0x4euy -> parseAtomicRmw span reader 2 I64AtomicRmw32CmpxchgU
    | _ -> raise ParsingFailureException
  | 0x00uy -> struct (Unreachable, NoOperand, 1u)
  | 0x01uy -> struct (Nop, NoOperand, 1u)
  | 0x02uy -> parseType span reader 1 Block
  | 0x03uy -> parseType span reader 1 Loop
  | 0x04uy -> parseType span reader 1 If
  | 0x05uy -> struct (Else, NoOperand, 1u)
  | 0x06uy -> parseType span reader 1 Try
  | 0x07uy -> parseIndex span reader 1 Catch
  | 0x08uy -> parseIndex span reader 1 Throw
  | 0x09uy -> parseIndex span reader 1 Rethrow
  | 0x0buy -> struct (End, NoOperand, 1u)
  | 0x0cuy -> parseIndex span reader 1 Br
  | 0x0duy -> parseIndex span reader 1 BrIf
  | 0x0euy ->
    let struct (count, pos) = parseCount span reader 1
    let struct (operands, pos) = parseIndices span reader (int pos) count []
    struct (BrTable, Operands operands, pos)
  | 0x0fuy -> struct (Return, NoOperand, 1u)
  | 0x10uy -> parseIndex span reader 1 Call
  | 0x11uy ->
    let struct (sigIndex, pos) = readIndex span reader 1
    let struct (tableIndex, pos) = readIndex span reader pos
    struct (CallIndirect, TwoOperands (sigIndex, tableIndex), uint32 pos)
  | 0x12uy -> parseIndex span reader 1 ReturnCall
  | 0x13uy ->
    let struct (sigIndex, pos) = readIndex span reader 1
    let struct (tableIndex, pos) = readIndex span reader pos
    struct (ReturnCallIndirect, TwoOperands (sigIndex, tableIndex), uint32 pos)
  | 0x14uy -> struct (CallRef, NoOperand, 1u)
  | 0x18uy -> parseIndex span reader 1 Delegate
  | 0x19uy -> struct (CatchAll, NoOperand, 1u)
  | 0x1auy -> struct (Drop, NoOperand, 1u)
  | 0x1buy -> struct (Select, NoOperand, 1u)
  | 0x1cuy ->
    let struct (cnt, pos) = parseCount span reader 1
    let struct (operands, pos) = parseTypes span reader (int pos) cnt []
    struct (SelectT, Operands operands, pos)
  | 0x20uy -> parseIndex span reader 1 LocalGet
  | 0x21uy -> parseIndex span reader 1 LocalSet
  | 0x22uy -> parseIndex span reader 1 LocalTee
  | 0x23uy -> parseIndex span reader 1 GlobalGet
  | 0x24uy -> parseIndex span reader 1 GlobalSet
  | 0x28uy -> parseLoad span reader 1 I32Load
  | 0x29uy -> parseLoad span reader 1 I64Load
  | 0x2auy -> parseLoad span reader 1 F32Load
  | 0x2buy -> parseLoad span reader 1 F64Load
  | 0x2cuy -> parseLoad span reader 1 I32Load8S
  | 0x2duy -> parseLoad span reader 1 I32Load8U
  | 0x2euy -> parseLoad span reader 1 I32Load16S
  | 0x2fuy -> parseLoad span reader 1 I32Load16U
  | 0x30uy -> parseLoad span reader 1 I64Load8S
  | 0x31uy -> parseLoad span reader 1 I64Load8U
  | 0x32uy -> parseLoad span reader 1 I64Load16S
  | 0x33uy -> parseLoad span reader 1 I64Load16U
  | 0x34uy -> parseLoad span reader 1 I64Load32S
  | 0x35uy -> parseLoad span reader 1 I64Load32U
  | 0x36uy -> parseStore span reader 1 I32Store
  | 0x37uy -> parseStore span reader 1 I64Store
  | 0x38uy -> parseStore span reader 1 F32Store
  | 0x39uy -> parseStore span reader 1 F64Store
  | 0x3auy -> parseStore span reader 1 I32Store8
  | 0x3buy -> parseStore span reader 1 I32Store16
  | 0x3cuy -> parseStore span reader 1 I64Store8
  | 0x3duy -> parseStore span reader 1 I64Store16
  | 0x3euy -> parseStore span reader 1 I64Store32
  | 0x3fuy -> parseIndex span reader 1 MemorySize
  | 0x40uy -> parseIndex span reader 1 MemoryGrow
  | 0x41uy -> parseU32LEB128 span reader 1 I32Const
  | 0x42uy -> parseU64LEB128 span reader 1 I64Const
  | 0x43uy -> parseF32 span reader 1 F32Const
  | 0x44uy -> parseF64 span reader 1 F64Const
  | 0x45uy -> struct (I32Eqz, NoOperand, 1u)
  | 0x46uy -> struct (I32Eq, NoOperand, 1u)
  | 0x47uy -> struct (I32Ne, NoOperand, 1u)
  | 0x48uy -> struct (I32LtS, NoOperand, 1u)
  | 0x49uy -> struct (I32LtU, NoOperand, 1u)
  | 0x4auy -> struct (I32GtS, NoOperand, 1u)
  | 0x4buy -> struct (I32GtU, NoOperand, 1u)
  | 0x4cuy -> struct (I32LeS, NoOperand, 1u)
  | 0x4duy -> struct (I32LeU, NoOperand, 1u)
  | 0x4euy -> struct (I32GeS, NoOperand, 1u)
  | 0x4fuy -> struct (I32GeU, NoOperand, 1u)
  | 0x50uy -> struct (I64Eqz, NoOperand, 1u)
  | 0x51uy -> struct (I64Eq, NoOperand, 1u)
  | 0x52uy -> struct (I64Ne, NoOperand, 1u)
  | 0x53uy -> struct (I64LtS, NoOperand, 1u)
  | 0x54uy -> struct (I64LtU, NoOperand, 1u)
  | 0x55uy -> struct (I64GtS, NoOperand, 1u)
  | 0x56uy -> struct (I64GtU, NoOperand, 1u)
  | 0x57uy -> struct (I64LeS, NoOperand, 1u)
  | 0x58uy -> struct (I64LeU, NoOperand, 1u)
  | 0x59uy -> struct (I64GeS, NoOperand, 1u)
  | 0x5auy -> struct (I64GeU, NoOperand, 1u)
  | 0x5buy -> struct (F32Eq, NoOperand, 1u)
  | 0x5cuy -> struct (F32Ne, NoOperand, 1u)
  | 0x5duy -> struct (F32Lt, NoOperand, 1u)
  | 0x5euy -> struct (F32Gt, NoOperand, 1u)
  | 0x5fuy -> struct (F32Le, NoOperand, 1u)
  | 0x60uy -> struct (F32Ge, NoOperand, 1u)
  | 0x61uy -> struct (F64Eq, NoOperand, 1u)
  | 0x62uy -> struct (F64Ne, NoOperand, 1u)
  | 0x63uy -> struct (F64Lt, NoOperand, 1u)
  | 0x64uy -> struct (F64Gt, NoOperand, 1u)
  | 0x65uy -> struct (F64Le, NoOperand, 1u)
  | 0x66uy -> struct (F64Ge, NoOperand, 1u)
  | 0x67uy -> struct (I32Clz, NoOperand, 1u)
  | 0x68uy -> struct (I32Ctz, NoOperand, 1u)
  | 0x69uy -> struct (I32Popcnt, NoOperand, 1u)
  | 0x6auy -> struct (I32Add, NoOperand, 1u)
  | 0x6buy -> struct (I32Sub, NoOperand, 1u)
  | 0x6cuy -> struct (I32Mul, NoOperand, 1u)
  | 0x6duy -> struct (I32DivS, NoOperand, 1u)
  | 0x6euy -> struct (I32DivU, NoOperand, 1u)
  | 0x6fuy -> struct (I32RemS, NoOperand, 1u)
  | 0x70uy -> struct (I32RemU, NoOperand, 1u)
  | 0x71uy -> struct (I32And, NoOperand, 1u)
  | 0x72uy -> struct (I32Or, NoOperand, 1u)
  | 0x73uy -> struct (I32Xor, NoOperand, 1u)
  | 0x74uy -> struct (I32Shl, NoOperand, 1u)
  | 0x75uy -> struct (I32ShrS, NoOperand, 1u)
  | 0x76uy -> struct (I32ShrU, NoOperand, 1u)
  | 0x77uy -> struct (I32Rotl, NoOperand, 1u)
  | 0x78uy -> struct (I32Rotr, NoOperand, 1u)
  | 0x79uy -> struct (I64Clz, NoOperand, 1u)
  | 0x7auy -> struct (I64Ctz, NoOperand, 1u)
  | 0x7buy -> struct (I64Popcnt, NoOperand, 1u)
  | 0x7cuy -> struct (I64Add, NoOperand, 1u)
  | 0x7duy -> struct (I64Sub, NoOperand, 1u)
  | 0x7euy -> struct (I64Mul, NoOperand, 1u)
  | 0x7fuy -> struct (I64DivS, NoOperand, 1u)
  | 0x80uy -> struct (I64DivU, NoOperand, 1u)
  | 0x81uy -> struct (I64RemS, NoOperand, 1u)
  | 0x82uy -> struct (I64RemU, NoOperand, 1u)
  | 0x83uy -> struct (I64And, NoOperand, 1u)
  | 0x84uy -> struct (I64Or, NoOperand, 1u)
  | 0x85uy -> struct (I64Xor, NoOperand, 1u)
  | 0x86uy -> struct (I64Shl, NoOperand, 1u)
  | 0x87uy -> struct (I64ShrS, NoOperand, 1u)
  | 0x88uy -> struct (I64ShrU, NoOperand, 1u)
  | 0x89uy -> struct (I64Rotl, NoOperand, 1u)
  | 0x8auy -> struct (I64Rotr, NoOperand, 1u)
  | 0x8buy -> struct (F32Abs, NoOperand, 1u)
  | 0x8cuy -> struct (F32Neg, NoOperand, 1u)
  | 0x8duy -> struct (F32Ceil, NoOperand, 1u)
  | 0x8euy -> struct (F32Floor, NoOperand, 1u)
  | 0x8fuy -> struct (F32Trunc, NoOperand, 1u)
  | 0x90uy -> struct (F32Nearest, NoOperand, 1u)
  | 0x91uy -> struct (F32Sqrt, NoOperand, 1u)
  | 0x92uy -> struct (F32Add, NoOperand, 1u)
  | 0x93uy -> struct (F32Sub, NoOperand, 1u)
  | 0x94uy -> struct (F32Mul, NoOperand, 1u)
  | 0x95uy -> struct (F32Div, NoOperand, 1u)
  | 0x96uy -> struct (F32Min, NoOperand, 1u)
  | 0x97uy -> struct (F32Max, NoOperand, 1u)
  | 0x98uy -> struct (F32Copysign, NoOperand, 1u)
  | 0x99uy -> struct (F64Abs, NoOperand, 1u)
  | 0x9auy -> struct (F64Neg, NoOperand, 1u)
  | 0x9buy -> struct (F64Ceil, NoOperand, 1u)
  | 0x9cuy -> struct (F64Floor, NoOperand, 1u)
  | 0x9duy -> struct (F64Trunc, NoOperand, 1u)
  | 0x9euy -> struct (F64Nearest, NoOperand, 1u)
  | 0x9fuy -> struct (F64Sqrt, NoOperand, 1u)
  | 0xa0uy -> struct (F64Add, NoOperand, 1u)
  | 0xa1uy -> struct (F64Sub, NoOperand, 1u)
  | 0xa2uy -> struct (F64Mul, NoOperand, 1u)
  | 0xa3uy -> struct (F64Div, NoOperand, 1u)
  | 0xa4uy -> struct (F64Min, NoOperand, 1u)
  | 0xa5uy -> struct (F64Max, NoOperand, 1u)
  | 0xa6uy -> struct (F64Copysign, NoOperand, 1u)
  | 0xa7uy -> struct (I32WrapI64, NoOperand, 1u)
  | 0xa8uy -> struct (I32TruncF32S, NoOperand, 1u)
  | 0xa9uy -> struct (I32TruncF32U, NoOperand, 1u)
  | 0xaauy -> struct (I32TruncF64S, NoOperand, 1u)
  | 0xabuy -> struct (I32TruncF64U, NoOperand, 1u)
  | 0xacuy -> struct (I64ExtendI32S, NoOperand, 1u)
  | 0xaduy -> struct (I64ExtendI32U, NoOperand, 1u)
  | 0xaeuy -> struct (I64TruncF32S, NoOperand, 1u)
  | 0xafuy -> struct (I64TruncF32U, NoOperand, 1u)
  | 0xb0uy -> struct (I64TruncF64S, NoOperand, 1u)
  | 0xb1uy -> struct (I64TruncF64U, NoOperand, 1u)
  | 0xb2uy -> struct (F32ConvertI32S, NoOperand, 1u)
  | 0xb3uy -> struct (F32ConvertI32U, NoOperand, 1u)
  | 0xb4uy -> struct (F32ConvertI64S, NoOperand, 1u)
  | 0xb5uy -> struct (F32ConvertI64U, NoOperand, 1u)
  | 0xb6uy -> struct (F32DemoteF64, NoOperand, 1u)
  | 0xb7uy -> struct (F64ConvertI32S, NoOperand, 1u)
  | 0xb8uy -> struct (F64ConvertI32U, NoOperand, 1u)
  | 0xb9uy -> struct (F64ConvertI64S, NoOperand, 1u)
  | 0xbauy -> struct (F64ConvertI64U, NoOperand, 1u)
  | 0xbbuy -> struct (F64PromoteF32, NoOperand, 1u)
  | 0xbcuy -> struct (I32ReinterpretF32, NoOperand, 1u)
  | 0xbduy -> struct (I64ReinterpretF64, NoOperand, 1u)
  | 0xbeuy -> struct (F32ReinterpretI32, NoOperand, 1u)
  | 0xbfuy -> struct (F64ReinterpretI64, NoOperand, 1u)
  | 0xc0uy -> struct (I32Extend8S, NoOperand, 1u)
  | 0xc1uy -> struct (I32Extend16S, NoOperand, 1u)
  | 0xc2uy -> struct (I64Extend8S, NoOperand, 1u)
  | 0xc3uy -> struct (I64Extend16S, NoOperand, 1u)
  | 0xc4uy -> struct (I64Extend32S, NoOperand, 1u)
  | 0xe0uy -> struct (InterpAlloca, NoOperand, 1u)
  | 0xe1uy -> struct (InterpBrUnless, NoOperand, 1u)
  | 0xe2uy -> struct (InterpCallImport, NoOperand, 1u)
  | 0xe3uy -> struct (InterpData, NoOperand, 1u)
  | 0xe4uy -> struct (InterpDropKeep, NoOperand, 1u)
  | 0xe5uy -> struct (InterpCatchDrop, NoOperand, 1u)
  | 0xe6uy -> struct (InterpAdjustFrameForReturnCall, NoOperand, 1u)
  | 0x25uy -> parseIndex span reader 1 TableGet
  | 0x26uy -> parseIndex span reader 1 TableSet
  | 0xd0uy -> struct (RefNull, NoOperand, 1u)
  | 0xd1uy -> struct (RefIsNull, NoOperand, 1u)
  | 0xd2uy -> parseIndex span reader 1 RefFunc
  | _ -> raise ParsingFailureException

let parse lifter (span: ByteSpan) (reader: IBinReader) addr =
  let struct (opcode, operands, instrLen) = parseInstruction span reader
  Instruction (addr, instrLen, opcode, operands, lifter)
