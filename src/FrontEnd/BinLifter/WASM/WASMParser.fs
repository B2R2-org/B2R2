module B2R2.FrontEnd.BinLifter.WASM.Parser

open B2R2
open B2R2.FrontEnd.BinLifter

let isPrefix = function
  | 0xfc | 0xfd | 0xfe -> true
  | _ -> false

let private readIndex (reader: BinReader) pos =
  let struct (value, nextPos) = reader.ReadUInt32LEB128 pos
  struct (value |> Index, nextPos)

let private readType (reader: BinReader) pos =
  let struct (t, nextPos) = reader.ReadInt32LEB128 pos
  struct (t |> Type, nextPos)

let private readAlignment (reader: BinReader) pos =
  let struct (alignment, nextPos) = reader.ReadUInt32LEB128 pos
  struct (alignment |> Alignment, nextPos)

let private readAddress (reader: BinReader) pos =
  let struct (address, nextPos) = reader.ReadUInt32LEB128 pos
  struct (address |> Address, nextPos)

let private readLane (reader: BinReader) pos =
  let struct (lane, nextPos) = reader.ReadUInt8 pos
  struct (lane |> LaneIndex, nextPos)

let private parseU32LEB128 (reader: BinReader) pos opcode =
  let struct (value, nextPos) = reader.ReadUInt32LEB128 pos
  struct (opcode, OneOperand (value |> I32), nextPos)

let private parseU64LEB128 (reader: BinReader) pos opcode =
  let struct (value, nextPos) = reader.ReadUInt64LEB128 pos
  struct (opcode, OneOperand (value |> I64), nextPos)

let private parseF32 (reader: BinReader) pos opcode =
  let struct (value, nextPos) = reader.ReadUInt32 pos
  let value = BitVector.ofUInt32 value 32<rt>
  struct (opcode, OneOperand (value |> F32), nextPos)

let private parseF64 (reader: BinReader) pos opcode =
  let struct (value, nextPos) = reader.ReadUInt64 pos
  let value = BitVector.ofUInt64 value 64<rt>
  struct (opcode, OneOperand (value |> F64), nextPos)

let private parseV128 (reader: BinReader) pos opcode =
  let struct (i32One, nextPos) = reader.ReadUInt32 pos
  let i32One = BitVector.ofUInt32 i32One 32<rt>
  let struct (i32Two, nextPos) = reader.ReadUInt32 nextPos
  let i32Two = BitVector.ofUInt32 i32Two 32<rt>
  let struct (i32Three, nextPos) = reader.ReadUInt32 nextPos
  let i32Three = BitVector.ofUInt32 i32Three 32<rt>
  let struct (i32Four, nextPos) = reader.ReadUInt32 nextPos
  let i32Four = BitVector.ofUInt32 i32Four 32<rt>
  let v128 = (i32One, i32Two, i32Three, i32Four) |> V128
  struct (opcode, OneOperand v128, nextPos)

let private parseType (reader: BinReader) pos opcode =
  let struct (t, nextPos) = reader.ReadInt32LEB128 pos
  struct (opcode, OneOperand (t |> Type), nextPos)

let private parseRefType (reader: BinReader) pos opcode =
  let struct (refType, nextPos) = reader.ReadInt32LEB128 pos
  struct (opcode, OneOperand (refType |> RefType), nextPos)

let private parseIndex (reader: BinReader) pos opcode =
  let struct (index, nextPos) = reader.ReadUInt32LEB128 pos
  struct (opcode, OneOperand (index |> Index), nextPos)

let private parseLoad reader pos opcode =
  let struct (alignment, nextPos) = readAlignment reader pos
  let struct (offset, nextPos) = readAddress reader nextPos
  let operands = TwoOperands (alignment, offset)
  struct (opcode, operands, nextPos)

let private parseStore reader pos opcode =
  let struct (alignment, nextPos) = readAlignment reader pos
  let struct (offset, nextPos) = readAddress reader nextPos
  let operands = TwoOperands (alignment, offset)
  struct (opcode, operands, nextPos)

let rec private parseTypes (reader: BinReader) pos cnt ret =
  if cnt = 0 then struct (ret, pos + 1)
  else
    let struct (t, nextPos) = readType reader pos
    parseTypes reader nextPos (cnt - 1) (ret @ [t])

let rec private parseIndices (reader: BinReader) pos cnt ret =
  if cnt = 0 then struct (ret, pos + 1)
  else
    let struct (index, nextPos) = readIndex reader pos
    parseIndices reader nextPos (cnt - 1) (ret @ [index])

let private parseCount (reader: BinReader) pos =
  let struct (cnt, nextPos) = reader.ReadInt32LEB128 pos
  struct (cnt, nextPos)

(*** SIMD-related parsing function. ***)

let private parseSimdLane (reader: BinReader) pos opcode =
  let struct (lane, nextPos) = readLane reader pos
  struct (opcode, OneOperand lane, nextPos)

let private parseSimdLoadLane (reader: BinReader) pos opcode =
  let struct (alignment, nextPos) = readAlignment reader pos
  let struct (offset, nextPos) = readAddress reader nextPos
  let struct (lane, nextPos) = readLane reader nextPos
  struct (opcode, ThreeOperands (alignment, offset, lane), nextPos)

let private parseSimdLoadZero (reader: BinReader) pos opcode =
  let struct (alignment, nextPos) = readAlignment reader pos
  let struct (offset, nextPos) = readAddress reader nextPos
  struct (opcode, TwoOperands (alignment, offset), nextPos)

let private parseSimdStoreLane (reader: BinReader) pos opcode =
  let struct (alignment, nextPos) = readAlignment reader pos
  let struct (offset, nextPos) = readAddress reader nextPos
  let struct (lane, nextPos) = readLane reader nextPos
  struct (opcode, ThreeOperands (alignment, offset, lane), nextPos)

let private parseSimdShuffle (reader: BinReader) pos opcode =
  parseV128 reader pos opcode

let private parseSimdSplat (reader: BinReader) pos opcode =
  let struct (alignment, nextPos) = readAlignment reader pos
  let struct (offset, nextPos) = readAddress reader nextPos
  struct (opcode, TwoOperands (alignment, offset), nextPos)

(*** Thread-related parsing function. ***)

let private parseAtomicNotify (reader: BinReader) pos opcode =
  let struct (alignment, nextPos) = readAlignment reader pos
  let struct (offset, nextPos) = readAddress reader nextPos
  struct (opcode, TwoOperands (alignment, offset), nextPos)

let private parseAtomicFence (reader: BinReader) pos opcode =
  let struct (consistencyModel, nextPos) = reader.ReadUInt8 pos
  struct (opcode, OneOperand (consistencyModel |> ConsistencyModel), nextPos)

let private parseAtomicLoad (reader: BinReader) pos opcode =
  let struct (alignment, nextPos) = readAlignment reader pos
  let struct (offset, nextPos) = readAddress reader nextPos
  struct (opcode, TwoOperands (alignment, offset), nextPos)

let private parseAtomicStore (reader: BinReader) pos opcode =
  let struct (alignment, nextPos) = readAlignment reader pos
  let struct (offset, nextPos) = readAddress reader nextPos
  struct (opcode, TwoOperands (alignment, offset), nextPos)

let private parseAtomicWait (reader: BinReader) pos opcode =
  let struct (alignment, nextPos) = readAlignment reader pos
  let struct (offset, nextPos) = readAddress reader nextPos
  struct (opcode, TwoOperands (alignment, offset), nextPos)

let private parseAtomicRmw (reader: BinReader) pos opcode =
  let struct (alignment, nextPos) = readAlignment reader pos
  let struct (offset, nextPos) = readAddress reader nextPos
  struct (opcode, TwoOperands (alignment, offset), nextPos)

let private parseInstruction (reader: BinReader) pos =
  let struct (bin, nextPos) = reader.ReadByte pos
  match bin with
  | 0xfcuy ->
    let struct (bin, nextPos) = reader.ReadByte nextPos
    match bin with
    | 0x00uy -> struct (I32TruncSatF32S, NoOperand, nextPos)
    | 0x01uy -> struct (I32TruncSatF32U, NoOperand, nextPos)
    | 0x02uy -> struct (I32TruncSatF64S, NoOperand, nextPos)
    | 0x03uy -> struct (I32TruncSatF64U, NoOperand, nextPos)
    | 0x04uy -> struct (I64TruncSatF32S, NoOperand, nextPos)
    | 0x05uy -> struct (I64TruncSatF32U, NoOperand, nextPos)
    | 0x06uy -> struct (I64TruncSatF64S, NoOperand, nextPos)
    | 0x07uy -> struct (I64TruncSatF64U, NoOperand, nextPos)
    | 0x08uy ->
      let struct (segment, nextPos) = readIndex reader nextPos
      let struct (memIndex, nextPos) = readIndex reader nextPos
      struct (MemoryInit, TwoOperands (segment, memIndex), nextPos)
    | 0x09uy -> parseIndex reader nextPos DataDrop
    | 0x0auy ->
      let struct (destMemIndex, nextPos) = readIndex reader nextPos
      let struct (srcMemIndex, nextPos) = readIndex reader nextPos
      struct (MemoryCopy, TwoOperands (destMemIndex, srcMemIndex), nextPos)
    | 0x0buy -> parseIndex reader nextPos MemoryFill
    | 0x0cuy ->
      let struct (segment, nextPos) = readIndex reader nextPos
      let struct (tableIndex, nextPos) = readIndex reader nextPos
      struct (TableInit, TwoOperands (segment, tableIndex), nextPos)
    | 0x0duy -> struct (ElemDrop, NoOperand, nextPos)
    | 0x0euy ->
      let struct (destTable, nextPos) = readIndex reader nextPos
      let struct (srcTable, nextPos) = readIndex reader nextPos
      struct (TableCopy, TwoOperands (destTable, srcTable), nextPos)
    | 0x0fuy -> parseIndex reader nextPos TableGrow
    | 0x10uy -> parseIndex reader nextPos TableSize
    | 0x11uy -> parseIndex reader nextPos TableFill
    | _ -> raise ParsingFailureException
  | 0xfduy ->
    let struct (bin, nextPos) = reader.ReadByte nextPos
    match bin with
    | 0x00uy -> parseLoad reader nextPos V128Load
    | 0x01uy -> parseLoad reader nextPos V128Load8X8S
    | 0x02uy -> parseLoad reader nextPos V128Load8X8U
    | 0x03uy -> parseLoad reader nextPos V128Load16X4S
    | 0x04uy -> parseLoad reader nextPos V128Load16X4U
    | 0x05uy -> parseLoad reader nextPos V128Load32X2S
    | 0x06uy -> parseLoad reader nextPos V128Load32X2U
    | 0x07uy -> parseSimdSplat reader nextPos V128Load8Splat
    | 0x08uy -> parseSimdSplat reader nextPos V128Load16Splat
    | 0x09uy -> parseSimdSplat reader nextPos V128Load32Splat
    | 0x0auy -> parseSimdSplat reader nextPos V128Load64Splat
    | 0x0buy -> parseStore reader nextPos V128Store
    | 0x0cuy -> parseV128 reader nextPos V128Const
    | 0x0duy -> parseSimdShuffle reader nextPos I8X16Shuffle
    | 0x0euy -> struct (I8X16Swizzle, NoOperand, nextPos)
    | 0x0fuy -> parseSimdSplat reader nextPos I8X16Splat
    | 0x10uy -> parseSimdSplat reader nextPos I16X8Splat
    | 0x11uy -> parseSimdSplat reader nextPos I32X4Splat
    | 0x12uy -> parseSimdSplat reader nextPos I64X2Splat
    | 0x13uy -> parseSimdSplat reader nextPos F32X4Splat
    | 0x14uy -> parseSimdSplat reader nextPos F64X2Splat
    | 0x15uy -> parseSimdLane reader nextPos I8X16ExtractLaneS
    | 0x16uy -> parseSimdLane reader nextPos I8X16ExtractLaneU
    | 0x17uy -> parseSimdLane reader nextPos I8X16ReplaceLane
    | 0x18uy -> parseSimdLane reader nextPos I16X8ExtractLaneS
    | 0x19uy -> parseSimdLane reader nextPos I16X8ExtractLaneU
    | 0x1auy -> parseSimdLane reader nextPos I16X8ReplaceLane
    | 0x1buy -> parseSimdLane reader nextPos I32X4ExtractLane
    | 0x1cuy -> parseSimdLane reader nextPos I32X4ReplaceLane
    | 0x1duy -> parseSimdLane reader nextPos I64X2ExtractLane
    | 0x1euy -> parseSimdLane reader nextPos I64X2ReplaceLane
    | 0x1fuy -> parseSimdLane reader nextPos F32X4ExtractLane
    | 0x20uy -> parseSimdLane reader nextPos F32X4ReplaceLane
    | 0x21uy -> parseSimdLane reader nextPos F64X2ExtractLane
    | 0x22uy -> parseSimdLane reader nextPos F64X2ReplaceLane
    | 0x23uy -> struct (I8X16Eq, NoOperand, nextPos)
    | 0x24uy -> struct (I8X16Ne, NoOperand, nextPos)
    | 0x25uy -> struct (I8X16LtS, NoOperand, nextPos)
    | 0x26uy -> struct (I8X16LtU, NoOperand, nextPos)
    | 0x27uy -> struct (I8X16GtS, NoOperand, nextPos)
    | 0x28uy -> struct (I8X16GtU, NoOperand, nextPos)
    | 0x29uy -> struct (I8X16LeS, NoOperand, nextPos)
    | 0x2auy -> struct (I8X16LeU, NoOperand, nextPos)
    | 0x2buy -> struct (I8X16GeS, NoOperand, nextPos)
    | 0x2cuy -> struct (I8X16GeU, NoOperand, nextPos)
    | 0x2duy -> struct (I16X8Eq, NoOperand, nextPos)
    | 0x2euy -> struct (I16X8Ne, NoOperand, nextPos)
    | 0x2fuy -> struct (I16X8LtS, NoOperand, nextPos)
    | 0x30uy -> struct (I16X8LtU, NoOperand, nextPos)
    | 0x31uy -> struct (I16X8GtS, NoOperand, nextPos)
    | 0x32uy -> struct (I16X8GtU, NoOperand, nextPos)
    | 0x33uy -> struct (I16X8LeS, NoOperand, nextPos)
    | 0x34uy -> struct (I16X8LeU, NoOperand, nextPos)
    | 0x35uy -> struct (I16X8GeS, NoOperand, nextPos)
    | 0x36uy -> struct (I16X8GeU, NoOperand, nextPos)
    | 0x37uy -> struct (I32X4Eq, NoOperand, nextPos)
    | 0x38uy -> struct (I32X4Ne, NoOperand, nextPos)
    | 0x39uy -> struct (I32X4LtS, NoOperand, nextPos)
    | 0x3auy -> struct (I32X4LtU, NoOperand, nextPos)
    | 0x3buy -> struct (I32X4GtS, NoOperand, nextPos)
    | 0x3cuy -> struct (I32X4GtU, NoOperand, nextPos)
    | 0x3duy -> struct (I32X4LeS, NoOperand, nextPos)
    | 0x3euy -> struct (I32X4LeU, NoOperand, nextPos)
    | 0x3fuy -> struct (I32X4GeS, NoOperand, nextPos)
    | 0x40uy -> struct (I32X4GeU, NoOperand, nextPos)
    | 0x41uy -> struct (F32X4Eq, NoOperand, nextPos)
    | 0x42uy -> struct (F32X4Ne, NoOperand, nextPos)
    | 0x43uy -> struct (F32X4Lt, NoOperand, nextPos)
    | 0x44uy -> struct (F32X4Gt, NoOperand, nextPos)
    | 0x45uy -> struct (F32X4Le, NoOperand, nextPos)
    | 0x46uy -> struct (F32X4Ge, NoOperand, nextPos)
    | 0x47uy -> struct (F64X2Eq, NoOperand, nextPos)
    | 0x48uy -> struct (F64X2Ne, NoOperand, nextPos)
    | 0x49uy -> struct (F64X2Lt, NoOperand, nextPos)
    | 0x4auy -> struct (F64X2Gt, NoOperand, nextPos)
    | 0x4buy -> struct (F64X2Le, NoOperand, nextPos)
    | 0x4cuy -> struct (F64X2Ge, NoOperand, nextPos)
    | 0x4duy -> struct (V128Not, NoOperand, nextPos)
    | 0x4euy -> struct (V128And, NoOperand, nextPos)
    | 0x4fuy -> struct (V128Andnot, NoOperand, nextPos)
    | 0x50uy -> struct (V128Or, NoOperand, nextPos)
    | 0x51uy -> struct (V128Xor, NoOperand, nextPos)
    | 0x52uy -> struct (V128BitSelect, NoOperand, nextPos)
    | 0x53uy -> struct (V128AnyTrue, NoOperand, nextPos)
    | 0x54uy -> parseSimdLoadLane reader nextPos V128Load8Lane
    | 0x55uy -> parseSimdLoadLane reader nextPos V128Load16Lane
    | 0x56uy -> parseSimdLoadLane reader nextPos V128Load32Lane
    | 0x57uy -> parseSimdLoadLane reader nextPos V128Load64Lane
    | 0x58uy -> parseSimdStoreLane reader nextPos V128Store8Lane
    | 0x59uy -> parseSimdStoreLane reader nextPos V128Store16Lane
    | 0x5auy -> parseSimdStoreLane reader nextPos V128Store32Lane
    | 0x5buy -> parseSimdStoreLane reader nextPos V128Store64Lane
    | 0x5cuy -> parseSimdLoadZero reader nextPos V128Load32Zero
    | 0x5duy -> parseSimdLoadZero reader nextPos V128Load64Zero
    | 0x5euy -> struct (F32X4DemoteF64X2Zero, NoOperand, nextPos)
    | 0x5fuy -> struct (F64X2PromoteLowF32X4, NoOperand, nextPos)
    | 0x60uy -> struct (I8X16Abs, NoOperand, nextPos)
    | 0x61uy -> struct (I8X16Neg, NoOperand, nextPos)
    | 0x62uy -> struct (I8X16Popcnt, NoOperand, nextPos)
    | 0x63uy -> struct (I8X16AllTrue, NoOperand, nextPos)
    | 0x64uy -> struct (I8X16Bitmask, NoOperand, nextPos)
    | 0x65uy -> struct (I8X16NarrowI16X8S, NoOperand, nextPos)
    | 0x66uy -> struct (I8X16NarrowI16X8U, NoOperand, nextPos)
    | 0x6buy -> struct (I8X16Shl, NoOperand, nextPos)
    | 0x6cuy -> struct (I8X16ShrS, NoOperand, nextPos)
    | 0x6duy -> struct (I8X16ShrU, NoOperand, nextPos)
    | 0x6euy -> struct (I8X16Add, NoOperand, nextPos)
    | 0x6fuy -> struct (I8X16AddSatS, NoOperand, nextPos)
    | 0x70uy -> struct (I8X16AddSatU, NoOperand, nextPos)
    | 0x71uy -> struct (I8X16Sub, NoOperand, nextPos)
    | 0x72uy -> struct (I8X16SubSatS, NoOperand, nextPos)
    | 0x73uy -> struct (I8X16SubSatU, NoOperand, nextPos)
    | 0x76uy -> struct (I8X16MinS, NoOperand, nextPos)
    | 0x77uy -> struct (I8X16MinU, NoOperand, nextPos)
    | 0x78uy -> struct (I8X16MaxS, NoOperand, nextPos)
    | 0x79uy -> struct (I8X16MaxU, NoOperand, nextPos)
    | 0x7buy -> struct (I8X16AvgrU, NoOperand, nextPos)
    | 0x7cuy -> struct (I16X8ExtaddPairwiseI8X16S, NoOperand, nextPos)
    | 0x7duy -> struct (I16X8ExtaddPairwiseI8X16U, NoOperand, nextPos)
    | 0x7euy -> struct (I32X4ExtaddPairwiseI16X8S, NoOperand, nextPos)
    | 0x7fuy -> struct (I32X4ExtaddPairwiseI16X8U, NoOperand, nextPos)
    | 0x80uy -> struct (I16X8Abs, NoOperand, nextPos)
    | 0x81uy -> struct (I16X8Neg, NoOperand, nextPos)
    | 0x82uy -> struct (I16X8Q15mulrSatS, NoOperand, nextPos)
    | 0x83uy -> struct (I16X8AllTrue, NoOperand, nextPos)
    | 0x84uy -> struct (I16X8Bitmask, NoOperand, nextPos)
    | 0x85uy -> struct (I16X8NarrowI32X4S, NoOperand, nextPos)
    | 0x86uy -> struct (I16X8NarrowI32X4U, NoOperand, nextPos)
    | 0x87uy -> struct (I16X8ExtendLowI8X16S, NoOperand, nextPos)
    | 0x88uy -> struct (I16X8ExtendHighI8X16S, NoOperand, nextPos)
    | 0x89uy -> struct (I16X8ExtendLowI8X16U, NoOperand, nextPos)
    | 0x8auy -> struct (I16X8ExtendHighI8X16U, NoOperand, nextPos)
    | 0x8buy -> struct (I16X8Shl, NoOperand, nextPos)
    | 0x8cuy -> struct (I16X8ShrS, NoOperand, nextPos)
    | 0x8duy -> struct (I16X8ShrU, NoOperand, nextPos)
    | 0x8euy -> struct (I16X8Add, NoOperand, nextPos)
    | 0x8fuy -> struct (I16X8AddSatS, NoOperand, nextPos)
    | 0x90uy -> struct (I16X8AddSatU, NoOperand, nextPos)
    | 0x91uy -> struct (I16X8Sub, NoOperand, nextPos)
    | 0x92uy -> struct (I16X8SubSatS, NoOperand, nextPos)
    | 0x93uy -> struct (I16X8SubSatU, NoOperand, nextPos)
    | 0x95uy -> struct (I16X8Mul, NoOperand, nextPos)
    | 0x96uy -> struct (I16X8MinS, NoOperand, nextPos)
    | 0x97uy -> struct (I16X8MinU, NoOperand, nextPos)
    | 0x98uy -> struct (I16X8MaxS, NoOperand, nextPos)
    | 0x99uy -> struct (I16X8MaxU, NoOperand, nextPos)
    | 0x9buy -> struct (I16X8AvgrU, NoOperand, nextPos)
    | 0x9cuy -> struct (I16X8ExtmulLowI8X16S, NoOperand, nextPos)
    | 0x9duy -> struct (I16X8ExtmulHighI8X16S, NoOperand, nextPos)
    | 0x9euy -> struct (I16X8ExtmulLowI8X16U, NoOperand, nextPos)
    | 0x9fuy -> struct (I16X8ExtmulHighI8X16U, NoOperand, nextPos)
    | 0xa0uy -> struct (I32X4Abs, NoOperand, nextPos)
    | 0xa1uy -> struct (I32X4Neg, NoOperand, nextPos)
    | 0xa3uy -> struct (I32X4AllTrue, NoOperand, nextPos)
    | 0xa4uy -> struct (I32X4Bitmask, NoOperand, nextPos)
    | 0xa7uy -> struct (I32X4ExtendLowI16X8S, NoOperand, nextPos)
    | 0xa8uy -> struct (I32X4ExtendHighI16X8S, NoOperand, nextPos)
    | 0xa9uy -> struct (I32X4ExtendLowI16X8U, NoOperand, nextPos)
    | 0xaauy -> struct (I32X4ExtendHighI16X8U, NoOperand, nextPos)
    | 0xabuy -> struct (I32X4Shl, NoOperand, nextPos)
    | 0xacuy -> struct (I32X4ShrS, NoOperand, nextPos)
    | 0xaduy -> struct (I32X4ShrU, NoOperand, nextPos)
    | 0xaeuy -> struct (I32X4Add, NoOperand, nextPos)
    | 0xb1uy -> struct (I32X4Sub, NoOperand, nextPos)
    | 0xb5uy -> struct (I32X4Mul, NoOperand, nextPos)
    | 0xb6uy -> struct (I32X4MinS, NoOperand, nextPos)
    | 0xb7uy -> struct (I32X4MinU, NoOperand, nextPos)
    | 0xb8uy -> struct (I32X4MaxS, NoOperand, nextPos)
    | 0xb9uy -> struct (I32X4MaxU, NoOperand, nextPos)
    | 0xbauy -> struct (I32X4DotI16X8S, NoOperand, nextPos)
    | 0xbcuy -> struct (I32X4ExtmulLowI16X8S, NoOperand, nextPos)
    | 0xbduy -> struct (I32X4ExtmulHighI16X8S, NoOperand, nextPos)
    | 0xbeuy -> struct (I32X4ExtmulLowI16X8U, NoOperand, nextPos)
    | 0xbfuy -> struct (I32X4ExtmulHighI16X8U, NoOperand, nextPos)
    | 0xc0uy -> struct (I64X2Abs, NoOperand, nextPos)
    | 0xc1uy -> struct (I64X2Neg, NoOperand, nextPos)
    | 0xc3uy -> struct (I64X2AllTrue, NoOperand, nextPos)
    | 0xc4uy -> struct (I64X2Bitmask, NoOperand, nextPos)
    | 0xc7uy -> struct (I64X2ExtendLowI32X4S, NoOperand, nextPos)
    | 0xc8uy -> struct (I64X2ExtendHighI32X4S, NoOperand, nextPos)
    | 0xc9uy -> struct (I64X2ExtendLowI32X4U, NoOperand, nextPos)
    | 0xcauy -> struct (I64X2ExtendHighI32X4U, NoOperand, nextPos)
    | 0xcbuy -> struct (I64X2Shl, NoOperand, nextPos)
    | 0xccuy -> struct (I64X2ShrS, NoOperand, nextPos)
    | 0xcduy -> struct (I64X2ShrU, NoOperand, nextPos)
    | 0xceuy -> struct (I64X2Add, NoOperand, nextPos)
    | 0xd1uy -> struct (I64X2Sub, NoOperand, nextPos)
    | 0xd5uy -> struct (I64X2Mul, NoOperand, nextPos)
    | 0xd6uy -> struct (I64X2Eq, NoOperand, nextPos)
    | 0xd7uy -> struct (I64X2Ne, NoOperand, nextPos)
    | 0xd8uy -> struct (I64X2LtS, NoOperand, nextPos)
    | 0xd9uy -> struct (I64X2GtS, NoOperand, nextPos)
    | 0xdauy -> struct (I64X2LeS, NoOperand, nextPos)
    | 0xdbuy -> struct (I64X2GeS, NoOperand, nextPos)
    | 0xdcuy -> struct (I64X2ExtmulLowI32X4S, NoOperand, nextPos)
    | 0xdduy -> struct (I64X2ExtmulHighI32X4S, NoOperand, nextPos)
    | 0xdeuy -> struct (I64X2ExtmulLowI32X4U, NoOperand, nextPos)
    | 0xdfuy -> struct (I64X2ExtmulHighI32X4U, NoOperand, nextPos)
    | 0x67uy -> struct (F32X4Ceil, NoOperand, nextPos)
    | 0x68uy -> struct (F32X4Floor, NoOperand, nextPos)
    | 0x69uy -> struct (F32X4Trunc, NoOperand, nextPos)
    | 0x6auy -> struct (F32X4Nearest, NoOperand, nextPos)
    | 0x74uy -> struct (F64X2Ceil, NoOperand, nextPos)
    | 0x75uy -> struct (F64X2Floor, NoOperand, nextPos)
    | 0x7auy -> struct (F64X2Trunc, NoOperand, nextPos)
    | 0x94uy -> struct (F64X2Nearest, NoOperand, nextPos)
    | 0xe0uy -> struct (F32X4Abs, NoOperand, nextPos)
    | 0xe1uy -> struct (F32X4Neg, NoOperand, nextPos)
    | 0xe3uy -> struct (F32X4Sqrt, NoOperand, nextPos)
    | 0xe4uy -> struct (F32X4Add, NoOperand, nextPos)
    | 0xe5uy -> struct (F32X4Sub, NoOperand, nextPos)
    | 0xe6uy -> struct (F32X4Mul, NoOperand, nextPos)
    | 0xe7uy -> struct (F32X4Div, NoOperand, nextPos)
    | 0xe8uy -> struct (F32X4Min, NoOperand, nextPos)
    | 0xe9uy -> struct (F32X4Max, NoOperand, nextPos)
    | 0xeauy -> struct (F32X4PMin, NoOperand, nextPos)
    | 0xebuy -> struct (F32X4PMax, NoOperand, nextPos)
    | 0xecuy -> struct (F64X2Abs, NoOperand, nextPos)
    | 0xeduy -> struct (F64X2Neg, NoOperand, nextPos)
    | 0xefuy -> struct (F64X2Sqrt, NoOperand, nextPos)
    | 0xf0uy -> struct (F64X2Add, NoOperand, nextPos)
    | 0xf1uy -> struct (F64X2Sub, NoOperand, nextPos)
    | 0xf2uy -> struct (F64X2Mul, NoOperand, nextPos)
    | 0xf3uy -> struct (F64X2Div, NoOperand, nextPos)
    | 0xf4uy -> struct (F64X2Min, NoOperand, nextPos)
    | 0xf5uy -> struct (F64X2Max, NoOperand, nextPos)
    | 0xf6uy -> struct (F64X2PMin, NoOperand, nextPos)
    | 0xf7uy -> struct (F64X2PMax, NoOperand, nextPos)
    | 0xf8uy -> struct (I32X4TruncSatF32X4S, NoOperand, nextPos)
    | 0xf9uy -> struct (I32X4TruncSatF32X4U, NoOperand, nextPos)
    | 0xfauy -> struct (F32X4ConvertI32X4S, NoOperand, nextPos)
    | 0xfbuy -> struct (F32X4ConvertI32X4U, NoOperand, nextPos)
    | 0xfcuy -> struct (I32X4TruncSatF64X2SZero, NoOperand, nextPos)
    | 0xfduy -> struct (I32X4TruncSatF64X2UZero, NoOperand, nextPos)
    | 0xfeuy -> struct (F64X2ConvertLowI32X4S, NoOperand, nextPos)
    | 0xffuy -> struct (F64X2ConvertLowI32X4U, NoOperand, nextPos)
    | _ -> raise ParsingFailureException
  | 0xfeuy ->
    let struct (bin, nextPos) = reader.ReadByte nextPos
    match bin with  
    | 0x00uy -> parseAtomicNotify reader nextPos MemoryAtomicNotify
    | 0x01uy -> parseAtomicWait reader nextPos MemoryAtomicWait32
    | 0x02uy -> parseAtomicWait reader nextPos MemoryAtomicWait64
    | 0x03uy -> parseAtomicFence reader nextPos AtomicFence
    | 0x10uy -> parseAtomicLoad reader nextPos I32AtomicLoad
    | 0x11uy -> parseAtomicLoad reader nextPos I64AtomicLoad
    | 0x12uy -> parseAtomicLoad reader nextPos I32AtomicLoad8U
    | 0x13uy -> parseAtomicLoad reader nextPos I32AtomicLoad16U
    | 0x14uy -> parseAtomicLoad reader nextPos I64AtomicLoad8U
    | 0x15uy -> parseAtomicLoad reader nextPos I64AtomicLoad16U
    | 0x16uy -> parseAtomicLoad reader nextPos I64AtomicLoad32U
    | 0x17uy -> parseAtomicStore reader nextPos I32AtomicStore
    | 0x18uy -> parseAtomicStore reader nextPos I64AtomicStore
    | 0x19uy -> parseAtomicStore reader nextPos I32AtomicStore8
    | 0x1auy -> parseAtomicStore reader nextPos I32AtomicStore16
    | 0x1buy -> parseAtomicStore reader nextPos I64AtomicStore8
    | 0x1cuy -> parseAtomicStore reader nextPos I64AtomicStore16
    | 0x1duy -> parseAtomicStore reader nextPos I64AtomicStore32
    | 0x1euy -> parseAtomicRmw reader nextPos I32AtomicRmwAdd
    | 0x1fuy -> parseAtomicRmw reader nextPos I64AtomicRmwAdd
    | 0x20uy -> parseAtomicRmw reader nextPos I32AtomicRmw8AddU
    | 0x21uy -> parseAtomicRmw reader nextPos I32AtomicRmw16AddU
    | 0x22uy -> parseAtomicRmw reader nextPos I64AtomicRmw8AddU
    | 0x23uy -> parseAtomicRmw reader nextPos I64AtomicRmw16AddU
    | 0x24uy -> parseAtomicRmw reader nextPos I64AtomicRmw32AddU
    | 0x25uy -> parseAtomicRmw reader nextPos I32AtomicRmwSub
    | 0x26uy -> parseAtomicRmw reader nextPos I64AtomicRmw8SubU
    | 0x27uy -> parseAtomicRmw reader nextPos I32AtomicRmw8SubU
    | 0x28uy -> parseAtomicRmw reader nextPos I32AtomicRmw16SubU
    | 0x29uy -> parseAtomicRmw reader nextPos I64AtomicRmw8SubU
    | 0x2auy -> parseAtomicRmw reader nextPos I64AtomicRmw16SubU
    | 0x2buy -> parseAtomicRmw reader nextPos I64AtomicRmw32SubU
    | 0x2cuy -> parseAtomicRmw reader nextPos I32AtomicRmwAnd
    | 0x2duy -> parseAtomicRmw reader nextPos I64AtomicRmwAnd
    | 0x2euy -> parseAtomicRmw reader nextPos I32AtomicRmw8AndU
    | 0x2fuy -> parseAtomicRmw reader nextPos I32AtomicRmw16AndU
    | 0x30uy -> parseAtomicRmw reader nextPos I64AtomicRmw8AndU
    | 0x31uy -> parseAtomicRmw reader nextPos I64AtomicRmw16AndU
    | 0x32uy -> parseAtomicRmw reader nextPos I64AtomicRmw32AndU
    | 0x33uy -> parseAtomicRmw reader nextPos I32AtomicRmwOr
    | 0x34uy -> parseAtomicRmw reader nextPos I64AtomicRmwOr
    | 0x35uy -> parseAtomicRmw reader nextPos I32AtomicRmw8OrU
    | 0x36uy -> parseAtomicRmw reader nextPos I32AtomicRmw16OrU
    | 0x37uy -> parseAtomicRmw reader nextPos I64AtomicRmw8OrU
    | 0x38uy -> parseAtomicRmw reader nextPos I64AtomicRmw16OrU
    | 0x39uy -> parseAtomicRmw reader nextPos I64AtomicRmw32OrU
    | 0x3auy -> parseAtomicRmw reader nextPos I32AtomicRmwXor
    | 0x3buy -> parseAtomicRmw reader nextPos I64AtomicRmwXor
    | 0x3cuy -> parseAtomicRmw reader nextPos I32AtomicRmw8XorU
    | 0x3duy -> parseAtomicRmw reader nextPos I32AtomicRmw16XorU
    | 0x3euy -> parseAtomicRmw reader nextPos I64AtomicRmw8XorU
    | 0x3fuy -> parseAtomicRmw reader nextPos I64AtomicRmw16XorU
    | 0x40uy -> parseAtomicRmw reader nextPos I64AtomicRmw32XorU
    | 0x41uy -> parseAtomicRmw reader nextPos I32AtomicRmwXchg
    | 0x42uy -> parseAtomicRmw reader nextPos I64AtomicRmwXchg
    | 0x43uy -> parseAtomicRmw reader nextPos I32AtomicRmw8XchgU
    | 0x44uy -> parseAtomicRmw reader nextPos I32AtomicRmw16XchgU
    | 0x45uy -> parseAtomicRmw reader nextPos I64AtomicRmw8XchgU
    | 0x46uy -> parseAtomicRmw reader nextPos I64AtomicRmw16XchgU
    | 0x47uy -> parseAtomicRmw reader nextPos I64AtomicRmw32XchgU
    | 0x48uy -> parseAtomicRmw reader nextPos I32AtomicRmwCmpxchg
    | 0x49uy -> parseAtomicRmw reader nextPos I64AtomicRmwCmpxchg
    | 0x4auy -> parseAtomicRmw reader nextPos I32AtomicRmw8CmpxchgU
    | 0x4buy -> parseAtomicRmw reader nextPos I32AtomicRmw16CmpxchgU
    | 0x4cuy -> parseAtomicRmw reader nextPos I64AtomicRmw8CmpxchgU
    | 0x4duy -> parseAtomicRmw reader nextPos I64AtomicRmw16CmpxchgU
    | 0x4euy -> parseAtomicRmw reader nextPos I64AtomicRmw32CmpxchgU
    | _ -> raise ParsingFailureException
  | 0x00uy -> struct (Unreachable, NoOperand, nextPos)
  | 0x01uy -> struct (Nop, NoOperand, nextPos)
  | 0x02uy -> parseType reader nextPos Block
  | 0x03uy -> parseType reader nextPos Loop
  | 0x04uy -> parseType reader nextPos If
  | 0x05uy -> struct (Else, NoOperand, nextPos)
  | 0x06uy -> parseType reader nextPos Try
  | 0x07uy -> parseIndex reader nextPos Catch
  | 0x08uy -> parseIndex reader nextPos Throw
  | 0x09uy -> parseIndex reader nextPos Rethrow
  | 0x0buy -> struct (End, NoOperand, nextPos)
  | 0x0cuy -> parseIndex reader nextPos Br
  | 0x0duy -> parseIndex reader nextPos BrIf
  | 0x0euy ->
    let struct (count, nextPos) = parseCount reader nextPos
    let struct (operands, nextPos) = parseIndices reader nextPos count []
    struct (BrTable, Operands operands, nextPos)
  | 0x0fuy -> struct (Return, NoOperand, nextPos)
  | 0x10uy -> parseIndex reader nextPos Call
  | 0x11uy ->
    let struct (sigIndex, nextPos) = readIndex reader nextPos
    let struct (tableIndex, nextPos) = readIndex reader nextPos
    struct (CallIndirect, TwoOperands (sigIndex, tableIndex), nextPos)
  | 0x12uy -> parseIndex reader nextPos ReturnCall
  | 0x13uy ->
    let struct (sigIndex, nextPos) = readIndex reader nextPos
    let struct (tableIndex, nextPos) = readIndex reader nextPos
    struct (ReturnCallIndirect, TwoOperands (sigIndex, tableIndex), nextPos)
  | 0x14uy -> struct (CallRef, NoOperand, nextPos)
  | 0x18uy -> parseIndex reader nextPos Delegate
  | 0x19uy -> struct (CatchAll, NoOperand, nextPos)
  | 0x1auy -> struct (Drop, NoOperand, nextPos)
  | 0x1buy -> struct (Select, NoOperand, nextPos)
  | 0x1cuy ->
    let struct (cnt, nextPos) = parseCount reader nextPos
    let struct (operands, nextPos) = parseTypes reader nextPos cnt []
    struct (SelectT, Operands operands, nextPos)
  | 0x20uy -> parseIndex reader nextPos LocalGet
  | 0x21uy -> parseIndex reader nextPos LocalSet
  | 0x22uy -> parseIndex reader nextPos LocalTee
  | 0x23uy -> parseIndex reader nextPos GlobalGet
  | 0x24uy -> parseIndex reader nextPos GlobalSet
  | 0x28uy -> parseLoad reader nextPos I32Load
  | 0x29uy -> parseLoad reader nextPos I64Load
  | 0x2auy -> parseLoad reader nextPos F32Load
  | 0x2buy -> parseLoad reader nextPos F64Load
  | 0x2cuy -> parseLoad reader nextPos I32Load8S
  | 0x2duy -> parseLoad reader nextPos I32Load8U
  | 0x2euy -> parseLoad reader nextPos I32Load16S
  | 0x2fuy -> parseLoad reader nextPos I32Load16U
  | 0x30uy -> parseLoad reader nextPos I64Load8S
  | 0x31uy -> parseLoad reader nextPos I64Load8U
  | 0x32uy -> parseLoad reader nextPos I64Load16S
  | 0x33uy -> parseLoad reader nextPos I64Load16U
  | 0x34uy -> parseLoad reader nextPos I64Load32S
  | 0x35uy -> parseLoad reader nextPos I64Load32U
  | 0x36uy -> parseStore reader nextPos I32Store
  | 0x37uy -> parseStore reader nextPos I64Store
  | 0x38uy -> parseStore reader nextPos F32Store
  | 0x39uy -> parseStore reader nextPos F64Store
  | 0x3auy -> parseStore reader nextPos I32Store8
  | 0x3buy -> parseStore reader nextPos I32Store16
  | 0x3cuy -> parseStore reader nextPos I64Store8
  | 0x3duy -> parseStore reader nextPos I64Store16
  | 0x3euy -> parseStore reader nextPos I64Store32
  | 0x3fuy -> parseIndex reader nextPos MemorySize 
  | 0x40uy -> parseIndex reader nextPos MemoryGrow
  | 0x41uy -> parseU32LEB128 reader nextPos I32Const
  | 0x42uy -> parseU64LEB128 reader nextPos I64Const
  | 0x43uy -> parseF32 reader nextPos F32Const
  | 0x44uy -> parseF64 reader nextPos F64Const
  | 0x45uy -> struct (I32Eqz, NoOperand, nextPos)
  | 0x46uy -> struct (I32Eq, NoOperand, nextPos)
  | 0x47uy -> struct (I32Ne, NoOperand, nextPos)
  | 0x48uy -> struct (I32LtS, NoOperand, nextPos)
  | 0x49uy -> struct (I32LtU, NoOperand, nextPos)
  | 0x4auy -> struct (I32GtS, NoOperand, nextPos)
  | 0x4buy -> struct (I32GtU, NoOperand, nextPos)
  | 0x4cuy -> struct (I32LeS, NoOperand, nextPos)
  | 0x4duy -> struct (I32LeU, NoOperand, nextPos)
  | 0x4euy -> struct (I32GeS, NoOperand, nextPos)
  | 0x4fuy -> struct (I32GeU, NoOperand, nextPos)
  | 0x50uy -> struct (I64Eqz, NoOperand, nextPos)
  | 0x51uy -> struct (I64Eq, NoOperand, nextPos)
  | 0x52uy -> struct (I64Ne, NoOperand, nextPos)
  | 0x53uy -> struct (I64LtS, NoOperand, nextPos)
  | 0x54uy -> struct (I64LtU, NoOperand, nextPos)
  | 0x55uy -> struct (I64GtS, NoOperand, nextPos)
  | 0x56uy -> struct (I64GtU, NoOperand, nextPos)
  | 0x57uy -> struct (I64LeS, NoOperand, nextPos)
  | 0x58uy -> struct (I64LeU, NoOperand, nextPos)
  | 0x59uy -> struct (I64GeS, NoOperand, nextPos)
  | 0x5auy -> struct (I64GeU, NoOperand, nextPos)
  | 0x5buy -> struct (F32Eq, NoOperand, nextPos)
  | 0x5cuy -> struct (F32Ne, NoOperand, nextPos)
  | 0x5duy -> struct (F32Lt, NoOperand, nextPos)
  | 0x5euy -> struct (F32Gt, NoOperand, nextPos)
  | 0x5fuy -> struct (F32Le, NoOperand, nextPos)
  | 0x60uy -> struct (F32Ge, NoOperand, nextPos)
  | 0x61uy -> struct (F64Eq, NoOperand, nextPos)
  | 0x62uy -> struct (F64Ne, NoOperand, nextPos)
  | 0x63uy -> struct (F64Lt, NoOperand, nextPos)
  | 0x64uy -> struct (F64Gt, NoOperand, nextPos)
  | 0x65uy -> struct (F64Le, NoOperand, nextPos)
  | 0x66uy -> struct (F64Ge, NoOperand, nextPos)
  | 0x67uy -> struct (I32Clz, NoOperand, nextPos)
  | 0x68uy -> struct (I32Ctz, NoOperand, nextPos)
  | 0x69uy -> struct (I32Popcnt, NoOperand, nextPos)
  | 0x6auy -> struct (I32Add, NoOperand, nextPos)
  | 0x6buy -> struct (I32Sub, NoOperand, nextPos)
  | 0x6cuy -> struct (I32Mul, NoOperand, nextPos)
  | 0x6duy -> struct (I32DivS, NoOperand, nextPos)
  | 0x6euy -> struct (I32DivU, NoOperand, nextPos)
  | 0x6fuy -> struct (I32RemS, NoOperand, nextPos)
  | 0x70uy -> struct (I32RemU, NoOperand, nextPos)
  | 0x71uy -> struct (I32And, NoOperand, nextPos)
  | 0x72uy -> struct (I32Or, NoOperand, nextPos)
  | 0x73uy -> struct (I32Xor, NoOperand, nextPos)
  | 0x74uy -> struct (I32Shl, NoOperand, nextPos)
  | 0x75uy -> struct (I32ShrS, NoOperand, nextPos)
  | 0x76uy -> struct (I32ShrU, NoOperand, nextPos)
  | 0x77uy -> struct (I32Rotl, NoOperand, nextPos)
  | 0x78uy -> struct (I32Rotr, NoOperand, nextPos)
  | 0x79uy -> struct (I64Clz, NoOperand, nextPos)
  | 0x7auy -> struct (I64Ctz, NoOperand, nextPos)
  | 0x7buy -> struct (I64Popcnt, NoOperand, nextPos)
  | 0x7cuy -> struct (I64Add, NoOperand, nextPos)
  | 0x7duy -> struct (I64Sub, NoOperand, nextPos)
  | 0x7euy -> struct (I64Mul, NoOperand, nextPos)
  | 0x7fuy -> struct (I64DivS, NoOperand, nextPos)
  | 0x80uy -> struct (I64DivU, NoOperand, nextPos)
  | 0x81uy -> struct (I64RemS, NoOperand, nextPos)
  | 0x82uy -> struct (I64RemU, NoOperand, nextPos)
  | 0x83uy -> struct (I64And, NoOperand, nextPos)
  | 0x84uy -> struct (I64Or, NoOperand, nextPos)
  | 0x85uy -> struct (I64Xor, NoOperand, nextPos)
  | 0x86uy -> struct (I64Shl, NoOperand, nextPos)
  | 0x87uy -> struct (I64ShrS, NoOperand, nextPos)
  | 0x88uy -> struct (I64ShrU, NoOperand, nextPos)
  | 0x89uy -> struct (I64Rotl, NoOperand, nextPos)
  | 0x8auy -> struct (I64Rotr, NoOperand, nextPos)
  | 0x8buy -> struct (F32Abs, NoOperand, nextPos)
  | 0x8cuy -> struct (F32Neg, NoOperand, nextPos)
  | 0x8duy -> struct (F32Ceil, NoOperand, nextPos)
  | 0x8euy -> struct (F32Floor, NoOperand, nextPos)
  | 0x8fuy -> struct (F32Trunc, NoOperand, nextPos)
  | 0x90uy -> struct (F32Nearest, NoOperand, nextPos)
  | 0x91uy -> struct (F32Sqrt, NoOperand, nextPos)
  | 0x92uy -> struct (F32Add, NoOperand, nextPos)
  | 0x93uy -> struct (F32Sub, NoOperand, nextPos)
  | 0x94uy -> struct (F32Mul, NoOperand, nextPos)
  | 0x95uy -> struct (F32Div, NoOperand, nextPos)
  | 0x96uy -> struct (F32Min, NoOperand, nextPos)
  | 0x97uy -> struct (F32Max, NoOperand, nextPos)
  | 0x98uy -> struct (F32Copysign, NoOperand, nextPos)
  | 0x99uy -> struct (F64Abs, NoOperand, nextPos)
  | 0x9auy -> struct (F64Neg, NoOperand, nextPos)
  | 0x9buy -> struct (F64Ceil, NoOperand, nextPos)
  | 0x9cuy -> struct (F64Floor, NoOperand, nextPos)
  | 0x9duy -> struct (F64Trunc, NoOperand, nextPos)
  | 0x9euy -> struct (F64Nearest, NoOperand, nextPos)
  | 0x9fuy -> struct (F64Sqrt, NoOperand, nextPos)
  | 0xa0uy -> struct (F64Add, NoOperand, nextPos)
  | 0xa1uy -> struct (F64Sub, NoOperand, nextPos)
  | 0xa2uy -> struct (F64Mul, NoOperand, nextPos)
  | 0xa3uy -> struct (F64Div, NoOperand, nextPos)
  | 0xa4uy -> struct (F64Min, NoOperand, nextPos)
  | 0xa5uy -> struct (F64Max, NoOperand, nextPos)
  | 0xa6uy -> struct (F64Copysign, NoOperand, nextPos)
  | 0xa7uy -> struct (I32WrapI64, NoOperand, nextPos)
  | 0xa8uy -> struct (I32TruncF32S, NoOperand, nextPos)
  | 0xa9uy -> struct (I32TruncF32U, NoOperand, nextPos)
  | 0xaauy -> struct (I32TruncF64S, NoOperand, nextPos)
  | 0xabuy -> struct (I32TruncF64U, NoOperand, nextPos)
  | 0xacuy -> struct (I64ExtendI32S, NoOperand, nextPos)
  | 0xaduy -> struct (I64ExtendI32U, NoOperand, nextPos)
  | 0xaeuy -> struct (I64TruncF32S, NoOperand, nextPos)
  | 0xafuy -> struct (I64TruncF32U, NoOperand, nextPos)
  | 0xb0uy -> struct (I64TruncF64S, NoOperand, nextPos)
  | 0xb1uy -> struct (I64TruncF64U, NoOperand, nextPos)
  | 0xb2uy -> struct (F32ConvertI32S, NoOperand, nextPos)
  | 0xb3uy -> struct (F32ConvertI32U, NoOperand, nextPos)
  | 0xb4uy -> struct (F32ConvertI64S, NoOperand, nextPos)
  | 0xb5uy -> struct (F32ConvertI64U, NoOperand, nextPos)
  | 0xb6uy -> struct (F32DemoteF64, NoOperand, nextPos)
  | 0xb7uy -> struct (F64ConvertI32S, NoOperand, nextPos)
  | 0xb8uy -> struct (F64ConvertI32U, NoOperand, nextPos)
  | 0xb9uy -> struct (F64ConvertI64S, NoOperand, nextPos)
  | 0xbauy -> struct (F64ConvertI64U, NoOperand, nextPos)
  | 0xbbuy -> struct (F64PromoteF32, NoOperand, nextPos)
  | 0xbcuy -> struct (I32ReinterpretF32, NoOperand, nextPos)
  | 0xbduy -> struct (I64ReinterpretF64, NoOperand, nextPos)
  | 0xbeuy -> struct (F32ReinterpretI32, NoOperand, nextPos)
  | 0xbfuy -> struct (F64ReinterpretI64, NoOperand, nextPos)
  | 0xc0uy -> struct (I32Extend8S, NoOperand, nextPos)
  | 0xc1uy -> struct (I32Extend16S, NoOperand, nextPos)
  | 0xc2uy -> struct (I64Extend8S, NoOperand, nextPos)
  | 0xc3uy -> struct (I64Extend16S, NoOperand, nextPos)
  | 0xc4uy -> struct (I64Extend32S, NoOperand, nextPos)
  | 0xe0uy -> struct (InterpAlloca, NoOperand, nextPos)
  | 0xe1uy -> struct (InterpBrUnless, NoOperand, nextPos)
  | 0xe2uy -> struct (InterpCallImport, NoOperand, nextPos)
  | 0xe3uy -> struct (InterpData, NoOperand, nextPos)
  | 0xe4uy -> struct (InterpDropKeep, NoOperand, nextPos)
  | 0xe5uy -> struct (InterpCatchDrop, NoOperand, nextPos)
  | 0xe6uy -> struct (InterpAdjustFrameForReturnCall, NoOperand, nextPos)
  | 0x25uy -> parseIndex reader nextPos TableGet
  | 0x26uy -> parseIndex reader nextPos TableSet
  | 0xd0uy -> struct (RefNull, NoOperand, nextPos)
  | 0xd1uy -> struct (RefIsNull, NoOperand, nextPos)
  | 0xd2uy -> parseIndex reader nextPos RefFunc
  | _ -> raise ParsingFailureException

let parse (reader: BinReader) wordSize addr pos =
  let struct (opcode, operands, nextPos) = parseInstruction reader pos
  let instrLen = nextPos - pos |> uint32
  let insInfo =
    { Address = addr
      NumBytes = instrLen
      Opcode = opcode
      Operands = operands }
  WASMInstruction (addr, instrLen, insInfo, wordSize)

// vim: set tw=80 sts=2 sw=2: