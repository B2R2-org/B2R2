module internal B2R2.FrontEnd.BinLifter.WASM.Disasm

open B2R2
open B2R2.FrontEnd.BinLifter

let opcodeToString = function
  | Unreachable -> "unreachable"
  | Nop -> "nop"
  | Block -> "block"
  | Loop -> "loop"
  | If -> "if"
  | Else -> "else"
  | Try -> "try"
  | Catch -> "catch"
  | Throw -> "throw"
  | Rethrow -> "rethrow"
  | End -> "end"
  | Br -> "br"
  | BrIf -> "br_if"
  | BrTable -> "br_table"
  | Return -> "return"
  | Call -> "call"
  | CallIndirect -> "call_indirect"
  | ReturnCall -> "return_call"
  | ReturnCallIndirect -> "return_call_indirect"
  | CallRef -> "call_ref"
  | Delegate -> "delegate"
  | CatchAll -> "catch_all"
  | Drop -> "drop"
  | Select -> "select"
  | SelectT -> "select"
  | LocalGet -> "local.get"
  | LocalSet -> "local.set"
  | LocalTee -> "local.tee"
  | GlobalGet -> "global.get"
  | GlobalSet-> "global.set"
  | I32Load -> "i32.load"
  | I64Load -> "i64.load"
  | F32Load -> "f32.load"
  | F64Load -> "f64.load"
  | I32Load8S -> "i32.load8_s"
  | I32Load8U -> "i32.load8_u"
  | I32Load16S -> "i32.load16_s"
  | I32Load16U -> "i32.load16_u"
  | I64Load8S -> "i64.load8_s"
  | I64Load8U -> "i64.load8_u"
  | I64Load16S -> "i64.load16_s"
  | I64Load16U -> "i64.load16_u"
  | I64Load32S -> "i64.load32_s"
  | I64Load32U -> "i64.load32_u"
  | I32Store -> "i32.store"
  | I64Store -> "i64.store"
  | F32Store -> "f32.store"
  | F64Store -> "f64.store"
  | I32Store8 -> "i32.store8"
  | I32Store16 -> "i32.store16"
  | I64Store8 -> "i64.store8"
  | I64Store16 -> "i64.store16"
  | I64Store32 -> "i64.store32"
  | MemorySize -> "memory.size"
  | MemoryGrow -> "memory.grow"
  | I32Const -> "i32.const"
  | I64Const -> "i64.const"
  | F32Const -> "f32.const"
  | F64Const -> "f64.const"
  | I32Eqz -> "i32.eqz"
  | I32Eq -> "i32.eq"
  | I32Ne -> "i32.ne"
  | I32LtS -> "i32.lt_s"
  | I32LtU -> "i32.lt_u"
  | I32GtS -> "i32.gt_s"
  | I32GtU -> "i32.gt_u"
  | I32LeS -> "i32.le_s"
  | I32LeU -> "i32.le_u"
  | I32GeS -> "i32.ge_s"
  | I32GeU -> "i32.ge_u"
  | I64Eqz -> "i64.eqz"
  | I64Eq -> "i64.eq"
  | I64Ne -> "i64.ne"
  | I64LtS -> "i64.lt_s"
  | I64LtU -> "i64.lt_u"
  | I64GtS -> "i64.gt_s"
  | I64GtU -> "i64.gt_u"
  | I64LeS -> "i64.le_s"
  | I64LeU -> "i64.le_u"
  | I64GeS -> "i64.ge_s"
  | I64GeU -> "i64.ge_u"
  | F32Eq -> "f32.eq"
  | F32Ne -> "f32.ne"
  | F32Lt -> "f32.lt"
  | F32Gt -> "f32.gt"
  | F32Le -> "f32.le"
  | F32Ge -> "f32.ge"
  | F64Eq -> "f64.eq"
  | F64Ne -> "f64.ne"
  | F64Lt -> "f64.lt"
  | F64Gt -> "f64.gt"
  | F64Le -> "f64.le"
  | F64Ge -> "f64.ge"
  | I32Clz -> "i32.clz"
  | I32Ctz -> "i32.ctz"
  | I32Popcnt -> "i32.popcnt"
  | I32Add -> "i32.add"
  | I32Sub -> "i32.sub"
  | I32Mul -> "i32.mul"
  | I32DivS -> "i32.div_s"
  | I32DivU -> "i32.div_u"
  | I32RemS -> "i32.rem_s"
  | I32RemU -> "i32.rem_u"
  | I32And -> "i32.and"
  | I32Or -> "i32.or"
  | I32Xor -> "i32.xor"
  | I32Shl -> "i32.shl"
  | I32ShrS -> "i32.shr_s"
  | I32ShrU -> "i32.shr_u"
  | I32Rotl -> "i32.rotl"
  | I32Rotr -> "i32.rotr"
  | I64Clz -> "i64.clz"
  | I64Ctz -> "i64.ctz"
  | I64Popcnt -> "i64.popcnt"
  | I64Add -> "i64.add"
  | I64Sub -> "i64.sub"
  | I64Mul -> "i64.mul"
  | I64DivS -> "i64.div_s"
  | I64DivU -> "i64.div_u"
  | I64RemS -> "i64.rem_s"
  | I64RemU -> "i64.rem_u"
  | I64And -> "i64.and"
  | I64Or -> "i64.or"
  | I64Xor -> "i64.xor"
  | I64Shl -> "i64.shl"
  | I64ShrS -> "i64.shr_s"
  | I64ShrU -> "i64.shr_u"
  | I64Rotl -> "i64.rotl"
  | I64Rotr -> "i64.rotr"
  | F32Abs -> "f32.abs"
  | F32Neg -> "f32.neg"
  | F32Ceil -> "f32.ceil"
  | F32Floor -> "f32.floor"
  | F32Trunc -> "f32.trunc"
  | F32Nearest -> "f32.nearest"
  | F32Sqrt -> "f32.sqrt"
  | F32Add -> "f32.add"
  | F32Sub -> "f32.sub"
  | F32Mul -> "f32.mul"
  | F32Div -> "f32.div"
  | F32Min -> "f32.min"
  | F32Max -> "f32.max"
  | F32Copysign -> "f32.copysign"
  | F64Abs -> "f64.abs"
  | F64Neg -> "f64.neg"
  | F64Ceil -> "f64.ceil"
  | F64Floor -> "f64.floor"
  | F64Trunc -> "f64.trunc"
  | F64Nearest -> "f64.nearest"
  | F64Sqrt -> "f64.sqrt"
  | F64Add -> "f64.add"
  | F64Sub -> "f64.sub"
  | F64Mul -> "f64.mul"
  | F64Div -> "f64.div"
  | F64Min -> "f64.min"
  | F64Max -> "f64.max"
  | F64Copysign -> "f64.copysign"
  | I32WrapI64 -> "i32.wrap_i64"
  | I32TruncF32S -> "i32.trunc_f32_s"
  | I32TruncF32U -> "i32.trunc_f32_u"
  | I32TruncF64S -> "i32.trunc_f64_s"
  | I32TruncF64U -> "i32.trunc_f64_u"
  | I64ExtendI32S -> "i64.extend_i32_s"
  | I64ExtendI32U -> "i64.extend_i32_u"
  | I64TruncF32S -> "i64.trunc_f32_s"
  | I64TruncF32U -> "i64.trunc_f32_u"
  | I64TruncF64S -> "i64.trunc_f64_s"
  | I64TruncF64U -> "i64.trunc_f64_u"
  | F32ConvertI32S -> "f32.convert_i32_s"
  | F32ConvertI32U -> "f32.convert_i32_u"
  | F32ConvertI64S -> "f32.convert_i64_s"
  | F32ConvertI64U -> "f32.convert_i64_u"
  | F32DemoteF64 -> "f32.demote_f64"
  | F64ConvertI32S -> "f64.convert_i32_s"
  | F64ConvertI32U -> "f64.convert_i32_u"
  | F64ConvertI64S -> "f64.convert_i64_s"
  | F64ConvertI64U -> "f64.convert_i64_u"
  | F64PromoteF32 -> "f64.promote_f32"
  | I32ReinterpretF32 -> "i32.reinterpret_f32"
  | I64ReinterpretF64 -> "i64.reinterpret_f64"
  | F32ReinterpretI32 -> "f32.reinterpret_i32"
  | F64ReinterpretI64 -> "f64.reinterpret_i64"
  | I32Extend8S -> "i32.extend8_s"
  | I32Extend16S -> "i32.extend16_s"
  | I64Extend8S -> "i64.extend8_s"
  | I64Extend16S -> "i64.extend16_s"
  | I64Extend32S -> "i64.extend32_s"
  | InterpAlloca -> "alloca"
  | InterpBrUnless -> "br_unless"
  | InterpCallImport -> "call_import"
  | InterpData -> "data"
  | InterpDropKeep -> "drop_keep"
  | InterpCatchDrop -> "catch_drop"
  | InterpAdjustFrameForReturnCall -> "adjust_frame_for_return_call"
  | I32TruncSatF32S -> "i32.trunc_sat_f32_s"
  | I32TruncSatF32U -> "i32.trunc_sat_f32_u"
  | I32TruncSatF64S -> "i32.trunc_sat_f64_s"
  | I32TruncSatF64U -> "i32.trunc_sat_f64_u"
  | I64TruncSatF32S -> "i64.trunc_sat_f32_s"
  | I64TruncSatF32U -> "i64.trunc_sat_f32_u"
  | I64TruncSatF64S -> "i64.trunc_sat_f64_s"
  | I64TruncSatF64U -> "i64.trunc_sat_f64_u"
  | MemoryInit -> "memory.init"
  | DataDrop -> "data.drop"
  | MemoryCopy -> "memory.copy"
  | MemoryFill -> "memory.fill"
  | TableInit -> "table.init"
  | ElemDrop -> "elem.drop"
  | TableCopy -> "table.copy"
  | TableGet -> "table.get"
  | TableSet -> "table.set"
  | TableGrow -> "table.grow"
  | TableSize -> "table.size"
  | TableFill -> "table.fill"
  | RefNull -> "ref.null"
  | RefIsNull -> "ref.is_null"
  | RefFunc -> "ref.func"
  | V128Load ->  "v128.load"
  | V128Load8X8S -> "v128.load8x8_s"
  | V128Load8X8U -> "v128.load8x8_u"
  | V128Load16X4S -> "v128.load16x4_s"
  | V128Load16X4U -> "v128.load16x4_u"
  | V128Load32X2S -> "v128.load32x2_s"
  | V128Load32X2U -> "v128.load32x2_u"
  | V128Load8Splat -> "v128.load8_splat"
  | V128Load16Splat -> "v128.load16_splat"
  | V128Load32Splat -> "v128.load32_splat"
  | V128Load64Splat -> "v128.load64_splat"
  | V128Store -> "v128.store"
  | V128Const -> "v128.const"
  | I8X16Shuffle -> "i8x16.shuffle"
  | I8X16Swizzle -> "i8x16.swizzle"
  | I8X16Splat -> "i8x16.splat"
  | I16X8Splat -> "i16x8.splat"
  | I32X4Splat -> "i32x4.splat"
  | I64X2Splat -> "i64x2.splat"
  | F32X4Splat -> "f32x4.splat"
  | F64X2Splat -> "f64x2.splat"
  | I8X16ExtractLaneS -> "i8x16.extract_lane_s"
  | I8X16ExtractLaneU -> "i8x16.extract_lane_u"
  | I8X16ReplaceLane -> "i8x16.replace_lane"
  | I16X8ExtractLaneS -> "i16x8.extract_lane_s"
  | I16X8ExtractLaneU -> "i16x8.extract_lane_u"
  | I16X8ReplaceLane -> "i16x8.replace_lane"
  | I32X4ExtractLane -> "i32x4.extract_lane"
  | I32X4ReplaceLane -> "i32x4.replace_lane"
  | I64X2ExtractLane -> "i64x2.extract_lane"
  | I64X2ReplaceLane -> "i64x2.replace_lane"
  | F32X4ExtractLane -> "f32x4.extract_lane"
  | F32X4ReplaceLane -> "f32x4.replace_lane"
  | F64X2ExtractLane -> "f64x2.extract_lane"
  | F64X2ReplaceLane -> "f64x2.replace_lane"
  | I8X16Eq -> "i8x16.eq"
  | I8X16Ne -> "i8x16.ne"
  | I8X16LtS -> "i8x16.lt_s"
  | I8X16LtU -> "i8x16.lt_u"
  | I8X16GtS -> "i8x16.gt_s"
  | I8X16GtU -> "i8x16.gt_u"
  | I8X16LeS -> "i8x16.le_s"
  | I8X16LeU -> "i8x16.le_u"
  | I8X16GeS -> "i8x16.ge_s"
  | I8X16GeU -> "i8x16.ge_u"
  | I16X8Eq -> "i16x8.eq"
  | I16X8Ne -> "i16x8.ne"
  | I16X8LtS -> "i16x8.lt_s"
  | I16X8LtU -> "i16x8.lt_u"
  | I16X8GtS -> "i16x8.gt_s"
  | I16X8GtU -> "i16x8.gt_u"
  | I16X8LeS -> "i16x8.le_s"
  | I16X8LeU -> "i16x8.le_u"
  | I16X8GeS -> "i16x8.ge_s"
  | I16X8GeU -> "i16x8.ge_u"
  | I32X4Eq -> "i32x4.eq"
  | I32X4Ne -> "i32x4.ne"
  | I32X4LtS -> "i32x4.lt_s"
  | I32X4LtU -> "i32x4.lt_u"
  | I32X4GtS -> "i32x4.gt_s"
  | I32X4GtU -> "i32x4.gt_u"
  | I32X4LeS -> "i32x4.le_s"
  | I32X4LeU -> "i32x4.le_u"
  | I32X4GeS -> "i32x4.ge_s"
  | I32X4GeU -> "i32x4.ge_u"
  | F32X4Eq -> "f32x4.eq"
  | F32X4Ne -> "f32x4.ne"
  | F32X4Lt -> "f32x4.lt"
  | F32X4Gt -> "f32x4.gt"
  | F32X4Le -> "f32x4.le"
  | F32X4Ge -> "f32x4.ge"
  | F64X2Eq -> "f64x2.eq"
  | F64X2Ne -> "f64x2.ne"
  | F64X2Lt -> "f64x2.lt"
  | F64X2Gt -> "f64x2.gt"
  | F64X2Le -> "f64x2.le"
  | F64X2Ge -> "f64x2.ge"
  | V128Not -> "v128.not"
  | V128And -> "v128.and"
  | V128Andnot -> "v128.andnot"
  | V128Or ->  "v128.or"
  | V128Xor -> "v128.xor"
  | V128BitSelect -> "v128.bitselect"
  | V128AnyTrue -> "v128.any_true"
  | V128Load8Lane -> "v128.load8_lane"
  | V128Load16Lane -> "v128.load16_lane"
  | V128Load32Lane -> "v128.load32_lane"
  | V128Load64Lane -> "v128.load64_lane"
  | V128Store8Lane -> "v128.store8_lane"
  | V128Store16Lane -> "v128.store16_lane"
  | V128Store32Lane -> "v128.store32_lane"
  | V128Store64Lane -> "v128.store64_lane"
  | V128Load32Zero -> "v128.load32_zero"
  | V128Load64Zero -> "v128.load64_zero"
  | F32X4DemoteF64X2Zero -> "f32x4.demote_f64x2_zero"
  | F64X2PromoteLowF32X4 -> "f64x2.promote_low_f32x4"
  | I8X16Abs -> "i8x16.abs"
  | I8X16Neg -> "i8x16.neg"
  | I8X16Popcnt -> "i8x16.popcnt"
  | I8X16AllTrue -> "i8x16.all_true"
  | I8X16Bitmask -> "i8x16.bitmask"
  | I8X16NarrowI16X8S -> "i8x16.narrow_i16x8_s"
  | I8X16NarrowI16X8U -> "i8x16.narrow_i16x8_u"
  | I8X16Shl -> "i8x16.shl"
  | I8X16ShrS -> "i8x16.shr_s"
  | I8X16ShrU -> "i8x16.shr_u"
  | I8X16Add -> "i8x16.add"
  | I8X16AddSatS -> "i8x16.add_sat_s"
  | I8X16AddSatU -> "i8x16.add_sat_u"
  | I8X16Sub -> "i8x16.sub"
  | I8X16SubSatS -> "i8x16.sub_sat_s"
  | I8X16SubSatU -> "i8x16.sub_sat_u"
  | I8X16MinS -> "i8x16.min_s"
  | I8X16MinU -> "i8x16.min_u"
  | I8X16MaxS -> "i8x16.max_s"
  | I8X16MaxU -> "i8x16.max_u"
  | I8X16AvgrU -> "i8x16.avgr_u"
  | I16X8ExtaddPairwiseI8X16S -> "i16x8.extadd_pairwise_i8x16_s"
  | I16X8ExtaddPairwiseI8X16U -> "i16x8.extadd_pairwise_i8x16_u"
  | I32X4ExtaddPairwiseI16X8S -> "i32x4.extadd_pairwise_i16x8_s"
  | I32X4ExtaddPairwiseI16X8U -> "i32x4.extadd_pairwise_i16x8_u"
  | I16X8Abs -> "i16x8.abs"
  | I16X8Neg -> "i16x8.neg"
  | I16X8Q15mulrSatS -> "i16x8.q15mulr_sat_s"
  | I16X8AllTrue -> "i16x8.all_true"
  | I16X8Bitmask -> "i16x8.bitmask"
  | I16X8NarrowI32X4S -> "i16x8.narrow_i32x4_s"
  | I16X8NarrowI32X4U -> "i16x8.narrow_i32x4_u"
  | I16X8ExtendLowI8X16S -> "i16x8.extend_low_i8x16_s"
  | I16X8ExtendHighI8X16S -> "i16x8.extend_high_i8x16_s"
  | I16X8ExtendLowI8X16U -> "i16x8.extend_low_i8x16_u"
  | I16X8ExtendHighI8X16U -> "i16x8.extend_high_i8x16_u"
  | I16X8Shl -> "i16x8.shl"
  | I16X8ShrS -> "i16x8.shr_s"
  | I16X8ShrU -> "i16x8.shr_u"
  | I16X8Add -> "i16x8.add"
  | I16X8AddSatS -> "i16x8.add_sat_s"
  | I16X8AddSatU -> "i16x8.add_sat_u"
  | I16X8Sub -> "i16x8.sub"
  | I16X8SubSatS -> "i16x8.sub_sat_s"
  | I16X8SubSatU -> "i16x8.sub_sat_u"
  | I16X8Mul -> "i16x8.mul"
  | I16X8MinS -> "i16x8.min_s"
  | I16X8MinU -> "i16x8.min_u"
  | I16X8MaxS -> "i16x8.max_s"
  | I16X8MaxU -> "i16x8.max_u"
  | I16X8AvgrU -> "i16x8.avgr_u"
  | I16X8ExtmulLowI8X16S -> "i16x8.extmul_low_i8x16_s"
  | I16X8ExtmulHighI8X16S -> "i16x8.extmul_high_i8x16_s"
  | I16X8ExtmulLowI8X16U -> "i16x8.extmul_low_i8x16_u"
  | I16X8ExtmulHighI8X16U -> "i16x8.extmul_high_i8x16_u"
  | I32X4Abs -> "i32x4.abs"
  | I32X4Neg -> "i32x4.neg"
  | I32X4AllTrue -> "i32x4.all_true"
  | I32X4Bitmask -> "i32x4.bitmask"
  | I32X4ExtendLowI16X8S -> "i32x4.extend_low_i16x8_s"
  | I32X4ExtendHighI16X8S -> "i32x4.extend_high_i16x8_s"
  | I32X4ExtendLowI16X8U -> "i32x4.extend_low_i16x8_u"
  | I32X4ExtendHighI16X8U -> "i32x4.extend_high_i16x8_u"
  | I32X4Shl -> "i32x4.shl"
  | I32X4ShrS -> "i32x4.shr_s"
  | I32X4ShrU -> "i32x4.shr_u"
  | I32X4Add -> "i32x4.add"
  | I32X4Sub -> "i32x4.sub"
  | I32X4Mul -> "i32x4.mul"
  | I32X4MinS -> "i32x4.min_s"
  | I32X4MinU -> "i32x4.min_u"
  | I32X4MaxS -> "i32x4.max_s"
  | I32X4MaxU -> "i32x4.max_u"
  | I32X4DotI16X8S -> "i32x4.dot_i16x8_s"
  | I32X4ExtmulLowI16X8S -> "i32x4.extmul_low_i16x8_s"
  | I32X4ExtmulHighI16X8S -> "i32x4.extmul_high_i16x8_s"
  | I32X4ExtmulLowI16X8U -> "i32x4.extmul_low_i16x8_u"
  | I32X4ExtmulHighI16X8U -> "i32x4.extmul_high_i16x8_u"
  | I64X2Abs -> "i64x2.abs"
  | I64X2Neg -> "i64x2.neg"
  | I64X2AllTrue -> "i64x2.all_true"
  | I64X2Bitmask -> "i64x2.bitmask"
  | I64X2ExtendLowI32X4S -> "i64x2.extend_low_i32x4_s"
  | I64X2ExtendHighI32X4S -> "i64x2.extend_high_i32x4_s"
  | I64X2ExtendLowI32X4U -> "i64x2.extend_low_i32x4_u"
  | I64X2ExtendHighI32X4U -> "i64x2.extend_high_i32x4_u"
  | I64X2Shl -> "i64x2.shl"
  | I64X2ShrS -> "i64x2.shr_s"
  | I64X2ShrU -> "i64x2.shr_u"
  | I64X2Add -> "i64x2.add"
  | I64X2Sub -> "i64x2.sub"
  | I64X2Mul -> "i64x2.mul"
  | I64X2Eq -> "i64x2.eq"
  | I64X2Ne -> "i64x2.ne"
  | I64X2LtS -> "i64x2.lt_s"
  | I64X2GtS -> "i64x2.gt_s"
  | I64X2LeS -> "i64x2.le_s"
  | I64X2GeS -> "i64x2.ge_s"
  | I64X2ExtmulLowI32X4S -> "i64x2.extmul_low_i32x4_s"
  | I64X2ExtmulHighI32X4S -> "i64x2.extmul_high_i32x4_s"
  | I64X2ExtmulLowI32X4U -> "i64x2.extmul_low_i32x4_u"
  | I64X2ExtmulHighI32X4U -> "i64x2.extmul_high_i32x4_u"
  | F32X4Ceil -> "f32x4.ceil"
  | F32X4Floor -> "f32x4.floor"
  | F32X4Trunc -> "f32x4.trunc"
  | F32X4Nearest -> "f32x4.nearest"
  | F64X2Ceil -> "f64x2.ceil"
  | F64X2Floor -> "f64x2.floor"
  | F64X2Trunc -> "f64x2.trunc"
  | F64X2Nearest -> "f64x2.nearest"
  | F32X4Abs -> "f32x4.abs"
  | F32X4Neg -> "f32x4.neg"
  | F32X4Sqrt -> "f32x4.sqrt"
  | F32X4Add -> "f32x4.add"
  | F32X4Sub -> "f32x4.sub"
  | F32X4Mul -> "f32x4.mul"
  | F32X4Div -> "f32x4.div"
  | F32X4Min -> "f32x4.min"
  | F32X4Max -> "f32x4.max"
  | F32X4PMin -> "f32x4.pmin"
  | F32X4PMax -> "f32x4.pmax"
  | F64X2Abs -> "f64x2.abs"
  | F64X2Neg -> "f64x2.neg"
  | F64X2Sqrt -> "f64x2.sqrt"
  | F64X2Add -> "f64x2.add"
  | F64X2Sub -> "f64x2.sub"
  | F64X2Mul -> "f64x2.mul"
  | F64X2Div -> "f64x2.div"
  | F64X2Min -> "f64x2.min"
  | F64X2Max -> "f64x2.max"
  | F64X2PMin -> "f64x2.pmin"
  | F64X2PMax -> "f64x2.pmax"
  | I32X4TruncSatF32X4S -> "i32x4.trunc_sat_f32x4_s"
  | I32X4TruncSatF32X4U -> "i32x4.trunc_sat_f32x4_u"
  | F32X4ConvertI32X4S -> "f32x4.convert_i32x4_s"
  | F32X4ConvertI32X4U -> "f32x4.convert_i32x4_u"
  | I32X4TruncSatF64X2SZero -> "i32x4.trunc_sat_f64x2_s_zero"
  | I32X4TruncSatF64X2UZero -> "i32x4.trunc_sat_f64x2_u_zero"
  | F64X2ConvertLowI32X4S -> "f64x2.convert_low_i32x4_s"
  | F64X2ConvertLowI32X4U -> "f64x2.convert_low_i32x4_u"
  | MemoryAtomicNotify -> "memory.atomic.notify"
  | MemoryAtomicWait32 -> "memory.atomic.wait32"
  | MemoryAtomicWait64 -> "memory.atomic.wait64"
  | AtomicFence -> "atomic.fence"
  | I32AtomicLoad -> "i32.atomic.load"
  | I64AtomicLoad -> "i64.atomic.load"
  | I32AtomicLoad8U -> "i32.atomic.load8_u"
  | I32AtomicLoad16U -> "i32.atomic.load16_u"
  | I64AtomicLoad8U -> "i64.atomic.load8_u"
  | I64AtomicLoad16U -> "i64.atomic.load16_u"
  | I64AtomicLoad32U -> "i64.atomic.load32_u"
  | I32AtomicStore -> "i32.atomic.store"
  | I64AtomicStore -> "i64.atomic.store"
  | I32AtomicStore8 -> "i32.atomic.store8"
  | I32AtomicStore16 -> "i32.atomic.store16"
  | I64AtomicStore8 -> "i64.atomic.store8"
  | I64AtomicStore16 -> "i64.atomic.store16"
  | I64AtomicStore32 -> "i64.atomic.store32"
  | I32AtomicRmwAdd -> "i32.atomic.rmw.add"
  | I64AtomicRmwAdd -> "i64.atomic.rmw.add"
  | I32AtomicRmw8AddU -> "i32.atomic.rmw8.add_u"
  | I32AtomicRmw16AddU -> "i32.atomic.rmw16.add_u"
  | I64AtomicRmw8AddU -> "i64.atomic.rmw8.add_u"
  | I64AtomicRmw16AddU -> "i64.atomic.rmw16.add_u"
  | I64AtomicRmw32AddU -> "i64.atomic.rmw32.add_u"
  | I32AtomicRmwSub -> "i32.atomic.rmw.sub"
  | I64AtomicRmwSub -> "i64.atomic.rmw.sub"
  | I32AtomicRmw8SubU -> "i32.atomic.rmw8.sub_u"
  | I32AtomicRmw16SubU -> "i32.atomic.rmw16.sub_u"
  | I64AtomicRmw8SubU -> "i64.atomic.rmw8.sub_u"
  | I64AtomicRmw16SubU -> "i64.atomic.rmw16.sub_u"
  | I64AtomicRmw32SubU -> "i64.atomic.rmw32.sub_u"
  | I32AtomicRmwAnd -> "i32.atomic.rmw.and"
  | I64AtomicRmwAnd -> "i64.atomic.rmw.and"
  | I32AtomicRmw8AndU -> "i32.atomic.rmw8.and_u"
  | I32AtomicRmw16AndU -> "i32.atomic.rmw16.and_u"
  | I64AtomicRmw8AndU -> "i64.atomic.rmw8.and_u"
  | I64AtomicRmw16AndU -> "i64.atomic.rmw16.and_u"
  | I64AtomicRmw32AndU -> "i64.atomic.rmw32.and_u"
  | I32AtomicRmwOr -> "i32.atomic.rmw.or"
  | I64AtomicRmwOr -> "i64.atomic.rmw.or"
  | I32AtomicRmw8OrU -> "i32.atomic.rmw8.or_u"
  | I32AtomicRmw16OrU -> "i32.atomic.rmw16.or_u"
  | I64AtomicRmw8OrU -> "i64.atomic.rmw8.or_u"
  | I64AtomicRmw16OrU -> "i64.atomic.rmw16.or_u"
  | I64AtomicRmw32OrU -> "i64.atomic.rmw32.or_u"
  | I32AtomicRmwXor -> "i32.atomic.rmw.xor"
  | I64AtomicRmwXor -> "i64.atomic.rmw.xor"
  | I32AtomicRmw8XorU -> "i32.atomic.rmw8.xor_u"
  | I32AtomicRmw16XorU -> "i32.atomic.rmw16.xor_u"
  | I64AtomicRmw8XorU -> "i64.atomic.rmw8.xor_u"
  | I64AtomicRmw16XorU -> "i64.atomic.rmw16.xor_u"
  | I64AtomicRmw32XorU -> "i64.atomic.rmw32.xor_u"
  | I32AtomicRmwXchg -> "i32.atomic.rmw.xchg"
  | I64AtomicRmwXchg -> "i64.atomic.rmw.xchg"
  | I32AtomicRmw8XchgU -> "i32.atomic.rmw8.xchg_u"
  | I32AtomicRmw16XchgU -> "i32.atomic.rmw16.xchg_u"
  | I64AtomicRmw8XchgU -> "i64.atomic.rmw8.xchg_u"
  | I64AtomicRmw16XchgU -> "i64.atomic.rmw16.xchg_u"
  | I64AtomicRmw32XchgU -> "i64.atomic.rmw32.xchg_u"
  | I32AtomicRmwCmpxchg -> "i32.atomic.rmw.cmpxchg"
  | I64AtomicRmwCmpxchg -> "i64.atomic.rmw.cmpxchg"
  | I32AtomicRmw8CmpxchgU -> "i32.atomic.rmw8.cmpxchg_u"
  | I32AtomicRmw16CmpxchgU -> "i32.atomic.rmw16.cmpxchg_u"
  | I64AtomicRmw8CmpxchgU -> "i64.atomic.rmw8.cmpxchg_u"
  | I64AtomicRmw16CmpxchgU -> "i64.atomic.rmw16.cmpxchg_u"
  | I64AtomicRmw32CmpxchgU -> "i64.atomic.rmw32.cmpxchg_u"

let inline buildOpcode insInfo (builder: DisasmBuilder<_>) =
  let opcode = opcodeToString insInfo.Opcode
  builder.Accumulate AsmWordKind.Mnemonic opcode

let oprToString opr delim (builder: DisasmBuilder<_>) =
  match opr with
  | Type t ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (t |> string)
  | Index idx ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (idx |> string)
  | I32 i32 ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (i32 |> string)
  | I64 i64 ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (i64 |> string)
  | F32 f32 ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (f32 |> string)
  | F64 f64 ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (f64 |> string)
  | V128 (i32One, i32Two, i32Three, i32Four) ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.String "i32x4:"
    builder.Accumulate AsmWordKind.Value (BitVector.valToString i32One)
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (BitVector.valToString i32Two)
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (BitVector.valToString i32Three)
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (BitVector.valToString i32Four)
  | Alignment align ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (align |> string)
  | Address addr ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (addr |> string)
  | LaneIndex lane ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (lane |> string)
  | ConsistencyModel model ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (model |> string)
  | RefType reftype ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (reftype |> string)

let buildOperands insInfo (builder: DisasmBuilder<_>) =
  match insInfo.Operands with
  | NoOperand -> ()
  | OneOperand opr ->
    oprToString opr " " builder
  | TwoOperands (opr1, opr2) ->
    oprToString opr1 " " builder
    oprToString opr2 " " builder
  | ThreeOperands (opr1, opr2, opr3) ->
    oprToString opr1 " " builder
    oprToString opr2 " " builder
    oprToString opr3 " " builder
  | Operands oprs ->
    let rec auxOprsToString oprs builder =
      if List.isEmpty oprs then ()
      else
        oprToString (List.head oprs) " " builder
        auxOprsToString (List.tail oprs) builder
    auxOprsToString oprs builder

let disasm insInfo (builder: DisasmBuilder<_>) =
  if builder.ShowAddr then builder.AccumulateAddr () else ()
  buildOpcode insInfo builder
  buildOperands insInfo builder

// vim: set tw=80 sts=2 sw=2: