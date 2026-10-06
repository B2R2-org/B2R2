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

/// Intel AMX. A tile register holds sixteen rows of 64 bytes, row r in bits
/// 512r to 512r + 511; how many rows and how many bytes of each are in use is
/// what TILECFG says, and LDTILECFG loads that at run time. So every
/// instruction here reads its shapes off TILECFG as it runs, and walks rows
/// and elements in loops rather than unrolling the largest shape there could
/// be. Intel SDM Vol. 1, Chapter 18, and the AMX pages of Vol. 2.
module internal B2R2.FrontEnd.Intel.AMXLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.Intel
open B2R2.FrontEnd.Intel.LiftingUtils

let private tileSz = 8192<rt>

let private rowSz = 512<rt>

let private one32 = AST.num1 32<rt>

let private cfgVar bld = regVar bld R.TILECFG

/// The value of the given width with its low n units of unitBits set: all of
/// it once n reaches the given count of units.
let private lowUnitsMask ty unitBits units (n: Expr) =
  let one = AST.num1 ty
  let shift = AST.zext ty (n .* numI32 unitBits 32<rt>)
  AST.ite (n .>= numI32 units 32<rt>) (numI64 -1L ty) ((one << shift) .- one)

/// Clears every tile.
let private clearTiles bld =
  append bld {
    for t in 0 .. 7 do
      let r = LanguagePrimitives.EnumOfValue<int, Register>(int R.TMM0 + t)
      direct (regVar bld r) := AST.num0 tileSz
  }

/// Whether a configuration names anything palette 1 cannot hold: a palette
/// above 1, a reserved byte that is set, a row wider than 64 bytes, a tile
/// taller than 16 rows, or a tile given rows but no bytes per row or the
/// other way round. Palette 0 is always valid, as it releases the tiles.
/// Intel SDM Vol. 2, LDTILECFG.
let private isInvalidConfig (buf: Expr) =
  let palette = AST.xtlo 8<rt> buf
  let isSet (pos, sz) = AST.extract buf sz pos != AST.num0 sz
  let colsb t = AST.extract buf 16<rt> (128 + 16 * t)
  let rows t = AST.extract buf 8<rt> (384 + 8 * t)
  let isHalfSet t =
    (colsb t == AST.num0 16<rt>) <+> (rows t == AST.num0 8<rt>)
  let reserved = [ 16, 112<rt>; 256, 128<rt>; 448, 64<rt> ] |> List.map isSet
  let shapes =
    [ for t in 0 .. 7 do
        colsb t .> numI32 64 16<rt>
        rows t .> numI32 16 8<rt>
        isHalfSet t ]
  let bad = List.reduce (.|) (reserved @ shapes)
  (palette .> AST.num1 8<rt>) .| ((palette == AST.num1 8<rt>) .& bad)

/// LDTILECFG loads a tile configuration and clears every tile. Palette 0
/// releases the tiles instead, leaving the configuration all zeros.
let ldtilecfg (ins: Instruction) bld =
  lift bld ins {
    let buf = tmpVar bld rowSz
    let cfg = cfgVar bld
    direct buf := transOneOpr ins bld
    _when bld "BadConfig" (isInvalidConfig buf)
      (block {
        AST.sideEffect (Exception ProtectionFault) })
    direct cfg :=
      AST.ite (AST.xtlo 8<rt> buf == AST.num0 8<rt>) (AST.num0 rowSz) buf
    clearTiles bld
  }

/// STTILECFG stores the configuration, which is all zeros while no palette is
/// loaded.
let sttilecfg (ins: Instruction) bld =
  lift bld ins {
    direct (transOneOpr ins bld) := cfgVar bld
  }

/// TILERELEASE returns the tiles to their initial state.
let tilerelease (ins: Instruction) bld =
  lift bld ins {
    direct (cfgVar bld) := AST.num0 rowSz
    clearTiles bld
  }

/// The tile a TMM operand names, counted from TMM0.
let private tileIndex (o: Operand) = int o.Register - int R.TMM0

/// The rows tile t is configured with, TILECFG byte 48 + t.
let private rowsOf bld t =
  AST.zext 32<rt> (AST.extract (cfgVar bld) 8<rt> (384 + 8 * t))

/// The bytes per row tile t is configured with, TILECFG bytes 16 + 2t.
let private colsbOf bld t =
  AST.zext 32<rt> (AST.extract (cfgVar bld) 16<rt> (128 + 16 * t))

/// Whether a row width is no whole number of dwords.
let private isNotDwords n = (n .& numI32 3 32<rt>) != AST.num0 32<rt>

/// Whether no configuration is loaded: palette 0.
let private isUnconfigured bld =
  AST.xtlo 8<rt> (cfgVar bld) == AST.num0 8<rt>

/// Faults, as an instruction naming tile t does, while no configuration is
/// loaded or the configuration leaves tile t unused, with no rows or no bytes
/// per row. A tile load or store also faults on a row width that is no whole
/// number of dwords. Intel SDE, which these were checked against, has it so.
let private checkTile bld t isMoved =
  let colsb = colsbOf bld t
  let isUnused = (rowsOf bld t == AST.num0 32<rt>) .| (colsb == AST.num0 32<rt>)
  let isBad = isUnconfigured bld .| isUnused
  let isBad = if isMoved then isBad .| isNotDwords colsb else isBad
  _when bld "BadTile" isBad
    (block {
      AST.sideEffect UndefinedInstruction })

/// Clears the row a restarted load or store would resume at: an instruction
/// that ran to its end leaves nothing to resume.
let private clearStartRow bld =
  let cfg = cfgVar bld
  append bld {
    direct cfg := cfg .& AST.not (numI32 0xFF00 rowSz)
  }

let tilezero (ins: Instruction) bld =
  lift bld ins {
    let tile = transOneOpr ins bld
    checkTile bld (tileIndex ins.Operands[0]) false
    direct tile := AST.num0 tileSz
    clearStartRow bld
  }

/// The address of row 0 of a tile load or store, and the stride to each next
/// row: an AMX memory operand takes its index register, times the scale, as
/// the distance between rows rather than as an offset.
let private sibParts bld (o: Operand) =
  let baseReg =
    match o.MemBase with
    | ValueSome r -> regVar bld r
    | ValueNone -> AST.num0 64<rt>
  let disp =
    match o.MemDisp with
    | ValueSome d -> numI64 d 64<rt>
    | ValueNone -> AST.num0 64<rt>
  let stride =
    match o.MemIndex with
    | ValueSome(struct (r, s)) -> regVar bld r .* numI32 (int s) 64<rt>
    | ValueNone -> AST.num0 64<rt>
  struct (baseReg .+ disp, stride)

/// The row a restarted tile load or store resumes at, TILECFG byte 1.
let private startRowOf bld =
  AST.zext 32<rt> (AST.extract (cfgVar bld) 8<rt> 8)

/// An amount of bits at the given type: idx units of the given width.
let private bitOffset ty width (idx: Expr) =
  AST.zext ty (idx .* numI32 width 32<rt>)

/// The address of byte i of row r.
let private rowByteAddr (struct (addr, stride)) r i =
  addr .+ (AST.zext 64<rt> r .* stride) .+ AST.zext 64<rt> i

/// Reads row r of a tile load into row, byte by byte as far as the row is
/// configured, so that no byte past it is touched; the rest of the row is
/// zero.
let private loadRow bld parts r nbytes row =
  let i = tmpVar bld 32<rt>
  append bld {
    direct row := AST.num0 rowSz
    direct i := AST.num0 32<rt>
  }
  _while bld "Byte" (i .< nbytes)
    (block {
      let b = AST.loadLE 8<rt> (rowByteAddr parts r i)
      direct row := row .| (AST.zext rowSz b << bitOffset rowSz 8 i)
      direct i := i .+ one32 })

/// Writes a whole row of a tile.
let private writeRow bld tile r v =
  let sh = bitOffset tileSz 512 r
  let mask = AST.zext tileSz (numI64 -1L rowSz) << sh
  append bld {
    direct tile := (tile .& AST.not mask) .| (AST.zext tileSz v << sh)
  }

/// TILELOADD and its hinted forms load the configured rows of a tile, from
/// the start row on, and clear the rows past them. A load restarted at a
/// later row keeps the rows above it.
let tileloadd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let t = tileIndex dst
    let tile = regVar bld dst.Register
    let parts = sibParts bld src
    let struct (r, rows, nbytes) = tmpVars3 bld 32<rt>
    let row = tmpVar bld rowSz
    checkTile bld t true
    direct rows := rowsOf bld t
    direct nbytes := colsbOf bld t
    direct tile := tile .& lowUnitsMask tileSz 512 16 rows
    direct r := startRowOf bld
    _while bld "Row" (r .< rows)
      (block {
        loadRow bld parts r nbytes row
        writeRow bld tile r row
        direct r := r .+ one32 })
    clearStartRow bld
  }

/// Element n, of the given width, of a row.
let private readElem width (row: Expr) n =
  AST.xtlo width (row >> bitOffset rowSz (int width) n)

/// Writes row r of a tile store, byte by byte as far as the row is
/// configured.
let private storeRow bld parts r nbytes row =
  let i = tmpVar bld 32<rt>
  append bld {
    direct i := AST.num0 32<rt>
  }
  _while bld "Byte" (i .< nbytes)
    (block {
      let addr = rowByteAddr parts r i
      direct (AST.loadLE 8<rt> addr) := readElem 8<rt> row i
      direct i := i .+ one32 })

/// Row r of a tile.
let private readRow tile (r: Expr) =
  AST.xtlo rowSz (tile >> bitOffset tileSz 512 r)

/// TILESTORED stores the configured rows of a tile, from the start row on.
let tilestored (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let t = tileIndex src
    let tile = regVar bld src.Register
    let parts = sibParts bld dst
    let struct (r, rows, nbytes) = tmpVars3 bld 32<rt>
    let row = tmpVar bld rowSz
    checkTile bld t true
    direct rows := rowsOf bld t
    direct nbytes := colsbOf bld t
    direct r := startRowOf bld
    _while bld "Row" (r .< rows)
      (block {
        direct row := readRow tile r
        storeRow bld parts r nbytes row
        direct r := r .+ one32 })
    clearStartRow bld
  }

/// Faults unless the three tiles of a product differ, a configuration is
/// loaded, and the shapes agree: the destination as tall as the first source
/// and as wide as the second, the first source's dword columns as many as
/// the second's rows, and every row a whole number of dwords.
let private checkProduct bld d a b =
  let isMismatch =
    (rowsOf bld d != rowsOf bld a)
    .| (colsbOf bld d != colsbOf bld b)
    .| (colsbOf bld a != (rowsOf bld b << numI32 2 32<rt>))
    .| isNotDwords (colsbOf bld d)
    .| isNotDwords (colsbOf bld a)
  if d = a || d = b || a = b then
    append bld { AST.sideEffect UndefinedInstruction }
  else
    _when bld "BadShape" (isUnconfigured bld .| isMismatch)
      (block {
        AST.sideEffect UndefinedInstruction })

/// A row with element n, of the width of v, replaced by v.
let private insertElem (row: Expr) n v =
  let width = Expr.typeOf v
  let sh = bitOffset rowSz (int width) n
  let mask = AST.zext rowSz (numI64 -1L width) << sh
  (row .& AST.not mask) .| (AST.zext rowSz v << sh)

/// Runs body for every dword k of row m of the first source and every dword
/// column n of the destination, handing it n, that dword of the first source
/// and dword n of row k of the second.
let private forEachProduct bld tiles m (struct (ks, ns)) body =
  let struct (tA, tB) = tiles
  let struct (k, n) = tmpVars2 bld 32<rt>
  let aElem = tmpVar bld 32<rt>
  let bRow = tmpVar bld rowSz
  append bld {
    direct k := AST.num0 32<rt>
  }
  _while bld "Inner" (k .< ks)
    (block {
      direct aElem := readElem 32<rt> (readRow tA m) k
      direct bRow := readRow tB k
      direct n := AST.num0 32<rt>
      _while bld "Col" (n .< ns)
        (block {
          body n aElem (readElem 32<rt> bRow n)
          direct n := n .+ one32 })
      direct k := k .+ one32 })

/// The tile product every TDP instruction is, row by row of the destination:
/// rowOp works the row out from what it held. Bytes past the configured width
/// of a row, and rows past the configured height, are cleared.
let private tileProduct (ins: Instruction) bld rowOp =
  lift bld ins {
    let struct (dOpr, aOpr, bOpr) = getThreeOprs ins
    let d = tileIndex dOpr
    let a = tileIndex aOpr
    let tD = regVar bld dOpr.Register
    let tiles = struct (regVar bld aOpr.Register, regVar bld bOpr.Register)
    let struct (m, rows, ks) = tmpVars3 bld 32<rt>
    let ns = tmpVar bld 32<rt>
    let acc = tmpVar bld rowSz
    checkProduct bld d a (tileIndex bOpr)
    direct rows := rowsOf bld d
    direct ks := colsbOf bld a >> numI32 2 32<rt>
    direct ns := colsbOf bld d >> numI32 2 32<rt>
    direct m := AST.num0 32<rt>
    _while bld "Row" (m .< rows)
      (block {
        direct acc := readRow tD m
        rowOp bld tiles m (struct (ks, ns)) acc
        direct acc := acc .& lowUnitsMask rowSz 32 16 ns
        writeRow bld tD m acc
        direct m := m .+ one32 })
    direct tD := tD .& lowUnitsMask tileSz 512 16 rows
    clearStartRow bld
  }

/// The dot product of the four bytes of two dwords, each byte widened as its
/// tile's signedness says.
let private dotBytes extA extB (a: Expr) (b: Expr) =
  [ for i in 0 .. 3 ->
      let x = extA 32<rt> (AST.extract a 8<rt> (8 * i))
      let y = extB 32<rt> (AST.extract b 8<rt> (8 * i))
      x .* y ]
  |> List.reduce (.+)

/// A row of an integer tile product: every dword column gains, modulo 2^32,
/// the dot products of the bytes it meets.
let private intRow extA extB bld tiles m dims (acc: Expr) =
  forEachProduct bld tiles m dims (fun n a b ->
    let v = readElem 32<rt> acc n .+ dotBytes extA extB a b
    append bld { direct acc := insertElem acc n v })

let tdpbssd ins bld = tileProduct ins bld (intRow AST.sext AST.sext)

let tdpbsud ins bld = tileProduct ins bld (intRow AST.sext AST.zext)

let tdpbusd ins bld = tileProduct ins bld (intRow AST.zext AST.sext)

let tdpbuud ins bld = tileProduct ins bld (intRow AST.zext AST.zext)

/// A single with its denormals flushed to zero of the same sign. The
/// floating-point tile products read denormals as zero and write them as
/// zero, whatever MXCSR says.
let private flushDenormal (x: Expr) =
  let isDenormal = (x .& numI32 0x7F800000 32<rt>) == AST.num0 32<rt>
  AST.ite isDenormal (x .& numU32 0x80000000u 32<rt>) x

let private isNaN (x: Expr) =
  let expo = numI32 0x7F800000 32<rt>
  ((x .& expo) == expo) .& ((x .& numI32 0x7FFFFF 32<rt>) != AST.num0 32<rt>)

/// The result of an operation on singles under the NaN rules the tile
/// products follow, rather than those of whatever host evaluates them: the
/// first NaN among the operands, in the order given, quieted; or, where none
/// is a NaN but the result is, the default NaN, negative and quiet. Intel
/// SDE, which these were checked against, has it so.
let private withNaNRules (operands: Expr list) (result: Expr) =
  let quiet z = z .| numI32 0x400000 32<rt>
  let ofNumbers =
    AST.ite (isNaN result) (numU32 0xFFC00000u 32<rt>) result
  List.foldBack (fun o r -> AST.ite (isNaN o) (quiet o) r) operands ofNumbers

/// x * y + s on singles, rounded once. The product of two values of 16-bit
/// precision is exact in double precision, and their sum with a single,
/// rounded to a double and then to a single, rounds as the fused operation
/// does: the second rounding can only meet a tie where the exact sum held
/// one, which the first leaves alone.
let private fusedMulAdd x y s =
  let toDouble e = AST.cast CastKind.FloatCast 64<rt> e
  let sum = AST.fadd (toDouble s) (AST.fmul (toDouble x) (toDouble y))
  AST.cast CastKind.FloatCast 32<rt> sum

/// One step of a floating-point tile product: the halves at pos of two pairs,
/// widened to singles, multiplied and added to a sum in one fused operation
/// that reads and writes denormals as zero and rounds to nearest even. Of
/// NaN operands, those of the product come first, then the sum; of the two
/// in the product, a bfloat16 product takes the second source's first and a
/// half-precision one the first source's.
let private fmaStep bld (struct (widen, isBF16)) sum a b pos =
  let x = flushDenormal (widen (AST.extract (a: Expr) 16<rt> pos))
  let y = flushDenormal (widen (AST.extract (b: Expr) 16<rt> pos))
  let s = flushDenormal (sum: Expr)
  let fused = fusedMulAdd x y s
  let r = tmpVar bld 32<rt>
  append bld {
    let operands = if isBF16 then [ y; x; s ] else [ x; y; s ]
    direct r := flushDenormal (withNaNRules operands fused)
  }
  r

/// Adds two singles as the last steps of a floating-point tile product do:
/// of two NaN operands, the second wins.
let private addSingles x y =
  let x = flushDenormal x
  let y = flushDenormal y
  flushDenormal (withNaNRules [ y; x ] (AST.fadd x y))

/// A row of a floating-point tile product. The products of the low halves of
/// the pairs, and those of the high halves, gather apart in two sums, each
/// from zero; only then are the two summed and that sum added to the
/// destination. Intel SDM Vol. 2, TDPBF16PS and TDPFP16PS.
let private fpRow pairs bld tiles m (struct (ks, ns)) (acc: Expr) =
  let struct (lows, highs) = tmpVars2 bld rowSz
  let n = tmpVar bld 32<rt>
  append bld {
    direct lows := AST.num0 rowSz
    direct highs := AST.num0 rowSz
  }
  forEachProduct bld tiles m (struct (ks, ns)) (fun n a b ->
    let lo = fmaStep bld pairs (readElem 32<rt> lows n) a b 0
    let hi = fmaStep bld pairs (readElem 32<rt> highs n) a b 16
    append bld {
      direct lows := insertElem lows n lo
      direct highs := insertElem highs n hi
    })
  append bld {
    direct n := AST.num0 32<rt>
  }
  _while bld "Sum" (n .< ns)
    (block {
      let pair = addSingles (readElem 32<rt> lows n) (readElem 32<rt> highs n)
      direct acc := insertElem acc n (addSingles (readElem 32<rt> acc n) pair)
      direct n := n .+ one32 })

let private bf16ToSingle (h: Expr) = AST.zext 32<rt> h << numI32 16 32<rt>

/// The pairs of bfloat16 values TDPBF16PS multiplies.
let private bf16Pairs = struct (bf16ToSingle, true)

let tdpbf16ps ins bld = tileProduct ins bld (fpRow bf16Pairs)

/// The pairs of half-precision values TDPFP16PS multiplies.
let private halfPairs = struct (halfToSingle, false)

let tdpfp16ps ins bld = tileProduct ins bld (fpRow halfPairs)
