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

/// <summary>
/// The integer Advanced SIMD instructions Armv8 added to AArch32 after the
/// first version: VQRDMLAH and VQRDMLSH (Armv8.1), the dot products VSDOT and
/// VUDOT (Armv8.2), and the Int8 matrix multiplies' VUSDOT, VSUDOT, VSMMLA,
/// VUMMLA and VUSMMLA (Armv8.6).
/// </summary>
module internal B2R2.FrontEnd.ARM32.SIMDv8Lifter

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.ARM32
open B2R2.FrontEnd.ARM32.LiftingUtils
open B2R2.FrontEnd.ARM32.NEONLifter
open B2R2.FrontEnd.ARM32.FPLifter

/// The second operand's lanes: the vector's own, or, by scalar, the one
/// element it names in every lane, read once.
let private secondOf bld esize count opr =
  match opr with
  | OprSIMD(SFReg(Scalar(r, Some idx))) ->
    let rt = RegType.fromBitWidth esize
    let t = tmpVar bld rt
    append bld { t := AST.extract (regVar bld r) rt (int idx * esize) }
    Array.create count t
  | _ ->
    readLanes bld esize opr

/// <summary>
/// The rounding doubled product accumulated into an element's high half, or
/// taken from it: the element moved up by its width, the doubled product of
/// the two others added or subtracted, half of what is discarded added, and
/// the top half saturated. It is formed at four times the element's width,
/// where neither the move nor the sum can be lost before the clamp is asked
/// about it.
/// </summary>
let private accumulatedHigh bld esize isSub acc e1 e2 =
  let room = RegType.fromBitWidth (esize * 4)
  let prod = (AST.sext room e1 .* AST.sext room e2) << AST.num1 room
  let moved = AST.sext room acc << numI32 esize room
  let sum = if isSub then moved .- prod else moved .+ prod
  let rounded = sum .+ (AST.num1 room << numI32 (esize - 1) room)
  let esz = RegType.fromBitWidth esize
  satLane bld false false room esz (rounded ?>> numI32 esize room)

/// <summary>
/// VQRDMLAH and VQRDMLSH, by vector and by scalar (DDI0487F.c F6.1.179 and
/// F6.1.180): every element of Dd or Qd accumulates the rounding doubled
/// product into its high half, saturating and raising QC where it clamps.
/// </summary>
let vqrdmlah (ins: Instruction) bld isSub =
  conditional ins bld (fun () ->
    let p = getParsingInfo ins
    let struct (dst, src1, src2) = getThreeOprs ins
    let d = readLanes bld p.ESize dst
    let n = readLanes bld p.ESize src1
    let m = secondOf bld p.ESize n.Length src2
    Array.init d.Length (fun e ->
      accumulatedHigh bld p.ESize isSub d[e] n[e] m[e])
    |> writeLanes bld dst)

/// The extension of a byte to a word, as its operand's signedness says.
let private widen unsigned e =
  if unsigned then AST.zext 32<rt> e else AST.sext 32<rt> e

/// <summary>
/// VSDOT, VUDOT, VUSDOT and VSUDOT: four byte products summed into each word,
/// wrapping (F6.1.222, F6.1.221, F6.1.257, F6.1.256, F6.1.260, F6.1.259 and
/// F6.1.251). Each word of Dd or Qd reads the four bytes under it in each
/// operand, multiplies them pairwise, each byte with its own operand's
/// signedness, and adds all four to what it holds. By element, every word
/// reads the same four bytes of Dm, the word the index names.
/// </summary>
let dotProduct (ins: Instruction) bld unsigned1 unsigned2 =
  conditional ins bld (fun () ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let d = readLanes bld 32 dst
    let n = readLanes bld 8 src1
    let m =
      match src2 with
      | OprSIMD(SFReg(Scalar(r, Some idx))) ->
        let word = tmpVar bld 32<rt>
        append bld { word := AST.extract (regVar bld r) 32<rt> (int idx * 32) }
        Array.init n.Length (fun i -> AST.extract word 8<rt> (i % 4 * 8))
      | _ ->
        readLanes bld 8 src2
    Array.init d.Length (fun i ->
      Array.init 4 (fun k ->
        widen unsigned1 n[i * 4 + k] .* widen unsigned2 m[i * 4 + k])
      |> Array.fold (.+) d[i])
    |> writeLanes bld dst)

/// <summary>
/// VSMMLA, VUMMLA and VUSMMLA: Qd as a two-by-two matrix of words, word (i, j)
/// adding the eight byte products of row i of Qn with row j of Qm, a row being
/// a doubleword, each operand read with its own signedness (F6.1.232, F6.1.258
/// and F6.1.261).
/// </summary>
let matMulAdd (ins: Instruction) bld unsigned1 unsigned2 =
  conditional ins bld (fun () ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let d = readLanes bld 32 dst
    let n = readLanes bld 8 src1
    let m = readLanes bld 8 src2
    Array.init 4 (fun e ->
      let i, j = e / 2, e % 2
      Array.init 8 (fun k ->
        widen unsigned1 n[8 * i + k] .* widen unsigned2 m[8 * j + k])
      |> Array.fold (.+) d[e])
    |> writeLanes bld dst)
