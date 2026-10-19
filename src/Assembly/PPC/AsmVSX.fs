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
/// Encodes the Vector-Scalar Extension forms ISA 3.0 and 3.1 added, which the
/// decoder reads in ParsingVSX: the VSX loads and stores, the vector-scalar
/// arithmetic, the quad-precision forms and the matrix accumulators. A
/// vector-scalar register number is six bits, and where its sixth bit lies
/// depends on the form.
/// </summary>
module internal B2R2.Assembly.PPC.AsmVSX

open B2R2.FrontEnd.PPC
open B2R2.Assembly.PPC.ParserHelper
open B2R2.Assembly.PPC.AsmField

/// The field of five bits a vector-scalar register number leaves once its
/// sixth bit is taken out, and that bit.
let private split n = struct (n &&& 0x1Fu, n >>> 5)

/// An X-form VSX access "xT, rA, rB" of primary opcode 31, and the moves of
/// the same shape with no rB, the register number's sixth bit last.
let private xIndexed xo ins =
  match ins.Operands with
  | [ Rg x; Rg a; Rg b ] ->
    let struct (t, tx) = split (vsr x)
    word 31u t (gpr a) (gpr b) ((xo <<< 1) ||| tx)
  | [ Rg x; Rg a ] ->
    let struct (t, tx) = split (vsr x)
    word 31u t (gpr a) 0u ((xo <<< 1) ||| tx)
  | _ ->
    wrongOperands ins

/// The field naming a register pair: four bits counting pairs, then the bit
/// saying which half of the vector-scalar registers the pair lies in. Only an
/// even register begins a pair.
let private pairField reg =
  let n = vsr reg
  if n &&& 1u = 0u then (n &&& 0x1Eu) ||| (n >>> 5)
  else fail $"{reg} does not begin a register pair"

/// lxvpx and stxvpx, "xTp, rA, rB".
let private pairIndexed xo ins =
  match ins.Operands with
  | [ Rg x; Rg a; Rg b ] -> word 31u (pairField x) (gpr a) (gpr b) (xo <<< 1)
  | _ -> wrongOperands ins

/// The sixteen bits a DQ-form holds, which leave out the four low bits of the
/// distance because what it reaches is a whole quadword away.
let private quadDisplacement (disp: int32) =
  if disp % 16 = 0 then signed 16 (int64 disp)
  else fail "this access cannot reach a place that is not a quadword away"

/// lxssp and stxssp, "vRT, DS(rA)", whose two low bits are 11.
let private singleDS po ins =
  match ins.Operands with
  | [ Rg v; Mem(disp, b) ] ->
    dForm po (vr v) (gpr b) ((wordDisplacement disp) ||| 3u)
  | _ ->
    wrongOperands ins

/// lxv and stxv, "xT, DQ(rA)": the sixth bit of the register number sits
/// above the three bits that say which of the two this is.
let private vectorDQ low ins =
  match ins.Operands with
  | [ Rg x; Mem(disp, b) ] ->
    let struct (t, tx) = split (vsr x)
    dForm 61u t (gpr b) ((quadDisplacement disp) ||| (tx <<< 3) ||| low)
  | _ ->
    wrongOperands ins

/// lxvp and stxvp, "xTp, DQ(rA)", told apart by their four low bits.
let private pairDQ low ins =
  match ins.Operands with
  | [ Rg x; Mem(disp, b) ] ->
    dForm 6u (pairField x) (gpr b) ((quadDisplacement disp) ||| low)
  | _ ->
    wrongOperands ins

/// lxvkq, "xT, UIM", which keeps five ones where xxspltib keeps the top of
/// its byte.
let private loadConstant ins =
  match ins.Operands with
  | [ Rg x; Im u ] ->
    let struct (t, tx) = split (vsr x)
    word 60u t 31u (unsigned 5 u) ((360u <<< 1) ||| tx)
  | _ ->
    wrongOperands ins

/// The loads and stores of the vector-scalar registers, and the moves beside
/// them.
let private memoryEncoders () =
  [ Op.LXSIBZX, xIndexed 781u
    Op.LXSIHZX, xIndexed 813u
    Op.LXSIWAX, xIndexed 76u
    Op.LXSIWZX, xIndexed 12u
    Op.LXSSPX, xIndexed 524u
    Op.LXVB16X, xIndexed 876u
    Op.LXVH8X, xIndexed 812u
    Op.LXVL, xIndexed 269u
    Op.LXVLL, xIndexed 301u
    Op.LXVRBX, xIndexed 13u
    Op.LXVRDX, xIndexed 109u
    Op.LXVRHX, xIndexed 45u
    Op.LXVRWX, xIndexed 77u
    Op.LXVWSX, xIndexed 364u
    Op.LXVX, xIndexed 268u
    Op.MTVSRWS, xIndexed 403u
    Op.STXSIBX, xIndexed 909u
    Op.STXSIHX, xIndexed 941u
    Op.STXSIWX, xIndexed 140u
    Op.STXSSPX, xIndexed 652u
    Op.STXVB16X, xIndexed 1004u
    Op.STXVH8X, xIndexed 940u
    Op.STXVL, xIndexed 397u
    Op.STXVLL, xIndexed 429u
    Op.STXVRBX, xIndexed 141u
    Op.STXVRDX, xIndexed 237u
    Op.STXVRHX, xIndexed 173u
    Op.STXVRWX, xIndexed 205u
    Op.STXVX, xIndexed 396u
    Op.LXVPX, pairIndexed 333u
    Op.STXVPX, pairIndexed 461u
    Op.LXSSP, singleDS 57u
    Op.STXSSP, singleDS 61u
    Op.LXV, vectorDQ 1u
    Op.STXV, vectorDQ 5u
    Op.LXVP, pairDQ 0u
    Op.STXVP, pairDQ 1u
    Op.LXVKQ, loadConstant ]

/// Every instruction this module encodes.
let vsxEncoders () = memoryEncoders ()
