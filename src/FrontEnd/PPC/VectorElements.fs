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
/// The vector facility's registers seen as rows of elements. A vector register
/// is kept as two 64-bit halves; the instructions name its elements from the
/// most significant end, element 0 sitting at the top of the high half, so an
/// element is read out of whichever half holds it and a result is put back
/// together from its elements in that same order. A result is assembled in
/// temporaries before it reaches the target, so a target that is also a source
/// reads its old value throughout.
/// </summary>
module internal B2R2.FrontEnd.PPC.VectorElements

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.OperandHelper

/// The two halves of a vector register operand, the high one first.
let halvesOf bld opr =
  match opr with
  | OprReg reg -> struct (regVar bld reg, regVar bld (getLowHalf reg))
  | _ -> raise InvalidOperandException

/// The elements of a 128-bit value given as its two halves, element 0 first.
let elementsOfHalves (esize: RegType) hi lo =
  let n = int esize
  if n = 128 then
    [| AST.concat hi lo |]
  else
    let perHalf = 64 / n
    Array.init (128 / n) (fun i ->
      let half = if i < perHalf then hi else lo
      AST.extract half esize ((perHalf - 1 - i % perHalf) * n))

/// The esize-bit elements of a vector register operand, element 0 first.
let elementsOf bld esize opr =
  let struct (hi, lo) = halvesOf bld opr
  elementsOfHalves esize hi lo

/// The 128-bit value a vector register holds.
let quadOf bld opr = (elementsOf bld 128<rt> opr)[0]

/// The value whose elements, element 0 first, are the given ones.
let concatElements (elements: Expr[]) = Array.reduce AST.concat elements

/// Writes a 128-bit value, given as its elements with element 0 first, to a
/// vector register through temporaries. A single quadword element is held
/// whole first, so that its two halves are taken from one computation.
let putElements (bld: ILowUIRBuilder) opr (elements: Expr[]) =
  let struct (dh, dl) = halvesOf bld opr
  if elements.Length = 1 then
    let q = tmpVar bld 128<rt>
    append bld {
      q := elements[0]
      dh := AST.xthi 64<rt> q
      dl := AST.xtlo 64<rt> q
    }
  else
    let half = elements.Length / 2
    let struct (th, tl) = tmpVars2 bld 64<rt>
    append bld {
      th := concatElements elements[..half - 1]
      tl := concatElements elements[half..]
      dh := th
      dl := tl
    }

/// A number of a given width, from a signed 64-bit value.
let numOf (rt: RegType) (v: int64) = numI64 v rt

/// The smallest and the largest value an esize-bit element holds, signed or
/// unsigned, as numbers of the given wider type. No instruction saturates to
/// a doubleword, so an element is narrower than 64 bits.
let private elementRange esize signed (wide: RegType) =
  let n = int esize
  if signed then
    struct (numOf wide (-(1L <<< (n - 1))), numOf wide ((1L <<< (n - 1)) - 1L))
  else
    struct (AST.num0 wide, numOf wide ((1L <<< n) - 1L))

/// A value computed exactly at a wider type, clamped to the range of an
/// esize-bit element -- signed or unsigned -- and narrowed to it, with whether
/// it had to be clamped. The wider type leaves room for a sign, so the clamp
/// compares as signed whichever kind of element it is.
let saturate esize signed (wide: Expr) =
  let rt = Expr.typeOf wide
  let struct (lo, hi) = elementRange esize signed rt
  let above = wide ?> hi
  let below = wide ?< lo
  let inRange = AST.ite below (AST.xtlo esize lo) (AST.xtlo esize wide)
  let value = AST.ite above (AST.xtlo esize hi) inRange
  struct (value, above .| below)

/// Widens an element, sign- or zero-extending it.
let widen signed (rt: RegType) e =
  if signed then AST.sext rt e else AST.zext rt e

/// Writes the elements of a saturating instruction and sets VSCR[SAT], which
/// is sticky, where any element had to be clamped. Whether one did is settled
/// before the target is written, as the target may be a source.
let putSaturated (bld: ILowUIRBuilder) opr (results: struct (Expr * Expr)[]) =
  let sat = tmpVar bld 1<rt>
  let vscr = regVar bld Register.VSCR
  let clamped = results |> Array.map (fun struct (_, s) -> s)
  append bld { sat := Array.reduce (.|) clamped }
  putElements bld opr (results |> Array.map (fun struct (v, _) -> v))
  append bld { vscr := vscr .| AST.zext 32<rt> sat }
