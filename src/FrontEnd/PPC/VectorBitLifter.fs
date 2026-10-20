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

/// The vector facility's bit-level instructions: the counts, the parities,
/// the rotates and shifts, and the gathers and scatters of bits, lifted
/// element by element.
module internal B2R2.FrontEnd.PPC.VectorBitLifter

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC.LiftingUtils
open B2R2.FrontEnd.PPC.VectorElements
open B2R2.FrontEnd.PPC.VectorLifter
open B2R2.FrontEnd.PPC.VectorIntegerLifter

/// An element-wise "vD, vB": each element of vD is f of the matching element
/// of vB.
let vecMap1 ins bld esize f =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    putElements bld o1 (Array.map f (elementsOf bld esize o2))
  }

/// vctz*, the trailing zeros of each element: the set bits of the mask below
/// its lowest set bit, which is every bit for a zero element.
let vecCountTrailingZeros ins bld esize =
  vecMap1 ins bld esize (fun x ->
    popCountOf esize (AST.not x .& (x .- AST.num1 esize)))

/// vclzlsbb/vctzlsbb rD, vB: how many bytes of vB, from byte 0 or from byte
/// 15, have their lowest bit clear before the first that has it set.
let vecCountLsbZeroBytes ins (bld: ILowUIRBuilder) leading =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let rt = transOpr bld o1
    let bytes = elementsOf bld 8<rt> o2
    let order = if leading then bytes else Array.rev bytes
    let pick (i, b) acc =
      AST.ite (AST.xtlo 1<rt> b) (numI32 i bld.RegType) acc
    let none = numI32 16 bld.RegType
    rt := Array.foldBack pick (Array.indexed order) none
  }

/// vprtyb*, the parity of the lowest bits of the bytes of each element.
let vecParity ins bld esize =
  vecMap1 ins bld esize (fun x ->
    Array.init (int esize / 8) (fun j -> AST.extract x 1<rt> (8 * j))
    |> Array.reduce (<+>)
    |> AST.zext esize)

/// vextsb2w and the rest, which sign-extend the low byte, halfword, word or
/// doubleword of each element to the whole of it.
let vecSignExtend ins bld esize (from: RegType) =
  vecMap1 ins bld esize (fun x -> AST.sext esize (AST.xtlo from x))
