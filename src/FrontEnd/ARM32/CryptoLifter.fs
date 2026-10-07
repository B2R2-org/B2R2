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
/// The Armv8 Cryptographic Extension in AArch32: AESE, AESD, AESMC, AESIMC,
/// and the SHA-1 and SHA-256 instructions (DDI0487F.c F6.1.1-F6.1.4 and
/// F6.1.7-F6.1.16). Every operand is a quadword, read here as its pair of
/// doublewords, high and low.
/// </summary>
module internal B2R2.FrontEnd.ARM32.CryptoLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.ARM32
open B2R2.FrontEnd.ARM32.LiftingUtils
open B2R2.FrontEnd.ARM32.GeneralLifter

/// A quadword operand as one 128-bit value.
let private whole bld o =
  let struct (b, a) = transOpr128 bld o
  AST.concat b a

/// Writes a 128-bit value to a quadword operand, a doubleword at a time.
let private putWhole bld o (v: Expr) =
  let struct (b, a) = transOpr128 bld o
  append bld { a := AST.xtlo 64<rt> v }
  append bld { b := AST.xthi 64<rt> v }

/// <summary>
/// AESE and AESD: add the round key, then shift the rows and substitute the
/// bytes. They are half a round each and split differently from x86, where
/// a round is shift-substitute-mix-add and the key comes last. The two meet
/// because x86's last-round instruction with a zero key is exactly the shift
/// and the substitution, so AESE is AESENCLAST of the state already added to
/// the key, and AESD is AESDECLAST of it.
/// </summary>
let aesRound (ins: Instruction) bld isDecrypt =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (o1, o2) = getTwoOprs ins
    let name = if isDecrypt then "AESDECLAST" else "AESENCLAST"
    let state = whole bld o1 <+> whole bld o2
    let t = tmpVar bld 128<rt>
    t := AST.app name [ state; AST.num0 128<rt> ] 128<rt>
    putWhole bld o1 t
    putEndLabel bld lblIgnore
  }

/// <summary>
/// AESMC and AESIMC: the column mixing of a round, and its inverse. The
/// inverse is an instruction on x86 too and goes straight across. The forward
/// one is not, and comes out of a round: an x86 round mixes what it has just
/// shifted and substituted, so undoing those two first -- AESDECLAST with a
/// zero key, the inverse substitution being bytewise and commuting with the
/// row shift -- leaves the mixing alone.
/// </summary>
let aesMixColumns (ins: Instruction) bld isInverse =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (o1, o2) = getTwoOprs ins
    let zero = AST.num0 128<rt>
    let t = tmpVar bld 128<rt>
    if isInverse then
      t := AST.app "AESIMC" [ whole bld o2 ] 128<rt>
    else
      t := AST.app "AESDECLAST" [ whole bld o2; zero ] 128<rt>
      t := AST.app "AESENC" [ t; zero ] 128<rt>
    putWhole bld o1 t
    putEndLabel bld lblIgnore
  }

/// The three bitwise choices SHA-1 and SHA-256 are built from, each the
/// manual's definition written out.
let private shaChoose x y z = ((y <+> z) .& x) <+> z

let private shaMajority x y z = (x .& y) .| ((x .| y) .& z)

let private shaParity x y z = x <+> y <+> z

/// A word rotated left. Every amount these hashes use is between one and
/// thirty-one, so neither shift is by the whole width.
let private rol32 e n = (e << numI32 n 32<rt>) .| (e >> numI32 (32 - n) 32<rt>)

let private ror32 e n = rol32 e (32 - n)

/// The four words of a quadword, lowest first.
let private wordsOf bld o =
  let struct (hi, lo) = transOpr128 bld o
  [| AST.xtlo 32<rt> lo
     AST.xthi 32<rt> lo
     AST.xtlo 32<rt> hi
     AST.xthi 32<rt> hi |]

/// Writes four words to a quadword operand, lowest first.
let private putWords bld o (w: Expr[]) =
  let struct (hi, lo) = transOpr128 bld o
  append bld { lo := AST.concat w[1] w[0] }
  append bld { hi := AST.concat w[3] w[2] }

/// Copies the words of a quadword into fresh temporaries, so that what is
/// written next cannot change what was read.
let private copyWords bld (w: Expr[]) =
  let t = Array.init 4 (fun _ -> tmpVar bld 32<rt>)
  for i in 0 .. 3 do append bld { t[i] := w[i] }
  t

/// <summary>
/// SHA1C, SHA1P and SHA1M: four rounds of SHA-1, differing only in the choice
/// each round makes (F6.1.7, F6.1.10 and F6.1.9). The hash is the quadword Qd
/// and the low word of Qn, and the manual rotates the 160-bit pair left by a
/// word at the end of each round, which is a renaming of the temporaries here.
/// </summary>
let private sha1Hash (ins: Instruction) bld choose =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src1, src2) = getThreeOprs ins
    let w = copyWords bld (wordsOf bld src2)
    let x = copyWords bld (wordsOf bld dst)
    let struct (y, t, carried) = tmpVars3 bld 32<rt>
    y := (wordsOf bld src1)[0]
    for e in 0 .. 3 do
      t := choose x[1] x[2] x[3]
      carried := y .+ rol32 x[0] 5 .+ t .+ w[e]
      x[1] := rol32 x[1] 30
      t := x[3]
      x[3] := x[2]
      x[2] := x[1]
      x[1] := x[0]
      x[0] := carried
      y := t
    putWords bld dst x
    putEndLabel bld lblIgnore
  }

let sha1c ins bld = sha1Hash ins bld shaChoose

let sha1p ins bld = sha1Hash ins bld shaParity

let sha1m ins bld = sha1Hash ins bld shaMajority

/// SHA1H: the low word of Qm rotated, the rest of Qd cleared (F6.1.8).
let sha1h (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src) = getTwoOprs ins
    let low = (wordsOf bld src)[0]
    let t = tmpVar bld 32<rt>
    t := rol32 low 30
    let zero = AST.num0 32<rt>
    putWords bld dst [| t; zero; zero; zero |]
    putEndLabel bld lblIgnore
  }

/// SHA1SU0: the first half of the schedule update, exclusive ors over a
/// window of Qd's top half and Qn's bottom half (F6.1.11).
let sha1su0 (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src1, src2) = getThreeOprs ins
    let d = copyWords bld (wordsOf bld dst)
    let n = wordsOf bld src1
    let m = wordsOf bld src2
    let window = [| d[2]; d[3]; n[0]; n[1] |]
    let r = Array.init 4 (fun i -> window[i] <+> d[i] <+> m[i])
    putWords bld dst (copyWords bld r)
    putEndLabel bld lblIgnore
  }

/// SHA1SU1: every word of Qd, exclusive-or'd with Qm shifted down a word, is
/// rotated, and the top one mixed with the bottom one's rotate (F6.1.12).
let sha1su1 (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src) = getTwoOprs ins
    let d = wordsOf bld dst
    let n = wordsOf bld src
    let mixed =
      [| d[0] <+> n[1]
         d[1] <+> n[2]
         d[2] <+> n[3]
         d[3] |]
    let t = copyWords bld mixed
    let r =
      [| rol32 t[0] 1
         rol32 t[1] 1
         rol32 t[2] 1
         rol32 t[3] 1 <+> rol32 t[0] 2 |]
    putWords bld dst (copyWords bld r)
    putEndLabel bld lblIgnore
  }

/// SHA256SU0: the schedule's sigma-0 step over a window that starts a word
/// into Qd and takes its last word from Qm (F6.1.15).
let sha256su0 (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src) = getTwoOprs ins
    let d = copyWords bld (wordsOf bld dst)
    let n = wordsOf bld src
    let window = [| d[1]; d[2]; d[3]; n[0] |]
    let sigma e = ror32 e 7 <+> ror32 e 18 <+> (e >> numI32 3 32<rt>)
    let r = Array.init 4 (fun i -> sigma window[i] .+ d[i])
    putWords bld dst (copyWords bld r)
    putEndLabel bld lblIgnore
  }

/// <summary>
/// SHA256SU1: the schedule's sigma-1 step (F6.1.16). The halves are not
/// alike: the first pair of words mixes Qm's top half and the second pair
/// what the first pair just produced, which is why the words are written
/// into temporaries a pair at a time.
/// </summary>
let sha256su1 (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src1, src2) = getThreeOprs ins
    let d = copyWords bld (wordsOf bld dst)
    let n = wordsOf bld src1
    let m = copyWords bld (wordsOf bld src2)
    let t0 = [| n[1]; n[2]; n[3]; m[0] |]
    let sigma e = ror32 e 17 <+> ror32 e 19 <+> (e >> numI32 10 32<rt>)
    let r = Array.init 4 (fun _ -> tmpVar bld 32<rt>)
    for i in 0 .. 1 do r[i] := sigma m[i + 2] .+ d[i] .+ t0[i]
    for i in 2 .. 3 do r[i] := sigma r[i - 2] .+ d[i] .+ t0[i]
    putWords bld dst r
    putEndLabel bld lblIgnore
  }

/// The SHA-256 Sigma functions of the compression rounds.
let private shaSigma0 x = ror32 x 2 <+> ror32 x 13 <+> ror32 x 22

let private shaSigma1 x = ror32 x 6 <+> ror32 x 11 <+> ror32 x 25

/// One round of SHA-256 over the pair x (a, b, c, d) and y (e, f, g, h),
/// rotating the 256-bit pair left by a word, done by renaming temporaries.
let private sha256Round bld (x: Expr[]) (y: Expr[]) w t carried =
  append bld {
    t := y[3] .+ shaSigma1 y[0] .+ shaChoose y[0] y[1] y[2] .+ w
  }
  append bld { x[3] := t .+ x[3] }
  append bld { y[3] := t .+ shaSigma0 x[0] .+ shaMajority x[0] x[1] x[2] }
  append bld { carried := x[3] }
  for i in 3 .. -1 .. 1 do append bld { x[i] := x[i - 1] }
  append bld { x[0] := y[3] }
  for i in 3 .. -1 .. 1 do append bld { y[i] := y[i - 1] }
  append bld { y[0] := carried }

/// <summary>
/// SHA256H and SHA256H2: four rounds of SHA-256 between them (F6.1.13 and
/// F6.1.14). The manual states one function over a 256-bit pair and the two
/// call it with Qd and Qn the other way round, each keeping the half it is
/// named for.
/// </summary>
let sha256Hash (ins: Instruction) bld keepX =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src1, src2) = getThreeOprs ins
    let w = copyWords bld (wordsOf bld src2)
    let d = wordsOf bld dst
    let n = wordsOf bld src1
    let x = copyWords bld (if keepX then d else n)
    let y = copyWords bld (if keepX then n else d)
    let struct (t, carried) = tmpVars2 bld 32<rt>
    for e in 0 .. 3 do sha256Round bld x y w[e] t carried
    putWords bld dst (if keepX then x else y)
    putEndLabel bld lblIgnore
  }
