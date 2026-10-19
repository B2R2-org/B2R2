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
/// The vector facility's cryptography support: the AES rounds, the SHA-2
/// sigma functions, the carry-less multiply-sums and the permute-and-XOR.
/// <para>
/// An AES round goes out as the named call the other front ends use for it,
/// a round being one operation no shorter spelling makes clearer. Those calls
/// number the state's bytes from the least significant end, where the vector
/// facility numbers them from the most significant one, so the state and the
/// round key are laid out the other way round on the way in and the answer's
/// bytes are read back from that end.
/// </para>
/// </summary>
module internal B2R2.FrontEnd.PPC.VectorCryptoLifter

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC.LiftingUtils
open B2R2.FrontEnd.PPC.VectorElements

/// A vector register's value laid out the way the named AES calls take a
/// state: its byte k at bits 8k, counted from the least significant end.
let private aesState bld opr =
  elementsOf bld 8<rt> opr |> Array.rev |> concatElements

/// The two operands of an AES round, held in that layout.
let private aesOperands bld o2 o3 =
  let struct (state, key) = tmpVars2 bld 128<rt>
  append bld {
    state := aesState bld o2
    key := aesState bld o3
  }
  struct (state, key)

/// The answer of a named AES call, held, as the bytes the vector facility
/// numbers 0 to 15.
let private aesCall bld name args =
  let t = tmpVar bld 128<rt>
  append bld { t := AST.app name args 128<rt> }
  Array.init 16 (fun k -> AST.extract t 8<rt> (8 * k))

/// vcipher/vcipherlast/vncipherlast: one AES round over vA as the state and vB
/// as the round key, the named call doing exactly what the instruction does.
let aesRound ins bld name =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (state, key) = aesOperands bld o2 o3
    putElements bld o1 (aesCall bld name [ state; key ])
  }

/// vncipher, whose round adds the key before InvMixColumns rather than after
/// it: the last-round call (InvShiftRows, InvSubBytes, AddRoundKey) followed
/// by InvMixColumns on its own.
let vncipher ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (state, key) = aesOperands bld o2 o3
    let round = tmpVar bld 128<rt>
    round := AST.app "AESDECLAST" [ state; key ] 128<rt>
    putElements bld o1 (aesCall bld "AESIMC" [ round ])
  }

/// vsbox, SubBytes alone. The last-round call applies ShiftRows as well,
/// which moves bytes without changing them, so its answer is put back in
/// place: byte r + 4c of the state comes from byte r + 4((c - r) mod 4) of
/// the call's.
let vsbox ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let state = tmpVar bld 128<rt>
    state := aesState bld o2
    let bytes = aesCall bld "AESENCLAST" [ state; AST.num0 128<rt> ]
    Array.init 16 (fun k -> bytes[k % 4 + 4 * ((k / 4 - k % 4 + 4) % 4)])
    |> putElements bld o1
  }

/// The rotate-right of an element by a fixed count.
let private rotr esize (x: Expr) n =
  (x >> numI32 n esize) .| (x << numI32 (int esize - n) esize)

/// The SHA-2 sigma functions of one element, as rotate and shift counts: the
/// lower-case sigma (ST = 0) ends in a shift, the upper-case one (ST = 1) in a
/// third rotate.
let private sigma esize st six (x: Expr) =
  let n i = numI32 i esize
  let a, b, c =
    match int esize, st, six with
    | 32, false, false -> 7, 18, 3
    | 32, false, true -> 17, 19, 10
    | 32, true, false -> 2, 13, 22
    | 32, true, true -> 6, 11, 25
    | _, false, false -> 1, 8, 7
    | _, false, true -> 19, 61, 6
    | _, true, false -> 28, 34, 39
    | _, true, true -> 14, 18, 41
  let last = if st then rotr esize x c else x >> n c
  rotr esize x a <+> rotr esize x b <+> last

/// vshasigmaw/vshasigmad: a SHA-256 or SHA-512 sigma function of each element
/// of vA, ST picking the upper- or lower-case one and a bit of SIX for each
/// element which of its two: bit i for word i, and bit 2i for doubleword i.
let vshasigma ins bld esize =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let st = getImmValue o3 = 1u
    let six = getImmValue o4
    let a = elementsOf bld esize o2
    let step = if int esize = 32 then 1 else 2
    a
    |> Array.mapi (fun i x ->
      sigma esize st ((six >>> (3 - step * i)) &&& 1u = 1u) x)
    |> putElements bld o1
  }

/// The carry-less product of two elements, twice their width: the XOR of a
/// copy of a shifted to each bit of b that is set.
let private carrylessProduct (esize: RegType) a b =
  let wide = regTypeOf (int esize * 2)
  let aw = AST.zext wide a
  Array.init (int esize) (fun j ->
    AST.ite (AST.extract b 1<rt> j) (aw << numI32 j wide) (AST.num0 wide))
  |> Array.reduce (<+>)

/// vpmsum*: the carry-less products of each pair of elements of vA and vB,
/// XORed in twos into elements twice as wide.
let vpmsum ins bld esize =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let a = elementsOf bld esize o2
    let b = elementsOf bld esize o3
    Array.init (a.Length / 2) (fun i ->
      carrylessProduct esize a[2 * i] b[2 * i]
      <+> carrylessProduct esize a[2 * i + 1] b[2 * i + 1])
    |> putElements bld o1
  }

/// The byte of a 16-byte vector a run-time index names, by a chain of selects.
let byteAt (bytes: Expr[]) index =
  let rt = Expr.typeOf index
  bytes
  |> Array.mapi (fun k b -> k, b)
  |> Array.fold (fun acc (k, b) ->
    AST.ite (index == numI32 k rt) b acc) (AST.num0 8<rt>)

/// vpermxor, which XORs the byte of vA the high nibble of each byte of vC
/// names with the byte of vB its low nibble names.
let vpermxor ins bld =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let a = elementsOf bld 8<rt> o2
    let b = elementsOf bld 8<rt> o3
    let c = elementsOf bld 8<rt> o4
    c
    |> Array.map (fun sel ->
      byteAt a (sel >> numI32 4 8<rt>) <+> byteAt b (sel .& numI32 15 8<rt>))
    |> putElements bld o1
  }
