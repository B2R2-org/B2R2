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

/// The conversions between the three Unicode encodings, CU12 and its kin.
/// Each reads the second operand one character at a time and writes it to the
/// first in the other encoding, both operands named by a register pair holding
/// an address and a length that are left pointing past what was converted.
module internal B2R2.FrontEnd.S390.UnicodeLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.S390
open B2R2.FrontEnd.S390.LiftingUtils

/// The two operands of a conversion: the first is written and the second read,
/// each an address in an even register and a length in the odd one after it.
type private Streams =
  { Dst: Expr
    DstLen: Expr
    Src: Expr
    SrcLen: Expr }

/// The character in hand: its code point, the bytes it took from the second
/// operand, and the bytes it will take in the first.
type private CodePoint =
  { Cp: Expr
    Need: Expr
    Out: Expr }

/// Where a conversion leaves its loop: the second operand used up, the first
/// operand full, or a malformed character.
type private Exits =
  { Done: Label
    Full: Label
    Bad: Label }

let private newStreams bld r1 r2 =
  { Dst = reg bld r1
    DstLen = reg bld (pairOf r1)
    Src = reg bld r2
    SrcLen = reg bld (pairOf r2) }

let private newCodePoint bld =
  { Cp = tmpVar bld 32<rt>
    Need = tmpVar bld GRSize
    Out = tmpVar bld GRSize }

let private newExits bld =
  { Done = label bld "CuDone"
    Full = label bld "CuFull"
    Bad = label bld "CuBad" }

let private numW32 (v: int) = numI32 v 32<rt>

let private zext32 e = AST.zext 32<rt> e

let private lo8 e = AST.xtlo 8<rt> e

/// Whether a code point lies in the given range, inclusive.
let private between e lo hi = (e .>= numW32 lo) .& (e .<= numW32 hi)

/// Whether a UTF-8 byte is a continuation byte, 80 to BF.
let private isCont b = (b .& numI32 0xc0 8<rt>) == numI32 0x80 8<rt>

/// The six payload bits of a continuation byte, in place for the given shift.
let private contBits b shift =
  zext32 (b .& numI32 0x3f 8<rt>) << numW32 shift

/// The payload bits of a lead byte under the given mask, in place for the
/// given shift.
let private leadBits b mask shift =
  zext32 (b .& numI32 mask 8<rt>) << numW32 shift

/// How many bytes a UTF-8 character has, by its lead byte, or zero when the
/// byte cannot lead one: 80 to BF, or F8 and above.
let private utf8Length b0 =
  let inRange lo hi = (b0 .>= numI32 lo 8<rt>) .& (b0 .<= numI32 hi 8<rt>)
  let four = AST.ite (inRange 0xf0 0xf7) (numG 4L) (numG 0L)
  let three = AST.ite (inRange 0xe0 0xef) (numG 3L) four
  let two = AST.ite (inRange 0xc0 0xdf) (numG 2L) three
  AST.ite (b0 .< numI32 0x80 8<rt>) (numG 1L) two

/// The lead byte of a UTF-8 character and what it settles: a byte that cannot
/// lead one is malformed, and a character the second operand has too few
/// bytes left for ends the conversion.
let private utf8Lead bld (s: Streams) (x: Exits) (ch: CodePoint) b0 =
  let lenOk = label bld "U8LenOk"
  let haveAll = label bld "U8HaveAll"
  append bld {
    b0 := loadMem 8<rt> s.Src
    ch.Need := utf8Length b0
    AST.cjmp (ch.Need == numG 0L) (AST.jmpDest x.Bad) (AST.jmpDest lenOk)
    AST.lmark lenOk
    AST.cjmp (s.SrcLen .< ch.Need) (AST.jmpDest x.Done) (AST.jmpDest haveAll)
    AST.lmark haveAll
  }

/// The value of a two-byte UTF-8 character, and whether it is ill-formed: a
/// second byte that is not a continuation byte, or a value that would have
/// fit in one byte.
let private utf8Two bld (ch: CodePoint) bad b0 b1 =
  append bld {
    ch.Cp := leadBits b0 0x1f 6 .| contBits b1 0
    bad := (AST.not (isCont b1)) .| (ch.Cp .< numW32 0x80)
  }

/// The same for three bytes, a surrogate being ill-formed as well.
let private utf8Three bld (ch: CodePoint) bad b0 b1 b2 =
  append bld {
    ch.Cp := (leadBits b0 0x0f 12 .| contBits b1 6) .| contBits b2 0
    let cont = isCont b1 .& isCont b2
    let overlong = ch.Cp .< numW32 0x800
    bad := ((AST.not cont) .| overlong) .| between ch.Cp 0xd800 0xdfff
  }

/// The same for four bytes, a value above 10FFFF being ill-formed as well.
let private utf8Four bld (ch: CodePoint) bad b0 b1 b2 b3 =
  append bld {
    let high = leadBits b0 0x07 18 .| contBits b1 12
    ch.Cp := (high .| contBits b2 6) .| contBits b3 0
    let cont = (isCont b1 .& isCont b2) .& isCont b3
    let overlong = ch.Cp .< numW32 0x10000
    bad := ((AST.not cont) .| overlong) .| (ch.Cp .> numW32 0x10ffff)
  }

/// The value of a UTF-8 character of the length its lead byte gave, read one
/// byte at a time so that no more of the second operand is touched than the
/// character has.
let private utf8Value bld (s: Streams) (ch: CodePoint) bad bytes =
  let struct (b0, b1, b2, b3) = bytes
  let one = label bld "U8One"
  let more1 = label bld "U8More1"
  let two = label bld "U8Two"
  let more2 = label bld "U8More2"
  let three = label bld "U8Three"
  let four = label bld "U8Four"
  let decoded = label bld "U8Decoded"
  let at k = loadMem 8<rt> (s.Src .+ numG k)
  append bld {
    AST.cjmp (ch.Need == numG 1L) (AST.jmpDest one) (AST.jmpDest more1)
    AST.lmark one
    ch.Cp := zext32 b0
    bad := AST.b0
    AST.jmp (AST.jmpDest decoded)
    AST.lmark more1
    b1 := at 1L
    AST.cjmp (ch.Need == numG 2L) (AST.jmpDest two) (AST.jmpDest more2)
    AST.lmark two
    utf8Two bld ch bad b0 b1
    AST.jmp (AST.jmpDest decoded)
    AST.lmark more2
    b2 := at 2L
    AST.cjmp (ch.Need == numG 3L) (AST.jmpDest three) (AST.jmpDest four)
    AST.lmark three
    utf8Three bld ch bad b0 b1 b2
    AST.jmp (AST.jmpDest decoded)
    AST.lmark four
    b3 := at 3L
    utf8Four bld ch bad b0 b1 b2 b3
    AST.lmark decoded
  }

/// The well-formedness check, made only when the instruction asks for it.
let private utf8Check wellFormed bld (x: Exits) bad =
  let ok = label bld "U8Ok"
  if wellFormed then
    append bld {
      AST.cjmp bad (AST.jmpDest x.Bad) (AST.jmpDest ok)
      AST.lmark ok
    }
  else
    ()

/// Reads one UTF-8 character. Its lead byte says how many bytes it has, and a
/// byte that cannot lead one is malformed. When well-formedness is asked for,
/// so is a character whose continuation bytes are not 80 to BF, or whose
/// value is overlong for its length, a surrogate, or above 10FFFF.
let private decodeUtf8 wellFormed bld s x ch =
  let struct (b0, b1, b2, b3) = tmpVars4 bld 8<rt>
  let bad = tmpVar bld 1<rt>
  utf8Lead bld s x ch b0
  utf8Value bld s ch bad (struct (b0, b1, b2, b3))
  utf8Check wellFormed bld x bad

/// Reads one UTF-16 character: a unit from D800 to DBFF is the high half of a
/// pair whose other half must be from DC00 to DFFF.
let private decodeUtf16 bld (s: Streams) (x: Exits) (ch: CodePoint) =
  let u0 = tmpVar bld 16<rt>
  let u1 = tmpVar bld 16<rt>
  let haveAll = label bld "U16HaveAll"
  let single = label bld "U16Single"
  let pair = label bld "U16Pair"
  let lowOk = label bld "U16LowOk"
  let decoded = label bld "U16Decoded"
  let isHigh = (u0 .>= numI32 0xd800 16<rt>) .& (u0 .<= numI32 0xdbff 16<rt>)
  let isLow = (u1 .>= numI32 0xdc00 16<rt>) .& (u1 .<= numI32 0xdfff 16<rt>)
  append bld {
    u0 := loadMem 16<rt> s.Src
    ch.Need := AST.ite isHigh (numG 4L) (numG 2L)
    AST.cjmp (s.SrcLen .< ch.Need) (AST.jmpDest x.Done) (AST.jmpDest haveAll)
    AST.lmark haveAll
    AST.cjmp isHigh (AST.jmpDest pair) (AST.jmpDest single)
    AST.lmark single
    ch.Cp := zext32 u0
    AST.jmp (AST.jmpDest decoded)
    AST.lmark pair
    u1 := loadMem 16<rt> (s.Src .+ numG 2L)
    AST.cjmp isLow (AST.jmpDest lowOk) (AST.jmpDest x.Bad)
    AST.lmark lowOk
    let high = (zext32 u0 .- numW32 0xd800) << numW32 10
    let low = zext32 u1 .- numW32 0xdc00
    ch.Cp := (numW32 0x10000 .+ high) .+ low
    AST.lmark decoded
  }

/// Reads one UTF-32 character, which must be at most 10FFFF and no surrogate.
let private decodeUtf32 bld (s: Streams) (x: Exits) (ch: CodePoint) =
  let haveAll = label bld "U32HaveAll"
  let ok = label bld "U32Ok"
  append bld {
    ch.Need := numG 4L
    AST.cjmp (s.SrcLen .< ch.Need) (AST.jmpDest x.Done) (AST.jmpDest haveAll)
    AST.lmark haveAll
    ch.Cp := loadMem 32<rt> s.Src
    let bad = (ch.Cp .> numW32 0x10ffff) .| between ch.Cp 0xd800 0xdfff
    AST.cjmp bad (AST.jmpDest x.Bad) (AST.jmpDest ok)
    AST.lmark ok
  }

/// Checks that the first operand has room for the bytes the character will
/// take, ending the conversion when it does not.
let private room bld (s: Streams) (x: Exits) (ch: CodePoint) name =
  let roomOk = label bld name
  append bld {
    AST.cjmp (s.DstLen .< ch.Out) (AST.jmpDest x.Full) (AST.jmpDest roomOk)
    AST.lmark roomOk
  }

/// Stores a byte of the character's encoding when the encoding is long enough
/// to have it.
let private storeByteIf bld (s: Streams) (ch: CodePoint) k v =
  let dst = s.Dst .+ numG (int64 k)
  _when bld "U8Byte" (ch.Out .> numG (int64 k)) (block { storeMem dst v })

/// Writes one character as UTF-8: one byte below 80, two below 800, three
/// below 10000, and four above.
let private encodeUtf8 bld (s: Streams) (x: Exits) (ch: CodePoint) =
  let cp = ch.Cp
  let cont shift =
    numI32 0x80 8<rt> .| lo8 ((cp >> numW32 shift) .& numW32 0x3f)
  let lead mark shift = numI32 mark 8<rt> .| lo8 (cp >> numW32 shift)
  let is n = ch.Out == numG n
  let three = AST.ite (cp .< numW32 0x10000) (numG 3L) (numG 4L)
  let two = AST.ite (cp .< numW32 0x800) (numG 2L) three
  let lead3 = AST.ite (is 3L) (lead 0xe0 12) (lead 0xf0 18)
  let lead2 = AST.ite (is 2L) (lead 0xc0 6) lead3
  let first = AST.ite (is 1L) (lo8 cp) lead2
  let second = AST.ite (is 2L) (cont 0) (AST.ite (is 3L) (cont 6) (cont 12))
  let third = AST.ite (is 3L) (cont 0) (cont 6)
  append bld {
    ch.Out := AST.ite (cp .< numW32 0x80) (numG 1L) two
  }
  room bld s x ch "U8RoomOk"
  append bld {
    storeMem s.Dst first
  }
  storeByteIf bld s ch 1 second
  storeByteIf bld s ch 2 third
  storeByteIf bld s ch 3 (cont 0)

/// Writes one character as UTF-16: one unit below 10000, else a surrogate
/// pair.
let private encodeUtf16 bld (s: Streams) (x: Exits) (ch: CodePoint) =
  let single = label bld "U16Out1"
  let pair = label bld "U16Out2"
  let encoded = label bld "U16Encoded"
  let cp = ch.Cp
  let v = cp .- numW32 0x10000
  let high = numW32 0xd800 .+ (v >> numW32 10)
  let low = numW32 0xdc00 .+ (v .& numW32 0x3ff)
  append bld {
    ch.Out := AST.ite (cp .< numW32 0x10000) (numG 2L) (numG 4L)
  }
  room bld s x ch "U16RoomOk"
  append bld {
    AST.cjmp (ch.Out == numG 2L) (AST.jmpDest single) (AST.jmpDest pair)
    AST.lmark single
    storeMem s.Dst (AST.xtlo 16<rt> cp)
    AST.jmp (AST.jmpDest encoded)
    AST.lmark pair
    storeMem s.Dst (AST.xtlo 16<rt> high)
    storeMem (s.Dst .+ numG 2L) (AST.xtlo 16<rt> low)
    AST.lmark encoded
  }

/// Writes one character as UTF-32.
let private encodeUtf32 bld (s: Streams) (x: Exits) (ch: CodePoint) =
  append bld {
    ch.Out := numG 4L
  }
  room bld s x ch "U32RoomOk"
  append bld {
    storeMem s.Dst ch.Cp
  }

/// The condition code each way out of the loop sets: the second operand used
/// up, the first full, or a malformed character.
let private convertExits bld (x: Exits) out =
  append bld {
    AST.lmark x.Done
    setCC bld 0
    AST.jmp (AST.jmpDest out)
    AST.lmark x.Full
    setCC bld 1
    AST.jmp (AST.jmpDest out)
    AST.lmark x.Bad
    setCC bld 2
    AST.lmark out
  }

/// Runs a conversion: while the second operand has anything left, one
/// character is read from it and, if the first operand has room, written
/// there in the other encoding, both operands then advancing past it. The
/// condition code says what ended the loop: the second operand used up, or
/// ending in a partial character; the first operand full; or a malformed
/// character, which is left unconverted along with everything after it.
let private convert ins bld decode encode =
  let oprs = oprArray ins
  let r1 = oprReg oprs[0]
  let r2 = oprReg oprs[1]
  if not (isPair r1 && isPair r2) then
    specException ins bld
  else
    let s = newStreams bld r1 r2
    let ch = newCodePoint bld
    let x = newExits bld
    let body = label bld "CuBody"
    let next = label bld "CuNext"
    let out = label bld "CuOut"
    lift bld (ins: Instruction) {
      AST.lmark body
      AST.cjmp (s.SrcLen == numG 0L) (AST.jmpDest x.Done) (AST.jmpDest next)
      AST.lmark next
      decode bld s x ch
      encode bld s x ch
      s.Src := s.Src .+ ch.Need
      s.SrcLen := s.SrcLen .- ch.Need
      s.Dst := s.Dst .+ ch.Out
      s.DstLen := s.DstLen .- ch.Out
      AST.jmp (AST.jmpDest body)
      convertExits bld x out
    }

/// Whether the M3 field asks for well-formedness checking, with its leftmost
/// bit.
let private wellFormed (ins: Instruction) =
  match ins.Operands with
  | ThreeOperands(_, _, OpMask m) -> m &&& 8us <> 0us
  | _ -> false

/// Translates one Unicode conversion.
let translate (ins: Instruction) bld =
  match ins.Opcode with
  | Opcode.CU12 | Opcode.CUTFU ->
    convert ins bld (decodeUtf8 (wellFormed ins)) encodeUtf16
  | Opcode.CU14 ->
    convert ins bld (decodeUtf8 (wellFormed ins)) encodeUtf32
  | Opcode.CU21 | Opcode.CUUTF ->
    convert ins bld decodeUtf16 encodeUtf8
  | Opcode.CU24 ->
    convert ins bld decodeUtf16 encodeUtf32
  | Opcode.CU41 ->
    convert ins bld decodeUtf32 encodeUtf8
  | Opcode.CU42 ->
    convert ins bld decodeUtf32 encodeUtf16
  | _ ->
    raise ParsingFailureException
