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

/// The packed-decimal instructions of the System/360 commercial instruction
/// set. A packed field holds two digits to a byte, the low half of its last
/// byte being the sign, and the arithmetic here carries such a field as a
/// binary number wide enough for its thirty-one digits, does the operation
/// in binary, and packs the result again.
module internal B2R2.FrontEnd.S390.DecimalLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.S390
open B2R2.FrontEnd.S390.LiftingUtils

/// The width a decimal number is carried in while it is binary: the thirty-one
/// digits of a sixteen-byte field need 103 bits, and so does the widest
/// product MULTIPLY DECIMAL may form.
let [<Literal>] DecSize = 128<rt>

/// A constant wider than the machine integers.
let private numBig (v: bigint) = BitVector(v, DecSize) |> AST.num

/// Ten to the given power.
let private pow10 n = numBig (bigint.Pow(10I, n))

let private ten = numI32 10 DecSize

let private hiNibble b = b >> numI32 4 8<rt>

let private loNibble b = b .& numI32 0xf 8<rt>

/// A nibble moved up into the high half of a byte.
let private toHigh n = n << numI32 4 8<rt>

/// Whether a sign nibble is one of the two minus codes, B and D.
let private isMinus s = (s == numI32 0xb 8<rt>) .| (s == numI32 0xd 8<rt>)

/// A decimal-width value negated when the condition holds: the two's
/// complement written as an exclusive-or with the all-ones mask the condition
/// sign-extends to, less that mask, so that nothing wider than a machine word
/// needs a conditional or a unary negation.
let private negWhen cond v =
  let m = AST.sext DecSize cond
  (v <+> m) .- m

/// The bytes of a field of storage, each held in a temporary so that a result
/// written over the field cannot change what was read from it.
let private loadBytes bld addr len =
  let bytes = Array.init len (fun _ -> tmpVar bld 8<rt>)
  append bld {
    for i in 0 .. len - 1 do
      bytes[i] := loadMem 8<rt> (addr .+ numG (int64 i))
  }
  bytes

/// The byte k places from the right end of a field, or zero past its left end,
/// which is what a shorter operand supplies to a longer one.
let private byteFromRight (bytes: Expr[]) k =
  if k < bytes.Length then bytes[bytes.Length - 1 - k] else AST.num0 8<rt>

/// Nibble n from the right end of a packed field, the sign being nibble zero:
/// the odd-numbered nibbles are high halves and the even ones low halves.
let private nibbleFromRight bytes n =
  let b = byteFromRight bytes (n / 2)
  if n % 2 = 1 then hiNibble b else loNibble b

/// The digits of a packed field, most significant first: both halves of every
/// byte but the last, whose low half is the sign.
let private packedDigits (bytes: Expr[]) =
  Array.init (2 * bytes.Length - 1) (fun i ->
    if i % 2 = 0 then hiNibble bytes[i / 2] else loNibble bytes[i / 2])

let private packedSign bytes = byteFromRight bytes 0 |> loNibble

/// The signed value of the packed field of the given length at the given
/// address, carried in a temporary of the decimal width.
let private loadPacked bld addr len =
  let bytes = loadBytes bld addr len
  let mag = tmpVar bld DecSize
  let v = tmpVar bld DecSize
  append bld {
    mag := AST.num0 DecSize
    for d in packedDigits bytes do
      mag := (mag .* ten) .+ AST.zext DecSize d
    v := negWhen (isMinus (packedSign bytes)) mag
  }
  v

/// Writes a signed value into the packed field of the given length at the
/// given address, keeping the low-order digits when there are more than the
/// field holds, and reports whether any were lost. A zero result is positive.
let private storePacked bld addr len v =
  let m = tmpVar bld DecSize
  let neg = tmpVar bld 1<rt>
  let ovf = tmpVar bld 1<rt>
  let d0 = tmpVar bld 8<rt>
  append bld {
    neg := v ?< AST.num0 DecSize
    m := negWhen neg v
    ovf := m .>= pow10 (2 * len - 1)
    for k in 0 .. len - 1 do
      let a = addr .+ numG (int64 (len - 1 - k))
      if k = 0 then
        let sign = AST.ite neg (numI32 0xd 8<rt>) (numI32 0xc 8<rt>)
        storeMem a (toHigh (AST.xtlo 8<rt> (m .% ten)) .| sign)
        m := m ./ ten
      else
        d0 := AST.xtlo 8<rt> (m .% ten)
        m := m ./ ten
        storeMem a (toHigh (AST.xtlo 8<rt> (m .% ten)) .| d0)
        m := m ./ ten
  }
  ovf

/// The condition code of a decimal result: zero, less than zero, greater than
/// zero, or, when digits were lost, overflow.
let private setCCDecimal bld v ovf =
  append bld {
    let zero = AST.num0 DecSize
    let sign = AST.ite (v ?< zero) (numCC 1) (numCC 2)
    ccVar bld := AST.ite ovf (numCC 3) (AST.ite (v == zero) (numCC 0) sign)
  }

/// The addresses of two storage operands, each held in a temporary.
let private twoAddrs bld o1 o2 =
  let a1 = tmpVar bld GRSize
  let a2 = tmpVar bld GRSize
  append bld {
    a1 := transMem bld o1
    a2 := transMem bld o2
  }
  struct (a1, a2)

/// ADD DECIMAL and SUBTRACT DECIMAL, whose first operand takes its sum with or
/// difference from the second.
let addSub ins bld f =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let struct (a1, a2) = twoAddrs bld o1 o2
    let v1 = loadPacked bld a1 (lenOfMem o1)
    let v2 = loadPacked bld a2 (lenOfMem o2)
    let r = tmpVar bld DecSize
    r := f v1 v2
    let ovf = storePacked bld a1 (lenOfMem o1) r
    setCCDecimal bld r ovf
  }

/// ZERO AND ADD, which puts the second operand into the first, the condition
/// code reporting its sign or that it did not fit.
let zeroAndAdd ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let struct (a1, a2) = twoAddrs bld o1 o2
    let v = loadPacked bld a2 (lenOfMem o2)
    let ovf = storePacked bld a1 (lenOfMem o1) v
    setCCDecimal bld v ovf
  }

/// COMPARE DECIMAL, an algebraic comparison, so that a negative zero equals
/// zero.
let compareDecimal ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let struct (a1, a2) = twoAddrs bld o1 o2
    let v1 = loadPacked bld a1 (lenOfMem o1)
    let v2 = loadPacked bld a2 (lenOfMem o2)
    let low = AST.ite (v1 ?< v2) (numCC 1) (numCC 2)
    ccVar bld := AST.ite (v1 == v2) (numCC 0) low
  }

/// Whether the lengths of a multiply or divide are as the architecture
/// requires: a second operand of at most eight bytes, shorter than the first.
let private lengthsOk o1 o2 = lenOfMem o2 <= 8 && lenOfMem o1 > lenOfMem o2

/// MULTIPLY DECIMAL: the first operand, which must have room for the product,
/// takes its product with the second.
let multiply ins bld =
  let struct (o1, o2) = getTwoOprs ins
  if not (lengthsOk o1 o2) then
    specException ins bld
  else
    lift bld (ins: Instruction) {
      let struct (a1, a2) = twoAddrs bld o1 o2
      let v1 = loadPacked bld a1 (lenOfMem o1)
      let v2 = loadPacked bld a2 (lenOfMem o2)
      let r = tmpVar bld DecSize
      r := v1 .* v2
      storePacked bld a1 (lenOfMem o1) r |> ignore
    }

/// DIVIDE DECIMAL: the first operand is divided by the second, its leftmost
/// bytes taking the quotient and its rightmost, as many as the divisor has,
/// the remainder, which keeps the dividend's sign. A zero divisor is the
/// decimal-divide exception.
let divide ins bld =
  let struct (o1, o2) = getTwoOprs ins
  if not (lengthsOk o1 o2) then
    specException ins bld
  else
    let l1 = lenOfMem o1
    let l2 = lenOfMem o2
    lift bld (ins: Instruction) {
      let struct (a1, a2) = twoAddrs bld o1 o2
      let v1 = loadPacked bld a1 l1
      let v2 = loadPacked bld a2 l2
      let q = tmpVar bld DecSize
      let r = tmpVar bld DecSize
      let divZero =
        block { AST.sideEffect (Exception DivideError) }
      _when bld "DpZero" (v2 == AST.num0 DecSize) divZero
      q := v1 ?/ v2
      r := v1 ?% v2
      storePacked bld a1 (l1 - l2) q |> ignore
      storePacked bld (a1 .+ numG (int64 (l1 - l2))) l2 r |> ignore
    }

/// The loop of SHIFT AND ROUND DECIMAL: one digit per pass, multiplying by
/// ten for a left shift and dividing for a right one, whose last pass adds the
/// rounding digit before it divides.
let private shiftLoop bld count right m round =
  let body = label bld "SrpBody"
  let step = label bld "SrpStep"
  let left = label bld "SrpLeft"
  let rightStep = label bld "SrpRight"
  let last = label bld "SrpLast"
  let plain = label bld "SrpPlain"
  let next = label bld "SrpNext"
  let out = label bld "SrpOut"
  append bld {
    AST.lmark body
    AST.cjmp (count == AST.num0 GRSize) (AST.jmpDest out) (AST.jmpDest step)
    AST.lmark step
    AST.cjmp right (AST.jmpDest rightStep) (AST.jmpDest left)
    AST.lmark left
    m := m .* ten
    AST.jmp (AST.jmpDest next)
    AST.lmark rightStep
    AST.cjmp (count == AST.num1 GRSize) (AST.jmpDest last) (AST.jmpDest plain)
    AST.lmark last
    m := (m .+ round) ./ ten
    AST.jmp (AST.jmpDest next)
    AST.lmark plain
    m := m ./ ten
    AST.lmark next
    count := count .- AST.num1 GRSize
    AST.jmp (AST.jmpDest body)
    AST.lmark out
  }

/// SHIFT AND ROUND DECIMAL: the first operand is shifted by the rightmost six
/// bits of the second operand address, a signed count of digits, to the left
/// when positive and to the right when negative. A right shift rounds: the
/// third operand's digit is added to the last digit shifted out and the carry
/// kept. Only a left shift can overflow.
let shiftAndRound ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2, o3) = getThreeOprs ins
    let len = lenOfMem o1
    let a1 = tmpVar bld GRSize
    let count = tmpVar bld GRSize
    let right = tmpVar bld 1<rt>
    let neg = tmpVar bld 1<rt>
    let m = tmpVar bld DecSize
    let r = tmpVar bld DecSize
    a1 := transMem bld o1
    let v = loadPacked bld a1 len
    let sh = AST.xtlo 6<rt> (transMem bld o2)
    right := AST.xthi 1<rt> sh
    count := AST.zext GRSize (AST.ite right (AST.neg sh) sh)
    neg := v ?< AST.num0 DecSize
    m := negWhen neg v
    shiftLoop bld count right m (numI64 (oprImm o3) DecSize)
    r := negWhen neg m
    let ovf = storePacked bld a1 len r
    setCCDecimal bld r ovf
  }

/// TEST DECIMAL, which reports whether the digits and the sign of a packed
/// field are valid codes: digits of 0 to 9, and a sign of A to F. An invalid
/// sign is condition code 1, an invalid digit 2, and both 3.
let testDecimal ins bld =
  lift bld (ins: Instruction) {
    let o = getOneOpr ins
    let a = tmpVar bld GRSize
    a := transMem bld o
    let bytes = loadBytes bld a (lenOfMem o)
    let badDigit =
      packedDigits bytes
      |> Array.map (fun d -> d .> numI32 9 8<rt>)
      |> Array.reduce (.|)
    let badSign = packedSign bytes .< numI32 0xa 8<rt>
    let digitCode = AST.ite badDigit (numCC 2) (numCC 0)
    let signCode = AST.ite badSign (numCC 1) (numCC 0)
    ccVar bld := digitCode .+ signCode
  }

/// CONVERT TO BINARY: an eight-byte packed field becomes the low word of the
/// register, or a sixteen-byte one the whole register.
let convertToBinary ins bld rt =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let a = tmpVar bld GRSize
    a := transMem bld o2
    let v = loadPacked bld a (if rt = GRSize then 16 else 8)
    let r = oprRegVar bld o1
    (if rt = GRSize then r else low r) := AST.xtlo rt v
  }

/// CONVERT TO DECIMAL: the low word of the register, or the whole register,
/// becomes an eight- or sixteen-byte packed field.
let convertToDecimal ins bld rt =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let a = tmpVar bld GRSize
    a := transMem bld o2
    let v = AST.sext DecSize (narrowTo rt (oprRegVar bld o1))
    storePacked bld a (if rt = GRSize then 16 else 8) v |> ignore
  }

/// PACK: the digits of the second operand, one to a byte in its low halves,
/// are packed two to a byte into the first, from the right, and the high half
/// of the rightmost source byte, its zone, becomes the sign.
let pack ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let struct (a1, a2) = twoAddrs bld o1 o2
    let l1 = lenOfMem o1
    let src = loadBytes bld a2 (lenOfMem o2)
    let digit k = byteFromRight src k |> loNibble
    for k in 0 .. l1 - 1 do
      let b =
        if k = 0 then toHigh (digit 0) .| hiNibble (byteFromRight src 0)
        else toHigh (digit (2 * k)) .| digit (2 * k - 1)
      storeMem (a1 .+ numG (int64 (l1 - 1 - k))) b
  }

/// UNPACK: the digits of the packed second operand go one to a byte into the
/// first, from the right, under a zone of F, and its sign becomes the zone of
/// the rightmost result byte.
let unpack ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let struct (a1, a2) = twoAddrs bld o1 o2
    let l1 = lenOfMem o1
    let src = loadBytes bld a2 (lenOfMem o2)
    for k in 0 .. l1 - 1 do
      let b =
        if k = 0 then toHigh (packedSign src) .| nibbleFromRight src 1
        else numI32 0xf0 8<rt> .| nibbleFromRight src (k + 1)
      storeMem (a1 .+ numG (int64 (l1 - 1 - k))) b
  }

/// PACK ASCII and PACK UNICODE: the low half of each character of the second
/// operand -- a byte, or the low byte of a two-byte character -- is a digit,
/// and the digits are packed from the right into a sixteen-byte positive
/// result, zeros filling what the operand does not reach.
let packChars ins bld charSize =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let struct (a1, a2) = twoAddrs bld o1 o2
    let src = loadBytes bld a2 (lenOfMem o2)
    let digit n = byteFromRight src ((n - 1) * charSize) |> loNibble
    for k in 0 .. 15 do
      let b =
        if k = 0 then toHigh (digit 1) .| numI32 0xc 8<rt>
        else toHigh (digit (2 * k + 1)) .| digit (2 * k)
      storeMem (a1 .+ numG (int64 (15 - k))) b
  }

/// UNPACK ASCII and UNPACK UNICODE: the thirty-one digits of a sixteen-byte
/// packed second operand become the characters of the first, ASCII digits or
/// two-byte Unicode digits, as many as it has room for from the right. The
/// condition code reports the sign: plus, minus, or not a sign at all.
let unpackChars ins bld charSize =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let struct (a1, a2) = twoAddrs bld o1 o2
    let l1 = lenOfMem o1
    let src = loadBytes bld a2 16
    for c in 0 .. l1 / charSize - 1 do
      let a = a1 .+ numG (int64 (l1 - (c + 1) * charSize))
      let d = numI32 0x30 8<rt> .| nibbleFromRight src (c + 1)
      if charSize = 2 then
        storeMem a (AST.num0 8<rt>)
        storeMem (a .+ numG 1L) d
      else
        storeMem a d
    let s = packedSign src
    let sign = AST.ite (isMinus s) (numCC 1) (numCC 0)
    ccVar bld := AST.ite (s .< numI32 0xa 8<rt>) (numCC 3) sign
  }

/// What EDIT carries from one pattern byte to the next: the pattern byte being
/// replaced, the source byte the next digit comes from and whether that digit
/// is its low half, the fill character, the significance indicator, and
/// whether the field in hand has had a nonzero digit.
type private EditState =
  { Pattern: Expr
    Source: Expr
    LowNext: Expr
    Fill: Expr
    Signif: Expr
    Nonzero: Expr }

let private newEditState bld =
  { Pattern = tmpVar bld GRSize
    Source = tmpVar bld GRSize
    LowNext = tmpVar bld 1<rt>
    Fill = tmpVar bld 8<rt>
    Signif = tmpVar bld 1<rt>
    Nonzero = tmpVar bld 1<rt> }

/// A digit selector or significance starter: the next source digit goes out
/// as a zoned digit once significance is on, or when it is not zero, which
/// also turns significance on -- as a starter does regardless -- and EDIT AND
/// MARK notes where the first such digit went. A digit from a byte's high
/// half has the low half checked for a sign, which is skipped and, if plus,
/// ends significance.
let private editDigit bld (st: EditState) c d mark adv =
  let hiDone = label bld "EdHiDone"
  let loDone = label bld "EdLoDone"
  let skipSign = label bld "EdSkipSign"
  let setLow = label bld "EdSetLow"
  let srcByte = loadMem 8<rt> st.Source
  let nonzero = d != AST.num0 8<rt>
  append bld {
    d := AST.ite st.LowNext (loNibble srcByte) (hiNibble srcByte)
    let zoned = numI32 0xf0 8<rt> .| d
    storeMem st.Pattern (AST.ite (st.Signif .| nonzero) zoned st.Fill)
    if mark then
      let r1 = reg bld Register.R1
      append bld {
        r1 := AST.ite ((AST.not st.Signif) .& nonzero) st.Pattern r1
      }
    else
      ()
    st.Nonzero := st.Nonzero .| nonzero
    st.Signif := (st.Signif .| nonzero) .| (c == numI32 0x21 8<rt>)
    AST.cjmp st.LowNext (AST.jmpDest loDone) (AST.jmpDest hiDone)
    AST.lmark hiDone
    d := loNibble srcByte
    AST.cjmp (d .> numI32 9 8<rt>) (AST.jmpDest skipSign) (AST.jmpDest setLow)
    AST.lmark skipSign
    st.Signif := AST.ite (isMinus d) st.Signif AST.b0
    st.Source := st.Source .+ numG 1L
    AST.jmp (AST.jmpDest adv)
    AST.lmark setLow
    st.LowNext := AST.b1
    AST.jmp (AST.jmpDest adv)
    AST.lmark loDone
    st.Source := st.Source .+ numG 1L
    st.LowNext := AST.b0
    AST.jmp (AST.jmpDest adv)
  }

/// The pass over the pattern bytes after the fill character, each replaced
/// according to what it is: a field separator (22) ends the field and becomes
/// the fill character, a digit selector (20) or significance starter (21)
/// takes a source digit, and any other byte stays only once significance is
/// on.
let private editLoop bld (st: EditState) len mark =
  let c = tmpVar bld 8<rt>
  let d = tmpVar bld 8<rt>
  let i = tmpVar bld GRSize
  let body = label bld "EdBody"
  let next = label bld "EdNext"
  let msg = label bld "EdMsg"
  let sep = label bld "EdSep"
  let digit = label bld "EdDigit"
  let adv = label bld "EdAdv"
  let out = label bld "EdOut"
  let isSelector = (c == numI32 0x20 8<rt>) .| (c == numI32 0x21 8<rt>)
  append bld {
    i := numG 1L
    AST.lmark body
    c := loadMem 8<rt> st.Pattern
    AST.cjmp (c == numI32 0x22 8<rt>) (AST.jmpDest sep) (AST.jmpDest next)
    AST.lmark next
    AST.cjmp isSelector (AST.jmpDest digit) (AST.jmpDest msg)
    AST.lmark msg
    storeMem st.Pattern (AST.ite st.Signif c st.Fill)
    AST.jmp (AST.jmpDest adv)
    AST.lmark sep
    storeMem st.Pattern st.Fill
    st.Signif := AST.b0
    st.Nonzero := AST.b0
    AST.jmp (AST.jmpDest adv)
    AST.lmark digit
    editDigit bld st c d mark adv
    AST.lmark adv
    st.Pattern := st.Pattern .+ numG 1L
    i := i .+ numG 1L
    AST.cjmp (i == numG (int64 len)) (AST.jmpDest out) (AST.jmpDest body)
    AST.lmark out
  }

/// EDIT and EDIT AND MARK, which edit the packed digits of the second operand
/// into the pattern that is the first, in place. The pattern's first byte is
/// the fill character; the rest are replaced one by one, and the condition
/// code says whether the last field was zero, less than zero (significance
/// still on at the end), or greater than zero.
let edit ins bld mark =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let len = lenOfMem o1
    let st = newEditState bld
    st.Pattern := transMem bld o1
    st.Source := transMem bld o2
    st.Fill := loadMem 8<rt> st.Pattern
    st.Signif := AST.b0
    st.LowNext := AST.b0
    st.Nonzero := AST.b0
    st.Pattern := st.Pattern .+ numG 1L
    if len > 1 then editLoop bld st len mark else ()
    let sign = AST.ite st.Signif (numCC 1) (numCC 2)
    ccVar bld := AST.ite st.Nonzero sign (numCC 0)
  }

/// Translates one packed-decimal instruction.
let translate (ins: Instruction) bld =
  match ins.Opcode with
  | Opcode.CVB | Opcode.CVBY -> convertToBinary ins bld WSize
  | Opcode.CVBG -> convertToBinary ins bld GRSize
  | Opcode.CVD | Opcode.CVDY -> convertToDecimal ins bld WSize
  | Opcode.CVDG -> convertToDecimal ins bld GRSize
  | Opcode.PACK -> pack ins bld
  | Opcode.PKA -> packChars ins bld 1
  | Opcode.PKU -> packChars ins bld 2
  | Opcode.UNPK -> unpack ins bld
  | Opcode.UNPKA -> unpackChars ins bld 1
  | Opcode.UNPKU -> unpackChars ins bld 2
  | Opcode.AP -> addSub ins bld (.+)
  | Opcode.SP -> addSub ins bld (.-)
  | Opcode.ZAP -> zeroAndAdd ins bld
  | Opcode.CP -> compareDecimal ins bld
  | Opcode.MP -> multiply ins bld
  | Opcode.DP -> divide ins bld
  | Opcode.SRP -> shiftAndRound ins bld
  | Opcode.TP -> testDecimal ins bld
  | Opcode.ED -> edit ins bld false
  | Opcode.EDMK -> edit ins bld true
  | _ -> raise ParsingFailureException
