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

/// The AVX-512 opmask instructions: the arithmetic on the k registers that
/// every masked vector instruction ultimately depends on. Each comes in one
/// width per mask size -- B for 8 bits, W for 16, D for 32, Q for 64 -- and
/// each writes only that many bits of its destination, clearing the rest: a k
/// register is 64 bits wide whatever produced its contents.
module internal B2R2.FrontEnd.Intel.OpMaskLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.Intel
open B2R2.FrontEnd.Intel.LiftingUtils

/// The low bits of an expression, or the expression itself when it is already
/// that narrow. A mask register always arrives 64 bits wide, a memory operand
/// arrives at exactly the mask's width, and both go through here.
let private low width e =
  if Expr.typeOf e = width then e else AST.xtlo width e

/// A source operand read at the mask's width.
let private maskSrc ins bld width opr =
  transOpr ins bld false opr |> low width

/// Writes a result to a mask register, clearing the bits above it. Every page
/// in this file says DEST[MAX_KL-1:width] := 0, so the write goes through here
/// rather than through the operand-size rules, which leave the upper bits of a
/// narrow write alone.
let private writeMask ins bld dst value =
  direct (transOpr ins bld false dst) := AST.zext 64<rt> value

/// The three-operand mask logic. KAND, KANDN, KOR, KXOR, KXNOR and KADD all
/// read two masks at their width and write one back.
let private binOp (ins: Instruction) bld width op =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let src1 = maskSrc ins bld width src1
    let src2 = maskSrc ins bld width src2
    writeMask ins bld dst (op src1 src2)
  }

let kaddb ins bld = binOp ins bld 8<rt> (.+)

let kaddw ins bld = binOp ins bld 16<rt> (.+)

let kaddd ins bld = binOp ins bld 32<rt> (.+)

let kaddq ins bld = binOp ins bld 64<rt> (.+)

let kandb ins bld = binOp ins bld 8<rt> (.&)

let kandw ins bld = binOp ins bld 16<rt> (.&)

let kandd ins bld = binOp ins bld 32<rt> (.&)

let kandq ins bld = binOp ins bld 64<rt> (.&)

/// KANDN negates the first source, not the second: the operand the VEX prefix
/// names is the one complemented.
let private opAndn src1 src2 = AST.not src1 .& src2

let kandnb ins bld = binOp ins bld 8<rt> opAndn

let kandnw ins bld = binOp ins bld 16<rt> opAndn

let kandnd ins bld = binOp ins bld 32<rt> opAndn

let kandnq ins bld = binOp ins bld 64<rt> opAndn

/// Whether an operand names a mask register, which decides how wide a write to
/// it is: a mask register takes the whole 64 bits, a general-purpose register
/// the operand size the instruction declares.
let private isMaskReg = function
  | OprReg r -> RegisterHelper.getKind r = RegisterHelper.Kind.OpMaskRegister
  | _ -> false

/// KMOV moves a mask between a mask register, a general-purpose register and
/// memory. The memory form writes exactly the mask's width and nothing else;
/// the register forms clear everything above the mask, and a general-purpose
/// destination is a 32-bit write for every width but Q.
let private kmov (ins: Instruction) bld width =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let value = maskSrc ins bld width src
    if isMaskReg dst then
      writeMask ins bld dst value
    elif isMemOpr dst then
      direct (transOpr ins bld false dst) := value
    else
      let gprSize = if width = 64<rt> then 64<rt> else 32<rt>
      sized gprSize (transOpr ins bld false dst) := AST.zext gprSize value
  }

let kmovb ins bld = kmov ins bld 8<rt>

let kmovw ins bld = kmov ins bld 16<rt>

let kmovd ins bld = kmov ins bld 32<rt>

let kmovq ins bld = kmov ins bld 64<rt>

let private knot (ins: Instruction) bld width =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    writeMask ins bld dst (AST.not (maskSrc ins bld width src))
  }

let knotb ins bld = knot ins bld 8<rt>

let knotw ins bld = knot ins bld 16<rt>

let knotd ins bld = knot ins bld 32<rt>

let knotq ins bld = knot ins bld 64<rt>

let korb ins bld = binOp ins bld 8<rt> (.|)

let korw ins bld = binOp ins bld 16<rt> (.|)

let kord ins bld = binOp ins bld 32<rt> (.|)

let korq ins bld = binOp ins bld 64<rt> (.|)

/// KORTEST reports on the OR of its two masks and writes neither: ZF when the
/// OR has no bit set, CF when it has them all. The other four arithmetic flags
/// are cleared rather than left undefined.
let private kortest (ins: Instruction) bld width =
  lift bld ins {
    let struct (src1, src2) = getTwoOprs ins
    let src1 = maskSrc ins bld width src1
    let src2 = maskSrc ins bld width src2
    let t = tmpVar bld width
    direct t := src1 .| src2
    direct (regVar bld R.ZF) := t == AST.num0 width
    direct (regVar bld R.CF) := t == getMask width
    direct (regVar bld R.OF) := AST.b0
    direct (regVar bld R.AF) := AST.b0
    direct (regVar bld R.PF) := AST.b0
    direct (regVar bld R.SF) := AST.b0
#if EMULATION
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let kortestb ins bld = kortest ins bld 8<rt>

let kortestw ins bld = kortest ins bld 16<rt>

let kortestd ins bld = kortest ins bld 32<rt>

let kortestq ins bld = kortest ins bld 64<rt>

/// The shift count is an immediate, so a count that clears the mask outright
/// is settled here rather than in the IR: the manual leaves the destination
/// zero unless the count is below the mask's width, and a count of 255 on an
/// 8-bit mask is a perfectly ordinary encoding.
let private shift (ins: Instruction) bld width isLeft =
  lift bld ins {
    let struct (dst, src, imm) = getThreeOprs ins
    let count = getImmValue imm &&& 0xFFL
    let value =
      if count >= int64 (RegType.toBitWidth width) then
        AST.num0 width
      else
        let src = maskSrc ins bld width src
        let count = numI64 count width
        if isLeft then src << count else src >> count
    writeMask ins bld dst value
  }

let kshiftlb ins bld = shift ins bld 8<rt> true

let kshiftlw ins bld = shift ins bld 16<rt> true

let kshiftld ins bld = shift ins bld 32<rt> true

let kshiftlq ins bld = shift ins bld 64<rt> true

let kshiftrb ins bld = shift ins bld 8<rt> false

let kshiftrw ins bld = shift ins bld 16<rt> false

let kshiftrd ins bld = shift ins bld 32<rt> false

let kshiftrq ins bld = shift ins bld 64<rt> false

/// KTEST reports on both halves of a mask test at once: ZF when the two masks
/// share no bit, CF when the second sets no bit the first leaves clear.
let private ktest (ins: Instruction) bld width =
  lift bld ins {
    let struct (src1, src2) = getTwoOprs ins
    let src1 = maskSrc ins bld width src1
    let src2 = maskSrc ins bld width src2
    let zero = AST.num0 width
    direct (regVar bld R.ZF) := (src2 .& src1) == zero
    direct (regVar bld R.CF) := (src2 .& AST.not src1) == zero
    direct (regVar bld R.OF) := AST.b0
    direct (regVar bld R.AF) := AST.b0
    direct (regVar bld R.PF) := AST.b0
    direct (regVar bld R.SF) := AST.b0
#if EMULATION
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let ktestb ins bld = ktest ins bld 8<rt>

let ktestw ins bld = ktest ins bld 16<rt>

let ktestd ins bld = ktest ins bld 32<rt>

let ktestq ins bld = ktest ins bld 64<rt>

/// KUNPCK takes the low half of the result from its last operand and the high
/// half from the one before it, which is the opposite order to the way the two
/// are written.
let private unpck (ins: Instruction) bld halfWidth =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let hi = maskSrc ins bld halfWidth src1
    let lo = maskSrc ins bld halfWidth src2
    writeMask ins bld dst (AST.concat hi lo)
  }

let kunpckbw ins bld = unpck ins bld 8<rt>

let kunpckwd ins bld = unpck ins bld 16<rt>

let kunpckdq ins bld = unpck ins bld 32<rt>

let private opXnor src1 src2 = AST.not (src1 <+> src2)

let kxnorb ins bld = binOp ins bld 8<rt> opXnor

let kxnorw ins bld = binOp ins bld 16<rt> opXnor

let kxnord ins bld = binOp ins bld 32<rt> opXnor

let kxnorq ins bld = binOp ins bld 64<rt> opXnor

let kxorb ins bld = binOp ins bld 8<rt> (<+>)

let kxorw ins bld = binOp ins bld 16<rt> (<+>)

let kxord ins bld = binOp ins bld 32<rt> (<+>)

let kxorq ins bld = binOp ins bld 64<rt> (<+>)
