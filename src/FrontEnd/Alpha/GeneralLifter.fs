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

/// Translates every Alpha instruction but the floating-point ones: the loads
/// and stores, the branches and the calls, the arithmetic and the logic, the
/// instructions reaching inside a quadword, and the traps to PALcode.
module internal B2R2.FrontEnd.Alpha.GeneralLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.Alpha.LiftHelper

/// An instruction whose whole effect is to leave the machine as it was, which
/// is what the barriers waiting for traps and the hints about the cache are to
/// anything that models neither.
let nop (ins: Instruction) bld =
  lift bld ins { () }

/// An instruction this lifter has no model for, which the emulator is left to
/// refuse rather than to run as something it is not.
let unsupported (ins: Instruction) bld =
  lift bld ins { AST.sideEffect UnsupportedInstruction }

/// lda/ldah: an address computed into a register rather than reached. The high
/// form scales its displacement by a whole word, which is how the two together
/// reach any address a full quadword names.
let private loadAddress ins bld scale =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    match o2 with
    | OprMem(b, disp) ->
      regWrite bld (getReg o1) (regRead bld b .+ num64 (disp * scale))
    | _ ->
      raise InvalidOperandException
  }

let lda ins bld = loadAddress ins bld 1

let ldah ins bld = loadAddress ins bld 65536

/// <summary>
/// The address a memory operand names, computed into a temporary.
///
/// The unaligned forms clear the low three bits of what they compute, which is
/// how a program reaches the quadword a byte lies in without knowing where in
/// it the byte sits.
/// </summary>
let private effectiveAddr bld aligned opr =
  let t = tmpVar bld 64<rt>
  let ea = transOpr bld opr
  let ea = if aligned then ea else ea .& num64 -8
  append bld { t := ea }
  t

/// The plain loads, which differ only in how wide a piece of memory they read
/// and whether what they read is widened with its sign or with zeros.
let private load ins bld size ext aligned =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = effectiveAddr bld aligned o2
    regWrite bld (getReg o1) (ext 64<rt> (loadNative bld size ea))
  }

let ldbu ins bld = load ins bld 8<rt> AST.zext true

let ldwu ins bld = load ins bld 16<rt> AST.zext true

let ldl ins bld = load ins bld 32<rt> AST.sext true

let ldq ins bld = load ins bld 64<rt> AST.sext true

let ldqu ins bld = load ins bld 64<rt> AST.sext false

/// The plain stores, which write as much of the register as the piece of
/// memory they reach holds.
let private store ins bld size aligned =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = effectiveAddr bld aligned o2
    let v = transOpr bld o1
    storeNative bld ea (if size = 64<rt> then v else AST.xtlo size v)
  }

let stb ins bld = store ins bld 8<rt> true

let stw ins bld = store ins bld 16<rt> true

let stl ins bld = store ins bld 32<rt> true

let stq ins bld = store ins bld 64<rt> true

let stqu ins bld = store ins bld 64<rt> false

/// <summary>
/// ldl_l/ldq_l: a load that arms the reservation a following store-conditional
/// checks.
///
/// What is kept is the address and the value found there, so that the store
/// can tell whether anything wrote over it in between -- the same value-based
/// monitor the other ports with a reservation pair are modeled by, an exact
/// enough stand-in for a machine whose cache line nothing here has.
/// </summary>
let private loadLocked ins bld size =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = effectiveAddr bld true o2
    let v = tmpVar bld 64<rt>
    v := AST.sext 64<rt> (loadNative bld size ea)
    regVar bld Register.ExMonAddr := ea
    regVar bld Register.ExMonVal := v
    regWrite bld (getReg o1) v
  }

let ldll ins bld = loadLocked ins bld 32<rt>

let ldql ins bld = loadLocked ins bld 64<rt>

/// <summary>
/// stl_c/stq_c: the store half of a reservation pair, which writes only where
/// the address and the value both still match what the paired load reserved
/// and says in Ra whether it did.
///
/// Ra is both what the instruction stores and where it reports, so the value
/// is taken before the report is written.
/// </summary>
let private storeConditional ins bld size =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = effectiveAddr bld true o2
    let v = tmpVar bld 64<rt>
    let cur = tmpVar bld size
    let matched = tmpVar bld 1<rt>
    v := transOpr bld o1
    cur := loadNative bld size ea
    matched := (ea == regVar bld Register.ExMonAddr)
               .& (AST.sext 64<rt> cur == regVar bld Register.ExMonVal)
    storeNative bld ea (AST.ite matched (AST.xtlo size v) cur)
    regVar bld Register.ExMonAddr := num64 -1
    regWrite bld (getReg o1) (AST.zext 64<rt> matched)
  }

let stlc ins bld = storeConditional ins bld 32<rt>

let stqc ins bld = storeConditional ins bld 64<rt>

/// br/bsr: a branch that always goes, keeping in Ra where it came from so that
/// the subroutine form has somewhere to return to. The unconditional form
/// keeps it too, which is how a program reads its own address.
let private branchAlways ins bld kind =
  lift bld ins {
    let struct (o1, _) = getTwoOprs ins
    regWrite bld (getReg o1) (numU64 (nextAddr ins) 64<rt>)
    AST.interjmp (numU64 (branchTarget ins) 64<rt>) kind
    return NoEndMark
  }

let br ins bld = branchAlways ins bld InterJmpKind.Base

let bsr ins bld = branchAlways ins bld InterJmpKind.IsCall

/// The conditional branches, whose condition is a test of the register they
/// name against zero.
let private branchCond ins bld cond =
  lift bld ins {
    let struct (o1, _) = getTwoOprs ins
    let v = transOpr bld o1
    AST.intercjmp (cond v)
                  (numU64 (branchTarget ins) 64<rt>)
                  (numU64 (nextAddr ins) 64<rt>)
    return NoEndMark
  }

let beq ins bld = branchCond ins bld (fun v -> v == AST.num0 64<rt>)

let bne ins bld = branchCond ins bld (fun v -> v != AST.num0 64<rt>)

let blt ins bld = branchCond ins bld (fun v -> v ?< AST.num0 64<rt>)

let ble ins bld = branchCond ins bld (fun v -> v ?<= AST.num0 64<rt>)

let bgt ins bld = branchCond ins bld (fun v -> v ?> AST.num0 64<rt>)

let bge ins bld = branchCond ins bld (fun v -> v ?>= AST.num0 64<rt>)

let blbs ins bld = branchCond ins bld (fun v -> AST.xtlo 1<rt> v)

let blbc ins bld =
  branchCond ins bld (fun v -> AST.not (AST.xtlo 1<rt> v))

/// <summary>
/// jmp/jsr/ret/jsr_coroutine: a branch to an address a register holds, whose
/// low two bits the machine ignores because no instruction sits at them.
///
/// The address is taken into a temporary before Ra is written: the two are the
/// same register often enough -- a return through the register it was called
/// through is written that way -- and writing first would send the branch to
/// its own return address.
/// </summary>
let private jump ins bld kind =
  lift bld ins {
    let struct (o1, o2, _) = getThreeOprs ins
    let t = tmpVar bld 64<rt>
    t := transOpr bld o2 .& num64 -4
    regWrite bld (getReg o1) (numU64 (nextAddr ins) 64<rt>)
    AST.interjmp t kind
    return NoEndMark
  }

let jmp ins bld = jump ins bld InterJmpKind.Base

let jsr ins bld = jump ins bld InterJmpKind.IsCall

let ret ins bld = jump ins bld InterJmpKind.IsRet

let jsrCoroutine ins bld = jump ins bld InterJmpKind.IsCall

/// <summary>
/// The shape every Operate instruction shares: two values in, one register
/// out, where what stands second is a register or the number the encoding
/// holds in its place.
///
/// What the instruction computes is handed in as a function of the two, so
/// each of them below is that expression and nothing else.
/// </summary>
let private operate ins bld compute =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let a = transOpr bld o1
    let b = transOpr bld o2
    regWrite bld (getReg o3) (compute a b)
  }

/// The same, for the instructions reading only what stands second.
let private operateUnary ins bld compute =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    regWrite bld (getReg o2) (compute (transOpr bld o1))
  }

/// A longword result, which the machine leaves in a register widened with the
/// sign of its own high bit rather than truncated.
let private sextL e = AST.sext 64<rt> (AST.xtlo 32<rt> e)

let addl ins bld = operate ins bld (fun a b -> sextL (a .+ b))

let addq ins bld = operate ins bld (fun a b -> a .+ b)

let subl ins bld = operate ins bld (fun a b -> sextL (a .- b))

let subq ins bld = operate ins bld (fun a b -> a .- b)

/// The scaled adds and subtracts, which shift what stands first before adding
/// it, so that stepping through an array of longwords or of quadwords is one
/// instruction rather than two.
let private scaledAdd ins bld shift isLong =
  let compute a b =
    let sum = (a << num64 shift) .+ b
    if isLong then sextL sum else sum
  operate ins bld compute

let private scaledSub ins bld shift isLong =
  let compute a b =
    let diff = (a << num64 shift) .- b
    if isLong then sextL diff else diff
  operate ins bld compute

let s4addl ins bld = scaledAdd ins bld 2 true

let s4addq ins bld = scaledAdd ins bld 2 false

let s8addl ins bld = scaledAdd ins bld 3 true

let s8addq ins bld = scaledAdd ins bld 3 false

let s4subl ins bld = scaledSub ins bld 2 true

let s4subq ins bld = scaledSub ins bld 2 false

let s8subl ins bld = scaledSub ins bld 3 true

let s8subq ins bld = scaledSub ins bld 3 false

/// <summary>
/// The comparisons, which leave one or zero in a register rather than in
/// condition codes -- Alpha keeps none -- so that what tests a comparison is
/// an ordinary branch on a register.
/// </summary>
let private compare ins bld rel =
  operate ins bld (fun a b -> AST.zext 64<rt> (rel a b))

let cmpeq ins bld = compare ins bld (==)

let cmplt ins bld = compare ins bld (?<)

let cmple ins bld = compare ins bld (?<=)

let cmpult ins bld = compare ins bld (.<)

let cmpule ins bld = compare ins bld (.<=)

/// <summary>
/// cmpbge: eight unsigned comparisons at once, one per byte, whose answers
/// land in the low eight bits of the result.
///
/// This is what a string routine reads to find a byte in a whole quadword at
/// a time, and the reason it compares for being no smaller rather than for
/// being equal is that a zero byte is then the borrow out of its own column.
/// </summary>
let cmpbge ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let a = tmpVar bld 64<rt>
    let b = tmpVar bld 64<rt>
    let acc = tmpVar bld 64<rt>
    a := transOpr bld o1
    b := transOpr bld o2
    acc := AST.num0 64<rt>
    for i in 0 .. 7 do
      let shift = num64 (i * 8)
      let ai = AST.xtlo 8<rt> (a >> shift)
      let bi = AST.xtlo 8<rt> (b >> shift)
      acc := acc .| (AST.zext 64<rt> (ai .>= bi) << num64 i)
    regWrite bld (getReg o3) acc
  }

let logicAnd ins bld = operate ins bld (fun a b -> a .& b)

let bic ins bld = operate ins bld (fun a b -> a .& AST.not b)

let bis ins bld = operate ins bld (fun a b -> a .| b)

let ornot ins bld = operate ins bld (fun a b -> a .| AST.not b)

let logicXor ins bld = operate ins bld (fun a b -> a <+> b)

let eqv ins bld = operate ins bld (fun a b -> a <+> AST.not b)

/// <summary>
/// The conditional moves, which write what stands second only where the test
/// of what stands first holds.
///
/// The write is kept as one assignment of a choice rather than as a branch,
/// which is what the instruction is for: a program reaches for it exactly
/// where it wants no branch.
/// </summary>
let private cmov ins bld cond =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let dst = getReg o3
    let a = transOpr bld o1
    let b = transOpr bld o2
    regWrite bld dst (AST.ite (cond a) b (regRead bld dst))
  }

let cmoveq ins bld = cmov ins bld (fun v -> v == AST.num0 64<rt>)

let cmovne ins bld = cmov ins bld (fun v -> v != AST.num0 64<rt>)

let cmovlt ins bld = cmov ins bld (fun v -> v ?< AST.num0 64<rt>)

let cmovle ins bld = cmov ins bld (fun v -> v ?<= AST.num0 64<rt>)

let cmovgt ins bld = cmov ins bld (fun v -> v ?> AST.num0 64<rt>)

let cmovge ins bld = cmov ins bld (fun v -> v ?>= AST.num0 64<rt>)

let cmovlbs ins bld = cmov ins bld (fun v -> AST.xtlo 1<rt> v)

let cmovlbc ins bld =
  cmov ins bld (fun v -> AST.not (AST.xtlo 1<rt> v))

/// The shifts, whose count is the low six bits of what stands second: a shift
/// by more than the width of a quadword is not something the field can say.
let private shiftBy ins bld op =
  operate ins bld (fun a b -> op a (b .& num64 0x3f))

let sll ins bld = shiftBy ins bld (<<)

let srl ins bld = shiftBy ins bld (>>)

let sra ins bld = shiftBy ins bld (?>>)

/// <summary>
/// The bytes an extract, insert or mask instruction names in its function
/// code, as the quadword keeping exactly those of them that lie lowest.
///
/// The instruction shifts this to where its second operand points; what is
/// here is where the architecture starts from.
/// </summary>
let private extractMask (size: RegType) =
  numU64 (System.UInt64.MaxValue >>> (64 - int size)) 64<rt>

/// The low forms of extract, which shift what stands first down to the byte
/// its second operand names and keep as many bytes as the function code says.
let private extractLow ins bld size =
  operate ins bld (fun a b -> (a >> lowShift b) .& extractMask size)

/// The high forms, which shift the other way by what is left of a quadword
/// above that byte, so that the two together reach a datum lying across the
/// boundary between quadwords.
let private extractHigh ins bld size =
  operate ins bld (fun a b -> (a << highShift b) .& extractMask size)

let extbl ins bld = extractLow ins bld 8<rt>

let extwl ins bld = extractLow ins bld 16<rt>

let extll ins bld = extractLow ins bld 32<rt>

let extql ins bld = extractLow ins bld 64<rt>

let extwh ins bld = extractHigh ins bld 16<rt>

let extlh ins bld = extractHigh ins bld 32<rt>

let extqh ins bld = extractHigh ins bld 64<rt>

/// <summary>
/// The bytes an insert or a mask instruction reaches, as an eight-bit mask
/// moved to where the second operand points.
///
/// The architecture writes this mask sixteen bits wide and then reads its low
/// half for the low form of an instruction and its high half for the high one,
/// which is how a datum crossing a quadword boundary is written by a pair.
/// </summary>
let private placedMask size b =
  numU64 (sizeMask size) 64<rt> << (b .& num64 0x7)

/// The low forms of insert, which shift what stands first up to the byte the
/// second operand names and keep what stays inside the quadword.
let private insertLow ins bld size =
  let compute a b =
    (a << lowShift b) .& byteMaskToBits bld (placedMask size b)
  operate ins bld compute

/// The high forms, which keep instead what fell off the top, so that the pair
/// writes the whole of a datum lying across the boundary.
let private insertHigh ins bld size =
  let compute a b =
    (a >> highShift b) .& byteMaskToBits bld (placedMask size b >> num64 8)
  operate ins bld compute

let insbl ins bld = insertLow ins bld 8<rt>

let inswl ins bld = insertLow ins bld 16<rt>

let insll ins bld = insertLow ins bld 32<rt>

let insql ins bld = insertLow ins bld 64<rt>

let inswh ins bld = insertHigh ins bld 16<rt>

let inslh ins bld = insertHigh ins bld 32<rt>

let insqh ins bld = insertHigh ins bld 64<rt>

/// The low forms of mask, which clear the bytes an insert of the same size
/// would have written, so that the two together replace a datum in place.
let private maskLow ins bld size =
  let compute a b =
    a .& AST.not (byteMaskToBits bld (placedMask size b))
  operate ins bld compute

/// The high forms, clearing what the matching high insert would write.
let private maskHigh ins bld size =
  let compute a b =
    a .& AST.not (byteMaskToBits bld (placedMask size b >> num64 8))
  operate ins bld compute

let mskbl ins bld = maskLow ins bld 8<rt>

let mskwl ins bld = maskLow ins bld 16<rt>

let mskll ins bld = maskLow ins bld 32<rt>

let mskql ins bld = maskLow ins bld 64<rt>

let mskwh ins bld = maskHigh ins bld 16<rt>

let msklh ins bld = maskHigh ins bld 32<rt>

let mskqh ins bld = maskHigh ins bld 64<rt>

/// zap: clears each byte the low eight bits of the second operand name.
let zap ins bld =
  operate ins bld (fun a b -> a .& AST.not (byteMaskToBits bld b))

/// zapnot: keeps only those, which is how a program widens a byte, a word or
/// a longword with zeros in one instruction.
let zapnot ins bld = operate ins bld (fun a b -> a .& byteMaskToBits bld b)

let mull ins bld = operate ins bld (fun a b -> sextL (a .* b))

let mulq ins bld = operate ins bld (fun a b -> a .* b)

/// umulh: the high quadword of a product that does not fit in one, had by
/// multiplying at twice the width and keeping the half a plain multiply drops.
let umulh ins bld =
  let compute a b =
    AST.xthi 64<rt> (AST.zext 128<rt> a .* AST.zext 128<rt> b)
  operate ins bld compute

let sextb ins bld =
  operateUnary ins bld (fun v -> AST.sext 64<rt> (AST.xtlo 8<rt> v))

let sextw ins bld =
  operateUnary ins bld (fun v -> AST.sext 64<rt> (AST.xtlo 16<rt> v))

/// ctpop: how many bits are set.
let ctpop ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    regWrite bld (getReg o2) (popCount bld (transOpr bld o1))
  }

/// <summary>
/// ctlz: how many zero bits lie above the highest set one.
///
/// Smearing that bit downward turns the question into how many bits are set,
/// which is the count the instruction beside this one answers.
/// </summary>
let ctlz ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let smeared = smearHighBit bld (transOpr bld o1)
    regWrite bld (getReg o2) (num64 64 .- popCount bld smeared)
  }

/// <summary>
/// cttz: how many zero bits lie below the lowest set one.
///
/// Taking one from the value sets exactly those bits and clears the one above
/// them, so counting the bits of that -- with the value's own bits taken out,
/// which is what leaves a word of no set bits counting sixty-four -- is the
/// answer.
/// </summary>
let cttz ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let v = tmpVar bld 64<rt>
    v := transOpr bld o1
    regWrite bld (getReg o2) (popCount bld (AST.not v .& (v .- num64 1)))
  }

/// <summary>
/// The shape the byte- and word-parallel instructions share: the same
/// operation over each lane of a quadword, gathered back into one.
///
/// Each of them is that operation and the width of its lane, which is what
/// makes them one function here and eight names below.
/// </summary>
let private lanewise ins bld (lane: RegType) compute =
  lift bld ins {
    let width = RegType.toBitWidth lane
    let a = tmpVar bld 64<rt>
    let b = tmpVar bld 64<rt>
    let acc = tmpVar bld 64<rt>
    let struct (o1, o2, o3) = getThreeOprs ins
    a := transOpr bld o1
    b := transOpr bld o2
    acc := AST.num0 64<rt>
    for i in 0 .. (64 / width) - 1 do
      let shift = num64 (i * width)
      let ai = AST.xtlo lane (a >> shift)
      let bi = AST.xtlo lane (b >> shift)
      acc := acc .| (AST.zext 64<rt> (compute ai bi) << shift)
    regWrite bld (getReg o3) acc
  }

let minsb8 ins bld =
  lanewise ins bld 8<rt> (fun a b -> AST.ite (a ?< b) a b)

let minsw4 ins bld =
  lanewise ins bld 16<rt> (fun a b -> AST.ite (a ?< b) a b)

let minub8 ins bld =
  lanewise ins bld 8<rt> (fun a b -> AST.ite (a .< b) a b)

let minuw4 ins bld =
  lanewise ins bld 16<rt> (fun a b -> AST.ite (a .< b) a b)

let maxsb8 ins bld =
  lanewise ins bld 8<rt> (fun a b -> AST.ite (a ?> b) a b)

let maxsw4 ins bld =
  lanewise ins bld 16<rt> (fun a b -> AST.ite (a ?> b) a b)

let maxub8 ins bld =
  lanewise ins bld 8<rt> (fun a b -> AST.ite (a .> b) a b)

let maxuw4 ins bld =
  lanewise ins bld 16<rt> (fun a b -> AST.ite (a .> b) a b)

/// <summary>
/// perr: how far apart two quadwords are, byte by byte, summed.
///
/// The distance of a pair of bytes is their difference taken the way round
/// that leaves it positive, and what the instruction leaves is the total of
/// all eight, which is why this gathers a sum rather than lanes.
/// </summary>
let perr ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let a = tmpVar bld 64<rt>
    let b = tmpVar bld 64<rt>
    let acc = tmpVar bld 64<rt>
    a := transOpr bld o1
    b := transOpr bld o2
    acc := AST.num0 64<rt>
    for i in 0 .. 7 do
      let shift = num64 (i * 8)
      let ai = AST.zext 64<rt> (AST.xtlo 8<rt> (a >> shift))
      let bi = AST.zext 64<rt> (AST.xtlo 8<rt> (b >> shift))
      acc := acc .+ AST.ite (ai .>= bi) (ai .- bi) (bi .- ai)
    regWrite bld (getReg o3) acc
  }

/// <summary>
/// The instructions widening and narrowing the lanes of a quadword: unpacking
/// spreads bytes into wider lanes with zeros above them, and packing keeps the
/// low byte of each wider lane.
///
/// Both read only what stands second, and both are named by the two widths
/// they move between.
/// </summary>
let private repack ins bld (from: RegType) (into: RegType) =
  lift bld ins {
    let fromWidth = RegType.toBitWidth from
    let intoWidth = RegType.toBitWidth into
    let lanes = min (64 / fromWidth) (64 / intoWidth)
    (* What moves is the narrower of the two lanes, whichever direction this
       goes: unpacking widens a byte and leaves zeros above it, and packing
       keeps the low byte of a wider lane and drops the rest. Reading the
       destination's width out of the source instead would carry the
       neighbouring lane in along with it. *)
    let laneWidth = min from into
    let struct (o1, o2) = getTwoOprs ins
    let v = tmpVar bld 64<rt>
    let acc = tmpVar bld 64<rt>
    v := transOpr bld o1
    acc := AST.num0 64<rt>
    for i in 0 .. lanes - 1 do
      let lane = AST.xtlo laneWidth (v >> num64 (i * fromWidth))
      acc := acc .| (AST.zext 64<rt> lane << num64 (i * intoWidth))
    regWrite bld (getReg o2) acc
  }

let unpkbw ins bld = repack ins bld 8<rt> 16<rt>

let unpkbl ins bld = repack ins bld 8<rt> 32<rt>

let pkwb ins bld = repack ins bld 16<rt> 8<rt>

let pklb ins bld = repack ins bld 32<rt> 8<rt>

/// <summary>
/// The extensions this lifter has a model for, as the mask amask reports them
/// by: the byte and word instructions, the ones moving between register files
/// and taking square roots, the ones counting bits, and the byte- and
/// word-parallel ones.
///
/// A program reads this to decide whether to use them, so what is claimed here
/// has to be what is lifted below -- claiming one that is not would send the
/// program to an instruction the emulator refuses.
/// </summary>
let [<Literal>] private ImplementedExtensions = 0x107UL

/// amask: clears from its argument the bit of every extension this machine
/// has, leaving set the bits of those it lacks.
let amask ins bld =
  let mask = numU64 ImplementedExtensions 64<rt>
  operateUnary ins bld (fun v -> v .& AST.not mask)

/// implver: which member of the family this is, of which 2 names the last one
/// and the one the extensions above together describe.
let implver ins bld =
  lift bld ins { regWrite bld (getReg (getOneOpr ins)) (num64 2) }

/// mb/wmb: the barriers ordering what reaches memory around them.
let memoryBarrier (ins: Instruction) bld =
  lift bld ins { AST.sideEffect Fence }

/// <summary>
/// rpcc: the cycle counter, which the emulator supplies because nothing in the
/// IR counts cycles.
///
/// The architecture puts the count in the low longword and a correction the
/// operating system keeps in the high one, so what is asked for is the lower
/// half.
/// </summary>
let rpcc ins bld =
  lift bld ins {
    let reg = getReg (getOneOpr ins)
    AST.sideEffect (ClockCounterRead(Some(Register.toRegID reg, false)))
  }

/// The PALcode routine a trap names, of those a program running under Linux
/// reaches. The rest of the space is the operating system's own and is not
/// something a user program is left to call.
module private PalCode =
  /// Stops the machine.
  let [<Literal>] Halt = 0x00UL

  /// Breakpoint.
  let [<Literal>] Bpt = 0x80UL

  /// Reports a failed consistency check.
  let [<Literal>] Bugchk = 0x81UL

  /// Enters the operating system to perform a system call.
  let [<Literal>] Callsys = 0x83UL

  /// Makes what has been written as instructions visible as instructions.
  let [<Literal>] Imb = 0x86UL

  /// Reads the process unique value.
  let [<Literal>] Rduniq = 0x9EUL

  /// Writes the process unique value.
  let [<Literal>] Wruniq = 0x9FUL

  /// Raises the trap whose kind the first argument names.
  let [<Literal>] Gentrap = 0xAAUL

/// <summary>
/// call_pal: a trap to the PALcode routine its function code names.
///
/// Two of them are the whole of what an Alpha program has in place of a
/// thread register, and are the reason this reads as ordinary statements
/// rather than as one side effect: reading and writing the process unique
/// value is a move between registers, and leaving it to the emulator would
/// hide from every analysis what the thread pointer even is.
/// </summary>
let callPal ins bld =
  lift bld ins {
    match getOneOpr ins with
    | OprImm PalCode.Rduniq ->
      regVar bld Register.R0 := regVar bld Register.UNIQ
    | OprImm PalCode.Wruniq ->
      regVar bld Register.UNIQ := regVar bld Register.R16
    | OprImm PalCode.Callsys ->
      AST.sideEffect SysCall
    | OprImm PalCode.Imb ->
      ()
    | OprImm PalCode.Halt ->
      AST.sideEffect Terminate
    | OprImm PalCode.Bpt ->
      AST.sideEffect Breakpoint
    | OprImm PalCode.Bugchk ->
      AST.sideEffect (Interrupt(int PalCode.Bugchk))
    | OprImm PalCode.Gentrap ->
      AST.sideEffect (Interrupt(int PalCode.Gentrap))
    | _ ->
      AST.sideEffect UnsupportedInstruction
  }

// vim: set tw=80 sts=2 sw=2:
