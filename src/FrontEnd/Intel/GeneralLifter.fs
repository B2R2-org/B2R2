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

module internal B2R2.FrontEnd.Intel.GeneralLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.Intel
open B2R2.FrontEnd.Intel.RegGroup
open B2R2.FrontEnd.Intel.LiftingUtils

#if !EMULATION
let private undefCF = AST.undef 1<rt> "CF is undefined."

let private undefOF = AST.undef 1<rt> "OF is undefined."

let private undefAF = AST.undef 1<rt> "AF is undefined."

let private undefSF = AST.undef 1<rt> "SF is undefined."

let private undefZF = AST.undef 1<rt> "ZF is undefined."

let private undefPF = AST.undef 1<rt> "PF is undefined."
#endif

let private getInstrPtr bld = regVar bld (if is64bit bld then R.RIP else R.EIP)

let private getStackPtr bld = regVar bld (if is64bit bld then R.RSP else R.ESP)

let private getBasePtr bld = regVar bld (if is64bit bld then R.RBP else R.EBP)

let private getRegOfSize bld oprSize regGrp = regGrp oprSize |> regVar bld

let inline private getStackWidth wordSize oprSize =
  numI32 (RegType.toByteWidth oprSize) wordSize

/// Push the given expression to the stack, assuming that the expression does
/// not include stack pointer.
let private auxPush oprSize bld expr =
  append bld {
    let sp = getStackPtr bld
    sp := sp .- (getStackWidth bld.RegType oprSize)
    AST.loadLE oprSize sp := expr
  }

let private computePopSize oprSize = function
  | Var(_, id, _, _) when isSegReg (Register.ofRegID id) -> 16<rt>
  | _ -> oprSize

let private auxPop oprSize bld dst =
  append bld {
    let sp = getStackPtr bld
    dst := AST.loadLE (computePopSize oprSize dst) sp
    sp := sp .+ (getStackWidth bld.RegType oprSize)
  }

let private maskOffset offset oprSize =
  let offset = AST.zext oprSize offset
  match oprSize with
  | 16<rt> -> offset .& numU32 0xFu 16<rt>
  | 32<rt> -> offset .& numU32 0x1Fu 32<rt>
  | 64<rt> -> offset .& numU32 0x3Fu 64<rt>
  | _ -> raise InvalidOperandSizeException

let rec private isVar = function
  | Var _ | TempVar _ -> true
  | Extract(e, _, _, _) -> isVar e
  | _ -> false

let private calculateOffset offset oprSize =
  match offset with
  | Num _ ->
    numU32 0u oprSize, maskOffset offset oprSize
  | _ ->
    let offset = AST.zext oprSize offset
    match oprSize with
    | 16<rt> ->
      let scaledBlockOffset = numU32 2u 16<rt> .* (offset ./ numU32 16u 16<rt>)
      scaledBlockOffset, offset .& numU32 15u 16<rt>
    | 32<rt> ->
      let scaledBlockOffset = numU32 4u 32<rt> .* (offset ./ numU32 32u 32<rt>)
      scaledBlockOffset, offset .& numU32 31u 32<rt>
    | 64<rt> ->
      let scaledBlockOffset = numU32 4u 64<rt> .* (offset ./ numU32 32u 64<rt>)
      scaledBlockOffset, offset .& numU32 31u 64<rt>
    | _ ->
      raise InvalidOperandSizeException

let private strRepeat ins insLen bld body cond =
  append bld {
    let lblExit = label bld "Exit"
    let lblCont = label bld "Continue"
    let lblNext = label bld "Next"
    let n0 = AST.num0 bld.RegType
    let cx = regVar bld (if is64bit bld then R.RCX else R.ECX)
    let pc = getInstrPtr bld
    let ninstAddr = pc .+ numInsLen insLen bld
    AST.cjmp (cx == n0) (AST.jmpDest lblExit) (AST.jmpDest lblCont)
    AST.lmark lblCont
    body ins bld
    cx := cx .- AST.num1 bld.RegType
#if EMULATION
    setCCOp bld
    bld.ConditionCodeOp <- ConditionCodeOp.TraceStart
#endif
    match cond with
    | None ->
      AST.interjmp pc InterJmpKind.Base
    | Some cond ->
      AST.cjmp (cx == n0) (AST.jmpDest lblExit) (AST.jmpDest lblNext)
      AST.lmark lblNext
      AST.intercjmp cond ninstAddr pc
    AST.lmark lblExit
    (* We consider each individual loop from a REP-prefixed instruction as an
       independent basic block, because it is more intuitive and matches with
       the definition of basic block from text books. *)
    AST.interjmp ninstAddr InterJmpKind.Base
  }

let aaa (ins: Instruction) insLen bld =
  lift bld ins insLen {
#if DEBUG
    assert32 bld
#endif
    let al = regVar bld R.AL
    let af = regVar bld R.AF
    let ax = regVar bld R.AX
    let cf = regVar bld R.CF
    let alAnd0f = al .& numI32 0x0f 8<rt>
    let cond1 = AST.gt alAnd0f (numI32 9 8<rt>)
    let cond = tmpVar bld 1<rt>
#if EMULATION
    cond := cond1 .| ((getAFLazy bld) == AST.b1)
#else
    cond := cond1 .| (af == AST.b1)
#endif
    ax := AST.ite cond (ax .+ numI32 0x106 16<rt>) ax
    af := AST.ite cond AST.b1 AST.b0
    cf := AST.ite cond AST.b1 AST.b0
    al := alAnd0f
#if !EMULATION
    regVar bld R.OF := undefOF
    regVar bld R.SF := undefSF
    regVar bld R.ZF := undefZF
    regVar bld R.PF := undefPF
#else
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let aad (ins: Instruction) insLen bld =
  lift bld ins insLen {
#if DEBUG
    assert32 bld
#endif
    let imm8 = transOneOpr bld ins insLen |> AST.xtlo 8<rt>
    let al = regVar bld R.AL
    let ah = regVar bld R.AH
    let sf = AST.xthi 1<rt> al
    al := (al .+ (ah .* imm8)) .& (numI32 0xff 8<rt>)
    ah := AST.num0 8<rt>
    enumSZPFlags bld al 8<rt> sf
#if !EMULATION
    regVar bld R.OF := undefOF
    regVar bld R.AF := undefAF
    regVar bld R.CF := undefCF
#else
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let aam (ins: Instruction) insLen bld =
  lift bld ins insLen {
#if DEBUG
    assert32 bld
#endif
    let imm8 = transOneOpr bld ins insLen |> AST.xtlo 8<rt>
    let al = regVar bld R.AL
    let ah = regVar bld R.AH
    let sf = AST.xthi 1<rt> al
    ah := al ./ imm8
    al := al .% imm8
    enumSZPFlags bld al 8<rt> sf
#if !EMULATION
    regVar bld R.OF := undefOF
    regVar bld R.AF := undefAF
    regVar bld R.CF := undefCF
#else
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let aas (ins: Instruction) insLen bld =
  lift bld ins insLen {
#if DEBUG
    assert32 bld
#endif
    let ax = regVar bld R.AX
    let al = regVar bld R.AL
    let af = regVar bld R.AF
    let cf = regVar bld R.CF
    let ah = regVar bld R.AH
    let alAnd0f = al .& numI32 0x0f 8<rt>
    let cond1 = AST.gt alAnd0f (numI32 9 8<rt>)
    let cond = tmpVar bld 1<rt>
#if EMULATION
    cond := cond1 .| ((getAFLazy bld) == AST.b1)
#else
    cond := cond1 .| (af == AST.b1)
#endif
    ax := AST.ite cond (ax .- numI32 6 16<rt>) ax
    ah := AST.ite cond (ah .- AST.num1 8<rt>) ah
    af := AST.ite cond AST.b1 AST.b0
    cf := AST.ite cond AST.b1 AST.b0
    al := alAnd0f
#if EMULATION
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let adc (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs bld true ins insLen
    let oprSize = getOperationSize ins
    let cf = regVar bld R.CF
    let struct (t1, t2, t3, t4) = tmpVars4 bld oprSize
    t1 := dst
    t2 := AST.sext oprSize src
#if EMULATION
    t3 := t2 .+ AST.zext oprSize (getCFLazy bld)
#else
    t3 := t2 .+ AST.zext oprSize cf
#endif
    t4 := t1 .+ t3
    dstAssign oprSize dst t4
    cf := (t3 .< t2) .| (t4 .< t1)
    let struct (ofl, sf) = osfOnAdd t1 t2 t4 bld
    regVar bld R.OF := ofl
    enumASZPFlags bld t1 t2 t4 oprSize sf
#if EMULATION
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let private atomicBeginIfLocked (ins: Instruction) bld =
  append bld {
    if Prefix.hasLock ins.Prefixes then AST.sideEffect AtomicBegin else ()
  }

let private atomicEndIfLocked (ins: Instruction) bld =
  append bld {
    if Prefix.hasLock ins.Prefixes then AST.sideEffect AtomicEnd else ()
  }

/// Adds a value to itself, which is what an ADD whose two operands are the
/// same comes down to.
let private addSameOprs (ins: Instruction) insLen bld oprSize o1 =
  append bld {
    let dst = transOprToExpr bld false ins insLen o1
    atomicBeginIfLocked ins bld
#if !EMULATION
    let struct (t1, t2) = tmpVars2 bld oprSize
    t1 := dst
    t2 := t1 .+ t1
    dstAssign oprSize dst t2
    let struct (ofl, sf) = osfOnAdd t1 t1 t2 bld
    enumEFLAGS bld t1 t1 t2 oprSize (cfOnAdd t1 t2) ofl sf
#else
    let t = tmpVar bld oprSize
    t := dst
    dstAssign oprSize dst (t .+ t)
    setCCOperands2 bld t dst
    match oprSize with
    | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.ADDB
    | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.ADDW
    | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.ADDD
    | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.ADDQ
    | _ -> raise InvalidRegTypeException
#endif
  }

/// Adds the source to the destination, which is what every other ADD comes
/// down to.
let private addTwoOprs (ins: Instruction) insLen bld oprSize o1 o2 =
  append bld {
    let dst = transOprToExpr bld true ins insLen o1
    let src = transOprToExpr bld false ins insLen o2 |> transReg bld true
    atomicBeginIfLocked ins bld
#if !EMULATION
    let isSrcConst = isConst src
    let t1 = tmpVar bld oprSize
    let t2 = if isSrcConst then src else tmpVar bld oprSize
    let t3 = tmpVar bld oprSize
    t1 := dst
    if isSrcConst then () else t2 := src
    t3 := t1 .+ t2
    dstAssign oprSize dst t3
    let struct (ofl, sf) = osfOnAdd t1 t2 t3 bld
    enumEFLAGS bld t1 t2 t3 oprSize (cfOnAdd t1 t3) ofl sf
#else
    let src =
      if isConst src then
        src
      else
        let t = tmpVar bld oprSize
        append bld { t := src }
        t
    dstAssign oprSize dst (dst .+ src)
    setCCOperands2 bld src dst
    match oprSize with
    | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.ADDB
    | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.ADDW
    | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.ADDD
    | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.ADDQ
    | _ -> raise InvalidRegTypeException
#endif
  }

let add (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let oprSize = getOperationSize ins
    match ins.Operands with
    | TwoOperands(o1, o2) when o1 = o2 ->
      addSameOprs ins insLen bld oprSize o1
    | TwoOperands(o1, o2) ->
      addTwoOprs ins insLen bld oprSize o1 o2
    | _ ->
      raise InvalidOperandException
    atomicEndIfLocked ins bld
  }

let adox (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs bld true ins insLen
    let oprSize = getOperationSize ins
#if EMULATION
    let oF = getOFLazy bld
#else
    let oF = regVar bld R.OF
#endif
    match oprSize with
    | 32<rt> ->
      let struct (t1, t2, t3) = tmpVars3 bld 64<rt>
      t1 := AST.zext 64<rt> dst
      t2 := AST.zext 64<rt> src
      t3 := t1 .+ t2 .+ AST.zext 64<rt> oF
      dstAssign oprSize dst (AST.xtlo oprSize t3)
      oF := AST.extract t3 1<rt> 32
    | 64<rt> ->
      let struct (t1a, t2a, t3a) = tmpVars3 bld 64<rt>
      let struct (t1b, t2b, t3b) = tmpVars3 bld 64<rt>
      let mask = tmpVar bld 64<rt>
      mask := numU64 0xFFFFFFFFUL 64<rt>
      t1a := dst .& mask
      t1b := (dst >> (numI32 32 64<rt>)) .& mask
      t2a := src .& mask
      t2b := (src >> (numI32 32 64<rt>)) .& mask
      t3a := t1a .+ t2a .+ AST.zext 64<rt> oF
      t3b := t1b .+ t2b .+ (t3a >> (numI32 32 64<rt>))
      dstAssign oprSize dst (dst .+ src .+ (AST.zext 64<rt> oF))
      oF := AST.extract t3b 1<rt> 32
    | _ ->
      raise InvalidOperandSizeException
  }

let ``and`` (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs bld true ins insLen
    let oprSize = getOperationSize ins
    let t = tmpVar bld oprSize
    atomicBeginIfLocked ins bld
    dstAssign oprSize dst (dst .& AST.sext oprSize src)
#if EMULATION
    setCCDst bld dst
    match oprSize with
    | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICB
    | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICW
    | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICD
    | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICQ
    | _ -> raise InvalidRegTypeException
#else
    let sf = AST.xthi 1<rt> dst
    regVar bld R.OF := AST.b0
    regVar bld R.CF := AST.b0
    enumSZPFlags bld dst oprSize sf
    regVar bld R.AF := undefAF
#endif
    atomicEndIfLocked ins bld
  }

let andn (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs bld false ins insLen
    let oprSize = getOperationSize ins
    let t = tmpVar bld oprSize
    t := (AST.not src1) .& src2
    dstAssign oprSize dst t
    regVar bld R.SF := AST.extract dst 1<rt> (int oprSize - 1)
    regVar bld R.ZF := AST.eq dst (AST.num0 oprSize)
    regVar bld R.OF := AST.b0
    regVar bld R.CF := AST.b0
#if !EMULATION
    regVar bld R.AF := undefAF
    regVar bld R.PF := undefPF
#else
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let arpl (ins: Instruction) insLen bld =
  lift bld ins insLen {
#if DEBUG
    assert32 bld
#endif
    let struct (dst, src) = transTwoOprs bld false ins insLen
    let struct (t1, t2) = tmpVars2 bld 16<rt>
    let mask = numI32 0xfffc 16<rt>
    let zF = regVar bld R.ZF
    t1 := dst .& numI32 0x3 16<rt>
    t2 := src .& numI32 0x3 16<rt>
    dst := AST.ite (t1 .< t2) ((dst .& mask) .| t2) dst
    zF := t1 .< t2
#if EMULATION
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let bextr (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let oprSize = getOperationSize ins
    let struct (dst, src1, src2) = transThreeOprs bld false ins insLen
    let zF = regVar bld R.ZF
    let struct (tmp, mask, start, len) = tmpVars4 bld oprSize
    start := AST.zext oprSize (AST.extract src2 8<rt> 0)
    len := AST.zext oprSize (AST.extract src2 8<rt> 8)
    mask := AST.not (numI32 0 oprSize) << len
    tmp := AST.zext oprSize src1
    tmp := (tmp >> start) .& AST.not (mask)
    dstAssign oprSize dst tmp
    zF := (dst == AST.num0 oprSize)
    regVar bld R.CF := AST.b0
    regVar bld R.OF := AST.b0
#if !EMULATION
    regVar bld R.AF := undefAF
    regVar bld R.SF := undefSF
    regVar bld R.PF := undefPF
#else
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let blsi (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let oprSize = getOperationSize ins
    let struct (dst, src) = transTwoOprs bld false ins insLen
    let tmp = tmpVar bld oprSize
    tmp := AST.neg src .& src
    regVar bld R.SF := AST.xthi 1<rt> tmp
    regVar bld R.ZF := tmp == AST.num0 oprSize
    regVar bld R.CF := src != AST.num0 oprSize
    dstAssign oprSize dst tmp
    regVar bld R.OF := AST.b0
#if !EMULATION
    regVar bld R.AF := undefAF
    regVar bld R.PF := undefPF
#else
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let private bndmov64 (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = getTwoOprs ins
    let struct (dst1, dst2) = transOprToExpr128 bld false ins insLen dst
    let struct (src1, src2) = transOprToExpr128 bld false ins insLen src
    dst1 := src1
    dst2 := src2
  }

let private bndmov32Aux (ins: Instruction) insLen bld =
  let struct (dst, src) = getTwoOprs ins
  match dst, src with
  | OprReg _, OprMem _ ->
    let struct (dst1, dst2) = transOprToExpr128 bld false ins insLen dst
    let src = transOprToExpr bld false ins insLen src
    append bld {
      dst1 := AST.xthi 32<rt> src |> AST.zext 64<rt>
      dst2 := AST.xtlo 32<rt> src |> AST.zext 64<rt>
    }
  | OprMem _, OprReg _ ->
    let struct (src1, src2) = transOprToExpr128 bld false ins insLen src
    let dst = transOprToExpr bld false ins insLen dst
    append bld {
      dst := AST.concat (AST.xtlo 32<rt> src1) (AST.xtlo 32<rt> src2)
    }
  | _ ->
    raise InvalidOperandException

let bndmov32 (ins: Instruction) insLen bld =
  lift bld ins insLen {
    bndmov32Aux ins insLen bld
  }

let bndmov ins insLen bld =
  if is64bit bld then bndmov64 ins insLen bld else bndmov32 ins insLen bld

/// The flags a bit scan leaves undefined. Under EMULATION they are worked out
/// lazily instead, from the operation the condition codes last came from --
/// which is the only thing the builder is asked for there, so its type is
/// named rather than left to be read off a use that compilation removed.
let private setBitScanUndefFlags (bld: ILowUIRBuilder) =
#if !EMULATION
  append bld {
    regVar bld R.CF := undefCF
    regVar bld R.OF := undefOF
    regVar bld R.AF := undefAF
    regVar bld R.SF := undefSF
    regVar bld R.PF := undefPF
  }
#else
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif

/// Walks the source a bit at a time until a set bit turns up, and hands back
/// where it was. `isForward` says which end to start from and which way to
/// step; that, and nothing else, is what separates `bsf` from `bsr`.
let private liftBitScan (ins: Instruction) insLen bld isForward =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs bld true ins insLen
    let oprSize = getOperationSize ins
    let zf = regVar bld R.ZF
    let t = tmpVar bld oprSize
    let start =
      if isForward then AST.num0 oprSize
      else numOprSize oprSize .- AST.num1 oprSize
    let step =
      if isForward then t .+ AST.num1 oprSize else t .- AST.num1 oprSize
#if EMULATION
    genDynamicFlagsUpdate bld
#endif
    _if bld "Zero" (src == AST.num0 oprSize)
      (block {
        zf := AST.b1
#if !EMULATION
        dst := AST.undef oprSize "DEST is undefined."
#endif
      })
      (block {
        zf := AST.b0
        t := start
        _while bld "Loop" ((AST.xtlo 1<rt> (src >> t)) == AST.b0)
          (block {
            t := step })
        dstAssign oprSize dst t })
    setBitScanUndefFlags bld
  }

/// Scans for the least significant set bit.
let bsf (ins: Instruction) insLen bld = liftBitScan ins insLen bld true

/// Scans for the most significant set bit.
let bsr (ins: Instruction) insLen bld = liftBitScan ins insLen bld false

let bswap (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let dst = transOneOpr bld ins insLen
    let oprSize = getOperationSize ins
#if EMULATION
    (* Byte-reverse as one APP intrinsic (a host bswap) instead of decomposing
       into per-byte extracts + revConcat. bswap ignores the operand-size
       prefix, so oprSize is only ever 32 or 64; the name carries the width. *)
    let name = if oprSize = 64<rt> then "BSWAP64" else "BSWAP32"
    dstAssign oprSize dst (AST.app name [ dst ] oprSize)
#else
    let cnt = RegType.toByteWidth oprSize |> int
    let t = tmpVar bld oprSize
    let tmps = Array.init cnt (fun _ -> tmpVar bld 8<rt>)
    t := dst
    for i in 0 .. cnt - 1 do
      tmps[i] := AST.extract t 8<rt> (i * 8)
    done
    dstAssign oprSize dst (AST.revConcat (Array.rev tmps))
#endif
  }

let private bit ins bitBase bitOffset oprSize =
  match bitBase with
  | Load(e, t, expr, _) ->
    let effAddrSz = getEffAddrSz ins
    let addrOffset, bitOffset = calculateOffset bitOffset oprSize
    let addrOffset = AST.zext effAddrSz addrOffset
    AST.xtlo 1<rt> ((AST.load e t (expr .+ addrOffset)) >> bitOffset)
  | _ ->
    if isVar bitBase then
      AST.xtlo 1<rt> (bitBase >> maskOffset bitOffset oprSize)
    else
      raise InvalidExprException

let bt (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (bitBase, bitOffset) = transTwoOprs bld true ins insLen
    let oprSize = getOperationSize ins
#if EMULATION
    regVar bld R.ZF := getZFLazy bld
#endif
    regVar bld R.CF := bit ins bitBase bitOffset oprSize
#if !EMULATION
    regVar bld R.OF := undefOF
    regVar bld R.SF := undefSF
    regVar bld R.AF := undefAF
    regVar bld R.PF := undefPF
#else
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let private setBit ins bitBase bitOffset oprSize setValue =
  match bitBase with
  | Load(e, t, expr, _) ->
    let effAddrSz = getEffAddrSz ins
    let addrOffset, bitOffset = calculateOffset bitOffset oprSize
    let addrOffset = AST.zext effAddrSz addrOffset
    let mask = setValue << bitOffset
    let bit = (AST.zext oprSize AST.b1) << bitOffset
    let loadMem = AST.load e t (expr .+ addrOffset)
    loadMem := (loadMem .& (getMask oprSize .- bit)) .| mask
  | _ ->
    if isVar bitBase then
      let mask = setValue << maskOffset bitOffset oprSize
      let bit = (AST.zext oprSize AST.b1) << maskOffset bitOffset oprSize
      dstAssign oprSize bitBase ((bitBase .& (getMask oprSize .- bit)) .| mask)
    else
      raise InvalidExprException

let bitTest (ins: Instruction) insLen bld setValue =
  lift bld ins insLen {
    let struct (bitBase, bitOffset) = transTwoOprs bld true ins insLen
    let oprSize = getOperationSize ins
    let setValue = AST.zext oprSize setValue
    atomicBeginIfLocked ins bld
#if EMULATION
    regVar bld R.ZF := getZFLazy bld
#endif
    regVar bld R.CF := bit ins bitBase bitOffset oprSize
    setBit ins bitBase bitOffset oprSize setValue
#if !EMULATION
    regVar bld R.OF := undefOF
    regVar bld R.SF := undefSF
    regVar bld R.AF := undefAF
    regVar bld R.PF := undefPF
#else
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
    atomicEndIfLocked ins bld
  }

let btc (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (bitBase, bitOffset) = transTwoOprs bld true ins insLen
    let oprSize = getOperationSize ins
    atomicBeginIfLocked ins bld
#if !EMULATION
    let setValue = AST.zext oprSize (regVar bld R.CF |> AST.not)
#else
    let setValue = AST.zext oprSize (getCFLazy bld |> AST.not)
    regVar bld R.ZF := getZFLazy bld
#endif
    regVar bld R.CF := bit ins bitBase bitOffset oprSize
    setBit ins bitBase bitOffset oprSize setValue
#if !EMULATION
    regVar bld R.OF := undefOF
    regVar bld R.SF := undefSF
    regVar bld R.AF := undefAF
    regVar bld R.PF := undefPF
#else
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
    atomicEndIfLocked ins bld
  }

let btr ins insLen bld = bitTest ins insLen bld AST.b0

let bts ins insLen bld = bitTest ins insLen bld AST.b1

let bzhi (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs bld false ins insLen
    let oprSize = getOperationSize ins
    let n = tmpVar bld 8<rt>
    n := AST.xtlo 8<rt> src2
    let cond1 = n .< numI32 (RegType.toBitWidth oprSize) 8<rt>
    let cond2 = n .> numI32 ((RegType.toBitWidth oprSize) - 1) 8<rt>
    let tmp = AST.zext oprSize (numI32 (RegType.toBitWidth oprSize) 8<rt> .- n)
    let cf = regVar bld R.CF
    dstAssign oprSize dst (AST.ite cond1 ((src1 << tmp) >> tmp) src1)
    cf := AST.ite cond2 AST.b1 AST.b0
    regVar bld R.SF := AST.xthi 1<rt> dst
    regVar bld R.ZF := dst == (AST.num0 oprSize)
    regVar bld R.OF := AST.b0
#if !EMULATION
    regVar bld R.AF := undefAF
    regVar bld R.PF := undefPF
#else
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let call (ins: Instruction) insLen bld =
  liftOpen bld ins insLen {
    let pc = numU64 (ins: Instruction).Address bld.RegType
    let oprSize = getOperationSize ins
#if EMULATION
    setCCOp bld
    bld.ConditionCodeOp <- ConditionCodeOp.TraceStart
#endif
    let struct (target, ispcrel) = transJumpTargetOpr bld false ins pc insLen
    if ispcrel || not (hasStackPtr ins) then
      auxPush oprSize bld (pc .+ numInsLen insLen bld)
      AST.interjmp target InterJmpKind.IsCall
    else
      let t = tmpVar bld oprSize (* Use tmpvar because the target can use RSP *)
      t := target
      auxPush oprSize bld (pc .+ numInsLen insLen bld)
      AST.interjmp t InterJmpKind.IsCall
  }

let convBWQ (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let opr = regVar bld (if is64bit bld then R.RAX else R.EAX)
    let oprSize = getOperationSize ins
    let src = AST.sext oprSize (AST.xtlo (oprSize / 2) opr)
    dstAssign oprSize (AST.xtlo oprSize opr) src
  }

let clearFlag (ins: Instruction) insLen bld flagReg =
  lift bld ins insLen {
    regVar bld flagReg := AST.b0
#if EMULATION
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let cmc (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let cf = regVar bld R.CF
#if EMULATION
    cf := AST.not (getCFLazy bld)
#else
    cf := AST.not cf
#endif
#if !EMULATION
    regVar bld R.OF := undefOF
    regVar bld R.AF := undefAF
    regVar bld R.SF := undefSF
    regVar bld R.ZF := undefZF
    regVar bld R.PF := undefPF
#else
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let private getCondOfCMov (ins: Instruction) bld =
  match ins.Opcode with
  | Opcode.CMOVO -> regVar bld R.OF
  | Opcode.CMOVNO -> regVar bld R.OF == AST.b0
  | Opcode.CMOVB -> regVar bld R.CF
  | Opcode.CMOVAE -> regVar bld R.CF == AST.b0
  | Opcode.CMOVZ -> regVar bld R.ZF
  | Opcode.CMOVNZ -> regVar bld R.ZF == AST.b0
  | Opcode.CMOVBE -> (regVar bld R.CF) .| (regVar bld R.ZF)
  | Opcode.CMOVA -> ((regVar bld R.CF) .| (regVar bld R.ZF)) == AST.b0
  | Opcode.CMOVS -> regVar bld R.SF
  | Opcode.CMOVNS -> regVar bld R.SF == AST.b0
  | Opcode.CMOVP -> regVar bld R.PF
  | Opcode.CMOVNP -> regVar bld R.PF == AST.b0
  | Opcode.CMOVL -> regVar bld R.SF != regVar bld R.OF
  | Opcode.CMOVGE -> regVar bld R.SF == regVar bld R.OF
  | Opcode.CMOVLE -> regVar bld R.ZF .|
                     (regVar bld R.SF != regVar bld R.OF)
  | Opcode.CMOVG -> regVar bld R.ZF == AST.b0 .&
                    (regVar bld R.SF == regVar bld R.OF)
  | _ -> raise InvalidOpcodeException

#if EMULATION
let private getCondOfCMovLazy (ins: Instruction) bld =
  match ins.Opcode with
  | Opcode.CMOVO ->
    getOFLazy bld
  | Opcode.CMOVNO ->
    getOFLazy bld |> AST.not
  | Opcode.CMOVB ->
    getCFLazy bld
  | Opcode.CMOVAE ->
    getCFLazy bld |> AST.not
  | Opcode.CMOVZ ->
    getZFLazy bld
  | Opcode.CMOVNZ ->
    getZFLazy bld |> AST.not
  | Opcode.CMOVBE ->
    let ccOp = bld.ConditionCodeOp
    match ccOp with
    | ConditionCodeOp.SUBB
    | ConditionCodeOp.SUBW
    | ConditionCodeOp.SUBD
    | ConditionCodeOp.SUBQ ->
      let size = 1 <<< ((int ccOp - int ConditionCodeOp.SUBB) &&& 0b11)
      let regType = RegType.fromByteWidth size
      let src2 = getCCSrc1 bld regType
      let src1 = getCCDst bld regType .+ src2
      src1 .<= src2
    | _ ->
      (getCFLazy bld) .| (getZFLazy bld)
  | Opcode.CMOVA ->
    (getCFLazy bld .| getZFLazy bld) |> AST.not
  | Opcode.CMOVS ->
    getSFLazy bld
  | Opcode.CMOVNS ->
    getSFLazy bld |> AST.not
  | Opcode.CMOVP ->
    getPFLazy bld
  | Opcode.CMOVNP ->
    getPFLazy bld |> AST.not
  | Opcode.CMOVL ->
    let ccOp = bld.ConditionCodeOp
    match ccOp with
    | ConditionCodeOp.SUBB
    | ConditionCodeOp.SUBW
    | ConditionCodeOp.SUBD
    | ConditionCodeOp.SUBQ ->
      let size = 1 <<< ((int ccOp - int ConditionCodeOp.SUBB) &&& 0b11)
      let regType = RegType.fromByteWidth size
      let src2 = getCCSrc1 bld regType
      let src1 = getCCDst bld regType .+ src2
      src1 ?< src2
    | _ ->
      getOFLazy bld != getSFLazy bld
  | Opcode.CMOVGE ->
    getOFLazy bld == getSFLazy bld
  | Opcode.CMOVLE ->
    let ccOp = bld.ConditionCodeOp
    match ccOp with
    | ConditionCodeOp.SUBB
    | ConditionCodeOp.SUBW
    | ConditionCodeOp.SUBD
    | ConditionCodeOp.SUBQ ->
      let size = 1 <<< ((int ccOp - int ConditionCodeOp.SUBB) &&& 0b11)
      let regType = RegType.fromByteWidth size
      let src2 = getCCSrc1 bld regType
      let src1 = getCCDst bld regType .+ src2
      src1 ?<= src2
    | _ ->
      (getOFLazy bld != getSFLazy bld) .| (getZFLazy bld)
  | Opcode.CMOVG ->
    (getOFLazy bld == getSFLazy bld) .& (getZFLazy bld |> AST.not)
  | _ ->
    raise InvalidOpcodeException
#endif

let cmovcc (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs bld false ins insLen
    let oprSize = getOperationSize ins
#if EMULATION
    dstAssign oprSize dst (AST.ite (getCondOfCMovLazy ins bld) src dst)
#else
    dstAssign oprSize dst (AST.ite (getCondOfCMov ins bld) src dst)
#endif
  }

let cmp (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (src1, src2) = transTwoOprs bld false ins insLen
    let oprSize = getOperationSize ins
#if EMULATION
    setCCOperands2 bld src2 (src1 .- src2)
    match oprSize with
    | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SUBB
    | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SUBW
    | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SUBD
    | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SUBQ
    | _ -> raise InvalidRegTypeException
#else
    let isRhsConst = isConst src2
    let t1 = tmpVar bld oprSize
    let t2 = if isRhsConst then AST.sext oprSize src2 else tmpVar bld oprSize
    let t3 = tmpVar bld oprSize
    t1 := src1
    if isRhsConst then () else t2 := AST.sext oprSize src2
    t3 := t1 .- t2
    let sf = AST.xthi 1<rt> t3
    enumEFLAGS bld t1 t2 t3 oprSize (cfOnSub t1 t2) (ofOnSub t1 t2 t3) sf
#endif
  }

let private cmpsBody ins bld =
  let oprSize = getOperationSize ins
  let df = regVar bld R.DF
  let si = regVar bld (if is64bit bld then R.RSI else R.ESI)
  let di = regVar bld (if is64bit bld then R.RDI else R.EDI)
  let src1 = AST.loadLE oprSize si
  let src2 = AST.loadLE oprSize di
  let struct (t1, t2, t3) = tmpVars3 bld oprSize
  let amount = numI32 (RegType.toByteWidth oprSize) bld.RegType
  let sf = AST.xthi 1<rt> t3
  append bld {
    t1 := src1
    t2 := src2
    t3 := t1 .- t2
    si := AST.ite df (si .- amount) (si .+ amount)
    di := AST.ite df (di .- amount) (di .+ amount)
  }
  enumEFLAGS bld t1 t2 t3 oprSize (cfOnSub t1 t2) (ofOnSub t1 t2 t3) sf
#if EMULATION
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif

let cmps (ins: Instruction) insLen bld =
  let pref = ins.Prefixes
  let zf = regVar bld R.ZF
  liftOpen bld ins insLen {
    if Prefix.hasREPZ pref then
      strRepeat ins insLen bld cmpsBody (Some(zf == AST.b0))
    elif Prefix.hasREPNZ pref then
      strRepeat ins insLen bld cmpsBody (Some zf)
    else
      cmpsBody ins bld
      markEnd bld insLen
  }

let cmpxchg (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs bld true ins insLen
    let oprSize = getOperationSize ins
    atomicBeginIfLocked ins bld
    let t = tmpVar bld oprSize
    let r = tmpVar bld oprSize
    let acc = getRegOfSize bld oprSize grpEAX
    let tAcc = tmpVar bld oprSize
    let cond = tmpVar bld 1<rt>
    let lblEq = label bld "Equal"
    let lblNeq = label bld "NotEqual"
    let lblEnd = label bld "End"
    t := dst
    tAcc := acc
    r := tAcc .- t
    cond := tAcc == t
    AST.cjmp cond (AST.jmpDest lblEq) (AST.jmpDest lblNeq)
    AST.lmark lblEq
    regVar bld R.ZF := AST.b1
    dstAssign oprSize dst src
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblNeq
    regVar bld R.ZF := AST.b0
    dstAssign oprSize acc t
    AST.lmark lblEnd
    regVar bld R.OF := ofOnSub tAcc t r
    regVar bld R.SF := AST.xthi 1<rt> r
    buildAF bld tAcc t r oprSize
    buildPF bld r oprSize None
    regVar bld R.CF := cfOnSub tAcc t
    atomicEndIfLocked ins bld
#if EMULATION
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let private saveOprMem (bld: ILowUIRBuilder) expr =
  let sz = bld.RegType
  let t = tmpVar bld sz
  match expr with
  | Load(e, rt, expr, _) ->
    append bld {
      t := AST.zext sz expr
    }
    AST.load e rt t
  | _ ->
    expr

/// Compares EDX:EAX against a 64-bit memory operand and swaps in ECX:EBX
/// when they match, which is what CMPXCHG8B comes down to.
let private cmpXchg8b ins insLen bld oprSize zf cond =
  append bld {
    let lblEq = label bld "Equal"
    let lblNeq = label bld "NotEqual"
    let lblEnd = label bld "End"
    let dst = transOneOpr bld ins insLen
    let orgDstMem = saveOprMem bld dst
    let eax = regVar bld R.EAX
    let ecx = regVar bld R.ECX
    let edx = regVar bld R.EDX
    let ebx = regVar bld R.EBX
    let t = tmpVar bld oprSize
    t := dst
    cond := AST.concat edx eax == t
    AST.cjmp cond (AST.jmpDest lblEq) (AST.jmpDest lblNeq)
    AST.lmark lblEq
    zf := AST.b1
    orgDstMem := AST.concat ecx ebx
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblNeq
    zf := AST.b0
    dstAssign 32<rt> eax (AST.xtlo 32<rt> t)
    dstAssign 32<rt> edx (AST.xthi 32<rt> t)
    orgDstMem := t
    AST.lmark lblEnd
  }

/// Compares RDX:RAX against a 128-bit memory operand and swaps in RCX:RBX
/// when they match, which is what CMPXCHG16B comes down to.
let private cmpXchg16b (ins: Instruction) insLen bld zf cond =
  append bld {
    let struct (dstB, dstA) =
      match ins.Operands with
      | OneOperand opr -> transOprToExpr128 bld false ins insLen opr
      | _ -> raise InvalidOperandException
    let orgDstAMem = saveOprMem bld dstA
    let orgDstBMem = saveOprMem bld dstB
    let rax = regVar bld R.RAX
    let rcx = regVar bld R.RCX
    let rdx = regVar bld R.RDX
    let rbx = regVar bld R.RBX
    let struct (t1, t2) = tmpVars2 bld 64<rt>
    t1 := dstA
    t2 := dstB
    cond := (t2 == rdx) .& (t1 == rax)
    zf := cond
    rax := AST.ite cond rax t1
    rdx := AST.ite cond rdx t2
    orgDstAMem := AST.ite cond rbx t1
    orgDstBMem := AST.ite cond rcx t2
  }

let compareExchangeBytes ins insLen bld =
  lift bld ins insLen {
    let oprSize = getOperationSize ins
    let zf = regVar bld R.ZF
    let cond = tmpVar bld 1<rt>
    match oprSize with
    | 64<rt> -> cmpXchg8b ins insLen bld oprSize zf cond
    | 128<rt> -> cmpXchg16b ins insLen bld zf cond
    | _ -> raise InvalidOperandSizeException
  }

let convWDQ ins insLen bld =
  lift bld ins insLen {
    let oprSize = getOperationSize ins
    match oprSize, bld.RegType with
    | 16<rt>, _ ->
      let t = tmpVar bld 32<rt>
      let ax = regVar bld R.AX
      let dx = regVar bld R.DX
      t := AST.sext 32<rt> ax
      dx := AST.xthi 16<rt> t
      ax := AST.xtlo 16<rt> t
    | 32<rt>, _ ->
      let t = tmpVar bld 64<rt>
      let eax = regVar bld R.EAX
      let edx = regVar bld R.EDX
      t := AST.sext 64<rt> eax
      dstAssign oprSize edx (AST.xthi 32<rt> t)
      eax := AST.xtlo 32<rt> t
    | 64<rt>, 64<rt> ->
      let rdx = regVar bld R.RDX
      let rax = regVar bld R.RAX
      let cond = AST.extract rax 1<rt> 63
      rdx := AST.ite cond (numI32 -1 64<rt>) (AST.num0 64<rt>)
    | _, _ ->
      raise InvalidOperandSizeException
  }

let private bitReflect bld src =
  let oprSize = Expr.typeOf src
  let struct (res, tmp) = tmpVars2 bld oprSize
  append bld {
    res := AST.num0 oprSize
    tmp := src
  }
  let oSz = int oprSize
  for i in 0 .. oSz - 1 do
    append bld {
      AST.extract res 1<rt> (oSz - 1 - i) := AST.extract tmp 1<rt> i
    }
  done
  res |> AST.zext 64<rt>

let private mod2 bld dividend divisor divdnSz =
  let divsSz = 33
  let struct (remainder, mask) = tmpVars2 bld 64<rt>
  let divdnSzMask = numI64 ((1L <<< (int divdnSz)) - 1L) 64<rt>
  append bld {
    mask := if divdnSz = 64 then getMask 64<rt> else divdnSzMask
  }
  for i in (divdnSz - 1) .. -1 .. divsSz - 1 do
    let shfAmt = numI32 (i + 1 - divsSz) 64<rt>
    let pDivdn = dividend >> shfAmt
    let cond = AST.extract dividend 1<rt> i
    append bld {
      remainder := AST.ite cond (pDivdn <+> divisor) pDivdn
    }
    let m = mask >> (numI32 divdnSz 64<rt> .- shfAmt)
    append bld {
      dividend := (dividend .& m) .| (remainder << shfAmt)
    }
  done
  dividend |> AST.xtlo 32<rt>

let crc32 (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs bld true ins insLen
    let divisor = tmpVar bld 64<rt>
    divisor := numI64 0x11EDC6F41L 64<rt>
    let srcSz = Expr.typeOf src
    match srcSz with
    | 32<rt> | 16<rt> | 8<rt> ->
      let struct (t1, t2, t3) = tmpVars3 bld 64<rt>
      let struct (t4, t5) = tmpVars2 bld 64<rt>
      let t6 = tmpVar bld 32<rt>
      t1 := bitReflect bld src
      t2 := bitReflect bld (AST.xtlo 32<rt> dst)
      t3 := t1 << numI32 32 64<rt>
      t4 := t2 << numI32 (int srcSz) 64<rt>
      t5 := t3 <+> t4
      t6 := mod2 bld t5 divisor (int srcSz + 32)
      dstAssign 32<rt> dst (bitReflect bld t6)
    | 64<rt> ->
      let struct (t1, t2) = tmpVars2 bld 64<rt>
      let struct (t3a, t3b) = tmpVars2 bld 64<rt>
      let struct (t4a, t4b) = tmpVars2 bld 64<rt>
      let struct (t5a, t5b) = tmpVars2 bld 64<rt>
      let t6 = tmpVar bld 32<rt>
      t1 := bitReflect bld src
      t2 := bitReflect bld (AST.xtlo 32<rt> dst)
      t3a := (AST.xtlo 32<rt> t1 |> AST.zext 64<rt>) << numI32 32 64<rt>
      t3b := AST.xthi 32<rt> t1 |> AST.zext 64<rt>
      t4a := AST.num0 64<rt>
      t4b := AST.xtlo 32<rt> t2 |> AST.zext 64<rt>
      t5a := t3a <+> t4a
      t5b := t3b <+> t4b
      t5b := AST.concat (AST.xtlo 32<rt> t5b) (AST.xthi 32<rt> t5a)
      t6 := mod2 bld t5b divisor 64
      t5a := AST.concat (AST.xtlo 32<rt> t6) (AST.xtlo 32<rt> t5a)
      t6 := mod2 bld t5a divisor 64
      dstAssign 32<rt> dst (bitReflect bld t6)
    | _ ->
      raise InvalidOperandSizeException
  }

let daa (ins: Instruction) insLen bld =
  lift bld ins insLen {
#if DEBUG
    assert32 bld
#endif
    let al = regVar bld R.AL
    let cf = regVar bld R.CF
    let af = regVar bld R.AF
    let oldAl = tmpVar bld 8<rt>
    let oldCf = tmpVar bld 1<rt>
    let alAnd0f = al .& numI32 0x0f 8<rt>
    let subCond1 = AST.gt alAnd0f (numI32 9 8<rt>)
    let cond1 = tmpVar bld 1<rt>
    let subCond3 = AST.gt oldAl (numI32 0x99 8<rt>)
    let subCond4 = oldCf == AST.b1
    let cond2 = tmpVar bld 1<rt>
    let sf = AST.xthi 1<rt> al
    oldAl := al
#if EMULATION
    oldCf := getCFLazy bld
#else
    oldCf := cf
#endif
    cf := AST.b0
#if EMULATION
    cond1 := subCond1 .| ((getAFLazy bld) == AST.b1)
#else
    cond1 := subCond1 .| (af == AST.b1)
#endif
    al := AST.ite cond1 (al .+ numI32 6 8<rt>) al
    cf := AST.ite cond1 oldCf cf
    af := cond1
    cond2 := subCond3 .| subCond4
    al := AST.ite cond2 (al .+ numI32 0x60 8<rt>) al
    cf := cond2
    enumSZPFlags bld al 8<rt> sf
#if !EMULATION
    regVar bld R.OF := undefOF
#else
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let das (ins: Instruction) insLen bld =
  lift bld ins insLen {
#if DEBUG
    assert32 bld
#endif
    let al = regVar bld R.AL
    let cf = regVar bld R.CF
    let af = regVar bld R.AF
    let oldAl = tmpVar bld 8<rt>
    let oldCf = tmpVar bld 1<rt>
    let alAnd0f = al .& numI32 0x0f 8<rt>
    let subCond1 = AST.gt alAnd0f (numI32 9 8<rt>)
    let subCond2 = af == AST.b1
    let cond1 = tmpVar bld 1<rt>
    let subCond3 = AST.gt oldAl (numI32 0x99 8<rt>)
    let subCond4 = oldCf == AST.b1
    let cond2 = tmpVar bld 1<rt>
    let sf = AST.xthi 1<rt> al
    oldAl := al
#if EMULATION
    oldCf := getCFLazy bld
#else
    oldCf := cf
#endif
    cf := AST.b0
#if EMULATION
    cond1 := subCond1 .| ((getAFLazy bld) == AST.b1)
#else
    cond1 := subCond1 .| (af == AST.b1)
#endif
    al := AST.ite cond1 (al .- numI32 6 8<rt>) al
    cf := AST.ite cond1 oldCf cf
    af := cond1
    cond2 := subCond3 .| subCond4
    al := AST.ite cond2 (al .- numI32 0x60 8<rt>) al
    cf := cond2
    enumSZPFlags bld al 8<rt> sf
#if !EMULATION
    regVar bld R.OF := undefOF
#else
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let dec (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let dst = transOneOpr bld ins insLen
    let oprSize = getOperationSize ins
    let struct (t1, t2) = tmpVars2 bld oprSize
    let sf = AST.xthi 1<rt> t2
    atomicBeginIfLocked ins bld
    t1 := dst
    t2 := (t1 .- AST.num1 oprSize)
    dstAssign oprSize dst t2
    regVar bld R.OF := ofOnSub t1 (AST.num1 oprSize) t2
    enumASZPFlags bld t1 (AST.num1 oprSize) t2 oprSize sf
    atomicEndIfLocked ins bld
#if EMULATION
    regVar bld R.CF := getCFLazy bld
    setCCOperands2 bld (AST.num1 oprSize) t2
    match oprSize with
    | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.DECB
    | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.DECW
    | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.DECD
    | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.DECQ
    | _ -> raise InvalidRegTypeException
#endif
  }

let private getDividend bld = function
  | 8<rt> -> regVar bld R.AX
  | 16<rt> -> AST.concat (regVar bld R.DX) (regVar bld R.AX)
  | 32<rt> -> AST.concat (regVar bld R.EDX) (regVar bld R.EAX)
  | 64<rt> -> AST.concat (regVar bld R.RDX) (regVar bld R.RAX)
  | _ -> raise InvalidOperandSizeException

let private checkQuotientDIV oprSize lblAssign lblErr q =
  AST.cjmp (AST.xthi oprSize q == AST.num0 oprSize)
           (AST.jmpDest lblAssign)
           (AST.jmpDest lblErr)

let private checkQuotientIDIV oprSize sz lblAssign lblErr q =
  let amount = numI32 (RegType.toBitWidth oprSize - 1) oprSize
  let mask = AST.num1 oprSize << amount
  let msb = AST.xthi 1<rt> q
  let negRes = q .< (AST.zext sz mask)
  let posRes = q .> (AST.zext sz (mask .- (AST.num1 oprSize)))
  let cond = AST.ite (msb == AST.b1) negRes posRes
  AST.cjmp cond (AST.jmpDest lblErr) (AST.jmpDest lblAssign)

let divideWithConcat opcode oprSize divisor lblAssign lblErr bld =
  let dividend = getDividend bld oprSize
  let sz = Expr.typeOf dividend
  let quotient = tmpVar bld sz
  let remainder = tmpVar bld sz
  match opcode with
  | Opcode.DIV ->
    let divisor = AST.zext sz divisor
    append bld {
      quotient := dividend ./ divisor
      remainder := dividend .% divisor
      checkQuotientDIV oprSize lblAssign lblErr quotient
    }
  | Opcode.IDIV ->
    let divisor = AST.sext sz divisor
    append bld {
      quotient := dividend ?/ divisor
      remainder := dividend ?% divisor
      checkQuotientIDIV oprSize sz lblAssign lblErr quotient
    }
  | _ ->
    raise InvalidOpcodeException
  append bld {
    AST.lmark lblAssign
  }
  match oprSize with
  | 8<rt> ->
    append bld {
      regVar bld R.AL := AST.xtlo oprSize quotient
      regVar bld R.AH := AST.xtlo oprSize remainder
    }
  | 16<rt> | 32<rt> | 64<rt> ->
    let q = getRegOfSize bld oprSize grpEAX
    let r = getRegOfSize bld oprSize grpEDX
    append bld {
      dstAssign oprSize q (AST.xtlo oprSize quotient)
      dstAssign oprSize r (AST.xtlo oprSize remainder)
    }
  | _ ->
    raise InvalidOperandSizeException

let div (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let lblAssign = label bld "Assign"
    let lblChk = label bld "Check"
    let lblErr = label bld "DivErr"
    let divisor = transOneOpr bld ins insLen
    let oprSize = getOperationSize ins
    AST.cjmp (divisor == AST.num0 oprSize)
             (AST.jmpDest lblErr)
             (AST.jmpDest lblChk)
    AST.lmark lblErr
    AST.sideEffect (Exception DivideError)
    AST.lmark lblChk
    divideWithConcat ins.Opcode oprSize divisor lblAssign lblErr bld
#if !EMULATION
    regVar bld R.CF := undefCF
    regVar bld R.OF := undefOF
    regVar bld R.AF := undefAF
    regVar bld R.SF := undefSF
    regVar bld R.ZF := undefZF
    regVar bld R.PF := undefPF
#else
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let enter ins insLen bld =
  lift bld ins insLen {
    let oSz = getOperationSize ins
    let struct (imm16, imm8) = transTwoOprs bld false ins insLen
    let struct (allocSize, nestingLevel, cnt) = tmpVars3 bld oSz
    let struct (frameTemp, addrSize) = tmpVars2 bld bld.RegType
    let bp = getBasePtr bld
    let sp = getStackPtr bld
    let lblLoop = label bld "Loop"
    let lblCont = label bld "Continue"
    let lblLevelCheck = label bld "NestingLevelCheck"
    let lblLv1 = label bld "NestingLevel1"
    let getAddrSize bitSize =
      if bitSize = 64<rt> then numI32 8 bitSize else numI32 4 bitSize
    allocSize := imm16
    nestingLevel := imm8 .% (numI32 32 oSz)
    auxPush bld.RegType bld bp
    frameTemp := sp
    addrSize := getAddrSize bld.RegType
    if imm8 .% (numI32 32 oSz) = (numI32 0 oSz) then
      () (* IR Optimization: Do not add unnecessary IRs *)
    else
      AST.cjmp (nestingLevel == AST.num0 oSz)
               (AST.jmpDest lblCont)
               (AST.jmpDest lblLevelCheck)
      AST.lmark lblLevelCheck
      cnt := nestingLevel .- AST.num1 oSz
      AST.cjmp (AST.gt nestingLevel (AST.num1 oSz))
               (AST.jmpDest lblLoop)
               (AST.jmpDest lblLv1)
      AST.lmark lblLoop
      bp := bp .- addrSize
      auxPush bld.RegType bld (AST.loadLE bld.RegType bp)
      cnt := cnt .- AST.num1 oSz
      AST.cjmp (cnt == AST.num0 oSz)
               (AST.jmpDest lblCont)
               (AST.jmpDest lblLoop)
      AST.lmark lblLv1
      auxPush bld.RegType bld frameTemp
      AST.lmark lblCont
    bp := frameTemp
    sp := sp .- AST.zext bld.RegType allocSize
  }

let private oneOperandImul bld oprSize src =
  match oprSize with
  | 8<rt> ->
    let mulSize = oprSize * 2
    let t = tmpVar bld mulSize
    let cond = AST.sext mulSize (AST.xtlo oprSize t) == t
    append bld {
      t := AST.sext mulSize (regVar bld R.AL) .* AST.sext mulSize src
      dstAssign oprSize (regVar bld R.AX) t
      regVar bld R.CF := cond == AST.b0
      regVar bld R.OF := cond == AST.b0
    }
  | 16<rt> | 32<rt> | 64<rt> ->
    (* The double-width product now includes 64x64->128 (mulSize = 128<rt>),
       which the evaluator holds directly, so a single sign-extended multiply
       replaces the former hand-rolled 32-bit decomposition. *)
    let mulSize = oprSize * 2
    let t = tmpVar bld mulSize
    let cond = AST.sext mulSize (AST.xtlo oprSize t) == t
    let r1 = getRegOfSize bld oprSize grpEDX
    let r2 = getRegOfSize bld oprSize grpEAX
    append bld {
      t := AST.sext mulSize r2 .* AST.sext mulSize src
      dstAssign oprSize r1 (AST.xthi oprSize t)
      dstAssign oprSize r2 (AST.xtlo oprSize t)
      regVar bld R.CF := cond == AST.b0
      regVar bld R.OF := cond == AST.b0
    }
  | _ ->
    raise InvalidOperandSizeException

let private operandsImul bld oprSize dst src1 src2 =
  match oprSize with
  | 8<rt> | 16<rt> | 32<rt> | 64<rt> ->
    (* doubleWidth reaches 128<rt> for the 64-bit form, which the evaluator now
       holds, so the one sign-extended multiply covers every operand size. *)
    let doubleWidth = oprSize * 2
    let t = tmpVar bld doubleWidth
    let cond = (AST.sext doubleWidth dst) != t
    append bld {
      t := AST.sext doubleWidth src1 .* AST.sext doubleWidth src2
      dstAssign oprSize dst (AST.xtlo oprSize t)
      regVar bld R.CF := cond
      regVar bld R.OF := cond
    }
  | _ ->
    raise InvalidOperandSizeException

let private buildMulBody ins insLen bld =
  let oprSize = getOperationSize ins
  match ins.Operands with
  | OneOperand op ->
    let src = transOprToExpr bld false ins insLen op
    oneOperandImul bld oprSize src
  | TwoOperands(o1, o2) ->
    let dst = transOprToExpr bld false ins insLen o1
    let src = transOprToExpr bld false ins insLen o2
    operandsImul bld oprSize dst dst src
  | ThreeOperands(o1, o2, o3) ->
    let dst = transOprToExpr bld false ins insLen o1
    let src1 = transOprToExpr bld false ins insLen o2
    let src2 = transOprToExpr bld false ins insLen o3
    operandsImul bld oprSize dst src1 src2
  | _ ->
    raise InvalidOperandException

let imul (ins: Instruction) insLen bld =
  lift bld ins insLen {
    buildMulBody ins insLen bld
#if !EMULATION
    regVar bld R.SF := undefSF
    regVar bld R.ZF := undefZF
    regVar bld R.AF := undefAF
    regVar bld R.PF := undefPF
#else
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let inc (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let dst = transOneOpr bld ins insLen
    let oprSize = getOperationSize ins
    let struct (t1, t2, t3) = tmpVars3 bld oprSize
    atomicBeginIfLocked ins bld
    t1 := dst
    t2 := AST.num1 oprSize
    t3 := (t1 .+ t2)
    dstAssign oprSize dst t3
    let struct (ofl, sf) = osfOnAdd t1 t2 t3 bld
    regVar bld R.OF := ofl
    enumASZPFlags bld t1 t2 t3 oprSize sf
    atomicEndIfLocked ins bld
#if EMULATION
    regVar bld R.CF := getCFLazy bld
    setCCOperands2 bld t1 t3
    match oprSize with
    | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.INCB
    | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.INCW
    | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.INCD
    | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.INCQ
    | _ -> raise InvalidRegTypeException
#endif
  }

let interrupt ins insLen bld =
  match transOneOpr bld ins insLen with
  | Num(n, _) ->
    Interrupt(n.ToInt32())
    |> sideEffects bld ins insLen
  | _ ->
    raise InvalidOperandException

let private getCondOfJcc (ins: Instruction) (bld: ILowUIRBuilder) =
#if DEBUG
  if bld.RegType = 64<rt> && (getOperationSize ins) = 16<rt> then
    Terminator.impossible ()
  else
    ()
#endif
  match ins.Opcode with
  | Opcode.JO ->
    regVar bld R.OF
  | Opcode.JNO ->
    regVar bld R.OF == AST.b0
  | Opcode.JB ->
    regVar bld R.CF
  | Opcode.JNB ->
    regVar bld R.CF == AST.b0
  | Opcode.JZ ->
    regVar bld R.ZF
  | Opcode.JNZ ->
    regVar bld R.ZF == AST.b0
  | Opcode.JBE ->
    (regVar bld R.CF) .| (regVar bld R.ZF)
  | Opcode.JA ->
    ((regVar bld R.CF) .| (regVar bld R.ZF)) == AST.b0
  | Opcode.JS ->
    regVar bld R.SF
  | Opcode.JNS ->
    regVar bld R.SF == AST.b0
  | Opcode.JP ->
    regVar bld R.PF
  | Opcode.JNP ->
    regVar bld R.PF == AST.b0
  | Opcode.JL ->
    regVar bld R.SF != regVar bld R.OF
  | Opcode.JNL ->
    regVar bld R.SF == regVar bld R.OF
  | Opcode.JLE ->
    (regVar bld R.ZF) .|
                  (regVar bld R.SF != regVar bld R.OF)
  | Opcode.JG ->
    (regVar bld R.ZF == AST.b0) .&
                 (regVar bld R.SF == regVar bld R.OF)
  | Opcode.JCXZ ->
    (regVar bld R.CX) == (AST.num0 bld.RegType)
  | Opcode.JECXZ ->
    let sz = bld.RegType
    (AST.cast CastKind.ZeroExt sz (regVar bld R.ECX)) == (AST.num0 sz)
  | Opcode.JRCXZ ->
    (regVar bld R.RCX) == (AST.num0 bld.RegType)
  | _ ->
    raise InvalidOpcodeException

#if EMULATION
let private getCondOfJccLazy (ins: Instruction) (bld: ILowUIRBuilder) =
#if DEBUG
  if bld.RegType = 64<rt> && (getOperationSize ins) = 16<rt> then
    Terminator.impossible ()
  else
    ()
#endif
  match ins.Opcode with
  | Opcode.JO ->
    getOFLazy bld
  | Opcode.JNO ->
    getOFLazy bld |> AST.not
  | Opcode.JB ->
    getCFLazy bld
  | Opcode.JNB ->
    getCFLazy bld |> AST.not
  | Opcode.JZ ->
    getZFLazy bld
  | Opcode.JNZ ->
    getZFLazy bld |> AST.not
  | Opcode.JBE ->
    let ccOp = bld.ConditionCodeOp
    match ccOp with
    | ConditionCodeOp.SUBB
    | ConditionCodeOp.SUBW
    | ConditionCodeOp.SUBD
    | ConditionCodeOp.SUBQ ->
      let size = 1 <<< ((int ccOp - int ConditionCodeOp.SUBB) &&& 0b11)
      let regType = RegType.fromByteWidth size
      let src2 = getCCSrc1 bld regType
      let src1 = getCCDst bld regType .+ src2
      src1 .<= src2
    | _ ->
      (getCFLazy bld) .| (getZFLazy bld)
  | Opcode.JA ->
    (getCFLazy bld .| getZFLazy bld) |> AST.not
  | Opcode.JS ->
    getSFLazy bld
  | Opcode.JNS ->
    getSFLazy bld |> AST.not
  | Opcode.JP ->
    getPFLazy bld
  | Opcode.JNP ->
    getPFLazy bld |> AST.not
  | Opcode.JL ->
    let ccOp = bld.ConditionCodeOp
    match ccOp with
    | ConditionCodeOp.SUBB
    | ConditionCodeOp.SUBW
    | ConditionCodeOp.SUBD
    | ConditionCodeOp.SUBQ ->
      let size = 1 <<< ((int ccOp - int ConditionCodeOp.SUBB) &&& 0b11)
      let regType = RegType.fromByteWidth size
      let src2 = getCCSrc1 bld regType
      let src1 = getCCDst bld regType .+ src2
      src1 ?< src2
    | _ ->
      getOFLazy bld != getSFLazy bld
  | Opcode.JNL ->
    getOFLazy bld == getSFLazy bld
  | Opcode.JLE ->
    let ccOp = bld.ConditionCodeOp
    match ccOp with
    | ConditionCodeOp.SUBB
    | ConditionCodeOp.SUBW
    | ConditionCodeOp.SUBD
    | ConditionCodeOp.SUBQ ->
      let size = 1 <<< ((int ccOp - int ConditionCodeOp.SUBB) &&& 0b11)
      let regType = RegType.fromByteWidth size
      let src2 = getCCSrc1 bld regType
      let src1 = getCCDst bld regType .+ src2
      src1 ?<= src2
    | _ ->
      (getOFLazy bld != getSFLazy bld) .| (getZFLazy bld)
  | Opcode.JG ->
    (getOFLazy bld == getSFLazy bld) .& (getZFLazy bld |> AST.not)
  | Opcode.JCXZ ->
    regVar bld R.CX == AST.num0 bld.RegType
  | Opcode.JECXZ ->
    let sz = bld.RegType
    (AST.cast CastKind.ZeroExt sz (regVar bld R.ECX)) == (AST.num0 sz)
  | Opcode.JRCXZ ->
    (regVar bld R.RCX) == (AST.num0 bld.RegType)
  | _ ->
    raise InvalidOpcodeException
#endif

let jcc (ins: Instruction) insLen bld =
  liftOpen bld ins insLen {
    let pc = numU64 ins.Address bld.RegType
    let jmpTarget = pc .+ transOneOpr bld ins insLen
#if EMULATION
    let cond = getCondOfJccLazy ins bld
    setCCOp bld
    bld.ConditionCodeOp <- ConditionCodeOp.TraceStart
#else
    let cond = getCondOfJcc ins bld
#endif
    let fallThrough = pc .+ numInsLen insLen bld
    AST.intercjmp cond jmpTarget fallThrough
  }

let jmp (ins: Instruction) insLen bld =
  liftOpen bld ins insLen {
#if EMULATION
    setCCOp bld
    bld.ConditionCodeOp <- ConditionCodeOp.TraceStart
#endif
    let pc = numU64 (ins: Instruction).Address bld.RegType
    let struct (target, _) = transJumpTargetOpr bld false ins pc insLen
    AST.interjmp target InterJmpKind.Base
  }

let lahf (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let t = tmpVar bld 8<rt>
    let ah = regVar bld R.AH
#if EMULATION
    let cf = getCFLazy bld
    let pf = getPFLazy bld
    let af = getAFLazy bld
    let zf = getZFLazy bld
    let sf = getSFLazy bld
#else
    let cf = AST.zext 8<rt> (regVar bld R.CF)
    let pf = AST.zext 8<rt> (regVar bld R.PF)
    let af = AST.zext 8<rt> (regVar bld R.AF)
    let zf = AST.zext 8<rt> (regVar bld R.ZF)
    let sf = AST.zext 8<rt> (regVar bld R.SF)
#endif
    let cf = AST.zext 8<rt> (regVar bld R.CF)
    let pf = AST.zext 8<rt> (regVar bld R.PF)
    let af = AST.zext 8<rt> (regVar bld R.AF)
    let zf = AST.zext 8<rt> (regVar bld R.ZF)
    let sf = AST.zext 8<rt> (regVar bld R.SF)
    t := numI32 2 8<rt>
    t := t .| cf
    t := t .| (pf << numI32 2 8<rt>)
    t := t .| (af << numI32 4 8<rt>)
    t := t .| (zf << numI32 6 8<rt>)
    t := t .| (sf << numI32 7 8<rt>)
    ah := t
  }

let private unwrapLeaSrc = function
  | Load(_, _, BinOp(BinOpType.ADD, _, e, Num(n, _), _), _) when n.IsZero -> e
  | Load(_, _, expr, _) -> expr
  | _ -> Terminator.impossible ()

let lea (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs bld false ins insLen
    let oprSize = getOperationSize ins
    let src = unwrapLeaSrc src
    let addrSize = getEffAddrSz ins
    match oprSize, addrSize with
    | 16<rt>, 16<rt> | 32<rt>, 32<rt> | 64<rt>, 64<rt> ->
      dstAssign oprSize dst src
    | 16<rt>, 32<rt> | 16<rt>, 64<rt> ->
      dstAssign oprSize dst (AST.xtlo 16<rt> src)
    | 32<rt>, 16<rt> ->
      dstAssign oprSize dst (AST.zext 32<rt> src)
    | 32<rt>, 64<rt> ->
      dstAssign oprSize dst (AST.xtlo 32<rt> src)
    | 64<rt>, 32<rt> ->
      dstAssign oprSize dst (AST.zext 64<rt> src)
    | _ ->
      raise InvalidOperandSizeException
  }

let leave (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let sp = getStackPtr bld
    let bp = getBasePtr bld
    sp := bp
    auxPop bld.RegType bld bp
  }

let private lodsBody ins bld =
  append bld {
    let oprSize = getOperationSize ins
    let df = regVar bld R.DF
    let si = regVar bld (if is64bit bld then R.RSI else R.ESI)
    let dst = getRegOfSize bld oprSize grpEAX
    let amount = numI32 (RegType.toByteWidth oprSize) bld.RegType
    dst := AST.loadLE oprSize si
    si := AST.ite df (si .- amount) (si .+ amount)
  }

let lods (ins: Instruction) insLen bld =
  liftOpen bld ins insLen {
    if Prefix.hasREPZ ins.Prefixes then
      strRepeat ins insLen bld lodsBody None
    elif Prefix.hasREPNZ ins.Prefixes then
      Terminator.impossible ()
    else
      lodsBody ins bld
      markEnd bld insLen
  }

let loop (ins: Instruction) insLen bld =
  liftOpen bld ins insLen {
    let dst = transOneOpr bld ins insLen
    let addrSize = getEffAddrSz ins
    let pc = getInstrPtr bld
    let count, cntSize =
      if addrSize = 32<rt> then regVar bld R.ECX, 32<rt>
      elif addrSize = 64<rt> then regVar bld R.RCX, 64<rt>
      else regVar bld R.CX, 16<rt>
#if EMULATION
    let zf = getZFLazy bld
#else
    let zf = regVar bld R.ZF
#endif
    count := count .- AST.num1 cntSize
    let branchCond =
      match ins.Opcode with
      | Opcode.LOOP -> count != AST.num0 cntSize
      | Opcode.LOOPE -> (zf == AST.b1) .& (count != AST.num0 cntSize)
      | Opcode.LOOPNE -> (zf == AST.b0) .& (count != AST.num0 cntSize)
      | _ -> raise InvalidOpcodeException
    let fallThrough = pc .+ numInsLen insLen bld
    let jumpTarget =
      if addrSize = 16<rt> then pc .& numI32 0xFFFF 32<rt>
      else pc .+ AST.sext bld.RegType dst
    AST.intercjmp branchCond jumpTarget fallThrough
  }

/// The three masks a SWAR population count folds a value through, one per
/// operand width.
let private popCountMasks oprSize =
  match oprSize with
  | 16<rt> ->
    struct (numI32 0x5555 16<rt>, numI32 0x3333 16<rt>, numI32 0x0f0f 16<rt>)
  | 32<rt> ->
    let m1 = numI32 0x55555555 32<rt>
    let m2 = numI32 0x33333333 32<rt>
    struct (m1, m2, numI32 0x0f0f0f0f 32<rt>)
  | 64<rt> ->
    let m1 = numU64 0x5555555555555555UL 64<rt>
    let m2 = numU64 0x3333333333333333UL 64<rt>
    struct (m1, m2, numU64 0x0f0f0f0f0f0f0f0fUL 64<rt>)
  | _ ->
    raise InvalidOperandSizeException

/// Smears the highest set bit of `x` down through every bit below it, by
/// doubling the shift until it covers the whole operand.
let private smearHighBit bld oprSize x =
  let bits = RegType.toBitWidth oprSize
  let rec go step =
    if step < bits then
      append bld { x := x .| (x >> numI32 step oprSize) }
      go (step * 2)
    else
      ()
  go 1

/// Folds the per-byte counts a SWAR population count has built up into the
/// low byte of `x`.
let private sumByteCounts bld oprSize x =
  let bits = RegType.toBitWidth oprSize
  let rec go step =
    if step < bits then
      append bld { x := x .+ (x >> numI32 step oprSize) }
      go (step * 2)
    else
      ()
  go 8

let lzcnt ins insLen bld =
  lift bld ins insLen {
    let oprSize = getOperationSize ins
    let struct (dst, src) = transTwoOprs bld true ins insLen
    let x = tmpVar bld oprSize
    let n = AST.num0 oprSize
    let struct (mask1, mask2, mask3) = popCountMasks oprSize
    let bits = RegType.toBitWidth oprSize
    x := src
    smearHighBit bld oprSize x
    x := x .- ((x >> numI32 1 oprSize) .& mask1)
    x := ((x >> numI32 2 oprSize) .& mask2) .+ (x .& mask2)
    x := ((x >> numI32 4 oprSize) .+ x) .& mask3
    sumByteCounts bld oprSize x
    let ones = x .& numI32 (bits * 2 - 1) oprSize
    dstAssign oprSize dst (numI32 bits oprSize .- ones)
    let width = numI32 bits oprSize
    regVar bld R.CF := dst == width
    regVar bld R.ZF := dst == n
#if !EMULATION
    regVar bld R.OF := undefOF
    regVar bld R.SF := undefSF
    regVar bld R.PF := undefPF
    regVar bld R.AF := undefAF
#else
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let mov (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs bld false ins insLen
    let oprSize = getOperationSize ins
    (* MOV Sreg, r/m64 names a whole register and keeps only the selector-wide
       half of it, so here alone the source is wider than the operation. *)
    let src =
      if Expr.typeOf src > oprSize then AST.xtlo oprSize src
      else AST.zext oprSize src
    dstAssign oprSize dst src
  }

let movbe (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs bld false ins insLen
    let oprSize = getOperationSize ins
    let cnt = RegType.toByteWidth oprSize |> int
    let t = tmpVar bld oprSize
    let tmps = Array.init cnt (fun _ -> tmpVar bld 8<rt>)
    t := src
    for i in 0 .. cnt - 1 do
      tmps[i] := AST.extract t 8<rt> (i * 8)
    done
    dstAssign oprSize dst (AST.revConcat (Array.rev tmps))
  }

let private movsBody ins bld =
  append bld {
    let oprSize = getOperationSize ins
    let df = regVar bld R.DF
    let si = regVar bld (if is64bit bld then R.RSI else R.ESI)
    let di = regVar bld (if is64bit bld then R.RDI else R.EDI)
    let amount = numI32 (RegType.toByteWidth oprSize) bld.RegType
    AST.loadLE oprSize di := AST.loadLE oprSize si
    si := AST.ite df (si .- amount) (si .+ amount)
    di := AST.ite df (di .- amount) (di .+ amount)
  }

let movs (ins: Instruction) insLen bld =
  liftOpen bld ins insLen {
    if Prefix.hasREPZ ins.Prefixes then
      strRepeat ins insLen bld movsBody None
    else
      movsBody ins bld
      markEnd bld insLen
  }

let movsx (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs bld false ins insLen
    let oprSize = getOperationSize ins
    dstAssign oprSize dst (AST.sext oprSize src)
  }

let movzx (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs bld false ins insLen
    let oprSize = getOperationSize ins
    dstAssign oprSize dst (AST.zext oprSize src)
  }

/// Sets the flags a MUL leaves behind: CF and OF both say whether the upper
/// half of the product carries anything, and the rest are undefined.
let private setMulFlags bld oprSize t cond =
  append bld {
    cond := AST.xthi oprSize t != (AST.num0 oprSize)
    regVar bld R.CF := cond
    regVar bld R.OF := cond
#if !EMULATION
    regVar bld R.SF := undefSF
    regVar bld R.ZF := undefZF
    regVar bld R.AF := undefAF
    regVar bld R.PF := undefPF
#else
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let mul ins insLen bld =
  lift bld ins insLen {
    let oprSize = getOperationSize ins
    match oprSize with
    | 8<rt> ->
      let dblWidth = oprSize * 2
      let src1 = AST.zext dblWidth (getRegOfSize bld oprSize grpEAX)
      let src2 = AST.zext dblWidth (transOneOpr bld ins insLen)
      let t = tmpVar bld dblWidth
      t := src1 .* src2
      let cond = tmpVar bld 1<rt>
      regVar bld R.AX := t
      setMulFlags bld oprSize t cond
    | 16<rt> | 32<rt> | 64<rt> ->
      (* dblWidth reaches 128<rt> for the 64-bit form, which the evaluator holds
         directly, so one zero-extended multiply replaces the former hand-rolled
         32-bit decomposition. *)
      let dblWidth = oprSize * 2
      let edx = getRegOfSize bld oprSize grpEDX
      let eax = getRegOfSize bld oprSize grpEAX
      let src1 = AST.zext dblWidth eax
      let src2 = AST.zext dblWidth (transOneOpr bld ins insLen)
      let t = tmpVar bld dblWidth
      t := src1 .* src2
      let cond = tmpVar bld 1<rt>
      dstAssign oprSize edx (AST.xthi oprSize t)
      dstAssign oprSize eax (AST.xtlo oprSize t)
      setMulFlags bld oprSize t cond
    | _ ->
      raise InvalidOperandSizeException
  }

let mulx ins insLen bld =
  lift bld ins insLen {
    let oprSize = getOperationSize ins
    match oprSize with
    | 32<rt> ->
      let struct (dst1, dst2, src) = transThreeOprs bld false ins insLen
      let dblWidth = oprSize * 2
      let src1 = AST.zext dblWidth (getRegOfSize bld oprSize grpEDX)
      let src2 = AST.zext dblWidth src
      let t = tmpVar bld dblWidth
      t := src1 .* src2
      dstAssign oprSize dst2 (AST.xtlo 32<rt> t)
      dstAssign oprSize dst1 (AST.xthi 32<rt> t)
    | 64<rt> ->
      let struct (dst1, dst2, src) = transThreeOprs bld false ins insLen
      let src1 = getRegOfSize bld oprSize grpEDX
      let struct (hiSrc1, loSrc1, hiSrc, loSrc) = tmpVars4 bld 64<rt>
      let struct (tHigh, tLow) = tmpVars2 bld 64<rt>
      let n32 = numI32 32 64<rt>
      let mask = numI64 0xFFFFFFFFL 64<rt>
      hiSrc1 := (src1 >> n32) .& mask (* SRC1[63:32] *)
      loSrc1 := src1 .& mask (* SRC1[31:0] *)
      hiSrc := (src >> n32) .& mask (* SRC[63:32] *)
      loSrc := src .& mask (* SRC[31:0] *)
      let pHigh = hiSrc1 .* hiSrc
      let pMid = (hiSrc1 .* loSrc) .+ (loSrc1 .* hiSrc)
      let pLow = (loSrc1 .* loSrc)
      let high = pHigh .+ ((pMid .+ (pLow >> n32)) >> n32)
      let low = pLow .+ ((pMid .& mask) << n32)
      let isOverflow =
        hiSrc1 .* loSrc .> numI64 0xffffffff_ffffffffL 64<rt> .- loSrc1 .* hiSrc
      let carry = AST.ite isOverflow (numI64 0x100000000L 64<rt>)
                                     (AST.num0 64<rt>)
      tHigh := high .+ carry
      tLow := low
      dstAssign oprSize dst2 tLow
      dstAssign oprSize dst1 tHigh
    | _ ->
      raise InvalidOperandSizeException
  }

let neg (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let dst = transOneOpr bld ins insLen
    let oprSize = getOperationSize ins
    let t = tmpVar bld oprSize
    let zero = AST.num0 oprSize
    t := dst
    dstAssign oprSize dst (AST.neg t)
#if EMULATION
    setCCOperands2 bld t dst
    match oprSize with
    | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SUBB
    | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SUBW
    | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SUBD
    | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SUBQ
    | _ -> raise InvalidRegTypeException
#else
    let sf = AST.xthi 1<rt> dst
    let cf = cfOnSub zero t
    let ofl = ofOnSub zero t dst
    enumEFLAGS bld zero t dst oprSize cf ofl sf
#endif
  }

let nop (ins: Instruction) insLen bld =
  lift bld ins insLen { () }

let not (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let dst = transOneOpr bld ins insLen
    let oprSize = getOperationSize ins
    dstAssign oprSize dst (AST.unop UnOpType.NOT dst)
  }

let logOr (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs bld true ins insLen
    let oprSize = getOperationSize ins
    atomicBeginIfLocked ins bld
    dstAssign oprSize dst (dst .| src)
#if EMULATION
    setCCDst bld dst
    match oprSize with
    | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICB
    | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICW
    | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICD
    | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICQ
    | _ -> raise InvalidRegTypeException
#else
    let sf = AST.xthi 1<rt> dst
    regVar bld R.CF := AST.b0
    regVar bld R.OF := AST.b0
    enumSZPFlags bld dst oprSize sf
    regVar bld R.AF := undefAF
#endif
    atomicEndIfLocked ins bld
  }

let pdep (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs bld false ins insLen
    let oprSize = getOperationSize ins
    let struct (temp, mask, dest) = tmpVars3 bld oprSize
    let cond = tmpVar bld 1<rt>
    let k = tmpVar bld oprSize
    temp := src1
    mask := src2
    dest := AST.num0 oprSize
    k := AST.num0 oprSize
    for i in 0 .. (int oprSize) - 1 do
      cond := AST.extract mask 1<rt> i
      let tempk = (temp >> k) |> AST.xtlo 1<rt>
      AST.extract dest 1<rt> i := AST.ite cond tempk AST.b0
      k := AST.ite cond (k .+ AST.num1 oprSize) k
    done
    dstAssign oprSize dst dest
  }

let pext (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src, mask) = transThreeOprs bld false ins insLen
    let oSz = getOperationSize ins
    let struct (t, k) = tmpVars2 bld oSz
    let cond = tmpVar bld 1<rt>
    t := AST.num0 oSz
    k := AST.num0 oSz
    for i in 0 .. (int oSz) - 1 do
      cond := AST.extract mask 1<rt> i
      let extSrc = AST.zext oSz (AST.extract src 1<rt> i)
      t := t .| (AST.ite cond (extSrc << k) t)
      k := k .+ (AST.zext oSz cond)
    done
    dstAssign oSz dst t
  }

let pop (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let dst = transOneOpr bld ins insLen
    let oprSize = getOperationSize ins
    auxPop oprSize bld dst
  }

let popa (ins: Instruction) insLen bld oprSize =
  lift bld ins insLen {
    let sp = regVar bld R.ESP
    let di = if oprSize = 32<rt> then R.EDI else R.DI
    let si = if oprSize = 32<rt> then R.ESI else R.SI
    let bp = if oprSize = 32<rt> then R.EBP else R.BP
    let bx = if oprSize = 32<rt> then R.EBX else R.BX
    let dx = if oprSize = 32<rt> then R.EDX else R.DX
    let cx = if oprSize = 32<rt> then R.ECX else R.CX
    let ax = if oprSize = 32<rt> then R.EAX else R.AX
    auxPop oprSize bld (regVar bld di)
    auxPop oprSize bld (regVar bld si)
    auxPop oprSize bld (regVar bld bp)
    sp := sp .+ (numI32 (int oprSize / 8) 32<rt>)
    auxPop oprSize bld (regVar bld bx)
    auxPop oprSize bld (regVar bld dx)
    auxPop oprSize bld (regVar bld cx)
    auxPop oprSize bld (regVar bld ax)
  }

let popcnt (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let lblLoop = label bld "Loop"
    let lblExit = label bld "Exit"
    let lblLoopCond = label bld "LoopCond"
    let struct (dst, src) = transTwoOprs bld false ins insLen
    let oprSize = getOperationSize ins
    let max = numI32 (RegType.toBitWidth oprSize) oprSize
    let struct (i, count, orgSrc) = tmpVars3 bld oprSize
    i := AST.num0 oprSize
    count := AST.num0 oprSize
    orgSrc := src
    AST.lmark lblLoopCond
    AST.cjmp (i .< max) (AST.jmpDest lblLoop) (AST.jmpDest lblExit)
    AST.lmark lblLoop
    let cond = (AST.xtlo 1<rt> (src >> i)) == AST.b1
    count := AST.ite cond (count .+ AST.num1 oprSize) count
    i := i .+ AST.num1 oprSize
    AST.jmp (AST.jmpDest lblLoopCond)
    AST.lmark lblExit
    dstAssign oprSize dst count
    regVar bld R.OF := AST.b0
    regVar bld R.SF := AST.b0
    regVar bld R.ZF := orgSrc == AST.num0 oprSize
    regVar bld R.AF := AST.b0
    regVar bld R.CF := AST.b0
    regVar bld R.PF := AST.b0
#if EMULATION
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let popf ins insLen bld =
  lift bld ins insLen {
    let oprSize = getOperationSize ins
    let t = tmpVar bld oprSize
    auxPop oprSize bld t
    regVar bld R.OF := AST.extract t 1<rt> 11
    regVar bld R.DF := AST.extract t 1<rt> 10
    regVar bld R.IF := AST.extract t 1<rt> 9
    regVar bld R.TF := AST.extract t 1<rt> 8
    regVar bld R.SF := AST.extract t 1<rt> 7
    regVar bld R.ZF := AST.extract t 1<rt> 6
    regVar bld R.AF := AST.extract t 1<rt> 4
    regVar bld R.PF := AST.extract t 1<rt> 2
    regVar bld R.CF := AST.xtlo 1<rt> t
#if EMULATION
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let inline private padPushExpr oprSize opr =
  match opr with
  | Var(_, s, _, _) ->
    if isSegReg <| Register.ofRegID s then AST.zext oprSize opr else opr
  | Num(_) ->
    AST.sext oprSize opr
  | _ ->
    opr

let push (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let src = transOneOpr bld ins insLen
    let oprSize = getOperationSize ins
    if hasStackPtr ins then
      let t = tmpVar bld oprSize
      t := padPushExpr oprSize src
      auxPush oprSize bld (padPushExpr oprSize t)
    else
      auxPush oprSize bld (padPushExpr oprSize src)
  }

let pusha (ins: Instruction) insLen bld oprSize =
  lift bld ins insLen {
    let t = tmpVar bld oprSize
    let sp = if oprSize = 32<rt> then R.ESP else R.SP
    let ax = if oprSize = 32<rt> then R.EAX else R.AX
    let cx = if oprSize = 32<rt> then R.ECX else R.CX
    let dx = if oprSize = 32<rt> then R.EDX else R.DX
    let bx = if oprSize = 32<rt> then R.EBX else R.BX
    let bp = if oprSize = 32<rt> then R.EBP else R.BP
    let si = if oprSize = 32<rt> then R.ESI else R.SI
    let di = if oprSize = 32<rt> then R.EDI else R.DI
    dstAssign oprSize t (regVar bld sp)
    auxPush oprSize bld (regVar bld ax)
    auxPush oprSize bld (regVar bld cx)
    auxPush oprSize bld (regVar bld dx)
    auxPush oprSize bld (regVar bld bx)
    auxPush oprSize bld t
    auxPush oprSize bld (regVar bld bp)
    auxPush oprSize bld (regVar bld si)
    auxPush oprSize bld (regVar bld di)
  }

let pushf ins insLen bld =
  lift bld ins insLen {
    let oprSize = getOperationSize ins
    let e = AST.zext oprSize <| regVar bld R.CF
    (* We only consider 9 flags (we ignore system flags). *)
#if EMULATION
    let e = e .| ((AST.zext oprSize (getPFLazy bld)) << numI32 2 oprSize)
    let e = e .| ((AST.zext oprSize (getAFLazy bld)) << numI32 4 oprSize)
    let e = e .| ((AST.zext oprSize (getZFLazy bld)) << numI32 6 oprSize)
    let e = e .| ((AST.zext oprSize (getSFLazy bld)) << numI32 7 oprSize)
    let e = e .| ((AST.zext oprSize (regVar bld R.TF)) << numI32 8 oprSize)
    let e = e .| ((AST.zext oprSize (regVar bld R.IF)) << numI32 9 oprSize)
    let e = e .| ((AST.zext oprSize (regVar bld R.DF)) << numI32 10 oprSize)
    let e = e .| ((AST.zext oprSize (getOFLazy bld)) << numI32 11 oprSize)
#else
#endif
    let e = e .| ((AST.zext oprSize (regVar bld R.PF)) << numI32 2 oprSize)
    let e = e .| ((AST.zext oprSize (regVar bld R.AF)) << numI32 4 oprSize)
    let e = e .| ((AST.zext oprSize (regVar bld R.ZF)) << numI32 6 oprSize)
    let e = e .| ((AST.zext oprSize (regVar bld R.SF)) << numI32 7 oprSize)
    let e = e .| ((AST.zext oprSize (regVar bld R.TF)) << numI32 8 oprSize)
    let e = e .| ((AST.zext oprSize (regVar bld R.IF)) << numI32 9 oprSize)
    let e = e .| ((AST.zext oprSize (regVar bld R.DF)) << numI32 10 oprSize)
    let e = e .| ((AST.zext oprSize (regVar bld R.OF)) << numI32 11 oprSize)
    let e = match oprSize with
            | 16<rt> -> e
            | 32<rt> -> e .& (numI32 0xfcffff 32<rt>)
            | 64<rt> -> e .& (numI32 0xfcffff 64<rt>)
            | _ -> raise InvalidOperandSizeException
    auxPush oprSize bld e
  }

/// How many places a rotate-through-carry actually turns. The count is masked
/// to five bits (six on 64-bit operands) and, for the narrow sizes, taken
/// modulo the width of the operand plus the carry bit it rotates through.
let private rotateThroughCarryCount oprSize count =
  match oprSize with
  | 8<rt> -> (count .& numI32 0x1f oprSize) .% numI32 9 oprSize
  | 16<rt> -> (count .& numI32 0x1f oprSize) .% numI32 17 oprSize
  | 32<rt> -> count .& numI32 0x1f oprSize
  | 64<rt> -> count .& numI32 0x3f oprSize
  | _ -> raise InvalidOperandSizeException

let rcl (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, count) = transTwoOprs bld true ins insLen
    let oprSize = getOperationSize ins
    let cF = regVar bld R.CF
    let oF = regVar bld R.OF
    let tmpCF = tmpVar bld 1<rt>
    let count = AST.zext oprSize count
    let tmpCnt = tmpVar bld oprSize
    let cnt = rotateThroughCarryCount oprSize count
    tmpCnt := cnt
    let cond1 = tmpCnt != AST.num0 oprSize
    let cntMask = numI32 (if oprSize = 64<rt> then 0x3F else 0x1F) oprSize
    let cond2 = (count .& cntMask) == AST.num1 oprSize
#if EMULATION
    cF := getCFLazy bld
#endif
    _repeat bld "Rotate" cond1
      (block {
        tmpCF := AST.xthi 1<rt> dst
        let r = (dst << AST.num1 oprSize) .+ (AST.zext oprSize cF)
        dstAssign oprSize dst r
        cF := tmpCF
        tmpCnt := tmpCnt .- AST.num1 oprSize })
      (block {
        dstAssign oprSize dst dst })
#if !EMULATION
    oF := AST.ite cond2 (AST.xthi 1<rt> dst <+> cF) undefOF
#else
    oF := AST.ite cond2 (AST.xthi 1<rt> dst <+> cF) (getOFLazy bld)
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let rcr (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, count) = transTwoOprs bld true ins insLen
    let oprSize = getOperationSize ins
    let cF = regVar bld R.CF
    let oF = regVar bld R.OF
    let struct (tmpCF, tmpOF) = tmpVars2 bld 1<rt>
    let count = AST.zext oprSize count
    let tmpCnt = tmpVar bld oprSize
    let cnt = rotateThroughCarryCount oprSize count
    tmpCnt := cnt
    let cond1 = tmpCnt != AST.num0 oprSize
    let cntMask = numI32 (if oprSize = 64<rt> then 0x3F else 0x1F) oprSize
    let cond2 = (count .& cntMask) == AST.num1 oprSize
#if EMULATION
    cF := getCFLazy bld
#endif
    tmpOF := AST.xthi 1<rt> dst <+> cF
    _repeat bld "Rotate" cond1
      (block {
        tmpCF := AST.xtlo 1<rt> dst
        let extCF = (AST.zext oprSize cF) << (numI32 (int oprSize - 1) oprSize)
        dstAssign oprSize dst ((dst >> AST.num1 oprSize) .+ extCF)
        cF := tmpCF
        tmpCnt := tmpCnt .- AST.num1 oprSize })
      (block {
        dstAssign oprSize dst dst })
#if !EMULATION
    oF := AST.ite cond2 tmpOF undefOF
#else
    oF := AST.ite cond2 tmpOF (getOFLazy bld)
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let rdpkru ins insLen bld =
  lift bld ins insLen {
    let oprSize = getOperationSize ins
    let ecx = regVar bld R.ECX
    let eax = getRegOfSize bld bld.RegType grpEAX
    let edx = getRegOfSize bld bld.RegType grpEDX
    _unless bld "Err" (ecx == AST.num0 oprSize)
      (block {
        AST.sideEffect (Exception ProtectionFault) })
    eax := AST.zext bld.RegType (regVar bld R.PKRU)
    edx := AST.num0 bld.RegType
  }

let ret (ins: Instruction) insLen bld =
  let oprSize = getOperationSize ins
  let t = tmpVar bld oprSize
  liftOpen bld ins insLen {
    match ins.Operands with
    | NoOperand ->
#if EMULATION
      setCCOp bld
      bld.ConditionCodeOp <- ConditionCodeOp.TraceStart
#endif
      auxPop oprSize bld t
    | _ (* OneOperand *) ->
      let sp = getStackPtr bld
      let src = transOneOpr bld ins insLen
#if EMULATION
      setCCOp bld
      bld.ConditionCodeOp <- ConditionCodeOp.TraceStart
#endif
      auxPop oprSize bld t
      sp := sp .+ (AST.zext oprSize src)
    AST.interjmp t InterJmpKind.IsRet
  }

let rotate (ins: Instruction) insLen bld lfn hfn cfFn ofFn =
  lift bld ins insLen {
    let struct (dst, count) = transTwoOprs bld true ins insLen
    let oprSize = getOperationSize ins
    let cF = regVar bld R.CF
    let oF = regVar bld R.OF
    let struct (orgCount, maskedCnt) = tmpVars2 bld oprSize
    let size = numI32 (RegType.toBitWidth oprSize) oprSize
    orgCount := AST.zext oprSize count .% (numI32 (int oprSize) oprSize)
    let countmask = if oprSize = 64<rt> then 0x3F else 0x1F
    maskedCnt := AST.zext oprSize count .& numI32 countmask oprSize
    let cond1 = maskedCnt == AST.num0 oprSize
    let cond2 = maskedCnt == AST.num1 oprSize
    let value = (lfn dst orgCount) .| (hfn dst (size .- orgCount))
    dstAssign oprSize dst value
#if !EMULATION
    cF := AST.ite cond1 cF (cfFn 1<rt> dst)
    oF := AST.ite cond2 (ofFn dst cF) undefOF
#else
    genDynamicFlagsUpdate bld
    cF := AST.ite cond1 cF (cfFn 1<rt> dst)
    oF := AST.ite cond2 (ofFn dst cF) oF
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let rol ins insLen bld =
  let ofFn dst cF = cF <+> AST.xthi 1<rt> dst
  rotate ins insLen bld (<<) (>>) AST.xtlo ofFn

let ror ins insLen bld =
  let oprSize = getOperationSize ins
  let ofFn dst _cF =
    AST.xthi 1<rt> dst <+> AST.extract dst 1<rt> ((int oprSize - 1) - 1)
  rotate ins insLen bld (>>) (<<) AST.xthi ofFn

let rorx (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src, imm) = transThreeOprs bld false ins insLen
    let oprSize = getOperationSize ins
    let y = tmpVar bld oprSize
    if oprSize = 32<rt> then
      y := imm .& (numI32 0x1F oprSize)
      dstAssign oprSize
                dst
                ((src >> y) .| (src << (numI32 32 oprSize .- y)))
    else (* OperandSize = 64 *)
      y := imm .& (numI32 0x3F oprSize)
      dstAssign oprSize
                dst
                ((src >> y) .| (src << (numI32 64 oprSize .- y)))
  }

let sahf (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let ah = regVar bld R.AH
    regVar bld R.CF := AST.xtlo 1<rt> ah
    regVar bld R.PF := AST.extract ah 1<rt> 2
    regVar bld R.AF := AST.extract ah 1<rt> 4
    regVar bld R.ZF := AST.extract ah 1<rt> 6
    regVar bld R.SF := AST.extract ah 1<rt> 7
#if EMULATION
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

#if !EMULATION
/// The pieces every shift needs before it can work out its flags: whether the
/// count is a constant, the count less one, the two conditions that gate the
/// flags -- a count of exactly one, and a count of zero -- and the two flags
/// that the shift's direction decides.
let private shiftFlagParts bld oprSize src cnt =
  let isCntConst = isConst src
  let n1 = AST.num1 oprSize
  let tCnt = if isCntConst then cnt .- n1 else tmpVar bld oprSize
  let cond1 = cnt == n1
  let cond2 = cnt == AST.num0 oprSize
  let oF = regVar bld R.OF
  struct (isCntConst, tCnt, n1, cond1, cond2, oF, regVar bld R.CF)
#endif

#if !EMULATION
/// Shifts left and sets the flags that direction decides: CF is the last bit
/// pushed off the top, and OF flips only where a single place was shifted.
let private shlAndSetFlags bld oprSize dst tDst cnt parts =
  let struct (isCntConst, tCnt, n1, cond1, cond2, oF, cF) = parts
  append bld {
    dstAssign oprSize dst (tDst << cnt)
    if isCntConst then () else tCnt := cnt .- n1
    cF := AST.ite cond2 cF (AST.xthi 1<rt> (tDst << tCnt))
    oF := AST.ite cond1 (AST.xthi 1<rt> dst <+> cF) (AST.ite cond2 oF undefOF)
  }
#endif

#if !EMULATION
/// Shifts right and sets the flags that direction decides: CF is the last bit
/// pushed off the bottom, and OF is the old sign where a single place was
/// shifted.
let private shrAndSetFlags bld oprSize dst tDst cnt parts =
  let struct (isCntConst, tCnt, n1, cond1, cond2, oF, cF) = parts
  append bld {
    dstAssign oprSize dst (tDst >> cnt)
    if isCntConst then () else tCnt := cnt .- n1
    cF := AST.ite cond2 cF (AST.xtlo 1<rt> (tDst >> tCnt))
    oF := AST.ite cond1 (AST.xthi 1<rt> tDst) (AST.ite cond2 oF undefOF)
  }
#endif

#if !EMULATION
/// Shifts right arithmetically and sets the flags that direction decides: the
/// sign is kept, so OF is clear wherever the count answers for it at all.
let private sarAndSetFlags bld oprSize dst tDst cnt parts =
  let struct (isCntConst, tCnt, n1, cond1, cond2, oF, cF) = parts
  append bld {
    dstAssign oprSize dst (tDst ?>> cnt)
    if isCntConst then () else tCnt := cnt .- n1
    cF := AST.ite cond2 cF (AST.xtlo 1<rt> (tDst ?>> tCnt))
    oF := AST.ite cond1 AST.b0 (AST.ite cond2 oF undefOF)
  }
#endif

#if !EMULATION
/// Sets the flags a shift leaves behind that do not turn on its direction: a
/// count of zero leaves every one of them alone.
let private setShiftFlags bld oprSize dst cond2 sF zF =
  append bld {
    let aF = regVar bld R.AF
    aF := AST.ite cond2 aF undefAF
    sF := AST.ite cond2 sF (AST.xthi 1<rt> dst)
    buildPF bld dst oprSize (Some cond2)
    zF := AST.ite cond2 zF (dst == AST.num0 oprSize)
  }
#endif

#if EMULATION
/// Shifts left for the emulator and records the shift, so that the flags are
/// worked out only if something goes on to read them.
let private shlLazily bld oprSize dst cnt tDst =
  append bld {
    tDst := dst << cnt
    setCCOperands3 bld dst cnt tDst
    dstAssign oprSize dst tDst
    match oprSize with
    | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SHLB
    | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SHLW
    | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SHLD
    | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SHLQ
    | _ -> raise InvalidRegTypeException
  }
#endif

#if EMULATION
/// Shifts right for the emulator and records the shift, so that the flags are
/// worked out only if something goes on to read them.
let private shrLazily bld oprSize dst cnt tDst =
  append bld {
    tDst := dst >> cnt
    setCCOperands3 bld dst cnt tDst
    dstAssign oprSize dst tDst
    match oprSize with
    | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SHRB
    | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SHRW
    | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SHRD
    | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SHRQ
    | _ -> raise InvalidRegTypeException
  }
#endif

#if EMULATION
/// Shifts right arithmetically for the emulator and records the shift, so
/// that the flags are worked out only if something goes on to read them.
let private sarLazily bld oprSize dst cnt tDst =
  append bld {
    tDst := dst ?>> cnt
    setCCOperands3 bld dst cnt tDst
    dstAssign oprSize dst tDst
    match oprSize with
    | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SARB
    | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SARW
    | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SARD
    | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SARQ
    | _ -> raise InvalidRegTypeException
  }
#endif

let shift (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs bld true ins insLen
    let oprSize = getOperationSize ins
    let countMask =
      if is64REXW bld ins then numU32 0x3Fu oprSize else numU32 0x1Fu oprSize
    let cnt = (AST.zext oprSize src) .& countMask
    let tDst = tmpVar bld oprSize
#if !EMULATION
    let parts = shiftFlagParts bld oprSize src cnt
    let struct (_, _, _, _, cond2, _, _) = parts
    let sF = regVar bld R.SF
    let zF = regVar bld R.ZF
    tDst := dst
#endif
    match ins.Opcode with
    | Opcode.SHL ->
#if EMULATION
      shlLazily bld oprSize dst cnt tDst
#else
      shlAndSetFlags bld oprSize dst tDst cnt parts
#endif
    | Opcode.SHR ->
#if EMULATION
      shrLazily bld oprSize dst cnt tDst
#else
      shrAndSetFlags bld oprSize dst tDst cnt parts
#endif
    | Opcode.SAR ->
#if EMULATION
      sarLazily bld oprSize dst cnt tDst
#else
      sarAndSetFlags bld oprSize dst tDst cnt parts
#endif
    | _ ->
      raise InvalidOpcodeException
#if !EMULATION
    setShiftFlags bld oprSize dst cond2 sF zF
#endif
  }

let sbb (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs bld true ins insLen
    let oprSize = getOperationSize ins
    let struct (t1, t2, t3, t4) = tmpVars4 bld oprSize
    let cf = regVar bld R.CF
    let sf = AST.xthi 1<rt> t4
    t1 := dst
    t2 := AST.sext oprSize src
#if EMULATION
    t3 := t2 .+ AST.zext oprSize (getCFLazy bld)
#else
    t3 := t2 .+ AST.zext oprSize cf
#endif
    t4 := t1 .- t3
    dstAssign oprSize dst t4
    cf := (t1 .< t3) .| (t3 .< t2)
    regVar bld R.OF := ofOnSub t1 t2 t4
    enumASZPFlags bld t1 t2 t4 oprSize sf
#if EMULATION
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let private scasBody ins bld =
  append bld {
    let oprSize = getOperationSize ins
    let t = tmpVar bld oprSize
    let df = regVar bld R.DF
    let x = getRegOfSize bld oprSize grpEAX
    let di = regVar bld (if is64bit bld then R.RDI else R.EDI)
    let tSrc = tmpVar bld oprSize
    let amount = numI32 (RegType.toByteWidth oprSize) bld.RegType
    let sf = AST.xthi 1<rt> t
    tSrc := AST.loadLE oprSize di
    t := x .- tSrc
    enumEFLAGS bld x tSrc t oprSize (cfOnSub x tSrc) (ofOnSub x tSrc t) sf
    di := AST.ite df (di .- amount) (di .+ amount)
  }

let scas (ins: Instruction) insLen bld =
  let pref = ins.Prefixes
  let zfCond n = Some(regVar bld R.ZF == n)
  liftOpen bld ins insLen {
    if Prefix.hasREPZ pref then
      strRepeat ins insLen bld scasBody (zfCond AST.b0)
#if EMULATION
      bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
    elif Prefix.hasREPNZ pref then
      strRepeat ins insLen bld scasBody (zfCond AST.b1)
#if EMULATION
      bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
    else
      scasBody ins bld
#if EMULATION
      bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
      markEnd bld insLen
  }

let private getCondOfSet (ins: Instruction) bld =
  match ins.Opcode with
  | Opcode.SETO -> regVar bld R.OF
  | Opcode.SETNO -> regVar bld R.OF == AST.b0
  | Opcode.SETB -> regVar bld R.CF
  | Opcode.SETNB -> regVar bld R.CF == AST.b0
  | Opcode.SETZ -> regVar bld R.ZF
  | Opcode.SETNZ -> regVar bld R.ZF == AST.b0
  | Opcode.SETBE -> (regVar bld R.CF) .| (regVar bld R.ZF)
  | Opcode.SETA -> ((regVar bld R.CF) .| (regVar bld R.ZF)) == AST.b0
  | Opcode.SETS -> regVar bld R.SF
  | Opcode.SETNS -> regVar bld R.SF == AST.b0
  | Opcode.SETP -> regVar bld R.PF
  | Opcode.SETNP -> regVar bld R.PF == AST.b0
  | Opcode.SETL -> regVar bld R.SF != regVar bld R.OF
  | Opcode.SETNL -> regVar bld R.SF == regVar bld R.OF
  | Opcode.SETLE -> regVar bld R.ZF .|
                     (regVar bld R.SF != regVar bld R.OF)
  | Opcode.SETG -> (regVar bld R.ZF == AST.b0) .&
                     (regVar bld R.SF == regVar bld R.OF)
  | _ -> raise InvalidOpcodeException

#if EMULATION
let private getCondOfSetLazy (ins: Instruction) bld =
  match ins.Opcode with
  | Opcode.SETO -> getOFLazy bld
  | Opcode.SETNO -> getOFLazy bld |> AST.not
  | Opcode.SETB -> getCFLazy bld
  | Opcode.SETNB -> getCFLazy bld |> AST.not
  | Opcode.SETZ -> getZFLazy bld
  | Opcode.SETNZ -> getZFLazy bld |> AST.not
  | Opcode.SETBE -> (getCFLazy bld) .| (getZFLazy bld)
  | Opcode.SETA -> (getCFLazy bld .| getZFLazy bld) |> AST.not
  | Opcode.SETS -> getSFLazy bld
  | Opcode.SETNS -> getSFLazy bld |> AST.not
  | Opcode.SETP -> getPFLazy bld
  | Opcode.SETNP -> getPFLazy bld |> AST.not
  | Opcode.SETL -> getSFLazy bld != getOFLazy bld
  | Opcode.SETNL -> getSFLazy bld == getOFLazy bld
  | Opcode.SETLE -> (getZFLazy bld) .| (getSFLazy bld != getOFLazy bld)
  | Opcode.SETG -> (getZFLazy bld |> AST.not) .&
                   (getSFLazy bld == getOFLazy bld)
  | _ -> raise InvalidOpcodeException
#endif

let setcc (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let dst = transOneOpr bld ins insLen
    let oprSize = getOperationSize ins
#if EMULATION
    let cond = getCondOfSetLazy ins bld |> AST.zext oprSize
#else
    let cond = getCondOfSet ins bld |> AST.zext oprSize
#endif
    dstAssign oprSize dst cond
  }

/// The carry a double-precision shift leaves behind: the last bit shifted out
/// of the original destination, or the old carry where no place was shifted.
let private setShiftDblPrecCF bld org amount cond1 cond2 =
  let cF = regVar bld R.CF
  append bld {
#if !EMULATION
    let fallThrough = AST.ite cond2 undefCF (AST.xtlo 1<rt> (org >> amount))
    cF := AST.ite cond1 cF fallThrough
#else
    cF := AST.ite (cond1 .| cond2) cF (AST.xtlo 1<rt> (org >> amount))
#endif
  }

/// The overflow a double-precision shift leaves behind, which answers only
/// for the case where exactly one place was shifted.
let private setShiftDblPrecOF bld dst org conds =
  let cond1, cond2, cond3 = conds
  let oF = regVar bld R.OF
  let overflow = AST.xthi 1<rt> (org <+> dst)
  append bld {
#if !EMULATION
    let aF = regVar bld R.AF
    let fallThrough = AST.ite cond2 undefOF (AST.ite cond3 overflow undefOF)
    oF := AST.ite cond1 oF fallThrough
    aF := AST.ite cond1 aF undefAF
#else
    oF := AST.ite (cond1 .| cond2) oF (AST.ite cond3 overflow oF)
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

/// The sign and zero a double-precision shift leaves behind, which read off
/// the result unless no place was shifted at all.
let private setShiftDblPrecSZ bld oprSz dst cond1 cond2 =
  let sf = regVar bld R.SF
  let zf = regVar bld R.ZF
  append bld {
#if !EMULATION
    sf := AST.ite cond1 sf (AST.ite cond2 undefSF (AST.xthi 1<rt> dst))
    zf := AST.ite cond1 zf (AST.ite cond2 undefZF (dst == AST.num0 oprSz))
#else
    sf := AST.ite (cond1 .| cond2) sf (AST.xthi 1<rt> dst)
    zf := AST.ite (cond1 .| cond2) zf (dst == AST.num0 oprSz)
#endif
  }

/// The flags a double-precision shift leaves behind. CF is the last bit
/// shifted out of the original destination, OF flips only where a single
/// place was shifted, and SF, ZF and PF read off the result. `conds` carries
/// the three cases the count falls into: no places at all, which leaves
/// every flag alone; more places than the operand is wide, which leaves them
/// undefined; and exactly one place, which is the only one OF answers for.
let private setShiftDblPrecFlags bld oprSz dst org count size conds isShl =
  let cond1, cond2, _ = conds
  let amount = if isShl then size .- count else count .- AST.num1 oprSz
  setShiftDblPrecCF bld org amount cond1 cond2
  setShiftDblPrecOF bld dst org conds
  setShiftDblPrecSZ bld oprSz dst cond1 cond2
  buildPF bld dst oprSz (Some(cond1 .| cond2))

let shiftDblPrec (ins: Instruction) insLen bld fnDst fnSrc isShl =
  lift bld ins insLen {
    let oprSz = getOperationSize ins
    let exprOprSz = numI32 (int oprSz) oprSz
    let struct (dst, src, cnt) = transThreeOprs bld false ins insLen
    let struct (count, size, tDst, tSrc) = tmpVars4 bld oprSz
    let struct (cond1, cond2, cond3) = tmpVars3 bld 1<rt>
    let conds = cond1, cond2, cond3
    let org = tmpVar bld oprSz
    let wordBits = if REXPrefix.hasW ins.REXPrefix then 64 else 32
    let wordSize = numI32 wordBits oprSz
    count := (AST.zext oprSz cnt .% wordSize)
    size := exprOprSz
    cond1 := count == AST.num0 oprSz
    cond2 := count .> size
    cond3 := count == AST.num1 oprSz
    org := dst
    tDst := dst
    tSrc := src
    tDst := fnDst tDst count
    tSrc := fnSrc tSrc (size .- count)
#if !EMULATION
    let undefDEST = AST.undef oprSz "DEST is undefined."
    let fallThrough = AST.ite cond2 undefDEST (tDst .| tSrc)
    dstAssign oprSz dst (AST.ite cond1 org fallThrough)
#else
    dstAssign oprSz dst (AST.ite (cond1 .| cond2) org (tDst .| tSrc))
#endif
    setShiftDblPrecFlags bld oprSz dst org count size conds isShl
  }

let shld ins insLen bld = shiftDblPrec ins insLen bld (<<) (>>) true

let shrd ins insLen bld = shiftDblPrec ins insLen bld (>>) (<<) false

let private shiftWithoutFlags (ins: Instruction) insLen bld opFn =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs bld false ins insLen
    let oprSize = getOperationSize ins
    let countMask = if is64REXW bld ins then 0x3F else 0x1F // FIXME: CS.L = 1
    let count = src2 .& (numI32 countMask oprSize)
    dstAssign oprSize dst (opFn src1 count)
  }

let sarx ins insLen bld = shiftWithoutFlags ins insLen bld (?>>)

let shlx ins insLen bld = shiftWithoutFlags ins insLen bld (<<)

let shrx ins insLen bld = shiftWithoutFlags ins insLen bld (>>)

let setFlag (ins: Instruction) insLen bld flag =
  lift bld ins insLen {
    regVar bld flag := AST.b1
#if EMULATION
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let stc ins insLen bld = setFlag ins insLen bld R.CF

let std ins insLen bld = setFlag ins insLen bld R.DF

let sti ins insLen bld = setFlag ins insLen bld R.IF

let private stosBody ins bld =
  append bld {
    let oprSize = getOperationSize ins
    let df = regVar bld R.DF
    let di = regVar bld (if is64bit bld then R.RDI else R.EDI)
    let src = getRegOfSize bld oprSize grpEAX
    let amount = numI32 (RegType.toByteWidth oprSize) bld.RegType
    AST.loadLE oprSize di := src
    di := AST.ite df (di .- amount) (di .+ amount)
  }

let stos (ins: Instruction) insLen bld =
  liftOpen bld ins insLen {
    if Prefix.hasREPZ ins.Prefixes then
      strRepeat ins insLen bld stosBody None
    elif Prefix.hasREPNZ ins.Prefixes then
      Terminator.impossible ()
    else
      stosBody ins bld
      markEnd bld insLen
  }

let sub (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs bld true ins insLen
    let oprSize = getOperationSize ins
    atomicBeginIfLocked ins bld
#if !EMULATION
    let isSrcConst = isConst src
    let t1 = tmpVar bld oprSize
    let t2 = if isSrcConst then src else tmpVar bld oprSize
    let t3 = tmpVar bld oprSize
    t1 := dst
    if isSrcConst then () else t2 := src
    t3 := t1 .- t2
    dstAssign oprSize dst t3
    let sf = AST.xthi 1<rt> t3
    enumEFLAGS bld t1 t2 t3 oprSize (cfOnSub t1 t2) (ofOnSub t1 t2 t3) sf
#else
    let src =
      if isConst src then
        src
      else
        let t = tmpVar bld oprSize
        append bld { t := src }
        t
    dstAssign oprSize dst (dst .- src)
    setCCOperands2 bld src dst
    match oprSize with
    | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SUBB
    | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SUBW
    | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SUBD
    | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SUBQ
    | _ -> raise InvalidRegTypeException
#endif
    atomicEndIfLocked ins bld
  }

let test (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (src1, src2) = transTwoOprs bld false ins insLen
    let oprSize = getOperationSize ins
    let r = if src1 = src2 then src1 else src1 .& src2
#if EMULATION
    setCCDst bld r
    match oprSize with
    | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICB
    | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICW
    | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICD
    | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICQ
    | _ -> raise InvalidRegTypeException
#else
    let t = tmpVar bld oprSize
    t := r
    regVar bld R.SF := AST.xthi 1<rt> t
    regVar bld R.ZF := t == (AST.num0 oprSize)
    buildPF bld t oprSize None
    regVar bld R.CF := AST.b0
    regVar bld R.OF := AST.b0
    regVar bld R.AF := undefAF
#endif
  }

/// Narrows the source to the half it still has bits in, counting the halves
/// that went. Each step shifts away the top half of what is left: if anything
/// survives, that is where the set bits are, and the width shifted past is
/// added to the count. The widths run from half the operand down to four,
/// which is as far as halving goes before the nibble table below takes over.
let private narrowByHalves bld oprSize (t1, t2, res) z =
  append bld {
    let widths =
      match oprSize with
      | 16<rt> -> [ 8; 4 ]
      | 32<rt> -> [ 16; 8; 4 ]
      | 64<rt> -> [ 32; 16; 8; 4 ]
      | _ -> raise InvalidOperandSizeException
    for w in widths do
      t2 := t1 >> numI32 w oprSize
      t1 := AST.ite (t2 != z) t2 t1
      res := AST.ite (t2 != z) (res .+ numI32 w oprSize) res
  }

let tzcnt ins insLen bld =
  lift bld ins insLen {
    let oprSize = getOperationSize ins
    let struct (dst, src) = transTwoOprs bld true ins insLen
    let lblCnt = label bld "Count"
    let lblZero = label bld "Zero"
    let lblEnd = label bld "End"
    let z = AST.num0 oprSize
    let max = numI32 (RegType.toBitWidth oprSize) oprSize
    let struct (t1, t2, res) = tmpVars3 bld oprSize
    t1 := src
    AST.cjmp (t1 == z) (AST.jmpDest lblZero) (AST.jmpDest lblCnt)
    AST.lmark lblZero
    dstAssign oprSize dst max
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblCnt
    res := z
    t1 := t1 .& (t1 .* numI32 0xFFFFFFFF oprSize)
    narrowByHalves bld oprSize (t1, t2, res) z
    let v = (res .+ ((t1 >> numI32 1 oprSize) .- (t1 >> numI32 3 oprSize)))
    dstAssign oprSize dst v
    AST.lmark lblEnd
    regVar bld R.CF := dst == max
    regVar bld R.ZF := dst == z
#if !EMULATION
    regVar bld R.OF := undefOF
    regVar bld R.SF := undefSF
    regVar bld R.PF := undefPF
    regVar bld R.AF := undefAF
#else
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let wrfsbase (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let src = transOneOpr bld ins insLen
    regVar bld R.FSBase := AST.zext bld.RegType src
  }

let wrgsbase (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let src = transOneOpr bld ins insLen
    regVar bld R.GSBase := AST.zext bld.RegType src
  }

let wrpkru ins insLen bld =
  lift bld ins insLen {
    let oprSize = getOperationSize ins
    let ecxIsZero = regVar bld R.ECX == AST.num0 oprSize
    let edxIsZero = regVar bld R.EDX == AST.num0 oprSize
    _unless bld "Err" (ecxIsZero .& edxIsZero)
      (block {
        AST.sideEffect (Exception ProtectionFault) })
    regVar bld R.PKRU := regVar bld R.EAX
  }

let xadd (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs bld false ins insLen
    let orgDst = saveOprMem bld dst
    let oprSize = getOperationSize ins
    let struct (t1, t2, t3) = tmpVars3 bld oprSize
    atomicBeginIfLocked ins bld
    t1 := dst
    t2 := src
    t3 := t1 .+ t2
    dstAssign oprSize src dst
    dstAssign oprSize orgDst t3
#if EMULATION
    setCCOperands2 bld t2 t3
    match oprSize with
    | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.ADDB
    | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.ADDW
    | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.ADDD
    | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.ADDQ
    | _ -> raise InvalidRegTypeException
#else
    let struct (ofl, sf) = osfOnAdd t1 t2 t3 bld
    enumEFLAGS bld t1 t2 t3 oprSize (cfOnAdd t1 t3) ofl sf
#endif
    atomicEndIfLocked ins bld
  }

let xchg (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs bld false ins insLen
    let oprSize = getOperationSize ins
    if dst <> src then
      let t = tmpVar bld oprSize
      t := dst
      dstAssign oprSize dst src
      dstAssign oprSize src t
    else
      dstAssign oprSize dst src
  }

let xlatb ins insLen bld =
  lift bld ins insLen {
    let addressSize = getEffAddrSz ins
    let al = AST.zext addressSize (regVar bld R.AL)
    let bx = getRegOfSize bld addressSize grpEBX
    regVar bld R.AL := AST.loadLE 8<rt> (al .+ bx)
  }

let xor (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let oprSize = getOperationSize ins
    match ins.Operands with
    | TwoOperands(o1, o2) when o1 = o2 ->
      let dst = transOprToExpr bld false ins insLen o1
      let r = AST.num0 oprSize
      dstAssign oprSize dst r
#if EMULATION
      setCCDst bld r
      bld.ConditionCodeOp <- ConditionCodeOp.XORXX
#else
      regVar bld R.OF := AST.b0
      regVar bld R.CF := AST.b0
      regVar bld R.SF := AST.b0
      regVar bld R.ZF := AST.b1
      regVar bld R.PF := AST.b1
#endif
    | TwoOperands(o1, o2) ->
      let dst = transOprToExpr bld false ins insLen o1
      let src = transOprToExpr bld false ins insLen o2 |> transReg bld true
      dstAssign oprSize dst (dst <+> src)
#if EMULATION
      setCCDst bld dst
      match oprSize with
      | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICB
      | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICW
      | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICD
      | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICQ
      | _ -> raise InvalidRegTypeException
#else
      regVar bld R.OF := AST.b0
      regVar bld R.CF := AST.b0
      regVar bld R.SF := AST.xthi 1<rt> dst
      regVar bld R.ZF := dst == (AST.num0 oprSize)
      buildPF bld dst oprSize None
#endif
    | _ ->
      raise InvalidOperandException
#if !EMULATION
    regVar bld R.AF := undefAF
#endif
  }
