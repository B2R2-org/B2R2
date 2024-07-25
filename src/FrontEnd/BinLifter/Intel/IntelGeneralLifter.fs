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

module internal B2R2.FrontEnd.BinLifter.Intel.GeneralLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingOperators
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.FrontEnd.BinLifter.Intel.RegGroup
open B2R2.FrontEnd.BinLifter.Intel.Helper
open B2R2.FrontEnd.BinLifter.Intel.LiftingUtils

#if !EMULATION
let private undefCF = AST.undef 1<rt> "CF is undefined."

let private undefOF = AST.undef 1<rt> "OF is undefined."

let private undefAF = AST.undef 1<rt> "AF is undefined."

let private undefSF = AST.undef 1<rt> "SF is undefined."

let private undefZF = AST.undef 1<rt> "ZF is undefined."

let private undefPF = AST.undef 1<rt> "PF is undefined."
#endif

let private getInstrPtr ctxt =
  !.ctxt (if is64bit ctxt then R.RIP else R.EIP)

let private getStackPtr ctxt =
  !.ctxt (if is64bit ctxt then R.RSP else R.ESP)

let private getBasePtr ctxt =
  !.ctxt (if is64bit ctxt then R.RBP else R.EBP)

let private getRegOfSize ctxt oprSize regGrp =
  regGrp oprSize |> !.ctxt

let inline private getStackWidth wordSize oprSize =
  numI32 (RegType.toByteWidth oprSize) wordSize

/// Push the given expression to the stack, assuming that the expression does
/// not include stack pointer.
let private auxPush oprSize ctxt expr ir =
  let sp = getStackPtr ctxt
  !!ir (sp := sp .- (getStackWidth ctxt.WordBitSize oprSize))
  !!ir (AST.loadLE oprSize sp := expr)

let private computePopSize oprSize = function
  | Var (_, id, _) when isSegReg (Register.ofRegID id) -> 16<rt>
  | _ -> oprSize

let private auxPop oprSize ctxt dst ir =
  let sp = getStackPtr ctxt
  !!ir (dst := AST.loadLE (computePopSize oprSize dst.E) sp)
  !!ir (sp := sp .+ (getStackWidth ctxt.WordBitSize oprSize))

let private maskOffset offset oprSize =
  let offset = AST.zext oprSize offset
  match oprSize with
  | 16<rt> -> offset .& numU32 0xFu 16<rt>
  | 32<rt> -> offset .& numU32 0x1Fu 32<rt>
  | 64<rt> -> offset .& numU32 0x3Fu 64<rt>
  | _ -> raise InvalidOperandSizeException

let rec private isVar = function
  | Var _ | TempVar _ -> true
  | Extract (e, _, _) -> isVar e.E
  | _ -> false

let private calculateOffset offset oprSize =
  match offset.E with
  | Num _ ->
    numU32 0u oprSize , maskOffset offset oprSize
  | _ ->
    let offset = AST.zext oprSize offset
    match oprSize with
    | 16<rt> -> numU32 2u 16<rt> .* (offset ./ numU32 16u 16<rt>),
                offset .& numU32 15u 16<rt>
    | 32<rt> -> numU32 4u 32<rt> .* (offset ./ numU32 32u 32<rt>),
                offset .& numU32 31u 32<rt>
    | 64<rt> -> numU32 4u 64<rt> .* (offset ./ numU32 32u 64<rt>),
                offset .& numU32 31u 64<rt>
    | _ -> raise InvalidOperandSizeException

let private strRepeat ins insLen ctxt body cond (ir: IRBuilder) =
  let lblExit = !%ir "Exit"
  let lblCont = !%ir "Continue"
  let lblNext = !%ir "Next"
  let n0 = AST.num0 (ctxt: TranslationContext).WordBitSize
  let cx = !.ctxt (if is64bit ctxt then R.RCX else R.ECX)
  let pc = getInstrPtr ctxt
  let ninstAddr = pc .+ numInsLen insLen ctxt
  !!ir (AST.cjmp (cx == n0) (AST.name lblExit) (AST.name lblCont))
  !!ir (AST.lmark lblCont)
  !?ir (body ins ctxt)
  !!ir (cx := cx .- AST.num1 ctxt.WordBitSize)
#if EMULATION
  !?ir (setCCOp ctxt)
  ctxt.ConditionCodeOp <- ConditionCodeOp.TraceStart
#endif
  match cond with
  | None -> !!ir (AST.interjmp pc InterJmpKind.Base)
  | Some cond ->
    !!ir (AST.cjmp (cx == n0) (AST.name lblExit) (AST.name lblNext))
    !!ir (AST.lmark lblNext)
    !!ir (AST.intercjmp cond ninstAddr pc)
  !!ir (AST.lmark lblExit)
  (* We consider each individual loop from a REP-prefixed instruction as an
     independent basic block, because it is more intuitive and matches with
     the definition of basic block from text books. *)
  !!ir (AST.interjmp ninstAddr InterJmpKind.Base)

let aaa insLen ctxt =
#if DEBUG
  assert32 ctxt
#endif
  let ir = !*ctxt
  let al = !.ctxt R.AL
  let af = !.ctxt R.AF
  let ax = !.ctxt R.AX
  let cf = !.ctxt R.CF
  let alAnd0f = al .& numI32 0x0f 8<rt>
  let cond1 = AST.gt alAnd0f (numI32 9 8<rt>)
  let cond = !+ir 1<rt>
  !<ir insLen
#if EMULATION
  !!ir (cond := cond1 .| ((getAFLazy ctxt ir) == AST.b1))
#else
  !!ir (cond := cond1 .| (af == AST.b1))
#endif
  !!ir (ax := AST.ite cond (ax .+ numI32 0x106 16<rt>) ax)
  !!ir (af := AST.ite cond AST.b1 AST.b0)
  !!ir (cf := AST.ite cond AST.b1 AST.b0)
  !!ir (al := alAnd0f)
#if !EMULATION
  !!ir (!.ctxt R.OF := undefOF)
  !!ir (!.ctxt R.SF := undefSF)
  !!ir (!.ctxt R.ZF := undefZF)
  !!ir (!.ctxt R.PF := undefPF)
#else
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let aad ins insLen ctxt =
#if DEBUG
  assert32 ctxt
#endif
  let ir = !*ctxt
  !<ir insLen
  let imm8 = transOneOpr ir ins insLen ctxt |> AST.xtlo 8<rt>
  let al = !.ctxt R.AL
  let ah = !.ctxt R.AH
  let sf = AST.xthi 1<rt> al
  !!ir (al := (al .+ (ah .* imm8)) .& (numI32 0xff 8<rt>))
  !!ir (ah := AST.num0 8<rt>)
  !?ir (enumSZPFlags ctxt al 8<rt> sf)
#if !EMULATION
  !!ir (!.ctxt R.OF := undefOF)
  !!ir (!.ctxt R.AF := undefAF)
  !!ir (!.ctxt R.CF := undefCF)
#else
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let aam ins insLen ctxt =
#if DEBUG
  assert32 ctxt
#endif
  let ir = !*ctxt
  !<ir insLen
  let imm8 = transOneOpr ir ins insLen ctxt |>  AST.xtlo 8<rt>
  let al = !.ctxt R.AL
  let ah = !.ctxt R.AH
  let sf = AST.xthi 1<rt> al
  !!ir (ah := al ./ imm8)
  !!ir (al := al .% imm8)
  !?ir (enumSZPFlags ctxt al 8<rt> sf)
#if !EMULATION
  !!ir (!.ctxt R.OF := undefOF)
  !!ir (!.ctxt R.AF := undefAF)
  !!ir (!.ctxt R.CF := undefCF)
#else
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let aas insLen ctxt =
#if DEBUG
  assert32 ctxt
#endif
  let ax = !.ctxt R.AX
  let al = !.ctxt R.AL
  let af = !.ctxt R.AF
  let cf = !.ctxt R.CF
  let ah = !.ctxt R.AH
  let alAnd0f = al .& numI32 0x0f 8<rt>
  let cond1 = AST.gt alAnd0f (numI32 9 8<rt>)
  let ir = !*ctxt
  let cond = !+ir 1<rt>
  !<ir insLen
#if EMULATION
  !!ir (cond := cond1 .| ((getAFLazy ctxt ir) == AST.b1))
#else
  !!ir (cond := cond1 .| (af == AST.b1))
#endif
  !!ir (ax := AST.ite cond (ax .- numI32 6 16<rt>) ax)
  !!ir (ah := AST.ite cond (ah .- AST.num1 8<rt>) ah)
  !!ir (af := AST.ite cond AST.b1 AST.b0)
  !!ir (cf := AST.ite cond AST.b1 AST.b0)
  !!ir (al := alAnd0f)
#if EMULATION
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let adc ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir true ins insLen ctxt
  let oprSize = getOperationSize ins
  let cf = !.ctxt R.CF
  let struct (t1, t2, t3, t4) = tmpVars4 ir oprSize
  !!ir (t1 := dst)
  !!ir (t2 := AST.sext oprSize src)
#if EMULATION
  !!ir (t3 := t2 .+ AST.zext oprSize (getCFLazy ctxt ir))
#else
  !!ir (t3 := t2 .+ AST.zext oprSize cf)
#endif
  !!ir (t4 := t1 .+ t3)
  !!ir (dstAssign oprSize dst t4)
  !!ir (cf := (t3 .< t2) .| (t4 .< t1))
  let struct (ofl, sf) = osfOnAdd t1 t2 t4 ir
  !!ir (!.ctxt R.OF := ofl)
  !?ir (enumASZPFlags ctxt t1 t2 t4 oprSize sf)
#if EMULATION
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let add ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  match ins.Operands with
  | TwoOperands (o1, o2) when o1 = o2 ->
    let dst = transOprToExpr ir false ins insLen ctxt o1
    if hasLock ins.Prefixes then !!ir (AST.sideEffect Lock) else ()
#if !EMULATION
    let struct (t1, t2) = tmpVars2 ir oprSize
    !!ir (t1 := dst)
    !!ir (t2 := t1 .+ t1)
    !!ir (dstAssign oprSize dst t2)
    let struct (ofl, sf) = osfOnAdd t1 t1 t2 ir
    !?ir (enumEFLAGS ctxt t1 t1 t2 oprSize (cfOnAdd t1 t2) ofl sf)
#else
    let t = !+ir oprSize
    !!ir (t := dst)
    !!ir (dstAssign oprSize dst (t .+ t))
    !?ir (setCCOperands2 ctxt t dst)
    match oprSize with
    | 8<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.ADDB
    | 16<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.ADDW
    | 32<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.ADDD
    | 64<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.ADDQ
    | _ -> raise InvalidRegTypeException
#endif
  | TwoOperands (o1, o2) ->
    let dst = transOprToExpr ir true ins insLen ctxt o1
    let src = transOprToExpr ir false ins insLen ctxt o2 |> transReg ir true
    if hasLock ins.Prefixes then !!ir (AST.sideEffect Lock) else ()
#if !EMULATION
    let isSrcConst = isConst src
    let t1 = !+ir oprSize
    let t2 = if isSrcConst then src else !+ir oprSize
    let t3 = !+ir oprSize
    !!ir (t1 := dst)
    if isSrcConst then () else !!ir (t2 := src)
    !!ir (t3 := t1 .+ t2)
    !!ir (dstAssign oprSize dst t3)
    let struct (ofl, sf) = osfOnAdd t1 t2 t3 ir
    !?ir (enumEFLAGS ctxt t1 t2 t3 oprSize (cfOnAdd t1 t3) ofl sf)
#else
    let src =
      if isConst src then src
      else
        let t = !+ir oprSize
        !!ir (t := src)
        t
    !!ir (dstAssign oprSize dst (dst .+ src))
    !?ir (setCCOperands2 ctxt src dst)
    match oprSize with
    | 8<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.ADDB
    | 16<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.ADDW
    | 32<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.ADDD
    | 64<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.ADDQ
    | _ -> raise InvalidRegTypeException
#endif
  | _ -> raise InvalidOperandException
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Unlock) else ()
  !>ir insLen

let adox ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir true ins insLen ctxt
  let oprSize = getOperationSize ins
#if EMULATION
  let oF = getOFLazy ctxt ir
#else
  let oF = !.ctxt R.OF
#endif
  match oprSize with
  | 32<rt> ->
    let struct (t1, t2, t3) = tmpVars3 ir 64<rt>
    !!ir (t1 := AST.zext 64<rt> dst)
    !!ir (t2 := AST.zext 64<rt> src)
    !!ir (t3 := t1 .+ t2 .+ AST.zext 64<rt> oF)
    !!ir (dstAssign oprSize dst (AST.xtlo oprSize t3))
    !!ir (oF := AST.extract t3 1<rt> 32)
  | 64<rt> ->
    let struct (t1a, t2a, t3a) = tmpVars3 ir 64<rt>
    let struct (t1b, t2b, t3b) = tmpVars3 ir 64<rt>
    let mask = !+ir 64<rt>
    !!ir (mask := numU64 0xFFFFFFFFUL 64<rt>)
    !!ir (t1a := dst .& mask)
    !!ir (t1b := (dst >> (numI32 32 64<rt>)) .& mask)
    !!ir (t2a := src .& mask)
    !!ir (t2b := (src >> (numI32 32 64<rt>)) .& mask)
    !!ir (t3a := t1a .+ t2a .+ AST.zext 64<rt> oF)
    !!ir (t3b := t1b .+ t2b .+ (t3a >> (numI32 32 64<rt>)))
    !!ir (dstAssign oprSize dst (dst .+ src .+ (AST.zext 64<rt> oF)))
    !!ir (oF := AST.extract t3b 1<rt> 32)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let ``and`` ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir true ins insLen ctxt
  let oprSize = getOperationSize ins
  let t = !+ir oprSize
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Lock) else ()
  !!ir (dstAssign oprSize dst (dst .& AST.sext oprSize src))
#if EMULATION
  !?ir (setCCDst ctxt dst)
  match oprSize with
  | 8<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.LOGICB
  | 16<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.LOGICW
  | 32<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.LOGICD
  | 64<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.LOGICQ
  | _ -> raise InvalidRegTypeException
#else
  let sf = AST.xthi 1<rt> dst
  !!ir (!.ctxt R.OF := AST.b0)
  !!ir (!.ctxt R.CF := AST.b0)
  !?ir (enumSZPFlags ctxt dst oprSize sf)
  !!ir (!.ctxt R.AF := undefAF)
#endif
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Unlock) else ()
  !>ir insLen

let andn ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = transThreeOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let t = !+ir oprSize
  !!ir (t := (AST.not src1) .& src2)
  !!ir (dstAssign oprSize dst t)
  !!ir (!.ctxt R.SF := AST.extract dst 1<rt> (int oprSize - 1))
  !!ir (!.ctxt R.ZF := AST.eq dst (AST.num0 oprSize))
#if EMULATION
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let arpl ins insLen ctxt =
#if DEBUG
  assert32 ctxt
#endif
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
  let struct (t1, t2) = tmpVars2 ir 16<rt>
  let mask = numI32 0xfffc 16<rt>
  let zF = !.ctxt R.ZF
  !!ir (t1 := dst .& numI32 0x3 16<rt>)
  !!ir (t2 := src .& numI32 0x3 16<rt>)
  !!ir (dst := AST.ite (t1 .< t2) ((dst .& mask) .| t2) dst)
  !!ir (zF := t1 .< t2)
#if EMULATION
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let bextr ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let struct (dst, src1, src2) = transThreeOprs ir false ins insLen ctxt
  let zF = !.ctxt R.ZF
  let struct (tmp, mask, start, len) = tmpVars4 ir oprSize
  !!ir (start := AST.zext oprSize (AST.extract src2 8<rt> 0))
  !!ir (len := AST.zext oprSize (AST.extract src2 8<rt> 8))
  !!ir (mask := AST.not(numI32 0 oprSize) << len)
  !!ir (tmp := AST.zext oprSize src1)
  !!ir (tmp := (tmp >> start) .& AST.not(mask))
  !!ir (dstAssign oprSize dst tmp)
  !!ir (zF := (dst == AST.num0 oprSize))
#if !EMULATION
  !!ir (!.ctxt R.AF := undefAF)
  !!ir (!.ctxt R.SF := undefSF)
  !!ir (!.ctxt R.PF := undefPF)
#else
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let blsi ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
  let tmp = !+ir oprSize
  !!ir (tmp := AST.neg src .& src)
  !!ir (!.ctxt R.SF := AST.xthi 1<rt> tmp)
  !!ir (!.ctxt R.ZF := tmp == AST.num0 oprSize)
  !!ir (!.ctxt R.CF := src != AST.num0 oprSize)
  !!ir (dstAssign oprSize dst tmp)
#if !EMULATION
  !!ir (!.ctxt R.AF := undefAF)
  !!ir (!.ctxt R.PF := undefPF)
#else
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let private bndmov64 ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst1, dst2 = transOprToExpr128 ir false ins insLen ctxt dst
  let src1, src2 = transOprToExpr128 ir false ins insLen ctxt src
  !!ir (dst1 := src1)
  !!ir (dst2 := src2)
  !>ir insLen

let private bndmov32Aux ins insLen ctxt ir =
  let struct (dst, src) = getTwoOprs ins
  match dst, src with
  | OprReg _, OprMem _ ->
    let dst1, dst2 = transOprToExpr128 ir false ins insLen ctxt dst
    let src = transOprToExpr ir false ins insLen ctxt src
    !!ir (dst1 := AST.xthi 32<rt> src |> AST.zext 64<rt>)
    !!ir (dst2 := AST.xtlo 32<rt> src |> AST.zext 64<rt>)
  | OprMem _, OprReg _ ->
    let src1, src2 = transOprToExpr128 ir false ins insLen ctxt src
    let dst = transOprToExpr ir false ins insLen ctxt dst
    !!ir (dst := AST.concat (AST.xtlo 32<rt> src1) (AST.xtlo 32<rt> src2))
  | _ -> raise InvalidOperandException

let bndmov32 ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  bndmov32Aux ins insLen ctxt ir
  !>ir insLen

let bndmov ins insLen ctxt =
  if is64bit ctxt then bndmov64 ins insLen ctxt
  else bndmov32 ins insLen ctxt

let bsf ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let lblLoopCond = !%ir "LoopCond"
  let lblLE = !%ir "LoopEnd"
  let lblLoop = !%ir "Loop"
  let struct (dst, src) = transTwoOprs ir true ins insLen ctxt
  let oprSize = getOperationSize ins
  let cond = src == AST.num0 oprSize
  let zf = !.ctxt R.ZF
  let t = !+ir oprSize
#if EMULATION
  !?ir (genDynamicFlagsUpdate ctxt)
#endif
  !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (zf := AST.b1)
  !!ir (dst := AST.undef oprSize "DEST is undefined.")
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (zf := AST.b0)
  !!ir (t := AST.num0 oprSize)
  !!ir (AST.lmark lblLoopCond)
  !!ir (AST.cjmp ((AST.xtlo 1<rt> (src >> t)) == AST.b0)
                 (AST.name lblLoop) (AST.name lblLE))
  !!ir (AST.lmark lblLoop)
  !!ir (t := t .+ AST.num1 oprSize)
  !!ir (AST.jmp (AST.name lblLoopCond))
  !!ir (AST.lmark lblLE)
  !!ir (dstAssign oprSize dst t)
  !!ir (AST.lmark lblEnd)
#if !EMULATION
  !!ir (!.ctxt R.CF := undefCF)
  !!ir (!.ctxt R.OF := undefOF)
  !!ir (!.ctxt R.AF := undefAF)
  !!ir (!.ctxt R.SF := undefSF)
  !!ir (!.ctxt R.PF := undefPF)
#else
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let bsr ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let lblLoopCond = !%ir "LoopCond"
  let lblLE = !%ir "LoopEnd"
  let lblLoop = !%ir "Loop"
  let struct (dst, src) = transTwoOprs ir true ins insLen ctxt
  let oprSize = getOperationSize ins
  let cond = src == AST.num0 oprSize
  let zf = !.ctxt R.ZF
  let t = !+ir oprSize
#if EMULATION
  !?ir (genDynamicFlagsUpdate ctxt)
#endif
  !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (zf := AST.b1)
  !!ir (dst := AST.undef oprSize "DEST is undefined.")
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (zf := AST.b0)
  !!ir (t := numOprSize oprSize .- AST.num1 oprSize)
  !!ir (AST.lmark lblLoopCond)
  !!ir (AST.cjmp ((AST.xtlo 1<rt> (src >> t)) == AST.b0)
                 (AST.name lblLoop) (AST.name lblLE))
  !!ir (AST.lmark lblLoop)
  !!ir (t := t .- AST.num1 oprSize)
  !!ir (AST.jmp (AST.name lblLoopCond))
  !!ir (AST.lmark lblLE)
  !!ir (dstAssign oprSize dst t)
  !!ir (AST.lmark lblEnd)
#if !EMULATION
  !!ir (!.ctxt R.CF := undefCF)
  !!ir (!.ctxt R.OF := undefOF)
  !!ir (!.ctxt R.AF := undefAF)
  !!ir (!.ctxt R.SF := undefSF)
  !!ir (!.ctxt R.PF := undefPF)
#else
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let bswap ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let dst = transOneOpr ir ins insLen ctxt
  let oprSize = getOperationSize ins
  let cnt = RegType.toByteWidth oprSize |> int
  let t = !+ir oprSize
  let tmps = Array.init cnt (fun _ -> !+ir 8<rt>)
  !!ir (t := dst)
  for i in 0 .. cnt - 1 do
    !!ir (tmps[i] := AST.extract t 8<rt> (i * 8))
  done
  !!ir (dstAssign oprSize dst (AST.concatArr (Array.rev tmps)))
  !>ir insLen

let private bit ins bitBase bitOffset oprSize =
  match bitBase.E with
  | Load (e, t, expr) ->
    let effAddrSz = getEffAddrSz ins
    let addrOffset, bitOffset = calculateOffset bitOffset oprSize
    let addrOffset = AST.zext effAddrSz addrOffset
    AST.xtlo 1<rt> ((AST.load e t (expr .+ addrOffset)) >> bitOffset)
  | _ -> if isVar bitBase.E
         then AST.xtlo 1<rt> (bitBase >> maskOffset bitOffset oprSize)
         else raise InvalidExprException

let bt ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (bitBase, bitOffset) = transTwoOprs ir true ins insLen ctxt
  let oprSize = getOperationSize ins
#if EMULATION
  !!ir (!.ctxt R.ZF := getZFLazy ctxt ir)
#endif
  !!ir (!.ctxt R.CF := bit ins bitBase bitOffset oprSize)
#if !EMULATION
  !!ir (!.ctxt R.OF := undefOF)
  !!ir (!.ctxt R.SF := undefSF)
  !!ir (!.ctxt R.AF := undefAF)
  !!ir (!.ctxt R.PF := undefPF)
#else
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let private setBit ins bitBase bitOffset oprSize setValue =
  match bitBase.E with
  | Load (e, t, expr) ->
    let effAddrSz = getEffAddrSz ins
    let addrOffset, bitOffset = calculateOffset bitOffset oprSize
    let addrOffset = AST.zext effAddrSz addrOffset
    let mask = setValue << bitOffset
    let bit = (AST.zext oprSize AST.b1) << bitOffset
    let loadMem = AST.load e t (expr .+ addrOffset)
    loadMem := (loadMem .& (getMask oprSize .- bit)) .| mask
  | _ ->
    if isVar bitBase.E then
      let mask = setValue << maskOffset bitOffset oprSize
      let bit = (AST.zext oprSize AST.b1) << maskOffset bitOffset oprSize
      dstAssign oprSize bitBase ((bitBase .& (getMask oprSize .- bit)) .| mask)
    else
      raise InvalidExprException

let bitTest ins insLen ctxt setValue =
  let ir = !*ctxt
  !<ir insLen
  let struct (bitBase, bitOffset) = transTwoOprs ir true ins insLen ctxt
  let oprSize = getOperationSize ins
  let setValue = AST.zext oprSize setValue
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Lock) else ()
#if EMULATION
  !!ir (!.ctxt R.ZF := getZFLazy ctxt ir)
#endif
  !!ir (!.ctxt R.CF := bit ins bitBase bitOffset oprSize)
  !!ir (setBit ins bitBase bitOffset oprSize setValue)
#if !EMULATION
  !!ir (!.ctxt R.OF := undefOF)
  !!ir (!.ctxt R.SF := undefSF)
  !!ir (!.ctxt R.AF := undefAF)
  !!ir (!.ctxt R.PF := undefPF)
#else
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Unlock) else ()
  !>ir insLen

let btc ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (bitBase, bitOffset) = transTwoOprs ir true ins insLen ctxt
  let oprSize = getOperationSize ins
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Lock) else ()
#if !EMULATION
  let setValue = AST.zext oprSize (!.ctxt R.CF |> AST.not)
#else
  let setValue = AST.zext oprSize (getCFLazy ctxt ir |> AST.not)
  !!ir (!.ctxt R.ZF := getZFLazy ctxt ir)
#endif
  !!ir (!.ctxt R.CF := bit ins bitBase bitOffset oprSize)
  !!ir (setBit ins bitBase bitOffset oprSize setValue)
#if !EMULATION
  !!ir (!.ctxt R.OF := undefOF)
  !!ir (!.ctxt R.SF := undefSF)
  !!ir (!.ctxt R.AF := undefAF)
  !!ir (!.ctxt R.PF := undefPF)
#else
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Unlock) else ()
  !>ir insLen

let btr ins insLen ctxt =
  bitTest ins insLen ctxt AST.b0

let bts ins insLen ctxt =
  bitTest ins insLen ctxt AST.b1

let bzhi ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = transThreeOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let n = AST.xtlo 8<rt> src2
  let cond1 = n .< numI32 (RegType.toBitWidth oprSize) 8<rt>
  let cond2 = n .> numI32 ((RegType.toBitWidth oprSize) - 1) 8<rt>
  let tmp = AST.zext oprSize (numI32 (RegType.toBitWidth oprSize) 8<rt> .- n)
  let cf = !.ctxt R.CF
  !!ir (dstAssign oprSize dst (AST.ite cond1 ((src1 << tmp) >> tmp) src1))
  !!ir (cf := AST.ite cond2 AST.b1 AST.b0)
#if EMULATION
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let call ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let pc = numU64 (ins: InsInfo).Address ctxt.WordBitSize
  let oprSize = getOperationSize ins
#if EMULATION
  !?ir (setCCOp ctxt)
  ctxt.ConditionCodeOp <- ConditionCodeOp.TraceStart
#endif
  let struct (target, ispcrel) = transJumpTargetOpr ir false ins pc insLen ctxt
  if ispcrel || not (hasStackPtr ins) then
    !?ir (auxPush oprSize ctxt (pc .+ numInsLen insLen ctxt))
    !!ir (AST.interjmp target InterJmpKind.IsCall)
  else
    let t = !+ir oprSize (* Use tmpvar because the target can use RSP *)
    !!ir (t := target)
    !?ir (auxPush oprSize ctxt (pc .+ numInsLen insLen ctxt))
    !!ir (AST.interjmp t InterJmpKind.IsCall)
  !>ir insLen

let convBWQ ins insLen ctxt =
  let opr = !.ctxt (if is64bit ctxt then R.RAX else R.EAX)
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let src = AST.sext oprSize (AST.xtlo (oprSize / 2) opr)
  !!ir (dstAssign oprSize (AST.xtlo oprSize opr) src)
  !>ir insLen

let clearFlag insLen ctxt flagReg =
  let ir = !*ctxt
  !<ir insLen
  !!ir (!.ctxt flagReg := AST.b0)
#if EMULATION
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let cmc ins insLen ctxt =
  let cf = !.ctxt R.CF
  let ir = !*ctxt
  !<ir insLen
#if EMULATION
  !!ir (cf := AST.not (getCFLazy ctxt ir))
#else
  !!ir (cf := AST.not cf)
#endif
#if !EMULATION
  !!ir (!.ctxt R.OF := undefOF)
  !!ir (!.ctxt R.AF := undefAF)
  !!ir (!.ctxt R.SF := undefSF)
  !!ir (!.ctxt R.ZF := undefZF)
  !!ir (!.ctxt R.PF := undefPF)
#else
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let private getCondOfCMov (ins: IntelInternalInstruction) ctxt =
  match ins.Opcode with
  | Opcode.CMOVO -> !.ctxt R.OF
  | Opcode.CMOVNO -> !.ctxt R.OF == AST.b0
  | Opcode.CMOVB -> !.ctxt R.CF
  | Opcode.CMOVAE -> !.ctxt R.CF == AST.b0
  | Opcode.CMOVZ -> !.ctxt R.ZF
  | Opcode.CMOVNZ -> !.ctxt R.ZF == AST.b0
  | Opcode.CMOVBE -> (!.ctxt R.CF) .| (!.ctxt R.ZF)
  | Opcode.CMOVA -> ((!.ctxt R.CF) .| (!.ctxt R.ZF)) == AST.b0
  | Opcode.CMOVS -> !.ctxt R.SF
  | Opcode.CMOVNS -> !.ctxt R.SF == AST.b0
  | Opcode.CMOVP -> !.ctxt R.PF
  | Opcode.CMOVNP -> !.ctxt R.PF == AST.b0
  | Opcode.CMOVL -> !.ctxt R.SF != !.ctxt R.OF
  | Opcode.CMOVGE -> !.ctxt R.SF == !.ctxt R.OF
  | Opcode.CMOVLE -> !.ctxt R.ZF .|
                     (!.ctxt R.SF != !.ctxt R.OF)
  | Opcode.CMOVG -> !.ctxt R.ZF == AST.b0 .&
                    (!.ctxt R.SF == !.ctxt R.OF)
  | _ -> raise InvalidOpcodeException

#if EMULATION
let private getCondOfCMovLazy (ins: IntelInternalInstruction) ctxt ir =
  match ins.Opcode with
  | Opcode.CMOVO -> getOFLazy ctxt ir
  | Opcode.CMOVNO -> getOFLazy ctxt ir |> AST.not
  | Opcode.CMOVB -> getCFLazy ctxt ir
  | Opcode.CMOVAE -> getCFLazy ctxt ir |> AST.not
  | Opcode.CMOVZ -> getZFLazy ctxt ir
  | Opcode.CMOVNZ -> getZFLazy ctxt ir |> AST.not
  | Opcode.CMOVBE ->
    let ccOp = ctxt.ConditionCodeOp
    match ccOp with
    | ConditionCodeOp.SUBB
    | ConditionCodeOp.SUBW
    | ConditionCodeOp.SUBD
    | ConditionCodeOp.SUBQ ->
      let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
      let regType = RegType.fromByteWidth size
      let src2 = getCCSrc1 ctxt regType
      let src1 = getCCDst ctxt regType .+ src2
      src1 .<= src2
    | _ -> (getCFLazy ctxt ir) .| (getZFLazy ctxt ir)
  | Opcode.CMOVA -> (getCFLazy ctxt ir .| getZFLazy ctxt ir) |> AST.not
  | Opcode.CMOVS -> getSFLazy ctxt ir
  | Opcode.CMOVNS -> getSFLazy ctxt ir |> AST.not
  | Opcode.CMOVP -> getPFLazy ctxt ir
  | Opcode.CMOVNP -> getPFLazy ctxt ir |> AST.not
  | Opcode.CMOVL ->
    let ccOp = ctxt.ConditionCodeOp
    match ccOp with
    | ConditionCodeOp.SUBB
    | ConditionCodeOp.SUBW
    | ConditionCodeOp.SUBD
    | ConditionCodeOp.SUBQ ->
      let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
      let regType = RegType.fromByteWidth size
      let src2 = getCCSrc1 ctxt regType
      let src1 = getCCDst ctxt regType .+ src2
      src1 ?< src2
    | _ -> getOFLazy ctxt ir != getSFLazy ctxt ir
  | Opcode.CMOVGE -> getOFLazy ctxt ir == getSFLazy ctxt ir
  | Opcode.CMOVLE ->
    let ccOp = ctxt.ConditionCodeOp
    match ccOp with
    | ConditionCodeOp.SUBB
    | ConditionCodeOp.SUBW
    | ConditionCodeOp.SUBD
    | ConditionCodeOp.SUBQ ->
      let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
      let regType = RegType.fromByteWidth size
      let src2 = getCCSrc1 ctxt regType
      let src1 = getCCDst ctxt regType .+ src2
      src1 ?<= src2
    | _ -> (getOFLazy ctxt ir != getSFLazy ctxt ir) .| (getZFLazy ctxt ir)
  | Opcode.CMOVG ->
    (getOFLazy ctxt ir == getSFLazy ctxt ir) .& (getZFLazy ctxt ir |> AST.not)
  | _ -> raise InvalidOpcodeException
#endif

let cmovcc ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
#if EMULATION
  !!ir (dstAssign oprSize dst (AST.ite (getCondOfCMovLazy ins ctxt ir) src dst))
#else
  !!ir (dstAssign oprSize dst (AST.ite (getCondOfCMov ins ctxt) src dst))
#endif
  !>ir insLen

let cmp ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (src1, src2) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
#if EMULATION
  !?ir (setCCOperands2 ctxt src2 (src1 .- src2))
  match oprSize with
  | 8<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.SUBB
  | 16<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.SUBW
  | 32<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.SUBD
  | 64<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.SUBQ
  | _ -> raise InvalidRegTypeException
#else
  let isRhsConst = isConst src2
  let t1 = !+ir oprSize
  let t2 = if isRhsConst then AST.sext oprSize src2 else !+ir oprSize
  let t3 = !+ir oprSize
  !!ir (t1 := src1)
  if isRhsConst then () else !!ir (t2 := AST.sext oprSize src2)
  !!ir (t3 := t1 .- t2)
  let sf = AST.xthi 1<rt> t3
  !?ir (enumEFLAGS ctxt t1 t2 t3 oprSize (cfOnSub t1 t2) (ofOnSub t1 t2 t3) sf)
#endif
  !>ir insLen

let private cmpsBody ins ctxt ir =
  let oprSize = getOperationSize ins
  let df = !.ctxt R.DF
  let si = !.ctxt (if is64bit ctxt then R.RSI else R.ESI)
  let di = !.ctxt (if is64bit ctxt then R.RDI else R.EDI)
  let src1 = AST.loadLE oprSize si
  let src2 = AST.loadLE oprSize di
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  let amount = numI32 (RegType.toByteWidth oprSize) ctxt.WordBitSize
  let sf = AST.xthi 1<rt> t3
  !!ir (t1 := src1)
  !!ir (t2 := src2)
  !!ir (t3 := t1 .- t2)
  !!ir (si := AST.ite df (si .- amount) (si .+ amount))
  !!ir (di := AST.ite df (di .- amount) (di .+ amount))
  !?ir (enumEFLAGS ctxt t1 t2 t3 oprSize (cfOnSub t1 t2) (ofOnSub t1 t2 t3) sf)
#if EMULATION
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif

let cmps (ins: InsInfo) insLen ctxt =
  let pref = ins.Prefixes
  let zf = !.ctxt R.ZF
  let ir = !*ctxt
  !<ir insLen
  (if hasREPZ pref then
     strRepeat ins insLen ctxt cmpsBody (Some (zf == AST.b0)) ir
   elif hasREPNZ pref then
     strRepeat ins insLen ctxt cmpsBody (Some (zf)) ir
   else cmpsBody ins ctxt ir)
  !>ir insLen

let cmpxchg ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir true ins insLen ctxt
  let oprSize = getOperationSize ins
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Lock) else ()
  let t = !+ir oprSize
  let r = !+ir oprSize
  let acc = getRegOfSize ctxt oprSize grpEAX
  let tAcc = !+ir oprSize
  let cond = !+ir 1<rt>
  let lblEq = !%ir "Equal"
  let lblNeq = !%ir "NotEqual"
  let lblEnd = !%ir "End"
  !!ir (t := dst)
  !!ir (tAcc := acc)
  !!ir (r := tAcc .- t)
  !!ir (cond := tAcc == t)
  !!ir (AST.cjmp cond (AST.name lblEq) (AST.name lblNeq))
  !!ir (AST.lmark lblEq)
  !!ir (!.ctxt R.ZF := AST.b1)
  !!ir (dstAssign oprSize dst src)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblNeq)
  !!ir (!.ctxt R.ZF := AST.b0)
  !!ir (dstAssign oprSize acc t)
  !!ir (AST.lmark lblEnd)
  !!ir (!.ctxt R.OF := ofOnSub tAcc t r)
  !!ir (!.ctxt R.SF := AST.xthi 1<rt> r)
  !!ir (buildAF ctxt tAcc t r oprSize)
  !?ir (buildPF ctxt r oprSize None)
  !!ir (!.ctxt R.CF := cfOnSub tAcc t)
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Unlock) else ()
#if EMULATION
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let compareExchangeBytes ins insLen ctxt =
  let ir = !*ctxt
  let oprSize = getOperationSize ins
  let zf = !.ctxt R.ZF
  let cond = !+ir 1<rt>
  !<ir insLen
  match oprSize with
  | 64<rt> ->
    let dst = transOneOpr ir ins insLen ctxt
    let eax = !.ctxt R.EAX
    let ecx = !.ctxt R.ECX
    let edx = !.ctxt R.EDX
    let ebx = !.ctxt R.EBX
    let t = !+ir oprSize
    !!ir (t := dst)
    !!ir (cond := AST.concat edx eax == t)
    !!ir (zf := cond)
    !!ir (dstAssign 32<rt> eax (AST.ite cond eax (AST.xtlo 32<rt> t)))
    !!ir (dstAssign 32<rt> edx (AST.ite cond edx (AST.xthi 32<rt> t)))
    !!ir (dst := AST.ite cond (AST.concat ecx ebx) t)
  | 128<rt> ->
    let dstB, dstA =
      match ins.Operands with
      | OneOperand opr -> transOprToExpr128 ir false ins insLen ctxt opr
      | _ -> raise InvalidOperandException
    let rax = !.ctxt R.RAX
    let rcx = !.ctxt R.RCX
    let rdx = !.ctxt R.RDX
    let rbx = !.ctxt R.RBX
    !!ir (cond := (dstB == rdx) .& (dstA == rax))
    !!ir (zf := cond)
    !!ir (rax := AST.ite cond rax dstA)
    !!ir (rdx := AST.ite cond rdx dstB)
    !!ir (dstA := AST.ite cond rbx dstA)
    !!ir (dstB := AST.ite cond rcx dstB)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let convWDQ ins insLen (ctxt: TranslationContext) =
  let ir = !*ctxt
  let oprSize = getOperationSize ins
  !<ir insLen
  match oprSize, ctxt.WordBitSize with
  | 16<rt>, _ ->
    let t = !+ir 32<rt>
    let ax = !.ctxt R.AX
    let dx = !.ctxt R.DX
    !!ir (t := AST.sext 32<rt> ax)
    !!ir (dx := AST.xthi 16<rt> t)
    !!ir (ax := AST.xtlo 16<rt> t)
  | 32<rt>, _ ->
    let t = !+ir 64<rt>
    let eax = !.ctxt R.EAX
    let edx = !.ctxt R.EDX
    !!ir (t := AST.sext 64<rt> eax)
    !!ir (dstAssign oprSize edx (AST.xthi 32<rt> t))
    !!ir (eax := AST.xtlo 32<rt> t)
  | 64<rt>, 64<rt> ->
    let rdx = !.ctxt R.RDX
    let rax = !.ctxt R.RAX
    let cond = AST.extract rax 1<rt> 63
    !!ir (rdx := AST.ite cond (numI32 -1 64<rt>) (AST.num0 64<rt>))
  | _, _ -> raise InvalidOperandSizeException
  !>ir insLen

let daa insLen ctxt =
#if DEBUG
  assert32 ctxt
#endif
  let ir = !*ctxt
  let al = !.ctxt R.AL
  let cf = !.ctxt R.CF
  let af = !.ctxt R.AF
  let oldAl = !+ir 8<rt>
  let oldCf = !+ir 1<rt>
  let alAnd0f = al .& numI32 0x0f 8<rt>
  let subCond1 = AST.gt alAnd0f (numI32 9 8<rt>)
  let cond1 = !+ir 1<rt>
  let subCond3 = AST.gt oldAl (numI32 0x99 8<rt>)
  let subCond4 = oldCf == AST.b1
  let cond2 = !+ir 1<rt>
  let sf = AST.xthi 1<rt> al
  !<ir insLen
  !!ir (oldAl := al)
#if EMULATION
  !!ir (oldCf := getCFLazy ctxt ir)
#else
  !!ir (oldCf := cf)
#endif
  !!ir (cf := AST.b0)
#if EMULATION
  !!ir (cond1 := subCond1 .| ((getAFLazy ctxt ir) == AST.b1))
#else
  !!ir (cond1 := subCond1 .| (af == AST.b1))
#endif
  !!ir (al := AST.ite cond1 (al .+ numI32 6 8<rt>) al)
  !!ir (cf := AST.ite cond1 oldCf cf)
  !!ir (af := cond1)
  !!ir (cond2 := subCond3 .| subCond4)
  !!ir (al := AST.ite cond2 (al .+ numI32 0x60 8<rt>) al)
  !!ir (cf := cond2)
  !?ir (enumSZPFlags ctxt al 8<rt> sf)
#if !EMULATION
  !!ir (!.ctxt R.OF := undefOF)
#else
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let das insLen ctxt =
#if DEBUG
  assert32 ctxt
#endif
  let ir = !*ctxt
  let al = !.ctxt R.AL
  let cf = !.ctxt R.CF
  let af = !.ctxt R.AF
  let oldAl = !+ir 8<rt>
  let oldCf = !+ir 1<rt>
  let alAnd0f = al .& numI32 0x0f 8<rt>
  let subCond1 = AST.gt alAnd0f (numI32 9 8<rt>)
  let subCond2 = af == AST.b1
  let cond1 = !+ir 1<rt>
  let subCond3 = AST.gt oldAl (numI32 0x99 8<rt>)
  let subCond4 = oldCf == AST.b1
  let cond2 = !+ir 1<rt>
  let sf = AST.xthi 1<rt> al
  !<ir insLen
  !!ir (oldAl := al)
#if EMULATION
  !!ir (oldCf := getCFLazy ctxt ir)
#else
  !!ir (oldCf := cf)
#endif
  !!ir (cf := AST.b0)
#if EMULATION
  !!ir (cond1 := subCond1 .| ((getAFLazy ctxt ir) == AST.b1))
#else
  !!ir (cond1 := subCond1 .| (af == AST.b1))
#endif
  !!ir (al := AST.ite cond1 (al .- numI32 6 8<rt>) al)
  !!ir (cf := AST.ite cond1 oldCf cf)
  !!ir (af := cond1)
  !!ir (cond2 := subCond3 .| subCond4)
  !!ir (al := AST.ite cond2 (al .- numI32 0x60 8<rt>) al)
  !!ir (cf := cond2)
  !?ir (enumSZPFlags ctxt al 8<rt> sf)
#if !EMULATION
  !!ir (!.ctxt R.OF := undefOF)
#else
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let dec ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let dst = transOneOpr ir ins insLen ctxt
  let oprSize = getOperationSize ins
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  let sf = AST.xthi 1<rt> t3
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Lock) else ()
  !!ir (t1 := dst)
  !!ir (t2 := AST.num1 oprSize)
  !!ir (t3 := (t1 .- t2))
  !!ir (dstAssign oprSize dst t3)
  !!ir (!.ctxt R.OF := ofOnSub t1 t2 t3)
  !?ir (enumASZPFlags ctxt t1 t2 t3 oprSize sf)
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Unlock) else ()
#if EMULATION
  !!ir (!.ctxt R.CF := getCFLazy ctxt ir)
  !?ir (setCCOperands2 ctxt t2 t3)
  match oprSize with
  | 8<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.DECB
  | 16<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.DECW
  | 32<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.DECD
  | 64<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.DECQ
  | _ -> raise InvalidRegTypeException
#endif
  !>ir insLen

let private mul64Bit src1 src2 ir =
  let struct (hiSrc1, loSrc1, hiSrc2, loSrc2) = tmpVars4 ir 64<rt>
  let struct (tSrc1, tSrc2) = tmpVars2 ir 64<rt>
  let struct (tHigh, tLow) = tmpVars2 ir 64<rt>
  let struct (pMid, pLow) = tmpVars2 ir 64<rt>
  let struct (hi1Lo2, lo1Hi2) = tmpVars2 ir 64<rt>
  let n32 = numI32 32 64<rt>
  let mask = numI64 0xFFFFFFFFL 64<rt>
  !!ir (tSrc1 := src1)
  !!ir (tSrc2 := src2)
  !!ir (hiSrc1 := (tSrc1 >> n32) .& mask) (* SRC1[63:32] *)
  !!ir (loSrc1 := tSrc1 .& mask) (* SRC1[31:0] *)
  !!ir (hiSrc2 := (tSrc2 >> n32) .& mask) (* SRC2[63:32] *)
  !!ir (loSrc2 := tSrc2 .& mask) (* SRC2[31:0] *)
  let pHigh = hiSrc1 .* hiSrc2
  !!ir (hi1Lo2 := hiSrc1 .* loSrc2)
  !!ir (lo1Hi2 := loSrc1 .* hiSrc2)
  !!ir (pMid := hi1Lo2 .+ lo1Hi2)
  !!ir (pLow := loSrc1 .* loSrc2)
  let high = pHigh .+ ((pMid .+ (pLow  >> n32)) >> n32)
  let low = pLow .+ ((pMid .& mask) << n32)
  let isOverflow = hi1Lo2 .> numI64 0xffffffff_ffffffffL 64<rt> .- lo1Hi2
  !!ir (tHigh :=
    high .+ AST.ite isOverflow (numI64 0x100000000L 64<rt>) (AST.num0 64<rt>))
  !!ir (tLow := low)
  struct (tHigh, tLow)

let private helperRemSub remHi remLo srcHi srcLo ir =
  let t = !+ir 1<rt>
  !!ir (t := remLo .< srcLo)
  !!ir (remLo := remLo .- srcLo)
  !!ir (remHi := remHi .- srcHi)
  !!ir (remHi := remHi .- AST.ite t (AST.num1 64<rt>) (AST.num0 64<rt>))

let helperRemAdd remHi remLo srcHi srcLo remMsb ir =
  let r = !+ir 64<rt>
  let t = !+ir 1<rt>
  let cond = r .< remLo
  !!ir (r := remLo .+ srcLo)
  !!ir (t := cond)
  !!ir (remLo := AST.ite remMsb r remLo)
  let toAdd = AST.ite t (AST.num1 64<rt>) (AST.num0 64<rt>)
  !!ir (remHi := AST.ite remMsb (remHi .+ srcHi .+ toAdd) remHi)

let divideWithoutConcat opcode oprSize divisor lblAssign lblErr ctxt ir =
  let struct (trdx, trax, tdivisor) = tmpVars3 ir oprSize
  let rdx, rax = !.ctxt R.RDX, !.ctxt R.RAX
  let struct (lz, y, t, nrmDvsr) = tmpVars4 ir oprSize
  let struct (remHi, remLo) = tmpVars2 ir oprSize
  let struct (qh, ql, q) = tmpVars3 ir oprSize
  let remMsb = !+ir 1<rt>
  let n32 = numI32 32 64<rt>
  let zero = AST.num0 64<rt>
  let one = AST.num1 64<rt>
  let numF = numI64 0xffffffff oprSize
  let struct (nrmDvsrShl32, nrmDvsrShr32) = tmpVars2 ir oprSize
  let condGE = (remHi >> n32) .>= nrmDvsrShr32
  let updateSign = !+ir 1<rt>
  let lblComputable = !%ir "Computable"
  let lblEasy = !%ir "Easy"
  let lblHard = !%ir "Hard"
  let isEasy = trdx == AST.num0 oprSize
  let errChk = AST.gt divisor trdx
  let quotient = !+ir oprSize
  let remainder = !+ir oprSize
  match opcode with
  | Opcode.DIV ->
    !!ir (trdx := rdx)
    !!ir (trax := rax)
    !!ir (tdivisor := divisor)
  | Opcode.IDIV ->
    let struct (dividendIsNeg, divisorIsNeg) = tmpVars2 ir 1<rt>
    !!ir (dividendIsNeg := (AST.xthi 1<rt> rdx == AST.b1))
    !!ir (divisorIsNeg := (AST.xthi 1<rt> divisor == AST.b1))
    !!ir (trdx := AST.ite dividendIsNeg (AST.not rdx) rdx)
    !!ir (trax := AST.ite dividendIsNeg (AST.not rax .+ numI32 1 oprSize) rax)
    let carry = AST.ite (AST.``and`` dividendIsNeg (AST.eq trax zero)) one zero
    !!ir (trdx := trdx .+ carry)
    !!ir (tdivisor := AST.ite divisorIsNeg (AST.neg divisor) divisor)
    !!ir (updateSign := dividendIsNeg <+> divisorIsNeg)
  | _ -> raise InvalidOpcodeException
  !!ir (AST.cjmp errChk (AST.name lblComputable) (AST.name lblErr))
  !!ir (AST.lmark lblComputable)
  !!ir (AST.cjmp isEasy (AST.name lblEasy) (AST.name lblHard))
  !!ir (AST.lmark lblEasy)
  !!ir (quotient := trax ./ tdivisor)
  !!ir (remainder := trax .% tdivisor)
  !!ir (AST.jmp (AST.name lblAssign))
  !!ir (AST.lmark lblHard)
  (* normalize divisor; adjust dividend
     accordingly (initial partial remainder) *)
  let z = !+ir 1<rt>
  !!ir (lz := (numI64 64L oprSize))
  !!ir (t := tdivisor)
  !!ir (y := (t >> (numI64 32 oprSize)))
  !!ir (z := y != zero)
  !!ir (lz := (AST.ite z (lz .- numI64 32 oprSize) lz))
  !!ir (t := (AST.ite z y t))
  !!ir (y := (t >> (numI64 16 oprSize)))
  !!ir (z := y != zero)
  !!ir (lz := (AST.ite z (lz .- numI64 16 oprSize) lz))
  !!ir (t := (AST.ite z y t))
  !!ir (y := (t >> (numI64 8 oprSize)))
  !!ir (z := y != zero)
  !!ir (lz := (AST.ite z (lz .- numI64 8 oprSize) lz))
  !!ir (t := (AST.ite z y t))
  !!ir (y := (t >> (numI64 4 oprSize)))
  !!ir (z := y != zero)
  !!ir (lz := (AST.ite z (lz .- numI64 4 oprSize) lz))
  !!ir (t := (AST.ite z y t))
  !!ir (y := (t >> (numI64 2 oprSize)))
  !!ir (z := y != zero)
  !!ir (lz := (AST.ite z (lz .- numI64 2 oprSize) lz))
  !!ir (t := (AST.ite z y t))
  !!ir (y := (t >> (numI64 1 oprSize)))
  !!ir (z := y != zero)
  !!ir (lz := (AST.ite z (lz .- numI64 2 oprSize) (lz .- t)))
  !!ir (nrmDvsr := tdivisor << lz)
  !!ir (nrmDvsrShl32 := nrmDvsr << n32)
  !!ir (nrmDvsrShr32 := nrmDvsr >> n32)
  !!ir (t := AST.ite (lz != zero) (trax >> ((numI64 64 oprSize) .- lz)) zero)
  !!ir (remHi := (trdx << lz) .| t)
  !!ir (remLo := trax << lz)
  !!ir (qh := AST.ite condGE numF (remHi ./ nrmDvsrShr32))
  (* compute remainder; correct quotient "digit" if remainder negative *)
  let struct (prodHi, prodLo) = mul64Bit (qh << n32) nrmDvsr ir
  helperRemSub remHi remLo prodHi prodLo ir
  !!ir (remMsb := (AST.xthi 1<rt> remHi))
  !!ir (qh := (AST.ite remMsb (qh .- one) (qh)))
  helperRemAdd remHi remLo nrmDvsrShr32 (nrmDvsrShl32) remMsb ir
  !!ir (remMsb := (AST.xthi 1<rt> remHi))
  !!ir (qh := (AST.ite remMsb (qh .- one) (qh)))
  helperRemAdd remHi remLo nrmDvsrShr32 (nrmDvsrShl32) remMsb ir
  !!ir (remHi := (remHi << n32) .| (remLo >> n32))
  !!ir (remLo := (remLo << n32))
  (* compute least significant quotient "digit";
     TAOCP: may be off by 0, +1, +2 *)
  !!ir (ql := AST.ite condGE numF (remHi ./ nrmDvsrShr32))
  !!ir (q := (qh << n32) .+ ql)
  (* compute remainder; correct quotient "digit" if remainder negative *)
  let struct (prodHi, prodLo) = mul64Bit q tdivisor ir
  !!ir (remLo := trax)
  !!ir (remHi := trdx)
  helperRemSub remHi remLo prodHi prodLo ir
  !!ir (remMsb := (AST.xthi 1<rt> remHi))
  !!ir (q := (AST.ite remMsb (q .- one) q))
  helperRemAdd remHi remLo zero tdivisor remMsb ir
  !!ir (remMsb := (AST.xthi 1<rt> remHi))
  !!ir (q := (AST.ite remMsb (q .- one) q))
  let struct (prodHi, prodLo) = mul64Bit q tdivisor ir
  helperRemSub trdx trax prodHi prodLo ir
  !!ir (quotient := q)
  !!ir (remainder := trax)
  !!ir (AST.lmark lblAssign)
  match opcode with
  | Opcode.DIV ->
    !!ir (dstAssign oprSize rax quotient)
    !!ir (dstAssign oprSize rdx remainder)
  | Opcode.IDIV ->
    let isDividendNeg = AST.xthi 1<rt> rdx == AST.b1
    !!ir (rax := (AST.ite updateSign (AST.neg quotient) quotient))
    !!ir (rdx := (AST.ite isDividendNeg (AST.neg remainder) remainder))
  | _ -> raise InvalidOpcodeException

let private getDividend ctxt = function
  | 8<rt> -> !.ctxt R.AX
  | 16<rt> -> AST.concat (!.ctxt R.DX) (!.ctxt R.AX)
  | 32<rt> -> AST.concat (!.ctxt R.EDX) (!.ctxt R.EAX)
  | _ -> raise InvalidOperandSizeException

let private checkQuotientDIV oprSize lblAssign lblErr q =
  AST.cjmp (AST.xthi oprSize q == AST.num0 oprSize)
           (AST.name lblAssign) (AST.name lblErr)

let private checkQuotientIDIV oprSize sz lblAssign lblErr q =
  let amount = numI32 (RegType.toBitWidth oprSize - 1) oprSize
  let mask = AST.num1 oprSize << amount
  let msb = AST.xthi 1<rt> q
  let negRes =  q .< (AST.zext sz mask)
  let posRes = q .> (AST.zext sz (mask .- (AST.num1 oprSize)))
  let cond = AST.ite (msb == AST.b1) negRes posRes
  AST.cjmp cond (AST.name lblErr) (AST.name lblAssign)

let divideWithConcat opcode oprSize divisor lblAssign lblErr ctxt ir =
  let dividend = getDividend ctxt oprSize
  let sz = TypeCheck.typeOf dividend
  let quotient = !+ir sz
  let remainder = !+ir sz
  match opcode with
  | Opcode.DIV ->
    let divisor = AST.zext sz divisor
    !!ir (quotient := dividend ./ divisor)
    !!ir (remainder := dividend .% divisor)
    !!ir (checkQuotientDIV oprSize lblAssign lblErr quotient)
  | Opcode.IDIV ->
    let divisor = AST.sext sz divisor
    !!ir (quotient := dividend ?/ divisor)
    !!ir (remainder := dividend ?% divisor)
    !!ir (checkQuotientIDIV oprSize sz lblAssign lblErr quotient)
  | _ -> raise InvalidOpcodeException
  !!ir (AST.lmark lblAssign)
  match oprSize with
  | 8<rt> ->
    !!ir (!.ctxt R.AL := AST.xtlo oprSize quotient)
    !!ir (!.ctxt R.AH := AST.xtlo oprSize remainder)
  | 16<rt> | 32<rt> ->
    let q = getRegOfSize ctxt oprSize grpEAX
    let r = getRegOfSize ctxt oprSize grpEDX
    !!ir (dstAssign oprSize q (AST.xtlo oprSize quotient))
    !!ir (dstAssign oprSize r (AST.xtlo oprSize remainder))
  | _ -> raise InvalidOperandSizeException

let div ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let lblAssign = !%ir "Assign"
  let lblChk = !%ir "Check"
  let lblErr = !%ir "DivErr"
  let divisor = transOneOpr ir ins insLen ctxt
  let oprSize = getOperationSize ins
  !!ir (AST.cjmp (divisor == AST.num0 oprSize)
                 (AST.name lblErr) (AST.name lblChk))
  !!ir (AST.lmark lblErr)
  !!ir (AST.sideEffect (Exception "DivErr"))
  !!ir (AST.lmark lblChk)
  match oprSize with
  | 64<rt> ->
    divideWithoutConcat ins.Opcode oprSize divisor lblAssign lblErr ctxt ir
  | _ ->
    divideWithConcat ins.Opcode oprSize divisor lblAssign lblErr ctxt ir
#if !EMULATION
  !!ir (!.ctxt R.CF := undefCF)
  !!ir (!.ctxt R.OF := undefOF)
  !!ir (!.ctxt R.AF := undefAF)
  !!ir (!.ctxt R.SF := undefSF)
  !!ir (!.ctxt R.ZF := undefZF)
  !!ir (!.ctxt R.PF := undefPF)
#else
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let enter ins insLen ctxt =
  let oSz = getOperationSize ins
  let ir = !*ctxt
  !<ir insLen
  let struct (imm16, imm8) = transTwoOprs ir false ins insLen ctxt
  let struct (allocSize, nestingLevel, cnt) = tmpVars3 ir oSz
  let struct (frameTemp, addrSize) = tmpVars2 ir ctxt.WordBitSize
  let bp = getBasePtr ctxt
  let sp = getStackPtr ctxt
  let lblLoop = !%ir "Loop"
  let lblCont = !%ir "Continue"
  let lblLevelCheck = !%ir "NestingLevelCheck"
  let lblLv1 = !%ir "NestingLevel1"
  let getAddrSize bitSize =
    if bitSize = 64<rt> then numI32 8 bitSize else numI32 4 bitSize
  !!ir (allocSize := imm16)
  !!ir (nestingLevel := imm8 .% (numI32 32 oSz))
  !?ir (auxPush ctxt.WordBitSize ctxt bp)
  !!ir (frameTemp := sp)
  !!ir (addrSize := getAddrSize ctxt.WordBitSize)
  if imm8 .% (numI32 32 oSz) = (numI32 0 oSz) then
    () (* IR Optimization: Do not add unnecessary IRs *)
  else
    !!ir (AST.cjmp (nestingLevel == AST.num0 oSz)
                   (AST.name lblCont) (AST.name lblLevelCheck))
    !!ir (AST.lmark lblLevelCheck)
    !!ir (cnt := nestingLevel .- AST.num1 oSz)
    !!ir (AST.cjmp (AST.gt nestingLevel (AST.num1 oSz))
                   (AST.name lblLoop) (AST.name lblLv1))
    !!ir (AST.lmark lblLoop)
    !!ir (bp := bp .- addrSize)
    !?ir (auxPush ctxt.WordBitSize ctxt (AST.loadLE ctxt.WordBitSize bp))
    !!ir (cnt := cnt .- AST.num1 oSz)
    !!ir (AST.cjmp (cnt == AST.num0 oSz) (AST.name lblCont) (AST.name lblLoop))
    !!ir (AST.lmark lblLv1)
    !?ir (auxPush ctxt.WordBitSize ctxt frameTemp)
    !!ir (AST.lmark lblCont)
  !!ir (bp := frameTemp)
  !!ir (sp := sp .- AST.zext ctxt.WordBitSize allocSize)
  !>ir insLen

let private imul64Bit src1 src2 ir =
  let struct (hiSrc1, loSrc1, hiSrc2, loSrc2) = tmpVars4 ir 64<rt>
  let struct (tSrc1, tSrc2) = tmpVars2 ir 64<rt>
  let struct (tHigh, tLow) = tmpVars2 ir 64<rt>
  let struct (pHigh, pMid, pLow) = tmpVars3 ir 64<rt>
  let struct (pMid1, pMid2) = tmpVars2 ir 64<rt>
  let struct (high, low) = tmpVars2 ir 64<rt>
  let n32 = numI32 32 64<rt>
  let zero = numI32 0 64<rt>
  let one = numI32 1 64<rt>
  let mask = numI64 0xFFFFFFFFL 64<rt>
  let struct (src1IsNeg, src2IsNeg, isSign) = tmpVars3 ir 1<rt>
  !!ir (src1IsNeg := AST.xthi 1<rt> src1)
  !!ir (src2IsNeg := AST.xthi 1<rt> src2)
  !!ir (tSrc1 := AST.ite src1IsNeg (AST.neg src1) src1)
  !!ir (tSrc2 := AST.ite src2IsNeg (AST.neg src2) src2)
  !!ir (hiSrc1 := (tSrc1 >> n32) .& mask) (* SRC1[63:32] *)
  !!ir (loSrc1 := tSrc1 .& mask) (* SRC1[31:0] *)
  !!ir (hiSrc2 := (tSrc2 >> n32) .& mask) (* SRC2[63:32] *)
  !!ir (loSrc2 := tSrc2 .& mask) (* SRC2[31:0] *)
  !!ir (pHigh := hiSrc1 .* hiSrc2)
  !!ir (pMid1 := hiSrc1 .* loSrc2)
  !!ir (pMid2 := loSrc1 .* hiSrc2)
  !!ir (pMid := pMid1 .+ pMid2)
  !!ir (pLow := loSrc1 .* loSrc2)
  let isOverflow =
    pMid1 .> numI64 0xffffffff_ffffffffL 64<rt> .- pMid2
  let c = AST.ite isOverflow (numI64 0x100000000L 64<rt>) (AST.num0 64<rt>)
  !!ir (high := pHigh .+ ((pMid .+ (pLow  >> n32)) >> n32) .+ c)
  !!ir (low := pLow .+ ((pMid .& mask) << n32))
  !!ir (isSign := src1IsNeg <+> src2IsNeg) // T11
  !!ir (tHigh := AST.ite isSign (AST.not high) high)
  !!ir (tLow := AST.ite isSign (AST.neg low) low)
  let carry = AST.ite (AST.``and`` isSign (AST.eq tLow zero)) one zero
  !!ir (tHigh := tHigh .+ carry)
  struct (tHigh, tLow)

let private oneOperandImul ctxt oprSize src ir =
  match oprSize with
  | 8<rt> ->
    let mulSize = oprSize * 2
    let t = !+ir mulSize
    let cond = AST.sext mulSize (AST.xtlo oprSize t) == t
    !!ir (t := AST.sext mulSize (!.ctxt R.AL) .* AST.sext mulSize src)
    !!ir (dstAssign oprSize (!.ctxt R.AX) t)
    !!ir (!.ctxt R.CF := cond == AST.b0)
    !!ir (!.ctxt R.OF := cond == AST.b0)
  | 16<rt> | 32<rt> ->
    let mulSize = oprSize * 2
    let t = !+ir mulSize
    let cond = AST.sext mulSize (AST.xtlo oprSize t) == t
    let r1 = getRegOfSize ctxt oprSize grpEDX
    let r2 = getRegOfSize ctxt oprSize grpEAX
    !!ir (t := AST.sext mulSize r2 .* AST.sext mulSize src)
    !!ir (dstAssign oprSize r1 (AST.xthi oprSize t))
    !!ir (dstAssign oprSize r2 (AST.xtlo oprSize t))
    !!ir (!.ctxt R.CF := cond == AST.b0)
    !!ir (!.ctxt R.OF := cond == AST.b0)
  | 64<rt> ->
    let r1 = getRegOfSize ctxt oprSize grpEDX
    let r2 = getRegOfSize ctxt oprSize grpEAX
    let struct (high, low) = imul64Bit r2 src ir
    !!ir (dstAssign oprSize r1 high)
    !!ir (dstAssign oprSize r2 low)
    let num0 = AST.num0 64<rt>
    let numF = numI64 0xFFFFFFFFFFFFFFFFL 64<rt>
    let cond = !+ir 1<rt>
    !!ir (cond := AST.ite (AST.xthi 1<rt> low) (high == numF) (high == num0))
    !!ir (!.ctxt R.CF := cond == AST.b0)
    !!ir (!.ctxt R.OF := cond == AST.b0)
  | _ -> raise InvalidOperandSizeException

let private operandsImul ctxt oprSize dst src1 src2 ir =
  match oprSize with
  | 8<rt> | 16<rt> | 32<rt> ->
    let doubleWidth = oprSize * 2
    let t = !+ir doubleWidth
    let cond = (AST.sext doubleWidth dst) != t
    !!ir (t := AST.sext doubleWidth src1 .* AST.sext doubleWidth src2)
    !!ir (dstAssign oprSize dst (AST.xtlo oprSize t))
    !!ir (!.ctxt R.CF := cond)
    !!ir (!.ctxt R.OF := cond)
  | 64<rt> ->
    let struct (high, low) = imul64Bit src1 src2 ir
    !!ir (dstAssign oprSize dst low)
    let num0 = AST.num0 64<rt>
    let numF = numI64 0xFFFFFFFFFFFFFFFFL 64<rt>
    let cond = !+ir 1<rt>
    !!ir (cond := AST.ite (AST.xthi 1<rt> low) (high != numF) (high != num0))
    !!ir (!.ctxt R.CF := cond)
    !!ir (!.ctxt R.OF := cond)
  | _ -> raise InvalidOperandSizeException

let private buildMulBody ins insLen ctxt ir =
  let oprSize = getOperationSize ins
  match ins.Operands with
  | OneOperand op ->
    let src = transOprToExpr ir false ins insLen ctxt op
    oneOperandImul ctxt oprSize src ir
  | TwoOperands (o1, o2) ->
    let dst = transOprToExpr ir false ins insLen ctxt o1
    let src = transOprToExpr ir false ins insLen ctxt o2
    operandsImul ctxt oprSize dst dst src ir
  | ThreeOperands (o1, o2, o3) ->
    let dst = transOprToExpr ir false ins insLen ctxt o1
    let src1 = transOprToExpr ir false ins insLen ctxt o2
    let src2 = transOprToExpr ir false ins insLen ctxt o3
    operandsImul ctxt oprSize dst src1 src2 ir
  | _ -> raise InvalidOperandException

let imul ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  !?ir (buildMulBody ins insLen ctxt)
#if !EMULATION
  !!ir (!.ctxt R.SF := undefSF)
  !!ir (!.ctxt R.ZF := undefZF)
  !!ir (!.ctxt R.AF := undefAF)
  !!ir (!.ctxt R.PF := undefPF)
#else
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let inc ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let dst = transOneOpr ir ins insLen ctxt
  let oprSize = getOperationSize ins
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Lock) else ()
  !!ir (t1 := dst)
  !!ir (t2 := AST.num1 oprSize)
  !!ir (t3 := (t1 .+ t2))
  !!ir (dstAssign oprSize dst t3)
  let struct (ofl, sf) = osfOnAdd t1 t2 t3 ir
  !!ir (!.ctxt R.OF := ofl)
  !?ir (enumASZPFlags ctxt t1 t2 t3 oprSize sf)
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Unlock) else ()
#if EMULATION
  !!ir (!.ctxt R.CF := getCFLazy ctxt ir)
  !?ir (setCCOperands2 ctxt t1 t3)
  match oprSize with
  | 8<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.INCB
  | 16<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.INCW
  | 32<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.INCD
  | 64<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.INCQ
  | _ -> raise InvalidRegTypeException
#endif
  !>ir insLen

let private insBody ins ctxt ir =
  let oprSize = getOperationSize ins
  let df = !.ctxt R.DF
  let di = !.ctxt (if is64bit ctxt then R.RDI else R.EDI)
  let src = AST.zext ctxt.WordBitSize (!.ctxt R.DX)
  let amount = numI32 (RegType.toByteWidth oprSize) ctxt.WordBitSize
  !!ir (AST.loadLE ctxt.WordBitSize di := src)
  !!ir (di := AST.ite df (di .- amount) (di .+ amount))

let insinstr (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  if hasREPZ ins.Prefixes then
    strRepeat ins insLen ctxt insBody None ir
  elif hasREPNZ ins.Prefixes then Utils.impossible ()
  else insBody ins ctxt ir
  !>ir insLen

let interrupt ins insLen ctxt =
  let ir = !*ctxt
  match transOneOpr ir ins insLen ctxt with
  | { E = Num n } -> Interrupt (BitVector.ToInt32 n) |> sideEffects ctxt insLen
  | _ -> raise InvalidOperandException

let private getCondOfJcc (ins: IntelInternalInstruction)
                         (ctxt: TranslationContext) =
#if DEBUG
  if ctxt.WordBitSize = 64<rt> && (getOperationSize ins) = 16<rt> then
    Utils.impossible ()
  else ()
#endif
  match ins.Opcode with
  | Opcode.JO -> !.ctxt R.OF
  | Opcode.JNO -> !.ctxt R.OF == AST.b0
  | Opcode.JB -> !.ctxt R.CF
  | Opcode.JNB -> !.ctxt R.CF == AST.b0
  | Opcode.JZ -> !.ctxt R.ZF
  | Opcode.JNZ -> !.ctxt R.ZF == AST.b0
  | Opcode.JBE -> (!.ctxt R.CF) .| (!.ctxt R.ZF)
  | Opcode.JA -> ((!.ctxt R.CF) .| (!.ctxt R.ZF)) == AST.b0
  | Opcode.JS -> !.ctxt R.SF
  | Opcode.JNS -> !.ctxt R.SF == AST.b0
  | Opcode.JP -> !.ctxt R.PF
  | Opcode.JNP -> !.ctxt R.PF == AST.b0
  | Opcode.JL -> !.ctxt R.SF != !.ctxt R.OF
  | Opcode.JNL -> !.ctxt R.SF == !.ctxt R.OF
  | Opcode.JLE -> (!.ctxt R.ZF) .|
                  (!.ctxt R.SF != !.ctxt R.OF)
  | Opcode.JG -> (!.ctxt R.ZF == AST.b0) .&
                 (!.ctxt R.SF == !.ctxt R.OF)
  | Opcode.JCXZ -> (!.ctxt R.CX) == (AST.num0 ctxt.WordBitSize)
  | Opcode.JECXZ ->
    let sz = ctxt.WordBitSize
    (AST.cast CastKind.ZeroExt sz (!.ctxt R.ECX)) == (AST.num0 sz)
  | Opcode.JRCXZ -> (!.ctxt R.RCX) == (AST.num0 ctxt.WordBitSize)
  | _ -> raise InvalidOpcodeException

#if EMULATION
let private getCondOfJccLazy (ins: IntelInternalInstruction)
                             (ctxt: TranslationContext)
                             (ir: IRBuilder) =
#if DEBUG
  if ctxt.WordBitSize = 64<rt> && (getOperationSize ins) = 16<rt> then
    Utils.impossible ()
  else ()
#endif
  match ins.Opcode with
  | Opcode.JO -> getOFLazy ctxt ir
  | Opcode.JNO -> getOFLazy ctxt ir |> AST.not
  | Opcode.JB -> getCFLazy ctxt ir
  | Opcode.JNB -> getCFLazy ctxt ir |> AST.not
  | Opcode.JZ -> getZFLazy ctxt ir
  | Opcode.JNZ -> getZFLazy ctxt ir |> AST.not
  | Opcode.JBE ->
    let ccOp = ctxt.ConditionCodeOp
    match ccOp with
    | ConditionCodeOp.SUBB
    | ConditionCodeOp.SUBW
    | ConditionCodeOp.SUBD
    | ConditionCodeOp.SUBQ ->
      let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
      let regType = RegType.fromByteWidth size
      let src2 = getCCSrc1 ctxt regType
      let src1 = getCCDst ctxt regType .+ src2
      src1 .<= src2
    | _ -> (getCFLazy ctxt ir) .| (getZFLazy ctxt ir)
  | Opcode.JA -> (getCFLazy ctxt ir .| getZFLazy ctxt ir) |> AST.not
  | Opcode.JS -> getSFLazy ctxt ir
  | Opcode.JNS -> getSFLazy ctxt ir |> AST.not
  | Opcode.JP -> getPFLazy ctxt ir
  | Opcode.JNP -> getPFLazy ctxt ir |> AST.not
  | Opcode.JL ->
    let ccOp = ctxt.ConditionCodeOp
    match ccOp with
    | ConditionCodeOp.SUBB
    | ConditionCodeOp.SUBW
    | ConditionCodeOp.SUBD
    | ConditionCodeOp.SUBQ ->
      let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
      let regType = RegType.fromByteWidth size
      let src2 = getCCSrc1 ctxt regType
      let src1 = getCCDst ctxt regType .+ src2
      src1 ?< src2
    | _ -> getOFLazy ctxt ir != getSFLazy ctxt ir
  | Opcode.JNL -> getOFLazy ctxt ir == getSFLazy ctxt ir
  | Opcode.JLE ->
    let ccOp = ctxt.ConditionCodeOp
    match ccOp with
    | ConditionCodeOp.SUBB
    | ConditionCodeOp.SUBW
    | ConditionCodeOp.SUBD
    | ConditionCodeOp.SUBQ ->
      let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
      let regType = RegType.fromByteWidth size
      let src2 = getCCSrc1 ctxt regType
      let src1 = getCCDst ctxt regType .+ src2
      src1 ?<= src2
    | _ -> (getOFLazy ctxt ir != getSFLazy ctxt ir) .| (getZFLazy ctxt ir)
  | Opcode.JG ->
    (getOFLazy ctxt ir == getSFLazy ctxt ir) .& (getZFLazy ctxt ir |> AST.not)
  | Opcode.JCXZ -> !.ctxt R.CX == AST.num0 ctxt.WordBitSize
  | Opcode.JECXZ ->
    let sz = ctxt.WordBitSize
    (AST.cast CastKind.ZeroExt sz (!.ctxt R.ECX)) == (AST.num0 sz)
  | Opcode.JRCXZ -> (!.ctxt R.RCX) == (AST.num0 ctxt.WordBitSize)
  | _ -> raise InvalidOpcodeException
#endif

let jcc ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let pc = numU64 (ins: InsInfo).Address ctxt.WordBitSize
  let jmpTarget = pc .+ transOneOpr ir ins insLen ctxt
#if EMULATION
  let cond = getCondOfJccLazy ins ctxt ir
  !?ir (setCCOp ctxt)
  ctxt.ConditionCodeOp <- ConditionCodeOp.TraceStart
#else
  let cond = getCondOfJcc ins ctxt
#endif
  let fallThrough = pc .+ numInsLen insLen ctxt
  !!ir (AST.intercjmp cond jmpTarget fallThrough)
  !>ir insLen

let jmp ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
#if EMULATION
  !?ir (setCCOp ctxt)
  ctxt.ConditionCodeOp <- ConditionCodeOp.TraceStart
#endif
  let pc = numU64 (ins: InsInfo).Address ctxt.WordBitSize
  let struct (target, _) = transJumpTargetOpr ir false ins pc insLen ctxt
  !!ir (AST.interjmp target InterJmpKind.Base)
  !>ir insLen

let private convertSrc = function
  | Load (_, _, expr) -> expr
  | _ -> Utils.impossible ()

let lahf _ insLen ctxt =
  let ir = !*ctxt
  let t = !+ir 8<rt>
  !<ir insLen
  let ah = !.ctxt R.AH
#if EMULATION
  let cf = getCFLazy ctxt ir
  let pf = getPFLazy ctxt ir
  let af = getAFLazy ctxt ir
  let zf = getZFLazy ctxt ir
  let sf = getSFLazy ctxt ir
#else
  let cf = AST.zext 8<rt> (!.ctxt R.CF)
  let pf = AST.zext 8<rt> (!.ctxt R.PF)
  let af = AST.zext 8<rt> (!.ctxt R.AF)
  let zf = AST.zext 8<rt> (!.ctxt R.ZF)
  let sf = AST.zext 8<rt> (!.ctxt R.SF)
#endif
  let cf = AST.zext 8<rt> (!.ctxt R.CF)
  let pf = AST.zext 8<rt> (!.ctxt R.PF)
  let af = AST.zext 8<rt> (!.ctxt R.AF)
  let zf = AST.zext 8<rt> (!.ctxt R.ZF)
  let sf = AST.zext 8<rt> (!.ctxt R.SF)
  !!ir (t := numI32 2 8<rt>)
  !!ir (t := t .| cf)
  !!ir (t := t .| (pf << numI32 2 8<rt>))
  !!ir (t := t .| (af << numI32 4 8<rt>))
  !!ir (t := t .| (zf << numI32 6 8<rt>))
  !!ir (t := t .| (sf << numI32 7 8<rt>))
  !!ir (ah := t)
  !>ir insLen

let lea ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let src = convertSrc src.E
  let addrSize = getEffAddrSz ins
  !!ir
    (match oprSize, addrSize with
     | 16<rt>, 16<rt> | 32<rt>, 32<rt> | 64<rt>, 64<rt> ->
       dstAssign oprSize dst src
     | 16<rt>, 32<rt> | 16<rt>, 64<rt> ->
       dstAssign oprSize dst (AST.xtlo 16<rt> src)
     | 32<rt>, 16<rt> -> dstAssign oprSize dst (AST.zext 32<rt> src)
     | 32<rt>, 64<rt> -> dstAssign oprSize dst (AST.xtlo 32<rt> src)
     | 64<rt>, 32<rt> -> dstAssign oprSize dst (AST.zext 64<rt> src)
     | _ -> raise InvalidOperandSizeException)
  !>ir insLen

let leave _ins insLen ctxt =
  let sp = getStackPtr ctxt
  let bp = getBasePtr ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (sp := bp)
  !?ir (auxPop ctxt.WordBitSize ctxt bp)
  !>ir insLen

let private lodsBody ins ctxt ir =
  let oprSize = getOperationSize ins
  let df = !.ctxt R.DF
  let si = !.ctxt (if is64bit ctxt then R.RSI else R.ESI)
  let dst = getRegOfSize ctxt oprSize grpEAX
  let amount = numI32 (RegType.toByteWidth oprSize) ctxt.WordBitSize
  !!ir (dst := AST.loadLE oprSize si)
  !!ir (si := AST.ite df (si .- amount) (si .+ amount))

let lods (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  if hasREPZ ins.Prefixes then
    strRepeat ins insLen ctxt lodsBody None ir
  elif hasREPNZ ins.Prefixes then Utils.impossible ()
  else lodsBody ins ctxt ir
  !>ir insLen

let loop ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let dst = transOneOpr ir ins insLen ctxt
  let addrSize = getEffAddrSz ins
  let pc = getInstrPtr ctxt
  let count, cntSize =
    if addrSize = 32<rt> then !.ctxt R.ECX, 32<rt>
    elif addrSize = 64<rt> then !.ctxt R.RCX, 64<rt>
    else !.ctxt R.CX, 16<rt>
#if EMULATION
  let zf = getZFLazy ctxt ir
#else
  let zf = !.ctxt R.ZF
#endif
  !!ir (count := count .- AST.num1 cntSize)
  let branchCond =
    match ins.Opcode with
    | Opcode.LOOP -> count != AST.num0 cntSize
    | Opcode.LOOPE -> (zf == AST.b1) .& (count != AST.num0 cntSize)
    | Opcode.LOOPNE -> (zf == AST.b0) .& (count != AST.num0 cntSize)
    | _ -> raise InvalidOpcodeException
  let fallThrough = pc .+ numInsLen insLen ctxt
  let jumpTarget = if addrSize = 16<rt> then pc .& numI32 0xFFFF 32<rt>
                   else pc .+ AST.sext ctxt.WordBitSize dst
  !!ir (AST.intercjmp branchCond jumpTarget fallThrough)
  !>ir insLen

let lzcnt ins insLen ctxt =
  let ir = !*ctxt
  let oprSize = getOperationSize ins
  let struct (dst, src) = transTwoOprs ir true ins insLen ctxt
  !<ir insLen
  let x = !+ir oprSize
  let n = AST.num0 oprSize
  match oprSize with
  | 16<rt> ->
    let mask1 = numI32 0x5555 16<rt>
    let mask2 = numI32 0x3333 16<rt>
    let mask3 = numI32 0x0f0f 16<rt>
    !!ir (x := src)
    !!ir (x := x .| (x >> numI32 1 16<rt>))
    !!ir (x := x .| (x >> numI32 2 16<rt>))
    !!ir (x := x .| (x >> numI32 4 16<rt>))
    !!ir (x := x .| (x >> numI32 8 16<rt>))
    !!ir (x := x .- ((x >> numI32 1 16<rt>) .& mask1))
    !!ir (x := ((x >> numI32 2 16<rt>) .& mask2) .+ (x .& mask2))
    !!ir (x := ((x >> numI32 4 16<rt>) .+ x) .& mask3)
    !!ir (x := x .+ (x >> numI32 8 16<rt>))
    !!ir (dstAssign oprSize dst (numI32 16 16<rt> .- (x .& numI32 31 16<rt>)))
  | 32<rt> ->
    let mask1 = numI32 0x55555555 32<rt>
    let mask2 = numI32 0x33333333 32<rt>
    let mask3 = numI32 0x0f0f0f0f 32<rt>
    !!ir (x := src)
    !!ir (x := x .| (x >> numI32 1 32<rt>))
    !!ir (x := x .| (x >> numI32 2 32<rt>))
    !!ir (x := x .| (x >> numI32 4 32<rt>))
    !!ir (x := x .| (x >> numI32 8 32<rt>))
    !!ir (x := x .| (x >> numI32 16 32<rt>))
    !!ir (x := x .- ((x >> numI32 1 32<rt>) .& mask1))
    !!ir (x := ((x >> numI32 2 32<rt>) .& mask2) .+ (x .& mask2))
    !!ir (x := ((x >> numI32 4 32<rt>) .+ x) .& mask3)
    !!ir (x := x .+ (x >> numI32 8 32<rt>))
    !!ir (x := x .+ (x >> numI32 16 32<rt>))
    !!ir (dstAssign oprSize dst (numI32 32 32<rt> .- (x .& numI32 63 32<rt>)))
  | 64<rt> ->
    let mask1 = numU64 0x5555555555555555UL 64<rt>
    let mask2 = numU64 0x3333333333333333UL 64<rt>
    let mask3 = numU64 0x0f0f0f0f0f0f0f0fUL 64<rt>
    !!ir (x := src)
    !!ir (x := x .| (x >> numI32 1 64<rt>))
    !!ir (x := x .| (x >> numI32 2 64<rt>))
    !!ir (x := x .| (x >> numI32 4 64<rt>))
    !!ir (x := x .| (x >> numI32 8 64<rt>))
    !!ir (x := x .| (x >> numI32 16 64<rt>))
    !!ir (x := x .| (x >> numI32 32 64<rt>))
    !!ir (x := x .- ((x >> numI32 1 64<rt>) .& mask1))
    !!ir (x := ((x >> numI32 2 64<rt>) .& mask2) .+ (x .& mask2))
    !!ir (x := ((x >> numI32 4 64<rt>) .+ x) .& mask3)
    !!ir (x := x .+ (x >> numI32 8 64<rt>))
    !!ir (x := x .+ (x >> numI32 16 64<rt>))
    !!ir (x := x .+ (x >> numI32 32 64<rt>))
    !!ir (dstAssign oprSize dst (numI32 64 64<rt> .- (x .& numI32 127 64<rt>)))
  | _ -> raise InvalidOperandSizeException
  let oprSize = numI32 (RegType.toBitWidth oprSize) oprSize
  !!ir (!.ctxt R.CF := dst == oprSize)
  !!ir (!.ctxt R.ZF := dst == n)
#if !EMULATION
  !!ir (!.ctxt R.OF := undefOF)
  !!ir (!.ctxt R.SF := undefSF)
  !!ir (!.ctxt R.PF := undefPF)
  !!ir (!.ctxt R.AF := undefAF)
#else
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let mov ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  !!ir (dstAssign oprSize dst (AST.zext oprSize src))
  !>ir insLen

let movbe ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let cnt = RegType.toByteWidth oprSize |> int
  let t = !+ir oprSize
  let tmps = Array.init cnt (fun _ -> !+ir 8<rt>)
  !!ir (t := src)
  for i in 0 .. cnt - 1 do
    !!ir (tmps[i] := AST.extract t 8<rt> (i * 8))
  done
  !!ir (dstAssign oprSize dst (AST.concatArr (Array.rev tmps)))
  !>ir insLen

let private movsBody ins ctxt ir =
  let oprSize = getOperationSize ins
  let df = !.ctxt R.DF
  let si = !.ctxt (if is64bit ctxt then R.RSI else R.ESI)
  let di = !.ctxt (if is64bit ctxt then R.RDI else R.EDI)
  let amount = numI32 (RegType.toByteWidth oprSize) ctxt.WordBitSize
  !!ir (AST.loadLE oprSize di := AST.loadLE oprSize si)
  !!ir (si := AST.ite df (si .- amount) (si .+ amount))
  !!ir (di := AST.ite df (di .- amount) (di .+ amount))

let movs (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  if hasREPZ ins.Prefixes then strRepeat ins insLen ctxt movsBody None ir
  else movsBody ins ctxt ir
  !>ir insLen

let movsx ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  !!ir (dstAssign oprSize dst (AST.sext oprSize src))
  !>ir insLen

let movzx ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  !!ir (dstAssign oprSize dst (AST.zext oprSize src))
  !>ir insLen

let mul ins insLen ctxt =
  let ir = !*ctxt
  let oprSize = getOperationSize ins
  !<ir insLen
  match oprSize with
  | 8<rt> ->
    let dblWidth = oprSize * 2
    let src1 = AST.zext dblWidth (getRegOfSize ctxt oprSize grpEAX)
    let src2 = AST.zext dblWidth (transOneOpr ir ins insLen ctxt)
    let t = !+ir dblWidth
    !!ir (t := src1 .* src2)
    let cond = !+ir 1<rt>
    !!ir (!.ctxt R.AX := t)
    !!ir (cond := AST.xthi oprSize t != (AST.num0 oprSize))
    !!ir (!.ctxt R.CF := cond)
    !!ir (!.ctxt R.OF := cond)
#if !EMULATION
    !!ir (!.ctxt R.SF := undefSF)
    !!ir (!.ctxt R.ZF := undefZF)
    !!ir (!.ctxt R.AF := undefAF)
    !!ir (!.ctxt R.PF := undefPF)
#else
    ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  | 16<rt> | 32<rt> ->
    let dblWidth = oprSize * 2
    let edx = getRegOfSize ctxt oprSize grpEDX
    let eax = getRegOfSize ctxt oprSize grpEAX
    let src1 = AST.zext dblWidth eax
    let src2 = AST.zext dblWidth (transOneOpr ir ins insLen ctxt)
    let t = !+ir dblWidth
    !!ir (t := src1 .* src2)
    let cond = !+ir 1<rt>
    !!ir (dstAssign oprSize edx (AST.xthi oprSize t))
    !!ir (dstAssign oprSize eax (AST.xtlo oprSize t))
    !!ir (cond := AST.xthi oprSize t != (AST.num0 oprSize))
    !!ir (!.ctxt R.CF := cond)
    !!ir (!.ctxt R.OF := cond)
#if !EMULATION
    !!ir (!.ctxt R.SF := undefSF)
    !!ir (!.ctxt R.ZF := undefZF)
    !!ir (!.ctxt R.AF := undefAF)
    !!ir (!.ctxt R.PF := undefPF)
#else
    ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  | 64<rt> ->
    let rax = getRegOfSize ctxt oprSize grpEAX
    let rdx = getRegOfSize ctxt oprSize grpEDX
    let src = transOneOpr ir ins insLen ctxt
    let struct (hiRAX, loRAX, hiSrc, loSrc) = tmpVars4 ir 64<rt>
    let struct (tHigh, tLow) = tmpVars2 ir 64<rt>
    let n32 = numI32 32 64<rt>
    let mask = numI64 0xFFFFFFFFL 64<rt>
    !!ir (hiRAX := (rax >> n32) .& mask) (* RAX[63:32] *)
    !!ir (loRAX := rax .& mask) (* RAX[31:0] *)
    !!ir (hiSrc := (src >> n32) .& mask) (* SRC[63:32] *)
    !!ir (loSrc := src .& mask) (* SRC[31:0] *)
    let pHigh = hiRAX .* hiSrc
    let pMid = (hiRAX .* loSrc) .+ (loRAX .* hiSrc)
    let pLow = (loRAX .* loSrc)
    let high = pHigh .+ ((pMid .+ (pLow  >> n32)) >> n32)
    let low = pLow .+ ((pMid .& mask) << n32)
    let isOverflow =
      hiRAX .* loSrc .> numI64 0xffffffff_ffffffffL 64<rt> .- loRAX .* hiSrc
    !!ir (tHigh :=
      high .+ AST.ite isOverflow (numI64 0x100000000L 64<rt>) (AST.num0 64<rt>))
    !!ir (tLow := low)
    !!ir (dstAssign oprSize rdx tHigh)
    !!ir (dstAssign oprSize rax tLow)
    let cond = !+ir 1<rt>
    !!ir (cond := tHigh != (AST.num0 oprSize))
    !!ir (!.ctxt R.CF := cond)
    !!ir (!.ctxt R.OF := cond)
#if !EMULATION
    !!ir (!.ctxt R.SF := undefSF)
    !!ir (!.ctxt R.ZF := undefZF)
    !!ir (!.ctxt R.AF := undefAF)
    !!ir (!.ctxt R.PF := undefPF)
#else
    ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let mulx ins insLen ctxt =
  let ir = !*ctxt
  let oprSize = getOperationSize ins
  !<ir insLen
  match oprSize with
  | 32<rt> ->
    let struct (dst1, dst2, src) = transThreeOprs ir false ins insLen ctxt
    let dblWidth = oprSize * 2
    let src1 = AST.zext dblWidth (getRegOfSize ctxt oprSize grpEDX)
    let src2 = AST.zext dblWidth src
    let t = !+ir dblWidth
    !!ir (t := src1 .* src2)
    !!ir (dstAssign oprSize dst2 (AST.xtlo 32<rt> t))
    !!ir (dstAssign oprSize dst1 (AST.xthi 32<rt> t))
  | 64<rt> ->
    let struct (dst1, dst2, src) = transThreeOprs ir false ins insLen ctxt
    let src1 = getRegOfSize ctxt oprSize grpEDX
    let struct (hiSrc1, loSrc1, hiSrc, loSrc) = tmpVars4 ir 64<rt>
    let struct (tHigh, tLow) = tmpVars2 ir 64<rt>
    let n32 = numI32 32 64<rt>
    let mask = numI64 0xFFFFFFFFL 64<rt>
    !!ir (hiSrc1 := (src1 >> n32) .& mask) (* SRC1[63:32] *)
    !!ir (loSrc1 := src1 .& mask) (* SRC1[31:0] *)
    !!ir (hiSrc := (src >> n32) .& mask) (* SRC[63:32] *)
    !!ir (loSrc := src .& mask) (* SRC[31:0] *)
    let pHigh = hiSrc1 .* hiSrc
    let pMid = (hiSrc1 .* loSrc) .+ (loSrc1 .* hiSrc)
    let pLow = (loSrc1 .* loSrc)
    let high = pHigh .+ ((pMid .+ (pLow  >> n32)) >> n32)
    let low = pLow .+ ((pMid .& mask) << n32)
    let isOverflow =
      hiSrc1 .* loSrc .> numI64 0xffffffff_ffffffffL 64<rt> .- loSrc1 .* hiSrc
    !!ir (tHigh :=
      high .+ AST.ite isOverflow (numI64 0x100000000L 64<rt>) (AST.num0 64<rt>))
    !!ir (tLow := low)
    !!ir (dstAssign oprSize dst2 tLow)
    !!ir (dstAssign oprSize dst1 tHigh)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let neg ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let dst = transOneOpr ir ins insLen ctxt
  let oprSize = getOperationSize ins
  let t = !+ir oprSize
  let zero = AST.num0 oprSize
  !!ir (t := dst)
  !!ir (dstAssign oprSize dst (AST.neg t))
#if EMULATION
  !?ir (setCCOperands2 ctxt t dst)
  match oprSize with
  | 8<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.SUBB
  | 16<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.SUBW
  | 32<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.SUBD
  | 64<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.SUBQ
  | _ -> raise InvalidRegTypeException
#else
  let sf = AST.xthi 1<rt> dst
  let cf = cfOnSub zero t
  let ofl = ofOnSub zero t dst
  !?ir (enumEFLAGS ctxt zero t dst oprSize cf ofl sf)
#endif
  !>ir insLen

let nop insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  !>ir insLen

let not ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let dst = transOneOpr ir ins insLen ctxt
  let oprSize = getOperationSize ins
  !!ir (dstAssign oprSize dst (AST.unop UnOpType.NOT dst))
  !>ir insLen

let logOr ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir true ins insLen ctxt
  let oprSize = getOperationSize ins
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Lock) else ()
  !!ir (dstAssign oprSize dst (dst .| src))
#if EMULATION
  !?ir (setCCDst ctxt dst)
  match oprSize with
  | 8<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.LOGICB
  | 16<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.LOGICW
  | 32<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.LOGICD
  | 64<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.LOGICQ
  | _ -> raise InvalidRegTypeException
#else
  let sf = AST.xthi 1<rt> dst
  !!ir (!.ctxt R.CF := AST.b0)
  !!ir (!.ctxt R.OF := AST.b0)
  !?ir (enumSZPFlags ctxt dst oprSize sf)
  !!ir (!.ctxt R.AF := undefAF)
#endif
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Unlock) else ()
  !>ir insLen

let private outsBody ins ctxt ir =
  let oprSize = getOperationSize ins
  let df = !.ctxt R.DF
  let si = !.ctxt (if is64bit ctxt then R.RSI else R.ESI)
  let src = !.ctxt R.DX
  let amount = numI32 (RegType.toByteWidth oprSize) ctxt.WordBitSize
  match oprSize with
  | 8<rt> ->
    !!ir (src := AST.zext 16<rt> (AST.loadLE oprSize si))
    !!ir (si := AST.ite df (si .- amount) (si .+ amount))
  | 16<rt> ->
    !!ir (src := AST.loadLE oprSize si)
    !!ir (si := AST.ite df (si .- amount) (si .+ amount))
  | 32<rt> ->
    !!ir (si := AST.ite df (si .- amount) (si .+ amount))
    !!ir (src := AST.xtlo 16<rt> (AST.loadLE oprSize si))
  | _ -> raise InvalidOperandSizeException

let outs (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  if hasREPZ ins.Prefixes then
    strRepeat ins insLen ctxt outsBody None ir
  elif hasREPNZ ins.Prefixes then Utils.impossible ()
  else outsBody ins ctxt ir
  !>ir insLen

let pdep ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = transThreeOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let struct (temp, mask, dest) = tmpVars3 ir oprSize
  let cond = !+ir 1<rt>
  let k = !+ir oprSize
  !!ir (temp := src1)
  !!ir (mask := src2)
  !!ir (dest := AST.num0 oprSize)
  !!ir (k := AST.num0 oprSize)
  for i in 0 .. (int oprSize) - 1 do
    !!ir (cond := AST.extract mask 1<rt> i)
    let tempk = (temp >> k) |> AST.xtlo 1<rt>
    !!ir (AST.extract dest 1<rt> i := AST.ite cond tempk AST.b0)
    !!ir (k := AST.ite cond (k .+ AST.num1 oprSize) k)
  done
  !!ir (dstAssign oprSize dst dest)
  !>ir insLen

let pext ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, mask) = transThreeOprs ir false ins insLen ctxt
  let oSz = getOperationSize ins
  let struct (t, k) = tmpVars2 ir oSz
  let cond = !+ir 1<rt>
  !!ir (t := AST.num0 oSz)
  !!ir (k := AST.num0 oSz)
  for i in 0 .. (int oSz) - 1 do
    !!ir (cond := AST.extract mask 1<rt> i)
    let extSrc = AST.zext oSz (AST.extract src 1<rt> i)
    !!ir (t := t .| (AST.ite cond (extSrc << k) t))
    !!ir (k := k .+ (AST.zext oSz cond))
  done
  !!ir (dstAssign oSz dst t)
  !>ir insLen

let pop ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let dst = transOneOpr ir ins insLen ctxt
  let oprSize = getOperationSize ins
  !?ir (auxPop oprSize ctxt dst)
  !>ir insLen

let popa insLen ctxt oprSize =
  let sp = !.ctxt R.ESP
  let di = if oprSize = 32<rt> then R.EDI else R.DI
  let si = if oprSize = 32<rt> then R.ESI else R.SI
  let bp = if oprSize = 32<rt> then R.EBP else R.BP
  let bx = if oprSize = 32<rt> then R.EBX else R.BX
  let dx = if oprSize = 32<rt> then R.EDX else R.DX
  let cx = if oprSize = 32<rt> then R.ECX else R.CX
  let ax = if oprSize = 32<rt> then R.EAX else R.AX
  let ir = !*ctxt
  !<ir insLen
  !?ir (auxPop oprSize ctxt (!.ctxt di))
  !?ir (auxPop oprSize ctxt (!.ctxt si))
  !?ir (auxPop oprSize ctxt (!.ctxt bp))
  !!ir (sp := sp .+ (numI32 (int oprSize / 8) 32<rt>))
  !?ir (auxPop oprSize ctxt (!.ctxt bx))
  !?ir (auxPop oprSize ctxt (!.ctxt dx))
  !?ir (auxPop oprSize ctxt (!.ctxt cx))
  !?ir (auxPop oprSize ctxt (!.ctxt ax))
  !>ir insLen

let popcnt ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let lblLoop = !%ir "Loop"
  let lblExit = !%ir "Exit"
  let lblLoopCond = !%ir "LoopCond"
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let max = numI32 (RegType.toBitWidth oprSize) oprSize
  let struct (i, count, orgSrc) = tmpVars3 ir oprSize
  !!ir (i := AST.num0 oprSize)
  !!ir (count := AST.num0 oprSize)
  !!ir (orgSrc := src)
  !!ir (AST.lmark lblLoopCond)
  !!ir (AST.cjmp (i .< max) (AST.name lblLoop) (AST.name lblExit))
  !!ir (AST.lmark lblLoop)
  let cond = (AST.xtlo 1<rt> (src >> i)) == AST.b1
  !!ir (count := AST.ite cond (count .+ AST.num1 oprSize) count)
  !!ir (i := i .+ AST.num1 oprSize)
  !!ir (AST.jmp (AST.name lblLoopCond))
  !!ir (AST.lmark lblExit)
  !!ir (dstAssign oprSize dst count)
  !!ir (!.ctxt R.OF := AST.b0)
  !!ir (!.ctxt R.SF := AST.b0)
  !!ir (!.ctxt R.ZF := orgSrc == AST.num0 oprSize)
  !!ir (!.ctxt R.AF := AST.b0)
  !!ir (!.ctxt R.CF := AST.b0)
  !!ir (!.ctxt R.PF := AST.b0)
#if EMULATION
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let popf ins insLen ctxt =
  let ir = !*ctxt
  let oprSize = getOperationSize ins
  let t = !+ir oprSize
  !<ir insLen
  !?ir (auxPop oprSize ctxt t)
  !!ir (!.ctxt R.OF := AST.extract t 1<rt> 11)
  !!ir (!.ctxt R.DF := AST.extract t 1<rt> 10)
  !!ir (!.ctxt R.IF := AST.extract t 1<rt> 9)
  !!ir (!.ctxt R.TF := AST.extract t 1<rt> 8)
  !!ir (!.ctxt R.SF := AST.extract t 1<rt> 7)
  !!ir (!.ctxt R.ZF := AST.extract t 1<rt> 6)
  !!ir (!.ctxt R.AF := AST.extract t 1<rt> 4)
  !!ir (!.ctxt R.PF := AST.extract t 1<rt> 2)
  !!ir (!.ctxt R.CF := AST.xtlo 1<rt> t)
#if EMULATION
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let inline private padPushExpr oprSize opr =
  match opr.E with
  | Var (_, s, _) ->
    if isSegReg <| Register.ofRegID s then AST.zext oprSize opr else opr
  | Num (_) -> AST.sext oprSize opr
  | _ -> opr

let push ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let src = transOneOpr ir ins insLen ctxt
  let oprSize = getOperationSize ins
  if hasStackPtr ins then
    let t = !+ir oprSize
    !!ir (t := padPushExpr oprSize src)
    !?ir (auxPush oprSize ctxt (padPushExpr oprSize t))
  else
    !?ir (auxPush oprSize ctxt (padPushExpr oprSize src))
  !>ir insLen

let pusha ins insLen ctxt oprSize =
  let ir = !*ctxt
  let t = !+ir oprSize
  let sp = if oprSize = 32<rt> then R.ESP else R.SP
  let ax = if oprSize = 32<rt> then R.EAX else R.AX
  let cx = if oprSize = 32<rt> then R.ECX else R.CX
  let dx = if oprSize = 32<rt> then R.EDX else R.DX
  let bx = if oprSize = 32<rt> then R.EBX else R.BX
  let bp = if oprSize = 32<rt> then R.EBP else R.BP
  let si = if oprSize = 32<rt> then R.ESI else R.SI
  let di = if oprSize = 32<rt> then R.EDI else R.DI
  !<ir insLen
  !!ir (dstAssign oprSize t (!.ctxt sp))
  !?ir (auxPush oprSize ctxt (!.ctxt ax))
  !?ir (auxPush oprSize ctxt (!.ctxt cx))
  !?ir (auxPush oprSize ctxt (!.ctxt dx))
  !?ir (auxPush oprSize ctxt (!.ctxt bx))
  !?ir (auxPush oprSize ctxt t)
  !?ir (auxPush oprSize ctxt (!.ctxt bp))
  !?ir (auxPush oprSize ctxt (!.ctxt si))
  !?ir (auxPush oprSize ctxt (!.ctxt di))
  !>ir insLen

let pushf ins insLen ctxt =
  let ir = !*ctxt
  let oprSize = getOperationSize ins
  let e = AST.zext oprSize <| !.ctxt R.CF
  (* We only consider 9 flags (we ignore system flags). *)
  !<ir insLen
#if EMULATION
  let e = e .| ((AST.zext oprSize (getPFLazy ctxt ir)) << numI32 2 oprSize)
  let e = e .| ((AST.zext oprSize (getAFLazy ctxt ir)) << numI32 4 oprSize)
  let e = e .| ((AST.zext oprSize (getZFLazy ctxt ir)) << numI32 6 oprSize)
  let e = e .| ((AST.zext oprSize (getSFLazy ctxt ir)) << numI32 7 oprSize)
  let e = e .| ((AST.zext oprSize (!.ctxt R.TF)) << numI32 8 oprSize)
  let e = e .| ((AST.zext oprSize (!.ctxt R.IF)) << numI32 9 oprSize)
  let e = e .| ((AST.zext oprSize (!.ctxt R.DF)) << numI32 10 oprSize)
  let e = e .| ((AST.zext oprSize (getOFLazy ctxt ir)) << numI32 11 oprSize)
#else
#endif
  let e = e .| ((AST.zext oprSize (!.ctxt R.PF)) << numI32 2 oprSize)
  let e = e .| ((AST.zext oprSize (!.ctxt R.AF)) << numI32 4 oprSize)
  let e = e .| ((AST.zext oprSize (!.ctxt R.ZF)) << numI32 6 oprSize)
  let e = e .| ((AST.zext oprSize (!.ctxt R.SF)) << numI32 7 oprSize)
  let e = e .| ((AST.zext oprSize (!.ctxt R.TF)) << numI32 8 oprSize)
  let e = e .| ((AST.zext oprSize (!.ctxt R.IF)) << numI32 9 oprSize)
  let e = e .| ((AST.zext oprSize (!.ctxt R.DF)) << numI32 10 oprSize)
  let e = e .| ((AST.zext oprSize (!.ctxt R.OF)) << numI32 11 oprSize)
  let e = match oprSize with
          | 16<rt> -> e
          | 32<rt> -> e .& (numI32 0xfcffff 32<rt>)
          | 64<rt> -> e .& (numI32 0xfcffff 64<rt>)
          | _ -> raise InvalidOperandSizeException
  !?ir (auxPush oprSize ctxt e)
  !>ir insLen

let rcl ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, count) = transTwoOprs ir true ins insLen ctxt
  let oprSize = getOperationSize ins
  let cF = !.ctxt R.CF
  let oF = !.ctxt R.OF
  let tmpCF = !+ir 1<rt>
  let count = AST.zext oprSize count
  let tmpCnt = !+ir oprSize
  let cnt =
    match oprSize with
    | 8<rt> -> (count .& numI32 0x1f oprSize) .% numI32 9 oprSize
    | 16<rt> -> (count .& numI32 0x1f oprSize) .% numI32 17 oprSize
    | 32<rt> -> count .& numI32 0x1f oprSize
    | 64<rt> -> count .& numI32 0x3f oprSize
    | _ -> raise InvalidOperandSizeException
  !!ir (tmpCnt := cnt)
  let cond1 = tmpCnt != AST.num0 oprSize
  let cntMask = numI32 (if oprSize = 64<rt> then 0x3F else 0x1F) oprSize
  let cond2 = (count .& cntMask) == AST.num1 oprSize
#if EMULATION
  !!ir (cF := getCFLazy ctxt ir)
#endif
  let lblRotate = !%ir "Rotate"
  let lblZero = !%ir "Zero"
  let lblExit = !%ir "Exit"
  !!ir (AST.cjmp cond1 (AST.name lblRotate) (AST.name lblZero))
  !!ir (AST.lmark lblRotate)
  !!ir (tmpCF := AST.xthi 1<rt> dst)
  let r = (dst << AST.num1 oprSize) .+ (AST.zext oprSize cF)
  !!ir (dstAssign oprSize dst r)
  !!ir (cF := tmpCF)
  !!ir (tmpCnt := tmpCnt .- AST.num1 oprSize)
  !!ir (AST.cjmp cond1 (AST.name lblRotate) (AST.name lblExit))
  !!ir (AST.lmark lblZero)
  !!ir (dstAssign oprSize dst dst)
  !!ir (AST.lmark lblExit)
#if !EMULATION
  !!ir (oF := AST.ite cond2 (AST.xthi 1<rt> dst <+> cF) undefOF)
#else
  !!ir (oF := AST.ite cond2 (AST.xthi 1<rt> dst <+> cF) (getOFLazy ctxt ir))
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let rcr ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, count) = transTwoOprs ir true ins insLen ctxt
  let oprSize = getOperationSize ins
  let cF = !.ctxt R.CF
  let oF = !.ctxt R.OF
  let struct (tmpCF, tmpOF) = tmpVars2 ir 1<rt>
  let count = AST.zext oprSize count
  let tmpCnt = !+ir oprSize
  let cnt =
    match oprSize with
    | 8<rt> -> (count .& numI32 0x1f oprSize) .% numI32 9 oprSize
    | 16<rt> -> (count .& numI32 0x1f oprSize) .% numI32 17 oprSize
    | 32<rt> -> count .& numI32 0x1f oprSize
    | 64<rt> -> count .& numI32 0x3f oprSize
    | _ -> raise InvalidOperandSizeException
  !!ir (tmpCnt := cnt)
  let cond1 = tmpCnt != AST.num0 oprSize
  let cntMask = numI32 (if oprSize = 64<rt> then 0x3F else 0x1F) oprSize
  let cond2 = (count .& cntMask) == AST.num1 oprSize
#if EMULATION
  !!ir (cF := getCFLazy ctxt ir)
#endif
  !!ir (tmpOF := AST.xthi 1<rt> dst <+> cF)
  let lblRotate = !%ir "Rotate"
  let lblZero = !%ir "Zero"
  let lblExit = !%ir "Exit"
  !!ir (AST.cjmp cond1 (AST.name lblRotate) (AST.name lblZero))
  !!ir (AST.lmark lblRotate)
  !!ir (tmpCF := AST.xtlo 1<rt> dst)
  let extCF = (AST.zext oprSize cF) << (numI32 (int oprSize - 1) oprSize)
  !!ir (dstAssign oprSize dst ((dst >> AST.num1 oprSize) .+ extCF))
  !!ir (cF := tmpCF)
  !!ir (tmpCnt := tmpCnt .- AST.num1 oprSize)
  !!ir (AST.cjmp cond1 (AST.name lblRotate) (AST.name lblExit))
  !!ir (AST.lmark lblZero)
  !!ir (dstAssign oprSize dst dst)
  !!ir (AST.lmark lblExit)
#if !EMULATION
  !!ir (oF := AST.ite cond2 tmpOF undefOF)
#else
  !!ir (oF := AST.ite cond2 tmpOF (getOFLazy ctxt ir))
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let rdpkru ins insLen ctxt =
  let ir = !*ctxt
  let lblSucc = !%ir "Succ"
  let lblErr = !%ir "Err"
  let oprSize = getOperationSize ins
  let ecx = !.ctxt R.ECX
  let eax = getRegOfSize ctxt ctxt.WordBitSize grpEAX
  let edx = getRegOfSize ctxt ctxt.WordBitSize grpEDX
  !<ir insLen
  !!ir (AST.cjmp (ecx == AST.num0 oprSize) (AST.name lblSucc) (AST.name lblErr))
  !!ir (AST.lmark lblErr)
  !!ir (AST.sideEffect (Exception "GP"))
  !!ir (AST.lmark lblSucc)
  !!ir (eax := AST.zext ctxt.WordBitSize (!.ctxt R.PKRU))
  !!ir (edx := AST.num0 ctxt.WordBitSize)
  !>ir insLen

let retWithImm ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let t = !+ir oprSize
  let sp = getStackPtr ctxt
  let src = transOneOpr ir ins insLen ctxt
#if EMULATION
  !?ir (setCCOp ctxt)
  ctxt.ConditionCodeOp <- ConditionCodeOp.TraceStart
#endif
  !?ir (auxPop oprSize ctxt t)
  !!ir (sp := sp .+ (AST.zext oprSize src))
  !!ir (AST.interjmp t InterJmpKind.IsRet)
  !>ir insLen

let ret ins insLen ctxt =
  let ir = !*ctxt
  let oprSize = getOperationSize ins
  let t = !+ir oprSize
  !<ir insLen
#if EMULATION
  !?ir (setCCOp ctxt)
  ctxt.ConditionCodeOp <- ConditionCodeOp.TraceStart
#endif
  !?ir (auxPop oprSize ctxt t)
  !!ir (AST.interjmp t InterJmpKind.IsRet)
  !>ir insLen

let rotate ins insLen ctxt lfn hfn cfFn ofFn =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, count) = transTwoOprs ir true ins insLen ctxt
  let oprSize = getOperationSize ins
  let cF = !.ctxt R.CF
  let oF = !.ctxt R.OF
  let size = numI32 (RegType.toBitWidth oprSize) oprSize
  let orgCount = AST.zext oprSize count .% (numI32 (int oprSize) oprSize)
  let cond1 = orgCount == AST.num0 oprSize
  let cond2 = orgCount == AST.num1 oprSize
  let value = (lfn dst orgCount) .| (hfn dst (size .- orgCount))
  !!ir (dstAssign oprSize dst value)
#if EMULATION
  !?ir (genDynamicFlagsUpdate ctxt)
#endif
  !!ir (cF := AST.ite cond1 cF (cfFn 1<rt> dst))
#if !EMULATION
  !!ir (oF := AST.ite cond2 (ofFn dst cF) undefOF)
#else
  !!ir (oF := AST.ite cond2 (ofFn dst cF) oF)
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let rol ins insLen ctxt =
  let ofFn dst cF = cF <+> AST.xthi 1<rt> dst
  rotate ins insLen ctxt (<<) (>>) AST.xtlo ofFn

let ror ins insLen ctxt =
  let oprSize = getOperationSize ins
  let ofFn dst _cF =
    AST.xthi 1<rt> dst <+> AST.extract dst 1<rt> ((int oprSize - 1) - 1)
  rotate ins insLen ctxt (>>) (<<) AST.xthi ofFn

let rorx ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, imm) = transThreeOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let y = !+ir oprSize
  if oprSize = 32<rt> then
    !!ir (y := imm .& (numI32 0x1F oprSize))
    !!ir (dstAssign oprSize dst
      ((src >> y) .| (src << (numI32 32 oprSize .- y))))
  else (* OperandSize = 64 *)
    !!ir (y := imm .& (numI32 0x3F oprSize))
    !!ir (dstAssign oprSize dst
      ((src >> y) .| (src << (numI32 64 oprSize .- y))))
  !>ir insLen

let sahf ins insLen ctxt =
  let ir = !*ctxt
  let ah = !.ctxt R.AH
  !<ir insLen
  !!ir (!.ctxt R.CF := AST.xtlo 1<rt> ah)
  !!ir (!.ctxt R.PF := AST.extract ah 1<rt> 2)
  !!ir (!.ctxt R.AF := AST.extract ah 1<rt> 4)
  !!ir (!.ctxt R.ZF := AST.extract ah 1<rt> 6)
  !!ir (!.ctxt R.SF := AST.extract ah 1<rt> 7)
#if EMULATION
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let shift ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir true ins insLen ctxt
  let oprSize = getOperationSize ins
  let countMask = if is64REXW ctxt ins then numU32 0x3Fu oprSize
                  else numU32 0x1Fu oprSize
  let cnt = (AST.zext oprSize src) .& countMask
  let tDst = !+ir oprSize
#if !EMULATION
  let n0 = AST.num0 oprSize
  let n1 = AST.num1 oprSize
  let isCntConst = isConst src
  let cond1 = cnt == n1
  let cond2 = cnt == n0
  let oF = !.ctxt R.OF
  let cF = !.ctxt R.CF
  let sF = !.ctxt R.SF
  let zF = !.ctxt R.ZF
  let tCnt = if isCntConst then cnt .- n1 else !+ir oprSize
  !!ir (tDst := dst)
#endif
  match ins.Opcode with
  | Opcode.SHL ->
#if EMULATION
    !!ir (tDst := dst << cnt)
    !?ir (setCCOperands3 ctxt dst cnt tDst)
    !!ir (dstAssign oprSize dst tDst)
    match oprSize with
    | 8<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.SHLB
    | 16<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.SHLW
    | 32<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.SHLD
    | 64<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.SHLQ
    | _ -> raise InvalidRegTypeException
#else
    !!ir (dstAssign oprSize dst (tDst << cnt))
    if isCntConst then () else !!ir (tCnt := cnt .- n1)
    !!ir (cF := AST.ite cond2 cF (AST.xthi 1<rt> (tDst << tCnt)))
    let of1 = AST.xthi 1<rt> dst <+> cF
    !!ir (oF := AST.ite cond1 of1 (AST.ite cond2 oF undefOF))
#endif
  | Opcode.SHR ->
#if EMULATION
    !!ir (tDst := dst >> cnt)
    !?ir (setCCOperands3 ctxt dst cnt tDst)
    !!ir (dstAssign oprSize dst tDst)
    match oprSize with
    | 8<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.SHRB
    | 16<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.SHRW
    | 32<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.SHRD
    | 64<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.SHRQ
    | _ -> raise InvalidRegTypeException
#else
    !!ir (dstAssign oprSize dst (tDst >> cnt))
    if isCntConst then () else !!ir (tCnt := cnt .- n1)
    !!ir (cF := AST.ite cond2 cF (AST.xtlo 1<rt> (tDst >> tCnt)))
    !!ir (oF := AST.ite cond1 (AST.xthi 1<rt> tDst) (AST.ite cond2 oF undefOF))
#endif
  | Opcode.SAR ->
#if EMULATION
    !!ir (tDst := dst ?>> cnt)
    !?ir (setCCOperands3 ctxt dst cnt tDst)
    !!ir (dstAssign oprSize dst tDst)
    match oprSize with
    | 8<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.SARB
    | 16<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.SARW
    | 32<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.SARD
    | 64<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.SARQ
    | _ -> raise InvalidRegTypeException
#else
    !!ir (dstAssign oprSize dst (tDst ?>> cnt))
    if isCntConst then () else !!ir (tCnt := cnt .- n1)
    !!ir (cF := AST.ite cond2 cF (AST.xtlo 1<rt> (tDst ?>> tCnt)))
    !!ir (oF := AST.ite cond1 AST.b0 (AST.ite cond2 oF undefOF))
#endif
  | _ -> raise InvalidOpcodeException
#if !EMULATION
  let aF = !.ctxt R.AF
  !!ir (aF := AST.ite cond2 aF undefAF)
  !!ir (sF := AST.ite cond2 sF (AST.xthi 1<rt> dst))
  !?ir (buildPF ctxt dst oprSize (Some cond2))
  !!ir (zF := AST.ite cond2 zF (dst == n0))
#endif
  !>ir insLen


let sbb ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir true ins insLen ctxt
  let oprSize = getOperationSize ins
  let struct (t1, t2, t3, t4) = tmpVars4 ir oprSize
  let cf = !.ctxt R.CF
  let sf = AST.xthi 1<rt> t4
  !!ir (t1 := dst)
  !!ir (t2 := AST.sext oprSize src)
#if EMULATION
  !!ir (t3 := t2 .+ AST.zext oprSize (getCFLazy ctxt ir))
#else
  !!ir (t3 := t2 .+ AST.zext oprSize cf)
#endif
  !!ir (t4 := t1 .- t3)
  !!ir (dstAssign oprSize dst t4)
  !!ir (cf := (t1 .< t3) .| (t3 .< t2))
  !!ir (!.ctxt R.OF := ofOnSub t1 t2 t4)
  !?ir (enumASZPFlags ctxt t1 t2 t4 oprSize sf)
#if EMULATION
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let private scasBody ins ctxt ir =
  let oprSize = getOperationSize ins
  let t = !+ir oprSize
  let df = !.ctxt R.DF
  let x = getRegOfSize ctxt oprSize grpEAX
  let di = !.ctxt (if is64bit ctxt then R.RDI else R.EDI)
  let tSrc = !+ir oprSize
  let amount = numI32 (RegType.toByteWidth oprSize) ctxt.WordBitSize
  let sf = AST.xthi 1<rt> t
  !!ir (tSrc := AST.loadLE oprSize di)
  !!ir (t := x .- tSrc)
  !?ir (enumEFLAGS ctxt x tSrc t oprSize (cfOnSub x tSrc) (ofOnSub x tSrc t) sf)
  !!ir (di := AST.ite df (di .- amount) (di .+ amount))

let scas (ins: InsInfo) insLen ctxt =
  let pref = ins.Prefixes
  let zfCond n = Some (!.ctxt R.ZF == n)
  let ir = !*ctxt
  !<ir insLen
  if hasREPZ pref then
    strRepeat ins insLen ctxt scasBody (zfCond AST.b0) ir
  elif hasREPNZ pref then
    strRepeat ins insLen ctxt scasBody (zfCond AST.b1) ir
  else scasBody ins ctxt ir
#if EMULATION
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let private getCondOfSet (ins: IntelInternalInstruction) ctxt =
  match ins.Opcode with
  | Opcode.SETO   -> !.ctxt R.OF
  | Opcode.SETNO  -> !.ctxt R.OF == AST.b0
  | Opcode.SETB   -> !.ctxt R.CF
  | Opcode.SETNB  -> !.ctxt R.CF == AST.b0
  | Opcode.SETZ   -> !.ctxt R.ZF
  | Opcode.SETNZ  -> !.ctxt R.ZF == AST.b0
  | Opcode.SETBE  -> (!.ctxt R.CF) .| (!.ctxt R.ZF)
  | Opcode.SETA   -> ((!.ctxt R.CF) .| (!.ctxt R.ZF)) == AST.b0
  | Opcode.SETS   -> !.ctxt R.SF
  | Opcode.SETNS  -> !.ctxt R.SF == AST.b0
  | Opcode.SETP   -> !.ctxt R.PF
  | Opcode.SETNP  -> !.ctxt R.PF == AST.b0
  | Opcode.SETL   -> !.ctxt R.SF != !.ctxt R.OF
  | Opcode.SETNL  -> !.ctxt R.SF == !.ctxt R.OF
  | Opcode.SETLE  -> !.ctxt R.ZF .|
                     (!.ctxt R.SF != !.ctxt R.OF)
  | Opcode.SETG   -> (!.ctxt R.ZF == AST.b0) .&
                     (!.ctxt R.SF == !.ctxt R.OF)
  | _ -> raise InvalidOpcodeException

#if EMULATION
let private getCondOfSetLazy (ins: IntelInternalInstruction) ctxt ir =
  match ins.Opcode with
  | Opcode.SETO -> getOFLazy ctxt ir
  | Opcode.SETNO -> getOFLazy ctxt ir |> AST.not
  | Opcode.SETB -> getCFLazy ctxt ir
  | Opcode.SETNB -> getCFLazy ctxt ir |> AST.not
  | Opcode.SETZ -> getZFLazy ctxt ir
  | Opcode.SETNZ -> getZFLazy ctxt ir |> AST.not
  | Opcode.SETBE -> (getCFLazy ctxt ir) .| (getZFLazy ctxt ir)
  | Opcode.SETA -> (getCFLazy ctxt ir .| getZFLazy ctxt ir) |> AST.not
  | Opcode.SETS -> getSFLazy ctxt ir
  | Opcode.SETNS -> getSFLazy ctxt ir |> AST.not
  | Opcode.SETP -> getPFLazy ctxt ir
  | Opcode.SETNP -> getPFLazy ctxt ir |> AST.not
  | Opcode.SETL -> getSFLazy ctxt ir != getOFLazy ctxt ir
  | Opcode.SETNL -> getSFLazy ctxt ir == getOFLazy ctxt ir
  | Opcode.SETLE -> (getZFLazy ctxt ir) .|
                    (getSFLazy ctxt ir != getOFLazy ctxt ir)
  | Opcode.SETG   -> (getZFLazy ctxt ir |> AST.not) .&
                     (getSFLazy ctxt ir == getOFLazy ctxt ir)
  | _ -> raise InvalidOpcodeException
#endif

let setcc ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let dst = transOneOpr ir ins insLen ctxt
  let oprSize = getOperationSize ins
#if EMULATION
  let cond = getCondOfSetLazy ins ctxt ir |> AST.zext oprSize
#else
  let cond = getCondOfSet ins ctxt |> AST.zext oprSize
#endif
  !!ir (dstAssign oprSize dst cond)
  !>ir insLen

let inline shiftDblPrec ins insLen ctxt fnDst fnSrc isShl =
  let ir = !*ctxt
  !<ir insLen
  let oprSz = getOperationSize ins
  let exprOprSz = numI32 (int oprSz) oprSz
  let struct (dst, src, cnt) = transThreeOprs ir false ins insLen ctxt
  let struct (count, size, tDst, tSrc) = tmpVars4 ir oprSz
  let org = !+ir oprSz
  let cF = !.ctxt R.CF
  let oF = !.ctxt R.OF
  let sf = !.ctxt R.SF
  let zf = !.ctxt R.ZF
  let cond1 = count == AST.num0 oprSz
  let cond2 = count == AST.num1 oprSz
  !!ir (org := dst)
  !!ir (size := exprOprSz)
  let wordSize = numI32 (if hasREXW ins.REXPrefix then 64 else 32) oprSz
  !!ir (count := (AST.zext oprSz cnt .% wordSize))
  !!ir (tDst := dst)
  !!ir (tSrc := src)
  !!ir (tDst := fnDst tDst count)
  !!ir (tSrc := fnSrc tSrc (size .- count))
  !!ir (dstAssign oprSz dst (AST.ite cond1 org (tDst .| tSrc)))
  let amount = if isShl then size .- count else count .- AST.num1 oprSz
  !!ir (cF := AST.ite cond1 cF (AST.xtlo 1<rt> (org >> amount)))
  let overflow = AST.xthi 1<rt> (org <+> dst)
#if !EMULATION
  let aF = !.ctxt R.AF
  !!ir (oF := AST.ite cond1 oF (AST.ite cond2 overflow undefOF))
  !!ir (aF := AST.ite cond1 aF undefAF)
#else
  !!ir (oF := AST.ite cond1 oF (AST.ite cond2 overflow oF))
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !!ir (sf := AST.ite cond1 sf (AST.xthi 1<rt> dst))
  !!ir (zf := AST.ite cond1 zf (dst == (AST.num0 oprSz)))
  !?ir (buildPF ctxt dst oprSz (Some cond1))
  !>ir insLen

let shld ins insLen ctxt =
  shiftDblPrec ins insLen ctxt (<<) (>>) true

let shrd ins insLen ctxt =
  shiftDblPrec ins insLen ctxt (>>) (<<) false

let private shiftWithoutFlags ins insLen ctxt opFn =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = transThreeOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let countMask = if is64REXW ctxt ins then 0x3F else 0x1F // FIXME: CS.L = 1
  let count = src2 .& (numI32 countMask oprSize)
  !!ir (dstAssign oprSize dst (opFn src1 count))
  !>ir insLen

let sarx ins insLen ctxt = shiftWithoutFlags ins insLen ctxt (?>>)

let shlx ins insLen ctxt = shiftWithoutFlags ins insLen ctxt (<<)

let shrx ins insLen ctxt = shiftWithoutFlags ins insLen ctxt (>>)

let setFlag insLen ctxt flag =
  let ir = !*ctxt
  !<ir insLen
  !!ir (!.ctxt flag := AST.b1)
#if EMULATION
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let stc insLen ctxt = setFlag insLen ctxt R.CF

let std insLen ctxt = setFlag insLen ctxt R.DF

let sti insLen ctxt = setFlag insLen ctxt R.IF

let private stosBody ins ctxt ir =
  let oprSize = getOperationSize ins
  let df = !.ctxt R.DF
  let di = !.ctxt (if is64bit ctxt then R.RDI else R.EDI)
  let src = getRegOfSize ctxt oprSize grpEAX
  let amount = numI32 (RegType.toByteWidth oprSize) ctxt.WordBitSize
  !!ir (AST.loadLE oprSize di := src)
  !!ir (di := AST.ite df (di .- amount) (di .+ amount))

let stos (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  if hasREPZ ins.Prefixes then
    strRepeat ins insLen ctxt stosBody None ir
  elif hasREPNZ ins.Prefixes then Utils.impossible ()
  else stosBody ins ctxt ir
  !>ir insLen

let sub ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir true ins insLen ctxt
  let oprSize = getOperationSize ins
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Lock) else ()
#if !EMULATION
  let isSrcConst = isConst src
  let t1 = !+ir oprSize
  let t2 = if isSrcConst then src else !+ir oprSize
  let t3 = !+ir oprSize
  !!ir (t1 := dst)
  if isSrcConst then () else !!ir (t2 := src)
  !!ir (t3 := t1 .- t2)
  !!ir (dstAssign oprSize dst t3)
  let sf = AST.xthi 1<rt> t3
  !?ir (enumEFLAGS ctxt t1 t2 t3 oprSize (cfOnSub t1 t2) (ofOnSub t1 t2 t3) sf)
#else
  let src =
    if isConst src then src
    else
      let t = !+ir oprSize
      !!ir (t := src)
      t
  !!ir (dstAssign oprSize dst (dst .- src))
  !?ir (setCCOperands2 ctxt src dst)
  match oprSize with
  | 8<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.SUBB
  | 16<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.SUBW
  | 32<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.SUBD
  | 64<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.SUBQ
  | _ -> raise InvalidRegTypeException
#endif
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Unlock) else ()
  !>ir insLen

let test ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (src1, src2) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let r = if src1 = src2 then src1 else src1 .& src2
#if EMULATION
  !?ir (setCCDst ctxt r)
  match oprSize with
  | 8<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.LOGICB
  | 16<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.LOGICW
  | 32<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.LOGICD
  | 64<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.LOGICQ
  | _ -> raise InvalidRegTypeException
#else
  let t = !+ir oprSize
  !!ir (t := r)
  !!ir (!.ctxt R.SF := AST.xthi 1<rt> t)
  !!ir (!.ctxt R.ZF := t == (AST.num0 oprSize))
  !?ir (buildPF ctxt t oprSize None)
  !!ir (!.ctxt R.CF := AST.b0)
  !!ir (!.ctxt R.OF := AST.b0)
  !!ir (!.ctxt R.AF := undefAF)
#endif
  !>ir insLen

let tzcnt ins insLen ctxt =
  let ir = !*ctxt
  let oprSize = getOperationSize ins
  let struct (dst, src) = transTwoOprs ir true ins insLen ctxt
  !<ir insLen
  let lblCnt = !%ir "Count"
  let lblZero = !%ir "Zero"
  let lblEnd = !%ir "End"
  let z = AST.num0 oprSize
  let max = numI32 (RegType.toBitWidth oprSize) oprSize
  let struct (t1, t2, res) = tmpVars3 ir oprSize
  !!ir (t1 := src)
  !!ir (AST.cjmp (t1 == z) (AST.name lblZero) (AST.name lblCnt))
  !!ir (AST.lmark lblZero)
  !!ir (dstAssign oprSize dst max)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblCnt)
  !!ir (res := z)
  !!ir (t1 := t1 .& (t1 .* numI32 0xFFFFFFFF oprSize))
  match oprSize with
  | 16<rt> ->
    !!ir (t2 := t1 >> numI32 8 16<rt>)
    !!ir (t1 := AST.ite (t2 != z) t2 t1)
    !!ir (res := AST.ite (t2 != z) (res .+  numI32 8 16<rt>) res)
    !!ir (t2 := t1 >> numI32 4 16<rt>)
    !!ir (t1 := AST.ite (t2 != z) t2 t1)
    !!ir (res := AST.ite (t2 != z) (res .+  numI32 4 16<rt>) res)
  | 32<rt> ->
    !!ir (t2 := t1 >> numI32 16 32<rt>)
    !!ir (t1 := AST.ite (t2 != z) t2 t1)
    !!ir (res := AST.ite (t2 != z) (res .+  numI32 16 32<rt>) res)
    !!ir (t2 := t1 >> numI32 8 32<rt>)
    !!ir (t1 := AST.ite (t2 != z) t2 t1)
    !!ir (res := AST.ite (t2 != z) (res .+  numI32 8 32<rt>) res)
    !!ir (t2 := t1 >> numI32 4 32<rt>)
    !!ir (t1 := AST.ite (t2 != z) t2 t1)
    !!ir (res := AST.ite (t2 != z) (res .+  numI32 4 32<rt>) res)
  | 64<rt> ->
    !!ir (t2 := t1 >> numI32 32 64<rt>)
    !!ir (t1 := AST.ite (t2 != z) t2 t1)
    !!ir (res := AST.ite (t2 != z) (res .+  numI32 32 64<rt>) res)
    !!ir (t2 := t1 >> numI32 16 64<rt>)
    !!ir (t1 := AST.ite (t2 != z) t2 t1)
    !!ir (res := AST.ite (t2 != z) (res .+  numI32 16 64<rt>) res)
    !!ir (t2 := t1 >> numI32 8 64<rt>)
    !!ir (t1 := AST.ite (t2 != z) t2 t1)
    !!ir (res := AST.ite (t2 != z) (res .+  numI32 8 64<rt>) res)
    !!ir (t2 := t1 >> numI32 4 64<rt>)
    !!ir (t1 := AST.ite (t2 != z) t2 t1)
    !!ir (res := AST.ite (t2 != z) (res .+  numI32 4 64<rt>) res)
  | _ -> raise InvalidOperandSizeException
  let v = (res .+ ((t1 >> numI32 1 oprSize) .- (t1 >> numI32 3 oprSize)))
  !!ir (dstAssign oprSize dst v)
  !!ir (AST.lmark lblEnd)
  !!ir (!.ctxt R.CF := dst == max)
  !!ir (!.ctxt R.ZF := dst == z)
#if !EMULATION
  !!ir (!.ctxt R.OF := undefOF)
  !!ir (!.ctxt R.SF := undefSF)
  !!ir (!.ctxt R.PF := undefPF)
  !!ir (!.ctxt R.AF := undefAF)
#else
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let wrfsbase ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let src = transOneOpr ir ins insLen ctxt
  !!ir (!.ctxt R.FSBase := AST.zext ctxt.WordBitSize src)
  !>ir insLen

let wrgsbase ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let src = transOneOpr ir ins insLen ctxt
  !!ir (!.ctxt R.GSBase := AST.zext ctxt.WordBitSize src)
  !>ir insLen

let wrpkru ins insLen ctxt =
  let ir = !*ctxt
  let lblSucc = !%ir "Succ"
  let lblErr = !%ir "Err"
  let oprSize = getOperationSize ins
  let ecxIsZero = !.ctxt R.ECX == AST.num0 oprSize
  let edxIsZero = !.ctxt R.EDX == AST.num0 oprSize
  let cond = ecxIsZero .& edxIsZero
  !<ir insLen
  !!ir (AST.cjmp cond (AST.name lblSucc) (AST.name lblErr))
  !!ir (AST.lmark lblErr)
  !!ir (AST.sideEffect (Exception "GP"))
  !!ir (AST.lmark lblSucc)
  !!ir (!.ctxt R.PKRU := !.ctxt R.EAX)
  !>ir insLen

let xadd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Lock) else ()
  !!ir (t1 := dst)
  !!ir (t2 := src)
  !!ir (t3 := t1 .+ t2)
  !!ir (dstAssign oprSize src dst)
  !!ir (dstAssign oprSize dst t3)
#if EMULATION
  !?ir (setCCOperands2 ctxt t2 t3)
  match oprSize with
  | 8<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.ADDB
  | 16<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.ADDW
  | 32<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.ADDD
  | 64<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.ADDQ
  | _ -> raise InvalidRegTypeException
#else
  let struct (ofl, sf) = osfOnAdd t1 t2 t3 ir
  !?ir (enumEFLAGS ctxt t1 t2 t3 oprSize (cfOnAdd t1 t3) ofl sf)
#endif
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Unlock) else ()
  !>ir insLen

let xchg ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  if dst <> src then
    let t = !+ir oprSize
    !!ir (t := dst)
    !!ir (dstAssign oprSize dst src)
    !!ir (dstAssign oprSize src t)
  else
    !!ir (dstAssign oprSize dst src)
  !>ir insLen

let xlatb ins insLen ctxt =
  let ir = !*ctxt
  let addressSize = getEffAddrSz ins
  let al = AST.zext addressSize (!.ctxt R.AL)
  let bx = getRegOfSize ctxt addressSize grpEBX
  !<ir insLen
  !!ir (!.ctxt R.AL := AST.loadLE 8<rt> (al .+ bx))
  !>ir insLen

let xor ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  match ins.Operands with
  | TwoOperands (o1, o2) when o1 = o2 ->
    let dst = transOprToExpr ir false ins insLen ctxt o1
    let r = AST.num0 oprSize
    !!ir (dstAssign oprSize dst r)
#if EMULATION
    !?ir (setCCDst ctxt r)
    ctxt.ConditionCodeOp <- ConditionCodeOp.XORXX
#else
    !!ir (!.ctxt R.OF := AST.b0)
    !!ir (!.ctxt R.CF := AST.b0)
    !!ir (!.ctxt R.SF := AST.b0)
    !!ir (!.ctxt R.ZF := AST.b1)
    !!ir (!.ctxt R.PF := AST.b1)
#endif
  | TwoOperands (o1, o2) ->
    let dst = transOprToExpr ir false ins insLen ctxt o1
    let src = transOprToExpr ir false ins insLen ctxt o2 |> transReg ir true
    !!ir (dstAssign oprSize dst (dst <+> src))
#if EMULATION
    !?ir (setCCDst ctxt dst)
    match oprSize with
    | 8<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.LOGICB
    | 16<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.LOGICW
    | 32<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.LOGICD
    | 64<rt> -> ctxt.ConditionCodeOp <- ConditionCodeOp.LOGICQ
    | _ -> raise InvalidRegTypeException
#else
    !!ir (!.ctxt R.OF := AST.b0)
    !!ir (!.ctxt R.CF := AST.b0)
    !!ir (!.ctxt R.SF := AST.xthi 1<rt> dst)
    !!ir (!.ctxt R.ZF := dst == (AST.num0 oprSize))
    !?ir (buildPF ctxt dst oprSize None)
#endif
  | _ -> raise InvalidOperandException
#if !EMULATION
  !!ir (!.ctxt R.AF := undefAF)
#endif
  !>ir insLen
