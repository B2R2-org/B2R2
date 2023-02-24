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

let private buildAF ctxt e1 e2 r size =
  let t1 = r <+> e1
  let t2 = t1 <+> e2
  let t3 = (AST.num1 size) << (numU32 4ul size)
  let t4 = t2 .& t3
  !.ctxt R.AF := t4 == t3

let private buildPF ctxt r size cond ir =
  let struct (t1, t2) = tmpVars2 ir size
  let s2 = r <+> (r >> (AST.zext size (numU32 4ul 8<rt>)))
  let s4 = t1 <+> (t1 >> (AST.zext size (numU32 2ul 8<rt>)))
  let s5 = t2 <+> (t2 >> (AST.zext size (AST.num1 8<rt>)))
  let pf = !.ctxt R.PF
  let computedPF = AST.unop UnOpType.NOT (AST.xtlo 1<rt> s5)
  !!ir (t1 := s2)
  !!ir (t2 := s4)
  !!ir (match cond with
         | None -> pf := computedPF
         | Some cond -> pf := AST.ite cond pf computedPF)

let private enumSZPFlags ctxt r size sf ir =
  !!ir (!.ctxt R.SF := sf)
  !!ir (!.ctxt R.ZF := r == (AST.num0 size))
  !?ir (buildPF ctxt r size None)

let private enumASZPFlags ctxt e1 e2 r size sf ir =
  !!ir (buildAF ctxt e1 e2 r size)
  !?ir (enumSZPFlags ctxt r size sf)

let private enumEFLAGS ctxt e1 e2 e3 size cf ofl sf ir =
  !!ir (!.ctxt R.CF := cf)
  !!ir (!.ctxt R.OF := ofl)
  !!ir (buildAF ctxt e1 e2 e3 size)
  !!ir (!.ctxt R.SF := sf)
  !!ir (!.ctxt R.ZF := e3 == (AST.num0 size))
  !?ir (buildPF ctxt e3 size None)

/// CF on add.
let private cfOnAdd e1 r = AST.lt r e1

/// CF on sub.
let private cfOnSub e1 e2 = AST.lt e1 e2

/// OF and SF on add.
let private osfOnAdd e1 e2 r ir =
  let struct (t1, t2) = tmpVars2 ir 1<rt>
  let e1High = AST.xthi 1<rt> e1
  let e2High = AST.xthi 1<rt> e2
  let rHigh = AST.xthi 1<rt> r
  !!ir (t1 := e1High)
  !!ir (t2 := rHigh)
  struct ((t1 == e2High) .& (t1 <+> t2), t2)

/// OF on sub.
let private ofOnSub e1 e2 r =
  AST.xthi 1<rt> ((e1 <+> e2) .& (e1 <+> r))

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

let private auxPush oprSize ctxt expr ir =
  let t = !+ir oprSize
  let sp = getStackPtr ctxt
  !!ir (t := expr)
  !!ir (sp := sp .- (getStackWidth ctxt.WordBitSize oprSize))
  !!ir (AST.loadLE oprSize sp := t)

let private computePopSize oprSize = function
  | Var (_, id, _, _) when isSegReg (Register.ofRegID id) -> 16<rt>
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
  | Extract (e, _, _, _) -> isVar e.E
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
  let cond2 = af == AST.b1
  let cond = !+ir 1<rt>
  !<ir insLen
  !!ir (cond := cond1 .| cond2)
  !!ir (ax := AST.ite cond (ax .+ numI32 0x106 16<rt>) ax)
  !!ir (af := AST.ite cond AST.b1 AST.b0)
  !!ir (cf := AST.ite cond AST.b1 AST.b0)
  !!ir (al := alAnd0f)
#if !EMULATION
  !!ir (!.ctxt R.OF := undefOF)
  !!ir (!.ctxt R.SF := undefSF)
  !!ir (!.ctxt R.ZF := undefZF)
  !!ir (!.ctxt R.PF := undefPF)
#endif
  !>ir insLen

let aad ins insLen ctxt =
#if DEBUG
  assert32 ctxt
#endif
  let ir = !*ctxt
  !<ir insLen
  let imm8 = transOneOpr ir false ins insLen ctxt |> AST.xtlo 8<rt>
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
#endif
  !>ir insLen

let aam ins insLen ctxt =
#if DEBUG
  assert32 ctxt
#endif
  let ir = !*ctxt
  !<ir insLen
  let imm8 = transOneOpr ir false ins insLen ctxt |>  AST.xtlo 8<rt>
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
  let cond2 = af == AST.b1
  let ir = !*ctxt
  let cond = !+ir 1<rt>
  !<ir insLen
  !!ir (cond := cond1 .| cond2)
  !!ir (ax := AST.ite cond (ax .- numI32 6 16<rt>) ax)
  !!ir (ah := AST.ite cond (ah .- AST.num1 8<rt>) ah)
  !!ir (af := AST.ite cond AST.b1 AST.b0)
  !!ir (cf := AST.ite cond AST.b1 AST.b0)
  !!ir (al := alAnd0f)
  !>ir insLen

let adc ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let cf = !.ctxt R.CF
  let struct (t1, t2, t3, t4) = tmpVars4 ir oprSize
  !!ir (t1 := dst)
  !!ir (t2 := AST.sext oprSize src)
  !!ir (t3 := t2 .+ AST.zext oprSize cf)
  !!ir (t4 := t1 .+ t3)
  !!ir (dstAssign oprSize dst t4)
  !!ir (cf := AST.lt t3 t2 .| AST.lt t4 t1)
  let struct (ofl, sf) = osfOnAdd t1 t2 t4 ir
  !!ir (!.ctxt R.OF := ofl)
  !?ir (enumASZPFlags ctxt t1 t2 t4 oprSize sf)
  !>ir insLen

let add ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir true ins insLen ctxt
  let oprSize = getOperationSize ins
  if src = dst then
    let struct (t1, t2) = tmpVars2 ir oprSize
    if hasLock ins.Prefixes then !!ir (AST.sideEffect Lock) else ()
    !!ir (t1 := dst)
    !!ir (t2 := t1 .+ t1)
    !!ir (dstAssign oprSize dst t2)
    let struct (ofl, sf) = osfOnAdd t1 t1 t2 ir
    !?ir (enumEFLAGS ctxt t1 t1 t2 oprSize (cfOnAdd t1 t2) ofl sf)
  else
    let struct (t1, t2, t3) = tmpVars3 ir oprSize
    if hasLock ins.Prefixes then !!ir (AST.sideEffect Lock) else ()
    !!ir (t1 := dst)
    !!ir (t2 := src)
    !!ir (t3 := t1 .+ t2)
    !!ir (dstAssign oprSize dst t3)
    let struct (ofl, sf) = osfOnAdd t1 t2 t3 ir
    !?ir (enumEFLAGS ctxt t1 t2 t3 oprSize (cfOnAdd t1 t3) ofl sf)
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Unlock) else ()
  !>ir insLen

let adox ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let oF = !.ctxt R.OF
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !!ir (t1 := dst)
  !!ir (t2 := src)
  !!ir (t3 := t1 .+ t2 .+ AST.zext oprSize oF)
  !!ir (dstAssign oprSize dst t3)
  !>ir insLen

let ``and`` ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let t = !+ir oprSize
  let sf = AST.xthi 1<rt> t
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Lock) else ()
  !!ir (t := dst .& AST.sext oprSize src)
  !!ir (dstAssign oprSize dst t)
  !!ir (!.ctxt R.OF := AST.b0)
  !!ir (!.ctxt R.CF := AST.b0)
#if !EMULATION
  !!ir (!.ctxt R.AF := undefAF)
#endif
  !?ir (enumSZPFlags ctxt t oprSize sf)
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
  !!ir (dst := AST.ite (AST.lt t1 t2) ((dst .& mask) .| t2) dst)
  !!ir (zF := AST.lt t1 t2)
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
  !!ir (mask := AST.not(mask) << len)
  !!ir (tmp := AST.zext oprSize src1)
  !!ir (tmp := (tmp >> start) .& AST.not(mask))
  !!ir (dst := tmp)
  !!ir (zF := (dst == AST.num0 oprSize))
#if !EMULATION
  !!ir (!.ctxt R.AF := undefAF)
  !!ir (!.ctxt R.SF := undefSF)
  !!ir (!.ctxt R.PF := undefPF)
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
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let cond = src == AST.num0 oprSize
  let zf = !.ctxt R.ZF
  let t = !+ir oprSize
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
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let cond = src == AST.num0 oprSize
  let zf = !.ctxt R.ZF
  let t = !+ir oprSize
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
#endif
  !>ir insLen

let bswap ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let dst = transOneOpr ir false ins insLen ctxt
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
  | Load (e, t, expr, _) ->
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
  let struct (bitBase, bitOffset) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  !!ir (!.ctxt R.CF := bit ins bitBase bitOffset oprSize)
#if !EMULATION
  !!ir (!.ctxt R.OF := undefOF)
  !!ir (!.ctxt R.SF := undefSF)
  !!ir (!.ctxt R.AF := undefAF)
  !!ir (!.ctxt R.PF := undefPF)
#endif
  !>ir insLen

let private setBit ins bitBase bitOffset oprSize setValue =
  match bitBase.E with
  | Load (e, t, expr, _) ->
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
  let struct (bitBase, bitOffset) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let setValue = AST.zext oprSize setValue
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Lock) else ()
  !!ir (!.ctxt R.CF := bit ins bitBase bitOffset oprSize)
  !!ir (setBit ins bitBase bitOffset oprSize setValue)
#if !EMULATION
  !!ir (!.ctxt R.OF := undefOF)
  !!ir (!.ctxt R.SF := undefSF)
  !!ir (!.ctxt R.AF := undefAF)
  !!ir (!.ctxt R.PF := undefPF)
#endif
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Unlock) else ()
  !>ir insLen

let btc ins insLen ctxt =
  bitTest ins insLen ctxt (!.ctxt R.CF |> AST.not)

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
  !!ir (dst := AST.ite cond1 ((src1 << tmp) >> tmp) src1)
  !!ir (cf := AST.ite cond2 AST.b1 AST.b0)
  !>ir insLen

let call ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let pc = getInstrPtr ctxt
  let oprSize = getOperationSize ins
  let struct (target, ispcrel) = transJumpTargetOpr ir false ins pc insLen ctxt
  if ispcrel then
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
  !>ir insLen

let cmc ins insLen ctxt =
  let cf = !.ctxt R.CF
  let ir = !*ctxt
  !<ir insLen
  !!ir (cf := AST.not cf)
#if !EMULATION
  !!ir (!.ctxt R.OF := undefOF)
  !!ir (!.ctxt R.AF := undefAF)
  !!ir (!.ctxt R.SF := undefSF)
  !!ir (!.ctxt R.ZF := undefZF)
  !!ir (!.ctxt R.PF := undefPF)
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

let cmovcc ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  !!ir (dstAssign oprSize dst (AST.ite (getCondOfCMov ins ctxt) src dst))
  !>ir insLen

let cmp ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let struct (src1, src2) = transTwoOprs ir false ins insLen ctxt
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  let sf = AST.xthi 1<rt> t3
  !!ir (t1 := src1)
  !!ir (t2 := AST.sext oprSize src2)
  !!ir (t3 := t1 .- t2)
  !?ir (enumEFLAGS ctxt t1 t2 t3 oprSize (cfOnSub t1 t2) (ofOnSub t1 t2 t3) sf)
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
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
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
  !!ir (!.ctxt R.CF := AST.lt (tAcc .+ t) tAcc)
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Unlock) else ()
  !>ir insLen

let compareExchangeBytes ins insLen ctxt =
  let ir = !*ctxt
  let oprSize = getOperationSize ins
  let zf = !.ctxt R.ZF
  let cond = !+ir 1<rt>
  !<ir insLen
  match oprSize with
  | 64<rt> ->
    let dst = transOneOpr ir false ins insLen ctxt
    let edx = getRegOfSize ctxt 32<rt> grpEDX
    let eax = getRegOfSize ctxt 32<rt> grpEAX
    let ecx = getRegOfSize ctxt 32<rt> grpECX
    let ebx = getRegOfSize ctxt 32<rt> grpEBX
    let t = !+ir oprSize
    !!ir (t := dst)
    !!ir (cond := AST.concat edx eax == t)
    !!ir (zf := cond)
    !!ir (eax := AST.ite cond eax (AST.extract t 32<rt> 0))
    !!ir (edx := AST.ite cond edx (AST.extract t 32<rt> 32))
    !!ir (dst := AST.ite cond (AST.concat ecx ebx) t)
  | 128<rt> ->
    let dstB, dstA =
      match ins.Operands with
      | OneOperand opr -> transOprToExpr128 ir false ins insLen ctxt opr
      | _ -> raise InvalidOperandException
    let rdx = getRegOfSize ctxt 64<rt> grpEDX
    let rax = getRegOfSize ctxt 64<rt> grpEAX
    let rcx = getRegOfSize ctxt 64<rt> grpECX
    let rbx = getRegOfSize ctxt 64<rt> grpEBX
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
  let subCond2 = af == AST.b1
  let cond1 = !+ir 1<rt>
  let subCond3 = AST.gt oldAl (numI32 0x99 8<rt>)
  let subCond4 = oldCf == AST.b1
  let cond2 = !+ir 1<rt>
  let sf = AST.xthi 1<rt> al
  !<ir insLen
  !!ir (oldAl := al)
  !!ir (oldCf := cf)
  !!ir (cf := AST.b0)
  !!ir (cond1 := subCond1 .| subCond2)
  !!ir (al := AST.ite cond1 (al .+ numI32 6 8<rt>) al)
  !!ir (cf := AST.ite cond1 oldCf cf)
  !!ir (af := cond1)
  !!ir (cond2 := subCond3 .| subCond4)
  !!ir (al := AST.ite cond2 (al .+ numI32 0x60 8<rt>) al)
  !!ir (cf := cond2)
  !?ir (enumSZPFlags ctxt al 8<rt> sf)
#if !EMULATION
  !!ir (!.ctxt R.OF := undefOF)
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
  !!ir (oldCf := cf)
  !!ir (cf := AST.b0)
  !!ir (cond1 := subCond1 .| subCond2)
  !!ir (al := AST.ite cond1 (al .- numI32 6 8<rt>) al)
  !!ir (cf := AST.ite cond1 oldCf cf)
  !!ir (af := cond1)
  !!ir (cond2 := subCond3 .| subCond4)
  !!ir (al := AST.ite cond2 (al .- numI32 0x60 8<rt>) al)
  !!ir (cf := cond2)
  !?ir (enumSZPFlags ctxt al 8<rt> sf)
#if !EMULATION
  !!ir (!.ctxt R.OF := undefOF)
#endif
  !>ir insLen

let dec ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let dst = transOneOpr ir false ins insLen ctxt
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
  !>ir insLen

let private mul64Bit src1 src2 ir =
  let struct (hiSrc1, loSrc1, hiSrc2, loSrc2) = tmpVars4 ir 64<rt>
  let struct (tSrc1, tSrc2) = tmpVars2 ir 64<rt>
  let struct (tHigh, tLow) = tmpVars2 ir 64<rt>
  let n32 = numI32 32 64<rt>
  let mask = numI64 0xFFFFFFFFL 64<rt>
  !!ir (tSrc1 := src1)
  !!ir (tSrc2 := src2)
  !!ir (hiSrc1 := (tSrc1 >> n32) .& mask) (* SRC1[63:32] *)
  !!ir (loSrc1 := tSrc1 .& mask) (* SRC1[31:0] *)
  !!ir (hiSrc2 := (tSrc2 >> n32) .& mask) (* SRC2[63:32] *)
  !!ir (loSrc2 := tSrc2 .& mask) (* SRC2[31:0] *)
  let pHigh = hiSrc1 .* hiSrc2
  let pMid = (hiSrc1 .* loSrc2) .+ (loSrc1 .* hiSrc2)
  let pLow = (loSrc1 .* loSrc2)
  let high = pHigh .+ ((pMid .+ (pLow  >> n32)) >> n32)
  let low = pLow .+ ((pMid .& mask) << n32)
  !!ir (tHigh := high)
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
  let cond = ((AST.xthi 1<rt> remLo) == (AST.xthi 1<rt> srcHi))
              .& ((AST.xthi 1<rt> remLo) <+> (AST.xthi 1<rt> r))
  !!ir (t := cond)
  !!ir (r := remLo .+ srcHi)
  !!ir (remLo := AST.ite remMsb r remLo)
  let toAdd = AST.ite t (AST.num1 64<rt>) (AST.num0 64<rt>)
  !!ir (remHi := AST.ite remMsb (srcLo .+ toAdd) remHi)

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
  let condGE = (remHi >> n32) .>= (nrmDvsr >> n32)
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
  !!ir (lz := (numI64 64L oprSize))
  !!ir (t := tdivisor)
  !!ir (y := (t >> (numI64 32 oprSize)))
  !!ir (lz := (AST.ite (y != zero) (lz .- numI64 32 oprSize) lz))
  !!ir (t := (AST.ite (y != zero) y t))
  !!ir (y := (t >> (numI64 16 oprSize)))
  !!ir (lz := (AST.ite (y != zero) (lz .- numI64 16 oprSize) lz))
  !!ir (t := (AST.ite (y != zero) y t))
  !!ir (y := (t >> (numI64 8 oprSize)))
  !!ir (lz := (AST.ite (y != zero) (lz .- numI64 8 oprSize) lz))
  !!ir (t := (AST.ite (y != zero) y t))
  !!ir (y := (t >> (numI64 4 oprSize)))
  !!ir (lz := (AST.ite (y != zero) (lz .- numI64 4 oprSize) lz))
  !!ir (t := (AST.ite (y != zero) y t))
  !!ir (y := (t >> (numI64 2 oprSize)))
  !!ir (lz := (AST.ite (y != zero) (lz .- numI64 2 oprSize) lz))
  !!ir (t := (AST.ite (y != zero) y t))
  !!ir (y := (t >> (numI64 1 oprSize)))
  !!ir (lz := (AST.ite (y != zero) (lz .- numI64 2 oprSize) (lz .- t)))
  !!ir (nrmDvsr := tdivisor << lz)
  !!ir (t := AST.ite (lz != zero) (trax >> ((numI64 64 oprSize) .- lz)) zero)
  !!ir (remHi := (trdx << lz) .| t)
  !!ir (remLo := trax << lz)
  !!ir (qh := AST.ite condGE numF (remHi ./ (nrmDvsr >> n32)))
  (* compute remainder; correct quotient "digit" if remainder negative *)
  let struct (prodHi, prodLo) = mul64Bit (qh << n32) nrmDvsr ir
  helperRemSub remHi remLo prodHi prodLo ir
  !!ir (remMsb := (AST.xthi 1<rt> remHi))
  !!ir (qh := (AST.ite remMsb (qh .- one) (qh)))
  helperRemAdd remHi remLo (nrmDvsr << n32) (nrmDvsr >> n32) remMsb ir
  !!ir (remMsb := (AST.xthi 1<rt> remHi))
  !!ir (qh := (AST.ite remMsb (qh .- one) (qh)))
  helperRemAdd remHi remLo (nrmDvsr << n32) (nrmDvsr >> n32) remMsb ir
  !!ir (remHi := (remHi << n32) .| (remLo >> n32))
  !!ir (remLo := (remLo << n32))
  (* compute least significant quotient "digit";
     TAOCP: may be off by 0, +1, +2 *)
  !!ir (ql := AST.ite condGE numF (remHi ./ (nrmDvsr >> n32)))
  !!ir (q := (qh << n32) .| ql)
  (* compute remainder; correct quotient "digit" if remainder negative *)
  let struct (prodHi, prodLo) = mul64Bit q tdivisor ir
  !!ir (remLo := trax)
  !!ir (remHi := trdx)
  helperRemSub remHi remLo prodHi prodLo ir
  !!ir (remMsb := (AST.xthi 1<rt> remHi))
  !!ir (q := (AST.ite remMsb (q .- one) q))
  helperRemAdd remHi remLo tdivisor zero remMsb ir
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
    !!ir (rax := (AST.ite updateSign (AST.neg quotient) quotient))
    !!ir (rdx := (AST.ite updateSign (AST.neg remainder) remainder))
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
  let negRes = AST.lt q (AST.zext sz mask)
  let posRes = AST.gt q (AST.zext sz (mask .- (AST.num1 oprSize)))
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
  let divisor = transOneOpr ir false ins insLen ctxt
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
  let pHigh = hiSrc1 .* hiSrc2
  let pMid = (hiSrc1 .* loSrc2) .+ (loSrc1 .* hiSrc2)
  let pLow = (loSrc1 .* loSrc2)
  let high = pHigh .+ ((pMid .+ (pLow  >> n32)) >> n32)
  let low = pLow .+ ((pMid .& mask) << n32)
  !!ir (isSign := src1IsNeg <+> src2IsNeg)
  !!ir (tHigh := AST.ite isSign (AST.not high) high)
  !!ir (tLow := AST.ite isSign (AST.neg low) low)
  let carry = AST.ite (AST.``and`` isSign (AST.eq tLow zero)) one zero
  !!ir (tHigh := tHigh .+ carry)
  struct (tHigh, tLow)

let private oneOperandImul ctxt oprSize src ir =
  let sF = !.ctxt R.SF
  let shiftNum = RegType.toBitWidth oprSize
  match oprSize with
  | 8<rt> ->
    let mulSize = RegType.double oprSize
    let t = !+ir mulSize
    let cond = AST.sext mulSize (AST.xtlo oprSize t) == t
    !!ir (t := AST.sext mulSize (!.ctxt R.AL) .* AST.sext mulSize src)
    !!ir (dstAssign oprSize (!.ctxt R.AX) t)
    !!ir (sF := AST.extract t 1<rt> (shiftNum - 1))
    !!ir (!.ctxt R.CF := cond == AST.b0)
    !!ir (!.ctxt R.OF := cond == AST.b0)
  | 16<rt> | 32<rt> ->
    let mulSize = RegType.double oprSize
    let t = !+ir mulSize
    let cond = AST.sext mulSize (AST.xtlo oprSize t) == t
    let r1 = getRegOfSize ctxt oprSize grpEDX
    let r2 = getRegOfSize ctxt oprSize grpEAX
    !!ir (t := AST.sext mulSize r2 .* AST.sext mulSize src)
    !!ir (dstAssign oprSize r1 (AST.xthi oprSize t))
    !!ir (dstAssign oprSize r2 (AST.xtlo oprSize t))
    !!ir (sF := AST.extract t 1<rt> (shiftNum - 1))
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
    !!ir (sF := AST.extract high 1<rt> (shiftNum - 1))
    !!ir (!.ctxt R.CF := cond == AST.b0)
    !!ir (!.ctxt R.OF := cond == AST.b0)
  | _ -> raise InvalidOperandSizeException

let private operandsImul ctxt oprSize dst src1 src2 ir =
  match oprSize with
  | 8<rt> | 16<rt> | 32<rt> ->
    let doubleWidth = RegType.double oprSize
    let t = !+ir doubleWidth
    let cond = (AST.sext doubleWidth dst) != t
    !!ir (t := AST.sext doubleWidth src1 .* AST.sext doubleWidth src2)
    !!ir (dstAssign oprSize dst (AST.xtlo oprSize t))
    !!ir (!.ctxt R.SF := AST.xthi 1<rt> dst)
    !!ir (!.ctxt R.CF := cond)
    !!ir (!.ctxt R.OF := cond)
  | 64<rt> ->
    let struct (high, low) = imul64Bit src1 src2 ir
    !!ir (dstAssign oprSize dst low)
    let num0 = AST.num0 64<rt>
    let numF = numI64 0xFFFFFFFFFFFFFFFFL 64<rt>
    let cond = !+ir 1<rt>
    !!ir (cond := AST.ite (AST.xthi 1<rt> low) (high != numF) (high != num0))
    !!ir (!.ctxt R.SF := AST.xthi 1<rt> dst)
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
  !!ir (!.ctxt R.ZF := undefZF)
  !!ir (!.ctxt R.AF := undefAF)
  !!ir (!.ctxt R.PF := undefPF)
#endif
  !>ir insLen

let inc ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let dst = transOneOpr ir false ins insLen ctxt
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
  match transOneOpr ir false ins insLen ctxt with
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

let jcc ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let pc = getInstrPtr ctxt
  let jmpTarget = pc .+ transOneOpr ir false ins insLen ctxt
  let cond = getCondOfJcc ins ctxt
  let fallThrough = pc .+ numInsLen insLen ctxt
  !!ir (AST.intercjmp cond jmpTarget fallThrough)
  !>ir insLen

let jmp ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let pc = getInstrPtr ctxt
  let struct (target, _) = transJumpTargetOpr ir false ins pc insLen ctxt
  !!ir (AST.interjmp target InterJmpKind.Base)
  !>ir insLen

let private convertSrc = function
  | Load (_, _, expr, _) -> expr
  | _ -> Utils.impossible ()

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
  let di = !.ctxt (if is64bit ctxt then R.RDI else R.EDI)
  let dst = getRegOfSize ctxt oprSize grpEAX
  let amount = numI32 (RegType.toByteWidth oprSize) ctxt.WordBitSize
  !!ir (dst := AST.loadLE oprSize di)
  !!ir (di := AST.ite df (di .- amount) (di .+ amount))

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
  let dst = transOneOpr ir false ins insLen ctxt
  let addrSize = getEffAddrSz ins
  let pc = getInstrPtr ctxt
  let count, cntSize =
    if addrSize = 32<rt> then !.ctxt R.ECX, 32<rt>
    elif addrSize = 64<rt> then !.ctxt R.RCX, 64<rt>
    else !.ctxt R.CX, 16<rt>
  let zf = !.ctxt R.ZF
  !!ir (count := count .- AST.num1 cntSize)
  let branchCond =
    match ins.Opcode with
    | Opcode.LOOP -> count != AST.num0 cntSize
    | Opcode.LOOPE -> (zf == AST.b1) .& (count != AST.num0 cntSize)
    | Opcode.LOOPNE -> (zf == AST.b0) .& (count != AST.num0 cntSize)
    | _ -> raise InvalidOpcodeException
  let fallThrough = pc .+ numInsLen insLen ctxt
  let jumpTarget = if addrSize = 16<rt> then pc .& numI32 0xFFFF 32<rt>
                   else pc .+ AST.sext addrSize dst
  !!ir (AST.intercjmp branchCond jumpTarget fallThrough)
  !>ir insLen

let lzcnt ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let lblLoop = !%ir "Loop"
  let lblExit = !%ir "Exit"
  let lblLoopCond = !%ir "LoopCond"
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let n = AST.num0 oprSize
  let temp = !+ir oprSize
  !!ir (temp := numI32 (RegType.toBitWidth oprSize - 1) oprSize)
  !!ir (dst := n)
  !!ir (AST.lmark lblLoopCond)
  let cond1 = (AST.ge temp n) .& ((AST.xtlo 1<rt> (src >> temp)) == AST.b0)
  !!ir (AST.cjmp cond1 (AST.name lblLoop) (AST.name lblExit))
  !!ir (AST.lmark lblLoop)
  !!ir (temp := temp .- AST.num1 oprSize)
  !!ir (dst := dst .+ AST.num1 oprSize)
  !!ir (AST.jmp (AST.name lblLoopCond))
  !!ir (AST.lmark lblExit)
  let oprSize = numI32 (RegType.toBitWidth oprSize) oprSize
  !!ir (!.ctxt R.CF := dst == oprSize)
  !!ir (!.ctxt R.ZF := dst == n)
#if !EMULATION
  !!ir (!.ctxt R.OF := undefOF)
  !!ir (!.ctxt R.SF := undefSF)
  !!ir (!.ctxt R.PF := undefPF)
  !!ir (!.ctxt R.AF := undefAF)
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
  if hasREPZ ins.Prefixes then
    strRepeat ins insLen ctxt movsBody None ir
  elif hasREPNZ ins.Prefixes then Utils.impossible ()
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
    let dblWidth = RegType.double oprSize
    let src1 = AST.zext dblWidth (getRegOfSize ctxt oprSize grpEAX)
    let src2 = AST.zext dblWidth (transOneOpr ir false ins insLen ctxt)
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
#endif
  | 16<rt> | 32<rt> ->
    let dblWidth = RegType.double oprSize
    let edx = getRegOfSize ctxt oprSize grpEDX
    let eax = getRegOfSize ctxt oprSize grpEAX
    let src1 = AST.zext dblWidth eax
    let src2 = AST.zext dblWidth (transOneOpr ir false ins insLen ctxt)
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
#endif
  | 64<rt> ->
    let rax = getRegOfSize ctxt oprSize grpEAX
    let rdx = getRegOfSize ctxt oprSize grpEDX
    let src = transOneOpr ir false ins insLen ctxt
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
    !!ir (tHigh := high)
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
#endif
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let neg ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let dst = transOneOpr ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let t = !+ir oprSize
  let oFCond = t == (AST.num1 oprSize << (numU32 31u oprSize) )
  let sf = AST.xthi 1<rt> dst
  !!ir (t := dst)
  !!ir (dstAssign oprSize dst (AST.neg t))
  !!ir (!.ctxt R.CF := t != AST.num0 oprSize)
  !!ir (!.ctxt R.OF := oFCond)
  !?ir (enumASZPFlags ctxt t (AST.num0 oprSize) dst oprSize sf)
  !>ir insLen

let nop insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  !>ir insLen

let not ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let dst = transOneOpr ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  !!ir (dstAssign oprSize dst (AST.unop UnOpType.NOT dst))
  !>ir insLen

let logOr ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let t = !+ir oprSize
  let sf = AST.xthi 1<rt> t
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Lock) else ()
  !!ir (t := (dst .| AST.sext oprSize src))
  !!ir (dstAssign oprSize dst t)
  !!ir (!.ctxt R.CF := AST.b0)
  !!ir (!.ctxt R.OF := AST.b0)
#if !EMULATION
  !!ir (!.ctxt R.AF := undefAF)
#endif
  !?ir (enumSZPFlags ctxt t oprSize sf)
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
  let struct (dst, src, mask) = transThreeOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let tmp = !+ir oprSize
  for i in 0 .. (int oprSize) - 1 do
    let t = AST.extract src 1<rt> i
    let cond = AST.extract mask 1<rt> i
    !!ir (AST.extract tmp 1<rt> i := AST.ite cond (AST.b0) t)
  done
  !!ir (dst := tmp)
  !>ir insLen

let pext ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, mask) = transThreeOprs ir false ins insLen ctxt
  let oSz = getOperationSize ins
  let tmp = !+ir oSz
  for i in 0 .. (int oSz) - 1 do
    let t = (tmp << AST.num1 oSz) .| (AST.zext oSz (AST.extract src 1<rt> i))
    let cond = AST.extract mask 1<rt> i
    !!ir (tmp := AST.ite cond tmp t)
  done
  !!ir (dst := tmp)
  !>ir insLen

let pop ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let dst = transOneOpr ir false ins insLen ctxt
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
  let i = !+ir oprSize
  let count = !+ir oprSize
  !!ir (i := AST.num0 oprSize)
  !!ir (count := AST.num0 oprSize)
  !!ir (AST.lmark lblLoopCond)
  !!ir (AST.cjmp (AST.lt i max) (AST.name lblLoop) (AST.name lblExit))
  !!ir (AST.lmark lblLoop)
  let cond = (AST.xtlo 1<rt> (src >> i)) == AST.b1
  !!ir (count := AST.ite cond (count .+ AST.num1 oprSize) count)
  !!ir (i := i .+ AST.num1 oprSize)
  !!ir (AST.jmp (AST.name lblLoopCond))
  !!ir (AST.lmark lblExit)
  !!ir (dstAssign oprSize dst count)
  !!ir (!.ctxt R.OF := AST.b0)
  !!ir (!.ctxt R.SF := AST.b0)
  !!ir (!.ctxt R.ZF := src == AST.num0 oprSize)
  !!ir (!.ctxt R.AF := AST.b0)
  !!ir (!.ctxt R.CF := AST.b0)
  !!ir (!.ctxt R.PF := AST.b0)
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
  !>ir insLen

let inline private padPushExpr oprSize opr =
  match opr.E with
  | Var (_, s, _, _) ->
    if isSegReg <| Register.ofRegID s then AST.zext oprSize opr else opr
  | Num (_) -> AST.sext oprSize opr
  | _ -> opr

let push ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let src = transOneOpr ir false ins insLen ctxt
  let oprSize = getOperationSize ins
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
  let oprSize = getOperationSize ins
  let e = AST.zext oprSize <| !.ctxt R.CF
  (* We only consider 9 flags (we ignore system flags). *)
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
  let ir = !*ctxt
  !<ir insLen
  !?ir (auxPush oprSize ctxt e)
  !>ir insLen

let rcl ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, count) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let cF = !.ctxt R.CF
  let oF = !.ctxt R.OF
  let tmpCount = !+ir oprSize
  let size = numI32 (RegType.toBitWidth oprSize) oprSize
  let count = AST.zext oprSize count
  let cnt =
    match oprSize with
    | 8<rt> -> (count .& numI32 0x1f oprSize) .% numI32 9 oprSize
    | 16<rt> -> (count .& numI32 0x1f oprSize) .% numI32 17 oprSize
    | 32<rt> -> count .& numI32 0x1f oprSize
    | 64<rt> -> count .& numI32 0x3f oprSize
    | _ -> raise InvalidOperandSizeException
  let cond = count == AST.num1 oprSize
  !!ir (tmpCount := cnt)
  !!ir (dst := (dst << tmpCount) .| (dst >> (size .- tmpCount)))
  !!ir (cF := AST.xthi 1<rt> dst)
#if !EMULATION
  !!ir (oF := AST.ite cond (AST.xthi 1<rt> dst <+> cF) undefOF)
#else
  !!ir (oF := AST.ite cond (AST.xthi 1<rt> dst <+> cF) oF)
#endif
  !>ir insLen

let rcr ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, count) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let cF = !.ctxt R.CF
  let oF = !.ctxt R.OF
  let tmpCount = !+ir oprSize
  let size = numI32 (RegType.toBitWidth oprSize) oprSize
  let count = AST.zext oprSize count
  let cnt =
    match oprSize with
    | 8<rt> -> (count .& numI32 0x1f oprSize) .% numI32 9 oprSize
    | 16<rt> -> (count .& numI32 0x1f oprSize) .% numI32 17 oprSize
    | 32<rt> -> count .& numI32 0x1f oprSize
    | 64<rt> -> count .& numI32 0x3f oprSize
    | _ -> raise InvalidOperandSizeException
  let cond = count == AST.num1 oprSize
  !!ir (tmpCount := cnt)
#if !EMULATION
  !!ir (oF := AST.ite cond (AST.xthi 1<rt> dst <+> cF) undefOF)
#else
  !!ir (oF := AST.ite cond (AST.xthi 1<rt> dst <+> cF) oF)
#endif
  !!ir (dst := (dst >> tmpCount) .| (dst << (size .- tmpCount)))
  !!ir (cF := AST.xthi 1<rt> dst)
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
  let src = transOneOpr ir false ins insLen ctxt
  !?ir (auxPop oprSize ctxt t)
  !!ir (sp := sp .+ (AST.zext oprSize src))
  !!ir (AST.interjmp t InterJmpKind.IsRet)
  !>ir insLen

let ret ins insLen ctxt =
  let ir = !*ctxt
  let oprSize = getOperationSize ins
  let t = !+ir oprSize
  !<ir insLen
  !?ir (auxPop oprSize ctxt t)
  !!ir (AST.interjmp t InterJmpKind.IsRet)
  !>ir insLen

let rotate ins insLen ctxt lfn hfn cfFn ofFn =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, count) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let cF = !.ctxt R.CF
  let oF = !.ctxt R.OF
  let countMask = if is64REXW ctxt ins then numU32 0x3Fu oprSize
                  else numU32 0x1Fu oprSize
  let size = numI32 (RegType.toBitWidth oprSize) oprSize
  let orgCount = !+ir oprSize
  let cond1 = orgCount == AST.num0 oprSize
  let cond2 = orgCount == AST.num1 oprSize
  !!ir (orgCount := (AST.zext oprSize count .& countMask))
  !!ir (dst := (lfn dst orgCount) .| (hfn dst (size .- orgCount)))
  !!ir (cF := AST.ite cond1 cF (cfFn 1<rt> dst))
#if !EMULATION
  !!ir (oF := AST.ite cond2 (ofFn dst cF) undefOF)
#else
  !!ir (oF := AST.ite cond2 (ofFn dst cF) oF)
#endif
  !>ir insLen

let rol ins insLen ctxt =
  let ofFn dst cF = cF <+> AST.xthi 1<rt> dst
  rotate ins insLen ctxt (<<) (>>) AST.xtlo ofFn

let ror ins insLen ctxt =
  let ofFn dst _cF =
    AST.xthi 1<rt> dst <+> AST.extract dst 1<rt> 1
  rotate ins insLen ctxt (>>) (<<) AST.xthi ofFn

let rorx ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, imm) = transThreeOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let y = !+ir oprSize
  if oprSize = 32<rt> then
    !!ir (y := imm .& (numI32 0x1F oprSize))
    !!ir (dst := (src >> y) .| (src << (numI32 32 oprSize .- y)))
  else (* OperandSize = 64 *)
    !!ir (y := imm .& (numI32 0x3F oprSize))
    !!ir (dst := (src >> y) .| (src << (numI32 64 oprSize .- y)))
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
  !>ir insLen

let shift ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let n0 = AST.num0 oprSize
  let n1 = AST.num1 oprSize
  let countMask = if is64REXW ctxt ins then numU32 0x3Fu oprSize
                  else numU32 0x1Fu oprSize
  let cnt = (AST.zext oprSize src) .& countMask
  let cond1 = cnt == n1
  let cond2 = cnt == n0
  let oF = !.ctxt R.OF
  let cF = !.ctxt R.CF
  let sF = !.ctxt R.SF
  let zF = !.ctxt R.ZF
#if !EMULATION
  let aF = !.ctxt R.AF
#endif
  let tDst = !+ir oprSize
  let tCnt = !+ir oprSize
  !!ir (tDst := dst)
  match ins.Opcode with
  | Opcode.SAR ->
    let prevLBit = AST.xtlo 1<rt> (tDst ?>> tCnt)
    !!ir (dstAssign oprSize dst (tDst ?>> cnt))
    !!ir (tCnt := cnt .- n1)
    !!ir (cF := AST.ite cond2 cF prevLBit)
#if !EMULATION
    !!ir (oF := AST.ite cond1 AST.b0 (AST.ite cond2 oF undefOF))
#else
    !!ir (oF := AST.ite cond1 AST.b0 oF)
#endif
  | Opcode.SHL ->
    let prevHBit = AST.xthi 1<rt> (tDst << tCnt)
    let of1 = AST.xthi 1<rt> dst <+> cF
    !!ir (dstAssign oprSize dst (tDst << cnt))
    !!ir (tCnt := cnt .- n1)
    !!ir (cF := AST.ite cond2 cF prevHBit)
#if !EMULATION
    !!ir (oF := AST.ite cond1 of1 (AST.ite cond2 oF undefOF))
#else
    !!ir (oF := AST.ite cond1 of1 oF)
#endif
  | Opcode.SHR ->
    let prevLBit = AST.xtlo 1<rt> (tDst ?>> tCnt)
    !!ir (dstAssign oprSize dst (tDst >> cnt))
    !!ir (tCnt := cnt .- n1)
    !!ir (cF := AST.ite cond2 cF prevLBit)
#if !EMULATION
    !!ir
      (oF := AST.ite cond1 (AST.xthi 1<rt> tDst) (AST.ite cond2 oF undefOF))
#else
    !!ir (oF := AST.ite cond1 (AST.xthi 1<rt> tDst) oF)
#endif
  | _ -> raise InvalidOpcodeException
  !!ir (sF := AST.ite cond2 sF (AST.xthi 1<rt> dst))
  let tDst = !+ir oprSize
  !!ir (tDst := dst)
  !?ir (buildPF ctxt tDst oprSize (Some cond2))
  !!ir (zF := AST.ite cond2 zF (tDst == n0))
#if !EMULATION
  !!ir (aF := AST.ite cond2 aF undefAF)
#endif
  !>ir insLen

let sbb ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let struct (t1, t2, t3, t4) = tmpVars4 ir oprSize
  let cf = !.ctxt R.CF
  let sf = AST.xthi 1<rt> t4
  !!ir (t1 := dst)
  !!ir (t2 := AST.sext oprSize src)
  !!ir (t3 := t2 .+ AST.zext oprSize cf)
  !!ir (t4 := t1 .- t3)
  !!ir (dstAssign oprSize dst t4)
  !!ir (cf := (AST.lt t1 t3) .| (AST.lt t3 t2))
  !!ir (!.ctxt R.OF := ofOnSub t1 t2 t4)
  !?ir (enumASZPFlags ctxt t1 t2 t4 oprSize sf)
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

let setcc ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let dst = transOneOpr ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let cond = getCondOfSet ins ctxt |> AST.zext oprSize
  !!ir (dstAssign oprSize dst cond)
  !>ir insLen

let inline shiftDblPrec ins insLen ctxt fnDst fnSrc isShl =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, cnt) = transThreeOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let orig = !+ir oprSize
  let c = !+ir oprSize
  let cond1 = c == AST.num0 oprSize
  let cond2 = c == AST.num1 oprSize
  let cF = !.ctxt R.CF
  let oF = !.ctxt R.OF
  let aF = !.ctxt R.AF
  let maxSz = numI32 (if is64REXW ctxt ins then 64 else 32) oprSize
  let final = AST.ite cond1 orig ((fnDst orig c) .| (fnSrc src (maxSz .- c)))
  let sf = AST.xthi 1<rt> dst
  !!ir (orig := dst)
  !!ir (c := (AST.zext oprSize cnt) .% maxSz)
  !!ir (dstAssign oprSize dst final)
  !!ir (
    if isShl then
      cF := AST.ite cond1 cF (AST.xtlo 1<rt> (orig >> (maxSz .- c)))
    else
      cF := AST.ite cond1 cF (AST.xtlo 1<rt> (orig >> (c .- AST.num1 oprSize)))
  )
#if !EMULATION
  !!ir (oF := AST.ite cond1 oF
               (AST.ite cond2 (AST.xthi 1<rt> (orig <+> dst)) undefOF))
  !!ir (aF := AST.ite cond1 aF undefAF)
#else
  !!ir (oF := AST.ite cond1 oF
               (AST.ite cond2 (AST.xthi 1<rt> (orig <+> dst)) oF))
#endif
  !?ir (enumSZPFlags ctxt dst oprSize sf)
  !>ir insLen

let shld ins insLen ctxt =
  shiftDblPrec ins insLen ctxt (<<) (>>) true

let shrd ins insLen ctxt =
  shiftDblPrec ins insLen ctxt (>>) (<<) false

let shlx ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = transThreeOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let temp = !+ir oprSize
  let countMask = if is64REXW ctxt ins then 0x3F else 0x1F // FIXME: CS.L = 1
  let count = src2 .& (numI32 countMask oprSize)
  !!ir (temp := src1)
  !!ir (AST.xthi 1<rt> dst := AST.xthi 1<rt> temp)
  !!ir (dst := dst << count)
  !>ir insLen

let setFlag insLen ctxt flag =
  let ir = !*ctxt
  !<ir insLen
  !!ir (!.ctxt flag := AST.b1)
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
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  let sf = AST.xthi 1<rt> t3
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Lock) else ()
  !!ir (t1 := dst)
  !!ir (t2 := src)
  !!ir (t3 := t1 .- t2)
  !!ir (dstAssign oprSize dst t3)
  !?ir (enumEFLAGS ctxt t1 t2 t3 oprSize (cfOnSub t1 t2) (ofOnSub t1 t2 t3) sf)
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Unlock) else ()
  !>ir insLen

let test ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (src1, src2) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let t = !+ir oprSize
  if src1 = src2 then !!ir (t := src1)
  else !!ir (t := src1 .& src2)
  !!ir (!.ctxt R.SF := AST.xthi 1<rt> t)
  !!ir (!.ctxt R.ZF := t == (AST.num0 oprSize))
  !?ir (buildPF ctxt t oprSize None)
  !!ir (!.ctxt R.CF := AST.b0)
  !!ir (!.ctxt R.OF := AST.b0)
#if !EMULATION
  !!ir (!.ctxt R.AF := undefAF)
#endif
  !>ir insLen

let tzcnt ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let lblLoop = !%ir "Loop"
  let lblExit = !%ir "Exit"
  let lblLoopCond = !%ir "LoopCond"
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let max = numI32 (RegType.toBitWidth oprSize) oprSize
  let t1 = !+ir oprSize
  !!ir (t1 := AST.num0 oprSize)
  !!ir (AST.lmark lblLoopCond)
  let cond = (AST.lt t1 max) .& (AST.xtlo 1<rt> (src >> t1) == AST.b0)
  !!ir (AST.cjmp cond (AST.name lblLoop) (AST.name lblExit))
  !!ir (AST.lmark lblLoop)
  !!ir (t1 := t1 .+ AST.num1 oprSize)
  !!ir (AST.jmp (AST.name lblLoopCond))
  !!ir (AST.lmark lblExit)
  !!ir (dstAssign oprSize dst t1)
  !!ir (!.ctxt R.CF := dst == max)
  !!ir (!.ctxt R.ZF := dst == AST.num0 oprSize)
#if !EMULATION
  !!ir (!.ctxt R.OF := undefOF)
  !!ir (!.ctxt R.SF := undefSF)
  !!ir (!.ctxt R.PF := undefPF)
  !!ir (!.ctxt R.AF := undefAF)
#endif
  !>ir insLen

let wrfsbase ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let src = transOneOpr ir false ins insLen ctxt
  !!ir (!.ctxt R.FSBase := AST.zext ctxt.WordBitSize src)
  !>ir insLen

let wrgsbase ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let src = transOneOpr ir false ins insLen ctxt
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
  let struct (d, s) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let t = !+ir oprSize
  let sf = AST.xthi 1<rt> t
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Lock) else ()
  !!ir (t := s .+ d)
  !!ir (dstAssign oprSize s d)
  !!ir (dstAssign oprSize d t)
  let struct (ofl, sf) = osfOnAdd d s t ir
  !?ir (enumEFLAGS ctxt d s t oprSize (cfOnSub d s) ofl sf)
  if hasLock ins.Prefixes then !!ir (AST.sideEffect Unlock) else ()
  !>ir insLen

let xchg ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
  if dst <> src then
    let oprSize = getOperationSize ins
    let t = !+ir oprSize
    !!ir (t := dst)
    !!ir (dstAssign oprSize dst src)
    !!ir (dstAssign oprSize src t)
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
  let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let r = !+ir oprSize
  !!ir (r := dst <+> AST.sext oprSize src)
  !!ir (dstAssign oprSize dst r)
  !!ir (!.ctxt R.OF := AST.b0)
  !!ir (!.ctxt R.CF := AST.b0)
  !!ir (!.ctxt R.SF := AST.xthi 1<rt> r)
  !!ir (!.ctxt R.ZF := r == (AST.num0 oprSize))
  !?ir (buildPF ctxt r oprSize None)
#if !EMULATION
  !!ir (!.ctxt R.AF := undefAF)
#endif
  !>ir insLen
