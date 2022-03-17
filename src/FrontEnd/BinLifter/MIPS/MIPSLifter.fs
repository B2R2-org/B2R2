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

module internal B2R2.FrontEnd.BinLifter.MIPS.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.BinLifter.MIPS

let inline getRegVar (ctxt: TranslationContext) name =
  Register.toRegID name |> ctxt.GetRegVar

let inline private (<!) (builder: IRBuilder) (s) = builder.Append (s)

let startMark insInfo (builder: IRBuilder) =
  builder <! (AST.ismark (insInfo.NumBytes))

let endMark insInfo (builder: IRBuilder) =
  builder <! (AST.iemark (insInfo.NumBytes)); builder

let bvOfBaseAddr (ctxt: TranslationContext) addr = numU64 addr ctxt.WordBitSize

let bvOfInstrLen (ctxt: TranslationContext) insInfo =
  numU32 insInfo.NumBytes ctxt.WordBitSize

let transOprToExpr insInfo ctxt = function
  | OpReg reg -> getRegVar ctxt reg
  | OpImm imm
  | OpShiftAmount imm -> numU64 imm ctxt.WordBitSize
  | OpMem (b, Imm o, sz) ->
    AST.loadLE sz (getRegVar ctxt b .+ numI64 o ctxt.WordBitSize)
  | OpMem (b, Reg o, sz) ->
    AST.loadLE sz (getRegVar ctxt b .+ getRegVar ctxt o)
  | OpAddr (Relative o) ->
    numI64 (int64 insInfo.Address + o + int64 insInfo.NumBytes) ctxt.WordBitSize
    |> AST.loadLE ctxt.WordBitSize
  | GoToLabel _ -> raise InvalidOperandException

let transOprToImm = function
  | OpImm imm
  | OpShiftAmount imm -> imm
  | _ -> raise InvalidOperandException

let transOprToBaseOffset ctxt = function
  | OpMem (b, Imm o, _) -> getRegVar ctxt b .+ numI64 o ctxt.WordBitSize
  | OpMem (b, Reg o, _) -> getRegVar ctxt b .+ getRegVar ctxt o
  | _ -> raise InvalidOperandException

let getOneOpr insInfo =
  match insInfo.Operands with
  | OneOperand opr -> opr
  | _ -> raise InvalidOperandException

let getTwoOprs insInfo =
  match insInfo.Operands with
  | TwoOperands (o1, o2) -> o1, o2
  | _ -> raise InvalidOperandException

let getThreeOprs insInfo =
  match insInfo.Operands with
  | ThreeOperands (o1, o2, o3) -> o1, o2, o3
  | _ -> raise InvalidOperandException

let getFourOprs insInfo =
  match insInfo.Operands with
  | FourOperands (o1, o2, o3, o4) -> o1, o2, o3, o4
  | _ -> raise InvalidOperandException

let transOneOpr insInfo ctxt opr =
  transOprToExpr insInfo ctxt opr

let transTwoOprs insInfo ctxt (o1, o2) =
  transOprToExpr insInfo ctxt o1, transOprToExpr insInfo ctxt o2

let transThreeOprs insInfo ctxt (o1, o2, o3) =
  transOprToExpr insInfo ctxt o1,
  transOprToExpr insInfo ctxt o2,
  transOprToExpr insInfo ctxt o3

let sideEffects insInfo name =
  let builder = IRBuilder (4)
  startMark insInfo builder
  builder <! (AST.sideEffect name)
  endMark insInfo builder

let checkOverfolwOnAdd e1 e2 r =
  let e1High = AST.extract e1 1<rt> 31
  let e2High = AST.extract e2 1<rt> 31
  let rHigh = AST.extract r 1<rt> 31
  (e1High == e2High) .& (e1High <+> rHigh)

let notWordValue v =
  (AST.xthi 32<rt> v) != AST.sext 32<rt> (AST.extract v 1<rt> 31)

let add insInfo ctxt =
  let builder = IRBuilder (8)
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblEnd = builder.NewSymbol "End"
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = builder.NewTempVar 32<rt>
  let cond = checkOverfolwOnAdd rs rt result
  startMark insInfo builder
  builder <! (result := rs .+ rt)
  builder <! (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
  builder <! (AST.lmark lblL0)
  builder <! (AST.sideEffect UndefinedInstr) (* FIXME: (SignalException(IntegerOverflow)) *)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (rd := result)
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let add64 insInfo ctxt =
  let builder = IRBuilder (16)
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblL2 = builder.NewSymbol "L2"
  let lblL3 = builder.NewSymbol "L3"
  let lblEnd = builder.NewSymbol "End"
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = builder.NewTempVar 32<rt>
  let cond = notWordValue rs .| notWordValue rt
  let cond2 = checkOverfolwOnAdd rs rt result
  startMark insInfo builder
  builder <! (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
  builder <! (AST.lmark lblL0)
  builder <! (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (result := AST.xtlo 32<rt> rs .+ AST.xtlo 32<rt> rt)
  builder <! (AST.cjmp cond2 (AST.name lblL2) (AST.name lblL3))
  builder <! (AST.lmark lblL0)
  builder <! (AST.sideEffect UndefinedInstr) (* FIXME: (SignalException(IntegerOverflow)) *)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (rd := AST.sext 64<rt> result)
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let addiu insInfo ctxt =
  let builder = IRBuilder (4)
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = builder.NewTempVar 32<rt>
  startMark insInfo builder
  builder <! (result := rs .+ imm)
  builder <! (rt := result)
  endMark insInfo builder

let addiu64 insInfo ctxt =
  let builder = IRBuilder (16)
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblEnd = builder.NewSymbol "End"
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = builder.NewTempVar 64<rt>
  let cond = notWordValue rs
  startMark insInfo builder
  builder <! (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
  builder <! (AST.lmark lblL0)
  builder <! (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (result := rs .+ imm)
  builder <! (rt := AST.sext 64<rt> (AST.xtlo 32<rt> result))
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let addu insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := rs .+ rt)
  endMark insInfo builder

let addu64 insInfo ctxt =
  let builder = IRBuilder (16)
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblEnd = builder.NewSymbol "End"
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = builder.NewTempVar 64<rt>
  let cond = notWordValue rs .| notWordValue rt
  startMark insInfo builder
  builder <! (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
  builder <! (AST.lmark lblL0)
  builder <! (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (result := rs .+ rt)
  builder <! (rd := AST.sext 64<rt> (AST.xtlo 32<rt> result))
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let logAnd insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := rs .& rt)
  endMark insInfo builder

let andi insInfo ctxt =
  let builder = IRBuilder (4)
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rt := rs .& imm)
  endMark insInfo builder

let aui insInfo ctxt =
  let builder = IRBuilder (4)
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let imm = imm << numI32 16 ctxt.WordBitSize
  startMark insInfo builder
  builder <! (rt := rs .+ imm)
  endMark insInfo builder

let b insInfo ctxt =
  let builder = IRBuilder (4)
  let offset = getOneOpr insInfo |> transOneOpr insInfo ctxt
  startMark insInfo builder
  builder <! (AST.interjmp offset InterJmpKind.Base)
  endMark insInfo builder

let bal insInfo ctxt =
  let builder = IRBuilder (4)
  let offset = getOneOpr insInfo |> transOneOpr insInfo ctxt
  let pc = getRegVar ctxt R.PC
  startMark insInfo builder
  builder <! (getRegVar ctxt R.R31 := pc .+ numI32 8 ctxt.WordBitSize)
  builder <! (AST.interjmp offset InterJmpKind.IsCall)
  endMark insInfo builder

let beq insInfo ctxt =
  let builder = IRBuilder (4)
  let rs, rt, offset = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = rs == rt
  let fallThrough =
    bvOfBaseAddr ctxt insInfo.Address .+ bvOfInstrLen ctxt insInfo
  startMark insInfo builder
  builder <! (AST.intercjmp cond offset fallThrough)
  endMark insInfo builder

let blez insInfo ctxt =
  let builder = IRBuilder (4)
  let rs, offset = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let cond = AST.le rs (AST.num0 ctxt.WordBitSize)
  let fallThrough =
    bvOfBaseAddr ctxt insInfo.Address .+ bvOfInstrLen ctxt insInfo
  startMark insInfo builder
  builder <! (AST.intercjmp cond offset fallThrough)
  endMark insInfo builder

let bltz insInfo ctxt =
  let builder = IRBuilder (4)
  let rs, offset = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let cond = AST.lt rs (AST.num0 ctxt.WordBitSize)
  let fallThrough =
    bvOfBaseAddr ctxt insInfo.Address .+ bvOfInstrLen ctxt insInfo
  startMark insInfo builder
  builder <! (AST.intercjmp cond offset fallThrough)
  endMark insInfo builder

let bgez insInfo ctxt =
  let builder = IRBuilder (4)
  let rs, offset = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let cond = AST.ge rs (AST.num0 ctxt.WordBitSize)
  let fallThrough =
    bvOfBaseAddr ctxt insInfo.Address .+ bvOfInstrLen ctxt insInfo
  startMark insInfo builder
  builder <! (AST.intercjmp cond offset fallThrough)
  endMark insInfo builder

let bgtz insInfo ctxt =
  let builder = IRBuilder (4)
  let rs, offset = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let cond = AST.gt rs (AST.num0 ctxt.WordBitSize)
  let fallThrough =
    bvOfBaseAddr ctxt insInfo.Address .+ bvOfInstrLen ctxt insInfo
  startMark insInfo builder
  builder <! (AST.intercjmp cond offset fallThrough)
  endMark insInfo builder

let bne insInfo ctxt =
  let builder = IRBuilder (4)
  let rs, rt, offset = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = rs != rt
  let fallThrough =
    bvOfBaseAddr ctxt insInfo.Address .+ bvOfInstrLen ctxt insInfo
  startMark insInfo builder
  builder <! (AST.intercjmp cond offset fallThrough)
  endMark insInfo builder

let clz insInfo (ctxt: TranslationContext) =
  let builder = IRBuilder (16)
  let lblLoop = builder.NewSymbol "Loop"
  let lblContinue = builder.NewSymbol "Continue"
  let lblUpdate = builder.NewSymbol "update"
  let lblEnd = builder.NewSymbol "End"
  let wordSz = ctxt.WordBitSize
  let rd, rs = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let t = builder.NewTempVar wordSz
  let tmp = numI32 (32 - 1) wordSz
  startMark insInfo builder
  builder <! (t := tmp)
  builder <! (AST.lmark lblLoop)
  builder <! (AST.cjmp (rs >> t == AST.num1 wordSz)
                       (AST.name lblEnd) (AST.name lblContinue))
  builder <! (AST.lmark lblContinue)
  builder <! (AST.cjmp (t == AST.num0 wordSz)
                       (AST.name lblEnd) (AST.name lblUpdate))
  builder <! (AST.lmark lblUpdate)
  builder <! (t := t .- AST.num1 wordSz)
  builder <! (AST.jmp (AST.name lblLoop))
  builder <! (AST.lmark lblEnd)
  builder <! (rd := t)
  endMark insInfo builder

let daddiu insInfo ctxt =
  let builder = IRBuilder (4)
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = builder.NewTempVar 64<rt>
  startMark insInfo builder
  builder <! (result := rs .+ imm)
  builder <! (rt := result)
  endMark insInfo builder

let dclz insInfo (ctxt: TranslationContext) =
  let builder = IRBuilder (16)
  let lblLoop = builder.NewSymbol "Loop"
  let lblContinue = builder.NewSymbol "Continue"
  let lblUpdate = builder.NewSymbol "update"
  let lblEnd = builder.NewSymbol "End"
  let wordSz = ctxt.WordBitSize
  let rd, rs = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let t = builder.NewTempVar wordSz
  let tmp = numI32 (64 - 1) wordSz
  startMark insInfo builder
  builder <! (t := tmp)
  builder <! (AST.lmark lblLoop)
  builder <! (AST.cjmp (rs >> t == AST.num1 wordSz)
                       (AST.name lblEnd) (AST.name lblContinue))
  builder <! (AST.lmark lblContinue)
  builder <! (AST.cjmp (t == AST.num0 wordSz)
                       (AST.name lblEnd) (AST.name lblUpdate))
  builder <! (AST.lmark lblUpdate)
  builder <! (t := t .- AST.num1 wordSz)
  builder <! (AST.jmp (AST.name lblLoop))
  builder <! (AST.lmark lblEnd)
  builder <! (rd := t)
  endMark insInfo builder

let ddivu insInfo ctxt =
  let builder = IRBuilder (16)
  startMark insInfo builder
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let q = builder.NewTempVar 128<rt>
  let r = builder.NewTempVar 128<rt>
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  let rs = AST.zext 128<rt> rs
  let rt = AST.zext 128<rt> rt
  builder <! (q := rs ./ rt)
  builder <! (r := rs .% rt)
  builder <! (lo := AST.xtlo 64<rt> q)
  builder <! (hi := AST.xtlo 64<rt> r)
  endMark insInfo builder

let checkDEXTPosSize pos size =
  let posSize = pos + size
  if 0 <= pos && pos < 32 &&
     0 < size && size <= 32 &&
     0 < posSize && posSize <= 63 then ()
  else  raise InvalidOperandException

let dext insInfo ctxt =
  let builder = IRBuilder (16)
  startMark insInfo builder
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = int32 (transOprToImm pos)
  let size = int32 (transOprToImm size)
  checkDEXTPosSize pos size
  let getMask size = (1L <<< size) - 1L
  let mask = numI64 (getMask size) ctxt.WordBitSize
  let rs = if pos = 0 then rs else rs >> numI32 pos ctxt.WordBitSize
  builder <! (rt :=  mask .& rs)
  endMark insInfo builder

let checkDEXTMPosSize pos size =
  let posSize = pos + size
  if 0 <= pos && pos < 32 &&
     32 < size && size <= 64 &&
     32 < posSize && posSize <= 64 then ()
  else  raise InvalidOperandException

let checkDEXTUPosSize pos size =
  let posSize = pos + size
  if 32 <= pos && pos < 64 &&
     0 < size && size <= 32 &&
     32 < posSize && posSize <= 64 then ()
  else  raise InvalidOperandException

let dextx insInfo posSizeCheckFn ctxt =
  let builder = IRBuilder (16)
  startMark insInfo builder
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = int32 (transOprToImm pos)
  let sz = int32 (transOprToImm size)
  posSizeCheckFn pos sz
  if sz = 64 then if rt = rs then () else builder <! (rt := rs)
  else
    let getMask size = (1L <<< size) - 1L
    let rs = if pos = 0 then rs else rs >> numI32 pos ctxt.WordBitSize
    let rs = if sz = 64 then rs else rs .& numI64 (getMask sz) ctxt.WordBitSize
    builder <! (rt :=  rs)
  endMark insInfo builder

let checkINSorExtPosSize pos size =
  let posSize = pos + size
  if 0 <= pos && pos < 32 &&
     0 < size && size <= 32 &&
     0 < posSize && posSize <= 32 then ()
  else raise InvalidOperandException

let dins insInfo ctxt =
  let builder = IRBuilder (16)
  startMark insInfo builder
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = int32 (transOprToImm pos)
  let size = int32 (transOprToImm size)
  checkINSorExtPosSize pos size
  if pos = 0 && rt = rs then ()
  else
    let posExpr = numI32 pos ctxt.WordBitSize
    let getMask size = (1L <<< size) - 1L
    let mask = numI64 (getMask size) ctxt.WordBitSize
    let rs', rt' =
      if pos = 0 then rs .& mask, rt .& (AST.not mask)
      else (rs .& mask) << posExpr, rt .& (AST.not (mask << posExpr))
    builder <! (rt := rt' .| rs')
  endMark insInfo builder

let checkDINSMPosSize pos size =
  let posSize = pos + size
  if 0 <= pos && pos < 32 &&
     2 < size && size <= 64 &&
     32 < posSize && posSize <= 64 then ()
  else raise InvalidOperandException

let checkDINSUPosSize pos size =
  let posSize = pos + size
  if 32 <= pos && pos < 64 &&
     1 <= size && size <= 32 &&
     32 < posSize && posSize <= 64 then ()
  else raise InvalidOperandException

let dinsx insInfo posSizeCheckFn ctxt =
  let builder = IRBuilder (16)
  startMark insInfo builder
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = int32 (transOprToImm pos)
  let size = int32 (transOprToImm size)
  posSizeCheckFn pos size
  if size = 64 then if rt = rs then () else builder <! (rt := rs)
  else
    let posExpr = numI32 pos ctxt.WordBitSize
    let getMask size = (1L <<< size) - 1L
    let mask = numI64 (getMask size) ctxt.WordBitSize
    let rs', rt' =
      if pos = 0 then rs .& mask, rt .& (AST.not mask)
      else (rs .& mask) << posExpr, rt .& (AST.not (mask << posExpr))
    builder <! (rt := rt' .| rs')
  endMark insInfo builder

let divu insInfo ctxt =
  let builder = IRBuilder (16)
  startMark insInfo builder
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let q = builder.NewTempVar 64<rt>
  let r = builder.NewTempVar 64<rt>
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  if ctxt.WordBitSize = 64<rt> then
    let lblL0 = builder.NewSymbol "L0"
    let lblL1 = builder.NewSymbol "L1"
    let lblEnd = builder.NewSymbol "End"
    let cond = notWordValue rs .| notWordValue rt
    let mask = numI64 0xFFFFFFFFL 64<rt>
    let rs = rs .& mask
    let rt = rt .& mask
    builder <! (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
    builder <! (AST.lmark lblL0)
    builder <! (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
    builder <! (AST.jmp (AST.name lblEnd))
    builder <! (AST.lmark lblL1)
    builder <! (q := rs ./ rt)
    builder <! (r := rs .% rt)
    builder <! (lo := AST.sext 64<rt> (AST.xtlo 32<rt> q))
    builder <! (hi := AST.sext 64<rt> (AST.xtlo 32<rt> r))
    builder <! (AST.lmark lblEnd)
  else
    let rs = AST.zext 64<rt> rs
    let rt = AST.zext 64<rt> rt
    builder <! (q := rs ./ rt)
    builder <! (r := rs .% rt)
    builder <! (lo := AST.xtlo 32<rt> q)
    builder <! (hi := AST.xtlo 32<rt> r)
  endMark insInfo builder

let dmult insInfo ctxt =
  let builder = IRBuilder (16)
  startMark insInfo builder
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let result = builder.NewTempVar 128<rt>
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  builder <! (result := (AST.sext 128<rt> rs) .* (AST.sext 128<rt> rt))
  builder <! (lo := AST.xtlo 64<rt> result)
  builder <! (hi := AST.xthi 64<rt> result)
  endMark insInfo builder

let dmultu insInfo ctxt =
  let builder = IRBuilder (16)
  startMark insInfo builder
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let result = builder.NewTempVar 128<rt>
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  builder <! (result := (AST.zext 128<rt> rs) .* (AST.zext 128<rt> rt))
  builder <! (lo := AST.xtlo 64<rt> result)
  builder <! (hi := AST.xthi 64<rt> result)
  endMark insInfo builder

let drotr insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rt, sa = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let size = numI32 64 64<rt>
  startMark insInfo builder
  builder <! (rd := (rt << (size .- sa)) .| (rt >> sa))
  endMark insInfo builder

let dsll insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rt, sa = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  if sa = AST.num0 ctxt.WordBitSize then builder <! (rd := rt)
  else builder <! (rd := rt << sa)
  endMark insInfo builder

let dsll32 insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rt, sa = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let sa = sa .+ numI32 32 64<rt>
  startMark insInfo builder
  builder <! (rd := rt << sa)
  endMark insInfo builder

let dsllv insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rt, rs = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := rt << (rs .& numI32 63 64<rt>))
  endMark insInfo builder

let dsra insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rt, sa = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  if sa = AST.num0 ctxt.WordBitSize then builder <! (rd := rt)
  else builder <! (rd := rt ?>> sa)
  endMark insInfo builder

let dsra32 insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rt, sa = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let sa = sa .+ numI32 32 64<rt>
  startMark insInfo builder
  builder <! (rd := rt ?>> sa)
  endMark insInfo builder

let dsrl insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rt, sa = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  if sa = AST.num0 ctxt.WordBitSize then builder <! (rd := rt)
  else builder <! (rd := rt >> sa)
  endMark insInfo builder

let dsrl32 insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rt, sa = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let sa = sa .+ numI32 32 64<rt>
  startMark insInfo builder
  builder <! (rd := rt >> sa)
  endMark insInfo builder

let dsrlv insInfo ctxt =
  let builder = IRBuilder (16)
  let rd, rt, rs = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := rt >> (rs .& numI32 63 64<rt>))
  endMark insInfo builder

let ins insInfo ctxt =
  let builder = IRBuilder (16)
  startMark insInfo builder
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = int32 (transOprToImm pos)
  let size = int32 (transOprToImm size)
  checkINSorExtPosSize pos size
  if size = 32 then if rt = rs then () else builder <! (rt := rs)
  else
    let posExpr = numI32 pos ctxt.WordBitSize
    let getMask size = (1L <<< size) - 1L
    let mask = numI64 (getMask size) ctxt.WordBitSize
    let rs', rt' =
      if pos = 0 then rs .& mask, rt .& (AST.not mask)
      else (rs .& mask) << posExpr, rt .& (AST.not (mask << posExpr))
    builder <! (rt := rt' .| rs')
  endMark insInfo builder

let ins64 insInfo ctxt =
  let builder = IRBuilder (16)
  startMark insInfo builder
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = int32 (transOprToImm pos)
  let size = int32 (transOprToImm size)
  checkINSorExtPosSize pos size
  let posExpr = numI32 pos ctxt.WordBitSize
  let getMask size = (1L <<< size) - 1L
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblEnd = builder.NewSymbol "End"
  let cond = notWordValue rs .| notWordValue rt
  builder <! (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
  builder <! (AST.lmark lblL0)
  builder <! (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  let mask = numI64 (getMask size) ctxt.WordBitSize
  let rs', rt' = if pos = 0 then rs .& mask, rt .& (AST.not mask)
                 else (rs .& mask) << posExpr, rt .& (AST.not (mask << posExpr))
  builder <! (rt := rt' .| rs')
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let getJALROprs insInfo ctxt =
  match insInfo.Operands with
  | OneOperand opr -> getRegVar ctxt R.R31, transOprToExpr insInfo ctxt opr
  | TwoOperands (o1, o2) ->
    transOprToExpr insInfo ctxt o1, transOprToExpr insInfo ctxt o2
  | _ -> raise InvalidOperandException

let jalr insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs = getJALROprs insInfo ctxt
  let r = bvOfBaseAddr ctxt insInfo.Address .+ bvOfInstrLen ctxt insInfo
  startMark insInfo builder
  builder <! (rd := r)
  builder <! (AST.interjmp rs InterJmpKind.IsCall)
  endMark insInfo builder

let jr insInfo ctxt =
  let builder = IRBuilder (4)
  let rs = getOneOpr insInfo |> transOneOpr insInfo ctxt
  startMark insInfo builder
  builder <! (AST.interjmp rs InterJmpKind.Base)
  endMark insInfo builder

let load insInfo ctxt =
  let builder = IRBuilder (4)
  let rt, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rt := AST.sext ctxt.WordBitSize mem)
  endMark insInfo builder

let loadu insInfo ctxt =
  let builder = IRBuilder (4)
  let rt, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rt := AST.zext ctxt.WordBitSize mem)
  endMark insInfo builder

let ext insInfo ctxt =
  let builder = IRBuilder (4)
  startMark insInfo builder
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = int32 (transOprToImm pos)
  let size = int32 (transOprToImm size)
  let getMask size = (1L <<< size) - 1L
  checkINSorExtPosSize pos size
  if size = 32 then if rt = rs then () else  builder <! (rt := rs)
  else let rs = if pos = 0 then rs else rs >> numI32 pos ctxt.WordBitSize
       builder <! (rt := rs .& numI64 (getMask size) ctxt.WordBitSize)
  endMark insInfo builder

let ext64 insInfo ctxt =
  let builder = IRBuilder (16)
  startMark insInfo builder
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = int32 (transOprToImm pos)
  let size = int32 (transOprToImm size)
  let getMask size = (1L <<< size) - 1L
  checkINSorExtPosSize pos size
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblEnd = builder.NewSymbol "End"
  let cond = notWordValue rs
  builder <! (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
  builder <! (AST.lmark lblL0)
  builder <! (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  if size = 32 then if rt = rs then () else  builder <! (rt := rs)
  else let rs = if pos = 0 then rs else rs >> numI32 pos ctxt.WordBitSize
       builder <! (rt := rs .& numI64 (getMask size) ctxt.WordBitSize)
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let lui insInfo ctxt =
  let builder = IRBuilder (4)
  let rt, imm = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  startMark insInfo builder
  if ctxt.WordBitSize = 64<rt> then
    builder <!
      (rt := AST.sext 64<rt> (AST.concat (AST.xtlo 16<rt> imm) (AST.num0 16<rt>)))
  else builder <! (rt := AST.concat (AST.xtlo 16<rt> imm) (AST.num0 16<rt>))
  endMark insInfo builder

let madd insInfo ctxt =
  let builder = IRBuilder (16)
  startMark insInfo builder
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let result = builder.NewTempVar 64<rt>
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  if ctxt.WordBitSize = 64<rt> then
    let lblL0 = builder.NewSymbol "L0"
    let lblL1 = builder.NewSymbol "L1"
    let lblEnd = builder.NewSymbol "End"
    let cond = notWordValue rs .| notWordValue rt
    let hilo = AST.concat (AST.xtlo 32<rt> hi) (AST.xtlo 32<rt> lo)
    let mask = numU32 0xFFFFu 64<rt>
    builder <! (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
    builder <! (AST.lmark lblL0)
    builder <! (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
    builder <! (AST.jmp (AST.name lblEnd))
    builder <! (AST.lmark lblL1)
    builder <! (result := hilo .+ ((rs .& mask) .* (rt .& mask)))
    builder <! (hi := AST.sext 64<rt> (AST.xthi 32<rt> result))
    builder <! (lo := AST.sext 64<rt> (AST.xtlo 32<rt> result))
    builder <! (AST.lmark lblEnd)
  else
    builder <! (result := (AST.concat hi lo) .+ (AST.sext 64<rt> rs .* AST.sext 64<rt> rt))
    builder <! (hi := AST.xthi 32<rt> result)
    builder <! (lo := AST.xtlo 32<rt> result)
  endMark insInfo builder

let mfhi insInfo ctxt =
  let builder = IRBuilder (4)
  let rd = getOneOpr insInfo |> transOneOpr insInfo ctxt
  startMark insInfo builder
  builder <! (rd := getRegVar ctxt R.HI)
  endMark insInfo builder

let mflo insInfo ctxt =
  let builder = IRBuilder (4)
  let rd = getOneOpr insInfo |> transOneOpr insInfo ctxt
  startMark insInfo builder
  builder <! (rd := getRegVar ctxt R.LO)
  endMark insInfo builder

let movz insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = rt == AST.num0 ctxt.WordBitSize
  startMark insInfo builder
  builder <! (rd := AST.ite cond rs rd)
  endMark insInfo builder

let movn insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = rt != AST.num0 ctxt.WordBitSize
  startMark insInfo builder
  builder <! (rd := AST.ite cond rs rd)
  endMark insInfo builder

let mul insInfo ctxt =
  let builder = IRBuilder (16)
  startMark insInfo builder
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = builder.NewTempVar 64<rt>
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  if ctxt.WordBitSize = 64<rt> then
    let lblL0 = builder.NewSymbol "L0"
    let lblL1 = builder.NewSymbol "L1"
    let lblEnd = builder.NewSymbol "End"
    let cond = notWordValue rs .| notWordValue rt
    builder <! (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
    builder <! (AST.lmark lblL0)
    builder <! (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
    builder <! (AST.jmp (AST.name lblEnd))
    builder <! (AST.lmark lblL1)
    builder <! (result := rs .* rt)
    builder <! (rd := AST.sext 64<rt> (AST.xtlo 32<rt> result))
    builder <! (AST.lmark lblEnd)
  else
    builder <! (result := (AST.sext 64<rt> rs .* AST.sext 64<rt> rt))
    builder <! (rd := AST.xtlo 32<rt> result)
  builder <! (hi := AST.undef ctxt.WordBitSize "UNPREDICTABLE")
  builder <! (lo := AST.undef ctxt.WordBitSize "UNPREDICTABLE")
  endMark insInfo builder

let mult insInfo ctxt =
  let builder = IRBuilder (16)
  startMark insInfo builder
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let result = builder.NewTempVar 64<rt>
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  if ctxt.WordBitSize = 64<rt> then
    let lblL0 = builder.NewSymbol "L0"
    let lblL1 = builder.NewSymbol "L1"
    let lblEnd = builder.NewSymbol "End"
    let cond = notWordValue rs .| notWordValue rt
    let mask = numI64 0xFFFFFFFFL 64<rt>
    builder <! (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
    builder <! (AST.lmark lblL0)
    builder <! (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
    builder <! (AST.jmp (AST.name lblEnd))
    builder <! (AST.lmark lblL1)
    builder <! (result := (rs .& mask) .* (rt .& mask))
    builder <! (lo := AST.sext 64<rt> (AST.xtlo 32<rt> result))
    builder <! (hi := AST.sext 64<rt> (AST.xthi 32<rt> result))
    builder <! (AST.lmark lblEnd)
  else
    builder <! (result := (AST.sext 64<rt> rs .* AST.sext 64<rt> rt))
    builder <! (lo := AST.xtlo 32<rt> result)
    builder <! (hi := AST.xthi 32<rt> result)
  endMark insInfo builder

let multu insInfo ctxt =
  let builder = IRBuilder (16)
  startMark insInfo builder
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let result = builder.NewTempVar 64<rt>
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  if ctxt.WordBitSize = 64<rt> then
    let lblL0 = builder.NewSymbol "L0"
    let lblL1 = builder.NewSymbol "L1"
    let lblEnd = builder.NewSymbol "End"
    let cond = notWordValue rs .| notWordValue rt
    let mask = numI64 0xFFFFFFFFL 64<rt>
    builder <! (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
    builder <! (AST.lmark lblL0)
    builder <! (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
    builder <! (AST.jmp (AST.name lblEnd))
    builder <! (AST.lmark lblL1)
    builder <! (result := (rs .& mask) .* (rt .& mask))
    builder <! (lo := AST.sext 64<rt> (AST.xtlo 32<rt> result))
    builder <! (hi := AST.sext 64<rt> (AST.xthi 32<rt> result))
    builder <! (AST.lmark lblEnd)
  else
    builder <! (result := (AST.zext 64<rt> rs .* AST.zext 64<rt> rt))
    builder <! (lo := AST.xtlo 32<rt> result)
    builder <! (hi := AST.xthi 32<rt> result)
  endMark insInfo builder

let nop insInfo =
  let builder = IRBuilder (4)
  startMark insInfo builder
  endMark insInfo builder

let nor insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := AST.not (rs .| rt))
  endMark insInfo builder

let logOr insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := rs .| rt)
  endMark insInfo builder

let ori insInfo ctxt =
  let builder = IRBuilder (4)
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rt := rs .| imm)
  endMark insInfo builder

let rotr insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rt, sa = getThreeOprs insInfo
  let rd, rt = transTwoOprs insInfo ctxt (rd, rt)
  let sa = numI32 (int32 (transOprToImm sa)) 32<rt>
  let size = numI32 32 32<rt>
  startMark insInfo builder
  if ctxt.WordBitSize = 64<rt> then
    let t1 = builder.NewTempVar 32<rt>
    builder <! (t1 := AST.xtlo 32<rt> rt)
    builder <! (rd := AST.sext 64<rt> ((t1 << (size .- sa)) .| (t1 >> sa)))
  else
    builder <! (rd := (rt << (size .- sa)) .| (rt >> sa))
  endMark insInfo builder

let sb insInfo ctxt =
  let builder = IRBuilder (4)
  let rt, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  startMark insInfo builder
  builder <! (mem := AST.xtlo 8<rt> rt)
  endMark insInfo builder

let sd insInfo ctxt =
  let builder = IRBuilder (4)
  let rt, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  startMark insInfo builder
  builder <! (mem := AST.xtlo 64<rt> rt)
  endMark insInfo builder

let sdl insInfo ctxt =
  let builder = IRBuilder (4)
  let rt, mem = getTwoOprs insInfo
  let baseOffset = transOprToBaseOffset ctxt mem
  let rt, mem = transTwoOprs insInfo ctxt (rt, mem)
  let t1 = builder.NewTempVar 64<rt>
  let t2 = builder.NewTempVar 64<rt>
  let getMask size = (1L <<< size) - 1L
  let mask3 = numI64 (getMask 3) 64<rt>
  let vaddr0To2 = baseOffset .& mask3
  let num8 = numI32 8 64<rt>
  startMark insInfo builder
  builder <! (t1 := (numI32 7 64<rt> .- vaddr0To2) .* num8)
  builder <! (t2 := (AST.num1 64<rt> .+ vaddr0To2) .* num8)
  builder <! (mem := (rt >> t1) .| ((mem >> t2) << t2))
  endMark insInfo builder

let sdr insInfo ctxt =
  let builder = IRBuilder (4)
  let rt, mem = getTwoOprs insInfo
  let baseOffset = transOprToBaseOffset ctxt mem
  let rt, mem = transTwoOprs insInfo ctxt (rt, mem)
  let t1 = builder.NewTempVar 64<rt>
  let t2 = builder.NewTempVar 64<rt>
  let getMask size = (1L <<< size) - 1L
  let mask3 = numI64 (getMask 3) ctxt.WordBitSize
  let vaddr0To2 = baseOffset .& mask3
  let num8 = numI32 8 ctxt.WordBitSize
  startMark insInfo builder
  builder <! (t1 := vaddr0To2 .* num8)
  builder <! (t2 := (num8 .- vaddr0To2) .* num8)
  builder <! (mem := (rt << t1) .| ((mem << t2) >> t2))
  endMark insInfo builder

let sh insInfo ctxt =
  let builder = IRBuilder (4)
  let rt, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  startMark insInfo builder
  builder <! (mem := AST.xtlo 16<rt> rt)
  endMark insInfo builder

let sw insInfo ctxt =
  let builder = IRBuilder (4)
  let rt, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  startMark insInfo builder
  builder <! (mem := AST.xtlo 32<rt> rt)
  endMark insInfo builder

let swl insInfo ctxt =
  let builder = IRBuilder (4)
  let rt, mem = getTwoOprs insInfo
  let baseOffset = transOprToBaseOffset ctxt mem
  let rt, mem = transTwoOprs insInfo ctxt (rt, mem)
  let t1 = builder.NewTempVar 32<rt>
  let t2 = builder.NewTempVar 32<rt>
  let getMask size = (1L <<< size) - 1L
  let mask2 = numI64 (getMask 2) 32<rt>
  let baseOffset = if ctxt.WordBitSize = 32<rt> then baseOffset
                   else AST.xtlo 32<rt> baseOffset
  let rt = if ctxt.WordBitSize = 32<rt> then rt else AST.xtlo 32<rt> rt
  let vaddr0To2 = baseOffset .& mask2
  let num8 = numI32 8 32<rt>
  startMark insInfo builder
  builder <! (t1 := (numI32 3 32<rt> .- vaddr0To2) .* num8)
  builder <! (t2 := (AST.num1 32<rt> .+ vaddr0To2) .* num8)
  builder <! (mem := (rt >> t1) .| ((mem >> t2) << t2))
  endMark insInfo builder

let swr insInfo ctxt =
  let builder = IRBuilder (4)
  let rt, mem = getTwoOprs insInfo
  let baseOffset = transOprToBaseOffset ctxt mem
  let rt, mem = transTwoOprs insInfo ctxt (rt, mem)
  let t1 = builder.NewTempVar 32<rt>
  let t2 = builder.NewTempVar 32<rt>
  let getMask size = (1L <<< size) - 1L
  let mask2 = numI64 (getMask 2) 32<rt>
  let baseOffset = if ctxt.WordBitSize = 32<rt> then baseOffset
                   else AST.xtlo 32<rt> baseOffset
  let rt = if ctxt.WordBitSize = 32<rt> then rt else AST.xtlo 32<rt> rt
  let vaddr0To2 = baseOffset .& mask2
  let num8 = numI32 8 32<rt>
  startMark insInfo builder
  builder <! (t1 := vaddr0To2 .* num8)
  builder <! (t2 := (numI32 4 32<rt> .- vaddr0To2) .* num8)
  builder <! (mem := (rt << t1) .| ((mem << t2) >> t2))
  endMark insInfo builder

let seb insInfo ctxt =
  let builder = IRBuilder (16)
  let rd, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  startMark insInfo builder
  if ctxt.WordBitSize = 64<rt> then
    let lblL0 = builder.NewSymbol "L0"
    let lblL1 = builder.NewSymbol "L1"
    let lblEnd = builder.NewSymbol "End"
    let cond = notWordValue rt
    builder <! (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
    builder <! (AST.lmark lblL0)
    builder <! (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
    builder <! (AST.jmp (AST.name lblEnd))
    builder <! (AST.lmark lblL1)
    builder <! (rd := AST.sext 64<rt> (AST.extract rt 8<rt> 0))
    builder <! (AST.lmark lblEnd)
  else
    builder <! (rd := AST.sext 32<rt> (AST.extract rt 8<rt> 0))
  endMark insInfo builder

let seh insInfo ctxt =
  let builder = IRBuilder (16)
  let rd, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  startMark insInfo builder
  if ctxt.WordBitSize = 64<rt> then
    let lblL0 = builder.NewSymbol "L0"
    let lblL1 = builder.NewSymbol "L1"
    let lblEnd = builder.NewSymbol "End"
    let cond = notWordValue rt
    builder <! (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
    builder <! (AST.lmark lblL0)
    builder <! (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
    builder <! (AST.jmp (AST.name lblEnd))
    builder <! (AST.lmark lblL1)
    builder <! (rd := AST.sext 64<rt> (AST.extract rt 16<rt> 0))
    builder <! (AST.lmark lblEnd)
  else
    builder <! (rd := AST.sext 32<rt> (AST.extract rt 16<rt> 0))
  endMark insInfo builder

let sll insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rt, sa = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  if ctxt.WordBitSize = 64<rt> then
    let rt = AST.xtlo 32<rt> rt
    builder <! (rd := AST.sext 64<rt> (rt << AST.xtlo 32<rt> sa))
  else
    builder <! (rd := rt << sa)
  endMark insInfo builder

let sllv insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rt, rs = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let mask = numI32 31 32<rt>
  startMark insInfo builder
  if ctxt.WordBitSize = 64<rt> then
    let rt = AST.xtlo 32<rt> rt
    builder <! (rd := AST.sext 64<rt> (rt << (AST.xtlo 32<rt> rs .& mask)))
  else
    builder <! (rd := rt << (rs .& mask))
  endMark insInfo builder

let slt insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = AST.lt rs rt
  let rtVal = AST.ite cond (AST.num1 ctxt.WordBitSize) (AST.num0 ctxt.WordBitSize)
  startMark insInfo builder
  builder <! (rd := rtVal)
  endMark insInfo builder

let slti insInfo ctxt =
  let builder = IRBuilder (4)
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = AST.lt rs imm
  let rtVal = AST.ite cond (AST.num1 ctxt.WordBitSize) (AST.num0 ctxt.WordBitSize)
  startMark insInfo builder
  builder <! (rt := rtVal)
  endMark insInfo builder

let sltiu insInfo (ctxt: TranslationContext) =
  let builder = IRBuilder (4)
  let wordSz = ctxt.WordBitSize
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = AST.lt (AST.zext (wordSz * 2) rs) (AST.zext (wordSz * 2) imm)
  let rtVal = AST.ite cond (AST.num1 ctxt.WordBitSize) (AST.num0 ctxt.WordBitSize)
  startMark insInfo builder
  builder <! (rt := rtVal)
  endMark insInfo builder

let sltu insInfo (ctxt: TranslationContext) =
  let builder = IRBuilder (4)
  let wordSz = ctxt.WordBitSize
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = AST.lt (AST.zext (wordSz * 2) rs) (AST.zext (wordSz * 2) rt)
  let rtVal = AST.ite cond (AST.num1 ctxt.WordBitSize) (AST.num0 ctxt.WordBitSize)
  startMark insInfo builder
  builder <! (rd := rtVal)
  endMark insInfo builder

let sra insInfo ctxt =
  let builder = IRBuilder (16)
  let rd, rt, sa = getThreeOprs insInfo
  let rd, rt = transTwoOprs insInfo ctxt (rd, rt)
  let sa = numI32 (int32 (transOprToImm sa)) 32<rt>
  startMark insInfo builder
  if ctxt.WordBitSize = 64<rt> then
    let lblL0 = builder.NewSymbol "L0"
    let lblL1 = builder.NewSymbol "L1"
    let lblEnd = builder.NewSymbol "End"
    let cond = notWordValue rt
    let t1 = builder.NewTempVar 32<rt>
    builder <! (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
    builder <! (AST.lmark lblL0)
    builder <! (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
    builder <! (AST.jmp (AST.name lblEnd))
    builder <! (AST.lmark lblL1)
    builder <! (t1 := AST.xtlo 32<rt> rt)
    builder <! (rd := AST.sext 64<rt> (t1 ?>> sa))
    builder <! (AST.lmark lblEnd)
  else
    builder <! (rd := rt ?>> sa)
  endMark insInfo builder

let srl insInfo ctxt =
  let builder = IRBuilder (16)
  let rd, rt, sa = getThreeOprs insInfo
  let rd, rt = transTwoOprs insInfo ctxt (rd, rt)
  let sa = numI32 (int32 (transOprToImm sa)) 32<rt>
  startMark insInfo builder
  if ctxt.WordBitSize = 64<rt> then
    let lblL0 = builder.NewSymbol "L0"
    let lblL1 = builder.NewSymbol "L1"
    let lblEnd = builder.NewSymbol "End"
    let cond = notWordValue rt
    let t1 = builder.NewTempVar 32<rt>
    builder <! (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
    builder <! (AST.lmark lblL0)
    builder <! (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
    builder <! (AST.jmp (AST.name lblEnd))
    builder <! (AST.lmark lblL1)
    builder <! (t1 := AST.xtlo 32<rt> rt)
    builder <! (rd := AST.sext 64<rt> (t1 >> sa))
    builder <! (AST.lmark lblEnd)
  else
    builder <! (rd := rt >> sa)
  endMark insInfo builder

let srlv insInfo ctxt =
  let builder = IRBuilder (16)
  let rd, rt, rs = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let mask = numI32 31 32<rt>
  startMark insInfo builder
  if ctxt.WordBitSize = 64<rt> then
    let lblL0 = builder.NewSymbol "L0"
    let lblL1 = builder.NewSymbol "L1"
    let lblEnd = builder.NewSymbol "End"
    let cond = notWordValue rt
    let t1 = builder.NewTempVar 32<rt>
    builder <! (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
    builder <! (AST.lmark lblL0)
    builder <! (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
    builder <! (AST.jmp (AST.name lblEnd))
    builder <! (AST.lmark lblL1)
    builder <! (t1 := AST.xtlo 32<rt> rt)
    builder <! (rd := AST.sext 64<rt> (t1 >> (AST.xtlo 32<rt> rs .& mask)))
    builder <! (AST.lmark lblEnd)
  else
    builder <! (rd := rt >> (rs .& mask))
  endMark insInfo builder

let subu insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := rs .- rt)
  endMark insInfo builder

let subu64 insInfo ctxt =
  let builder = IRBuilder (16)
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblEnd = builder.NewSymbol "End"
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = notWordValue rs .| notWordValue rt
  startMark insInfo builder
  builder <! (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
  builder <! (AST.lmark lblL0)
  builder <! (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (rd := rs .- rt)
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let teq insInfo ctxt =
  let builder = IRBuilder (4)
  let lblL0 = builder.NewSymbol "L0"
  let lblEnd = builder.NewSymbol "End"
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  startMark insInfo builder
  builder <! (AST.cjmp (rs == rt) (AST.name lblL0) (AST.name lblEnd))
  builder <! (AST.lmark lblL0)
  builder <! (AST.sideEffect UndefinedInstr) (* FIXME: Trap *)
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let logXor insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := rs <+> rt)
  endMark insInfo builder

let xori insInfo ctxt =
  let builder = IRBuilder (4)
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rt := rs <+> imm)
  endMark insInfo builder

let transaui insInfo ctxt =
  match insInfo.Operands with
  | TwoOperands _ -> lui insInfo ctxt
  | ThreeOperands _ -> aui insInfo ctxt
  | _ -> raise InvalidOperandException

let translate insInfo (ctxt: TranslationContext) =
  match insInfo.Opcode with
  | Op.ADD when insInfo.Fmt.IsNone && ctxt.WordBitSize = 32<rt> ->
    add insInfo ctxt
  | Op.ADD when insInfo.Fmt.IsNone -> add64 insInfo ctxt
  | Op.ADD -> sideEffects insInfo UnsupportedFP
  | Op.ADDIU when ctxt.WordBitSize = 32<rt> -> addiu insInfo ctxt
  | Op.ADDIU -> addiu64 insInfo ctxt
  | Op.ADDU when ctxt.WordBitSize = 32<rt> -> addu insInfo ctxt
  | Op.ADDU -> addu64 insInfo ctxt
  | Op.AND -> logAnd insInfo ctxt
  | Op.ANDI -> andi insInfo ctxt
  | Op.AUI -> transaui insInfo ctxt
  | Op.B -> b insInfo ctxt
  | Op.BAL -> bal insInfo ctxt
  | Op.BC1F | Op.BC1T -> sideEffects insInfo UnsupportedFP
  | Op.BEQ -> beq insInfo ctxt
  | Op.BGEZ -> bgez insInfo ctxt
  | Op.BGTZ -> bgtz insInfo ctxt
  | Op.BLEZ -> blez insInfo ctxt
  | Op.BLTZ -> bltz insInfo ctxt
  | Op.BNE -> bne insInfo ctxt
  | Op.C | Op.CFC1 | Op.CTC1 -> sideEffects insInfo UnsupportedFP
  | Op.CLZ -> clz insInfo ctxt
  | Op.CVTD | Op.CVTS -> sideEffects insInfo UnsupportedFP
  | Op.DADDU -> addu insInfo ctxt
  | Op.DADDIU -> daddiu insInfo ctxt
  | Op.DCLZ -> dclz insInfo ctxt
  | Op.DMFC1 | Op.DMTC1 -> sideEffects insInfo UnsupportedFP
  | Op.DEXT -> dext insInfo ctxt
  | Op.DEXTM -> dextx insInfo checkDEXTMPosSize ctxt
  | Op.DEXTU -> dextx insInfo checkDEXTUPosSize ctxt
  | Op.DINS -> dins insInfo ctxt
  | Op.DINSM -> dinsx insInfo checkDINSMPosSize ctxt
  | Op.DINSU -> dinsx insInfo checkDINSUPosSize ctxt
  | Op.DIV when insInfo.Fmt.IsSome -> sideEffects insInfo UnsupportedFP
  | Op.DIVU when Helper.isRel2 insInfo.Arch  -> divu insInfo ctxt
  | Op.DDIVU -> ddivu insInfo ctxt
  | Op.DMULT -> dmult insInfo ctxt
  | Op.DMULTU -> dmultu insInfo ctxt
  | Op.DROTR -> drotr insInfo ctxt
  | Op.DSLL -> dsll insInfo ctxt
  | Op.DSLL32 -> dsll32 insInfo ctxt
  | Op.DSLLV -> dsllv insInfo ctxt
  | Op.DSRA -> dsra insInfo ctxt
  | Op.DSRA32 -> dsra32 insInfo ctxt
  | Op.DSRL -> dsrl insInfo ctxt
  | Op.DSRL32 -> dsrl32 insInfo ctxt
  | Op.DSRLV -> dsrlv insInfo ctxt
  | Op.DSUBU -> subu insInfo ctxt
  | Op.EHB -> nop insInfo (* FIXME *)
  | Op.EXT when ctxt.WordBitSize = 3232<rt> -> ext insInfo ctxt
  | Op.EXT -> ext64 insInfo ctxt
  | Op.INS when ctxt.WordBitSize = 3232<rt> -> ins insInfo ctxt
  | Op.INS -> ins64 insInfo ctxt
  | Op.JALR | Op.JALRHB -> jalr insInfo ctxt
  | Op.JR | Op.JRHB -> jr insInfo ctxt
  | Op.PAUSE -> sideEffects insInfo Delay
  | Op.LB | Op.LH | Op.LW | Op.LD -> load insInfo ctxt
  | Op.LBU | Op.LHU | Op.LWU -> loadu insInfo ctxt
  | Op.LDC1 | Op.LWC1 | Op.SDC1 | Op.SWC1 -> sideEffects insInfo UnsupportedFP
  | Op.LUI -> lui insInfo ctxt
  | Op.MADD when insInfo.Fmt.IsNone -> madd insInfo ctxt
  | Op.MFHI -> mfhi insInfo ctxt
  | Op.MFLO -> mflo insInfo ctxt
  | Op.MFC1 -> sideEffects insInfo UnsupportedFP
  | Op.MOV -> sideEffects insInfo UnsupportedFP
  | Op.MOVZ -> movz insInfo ctxt
  | Op.MOVN -> movn insInfo ctxt
  | Op.MTC1 -> sideEffects insInfo UnsupportedFP
  | Op.MUL when insInfo.Fmt.IsNone && Helper.isRel2 insInfo.Arch ->
    mul insInfo ctxt
  | Op.MUL when insInfo.Fmt.IsSome -> sideEffects insInfo UnsupportedFP
  | Op.MULT -> mult insInfo ctxt
  | Op.MULTU -> multu insInfo ctxt
  | Op.NOP -> nop insInfo
  | Op.NOR -> nor insInfo ctxt
  | Op.OR -> logOr insInfo ctxt
  | Op.ORI -> ori insInfo ctxt
  | Op.ROTR -> rotr insInfo ctxt
  | Op.SLL -> sll insInfo ctxt
  | Op.SLLV -> sllv insInfo ctxt
  | Op.SLT -> slt insInfo ctxt
  | Op.SLTI -> slti insInfo ctxt
  | Op.SLTIU -> sltiu insInfo ctxt
  | Op.SLTU -> sltu insInfo ctxt
  | Op.SSNOP -> nop insInfo
  | Op.SB -> sb insInfo ctxt
  | Op.SD -> sd insInfo ctxt
  | Op.SEB -> seb insInfo ctxt
  | Op.SEH -> seh insInfo ctxt
  | Op.SH -> sh insInfo ctxt
  | Op.SRA -> sra insInfo ctxt
  | Op.SRL -> srl insInfo ctxt
  | Op.SRLV -> srlv insInfo ctxt
  | Op.SUB when insInfo.Fmt.IsSome -> sideEffects insInfo UnsupportedFP
  | Op.SUBU when ctxt.WordBitSize = 32<rt> -> subu insInfo ctxt
  | Op.SUBU -> subu64 insInfo ctxt
  | Op.SW -> sw insInfo ctxt
  | Op.SDL -> sdl insInfo ctxt
  | Op.SDR -> sdr insInfo ctxt
  | Op.SWL -> swl insInfo ctxt
  | Op.SWR -> swr insInfo ctxt
  | Op.TEQ -> teq insInfo ctxt
  | Op.TRUNCL | Op.TRUNCW -> sideEffects insInfo UnsupportedFP
  | Op.XOR -> logXor insInfo ctxt
  | Op.XORI -> xori insInfo ctxt
  | Op.ABS | Op.BC3F | Op.BC3FL | Op.BC3T | Op.BC3TL | Op.DDIV | Op.DIV
  | Op.DROTR32 | Op.DROTRV | Op.DSBH | Op.DSHD | Op.DSRAV | Op.J | Op.JAL
  | Op.LDL | Op.LDR | Op.LDXC1 | Op.LWL | Op.LWR | Op.LWXC1 | Op.MADDU
  | Op.MFHC1 | Op.MOVF | Op.MOVN | Op.MOVT | Op.MSUB | Op.MTHC1 | Op.MTHI
  | Op.MTLO | Op.NEG | Op.ROTRV | Op.SDXC1 | Op.SQRT | Op.SRAV | Op.SWXC1
  | Op.SYNC | Op.TRUNCL | Op.WSBH -> sideEffects insInfo UnsupportedExtension // XXX this is temporary fix
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException (Disasm.opCodeToString o)
  |> fun builder -> builder.ToStmts ()
