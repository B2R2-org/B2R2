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
open B2R2.FrontEnd.BinLifter.LiftingOperators
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.BinLifter.MIPS

let inline getRegVar (ctxt: TranslationContext) name =
  Register.toRegID name |> ctxt.GetRegVar

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
    numI64 (int64 insInfo.Address + o) ctxt.WordBitSize
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

let sideEffects insLen ctxt name =
  let ir = !*ctxt
  !<ir insLen
  !!ir (AST.sideEffect name)
  !>ir insLen

let checkOverfolwOnAdd e1 e2 r =
  let e1High = AST.extract e1 1<rt> 31
  let e2High = AST.extract e2 1<rt> 31
  let rHigh = AST.extract r 1<rt> 31
  (e1High == e2High) .& (e1High <+> rHigh)

let notWordValue v =
  (AST.xthi 32<rt> v) != AST.sext 32<rt> (AST.extract v 1<rt> 31)

let advancePC (ctxt: TranslationContext) ir =
  if ctxt.DelayedBranch = InterJmpKind.NotAJmp then
    () (* Do nothing, because IEMark will advance PC. *)
  else
    let nPC = getRegVar ctxt R.NPC
    !!ir (AST.interjmp nPC ctxt.DelayedBranch)
    ctxt.DelayedBranch <- InterJmpKind.NotAJmp

let updatePCCond ctxt offset cond kind ir =
  let lblTrueCase = !%ir "TrueCase"
  let lblFalseCase = !%ir "FalseCase"
  let lblEnd = !%ir "End"
  let pc = getRegVar ctxt R.PC
  let nPC = getRegVar ctxt R.NPC
  ctxt.DelayedBranch <- kind
  !!ir (AST.cjmp cond (AST.name lblTrueCase) (AST.name lblFalseCase))
  !!ir (AST.lmark lblTrueCase)
  !!ir (nPC := offset)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblFalseCase)
  !!ir (nPC := pc .+ numI32 8 ctxt.WordBitSize)
  !!ir (AST.lmark lblEnd)

let add insInfo insLen ctxt =
  let ir = !*ctxt
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = !+ir 32<rt>
  let cond = checkOverfolwOnAdd rs rt result
  !<ir insLen
  !!ir (result := rs .+ rt)
  !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (AST.sideEffect (Exception "int overflow"))
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (rd := result)
  !!ir (AST.lmark lblEnd)
  advancePC ctxt ir
  !>ir insLen

let add64 insInfo insLen ctxt =
  let ir = !*ctxt
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblEnd = !%ir "End"
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = !+ir 32<rt>
  let cond = notWordValue rs .| notWordValue rt
  let cond2 = checkOverfolwOnAdd rs rt result
  !<ir insLen
  !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (result := AST.xtlo 32<rt> rs .+ AST.xtlo 32<rt> rt)
  !!ir (AST.cjmp cond2 (AST.name lblL2) (AST.name lblL3))
  !!ir (AST.lmark lblL0)
  !!ir (AST.sideEffect (Exception "int overflow"))
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (rd := AST.sext 64<rt> result)
  !!ir (AST.lmark lblEnd)
  advancePC ctxt ir
  !>ir insLen

let addiu insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = !+ir 32<rt>
  !<ir insLen
  !!ir (result := rs .+ imm)
  !!ir (rt := result)
  advancePC ctxt ir
  !>ir insLen

let addiu64 insInfo insLen ctxt =
  let ir = !*ctxt
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = !+ir 64<rt>
  let cond = notWordValue rs
  !<ir insLen
  !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (result := rs .+ imm)
  !!ir (rt := AST.sext 64<rt> (AST.xtlo 32<rt> result))
  !!ir (AST.lmark lblEnd)
  advancePC ctxt ir
  !>ir insLen

let addu insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rs .+ rt)
  advancePC ctxt ir
  !>ir insLen

let addu64 insInfo insLen ctxt =
  let ir = !*ctxt
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = !+ir 64<rt>
  let cond = notWordValue rs .| notWordValue rt
  !<ir insLen
  !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (result := rs .+ rt)
  !!ir (rd := AST.sext 64<rt> (AST.xtlo 32<rt> result))
  !!ir (AST.lmark lblEnd)
  advancePC ctxt ir
  !>ir insLen

let logAnd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rs .& rt)
  advancePC ctxt ir
  !>ir insLen

let andi insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rt := rs .& imm)
  advancePC ctxt ir
  !>ir insLen

let aui insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let imm = imm << numI32 16 ctxt.WordBitSize
  !<ir insLen
  !!ir (rt := rs .+ imm)
  advancePC ctxt ir
  !>ir insLen

let b insInfo insLen ctxt =
  let ir = !*ctxt
  let nPC = getRegVar ctxt R.NPC
  let offset = getOneOpr insInfo |> transOneOpr insInfo ctxt
  ctxt.DelayedBranch <- InterJmpKind.Base
  !<ir insLen
  !!ir (nPC := offset)
  !>ir insLen

let bal insInfo insLen ctxt =
  let ir = !*ctxt
  let offset = getOneOpr insInfo |> transOneOpr insInfo ctxt
  let pc = getRegVar ctxt R.PC
  let nPC = getRegVar ctxt R.NPC
  ctxt.DelayedBranch <- InterJmpKind.IsCall
  !<ir insLen
  !!ir (getRegVar ctxt R.R31 := pc .+ numI32 8 ctxt.WordBitSize)
  !!ir (nPC := offset)
  !>ir insLen

let beq insInfo insLen ctxt =
  let ir = !*ctxt
  let rs, rt, offset = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = rs == rt
  !<ir insLen
  updatePCCond ctxt offset cond InterJmpKind.Base ir
  !>ir insLen

let blez insInfo insLen ctxt =
  let ir = !*ctxt
  let rs, offset = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let cond = AST.le rs (AST.num0 ctxt.WordBitSize)
  !<ir insLen
  updatePCCond ctxt offset cond InterJmpKind.Base ir
  !>ir insLen

let bltz insInfo insLen ctxt =
  let ir = !*ctxt
  let rs, offset = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let cond = AST.lt rs (AST.num0 ctxt.WordBitSize)
  !<ir insLen
  updatePCCond ctxt offset cond InterJmpKind.Base ir
  !>ir insLen

let bltzal insInfo insLen ctxt =
  let ir = !*ctxt
  let rs, offset = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let pc = getRegVar ctxt R.PC
  let cond = AST.lt rs (AST.num0 ctxt.WordBitSize)
  !<ir insLen
  !!ir (getRegVar ctxt R.R31 := pc .+ numI32 8 ctxt.WordBitSize)
  updatePCCond ctxt offset cond InterJmpKind.IsCall ir
  !>ir insLen

let bgez insInfo insLen ctxt =
  let ir = !*ctxt
  let rs, offset = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let cond = AST.ge rs (AST.num0 ctxt.WordBitSize)
  !<ir insLen
  updatePCCond ctxt offset cond InterJmpKind.Base ir
  !>ir insLen

let bgezal insInfo insLen ctxt =
  let ir = !*ctxt
  let rs, offset = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let pc = getRegVar ctxt R.PC
  let cond = AST.ge rs (AST.num0 ctxt.WordBitSize)
  !<ir insLen
  !!ir (getRegVar ctxt R.R31 := pc .+ numI32 8 ctxt.WordBitSize)
  updatePCCond ctxt offset cond InterJmpKind.IsCall ir
  !>ir insLen

let bgtz insInfo insLen ctxt =
  let ir = !*ctxt
  let rs, offset = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let cond = AST.gt rs (AST.num0 ctxt.WordBitSize)
  !<ir insLen
  updatePCCond ctxt offset cond InterJmpKind.Base ir
  !>ir insLen

let bne insInfo insLen ctxt =
  let ir = !*ctxt
  let rs, rt, offset = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = rs != rt
  !<ir insLen
  updatePCCond ctxt offset cond InterJmpKind.Base ir
  !>ir insLen

let clz insInfo insLen ctxt =
  let ir = !*ctxt
  let lblLoop = !%ir "Loop"
  let lblContinue = !%ir "Continue"
  let lblUpdate = !%ir "update"
  let lblEnd = !%ir "End"
  let wordSz = ctxt.WordBitSize
  let rd, rs = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let t = !+ir wordSz
  let tmp = numI32 (32 - 1) wordSz
  !<ir insLen
  !!ir (t := tmp)
  !!ir (AST.lmark lblLoop)
  !!ir (AST.cjmp (rs >> t == AST.num1 wordSz)
                       (AST.name lblEnd) (AST.name lblContinue))
  !!ir (AST.lmark lblContinue)
  !!ir (AST.cjmp (t == AST.num0 wordSz)
                       (AST.name lblEnd) (AST.name lblUpdate))
  !!ir (AST.lmark lblUpdate)
  !!ir (t := t .- AST.num1 wordSz)
  !!ir (AST.jmp (AST.name lblLoop))
  !!ir (AST.lmark lblEnd)
  !!ir (rd := t)
  advancePC ctxt ir
  !>ir insLen

let daddiu insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = !+ir 64<rt>
  !<ir insLen
  !!ir (result := rs .+ imm)
  !!ir (rt := result)
  advancePC ctxt ir
  !>ir insLen

let dclz insInfo insLen ctxt =
  let ir = !*ctxt
  let lblLoop = !%ir "Loop"
  let lblContinue = !%ir "Continue"
  let lblUpdate = !%ir "update"
  let lblEnd = !%ir "End"
  let wordSz = ctxt.WordBitSize
  let rd, rs = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let t = !+ir wordSz
  let tmp = numI32 (64 - 1) wordSz
  !<ir insLen
  !!ir (t := tmp)
  !!ir (AST.lmark lblLoop)
  !!ir (AST.cjmp (rs >> t == AST.num1 wordSz)
                       (AST.name lblEnd) (AST.name lblContinue))
  !!ir (AST.lmark lblContinue)
  !!ir (AST.cjmp (t == AST.num0 wordSz)
                       (AST.name lblEnd) (AST.name lblUpdate))
  !!ir (AST.lmark lblUpdate)
  !!ir (t := t .- AST.num1 wordSz)
  !!ir (AST.jmp (AST.name lblLoop))
  !!ir (AST.lmark lblEnd)
  !!ir (rd := t)
  advancePC ctxt ir
  !>ir insLen

let ddivu insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let q = !+ir 128<rt>
  let r = !+ir 128<rt>
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  let rs = AST.zext 128<rt> rs
  let rt = AST.zext 128<rt> rt
  !!ir (q := rs ./ rt)
  !!ir (r := rs .% rt)
  !!ir (lo := AST.xtlo 64<rt> q)
  !!ir (hi := AST.xtlo 64<rt> r)
  advancePC ctxt ir
  !>ir insLen

let checkDEXTPosSize pos size =
  let posSize = pos + size
  if 0 <= pos && pos < 32 &&
     0 < size && size <= 32 &&
     0 < posSize && posSize <= 63 then ()
  else  raise InvalidOperandException

let dext insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = int32 (transOprToImm pos)
  let size = int32 (transOprToImm size)
  checkDEXTPosSize pos size
  let getMask size = (1L <<< size) - 1L
  let mask = numI64 (getMask size) ctxt.WordBitSize
  let rs = if pos = 0 then rs else rs >> numI32 pos ctxt.WordBitSize
  !!ir (rt :=  mask .& rs)
  advancePC ctxt ir
  !>ir insLen

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

let dextx insInfo insLen posSizeCheckFn ctxt =
  let ir = !*ctxt
  !<ir insLen
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = int32 (transOprToImm pos)
  let sz = int32 (transOprToImm size)
  posSizeCheckFn pos sz
  if sz = 64 then if rt = rs then () else !!ir (rt := rs)
  else
    let getMask size = (1L <<< size) - 1L
    let rs = if pos = 0 then rs else rs >> numI32 pos ctxt.WordBitSize
    let rs = if sz = 64 then rs else rs .& numI64 (getMask sz) ctxt.WordBitSize
    !!ir (rt :=  rs)
  advancePC ctxt ir
  !>ir insLen

let checkINSorExtPosSize pos size =
  let posSize = pos + size
  if 0 <= pos && pos < 32 &&
     0 < size && size <= 32 &&
     0 < posSize && posSize <= 32 then ()
  else raise InvalidOperandException

let dins insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
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
    !!ir (rt := rt' .| rs')
  advancePC ctxt ir
  !>ir insLen

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

let dinsx insInfo insLen posSizeCheckFn ctxt =
  let ir = !*ctxt
  !<ir insLen
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = int32 (transOprToImm pos)
  let size = int32 (transOprToImm size)
  posSizeCheckFn pos size
  if size = 64 then if rt = rs then () else !!ir (rt := rs)
  else
    let posExpr = numI32 pos ctxt.WordBitSize
    let getMask size = (1L <<< size) - 1L
    let mask = numI64 (getMask size) ctxt.WordBitSize
    let rs', rt' =
      if pos = 0 then rs .& mask, rt .& (AST.not mask)
      else (rs .& mask) << posExpr, rt .& (AST.not (mask << posExpr))
    !!ir (rt := rt' .| rs')
  advancePC ctxt ir
  !>ir insLen

let divu insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let q = !+ir 64<rt>
  let r = !+ir 64<rt>
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  if ctxt.WordBitSize = 64<rt> then
    let lblL0 = !%ir "L0"
    let lblL1 = !%ir "L1"
    let lblEnd = !%ir "End"
    let cond = notWordValue rs .| notWordValue rt
    let mask = numI64 0xFFFFFFFFL 64<rt>
    let rs = rs .& mask
    let rt = rt .& mask
    !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
    !!ir (AST.lmark lblL0)
    !!ir (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
    !!ir (AST.jmp (AST.name lblEnd))
    !!ir (AST.lmark lblL1)
    !!ir (q := rs ./ rt)
    !!ir (r := rs .% rt)
    !!ir (lo := AST.sext 64<rt> (AST.xtlo 32<rt> q))
    !!ir (hi := AST.sext 64<rt> (AST.xtlo 32<rt> r))
    !!ir (AST.lmark lblEnd)
  else
    let rs = AST.zext 64<rt> rs
    let rt = AST.zext 64<rt> rt
    !!ir (q := rs ./ rt)
    !!ir (r := rs .% rt)
    !!ir (lo := AST.xtlo 32<rt> q)
    !!ir (hi := AST.xtlo 32<rt> r)
  advancePC ctxt ir
  !>ir insLen

let dmult insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let result = !+ir 128<rt>
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  !!ir (result := (AST.sext 128<rt> rs) .* (AST.sext 128<rt> rt))
  !!ir (lo := AST.xtlo 64<rt> result)
  !!ir (hi := AST.xthi 64<rt> result)
  advancePC ctxt ir
  !>ir insLen

let dmultu insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let result = !+ir 128<rt>
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  !!ir (result := (AST.zext 128<rt> rs) .* (AST.zext 128<rt> rt))
  !!ir (lo := AST.xtlo 64<rt> result)
  !!ir (hi := AST.xthi 64<rt> result)
  advancePC ctxt ir
  !>ir insLen

let drotr insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, sa = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let size = numI32 64 64<rt>
  !<ir insLen
  !!ir (rd := (rt << (size .- sa)) .| (rt >> sa))
  advancePC ctxt ir
  !>ir insLen

let dsll insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, sa = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  if sa = AST.num0 ctxt.WordBitSize then !!ir (rd := rt)
  else !!ir (rd := rt << sa)
  advancePC ctxt ir
  !>ir insLen

let dsll32 insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, sa = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let sa = sa .+ numI32 32 64<rt>
  !<ir insLen
  !!ir (rd := rt << sa)
  advancePC ctxt ir
  !>ir insLen

let dsllv insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, rs = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rt << (rs .& numI32 63 64<rt>))
  advancePC ctxt ir
  !>ir insLen

let dsra insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, sa = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  if sa = AST.num0 ctxt.WordBitSize then !!ir (rd := rt)
  else !!ir (rd := rt ?>> sa)
  advancePC ctxt ir
  !>ir insLen

let dsra32 insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, sa = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let sa = sa .+ numI32 32 64<rt>
  !<ir insLen
  !!ir (rd := rt ?>> sa)
  advancePC ctxt ir
  !>ir insLen

let dsrl insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, sa = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  if sa = AST.num0 ctxt.WordBitSize then !!ir (rd := rt)
  else !!ir (rd := rt >> sa)
  advancePC ctxt ir
  !>ir insLen

let dsrl32 insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, sa = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let sa = sa .+ numI32 32 64<rt>
  !<ir insLen
  !!ir (rd := rt >> sa)
  advancePC ctxt ir
  !>ir insLen

let dsrlv insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, rs = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rt >> (rs .& numI32 63 64<rt>))
  advancePC ctxt ir
  !>ir insLen

let ins insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = int32 (transOprToImm pos)
  let size = int32 (transOprToImm size)
  checkINSorExtPosSize pos size
  if size = 32 then if rt = rs then () else !!ir (rt := rs)
  else
    let posExpr = numI32 pos ctxt.WordBitSize
    let getMask size = (1L <<< size) - 1L
    let mask = numI64 (getMask size) ctxt.WordBitSize
    let rs', rt' =
      if pos = 0 then rs .& mask, rt .& (AST.not mask)
      else (rs .& mask) << posExpr, rt .& (AST.not (mask << posExpr))
    !!ir (rt := rt' .| rs')
  advancePC ctxt ir
  !>ir insLen

let ins64 insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = int32 (transOprToImm pos)
  let size = int32 (transOprToImm size)
  checkINSorExtPosSize pos size
  let posExpr = numI32 pos ctxt.WordBitSize
  let getMask size = (1L <<< size) - 1L
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let cond = notWordValue rs .| notWordValue rt
  !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  let mask = numI64 (getMask size) ctxt.WordBitSize
  let rs', rt' = if pos = 0 then rs .& mask, rt .& (AST.not mask)
                 else (rs .& mask) << posExpr, rt .& (AST.not (mask << posExpr))
  !!ir (rt := rt' .| rs')
  !!ir (AST.lmark lblEnd)
  advancePC ctxt ir
  !>ir insLen

let getJALROprs insInfo ctxt =
  match insInfo.Operands with
  | OneOperand opr ->
    struct (getRegVar ctxt R.R31, transOprToExpr insInfo ctxt opr)
  | TwoOperands (o1, o2) ->
    struct (transOprToExpr insInfo ctxt o1, transOprToExpr insInfo ctxt o2)
  | _ -> raise InvalidOperandException

let jalr insInfo insLen ctxt =
  let ir = !*ctxt
  let pc = getRegVar ctxt R.PC
  let nPC = getRegVar ctxt R.NPC
  let struct (lr, rs) = getJALROprs insInfo ctxt
  ctxt.DelayedBranch <- InterJmpKind.IsCall
  !<ir insLen
  !!ir (lr := pc .+ numI32 8 ctxt.WordBitSize)
  !!ir (nPC := rs)
  !>ir insLen

let jr insInfo insLen ctxt =
  let ir = !*ctxt
  let nPC = getRegVar ctxt R.NPC
  let rs = getOneOpr insInfo |> transOneOpr insInfo ctxt
  ctxt.DelayedBranch <- InterJmpKind.Base
  !<ir insLen
  !!ir (nPC := rs)
  !>ir insLen

let loadByteWord insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (rt := AST.sext ctxt.WordBitSize mem)
  advancePC ctxt ir
  !>ir insLen

let loadHalfDword insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (rt := AST.sext ctxt.WordBitSize mem)
  advancePC ctxt ir
  !>ir insLen

let loadu insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (rt := AST.zext ctxt.WordBitSize mem)
  advancePC ctxt ir
  !>ir insLen

let ext insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = int32 (transOprToImm pos)
  let size = int32 (transOprToImm size)
  let getMask size = (1L <<< size) - 1L
  checkINSorExtPosSize pos size
  if size = 32 then if rt = rs then () else  !!ir (rt := rs)
  else let rs = if pos = 0 then rs else rs >> numI32 pos ctxt.WordBitSize
       !!ir (rt := rs .& numI64 (getMask size) ctxt.WordBitSize)
  advancePC ctxt ir
  !>ir insLen

let ext64 insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = int32 (transOprToImm pos)
  let size = int32 (transOprToImm size)
  let getMask size = (1L <<< size) - 1L
  checkINSorExtPosSize pos size
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let cond = notWordValue rs
  !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  if size = 32 then if rt = rs then () else  !!ir (rt := rs)
  else let rs = if pos = 0 then rs else rs >> numI32 pos ctxt.WordBitSize
       !!ir (rt := rs .& numI64 (getMask size) ctxt.WordBitSize)
  !!ir (AST.lmark lblEnd)
  advancePC ctxt ir
  !>ir insLen

let lui insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, imm = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  if ctxt.WordBitSize = 64<rt> then
    !!ir
      (rt := AST.sext 64<rt>
        (AST.concat (AST.xtlo 16<rt> imm) (AST.num0 16<rt>)))
  else !!ir (rt := AST.concat (AST.xtlo 16<rt> imm) (AST.num0 16<rt>))
  advancePC ctxt ir
  !>ir insLen

let madd insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let result = !+ir 64<rt>
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  if ctxt.WordBitSize = 64<rt> then
    let lblL0 = !%ir "L0"
    let lblL1 = !%ir "L1"
    let lblEnd = !%ir "End"
    let cond = notWordValue rs .| notWordValue rt
    let hilo = AST.concat (AST.xtlo 32<rt> hi) (AST.xtlo 32<rt> lo)
    let mask = numU32 0xFFFFu 64<rt>
    !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
    !!ir (AST.lmark lblL0)
    !!ir (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
    !!ir (AST.jmp (AST.name lblEnd))
    !!ir (AST.lmark lblL1)
    !!ir (result := hilo .+ ((rs .& mask) .* (rt .& mask)))
    !!ir (hi := AST.sext 64<rt> (AST.xthi 32<rt> result))
    !!ir (lo := AST.sext 64<rt> (AST.xtlo 32<rt> result))
    !!ir (AST.lmark lblEnd)
  else
    !!ir (result := (AST.concat hi lo)
                       .+ (AST.sext 64<rt> rs .* AST.sext 64<rt> rt))
    !!ir (hi := AST.xthi 32<rt> result)
    !!ir (lo := AST.xtlo 32<rt> result)
  advancePC ctxt ir
  !>ir insLen

let mfhi insInfo insLen ctxt =
  let ir = !*ctxt
  let rd = getOneOpr insInfo |> transOneOpr insInfo ctxt
  !<ir insLen
  !!ir (rd := getRegVar ctxt R.HI)
  advancePC ctxt ir
  !>ir insLen

let mflo insInfo insLen ctxt =
  let ir = !*ctxt
  let rd = getOneOpr insInfo |> transOneOpr insInfo ctxt
  !<ir insLen
  !!ir (rd := getRegVar ctxt R.LO)
  advancePC ctxt ir
  !>ir insLen

let movz insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = rt == AST.num0 ctxt.WordBitSize
  !<ir insLen
  !!ir (rd := AST.ite cond rs rd)
  advancePC ctxt ir
  !>ir insLen

let movn insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = rt != AST.num0 ctxt.WordBitSize
  !<ir insLen
  !!ir (rd := AST.ite cond rs rd)
  advancePC ctxt ir
  !>ir insLen

let mul insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = !+ir 64<rt>
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  if ctxt.WordBitSize = 64<rt> then
    let lblL0 = !%ir "L0"
    let lblL1 = !%ir "L1"
    let lblEnd = !%ir "End"
    let cond = notWordValue rs .| notWordValue rt
    !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
    !!ir (AST.lmark lblL0)
    !!ir (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
    !!ir (AST.jmp (AST.name lblEnd))
    !!ir (AST.lmark lblL1)
    !!ir (result := rs .* rt)
    !!ir (rd := AST.sext 64<rt> (AST.xtlo 32<rt> result))
    !!ir (AST.lmark lblEnd)
  else
    !!ir (result := (AST.sext 64<rt> rs .* AST.sext 64<rt> rt))
    !!ir (rd := AST.xtlo 32<rt> result)
  !!ir (hi := AST.undef ctxt.WordBitSize "UNPREDICTABLE")
  !!ir (lo := AST.undef ctxt.WordBitSize "UNPREDICTABLE")
  advancePC ctxt ir
  !>ir insLen

let mult insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let result = !+ir 64<rt>
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  if ctxt.WordBitSize = 64<rt> then
    let lblL0 = !%ir "L0"
    let lblL1 = !%ir "L1"
    let lblEnd = !%ir "End"
    let cond = notWordValue rs .| notWordValue rt
    let mask = numI64 0xFFFFFFFFL 64<rt>
    !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
    !!ir (AST.lmark lblL0)
    !!ir (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
    !!ir (AST.jmp (AST.name lblEnd))
    !!ir (AST.lmark lblL1)
    !!ir (result := (rs .& mask) .* (rt .& mask))
    !!ir (lo := AST.sext 64<rt> (AST.xtlo 32<rt> result))
    !!ir (hi := AST.sext 64<rt> (AST.xthi 32<rt> result))
    !!ir (AST.lmark lblEnd)
  else
    !!ir (result := (AST.sext 64<rt> rs .* AST.sext 64<rt> rt))
    !!ir (lo := AST.xtlo 32<rt> result)
    !!ir (hi := AST.xthi 32<rt> result)
  advancePC ctxt ir
  !>ir insLen

let multu insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let result = !+ir 64<rt>
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  if ctxt.WordBitSize = 64<rt> then
    let lblL0 = !%ir "L0"
    let lblL1 = !%ir "L1"
    let lblEnd = !%ir "End"
    let cond = notWordValue rs .| notWordValue rt
    let mask = numI64 0xFFFFFFFFL 64<rt>
    !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
    !!ir (AST.lmark lblL0)
    !!ir (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
    !!ir (AST.jmp (AST.name lblEnd))
    !!ir (AST.lmark lblL1)
    !!ir (result := (rs .& mask) .* (rt .& mask))
    !!ir (lo := AST.sext 64<rt> (AST.xtlo 32<rt> result))
    !!ir (hi := AST.sext 64<rt> (AST.xthi 32<rt> result))
    !!ir (AST.lmark lblEnd)
  else
    !!ir (result := (AST.zext 64<rt> rs .* AST.zext 64<rt> rt))
    !!ir (lo := AST.xtlo 32<rt> result)
    !!ir (hi := AST.xthi 32<rt> result)
  advancePC ctxt ir
  !>ir insLen

let nop insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  advancePC ctxt ir
  !>ir insLen

let nor insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := AST.not (rs .| rt))
  advancePC ctxt ir
  !>ir insLen

let logOr insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rs .| rt)
  advancePC ctxt ir
  !>ir insLen

let ori insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rt := rs .| imm)
  advancePC ctxt ir
  !>ir insLen

let rotr insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, sa = getThreeOprs insInfo
  let rd, rt = transTwoOprs insInfo ctxt (rd, rt)
  let sa = numI32 (int32 (transOprToImm sa)) 32<rt>
  let size = numI32 32 32<rt>
  !<ir insLen
  if ctxt.WordBitSize = 64<rt> then
    let t1 = !+ir 32<rt>
    !!ir (t1 := AST.xtlo 32<rt> rt)
    !!ir (rd := AST.sext 64<rt> ((t1 << (size .- sa)) .| (t1 >> sa)))
  else
    !!ir (rd := (rt << (size .- sa)) .| (rt >> sa))
  advancePC ctxt ir
  !>ir insLen

let sb insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (mem := AST.xtlo 8<rt> rt)
  advancePC ctxt ir
  !>ir insLen

let sd insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (mem := AST.xtlo 64<rt> rt)
  advancePC ctxt ir
  !>ir insLen

let sdl insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, mem = getTwoOprs insInfo
  let baseOffset = transOprToBaseOffset ctxt mem
  let rt, mem = transTwoOprs insInfo ctxt (rt, mem)
  let t1 = !+ir 64<rt>
  let t2 = !+ir 64<rt>
  let getMask size = (1L <<< size) - 1L
  let mask3 = numI64 (getMask 3) 64<rt>
  let vaddr0To2 = baseOffset .& mask3
  let num8 = numI32 8 64<rt>
  !<ir insLen
  !!ir (t1 := (numI32 7 64<rt> .- vaddr0To2) .* num8)
  !!ir (t2 := (AST.num1 64<rt> .+ vaddr0To2) .* num8)
  !!ir (mem := (rt >> t1) .| ((mem >> t2) << t2))
  advancePC ctxt ir
  !>ir insLen

let sdr insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, mem = getTwoOprs insInfo
  let baseOffset = transOprToBaseOffset ctxt mem
  let rt, mem = transTwoOprs insInfo ctxt (rt, mem)
  let t1 = !+ir 64<rt>
  let t2 = !+ir 64<rt>
  let getMask size = (1L <<< size) - 1L
  let mask3 = numI64 (getMask 3) ctxt.WordBitSize
  let vaddr0To2 = baseOffset .& mask3
  let num8 = numI32 8 ctxt.WordBitSize
  !<ir insLen
  !!ir (t1 := vaddr0To2 .* num8)
  !!ir (t2 := (num8 .- vaddr0To2) .* num8)
  !!ir (mem := (rt << t1) .| ((mem << t2) >> t2))
  advancePC ctxt ir
  !>ir insLen

let sh insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (mem := AST.xtlo 16<rt> rt)
  advancePC ctxt ir
  !>ir insLen

let sw insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (mem := AST.xtlo 32<rt> rt)
  advancePC ctxt ir
  !>ir insLen

let swl insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, mem = getTwoOprs insInfo
  let baseOffset = transOprToBaseOffset ctxt mem
  let rt, mem = transTwoOprs insInfo ctxt (rt, mem)
  let t1 = !+ir 32<rt>
  let t2 = !+ir 32<rt>
  let getMask size = (1L <<< size) - 1L
  let mask2 = numI64 (getMask 2) 32<rt>
  let baseOffset = if ctxt.WordBitSize = 32<rt> then baseOffset
                   else AST.xtlo 32<rt> baseOffset
  let rt = if ctxt.WordBitSize = 32<rt> then rt else AST.xtlo 32<rt> rt
  let vaddr0To2 = baseOffset .& mask2
  let num8 = numI32 8 32<rt>
  !<ir insLen
  !!ir (t1 := (numI32 3 32<rt> .- vaddr0To2) .* num8)
  !!ir (t2 := (AST.num1 32<rt> .+ vaddr0To2) .* num8)
  !!ir (mem := (rt >> t1) .| ((mem >> t2) << t2))
  advancePC ctxt ir
  !>ir insLen

let swr insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, mem = getTwoOprs insInfo
  let baseOffset = transOprToBaseOffset ctxt mem
  let rt, mem = transTwoOprs insInfo ctxt (rt, mem)
  let t1 = !+ir 32<rt>
  let t2 = !+ir 32<rt>
  let getMask size = (1L <<< size) - 1L
  let mask2 = numI64 (getMask 2) 32<rt>
  let baseOffset = if ctxt.WordBitSize = 32<rt> then baseOffset
                   else AST.xtlo 32<rt> baseOffset
  let rt = if ctxt.WordBitSize = 32<rt> then rt else AST.xtlo 32<rt> rt
  let vaddr0To2 = baseOffset .& mask2
  let num8 = numI32 8 32<rt>
  !<ir insLen
  !!ir (t1 := vaddr0To2 .* num8)
  !!ir (t2 := (numI32 4 32<rt> .- vaddr0To2) .* num8)
  !!ir (mem := (rt << t1) .| ((mem << t2) >> t2))
  advancePC ctxt ir
  !>ir insLen

let seb insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  if ctxt.WordBitSize = 64<rt> then
    let lblL0 = !%ir "L0"
    let lblL1 = !%ir "L1"
    let lblEnd = !%ir "End"
    let cond = notWordValue rt
    !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
    !!ir (AST.lmark lblL0)
    !!ir (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
    !!ir (AST.jmp (AST.name lblEnd))
    !!ir (AST.lmark lblL1)
    !!ir (rd := AST.sext 64<rt> (AST.extract rt 8<rt> 0))
    !!ir (AST.lmark lblEnd)
  else
    !!ir (rd := AST.sext 32<rt> (AST.extract rt 8<rt> 0))
  advancePC ctxt ir
  !>ir insLen

let seh insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  if ctxt.WordBitSize = 64<rt> then
    let lblL0 = !%ir "L0"
    let lblL1 = !%ir "L1"
    let lblEnd = !%ir "End"
    let cond = notWordValue rt
    !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
    !!ir (AST.lmark lblL0)
    !!ir (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
    !!ir (AST.jmp (AST.name lblEnd))
    !!ir (AST.lmark lblL1)
    !!ir (rd := AST.sext 64<rt> (AST.extract rt 16<rt> 0))
    !!ir (AST.lmark lblEnd)
  else
    !!ir (rd := AST.sext 32<rt> (AST.extract rt 16<rt> 0))
  advancePC ctxt ir
  !>ir insLen

let sll insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, sa = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  if ctxt.WordBitSize = 64<rt> then
    let rt = AST.xtlo 32<rt> rt
    !!ir (rd := AST.sext 64<rt> (rt << AST.xtlo 32<rt> sa))
  else
    !!ir (rd := rt << sa)
  advancePC ctxt ir
  !>ir insLen

let sllv insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, rs = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let mask = numI32 31 32<rt>
  !<ir insLen
  if ctxt.WordBitSize = 64<rt> then
    let rt = AST.xtlo 32<rt> rt
    !!ir (rd := AST.sext 64<rt> (rt << (AST.xtlo 32<rt> rs .& mask)))
  else
    !!ir (rd := rt << (rs .& mask))
  advancePC ctxt ir
  !>ir insLen

let slt insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = AST.lt rs rt
  let rtVal =
    AST.ite cond (AST.num1 ctxt.WordBitSize) (AST.num0 ctxt.WordBitSize)
  !<ir insLen
  !!ir (rd := rtVal)
  advancePC ctxt ir
  !>ir insLen

let slti insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = AST.lt rs imm
  let rtVal =
    AST.ite cond (AST.num1 ctxt.WordBitSize) (AST.num0 ctxt.WordBitSize)
  !<ir insLen
  !!ir (rt := rtVal)
  advancePC ctxt ir
  !>ir insLen

let sltiu insInfo insLen ctxt =
  let ir = !*ctxt
  let wordSz = ctxt.WordBitSize
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = AST.lt (AST.zext (wordSz * 2) rs) (AST.zext (wordSz * 2) imm)
  let rtVal =
    AST.ite cond (AST.num1 ctxt.WordBitSize) (AST.num0 ctxt.WordBitSize)
  !<ir insLen
  !!ir (rt := rtVal)
  advancePC ctxt ir
  !>ir insLen

let sltu insInfo insLen ctxt =
  let ir = !*ctxt
  let wordSz = ctxt.WordBitSize
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = AST.lt (AST.zext (wordSz * 2) rs) (AST.zext (wordSz * 2) rt)
  let rtVal =
    AST.ite cond (AST.num1 ctxt.WordBitSize) (AST.num0 ctxt.WordBitSize)
  !<ir insLen
  !!ir (rd := rtVal)
  advancePC ctxt ir
  !>ir insLen

let sra insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, sa = getThreeOprs insInfo
  let rd, rt = transTwoOprs insInfo ctxt (rd, rt)
  let sa = numI32 (int32 (transOprToImm sa)) 32<rt>
  !<ir insLen
  if ctxt.WordBitSize = 64<rt> then
    let lblL0 = !%ir "L0"
    let lblL1 = !%ir "L1"
    let lblEnd = !%ir "End"
    let cond = notWordValue rt
    let t1 = !+ir 32<rt>
    !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
    !!ir (AST.lmark lblL0)
    !!ir (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
    !!ir (AST.jmp (AST.name lblEnd))
    !!ir (AST.lmark lblL1)
    !!ir (t1 := AST.xtlo 32<rt> rt)
    !!ir (rd := AST.sext 64<rt> (t1 ?>> sa))
    !!ir (AST.lmark lblEnd)
  else
    !!ir (rd := rt ?>> sa)
  advancePC ctxt ir
  !>ir insLen

let srl insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, sa = getThreeOprs insInfo
  let rd, rt = transTwoOprs insInfo ctxt (rd, rt)
  let sa = numI32 (int32 (transOprToImm sa)) 32<rt>
  !<ir insLen
  if ctxt.WordBitSize = 64<rt> then
    let lblL0 = !%ir "L0"
    let lblL1 = !%ir "L1"
    let lblEnd = !%ir "End"
    let cond = notWordValue rt
    let t1 = !+ir 32<rt>
    !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
    !!ir (AST.lmark lblL0)
    !!ir (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
    !!ir (AST.jmp (AST.name lblEnd))
    !!ir (AST.lmark lblL1)
    !!ir (t1 := AST.xtlo 32<rt> rt)
    !!ir (rd := AST.sext 64<rt> (t1 >> sa))
    !!ir (AST.lmark lblEnd)
  else
    !!ir (rd := rt >> sa)
  advancePC ctxt ir
  !>ir insLen

let srlv insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, rs = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let mask = numI32 31 32<rt>
  !<ir insLen
  if ctxt.WordBitSize = 64<rt> then
    let lblL0 = !%ir "L0"
    let lblL1 = !%ir "L1"
    let lblEnd = !%ir "End"
    let cond = notWordValue rt
    let t1 = !+ir 32<rt>
    !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
    !!ir (AST.lmark lblL0)
    !!ir (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
    !!ir (AST.jmp (AST.name lblEnd))
    !!ir (AST.lmark lblL1)
    !!ir (t1 := AST.xtlo 32<rt> rt)
    !!ir (rd := AST.sext 64<rt> (t1 >> (AST.xtlo 32<rt> rs .& mask)))
    !!ir (AST.lmark lblEnd)
  else
    !!ir (rd := rt >> (rs .& mask))
  advancePC ctxt ir
  !>ir insLen

let subu insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rs .- rt)
  advancePC ctxt ir
  !>ir insLen

let subu64 insInfo insLen ctxt =
  let ir = !*ctxt
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = notWordValue rs .| notWordValue rt
  !<ir insLen
  !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (AST.sideEffect UndefinedInstr) (* FIXME: UNPREDICTABLE *)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (rd := rs .- rt)
  !!ir (AST.lmark lblEnd)
  advancePC ctxt ir
  !>ir insLen

let teq insInfo insLen ctxt =
  let ir = !*ctxt
  let lblL0 = !%ir "L0"
  let lblEnd = !%ir "End"
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (AST.cjmp (rs == rt) (AST.name lblL0) (AST.name lblEnd))
  !!ir (AST.lmark lblL0)
  !!ir (AST.sideEffect UndefinedInstr) (* FIXME: Trap *)
  !!ir (AST.lmark lblEnd)
  advancePC ctxt ir
  !>ir insLen

let logXor insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rs <+> rt)
  advancePC ctxt ir
  !>ir insLen

let xori insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rt := rs <+> imm)
  advancePC ctxt ir
  !>ir insLen

let transaui insInfo ctxt =
  match insInfo.Operands with
  | TwoOperands _ -> lui insInfo ctxt
  | ThreeOperands _ -> aui insInfo ctxt
  | _ -> raise InvalidOperandException

let translate insInfo insLen (ctxt: TranslationContext) =
  match insInfo.Opcode with
  | Op.ADD when insInfo.Fmt.IsNone && ctxt.WordBitSize = 32<rt> ->
    add insInfo insLen ctxt
  | Op.ADD when insInfo.Fmt.IsNone -> add64 insInfo insLen ctxt
  | Op.ADD -> sideEffects insLen ctxt UnsupportedFP
  | Op.ADDIU when ctxt.WordBitSize = 32<rt> -> addiu insInfo insLen ctxt
  | Op.ADDIU -> addiu64 insInfo insLen ctxt
  | Op.ADDU when ctxt.WordBitSize = 32<rt> -> addu insInfo insLen ctxt
  | Op.ADDU -> addu64 insInfo insLen ctxt
  | Op.AND -> logAnd insInfo insLen ctxt
  | Op.ANDI -> andi insInfo insLen ctxt
  | Op.AUI -> transaui insInfo insLen ctxt
  | Op.B -> b insInfo insLen ctxt
  | Op.BAL -> bal insInfo insLen ctxt
  | Op.BC1F | Op.BC1T -> sideEffects insLen ctxt UnsupportedFP
  | Op.BEQ | Op.BEQL -> beq insInfo insLen ctxt
  | Op.BGEZ -> bgez insInfo insLen ctxt
  | Op.BGEZAL -> bgezal insInfo insLen ctxt
  | Op.BGTZ -> bgtz insInfo insLen ctxt
  | Op.BLEZ -> blez insInfo insLen ctxt
  | Op.BLTZ -> bltz insInfo insLen ctxt
  | Op.BLTZAL -> bltzal insInfo insLen ctxt
  | Op.BNE | Op.BNEL -> bne insInfo insLen ctxt
  | Op.BREAK -> sideEffects insLen ctxt Breakpoint
  | Op.C | Op.CFC1 | Op.CTC1 -> sideEffects insLen ctxt UnsupportedFP
  | Op.CLZ -> clz insInfo insLen ctxt
  | Op.CVTD | Op.CVTS | Op.CVTW -> sideEffects insLen ctxt UnsupportedFP
  | Op.DADDU -> addu insInfo insLen ctxt
  | Op.DADDIU -> daddiu insInfo insLen ctxt
  | Op.DCLZ -> dclz insInfo insLen ctxt
  | Op.DMFC1 | Op.DMTC1 -> sideEffects insLen ctxt UnsupportedFP
  | Op.DEXT -> dext insInfo insLen ctxt
  | Op.DEXTM -> dextx insInfo insLen checkDEXTMPosSize ctxt
  | Op.DEXTU -> dextx insInfo insLen checkDEXTUPosSize ctxt
  | Op.DINS -> dins insInfo insLen ctxt
  | Op.DINSM -> dinsx insInfo insLen checkDINSMPosSize ctxt
  | Op.DINSU -> dinsx insInfo insLen checkDINSUPosSize ctxt
  | Op.DIV when insInfo.Fmt.IsSome -> sideEffects insLen ctxt UnsupportedFP
  | Op.DIVU -> divu insInfo insLen ctxt
  | Op.DDIVU -> ddivu insInfo insLen ctxt
  | Op.DMULT -> dmult insInfo insLen ctxt
  | Op.DMULTU -> dmultu insInfo insLen ctxt
  | Op.DROTR -> drotr insInfo insLen ctxt
  | Op.DSLL -> dsll insInfo insLen ctxt
  | Op.DSLL32 -> dsll32 insInfo insLen ctxt
  | Op.DSLLV -> dsllv insInfo insLen ctxt
  | Op.DSRA -> dsra insInfo insLen ctxt
  | Op.DSRA32 -> dsra32 insInfo insLen ctxt
  | Op.DSRL -> dsrl insInfo insLen ctxt
  | Op.DSRL32 -> dsrl32 insInfo insLen ctxt
  | Op.DSRLV -> dsrlv insInfo insLen ctxt
  | Op.DSUBU -> subu insInfo insLen ctxt
  | Op.EHB -> nop insLen ctxt
  | Op.EXT when ctxt.WordBitSize = 3232<rt> -> ext insInfo insLen ctxt
  | Op.EXT -> ext64 insInfo insLen ctxt
  | Op.INS when ctxt.WordBitSize = 3232<rt> -> ins insInfo insLen ctxt
  | Op.INS -> ins64 insInfo insLen ctxt
  | Op.JALR | Op.JALRHB -> jalr insInfo insLen ctxt
  | Op.JR | Op.JRHB -> jr insInfo insLen ctxt
  | Op.PAUSE -> sideEffects insLen ctxt Delay
  | Op.LH | Op.LD -> loadHalfDword insInfo insLen ctxt
  | Op.LB | Op.LW -> loadByteWord insInfo insLen ctxt
  | Op.LBU | Op.LHU | Op.LWU -> loadu insInfo insLen ctxt
  | Op.LDC1 | Op.LWC1 | Op.SDC1 | Op.SWC1 ->
    sideEffects insLen ctxt UnsupportedFP
  | Op.LUI -> lui insInfo insLen ctxt
  | Op.MADD when insInfo.Fmt.IsNone -> madd insInfo insLen ctxt
  | Op.MADD -> sideEffects insLen ctxt UnsupportedFP
  | Op.MFHI -> mfhi insInfo insLen ctxt
  | Op.MFLO -> mflo insInfo insLen ctxt
  | Op.MFC1 -> sideEffects insLen ctxt UnsupportedFP
  | Op.MOV -> sideEffects insLen ctxt UnsupportedFP
  | Op.MOVZ -> movz insInfo insLen ctxt
  | Op.MOVN -> movn insInfo insLen ctxt
  | Op.MTC1 -> sideEffects insLen ctxt UnsupportedFP
  | Op.MUL when insInfo.Fmt.IsNone -> mul insInfo insLen ctxt
  | Op.MUL -> sideEffects insLen ctxt UnsupportedFP
  | Op.MULT -> mult insInfo insLen ctxt
  | Op.MULTU -> multu insInfo insLen ctxt
  | Op.NOP -> nop insLen ctxt
  | Op.NOR -> nor insInfo insLen ctxt
  | Op.OR -> logOr insInfo insLen ctxt
  | Op.ORI -> ori insInfo insLen ctxt
  | Op.ROTR -> rotr insInfo insLen ctxt
  | Op.SLL -> sll insInfo insLen ctxt
  | Op.SLLV -> sllv insInfo insLen ctxt
  | Op.SLT -> slt insInfo insLen ctxt
  | Op.SLTI -> slti insInfo insLen ctxt
  | Op.SLTIU -> sltiu insInfo insLen ctxt
  | Op.SLTU -> sltu insInfo insLen ctxt
  | Op.SSNOP -> nop insLen ctxt
  | Op.SB -> sb insInfo insLen ctxt
  | Op.SD -> sd insInfo insLen ctxt
  | Op.SEB -> seb insInfo insLen ctxt
  | Op.SEH -> seh insInfo insLen ctxt
  | Op.SH -> sh insInfo insLen ctxt
  | Op.SRA -> sra insInfo insLen ctxt
  | Op.SRL -> srl insInfo insLen ctxt
  | Op.SRLV -> srlv insInfo insLen ctxt
  | Op.SUB when insInfo.Fmt.IsSome -> sideEffects insLen ctxt UnsupportedFP
  | Op.SUBU when ctxt.WordBitSize = 32<rt> -> subu insInfo insLen ctxt
  | Op.SUBU -> subu64 insInfo insLen ctxt
  | Op.SW -> sw insInfo insLen ctxt
  | Op.SDL -> sdl insInfo insLen ctxt
  | Op.SDR -> sdr insInfo insLen ctxt
  | Op.SWL -> swl insInfo insLen ctxt
  | Op.SWR -> swr insInfo insLen ctxt
  | Op.TEQ -> teq insInfo insLen ctxt
  | Op.TRUNCL | Op.TRUNCW -> sideEffects insLen ctxt UnsupportedFP
  | Op.XOR -> logXor insInfo insLen ctxt
  | Op.XORI -> xori insInfo insLen ctxt
  | Op.ABS | Op.BC3F | Op.BC3FL | Op.BC3T | Op.BC3TL | Op.DDIV | Op.DIV
  | Op.DROTR32 | Op.DROTRV | Op.DSBH | Op.DSHD | Op.DSRAV | Op.J | Op.JAL
  | Op.LDL | Op.LDR | Op.LDXC1 | Op.LWL | Op.LWR | Op.LWXC1 | Op.MADDU
  | Op.MFHC1 | Op.MOVF | Op.MOVN | Op.MOVT | Op.MSUB | Op.MTHC1 | Op.MTHI
  | Op.MTLO | Op.NEG | Op.ROTRV | Op.SDXC1 | Op.SQRT | Op.SRAV | Op.SWXC1
  | Op.SYNC | Op.TRUNCL | Op.WSBH ->
    sideEffects insLen ctxt UnsupportedExtension // XXX this is a temporary fix
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException (Disasm.opCodeToString o)