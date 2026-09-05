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

module internal B2R2.FrontEnd.SPARC.GeneralLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils

/// SPARC's %g0 reads as zero and discards writes. This shadows AST's := for
/// every lifter below so an assignment to %g0 becomes a self-assign the
/// optimizer drops; %g0 thus stays at its initial zero and reads back as zero,
/// which is what mov/clr/cmp/tst and a jmpl (or ret) discarding its link into
/// %g0 all rely on.
let inline (:=) dst src =
  match dst with
  | Var(_, rid, _, _) when rid = Register.toRegID Register.G0 -> dst := dst
  | _ -> dst := src

/// Marks the start of an instruction and, when it is the delay slot of an
/// annulling conditional branch (AnnulCond set by that branch), wraps the body
/// in a guard: it runs only if the branch was taken, else jumps past it to a
/// skip label the matching instruction end plants. It stands in for
/// LiftingUtils's markStart.
let markInsStart (bld: ILowUIRBuilder) addr insLen =
  bld.Stream.MarkStart(addr, insLen)
  match bld with
  | :? LowUIRBuilder as sbld ->
    (* A branch deferred by a prior block's decode expects its delay slot at a
       fixed address; reaching a different address instead means that state
       leaked across the block boundary (the slot was never lifted here), so
       drop it rather than flush this unrelated instruction as the slot. *)
    match sbld.DelaySlotAddr with
    | ValueSome expected when sbld.DelayedBranch <> InterJmpKind.NotAJmp
                              && not sbld.Armed
                              && addr <> expected -> sbld.ResetDelayState()
    | _ -> ()
    sbld.CurAddr <- addr
    match sbld.AnnulCond with
    | ValueSome cond ->
      let runLbl = label bld "AnnulRun"
      let skipLbl = label bld "AnnulSkip"
      append bld {
        AST.cjmp cond (AST.jmpDest runLbl) (AST.jmpDest skipLbl)
        AST.lmark runLbl
      }
      sbld.AnnulSkip <- ValueSome skipLbl
      sbld.AnnulCond <- ValueNone
    | ValueNone ->
      ()
  | _ ->
    ()

/// Finalizes an instruction: closes any annulled delay slot's skip label, then
/// flushes a pending delayed branch. A SPARC control transfer arms the branch
/// and stores its target in %nPC rather than jumping, so the delay-slot
/// instruction that follows executes and then this emits the InterJmp. The
/// transfer's own end (Armed) defers; the delay slot's end flushes. It
/// stands in for LiftingUtils's markEnd.
let markInsEnd (bld: ILowUIRBuilder) insLen =
  match bld with
  | :? LowUIRBuilder as sbld ->
    match sbld.AnnulSkip with
    | ValueSome lbl ->
      append bld {
        AST.lmark lbl
      }
      sbld.AnnulSkip <- ValueNone
    | ValueNone ->
      ()
    if sbld.DelayedBranch <> InterJmpKind.NotAJmp then
      if sbld.Armed then
        sbld.Armed <- false
        sbld.DelaySlotAddr <- ValueSome(sbld.CurAddr + uint64 insLen)
      else
        append bld {
          AST.interjmp (regVar bld Register.NPC) sbld.DelayedBranch
        }
        sbld.Disarm()
    else
      ()
    bld.Stream.MarkEnd insLen
    bld
  | _ ->
    bld.Stream.MarkEnd insLen
    bld


/// Provides the `lift` computation expression for SPARC, whose instruction
/// marks carry the delay-slot bookkeeping that LiftingUtils's cannot. It
/// shadows the one from LiftingUtils, so a lifter in this module gets the
/// SPARC marks without asking for them.
[<Struct>]
type LiftBuilder =
  /// Builder that the statements are emitted into.
  val Bld: ILowUIRBuilder

  /// Address of the instruction being lifted.
  val Address: Addr

  /// Length of the instruction being lifted.
  val InsLen: uint32

  /// Creates a lift builder for the instruction at the given address.
  new(bld, addr, insLen) = { Bld = bld; Address = addr; InsLen = insLen }

  member inline _.Zero() = ()

  member inline _.Delay([<InlineIfLambda>] f: unit -> unit) = f

  member inline _.Combine((), [<InlineIfLambda>] f: unit -> unit) = f ()

  member inline this.Yield(stmt: Stmt) = this.Bld.Stream.Append stmt

  member inline _.For(xs: seq<'T>, [<InlineIfLambda>] f: 'T -> unit) =
    for x in xs do f x

  member inline this.Run([<InlineIfLambda>] f: unit -> unit) =
    markInsStart this.Bld this.Address this.InsLen
    f ()
    markInsEnd this.Bld this.InsLen

/// Starts lifting the given instruction, closing it with the SPARC
/// instruction end rather than a plain IEMark.
let inline lift bld (ins: Instruction) insLen =
  LiftBuilder(bld, ins.Address, insLen)

/// Arms a delayed control transfer of the given kind; its target must already
/// have been stored into %nPC. The following instruction end (after the
/// delay slot) emits
/// the InterJmp.
let arm (bld: ILowUIRBuilder) kind = (bld :?> LowUIRBuilder).Arm kind

let inline numI32PC (n: int) = BitVector(n, 64<rt>) |> AST.num

let inline getCCVar (bld: ILowUIRBuilder) name =
  ConditionCode.toRegID name |> bld.GetRegVar

let dstAssign oprSize dst src =
  match oprSize with
  | 8<rt> | 16<rt> ->
    dst := src (* No extension for 8- and 16-bit operands *)
  | _ ->
    let dst = AST.unwrap dst
    let dstOrigSz = dst |> Expr.typeOf
    let oprBitSize = RegType.toBitWidth oprSize
    let dstBitSize = RegType.toBitWidth dstOrigSz
    if dstBitSize > oprBitSize then dst := AST.zext dstOrigSz src
    elif dstBitSize = oprBitSize then dst := src
    else raise InvalidOperandSizeException

let transOprToExpr ins insLen bld = function
  | OprReg reg -> regVar bld reg
  | OprImm imm -> numI32 imm 64<rt>
  | OprAddr addr -> numI32PC addr
  | OprCC cc -> getCCVar bld cc
  | OprPriReg prireg -> regVar bld prireg
  | _ -> Terminator.impossible ()

let isRegOpr (ins: Instruction) insLen bld =
  match ins.Operands with
  | ThreeOperands(_, o2, _) ->
    match o2 with
    | OprReg reg -> true
    | _ -> false
  | _ ->
    raise InvalidOperandException

let getOneOpr (ins: Instruction) =
  match ins.Operands with
  | OneOperand opr -> opr
  | _ -> raise InvalidOperandException

let getTwoOprs (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(o1, o2) -> o1, o2
  | _ -> raise InvalidOperandException

let getThreeOprs (ins: Instruction) =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) -> o1, o2, o3
  | _ -> raise InvalidOperandException

let transOneOpr (ins: Instruction) insLen bld =
  match ins.Operands with
  | OneOperand o1 -> transOprToExpr ins insLen bld o1
  | _ -> raise InvalidOperandException

let transTwoOprs (ins: Instruction) insLen bld =
  match ins.Operands with
  | TwoOperands(o1, o2) ->
    struct (transOprToExpr ins insLen bld o1, transOprToExpr ins insLen bld o2)
  | _ ->
    raise InvalidOperandException

let transThreeOprs (ins: Instruction) insLen bld =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) ->
    let o1 = transOprToExpr ins insLen bld o1
    let o2 = transOprToExpr ins insLen bld o2
    let o3 = transOprToExpr ins insLen bld o3
    struct (o1, o2, o3)
  | _ ->
    raise InvalidOperandException

let transFourOprs (ins: Instruction) insLen bld =
  match ins.Operands with
  | FourOperands(o1, o2, o3, o4) ->
    let o1 = transOprToExpr ins insLen bld o1
    let o2 = transOprToExpr ins insLen bld o2
    let o3 = transOprToExpr ins insLen bld o3
    let o4 = transOprToExpr ins insLen bld o4
    struct (o1, o2, o3, o4)
  | _ ->
    raise InvalidOperandException

let transAddrThreeOprs (ins: Instruction) insLen bld =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) ->
    struct (transOprToExpr ins insLen bld o1 .+
            transOprToExpr ins insLen bld o2, transOprToExpr ins insLen bld o3)
  | _ ->
    raise InvalidOperandException

let transAddrFourOprs (ins: Instruction) insLen bld =
  match ins.Operands with
  | FourOperands(o1, o2, o3, o4) ->
    let o1 = transOprToExpr ins insLen bld o1
    let o2 = transOprToExpr ins insLen bld o2
    let o3 = transOprToExpr ins insLen bld o3
    let o4 = transOprToExpr ins insLen bld o4
    struct (o1 .+ o2, o3, o4)
  | _ ->
    raise InvalidOperandException

let transTwooprsAddr (ins: Instruction) insLen bld =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) ->
    let o1 = transOprToExpr ins insLen bld o1
    let o2 = transOprToExpr ins insLen bld o2
    let o3 = transOprToExpr ins insLen bld o3
    struct (o1, o2 .+ o3)
  | _ ->
    raise InvalidOperandException

let transThroprsAddr (ins: Instruction) insLen bld =
  match ins.Operands with
  | FourOperands(o1, o2, o3, o4) ->
    let o1 = transOprToExpr ins insLen bld o1
    let o2 = transOprToExpr ins insLen bld o2
    let o3 = transOprToExpr ins insLen bld o3
    let o4 = transOprToExpr ins insLen bld o4
    struct (o1, o2 .+ o3, o4)
  | _ ->
    raise InvalidOperandException

let getConditionCodeAdd res src src1 =
  let sign = AST.extract src 1<rt> 63
  let sign1 = AST.extract src1 1<rt> 63
  let ressign = AST.extract res 1<rt> 63
  let res32 = AST.extract res 32<rt> 0
  let sign32 = AST.extract src 1<rt> 31
  let sign321 = AST.extract src1 1<rt> 31
  let ressign32 = AST.extract res 1<rt> 31
  let xccn = ressign
  let xccz = res == AST.num0 64<rt>
  let xccv = ((sign .& sign1 .& AST.not ressign) .|
    (AST.not sign .& AST.not sign1 .& ressign))
  let xccc = (sign .& sign1) .| ((AST.not ressign) .& (sign .| sign1))
  let iccn = (ressign32)
  let iccz = ((res32) == AST.num0 32<rt>)
  let iccv = ((sign32 .& sign321 .& AST.not ressign32) .|
    (AST.not sign32 .& AST.not sign321 .& ressign32))
  let iccc = (sign32 .& sign321) .| ((AST.not ressign32) .& (sign32 .| sign321))
  // AST.concat xccn (AST. concat xccz (AST.concat xccv (AST.concat xccc
    // (AST.concat iccn (AST.concat iccz (AST.concat iccv iccc))))))
  AST.revConcat [| iccc; iccv; iccz; iccn; xccc; xccv; xccz; xccn |]

let getConditionCodeSub res src src1 =
  let sign = AST.extract src 1<rt> 63
  let sign1 = AST.extract src1 1<rt> 63
  let ressign = AST.extract res 1<rt> 63
  let res32 = AST.extract res 32<rt> 0
  let sign32 = AST.extract src 1<rt> 31
  let sign321 = AST.extract src1 1<rt> 31
  let ressign32 = AST.extract res 1<rt> 31
  let xccn = ressign
  let xccz = res == AST.num0 64<rt>
  let xccv = ((sign .& AST.not sign1 .& AST.not ressign) .|
    (AST.not sign .& sign1 .& ressign))
  let xccc = (((AST.not sign) .& sign1) .|
    (ressign .& ((AST.not sign) .| sign1)))
  let iccn = (ressign32)
  let iccz = ((res32) == AST.num0 32<rt>)
  let iccv = ((sign32 .& AST.not sign321 .& AST.not ressign32) .|
    (AST.not sign32 .& sign321 .& ressign32))
  let iccc = (((AST.not sign32) .& sign321) .|
    (ressign32 .& ((AST.not sign32) .| sign321)))
  // AST.concat xccn (AST. concat xccz (AST.concat xccv (AST.concat xccc
    // (AST.concat iccn (AST.concat iccz (AST.concat iccv iccc))))))
  AST.revConcat [| iccc; iccv; iccz; iccn; xccc; xccv; xccz; xccn |]

let getConditionCodeLog res src src1 =
  let sign = AST.extract src 1<rt> 63
  let sign1 = AST.extract src1 1<rt> 63
  let ressign = AST.extract res 1<rt> 63
  let res32 = AST.extract res 32<rt> 0
  let sign32 = AST.extract src 1<rt> 31
  let sign321 = AST.extract src1 1<rt> 31
  let ressign32 = AST.extract res 1<rt> 31
  let xccn = ressign
  let xccz = res == AST.num0 64<rt>
  let xccv = AST.num0 1<rt>
  let xccc = AST.num0 1<rt>
  let iccn = (ressign32)
  let iccz = ((res32) == AST.num0 32<rt>)
  let iccv = AST.num0 1<rt>
  let iccc = AST.num0 1<rt>
  // AST.concat xccn (AST. concat xccz (AST.concat xccv (AST.concat xccc
    // (AST.concat iccn (AST.concat iccz (AST.concat iccv iccc))))))
  AST.revConcat [| iccc; iccv; iccz; iccn; xccc; xccv; xccz; xccn |]

let getConditionCodeMul res src src1 =
  let sign = AST.extract src 1<rt> 63
  let sign1 = AST.extract src1 1<rt> 63
  let ressign = AST.extract res 1<rt> 63
  let res32 = AST.extract res 32<rt> 0
  let sign32 = AST.extract src 1<rt> 31
  let sign321 = AST.extract src1 1<rt> 31
  let ressign32 = AST.extract res 1<rt> 31
  let xccn = ressign
  let xccz = res == AST.num0 64<rt>
  let xccv = AST.num0 1<rt>
  let xccc = AST.num0 1<rt>
  let iccn = (ressign32)
  let iccz = ((res32) == AST.num0 32<rt>)
  let iccv = AST.num0 1<rt>
  let iccc = AST.num0 1<rt>
  // AST.concat xccn (AST. concat xccz (AST.concat xccv (AST.concat xccc
    // (AST.concat iccn (AST.concat iccz (AST.concat iccv iccc))))))
  AST.revConcat [| iccc; iccv; iccz; iccn; xccc; xccv; xccz; xccn |]

let getConditionCodeMulscc res src src1 =
  let res32 = AST.extract res 32<rt> 0
  let sign32 = AST.extract src 1<rt> 31
  let sign321 = AST.extract src1 1<rt> 31
  let ressign32 = AST.extract res 1<rt> 31
  let iccn = ressign32
  let iccz = res32 == AST.num0 32<rt>
  let iccv = (sign32 .& sign321 .& AST.not ressign32 .|
    (AST.not sign32 .& AST.not sign321 .& ressign32))
  let iccc = (sign32 .& sign321) .| ((AST.not ressign32)
    .& (sign32 .| sign321))
  AST.revConcat [| iccc; iccv; iccz; iccn |]

let getNextReg bld reg =
  if reg = regVar bld Register.G0 then Register.G1
  elif reg = regVar bld Register.G2 then Register.G3
  elif reg = regVar bld Register.G4 then Register.G5
  elif reg = regVar bld Register.G6 then Register.G7
  elif reg = regVar bld Register.O0 then Register.O1
  elif reg = regVar bld Register.O2 then Register.O3
  elif reg = regVar bld Register.O4 then Register.O5
  elif reg = regVar bld Register.O6 then Register.O7
  elif reg = regVar bld Register.L0 then Register.L1
  elif reg = regVar bld Register.L2 then Register.L3
  elif reg = regVar bld Register.L4 then Register.L5
  elif reg = regVar bld Register.L6 then Register.L7
  elif reg = regVar bld Register.I0 then Register.I1
  elif reg = regVar bld Register.I2 then Register.I3
  elif reg = regVar bld Register.I4 then Register.I5
  elif reg = regVar bld Register.I6 then Register.I7
  else raise InvalidRegisterException

let getFloatClass bld freg =
  if (freg = regVar bld Register.F0
    || freg = regVar bld Register.F2
    || freg = regVar bld Register.F4
    || freg = regVar bld Register.F6
    || freg = regVar bld Register.F8
    || freg = regVar bld Register.F10
    || freg = regVar bld Register.F12
    || freg = regVar bld Register.F14
    || freg = regVar bld Register.F16
    || freg = regVar bld Register.F18
    || freg = regVar bld Register.F20
    || freg = regVar bld Register.F22
    || freg = regVar bld Register.F24
    || freg = regVar bld Register.F26
    || freg = regVar bld Register.F28
    || freg = regVar bld Register.F30)
  then 0
  elif (freg = regVar bld Register.F32
    || freg = regVar bld Register.F34
    || freg = regVar bld Register.F36
    || freg = regVar bld Register.F38
    || freg = regVar bld Register.F40
    || freg = regVar bld Register.F42
    || freg = regVar bld Register.F44
    || freg = regVar bld Register.F46
    || freg = regVar bld Register.F48
    || freg = regVar bld Register.F50
    || freg = regVar bld Register.F52
    || freg = regVar bld Register.F54
    || freg = regVar bld Register.F56
    || freg = regVar bld Register.F58
    || freg = regVar bld Register.F60
    || freg = regVar bld Register.F62)
  then 1
  else raise InvalidRegisterException

let getDFloatNext bld freg =
  if freg = regVar bld Register.F0 then Register.F1
  elif freg = regVar bld Register.F2 then Register.F3
  elif freg = regVar bld Register.F4 then Register.F5
  elif freg = regVar bld Register.F6 then Register.F7
  elif freg = regVar bld Register.F8 then Register.F9
  elif freg = regVar bld Register.F10 then Register.F11
  elif freg = regVar bld Register.F12 then Register.F13
  elif freg = regVar bld Register.F14 then Register.F15
  elif freg = regVar bld Register.F16 then Register.F17
  elif freg = regVar bld Register.F18 then Register.F19
  elif freg = regVar bld Register.F20 then Register.F21
  elif freg = regVar bld Register.F22 then Register.F23
  elif freg = regVar bld Register.F24 then Register.F25
  elif freg = regVar bld Register.F26 then Register.F27
  elif freg = regVar bld Register.F28 then Register.F29
  elif freg = regVar bld Register.F30 then Register.F31
  else raise InvalidRegisterException

let movFregD bld src dst =
  let sClass = getFloatClass bld src
  let dClass = getFloatClass bld dst
  match sClass, dClass with
  | 0, 0 ->
    let nextsrc = regVar bld (getDFloatNext bld src)
    let nextdst = regVar bld (getDFloatNext bld dst)
    append bld {
      dst := src
      nextdst := nextsrc
    }
  | 0, 1 ->
    let nextsrc = regVar bld (getDFloatNext bld src)
    append bld {
      AST.extract dst 32<rt> 0 := nextsrc
      AST.extract dst 32<rt> 32 := src
    }
  | 1, 0 ->
    let nextdst = regVar bld (getDFloatNext bld dst)
    append bld {
      dst := AST.extract src 32<rt> 32
      nextdst := AST.extract src 32<rt> 0
    }
  | 1, 1 ->
    append bld {
      dst := src
    }
  | _ ->
    raise InvalidRegisterException

let getQFloatNext0 bld freg =
  if (freg = regVar bld Register.F0) then
    struct (Register.F1, Register.F2, Register.F3)
  elif (freg = regVar bld Register.F4) then
    struct (Register.F5, Register.F6, Register.F7)
  elif (freg = regVar bld Register.F8) then
    struct (Register.F9, Register.F10, Register.F11)
  elif (freg = regVar bld Register.F12) then
    struct (Register.F13, Register.F14, Register.F15)
  elif (freg = regVar bld Register.F16) then
    struct (Register.F17, Register.F18, Register.F19)
  elif (freg = regVar bld Register.F20) then
    struct (Register.F21, Register.F22, Register.F23)
  elif (freg = regVar bld Register.F24) then
    struct (Register.F25, Register.F26, Register.F27)
  elif (freg = regVar bld Register.F28) then
    struct (Register.F29, Register.F30, Register.F31)
  else
    raise InvalidRegisterException

let getQFloatNext1 bld freg =
  if (freg = regVar bld Register.F32) then Register.F34
  elif (freg = regVar bld Register.F36) then Register.F38
  elif (freg = regVar bld Register.F40) then Register.F42
  elif (freg = regVar bld Register.F44) then Register.F46
  elif (freg = regVar bld Register.F48) then Register.F50
  elif (freg = regVar bld Register.F52) then Register.F54
  elif (freg = regVar bld Register.F56) then Register.F58
  elif (freg = regVar bld Register.F60) then Register.F62
  else raise InvalidRegisterException

let movFregQ bld src dst =
  let sClass = getFloatClass bld src
  let dClass = getFloatClass bld dst
  match sClass, dClass with
  | 0, 0 ->
    let struct (s1, s2, s3) = getQFloatNext0 bld src
    let src1 = regVar bld s1
    let src2 = regVar bld s2
    let src3 = regVar bld s3
    let struct (d1, d2, d3) = getQFloatNext0 bld dst
    let dst1 = regVar bld d1
    let dst2 = regVar bld d2
    let dst3 = regVar bld d3
    append bld {
      dst := src
      dst1 := src1
      dst2 := src2
      dst3 := src3
    }
  | 0, 1 ->
    let struct (s1, s2, s3) = getQFloatNext0 bld src
    let src1 = regVar bld s1
    let src2 = regVar bld s2
    let src3 = regVar bld s3
    let nextdst = regVar bld (getQFloatNext1 bld dst)
    append bld {
      AST.extract nextdst 32<rt> 0 := src3
      AST.extract nextdst 32<rt> 32 := src2
      AST.extract dst 32<rt> 0 := src1
      AST.extract dst 32<rt> 32 := src
    }
  | 1, 0 ->
    let nextsrc = regVar bld (getQFloatNext1 bld src)
    let struct (d1, d2, d3) = getQFloatNext0 bld dst
    let dst1 = regVar bld d1
    let dst2 = regVar bld d2
    let dst3 = regVar bld d3
    append bld {
      dst := AST.extract src 32<rt> 32
      dst1 := AST.extract src 32<rt> 0
      dst2 := AST.extract nextsrc 32<rt> 32
      dst3 := AST.extract nextsrc 32<rt> 0
    }
  | 1, 1 ->
    let nextsrc = regVar bld (getQFloatNext1 bld src)
    let nextdst = regVar bld (getQFloatNext1 bld dst)
    append bld {
      nextdst := nextsrc
      dst := src
    }
  | _ ->
    raise InvalidRegisterException

let getDFloatOp bld src op =
  let regclass = getFloatClass bld src
  match regclass with
  | 0 ->
    let nextreg = regVar bld (getDFloatNext bld src)
    append bld {
      (AST.extract op 32<rt> 32) := src
      (AST.extract op 32<rt> 0) := nextreg
    }
  | 1 ->
    append bld {
      op := src
    }
  | _ ->
    raise InvalidRegisterException

let getQFloatOp bld src op1 op2 =
  let regclass = getFloatClass bld src
  match regclass with
  | 0 ->
    let struct (r1, r2, r3) = getQFloatNext0 bld src
    let src1 = regVar bld r1
    let src2 = regVar bld r2
    let src3 = regVar bld r3
    append bld {
      (AST.extract op1 32<rt> 32) := src
      (AST.extract op1 32<rt> 0) := src1
      (AST.extract op2 32<rt> 32) := src2
      (AST.extract op2 32<rt> 0) := src3
    }
  | 1 ->
    let r1 = getQFloatNext1 bld src
    let src1 = regVar bld r1
    append bld {
      (AST.extract op1 64<rt> 0) := src
      (AST.extract op2 64<rt> 0) := src1
    }
  | _ ->
    raise InvalidRegisterException

let setDFloatOp bld dst res =
  let regclass = getFloatClass bld dst
  match regclass with
  | 0 ->
    let nextreg = regVar bld (getDFloatNext bld dst)
    append bld {
      dst := (AST.extract res 32<rt> 32)
      nextreg := (AST.extract res 32<rt> 0)
    }
  | 1 ->
    append bld {
      dst := res
    }
  | _ ->
    raise InvalidRegisterException

let setQFloatOp bld dst res1 res2 =
  let regclass = getFloatClass bld dst
  match regclass with
  | 0 ->
    let struct (r1, r2, r3) = getQFloatNext0 bld dst
    let dst1 = regVar bld r1
    let dst2 = regVar bld r2
    let dst3 = regVar bld r3
    append bld {
      dst := (AST.extract res1 32<rt> 32)
      dst1 := (AST.extract res1 32<rt> 0)
      dst2 := (AST.extract res2 32<rt> 32)
      dst3 := (AST.extract res2 32<rt> 0)
    }
  | 1 ->
    let r1 = getQFloatNext1 bld dst
    let dst1 = regVar bld r1
    append bld {
      dst := (AST.extract res1 64<rt> 0)
      dst1 := (AST.extract res2 64<rt> 0)
    }
  | _ ->
    raise InvalidRegisterException

/// VIS 64-bit logical/select ops (fzerod, fsrc*d, for*d, ...): read the two
/// double-float sources as 64-bit values, apply the bitwise operation, and
/// write the double-float destination. These are pure bit operations -- no FP
/// rounding or exceptions -- so they need no FSR handling.
let visLogic ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let op1 = tmpVar bld 64<rt>
    let op2 = tmpVar bld 64<rt>
    let res = tmpVar bld 64<rt>
    getDFloatOp bld src op1
    getDFloatOp bld src1 op2
    match ins.Opcode with
    | Opcode.FZEROd -> append bld { res := AST.num0 64<rt> }
    | Opcode.FONEd -> append bld { res := numI64 -1L 64<rt> }
    | Opcode.FSRC1d -> append bld { res := op1 }
    | Opcode.FSRC2d -> append bld { res := op2 }
    | Opcode.FNOT1d -> append bld { res := AST.not op1 }
    | Opcode.FNOT2d -> append bld { res := AST.not op2 }
    | Opcode.FORd -> append bld { res := op1 .| op2 }
    | Opcode.FNORd -> append bld { res := AST.not (op1 .| op2) }
    | Opcode.FANDd -> append bld { res := op1 .& op2 }
    | Opcode.FNANDd -> append bld { res := AST.not (op1 .& op2) }
    | Opcode.FXORd -> append bld { res := op1 <+> op2 }
    | Opcode.FXNORd -> append bld { res := AST.not (op1 <+> op2) }
    | Opcode.FORNOT1d -> append bld { res := (AST.not op1) .| op2 }
    | Opcode.FORNOT2d -> append bld { res := op1 .| (AST.not op2) }
    | Opcode.FANDNOT1d -> append bld { res := (AST.not op1) .& op2 }
    | Opcode.FANDNOT2d -> append bld { res := op1 .& (AST.not op2) }
    | _ -> raise InvalidOpcodeException
    setDFloatOp bld dst res
  }

/// VIS alignaddr[l]: rd = (rs1 + rs2) with the low three bits cleared (an
/// 8-byte-aligned address), and GSR.align (bits 2:0) records the byte offset
/// that faligndata later realigns by -- rs1+rs2 for alignaddr, its negation for
/// the little-endian alignaddrl.
let alignaddr ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let gsr = regVar bld Register.GSR
    let sum = tmpVar bld 64<rt>
    let off = tmpVar bld 64<rt>
    sum := src .+ src1
    match ins.Opcode with
    | Opcode.ALIGNADDRL ->
      append bld { off := (AST.neg sum) .& numI64 7L 64<rt> }
    | _ ->
      append bld { off := sum .& numI64 7L 64<rt> }
    dst := sum .& numI64 -8L 64<rt>
    gsr := (gsr .& numI64 -8L 64<rt>) .| off
  }

/// VIS faligndata: concatenate the two double sources (fs1 high, fs2 low) and
/// extract the 64-bit window starting GSR.align bytes in --
/// (fs1 << align*8) | (fs2 >> (64 - align*8)). An align of 0 yields fs1 (the
/// fs2 shift by 64 folds to 0), matching the hardware.
let faligndata ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let gsr = regVar bld Register.GSR
    let op1 = tmpVar bld 64<rt>
    let op2 = tmpVar bld 64<rt>
    let shl = tmpVar bld 64<rt>
    let res = tmpVar bld 64<rt>
    getDFloatOp bld src op1
    getDFloatOp bld src1 op2
    shl := (gsr .& numI64 7L 64<rt>) .* numI64 8L 64<rt>
    res := (op1 << shl) .| (op2 >> (numI64 64L 64<rt> .- shl))
    setDFloatOp bld dst res
  }

let cast64To128 bld src dst1 dst2 =
  append bld {
    let oprSize = 64<rt>
    let zero = AST.num0 64<rt>
    let tmpSrc = tmpVar bld oprSize
    let n63 = numI32 63 64<rt>
    let n15 = numI32 15 16<rt>
    let n52 = numI32 52 64<rt>
    let one = numI32 1 64<rt>
    let n60 = numI32 60 64<rt>
    let final = tmpVar bld 52<rt>
    let biasDiff = numI32 0x3c00 16<rt>
    let sign = (AST.xtlo 16<rt> (((src >> n63) .& one))) << n15
    let exponent =
      (AST.xtlo 16<rt> (((src >> n52) .& (numI32 0x7ff 64<rt>)))) .+ biasDiff
    let integerpart = numI64 0x0010000000000000L 64<rt>
    let significand = src .& numI64 0xFFFFFFFFFFFFFL 64<rt> .| integerpart
    AST.extract dst1 16<rt> 48 := AST.ite (AST.eq src zero)
                                          (AST.num0 16<rt>)
                                          (sign .| exponent)
    final := AST.ite (AST.eq tmpSrc zero)
                     (AST.num0 52<rt>)
                     (AST.extract significand 52<rt> 0)
    AST.extract dst1 48<rt> 0 := (AST.extract final 48<rt> 4)
    AST.extract dst2 4<rt> 60 := (AST.extract final 4<rt> 0)
    AST.extract dst2 60<rt> 4 := AST.num0 60<rt>
  }

let cast128to64 bld src1 src2 dst =
  append bld {
    let n48 = numI32 48 64<rt>
    let n63 = numI32 63 64<rt>
    let top16b = AST.extract src1 16<rt> 48
    let sign = (AST.zext 64<rt> top16b .& (numI32 0x8000 64<rt>)) << n48
    let biasDiff = numI32 0x3c00 64<rt>
    let tmpExp = tmpVar bld 64<rt>
    let significand = tmpVar bld 64<rt>
    let computedExp =
      (AST.zext 64<rt> (top16b .& (numI32 0x7fff 16<rt>)) .- biasDiff)
    let maxExp = numI32 0x7fe 64<rt>
    let exponent =
      AST.ite (AST.eq top16b (AST.num0 16<rt>))
        (AST.num0 64<rt>)
        (AST.ite (AST.gt tmpExp maxExp) maxExp tmpExp)
    let exponent = exponent << numI32 52 64<rt>
    let n11 = numI32 11 64<rt>
    AST.extract significand 16<rt> 48 := AST.extract src1 16<rt> 32
    AST.extract significand 32<rt> 0 := AST.extract src2 32<rt> 32
    tmpExp := computedExp
    dst := (sign .| exponent .| significand)
  }

/// Rounds a 64-bit result the way FSR's RD field asks for. The mode sits in
/// bits 31 and 30, and every lifter below that hands back a rounded value
/// walks this same cascade.
let roundByFSR bld res64 rounded regSize =
  append bld {
    let fsr = regVar bld Register.FSR
    let fsr30 = AST.extract fsr 1<rt> 30
    let fsr31 = AST.extract fsr 1<rt> 31
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblL4 = label bld "L4"
    let lblL5 = label bld "L5"
    let lblEnd = label bld "End"
    let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
    let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
    let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
    AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rounded := AST.cast CastKind.FtoFRound regSize res64
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    rounded := AST.cast CastKind.FtoFTrunc regSize res64
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5)
    AST.lmark lblL4
    rounded := AST.cast CastKind.FtoFCeil regSize res64
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL5
    rounded := AST.cast CastKind.FtoFFloor regSize res64
    AST.lmark lblEnd
  }

/// A quad-precision operation carried out in 64-bit: both operands are
/// narrowed, `fop` runs on them, and the result is rounded and widened back.
/// Only the operation tells `faddq`, `fsubq`, `fmulq` and `fdivq` apart.
/// Which FSR field the given condition code register writes to. The four
/// fcc fields are not laid out contiguously, so the positions are listed.
let fccPosition bld cc =
  let fcc0 = getCCVar bld ConditionCode.Fcc0
  let fcc1 = getCCVar bld ConditionCode.Fcc1
  let fcc2 = getCCVar bld ConditionCode.Fcc2
  let fcc3 = getCCVar bld ConditionCode.Fcc3
  if cc = fcc0 then 10
  elif cc = fcc1 then 32
  elif cc = fcc2 then 34
  elif cc = fcc3 then 36
  else raise InvalidOperandException

/// Compares two floats and writes the verdict into the FSR field at `pos`:
/// 0 equal, 1 less, 2 greater, 3 unordered. Only how the operands are read
/// tells `fcmps`, `fcmpd` and `fcmpq` apart.
/// Which FSR field a conditional float move reads. `fccPosition` answers the
/// same question for a compare, but raises a different exception, so the two
/// are kept apart.
/// The condition codes a 32-bit divide leaves behind: the reserved nibble and
/// C cleared, N and Z read off the quotient's low word.
let setDivCC bld ccr quotient =
  append bld {
    AST.extract ccr 4<rt> 4 := AST.num0 4<rt>
    AST.extract ccr 1<rt> 3 :=
      AST.ite (AST.extract quotient 1<rt> 31 == AST.b1) AST.b1 AST.b0
    AST.extract ccr 1<rt> 2 :=
      AST.ite (AST.extract quotient 32<rt> 0 == AST.num0 32<rt>) AST.b1 AST.b0
    AST.extract ccr 1<rt> 0 := AST.b0
  }

/// Whether a signed quotient fits 32 bits, and what it saturates to when it
/// does not: INT32_MIN or INT32_MAX by its sign. Overflow (V) is that case.
let signedDivResult quotient =
  let lo = AST.extract quotient 32<rt> 0
  let fits = AST.sext 64<rt> lo == quotient
  let saturated =
    AST.ite fits (AST.sext 64<rt> lo)
      (AST.ite (AST.extract quotient 1<rt> 63 == AST.b1)
               (numU64 0x80000000UL 64<rt>)
               (numU64 0x7fffffffUL 64<rt>))
  struct (fits, saturated)

/// The same for an unsigned quotient, which fits while its high word is zero
/// and saturates to UINT32_MAX otherwise.
let unsignedDivResult quotient =
  let fits = AST.extract quotient 32<rt> 32 == AST.num0 32<rt>
  let saturated =
    AST.ite fits
      (AST.zext 64<rt> (AST.extract quotient 32<rt> 0))
      (numU64 0xFFFFFFFFUL 64<rt>)
  struct (fits, saturated)

let fccMovePosition bld cc =
  if cc = getCCVar bld ConditionCode.Fcc0 then 10
  elif cc = getCCVar bld ConditionCode.Fcc1 then 32
  elif cc = getCCVar bld ConditionCode.Fcc2 then 34
  elif cc = getCCVar bld ConditionCode.Fcc3 then 36
  else raise InvalidRegisterException

/// The four verdicts held in the FSR field at `pos`: equal, less, greater and
/// unordered.
let fccFlags bld pos =
  let fsr = regVar bld Register.FSR
  let fsr0 = AST.extract fsr 1<rt> pos
  let fsr1 = AST.extract fsr 1<rt> (pos + 1)
  let e = (fsr1 == AST.b0 .& fsr0 == AST.b0)
  let l = (fsr1 == AST.b0 .& fsr0 == AST.b1)
  let g = (fsr1 == AST.b1 .& fsr0 == AST.b0)
  let u = (fsr1 == AST.b1 .& fsr0 == AST.b1)
  struct (e, l, g, u)

let compareFloatsInto bld pos op op1 =
  append bld {
    let fsr = regVar bld Register.FSR
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblL4 = label bld "L4"
    let lblL5 = label bld "L5"
    let lblEnd = label bld "End"
    let cond0 = AST.feq op op1
    let cond1 = AST.flt op op1 == AST.b1
    let cond2 = AST.fgt op op1 == AST.b1
    AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    AST.extract fsr 2<rt> pos := numI32 0 2<rt>
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    AST.extract fsr 2<rt> pos := numI32 1 2<rt>
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5)
    AST.lmark lblL4
    AST.extract fsr 2<rt> pos := numI32 2 2<rt>
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL5
    AST.extract fsr 2<rt> pos := numI32 3 2<rt>
    AST.lmark lblEnd
  }

let liftQFloatBinOp ins insLen bld fop =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let regSize = 64<rt>
    let res1 = tmpVar bld regSize
    let res2 = tmpVar bld regSize
    let op01 = tmpVar bld regSize
    let op02 = tmpVar bld regSize
    let op11 = tmpVar bld regSize
    let op12 = tmpVar bld regSize
    let op64 = tmpVar bld 64<rt>
    let op164 = tmpVar bld 64<rt>
    let res64 = tmpVar bld 64<rt>
    let rounded = tmpVar bld regSize
    getQFloatOp bld src op01 op02
    getQFloatOp bld src1 op11 op12
    cast128to64 bld op01 op02 op64
    cast128to64 bld op11 op12 op164
    res64 := fop op64 op164
    roundByFSR bld res64 rounded regSize
    cast64To128 bld rounded res1 res2
    setQFloatOp bld dst res1 res2
  }

let add ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    let res = tmpVar bld oprSize
    res := src .+ src1
    if dst = regVar bld Register.G0 then append bld { dst := AST.num0 64<rt> }
    else append bld { dst := res }
  }

let addcc ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    let res = tmpVar bld oprSize
    let ccr = regVar bld Register.CCR
    let byte = tmpVar bld 8<rt>
    res := src .+ src1
    (* flags before dst: rd may alias an operand the V/C formula reads. *)
    byte := getConditionCodeAdd res src src1
    AST.extract ccr 8<rt> 0 := byte
    if (dst = regVar bld Register.G0) then append bld { dst := AST.num0 64<rt> }
    else append bld { dst := res }
  }

let addC ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    let res = tmpVar bld oprSize
    let ccr = regVar bld Register.CCR
    res := src .+ src1 .+ AST.zext 64<rt> (AST.extract ccr 1<rt> 0)
    if dst = regVar bld Register.G0 then append bld { dst := AST.num0 64<rt> }
    else append bld { dst := res }
  }

let addCcc ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    let res = tmpVar bld oprSize
    let ccr = regVar bld Register.CCR
    let byte = tmpVar bld 8<rt>
    res := src .+ src1 .+ AST.zext 64<rt> (AST.extract ccr 1<rt> 0)
    (* flags before dst: rd may alias an operand the V/C formula reads. *)
    byte := (getConditionCodeAdd res src src1)
    AST.extract ccr 8<rt> 0 := byte
    if dst = regVar bld Register.G0 then append bld { dst := AST.num0 64<rt> }
    else append bld { dst := res }
  }

let ``and`` ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    let res = tmpVar bld oprSize
    res := src .& src1
    if dst = regVar bld Register.G0 then append bld { dst := AST.num0 64<rt> }
    else append bld { dst := res }
  }

let andcc ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    let ccr = regVar bld Register.CCR
    let res = tmpVar bld oprSize
    let byte = tmpVar bld 8<rt>
    res := src .& src1
    if dst = regVar bld Register.G0 then append bld { dst := AST.num0 64<rt> }
    else append bld { dst := res }
    byte := (getConditionCodeLog res src src1)
    AST.extract ccr 8<rt> 0 := byte
  }

let andn ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    let res = tmpVar bld oprSize
    res := src .& (AST.not src1)
    if dst = regVar bld Register.G0 then append bld { dst := AST.num0 64<rt> }
    else append bld { dst := res }
  }

let andncc ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    let ccr = regVar bld Register.CCR
    let res = tmpVar bld oprSize
    let byte = tmpVar bld 8<rt>
    res := src .& (AST.not src1)
    if dst = regVar bld Register.G0 then append bld { dst := AST.num0 64<rt> }
    else append bld { dst := res }
    byte := (getConditionCodeLog res src src1)
    AST.extract ccr 8<rt> 0 := byte
  }

/// Sets %nPC to the taken target when cond holds, else to the not-taken
/// continuation, for a delayed conditional branch: the following delay slot
/// runs and then the instruction end emits the InterJmp to %nPC. The delay
/// slot thus always
/// executes (annulling branches are not yet modeled).
let setNPCCond (bld: ILowUIRBuilder) cond taken notTaken =
  append bld {
    let nPC = regVar bld Register.NPC
    let lblTaken = label bld "Taken"
    let lblNotTaken = label bld "NotTaken"
    let lblEnd = label bld "End"
    AST.cjmp cond (AST.jmpDest lblTaken) (AST.jmpDest lblNotTaken)
    AST.lmark lblTaken
    nPC := taken
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblNotTaken
    nPC := notTaken
    AST.lmark lblEnd
  }

/// Arms a branch's delayed transfer, honoring the annul bit. Without annul the
/// delay slot always runs (%nPC set conditionally, then armed). With annul: an
/// always/never branch (cond is the constant b1/b0) jumps at once, annulling
/// the delay slot; a conditional one arms but records AnnulCond so its delay
/// slot runs only when taken.
let branchTo (bld: ILowUIRBuilder) an cond taken notTaken =
  let annul = (AST.extract an 1<rt> 0 = AST.b1)
  if annul && cond = AST.b1 then
    append bld {
      AST.interjmp taken InterJmpKind.Base
    }
  elif annul && cond = AST.b0 then
    append bld {
      AST.interjmp notTaken InterJmpKind.Base
    }
  else
    setNPCCond bld cond taken notTaken
    arm bld InterJmpKind.Base
    if annul then (bld :?> LowUIRBuilder).AnnulCond <- ValueSome cond else ()

let branchpr ins insLen bld =
  lift bld ins insLen {
    let oprSize = 64<rt>
    let struct (src, label, an, _) = transFourOprs ins insLen bld
    let pc = regVar bld Register.PC
    let branchCond =
      match ins.Opcode with
      | Opcode.BRZ -> (src == AST.num0 oprSize)
      | Opcode.BRLEZ -> (src ?<= AST.num0 oprSize)
      | Opcode.BRLZ -> (src ?< AST.num0 oprSize)
      | Opcode.BRNZ -> (src != AST.num0 oprSize)
      | Opcode.BRGZ -> (src ?> AST.num0 oprSize)
      | Opcode.BRGEZ -> (src ?>= AST.num0 oprSize)
      | _ -> raise InvalidOpcodeException
    let jumpTarget = pc .+ AST.zext 64<rt> label
    branchTo bld an branchCond jumpTarget (pc .+ numI32PC 8)
  }

/// The condition the branchicc family branches on, which the
/// opcode alone decides.
let private branchiccCond (ins: Instruction) ccr =
  match ins.Opcode with
  | Opcode.BA ->
    (AST.b1)
  | Opcode.BN ->
    (AST.b0)
  | Opcode.BNE ->
    (AST.extract ccr 1<rt> 2 == AST.b0)
  | Opcode.BE ->
    (AST.extract ccr 1<rt> 2 == AST.b1)
  | Opcode.BG ->
    (((AST.extract ccr 1<rt> 2) .| ((AST.extract ccr 1<rt> 1) <+>
      (AST.extract ccr 1<rt> 3))) == AST.b0)
  | Opcode.BLE ->
    (((AST.extract ccr 1<rt> 2) .| ((AST.extract ccr 1<rt> 1) <+>
      (AST.extract ccr 1<rt> 3))) == AST.b1)
  | Opcode.BGE ->
    ((AST.extract ccr 1<rt> 1) <+> (AST.extract ccr 1<rt> 3) == AST.b0)
  | Opcode.BL ->
    ((AST.extract ccr 1<rt> 1) <+> (AST.extract ccr 1<rt> 3) == AST.b1)
  | Opcode.BGU ->
    ((AST.extract ccr 1<rt> 0) .| (AST.extract ccr 1<rt> 2) == AST.b0)
  | Opcode.BLEU ->
    ((AST.extract ccr 1<rt> 0) .| (AST.extract ccr 1<rt> 2) == AST.b1)
  | Opcode.BCC ->
    (AST.extract ccr 1<rt> 0 == AST.b0)
  | Opcode.BCS ->
    (AST.extract ccr 1<rt> 0 == AST.b1)
  | Opcode.BPOS ->
    (AST.extract ccr 1<rt> 3 == AST.b0)
  | Opcode.BNEG ->
    (AST.extract ccr 1<rt> 3 == AST.b1)
  | Opcode.BVC ->
    (AST.extract ccr 1<rt> 1 == AST.b0)
  | Opcode.BVS ->
    (AST.extract ccr 1<rt> 1 == AST.b1)
  | _ ->
    raise InvalidOpcodeException

let branchicc ins insLen bld =
  lift bld ins insLen {
    let oprSize = 64<rt>
    let struct (an, label) = transTwoOprs ins insLen bld
    let pc = regVar bld Register.PC
    let ccr = regVar bld Register.CCR
    let branchCond = branchiccCond ins ccr
    let jumpTarget = pc .+ AST.zext 64<rt> label
    branchTo bld an branchCond jumpTarget (pc .+ numI32PC 8)
  }

/// The condition the branchpcc family branches on, which the
/// opcode alone decides.
let private branchpccCond (ins: Instruction) cc bld ccr =
  match ins.Opcode with
  | Opcode.BPA ->
    (AST.b1)
  | Opcode.BPN ->
    (AST.b0)
  | Opcode.BPNE ->
    if (cc = getCCVar bld ConditionCode.Icc) then
      (AST.extract ccr 1<rt> 2 == AST.b0)
    else
      (AST.extract ccr 1<rt> 6 == AST.b0)
  | Opcode.BPE ->
    if (cc = getCCVar bld ConditionCode.Icc) then
      (AST.extract ccr 1<rt> 2 == AST.b1)
    else
      (AST.extract ccr 1<rt> 6 == AST.b1)
  | Opcode.BPG ->
    if (cc = getCCVar bld ConditionCode.Icc) then
      (((AST.extract ccr 1<rt> 2) .| ((AST.extract ccr 1<rt> 1) <+>
        (AST.extract ccr 1<rt> 3))) == AST.b0)
    else
      (((AST.extract ccr 1<rt> 6) .| ((AST.extract ccr 1<rt> 5) <+>
        (AST.extract ccr 1<rt> 7))) == AST.b0)
  | Opcode.BPLE ->
    if (cc = getCCVar bld ConditionCode.Icc) then
      (((AST.extract ccr 1<rt> 2) .| ((AST.extract ccr 1<rt> 1) <+>
        (AST.extract ccr 1<rt> 3))) == AST.b1)
    else
      (((AST.extract ccr 1<rt> 6) .| ((AST.extract ccr 1<rt> 5) <+>
        (AST.extract ccr 1<rt> 7))) == AST.b1)
  | Opcode.BPGE ->
    if (cc = getCCVar bld ConditionCode.Icc) then
      ((AST.extract ccr 1<rt> 1) <+> (AST.extract ccr 1<rt> 3) == AST.b0)
    else
      ((AST.extract ccr 1<rt> 5) <+> (AST.extract ccr 1<rt> 7) == AST.b0)
  | Opcode.BPL ->
    if (cc = getCCVar bld ConditionCode.Icc) then
      ((AST.extract ccr 1<rt> 1) <+> (AST.extract ccr 1<rt> 3) == AST.b1)
    else
      ((AST.extract ccr 1<rt> 5) <+> (AST.extract ccr 1<rt> 7) == AST.b1)
  | Opcode.BPGU ->
    if (cc = getCCVar bld ConditionCode.Icc) then
      ((AST.extract ccr 1<rt> 0) .| (AST.extract ccr 1<rt> 2) == AST.b0)
    else
      ((AST.extract ccr 1<rt> 4) .| (AST.extract ccr 1<rt> 6) == AST.b0)
  | Opcode.BPLEU ->
    if (cc = getCCVar bld ConditionCode.Icc) then
      ((AST.extract ccr 1<rt> 0) .| (AST.extract ccr 1<rt> 2) == AST.b1)
    else
      ((AST.extract ccr 1<rt> 4) .| (AST.extract ccr 1<rt> 6) == AST.b1)
  | Opcode.BPCC ->
    if (cc = getCCVar bld ConditionCode.Icc) then
      (AST.extract ccr 1<rt> 0 == AST.b0)
    else
      (AST.extract ccr 1<rt> 4 == AST.b0)
  | Opcode.BPCS ->
    if (cc = getCCVar bld ConditionCode.Icc) then
      (AST.extract ccr 1<rt> 0 == AST.b1)
    else
      (AST.extract ccr 1<rt> 4 == AST.b1)
  | Opcode.BPPOS ->
    if (cc = getCCVar bld ConditionCode.Icc) then
      (AST.extract ccr 1<rt> 3 == AST.b0)
    else
      (AST.extract ccr 1<rt> 7 == AST.b0)
  | Opcode.BPNEG ->
    if (cc = getCCVar bld ConditionCode.Icc) then
      (AST.extract ccr 1<rt> 3 == AST.b1)
    else
      (AST.extract ccr 1<rt> 7 == AST.b1)
  | Opcode.BPVC ->
    if (cc = getCCVar bld ConditionCode.Icc) then
      (AST.extract ccr 1<rt> 1 == AST.b0)
    else
      (AST.extract ccr 1<rt> 5 == AST.b0)
  | Opcode.BPVS ->
    if (cc = getCCVar bld ConditionCode.Icc) then
      (AST.extract ccr 1<rt> 1 == AST.b1)
    else
      (AST.extract ccr 1<rt> 5 == AST.b1)
  | _ ->
    raise InvalidOpcodeException

let branchpcc ins insLen bld =
  lift bld ins insLen {
    let oprSize = 64<rt>
    let struct (cc, label, an, _) = transFourOprs ins insLen bld
    let pc = regVar bld Register.PC
    let ccr = regVar bld Register.CCR
    let branchCond = branchpccCond ins cc bld ccr
    let jumpTarget = pc .+ AST.zext 64<rt> label
    branchTo bld an branchCond jumpTarget (pc .+ numI32PC 8)
  }

let call ins insLen bld =
  lift bld ins insLen {
    let dst = transOneOpr ins insLen bld
    let o7 = regVar bld Register.O7
    let pc = regVar bld Register.PC
    o7 := pc
    regVar bld Register.NPC := pc .+ dst
    arm bld InterJmpKind.IsCall
  }

let casa ins insLen bld =
  lift bld ins insLen {
    let struct (src, asi, src1, dst) = transFourOprs ins insLen bld
    let old = tmpVar bld 32<rt>
    let lblL0 = label bld "L0"
    let lblEnd = label bld "End"
    (* operands (Rs1, ASI, Rs2, Rd): the address is [Rs1] alone -- the ASI
       only selects the address space. Compare rs2 (src1) against the memory
       word; on a match store rd (dst, the new value); rd always receives the
       old word. *)
    old := AST.loadBE 32<rt> src
    let cond = ((AST.extract src1 32<rt> 0) == old)
    AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd)
    AST.lmark lblL0
    AST.loadBE 32<rt> src := AST.extract dst 32<rt> 0
    AST.lmark lblEnd
    dst := AST.zext 64<rt> old
  }

let casxa ins insLen bld =
  lift bld ins insLen {
    let struct (src, asi, src1, dst) = transFourOprs ins insLen bld
    let old = tmpVar bld 64<rt>
    let lblL0 = label bld "L0"
    let lblEnd = label bld "End"
    (* operands (Rs1, ASI, Rs2, Rd): the address is [Rs1] alone -- the ASI
       only selects the address space. Compare rs2 (src1) against the memory
       doubleword; on a match store rd (dst); rd always receives the old
       word. *)
    old := AST.loadBE 64<rt> src
    let cond = (src1 == old)
    AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd)
    AST.lmark lblL0
    AST.loadBE 64<rt> src := dst
    AST.lmark lblEnd
    dst := old
  }

let ``done`` (ins: Instruction) insLen bld =
  lift bld ins insLen {
    (* nPC before PC: %pc is a PCVar, so the interpreter treats its write as a
       control transfer that ends the trace -- writing it last keeps the nPC
       update from being skipped. *)
    regVar bld Register.NPC := regVar bld Register.TNPC .+ numI32PC 4
    regVar bld Register.PC := regVar bld Register.TNPC
  }

let fabss ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let oprSize = 32<rt>
    AST.extract dst 1<rt> 31 := AST.b0
    AST.extract dst 31<rt> 0 := AST.extract src 31<rt> 0
  }

let fabsd ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let oprSize = 64<rt>
    let op = tmpVar bld oprSize
    let res = tmpVar bld oprSize
    getDFloatOp bld src op
    AST.extract res 1<rt> 63 := AST.b0
    AST.extract res 63<rt> 0 := AST.extract op 63<rt> 0
    setDFloatOp bld dst res
  }

let fabsq ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let oprSize = 64<rt>
    let op1 = tmpVar bld oprSize
    let op2 = tmpVar bld oprSize
    let res1 = tmpVar bld oprSize
    let res2 = tmpVar bld oprSize
    getQFloatOp bld src op1 op2
    AST.extract res1 1<rt> 63 := AST.b0
    AST.extract res1 63<rt> 0 := AST.extract op1 63<rt> 0
    AST.extract res2 64<rt> 0 := AST.extract op2 64<rt> 0
    setQFloatOp bld dst res1 res2
  }

let fmovs ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    dst := src
  }

let fmovd ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    movFregD bld src dst
  }

let fmovq ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    movFregQ bld src dst
  }

let fnegs ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let oprSize = 32<rt>
    let sign = ((AST.extract src 1<rt> 31) <+> (AST.b1))
    AST.extract dst 1<rt> 31 := sign
    AST.extract dst 31<rt> 0 := AST.extract src 31<rt> 0
  }

let fnegd ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let oprSize = 64<rt>
    let op = tmpVar bld oprSize
    let res = tmpVar bld oprSize
    getDFloatOp bld src op
    let sign = ((AST.extract op 1<rt> 63) <+> (AST.b1))
    AST.extract res 1<rt> 63 := sign
    AST.extract res 63<rt> 0 := AST.extract op 63<rt> 0
    setDFloatOp bld dst res
  }

let fnegq ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let oprSize = 64<rt>
    let op1 = tmpVar bld oprSize
    let op2 = tmpVar bld oprSize
    let res1 = tmpVar bld oprSize
    let res2 = tmpVar bld oprSize
    getQFloatOp bld src op1 op2
    let sign = ((AST.extract op1 1<rt> 63) <+> (AST.b1))
    AST.extract res1 1<rt> 63 := sign
    AST.extract res1 63<rt> 0 := AST.extract op1 63<rt> 0
    AST.extract res2 64<rt> 0 := AST.extract op2 64<rt> 0
    setQFloatOp bld dst res1 res2
  }

let fadds ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let fsr = regVar bld Register.FSR
    let fsr30 = AST.extract fsr 1<rt> 30
    let fsr31 = AST.extract fsr 1<rt> 31
    let regSize = 32<rt>
    let res = tmpVar bld regSize
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblL4 = label bld "L4"
    let lblL5 = label bld "L5"
    let lblEnd = label bld "End"
    let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
    let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
    let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
    res := (AST.fadd src src1)
    AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    dst := AST.cast CastKind.FtoFRound regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    dst := AST.cast CastKind.FtoFTrunc regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5)
    AST.lmark lblL4
    dst := AST.cast CastKind.FtoFCeil regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL5
    dst := AST.cast CastKind.FtoFFloor regSize (res)
    AST.lmark lblEnd
  }

let faddd ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let fsr = regVar bld Register.FSR
    let fsr30 = AST.extract fsr 1<rt> 30
    let fsr31 = AST.extract fsr 1<rt> 31
    let regSize = 64<rt>
    let res = tmpVar bld regSize
    let op = tmpVar bld regSize
    let op1 = tmpVar bld regSize
    let rounded = tmpVar bld regSize
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblL4 = label bld "L4"
    let lblL5 = label bld "L5"
    let lblEnd = label bld "End"
    let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
    let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
    let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
    getDFloatOp bld src op
    getDFloatOp bld src1 op1
    res := (AST.fadd op op1)
    AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rounded := AST.cast CastKind.FtoFRound regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    rounded := AST.cast CastKind.FtoFTrunc regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5)
    AST.lmark lblL4
    rounded := AST.cast CastKind.FtoFCeil regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL5
    rounded := AST.cast CastKind.FtoFFloor regSize (res)
    AST.lmark lblEnd
    setDFloatOp bld dst rounded
  }

/// Adds two quad-precision operands.
let faddq ins insLen bld =
  liftQFloatBinOp ins insLen bld AST.fadd

let fbranchfcc ins insLen bld =
  lift bld ins insLen {
    let struct (an, label) = transTwoOprs ins insLen bld
    let pc = regVar bld Register.PC
    let fsr = regVar bld Register.FSR
    let u = ((AST.extract fsr 2<rt> 10) == (numI32 3 2<rt>))
    let g = ((AST.extract fsr 2<rt> 10) == (numI32 2 2<rt>))
    let l = ((AST.extract fsr 2<rt> 10) == (numI32 1 2<rt>))
    let e = ((AST.extract fsr 2<rt> 10) == (numI32 0 2<rt>))
    let branchCond =
      match ins.Opcode with
      | Opcode.FBA -> AST.b1
      | Opcode.FBN -> AST.b0
      | Opcode.FBU -> u
      | Opcode.FBG -> g
      | Opcode.FBUG -> (u .| g)
      | Opcode.FBL -> l
      | Opcode.FBUL -> (u .| l)
      | Opcode.FBLG -> (l .| g)
      | Opcode.FBNE -> (l .| g .| u)
      | Opcode.FBE -> e
      | Opcode.FBUE -> (e .| u)
      | Opcode.FBGE -> (g .| e)
      | Opcode.FBUGE -> (u .| g .| e)
      | Opcode.FBLE -> (l .| e)
      | Opcode.FBULE -> (u .| l .| e)
      | Opcode.FBO -> (l .| e .| g)
      | _ -> raise InvalidOpcodeException
    let jumpTarget = pc .+ AST.zext 64<rt> label
    branchTo bld an branchCond jumpTarget (pc .+ numI32PC 8)
  }

let fbranchpfcc ins insLen bld =
  lift bld ins insLen {
    let struct (cc, label, an, _) = transFourOprs ins insLen bld
    let pc = regVar bld Register.PC
    let fsr = regVar bld Register.FSR
    let fcc0 = getCCVar bld ConditionCode.Fcc0
    let fcc1 = getCCVar bld ConditionCode.Fcc1
    let fcc2 = getCCVar bld ConditionCode.Fcc2
    let fcc3 = getCCVar bld ConditionCode.Fcc3
    let pos =
      if (cc = fcc0) then 10
      elif (cc = fcc1) then 32
      elif (cc = fcc2) then 34
      elif (cc = fcc3) then 36
      else raise InvalidOperandException
    let u = ((AST.extract fsr 2<rt> pos) == (numI32 3 2<rt>))
    let g = ((AST.extract fsr 2<rt> pos) == (numI32 2 2<rt>))
    let l = ((AST.extract fsr 2<rt> pos) == (numI32 1 2<rt>))
    let e = ((AST.extract fsr 2<rt> pos) == (numI32 0 2<rt>))
    let branchCond =
      match ins.Opcode with
      | Opcode.FBPA -> AST.b1
      | Opcode.FBPN -> AST.b0
      | Opcode.FBPU -> u
      | Opcode.FBPG -> g
      | Opcode.FBPUG -> (u .| g)
      | Opcode.FBPL -> l
      | Opcode.FBPUL -> (u .| l)
      | Opcode.FBPLG -> (l .| g)
      | Opcode.FBPNE -> (l .| g .| u)
      | Opcode.FBPE -> e
      | Opcode.FBPUE -> (e .| u)
      | Opcode.FBPGE -> (g .| e)
      | Opcode.FBPUGE -> (u .| g .| e)
      | Opcode.FBPLE -> (l .| e)
      | Opcode.FBPULE -> (u .| l .| e)
      | Opcode.FBPO -> (l .| e .| g)
      | _ -> raise InvalidOpcodeException
    let jumpTarget = pc .+ AST.zext 64<rt> label
    branchTo bld an branchCond jumpTarget (pc .+ numI32PC 8)
  }

/// Compares two single-precision operands.
let fcmps ins insLen bld =
  lift bld ins insLen {
    let struct (cc, src, src1) = transThreeOprs ins insLen bld
    let pos = fccPosition bld cc
    let op = AST.extract src 32<rt> 0
    let op1 = AST.extract src1 32<rt> 0
    compareFloatsInto bld pos op op1
  }

/// Compares two double-precision operands.
let fcmpd ins insLen bld =
  lift bld ins insLen {
    let struct (cc, src, src1) = transThreeOprs ins insLen bld
    let regSize = 64<rt>
    let pos = fccPosition bld cc
    let op = tmpVar bld regSize
    let op1 = tmpVar bld regSize
    getDFloatOp bld src op
    getDFloatOp bld src1 op1
    compareFloatsInto bld pos op op1
  }

/// Compares two quad-precision operands, narrowed to 64-bit first.
let fcmpq ins insLen bld =
  lift bld ins insLen {
    let struct (cc, src, src1) = transThreeOprs ins insLen bld
    let regSize = 64<rt>
    let pos = fccPosition bld cc
    let op01 = tmpVar bld regSize
    let op02 = tmpVar bld regSize
    let op11 = tmpVar bld regSize
    let op12 = tmpVar bld regSize
    let op64 = tmpVar bld regSize
    let op164 = tmpVar bld regSize
    getQFloatOp bld src op01 op02
    getQFloatOp bld src1 op11 op12
    cast128to64 bld op01 op02 op64
    cast128to64 bld op11 op12 op164
    compareFloatsInto bld pos op64 op164
  }

let fdivs ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let fsr = regVar bld Register.FSR
    let fsr30 = AST.extract fsr 1<rt> 30
    let fsr31 = AST.extract fsr 1<rt> 31
    let regSize = 32<rt>
    let res = tmpVar bld regSize
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblL4 = label bld "L4"
    let lblL5 = label bld "L5"
    let lblEnd = label bld "End"
    let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
    let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
    let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
    res := (AST.fdiv src src1)
    AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    dst := AST.cast CastKind.FtoFRound regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    dst := AST.cast CastKind.FtoFTrunc regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5)
    AST.lmark lblL4
    dst := AST.cast CastKind.FtoFCeil regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL5
    dst := AST.cast CastKind.FtoFFloor regSize (res)
    AST.lmark lblEnd
  }

let fdivd ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let fsr = regVar bld Register.FSR
    let fsr30 = AST.extract fsr 1<rt> 30
    let fsr31 = AST.extract fsr 1<rt> 31
    let regSize = 64<rt>
    let res = tmpVar bld regSize
    let op = tmpVar bld regSize
    let op1 = tmpVar bld regSize
    let rounded = tmpVar bld regSize
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblL4 = label bld "L4"
    let lblL5 = label bld "L5"
    let lblEnd = label bld "End"
    let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
    let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
    let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
    getDFloatOp bld src op
    getDFloatOp bld src1 op1
    res := (AST.fdiv op op1)
    AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rounded := AST.cast CastKind.FtoFRound regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    rounded := AST.cast CastKind.FtoFTrunc regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5)
    AST.lmark lblL4
    rounded := AST.cast CastKind.FtoFCeil regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL5
    rounded := AST.cast CastKind.FtoFFloor regSize (res)
    AST.lmark lblEnd
    setDFloatOp bld dst rounded
  }

/// Divides one quad-precision operand by another.
let fdivq ins insLen bld =
  liftQFloatBinOp ins insLen bld AST.fdiv

let fmovscc ins insLen bld =
  let struct (cc, fsrc, fdst) = transThreeOprs ins insLen bld
  let ccr = regVar bld Register.CCR
  let offset = if (cc = getCCVar bld ConditionCode.Icc) then 0 else 4
  let n = AST.extract ccr 1<rt> (3 + offset)
  let z = AST.extract ccr 1<rt> (2 + offset)
  let v = AST.extract ccr 1<rt> (1 + offset)
  let c = AST.extract ccr 1<rt> (offset)
  let cond =
    match ins.Opcode with
    | Opcode.FMOVsA -> AST.b1
    | Opcode.FMOVsN -> AST.b0
    | Opcode.FMOVsNE -> (z == AST.b0)
    | Opcode.FMOVsE -> (z == AST.b1)
    | Opcode.FMOVsG -> ((z .| (n <+> v)) == AST.b0)
    | Opcode.FMOVsLE -> ((z .| (n <+> v)) == AST.b1)
    | Opcode.FMOVsGE -> ((n <+> v) == AST.b0)
    | Opcode.FMOVsL -> ((n <+> v) == AST.b1)
    | Opcode.FMOVsGU -> ((c .| z) == AST.b0)
    | Opcode.FMOVsLEU -> ((c .| z) == AST.b1)
    | Opcode.FMOVsCC -> (c == AST.b0)
    | Opcode.FMOVsCS -> (c == AST.b1)
    | Opcode.FMOVsPOS -> (n == AST.b0)
    | Opcode.FMOVsNEG -> (n == AST.b1)
    | Opcode.FMOVsVC -> (v == AST.b0)
    | Opcode.FMOVsVS -> (v == AST.b1)
    | _ -> raise InvalidOpcodeException
  lift bld ins insLen {
    if (ins.Opcode = Opcode.FMOVsA) then
      fdst := fsrc
    elif (ins.Opcode = Opcode.FMOVsN) then
      ()
    else
      fdst := AST.ite (cond) (fsrc) (fdst)
  }

let fmovdcc ins insLen bld =
  let struct (cc, fsrc, fdst) = transThreeOprs ins insLen bld
  let ccr = regVar bld Register.CCR
  let offset = if (cc = getCCVar bld ConditionCode.Icc) then 0 else 4
  let n = AST.extract ccr 1<rt> (3 + offset)
  let z = AST.extract ccr 1<rt> (2 + offset)
  let v = AST.extract ccr 1<rt> (1 + offset)
  let c = AST.extract ccr 1<rt> (offset)
  let cond =
    match ins.Opcode with
    | Opcode.FMOVdA -> AST.b1
    | Opcode.FMOVdN -> AST.b0
    | Opcode.FMOVdNE -> (z == AST.b0)
    | Opcode.FMOVdE -> (z == AST.b1)
    | Opcode.FMOVdG -> ((z .| (n <+> v)) == AST.b0)
    | Opcode.FMOVdLE -> ((z .| (n <+> v)) == AST.b1)
    | Opcode.FMOVdGE -> ((n <+> v) == AST.b0)
    | Opcode.FMOVdL -> ((n <+> v) == AST.b1)
    | Opcode.FMOVdGU -> ((c .| z) == AST.b0)
    | Opcode.FMOVdLEU -> ((c .| z) == AST.b1)
    | Opcode.FMOVdCC -> (c == AST.b0)
    | Opcode.FMOVdCS -> (c == AST.b1)
    | Opcode.FMOVdPOS -> (n == AST.b0)
    | Opcode.FMOVdNEG -> (n == AST.b1)
    | Opcode.FMOVdVC -> (v == AST.b0)
    | Opcode.FMOVdVS -> (v == AST.b1)
    | _ -> raise InvalidOpcodeException
  let lblL0 = label bld "L0"
  let lblEnd = label bld "End"
  lift bld ins insLen {
    if (ins.Opcode = Opcode.FMOVdA) then
      movFregD bld fsrc fdst
    elif (ins.Opcode = Opcode.FMOVdN) then
      ()
    else
      AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd)
      AST.lmark lblL0
      movFregD bld fsrc fdst
      AST.lmark lblEnd
  }

let fmovqcc ins insLen bld =
  let struct (cc, fsrc, fdst) = transThreeOprs ins insLen bld
  let ccr = regVar bld Register.CCR
  let offset = if (cc = getCCVar bld ConditionCode.Icc) then 0 else 4
  let n = AST.extract ccr 1<rt> (3 + offset)
  let z = AST.extract ccr 1<rt> (2 + offset)
  let v = AST.extract ccr 1<rt> (1 + offset)
  let c = AST.extract ccr 1<rt> (offset)
  let cond =
    match ins.Opcode with
    | Opcode.FMOVqA -> AST.b1
    | Opcode.FMOVqN -> AST.b0
    | Opcode.FMOVqNE -> (z == AST.b0)
    | Opcode.FMOVqE -> (z == AST.b1)
    | Opcode.FMOVqG -> ((z .| (n <+> v)) == AST.b0)
    | Opcode.FMOVqLE -> ((z .| (n <+> v)) == AST.b1)
    | Opcode.FMOVqGE -> ((n <+> v) == AST.b0)
    | Opcode.FMOVqL -> ((n <+> v) == AST.b1)
    | Opcode.FMOVqGU -> ((c .| z) == AST.b0)
    | Opcode.FMOVqLEU -> ((c .| z) == AST.b1)
    | Opcode.FMOVqCC -> (c == AST.b0)
    | Opcode.FMOVqCS -> (c == AST.b1)
    | Opcode.FMOVqPOS -> (n == AST.b0)
    | Opcode.FMOVqNEG -> (n == AST.b1)
    | Opcode.FMOVqVC -> (v == AST.b0)
    | Opcode.FMOVqVS -> (v == AST.b1)
    | _ -> raise InvalidOpcodeException
  let lblL0 = label bld "L0"
  let lblEnd = label bld "End"
  lift bld ins insLen {
    if (ins.Opcode = Opcode.FMOVqA) then
      movFregQ bld fsrc fdst
    elif (ins.Opcode = Opcode.FMOVqN) then
      ()
    else
      AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd)
      AST.lmark lblL0
      movFregQ bld fsrc fdst
      AST.lmark lblEnd
  }

let fmovfscc ins insLen bld =
  let struct (cc, fsrc, fdst) = transThreeOprs ins insLen bld
  let fsr = regVar bld Register.FSR
  let pos =
    if (cc = getCCVar bld ConditionCode.Fcc0) then 10
    elif (cc = getCCVar bld ConditionCode.Fcc1) then 32
    elif (cc = getCCVar bld ConditionCode.Fcc2) then 34
    elif (cc = getCCVar bld ConditionCode.Fcc3) then 36
    else raise InvalidRegisterException
  let fsr0 = AST.extract fsr 1<rt> pos
  let fsr1 = AST.extract fsr 1<rt> (pos + 1)
  let e = (fsr1 == AST.b0 .& fsr0 == AST.b0)
  let l = (fsr1 == AST.b0 .& fsr0 == AST.b1)
  let g = (fsr1 == AST.b1 .& fsr0 == AST.b0)
  let u = (fsr1 == AST.b1 .& fsr0 == AST.b1)
  let cond =
    match ins.Opcode with
    | Opcode.FMOVFsA -> AST.b1
    | Opcode.FMOVFsN -> AST.b0
    | Opcode.FMOVFsU -> u
    | Opcode.FMOVFsG -> g
    | Opcode.FMOVFsUG -> (g .| u)
    | Opcode.FMOVFsL -> l
    | Opcode.FMOVFsUL -> (u .| l)
    | Opcode.FMOVFsLG -> (l .| g)
    | Opcode.FMOVFsNE -> (l .| g .| u)
    | Opcode.FMOVFsE -> e
    | Opcode.FMOVFsUE -> (u .| e)
    | Opcode.FMOVFsGE -> (g .| e)
    | Opcode.FMOVFsUGE -> (u .| g .| e)
    | Opcode.FMOVFsLE -> (l .| e)
    | Opcode.FMOVFsULE -> (u .| l .| e)
    | Opcode.FMOVFsO -> (e .| l .| g)
    | _ -> raise InvalidOpcodeException
  lift bld ins insLen {
    if (ins.Opcode = Opcode.FMOVFsA) then
      fdst := fsrc
    elif (ins.Opcode = Opcode.FMOVFsN) then
      ()
    else
      fdst := AST.ite (cond) (fsrc) (fdst)
  }

/// Moves a double-precision float register when the FSR condition the opcode
/// names holds.
let fmovfdcc ins insLen bld =
  let struct (cc, fsrc, fdst) = transThreeOprs ins insLen bld
  let pos = fccMovePosition bld cc
  let struct (e, l, g, u) = fccFlags bld pos
  let cond =
    match ins.Opcode with
    | Opcode.FMOVFdA -> AST.b1
    | Opcode.FMOVFdN -> AST.b0
    | Opcode.FMOVFdU -> u
    | Opcode.FMOVFdG -> g
    | Opcode.FMOVFdUG -> (g .| u)
    | Opcode.FMOVFdL -> l
    | Opcode.FMOVFdUL -> (u .| l)
    | Opcode.FMOVFdLG -> (l .| g)
    | Opcode.FMOVFdNE -> (l .| g .| u)
    | Opcode.FMOVFdE -> e
    | Opcode.FMOVFdUE -> (u .| e)
    | Opcode.FMOVFdGE -> (g .| e)
    | Opcode.FMOVFdUGE -> (u .| g .| e)
    | Opcode.FMOVFdLE -> (l .| e)
    | Opcode.FMOVFdULE -> (u .| l .| e)
    | Opcode.FMOVFdO -> (e .| l .| g)
    | _ -> raise InvalidOpcodeException
  let lblL0 = label bld "L0"
  let lblEnd = label bld "End"
  lift bld ins insLen {
    if (ins.Opcode = Opcode.FMOVFdA) then
      movFregD bld fsrc fdst
    elif (ins.Opcode = Opcode.FMOVFdN) then
      ()
    else
      AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd)
      AST.lmark lblL0
      movFregD bld fsrc fdst
      AST.lmark lblEnd
  }

/// Moves a quad-precision float register when the FSR condition the opcode
/// names holds.
let fmovfqcc ins insLen bld =
  let struct (cc, fsrc, fdst) = transThreeOprs ins insLen bld
  let pos = fccMovePosition bld cc
  let struct (e, l, g, u) = fccFlags bld pos
  let cond =
    match ins.Opcode with
    | Opcode.FMOVFqA -> AST.b1
    | Opcode.FMOVFqN -> AST.b0
    | Opcode.FMOVFqU -> u
    | Opcode.FMOVFqG -> g
    | Opcode.FMOVFqUG -> (g .| u)
    | Opcode.FMOVFqL -> l
    | Opcode.FMOVFqUL -> (u .| l)
    | Opcode.FMOVFqLG -> (l .| g)
    | Opcode.FMOVFqNE -> (l .| g .| u)
    | Opcode.FMOVFqE -> e
    | Opcode.FMOVFqUE -> (u .| e)
    | Opcode.FMOVFqGE -> (g .| e)
    | Opcode.FMOVFqUGE -> (u .| g .| e)
    | Opcode.FMOVFqLE -> (l .| e)
    | Opcode.FMOVFqULE -> (u .| l .| e)
    | Opcode.FMOVFqO -> (e .| l .| g)
    | _ -> raise InvalidOpcodeException
  let lblL0 = label bld "L0"
  let lblEnd = label bld "End"
  lift bld ins insLen {
    if (ins.Opcode = Opcode.FMOVFqA) then
      movFregQ bld fsrc fdst
    elif (ins.Opcode = Opcode.FMOVFqN) then
      ()
    else
      AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd)
      AST.lmark lblL0
      movFregQ bld fsrc fdst
      AST.lmark lblEnd
  }

let fmovrs ins insLen bld =
  lift bld ins insLen {
    let struct (src, fsrc, fdst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    match ins.Opcode with
    | Opcode.FMOVRsZ ->
      fdst := AST.ite (src == AST.num0 oprSize) (fsrc) (fdst)
    | Opcode.FMOVRsLEZ ->
      fdst := AST.ite (src ?<= AST.num0 oprSize) (fsrc) (fdst)
    | Opcode.FMOVRsLZ ->
      fdst := AST.ite (src ?< AST.num0 oprSize) (fsrc) (fdst)
    | Opcode.FMOVRsNZ ->
      fdst := AST.ite (src != AST.num0 oprSize) (fsrc) (fdst)
    | Opcode.FMOVRsGZ ->
      fdst := AST.ite (src ?> AST.num0 oprSize) (fsrc) (fdst)
    | Opcode.FMOVRsGEZ ->
      fdst := AST.ite (src ?>= AST.num0 oprSize) (fsrc) (fdst)
    | _ ->
      raise InvalidOpcodeException
  }

let fmovrd ins insLen bld =
  lift bld ins insLen {
    let struct (src, fsrc, fdst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    let cond =
      match ins.Opcode with
      | Opcode.FMOVRdZ -> src == AST.num0 oprSize
      | Opcode.FMOVRdLEZ -> src ?<= AST.num0 oprSize
      | Opcode.FMOVRdLZ -> src ?< AST.num0 oprSize
      | Opcode.FMOVRdNZ -> src != AST.num0 oprSize
      | Opcode.FMOVRdGZ -> src ?> AST.num0 oprSize
      | Opcode.FMOVRdGEZ -> src ?>= AST.num0 oprSize
      | _ -> raise InvalidOpcodeException
    let lblL0 = label bld "L0"
    let lblEnd = label bld "End"
    AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd)
    AST.lmark lblL0
    movFregD bld fsrc fdst
    AST.lmark lblEnd
  }

let fmovrq ins insLen bld =
  lift bld ins insLen {
    let struct (src, fsrc, fdst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    let cond =
      match ins.Opcode with
      | Opcode.FMOVRqZ -> src == AST.num0 oprSize
      | Opcode.FMOVRqLEZ -> src ?<= AST.num0 oprSize
      | Opcode.FMOVRqLZ -> src ?< AST.num0 oprSize
      | Opcode.FMOVRqNZ -> src != AST.num0 oprSize
      | Opcode.FMOVRqGZ -> src ?> AST.num0 oprSize
      | Opcode.FMOVRqGEZ -> src ?>= AST.num0 oprSize
      | _ -> raise InvalidOpcodeException
    let lblL0 = label bld "L0"
    let lblEnd = label bld "End"
    AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd)
    AST.lmark lblL0
    movFregQ bld fsrc fdst
    AST.lmark lblEnd
  }

let fmuls ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let fsr = regVar bld Register.FSR
    let fsr30 = AST.extract fsr 1<rt> 30
    let fsr31 = AST.extract fsr 1<rt> 31
    let regSize = 32<rt>
    let res = tmpVar bld regSize
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblL4 = label bld "L4"
    let lblL5 = label bld "L5"
    let lblEnd = label bld "End"
    let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
    let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
    let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
    res := (AST.fmul src src1)
    AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    dst := AST.cast CastKind.FtoFRound regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    dst := AST.cast CastKind.FtoFTrunc regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5)
    AST.lmark lblL4
    dst := AST.cast CastKind.FtoFCeil regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL5
    dst := AST.cast CastKind.FtoFFloor regSize (res)
    AST.lmark lblEnd
  }

let fmuld ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let fsr = regVar bld Register.FSR
    let fsr30 = AST.extract fsr 1<rt> 30
    let fsr31 = AST.extract fsr 1<rt> 31
    let regSize = 64<rt>
    let res = tmpVar bld regSize
    let op = tmpVar bld regSize
    let op1 = tmpVar bld regSize
    let rounded = tmpVar bld regSize
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblL4 = label bld "L4"
    let lblL5 = label bld "L5"
    let lblEnd = label bld "End"
    let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
    let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
    let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
    getDFloatOp bld src op
    getDFloatOp bld src1 op1
    res := (AST.fmul op op1)
    AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rounded := AST.cast CastKind.FtoFRound regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    rounded := AST.cast CastKind.FtoFTrunc regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5)
    AST.lmark lblL4
    rounded := AST.cast CastKind.FtoFCeil regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL5
    rounded := AST.cast CastKind.FtoFFloor regSize (res)
    AST.lmark lblEnd
    setDFloatOp bld dst rounded
  }

/// Multiplies two quad-precision operands.
let fmulq ins insLen bld =
  liftQFloatBinOp ins insLen bld AST.fmul

let fsmuld ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let fsr = regVar bld Register.FSR
    let fsr30 = AST.extract fsr 1<rt> 30
    let fsr31 = AST.extract fsr 1<rt> 31
    let regSize = 64<rt>
    let res = tmpVar bld regSize
    let rounded = tmpVar bld regSize
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblL4 = label bld "L4"
    let lblL5 = label bld "L5"
    let lblEnd = label bld "End"
    let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
    let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
    let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
    let op1 = AST.cast CastKind.FloatCast 64<rt> src
    let op2 = AST.cast CastKind.FloatCast 64<rt> src1
    res := (AST.fmul op1 op2)
    AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rounded := AST.cast CastKind.FtoFRound regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    rounded := AST.cast CastKind.FtoFTrunc regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5)
    AST.lmark lblL4
    rounded := AST.cast CastKind.FtoFCeil regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL5
    rounded := AST.cast CastKind.FtoFFloor regSize (res)
    AST.lmark lblEnd
    setDFloatOp bld dst rounded
  }

/// Multiplies two double-precision operands into a quad-precision result.
let fdmulq ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let regSize = 64<rt>
    let res = tmpVar bld regSize
    let res1 = tmpVar bld regSize
    let res2 = tmpVar bld regSize
    let op = tmpVar bld regSize
    let op1 = tmpVar bld regSize
    let rounded = tmpVar bld regSize
    getDFloatOp bld src op
    getDFloatOp bld src1 op1
    res := AST.fmul op op1
    roundByFSR bld res rounded regSize
    cast64To128 bld rounded res1 res2
    setQFloatOp bld dst res1 res2
  }

let fsqrts ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let fsr = regVar bld Register.FSR
    let fsr30 = AST.extract fsr 1<rt> 30
    let fsr31 = AST.extract fsr 1<rt> 31
    let regSize = 32<rt>
    let res = tmpVar bld regSize
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblL4 = label bld "L4"
    let lblL5 = label bld "L5"
    let lblEnd = label bld "End"
    let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
    let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
    let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
    res := (AST.fsqrt src)
    AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    dst := AST.cast CastKind.FtoFRound regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    dst := AST.cast CastKind.FtoFTrunc regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5)
    AST.lmark lblL4
    dst := AST.cast CastKind.FtoFCeil regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL5
    dst := AST.cast CastKind.FtoFFloor regSize (res)
    AST.lmark lblEnd
  }

let fsqrtd ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let fsr = regVar bld Register.FSR
    let fsr30 = AST.extract fsr 1<rt> 30
    let fsr31 = AST.extract fsr 1<rt> 31
    let regSize = 64<rt>
    let res = tmpVar bld regSize
    let op = tmpVar bld regSize
    let rounded = tmpVar bld regSize
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblL4 = label bld "L4"
    let lblL5 = label bld "L5"
    let lblEnd = label bld "End"
    let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
    let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
    let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
    getDFloatOp bld src op
    res := (AST.fsqrt op)
    AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rounded := AST.cast CastKind.FtoFRound regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    rounded := AST.cast CastKind.FtoFTrunc regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5)
    AST.lmark lblL4
    rounded := AST.cast CastKind.FtoFCeil regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL5
    rounded := AST.cast CastKind.FtoFFloor regSize (res)
    AST.lmark lblEnd
    setDFloatOp bld dst rounded
  }

/// Takes the square root of a quad-precision operand. The one operand aside,
/// this is what `liftQFloatBinOp` does.
let fsqrtq ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let regSize = 64<rt>
    let res1 = tmpVar bld regSize
    let res2 = tmpVar bld regSize
    let op01 = tmpVar bld regSize
    let op02 = tmpVar bld regSize
    let op64 = tmpVar bld 64<rt>
    let res64 = tmpVar bld 64<rt>
    let rounded = tmpVar bld regSize
    getQFloatOp bld src op01 op02
    cast128to64 bld op01 op02 op64
    res64 := AST.fsqrt op64
    roundByFSR bld res64 rounded regSize
    cast64To128 bld rounded res1 res2
    setQFloatOp bld dst res1 res2
  }

let fstox ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let oprSize = 64<rt>
    let cst = tmpVar bld oprSize
    cst := AST.cast CastKind.FtoITrunc oprSize src
    setDFloatOp bld dst cst
  }

let fdtox ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let oprSize = 64<rt>
    let op = tmpVar bld oprSize
    let cst = tmpVar bld oprSize
    getDFloatOp bld src op
    cst := AST.cast CastKind.FtoITrunc oprSize op
    setDFloatOp bld dst cst
  }

let fqtox ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let oprSize = 64<rt>
    let regSize = 64<rt>
    let op1 = tmpVar bld regSize
    let op2 = tmpVar bld regSize
    let op64 = tmpVar bld regSize
    let cst = tmpVar bld oprSize
    getQFloatOp bld src op1 op2
    cast128to64 bld op1 op2 op64
    cst := AST.cast CastKind.FtoITrunc oprSize op64
    setDFloatOp bld dst cst
  }

let fstoi ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let oprSize = 32<rt>
    let cst = tmpVar bld oprSize
    dst := AST.cast CastKind.FtoITrunc oprSize src
  }

let fdtoi ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let oprSize = 64<rt>
    let regSize = 32<rt>
    let op = tmpVar bld oprSize
    let cst = tmpVar bld regSize
    getDFloatOp bld src op
    dst := AST.cast CastKind.FtoITrunc regSize op
  }

let fqtoi ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let oprSize = 32<rt>
    let regSize = 64<rt>
    let op1 = tmpVar bld regSize
    let op2 = tmpVar bld regSize
    let op64 = tmpVar bld regSize
    let cst = tmpVar bld oprSize
    getQFloatOp bld src op1 op2
    cast128to64 bld op1 op2 op64
    dst := AST.cast CastKind.FtoITrunc oprSize op64
  }

let fstod ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let oprSize = 64<rt>
    let fsr = regVar bld Register.FSR
    let fsr30 = AST.extract fsr 1<rt> 30
    let fsr31 = AST.extract fsr 1<rt> 31
    let res = tmpVar bld oprSize
    let rounded = tmpVar bld oprSize
    let regSize = 64<rt>
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblL4 = label bld "L4"
    let lblL5 = label bld "L5"
    let lblEnd = label bld "End"
    let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
    let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
    let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
    res := AST.cast CastKind.FloatCast oprSize src
    AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rounded := AST.cast CastKind.FtoFRound regSize res
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    rounded := AST.cast CastKind.FtoFTrunc regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5)
    AST.lmark lblL4
    rounded := AST.cast CastKind.FtoFCeil regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL5
    rounded := AST.cast CastKind.FtoFFloor regSize (res)
    AST.lmark lblEnd
    setDFloatOp bld dst rounded
  }

let fstoq ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let oprSize = 64<rt>
    let fsr = regVar bld Register.FSR
    let fsr30 = AST.extract fsr 1<rt> 30
    let fsr31 = AST.extract fsr 1<rt> 31
    let res1 = tmpVar bld oprSize
    let res2 = tmpVar bld oprSize
    let res64 = tmpVar bld oprSize
    let rounded = tmpVar bld oprSize
    let regSize = 64<rt>
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblL4 = label bld "L4"
    let lblL5 = label bld "L5"
    let lblEnd = label bld "End"
    let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
    let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
    let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
    res64 := AST.cast CastKind.FloatCast oprSize src
    AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rounded := AST.cast CastKind.FtoFRound regSize (res64)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    rounded := AST.cast CastKind.FtoFTrunc regSize (res64)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5)
    AST.lmark lblL4
    rounded := AST.cast CastKind.FtoFCeil regSize (res64)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL5
    rounded := AST.cast CastKind.FtoFFloor regSize (res64)
    AST.lmark lblEnd
    cast64To128 bld rounded res1 res2
    setQFloatOp bld dst res1 res2
  }

let fdtos ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let fsr = regVar bld Register.FSR
    let fsr30 = AST.extract fsr 1<rt> 30
    let fsr31 = AST.extract fsr 1<rt> 31
    let regSize = 32<rt>
    let op = tmpVar bld 64<rt>
    let res = tmpVar bld regSize
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblL4 = label bld "L4"
    let lblL5 = label bld "L5"
    let lblEnd = label bld "End"
    let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
    let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
    let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
    getDFloatOp bld src op
    res := AST.cast CastKind.FloatCast regSize op
    AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    dst := AST.cast CastKind.FtoFRound regSize res
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    dst := AST.cast CastKind.FtoFTrunc regSize res
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5)
    AST.lmark lblL4
    dst := AST.cast CastKind.FtoFCeil regSize res
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL5
    dst := AST.cast CastKind.FtoFFloor regSize res
    AST.lmark lblEnd
  }

let fdtoq ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let oprSize = 64<rt>
    let op = tmpVar bld oprSize
    let res1 = tmpVar bld oprSize
    let res2 = tmpVar bld oprSize
    getDFloatOp bld src op
    cast64To128 bld op res1 res2
    setQFloatOp bld dst res1 res2
  }

let fqtos ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let fsr = regVar bld Register.FSR
    let fsr30 = AST.extract fsr 1<rt> 30
    let fsr31 = AST.extract fsr 1<rt> 31
    let regSize = 32<rt>
    let op1 = tmpVar bld 64<rt>
    let op2 = tmpVar bld 64<rt>
    let op64 = tmpVar bld 64<rt>
    let res = tmpVar bld regSize
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblL4 = label bld "L4"
    let lblL5 = label bld "L5"
    let lblEnd = label bld "End"
    let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
    let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
    let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
    getQFloatOp bld src op1 op2
    cast128to64 bld op1 op2 op64
    res := AST.cast CastKind.FloatCast regSize op64
    AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    dst := AST.cast CastKind.FtoFRound regSize res
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    dst := AST.cast CastKind.FtoFTrunc regSize res
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5)
    AST.lmark lblL4
    dst := AST.cast CastKind.FtoFCeil regSize res
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL5
    dst := AST.cast CastKind.FtoFFloor regSize res
    AST.lmark lblEnd
  }

let fqtod ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let regSize = 64<rt>
    let op1 = tmpVar bld regSize
    let op2 = tmpVar bld regSize
    let op64 = tmpVar bld regSize
    getQFloatOp bld src op1 op2
    cast128to64 bld op1 op2 op64
    setDFloatOp bld dst op64
  }

let fsubs ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let fsr = regVar bld Register.FSR
    let fsr30 = AST.extract fsr 1<rt> 30
    let fsr31 = AST.extract fsr 1<rt> 31
    let regSize = 32<rt>
    let res = tmpVar bld regSize
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblL4 = label bld "L4"
    let lblL5 = label bld "L5"
    let lblEnd = label bld "End"
    let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
    let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
    let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
    res := (AST.fsub src src1)
    AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    dst := AST.cast CastKind.FtoFRound regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    dst := AST.cast CastKind.FtoFTrunc regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5)
    AST.lmark lblL4
    dst := AST.cast CastKind.FtoFCeil regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL5
    dst := AST.cast CastKind.FtoFFloor regSize (res)
    AST.lmark lblEnd
  }

let fsubd ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let fsr = regVar bld Register.FSR
    let fsr30 = AST.extract fsr 1<rt> 30
    let fsr31 = AST.extract fsr 1<rt> 31
    let regSize = 64<rt>
    let res = tmpVar bld regSize
    let op = tmpVar bld regSize
    let op1 = tmpVar bld regSize
    let rounded = tmpVar bld regSize
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblL4 = label bld "L4"
    let lblL5 = label bld "L5"
    let lblEnd = label bld "End"
    let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
    let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
    let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
    getDFloatOp bld src op
    getDFloatOp bld src1 op1
    res := (AST.fsub op op1)
    AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rounded := AST.cast CastKind.FtoFRound regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    rounded := AST.cast CastKind.FtoFTrunc regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5)
    AST.lmark lblL4
    rounded := AST.cast CastKind.FtoFCeil regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL5
    rounded := AST.cast CastKind.FtoFFloor regSize (res)
    AST.lmark lblEnd
    setDFloatOp bld dst rounded
  }

/// Subtracts one quad-precision operand from another.
let fsubq ins insLen bld =
  liftQFloatBinOp ins insLen bld AST.fsub

let fxtos ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let oprSize = 32<rt>
    let fsr = regVar bld Register.FSR
    let fsr30 = AST.extract fsr 1<rt> 30
    let fsr31 = AST.extract fsr 1<rt> 31
    let res = tmpVar bld oprSize
    let op = tmpVar bld 64<rt>
    let regSize = tmpVar bld 32<rt>
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblL4 = label bld "L4"
    let lblL5 = label bld "L5"
    let lblEnd = label bld "End"
    let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
    let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
    let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
    getDFloatOp bld src op
    res := (AST.cast CastKind.SIntToFloat oprSize op)
    AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    dst := (AST.cast (CastKind.FtoFRound) oprSize res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    dst := (AST.cast (CastKind.FtoFTrunc) oprSize (res))
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5)
    AST.lmark lblL4
    dst := (AST.cast (CastKind.FtoFCeil) oprSize (res))
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL5
    dst := (AST.cast (CastKind.FtoFFloor) oprSize (res))
    AST.lmark lblEnd
  }

let fitos ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let oprSize = 32<rt>
    let fsr = regVar bld Register.FSR
    let fsr30 = AST.extract fsr 1<rt> 30
    let fsr31 = AST.extract fsr 1<rt> 31
    let res = tmpVar bld oprSize
    let regSize = 32<rt>
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblL4 = label bld "L4"
    let lblL5 = label bld "L5"
    let lblEnd = label bld "End"
    let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
    let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
    let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
    res := AST.cast CastKind.SIntToFloat oprSize src
    AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    dst := AST.cast CastKind.FtoFRound regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    dst := AST.cast CastKind.FtoFTrunc regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5)
    AST.lmark lblL4
    dst := AST.cast CastKind.FtoFCeil regSize (res)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL5
    dst := AST.cast CastKind.FtoFFloor regSize (res)
    AST.lmark lblEnd
  }

/// Converts a 64-bit integer to double precision.
let fxtod ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let oprSize = 64<rt>
    let op = tmpVar bld oprSize
    let res = tmpVar bld oprSize
    let rounded = tmpVar bld oprSize
    (* The 64-bit source integer occupies a double register (an even/odd %f pair
       on %f0-%f31), so assemble it with getDFloatOp; reading the operand
       register directly takes only its high half -- zero for any value below
       2^32 -- which silently converts small integers to 0.0. *)
    getDFloatOp bld src op
    res := AST.cast CastKind.SIntToFloat oprSize op
    roundByFSR bld res rounded oprSize
    setDFloatOp bld dst rounded
  }

let fitod ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let oprSize = 64<rt>
    let rounded = tmpVar bld oprSize
    rounded := AST.cast CastKind.SIntToFloat 64<rt> src
    setDFloatOp bld dst rounded
  }

let fxtoq ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let oprSize = 64<rt>
    let op = tmpVar bld oprSize
    let rounded = tmpVar bld 64<rt>
    let res1 = tmpVar bld oprSize
    let res2 = tmpVar bld oprSize
    getDFloatOp bld src op
    rounded := AST.cast CastKind.SIntToFloat 64<rt> op
    cast64To128 bld rounded res1 res2
    setQFloatOp bld dst res1 res2
  }

let fitoq ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let oprSize = 64<rt>
    let rounded = tmpVar bld 64<rt>
    let res1 = tmpVar bld oprSize
    let res2 = tmpVar bld oprSize
    rounded := AST.cast CastKind.SIntToFloat oprSize src
    cast64To128 bld rounded res1 res2
    setQFloatOp bld dst res1 res2
  }

let jmpl ins insLen bld =
  lift bld ins insLen {
    let struct (addr, dst) = transAddrThreeOprs ins insLen bld
    regVar bld Register.NPC := addr
    dst := regVar bld Register.PC
    arm bld InterJmpKind.Base
  }

let ldf ins insLen bld =
  lift bld ins insLen {
    let struct (addr, dst) = transAddrThreeOprs ins insLen bld
    let oprSize = 64<rt>
    match ins.Opcode with
    | Opcode.LDF ->
      dst := (AST.loadBE 32<rt> addr)
    | Opcode.LDDF ->
      let op = tmpVar bld oprSize
      op := (AST.loadBE oprSize addr)
      setDFloatOp bld dst op
    | Opcode.LDQF ->
      let op0 = tmpVar bld oprSize
      let op1 = tmpVar bld oprSize
      op0 := (AST.loadBE oprSize addr)
      op1 := (AST.loadBE oprSize (addr .+ numI64 8L 64<rt>))
      setQFloatOp bld dst op0 op1
    | Opcode.LDFSR ->
      (AST.extract dst 32<rt> 0) :=
      (AST.loadBE 32<rt> addr)
    | Opcode.LDXFSR ->
      dst := (AST.loadBE oprSize addr)
    | _ ->
      raise InvalidOpcodeException
  }

/// The eight double-float registers of the 64-byte VIS block whose first
/// register is baseReg. Consecutive doubles are two register ids apart below
/// %f32 (paired 32-bit registers) and one apart from %f32 up (64-bit
/// registers), so the block is [baseReg, baseReg + 2 (or 1), ... x8].
let private dfloatBlockOf (baseReg: Register) =
  let baseId = int baseReg
  let step = if baseId < int Register.F32 then 2 else 1
  [ for i in 0..7 -> enum<Register> (baseId + step * i) ]

let private blockDFloatRegs bld baseReg =
  let r n = regVar bld n
  let bases = [ Register.F0; Register.F16; Register.F32; Register.F48 ]
  match bases |> List.tryFind (fun b -> baseReg = r b) with
  | Some b -> dfloatBlockOf b |> List.map r
  | None -> raise InvalidRegisterException

/// Whether an ASI selects a 64-byte block transfer (ASI_BLK_*: 0xe0/0xe1
/// commit, 0xf0/0xf1 primary/secondary), for which stda/ldda move a whole
/// eight-register float block rather than a single doubleword.
let private isBlockAsi asi =
  (asi == numI64 0xf0L 64<rt>) .| (asi == numI64 0xf1L 64<rt>)
  .| (asi == numI64 0xe0L 64<rt>) .| (asi == numI64 0xe1L 64<rt>)

/// Loads a float block or a single doubleword, as the ASI selects.
let private ldfaWide bld addr asiVal dst oprSize =
  append bld {
    (* a block-transfer ASI loads the eight-register float block; any other
       ASI loads src's single doubleword. *)
    let op = tmpVar bld oprSize
    let lblBlk = label bld "Blk"
    let lblReg = label bld "Reg"
    let lblEnd = label bld "End"
    AST.cjmp (isBlockAsi asiVal)
             (AST.jmpDest lblBlk)
             (AST.jmpDest lblReg)
    AST.lmark lblBlk
    blockDFloatRegs bld dst
    |> List.iteri (fun i reg ->
      append bld {
        op := AST.loadBE 64<rt> (addr .+ numI64 (int64 (8 * i)) 64<rt>)
      }
      setDFloatOp bld reg op)
    append bld {
      AST.jmp (AST.jmpDest lblEnd)
      AST.lmark lblReg
      op := (AST.loadBE oprSize addr)
    }
    setDFloatOp bld dst op
    append bld {
      AST.lmark lblEnd
    }
  }

let ldfa ins insLen bld =
  lift bld ins insLen {
    let struct (addr, asiVal, dst) = transAddrFourOprs ins insLen bld
    let oprSize = 64<rt>
    (* address is Rs1 + Rs2; the ASI selects the address space (or a block
       transfer). *)
    match ins.Opcode with
    | Opcode.LDFA ->
      dst := (AST.loadBE 32<rt> addr)
    | Opcode.LDDFA ->
      ldfaWide bld addr asiVal dst oprSize
    | Opcode.LDQFA ->
      let op0 = tmpVar bld oprSize
      let op1 = tmpVar bld oprSize
      op0 := (AST.loadBE oprSize addr)
      op1 := (AST.loadBE oprSize (addr .+ numI64 8L 64<rt>))
      setQFloatOp bld dst op0 op1
    | _ ->
      raise InvalidOpcodeException
  }

let ld ins insLen bld =
  lift bld ins insLen {
    let struct (addr, dst) = transAddrThreeOprs ins insLen bld
    let oprSize = 64<rt>
    match ins.Opcode with
    | Opcode.LDSB ->
      dst := (AST.sext oprSize (AST.loadBE 8<rt> addr))
    | Opcode.LDSH ->
      dst := (AST.sext oprSize (AST.loadBE 16<rt> addr))
    | Opcode.LDSW ->
      dst := (AST.sext oprSize (AST.loadBE 32<rt> addr))
    | Opcode.LDUB ->
      dst := (AST.zext oprSize (AST.loadBE 8<rt> addr))
    | Opcode.LDUH ->
      dst := (AST.zext oprSize (AST.loadBE 16<rt> addr))
    | Opcode.LDUW ->
      dst := (AST.zext oprSize (AST.loadBE 32<rt> addr))
    | Opcode.LDX ->
      dst := AST.loadBE oprSize addr
    | Opcode.LDD ->
      if (dst = regVar bld Register.G0) then
        let nxt = regVar bld Register.G1
        nxt := (AST.zext oprSize (AST.extract
          (AST.loadBE oprSize addr) 32<rt> 0))
      else
        let nxt = regVar bld (getNextReg bld dst)
        dst := (AST.zext oprSize (AST.extract
          (AST.loadBE oprSize addr) 32<rt> 32))
        nxt := (AST.zext oprSize (AST.extract
          (AST.loadBE oprSize addr) 32<rt> 0))
    | _ ->
      raise InvalidOpcodeException
  }

let lda ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, _asi, dst) = transFourOprs ins insLen bld
    let oprSize = 64<rt>
    (* operands are (Rs1, Rs2, ASI, Rd): the effective address is Rs1 + Rs2; the
       ASI only selects the address space (all user ASIs map to primary memory
       here), so it is never part of the address. *)
    let addr = src .+ src1
    match ins.Opcode with
    | Opcode.LDSBA ->
      dst := (AST.sext oprSize (AST.loadBE 8<rt> addr))
    | Opcode.LDSHA ->
      dst := (AST.sext oprSize (AST.loadBE 16<rt> addr))
    | Opcode.LDSWA ->
      dst := (AST.sext oprSize (AST.loadBE 32<rt> addr))
    | Opcode.LDUBA ->
      dst := (AST.zext oprSize (AST.loadBE 8<rt> addr))
    | Opcode.LDUHA ->
      dst := (AST.zext oprSize (AST.loadBE 16<rt> addr))
    | Opcode.LDUWA ->
      dst := (AST.zext oprSize (AST.loadBE 32<rt> addr))
    | Opcode.LDXA ->
      dst := AST.loadBE oprSize addr
    | Opcode.LDDA ->
      if (dst = regVar bld Register.G0) then
        let nxt = regVar bld Register.G1
        nxt := (AST.zext oprSize (AST.extract
          (AST.loadBE oprSize addr) 32<rt> 0))
      else
        let nxt = regVar bld (getNextReg bld dst)
        dst := (AST.zext oprSize (AST.extract
          (AST.loadBE oprSize addr) 32<rt> 32))
        nxt := (AST.zext oprSize (AST.extract
          (AST.loadBE oprSize addr) 32<rt> 0))
    | _ ->
      raise InvalidOpcodeException
  }

let ldstub ins insLen bld =
  lift bld ins insLen {
    let struct (addr, dst) = transAddrThreeOprs ins insLen bld
    let oprSize = 64<rt>
    dst := (AST.zext oprSize (AST.loadBE 8<rt> addr))
    (AST.loadBE 8<rt> addr) := (numI32 0xff 8<rt>)
  }

let ldstuba ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, _asi, dst) = transFourOprs ins insLen bld
    let oprSize = 64<rt>
    (* operands (Rs1, Rs2, ASI, Rd): address is Rs1 + Rs2; the ASI selects the
       address space only, so it is not part of the address. *)
    let addr = src .+ src1
    dst := (AST.zext oprSize (AST.loadBE 8<rt> addr))
    (AST.loadBE 8<rt> addr) := (numI32 0xff 8<rt>)
  }

let membar ins insLen bld = (* FIXME *)
  let mask = transOneOpr ins insLen bld
  let oprSize = 64<rt>
  let t1 = tmpVar bld oprSize
  lift bld ins insLen {
    t1 := mask
  }

/// The bit of the condition-code register that the given integer condition
/// reads, from whichever of the two condition codes the operand selects.
let private iccBit bld cc ccr n =
  if cc = getCCVar bld ConditionCode.Icc then AST.extract ccr 1<rt> n
  else AST.extract ccr 1<rt> (n + 4)

/// Moves the source under the condition the opcode names, which is what
/// every member of the MOVcc family comes down to.
/// The condition an integer MOVcc tests.
let private movUnderIccCondOf (ins: Instruction) bld cc ccr =
  match ins.Opcode with
  | Opcode.MOVNE ->
    (iccBit bld cc ccr 2 == AST.b0)
  | Opcode.MOVE ->
    (iccBit bld cc ccr 2 == AST.b1)
  | Opcode.MOVG ->
    let n = iccBit bld cc ccr 3
    let z = iccBit bld cc ccr 2
    let v = iccBit bld cc ccr 1
    ((z .| (n <+> v)) == AST.b0)
  | Opcode.MOVLE ->
    let n = iccBit bld cc ccr 3
    let z = iccBit bld cc ccr 2
    let v = iccBit bld cc ccr 1
    ((z .| (n <+> v)) == AST.b1)
  | Opcode.MOVGE ->
    let n = iccBit bld cc ccr 3
    let v = iccBit bld cc ccr 1
    ((n <+> v) == AST.b0)
  | Opcode.MOVL ->
    let n = iccBit bld cc ccr 3
    let v = iccBit bld cc ccr 1
    ((n <+> v) == AST.b1)
  | Opcode.MOVGU ->
    let z = iccBit bld cc ccr 2
    let c = iccBit bld cc ccr 0
    ((c .| z) == AST.b0)
  | Opcode.MOVLEU ->
    let z = iccBit bld cc ccr 2
    let c = iccBit bld cc ccr 0
    ((c .| z) == AST.b1)
  | Opcode.MOVCC ->
    let c = iccBit bld cc ccr 0
    (c == AST.b0)
  | Opcode.MOVCS ->
    let ccr = regVar bld Register.CCR
    if (cc = getCCVar bld ConditionCode.Icc) then
      let c = AST.extract ccr 1<rt> 0
      (c == AST.b1)
    else
      let c = AST.extract ccr 1<rt> 4
      (c == AST.b1)
  | Opcode.MOVPOS ->
    let n = iccBit bld cc ccr 3
    (n == AST.b0)
  | Opcode.MOVNEG ->
    let n = iccBit bld cc ccr 3
    (n == AST.b1)
  | Opcode.MOVVC ->
    let v = iccBit bld cc ccr 1
    (v == AST.b0)
  | Opcode.MOVVS ->
    (iccBit bld cc ccr 1 == AST.b1)
  | _ ->
    raise InvalidOpcodeException

let private movUnderIccCond (ins: Instruction) bld cc ccr src dst =
  append bld {
    dst := AST.ite (movUnderIccCondOf ins bld cc ccr) (src) (dst)
  }

/// The two-bit floating-point condition code the operand selects.
let private fccValue bld cc fsr =
  if cc = getCCVar bld ConditionCode.Fcc0 then
    AST.extract fsr 2<rt> 10
  elif cc = getCCVar bld ConditionCode.Fcc1 then
    AST.extract fsr 2<rt> 32
  elif cc = getCCVar bld ConditionCode.Fcc2 then
    AST.extract fsr 2<rt> 34
  else
    AST.extract fsr 2<rt> 36

/// The condition a floating-point MOVcc tests, which is whether the
/// comparison's answer is one of the ones the opcode names.
let private movUnderFccCondOf (ins: Instruction) bld cc fsr =
  let fcc = fccValue bld cc fsr
  let isAny (vs: int list) =
    vs
    |> List.map (fun v -> fcc == numI32 v 2<rt>)
    |> List.reduce (.|)
  match ins.Opcode with
  | Opcode.MOVFU -> isAny [ 3 ]
  | Opcode.MOVFG -> isAny [ 2 ]
  | Opcode.MOVFUG -> isAny [ 3; 2 ]
  | Opcode.MOVFL -> isAny [ 1 ]
  | Opcode.MOVFUL -> isAny [ 3; 1 ]
  | Opcode.MOVFLG -> isAny [ 1; 2 ]
  | Opcode.MOVFNE -> isAny [ 3; 2; 1 ]
  | Opcode.MOVFE -> isAny [ 0 ]
  | Opcode.MOVFUE -> isAny [ 3; 0 ]
  | Opcode.MOVFGE -> isAny [ 0; 2 ]
  | Opcode.MOVFUGE -> isAny [ 3; 2; 0 ]
  | Opcode.MOVFLE -> isAny [ 1; 0 ]
  | Opcode.MOVFULE -> isAny [ 3; 1; 0 ]
  | Opcode.MOVFO -> isAny [ 1; 2; 0 ]
  | _ -> raise InvalidOpcodeException

let private movUnderFccCond (ins: Instruction) bld cc fsr src dst =
  append bld {
    dst := AST.ite (movUnderFccCondOf ins bld cc fsr) (src) (dst)
  }

let private movUnderCond (ins: Instruction) bld cc ccr fsr src dst =
  match ins.Opcode with
  | Opcode.MOVA | Opcode.MOVFA ->
    append bld { dst := src }
  | Opcode.MOVN | Opcode.MOVFN ->
    ()
  | Opcode.MOVFU | Opcode.MOVFG | Opcode.MOVFUG
  | Opcode.MOVFL | Opcode.MOVFUL | Opcode.MOVFLG
  | Opcode.MOVFNE | Opcode.MOVFE | Opcode.MOVFUE
  | Opcode.MOVFGE | Opcode.MOVFUGE | Opcode.MOVFLE
  | Opcode.MOVFULE | Opcode.MOVFO ->
    movUnderFccCond ins bld cc fsr src dst
  | _ ->
    movUnderIccCond ins bld cc ccr src dst

let movcc ins insLen bld =
  lift bld ins insLen {
    let struct (cc, src, dst) = transThreeOprs ins insLen bld
    let ccr = regVar bld Register.CCR
    let fsr = regVar bld Register.FSR
    if (dst <> regVar bld Register.G0) then
      movUnderCond ins bld cc ccr fsr src dst
    else
      ()
  }

let movr ins insLen bld = (* TODO : check that destination is not g0*)
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  lift bld ins insLen {
    match ins.Opcode with
    | Opcode.MOVRZ ->
      dst := AST.ite (src == AST.num0 oprSize) (src1) (dst)
    | Opcode.MOVRLEZ ->
      dst := AST.ite (src ?<= AST.num0 oprSize) (src1) (dst)
    | Opcode.MOVRLZ ->
      dst := AST.ite (src ?< AST.num0 oprSize) (src1) (dst)
    | Opcode.MOVRNZ ->
      dst := AST.ite (src != AST.num0 oprSize) (src1) (dst)
    | Opcode.MOVRGZ ->
      dst := AST.ite (src ?> AST.num0 oprSize) (src1) (dst)
    | Opcode.MOVRGEZ ->
      dst := AST.ite (src ?>= AST.num0 oprSize) (src1) (dst)
    | _ ->
      raise InvalidOpcodeException
  }

let mulscc ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    let res = tmpVar bld oprSize
    let src32 = tmpVar bld 32<rt>
    let y = regVar bld Register.Y
    let ccr = regVar bld Register.CCR
    let src2 = tmpVar bld 32<rt>
    let hbyte = tmpVar bld 4<rt>
    src32 := AST.concat ((AST.extract ccr 1<rt> 3) <+>
      (AST.extract ccr 1<rt> 1)) (AST.extract src 31<rt> 1)
    src2 := AST.ite ((AST.extract y 1<rt> 0) == AST.b0)
                    (AST.num0 32<rt>)
                    (AST.extract src1 32<rt> 0)
    res := AST.zext 64<rt> (src32 .+ src2)
    if (dst <> regVar bld Register.G0) then append bld { dst := res } else ()
    (AST.extract y 32<rt> 0) := AST.concat (AST.extract src 1<rt> 0)
      (AST.extract y 31<rt> 1)
    hbyte := getConditionCodeMulscc res src32 src2
    AST.extract ccr 4<rt> 0 := hbyte
  }

let mulx ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    if (dst = regVar bld Register.G0) then append bld { dst := AST.num0 64<rt> }
    else append bld { dst := src .* src1 }
  }

let nop (ins: Instruction) insLen bld =
  lift bld ins insLen {
  }

let ``or`` ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    let res = tmpVar bld oprSize
    res := src .| src1
    if (dst = regVar bld Register.G0) then append bld { dst := AST.num0 64<rt> }
    else append bld { dst := res }
  }

let orcc ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    let res = tmpVar bld oprSize
    let ccr = regVar bld Register.CCR
    let byte = tmpVar bld 8<rt>
    res := src .| src1
    if (dst = regVar bld Register.G0) then append bld { dst := AST.num0 64<rt> }
    else append bld { dst := res }
    byte := (getConditionCodeLog res src src1)
    AST.extract ccr 8<rt> 0 := byte
  }

let orn ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    let res = tmpVar bld oprSize
    res := (src .| AST.not (src1))
    if (dst = regVar bld Register.G0) then append bld { dst := AST.num0 64<rt> }
    else append bld { dst := res }
  }

let orncc ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    let res = tmpVar bld oprSize
    let ccr = regVar bld Register.CCR
    let byte = tmpVar bld 8<rt>
    res := (src .| AST.not (src1))
    if (dst = regVar bld Register.G0) then append bld { dst := AST.num0 64<rt> }
    else append bld { dst := res }
    byte := (getConditionCodeLog res src src1)
    AST.extract ccr 8<rt> 0 := byte
  }

let popc ins insLen bld =
  lift bld ins insLen {
    let struct (src, dst) = transTwoOprs ins insLen bld
    let oprSize = 64<rt>
    let max = numI32 (RegType.toBitWidth oprSize) 64<rt>
    let lblLoop = label bld "Loop"
    let lblExit = label bld "Exit"
    let lblLoopCond = label bld "LoopCond"
    let struct (i, count) = tmpVars2 bld oprSize
    i := AST.num0 oprSize
    count := AST.num0 oprSize
    AST.lmark lblLoopCond
    AST.cjmp (AST.lt i max) (AST.jmpDest lblLoop) (AST.jmpDest lblExit)
    AST.lmark lblLoop
    let cond = (AST.xtlo 1<rt> (src >> i)) == AST.b1
    count := AST.ite cond (count .+ AST.num1 oprSize) count
    i := i .+ AST.num1 oprSize
    AST.jmp (AST.jmpDest lblLoopCond)
    AST.lmark lblExit
    dst := count
  }

let rd ins insLen bld =
  lift bld ins insLen {
    let struct (reg, dst) = transTwoOprs ins insLen bld
    dst := reg
  }

/// The in/out register pairs the register window rotates: on SAVE the caller's
/// %o becomes the callee's %i (so %i6 takes the caller %sp as the new %fp and
/// %i7 the return address), and on RESTORE the %i rotates back to %o.
let private inOutPairs =
  [ Register.I0, Register.O0
    Register.I1, Register.O1
    Register.I2, Register.O2
    Register.I3, Register.O3
    Register.I4, Register.O4
    Register.I5, Register.O5
    Register.I6, Register.O6
    Register.I7, Register.O7 ]

let restore ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let result = tmpVar bld 64<rt>
    result := src .+ src1
    for i, o in inOutPairs do
      regVar bld o := regVar bld i
    AST.sideEffect RestoreWindow
    dst := result
  }

let restored (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let cs = regVar bld Register.CANSAVE
    let cr = regVar bld Register.CANRESTORE
    let ow = regVar bld Register.OTHERWIN
    (* RESTORED: CANRESTORE += 1; then if OTHERWIN == 0 decrement CANSAVE, else
       decrement OTHERWIN. *)
    cr := (cr .+ AST.num1 64<rt>)
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let cond = (ow == AST.num0 64<rt>)
    AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    cs := (cs .- AST.num1 64<rt>)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    ow := (ow .- AST.num1 64<rt>)
    AST.lmark lblEnd
  }

let ret ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1) = transTwoOprs ins insLen bld
    (* RETURN is jmpl + a register-window RESTORE: the target reads %i7
       first, then the window rotates out (%o := %i, matching the RESTORE
       instruction), so the caller regains its %l/%i and receives the callee's
       %i as its %o. *)
    regVar bld Register.NPC := src .+ src1
    for i, o in inOutPairs do
      regVar bld o := regVar bld i
    AST.sideEffect RestoreWindow
    arm bld InterJmpKind.IsRet
  }

let retry (ins: Instruction) insLen bld =
  lift bld ins insLen {
    (* nPC before PC: writing %pc (a PCVar) ends the trace, so it goes last. *)
    regVar bld Register.NPC := regVar bld Register.TNPC
    regVar bld Register.PC := regVar bld Register.TPC
  }

let save ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let result = tmpVar bld 64<rt>
    result := src .+ src1
    AST.sideEffect SaveWindow
    for i, o in inOutPairs do
      regVar bld i := regVar bld o
    dst := result
  }

let flushw (ins: Instruction) insLen bld =
  lift bld ins insLen {
    AST.sideEffect FlushWindows
  }

/// The %g, %o, %l, and %i register for a window index (0-7).
let private gReg i = enum<Register> i
let private oReg i = enum<Register> (0x8 + i)
let private lReg i = enum<Register> (0x10 + i)
let private iReg i = enum<Register> (0x18 + i)

/// GETCONTEXT (ta 0x6e): sparc64 Linux realizes setjmp and getcontext with
/// this trap, saving the caller's context into the ucontext at %o0. Store the
/// integer state at the mc_gregs offsets glibc uses (base %o0 + 0x20: PC 0x28,
/// NPC 0x30, Y 0x38, %g1-7 0x40-0x70, %o0-7 0x78-0xb0) and spill the current
/// window's %l/%i to the stack save area [%sp + bias], as the kernel flushes
/// the trapped window. The saved PC/NPC resume just past the trap, so execution
/// falls through and setjmp returns with %g1 as-is (0); _longjmp overwrites
/// MC_G1 with the value the matching SETCONTEXT then loads.
let getContext (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let buf = regVar bld Register.O0
    let sp = regVar bld Register.O6
    let gregs off = AST.loadBE 64<rt> (buf .+ numI64 off 64<rt>)
    let slot k = AST.loadBE 64<rt> (sp .+ numI64 (2047L + int64 k * 8L) 64<rt>)
    gregs 0x28L := numI64 (int64 (ins.Address + 4UL)) 64<rt>
    gregs 0x30L := numI64 (int64 (ins.Address + 8UL)) 64<rt>
    gregs 0x38L := regVar bld Register.Y
    for i in 1 .. 7 do
      gregs (0x40L + int64 (i - 1) * 8L) := regVar bld (gReg i)
    for i in 0 .. 7 do
      gregs (0x78L + int64 i * 8L) := regVar bld (oReg i)
    for i in 0 .. 7 do append bld { slot i := regVar bld (lReg i) }
    for i in 0 .. 7 do append bld { slot (8 + i) := regVar bld (iReg i) }
  }

/// SETCONTEXT (ta 0x6f): the restore half used by _longjmp and setcontext.
/// Reload the integer state saved by GETCONTEXT from the ucontext at %o0 (%g1
/// takes MC_G1, which _longjmp set to the longjmp value) and the window's %l/%i
/// from the restored frame's save area, then resume at the saved PC/NPC the way
/// RETRY does. Windows the skipped frames orphaned on the stack are dropped
/// lazily by the next RESTORE.
let setContext (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let buf = tmpVar bld 64<rt>
    buf := regVar bld Register.O0
    let gregs off = AST.loadBE 64<rt> (buf .+ numI64 off 64<rt>)
    for i in 1 .. 7 do
      regVar bld (gReg i) := gregs (0x40L + int64 (i - 1) * 8L)
    for i in 0 .. 7 do
      regVar bld (oReg i) := gregs (0x78L + int64 i * 8L)
    regVar bld Register.Y := gregs 0x38L
    let sp = regVar bld Register.O6
    let slot k = AST.loadBE 64<rt> (sp .+ numI64 (2047L + int64 k * 8L) 64<rt>)
    for i in 0 .. 7 do append bld { regVar bld (lReg i) := slot i }
    for i in 0 .. 7 do append bld { regVar bld (iReg i) := slot (8 + i) }
    regVar bld Register.NPC := gregs 0x30L
    regVar bld Register.PC := gregs 0x28L
  }

/// A trap-always used as the Linux system-call gate: sparc64 traps to 0x6d,
/// sparc32 to 0x10, and realizes setjmp/longjmp through the getcontext (0x6e)
/// and setcontext (0x6f) traps. Only these are modeled; every other
/// trap-on-condition is a no-op here (real traps are not modeled). The kernel
/// reads the call number from %g1 and the arguments from %o0..%o5.
let tcc (ins: Instruction) insLen bld =
  match ins.Operands with
  | TwoOperands(_, OprImm n) when n = 0x6e ->
    getContext ins insLen bld
  | TwoOperands(_, OprImm n) when n = 0x6f ->
    setContext ins insLen bld
  | _ ->
    lift bld ins insLen {
      match ins.Operands with
      | TwoOperands(_, OprImm n) when n = 0x6d || n = 0x10 ->
        AST.sideEffect SysCall
      | _ ->
        ()
    }

let saved (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let cs = regVar bld Register.CANSAVE
    let cr = regVar bld Register.CANRESTORE
    let ow = regVar bld Register.OTHERWIN
    (* SAVED: CANSAVE += 1; then if OTHERWIN == 0 decrement CANRESTORE, else
       decrement OTHERWIN. *)
    cs := (cs .+ AST.num1 64<rt>)
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let cond = (ow == AST.num0 64<rt>)
    AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    cr := (cr .- AST.num1 64<rt>)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    ow := (ow .- AST.num1 64<rt>)
    AST.lmark lblEnd
  }

let sdiv ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let divisor = tmpVar bld 32<rt>
    let dividend = tmpVar bld 64<rt>
    let quotient = tmpVar bld 64<rt>
    let y = regVar bld Register.Y
    let lo = AST.extract quotient 32<rt> 0
    (* Signed division with signed 32-bit saturation: the quotient is kept when
       it fits a signed 32-bit value, else clamped to INT32_MIN/INT32_MAX by its
       sign. SDIV (non-cc) leaves the condition codes untouched, like UDIV. *)
    let saturated =
      AST.ite ((AST.sext 64<rt> lo) == quotient) (AST.sext 64<rt> lo)
        (AST.ite (AST.extract quotient 1<rt> 63 == AST.b1)
                 (numU64 0x80000000UL 64<rt>)
                 (numU64 0x7fffffffUL 64<rt>))
    divisor := AST.extract src1 32<rt> 0
    dividend := AST.concat (AST.extract y 32<rt> 0)
      (AST.extract src 32<rt> 0)
    let cond = (divisor == AST.num0 32<rt>)
    if (divisor = AST.num0 32<rt> || src1 = regVar bld Register.G0) then
      AST.sideEffect (Exception DivideError)
    elif (isRegOpr ins insLen bld) then
      AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblL1)
      AST.lmark lblL1
      if (dst <> regVar bld Register.G0) then
        quotient := dividend ?/ (AST.sext 64<rt> divisor)
      else
        ()
      dst := saturated
      AST.jmp (AST.jmpDest lblEnd)
      AST.lmark lblL0
      AST.sideEffect (Exception DivideError)
      AST.lmark lblEnd
    else
      quotient := dividend ?/ (AST.sext 64<rt> divisor)
      dst := saturated
  }

/// Signed 32-bit divide, setting the condition codes.
let sdivcc ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let divisor = tmpVar bld 32<rt>
    let dividend = tmpVar bld 64<rt>
    let quotient = tmpVar bld 64<rt>
    let y = regVar bld Register.Y
    let ccr = regVar bld Register.CCR
    let struct (fits, saturated) = signedDivResult quotient
    divisor := AST.extract src1 32<rt> 0
    dividend := AST.concat (AST.extract y 32<rt> 0)
      (AST.extract src 32<rt> 0)
    let cond = (divisor == AST.num0 32<rt>)
    if (divisor = AST.num0 32<rt> || src1 = regVar bld Register.G0) then
      AST.sideEffect (Exception DivideError)
    elif (isRegOpr ins insLen bld) then
      AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblL1)
      AST.lmark lblL1
      if (dst <> regVar bld Register.G0) then
        quotient := dividend ?/ (AST.sext 64<rt> divisor)
      else
        ()
      dst := saturated
      AST.extract ccr 1<rt> 1 := AST.ite fits (AST.b0) (AST.b1)
      AST.jmp (AST.jmpDest lblEnd)
      AST.lmark lblL0
      AST.sideEffect (Exception DivideError)
      AST.lmark lblEnd
    else
      quotient := dividend ?/ (AST.sext 64<rt> divisor)
      dst := saturated
      AST.extract ccr 1<rt> 1 := AST.ite fits (AST.b0) (AST.b1)
    setDivCC bld ccr quotient
  }

let sdivx ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let cond = (src1 == AST.num0 64<rt>)
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    if (src1 = AST.num0 64<rt> || src1 = regVar bld Register.G0) then
      AST.sideEffect (Exception DivideError)
    elif (isRegOpr ins insLen bld) then
      AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblL1)
      AST.lmark lblL1
      if (dst = regVar bld Register.G0) then
        append bld { dst := AST.num0 64<rt> }
      else
        append bld { dst := src ?/ src1 }
      AST.jmp (AST.jmpDest lblEnd)
      AST.lmark lblL0
      AST.sideEffect (Exception DivideError)
      AST.lmark lblEnd
    else
      if (dst = regVar bld Register.G0) then
        append bld { dst := AST.num0 64<rt> }
      else
        append bld { dst := src ?/ src1 }
  }

let sethi ins insLen bld =
  lift bld ins insLen {
    let struct (imm, dst) = transTwoOprs ins insLen bld
    if (dst <> regVar bld Register.G0) then
      dst := AST.concat (AST.zext 32<rt> AST.b0)
        (AST.extract imm 32<rt> 0)
    else
      ()
  }

let sll ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    if (dst = regVar bld Register.G0) then
      dst := AST.num0 64<rt>
    else
      (* the hardware masks the shift count -- 5 bits for the 32-bit form, 6 for
         the 64-bit -- and code (e.g. glibc's GNU-hash bloom filter) relies on
         it by passing an unmasked count, so mask here to match. *)
      match ins.Opcode with
      | Opcode.SLL ->
        dst := AST.zext 64<rt> (AST.extract src 32<rt> 0
          << (AST.extract src1 32<rt> 0 .& numI32 0x1f 32<rt>))
      | _ ->
        dst := src << (src1 .& numI64 0x3fL 64<rt>)
  }

let smul ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let yreg = regVar bld Register.Y
    if (dst = regVar bld Register.G0) then
      dst := AST.num0 64<rt>
    else
      dst := (AST.sext 64<rt> (AST.extract src 32<rt> 0))
        .* (AST.sext 64<rt> (AST.extract src1 32<rt> 0))
      AST.extract yreg 64<rt> 0 := AST.zext 64<rt>
        (AST.extract dst 32<rt> 32)
  }

let smulcc ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let yreg = regVar bld Register.Y
    let ccr = regVar bld Register.CCR
    let byte = tmpVar bld 8<rt>
    if (dst = regVar bld Register.G0) then
      dst := AST.num0 64<rt>
    else
      dst := (AST.sext 64<rt> (AST.extract src 32<rt> 0))
        .* (AST.sext 64<rt> (AST.extract src1 32<rt> 0))
      AST.extract yreg 64<rt> 0 := AST.zext 64<rt>
        (AST.extract dst 32<rt> 32)
      byte := (getConditionCodeMul dst src src1)
      AST.extract ccr 8<rt> 0 := byte
  }

let sra ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    if (dst = regVar bld Register.G0) then
      dst := AST.num0 64<rt>
    else
      (* mask the shift count as the hardware does (5 bits / 6 bits). *)
      match ins.Opcode with
      | Opcode.SRA ->
        dst := AST.sext 64<rt> (AST.extract src 32<rt> 0
          ?>> (AST.extract src1 32<rt> 0 .& numI32 0x1f 32<rt>))
      | _ ->
        dst := src ?>> (src1 .& numI64 0x3fL 64<rt>)
  }

let srl ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    if (dst = regVar bld Register.G0) then
      dst := AST.num0 64<rt>
    else
      (* mask the shift count as the hardware does (5 bits / 6 bits). *)
      match ins.Opcode with
      | Opcode.SRL ->
        dst := AST.zext 64<rt> (AST.extract src 32<rt> 0
          >> (AST.extract src1 32<rt> 0 .& numI32 0x1f 32<rt>))
      | _ ->
        dst := src >> (src1 .& numI64 0x3fL 64<rt>)
  }

let st ins insLen bld =
  lift bld ins insLen {
    let struct (src, addr) = transTwooprsAddr ins insLen bld
    match ins.Opcode with
    | Opcode.STB ->
      (AST.loadBE 8<rt> addr) := (AST.extract src 8<rt> 0)
    | Opcode.STH ->
      (AST.loadBE 16<rt> addr) := (AST.extract src 16<rt> 0)
    | Opcode.STW ->
      (AST.loadBE 32<rt> addr) := (AST.extract src 32<rt> 0)
    | Opcode.STX ->
      (AST.loadBE 64<rt> addr) := (AST.extract src 64<rt> 0)
    | Opcode.STD ->
      let nxt = regVar bld (getNextReg bld src)
      (AST.loadBE 32<rt> addr) := (AST.extract src 32<rt> 0)
      (AST.loadBE 32<rt> (addr .+ numI64 4L 64<rt>)) :=
        (AST.extract nxt 32<rt> 0)
    | _ ->
      raise InvalidOpcodeException
  }

let sta ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, asi, _dst) = transFourOprs ins insLen bld
    (* operands are (Rd, Rs1, Rs2, ASI): src is the value to store; the
       effective address is Rs1 + Rs2 (src1 + asi), never the value register,
       and the ASI only selects the address space -- it is not part of the
       address. *)
    let addr = src1 .+ asi
    match ins.Opcode with
    | Opcode.STBA ->
      (AST.loadBE 8<rt> addr) := (AST.extract src 8<rt> 0)
    | Opcode.STHA ->
      (AST.loadBE 16<rt> addr) := (AST.extract src 16<rt> 0)
    | Opcode.STWA ->
      (AST.loadBE 32<rt> addr) := (AST.extract src 32<rt> 0)
    | Opcode.STXA ->
      (AST.loadBE 64<rt> addr) := (AST.extract src 64<rt> 0)
    | Opcode.STDA ->
      let nxt = regVar bld (getNextReg bld src)
      (AST.loadBE 32<rt> addr) := (AST.extract src 32<rt> 0)
      (AST.loadBE 32<rt> (addr .+ numI64 4L 64<rt>)) :=
        (AST.extract nxt 32<rt> 0)
    | _ ->
      raise InvalidOpcodeException
  }

let stf ins insLen bld =
  lift bld ins insLen {
    let struct (src, addr) = transTwooprsAddr ins insLen bld
    let oprSize = 64<rt>
    match ins.Opcode with
    | Opcode.STF ->
      (AST.loadBE 32<rt> addr) := (AST.extract src 32<rt> 0)
    | Opcode.STDF ->
      let op = tmpVar bld oprSize
      getDFloatOp bld src op
      (AST.loadBE 64<rt> addr) := (AST.extract op 64<rt> 0)
    | Opcode.STQF ->
      let op0 = tmpVar bld oprSize
      let op1 = tmpVar bld oprSize
      getQFloatOp bld src op0 op1
      (AST.loadBE 64<rt> addr) := (AST.extract op0 64<rt> 0)
      (AST.loadBE 64<rt> (addr .+ numI64 8L 64<rt>)) :=
        (AST.extract op1 64<rt> 0)
    | Opcode.STFSR ->
      (AST.loadBE 32<rt> addr) := (AST.extract src 32<rt> 0)
    | Opcode.STXFSR ->
      (AST.loadBE 64<rt> addr) := src
    | _ ->
      raise InvalidOpcodeException
  }

/// Stores a float block or a single doubleword, as the ASI selects.
let private stfaWide bld addr asiVal src oprSize =
  append bld {
    (* a block-transfer ASI stores the eight-register float block; any other
       ASI stores src's single doubleword. *)
    let op = tmpVar bld oprSize
    let lblBlk = label bld "Blk"
    let lblReg = label bld "Reg"
    let lblEnd = label bld "End"
    AST.cjmp (isBlockAsi asiVal)
             (AST.jmpDest lblBlk)
             (AST.jmpDest lblReg)
    AST.lmark lblBlk
    blockDFloatRegs bld src
    |> List.iteri (fun i reg ->
      getDFloatOp bld reg op
      append bld {
        AST.loadBE 64<rt> (addr .+ numI64 (int64 (8 * i)) 64<rt>) := op
      })
    append bld {
      AST.jmp (AST.jmpDest lblEnd)
      AST.lmark lblReg
    }
    getDFloatOp bld src op
    append bld {
      AST.loadBE 64<rt> addr := op
      AST.lmark lblEnd
    }
  }

let stfa ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, asi, asiVal) = transFourOprs ins insLen bld
    let oprSize = 64<rt>
    (* operands (FloatRd, Rs1, Rs2-or-simm13, ASI): src is the value; the
       address is Rs1 + Rs2 (src1 + asi); asiVal selects the address space. *)
    let addr = src1 .+ asi
    match ins.Opcode with
    | Opcode.STFA ->
      (AST.loadBE 32<rt> (addr)) :=
                  (AST.extract src 32<rt> 0)
    | Opcode.STDFA ->
      stfaWide bld addr asiVal src oprSize
    | Opcode.STQFA ->
      let op0 = tmpVar bld oprSize
      let op1 = tmpVar bld oprSize
      getQFloatOp bld src op0 op1
      (AST.loadBE 64<rt> (addr)) := (AST.extract op0 64<rt> 0)
      (AST.loadBE 64<rt> ((addr) .+ numI64 8L 64<rt>)) :=
        (AST.extract op1 64<rt> 0)
    | _ ->
      raise InvalidOpcodeException
  }

let sub ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    let res = tmpVar bld oprSize
    res := src .- src1
    if (dst = regVar bld Register.G0) then append bld { dst := AST.num0 64<rt> }
    else append bld { dst := res }
  }

let subcc ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    let res = tmpVar bld oprSize
    let ccr = regVar bld Register.CCR
    let byte = tmpVar bld 8<rt>
    res := src .- src1
    (* compute the flags from the original operands before writing dst: rd may
       alias rs1/rs2, and the V/C flags read the operands' sign bits, so writing
       dst first would feed the flag formula the result instead of the input. *)
    byte := (getConditionCodeSub res src src1)
    AST.extract ccr 8<rt> 0 := byte
    if (dst = regVar bld Register.G0) then append bld { dst := AST.num0 64<rt> }
    else append bld { dst := res }
  }

let subC ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    let res = tmpVar bld oprSize
    let ccr = regVar bld Register.CCR
    res := src .- src1 .- AST.zext 64<rt> (AST.extract ccr 1<rt> 0)
    if (dst = regVar bld Register.G0) then append bld { dst := AST.num0 64<rt> }
    else append bld { dst := res }
  }

let subCcc ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    let res = tmpVar bld oprSize
    let ccr = regVar bld Register.CCR
    let byte = tmpVar bld 8<rt>
    res := src .- src1 .- AST.zext 64<rt> (AST.extract ccr 1<rt> 0)
    (* flags before dst: rd may alias an operand the V/C formula reads. *)
    byte := (getConditionCodeSub res src src1)
    AST.extract ccr 8<rt> 0 := byte
    if (dst = regVar bld Register.G0) then append bld { dst := AST.num0 64<rt> }
    else append bld { dst := res }
  }

let swap ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    let addr = tmpVar bld oprSize
    let tmp = tmpVar bld 32<rt>
    (* atomic exchange: load the memory word, write the old rd there, then move
       the loaded word into rd (rd read before it is overwritten). *)
    addr := (src .+ src1)
    tmp := AST.loadBE 32<rt> addr
    AST.loadBE 32<rt> addr := AST.extract dst 32<rt> 0
    dst := AST.zext oprSize tmp
  }

let swapa ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, _asi, dst) = transFourOprs ins insLen bld
    let oprSize = 64<rt>
    let addr = tmpVar bld oprSize
    let tmp = tmpVar bld 32<rt>
    (* operands (Rs1, Rs2, ASI, Rd): address is Rs1 + Rs2; the ASI selects the
       address space only. *)
    addr := (src .+ src1)
    tmp := AST.loadBE 32<rt> addr
    AST.loadBE 32<rt> addr := AST.extract dst 32<rt> 0
    dst := AST.zext oprSize tmp
  }

let udiv ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let divisor = tmpVar bld 32<rt>
    let dividend = tmpVar bld 64<rt>
    let quotient = tmpVar bld 64<rt>
    let y = regVar bld Register.Y
    divisor := AST.extract src1 32<rt> 0
    dividend := AST.concat (AST.extract y 32<rt> 0)
      (AST.extract src 32<rt> 0)
    let cond = (divisor == AST.num0 32<rt>)
    if (divisor = AST.num0 32<rt> || src1 = regVar bld Register.G0) then
      AST.sideEffect (Exception DivideError)
    elif (isRegOpr ins insLen bld) then
      AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblL1)
      AST.lmark lblL1
      if (dst <> regVar bld Register.G0) then
        quotient := dividend ./ (AST.zext 64<rt> divisor)
      else
        ()
      dst := AST.ite ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>)
        (AST.zext 64<rt> (AST.extract quotient 32<rt> 0))
        (numU64 0xFFFFFFFFUL 64<rt>)
      AST.jmp (AST.jmpDest lblEnd)
      AST.lmark lblL0
      AST.sideEffect (Exception DivideError)
      AST.lmark lblEnd
    else
      quotient := dividend ./ (AST.zext 64<rt> divisor)
      dst := AST.ite ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>)
        (AST.zext 64<rt> (AST.extract quotient 32<rt> 0))
        (numU64 0xFFFFFFFFUL 64<rt>)
  }

/// Unsigned 32-bit divide, setting the condition codes.
let udivcc ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let divisor = tmpVar bld 32<rt>
    let dividend = tmpVar bld 64<rt>
    let quotient = tmpVar bld 64<rt>
    let y = regVar bld Register.Y
    let ccr = regVar bld Register.CCR
    let struct (fits, saturated) = unsignedDivResult quotient
    divisor := AST.extract src1 32<rt> 0
    dividend := AST.concat (AST.extract y 32<rt> 0)
      (AST.extract src 32<rt> 0)
    let cond = (divisor == AST.num0 32<rt>)
    if (divisor = AST.num0 32<rt> || src1 = regVar bld Register.G0) then
      AST.sideEffect (Exception DivideError)
    elif (isRegOpr ins insLen bld) then
      AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblL1)
      AST.lmark lblL1
      if (dst <> regVar bld Register.G0) then
        quotient := dividend ./ (AST.zext 64<rt> divisor)
      else
        ()
      dst := saturated
      AST.extract ccr 1<rt> 1 := AST.ite fits (AST.b0) (AST.b1)
      AST.jmp (AST.jmpDest lblEnd)
      AST.lmark lblL0
      AST.sideEffect (Exception DivideError)
      AST.lmark lblEnd
    else
      quotient := dividend ./ (AST.zext 64<rt> divisor)
      dst := saturated
      AST.extract ccr 1<rt> 1 := AST.ite fits (AST.b0) (AST.b1)
    setDivCC bld ccr quotient
  }

let udivx ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let cond = (src1 == AST.num0 64<rt>)
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    if (src1 = AST.num0 64<rt> || src1 = regVar bld Register.G0) then
      AST.sideEffect (Exception DivideError)
    elif (isRegOpr ins insLen bld) then
      AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblL1)
      AST.lmark lblL1
      if (dst = regVar bld Register.G0) then
        append bld { dst := AST.num0 64<rt> }
      else
        append bld { dst := src ./ src1 }
      AST.jmp (AST.jmpDest lblEnd)
      AST.lmark lblL0
      AST.sideEffect (Exception DivideError)
      AST.lmark lblEnd
    else
      if (dst = regVar bld Register.G0) then
        append bld { dst := AST.num0 64<rt> }
      else
        append bld { dst := src ./ src1 }
  }

let umul ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let yreg = regVar bld Register.Y
    if (dst = regVar bld Register.G0) then
      dst := AST.num0 64<rt>
    else
      dst := (AST.zext 64<rt> (AST.extract src 32<rt> 0))
        .* (AST.zext 64<rt> (AST.extract src1 32<rt> 0))
      AST.extract yreg 64<rt> 0 :=
        AST.zext 64<rt> (AST.extract dst 32<rt> 32)
  }

let umulcc ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let yreg = regVar bld Register.Y
    let ccr = regVar bld Register.CCR
    let byte = tmpVar bld 8<rt>
    if (dst = regVar bld Register.G0) then
      dst := AST.num0 64<rt>
    else
      dst := (AST.zext 64<rt> (AST.extract src 32<rt> 0))
        .* (AST.zext 64<rt> (AST.extract src1 32<rt> 0))
      AST.extract yreg 64<rt> 0 :=
        AST.zext 64<rt> (AST.extract dst 32<rt> 32)
      byte := (getConditionCodeMul dst src src1)
      AST.extract ccr 8<rt> 0 := byte
  }

let wr ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, reg) = transThreeOprs ins insLen bld
    reg := src <+> src1
  }

let xor ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    let res = tmpVar bld oprSize
    res := src <+> src1
    if (dst = regVar bld Register.G0) then append bld { dst := AST.num0 64<rt> }
    else append bld { dst := res }
  }

let xorcc ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    let res = tmpVar bld oprSize
    let ccr = regVar bld Register.CCR
    let byte = tmpVar bld 8<rt>
    res := src <+> src1
    if (dst = regVar bld Register.G0) then append bld { dst := AST.num0 64<rt> }
    else append bld { dst := res }
    byte := (getConditionCodeLog res src src1)
    AST.extract ccr 8<rt> 0 := byte
  }

let xnor ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    let res = tmpVar bld oprSize
    res := src <+> AST.not (src1)
    if (dst = regVar bld Register.G0) then append bld { dst := AST.num0 64<rt> }
    else append bld { dst := res }
  }

let xnorcc ins insLen bld =
  lift bld ins insLen {
    let struct (src, src1, dst) = transThreeOprs ins insLen bld
    let oprSize = 64<rt>
    let res = tmpVar bld oprSize
    let ccr = regVar bld Register.CCR
    let byte = tmpVar bld 8<rt>
    res := src <+> AST.not (src1)
    if (dst = regVar bld Register.G0) then append bld { dst := AST.num0 64<rt> }
    else append bld { dst := res }
    byte := (getConditionCodeLog res src src1)
    AST.extract ccr 8<rt> 0 := byte
  }
