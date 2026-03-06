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

namespace B2R2.FrontEnd.Intel

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Intel
open B2R2.FrontEnd.Intel.ParsingFunctions
open LanguagePrimitives

/// Represents a parser for Intel (x86 or x86-64) instructions.
type IntelParser(wordSz, reader) =
  /// Split a byte value into two fileds (high 3 bits; low 5 bits), and
  /// categorize prefix values into 8 groups based on the high 3 bits (= 2^3).
  /// The below array is a collection of bitmaps that maps the low 5-bit value
  /// to a bit value indicating whether the given byte value is a prefix value
  /// or not.
  let prefixCheck =
    [| 0x0u        (* 000xxxxx = cannot be a prefix value *)
       0x40404040u (* 001xxxxx = 26/2e/36/3e is possible *)
       0x0u        (* 010xxxxx = cannot be a prefix value *)
       0x000000f0u (* 011xxxxx = 64/65/66/67 is possible *)
       0x0u
       0x0u
       0x0u
       0x000d0000u (* 111xxxxx = f0/f2/f3 is possible *) |]

  let mutable disasm = Disasm.Delegate Disasm.IntelSyntax.disasm

  let lifter =
    { new ILiftable with
        member _.Lift(ins, builder) = Lifter.translate ins ins.Length builder
        member _.Disasm(ins, builder) = disasm.Invoke(builder, ins); builder }

  let phlp = ParsingHelper(reader, wordSz, lifter)

  let checkVectorLength (vex: VEXInfo option) insVecLen =
    if insVecLen = VectorLength.None then true
    else
      match vex with
      | Some v ->
        match v.VectorLength with
        | 128<rt> -> insVecLen = VectorLength.V128
        | 256<rt> -> insVecLen = VectorLength.V256
        | 512<rt> -> insVecLen = VectorLength.V512
        | _ -> false
      | _ -> true

  let checkREXPrefix (rex: REXPrefix) insREX =
    match rex with
    | REXPrefix.NOREX ->
      (insREX = REXPrefixType.WIG) || (insREX = REXPrefixType.W0) ||
      (insREX = REXPrefixType.NOREX)
    | r when (r &&& REXPrefix.REXW) = REXPrefix.REXW ->
      (insREX = REXPrefixType.WIG) || (insREX = REXPrefixType.W1) ||
      (insREX = REXPrefixType.REXW)
    //| r when (r &&& REXPrefix.REX) = REXPrefix.REX ->
    //  (insREX = REXPrefixType.WIG) || (insREX = REXPrefixType.W0) ||
    //  (insREX = REXPrefixType.REX)
    | _ -> true

  let toPrefixType preType pref =
    if (pref &&& Prefix.OPSIZE) <> Prefix.None then preType P66
    elif (pref &&& Prefix.REPZ) <> Prefix.None then preType F3
    elif (pref &&& Prefix.REPNZ) <> Prefix.None then preType F2
    else preType NP

  let convertPrefix maps (pref: Prefix) (vex: VEXInfo option) opByte =
    match vex with
    | Some v -> toPrefixType Mandatory v.VPrefixes
    | None ->
      let baseType =
        match maps with
        | Normal OneByte -> Legacy
        | Normal TwoBytes when opByte = 0x1Fuy (* NOP *) -> Legacy
        | _ -> Mandatory // FIXME: Two-byte opcodes(0x0F) are not always
                         // mandatory. Need more precise handling logic.
      toPrefixType baseType pref

  let getOperandSize operands =
    Array.map (fun o ->
      match o with
      | RM sz | Reg sz | Mem sz | Imm sz | Rel sz -> Some sz
      | _ -> None) operands
    |> Array.distinct

  let checkPrefix pref insPref =
    match pref with
    | Mandatory NP -> insPref = Mandatory NP || insPref = Legacy NP
    | Mandatory _ ->
      if insPref = Legacy NP then false
      else pref = insPref
    | _ -> true

  let containsSz16 oprSz =
    match oprSz with
    | [| Some Sz16 |]
    | [| Some Sz16; _ |]
    | [| None; Some Sz16 |] (* Temp *) -> true
    | _ -> false

  let checkSize pref operands opEn =
    if opEn = OpEn.None then true
    else
      let oprSz = getOperandSize operands
      if containsSz16 oprSz then
        // FIXME: 16-bit operands do not always require a 66h prefix.
        pref = Legacy P66 || pref = Mandatory P66
      else true

  let checkCPUMode wordSize mode64 compat =
    match wordSize with
    | WordSize.Bit64 -> mode64 <> Mode64.NE && mode64 <> Mode64.NS // ??
    | WordSize.Bit32 -> compat <> CompatLegMode.NE
    | _ -> failwith "Unsupported word size."

  let isOpcodeExtensions = function
    | ModRMType.ModRMOp0 | ModRMType.ModRMOp1 | ModRMType.ModRMOp2
    | ModRMType.ModRMOp3 | ModRMType.ModRMOp4 | ModRMType.ModRMOp5
    | ModRMType.ModRMOp6 | ModRMType.ModRMOp7 -> true
    | _ -> false

  let checkOpcodeExtensions (span: ByteSpan) (phlp: ParsingHelper) modRMType =
    if isOpcodeExtensions modRMType then
      let modRM = span[phlp.CurrPos]
      let reg = (modRM >>> 3) &&& 0b111uy
      match reg with
      | 0uy -> modRMType = ModRMType.ModRMOp0
      | 1uy -> modRMType = ModRMType.ModRMOp1
      | 2uy -> modRMType = ModRMType.ModRMOp2
      | 3uy -> modRMType = ModRMType.ModRMOp3
      | 4uy -> modRMType = ModRMType.ModRMOp4
      | 5uy -> modRMType = ModRMType.ModRMOp5
      | 6uy -> modRMType = ModRMType.ModRMOp6
      | 7uy -> modRMType = ModRMType.ModRMOp7
      | _ -> false
    else true

  let checkD8Escape span phlp (i: InstructionCore) modRM =
    if Operands.getMod modRM = 0b11 then
      if i.ModRM = ModRMType.NoModRM then
        match modRM &&& 0xF8uy with
        | 0xC0uy -> i.Opcode = Opcode.FADD
        | 0xC8uy -> i.Opcode = Opcode.FMUL
        | 0xD0uy -> i.Opcode = Opcode.FCOM
        | 0xD8uy -> i.Opcode = Opcode.FCOMP
        | 0xE0uy -> i.Opcode = Opcode.FSUB
        | 0xE8uy -> i.Opcode = Opcode.FSUBR
        | 0xF0uy -> i.Opcode = Opcode.FDIV
        | 0xF8uy -> i.Opcode = Opcode.FDIVR
        | _ -> false
      else false
    else
      if i.ModRM = ModRMType.NoModRM then false
      else checkOpcodeExtensions span phlp i.ModRM

  let checkD9Escape span phlp (i: InstructionCore) modRM =
    if Operands.getMod modRM = 0b11 then
      if i.ModRM = ModRMType.NoModRM then
        match modRM with
        | 0xC0uy | 0xC1uy | 0xC2uy | 0xC3uy | 0xC4uy | 0xC5uy | 0xC6uy
        | 0xC7uy -> i.Opcode = Opcode.FLD
        | 0xC8uy | 0xC9uy | 0xCAuy | 0xCBuy | 0xCCuy | 0xCDuy | 0xCEuy
        | 0xD0uy -> i.Opcode = Opcode.FNOP
        | 0xD1uy | 0xD2uy | 0xD3uy | 0xD4uy | 0xD5uy | 0xD6uy | 0xD7uy | 0xD8uy
        | 0xD9uy | 0xDAuy | 0xDBuy | 0xDCuy | 0xDDuy | 0xDEuy | 0xDFuy -> false
        | 0xE0uy -> i.Opcode = Opcode.FCHS
        | 0xE1uy -> i.Opcode = Opcode.FABS
        | 0xE2uy | 0xE3uy -> false
        | 0xE4uy -> i.Opcode = Opcode.FTST
        | 0xE5uy -> i.Opcode = Opcode.FXAM
        | 0xE6uy | 0xE7uy -> false
        | 0xE8uy -> i.Opcode = Opcode.FLD1
        | 0xE9uy -> i.Opcode = Opcode.FLDL2T
        | 0xEAuy -> i.Opcode = Opcode.FLDL2E
        | 0xEBuy -> i.Opcode = Opcode.FLDPI
        | 0xECuy -> i.Opcode = Opcode.FLDLG2
        | 0xEDuy -> i.Opcode = Opcode.FLDLN2
        | 0xEEuy -> i.Opcode = Opcode.FLDZ
        | 0xEFuy -> false
        | 0xF0uy -> i.Opcode = Opcode.F2XM1
        | 0xF1uy -> i.Opcode = Opcode.FYL2X
        | 0xF2uy -> i.Opcode = Opcode.FPTAN
        | 0xF3uy -> i.Opcode = Opcode.FPATAN
        | 0xF4uy -> i.Opcode = Opcode.FXTRACT
        | 0xF5uy -> i.Opcode = Opcode.FPREM1
        | 0xF6uy -> i.Opcode = Opcode.FDECSTP
        | 0xF7uy -> i.Opcode = Opcode.FINCSTP
        | 0xF8uy -> i.Opcode = Opcode.FPREM
        | 0xF9uy -> i.Opcode = Opcode.FYL2XP1
        | 0xFAuy -> i.Opcode = Opcode.FSQRT
        | 0xFBuy -> i.Opcode = Opcode.FSINCOS
        | 0xFCuy -> i.Opcode = Opcode.FRNDINT
        | 0xFDuy -> i.Opcode = Opcode.FSCALE
        | 0xFEuy -> i.Opcode = Opcode.FSIN
        | 0xFFuy -> i.Opcode = Opcode.FCOS
        | _ -> false
      else false
    else
      if i.ModRM = ModRMType.NoModRM then false
      else checkOpcodeExtensions span phlp i.ModRM

  let checkDBEscape span phlp (i: InstructionCore) modRM =
    if Operands.getMod modRM = 0b11 then
      if i.ModRM = ModRMType.NoModRM then
        match modRM &&& 0xF8uy with
        | 0xC0uy -> i.Opcode = Opcode.FCMOVNB
        | 0xC8uy -> i.Opcode = Opcode.FCMOVNE
        | 0xD0uy -> i.Opcode = Opcode.FCMOVNBE
        | 0xD8uy -> i.Opcode = Opcode.FCMOVNU
        | 0xE0uy ->
          match modRM with
          | 0xE2uy -> i.Opcode = Opcode.FCLEX
          | 0xE3uy -> i.Opcode = Opcode.FINIT
          | _ -> false
        | 0xE8uy -> i.Opcode = Opcode.FUCOMI
        | 0xF0uy -> i.Opcode = Opcode.FCOMI
        | 0xF8uy -> false
        | _ -> false
      else false
    else
      if i.ModRM = ModRMType.NoModRM then false
      else checkOpcodeExtensions span phlp i.ModRM

  let checkDCEscape span phlp (i: InstructionCore) modRM =
    if Operands.getMod modRM = 0b11 then
      if i.ModRM = ModRMType.NoModRM then
        match modRM &&& 0xF8uy with
        | 0xC0uy -> i.Opcode = Opcode.FADD
        | 0xC8uy -> i.Opcode = Opcode.FMUL
        | 0xD0uy | 0xD8uy -> false
        | 0xE0uy -> i.Opcode = Opcode.FSUBR
        | 0xE8uy -> i.Opcode = Opcode.FSUB
        | 0xF0uy -> i.Opcode = Opcode.FDIVR
        | 0xF8uy -> i.Opcode = Opcode.FDIV
        | _ -> false
      else false
    else
      if i.ModRM = ModRMType.NoModRM then false
      else checkOpcodeExtensions span phlp i.ModRM

  let checkDDEscape span phlp (i: InstructionCore) modRM =
    if Operands.getMod modRM = 0b11 then
      if i.ModRM = ModRMType.NoModRM then
        match modRM &&& 0xF8uy with
        | 0xC0uy -> i.Opcode = Opcode.FFREE
        | 0xC8uy -> false
        | 0xD0uy -> i.Opcode = Opcode.FST
        | 0xD8uy -> i.Opcode = Opcode.FSTP
        | 0xE0uy -> i.Opcode = Opcode.FUCOM
        | 0xE8uy -> i.Opcode = Opcode.FUCOMP
        | 0xF0uy | 0xF8uy -> false
        | _ -> false
      else false
    else
      if i.ModRM = ModRMType.NoModRM then false
      else checkOpcodeExtensions span phlp i.ModRM

  let checkDEEscape span phlp (i: InstructionCore) modRM =
    if Operands.getMod modRM = 0b11 then
      if i.ModRM = ModRMType.NoModRM then
        match modRM &&& 0xF8uy with
        | 0xC0uy -> i.Opcode = Opcode.FADDP && i.ModRM = ModRMType.NoModRM
        | 0xC8uy -> i.Opcode = Opcode.FMULP && i.ModRM = ModRMType.NoModRM
        | 0xD0uy -> false
        | 0xD8uy ->
          match modRM with
          | 0xD9uy -> i.Opcode = Opcode.FCOMPP && i.ModRM = ModRMType.NoModRM
          | _ -> false
        | 0xE0uy -> i.Opcode = Opcode.FSUBRP && i.ModRM = ModRMType.NoModRM
        | 0xE8uy -> i.Opcode = Opcode.FSUBP && i.ModRM = ModRMType.NoModRM
        | 0xF0uy -> i.Opcode = Opcode.FDIVRP && i.ModRM = ModRMType.NoModRM
        | 0xF8uy -> i.Opcode = Opcode.FDIVP && i.ModRM = ModRMType.NoModRM
        | _ -> false
      else false
    else
      if i.ModRM = ModRMType.NoModRM then false
      else checkOpcodeExtensions span phlp i.ModRM

  let checkDFEscape span phlp (i: InstructionCore) modRM =
    if Operands.getMod modRM = 0b11 then
      if i.ModRM = ModRMType.NoModRM then
        match modRM &&& 0xF8uy with
        | 0xC0uy | 0xC8uy | 0xD0uy | 0xD8uy -> false
        | 0xE0uy ->
          match modRM with
          | 0xE0uy -> i.Opcode = Opcode.FSTSW && i.ModRM = ModRMType.NoModRM
          | _ -> false
        | 0xE8uy -> i.Opcode = Opcode.FUCOMIP && i.ModRM = ModRMType.NoModRM
        | 0xF0uy -> i.Opcode = Opcode.FCOMIP && i.ModRM = ModRMType.NoModRM
        | 0xF8uy -> false
        | _ -> false
      else false
    else
      if i.ModRM = ModRMType.NoModRM then false
      else checkOpcodeExtensions span phlp i.ModRM

  let checkEscape (span: ByteSpan) (phlp: ParsingHelper) (i: InstructionCore) =
    match i.OpEn with
    | OpEn.None ->
      let modRM = span[phlp.CurrPos]
      match i.OpcodeByte with
      | 0xD8u -> checkD8Escape span phlp i modRM
      | 0xD9u -> checkD9Escape span phlp i modRM
      | 0xDBu -> checkDBEscape span phlp i modRM
      | 0xDCu -> checkDCEscape span phlp i modRM
      | 0xDDu -> checkDDEscape span phlp i modRM
      | 0xDEu -> checkDEEscape span phlp i modRM
      | 0xDFu -> checkDFEscape span phlp i modRM
      | _ -> false
    | _ -> true

  let findSubIndex (span: ByteSpan) (phlp: ParsingHelper)
    (ins: InstructionCore[]) =
    let insLen = ins.Length
    if insLen = 0 then failwith "Error: Instruction core array is empty."
    elif insLen = 1 then 0
    else
      let opcodeByte = span[phlp.CurrPos - 1]
      let pref =
        convertPrefix phlp.OpcodeClass phlp.Prefixes phlp.VEXInfo opcodeByte
      let mutable idx = -1
      let mutable i = 0
      while i < insLen && idx = -1 do
        let insCore = ins[i]
        let p = checkPrefix pref insCore.PrefixType
        let s = checkSize pref insCore.Operands insCore.OpEn
        let c = checkCPUMode phlp.WordSize insCore.Mode64 insCore.Compat
        let r = checkREXPrefix phlp.REXPrefix insCore.REXPrefixType
        let v = checkVectorLength phlp.VEXInfo insCore.VectorLength
        let e = checkEscape span phlp insCore
        let x = checkOpcodeExtensions span phlp insCore.ModRM
#if DEBUG
        printfn "Checking %d: p=%b, s=%b, r=%b, v=%b, e=%b, x=%b" i p s r v e x
#endif
        if p && c && s && r && v && e && x then
#if DEBUG
          printfn "[Success] maps: %A, pref: %A, rex: %A, vex: %A\nIdx:%d\n%A"
            phlp.OpcodeClass pref phlp.REXPrefix phlp.VEXInfo i insCore
#endif
          idx <- i
        else ()
        i <- i + 1
      if idx = -1 then
#if DEBUG
        printfn "Fail: find sub index\n maps: %A, pref: %A, rex: %A, vex: %A"
          phlp.OpcodeClass pref phlp.REXPrefix phlp.VEXInfo
        Array.iter (printfn " %A") ins
#endif
        failwithf "No matching instruction format."
      else ()
      idx

  let oprSzToRegType = function
    | OprSize.Sz8 -> 8<rt>
    | OprSize.Sz16 -> 16<rt>
    | OprSize.Sz32 -> 32<rt>
    | OprSize.Sz64 -> 64<rt>
    | OprSize.Sz80 -> 80<rt>
    | OprSize.Sz128 -> 128<rt>
    | OprSize.Sz256 -> 256<rt>
    | OprSize.Sz512 -> 512<rt>
    | OprSize.SzUnknown -> 0<rt>

  let getImmSz = function
    | [| Some Sz8; None |] -> 8<rt>
    | [| Some Sz16; None |] -> 16<rt>
    | [| Some Sz32; None |] -> 32<rt>
    | [| Some Sz64; None |] -> 64<rt>
    | _ -> 0<rt> // Temp

  let parseOperand span (phlp: ParsingHelper) sz modRM (ic: InstructionCore) i =
    function
    | RM sz ->
      let sz = oprSzToRegType sz
      // FIXME: need operand size determination logic
      phlp.MemEffOprSize <- sz
      phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
      phlp.MemEffRegSize <- sz
      phlp.RegSize <- sz
      phlp.OperationSize <- sz
      OperandParsers.parseMemOrReg modRM span phlp
    | RMdiff(regSz, memSz) ->
      let regSz = oprSzToRegType regSz
      let memSz = oprSzToRegType memSz
      // FIXME: need operand size determination logic
      phlp.MemEffOprSize <- memSz
      phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
      phlp.MemEffRegSize <- memSz
      phlp.RegSize <- regSz
      phlp.OperationSize <- memSz
      OperandParsers.parseMemOrReg modRM span phlp
    | Reg sz when ic.OpEn = OpEn.O || ic.OpEn = OpEn.OI ->
      // Opcode[2:0] contains the operand.
      let regBit = Operands.getRM (uint8 ic.OpcodeByte)
      OperandParsers.findRegRBits (oprSzToRegType sz) phlp.REXPrefix regBit
      |> OprReg
    | Reg sz ->
      match ic.OpEn with
      | OpEn.RVM when i = 1 -> OperandParsers.parseVVVVReg phlp
      | _ ->
        OperandParsers.findRegRBits (oprSzToRegType sz) phlp.REXPrefix
          (Operands.getReg modRM)
        |> OprReg
    | Mem SzUnknown ->
      // FIXME: need operand size determination logic
      let effAddrSz = ParsingHelper.GetEffAddrSize phlp
      let effOprSz = ParsingHelper.GetEffOprSize(phlp, SzCond.Normal)
      phlp.MemEffOprSize <- effOprSz
      phlp.MemEffAddrSize <- effAddrSz
      phlp.MemEffRegSize <- effOprSz
      phlp.RegSize <- effOprSz
      phlp.OperationSize <- effOprSz
      OperandParsers.parseMemory modRM span (phlp: ParsingHelper)
    | Mem sz ->
      // FIXME: need operand size determination logic
      let sz = oprSzToRegType sz
      phlp.MemEffOprSize <- sz
      phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
      phlp.MemEffRegSize <- sz
      phlp.RegSize <- sz
      phlp.OperationSize <- sz
      OperandParsers.parseMemory modRM span phlp
    | Imm sz ->
      OperandParsers.parseOprImm span phlp (oprSzToRegType sz)
    | Rel sz ->
      OperandParsers.parseOprForRelJmp span phlp (oprSzToRegType sz)
    | FixedReg(reg, _) -> OprReg reg
    | STReg None -> Operands.getRM modRM |> Operands.getSTReg
    | STReg(Some reg) -> OprReg reg
    | BM sz ->
      if Operands.modIsReg modRM then
        OperandParsers.parseBoundRegister (Operands.getRM modRM)
      else
        let sz = oprSzToRegType sz
        phlp.MemEffOprSize <- sz
        phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
        phlp.MemEffRegSize <- sz
        phlp.RegSize <- sz
        phlp.OperationSize <- sz
        OperandParsers.parseMemory modRM span phlp
    | BndReg -> OperandParsers.parseBoundRegister (Operands.getReg modRM)
    | MMXReg -> OperandParsers.parseMMXReg (Operands.getReg modRM)
    | FixedImm imm -> OprImm(int64 imm, getImmSz sz)
    | Unknown s ->
      failwithf "Need unknown operand type handling logic: %s" s
    | o ->
      failwithf "Unsupported operand type: %A" o

  let arrayToOperands = function
    | [||] -> Operands.NoOperand
    | [| op1 |] -> Operands.OneOperand(op1)
    | [| op1; op2 |] -> Operands.TwoOperands(op1, op2)
    | [| op1; op2; op3 |] -> Operands.ThreeOperands(op1, op2, op3)
    | [| op1; op2; op3; op4 |] -> Operands.FourOperands(op1, op2, op3, op4)
    | _ -> failwith "Invalid number of operands."

  let parseOperands span (phlp: ParsingHelper) (ic: InstructionCore) =
    let modRM =
      match ic.ModRM with
      | ModRMType.NoModRM when ic.OpEn = OpEn.M ->
        phlp.ReadByte span (* SETcc *)
      | ModRMType.NoModRM when ic.OpEn = OpEn.None ->
        phlp.ReadByte span (* Escape Opcode *)
      | ModRMType.NoModRM -> 0uy
      | _ -> phlp.ReadByte span
    match ic.Operands with
    | [| NoOpr |] -> Operands.NoOperand
    | _ ->
      let operands = Array.zeroCreate ic.Operands.Length
      let sz = getOperandSize ic.Operands
      for i = 0 to ic.Operands.Length - 1 do
        let opr = ic.Operands[i]
        operands[i] <- parseOperand span phlp sz modRM ic i opr
      operands |> arrayToOperands

  let handleOneByteOpcodeExtension opcodeByte =
    match opcodeByte with
    (* MOV *)
    | 0xB9uy | 0xBAuy | 0xBBuy | 0xBCuy | 0xBDuy | 0xBEuy | 0xBFuy ->
      InstructionArrays.norOne[0xB8]
    (* PUSH *)
    | 0x51uy | 0x52uy | 0x53uy | 0x54uy | 0x55uy | 0x56uy | 0x57uy
    | 0x58uy | 0x59uy | 0x5Auy | 0x5Buy | 0x5Cuy | 0x5Duy | 0x5Euy | 0x5Fuy ->
      InstructionArrays.norOne[0x50]
    | _ -> InstructionArrays.norOne[int opcodeByte]

  let handleTwoByteOpcodeExtension opcodeByte =
    match opcodeByte with
    (* BSWAP *)
    | 0xC9uy | 0xCAuy | 0xCBuy | 0xCCuy | 0xCDuy | 0xCEuy | 0xCFuy ->
      InstructionArrays.norTwo[0xC8]
    | _ -> InstructionArrays.norTwo[int opcodeByte]

  member _.SetDisassemblySyntax syntax =
    match syntax with
    | DefaultSyntax -> disasm <- Disasm.Delegate Disasm.IntelSyntax.disasm
    | ATTSyntax -> disasm <- Disasm.Delegate Disasm.ATTSyntax.disasm

  member inline private _.ParsePrefix(span: ByteSpan) =
    let mutable pos = 0
    let mutable pref = Prefix.None
    let mutable b = span[0]
    while ((prefixCheck[(int b >>> 5)] >>> (int b &&& 0b11111)) &&& 1u) > 0u do
      match b with
      | 0xF0uy -> pref <- Prefix.LOCK ||| (Prefix.ClearGrp1PrefMask &&& pref)
      | 0xF2uy -> pref <- Prefix.REPNZ ||| (Prefix.ClearGrp1PrefMask &&& pref)
      | 0xF3uy -> pref <- Prefix.REPZ ||| (Prefix.ClearGrp1PrefMask &&& pref)
      | 0x2Euy -> pref <- Prefix.CS ||| (Prefix.ClearSegMask &&& pref)
      | 0x36uy -> pref <- Prefix.SS ||| (Prefix.ClearSegMask &&& pref)
      | 0x3Euy -> pref <- Prefix.DS ||| (Prefix.ClearSegMask &&& pref)
      | 0x26uy -> pref <- Prefix.ES ||| (Prefix.ClearSegMask &&& pref)
      | 0x64uy -> pref <- Prefix.FS ||| (Prefix.ClearSegMask &&& pref)
      | 0x65uy -> pref <- Prefix.GS ||| (Prefix.ClearSegMask &&& pref)
      | 0x66uy -> pref <- Prefix.OPSIZE ||| pref
      | 0x67uy -> pref <- Prefix.ADDRSIZE ||| pref
      | _ -> pos <- pos - 1
      pos <- pos + 1
      b <- span[pos]
    phlp.Prefixes <- pref
    pos

  member inline private _.ParseREX(bs: ByteSpan, pos, rex: REXPrefix byref) =
    if wordSz = WordSize.Bit32 then pos
    else
      let rb = bs[pos] |> int
      if rb &&& 0b11110000 = 0b01000000 then
        rex <- EnumOfValue rb
        pos + 1
      else pos

  member inline private _.ParseVEX(bs: ByteSpan, pos, rex: REXPrefix byref,
    vex: VEXInfo option byref) =
    match bs[pos] with
    | 0xC5uy ->
      vex <- Some(getTwoVEXInfo bs &rex (pos + 1))
      pos + 2
    | 0xC4uy ->
      vex <- Some(getThreeVEXInfo bs &rex (pos + 1))
      pos + 3
    | 0x62uy ->
      vex <- Some(getEVEXInfo bs &rex (pos + 1))
      pos + 4
    | 0x0Fuy ->
      match bs[pos + 1] with
      | 0x38uy ->
        phlp.OpcodeClass <- Normal ThreeBytes38
        pos + 2
      | 0x3Auy ->
        phlp.OpcodeClass <- Normal ThreeBytes3A
        pos + 2
      | _ ->
        phlp.OpcodeClass <- Normal TwoBytes
        pos + 1
    | _ ->
      phlp.OpcodeClass <- Normal OneByte
      pos

  interface IInstructionParsable with
    member _.MaxInstructionSize = 15

    member this.Parse(bs: byte[], addr) =
      (this :> IInstructionParsable).Parse(ReadOnlySpan bs, addr)

    member this.Parse(span: ByteSpan, addr) =
      let mutable rex = REXPrefix.NOREX
      let mutable vex = None
      let prefEndPos = this.ParsePrefix span
      let rexEndPos = this.ParseREX(span, prefEndPos, &rex)
      let nextPos = this.ParseVEX(span, rexEndPos, &rex, &vex)
      phlp.InsAddr <- addr
      phlp.REXPrefix <- rex
      phlp.VEXInfo <- vex
      phlp.CurrPos <- nextPos
#if LCACHE
      phlp.MarkPrefixEnd(prefEndPos)
#endif
      //oneByteParsers[int (phlp.ReadByte span)].Run(span, phlp) :> IInstruction
      let insCores =
        match phlp.VEXInfo with
        | Some vInfo ->
          match vInfo.VEXType with
          | v when v &&& VEXType.EVEX = VEXType.EVEX ->
            match vInfo.VEXType &&& (~~~VEXType.EVEX) with
            | VEXType.TwoByteOp ->
              phlp.OpcodeClass <- EVEX TwoBytes
              InstructionArrays.evexTwo[int (phlp.ReadByte span)]
            | VEXType.ThreeByteOpOne ->
              phlp.OpcodeClass <- EVEX ThreeBytes38
              InstructionArrays.evexThree38[int (phlp.ReadByte span)]
            | VEXType.ThreeByteOpTwo ->
              phlp.OpcodeClass <- EVEX ThreeBytes3A
              InstructionArrays.evexThree3A[int (phlp.ReadByte span)]
            | _ -> raise ParsingFailureException
          | VEXType.TwoByteOp ->
            phlp.OpcodeClass <- VEX TwoBytes
            InstructionArrays.vexTwo[int (phlp.ReadByte span)]
          | VEXType.ThreeByteOpOne ->
            phlp.OpcodeClass <- VEX ThreeBytes38
            InstructionArrays.vexThree38[int (phlp.ReadByte span)]
          | VEXType.ThreeByteOpTwo ->
            phlp.OpcodeClass <- VEX ThreeBytes3A
            InstructionArrays.vexThree3A[int (phlp.ReadByte span)]
          | _ -> raise ParsingFailureException
        | None ->
          match phlp.OpcodeClass with
          | Normal ThreeBytes38 ->
            InstructionArrays.norThree38[int (phlp.ReadByte span)]
          | Normal ThreeBytes3A ->
            InstructionArrays.norThree3A[int (phlp.ReadByte span)]
          | Normal TwoBytes ->
            handleTwoByteOpcodeExtension (phlp.ReadByte span)
          | _ -> handleOneByteOpcodeExtension (phlp.ReadByte span)
      let subIdx = findSubIndex span phlp insCores
#if DEBUG
      //printfn "\nSelected InstructionCore(%d)\n%A\nOpcode Class: %A"
      //  subIdx insCores[subIdx] phlp.OpcodeClass
#endif
      let subIdx =
        match insCores[subIdx].Opcode with
        | Opcode.ENDBR32 ->
          match phlp.ReadByte(span) with
          | 0xFAuy when insCores[subIdx + 1].Opcode = Opcode.ENDBR64 ->
            subIdx + 1
          | 0xFBuy -> subIdx
          | _ -> raise ParsingFailureException
        | _ -> subIdx
      let operands = parseOperands span phlp insCores[subIdx]
      newInstruction phlp insCores[subIdx].Opcode operands :> IInstruction