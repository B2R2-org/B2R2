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

  let convertPrefix maps (pref: Prefix) (vex: VEXInfo option) =
    match vex with
    | Some v -> toPrefixType Mandatory v.VPrefixes
    | None ->
      let baseType =
        match maps with
        | Normal OneByte -> Legacy
        | _ -> Mandatory
      toPrefixType baseType pref

  let getOperandSize operands =
    Array.map (fun o ->
      match o with
      | RM sz | Reg sz | Mem sz | Imm sz | Rel sz -> Some sz
      | _ -> None) operands
    |> Array.distinct

  let checkPrefix pref insPref compat =
    match pref with
    | Mandatory NP -> true
    | Mandatory _ when compat = CompatLegMode.None -> pref = insPref
    | _ -> true

  let checkSize pref operands =
    let oprSz = getOperandSize operands
    match oprSz with
    | [| Some Sz16 |] | [| Some Sz16; _ |] | [| Some Sz16; _ |] ->
      pref = Legacy P66 || pref = Mandatory P66 // XXX: NP
    | _ -> true

  let checkCPUMode wordSize mode64 compat =
    match wordSize with
    | WordSize.Bit64 -> mode64 <> Mode64.NE && mode64 <> Mode64.NS // ??
    | WordSize.Bit32 -> compat <> CompatLegMode.NE
    | _ -> failwith "Unsupported word size."

  let isGroupOpcode = function
    | ModRMType.ModRMOp0 | ModRMType.ModRMOp1 | ModRMType.ModRMOp2
    | ModRMType.ModRMOp3 | ModRMType.ModRMOp4 | ModRMType.ModRMOp5
    | ModRMType.ModRMOp6 | ModRMType.ModRMOp7 -> true
    | _ -> false

  let checkGroupOpcode (span: ByteSpan) (phlp: ParsingHelper) modRMType =
    if isGroupOpcode modRMType then
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

  let findSubIndex span (phlp: ParsingHelper) (ins: InstructionCore[]) =
    let insLen = ins.Length
    if insLen = 0 then failwith "Error: Instruction core array is empty."
    elif insLen = 1 then 0
    else
      let pref = convertPrefix phlp.OpcodeClass phlp.Prefixes phlp.VEXInfo
      let mutable idx = -1
      let mutable i = 0
      while i < insLen && idx = -1 do
        let insCore = ins[i]
        let p = checkPrefix pref insCore.PrefixType insCore.Compat
        let s = checkSize pref insCore.Operands
        let c = checkCPUMode phlp.WordSize insCore.Mode64 insCore.Compat
        let r = checkREXPrefix phlp.REXPrefix insCore.REXPrefixType
        let v = checkVectorLength phlp.VEXInfo insCore.VectorLength
        let g = checkGroupOpcode span phlp insCore.ModRM
#if DEBUG
        printfn "Checking %d: p=%b, s=%b, r=%b, v=%b, g=%b" i p s r v g
#endif
        if p && c && s && r && v && g then idx <- i
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
    | OprSize.Sz128 -> 128<rt>
    | OprSize.Sz256 -> 256<rt>
    | OprSize.Sz512 -> 512<rt>

  let parseOperand span (phlp: ParsingHelper) modRM (opEn: OpEn) i = function
    | RM sz ->
      let sz = oprSzToRegType sz
      // FIXME: need operand size determination logic
      phlp.MemEffOprSize <- sz
      phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
      phlp.MemEffRegSize <- sz
      phlp.RegSize <- sz
      phlp.OperationSize <- sz
      OperandParsers.parseMemOrReg modRM span phlp
    | Reg sz ->
      match opEn with
      | OpEn.RVM when i = 1 -> OperandParsers.parseVVVVReg phlp
      | _ ->
        OperandParsers.findRegRBits (oprSzToRegType sz) phlp.REXPrefix
          (Operands.getReg modRM)
        |> OprReg
    | Imm sz ->
      OperandParsers.parseOprImm span phlp (oprSzToRegType sz)
    | Rel sz ->
      OperandParsers.parseOprForRelJmp span phlp (oprSzToRegType sz)
    | Unknown s -> // FIXME: need unknown operand type handling logic
      match s with
      | "M" ->
        // FIXME: need operand size determination logic
        let effAddrSz = ParsingHelper.GetEffAddrSize phlp
        let effOprSz = ParsingHelper.GetEffOprSize(phlp, SzCond.Normal)
        phlp.MemEffOprSize <- effOprSz
        phlp.MemEffAddrSize <- effAddrSz
        phlp.MemEffRegSize <- effOprSz
        phlp.RegSize <- effOprSz
        phlp.OperationSize <- effOprSz
        OperandParsers.parseMemory modRM span (phlp: ParsingHelper)
      | _ -> failwithf "Unsupported operand type: %s" s
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
      | ModRMType.NoModRM -> 0uy
      | _ -> phlp.ReadByte span

    match ic.Operands with
    | [| NoOpr |] -> Operands.NoOperand
    | _ ->
      let operands = Array.zeroCreate ic.Operands.Length
      for i = 0 to ic.Operands.Length - 1 do
        let opr = ic.Operands[i]
        operands[i] <- parseOperand span phlp modRM ic.OpEn i opr
      operands |> arrayToOperands

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
      let nextPos = this.ParseREX(span, prefEndPos, &rex)
      let rexEndPos = this.ParseREX(span, prefEndPos, &rex)
      let nextPos = this.ParseVEX(span, rexEndPos, &rex, &vex)
      phlp.VEXInfo <- None
      phlp.IsFar <- false
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
            InstructionArrays.norTwo[int (phlp.ReadByte span)]
          | _ ->
            InstructionArrays.norOne[int (phlp.ReadByte span)]
      let subIdx = findSubIndex span phlp insCores
#if DEBUG
      printfn "InstructionCore: %A\nOpcode Class: %A"
        insCores[subIdx] phlp.OpcodeClass
#endif
      let operands = parseOperands span phlp insCores[subIdx]
      newInstruction phlp insCores[subIdx].Opcode operands :> IInstruction