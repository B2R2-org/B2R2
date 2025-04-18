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

module internal B2R2.FrontEnd.AVR.Lifter

open B2R2.BinIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.AVR
open B2R2.FrontEnd.AVR.GeneralLifter

/// Translate IR.
let translate (ins: InsInfo) insLen (ctxt : TranslationContext)  =
  match ins.Opcode with
  | Opcode.ADC -> adc ins insLen ctxt
  | Opcode.ADD -> add ins insLen ctxt
  | Opcode.ADIW -> adiw ins insLen ctxt
  | Opcode.AND -> ``and`` ins insLen ctxt
  | Opcode.ANDI -> andi ins insLen ctxt
  | Opcode.ASR -> ``asr`` ins insLen ctxt
  | Opcode.BLD -> bld ins insLen ctxt
  | Opcode.BRCC| Opcode.BRCS| Opcode.BREQ| Opcode.BRGE| Opcode.BRHC| Opcode.BRHS
  | Opcode.BRID| Opcode.BRIE| Opcode.BRLT| Opcode.BRMI| Opcode.BRNE| Opcode.BRPL
  | Opcode.BRTC| Opcode.BRTS| Opcode.BRVC| Opcode.BRVS -> branch ins insLen ctxt
  | Opcode.BREAK -> sideEffects ins.Address insLen ProcessorID
  | Opcode.BST -> bst ins insLen ctxt
  | Opcode.CALL -> call ins insLen ctxt
  | Opcode.CBI| Opcode.IN | Opcode.OUT | Opcode.SBI | Opcode.SBIC | Opcode.SBIS
  | Opcode.ELPM | Opcode.SLEEP | Opcode.SPM ->
    sideEffects ins.Address insLen UnsupportedExtension
  | Opcode.CLC -> clc ins insLen ctxt
  | Opcode.CLH -> clh ins insLen ctxt
  | Opcode.CLI -> cli ins insLen ctxt
  | Opcode.CLN -> cln ins insLen ctxt
  | Opcode.CLR -> clr ins insLen ctxt
  | Opcode.CLS -> cls ins insLen ctxt
  | Opcode.CLT -> clt ins insLen ctxt
  | Opcode.CLV -> clv ins insLen ctxt
  | Opcode.CLZ -> clz ins insLen ctxt
  | Opcode.COM -> com ins insLen ctxt
  | Opcode.CP -> cp ins insLen ctxt
  | Opcode.CPC -> cpc ins insLen ctxt
  | Opcode.CPI -> cpi ins insLen ctxt
  | Opcode.CPSE -> cpse ins insLen ctxt
  | Opcode.DEC -> dec ins insLen ctxt
  | Opcode.DES -> des ins insLen ctxt
  | Opcode.EICALL -> eicall ins insLen
  | Opcode.EIJMP -> eijmp ins insLen
  | Opcode.EOR -> eor ins insLen ctxt
  | Opcode.FMUL -> fmul ins insLen ctxt
  | Opcode.FMULS -> fmuls ins insLen ctxt
  | Opcode.FMULSU -> fmulsu ins insLen ctxt
  | Opcode.ICALL -> icall ins insLen ctxt
  | Opcode.IJMP -> ijmp ins insLen ctxt
  | Opcode.INC -> inc ins insLen ctxt
  | Opcode.JMP -> jmp ins insLen ctxt
  | Opcode.LAC -> lac ins insLen ctxt
  | Opcode.LAS -> las ins insLen ctxt
  | Opcode.LAT -> lat ins insLen ctxt
  | Opcode.LD -> ld ins insLen ctxt
  | Opcode.LDD -> ldd ins insLen ctxt
  | Opcode.LDI -> ldi ins insLen ctxt
  | Opcode.LDS -> lds ins insLen ctxt
  | Opcode.LSR -> ``lsr`` ins insLen ctxt
  | Opcode.MOV -> mov ins insLen ctxt
  | Opcode.MOVW -> movw ins insLen ctxt
  | Opcode.MUL -> mul ins insLen ctxt
  | Opcode.MULS -> muls ins insLen ctxt
  | Opcode.MULSU -> mulsu ins insLen ctxt
  | Opcode.NOP -> nop ins.Address insLen
  | Opcode.OR | Opcode.ORI -> ``or`` ins insLen ctxt
  | Opcode.POP -> pop ins insLen ctxt
  | Opcode.PUSH -> push ins insLen ctxt
  | Opcode.RCALL -> rcall ins insLen ctxt
  | Opcode.RET | Opcode.RETI as opr -> ret ins.Address insLen opr ctxt
  | Opcode.RJMP -> rjmp ins insLen ctxt
  | Opcode.ROR -> ror ins insLen ctxt
  | Opcode.SBC | Opcode.SBCI -> sbc ins insLen ctxt
  | Opcode.SBIW -> sbiw ins insLen ctxt
  | Opcode.SEC | Opcode.SEH | Opcode.SEI | Opcode.SEN | Opcode.SES | Opcode.SET
  | Opcode.SEV | Opcode.SEZ -> sf ins insLen ctxt
  | Opcode.SUB | Opcode.SUBI -> sub ins insLen ctxt
  | Opcode.ST -> st ins insLen ctxt
  | Opcode.STD -> std ins insLen ctxt
  | Opcode.STS -> sts ins insLen ctxt
  | Opcode.SWAP -> swap ins insLen ctxt
  | Opcode.WDR -> sideEffects ins.Address insLen ClockCounter
  | Opcode.XCH -> xch ins insLen ctxt
  | Opcode.InvalidOp -> raise InvalidOpcodeException
  | o ->
  #if DEBUG
           eprintfn "%A" o
  #endif
           raise <| NotImplementedIRException (Disasm.opCodeToString o)
