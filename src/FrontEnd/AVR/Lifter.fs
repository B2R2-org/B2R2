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

open B2R2
open B2R2.BinIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.AVR
open B2R2.FrontEnd.AVR.GeneralLifter

/// Translate IR. The core is only read by the instructions that lay out a call
/// frame, avr6 holding three bytes of return address where the earlier cores
/// hold two; everything else is settled by the encoding alone.
let translate (core: AVRCore) pcMask (ins: Instruction) insLen builder =
  match ins.Opcode with
  | Opcode.ADC -> adc ins insLen builder
  | Opcode.ADD -> add ins insLen builder
  | Opcode.ADIW -> adiw ins insLen builder
  | Opcode.AND -> ``and`` ins insLen builder
  | Opcode.ANDI -> andi ins insLen builder
  | Opcode.ASR -> ``asr`` ins insLen builder
  | Opcode.BLD -> bld ins insLen builder
  | Opcode.BRCC| Opcode.BRCS| Opcode.BREQ| Opcode.BRGE| Opcode.BRHC| Opcode.BRHS
  | Opcode.BRID| Opcode.BRIE| Opcode.BRLT| Opcode.BRMI| Opcode.BRNE| Opcode.BRPL
  | Opcode.BRTC| Opcode.BRTS| Opcode.BRVC| Opcode.BRVS ->
    branch pcMask ins insLen builder
  (* A BREAK is what a debugger plants, so it stops the run rather than
     reporting anything about the processor. *)
  | Opcode.BREAK -> sideEffects ins.Address insLen Breakpoint builder
  | Opcode.BST -> bst ins insLen builder
  | Opcode.CALL -> call core ins insLen builder
  | Opcode.CBI -> cbi ins insLen builder
  | Opcode.IN -> ``in`` ins insLen builder
  | Opcode.OUT -> out ins insLen builder
  | Opcode.SBI -> sbi ins insLen builder
  | Opcode.SBIC -> sbic ins insLen builder
  | Opcode.SBIS -> sbis ins insLen builder
  | Opcode.SBRC -> sbrc ins insLen builder
  | Opcode.SBRS -> sbrs ins insLen builder
  | Opcode.LPM -> lpm ins insLen builder
  | Opcode.NEG -> neg ins insLen builder
  | Opcode.ELPM -> elpm ins insLen builder
  | Opcode.EICALL -> eicall core ins insLen builder
  | Opcode.EIJMP -> eijmp ins insLen builder
  (* Still to do: SPM writes program memory, and SLEEP needs a platform that can
     wake the guest again. Reporting them rather than letting them pass keeps a
     program that reaches one from running on silently. *)
  | Opcode.SPM | Opcode.SLEEP ->
    sideEffects ins.Address insLen UnsupportedInstruction builder
  | Opcode.CLC -> clc ins insLen builder
  | Opcode.CLH -> clh ins insLen builder
  | Opcode.CLI -> cli ins insLen builder
  | Opcode.CLN -> cln ins insLen builder
  | Opcode.CLR -> clr ins insLen builder
  | Opcode.CLS -> cls ins insLen builder
  | Opcode.CLT -> clt ins insLen builder
  | Opcode.CLV -> clv ins insLen builder
  | Opcode.CLZ -> clz ins insLen builder
  | Opcode.COM -> com ins insLen builder
  | Opcode.CP -> cp ins insLen builder
  | Opcode.CPC -> cpc ins insLen builder
  | Opcode.CPI -> cpi ins insLen builder
  | Opcode.CPSE -> cpse ins insLen builder
  | Opcode.DEC -> dec ins insLen builder
  | Opcode.DES -> des ins insLen builder
  | Opcode.EOR -> eor ins insLen builder
  | Opcode.FMUL -> fmul ins insLen builder
  | Opcode.FMULS -> fmuls ins insLen builder
  | Opcode.FMULSU -> fmulsu ins insLen builder
  | Opcode.ICALL -> icall core ins insLen builder
  | Opcode.IJMP -> ijmp ins insLen builder
  | Opcode.INC -> inc ins insLen builder
  | Opcode.JMP -> jmp ins insLen builder
  | Opcode.LAC -> lac ins insLen builder
  | Opcode.LAS -> las ins insLen builder
  | Opcode.LAT -> lat ins insLen builder
  | Opcode.LD -> ld ins insLen builder
  | Opcode.LDD -> ldd ins insLen builder
  | Opcode.LDI -> ldi ins insLen builder
  | Opcode.LDS -> lds ins insLen builder
  | Opcode.LSR -> ``lsr`` ins insLen builder
  | Opcode.MOV -> mov ins insLen builder
  | Opcode.MOVW -> movw ins insLen builder
  | Opcode.MUL -> mul ins insLen builder
  | Opcode.MULS -> muls ins insLen builder
  | Opcode.MULSU -> mulsu ins insLen builder
  | Opcode.NOP -> nop ins.Address insLen builder
  | Opcode.OR | Opcode.ORI -> ``or`` ins insLen builder
  | Opcode.POP -> pop ins insLen builder
  | Opcode.PUSH -> push ins insLen builder
  | Opcode.RCALL -> rcall core pcMask ins insLen builder
  | Opcode.RET | Opcode.RETI as opr ->
    ret core ins.Address insLen opr builder
  | Opcode.RJMP -> rjmp pcMask ins insLen builder
  | Opcode.ROR -> ror ins insLen builder
  | Opcode.SBC | Opcode.SBCI -> sbc ins insLen builder
  | Opcode.SBIW -> sbiw ins insLen builder
  | Opcode.SEC | Opcode.SEH | Opcode.SEI | Opcode.SEN | Opcode.SES | Opcode.SET
  | Opcode.SEV | Opcode.SEZ -> sf ins insLen builder
  | Opcode.SUB | Opcode.SUBI -> sub ins insLen builder
  | Opcode.ST -> st ins insLen builder
  | Opcode.STD -> std ins insLen builder
  | Opcode.STS -> sts ins insLen builder
  | Opcode.SWAP -> swap ins insLen builder
  (* A watchdog reset needs a watchdog to reset. Reporting it is what keeps a
     guest that relies on one from looking like it ran correctly. *)
  | Opcode.WDR ->
    sideEffects ins.Address insLen UnsupportedInstruction builder
  | Opcode.XCH -> xch ins insLen builder
  (* No parser produces this opcode: an undecodable encoding is reported as a
     parsing failure, so an instruction never carries it this far. *)
  | Opcode.InvalidOp -> B2R2.Terminator.impossible ()
  | o ->
  #if DEBUG
           eprintfn "%A" o
  #endif
           raise <| NotImplementedIRException(Disasm.opCodeToString o)
