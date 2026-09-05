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
let translate (core: AVRCore) pcMask (ins: Instruction) builder =
  match ins.Opcode with
  | Opcode.ADC ->
    adc ins builder
  | Opcode.ADD ->
    add ins builder
  | Opcode.ADIW ->
    adiw ins builder
  | Opcode.AND ->
    ``and`` ins builder
  | Opcode.ANDI ->
    andi ins builder
  | Opcode.ASR ->
    ``asr`` ins builder
  | Opcode.BLD ->
    bld ins builder
  | Opcode.BRCC| Opcode.BRCS| Opcode.BREQ| Opcode.BRGE| Opcode.BRHC| Opcode.BRHS
  | Opcode.BRID| Opcode.BRIE| Opcode.BRLT| Opcode.BRMI| Opcode.BRNE| Opcode.BRPL
  | Opcode.BRTC| Opcode.BRTS| Opcode.BRVC| Opcode.BRVS ->
    branch pcMask ins builder
  (* A BREAK is what a debugger plants, so it stops the run rather than
     reporting anything about the processor. *)
  | Opcode.BREAK ->
    sideEffects ins builder Breakpoint
  | Opcode.BST ->
    bst ins builder
  | Opcode.CALL ->
    call core ins builder
  | Opcode.CBI ->
    cbi ins builder
  | Opcode.IN ->
    ``in`` ins builder
  | Opcode.OUT ->
    out ins builder
  | Opcode.SBI ->
    sbi ins builder
  | Opcode.SBIC ->
    sbic ins builder
  | Opcode.SBIS ->
    sbis ins builder
  | Opcode.SBRC ->
    sbrc ins builder
  | Opcode.SBRS ->
    sbrs ins builder
  | Opcode.LPM ->
    lpm ins builder
  | Opcode.NEG ->
    neg ins builder
  | Opcode.ELPM ->
    elpm ins builder
  | Opcode.EICALL ->
    eicall core ins builder
  | Opcode.EIJMP ->
    eijmp ins builder
  (* SLEEP stops the core until something outside it intervenes, which is all
     this translation can say: whether anything can wake the core again, and
     what does, is the platform's to answer. *)
  | Opcode.SLEEP ->
    sideEffects ins builder Terminate
  (* Still to do: SPM writes program memory. Reporting it rather than letting it
     pass keeps a program that reaches one from running on silently. *)
  | Opcode.SPM ->
    unsupported ins builder
  | Opcode.CLC ->
    clc ins builder
  | Opcode.CLH ->
    clh ins builder
  | Opcode.CLI ->
    cli ins builder
  | Opcode.CLN ->
    cln ins builder
  | Opcode.CLR ->
    clr ins builder
  | Opcode.CLS ->
    cls ins builder
  | Opcode.CLT ->
    clt ins builder
  | Opcode.CLV ->
    clv ins builder
  | Opcode.CLZ ->
    clz ins builder
  | Opcode.COM ->
    com ins builder
  | Opcode.CP ->
    cp ins builder
  | Opcode.CPC ->
    cpc ins builder
  | Opcode.CPI ->
    cpi ins builder
  | Opcode.CPSE ->
    cpse ins builder
  | Opcode.DEC ->
    dec ins builder
  | Opcode.DES ->
    des ins builder
  | Opcode.EOR ->
    eor ins builder
  | Opcode.FMUL ->
    fmul ins builder
  | Opcode.FMULS ->
    fmuls ins builder
  | Opcode.FMULSU ->
    fmulsu ins builder
  | Opcode.ICALL ->
    icall core ins builder
  | Opcode.IJMP ->
    ijmp ins builder
  | Opcode.INC ->
    inc ins builder
  | Opcode.JMP ->
    jmp ins builder
  | Opcode.LAC ->
    lac ins builder
  | Opcode.LAS ->
    las ins builder
  | Opcode.LAT ->
    lat ins builder
  | Opcode.LD ->
    ld ins builder
  | Opcode.LDD ->
    ldd ins builder
  | Opcode.LDI ->
    ldi ins builder
  | Opcode.LDS ->
    lds ins builder
  | Opcode.LSR ->
    ``lsr`` ins builder
  | Opcode.MOV ->
    mov ins builder
  | Opcode.MOVW ->
    movw ins builder
  | Opcode.MUL ->
    mul ins builder
  | Opcode.MULS ->
    muls ins builder
  | Opcode.MULSU ->
    mulsu ins builder
  | Opcode.NOP ->
    nop ins builder
  | Opcode.OR | Opcode.ORI ->
    ``or`` ins builder
  | Opcode.POP ->
    pop ins builder
  | Opcode.PUSH ->
    push ins builder
  | Opcode.RCALL ->
    rcall core pcMask ins builder
  | Opcode.RET | Opcode.RETI as opr ->
    ret core ins opr builder
  | Opcode.RJMP ->
    rjmp pcMask ins builder
  | Opcode.ROR ->
    ror ins builder
  | Opcode.SBC | Opcode.SBCI ->
    sbc ins builder
  | Opcode.SBIW ->
    sbiw ins builder
  | Opcode.SEC | Opcode.SEH | Opcode.SEI | Opcode.SEN | Opcode.SES | Opcode.SET
  | Opcode.SEV | Opcode.SEZ ->
    sf ins builder
  | Opcode.SUB | Opcode.SUBI ->
    sub ins builder
  | Opcode.ST ->
    st ins builder
  | Opcode.STD ->
    std ins builder
  | Opcode.STS ->
    sts ins builder
  | Opcode.SWAP ->
    swap ins builder
  (* A watchdog reset needs a watchdog to reset. Reporting it is what keeps a
     guest that relies on one from looking like it ran correctly. *)
  | Opcode.WDR ->
    unsupported ins builder
  | Opcode.XCH ->
    xch ins builder
  (* No parser produces this opcode: an undecodable encoding is reported as a
     parsing failure, so an instruction never carries it this far. *)
  | Opcode.InvalidOp ->
    B2R2.Terminator.impossible ()
  | o ->
  #if DEBUG
           eprintfn "%A" o
  #endif
           raise <| NotImplementedIRException(Disasm.opCodeToString o)
