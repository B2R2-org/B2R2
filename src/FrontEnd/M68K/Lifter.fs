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


/// Chooses the lifter that each m68k opcode is translated by.
module internal B2R2.FrontEnd.M68K.Lifter

open B2R2.FrontEnd.M68K.GeneralLifter
open B2R2.FrontEnd.M68K.FloatLifter

/// Translates an m68k instruction into its LowUIR statements.
let translate (ins: Instruction) bld =
  match ins.Opcode with
  | Op.MOVE -> move ins bld
  | Op.MOVEA -> movea ins bld
  | Op.MOVEQ -> moveq ins bld
  | Op.MOVEM -> movem ins bld
  | Op.MOVEP -> movep ins bld
  | Op.LEA -> lea ins bld
  | Op.PEA -> pea ins bld
  | Op.LINK -> link ins bld
  | Op.UNLK -> unlk ins bld
  | Op.EXG -> exg ins bld
  | Op.SWAP -> swap ins bld
  | Op.CLR -> clr ins bld
  | Op.EXT | Op.EXTB -> ext ins bld
  | Op.ADD | Op.ADDI | Op.ADDQ -> add ins bld
  | Op.SUB | Op.SUBI | Op.SUBQ -> sub ins bld
  | Op.ADDA -> adda ins bld
  | Op.SUBA -> suba ins bld
  | Op.ADDX -> addx ins bld
  | Op.SUBX -> subx ins bld
  | Op.NEG -> neg ins bld
  | Op.NEGX -> negx ins bld
  | Op.CMP | Op.CMPI | Op.CMPM -> cmp ins bld
  | Op.CMPA -> cmpa ins bld
  | Op.TST -> tst ins bld
  | Op.NOT -> logicNot ins bld
  | Op.AND | Op.ANDI -> logicAnd ins bld
  | Op.OR | Op.ORI -> logicOr ins bld
  | Op.EOR | Op.EORI -> logicXor ins bld
  | Op.MULU -> mulu ins bld
  | Op.MULS -> muls ins bld
  | Op.DIVU -> divu ins bld
  | Op.DIVS -> divs ins bld
  | Op.DIVUL -> divul ins bld
  | Op.DIVSL -> divsl ins bld
  | Op.ASL | Op.ASR | Op.LSL | Op.LSR
  | Op.ROL | Op.ROR | Op.ROXL | Op.ROXR -> shiftOrRotate ins bld
  | Op.BTST | Op.BSET | Op.BCLR | Op.BCHG -> bit ins bld
  | Op.BRA -> bra ins bld
  | Op.BSR -> bsr ins bld
  | Op.BHI | Op.BLS | Op.BCC | Op.BCS | Op.BNE | Op.BEQ | Op.BVC | Op.BVS
  | Op.BPL | Op.BMI | Op.BGE | Op.BLT | Op.BGT | Op.BLE -> bcc ins bld
  | Op.DBT | Op.DBF | Op.DBHI | Op.DBLS | Op.DBCC | Op.DBCS | Op.DBNE
  | Op.DBEQ | Op.DBVC | Op.DBVS | Op.DBPL | Op.DBMI | Op.DBGE | Op.DBLT
  | Op.DBGT | Op.DBLE -> dbcc ins bld
  | Op.ST | Op.SF | Op.SHI | Op.SLS | Op.SCC | Op.SCS | Op.SNE | Op.SEQ
  | Op.SVC | Op.SVS | Op.SPL | Op.SMI | Op.SGE | Op.SLT | Op.SGT
  | Op.SLE -> scc ins bld
  | Op.JMP -> jmp ins bld
  | Op.JSR -> jsr ins bld
  | Op.RTS -> rts ins bld
  | Op.RTD -> rtd ins bld
  | Op.RTR -> rtr ins bld
  | Op.NOP -> nop ins bld
  | Op.TRAP -> trap ins bld
  | Op.TRAPV -> trapv ins bld
  | Op.TRAPT | Op.TRAPF | Op.TRAPHI | Op.TRAPLS | Op.TRAPCC | Op.TRAPCS
  | Op.TRAPNE | Op.TRAPEQ | Op.TRAPVC | Op.TRAPVS | Op.TRAPPL | Op.TRAPMI
  | Op.TRAPGE | Op.TRAPLT | Op.TRAPGT | Op.TRAPLE -> trapcc ins bld
  | Op.ILLEGAL -> illegal ins bld
  | Op.BKPT -> bkpt ins bld
  | Op.CHK -> chk ins bld
  | Op.CHK2 | Op.CMP2 -> cmp2 ins bld
  | Op.TAS -> tas ins bld
  | Op.CAS -> cas ins bld
  | Op.CAS2 -> cas2 ins bld
  | Op.ABCD -> abcd ins bld
  | Op.SBCD -> sbcd ins bld
  | Op.NBCD -> nbcd ins bld
  | Op.PACK -> pack ins bld
  | Op.UNPK -> unpk ins bld
  | Op.MOVE16 -> move16 ins bld
  | Op.BFTST | Op.BFCHG | Op.BFCLR | Op.BFSET
  | Op.BFEXTU | Op.BFEXTS | Op.BFFFO | Op.BFINS -> bitFieldOp ins bld
  | Op.FMOVEM -> fmovem ins bld
  | Op.FMOVE | Op.FSMOVE | Op.FDMOVE -> fmove ins bld
  | Op.FMOVECR -> fmovecr ins bld
  | Op.FADD | Op.FSADD | Op.FDADD -> fadd ins bld
  | Op.FSUB | Op.FSSUB | Op.FDSUB -> fsub ins bld
  | Op.FMUL | Op.FSMUL | Op.FDMUL -> fmul ins bld
  | Op.FDIV | Op.FSDIV | Op.FDDIV -> fdiv ins bld
  | Op.FSGLMUL -> fsglmul ins bld
  | Op.FSGLDIV -> fsgldiv ins bld
  | Op.FNEG | Op.FSNEG | Op.FDNEG -> fneg ins bld
  | Op.FABS | Op.FSABS | Op.FDABS -> fabs ins bld
  | Op.FSQRT | Op.FSSQRT | Op.FDSQRT -> fsqrt ins bld
  | Op.FINT -> fint ins bld
  | Op.FINTRZ -> fintrz ins bld
  | Op.FGETEXP -> fgetexp ins bld
  | Op.FSCALE -> fscale ins bld
  | Op.FMOD -> fmod ins bld
  | Op.FREM -> frem ins bld
  | Op.FETOX -> fetox ins bld
  | Op.FETOXM1 -> fetoxm1 ins bld
  | Op.FTWOTOX -> ftwotox ins bld
  | Op.FTENTOX -> ftentox ins bld
  | Op.FLOGN -> flogn ins bld
  | Op.FLOGNP1 -> flognp1 ins bld
  | Op.FLOG2 -> flog2 ins bld
  | Op.FLOG10 -> flog10 ins bld
  | Op.FGETMAN -> fgetman ins bld
  | Op.FSIN -> fsin ins bld
  | Op.FCOS -> fcos ins bld
  | Op.FTAN -> ftan ins bld
  | Op.FASIN -> fasin ins bld
  | Op.FACOS -> facos ins bld
  | Op.FATAN -> fatan ins bld
  | Op.FSINH -> fsinh ins bld
  | Op.FCOSH -> fcosh ins bld
  | Op.FTANH -> ftanh ins bld
  | Op.FATANH -> fatanh ins bld
  | Op.FSINCOS -> fsincos ins bld
  | Op.FCMP -> fcmp ins bld
  | Op.FTST -> ftst ins bld
  | Op.FNOP -> nop ins bld
  | Op.FBF | Op.FBEQ | Op.FBOGT | Op.FBOGE | Op.FBOLT | Op.FBOLE | Op.FBOGL
  | Op.FBOR | Op.FBUN | Op.FBUEQ | Op.FBUGT | Op.FBUGE | Op.FBULT | Op.FBULE
  | Op.FBNE | Op.FBT | Op.FBSF | Op.FBSEQ | Op.FBGT | Op.FBGE | Op.FBLT
  | Op.FBLE | Op.FBGL | Op.FBGLE | Op.FBNGLE | Op.FBNGL | Op.FBNLE
  | Op.FBNLT | Op.FBNGE | Op.FBNGT | Op.FBSNE | Op.FBST -> fbcc ins bld
  | Op.FSF | Op.FSEQ | Op.FSOGT | Op.FSOGE | Op.FSOLT | Op.FSOLE | Op.FSOGL
  | Op.FSOR | Op.FSUN | Op.FSUEQ | Op.FSUGT | Op.FSUGE | Op.FSULT | Op.FSULE
  | Op.FSNE | Op.FST | Op.FSSF | Op.FSSEQ | Op.FSGT | Op.FSGE | Op.FSLT
  | Op.FSLE | Op.FSGL | Op.FSGLE | Op.FSNGLE | Op.FSNGL | Op.FSNLE
  | Op.FSNLT | Op.FSNGE | Op.FSNGT | Op.FSSNE | Op.FSST -> fscc ins bld
  | Op.FDBF | Op.FDBEQ | Op.FDBOGT | Op.FDBOGE | Op.FDBOLT | Op.FDBOLE
  | Op.FDBOGL | Op.FDBOR | Op.FDBUN | Op.FDBUEQ | Op.FDBUGT | Op.FDBUGE
  | Op.FDBULT | Op.FDBULE | Op.FDBNE | Op.FDBT | Op.FDBSF | Op.FDBSEQ
  | Op.FDBGT | Op.FDBGE | Op.FDBLT | Op.FDBLE | Op.FDBGL | Op.FDBGLE
  | Op.FDBNGLE | Op.FDBNGL | Op.FDBNLE | Op.FDBNLT | Op.FDBNGE | Op.FDBNGT
  | Op.FDBSNE | Op.FDBST -> fdbcc ins bld
  | Op.FTRAPF | Op.FTRAPEQ | Op.FTRAPOGT | Op.FTRAPOGE | Op.FTRAPOLT
  | Op.FTRAPOLE | Op.FTRAPOGL | Op.FTRAPOR | Op.FTRAPUN | Op.FTRAPUEQ
  | Op.FTRAPUGT | Op.FTRAPUGE | Op.FTRAPULT | Op.FTRAPULE | Op.FTRAPNE
  | Op.FTRAPT | Op.FTRAPSF | Op.FTRAPSEQ | Op.FTRAPGT | Op.FTRAPGE
  | Op.FTRAPLT | Op.FTRAPLE | Op.FTRAPGL | Op.FTRAPGLE | Op.FTRAPNGLE
  | Op.FTRAPNGL | Op.FTRAPNLE | Op.FTRAPNLT | Op.FTRAPNGE | Op.FTRAPNGT
  | Op.FTRAPSNE | Op.FTRAPST -> ftrapcc ins bld
  | _ -> unsupported ins bld
