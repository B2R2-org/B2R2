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

module internal B2R2.FrontEnd.M68K.OpcodeInfo

open B2R2

/// Returns the earliest and the latest member of the 68000 family
/// that read the given opcode, which is Table A-1 of the M68000
/// Family Programmer's Reference Manual read across. Every opcode
/// the parser can produce belongs here: one missing from this list
/// would be reported as available on a 68000, which is the one
/// answer that is never safe.
let private modelRange = function
  | Op.ABCD | Op.ADD | Op.ADDA | Op.ADDI | Op.ADDQ | Op.ADDX | Op.AND | Op.ANDI
  | Op.ASL | Op.ASR | Op.BCC | Op.BCHG | Op.BCLR | Op.BCS | Op.BEQ | Op.BGE
  | Op.BGT | Op.BHI | Op.BLE | Op.BLS | Op.BLT | Op.BMI | Op.BNE | Op.BPL
  | Op.BRA | Op.BSET | Op.BSR | Op.BTST | Op.BVC | Op.BVS | Op.CHK | Op.CLR
  | Op.CMP | Op.CMPA | Op.CMPI | Op.CMPM | Op.DBCC | Op.DBCS | Op.DBEQ | Op.DBF
  | Op.DBGE | Op.DBGT | Op.DBHI | Op.DBLE | Op.DBLS | Op.DBLT | Op.DBMI
  | Op.DBNE | Op.DBPL | Op.DBT | Op.DBVC | Op.DBVS | Op.DIVS | Op.DIVU | Op.EOR
  | Op.EORI | Op.EXG | Op.EXT | Op.ILLEGAL | Op.JMP | Op.JSR | Op.LEA | Op.LINK
  | Op.LSL | Op.LSR | Op.MOVE | Op.MOVEA | Op.MOVEM | Op.MOVEP | Op.MOVEQ
  | Op.MULS | Op.MULU | Op.NBCD | Op.NEG | Op.NEGX | Op.NOP | Op.NOT | Op.OR
  | Op.ORI | Op.PEA | Op.RESET | Op.ROL | Op.ROR | Op.ROXL | Op.ROXR | Op.RTE
  | Op.RTR | Op.RTS | Op.SBCD | Op.SCC | Op.SCS | Op.SEQ | Op.SF | Op.SGE
  | Op.SGT | Op.SHI | Op.SLE | Op.SLS | Op.SLT | Op.SMI | Op.SNE | Op.SPL
  | Op.ST | Op.STOP | Op.SUB | Op.SUBA | Op.SUBI | Op.SUBQ | Op.SUBX | Op.SVC
  | Op.SVS | Op.SWAP | Op.TAS | Op.TRAP | Op.TRAPV | Op.TST | Op.UNLK ->
    M68KModel.M68000, M68KModel.M68060
  | Op.BKPT | Op.MOVEC | Op.MOVES | Op.RTD ->
    M68KModel.M68010, M68KModel.M68060
  | Op.BFCHG | Op.BFCLR | Op.BFEXTS | Op.BFEXTU | Op.BFFFO | Op.BFINS
  | Op.BFSET | Op.BFTST | Op.CAS | Op.CAS2 | Op.CHK2 | Op.CMP2 | Op.DIVSL
  | Op.DIVUL | Op.EXTB | Op.FABS | Op.FACOS | Op.FADD | Op.FASIN | Op.FATAN
  | Op.FATANH | Op.FBEQ | Op.FBF | Op.FBGE | Op.FBGL | Op.FBGLE | Op.FBGT
  | Op.FBLE | Op.FBLT | Op.FBNE | Op.FBNGE | Op.FBNGL | Op.FBNGLE | Op.FBNGT
  | Op.FBNLE | Op.FBNLT | Op.FBOGE | Op.FBOGL | Op.FBOGT | Op.FBOLE | Op.FBOLT
  | Op.FBOR | Op.FBSEQ | Op.FBSF | Op.FBSNE | Op.FBST | Op.FBT | Op.FBUEQ
  | Op.FBUGE | Op.FBUGT | Op.FBULE | Op.FBULT | Op.FBUN | Op.FCMP | Op.FCOS
  | Op.FCOSH | Op.FDBEQ | Op.FDBF | Op.FDBGE | Op.FDBGL | Op.FDBGLE | Op.FDBGT
  | Op.FDBLE | Op.FDBLT | Op.FDBNE | Op.FDBNGE | Op.FDBNGL | Op.FDBNGLE
  | Op.FDBNGT | Op.FDBNLE | Op.FDBNLT | Op.FDBOGE | Op.FDBOGL | Op.FDBOGT
  | Op.FDBOLE | Op.FDBOLT | Op.FDBOR | Op.FDBSEQ | Op.FDBSF | Op.FDBSNE
  | Op.FDBST | Op.FDBT | Op.FDBUEQ | Op.FDBUGE | Op.FDBUGT | Op.FDBULE
  | Op.FDBULT | Op.FDBUN | Op.FDIV | Op.FETOX | Op.FETOXM1 | Op.FGETEXP
  | Op.FGETMAN | Op.FINT | Op.FINTRZ | Op.FLOG10 | Op.FLOG2 | Op.FLOGN
  | Op.FLOGNP1 | Op.FMOD | Op.FMOVE | Op.FMOVECR | Op.FMOVEM | Op.FMUL
  | Op.FNEG | Op.FNOP | Op.FREM | Op.FRESTORE | Op.FSAVE | Op.FSCALE | Op.FSEQ
  | Op.FSF | Op.FSGE | Op.FSGL | Op.FSGLDIV | Op.FSGLE | Op.FSGLMUL | Op.FSGT
  | Op.FSIN | Op.FSINCOS | Op.FSINH | Op.FSLE | Op.FSLT | Op.FSNE | Op.FSNGE
  | Op.FSNGL | Op.FSNGLE | Op.FSNGT | Op.FSNLE | Op.FSNLT | Op.FSOGE | Op.FSOGL
  | Op.FSOGT | Op.FSOLE | Op.FSOLT | Op.FSOR | Op.FSQRT | Op.FSSEQ | Op.FSSF
  | Op.FSSNE | Op.FSST | Op.FST | Op.FSUB | Op.FSUEQ | Op.FSUGE | Op.FSUGT
  | Op.FSULE | Op.FSULT | Op.FSUN | Op.FTAN | Op.FTANH | Op.FTENTOX
  | Op.FTRAPEQ | Op.FTRAPF | Op.FTRAPGE | Op.FTRAPGL | Op.FTRAPGLE | Op.FTRAPGT
  | Op.FTRAPLE | Op.FTRAPLT | Op.FTRAPNE | Op.FTRAPNGE | Op.FTRAPNGL
  | Op.FTRAPNGLE | Op.FTRAPNGT | Op.FTRAPNLE | Op.FTRAPNLT | Op.FTRAPOGE
  | Op.FTRAPOGL | Op.FTRAPOGT | Op.FTRAPOLE | Op.FTRAPOLT | Op.FTRAPOR
  | Op.FTRAPSEQ | Op.FTRAPSF | Op.FTRAPSNE | Op.FTRAPST | Op.FTRAPT
  | Op.FTRAPUEQ | Op.FTRAPUGE | Op.FTRAPUGT | Op.FTRAPULE | Op.FTRAPULT
  | Op.FTRAPUN | Op.FTST | Op.FTWOTOX | Op.PACK | Op.TRAPCC | Op.TRAPCS
  | Op.TRAPEQ | Op.TRAPF | Op.TRAPGE | Op.TRAPGT | Op.TRAPHI | Op.TRAPLE
  | Op.TRAPLS | Op.TRAPLT | Op.TRAPMI | Op.TRAPNE | Op.TRAPPL | Op.TRAPT
  | Op.TRAPVC | Op.TRAPVS | Op.UNPK ->
    M68KModel.M68020, M68KModel.M68060
  | Op.CALLM | Op.RTM ->
    M68KModel.M68020, M68KModel.M68020
  | Op.CINVA | Op.CINVL | Op.CINVP | Op.CPUSHA | Op.CPUSHL | Op.CPUSHP
  | Op.FDABS | Op.FDADD | Op.FDDIV | Op.FDMOVE | Op.FDMUL | Op.FDNEG
  | Op.FDSQRT | Op.FDSUB | Op.FSABS | Op.FSADD | Op.FSDIV | Op.FSMOVE
  | Op.FSMUL | Op.FSNEG | Op.FSSQRT | Op.FSSUB | Op.MOVE16 | Op.PFLUSH
  | Op.PFLUSHA | Op.PFLUSHAN | Op.PFLUSHN | Op.PTESTR | Op.PTESTW ->
    M68KModel.M68040, M68KModel.M68060
  | _ -> Terminator.impossible ()

/// Returns true when the given opcode can be decoded on the given
/// member of the family. The family shares one encoding space and
/// each model both added to it and dropped from it, so an opcode
/// outside the range of the target means we are not looking at
/// code.
let isAvailable model opcode =
  let lo, hi = modelRange opcode
  lo <= model && model <= hi
