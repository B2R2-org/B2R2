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

module internal B2R2.FrontEnd.S390.OpcodeInfo

open B2R2

/// Returns true when the opcode belongs to the ESA/390 instruction set, and so
/// can appear in 32-bit S390 code as well as in 64-bit z/Architecture code.
/// The list is Figure B-3 of the z/Architecture Principles of Operation
/// (SA22-7832) minus every entry its "Characteristics" column marks with N,
/// which reads "instruction is new in z/Architecture as compared to ESA/390".
/// An entry marked N3 stays, because that mark reads "new in z/Architecture and
/// has been added to ESA/390" -- BRASL and LARL are such instructions.
let isEsa390 = function
  | Op.AR | Op.A | Op.AH | Op.AHI | Op.ALR | Op.AL | Op.ALCR | Op.ALC | Op.NR
  | Op.N | Op.NI | Op.NC | Op.BALR | Op.BAL | Op.BASR | Op.BAS | Op.BASSM
  | Op.BSM | Op.BCR | Op.BC | Op.BCTR | Op.BCT | Op.BXH | Op.BXLE | Op.BRAS
  | Op.BRASL | Op.BRC | Op.BRCL | Op.BRCT | Op.BRXH | Op.BRXLE | Op.CKSM | Op.CR
  | Op.C | Op.CFC | Op.CS | Op.CDS | Op.CH | Op.CHI | Op.CLR | Op.CL | Op.CLC
  | Op.CLI | Op.CLM | Op.CLCL | Op.CLCLE | Op.CLCLU | Op.CLST | Op.CUSE
  | Op.CMPSC | Op.CVB | Op.CVD | Op.CUUTF | Op.CUTFU | Op.CPYA | Op.DR | Op.D
  | Op.DLR | Op.DL | Op.XR | Op.X | Op.XI | Op.XC | Op.EX | Op.EAR | Op.EPSW
  | Op.IC | Op.ICM | Op.IPM | Op.LR | Op.L | Op.LAM | Op.LA | Op.LAE | Op.LARL
  | Op.LTR | Op.LCR | Op.LH | Op.LHI | Op.LM | Op.LNR | Op.LPR | Op.LRVR
  | Op.LRVH | Op.LRV | Op.MC | Op.MVC | Op.MVI | Op.MVCIN | Op.MVCL | Op.MVCLE
  | Op.MVCLU | Op.MVN | Op.MVST | Op.MVO | Op.MVZ | Op.MR | Op.M | Op.MH
  | Op.MHI | Op.MLR | Op.ML | Op.MSR | Op.MS | Op.OR | Op.O | Op.OI | Op.OC
  | Op.PACK | Op.PKA | Op.PKU | Op.PLO | Op.RLL | Op.SRST | Op.SAR | Op.SAM24
  | Op.SAM31 | Op.SPM | Op.SLDA | Op.SLDL | Op.SLA | Op.SLL | Op.SRDA | Op.SRDL
  | Op.SRA | Op.SRL | Op.ST | Op.STAM | Op.STC | Op.STCM | Op.STCK | Op.STCKE
  | Op.STH | Op.STM | Op.STRVH | Op.STRV | Op.SR | Op.S | Op.SH | Op.SLR | Op.SL
  | Op.SLBR | Op.SLB | Op.SVC | Op.TAM | Op.TS | Op.TM | Op.TMLH | Op.TMLL
  | Op.TR | Op.TRT | Op.TRE | Op.TROO | Op.TROT | Op.TRTO | Op.TRTT | Op.UNPK
  | Op.UNPKA | Op.UNPKU | Op.UPT | Op.AP | Op.CP | Op.DP | Op.ED | Op.EDMK
  | Op.MP | Op.SRP | Op.SP | Op.TP | Op.ZAP | Op.THDER | Op.THDR | Op.TBEDR
  | Op.TBDR | Op.EFPC | Op.LER | Op.LDR | Op.LXR | Op.LE | Op.LD | Op.LFPC
  | Op.LZER | Op.LZDR | Op.LZXR | Op.SRNM | Op.SFPC | Op.STE | Op.STD | Op.STFPC
  | Op.BSA | Op.BAKR | Op.BSG | Op.CSP | Op.EPAR | Op.ESAR | Op.EREG | Op.ESTA
  | Op.IAC | Op.IPK | Op.ISKE | Op.IVSK | Op.IPTE | Op.LASP | Op.LCTL | Op.LPSW
  | Op.LRA | Op.LURA | Op.MSTA | Op.MVPG | Op.MVCP | Op.MVCS | Op.MVCDK
  | Op.MVCK | Op.MVCSK | Op.PGIN | Op.PGOUT | Op.PC | Op.PR | Op.PT | Op.PALB
  | Op.PTLB | Op.RRBE | Op.RP | Op.SAC | Op.SACF | Op.SCK | Op.SCKC | Op.SCKPF
  | Op.SPT | Op.SPX | Op.SPKA | Op.SSAR | Op.SSKE | Op.SSM | Op.SIGP | Op.STCKC
  | Op.STCTL | Op.STAP | Op.STIDP | Op.STPT | Op.STFL | Op.STPX | Op.STSI
  | Op.STNSM | Op.STOSM | Op.STURA | Op.TAR | Op.TB | Op.TPROT | Op.TRACE
  | Op.TRAP2 | Op.TRAP4 | Op.XSCH | Op.CSCH | Op.HSCH | Op.MSCH | Op.RCHP
  | Op.RSCH | Op.SAL | Op.SCHM | Op.SSCH | Op.STCPS | Op.STCRW | Op.STSCH
  | Op.TPI | Op.TSCH | Op.AER | Op.ADR | Op.AXR | Op.AE | Op.AD | Op.AUR
  | Op.AWR | Op.AU | Op.AW | Op.CER | Op.CDR | Op.CXR | Op.CE | Op.CD | Op.CEFR
  | Op.CDFR | Op.CXFR | Op.CFER | Op.CFDR | Op.CFXR | Op.DER | Op.DDR | Op.DXR
  | Op.DE | Op.DD | Op.HER | Op.HDR | Op.LTER | Op.LTDR | Op.LTXR | Op.LCER
  | Op.LCDR | Op.LCXR | Op.FIER | Op.FIDR | Op.FIXR | Op.LDER | Op.LXDR
  | Op.LXER | Op.LDE | Op.LXD | Op.LXE | Op.LNER | Op.LNDR | Op.LNXR | Op.LPER
  | Op.LPDR | Op.LPXR | Op.LEDR | Op.LDXR | Op.LEXR | Op.MEER | Op.MDR | Op.MXR
  | Op.MDER | Op.MXDR | Op.MEE | Op.MD | Op.MDE | Op.MXD | Op.SQER | Op.SQDR
  | Op.SQXR | Op.SQE | Op.SQD | Op.SER | Op.SDR | Op.SXR | Op.SE | Op.SD
  | Op.SUR | Op.SWR | Op.SU | Op.SW | Op.AEBR | Op.ADBR | Op.AXBR | Op.AEB
  | Op.ADB | Op.CEBR | Op.CDBR | Op.CXBR | Op.CEB | Op.CDB | Op.KEBR | Op.KDBR
  | Op.KXBR | Op.KEB | Op.KDB | Op.CEFBR | Op.CDFBR | Op.CXFBR | Op.CFEBR
  | Op.CFDBR | Op.CFXBR | Op.DEBR | Op.DDBR | Op.DXBR | Op.DEB | Op.DDB
  | Op.DIEBR | Op.DIDBR | Op.LTEBR | Op.LTDBR | Op.LTXBR | Op.LCEBR | Op.LCDBR
  | Op.LCXBR | Op.FIEBR | Op.FIDBR | Op.FIXBR | Op.LDEBR | Op.LXDBR | Op.LXEBR
  | Op.LDEB | Op.LXDB | Op.LXEB | Op.LNEBR | Op.LNDBR | Op.LNXBR | Op.LPEBR
  | Op.LPDBR | Op.LPXBR | Op.LEDBR | Op.LDXBR | Op.LEXBR | Op.MEEBR | Op.MDBR
  | Op.MXBR | Op.MDEBR | Op.MXDBR | Op.MEEB | Op.MDB | Op.MDEB | Op.MXDB
  | Op.MAEBR | Op.MADBR | Op.MAEB | Op.MADB | Op.MSEBR | Op.MSDBR | Op.MSEB
  | Op.MSDB | Op.SQEBR | Op.SQDBR | Op.SQXBR | Op.SQEB | Op.SQDB | Op.SEBR
  | Op.SDBR | Op.SXBR | Op.SEB | Op.SDB | Op.TCEB | Op.TCDB | Op.TCXB -> true
  | _ -> false

/// Returns true when the opcode can be decoded under the given word size. A
/// 32-bit S390 target runs ESA/390, which knows nothing of the instructions
/// z/Architecture added, so decoding one there means we are not looking at
/// code.
let isAvailable wordSize opcode =
  if wordSize = WordSize.Bit32 then isEsa390 opcode else true
