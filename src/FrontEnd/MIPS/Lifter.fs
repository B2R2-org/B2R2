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

module internal B2R2.FrontEnd.MIPS.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.MIPS
open B2R2.FrontEnd.MIPS.LiftingUtils
open B2R2.FrontEnd.MIPS.GeneralLifter

let translate (ins: Instruction) (bld: LowUIRBuilder) =
  match ins.Opcode with
  | Op.ABS ->
    abs ins bld
  | Op.ADD ->
    add ins bld
  | Op.ADDI ->
    addi ins bld
  | Op.ADDIU ->
    addiu ins bld
  | Op.ADDU ->
    addu ins bld
  | Op.AND ->
    logAnd ins bld
  | Op.ANDI ->
    andi ins bld
  | Op.AUI ->
    aui ins bld
  | Op.B ->
    b ins bld
  | Op.BAL ->
    bal ins bld
  | Op.BC1F ->
    bc1f ins bld
  | Op.BC1T ->
    bc1t ins bld
  | Op.BEQ ->
    beq ins bld
  | Op.BC1FL ->
    bc1condl ins bld false
  | Op.BC1TL ->
    bc1condl ins bld true
  | Op.BGEZL ->
    bcondzl ins bld (?>=)
  | Op.BLTZL ->
    bcondzl ins bld (?<)
  | Op.BLEZL ->
    bcondzl ins bld (?<=)
  | Op.BGTZL ->
    bcondzl ins bld (?>)
  | Op.BGEZALL ->
    bcondzall ins bld (?>=)
  | Op.BLTZALL ->
    bcondzall ins bld (?<)
  | Op.BEQL ->
    beql ins bld
  | Op.BGEZ ->
    bgez ins bld
  | Op.BGEZAL ->
    bgezal ins bld
  | Op.BGTZ ->
    bgtz ins bld
  | Op.BLEZ ->
    blez ins bld
  | Op.BLTZ ->
    bltz ins bld
  | Op.BLTZAL ->
    bltzal ins bld
  | Op.BNE ->
    bne ins bld
  | Op.BNEL ->
    bnel ins bld
  | Op.BREAK ->
    sideEffects ins bld Breakpoint
  | Op.C ->
    cCond ins bld
  | Op.CFC1 ->
    cfc1 ins bld
  | Op.CRC32B ->
    crc32 ins bld 0xEDB88320u 8
  | Op.CRC32H ->
    crc32 ins bld 0xEDB88320u 16
  | Op.CRC32W ->
    crc32 ins bld 0xEDB88320u 32
  | Op.CRC32D ->
    crc32 ins bld 0xEDB88320u 64
  | Op.CRC32CB ->
    crc32 ins bld 0x82F63B78u 8
  | Op.CRC32CH ->
    crc32 ins bld 0x82F63B78u 16
  | Op.CRC32CW ->
    crc32 ins bld 0x82F63B78u 32
  | Op.CRC32CD ->
    crc32 ins bld 0x82F63B78u 64
  | Op.CTC1 ->
    ctc1 ins bld
  | Op.CLO ->
    clo ins bld
  | Op.CLZ ->
    clz ins bld
  | Op.CVTD ->
    cvtd ins bld
  | Op.CVTL ->
    cvtl ins bld
  | Op.CVTS ->
    cvts ins bld
  | Op.CVTW ->
    cvtw ins bld
  | Op.CVTPSS ->
    cvtpss ins bld
  | Op.CVTSPU ->
    cvtsFromPair ins bld true
  | Op.CVTSPL ->
    cvtsFromPair ins bld false
  | Op.PLLPS ->
    pairHalves ins bld false false
  | Op.PLUPS ->
    pairHalves ins bld false true
  | Op.PULPS ->
    pairHalves ins bld true false
  | Op.PUUPS ->
    pairHalves ins bld true true
  | Op.ALNVPS ->
    alnvps ins bld
  | Op.DADD ->
    dadd ins bld
  | Op.DADDU ->
    daddu ins bld
  | Op.DADDI ->
    daddi ins bld
  | Op.DADDIU ->
    daddiu ins bld
  | Op.DCLO ->
    dclo ins bld
  | Op.DCLZ ->
    dclz ins bld
  | Op.DDIV ->
    (* Three operands AND no format is the Release 6 integer form,
       which writes rd; two operands is the older one, which writes HI
       and LO. The format has to be part of the test: DIV.S and DIV.D
       are this same opcode with three operands too, and keying on the
       count alone sent every float division to the integer lifter. *)
    match ins.Fmt, ins.Operands with
    | None, ThreeOperands _ -> divR6 ins bld false true true
    | _ -> ddiv ins bld
  | Op.DMFC1 ->
    dmfc1 ins bld
  | Op.DMTC1 ->
    dmtc1 ins bld
  | Op.DEXT ->
    dext ins bld
  | Op.DEXTM ->
    dextx ins checkDEXTMPosSize bld
  | Op.DEXTU ->
    dextx ins checkDEXTUPosSize bld
  | Op.DINS ->
    dins ins bld
  | Op.DINSM ->
    dinsx ins checkDINSMPosSize bld
  | Op.DINSU ->
    dinsx ins checkDINSUPosSize bld
  | Op.DIV ->
    (* Three operands AND no format is the Release 6 integer form,
       which writes rd; two operands is the older one, which writes HI
       and LO. The format has to be part of the test: DIV.S and DIV.D
       are this same opcode with three operands too, and keying on the
       count alone sent every float division to the integer lifter. *)
    match ins.Fmt, ins.Operands with
    | None, ThreeOperands _ -> divR6 ins bld false true false
    | _ -> div ins bld
  | Op.DIVU ->
    (* Three operands AND no format is the Release 6 integer form,
       which writes rd; two operands is the older one, which writes HI
       and LO. The format has to be part of the test: DIV.S and DIV.D
       are this same opcode with three operands too, and keying on the
       count alone sent every float division to the integer lifter. *)
    match ins.Fmt, ins.Operands with
    | None, ThreeOperands _ -> divR6 ins bld false false false
    | _ -> divu ins bld
  | Op.DDIVU ->
    (* Three operands AND no format is the Release 6 integer form,
       which writes rd; two operands is the older one, which writes HI
       and LO. The format has to be part of the test: DIV.S and DIV.D
       are this same opcode with three operands too, and keying on the
       count alone sent every float division to the integer lifter. *)
    match ins.Fmt, ins.Operands with
    | None, ThreeOperands _ -> divR6 ins bld false false true
    | _ -> ddivu ins bld
  | Op.DMULT ->
    dmul ins bld true
  | Op.DMULTU ->
    dmul ins bld false
  | Op.DROTR ->
    drotr ins bld
  | Op.DROTR32 ->
    drotr32 ins bld
  | Op.DROTRV ->
    drotrv ins bld
  | Op.DSBH ->
    dsbh ins bld
  | Op.DSHD ->
    dshd ins bld
  | Op.DSLL ->
    dShiftLeftRight ins bld (<<)
  | Op.DSLL32 ->
    dShiftLeftRight32 ins bld (<<)
  | Op.DSLLV ->
    dShiftLeftRightVar ins bld (<<)
  | Op.DSRA ->
    dsra ins bld
  | Op.DSRAV ->
    dsrav ins bld
  | Op.DSRA32 ->
    dsra32 ins bld
  | Op.DSRL ->
    dShiftLeftRight ins bld (>>)
  | Op.DSRL32 ->
    dShiftLeftRight32 ins bld (>>)
  | Op.DSRLV ->
    dShiftLeftRightVar ins bld (>>)
  | Op.DSUB ->
    dsub ins bld
  | Op.DSUBU ->
    dsubu ins bld
  | Op.EHB ->
    nop ins bld
  | Op.EXT ->
    ext ins bld
  | Op.INS ->
    insert ins bld
  | Op.J ->
    j ins bld
  | Op.JAL ->
    jal ins bld
  | Op.JALX ->
    jalx ins bld
  | Op.JALR | Op.JALRHB ->
    jalr ins bld
  | Op.JR | Op.JRHB ->
    jr ins bld
  | Op.JRC ->
    jumpRegCompact ins bld
  | Op.JALRS ->
    jalrShortSlot ins bld
  | Op.JALRC ->
    jalrCompact ins bld
  | Op.JRADDIUSP ->
    jumpRegAdjust ins bld
  | Op.JRCADDIUSP ->
    jumpRegAdjustCompact ins bld
  | Op.MOVEP ->
    movePair ins bld
  | Op.LWM ->
    loadStoreMultiple ins bld true 32<rt>
  | Op.SWM ->
    loadStoreMultiple ins bld false 32<rt>
  | Op.LDM ->
    loadStoreMultiple ins bld true 64<rt>
  | Op.SDM ->
    loadStoreMultiple ins bld false 64<rt>
  | Op.LWP ->
    loadStorePair ins bld true 32<rt>
  | Op.SWP ->
    loadStorePair ins bld false 32<rt>
  | Op.LDP ->
    loadStorePair ins bld true 64<rt>
  | Op.SDP ->
    loadStorePair ins bld false 64<rt>
  | Op.LWXS ->
    loadWordScaled ins bld
  | Op.JALS ->
    jalShortSlot ins bld
  | Op.JALRSHB ->
    jalrShortSlot ins bld
  | Op.BLTZALS ->
    branchLinkShortSlot ins bld AST.slt
  | Op.BGEZALS ->
    branchLinkShortSlot ins bld AST.sge
  | Op.LD | Op.LB | Op.LH | Op.LW
  | Op.LBE | Op.LHE | Op.LWE ->
    loadSigned ins bld
  | Op.LBU | Op.LHU | Op.LWU
  | Op.LBUE | Op.LHUE ->
    loadUnsigned ins bld
  | Op.LLWP | Op.LLWPE ->
    loadLinkedPair ins bld 32<rt>
  | Op.LLDP ->
    loadLinkedPair ins bld 64<rt>
  | Op.SCWP | Op.SCWPE ->
    storeConditionalPair ins bld 32<rt>
  | Op.SCDP ->
    storeConditionalPair ins bld 64<rt>
  | Op.LL | Op.LLD | Op.LLE ->
    loadLinked ins bld
  | Op.SDC1 | Op.SDXC1 ->
    sldc1 ins bld true false
  | Op.LDC1 | Op.LDXC1 ->
    sldc1 ins bld false false
  | Op.SUXC1 ->
    sldc1 ins bld true true
  | Op.LUXC1 ->
    sldc1 ins bld false true
  | Op.SWC1 | Op.SWXC1 ->
    slwc1 ins bld true
  | Op.LWC1 | Op.LWXC1 ->
    slwc1 ins bld false
  | Op.LUI ->
    lui ins bld
  | Op.LDL ->
    loadLeftRight ins bld (<<) (>>) (.&) 64<rt>
  | Op.LDR ->
    loadLeftRight ins bld (>>) (<<) (<+>) 64<rt>
  | Op.LWL | Op.LWLE ->
    loadLeftRight ins bld (<<) (>>) (.&) 32<rt>
  | Op.LWR | Op.LWRE ->
    loadLeftRight ins bld (>>) (<<) (<+>) 32<rt>
  | Op.MADD ->
    mAddSub ins bld true
  | Op.MADDU ->
    mAdduSubu ins bld true
  | Op.MFHI ->
    mfhi ins bld
  | Op.MFLO ->
    mflo ins bld
  | Op.MFHC1 ->
    mfhc1 ins bld
  | Op.MTHC1 ->
    mthc1 ins bld
  | Op.MTHI ->
    mthi ins bld
  | Op.MTLO ->
    mtlo ins bld
  | Op.MFC1 ->
    mfc1 ins bld
  | Op.MOV ->
    mov ins bld
  | Op.MOVT ->
    movt ins bld
  | Op.MOVF ->
    movf ins bld
  | Op.MOVZ ->
    movzOrn ins bld (==)
  | Op.MOVN ->
    movzOrn ins bld (!=)
  | Op.MSUB ->
    mAddSub ins bld false
  | Op.MSUBU ->
    mAdduSubu ins bld false
  | Op.MTC1 ->
    mtc1 ins bld
  | Op.MUL ->
    mul ins bld
  | Op.MULT ->
    mult ins bld
  | Op.MULTU ->
    multu ins bld
  | Op.NEG ->
    neg ins bld
  | Op.NMADD ->
    nmadd ins bld
  | Op.NMSUB ->
    nmsub ins bld
  | Op.NOP ->
    nop ins bld
  | Op.NOR ->
    nor ins bld
  | Op.OR ->
    logOr ins bld
  | Op.ORI ->
    ori ins bld
  | Op.PAUSE ->
    nop ins bld
  | Op.PREF | Op.PREFE | Op.PREFX ->
    nop ins bld
  (* The system control coprocessor, and the instructions that reach the
     caches and the other processors. Everything here needs a privilege level
     to be legal in, which is the one thing this front end has no way to
     check -- a real implementation takes Coprocessor Unusable on all of them
     unless Status.CU0 is set or the core is in kernel mode. *)
  | Op.MFC0 ->
    moveFromCP0 ins bld false false
  | Op.DMFC0 ->
    moveFromCP0 ins bld true false
  | Op.MFHC0 ->
    moveFromCP0 ins bld false true
  | Op.MTC0 ->
    moveToCP0 ins bld false false
  | Op.DMTC0 ->
    moveToCP0 ins bld true false
  | Op.MTHC0 ->
    moveToCP0 ins bld false true
  | Op.RDPGPR | Op.WRPGPR ->
    movePrevGPR ins bld
  | Op.DI ->
    interruptEnable ins bld false
  | Op.EI ->
    interruptEnable ins bld true
  | Op.DVP ->
    virtualProcessorEnable ins bld false
  | Op.EVP ->
    virtualProcessorEnable ins bld true
  | Op.ERET ->
    exceptionReturn ins bld true
  | Op.ERETNC ->
    exceptionReturn ins bld false
  | Op.DERET ->
    debugReturn ins bld
  (* A cache maintenance operation on a machine with no cache has nothing to
     do, and doing nothing is what the architecture asks of it. The two global
     invalidates reach the caches and TLBs of the OTHER processors of a
     multiprocessor, which is the same answer on a machine with one. *)
  | Op.CACHE | Op.CACHEE | Op.GINVI | Op.GINVT ->
    nop ins bld
  (* WAIT stops fetching until an interrupt arrives. Nothing here raises one,
     so waiting would be waiting forever; carrying on is what an
     implementation that treats the wait condition as already satisfied does,
     which the manual allows. *)
  | Op.WAIT ->
    sideEffects ins bld Delay
  (* The three that only move values between the registers that describe an
     entry and the array of entries itself. Nothing translates an address
     through what they write -- addresses here are translated without a TLB --
     so what they model is the array and not the translation, which is exactly
     what a case can compare against a processor. *)
  | Op.TLBWI ->
    tlbWriteIndexed ins bld
  | Op.TLBR ->
    tlbRead ins bld
  | Op.TLBP ->
    tlbProbe ins bld
  | Op.TLBWR ->
    tlbWriteRandom ins bld
  | Op.TLBINV ->
    tlbInvalidate ins bld true
  | Op.TLBINVF ->
    tlbInvalidate ins bld false
  (* Release 6. The compact branches share one lifter and differ only in the
     comparison, which is what they differ by in the manual too. *)
  | Op.BC ->
    bcCompact ins bld
  | Op.BALC ->
    balc ins bld
  | Op.BEQC ->
    compactBranchRR ins bld (==)
  | Op.BNEC ->
    compactBranchRR ins bld (!=)
  | Op.BLTC ->
    compactBranchRR ins bld (?<)
  | Op.BGEC ->
    compactBranchRR ins bld (?>=)
  | Op.BLTUC ->
    compactBranchRR ins bld (.<)
  | Op.BGEUC ->
    compactBranchRR ins bld (.>=)
  | Op.BEQZC ->
    compactBranchZ ins bld (==)
  | Op.BNEZC ->
    compactBranchZ ins bld (!=)
  | Op.BLEZC ->
    compactBranchZ ins bld (?<=)
  | Op.BGEZC ->
    compactBranchZ ins bld (?>=)
  | Op.BGTZC ->
    compactBranchZ ins bld (?>)
  | Op.BLTZC ->
    compactBranchZ ins bld (?<)
  | Op.BEQZALC ->
    compactBranchLinkZ ins bld (==)
  | Op.BNEZALC ->
    compactBranchLinkZ ins bld (!=)
  | Op.BLEZALC ->
    compactBranchLinkZ ins bld (?<=)
  | Op.BGEZALC ->
    compactBranchLinkZ ins bld (?>=)
  | Op.BGTZALC ->
    compactBranchLinkZ ins bld (?>)
  | Op.BLTZALC ->
    compactBranchLinkZ ins bld (?<)
  | Op.BOVC ->
    branchOverflowCompact ins bld true
  | Op.BNVC ->
    branchOverflowCompact ins bld false
  | Op.JIC ->
    jicCompact ins bld false
  | Op.JIALC ->
    jicCompact ins bld true
  (* The multiply and divide family keeps one half of the result in a general
     register, because Release 6 has no HI and LO to put the other half in.
     MUL is dispatched by operand count below, since the opcode is shared with
     the three-operand MUL that Release 2 put in SPECIAL2. *)
  | Op.MUH ->
    mulR6 ins bld true true false
  | Op.MULU ->
    mulR6 ins bld false false false
  | Op.MUHU ->
    mulR6 ins bld true false false
  | Op.DMUL ->
    mulR6 ins bld false true true
  | Op.DMUH ->
    mulR6 ins bld true true true
  | Op.DMULU ->
    mulR6 ins bld false false true
  | Op.DMUHU ->
    mulR6 ins bld true false true
  | Op.MOD ->
    divR6 ins bld true true false
  | Op.MODU ->
    divR6 ins bld true false false
  | Op.DMOD ->
    divR6 ins bld true true true
  | Op.DMODU ->
    divR6 ins bld true false true
  | Op.DAUI ->
    addUpperImm ins bld 16 false
  | Op.DAHI ->
    addUpperImm ins bld 32 true
  | Op.DATI ->
    addUpperImm ins bld 48 true
  | Op.BITSWAP ->
    bitswap ins bld false
  | Op.DBITSWAP ->
    bitswap ins bld true
  | Op.ALIGN ->
    align ins bld false
  | Op.DALIGN ->
    align ins bld true
  | Op.SEL ->
    fpSelect ins bld 0
  | Op.SELEQZ when ins.Fmt <> None ->
    fpSelect ins bld 1
  | Op.SELNEZ when ins.Fmt <> None ->
    fpSelect ins bld 2
  | Op.MIN ->
    fpMinMax ins bld false false
  | Op.MAX ->
    fpMinMax ins bld true false
  | Op.MINA ->
    fpMinMax ins bld false true
  | Op.MAXA ->
    fpMinMax ins bld true true
  | Op.CLASS ->
    fpClass ins bld
  | Op.RINT ->
    rint ins bld
  | Op.MADDF ->
    maddf ins bld
  | Op.MSUBF ->
    msubf ins bld
  | Op.CMP ->
    fpCmpR6 ins bld
  | Op.BC1EQZ ->
    bc1z ins bld false
  | Op.BC1NEZ ->
    bc1z ins bld true
  | Op.ADDIUPC ->
    addiupc ins bld
  | Op.AUIPC ->
    auipc ins bld false
  | Op.ALUIPC ->
    auipc ins bld true
  | Op.LWPC ->
    loadPC ins bld 32<rt> true
  | Op.LWUPC ->
    loadPC ins bld 32<rt> false
  | Op.LDPC ->
    loadPC ins bld 64<rt> true
  | Op.SELEQZ ->
    selectZ ins bld true
  | Op.SELNEZ ->
    selectZ ins bld false
  | Op.LSA ->
    lsa ins bld false
  | Op.DLSA ->
    lsa ins bld true
  | Op.RDHWR ->
    readHWR ins bld
  | Op.ROTR ->
    rotr ins bld
  | Op.ROTRV ->
    rotrv ins bld
  | Op.RECIP ->
    recip ins bld
  | Op.RSQRT ->
    rsqrt ins bld
  | Op.SLL ->
    shiftLeftRight ins bld (<<)
  | Op.SLLV ->
    shiftLeftRightVar ins bld (<<)
  | Op.SLT ->
    sltAndU ins bld (?<)
  | Op.SLTU ->
    sltAndU ins bld (.<)
  | Op.SLTI ->
    sltiAndU ins bld (?<)
  | Op.SLTIU ->
    sltiAndU ins bld (.<)
  | Op.SSNOP ->
    nop ins bld
  | Op.SB | Op.SBE ->
    store ins 8<rt> bld
  | Op.SC | Op.SCE ->
    storeConditional ins 32<rt> bld
  | Op.SCD ->
    storeConditional ins 64<rt> bld
  | Op.SD ->
    store ins 64<rt> bld
  | Op.SEB ->
    seb ins bld
  | Op.SEH ->
    seh ins bld
  | Op.SH | Op.SHE ->
    store ins 16<rt> bld
  | Op.SQRT ->
    sqrt ins bld
  | Op.SRA ->
    sra ins bld
  | Op.SRAV ->
    srav ins bld
  | Op.SRL ->
    shiftLeftRight ins bld (>>)
  | Op.SRLV ->
    shiftLeftRightVar ins bld (>>)
  | Op.SUB ->
    sub ins bld
  | Op.SUBU ->
    subu ins bld
  | Op.SW | Op.SWE ->
    store ins 32<rt> bld
  | Op.SDL ->
    storeLeftRight ins bld (<<) (>>) (.&) 64<rt>
  | Op.SDR ->
    storeLeftRight ins bld (>>) (<<) (<+>) 64<rt>
  | Op.SWL | Op.SWLE ->
    storeLeftRight ins bld (<<) (>>) (.&) 32<rt>
  | Op.SWR | Op.SWRE ->
    storeLeftRight ins bld (>>) (<<) (<+>) 32<rt>
  | Op.SYNC | Op.SYNCI ->
    nop ins bld
  | Op.SYSCALL ->
    syscall ins bld
  (* The conditional traps, which differ only in the comparison. The
     immediate forms sign-extend what they compare against, including the two
     that then compare it as unsigned -- which is the architecture's rule and
     not an oversight here. *)
  | Op.TEQ | Op.TEQI ->
    trapIf ins bld (==)
  | Op.TNE | Op.TNEI ->
    trapIf ins bld (!=)
  | Op.TGE | Op.TGEI ->
    trapIf ins bld AST.sge
  | Op.TGEU | Op.TGEIU ->
    trapIf ins bld AST.ge
  | Op.TLT | Op.TLTI ->
    trapIf ins bld AST.slt
  | Op.TLTU | Op.TLTIU ->
    trapIf ins bld AST.lt
  (* SIGRIE's whole effect IS a Reserved Instruction exception, so the
     undefined-instruction side effect is what it means rather than a
     placeholder. SDBBP enters the debug exception handler, which is the
     breakpoint of this architecture. *)
  | Op.SIGRIE ->
    sideEffects ins bld UndefinedInstruction
  | Op.SDBBP ->
    sideEffects ins bld Breakpoint
  | Op.ROUNDW ->
    roundw ins bld
  | Op.ROUNDL ->
    roundl ins bld
  | Op.CEILW ->
    ceilw ins bld
  | Op.CEILL ->
    ceill ins bld
  | Op.FLOORW ->
    floorw ins bld
  | Op.FLOORL ->
    floorl ins bld
  | Op.TRUNCW ->
    truncw ins bld
  | Op.TRUNCL ->
    truncl ins bld
  | Op.XOR ->
    logXor ins bld
  | Op.XORI ->
    xori ins bld
  | Op.WSBH ->
    wsbh ins bld
  | Op.BC3F | Op.BC3FL | Op.BC3T | Op.BC3TL ->
    unsupported ins bld
  | o ->
#if DEBUG
    eprintfn "%A" o
#endif
    raise <| NotImplementedIRException(Disasm.opCodeToString o)
