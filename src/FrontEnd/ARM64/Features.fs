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

/// <summary>
/// Which version of the architecture, and which of its OPTIONAL features, an
/// A64 instruction needs, as DDI0487F.c A2 lays them out -- so that an ISA
/// naming a version refuses what the version does not have.
/// </summary>
module internal B2R2.FrontEnd.ARM64.Features

open System
open B2R2
open B2R2.FrontEnd.BinLifter

/// What an encoding needs of the ISA it is read under.
type Requirement =
  /// Nothing beyond Armv8.0.
  | Base
  /// An OPTIONAL feature: named as an extension, or made mandatory by a
  /// version.
  | Needs of AArch64Extension
  /// A feature every processor of a version has, and no version below leaves
  /// OPTIONAL.
  | Since of ARMArchVersion
  /// Both of these.
  | Both of Requirement * Requirement
  /// A feature of a version above Armv8.6, which no version here has.
  | Later

/// <summary>
/// The OPTIONAL features each version makes mandatory: FEAT_CRC32, FEAT_LSE
/// and FEAT_RDM at Armv8.1; FEAT_RAS at Armv8.2; FEAT_LRCPC and FEAT_PAuth
/// at Armv8.3;
/// FEAT_DotProd and FEAT_FlagM at Armv8.4; FEAT_SB and FEAT_SSBS at
/// Armv8.5; and FEAT_BF16 and FEAT_I8MM at Armv8.6.
/// </summary>
let private mandatory (version: ARMArchVersion) =
  let from v (exts: AArch64Extension) =
    if version >= v then exts else AArch64Extension.None
  from ARMArchVersion.V8_1
    (AArch64Extension.CRC ||| AArch64Extension.LSE ||| AArch64Extension.RDMA)
  ||| from ARMArchVersion.V8_2 AArch64Extension.RAS
  ||| from ARMArchVersion.V8_3
        (AArch64Extension.RCPC ||| AArch64Extension.PAuth)
  ||| from ARMArchVersion.V8_4
        (AArch64Extension.DotProd ||| AArch64Extension.FlagM)
  ||| from ARMArchVersion.V8_5
        (AArch64Extension.SB ||| AArch64Extension.SSBS)
  ||| from ARMArchVersion.V8_6
        (AArch64Extension.BF16 ||| AArch64Extension.I8MM)

/// <summary>
/// The features an ISA has: the ones its extensions name, the ones its version
/// makes mandatory, and the ones those bring. FEAT_FHM cannot be had without
/// FEAT_FP16, Armv8.4 makes FEAT_FHM mandatory wherever FEAT_FP16 is had,
/// and FEAT_SHA512 and FEAT_SHA3 need FEAT_SHA1 and FEAT_SHA256.
/// </summary>
let private featuresOf (isa: ISA) =
  let named = isa.AArch64Extensions ||| mandatory isa.ARMArchVersion
  let has (ext: AArch64Extension) = (named &&& ext) = ext
  let bring cond (ext: AArch64Extension) =
    if cond then ext else AArch64Extension.None
  named
  ||| bring (has AArch64Extension.FP16FML) AArch64Extension.FP16
  ||| bring (has AArch64Extension.FP16
             && isa.ARMArchVersion >= ARMArchVersion.V8_4)
        AArch64Extension.FP16FML
  ||| bring (has AArch64Extension.SHA3) AArch64Extension.SHA2

let rec private isMet (isa: ISA) req =
  match req with
  | Base -> true
  | Needs ext -> (featuresOf isa &&& ext) = ext
  | Since version -> isa.ARMArchVersion >= version
  | Both(r1, r2) -> isMet isa r1 && isMet isa r2
  | Later -> false

/// The opcodes whose names begin with one of the prefixes, for the families
/// whose members are named that way.
let private opcodesNamed (prefixes: string list) =
  Enum.GetValues<Opcode>()
  |> Array.filter (fun o ->
    let name = string o
    List.exists (fun (p: string) -> name.StartsWith p) prefixes)
  |> Set.ofArray

/// The operations of the atomic memory instructions, each of which is an LD
/// form and an ST alias.
let private atomicOperations =
  [ "ADD"; "CLR"; "EOR"; "SET"; "SMAX"; "SMIN"; "UMAX"; "UMIN" ]

/// FEAT_LSE: the compare-and-swaps, SWP and the atomic memory operations.
let private atomics =
  [ "LD"; "ST" ]
  |> List.collect (fun ld -> List.map (fun op -> ld + op) atomicOperations)
  |> List.append [ "CAS"; "SWP" ]
  |> opcodesNamed

/// FEAT_SHA512's and FEAT_SHA3's instructions, which GCC names together.
let private sha3Names = [ "SHA512"; "EOR3"; "BCAX"; "RAX1"; "XAR" ]

/// FEAT_PAuth's instructions, the hint-space ones with the others.
let private pointerAuthNames =
  [ "PAC"; "AUT"; "XPAC"; "BRA"; "BLRA"; "RETA"; "ERETA"; "LDRA" ]

/// <summary>
/// The families whose members are named alike, by the feature they need,
/// from the feature descriptions of DDI0487F.c A2. FEAT_PAuth's hint-space
/// ones, PACIASP and the like, are here like any other: what the hint space
/// does with them is decided by the caller.
/// </summary>
let private namedFamilies =
  [ opcodesNamed [ "CRC32" ], Needs AArch64Extension.CRC
    opcodesNamed [ "AES" ], Needs AArch64Extension.AES
    opcodesNamed [ "SHA1"; "SHA256" ], Needs AArch64Extension.SHA2
    opcodesNamed sha3Names, Needs AArch64Extension.SHA3
    opcodesNamed [ "SM3"; "SM4" ], Needs AArch64Extension.SM4
    atomics, Needs AArch64Extension.LSE
    opcodesNamed [ "LDLAR"; "STLLR" ], Since ARMArchVersion.V8_1
    opcodesNamed pointerAuthNames, Needs AArch64Extension.PAuth
    opcodesNamed [ "LDAPUR"; "STLUR" ], Since ARMArchVersion.V8_4 ]

/// The floating-point instructions whose half-precision forms FEAT_FP16
/// adds. FCVT, FCVTL and FCVTN are not among them: converting to and from a
/// half is Armv8.0's.
let private isHalfCapable opcode =
  match opcode with
  | Opcode.FABD | Opcode.FABS | Opcode.FACGE | Opcode.FACGT | Opcode.FADD
  | Opcode.FADDP | Opcode.FCCMP | Opcode.FCCMPE | Opcode.FCMEQ | Opcode.FCMGE
  | Opcode.FCMGT | Opcode.FCMLE | Opcode.FCMLT | Opcode.FCMP | Opcode.FCMPE
  | Opcode.FCSEL | Opcode.FCVTAS | Opcode.FCVTAU | Opcode.FCVTMS
  | Opcode.FCVTMU | Opcode.FCVTNS | Opcode.FCVTNU | Opcode.FCVTPS
  | Opcode.FCVTPU | Opcode.FCVTZS | Opcode.FCVTZU | Opcode.FDIV
  | Opcode.FMADD | Opcode.FMAX | Opcode.FMAXNM | Opcode.FMAXNMP
  | Opcode.FMAXNMV | Opcode.FMAXP | Opcode.FMAXV | Opcode.FMIN
  | Opcode.FMINNM | Opcode.FMINNMP | Opcode.FMINNMV | Opcode.FMINP
  | Opcode.FMINV | Opcode.FMLA | Opcode.FMLS | Opcode.FMOV | Opcode.FMSUB
  | Opcode.FMUL | Opcode.FMULX | Opcode.FNEG | Opcode.FNMADD | Opcode.FNMSUB
  | Opcode.FNMUL | Opcode.FRECPE | Opcode.FRECPS | Opcode.FRECPX
  | Opcode.FRINTA | Opcode.FRINTI | Opcode.FRINTM | Opcode.FRINTN
  | Opcode.FRINTP | Opcode.FRINTX | Opcode.FRINTZ | Opcode.FRSQRTE
  | Opcode.FRSQRTS | Opcode.FSQRT | Opcode.FSUB | Opcode.SCVTF
  | Opcode.UCVTF | Opcode.FCADD | Opcode.FCMLA ->
    true
  | _ ->
    false

let private isHalfRegister (r: Register) =
  r >= Register.H0 && r <= Register.H31

let private isHalfVector v =
  match v with
  | VecH | TwoH | FourH | EightH -> true
  | _ -> false

let private isHalfOperand opr =
  match opr with
  | OprRegister r | OprSIMD(ScalarReg r) -> isHalfRegister r
  | OprSIMD(VecReg(_, v)) | OprSIMD(VecRegWithIdx(_, v, _)) -> isHalfVector v
  | _ -> false

let private operandList operands =
  match operands with
  | NoOperand -> []
  | OneOperand o1 -> [ o1 ]
  | TwoOperands(o1, o2) -> [ o1; o2 ]
  | ThreeOperands(o1, o2, o3) -> [ o1; o2; o3 ]
  | FourOperands(o1, o2, o3, o4) -> [ o1; o2; o3; o4 ]
  | FiveOperands(o1, o2, o3, o4, o5) -> [ o1; o2; o3; o4; o5 ]

/// FEAT_FP16 where a floating-point instruction reads or writes a half.
let private halfPrecision opcode operands =
  if isHalfCapable opcode
     && List.exists isHalfOperand (operandList operands) then
    Needs AArch64Extension.FP16
  else
    Base

/// PMULL of doublewords into a quadword is FEAT_PMULL's, which comes with
/// FEAT_AES; PMULL of bytes is Armv8.0's.
let private polynomialMultiply operands =
  match operands with
  | ThreeOperands(OprSIMD(VecReg(_, OneQ)), _, _) -> Needs AArch64Extension.AES
  | _ -> Base

/// What an instruction none of the families below names needs: the feature
/// its name puts it in, or FEAT_FP16 where it works on halves, or nothing.
let private namedRequirement opcode operands =
  let isIn (ops: Set<Opcode>, _) = ops.Contains opcode
  match List.tryFind isIn namedFamilies with
  | Some(_, req) -> req
  | None -> halfPrecision opcode operands

/// What a field of PSTATE needs, named either by an MSR (immediate) or by
/// the register that reads it: FEAT_PAN is Armv8.1's, FEAT_UAO Armv8.2's and
/// FEAT_DIT Armv8.4's, and FEAT_SSBS and FEAT_MTE are had by naming them.
let private fieldRequirement opr =
  match opr with
  | OprPstate PAN | OprRegister Register.PAN -> Since ARMArchVersion.V8_1
  | OprPstate UAO | OprRegister Register.UAO -> Since ARMArchVersion.V8_2
  | OprPstate DIT | OprRegister Register.DIT -> Since ARMArchVersion.V8_4
  | OprPstate SSBS | OprRegister Register.SSBS -> Needs AArch64Extension.SSBS
  | OprPstate TCO | OprRegister Register.TCO -> Needs AArch64Extension.MemTag
  | _ -> Base

/// What an MRS or an MSR needs, which is what the field of PSTATE it names
/// needs where it names one.
let private systemRequirement operands =
  match operands with
  | TwoOperands(o1, o2) -> Both(fieldRequirement o1, fieldRequirement o2)
  | _ -> Base

/// <summary>
/// What an instruction needs: the feature its opcode belongs to, and
/// FEAT_FP16 as well where it is a floating-point one working on halves --
/// which FEAT_FCMA's are too, on top of being Armv8.3's. The named hints are
/// here as well; one whose feature is missing is read as the HINT it is
/// encoded as, which every version has.
/// </summary>
let private requirementOf opcode operands =
  match opcode with
  | Opcode.PMULL | Opcode.PMULL2 ->
    polynomialMultiply operands
  | Opcode.FCADD | Opcode.FCMLA ->
    Both(Since ARMArchVersion.V8_3, halfPrecision opcode operands)
  | Opcode.SQRDMLAH | Opcode.SQRDMLSH ->
    Needs AArch64Extension.RDMA
  | Opcode.SDOT | Opcode.UDOT ->
    Needs AArch64Extension.DotProd
  | Opcode.USDOT | Opcode.SUDOT | Opcode.SMMLA | Opcode.UMMLA
  | Opcode.USMMLA ->
    Needs AArch64Extension.I8MM
  | Opcode.BFCVT | Opcode.BFCVTN | Opcode.BFCVTN2 | Opcode.BFDOT
  | Opcode.BFMMLA | Opcode.BFMLALB | Opcode.BFMLALT ->
    Needs AArch64Extension.BF16
  | Opcode.FMLAL | Opcode.FMLAL2 | Opcode.FMLSL | Opcode.FMLSL2 ->
    Needs AArch64Extension.FP16FML
  | Opcode.FJCVTZS ->
    Since ARMArchVersion.V8_3
  | Opcode.LDAPR | Opcode.LDAPRB | Opcode.LDAPRH ->
    Needs AArch64Extension.RCPC
  | Opcode.CFINV | Opcode.RMIF | Opcode.SETF8 | Opcode.SETF16 ->
    Needs AArch64Extension.FlagM
  | Opcode.AXFLAG | Opcode.XAFLAG | Opcode.FRINT32X | Opcode.FRINT32Z
  | Opcode.FRINT64X | Opcode.FRINT64Z ->
    Since ARMArchVersion.V8_5
  | Opcode.SB ->
    Needs AArch64Extension.SB
  | Opcode.ESB ->
    Needs AArch64Extension.RAS
  | Opcode.PSB ->
    Needs AArch64Extension.SPE
  | Opcode.TSB ->
    Needs AArch64Extension.TRF
  | Opcode.BTI ->
    Since ARMArchVersion.V8_5
  | Opcode.IRG | Opcode.GMI | Opcode.ADDG | Opcode.SUBG | Opcode.SUBP
  | Opcode.SUBPS | Opcode.CMPP | Opcode.STG | Opcode.STZG | Opcode.ST2G
  | Opcode.STZ2G | Opcode.STGP | Opcode.LDG | Opcode.LDGM | Opcode.STGM
  | Opcode.STZGM ->
    Needs AArch64Extension.MemTag
  | Opcode.MSR | Opcode.MRS ->
    systemRequirement operands
  | Opcode.CTZ ->
    Later
  | _ ->
    namedRequirement opcode operands

/// Whether a word is in the hint space, HINT #imm, where every value is
/// defined and one whose instruction is not implemented executes as a NOP.
let private isHint (bin: uint32) = (bin &&& 0xfffff01fu) = 0xd503201fu

/// <summary>
/// The instruction a word is under the ISA: itself where the ISA has what it
/// needs; HINT where it does not and the word is in the hint space; and
/// otherwise nothing, since the ISA leaves the word UNDEFINED. An ISA naming
/// no version has everything.
/// </summary>
let check (isa: ISA) bin opcode operands (oprSize: RegType) =
  if isa.ARMArchVersion = ARMArchVersion.Any
     || isMet isa (requirementOf opcode operands) then
    struct (opcode, operands, oprSize)
  elif isHint bin then
    let imm = int64 ((bin >>> 5) &&& 0x7fu)
    struct (Opcode.HINT, OneOperand(OprImm imm), 0<rt>)
  else
    raise ParsingFailureException
