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

namespace B2R2.FrontEnd.ARM64

open System.Collections.Generic
open B2R2

/// <summary>
/// The operations the aliases of SYS name, by the op1, CRn, CRm and op2 they
/// are encoded with: DC's, AT's, IC's and TLBI's, and the one context CFP,
/// DVP and CPP restrict prediction by (DDI0487F.c C6.2.75 DC, C6.2.19 AT,
/// C6.2.95 IC, C6.2.328 TLBI, C6.2.51 CFP, C6.2.83 DVP and C6.2.65 CPP).
///
/// <para>An instruction names a DC operation by its opcode, as this front end
/// always has; the others it keeps as their encoding, the fourteen bits
/// op1:CRn:CRm:op2 at 18:5, in an OprSysOp. Decoding, printing and assembling
/// all read this one table, so they cannot disagree; the names are the
/// manual's.</para>
/// </summary>
module SysOp =
  /// <summary>
  /// One operation: the opcode an instruction naming it has, the mnemonic it
  /// is written with, its name, its encoding, whether it reads the register
  /// the instruction carries -- one that does not still has the field, which
  /// the syntax leaves out where it holds 11111 -- and the version that
  /// brought it.
  /// </summary>
  type Entry =
    { Opcode: Opcode
      Mnemonic: string
      Name: string
      Encoding: uint32
      TakesRegister: bool
      Since: ARMArchVersion }

  let private make opcode mnemonic name (op1, crn, crm, op2) reads since =
    { Opcode = opcode
      Mnemonic = mnemonic
      Name = name
      Encoding = (op1 <<< 11) ||| (crn <<< 7) ||| (crm <<< 3) ||| op2
      TakesRegister = reads
      Since = since }

  let private v8 = ARMArchVersion.V8

  let private dc opcode name op1 crm op2 since =
    make opcode "dc" name (op1, 7u, crm, op2) true since

  /// DC's operations: the eight Armv8.0 has, FEAT_MTE's, which work on
  /// allocation tags as well, and FEAT_DPB's and FEAT_DPB2's cleans to the
  /// points of persistence (C6.2.75).
  let private dataCache =
    let mte = ARMArchVersion.V8_5
    [ dc Opcode.DCIVAC "IVAC" 0u 6u 1u v8
      dc Opcode.DCISW "ISW" 0u 6u 2u v8
      dc Opcode.DCCSW "CSW" 0u 10u 2u v8
      dc Opcode.DCCISW "CISW" 0u 14u 2u v8
      dc Opcode.DCZVA "ZVA" 3u 4u 1u v8
      dc Opcode.DCCVAC "CVAC" 3u 10u 1u v8
      dc Opcode.DCCVAU "CVAU" 3u 11u 1u v8
      dc Opcode.DCCIVAC "CIVAC" 3u 14u 1u v8
      dc Opcode.DCIGVAC "IGVAC" 0u 6u 3u mte
      dc Opcode.DCIGSW "IGSW" 0u 6u 4u mte
      dc Opcode.DCIGDVAC "IGDVAC" 0u 6u 5u mte
      dc Opcode.DCIGDSW "IGDSW" 0u 6u 6u mte
      dc Opcode.DCCGSW "CGSW" 0u 10u 4u mte
      dc Opcode.DCCGDSW "CGDSW" 0u 10u 6u mte
      dc Opcode.DCCIGSW "CIGSW" 0u 14u 4u mte
      dc Opcode.DCCIGDSW "CIGDSW" 0u 14u 6u mte
      dc Opcode.DCGVA "GVA" 3u 4u 3u mte
      dc Opcode.DCGZVA "GZVA" 3u 4u 4u mte
      dc Opcode.DCCGVAC "CGVAC" 3u 10u 3u mte
      dc Opcode.DCCGDVAC "CGDVAC" 3u 10u 5u mte
      dc Opcode.DCCGVAP "CGVAP" 3u 12u 3u mte
      dc Opcode.DCCGDVAP "CGDVAP" 3u 12u 5u mte
      dc Opcode.DCCGVADP "CGVADP" 3u 13u 3u mte
      dc Opcode.DCCGDVADP "CGDVADP" 3u 13u 5u mte
      dc Opcode.DCCIGVAC "CIGVAC" 3u 14u 3u mte
      dc Opcode.DCCIGDVAC "CIGDVAC" 3u 14u 5u mte
      dc Opcode.DCCVAP "CVAP" 3u 12u 1u ARMArchVersion.V8_2
      dc Opcode.DCCVADP "CVADP" 3u 13u 1u ARMArchVersion.V8_5 ]

  let private at name op1 crm op2 since =
    make Opcode.AT "at" name (op1, 7u, crm, op2) true since

  /// AT's, C7 with CRm 100x; the two that respect PAN are FEAT_PAN2's
  /// (C6.2.19).
  let private translations =
    [ at "S1E1R" 0u 8u 0u v8
      at "S1E1W" 0u 8u 1u v8
      at "S1E0R" 0u 8u 2u v8
      at "S1E0W" 0u 8u 3u v8
      at "S1E2R" 4u 8u 0u v8
      at "S1E2W" 4u 8u 1u v8
      at "S12E1R" 4u 8u 4u v8
      at "S12E1W" 4u 8u 5u v8
      at "S12E0R" 4u 8u 6u v8
      at "S12E0W" 4u 8u 7u v8
      at "S1E3R" 6u 8u 0u v8
      at "S1E3W" 6u 8u 1u v8
      at "S1E1RP" 0u 9u 0u ARMArchVersion.V8_2
      at "S1E1WP" 0u 9u 1u ARMArchVersion.V8_2 ]

  /// IC's (C6.2.95): the two that invalidate everything read no register.
  let private instructionCache =
    [ make Opcode.IC "ic" "IALLUIS" (0u, 7u, 1u, 0u) false v8
      make Opcode.IC "ic" "IALLU" (0u, 7u, 5u, 0u) false v8
      make Opcode.IC "ic" "IVAU" (3u, 7u, 5u, 1u) true v8 ]

  (* The TLBI operations that take an address or an ASID from the register,
     which is all of them but the ones invalidating everything at a level. *)
  let private tlbi (name: string) op1 crm op2 since =
    let reads = not (name.StartsWith "ALL" || name.StartsWith "VMALL")
    make Opcode.TLBI "tlbi" name (op1, 8u, crm, op2) reads since

  /// TLBI's: Armv8.0's, then FEAT_TLBIOS's outer-shareable forms and
  /// FEAT_TLBIRANGE's range forms, both Armv8.4's (C6.2.328).
  let private tlbMaintenance =
    let v84 = ARMArchVersion.V8_4
    [ tlbi "VMALLE1IS" 0u 3u 0u v8
      tlbi "VAE1IS" 0u 3u 1u v8
      tlbi "ASIDE1IS" 0u 3u 2u v8
      tlbi "VAAE1IS" 0u 3u 3u v8
      tlbi "VALE1IS" 0u 3u 5u v8
      tlbi "VAALE1IS" 0u 3u 7u v8
      tlbi "VMALLE1" 0u 7u 0u v8
      tlbi "VAE1" 0u 7u 1u v8
      tlbi "ASIDE1" 0u 7u 2u v8
      tlbi "VAAE1" 0u 7u 3u v8
      tlbi "VALE1" 0u 7u 5u v8
      tlbi "VAALE1" 0u 7u 7u v8
      tlbi "IPAS2E1IS" 4u 0u 1u v8
      tlbi "IPAS2LE1IS" 4u 0u 5u v8
      tlbi "ALLE2IS" 4u 3u 0u v8
      tlbi "VAE2IS" 4u 3u 1u v8
      tlbi "ALLE1IS" 4u 3u 4u v8
      tlbi "VALE2IS" 4u 3u 5u v8
      tlbi "VMALLS12E1IS" 4u 3u 6u v8
      tlbi "IPAS2E1" 4u 4u 1u v8
      tlbi "IPAS2LE1" 4u 4u 5u v8
      tlbi "ALLE2" 4u 7u 0u v8
      tlbi "VAE2" 4u 7u 1u v8
      tlbi "ALLE1" 4u 7u 4u v8
      tlbi "VALE2" 4u 7u 5u v8
      tlbi "VMALLS12E1" 4u 7u 6u v8
      tlbi "ALLE3IS" 6u 3u 0u v8
      tlbi "VAE3IS" 6u 3u 1u v8
      tlbi "VALE3IS" 6u 3u 5u v8
      tlbi "ALLE3" 6u 7u 0u v8
      tlbi "VAE3" 6u 7u 1u v8
      tlbi "VALE3" 6u 7u 5u v8
      tlbi "VMALLE1OS" 0u 1u 0u v84
      tlbi "VAE1OS" 0u 1u 1u v84
      tlbi "ASIDE1OS" 0u 1u 2u v84
      tlbi "VAAE1OS" 0u 1u 3u v84
      tlbi "VALE1OS" 0u 1u 5u v84
      tlbi "VAALE1OS" 0u 1u 7u v84
      tlbi "ALLE2OS" 4u 1u 0u v84
      tlbi "VAE2OS" 4u 1u 1u v84
      tlbi "ALLE1OS" 4u 1u 4u v84
      tlbi "VALE2OS" 4u 1u 5u v84
      tlbi "VMALLS12E1OS" 4u 1u 6u v84
      tlbi "IPAS2E1OS" 4u 4u 0u v84
      tlbi "IPAS2LE1OS" 4u 4u 4u v84
      tlbi "ALLE3OS" 6u 1u 0u v84
      tlbi "VAE3OS" 6u 1u 1u v84
      tlbi "VALE3OS" 6u 1u 5u v84
      tlbi "RVAE1IS" 0u 2u 1u v84
      tlbi "RVAAE1IS" 0u 2u 3u v84
      tlbi "RVALE1IS" 0u 2u 5u v84
      tlbi "RVAALE1IS" 0u 2u 7u v84
      tlbi "RVAE1OS" 0u 5u 1u v84
      tlbi "RVAAE1OS" 0u 5u 3u v84
      tlbi "RVALE1OS" 0u 5u 5u v84
      tlbi "RVAALE1OS" 0u 5u 7u v84
      tlbi "RVAE1" 0u 6u 1u v84
      tlbi "RVAAE1" 0u 6u 3u v84
      tlbi "RVALE1" 0u 6u 5u v84
      tlbi "RVAALE1" 0u 6u 7u v84
      tlbi "RIPAS2E1IS" 4u 0u 2u v84
      tlbi "RIPAS2LE1IS" 4u 0u 6u v84
      tlbi "RVAE2IS" 4u 2u 1u v84
      tlbi "RVALE2IS" 4u 2u 5u v84
      tlbi "RIPAS2E1" 4u 4u 2u v84
      tlbi "RIPAS2E1OS" 4u 4u 3u v84
      tlbi "RIPAS2LE1" 4u 4u 6u v84
      tlbi "RIPAS2LE1OS" 4u 4u 7u v84
      tlbi "RVAE2OS" 4u 5u 1u v84
      tlbi "RVALE2OS" 4u 5u 5u v84
      tlbi "RVAE2" 4u 6u 1u v84
      tlbi "RVALE2" 4u 6u 5u v84
      tlbi "RVAE3IS" 6u 2u 1u v84
      tlbi "RVALE3IS" 6u 2u 5u v84
      tlbi "RVAE3OS" 6u 5u 1u v84
      tlbi "RVALE3OS" 6u 5u 5u v84
      tlbi "RVAE3" 6u 6u 1u v84
      tlbi "RVALE3" 6u 6u 5u v84 ]

  /// FEAT_SPECRES's three restrictions of prediction, each by the one
  /// context RCTX names, Armv8.5's (C6.2.51, C6.2.83, C6.2.65).
  let private predictionRestrictions =
    let v85 = ARMArchVersion.V8_5
    [ make Opcode.CFP "cfp" "RCTX" (3u, 7u, 3u, 4u) true v85
      make Opcode.DVP "dvp" "RCTX" (3u, 7u, 3u, 5u) true v85
      make Opcode.CPP "cpp" "RCTX" (3u, 7u, 3u, 7u) true v85 ]

  /// Every operation the aliases name.
  let all =
    dataCache @ translations @ instructionCache @ tlbMaintenance
    @ predictionRestrictions

  let private byEncoding =
    let d = Dictionary<uint32, Entry>()
    for e in all do d[e.Encoding] <- e
    d

  let private byOpcode =
    let d = Dictionary<Opcode, Entry>()
    for e in dataCache do d[e.Opcode] <- e
    d

  /// The operation the fourteen bits op1:CRn:CRm:op2 name, if they name one.
  let tryOfEncoding enc =
    match byEncoding.TryGetValue enc with
    | true, e -> Some e
    | _ -> None

  /// The DC operation an opcode is, if it is one.
  let tryOfDataCacheOpcode opcode =
    match byOpcode.TryGetValue opcode with
    | true, e -> Some e
    | _ -> None

  /// The operation a mnemonic names by a name, if it names one by it.
  let tryFind mnemonic (name: string) =
    let name = name.ToUpperInvariant()
    all |> List.tryFind (fun e -> e.Mnemonic = mnemonic && e.Name = name)
