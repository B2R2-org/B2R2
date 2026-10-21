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
/// Decodes the instructions of the Signal Processing Engine, which take
/// primary opcode 4 from the vector facility on the processors that have it.
/// ParsingMain hands a word here first; a word of another primary opcode, or
/// of a processor whose categories do not include the engine, goes on to its
/// own decoder.
/// </summary>
module internal B2R2.FrontEnd.PPC.ParsingSPE

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ParsingUtils
open B2R2.FrontEnd.PPC.OperandHelper

/// The general register a field of the word names.
let private gpr bin hi lo = getRegister (Bits.extract bin hi lo) |> OprReg

/// The registers the three register fields of the word name.
let private rtOf bin = gpr bin 25u 21u

let private raOf bin = gpr bin 20u 16u

let private rbOf bin = gpr bin 15u 11u

/// The unsigned number a field of the word holds.
let private uimm bin hi lo = Bits.extract bin hi lo |> uint64 |> OprImm

/// The signed number a five-bit field of the word holds, as a doubleword.
let private simm5 bin hi lo =
  Bits.extract bin hi lo |> uint64 |> Bits.signExtend 5 64 |> uint64 |> OprImm

/// A field of the word a form keeps reserved, which is zero where the
/// instruction is valid.
let private reserved bin hi lo =
  if Bits.extract bin hi lo <> 0u then raise ParsingFailureException else ()

/// An EVX-form "RT, RA, RB".
let private rrr op bin =
  struct (op, ThreeOperands(rtOf bin, raOf bin, rbOf bin))

/// An EVX-form "RT, RA" whose RB field is reserved.
let private rr op bin =
  reserved bin 15u 11u
  struct (op, TwoOperands(rtOf bin, raOf bin))

/// An EVX-form "RT, RB" whose RA field is reserved.
let private rb op bin =
  reserved bin 20u 16u
  struct (op, TwoOperands(rtOf bin, rbOf bin))

/// An EVX-form "RT, RB, UI" whose UI is in the RA field.
let private rbUi op bin =
  struct (op, ThreeOperands(rtOf bin, rbOf bin, uimm bin 20u 16u))

/// An EVX-form "RT, UI, RB" whose UI is in the RA field.
let private uiRb op bin =
  struct (op, ThreeOperands(rtOf bin, uimm bin 20u 16u, rbOf bin))

/// An EVX-form "RT, RA, UI" whose UI is in the RB field.
let private raUi op bin =
  struct (op, ThreeOperands(rtOf bin, raOf bin, uimm bin 15u 11u))

/// An EVX-form "RT, SI" whose SI is in the RA field and whose RB field is
/// reserved.
let private si op bin =
  reserved bin 15u 11u
  struct (op, TwoOperands(rtOf bin, simm5 bin 20u 16u))

/// An EVX-form "BF, RA, RB" whose two bits below BF are reserved.
let private crf op bin =
  reserved bin 22u 21u
  let bf = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
  struct (op, ThreeOperands(bf, raOf bin, rbOf bin))

/// An EVS-form "RT, RA, RB, BFA", the CR field in the low three bits.
let private sel op bin =
  let bfa = getCondRegister (Bits.extract bin 2u 0u) |> OprReg
  struct (op, FourOperands(rtOf bin, raOf bin, rbOf bin, bfa))

/// An EVX-form access "RT, D(RA)" whose five-bit UI is scaled by the size of
/// what the instruction reaches.
let private disp op size bin =
  let d = int (Bits.extract bin 15u 11u) * size
  let ra = getRegister (Bits.extract bin 20u 16u)
  struct (op, TwoOperands(rtOf bin, OprMem(d, ra)))

/// The instruction a word of primary opcode 4 is, by the eleven bits
/// below the register fields.
let private parseWord bin =
  match Bits.extract bin 10u 0u with
  | 512u -> rrr Op.EVADDW bin
  | 514u -> rbUi Op.EVADDIW bin
  | 516u -> rrr Op.EVSUBFW bin
  | 518u -> uiRb Op.EVSUBIFW bin
  | 520u -> rr Op.EVABS bin
  | 521u -> rr Op.EVNEG bin
  | 522u -> rr Op.EVEXTSB bin
  | 523u -> rr Op.EVEXTSH bin
  | 524u -> rr Op.EVRNDW bin
  | 525u -> rr Op.EVCNTLZW bin
  | 526u -> rr Op.EVCNTLSW bin
  | 527u -> rrr Op.BRINC bin
  | 529u -> rrr Op.EVAND bin
  | 530u -> rrr Op.EVANDC bin
  | 534u -> rrr Op.EVXOR bin
  | 535u -> rrr Op.EVOR bin
  | 536u -> rrr Op.EVNOR bin
  | 537u -> rrr Op.EVEQV bin
  | 539u -> rrr Op.EVORC bin
  | 542u -> rrr Op.EVNAND bin
  | 544u -> rrr Op.EVSRWU bin
  | 545u -> rrr Op.EVSRWS bin
  | 546u -> raUi Op.EVSRWIU bin
  | 547u -> raUi Op.EVSRWIS bin
  | 548u -> rrr Op.EVSLW bin
  | 550u -> raUi Op.EVSLWI bin
  | 552u -> rrr Op.EVRLW bin
  | 553u -> si Op.EVSPLATI bin
  | 554u -> raUi Op.EVRLWI bin
  | 555u -> si Op.EVSPLATFI bin
  | 556u -> rrr Op.EVMERGEHI bin
  | 557u -> rrr Op.EVMERGELO bin
  | 558u -> rrr Op.EVMERGEHILO bin
  | 559u -> rrr Op.EVMERGELOHI bin
  | 560u -> crf Op.EVCMPGTU bin
  | 561u -> crf Op.EVCMPGTS bin
  | 562u -> crf Op.EVCMPLTU bin
  | 563u -> crf Op.EVCMPLTS bin
  | 564u -> crf Op.EVCMPEQ bin
  | 644u -> rr Op.EVFSABS bin
  | 645u -> rr Op.EVFSNABS bin
  | 646u -> rr Op.EVFSNEG bin
  | 708u -> rr Op.EFSABS bin
  | 709u -> rr Op.EFSNABS bin
  | 710u -> rr Op.EFSNEG bin
  | 740u -> rr Op.EFDABS bin
  | 741u -> rr Op.EFDNABS bin
  | 742u -> rr Op.EFDNEG bin
  | 768u -> rrr Op.EVLDDX bin
  | 769u -> disp Op.EVLDD 8 bin
  | 770u -> rrr Op.EVLDWX bin
  | 771u -> disp Op.EVLDW 8 bin
  | 772u -> rrr Op.EVLDHX bin
  | 773u -> disp Op.EVLDH 8 bin
  | 776u -> rrr Op.EVLHHESPLATX bin
  | 777u -> disp Op.EVLHHESPLAT 2 bin
  | 780u -> rrr Op.EVLHHOUSPLATX bin
  | 781u -> disp Op.EVLHHOUSPLAT 2 bin
  | 782u -> rrr Op.EVLHHOSSPLATX bin
  | 783u -> disp Op.EVLHHOSSPLAT 2 bin
  | 784u -> rrr Op.EVLWHEX bin
  | 785u -> disp Op.EVLWHE 4 bin
  | 788u -> rrr Op.EVLWHOUX bin
  | 789u -> disp Op.EVLWHOU 4 bin
  | 790u -> rrr Op.EVLWHOSX bin
  | 791u -> disp Op.EVLWHOS 4 bin
  | 792u -> rrr Op.EVLWWSPLATX bin
  | 793u -> disp Op.EVLWWSPLAT 4 bin
  | 796u -> rrr Op.EVLWHSPLATX bin
  | 797u -> disp Op.EVLWHSPLAT 4 bin
  | 800u -> rrr Op.EVSTDDX bin
  | 801u -> disp Op.EVSTDD 8 bin
  | 802u -> rrr Op.EVSTDWX bin
  | 803u -> disp Op.EVSTDW 8 bin
  | 804u -> rrr Op.EVSTDHX bin
  | 805u -> disp Op.EVSTDH 8 bin
  | 816u -> rrr Op.EVSTWHEX bin
  | 817u -> disp Op.EVSTWHE 4 bin
  | 820u -> rrr Op.EVSTWHOX bin
  | 821u -> disp Op.EVSTWHO 4 bin
  | 824u -> rrr Op.EVSTWWEX bin
  | 825u -> disp Op.EVSTWWE 4 bin
  | 828u -> rrr Op.EVSTWWOX bin
  | 829u -> disp Op.EVSTWWO 4 bin
  | 1027u -> rrr Op.EVMHESSF bin
  | 1031u -> rrr Op.EVMHOSSF bin
  | 1032u -> rrr Op.EVMHEUMI bin
  | 1033u -> rrr Op.EVMHESMI bin
  | 1035u -> rrr Op.EVMHESMF bin
  | 1036u -> rrr Op.EVMHOUMI bin
  | 1037u -> rrr Op.EVMHOSMI bin
  | 1039u -> rrr Op.EVMHOSMF bin
  | 1059u -> rrr Op.EVMHESSFA bin
  | 1063u -> rrr Op.EVMHOSSFA bin
  | 1064u -> rrr Op.EVMHEUMIA bin
  | 1065u -> rrr Op.EVMHESMIA bin
  | 1067u -> rrr Op.EVMHESMFA bin
  | 1068u -> rrr Op.EVMHOUMIA bin
  | 1069u -> rrr Op.EVMHOSMIA bin
  | 1071u -> rrr Op.EVMHOSMFA bin
  | 1095u -> rrr Op.EVMWHSSF bin
  | 1096u -> rrr Op.EVMWLUMI bin
  | 1100u -> rrr Op.EVMWHUMI bin
  | 1101u -> rrr Op.EVMWHSMI bin
  | 1103u -> rrr Op.EVMWHSMF bin
  | 1107u -> rrr Op.EVMWSSF bin
  | 1112u -> rrr Op.EVMWUMI bin
  | 1113u -> rrr Op.EVMWSMI bin
  | 1115u -> rrr Op.EVMWSMF bin
  | 1127u -> rrr Op.EVMWHSSFA bin
  | 1128u -> rrr Op.EVMWLUMIA bin
  | 1132u -> rrr Op.EVMWHUMIA bin
  | 1133u -> rrr Op.EVMWHSMIA bin
  | 1135u -> rrr Op.EVMWHSMFA bin
  | 1139u -> rrr Op.EVMWSSFA bin
  | 1144u -> rrr Op.EVMWUMIA bin
  | 1145u -> rrr Op.EVMWSMIA bin
  | 1147u -> rrr Op.EVMWSMFA bin
  | 1216u -> rr Op.EVADDUSIAAW bin
  | 1217u -> rr Op.EVADDSSIAAW bin
  | 1218u -> rr Op.EVSUBFUSIAAW bin
  | 1219u -> rr Op.EVSUBFSSIAAW bin
  | 1220u -> rr Op.EVMRA bin
  | 1222u -> rrr Op.EVDIVWS bin
  | 1223u -> rrr Op.EVDIVWU bin
  | 1224u -> rr Op.EVADDUMIAAW bin
  | 1225u -> rr Op.EVADDSMIAAW bin
  | 1226u -> rr Op.EVSUBFUMIAAW bin
  | 1227u -> rr Op.EVSUBFSMIAAW bin
  | 1280u -> rrr Op.EVMHEUSIAAW bin
  | 1281u -> rrr Op.EVMHESSIAAW bin
  | 1283u -> rrr Op.EVMHESSFAAW bin
  | 1284u -> rrr Op.EVMHOUSIAAW bin
  | 1285u -> rrr Op.EVMHOSSIAAW bin
  | 1287u -> rrr Op.EVMHOSSFAAW bin
  | 1288u -> rrr Op.EVMHEUMIAAW bin
  | 1289u -> rrr Op.EVMHESMIAAW bin
  | 1291u -> rrr Op.EVMHESMFAAW bin
  | 1292u -> rrr Op.EVMHOUMIAAW bin
  | 1293u -> rrr Op.EVMHOSMIAAW bin
  | 1295u -> rrr Op.EVMHOSMFAAW bin
  | 1320u -> rrr Op.EVMHEGUMIAA bin
  | 1321u -> rrr Op.EVMHEGSMIAA bin
  | 1323u -> rrr Op.EVMHEGSMFAA bin
  | 1324u -> rrr Op.EVMHOGUMIAA bin
  | 1325u -> rrr Op.EVMHOGSMIAA bin
  | 1327u -> rrr Op.EVMHOGSMFAA bin
  | 1344u -> rrr Op.EVMWLUSIAAW bin
  | 1345u -> rrr Op.EVMWLSSIAAW bin
  | 1352u -> rrr Op.EVMWLUMIAAW bin
  | 1353u -> rrr Op.EVMWLSMIAAW bin
  | 1363u -> rrr Op.EVMWSSFAA bin
  | 1368u -> rrr Op.EVMWUMIAA bin
  | 1369u -> rrr Op.EVMWSMIAA bin
  | 1371u -> rrr Op.EVMWSMFAA bin
  | 1408u -> rrr Op.EVMHEUSIANW bin
  | 1409u -> rrr Op.EVMHESSIANW bin
  | 1411u -> rrr Op.EVMHESSFANW bin
  | 1412u -> rrr Op.EVMHOUSIANW bin
  | 1413u -> rrr Op.EVMHOSSIANW bin
  | 1415u -> rrr Op.EVMHOSSFANW bin
  | 1416u -> rrr Op.EVMHEUMIANW bin
  | 1417u -> rrr Op.EVMHESMIANW bin
  | 1419u -> rrr Op.EVMHESMFANW bin
  | 1420u -> rrr Op.EVMHOUMIANW bin
  | 1421u -> rrr Op.EVMHOSMIANW bin
  | 1423u -> rrr Op.EVMHOSMFANW bin
  | 1448u -> rrr Op.EVMHEGUMIAN bin
  | 1449u -> rrr Op.EVMHEGSMIAN bin
  | 1451u -> rrr Op.EVMHEGSMFAN bin
  | 1452u -> rrr Op.EVMHOGUMIAN bin
  | 1453u -> rrr Op.EVMHOGSMIAN bin
  | 1455u -> rrr Op.EVMHOGSMFAN bin
  | 1472u -> rrr Op.EVMWLUSIANW bin
  | 1473u -> rrr Op.EVMWLSSIANW bin
  | 1480u -> rrr Op.EVMWLUMIANW bin
  | 1481u -> rrr Op.EVMWLSMIANW bin
  | 1491u -> rrr Op.EVMWSSFAN bin
  | 1496u -> rrr Op.EVMWUMIAN bin
  | 1497u -> rrr Op.EVMWSMIAN bin
  | 1499u -> rrr Op.EVMWSMFAN bin
  | xo when xo >>> 3 = 79u -> sel Op.EVSEL bin
  | _ -> raise ParsingFailureException

/// Whether the categories give primary opcode 4 to the Signal Processing
/// Engine.
let private hasSignalProcessing category =
  Category.includes Category.SignalProcessing category

/// The instruction a word is, if it is one this module takes on a processor
/// implementing the categories given.
let tryParse category bin =
  match bin >>> 26 with
  | 4u when hasSignalProcessing category -> ValueSome(parseWord bin)
  | _ -> ValueNone
