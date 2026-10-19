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
/// Encodes the rest of the vector facility's instructions in primary opcode
/// 4: the forms the processors after the first vector units added, and the
/// ones the older encoders here had left out.
/// </summary>
module internal B2R2.Assembly.PPC.AsmVMX

open B2R2.FrontEnd.PPC
open B2R2.Assembly.PPC.ParserHelper
open B2R2.Assembly.PPC.AsmField
open B2R2.Assembly.PPC.AsmVector

/// The packs and unpacks beside the modulo ones the older encoders have --
/// the saturating packs, the doubleword packs and the pixel forms -- and the
/// multiply-sums and multiply-adds.
let private packAndSumEncoders () =
  [ Op.VPKUHUS, vx 142u
    Op.VPKUWUS, vx 206u
    Op.VPKSHSS, vx 398u
    Op.VPKSWSS, vx 462u
    Op.VPKSHUS, vx 270u
    Op.VPKSWUS, vx 334u
    Op.VPKPX, vx 782u
    Op.VUPKHPX, vx2 846u
    Op.VUPKLPX, vx2 974u
    Op.VPKUDUM, vx 1102u
    Op.VPKSDSS, vx 1486u
    Op.VPKSDUS, vx 1358u
    Op.VPKUDUS, vx 1230u
    Op.VMSUMCUD, va 23u
    Op.VMHADDSHS, va 32u
    Op.VMHRADDSHS, va 33u
    Op.VMLADDUHM, va 34u
    Op.VMSUMUDM, va 35u
    Op.VMSUMUBM, va 36u
    Op.VMSUMMBM, va 37u
    Op.VMSUMUHM, va 38u
    Op.VMSUMUHS, va 39u
    Op.VMSUMSHM, va 40u
    Op.VMSUMSHS, va 41u ]

/// The even and odd multiplies, whose products are twice as wide as the
/// elements multiplied.
let private multiplyEncoders () =
  [ Op.VMULEUB, vx 520u
    Op.VMULOUB, vx 8u
    Op.VMULESB, vx 776u
    Op.VMULOSB, vx 264u
    Op.VMULEUH, vx 584u
    Op.VMULOUH, vx 72u
    Op.VMULESH, vx 840u
    Op.VMULOSH, vx 328u
    Op.VMULEUW, vx 648u
    Op.VMULOUW, vx 136u
    Op.VMULEUD, vx 712u
    Op.VMULOUD, vx 200u
    Op.VMULESD, vx 968u
    Op.VMULOSD, vx 456u ]

/// Every instruction of primary opcode 4 the older encoders leave out.
let vmxEncoders () =
  List.concat
    [ packAndSumEncoders ()
      multiplyEncoders () ]
