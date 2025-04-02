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

module internal B2R2.FrontEnd.ARM32.OperandHelper

open B2R2
open B2R2.FrontEnd.BinLifter

(* Offset *)
let memOffsetImm offset = OprMemory (OffsetMode (ImmOffset offset))

let memOffsetReg offset = OprMemory (OffsetMode (RegOffset offset))

let memOffsetAlign offset = OprMemory (OffsetMode (AlignOffset offset))

(* Pre-Indexed [<Rn>, #+/-<imm>]! *)
let memPreIdxImm offset = OprMemory (PreIdxMode (ImmOffset offset))

let memPreIdxReg offset = OprMemory (PreIdxMode (RegOffset offset))

let memPreIdxAlign offset = OprMemory (PreIdxMode (AlignOffset offset))

(* Post-Indexed *)
let memPostIdxImm offset = OprMemory (PostIdxMode (ImmOffset offset))

let memPostIdxReg offset = OprMemory (PostIdxMode (RegOffset offset))

let memPostIdxAlign offset = OprMemory (PostIdxMode (AlignOffset offset))

(* Label *)
let memLabel lbl = OprMemory (LiteralMode lbl)

(* Unindexed *)
let memUnIdxImm offset = OprMemory (UnIdxMode offset)

(* SIMD Operand *)
let toSVReg vReg = vReg |> Vector |> SFReg |> OprSIMD

let toSSReg scalar = scalar |> Scalar |> SFReg |> OprSIMD

let inline checkUnpred cond = if cond then raise UnpredictableException else ()

let inline checkUndef cond = if cond then raise UndefinedException else ()

let oneDt dt = Some (OneDT dt)

let twoDt (dt1, dt2) = Some (TwoDT (dt1, dt2))

let getSign s = if s = 1u then Plus else Minus

let getEndian = function
  | 0b0uy -> Endian.Little
  | _ (* 1 *) -> Endian.Big

let getRegister n: Register = n |> int |> LanguagePrimitives.EnumOfValue

let rec private getRegListLoop acc b = function
  | n when n > 15 -> acc
  | n when ((b >>> n) &&& 1u) <> 0u ->
    getRegListLoop (getRegister (uint32 n) :: acc) b (n + 1)
  | n -> getRegListLoop acc b (n + 1)

let inline getRegList b =
  getRegListLoop [] b 0 |> List.rev

(* SIMD vector register list *)
let getSIMDVector rLst =
  match rLst with
  | [ vt ] -> OneReg (Vector vt)
  | [ vt; vt2 ] -> TwoRegs (Vector vt, Vector vt2)
  | [ vt; vt2; vt3 ] -> ThreeRegs (Vector vt, Vector vt2, Vector vt3)
  | [ vt; vt2; vt3; vt4 ] ->
    FourRegs (Vector vt, Vector vt2, Vector vt3, Vector vt4)
  | _ -> raise ParsingFailureException
  |> OprSIMD

(* SIMD scalar list *)
let getSIMDScalar idx rLst =
  let s v = Scalar (v, idx)
  match rLst with
  | [ vt ] -> OneReg (s vt)
  | [ vt; vt2 ] -> TwoRegs (s vt, s vt2)
  | [ vt; vt2; vt3 ] -> ThreeRegs (s vt, s vt2, s vt3)
  | [ vt; vt2; vt3; vt4 ] -> FourRegs (s vt, s vt2, s vt3, s vt4)
  | _ -> raise ParsingFailureException
  |> OprSIMD

let getVFPSRegister = function
  | 0x00uy -> R.S0
  | 0x01uy -> R.S1
  | 0x02uy -> R.S2
  | 0x03uy -> R.S3
  | 0x04uy -> R.S4
  | 0x05uy -> R.S5
  | 0x06uy -> R.S6
  | 0x07uy -> R.S7
  | 0x08uy -> R.S8
  | 0x09uy -> R.S9
  | 0x0Auy -> R.S10
  | 0x0Buy -> R.S11
  | 0x0Cuy -> R.S12
  | 0x0Duy -> R.S13
  | 0x0Euy -> R.S14
  | 0x0Fuy -> R.S15
  | 0x10uy -> R.S16
  | 0x11uy -> R.S17
  | 0x12uy -> R.S18
  | 0x13uy -> R.S19
  | 0x14uy -> R.S20
  | 0x15uy -> R.S21
  | 0x16uy -> R.S22
  | 0x17uy -> R.S23
  | 0x18uy -> R.S24
  | 0x19uy -> R.S25
  | 0x1Auy -> R.S26
  | 0x1Buy -> R.S27
  | 0x1Cuy -> R.S28
  | 0x1Duy -> R.S29
  | 0x1Euy -> R.S30
  | 0x1Fuy -> R.S31
  | _ -> raise InvalidRegisterException

let getVFPDRegister = function
  | 0x00uy -> R.D0
  | 0x01uy -> R.D1
  | 0x02uy -> R.D2
  | 0x03uy -> R.D3
  | 0x04uy -> R.D4
  | 0x05uy -> R.D5
  | 0x06uy -> R.D6
  | 0x07uy -> R.D7
  | 0x08uy -> R.D8
  | 0x09uy -> R.D9
  | 0x0Auy -> R.D10
  | 0x0Buy -> R.D11
  | 0x0Cuy -> R.D12
  | 0x0Duy -> R.D13
  | 0x0Euy -> R.D14
  | 0x0Fuy -> R.D15
  | 0x10uy -> R.D16
  | 0x11uy -> R.D17
  | 0x12uy -> R.D18
  | 0x13uy -> R.D19
  | 0x14uy -> R.D20
  | 0x15uy -> R.D21
  | 0x16uy -> R.D22
  | 0x17uy -> R.D23
  | 0x18uy -> R.D24
  | 0x19uy -> R.D25
  | 0x1Auy -> R.D26
  | 0x1Buy -> R.D27
  | 0x1Cuy -> R.D28
  | 0x1Duy -> R.D29
  | 0x1Euy -> R.D30
  | 0x1Fuy -> R.D31
  | 0x20uy -> R.FPINST2 (* VTBL, VTBX only *)
  | 0x21uy -> R.MVFR0
  | 0x22uy -> R.MVFR1
  | _ -> raise InvalidRegisterException
