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

module internal B2R2.FrontEnd.ARM32.ARMValidator

#if !EMULATION
open B2R2.FrontEnd.ARM32.ParseUtils
open B2R2.FrontEnd.ARM32.OperandHelper
open B2R2.FrontEnd.ARM32.OperandParsingHelper

(* if n == 15 then UNPREDICTABLE *)
let chkPCRn bin = checkUnpred (extract bin 19 16 = 15u)

(* if n == 15 then UNPREDICTABLE *)
let chkPCRnB bin = checkUnpred (extract bin 3 0 = 15u)

(* if wback && (n == 15 || n == t) then UNPREDICTABLE *)
let chkPCRnWithWB bin =
  let n = extract bin 19 16
  let t = extract bin 15 12
  checkUnpred (wback bin && (n = 15u || n = t))

(* if t == 15 then UNPREDICTABLE
   if wback && (n == 15 || n == t) then UNPREDICTABLE *)
let chkPCRnRtWithWB bin =
  let t = extract bin 15 12
  let n = extract bin 19 16
  checkUnpred ((t = 15u) || ((wback bin) && (n = 15u || n = t)))

(* if t == 15 || wback then UNPREDICTABLE *)
let chkPCRtWithWB bin = checkUnpred ((extract bin 15 12 = 15u) || wback bin)

(* if t == 15 || (wback && n == t) then UNPREDICTABLE *)
let chkPCRtRnWithWB bin =
  let t = extract bin 15 12
  checkUnpred (t = 15u || (wback bin && (extract bin 19 16 = t)))

(* if n == 15 || n == t then UNPREDICTABLE *)
let chkPCRnRt bin =
  let n = extract bin 19 16
  checkUnpred (n = 15u || n = extract bin 15 12)

(* if t == 15 || n == 15 || n == t then UNPREDICTABLE *)
let chkPCRtRnEq bin =
  let n = extract bin 19 16
  let t = extract bin 15 12
  checkUnpred (t = 15u || n = 15u || n = t)

(* if t == 15 || n == 15 then UNPREDICTABLE *)
let chkPCRtRn bin =
  checkUnpred (extract bin 15 12 = 15u || extract bin 19 16 = 15u)

(* if d == 15 || Rt<0> == '1' || t2 == 15 || n == 15 then UNPREDICTABLE
   if d == n || d == t || d == t2 then UNPREDICTABLE *)
let chkPCRdRt2Rn bin =
  let d = extract bin 15 12
  let n = extract bin 19 16
  let t = extract bin 3 0
  checkUnpred (((d = 15u) || (pickBit t 0 = 1u) || (t + 1u = 15u) || (n = 15u))
              || ((d = n) || (d = t) || (d = t + 1u)))

(* if Rt<0> == '1' || t2 == 15 || n == 15 then UNPREDICTABLE *)
let chkPCRt2Rn bin =
  let t = extract bin 3 0
  checkUnpred (((pickBit t 0 = 1u) || (t + 1u = 15u) ||
                (extract bin 19 16 = 15u)))

(* if d == 15 || t == 15 || n == 15 then UNPREDICTABLE
   if d == n || d == t then UNPREDICTABLE *)
let chkPCRdRtRn bin =
  let d = extract bin 15 12
  let n = extract bin 19 16
  let t = extract bin 3 0
  checkUnpred (((d = 15u) || (t = 15u) || (n = 15u)) || ((d = n) || (d = t)))

(* if m == 15 then UNPREDICTABLE
   if wback && (n == 15 || n == t) then UNPREDICTABLE *)
let chkPCRmRn bin =
  let n = extract bin 19 16
  ((extract bin 3 0 = 15u) ||
   (wback bin && (n = 15u || n = extract bin 15 12))) |> checkUnpred

(* if n == 15 || n == t || m == 15 then UNPREDICTABLE *)
let chkPCRnRm bin =
  let n = extract bin 19 16
  checkUnpred (n = 15u || n = extract bin 15 12 || extract bin 3 0 = 15u)

(* if d == 15 || n == 15 || m == 15 then UNPREDICTABLE *)
let chkPCRdRnRm bin =
  ((extract bin 19 16 = 15u) || (extract bin 3 0 = 15u) ||
   (extract bin 11 8 = 15u)) |> checkUnpred

(* if d == 15 || n == 15 || m == 15 then UNPREDICTABLE *)
let chkPCRdOptRnRm bin =
  ((extract bin 15 12 = 15u) || (extract bin 19 16 = 15u) ||
   (extract bin 3 0 = 15u)) |> checkUnpred

(* if d == 15 || n == 15 then UNPREDICTABLE *)
let chkPCRdRn bin =
  checkUnpred ((extract bin 15 12 = 15u) || (extract bin 3 0 = 15u))

(* if d == 15 || n == 15 || m == 15 || a == 15 then UNPREDICTABLE *)
let chkPCRdRnRmRa bin =
  checkUnpred ((extract bin 19 16 = 15u) || (extract bin 3 0 = 15u) ||
              (extract bin 11 8 = 15u) || (extract bin 15 12 = 15u))

(* if d == 15 || n == 15 || m == 15 || a != 15 then UNPREDICTABLE *)
let chkPCRdRnRmRaNot bin =
  checkUnpred ((extract bin 19 16 = 15u) || (extract bin 3 0 = 15u) ||
              (extract bin 11 8 = 15u) || (extract bin 15 12 <> 15u))

(* if dLo == 15 || dHi == 15 || n == 15 || m == 15 then UNPREDICTABLE
   if dHi == dLo then UNPREDICTABLE *)
let chkPCRdlRdhRnRm bin =
  let dLo = extract bin 15 12
  let dHi = extract bin 19 16
  checkUnpred (((dLo = 15u) || (dHi = 15u) || (extract bin 3 0 = 15u) ||
                (extract bin 11 8 = 15u)) || (dHi = dLo))

(* if t == 15 || n == 15 || n == t || m == 15 then UNPREDICTABLE *)
let chkPCRtRnRm bin =
  let n = extract bin 19 16
  let t = extract bin 15 12
  checkUnpred (t = 15u || n = 15u || n = t || extract bin 3 0 = 15u)

(* if t == 15 || m == 15 then UNPREDICTABLE
   if wback && (n == 15 || n == t) then UNPREDICTABLE *)
let chkPCRtRm bin =
  let n = extract bin 19 16
  let t = extract bin 15 12
  ((t = 15u || extract bin 3 0 = 15u) || (wback bin && (n = 15u || n = t)))
  |> checkUnpred

(* if Rt<0> == '1' then UNPREDICTABLE
   if t2 == 15 then UNPREDICTABLE *)
let chkRtPCRt2 bin =
  checkUnpred ((pickBit bin 12 = 1u) || (extract bin 15 12 + 1u = 15u))

(* if Rt<0> == '1' then UNPREDICTABLE
   if t2 == 15 || m == 15 || m == t || m == t2 then UNPREDICTABLE
   if wback && (n == 15 || n == t || n == t2) then UNPREDICTABLE *)
let chkPCRt2RmRnEq bin =
  let m = extract bin 3 0
  let t = extract bin 15 12
  let n = extract bin 19 16
  let t2 = t + 1u
  ((pickBit bin 12 = 1u) || (t2 = 15u || m = 15u || m = t || m = t2) ||
   ((wback bin) && (n = 15u || n = t || n = t2))) |> checkUnpred

(* if Rt<0> == '1' then UNPREDICTABLE
   if t2 == 15 || m == 15 then UNPREDICTABLE
   if wback && (n == 15 || n == t || n == t2) then UNPREDICTABLE *)
let chkPCRt2RmRn bin =
  let n = extract bin 19 16
  let t2 = (extract bin 15 12) + 1u
  ((pickBit bin 12 = 1u) || (t2 = 15u || extract bin 3 0 = 15u) ||
   (wback bin && (n = 15u || n = extract bin 15 12 || n = t2))) |> checkUnpred

(* if mask == '0000' then UNPREDICTABLE *)
let chkMask bin = checkUnpred (extract bin 19 16 = 0b0000u)

(* if wback && n == t then UNPREDICTABLE *)
let chkRnRt bin =
  checkUnpred ((wback bin) && (extract bin 19 16 = extract bin 15 12))

(* if wback then UNPREDICTABLE *)
let chkWback bin = checkUnpred (wback bin)

(* if n == 15 || BitCount(registers) < 1 then UNPREDICTABLE *)
let chkPCRnRegs bin =
  checkUnpred (extract bin 19 16 = 15u || (extract bin 15 0 = 0u))

(* if n == 15 || BitCount(registers) < 1 then UNPREDICTABLE
   if wback && registers<n> == '1' then UNPREDICTABLE *)
let chkWBRegs bin =
  let n = extract bin 19 16 |> int
  ((n = 15 || (extract bin 15 0 = 0u)) ||
   (wbackW bin && (pickBit bin n = 1u))) |> checkUnpred

(* if Rt<0> == '1' then UNPREDICTABLE
   if wback && (n == t || n == t2) then UNPREDICTABLE
   if t2 == 15 then UNPREDICTABLE *)
let chkRnRtPCRt2 bin =
  let n = extract bin 19 16
  let t2 = (extract bin 15 12) + 1u
  checkUnpred ((pickBit (extract bin 15 12) 0 = 1u) ||
              (wback bin && (n = extract bin 15 12 || n = t2)) || (t2 = 15u))

(* if Rt<0> == '1' then UNPREDICTABLE
   if wback && (n == 15 || n == t || n == t2) then UNPREDICTABLE
   if t2 == 15 then UNPREDICTABLE *)
let chkPCRnRt2 bin =
  let n = extract bin 19 16
  let t2 = (extract bin 15 12) + 1u
  ((pickBit bin 12 = 1u) ||
   (wback bin && ((n = 15u) || (n = extract bin 15 12) || (n = t2))) ||
   (t2 = 15u)) |> checkUnpred

(* if d == 15 || m == 15 then UNPREDICTABLE *)
let chkPCRdRm bin =
  checkUnpred ((extract bin 15 12 = 15u) || (extract bin 3 0 = 15u))

(* if m == 15 then UNPREDICTABLE *)
let chkPCRm bin = checkUnpred (extract bin 3 0 = 15u)

(* if d == 15 then UNPREDICTABLE *)
let chkPCRd bin = checkUnpred (extract bin 15 12 = 15u)

(* if mask == '0000' then UNPREDICTABLE
   if n == 15 then UNPREDICTABLE *)
let chkMaskPCRn bin =
  checkUnpred ((extract bin 19 16 = 0b0000u) || (extract bin 3 0 = 15u))

(* if d == 15 || n == 15 || m == 15 || s == 15 then UNPREDICTABLE *)
let chkPCRdRnRmRs bin =
  ((extract bin 15 12 = 15u) || (extract bin 19 16 = 15u) ||
    (extract bin 3 0 = 15u) || (extract bin 11 8 = 15u)) |> checkUnpred

(* if d == 15 || m == 15 || s == 15 then UNPREDICTABLE *)
let chkPCRdRmRs bin =
  ((extract bin 15 12 = 15u) || (extract bin 3 0 = 15u) ||
   (extract bin 11 8 = 15u)) |> checkUnpred

(* if n == 15 || m == 15 || s == 15 then UNPREDICTABLE *)
let chkPCRnRmRs bin =
  ((extract bin 19 16 = 15u) || (extract bin 3 0 = 15u) ||
   (extract bin 11 8 = 15u)) |> checkUnpred

(* if d == 15 || n == 15 || m == 15 then UNPREDICTABLE
   if cond != '1110' then UNPREDICTABLE *)
let chkPCRdRnRmSz bin cond =
  ((extract bin 15 12 = 15u || extract bin 19 16 = 15u ||
    extract bin 3 0 = 15u) || (cond <> Condition.AL)) |> checkUnpred

(* if cond != '1110' then UNPREDICTABLE *)
let chkCondAL cond = checkUnpred (cond <> Condition.AL)

(* if t == 15 || t2 == 15 || m == 31 then UNPREDICTABLE
   if to_arm_registers && t == t2 then UNPREDICTABLE *)
let chkPCRtRt2VmRegsEq bin =
  let sm = concat (extract bin 3 0) (pickBit bin 5) 1 (* Vm:M *)
  let t = extract bin 15 12
  let t2 = extract bin 19 16
  ((t = 15u || t2 = 15u || sm = 31u) || (pickBit bin 20 = 1u && t = t2))
  |> checkUnpred

(* Armv8-A removes UNPREDICTABLE for R13
   if t == 15 || t2 == 15 then UNPREDICTABLE
   if to_arm_registers && t == t2 then UNPREDICTABLE *)
let chkPCRtRt2ArmEq bin =
  let t = extract bin 15 12
  let t2 = extract bin 19 16
  checkUnpred ((t = 15u || t2 = 15u) || (pickBit bin 20 = 1u && t = t2))

(* Armv8-A removes UNPREDICTABLE for R13
   if t == 15 || t2 == 15 || t == t2 then UNPREDICTABLE *)
let chkPCRtRt2Eq bin =
  let t = extract bin 15 12
  let t2 = extract bin 19 16
  checkUnpred ((t = 15u) || (t2 = 15u) || (t = t2))

(* Armv8-A removes UNPREDICTABLE for R13
   if t == 15 || t2 == 15 then UNPREDICTABLE *)
let chkPCRtRt2 bin =
  checkUnpred (extract bin 15 12 = 15u || (extract bin 19 16 = 15u))

(* if n == 15 && (wback || CurrentInstrSet() != InstrSet_A32) then UNPREDICTABLE
   if regs == 0 || (d+regs) > 32 then UNPREDICTABLE *)
let chkPCRnDRegs bin =
  let regs = extract bin 7 0
  let d = concat (extract bin 15 12) (pickBit bin 22) 1 (* Vd:D *)
  ((extract bin 19 16 = 15u && wbackW bin) || (regs = 0u || d + regs > 32u))
  |> checkUnpred

(* if n == 15 && (wback || CurrentInstrSet() != InstrSet_A32) then UNPREDICTABLE
   if regs == 0 || regs > 16 || (d+regs) > 32 then UNPREDICTABLE
   if imm8<0> == '1' && (d+regs) > 16 then UNPREDICTABLE *)
let chkPCRnRegsImm bin =
  let regs = (extract bin 7 0) / 2u
  let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
  ((extract bin 19 16 = 15u && wbackW bin) ||
   (regs = 0u || regs > 16u || d + regs > 32u) ||
   ((pickBit bin 0 = 1u) && (d + regs > 16u))) |> checkUnpred

(* if size == '01' && cond != '1110' then UNPREDICTABLE
   if n == 15 && CurrentInstrSet() != InstrSet_A32 then UNPREDICTABLE *)
let chkSzCondPCRn bin cond =
  (((extract bin 9 8 = 0b01u) && (cond <> Condition.AL)) ||
   (extract bin 19 16 = 15u (* && != InstrSet_A32 *))) |> checkUnpred

(* if size == '01' && cond != '1110' then UNPREDICTABLE *)
let chkSzCond bin cond =
  checkUnpred ((extract bin 9 8 = 0b01u) && (cond <> Condition.AL))

(* if n == 15 && (wback || CurrentInstrSet() != InstrSet_A32)
   then UNPREDICTABLE *)
let chkPCRnWback bin = checkUnpred ((extract bin 19 16 = 15u) && (wbackW bin))

(* if t == 15 then UNPREDICTABLE *)
let chkPCRt bin = checkUnpred (extract bin 15 12 = 15u)

(* if t == 15 && reg != '0001' then UNPREDICTABLE *)
let chkPCRtR1 bin =
  let reg = extract bin 19 16
  checkUnpred (extract bin 15 12 = 15u && reg <> 0b0001u)

(* if cond != '1110' then UNPREDICTABLE
   if t == 15 then UNPREDICTABLE *)
let chkCondPCRt bin cond =
  checkUnpred (cond <> Condition.AL || extract bin 15 12 = 15u)

(* is_pldw = (R == '0') *)
(* if m == 15 || (n == 15 && is_pldw) then UNPREDICTABLE *)
let chkPCRmRnPldw bin =
  ((extract bin 3 0 = 15u) ||
   ((extract bin 19 16 = 15u) && (pickBit bin 22 = 0u))) |> checkUnpred

(* if Q == '1' && Vd<0> == '1' then UNDEFINED *)
let chkQVd bin = checkUndef ((pickBit bin 6 = 0b1u) && (pickBit bin 12 = 0b1u))

(* if Vd<0> == '1' || Vn<0> == '1' then UNDEFINED *)
let chkVdVn bin = checkUndef (pickBit bin 16 = 1u || pickBit bin 12 = 1u)

(* if size == '11' then UNDEFINED
   if n == 15 || d4 > 31 then UNPREDICTABLE *)
let chkSzPCRnD4 bin =
  let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
  let inc =
    match extract bin 11 8 (* itype *) with
    | 0b0000u | 0b0100u -> 1u
    | _ -> 2u
  let d4 = d + inc + inc + inc
  checkUndef (extract bin 7 6 = 0b11u)
  checkUnpred ((extract bin 19 16 = 15u) || (d4 > 31u))

(* if n == 15 || d+regs > 32 then UNPREDICTABLE *)
let chkPCRnDregs bin =
  let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
  checkUnpred ((extract bin 19 16 = 15u) || (d + 4u > 32u))

(* if size == '11' then UNDEFINED
   if n == 15 || d2+regs > 32 then UNPREDICTABLE *)
let chkPCRnD2regs bin =
  let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
  let inc =
    match extract bin 11 8 (* itype *) with
    | 0b0000u | 0b0100u -> 1u
    | _ -> 2u
  let d2 = d + inc
  checkUndef (extract bin 7 6 = 0b11u)
  checkUnpred ((extract bin 19 16 = 15u) || (d2 + 2u > 32u))

(* if size == '11' || align<1> == '1' then UNDEFINED
   if n == 15 || d3 > 31 then UNPREDICTABLE *)
let chkPCRnD3 bin =
  let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
  let inc =
    match extract bin 11 8 (* itype *) with
    | 0b0000u | 0b0100u -> 1u
    | _ -> 2u
  let d3 = d + inc + inc
  checkUndef ((extract bin 7 6 = 0b11u) || (pickBit bin 5 = 1u))
  checkUnpred ((extract bin 19 16 = 15u) || (d3 > 31u))

(* if align<1> == '1' then UNDEFINED
   if n == 15 || d+regs > 32 then UNPREDICTABLE *)
let chkAlign1PCRnDregs bin regs =
  let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
  checkUndef (pickBit bin 5 = 1u)
  checkUnpred ((extract bin 19 16 = 15u) || (d + regs > 32u))

(* if align == '11' then UNDEFINED
   if n == 15 || d+regs > 32 then UNPREDICTABLE *)
let chkAlignPCRnDregs bin =
  let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
  checkUndef (extract bin 5 4 = 0b11u)
  checkUnpred ((extract bin 19 16 = 15u) || (d + 2u > 32u))

(* if align == '11' then UNDEFINED
   if size == '11' then UNDEFINED
   if n == 15 || d2+regs > 32 then UNPREDICTABLE *)
let chkAlignPCRnD2regs bin =
  let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
  let inc =
    match extract bin 11 8 (* itype *) with
    | 0b0000u | 0b0100u -> 1u
    | _ -> 2u
  let d2 = d + inc
  checkUndef ((extract bin 5 4 = 0b11u) || (extract bin 7 6 = 0b11u))
  checkUnpred ((extract bin 19 16 = 15u) || (d2 + 1u > 32u))

(* if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED
   if Q == '0' && imm4<3> == '1' then UNDEFINED *)
let chkQVdImm bin =
  let q = pickBit bin 6 (* Q *)
  ((q = 1u && (pickBit bin 12 = 1u || pickBit bin 16 = 1u ||
     pickBit bin 0 = 1u)) || (q = 0u && pickBit bin 11 = 1u)) |> checkUndef

(* if n+length > 32 then UNPREDICTABLE *)
let chkPCRnLen bin =
  let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
  checkUnpred (n + (extract bin 9 8 + 1u) > 32u)

(* if Vd<0> == '1' || (op == '1' && Vn<0> == '1') then UNDEFINED *)
let chkVdOpVn bin =
  (pickBit bin 12 = 1u || (pickBit bin 8 = 1u && pickBit bin 16 = 1u))
  |> checkUndef

(* if Vn<0> == '1' || Vm<0> == '1' then UNDEFINED *)
let chkVnVm bin = checkUndef (pickBit bin 16 = 1u || pickBit bin 0 = 1u)

(* if size == '00' || Vd<0> == '1' then UNDEFINED *)
let chkSzVd bin =
  checkUndef ((extract bin 21 20 = 0b00u) || (pickBit bin 12 = 1u))

(* if Vn<0> == '1' then UNDEFINED *)
let chkVd0 bin = checkUndef (pickBit bin 12 = 1u)

(* if size == '00' ||
   if Q == '1' && (Vd<0> == '1' || Vn<0> == '1') then UNDEFINED *)
let chkSzQVdVn bin =
  ((extract bin 21 20 = 0b00u) ||
   ((pickBit bin 24 = 1u) && (pickBit bin 12 = 1u || pickBit bin 16 = 1u)))
   |> checkUndef

(* if size == '11' || (size == '00' && a == '1') then UNDEFINED
   if n == 15 || d+regs > 32 then UNPREDICTABLE *)
let chkSzAPCRnDregs bin =
  let size = extract bin 7 6 (* size *)
  let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
  let regs = if pickBit bin 5 (* T *) = 0u then 1u else 2u
  checkUndef ((size = 0b11u) || ((size = 0b00u) && (pickBit bin 4 = 1u)))
  checkUnpred ((extract bin 19 16 = 15u) || ((d + regs) > 32u))

(* if size == '11' then UNDEFINED
   if n == 15 || d2 > 31 then UNPREDICTABLE *)
let chkSzPCRnD2 bin =
  let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
  let inc = if pickBit bin 5 (* T *) = 0u then 1u else 2u
  let d2 = d + inc
  checkUndef (extract bin 7 6 = 0b11u)
  checkUnpred (extract bin 19 16 = 15u || d2 > 31u)

(* if size == '11' || a == '1' then UNDEFINED
   if n == 15 || d3 > 31 then UNPREDICTABLE *)
let chkSzAPCRnD3 bin =
  let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
  let inc = if pickBit bin 5 (* T *) = 0u then 1u else 2u
  let d3 = d + inc + inc
  checkUndef (extract bin 7 6 = 0b11u || pickBit bin 4 = 1u)
  checkUnpred (extract bin 19 16 = 15u || d3 > 31u)

(* if size == '11' && a == '0' then UNDEFINED
   if n == 15 || d4 > 31 then UNPREDICTABLE *)
let chkSzAPCRnD4 bin =
  let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
  let inc = if pickBit bin 5 (* T *) = 0u then 1u else 2u
  let d4 = d + inc + inc + inc
  checkUndef (extract bin 7 6 = 0b11u && pickBit bin 4 = 0u)
  checkUnpred (extract bin 19 16 = 15u || d4 > 31u)

(* if size == '11' then UNDEFINED
   if index_align<0> != '0' then UNDEFINED
   if n == 15 then UNPREDICTABLE *)
let chkSzIdx0PCRn bin =
  checkUndef ((extract bin 11 10 = 0b11u) || (pickBit bin 4 <> 0u))
  checkUnpred (extract bin 19 16 = 15u)

(* if size == '11' then UNDEFINED
   if index_align<1> != '0' then UNDEFINED
   if n == 15 then UNPREDICTABLE *)
let chkSzIdx1PCRn bin =
  checkUndef ((extract bin 11 10 = 0b11u) || (pickBit bin 5 <> 0u))
  checkUnpred (extract bin 19 16 = 15u)

(* if size == '11' then UNDEFINED
   if index_align<2> != '0' then UNDEFINED
   if index_align<1:0> != '00' && index_align<1:0> != '11' then UNDEFINED
   if n == 15 then UNPREDICTABLE *)
let chkSzIdx2PCRn bin =
  checkUndef ((extract bin 11 10 = 0b11u) || (pickBit bin 6 <> 0u) ||
             (extract bin 5 4 <> 0b00u && extract bin 5 4 <> 0b11u))
  checkUnpred (extract bin 19 16 = 15u)

let inc bin =
  match extract bin 11 10 (* size *) with
  | 0b00u -> 1u
  | 0b01u -> if pickBit bin 5 (* index_align<1> *) = 0u then 1u else 2u
  | 0b10u -> if pickBit bin 6 (* index_align<2> *) = 0u then 1u else 2u
  | _ -> raise UndefinedException

(* if n == 15 || d2 > 31 then UNPREDICTABLE *)
let chkPCRnD2 bin =
  let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
  let d2 = d + (inc bin)
  checkUnpred ((extract bin 19 16 = 15u) || (d2 > 31u))

(* if index_align<0> != '0' then UNDEFINED
   if n == 15 || d3 > 31 then UNPREDICTABLE *)
let chkIdx0PCRnD3 bin =
  let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
  let inc = inc bin
  let d3 = d + inc + inc
  checkUndef (pickBit bin 4 <> 0u)
  checkUnpred ((extract bin 19 16 = 15u) || (d3 > 31u))

(* if index_align<1> != '0' then UNDEFINED
   if n == 15 || d2 > 31 then UNPREDICTABLE *)
let chkIdxPCRnD2 bin =
  let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
  let inc = inc bin
  let d2 = d + inc
  checkUndef (pickBit bin 5 (* index_align<1> *) <> 0u)
  checkUnpred ((extract bin 19 16 = 15u) || (d2 > 31u))

(* if index_align<1:0> != '00' then UNDEFINED
   if n == 15 || d3 > 31 then UNPREDICTABLE *)
let chkIdx10PCRnD3 bin =
  let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
  let inc = inc bin
  let d3 = d + inc + inc
  checkUndef (extract bin 5 4 (* index_align<1:0> *) <> 0b00u)
  checkUnpred ((extract bin 19 16 = 15u) || (d3 > 31u))

(* if n == 15 || d4 > 31 then UNPREDICTABLE *)
let chkPCRnD4 bin =
  let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
  let inc = inc bin
  let d4 = d + inc + inc + inc
  checkUnpred ((extract bin 19 16 = 15u) || (d4 > 31u))

(* if index_align<1:0> == '11' then UNDEFINED
   if n == 15 || d4 > 31 then UNPREDICTABLE *)
let chkIdxPCRnD4 bin =
  let d = concat (pickBit bin 22) (extract bin 15 12) 4 (* D:Vd *)
  let inc = inc bin
  let d4 = d + inc + inc + inc
  checkUndef (extract bin 5 4 (* index_align<1:0> *) = 0b11u)
  checkUnpred ((extract bin 19 16 = 15u) || (d4 > 31u))

(* if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED *)
let chkQVdVm bin =
  ((pickBit bin 6 (* Q *) = 1u) &&
   ((pickBit bin 12 (* Vd<0> *) = 1u) || (pickBit bin 0 (* Vm<0> *) = 1u)))
   |> checkUndef

(* Vd<0> == '1' || Vm<0> == '1' then UNDEFINED *)
let chkVdVm bin =
  ((pickBit bin 12 (* Vd<0> *) = 1u) || (pickBit bin 0 (* Vm<0> *) = 1u))
  |> checkUndef

(* if Vm<0> == '1' then UNDEFINED *)
let chkVm bin = pickBit bin 0 (* Vm<0> *) = 1u |> checkUndef

(* if Vd<0> == '1' then UNDEFINED *)
let chkVd bin = pickBit bin 12 (* Vd<0> *) = 1u |> checkUndef

(* if U == '0' && op == '0' then UNDEFINED
   if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED *)
let chkUOpQVdVm bin =
  (((pickBit bin 24 (* U *) = 0u) && (pickBit bin 8 (* op *) = 0u)) ||
   (pickBit bin 6 (* Q *) = 1u) &&
    ((pickBit bin 12 (* Vd<0> *) = 1u) || (pickBit bin 0 (* Vm<0> *) = 1u)))
    |> checkUndef

(* if UInt(op)+UInt(size) >= 3 then UNDEFINED
   if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED *)
let chkOpSzQVdVm bin =
  ((extract bin 8 7 + extract bin 19 18 >= 3u) ||
   (pickBit bin 6 (* Q *) = 1u) &&
    ((pickBit bin 12 (* Vd<0> *) = 1u) || (pickBit bin 0 (* Vm<0> *) = 1u)))
    |> checkUndef

(* if t == 15 || t2 == 15 || n == 15 || n == t || n == t2 then UNPREDICTABLE *)
let chkPCRtRt2Rn bin =
  let t = extract bin 15 12
  let t2 = extract bin 3 0
  let n = extract bin 19 16
  ((t = 15u) || (t2 = 15u) || (n = 15u) || (n = t) || (n = t2)) |> checkUnpred

(* if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1')
   then UNDEFINED *)
let chkQVdVnVm bin = (* chkQVdVmVn *)
  ((pickBit bin 6 = 1u) &&
   ((pickBit bin 12 = 1u) || (pickBit bin 16 = 1u) || (pickBit bin 0 = 1u)))
   |> checkUndef

(* if Q == '1' && (Vd<0> == '1' || Vn<0> == '1') then UNDEFINED *)
let chkQVdVn bin =
  ((pickBit bin 6 = 1u) && ((pickBit bin 12 = 1u) || (pickBit bin 16 = 1u)))
  |> checkUndef

(* if size == '00' then UNDEFINED
   if Q == '1' && (Vd<0> == '1' || Vn<0> == '1') then UNDEFINED *)
let chkQVdVnSz bin =
  ((extract bin 21 20 = 0b00u) ||
   (pickBit bin 24 = 1u) && ((pickBit bin 12 = 1u) || (pickBit bin 16 = 1u)))
   |> checkUndef

(* if P == '0' && U == '0' && D == '0' && W == '0' then UNDEFINED
   if coproc IN "101x" then UNDEFINED
   if n == 15 && (wback || CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE
*)
let chkPUDWCopPCRn bin =
  let cop = extract bin 11 8
  checkUndef ((extract bin 24 21 = 0b0000u) || (cop = 0b1010u || cop = 0b1011u))
  checkUnpred (extract bin 19 16 = 15u && wbackW bin)

(* if Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1' then UNDEFINED *)
let chkVdVnVm bin =
  ((pickBit bin 12 = 1u) || (pickBit bin 16 = 1u) || (pickBit bin 0 = 1u))
  |> checkUndef

(* if op<1> == '0' && imm6 == '10xxxx' then UNDEFINED
   if imm6 == '0xxxxx' then UNDEFINED
   if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED *)
let chkOpImm6QVdVm bin =
  ((pickBit bin 9 = 0u && extract bin 21 20 = 0b10u) ||
   (pickBit bin 21 = 0u) ||
   (pickBit bin 6 = 1u && (pickBit bin 12 = 1u || pickBit bin 0 = 1u)))
   |> checkUndef

(* if n == 15 || BitCount(registers) < 2 then UNPREDICTABLE
  if wback && registers<n> == '1' then UNPREDICTABLE
  if registers<13> == '1' then UNPREDICTABLE
  if registers<15> == '1' then UNPREDICTABLE *)
let chkPCRnRegsWBRegs bin =
  let n = extract bin 19 16 |> int
  ((n = 15 || (bitCount (extract bin 15 0) 15 < 2)) ||
   (wbackW bin && (pickBit bin n = 1u)) || (pickBit bin 13 = 1u) ||
   (pickBit bin 15 = 1u)) |> checkUnpred

(* if n < 8 && m < 8 then UNPREDICTABLE
   if n == 15 || m == 15 then UNPREDICTABLE *)
let chkNMPCRnRm bin =
  let n = concat (pickBit bin 7) (extract bin 2 0) 3 (* N:Rn *)
  let m = extract bin 6 3 (* Rm *)
  ((n < 8u && m < 8u) || (n = 15u || m = 15u)) |> checkUnpred

(* if n == 15 || BitCount(registers) < 2 || (P == '1' && M == '1') then
     UNPREDICTABLE
   if wback && registers<n> == '1' then UNPREDICTABLE
   if registers<13> == '1' then UNPREDICTABLE
   if registers<15> == '1' && InITBlock() && !LastInITBlock() then UNPREDICTABLE
*)
let chkPCRnRegsPMWback bin itstate =
  let n = extract bin 19 16 |> int
  ((n = 15 || bitCount (extract bin 15 0) 15 < 2 ||
    (pickBit bin 15 = 1u && pickBit bin 14 = 1u)) ||
    (wbackW bin && pickBit bin n = 1u) || (pickBit bin 13 = 1u) ||
    (pickBit bin 15 = 1u && inITBlock itstate && lastInITBlock itstate |> not))
    |> checkUnpred

(* if n == 15 then UNPREDICTABLE
   if InITBlock() && !LastInITBlock() then UNPREDICTABLE *)
let chkPCRnIT bin itstate =
  (extract bin 19 16 = 15u ||
   (inITBlock itstate && lastInITBlock itstate |> not))
   |> checkUnpred

(* if firstcond == '1111' || (firstcond == '1110' && BitCount(mask) != 1)
     then UNPREDICTABLE
   if InITBlock() then UNPREDICTABLE *)
let chkFstCondIT bin itstate =
  ((extract bin 7 4 (* firstcond *) = 0b1111u ||
    (extract bin 7 4 = 0b1110u && bitCount (extract bin 3 0 (* mask *)) 3 <> 1))
    || (inITBlock itstate)) |> checkUnpred

(* if A:I:F == '000' then UNPREDICTABLE
   if InITBlock() then UNPREDICTABLE *)
let chkAIFIT bin itstate =
  (extract bin 2 0 = 0b000u && inITBlock itstate) |> checkUnpred

(* if InITBlock() && !LastInITBlock() then UNPREDICTABLE *)
let chkInITLastIT itstate =
  (inITBlock itstate && lastInITBlock itstate |> not) |> checkUnpred

(* if m == 15 then UNPREDICTABLE
   if InITBlock() && !LastInITBlock() then UNPREDICTABLE *)
let chkPCRmIT16 bin itstate =
  ((extract bin 6 3 = 15u) ||
   (inITBlock itstate && lastInITBlock itstate |> not)) |> checkUnpred

(* if m == 15 then UNPREDICTABLE
   if InITBlock() && !LastInITBlock() then UNPREDICTABLE *)
let chkPCRmIT32 bin itstate =
  ((extract bin 3 0 = 15u) ||
   (inITBlock itstate && lastInITBlock itstate |> not)) |> checkUnpred

(* if n != 14 then UNPREDICTABLE
   if InITBlock() && !LastInITBlock() then UNPREDICTABLE *)
let chkRnIT bin itstate =
  ((extract bin 19 16 <> 14u) ||
   (inITBlock itstate && lastInITBlock itstate |> not)) |> checkUnpred

(* if H = '1' then UNPREDICTABLE
   if InITBlock() && !LastInITBlock() then UNPREDICTABLE *)
let chkHInLastIT bin itstate =
  ((pickBit bin 0 = 1u) ||
   (inITBlock itstate && lastInITBlock itstate |> not)) |> checkUnpred

(* if d == 15 && InITBlock() && !LastInITBlock() then UNPREDICTABLE *)
let chkPCRdIT bin itstate =
  let d = concat (pickBit bin 7) (extract bin 2 0) 3 (* DM:Rdm *)
  (d = 15u && inITBlock itstate && lastInITBlock itstate |> not)
  |> checkUnpred

(* if d == 15 && InITBlock() && !LastInITBlock() then UNPREDICTABLE *)
let chkPCDRdIT bin itstate =
  let d = concat (pickBit bin 7) (extract bin 2 0) 3 (* D:Rd *)
  (d = 15u && inITBlock itstate && lastInITBlock itstate |> not) |> checkUnpred

(* if n == 15 && m == 15 then UNPREDICTABLE
   if d == 15 && InITBlock() && !LastInITBlock() then UNPREDICTABLE *)
let chkPCRnRmRdIT bin itstate =
  let d = concat (pickBit bin 7) (extract bin 2 0) 3 (* DN:Rdn *)
  ((d (* n = d *) = 15u && extract bin 6 3 = 15u) ||
   (d = 15u && inITBlock itstate && lastInITBlock itstate |> not))
   |> checkUnpred

(* if BitCount(registers) < 1 then UNPREDICTABLE;
   if registers<15> == '1' && InITBlock() && !LastInITBlock() then UNPREDICTABLE
*)
let chkRegsIT bin itstate =
  ((concat (pickBit bin 8 <<< 7) (extract bin 7 0) 8 (* registers *) = 0u) ||
   (pickBit bin 8 = 1u && inITBlock itstate && lastInITBlock itstate |> not))
   |> checkUnpred

(* if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED
   if sz == '1' && InITBlock() then UNPREDICTABLE *)
let chkQVdVnVmSzIT bin itstate =
  ((pickBit bin 6 = 1u) &&
   (pickBit bin 12 = 1u || pickBit bin 16 = 1u || pickBit bin 0 = 1u))
   |> checkUndef
  (pickBit bin 20 = 1u && inITBlock itstate) |> checkUnpred

(* if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED
   if size == '11' then UNDEFINED *)
let chkQVdVnVmSz bin =
  (((pickBit bin 6 = 1u) &&
    (pickBit bin 12 = 1u || pickBit bin 16 = 1u || pickBit bin 0 = 1u)) ||
    (extract bin 21 20 = 0b11u)) |> checkUndef

(* if InITBlock() then UNPREDICTABLE
   if Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1' then UNDEFINED *)
let chkITVdVnVm bin itstate =
  inITBlock itstate |> checkUnpred
  (pickBit bin 12 = 1u || pickBit bin 16 = 1u || pickBit bin 0 = 1u)
  |> checkUndef

(* if sz == '1' && InITBlock() then UNPREDICTABLE *)
let chkSzIT bin itstate =
  (pickBit bin 20 = 1u && inITBlock itstate) |> checkUnpred

(* if size == '01' && InITBlock() then UNPREDICTABLE *)
let chkSz01IT bin itstate =
  (extract bin 9 8 = 0b01u && inITBlock itstate) |> checkUnpred

(* if sz == '1' && InITBlock() then UNPREDICTABLE
   if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED
*)
let chkSzITQVdVnVm bin itstate =
  (pickBit bin 20 = 1u && inITBlock itstate) |> checkUnpred
  ((pickBit bin 6 = 1u) &&
   (pickBit bin 12 = 1u || pickBit bin 16 = 1u || pickBit bin 0 = 1u))
   |> checkUndef

(* if InITBlock() then UNPREDICTABLE
   if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED
*)
let chkITQVdVnVm bin itstate =
  inITBlock itstate |> checkUnpred
  ((pickBit bin 6 = 1u) &&
   ((pickBit bin 12 = 1u) || (pickBit bin 16 = 1u) || (pickBit bin 0 = 1u)))
   |> checkUndef

(* if InITBlock() then UNPREDICTABLE
   if Q == '1' && (Vd<0> == '1' || Vn<0> == '1') then UNDEFINED
*)
let chkITQVdVn bin itstate =
  inITBlock itstate |> checkUnpred
  ((pickBit bin 6 = 1u) && (pickBit bin 12 = 1u || pickBit bin 16 = 1u))
  |> checkUndef

(* if InITBlock() then UNPREDICTABLE
   if Q == '1' && Vd<0> == '1' then UNDEFINED *)
let chkITQVd bin itstate =
  inITBlock itstate |> checkUnpred
  (pickBit bin 6 = 1u && pickBit bin 12 = 1u) |> checkUndef

(* if InITBlock() then UNPREDICTABLE
   if Vd<0> == '1' || Vn<0> == '1' then UNDEFINED *)
let chkITVdVn bin itstate =
  inITBlock itstate |> checkUnpred
  checkUndef (pickBit bin 12 = 1u || pickBit bin 16 = 1u)

(* if op == '1' && size != '00' then UNDEFINED
   if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED
*)
let chkQVdVnVmxx bin =
  ((pickBit bin 28 = 1u && extract bin 21 20 <> 0b00u) ||
   ((pickBit bin 6 = 1u) &&
    (pickBit bin 12 = 1u || pickBit bin 16 = 1u || pickBit bin 0 = 1u)))
    |> checkUndef

(* if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED
   if Q == '0' && imm4<3> == '1' then UNDEFINED *)
let chkQVdVnVmImm4 bin =
  (((pickBit bin 6 = 1u) &&
    (pickBit bin 12 = 1u || pickBit bin 16 = 1u || pickBit bin 0 = 1u)) ||
   ((pickBit bin 6 = 0u) && (pickBit bin 11 = 1u))) |> checkUndef

(* if n+length > 32 then UNPREDICTABLE *)
let chkNLen bin =
  let n = concat (pickBit bin 7) (extract bin 19 16) 4
  (n + ((extract bin 9 8) + 1u (* length *)) > 32u) |> checkUnpred

(* half_to_single = (op == '1')
   if half_to_single && Vd<0> == '1' then UNDEFINED
   if !half_to_single && Vm<0> == '1' then UNDEFINED *)
let chkOpVdVm bin =
  ((pickBit bin 8 = 1u && pickBit bin 12 = 1u) ||
   (pickBit bin 8 <> 1u && pickBit bin 0 = 1u)) |> checkUndef

(* if InITBlock() then UNPREDICTABLE
   if Vd<0> == '1' || Vm<0> == '1' then UNDEFINED *)
let chkITVdVm bin itstate =
  inITBlock itstate |> checkUnpred
  (pickBit bin 12 = 1u || pickBit bin 0 = 1u) |> checkUndef

(* if InITBlock() then UNPREDICTABLE
   if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED *)
let chkITQVdVm bin itstate =
  inITBlock itstate |> checkUnpred
  ((pickBit bin 6 = 1u) && (pickBit bin 12 = 1u || pickBit bin 0 = 1u))
  |> checkUndef

(* if F == '1' && size == '01' && InITBlock() then UNPREDICTABLE
   if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED *)
let chkFSzITQVdVm bin itstate =
  (pickBit bin 10 = 1u && extract bin 19 18 = 0b01u && inITBlock itstate)
  |> checkUnpred
  ((pickBit bin 6 = 1u) && (pickBit bin 12 = 1u || pickBit bin 0 = 1u))
  |> checkUndef

(* if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED
   if size == '01' && InITBlock() then UNPREDICTABLE *)
let chkQVdVmSzIT bin itstate =
  ((pickBit bin 6 = 1u) && (pickBit bin 12 = 1u || pickBit bin 0 = 1u))
  |> checkUndef
  (extract bin 19 18 = 0b01u && inITBlock itstate) |> checkUnpred

(* polynomial = (op == '1');
   if polynomial then
     if size == '10' then // .p64
       if InITBlock() then UNPREDICTABLE;
   if Vd<0> == '1' then UNDEFINED *)
let chkPolySzITVd bin itstate =
  (pickBit bin 9 = 1u && extract bin 21 20 = 0b10u && inITBlock itstate)
  |> checkUnpred
  (pickBit bin 16 = 1u) |> checkUndef

(* if size == '00' then UNDEFINED
   if F == '1' && size == '01' && InITBlock() then UNPREDICTABLE
   if Q == '1' && (Vd<0> == '1' || Vn<0> == '1') then UNDEFINED *)
let chkSzFSzITQVdVn bin itstate =
  ((extract bin 21 20 = 0b00u) ||
   ((pickBit bin 24 = 1u) && (pickBit bin 12 = 1u || pickBit bin 16 = 1u)))
   |> checkUndef
  (pickBit bin 8 = 1u && extract bin 21 20 = 0b01u && inITBlock itstate)
  |> checkUnpred

(* if t == 15 || t2 == 15 || t == t2 then UNPREDICTABLE
   if W == '1' then UNPREDICTABLE *)
let chkPCRtRt2EqW bin =
  let t = extract bin 15 12
  let t2 = extract bin 11 8
  checkUnpred ((t = 15u || t2 = 15u || t = t2) || (pickBit bin 21 = 1u))

(* if d == 15 || t == 15 || n == 15 then UNPREDICTABLE
   if d == n || d == t then UNPREDICTABLE *)
let chkPCRd11RtRn bin =
  let d = extract bin 11 8
  let n = extract bin 19 16
  let t = extract bin 15 12
  checkUnpred ((d = 15u || t = 15u || n = 15u) || (d = n || d = t))

(* if d == 15 || t == 15 || n == 15 then UNPREDICTABLE
   if d == n || d == t then UNPREDICTABLE *)
let chkPCRd3RtRn bin =
  let d = extract bin 3 0
  let n = extract bin 19 16
  let t = extract bin 15 12
  checkUnpred ((d = 15u || t = 15u || n = 15u) || (d = n || d = t))

(* if d == 15 || t == 15 || t2 == 15 || n == 15 then UNPREDICTABLE
   if d == n || d == t || d == t2 then UNPREDICTABLE *)
let chkPCRdRtRt2Rn bin =
  let d = extract bin 3 0
  let t = extract bin 15 12
  let t2 = extract bin 11 8
  let n = extract bin 19 16
  ((d = 15u || t = 15u || t2 = 15u || n = 15u) || (d = n || d = t || d = t2))
  |> checkUnpred

(* if t == 15 || t2 == 15 || t == t2 || n == 15 then UNPREDICTABLE *)
let chkThumbPCRtRt2Rn bin =
  let t = extract bin 15 12
  let t2 = extract bin 11 8
  (t = 15u || t2 = 15u || t = t2 || (extract bin 19 16 = 15u)) |> checkUnpred

(* if wback && (n == t || n == t2) then UNPREDICTABLE
   if n == 15 || t == 15 || t2 == 15 then UNPREDICTABLE *)
let chkPCRnRtRt2 bin =
  let n = extract bin 19 16
  let t = extract bin 15 12
  let t2 = extract bin 11 8
  ((wbackW bin && (n = t || n = t2)) || (n = 15u || t = 15u || t2 = 15u))
  |> checkUnpred

(* if wback && (n == t || n == t2) then UNPREDICTABLE
   if t == 15 || t2 == 15 || t == t2 then UNPREDICTABLE *)
let chkThumbPCRtRt2Eq bin =
  let n = extract bin 19 16
  let t = extract bin 15 12
  let t2 = extract bin 11 8
  ((wbackW bin && (n = t || n = t2)) || (t = 15u || t2 = 15u || t = t2))
  |> checkUnpred

(* setflags = (S == '1')
   if (d == 15 && !setflags) || n == 15 || m == 15 then UNPREDICTABLE *)
let chkPCRdSRnRm bin =
  ((extract bin 11 8 = 15u && pickBit bin 20 <> 1u) ||
   (extract bin 19 16 = 15u) || (extract bin 3 0 = 15u)) |> checkUnpred

(* setflags = (S == '1')
   if (d == 15 && !setflags) || m == 15 then UNPREDICTABLE *)
let chkPCRdSRm bin =
  ((extract bin 11 8 = 15u && pickBit bin 20 <> 1u) || (extract bin 3 0 = 15u))
  |> checkUnpred

(* setflags = (S == '1')
   if (d == 15 && !setflags) || n == 15 then UNPREDICTABLE *)
let chkPCRdSRn bin =
  ((extract bin 11 8 = 15u && pickBit bin 20 <> 1u)
    || (extract bin 19 16 = 15u))
  |> checkUnpred

(* setflags = (S == '1')
   if d == 15 && !setflags then UNPREDICTABLE *)
let chkPCRdS bin =
  (extract bin 11 8 = 15u && pickBit bin 20 <> 1u) |> checkUnpred

(* if d == 15 then UNPREDICTABLE *)
let chkThumbPCRd bin = checkUnpred (extract bin 11 8 = 15u)

(* if d == 15 || m == 15 then UNPREDICTABLE *)
let chkThumbPCRdRm bin =
  checkUnpred ((extract bin 11 8 = 15u) || (extract bin 3 0 = 15u))

(* if n == 15 || m == 15 then UNPREDICTABLE *)
let chkThumbPCRnRm bin =
  checkUnpred (extract bin 19 16 = 15u || extract bin 3 0 = 15u)

(* if d == 15 || n == 15 then UNPREDICTABLE *)
let chkThumbPCRdRn bin =
  checkUnpred (extract bin 11 8 = 15u || extract bin 19 16 = 15u)

(* if mask == '0000' then UNPREDICTABLE
   if n == 15 then UNPREDICTABLE *)
let chkThumbMaskPCRn bin =
  checkUnpred ((extract bin 11 8 = 0b0000u) || (extract bin 19 16 = 15u))

(* if mode != '00000' && M == '0' then UNPREDICTABLE
   if (imod<1> == '1' && A:I:F == '000') || (imod<1> == '0' && A:I:F != '000')
   then UNPREDICTABLE
   if imod == '01' || InITBlock() then UNPREDICTABLE *)
let chkModeImodAIFIT bin itstate =
  let imod1 = pickBit bin 10 (* imod<1> *)
  let aif = extract bin 7 5 (* A:I:F *)
  (((extract bin 4 0 (* mode *) <> 0u) && (pickBit bin 8 = 0u (* M *))) ||
   ((imod1 = 1u && aif = 0u) || (imod1 = 0u && aif <> 0u)) ||
   (extract bin 10 9 = 0b01u || inITBlock itstate)) |> checkUndef

(* if t == 15 || m == 15 then UNPREDICTABLE *)
let chkThumbPCRtRm bin =
  ((extract bin 15 12 (* Rt *) = 15u) || (extract bin 3 0 (* Rm *) = 15u))
  |> checkUnpred

(* if m == 15 then UNPREDICTABLE
   if t == 15 && InITBlock() && !LastInITBlock() then UNPREDICTABLE *)
let chkPCRmRtIT bin itstate =
  ((extract bin 3 0 = 15u) ||
   (extract bin 19 16 = 15u &&
    inITBlock itstate && (lastInITBlock itstate |> not)))
    |> checkUnpred

(* if t == 15 && InITBlock() && !LastInITBlock() then UNPREDICTABLE *)
let chkPCRtIT bin itstate =
  (extract bin 19 16 = 15u && inITBlock itstate && lastInITBlock itstate |> not)
  |> checkUnpred

(* if Rn == '1111' || (P == '0' && W == '0') then UNDEFINED
   if t == 15 || (wback && n == t) then UNPREDICTABLE *)
let chkRnPWPCRtWBRn bin =
  let n = extract bin 19 16
  let t = extract bin 15 12
  ((n = 0b1111u) || (pickBit bin 10 = 0u && pickBit bin 8 = 0u)) |> checkUndef
  (t = 15u || (wbackW8 bin && n = t)) |> checkUnpred

(* if P == '0' && W == '0' then UNDEFINED
   if (t == 15 && W == '1') || (wback && n == t) then UNPREDICTABLE *)
let chkPWPCRtWBRn bin =
  let w = pickBit bin 8
  let t = extract bin 15 12
  (pickBit bin 10 (* P *) = 0u && w = 0u) |> checkUndef
  ((t = 15u && w = 1u) || (wbackW8 bin && extract bin 19 16 (* Rn *) = t))
  |> checkUnpred

(* if P == '0' && W == '0' then UNDEFINED
   if (wback && n == t) || (t == 15 && InITBlock() && !LastInITBlock())
   then UNPREDICTABLE *)
let chkPWWBRnPCRtIT bin itstate =
  let t = extract bin 15 12
  (pickBit bin 10 (* P *) = 0u && pickBit bin 8 (* W *) = 0u) |> checkUndef
  ((wbackW8 bin && extract bin 19 16 (* Rn *) = t) ||
   (t = 15u && inITBlock itstate && (lastInITBlock itstate |> not)))
   |> checkUnpred

(* if Rn == '1111' then UNDEFINED
   if t == 15 then UNPREDICTABLE *)
let chkRnPCRt bin =
  extract bin 19 16 (* Rn *) = 0b1111u |> checkUndef
  extract bin 15 12 (* Rt *) = 15u |> checkUnpred

(* if d == 15 || m == 15 || s == 15 then UNPREDICTABLE *)
let chkThumbPCRdRmRs bin =
  ((extract bin 11 8 = 15u) || (extract bin 19 16 = 15u) ||
   (extract bin 3 0 = 15u)) |> checkUnpred

(* if d == 15 || n == 15 || m == 15 then UNPREDICTABLE *)
let chkThumbPCRdRnRm bin =
  ((extract bin 11 8 = 15u) || (extract bin 19 16 = 15u) ||
   (extract bin 3 0 = 15u)) |> checkUnpred

(* if InITBlock() then UNPREDICTABLE
   if d == 15 || n == 15 || m == 15 then UNPREDICTABLE *)
let chkITPCRdRnRm bin itstate =
  (inITBlock itstate || extract bin 11 8 = 15u || extract bin 19 16 = 15u ||
   extract bin 3 0 = 15u) |> checkUnpred

(* if m != n || d == 15 || m == 15 then UNPREDICTABLE *)
let chkRmRnPCRdRm bin =
  let rm = extract bin 3 0
  ((rm <> extract bin 19 16) || (extract bin 11 8 = 15u) || (rm = 15u))
  |> checkUnpred

(* if d == 15 || n == 15 || m == 15 || a == 15 then UNPREDICTABLE *)
let chkThumbPCRdRnRmRa bin =
  (extract bin 11 8 = 15u || extract bin 19 16 = 15u || extract bin 3 0 = 15u ||
   extract bin 15 12 = 15u) |> checkUnpred

(* if d == 15 || n == 15 || m == 15 || a != 15 then UNPREDICTABLE *)
let chkThumbPCRdRnRmRaNot bin =
  (extract bin 11 8 = 15u || extract bin 19 16 = 15u || extract bin 3 0 = 15u ||
   extract bin 15 12 <> 15u) |> checkUnpred

(* if dLo == 15 || dHi == 15 || n == 15 || m == 15 then UNPREDICTABLE
   if dHi == dLo then UNPREDICTABLE *)
let chkThumbPCRdlRdhRnRm bin =
  let dLo = extract bin 15 12
  let dHi = extract bin 11 8
  ((dLo = 15u || dHi = 15u || extract bin 19 16 = 15u || extract bin 3 0 = 15u)
  || (dHi = dLo)) |> checkUnpred
#endif
