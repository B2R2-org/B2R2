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

module internal B2R2.FrontEnd.BinLifter.ARM32.ARMParser

open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ARM32
open B2R2.FrontEnd.BinLifter.ARM32.ParseUtils
open B2R2.FrontEnd.BinLifter.ARM32.OperandHelper
open OperandParsingHelper

let inc bin =
  match extract bin 11 10 (* size *) with
  | 0b00u -> 1u
  | 0b01u -> if pickBit bin 5 (* index_align<1> *) = 0u then 1u else 2u
  | 0b10u -> if pickBit bin 6 (* index_align<2> *) = 0u then 1u else 2u
  | _ -> raise UndefinedException

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
let chkPCRt2 bin =
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
let chkPCRtRt2VmEq bin =
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

(* if cond != '1110' then UNPREDICTABLE
   if t == 15 then UNPREDICTABLE *)
let chkCondPCRt bin cond =
  checkUnpred (cond <> Condition.AL || extract bin 15 12 = 15u)

(* if W == '1' || (P == '0' && CurrentInstrSet() != InstrSet_A32)
   then UNPREDICTABLE *)
let chkWP bin =
  checkUnpred ((pickBit bin 21 = 0b1u) || (pickBit bin 24 = 0b0u))

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
  let Q = pickBit bin 6 (* Q *)
  ((Q = 1u && (pickBit bin 12 = 1u || pickBit bin 16 = 1u ||
     pickBit bin 0 = 1u)) || (Q = 0u && pickBit bin 11 = 1u)) |> checkUndef

(* if n+length > 32 then UNPREDICTABLE *)
let chkPCRnLen bin =
  let n = concat (pickBit bin 7) (extract bin 19 16) 4 (* N:Vn *)
  checkUnpred (n + (extract bin 9 8 + 1u) > 32u)

(* if Vd<0> == '1' || (op == '1' && Vn<0> == '1') then UNDEFINED *)
let chkVdOp bin =
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
   (F == '1' && size == '01' && !HaveFP16Ext()) then UNDEFINED
   if Q == '1' && (Vd<0> == '1' || Vn<0> == '1') then UNDEFINED *)
let chkSzQVdVn bin =
  ((extract bin 21 20 = 0b00u) ||
   ((pickBit bin 24 = 1u) && (pickBit bin 12 = 1u || pickBit bin 16 = 1u)))
   |> checkUndef

(* if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED
   if size == '00' || size == '11' then UNDEFINED *)
let chkQVdVnVmSz bin =
  let size = extract bin 21 20
  (((pickBit bin 24 = 1u) &&
    (pickBit bin 12 = 1u || pickBit bin 16 = 1u || pickBit bin 0 = 1u))
    || (size = 0b00u || size = 0b11u)) |> checkUndef

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
  (((pickBit bin 24 (* U *)  = 0u) && (pickBit bin 8 (* op *) = 0u)) ||
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
let chkQVdVnVm bin =
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

let newInsInfo (phlp: ParsingHelper) opcode oprs itState wback q simdt cflag =
  let insInfo =
    { Address = phlp.InsAddr
      NumBytes = phlp.Len
      Condition = Some phlp.Cond
      Opcode = opcode
      Operands = oprs
      ITState = itState
      WriteBack = wback
      Qualifier = q
      SIMDTyp = simdt
      Mode = phlp.Mode
      Cflag = cflag }
  ARM32Instruction (phlp.InsAddr, phlp.Len, insInfo)

let render (phlp: ParsingHelper) bin opcode dt oidx =
  //let struct (oprs, wback, cflag) = ohlp.OprParsers.[int oidx].Render bin
  let o = phlp.OprParsers.[int oidx].Render bin
  //newInsInfo ohlp mode addr len cond opcode oprs 0uy wback Qualifier.N dt cflag
  newInsInfo phlp opcode o.Operands 0uy o.WBack N dt o.CFlags

/// Load/Store Dual, Half, Signed Byte (register) on page F4-4221.
let parseLoadStoreReg (phlp: ParsingHelper) bin =
  let decodeField = (* P:W:o1:o2 *)
    (pickBit bin 24 <<< 4) + (extract bin 21 20 <<< 2) + (extract bin 6 5)
  match decodeField with
  | 0b00001u ->
    chkPCRtRm bin; render phlp bin Op.STRH None OD.OprRtMemReg
  | 0b00010u ->
    chkPCRt2RmRnEq bin
    render phlp bin Op.LDRD None OD.OprRtRt2MemReg
  | 0b00011u ->
    chkPCRt2RmRn bin; render phlp bin Op.STRD None OD.OprRtRt2MemReg
  | 0b00101u ->
    chkPCRtRm bin; render phlp bin Op.LDRH None OD.OprRtMemReg
  | 0b00110u ->
    chkPCRtRm bin; render phlp bin Op.LDRSB None OD.OprRtMemReg
  | 0b00111u ->
    chkPCRtRm bin; render phlp bin Op.LDRSH None OD.OprRtMemReg
  | 0b01001u ->
    chkPCRtRnRm bin; render phlp bin Op.STRHT None OD.OprRtMemRegP
  | 0b01010u | 0b01011u -> raise ParsingFailureException
  | 0b01101u ->
    chkPCRtRnRm bin; render phlp bin Op.LDRHT None OD.OprRtMemRegP
  | 0b01110u ->
    chkPCRtRnRm bin; render phlp bin Op.LDRSBT None OD.OprRtMemRegP
  | 0b01111u ->
    chkPCRtRnRm bin; render phlp bin Op.LDRSHT None OD.OprRtMemRegP
  | 0b10001u | 0b11001u ->
    chkPCRtRm bin; render phlp bin Op.STRH None OD.OprRtMemReg
  | 0b10010u | 0b11010u ->
    chkPCRt2RmRnEq bin
    render phlp bin Op.LDRD None OD.OprRtRt2MemReg
  | 0b10011u | 0b11011u ->
    chkPCRt2RmRn bin; render phlp bin Op.STRD None OD.OprRtRt2MemReg
  | 0b10101u | 0b11101u ->
    chkPCRtRm bin; render phlp bin Op.LDRH None OD.OprRtMemReg
  | 0b10110u | 0b11110u ->
    chkPCRtRm bin; render phlp bin Op.LDRSB None OD.OprRtMemReg
  | 0b10111u | 0b11111u ->
    chkPCRtRm bin; render phlp bin Op.LDRSH None OD.OprRtMemReg
  | _ -> raise ParsingFailureException

/// Load/Store Dual, Half, Signed Byte (immediate, literal) on page F4-4221.
let parseLoadStoreImm (phlp: ParsingHelper) bin =
  let decodeField = (* P:W:o1:op2 *)
    concat (concat (pickBit bin 24) (extract bin 21 20) 2)
           (extract bin 6 5) 2
  let isNotRn1111 bin = extract bin 19 16 <> 0b1111u
  match decodeField (* P:W:o1:op2 *) with
  | 0b00010u when isNotRn1111 bin -> (* LDRD (immediate) *)
    chkRnRtPCRt2 bin; render phlp bin Op.LDRD None OD.OprRtRt2MemImm
  | 0b00010u -> (* LDRD (literal) *)
    chkPCRt2 bin; render phlp bin Op.LDRD None OD.OprRtRt2Label
  | 0b00001u ->
    chkPCRnRtWithWB bin; render phlp bin Op.STRH None OD.OprRtMemImm
  | 0b00011u ->
    chkPCRnRt2 bin; render phlp bin Op.STRD None OD.OprRtRt2MemImm
  | 0b00101u when isNotRn1111 bin ->
    chkPCRtRnWithWB bin; render phlp bin Op.LDRH None OD.OprRtMemImm
  | 0b00101u -> (* LDRH (literal) *)
    chkPCRtWithWB bin; render phlp bin Op.LDRH None OD.OprRtLabelHL
  | 0b00110u when isNotRn1111 bin -> (* LDRH (immediate) *)
    chkPCRtRnWithWB bin; render phlp bin Op.LDRSB None OD.OprRtMemImm
  | 0b00110u ->
    chkPCRtWithWB bin; render phlp bin Op.LDRSB None OD.OprRtLabelHL
  | 0b00111u when isNotRn1111 bin ->
    chkPCRtRnWithWB bin; render phlp bin Op.LDRSH None OD.OprRtMemImm
  | 0b00111u ->
    chkPCRtWithWB bin; render phlp bin Op.LDRSH None OD.OprRtLabelHL
  | 0b01010u when isNotRn1111 bin -> raise ParsingFailureException
  | 0b01010u ->
    chkPCRt2 bin; render phlp bin Op.LDRD None OD.OprRtRt2Label
  | 0b01001u ->
    chkPCRtRnEq bin; render phlp bin Op.STRHT None OD.OprRtMemImmP
  | 0b01011u -> raise ParsingFailureException
  | 0b01101u ->
    chkPCRtRnEq bin; render phlp bin Op.LDRHT None OD.OprRtMemImmP
  | 0b01110u ->
    chkPCRtRnEq bin; render phlp bin Op.LDRSBT None OD.OprRtMemImmP
  | 0b01111u ->
    chkPCRtRnEq bin; render phlp bin Op.LDRSHT None OD.OprRtMemImmP
  | 0b10010u when isNotRn1111 bin ->
    chkRnRtPCRt2 bin; render phlp bin Op.LDRD None OD.OprRtRt2MemImm
  | 0b10010u ->
    chkPCRt2 bin; render phlp bin Op.LDRD None OD.OprRtRt2Label
  | 0b10001u ->
    chkPCRnRtWithWB bin; render phlp bin Op.STRH None OD.OprRtMemImm
  | 0b10011u ->
    chkPCRnRt2 bin; render phlp bin Op.STRD None OD.OprRtRt2MemImm
  | 0b10101u when isNotRn1111 bin ->
    chkPCRtRnWithWB bin; render phlp bin Op.LDRH None OD.OprRtMemImm
  | 0b10101u ->
    chkPCRtWithWB bin; render phlp bin Op.LDRH None OD.OprRtLabelHL
  | 0b10110u when isNotRn1111 bin ->
    chkPCRtRnWithWB bin; render phlp bin Op.LDRSB None OD.OprRtMemImm
  | 0b10110u ->
    chkPCRtWithWB bin; render phlp bin Op.LDRSB None OD.OprRtLabelHL
  | 0b10111u when isNotRn1111 bin ->
    chkPCRtRnWithWB bin; render phlp bin Op.LDRSH None OD.OprRtMemImm
  | 0b10111u ->
    chkPCRtWithWB bin; render phlp bin Op.LDRSH None OD.OprRtLabelHL
  | 0b11010u when isNotRn1111 bin ->
    chkRnRtPCRt2 bin; render phlp bin Op.LDRD None OD.OprRtRt2MemImm
  | 0b11010u ->
    chkPCRt2 bin; render phlp bin Op.LDRD None OD.OprRtRt2Label
  | 0b11001u ->
    chkPCRnRtWithWB bin; render phlp bin Op.STRH None OD.OprRtMemImm
  | 0b11011u ->
    chkPCRnRt2 bin; render phlp bin Op.STRD None OD.OprRtRt2MemImm
  | 0b11101u when isNotRn1111 bin ->
    chkPCRtRnWithWB bin; render phlp bin Op.LDRH None OD.OprRtMemImm
  | 0b11101u ->
    chkPCRtWithWB bin; render phlp bin Op.LDRH None OD.OprRtLabelHL
  | 0b11110u when isNotRn1111 bin ->
    chkPCRtRnWithWB bin; render phlp bin Op.LDRSB None OD.OprRtMemImm
  | 0b11110u ->
    chkPCRtWithWB bin; render phlp bin Op.LDRSB None OD.OprRtLabelHL
  | 0b11111u when isNotRn1111 bin ->
    chkPCRtRnWithWB bin; render phlp bin Op.LDRSH None OD.OprRtMemImm
  | 0b11111u ->
    chkPCRtWithWB bin; render phlp bin Op.LDRSH None OD.OprRtLabelHL
  | _ -> raise ParsingFailureException

/// Extra load/store on page F4-4220.
let parseExtraLoadStore (phlp: ParsingHelper) bin =
  match pickBit bin 22 (* op0 *) with
  | 0b0u -> parseLoadStoreReg phlp bin
  | _ (* 0b1u *) -> parseLoadStoreImm phlp bin

/// Multiply and Accumulate on page F4-4129.
let parseMultiplyAndAccumlate (phlp: ParsingHelper) bin =
  match extract bin 23 20 (* opc:S *) with
  | 0b0000u ->
    chkPCRdRnRm bin; render phlp bin Op.MUL None OD.OprRdRnRmOpt
  | 0b0001u ->
    chkPCRdRnRm bin; render phlp bin Op.MULS None OD.OprRdRnRmOpt
  | 0b0010u ->
    chkPCRdRnRmRa bin; render phlp bin Op.MLA None OD.OprRdRnRmRa
  | 0b0011u ->
    chkPCRdRnRmRa bin; render phlp bin Op.MLAS None OD.OprRdRnRmRa
  | 0b0100u ->
    chkPCRdlRdhRnRm bin
    render phlp bin Op.UMAAL None OD.OprRdlRdhRnRm
  | 0b0101u -> raise ParsingFailureException
  | 0b0110u ->
    chkPCRdRnRmRa bin; render phlp bin Op.MLS None OD.OprRdRnRmRa
  | 0b0111u -> raise ParsingFailureException
  | 0b1000u ->
    chkPCRdlRdhRnRm bin
    render phlp bin Op.UMULL None OD.OprRdlRdhRnRm
  | 0b1001u ->
    chkPCRdlRdhRnRm bin
    render phlp bin Op.UMULLS None OD.OprRdlRdhRnRm
  | 0b1010u ->
    chkPCRdlRdhRnRm bin
    render phlp bin Op.UMLAL None OD.OprRdlRdhRnRm
  | 0b1011u ->
    chkPCRdlRdhRnRm bin
    render phlp bin Op.UMLALS None OD.OprRdlRdhRnRm
  | 0b1100u ->
    chkPCRdlRdhRnRm bin
    render phlp bin Op.SMULL None OD.OprRdlRdhRnRm
  | 0b1101u ->
    chkPCRdlRdhRnRm bin
    render phlp bin Op.SMULLS None OD.OprRdlRdhRnRm
  | 0b1110u ->
    chkPCRdlRdhRnRm bin
    render phlp bin Op.SMLAL None OD.OprRdlRdhRnRm
  | _ (* 0b1111u *) ->
    chkPCRdlRdhRnRm bin
    render phlp bin Op.SMLALS None OD.OprRdlRdhRnRm

/// Load/Store Exclusive and Load-Acquire/Store-Release on page F4-4223
/// ARMv8
let parseLdStExclAndLdAcqStRel (phlp: ParsingHelper) bin =
  match concat (extract bin 22 20) (extract bin 9 8) 2 (* size:L:ex:ord *) with
  | 0b00000u ->
    chkPCRtRn bin; render phlp bin Op.STL None OD.OprRtMem
  | 0b00001u -> raise ParsingFailureException
  | 0b00010u ->
    chkPCRdRtRn bin; render phlp bin Op.STLEX None OD.OprRdRtMem
  | 0b00011u ->
    chkPCRdRtRn bin; render phlp bin Op.STREX None OD.OprRdRtMem
  | 0b00100u ->
    chkPCRtRn bin; render phlp bin Op.LDA None OD.OprRtAMem
  | 0b00101u -> raise ParsingFailureException
  | 0b00110u ->
    chkPCRtRn bin; render phlp bin Op.LDAEX None OD.OprRtAMem
  | 0b00111u ->
    chkPCRtRn bin; render phlp bin Op.LDREX None OD.OprRtMemImm0
  | 0b01000u | 0b01001u -> raise ParsingFailureException
  | 0b01010u ->
    chkPCRdRt2Rn bin; render phlp bin Op.STLEXD None OD.OprRdRtRt2Mem
  | 0b01011u ->
    chkPCRdRt2Rn bin; render phlp bin Op.STREXD None OD.OprRdRtRt2Mem
  | 0b01100u | 0b01101u -> raise ParsingFailureException
  | 0b01110u ->
    chkPCRt2Rn bin; render phlp bin Op.LDAEXD None OD.OprRtRt2Mem
  | 0b01111u ->
    chkPCRt2Rn bin; render phlp bin Op.LDREXD None OD.OprRtRt2Mem
  | 0b10000u ->
    chkPCRtRn bin; render phlp bin Op.STLB None OD.OprRtMem
  | 0b10001u -> raise ParsingFailureException
  | 0b10010u ->
    chkPCRdRtRn bin; render phlp bin Op.STLEXB None OD.OprRdRtMem
  | 0b10011u ->
    chkPCRdRtRn bin; render phlp bin Op.STREXB None OD.OprRdRtMem
  | 0b10100u ->
    chkPCRtRn bin; render phlp bin Op.LDAB None OD.OprRtMem
  | 0b10101u -> raise ParsingFailureException
  | 0b10110u ->
    chkPCRtRn bin; render phlp bin Op.LDAEXB None OD.OprRtMem
  | 0b10111u ->
    chkPCRtRn bin; render phlp bin Op.LDREXB None OD.OprRtMem
  | 0b11000u ->
    chkPCRtRn bin; render phlp bin Op.STLH None OD.OprRtMem
  | 0b11001u -> raise ParsingFailureException
  | 0b11010u ->
    chkPCRdRtRn bin; render phlp bin Op.STLEXH None OD.OprRdRtMem
  | 0b11011u ->
    chkPCRdRtRn bin; render phlp bin Op.STREXH None OD.OprRdRtMem
  | 0b11100u ->
    chkPCRtRn bin; render phlp bin Op.LDAH None OD.OprRtMem
  | 0b11101u -> raise ParsingFailureException
  | 0b11110u ->
    chkPCRtRn bin; render phlp bin Op.LDAEXH None OD.OprRtMem
  | _ (* 0b11111u *) ->
    chkPCRtRn bin; render phlp bin Op.LDREXH None OD.OprRtMem

/// Synchronization primitives and Load-Acquire/Store-Release on page F4-4223.
let parseSyncAndLoadAcqStoreRel (phlp: ParsingHelper) bin =
  match pickBit bin 23 (* op0 *) with
  | 0b0u when phlp.IsARMv7 -> (* ARMv7 A8-723 *)
    chkPCRtRt2Rn bin
    let op = if pickBit bin 22 (* B *) = 1u then Op.SWPB else Op.SWP
    render phlp bin op None OD.OprRtRt2Mem2
  | 0b0u -> raise ParsingFailureException
  | _ (* 0b01u *) -> parseLdStExclAndLdAcqStRel phlp bin

/// Move special register (register) on page F4-4225.
let parseMoveSpecialReg (phlp: ParsingHelper) bin =
  match concat (extract bin 22 21) (pickBit bin 9) 1 (* opc:B *) with
  | 0b000u | 0b100u ->
    chkPCRd bin; render phlp bin Op.MRS None OD.OprRdSreg
  | 0b001u | 0b101u ->
    chkPCRd bin; render phlp bin Op.MRS None OD.OprRdBankreg
  | 0b010u | 0b110u ->
    chkMaskPCRn bin; render phlp bin Op.MSR None OD.OprSregRn
  | _ (* 0bx11u *) ->
    chkPCRnB bin; render phlp bin Op.MSR None OD.OprBankregRn

/// Cyclic Redundancy Check on page F4-4226.
/// ARMv8-A
let parseCyclicRedundancyCheck (phlp: ParsingHelper) bin =
  match concat (extract bin 22 21) (pickBit bin 9) 1 (* sz:C *) with
  | 0b000u ->
    chkPCRdRnRmSz bin phlp.Cond
    render phlp bin Op.CRC32B None OD.OprRdRnRm
  | 0b001u ->
    chkPCRdRnRmSz bin phlp.Cond
    render phlp bin Op.CRC32CB None OD.OprRdRnRm
  | 0b010u ->
    chkPCRdRnRmSz bin phlp.Cond
    render phlp bin Op.CRC32H None OD.OprRdRnRm
  | 0b011u ->
    chkPCRdRnRmSz bin phlp.Cond
    render phlp bin Op.CRC32CH None OD.OprRdRnRm
  | 0b100u ->
    chkPCRdRnRmSz bin phlp.Cond
    render phlp bin Op.CRC32W None OD.OprRdRnRm
  | 0b101u ->
    chkPCRdRnRmSz bin phlp.Cond
    render phlp bin Op.CRC32CW None OD.OprRdRnRm
  | _ (* 0b11xu *) -> raise UnpredictableException

/// Integer Saturating Arithmetic on page F4-4226.
let parseIntegerSaturatingArithmetic (phlp: ParsingHelper) bin =
  match extract bin 22 21 (* opc *) with
  | 0b00u ->
    chkPCRdOptRnRm bin; render phlp bin Op.QADD None OD.OprRdRmRn
  | 0b01u -> render phlp bin Op.QSUB None OD.OprRdRmRn
  | 0b10u -> render phlp bin Op.QDADD None OD.OprRdRmRn
  | _ (* 0b11u *) -> render phlp bin Op.QDSUB None OD.OprRdRmRn

/// Miscellaneous on page F4-4224.
let parseMiscellaneous (phlp: ParsingHelper) bin =
  match concat (extract bin 22 21) (extract bin 6 4) 3 (* op0:op1 *) with
  | 0b00001u | 0b00010u | 0b00011u | 0b00110u -> raise ParsingFailureException
  | 0b01001u -> render phlp bin Op.BX None OD.OprRm
  | 0b01010u -> chkPCRm bin; render phlp bin Op.BXJ None OD.OprRm
  | 0b01011u -> chkPCRm bin; render phlp bin Op.BLX None OD.OprRm
  | 0b01110u | 0b10001u | 0b10010u | 0b10011u | 0b10110u ->
    raise ParsingFailureException
  | 0b11001u -> chkPCRdRm bin; render phlp bin Op.CLZ None OD.OprRdRm
  | 0b11010u | 0b11011u -> raise ParsingFailureException
  | 0b11110u -> render phlp bin Op.ERET None OD.OprNo
  (* Exception Generation on page F4-4225. *)
  | 0b00111u ->
    chkCondAL phlp.Cond; render phlp bin Op.HLT None OD.OprImm16
  | 0b01111u ->
    chkCondAL phlp.Cond; render phlp bin Op.BKPT None OD.OprImm16
  | 0b10111u ->
    chkCondAL phlp.Cond; render phlp bin Op.HVC None OD.OprImm16
  | 0b11111u -> render phlp bin Op.SMC None OD.OprImm4
  | 0b00000u | 0b01000u | 0b10000u | 0b11000u ->
    parseMoveSpecialReg phlp bin
  | 0b00100u | 0b01100u | 0b10100u | 0b11100u ->
    parseCyclicRedundancyCheck phlp bin
  | _ (* 0bxx101 *) -> parseIntegerSaturatingArithmetic phlp bin

/// Halfword Multiply and Accumulate on page F4-4220.
let parseHalfMulAndAccumulate (phlp: ParsingHelper) bin =
  match concat (extract bin 22 21) (extract bin 6 5) 2 (* opc:M:N *) with
  | 0b0000u ->
    chkPCRdRnRmRa bin; render phlp bin Op.SMLABB None OD.OprRdRnRmRa
  | 0b0001u ->
    chkPCRdRnRmRa bin; render phlp bin Op.SMLATB None OD.OprRdRnRmRa
  | 0b0010u ->
    chkPCRdRnRmRa bin; render phlp bin Op.SMLABT None OD.OprRdRnRmRa
  | 0b0011u ->
    chkPCRdRnRmRa bin; render phlp bin Op.SMLATT None OD.OprRdRnRmRa
  | 0b0100u ->
    chkPCRdRnRmRa bin; render phlp bin Op.SMLAWB None OD.OprRdRnRmRa
  | 0b0101u ->
    chkPCRdRnRm bin; render phlp bin Op.SMULWB None OD.OprRdRnRmOpt
  | 0b0110u ->
    chkPCRdRnRmRa bin; render phlp bin Op.SMLAWT None OD.OprRdRnRmRa
  | 0b0111u ->
    chkPCRdRnRm bin; render phlp bin Op.SMULWT None OD.OprRdRnRmOpt
  | 0b1000u ->
    chkPCRdlRdhRnRm bin
    render phlp bin Op.SMLALBB None OD.OprRdlRdhRnRm
  | 0b1001u ->
    chkPCRdlRdhRnRm bin
    render phlp bin Op.SMLALTB None OD.OprRdlRdhRnRm
  | 0b1010u ->
    chkPCRdlRdhRnRm bin
    render phlp bin Op.SMLALBT None OD.OprRdlRdhRnRm
  | 0b1011u ->
    chkPCRdlRdhRnRm bin
    render phlp bin Op.SMLALTT None OD.OprRdlRdhRnRm
  | 0b1100u ->
    chkPCRdRnRm bin; render phlp bin Op.SMULBB None OD.OprRdRnRmOpt
  | 0b1101u ->
    chkPCRdRnRm bin; render phlp bin Op.SMULTB None OD.OprRdRnRmOpt
  | 0b1110u ->
    chkPCRdRnRm bin; render phlp bin Op.SMULBT None OD.OprRdRnRmOpt
  | _ (* 0b1111u *) ->
    chkPCRdRnRm bin; render phlp bin Op.SMULTT None OD.OprRdRnRmOpt

/// Integer Data Processing (three register, immediate shift) on page F4-4227.
let parseIntegerDataProcThreeRegImm (phlp: ParsingHelper) bin =
  match concat (extract bin 23 21) (pickBit bin 20) 1 (* opc:S *) with
  | 0b0000u -> render phlp bin Op.AND None OD.OprRdRnRmShf
  | 0b0001u -> render phlp bin Op.ANDS None OD.OprRdRnRmShf
  | 0b0010u -> render phlp bin Op.EOR None OD.OprRdRnRmShf
  | 0b0011u -> render phlp bin Op.EORS None OD.OprRdRnRmShf
  | 0b0100u -> render phlp bin Op.SUB None OD.OprRdRnRmShf
  | 0b0101u -> render phlp bin Op.SUBS None OD.OprRdRnRmShf
  | 0b0110u -> render phlp bin Op.RSB None OD.OprRdRnRmShf
  | 0b0111u -> render phlp bin Op.RSBS None OD.OprRdRnRmShf
  | 0b1000u -> render phlp bin Op.ADD None OD.OprRdRnRmShf
  | 0b1001u -> render phlp bin Op.ADDS None OD.OprRdRnRmShf
  | 0b1010u -> render phlp bin Op.ADC None OD.OprRdRnRmShf
  | 0b1011u -> render phlp bin Op.ADCS None OD.OprRdRnRmShf
  | 0b1100u -> render phlp bin Op.SBC None OD.OprRdRnRmShf
  | 0b1101u -> render phlp bin Op.SBCS None OD.OprRdRnRmShf
  | 0b1110u -> render phlp bin Op.RSC None OD.OprRdRnRmShf
  | _ (* 0b1111u *) -> render phlp bin Op.RSCS None OD.OprRdRnRmShf

/// Integer Test and Compare (two register, immediate shift) on page F4-4228.
let parseIntegerTestAndCompareTwoRegImm (phlp: ParsingHelper) bin =
  match extract bin 22 21 (* opc *) with
  | 0b00u -> render phlp bin Op.TST None OD.OprRnRmShf
  | 0b01u -> render phlp bin Op.TEQ None OD.OprRnRmShf
  | 0b10u -> render phlp bin Op.CMP None OD.OprRnRmShf
  | _ (* 0b11u *) -> render phlp bin Op.CMN None OD.OprRnRmShf

/// Alias conditions on page F5-4557.
let changeToAliasOfMOV bin =
  let stype = extract bin 6 5
  let imm5 = extract bin 11 7
  if stype = 0b10u then struct (Op.ASR, OD.OprRdRmImm)
  elif imm5 <> 0b00000u && stype = 0b00u then struct (Op.LSL, OD.OprRdRmImm)
  elif stype = 0b01u then struct (Op.LSR, OD.OprRdRmImm)
  elif imm5 <> 0b00000u && stype = 0b11u then struct (Op.ROR, OD.OprRdRmImm)
  elif imm5 = 0b00000u && stype = 0b11u then struct (Op.RRX, OD.OprRdRm)
  /// FIXME: AArch32(F5-4555) vs ARMv7(A8-489)
  elif imm5 = 0b00000u then struct (Op.MOV, OD.OprRdRm)
  else struct (Op.MOV, OD.OprRdRmShf)

/// Alias conditions on page F5-4557.
let changeToAliasOfMOVS bin =
  let stype = extract bin 6 5
  let imm5 = extract bin 11 7
  if stype = 0b10u then struct (Op.ASRS, OD.OprRdRmImm)
  elif imm5 <> 0b00000u && stype = 0b00u then struct (Op.LSLS, OD.OprRdRmImm)
  elif stype = 0b01u then struct (Op.LSRS, OD.OprRdRmImm)
  elif imm5 <> 0b00000u && stype = 0b11u then struct (Op.RORS, OD.OprRdRmImm)
  elif imm5 = 0b00000u && stype = 0b11u then struct (Op.RRXS, OD.OprRdRm)
  elif imm5 = 0b00000u then struct (Op.MOVS, OD.OprRdRm)
  else struct (Op.MOVS, OD.OprRdRmShf)

/// Logical Arithmetic (three register, immediate shift) on page F4-4229.
let parseLogicalArithThreeRegImm (phlp: ParsingHelper) bin =
  match extract bin 22 20 (* opc:S *) with
  | 0b000u -> render phlp bin Op.ORR None OD.OprRdRnRmShf
  | 0b001u -> render phlp bin Op.ORRS None OD.OprRdRnRmShf
  | 0b010u ->
    let struct (opcode, oprFn) = changeToAliasOfMOV bin
    render phlp bin opcode None oprFn
  | 0b011u ->
    let struct (opcode, oprFn) = changeToAliasOfMOVS bin
    render phlp bin opcode None oprFn
  | 0b100u -> render phlp bin Op.BIC None OD.OprRdRnRmShf
  | 0b101u -> render phlp bin Op.BICS None OD.OprRdRnRmShf
  | 0b110u -> render phlp bin Op.MVN None OD.OprRdRmShf
  | _ (* 0b111u *) -> render phlp bin Op.MVNS None OD.OprRdRmShf

/// Data-processing register (immediate shift) on page F4-4227.
let parseDataProcRegisterImmShf (phlp: ParsingHelper) bin =
  match concat (extract bin 24 23) (pickBit bin 20) 1 (* op0:op1 *) with
  | 0b000u | 0b001u | 0b010u | 0b011u ->
    parseIntegerDataProcThreeRegImm phlp bin
  | 0b101u -> parseIntegerTestAndCompareTwoRegImm phlp bin
  | 0b110u | 0b111u -> parseLogicalArithThreeRegImm phlp bin
  | _ (* 0b100u *) -> raise ParsingFailureException

/// Integer Data Processing (three register, register shift) on page F4-4229.
let parseIntegerDataProcThreeRegRegShf (phlp: ParsingHelper) bin =
  match extract bin 23 20 (* opc:S *) with
  | 0b0000u ->
    chkPCRdRnRmRs bin; render phlp bin Op.AND None OD.OprRdRnRmShfRs
  | 0b0001u ->
    chkPCRdRnRmRs bin; render phlp bin Op.ANDS None OD.OprRdRnRmShfRs
  | 0b0010u ->
    chkPCRdRnRmRs bin; render phlp bin Op.EOR None OD.OprRdRnRmShfRs
  | 0b0011u ->
    chkPCRdRnRmRs bin; render phlp bin Op.EORS None OD.OprRdRnRmShfRs
  | 0b0100u ->
    chkPCRdRnRmRs bin; render phlp bin Op.SUB None OD.OprRdRnRmShfRs
  | 0b0101u ->
    chkPCRdRnRmRs bin; render phlp bin Op.SUBS None OD.OprRdRnRmShfRs
  | 0b0110u ->
    chkPCRdRnRmRs bin; render phlp bin Op.RSB None OD.OprRdRnRmShfRs
  | 0b0111u ->
    chkPCRdRnRmRs bin; render phlp bin Op.RSBS None OD.OprRdRnRmShfRs
  | 0b1000u ->
    chkPCRdRnRmRs bin; render phlp bin Op.ADD None OD.OprRdRnRmShfRs
  | 0b1001u ->
    chkPCRdRnRmRs bin; render phlp bin Op.ADDS None OD.OprRdRnRmShfRs
  | 0b1010u ->
    chkPCRdRnRmRs bin; render phlp bin Op.ADC None OD.OprRdRnRmShfRs
  | 0b1011u ->
    chkPCRdRnRmRs bin; render phlp bin Op.ADCS None OD.OprRdRnRmShfRs
  | 0b1100u ->
    chkPCRdRnRmRs bin; render phlp bin Op.SBC None OD.OprRdRnRmShfRs
  | 0b1101u ->
    chkPCRdRnRmRs bin; render phlp bin Op.SBCS None OD.OprRdRnRmShfRs
  | 0b1110u ->
    chkPCRdRnRmRs bin; render phlp bin Op.RSC None OD.OprRdRnRmShfRs
  | _ (* 0b1111u *) ->
    chkPCRdRnRmRs bin; render phlp bin Op.RSCS None OD.OprRdRnRmShfRs

/// Integer Test and Compare (two register, register shift) on page F4-4230.
let parseIntegerTestAndCompareTwoRegRegShf (phlp: ParsingHelper) bin =
  match extract bin 22 21 (* opc *) with
  | 0b00u ->
    chkPCRnRmRs bin; render phlp bin Op.TST None OD.OprRnRmShfRs
  | 0b01u ->
    chkPCRnRmRs bin; render phlp bin Op.TEQ None OD.OprRnRmShfRs
  | 0b10u ->
    chkPCRnRmRs bin; render phlp bin Op.CMP None OD.OprRnRmShfRs
  | _ (* 0b11u *) ->
    chkPCRnRmRs bin; render phlp bin Op.CMN None OD.OprRnRmShfRs

/// Alias conditions on page F5-4562.
let changeToAliasOfMOVRegShf bin =
  let s = pickBit bin 20 (* S *)
  let stype = extract bin 6 5 (* stype *)
  match concat s stype 2 (* S:stype *) with
  | 0b010u -> struct (Op.ASR, OD.OprRdRmRs)
  | 0b000u -> struct (Op.LSL, OD.OprRdRmRs)
  | 0b001u -> struct (Op.LSR, OD.OprRdRmRs)
  | 0b011u -> struct (Op.ROR, OD.OprRdRmRs)
  | _ -> struct (Op.MOV, OD.OprRdRmShfRs)

/// Alias conditions on page F5-4562.
let changeToAliasOfMOVSRegShf bin =
  let s = pickBit bin 20 (* S *)
  let stype = extract bin 6 5 (* stype *)
  match concat s stype 2 (* S:stype *) with
  | 0b110u -> struct (Op.ASRS, OD.OprRdRmRs)
  | 0b100u -> struct (Op.LSLS, OD.OprRdRmRs)
  | 0b101u -> struct (Op.LSRS, OD.OprRdRmRs)
  | 0b111u -> struct (Op.RORS, OD.OprRdRmRs)
  | _ -> struct (Op.MOVS, OD.OprRdRmShfRs)

/// Logical Arithmetic (three register, register shift) on page F4-4230.
let parseLogicalArithThreeRegRegShf (phlp: ParsingHelper) bin =
  match extract bin 22 20 (* opc:S *) with
  | 0b000u ->
    chkPCRdRnRmRs bin; render phlp bin Op.ORR None OD.OprRdRnRmShfRs
  | 0b001u ->
    chkPCRdRnRmRs bin; render phlp bin Op.ORRS None OD.OprRdRnRmShfRs
  | 0b010u ->
    chkPCRdRmRs bin
    let struct (opcode, oprFn) = changeToAliasOfMOVRegShf bin
    render phlp bin opcode None oprFn
  | 0b011u ->
    chkPCRdRmRs bin
    let struct (opcode, oprFn) = changeToAliasOfMOVSRegShf bin
    render phlp bin opcode None oprFn
  | 0b100u ->
    chkPCRdRnRmRs bin; render phlp bin Op.BIC None OD.OprRdRnRmShfRs
  | 0b101u ->
    chkPCRdRnRmRs bin; render phlp bin Op.BICS None OD.OprRdRnRmShfRs
  | 0b110u ->
    chkPCRdRmRs bin; render phlp bin Op.MVN None OD.OprRdRmShfRs
  | _ (* 0b111u *) ->
    chkPCRdRmRs bin; render phlp bin Op.MVNS None OD.OprRdRmShfRs

/// Data-processing register (register shift) on page F4-4229.
let parseDataProcRegisterRegShf (phlp: ParsingHelper) bin =
  match concat (extract bin 24 23) (pickBit bin 20) 1 (* op0:op1 *) with
  | 0b000u | 0b001u | 0b010u | 0b011u ->
    parseIntegerDataProcThreeRegRegShf phlp bin
  | 0b101u -> parseIntegerTestAndCompareTwoRegRegShf phlp bin
  | 0b110u | 0b111u -> parseLogicalArithThreeRegRegShf phlp bin
  | _ (* 0b100u *) -> raise ParsingFailureException

/// Data-processing and miscellaneous instructions on page F4-4218.
let parseCase000 (phlp: ParsingHelper) bin =
  let op1 = extract bin 24 20
  let is0xxxx bin = bin &&& 0b10000u = 0b00000u
  let is10xx0 bin = bin &&& 0b11001u = 0b10000u
  match extract bin 7 4 (* op2:op3:op4 *) with
  | 0b1011u | 0b1101u | 0b1111u -> parseExtraLoadStore phlp bin
  | 0b1001u when is0xxxx op1 -> parseMultiplyAndAccumlate phlp bin
  | 0b1001u (* op1 = 0b1xxxxu *) -> parseSyncAndLoadAcqStoreRel phlp bin
  | 0b0000u | 0b0010u | 0b0100u | 0b0110u | 0b0001u | 0b0011u | 0b0101u
  | 0b0111u when is10xx0 op1 -> parseMiscellaneous phlp bin
  | 0b1000u | 0b1010u | 0b1100u | 0b1110u when is10xx0 op1 ->
    parseHalfMulAndAccumulate phlp bin
  | 0b0000u | 0b0010u | 0b0100u | 0b0110u | 0b1000u | 0b1010u | 0b1100u
  | 0b1110u -> parseDataProcRegisterImmShf phlp bin
  | _ (* 0b0xx1u *) -> parseDataProcRegisterRegShf phlp bin

/// Integer Data Processing (two register and immediate) on page F4-4231.
let parseIntDataProc0100 (phlp: ParsingHelper) bin =
  match extract bin 19 16 (* Rn *) with
  | 0b1101u -> render phlp bin Op.SUB None OD.OprRdSPConst
  ///| 0b1111u -> (* FIXME: Alias conditions on page F5-4310 *)
  ///  render phlp bin Op.ADR None OD.OprRdLabel
  | _ (* != 0b11x1u *) -> render phlp bin Op.SUB None OD.OprRdRnConst

/// Integer Data Processing (two register and immediate) on page F4-4231.
let parseIntDataProc0101 (phlp: ParsingHelper) bin =
  match extract bin 19 16 (* Rn *) with
  | 0b1101u -> render phlp bin Op.SUBS None OD.OprRdSPConst
  | _ (* != 0b1101u *) ->
    render phlp bin Op.SUBS None OD.OprRdRnConst

/// Integer Data Processing (two register and immediate) on page F4-4231.
let parseIntDataProc1000 (phlp: ParsingHelper) bin =
  match extract bin 19 16 (* Rn *) with
  | 0b1101u -> render phlp bin Op.ADD None OD.OprRdSPConst
  ///| 0b1111u -> (* FIXME: Alias conditions on page F5-4310 *)
  ///  render phlp bin Op.ADR None OD.OprRdLabel
  | _ (* != 0b11x1u *) -> render phlp bin Op.ADD None OD.OprRdRnConst

/// Integer Data Processing (two register and immediate) on page F4-4231.
let parseIntDataProc1001 (phlp: ParsingHelper) bin =
  match extract bin 19 16 (* Rn *) with
  | 0b1101u -> render phlp bin Op.ADDS None OD.OprRdSPConst
  | _ (* != 0b1101u *) ->
    render phlp bin Op.ADDS None OD.OprRdRnConst

/// Integer Data Processing (two register and immediate) on page F4-4231.
let parseIntegerDataProcessing (phlp: ParsingHelper) bin =
  match extract bin 23 20 (* opc:S *) with
  | 0b0000u -> render phlp bin Op.AND None OD.OprRdRnConst
  | 0b0001u -> render phlp bin Op.ANDS None OD.OprRdRnConstCF
  | 0b0010u -> render phlp bin Op.EOR None OD.OprRdRnConst
  | 0b0011u -> render phlp bin Op.EORS None OD.OprRdRnConstCF
  | 0b0100u -> parseIntDataProc0100 phlp bin
  | 0b0101u -> parseIntDataProc0101 phlp bin
  | 0b0110u -> render phlp bin Op.RSB None OD.OprRdRnConst
  | 0b0111u -> render phlp bin Op.RSBS None OD.OprRdRnConst
  | 0b1000u -> parseIntDataProc1000 phlp bin
  | 0b1001u -> parseIntDataProc1001 phlp bin
  | 0b1010u -> render phlp bin Op.ADC None OD.OprRdRnConst
  | 0b1011u -> render phlp bin Op.ADCS None OD.OprRdRnConst
  | 0b1100u -> render phlp bin Op.SBC None OD.OprRdRnConst
  | 0b1101u -> render phlp bin Op.SBCS None OD.OprRdRnConst
  | 0b1110u -> render phlp bin Op.RSC None OD.OprRdRnConst
  | 0b1111u -> render phlp bin Op.RSCS None OD.OprRdRnConst
  | _ (* 0b1111u *) -> render phlp bin Op.RSCS None OD.OprRdRnConst

/// Move Halfword (immediate) on page F4-4232.
let parseMoveHalfword (phlp: ParsingHelper) bin =
  match pickBit bin 22 (* H *) with
  | 0b0u -> render phlp bin Op.MOVW None OD.OprRdImm16
  | _ (* 0b1u *) -> render phlp bin Op.MOVT None OD.OprRdImm16

/// Move Special Register and Hints (immediate) on page F4-4233.
let parseMovSpecReg00 (phlp: ParsingHelper) bin =
  match extract bin 5 0 (* imm12<5:0> *) with
  | 0b000000u -> render phlp bin Op.NOP None OD.OprNo
  | 0b000001u -> render phlp bin Op.YIELD None OD.OprNo
  | 0b000010u -> render phlp bin Op.WFE None OD.OprNo
  | 0b000011u -> render phlp bin Op.WFI None OD.OprNo
  | 0b000100u -> render phlp bin Op.SEV None OD.OprNo
  | 0b000101u -> render phlp bin Op.SEVL None OD.OprNo (* AArch32 *)
  | 0b000110u | 0b000111u -> render phlp bin Op.NOP None OD.OprNo
  | imm when imm &&& 0b111000u = 0b001000u (* 0b001xxx *) ->
    render phlp bin Op.NOP None OD.OprNo
  | 0b010000u ->
    phlp.Cond <> Condition.AL |> checkUnpred
    render phlp bin Op.ESB None OD.OprNo (* Armv8.2 *)
  | 0b010001u -> render phlp bin Op.NOP None OD.OprNo
  | 0b010010u -> (* TSB CSYNC *)
    phlp.Cond <> Condition.AL |> checkUnpred
    render phlp bin Op.TSB None OD.OprNo (* Armv8.4 *)
  | 0b010011u -> render phlp bin Op.NOP None OD.OprNo
  | 0b010100u ->
    phlp.Cond <> Condition.AL |> checkUnpred
    render phlp bin Op.CSDB None OD.OprNo
  | 0b010101u -> render phlp bin Op.NOP None OD.OprNo
  | imm when imm &&& 0b111000u = 0b011000u (* 0b011xxx *) ->
    render phlp bin Op.NOP None OD.OprNo
  | imm when imm &&& 0b111110u = 0b011110u (* 0b01111x *) ->
    render phlp bin Op.NOP None OD.OprNo
  | imm when imm &&& 0b100000u = 0b100000u (* 0b1xxxxx *) ->
    render phlp bin Op.NOP None OD.OprNo
  | _ -> raise ParsingFailureException

let parseMovSpecReg11 (phlp: ParsingHelper) bin =
  match extract bin 5 4 with
  | 0b10u -> render phlp bin Op.NOP None OD.OprNo
  | 0b11u -> render phlp bin Op.DBG None OD.OprNo
  | _ (* 0b0xu *) -> render phlp bin Op.NOP None OD.OprNo

/// Move Special Register and Hints (immediate) on page F4-4233.
let parseMoveSpecialRegisterAndHints (phlp: ParsingHelper) bin =
  let rimm4 = concat (pickBit bin 22) (extract bin 19 16) 4
  checkUndef (extract bin 15 12 <> 0b1111u)
  match extract bin 7 6 (* imm12<7:6> *) with
  | _ when rimm4 <> 0b00000u ->
    render phlp bin Op.MSR None OD.OprSregImm
  | 0b00u -> parseMovSpecReg00 phlp bin
  | 0b01u -> render phlp bin Op.NOP None OD.OprNo
  | 0b10u -> render phlp bin Op.NOP None OD.OprNo
  | _ (* 0b11u *) -> parseMovSpecReg11 phlp bin

/// Integer Test and Compare (one register and immediate) on page F4-4233.
let parseIntegerTestAndCompareOneReg (phlp: ParsingHelper) bin =
  match extract bin 22 21 (* opc *) with
  | 0b00u -> render phlp bin Op.TST None OD.OprRnConstCF
  | 0b01u -> render phlp bin Op.TEQ None OD.OprRnConstCF
  | 0b10u -> render phlp bin Op.CMP None OD.OprRnConst
  | _ (* 0b11u *) -> render phlp bin Op.CMN None OD.OprRnConst

let parseCase00110 (phlp: ParsingHelper) bin =
  match extract bin 21 20 with
  | 0b00u -> parseMoveHalfword phlp bin
  | 0b10u -> parseMoveSpecialRegisterAndHints phlp bin
  | _ (* 0bx1u *) -> parseIntegerTestAndCompareOneReg phlp bin

/// Logical Arithmetic (two register and immediate) on page F4-4234.
let parseLogicalArithmetic (phlp: ParsingHelper) bin =
  match (extract bin 22 20) (* opc:S *) with
  | 0b000u -> render phlp bin Op.ORR None OD.OprRdRnConst
  | 0b001u -> render phlp bin Op.ORRS None OD.OprRdRnConstCF
  | 0b010u -> render phlp bin Op.MOV None OD.OprRdConst
  | 0b011u -> render phlp bin Op.MOVS None OD.OprRdConstCF
  | 0b100u -> render phlp bin Op.BIC None OD.OprRdRnConst
  | 0b101u -> render phlp bin Op.BICS None OD.OprRdRnConstCF
  | 0b110u -> render phlp bin Op.MVN None OD.OprRdConst
  | _ (* 0b111u *) -> render phlp bin Op.MVNS None OD.OprRdConstCF

/// Data-processing immediate on page F4-4231.
let parseCase001 (phlp: ParsingHelper) bin =
  match extract bin 24 23 (* op0 *) with
  | 0b00u | 0b01u -> parseIntegerDataProcessing phlp bin
  | 0b10u -> parseCase00110 phlp bin
  | _ (* 0b11u *) -> parseLogicalArithmetic phlp bin

/// Data-processing and miscellaneous instructions on page F4-4218.
let parseCase00 (phlp: ParsingHelper) bin =
  match pickBit bin 25 (* op0 *) with
  | 0b0u -> parseCase000 phlp bin
  | _ (* 0b1u *) -> parseCase001 phlp bin

/// Alias conditions on page F5-4453.
let changeToAliasOfLDR bin =
  (* U == '1' && Rn == '1101' && imm12 == '000000000100' *)
  let isRn1101 = extract bin 19 16 = 0b1101u
  if (pickBit bin 23 = 1u) && isRn1101 && (extract bin 11 0 = 0b100u) then
    struct (Op.POP, OD.OprSingleRegs)
  else struct (Op.LDR, OD.OprRtMemImm12)

/// Alias conditions on page F5-4819.
let changeToAliasOfSTR bin =
  (* U == '0' && Rn == '1101' && imm12 == '000000000100' *)
  let isRn1101 = extract bin 19 16 = 0b1101u
  if (pickBit bin 23 = 0u) && isRn1101 && (extract bin 11 0 = 0b100u) then
    struct (Op.PUSH, OD.OprSingleRegs)
  else struct (Op.STR, OD.OprRtMemImm12)

/// Load/Store Word, Unsigned Byte (immediate, literal) on page F4-4234.
let parseCase010 (phlp: ParsingHelper) bin =
  let pw = concat (pickBit bin 24) (pickBit bin 21) 1
  let o2o1 = concat (pickBit bin 22) (pickBit bin 20) 1
  let rn = extract bin 19 16
  match concat pw o2o1 2 (* P:W:o2:o1 *) with
  (* LDR (literal) *)
  | 0b0001u when rn = 0b1111u ->
    chkWback bin; render phlp bin Op.LDR None OD.OprRtLabel
  | 0b1001u when rn = 0b1111u ->
    chkWback bin; render phlp bin Op.LDR None OD.OprRtLabel
  | 0b1101u when rn = 0b1111u ->
    chkWback bin; render phlp bin Op.LDR None OD.OprRtLabel
  (* LDRB (literal) *)
  | 0b0011u when rn = 0b1111u ->
    chkPCRtWithWB bin; render phlp bin Op.LDRB None OD.OprRtLabel
  | 0b1011u when rn = 0b1111u ->
    chkPCRtWithWB bin; render phlp bin Op.LDRB None OD.OprRtLabel
  | 0b1111u when rn = 0b1111u ->
    chkPCRtWithWB bin; render phlp bin Op.LDRB None OD.OprRtLabel
  | 0b0000u -> (* STR (immediate) - Post-indexed variant *)
    chkPCRnRt bin; render phlp bin Op.STR None OD.OprRtMemImm12
  | 0b0001u (* rn != 1111 *) -> (* LDR (immediate) - Post-indexed variant *)
    chkRnRt bin
    let struct (opcode, oprFn) = changeToAliasOfLDR bin
    render phlp bin opcode None oprFn
  | 0b0010u -> (* STRB (immediate) - Post-indexed variant *)
    chkPCRnRtWithWB bin
    render phlp bin Op.STRB None OD.OprRtMemImm12
  | 0b0011u (* rn != 1111 *) -> (* LDRB (immediate) - Post-indexed variant *)
    chkPCRtRnWithWB bin
    render phlp bin Op.LDRB None OD.OprRtMemImm12
  | 0b0100u ->
    chkPCRnRt bin; render phlp bin Op.STRT None OD.OprRtMemImm12P
  | 0b0101u ->
    chkPCRtRnEq bin; render phlp bin Op.LDRT None OD.OprRtMemImm12P
  | 0b0110u ->
    chkPCRtRnEq bin; render phlp bin Op.STRBT None OD.OprRtMemImm12P
  | 0b0111u ->
    chkPCRtRnEq bin; render phlp bin Op.LDRBT None OD.OprRtMemImm12P
  | 0b1000u ->
    chkPCRnWithWB bin; render phlp bin Op.STR None OD.OprRtMemImm12
  | 0b1001u (* rn != 1111 *) ->
    chkRnRt bin; render phlp bin Op.LDR None OD.OprRtMemImm12
  | 0b1010u -> chkPCRnRtWithWB bin
               render phlp bin Op.STRB None OD.OprRtMemImm12
  | 0b1011u (* rn != 1111 *) ->
    chkPCRtRnWithWB bin
    render phlp bin Op.LDRB None OD.OprRtMemImm12
  | 0b1100u ->
    chkPCRnRt bin
    let struct (opcode, oprFn) = changeToAliasOfSTR bin
    render phlp bin opcode None oprFn
  | 0b1101u (* rn != 1111 *) ->
    chkRnRt bin; render phlp bin Op.LDR None OD.OprRtMemImm12
  | 0b1110u ->
    chkPCRnRtWithWB bin
    render phlp bin Op.STRB None OD.OprRtMemImm12
  | _ (* 0b1111u & rn != 1111 *) ->
    chkPCRtRnWithWB bin
    render phlp bin Op.LDRB None OD.OprRtMemImm12

/// Load/Store Word, Unsigned Byte (register) on page F4-4235.
let parseCase0110 (phlp: ParsingHelper) bin =
  match concat (pickBit bin 24) (extract bin 22 20) 3 (* P:o2:W:o1 *) with
  | 0b0000u ->
    chkPCRmRn bin; render phlp bin Op.STR None OD.OprRtMemShf
  | 0b0001u ->
    chkPCRmRn bin; render phlp bin Op.LDR None OD.OprRtMemShf
  | 0b0010u ->
    chkPCRnRm bin; render phlp bin Op.STRT None OD.OprRtMemShfP
  | 0b0011u ->
    chkPCRtRnRm bin; render phlp bin Op.LDRT None OD.OprRtMemShfP
  | 0b0100u ->
    chkPCRtRm bin; render phlp bin Op.STRB None OD.OprRtMemShf
  | 0b0101u ->
    chkPCRtRm bin; render phlp bin Op.LDRB None OD.OprRtMemShf
  | 0b0110u ->
    chkPCRtRnRm bin; render phlp bin Op.STRBT None OD.OprRtMemShfP
  | 0b0111u ->
    chkPCRtRnRm bin; render phlp bin Op.LDRBT None OD.OprRtMemShfP
  | 0b1000u | 0b1010u ->
    chkPCRmRn bin; render phlp bin Op.STR None OD.OprRtMemShf
  | 0b1001u | 0b1011u ->
    chkPCRmRn bin; render phlp bin Op.LDR None OD.OprRtMemShf
  | 0b1100u | 0b1110u ->
    chkPCRtRm bin; render phlp bin Op.STRB None OD.OprRtMemShf
  | _ (*  0b11x1u *) ->
    chkPCRtRm bin; render phlp bin Op.LDRB None OD.OprRtMemShf

/// Parallel Arithmetic on page F4-4237.
let parseParallelArith (phlp: ParsingHelper) bin =
  match concat (extract bin 22 20) (extract bin 7 5) 3 (* op1:B:op2 *) with
  | 0b000000u | 0b000001u | 0b000010u | 0b000111u | 0b000100u | 0b000101u
  | 0b000110u | 0b000111u (* 000xxx *) -> raise ParsingFailureException
  | 0b001000u ->
    chkPCRdOptRnRm bin; render phlp bin Op.SADD16 None OD.OprRdRnRm
  | 0b001001u ->
    chkPCRdOptRnRm bin; render phlp bin Op.SASX None OD.OprRdRnRm
  | 0b001010u ->
    chkPCRdOptRnRm bin; render phlp bin Op.SSAX None OD.OprRdRnRm
  | 0b001011u ->
    chkPCRdOptRnRm bin; render phlp bin Op.SSUB16 None OD.OprRdRnRm
  | 0b001100u ->
    chkPCRdOptRnRm bin; render phlp bin Op.SADD8 None OD.OprRdRnRm
  | 0b001101u -> raise ParsingFailureException
  | 0b001110u -> raise ParsingFailureException
  | 0b001111u ->
    chkPCRdOptRnRm bin; render phlp bin Op.SSUB8 None OD.OprRdRnRm
  | 0b010000u ->
    chkPCRdOptRnRm bin; render phlp bin Op.QADD16 None OD.OprRdRnRm
  | 0b010001u ->
    chkPCRdOptRnRm bin; render phlp bin Op.QASX None OD.OprRdRnRm
  | 0b010010u ->
    chkPCRdOptRnRm bin; render phlp bin Op.QSAX None OD.OprRdRnRm
  | 0b010011u ->
    chkPCRdOptRnRm bin; render phlp bin Op.QSUB16 None OD.OprRdRnRm
  | 0b010100u ->
    chkPCRdOptRnRm bin; render phlp bin Op.QADD8 None OD.OprRdRnRm
  | 0b010101u -> raise ParsingFailureException
  | 0b010110u -> raise ParsingFailureException
  | 0b010111u ->
    chkPCRdOptRnRm bin; render phlp bin Op.QSUB8 None OD.OprRdRnRm
  | 0b011000u ->
    chkPCRdOptRnRm bin; render phlp bin Op.SHADD16 None OD.OprRdRnRm
  | 0b011001u ->
    chkPCRdOptRnRm bin; render phlp bin Op.SHASX None OD.OprRdRnRm
  | 0b011010u ->
    chkPCRdOptRnRm bin; render phlp bin Op.SHSAX None OD.OprRdRnRm
  | 0b011011u ->
    chkPCRdOptRnRm bin; render phlp bin Op.SHSUB16 None OD.OprRdRnRm
  | 0b011100u ->
    chkPCRdOptRnRm bin; render phlp bin Op.SHADD8 None OD.OprRdRnRm
  | 0b011101u -> raise ParsingFailureException
  | 0b011110u -> raise ParsingFailureException
  | 0b011111u ->
    chkPCRdOptRnRm bin; render phlp bin Op.SHSUB8 None OD.OprRdRnRm
  | 0b100000u | 0b100001u | 0b100010u | 0b100111u | 0b100100u | 0b100101u
  | 0b100110u | 0b100111u (* 100xxx *) -> raise ParsingFailureException
  | 0b101000u ->
    chkPCRdOptRnRm bin; render phlp bin Op.UADD16 None OD.OprRdRnRm
  | 0b101001u ->
    chkPCRdOptRnRm bin; render phlp bin Op.UASX None OD.OprRdRnRm
  | 0b101010u ->
    chkPCRdOptRnRm bin; render phlp bin Op.USAX None OD.OprRdRnRm
  | 0b101011u ->
    chkPCRdOptRnRm bin; render phlp bin Op.USUB16 None OD.OprRdRnRm
  | 0b101100u ->
    chkPCRdOptRnRm bin; render phlp bin Op.UADD8 None OD.OprRdRnRm
  | 0b101101u -> raise ParsingFailureException
  | 0b101110u -> raise ParsingFailureException
  | 0b101111u ->
    chkPCRdOptRnRm bin; render phlp bin Op.USUB8 None OD.OprRdRnRm
  | 0b110000u ->
    chkPCRdOptRnRm bin; render phlp bin Op.UQADD16 None OD.OprRdRnRm
  | 0b110001u ->
    chkPCRdOptRnRm bin; render phlp bin Op.UQASX None OD.OprRdRnRm
  | 0b110010u ->
    chkPCRdOptRnRm bin; render phlp bin Op.UQSAX None OD.OprRdRnRm
  | 0b110011u ->
    chkPCRdOptRnRm bin; render phlp bin Op.UQSUB16 None OD.OprRdRnRm
  | 0b110100u ->
    chkPCRdOptRnRm bin; render phlp bin Op.UQADD8 None OD.OprRdRnRm
  | 0b110101u -> raise ParsingFailureException
  | 0b110110u -> raise ParsingFailureException
  | 0b110111u ->
    chkPCRdOptRnRm bin; render phlp bin Op.UQSUB8 None OD.OprRdRnRm
  | 0b111000u ->
    chkPCRdOptRnRm bin; render phlp bin Op.UHADD16 None OD.OprRdRnRm
  | 0b111001u ->
    chkPCRdOptRnRm bin; render phlp bin Op.UHASX None OD.OprRdRnRm
  | 0b111010u ->
    chkPCRdOptRnRm bin; render phlp bin Op.UHSAX None OD.OprRdRnRm
  | 0b111011u ->
    chkPCRdOptRnRm bin; render phlp bin Op.UHSUB16 None OD.OprRdRnRm
  | 0b111100u ->
    chkPCRdOptRnRm bin; render phlp bin Op.UHADD8 None OD.OprRdRnRm
  | 0b111101u -> raise ParsingFailureException
  | 0b111110u -> raise ParsingFailureException
  | _ (* 0b111111u *) ->
    chkPCRdOptRnRm bin; render phlp bin Op.UHSUB8 None OD.OprRdRnRm

/// Saturate 16-bit on page F4-4239.
let parseSaturate16bit (phlp: ParsingHelper) bin =
  match pickBit bin 22 (* U *) with
  | 0b0u ->
    chkPCRdRn bin; render phlp bin Op.SSAT16 None OD.OprRdImmRn
  | _ (* 0b1u *) ->
    chkPCRdRn bin; render phlp bin Op.USAT16 None OD.OprRdImmRn

/// Reverse Bit/Byte on page F4-4240.
let parseReverseBitByte (phlp: ParsingHelper) bin =
  match concat (pickBit bin 22) (pickBit bin 7) 1 (* o1:o2 *) with
  | 0b00u -> chkPCRdRm bin; render phlp bin Op.REV None OD.OprRdRm
  | 0b01u -> chkPCRdRm bin; render phlp bin Op.REV16 None OD.OprRdRm
  | 0b10u -> chkPCRdRm bin; render phlp bin Op.RBIT None OD.OprRdRm
  | _ (* 0b11u *) ->
    chkPCRdRm bin; render phlp bin Op.REVSH None OD.OprRdRm

/// Saturate 32-bit on page F4-4240.
let parseSaturate32bit (phlp: ParsingHelper) bin =
  match pickBit bin 22 (* U *) with
  | 0b0u ->
    chkPCRdRn bin; render phlp bin Op.SSAT None OD.OprRdImmRnShf
  | _ (* 0b1u *) ->
    chkPCRdRn bin; render phlp bin Op.USAT None OD.OprRdImmRnShf

/// Extend and Add on page F4-4241.
let parseExtendAndAdd (phlp: ParsingHelper) bin =
  let isNotRn1111 bin = extract bin 19 16 <> 0b1111u (* Rn != 1111 *)
  match extract bin 22 20 (* U:op *) with
  | 0b000u when isNotRn1111 bin ->
    chkPCRdRm bin; render phlp bin Op.SXTAB16 None OD.OprRdRnRmROR
  | 0b000u ->
    chkPCRdRm bin; render phlp bin Op.SXTB16 None OD.OprRdRmROR
  | 0b010u when isNotRn1111 bin ->
    chkPCRdRm bin; render phlp bin Op.SXTAB None OD.OprRdRnRmROR
  | 0b010u ->
    chkPCRdRm bin; render phlp bin Op.SXTB None OD.OprRdRmROR
  | 0b011u when isNotRn1111 bin ->
    chkPCRdRm bin; render phlp bin Op.SXTAH None OD.OprRdRnRmROR
  | 0b011u ->
    chkPCRdRm bin; render phlp bin Op.SXTH None OD.OprRdRmROR
  | 0b100u when isNotRn1111 bin ->
    chkPCRdRm bin; render phlp bin Op.UXTAB16 None OD.OprRdRnRmROR
  | 0b100u ->
    chkPCRdRm bin; render phlp bin Op.UXTB16 None OD.OprRdRmROR
  | 0b110u when isNotRn1111 bin ->
    chkPCRdRm bin; render phlp bin Op.UXTAB None OD.OprRdRnRmROR
  | 0b110u ->
    chkPCRdRm bin; render phlp bin Op.UXTB None OD.OprRdRmROR
  | 0b111u when isNotRn1111 bin ->
    chkPCRdRm bin; render phlp bin Op.UXTAH None OD.OprRdRnRmROR
  | _ (* 0b111u *) ->
    chkPCRdRm bin; render phlp bin Op.UXTH None OD.OprRdRmROR

/// Signed multiply, Divide on page F4-4241.
let parseSignedMulDiv (phlp: ParsingHelper) bin =
  let isNotRa1111 bin = extract bin 15 12 (* a *) <> 0b1111u (* Ra != 1111 *)
  match concat (extract bin 22 20) (extract bin 7 5) 3 (* op1:op2 *) with
  | 0b000000u when isNotRa1111 bin ->
    chkPCRdRnRm bin; render phlp bin Op.SMLAD None OD.OprRdRnRmRa
  | 0b000001u when isNotRa1111 bin ->
    chkPCRdRnRm bin; render phlp bin Op.SMLADX None OD.OprRdRnRmRa
  | 0b000010u when isNotRa1111 bin ->
    chkPCRdRnRm bin; render phlp bin Op.SMLSD None OD.OprRdRnRmRa
  | 0b000011u when isNotRa1111 bin ->
    chkPCRdRnRm bin; render phlp bin Op.SMLSDX None OD.OprRdRnRmRa
  | 0b000100u | 0b000101u | 0b000110u | 0b000111u (* 0001xx *) ->
    raise ParsingFailureException
  | 0b000000u ->
    chkPCRdRnRm bin; render phlp bin Op.SMUAD None OD.OprRdRnRmOpt
  | 0b000001u ->
    chkPCRdRnRm bin; render phlp bin Op.SMUADX None OD.OprRdRnRmOpt
  | 0b000010u ->
    chkPCRdRnRm bin; render phlp bin Op.SMUSD None OD.OprRdRnRmOpt
  | 0b000011u ->
    chkPCRdRnRm bin; render phlp bin Op.SMUSDX None OD.OprRdRnRmOpt
  | 0b001000u ->
    chkPCRdRnRmRaNot bin
    render phlp bin Op.SDIV None OD.OprRdRnRmOpt
  | 0b001001u | 0b001010u | 0b001011u | 0b001100u | 0b001101u | 0b001110u
  | 0b001111u (* 001 - != 000 *) -> raise ParsingFailureException
  | 0b010000u | 0b010001u | 0b010010u | 0b010011u | 0b010100u | 0b010101u
  | 0b010110u | 0b010111u (* 010 - - *) -> raise ParsingFailureException
  | 0b011000u ->
    chkPCRdRnRmRaNot bin
    render phlp bin Op.UDIV None OD.OprRdRnRmOpt
  | 0b011001u | 0b011010u | 0b011011u | 0b011100u | 0b011101u | 0b011110u
  | 0b011111u (* 001 - != 000 *) -> raise ParsingFailureException
  | 0b100000u ->
    chkPCRdlRdhRnRm bin
    render phlp bin Op.SMLALD None OD.OprRdlRdhRnRm
  | 0b100001u ->
    chkPCRdlRdhRnRm bin
    render phlp bin Op.SMLALDX None OD.OprRdlRdhRnRm
  | 0b100010u ->
    chkPCRdlRdhRnRm bin
    render phlp bin Op.SMLSLD None OD.OprRdlRdhRnRm
  | 0b100011u ->
    chkPCRdlRdhRnRm bin
    render phlp bin Op.SMLSLDX None OD.OprRdlRdhRnRm
  | 0b100100u | 0b100101u | 0b100110u | 0b100111u (* 100 - 1xx *) ->
    raise ParsingFailureException
  | 0b101000u when isNotRa1111 bin ->
    chkPCRdRnRm bin; render phlp bin Op.SMMLA None OD.OprRdRnRmRa
  | 0b101001u when isNotRa1111 bin ->
    chkPCRdRnRm bin; render phlp bin Op.SMMLAR None OD.OprRdRnRmRa
  | 0b101010u | 0b101011u (* 101 - 01x *) -> raise ParsingFailureException
  | 0b101100u | 0b101101u (* 101 - 10x *) -> raise ParsingFailureException
  | 0b101110u ->
    chkPCRdRnRmRa bin; render phlp bin Op.SMMLS None OD.OprRdRnRmRa
  | 0b101111u ->
    chkPCRdRnRmRa bin; render phlp bin Op.SMMLSR None OD.OprRdRnRmRa
  | 0b101000u ->
    chkPCRdRnRm bin; render phlp bin Op.SMMUL None OD.OprRdRnRmOpt
  | 0b101001u ->
    chkPCRdRnRm bin; render phlp bin Op.SMMULR None OD.OprRdRnRmOpt
  | _ (* 11x - - *) -> raise ParsingFailureException

/// Unsigned Sum of Absolute Differences on page F4-4242.
let parseUnsignedSumOfAbsoluteDiff (phlp: ParsingHelper) bin =
  match extract bin 15 12 (* Ra *) with
  | 0b1111u ->
    chkPCRdRnRm bin; render phlp bin Op.USAD8 None OD.OprRdRnRmOpt
  | _ (* != 1111 *) ->
    chkPCRdRnRm bin; render phlp bin Op.USADA8 None OD.OprRdRnRmRa

/// Bitfield Insert on page F4-4243.
let parseBitfieldInsert (phlp: ParsingHelper) bin =
  match extract bin 3 0 (* Rn *) with
  | 0b1111u ->
    chkPCRd bin; render phlp bin Op.BFC None OD.OprRdLsbWidth
  | _ (* != 1111 *) ->
    chkPCRd bin; render phlp bin Op.BFI None OD.OprRdRnLsbWidth

/// Permanently UNDEFINED on page F4-4243.
let parsePermanentlyUndef (phlp: ParsingHelper) bin =
  if phlp.Cond <> Condition.AL then raise ParsingFailureException
  else render phlp bin Op.UDF None OD.OprImm16

/// Bitfield Extract on page F4-4244.
let parseBitfieldExtract (phlp: ParsingHelper) bin =
  match pickBit bin 22 (* U *) with
  | 0b0u ->
    chkPCRdRn bin; render phlp bin Op.SBFX None OD.OprRdRnLsbWidthM1
  | _ (* 0b1u *) ->
    chkPCRdRn bin; render phlp bin Op.UBFX None OD.OprRdRnLsbWidthM1

/// Media instructions on page F4-4236.
let parseCase0111 (phlp: ParsingHelper) bin =
  match concat (extract bin 24 20) (extract bin 7 5) 3 (* op0:op1 *) with
  | b when b &&& 0b11000000u = 0b00000000u (* 0b00xxxxxx *) ->
    parseParallelArith phlp bin
  | 0b01000101u ->
    chkPCRdOptRnRm bin; render phlp bin Op.SEL None OD.OprRdRnRm
  | 0b01000001u -> raise ParsingFailureException
  | 0b01000000u | 0b01000100u (* 01000x00 *) ->
    chkPCRdOptRnRm bin; render phlp bin Op.PKHBT None OD.OprRdRnRmShf
  | 0b01000010u | 0b01000110u (* 01000x10 *) ->
    chkPCRdOptRnRm bin; render phlp bin Op.PKHTB None OD.OprRdRnRmShf
  | 0b01001001u | 0b01001101u (* 01001x01 *) -> raise ParsingFailureException
  | 0b01001000u | 0b01001010u | 0b01001100u | 0b01001110u (* 01001xx0 *) ->
    raise ParsingFailureException
  | 0b01100001u | 0b01100101u | 0b01101001u | 0b01101101u (* 0110xx01 *) ->
    raise ParsingFailureException
  | 0b01100000u | 0b01100010u | 0b01100100u | 0b01100110u | 0b01101000u
  | 0b01101010u | 0b01101100u | 0b01101110u (* 0110xxx0 *) ->
    raise ParsingFailureException
  | 0b01010001u | 0b01110001u (* 01x10001 *) ->
    parseSaturate16bit phlp bin
  | 0b01010101u | 0b01110101u (* 01x10101 *) -> raise ParsingFailureException
  | 0b01011001u | 0b01011101u | 0b01111001u | 0b01111101u (* 01x11x01 *) ->
    parseReverseBitByte phlp bin
  | 0b01010000u | 0b01010010u | 0b01010100u | 0b01010110u | 0b01011000u
  | 0b01011010u | 0b01011100u | 0b01011110u | 0b01110000u | 0b01110010u
  | 0b01110100u | 0b01110110u | 0b01111000u | 0b01111010u | 0b01111100u
  | 0b01111110u (* 01x1xxx0 *) -> parseSaturate32bit phlp bin
  | 0b01000111u | 0b01001111u | 0b01010111u | 0b01011111u | 0b01100111u
  | 0b01101111u | 0b01110111u | 0b01111111u (* 01xxx111 *) ->
    raise ParsingFailureException
  | 0b01000011u | 0b01001011u | 0b01010011u | 0b01011011u | 0b01100011u
  | 0b01101011u | 0b01110011u | 0b01111011u (* 01xxx011 *) ->
    parseExtendAndAdd phlp bin
  | b when b &&& 0b11000000u = 0b10000000u (* 10xxxxxx *) ->
    parseSignedMulDiv phlp bin
  | 0b11000000u -> parseUnsignedSumOfAbsoluteDiff phlp bin
  | 0b11000100u -> raise ParsingFailureException
  | 0b11001000u | 0b11001100u (* 11001x00 *) -> raise ParsingFailureException
  | 0b11010000u | 0b11010100u | 0b11011000u | 0b11011100u (* 1101xx00 *) ->
    raise ParsingFailureException
  | 0b11000111u | 0b11001111u | 0b11010111u | 0b11011111u (* 110xx111 *) ->
    raise ParsingFailureException
  | 0b11100111u | 0b11101111u (* 1110x111 *) -> raise ParsingFailureException
  | 0b11100000u | 0b11100100u | 0b11101000u | 0b11101100u (* 1110xx00 *) ->
    parseBitfieldInsert phlp bin
  | 0b11110111u -> raise ParsingFailureException
  | 0b11111111u -> parsePermanentlyUndef phlp bin
  | 0b11110000u | 0b11110100u | 0b11111000u | 0b11111100u (* 1111xx00 *) ->
    raise ParsingFailureException
  | 0b11000010u | 0b11000110u | 0b11001010u | 0b11001110u | 0b11100010u
  | 0b11100110u | 0b11101010u | 0b11101110u (* 11x0xx10 *) ->
    raise ParsingFailureException
  | 0b11010010u | 0b11010110u | 0b11011010u | 0b11011110u | 0b11110010u
  | 0b11110110u | 0b11111010u | 0b11111110u (* 11x1xx10 *) ->
    parseBitfieldExtract phlp bin
  | 0b11000011u | 0b11001011u | 0b11010011u | 0b11011011u | 0b11100011u
  | 0b11101011u | 0b11110011u | 0b11111011u (* 11xxx011 *) ->
    raise ParsingFailureException
  | b when b &&& 0b11000011u = 0b11000001u (* 11xxxx01 *) ->
    raise ParsingFailureException
  | _ -> raise ParsingFailureException

let parseCase011 (phlp: ParsingHelper) bin =
  match pickBit bin 4 with
  | 0b0u -> parseCase0110 phlp bin
  | _ (* 0b1u *) -> parseCase0111 phlp bin

let parseCase01 (phlp: ParsingHelper) bin =
  match pickBit bin 25 with
  | 0b0u -> parseCase010 phlp bin
  | _ (* 0b1u *) -> parseCase011 phlp bin

/// Exception Save/Restore on page F4-4244.
let parseExceptionSaveStore (phlp: ParsingHelper) bin =
  match concat (extract bin 24 22) (pickBit bin 20) 1 (* P:U:S:L *) with
  | 0b0001u -> chkPCRn bin; render phlp bin Op.RFEDA None OD.OprRn
  | 0b0010u -> render phlp bin Op.SRSDA None OD.OprSPMode
  | 0b0101u -> chkPCRn bin; render phlp bin Op.RFEIA None OD.OprRn
  | 0b0110u -> render phlp bin Op.SRSIA None OD.OprSPMode
  | 0b1001u -> chkPCRn bin; render phlp bin Op.RFEDB None OD.OprRn
  | 0b1010u -> render phlp bin Op.SRSDB None OD.OprSPMode
  | 0b1101u -> chkPCRn bin; render phlp bin Op.RFEIB None OD.OprRn
  | 0b1110u -> render phlp bin Op.SRSIB None OD.OprSPMode
  | _ (* 0b--00u or 0b--11u *) -> raise ParsingFailureException

/// Alias conditions on page F5-4438.
let changeToAliasOfLDM bin =
  if (wbackW bin) && (extract bin 19 16 = 0b1101u) && (bitCount bin > 1) then
    struct (Op.POP, OD.OprRegs)
  else struct (Op.LDM, OD.OprRnRegs)

/// Alias conditions on page F5-4813.
let changeToAliasOfSTMDB bin =
  if (pickBit bin 21 = 1u) && (extract bin 19 16 = 0b1101u) && (bitCount bin > 1) then
    struct (Op.PUSH, OD.OprRegs)
  else struct (Op.STMDB, OD.OprRnRegs)

/// Load/Store Multiple on page F4-4245.
let parseLoadStoreMultiple (phlp: ParsingHelper) bin =
  match concat (extract bin 24 22) (pickBit bin 20) 1 (* P:U:op:L *) with
  | 0b0000u ->
    chkPCRnRegs bin; render phlp bin Op.STMDA None OD.OprRnRegs
  | 0b0001u ->
    chkWBRegs bin; render phlp bin Op.LDMDA None OD.OprRnRegs
  | 0b0100u ->
    chkPCRnRegs bin; render phlp bin Op.STM None OD.OprRnRegs
  | 0b0101u ->
    chkWBRegs bin
    let struct (opcode, oprFn) = changeToAliasOfLDM bin
    render phlp bin opcode None oprFn
  | 0b0010u ->
    chkPCRnRegs bin; render phlp bin Op.STMDA None OD.OprRnRegsCaret
  | 0b0110u ->
    chkPCRnRegs bin; render phlp bin Op.STMIA None OD.OprRnRegsCaret
  | 0b1010u ->
    chkPCRnRegs bin; render phlp bin Op.STMDB None OD.OprRnRegsCaret
  | 0b1110u ->
    chkPCRnRegs bin; render phlp bin Op.STMIB None OD.OprRnRegsCaret
  | 0b1000u ->
    chkPCRnRegs bin
    let struct (opcode, oprFn) = changeToAliasOfSTMDB bin
    render phlp bin opcode None oprFn
  | 0b1001u ->
    chkWBRegs bin; render phlp bin Op.LDMDB None OD.OprRnRegs
  | 0b0011u ->
    (* 0xxxxxxxxxxxxxxx LDM (User registers) *)
    if pickBit bin 15 = 0u then
      chkPCRnRegs bin
      render phlp bin Op.LDMDA None OD.OprRnRegsCaret
    else (* 1xxxxxxxxxxxxxxx LDM (exception return) *)
      chkWBRegs bin; render phlp bin Op.LDMDA None OD.OprRnRegsCaret
  | 0b0111u ->
    if pickBit bin 15 = 0u then
      chkPCRnRegs bin; render phlp bin Op.LDM None OD.OprRnRegsCaret
    else chkWBRegs bin; render phlp bin Op.LDM None OD.OprRnRegsCaret
  | 0b1011u ->
    if pickBit bin 15 = 0u then
      chkPCRnRegs bin
      render phlp bin Op.LDMDB None OD.OprRnRegsCaret
    else
      chkWBRegs bin; render phlp bin Op.LDMDB None OD.OprRnRegsCaret
  | 0b1111u ->
    if pickBit bin 15 = 0u then
      chkPCRnRegs bin
      render phlp bin Op.LDMIB None OD.OprRnRegsCaret
    else
      chkWBRegs bin; render phlp bin Op.LDMIB None OD.OprRnRegsCaret
  | 0b1100u ->
    chkPCRnRegs bin; render phlp bin Op.STMIB None OD.OprRnRegs
  | _ (* 0b1101u *) ->
    chkWBRegs bin; render phlp bin Op.LDMIB None OD.OprRnRegs

let parseCase100 (phlp: ParsingHelper) bin =
  match phlp.Cond with
  | Condition.UN (* 0b1111u *) -> parseExceptionSaveStore phlp bin
  | _ (* != 0b1111u *) -> parseLoadStoreMultiple phlp bin

/// Branch (immediate) on page F4-4246.
let parseCase101 (phlp: ParsingHelper) bin =
  match phlp.Cond with
  | Condition.UN (* 0b1111u *) ->
    render phlp bin Op.BLX None OD.OprLabelH
  | _ (* != 0b1111u *) ->
    if pickBit bin 24 (* H *) = 0u then
      render phlp bin Op.B None OD.OprLabel
    else render phlp bin Op.BL None OD.OprLabel

/// Branch, branch with link, and block data transfer on page F4-4244.
let parseCase10 (phlp: ParsingHelper) bin =
  match pickBit bin 25 (* op0 *) with
  | 0b0u -> parseCase100 phlp bin
  | _ (* 0b1u *) -> parseCase101 phlp bin

/// Supervisor call on page F4-4247.
let parseSupervisorCall (phlp: ParsingHelper) bin =
  if phlp.Cond = Condition.UN then raise ParsingFailureException
  else render phlp bin Op.SVC None OD.OprImm24

/// Advanced SIMD three registers of the same length extension on page F4-4248.
let parseAdvSIMDThreeRegSameLenExt (phlp: ParsingHelper) bin =
  let decodeFields =
    (extract bin 24 23 <<< 6) + (extract bin 21 20 <<< 4) +
    (pickBit bin 10 <<< 3) + (pickBit bin 8 <<< 2) + (pickBit bin 6 <<< 1) +
    (pickBit bin 4)
  match decodeFields (* op1:op2:op3:op4:Q:U *) with
  | 0b01000000u | 0b11000000u (* x1000000 *) -> (* Armv8.3 *)
    chkQVdVnVm bin
    render phlp bin Op.VCADD (oneDt SIMDTypF16) OD.OprDdDnDmRotate
  | 0b01010000u | 0b11010000u (* x1010000 *) -> (* Armv8.3 *)
    chkQVdVnVm bin
    render phlp bin Op.VCADD (oneDt SIMDTypF32) OD.OprDdDnDmRotate
  | 0b01000001u | 0b01010001u | 0b11000001u | 0b11010001u (* x10x0001 *) ->
    raise ParsingFailureException
  | 0b01000010u | 0b11000010u (* x1000010 *) -> (* Armv8.3 *)
    chkQVdVnVm bin
    render phlp bin Op.VCADD (oneDt SIMDTypF16) OD.OprQdQnQmRotate
  | 0b01010010u | 0b11010010u (* x1010010 *) -> (* Armv8.3 *)
    chkQVdVnVm bin
    render phlp bin Op.VCADD (oneDt SIMDTypF32) OD.OprQdQnQmRotate
  | b when b &&& 0b01101111u = 0b01000011u (* x10x0011 *) ->
    raise ParsingFailureException
  | b when b &&& 0b11101100u = 0b00000000u (* 000x00xx *) ->
    raise ParsingFailureException
  | b when b &&& 0b11101100u = 0b00000100u (* 000x01xx *) ->
    raise ParsingFailureException
  | 0b00001000u -> raise ParsingFailureException
  | 0b00001001u -> raise ParsingFailureException
  | 0b00001010u ->
    chkQVdVnVm bin
    render phlp bin Op.VMMLA (oneDt BF16) OD.OprQdQnQm (* Armv8.6 *)
  | 0b00001011u -> raise ParsingFailureException
  | 0b00001100u -> (* Armv8.6 *)
    chkQVdVnVm bin; render phlp bin Op.VDOT (oneDt BF16) OD.OprDdDnDm
  | 0b00001101u -> raise ParsingFailureException
  | 0b00001110u -> (* Armv8.6 *)
    chkQVdVnVm bin; render phlp bin Op.VDOT (oneDt BF16) OD.OprQdQnQm
  | 0b00001111u -> raise ParsingFailureException
  | 0b00011000u | 0b00011001u | 0b00011010u | 0b00011011u (* 000110xx *) ->
    raise ParsingFailureException
  | 0b00011100u | 0b00011101u | 0b00011110u | 0b00011111u (* 000111xx *) ->
    raise ParsingFailureException
  | 0b00100001u -> (* Armv8.2 *)
    chkQVd bin
    render phlp bin Op.VFMAL (oneDt SIMDTypF16) OD.OprDdSnSm
  | 0b00100011u -> (* Armv8.2 *)
    chkQVd bin
    render phlp bin Op.VFMAL (oneDt SIMDTypF16) OD.OprQdDnDm
  | 0b00100100u | 0b00100101u | 0b00100110u | 0b00100111u (* 001001xx *) ->
    raise ParsingFailureException
  | 0b00101000u | 0b00101001u (* 0010100xu *) -> raise ParsingFailureException
  | 0b00101010u -> (* Armv8.6 *)
    chkVdVnVm bin
    render phlp bin Op.VSMMLA (oneDt SIMDTypS8) OD.OprQdQnQm
  | 0b00101011u -> (* Armv8.6 *)
    chkVdVnVm bin
    render phlp bin Op.VUMMLA (oneDt SIMDTypU8) OD.OprQdQnQm
  | 0b00101100u -> (* Armv8.2 *)
    chkQVdVnVm bin
    render phlp bin Op.VSDOT (oneDt SIMDTypS8) OD.OprDdDnDm
  | 0b00101101u -> (* Armv8.2 *)
    chkQVdVnVm bin
    render phlp bin Op.VUDOT (oneDt SIMDTypU8) OD.OprDdDnDm
  | 0b00101110u -> (* Armv8.2 *)
    chkQVdVnVm bin
    render phlp bin Op.VSDOT (oneDt SIMDTypS8) OD.OprQdQnQm
  | 0b00101111u -> (* Armv8.2 *)
    chkQVdVnVm bin
    render phlp bin Op.VUDOT (oneDt SIMDTypU8) OD.OprQdQnQm
  | 0b00110001u -> (* Armv8.6 *)
    chkVdVnVm bin; render phlp bin Op.VFMAB (oneDt BF16) OD.OprQdQnQm
  | 0b00110011u -> (* Armv8.6 *)
    chkVdVnVm bin; render phlp bin Op.VFMAT (oneDt BF16) OD.OprQdQnQm
  | 0b00110100u | 0b00110101u | 0b00110110u | 0b00110111u (* 0b001101xxu *) ->
    raise ParsingFailureException
  | 0b00111000u | 0b00111001u | 0b00111010u | 0b00111011u (* 0b001110xxu *) ->
    raise ParsingFailureException
  | 0b00111100u | 0b00111101u | 0b00111110u | 0b00111111u (* 0b001111xxu *) ->
    raise ParsingFailureException
  | 0b01100001u -> (* Armv8.2 *)
    chkQVd bin
    render phlp bin Op.VFMSL (oneDt SIMDTypF16) OD.OprDdSnSm
  | 0b01100011u -> (* Armv8.2 *)
    chkQVd bin
    render phlp bin Op.VFMSL (oneDt SIMDTypF16) OD.OprQdDnDm
  | 0b01100100u | 0b01100101u | 0b01100110u | 0b01100111u (* 011001xx *) ->
    raise ParsingFailureException
  | 0b01101000u | 0b01101001u (* 0110100x *) -> raise ParsingFailureException
  | 0b01101010u -> (* Armv8.6 *)
    chkVdVnVm bin
    render phlp bin Op.VUSMMLA (oneDt SIMDTypS8) OD.OprQdQnQm
  | 0b01101011u -> raise ParsingFailureException
  | 0b01101100u -> (* Armv8.6 *)
    chkQVdVnVm bin
    render phlp bin Op.VUSDOT (oneDt SIMDTypS8) OD.OprDdDnDm
  | 0b01101101u | 0b01101111u (* 011011x1 *) -> raise ParsingFailureException
  | 0b01101110u ->  (* Armv8.6 *)
    chkQVdVnVm bin
    render phlp bin Op.VUSDOT (oneDt SIMDTypS8) OD.OprQdQnQm
  | 0b01110100u | 0b01110101u | 0b01110110u | 0b01110111u (* 011101xx *) ->
    raise ParsingFailureException
  | 0b01111000u | 0b01111001u | 0b01111010u | 0b01111011u (* 011110xx *) ->
    raise ParsingFailureException
  | 0b01111100u | 0b01111101u | 0b01111110u | 0b01111111u (* 011111xx *) ->
    raise ParsingFailureException
  (* VCMLA Armv8.3 *)
  | 0b00100000u ->
    chkQVdVnVm bin
    render phlp bin Op.VCMLA (oneDt SIMDTypF16) OD.OprDdDnDmRotate
  | 0b00100010u ->
    chkQVdVnVm bin
    render phlp bin Op.VCMLA (oneDt SIMDTypF16) OD.OprQdQnQmRotate
  | 0b00110000u ->
    chkQVdVnVm bin
    render phlp bin Op.VCMLA (oneDt SIMDTypF32) OD.OprDdDnDmRotate
  | 0b00110010u ->
    chkQVdVnVm bin
    render phlp bin Op.VCMLA (oneDt SIMDTypF32) OD.OprQdQnQmRotate
  | 0b10110100u | 0b10110101u | 0b10110110u | 0b10110111u (* 101101xx *) ->
    raise ParsingFailureException
  | 0b10111000u | 0b10111001u | 0b10111010u | 0b10111011u (* 101110xx *) ->
    raise ParsingFailureException
  | 0b10111100u | 0b10111101u | 0b10111110u | 0b10111111u (* 101111xx *) ->
    raise ParsingFailureException
  | 0b11110100u | 0b11110101u | 0b11110110u | 0b11110111u (* 111101xx *) ->
    raise ParsingFailureException
  | 0b11111000u | 0b11111001u | 0b11111010u | 0b11111011u (* 111110xx *) ->
    raise ParsingFailureException
  | 0b11111100u | 0b11111101u | 0b11111110u | 0b11111111u (* 111111xx *) ->
    raise ParsingFailureException
  | _ -> raise ParsingFailureException

/// Floating-point minNum/maxNum on page F4-4250.
let parseFloatingPointMinMaxNum (phlp: ParsingHelper) bin =
  match concat (pickBit bin 6) (extract bin 9 8) 2 (* op:size *) with
  | 0b000u | 0b100u -> raise UndefinedException
  | 0b001u ->
    render phlp bin Op.VMAXNM (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b010u ->
    render phlp bin Op.VMAXNM (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b011u ->
    render phlp bin Op.VMAXNM (oneDt SIMDTypF64) OD.OprDdDnDm
  | 0b101u ->
    render phlp bin Op.VMINNM (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b110u ->
    render phlp bin Op.VMINNM (oneDt SIMDTypF32) OD.OprSdSnSm
  | _ (* 111 *) ->
    render phlp bin Op.VMINNM (oneDt SIMDTypF64) OD.OprDdDnDm

/// Floating-point extraction and insertion on page F4-4250.
let parseFloatingPointExtractionAndInsertion (phlp: ParsingHelper) bin =
  match concat (extract bin 9 8) (pickBit bin 7) 1 (* size:op *) with
  | 0b010u | 0b011u (* 01x *) -> raise ParsingFailureException
  | 0b100u -> (* Armv8.2 *)
    render phlp bin Op.VMOVX (oneDt SIMDTypF16) OD.OprSdSm
  | 0b101u -> (* Armv8.2 *)
    render phlp bin Op.VINS (oneDt SIMDTypF16) OD.OprSdSm
  | 0b110u | 0b111u (* 11x *) -> raise ParsingFailureException
  | _ (* 00x *) -> raise UndefinedException

/// Floating-point directed convert to integer on page F4-4250.
let parseFloatingPointDirectedConvertToInteger (phlp: ParsingHelper) bin =
  let struct (dt1, oprs1) =
    match extract bin 9 8 (* size *) with
    | 0b00u -> raise UndefinedException
    | 0b01u -> struct (SIMDTypF16 |> oneDt, OD.OprSdSm)
    | 0b10u -> struct (SIMDTypF32 |> oneDt, OD.OprSdSm)
    | _ (* 11 *) -> struct (SIMDTypF64 |> oneDt, OD.OprDdDm)
  let struct (dt2, oprs2) =
    match extract bin 9 7 (* size:op *) with
    | 0b000u | 0b001u -> raise UndefinedException
    | 0b010u -> struct (twoDt (SIMDTypF16, SIMDTypU32), OD.OprSdSm)
    | 0b011u -> struct (twoDt (SIMDTypF16, SIMDTypS32), OD.OprSdSm)
    | 0b100u -> struct (twoDt (SIMDTypF32, SIMDTypU32), OD.OprSdSm)
    | 0b101u -> struct (twoDt (SIMDTypF32, SIMDTypS32), OD.OprSdSm)
    | 0b110u -> struct (twoDt (SIMDTypF64, SIMDTypU32), OD.OprSdDm)
    | _ (* 111 *) -> struct (twoDt (SIMDTypF64, SIMDTypS32), OD.OprSdDm)
  match extract bin 18 16 (* o1:RM *) with
  | 0b000u -> render phlp bin Op.VRINTA dt1 oprs1
  | 0b001u -> render phlp bin Op.VRINTN dt1 oprs1
  | 0b010u -> render phlp bin Op.VRINTP dt1 oprs1
  | 0b011u -> render phlp bin Op.VRINTM dt1 oprs1
  | 0b100u -> render phlp bin Op.VCVTA dt2 oprs2
  | 0b101u -> render phlp bin Op.VCVTN dt2 oprs2
  | 0b110u -> render phlp bin Op.VCVTP dt2 oprs2
  | _ (* 111 *) -> render phlp bin Op.VCVTM dt2 oprs2

/// Advanced SIMD and floating-point multiply with accumulate on page F4-4251.
let parseAdvSIMDAndFPMulWithAccumulate (phlp: ParsingHelper) bin =
  let decodeFields = (* op1:op2:Q:U *)
    (pickBit bin 23 <<< 4) + (extract bin 21 20 <<< 2) + (pickBit bin 6 <<< 1) +
    (pickBit bin 4)
  match decodeFields with
  | 0b00000u | 0b00100u | 0b01000u | 0b01100u (* 0xx00 *) -> (* Armv8.3 *)
    chkQVdVn bin
    render phlp bin Op.VCMLA (oneDt SIMDTypF16) OD.OprDdDnDmidxRotate
  | 0b00010u | 0b00110u | 0b01010u | 0b01110u (* 0xx10 *) -> (* Armv8.3 *)
    render phlp bin Op.VCMLA (oneDt SIMDTypF16) OD.OprQdQnDmidxRotate
  | 0b00001u -> (* Armv8.2 *)
    chkQVd bin
    render phlp bin Op.VFMAL (oneDt SIMDTypF16) OD.OprDdSnSmidx
  | 0b00011u -> (* Armv8.2 *)
    chkQVd bin
    render phlp bin Op.VFMAL (oneDt SIMDTypF16) OD.OprQdDnDmidx
  | 0b00101u -> (* Armv8.2 *)
    chkQVd bin
    render phlp bin Op.VFMSL (oneDt SIMDTypF16) OD.OprDdSnSmidx
  | 0b00111u -> (* Armv8.2 *)
    chkQVd bin
    render phlp bin Op.VFMSL (oneDt SIMDTypF16) OD.OprQdDnDmidx
  | 0b01001u | 0b01011u (* 010x1 *) -> raise ParsingFailureException
  | 0b01101u -> (* Armv8.6 *)
    chkVdVn bin
    render phlp bin Op.VFMAB (oneDt BF16) OD.OprQdQnDmidxm
  | 0b01111u -> (* Armv8.6 *)
    chkVdVn bin
    render phlp bin Op.VFMAT (oneDt BF16) OD.OprQdQnDmidxm
  | 0b10000u | 0b10100u | 0b11000u | 0b11100u (* 1xx00 *) -> (* Armv8.3 *)
    chkQVdVn bin
    render phlp bin Op.VCMLA (oneDt SIMDTypF16) OD.OprDdDnDm0Rotate
  | 0b10001u | 0b10011u | 0b10101u | 0b10111u | 0b11001u | 0b11011u | 0b11101u
  | 0b11111u (* 1xxx1 *) -> raise ParsingFailureException
  | _ (* 1xx10 *) -> (* Armv8.3 *)
    chkQVdVn bin
    render phlp bin Op.VCMLA (oneDt SIMDTypF16) OD.OprQdQnDm0Rotate

/// Advanced SIMD and floating-point dot product on page F4-4252.
let parseAdvSIMDAndFPDotProduct (phlp: ParsingHelper) bin =
  let decodeFields = (* op1:op2:op4:Q:U *)
    (pickBit bin 23 <<< 5) + (extract bin 21 20 <<< 3) + (pickBit bin 8 <<< 2) +
    (pickBit bin 6 <<< 1) + (pickBit bin 4)
  match decodeFields (* op1:op2:op4:Q:U *) with
  | 0b000000u | 0b000001u | 0b000010u | 0b000011u (* 0000xx *) ->
    raise ParsingFailureException
  | 0b000100u -> (* Armv8.6 *)
    chkQVdVn bin
    render phlp bin Op.VDOT (oneDt BF16) OD.OprDdDnDmidx
  | 0b000101u | 0b000111u (* 0001x1 *) -> raise ParsingFailureException
  | 0b000110u -> (* Armv8.6 *)
    chkQVdVn bin
    render phlp bin Op.VDOT (oneDt BF16) OD.OprQdQnDmidx
  | 0b001000u | 0b001001u | 0b001010u | 0b001011u (* 0010xx *) ->
    raise ParsingFailureException
  | 0b010000u | 0b010001u | 0b010010u | 0b010011u (* 0100xx *) ->
    raise ParsingFailureException
  | 0b010100u -> (* Armv8.2 *)
    chkQVdVn bin
    render phlp bin Op.VSDOT (oneDt SIMDTypS8) OD.OprDdDnDmidx
  | 0b010101u -> (* Armv8.2 *)
    chkQVdVn bin
    render phlp bin Op.VUDOT (oneDt SIMDTypU8) OD.OprDdDnDmidx
  | 0b010110u -> (* Armv8.2 *)
    chkQVdVn bin
    render phlp bin Op.VSDOT (oneDt SIMDTypS8) OD.OprQdQnDmidx
  | 0b010111u -> (* Armv8.2 *)
    chkQVdVn bin
    render phlp bin Op.VUDOT (oneDt SIMDTypU8) OD.OprQdQnDmidx
  | b when b &&& 0b111000u = 0b011000u (* 011xxx *) ->
    raise ParsingFailureException
  | b when b &&& 0b100100u = 0b100000u (* 1xx0xx *) ->
    raise ParsingFailureException
  | 0b100100u -> (* Armv8.6 *)
    chkQVdVn bin
    render phlp bin Op.VUSDOT (oneDt SIMDTypS8) OD.OprDdDnDmidx
  | 0b100101u -> (* Armv8.6 *)
    chkQVdVn bin
    render phlp bin Op.VSUDOT (oneDt SIMDTypU8) OD.OprDdDnDmidx
  | 0b100110u -> (* Armv8.6 *)
    chkQVdVn bin
    render phlp bin Op.VUSDOT (oneDt SIMDTypS8) OD.OprQdQnDmidx
  | 0b100111u -> (* Armv8.6 *)
    chkQVdVn bin
    render phlp bin Op.VSUDOT (oneDt SIMDTypU8) OD.OprQdQnDmidx
  | 0b101100u | 0b101101u | 0b101110u | 0b101111u (* 1011xx *) ->
    raise ParsingFailureException
  | b when b &&& 0b110100u = 0b110100u (* 11x1xx *) ->
    raise ParsingFailureException
  | _ -> raise ParsingFailureException

/// VSELEQ, VSELGE, VSELGT, VSELVS on page F6-5579.
let parseVectorSelect (phlp: ParsingHelper) bin =
  match concat (extract bin 21 20) (extract bin 9 8) 2 (* cc:size *) with
  | 0b0011u ->
    render phlp bin Op.VSELEQ (oneDt SIMDTypF64) OD.OprDdDnDm
  | 0b0001u ->
    render phlp bin Op.VSELEQ (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b0010u ->
    render phlp bin Op.VSELEQ (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b1011u ->
    render phlp bin Op.VSELGE (oneDt SIMDTypF64) OD.OprDdDnDm
  | 0b1001u ->
    render phlp bin Op.VSELGE (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b1010u ->
    render phlp bin Op.VSELGE (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b1111u ->
    render phlp bin Op.VSELGT (oneDt SIMDTypF64) OD.OprDdDnDm
  | 0b1101u ->
    render phlp bin Op.VSELGT (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b1110u ->
    render phlp bin Op.VSELGT (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b0111u ->
    render phlp bin Op.VSELVS (oneDt SIMDTypF64) OD.OprDdDnDm
  | 0b0101u ->
    render phlp bin Op.VSELVS (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b0110u ->
    render phlp bin Op.VSELVS (oneDt SIMDTypF32) OD.OprSdSnSm
  | _ (* xx00 *) -> raise UndefinedException

/// Unconditional Advanced SIMD and floating-point instructions on page F4-4247.
let parseUncondAdvSIMDAndFPInstr (phlp: ParsingHelper) bin =
  let op0op2op3op4op5 = (* op0:op2:op3:op4:op5 *)
    (extract bin 25 23 <<< 5) + (extract bin 10 8 <<< 2) +
    (pickBit bin 6 <<< 1) + (pickBit bin 4)
  let is00xxxx bin = (extract bin 21 16) &&& 0b110000u = 0b000000u
  let is110000 bin = extract bin 21 16 = 0b110000u
  let is111xxx bin = (extract bin 21 16) &&& 0b111000u = 0b111000u
  match op0op2op3op4op5 with
  | b when b &&& 0b10001000u = 0b00000000u ->
    parseAdvSIMDThreeRegSameLenExt phlp bin
  | 0b10000100u | 0b10001000u | 0b10001100u ->
    parseVectorSelect phlp bin
  | 0b10100100u | 0b10101000u | 0b10101100u | 0b10100110u | 0b10101010u
  | 0b10101110u when is00xxxx bin ->
    parseFloatingPointMinMaxNum phlp bin
  | 0b10100110u | 0b10101010u | 0b10101110u when is110000 bin ->
    parseFloatingPointExtractionAndInsertion phlp bin
  | 0b10100110u | 0b10101010u | 0b10101110u when is111xxx bin ->
    parseFloatingPointDirectedConvertToInteger phlp bin
  | 0b10000000u | 0b10000001u | 0b10000010u | 0b10000011u | 0b10100000u
  | 0b10100001u | 0b10100010u | 0b10100011u ->
    parseAdvSIMDAndFPMulWithAccumulate phlp bin
  | b when b &&& 0b11011000u = 0b10010000u ->
    parseAdvSIMDAndFPDotProduct phlp bin
  | _ -> raise ParsingFailureException

/// Advanced SIMD and floating-point 64-bit move on page F4-4253.
let parseAdvancedSIMDandFP64bitMove (phlp: ParsingHelper) bin =
  let decodeFields = (* D:op:size:opc2:o3 *)
    (pickBit bin 22 <<< 6) + (pickBit bin 20 <<< 5) + (extract bin 9 6 <<< 1) +
    (pickBit bin 4)
  match decodeFields (* D:op:size:opc2:o3 *) with
  | 0b1010001u ->
    chkPCRtRt2VmEq bin; render phlp bin Op.VMOV None OD.OprSmSm1RtRt2
  | 0b1011001u ->
    chkPCRtRt2ArmEq bin; render phlp bin Op.VMOV None OD.OprDmRtRt2
  | 0b1110001u ->
    chkPCRtRt2VmEq bin; render phlp bin Op.VMOV None OD.OprRtRt2SmSm1
  | 0b1111001u ->
    chkPCRtRt2ArmEq bin; render phlp bin Op.VMOV None OD.OprRtRt2Dm
  | _ (* 0xxxxxx 1xxxxx0 1x0x001 1xxx01x 1xxx1xx *) ->
    raise ParsingFailureException

/// System register 64-bit move on page F4-4254.
let parseSystemReg64bitMove (phlp: ParsingHelper) bin =
  match concat (pickBit bin 22) (pickBit bin 20) 1 (* D:L *) with
  | 0b00u | 0b01u -> raise ParsingFailureException
  | 0b10u ->
    chkPCRtRt2 bin; render phlp bin Op.MCRR None OD.OprCpOpc1RtRt2CRm
  | _ (* 0b11u *) ->
    chkPCRtRt2Eq bin
    render phlp bin Op.MRRC None OD.OprCpOpc1RtRt2CRm

/// Advanced SIMD and floating-point load/store on page F4-4254.
let parseAdvSIMDAndFPLdSt (phlp: ParsingHelper) bin =
  let decodeFields = (* P:U:W:L:size *)
    (extract bin 24 23 <<< 4) + (extract bin 21 20 <<< 2) + (extract bin 9 8)
  let isxxxxxxx0 bin = pickBit bin 0 = 0u
  let isxxxxxxx1 bin = pickBit bin 1 = 1u
  let isRn1111 bin = extract bin 19 16 = 0b1111u
  match decodeFields (* P:U:W:L:size *) with
  | 0b001000u | 0b001001u | 0b001010u | 0b001011u | 0b001100u | 0b001101u
  | 0b001110u | 0b001111u (* 001xxx *) -> raise ParsingFailureException
  | 0b010000u | 0b010001u | 0b010100u | 0b011000u | 0b011000u | 0b011001u
  | 0b011100u | 0b011101u (* 01xx0x *) -> raise ParsingFailureException
  | 0b010010u | 0b011010u (* 01x010 *) ->
    chkPCRnDRegs bin; render phlp bin Op.VSTMIA None OD.OprRnSreglist
  | 0b010011u | 0b011011u when isxxxxxxx0 bin ->
    chkPCRnRegsImm bin
    render phlp bin Op.VSTMIA None OD.OprRnDreglist
  | 0b010011u | 0b011011u (* 01x011 *) when isxxxxxxx1 bin ->
    chkPCRnRegsImm bin
    render phlp bin Op.FSTMIAX None OD.OprRnDreglist
  | 0b010110u | 0b011110u (* 01x110 *) ->
    chkPCRnDRegs bin
    render phlp bin Op.VLDMIA None OD.OprRnSreglist
  | 0b010111u | 0b011111u (* 01x111 *) when isxxxxxxx0 bin ->
    chkPCRnRegsImm bin
    render phlp bin Op.VLDMIA None OD.OprRnDreglist
  | 0b010111u | 0b011111u (* 01x111 *) when isxxxxxxx1 bin ->
    chkPCRnRegsImm bin
    render phlp bin Op.FLDMIAX None OD.OprRnDreglist
  | 0b100000u | 0b110000u (* 1x0000 *) -> raise UndefinedException
  | 0b100001u | 0b110001u | 0b100010u | 0b110010u ->
    chkSzCondPCRn bin phlp.Cond; render phlp bin Op.VSTR None OD.OprSdMem
  | 0b100011u | 0b110011u ->
    chkSzCondPCRn bin phlp.Cond; render phlp bin Op.VSTR None OD.OprDdMem
  | 0b100100u | 0b110100u when phlp.Cond <> Condition.UN -> raise UndefinedException
  | 0b100101u | 0b110101u | 0b100110u | 0b110110u when phlp.Cond <> Condition.UN ->
    chkSzCond bin phlp.Cond; render phlp bin Op.VLDR None OD.OprSdMem
  | 0b100111u | 0b110111u when phlp.Cond <> Condition.UN ->
    chkSzCond bin phlp.Cond; render phlp bin Op.VLDR None OD.OprDdMem
  | 0b101000u | 0b101001u | 0b101100u | 0b101101u ->
    raise ParsingFailureException
  | 0b101010u ->
    chkPCRnDRegs bin; render phlp bin Op.VSTMDB None OD.OprRnSreglist
  | 0b101011u when isxxxxxxx0 bin ->
    chkPCRnRegsImm bin
    render phlp bin Op.VSTMDB None OD.OprRnDreglist
  | 0b101011u when isxxxxxxx1 bin ->
    chkPCRnRegsImm bin
    render phlp bin Op.FSTMDBX None OD.OprRnDreglist
  | 0b101110u ->
    chkPCRnDRegs bin; render phlp bin Op.VLDMDB None OD.OprRnSreglist
  | 0b101111u when isxxxxxxx0 bin ->
    chkPCRnRegsImm bin
    render phlp bin Op.VLDMDB None OD.OprRnDreglist
  | 0b101111u when isxxxxxxx1 bin ->
    chkPCRnRegsImm bin
    render phlp bin Op.FLDMDBX None OD.OprRnDreglist
  | 0b100100u | 0b110100u when isRn1111 bin -> raise UndefinedException
  | 0b100101u | 0b110101u | 0b100110u | 0b110110u when isRn1111 bin ->
    chkSzCond bin phlp.Cond; render phlp bin Op.VLDR None OD.OprSdLabel
  | 0b100111u | 0b110111u when isRn1111 bin ->
    chkSzCond bin phlp.Cond; render phlp bin Op.VLDR None OD.OprDdLabel
  | 0b111000u | 0b111001u | 0b111010u | 0b111011u | 0b111100u | 0b111101u
  | 0b111110u | 0b111111u -> raise ParsingFailureException
  | _ -> raise ParsingFailureException

/// System register load/store on page F4-4255.
let parseSysRegisterLdSt (phlp: ParsingHelper) bin =
  let isNotRn1111 bin = extract bin 19 16 <> 0b1111u
  let isCRd0101 bin = (extract bin 15 12) = 0b0101u
  let puw = concat (extract bin 24 23) (pickBit bin 21) 1 (* P:U:W *)
  let dL = concat (pickBit bin 22) (pickBit bin 20) 1 (* D:L *)
  let cRdCp15 = concat (extract bin 15 12) (pickBit bin 8) 1 (* CRd:cp15 *)
  match concat dL (pickBit bin 8) 1 (* D:L:cp15 *) with
  | 0b000u | 0b001u | 0b010u | 0b011u (* 0b0xxu *)
    when puw <> 0b000u && not (isCRd0101 bin) -> raise ParsingFailureException
  | 0b010u when puw <> 0b000u && isNotRn1111 bin |> not && isCRd0101 bin ->
    chkWP bin; render phlp bin Op.LDC None OD.OprP14C5Label
  | 0b001u | 0b011u | 0b101u | 0b111u (* 0bxx1u *) when puw <> 0b000u ->
    raise ParsingFailureException
  | 0b100u | 0b110u (* 0b1x0u *) when puw <> 0b000u && isCRd0101 bin ->
    raise ParsingFailureException
  | _ ->
    match concat (concat puw dL 2) cRdCp15 5 (* P:U:W:D:L:CRd:cp15 *) with
    | 0b0010001010u | 0b0110001010u ->
      chkPCRnWback bin; render phlp bin Op.STC None OD.OprP14C5Mem
    | 0b0010101010u | 0b0110101010u when isNotRn1111 bin ->
      render phlp bin Op.LDC None OD.OprP14C5Mem
    | 0b0100001010u ->
      chkPCRnWback bin; render phlp bin Op.STC None OD.OprP14C5Option
    | 0b0100101010u when isNotRn1111 bin ->
      render phlp bin Op.LDC None OD.OprP14C5Option
    | 0b1000001010u | 0b1100001010u ->
      chkPCRnWback bin; render phlp bin Op.STC None OD.OprP14C5Mem
    | 0b1000101010u | 0b1100101010u when isNotRn1111 bin ->
      render phlp bin Op.LDC None OD.OprP14C5Mem
    | 0b1010001010u | 0b1110001010u ->
      chkPCRnWback bin; render phlp bin Op.STC None OD.OprP14C5Mem
    | 0b1010101010u | 0b1110101010u when isNotRn1111 bin ->
      render phlp bin Op.LDC None OD.OprP14C5Mem
    | _ -> raise ParsingFailureException

/// Advanced SIMD and System register load/store and 64-bit move
/// on page F4-4252.
let parseAdvSIMDAndSysRegLdStAnd64bitMove (phlp: ParsingHelper) bin =
  let is00x0 bin = (extract bin 24 21 (* op0 *)) &&& 0b1101u = 0b0000u
  match extract bin 10 9 (* op1 *) with
  | 0b00u | 0b01u when is00x0 bin ->
    parseAdvancedSIMDandFP64bitMove phlp bin
  | 0b11u when is00x0 bin -> parseSystemReg64bitMove phlp bin
  | 0b00u | 0b01u -> parseAdvSIMDAndFPLdSt phlp bin
  | 0b11u -> parseSysRegisterLdSt phlp bin
  | _ (* 10 *) -> raise ParsingFailureException

/// Floating-point data-processing (two registers) on page F4-4256.
let parseFPDataProcTwoRegs (phlp: ParsingHelper) bin =
  let decodeFields =
    concat (extract bin 19 16) (extract bin 9 7) 3 (* o1:opc2:size:o3 *)
  match decodeFields (* o1:opc2:size:o3 *) with
  | b when b &&& 0b0000110u = 0b0000000u (* xxxx00x *) ->
    raise ParsingFailureException
  | 0b0000010u -> raise ParsingFailureException
  (* 0000xx1 VABS *)
  | 0b0000001u -> raise UndefinedException
  | 0b0000011u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VABS (oneDt SIMDTypF16) OD.OprSdSm
  | 0b0000101u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VABS (oneDt SIMDTypF32) OD.OprSdSm
  | 0b0000111u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VABS (oneDt SIMDTypF64) OD.OprDdDm
  (* 00001x0 VMOV *)
  | 0b0000100u ->
    render phlp bin Op.VMOV (oneDt SIMDTypF32) OD.OprSdSm
  | 0b0000110u ->
    render phlp bin Op.VMOV (oneDt SIMDTypF64) OD.OprDdDm
  (* 0001xx0 VNEG *)
  | 0b0001000u -> raise UndefinedException
  | 0b0001010u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VNEG (oneDt SIMDTypF16) OD.OprSdSm
  | 0b0001100u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VNEG (oneDt SIMDTypF32) OD.OprSdSm
  | 0b0001110u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VNEG (oneDt SIMDTypF64) OD.OprDdDm
  (* 0001xx1 VSQRT *)
  | 0b0001001u -> raise UndefinedException
  | 0b0001011u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VSQRT (oneDt SIMDTypF16) OD.OprSdSm
  | 0b0001101u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VSQRT (oneDt SIMDTypF32) OD.OprSdSm
  | 0b0001111u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VSQRT (oneDt SIMDTypF64) OD.OprDdDm
  (* 0010xx0 VCVTB *)
  | 0b0010100u ->
    let dt = twoDt (SIMDTypF32, SIMDTypF16)
    render phlp bin Op.VCVTB dt OD.OprSdSm
  | 0b0010110u ->
    let dt = twoDt (SIMDTypF64, SIMDTypF16)
    render phlp bin Op.VCVTB dt OD.OprDdSm
  | 0b0010010u | 0b0010011u (* 001001x *) -> raise ParsingFailureException
  (* 0010xx1 VCVTT *)
  | 0b0010101u ->
    let dt = twoDt (SIMDTypF32, SIMDTypF16)
    render phlp bin Op.VCVTT dt OD.OprSdSm
  | 0b0010111u ->
    let dt = twoDt (SIMDTypF64, SIMDTypF16)
    render phlp bin Op.VCVTT dt OD.OprDdSm
  | 0b0011010u -> (* Armv8.6 *)
    render phlp bin Op.VCVTB (twoDt (BF16, SIMDTypF16)) OD.OprSdSm
  | 0b0011011u -> (* Armv8.6 *)
    render phlp bin Op.VCVTT (twoDt (BF16, SIMDTypF16)) OD.OprSdSm
  | 0b0011100u ->
    let dt = twoDt (SIMDTypF16, SIMDTypF32)
    render phlp bin Op.VCVTB dt OD.OprSdSm
  | 0b0011101u ->
    let dt = twoDt (SIMDTypF16, SIMDTypF32)
    render phlp bin Op.VCVTT dt OD.OprSdSm
  | 0b0011110u ->
    let dt = twoDt (SIMDTypF16, SIMDTypF64)
    render phlp bin Op.VCVTB dt OD.OprSdDm
  | 0b0011111u ->
    let dt = twoDt (SIMDTypF16, SIMDTypF64)
    render phlp bin Op.VCVTT dt OD.OprSdDm
  (* 0100xx0 VCMP *)
  | 0b0100000u -> raise UndefinedException
  | 0b0100010u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VCMP (oneDt SIMDTypF16) OD.OprSdSm
  | 0b0100100u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VCMP (oneDt SIMDTypF32) OD.OprSdSm
  | 0b0100110u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VCMP (oneDt SIMDTypF64) OD.OprDdDm
  (* 0100xx1 VCMPE *)
  | 0b0100001u -> raise UndefinedException
  | 0b0100011u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VCMPE (oneDt SIMDTypF16) OD.OprSdSm
  | 0b0100101u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VCMPE (oneDt SIMDTypF32) OD.OprSdSm
  | 0b0100111u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VCMPE (oneDt SIMDTypF64) OD.OprDdDm
  (* 0101xx0 VCMP *)
  | 0b0101000u -> raise UndefinedException
  | 0b0101010u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VCMP (oneDt SIMDTypF16) OD.OprSdImm0
  | 0b0101100u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VCMP (oneDt SIMDTypF32) OD.OprSdImm0
  | 0b0101110u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VCMP (oneDt SIMDTypF64) OD.OprDdImm0
  (* 0101xx1 VCMPE *)
  | 0b0101001u -> raise UndefinedException
  | 0b0101011u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VCMPE (oneDt SIMDTypF16) OD.OprSdImm0
  | 0b0101101u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VCMPE (oneDt SIMDTypF32) OD.OprSdImm0
  | 0b0101111u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VCMPE (oneDt SIMDTypF64) OD.OprDdImm0
  (* 0110xx0 VRINTR ARMv8 *)
  | 0b0110000u -> raise UndefinedException
  | 0b0110010u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VRINTR (oneDt SIMDTypF16) OD.OprSdSm
  | 0b0110100u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VRINTR (oneDt SIMDTypF32) OD.OprSdSm
  | 0b0110110u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VRINTR (oneDt SIMDTypF64) OD.OprDdDm
  (* 0110xx1 VRINTZ ARMv8 *)
  | 0b0110001u -> raise UndefinedException
  | 0b0110011u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VRINTZ (oneDt SIMDTypF16) OD.OprSdSm
  | 0b0110101u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VRINTZ (oneDt SIMDTypF32) OD.OprSdSm
  | 0b0110111u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VRINTZ (oneDt SIMDTypF64) OD.OprDdDm
  (* 0111xx0 VRINTX ARMv8 *)
  | 0b0111000u -> raise UndefinedException
  | 0b0111010u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VRINTX (oneDt SIMDTypF16) OD.OprSdSm
  | 0b0111100u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VRINTX (oneDt SIMDTypF32) OD.OprSdSm
  | 0b0111110u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VRINTX (oneDt SIMDTypF64) OD.OprDdDm
  | 0b0111011u -> raise ParsingFailureException
  | 0b0111101u ->
    let dt = twoDt (SIMDTypF64, SIMDTypF32)
    render phlp bin Op.VCVT dt OD.OprDdSm
  | 0b0111111u ->
    let dt = twoDt (SIMDTypF32, SIMDTypF64)
    render phlp bin Op.VCVT dt OD.OprSdDm
  (* 1000xxx VCVT *)
  | 0b1000000u | 0b1000001u -> raise UndefinedException
  | 0b1000010u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypF16, SIMDTypU32)
    render phlp bin Op.VCVT dt OD.OprSdSm
  | 0b1000011u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypF16, SIMDTypS32)
    render phlp bin Op.VCVT dt OD.OprSdSm
  | 0b1000100u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypF32, SIMDTypU32)
    render phlp bin Op.VCVT dt OD.OprSdSm
  | 0b1000101u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypF32, SIMDTypS32)
    render phlp bin Op.VCVT dt OD.OprSdSm
  | 0b1000110u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypF64, SIMDTypU32)
    render phlp bin Op.VCVT dt OD.OprDdSm
  | 0b1000111u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypF64, SIMDTypS32)
    render phlp bin Op.VCVT dt OD.OprDdSm
  | 0b1001010u | 0b1001011u (* 100101x *) -> raise ParsingFailureException
  | 0b1001100u | 0b1001101u (* 100110x *) -> raise ParsingFailureException
  | 0b1001110u -> raise ParsingFailureException
  | 0b1001111u -> (* Armv8.3 *)
    phlp.Cond <> Condition.AL |> checkUnpred
    let dt = twoDt (SIMDTypS32, SIMDTypF64)
    render phlp bin Op.VJCVT dt OD.OprSdDm
  (* 101xxxx Op.VCVT *)
  | 0b1010000u | 0b1010001u | 0b1011000u | 0b1011001u ->
    raise UndefinedException
  | 0b1010010u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypF16, SIMDTypS16)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1010011u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypF16, SIMDTypS32)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1011010u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypF16, SIMDTypU16)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1011011u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypF16, SIMDTypU32)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1010100u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypF32, SIMDTypS16)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1010101u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypF32, SIMDTypS32)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1011100u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypF32, SIMDTypU16)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1011101u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypF32, SIMDTypU32)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1010110u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypF64, SIMDTypS16)
    render phlp bin Op.VCVT dt OD.OprDdmDdmFbits
  | 0b1010111u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypF64, SIMDTypS32)
    render phlp bin Op.VCVT dt OD.OprDdmDdmFbits
  | 0b1011110u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypF64, SIMDTypU16)
    render phlp bin Op.VCVT dt OD.OprDdmDdmFbits
  | 0b1011111u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypF64, SIMDTypU32)
    render phlp bin Op.VCVT dt OD.OprDdmDdmFbits
  (* 1100xx0 VCVTR *)
  | 0b1100000u -> raise UndefinedException
  | 0b1100010u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypU32, SIMDTypF16)
    render phlp bin Op.VCVTR dt OD.OprSdSm
  | 0b1100100u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVTR dt OD.OprSdSm
  | 0b1100110u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypU32, SIMDTypF64)
    render phlp bin Op.VCVTR dt OD.OprSdDm
  (* 1100xx1 VCVT *)
  | 0b1100001u -> raise UndefinedException
  | 0b1100011u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypU32, SIMDTypF16)
    render phlp bin Op.VCVT dt OD.OprSdSm
  | 0b1100101u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVT dt OD.OprSdSm
  | 0b1100111u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypU32, SIMDTypF64)
    render phlp bin Op.VCVT dt OD.OprSdDm
  (* 1101xx0 VCVTR *)
  | 0b1101000u -> raise UndefinedException
  | 0b1101010u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypS32, SIMDTypF16)
    render phlp bin Op.VCVTR dt OD.OprSdSm
  | 0b1101100u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVTR dt OD.OprSdSm
  | 0b1101110u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypS32, SIMDTypF64)
    render phlp bin Op.VCVTR dt OD.OprSdDm
  (* 1101xx1u VCVT *)
  | 0b1101001u -> raise UndefinedException
  | 0b1101011u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypS32, SIMDTypF16)
    render phlp bin Op.VCVT dt OD.OprSdSm
  | 0b1101101u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVT dt OD.OprSdSm
  | 0b1101111u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypS32, SIMDTypF64)
    render phlp bin Op.VCVT dt OD.OprSdDm
  (* 111xxxx VCVT *)
  | 0b1110000u | 0b1110001u | 0b1111000u | 0b1111001u ->
    raise UndefinedException
  | 0b1110010u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1110011u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypS32, SIMDTypF16)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1111010u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1111011u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypU32, SIMDTypF16)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1110100u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypS16, SIMDTypF32)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1110101u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1111100u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypU16, SIMDTypF32)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1111101u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1110110u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypS16, SIMDTypF64)
    render phlp bin Op.VCVT dt OD.OprDdmDdmFbits
  | 0b1110111u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypS32, SIMDTypF64)
    render phlp bin Op.VCVT dt OD.OprDdmDdmFbits
  | 0b1111110u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypU16, SIMDTypF64)
    render phlp bin Op.VCVT dt OD.OprDdmDdmFbits
  | 0b1111111u ->
    chkSzCond bin phlp.Cond
    let dt = twoDt (SIMDTypU32, SIMDTypF64)
    render phlp bin Op.VCVT dt OD.OprDdmDdmFbits
  | _ -> raise ParsingFailureException

/// Floating-point move immediate on page F4-4258.
let parseFPMoveImm (phlp: ParsingHelper) bin =
  match extract bin 9 8 (* size *) with
  | 0b00u -> raise ParsingFailureException
  | 0b01u -> (* Armv8.2 *)
    chkSzCond bin phlp.Cond
    render phlp bin Op.VMOV (oneDt SIMDTypF16) OD.OprSdVImm
  | 0b10u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VMOV (oneDt SIMDTypF32) OD.OprSdVImm
  | _ (* 11 *) ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VMOV (oneDt SIMDTypF64) OD.OprDdVImm

/// Floating-point data-processing (three registers) on page F4-4258.
let parseFPDataProcThreeRegs (phlp: ParsingHelper) bin =
  let decodeFields = (* o0:o1:size:o2 *)
    (pickBit bin 23 <<< 5) + (extract bin 21 20 <<< 3) + (extract bin 9 8 <<< 1)
    + (pickBit bin 6)
  match decodeFields with
  | b when (b >>> 3 <> 0b111u) && (b &&& 0b000110u = 0b000u) (* != 111 00x *) ->
    raise ParsingFailureException
  (* 000xx0 VMLA *)
  | 0b000000u -> raise UndefinedException
  | 0b000010u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VMLA (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b000100u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VMLA (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b000110u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VMLA (oneDt SIMDTypF64) OD.OprDdDnDm
  (* 000xx1 VMLS *)
  | 0b000001u -> raise UndefinedException
  | 0b000011u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VMLS (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b000101u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VMLS (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b000111u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VMLS (oneDt SIMDTypF64) OD.OprDdDnDm
  (* 001xx0 VNMLS *)
  | 0b001000u -> raise UndefinedException
  | 0b001010u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VNMLS (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b001100u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VNMLS (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b001110u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VNMLS (oneDt SIMDTypF64) OD.OprDdDnDm
  (* 001xx1 VNMLA *)
  | 0b001001u -> raise UndefinedException
  | 0b001011u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VNMLA (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b001101u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VNMLA (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b001111u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VNMLA (oneDt SIMDTypF64) OD.OprDdDnDm
  (* 010xx0 VMUL *)
  | 0b010000u ->raise UndefinedException
  | 0b010010u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VMUL (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b010100u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VMUL (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b010110u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VMUL (oneDt SIMDTypF64) OD.OprDdDnDm
  (* 010xx1 VNMUL *)
  | 0b010001u -> raise UndefinedException
  | 0b010011u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VNMUL (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b010101u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VNMUL (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b010111u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VNMUL (oneDt SIMDTypF64) OD.OprDdDnDm
  (* 011xx0 VADD *)
  | 0b011000u ->raise UndefinedException
  | 0b011010u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VADD (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b011100u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VADD (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b011110u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VADD (oneDt SIMDTypF64) OD.OprDdDnDm
  (* 011xx1 VSUB *)
  | 0b011001u ->raise UndefinedException
  | 0b011011u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VSUB (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b011101u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VSUB (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b011111u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VSUB (oneDt SIMDTypF64) OD.OprDdDnDm
  (* 100xx0 VDIV *)
  | 0b100000u ->raise UndefinedException
  | 0b100010u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VDIV (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b100100u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VDIV (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b100110u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VDIV (oneDt SIMDTypF64) OD.OprDdDnDm
  (* 101xx0 VFNMS *)
  | 0b101000u -> raise UndefinedException
  | 0b101010u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VFNMS (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b101100u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VFNMS (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b101110u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VFNMS (oneDt SIMDTypF64) OD.OprDdDnDm
  (* 101xx1 VFNMA *)
  | 0b101001u -> raise UndefinedException
  | 0b101011u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VFNMA (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b101101u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VFNMA (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b101111u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VFNMA (oneDt SIMDTypF64) OD.OprDdDnDm
  (* 110xx0 VFMA *)
  | 0b110000u ->raise UndefinedException
  | 0b110010u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VFMA (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b110100u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VFMA (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b110110u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VFMA (oneDt SIMDTypF64) OD.OprDdDnDm
  (* 110xx1 VFMS *)
  | 0b110001u ->raise UndefinedException
  | 0b110011u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VFMS (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b110101u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VFMS (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b110111u ->
    chkSzCond bin phlp.Cond
    render phlp bin Op.VFMS (oneDt SIMDTypF64) OD.OprDdDnDm
  | _ -> raise ParsingFailureException

/// Floating-point data-processing on page F4-4256.
let parseFloatingPointDataProcessing (phlp: ParsingHelper) bin =
  match concat (extract bin 23 20) (pickBit bin 6) 1 (* op0:op1 *) with
  | 0b10111u | 0b11111u -> parseFPDataProcTwoRegs phlp bin
  | 0b10110u | 0b11110u -> parseFPMoveImm phlp bin
  | _ (* != 1x11 && 0bxu *) -> parseFPDataProcThreeRegs phlp bin

/// Floating-point move special register on page F4-4259.
let parseFPMoveSpecialReg (phlp: ParsingHelper) bin =
  match pickBit bin 20 (* L *) with
  | 0b0u -> chkPCRt bin; render phlp bin Op.VMSR None OD.OprSregRt
  | _ (* 0b1u *) ->
     chkPCRt bin; render phlp bin Op.VMRS None OD.OprRtSreg

/// Advanced SIMD 8/16/32-bit element move/duplicate on page F4-4260.
let parseAdvSIMD8n16n32bitElemMoveDup (phlp: ParsingHelper) bin =
  chkPCRt bin
  let decodeField = concat (extract bin 23 20) (extract bin 6 5) 2
  match decodeField (* opc1:L:opc2 *) with
  (* 0xx0xx VMOV (general-purpose register to scalar) *)
  | 0b010000u -> render phlp bin Op.VMOV (oneDt SIMDTyp8) OD.OprDd0Rt
  | 0b010001u -> render phlp bin Op.VMOV (oneDt SIMDTyp8) OD.OprDd1Rt
  | 0b010010u -> render phlp bin Op.VMOV (oneDt SIMDTyp8) OD.OprDd2Rt
  | 0b010011u -> render phlp bin Op.VMOV (oneDt SIMDTyp8) OD.OprDd3Rt
  | 0b011000u -> render phlp bin Op.VMOV (oneDt SIMDTyp8) OD.OprDd4Rt
  | 0b011001u -> render phlp bin Op.VMOV (oneDt SIMDTyp8) OD.OprDd5Rt
  | 0b011010u -> render phlp bin Op.VMOV (oneDt SIMDTyp8) OD.OprDd6Rt
  | 0b011011u -> render phlp bin Op.VMOV (oneDt SIMDTyp8) OD.OprDd7Rt
  | 0b000001u ->
    render phlp bin Op.VMOV (oneDt SIMDTyp16) OD.OprDd0Rt
  | 0b000011u ->
    render phlp bin Op.VMOV (oneDt SIMDTyp16) OD.OprDd1Rt
  | 0b001001u ->
    render phlp bin Op.VMOV (oneDt SIMDTyp16) OD.OprDd2Rt
  | 0b001011u ->
    render phlp bin Op.VMOV (oneDt SIMDTyp16) OD.OprDd3Rt
  | 0b000000u ->
    render phlp bin Op.VMOV (oneDt SIMDTyp32) OD.OprDd0Rt
  | 0b001000u ->
    render phlp bin Op.VMOV (oneDt SIMDTyp32) OD.OprDd1Rt
  | 0b000010u | 0b001010u -> raise UndefinedException
  (* xxx1xx VMOV (scalar to general-purpose register) *)
  | 0b010100u ->
    render phlp bin Op.VMOV (oneDt SIMDTypS8) OD.OprRtDn0
  | 0b010101u ->
    render phlp bin Op.VMOV (oneDt SIMDTypS8) OD.OprRtDn1
  | 0b010110u ->
    render phlp bin Op.VMOV (oneDt SIMDTypS8) OD.OprRtDn2
  | 0b010111u ->
    render phlp bin Op.VMOV (oneDt SIMDTypS8) OD.OprRtDn3
  | 0b011100u ->
    render phlp bin Op.VMOV (oneDt SIMDTypS8) OD.OprRtDn4
  | 0b011101u ->
    render phlp bin Op.VMOV (oneDt SIMDTypS8) OD.OprRtDn5
  | 0b011110u ->
    render phlp bin Op.VMOV (oneDt SIMDTypS8) OD.OprRtDn6
  | 0b011111u ->
    render phlp bin Op.VMOV (oneDt SIMDTypS8) OD.OprRtDn7
  | 0b110100u ->
    render phlp bin Op.VMOV (oneDt SIMDTypU8) OD.OprRtDn0
  | 0b110101u ->
    render phlp bin Op.VMOV (oneDt SIMDTypU8) OD.OprRtDn1
  | 0b110110u ->
    render phlp bin Op.VMOV (oneDt SIMDTypU8) OD.OprRtDn2
  | 0b110111u ->
    render phlp bin Op.VMOV (oneDt SIMDTypU8) OD.OprRtDn3
  | 0b111100u ->
    render phlp bin Op.VMOV (oneDt SIMDTypU8) OD.OprRtDn4
  | 0b111101u ->
    render phlp bin Op.VMOV (oneDt SIMDTypU8) OD.OprRtDn5
  | 0b111110u ->
    render phlp bin Op.VMOV (oneDt SIMDTypU8) OD.OprRtDn6
  | 0b111111u ->
    render phlp bin Op.VMOV (oneDt SIMDTypU8) OD.OprRtDn7
  | 0b000101u ->
    render phlp bin Op.VMOV (oneDt SIMDTypS16) OD.OprRtDn0
  | 0b000111u ->
    render phlp bin Op.VMOV (oneDt SIMDTypS16) OD.OprRtDn1
  | 0b001101u ->
    render phlp bin Op.VMOV (oneDt SIMDTypS16) OD.OprRtDn2
  | 0b001111u ->
    render phlp bin Op.VMOV (oneDt SIMDTypS16) OD.OprRtDn3
  | 0b100101u ->
    render phlp bin Op.VMOV (oneDt SIMDTypU16) OD.OprRtDn0
  | 0b100111u ->
    render phlp bin Op.VMOV (oneDt SIMDTypU16) OD.OprRtDn1
  | 0b101101u ->
    render phlp bin Op.VMOV (oneDt SIMDTypU16) OD.OprRtDn2
  | 0b101111u ->
    render phlp bin Op.VMOV (oneDt SIMDTypU16) OD.OprRtDn3
  | 0b000100u ->
    render phlp bin Op.VMOV (oneDt SIMDTyp32) OD.OprRtDn0
  | 0b001100u ->
    render phlp bin Op.VMOV (oneDt SIMDTyp32) OD.OprRtDn1
  | 0b100100u | 0b101100u | 0b000110u | 0b001110u | 0b100110u | 0b101110u ->
    raise UndefinedException (* 10x100 or x0x110 *)
  (* 1xx00x VDUP (general-purpose register) *)
  | 0b110000u -> render phlp bin Op.VDUP (oneDt SIMDTyp8) OD.OprDdRt
  | 0b100001u -> render phlp bin Op.VDUP (oneDt SIMDTyp16) OD.OprDdRt
  | 0b100000u -> render phlp bin Op.VDUP (oneDt SIMDTyp32) OD.OprDdRt
  | 0b111000u -> render phlp bin Op.VDUP (oneDt SIMDTyp8) OD.OprQdRt
  | 0b101001u -> render phlp bin Op.VDUP (oneDt SIMDTyp16) OD.OprQdRt
  | 0b101000u -> render phlp bin Op.VDUP (oneDt SIMDTyp32) OD.OprQdRt
  | 0b111001u | 0b110001u -> raise UndefinedException
  | b when b &&& 0b100110u = 0b100010u (* 1xx01x *) ->
    raise ParsingFailureException
  | _ -> raise ParsingFailureException

/// System register 32-bit move on page F4-4260.
let parseSystemReg32bitMove (phlp: ParsingHelper) bin =
  match pickBit bin 20 (* L *) with
  | 0b0u ->
    chkPCRt bin; render phlp bin Op.MCR None OD.OprCpOpc1RtCRnCRmOpc2
  | _ (* 0b1u *) ->
    render phlp bin Op.MRC None OD.OprCpOpc1RtCRnCRmOpc2

/// Advanced SIMD and System register 32-bit move on page F4-4259.
let parseAdvSIMDAndSysReg32bitMove (phlp: ParsingHelper) bin =
  match concat (extract bin 23 21) (extract bin 10 8) 3 (* op0:op1 *) with
  | 0b000000u -> raise ParsingFailureException
  | 0b000001u -> (* Armv8.2 *)
    chkCondPCRt bin phlp.Cond
    let oprFn = if pickBit bin 20 = 0u (* op *) then OD.OprSnRt else OD.OprRtSn
    render phlp bin Op.VMOV (oneDt SIMDTypF16) oprFn
  | 0b000010u ->
    chkPCRt bin
    let oprFn = if pickBit bin 20 = 0u (* op *) then OD.OprSnRt else OD.OprRtSn
    render phlp bin Op.VMOV None oprFn
  | 0b001010u -> raise ParsingFailureException
  | 0b010010u | 0b011010u -> raise ParsingFailureException
  | 0b100010u | 0b101010u -> raise ParsingFailureException
  | 0b110010u -> raise ParsingFailureException
  | 0b111010u -> parseFPMoveSpecialReg phlp bin
  | _ ->
    match extract bin 10 8 (* op1 *) with
    | 0b011u -> parseAdvSIMD8n16n32bitElemMoveDup phlp bin
    | 0b100u | 0b101u -> raise ParsingFailureException
    | 0b110u | 0b111u -> parseSystemReg32bitMove phlp bin
    | _ -> raise ParsingFailureException

/// System register access, Advanced SIMD, floating-point, and Supervisor call
/// on page F4-4246.
let parseCase11 (phlp: ParsingHelper) bin =
  let op0op1op2 =
    (extract bin 25 24 <<< 2) + (pickBit bin 11 <<< 1) +
    (pickBit bin 4)
  match op0op1op2 (* op0:op1:op2 *) with
  | _ when phlp.IsARMv7 && phlp.Cond = Condition.UN && (pickBit bin 25 = 0u)
           && (pickBit bin 20 = 0u) -> (* ARMv7 A8-663 *)
    chkPUDWCopPCRn bin
    render phlp bin Op.STC2 None OD.OprCoprocCRdMem
  | 0b0000u | 0b0001u | 0b0100u | 0b0101u (* 0x0x *) ->
    raise ParsingFailureException
  | 0b1000u | 0b1001u (* 100x *) when phlp.IsARMv7 -> (* ARMv7 A8-356 *)
    render phlp bin Op.CDP None OD.OprCpOpc1CRdCRnCRmOpc2
  | 0b1000u | 0b1001u (* 100x *) -> raise ParsingFailureException
  | 0b1100u | 0b1101u | 0b1110u | 0b1111u (* 11xx *) ->
    parseSupervisorCall phlp bin
  | 0b0010u | 0b0011u | 0b0110u | 0b0111u | 0b1010u | 0b1011u (* != 11 1 x *)
    when phlp.Cond = Condition.UN ->
    parseUncondAdvSIMDAndFPInstr phlp bin
  | 0b0010u | 0b0011u | 0b0110u | 0b0111u ->
    parseAdvSIMDAndSysRegLdStAnd64bitMove phlp bin
  | 0b1010u -> parseFloatingPointDataProcessing phlp bin
  | _ (* 0b1011u *) -> parseAdvSIMDAndSysReg32bitMove phlp bin

let parseCPS (phlp: ParsingHelper) bin =
  (* if mode != '00000' && M == '0' then UNPREDICTABLE
     if (imod<1> == '1' && A:I:F == '000') || (imod<1> == '0' && A:I:F != '000')
     then UNPREDICTABLE *)
  let imod1 = pickBit bin 19 (* imod<1> *)
  let aif = extract bin 8 6 (* A:I:F *)
  (((extract bin 4 0 (* mode *) <> 0u) && (pickBit bin 8 = 0u (* M *))) ||
   (((imod1 = 1u) && (aif = 0u)) || ((imod1 = 0u) && (aif <> 0u))))
   |> checkUnpred
  let struct (op, oprs) =
    match extract bin 19 17 (* imod:M *) with
    | 0b001u -> struct (Op.CPS, OD.OprMode)
    | 0b110u -> struct (Op.CPSID, OD.OprIflags)
    | 0b111u -> struct (Op.CPSID, OD.OprIflagsMode)
    | 0b100u -> struct (Op.CPSIE, OD.OprIflags)
    | 0b101u -> struct (Op.CPSIE, OD.OprIflagsMode)
    | _ (* 000 or 01x *) -> raise UnpredictableException
  render phlp bin op None oprs

/// Change Process State on page F4-4262.
let parseChangeProcessState (phlp: ParsingHelper) bin =
  match concat (pickBit bin 16) (pickBit bin 4) 1 (* op:mode<4> *) with
  | 0b10u -> render phlp bin Op.SETEND None OD.OprEndian
  | 0b00u | 0b01u -> parseCPS phlp bin
  | _ (* 11 *) -> raise ParsingFailureException

/// Miscellaneous on page F4-4261.
let parseUncondMiscellaneous (phlp: ParsingHelper) bin =
  match concat (extract bin 24 20) (extract bin 7 4) 4 (* op0:op1 *) with
  | 0b100000000u | 0b100000001u | 0b100000100u | 0b100000101u | 0b100001000u
  | 0b100001001u | 0b100001100u | 0b100001101u (* 10000xx0x *) ->
    parseChangeProcessState phlp bin
  | 0b100010000u -> (* Armv8.1 *)
    render phlp bin Op.SETPAN None OD.OprImm1
  | 0b100100111u -> raise UnpredictableException
  | _ -> raise ParsingFailureException

/// Advanced SIMD three registers of the same length on page F4-4263.
let parseAdvSIMDThreeRegsSameLen (phlp: ParsingHelper) bin =
  let decodeFields =
    (pickBit bin 24 <<< 8) + (extract bin 21 20 <<< 6) +
    (extract bin 11 8 <<< 2) + (pickBit bin 6 <<< 1) + (pickBit bin 4)
  match decodeFields (* U:size:opc:Q:o1 *) with
  | 0b000110001u ->
    chkQVdVnVm bin
    render phlp bin Op.VFMA (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b000110011u ->
    chkQVdVnVm bin
    render phlp bin Op.VFMA (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b001110001u ->
    chkQVdVnVm bin
    render phlp bin Op.VFMA (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b001110011u ->
    chkQVdVnVm bin
    render phlp bin Op.VFMA (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b000110100u ->
    chkQVdVnVm bin
    render phlp bin Op.VADD (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b000110110u ->
    chkQVdVnVm bin
    render phlp bin Op.VADD (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b001110100u ->
    chkQVdVnVm bin
    render phlp bin Op.VADD (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b001110110u ->
    chkQVdVnVm bin
    render phlp bin Op.VADD (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b000110101u ->
    chkQVdVnVm bin
    render phlp bin Op.VMLA (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b000110111u ->
    chkQVdVnVm bin
    render phlp bin Op.VMLA (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b001110101u ->
    chkQVdVnVm bin
    render phlp bin Op.VMLA (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b001110111u ->
    chkQVdVnVm bin
    render phlp bin Op.VMLA (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b000111000u ->
    chkQVdVnVm bin
    render phlp bin Op.VCEQ (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b000111010u ->
    chkQVdVnVm bin
    render phlp bin Op.VCEQ (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b001111000u ->
    chkQVdVnVm bin
    render phlp bin Op.VCEQ (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b001111010u ->
    chkQVdVnVm bin
    render phlp bin Op.VCEQ (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b000111100u ->
    chkQVdVnVm bin
    render phlp bin Op.VMAX (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b000111110u ->
    chkQVdVnVm bin
    render phlp bin Op.VMAX (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b001111100u ->
    chkQVdVnVm bin
    render phlp bin Op.VMAX (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b001111110u ->
    chkQVdVnVm bin
    render phlp bin Op.VMAX (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b000111101u ->
    chkQVdVnVm bin
    render phlp bin Op.VRECPS (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b000111111u ->
    chkQVdVnVm bin
    render phlp bin Op.VRECPS (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b001111101u ->
    chkQVdVnVm bin
    render phlp bin Op.VRECPS (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b001111111u ->
    chkQVdVnVm bin
    render phlp bin Op.VRECPS (oneDt SIMDTypF16) OD.OprQdQnQm
  | b when b &&& 0b000111111u = 0b000000000u (* xxx000000 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VHADD (getDTUSize bin) OD.OprDdDnDm
  | b when b &&& 0b000111111u = 0b000000010u (* xxx000010 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VHADD (getDTUSize bin) OD.OprQdQnQm
  | 0b000000101u ->
    chkQVdVnVm bin; render phlp bin Op.VAND None OD.OprDdDnDm
  | 0b000000111u ->
    chkQVdVnVm bin; render phlp bin Op.VAND None OD.OprQdQnQm
  | b when b &&& 0b000111111u = 0b000000001u (* xxx000001 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VQADD (getDTUSzQ bin) OD.OprDdDnDm
  | b when b &&& 0b000111111u = 0b000000011u (* xxx000011 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VQADD (getDTUSzQ bin) OD.OprQdQnQm
  | b when b &&& 0b000111111u = 0b000000100u (* xxx000100 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VRHADD (getDTUSize bin) OD.OprDdDnDm
  | b when b &&& 0b000111111u = 0b000000110u (* xxx000110 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VRHADD (getDTUSize bin) OD.OprQdQnQm
  | 0b000110000u -> raise UndefinedException (* if Q != '1' then UNDEFINED *)
  | 0b000110010u -> (* ARMv8 *)
    chkVdVnVm bin
    render phlp bin Op.SHA1C (oneDt SIMDTyp32) OD.OprQdQnQm
  | b when b &&& 0b000111111u = 0b000001000u (* xxx001000 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VHSUB (getDTUSize bin) OD.OprDdDnDm
  | b when b &&& 0b000111111u = 0b000001010u (* xxx001010 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VHSUB (getDTUSize bin) OD.OprQdQnQm
  | 0b001000101u ->
    chkQVdVnVm bin; render phlp bin Op.VBIC None OD.OprDdDnDm
  | 0b001000111u ->
    chkQVdVnVm bin; render phlp bin Op.VBIC None OD.OprQdQnQm
  | b when b &&& 0b000111111u = 0b000001001u (* xxx001001 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VQSUB (getDTUSzQ bin) OD.OprDdDnDm
  | b when b &&& 0b000111111u = 0b000001011u (* xxx001011 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VQSUB (getDTUSzQ bin) OD.OprDdDnDm
  | b when b &&& 0b000111111u = 0b000001100u (* xxx001100 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VCGT (getDTUSize bin) OD.OprDdDnDm
  | b when b &&& 0b000111111u = 0b000001110u (* xxx001110 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VCGT (getDTUSize bin) OD.OprQdQnQm
  | b when b &&& 0b000111111u = 0b000001101u (* xxx0011x1 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VCGE (getDTUSize bin) OD.OprDdDnDm
  | b when b &&& 0b000111111u = 0b000001111u (* xxx0011x1 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VCGE (getDTUSize bin) OD.OprQdQnQm
  | 0b001110000u -> raise UndefinedException (* if Q != '1' then UNDEFINED *)
  | 0b001110010u -> (* ARMv8 *)
    chkVdVnVm bin
    render phlp bin Op.SHA1P (oneDt SIMDTyp32) OD.OprQdQnQm
  | 0b010110001u ->
    chkQVdVnVm bin
    render phlp bin Op.VFMS (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b010110011u ->
    chkQVdVnVm bin
    render phlp bin Op.VFMS (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b011110001u ->
    chkQVdVnVm bin
    render phlp bin Op.VFMS (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b011110011u ->
    chkQVdVnVm bin
    render phlp bin Op.VFMS (oneDt SIMDTypF16) OD.OprQdQnQm
  (* 01x1101x0 VSUB (floating-point) *)
  | 0b010110100u ->
    chkQVdVnVm bin
    render phlp bin Op.VSUB (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b010110110u ->
    chkQVdVnVm bin
    render phlp bin Op.VSUB (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b011110100u ->
    chkQVdVnVm bin
    render phlp bin Op.VSUB (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b011110110u ->
    chkQVdVnVm bin
    render phlp bin Op.VSUB (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b010110101u ->
    chkQVdVnVm bin
    render phlp bin Op.VMLS (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b010110111u ->
    chkQVdVnVm bin
    render phlp bin Op.VMLS (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b011110101u ->
    chkQVdVnVm bin
    render phlp bin Op.VMLS (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b011110111u ->
    chkQVdVnVm bin
    render phlp bin Op.VMLS (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b010111000u | 0b010111010u | 0b011111000u | 0b011111010u (* 01x1110x0 *) ->
    raise ParsingFailureException
  | 0b010111100u ->
    chkQVdVnVm bin
    render phlp bin Op.VMIN (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b010111110u ->
    chkQVdVnVm bin
    render phlp bin Op.VMIN (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b011111100u ->
    chkQVdVnVm bin
    render phlp bin Op.VMIN (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b011111110u ->
    chkQVdVnVm bin
    render phlp bin Op.VMIN (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b010111101u ->
    chkQVdVnVm bin
    render phlp bin Op.VRSQRTS (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b010111111u ->
    chkQVdVnVm bin
    render phlp bin Op.VRSQRTS (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b011111101u ->
    chkQVdVnVm bin
    render phlp bin Op.VRSQRTS (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b011111111u ->
    chkQVdVnVm bin
    render phlp bin Op.VRSQRTS (oneDt SIMDTypF16) OD.OprQdQnQm
  | b when b &&& 0b000111111u = 0b000010000u (* xxx010000 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VSHL (getDTUSzQ bin) OD.OprDdDmDn
  | b when b &&& 0b000111111u = 0b000010010u (* xxx010010 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VSHL (getDTUSzQ bin) OD.OprQdQmQn
  | 0b000100000u ->
    chkQVdVnVm bin
    render phlp bin Op.VADD (oneDt SIMDTypI8) OD.OprDdDnDm
  | 0b001100000u ->
    chkQVdVnVm bin
    render phlp bin Op.VADD (oneDt SIMDTypI16) OD.OprDdDnDm
  | 0b010100000u ->
    chkQVdVnVm bin
    render phlp bin Op.VADD (oneDt SIMDTypI32) OD.OprDdDnDm
  | 0b011100000u ->
    chkQVdVnVm bin
    render phlp bin Op.VADD (oneDt SIMDTypI64) OD.OprDdDnDm
  | 0b000100010u ->
    chkQVdVnVm bin
    render phlp bin Op.VADD (oneDt SIMDTypI8) OD.OprQdQnQm
  | 0b001100010u ->
    chkQVdVnVm bin
    render phlp bin Op.VADD (oneDt SIMDTypI16) OD.OprQdQnQm
  | 0b010100010u ->
    chkQVdVnVm bin
    render phlp bin Op.VADD (oneDt SIMDTypI32) OD.OprQdQnQm
  | 0b011100010u ->
    chkQVdVnVm bin
    render phlp bin Op.VADD (oneDt SIMDTypI64) OD.OprQdQnQm
  | 0b010000101u ->
    chkQVdVnVm bin; render phlp bin Op.VORR None OD.OprDdDnDm
  | 0b010000111u ->
    chkQVdVnVm bin; render phlp bin Op.VORR None OD.OprQdQnQm
  | 0b000100001u ->
    chkQVdVnVm bin
    render phlp bin Op.VTST (oneDt SIMDTyp8) OD.OprDdDnDm
  | 0b001100001u ->
    chkQVdVnVm bin
    render phlp bin Op.VTST (oneDt SIMDTyp16) OD.OprDdDnDm
  | 0b010100001u ->
    chkQVdVnVm bin
    render phlp bin Op.VTST (oneDt SIMDTyp32) OD.OprDdDnDm
  | 0b000100011u ->
    chkQVdVnVm bin
    render phlp bin Op.VTST (oneDt SIMDTyp8) OD.OprQdQnQm
  | 0b001100011u ->
    chkQVdVnVm bin
    render phlp bin Op.VTST (oneDt SIMDTyp16) OD.OprQdQnQm
  | 0b010100011u ->
    chkQVdVnVm bin
    render phlp bin Op.VTST (oneDt SIMDTyp32) OD.OprQdQnQm
  | 0b011100001u | 0b011100011u (* 0111000x1 *) -> raise UndefinedException
  | b when b &&& 0b000111111u = 0b000010001u (* xxx010001 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VQSHL (getDTUSzQ bin) OD.OprDdDmDn
  | b when b &&& 0b000111111u = 0b000010011u (* xxx010011 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VQSHL (getDTUSzQ bin) OD.OprQdQmQn
  | 0b000100100u ->
    chkQVdVnVm bin
    render phlp bin Op.VMLA (oneDt SIMDTypI8) OD.OprDdDnDm
  | 0b001100100u ->
    chkQVdVnVm bin
    render phlp bin Op.VMLA (oneDt SIMDTypI16) OD.OprDdDnDm
  | 0b010100100u ->
    chkQVdVnVm bin
    render phlp bin Op.VMLA (oneDt SIMDTypI32) OD.OprDdDnDm
  | 0b000100110u ->
    chkQVdVnVm bin
    render phlp bin Op.VMLA (oneDt SIMDTypI8) OD.OprQdQnQm
  | 0b001100110u ->
    chkQVdVnVm bin
    render phlp bin Op.VMLA (oneDt SIMDTypI16) OD.OprQdQnQm
  | 0b010100110u ->
    chkQVdVnVm bin
    render phlp bin Op.VMLA (oneDt SIMDTypI32) OD.OprQdQnQm
  | 0b011100100u | 0b011100110u (* 0111001x0 *) -> raise UndefinedException
  | b when b &&& 0b000111111u = 0b000010100u (* xxx010100 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VRSHL (getDTUSzQ bin) OD.OprDdDmDn
  | b when b &&& 0b000111111u = 0b000010110u (* xxx010110 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VRSHL (getDTUSzQ bin) OD.OprQdQmQn
  | b when b &&& 0b000111111u = 0b000010101u (* xxx010101 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VQRSHL (getDTUSzQ bin) OD.OprDdDmDn
  | b when b &&& 0b000111111u = 0b000010111u (* xxx010111 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VQRSHL (getDTUSzQ bin) OD.OprQdQmQn
  | 0b001101100u ->
    chkQVdVnVm bin
    render phlp bin Op.VQDMULH (oneDt SIMDTypS16) OD.OprDdDnDm
  | 0b010101100u ->
    chkQVdVnVm bin
    render phlp bin Op.VQDMULH (oneDt SIMDTypS32) OD.OprDdDnDm
  | 0b001101110u ->
    chkQVdVnVm bin
    render phlp bin Op.VQDMULH (oneDt SIMDTypS16) OD.OprQdQnQm
  | 0b010101110u ->
    chkQVdVnVm bin
    render phlp bin Op.VQDMULH (oneDt SIMDTypS32) OD.OprQdQnQm
  | 0b000101100u | 0b000101110u (* 0001011x0 *)
  | 0b011101100u | 0b011101110u (* 0111011x0 *) -> raise UndefinedException
  | 0b010110000u -> raise UndefinedException (* if Q != '1' then UNDEFINED *)
  | 0b010110010u -> (* ARMv8 *)
    chkVdVnVm bin
    render phlp bin Op.SHA1M (oneDt SIMDTyp32) OD.OprQdQnQm
  | 0b000101101u (* 0xx101101 *) ->
    render phlp bin Op.VPADD (oneDt SIMDTypI8) OD.OprDdDnDm
  | 0b001101101u (* 0xx101101 *) ->
    render phlp bin Op.VPADD (oneDt SIMDTypI16) OD.OprDdDnDm
  | 0b010101101u (* 0xx101101 *) ->
    render phlp bin Op.VPADD (oneDt SIMDTypI32) OD.OprDdDnDm
  | 0b011101101u (* 0111011x1 *) -> raise UndefinedException
  | 0b000101111u | 0b001101111u | 0b010101111u | 0b011101111u (* 0xx101111 *) ->
    raise UndefinedException
  | b when b &&& 0b000111111u = 0b000011000u (* xxx011000 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VMAX (getDTUSize bin) OD.OprDdDnDm
  | b when b &&& 0b000111111u = 0b000011010u (* xxx011010 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VMAX (getDTUSize bin) OD.OprQdQnQm
  | 0b011000101u ->
    chkQVdVnVm bin; render phlp bin Op.VORN None OD.OprDdDnDm
  | 0b011000111u ->
    chkQVdVnVm bin; render phlp bin Op.VORN None OD.OprQdQnQm
  | b when b &&& 0b000111111u = 0b000011001u (* xxx011001 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VMIN (getDTUSize bin) OD.OprDdDnDm
  | b when b &&& 0b000111111u = 0b000011011u (* xxx011011 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VMIN (getDTUSize bin) OD.OprQdQnQm
  | b when b &&& 0b000111111u = 0b000011100u (* xxx011100 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VABD (getDTUSize bin) OD.OprDdDnDm
  | b when b &&& 0b000111111u = 0b000011110u (* xxx011110 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VABD (getDTUSize bin) OD.OprQdQnQm
  | b when b &&& 0b000111111u = 0b000011101u (* xxx011101 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VABA (getDTUSize bin) OD.OprDdDnDm
  | b when b &&& 0b000111111u = 0b000011111u (* xxx011111 *) ->
    chkQVdVnVm bin
    render phlp bin Op.VABA (getDTUSize bin) OD.OprQdQnQm
  | 0b011110000u -> raise UndefinedException (* if Q != '1' then UNDEFINED *)
  | 0b011110010u -> (* ARMv8 *)
    chkVdVnVm bin
    render phlp bin Op.SHA1SU0 (oneDt SIMDTyp32) OD.OprQdQnQm
  | 0b100110100u ->
    render phlp bin Op.VPADD (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b101110100u ->
    render phlp bin Op.VPADD (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b100110110u | 0b101110110u (* 10x110110 *) -> raise UndefinedException
  | 0b100110101u ->
    chkQVdVnVm bin
    render phlp bin Op.VMUL (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b100110111u ->
    chkQVdVnVm bin
    render phlp bin Op.VMUL (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b101110101u ->
    chkQVdVnVm bin
    render phlp bin Op.VMUL (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b101110111u ->
    chkQVdVnVm bin
    render phlp bin Op.VMUL (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b100111000u ->
    chkQVdVnVm bin
    render phlp bin Op.VCGE (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b100111010u ->
    chkQVdVnVm bin
    render phlp bin Op.VCGE (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b101111000u ->
    chkQVdVnVm bin
    render phlp bin Op.VCGE (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b101111010u ->
    chkQVdVnVm bin
    render phlp bin Op.VCGE (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b100111001u ->
    chkQVdVnVm bin
    render phlp bin Op.VACGE (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b100111011u ->
    chkQVdVnVm bin
    render phlp bin Op.VACGE (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b101111001u ->
    chkQVdVnVm bin
    render phlp bin Op.VACGE (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b101111011u ->
    chkQVdVnVm bin
    render phlp bin Op.VACGE (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b100111100u ->
    render phlp bin Op.VPMAX (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b101111100u ->
    render phlp bin Op.VPMAX (oneDt SIMDTypF16) OD.OprDdDnDm
  (* 10x1111x1 Op.VMAXNM ARMv8 *)
  | 0b100111101u ->
    chkQVdVnVm bin
    render phlp bin Op.VMAXNM (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b100111111u ->
    chkQVdVnVm bin
    render phlp bin Op.VMAXNM (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b101111101u ->
    chkQVdVnVm bin
    render phlp bin Op.VMAXNM (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b101111111u ->
    chkQVdVnVm bin
    render phlp bin Op.VMAXNM (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b100000101u ->
    chkQVdVnVm bin; render phlp bin Op.VEOR None OD.OprDdDnDm
  | 0b100000111u ->
    chkQVdVnVm bin; render phlp bin Op.VEOR None OD.OprQdQnQm
  | 0b000100101u ->
    chkQVdVnVm bin
    render phlp bin Op.VMUL (oneDt SIMDTypI8) OD.OprDdDnDm
  | 0b000100111u ->
    chkQVdVnVm bin
    render phlp bin Op.VMUL (oneDt SIMDTypI8) OD.OprQdQnQm
  | 0b001100101u ->
    chkQVdVnVm bin
    render phlp bin Op.VMUL (oneDt SIMDTypI16) OD.OprDdDnDm
  | 0b001100111u ->
    chkQVdVnVm bin
    render phlp bin Op.VMUL (oneDt SIMDTypI16) OD.OprQdQnQm
  | 0b010100101u ->
    chkQVdVnVm bin
    render phlp bin Op.VMUL (oneDt SIMDTypI32) OD.OprDdDnDm
  | 0b010100111u ->
    chkQVdVnVm bin
    render phlp bin Op.VMUL (oneDt SIMDTypI32) OD.OprQdQnQm
  | 0b100100101u ->
    chkQVdVnVm bin
    render phlp bin Op.VMUL (oneDt SIMDTypP8) OD.OprDdDnDm
  | 0b100100111u ->
    chkQVdVnVm bin
    render phlp bin Op.VMUL (oneDt SIMDTypP8) OD.OprQdQnQm
  (* if size == '11' || (op == '1' && size != '00') then UNDEFINED *)
  | 0b011100101u | 0b011100111u | 0b111100101u | 0b111100111u | 0b101100101u
  | 0b101100111u | 0b110100101u | 0b110100111u -> raise UndefinedException
  | 0b100110000u -> raise UndefinedException (* if Q != '1' then UNDEFINED *)
  | 0b100110010u -> (* ARMv8 *)
    chkVdVnVm bin
    render phlp bin Op.SHA256H (oneDt SIMDTyp32) OD.OprQdQnQm
  | 0b000101000u ->
    render phlp bin Op.VPMAX (oneDt SIMDTypS8) OD.OprDdDnDm
  | 0b001101000u ->
    render phlp bin Op.VPMAX (oneDt SIMDTypS16) OD.OprDdDnDm
  | 0b010101000u ->
    render phlp bin Op.VPMAX (oneDt SIMDTypS32) OD.OprDdDnDm
  | 0b100101000u ->
    render phlp bin Op.VPMAX (oneDt SIMDTypU8) OD.OprDdDnDm
  | 0b101101000u ->
    render phlp bin Op.VPMAX (oneDt SIMDTypU16) OD.OprDdDnDm
  | 0b110101000u ->
    render phlp bin Op.VPMAX (oneDt SIMDTypU32) OD.OprDdDnDm
  | 0b011101000u | 0b111101000u (* x11101000 *) -> raise UndefinedException
  | 0b101000101u ->
    chkQVdVnVm bin; render phlp bin Op.VBSL None OD.OprDdDnDm
  | 0b101000111u ->
    chkQVdVnVm bin; render phlp bin Op.VBSL None OD.OprQdQnQm
  | 0b000101001u ->
    render phlp bin Op.VPMIN (oneDt SIMDTypS8) OD.OprDdDnDm
  | 0b001101001u ->
    render phlp bin Op.VPMIN (oneDt SIMDTypS16) OD.OprDdDnDm
  | 0b010101001u ->
    render phlp bin Op.VPMIN (oneDt SIMDTypS32) OD.OprDdDnDm
  | 0b100101001u ->
    render phlp bin Op.VPMIN (oneDt SIMDTypU8) OD.OprDdDnDm
  | 0b101101001u ->
    render phlp bin Op.VPMIN (oneDt SIMDTypU16) OD.OprDdDnDm
  | 0b110101001u ->
    render phlp bin Op.VPMIN (oneDt SIMDTypU32) OD.OprDdDnDm
  | 0b011101001u | 0b111101001u (* x11101001 *) -> raise UndefinedException
  | b when b &&& 0b000111110u = 0b000101010u (* xxx10101x *) ->
    raise ParsingFailureException
  | 0b101110000u -> raise UndefinedException (* if Q != '1' then UNDEFINED *)
  | 0b101110010u -> (* ARMv8 *)
    chkVdVnVm bin
    render phlp bin Op.SHA256H2 (oneDt SIMDTyp32) OD.OprQdQnQm
  | 0b110110100u ->
    chkQVdVnVm bin
    render phlp bin Op.VABD (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b110110110u ->
    chkQVdVnVm bin
    render phlp bin Op.VABD (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b111110100u ->
    chkQVdVnVm bin
    render phlp bin Op.VABD (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b111110110u ->
    chkQVdVnVm bin
    render phlp bin Op.VABD (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b110111000u ->
    chkQVdVnVm bin
    render phlp bin Op.VCGT (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b110111010u ->
    chkQVdVnVm bin
    render phlp bin Op.VCGT (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b111111000u ->
    chkQVdVnVm bin
    render phlp bin Op.VCGT (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b111111010u ->
    chkQVdVnVm bin
    render phlp bin Op.VCGT (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b110111001u ->
    chkQVdVnVm bin
    render phlp bin Op.VACGT (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b110111011u ->
    chkQVdVnVm bin
    render phlp bin Op.VACGT (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b111111001u ->
    chkQVdVnVm bin
    render phlp bin Op.VACGT (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b111111011u ->
    chkQVdVnVm bin
    render phlp bin Op.VACGT (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b110111100u ->
    render phlp bin Op.VPMIN (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b111111100u ->
    render phlp bin Op.VPMIN (oneDt SIMDTypF16) OD.OprDdDnDm
  (* 11x1111x1 Op.VMINNM ARMv8 *)
  | 0b110111101u ->
    chkQVdVnVm bin
    render phlp bin Op.VMINNM (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b110111111u ->
    chkQVdVnVm bin
    render phlp bin Op.VMINNM (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b111111101u ->
    chkQVdVnVm bin
    render phlp bin Op.VMINNM (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b111111111u ->
    chkQVdVnVm bin
    render phlp bin Op.VMINNM (oneDt SIMDTypF16) OD.OprQdQnQm
  (* 1xx1000x0 VSUB *)
  | 0b100100000u ->
    chkQVdVnVm bin
    render phlp bin Op.VSUB (oneDt SIMDTypI8) OD.OprDdDnDm
  | 0b101100000u ->
    chkQVdVnVm bin
    render phlp bin Op.VSUB (oneDt SIMDTypI16) OD.OprDdDnDm
  | 0b110100000u ->
    chkQVdVnVm bin
    render phlp bin Op.VSUB (oneDt SIMDTypI32) OD.OprDdDnDm
  | 0b111100000u ->
    chkQVdVnVm bin
    render phlp bin Op.VSUB (oneDt SIMDTypI64) OD.OprDdDnDm
  | 0b100100010u ->
    chkQVdVnVm bin
    render phlp bin Op.VSUB (oneDt SIMDTypI8) OD.OprQdQnQm
  | 0b101100010u ->
    chkQVdVnVm bin
    render phlp bin Op.VSUB (oneDt SIMDTypI16) OD.OprQdQnQm
  | 0b110100010u ->
    chkQVdVnVm bin
    render phlp bin Op.VSUB (oneDt SIMDTypI32) OD.OprQdQnQm
  | 0b111100010u ->
    chkQVdVnVm bin
    render phlp bin Op.VSUB (oneDt SIMDTypI64) OD.OprQdQnQm
  (* 1100001x1 VBIT *)
  | 0b110000101u ->
    chkQVdVnVm bin; render phlp bin Op.VBIT None OD.OprDdDnDm
  | 0b110000111u ->
    chkQVdVnVm bin; render phlp bin Op.VBIT None OD.OprQdQnQm
   (* 1xx1000x1 VCEQ *)
  | 0b100100001u ->
    chkQVdVnVm bin
    render phlp bin Op.VCEQ (oneDt SIMDTypI8) OD.OprDdDnDm
  | 0b101100001u ->
    chkQVdVnVm bin
    render phlp bin Op.VCEQ (oneDt SIMDTypI16) OD.OprDdDnDm
  | 0b110100001u ->
    chkQVdVnVm bin
    render phlp bin Op.VCEQ (oneDt SIMDTypI32) OD.OprDdDnDm
  | 0b100100011u ->
    chkQVdVnVm bin
    render phlp bin Op.VCEQ (oneDt SIMDTypI8) OD.OprQdQnQm
  | 0b101100011u ->
    chkQVdVnVm bin
    render phlp bin Op.VCEQ (oneDt SIMDTypI16) OD.OprQdQnQm
  | 0b110100011u ->
    chkQVdVnVm bin
    render phlp bin Op.VCEQ (oneDt SIMDTypI32) OD.OprQdQnQm
  | 0b111100001u | 0b111100011u (* 0b1111000x1u *) -> raise UndefinedException
  (* 1xx1001x0 VMLS *)
  | 0b100100100u ->
    chkQVdVnVm bin
    render phlp bin Op.VMLS (oneDt SIMDTypI8) OD.OprDdDnDm
  | 0b101100100u ->
    chkQVdVnVm bin
    render phlp bin Op.VMLS (oneDt SIMDTypI16) OD.OprDdDnDm
  | 0b110100100u ->
    chkQVdVnVm bin
    render phlp bin Op.VMLS (oneDt SIMDTypI32) OD.OprDdDnDm
  | 0b100100110u ->
    chkQVdVnVm bin
    render phlp bin Op.VMLS (oneDt SIMDTypI8) OD.OprQdQnQm
  | 0b101100110u ->
    chkQVdVnVm bin
    render phlp bin Op.VMLS (oneDt SIMDTypI16) OD.OprQdQnQm
  | 0b110100110u ->
    chkQVdVnVm bin
    render phlp bin Op.VMLS (oneDt SIMDTypI32) OD.OprQdQnQm
  | 0b111100100u | 0b111100110u (* 1111001x0 *) -> raise UndefinedException
  (* 1xx1011x0 VQRDMULH *)
  | 0b101101100u ->
    chkQVdVnVm bin
    render phlp bin Op.VQRDMULH (oneDt SIMDTypS16) OD.OprDdDnDm
  | 0b110101100u ->
    chkQVdVnVm bin
    render phlp bin Op.VQRDMULH (oneDt SIMDTypS32) OD.OprDdDnDm
  | 0b101101110u ->
    chkQVdVnVm bin
    render phlp bin Op.VQRDMULH (oneDt SIMDTypS16) OD.OprQdQnQm
  | 0b110101110u ->
    chkQVdVnVm bin
    render phlp bin Op.VQRDMULH (oneDt SIMDTypS32) OD.OprQdQnQm
  | 0b100101100u | 0b100101110u | 0b111101100u
  | 0b111101110u (* 1001011x0 or 1111011x0 *) -> raise UndefinedException
  | 0b110110000u -> raise UndefinedException (* if Q != '1' then UNDEFINED *)
  | 0b110110010u -> (* ARMv8 *)
    chkVdVnVm bin
    render phlp bin Op.SHA256SU1 (oneDt SIMDTyp32) OD.OprQdQnQm
  (* 1xx1011x1 Op.VQRDMLAH Armv8.1 *)
  | 0b100101101u | 0b100101111u (* 1001011x1 *) -> raise UndefinedException
  | 0b111101101u | 0b111101111u (* 1111011x1 *) -> raise UndefinedException
  | 0b101101101u ->
    chkQVdVnVm bin
    render phlp bin Op.VQRDMLAH (oneDt SIMDTypS16) OD.OprDdDnDm
  | 0b101101111u ->
    chkQVdVnVm bin
    render phlp bin Op.VQRDMLAH (oneDt SIMDTypS16) OD.OprQdQnQm
  | 0b110101101u ->
    chkQVdVnVm bin
    render phlp bin Op.VQRDMLAH (oneDt SIMDTypS32) OD.OprDdDnDm
  | 0b110101111u ->
    chkQVdVnVm bin
    render phlp bin Op.VQRDMLAH (oneDt SIMDTypS32) OD.OprQdQnQm
  (* 1110001x1 VBIF *)
  | 0b111000101u ->
    chkQVdVnVm bin; render phlp bin Op.VBIF None OD.OprDdDnDm
  | 0b111000111u ->
    chkQVdVnVm bin; render phlp bin Op.VBIF None OD.OprQdQnQm
  (* 1xx1100x1 Op.VQRDMLSH Armv8.1 *)
  | 0b100110001u | 0b100110011u (* 1001100x1 *) -> raise UndefinedException
  | 0b111110001u | 0b111110011u (* 1111100x1 *) -> raise UndefinedException
  | 0b101110001u ->
    chkQVdVnVm bin
    render phlp bin Op.VQRDMLSH (oneDt SIMDTypS16) OD.OprDdDnDm
  | 0b101110011u ->
    chkQVdVnVm bin
    render phlp bin Op.VQRDMLSH (oneDt SIMDTypS16) OD.OprQdQnQm
  | 0b110110001u ->
    chkQVdVnVm bin
    render phlp bin Op.VQRDMLSH (oneDt SIMDTypS32) OD.OprDdDnDm
  | 0b110110011u ->
    chkQVdVnVm bin
    render phlp bin Op.VQRDMLSH (oneDt SIMDTypS32) OD.OprQdQnQm
  | b when b &&& 0b100111111u = 0b100111110u (* 1xx111110 *) ->
    raise ParsingFailureException
  | _ -> raise ParsingFailureException

/// Advanced SIMD two registers misc on page F4-4266.
let parseAdvaSIMDTwoRegsMisc (phlp: ParsingHelper) bin =
  (* size:opc1:opc2:Q *)
  match concat (extract bin 19 16) (extract bin 10 6) 5 with
  (* xx000000x VREV64 *)
  | 0b000000000u ->
    chkOpSzQVdVm bin
    render phlp bin Op.VREV64 (oneDt SIMDTyp8) OD.OprDdDm
  | 0b010000000u ->
    chkOpSzQVdVm bin
    render phlp bin Op.VREV64 (oneDt SIMDTyp16) OD.OprDdDm
  | 0b100000000u ->
    chkOpSzQVdVm bin
    render phlp bin Op.VREV64 (oneDt SIMDTyp32) OD.OprDdDm
  | 0b000000001u ->
    chkOpSzQVdVm bin
    render phlp bin Op.VREV64 (oneDt SIMDTyp8) OD.OprQdQm
  | 0b010000001u ->
    chkOpSzQVdVm bin
    render phlp bin Op.VREV64 (oneDt SIMDTyp16) OD.OprQdQm
  | 0b100000001u ->
    chkOpSzQVdVm bin
    render phlp bin Op.VREV64 (oneDt SIMDTyp32) OD.OprQdQm
  | 0b110000000u | 0b110000001u (* 11000000x *) -> raise UndefinedException
  (* xx000001x VREV32 *)
  | 0b000000010u ->
    chkOpSzQVdVm bin
    render phlp bin Op.VREV32 (oneDt SIMDTyp8) OD.OprDdDm
  | 0b010000010u ->
    chkOpSzQVdVm bin
    render phlp bin Op.VREV32 (oneDt SIMDTyp16) OD.OprDdDm
  | 0b000000011u ->
    chkOpSzQVdVm bin
    render phlp bin Op.VREV32 (oneDt SIMDTyp8) OD.OprQdQm
  | 0b010000011u ->
    chkOpSzQVdVm bin
    render phlp bin Op.VREV32 (oneDt SIMDTyp16) OD.OprQdQm
  | 0b100000010u | 0b100000011u | 0b110000010u | 0b110000011u (* 1x000001x *)
    -> raise UndefinedException (* reserved *)
  (* xx000010x VREV16 *)
  | 0b000000100u ->
    chkOpSzQVdVm bin
    render phlp bin Op.VREV16 (oneDt SIMDTyp8) OD.OprDdDm
  | 0b000000101u ->
    chkOpSzQVdVm bin
    render phlp bin Op.VREV16 (oneDt SIMDTyp8) OD.OprQdQm
  | 0b010000100u | 0b010000101u (* 01000010x *)
  | 0b100000100u | 0b100000101u | 0b110000100u | 0b110000101u (* 1x000010x *) ->
    raise UndefinedException (* reserved *)
  | b when b &&& 0b001111110u = 0b000000110u (* xx000011x *) ->
    raise ParsingFailureException
  (* xx00010xx VPADDL *)
  | 0b000001000u ->
    chkQVdVm bin
    render phlp bin Op.VPADDL (oneDt SIMDTypS8) OD.OprDdDm
  | 0b010001000u ->
    chkQVdVm bin
    render phlp bin Op.VPADDL (oneDt SIMDTypS16) OD.OprDdDm
  | 0b100001000u ->
    chkQVdVm bin
    render phlp bin Op.VPADDL (oneDt SIMDTypS32) OD.OprDdDm
  | 0b000001010u ->
    chkQVdVm bin
    render phlp bin Op.VPADDL (oneDt SIMDTypU8) OD.OprDdDm
  | 0b010001010u ->
    chkQVdVm bin
    render phlp bin Op.VPADDL (oneDt SIMDTypU16) OD.OprDdDm
  | 0b100001010u ->
    chkQVdVm bin
    render phlp bin Op.VPADDL (oneDt SIMDTypU32) OD.OprDdDm
  | 0b000001001u ->
    chkQVdVm bin
    render phlp bin Op.VPADDL (oneDt SIMDTypS8) OD.OprQdQm
  | 0b010001001u ->
    chkQVdVm bin
    render phlp bin Op.VPADDL (oneDt SIMDTypS16) OD.OprQdQm
  | 0b100001001u ->
    chkQVdVm bin
    render phlp bin Op.VPADDL (oneDt SIMDTypS32) OD.OprQdQm
  | 0b000001011u ->
    chkQVdVm bin
    render phlp bin Op.VPADDL (oneDt SIMDTypU8) OD.OprQdQm
  | 0b010001011u ->
    chkQVdVm bin
    render phlp bin Op.VPADDL (oneDt SIMDTypU16) OD.OprQdQm
  | 0b100001011u ->
    chkQVdVm bin
    render phlp bin Op.VPADDL (oneDt SIMDTypU32) OD.OprQdQm
  | 0b110001000u | 0b110001001u | 0b110001010u | 0b110001011u (* 1100010xx *) ->
    raise UndefinedException (* size = 11 *)
  (* xx0001100 AESE *)
  | 0b000001100u ->
    chkVdVm bin; render phlp bin Op.AESE (oneDt SIMDTyp8) OD.OprQdQm
  | 0b010001100u | 0b100001100u | 0b110001100u (* size = 10 or 1x *) ->
    raise UndefinedException
   (* xx0001101 AESD *)
  | 0b000001101u ->
    chkVdVm bin; render phlp bin Op.AESD (oneDt SIMDTyp8) OD.OprQdQm
  | 0b010001101u | 0b100001101u | 0b110001101u (* size = 10 or 1x *) ->
    raise UndefinedException
  (* xx0001110 AESMC *)
  | 0b000001110u ->
    chkVdVm bin; render phlp bin Op.AESMC (oneDt SIMDTyp8) OD.OprQdQm
  | 0b010001110u | 0b100001110u | 0b110001110u (* size = 10 or 1x *) ->
    raise UndefinedException
  (* xx0001111 AESIMC *)
  | 0b000001111u ->
    chkVdVm bin
    render phlp bin Op.AESIMC (oneDt SIMDTyp8) OD.OprQdQm
  | 0b010001111u | 0b100001111u | 0b110001111u (* size = 10 or 1x *) ->
    raise UndefinedException
  (* xx001000x VCLS *)
  | 0b000010000u ->
    chkQVdVm bin
    render phlp bin Op.VCLS (oneDt SIMDTypS8) OD.OprDdDm
  | 0b010010000u ->
    chkQVdVm bin
    render phlp bin Op.VCLS (oneDt SIMDTypS16) OD.OprDdDm
  | 0b100010000u ->
    chkQVdVm bin
    render phlp bin Op.VCLS (oneDt SIMDTypS32) OD.OprDdDm
  | 0b000010001u ->
    chkQVdVm bin
    render phlp bin Op.VCLS (oneDt SIMDTypS8) OD.OprQdQm
  | 0b010010001u ->
    chkQVdVm bin
    render phlp bin Op.VCLS (oneDt SIMDTypS16) OD.OprQdQm
  | 0b100010001u ->
    chkQVdVm bin
    render phlp bin Op.VCLS (oneDt SIMDTypS32) OD.OprQdQm
  | 0b110010000u| 0b110010001u (* 11001000x *) -> raise UndefinedException
  (* 00100000x VSWP *)
  | 0b001000000u ->
    chkQVdVnVm bin; render phlp bin Op.VSWP None OD.OprDdDm
  | 0b001000001u ->
    chkQVdVnVm bin; render phlp bin Op.VSWP None OD.OprQdQm
  (* xx001001x VCLZ *)
  | 0b000010010u ->
    chkQVdVm bin
    render phlp bin Op.VCLZ (oneDt SIMDTypI8) OD.OprDdDm
  | 0b010010010u ->
    chkQVdVm bin
    render phlp bin Op.VCLZ (oneDt SIMDTypI16) OD.OprDdDm
  | 0b100010010u ->
    chkQVdVm bin
    render phlp bin Op.VCLZ (oneDt SIMDTypI32) OD.OprDdDm
  | 0b000010011u ->
    chkQVdVm bin
    render phlp bin Op.VCLZ (oneDt SIMDTypI8) OD.OprQdQm
  | 0b010010011u ->
    chkQVdVm bin
    render phlp bin Op.VCLZ (oneDt SIMDTypI16) OD.OprQdQm
  | 0b100010011u ->
    chkQVdVm bin
    render phlp bin Op.VCLZ (oneDt SIMDTypI32) OD.OprQdQm
  | 0b110010010u | 0b110010011u (* 11x001001x *) -> raise UndefinedException
  (* xx001010x *)
  | 0b000010100u ->
    chkQVdVm bin; render phlp bin Op.VCNT (oneDt SIMDTyp8) OD.OprDdDm
  | 0b000010101u ->
    chkQVdVm bin; render phlp bin Op.VCNT (oneDt SIMDTyp8) OD.OprQdQm
  | 0b010010100u | 0b100010100u | 0b110010100u | 0b010010101u | 0b100010101u
  | 0b110010101u (* size != 00 *) -> raise UndefinedException
  (* xx001011x VMVN *)
  | 0b000010110u ->
    chkQVdVm bin; render phlp bin Op.VMVN None OD.OprDdDm
  | 0b000010111u ->
    chkQVdVm bin; render phlp bin Op.VMVN None OD.OprQdQm
  | 0b010010110u | 0b100010110u | 0b110010110u | 0b010010111u | 0b100010111u
  | 0b110010111u (* size != 00 *) -> raise UndefinedException
  | 0b001011001u -> raise ParsingFailureException
  (* xx00110xx VPADAL *)
  | 0b000011000u ->
    chkQVdVm bin
    render phlp bin Op.VPADAL (oneDt SIMDTypS8) OD.OprDdDm
  | 0b010011000u ->
    chkQVdVm bin
    render phlp bin Op.VPADAL (oneDt SIMDTypS16) OD.OprDdDm
  | 0b100011000u ->
    chkQVdVm bin
    render phlp bin Op.VPADAL (oneDt SIMDTypS32) OD.OprDdDm
  | 0b000011010u ->
    chkQVdVm bin
    render phlp bin Op.VPADAL (oneDt SIMDTypU8) OD.OprDdDm
  | 0b010011010u ->
    chkQVdVm bin
    render phlp bin Op.VPADAL (oneDt SIMDTypU16) OD.OprDdDm
  | 0b100011010u ->
    chkQVdVm bin
    render phlp bin Op.VPADAL (oneDt SIMDTypU32) OD.OprDdDm
  | 0b000011001u ->
    chkQVdVm bin
    render phlp bin Op.VPADAL (oneDt SIMDTypS8) OD.OprQdQm
  | 0b010011001u ->
    chkQVdVm bin
    render phlp bin Op.VPADAL (oneDt SIMDTypS16) OD.OprQdQm
  | 0b100011001u ->
    chkQVdVm bin
    render phlp bin Op.VPADAL (oneDt SIMDTypS32) OD.OprQdQm
  | 0b000011011u ->
    chkQVdVm bin
    render phlp bin Op.VPADAL (oneDt SIMDTypU8) OD.OprQdQm
  | 0b010011011u ->
    chkQVdVm bin
    render phlp bin Op.VPADAL (oneDt SIMDTypU16) OD.OprQdQm
  | 0b100011011u ->
    chkQVdVm bin
    render phlp bin Op.VPADAL (oneDt SIMDTypU32) OD.OprQdQm
  | 0b110011000u | 0b110011001u | 0b110011010u | 0b110011011u (* 1100110xx *) ->
    raise UndefinedException
  (* xx001110x VQABS *)
  | 0b000011100u ->
    chkQVdVm bin
    render phlp bin Op.VQABS (oneDt SIMDTypS8) OD.OprDdDm
  | 0b010011100u ->
    chkQVdVm bin
    render phlp bin Op.VQABS (oneDt SIMDTypS16) OD.OprDdDm
  | 0b100011100u ->
    chkQVdVm bin
    render phlp bin Op.VQABS (oneDt SIMDTypS32) OD.OprDdDm
  | 0b000011101u ->
    chkQVdVm bin
    render phlp bin Op.VQABS (oneDt SIMDTypS8) OD.OprQdQm
  | 0b010011101u ->
    chkQVdVm bin
    render phlp bin Op.VQABS (oneDt SIMDTypS16) OD.OprQdQm
  | 0b100011101u ->
    chkQVdVm bin
    render phlp bin Op.VQABS (oneDt SIMDTypS32) OD.OprQdQm
  | 0b110011100u | 0b110011101u (* 11001110x *) -> raise UndefinedException
  (* xx001111x VQNEG *)
  | 0b000011110u ->
    chkQVdVm bin
    render phlp bin Op.VQNEG (oneDt SIMDTypS8) OD.OprDdDm
  | 0b010011110u ->
    chkQVdVm bin
    render phlp bin Op.VQNEG (oneDt SIMDTypS16) OD.OprDdDm
  | 0b100011110u ->
    chkQVdVm bin
    render phlp bin Op.VQNEG (oneDt SIMDTypS32) OD.OprDdDm
  | 0b000011111u ->
    chkQVdVm bin
    render phlp bin Op.VQNEG (oneDt SIMDTypS8) OD.OprQdQm
  | 0b010011111u ->
    chkQVdVm bin
    render phlp bin Op.VQNEG (oneDt SIMDTypS16) OD.OprQdQm
  | 0b100011111u ->
    chkQVdVm bin
    render phlp bin Op.VQNEG (oneDt SIMDTypS32) OD.OprQdQm
  | 0b110011110u | 0b110011111u (* 11001111x *) -> raise UndefinedException
  (* xx01x000x VCGT *)
  | 0b000100000u ->
    chkQVdVm bin
    render phlp bin Op.VCGT (oneDt SIMDTypS8) OD.OprDdDmImm0
  | 0b010100000u ->
    chkQVdVm bin
    render phlp bin Op.VCGT (oneDt SIMDTypS16) OD.OprDdDmImm0
  | 0b100100000u ->
    chkQVdVm bin
    render phlp bin Op.VCGT (oneDt SIMDTypS32) OD.OprDdDmImm0
  | 0b010110000u ->
    chkQVdVm bin
    render phlp bin Op.VCGT (oneDt SIMDTypF16) OD.OprDdDmImm0
  | 0b100110000u ->
    chkQVdVm bin
    render phlp bin Op.VCGT (oneDt SIMDTypF32) OD.OprDdDmImm0
  | 0b000100001u ->
    chkQVdVm bin
    render phlp bin Op.VCGT (oneDt SIMDTypS8) OD.OprQdQmImm0
  | 0b010100001u ->
    chkQVdVm bin
    render phlp bin Op.VCGT (oneDt SIMDTypS16) OD.OprQdQmImm0
  | 0b100100001u ->
    chkQVdVm bin
    render phlp bin Op.VCGT (oneDt SIMDTypS32) OD.OprQdQmImm0
  | 0b010110001u ->
    chkQVdVm bin
    render phlp bin Op.VCGT (oneDt SIMDTypF16) OD.OprQdQmImm0
  | 0b100110001u ->
    chkQVdVm bin
    render phlp bin Op.VCGT (oneDt SIMDTypF32) OD.OprQdQmImm0
  | 0b000110000u | 0b000110001u (* 00011000x *) -> raise UndefinedException
  | 0b110100000u | 0b110100001u | 0b110110000u | 0b110110001u (* 1101x000x *) ->
    raise UndefinedException
  (* xx01x001x VCGE *)
  | 0b000100010u ->
    chkQVdVm bin
    render phlp bin Op.VCGE (oneDt SIMDTypS8) OD.OprDdDmImm0
  | 0b010100010u ->
    chkQVdVm bin
    render phlp bin Op.VCGE (oneDt SIMDTypS16) OD.OprDdDmImm0
  | 0b100100010u ->
    chkQVdVm bin
    render phlp bin Op.VCGE (oneDt SIMDTypS32) OD.OprDdDmImm0
  | 0b010110010u ->
    chkQVdVm bin
    render phlp bin Op.VCGE (oneDt SIMDTypF16) OD.OprDdDmImm0
  | 0b100110010u ->
    chkQVdVm bin
    render phlp bin Op.VCGE (oneDt SIMDTypF32) OD.OprDdDmImm0
  | 0b000100011u ->
    chkQVdVm bin
    render phlp bin Op.VCGE (oneDt SIMDTypS8) OD.OprQdQmImm0
  | 0b010100011u ->
    chkQVdVm bin
    render phlp bin Op.VCGE (oneDt SIMDTypS16) OD.OprQdQmImm0
  | 0b100100011u ->
    chkQVdVm bin
    render phlp bin Op.VCGE (oneDt SIMDTypS32) OD.OprQdQmImm0
  | 0b010110011u ->
    chkQVdVm bin
    render phlp bin Op.VCGE (oneDt SIMDTypF16) OD.OprQdQmImm0
  | 0b100110011u ->
    chkQVdVm bin
    render phlp bin Op.VCGE (oneDt SIMDTypF32) OD.OprQdQmImm0
  | 0b000110010u | 0b000110011u (* 00011001x *) -> raise UndefinedException
  | 0b110100010u | 0b110100011u | 0b110110010u | 0b110110011u (* 1101x001x *) ->
    raise UndefinedException
  (* xx01x010x VCEQ *)
  | 0b000100100u ->
    chkQVdVm bin
    render phlp bin Op.VCEQ (oneDt SIMDTypI8) OD.OprDdDmImm0
  | 0b010100100u ->
    chkQVdVm bin
    render phlp bin Op.VCEQ (oneDt SIMDTypI16) OD.OprDdDmImm0
  | 0b100100100u ->
    chkQVdVm bin
    render phlp bin Op.VCEQ (oneDt SIMDTypI32) OD.OprDdDmImm0
  | 0b010110100u ->
    chkQVdVm bin
    render phlp bin Op.VCEQ (oneDt SIMDTypF16) OD.OprDdDmImm0
  | 0b100110100u ->
    chkQVdVm bin
    render phlp bin Op.VCEQ (oneDt SIMDTypF32) OD.OprDdDmImm0
  | 0b000100101u ->
    chkQVdVm bin
    render phlp bin Op.VCEQ (oneDt SIMDTypI8) OD.OprQdQmImm0
  | 0b010100101u ->
    chkQVdVm bin
    render phlp bin Op.VCEQ (oneDt SIMDTypI16) OD.OprQdQmImm0
  | 0b100100101u ->
    chkQVdVm bin
    render phlp bin Op.VCEQ (oneDt SIMDTypI32) OD.OprQdQmImm0
  | 0b010110101u ->
    chkQVdVm bin
    render phlp bin Op.VCEQ (oneDt SIMDTypF16) OD.OprQdQmImm0
  | 0b100110101u ->
    chkQVdVm bin
    render phlp bin Op.VCEQ (oneDt SIMDTypF32) OD.OprQdQmImm0
  | 0b000110100u | 0b000110101u (* 00011010x *) -> raise UndefinedException
  | 0b110100100u | 0b110100101u | 0b110110100u | 0b110110101u (* 1101x010x *) ->
    raise UndefinedException
  (* xx01x011x VCLE *)
  | 0b000100110u ->
    chkQVdVm bin
    render phlp bin Op.VCLE (oneDt SIMDTypS8) OD.OprDdDmImm0
  | 0b010100110u ->
    chkQVdVm bin
    render phlp bin Op.VCLE (oneDt SIMDTypS16) OD.OprDdDmImm0
  | 0b100100110u ->
    chkQVdVm bin
    render phlp bin Op.VCLE (oneDt SIMDTypS32) OD.OprDdDmImm0
  | 0b010110110u ->
    chkQVdVm bin
    render phlp bin Op.VCLE (oneDt SIMDTypF16) OD.OprDdDmImm0
  | 0b100110110u ->
    chkQVdVm bin
    render phlp bin Op.VCLE (oneDt SIMDTypF32) OD.OprDdDmImm0
  | 0b000100111u ->
    chkQVdVm bin
    render phlp bin Op.VCLE (oneDt SIMDTypS8) OD.OprQdQmImm0
  | 0b010100111u ->
    chkQVdVm bin
    render phlp bin Op.VCLE (oneDt SIMDTypS16) OD.OprQdQmImm0
  | 0b100100111u ->
    chkQVdVm bin
    render phlp bin Op.VCLE (oneDt SIMDTypS32) OD.OprQdQmImm0
  | 0b010110111u ->
    chkQVdVm bin
    render phlp bin Op.VCLE (oneDt SIMDTypF16) OD.OprQdQmImm0
  | 0b100110111u ->
    chkQVdVm bin
    render phlp bin Op.VCLE (oneDt SIMDTypF32) OD.OprQdQmImm0
  | 0b000110110u| 0b000110111u (* 00011011x *) -> raise UndefinedException
  | 0b110100110u | 0b110100111u | 0b110110110u | 0b110110111u (* 1101x011x *) ->
    raise UndefinedException
  (* xx01x100x VCLT *)
  | 0b000101000u ->
    chkQVdVm bin
    render phlp bin Op.VCLT (oneDt SIMDTypS8) OD.OprDdDmImm0
  | 0b010101000u ->
    chkQVdVm bin
    render phlp bin Op.VCLT (oneDt SIMDTypS16) OD.OprDdDmImm0
  | 0b100101000u ->
    chkQVdVm bin
    render phlp bin Op.VCLT (oneDt SIMDTypS32) OD.OprDdDmImm0
  | 0b010111000u ->
    chkQVdVm bin
    render phlp bin Op.VCLT (oneDt SIMDTypF16) OD.OprDdDmImm0
  | 0b100111000u ->
    chkQVdVm bin
    render phlp bin Op.VCLT (oneDt SIMDTypF32) OD.OprDdDmImm0
  | 0b000101001u ->
    chkQVdVm bin
    render phlp bin Op.VCLT (oneDt SIMDTypS8) OD.OprQdQmImm0
  | 0b010101001u ->
    chkQVdVm bin
    render phlp bin Op.VCLT (oneDt SIMDTypS16) OD.OprQdQmImm0
  | 0b100101001u ->
    chkQVdVm bin
    render phlp bin Op.VCLT (oneDt SIMDTypS32) OD.OprQdQmImm0
  | 0b010111001u ->
    chkQVdVm bin
    render phlp bin Op.VCLT (oneDt SIMDTypF16) OD.OprQdQmImm0
  | 0b100111001u ->
    chkQVdVm bin
    render phlp bin Op.VCLT (oneDt SIMDTypF32) OD.OprQdQmImm0
  | 0b000111000u | 0b000111001u (* 00011100x *) -> raise UndefinedException
  | 0b110101000u | 0b110101001u | 0b110111000u | 0b110111001u (* 1101x100x *) ->
    raise UndefinedException
  (* xx01x110x VABS *)
  | 0b000101100u ->
    chkQVdVm bin
    render phlp bin Op.VABS (oneDt SIMDTypS8) OD.OprDdDm
  | 0b010101100u ->
    chkQVdVm bin
    render phlp bin Op.VABS (oneDt SIMDTypS16) OD.OprDdDm
  | 0b100101100u ->
    chkQVdVm bin
    render phlp bin Op.VABS (oneDt SIMDTypS32) OD.OprDdDm
  | 0b010111100u ->
    chkQVdVm bin
    render phlp bin Op.VABS (oneDt SIMDTypF16) OD.OprDdDm
  | 0b100111100u ->
    chkQVdVm bin
    render phlp bin Op.VABS (oneDt SIMDTypF32) OD.OprDdDm
  | 0b000101101u ->
    chkQVdVm bin
    render phlp bin Op.VABS (oneDt SIMDTypS8) OD.OprQdQm
  | 0b010101101u ->
    chkQVdVm bin
    render phlp bin Op.VABS (oneDt SIMDTypS16) OD.OprQdQm
  | 0b100101101u ->
    chkQVdVm bin
    render phlp bin Op.VABS (oneDt SIMDTypS32) OD.OprQdQm
  | 0b010111101u ->
    chkQVdVm bin
    render phlp bin Op.VABS (oneDt SIMDTypF16) OD.OprQdQm
  | 0b100111101u ->
    chkQVdVm bin
    render phlp bin Op.VABS (oneDt SIMDTypF32) OD.OprQdQm
  | 0b000111100u | 0b000111101u (* 00011110x *) -> raise UndefinedException
  | 0b110101100u | 0b110101101u | 0b110111100u | 0b110111101u (* 1101x110x *) ->
    raise UndefinedException
  (* xx01x111x VNEG *)
  | 0b000101110u ->
    chkQVdVm bin
    render phlp bin Op.VNEG (oneDt SIMDTypS8) OD.OprDdDm
  | 0b010101110u ->
    chkQVdVm bin
    render phlp bin Op.VNEG (oneDt SIMDTypS16) OD.OprDdDm
  | 0b100101110u ->
    chkQVdVm bin
    render phlp bin Op.VNEG (oneDt SIMDTypS32) OD.OprDdDm
  | 0b010111110u ->
    chkQVdVm bin
    render phlp bin Op.VNEG (oneDt SIMDTypF16) OD.OprDdDm
  | 0b100111110u ->
    chkQVdVm bin
    render phlp bin Op.VNEG (oneDt SIMDTypF32) OD.OprDdDm
  | 0b000101111u ->
    chkQVdVm bin
    render phlp bin Op.VNEG (oneDt SIMDTypS8) OD.OprQdQm
  | 0b010101111u ->
    chkQVdVm bin
    render phlp bin Op.VNEG (oneDt SIMDTypS16) OD.OprQdQm
  | 0b100101111u ->
    chkQVdVm bin
    render phlp bin Op.VNEG (oneDt SIMDTypS32) OD.OprQdQm
  | 0b010111111u ->
    chkQVdVm bin
    render phlp bin Op.VNEG (oneDt SIMDTypF16) OD.OprQdQm
  | 0b100111111u ->
    chkQVdVm bin
    render phlp bin Op.VNEG (oneDt SIMDTypF32) OD.OprQdQm
  | 0b000111110u | 0b000111111u (* 00011111x *) -> raise UndefinedException
  | 0b110101110u | 0b110101111u | 0b110111110u | 0b110111111u (* 1101x111x *) ->
    raise UndefinedException
  (* xx0101011 SHA1H *)
  | 0b100101011u ->
    chkVdVm bin
    render phlp bin Op.SHA1H (oneDt SIMDTyp32) OD.OprQdQm
  | 0b000101011u | 0b010101011u | 0b110101011u (* size != 10 *) ->
    raise UndefinedException
  | 0b011011001u -> (* Armv8.6 *)
    chkVm bin
    render phlp bin Op.VCVT (twoDt (BF16, SIMDTypF32)) OD.OprDdQm
  (* xx100001x VTRN *)
  | 0b001000010u ->
    chkQVdVm bin; render phlp bin Op.VTRN (oneDt SIMDTyp8) OD.OprDdDm
  | 0b011000010u ->
    chkQVdVm bin
    render phlp bin Op.VTRN (oneDt SIMDTyp16) OD.OprDdDm
  | 0b101000010u ->
    chkQVdVm bin
    render phlp bin Op.VTRN (oneDt SIMDTyp32) OD.OprDdDm
  | 0b001000011u ->
    chkQVdVm bin; render phlp bin Op.VTRN (oneDt SIMDTyp8) OD.OprQdQm
  | 0b011000011u ->
    chkQVdVm bin
    render phlp bin Op.VTRN (oneDt SIMDTyp16) OD.OprQdQm
  | 0b101000011u ->
    chkQVdVm bin
    render phlp bin Op.VTRN (oneDt SIMDTyp32) OD.OprQdQm
  | 0b111000010u | 0b111000011u (* 11100001x *) -> raise UndefinedException
  (* xx100010x VUZP *)
  | 0b001000100u ->
    chkQVdVm bin; render phlp bin Op.VUZP (oneDt SIMDTyp8) OD.OprDdDm
  | 0b011000100u ->
    chkQVdVm bin
    render phlp bin Op.VUZP (oneDt SIMDTyp16) OD.OprDdDm
  | 0b001000101u ->
    chkQVdVm bin; render phlp bin Op.VUZP (oneDt SIMDTyp8) OD.OprQdQm
  | 0b011000101u ->
    chkQVdVm bin
    render phlp bin Op.VUZP (oneDt SIMDTyp16) OD.OprQdQm
  | 0b101000101u ->
    chkQVdVm bin
    render phlp bin Op.VUZP (oneDt SIMDTyp32) OD.OprQdQm
  | 0b111000100u | 0b111000101u (* 11100010x *) -> raise UndefinedException
  | 0b101000100u -> raise UndefinedException (* Q == 0 && size == 10 *)
  (* xx100011x VZIP *)
  | 0b001000110u ->
    chkQVdVm bin; render phlp bin Op.VZIP (oneDt SIMDTyp8) OD.OprDdDm
  | 0b011000110u ->
    chkQVdVm bin
    render phlp bin Op.VZIP (oneDt SIMDTyp16) OD.OprDdDm
  | 0b001000111u ->
    chkQVdVm bin; render phlp bin Op.VZIP (oneDt SIMDTyp8) OD.OprQdQm
  | 0b011000111u ->
    chkQVdVm bin
    render phlp bin Op.VZIP (oneDt SIMDTyp16) OD.OprQdQm
  | 0b101000111u ->
    chkQVdVm bin
    render phlp bin Op.VZIP (oneDt SIMDTyp32) OD.OprQdQm
  | 0b111000110u | 0b111000111u (* 11100011x *) -> raise UndefinedException
  | 0b101000110u -> raise UndefinedException (* Q == 0 && size == 10 *)
  (* xx1001000 VMOVN *)
  | 0b001001000u ->
    chkVm bin; render phlp bin Op.VMOVN (oneDt SIMDTyp16) OD.OprDdQm
  | 0b011001000u ->
    chkVm bin; render phlp bin Op.VMOVN (oneDt SIMDTyp32) OD.OprDdQm
  | 0b101001000u ->
    chkVm bin; render phlp bin Op.VMOVN (oneDt SIMDTyp64) OD.OprDdQm
  | 0b111001000u (* size == 11 *) -> raise UndefinedException
  (* xx1001001 VQMOVUN *)
  | 0b001001001u ->
    chkVm bin
    render phlp bin Op.VQMOVUN (oneDt SIMDTypS16) OD.OprDdQm
  | 0b011001001u ->
    chkVm bin
    render phlp bin Op.VQMOVUN (oneDt SIMDTypS32) OD.OprDdQm
  | 0b101001001u ->
    chkVm bin
    render phlp bin Op.VQMOVUN (oneDt SIMDTypS64) OD.OprDdQm
  | 0b111001001u (* size = 11 *) -> raise UndefinedException
  (* xx100101x VQMOVN *)
  | 0b001001010u ->
    chkVm bin
    render phlp bin Op.VQMOVN (oneDt SIMDTypS16) OD.OprDdQm
  | 0b011001010u ->
    chkVm bin
    render phlp bin Op.VQMOVN (oneDt SIMDTypS32) OD.OprDdQm
  | 0b101001010u ->
    chkVm bin
    render phlp bin Op.VQMOVN (oneDt SIMDTypS64) OD.OprDdQm
  | 0b001001011u ->
    chkVm bin
    render phlp bin Op.VQMOVN (oneDt SIMDTypU16) OD.OprDdQm
  | 0b011001011u ->
    chkVm bin
    render phlp bin Op.VQMOVN (oneDt SIMDTypU32) OD.OprDdQm
  | 0b101001011u ->
    chkVm bin
    render phlp bin Op.VQMOVN (oneDt SIMDTypU64) OD.OprDdQm
  | 0b111001010u | 0b111001011u (* size = 11 *) -> raise UndefinedException
  (* xx1001100 VSHLL *)
  | 0b001001100u ->
    chkVd bin
    render phlp bin Op.VSHLL (oneDt SIMDTypI8) OD.OprQdDmImm8
  | 0b011001100u ->
    chkVd bin
    render phlp bin Op.VSHLL (oneDt SIMDTypI16) OD.OprQdDmImm16
  | 0b101001100u ->
    chkVd bin
    render phlp bin Op.VSHLL (oneDt SIMDTypI32) OD.OprQdDmImm32
  | 0b111001100u (* size = 11 *) -> raise UndefinedException
  (* xx1001110 SHA1SU1 *)
  | 0b101001110u ->
    chkVdVm bin
    render phlp bin Op.SHA1SU1 (oneDt SIMDTyp32) OD.OprQdQm
  | 00001001110u | 0b011001110u | 0b111001110u (* size != 10 *) ->
    raise UndefinedException
  (* xx1001111 SHA256SU0 *)
  | 0b101001111u ->
    chkVdVm bin
    render phlp bin Op.SHA256SU0 (oneDt SIMDTyp32) OD.OprQdQm
  | 0b001001111u| 0b011001111u| 0b111001111u (* size != 10 *) ->
    raise UndefinedException
  (* xx101000x VRINTN *)
  | 0b011010000u ->
    chkQVdVm bin
    render phlp bin Op.VRINTN (oneDt SIMDTypF16) OD.OprDdDm
  | 0b101010000u ->
    chkQVdVm bin
    render phlp bin Op.VRINTN (oneDt SIMDTypF32) OD.OprDdDm
  | 0b011010001u ->
    chkQVdVm bin
    render phlp bin Op.VRINTN (oneDt SIMDTypF16) OD.OprQdQm
  | 0b101010001u ->
    chkQVdVm bin
    render phlp bin Op.VRINTN (oneDt SIMDTypF32) OD.OprQdQm
  | 0b001010000u | 0b001010001u | 0b111010000u
  | 0b111010001u (* size = 00 or 11 *) -> raise UndefinedException
  (* xx101001x VRINTX *)
  | 0b011010010u ->
    chkQVdVm bin
    render phlp bin Op.VRINTX (oneDt SIMDTypF16) OD.OprDdDm
  | 0b101010010u ->
    chkQVdVm bin
    render phlp bin Op.VRINTX (oneDt SIMDTypF32) OD.OprDdDm
  | 0b011010011u ->
    chkQVdVm bin
    render phlp bin Op.VRINTX (oneDt SIMDTypF16) OD.OprQdQm
  | 0b101010011u ->
    chkQVdVm bin
    render phlp bin Op.VRINTX (oneDt SIMDTypF32) OD.OprQdQm
  | 0b001010010u | 0b001010011u | 0b111010010u
  | 0b111010011u (* size = 00 or 11 *) -> raise UndefinedException
  (* xx101010x VRINTA *)
  | 0b011010100u ->
    chkQVdVm bin
    render phlp bin Op.VRINTA (oneDt SIMDTypF16) OD.OprDdDm
  | 0b101010100u ->
    chkQVdVm bin
    render phlp bin Op.VRINTA (oneDt SIMDTypF32) OD.OprDdDm
  | 0b011010101u ->
    chkQVdVm bin
    render phlp bin Op.VRINTA (oneDt SIMDTypF16) OD.OprQdQm
  | 0b101010101u ->
    chkQVdVm bin
    render phlp bin Op.VRINTA (oneDt SIMDTypF32) OD.OprQdQm
  | 0b001010100u | 0b001010101u | 0b111010100u
  | 0b111010101u (* size = 00 or 11 *) -> raise UndefinedException
  (* xx101011x VRINTZ *)
  | 0b011010110u ->
    chkQVdVm bin
    render phlp bin Op.VRINTZ (oneDt SIMDTypF16) OD.OprDdDm
  | 0b101010110u ->
    chkQVdVm bin
    render phlp bin Op.VRINTZ (oneDt SIMDTypF32) OD.OprDdDm
  | 0b011010111u ->
    chkQVdVm bin
    render phlp bin Op.VRINTZ (oneDt SIMDTypF16) OD.OprQdQm
  | 0b101010111u ->
    chkQVdVm bin
    render phlp bin Op.VRINTZ (oneDt SIMDTypF32) OD.OprQdQm
  | 0b001010110u | 0b001010111u | 0b111010110u
  | 0b111010111u (* size = 00 or 1 1*) -> raise UndefinedException
  | 0b101011001u -> raise ParsingFailureException
  (* xx1011000 VCVT *)
  | 0b011011000u ->
    let dt = twoDt (SIMDTypF16, SIMDTypF32)
    render phlp bin Op.VCVT dt OD.OprDdQm
  | 0b001011000u | 0b101011000u | 0b111011000u (* size != 01 *) ->
    raise UndefinedException
  (* xx101101x VRINTM *)
  | 0b011011010u ->
    chkQVdVm bin
    render phlp bin Op.VRINTM (oneDt SIMDTypF16) OD.OprDdDm
  | 0b101011010u ->
    chkQVdVm bin
    render phlp bin Op.VRINTM (oneDt SIMDTypF32) OD.OprDdDm
  | 0b011011011u ->
    chkQVdVm bin
    render phlp bin Op.VRINTM (oneDt SIMDTypF16) OD.OprQdQm
  | 0b101011011u ->
    chkQVdVm bin
    render phlp bin Op.VRINTM (oneDt SIMDTypF32) OD.OprQdQm
  | 0b001011010u | 0b001011011u | 0b111011010u
  | 0b111011011u (* size = 00 or 11*) -> raise UndefinedException
  (* xx1011100 VCVT *)
  | 0b011011100u ->
    chkVdVm bin
    let dt = twoDt (SIMDTypF32, SIMDTypF16)
    render phlp bin Op.VCVT dt OD.OprQdDm
  | 0b001011100u | 0b101011100u | 0b111011100u (* size != 01 *) ->
    raise UndefinedException
  | 0b001011101u | 0b011011101u | 0b101011101u | 0b111011101u (* xx1011101 *) ->
    raise ParsingFailureException
  (* xx101111x VRINTP *)
  | 0b011011110u ->
    chkQVdVm bin
    render phlp bin Op.VRINTP (oneDt SIMDTypF16) OD.OprDdDm
  | 0b101011110u ->
    chkQVdVm bin
    render phlp bin Op.VRINTP (oneDt SIMDTypF32) OD.OprDdDm
  | 0b011011111u ->
    chkQVdVm bin
    render phlp bin Op.VRINTP (oneDt SIMDTypF16) OD.OprQdQm
  | 0b101011111u ->
    chkQVdVm bin
    render phlp bin Op.VRINTP (oneDt SIMDTypF32) OD.OprQdQm
  | 0b001011110u | 0b001011111u | 0b111011110u
  | 0b111011111u (* size = 00 or 11 *) -> raise UndefinedException
  (* xx11000xx VCVTA *)
  | 0b011100000u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp bin Op.VCVTA dt OD.OprDdDm
  | 0b101100000u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVTA dt OD.OprDdDm
  | 0b011100010u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp bin Op.VCVTA dt OD.OprDdDm
  | 0b101100010u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVTA dt OD.OprDdDm
  | 0b011100001u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp bin Op.VCVTA dt OD.OprQdQm
  | 0b101100001u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVTA dt OD.OprQdQm
  | 0b011100011u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp bin Op.VCVTA dt OD.OprQdQm
  | 0b101100011u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVTA dt OD.OprQdQm
  | 0b001100000u | 0b001100001u | 0b001100010u | 0b001100011u | 0b111100000u
  | 0b111100001u | 0b111100010u | 0b111100011u (* size = 00 or 11 *) ->
    raise UndefinedException
  (* xx11001xx VCVTN *)
  | 0b011100100u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp bin Op.VCVTN dt OD.OprDdDm
  | 0b101100100u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVTN dt OD.OprDdDm
  | 0b011100110u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp bin Op.VCVTN dt OD.OprDdDm
  | 0b101100110u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVTN dt OD.OprDdDm
  | 0b011100101u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp bin Op.VCVTN dt OD.OprQdQm
  | 0b101100101u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVTN dt OD.OprQdQm
  | 0b011100111u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp bin Op.VCVTN dt OD.OprQdQm
  | 0b101100111u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVTN dt OD.OprQdQm
  | 0b001100100u | 0b001100101u | 0b001100110u | 0b001100111u | 0b111100100u
  | 0b111100101u | 0b111100110u | 0b111100111u (* size = 00 or 11 *) ->
    raise UndefinedException
  (* xx11010xx VCVTP *)
  | 0b011101000u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp bin Op.VCVTP dt OD.OprDdDm
  | 0b101101000u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVTP dt OD.OprDdDm
  | 0b011101010u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp bin Op.VCVTP dt OD.OprDdDm
  | 0b101101010u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVTP dt OD.OprDdDm
  | 0b011101001u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp bin Op.VCVTP dt OD.OprQdQm
  | 0b101101001u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVTP dt OD.OprQdQm
  | 0b011101011u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp bin Op.VCVTP dt OD.OprQdQm
  | 0b101101011u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVTP dt OD.OprQdQm
  | 0b001101000u | 0b001101001u | 0b001101010u | 0b001101011u | 0b111101000u
  | 0b111101001u | 0b111101010u | 0b111101011u (* size = 00 or 11 *) ->
    raise UndefinedException
  (* xx11011xx VCVTM *)
  | 0b011101100u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp bin Op.VCVTM dt OD.OprDdDm
  | 0b101101100u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVTM dt OD.OprDdDm
  | 0b011101110u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp bin Op.VCVTM dt OD.OprDdDm
  | 0b101101110u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVTM dt OD.OprDdDm
  | 0b011101101u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp bin Op.VCVTM dt OD.OprQdQm
  | 0b101101101u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVTM dt OD.OprQdQm
  | 0b011101111u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp bin Op.VCVTM dt OD.OprQdQm
  | 0b101101111u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVTM dt OD.OprQdQm
  | 0b001101100u | 0b001101101u | 0b001101110u | 0b001101111u | 0b111101100u
  | 0b111101101u | 0b111101110u | 0b111101111u (* size = 00 or 11 *) ->
    raise UndefinedException
  (* xx1110x0x VRECPE *)
  | 0b101110000u ->
    chkQVdVm bin
    render phlp bin Op.VRECPE (oneDt SIMDTypU32) OD.OprDdDm
  | 0b011110100u ->
    chkQVdVm bin
    render phlp bin Op.VRECPE (oneDt SIMDTypF16) OD.OprDdDm
  | 0b101110100u ->
    chkQVdVm bin
    render phlp bin Op.VRECPE (oneDt SIMDTypF32) OD.OprDdDm
  | 0b101110001u ->
    chkQVdVm bin
    render phlp bin Op.VRECPE (oneDt SIMDTypU32) OD.OprQdQm
  | 0b011110101u ->
    chkQVdVm bin
    render phlp bin Op.VRECPE (oneDt SIMDTypF16) OD.OprQdQm
  | 0b101110101u ->
    chkQVdVm bin
    render phlp bin Op.VRECPE (oneDt SIMDTypF32) OD.OprQdQm
  | 0b001110000u | 0b001110001u | 0b001110100u | 0b001110101u | 0b111110000u
  | 0b111110001u | 0b111110100u | 0b111110101u (* size = 00 or 11 *) ->
    raise UndefinedException
  (* xx1110x1x VRSQRTE *)
  | 0b101110010u ->
    chkQVdVm bin
    render phlp bin Op.VRSQRTE (oneDt SIMDTypU32) OD.OprDdDm
  | 0b011110110u ->
    chkQVdVm bin
    render phlp bin Op.VRSQRTE (oneDt SIMDTypF16) OD.OprDdDm
  | 0b101110110u ->
    chkQVdVm bin
    render phlp bin Op.VRSQRTE (oneDt SIMDTypF32) OD.OprDdDm
  | 0b101110011u ->
    chkQVdVm bin
    render phlp bin Op.VRSQRTE (oneDt SIMDTypU32) OD.OprQdQm
  | 0b011110111u ->
    chkQVdVm bin
    render phlp bin Op.VRSQRTE (oneDt SIMDTypF16) OD.OprQdQm
  | 0b101110111u ->
    chkQVdVm bin
    render phlp bin Op.VRSQRTE (oneDt SIMDTypF32) OD.OprQdQm
  | 0b001110010u | 0b001110011u | 0b001110110u | 0b001110111u | 0b111110010u
  | 0b111110011u | 0b111110110u | 0b111110111u (* size = 00 or 11 *) ->
    raise UndefinedException
  | 0b111011001u -> raise ParsingFailureException
  (* xx1111xxx VCVT *)
  | 0b011111000u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypF16, SIMDTypS16)
    render phlp bin Op.VCVT dt OD.OprDdDm
  | 0b011111010u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypF16, SIMDTypU16)
    render phlp bin Op.VCVT dt OD.OprDdDm
  | 0b011111100u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp bin Op.VCVT dt OD.OprDdDm
  | 0b011111110u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypU32, SIMDTypF16)
    render phlp bin Op.VCVT dt OD.OprDdDm
  | 0b101111000u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypF32, SIMDTypS32)
    render phlp bin Op.VCVT dt OD.OprDdDm
  | 0b101111010u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypF32, SIMDTypU32)
    render phlp bin Op.VCVT dt OD.OprDdDm
  | 0b101111100u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVT dt OD.OprDdDm
  | 0b101111110u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVT dt OD.OprDdDm
  | 0b011111001u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypF16, SIMDTypS16)
    render phlp bin Op.VCVT dt OD.OprQdQm
  | 0b011111011u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypF16, SIMDTypU16)
    render phlp bin Op.VCVT dt OD.OprQdQm
  | 0b011111101u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp bin Op.VCVT dt OD.OprQdQm
  | 0b011111111u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypU32, SIMDTypF16)
    render phlp bin Op.VCVT dt OD.OprQdQm
  | 0b101111001u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypF32, SIMDTypS32)
    render phlp bin Op.VCVT dt OD.OprQdQm
  | 0b101111011u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypF32, SIMDTypU32)
    render phlp bin Op.VCVT dt OD.OprQdQm
  | 0b101111101u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVT dt OD.OprQdQm
  | 0b101111111u ->
    chkQVdVm bin
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVT dt OD.OprQdQm
  | 0b001111000u | 0b001111001u | 0b001111010u | 0b001111011u | 0b001111100u
  | 0b001111101u | 0b001111110u | 0b001111111u (* size = 00 *) ->
    raise UndefinedException
  | 0b111111000u | 0b111111001u | 0b111111010u | 0b111111011u | 0b111111100u
  | 0b111111101u | 0b111111110u | 0b111111111u (* size = 11 *) ->
    raise UndefinedException
  | _ -> raise ParsingFailureException

/// Advanced SIMD duplicate (scalar) on page F4-4268.
let parseAdvSIMDDupScalar (phlp: ParsingHelper) bin =
  match extract bin 9 7 (* opc *) with
  | 0b000u ->
    let dt = getDTImm4 (extract bin 19 16) |> oneDt
    chkQVd bin; render phlp bin Op.VDUP dt OD.OprDdDmx
  | _ (* 001 or 01x or 1xx *) -> raise ParsingFailureException

/// Advanced SIMD three registers of different lengths on page F4-4268.
let parseAdvSIMDThreeRegsDiffLen (phlp: ParsingHelper) bin =
  match concat (pickBit bin 24) (extract bin 11 8) 4 (* U:opc *) with
  | 0b00000u | 0b10000u (* x0000 *) ->
    let dt = getDT bin |> oneDt
    chkVdOp bin; render phlp bin Op.VADDL dt OD.OprQdDnDm
  | 0b00001u | 0b10001u (* x0001 *) ->
    let dt = getDT bin |> oneDt
    chkVdOp bin; render phlp bin Op.VADDW dt OD.OprQdQnDm
  | 0b00010u | 0b10010u (* x0010 *) ->
    let dt = getDT bin |> oneDt
    chkVdOp bin; render phlp bin Op.VSUBL dt OD.OprQdDnDm
  | 0b00100u ->
    let dt = getDTInt (extract bin 21 20) |> oneDt
    chkVnVm bin; render phlp bin Op.VADDHN dt OD.OprDdQnQm
  | 0b00011u | 0b10011u (* x0011 *) ->
    let dt = getDT bin |> oneDt
    chkVdOp bin; render phlp bin Op.VSUBW dt OD.OprQdQnDm
  | 0b00110u ->
    let dt = getDTInt (extract bin 21 20) |> oneDt
    chkVnVm bin; render phlp bin Op.VSUBHN dt OD.OprDdQnQm
  | 0b01001u ->
    let dt = getDT bin |> oneDt
    chkSzVd bin; render phlp bin Op.VQDMLAL dt OD.OprQdDnDm
  | 0b00101u | 0b10101u (* x0101 *) ->
    let dt = getDT bin |> oneDt
    chkVd0 bin; render phlp bin Op.VABAL dt OD.OprQdDnDm
  | 0b01011u ->
    let dt = getDT bin |> oneDt
    chkSzVd bin; render phlp bin Op.VQDMLSL dt OD.OprQdDnDm
  | 0b01101u ->
    let dt = getDT bin |> oneDt
    chkSzVd bin; render phlp bin Op.VQDMULL dt OD.OprQdDnDm
  | 0b00111u | 0b10111u (* x0111 *) ->
    let dt = getDT bin |> oneDt
    chkVd0 bin; render phlp bin Op.VABDL dt OD.OprQdDnDm
  | 0b01000u | 0b11000u (* x1000 *) ->
    let dt = getDT bin |> oneDt
    chkVd0 bin; render phlp bin Op.VMLAL dt OD.OprQdDnDm
  | 0b01010u | 0b11010u (* x1010 *) ->
    let dt = getDT bin |> oneDt
    chkVd0 bin; render phlp bin Op.VMLSL dt OD.OprQdDnDm
  | 0b10100u ->
    let dt = getDTInt (extract bin 21 20) |> oneDt
    chkVnVm bin; render phlp bin Op.VRADDHN dt OD.OprDdQnQm
  | 0b10110u ->
    let dt = getDTInt (extract bin 21 20) |> oneDt
    chkVnVm bin; render phlp bin Op.VRSUBHN dt OD.OprDdQnQm
  | 0b01100u | 0b01110u | 0b11100u | 0b11110u (* x11x0 *) ->
    let dt = getDT bin |> oneDt
    chkVd0 bin; render phlp bin Op.VMULL dt OD.OprQdDnDm
  | 0b11001u -> raise ParsingFailureException
  | 0b11011u -> raise ParsingFailureException
  | 0b11101u -> raise ParsingFailureException
  | _ (* x1111 *) -> raise ParsingFailureException

/// Advanced SIMD two registers and a scalar on page F4-4269.
let parseAdvSIMDTRegsAndScalar (phlp: ParsingHelper) bin =
  match concat (pickBit bin 24) (extract bin 11 8) 4 (* Q:opc *) with
  | 0b00000u ->
    let dt = getDTF0 (extract bin 21 20) |> oneDt
    chkSzQVdVn bin; render phlp bin Op.VMLA dt OD.OprDdDnDmx
  | 0b00001u ->
    let dt = getDTF1 (extract bin 21 20) |> oneDt
    chkSzQVdVn bin; render phlp bin Op.VMLA dt OD.OprDdDnDmx
  | 0b10000u ->
    let dt = getDTF0 (extract bin 21 20) |> oneDt
    chkSzQVdVn bin; render phlp bin Op.VMLA dt OD.OprQdQnDmx
  | 0b10001u ->
    let dt = getDTF1 (extract bin 21 20) |> oneDt
    chkSzQVdVn bin; render phlp bin Op.VMLA dt OD.OprQdQnDmx
  | 0b00011u ->
    let dt = getDT bin |> oneDt
    chkSzVd bin; render phlp bin Op.VQDMLAL dt OD.OprQdDnDmx
  | 0b00010u | 0b10010u (* x0010 *) ->
    let dt = getDT bin |> oneDt
    chkSzVd bin; render phlp bin Op.VMLAL dt OD.OprQdDnDmx
  | 0b00111u ->
    let dt = getDT bin |> oneDt
    chkSzVd bin; render phlp bin Op.VQDMLSL dt OD.OprQdDnDmx
  | 0b00100u ->
    let dt = getDTF0 (extract bin 21 20) |> oneDt
    chkSzQVdVn bin; render phlp bin Op.VMLS dt OD.OprDdDnDmx
  | 0b00101u ->
    let dt = getDTF1 (extract bin 21 20) |> oneDt
    chkSzQVdVn bin; render phlp bin Op.VMLS dt OD.OprDdDnDmx
  | 0b10100u ->
    let dt = getDTF0 (extract bin 21 20) |> oneDt
    chkSzQVdVn bin; render phlp bin Op.VMLS dt OD.OprQdQnDmx
  | 0b10101u ->
    let dt = getDTF1 (extract bin 21 20) |> oneDt
    chkSzQVdVn bin; render phlp bin Op.VMLS dt OD.OprQdQnDmx
  | 0b01011u ->
    let dt = getDT bin |> oneDt
    chkSzVd bin; render phlp bin Op.VQDMULL dt OD.OprQdDnDmx
  | 0b00110u | 0b10110u (* x0110 *) ->
    let dt = getDT bin |> oneDt
    chkSzVd bin; render phlp bin Op.VMLSL dt OD.OprQdDnDmx
  | 0b01000u ->
    let dt = getDTF0 (extract bin 21 20) |> oneDt
    chkSzQVdVn bin; render phlp bin Op.VMUL dt OD.OprDdDnDmx
  | 0b01001u ->
    let dt = getDTF1 (extract bin 21 20) |> oneDt
    chkSzQVdVn bin; render phlp bin Op.VMUL dt OD.OprDdDnDmx
  | 0b11000u ->
    let dt = getDTF0 (extract bin 21 20) |> oneDt
    chkSzQVdVn bin; render phlp bin Op.VMUL dt OD.OprQdQnDmx
  | 0b11001u ->
    let dt = getDTF1 (extract bin 21 20) |> oneDt
    chkSzQVdVn bin; render phlp bin Op.VMUL dt OD.OprQdQnDmx
  | 0b10011u -> raise ParsingFailureException
  | 0b01010u | 0b11010u (* x1010 *) ->
    let dt = getDT bin |> oneDt
    chkSzVd bin; render phlp bin Op.VMULL dt OD.OprQdDnDmx
  | 0b10111u -> raise ParsingFailureException
  | 0b01100u ->
    let dt = getDTSign (extract bin 21 20) |> oneDt
    chkSzQVdVn bin; render phlp bin Op.VQDMULH dt OD.OprDdDnDmx
  | 0b11100u ->
    let dt = getDTSign (extract bin 21 20) |> oneDt
    chkSzQVdVn bin; render phlp bin Op.VQDMULH dt OD.OprQdQnDmx
  | 0b01101u ->
    let dt = getDTSign (extract bin 21 20) |> oneDt
    chkSzQVdVn bin; render phlp bin Op.VQRDMULH dt OD.OprDdDnDmx
  | 0b11101u ->
    let dt = getDTSign (extract bin 21 20) |> oneDt
    chkSzQVdVn bin; render phlp bin Op.VQRDMULH dt OD.OprQdQnDmx
  | 0b11011u -> raise ParsingFailureException
  | 0b01110u -> (* Armv8.1 *)
    chkQVdVnSz bin
    let dt = getDTSign (extract bin 21 20) |> oneDt
    render phlp bin Op.VQRDMLAH dt OD.OprDdDnDmx
  | 0b11110u -> (* Armv8.1 *)
    chkQVdVnSz bin
    let dt = getDTSign (extract bin 21 20) |> oneDt
    render phlp bin Op.VQRDMLAH dt OD.OprQdQnDmx
  | 0b01111u -> (* Armv8.1 *)
    chkQVdVnSz bin
    let dt = getDTSign (extract bin 21 20) |> oneDt
    render phlp bin Op.VQRDMLSH dt OD.OprDdDnDmx
  | 0b11111u -> (* Armv8.1 *)
    chkQVdVnSz bin
    let dt = getDTSign (extract bin 21 20) |> oneDt
    render phlp bin Op.VQRDMLSH dt OD.OprQdQnDmx
  | _ -> raise ParsingFailureException

/// Advanced SIMD two registers, or three registers of different lengths
/// on page F4-4265.
let parseAdvSIMDTwoThreeRegsDiffLen (phlp: ParsingHelper) bin =
  let decodeField = (* op0:op1:op2:op3 *)
    (pickBit bin 24 <<< 5) + (extract bin 21 20 <<< 3) +
    (extract bin 11 10 <<< 1) + (pickBit bin 6)
  match decodeField (* op0:op1:op2:op3 *) with
  | 0b011000u | 0b011010u | 0b011100u | 0b011110u (* 011xx0 *) ->
    chkQVdImm bin
    render phlp bin Op.VEXT (oneDt SIMDTyp8) OD.OprDdDnDmImm
  | 0b011001u | 0b011011u | 0b011101u | 0b011111u (* 011xx1 *) ->
    chkQVdImm bin
    render phlp bin Op.VEXT (oneDt SIMDTyp8) OD.OprQdQnQmImm
  | 0b111000u | 0b111001u | 0b111010u | 0b111011u (* 1110xx *) ->
    parseAdvaSIMDTwoRegsMisc phlp bin
  | 0b111100u ->
    chkPCRnLen bin
    render phlp bin Op.VTBL (oneDt SIMDTyp8) OD.OprDdListDm
  | 0b111101u ->
    chkPCRnLen bin
    render phlp bin Op.VTBX (oneDt SIMDTyp8) OD.OprDdListDm
  | 0b111110u | 0b111111u (* 11111x *) ->
    parseAdvSIMDDupScalar phlp bin
  | b when (b &&& 0b000001u = 0b000000u) && (extract bin 21 20 <> 0b11u) ->
    (* x != 11 xx0 *) parseAdvSIMDThreeRegsDiffLen phlp bin
  | _ (* x != 11 xx1 *) -> parseAdvSIMDTRegsAndScalar phlp bin

/// Advanced SIMD one register and modified immediate on page F4-4271.
let parseAdvSIMDOneRegAndModImm (phlp: ParsingHelper) bin =
  match concat (extract bin 11 8) (pickBit bin 5) 1 (* cmode:op *) with
  | 0b00000u | 0b00100u | 0b01000u | 0b01100u (* 0xx00 *) ->
    let dt = Some (OneDT SIMDTypI32)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm else OD.OprQdImm
    chkQVd bin; render phlp bin Op.VMOV dt oprFn
  | 0b00001u | 0b00101u | 0b01001u | 0b01101u (* 0xx01 *) ->
    let dt = Some (OneDT SIMDTypI32)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm else OD.OprQdImm
    chkQVd bin; render phlp bin Op.VMVN dt oprFn
  | 0b00010u | 0b00110u | 0b01010u | 0b01110u (* 0xx10 *) ->
    let dt = Some (OneDT SIMDTypI32)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm else OD.OprQdImm
    chkQVd bin; render phlp bin Op.VORR dt oprFn
  | 0b00011u | 0b00111u | 0b01011u | 0b01111u (* 0xx11 *) ->
    let dt = Some (OneDT SIMDTypI32)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm else OD.OprQdImm
    chkQVd bin; render phlp bin Op.VBIC dt oprFn
  | 0b10000u | 0b10100u (* 10x00 *) ->
    let dt = Some (OneDT SIMDTypI16)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm else OD.OprQdImm
    chkQVd bin; render phlp bin Op.VMOV dt oprFn
  | 0b10001u | 0b10101u (* 10x01 *) ->
    let dt = Some (OneDT SIMDTypI16)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm else OD.OprQdImm
    chkQVd bin; render phlp bin Op.VMVN dt oprFn
  | 0b10010u | 0b10110u (* 10x10 *) ->
    let dt = Some (OneDT SIMDTypI16)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm else OD.OprQdImm
    chkQVd bin; render phlp bin Op.VORR dt oprFn
  | 0b10011u | 0b10111u (* 10x11 *) ->
    let dt = Some (OneDT SIMDTypI16)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm else OD.OprQdImm
    chkQVd bin; render phlp bin Op.VBIC dt oprFn
  (* 11xx0 VMOV (immediate) - A4 *)
  | 0b11000u | 0b11010u ->
    let dt = Some (OneDT SIMDTypI32)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm else OD.OprQdImm
    chkQVd bin; render phlp bin Op.VMOV dt oprFn
  | 0b11100u ->
    let dt = Some (OneDT SIMDTypI8)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm else OD.OprQdImm
    chkQVd bin; render phlp bin Op.VMOV dt oprFn
  | 0b11110u ->
    let dt = Some (OneDT SIMDTypF32)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm else OD.OprQdImm
    chkQVd bin; render phlp bin Op.VMOV dt oprFn
  | 0b11001u | 0b11011u (* 110x1 *) ->
    let dt = Some (OneDT SIMDTypI32)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm else OD.OprQdImm
    chkQVd bin; render phlp bin Op.VMVN dt oprFn
  | 0b11101u ->
    let dt = Some (OneDT SIMDTypI64)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm else OD.OprQdImm
    chkQVd bin; render phlp bin Op.VMOV dt oprFn
  | _ (* 11111 *) -> raise ParsingFailureException

/// Advanced SIMD two registers and shift amount on page F4-4271.
let parseAdvSIMDTwoRegsAndShfAmt (phlp: ParsingHelper) bin =
  (* imm3H:L *)
  if concat (extract bin 21 19) (pickBit bin 7) 1 <> 0b0000u then ()
  else raise ParsingFailureException
  let decodeField = (* U:opc:Q *)
    concat (concat (pickBit bin 24) (extract bin 11 8) 4) (pickBit bin 6) 1
  match decodeField (* U:opc:Q *) with
  | 0b000000u | 0b100000u (* x00000 *) ->
    chkQVdVm bin
    render phlp bin Op.VSHR (getDTLImm bin) OD.OprDdDmImm
  | 0b000001u | 0b100001u (* x00001 *) ->
    chkQVdVm bin
    render phlp bin Op.VSHR (getDTLImm bin) OD.OprQdQmImm
  | 0b000010u | 0b100010u (* x00010 *) ->
    chkQVdVm bin
    render phlp bin Op.VSRA (getDTLImm bin) OD.OprDdDmImm
  | 0b000011u | 0b100011u (* x00011 *) ->
    chkQVdVm bin
    render phlp bin Op.VSRA (getDTLImm bin) OD.OprQdQmImm
  | 0b010100u | 0b110100u (* x10100 *)
    when extract bin 18 16 (* imm3L *) = 0b000u ->
    (* if Vd<0> == '1' then UNDEFINED *)
    pickBit bin 12 (* Vd<0> *) = 1u |> checkUndef
    render phlp bin Op.VMOVL (getDTUImm3H bin) OD.OprQdDm
  | 0b000100u | 0b100100u (* x00100 *) ->
    chkQVdVm bin
    render phlp bin Op.VRSHR (getDTLImm bin) OD.OprDdDmImm
  | 0b000101u | 0b100101u (* x00101 *) ->
    chkQVdVm bin
    render phlp bin Op.VRSHR (getDTLImm bin) OD.OprQdQmImm
  | 0b000110u | 0b100110u (* x00110 *) ->
    chkQVdVm bin
    render phlp bin Op.VRSRA (getDTLImm bin) OD.OprDdDmImm
  | 0b000111u | 0b100111u (* x00111 *) ->
    chkQVdVm bin
    render phlp bin Op.VRSRA (getDTLImm bin) OD.OprQdQmImm
  | 0b001110u | 0b101110u (* x01110 *) ->
    chkUOpQVdVm bin
    render phlp bin Op.VQSHL (getDTLImm bin) OD.OprDdDmImmLeft
  | 0b001111u | 0b101111u (* x01111 *) ->
    chkUOpQVdVm bin
    render phlp bin Op.VQSHL (getDTLImm bin) OD.OprQdQmImmLeft
  | 0b010010u | 0b110010u (* x10010 *) ->
    (* if Vm<0> == '1' then UNDEFINED *)
    checkUndef (pickBit bin 0 = 1u)
    render phlp bin Op.VQSHRN (getDTImm6Word bin) OD.OprDdQmImm
  | 0b010011u | 0b110011u (* x10011 *) ->
    (* if Vm<0> == '1' then UNDEFINED *)
    pickBit bin 0 = 1u |> checkUndef
    render phlp bin Op.VQRSHRN (getDTImm6Word bin) OD.OprDdQmImm
  | 0b010100u | 0b110100u (* x10100 *) ->
    (* if Vd<0> == '1' then UNDEFINED *)
    pickBit bin 12 = 1u |> checkUndef
    render phlp bin Op.VSHLL (getDTImm6Byte bin) OD.OprQdDmImm
  | b when b &&& 0b011000u = 0b011000u (* x11xxx *) ->
    (* if op<1> == '0' && imm6 == '10xxxx' then UNDEFINED
       if imm6 == '0xxxxx' then UNDEFINED
       if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED *)
    ((pickBit bin 9 = 0u && extract bin 21 20 = 0b10u) ||
     (pickBit bin 21 = 0u) ||
      (pickBit bin 6 = 1u && (pickBit bin 12 = 1u || pickBit bin 0 = 1u)))
      |> checkUndef
    let dt1 =
      match concat (extract bin 9 8) (pickBit bin 24) 1 (* op:U *) with
      | 0b000u | 0b001u (* 00x *) -> SIMDTypF16
      | 0b010u -> SIMDTypS16
      | 0b011u -> SIMDTypU16
      | 0b100u | 0b101u (* 10x *) -> SIMDTypF32
      | 0b110u -> SIMDTypS32
      | _ (* 111 *) -> SIMDTypU32
    let dt2 =
      match concat (extract bin 9 8) (pickBit bin 24) 1 (* op:U *) with
      | 0b000u -> SIMDTypS16
      | 0b001u -> SIMDTypU16
      | 0b010u | 0b011u (* 01x *) -> SIMDTypF16
      | 0b100u -> SIMDTypS32
      | 0b101u -> SIMDTypU32
      | _ (* 11x *) -> SIMDTypF32
    let oprFn =
      if pickBit bin 6 (* Q *) = 0u then OD.OprDdDmFbits else OD.OprQdQmFbits
    render phlp bin Op.VCVT (twoDt (dt1, dt2)) oprFn
  | 0b001010u | 0b001011u (* 00101x *) ->
    chkQVdVm bin
    let dt = (* L:imm6<5:3> *)
      match concat (pickBit bin 7) (extract bin 21 19) 3 with
      | 0b0000u -> raise ParsingFailureException
      | 0b0001u -> SIMDTypI8
      | 0b0010u | 0b0011u (* 001x *) -> SIMDTypI16
      | 0b0100u | 0b0101u | 0b0110u | 0b0111u (* 01xx *) -> SIMDTypI32
      | _ (* 1xxx *) -> SIMDTypI64
      |> oneDt
    let oprFn =
      if pickBit bin 6 (* Q *) = 0u then OD.OprDdDmImmLeft else OD.OprQdQmImmLeft
    render phlp bin Op.VSHL dt oprFn
  | 0b010000u ->
    (* if Vm<0> == '1' then UNDEFINED *)
    pickBit bin 0 (* Vm<0> *) = 1u |> checkUndef
    render phlp bin Op.VSHRN (getDTImm6Int bin) OD.OprDdQmImm
  | 0b010001u ->
    (* if Vm<0> == '1' then UNDEFINED *)
    pickBit bin 0 (* Vm<0> *) = 1u |> checkUndef
    render phlp bin Op.VRSHRN (getDTImm6Int bin) OD.OprDdQmImm
  | 0b101000u ->
    chkQVdVm bin
    render phlp bin Op.VSRI (getDTImm6 bin) OD.OprDdDmImm
  | 0b101001u ->
    chkQVdVm bin
    render phlp bin Op.VSRI (getDTImm6 bin) OD.OprQdQmImm
  | 0b101010u ->
    chkQVdVm bin
    render phlp bin Op.VSLI (getDTImm6 bin) OD.OprDdDmImmLeft
  | 0b101011u ->
    chkQVdVm bin
    render phlp bin Op.VSLI (getDTImm6 bin) OD.OprQdQmImmLeft
  | 0b101100u ->
    chkUOpQVdVm bin
    render phlp bin Op.VQSHLU (getDTLImm bin) OD.OprDdDmImmLeft
  | 0b101101u ->
    chkUOpQVdVm bin
    render phlp bin Op.VQSHLU (getDTLImm bin) OD.OprQdQmImmLeft
  | 0b110000u ->
    (* if Vm<0> == '1' then UNDEFINED *)
    pickBit bin 0 (* Vm<0> *) = 1u |> checkUndef
    render phlp bin Op.VQSHRUN (getDTImm6Sign bin) OD.OprDdQmImm
  | 0b110001u ->
    (* if Vm<0> == '1' then UNDEFINED *)
    pickBit bin 0 (* Vm<0> *) = 1u |> checkUndef
    render phlp bin Op.VQRSHRUN (getDTImm6Sign bin) OD.OprDdQmImm
  | _ -> raise ParsingFailureException

/// Advanced SIMD shifts and immediate generation on page F4-4270.
let parseAdvSIMDShfAndImmGen (phlp: ParsingHelper) bin =
  if extract bin 21 7 &&& 0b111000000000001u = 0b0u (* 000xxxxxxxxxxx0 *) then
    parseAdvSIMDOneRegAndModImm phlp bin
  else (* != 000xxxxxxxxxxx0 *)
    parseAdvSIMDTwoRegsAndShfAmt phlp bin

/// Advanced SIMD data-processing on page F4-4262.
let parseAdvSIMDDataProc (phlp: ParsingHelper) bin =
  match concat (pickBit bin 23) (pickBit bin 4) 1 (* op0:op1 *) with
  | 0b00u | 0b01u (* 0x *) ->
    parseAdvSIMDThreeRegsSameLen phlp bin
  | 0b10u -> parseAdvSIMDTwoThreeRegsDiffLen phlp bin
  | _ (* 11 *) -> parseAdvSIMDShfAndImmGen phlp bin

/// Barriers on page F4-4273.
let parseBarriers (phlp: ParsingHelper) bin =
  let option = extract bin 3 0
  match extract bin 7 4 (* opcode *) with
  | 0b0000u -> raise UnpredictableException
  | 0b0001u -> render phlp bin Op.CLREX None OD.OprNo
  | 0b0010u | 0b0011u -> raise UnpredictableException
  | 0b0100u when (option <> 0b0000u) || (option <> 0b0100u) ->
    render phlp bin Op.DSB None OD.OprOption
  | 0b0100u when option = 0b0000u ->
    render phlp bin Op.SSBB None OD.OprNo
  | 0b0100u when option = 0b0100u ->
    render phlp bin Op.PSSBB None OD.OprNo
  | 0b0101u -> render phlp bin Op.DMB None OD.OprOption
  | 0b0110u -> render phlp bin Op.ISB None OD.OprOption
  | 0b0111u -> render phlp bin Op.SB None OD.OprNo
  | _ (* 1xxx *) -> raise UnpredictableException

/// Preload (immediate) on page F4-4273.
let parsePreloadImm (phlp: ParsingHelper) bin =
  let isRn1111 bin = extract bin 19 16 = 0b1111u
  match concat (pickBit bin 24) (pickBit bin 22) 1 (* D:R *) with
  | 0b00u -> render phlp bin Op.NOP None OD.OprNo
  | 0b01u -> render phlp bin Op.PLI None OD.OprLabel12
  | 0b10u | 0b11u when isRn1111 bin ->
    render phlp bin Op.PLD None OD.OprLabel12
  | 0b10u (* != 1111 *) -> render phlp bin Op.PLDW None OD.OprMemImm
  | _ (* 0b11u != 1111 *) -> render phlp bin Op.PLD None OD.OprMemImm

/// Preload (register) on page F4-4274.
let parsePreloadReg (phlp: ParsingHelper) bin =
  match concat (pickBit bin 24) (pickBit bin 22) 1 (* D:o2 *) with
  | 0b00u -> render phlp bin Op.NOP None OD.OprNo
  | 0b01u -> chkPCRm bin; render phlp bin Op.PLI None OD.OprMemReg
  | 0b10u ->
    chkPCRmRnPldw bin; render phlp bin Op.PLDW None OD.OprMemReg
  | _ (* 11 *) ->
    chkPCRmRnPldw bin; render phlp bin Op.PLD None OD.OprMemReg

/// Memory hints and barriers on page F4-4272.
let parseMemoryHintsAndBarriers (phlp: ParsingHelper) bin =
  match concat (extract bin 25 21) (pickBit bin 4) 1 (* op0:op1 *) with
  | b when b &&& 0b110010u = 0b000010u (* 00xx1x *) ->
    raise UnpredictableException
  | 0b010010u | 0b010011u (* 01001x *) -> raise UnpredictableException
  | 0b010110u | 0b010111u (* 01011x *) -> parseBarriers phlp bin
  | 0b011010u | 0b011011u | 0b011110u | 0b011111u (* 011x1x *) ->
    raise UnpredictableException
  | b when b &&& 0b100010u = 0b000000u (* 0xxx0x *) ->
    parsePreloadImm phlp bin
  | b when b &&& 0b100011u = 0b100000u (* 1xxx00 *) ->
    parsePreloadReg phlp bin
  | b when b &&& 0b100011u = 0b100010u (* 1xxx10 *) ->
    raise UnpredictableException
  | _ (* 1xxxx1 *) -> raise ParsingFailureException

/// Advanced SIMD load/store multiple structures on page F4-4275.
let parseAdvSIMDLdStMulStruct (phlp: ParsingHelper) bin =
  match concat (pickBit bin 21) (extract bin 11 8) 4 (* L:itype *) with
  | 0b00000u | 0b00001u (* 0000x *) ->
    let dt = getDT64 (extract bin 7 6) |> oneDt
    chkSzPCRnD4 bin; render phlp bin Op.VST4 dt OD.OprListMem
  | 0b00010u ->
    let dt = getDT64 (extract bin 7 6) |> oneDt
    chkPCRnDregs bin; render phlp bin Op.VST1 dt OD.OprListMem
  | 0b00011u ->
    let dt = getDT64 (extract bin 7 6) |> oneDt
    chkPCRnD2regs bin; render phlp bin Op.VST2 dt OD.OprListMem
  | 0b00100u | 0b00101u (* 0010x *) ->
    let dt = getDT64 (extract bin 7 6) |> oneDt
    chkPCRnD3 bin; render phlp bin Op.VST3 dt OD.OprListMem
  | 0b00110u ->
    let dt = getDT64 (extract bin 7 6) |> oneDt
    chkAlign1PCRnDregs bin 3u
    render phlp bin Op.VST1 dt OD.OprListMem
  | 0b00111u ->
    let dt = getDT64 (extract bin 7 6) |> oneDt
    chkAlign1PCRnDregs bin 1u
    render phlp bin Op.VST1 dt OD.OprListMem
  | 0b01000u | 0b01001u (* 0100x *) ->
    let dt = getDT64 (extract bin 7 6) |> oneDt
    chkAlignPCRnD2regs bin; render phlp bin Op.VST2 dt OD.OprListMem
  | 0b01010u ->
    let dt = getDT64 (extract bin 7 6) |> oneDt
    chkAlignPCRnDregs bin; render phlp bin Op.VST1 dt OD.OprListMem
  | 0b10000u | 0b10001u (* 1000x *) ->
    let dt = getDT64 (extract bin 7 6) |> oneDt
    chkSzPCRnD4 bin; render phlp bin Op.VLD4 dt OD.OprListMem
  | 0b10010u ->
    let dt = getDT64 (extract bin 7 6) |> oneDt
    chkPCRnDregs bin; render phlp bin Op.VLD1 dt OD.OprListMem
  | 0b10011u ->
    let dt = getDT64 (extract bin 7 6) |> oneDt
    chkPCRnD2regs bin; render phlp bin Op.VLD2 dt OD.OprListMem
  | 0b10100u | 0b10101u (* 1010x *) ->
    let dt = getDT64 (extract bin 7 6) |> oneDt
    chkPCRnD3 bin; render phlp bin Op.VLD3 dt OD.OprListMem
  | 0b01011u | 0b11011u (* x1011 *) -> raise ParsingFailureException
  | 0b10110u ->
    let dt = getDT64 (extract bin 7 6) |> oneDt
    chkAlign1PCRnDregs bin 3u
    render phlp bin Op.VLD1 dt OD.OprListMem
  | 0b10111u ->
    let dt = getDT64 (extract bin 7 6) |> oneDt
    chkAlign1PCRnDregs bin 1u
    render phlp bin Op.VLD1 dt OD.OprListMem
  | 0b01100u | 0b01101u | 0b01110u | 0b01111u | 0b11100u | 0b11101u | 0b11110u
  | 0b11111u (* x11xx *) -> raise ParsingFailureException
  | 0b11000u | 0b11001u (* 1100x *) ->
    let dt = getDT64 (extract bin 7 6) |> oneDt
    chkAlignPCRnD2regs bin; render phlp bin Op.VLD2 dt OD.OprListMem
  | 0b11010u ->
    let dt = getDT64 (extract bin 7 6) |> oneDt
    chkAlignPCRnDregs bin; render phlp bin Op.VLD1 dt OD.OprListMem
  | _ -> raise ParsingFailureException

/// Advanced SIMD load single structure to all lanes on page F4-4276.
let parseAdvSIMDLdSingleStructAllLanes (phlp: ParsingHelper) bin =
  let decodeField = (* L:N:a *)
    (pickBit bin 21 <<< 3) + (extract bin 9 8 <<< 1) +
    (pickBit bin 4)
  match decodeField with
  | b when b &&& 0b1000u = 0b0000u (* 0xxx *) -> raise ParsingFailureException
  | 0b1000u | 0b1001u (* 100x *) ->
    let dt = getDT64 (extract bin 7 6) |> oneDt
    chkSzAPCRnDregs bin; render phlp bin Op.VLD1 dt OD.OprListMem1
  | 0b1010u | 0b1011u (* 101x *) ->
    let dt = getDT64 (extract bin 7 6) |> oneDt
    chkSzPCRnD2 bin; render phlp bin Op.VLD2 dt OD.OprListMem2
  | 0b1100u ->
    let dt = getDT64 (extract bin 7 6) |> oneDt
    chkSzAPCRnD3 bin; render phlp bin Op.VLD3 dt OD.OprListMem3
  | 0b1101u -> raise ParsingFailureException
  | _ (* 111x *) ->
    let dt = getDT32 (extract bin 7 6) |> oneDt
    chkSzAPCRnD4 bin; render phlp bin Op.VLD4 dt OD.OprListMem4

/// Advanced SIMD load/store single structure to one lane on page F4-4276.
let parseAdvSIMDLdStSingleStructOneLane (phlp: ParsingHelper) bin =
  match concat (pickBit bin 21) (extract bin 11 8) 4 (* L:size:N *) with
  | 0b00000u ->
    chkSzIdx0PCRn bin
    render phlp bin Op.VST1 (oneDt SIMDTyp8) OD.OprListMemA
  | 0b00001u ->
    chkPCRnD2 bin
    render phlp bin Op.VST2 (oneDt SIMDTyp8) OD.OprListMemB
  | 0b00010u ->
    chkIdx0PCRnD3 bin
    render phlp bin Op.VST3 (oneDt SIMDTyp8) OD.OprListMemC
  | 0b00011u ->
    chkPCRnD4 bin
    render phlp bin Op.VST4 (oneDt SIMDTyp8) OD.OprListMemD
  | 0b00100u ->
    chkSzIdx1PCRn bin
    render phlp bin Op.VST1 (oneDt SIMDTyp16) OD.OprListMemA
  | 0b00101u ->
    chkPCRnD2 bin
    render phlp bin Op.VST2 (oneDt SIMDTyp16) OD.OprListMemB
  | 0b00110u ->
    chkIdx0PCRnD3 bin
    render phlp bin Op.VST3 (oneDt SIMDTyp16) OD.OprListMemC
  | 0b00111u ->
    chkPCRnD4 bin
    render phlp bin Op.VST4 (oneDt SIMDTyp16) OD.OprListMemD
  | 0b01000u ->
    chkSzIdx2PCRn bin
    render phlp bin Op.VST1 (oneDt SIMDTyp32) OD.OprListMemA
  | 0b01001u ->
    chkIdxPCRnD2 bin
    render phlp bin Op.VST2 (oneDt SIMDTyp32) OD.OprListMemB
  | 0b01010u ->
    chkIdx10PCRnD3 bin
    render phlp bin Op.VST3 (oneDt SIMDTyp32) OD.OprListMemC
  | 0b01011u ->
    chkIdxPCRnD4 bin
    render phlp bin Op.VST4 (oneDt SIMDTyp32) OD.OprListMemD
  | 0b10000u ->
    chkSzIdx0PCRn bin
    render phlp bin Op.VLD1 (oneDt SIMDTyp8) OD.OprListMemA
  | 0b10001u ->
    chkPCRnD2 bin
    render phlp bin Op.VLD2 (oneDt SIMDTyp8) OD.OprListMemB
  | 0b10010u ->
    chkIdx0PCRnD3 bin
    render phlp bin Op.VLD3 (oneDt SIMDTyp8) OD.OprListMemC
  | 0b10011u ->
    chkPCRnD4 bin
    render phlp bin Op.VLD4 (oneDt SIMDTyp8) OD.OprListMemD
  | 0b10100u ->
    chkSzIdx1PCRn bin
    render phlp bin Op.VLD1 (oneDt SIMDTyp16) OD.OprListMemA
  | 0b10101u ->
    chkPCRnD2 bin
    render phlp bin Op.VLD2 (oneDt SIMDTyp16) OD.OprListMemB
  | 0b10110u ->
    chkIdx0PCRnD3 bin
    render phlp bin Op.VLD3 (oneDt SIMDTyp16) OD.OprListMemC
  | 0b10111u ->
    chkPCRnD4 bin
    render phlp bin Op.VLD4 (oneDt SIMDTyp16) OD.OprListMemD
  | 0b11000u ->
    chkSzIdx2PCRn bin
    render phlp bin Op.VLD1 (oneDt SIMDTyp32) OD.OprListMemA
  | 0b11001u ->
    chkIdxPCRnD2 bin
    render phlp bin Op.VLD2 (oneDt SIMDTyp32) OD.OprListMemB
  | 0b11010u ->
    chkIdx10PCRnD3 bin
    render phlp bin Op.VLD3 (oneDt SIMDTyp32) OD.OprListMemC
  | 0b11011u ->
    chkIdxPCRnD4 bin
    render phlp bin Op.VLD4 (oneDt SIMDTyp32) OD.OprListMemD
  | _ -> raise ParsingFailureException

/// Advanced SIMD element or structure load/store on page F4-4274.
let parseAdvSIMDElemOrStructLdSt (phlp: ParsingHelper) bin =
  match concat (pickBit bin 23) (extract bin 11 10) 2 (* op0:op1 *) with
  | 0b000u | 0b001u | 0b010u | 0b011u (* 0xx *) ->
    parseAdvSIMDLdStMulStruct phlp bin
  | 0b111u -> parseAdvSIMDLdSingleStructAllLanes phlp bin
  | _ (* 1 !=11 *) -> parseAdvSIMDLdStSingleStructOneLane phlp bin

/// Unconditional instructions on page F4-4261.
let parseUncondInstr (phlp: ParsingHelper) bin =
  match concat (extract bin 26 25) (pickBit bin 20) 1 (* op0:op1 *) with
  | 0b000u | 0b001u -> parseUncondMiscellaneous phlp bin
  | 0b010u | 0b011u -> parseAdvSIMDDataProc phlp bin
  | 0b101u | 0b111u -> parseMemoryHintsAndBarriers phlp bin
  | 0b100u -> parseAdvSIMDElemOrStructLdSt phlp bin
  | _ (* 0b110u *) -> raise ParsingFailureException

/// Parse ARMv8 (AARCH32) and ARMv7 ARM mode instructions. The code is based on
/// ARM Architecture Reference Manual ARMv8-A, ARM DDI 0487F.c ID072120 A32
/// instruction set encoding on page F4-4218.
let parse (phlp: ParsingHelper) bin =
  let cond = extract bin 31 28 |> byte |> parseCond
  phlp.Cond <- cond
  match extract bin 27 26 (* op0<2:1> *) with
  | 0b00u when cond <> Condition.UN -> parseCase00 phlp bin
  | 0b01u when cond <> Condition.UN -> parseCase01 phlp bin
  | 0b10u -> parseCase10 phlp bin
  | 0b11u -> parseCase11 phlp bin
  | _ (* 0b0xu *) -> parseUncondInstr phlp bin

// vim: set tw=80 sts=2 sw=2:
