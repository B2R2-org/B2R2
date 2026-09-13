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
/// Chooses the lifter that each CIL opcode is translated by.
module internal B2R2.FrontEnd.CIL.Lifter

open B2R2.FrontEnd.CIL.GeneralLifter
open B2R2.FrontEnd.CIL.ObjectLifter

/// Translates a CIL instruction into its LowUIR statements.
let translate (ins: Instruction) bld =
  match ins.Opcode with
  | Nop -> nop ins bld
  | Break -> breakpoint ins bld
  (* The constants. *)
  | Ldc_I4_M1 -> ldcI4N ins bld -1
  | Ldc_I4_0 -> ldcI4N ins bld 0
  | Ldc_I4_1 -> ldcI4N ins bld 1
  | Ldc_I4_2 -> ldcI4N ins bld 2
  | Ldc_I4_3 -> ldcI4N ins bld 3
  | Ldc_I4_4 -> ldcI4N ins bld 4
  | Ldc_I4_5 -> ldcI4N ins bld 5
  | Ldc_I4_6 -> ldcI4N ins bld 6
  | Ldc_I4_7 -> ldcI4N ins bld 7
  | Ldc_I4_8 -> ldcI4N ins bld 8
  | Ldc_I4_S | Ldc_I4 -> ldcI4 ins bld
  | Ldc_I8 -> ldcI8 ins bld
  | Ldc_R4 -> ldcR4 ins bld
  | Ldc_R8 -> ldcR8 ins bld
  | Ldnull -> ldnull ins bld
  (* The arguments and the local variables. *)
  | Ldarg_0 -> ldargN ins bld 0
  | Ldarg_1 -> ldargN ins bld 1
  | Ldarg_2 -> ldargN ins bld 2
  | Ldarg_3 -> ldargN ins bld 3
  | Ldarg_S | Ldarg -> ldarg ins bld
  | Ldarga_S | Ldarga -> ldarga ins bld
  | Starg_S | Starg -> starg ins bld
  | Ldloc_0 -> ldlocN ins bld 0
  | Ldloc_1 -> ldlocN ins bld 1
  | Ldloc_2 -> ldlocN ins bld 2
  | Ldloc_3 -> ldlocN ins bld 3
  | Ldloc_S | Ldloc -> ldloc ins bld
  | Ldloca_S | Ldloca -> ldloca ins bld
  | Stloc_0 -> stlocN ins bld 0
  | Stloc_1 -> stlocN ins bld 1
  | Stloc_2 -> stlocN ins bld 2
  | Stloc_3 -> stlocN ins bld 3
  | Stloc_S | Stloc -> stloc ins bld
  | Dup -> dup ins bld
  | Pop -> pop ins bld
  (* The arithmetic. *)
  | Add -> add ins bld
  | Sub -> sub ins bld
  | Mul -> mul ins bld
  | Div -> div ins bld
  | Div_Un -> divUn ins bld
  | Rem -> rem ins bld
  | Rem_Un -> remUn ins bld
  | And -> logicAnd ins bld
  | Or -> logicOr ins bld
  | Xor -> logicXor ins bld
  | Shl -> shl ins bld
  | Shr -> shr ins bld
  | Shr_Un -> shrUn ins bld
  | Neg -> neg ins bld
  | Not -> logicNot ins bld
  | Add_Ovf -> addOvf ins bld
  | Add_Ovf_Un -> addOvfUn ins bld
  | Sub_Ovf -> subOvf ins bld
  | Sub_Ovf_Un -> subOvfUn ins bld
  | Mul_Ovf -> mulOvf ins bld
  | Mul_Ovf_Un -> mulOvfUn ins bld
  | Ckfinite -> ckfinite ins bld
  (* The conversions. *)
  | Conv_I1 -> convI1 ins bld
  | Conv_I2 -> convI2 ins bld
  | Conv_I4 -> convI4 ins bld
  | Conv_I8 -> convI8 ins bld
  | Conv_U1 -> convU1 ins bld
  | Conv_U2 -> convU2 ins bld
  | Conv_U4 -> convU4 ins bld
  | Conv_U8 -> convU8 ins bld
  | Conv_I -> convI ins bld
  | Conv_U -> convU ins bld
  | Conv_R4 -> convR4 ins bld
  | Conv_R8 -> convR8 ins bld
  | Conv_R_Un -> convRUn ins bld
  | Conv_Ovf_I1 -> convOvfI1 ins bld
  | Conv_Ovf_U1 -> convOvfU1 ins bld
  | Conv_Ovf_I2 -> convOvfI2 ins bld
  | Conv_Ovf_U2 -> convOvfU2 ins bld
  | Conv_Ovf_I4 -> convOvfI4 ins bld
  | Conv_Ovf_U4 -> convOvfU4 ins bld
  | Conv_Ovf_I8 -> convOvfI8 ins bld
  | Conv_Ovf_U8 -> convOvfU8 ins bld
  | Conv_Ovf_I -> convOvfI ins bld
  | Conv_Ovf_U -> convOvfU ins bld
  | Conv_Ovf_I1_Un -> convOvfI1Un ins bld
  | Conv_Ovf_U1_Un -> convOvfU1Un ins bld
  | Conv_Ovf_I2_Un -> convOvfI2Un ins bld
  | Conv_Ovf_U2_Un -> convOvfU2Un ins bld
  | Conv_Ovf_I4_Un -> convOvfI4Un ins bld
  | Conv_Ovf_U4_Un -> convOvfU4Un ins bld
  | Conv_Ovf_I8_Un -> convOvfI8Un ins bld
  | Conv_Ovf_U8_Un -> convOvfU8Un ins bld
  | Conv_Ovf_I_Un -> convOvfIUn ins bld
  | Conv_Ovf_U_Un -> convOvfUUn ins bld
  (* The comparisons and the branches. *)
  | Ceq -> ceq ins bld
  | Cgt -> cgt ins bld
  | Cgt_Un -> cgtUn ins bld
  | Clt -> clt ins bld
  | Clt_Un -> cltUn ins bld
  | Br_S | Br -> br ins bld
  | Brtrue_S | Brtrue -> brtrue ins bld
  | Brfalse_S | Brfalse -> brfalse ins bld
  | Beq_S | Beq -> beq ins bld
  | Bge_S | Bge -> bge ins bld
  | Bgt_S | Bgt -> bgt ins bld
  | Ble_S | Ble -> ble ins bld
  | Blt_S | Blt -> blt ins bld
  | Bne_Un_S | Bne_Un -> bneUn ins bld
  | Bge_Un_S | Bge_Un -> bgeUn ins bld
  | Bgt_Un_S | Bgt_Un -> bgtUn ins bld
  | Ble_Un_S | Ble_Un -> bleUn ins bld
  | Blt_Un_S | Blt_Un -> bltUn ins bld
  | Switch -> switch ins bld
  (* The loads and stores through a pointer, and the blocks. *)
  | Ldind_I1 -> ldindI1 ins bld
  | Ldind_U1 -> ldindU1 ins bld
  | Ldind_I2 -> ldindI2 ins bld
  | Ldind_U2 -> ldindU2 ins bld
  | Ldind_I4 | Ldind_U4 -> ldindI4 ins bld
  | Ldind_I8 -> ldindI8 ins bld
  | Ldind_I -> ldindI ins bld
  | Ldind_R4 -> ldindR4 ins bld
  | Ldind_R8 -> ldindR8 ins bld
  | Ldind_Ref -> ldindRef ins bld
  | Stind_I1 -> stindI1 ins bld
  | Stind_I2 -> stindI2 ins bld
  | Stind_I4 -> stindI4 ins bld
  | Stind_I8 -> stindI8 ins bld
  | Stind_I -> stindI ins bld
  | Stind_R4 -> stindR4 ins bld
  | Stind_R8 -> stindR8 ins bld
  | Stind_Ref -> stindRef ins bld
  | Cpblk -> cpblk ins bld
  | Initblk -> initblk ins bld
  | Localloc -> localloc ins bld
  (* The arrays whose element type is in the opcode. *)
  | Ldlen -> ldlen ins bld
  | Ldelem_I1 -> ldelemI1 ins bld
  | Ldelem_U1 -> ldelemU1 ins bld
  | Ldelem_I2 -> ldelemI2 ins bld
  | Ldelem_U2 -> ldelemU2 ins bld
  | Ldelem_I4 | Ldelem_U4 -> ldelemI4 ins bld
  | Ldelem_I8 -> ldelemI8 ins bld
  | Ldelem_I -> ldelemI ins bld
  | Ldelem_R4 -> ldelemR4 ins bld
  | Ldelem_R8 -> ldelemR8 ins bld
  | Ldelem_Ref -> ldelemRef ins bld
  | Stelem_I1 -> stelemI1 ins bld
  | Stelem_I2 -> stelemI2 ins bld
  | Stelem_I4 -> stelemI4 ins bld
  | Stelem_I8 -> stelemI8 ins bld
  | Stelem_I -> stelemI ins bld
  | Stelem_R4 -> stelemR4 ins bld
  | Stelem_R8 -> stelemR8 ins bld
  | Stelem_Ref -> stelemRef ins bld
  (* The calls, the return, and the exceptions. *)
  | Call -> call ins bld "call"
  | Callvirt -> call ins bld "callvirt"
  | Calli -> call ins bld "calli"
  | Newobj -> call ins bld "newobj"
  | Jmp -> jmp ins bld
  | Ret -> ret ins bld
  | Throw -> throw ins bld "throw"
  | Rethrow -> throw ins bld "rethrow"
  | Leave_S | Leave -> leave ins bld
  | Endfinally -> endHandler ins bld "endfinally"
  | Endfilter -> endHandler ins bld "endfilter"
  (* The instructions naming a field, a type, a method or a string by a token,
     which the runtime holding the metadata carries out. *)
  | Ldfld -> runtime ins bld "ldfld"
  | Ldflda -> runtime ins bld "ldflda"
  | Stfld -> runtime ins bld "stfld"
  | Ldsfld -> runtime ins bld "ldsfld"
  | Ldsflda -> runtime ins bld "ldsflda"
  | Stsfld -> runtime ins bld "stsfld"
  | Ldstr -> runtime ins bld "ldstr"
  | Ldtoken -> runtime ins bld "ldtoken"
  | Ldftn -> runtime ins bld "ldftn"
  | Ldvirtftn -> runtime ins bld "ldvirtftn"
  | Castclass -> runtime ins bld "castclass"
  | Isinst -> runtime ins bld "isinst"
  | Box -> runtime ins bld "box"
  | Unbox -> runtime ins bld "unbox"
  | Unbox_Any -> runtime ins bld "unbox.any"
  | Newarr -> runtime ins bld "newarr"
  | Ldelema -> runtime ins bld "ldelema"
  | Ldelem -> runtime ins bld "ldelem"
  | Stelem -> runtime ins bld "stelem"
  | Ldobj -> runtime ins bld "ldobj"
  | Stobj -> runtime ins bld "stobj"
  | Cpobj -> runtime ins bld "cpobj"
  | Initobj -> runtime ins bld "initobj"
  | Sizeof -> runtime ins bld "sizeof"
  | Mkrefany -> runtime ins bld "mkrefany"
  | Refanyval -> runtime ins bld "refanyval"
  | Refanytype -> runtime ins bld "refanytype"
  | Arglist -> runtime ins bld "arglist"
  (* The prefixes. The two that change what the instruction after them does to
     the runtime's state are told to it; the rest promise something about an
     access this model needs no promise of. *)
  | Constrained -> runtime ins bld "constrained."
  | Tail -> runtime ins bld "tail."
  | Unaligned | Volatile | Readonly | No -> nop ins bld

// vim: set tw=80 sts=2 sw=2:
