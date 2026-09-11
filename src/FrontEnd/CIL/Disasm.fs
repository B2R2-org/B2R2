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

module internal B2R2.FrontEnd.CIL.Disasm

open System.Globalization
open B2R2
open B2R2.FrontEnd.BinLifter

let opcodeToString = function
  | Nop -> "nop"
  | Break -> "break"
  | Ldarg_0 -> "ldarg.0"
  | Ldarg_1 -> "ldarg.1"
  | Ldarg_2 -> "ldarg.2"
  | Ldarg_3 -> "ldarg.3"
  | Ldloc_0 -> "ldloc.0"
  | Ldloc_1 -> "ldloc.1"
  | Ldloc_2 -> "ldloc.2"
  | Ldloc_3 -> "ldloc.3"
  | Stloc_0 -> "stloc.0"
  | Stloc_1 -> "stloc.1"
  | Stloc_2 -> "stloc.2"
  | Stloc_3 -> "stloc.3"
  | Ldarg_S -> "ldarg.s"
  | Ldarga_S -> "ldarga.s"
  | Starg_S -> "starg.s"
  | Ldloc_S -> "ldloc.s"
  | Ldloca_S -> "ldloca.s"
  | Stloc_S -> "stloc.s"
  | Ldnull -> "ldnull"
  | Ldc_I4_M1 -> "ldc.i4.m1"
  | Ldc_I4_0 -> "ldc.i4.0"
  | Ldc_I4_1 -> "ldc.i4.1"
  | Ldc_I4_2 -> "ldc.i4.2"
  | Ldc_I4_3 -> "ldc.i4.3"
  | Ldc_I4_4 -> "ldc.i4.4"
  | Ldc_I4_5 -> "ldc.i4.5"
  | Ldc_I4_6 -> "ldc.i4.6"
  | Ldc_I4_7 -> "ldc.i4.7"
  | Ldc_I4_8 -> "ldc.i4.8"
  | Ldc_I4_S -> "ldc.i4.s"
  | Ldc_I4 -> "ldc.i4"
  | Ldc_I8 -> "ldc.i8"
  | Ldc_R4 -> "ldc.r4"
  | Ldc_R8 -> "ldc.r8"
  | Dup -> "dup"
  | Pop -> "pop"
  | Jmp -> "jmp"
  | Call -> "call"
  | Calli -> "calli"
  | Ret -> "ret"
  | Br_S -> "br.s"
  | Brfalse_S -> "brfalse.s"
  | Brtrue_S -> "brtrue.s"
  | Beq_S -> "beq.s"
  | Bge_S -> "bge.s"
  | Bgt_S -> "bgt.s"
  | Ble_S -> "ble.s"
  | Blt_S -> "blt.s"
  | Bne_Un_S -> "bne.un.s"
  | Bge_Un_S -> "bge.un.s"
  | Bgt_Un_S -> "bgt.un.s"
  | Ble_Un_S -> "ble.un.s"
  | Blt_Un_S -> "blt.un.s"
  | Br -> "br"
  | Brfalse -> "brfalse"
  | Brtrue -> "brtrue"
  | Beq -> "beq"
  | Bge -> "bge"
  | Bgt -> "bgt"
  | Ble -> "ble"
  | Blt -> "blt"
  | Bne_Un -> "bne.un"
  | Bge_Un -> "bge.un"
  | Bgt_Un -> "bgt.un"
  | Ble_Un -> "ble.un"
  | Blt_Un -> "blt.un"
  | Switch -> "switch"
  | Ldind_I1 -> "ldind.i1"
  | Ldind_U1 -> "ldind.u1"
  | Ldind_I2 -> "ldind.i2"
  | Ldind_U2 -> "ldind.u2"
  | Ldind_I4 -> "ldind.i4"
  | Ldind_U4 -> "ldind.u4"
  | Ldind_I8 -> "ldind.i8"
  | Ldind_I -> "ldind.i"
  | Ldind_R4 -> "ldind.r4"
  | Ldind_R8 -> "ldind.r8"
  | Ldind_Ref -> "ldind.ref"
  | Stind_Ref -> "stind.ref"
  | Stind_I1 -> "stind.i1"
  | Stind_I2 -> "stind.i2"
  | Stind_I4 -> "stind.i4"
  | Stind_I8 -> "stind.i8"
  | Stind_R4 -> "stind.r4"
  | Stind_R8 -> "stind.r8"
  | Add -> "add"
  | Sub -> "sub"
  | Mul -> "mul"
  | Div -> "div"
  | Div_Un -> "div.un"
  | Rem -> "rem"
  | Rem_Un -> "rem.un"
  | And -> "and"
  | Or -> "or"
  | Xor -> "xor"
  | Shl -> "shl"
  | Shr -> "shr"
  | Shr_Un -> "shr.un"
  | Neg -> "neg"
  | Not -> "not"
  | Conv_I1 -> "conv.i1"
  | Conv_I2 -> "conv.i2"
  | Conv_I4 -> "conv.i4"
  | Conv_I8 -> "conv.i8"
  | Conv_R4 -> "conv.r4"
  | Conv_R8 -> "conv.r8"
  | Conv_U4 -> "conv.u4"
  | Conv_U8 -> "conv.u8"
  | Callvirt -> "callvirt"
  | Cpobj -> "cpobj"
  | Ldobj -> "ldobj"
  | Ldstr -> "ldstr"
  | Newobj -> "newobj"
  | Castclass -> "castclass"
  | Isinst -> "isinst"
  | Conv_R_Un -> "conv.r.un"
  | Unbox -> "unbox"
  | Throw -> "throw"
  | Ldfld -> "ldfld"
  | Ldflda -> "ldflda"
  | Stfld -> "stfld"
  | Ldsfld -> "ldsfld"
  | Ldsflda -> "ldsflda"
  | Stsfld -> "stsfld"
  | Stobj -> "stobj"
  | Conv_Ovf_I1_Un -> "conv.ovf.i1.un"
  | Conv_Ovf_I2_Un -> "conv.ovf.i2.un"
  | Conv_Ovf_I4_Un -> "conv.ovf.i4.un"
  | Conv_Ovf_I8_Un -> "conv.ovf.i8.un"
  | Conv_Ovf_U1_Un -> "conv.ovf.u1.un"
  | Conv_Ovf_U2_Un -> "conv.ovf.u2.un"
  | Conv_Ovf_U4_Un -> "conv.ovf.u4.un"
  | Conv_Ovf_U8_Un -> "conv.ovf.u8.un"
  | Conv_Ovf_I_Un -> "conv.ovf.i.un"
  | Conv_Ovf_U_Un -> "conv.ovf.u.un"
  | Box -> "box"
  | Newarr -> "newarr"
  | Ldlen -> "ldlen"
  | Ldelema -> "ldelema"
  | Ldelem_I1 -> "ldelem.i1"
  | Ldelem_U1 -> "ldelem.u1"
  | Ldelem_I2 -> "ldelem.i2"
  | Ldelem_U2 -> "ldelem.u2"
  | Ldelem_I4 -> "ldelem.i4"
  | Ldelem_U4 -> "ldelem.u4"
  | Ldelem_I8 -> "ldelem.i8"
  | Ldelem_I -> "ldelem.i"
  | Ldelem_R4 -> "ldelem.r4"
  | Ldelem_R8 -> "ldelem.r8"
  | Ldelem_Ref -> "ldelem.ref"
  | Stelem_I -> "stelem.i"
  | Stelem_I1 -> "stelem.i1"
  | Stelem_I2 -> "stelem.i2"
  | Stelem_I4 -> "stelem.i4"
  | Stelem_I8 -> "stelem.i8"
  | Stelem_R4 -> "stelem.r4"
  | Stelem_R8 -> "stelem.r8"
  | Stelem_Ref -> "stelem.ref"
  | Ldelem -> "ldelem"
  | Stelem -> "stelem"
  | Unbox_Any -> "unbox.any"
  | Conv_Ovf_I1 -> "conv.ovf.i1"
  | Conv_Ovf_U1 -> "conv.ovf.u1"
  | Conv_Ovf_I2 -> "conv.ovf.i2"
  | Conv_Ovf_U2 -> "conv.ovf.u2"
  | Conv_Ovf_I4 -> "conv.ovf.i4"
  | Conv_Ovf_U4 -> "conv.ovf.u4"
  | Conv_Ovf_I8 -> "conv.ovf.i8"
  | Conv_Ovf_U8 -> "conv.ovf.u8"
  | Refanyval -> "refanyval"
  | Ckfinite -> "ckfinite"
  | Mkrefany -> "mkrefany"
  | Ldtoken -> "ldtoken"
  | Conv_U2 -> "conv.u2"
  | Conv_U1 -> "conv.u1"
  | Conv_I -> "conv.i"
  | Conv_Ovf_I -> "conv.ovf.i"
  | Conv_Ovf_U -> "conv.ovf.u"
  | Add_Ovf -> "add.ovf"
  | Add_Ovf_Un -> "add.ovf.un"
  | Mul_Ovf -> "mul.ovf"
  | Mul_Ovf_Un -> "mul.ovf.un"
  | Sub_Ovf -> "sub.ovf"
  | Sub_Ovf_Un -> "sub.ovf.un"
  | Endfinally -> "endfinally"
  | Leave -> "leave"
  | Leave_S -> "leave.s"
  | Stind_I -> "stind.i"
  | Conv_U -> "conv.u"
  | Arglist -> "arglist"
  | Ceq -> "ceq"
  | Cgt -> "cgt"
  | Cgt_Un -> "cgt.un"
  | Clt -> "clt"
  | Clt_Un -> "clt.un"
  | Ldftn -> "ldftn"
  | Ldvirtftn -> "ldvirtftn"
  | Ldarg -> "ldarg"
  | Ldarga -> "ldarga"
  | Starg -> "starg"
  | Ldloc -> "ldloc"
  | Ldloca -> "ldloca"
  | Stloc -> "stloc"
  | Localloc -> "localloc"
  | Endfilter -> "endfilter"
  | Unaligned -> "unaligned."
  | Volatile -> "volatile."
  | Tail -> "tail."
  | Initobj -> "initobj"
  | Constrained -> "constrained."
  | Cpblk -> "cpblk"
  | Initblk -> "initblk"
  | No -> "no."
  | Rethrow -> "rethrow"
  | Sizeof -> "sizeof"
  | Refanytype -> "refanytype"
  | Readonly -> "readonly."

/// Renders a floating-point constant in the shortest decimal that reads back
/// as the same value, in the culture the assembler reads it in.
let private r4ToString (v: float32) = v.ToString CultureInfo.InvariantCulture

let private r8ToString (v: float) = v.ToString CultureInfo.InvariantCulture

/// Renders a metadata token at its full width, so that the table it names,
/// which the top byte carries, reads off the text.
let private tokenToString (token: uint32) = "0x" + token.ToString "x8"

let private buildTarget target (builder: IDisasmBuilder) =
  builder.Accumulate(AsmWordKind.Value, HexString.ofUInt64 target)

/// Writes the targets of a switch in parentheses, the way ilasm has them, so
/// that a table with nothing in it still reads as a table.
let private buildTargets targets (builder: IDisasmBuilder) =
  builder.Accumulate(AsmWordKind.String, "(")
  targets
  |> List.iteri (fun i target ->
    if i > 0 then builder.Accumulate(AsmWordKind.String, ", ") else ()
    buildTarget target builder)
  builder.Accumulate(AsmWordKind.String, ")")

let private buildOperand opr (builder: IDisasmBuilder) =
  builder.Accumulate(AsmWordKind.String, " ")
  match opr with
  | OprVar idx -> builder.Accumulate(AsmWordKind.Value, string idx)
  | OprI4 v -> builder.Accumulate(AsmWordKind.Value, string v)
  | OprI8 v -> builder.Accumulate(AsmWordKind.Value, string v)
  | OprR4 v -> builder.Accumulate(AsmWordKind.Value, r4ToString v)
  | OprR8 v -> builder.Accumulate(AsmWordKind.Value, r8ToString v)
  | OprTarget target -> buildTarget target builder
  | OprTargets targets -> buildTargets targets builder
  | OprToken token -> builder.Accumulate(AsmWordKind.Value, tokenToString token)
  | OprByte b -> builder.Accumulate(AsmWordKind.Value, string b)

let disasm (ins: Instruction) (builder: IDisasmBuilder) =
  builder.AccumulateAddrMarker ins.Address
  builder.Accumulate(AsmWordKind.Mnemonic, opcodeToString ins.Opcode)
  match ins.Operands with
  | NoOperand -> ()
  | OneOperand opr -> buildOperand opr builder

// vim: set tw=80 sts=2 sw=2:
