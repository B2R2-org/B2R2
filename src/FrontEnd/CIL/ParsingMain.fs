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

module internal B2R2.FrontEnd.CIL.ParsingMain

open System
open B2R2
open B2R2.FrontEnd.BinLifter

/// The address a branch reaches. The machine counts the distance from the
/// instruction after the branch, and the sum wraps within the sixty-four bits
/// of an address, so a branch backwards from near zero comes around at the top
/// of the space rather than running past it.
let inline private targetOf (addr: Addr) (len: int) (rel: int64) =
  addr + uint64 len + uint64 rel

let private bare op len = struct (op, NoOperand, uint32 (len: int))

let private parseVar1 (span: ByteSpan) (reader: IBinReader) pos op =
  let idx = reader.ReadUInt8(span, pos)
  struct (op, OneOperand(OprVar(uint16 idx)), uint32 (pos + 1))

let private parseVar2 (span: ByteSpan) (reader: IBinReader) pos op =
  let idx = reader.ReadUInt16(span, pos)
  struct (op, OneOperand(OprVar idx), uint32 (pos + 2))

let private parseI1 (span: ByteSpan) (reader: IBinReader) pos op =
  let v = reader.ReadInt8(span, pos)
  struct (op, OneOperand(OprI4(int32 v)), uint32 (pos + 1))

let private parseI4 (span: ByteSpan) (reader: IBinReader) pos op =
  let v = reader.ReadInt32(span, pos)
  struct (op, OneOperand(OprI4 v), uint32 (pos + 4))

let private parseI8 (span: ByteSpan) (reader: IBinReader) pos op =
  let v = reader.ReadInt64(span, pos)
  struct (op, OneOperand(OprI8 v), uint32 (pos + 8))

let private parseR4 (span: ByteSpan) (reader: IBinReader) pos op =
  let v = reader.ReadUInt32(span, pos) |> BitConverter.UInt32BitsToSingle
  struct (op, OneOperand(OprR4 v), uint32 (pos + 4))

let private parseR8 (span: ByteSpan) (reader: IBinReader) pos op =
  let v = reader.ReadUInt64(span, pos) |> BitConverter.UInt64BitsToDouble
  struct (op, OneOperand(OprR8 v), uint32 (pos + 8))

let private parseTarget1 (span: ByteSpan) (reader: IBinReader) addr pos op =
  let rel = reader.ReadInt8(span, pos)
  let len = pos + 1
  struct (op, OneOperand(OprTarget(targetOf addr len (int64 rel))), uint32 len)

let private parseTarget4 (span: ByteSpan) (reader: IBinReader) addr pos op =
  let rel = reader.ReadInt32(span, pos)
  let len = pos + 4
  struct (op, OneOperand(OprTarget(targetOf addr len (int64 rel))), uint32 len)

let private parseToken (span: ByteSpan) (reader: IBinReader) pos op =
  let token = reader.ReadUInt32(span, pos)
  struct (op, OneOperand(OprToken token), uint32 (pos + 4))

let private parseByte (span: ByteSpan) (reader: IBinReader) pos op =
  let b = reader.ReadUInt8(span, pos)
  struct (op, OneOperand(OprByte b), uint32 (pos + 1))

/// Reads the table of a switch, whose every entry is a distance from the
/// instruction after the whole table.
let private readTargets (span: ByteSpan) (reader: IBinReader) addr len count =
  let targets = Array.zeroCreate count
  for i in 0 .. count - 1 do
    let rel = reader.ReadInt32(span, 5 + 4 * i)
    targets[i] <- targetOf addr len (int64 rel)
  List.ofArray targets

/// Parses a switch, which is as long as the count ahead of its table says. A
/// count the span cannot hold is refused before anything is read by it, so
/// that a run of bytes which happens to start with the opcode does not ask for
/// the whole of memory.
let private parseSwitch (span: ByteSpan) (reader: IBinReader) addr =
  let count = reader.ReadUInt32(span, 1)
  if count > uint32 ((span.Length - 5) / 4) then raise ParsingFailureException
  else ()
  let len = 5 + 4 * int count
  let targets = readTargets span reader addr len (int count)
  struct (Switch, OneOperand(OprTargets targets), uint32 len)

/// Parses the instructions behind the 0xfe prefix byte, which is where the
/// long forms of the variable instructions, the comparisons and every prefix
/// live.
let private parseTwoByte (span: ByteSpan) (reader: IBinReader) =
  match span[1] with
  | 0x00uy -> bare Arglist 2
  | 0x01uy -> bare Ceq 2
  | 0x02uy -> bare Cgt 2
  | 0x03uy -> bare Cgt_Un 2
  | 0x04uy -> bare Clt 2
  | 0x05uy -> bare Clt_Un 2
  | 0x06uy -> parseToken span reader 2 Ldftn
  | 0x07uy -> parseToken span reader 2 Ldvirtftn
  | 0x09uy -> parseVar2 span reader 2 Ldarg
  | 0x0auy -> parseVar2 span reader 2 Ldarga
  | 0x0buy -> parseVar2 span reader 2 Starg
  | 0x0cuy -> parseVar2 span reader 2 Ldloc
  | 0x0duy -> parseVar2 span reader 2 Ldloca
  | 0x0euy -> parseVar2 span reader 2 Stloc
  | 0x0fuy -> bare Localloc 2
  | 0x11uy -> bare Endfilter 2
  | 0x12uy -> parseByte span reader 2 Unaligned
  | 0x13uy -> bare Volatile 2
  | 0x14uy -> bare Tail 2
  | 0x15uy -> parseToken span reader 2 Initobj
  | 0x16uy -> parseToken span reader 2 Constrained
  | 0x17uy -> bare Cpblk 2
  | 0x18uy -> bare Initblk 2
  | 0x19uy -> parseByte span reader 2 No
  | 0x1auy -> bare Rethrow 2
  | 0x1cuy -> parseToken span reader 2 Sizeof
  | 0x1duy -> bare Refanytype 2
  | 0x1euy -> bare Readonly 2
  | _ -> raise ParsingFailureException

let private parseInstruction (span: ByteSpan) (reader: IBinReader) addr =
  match span[0] with
  | 0x00uy -> bare Nop 1
  | 0x01uy -> bare Break 1
  | 0x02uy -> bare Ldarg_0 1
  | 0x03uy -> bare Ldarg_1 1
  | 0x04uy -> bare Ldarg_2 1
  | 0x05uy -> bare Ldarg_3 1
  | 0x06uy -> bare Ldloc_0 1
  | 0x07uy -> bare Ldloc_1 1
  | 0x08uy -> bare Ldloc_2 1
  | 0x09uy -> bare Ldloc_3 1
  | 0x0auy -> bare Stloc_0 1
  | 0x0buy -> bare Stloc_1 1
  | 0x0cuy -> bare Stloc_2 1
  | 0x0duy -> bare Stloc_3 1
  | 0x0euy -> parseVar1 span reader 1 Ldarg_S
  | 0x0fuy -> parseVar1 span reader 1 Ldarga_S
  | 0x10uy -> parseVar1 span reader 1 Starg_S
  | 0x11uy -> parseVar1 span reader 1 Ldloc_S
  | 0x12uy -> parseVar1 span reader 1 Ldloca_S
  | 0x13uy -> parseVar1 span reader 1 Stloc_S
  | 0x14uy -> bare Ldnull 1
  | 0x15uy -> bare Ldc_I4_M1 1
  | 0x16uy -> bare Ldc_I4_0 1
  | 0x17uy -> bare Ldc_I4_1 1
  | 0x18uy -> bare Ldc_I4_2 1
  | 0x19uy -> bare Ldc_I4_3 1
  | 0x1auy -> bare Ldc_I4_4 1
  | 0x1buy -> bare Ldc_I4_5 1
  | 0x1cuy -> bare Ldc_I4_6 1
  | 0x1duy -> bare Ldc_I4_7 1
  | 0x1euy -> bare Ldc_I4_8 1
  | 0x1fuy -> parseI1 span reader 1 Ldc_I4_S
  | 0x20uy -> parseI4 span reader 1 Ldc_I4
  | 0x21uy -> parseI8 span reader 1 Ldc_I8
  | 0x22uy -> parseR4 span reader 1 Ldc_R4
  | 0x23uy -> parseR8 span reader 1 Ldc_R8
  | 0x25uy -> bare Dup 1
  | 0x26uy -> bare Pop 1
  | 0x27uy -> parseToken span reader 1 Jmp
  | 0x28uy -> parseToken span reader 1 Call
  | 0x29uy -> parseToken span reader 1 Calli
  | 0x2auy -> bare Ret 1
  | 0x2buy -> parseTarget1 span reader addr 1 Br_S
  | 0x2cuy -> parseTarget1 span reader addr 1 Brfalse_S
  | 0x2duy -> parseTarget1 span reader addr 1 Brtrue_S
  | 0x2euy -> parseTarget1 span reader addr 1 Beq_S
  | 0x2fuy -> parseTarget1 span reader addr 1 Bge_S
  | 0x30uy -> parseTarget1 span reader addr 1 Bgt_S
  | 0x31uy -> parseTarget1 span reader addr 1 Ble_S
  | 0x32uy -> parseTarget1 span reader addr 1 Blt_S
  | 0x33uy -> parseTarget1 span reader addr 1 Bne_Un_S
  | 0x34uy -> parseTarget1 span reader addr 1 Bge_Un_S
  | 0x35uy -> parseTarget1 span reader addr 1 Bgt_Un_S
  | 0x36uy -> parseTarget1 span reader addr 1 Ble_Un_S
  | 0x37uy -> parseTarget1 span reader addr 1 Blt_Un_S
  | 0x38uy -> parseTarget4 span reader addr 1 Br
  | 0x39uy -> parseTarget4 span reader addr 1 Brfalse
  | 0x3auy -> parseTarget4 span reader addr 1 Brtrue
  | 0x3buy -> parseTarget4 span reader addr 1 Beq
  | 0x3cuy -> parseTarget4 span reader addr 1 Bge
  | 0x3duy -> parseTarget4 span reader addr 1 Bgt
  | 0x3euy -> parseTarget4 span reader addr 1 Ble
  | 0x3fuy -> parseTarget4 span reader addr 1 Blt
  | 0x40uy -> parseTarget4 span reader addr 1 Bne_Un
  | 0x41uy -> parseTarget4 span reader addr 1 Bge_Un
  | 0x42uy -> parseTarget4 span reader addr 1 Bgt_Un
  | 0x43uy -> parseTarget4 span reader addr 1 Ble_Un
  | 0x44uy -> parseTarget4 span reader addr 1 Blt_Un
  | 0x45uy -> parseSwitch span reader addr
  | 0x46uy -> bare Ldind_I1 1
  | 0x47uy -> bare Ldind_U1 1
  | 0x48uy -> bare Ldind_I2 1
  | 0x49uy -> bare Ldind_U2 1
  | 0x4auy -> bare Ldind_I4 1
  | 0x4buy -> bare Ldind_U4 1
  | 0x4cuy -> bare Ldind_I8 1
  | 0x4duy -> bare Ldind_I 1
  | 0x4euy -> bare Ldind_R4 1
  | 0x4fuy -> bare Ldind_R8 1
  | 0x50uy -> bare Ldind_Ref 1
  | 0x51uy -> bare Stind_Ref 1
  | 0x52uy -> bare Stind_I1 1
  | 0x53uy -> bare Stind_I2 1
  | 0x54uy -> bare Stind_I4 1
  | 0x55uy -> bare Stind_I8 1
  | 0x56uy -> bare Stind_R4 1
  | 0x57uy -> bare Stind_R8 1
  | 0x58uy -> bare Add 1
  | 0x59uy -> bare Sub 1
  | 0x5auy -> bare Mul 1
  | 0x5buy -> bare Div 1
  | 0x5cuy -> bare Div_Un 1
  | 0x5duy -> bare Rem 1
  | 0x5euy -> bare Rem_Un 1
  | 0x5fuy -> bare And 1
  | 0x60uy -> bare Or 1
  | 0x61uy -> bare Xor 1
  | 0x62uy -> bare Shl 1
  | 0x63uy -> bare Shr 1
  | 0x64uy -> bare Shr_Un 1
  | 0x65uy -> bare Neg 1
  | 0x66uy -> bare Not 1
  | 0x67uy -> bare Conv_I1 1
  | 0x68uy -> bare Conv_I2 1
  | 0x69uy -> bare Conv_I4 1
  | 0x6auy -> bare Conv_I8 1
  | 0x6buy -> bare Conv_R4 1
  | 0x6cuy -> bare Conv_R8 1
  | 0x6duy -> bare Conv_U4 1
  | 0x6euy -> bare Conv_U8 1
  | 0x6fuy -> parseToken span reader 1 Callvirt
  | 0x70uy -> parseToken span reader 1 Cpobj
  | 0x71uy -> parseToken span reader 1 Ldobj
  | 0x72uy -> parseToken span reader 1 Ldstr
  | 0x73uy -> parseToken span reader 1 Newobj
  | 0x74uy -> parseToken span reader 1 Castclass
  | 0x75uy -> parseToken span reader 1 Isinst
  | 0x76uy -> bare Conv_R_Un 1
  | 0x79uy -> parseToken span reader 1 Unbox
  | 0x7auy -> bare Throw 1
  | 0x7buy -> parseToken span reader 1 Ldfld
  | 0x7cuy -> parseToken span reader 1 Ldflda
  | 0x7duy -> parseToken span reader 1 Stfld
  | 0x7euy -> parseToken span reader 1 Ldsfld
  | 0x7fuy -> parseToken span reader 1 Ldsflda
  | 0x80uy -> parseToken span reader 1 Stsfld
  | 0x81uy -> parseToken span reader 1 Stobj
  | 0x82uy -> bare Conv_Ovf_I1_Un 1
  | 0x83uy -> bare Conv_Ovf_I2_Un 1
  | 0x84uy -> bare Conv_Ovf_I4_Un 1
  | 0x85uy -> bare Conv_Ovf_I8_Un 1
  | 0x86uy -> bare Conv_Ovf_U1_Un 1
  | 0x87uy -> bare Conv_Ovf_U2_Un 1
  | 0x88uy -> bare Conv_Ovf_U4_Un 1
  | 0x89uy -> bare Conv_Ovf_U8_Un 1
  | 0x8auy -> bare Conv_Ovf_I_Un 1
  | 0x8buy -> bare Conv_Ovf_U_Un 1
  | 0x8cuy -> parseToken span reader 1 Box
  | 0x8duy -> parseToken span reader 1 Newarr
  | 0x8euy -> bare Ldlen 1
  | 0x8fuy -> parseToken span reader 1 Ldelema
  | 0x90uy -> bare Ldelem_I1 1
  | 0x91uy -> bare Ldelem_U1 1
  | 0x92uy -> bare Ldelem_I2 1
  | 0x93uy -> bare Ldelem_U2 1
  | 0x94uy -> bare Ldelem_I4 1
  | 0x95uy -> bare Ldelem_U4 1
  | 0x96uy -> bare Ldelem_I8 1
  | 0x97uy -> bare Ldelem_I 1
  | 0x98uy -> bare Ldelem_R4 1
  | 0x99uy -> bare Ldelem_R8 1
  | 0x9auy -> bare Ldelem_Ref 1
  | 0x9buy -> bare Stelem_I 1
  | 0x9cuy -> bare Stelem_I1 1
  | 0x9duy -> bare Stelem_I2 1
  | 0x9euy -> bare Stelem_I4 1
  | 0x9fuy -> bare Stelem_I8 1
  | 0xa0uy -> bare Stelem_R4 1
  | 0xa1uy -> bare Stelem_R8 1
  | 0xa2uy -> bare Stelem_Ref 1
  | 0xa3uy -> parseToken span reader 1 Ldelem
  | 0xa4uy -> parseToken span reader 1 Stelem
  | 0xa5uy -> parseToken span reader 1 Unbox_Any
  | 0xb3uy -> bare Conv_Ovf_I1 1
  | 0xb4uy -> bare Conv_Ovf_U1 1
  | 0xb5uy -> bare Conv_Ovf_I2 1
  | 0xb6uy -> bare Conv_Ovf_U2 1
  | 0xb7uy -> bare Conv_Ovf_I4 1
  | 0xb8uy -> bare Conv_Ovf_U4 1
  | 0xb9uy -> bare Conv_Ovf_I8 1
  | 0xbauy -> bare Conv_Ovf_U8 1
  | 0xc2uy -> parseToken span reader 1 Refanyval
  | 0xc3uy -> bare Ckfinite 1
  | 0xc6uy -> parseToken span reader 1 Mkrefany
  | 0xd0uy -> parseToken span reader 1 Ldtoken
  | 0xd1uy -> bare Conv_U2 1
  | 0xd2uy -> bare Conv_U1 1
  | 0xd3uy -> bare Conv_I 1
  | 0xd4uy -> bare Conv_Ovf_I 1
  | 0xd5uy -> bare Conv_Ovf_U 1
  | 0xd6uy -> bare Add_Ovf 1
  | 0xd7uy -> bare Add_Ovf_Un 1
  | 0xd8uy -> bare Mul_Ovf 1
  | 0xd9uy -> bare Mul_Ovf_Un 1
  | 0xdauy -> bare Sub_Ovf 1
  | 0xdbuy -> bare Sub_Ovf_Un 1
  | 0xdcuy -> bare Endfinally 1
  | 0xdduy -> parseTarget4 span reader addr 1 Leave
  | 0xdeuy -> parseTarget1 span reader addr 1 Leave_S
  | 0xdfuy -> bare Stind_I 1
  | 0xe0uy -> bare Conv_U 1
  | 0xfeuy -> parseTwoByte span reader
  | _ -> raise ParsingFailureException

let parse lifter (span: ByteSpan) (reader: IBinReader) addr =
  let struct (opcode, operands, len) = parseInstruction span reader addr
  Instruction(addr, len, opcode, operands, lifter)

// vim: set tw=80 sts=2 sw=2:
