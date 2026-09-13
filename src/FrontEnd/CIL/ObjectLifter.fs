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
/// Translates the CIL instructions that reach beyond the evaluation stack: the
/// arrays, the calls and the return, the exceptions, and the instructions that
/// name a method, a field, a type or a string by a metadata token.
///
/// A token names something in the metadata of the assembly the instruction
/// came from, which no instruction carries with it, and a call moves between
/// methods, whose frames no expression here can name. So these instructions
/// are named to the runtime as external calls, the mnemonic as the name and
/// the token as the argument, and the runtime performs the stack effect as
/// well as the operation -- what a field load pushes is a function of the
/// field's type, which only the metadata says. The array instructions whose
/// element type is in the opcode are the exception: given the layout an array
/// is allocated with, they are spelled out here in full.
module internal B2R2.FrontEnd.CIL.ObjectLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.CIL.LiftHelper

/// The arguments an instruction hands the runtime: the token it carries, if
/// any.
let private tokenArgs (ins: Instruction) =
  match ins.Operands with
  | OneOperand(OprToken t) -> [ numU64 (uint64 t) 64<rt> ]
  | _ -> []

/// An instruction the runtime carries out, named by its mnemonic and given the
/// token it carries. The runtime performs the stack effect.
let runtime (ins: Instruction) bld name =
  lift bld ins { AST.extCall (AST.app name (tokenArgs ins) 64<rt>) }

/// <summary>
/// call, callvirt, calli and newobj: the runtime is handed the token and the
/// address to come back to, and moves to the method named, which no address
/// here can name. The inter-jump after it is what CFG recovery sees a call
/// edge in; the runtime, having moved the program counter itself, never
/// reaches it.
/// </summary>
let call (ins: Instruction) bld name =
  lift bld ins {
    let args = tokenArgs ins @ [ numU64 (nextAddr ins) 64<rt> ]
    AST.extCall (AST.app name args 64<rt>)
    AST.interjmp (AST.undef 64<rt> "CIL_CALL_TARGET") InterJmpKind.IsCall
    return NoEndMark
  }

/// jmp: the arguments are handed on to the method named and this one is left
/// for good.
let jmp (ins: Instruction) bld =
  lift bld ins {
    AST.extCall (AST.app "jmp" (tokenArgs ins) 64<rt>)
    AST.interjmp (AST.undef 64<rt> "CIL_JMP_TARGET") InterJmpKind.Base
    return NoEndMark
  }

/// ret: the runtime pops the frame and lands the program where the call was
/// made from, which is the address the inter-jump of kind IsRet stands for.
let ret (ins: Instruction) bld =
  lift bld ins {
    AST.extCall (AST.app "ret" [] 64<rt>)
    AST.interjmp (AST.undef 64<rt> "CIL_RETURN_ADDRESS") InterJmpKind.IsRet
    return NoEndMark
  }

/// throw and rethrow: where the exception is caught is for the runtime to
/// find; to everything here the instruction is an exit.
let throw (ins: Instruction) bld name =
  lift bld ins {
    AST.extCall (AST.app name [] 64<rt>)
    AST.sideEffect Terminate
  }

/// leave: a branch out of a protected region, which the runtime is told of
/// first so that it can run the finally handlers on the way.
let leave (ins: Instruction) bld =
  lift bld ins {
    let target = numU64 (getTarget ins) 64<rt>
    AST.extCall (AST.app "leave" [ target ] 64<rt>)
    AST.interjmp target InterJmpKind.Base
    return NoEndMark
  }

/// endfinally and endfilter, which leave a handler for wherever the runtime's
/// record of the exception in flight says.
let endHandler (ins: Instruction) bld name =
  lift bld ins {
    AST.extCall (AST.app name [] 64<rt>)
    AST.interjmp (AST.undef 64<rt> "CIL_HANDLER_EXIT") InterJmpKind.IsRet
    return NoEndMark
  }

/// The length of an array, read from its header.
let private lengthOf arr =
  AST.zext 64<rt> (AST.loadLE 32<rt> (arr .+ num64 ArrayLayout.LengthOffset))

/// Raises where the array is null.
let private checkArray bld arr =
  let isNull = arr == AST.num0 64<rt>
  raiseWhen bld "NullArray" isNull CILException.NullReference

/// Raises where the array is null and where the index is not below its
/// length. The index is a canonical int32 or a native int, so a negative one
/// is above every length as an unsigned quadword.
let private checkElement bld arr idx =
  checkArray bld arr
  raiseWhen bld "Bounds" (idx .>= lengthOf arr) CILException.IndexOutOfRange

/// The address of an element of the given size.
let private elemAddr arr idx size =
  arr .+ num64 ArrayLayout.DataOffset .+ (idx .* num64 size)

/// ldlen: the length as a native unsigned int.
let ldlen (ins: Instruction) bld =
  lift bld ins {
    let struct (arr, _) = peek bld 0
    checkArray bld arr
    writeSlot bld (slotAddr bld 0) (lengthOf arr) (tag SlotType.I)
  }

/// The loads of an element whose type is in the opcode, which widen it as the
/// loads through a pointer do.
let private ldelem (ins: Instruction) bld size widen outTag =
  lift bld ins {
    let struct (idx, _) = peek bld 0
    let struct (arr, _) = peek bld 1
    checkElement bld arr idx
    let addr = elemAddr arr idx (RegType.toByteWidth size)
    replace bld 2 (widen (AST.loadLE size addr)) (tag outTag)
  }

let ldelemI1 ins bld = ldelem ins bld 8<rt> (AST.sext 64<rt>) SlotType.I4

let ldelemU1 ins bld = ldelem ins bld 8<rt> (AST.zext 64<rt>) SlotType.I4

let ldelemI2 ins bld = ldelem ins bld 16<rt> (AST.sext 64<rt>) SlotType.I4

let ldelemU2 ins bld = ldelem ins bld 16<rt> (AST.zext 64<rt>) SlotType.I4

let ldelemI4 ins bld = ldelem ins bld 32<rt> (AST.sext 64<rt>) SlotType.I4

let ldelemI8 ins bld = ldelem ins bld 64<rt> id SlotType.I8

let ldelemI ins bld = ldelem ins bld 64<rt> id SlotType.I

let ldelemR4 ins bld = ldelem ins bld 32<rt> (AST.zext 64<rt>) SlotType.F4

let ldelemR8 ins bld = ldelem ins bld 64<rt> id SlotType.F8

let ldelemRef ins bld = ldelem ins bld 64<rt> id SlotType.O

/// The stores of an element whose type is in the opcode, which narrow the
/// value as the stores through a pointer do, given the value and its tag.
let private stelem (ins: Instruction) bld size narrow =
  lift bld ins {
    let struct (v, t) = peek bld 0
    let struct (idx, _) = peek bld 1
    let struct (arr, _) = peek bld 2
    checkElement bld arr idx
    let addr = elemAddr arr idx (RegType.toByteWidth size)
    AST.store Endian.Little addr (narrow v t)
    drop bld 3
  }

let stelemI1 ins bld = stelem ins bld 8<rt> (fun v _ -> lo8 v)

let stelemI2 ins bld = stelem ins bld 16<rt> (fun v _ -> lo16 v)

let stelemI4 ins bld = stelem ins bld 32<rt> (fun v _ -> lo32 v)

let stelemI8 ins bld = stelem ins bld 64<rt> (fun v _ -> v)

let stelemI ins bld = stelem ins bld 64<rt> (fun v _ -> v)

let stelemR4 ins bld = stelem ins bld 32<rt> (fun v t -> narrowF t v)

let stelemR8 ins bld = stelem ins bld 64<rt> (fun v t -> asDouble t v)

/// stelem.ref: the runtime checks that the object is of the element type, so
/// the store is its.
let stelemRef ins bld = runtime ins bld "stelem.ref"

// vim: set tw=80 sts=2 sw=2:
