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
/// Lifts the instructions the embedded environment adds (Power ISA 2.07B Book
/// II and Book III-E). Lifter hands this module every opcode it says it lifts.
/// </summary>
module internal B2R2.FrontEnd.PPC.EmbeddedLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.LiftingUtils

/// <summary>
/// Lifts dcblq. and icblq.: CR0 is 0b00 followed by the status of the block
/// and XER[SO]. The status says whether the block is locked in the cache the
/// CT field names, and the manual has it 0 where the query cannot be answered.
/// No cache is modeled and no lock set instruction locks anything (below), so
/// no block is ever locked.
/// </summary>
let private lockQuery (ins: Instruction) bld =
  lift bld ins {
    let xerSO = AST.xthi 1<rt> (regVar bld Register.XER)
    regVar bld Register.CR0_0 := AST.b0
    regVar bld Register.CR0_1 := AST.b0
    regVar bld Register.CR0_2 := AST.b0
    regVar bld Register.CR0_3 := xerSO
  }

/// mfpmr reads a performance monitor register. No event is ever counted here
/// and no performance monitor is modeled, so every register reads 0.
let private mfpmr (ins: Instruction) bld =
  lift bld ins {
    let struct (rt, _) = transTwoOprs ins bld
    rt := AST.num0 bld.RegType
  }

/// A decorated load of size bits, zero-extended: the address is rB alone and
/// the decoration rA holds is a request to the storage controller that the
/// model has no controller to make. The access is the plain one.
let private decoratedLoad ext size (ins: Instruction) bld =
  lift bld ins {
    let struct (rt, _, rb) = transThreeOprs ins bld
    let ea = tmpVar bld bld.RegType
    ea := rb
    rt := ext (Expr.typeOf rt) (loadNative bld size ea)
  }

/// A decorated store of the low size bits of rS, at the address rB holds.
let private decoratedStore size (ins: Instruction) bld =
  lift bld ins {
    let struct (rs, _, rb) = transThreeOprs ins bld
    let ea = tmpVar bld bld.RegType
    ea := rb
    loadNative bld size ea := AST.xtlo size rs
  }

/// Whether this module lifts the opcode.
let lifts = function
  | Op.DCBLC | Op.DCBLQdot | Op.DCBTLS | Op.DCBTSTLS
  | Op.ICBLC | Op.ICBLQdot | Op.ICBTLS
  | Op.DNH | Op.EHPRIV | Op.MBAR | Op.MFDCRUX | Op.MFPMR | Op.MTDCRUX
  | Op.MTPMR | Op.XNOP
  | Op.DSN | Op.LBDX | Op.LDDX | Op.LFDDX | Op.LHDX | Op.LWDX | Op.STBDX
  | Op.STDDX | Op.STFDDX | Op.STHDX | Op.STWDX -> true
  | _ -> false

/// <summary>
/// Lifts an instruction whose opcode this module lifts.
/// <para>
/// The lock set instructions are hints that may fail to lock ("an
/// unable-to-lock condition may occur", and then no operation is performed),
/// and the lock clear ones do nothing where nothing is locked, so none leaves a
/// trace. mbar orders storage accesses, and xnop is a no-op that executes, as
/// the barriers and hints before them. mtpmr writes a performance monitor that
/// is not modeled. dnh and ehpriv raise an illegal instruction exception: dnh
/// halts the thread only where an implementation-dependent means has enabled it
/// and ehpriv, "analogous to a guaranteed illegal instruction encoding",
/// invokes the hypervisor, which a user-level program has none of. The device
/// control registers of mfdcrux and mtdcrux are the state of a device that is
/// not modeled. dsn sends a decoration to the storage controller, which has no
/// effect a program can see.
/// </para>
/// </summary>
let translate (ins: Instruction) bld =
  match ins.Opcode with
  | Op.DCBLQdot | Op.ICBLQdot ->
    lockQuery ins bld
  | Op.DNH | Op.EHPRIV ->
    sideEffects ins bld UndefinedInstruction
  | Op.MFDCRUX | Op.MTDCRUX ->
    sideEffects ins bld UnsupportedInstruction
  | Op.MFPMR ->
    mfpmr ins bld
  | Op.LBDX ->
    decoratedLoad AST.zext 8<rt> ins bld
  | Op.LHDX ->
    decoratedLoad AST.zext 16<rt> ins bld
  | Op.LWDX ->
    decoratedLoad AST.zext 32<rt> ins bld
  | Op.LDDX | Op.LFDDX ->
    decoratedLoad AST.zext 64<rt> ins bld
  | Op.STBDX ->
    decoratedStore 8<rt> ins bld
  | Op.STHDX ->
    decoratedStore 16<rt> ins bld
  | Op.STWDX ->
    decoratedStore 32<rt> ins bld
  | Op.STDDX | Op.STFDDX ->
    decoratedStore 64<rt> ins bld
  | _ ->
    GeneralLifter.nop ins bld
