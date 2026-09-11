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


/// Translates every eBPF instruction: the arithmetic and the logic of both
/// classes, the jumps, the loads and the stores, the atomic stores, and the
/// call and the return whose frames the runtime keeps rather than the program.
module internal B2R2.FrontEnd.BPF.GeneralLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.BPF.LiftHelper

/// <summary>
/// An instruction this lifter has no model for, which the emulator is left to
/// refuse rather than to run as something it is not.
///
/// What ends up here is not a gap in the instruction set but the part of it
/// that is not a function of the program's own state: a read of a packet the
/// program was handed, a number a loader was to have replaced with the address
/// of a map, a call into a kernel named by a type identifier. Each of those
/// needs the platform the program was loaded by, and a lifter that answered
/// one anyway would be inventing the answer.
/// </summary>
let unsupported (ins: Instruction) bld =
  lift bld ins { AST.sideEffect UnsupportedInstruction }

/// <summary>
/// The shape every instruction computing from a register and one other thing
/// shares: the register it writes is also the first of the two values it
/// reads, and the second is either another register or the number written in
/// its place.
///
/// What the instruction computes is handed in as a function of the two, so
/// each of the lifters below is that expression and nothing else. Both values
/// arrive in the width the instruction's class computes in, and the write back
/// clears the upper half of the register for the narrower class, so neither
/// concern reaches the expressions themselves.
/// </summary>
let private compute ins bld rt f =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let dst = srcOf bld rt o1
    let src = srcOf bld rt o2
    dstWrite bld rt o1 (f dst src)
  }

let add ins bld rt = compute ins bld rt (fun a b -> a .+ b)

let sub ins bld rt = compute ins bld rt (fun a b -> a .- b)

let mul ins bld rt = compute ins bld rt (fun a b -> a .* b)

let logicOr ins bld rt = compute ins bld rt (fun a b -> a .| b)

let logicAnd ins bld rt = compute ins bld rt (fun a b -> a .& b)

let logicXor ins bld rt = compute ins bld rt (fun a b -> a <+> b)

let mov ins bld rt = compute ins bld rt (fun _ b -> b)

/// <summary>
/// The shifts, of which the machine reads only as many bits of the count as
/// the width being shifted needs.
///
/// A count of sixty-five therefore shifts a quadword by one and a count of
/// thirty-three shifts a word by one, which is the one thing about these a
/// lifter is likely to leave out -- and leaving it out agrees with the machine
/// for every count a compiler would ever emit.
/// </summary>
let private shift ins bld rt f =
  let bits = RegType.toBitWidth rt
  compute ins bld rt (fun a b -> f a (b .& numI32 (bits - 1) rt))

let lsh ins bld rt = shift ins bld rt (fun a b -> a << b)

let rsh ins bld rt = shift ins bld rt (fun a b -> a >> b)

let arsh ins bld rt = shift ins bld rt (fun a b -> a ?>> b)

/// <summary>
/// div/div32: an unsigned division, which the instruction set defines over
/// every divisor rather than leaving a trap where a machine would take one.
///
/// A division by zero yields zero (RFC 9669, section 4.1), so the divisor is
/// tested rather than handed to an evaluator that would raise on it.
/// </summary>
let div ins bld rt =
  let zero = AST.num0 rt
  compute ins bld rt (fun a b -> AST.ite (b == zero) zero (a ./ b))

/// mod/mod32: an unsigned remainder, which leaves the dividend where the
/// divisor is zero rather than yielding zero as the division does.
let modulo ins bld rt =
  let zero = AST.num0 rt
  compute ins bld rt (fun a b -> AST.ite (b == zero) a (a .% b))

/// <summary>
/// sdiv/sdiv32: a signed division, which needs a second guard the unsigned one
/// does not.
///
/// Dividing the most negative value by minus one overflows, and the answer the
/// architecture states is the dividend itself -- which is exactly what
/// negating computes there, and what negating computes for every other
/// dividend divided by minus one as well. So the case is not special-cased so
/// much as folded into the one expression that covers it.
/// </summary>
let sdiv ins bld rt =
  let zero = AST.num0 rt
  let minusOne = numI32 -1 rt
  compute ins bld rt (fun a b ->
    AST.ite (b == zero)
            zero
            (AST.ite (b == minusOne) (AST.neg a) (a ?/ b)))

/// smod/smod32: a signed remainder, which is zero for every dividend taken
/// modulo minus one -- the most negative value included, where the division it
/// pairs with overflows.
let smod ins bld rt =
  let zero = AST.num0 rt
  let minusOne = numI32 -1 rt
  compute ins bld rt (fun a b ->
    AST.ite (b == zero)
            a
            (AST.ite (b == minusOne) zero (a ?% b)))

/// neg/neg32: the one instruction computing from the register it writes and
/// from nothing else.
let neg ins bld rt =
  lift bld ins {
    let o = getOneOpr ins
    dstWrite bld rt o (AST.neg (srcOf bld rt o))
  }

/// How much of its source a widening move reads, which the encoding holds in
/// the halfword where a jump would count its distance.
let private widenSize opr =
  match getImm opr with
  | 8UL -> 8<rt>
  | 16UL -> 16<rt>
  | 32UL -> 32<rt>
  | _ -> raise InvalidOperandException

/// <summary>
/// movsx/movsx32: a move widening the low byte, halfword or word of what it
/// reads as signed.
///
/// The narrower class widens to a word and then clears the upper half of the
/// register, which is the same two steps every instruction of that class
/// takes, so widening to the class's own width is the whole of what this says.
/// </summary>
let movsx ins bld rt =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let src = srcOf bld rt o2
    dstWrite bld rt o1 (AST.sext rt (AST.xtlo (widenSize o3) src))
  }

/// <summary>
/// The shape the instructions naming a byte order share: one register read,
/// reordered, and written back.
///
/// Each names how much of the register it reaches, and what it leaves there is
/// that much and no more -- the bits above are cleared, which is the ordinary
/// rule of the narrower class for the six of these belonging to it and part of
/// what the wider three are defined to do.
/// </summary>
let private reorder ins bld width convert =
  lift bld ins {
    let r = regOf bld (getOneOpr ins)
    if width = 64<rt> then
      append bld { r := convert 64<rt> r }
    else
      append bld { r := AST.zext 64<rt> (convert width (AST.xtlo width r)) }
  }

/// bswap16/bswap32/bswap64: a reversal whatever the machine's own byte order
/// is, which is what tells these from the six converting to an order.
let bswap ins bld width = reorder ins bld width swapBytes

/// le16/le32/le64: a conversion to little-endian order, which is a reversal
/// only on a big-endian machine.
let toLittle ins bld width =
  reorder ins bld width (toOrder bld Endian.Little)

/// be16/be32/be64: a conversion to big-endian order, which is a reversal only
/// on a little-endian machine.
let toBig ins bld width = reorder ins bld width (toOrder bld Endian.Big)

/// ja/gotol: the jumps going where they name whatever holds. The two differ
/// only in which field they count their distance in, which the parser has
/// already read and scaled.
let goto ins bld =
  lift bld ins {
    let target = jumpTarget ins (getOneOpr ins)
    AST.interjmp (numU64 target 64<rt>) InterJmpKind.Base
    return NoEndMark
  }

/// <summary>
/// The shape every conditional jump shares, its two classes differing in how
/// much of the two values they compare rather than in what they compare them
/// for.
///
/// The comparison is handed in as a function of the two, each already narrowed
/// to the width its class reads -- which is what makes a signed comparison of
/// the narrower class read the sign of the word rather than the sign of the
/// quadword it sits in.
/// </summary>
let private jumpIf ins bld rt cond =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let a = srcOf bld rt o1
    let b = srcOf bld rt o2
    AST.intercjmp (cond a b)
                  (numU64 (jumpTarget ins o3) 64<rt>)
                  (numU64 (nextAddr ins) 64<rt>)
    return NoEndMark
  }

let jeq ins bld rt = jumpIf ins bld rt (fun a b -> a == b)

let jne ins bld rt = jumpIf ins bld rt (fun a b -> a != b)

let jgt ins bld rt = jumpIf ins bld rt (fun a b -> a .> b)

let jge ins bld rt = jumpIf ins bld rt (fun a b -> a .>= b)

let jlt ins bld rt = jumpIf ins bld rt (fun a b -> a .< b)

let jle ins bld rt = jumpIf ins bld rt (fun a b -> a .<= b)

let jsgt ins bld rt = jumpIf ins bld rt (fun a b -> a ?> b)

let jsge ins bld rt = jumpIf ins bld rt (fun a b -> a ?>= b)

let jslt ins bld rt = jumpIf ins bld rt (fun a b -> a ?< b)

let jsle ins bld rt = jumpIf ins bld rt (fun a b -> a ?<= b)

/// jset/jset32: the one conditional jump testing the two values for a bit in
/// common rather than comparing them.
let jset ins bld rt =
  jumpIf ins bld rt (fun a b -> (a .& b) != AST.num0 rt)

/// <summary>
/// call: a call to one of the functions the platform provides, which the
/// encoding names by the number the platform gives it.
///
/// What such a function computes is not in the instruction set at all -- it
/// belongs to the runtime, and a different runtime numbers a different set --
/// so the lifter names the call and leaves whatever runs the program to answer
/// it. An emulator with nothing installed to answer reports it the way it
/// reports any instruction it cannot run, which is the honest outcome for a
/// program lifted apart from its platform.
///
/// The five registers an argument is passed in are named as the arguments so
/// that a runtime answering the call reads them from the IR rather than
/// reaching into the register file behind it.
/// </summary>
let callHelper ins bld =
  lift bld ins {
    let n = numU64 (getImm (getOneOpr ins)) 64<rt>
    let args =
      [ n
        regVar bld Register.R1
        regVar bld Register.R2
        regVar bld Register.R3
        regVar bld Register.R4
        regVar bld Register.R5 ]
    regVar bld Register.R0 := AST.app "BPFHelper" args 64<rt>
  }

/// <summary>
/// call local: a call to a function of this same program, which the encoding
/// counts the distance to where a helper call holds its number.
///
/// The jump itself is an ordinary call edge, so nothing about the program's
/// control flow is hidden. What is hidden is the frame the machine pushes: the
/// address to come back to, the registers a called function is to leave as it
/// found, and the stack frame the callee gets for itself. None of that is
/// reachable by the program or held in any register it names, so the push is
/// named for the runtime to perform and the jump follows it.
/// </summary>
let callLocal ins bld =
  lift bld ins {
    let target = jumpTarget ins (getOneOpr ins)
    AST.extCall (AST.app "BPFPushFrame" [ numU64 (nextAddr ins) 64<rt> ] 64<rt>)
    AST.interjmp (numU64 target 64<rt>) InterJmpKind.IsCall
    return NoEndMark
  }

/// <summary>
/// exit: a return to whatever called this, which at the outermost frame is the
/// end of the program.
///
/// Where the return goes is nowhere an expression can name -- it is in the
/// frame the matching call pushed, which the machine keeps out of the
/// program's reach -- so the pop is named for the runtime to perform, the same
/// answer the same problem gets for a bytecode guest's return. The jump stays
/// an InterJmp of kind IsRet so that CFG recovery still sees a return edge;
/// only its target is unknown.
/// </summary>
let exitProgram ins bld =
  lift bld ins {
    AST.extCall (AST.app "BPFPopFrame" [] 64<rt>)
    AST.interjmp (AST.undef 64<rt> "BPF_EXIT_TARGET") InterJmpKind.IsRet
    return NoEndMark
  }

/// lddw: the one instruction two words wide, which carries a whole quadword
/// and needs none of it widened.
let lddw ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    regOf bld o1 := numU64 (getImm o2) 64<rt>
  }

/// The loads from the memory a register points into, which differ in how much
/// they read and in whether what they read is widened with its sign or with
/// zeroes.
let private load ins bld size ext =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = effectiveAddr bld o2
    let v = loadNative bld size ea
    regOf bld o1 := (if size = 64<rt> then v else ext 64<rt> v)
  }

let ldxu ins bld size = load ins bld size AST.zext

let ldxs ins bld size = load ins bld size AST.sext

/// <summary>
/// The stores of a number written in the instruction itself.
///
/// The number is widened as signed and then as much of it as the memory
/// reached holds is written, so `stdw [%r1+0], -1` fills the whole quadword
/// rather than its lower half.
/// </summary>
let stImm ins bld size =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = effectiveAddr bld o1
    storeNative bld ea (narrow size (immSExt (getImm o2)))
  }

/// The stores of what a register holds.
let stxReg ins bld size =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = effectiveAddr bld o1
    storeNative bld ea (narrow size (regOf bld o2))
  }

/// <summary>
/// The atomic stores that compute and write back without reporting what they
/// found.
///
/// The read and the write are bracketed as one atomic sequence, which is what
/// the instruction promises and what a machine running more than one thread
/// would need of it.
/// </summary>
let private atomic ins bld size f =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = effectiveAddr bld o1
    let v = narrow size (regOf bld o2)
    let t = tmpVar bld size
    AST.sideEffect AtomicBegin
    t := loadNative bld size ea
    storeNative bld ea (f t v)
    AST.sideEffect AtomicEnd
  }

/// <summary>
/// The atomic stores leaving what they found in the register they read their
/// operand from, and the swap, which is that same shape with no operation to
/// perform.
///
/// The register is written after the store rather than before it. A store that
/// faults leaves the whole instruction to run again from its first statement,
/// so a register committed before it would be committed twice -- and the
/// register committed here is the one the value to store was read from, which
/// would make the second run store what the first run had found.
/// </summary>
let private atomicFetch ins bld size f =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = effectiveAddr bld o1
    let r = regOf bld o2
    let v = narrow size r
    let t = tmpVar bld size
    AST.sideEffect AtomicBegin
    t := loadNative bld size ea
    storeNative bld ea (f t v)
    AST.sideEffect AtomicEnd
    r := widen size t
  }

/// <summary>
/// The compare-and-swap, which writes the operand only where what it found is
/// what R0 holds, and leaves what it found in R0 either way.
///
/// What it writes where the two disagree is what was already there, which is
/// one store rather than a store under a branch -- and is what the locked
/// compare-and-exchange of a real machine performs in that case too. R0 is
/// written after the store for the reason the fetching forms are, and is read
/// for the comparison before it is written.
/// </summary>
let private atomicCmpXchg ins bld size =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = effectiveAddr bld o1
    let v = narrow size (regOf bld o2)
    let r0 = regVar bld Register.R0
    let t = tmpVar bld size
    AST.sideEffect AtomicBegin
    t := loadNative bld size ea
    storeNative bld ea (AST.ite (t == narrow size r0) v t)
    AST.sideEffect AtomicEnd
    r0 := widen size t
  }

let atomicAdd ins bld size = atomic ins bld size (fun a b -> a .+ b)

let atomicOr ins bld size = atomic ins bld size (fun a b -> a .| b)

let atomicAnd ins bld size = atomic ins bld size (fun a b -> a .& b)

let atomicXor ins bld size = atomic ins bld size (fun a b -> a <+> b)

let atomicFetchAdd ins bld size =
  atomicFetch ins bld size (fun a b -> a .+ b)

let atomicFetchOr ins bld size =
  atomicFetch ins bld size (fun a b -> a .| b)

let atomicFetchAnd ins bld size =
  atomicFetch ins bld size (fun a b -> a .& b)

let atomicFetchXor ins bld size =
  atomicFetch ins bld size (fun a b -> a <+> b)

let atomicXchg ins bld size = atomicFetch ins bld size (fun _ b -> b)

let atomicCas ins bld size = atomicCmpXchg ins bld size

// vim: set tw=80 sts=2 sw=2:
