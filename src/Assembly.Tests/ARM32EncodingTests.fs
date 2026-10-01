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

namespace B2R2.Assembly.Tests

open System
open System.IO
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.ARM32

/// <summary>
/// Golden encoding vectors written by hand, covering the assembly syntax that
/// canonical disassembly cannot express and that ARM32RoundTripTests therefore
/// cannot reach: labels, aliases, letter case, comments, and the forms the
/// disassembler reads back as something other than what was written.
///
/// Every expected word here was validated by disassembling it with
/// B2R2.FrontEnd.ARM32 and confirming it means what the source text says.
/// </summary>
[<TestClass>]
type ARM32EncodingTests() =

  /// Source text paired with the encoding it must produce, written as the bytes
  /// come out. Multi-line sources are compared instruction by instruction,
  /// joined by a space.
  let vectors =
    [ (* Letter case and comments are not part of the syntax. *)
      "MOV R0, R1", "0100a0e1"
      "mov r0, r1 ; a comment", "0100a0e1"
      (* An immediate is an eight-bit value and an even rotation, so what can be
         written is what those two reach. *)
      "mov r0, #0xff", "ff00a0e3"
      "add r0, r1, #0x400", "010b81e2"
      (* The shifts are aliases of MOV, and the disassembler reads them back as
         the alias rather than as the move. *)
      "lsl r0, r1, #0x1", "8100a0e1"
      "mov r0, r1, lsl #0x2", "0101a0e1"
      "rrx r0, r1", "6100a0e1"
      (* A caret says a block transfer moves the registers of another mode, or
         returns from an exception when it also loads the program counter. *)
      "stm r1, {r0, r2}^", "0500c1e8"
      "stmda r1, {r0, r2}^", "050041e8"
      "ldm r1, {r0, r2}^", "0500d1e8"
      "ldm r1!, {r0, pc}^", "0180f1e8"
      (* PUSH and POP of one register are a store and a load; of several, a
         block transfer. Both spellings of the block form are the same word. *)
      "push {r0}", "04002de5"
      "push {r0, r1}", "03002de9"
      "pop {r0}", "04009de4"
      "pop {r0, r1}", "0300bde8"
      "stmdb sp!, {r4, lr}", "10402de9"
      "ldm r1!, {r0, r2}", "0500b1e8"
      (* A branch reaches a label in either direction, and a load reads the
         literal one marks. The program counter reads eight bytes ahead, which
         is why a branch to the instruction after the next one encodes zero. *)
      "b L\n  nop\nL:\n  nop", "000000ea 00f020e3 00f020e3"
      "bl L\n  nop\nL:\n  nop", "000000eb 00f020e3 00f020e3"
      "L:\n  nop\n  b L", "00f020e3 fdffffea"
      "ldr r0, L\n  nop\nL:\n  nop", "00009fe5 00f020e3 00f020e3"
      "adr r0, L\n  nop\nL:\n  nop", "00008fe2 00f020e3 00f020e3"
      (* A barrier with no option means the widest one. *)
      "dmb", "5ff07ff5"
      "dmb sy", "5ff07ff5"
      (* The status register is named APSR by the disassembler and CPSR by the
         manual, and both spellings mean the current one. *)
      "mrs r0, apsr", "00000fe1"
      "mrs r0, cpsr", "00000fe1"
      "msr cpsr_fc, r0", "00f029e1"
      "msr apsr_nzcvq, r0", "00f028e1"
      (* A banked register belongs to a mode the processor is not in, and is
         reached by a different encoding from the current mode's. *)
      "mrs r0, sp_irq", "000301e1"
      "mrs r0, spsr_irq", "000340e1"
      "msr sp_irq, r0", "00f321e1"
      (* The bitfield instructions name a field by where it starts and how wide
         it is; the encoding holds where it ends. *)
      "bfc r0, #0x2, #0x4", "1f01c5e7"
      "bfi r0, r1, #0x2, #0x4", "1101c5e7"
      "ubfx r0, r1, #0x2, #0x4", "5101e3e7"
      (* An extending move rotates by whole bytes, and naming no source to add
         to is how the manual writes the form that adds nothing. *)
      "sxtb r0, r1", "7100afe6"
      "sxtab r0, r1, r2, ror #0x8", "7204a1e6"
      (* The saturating moves count their width from one place for the signed
         form and from another for the unsigned one. *)
      "usat r0, #0x1, r1", "1100e1e6"
      "ssat r0, #0x1, r1", "1100a0e6"
      "usat16 r0, #0x1, r1", "310fe1e6"
      "ssat16 r0, #0x1, r1", "310fa0e6"
      (* An ordered or exclusive access keeps the register it transfers below
         the field a load keeps it in when it stores and above it when it loads.
         A round trip through text would not notice the assembler and the
         decoder agreeing on the wrong one, so the manual's layout is pinned
         here. *)
      "stl r0, [r1]", "90fc81e1"
      "ldrexb r0, [r1]", "9f0fd1e1" ]

  /// <summary>
  /// The same for the Thumb instruction set, whose narrow encodings say what
  /// A32 says in half the space.
  ///
  /// A Thumb instruction reads the program counter four bytes ahead of itself
  /// rather than eight, which is what the distances below turn on.
  /// </summary>
  let thumbVectors =
    [ "movs r0, r1", "0800"
      "adds r0, r1, r2", "8818"
      "adds r0, #0x5", "0530"
      (* Only these two lists reach past the first eight registers, and only in
         one direction each. *)
      "push {r0, lr}", "01b5"
      "pop {r4, pc}", "10bd"
      (* The offset of a narrow load counts in whatever it transfers, and the
         stack has an encoding of its own. *)
      "ldr r0, [r1, #0x8]", "8868"
      "ldr r0, [sp, #0x8]", "0298"
      "add r0, sp, #0x8", "02a8"
      (* A comparison of high registers is a different encoding from one of low
         registers, and the numbered name of a register the disassembler prints
         by its role is read back as that register. *)
      "cmp r8, r9", "c845"
      (* Branches, which reach a label in either direction. *)
      "b L\n  nop\nL:\n  nop", "00e0 00bf 00bf"
      "L:\n  nop\n  b L", "00bf fde7"
      "beq L\n  nop\nL:\n  nop", "00d0 00bf 00bf"
      "cbz r0, L\n  nop\nL:\n  nop", "00b1 00bf 00bf"
      "adr r0, L\n  nop\nL:\n  nop", "00a0 00bf 00bf"
      (* The half-precision multiplies that accumulate into single-precision
         numbers keep the top bit of their destination apart from the four
         below it, as every SIMD instruction does. *)
      "vfmal.f16 d16, s2, s9", "61fc3408"
      (* An IT block holds the condition of what follows it as a mask, one bit
         per instruction, ended by a one below them. *)
      "it eq", "08bf"
      "ittee ne", "19bf" ]

  /// <summary>
  /// Sources that hold both instruction sets, which a directive switches
  /// between: nothing in a line says which set it belongs to, so what says it
  /// is the last directive before it.
  /// </summary>
  let mixedVectors =
    [ ".thumb\n  mov r0, r1\n  nop", "0846 00bf"
      ".thumb\n  mov r0, r1\n  nop\n.arm\n  mov r0, r1", "0846 00bf 0100a0e1"
      (* A label is reached from either set, each measuring from where its own
         program counter reads: four bytes ahead in Thumb and eight in ARM. *)
      ".thumb\n  b L\n  nop\n.arm\nL:\n  mov r0, r1", "00e0 00bf 0100a0e1"
      ".arm\n  b L\n.thumb\nL:\n  nop", "ffffffea 00bf" ]

  /// Sources that must be refused rather than encoded.
  let rejected =
    [ (* An immediate no rotation of a byte can reach. *)
      "mov r0, #0x101"
      (* A shift by an amount its own encoding cannot hold: an LSR by nothing
         shares its bits with an LSR by thirty-two. *)
      "and r0, r1, r2, lsr #0x0"
      "and r0, r1, r2, lsl #0x20"
      (* BKPT is unconditional, so a condition written on it could not be read
         back from what it encodes. *)
      "bkptne #0x1"
      (* The 0b1111 condition marks the unconditional encoding space now, so
         nothing can be encoded to mean the condition it once named. *)
      "movnv r0, r1"
      (* A register with no place in the encoding. *)
      "mov r0, s0"
      "add r0, r1, apsr"
      (* A doubleword transfer reads the register after the one it names. *)
      "ldrd r0, r2, [r1]"
      (* A caret belongs to a block transfer, and a field must have a width. *)
      "push {r0}^"
      "bfi r0, r1, #0x6, #0x0"
      (* A label that was never defined. *)
      "b L"
      (* An ARM instruction reads a whole word, so it cannot start halfway
         through one however the source arrived there. *)
      ".thumb\n  nop\n.arm\n  mov r0, r1"
      (* A block says what the instructions after it run under, and an ARM
         instruction says that for itself. *)
      ".thumb\n  it eq\n.arm\n  moveq r0, r1" ]

  /// Runs the given action with stderr muted; see ARM32RoundTripTests.
  let mutingStderr action =
    let saved = Console.Error
    Console.SetError TextWriter.Null
    try action () finally Console.SetError saved

  let isa = ISA(Architecture.ARMv7, WordSize.Bit32)

  let encodeWith (asm: ILowerable) source =
    try
      match asm.Lower source with
      | Ok encoded ->
        encoded
        |> List.map (snd >> Array.map (sprintf "%02x") >> String.concat "")
        |> String.concat " "
      | Error _ ->
        "<cannot parse>"
    with
    | :? EncodingFailureException -> "<unsupported>"
    | :? NotImplementedException -> "<unsupported>"
    | :? InvalidOperationException -> "<invalid>"

  let encode source = encodeWith (Assembler(isa, 0UL) :> ILowerable) source

  let encodeThumb source =
    let thumbISA = ISA(Endian.Little, false, ARM32Mode.Thumb)
    encodeWith (Assembler(thumbISA, 0UL) :> ILowerable) source

  /// The ISA each instruction of a source was assembled for, named as that ISA
  /// names itself, so that what the assembler tells its caller can be read.
  let setsOf source =
    match (Assembler(isa, 0UL) :> ILowerable).Lower source with
    | Ok encoded ->
      encoded
      |> List.map (fun (isa: ISA, _) -> isa.ToString())
      |> String.concat " "
    | Error _ ->
      "<cannot parse>"

  let brokenWith encode vectors =
    mutingStderr (fun () ->
      vectors
      |> List.choose (fun (source, expected) ->
        let actual = encode source
        if actual = expected then None else Some $"{source} => {actual}"))
    |> List.sort

  let brokenVectors vectors = brokenWith encode vectors

  [<TestMethod>]
  member _.``Golden vectors encode exactly as specified``() =
    let defects = brokenVectors vectors
    Assert.AreEqual<string>(
      "",
      String.concat "\n" defects,
      "These vectors no longer encode as specified."
    )

  [<TestMethod>]
  member _.``A source may hold both instruction sets``() =
    let defects = brokenVectors mixedVectors
    Assert.AreEqual<string>(
      "",
      String.concat "\n" defects,
      "These no longer encode as specified when the source switches sets."
    )

  /// Two halfwords and one word look alike once they are bytes, so a caller
  /// handed only bytes cannot tell which instruction set to read them with.
  /// Saying it is the difference between disassembling what was assembled and
  /// disassembling something else.
  [<TestMethod>]
  member _.``Each instruction says which set it was assembled for``() =
    let source = ".thumb\n  nop\n  nop\n.arm\n  mov r0, r1\n.thumb\n  nop"
    Assert.AreEqual<string>(
      "thumb thumb armv7 thumb",
      setsOf source,
      "An instruction no longer says which instruction set it belongs to."
    )

  [<TestMethod>]
  member _.``Thumb vectors encode exactly as specified``() =
    let defects = brokenWith encodeThumb thumbVectors
    Assert.AreEqual<string>(
      "",
      String.concat "\n" defects,
      "These Thumb vectors no longer encode as specified."
    )

  [<TestMethod>]
  member _.``A source that cannot be encoded is refused``() =
    let accepted =
      mutingStderr (fun () ->
        rejected
        |> List.choose (fun source ->
          match encode source with
          | "<unsupported>" -> None
          | encoded -> Some $"{source} encoded as {encoded}"))
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" accepted,
      "These ask for something no A32 encoding can say."
    )

  /// TSB is written with the one option it has.
  [<TestMethod>]
  member _.``TSB CSYNC encodes``() =
    Assert.AreEqual<string>("12f020e3", encode "tsb csync")

  /// A single-precision VMOV into a doubleword or quadword is the Advanced SIMD
  /// one, whose eight bits are those of a floating-point move under cmode 1111.
  [<TestMethod>]
  member _.``VMOV.F32 (immediate) encodes its constant``() =
    Assert.AreEqual<string>("140f81f2", encode "vmov.f32 d0, #0x40a00000")

  [<TestMethod>]
  member _.``VMOV.F32 (immediate) encodes a quadword``() =
    Assert.AreEqual<string>("540f81f3", encode "vmov.f32 q0, #0xc0a00000")

  /// A byte shifted in over ones is cmode 1100 for eight of them and 1101 for
  /// sixteen, which only VMOV and VMVN have.
  [<TestMethod>]
  member _.``VMOV.I32 (immediate) encodes eight ones``() =
    Assert.AreEqual<string>("1a0c85f2", encode "vmov.i32 d0, #0x5aff")

  [<TestMethod>]
  member _.``VMOV.I32 (immediate) encodes sixteen ones``() =
    Assert.AreEqual<string>("1a0d85f2", encode "vmov.i32 d0, #0x5affff")

  [<TestMethod>]
  member _.``VMVN.I32 (immediate) encodes eight ones``() =
    Assert.AreEqual<string>("3a0c85f2", encode "vmvn.i32 d0, #0x5aff")

  [<TestMethod>]
  member _.``VMVN.I32 (immediate) encodes sixteen ones``() =
    Assert.AreEqual<string>("3a0d85f2", encode "vmvn.i32 d0, #0x5affff")

  [<TestMethod>]
  member _.``VORR.I32 (immediate) refuses ones``() =
    Assert.AreEqual<string>("<unsupported>", encode "vorr.i32 d0, #0x5aff")

  [<TestMethod>]
  member _.``Thumb VMOV.F32 (immediate) encodes its constant``() =
    Assert.AreEqual<string>("81ef140f", encodeThumb "vmov.f32 d0, #0x40a00000")

  [<TestMethod>]
  member _.``Thumb VMOV.I32 (immediate) encodes eight ones``() =
    Assert.AreEqual<string>("85ef1a0c", encodeThumb "vmov.i32 d0, #0x5aff")

  /// The wide hints, which a halfword cannot hold, and the barriers.
  [<TestMethod>]
  member _.``Thumb TSB CSYNC encodes``() =
    Assert.AreEqual<string>("aff31280", encodeThumb "tsb csync")

  [<TestMethod>]
  member _.``Thumb ESB encodes``() =
    Assert.AreEqual<string>("aff31080", encodeThumb "esb.w")

  [<TestMethod>]
  member _.``Thumb CSDB encodes``() =
    Assert.AreEqual<string>("aff31480", encodeThumb "csdb.w")

  [<TestMethod>]
  member _.``Thumb DBG encodes``() =
    Assert.AreEqual<string>("aff3f480", encodeThumb "dbg #0x4")

  [<TestMethod>]
  member _.``Thumb SB encodes``() =
    Assert.AreEqual<string>("bff3708f", encodeThumb "sb")

  [<TestMethod>]
  member _.``Thumb DSB encodes``() =
    Assert.AreEqual<string>("bff34f8f", encodeThumb "dsb sy")

  [<TestMethod>]
  member _.``Thumb DMB encodes``() =
    Assert.AreEqual<string>("bff35b8f", encodeThumb "dmb ish")

  [<TestMethod>]
  member _.``Thumb ISB encodes``() =
    Assert.AreEqual<string>("bff36f8f", encodeThumb "isb sy")

  [<TestMethod>]
  member _.``Thumb CLREX encodes``() =
    Assert.AreEqual<string>("bff32f8f", encodeThumb "clrex")

  /// The shifts by an immediate are MOV with Rn = PC, and a halfword holds
  /// only the form that sets the flags, outside a block.
  [<TestMethod>]
  member _.``Thumb LSL (immediate) encodes wide``() =
    Assert.AreEqual<string>("4feac100", encodeThumb "lsl r0, r1, #0x3")

  [<TestMethod>]
  member _.``Thumb LSLS.W (immediate) encodes wide``() =
    Assert.AreEqual<string>("5feac100", encodeThumb "lsls.w r0, r1, #0x3")

  [<TestMethod>]
  member _.``Thumb LSR (immediate) encodes wide``() =
    Assert.AreEqual<string>("4fea1100", encodeThumb "lsr r0, r1, #0x20")

  [<TestMethod>]
  member _.``Thumb LSRS.W (immediate) encodes wide``() =
    Assert.AreEqual<string>("5fead100", encodeThumb "lsrs.w r0, r1, #0x3")

  [<TestMethod>]
  member _.``Thumb ASR (immediate) encodes wide``() =
    Assert.AreEqual<string>("4feae100", encodeThumb "asr r0, r1, #0x3")

  [<TestMethod>]
  member _.``Thumb ASRS.W (immediate) encodes wide``() =
    Assert.AreEqual<string>("5feae100", encodeThumb "asrs.w r0, r1, #0x3")

  [<TestMethod>]
  member _.``Thumb ROR (immediate) encodes wide``() =
    Assert.AreEqual<string>("4feaf100", encodeThumb "ror r0, r1, #0x3")

  [<TestMethod>]
  member _.``Thumb RORS.W (immediate) encodes wide``() =
    Assert.AreEqual<string>("5feaf100", encodeThumb "rors.w r0, r1, #0x3")

  [<TestMethod>]
  member _.``Thumb RRX encodes wide``() =
    Assert.AreEqual<string>("4fea3100", encodeThumb "rrx r0, r1")

  [<TestMethod>]
  member _.``Thumb RRXS encodes wide``() =
    Assert.AreEqual<string>("5fea3100", encodeThumb "rrxs r0, r1")

  /// The shifts by a register are an encoding of their own.
  [<TestMethod>]
  member _.``Thumb LSL (register) encodes wide``() =
    Assert.AreEqual<string>("01fa02f0", encodeThumb "lsl r0, r1, r2")

  [<TestMethod>]
  member _.``Thumb LSLS.W (register) encodes wide``() =
    Assert.AreEqual<string>("11fa02f0", encodeThumb "lsls.w r0, r1, r2")

  [<TestMethod>]
  member _.``Thumb LSR (register) encodes wide``() =
    Assert.AreEqual<string>("21fa02f0", encodeThumb "lsr r0, r1, r2")

  [<TestMethod>]
  member _.``Thumb LSRS.W (register) encodes wide``() =
    Assert.AreEqual<string>("31fa02f0", encodeThumb "lsrs.w r0, r1, r2")

  [<TestMethod>]
  member _.``Thumb ASR (register) encodes wide``() =
    Assert.AreEqual<string>("41fa02f0", encodeThumb "asr r0, r1, r2")

  [<TestMethod>]
  member _.``Thumb ASRS.W (register) encodes wide``() =
    Assert.AreEqual<string>("51fa02f0", encodeThumb "asrs.w r0, r1, r2")

  [<TestMethod>]
  member _.``Thumb ROR (register) encodes wide``() =
    Assert.AreEqual<string>("61fa02f0", encodeThumb "ror r0, r1, r2")

  [<TestMethod>]
  member _.``Thumb RORS.W (register) encodes wide``() =
    Assert.AreEqual<string>("71fa02f0", encodeThumb "rors.w r0, r1, r2")

  /// The wide moves are ORR and ORN with Rn = PC.
  [<TestMethod>]
  member _.``Thumb MOV.W (register) encodes wide``() =
    Assert.AreEqual<string>("4fea0100", encodeThumb "mov.w r0, r1")

  [<TestMethod>]
  member _.``Thumb MOVS.W (register) encodes wide``() =
    Assert.AreEqual<string>("5fea0100", encodeThumb "movs.w r0, r1")

  [<TestMethod>]
  member _.``Thumb MOV (immediate) encodes wide``() =
    Assert.AreEqual<string>("4ff03408", encodeThumb "mov r8, #0x34")

  [<TestMethod>]
  member _.``Thumb MOVS (immediate) encodes wide``() =
    Assert.AreEqual<string>("5ff03408", encodeThumb "movs r8, #0x34")

  [<TestMethod>]
  member _.``Thumb MVN (register) encodes wide``() =
    Assert.AreEqual<string>("6fea0100", encodeThumb "mvn r0, r1")

  [<TestMethod>]
  member _.``Thumb MVNS.W (register) encodes wide``() =
    Assert.AreEqual<string>("7fea0100", encodeThumb "mvns.w r0, r1")

  [<TestMethod>]
  member _.``Thumb MVN (shifted register) encodes wide``() =
    Assert.AreEqual<string>("6fea0140", encodeThumb "mvn r0, r1, lsl #0x10")

  [<TestMethod>]
  member _.``Thumb MVNS (rotated through carry) encodes wide``() =
    Assert.AreEqual<string>("7fea3100", encodeThumb "mvns r0, r1, rrx")

  [<TestMethod>]
  member _.``Thumb MVN (immediate) encodes wide``() =
    Assert.AreEqual<string>("6ff03400", encodeThumb "mvn r0, #0x34")

  [<TestMethod>]
  member _.``Thumb MVNS (immediate) encodes wide``() =
    Assert.AreEqual<string>("7ff03408", encodeThumb "mvns r8, #0x34")

  /// VMOVL is VSHLL by nothing: the shift field's top bit is what says how wide
  /// an element is.
  [<TestMethod>]
  member _.``VMOVL encodes``() =
    Assert.AreEqual<string>("100a90f2", encode "vmovl.s16 q0, d0")

  [<TestMethod>]
  member _.``VMOVL (unsigned) encodes``() =
    Assert.AreEqual<string>("110aa0f3", encode "vmovl.u32 q0, d1")

  /// The long multiplies write elements twice as wide as the ones they read.
  [<TestMethod>]
  member _.``VMULL (signed) encodes``() =
    Assert.AreEqual<string>("000c91f2", encode "vmull.s16 q0, d1, d0")

  [<TestMethod>]
  member _.``VMULL (unsigned) encodes``() =
    Assert.AreEqual<string>("000c81f3", encode "vmull.u8 q0, d1, d0")

  [<TestMethod>]
  member _.``VMULL (polynomial) encodes``() =
    Assert.AreEqual<string>("000e81f2", encode "vmull.p8 q0, d1, d0")

  /// The product of two doubleword polynomials keeps the size field of words.
  [<TestMethod>]
  member _.``VMULL.P64 encodes``() =
    Assert.AreEqual<string>("000ea1f2", encode "vmull.p64 q0, d1, d0")

  [<TestMethod>]
  member _.``VMLAL encodes``() =
    Assert.AreEqual<string>("000891f2", encode "vmlal.s16 q0, d1, d0")

  [<TestMethod>]
  member _.``VMLSL encodes``() =
    Assert.AreEqual<string>("000aa1f3", encode "vmlsl.u32 q0, d1, d0")

  /// By an element, a long multiply keeps U where the others keep Q.
  [<TestMethod>]
  member _.``VMULL by an element encodes``() =
    Assert.AreEqual<string>("4f0a91f2", encode "vmull.s16 q0, d1, d7[1]")

  [<TestMethod>]
  member _.``VMULL (unsigned) by an element encodes``() =
    Assert.AreEqual<string>("4f0a91f3", encode "vmull.u16 q0, d1, d7[1]")

  [<TestMethod>]
  member _.``VMLAL by an element encodes``() =
    Assert.AreEqual<string>("4f0291f2", encode "vmlal.s16 q0, d1, d7[1]")

  [<TestMethod>]
  member _.``VMLSL by an element encodes``() =
    Assert.AreEqual<string>("4f0691f2", encode "vmlsl.s16 q0, d1, d7[1]")

  [<TestMethod>]
  member _.``VMUL by an element encodes``() =
    Assert.AreEqual<string>("4f0891f2", encode "vmul.i16 d0, d1, d7[1]")

  [<TestMethod>]
  member _.``VMUL.F32 by an element encodes``() =
    Assert.AreEqual<string>("6709a2f3", encode "vmul.f32 q0, q1, d7[1]")

  [<TestMethod>]
  member _.``VQDMULH by an element encodes``() =
    Assert.AreEqual<string>("4f0c91f2", encode "vqdmulh.s16 d0, d1, d7[1]")

  [<TestMethod>]
  member _.``VQRDMULH by an element encodes``() =
    Assert.AreEqual<string>("6f0da2f3", encode "vqrdmulh.s32 q0, q1, d15[1]")

  [<TestMethod>]
  member _.``VQRDMLAH by an element encodes``() =
    Assert.AreEqual<string>("4f0e91f2", encode "vqrdmlah.s16 d0, d1, d7[1]")

  [<TestMethod>]
  member _.``VQRDMLSH by an element encodes``() =
    Assert.AreEqual<string>("4f0f91f2", encode "vqrdmlsh.s16 d0, d1, d7[1]")

  /// The rounding narrowing shifts are the plain ones with bit 6 set.
  [<TestMethod>]
  member _.``VRSHRN encodes``() =
    Assert.AreEqual<string>("700889f2", encode "vrshrn.i16 d0, q8, #0x7")

  [<TestMethod>]
  member _.``VQRSHRUN encodes``() =
    Assert.AreEqual<string>("700889f3", encode "vqrshrun.s16 d0, q8, #0x7")

  [<TestMethod>]
  member _.``VQRSHRN encodes``() =
    Assert.AreEqual<string>("700989f2", encode "vqrshrn.s16 d0, q8, #0x7")

  [<TestMethod>]
  member _.``Thumb VMOVL encodes``() =
    Assert.AreEqual<string>("90ef100a", encodeThumb "vmovl.s16 q0, d0")

  [<TestMethod>]
  member _.``Thumb VMULL.P64 encodes``() =
    Assert.AreEqual<string>("a1ef000e", encodeThumb "vmull.p64 q0, d1, d0")

  [<TestMethod>]
  member _.``Thumb VQDMULH by an element encodes``() =
    Assert.AreEqual<string>("91ef4f0c", encodeThumb "vqdmulh.s16 d0, d1, d7[1]")

  /// MSR to SPSR sets the R bit, which is all that tells it from MSR to CPSR.
  [<TestMethod>]
  member _.``MSR (register) to SPSR encodes``() =
    Assert.AreEqual<string>("01f06fe1", encode "msr spsr_fsxc, r1")

  [<TestMethod>]
  member _.``MSR (immediate) to SPSR encodes``() =
    Assert.AreEqual<string>("fff068e3", encode "msr spsr_f, #0xff")

  [<TestMethod>]
  member _.``Thumb MSR to SPSR encodes``() =
    Assert.AreEqual<string>("91f3008f", encodeThumb "msr spsr_fsxc, r1")
