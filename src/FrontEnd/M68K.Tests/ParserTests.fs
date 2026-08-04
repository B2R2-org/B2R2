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

namespace B2R2.FrontEnd.BinLifter.Tests

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.M68K
open Microsoft.VisualStudio.TestTools.UnitTesting
open type Opcode
open type Register

[<TestClass>]
type ParserTests() =
  /// A 68020, which is the model an m68k ISA means unless it says otherwise and
  /// the baseline of the Linux/m68k port.
  static let m68020 = ISA Architecture.M68K

  /// A 68000, which reads every extension word as the brief format.
  static let m68000 = ISA M68KModel.M68000

  static let parseWith (isa: ISA) hex =
    let bytes = ByteArray.ofHexString hex
    let parser = M68KParser(isa, BinReader.Init isa.Endian)
    (parser :> IInstructionParsable).Parse(ReadOnlySpan bytes, 0UL)
    :?> Instruction

  static let assertIns opcode size (oprs: Operands) length hex =
    let ins = parseWith m68020 hex
    Assert.AreEqual<Opcode>(opcode, ins.Opcode)
    Assert.AreEqual<OperandSize>(size, ins.Size)
    Assert.AreEqual<Operands>(oprs, ins.Operands)
    Assert.AreEqual<uint32>(length, ins.Length)

  static let assertFails (isa: ISA) hex =
    Assert.ThrowsExactly<ParsingFailureException>(fun () ->
      parseWith isa hex |> ignore)
    |> ignore

  /// Builds an indexed operand out of the pieces the several indexed modes each
  /// leave some of absent.
  static let indexed bas idx bd od pre =
    OpMem(Indexed { Base = bas
                    Index = idx
                    BaseDisp = bd
                    OuterDisp = od
                    IsPreIndexed = pre })

  static let index reg isLong scale =
    Some { Reg = reg; IsLong = isLong; Scale = scale }

  /// A 68040, whose cache, translation, and block move instructions share group
  /// 1111 with the floating-point unit.
  static let m68040 = ISA M68KModel.M68040

  static let assertIns40 opcode size (oprs: Operands) length hex =
    let ins = parseWith m68040 hex
    Assert.AreEqual<Opcode>(opcode, ins.Opcode)
    Assert.AreEqual<OperandSize>(size, ins.Size)
    Assert.AreEqual<Operands>(oprs, ins.Operands)
    Assert.AreEqual<uint32>(length, ins.Length)

  (* The size of a MOVE is bits 15-12 of the opcode word rather than a field of
     its own, so each of the three sizes reaches a separate dispatch arm. *)
  [<TestMethod>]
  member _.``[M68K] a register to register move test``() =
    assertIns MOVE Sz.Byte (TwoOperands(OpReg D0, OpReg D1)) 2u "1200"
    assertIns MOVE Sz.Word (TwoOperands(OpReg D0, OpReg D1)) 2u "3200"
    assertIns MOVE Sz.Long (TwoOperands(OpReg D0, OpReg D1)) 2u "2200"

  (* A destination that names an address register makes the instruction a MOVEA,
     which is its own mnemonic rather than a MOVE with an unusual operand. *)
  [<TestMethod>]
  member _.``[M68K] a move to an address register is a movea test``() =
    assertIns MOVEA Sz.Long (TwoOperands(OpReg A0, OpReg A1)) 2u "2248"
    assertIns MOVEA Sz.Word (TwoOperands(OpReg A0, OpReg A1)) 2u "3248"

  (* There is no byte of an address register to move, so a byte-sized MOVE can
     name one on neither side. *)
  [<TestMethod>]
  member _.``[M68K] a byte move rejects an address register test``() =
    assertFails m68020 "1208"
    assertFails m68020 "1240"

  (* The destination of a MOVE has to be data alterable, which rules out the two
     program counter relative modes and immediate data. Absolute short and
     absolute long share the mode field with them and stay allowed. *)
  [<TestMethod>]
  member _.``[M68K] a move rejects a non-alterable destination test``() =
    assertFails m68020 "25C0"
    assertFails m68020 "27C0"
    assertFails m68020 "29C0"
    assertIns MOVE Sz.Long (TwoOperands(OpReg D0, OpAddr 0x1234UL)) 4u
      "21C01234"

  [<TestMethod>]
  member _.``[M68K] the register indirect modes test``() =
    let direct = TwoOperands(OpMem(Direct A0), OpReg D1)
    assertIns MOVE Sz.Long direct 2u "2210"
    let oprs = TwoOperands(OpMem(PostInc A0), OpMem(PreDec A1))
    assertIns MOVE Sz.Long oprs 2u "2318"

  [<TestMethod>]
  member _.``[M68K] the displacement modes test``() =
    let disp = TwoOperands(OpMem(Disp(8s, A0)), OpReg D1)
    assertIns MOVE Sz.Long disp 4u "22280008"
    let pcRel = TwoOperands(OpMem(Disp(0x10s, PC)), OpReg D1)
    assertIns MOVE Sz.Long pcRel 4u "223A0010"
    let negative = TwoOperands(OpMem(Disp(-8s, A0)), OpReg D1)
    assertIns MOVE Sz.Long negative 4u "2228FFF8"

  (* An absolute short address is sign-extended to 32 bits, so the top half of
     the address space is what the high half of that word reaches. *)
  [<TestMethod>]
  member _.``[M68K] the absolute modes test``() =
    let short = TwoOperands(OpAddr 0x1234UL, OpReg D1)
    assertIns MOVE Sz.Long short 4u "22381234"
    let sign = TwoOperands(OpAddr 0xffff8000UL, OpReg D1)
    assertIns MOVE Sz.Long sign 4u "22388000"
    let long = TwoOperands(OpAddr 0x12345678UL, OpReg D1)
    assertIns MOVE Sz.Long long 6u "223912345678"

  (* Byte-sized immediate data occupies the low half of one whole extension
     word, so it costs a word and not a byte. *)
  [<TestMethod>]
  member _.``[M68K] the immediate modes test``() =
    let byteImm = TwoOperands(OpImm 0x7fL, OpReg D1)
    assertIns MOVE Sz.Byte byteImm 4u "123C007F"
    let wordImm = TwoOperands(OpImm 0xffffL, OpReg D1)
    assertIns MOVE Sz.Word wordImm 4u "323CFFFF"
    let long = TwoOperands(OpImm 0x12345678L, OpReg D1)
    assertIns MOVE Sz.Long long 6u "223C12345678"

  [<TestMethod>]
  member _.``[M68K] a brief format index test``() =
    let src = indexed (Some A0) (index D1 false 2) 0x10 None false
    assertIns MOVE Sz.Long (TwoOperands(src, OpReg D2)) 4u "24301210"

  (* The full format costs an extension word plus whatever its two displacement
     size fields ask for, which is where the length of an m68k instruction stops
     being a property of the opcode word alone. *)
  [<TestMethod>]
  member _.``[M68K] a full format index test``() =
    let src = indexed (Some A0) (index A2 true 4) 0x1234 None false
    let oprs = TwoOperands(src, OpReg D2)
    assertIns MOVE Sz.Long oprs 8u "2430AD3000001234"

  [<TestMethod>]
  member _.``[M68K] a memory indirect preindexed test``() =
    let src = indexed (Some A0) (index D1 false 1) 0x10 (Some 0x20) true
    let oprs = TwoOperands(src, OpReg D2)
    assertIns MOVE Sz.Long oprs 8u "2430112200100020"

  [<TestMethod>]
  member _.``[M68K] a memory indirect postindexed test``() =
    let src = indexed (Some A0) (index D1 false 1) 0x10 (Some 0x20) false
    let oprs = TwoOperands(src, OpReg D2)
    assertIns MOVE Sz.Long oprs 8u "2430112600100020"

  (* Suppressing the index leaves a mode that is indirect but not indexed, and
     a null outer displacement is still an outer displacement: what makes the
     mode indirect is that the field names a size at all. With no index there is
     no preindexing to speak of, so that flag stays down. *)
  [<TestMethod>]
  member _.``[M68K] an index suppressed indirect test``() =
    let src = indexed (Some A0) None 0x10 (Some 0) false
    assertIns MOVE Sz.Long (TwoOperands(src, OpReg D2)) 6u "243001610010"

  [<TestMethod>]
  member _.``[M68K] a base suppressed index test``() =
    let src = indexed None (index D1 false 1) 0x10 None false
    assertIns MOVE Sz.Long (TwoOperands(src, OpReg D2)) 6u "243011A00010"

  (* A base displacement size of zero, a nonzero bit 3, and the index/indirect
     selections Table 2-2 marks reserved are all encodings no assembler emits,
     so reading one means we are not looking at code. *)
  [<TestMethod>]
  member _.``[M68K] the reserved full format encodings test``() =
    assertFails m68020 "24300100"
    assertFails m68020 "24300118"
    assertFails m68020 "24300114"
    assertFails m68020 "24300154"
    assertFails m68020 "24300155"

  (* The 68000 does not decode the scale bits, so an index scaled for a 68020
     counts once on it. Bit 8 is among the bits it ignores as well, which leaves
     it reading a full extension word as a brief one: same one word, and the
     displacement is that word's low byte. *)
  [<TestMethod>]
  member _.``[M68K] a 68000 reads every extension word as brief test``() =
    let ins = parseWith m68000 "24301210"
    let scaled = indexed (Some A0) (index D1 false 1) 0x10 None false
    Assert.AreEqual<Operands>(TwoOperands(scaled, OpReg D2), ins.Operands)
    Assert.AreEqual<uint32>(4u, ins.Length)
    let full = parseWith m68000 "2430AD3000001234"
    let brief = indexed (Some A0) (index A2 true 1) 0x30 None false
    Assert.AreEqual<Operands>(TwoOperands(brief, OpReg D2), full.Operands)
    Assert.AreEqual<uint32>(4u, full.Length)

  (* The longest instruction there is: a MOVE whose source and destination both
     use a full extension word with a long base displacement and a long outer
     one. Nothing may decode to more than the MaxInstructionSize a caller sizes
     its span by. *)
  [<TestMethod>]
  member _.``[M68K] the longest instruction is 22 bytes test``() =
    let hex = "23b00133000000100000002001330000003000000040"
    let ins = parseWith m68020 hex
    let src = indexed (Some A0) (index D0 false 1) 0x10 (Some 0x20) true
    let dst = indexed (Some A1) (index D0 false 1) 0x30 (Some 0x40) true
    Assert.AreEqual<Operands>(TwoOperands(src, dst), ins.Operands)
    Assert.AreEqual<uint32>(22u, ins.Length)
    let parser = M68KParser(m68020, BinReader.Init Endian.Big)
    let maxSize = (parser :> IInstructionParsable).MaxInstructionSize
    Assert.AreEqual<int>(maxSize, int ins.Length)

  (* Group 1010 is unassigned on every model, and the groups the parser does not
     read yet are bytes it can say nothing about either. *)
  [<TestMethod>]
  member _.``[M68K] an unread group is a parse failure test``() =
    assertFails m68020 "a000"
    assertFails m68020 "0000"
    assertFails m68020 "f000"

  (* MOVEQ sign-extends its byte to the whole of the register, so the data reads
     as the negative number it is rather than as a byte-wide bit pattern. *)
  [<TestMethod>]
  member _.``[M68K] moveq sign-extends its data test``() =
    assertIns MOVEQ Sz.Long (TwoOperands(OpImm -1L, OpReg D0)) 2u "70ff"
    assertIns MOVEQ Sz.Long (TwoOperands(OpImm 1L, OpReg D7)) 2u "7e01"
    assertFails m68020 "7100"

  (* A branch says how wide its displacement is by the byte where an eight-bit
     one would sit: zero sends it to the next word, and all ones to the next
     two, which is a 68020 addition that earlier models read as the displacement
     of minus one that it looks like. *)
  [<TestMethod>]
  member _.``[M68K] the three branch displacement widths test``() =
    assertIns BRA Sz.Byte (OneOperand(OpRelAddr 0x10)) 2u "6010"
    assertIns BRA Sz.Word (OneOperand(OpRelAddr 0x10)) 4u "60000010"
    assertIns BRA Sz.Long (OneOperand(OpRelAddr 0x1234)) 6u "60ff00001234"
    let ins = parseWith m68000 "60ff00001234"
    Assert.AreEqual<Operands>(OneOperand(OpRelAddr -1), ins.Operands)
    Assert.AreEqual<uint32>(2u, ins.Length)

  [<TestMethod>]
  member _.``[M68K] the condition of a branch is its mnemonic test``() =
    assertIns BSR Sz.Byte (OneOperand(OpRelAddr 0x10)) 2u "6110"
    assertIns BHI Sz.Byte (OneOperand(OpRelAddr 0x10)) 2u "6210"
    assertIns BLE Sz.Byte (OneOperand(OpRelAddr 0x10)) 2u "6f10"

  (* A quick add of zero would do nothing, so a data field of zero means eight.
     An address register takes part whole, which leaves it no byte to add to. *)
  [<TestMethod>]
  member _.``[M68K] a quick add of zero means eight test``() =
    assertIns ADDQ Sz.Byte (TwoOperands(OpImm 8L, OpReg D0)) 2u "5000"
    assertIns ADDQ Sz.Byte (TwoOperands(OpImm 1L, OpReg D0)) 2u "5200"
    assertIns SUBQ Sz.Long (TwoOperands(OpImm 2L, OpReg D0)) 2u "5580"
    assertFails m68020 "5008"
    assertFails m68020 "5108"

  (* The conditions that never occur to a branch do occur to the other three
     conditional families, where they are the mnemonics ST, SF, DBT, and DBF. *)
  [<TestMethod>]
  member _.``[M68K] the always and never conditions test``() =
    assertIns ST Sz.Byte (OneOperand(OpReg D0)) 2u "50c0"
    assertIns SF Sz.Byte (OneOperand(OpReg D0)) 2u "51c0"
    let dbf = TwoOperands(OpReg D0, OpRelAddr 0x10)
    assertIns DBF Sz.Word dbf 4u "51c80010"

  [<TestMethod>]
  member _.``[M68K] the three trapcc operand widths test``() =
    assertIns TRAPHI Sz.Word (OneOperand(OpImm 0x1234L)) 4u "52fa1234"
    let long = OneOperand(OpImm 0x12345678L)
    assertIns TRAPHI Sz.Long long 6u "52fb12345678"
    assertIns TRAPHI Sz.NoSize NoOperand 2u "52fc"
    assertFails m68020 "52fd"

  (* MOVEM writes its register list as a mask, and predecrement addressing runs
     that mask the other way round, A7 standing at bit 0 where D0 otherwise
     does. *)
  [<TestMethod>]
  member _.``[M68K] a movem mask runs backwards under predecrement test``() =
    let oprs = TwoOperands(OpRegList [| A6; A7 |], OpMem(PreDec A7))
    assertIns MOVEM Sz.Word oprs 4u "48a70003"
    let oprs = TwoOperands(OpMem(PostInc A7), OpRegList [| D0; D1 |])
    assertIns MOVEM Sz.Long oprs 4u "4cdf0003"

  [<TestMethod>]
  member _.``[M68K] the system instructions test``() =
    assertIns TRAP Sz.NoSize (OneOperand(OpImm 3L)) 2u "4e43"
    let link = TwoOperands(OpReg A6, OpImm 0x10L)
    assertIns LINK Sz.Word link 4u "4e560010"
    assertIns UNLK Sz.NoSize (OneOperand(OpReg A6)) 2u "4e5e"
    assertIns NOP Sz.NoSize NoOperand 2u "4e71"
    assertIns RTS Sz.NoSize NoOperand 2u "4e75"
    assertIns ILLEGAL Sz.NoSize NoOperand 2u "4afc"
    assertIns STOP Sz.NoSize (OneOperand(OpImm 0x1234L)) 4u "4e721234"

  (* MOVEC names a control register by a code of its own, and any code the model
     leaves unassigned is an illegal instruction rather than a register. *)
  [<TestMethod>]
  member _.``[M68K] movec names a control register by code test``() =
    let fromVbr = TwoOperands(OpReg VBR, OpReg D0)
    assertIns MOVEC Sz.Long fromVbr 4u "4e7a0801"
    let toSfc = TwoOperands(OpReg D1, OpReg SFC)
    assertIns MOVEC Sz.Long toSfc 4u "4e7b1000"
    assertFails m68020 "4e7a0808"
    assertFails m68020 "4e7a0003"

  (* A shift by zero places would do nothing, so a count field of zero means
     eight; setting the bit above the count names a register instead. *)
  [<TestMethod>]
  member _.``[M68K] a shift count of zero means eight test``() =
    assertIns ASL Sz.Byte (TwoOperands(OpImm 8L, OpReg D0)) 2u "e100"
    assertIns ASL Sz.Byte (TwoOperands(OpReg D0, OpReg D0)) 2u "e120"
    assertIns ASR Sz.Word (OneOperand(OpMem(Direct A0))) 2u "e0d0"
    assertFails m68020 "e0c0"

  (* A bit field of no bits is no field, so a width of zero means the whole
     thirty-two. Where a register holds the offset or the width, the bits that
     would have held the literal have to be zero. *)
  [<TestMethod>]
  member _.``[M68K] a bit field width of zero means 32 test``() =
    let spec = { Offset = OpImm 0x1fL; Width = OpImm 32L }
    let field = OpBitField(OpReg D0, spec)
    assertIns BFTST Sz.NoSize (OneOperand field) 4u "e8c007c0"
    let inReg = { Offset = OpReg D0; Width = OpReg D0 }
    let field = OpBitField(OpReg D0, inReg)
    assertIns BFTST Sz.NoSize (OneOperand field) 4u "e8c00820"
    assertFails m68020 "e8c00e20"
    assertFails m68020 "e8c00838"

  [<TestMethod>]
  member _.``[M68K] the three exchanges test``() =
    assertIns EXG Sz.Long (TwoOperands(OpReg D0, OpReg D0)) 2u "c140"
    assertIns EXG Sz.Long (TwoOperands(OpReg A0, OpReg A0)) 2u "c148"
    assertIns EXG Sz.Long (TwoOperands(OpReg D0, OpReg A0)) 2u "c188"
    assertFails m68020 "c180"

  (* A dividend of one register leaves a remainder to put somewhere, which is
     what makes the mnemonic DIVSL rather than DIVS. *)
  [<TestMethod>]
  member _.``[M68K] a long divide names its dividend width test``() =
    let pair = TwoOperands(OpReg D0, OpRegPair(D0, D0))
    assertIns DIVSL Sz.Long pair 4u "4c400800"
    assertIns DIVS Sz.Long pair 4u "4c400c00"
    assertIns DIVUL Sz.Long pair 4u "4c400000"
    let single = TwoOperands(OpReg D0, OpReg D0)
    assertIns MULS Sz.Long single 4u "4c000800"
    let wide = TwoOperands(OpReg D0, OpRegPair(D0, D0))
    assertIns MULS Sz.Long wide 4u "4c000c00"

  (* The 68020 widened TST to any addressing mode at all, there being nothing to
     write back, but left it no byte of an address register to test. *)
  [<TestMethod>]
  member _.``[M68K] the 68020 widened tst test``() =
    assertIns TST Sz.Long (OneOperand(OpImm 0x1L)) 6u "4abc00000001"
    assertFails m68000 "4abc00000001"
    assertFails m68020 "4a08"

  (* Every one of these is an encoding a later model gave a meaning to, so the
     68000 has to refuse it rather than read it as whatever it resembles. *)
  [<TestMethod>]
  member _.``[M68K] the model gate refuses later encodings test``() =
    assertFails m68000 "4100"
    assertFails m68000 "e8c007c0"
    assertFails m68000 "52fc"
    assertFails m68000 "480e00001234"
    assertFails m68000 "4e7a0801"
    assertFails m68000 "4e740010"
    assertFails m68000 "8140ffff"
    assertFails m68000 "49c0"
    assertFails m68000 "4c000800"
    assertFails m68000 "00d00000"

  (* A floating-point operation names itself in the command word that follows
     the opcode word, and where its source is an effective address the source
     specifier names the format to read it in, which is what the mnemonic's
     suffix says. *)
  [<TestMethod>]
  member _.``[M68K] a floating-point operation names itself twice test``() =
    let regs = TwoOperands(OpReg FP0, OpReg FP1)
    assertIns FMOVE Sz.Extended regs 4u "f2000080"
    assertIns FADD Sz.Extended (TwoOperands(OpReg FP0, OpReg FP0)) 4u "f2000022"
    let fromMem = TwoOperands(OpMem(Direct A0), OpReg FP0)
    assertIns FADD Sz.Single fromMem 4u "f2104422"
    assertIns FSQRT Sz.Double (TwoOperands(OpMem(Direct A0), OpReg FP0)) 4u
      "f2105404"

  (* A data register stands in for memory only where the format is no wider than
     it is, which the manual states as byte, word, long, or single. *)
  [<TestMethod>]
  member _.``[M68K] a data register holds no wide format test``() =
    let narrow = TwoOperands(OpReg D0, OpReg FP0)
    assertIns FADD Sz.Long narrow 4u "f2004022"
    assertFails m68020 "f2004822"

  (* FTST reads its operand and writes nothing, and FSINCOS writes two
     registers, so neither has the two operands the rest of the family does. *)
  [<TestMethod>]
  member _.``[M68K] the odd floating-point operand counts test``() =
    assertIns FTST Sz.Extended (OneOperand(OpReg FP0)) 4u "f200003a"
    let sincos = ThreeOperands(OpReg FP0, OpReg FP1, OpReg FP0)
    assertIns FSINCOS Sz.Extended sincos 4u "f2000031"

  (* An FBcc carries its condition in the opcode word rather than in a command
     word of its own, and bit 6 says whether the displacement is one word or
     two. *)
  [<TestMethod>]
  member _.``[M68K] a floating-point branch test``() =
    assertIns FBEQ Sz.Word (OneOperand(OpRelAddr 0x10)) 4u "f2810010"
    let long = OneOperand(OpRelAddr 0x10)
    assertIns FBEQ Sz.Long long 6u "f2c100000010"
    assertIns FBF Sz.Word (OneOperand(OpRelAddr 0x10)) 4u "f2800010"

  (* One control register makes an FMOVE and several an FMOVEM, and a register
     holds one long word, so a list of several has to be somewhere in memory. *)
  [<TestMethod>]
  member _.``[M68K] the floating-point control registers test``() =
    let single = TwoOperands(OpMem(PostInc A7), OpReg FPSR)
    assertIns FMOVE Sz.Long single 4u "f21f8800"
    let both = TwoOperands(OpMem(PostInc A7), OpRegList [| FPCR; FPSR |])
    assertIns FMOVEM Sz.Long both 4u "f21f9800"
    assertFails m68020 "f2009800"

  (* The mode field of an FMOVEM says which way it walks memory, so it has to
     agree both with the addressing mode and with the direction of the move. *)
  [<TestMethod>]
  member _.``[M68K] an fmovem walks memory one way test``() =
    let regs = OpRegList [| FP0; FP1 |]
    let load = TwoOperands(OpMem(PostInc A7), regs)
    assertIns FMOVEM Sz.Extended load 4u "f21fd003"
    let store = TwoOperands(OpRegList [| FP6; FP7 |], OpMem(PreDec A7))
    assertIns FMOVEM Sz.Extended store 4u "f227e003"
    assertFails m68020 "f21fe003"
    assertFails m68020 "f227d003"

  (* The 68040 spells the scope of a cache operation into the mnemonic and names
     the caches themselves as an operand. *)
  [<TestMethod>]
  member _.``[M68K] the cache instructions test``() =
    let line = TwoOperands(OpCaches 1uy, OpMem(Direct A0))
    assertIns40 CINVL Sz.NoSize line 2u "f448"
    let page = TwoOperands(OpCaches 3uy, OpMem(Direct A0))
    assertIns40 CPUSHP Sz.NoSize page 2u "f4f0"
    assertIns40 CINVA Sz.NoSize (OneOperand(OpCaches 2uy)) 2u "f498"
    assertFails m68040 "f440"
    assertFails m68020 "f448"

  [<TestMethod>]
  member _.``[M68K] the translation cache instructions test``() =
    assertIns40 PFLUSHN Sz.NoSize (OneOperand(OpMem(Direct A0))) 2u "f500"
    assertIns40 PFLUSH Sz.NoSize (OneOperand(OpMem(Direct A0))) 2u "f508"
    assertIns40 PFLUSHAN Sz.NoSize NoOperand 2u "f510"
    assertIns40 PFLUSHA Sz.NoSize NoOperand 2u "f518"
    assertIns40 PTESTW Sz.NoSize (OneOperand(OpMem(Direct A0))) 2u "f548"
    assertIns40 PTESTR Sz.NoSize (OneOperand(OpMem(Direct A0))) 2u "f568"

  (* MOVE16 either names two postincremented registers, carrying a second word
     for the destination, or one register and an absolute long address. *)
  [<TestMethod>]
  member _.``[M68K] move16 test``() =
    let toAbs = TwoOperands(OpMem(PostInc A0), OpAddr 0x12345678UL)
    assertIns40 MOVE16 Sz.NoSize toAbs 6u "f60012345678"
    let pair = TwoOperands(OpMem(PostInc A0), OpMem(PostInc A1))
    assertIns40 MOVE16 Sz.NoSize pair 4u "f6209000"
    assertFails m68040 "f640"

  (* The floating-point coprocessor is not on a 68000, and neither the cache nor
     the translation instructions are on anything before a 68040. *)
  [<TestMethod>]
  member _.``[M68K] the model gate refuses the coprocessor test``() =
    assertFails m68000 "f2000080"
    assertFails m68000 "f2810010"
    assertFails m68020 "f4e8"
    assertFails m68020 "f518"
    assertFails m68020 "f60012345678"
