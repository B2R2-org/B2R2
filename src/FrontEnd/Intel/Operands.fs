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

namespace B2R2.FrontEnd.Intel

open System
open System.Collections.Generic
open System.Runtime.CompilerServices
open B2R2

/// Represents the scaling factor used in index addressing.
type Scale =
  /// Times 1
  | X1 = 1
  /// Times 2
  | X2 = 2
  /// Times 4
  | X4 = 4
  /// Times 8
  | X8 = 8

/// Represents a scaled index composed of a register and a scaling factor.
type ScaledIndex = (struct (Register * Scale))

/// Represents a displacement value used for memory offset calculations.
type Displacement = int64

/// Represents operand size.
type OperandSize = RegType

/// Represents a segment selector used in intel architecture.
type SegmentSelector = int16

/// Represents an offset value used for relative jump instructions.
type Offset = int64

/// Represents the target of a jump instruction.
[<Struct>]
type JumpTarget =
  | Absolute of selector: SegmentSelector * address: Addr * size: OperandSize
  | Relative of offset: Offset

/// Which case an operand holds.
type OperandKind =
  /// A register.
  | Reg = 0uy
  /// A memory reference.
  | Mem = 1uy
  /// An immediate.
  | Imm = 2uy
  /// A relative branch target.
  | Relative = 3uy
  /// An absolute (far) branch target.
  | Absolute = 4uy
  /// A label, which only the assembler makes.
  | Label = 5uy

/// The names of the label operands made so far. A label operand keeps an
/// index into this table rather than the string, so that an operand holds no
/// reference and an instruction can carry its operands inline.
module internal LabelNames =
  let private names = ResizeArray<string>()

  let private ids = Dictionary<string, int>()

  /// The index of the name, adding it when it is new.
  let intern (name: string) =
    lock names (fun () ->
      match ids.TryGetValue name with
      | true, id ->
        id
      | _ ->
        let id = names.Count
        names.Add name
        ids[name] <- id
        id)

  /// The name at the index.
  let name (id: int) = lock names (fun () -> names[id])

/// Represents four different types of intel operands: register, memory,
/// direct address, and immediate, plus the label the assembler uses before
/// it knows an address. An operand is a 16-byte value holding no reference,
/// which is what lets an instruction carry its operands inline: as heap
/// objects they were three allocations and eight reference stores per
/// instruction, the largest single cost of parsing. The cases are read
/// through the OprReg, OprMem, OprDirAddr, OprImm and Label patterns and
/// made with the static members of the same names (open type Operand brings
/// them into scope unqualified), as when they were union cases. It has three
/// fields on purpose: the JIT keeps a struct of up to four primitive fields
/// in registers, and one with more is copied through memory at every step.
[<Struct; CustomEquality; NoComparison>]
type Operand =
  /// The displacement, the immediate, the branch offset or address, or the
  /// label's index, by kind. Zero where the kind has none.
  val internal Value: int64
  /// Bits 0-15: the register, the memory base register or the far pointer's
  /// segment selector; bits 16-31: the memory index register. Operand.NoReg
  /// marks an absent register.
  val internal Regs: uint32
  /// Bits 0-15: the operand size in bits; bits 16-23: the kind; bits 24-25:
  /// the index scale of a memory operand as a power of two; bit 26: set when
  /// a memory operand carries a displacement.
  val internal Meta: uint32

  [<MethodImpl(MethodImplOptions.AggressiveInlining)>]
  internal new(kind: OperandKind, value, regs, bits: uint16, flags: byte) =
    { Value = value
      Regs = regs
      Meta = uint32 bits ||| (uint32 kind <<< 16) ||| (uint32 flags <<< 24) }

  /// The register field value that marks no register.
  static member internal NoReg = 0xFFFFu

  /// Which case this is.
  member this.Kind =
    LanguagePrimitives.EnumOfValue<byte, OperandKind>(byte (this.Meta >>> 16))

  /// The operand size in bits.
  member internal this.Bits = uint16 this.Meta

  /// The memory operand's scale and displacement flags.
  member internal this.Flags = byte (this.Meta >>> 24)

  /// The register (OprReg) or the base register (OprMem).
  member internal this.Register =
    LanguagePrimitives.EnumOfValue<int, Register>(int (this.Regs &&& 0xFFFFu))

  /// Whether a memory operand names a base register.
  member internal this.HasBase = this.Regs &&& 0xFFFFu <> Operand.NoReg

  /// The index register of a memory operand.
  member internal this.Index =
    LanguagePrimitives.EnumOfValue<int, Register>(int (this.Regs >>> 16))

  /// Whether a memory operand names an index register.
  member internal this.HasIndex = this.Regs >>> 16 <> Operand.NoReg

  /// The scale of the index register.
  member internal this.Scale =
    LanguagePrimitives.EnumOfValue<int, Scale>(1 <<< int (this.Flags &&& 3uy))

  /// Whether a memory operand carries a displacement.
  member internal this.HasDisp = this.Meta &&& 0x4000000u <> 0u

  /// The segment selector of an absolute branch target.
  member internal this.Selector = int16 (this.Regs &&& 0xFFFFu)

  /// The base register of a memory operand, if any.
  member internal this.MemBase =
    if this.HasBase then ValueSome this.Register else ValueNone

  /// The scaled index of a memory operand, if any.
  member internal this.MemIndex: ScaledIndex voption =
    if this.HasIndex then ValueSome(struct (this.Index, this.Scale))
    else ValueNone

  /// The displacement of a memory operand, if any.
  member internal this.MemDisp =
    if this.HasDisp then ValueSome this.Value else ValueNone

  /// The operand size: the memory access, immediate, or address width.
  member this.Size: RegType =
    LanguagePrimitives.Int32WithMeasure<rt>(int this.Bits)

  /// The register operand.
  [<MethodImpl(MethodImplOptions.AggressiveInlining)>]
  static member OprReg(r: Register) =
    Operand(OperandKind.Reg, 0L, uint32 (int r) ||| 0xFFFF0000u, 0us, 0uy)

  /// The memory operand with the given base, scaled index, displacement and
  /// access size, any of the first three absent.
  static member OprMem(b: Register voption,
                       si: ScaledIndex voption,
                       d: Displacement voption,
                       sz: OperandSize) =
    let bBits =
      match b with
      | ValueSome r -> uint32 (int r)
      | ValueNone -> Operand.NoReg
    let struct (iBits, scale) =
      match si with
      | ValueSome(struct (r, s)) ->
        let log2 =
          match s with
          | Scale.X1 -> 0uy
          | Scale.X2 -> 1uy
          | Scale.X4 -> 2uy
          | _ -> 3uy
        struct (uint32 (int r) <<< 16, log2)
      | ValueNone ->
        struct (Operand.NoReg <<< 16, 0uy)
    let struct (disp, flag) =
      match d with
      | ValueSome d -> struct (d, 4uy)
      | ValueNone -> struct (0L, 0uy)
    let bits = uint16 (int sz)
    Operand(OperandKind.Mem, disp, bBits ||| iBits, bits, scale ||| flag)

  /// The direct branch target operand.
  static member OprDirAddr(t: JumpTarget) =
    match t with
    | Absolute(sel, addr, sz) ->
      let regs = uint32 (uint16 sel) ||| 0xFFFF0000u
      Operand(OperandKind.Absolute, int64 addr, regs, uint16 (int sz), 0uy)
    | Relative offset ->
      Operand(OperandKind.Relative, offset, 0xFFFFFFFFu, 0us, 0uy)

  /// The immediate operand of the given value and encoded width.
  [<MethodImpl(MethodImplOptions.AggressiveInlining)>]
  static member OprImm(v: int64, sz: OperandSize) =
    Operand(OperandKind.Imm, v, 0xFFFFFFFFu, uint16 (int sz), 0uy)

  /// The label operand, for the assembler.
  static member Label(name: string, sz: RegType) =
    let id = int64 (LabelNames.intern name)
    Operand(OperandKind.Label, id, 0xFFFFFFFFu, uint16 (int sz), 0uy)

  member this.Equals(o: Operand) =
    this.Value = o.Value && this.Regs = o.Regs && this.Meta = o.Meta

  override this.Equals(o: obj) =
    match o with
    | :? Operand as x -> this.Equals x
    | _ -> false

  override this.GetHashCode() =
    HashCode.Combine(this.Value, this.Regs, this.Meta)

  override this.ToString() =
    let opt (present: bool) (v: string) =
      if present then "ValueSome " + v else "ValueNone"
    match this.Kind with
    | OperandKind.Reg ->
      "OprReg " + this.Register.ToString()
    | OperandKind.Mem ->
      let si = sprintf "(%s, %A)" (this.Index.ToString()) this.Scale
      sprintf "OprMem (%s, %s, %s, %d<rt>)"
        (opt this.HasBase (this.Register.ToString()))
        (opt this.HasIndex si)
        (opt this.HasDisp (sprintf "%dL" this.Value))
        (int this.Bits)
    | OperandKind.Imm ->
      sprintf "OprImm (%dL, %d<rt>)" this.Value (int this.Bits)
    | OperandKind.Relative ->
      sprintf "OprDirAddr (Relative %dL)" this.Value
    | OperandKind.Absolute ->
      sprintf "OprDirAddr (Absolute (%ds, %dUL, %d<rt>))"
        this.Selector (uint64 this.Value) (int this.Bits)
    | _ ->
      sprintf "Label (%s, %d<rt>)" (LabelNames.name (int this.Value))
        (int this.Bits)

  interface IEquatable<Operand> with
    member this.Equals(o: Operand) = this.Equals o

/// Represents the operands of an intel instruction: up to four, kept inline
/// in the order they are written. Read through the NoOperand, OneOperand,
/// TwoOperands, ThreeOperands and FourOperands patterns, or by position, and
/// made with the static members of the same names (open type Operands brings
/// them into scope unqualified).
[<Struct; CustomEquality; NoComparison>]
type Operands =
  /// How many operands the value holds.
  val Count: int
  val internal O1: Operand
  val internal O2: Operand
  val internal O3: Operand
  val internal O4: Operand

  [<MethodImpl(MethodImplOptions.AggressiveInlining)>]
  internal new(count, o1, o2, o3, o4) =
    { Count = count; O1 = o1; O2 = o2; O3 = o3; O4 = o4 }

  /// No operand at all.
  static member NoOperand =
    Operands(0, Operand(), Operand(), Operand(), Operand())

  /// The operand at the given position, counting from the one written first.
  /// Reading them by position is what lets a caller relate an operand to
  /// something outside the list -- an EVEX decoration attaches to a position,
  /// not to a shape.
  member this.Item
    with get(i: int) =
      match i with
      | 0 when this.Count > 0 -> this.O1
      | 1 when this.Count > 1 -> this.O2
      | 2 when this.Count > 2 -> this.O3
      | 3 when this.Count > 3 -> this.O4
      | _ -> raise (IndexOutOfRangeException())

  /// One operand.
  [<MethodImpl(MethodImplOptions.AggressiveInlining)>]
  static member OneOperand(a: Operand) =
    Operands(1, a, Operand(), Operand(), Operand())

  /// Two operands, in the order they are written.
  [<MethodImpl(MethodImplOptions.AggressiveInlining)>]
  static member TwoOperands(a: Operand, b: Operand) =
    Operands(2, a, b, Operand(), Operand())

  /// Three operands, in the order they are written.
  [<MethodImpl(MethodImplOptions.AggressiveInlining)>]
  static member ThreeOperands(a: Operand, b: Operand, c: Operand) =
    Operands(3, a, b, c, Operand())

  /// Four operands, in the order they are written.
  [<MethodImpl(MethodImplOptions.AggressiveInlining)>]
  static member FourOperands(a: Operand, b: Operand, c: Operand, d: Operand) =
    Operands(4, a, b, c, d)

  member this.Equals(o: Operands) =
    this.Count = o.Count && this.O1.Equals o.O1 && this.O2.Equals o.O2
    && this.O3.Equals o.O3 && this.O4.Equals o.O4

  override this.Equals(o: obj) =
    match o with
    | :? Operands as x -> this.Equals x
    | _ -> false

  override this.GetHashCode() =
    HashCode.Combine(this.Count, this.O1, this.O2, this.O3, this.O4)

  override this.ToString() =
    match this.Count with
    | 0 ->
      "NoOperand"
    | 1 ->
      sprintf "OneOperand (%O)" this.O1
    | 2 ->
      sprintf "TwoOperands (%O, %O)" this.O1 this.O2
    | 3 ->
      sprintf "ThreeOperands (%O, %O, %O)" this.O1 this.O2 this.O3
    | _ ->
      sprintf "FourOperands (%O, %O, %O, %O)" this.O1 this.O2 this.O3 this.O4

  interface IEquatable<Operands> with
    member this.Equals(o: Operands) = this.Equals o

/// The cases of an operand and of an operand list as patterns, under the
/// names the union cases had: code written for the unions reads the values
/// unchanged, except that the parts of a memory operand are value options.
[<AutoOpen>]
module OperandPatterns =
  /// The case an operand holds.
  let (|OprReg|OprMem|OprDirAddr|OprImm|Label|) (o: Operand) =
    match o.Kind with
    | OperandKind.Reg ->
      OprReg o.Register
    | OperandKind.Mem ->
      OprMem(struct (o.MemBase, o.MemIndex, o.MemDisp, o.Size))
    | OperandKind.Imm ->
      OprImm(struct (o.Value, o.Size))
    | OperandKind.Relative ->
      OprDirAddr(Relative o.Value)
    | OperandKind.Absolute ->
      OprDirAddr(Absolute(o.Selector, uint64 o.Value, o.Size))
    | _ ->
      Label(struct (LabelNames.name (int o.Value), o.Size))

  [<return: Struct>]
  let (|NoOperand|_|) (o: Operands) =
    if o.Count = 0 then ValueSome() else ValueNone

  [<return: Struct>]
  let (|OneOperand|_|) (o: Operands) =
    if o.Count = 1 then ValueSome o.O1 else ValueNone

  [<return: Struct>]
  let (|TwoOperands|_|) (o: Operands) =
    if o.Count = 2 then ValueSome(struct (o.O1, o.O2)) else ValueNone

  [<return: Struct>]
  let (|ThreeOperands|_|) (o: Operands) =
    if o.Count = 3 then ValueSome(struct (o.O1, o.O2, o.O3)) else ValueNone

  [<return: Struct>]
  let (|FourOperands|_|) (o: Operands) =
    if o.Count = 4 then ValueSome(struct (o.O1, o.O2, o.O3, o.O4))
    else ValueNone

/// Provides several accessor functions for operands.
[<RequireQualifiedAccess>]
module internal Operands =
  let inline getMod (byte: byte) = (int byte >>> 6) &&& 0b11

  let inline getReg (byte: byte) = (int byte >>> 3) &&& 0b111

  let inline getRM (byte: byte) = (int byte) &&& 0b111

  /// The register operand naming the given register.
  let inline oprReg (r: Register) = Operand.OprReg r

  /// The operands value holding the given operand alone.
  let inline oneOperand (o: Operand) = Operands.OneOperand o

  /// The operands value holding the two given operands, in that order.
  let inline twoOperands (o1: Operand) (o2: Operand) =
    Operands.TwoOperands(o1, o2)

  /// The operands value holding the two given registers, in that order.
  let inline twoRegs (a: Register) (b: Register) =
    Operands.TwoOperands(Operand.OprReg a, Operand.OprReg b)

  /// The operands value holding the given register alone.
  let inline oneReg (r: Register) = Operands.OneOperand(Operand.OprReg r)

  /// The immediate operand of the given value and width.
  let inline oprImm (v: int64) (sz: RegType) = Operand.OprImm(v, sz)

  /// The direct-address operand of a branch to the given relative target.
  let inline relTarget (d: int64) =
    Operand(OperandKind.Relative, d, 0xFFFFFFFFu, 0us, 0uy)

  /// How many operands the value holds.
  let inline count (oprs: Operands) = oprs.Count

  /// The operand at the given position, counting from the one written first.
  let inline item i (oprs: Operands) = oprs[i]

  let inline getSTReg n = RegisterHelper.streg n |> oprReg

  let inline modIsMemory b = (getMod b) <> 0b11

  let inline modIsReg b = (getMod b) = 0b11

// vim: set tw=80 sts=2 sw=2:
