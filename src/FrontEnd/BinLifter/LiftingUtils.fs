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

/// Provides several utility functions for lifting binary code to IR.
module B2R2.FrontEnd.BinLifter.LiftingUtils

open B2R2
open B2R2.BinIR.LowUIR

/// Creates a new number expression from a given uint32 value.
let inline numU32 n t = BitVector.OfUInt32(n, t) |> AST.num

/// Creates a new number expression from a given int32 value.
let inline numI32 n t = BitVector.OfInt32(n, t) |> AST.num

/// Creates a new number expression from a given uint64 value.
let inline numU64 n t = BitVector.OfUInt64(n, t) |> AST.num

/// Creates a new number expression from a given int64 value.
let inline numI64 n t = BitVector.OfInt64(n, t) |> AST.num

/// Creates a new temporary variable with the given type.
let inline tmpVar (builder: ILowUIRBuilder) rt =
  builder.Stream.NewTempVar rt

/// Creates two new temporary variables with the given type.
let inline tmpVars2 (builder: ILowUIRBuilder) rt =
  struct (tmpVar builder rt, tmpVar builder rt)

/// Creates three new temporary variables with the given type.
let inline tmpVars3 (builder: ILowUIRBuilder) rt =
  struct (tmpVar builder rt, tmpVar builder rt, tmpVar builder rt)

/// Creates four new temporary variables with the given type.
let inline tmpVars4 (builder: ILowUIRBuilder) rt =
  struct (tmpVar builder rt,
          tmpVar builder rt,
          tmpVar builder rt,
          tmpVar builder rt)

/// Creates a new label with the given name.
let inline label (builder: ILowUIRBuilder) name =
  builder.Stream.NewLabel name

/// Creates a new register variable with the given register enum.
let inline regVar (builder: ILowUIRBuilder) reg =
  LanguagePrimitives.EnumToValue reg
  |> RegisterID.create
  |> builder.GetRegVar

/// Creates a new pseudo-register variable with the given register enum.
let inline pseudoRegVar (builder: ILowUIRBuilder) reg pos =
  let rid = LanguagePrimitives.EnumToValue reg |> RegisterID.create
  builder.GetPseudoRegVar rid pos

/// Creates two new pseudo-register variables for a 128-bit register of the
/// given register enum.
let inline pseudoRegVar128 (builder: ILowUIRBuilder) reg =
  struct (pseudoRegVar builder reg 2, pseudoRegVar builder reg 1)

/// Creates four new pseudo-register variables for a 256-bit register of the
/// given register enum.
let inline pseudoRegVar256 (builder: ILowUIRBuilder) reg =
  struct (pseudoRegVar builder reg 4,
          pseudoRegVar builder reg 3,
          pseudoRegVar builder reg 2,
          pseudoRegVar builder reg 1)

/// Creates eight new pseudo-register variables for a 512-bit register of the
/// given register enum.
let inline pseudoRegVar512 (builder: ILowUIRBuilder) reg =
  struct (pseudoRegVar builder reg 8,
          pseudoRegVar builder reg 7,
          pseudoRegVar builder reg 6,
          pseudoRegVar builder reg 5,
          pseudoRegVar builder reg 4,
          pseudoRegVar builder reg 3,
          pseudoRegVar builder reg 2,
          pseudoRegVar builder reg 1)

/// Appends a statement to the given builder. A builder is defined for each
/// different CPU architecture, so this function is only useful if the builder
/// implements the `Stream` member.
let inline (<+) (builder: ILowUIRBuilder) stmt =
  builder.Stream.Append stmt

/// Marks the start of an instruction by appending an ISMark statement to the
/// given builder. A builder is defined for each different CPU architecture,
/// so this function is only useful if the builder implements the `Stream`
/// member.
let inline (<!--) (builder: ILowUIRBuilder) (addr, insLen) =
  builder.Stream.MarkStart (addr, insLen)

/// Marks the end of an instruction by appending an IEMark statement to the
/// given builder. A builder is defined for each different CPU architecture,
/// so this function is only useful if the builder implements the `Stream`
/// member.
let inline (--!>) (builder: ILowUIRBuilder) insLen =
  builder.Stream.MarkEnd insLen
  builder

[<RequireQualifiedAccess>]
module IEEE754Single =
  open B2R2.BinIR.LowUIR.AST.InfixOp

  let inline private hasFraction x =
    (x .& numU32 0x7fffffu 32<rt>) != AST.num0 32<rt>

  let isNaN x =
    let exponent = (x >> numI32 23 32<rt>) .& numI32 0xff 32<rt>
    let e = numI32 0xff 32<rt>
    AST.xtlo 1<rt> ((exponent == e) .& hasFraction x)

  let isSNaN x =
    let nanChecker = isNaN x
    let signalBit = numU32 (1u <<< 22) 32<rt>
    nanChecker .& ((x .& signalBit) == AST.num0 32<rt>)

  let isQNaN x =
    let nanChecker = isNaN x
    let signalBit = numU32 (1u <<< 22) 32<rt>
    nanChecker .& ((x .& signalBit) != AST.num0 32<rt>)

  let isInfinity x =
    let exponent = (x >> numI32 23 32<rt>) .& numI32 0xff 32<rt>
    let fraction = x .& numU32 0x7fffffu 32<rt>
    let e = numI32 0xff 32<rt>
    let zero = AST.num0 32<rt>
    AST.xtlo 1<rt> ((exponent == e) .& (fraction == zero))

  let isZero x =
    let mask = numU32 0x7fffffffu 32<rt>
    AST.eq (x .& mask) (AST.num0 32<rt>)

[<RequireQualifiedAccess>]
module IEEE754Double =
  open B2R2.BinIR.LowUIR.AST.InfixOp

  let inline private hasFraction x =
    (x .& numU64 0xfffff_ffffffffUL 64<rt>) != AST.num0 64<rt>

  let isNaN x =
    let exponent = (x >> numI32 52 64<rt>) .& numI32 0x7ff 64<rt>
    let e = numI32 0x7ff 64<rt>
    AST.xtlo 1<rt> ((exponent == e) .& hasFraction x)

  let isSNaN x =
    let nanChecker = isNaN x
    let signalBit = numU64 (1UL <<< 51) 64<rt>
    nanChecker .& ((x .& signalBit) == AST.num0 64<rt>)

  let isQNaN x =
    let nanChecker = isNaN x
    let signalBit = numU64 (1UL <<< 51) 64<rt>
    nanChecker .& ((x .& signalBit) != AST.num0 64<rt>)

  let isInfinity x =
    let exponent = (x >> numI32 52 64<rt>) .& numI32 0x7ff 64<rt>
    let fraction = x .& numU64 0xfffff_ffffffffUL 64<rt>
    let e = numI32 0x7ff 64<rt>
    let zero = AST.num0 64<rt>
    AST.xtlo 1<rt> ((exponent == e) .& (fraction == zero))

  let isZero x =
    let mask = numU64 0x7fffffff_ffffffffUL 64<rt>
    AST.eq (x .& mask) (AST.num0 64<rt>)
