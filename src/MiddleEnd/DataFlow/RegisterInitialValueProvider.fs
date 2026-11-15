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

namespace B2R2.MiddleEnd.DataFlow

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter

/// Provides the initial values of registers for a data-flow analysis.
[<RequireQualifiedAccess>]
module RegisterInitialValueProvider =
  type private IntelRegisterInitialValueProvider(hdl: BinHandle) =
    let dsBase = Intel.Register.toRegID Intel.Register.DSBase
    interface IRegisterInitialValueProvider with
      member _.TryGetInitialValue rid =
        if rid = dsBase then
          Some(BitVector.Zero(hdl.RegisterFactory.GetRegType rid))
        else
          None

  type private DefaultRegisterInitialValueProvider() =
    interface IRegisterInitialValueProvider with
      member _.TryGetInitialValue _ = None

  /// Gives the MIPS zero register zero, which it always holds: the lifter
  /// keeps it from being written, so it holds its initial value throughout.
  type private MIPSRegisterInitialValueProvider(hdl: BinHandle) =
    let zero = MIPS.Register.toRegID MIPS.Register.R0
    interface IRegisterInitialValueProvider with
      member _.TryGetInitialValue rid =
        if rid = zero then
          Some(BitVector.Zero(hdl.RegisterFactory.GetRegType rid))
        else
          None

  /// Gives t9 the address of the function on entry, which is where the MIPS
  /// PIC calling convention has a caller put it, and where the function finds
  /// gp from.
  type private MIPSFunctionInitialValueProvider(hdl: BinHandle, entry: Addr) =
    let registers = MIPSRegisterInitialValueProvider hdl
    let t9 = MIPS.Register.toRegID MIPS.Register.R25
    interface IRegisterInitialValueProvider with
      member _.TryGetInitialValue rid =
        if rid = t9 then
          Some(BitVector(entry, hdl.RegisterFactory.GetRegType rid))
        else
          (registers :> IRegisterInitialValueProvider).TryGetInitialValue rid

  /// Creates the architecture-specific provider of initial values for a binary.
  let create (hdl: BinHandle): IRegisterInitialValueProvider =
    match hdl.RegisterFactory.ISA.Arch with
    | Architecture.Intel -> IntelRegisterInitialValueProvider(hdl)
    | Architecture.MIPS -> MIPSRegisterInitialValueProvider(hdl)
    | _ -> DefaultRegisterInitialValueProvider()

  /// Creates the architecture-specific provider of initial values for the
  /// function at the given entry, which may hold what the binary as a whole
  /// does not tell.
  let createForFunction (hdl: BinHandle) entry: IRegisterInitialValueProvider =
    match hdl.RegisterFactory.ISA.Arch with
    | Architecture.MIPS -> MIPSFunctionInitialValueProvider(hdl, entry)
    | _ -> create hdl

  /// Returns the initial value of a regular register variable.
  let tryGetInitialVarValue (provider: IRegisterInitialValueProvider) =
    function
    | Regular rid -> provider.TryGetInitialValue rid
    | _ -> None
