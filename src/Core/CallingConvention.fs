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

namespace B2R2

/// Represents the calling convention used for ordinary function calls under a
/// specific ISA and OS. This is an approximation: real binaries may deviate,
/// but it captures the dominant convention used by mainstream compilers.
type CallingConvention =
  { /// Argument locations in order (index 0 is the first argument). A trailing
    /// Stack element, if present, is a rule that covers every argument beyond
    /// the array as well.
    Args: ArgLocation[]
    /// Location of the integer/pointer return value.
    ReturnLocation: ArgLocation
    /// Callee-saved (non-volatile) registers.
    CalleeSavedRegisters: Set<RegisterID>
    /// Caller-saved (volatile) registers.
    CallerSavedRegisters: Set<RegisterID> }
with
  /// Returns the location of the argument at the given zero-based index. For a
  /// stack argument, the returned Stack layout's FirstOffset is the offset of
  /// that specific argument.
  member this.GetArgLocation(i) = ArgLocation.resolve this.Args i

  /// Returns the register holding the integer/pointer return value. Raises if
  /// the value is not returned in a single register under this convention.
  member this.ReturnRegister = ArgLocation.toRegister this.ReturnLocation

  /// Returns the register holding the argument at the given zero-based index.
  /// Raises if the argument is not passed in a single register.
  member this.ArgRegister(i) =
    this.GetArgLocation(i) |> ArgLocation.toRegister

  /// Returns true if the given register is callee-saved (non-volatile).
  member this.IsCalleeSaved(rid) =
    Set.contains rid this.CalleeSavedRegisters

  /// Returns true if the given register is caller-saved (volatile).
  member this.IsCallerSaved(rid) =
    Set.contains rid this.CallerSavedRegisters
