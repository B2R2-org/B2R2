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

/// Represents the system-call convention for a specific ISA and OS.
type SyscallConvention =
  { /// Register holding the syscall number on entry.
    NumberRegister: RegisterID
    /// Register holding the syscall return value.
    ReturnRegister: RegisterID
    /// Argument locations in order (index 0 is the first argument). A trailing
    /// Stack element, if present, is a rule that covers every argument beyond
    /// the array as well.
    Args: ArgLocation[] }
with
  /// Returns the location of the syscall argument at the given zero-based
  /// index.
  member this.GetArgLocation(i) = ArgLocation.resolve this.Args i

  /// Returns the register holding the syscall argument at the given zero-based
  /// index. Raises if the argument is not passed in a single register.
  member this.ArgRegister(i) =
    this.GetArgLocation(i) |> ArgLocation.toRegister
