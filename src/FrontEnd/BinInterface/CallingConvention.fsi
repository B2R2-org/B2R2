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

module B2R2.FrontEnd.BinInterface.CallingConvention

open B2R2

/// Obtain the list of volatile register IDs
[<CompiledName("VolatileRegisters")>]
val volatileRegisters: BinHandle -> RegisterID list

/// Obtain the register ID used for storing syscall return values.
[<CompiledName("ReturnRegister")>]
val returnRegister: BinHandle -> RegisterID

/// Obtain the register ID used for storing a syscall number.
[<CompiledName("SyscallNumRegister")>]
val syscallNumRegister: BinHandle -> RegisterID

/// Obtain the register ID used for the nth syscall parameter.
[<CompiledName("SyscallArgRegister")>]
val syscallArgRegister: BinHandle -> int -> RegisterID

/// Obtain the register ID used for the nth function call parameter. Since
/// actual calling convention may vary depending on the binaries, this function
/// only returns a generally used register for the given architecture and the
/// file format.
[<CompiledName("FunctionArgRegister")>]
val functionArgRegister: BinHandle -> int -> RegisterID

/// Check if the given register is non-volatile register in the given binary.
/// Non-volatile registers are preserved by callee, i.e., callee-saved
/// registers.
[<CompiledName("IsNonVolatile")>]
val isNonVolatile: BinHandle -> RegisterID -> bool
