(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
          Minkyu Jung <hestati@kaist.ac.kr>

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

namespace B2R2.BinIR

/// Raised when an illegal AST type is used. This should never be raised in
/// normal situation.
exception IllegalASTTypeException

/// Unary operator types.
type UnOpType =
  /// Make it negative (Two's complement)
  | NEG = 0
  /// Bitwise not (One's complement)
  | NOT = 1

/// Binary operator types.
type BinOpType =
  /// Addition
  | ADD = 0
  /// Subtraction
  | SUB = 1
  /// Multiplication
  | MUL = 2
  /// Unsigned division
  | DIV = 3
  /// Signed division
  | SDIV = 4
  /// Unsigned modulo
  | MOD = 5
  /// Signed modulo
  | SMOD = 6
  /// Shift left
  | SHL= 7
  /// Shift right
  | SHR = 8
  /// Sign-extended shift right
  | SAR = 9
  /// Bitwise and
  | AND = 10
  /// Bitwise or
  | OR = 11
  /// Bitwise xor
  | XOR = 12
  /// Concat two reg values
  | CONCAT = 13
  /// Apply a function
  | APP = 14
  /// Cons arguments of function
  | CONS = 15

/// Relative operator types.
type RelOpType =
  /// Equal
  | EQ = 0
  /// Not equal
  | NEQ = 1
  /// Unsigned greater than
  | GT = 2
  /// Unsigned greater than or equal
  | GE = 3
  /// Signed greater than
  | SGT = 4
  /// Signed greater than or equal
  | SGE = 5
  /// Unsigned less than
  | LT = 6
  /// Unsigned less than or equal
  | LE = 7
  /// Signed less than
  | SLT = 8
  /// Signed less than or equal
  | SLE = 9

/// Casting kinds.
type CastKind =
  /// Sign-extending conversion
  | SignExt = 0
  /// Zero-extending conversion
  | ZeroExt = 1

/// Side effect kinds.
type SideEffect =
    /// CPU clock access, e.g., RDTSC on x86.
  | ClockCounter
    /// Memory fence operations, e.g., LFENCE/MFENCE/SFENCE on x86.
  | Fence
    /// Process halt, e.g., HLT on x86.
  | Halt
    /// Interrupt, e.g., INT on x86.
  | Interrupt of int
    /// Locking, e.g., LOCK prefix on x86.
  | Lock
    /// Give a hint about a spin-wait loop, e.g., PAUSE on x86.
  | Pause
    /// Access CPU details, e.g., CPUID on x86.
  | ProcessorID
    /// System call.
  | SysCall
    /// Explicitly undefined instruction, e.g., UD2 on x86.
  | UndefinedInstr
    /// Unsupported floating point operations.
  | UnsupportedFP
    /// Unsupported privileged instructions.
  | UnsupportedPrivInstr
    /// Unsupported FAR branching.
  | UnsupportedFAR
    /// Unsupported processor extension
  | UnsupportedExtension

type StartPos = int

// vim: set tw=80 sts=2 sw=2:
