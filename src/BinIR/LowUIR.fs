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

namespace B2R2.BinIR.LowUIR

open System
open B2R2
open B2R2.BinIR

/// The kind of an InterJmp. Multiple kinds can present for a jump instruction.
[<Flags>]
type InterJmpKind =
  /// The base case, i.e., a simple jump instruction.
  | Base = 0
  /// A call to a function.
  | IsCall = 1
  /// A return from a function.
  | IsRet = 2
  /// An exit, which will terminate the process.
  | IsExit = 4
  /// A branch instructino that modifies the operation mode from Thumb to ARM.
  | SwitchToARM = 8
  /// A branch instructino that modifies the operation mode from ARM to Thumb.
  | SwitchToThumb = 16

/// ExprInfo summarizes several abstract information about the Expr. This is
/// useful for writing an efficient post analyses.
type ExprInfo = {
  /// Is this expression contains memory load(s).
  HasLoad: bool
  /// A set of registers (their regids) used in this expression.
  VarsUsed: RegisterSet
  /// A set of temp variables (their IDs) used in this expression.
  TempVarsUsed: Set<int>
}

/// IR Expressions.
/// NOTE: You MUST create Expr/Stmt through the AST module. *NEVER* directly
/// construct Expr nor Stmt.
type E =
  /// A number. For example, (0x42:I32) is a 32-bit number 0x42
  | Num of BitVector

  /// A variable that represents a register of a CPU. Var (t, r, n) indicates
  /// a variable of type (t) that has RegisterID r and name (n).
  /// For example, (EAX:I32) represents the EAX register (of type I32).
  /// Note that name (n) is additional information that doesn't be used
  /// internally.
  | Var of RegType * RegisterID * string * RegisterSet

  /// Nil to represent cons cells. This should only be used with BinOpType.CONS.
  | Nil

  /// A variable that represents a Program Counter (PC) of a CPU.
  | PCVar of RegType * string

  /// A temporary variable represents an internal (imaginary) register. Names
  /// of temporary variables should always be affixed by an underscore (_) and
  /// a number. This is to make sure that any temporary variable is unique in
  /// a CFG. For example, a temporary variable T can be represented as
  /// (T_2:I32), where 2 is a unique number assigned to the variable.
  | TempVar of RegType * int

  /// Unary operation such as negation.
  | UnOp of UnOpType * Expr * ExprInfo

  /// Symbolic constant for labels.
  | Name of Symbol

  /// Name of uninterpreted function.
  | FuncName of string

  /// Binary operation such as add, sub, etc. The second argument is a result
  /// type after applying BinOp.
  | BinOp of BinOpType * RegType * Expr * Expr * ExprInfo

  /// Relative operation such as eq, lt, etc.
  | RelOp of RelOpType * Expr * Expr * ExprInfo

  /// Memory loading such as LE:[T_1:I32]
  | Load of Endian * RegType * Expr * ExprInfo

  /// If-then-else expression. The first expression is a condition, and the
  /// second and the third are true and false expression respectively.
  | Ite of Expr * Expr * Expr * ExprInfo

  /// Type casting expression. The first argument is a casting type, and the
  /// second argument is a result type.
  | Cast of CastKind * RegType * Expr * ExprInfo

  /// Extraction expression. The first argument is target expression, and the
  /// second argument is the number of bits for extraction, and the third is
  /// the start position.
  | Extract of Expr * RegType * StartPos * ExprInfo

  /// Undefined expression. This is rarely used, and it is a fatal error when we
  /// encounter this expression while evaluating a program. Some CPU manuals
  /// explicitly say that a register value is undefined after a certain
  /// operation. We model such cases with this expression.
  | Undefined of RegType * string

/// When hash-consing is not used, we simply create a wrapper for an AST node.
and [<Struct>] Expr = {
  /// The actual AST node.
  E: E
}

/// IL Statements.
/// NOTE: You MUST create Expr/Stmt through the AST module. *NEVER* directly
/// construct Expr nor Stmt.
type S =
  /// Metadata representing the start of a machine instruction. More
  /// specifically, it contains the length of the instruction. There must be a
  /// single IMark per a machine instruction.
  | ISMark of uint32

  /// Metadata representing the end of a machine instruction. It contains the
  /// length of the current instruction.
  | IEMark of uint32

  /// Metadata representing a label (as in an assembly language). LMark is only
  /// valid within a machine instruction.
  | LMark of Symbol

  /// This statement puts a value into a register. The first argument is a
  /// destination operand, and the second argument is a source operand. The
  /// destination operand should have either a Var or a TempVar.
  ///
  /// Example: [Put(T_1:I32, Load(LE, T_2:I32))]
  /// loads a 32-bit value from the address T2, and store the value to the
  /// temporary register T1.
  | Put of Expr * Expr

  /// This statement stores a value into a memory. The first argument
  /// represents the endianness, the second argument is a destination operand,
  /// and the third argument is a value to store.
  ///
  /// Example: Store(LE, T_1:I32, T_2:I32)
  /// stores a 32-bit value T_2 into the address T_1
  | Store of Endian * Expr * Expr

  /// This statement represents a jump (unconditional) to an LMark. The first
  /// argument specifies the target address.
  | Jmp of Expr

  /// This statement represents a conditional jump to an LMark. The first
  /// argument specifies a jump condition. If the condition is true, jump to
  /// the address specified by the second argument. Otherwise, jump to the
  /// address specified by the third argument.
  | CJmp of Expr * Expr * Expr

  /// This is an unconditional jump instruction to another instruction. This is
  /// an inter-instruction jump unlike Jmp statement. The first argument is the
  /// jump target address.
  | InterJmp of Expr * InterJmpKind

  /// This is a conditional jump instruction to another instruction. The first
  /// argument specifies a jump condition. If the condition is true, change the
  /// program counter to jump to the address specified by the second argument.
  /// Otherwise, jump to the address specified by the third argument.
  | InterCJmp of Expr * Expr * Expr

  /// This represents an instruction with side effects such as a system call.
  | SideEffect of SideEffect

/// When hash-consing is not used, we simply create a wrapper for an AST node.
and [<Struct>] Stmt = {
  /// The actual AST node.
  S: S
}

// vim: set tw=80 sts=2 sw=2:
