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

/// Represents where a single function or syscall argument is located at the
/// moment control reaches the callee.
[<RequireQualifiedAccess>]
type ArgLocation =
  /// In a single register.
  | Reg of RegisterID
  /// In a register pair (low, high) -- e.g. a 64-bit value split across two
  /// 32-bit registers on a 32-bit ABI.
  | RegPair of low: RegisterID * high: RegisterID
  /// On the stack. The meaning of the carried layout depends on the context:
  /// when it appears as a (trailing) element of a convention's Args, it is a
  /// *rule* covering this argument and every subsequent one, and its
  /// FirstOffset is the offset of the first such argument. When returned by the
  /// GetArgLocation method, it is a *resolved* location for the queried
  /// argument, and its FirstOffset is the offset of that argument.
  | Stack of StackArgLayout

/// Describes how arguments that are passed on the stack are laid out, relative
/// to the stack pointer at the moment control reaches the callee (i.e., right
/// after the call transfers control, before the prologue runs).
and StackArgLayout =
  { /// Byte offset of the first stack-passed argument from the stack pointer at
    /// callee entry.
    FirstOffset: int
    /// Size in bytes of each stack argument slot.
    SlotSize: int }

/// Provides helpers for resolving argument locations from an Args array.
[<RequireQualifiedAccess>]
module ArgLocation =
  /// Resolves the location of the argument at the given zero-based index within
  /// the Args array, expanding a trailing Stack rule for spilled arguments. For
  /// a stack argument, the returned Stack layout's FirstOffset is the offset of
  /// that specific argument.
  let resolve (args: ArgLocation[]) i =
    if i < 0 then
      invalidArg (nameof i) "Argument index is zero-based."
    else
      match Array.tryItem i args with
      | Some loc ->
        loc
      | None ->
        match Array.tryLast args with
        | Some(ArgLocation.Stack l) ->
          let extra = i - (args.Length - 1)
          ArgLocation.Stack
            { l with FirstOffset = l.FirstOffset + extra * l.SlotSize }
        | _ ->
          invalidArg (nameof i) "Argument index out of range for this ABI."

  /// Extracts the single register from a register-passed location. Raises if
  /// the location is not a single register.
  let toRegister loc =
    match loc with
    | ArgLocation.Reg rid -> rid
    | _ -> invalidArg (nameof loc) "Not a single register."
