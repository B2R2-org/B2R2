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

namespace B2R2.MiddleEnd.ConcEval

open B2R2.MiddleEnd.Executor

/// Represents concrete execution configuration.
type ConcRunOptions =
  { /// Call-handling policy.
    Calls: CallPolicy<ConcCallHook>
    /// Undefined-value handling policy.
    UndefinedValues: ConcUndefinedValuePolicy
    /// Uninitialized register read handling policy.
    UninitializedRegisters: ConcUninitializedRegisterPolicy
    /// Maximum machine instructions to execute. Zero means unlimited.
    MaxInstructions: int
    /// Stop conditions used by Run.
    StopConditions: ConcStopCondition list }
with
  static member Default(stopConditions: ConcStopCondition list) =
    { Calls = CallPolicy.FollowDirectInternalCalls
      UndefinedValues = ConcUndefinedValuePolicy.IgnoreUndefinedWrites
      UninitializedRegisters = ConcUninitializedRegisterPolicy.ZeroCallerContext
      MaxInstructions = 50000
      StopConditions = stopConditions }

  static member Default(stopCondition: ConcStopCondition) =
    ConcRunOptions.Default [ stopCondition ]

  static member Default() = ConcRunOptions.Default []

  /// Uses the given maximum machine instruction count.
  member opts.WithMaxInstructions count =
    { opts with MaxInstructions = count }

  /// Stops before evaluating call instructions.
  member opts.StopAtCalls() =
    { opts with Calls = CallPolicy.StopAtCalls }

  /// Follows direct internal calls without using external-call hooks.
  member opts.FollowDirectInternalCalls() =
    { opts with Calls = CallPolicy.FollowDirectInternalCalls }

  /// Uses a prepared call hook registry for external-call dispatch.
  member opts.WithCallHooks hooks =
    { opts with Calls = CallPolicy.UseCallHooks hooks }

  /// Registers a call hook and enables hook-based call handling.
  member opts.RegisterCallHook(target, hook) =
    { opts with Calls = CallPolicy.register target hook opts.Calls }

  /// Registers call hooks and enables hook-based call handling.
  member opts.RegisterCallHooks hooks =
    { opts with Calls = CallPolicy.registerMany hooks opts.Calls }

  /// Treats undefined values as evaluation failures.
  member opts.StopOnUndefinedValue() =
    { opts with
        UndefinedValues = ConcUndefinedValuePolicy.StopOnUndefinedValue }

  /// Ignores writes whose right-hand side is undefined.
  member opts.IgnoreUndefinedWrites() =
    { opts with
        UndefinedValues = ConcUndefinedValuePolicy.IgnoreUndefinedWrites }

  /// Unsets the target of a write whose right-hand side is undefined.
  member opts.PreserveUndefinedValues() =
    { opts with
        UndefinedValues = ConcUndefinedValuePolicy.PreserveUndefinedValues }

  /// Treats uninitialized register reads as evaluation failures.
  member opts.StopOnUninitializedRegister() =
    { opts with
        UninitializedRegisters =
          ConcUninitializedRegisterPolicy.StopOnUninitializedRegister }

  /// Materializes caller-provided context registers as zero on first read.
  member opts.ZeroCallerContext() =
    { opts with
        UninitializedRegisters =
          ConcUninitializedRegisterPolicy.ZeroCallerContext }

  /// Materializes any uninitialized register as zero on first read.
  member opts.ZeroAnyRegister() =
    { opts with
        UninitializedRegisters =
          ConcUninitializedRegisterPolicy.ZeroAnyRegister }

  /// Adds one stop condition, after the ones already configured.
  member opts.AddStopCondition condition =
    { opts with StopConditions = opts.StopConditions @ [ condition ] }

  /// Adds stop conditions, after the ones already configured.
  member opts.AddStopConditions conditions =
    { opts with
        StopConditions = opts.StopConditions @ List.ofSeq conditions }

  /// Replaces the configured stop conditions.
  member opts.WithStopConditions conditions =
    { opts with StopConditions = List.ofSeq conditions }

  /// Stops before executing the instruction at the given address.
  member opts.StopAtAddress addr =
    opts.AddStopCondition(ConcStopCondition.StopAtAddress addr)

  /// Stops before executing the instruction at any of the given addresses.
  member opts.StopAtAddresses addrs =
    addrs
    |> Seq.map ConcStopCondition.StopAtAddress
    |> opts.AddStopConditions

  /// Stops after executing the instruction at the given address.
  member opts.StopAfterAddress addr =
    opts.AddStopCondition(ConcStopCondition.StopAfterAddress addr)

  /// Stops when a function return is observed.
  member opts.StopAtReturn() =
    opts.AddStopCondition ConcStopCondition.StopAtReturn

  /// Stops after executing a function return.
  member opts.StopAfterReturn() =
    opts.AddStopCondition ConcStopCondition.StopAfterReturn

  /// Stops when a side-effect statement is observed.
  member opts.StopAtSideEffect() =
    opts.AddStopCondition ConcStopCondition.StopAtSideEffect

  /// Stops when the given predicate holds.
  member opts.StopWhen predicate =
    opts.AddStopCondition(ConcStopCondition.StopWhen predicate)

/// Represents how concrete execution should handle undefined values.
and [<RequireQualifiedAccess>] ConcUndefinedValuePolicy =
  /// Treat undefined values as evaluation failures.
  | StopOnUndefinedValue
  /// Ignore writes whose right-hand side is undefined, leaving the target with
  /// whatever value it held before.
  | IgnoreUndefinedWrites
  /// Unset the register or temporary that an undefined write targets, so that
  /// it reads back as undefined instead of keeping a stale value. A store of
  /// an undefined value is skipped, since a memory cannot mark a cell
  /// undefined.
  | PreserveUndefinedValues

/// Represents how concrete execution should handle uninitialized register
/// reads.
and [<RequireQualifiedAccess>] ConcUninitializedRegisterPolicy =
  /// Treat uninitialized register reads as evaluation failures.
  | StopOnUninitializedRegister
  /// Materialize caller-provided context registers as zero on first read. The
  /// program counter, the stack pointer, and the register that holds the
  /// return address under the binary's ABI are left uninitialized.
  | ZeroCallerContext
  /// Materialize any uninitialized register as zero on first read.
  | ZeroAnyRegister
