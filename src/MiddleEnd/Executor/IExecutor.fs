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

namespace B2R2.MiddleEnd.Executor

open B2R2
open B2R2.BinIR

/// Represents a stop point observed by a user-defined stop predicate.
type StopPoint<'State> =
  { /// Current instruction address.
    Address: Addr
    /// Number of executed machine instructions.
    InstructionCount: int
    /// Executor-specific state.
    State: 'State }

/// Represents a condition for stopping execution.
type StopCondition<'State> =
  /// Stop before executing the instruction at the given address.
  | StopAtAddress of addr: Addr
  /// Stop when a function return is observed.
  | StopAtReturn
  /// Stop when a call instruction is observed.
  | StopAtCall
  /// Stop when a side-effect statement is observed.
  | StopAtSideEffect
  /// Stop after executing the given number of machine instructions.
  | StopAfterInstructionCount of count: int
  /// Stop when expression or statement evaluation fails.
  | StopOnEvaluationError
  /// Stop when a user-provided predicate holds.
  | StopWhen of predicate: (StopPoint<'State> -> bool)

/// Represents the reason why execution stopped.
type StopReason =
  /// Execution reached an address requested by a stop condition.
  | StoppedAtAddress of addr: Addr
  /// Execution reached a function return.
  | Returned of addr: Addr
  /// Execution reached a call instruction. The target may be unknown.
  | StoppedAtCall of callSite: Addr * target: Addr option
  /// Execution reached a side-effect statement.
  | StoppedAtSideEffect of addr: Addr * sideEffect: SideEffect
  /// Execution reached the configured instruction limit.
  | InstructionLimitReached of addr: Addr * limit: int
  /// Evaluation failed with a B2R2 error case.
  | EvaluationError of addr: Addr * error: ErrorCase
  /// A user-defined stop predicate requested termination.
  | UserStopConditionMet of addr: Addr
  /// No instruction could be fetched or lifted at the given address.
  | InvalidInstructionAddress of addr: Addr

/// Represents the initial memory used for creating an execution state.
type InitialMemory<'Memory> =
  /// Start with an empty memory.
  | EmptyMemory
  /// Use the given executor-specific memory.
  | PreinitializedMemory of memory: 'Memory
  /// Use binary file sections (e.g., .rodata, .data) for memory reads.
  | BinSectionBackedMemory

/// Represents options for creating an execution state.
type StateCreationOptions<'Memory, 'Value> =
  { /// Initial memory.
    Memory: InitialMemory<'Memory>
    /// Initial registers.
    Registers: (RegisterID * 'Value)[] }

/// Represents how the executor should handle call instructions.
type CallPolicy =
  /// Stop when any call instruction is observed.
  | StopAtCalls
  /// Follow direct calls whose target is inside the current binary.
  | FollowDirectInternalCalls
  /// Invoke registered call hooks when a matching target is observed.
  | UseCallHooks

/// Represents how the executor should handle undefined values produced by IR.
type UndefinedValuePolicy =
  /// Treat undefined values as evaluation failures.
  | StopOnUndefinedValue
  /// Ignore writes whose right-hand side is undefined.
  | IgnoreUndefinedWrites
  /// Let each concrete or symbolic executor preserve its own undefined value.
  | PreserveUndefinedValues

/// Represents common executor configuration.
type ExecutionOptions<'State> =
  { /// Call-handling policy.
    Calls: CallPolicy
    /// Undefined-value handling policy.
    UndefinedValues: UndefinedValuePolicy
    /// Stop conditions used by Run.
    StopConditions: StopCondition<'State> list }

/// Represents the result of an execution run.
type ExecutionResult<'State> =
  { /// Reason why execution stopped.
    StopReason: StopReason
    /// Final instruction address or program counter.
    FinalAddress: Addr
    /// Number of executed machine instructions.
    InstructionCount: int
    /// Final executor-specific state.
    State: 'State }

/// Represents an executor that executes binary code from a given address.
type IExecutor<'State, 'Memory, 'Value> =
  /// Create an executor-specific initial state with default options.
  abstract CreateState: unit -> 'State

  /// Create an executor-specific initial state with the given options.
  abstract CreateState: options: StateCreationOptions<'Memory, 'Value> -> 'State

  /// Execute from the given start address with the provided state.
  abstract Run:
    start: Addr *
    state: 'State *
    options: ExecutionOptions<'State> -> ExecutionResult<'State>
