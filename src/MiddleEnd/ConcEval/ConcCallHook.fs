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

open B2R2

/// Represents the calling-convention information passed to a call hook.
type ConcCallContext =
  { /// Address of the call instruction.
    CallSite: Addr
    /// Concrete target address selected for hook dispatch.
    Target: Addr
    /// Fall-through address after the call instruction.
    ReturnAddress: Addr
    /// Word type for the current binary.
    WordType: RegType
    /// Endian used by the current binary.
    Endian: Endian
    /// Register IDs for the first calling-convention arguments. Empty when the
    /// ABI passes every integer argument on the stack.
    ArgumentRegisters: RegisterID[]
    /// Register ID used for the function return value.
    ReturnRegister: RegisterID }

/// Represents a concrete external-call hook. A hook stands in for the call it
/// is registered against, updating the given state in place, and explains
/// itself in the Error case when it cannot model the call. The executor pushes
/// the return address before the hook runs and pops it afterwards, so a hook
/// sees the frame the callee would have seen and must leave the stack balanced.
type ConcCallHook = ConcCallContext -> EvalState -> Result<unit, string>

/// Represents a target-address-based call hook registry.
type ConcCallHookRegistry(hooks: Map<Addr, ConcCallHook>) =
  /// Creates an empty call hook registry.
  new() = ConcCallHookRegistry Map.empty

  /// Creates a call hook registry from target-hook pairs.
  new(hooks: seq<Addr * ConcCallHook>) = ConcCallHookRegistry(Map.ofSeq hooks)

  /// Registers a hook for a concrete target address.
  member _.Register(target, hook) =
    ConcCallHookRegistry(Map.add target hook hooks)

  /// Registers hooks for concrete target addresses.
  member this.RegisterMany(hooks: seq<Addr * ConcCallHook>) =
    Seq.fold (fun (registry: ConcCallHookRegistry) (target, hook) ->
      registry.Register(target, hook)) this hooks

  /// Finds a hook for a concrete target address.
  member _.TryFind target = Map.tryFind target hooks
