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

/// Represents how an executor should handle call instructions.
[<RequireQualifiedAccess>]
type CallPolicy<'Hook> =
  /// Stop when any call instruction is observed.
  | StopAtCalls
  /// Follow a direct call whose target belongs to the current binary, and
  /// reject one whose target lies outside it. What happens to an indirect
  /// call, whose target is unknown before it runs, is up to the executor.
  | FollowDirectInternalCalls
  /// Dispatch a registered hook in place of a call to a matching target, and
  /// follow a call to an unhooked internal target.
  | UseCallHooks of hooks: CallHookRegistry<'Hook>

/// Represents a target-address-based call hook registry.
and CallHookRegistry<'Hook>(hooks: Map<Addr, 'Hook>) =
  /// Creates an empty call hook registry.
  new() = CallHookRegistry Map.empty

  /// Creates a call hook registry from target-hook pairs.
  new(hooks: seq<Addr * 'Hook>) = CallHookRegistry(Map.ofSeq hooks)

  /// Registers a hook for a concrete target address.
  member _.Register(target, hook) =
    CallHookRegistry(Map.add target hook hooks)

  /// Registers hooks for concrete target addresses.
  member this.RegisterMany(hooks: seq<Addr * 'Hook>) =
    Seq.fold (fun (registry: CallHookRegistry<'Hook>) (target, hook) ->
      registry.Register(target, hook)) this hooks

  /// Finds a hook for a concrete target address.
  member _.TryFind target = Map.tryFind target hooks
