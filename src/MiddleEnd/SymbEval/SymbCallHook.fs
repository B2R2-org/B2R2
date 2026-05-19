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

namespace B2R2.MiddleEnd.SymbEval

open B2R2
open B2R2.BinIR

/// Represents the calling-convention information passed to a call hook.
type SymbCallContext =
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
    /// Register IDs for the first calling-convention arguments.
    ArgumentRegisters: RegisterID[]
    /// Register ID used for the function return value.
    ReturnRegister: RegisterID }

/// Represents a symbolic external-call hook.
type SymbCallHook =
  SymbCallContext -> SymbState -> Result<SymbState list, SymbEvalError>

/// Represents a target-address-based call hook registry.
type SymbCallHookRegistry(hooks: Map<Addr, SymbCallHook>) =
  /// Creates an empty call hook registry.
  new() = SymbCallHookRegistry Map.empty

  /// Creates a call hook registry from target-hook pairs.
  new(hooks: seq<Addr * SymbCallHook>) =
    SymbCallHookRegistry(Map.ofSeq hooks)

  /// Registers a hook for a concrete target address.
  member _.Register(target, hook) =
    SymbCallHookRegistry(Map.add target hook hooks)

  /// Registers hooks for concrete target addresses.
  member this.RegisterMany(hooks: seq<Addr * SymbCallHook>) =
    Seq.fold (fun (registry: SymbCallHookRegistry) (target, hook) ->
      registry.Register(target, hook)) this hooks

  /// Finds a hook for a concrete target address.
  member _.TryFind target = Map.tryFind target hooks

/// Built-in symbolic call hook models.
module SymbCallHooks =
  let defaultStringBound = SymbStateAccessor.DefaultStringBound

  let private byteZero = SymbExpr.zero 8<rt>

  let private wordConst typ value =
    SymbExpr.Const(BitVector(uint64 value, typ))

  let private concreteAddr = function
    | SymbExpr.Const bv -> Ok(BitVector.ToUInt64 bv)
    | expr -> Error(UnsupportedSymbolicAddress expr)

  let private isConcreteZero = function
    | SymbExpr.Const bv when BitVector.ToUInt64 bv = 0UL -> true
    | _ -> false

  let private isConcreteNonZero = function
    | SymbExpr.Const bv when BitVector.ToUInt64 bv <> 0UL -> true
    | _ -> false

  let private addNonNullCondition (st: SymbState) byte =
    if isConcreteNonZero byte then ()
    else st.AddPathCondition(SymbExpr.relop RelOpType.NEQ byte byteZero)

  let private addNullCondition (st: SymbState) byte =
    if isConcreteZero byte then ()
    else st.AddPathCondition(SymbExpr.relop RelOpType.EQ byte byteZero)

  let private setReturn (ctx: SymbCallContext) length (st: SymbState) =
    st.SetReg(ctx.ReturnRegister, wordConst ctx.WordType length)
    st.PC <- ctx.ReturnAddress
    st

  let private getArgument (ctx: SymbCallContext) (st: SymbState) =
    match st.TryGetReg ctx.ArgumentRegisters[0] with
    | Ok expr -> concreteAddr expr
    | Error _ -> Error(UninitializedRegister ctx.ArgumentRegisters[0])

  let private canBeNull = function
    | SymbExpr.Const bv -> BitVector.ToUInt64 bv = 0UL
    | _ -> true

  let private canBeNonNull = function
    | SymbExpr.Const bv -> BitVector.ToUInt64 bv <> 0UL
    | _ -> true

  let private makeStrlenState ctx length bytes terminator
                             (st: SymbState) =
    let st = st.Clone()
    bytes |> List.iter (addNonNullCondition st)
    addNullCondition st terminator
    setReturn ctx length st

  let private readByte addr offset (st: SymbState) =
    st.Memory.ByteRead(addr + uint64 offset)

  let private collectStrlenStates maxScan ctx addr (st: SymbState) =
    let rec loop offset prefix acc =
      if offset > maxScan then List.rev acc |> Ok
      else
        match readByte addr offset st with
        | Error e -> Error e
        | Ok byte ->
          let acc =
            if canBeNull byte then
              makeStrlenState ctx offset (List.rev prefix) byte st :: acc
            else acc
          if canBeNonNull byte then loop (offset + 1) (byte :: prefix) acc
          else List.rev acc |> Ok
    loop 0 [] []

  /// Default maximum symbolic C-string payload size.
  /// Models strlen by generating possible null-terminator positions.
  let strlenBounded maxScan (ctx: SymbCallContext) (st: SymbState) =
    if maxScan < 0 then Error(UnsupportedOperation "Negative strlen bound.")
    elif Array.isEmpty ctx.ArgumentRegisters then
      Error(UnsupportedOperation "strlen requires one argument register.")
    else
      match getArgument ctx st with
      | Error e -> Error e
      | Ok addr ->
        match collectStrlenStates maxScan ctx addr st with
        | Error e -> Error e
        | Ok [] ->
          Error(UnsupportedOperation "strlen produced no feasible state.")
        | Ok states -> Ok states

  /// Models strlen using the default string bound.
  let strlen ctx st =
    strlenBounded defaultStringBound ctx st
