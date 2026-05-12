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

namespace B2R2.MiddleEnd.SymEval

open System
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd.Executor

/// Provides convenience helpers for a symbolic state.
type SymStateHelper(hdl: BinHandle, state: SymState, ?os: OS) =
  let regFactory = hdl.RegisterFactory
  let os = defaultArg os OS.Linux
  let endian = hdl.File.ISA.Endian
  let wordType = hdl.File.ISA.WordSize |> WordSize.toRegType
  let wordBytes = RegType.toByteWidth wordType

  let wordValue (addr: Addr) = SymExpr.Const(BitVector(addr, wordType))

  let registerByName (name: string) =
    regFactory.GetRegisterID(name = name.ToUpperInvariant())

  let getStackPointerRegister () =
    match regFactory.StackPointer with
    | Some rid -> rid
    | None -> Terminator.futureFeature ()

  let getFramePointerRegister () =
    match regFactory.FramePointer with
    | Some rid -> rid
    | None -> Terminator.futureFeature ()

  let getConcreteAddr = function
    | SymExpr.Const bv -> BitVector.ToUInt64 bv
    | _ -> Terminator.futureFeature ()

  let getStackPointer () =
    getStackPointerRegister ()
    |> state.GetReg
    |> getConcreteAddr

  let setStackPointer addr =
    state.SetReg(getStackPointerRegister (), wordValue addr)

  let pushToStack value =
    let addr = getStackPointer () - uint64 wordBytes
    setStackPointer addr
    state.Memory.Store(addr, value, endian)
    addr

  let popFromStack () =
    let addr = getStackPointer ()
    match state.Memory.Load(addr, endian, wordType) with
    | Ok value ->
      setStackPointer (addr + uint64 wordBytes)
      value
    | Error _ -> Terminator.futureFeature ()

  interface IStateHelper<SymState, SymExpr> with

    member _.RawState = state

    member _.WordType = wordType

    member _.WordBytes = wordBytes

    member _.StackPointer = getStackPointer ()

    member _.SetStackPointer addr = setStackPointer addr

    member _.InitializeStack stackTop = setStackPointer stackTop

    member _.InitializeFramePointer() =
      state.SetReg(getFramePointerRegister (), wordValue (getStackPointer ()))

    member _.SetRegister(name, value) = state.SetReg(registerByName name, value)

    member _.SetRegister(rid, value) = state.SetReg(rid, value)

    member _.GetRegister name = registerByName name |> state.GetReg

    member _.GetRegister rid = state.GetReg rid

    member _.ZeroRegisters names =
      names
      |> Array.iter (fun name ->
        state.SetReg(registerByName name, SymExpr.zero wordType))

    member _.ZeroRegisters rids =
      rids
      |> Array.iter (fun rid -> state.SetReg(rid, SymExpr.zero wordType))

    member _.SetArgument(idx, value) =
      if idx < 0 then raise (ArgumentOutOfRangeException(nameof idx))
      let rid = CallingConvention.FunctionArgRegister(hdl, os, idx + 1)
      state.SetReg(rid, value)

    member _.GetReturnValue() =
      CallingConvention.ReturnRegister hdl |> state.GetReg

    member _.AllocateStackBuffer size =
      if size < 0 then raise (ArgumentOutOfRangeException(nameof size))
      let addr = getStackPointer () - uint64 size
      setStackPointer addr
      addr

    member _.PushToStack value = pushToStack value

    member _.PopFromStack() = popFromStack ()
