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

namespace B2R2.FrontEnd.Intel

open B2R2
open B2R2.FrontEnd.BinLifter

/// Represents the LowUIR builder for Intel.
type LowUIRBuilder(isa: ISA,
                   regFactory: IRegisterFactory,
                   stream: LowUIRStream) =
  let wordSize = isa.WordSize
  let regType = WordSize.toRegType wordSize
  let endian = isa.Endian
#if EMULATION
  let mutable ccop = ConditionCodeOp.TraceStart
#endif

  interface ILowUIRBuilder with
    member _.WordSize with get() = wordSize
    member _.RegType with get() = regType
    member _.Endianness with get() = endian
    member _.Stream with get() = stream
#if EMULATION
    member _.ConditionCodeOp with get() = ccop and set v = ccop <- v
#endif
    member _.GetRegVar rid = regFactory.GetRegVar(rid = rid)
    member _.GetRegVar name = regFactory.GetRegVar(name = name)
    member _.GetPseudoRegVar(id, idx) = regFactory.GetPseudoRegVar(id, idx)
    member _.GetAllRegVars() = regFactory.GetAllRegVars()
    member _.GetGeneralRegVars() = regFactory.GetGeneralRegVars()
    member _.GetRegisterID expr = regFactory.GetRegisterID(expr = expr)
    member _.GetRegisterID name = regFactory.GetRegisterID(name = name)
    member _.GetRegisterIDAliases id = regFactory.GetRegisterIDAliases id
    member _.GetRegString id = regFactory.GetRegString id
    member _.GetAllRegStrings() = regFactory.GetAllRegStrings()
    member _.GetRegType id = regFactory.GetRegType id
    member _.ProgramCounter = regFactory.ProgramCounter
    member _.StackPointer with get() = regFactory.StackPointer
    member _.FramePointer with get() = regFactory.FramePointer
    member _.IsProgramCounter id = regFactory.IsProgramCounter id
    member _.IsStackPointer id = regFactory.IsStackPointer id
    member _.IsFramePointer id = regFactory.IsFramePointer id
