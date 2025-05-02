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

namespace B2R2.FrontEnd.BinLifter

open B2R2

/// Provides a common functionality for building LowUIR statements from
/// instructions. Some CPU architectures may extend this interface to provide
/// additional functionalities, although most architectures will simply
/// implement the default implementation as is.
[<Interface>]
type ILowUIRBuilder =
  inherit IRegisterFactory

  /// Word size of the target architecture.
  abstract WordSize: WordSize

  /// Word size of the target architecture in RegType.
  abstract RegType: RegType

  /// Endianness of the target architecture.
  abstract Endianness: Endian

  /// LowUIR stream to which lifted instructions are stored and returned.
  abstract Stream: LowUIRStream

#if EMULATION
  /// Remember the lastly used opcode. This is used to update flags registers,
  /// such as x86 EFLAGS, in emulation.
  abstract ConditionCodeOp: ConditionCodeOp with get, set
#endif

  /// Create a default implementation of ILowUIRBuilder using the provided
  /// register factory and LowUIR stream.
  static member Default (isa: ISA,
                         regFactory: IRegisterFactory,
                         stream: LowUIRStream) =
    let wordSize = isa.WordSize
    let regType = WordSize.toRegType wordSize
    let endian = isa.Endian
    { new ILowUIRBuilder with
        member _.WordSize with get () = wordSize
        member _.RegType with get () = regType
        member _.Endianness with get () = endian
        member _.Stream with get () = stream
#if EMULATION
        member _.ConditionCodeOp
          with get () = Terminator.impossible ()
            and set v = Terminator.impossible ()
#endif
        member _.GetRegVar id = regFactory.GetRegVar (id=id)
        member _.GetRegVar name = regFactory.GetRegVar (name=name)
        member _.GetPseudoRegVar id idx = regFactory.GetPseudoRegVar id idx
        member _.GetAllRegVars () = regFactory.GetAllRegVars ()
        member _.GetGeneralRegVars () = regFactory.GetGeneralRegVars ()
        member _.GetRegisterID expr = regFactory.GetRegisterID (expr=expr)
        member _.GetRegisterID name = regFactory.GetRegisterID (name=name)
        member _.GetRegisterIDAliases id = regFactory.GetRegisterIDAliases id
        member _.GetRegString id = regFactory.GetRegString id
        member _.GetAllRegStrings () = regFactory.GetAllRegStrings ()
        member _.GetRegType id = regFactory.GetRegType id
        member _.ProgramCounter = regFactory.ProgramCounter
        member _.StackPointer with get () = regFactory.StackPointer
        member _.FramePointer with get () = regFactory.FramePointer
        member _.IsProgramCounter id = regFactory.IsProgramCounter id
        member _.IsStackPointer id = regFactory.IsStackPointer id
        member _.IsFramePointer id = regFactory.IsFramePointer id }
