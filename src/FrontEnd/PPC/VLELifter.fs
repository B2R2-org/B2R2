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

/// <summary>
/// Lifts the instructions of Variable Length Encoding (VLE) that have no
/// instruction of the base encoding to be lifted as. The rest are lifted by
/// the lifter of the instruction they are another encoding of, which is the
/// Power ISA's own statement that they mean the same.
/// </summary>
module internal B2R2.FrontEnd.PPC.VLELifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.LiftingUtils

/// se_illegal, which asks for an Illegal Instruction exception.
let illegal ins bld = sideEffects ins bld UndefinedInstruction

/// A branch to the address in a register, whose low bit is the only one it
/// clears: an instruction sits on a halfword, so the bit below that is not
/// masked as the base encoding masks it. A branch that links writes the
/// address of the instruction after it, which is two bytes on, only once it
/// has read where it goes.
let branchToRegister (ins: Instruction) (bld: ILowUIRBuilder) reg link =
  lift bld ins {
    let rt = bld.RegType
    let target = tmpVar bld rt
    target := regVar bld reg .& AST.not (AST.num1 rt)
    if link then
      regVar bld Register.LR := numU64 (ins.Address + uint64 ins.Length) rt
      AST.interjmp target InterJmpKind.IsCall
    elif reg = Register.LR then
      AST.interjmp target InterJmpKind.IsRet
    else
      AST.interjmp target InterJmpKind.Base
  }
