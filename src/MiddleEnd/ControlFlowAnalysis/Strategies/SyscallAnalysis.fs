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

namespace B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

open B2R2
open B2R2.BinIR
open B2R2.FrontEnd
open B2R2.MiddleEnd.ConcEval
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Basic syscall analysis that only analyzes a single basic block that contains
/// the syscall instruction.
type SyscallAnalysis () =
  interface ISyscallAnalyzable with
    member _.IsExit (ctx, v) =
      let hdl = ctx.BinHandle
      match hdl.File.Format with
      | FileFormat.RawBinary
      | FileFormat.ELFBinary ->
        let st = CFGEvaluator.evalBlockFromScratch hdl v
        let arch = hdl.File.ISA.Arch
        let exitSyscall = LinuxSyscall.toNumber arch LinuxSyscall.Exit
        let exitGrpSyscall = LinuxSyscall.toNumber arch LinuxSyscall.ExitGroup
        let sigretSyscall = LinuxSyscall.toNumber arch LinuxSyscall.RtSigreturn
        let reg = CallingConvention.returnRegister hdl
        match st.TryGetReg reg with
        | Def v ->
          let n = BitVector.ToInt32 v
          n = exitSyscall || n = exitGrpSyscall || n = sigretSyscall
        | Undef -> false
      | _ -> false

    member _.MakeAbstract (ctx, v, isExit) =
      let addr = ctx.FunctionAddress
      let hdl = ctx.BinHandle
      let returningStatus = if isExit then NoRet else NotNoRet
      match hdl.File.Format with
      | FileFormat.RawBinary
      | FileFormat.ELFBinary ->
        let rt = hdl.File.ISA.WordSize |> WordSize.toRegType
        let rid = CallingConvention.returnRegister hdl
        let reg = hdl.RegisterFactory.GetRegVar rid
        let e = LowUIR.AST.undef rt "ret"
        let rundown = [| LowUIR.AST.put reg e |]
        FunctionAbstraction (addr, 0, rundown, true, returningStatus)
      | _ ->
        FunctionAbstraction (addr, 0, [||], true, returningStatus)
