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

namespace B2R2.BinIR

/// Side effect kinds.
type SideEffect =
  /// Software breakpoint.
  | Breakpoint
  /// CPU clock access, e.g., RDTSC on x86.
  | ClockCounter
  /// Memory fence operations, e.g., LFENCE/MFENCE/SFENCE on x86.
  | Fence
  /// Delay the execution for a while, e.g. HLT, PAUSE on x86.
  | Delay
  /// Terminate the execution.
  | Terminate
  /// Asynchronous event triggered by software (e.g. INT on x86) or hardware.
  | Interrupt of int
  /// Synchronous event generated when the execution encounters error condition.
  | Exception of string
  /// Locking, e.g., LOCK prefix on x86.
  | Lock
  /// Access CPU details, e.g., CPUID on x86.
  | ProcessorID
  /// System call.
  | SysCall
  /// Explicitly undefined instruction, e.g., UD2 on x86.
  | UndefinedInstr
  /// Unsupported floating point operations.
  | UnsupportedFP
  /// Unsupported privileged instructions.
  | UnsupportedPrivInstr
  /// Unsupported FAR branching.
  | UnsupportedFAR
  /// Unsupported processor extension
  | UnsupportedExtension

module SideEffect =
  let toString = function
    | Breakpoint -> "Breakpoint"
    | ClockCounter -> "CLK"
    | Fence -> "Fence"
    | Delay -> "Delay"
    | Terminate -> "Terminate"
    | Interrupt (n) -> "Int" + n.ToString ()
    | Exception s -> "Exception(" + s + ")"
    | Lock -> "Lock"
    | ProcessorID -> "PID"
    | SysCall -> "SysCall"
    | UndefinedInstr -> "Undef"
    | UnsupportedFP -> "FP"
    | UnsupportedPrivInstr -> "PrivInstr"
    | UnsupportedFAR -> "FAR"
    | UnsupportedExtension -> "CPU extension"

  let ofString (input: string) =
    match input.ToLower () with
    | "breakpoint" -> Breakpoint
    | "clk" -> ClockCounter
    | "fence" -> Fence
    | "delay" -> Delay
    | "terminate" -> Terminate
    | "lock" -> Lock
    | "pid" -> ProcessorID
    | "syscall" -> SysCall
    | "undef" -> UndefinedInstr
    | "fp" -> UnsupportedFP
    | "privinstr" -> UnsupportedPrivInstr
    | "far" -> UnsupportedFAR
    | "cpu extension" -> UnsupportedExtension
    | s when s.StartsWith "exception(" && s.Length >= 6 && s.EndsWith ")" ->
      input.[ 5 .. input.Length - 2 ] |> Exception
    | s when s.StartsWith "int" && s.Length >= 5 ->
      int s.[4 ..] |> Interrupt
    | _ -> B2R2.Utils.impossible ()
