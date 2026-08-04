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

namespace B2R2.ABI

open B2R2

/// Represents the stack-frame discipline of an ABI at a call boundary. This is
/// independent of how arguments are passed (see CallingConvention); it captures
/// the geometry of the stack around a call. This is an approximation: values
/// for less common ISAs assume the mainstream toolchain defaults.
type StackConvention =
  { /// Required alignment, in bytes, of the stack pointer at a call site.
    Alignment: int
    /// Size in bytes of the red zone: a region just below the stack pointer
    /// that a leaf function may use as scratch without adjusting the stack
    /// pointer. 0 when the ABI has no red zone (only System V x86-64 uses 128).
    RedZoneSize: int
    /// Size in bytes of the shadow (home) space that the caller reserves above
    /// the return address for spilling the register arguments. 0 when the ABI
    /// has no shadow space (only the Microsoft x64 ABI uses 32).
    ShadowSpaceSize: int }

/// Builds the stack-frame convention for a given OS and ISA.
[<RequireQualifiedAccess>]
module StackConvention =
  let private make alignment redZone shadow =
    { Alignment = alignment; RedZoneSize = redZone; ShadowSpaceSize = shadow }

  /// Builds the stack-frame convention for the given OS and ISA. macOS and any
  /// unknown OS share the System V geometry; only Windows and the per-ISA
  /// alignments differ. Unmodeled ISAs fall back to System V x64, so this never
  /// throws.
  [<CompiledName "Create">]
  let create os isa =
    match os, isa with
    | OS.Windows, X86 -> make 4 0 0
    | OS.Windows, X64 -> make 16 0 32
    | _, X86 -> make 16 0 0
    | _, ARM32 -> make 8 0 0
    | _, AArch64 -> make 16 0 0
    | _, MIPS -> make 8 0 0
    | _, PPC -> make 16 0 0
    | _, RISCV64 -> make 16 0 0
    | _, SPARC -> make 16 0 0
    | _, S390 -> make 8 0 0
    | _, M68K -> make 4 0 0
    | _, SH4 -> make 4 0 0
    | _, PARISC -> make 8 0 0
    | _ -> make 16 128 0
