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

namespace B2R2.FrontEnd

open System
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter

/// <summary>
/// Represents a basic unit for lifting binaries, which can be used to parse,
/// disassemble, and lift instructions. To lift a binary in parallel, one needs
/// to create multiple lifting units.
/// </summary>
type LiftingUnit (binFile: IBinFile,
                  regFactory: IRegisterFactory,
                  parser: IInstructionParsable) =

  let irBuilder = GroundWork.CreateBuilder binFile.ISA regFactory

  let getAlignment =
    match binFile.ISA with
    | Intel | EVM | WASM | Python -> fun () -> 1
    | ARM32 ->
      let switch = parser :?> ARM32.IModeSwitchable
      fun () -> if switch.IsThumb then 2 else 4
    | AArch64 | MIPS | TMS320C6000 | PPC32 | PARISC -> fun () -> 4
    | AVR | RISCV64 | SH4 | SPARC -> fun () -> 2
    | _ -> Terminator.futureFeature ()

  let strDisasm =
    StringDisasmBuilder (true, binFile, binFile.ISA.WordSize)
    :> IDisasmBuilder

  let asmwordDisasm =
    AsmWordDisasmBuilder (false, binFile, binFile.ISA.WordSize)
    :> IDisasmBuilder

  let toReversedArray cnt lst =
    let arr = Array.zeroCreate cnt
    let mutable idx = cnt - 1
    for elt in lst do
      arr[idx] <- elt
      idx <- idx - 1
    arr

  let rec parseBBLByPtr (ptr: BinFilePointer) cnt acc =
    let parsed =
      try
        let len = ptr.MaxOffset - ptr.Offset + 1
        let span = ReadOnlySpan (binFile.RawBytes, ptr.Offset, len)
        Ok <| parser.Parse (span, ptr.Addr)
      with _ -> Error ErrorCase.ParsingFailure
    match parsed with
    | Ok ins ->
      if ins.IsTerminator () then
        Ok <| toReversedArray (cnt + 1) (ins :: acc)
      else
        let ptr = BinFilePointer.Advance ptr (int ins.Length)
        if ptr.IsValid then parseBBLByPtr ptr (cnt + 1) (ins :: acc)
        else Error <| toReversedArray (cnt + 1) (ins :: acc)
    | Error _ -> Error <| toReversedArray cnt acc

  /// Binary file to be lifted.
  member _.File with get () = binFile

  /// Parser of this lifting unit.
  member _.Parser with get () = parser

  /// The instruction alignment (in bytes) enforced by the CPU. For example, ARM
  /// requires instructions to be aligned to 4 bytes, while x86 does not have
  /// such a requirement (i.e., 1-byte alignment).
  member _.InstructionAlignment with get () = getAlignment ()

  /// <summary>
  /// Parses one instruction at the given address (addr), and return the
  /// corresponding instruction. This function raises an exception if the
  /// parsing process fails.
  /// <remark>
  /// It is recommended to use the same method that takes in a pointer when
  /// the performance is a concern.
  /// </remark>
  /// </summary>
  /// <param name="addr">The instruction address.</param>
  /// <returns>
  /// Parsed instruction.
  /// </returns>
  member _.ParseInstruction (addr: Addr) =
    let ptr = binFile.GetBoundedPointer addr
    let len = ptr.MaxOffset - ptr.Offset + 1
    parser.Parse (ReadOnlySpan (binFile.RawBytes, ptr.Offset, len), addr)

  /// <summary>
  /// Parses one instruction pointed to by the binary file pointer (ptr), and
  /// return the corresponding instruction. This function raises an exception if
  /// the parsing process fails.
  /// </summary>
  /// <param name="ptr">BinFilePointer.</param>
  /// <returns>
  /// Parsed instruction.
  /// </returns>
  member _.ParseInstruction (ptr: BinFilePointer) =
    let len = ptr.MaxOffset - ptr.Offset + 1
    parser.Parse (ReadOnlySpan (binFile.RawBytes, ptr.Offset, len), ptr.Addr)

  /// <summary>
  /// Tries to parse one instruction at the given address (addr), and return the
  /// corresponding instruction.
  /// </summary>
  /// <param name="addr">The instruction address.</param>
  /// <returns>
  /// Parsed instruction if succeeded, ErrorCase if otherwise.
  /// </returns>
  member this.TryParseInstruction (addr: Addr) =
    try this.ParseInstruction addr |> Ok
    with _ -> Error ErrorCase.ParsingFailure

  /// <summary>
  /// Tries to parse one instruction pointed to by the binary file pointer
  /// (ptr), and return the corresponding instruction.
  /// </summary>
  /// <param name="ptr">BinFilePointer.</param>
  /// <returns>
  /// Parsed instruction if succeeded, ErrorCase if otherwise.
  /// </returns>
  member this.TryParseInstruction (ptr: BinFilePointer) =
    try this.ParseInstruction ptr |> Ok
    with _ -> Error ErrorCase.ParsingFailure

  /// <summary>
  /// Parses a basic block starting from the given address (addr), and return
  /// the corresponding array of instructions. This function returns an
  /// incomplete list of instructions if the parsing process fails.
  /// <remark>
  /// It is recommended to use the same method that takes in a pointer when
  /// the performance is a concern.
  /// </remark>
  /// </summary>
  /// <param name="addr">The basic block address.</param>
  /// <returns>
  /// Parsed basic block (i.e., an array of instructions).
  /// </returns>
  member _.ParseBBlock (addr: Addr) =
    let ptr = binFile.GetBoundedPointer addr
    parseBBLByPtr ptr 0 []

  /// <summary>
  /// Parses a basic block pointed to by the given binary file pointer (ptr),
  /// and return the corresponding array of instructions. This function returns
  /// an incomplete list of instructions if the parsing process fails.
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <returns>
  /// Parsed basic block (i.e., an array of instructions).
  /// </returns>
  member _.ParseBBlock (ptr: BinFilePointer) =
    parseBBLByPtr ptr 0 []

  /// <summary>
  /// Lifts an instruction at the given address (addr) and return the lifted IR
  /// statements without optimization.
  /// <remark>
  /// It is recommended to use the same method that takes in a pointer when
  /// the performance is a concern.
  /// </remark>
  /// </summary>
  /// <param name="addr">The instruction address.</param>
  /// <returns>
  /// Lifted IR statements.
  /// </returns>
  member this.LiftInstruction (addr: Addr) =
    this.LiftInstruction (addr, false)

  /// <summary>
  /// Lifts an instruction at the given address (addr) and return the lifted IR
  /// statements.
  /// <remark>
  /// It is recommended to use the same method that takes in a pointer when
  /// the performance is a concern.
  /// </remark>
  /// </summary>
  /// <param name="addr">The instruction address.</param>
  /// <param name="optimize">
  /// Whether to optimize the lifted IR statements or not.
  /// </param>
  /// <returns>
  /// Lifted IR statements.
  /// </returns>
  member _.LiftInstruction (addr: Addr, optimize) =
    let ptr = binFile.GetBoundedPointer addr
    let len = ptr.MaxOffset - ptr.Offset + 1
    let span = ReadOnlySpan (binFile.RawBytes, ptr.Offset, len)
    let ins = parser.Parse (span, addr)
    if optimize then ins.Translate irBuilder |> LocalOptimizer.Optimize
    else ins.Translate irBuilder

  /// <summary>
  /// Lifts an instruction pointed to by the given pointer and return the
  /// lifted IR statements.
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <returns>
  /// Lifted IR statements.
  /// </returns>
  member _.LiftInstruction (ptr: BinFilePointer) =
    let len = ptr.MaxOffset - ptr.Offset + 1
    let span = ReadOnlySpan (binFile.RawBytes, ptr.Offset, len)
    let ins = parser.Parse (span, ptr.Addr)
    ins.Translate irBuilder

  /// <summary>
  /// Lifts an instruction pointed to by the given pointer and return the lifted
  /// IR statements.
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <param name="optimize">
  /// Whether to optimize the lifted IR statements or not.
  /// </param>
  /// <returns>
  /// Lifted IR statements.
  /// </returns>
  member _.LiftInstruction (ptr: BinFilePointer, optimize) =
    let len = ptr.MaxOffset - ptr.Offset + 1
    let span = ReadOnlySpan (binFile.RawBytes, ptr.Offset, len)
    let ins = parser.Parse (span, ptr.Addr)
    if optimize then ins.Translate irBuilder |> LocalOptimizer.Optimize
    else ins.Translate irBuilder

  /// <summary>
  /// Lifts the given instruction and return the lifted IR statements.
  /// </summary>
  /// <param name="ins">The instruction to be lifted.</param>
  /// <returns>
  /// Lifted IR statements.
  /// </returns>
  member _.LiftInstruction (ins: IInstruction) =
    ins.Translate irBuilder

  /// <summary>
  /// Lifts the given instruction and return the lifted IR statements.
  /// </summary>
  /// <param name="ins">The instruction to be lifted.</param>
  /// <param name="optimize">
  /// Whether to optimize the lifted IR statements or not.
  /// </param>
  /// <returns>
  /// Lifted IR statements.
  /// </returns>
  member _.LiftInstruction (ins: IInstruction, optimize) =
    if optimize then ins.Translate irBuilder |> LocalOptimizer.Optimize
    else ins.Translate irBuilder

  /// <summary>
  /// Lifts a basic block starting from the given address (addr) and return the
  /// lifted IR statements, grouped by instructions. This function returns an
  /// incomplete list of IR statments if the parsing process fails.
  /// </summary>
  /// <param name="addr">The start address.</param>
  /// <returns>
  /// Array of lifted IR statements, grouped by instructions.
  /// </returns>
  member _.LiftBBlock (addr: Addr) =
    let ptr = binFile.GetBoundedPointer addr
    match parseBBLByPtr ptr 0 [] with
    | Ok instrs ->
      instrs |> Array.map (fun i -> i.Translate irBuilder) |> Ok
    | Error instrs ->
      instrs |> Array.map (fun i -> i.Translate irBuilder) |> Error

  /// <summary>
  /// Lift a basic block starting from the given pointer (ptr) and return the
  /// lifted IR statements, grouped by instructions. This function returns an
  /// incomplete list of IR statments if the parsing process fails.
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <returns>
  /// Array of lifted IR statements, grouped by instructions.
  /// </returns>
  member _.LiftBBlock (ptr: BinFilePointer) =
    match parseBBLByPtr ptr 0 [] with
    | Ok instrs ->
      instrs |> Array.map (fun i -> i.Translate irBuilder) |> Ok
    | Error instrs ->
      instrs |> Array.map (fun i -> i.Translate irBuilder) |> Error

  /// <summary>
  /// Configure the disassembly output format for each disassembled instruction
  /// to show the address of the instruction or not.
  /// </summary>
  member _.ConfigureDisassembly (showAddr) =
    strDisasm.ShowAddress <- showAddr

  /// <summary>
  /// Configure the disassembly output format for each disassembled instruction.
  /// Subsequent disassembly will use the configured format.
  /// </summary>
  member _.ConfigureDisassembly (showAddr, showSymbol) =
    strDisasm.ShowAddress <- showAddr
    strDisasm.ShowSymbol <- showSymbol

  /// <summary>
  /// Disassemble the given instruction and return the disassembled string.
  /// </summary>
  /// <param name="ins">The instruction to disassemble.</param>
  /// <returns>
  /// Disassembled string.
  /// </returns>
  member _.DisasmInstruction (ins: IInstruction) =
    ins.Disasm strDisasm

  /// <summary>
  /// Disassemble an instruction at the given address (addr) and return the
  /// disassembled string. The output does not show the address of the
  /// instruction nor resolve the symbols of references.
  /// </summary>
  /// <param name="addr">The instruction address.</param>
  /// <returns>
  /// Disassembled string.
  /// </returns>
  member _.DisasmInstruction (addr: Addr) =
    let ptr = binFile.GetBoundedPointer addr
    let len = ptr.MaxOffset - ptr.Offset + 1
    let span = ReadOnlySpan (binFile.RawBytes, ptr.Offset, len)
    let ins = parser.Parse (span, addr)
    ins.Disasm ()

  /// <summary>
  /// Disassemble an instruction pointed to by the given pointer (ptr) and
  /// return the disassembled string. The output does not show the address of
  /// the instruction nor resolve the symbols of references.
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <returns>
  /// Disassembled string.
  /// </returns>
  member _.DisasmInstruction (ptr: BinFilePointer) =
    let len = ptr.MaxOffset - ptr.Offset + 1
    let span = ReadOnlySpan (binFile.RawBytes, ptr.Offset, len)
    let ins = parser.Parse (span, ptr.Addr)
    ins.Disasm ()

  /// <summary>
  /// Decompose the given instruction and return the disassembled sequence of
  /// AsmWords.
  /// </summary>
  /// <param name="ins">The instruction to decompose.</param>
  /// <returns>
  /// Decomposed AsmWords.
  /// </returns>
  member _.DecomposeInstruction (ins: IInstruction) =
    ins.Decompose asmwordDisasm

  /// <summary>
  /// Decompose an instruction at the given address (addr) and return the
  /// disassembled sequence of AsmWords.
  /// </summary>
  /// <param name="addr">The instruction address.</param>
  /// <returns>
  ///   Decomposed AsmWords.
  /// </returns>
  member _.DecomposeInstruction (addr: Addr) =
    let ptr = binFile.GetBoundedPointer addr
    let len = ptr.MaxOffset - ptr.Offset + 1
    let span = ReadOnlySpan (binFile.RawBytes, ptr.Offset, len)
    let ins = parser.Parse (span, addr)
    ins.Decompose asmwordDisasm

  /// <summary>
  /// Decompose an instruction pointed to by the given pointer (ptr) and return
  /// the disassembled sequence of AsmWords.
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <returns>
  /// Decomposed AsmWords.
  /// </returns>
  member _.DecomposeInstruction (ptr: BinFilePointer) =
    let len = ptr.MaxOffset - ptr.Offset + 1
    let span = ReadOnlySpan (binFile.RawBytes, ptr.Offset, len)
    let ins = parser.Parse (span, ptr.Addr)
    ins.Decompose asmwordDisasm

  /// <summary>
  /// Sets the disassembly syntax for the disassembler. Only Intel architecture
  /// is affected by this setting.
  /// </summary>
  member _.SetDisassemblySyntax syntax =
    match binFile.ISA with
    | Intel -> (parser :?> Intel.IntelParser).SetDisassemblySyntax syntax
    | _ -> ()
