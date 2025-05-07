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

open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter

/// Lifting unit is responsible for parsing/lifting binary instructions. To
/// lift a binary file in parallel, one needs to create multiple lifting units.
type LiftingUnit (binFile: IBinFile,
                  regFactory: IRegisterFactory,
                  parser: IInstructionParsable) =

  let irBuilder = GroundWork.CreateBuilder binFile.ISA regFactory

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

  let rec parseBBLByAddr addr cnt acc =
    let parsed =
      try parser.Parse (binFile.Slice (addr=addr), addr) |> Ok
      with _ -> Error ErrorCase.ParsingFailure
    match parsed with
    | Ok ins ->
      if ins.IsTerminator () then Ok <| toReversedArray (cnt + 1) (ins :: acc)
      else parseBBLByAddr (addr + uint64 ins.Length) (cnt + 1) (ins :: acc)
    | Error _ -> Error <| toReversedArray cnt acc

  let rec parseBBLByPtr (ptr: BinFilePointer) cnt acc =
    let parsed =
      try
        let span = binFile.Slice ptr.Offset
        let ins = parser.Parse (span, ptr.Addr)
        if BinFilePointer.IsValidAccess ptr (int ins.Length) then Ok ins
        else Error ErrorCase.ParsingFailure
      with _ -> Error ErrorCase.ParsingFailure
    match parsed with
    | Ok ins ->
      if ins.IsTerminator () then Ok <| toReversedArray (cnt + 1) (ins :: acc)
      else
        let ptr = BinFilePointer.Advance ptr (int ins.Length)
        parseBBLByPtr ptr (cnt + 1) (ins :: acc)
    | Error _ -> Error <| toReversedArray cnt acc

  /// Binary file to be lifted.
  member _.File with get() = binFile

  /// Parser of this lifting unit.
  member _.Parser with get() = parser

  /// <summary>
  /// Parse one instruction at the given address (addr), and return the
  /// corresponding instruction. This function raises an exception if the
  /// parsing process fails.
  /// </summary>
  /// <param name="addr">The instruction address.</param>
  /// <returns>
  /// Parsed instruction.
  /// </returns>
  member _.ParseInstruction (addr: Addr) =
    parser.Parse (binFile.Slice addr, addr)

  /// <summary>
  /// Parse one instruction pointed to by the binary file pointer (ptr), and
  /// return the corresponding instruction. This function raises an exception if
  /// the parsing process fails.
  /// </summary>
  /// <param name="ptr">BinFilePointer.</param>
  /// <returns>
  /// Parsed instruction.
  /// </returns>
  member _.ParseInstruction (ptr: BinFilePointer) =
    let span = binFile.Slice ptr.Offset
    let ins = parser.Parse (span, ptr.Addr)
    if BinFilePointer.IsValidAccess ptr (int ins.Length) then ins
    else raise ParsingFailureException

  /// <summary>
  /// Try to parse one instruction at the given address (addr), and return the
  /// corresponding instruction.
  /// </summary>
  /// <param name="addr">The instruction address.</param>
  /// <returns>
  /// Parsed instruction if succeeded, ErrorCase if otherwise.
  /// </returns>
  member _.TryParseInstruction (addr: Addr) =
    try parser.Parse (binFile.Slice (addr=addr), addr) |> Ok
    with _ -> Error ErrorCase.ParsingFailure

  /// <summary>
  /// Try to parse one instruction pointed to by the binary file pointer (ptr),
  /// and return the corresponding instruction.
  /// </summary>
  /// <param name="ptr">BinFilePointer.</param>
  /// <returns>
  /// Parsed instruction if succeeded, ErrorCase if otherwise.
  /// </returns>
  member _.TryParseInstruction (ptr: BinFilePointer) =
    try
      let span = binFile.Slice ptr.Offset
      let ins = parser.Parse (span, ptr.Addr)
      if BinFilePointer.IsValidAccess ptr (int ins.Length) then Ok ins
      else Error ErrorCase.ParsingFailure
    with _ ->
      Error ErrorCase.ParsingFailure

  /// <summary>
  /// Parse a basic block starting from the given address (addr), and return the
  /// corresponding array of instructions. This function returns an incomplete
  /// list of instructions if the parsing process fails.
  /// </summary>
  /// <param name="addr">The basic block address.</param>
  /// <returns>
  /// Parsed basic block (i.e., an array of instructions).
  /// </returns>
  member _.ParseBBlock (addr: Addr) =
    parseBBLByAddr addr 0 []

  /// <summary>
  /// Parse a basic block pointed to by the given binary file pointer (ptr), and
  /// return the corresponding array of instructions. This function returns an
  /// incomplete list of instructions if the parsing process fails.
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <returns>
  /// Parsed basic block (i.e., an array of instructions).
  /// </returns>
  member _.ParseBBlock (ptr: BinFilePointer) =
    parseBBLByPtr ptr 0 []

  /// <summary>
  /// Lift an instruction at the given address (addr) and return the lifted IR
  /// statements.
  /// </summary>
  /// <param name="addr">The instruction address.</param>
  /// <returns>
  /// Lifted IR statements.
  /// </returns>
  member _.LiftInstruction (addr: Addr) =
    let ins = parser.Parse (binFile.Slice addr, addr)
    ins.Translate irBuilder

  /// <summary>
  /// Lift an instruction at the given address (addr) and return the lifted IR
  /// statements.
  /// </summary>
  /// <param name="addr">The instruction address.</param>
  /// <param name="optimize">
  /// Whether to optimize the lifted IR statements or not.
  /// </param>
  /// <returns>
  /// Lifted IR statements.
  /// </returns>
  member _.LiftInstruction (addr: Addr, optimize) =
    let ins = parser.Parse (binFile.Slice addr, addr)
    if optimize then ins.Translate irBuilder |> LocalOptimizer.Optimize
    else ins.Translate irBuilder

  /// <summary>
  /// Lift an instruction pointed to by the given pointer and return the
  /// lifted IR statements.
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <returns>
  /// Lifted IR statements.
  /// </returns>
  member _.LiftInstruction (ptr: BinFilePointer) =
    let span = binFile.Slice ptr.Offset
    let ins = parser.Parse (span, ptr.Addr)
    if BinFilePointer.IsValidAccess ptr (int ins.Length) then
      ins.Translate irBuilder
    else raise ParsingFailureException

  /// <summary>
  /// Lift an instruction pointed to by the given pointer and return the lifted
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
    let span = binFile.Slice ptr.Offset
    let ins = parser.Parse (span, ptr.Addr)
    if BinFilePointer.IsValidAccess ptr (int ins.Length) then
      if optimize then ins.Translate irBuilder |> LocalOptimizer.Optimize
      else ins.Translate irBuilder
    else raise ParsingFailureException

  /// <summary>
  /// Lift the given instruction and return the lifted IR statements.
  /// </summary>
  /// <param name="ins">The instruction to be lifted.</param>
  /// <returns>
  /// Lifted IR statements.
  /// </returns>
  member _.LiftInstruction (ins: IInstruction) =
    ins.Translate irBuilder

  /// <summary>
  /// Lift the given instruction and return the lifted IR statements.
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
  /// Lift a basic block starting from the given address (addr) and return the
  /// lifted IR statements. This function returns an incomplete list of IR
  /// statments if the parsing process fails.
  /// </summary>
  /// <param name="addr">The start address.</param>
  /// <returns>
  /// Lifted IR statements.
  /// </returns>
  member _.LiftBBlock (addr: Addr) =
    match parseBBLByAddr addr 0 [] with
    | Ok instrs ->
      instrs |> Array.collect (fun i -> i.Translate irBuilder) |> Ok
    | Error instrs ->
      instrs |> Array.collect (fun i -> i.Translate irBuilder) |> Error

  /// <summary>
  /// Lift a basic block starting from the given pointer (ptr) and return the
  /// lifted IR statements. This function returns an incomplete list of IR
  /// statments if the parsing process fails.
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <returns>
  /// Lifted IR statements.
  /// </returns>
  member _.LiftBBlock (ptr: BinFilePointer) =
    match parseBBLByPtr ptr 0 [] with
    | Ok instrs ->
      instrs |> Array.collect (fun i -> i.Translate irBuilder) |> Ok
    | Error instrs ->
      instrs |> Array.collect (fun i -> i.Translate irBuilder) |> Error

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
    let ins = parser.Parse (binFile.Slice addr, addr)
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
    let span = binFile.Slice ptr.Offset
    let ins = parser.Parse (span, ptr.Addr)
    if BinFilePointer.IsValidAccess ptr (int ins.Length) then ins.Disasm ()
    else raise ParsingFailureException

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
    let ins = parser.Parse (binFile.Slice addr, addr)
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
    let span = binFile.Slice ptr.Offset
    let ins = parser.Parse (span, ptr.Addr)
    if BinFilePointer.IsValidAccess ptr (int ins.Length) then
      ins.Decompose asmwordDisasm
    else raise ParsingFailureException

  /// <summary>
  /// Sets the disassembly syntax for the disassembler. Only Intel architecture
  /// is affected by this setting.
  /// </summary>
  member _.SetDisassemblySyntax syntax =
    match binFile.ISA.Arch with
    | Architecture.IntelX86
    | Architecture.IntelX64 ->
      (parser :?> Intel.IntelParser).SetDisassemblySyntax syntax
    | _ -> ()
