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

/// <summary>
/// Represents a basic unit for lifting binaries, which can be used to parse,
/// disassemble, and lift instructions. To lift a binary in parallel, one needs
/// to create multiple lifting units.
/// </summary>
type LiftingUnit
  internal(binFile: IBinFile,
           regFactory: IRegisterFactory,
           parser: IInstructionParsable) =

  let irBuilder = ArchSupport.createBuilder binFile.ISA regFactory

  let rawBytes = binFile.RawBytes

  (* ARM32 is the only architecture with a parsing mode, and ArchSupport builds
     an ARM32Parser for every ISA the ARM32 pattern covers, AArch32 included.
     Owning the test here is what lets callers set a mode without repeating it;
     two of them used to test for ARMv7 alone and silently ignored AArch32. *)
  let modeSwitch =
    match binFile.ISA with
    | ARM32 ->
      parser :?> ARM32.IModeSwitchable
    | _ ->
      { new ARM32.IModeSwitchable with
          member _.IsThumb with get() = false and set _ = ()
          member _.ITState with get() = 0uy and set _ = () }

  let strDisasm =
    match binFile.NameResolver with
    | Some names ->
      StringDisasmBuilder(true, names, binFile.ISA.WordSize) :> IDisasmBuilder
    | None ->
      StringDisasmBuilder(true, null, binFile.ISA.WordSize) :> IDisasmBuilder

  let asmwordDisasm =
    match binFile.NameResolver with
    | Some names ->
      AsmWordDisasmBuilder(false, names, binFile.ISA.WordSize) :> IDisasmBuilder
    | None ->
      AsmWordDisasmBuilder(false, null, binFile.ISA.WordSize) :> IDisasmBuilder

  let mutable disasmSyntax = DefaultSyntax

  let toReversedArray cnt lst =
    let arr = Array.zeroCreate cnt
    let mutable idx = cnt - 1
    for elt in lst do
      arr[idx] <- elt
      idx <- idx - 1
    arr

  let rec parseBBLByPtr prevIns (ptr: BinFilePointer) cnt acc =
    let parsed =
      try
        let len = ptr.ReadableAmount
        if len <= 0 then
          Error ErrorCase.InvalidMemoryRead
        else
          let span = rawBytes.Span.Slice(ptr.Offset, len)
          Ok <| parser.Parse(span, ptr.Addr)
      with _ ->
        Error ErrorCase.ParsingFailure
    match parsed with
    | Ok ins ->
      if ins.IsTerminator prevIns then
        Ok <| toReversedArray (cnt + 1) (ins :: acc)
      else
        let ptr = ptr.Advance ins.Length
        if ptr.CanReadFileBytes then
          parseBBLByPtr ins ptr (cnt + 1) (ins :: acc)
        else
          Error <| toReversedArray (cnt + 1) (ins :: acc)
    | Error _ ->
      Error <| toReversedArray cnt acc

  let codeSpan (ptr: BinFilePointer) =
    let len = ptr.ReadableAmount
    if len > 0 then
      ()
    else
      invalidArg (nameof ptr) (ErrorCase.toMessage ErrorCase.InvalidMemoryRead)
    rawBytes.Span.Slice(ptr.Offset, len)

  /// Binary file to be lifted.
  member _.File with get() = binFile

  /// Whether this unit parses Thumb instructions. Reading this always yields
  /// false, and setting it has no effect, on architectures that have no
  /// ARM/Thumb distinction.
  member _.IsThumb
    with get() = modeSwitch.IsThumb
    and set v = modeSwitch.IsThumb <- v

  /// The state of the IT (If-Then) block the parser is currently inside, which
  /// is meaningful only in Thumb mode and reads as zero elsewhere. Exposed so
  /// that disassembly resuming mid-block can restore it.
  member _.ITState
    with get() = modeSwitch.ITState
    and set v = modeSwitch.ITState <- v

#if EMULATION
  /// The lazy condition-code op the IR builder currently carries: the last
  /// flag-defining operation lifted, or TraceStart when none is pending.
  /// Exposed so a block-at-a-time lifter can persist it across a fall-through
  /// block boundary, where no control-flow instruction flushes it to the CCOP
  /// pseudo-register.
  member _.ConditionCodeOp
    with get() = irBuilder.ConditionCodeOp
    and set v = irBuilder.ConditionCodeOp <- v
#endif

  /// The instruction alignment (in bytes) enforced by the CPU. For example, ARM
  /// requires instructions to be aligned to 4 bytes, while x86 does not have
  /// such a requirement (i.e., 1-byte alignment). For ARM32 this follows the
  /// parser's current mode: 2 bytes in Thumb mode and 4 bytes otherwise.
  member _.InstructionAlignment with get() = parser.InstructionAlignment

  /// <summary>
  /// The disassembly syntax currently in effect. Only Intel supports a syntax
  /// other than <c>DefaultSyntax</c>; assigning one that the architecture
  /// cannot honour leaves this unchanged, so reading it back is how a caller
  /// learns whether the request took effect.
  /// </summary>
  member _.DisassemblySyntax
    with get() = disasmSyntax
    and set syntax =
      match binFile.ISA with
      | Intel ->
        (parser :?> Intel.IntelParser).SetDisassemblySyntax syntax
        disasmSyntax <- syntax
      | _ -> ()

  /// <summary>
  /// Parses one instruction at the given address (addr), and return the
  /// corresponding instruction. This function raises an exception if the
  /// parsing process fails.
  /// <remarks>
  /// It is recommended to use the same method that takes in a pointer when
  /// the performance is a concern.
  /// </remarks>
  /// </summary>
  /// <param name="addr">The instruction address.</param>
  /// <returns>
  /// Parsed instruction.
  /// </returns>
  member _.ParseInstruction(addr: Addr) =
    let ptr = binFile.GetBoundedPointer addr
    parser.Parse(codeSpan ptr, addr)

  /// <summary>
  /// Parses one instruction pointed to by the binary file pointer (ptr), and
  /// return the corresponding instruction. This function raises an exception if
  /// the parsing process fails.
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <returns>
  /// Parsed instruction.
  /// </returns>
  member _.ParseInstruction(ptr: BinFilePointer) =
    parser.Parse(codeSpan ptr, ptr.Addr)

  /// <summary>
  /// Parses one instruction from the given byte span (span), pretending that it
  /// is located at the given address (addr). The span need not come from the
  /// file this unit was built for, and its bounds are not checked here, so the
  /// caller is responsible for passing a span that holds a whole instruction.
  /// This function raises an exception if the parsing process fails.
  /// </summary>
  /// <param name="span">The byte span holding the instruction.</param>
  /// <param name="addr">The address to assign to the instruction.</param>
  /// <returns>
  /// Parsed instruction.
  /// </returns>
  member _.ParseInstruction(span: ByteSpan, addr: Addr) =
    parser.Parse(span, addr)

  /// <summary>
  /// Tries to parse one instruction at the given address (addr), and return the
  /// corresponding instruction.
  /// </summary>
  /// <param name="addr">The instruction address.</param>
  /// <returns>
  /// Parsed instruction if succeeded, ErrorCase if otherwise.
  /// </returns>
  member this.TryParseInstruction(addr: Addr) =
    try this.ParseInstruction addr |> Ok
    with _ -> Error ErrorCase.ParsingFailure

  /// <summary>
  /// Tries to parse one instruction pointed to by the binary file pointer
  /// (ptr), and return the corresponding instruction.
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <returns>
  /// Parsed instruction if succeeded, ErrorCase if otherwise.
  /// </returns>
  member this.TryParseInstruction(ptr: BinFilePointer) =
    try this.ParseInstruction ptr |> Ok
    with _ -> Error ErrorCase.ParsingFailure

  /// <summary>
  /// Parses a basic block starting from the given address (addr), and return
  /// the corresponding array of instructions. This function returns an
  /// incomplete list of instructions if the parsing process fails.
  /// <remarks>
  /// It is recommended to use the same method that takes in a pointer when
  /// the performance is a concern.
  /// </remarks>
  /// </summary>
  /// <param name="addr">The basic block address.</param>
  /// <returns>
  /// Parsed basic block (i.e., an array of instructions).
  /// </returns>
  member _.ParseBBlock(addr: Addr) =
    let ptr = binFile.GetBoundedPointer addr
    parseBBLByPtr null ptr 0 []

  /// <summary>
  /// Parses a basic block pointed to by the given binary file pointer (ptr),
  /// and return the corresponding array of instructions. This function returns
  /// an incomplete list of instructions if the parsing process fails.
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <returns>
  /// Parsed basic block (i.e., an array of instructions).
  /// </returns>
  member _.ParseBBlock(ptr: BinFilePointer) =
    parseBBLByPtr null ptr 0 []

  /// <summary>
  /// Lifts an instruction at the given address (addr) and return the lifted IR
  /// statements without optimization.
  /// <remarks>
  /// It is recommended to use the same method that takes in a pointer when
  /// the performance is a concern.
  /// </remarks>
  /// </summary>
  /// <param name="addr">The instruction address.</param>
  /// <returns>
  /// Lifted IR statements.
  /// </returns>
  member this.LiftInstruction(addr: Addr) =
    this.LiftInstruction(addr, false)

  /// <summary>
  /// Lifts an instruction at the given address (addr) and return the lifted IR
  /// statements.
  /// <remarks>
  /// It is recommended to use the same method that takes in a pointer when
  /// the performance is a concern.
  /// </remarks>
  /// </summary>
  /// <param name="addr">The instruction address.</param>
  /// <param name="optimize">
  /// Whether to optimize the lifted IR statements or not.
  /// </param>
  /// <returns>
  /// Lifted IR statements.
  /// </returns>
  member _.LiftInstruction(addr: Addr, optimize) =
    let ptr = binFile.GetBoundedPointer addr
    let span = codeSpan ptr
    let ins = parser.Parse(span, addr)
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
  member _.LiftInstruction(ptr: BinFilePointer) =
    let span = codeSpan ptr
    let ins = parser.Parse(span, ptr.Addr)
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
  member _.LiftInstruction(ptr: BinFilePointer, optimize) =
    let span = codeSpan ptr
    let ins = parser.Parse(span, ptr.Addr)
    if optimize then ins.Translate irBuilder |> LocalOptimizer.Optimize
    else ins.Translate irBuilder

  /// <summary>
  /// Lifts the given instruction and return the lifted IR statements.
  /// </summary>
  /// <param name="ins">The instruction to be lifted.</param>
  /// <returns>
  /// Lifted IR statements.
  /// </returns>
  member _.LiftInstruction(ins: IInstruction) = ins.Translate irBuilder

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
  member _.LiftInstruction(ins: IInstruction, optimize) =
    if optimize then ins.Translate irBuilder |> LocalOptimizer.Optimize
    else ins.Translate irBuilder

  /// <summary>
  /// Lifts a basic block starting from the given address (addr) and return the
  /// lifted IR statements, grouped by instructions. This function returns an
  /// incomplete list of IR statements if the parsing process fails.
  /// </summary>
  /// <param name="addr">The start address.</param>
  /// <returns>
  /// Array of lifted IR statements, grouped by instructions.
  /// </returns>
  member _.LiftBBlock(addr: Addr) =
    let ptr = binFile.GetBoundedPointer addr
    match parseBBLByPtr null ptr 0 [] with
    | Ok instrs ->
      instrs |> Array.map (fun i -> i.Translate irBuilder) |> Ok
    | Error instrs ->
      instrs |> Array.map (fun i -> i.Translate irBuilder) |> Error

  /// <summary>
  /// Lift a basic block starting from the given pointer (ptr) and return the
  /// lifted IR statements, grouped by instructions. This function returns an
  /// incomplete list of IR statements if the parsing process fails.
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <returns>
  /// Array of lifted IR statements, grouped by instructions.
  /// </returns>
  member _.LiftBBlock(ptr: BinFilePointer) =
    match parseBBLByPtr null ptr 0 [] with
    | Ok instrs ->
      instrs |> Array.map (fun i -> i.Translate irBuilder) |> Ok
    | Error instrs ->
      instrs |> Array.map (fun i -> i.Translate irBuilder) |> Error

  /// <summary>
  /// Configure the disassembly output format for each disassembled instruction
  /// to show the address of the instruction or not.
  /// </summary>
  member _.ConfigureDisassembly(showAddr) = strDisasm.ShowAddress <- showAddr

  /// <summary>
  /// Configure the disassembly output format for each disassembled instruction.
  /// Subsequent disassembly will use the configured format.
  /// </summary>
  member _.ConfigureDisassembly(showAddr, showSymbol) =
    strDisasm.ShowAddress <- showAddr
    strDisasm.ShowSymbol <- showSymbol

  /// <summary>
  /// Disassemble the given instruction and return the disassembled string.
  /// </summary>
  /// <param name="ins">The instruction to disassemble.</param>
  /// <returns>
  /// Disassembled string.
  /// </returns>
  member _.DisasmInstruction(ins: IInstruction) = ins.Disasm strDisasm

  /// <summary>
  /// Disassemble an instruction at the given address (addr) and return the
  /// disassembled string. The output does not show the address of the
  /// instruction nor resolve the symbols of references.
  /// </summary>
  /// <param name="addr">The instruction address.</param>
  /// <returns>
  /// Disassembled string.
  /// </returns>
  member _.DisasmInstruction(addr: Addr) =
    let ptr = binFile.GetBoundedPointer addr
    let span = codeSpan ptr
    let ins = parser.Parse(span, addr)
    ins.Disasm()

  /// <summary>
  /// Disassemble an instruction pointed to by the given pointer (ptr) and
  /// return the disassembled string. The output does not show the address of
  /// the instruction nor resolve the symbols of references.
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <returns>
  /// Disassembled string.
  /// </returns>
  member _.DisasmInstruction(ptr: BinFilePointer) =
    let span = codeSpan ptr
    let ins = parser.Parse(span, ptr.Addr)
    ins.Disasm()

  /// <summary>
  /// Decompose the given instruction and return the disassembled sequence of
  /// AsmWords.
  /// </summary>
  /// <param name="ins">The instruction to decompose.</param>
  /// <returns>
  /// Decomposed AsmWords.
  /// </returns>
  member _.DecomposeInstruction(ins: IInstruction) = ins.Decompose asmwordDisasm

  /// <summary>
  /// Decompose an instruction at the given address (addr) and return the
  /// disassembled sequence of AsmWords.
  /// </summary>
  /// <param name="addr">The instruction address.</param>
  /// <returns>
  ///   Decomposed AsmWords.
  /// </returns>
  member _.DecomposeInstruction(addr: Addr) =
    let ptr = binFile.GetBoundedPointer addr
    let span = codeSpan ptr
    let ins = parser.Parse(span, addr)
    ins.Decompose asmwordDisasm

  /// <summary>
  /// Decompose an instruction pointed to by the given pointer (ptr) and return
  /// the disassembled sequence of AsmWords.
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <returns>
  /// Decomposed AsmWords.
  /// </returns>
  member _.DecomposeInstruction(ptr: BinFilePointer) =
    let span = codeSpan ptr
    let ins = parser.Parse(span, ptr.Addr)
    ins.Decompose asmwordDisasm
