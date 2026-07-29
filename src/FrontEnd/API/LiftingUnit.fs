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
open B2R2.BinIR.LowUIR
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

  let names = Option.toObj binFile.NameResolver

  (* Both builders start with the address off, so that the same instruction
     reads the same way whichever member rendered it. Callers that want the
     address ask for it through ConfigureDisassembly, which sets both. *)
  let strDisasm =
    StringDisasmBuilder(false, names, binFile.ISA.WordSize) :> IDisasmBuilder

  let asmwordDisasm =
    AsmWordDisasmBuilder(false, names, binFile.ISA.WordSize) :> IDisasmBuilder

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
        { IsTerminated = true
          Instructions = toReversedArray (cnt + 1) (ins :: acc) }
      else
        let ptr = ptr.Advance ins.Length
        if ptr.CanReadFileBytes then
          parseBBLByPtr ins ptr (cnt + 1) (ins :: acc)
        else
          { IsTerminated = false
            Instructions = toReversedArray (cnt + 1) (ins :: acc) }
    | Error _ ->
      { IsTerminated = false; Instructions = toReversedArray cnt acc }

  let codeSpan (ptr: BinFilePointer) =
    let len = ptr.ReadableAmount
    if len > 0 then
      ()
    else
      invalidArg (nameof ptr) (ErrorCase.toMessage ErrorCase.InvalidMemoryRead)
    rawBytes.Span.Slice(ptr.Offset, len)

  let liftBBLByPtr ptr =
    let parsed = parseBBLByPtr null ptr 0 []
    let lift (i: IInstruction) = i.Translate irBuilder
    { IsTerminated = parsed.IsTerminated
      Statements = Array.map lift parsed.Instructions }

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
  /// Parses a basic block starting from the given address (addr), returning its
  /// instructions. Parsing may stop before a terminator, so read
  /// <c>IsTerminated</c> to tell a whole block from one cut short.
  /// <remarks>
  /// It is recommended to use the same method that takes in a pointer when
  /// the performance is a concern.
  /// </remarks>
  /// </summary>
  /// <param name="addr">The basic block address.</param>
  /// <returns>
  /// Returns a <see cref='T:B2R2.FrontEnd.BBlockParseResult'/>.
  /// </returns>
  member _.ParseBBlock(addr: Addr) =
    let ptr = binFile.GetBoundedPointer addr
    parseBBLByPtr null ptr 0 []

  /// <summary>
  /// Parses a basic block pointed to by the given binary file pointer (ptr),
  /// returning its instructions. Parsing may stop before a terminator, so read
  /// <c>IsTerminated</c> to tell a whole block from one cut short.
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <returns>
  /// Returns a <see cref='T:B2R2.FrontEnd.BBlockParseResult'/>.
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
  /// Lifts a basic block starting from the given address (addr), returning the
  /// lifted IR statements grouped by instruction. Parsing may stop before a
  /// terminator, so read <c>IsTerminated</c> to tell a whole block from one cut
  /// short.
  /// </summary>
  /// <param name="addr">The start address.</param>
  /// <returns>
  /// Returns a <see cref='T:B2R2.FrontEnd.BBlockLiftResult'/>.
  /// </returns>
  member _.LiftBBlock(addr: Addr) =
    binFile.GetBoundedPointer addr |> liftBBLByPtr

  /// <summary>
  /// Lifts a basic block starting from the given pointer (ptr), returning the
  /// lifted IR statements grouped by instruction. Parsing may stop before a
  /// terminator, so read <c>IsTerminated</c> to tell a whole block from one cut
  /// short.
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <returns>
  /// Returns a <see cref='T:B2R2.FrontEnd.BBlockLiftResult'/>.
  /// </returns>
  member _.LiftBBlock(ptr: BinFilePointer) = liftBBLByPtr ptr

  /// <summary>
  /// Configure the disassembly output format for each disassembled instruction
  /// to show the address of the instruction or not. This applies to every
  /// <c>Disasm*</c> and <c>Decompose*</c> member alike.
  /// </summary>
  member _.ConfigureDisassembly(showAddr) =
    strDisasm.ShowAddress <- showAddr
    asmwordDisasm.ShowAddress <- showAddr

  /// <summary>
  /// Configure the disassembly output format for each disassembled instruction.
  /// Subsequent disassembly will use the configured format. This applies to
  /// every <c>Disasm*</c> and <c>Decompose*</c> member alike. Symbols are shown
  /// only when the underlying file can resolve names, so asking for them has no
  /// effect on a raw image.
  /// </summary>
  member _.ConfigureDisassembly(showAddr, showSymbol) =
    strDisasm.ShowAddress <- showAddr
    strDisasm.ShowSymbol <- showSymbol
    asmwordDisasm.ShowAddress <- showAddr
    asmwordDisasm.ShowSymbol <- showSymbol

  /// <summary>
  /// Disassemble the given instruction and return the disassembled string,
  /// using the format set by
  /// <see cref='M:B2R2.FrontEnd.LiftingUnit.ConfigureDisassembly'/>.
  /// </summary>
  /// <param name="ins">The instruction to disassemble.</param>
  /// <returns>
  /// Disassembled string.
  /// </returns>
  member _.DisasmInstruction(ins: IInstruction) = ins.Disasm strDisasm

  /// <summary>
  /// Disassemble an instruction at the given address (addr) and return the
  /// disassembled string, using the format set by
  /// <see cref='M:B2R2.FrontEnd.LiftingUnit.ConfigureDisassembly'/>.
  /// </summary>
  /// <param name="addr">The instruction address.</param>
  /// <returns>
  /// Disassembled string.
  /// </returns>
  member _.DisasmInstruction(addr: Addr) =
    let ptr = binFile.GetBoundedPointer addr
    let span = codeSpan ptr
    let ins = parser.Parse(span, addr)
    ins.Disasm strDisasm

  /// <summary>
  /// Disassemble an instruction pointed to by the given pointer (ptr) and
  /// return the disassembled string, using the format set by
  /// <see cref='M:B2R2.FrontEnd.LiftingUnit.ConfigureDisassembly'/>.
  /// </summary>
  /// <param name="ptr">The binary file pointer.</param>
  /// <returns>
  /// Disassembled string.
  /// </returns>
  member _.DisasmInstruction(ptr: BinFilePointer) =
    let span = codeSpan ptr
    let ins = parser.Parse(span, ptr.Addr)
    ins.Disasm strDisasm

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

/// <summary>
/// Represents the result of parsing a basic block. Parsing walks instructions
/// until one of them terminates the block, so it can also stop early, either
/// because it ran out of readable bytes or because an instruction failed to
/// decode. Both outcomes carry what was parsed, which is why they are told
/// apart by <c>IsTerminated</c> rather than by the type of the payload.
/// </summary>
and [<Struct>] BBlockParseResult =
  { /// Whether parsing reached an instruction that terminates the block. When
    /// this is false the block was cut short, not rejected.
    IsTerminated: bool
    /// The whole block when IsTerminated holds; otherwise the instructions
    /// parsed before parsing stopped, which may be empty.
    Instructions: IInstruction[] }

/// <summary>
/// Represents the result of lifting a basic block. The block is parsed first,
/// so this carries the same distinction as <see
/// cref='T:B2R2.FrontEnd.BBlockParseResult'/>: parsing may stop before a
/// terminator, and what was lifted up to that point is still given.
/// </summary>
and [<Struct>] BBlockLiftResult =
  { /// Whether parsing reached an instruction that terminates the block. When
    /// this is false the block was cut short, not rejected.
    IsTerminated: bool
    /// The whole block when IsTerminated holds; otherwise the statements lifted
    /// from the instructions parsed before parsing stopped. Grouped by
    /// instruction, and possibly empty.
    Statements: Stmt[][] }
