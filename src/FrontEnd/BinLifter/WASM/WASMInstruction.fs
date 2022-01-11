namespace B2R2.FrontEnd.BinLifter.WASM

open B2R2
open B2R2.FrontEnd.BinLifter

/// The internal representation for a WASM instruction used by our
/// disassembler and lifter.
type WASMInstruction (addr, numBytes, insInfo) =
  inherit Instruction (addr, numBytes, WordSize.Bit32)

  /// Basic instruction information.
  member val Info: InsInfo = insInfo

  override __.IsBranch () =
    match __.Info.Opcode with
    | _ -> false

  override __.IsModeChanging () = false

  member __.HasConcJmpTarget () = Utils.futureFeature ()

  override __.IsDirectBranch () =
    __.IsBranch () && __.HasConcJmpTarget ()

  override __.IsIndirectBranch () =
    __.IsBranch () && (not <| __.HasConcJmpTarget ())

  override __.IsCondBranch () = Utils.futureFeature ()

  override __.IsCJmpOnTrue () = Utils.futureFeature ()

  override __.IsCall () = Utils.futureFeature ()

  override __.IsRET () = Utils.futureFeature ()

  override __.IsInterrupt () = Utils.futureFeature ()

  override __.IsExit () = Utils.futureFeature ()

  override __.IsBBLEnd () =
    __.IsDirectBranch () ||
    __.IsIndirectBranch ()

  override __.DirectBranchTarget (_addr: byref<Addr>) = Utils.futureFeature ()

  override __.IndirectTrampolineAddr (_addr: byref<Addr>) =
    Utils.futureFeature ()

  override __.Immediate (_v: byref<int64>) = Utils.futureFeature ()

  override __.GetNextInstrAddrs () = Utils.futureFeature ()

  override __.InterruptNum (_num: byref<int64>) = Utils.futureFeature ()

  override __.IsNop () = Utils.futureFeature ()

  override __.Translate ctxt = Utils.futureFeature()

  override __.TranslateToList ctxt = Utils.futureFeature()

  override __.Disasm (showAddr, _resolveSymbol, _fileInfo) =
    let builder =
      DisasmStringBuilder (showAddr, false, WordSize.Bit32, addr, numBytes)
    Disasm.disasm __.Info builder
    builder.Finalize ()

  override __.Disasm () =
    let builder =
      DisasmStringBuilder (false, false, WordSize.Bit32, addr, numBytes)
    Disasm.disasm __.Info builder
    builder.Finalize ()

  override __.Decompose (showAddr) =
    let builder =
      DisasmWordBuilder (showAddr, false, WordSize.Bit32, addr, numBytes, 8)
    Disasm.disasm __.Info builder
    builder.Finalize ()

  override __.IsInlinedAssembly () = false

  override __.Equals (_) = Utils.futureFeature ()
  override __.GetHashCode () = Utils.futureFeature ()

// vim: set tw=80 sts=2 sw=2:
