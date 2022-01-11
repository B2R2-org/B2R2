namespace B2R2.FrontEnd.BinLifter.WASM

open System
open B2R2
open B2R2.FrontEnd.BinLifter

/// Translation context for WASM instructions.
type WASMTranslationContext internal (isa, regexprs) =
  inherit TranslationContext (isa)
  /// Register expressions.
  member val private RegExprs: RegExprs = regexprs
  override __.GetRegVar id = Register.ofRegID id |> __.RegExprs.GetRegVar
  override __.GetPseudoRegVar _id _pos = failwith "Implement"

/// Parser for WASM instructions. Parser will return a platform-agnostic
/// instruction type (Instruction).
type WASMParser (wordSize) =
  inherit Parser ()
  let reader = BinReader.binReaderLE

  override __.Parse (bs: byte[], addr) =
    let span = ReadOnlySpan bs
    Parser.parse span reader addr :> Instruction

  override __.Parse (span: ByteSpan, addr) =
    Parser.parse span reader addr :> Instruction

  override __.OperationMode with get() = ArchOperationMode.NoMode and set _ = ()

module Basis =
  let init (isa: ISA) =
    let regexprs = RegExprs ()
    struct (
      WASMTranslationContext (isa, regexprs) :> TranslationContext,
      WASMRegisterBay () :> RegisterBay
    )

// vim: set tw=80 sts=2 sw=2: