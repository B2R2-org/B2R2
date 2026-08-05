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

module B2R2.RearEnd.Assembler.Program

open System
open System.Collections.Generic
open B2R2
open B2R2.BinIR
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.RearEnd.Utils
open B2R2.Assembly

let [<Literal>] private NormalPrompt = "> "

/// The parser of the given ISA, made once and kept, since a single source may
/// need more than one: an ARM32 source that switches instruction sets needs
/// both of theirs.
let private parserFor (parsers: Dictionary<_, _>) (isa: ISA) =
  match parsers.TryGetValue(isa.ToString()) with
  | true, parser ->
    parser
  | false, _ ->
    let parser = ArchSupport.createParser (BinReader.Init isa.Endian) isa
    parsers[isa.ToString()] <- parser
    parser

/// Disassembles what was just assembled, with the parser of the ISA it was
/// assembled for rather than the one the command line named, because the
/// source may have said otherwise partway through.
let private printIns parsers addr (isa, bs) =
  let bCode = (BitConverter.ToString(bs: byte[])).Replace("-", "")
  let ins = (parserFor parsers isa).Parse(bs, addr)
  printfn "%08x: %-20s     %s" addr bCode (ins.Disasm())
  addr + uint64 (Array.length bs)

/// Gathers the assembled bytes so that they can be dumped into a raw binary
/// file, which is only requested when an output path is given.
type BinDumper(path: string option) =
  let buf = ResizeArray<byte>()
  let mutable hasError = false

  /// Appends the bytes of a single assembled instruction.
  member _.Add(bs: byte[]) =
    if Option.isSome path then buf.AddRange bs else ()

  /// Remembers that a part of the input failed to assemble, in which case
  /// nothing is dumped at all.
  member _.MarkError() = hasError <- true

  /// Writes the gathered bytes out, unless there was an error.
  member _.Dump() =
    match path with
    | Some path when hasError ->
      eprintsn $"Failed to assemble; nothing is written to {path}."
    | Some path ->
      IO.File.WriteAllBytes(path, buf.ToArray())
    | None ->
      ()

let inline private printResult (dumper: BinDumper) fn = function
  | Ok res ->
    fn res
  | Error err ->
    dumper.MarkError()
    eprintsn err

let getAssemblyPrinter (opts: AssemblerOpts) dumper =
  match opts.Mode with
  | GeneralMode(isa) ->
    let baseAddr = opts.BaseAddress
    let parsers = Dictionary()
    let asm = Assembler(isa, baseAddr)
    fun str ->
      asm.Lower str
      |> printResult dumper (fun res ->
        List.fold (printIns parsers) baseAddr res |> ignore
        res |> List.iter (snd >> (dumper: BinDumper).Add))
  | LowUIRMode(isa) ->
    let regFactory = ArchSupport.createRegisterFactory isa
    let parser = LowUIR.Parser(isa, regFactory, regFactory)
    fun str ->
      parser.Parse str
      |> printResult dumper (fun stmts ->
        stmts |> Array.iter (PrettyPrinter.ToString >> printsn))

let rec private asmFromStdin (console: FsReadLine.Console) printer str =
  match console.ReadLine() with
  | "" ->
    asmFromStdin console printer str
  | input when isNull input || input = "q" || input = "quit" ->
    printsn "Bye!"
  | input ->
    let input = input.Trim()
    let str =
      if input.EndsWith(";;") then
        console.UpdatePrompt NormalPrompt
        printer <| str + input.TrimEnd(';')
        ""
      else
        console.UpdatePrompt " "
        str + input + Environment.NewLine
    asmFromStdin console printer str

let showBasicInfo (opts: AssemblerOpts) =
  match opts.Mode with
  | GeneralMode(isa) ->
    ColoredString()
      .Append(Blue, isa.ToString())
      .Append(Green, " General Mode")
    |> printcn
  | LowUIRMode(isa) ->
    ColoredString()
      .Append(Blue, isa.ToString())
      .Append(Green, " LowUIR Mode")
    |> printcn

let private asmFromFiles files printer =
  files
  |> List.iter (IO.File.ReadAllText >> printer)

/// The path to dump the assembled bytes to, which only makes sense in general
/// mode as LowUIR mode produces no bytes at all.
let private outFileOf (opts: AssemblerOpts) =
  match opts.Mode, opts.OutFile with
  | LowUIRMode _, Some _ ->
    eprintsn "The output file option is ignored in LowUIR mode."
    None
  | _, path ->
    path

let asmMain files opts =
  let dumper = BinDumper(outFileOf opts)
  let printer = getAssemblyPrinter opts dumper
  if List.isEmpty files then
    let console = FsReadLine.Console(NormalPrompt, [ "quit" ])
    showBasicInfo opts
    asmFromStdin console printer ""
  else
    asmFromFiles files printer
  dumper.Dump()

[<EntryPoint>]
let main args =
  let opts = AssemblerOpts.Default
  CmdOpts.parseAndRun asmMain "assembler" "" AssemblerOpts.Spec opts args
