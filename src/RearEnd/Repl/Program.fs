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

module B2R2.RearEnd.Repl.Program

open System.Collections.Generic
open B2R2
open B2R2.BinIR
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.Assembly
open B2R2.RearEnd.Utils

let cmds = [ "show"; "switch-parser"; "exit" ]

let console = FsReadLine.Console("B2R2> ", cmds)

/// The parser of the given ISA, made once and kept, since a single source may
/// need more than one: an ARM32 source that switches instruction sets needs
/// both of theirs.
let parserFor (parsers: Dictionary<_, _>) (isa: ISA) =
  match parsers.TryGetValue(isa.ToString()) with
  | true, parser -> parser
  | false, _ ->
    let parser = ArchSupport.createParser (BinReader.Init isa.Endian) isa
    parsers[isa.ToString()] <- parser
    parser

let lift (asm: Assembler) builder parsers addr input =
  asm.Lower input
  |> Result.bind (fun bins ->
    bins
    |> List.fold (fun acc (isa, bs) ->
      let ins = (parserFor parsers isa).Parse(bs, addr)
      ins.Translate builder :: acc
    ) []
    |> List.rev
    |> Array.concat
    |> Ok)

let assemble state asm builder parsers uirParser (input: string) =
  match (state: ReplState).CurrentParser with
  | LowUIRParser ->
    try (uirParser: LowUIR.Parser).Parse(input.Trim())
    with exc -> Error exc.Message
  | _ ->
    try lift asm builder parsers asm.StartAddress (input.Trim())
    with exc -> Error exc.Message

let rec run showTemporary state asm builder parsers uirParser =
  let input = console.ReadLine()
  match ReplCommand.fromString input with
  | Quit -> ()
  | NoInput -> run showTemporary state asm builder parsers uirParser
  | SwitchParser ->
    (state: ReplState).SwitchParser()
    state.ConsolePrompt |> console.UpdatePrompt
    run showTemporary state asm builder parsers uirParser
  | Show ->
    Display.printRegisters showTemporary state []
    run showTemporary state asm builder parsers uirParser
  | StmtInput input ->
    match assemble state asm builder parsers uirParser input with
    | Error msg ->
      printfn "%s" msg
      run showTemporary state asm builder parsers uirParser
    | Ok stmts ->
      let regdelta = state.Update stmts
      Display.printRegisters showTemporary state regdelta
      run showTemporary state asm builder parsers uirParser

let runRepl _args (opts: ReplOpts) =
  let hdl = BinHandle.LoadEmpty opts.ISA
  let state = ReplState(opts.ISA, hdl.RegisterFactory, not opts.Verbose)
  let asm = Assembler(opts.ISA, 0UL)
  let builder = ArchSupport.createBuilder opts.ISA hdl.RegisterFactory
  let parsers = Dictionary()
  let regFactory = hdl.RegisterFactory
  let uirParser = LowUIR.Parser(opts.ISA, regFactory, regFactory)
  Display.printBlue "Welcome to B2R2 REPL\n"
  state.ConsolePrompt |> console.UpdatePrompt
  run opts.ShowTemp state asm builder parsers uirParser

[<EntryPoint>]
let main args =
  let opts = ReplOpts.Default
  CmdOpts.parseAndRun runRepl "repl" "" ReplOpts.Spec opts args
