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

open B2R2
open B2R2.FrontEnd
open B2R2.Peripheral.Assembly

let cmds = [ "show"; "switch-parser"; "exit" ]

let console = FsReadLine.Console("B2R2> ", cmds)

let assemble (state: ReplState) (asm: AsmInterface) (input: string) =
  let isLowUIRParser =
    match state.CurrentParser with
    | LowUIRParser -> true
    | _ -> false
  try asm.LiftLowUIR isLowUIRParser (input.Trim())
  with exc -> Error exc.Message

let rec run showTemporary (state: ReplState) asm =
  let input = console.ReadLine()
  match ReplCommand.fromString input with
  | Quit -> ()
  | NoInput -> run showTemporary state asm
  | SwitchParser ->
    state.SwitchParser()
    state.ConsolePrompt |> console.UpdatePrompt
    run showTemporary state asm
  | Show ->
    Display.printRegisters showTemporary state []
    run showTemporary state asm
  | StmtInput input ->
    match assemble state asm input with
    | Error msg ->
      printfn "%s" msg
      run showTemporary state asm
    | Ok stmts ->
      let regdelta = state.Update stmts
      Display.printRegisters showTemporary state regdelta
      run showTemporary state asm

let runRepl _args (opts: ReplOpts) =
  let binhandler = BinHandle("", opts.ISA)
  let state = ReplState(opts.ISA, binhandler.RegisterFactory, not opts.Verbose)
  let asm = AsmInterface(opts.ISA, 0UL)
  Display.printBlue "Welcome to B2R2 REPL\n"
  state.ConsolePrompt |> console.UpdatePrompt
  run opts.ShowTemp state asm

[<EntryPoint>]
let main args =
  let opts = ReplOpts()
  ReplOpts.ParseAndRun(runRepl, "repl", "", ReplOpts.spec, opts, args)
