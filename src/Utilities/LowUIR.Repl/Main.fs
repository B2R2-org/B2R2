(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Michael Tegegn <mick@kaist.ac.kr>
          Sang Kil Cha <sangkilc@kaist.ac.kr>

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

module B2R2.Utilities.LowUIRRepl.Repl

open System
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.ConcEval
open B2R2.FrontEnd
open B2R2.Utilities.LowUIRRepl.Utils
open B2R2.Utilities.LowUIRRepl.Utils.ReplDisplay

let console = FsReadLine.Console ("-> ", [])

/// Displays the error message.
let showError str =
  printfn "[Invalid] %s" str

/// Gets ISA choice from the user.
let rec getISAChoice () =
  printf "%s" ISATableStr
  let input = console.ReadLine ()
  let arch = numToArchitecture input
  if arch = None then getISAChoice () else arch.Value

/// Main repl that excecutes the instructions and provides user interface.
type Repl (pars: LowUIRParser, regfactory, status:Status) =
  member __.Run state =
    let input = console.ReadLine ()
    match ReplCommand.fromInput input with
    | Quit -> ()
    | NoInput -> __.Run  state
    | Show -> printRegisters state regfactory status; __.Run state
    | IRStatement input ->
      let parsed =
        try pars.Run (input.Trim ()) with
        | :? OverflowException -> showError "number too large"; None
        | :? InvalidRegTypeException ->
          showError "invalid register type"; None
        | exc -> showError exc.Message; None

      if parsed = None then __.Run state
      else
        try Evaluator.evalStmt state parsed.Value |> ignore; () with
        | :? InvalidMemException -> showError "memory address can not be read"
        | :? InvalidCastException -> showError "cast statement invalid"
        | :? InvalidOperationException -> showError "operation is invalid"
        | exc -> showError exc.Message
        printRegisters state regfactory status
        status.UpdateStatus state
        __.Run state

[<EntryPoint>]
let main argv =
  let isa = getISAChoice ()

  (* Parser helper is used by both the parser and the repl. *)
  let regfactory: RegisterFactory =
    match isa.Arch with
    | Arch.IntelX86
    | Arch.IntelX64 ->
      Intel.RegFactory isa.WordSize :> RegisterFactory
    | Arch.ARMv7
    | Arch.AARCH32 -> ARM32.RegFactory () :> RegisterFactory
    | Arch.AARCH64 -> ARM64.RegFactory () :> RegisterFactory
    | Arch.MIPS1
    | Arch.MIPS2
    | Arch.MIPS3
    | Arch.MIPS4
    | Arch.MIPS5
    | Arch.MIPS32
    | Arch.MIPS32R2
    | Arch.MIPS32R6
    | Arch.MIPS64
    | Arch.MIPS64R2
    | Arch.MIPS64R6 -> MIPS.RegFactory isa.WordSize :> RegisterFactory
    | _ -> raise InvalidISAException

  let state = initStateForReplStart regfactory

  let pars = LowUIRParser (isa, regfactory)
  isa.Arch.ToString () |>
  printBlue
    " ****************** %s B2R2 LowUIR Repl running  **********************\n"
  let context = EvalState.GetCurrentContext state
  let hist =
    Status (Array.copy (Seq.toArray (context.Registers.ToSeq ())), Array.empty)

  let Evaluator = Repl (pars, regfactory, hist)
  Evaluator.Run state

  0 // return an integer exit code
