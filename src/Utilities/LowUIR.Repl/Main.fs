// Learn more about F# at http://fsharp.org

open System
open B2R2
open B2R2.LowUIR
open B2R2.ConcEval
open B2R2.FrontEnd
open B2R2.Utilities.LowUIR.Repl.ReplUtils
open B2R2.BinIR.LowUIR.IRParseHelper


let showError str =
  printfn "[Invalid] %s" str

let rec getISAChoice () =
  printfn "Choose an architecture or press Enter for Default Architecture."
  printf "%s" ISATableStr
  let input = Console.ReadLine ()
  let arch = numToArchitecture input
  if arch = None then getISAChoice () else arch.Value

let rec Repl (pars: Parser.LowUIRParser) (state: EvalState) pHelper =
  printf "-> "
  let input = Console.ReadLine ()
  match ReplCommand.fromInput input with
  | Quit -> ()
  | NoInput -> printRegisters state pHelper; Repl pars state pHelper
  // FIXME
  | Undo -> Repl pars state pHelper
  | IRStatement input ->
    let parsed =
      try pars.Run input with
      | :? System.OverflowException -> showError "number too large"; None
      | exc -> printfn "%A" exc; None
    if parsed = None then  Repl pars state pHelper
    else
      let state = Evaluator.evalStmt state parsed.Value
      printRegisters state pHelper
      Repl pars state pHelper

[<EntryPoint>]
let main argv =
  let isa = getISAChoice ()
  // FIXME
  let pHelper : IRVarParseHelper =
    if isa.Arch = Architecture.ARMv7 then
      ARM32.ARM32ASM.ParseHelper () :> IRVarParseHelper
    else Intel.IntelASM.ParseHelper isa.WordSize :> IRVarParseHelper

  let state = initStateForReplStart (BinHandler.Init isa) pHelper

  let pars = Parser.LowUIRParser (isa, pHelper)
  printfn "..........Repl for %s LowUIR running........." (isa.Arch.ToString ())
  printfn ""

  Repl pars state pHelper

  0 // return an integer exit code
