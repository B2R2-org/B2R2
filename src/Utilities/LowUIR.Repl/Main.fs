// Learn more about F# at http://fsharp.org

open System
open B2R2
open B2R2.LowUIR
open B2R2.ConcEval
open B2R2.FrontEnd
open B2R2.Utilities.LowUIR.Repl.ReplUtils
open B2R2.BinIR.LowUIR.IRParseHelper
open ReplDisplay


let showError str =
  printfn "[Invalid] %s" str

let rec getISAChoice () =
  printf "%s" ISATableStr
  let input = Console.ReadLine ()
  let arch = numToArchitecture input
  if arch = None then getISAChoice () else arch.Value

type Repl (pars: Parser.LowUIRParser, PHelper, Hist:History) =
  member __.Run state =
    printf "-> "
    let input = Console.ReadLine ()
    match ReplCommand.fromInput input with
    | Quit -> ()
    | NoInput -> printRegisters state PHelper Hist; __.Run  state
    // FIXME
    | Undo -> Hist.Undo; __.Run state
    | IRStatement input ->
      let parsed =
        try pars.Run input with
        | :? System.OverflowException -> showError "number too large"; None
        | exc -> printfn "%A" exc; None
      if parsed = None then __.Run state
      else
        Evaluator.evalStmt state parsed.Value |> ignore
        printRegisters state PHelper Hist
        Hist.UpdateHistory state
        __.Run state

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
  printBlue "**************  %s B2R2 LowUIR Repl running  *******************\n"
    (isa.Arch.ToString ())
  let context = EvalState.GetCurrentContext state
  let Hist =
    History (Array.copy (Seq.toArray (context.Registers.ToSeq ())), Array.empty)


  let Evaluator = Repl (pars, pHelper, Hist)
  Evaluator.Run state

  0 // return an integer exit code
