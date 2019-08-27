module B2R2.Utilities.LowUIR.Repl.ReplUtils
open System
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.ConcEval
open B2R2.FrontEnd
open IRParseHelper

type ReplCommand =
  | IRStatement of string
  | Quit
  | Undo
  | NoInput

module ReplCommand =
  let fromInput (str: string) =
    match str with
    | "" -> NoInput
    | "quit" | "exit" | "stop" -> Quit
    | "undo" -> Undo
    | str -> IRStatement str

type History (regSeq, tempRegSeq) =

  let mutable prevContexts = [(regSeq, tempRegSeq)]

  let mutable index = 0

  member __.RegSeq = fst prevContexts.[index]

  member __.TempRegSeq = snd prevContexts.[index]

  member __.Undo =
    if prevContexts.Length > index + 1 then index <- index + 1 else ()

  member __.Redo =
    if index > 0 then index <- index - 1 else ()

  member __.UpdateHistory (state: EvalState) =
    let stateContext = EvalState.GetCurrentContext state
    let newContext =
      (stateContext.Registers.ToSeq () |> Seq.toArray |> Array.copy,
       stateContext.Temporaries.ToSeq () |> Seq.toArray |> Array.copy)
    prevContexts <- newContext:: prevContexts.[index ..]
    index <- 0

  member __.GetUpdatedRegIndices state =
    Seq.fold2
      (fun acc t1 t2 ->
        if t1 <> t2 then fst t1 :: acc else acc)
      []
      ((EvalState.GetCurrentContext state).Registers.ToSeq ()) __.RegSeq

  member __.GetUpdatedTempRegs state =
    Seq.fold2
      (fun acc t1 t2 ->
        if t1 <> t2 then fst t1 :: acc else acc)
      []
      ((EvalState.GetCurrentContext state).Temporaries.ToSeq ()) __.TempRegSeq


let private getEvalValueString = function
  | Def bv -> bv.ToString ()
  | Undef -> "undef"

let private getRegValue st e =
  match e with
  | Var (_, n, _, _) -> EvalState.GetReg st n
  | PCVar (t, _) -> BitVector.ofUInt64 st.PC t |> Def
  | _ -> raise InvalidExprException

let getRegNameValTuple regExpr evalState =
  let regName =
    match regExpr with
    | Var (_typ, _, n, _) -> n
    | PCVar (_typ, n) -> n
    | x -> sprintf "%A" x
  regName, getRegValue evalState regExpr

let numToArchitecture = function
  | "1" -> Some (ISA.Init (Arch.IntelX86) Endian.Little)
  | "" | "0" | "2" -> Some (ISA.DefaultISA)
  | "3" -> Some (ISA.Init (Arch.ARMv7) Endian.Little)
  | "4" -> Some (ISA.Init (Arch.ARMv7) Endian.Big)
  | "5" -> Some (ISA.Init (Arch.AARCH32) Endian.Little)
  | "6" -> Some (ISA.Init (Arch.AARCH32) Endian.Big)
  |  _  -> None


let initStateForReplStart handle (pHelper: IRVarParseHelper) =
  let st = EvalState (B2R2.BinGraph.DisasHeuristic.imageLoader handle, true)
  EvalState.PrepareContext st 0 0UL
    (pHelper.InitStateRegs |> List.map (fun (x, y) -> (x, Def y)))

let getRegValueString (rid: RegisterID, value: EvalValue) =
  let reg = Intel.Register.ofRegID rid
  let valueStr =
    match value with
    | Def bv -> BitVector.valToString bv
    | Undef -> "undef"
  sprintf "%s: %s" (reg.ToString ()) valueStr

let getTempRegrString (n: int, value: EvalValue) =
  let tRegName = "T_" + string (n)
  let valueStr =
    match value with
    | Def bv -> BitVector.valToString bv
    | Undef -> "undef"
  sprintf "%s: %s" tRegName valueStr



module ReplDisplay =

  let ISATableStr =

    "========================================================================\n\
     ** Choose an architecture number or press Enter for the default Arch **\n\
     ========================================================================\n\
     0. Default(Intelx64)            | 1. x86, i386   | 2. x64, x86-64, amd64\n\
     3. armv7, armv7le, armel, armhf | 4. armv7be     | 5. armv8a32, aarch32\n\
     6. armv8a32be, aarch32be\n"

  let cprintf c fmt =
    Printf.kprintf
        (fun s ->
            let old = System.Console.ForegroundColor
            try
              System.Console.ForegroundColor <- c;
              System.Console.Write s
            finally
              System.Console.ForegroundColor <- old)
        fmt

  let printRed str = cprintf ConsoleColor.Red str
  let printBlue str = cprintf ConsoleColor.Blue str
  let printCyan str = cprintf ConsoleColor.Cyan str

  let singleRegStatusString regExp evalState =
    getRegNameValTuple regExp evalState
    |> (fun (name, value) -> sprintf "%3s: %s" name (getEvalValueString value))

  let printRegStatusString state (pHelper: IRVarParseHelper) (hist:History) =
    let changedIds = hist.GetUpdatedRegIndices state
    let idList = List.map pHelper.IdOf pHelper.MainRegs
    List.map
      (fun s ->
        singleRegStatusString s state |> sprintf "%-20s")
      pHelper.MainRegs |>
    List.iteri (fun i str ->
      if i%3 = 2 && List.contains (idList.[i]) changedIds then
        printRed "%s\n" str
      elif i%3 = 2 then printfn "%s" str
      elif List.contains (idList.[i]) changedIds then printRed "%s" str
      else printf "%s" str)

  let printTRegStatusString state (hist: History) =
    let tRegSeq = (EvalState.GetCurrentContext state).Temporaries.ToSeq ()
    let changedTempRegs = hist.GetUpdatedTempRegs state
    Seq.iteri
      (fun i rTuple ->
        if i = hist.TempRegSeq.Length then
          printRed " %s " (getTempRegrString rTuple)
        elif List.contains (fst rTuple) changedTempRegs then
          printRed " %s " (getTempRegrString rTuple)
        else printf " %s " (getTempRegrString rTuple)
       ) tRegSeq
    printfn ""

  let printRegisters (state: EvalState) pHelper hist =
    printCyan "Main registers: \n" ;
    printRegStatusString state pHelper hist
    printCyan "\nTemporary Registers:" ;
    printTRegStatusString state hist



