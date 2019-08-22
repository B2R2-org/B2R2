module B2R2.Utilities.LowUIR.Repl.ReplUtils

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

let singleRegStatusString regExp evalState =
  getRegNameValTuple regExp evalState
  |> (fun (name, value) -> sprintf "%3s: %s" name (getEvalValueString value))

let regStatusString evalState (pHelper: IRVarParseHelper) =
  List.map (fun s -> singleRegStatusString s evalState) pHelper.MainRegs |>
  List.map (sprintf "%-20s") |>
  List.iteri (fun i str ->
    if i%3 = 2 then printfn "%s" str
    else printf "%s" str)

let ISATableStr =
  "0. Default(Intelx64)            | 1. x86, i386   | 2. x64, x86-64, amd64\n\
   3. armv7, armv7le, armel, armhf | 4. armv7be     | 5. armv8a32, aarch32\n\
   6. armv8a32be, aarch32be\n"

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

let printTReg tRegSeq =
  Seq.iter (fun rTuple -> printf " %s " (getTempRegrString rTuple)) tRegSeq

let printRegisters (state: EvalState) pHelper =
  let regs = EvalState.GetCurrentContext state
  let TRegMap = regs.Temporaries.ToSeq ()
  printfn "Main registers: " ;
  regStatusString state pHelper
  printf "\nTemporary Registers: " ; (printTReg TRegMap); printfn ""
