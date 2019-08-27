open  B2R2.LowUIR.Parser
open System
open B2R2
open B2R2.BinIR.LowUIR.IRParseHelper
open B2R2.FrontEnd

module Program =

  [<EntryPoint>]
  let main _ =
    printfn "........LowUIRParser running......"
    let pHelper = Intel.IntelASM.ParseHelper WordSize.Bit64 :> IRVarParseHelper
    let p = LowUIRParser (ISA.DefaultISA, pHelper)
    while true do
      let test = Console.ReadLine ()
      let result =
        if test.Length = 0 then "->"
        else "->" + string (p.Run test)
      printfn "%s" result
    0
