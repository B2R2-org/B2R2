open  B2R2.LowUIR.Parser
open System
open B2R2
module Program =

  [<EntryPoint>]
  let main _ =
    printfn "........LowUIRParser running......"
    let p = LowUIRParser (ISA.DefaultISA)
    while true do
      let test = Console.ReadLine ()
      let result =
        if test.Length = 0 then "->"
        else "->" + string (p.Run test)
      printfn "%s" result


    0
