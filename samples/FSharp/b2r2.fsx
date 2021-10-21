// ----------------------------------------------------------------------------
// B2R2 F# Sample.
// ----------------------------------------------------------------------------

#r "nuget: B2R2.FrontEnd.BinInterface, 0.5.0-rc3"

open B2R2
open B2R2.FrontEnd

let isa = ISA.OfString "amd64"
let bytes = [| 0x65uy; 0xffuy; 0x15uy; 0x10uy; 0x00uy; 0x00uy; 0x00uy |]
let handler = BinHandler.Init (isa, bytes)
let ins = BinHandler.ParseInstr handler handler.DefaultParsingContext 0UL
ins.Disasm () |> printfn "%s"
