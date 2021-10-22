// ----------------------------------------------------------------------------
// B2R2 F# Sample.
// ----------------------------------------------------------------------------

#r "nuget: B2R2.FrontEnd.BinInterface"

open B2R2
open B2R2.FrontEnd.BinInterface

let isa = ISA.OfString "amd64"
let bytes = [| 0x65uy; 0xffuy; 0x15uy; 0x10uy; 0x00uy; 0x00uy; 0x00uy |]
let handler = BinHandle.Init (isa, bytes)
let ins = BinHandle.ParseInstr (handler, 0UL)
ins.Disasm () |> printfn "%s"
