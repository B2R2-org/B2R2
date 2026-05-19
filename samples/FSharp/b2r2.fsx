// ----------------------------------------------------------------------------
// B2R2 F# Sample.
// ----------------------------------------------------------------------------

#r "nuget: B2R2.FrontEnd.API"

open B2R2
open B2R2.FrontEnd

let isa = ISA "amd64"
let bytes = [| 0x65uy; 0xffuy; 0x15uy; 0x10uy; 0x00uy; 0x00uy; 0x00uy |]
let hdl = BinHandle(bytes, isa)
let lifter = hdl.NewLiftingUnit()
let ins = lifter.ParseInstruction 0UL
lifter.DisasmInstruction ins |> printfn "%s"
