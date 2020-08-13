// ----------------------------------------------------------------------------
// B2R2 F# Sample.
// ----------------------------------------------------------------------------
// Currently we assume that you have published all the binaries into the
// `../../build` directory. To do so, you can simply run `make publish` in the
// source root directory.
// ----------------------------------------------------------------------------

#r "../../build/B2R2.Core.dll"
#r "../../build/B2R2.BinIR.dll"
#r "../../build/B2R2.BinFile.dll"
#r "../../build/B2R2.FrontEnd.Core.dll"
#r "../../build/B2R2.FrontEnd.Library.dll"

open B2R2
open B2R2.FrontEnd

let isa = ISA.OfString "amd64"
let bytes = [| 0x65uy; 0xffuy; 0x15uy; 0x10uy; 0x00uy; 0x00uy; 0x00uy |]
let handler = BinHandler.Init (isa, bytes)
let ins = BinHandler.ParseInstr handler handler.DefaultParsingContext 0UL
ins.Disasm () |> printfn "%s"
