// Learn more about F# at http://fsharp.org

open System
open B2R2
open B2R2.Assembler.MIPS.Parser
open B2R2.Assembler.MIPS.SecondPass
open B2R2.Assembler.MIPS.MIPSParserRunner

[<EntryPoint>]
let main argv =
    printfn "Hello World from F#!"
    let arch = Arch.MIPS32
    let sampleISA =
      { Arch = arch; Endian = Endian.Big; WordSize = WordSize.Bit32 }
    let parser = Runner (sampleISA, 0UL)
    let test =
      "sltu a3, t5, a3
      someLabel:
      beq $4, r0, 0xE5B0
      addiu a1, a2, 0x1
      sw v0, 4(v1)
      c.lt.s f2, f4, f6
      jr someLabel"

    printfn "%A" (parser.Run test)

    0
