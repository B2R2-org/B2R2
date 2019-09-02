namespace B2R2.Assembler.Tests


open Microsoft.VisualStudio.TestTools.UnitTesting
open System
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd

[<TestClass>]
type LowUIRTests () =
  let pHelper = Intel.ParseHelper WordSize.Bit64 :> RegParseHelper
  let p = LowUIRParser (ISA.DefaultISA, pHelper)

  [<TestMethod>]
  member __.``[Assembler] Parse Test (Intel64 lowUIR)`` () =
    // Test register parse
    let result = p.Run "EAX := 0x3423:I32"
    printf "%A\n" result
    // Test imm parse
    let result = p.Run "=== IEMark (pc := 401245)"
    printf "%A\n" result
    // Test addr parse
    let result = p.Run "PF := (~ ((((T_169:I32 ^ (T_169:I32 >> 0x4:I32)) ^ \
    (T_170:I32 >> 0x2:I32)) ^ (T_171:I32 >> 0x1:I32))[0:0]))"
    printf "%A\n" result
    // Test label parse
    let result = p.Run "ESP := (ESP - 0x4:I32)"
    printf "%A\n" result
