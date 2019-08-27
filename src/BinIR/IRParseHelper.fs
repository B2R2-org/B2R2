module B2R2.BinIR.LowUIR.IRParseHelper

open B2R2
open B2R2.BinIR.LowUIR



[<AbstractClass>]
type IRVarParseHelper () =
  abstract member IdOf: Expr -> RegisterID
  abstract member RegNames: string list
  abstract member StrToVar: string -> Expr
  abstract member InitStateRegs: (RegisterID * BitVector) list
  abstract member MainRegs: Expr list
