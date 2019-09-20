namespace B2R2.BinIR.LowUIR

open B2R2

[<AbstractClass>]
type RegParseHelper () =
  abstract member IdOf: Expr -> RegisterID
  abstract member RegNames: string list
  abstract member StrToReg: string -> Expr
  abstract member InitStateRegs: (RegisterID * BitVector) list
  abstract member MainRegs: Expr list
