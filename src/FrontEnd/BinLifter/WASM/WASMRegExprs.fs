namespace B2R2.FrontEnd.BinLifter.WASM

open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR

type internal RegExprs () =
  let var sz t name = AST.var sz t name (WASMRegisterSet.singleton t)

  member __.GetRegVar (name) =
    match name with
    | _ -> raise UnhandledRegExprException

// vim: set tw=80 sts=2 sw=2: