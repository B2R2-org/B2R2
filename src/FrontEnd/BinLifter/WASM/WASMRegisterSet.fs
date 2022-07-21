namespace B2R2.FrontEnd.BinLifter.WASM

open B2R2

module private RegisterSetLiteral =
  let [<Literal>] ArrLen = 2

open RegisterSetLiteral

type WASMRegisterSet (bitArray: uint64 [], s: Set<RegisterID>) =
  inherit NonEmptyRegisterSet (bitArray, s)

  new () = WASMRegisterSet (RegisterSet.MakeInternalBitArray ArrLen, Set.empty)

  override __.Tag = RegisterSetTag.WASM

  override __.ArrSize = ArrLen

  override __.New arr s = new WASMRegisterSet (arr, s) :> RegisterSet

  override __.RegIDToIndex rid =
    match Register.ofRegID rid with
    | _ -> Utils.futureFeature ()

  override __.IndexToRegID index =
    match index with
    | _ -> Utils.impossible ()

  override __.ToString () =
    sprintf "WASMReisterSet<%x, %x>" __.BitArray.[0] __.BitArray.[1]

[<RequireQualifiedAccess>]
module WASMRegisterSet =
  let singleton rid = WASMRegisterSet().Add(rid)
  let empty = WASMRegisterSet () :> RegisterSet

// vim: set tw=80 sts=2 sw=2: