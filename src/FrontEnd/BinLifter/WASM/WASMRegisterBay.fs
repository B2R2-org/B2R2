namespace B2R2.FrontEnd.BinLifter.WASM

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR

type WASMRegisterBay () =
  inherit RegisterBay ()

  override __.GetAllRegExprs () = Utils.futureFeature ()

  override __.GetAllRegNames () = []

  override __.GetGeneralRegExprs () = Utils.futureFeature ()

  override __.RegIDFromRegExpr (e) =
    match e.E with
    | _ -> failwith "not a register expression"

  override __.RegIDToRegExpr (id) = Utils.impossible ()

  override __.StrToRegExpr _s = Utils.impossible ()

  override __.RegIDFromString str =
    Register.ofString str |> Register.toRegID

  override __.RegIDToString rid =
    Register.ofRegID rid |> Register.toString

  override __.RegIDToRegType rid =
    Register.ofRegID rid |> Register.toRegType

  override __.GetRegisterAliases _ = Utils.futureFeature ()

  override __.ProgramCounter = Utils.impossible()

  override __.StackPointer = Utils.futureFeature ()

  override __.FramePointer = Utils.impossible ()

  override __.IsProgramCounter regid = Utils.futureFeature ()

  override __.IsStackPointer regid = Utils.futureFeature ()

  override __.IsFramePointer _ = Utils.impossible ()

// vim: set tw=80 sts=2 sw=2: