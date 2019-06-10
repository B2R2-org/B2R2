namespace B2R2.BinAnalysis

open System
open B2R2.BinIR.LowUIR

type IAbstractInterpreter<'astate> =
  abstract AbstractLFP : Func<'astate, 'astate> -> 'astate -> 'astate -> 'astate
  abstract InterpStmt : 'astate -> Stmt -> 'astate
  abstract InterpProg : Stmt [] list -> 'astate
