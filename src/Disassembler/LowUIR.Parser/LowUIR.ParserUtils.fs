module LowUIRParserUtils
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open FParsec

/// Used when parsing Undefined expression(not relevant).
let dummyRegType = 32<rt>
/// Used when parsing InterJmp statments(not relevant).
let dummyExpr = Undefined (dummyRegType, "dummy value")
/// Used when parsing InterJmp statements(not relevant).
let dummyInterJmpInfo = InterJmpInfo.Base

let typeCheckR st =
  if AST.typeCheck st then preturn st else fail "statment type check failed"

let pcFromRegName n = PCVar ((RegType.fromBitWidth 32), n)

let binOpFromString = function
  | "+" -> BinOpType.ADD
  |  "-" -> BinOpType.SUB
  | "*" -> BinOpType.MUL
  | "/" -> BinOpType.DIV
  | "?/" -> BinOpType.SDIV
  | "%" -> BinOpType.MOD
  | "?%" -> BinOpType. SMOD
  | "<<" -> BinOpType.SHL
  | ">>" -> BinOpType. SHR
  | "?>>" -> BinOpType. SAR
  | "&" -> BinOpType. AND
  | "|" -> BinOpType. OR
  | "^" -> BinOpType. XOR
  | "++" -> BinOpType.CONCAT
  | "-|" -> BinOpType.APP
  | "::" -> BinOpType.CONS
  | _ -> raise IllegalASTTypeException

let unOpFromString = function
  | "-" -> UnOpType.NEG
  | "~" -> UnOpType.NOT
  | _ -> raise IllegalASTTypeException

let relOpFromString = function
  | "=" -> RelOpType.EQ
  | "!=" -> RelOpType.NEQ
  | ">" -> RelOpType.GT
  | ">=" -> RelOpType.GE
  | "?>" -> RelOpType.SGT
  | "?>=" -> RelOpType.SGE
  | "<" -> RelOpType.LT
  | "<=" -> RelOpType.LE
  | "?<" -> RelOpType.SLT
  | "?<=" -> RelOpType.SLE
  | _ -> raise IllegalASTTypeException

let castTypeFromString = function
  | "sext" -> CastKind.SignExt
  | "zext" -> CastKind.ZeroExt
  | _ -> raise IllegalASTTypeException

let sideEffectFromString = function
  | _ -> ClockCounter
