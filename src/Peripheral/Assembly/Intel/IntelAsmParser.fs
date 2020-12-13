(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*)

namespace B2R2.Peripheral.Assembly.Intel

open B2R2
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.Peripheral.Assembly
open B2R2.Peripheral.Assembly.Intel.ParserHelper
open B2R2.Peripheral.Assembly.Intel.AsmMain
open FParsec
open System

/// Label name to relative index of instructions.
type LabelDefs = Map<string, int>

type IntelAsmParser (isa, baseAddr: Addr) =
  inherit AsmParser ()

  let mutable inferredPrefix = Prefix.PrxNone
  let defaultRegType = isa.WordSize |> WordSize.toRegType

  let addLabeldef lbl =
    updateUserState (fun us ->
      { us with LabelMap = Map.add lbl us.CurIndex us.LabelMap })
    >>. preturn ()

  let incrementIndex =
    updateUserState (fun us -> { us with CurIndex = us.CurIndex + 1 })
    >>. preturn ()

  let resetPrefix =
    preturn () |>> (fun _ -> inferredPrefix <- Prefix.PrxNone)

  let isWhitespace c = [ ' '; '\t'; '\f' ] |> List.contains c

  let whitespace = manySatisfy isWhitespace

  let whitespace1 = many1Satisfy isWhitespace

  let skipWhitespaces s = whitespace >>? s .>>? whitespace

  let terminator = (pchar ';' <|> newline) |> skipWhitespaces <?> ""

  let operandSeps = (pchar ',' >>. whitespace) <|> whitespace1

  let betweenSquareBraces s =
    s |> skipWhitespaces |> between (pchar '[') (pchar ']')

  let alphanumericWithUnderscore s = Char.IsLetterOrDigit s || s = '_'

  let pId = many1Satisfy alphanumericWithUnderscore

  let pLabelDef = pId .>>? pchar ':' >>= addLabeldef <?> "label"

  /// If the value satisfies the condition then check succeeds.
  let check p condition =
    if condition p then preturn () else fail "conditioner checker failed"

  let pOpcode =
    (Enum.GetNames typeof<Opcode>)
    |> Array.map pstringCI
    |> Array.map (fun p -> p .>> (lookAhead (anyOf "\n;. " |>> ignore) <|> eof))
    |> Array.map attempt
    |> Array.map
      (fun (p) ->
        p
        |>> (fun name -> Enum.Parse(typeof<Opcode>, name.ToUpper()) :?> Opcode))
    |> choice
    (* Since far calls, jmps, and rets are unnatural they are ignored *)
    <|> (pstringCI "jmp" >>. preturn Opcode.JMPNear)
    <|> (pstringCI "call" >>. preturn Opcode.CALLNear)
    <|> (pstringCI "ret" >>. preturn Opcode.RETNearImm)
    <?> "opcode"

  let numberFormat =
    NumberLiteralOptions.AllowBinary
    ||| NumberLiteralOptions.AllowOctal
    ||| NumberLiteralOptions.AllowHexadecimal
    ||| NumberLiteralOptions.AllowMinusSign
    ||| NumberLiteralOptions.AllowPlusSign

  let pImm =
    numberLiteral numberFormat "number"
    |>> (fun x ->
          if x.HasPlusSign then int64 x.String.[1 ..] else int64 x.String)

  let pAddr = pImm |>> uint64

  let registersList =
    (Enum.GetNames typeof<Register>)
    |> Array.map pstringCI
    |> Array.map (fun p -> p .>> (notFollowedBy (satisfy isLetter)) )
    |> Array.map attempt

  let pReg =
    registersList |> choice
    |>> (fun regName ->
          Enum.Parse (typeof<Register>, regName.ToUpper())
          :?> Register)

  let pPrefix =
    pstring "lock" |>> (fun _ -> inferredPrefix <- Prefix.PrxLOCK)
    <|> (attempt (pstring "repz") |>> fun _ -> inferredPrefix <- Prefix.PrxREPZ)
    <|> (pstring "repnz" |>> fun _ -> inferredPrefix <- Prefix.PrxREPNZ)
    >>. preturn ()
    <?> "prefix"

  let pScale =
    opt (pchar '*') >>. spaces >>.
    ((pchar '2' |>> (fun _ -> Scale.X2))
    <|> (pchar '4' |>> (fun _ -> Scale.X4))
    <|> (pchar '8' |>> (fun _ -> Scale.X8))
    <|> preturn Scale.X1 )

  let pSegmentRegPrefix =
    [ "cs"; "ds"; "es"; "fs"; "gs"; "ss" ]
    |> Seq.map pstringCI
    |> choice
    |>> prefixFromRegString

  let updatePrefix =
    pSegmentRegPrefix .>> spaces .>> pchar ':'
    |>> (fun pre -> inferredPrefix <- (inferredPrefix ||| pre))

  let pMemOprSize =
    [ "byte ptr"; "word ptr"; "word far ptr"; "dword ptr"; "dword far ptr";
    "qword ptr"; "qword far ptr"; "tword ptr"; "xmmword ptr"; "ymmword ptr";
    "zmmword ptr" ]
    |> Seq.map pstringCI
    |> Seq.map attempt
    |> choice
    |>> ptrStringToBitSize

  let pMemBaseReg =
    pReg .>> (notFollowedBy (spaces .>> pchar '*'))

  let pScaledIndexReg =
    opt (pchar '+') >>. pReg .>> spaces .>>. pScale
    |>> (fun (reg, scale) -> ScaledIndex (reg, scale))
  let pDisp = pImm

  let pMemOpr sz =
    let sz = Option.defaultValue defaultRegType sz
    opt (attempt updatePrefix) >>. spaces >>. opt (attempt pMemBaseReg)
    .>> spaces .>>. opt (attempt pScaledIndexReg) .>> spaces .>>. opt pDisp
    |>> fun ((bReg, scaledInd), disp) -> OprMem (bReg, scaledInd, disp, sz)
    |> betweenSquareBraces

  let pAbsoluteAddress =
    pImm |>> int16 .>> spaces .>> pchar ';' .>> spaces .>>. pAddr
    |>> (fun (sel, addr) -> Absolute (sel, addr, dummyRegType))

  let pJumpTarget = attempt pAbsoluteAddress <|> (pImm |>> Relative)

  let pOprReg = pReg |>> OprReg

  let pOprMem = opt (pMemOprSize .>> spaces) >>= pMemOpr

  let pOprDirAddr opc =
    check opc Helper.isBranch >>. pJumpTarget |>> OprDirAddr

  let pOprImm = pImm |>> OprImm

  let pSizedLabel sz =
    let sz = Option.defaultValue defaultRegType sz
    pId |>> fun lbl -> Label (lbl, sz)

  let pLabel = opt (pMemOprSize .>> spaces) >>= pSizedLabel

  let operand opc =
    pOprDirAddr opc
    <|> attempt pOprReg
    <|> pOprImm
    <|> attempt pOprMem
    <|> pLabel

  let operands opc =
    sepBy (operand opc) operandSeps |>> extractOperands
    |>> (fun operands ->
          match opc, operands with
          | Opcode.RETNearImm, NoOperand -> Opcode.RETNear, operands
          | _ -> opc, operands )
    |> skipWhitespaces

  let pInsInfo =
    opt pPrefix >>. spaces >>. (pOpcode >>= operands)
    |>> (fun (opcode, operands) ->
          newInfo inferredPrefix REXPrefix.NOREX None
            opcode operands dummyInsSize)

  let pInstructionLine =
    incrementIndex >>. opt pLabelDef >>. spaces >>. pInsInfo .>> resetPrefix
    |>> InstructionLine

  let statement =
    attempt pInstructionLine
    <|> ((pLabelDef |>> fun _ -> LabelDefLine) <?> "")
    <|> preturn LabelDefLine

  let statements = sepEndBy statement terminator .>> (eof <?> "")

  override __.Assemble assembly =
    let st = { LabelMap = Map.empty; CurIndex = -1 }
    match runParserOnString statements st "" assembly with
    | Success (result, us, _) ->
      filterInstructionLines result |> assemble us isa baseAddr |> Result.Ok
    | Failure (str, _, _) ->
      Result.Error (str)
