(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Michael Tegegn <mick@kaist.ac.kr>
          Mehdi Aghakishiyev <agakisiyev.mehdi@gmail.com>

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

namespace B2R2.Assembler.Intel

open B2R2
open B2R2.FrontEnd.Intel
open B2R2.Assembler.Intel.ParserHelper
open FParsec
open System

type LabelDefs = Map<string, Addr>

type AsmParser (startAddress: Addr) =

  (* TODO: No meaningful address manipulation is implemented. *)
  let mutable address = startAddress
  let mutable inferredPrefix = Prefix.PrxNone

  (* Helper functions for updating the UserState. *)
  let addLabeldef lbl =
    updateUserState ( fun (us: Map<string, Addr>) -> us.Add (lbl, address))
    >>. preturn ()

  let incrementAddress insSize =
    preturn () |>> (fun _ -> address <- address + insSize)

  let resetPrefix =
    preturn () |>> (fun _ -> inferredPrefix <- Prefix.PrxNone)

  let isWhitespace c = [ ' '; '\t'; '\f' ] |> List.contains c

  let whitespace = manySatisfy isWhitespace

  let whitespace1 = many1Satisfy isWhitespace

  let skipWhitespaces s = whitespace >>? s .>>? whitespace

  let terminator = (pchar ';' <|> newline) |> skipWhitespaces

  let operandSeps = (pchar ',' >>. whitespace) <|> whitespace1

  let betweenSquareBraces s =
    s |> skipWhitespaces |> between (pchar '[') (pchar ']')

  let alphanumericWithUnderscore s = Char.IsLetterOrDigit s || s = '_'

  let pId = many1Satisfy alphanumericWithUnderscore

  let pLabelDef = pId .>>? pchar ':' >>= addLabeldef

  /// If the value satisfies the condition then check succeeds.
  let check p condition =
    if condition p then preturn () else fail "conditioner checker failed"

  let pOpcode =
    (Enum.GetNames typeof<Opcode>)
    |> Array.map pstringCI
    |> Array.map
      (fun p -> p .>> (lookAhead (pchar '.') <|> lookAhead (pchar ' ')))
    |> Array.map attempt
    |> Array.map
      (fun (p) ->
        p |>>
          (fun name -> Enum.Parse(typeof<Opcode>, name.ToUpper()) :?> Opcode))
    |> choice
    <|> (pstringCI "jmp" >>. preturn Opcode.JMPFar)
    <|> (pstringCI "call" >>. preturn Opcode.CALLFar)

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
    pstring "lock" |>> (fun _ ->  inferredPrefix <- Prefix.PrxLOCK)
    <|> (attempt (pstring "repz") |>> fun _ ->  inferredPrefix <-Prefix.PrxREPZ)
    <|> (pstring "repnz" |>> fun _ ->  inferredPrefix <- Prefix.PrxREPNZ)
    >>. preturn ()

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
    |>> (fun pre -> inferredPrefix <- pre)

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
    opt (attempt updatePrefix) >>. spaces >>. opt (attempt pMemBaseReg)
    .>> spaces .>>. opt (attempt pScaledIndexReg) .>> spaces .>>. opt pDisp
    |>> fun ((bReg, scaledInd), disp) -> OprMem(bReg, scaledInd, disp, sz)
    |>betweenSquareBraces

  let pAbsoluteAddress =
    pImm |>> int16 .>> spaces .>> pchar ';' .>> spaces .>>. pAddr
    |>> (fun (sel, addr) -> Absolute (sel, addr, dummyRegType))

  let pJumpTarget = attempt pAbsoluteAddress <|> (pImm |>> Relative)

  (* operands *)
  let pOprReg = pReg |>> OprReg

  let pOprMem = pMemOprSize .>> spaces >>= pMemOpr

  let pOprDirAddr opc =
    check opc isCallOrJmpOpcode >>. pJumpTarget |>> OprDirAddr

  let pOprImm = pImm |>> OprImm

  let pGoToLabel = pId |>> GoToLabel

  let operand opc =
    pOprDirAddr opc
    <|> attempt pOprReg
    <|> pOprImm
    <|> pOprMem
    <|> pGoToLabel
    |>> (fun operand -> printfn "%A" operand; operand)

  let operands opc =
    sepBy (operand opc) operandSeps |>> extractOperands
    |>> (fun operands -> (opc, operands))
    |> skipWhitespaces

  let pInsInfo =
      opt pPrefix >>. (pOpcode >>= operands)
      |>> (fun (opcode, operands) ->
             newInfo inferredPrefix REXPrefix.NOREX None
              opcode operands dummyInsSize )

  // FixMe: the address does not get incremented.
  let pInstructionLine =
    opt pLabelDef >>. spaces >>. pInsInfo  .>> (incrementAddress 0UL) //FixMe
    .>> resetPrefix
    |>> InstructionLine

  let statement =
    attempt pInstructionLine
    <|> (pLabelDef |>> fun _ -> LabelDefLine)
    <|> preturn LabelDefLine

  let statements = sepEndBy statement terminator .>> eof

  member __.Run assembly =
    match runParserOnString statements Map.empty<string, Addr> "" assembly with
    | Success (result, us, _) ->
      FixInsInfo.updateInsInfos (filterInstructionLines result) us
    | Failure (str, _, _) -> printfn "Parser failed!\n%s" str; []
