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

namespace B2R2.Peripheral.Assembly.ARM32

open System
open FParsec
open B2R2
open B2R2.FrontEnd.ARM32
open B2R2.Peripheral.Assembly.ARM32.ParserHelper

/// <namespacedoc>
///   <summary>
///   Contains ARM32-specific assembly components and types.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents an assembler for ARM32 binaries.
/// </summary>
type Assembler(startAddress: Addr) =

  let mutable address = startAddress
  let mutable isThumb: bool = false
  let mutable wBackFlag = false

  (* Helper functions for updating the status of the parser. *)

  /// Adds the parsed label to the label definition map.
  let addLabeldef (lbl: string) =
    updateUserState (fun (us: Map<string, Addr>) -> us.Add(lbl, address))
    >>. preturn ()

  let pOpModeSwitcher =
    pchar '.' >>.
    (pstringCI "arm" |>> (fun _ -> isThumb <- false) <|>
      (pstringCI "thumb" |>> (fun _ -> isThumb <- true)))

  let checkWrightBack =
    opt (pchar '!') |>> fun x -> if x.IsNone then () else wBackFlag <- true

  let setWBFlag =
    wBackFlag <- true; preturn ()

  let clearWBackFlag = wBackFlag <- false; preturn ()

  let getInsLength () =
    if isThumb then 2u else 4u

  let incrementAddress =
    preturn ()
    |>> (fun _ ->
          if not isThumb then address <- address + 4UL
          else address <- address + 2UL)

  let isWhitespace c = [ ' '; '\t'; '\f' ] |> List.contains c

  let whitespace = manySatisfy isWhitespace

  let whitespace1 = many1Satisfy isWhitespace

  let skipWhitespaces s = whitespace >>? s .>>? whitespace

  let terminator = (pchar ';' <|> newline) |> skipWhitespaces

  let operandSeps = (pchar ',' >>. whitespace) <|> whitespace1

  let betweenSquareBraces s =
    s |> skipWhitespaces |> between (pchar '[') (pchar ']')

  let betweenCurlyBraces s =
    s |> skipWhitespaces |> between (pchar '{') (pchar '}')


  let alphanumericWithUnderscore s = Char.IsLetterOrDigit s || s = '_'

  let pId = many1Satisfy alphanumericWithUnderscore

  let pLabelDef =
    pId .>>? pchar ':' >>= addLabeldef |> skipWhitespaces

  let pSIMDDataType =
    [ "8"
      "16"
      "32"
      "64"
      "s8"
      "s16"
      "s32"
      "s64"
      "u8"
      "u16"
      "u32"
      "u64"
      "i8"
      "i16"
      "i32"
      "i64"
      "f16"
      "f32"
      "f64"
      "p8" ]
    |> Seq.map pstringCI
    |> choice
    |>> getSIMDTypFromStr

  let pPSRFlag =
    [ "c"
      "x"
      "xc"
      "s"
      "sc"
      "sx"
      "sxc"
      "f"
      "fc"
      "fx"
      "fxc"
      "fs"
      "fsc"
      "fsx"
      "fsxc"
      "nzcv"
      "nzcvq"
      "g"
      "nzcvqg" ]
    |> Seq.rev
    |> Seq.map (pstringCI >> attempt)
    |> choice
    |>> getPSRFlagFromStr
    |>> Some

  let pOptionOpr =
    [ "sy"
      "ld"
      "ishst"
      "ishld"
      "ish"
      "nshst"
      "nshld"
      "nsh"
      "oshst"
      "oshld"
      "osh" ]
    |> Seq.map (pstringCI >> attempt)
    |> choice
    |>> optionOprFromStr

  let pSRType =
    [ "lsl"; "lsr"; "asr"; "ror"; "rrx" ]
    |> Seq.map (pstringCI >> attempt)
    |> choice
    |>> getSRType

  let pIflag =
    [ "ai"; "af"; "if"; "aif"; "a"; "i" ]
    |> Seq.map (pstringCI >> attempt)
    |> choice
    |>> iFlagFromStr

  let pEndian =
    pstringCI "le" >>. preturn Endian.Little
    <|> (pstringCI "be" >>. preturn Endian.Big)

  let pSIMDDataTypes =
    many1 (pchar '.' >>. pSIMDDataType)
    |>> (fun lst ->
          match lst with
          | [ smd ] -> OneDT smd
          | [ smd1; smd2 ] -> TwoDT(smd1, smd2)
          | _ -> failwith "Can not have more than two SIMDDataTypes")

  let pQualifier =
    pchar '.' >>.
    ((anyOf "nN" >>. preturn Qualifier.N) <|>
     (anyOf "wW" >>. preturn Qualifier.W))

  let pOpcode =
    (Enum.GetNames typeof<Opcode>)
    |> Array.map (pstringCI)
    |> Array.rev (* This is so that (eg. ADD does not get parsed for 'ADDS' *)
    |> Array.map (fun p ->
      attempt p
      |>> (fun name -> Enum.Parse(typeof<Opcode>, name.ToUpper()) :?> Opcode))
    |> choice

  let pCondition =
    ((Enum.GetNames typeof<Condition>)
    |> Array.map
      (fun s ->
        pstringCI s
        |>> (fun name ->
          Enum.Parse(typeof<Condition>, name.ToUpper()) :?> Condition))
    |> choice)

  let numberFormat =
    NumberLiteralOptions.AllowBinary
    ||| NumberLiteralOptions.AllowOctal
    ||| NumberLiteralOptions.AllowHexadecimal
    ||| NumberLiteralOptions.AllowMinusSign

  let regNumberFormat = NumberLiteralOptions.None

  let pImm =
    opt (pchar '#') >>.
    numberLiteral numberFormat "number" |>> (fun x -> x.String |> int64)

  let pAmount =
    opt (pchar '#') >>. pImm |>> uint32 |>> Imm

  let registersList =
    Enum.GetNames typeof<Register>
    |> Array.rev (* This is so that (eg. s1 does not get parsed for 's12' *)
    |> Array.map pstringCI

  let pReg =
    Array.map attempt registersList |> choice
    |>> (fun regName ->
          Enum.Parse(typeof<Register>, regName.ToUpper())
          :?> Register)

  let operators = (pchar '+' |>> fun _ -> (+)) <|> (pchar '-' |>> fun _ -> (-))

  let immWithOperators =
    attempt (pipe3 pImm operators pImm (fun a op c -> op a c))

  let pShiftedIndexRegister =
    pOpcode .>> spaces .>>. pAmount
    >>= (fun (opcode, amt) -> parseShiftOperation opcode amt)

  let pDummyRegImmOffset =
    pImm |>> fun cons -> ImmOffset(Register.C0, None, Some cons)

  let pDummyShiftedRegOffset =
    opt (pchar '-' >>. preturn Minus) .>>. pReg .>> spaces .>> pchar ','
    .>> spaces .>>. pShiftedIndexRegister
    |>> fun ((sign, reg), shifter) ->
      RegOffset(Register.C0, sign, reg, Some shifter)

  let pDummyRegRegOffset =
    opt (pchar '-' >>. preturn Minus) .>>. pReg
    |>> (fun (sOpt, reg) -> RegOffset(Register.C0, sOpt, reg, None))
    .>> setWBFlag

  let pDummyRegOffset =
    pDummyRegImmOffset
    <|> attempt pDummyShiftedRegOffset
    <|> pDummyRegRegOffset

  let pOffsetOrPreIndexedAddress =
    pReg .>> spaces .>> pchar ',' .>> spaces .>>. pDummyRegOffset
    |> betweenSquareBraces
    |>> substituteParsedRegister
    |> attempt
    <|> (betweenSquareBraces pReg |>> (fun reg -> ImmOffset(reg, None, None)))
    .>>. opt (pchar '!')
    |>> (fun (offset, preIdxIdentifier) ->
          if preIdxIdentifier.IsNone then OffsetMode offset
          else PreIdxMode offset)

  let pPostIndexedAddress =
    betweenSquareBraces pReg .>> skipWhitespaces (pchar ',')
    .>>. pDummyRegOffset
    |>> substituteParsedRegister
    |>> PostIdxMode

  let pUnIdxMode =
    betweenSquareBraces pReg .>> spaces
    .>>. betweenCurlyBraces pImm
    |>> UnIdxMode

  let pAddressingMode =
    attempt pPostIndexedAddress
    <|> attempt pUnIdxMode
    <|> pOffsetOrPreIndexedAddress

  let pSIMDFPReg =
    pReg .>>. opt (betweenCurlyBraces (opt puint8))
    |>> (fun (reg, elementOpt) ->
          if elementOpt.IsNone then Vector reg
          else Scalar(reg, elementOpt.Value))

  (* Operand Parsers *)
  let pOprReg = pReg |>> OprReg .>> checkWrightBack

  let pOprSpecReg = pReg .>> pchar '_' .>>. pPSRFlag |>> OprSpecReg

  let pOprRegList =
    sepBy pReg (spaces >>. pchar ',' >>. spaces)
    |> betweenCurlyBraces
    |>> OprRegList

  let pOprSIMD opcode =
    if isSIMDOpcode opcode then
      sepBy pSIMDFPReg operandSeps |> betweenCurlyBraces |>> makeSIMDOperand
      <|> (pSIMDFPReg |>> SFReg) |>> OprSIMD
    else fail "not simd operand"

  let pOprImm =
    immWithOperators <|> pImm |>> Operand.OprImm

  let pOprFPImm = pfloat |>> OprFPImm

  let pOprShift = pSRType .>> spaces1 .>>. pAmount |>> OprShift

  let pOprRegShift = pSRType .>> spaces1 .>>. pReg |>> OprRegShift

  let pOprMemory = pAddressingMode |>> OprMemory

  let pOprOption opcode =
    if opcode = Opcode.DMB || opcode = Opcode.DSB then pOptionOpr |>> OprOption
    else fail "the opcode does not accept option operand"

  let pOprIflag = pIflag |>> OprIflag

  let pOprEndian opr =
    if opr = Opcode.SETEND then pEndian |>> OprEndian
    else fail "not an endian setting operand"

  let pOprCond opcode =
    if isITInstruction opcode then pCondition |>> OprCond
    else fail "not an IT opcode"

  let pGotoLabel = pId |>> Operand.GoToLabel

  let pOperand opcode =
      attempt (pOprSIMD opcode)
     <|> (pOprOption opcode)
     <|> (pOprEndian opcode)
     <|> (pOprCond opcode)
     <|> attempt pOprShift
     <|> attempt pOprRegShift
     <|> attempt pOprFPImm
     <|> attempt pOprSpecReg
     <|> attempt pOprReg
     <|> attempt pOprRegList
     <|> attempt pOprImm
     <|> attempt pOprMemory
     <|> attempt pOprIflag
     <|> attempt pGotoLabel

  /// Parses the operands making use of the already parsed opcode and returns
  /// a tuple of the previosly parsed information and the parsed operands.
  /// This is necessary because some operands depend on the opcode.
  let pOperands parsedInfo =
    sepBy (pOperand (getOpCode parsedInfo)) operandSeps |>> extractOperands
    |>> (fun operands -> parsedInfo, operands)
    |> skipWhitespaces

  let pInsInfo =
      pOpcode .>>. pCondition .>>. opt (attempt pSIMDDataTypes)
      .>>. opt pQualifier >>= pOperands
      |>> (fun ((((opcode, cond), simd), qual), operands) ->
              let qual =
                match qual with
                | Some W -> W
                | _ -> N
              newInsInfo
                 address opcode cond 0uy wBackFlag qual simd
                 operands (getInsLength ()) isThumb None)
      .>> clearWBackFlag

  let pInstructionLine =
    opt pLabelDef >>. spaces >>. pInsInfo .>> incrementAddress
    |>> InstructionLine

  let statement =
    attempt pInstructionLine <|>
    (pLabelDef |>> fun _ -> LabelDefLine) <|>
    (pOpModeSwitcher |>> fun _ -> LabelDefLine) <|>
    preturn LabelDefLine

  let statements = sepEndBy statement terminator .>> eof

  member _.Run assembly =
    match runParserOnString statements Map.empty<string, Addr> "" assembly with
    | Success(result, us, _) ->
      SecondPass.updateInsInfos (filterInstructionLines result) us |> ignore
      Terminator.futureFeature ()
    | Failure(str, _, _) -> printfn "Parser failed!\n%s" str; []
