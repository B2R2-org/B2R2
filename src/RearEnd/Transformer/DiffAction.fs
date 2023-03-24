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

namespace B2R2.RearEnd.Transformer

open System
open System.Collections.Generic
open B2R2
open B2R2.RearEnd.Transformer.Utils

type KVecDim = {
  XOffsets: int[]
  IdxForward: int
  IdxBackward: int
}

type OverlappedPosition = {
  X: int
  Y: int
}

type Box = {
  XOff: int
  XLim: int
  YOff: int
  YLim: int
}

type DiffData = {
  LineNo: int[]
  LineID: int[]
  ChangedLineNumbers: bool[]
  Len: int
}

/// The `diff` action.
type DiffAction () =
  let rec findUniqId lineNum cnt lines (dict: Dictionary<_, int>) =
    if lineNum = Array.length lines then dict
    else
      let found, _ = dict.TryGetValue lines[lineNum]
      if not found then
        dict.Add (lines[lineNum], cnt)
        findUniqId (lineNum + 1) (cnt + 1) lines dict
      else
        findUniqId (lineNum + 1) cnt lines dict

  let rec findChangedLines lineNum rchg lineToId (lines: _[]) =
    if lineNum = -1 then
      Array.ofList rchg
    else
      let found, _ = (lineToId: Dictionary<_, _>).TryGetValue lines[lineNum]
      if found then
        findChangedLines (lineNum - 1) (false :: rchg) lineToId lines
      else
        findChangedLines (lineNum - 1) (true :: rchg) lineToId lines

  let rec matchIndices n lineID rindex
                       (rchg: bool[]) (lineToId: Dictionary<_,int>) lines =
    if n = Array.length lines then
      lineID, rindex
    elif rchg[n] then
      matchIndices (n + 1) lineID rindex rchg lineToId lines
    else
      let lineID' = Array.append lineID [| lineToId[lines[n]] |]
      let rindex' = Array.append rindex [| n |]
      matchIndices (n + 1) lineID' rindex' rchg lineToId lines

  let rec findDiffstart n idA idB =
    if n >= min (Array.length idA) (Array.length idB) then 0
    elif idA[n] <> idB[n] then n
    else findDiffstart (n + 1) idA idB

  let rec findDiffend n idA idB =
    if n >= min (Array.length idA) (Array.length idB) then 1
    elif idA[(Array.length idA - 1) - n] <> idB[(Array.length idB - 1) - n] then
      n
    else findDiffend (n + 1) idA idB

  let trim idA idB (lnumA: int[]) (lnumB: int[]) =
    let diffStart = findDiffstart 0 idA idB
    let diffEnd = findDiffend 0 idA idB
    let idA' = idA[diffStart .. (Array.length idA - 1) - diffEnd]
    let idB' = idB[diffStart .. (Array.length idB - 1) - diffEnd]
    let lnumA' = lnumA[diffStart .. (Array.length lnumA - 1) - diffEnd]
    let lnumB' = lnumB[diffStart .. (Array.length lnumB - 1) - diffEnd]
    idA', idB', lnumA', lnumB'

  let prepareMyers linesA linesB =
    let lineToIdA = Dictionary<_, int> () |> findUniqId 0 0 linesA
    let lineToIdB = Dictionary<_, int> () |> findUniqId 0 0 linesB
    let clnumA = findChangedLines (Array.length linesA - 1) [] lineToIdB linesA
    let clnumB = findChangedLines (Array.length linesB - 1) [] lineToIdA linesB
    let idA, lnumA = matchIndices 0 [||] [||] clnumA lineToIdA linesA
    let idB, lnumB = matchIndices 0 [||] [||] clnumB lineToIdA linesB
    let idA, idB, lnumA, lnumB = trim idA idB lnumA lnumB
    { LineNo = lnumA
      LineID = idA
      ChangedLineNumbers = clnumA
      Len = Array.length lnumA },
    { LineNo = lnumB
      LineID = idB
      ChangedLineNumbers = clnumB
      Len = Array.length lnumB }

  /// Initialize the external K value
  let adjustMin kvd idx min dmin value =
    if min > dmin then
      kvd.XOffsets[idx + (min - 1) - 1] <- value
      min - 1
    else
      min + 1

  /// Initialize the external K value
  let adjustMax kvd idx max dmax value =
    if max < dmax then
      kvd.XOffsets[idx + (max + 1) + 1] <- value
      max + 1
    else
      max - 1

  let adjustBoundaryForward kvd min max dmin dmax =
    let min' = adjustMin kvd kvd.IdxForward min dmin -1
    let max' = adjustMax kvd kvd.IdxForward max dmax -1
    min', max'

  let adjustBoundaryBackward kvd min max dmin dmax =
    let min' = adjustMin kvd kvd.IdxBackward min dmin Int32.MaxValue
    let max' = adjustMax kvd kvd.IdxBackward max dmax Int32.MaxValue
    min', max'

  let rec takeSnakeForward x y boundX boundY (idA: int[]) (idB: int[]) =
    if x < boundX && y < boundY && idA[x] = idB[y] then
      takeSnakeForward (x + 1) (y + 1) boundX boundY idA idB
    else x

  let rec takeSnakeBackward x y boundX boundY (idA: int[]) (idB: int[]) =
    if x > boundX && y > boundY && idA[x - 1] = idB[y - 1] then
      takeSnakeBackward (x - 1) (y - 1) boundX boundY idA idB
    else x

  let rec traverseForward d fmin kvd idA idB box bmin bmax isOdd =
    if d < fmin then None
    else
      let x =
        if kvd.XOffsets[kvd.IdxForward + d - 1]
          >= kvd.XOffsets[kvd.IdxForward + d + 1] then
          kvd.XOffsets[kvd.IdxForward + d - 1] + 1
        else
          kvd.XOffsets[kvd.IdxForward + d + 1]
      let x = takeSnakeForward x (x - d) box.XLim box.YLim idA idB
      kvd.XOffsets[kvd.IdxForward + d] <- x
      if isOdd && bmin <= d && d <= bmax
        && kvd.XOffsets[kvd.IdxBackward + d] <= x
      then
        Some { X = x; Y = x - d }
      else
        traverseForward (d - 2) fmin kvd idA idB box bmin bmax isOdd

  let rec traverseBackward d bmin kvd idA idB box fmin fmax isOdd =
    if d < bmin then None
    else
      let x =
        if kvd.XOffsets[kvd.IdxBackward + d - 1]
          < kvd.XOffsets[kvd.IdxBackward + d + 1]
        then
          kvd.XOffsets[kvd.IdxBackward + d - 1]
        else
          kvd.XOffsets[kvd.IdxBackward + d + 1] - 1
      let x = takeSnakeBackward x (x - d) box.XOff box.YOff idA idB
      kvd.XOffsets[kvd.IdxBackward + d] <- x
      if not isOdd && fmin <= d && d <= fmax
        && x <= kvd.XOffsets[kvd.IdxForward + d] then
        Some { X = x; Y = x - d }
      else
        traverseBackward (d - 2) bmin kvd idA idB box fmin fmax isOdd

  let rec splitBox kvd idA idB box fmin fmax bmin bmax isOdd =
    let dmin = box.XOff - box.YLim
    let dmax = box.XLim - box.YOff
    (* Forward *)
    let fmin, fmax = adjustBoundaryForward kvd fmin fmax dmin dmax
    let overlap1 = traverseForward fmax fmin kvd idA idB box bmin bmax isOdd
    (* Backward *)
    let bmin, bmax = adjustBoundaryBackward kvd bmin bmax dmin dmax
    let overlap2 =  traverseBackward bmax bmin kvd idA idB box fmin fmax isOdd
    match (overlap1, overlap2) with
    | (Some ov1, _) -> ov1
    | (_, Some ov2) -> ov2
    | (_, _) -> splitBox kvd idA idB box fmin fmax bmin bmax isOdd

  /// Shrink the box by walking through SW diagonal snake.
  let rec walkThroughDiagonalSW (idA: int[]) (idB: int[]) off1 lim1 off2 lim2 =
    if off1 < lim1 && off2 < lim2 && idA[off1] = idB[off2] then
      walkThroughDiagonalSW idA idB (off1 + 1) lim1 (off2 + 1) lim2
    else
      { XOff = off1; XLim = lim1; YOff = off2; YLim = lim2 }

  /// Shrink the box by walking through NE diagonal snake.
  let rec walkThroughDiagonalNE (idA: int[]) (idB: int[]) off1 lim1 off2 lim2 =
    if off1 < lim1 && off2 < lim2 && idA[lim1 - 1] = idB[lim2 - 1] then
      walkThroughDiagonalNE idA idB off1 (lim1 - 1) off2 (lim2 - 1)
    else
      { XOff = off1; XLim = lim1; YOff = off2; YLim = lim2 }

  let rec markChangedLines dd off lim =
    if off < lim then
      dd.ChangedLineNumbers[dd.LineNo[off]] <- true
      markChangedLines dd (off + 1) lim
    else ()

  let shrinkBox idA idB box =
    let box' = walkThroughDiagonalSW idA idB box.XOff box.XLim box.YOff box.YLim
    walkThroughDiagonalNE idA idB box'.XOff box'.XLim box'.YOff box'.YLim

  let rec cmpChangedLines kvd dd1 dd2 box =
    (* Shrink the box by walking through each diagonal snake (SW and NE). *)
    let box = shrinkBox dd1.LineID dd2.LineID box
    if box.XOff = box.XLim then
      markChangedLines dd2 box.YOff box.YLim
    elif box.YOff = box.YLim then
      markChangedLines dd1 box.XOff box.XLim
    else
      (* Divide *)
      let fmid, bmid = box.XOff - box.YOff, box.XLim - box.YLim
      let isOdd = (fmid - bmid) % 2 <> 0
      kvd.XOffsets[kvd.IdxForward + fmid] <- box.XOff
      kvd.XOffsets[kvd.IdxBackward + bmid] <- box.XLim
      let spl = splitBox kvd dd1.LineID dd2.LineID box fmid fmid bmid bmid isOdd
      (* Conquer *)
      { XOff = box.XOff; XLim = spl.X; YOff = box.YOff; YLim = spl.Y }
      |> cmpChangedLines kvd dd1 dd2
      { XOff = spl.X; XLim = box.XLim; YOff = spl.Y; YLim = box.YLim }
      |> cmpChangedLines kvd dd1 dd2

  let myersDiff dd1 dd2 =
    let nDiags = dd1.Len + dd2.Len + 3
    let kvd =
      { XOffsets = Array.zeroCreate (2 * nDiags + 2);
        IdxForward = dd2.Len + 1
        IdxBackward = dd2.Len + 1 + nDiags }
    { XOff = 0; XLim = dd1.Len; YOff = 0; YLim = dd2.Len }
    |> cmpChangedLines kvd dd1 dd2
    dd1.ChangedLineNumbers, dd2.ChangedLineNumbers

  let [<Literal>] NumBytesPerLine = 16

  let padSpace (arr: _[]) =
    let len = arr.Length
    let padLen = NumBytesPerLine - len % NumBytesPerLine
    Array.concat [| arr
                    (Array.replicate (padLen - 1) (NoColor, "   "))
                    [| (NoColor, "    ") |] |]

  let colorResult bs color res =
    let hex = byteArrayToHexStringArray bs
    Array.mapi2 (fun idx hex needColor ->
      (if needColor then color else NoColor),
      (if idx = bs.Length - 1 then hex else hex + " ")
    ) hex res
    |> padSpace
    |> Array.chunkBySize NumBytesPerLine

  let diff bin1 bin2 =
    let hdl1, hdl2 = Binary.Handle bin1, Binary.Handle bin2
    let bs1, bs2 = hdl1.BinFile.Span.ToArray (), hdl2.BinFile.Span.ToArray ()
    let dd1, dd2 = prepareMyers bs1 bs2
    let res1, res2 = myersDiff dd1 dd2
    let res1, res2 = colorResult bs1 Red res1, colorResult bs2 Green res2
    Array.mapi2 (fun lnum line1 line2 ->
      let offsetStr = (lnum * NumBytesPerLine).ToString("x").PadLeft 8
      Array.concat [| [| (NoColor, offsetStr + " | ")  |]
                      line1
                      [| (NoColor, "| ") |]
                      line2
                      [| (NoColor, Environment.NewLine) |] |]) res1 res2
    |> Array.concat
    |> Array.toList
    |> ColoredString.compile
    |> OutputColored

  interface IAction with
    member __.ActionID with get() = "diff"
    member __.Signature with get() = "Binary[] -> OutString"
    member __.Description with get() = """
    Takes in two binaries as input and returns a diff string as output.
"""
    member __.Transform args collection =
      let bins = collection.Values
      if bins.Length <> 2 then
        invalidArg (nameof DiffAction) "Can only diff extractly two binaries."
      else
        match args with
        | [] ->
          let outstr = diff (unbox<Binary> bins[0]) (unbox<Binary> bins[1])
          { Values = [| box outstr |] }
        | _ -> invalidArg (nameof DiffAction) "Invalid input to diff"
