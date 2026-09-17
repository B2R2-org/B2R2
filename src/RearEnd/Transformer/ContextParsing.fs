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
open System.Globalization
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile

type ContextRegionPermission =
  { Read: bool
    Write: bool
    Execute: bool }

type ContextRegion =
  { Name: string
    Start: Addr
    Finish: Addr
    Permission: ContextRegionPermission }

[<RequireQualifiedAccess>]
module ContextParsing =
  let parseAddress (text: string) =
    if text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
      UInt64.Parse(
        text[2..],
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture
      )
    else
      UInt64.Parse(text, CultureInfo.InvariantCulture)

  let parseHexBytes (text: string) =
    let text = text.Replace(" ", String.Empty).Replace("_", String.Empty)
    let text =
      if text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
        text[2..]
      else
        text
    if text.Length % 2 <> 0 then
      invalidArg (nameof text) "Hex byte strings must have an even length."
    else
      [| for index in 0 .. 2 .. text.Length - 2 ->
           Byte.Parse(
             text.Substring(index, 2),
             NumberStyles.HexNumber,
             CultureInfo.InvariantCulture
           ) |]

  let trimBrackets (text: string) =
    let text = text.Trim()
    if text.StartsWith("[", StringComparison.Ordinal)
       && text.EndsWith("]", StringComparison.Ordinal) then
      text[1..text.Length - 2].Trim()
    else
      text

  let entries text =
    (trimBrackets text)
      .Split([| ';'; ',' |], StringSplitOptions.RemoveEmptyEntries)
    |> Array.map _.Trim()
    |> Array.filter (String.IsNullOrWhiteSpace >> not)

  let splitAssignment (entry: string) =
    let index = entry.IndexOf '='
    if index <= 0 then
      invalidArg (nameof entry) $"Expected key=value entry: {entry}"
    else
      entry[..index - 1].Trim(), entry[index + 1..].Trim()

  let splitParameter (token: string) =
    let key, value = splitAssignment token
    key.ToLowerInvariant(), value

  let private parseRegionPermission (entry: string) (text: string) =
    let text = text.Trim().ToLowerInvariant()
    let valid =
      text.Length > 0
      && (text |> Seq.forall (fun ch ->
        ch = 'r' || ch = 'w' || ch = 'x'))
    if valid then
      { Read = text.Contains "r"
        Write = text.Contains "w"
        Execute = text.Contains "x" }
    else
      invalidArg (nameof entry) $"Invalid region permission: {entry}"

  let parseRegion (entry: string) =
    let name, spec = splitAssignment entry
    let permissionIndex = spec.LastIndexOf ':'
    if permissionIndex <= 0 then
      invalidArg (nameof entry) $"Expected region name=start..end:perm: {entry}"
    else
      let range = spec[..permissionIndex - 1].Trim()
      let permission =
        parseRegionPermission entry spec[permissionIndex + 1..]
      let parts = range.Split([| ".." |], StringSplitOptions.None)
      if parts.Length <> 2 then
        invalidArg (nameof entry) $"Expected region range start..end: {entry}"
      else
        let startAddress = parseAddress (parts[0].Trim())
        let endAddress = parseAddress (parts[1].Trim())
        if startAddress >= endAddress then
          invalidArg (nameof entry)
            $"Region start must be smaller than end: {entry}"
        else
          { Name = name
            Start = startAddress
            Finish = endAddress
            Permission = permission }

  let imageRegions (file: IBinFile) =
    BinFileOps.getSegments file
    |> Array.mapi (fun index segment ->
      if segment.Size > UInt64.MaxValue - segment.Address then
        None
      else
        let name =
          match segment.Name with
          | Some name when not (String.IsNullOrWhiteSpace name) ->
            $"image-{index}:{name}"
          | _ ->
            $"image-{index}"
        let permission = segment.Permission
        Some
          { Name = name
            Start = segment.Address
            Finish = segment.Address + segment.Size
            Permission =
              { Read = permission.HasFlag Permission.Readable
                Write = permission.HasFlag Permission.Writable
                Execute = permission.HasFlag Permission.Executable } })
    |> Array.choose id
    |> Array.toList
