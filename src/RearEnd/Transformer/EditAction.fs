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
open System.Threading
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile

/// The `edit` action.
type EditAction() =
  let makeBinary bin newbs =
    let hdl = Binary.Handle bin
    if hdl.File.Format = FileFormat.RawBinary then
      Binary.OfFragment("Editted from ", bin, newbs, hdl.File.BaseAddress)
      |> box
    else
      Binary.OfEditedContent("Editted from ", bin, newbs) |> box

  let parseInt32 (value: string) =
    let style, value =
      if value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
        NumberStyles.HexNumber, value[2..]
      else
        NumberStyles.Integer, value
    Int32.Parse(value, style, CultureInfo.InvariantCulture)

  let parseEndOffset soff (eoff: string) =
    if eoff.StartsWith "+" then soff + parseInt32 (eoff[1..])
    else parseInt32 eoff

  let insert off (snip: byte[]) o =
    let bin = unbox<Binary> o
    let hdl = Binary.Handle bin
    let bs = hdl.File.RawBytes.ToArray()
    let newbs = Array.zeroCreate (bs.Length + snip.Length)
    if off > bs.Length then invalidArg (nameof off) "Offset is too large."
    elif off = 0 then
      Array.blit snip 0 newbs 0 snip.Length
      Array.blit bs 0 newbs snip.Length bs.Length
    else
      Array.blit bs 0 newbs 0 off
      Array.blit snip 0 newbs off snip.Length
      Array.blit bs off newbs (off + snip.Length) (bs.Length - off)
    makeBinary bin newbs

  let delete soff eoff o =
    let bin = unbox<Binary> o
    let hdl = Binary.Handle bin
    let bs = hdl.File.RawBytes.ToArray()
    let rmlen = eoff - soff
    let newbs = Array.zeroCreate (bs.Length - rmlen)
    if rmlen > bs.Length || eoff > bs.Length || soff >= bs.Length || soff < 0
    then invalidArg (nameof soff) "Wrong offset(s) given."
    elif soff = 0 then
      Array.blit bs rmlen newbs 0 (bs.Length - rmlen)
    else
      Array.blit bs 0 newbs 0 soff
      Array.blit bs (soff + rmlen) newbs soff (bs.Length - soff - rmlen)
    makeBinary bin newbs

  (* The edited whole content is bs, into which newbs has just been blitted;
     newbs alone is only the replacement snippet. *)
  let replace soff eoff newbs o =
    let bin = unbox<Binary> o
    let hdl = Binary.Handle bin
    let bs = hdl.File.RawBytes.ToArray()
    Array.blit newbs 0 bs soff (eoff - soff)
    makeBinary bin bs

  let map cancellationToken operation collection =
    let cancellationToken: CancellationToken = cancellationToken
    collection.Values
    |> Array.map (fun value ->
      cancellationToken.ThrowIfCancellationRequested()
      operation value)

  let transform cancellationToken args collection =
    match args with
    | "insert" :: off :: hexstr :: [] ->
      let off = parseInt32 off
      let bs = ByteArray.ofHexString hexstr
      { Values = map cancellationToken (insert off bs) collection }
    | "delete" :: soff :: eoff :: [] ->
      let soff = parseInt32 soff
      let eoff = parseEndOffset soff eoff
      if eoff > soff then
        { Values = map cancellationToken (delete soff eoff) collection }
      else
        invalidArg (nameof args) "Invalid offsets."
    | "replace" :: soff :: eoff :: hexstr :: [] ->
      let soff = parseInt32 soff
      let eoff = parseEndOffset soff eoff
      let newbs = ByteArray.ofHexString hexstr
      if eoff > soff && (eoff - soff) = newbs.Length then
        let replace = replace soff eoff newbs
        { Values = map cancellationToken replace collection }
      else
        invalidArg (nameof args) "Invalid offsets or hexstring."
    | _ -> invalidArg (nameof args) "Invalid edit action."

  interface IAction with
    member _.ActionID with get() = "edit"
    member _.Signature with get() =
      "Binary -> edit insert offset=<n> hex=<hex> | "
      + "delete offset=<n> end=<n-or-size> | "
      + "replace offset=<n> end=<n-or-size> hex=<hex> -> Binary"
    member _.Description with get() =
      """
    Take in a binary as well as edit action as input and return a modified
    binary as output. There are following supported edit actions.

      - `insert offset=<n> hex=<hex>`
        Insert bytes at offset n. This will increase the size of the resulting
        binary by the size of the given hex bytes.

      - `delete offset=<n> end=<m>`
        Remove bytes in the half-open range [n, m). The resulting binary will
        have the size less than the original one.

      - `delete offset=<n> end=+<sz>`
        Remove sz bytes starting at offset n.

      - `replace offset=<n> end=<m> hex=<hex>`
        Replace bytes in the half-open range [n, m). The hex byte length should
        be equal to m - n.

      - `replace offset=<n> end=+<sz> hex=<hex>`
        Replace sz bytes starting at offset n.
"""
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection
