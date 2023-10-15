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
open B2R2
open B2R2.FrontEnd.BinInterface

/// The `edit` action.
type EditAction () =
  let makeBinary bin hdl newbs =
    let hdl' = lazy BinHandle.NewBinHandle (hdl, newbs)
    let annot = Binary.MakeAnnotation "Editted from " bin
    Binary.Init annot hdl'
    |> box

  let parseEndOffset soff (eoff: string) =
    if eoff.StartsWith "+" then soff + Convert.ToInt32 eoff[1..] - 1
    else Convert.ToInt32 eoff

  let insert off (snip: byte[]) o =
    let bin = unbox<Binary> o
    let hdl = Binary.Handle bin
    let bs = hdl.BinFile.RawBytes
    let newbs = Array.zeroCreate (bs.Length + snip.Length)
    if off > bs.Length then invalidArg (nameof off) "Offset is too large."
    elif off = 0 then
      Array.blit snip 0 newbs 0 snip.Length
      Array.blit bs 0 newbs snip.Length bs.Length
    else
      Array.blit bs 0 newbs 0 off
      Array.blit snip 0 newbs off snip.Length
      Array.blit bs off newbs (off + snip.Length) (bs.Length - off)
    makeBinary bin hdl newbs

  let delete soff eoff o =
    let bin = unbox<Binary> o
    let hdl = Binary.Handle bin
    let bs = hdl.BinFile.RawBytes
    let rmlen = eoff - soff + 1
    let newbs = Array.zeroCreate (bs.Length - rmlen)
    if rmlen > bs.Length || eoff >= bs.Length || soff >= bs.Length || soff < 0
    then invalidArg (nameof soff) "Wrong offset(s) given."
    elif soff = 0 then
      Array.blit bs rmlen newbs 0 (bs.Length - rmlen)
    else
      Array.blit bs 0 newbs 0 soff
      Array.blit bs (soff + rmlen) newbs soff (bs.Length - soff - rmlen)
    makeBinary bin hdl newbs

  let replace soff eoff newbs o =
    let bin = unbox<Binary> o
    let hdl = Binary.Handle bin
    let bs = hdl.BinFile.RawBytes
    Array.blit newbs 0 bs soff (eoff - soff + 1)
    makeBinary bin hdl newbs

  interface IAction with
    member __.ActionID with get() = "edit"
    member __.Signature
      with get() = "Binary * <action> -> Binary"
    member __.Description with get() = """
    Take in a binary as well as edit action as input and return a modified
    binary as output. There are following supported edit actions.

      - `insert` <n> <hexstring>
        Insert bytes, given as <hexstring>, at offset <n>. This will increase
        the size of the resulting binary by the size of the given hexstring.

      - `delete` <n> <m>
        Remove bytes of size (m - n + 1) in the given binary located at <n>. The
        resulting binary will have the size less than the original one.

      - `delete` <n> +<sz>
        Remove bytes of size `sz` in the given binary located at <n>. The
        resulting binary will have the size less than the original one.

      - `replace` <n> <m> <hexstring>
        Replace bytes at offset from <n> to <m> with the given <hexstring>. The
        size of the hexstring should be equal to "m - n + 1" where m > n.

      - `replace` <n> +<sz> <hexstring>
        Replace bytes at offset from n to (n + sz - 1) with the given
        <hexstring>. The size of the hexstring should be equal to sz.
"""
    member __.Transform args collection =
      match args with
      | "insert" :: off :: hexstr :: [] ->
        let off = Convert.ToInt32 off
        let bs = ByteArray.ofHexString hexstr
        { Values = collection.Values
                   |> Array.map (insert off bs) }
      | "delete" :: soff :: eoff :: [] ->
        let soff = Convert.ToInt32 soff
        let eoff = parseEndOffset soff eoff
        if eoff >= soff then
          { Values = collection.Values |> Array.map (delete soff eoff) }
        else invalidArg (nameof args) "Invalid offsets."
      | "replace" :: soff :: eoff :: hexstr :: [] ->
        let soff = Convert.ToInt32 soff
        let eoff = parseEndOffset soff eoff
        let newbs = ByteArray.ofHexString hexstr
        if eoff >= soff && (eoff - soff + 1) = newbs.Length then
          { Values = collection.Values |> Array.map (replace soff eoff newbs) }
        else invalidArg (nameof args) "Invalid offsets or hexstring."
      | _ -> invalidArg (nameof args) "Invalid edit action."
