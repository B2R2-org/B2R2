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

[<RequireQualifiedAccess>]
module B2R2.RearEnd.BinExplore.GUI.IconAssets

open Avalonia.Media
open Avalonia.Svg.Skia

let private cfgIconLightSource: IImage =
  let svgImage = SvgImage()
  svgImage.Source <-
    SvgSource.Load "avares://B2R2.RearEnd.BinExplore/Assets/cfg-light.svg"
  svgImage :> IImage

let private cfgIconDarkSource: IImage =
  let svgImage = SvgImage()
  svgImage.Source <-
    SvgSource.Load "avares://B2R2.RearEnd.BinExplore/Assets/cfg-dark.svg"
  svgImage :> IImage

let private listIconLightSource: IImage =
  let svgImage = SvgImage()
  svgImage.Source <-
    SvgSource.Load "avares://B2R2.RearEnd.BinExplore/Assets/list-light.svg"
  svgImage :> IImage

let private listIconDarkSource: IImage =
  let svgImage = SvgImage()
  svgImage.Source <-
    SvgSource.Load "avares://B2R2.RearEnd.BinExplore/Assets/list-dark.svg"
  svgImage :> IImage

let private searchIconLightSource: IImage =
  let svgImage = SvgImage()
  svgImage.Source <-
    SvgSource.Load "avares://B2R2.RearEnd.BinExplore/Assets/search-light.svg"
  svgImage :> IImage

let private searchIconDarkSource: IImage =
  let svgImage = SvgImage()
  svgImage.Source <-
    SvgSource.Load "avares://B2R2.RearEnd.BinExplore/Assets/search-dark.svg"
  svgImage :> IImage

let private mapIconLightSource: IImage =
  let svgImage = SvgImage()
  svgImage.Source <-
    SvgSource.Load "avares://B2R2.RearEnd.BinExplore/Assets/map-light.svg"
  svgImage :> IImage

let private mapIconDarkSource: IImage =
  let svgImage = SvgImage()
  svgImage.Source <-
    SvgSource.Load "avares://B2R2.RearEnd.BinExplore/Assets/map-dark.svg"
  svgImage :> IImage

let private binaryIconDarkSource: IImage =
  let svgImage = SvgImage()
  svgImage.Source <-
    SvgSource.Load "avares://B2R2.RearEnd.BinExplore/Assets/binary-dark.svg"
  svgImage :> IImage

let private binaryIconLightSource: IImage =
  let svgImage = SvgImage()
  svgImage.Source <-
    SvgSource.Load "avares://B2R2.RearEnd.BinExplore/Assets/binary-light.svg"
  svgImage :> IImage

let private disasmIconDarkSource: IImage =
  let svgImage = SvgImage()
  svgImage.Source <-
    SvgSource.Load "avares://B2R2.RearEnd.BinExplore/Assets/disasm-dark.svg"
  svgImage :> IImage

let private disasmIconLightSource: IImage =
  let svgImage = SvgImage()
  svgImage.Source <-
    SvgSource.Load "avares://B2R2.RearEnd.BinExplore/Assets/disasm-light.svg"
  svgImage :> IImage

let private popoutIconDarkSource: IImage =
  let svgImage = SvgImage()
  svgImage.Source <-
    SvgSource.Load "avares://B2R2.RearEnd.BinExplore/Assets/popout-dark.svg"
  svgImage :> IImage

let private popoutIconLightSource: IImage =
  let svgImage = SvgImage()
  svgImage.Source <-
    SvgSource.Load "avares://B2R2.RearEnd.BinExplore/Assets/popout-light.svg"
  svgImage :> IImage

let private syncIconDarkSource: IImage =
  let svgImage = SvgImage()
  svgImage.Source <-
    SvgSource.Load "avares://B2R2.RearEnd.BinExplore/Assets/sync-dark.svg"
  svgImage :> IImage

let private syncIconLightSource: IImage =
  let svgImage = SvgImage()
  svgImage.Source <-
    SvgSource.Load "avares://B2R2.RearEnd.BinExplore/Assets/sync-light.svg"
  svgImage :> IImage

let private linearIconDarkSource: IImage =
  let svgImage = SvgImage()
  svgImage.Source <-
    SvgSource.Load "avares://B2R2.RearEnd.BinExplore/Assets/linear-dark.svg"
  svgImage :> IImage

let private linearIconLightSource: IImage =
  let svgImage = SvgImage()
  svgImage.Source <-
    SvgSource.Load "avares://B2R2.RearEnd.BinExplore/Assets/linear-light.svg"
  svgImage :> IImage

let private isBrightPrimaryText model =
  match Color.TryParse model.Theme.Text.Primary with
  | true, color ->
    let luminance =
      (0.299 * float color.R + 0.587 * float color.G + 0.114 * float color.B)
      / 255.0
    luminance >= 0.5
  | _ ->
    match model.ThemeMode with
    | Builtin Dark -> true
    | _ -> false

/// Returns the appropriate CFG icon based on the current theme mode and text
/// color.
let cfgIcon model =
  if isBrightPrimaryText model then cfgIconDarkSource
  else cfgIconLightSource

/// Returns the appropriate list icon based on the current theme mode and text
/// color.
let listIcon model =
  if isBrightPrimaryText model then listIconDarkSource
  else listIconLightSource

/// Returns the appropriate search icon based on the current theme mode and text
/// color.
let searchIcon model =
  if isBrightPrimaryText model then searchIconDarkSource
  else searchIconLightSource

/// Returns the appropriate map icon based on the current theme mode and text
/// color.
let mapIcon model =
  if isBrightPrimaryText model then mapIconDarkSource
  else mapIconLightSource

/// Returns the appropriate binary icon based on the current theme mode and text
/// color.
let binaryIcon model =
  if isBrightPrimaryText model then binaryIconDarkSource
  else binaryIconLightSource

/// Returns the appropriate disassembly icon based on the current theme mode
/// and text color.
let disasmIcon model =
  if isBrightPrimaryText model then disasmIconDarkSource
  else disasmIconLightSource

/// Returns the appropriate popout icon based on the current theme mode and text
/// color.
let popoutIcon model =
  if isBrightPrimaryText model then popoutIconDarkSource
  else popoutIconLightSource

/// Returns the appropriate sync icon based on the current theme mode and text
/// color.
let syncIcon model =
  if isBrightPrimaryText model then syncIconDarkSource
  else syncIconLightSource

/// Returns the appropriate linear icon based on the current theme mode and text
/// color.
let linearIcon model =
  if isBrightPrimaryText model then linearIconDarkSource
  else linearIconLightSource
