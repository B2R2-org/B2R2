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


namespace B2R2.RearEnd.BinExplore.GUI

open System
open System.Threading
open Avalonia
open Avalonia.Input
open Avalonia.Interactivity
open Avalonia.FuncUI.Builder
open Avalonia.FuncUI.DSL

module private TunnelSubscription =
  let create (routedEvent: RoutedEvent<'arg>) func patch =
    let subscribe (target: AvaloniaObject, fn, token: CancellationToken) =
      let element = target :?> Interactive
      let handler = EventHandler<'arg>(fun _ e -> fn e)
      let routes = RoutingStrategies.Tunnel
      let sub = element.AddDisposableHandler(routedEvent, handler, routes)
      token.Register(fun () -> sub.Dispose()) |> ignore
    let patch = defaultArg patch SubPatchOptions.Never
    AttrBuilder<'t>.CreateSubscription(routedEvent.Name, subscribe, func, patch)

/// Subscribes to routed events that both tunnel and bubble, in the tunnel
/// phase only. FuncUI subscribes a handler to every route its event takes, so
/// such a handler ran twice for each event: once on the way down, and again on
/// the way back up unless the first run had handled the event. The views rely
/// on the first run, which reaches an element before its descendants do: a
/// pane takes the focus before the hexdump inside it handles the press, say.
/// That is the run kept here; the second one only repeated the first.
[<AbstractClass; Sealed>]
type Tunnel =
  /// Listens to PointerPressed in its tunnel phase.
  static member OnPointerPressed(func, ?patch) =
    TunnelSubscription.create InputElement.PointerPressedEvent func patch

  /// Listens to PointerMoved in its tunnel phase.
  static member OnPointerMoved(func, ?patch) =
    TunnelSubscription.create InputElement.PointerMovedEvent func patch

  /// Listens to PointerReleased in its tunnel phase.
  static member OnPointerReleased(func, ?patch) =
    TunnelSubscription.create InputElement.PointerReleasedEvent func patch

  /// Listens to PointerWheelChanged in its tunnel phase.
  static member OnPointerWheelChanged(func, ?patch) =
    TunnelSubscription.create InputElement.PointerWheelChangedEvent func patch

  /// Listens to KeyDown in its tunnel phase.
  static member OnKeyDown(func, ?patch) =
    TunnelSubscription.create InputElement.KeyDownEvent func patch

  /// Listens to ContextRequested in its tunnel phase.
  static member OnContextRequested(func, ?patch) =
    TunnelSubscription.create InputElement.ContextRequestedEvent func patch
