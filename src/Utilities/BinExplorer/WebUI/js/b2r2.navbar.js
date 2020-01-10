/*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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
 */

"use strict";

class NavBar {
  constructor(winManager) {
    this.winManager = winManager;
    this.registerCopyCFGEvent();
    this.registerCFGMenuEvents();
    this.registerRefreshBtnEvent();
  }

  setCFGKind(kind) {
    if (kind == "Disasm" || kind == "LowUIR" || kind == "SSA")
      $("#js-cfgkind").text(kind);
    else
      $("#js-cfgkind").text("CFG Kind");
  }

  registerCopyCFGEvent() {
    const myself = this;
    $("#js-open-copy-json").click(function () {
      const currentWin = myself.winManager.currentWin;
      const json = myself.winManager.windows[currentWin].graph.json;
      if (json === undefined) $("#js-copy-json").text("");
      else $("#js-copy-json").text(JSON.stringify(json, null, " "));
      $("#js-modal-copy-json").modal("show");
      return false;
    });
  }

  chooseCFG(kind) {
    const funcID = this.winManager.currentWin;
    const winManager = this.winManager;
    if (funcID !== null && funcID.length > 0) {
      switch (winManager.windows[funcID].graph.kind) {
        case "Disasm":
        case "LowUIR":
        case "SSA":
          this.setCFGKind(kind);
          winManager.reloadGraph(funcID, kind);
          break;
        default: break;
      }
    }
  }

  registerCFGMenuEvents() {
    const myself = this;
    d3.select("#js-cfgmenu").selectAll("li").on("click", function () {
      myself.chooseCFG($(this).data("value"));
    });
  }

  registerRefreshBtnEvent() {
    const myself = this;
    d3.select("#js-icon-refresh").on("click", function () {
      const funcID = myself.winManager.currentWin;
      if (funcID !== null && funcID.length > 0) {
        const kind = myself.winManager.windows[funcID].graph.kind;
        myself.winManager.reloadGraph(funcID, kind);
      }
    });
  }
}

