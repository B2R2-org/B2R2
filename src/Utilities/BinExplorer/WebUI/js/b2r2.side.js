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

class SideMenu {
  static registerEvents(winManager) {
    d3.select("#js-sidemenu__cg").on("click", function () {
      winManager.createWindow("(call graph)", "CG", true);
    });
  }
}

class FunctionList {
  constructor(funcsView) {
    this.funcsView = funcsView;
    this.funcs = {};
  }

  focusEntry(name) {
    this.funcsView.selectAll("li").classed("focused", false);
    if (name in this.funcs) this.funcs[name].classed("focused", true);
  }

  pinEntry(name) {
    this.funcs[name].select("i").classed("pinned", true);
  }

  unpinEntry(name) {
    this.funcs[name].select("i").classed("pinned", false);
  }

  addEntry(name, fnClk, fnDblClk) {
    const entry = this.funcsView.append("li")
      .attr("title", name)
      .classed("c-function-view__item", true)
      .on("click", FunctionList.onClick(name, fnClk, fnDblClk))
      .on("dblclick", function () { d3.event.preventDefault(); });
    entry.append("i")
      .classed("c-function-view__icon", true)
      .classed("fas", true)
      .classed("fa-thumbtack", true);
    entry.append("span").text(name);
    this.funcs[name] = entry;
  }

  static onClick(funcName, fnClk, fnDblClk) {
    let clicks = 0;
    let timer = null;
    return function (_) {
      clicks += 1;
      if (clicks === 1) {
        timer = setTimeout(function () {
          fnClk(funcName);
          clicks = 0;
        }, dblClickWaitTime);
      } else if (clicks === 2) {
        clearTimeout(timer);
        fnDblClk(funcName);
        clicks = 0;
      }
    };
  }
}

class ResizeBar {
  constructor() {
    const sideDisplay = d3.select("#js-side-display");
    $("#js-side-display").resizable({
      handles: { e: "#js-side-resize-bar" },
      resize: function (_e, ui) {
        const nextWidth = ui.size.width;
        sideDisplay.style("flex-basis", nextWidth + "px");
        sideDisplay.style("max-width", nextWidth + "px");
        sideDisplay.style("height", null);
        sideDisplay.style("width", null);
      }
    });
  }
}

