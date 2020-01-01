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

class Window {
  constructor(tab, graph, pinned) {
    this.tab = tab;
    this.graph = graph;
    this.pinned = pinned;
  }
}

class WindowManager {
  constructor() {
    this.tabView = d3.select("#js-tabs");
    $(this.tabView.node())
      .sortable({ revert: true, axis: "x" })
      .disableSelection();
    this.graphView = d3.select("#js-graph");
    this.funcList = new FunctionList(d3.select("#js-function-list"));
    this.resizeBar = new ResizeBar();
    this.windows = {};
    this.currentWin = null;
    SideMenu.registerEvents(this);
  }

  activate(name) {
    const item = this.windows[name];
    this.tabView.selectAll("li").classed("active", false);
    item.tab.classed("active", true);
    this.graphView.selectAll("div").classed("active", false);
    item.graph.container.classed("active", true);
    this.currentWin = name;
    this.funcList.focusEntry(name);
    this.navbar.setCFGKind(item.graph.kind);
  }

  createTab(name, pinned) {
    const myself = this;
    const item = this.tabView.append("li").classed("c-tabs__item", true);
    const anchor = item.append("a").text(name);
    anchor.on("click", function () { myself.activate(anchor.text()); });
    item.append("span")
      .classed("glyphicon", true)
      .classed("glyphicon-remove-circle", true)
      .on("click", function () { myself.closeTab(anchor.text()); });
    if (pinned) item.classed("pinned", true);
    return item;
  }

  createGraph(name, kind) {
    const div = this.graphView.append("div").classed("c-graph", true);
    switch (kind) {
      case "Hexview":
        return new HexGraph(div, kind);
      default:
        return new FlowGraph(div, name, kind);
    }
  }

  // Reload the graph of an old kind to a new kind.
  reloadGraph(name, newKind) {
    const div = this.windows[name].graph.container;
    div.html("");
    this.windows[name].graph = new FlowGraph(div, name, newKind);
  }

  createWindow(name, kind, pinned) {
    if (this.windows[name] !== undefined && this.windows[name].pinned) {
      this.activate(name);
    } else {
      const myself = this;
      this.tabView.selectAll("li").each(function () {
        const funcName = d3.select(this).text();
        if (!myself.windows[funcName].pinned) myself.closeTab(funcName);
      });
      const tab = this.createTab(name, pinned);
      const graph = this.createGraph(name, kind);
      this.windows[name] = new Window(tab, graph, pinned);
      this.activate(name);
    }
  }

  loadWindow(name, kind) {
    if (this.currentWin == name) {
      // Do nothing here.
    } else {
      this.createWindow(name, kind, false);
    }
  }

  onEmptyTab() {
    this.currentWin = null;
    this.navbar.setCFGKind("");
  }

  closeTab(name) {
    if (this.windows[name] !== undefined) {
      this.windows[name].tab.remove();
      this.windows[name].tab.classed("pinned", false);
      this.windows[name].graph.container.remove();
      this.funcList.unpinEntry(name);
      delete this.windows[name];
      if (this.currentWin == name) {
        const tab = this.tabView.selectAll("li").filter(":last-child");
        if (tab.empty()) this.onEmptyTab();
        else this.activate(tab.select("a").text());
      }
    }
  }

  initiate(navbar) {
    this.navbar = navbar;
    const winManager = this;
    const fnClk = function (funcName) {
      winManager.loadWindow(funcName, "Disasm");
      winManager.funcList.focusEntry(funcName);
    };
    const fnDblClk = function (funcName) {
      winManager.createWindow(funcName, "Disasm", true);
      winManager.funcList.focusEntry(funcName);
      winManager.funcList.pinEntry(funcName);
    };
    query({ "q": "Functions" }, function (_status, funcs) {
      $.each(funcs, function (_, name) {
        winManager.funcList.addEntry(name, fnClk, fnDblClk);
      });
    });
  }
}
