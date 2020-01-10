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

  getCurrentHeight() {
    return this.graphView.node().getBoundingClientRect().height;
  }

  activate(id) {
    const item = this.windows[id];
    this.tabView.selectAll("li").classed("active", false);
    item.tab.classed("active", true);
    this.graphView.selectAll("div").classed("active", false);
    item.graph.container.classed("active", true);
    this.currentWin = id;
    this.funcList.focusEntry(id);
    this.navbar.setCFGKind(item.graph.kind);
    item.graph.onActivate();
  }

  createTab(id, name, pinned) {
    const myself = this;
    const item = this.tabView.append("li").classed("c-tabs__item", true)
      .attr("funcid", id);
    const anchor = item.append("a").text(name);
    anchor.on("click", function () { myself.activate(id); });
    item.append("span")
      .classed("glyphicon", true)
      .classed("glyphicon-remove-circle", true)
      .on("click", function () { myself.closeTab(id); });
    if (pinned) item.classed("pinned", true);
    return item;
  }

  createGraph(id, kind) {
    const div = this.graphView.append("div").classed("c-graph", true);
    switch (kind) {
      case "Hexview":
        return new HexGraph(div, kind);
      case "Term":
        return new TermGraph(div, kind);
      default:
        return new FlowGraph(div, id, kind);
    }
  }

  // Reload the graph of an old kind to a new kind.
  reloadGraph(id, newKind) {
    const div = this.windows[id].graph.container;
    div.html("");
    this.windows[id].graph = new FlowGraph(div, id, newKind);
  }

  createWindow(id, name, kind, pinned) {
    if (this.windows[id] !== undefined && this.windows[id].pinned) {
      this.activate(id);
    } else {
      const myself = this;
      this.tabView.selectAll("li").each(function () {
        const id = d3.select(this).attr("funcid");
        if (!myself.windows[id].pinned) myself.closeTab(id);
      });
      const tab = this.createTab(id, name, pinned);
      const graph = this.createGraph(id, kind);
      this.windows[id] = new Window(tab, graph, pinned);
      this.activate(id);
    }
  }

  loadWindow(id, name, kind) {
    if (this.currentWin == id) {
      // Do nothing here.
    } else {
      this.createWindow(id, name, kind, false);
    }
  }

  onEmptyTab() {
    this.currentWin = null;
    this.navbar.setCFGKind("");
  }

  closeTab(id) {
    if (this.windows[id] !== undefined) {
      this.windows[id].tab.remove();
      this.windows[id].tab.classed("pinned", false);
      this.windows[id].graph.container.remove();
      this.funcList.unpinEntry(id);
      delete this.windows[id];
      if (this.currentWin == id) {
        const tab = this.tabView.selectAll("li").filter(":last-child");
        if (tab.empty()) this.onEmptyTab();
        else { try { this.activate(tab.attr("funcid")); } catch (_) { } }
      }
    }
  }

  initiate(navbar) {
    this.navbar = navbar;
    const winManager = this;
    const fnClk = function (funcID, funcName) {
      winManager.loadWindow(funcID, funcName, "Disasm");
      winManager.funcList.focusEntry(funcID);
    };
    const fnDblClk = function (funcID, funcName) {
      winManager.createWindow(funcID, funcName, "Disasm", true);
      winManager.funcList.focusEntry(funcID);
      winManager.funcList.pinEntry(funcID);
    };
    query({ "q": "Functions" }, function (_status, funcs) {
      $.each(funcs, function (_, funcinfo) {
        const id = funcinfo.id;
        const name = funcinfo.name;
        winManager.funcList.addEntry(id, name, fnClk, fnDblClk);
      });
    });
  }
}
