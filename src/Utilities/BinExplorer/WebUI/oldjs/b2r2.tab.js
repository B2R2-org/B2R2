/*
  B2R2 - the Next-Generation Reversing Platform

  Author: Subin Jeong <cyclon2@kaist.ac.kr>
          Soomin Kim <soomink@kaist.ac.kr>
          Sang Kil Cha <sangkilc@kaist.ac.kr>

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

class TabList { // XXX: rename to MainContent
  constructor() {
    this.tabContainer = $(".tab-container");
    this.graph = $(".graph");
    this.minimap = $(".minimap");
    this.tabs = {};
    this.counter = 0;
  }

  append(tab) {
    const tabTemplate = b2r2.R.tabTemplate;
    const li = String.format(tabTemplate, "Disasm", tab.name, ++this.counter);
    const elem = $(this.tabContainer).find('ul').append(li);
    this.tabs[tab.name] = tab;
    return elem;
  }

  getLength() {
    return Object.keys(this.tabs).length
  }

  checkDuplicate(tabName) {
    let tab = $(this.id + " [value='{0}']".replace("{0}", tabName));
    return tab.length > 0;
  }

  remove(name) {
    delete this.tabs[name];
  }

  replace(oldtab, newtab) {
    this.remove(oldtab);
    this.tabs[newtab.name] = newtab;
  }

  getActiveTab() {
    for (let i in this.tabs) {
      if (this.tabs[i].active) return this.tabs[i];
    }
    return undefined;
  }

  closeTabAll() {
    Root.WordSearch.clearInput();
    Root.NavBar.setTitle("");
    UIElementInit(false);
  }

  closeTab(funcName) {
    const tab = this.tabs[funcName];
    tab.close();
    const tabLength = this.getLength();
    if (tabLength == 0) {
      this.closeTabAll();
    } else {
      if (this.getActiveTab() === undefined) {
        this.tabs[Object.keys(this.tabs)[0]].activate();
      }
    }
  }

  activate(funcName) {
    for (let i in this.tabs) {
      if (this.tabs[i].name == funcName) {
        this.tabs[i].activate();
      } else {
        this.tabs[i].deactivate();
      }
    }
  }

  deactivateAll() {
    for (let i in this.tabs) {
      this.tabs[i].deactivate();
    }
  }

  registerEvents() {
    const self = this;
    $(document).on('click', '.close-tab', function (e) {
      e.preventDefault();
      e.stopPropagation();
      const funcName = $(this).closest("li").attr("value");
      self.closeTab(funcName);
    });

    $(document).on('click', ".js-main__close-tab", function (e) {
      const funcName = $(this).attr('value');
      self.activate(funcName);
    });
  }
}

class Tab {
  constructor(tabs, name, dims) {
    this.tablist = tabs;
    this.active = true;
    this.name = name;
    this.type = "Disasm";
    this.dom = this.tablist.append(this);
    this.idx = this.tablist.counter;
    this.graph = null;
    this.wordsearch = null;
    this.loadElements(dims);
    this.tablist.activate(name);
  }

  getIndex() {
    return this.idx;
  }

  loadElements(dims) {
    const minimapId = "#js-minimap-" + this.idx;
    const cfgId = "#js-main__cfg-" + this.idx;

    if ($(minimapId).length == 0) {
      const miniMapTemplate = String.format(b2r2.R.miniMapTemplate, this.idx);
      $(this.tablist.minimap).append(miniMapTemplate);
    }

    if ($(cfgId).length == 0) {
      const graphDivTemplate = String.format(b2r2.R.graphDivTemplate, this.idx);
      $(this.tablist.graph).append(graphDivTemplate);
    }

    // Hide the new minimap when it is minimized.
    if ($(this.tablist.tabContainer).hasClass("active")) {
      d3.select(minimapId)
        .style("border", "unset")
        .style("height", "0");
    }

    d3.select(cfgId)
      .attr("width", dims.cfgVPDim.width)
      .attr("height", dims.cfgVPDim.height);
  }

  setName(name) {
    this.name = name;
    this.dom.attr("title", this.name);
    this.dom.attr("value", this.name);
    this.dom.find("a").text(this.name);
  }

  setType(type) {
    this.type = type;
    this.dom.attr("text-type", type);
  }

  setGraph(g) {
    this.graph = g;
  }

  activate() {
    this.dom.addClass("active");
    this.active = true;
    $("#js-main__cfg-" + this.idx).parent("div").show();
    $("#js-minimap-" + this.idx).show();
    Root.NavBar.updateCfgChooserLabel(this.type);
    Root.NavBar.setTitle(this.name);
    Root.NavBar.setTitle(this.name);
    Root.NavBar.setDropdownType("Disasm");
    if (this.graph != undefined) {
      Root.WordSearch.reload(this.graph);
    }
  }

  deactivate() {
    this.dom.removeClass("active");
    $("#js-main__cfg-" + this.idx).parent("div").hide();
    $("#js-minimap-" + this.idx).hide();
    this.active = false;
  }

  closeContent() {
    $("#js-main__cfg-" + this.idx).parent("div").remove();
    $("#js-minimap-" + this.idx).remove();
  }

  closeTab() {
    $(this.id).remove();
    const functionItem = Root.FunctionList.get(this.name);
    functionItem.setState("not");
    return this.idx;
  }

  close() {
    this.closeTab();
    this.closeContent();
    this.tablist.remove(this.name);
    return this.idx;
  }

  replace(name, dims, json) {
    const oldFuncName = this.name;
    const functionItem = Root.FunctionList.get(oldFuncName);
    functionItem.setState("not");
    this.setName(name);
    this.closeContent();
    const tabIdx = this.idx;
    this.loadElements(dims);
    this.tablist.replace(oldFuncName, this);
    let g = new FlowGraph(document, tabIdx, dims, json, false);
    return g;
  }

  reload(dims, json) {
    this.closeContent();
    const tab = this.idx;
    this.initContent(dims);
    let g = new FlowGraph(document, tabIdx, dims, json, false);
    g.drawGraph();
  }

  registerEvents() {
  }
}
