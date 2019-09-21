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

class TabList {
  constructor(d) {
    if (!isDict(d, "tablist")) return;

    if (d.id == undefined) {
      this.id = "#id_tabContainer";
    } else {
      this.id = d.id;
    }

    if (d.graphContainerid == undefined) {
      this.graphContainerid = "#id_graphContainer";
    } else {
      this.graphContainerid = d.graphContainerid;
    }

    if (d.minimapContainerid == undefined) {
      this.minimapContainerid = "#minimapDiv";
    } else {
      this.minimapContainerid = d.minimapContainerid;
    }

    this.tabs = {};
    this.endCounter = 0;
  }

  getElem() {
    return $(this.id);
  }

  addTab(tab) {
    this.tabs[tab.name] = tab;
    this.endCounter += 1;
    return this.endCounter;
  }

  setid(id) {
    this.id = id;
  }

  getLength() {
    return Object.keys(this.tabs).length
  }

  checkDuplicate(tabName) {
    let tab = $(this.id + " [value='{0}']".replace("{0}", tabName));
    if (tab.length > 0) {
      return true;
    } else {
      return false
    }
  }

  replace(oldtab, newtab) {
    delete this.tabs[oldtab];
    this.tabs[newtab.name] = newtab;
  }

  delete(name) {
    delete this.tabs[name];
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

  closeTabAll() {
    Root.AutoComplete.clearInput();
    Root.NavBar.setTitle("");
    UIElementInit(false);
  }

  getTab(funcName) {
    return this.tabs[funcName];
  }

  getActiveTab() {
    for (let i in this.tabs) {
      if (this.tabs[i].active) {
        return this.tabs[i];
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

    $(document).on('click', this.id + " .tab", function (e) {
      const funcName = $(this).attr('value');
      self.activate(funcName);
    });
  }
}

class Tab {
  constructor(d) {
    if (!isDict(d, "tab")) return;

    if (d.document === undefined)
      this.document = document;
    else
      this.document = d.document;

    this.tablist = d.tablist;
    this.active = d.active;
    this.name = d.name;
    this.type = d.type;
    this.counter = this.tablist.addTab(this);
    this.id = "#id_tab-" + this.counter;
    this.graph = null;
    this.autocomplete = null;
  }

  init(dims, functionName) {
    const tabTemplate = b2r2.R.tabTemplate;
    const textType = "Disasm";
    const li = String.format(tabTemplate, textType, functionName, this.counter, this.id.split("#")[1]);
    this.tablist.getElem().find('ul').append(li);
    this.initContent(dims);
    return this.counter;
  }

  initContent(dims) {
    const minimapid = "#minimap-" + this.counter;
    const cfgid = "#cfg-" + this.counter;

    if ($(minimapid).length == 0) {
      const miniMapTemplate = String.format(b2r2.R.miniMapTemplate, this.counter);
      $(this.tablist.minimapContainerid).append(miniMapTemplate);
    }
    if ($(cfgid).length == 0) {
      const graphDivTemplate = String.format(b2r2.R.graphDivTemplate, this.counter);
      $(this.tablist.graphContainerid).append(graphDivTemplate);
    }

    // minimize the new minimap when it is minimized.
    if ($(this.tablist.minimapContainerid).hasClass("active")) {
      d3.select(minimapid)
        .style("border", "unset")
        .style("height", "0")
    }

    d3.select(cfgid)
      .attr("width", dims.cfgVPDim.width)
      .attr("height", dims.cfgVPDim.height)
  }

  getElem() {
    return $(this.id);
  }

  setName(name) {
    this.name = name;
    let $tab = $(this.id);
    $tab.attr("title", this.name);
    $tab.attr("value", this.name);
    $tab.find("a").text(this.name);
  }

  setType(type) {
    this.type = type;
    let $tab = $(this.id);
    $tab.attr("text-type", type);
  }

  setGraph(g) {
    this.graph = g;
  }

  addAutoComplete(autocomplete) {
    this.autocomplete = autocomplete;
  }

  add(dims, funcName) {
    this.tablist.activate(funcName);
    return this.init(dims, funcName);
  }

  activateTab() {
    let $tab = $(this.id);
    $tab.addClass("active");
  }

  activateContent() {
    $("#cfgDiv-" + this.counter).show();
    $("#minimap-" + this.counter).show();
  }

  activate() {
    this.activateTab();
    this.activateContent();
    this.active = true;
    Root.NavBar.updateCfgChooserLabel(this.type);
    Root.NavBar.setTitle(this.name);
    Root.NavBar.setTitle(this.name);
    Root.NavBar.setDropdownType("Disasm");
    if (this.graph != undefined) {
      Root.AutoComplete.reload(this.graph);
    }
  }

  deactivateTab() {
    let $tab = $(this.id);
    $tab.removeClass("active");
  }

  deactivateContent() {
    $("#cfgDiv-" + this.counter).hide();
    $("#minimap-" + this.counter).hide();
  }

  deactivate() {
    this.deactivateTab();
    this.deactivateContent();
    this.active = false;
  }

  closeContent() {
    $("#cfgDiv-" + this.counter).remove();
    $("#minimap-" + this.counter).remove();
    return this.counter;
  }

  closeTab() {
    $(this.id).remove();
    const functionItem = Root.FunctionList.get(this.name);
    functionItem.setState("not");
    return this.counter;
  }

  close() {
    this.closeTab();
    this.closeContent();
    this.tablist.delete(this.name);
    return this.counter;
  }

  replace(name, dims, json) {
    const oldFuncName = this.name;
    const functionItem = Root.FunctionList.get(oldFuncName);
    functionItem.setState("not");
    this.setName(name);
    this.closeContent();
    const tab = this.counter;
    this.initContent(dims);
    this.tablist.replace(oldFuncName, this);
    let g = new FlowGraph({
      tab: tab,
      cfg: "#cfg-" + tab,
      stage: "#cfgStage-" + tab,
      group: "#cfgGrp-" + tab,
      minimap: "#minimap-" + tab,
      minimapStage: "#minimapStage-" + tab,
      minimapViewPort: "#minimapVP-" + tab,
      dims: dims,
      json: json
    });
    return g;
  }

  reload(dims, json) {
    this.closeContent();
    const tab = this.counter;
    this.initContent(dims);
    let g = new FlowGraph({
      tab: tab,
      cfg: "#cfg-" + tab,
      stage: "#cfgStage-" + tab,
      group: "#cfgGrp-" + tab,
      minimap: "#minimap-" + tab,
      minimapStage: "#minimapStage-" + tab,
      minimapViewPort: "#minimapVP-" + tab,
      dims: dims,
      json: json
    });
    g.drawGraph();
  }

  registerEvents() {

  }
}
