/*
  B2R2 - the Next-Generation Reversing Platform

  Author: Subin Jeong <cyclon2@kaist.ac.kr>
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

class NavBar {
  constructor(d) {
    this.functionName = d.functionName;
    this.path = d.path;
    this.searchInputId = "#id-input_address";
  }

  setTitle(functionName) {
    this.functionName = functionName;
    $("#uiFuncName").text(this.functionName);
    $("#uiFuncName").attr("title", this.functionName);
  }

  setDropdownType(type) {
    $(".cfgChooserBtn").text(type);
    $(".cfgChooserBtn").append('<span class="caret"></span>');
  }

  getDropdownType() {
    return $(".cfgChooserBtn").text().trim();
  }

  setFilePath() {
    let filepath;
    let token = str.split("/");
    if (this.path.length < 45) {
      filepath = this.path;
    } else {
      for (let t in token) {
        if (token.slice(t).join("/").length < 45) {
          filepath = ".../" + token.slice(t).join("/");
          break
        }
      }
    }

    if (filepath === undefined) {
      filepath = this.path.split("/").slice(str.split("/").length - 1); // only file name
    }

    $("#binInfo").text(filepath);
    $("#binInfo").attr("title", this.path);
  }

  copyEvent() {
    $("#binInfo").on("click", function () {
      let str = $("#binInfo").attr("title");
      copyToClipboard(str);
      popToast("info", "File path copied", 3);
    });
  }

  updateCfgChooserLabel(textType) {
    $("#cfgChooser li div a").parents(".dropdown")
      .find(".dropdown-toggle")
      .html(textType + ' <span class="caret"></span>');
  }

  cfgChooser(t) {
    const self = this;
    let funcName = $("#uiFuncName").text();
    $(this).parents(".dropdown").find(".dropdown-toggle").val(t);
    query({
      "q": ("cfg-" + t),
      "args": funcName
    },
      function (_status, json) {
        if (Object.keys(json).length > 0) {
          let dims = reloadUI();
          const currentTab = Root.TabList.getActiveTab();
          let g = currentTab.replace(currentTab.name, dims, json);
          g.drawGraph();
          Root.TabList.tabs[currentTab.name].setType(t);
          self.updateCfgChooserLabel(t);
          const functionItem = Root.FunctionList.get(currentTab.name);
          functionItem.setState("active");
          Root.NavBar.setModalData(json);
        }
      });
  }

  setModalData(json) {
    let mymodal = $("#codeCopyCFG");
    mymodal.text(JSON.stringify(json, null, " "));
  }

  searchAddress(addr) {
    query({
      "q": "address",
      "args": JSON.stringify({ "addr": addr })
    },
      function (status, json) {
        if (Object.keys(json).length > 0) {
          let dims = reloadUI();
          let tab = new Tab({
            tablist: Root.TabList,
            active: true,
            name: funcName,
            value: funcName,
            type: "Disasm"
          });
          const tabNum = tab.init(dims, funcName);

          let g = new FlowGraph({
            tab: tabNum,
            cfg: "#cfg-" + tabNum,
            stage: "#cfgStage-" + tabNum,
            group: "#cfgGrp-" + tabNum,
            minimap: "#minimap-" + tabNum,
            minimapStage: "#minimapStage-" + tabNum,
            minimapViewPort: "#minimapVP-" + tabNum,
            dims: dims,
            json: json
          });
          g.drawGraph();
          tab.setGraph(g);
          Root.AutoComplete.reload(g);
          Root.NavBar.setTitle(funcName);
          Root.NavBar.setDropdownType("Disasm");
          Root.NavBar.setModalData(json);

          UIElementInit(true);
        } else {
          popToast("alert", "Address not found", 3);
        }
      });
  }

  searchAddressAux(addr) {
    var key = window.event.keyCode;
    if (key === 13) {
      if (window.event.shiftKey) {
      } else {
        this.searchAddress(addr);
      }
      return false;
    }
    else {
      return true;
    }
  }

  registerEvents() {
    const self = this;
    self.copyEvent();
    $("#cfgChooser li div a").on("click", function () {
      const type = $(this).data("value");
      self.cfgChooser(type);
    });

    $(self.searchInputId).on("keypress", function () {
      self.searchAddressAux($(self.searchInputId).val());
    });

    $(self.searchInputId).next().on("click", function () {
      self.searchAddress($(self.searchInputId).val());
    });

    $("#btnCopyCFG").click(function (e) {
      copyToClipboard($("#codeCopyCFG").text());
    });
  }
}