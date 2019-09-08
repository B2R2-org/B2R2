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

  setTitle() {
    $("#uiFuncName").text(this.functionName);
    $("#uiFuncName").attr("title", this.functionName);
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
      popToast("info", "Copy File Path", 3);
    });
  }

  updateCfgChooserLabel(textType) {
    $("#cfgChooser li div a").parents(".dropdown")
      .find(".dropdown-toggle")
      .html(textType + ' <span class="caret"></span>');
  }

  cfgChooser(t) {
    const self = this;
    let dims = reloadUI();
    let funcName = $("#uiFuncName").text();
    $(this).parents(".dropdown").find(".dropdown-toggle").val(t);
    query({
      "q": ("cfg-" + t),
      "args": funcName
    },
      function (_status, json) {
        if (Object.keys(json).length > 0) {
          const currentTab = Root.TabList.getActiveTab();
          currentTab.replace(currentTab.name, dims, json);
          Root.TabList.tabs[currentTab.name].setType(t);
          self.updateCfgChooserLabel(t);
        }
      });
  }

  searchAddress(addr) {
    query({
      "q": "address",
      "args": JSON.stringify({ "addr": addr })
    },
      function (status, json) {
        if (Object.keys(json).length > 0) {
          let funcName = json.Name
          let dims = reloadUI();
          let fullAddr = "0".repeat(16 - addr.length) + addr;
          if (checkDuplicateTab(funcName)) {
            activateTab($("#id_tabContainer li[title='" + funcName + "']"));
          } else {
            addTab(funcName, dims, json);
            drawCFG(dims, json);
            setuiFuncName(funcName);
            UIElementInit(true);
            autocomplete(json);
          }
          $("#id_event-trigger").attr("target", getNodeElement(json, fullAddr).id);
          setTimeout(function () { $("#id_event-trigger").click(); }, 5);
        } else {
          popToast("alert", "Not found Address", 3);
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
  }
}