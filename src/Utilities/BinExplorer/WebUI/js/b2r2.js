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
"use strict";

var Root = {
  mainContainerId: null,
  graphContainerId: null,
  minimapContainerId: null,
  TabList: null,
  FunctionList: null,
  AutoComplete: null
};

function drawBinInfo(status, str) {
  let filepath;
  let token = str.split("/");
  if (str.length < 45) {
    filepath = str;
  } else {
    for (let t in token) {
      if (token.slice(t).join("/").length < 45) {
        filepath = ".../" + token.slice(t).join("/");
        break
      }
    }
  }

  if (filepath === undefined) {
    filepath = str.split("/").slice(str.split("/").length - 1); // only file name
  }
  $("#binInfo").text(filepath);
  $("#binInfo").attr("title", str);
}

$("#binInfo").on("click", function () {
  let str = $("#binInfo").attr("title");
  copyToClipboard(str);
  popToast("info", "Copy File Path", 3);
});

$("#icon-refresh").on("click", function () {
  const t = $(".cfgChooserBtn").text().trim();
  query({
    "q": "cfg-" + t,
    "args": $("#uiFuncName").text().trim()
  },
    function (status, json) {
      if (Object.keys(json).length > 0) {
        let tab = Root.TabList.getActiveTab();
        let dims = reloadUI();
        tab.reload(dims, json);
        UIElementInit(true);
      }
    });
});

$(window).on("resize", function () {
  const tab = Root.TabList.getActiveTab();
  const dims = reloadUI();
  tab.graph.resize(dims);
});

// Offline mode renders a single function only. Inter-function analysis is not
// supported in offline mode.
function runOffline(dims, tab) {
  fileInput = document.getElementById("cfgFile");
  $("#uiTitle").click(function () { fileInput.click(); });
  fileInput.addEventListener("change", function () {
    let file = fileInput.files[0];
    let reader = new FileReader();
    reader.onload = function () {
      let json = JSON.parse(reader.result);
      let g = new FlowGraph({
        tab: 1,
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
      tab.setGraph(g);
    };
    try { reader.readAsText(file); }
    catch (_) { console.log("Error: File open failure."); }
  });
}

// Run in online mode (this is the default).
function runOnline() {
  Root.mainContainerId = "#id_mainContainer";
  Root.graphContainerId = "#id_graphContainer";
  Root.minimapContainerId = "#minimapDiv";

  let tabList = new TabList({});
  let funcList = new FunctionList({});
  let autoComplete = new AutoComplete({});
  let navbar = new NavBar({});
  let functionSidebarItem = new SideBarItem({
    icon: "fas fa-list",
    contentid: "#id_functions-wrapper",
    id: "#id_sidebar-functions",
    active: true,
    name: "Functions"
  });
  functionSidebarItem.registerEvents();

  let callGraphSidebarItem = new SideBarItem({
    icon: "fas fa-project-diagram",
    id: "#id_sidebar-callgraph",
    contentid: null,
    active: false,
    name: "Call Graph"
  });
  callGraphSidebarItem.registerEvents();

  let terminalSidebarItem = new SideBarItem({
    icon: "fas fa-terminal",
    id: "#id_sidebar-terminal",
    contentid: "#id_terminal-wrapper",
    active: false,
    name: "Terminal"
  });
  terminalSidebarItem.registerEvents();

  let sidebar = new SideBar({
    items: [
      functionSidebarItem,
      callGraphSidebarItem,
      terminalSidebarItem
    ]
  });

  let minimap = new MiniMap({
    document: document,
    moveHandlerId: ".move-minimap",
    returnHandlerId: ".return-minimap",
    resizeHandlerId: ".resize-minimap"
  });

  tabList.registerEvents();
  funcList.init();
  funcList.registerEvents();
  autoComplete.registerEvents();
  navbar.registerEvents();
  sidebar.registerEvents();
  minimap.registerEvents();

  Root.NavBar = navbar;
  Root.TabList = tabList;
  Root.SideBar = sidebar;
  Root.FunctionList = funcList;
  Root.AutoComplete = autoComplete;
  Root.MiniMap = minimap;

  query({ "q": "bininfo" }, drawBinInfo);
}

function main() {
  let dims = reloadUI();
  UIElementInit(false);

  if (window.location.protocol == "file:")
    return runOffline(dims);
  else {
    return runOnline();
  }
}

if (typeof window === 'undefined') { // For Node.js
  module.exports.initSVG = initSVG;
  module.exports.initEvents = initEvents;
} else {
  window.addEventListener('load', function () { main(); }, false);
}
