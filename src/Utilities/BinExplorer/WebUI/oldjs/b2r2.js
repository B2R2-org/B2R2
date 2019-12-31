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
  WordSearch: null,
  ContextMenu: null
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
  $("#js-bininfo").text(filepath);
  $("#js-bininfo").attr("title", str);
}

$("#js-bininfo").on("click", function () {
  let str = $("#js-bininfo").attr("title");
  copyToClipboard(document, str);
  popToast("info", "File path copied", 3);
});

$("#js-icon-refresh").on("click", function () {
  const t = $("#js-cfg-btn").text().trim();
  query({
    "q": "cfg-" + t,
    "args": $("#js-funcinfo").text().trim()
  },
    function (status, json) {
      if (Object.keys(json).length > 0) {
        let tab = Root.TabList.getActiveTab();
        let dims = computeUIDimensions(document);
        tab.reload(dims, json);
        UIElementInit(true);
      }
    });
});

$(window).on("resize", function () {
  const tab = Root.TabList.getActiveTab();
  const dims = computeUIDimensions(document);
  if (tab !== undefined) { tab.graph.resize(dims); }
});

// Offline mode renders a single function only. Inter-function analysis is not
// supported in offline mode.
function runOffline(dims, tab) {
  let fileInput = document.getElementById("js-cfg-file");
  $("#js-bininfo").click(function () { fileInput.click(); });
  fileInput.addEventListener("change", function () {
    let file = fileInput.files[0];
    let reader = new FileReader();
    reader.onload = function () {
      let json = JSON.parse(reader.result);
      let g = new FlowGraph(document, 1, dims, json, false);
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

  let tabList = new TabList();
  let funcList = new FunctionList({});
  let wordSearch = new WordSearch({});
  let navbar = new NavBar({});
  let functionSidebarItem = new SideBarItem($("#js-sidemenu__functions"), true);
  let callGraphSidebarItem = new SideBarItem($("#js-sidemenu__cg"), false);
  let terminalSidebarItem = new SideBarItem($("#js-sidemenu__term"), false);
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

  let contextmenu = new ContextMenu({
    document: document,
    id: "id_main-contextmenu"
  });

  tabList.registerEvents();
  funcList.init();
  funcList.registerEvents();
  wordSearch.registerEvents();
  navbar.registerEvents();
  sidebar.registerEvents();
  minimap.registerEvents();
  contextmenu.registerEvents();

  Root.NavBar = navbar;
  Root.TabList = tabList;
  Root.SideBar = sidebar;
  Root.FunctionList = funcList;
  Root.WordSearch = wordSearch;
  Root.MiniMap = minimap;
  Root.ContextMenu = contextmenu;

  query({ "q": "bininfo" }, drawBinInfo);
}

function main() {
  let dims = computeUIDimensions(document);
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
