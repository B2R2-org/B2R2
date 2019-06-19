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

var tabTitle = $("#tab_title"),
  tabContent = $("#tab_content"),
  tabTemplate = "<li class='tab active' text-type={type} title={label} counter={number} value={label}><a href=#{href}>{label}</a><span class='glyphicon glyphicon-remove-circle close-tab'></span></li>",
  g_tabCounter = -1;

function addTab(functionName, dims, json) {
  g_tabCounter++;
  deactivatedTab()
  let tabContainer = $("#id_tabContainer");
  let tabId = "id_tabs-" + g_tabCounter;
  let textType = "disasm";
  let label = functionName,
    li = $(tabTemplate.replace('{href}', tabId).replace(/\{label\}/g, label).replace("{number}", g_tabCounter).replace("{type}", textType));
  tabContainer.find('ul').append(li);
  addGraphDiv(dims);
  toggleDisasmIR("disasm")
}


function addGraphDiv(dims) {
  let graphDivTemplate = "<div id='cfgDiv-{number}'><svg id='cfg-{number}' class='box'></svg></div>".replace(/\{number\}/g, g_tabCounter);
  let miniMapTemplate = "<svg id='minimap-{number}' class='box min-box'></svg>".replace(/\{number\}/g, g_tabCounter);
  $("#id_graphContainer").append(graphDivTemplate);
  $("#minimapDiv").append(miniMapTemplate);
  // minimize the new minimap when it is minimized.
  if ($("#minimapDiv").hasClass("active")) {
    d3.select("#minimap-" + g_tabCounter)
      .style("border", "unset")
      .style("height", "0")
  }
  d3.select("svg#cfg-" + g_tabCounter)
    .attr("width", dims.cfgVPDim.width)
    .attr("height", dims.cfgVPDim.height)
}

function closeTab($el) {
  let closedTabNum = $el.closest('li').attr("counter");
  $el.closest('li').remove();
  return closedTabNum;
}

function checkDuplicateTab(functionName) {
  let tab = $("#id_tabContainer [value='{functionName}']".replace("{functionName}", functionName));
  if (tab.length > 0) {
    return true;
  } else {
    return false
  }
}

function deactivatedTab() {
  let tabs = $("#id_tabContainer li");
  tabs.each(function () {
    $(this).removeClass("active")
  });
  let cfgs = $("#id_graphContainer div")
  cfgs.each(function () {
    $(this).hide()
  });
  let minimaps = $("#minimapDiv > svg");
  minimaps.each(function () {
    $(this).hide();
  });
}

function toggleDisasmIR(textType) {
  if (textType === "disasm") {
    $("#id_disasm-to-ir").addClass("show");
    $("#id_ir-to-disasm").removeClass("show");
  } else if (textType === "ir") {
    $("#id_ir-to-disasm").addClass("show");
    $("#id_disasm-to-ir").removeClass("show");
  } else {

  }
}

function activateTab($el, callback) {
  deactivatedTab();
  let functionName = $el.attr('title');
  let $tab = $("#id_tabContainer li[value='" + functionName + "']");
  let textType = $tab.attr('text-type') === undefined ? "disasm" : $tab.attr('text-type');
  let tabNumber = $tab.attr("counter");
  $tab.addClass("active");
  $("#cfgDiv-" + tabNumber).show();
  $("#minimap-" + tabNumber).show();
  toggleDisasmIR(textType);
  query({
    "q": "cfg-" + textType.toLowerCase(),
    "args": functionName
  },
    function (status, json) {
      if (!isEmpty(json)) {
        setuiFuncName(functionName);
        autocomplete(json);
        if (callback !== undefined) {
          callback("success");
        }
      }
    });
}

function replaceTab($self, name, dims) {
  let tabId = "id_tabs-" + g_tabCounter;
  let $tab = $("#id_tabContainer li.active");
  $tab.attr("value", name);
  $tab.attr("text-type", "disasm")
  let newTab = $(`<a href=#{href}>{label}<span class="glyphicon glyphicon-remove-circle close-tab"></span></a>`.replace('{href}', tabId).replace("{label}", name));
  $("#id_ir-to-disasm").removeClass("show");
  $("#id_disasm-to-ir").addClass("show");
  $tab.empty().append(newTab);
  query({
    "q": "cfg-disasm",
    "args": $self.attr('title')
  },
    function (status, json) {
      if (!isEmpty(json)) {
        setuiFuncName(name);
        drawCFG(dims, json);
      }
    });
}

function activateOpenFunction() {
  $("#funcSelector li.active").each(function () {
    $(this).removeClass("active")
  });
  $("#id_tabContainer li").each(function () {
    let tabFunctionName = $(this).attr("value")
    $("#funcSelector li[title='" + tabFunctionName + "']").each(function () {
      $(this).addClass("active")
    });
  })
}

function activateTabEvent() {
  $(document).on('click', "#id_tabContainer .tab", function (e) {
    activateTab($(this));
  });
}

function closeTabEvent() {
  $(document).on('click', '.close-tab', function (e) {
    e.preventDefault();
    e.stopPropagation();
    let closedTabNum = closeTab($(this));
    $("#cfgDiv-" + closedTabNum).remove();
    activateOpenFunction();
    let tabs = $("#id_tabContainer li");
    if (tabs.length <= 0) {
      d3.select("g#cfgStage-" + closedTabNum).remove();
      d3.select("g#minimapStage-" + closedTabNum).remove();
      d3.select("#minimap rect").remove();
      UIElementInit(false);
      $("#uiFuncName").text("");
    } else {
      if ($(this).closest('li').hasClass("active")) {
        activateTab($("#id_tabContainer li:last"));
      }
    }
    $(this).closest('li').remove();
  });
}

function checkValidAddress(addr) {

}

function getNodeElement(cfg, addr) {
  let currentTabNumber = $("#id_tabContainer li.tab.active").attr("counter");
  let data = cfg.Nodes;
  for (let d in data) {
    for (let t in data[d].Terms) {
      let terms = data[d].Terms[t];
      let address = terms[0][0].replace(":", "");
      if (addr === address) {
        return {
          "addr": address,
          "id": "#id_{tab}_rect-{nodeidx}-{idx}"
            .replace("{tab}", currentTabNumber)
            .replace("{nodeidx}", parseFloat(d))
            .replace("{idx}", parseFloat(t))
        }
      }
    }
  }
}

function searchAddress() {
  let addr = $("#id-input_address").val();
  query({
    "q": "address",
    "args": JSON.stringify({ "addr": addr })
  },
    function (status, json) {
      if (!isEmpty(json)) {
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

function onKeyPressSearchAddress() {
  var key = window.event.keyCode;
  if (key === 13) {
    if (window.event.shiftKey) {
    } else {
      searchAddress();
    }
    return false;
  }
  else {
    return true;
  }
}

function onClickSearchAddress() {
  searchAddress();
}