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

function drawFunctions(funcs) {
  $.each(funcs, function (_, addr) {
    $("#funcSelector").append($('<li>', {
      value: addr,
      text: addr
    }));
  });
}

function filterFunctions() {
  $("#id_funcFilter").on("keyup", function () {
    var value = $(this).val().toLowerCase();
    $("#funcSelector li").each(function (e, i) {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });
}

function drawBinInfo(str) {
  $("#binInfo").text(function (_, _) { return str; });
}

function query(arguments, callback) {
  function serialize(arguments) {
    var params = [];
    for (var arg in arguments)
      if (arguments.hasOwnProperty(arg)) {
        params.push(encodeURIComponent(arg) + "=" + encodeURIComponent(arguments[arg]));
      }
    return params.join("&");
  }
  let req = new XMLHttpRequest();
  let params = serialize(arguments);
  req.onreadystatechange = function () {
    if (this.readyState == 4 && this.status == 200) {
      callback(JSON.parse(this.responseText));
    }
  }
  req.open("GET", "/ajax/?" + params, true);
  req.send();
}

function disasm2irEvent(dims) {
  $(document).on("click", "#id_disasm-to-ir", function () {
    var funcName = $("#uiFuncName").text();
    query({
      "q": "cfg-ir",
      "args": funcName
    },
      function (json) {
        if (!isEmpty(json)) {
          $("#uiFuncName").text(function (_, _) {
            return $(this).attr('value');
          });
          drawCFG(dims, json);
          $("#id_tabContainer li.active").attr("text-type", "ir");
          toggleDisasmIR("ir");
        }
      });
  });
};

function ir2disasmEvent(dims) {
  $(document).on("click", "#id_ir-to-disasm", function () {
    var funcName = $("#uiFuncName").text();
    query({
      "q": "cfg-disasm",
      "args": funcName
    },
      function (json) {
        if (!isEmpty(json)) {
          $("#uiFuncName").text(function (_, _) {
            return $(this).attr('value');
          });
          drawCFG(dims, json);
          $("#id_tabContainer li.active").attr("text-type", "ir");
          toggleDisasmIR("disasm");
        }
      });
  });
}

// Offline mode renders a single function only. Inter-function analysis is not
// supported in offline mode.
function runOffline(dims) {
  fileInput = document.getElementById("cfgFile");
  $("#uiTitle").click(function () { fileInput.click(); });
  fileInput.addEventListener("change", function () {
    let file = fileInput.files[0];
    let reader = new FileReader();
    reader.onload = function () {
      let json = JSON.parse(reader.result);
      drawCFG(dims, json);
    };
    try { reader.readAsText(file); }
    catch (_) { console.log("Error: File open failure."); }
  });
}

// Run in online mode (this is the default).
function runOnline(dims) {
  activateTabEvent();
  closeTabEvent();
  disasm2irEvent(dims);
  ir2disasmEvent(dims);
  query({ "q": "functions" }, drawFunctions);
  query({ "q": "bininfo" }, drawBinInfo);
}

function reloadUI() {
  let cfgVPDim = {
    width: document.getElementById("id_graphContainer").getBoundingClientRect().width
      - parseInt($("#id_graphContainer").css("padding-right"))
      - rightMargin,
    height: document.getElementById("id_MainContainer").getBoundingClientRect().height
      - document.getElementById("id_tabContainer").getBoundingClientRect().height
      - bottomMargin
  }
  let minimapVPDim = {
    width: cfgVPDim.width * minimapRatio,
    height: cfgVPDim.height * minimapRatio,
  }

  return { cfgVPDim: cfgVPDim, minimapVPDim: minimapVPDim };
}

function functionListClickEvent() {
  function clickCall(e) {
    let $self = $(this);
    let funcName = $self.attr('value');
    let tabsLength = $("#id_tabContainer li").length;
    if (tabsLength === 0) {
      query({
        "q": "cfg-disasm",
        "args": funcName
      },
        function (json) {
          if (!isEmpty(json)) {
            $("#uiFuncName").text(function (_, _) {
              return funcName;
            });
            let dims = reloadUI();
            addTab(funcName, dims, json);
            drawCFG(dims, json);
            UIElementInit(true);
          }
        });
    } else if (checkDuplicateTab(funcName)) {
      activateTab($self);
    } else {
      let dims = reloadUI();
      replaceTab($self, funcName, dims)
    }
  }

  function dbclickCall(e) {
    let $self = $(this);
    let funcName = $self.attr('value');
    if (checkDuplicateTab(funcName)) {
      activateTab($self)
    } else {
      query({
        "q": "cfg-disasm",
        "args": funcName
      },
        function (json) {
          if (!isEmpty(json)) {
            $("#uiFuncName").text(function (_, _) {
              return funcName;
            });
            let dims = reloadUI();
            addTab(funcName, dims, json);
            drawCFG(dims, json);
            UIElementInit(true);
          }
        });
    }
  }
  $(document).on('click', "#funcSelector li", function (e) {
    $("#funcSelector li.clicked").each(function () {
      $(this).removeClass("clicked")
    });
    let self = this;
    $(self).addClass("clicked");
    setTimeout(function () {
      var dblclick = parseInt($(self).data('double'), 10);
      if (dblclick > 0) {
        $(self).data('double', dblclick - 1);
      } else {
        clickCall.call(self, e);
      }
      activateOpenFunction();

    }, 300);
  }).on('dblclick', "#funcSelector li", function (e) {
    $(this).data('double', 2);
    dbclickCall.call(this, e);
  });
}

function UIElementInit(isShow) {
  if (isShow) {
    $("#minimapDiv").show();
    $(".internel-autocomplete-container").show();
  } else {
    $("#minimapDiv").hide();
    $(".internel-autocomplete-container").hide();
  }
}

function main() {
  let dims = reloadUI();
  $(window).resize(function () { reloadUI(); });

  filterFunctions();
  registerRefreshEvents(dims);
  registerMinimapEvents();
  functionListClickEvent();

  if (window.location.protocol == "file:")
    return runOffline(dims);
  else {
    return runOnline(dims);
  }
}

if (typeof window === 'undefined') { // For Node.js
  module.exports.initSVG = initSVG;
  module.exports.initEvents = initEvents;
} else {
  window.addEventListener('load', function () { main(); }, false);
}
