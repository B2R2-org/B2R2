var tabTitle = $("#tab_title"),
  tabContent = $("#tab_content"),
  tabTemplate = "<li class='tab active' title={label} counter={number} value={label}><a href=#{href}>{label}</a><span class='glyphicon glyphicon-remove-circle close-tab'></span></li>",
  g_tabCounter = -1;

function addTab($self, functionName, dims) {
  g_tabCounter++;
  deactivatedTab()
  let tabContainer = $("#id_tabContainer");
  let tabId = "id_tabs-" + g_tabCounter;
  let textType = "disasm";
  let label = functionName,
    li = $(tabTemplate.replace('{href}', tabId).replace(/\{label\}/g, label).replace("{number}", g_tabCounter).replace("{type}", textType));
  tabContainer.find('ul').append(li);
  addGraphDiv(dims);
  query({
    "q": "cfg-disasm",
    "args": $self.attr('value')
  },
    function (json) {
      if (!isEmpty(json)) {
        $("#uiFuncName").text(function (_, _) {
          return $self.attr('value');
        });
        drawCFG(dims, json);
      }
    });
}

function addGraphDiv(dims) {
  let graphDivTemplate = "<div id='cfgDiv-{number}'><svg id='cfg-{number}' class='box'></svg></div>".replace(/\{number\}/g, g_tabCounter);
  let miniMapTemplate = "<svg id='minimap-{number}' class='box min-box'></svg>".replace(/\{number\}/g, g_tabCounter);
  $("#id_graphContainer").append(graphDivTemplate);
  $("#minimapDiv").append(miniMapTemplate);
  d3.select("svg#cfg-" + g_tabCounter)
    .attr("width", dims.cfgVPDim.width)
    .attr("height", dims.cfgVPDim.height)

  d3.select("svg#minimap" + g_tabCounter)
    .attr("width", dims.minimapVPDim.width)
    .attr("height", dims.minimapVPDim.height);
}

function closeTab($el) {
  $el.closest('li').remove();
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

function activateTabbyElement($el) {
  deactivatedTab();
  let tabNumber = $el.find('a').attr('href').split("-").slice(-1)[0];
  let functionName = $el.attr('value');
  let textType = $el.attr('text-type');
  $("#id_tabContainer [value='" + functionName + "']").addClass("active");
  $("#cfgDiv-" + tabNumber).show();
  $("#minimap-" + tabNumber).show();
  $("#uiFuncName").text(function (_, _) {
    return functionName;
  });
  if (textType === "disasm") {
    $("#id_disasm-to-ir").addClass("show");
    $("#id_ir-to-disasm").removeClass("show");
  } else if (textType === "ir") {
    $("#id_ir-to-disasm").addClass("show");
    $("#id_disasm-to-ir").removeClass("show");
  } else {

  }
}

function activateTabbyName($el) {
  deactivatedTab();
  let functionName = $el.attr('value');
  let tab = $("#id_tabContainer [value='" + functionName + "']");
  let tabNumber = tab.find('a').attr('href').split("-").slice(-1)[0];
  tab.addClass("active");
  $("#cfgDiv-" + tabNumber).show();
  $("#minimap-" + tabNumber).show();
  $("#uiFuncName").text(function (_, _) {
    return functionName;
  });
}

function replaceTab($self, name, dims) {
  let tabId = "id_tabs-" + g_tabCounter;
  let tab = $("#id_tabContainer li.active");
  tab.attr("value", name);
  tab.attr("text-type", "disasm")
  let newTab = $(`<a href=#{href}>{label}<span class="glyphicon glyphicon-remove-circle close-tab"></span></a>`.replace('{href}', tabId).replace("{label}", name));
  $("#id_ir-to-disasm").removeClass("show");
  $("#id_disasm-to-ir").addClass("show");
  tab.empty().append(newTab);
  query({
    "q": "cfg-disasm",
    "args": $self.attr('value')
  },
    function (json) {
      if (!isEmpty(json)) {
        $("#uiFuncName").text(function (_, _) {
          return $(self).attr('value');
        });
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
    $("#funcSelector li[value='" + tabFunctionName + "']").each(function () {
      $(this).addClass("active")
    });
  })
}
