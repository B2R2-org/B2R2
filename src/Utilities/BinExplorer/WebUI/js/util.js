var tabTitle = $("#tab_title"),
  tabContent = $("#tab_content"),
  tabTemplate = "<li class='tab active' value={label}><a href=#{href}>{label}</a><span class='glyphicon glyphicon-remove-circle close-tab'></span></li>",
  tabCounter = 0;

// var graphContainer = $("#id_graphContainer")
// $("#id_FunctionsList").resizable({
//   handles: 'e'
// });

function addTab(functionName) {
  deactivatedTab()
  let tabContainer = $("#id_tabContainer");

  let tabId = "id_tabs-" + tabCounter;
  let label = functionName,
    li = $(tabTemplate.replace('{href}', tabId).replace(/\{label\}/g, label));
  tabContainer.find('ul').append(li)
  tabCounter++;
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
    tabs.removeClass("active")
  })
}

function activateTabbyElement($el, dims) {
  let functionName = $el.attr('value');
  deactivatedTab()
  $("#id_tabContainer [value='" + functionName + "']").addClass("active")
  query("cfg",
    functionName,
    function (json) {
      if (!isEmpty(json)) {
        $("#uiFuncName").text(function (_, _) {
          return functionName;
        });
        drawCFG(dims, json);
        registerRefreshEvents(dims, json);
      }
    });
}

function setTabName(name) {
  let tabId = "id_tabs-" + tabCounter;
  let tab = $("#id_tabContainer li.active");
  tab.attr("value", name);
  let newTab = $('<a href=#{href}>{label}<span class="glyphicon glyphicon-remove-circle close-tab"></span></a>'.replace('{href}', tabId).replace("{label}", name))
  tab.empty().append(newTab);
}

function deactivateFunctionItem() {
  $("#funcSelector li.active").each(function () {
    $(this).removeClass("active")
  });
}

function activateFunctionItem() {
  $("#id_tabContainer li").each(function () {
    let tabFunctionName = $(this).attr("value")
    $("#funcSelector li[value='" + tabFunctionName + "']").each(function () {
      $(this).addClass("active")
    });
  })
}