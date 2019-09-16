class FunctionItem {
  constructor(d) {
    this.active = false;
    this.clicked = false;
    this.name = d.name;
    this.functionList = d.functionList;
  }

  init() {

  }

  getElem() {
    return $('<li>', {
      title: this.name,
      text: this.name
    });
  }

  setState(state) {
    const $li = $(this.functionList.id + " li[title='" + this.name + "']");
    if (state === "clicked") {
      this.clicked = true;
      this.active = false;
      $li.addClass("clicked");
      $li.removeClass("active");
    } else if (state === "active") {
      this.clicked = false;
      this.active = true;
      $li.addClass("active");
      $li.removeClass("clicked");
    } else if (state == "not") {
      this.clicked = false;
      this.active = false;
      $li.removeClass("active");
      $li.removeClass("clicked");
    }
    return state;
  }

  clickEvent($self) {
    /* To seperate single click event and double click event. */
    let functionList = this.functionList;
    let funcName = $self.attr('title');
    const self = this;
    $self.on("click", function () {
      functionList.deactivateAll();
      self.setState("clicked");
      functionList.clicks++;
      if (self.functionList.clicks === 1) {
        functionList.timer = setTimeout(function () {
          let tabsLength = $("#id_tabContainer li").length;
          if (tabsLength === 0) {
            query({
              "q": "cfg-Disasm",
              "args": funcName
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
                }
              });
          } else if (Root.TabList.checkDuplicate(funcName)) {
            Root.TabList.activate(funcName);
          } else {
            query({
              "q": "cfg-Disasm",
              "args": funcName
            },
              function (status, json) {
                if (Object.keys(json).length > 0) {
                  let tab = Root.TabList.getActiveTab();
                  if (tab != undefined) {
                    let dims = reloadUI();
                    let g = tab.replace(funcName, dims, json);
                    g.drawGraph();
                    tab.setGraph(g);
                    Root.AutoComplete.reload(g);
                    Root.NavBar.setTitle(funcName);
                    Root.NavBar.setDropdownType("Disasm");
                    Root.NavBar.setModalData(json);
                  } else {
                    console.log("No active tab!");
                  }
                }
              });
          }
          self.functionList.clicks = 0;
        }, 300);
      } else {
        clearTimeout(self.functionList.timer);
        self.functionList.clicks = 0;
        if (Root.TabList.checkDuplicate(funcName)) {
          Root.TabList.activate(funcName);
        } else {
          query({
            "q": "cfg-Disasm",
            "args": funcName
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
                const tabNum = tab.add(dims, funcName);
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
              }
            });

        }
      }
    }).on("dblclick", function (e) {
      e.preventDefault();
    });
  }

  registerEvents($self) {

  }
}

class FunctionList {
  constructor(d) {
    this.containerId = "#id_functions-wrapper";
    this.id = "#funcSelector";
    this.filterInputId = "#id_funcFilter";
    this.funcs = {};
    this.clicks = 0;
    this.timer = null;
  }

  init() {
    let self = this;
    query({
      "q": "functions"
    }, function (status, funcs) {
      $.each(funcs, function (_, name) {
        let func = new FunctionItem({
          name: name,
          functionList: self,
        });
        let $func = func.getElem();
        $(self.id).append($func);
        self.funcs[name] = func;
        func.clickEvent($func);
      });
    });
  }

  setFilterEvent() {
    const self = this;
    $(this.filterInputId).on("keyup", function () {
      var value = $(this).val().toLowerCase();
      $(self.id + " li").each(function (e, i) {
        const name = $(this).text();
        const idx = name.toLowerCase().indexOf(value);
        $(this).toggle(idx > -1);
        if (idx > -1) {
          const item = name.substr(0, idx)
            + "<strong>" + name.substr(idx, value.length) + "</strong>"
            + name.substr(idx + value.length);
          $(this).html(item);
        }
      });
    });
  }

  deactivateAll() {
    let liList = document.querySelectorAll(this.id + " li.clicked");
    for (let i = 0; i < liList.length; i++) {
      liList[i].classList.remove("clicked");
      liList[i].classList.add("active");
    }
  }

  get(name) {
    return this.funcs[name];
  }


  registerEvents() {
    this.setFilterEvent();

  }
}