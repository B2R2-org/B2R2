var cmdHistory = [""];
var idx = 0;

function Terminal() {
  const webCommand = ["show"];
  function setTerminal(width) {
    $(".sidebar-content").css("width", width);
    $(".sidebar-content").css("min-width", width);
    $(".sidebar-content").css("max-width", width);
  }
  function deleteTerminal() {
    $(".sidebar-content").css("width", "");
    $(".sidebar-content").css("min-width", "");
    $(".sidebar-content").css("max-width", "");
  }
  function resetCmdInput() {
    setTimeout(function () {
      $("#id_cmd").val("");
      $("#id_TerminalWrapper").scrollTop($("#id_cmdContainer").height());
    }, 5);
  }
  function addCommands(cmd, result) {
    const escaped = $('<div/>').text("B2R2> " + cmd + "\n" + result).html();
    const template = "<div>{CONTENT}</div>".replace("{CONTENT}", escaped);
    $("#id_content").append(template);
    cmdHistory.push(cmd);
    idx = 0;
    resetCmdInput();
  }
  function executeCommand(cmd) {
    if (cmd.length == 0) {
      addCommands(cmd, "");
    } else {
      query({
        "q": "command",
        "args": JSON.stringify({ "command": cmd })
      },
        function (status, json) {
          if (!isEmpty(json)) {
            addCommands(cmd, json);
          }
        });
    }
  }
  function isWebCommand(cmd) {
    return webCommand.includes(cmd);
  }
  function onCommandSubmit() {
    var key = window.event.keyCode;
    switch (key) {
      case 13:
        const cmd = $("#id_cmd").val().trim();
        const keyword = cmd.split(" ")[0];
        if (isWebCommand(keyword)) {
          switch (keyword) {
            case "show":
              let funcName = cmd.split(" ")[1];
              if (checkDuplicateTab(funcName)) {
                activateTab($("#id_tabContainer li[title='" + funcName + "']"));
                addCommands(cmd, "");
              } else {
                if (funcName === undefined) { funcName = ""; }
                query({
                  "q": "cfg-disasm",
                  "args": funcName
                },
                  function (status, json) {
                    if (status != 404 && !isEmpty(json)) {
                      let dims = reloadUI();
                      addTab(funcName, dims, json);
                      drawCFG(dims, json);
                      UIElementInit(true);
                      autocomplete(json);
                      setuiFuncName(funcName);
                      addCommands(cmd, "");
                    } else {
                      addCommands(cmd, "[*] Unknown function: '" + funcName + "'");
                    }
                  });
              }
              break;
            case "clear":

              break;
            default:
              break;
          }
        } else {
          // run b2r2 cli
          executeCommand(cmd);
        }
        break;
      case 38: //upArrow
        idx++;
        if (idx < 0) {
          idx = -1;
        } else if (idx > cmdHistory.length - 1) {
          idx = cmdHistory.length - 1;
        }
        $("#id_cmd").val(cmdHistory[cmdHistory.length - idx]);
        $('#id_cmd').focus().val(cmdHistory[cmdHistory.length - idx]);
        $('#id_cmd').focus(function () {
          var that = this;
          setTimeout(function () { that.selectionStart = that.selectionEnd = 10000; }, 0);
        });
        break;
      case 40: //downArrow
        idx--;
        if (idx < 0) {
          idx = 0;
        } else if (idx > cmdHistory.length - 1) {
          idx = cmdHistory.length - 1;
        }
        $("#id_cmd").val(cmdHistory[cmdHistory.length - idx]);
        $('#id_cmd').focus().val(cmdHistory[cmdHistory.length - idx]);
        break;
      default:
        break;
    }
  }
  return {
    setTerminal: setTerminal,
    deleteTerminal: deleteTerminal,
    onCommandSubmit: onCommandSubmit
  }
}

Terminal();