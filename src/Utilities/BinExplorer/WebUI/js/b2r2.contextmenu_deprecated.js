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

function ContextMenu() {
  $(document).on("click", ".contextmenu-item", function () {
    let currentTabNumber = $("#id_tabContainer li.tab.active").attr("counter");
    $("#id_node-contextmenu").hide();
    let target_id = $("#id_node-contextmenu").attr("target");
    let textbox = d3.select(target_id);
    let gtext = d3.select(textbox.node().parentNode);
    switch ($(this).attr("value")) {
      case "comment":
        textbox.attr("class", "nodestmtbox stmtHighlight");
        let text_id = "#id_" + currentTabNumber + "_text-" + target_id.split("_rect-")[1];
        $("#id_title-stmt").html(coloringStmt($(text_id).html()));
        $('#id_comment-modal').modal('show');
        let comment = $(target_id).parent().find(".commentText").text();
        commitInit(target_id, comment);
        break;
      case "copy":
        copyToClipboard(gtext.text());
        popToast("info", "Copy statement", 3);
        break;
      case "copy-address":
        copyToClipboard(gtext.text().split(": ")[0]);
        popToast("info", "Copy address", 3);
        break;
      case "copy-block":
        let textList = $(gtext.node().parentNode).find("text");
        let blockStr = "";
        for (let i = 0; i < textList.length; i++) {
          blockStr += $(textList[i]).text() + "\n";
        }
        copyToClipboard(blockStr);
        popToast("info", "Copy block", 3);
        break;
      default:
        break;
    }
    if ($(this).attr("value") === "comment") {

    }
  });
  $(document).on("click", function (e) {
    if ($("#id_node-contextmenu").is(":visible") && !$(e.target).hasClass(".contextmenu-item")) {
      $("#id_node-contextmenu").hide();
    } else {

    }
  });
  function coloringStmt(text) {
    let texts = text.split(/(<([^>]+)>)/ig);
    let textsrawNum = Math.floor(texts.length / 6);
    let coloredStmt = "<span class='cyan'>" + texts[3] + "</span>";
    for (let i = 1; i < textsrawNum; i++) {
      coloredStmt += texts[i * 6 + 3];
    }
    return coloredStmt;
  }
}

ContextMenu();